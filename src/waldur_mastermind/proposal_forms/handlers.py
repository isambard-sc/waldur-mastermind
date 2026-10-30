"""Connects this app to upstream's proposal app: the form_flow field on
calls, the rule that forms are answered before submission, and deleting a
draft's responses in Formbricks."""

from django.db import transaction
from django.db.models.signals import pre_delete
from rest_framework import exceptions

from waldur_core.core.models import is_feature_enabled
from waldur_core.core.signals import pre_serializer_fields
from waldur_core.structure import models as structure_models
from waldur_mastermind.proposal import models as proposal_models
from waldur_mastermind.proposal import serializers as proposal_serializers
from waldur_mastermind.proposal import views as proposal_views
from waldur_mastermind.proposal.enums import ProposalStates

from . import client, responses, serializers, tasks

# pre_serializer_fields is sent for the exact serializer class, so a subclass
# needs its own connection.
for call_serializer in (
    proposal_serializers.PublicCallSerializer,
    proposal_serializers.ProtectedCallSerializer,
):
    pre_serializer_fields.connect(
        sender=call_serializer,
        receiver=serializers.add_form_flow_to_call,
        dispatch_uid=f"proposal_forms.add_form_flow_to_{call_serializer.__name__}",
    )


def validate_forms_answered(proposal):
    """A proposal whose call has forms is submitted only once every form is
    answered, whether or not Formbricks can be reached: the answers checked
    are Waldur's copy. Only switching the feature off (the site no longer
    using Formbricks forms) lifts the rule."""
    flow = responses.call_flow(proposal)
    if flow is None or not is_feature_enabled(client.FEATURE):
        return
    missing = responses.missing_steps(proposal, flow)
    if not missing:
        return
    message = f"Fill in these forms before submitting: {', '.join(missing)}."
    if not client.is_available():
        message += (
            " The forms cannot be opened just now; please try again later, or "
            "contact the call's managers if it keeps happening."
        )
    raise exceptions.ValidationError({"forms": [message]})


# Added to upstream's submit validators rather than editing its view.
if validate_forms_answered not in proposal_views.ProposalViewSet.submit_validators:
    proposal_views.ProposalViewSet.submit_validators.append(validate_forms_answered)


def delete_draft_responses(sender, instance, **kwargs):
    """A draft proposal is deleted: its answers in Formbricks go too. Queued
    now (the links are about to go with the proposal), deleted once the
    proposal's deletion has committed."""
    if instance.state != ProposalStates.DRAFT:
        return
    if not instance.form_links.exclude(response_id="").exists():
        return
    responses.queue_subject_deletions(
        instance, f"draft proposal {instance.uuid.hex} deleted"
    )
    transaction.on_commit(tasks.process_formbricks_deletions.delay)


pre_delete.connect(
    delete_draft_responses,
    sender=proposal_models.Proposal,
    dispatch_uid="proposal_forms.delete_draft_responses",
)


def delete_project_responses(sender, instance, **kwargs):
    """A project is deleted (projects are soft-deleted, which sends this
    signal but cascades nothing): its end-of-project answers go, in Waldur
    and, once the deletion has committed, in Formbricks."""
    links = responses.subject_links(instance)
    answers = responses.subject_responses(instance)
    if not links.exists() and not answers.exists():
        return
    responses.queue_subject_deletions(instance, f"project {instance.uuid.hex} deleted")
    answers.delete()
    links.delete()
    transaction.on_commit(tasks.process_formbricks_deletions.delay)


pre_delete.connect(
    delete_project_responses,
    sender=structure_models.Project,
    dispatch_uid="proposal_forms.delete_project_responses",
)
