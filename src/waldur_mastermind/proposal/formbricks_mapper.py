"""Applies a Formbricks step's answers to a Proposal.

A step's mapper (FormbricksFlowStep.mapper, one of MAPPERS below) applies its
field mappings and resource options to Proposal/RequestedResource fields.
Steps without a mapper are snapshotted (models.FormStepResponse) but never
passed through one.
"""

import logging

from waldur_mastermind.proposal import enums, formbricks_flows
from waldur_mastermind.proposal import models as proposal_models

logger = logging.getLogger(__name__)


class FormbricksMappingError(Exception):
    """A configured question ID was missing from a webhook payload.

    Raised rather than silently defaulting, so a Formbricks survey edited
    out of sync with its Waldur flow configuration fails loudly instead of quietly
    dropping applicant data.
    """


def _get_required(data, question_id, step_key):
    if question_id not in data:
        raise FormbricksMappingError(
            f"Question {question_id!r} missing from {step_key!r} response - "
            f"the Formbricks survey may have been edited without updating "
            f"the Waldur Formbricks flow."
        )
    return data[question_id]


_YES_NO = {"yes": True, "no": False, "true": True, "false": False}


def _coerce_bool(value, question_id, step_key):
    try:
        return _YES_NO[value.strip().lower()]
    except (AttributeError, KeyError):
        raise FormbricksMappingError(
            f"Question {question_id!r} in {step_key!r} response was "
            f"{value!r} - expected one of {sorted(_YES_NO)}. The question "
            f"type may have changed in Formbricks without updating "
            f"the Waldur Formbricks flow."
        )


def _coerce_int(value, question_id, step_key):
    try:
        return int(value)
    except (TypeError, ValueError):
        raise FormbricksMappingError(
            f"Question {question_id!r} in {step_key!r} response was "
            f"{value!r} - expected a whole number."
        )


# Hidden fields Waldur itself injects into every survey URL for internal
# plumbing (see formbricks_client.lead_hidden_fields and the proposal_uuid/
# call_uuid/round_uuid/redirect_token kwargs throughout views.py) - Formbricks
# echoes these back as ordinary answers in the webhook payload, but they're
# not something an applicant or reviewer submitted and shouldn't be shown
# alongside the real question/answer pairs.
HIDDEN_INFRASTRUCTURE_FIELDS = {
    "proposal_uuid",
    "call_uuid",
    "round_uuid",
    "redirect_token",
}


def serialize_form_responses(proposal, step_keys=None):
    """Zip each FormStepResponse's raw_response/question_labels into
    label/value pairs, for the Lead's and reviewers' read-only display.

    `step_keys`, if given, restricts which steps are included (reviewers
    only ever see the flow's reviewer-visible steps); omitted, every
    stored step is returned (the Lead's own data, or a staff viewer's).
    Returns None if the call doesn't use the Formbricks flow at all.
    """
    flow = proposal.round.call.formbricks_flow
    if flow is None:
        return None

    steps = proposal.form_step_responses.all()
    if step_keys is not None:
        steps = steps.filter(step_key__in=step_keys)

    # Order by the flow's own step sequence (e.g. project_details,
    # team_details, compliance, assessment), not by
    # step_key alphabetically ("assessment" would sort first) or by
    # created/modified (which drifts out of submission order once any step
    # is edited later).
    flow_steps = formbricks_flows.get_steps(flow)
    flow_order = {step.key: index for index, step in enumerate(flow_steps)}
    steps = sorted(
        steps, key=lambda step: flow_order.get(step.step_key, len(flow_steps))
    )

    result = []
    for step in steps:
        # raw_response/question_labels are jsonb columns - Postgres doesn't
        # preserve object key order, so iterating them directly yields an
        # arbitrary order, not the order the applicant actually saw the
        # questions in. question_order is a JSON *array* (order-preserving)
        # captured separately at webhook-write time (see views.py) - sort
        # by it instead. Falls back to raw_response's own (unordered) order
        # for any question_id missing from it - rows written before this
        # field existed, or if the schema fetch failed for that submission.
        order = {
            question_id: index for index, question_id in enumerate(step.question_order)
        }
        questions = sorted(
            (
                (question_id, answer)
                for question_id, answer in step.raw_response.items()
                if question_id not in HIDDEN_INFRASTRUCTURE_FIELDS
            ),
            key=lambda pair: order.get(pair[0], len(order)),
        )
        result.append(
            {
                "step_key": step.step_key,
                "questions": [
                    {
                        "question_id": question_id,
                        "label": step.question_labels.get(question_id, question_id),
                        "answer": answer,
                    }
                    for question_id, answer in questions
                ],
            }
        )
    return result


def _resolve_requested_offering(call, offering):
    try:
        return proposal_models.RequestedOffering.objects.get(
            call=call, offering=offering
        )
    except proposal_models.RequestedOffering.DoesNotExist:
        raise FormbricksMappingError(
            f"Call {call} has no RequestedOffering for offering {offering} - "
            f"check the Formbricks flow's resource options against this "
            f"call's actual offerings."
        )
    except proposal_models.RequestedOffering.MultipleObjectsReturned:
        raise FormbricksMappingError(
            f"Call {call} has more than one RequestedOffering for offering "
            f"{offering} - this mapper can't tell which one is "
            f"authoritative. Remove or cancel the duplicate."
        )


_COERCERS = {
    enums.FormbricksValueTypes.TEXT: lambda value, question_id, step_key: value,
    enums.FormbricksValueTypes.INTEGER: _coerce_int,
    enums.FormbricksValueTypes.BOOLEAN: _coerce_bool,
}


def map_project_details(proposal, data, step):
    """Apply a project-details step's answers to `proposal`.

    Does not save `proposal` - the caller (the webhook handler) does that
    once, after the mapper returns, so a single save covers every field
    this function sets.

    `step` is a models.FormbricksFlowStep.
    """
    for mapping in step.field_mappings.all():
        value = _get_required(data, mapping.question_id, step.key)
        coerce = _COERCERS[mapping.value_type]
        setattr(
            proposal,
            mapping.proposal_field,
            coerce(value, mapping.question_id, step.key),
        )

    resource_options = list(step.resource_options.select_related("offering"))
    if not resource_options:
        return

    call = proposal.round.call
    options_by_label = {option.choice_label: option for option in resource_options}

    selected_labels = _get_required(data, step.resource_question_id, step.key)
    if isinstance(selected_labels, str):
        selected_labels = [selected_labels]

    selected_requested_offering_ids = []
    for label in selected_labels:
        # Formbricks records the choice's label text as the answer, not a
        # stable id - translate explicitly through the configured options.
        option = options_by_label.get(label)
        if option is None:
            logger.warning(
                "Proposal %s selected resource option %r for call %s with no "
                "matching resource option - skipping (offering may not be "
                "wired up yet).",
                proposal.uuid,
                label,
                call,
            )
            continue

        requested_offering = _resolve_requested_offering(call, option.offering)
        selected_requested_offering_ids.append(requested_offering.id)

        attributes = dict(option.default_attributes)
        for question_id, attribute_key in option.attribute_field_map.items():
            attributes[attribute_key] = _get_required(data, question_id, step.key)

        proposal_models.RequestedResource.objects.update_or_create(
            proposal=proposal,
            requested_offering=requested_offering,
            defaults={"attributes": attributes},
        )

    # Editing project_details replaces the resource selection wholesale: drop
    # any previously-selected resource option offering that is no longer
    # selected. Only offerings this step actually manages are touched - a
    # resource added independently by a call manager isn't affected.
    all_configured_requested_offering_ids = [
        _resolve_requested_offering(call, option.offering).id
        for option in resource_options
    ]
    proposal.requestedresource_set.filter(
        requested_offering_id__in=all_configured_requested_offering_ids
    ).exclude(requested_offering_id__in=selected_requested_offering_ids).delete()


MAPPERS = {
    enums.FormbricksStepMappers.PROJECT_DETAILS: map_project_details,
}
