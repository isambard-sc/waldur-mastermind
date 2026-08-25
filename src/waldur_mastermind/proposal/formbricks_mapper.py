"""Applies a Formbricks step's answers to a Proposal.

Only "project_details" has a mapper (see formbricks_flows.py) - it's the
only step whose answers feed directly into Proposal/RequestedResource
fields. Every other step is snapshotted (models.FormStepResponse) but never
passed through a mapper.
"""

import logging

from waldur_mastermind.proposal import models as proposal_models

logger = logging.getLogger(__name__)


class FormbricksMappingError(Exception):
    """A configured question ID was missing from a webhook payload.

    Raised rather than silently defaulting, so a Formbricks survey edited
    out of sync with formbricks_flows.py fails loudly instead of quietly
    dropping applicant data.
    """


def _get_required(data, question_id, step_key):
    if question_id not in data:
        raise FormbricksMappingError(
            f"Question {question_id!r} missing from {step_key!r} response - "
            f"the Formbricks survey may have been edited without updating "
            f"formbricks_flows.py."
        )
    return data[question_id]


def _resolve_requested_offering(call, offering_slug):
    try:
        return proposal_models.RequestedOffering.objects.get(
            call=call, offering__slug=offering_slug
        )
    except proposal_models.RequestedOffering.DoesNotExist:
        raise FormbricksMappingError(
            f"Call {call} has no RequestedOffering for offering slug "
            f"{offering_slug!r} - check formbricks_flows.py resource_options "
            f"against this call's actual offerings."
        )
    except proposal_models.RequestedOffering.MultipleObjectsReturned:
        raise FormbricksMappingError(
            f"Call {call} has more than one RequestedOffering for offering "
            f"slug {offering_slug!r} - this mapper can't tell which one is "
            f"authoritative. Remove or cancel the duplicate."
        )


def map_project_details(proposal, data, step):
    """Apply the project_details step's answers to `proposal`.

    Does not save `proposal` - the caller (the webhook handler) does that
    once, after the mapper returns, so a single save covers every field
    this function sets.

    `step` is the PROJECT_DETAILS_STEP dict from formbricks_flows.py.
    """
    for question_id, field_name in step["field_map"].items():
        value = _get_required(data, question_id, step["key"])
        setattr(proposal, field_name, value)

    call = proposal.round.call
    resource_options = step["resource_options"]

    selected_slugs = _get_required(data, step["resource_question_id"], step["key"])
    if isinstance(selected_slugs, str):
        selected_slugs = [selected_slugs]

    selected_requested_offering_ids = []
    for slug in selected_slugs:
        option = resource_options.get(slug)
        if option is None:
            logger.warning(
                "Proposal %s selected unknown resource option %r for call %s - skipping.",
                proposal.uuid,
                slug,
                call,
            )
            continue

        requested_offering = _resolve_requested_offering(call, slug)
        selected_requested_offering_ids.append(requested_offering.id)

        attributes = dict(option.get("default_attributes", {}))
        for question_id, attribute_key in option.get("attribute_field_map", {}).items():
            attributes[attribute_key] = _get_required(data, question_id, step["key"])

        proposal_models.RequestedResource.objects.update_or_create(
            proposal=proposal,
            requested_offering=requested_offering,
            defaults={"attributes": attributes},
        )

    # Editing project_details replaces the resource selection wholesale: drop
    # any previously-selected resource_options offering that is no longer
    # selected. Only offerings this step actually manages are touched - a
    # resource added independently by a call manager isn't affected.
    all_configured_requested_offering_ids = [
        _resolve_requested_offering(call, slug).id for slug in resource_options
    ]
    proposal.requestedresource_set.filter(
        requested_offering_id__in=all_configured_requested_offering_ids
    ).exclude(requested_offering_id__in=selected_requested_offering_ids).delete()
