"""Applies a Formbricks step's answers to a Proposal.

Only "project_details" has a mapper (see formbricks_flows.py) - it's the
only step whose answers feed directly into Proposal/RequestedResource
fields. Every other step is snapshotted (models.FormStepResponse) but never
passed through a mapper.
"""

import logging

from waldur_mastermind.proposal import formbricks_flows
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


_YES_NO = {"yes": True, "no": False, "true": True, "false": False}


def _coerce_bool(value, question_id, step_key):
    try:
        return _YES_NO[value.strip().lower()]
    except (AttributeError, KeyError):
        raise FormbricksMappingError(
            f"Question {question_id!r} in {step_key!r} response was "
            f"{value!r} - expected one of {sorted(_YES_NO)}. The question "
            f"type may have changed in Formbricks without updating "
            f"formbricks_flows.py."
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
    only ever see formbricks_flows.REVIEWER_VISIBLE_STEPS); omitted, every
    stored step is returned (the Lead's own data, or a staff viewer's).
    Returns None if the call doesn't use the Formbricks flow at all.
    """
    flow_key = proposal.round.call.formbricks_flow_key
    if not flow_key:
        return None

    steps = proposal.form_step_responses.all()
    if step_keys is not None:
        steps = steps.filter(step_key__in=step_keys)

    # Order by the flow's own step sequence (project_details, team_details,
    # compliance, assessment - see formbricks_flows.FORM_FLOWS), not by
    # step_key alphabetically ("assessment" would sort first) or by
    # created/modified (which drifts out of submission order once any step
    # is edited later).
    flow = formbricks_flows.get_flow(flow_key) or []
    flow_order = {step["key"]: index for index, step in enumerate(flow)}
    steps = sorted(steps, key=lambda step: flow_order.get(step.step_key, len(flow)))

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
            question_id: index
            for index, question_id in enumerate(step.question_order)
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

    for question_id, field_name in step.get("integer_field_map", {}).items():
        value = _get_required(data, question_id, step["key"])
        setattr(proposal, field_name, _coerce_int(value, question_id, step["key"]))

    for question_id, field_name in step.get("boolean_field_map", {}).items():
        value = _get_required(data, question_id, step["key"])
        setattr(proposal, field_name, _coerce_bool(value, question_id, step["key"]))

    call = proposal.round.call
    resource_options = step["resource_options"]
    label_to_slug = step["resource_label_to_slug"]

    selected_labels = _get_required(data, step["resource_question_id"], step["key"])
    if isinstance(selected_labels, str):
        selected_labels = [selected_labels]

    selected_requested_offering_ids = []
    for label in selected_labels:
        # Formbricks records the choice's label text as the answer, not a
        # stable id/slug - translate explicitly rather than deriving a slug
        # from the label (e.g. lowercasing it), since offering slugs are
        # free to diverge from Formbricks' label text over time.
        slug = label_to_slug.get(label)
        if slug is None:
            logger.warning(
                "Proposal %s selected resource option %r for call %s with no "
                "resource_label_to_slug entry - skipping (offering may not "
                "be wired up yet).",
                proposal.uuid,
                label,
                call,
            )
            continue

        option = resource_options.get(slug)
        if option is None:
            logger.warning(
                "Proposal %s selected resource option %r (slug %r) for call "
                "%s with no matching resource_options entry - skipping.",
                proposal.uuid,
                label,
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
