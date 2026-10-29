"""Writing a step's answers onto the proposal, and reading them back.

Every step's answers are kept as they arrived (models.FormStepResponse). A
step with a field_map or resources (see flows.py) also writes them onto the
proposal and its requested resources, so the rest of Waldur - reviews,
allocation, project creation - works on a Formbricks proposal as on any
other.
"""

import logging

from django.core.exceptions import ValidationError

from waldur_core.core.validators import get_project_name_regex_error
from waldur_mastermind.proposal import models as proposal_models

from . import client, flows

logger = logging.getLogger(__name__)


class FormbricksMappingError(Exception):
    """An answer the flow expects is missing or will not fit.

    Raised rather than quietly defaulting, so a survey edited out of step
    with its flow fails visibly instead of dropping an applicant's answers.
    """


def _get_required(data, question_id, step_key):
    if question_id not in data:
        raise FormbricksMappingError(
            f"Question {question_id!r} is missing from the {step_key!r} answers; "
            f"the survey may have been edited without updating the flow."
        )
    return data[question_id]


def _as_text(value):
    if isinstance(value, list):
        return ", ".join(str(item) for item in value)
    return "" if value is None else str(value)


def _set_field(proposal, field_name, value, step_key):
    field = proposal_models.Proposal._meta.get_field(field_name)
    try:
        value = field.clean(_as_text(value).strip(), proposal)
    except ValidationError as e:
        raise FormbricksMappingError(
            f"The {step_key!r} answer for {field_name!r} was refused: "
            f"{'; '.join(e.messages)}"
        ) from e
    if field_name == "name":
        # The name becomes part of the project's name on approval, so it is
        # held to the same pattern as the proposal API holds it to.
        error = get_project_name_regex_error(value)
        if error:
            raise FormbricksMappingError(
                f"The {step_key!r} answer for 'name' was refused: {error}"
            )
    setattr(proposal, field_name, value)


def _requested_offering(call, offering_slug):
    try:
        return proposal_models.RequestedOffering.objects.get(
            call=call, offering__slug=offering_slug
        )
    except proposal_models.RequestedOffering.DoesNotExist:
        raise FormbricksMappingError(
            f"Call {call} does not request offering {offering_slug!r}; check "
            f"the flow's resource options against the call's offerings."
        )
    except proposal_models.RequestedOffering.MultipleObjectsReturned:
        raise FormbricksMappingError(
            f"Call {call} requests offering {offering_slug!r} more than once; "
            f"remove the duplicate so the choice is unambiguous."
        )


def call_offering_problems(call, steps) -> list:
    """Why the flow's resource choices do not fit this call; empty if they do.

    Checked when a flow is attached to a call, so a mismatch is found by the
    call manager rather than by the first applicant to choose a resource.
    """
    problems = []
    for slug in flows.offering_slugs(steps):
        try:
            _requested_offering(call, slug)
        except FormbricksMappingError as e:
            problems.append(str(e))
    return problems


def _map_resources(proposal, data, step):
    resources = step["resources"]
    call = proposal.round.call
    options = {option["label"]: option for option in resources["options"]}

    chosen = _get_required(data, resources["question_id"], step["key"])
    if isinstance(chosen, str):
        chosen = [chosen]
    elif not isinstance(chosen, list):
        chosen = []

    # Formbricks records a choice by its label text, not an id.
    chosen_ids = []
    for label in chosen:
        option = options.get(label)
        if option is None:
            # A choice offered in the survey before its offering is set up:
            # skipped rather than failing the applicant's whole step.
            logger.warning(
                "Proposal %s chose %r in step %s, which the flow does not map "
                "to an offering; skipped.",
                proposal.uuid,
                label,
                step["key"],
            )
            continue
        requested_offering = _requested_offering(call, option["offering_slug"])
        chosen_ids.append(requested_offering.id)
        attributes = dict(option["default_attributes"])
        for question_id, attribute in option["attribute_map"].items():
            attributes[attribute] = _get_required(data, question_id, step["key"])
        proposal_models.RequestedResource.objects.update_or_create(
            proposal=proposal,
            requested_offering=requested_offering,
            defaults={"attributes": attributes},
        )

    # Answering again replaces the choice: drop offerings this step manages
    # that are no longer chosen. A resource a call manager added by other
    # means is left alone.
    managed_ids = [
        _requested_offering(call, option["offering_slug"]).id
        for option in resources["options"]
    ]
    proposal.requestedresource_set.filter(
        requested_offering_id__in=managed_ids
    ).exclude(requested_offering_id__in=chosen_ids).delete()


def apply_step(proposal, data, step):
    """Write a step's answers onto the proposal and its requested resources.

    Saves the proposal only if a field changed. Run inside the caller's
    transaction, so a refused answer leaves nothing half-written.
    """
    for question_id, field_name in step.get("field_map", {}).items():
        _set_field(
            proposal,
            field_name,
            _get_required(data, question_id, step["key"]),
            step["key"],
        )
    if step.get("field_map"):
        proposal.save(update_fields=list(set(step["field_map"].values())))
    if step.get("resources"):
        _map_resources(proposal, data, step)


def serialize_form_responses(proposal, steps, step_keys=None) -> list:
    """Each stored step's answers as labelled questions, in the order the
    flow asks them, for reading in the proposal.

    step_keys, if given, limits which steps are included (reviewers see
    only the reviewer-visible ones). A step no longer in the flow is listed
    last, under its key.
    """
    responses = proposal.form_step_responses.all()
    if step_keys is not None:
        responses = responses.filter(step_key__in=step_keys)

    position = {step["key"]: index for index, step in enumerate(steps)}
    labels = {step["key"]: step["label"] for step in steps}
    responses = sorted(
        responses, key=lambda r: (position.get(r.step_key, len(steps)), r.step_key)
    )

    result = []
    for response in responses:
        # The answers are jsonb, which does not keep key order;
        # question_order is the order the survey asked them in.
        order = {qid: index for index, qid in enumerate(response.question_order)}
        answers = sorted(
            (
                (question_id, answer)
                for question_id, answer in response.raw_response.items()
                if question_id not in client.HIDDEN_FIELD_KEYS
            ),
            key=lambda pair: order.get(pair[0], len(order)),
        )
        result.append(
            {
                "step_key": response.step_key,
                "step_label": labels.get(response.step_key, response.step_key),
                "submitted_at": response.modified,
                "questions": [
                    {
                        "question_id": question_id,
                        "label": response.question_labels.get(question_id, question_id),
                        "answer": answer,
                    }
                    for question_id, answer in answers
                ],
            }
        )
    return result
