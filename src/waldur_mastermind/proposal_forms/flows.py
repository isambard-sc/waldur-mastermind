"""The shape of a form flow's steps, and finding your way around them.

A flow (models.FormFlow) is an ordered list of steps; each step is one
Formbricks survey:

    {
        "key": "project_details",        # stable id, unique in the flow
        "label": "Project details",      # what applicants and reviewers see
        "survey_id": "cmt4q1c40...",     # the Formbricks survey
        "reviewer_visible": true,        # may reviewers read the answers?
        "field_map": {                   # answers copied onto the proposal
            "<question id>": "name",
        },
        "resources": {                   # a choice of offerings to request
            "question_id": "<question id>",
            "options": [
                {
                    "label": "Isambard-AI",       # the choice's text in Formbricks
                    "offering_slug": "isambard-a-1",
                    "attribute_map": {"<question id>": "allocation"},
                    "default_attributes": {},
                },
            ],
        },
    }

Only key, label and survey_id are required. Every step's answers are kept
(models.FormStepResponse); field_map and resources additionally write them
onto the proposal (see mapper.py). Steps are checked when a flow is saved
through the API, so a typo is refused there rather than turning up as a
failed webhook when an applicant reaches that step.
"""

import re

from django.utils.text import slugify

# Proposal fields an answer may be copied onto. Kept to plain text fields:
# Formbricks sends every answer as text (or a list of texts), and anything
# structural - state, round, project - is not the applicant's to set.
MAPPABLE_PROPOSAL_FIELDS = ("name", "description", "project_summary")

STEP_KEYS = frozenset(
    {"key", "label", "survey_id", "reviewer_visible", "field_map", "resources"}
)
RESOURCES_KEYS = frozenset({"question_id", "options"})
OPTION_KEYS = frozenset(
    {"label", "offering_slug", "attribute_map", "default_attributes"}
)

# Formbricks ids are cuid-style; the survey id also goes into a URL path.
_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")


class FlowError(ValueError):
    """A flow's steps are not well-formed. The message says where."""


def _require_id(value, where):
    if not isinstance(value, str) or not _ID_PATTERN.match(value):
        raise FlowError(
            f"{where} must be a Formbricks id (letters, digits, '-' and '_')."
        )
    return value


def _require_text(value, where):
    if not isinstance(value, str) or not value.strip():
        raise FlowError(f"{where} must be non-empty text.")
    return value.strip()


def _require_mapping(value, where):
    if not isinstance(value, dict):
        raise FlowError(f"{where} must be a mapping.")
    return value


def _refuse_unknown(item, allowed, where):
    unknown = sorted(set(item) - allowed)
    if unknown:
        raise FlowError(
            f"{where} has unknown key(s) {', '.join(unknown)}; "
            f"allowed: {', '.join(sorted(allowed))}."
        )


def _clean_question_map(value, where, allowed_targets=None):
    """{question id: target}, with every target a non-empty string - and,
    if allowed_targets is given, one of them."""
    result = {}
    for question_id, target in _require_mapping(value, where).items():
        _require_id(question_id, f"{where} question id {question_id!r}")
        target = _require_text(target, f"{where}[{question_id!r}]")
        if allowed_targets is not None and target not in allowed_targets:
            raise FlowError(
                f"{where}[{question_id!r}] is {target!r}; answers can only be "
                f"copied onto {', '.join(allowed_targets)}."
            )
        result[question_id] = target
    return result


def _clean_resources(value, where):
    resources = _require_mapping(value, where)
    _refuse_unknown(resources, RESOURCES_KEYS, where)
    question_id = _require_id(resources.get("question_id"), f"{where}.question_id")
    options = resources.get("options")
    if not isinstance(options, list) or not options:
        raise FlowError(f"{where}.options must be a non-empty list.")

    cleaned_options = []
    seen_labels = set()
    seen_slugs = set()
    for index, option in enumerate(options):
        option_where = f"{where}.options[{index}]"
        _require_mapping(option, option_where)
        _refuse_unknown(option, OPTION_KEYS, option_where)
        label = _require_text(option.get("label"), f"{option_where}.label")
        slug = _require_text(
            option.get("offering_slug"), f"{option_where}.offering_slug"
        )
        if label in seen_labels:
            raise FlowError(f"{option_where}: label {label!r} is used twice.")
        if slug in seen_slugs:
            raise FlowError(f"{option_where}: offering {slug!r} is used twice.")
        seen_labels.add(label)
        seen_slugs.add(slug)
        cleaned_options.append(
            {
                "label": label,
                "offering_slug": slug,
                "attribute_map": _clean_question_map(
                    option.get("attribute_map", {}), f"{option_where}.attribute_map"
                ),
                "default_attributes": dict(
                    _require_mapping(
                        option.get("default_attributes", {}),
                        f"{option_where}.default_attributes",
                    )
                ),
            }
        )
    return {"question_id": question_id, "options": cleaned_options}


def validate_steps(steps) -> list:
    """The steps, checked and normalised; raises FlowError if they are not
    well-formed.

    Checks only what can be known without a call: whether an offering slug
    matches one of a call's requested offerings depends on the call, and is
    checked when a flow is attached to one (see
    mapper.call_offering_problems).
    """
    if not isinstance(steps, list) or not steps:
        raise FlowError("A flow needs at least one step.")

    cleaned = []
    seen_keys = set()
    seen_surveys = set()
    mapped_fields = {}
    resource_step = None
    for index, step in enumerate(steps):
        where = f"Step {index + 1}"
        _require_mapping(step, where)
        _refuse_unknown(step, STEP_KEYS, where)

        key = step.get("key")
        if not isinstance(key, str) or not key or slugify(key) != key:
            raise FlowError(
                f"{where}: key must be a slug (lower-case letters, digits, '-' "
                f"and '_'), e.g. 'project_details'."
            )
        where = f"Step {key!r}"
        if key in seen_keys:
            raise FlowError(f"{where} appears twice: step keys must be unique.")
        seen_keys.add(key)

        survey_id = _require_id(step.get("survey_id"), f"{where}: survey_id")
        if survey_id in seen_surveys:
            raise FlowError(
                f"{where}: survey {survey_id!r} is used by another step; an "
                f"answer could not be told apart."
            )
        seen_surveys.add(survey_id)

        reviewer_visible = step.get("reviewer_visible", False)
        if not isinstance(reviewer_visible, bool):
            raise FlowError(f"{where}: reviewer_visible must be true or false.")

        field_map = _clean_question_map(
            step.get("field_map", {}),
            f"{where}: field_map",
            allowed_targets=MAPPABLE_PROPOSAL_FIELDS,
        )
        for field in field_map.values():
            if field in mapped_fields:
                raise FlowError(
                    f"{where}: {field!r} is already filled in by step "
                    f"{mapped_fields[field]!r}."
                )
            mapped_fields[field] = key

        cleaned_step = {
            "key": key,
            "label": _require_text(step.get("label"), f"{where}: label"),
            "survey_id": survey_id,
            "reviewer_visible": reviewer_visible,
            "field_map": field_map,
        }
        if step.get("resources") is not None:
            if resource_step is not None:
                # Each step replaces the resource request wholesale, so two
                # steps would undo each other's choices.
                raise FlowError(
                    f"{where}: only one step may choose resources; step "
                    f"{resource_step!r} already does."
                )
            resource_step = key
            cleaned_step["resources"] = _clean_resources(
                step["resources"], f"{where}: resources"
            )
        cleaned.append(cleaned_step)
    return cleaned


def offering_slugs(steps) -> list:
    """Every offering slug the flow's resource choices refer to."""
    return [
        option["offering_slug"]
        for step in steps
        if step.get("resources")
        for option in step["resources"]["options"]
    ]


def get_step(steps, step_key):
    for step in steps:
        if step["key"] == step_key:
            return step
    return None


def get_step_by_survey_id(steps, survey_id):
    for step in steps:
        if step["survey_id"] == survey_id:
            return step
    return None


def get_next_step(steps, step_key):
    """The step after step_key; None if it was the last, or not in the flow."""
    for index, step in enumerate(steps):
        if step["key"] == step_key:
            return steps[index + 1] if index + 1 < len(steps) else None
    return None


def reviewer_visible_keys(steps) -> set:
    return {step["key"] for step in steps if step.get("reviewer_visible")}
