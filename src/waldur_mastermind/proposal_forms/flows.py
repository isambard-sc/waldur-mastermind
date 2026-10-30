"""The shape of a form flow's steps, and finding your way around them.

A flow (models.FormFlow) is an ordered list of steps; each step is one
Formbricks survey the applicant fills in, besides Waldur's own proposal
form:

    {
        "key": "compliance",          # stable id; answers are filed under it
        "label": "Compliance",        # what applicants and reviewers see
        "survey_id": "cmt4rw5cp...",  # the Formbricks survey
        "reviewer_visible": false,    # may reviewers read the answers?
    }

Answers are kept and shown, never copied onto the proposal: what Waldur
reads (title, summary, resources...) comes from its own proposal form.
Steps are checked when a flow is saved through the API, so a typo is refused
there rather than turning up later.
"""

import re

from django.utils.text import slugify

STEP_KEYS = frozenset({"key", "label", "survey_id", "reviewer_visible"})

# Formbricks ids are cuid-style; the survey id also goes into a URL path.
SURVEY_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")


class FlowError(ValueError):
    """A flow's steps are not well-formed. The message says where."""


def validate_steps(steps) -> list:
    """The steps, checked and normalised; raises FlowError if they are not
    well-formed."""
    if not isinstance(steps, list) or not steps:
        raise FlowError("A flow needs at least one step.")

    cleaned = []
    seen_keys = set()
    seen_surveys = set()
    for index, step in enumerate(steps):
        where = f"Step {index + 1}"
        if not isinstance(step, dict):
            raise FlowError(f"{where} must be a mapping.")
        unknown = sorted(set(step) - STEP_KEYS)
        if unknown:
            raise FlowError(
                f"{where} has unknown key(s) {', '.join(unknown)}; "
                f"allowed: {', '.join(sorted(STEP_KEYS))}."
            )

        key = step.get("key")
        if not isinstance(key, str) or not key or slugify(key) != key:
            raise FlowError(
                f"{where}: key must be a slug (lower-case letters, digits, '-' "
                f"and '_'), e.g. 'compliance'."
            )
        where = f"Step {key!r}"
        if key in seen_keys:
            raise FlowError(f"{where} appears twice: step keys must be unique.")
        seen_keys.add(key)

        survey_id = step.get("survey_id")
        if not isinstance(survey_id, str) or not SURVEY_ID_PATTERN.match(survey_id):
            raise FlowError(
                f"{where}: survey_id must be a Formbricks id (letters, digits, '-' "
                "and '_')."
            )
        if survey_id in seen_surveys:
            raise FlowError(
                f"{where}: survey {survey_id!r} is used by another step; an "
                f"answer could not be told apart."
            )
        seen_surveys.add(survey_id)

        label = step.get("label")
        if not isinstance(label, str) or not label.strip():
            raise FlowError(f"{where}: label must be non-empty text.")

        reviewer_visible = step.get("reviewer_visible", False)
        if not isinstance(reviewer_visible, bool):
            raise FlowError(f"{where}: reviewer_visible must be true or false.")

        cleaned.append(
            {
                "key": key,
                "label": label.strip(),
                "survey_id": survey_id,
                "reviewer_visible": reviewer_visible,
            }
        )
    return cleaned


def get_step(steps, step_key):
    for step in steps:
        if step["key"] == step_key:
            return step
    return None


def reviewer_visible_keys(steps) -> set:
    return {step["key"] for step in steps if step.get("reviewer_visible")}
