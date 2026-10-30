"""Setting up a flow's surveys in Formbricks, so nobody has to by hand.

For each survey a flow uses, Waldur needs:

- single-use links on, unencrypted: Waldur mints one link per applicant and
  form, and recognises the response by the link's id;
- the hidden fields `proposal_uuid`, `call_uuid` and `round_uuid`, so staff
  browsing Formbricks can see whose response is whose, and filter by call
  and round (Waldur itself trusts only the link);
- every ending redirecting back to the proposal in Waldur.

("Anonymize responses", which stops Formbricks keeping the page URL, browser
and country with each response, is worth turning on by hand where a
Formbricks version has it. Sync leaves it alone: Formbricks 4.9 reports the
setting but does not keep it, so it could never be in sync there.)

plan() works out what is missing, without changing anything; apply() makes
those changes. Formbricks merges an update into the stored survey, so only
these settings are ever sent: questions, logic, styling and everything else
are never written. Only surveys that are a step of a flow are touched.
"""

import logging
import secrets
import string

from django.urls import reverse

from . import client

logger = logging.getLogger(__name__)

PROPOSAL_HIDDEN_FIELD = "proposal_uuid"
# Set on every link Waldur issues. Labels only: an applicant can edit them in
# the link, so Waldur never reads them back.
HIDDEN_FIELDS = (PROPOSAL_HIDDEN_FIELD, "call_uuid", "round_uuid")
RETURN_LABEL = "Back to your proposal"


def return_url(api_base_url, survey_id) -> str:
    """Where a survey's endings send the applicant: Waldur's return endpoint,
    which takes them on to the proposal in HomePort. Formbricks fills in the
    #recall:...# part from the hidden field when the survey ends."""
    path = reverse("proposal-form-return")
    return (
        f"{api_base_url.rstrip('/')}{path}?survey={survey_id}"
        f"&{PROPOSAL_HIDDEN_FIELD}=#recall:{PROPOSAL_HIDDEN_FIELD}/fallback:#"
    )


def _new_ending_id() -> str:
    # Formbricks ids are cuid2: lower-case letters and digits, starting with
    # a letter.
    alphabet = string.ascii_lowercase + string.digits
    return "c" + "".join(secrets.choice(alphabet) for _ in range(23))


def plan(survey: dict, ending_url: str) -> dict:
    """What has to change in a survey: {"changes": {setting: new value},
    "notes": [what each change does, readably], "problems": [what Waldur
    cannot fix itself]}."""
    changes = {}
    notes = []
    problems = []

    if survey.get("type") != "link":
        problems.append(
            f"The survey is a {survey.get('type') or 'non-link'} survey; it must be a "
            "link survey to be filled in from Waldur."
        )
    status = survey.get("status")
    if status != "inProgress":
        problems.append(
            f"The survey is {status or 'not published'}: applicants cannot fill it "
            "in until it is published (in progress) in Formbricks."
        )

    single_use = survey.get("singleUse") or {}
    if not single_use.get("enabled") or single_use.get("isEncrypted"):
        changes["singleUse"] = {
            **single_use,
            "enabled": True,
            "isEncrypted": False,
        }
        notes.append("Turn on single-use links (unencrypted).")

    hidden = survey.get("hiddenFields") or {}
    field_ids = list(hidden.get("fieldIds") or [])
    missing_fields = [f for f in HIDDEN_FIELDS if f not in field_ids]
    if not hidden.get("enabled") or missing_fields:
        changes["hiddenFields"] = {
            **hidden,
            "enabled": True,
            "fieldIds": field_ids + missing_fields,
        }
        if missing_fields:
            notes.append(f"Add the hidden fields {', '.join(missing_fields)}.")
        else:
            notes.append("Turn on hidden fields.")

    endings = survey.get("endings") or []
    new_endings = []
    for ending in endings:
        if ending.get("type") == "redirectToUrl" and ending.get("url") == ending_url:
            new_endings.append(ending)
            continue
        new_endings.append(
            {
                "id": ending["id"],
                "type": "redirectToUrl",
                "url": ending_url,
                "label": ending.get("label") or RETURN_LABEL,
            }
        )
    if not new_endings:
        new_endings.append(
            {
                "id": _new_ending_id(),
                "type": "redirectToUrl",
                "url": ending_url,
                "label": RETURN_LABEL,
            }
        )
    if new_endings != endings:
        changes["endings"] = new_endings
        replaced = sum(1 for old, new in zip(endings, new_endings) if old != new)
        if endings:
            notes.append(
                f"Make {replaced} of {len(endings)} ending(s) redirect back to the "
                "proposal in Waldur."
            )
        else:
            notes.append("Add an ending that redirects back to the proposal in Waldur.")

    return {"changes": changes, "notes": notes, "problems": problems}


def check_flow(flow, api_base_url) -> list:
    """Each step's survey as Formbricks has it now, and what Sync would
    change. Reads only."""
    results = []
    for step in flow.steps:
        result = {
            "key": step["key"],
            "survey_id": step["survey_id"],
            "survey_name": "",
            "changes": [],
            "problems": [],
            "questions": [],
        }
        try:
            survey = client.get_survey_definition(step["survey_id"])
        except client.FormbricksError as e:
            result["problems"].append(str(e))
        else:
            planned = plan(survey, return_url(api_base_url, step["survey_id"]))
            result["survey_name"] = survey.get("name") or ""
            result["changes"] = planned["notes"]
            result["problems"] = planned["problems"]
            result["questions"] = client.survey_questions(survey)
        result["in_sync"] = not result["changes"] and not result["problems"]
        results.append(result)
    return results


def sync_flow(flow, api_base_url, user=None) -> list:
    """Make each step's survey ready, re-reading it immediately before
    writing so the change is worked out against the survey as it is now.
    Stores what each survey asks on the flow. Returns check_flow's shape,
    after the changes."""
    synced = {}
    for step in flow.steps:
        survey_id = step["survey_id"]
        try:
            survey = client.get_survey_definition(survey_id)
        except client.FormbricksError:
            continue  # reported by the check below
        planned = plan(survey, return_url(api_base_url, survey_id))
        if planned["changes"]:
            survey = client.update_survey(survey_id, planned["changes"])
            logger.info(
                "Formbricks survey %s updated by %s: %s",
                survey_id,
                getattr(user, "username", "system"),
                ", ".join(sorted(planned["changes"])),
            )
        synced[survey_id] = {
            "name": survey.get("name") or "",
            "questions": client.survey_questions(survey),
        }
    flow.survey_schemas = synced
    flow.save(update_fields=["survey_schemas", "modified"])
    return check_flow(flow, api_base_url)
