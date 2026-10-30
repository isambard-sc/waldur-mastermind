"""Talking to Formbricks: single-use links, the Management API, webhook
signatures.

Everything is read from the FormbricksConnection row, so the server, the API
key and the webhook secret are set through the API rather than deployment
settings.

An applicant reaches a survey by a single-use link Waldur asks Formbricks for
(one response per link; reopening it resumes that response). Waldur records
the link's id against the proposal and form, and recognises the response by
it - nothing else in the response is trusted.

Formbricks signs webhooks per the Standard Webhooks spec. Checked against
Formbricks' own source (apps/web/lib/crypto.ts and
modules/response-pipeline/lib/process-webhook-delivery-job.ts): headers
webhook-id, webhook-timestamp and webhook-signature ("v1,<base64>"), over
"{id}.{timestamp}.{raw body}", keyed with the secret base64-DECODED - with or
without its "whsec_" prefix.
"""

import base64
import binascii
import hashlib
import hmac
import html
import logging
import re
import time
from urllib.parse import parse_qs, urlencode, urlsplit

import requests

from waldur_core.core.models import is_feature_enabled

from . import models

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT_SECONDS = 10

WEBHOOK_ID_HEADER = "webhook-id"
WEBHOOK_TIMESTAMP_HEADER = "webhook-timestamp"
WEBHOOK_SIGNATURE_HEADER = "webhook-signature"
# The Standard Webhooks recommendation: wide enough for clock skew and a
# delivery retry, narrow enough that a captured request cannot be replayed
# much later.
WEBHOOK_TIMESTAMP_TOLERANCE_SECONDS = 5 * 60


class FormbricksError(Exception):
    """Formbricks could not be reached, or answered with something unusable."""


# The site-wide switch: HomePort hides everything Formbricks while it is off.
FEATURE = "proposal.formbricks_forms"


def connection() -> models.FormbricksConnection:
    return models.FormbricksConnection.get()


def is_available() -> bool:
    """Whether calls may take applications through Formbricks now: the
    feature is on, and the connection is configured and enabled."""
    return is_feature_enabled(FEATURE) and connection().is_active


# Hidden fields that are not answers: proposal_uuid, which Waldur sets as a
# label for staff browsing Formbricks, and those an earlier version of this
# integration set. Left out wherever answers are shown.
HIDDEN_FIELD_KEYS = frozenset(
    {
        "proposal_uuid",
        "call_uuid",
        "round_uuid",
        "redirect_token",
        "lead_name",
        "lead_email",
    }
)


def prefill_from_answers(answers: dict) -> dict:
    """Earlier answers as URL prefill parameters, for editing a form.

    Formbricks prefills a question from a query parameter named by its id;
    a multiple choice takes its labels comma-separated. Answers that cannot
    be prefilled (files, matrices, addresses) are left for the applicant to
    give again, as are hidden fields, which are set afresh.
    """
    prefill = {}
    for question_id, answer in answers.items():
        if question_id in HIDDEN_FIELD_KEYS:
            continue
        if isinstance(answer, bool):
            continue
        if isinstance(answer, (str, int, float)):
            prefill[question_id] = answer
        elif isinstance(answer, list) and all(isinstance(a, str) for a in answer):
            prefill[question_id] = ",".join(answer)
    return prefill


def single_use_id(link_url) -> str:
    """The suId a single-use link carries."""
    values = parse_qs(urlsplit(link_url).query).get("suId") or [""]
    return values[0]


def with_params(link_url, params: dict) -> str:
    """The link with more query parameters: the proposal_uuid hidden field
    and, for an edit, the answers to prefill. The link's own (suId, and
    suToken on newer Formbricks) are kept and win."""
    parts = urlsplit(link_url)
    own = {k: v[0] for k, v in parse_qs(parts.query).items()}
    query = urlencode({**params, **own})
    return parts._replace(query=query).geturl()


# --- Management API -------------------------------------------------------


def _request(method, path, conn=None, json=None, params=None):
    conn = conn or connection()
    try:
        response = requests.request(
            method,
            f"{conn.management_base_url}{path}",
            headers={"x-api-key": conn.api_key},
            json=json,
            params=params,
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        return response.json()
    except requests.HTTPError as e:
        status = e.response.status_code
        if status in (401, 403):
            raise FormbricksError(
                f"Formbricks refused {method} {path} ({status}): the API key cannot "
                "reach it. Give the key access to the survey's project and "
                "environment, and make the survey visible to the whole workspace "
                "(Formbricks hides restricted surveys from API keys)."
            ) from e
        if status == 404:
            raise FormbricksError(f"Formbricks has no {path} (404).") from e
        detail = _error_detail(e.response)
        raise FormbricksError(
            f"Formbricks {method} {path} failed ({status})"
            + (f": {detail}" if detail else ".")
        ) from e
    except (requests.RequestException, ValueError) as e:
        raise FormbricksError(f"Formbricks {method} {path} failed: {e}") from e


def _error_detail(response) -> str:
    """Formbricks' own explanation of an error, from its JSON body."""
    try:
        body = response.json()
    except ValueError:
        return ""
    if not isinstance(body, dict):
        return ""
    detail = body.get("message") or body.get("error") or body.get("code") or ""
    return str(detail)[:300]


def _get(path, conn=None, params=None):
    return _request("GET", path, conn, params=params)


def check_connection(conn) -> int:
    """How many surveys the key can see: raises FormbricksError if Formbricks
    cannot be reached or rejects the key.

    Not /api/v1/management/me: Formbricks answers that with 400 for a key
    that reaches more than one environment, which a key for a project's
    production and development environments does.
    """
    return len(list_surveys(conn))


def _strip_html(rich_text: str) -> str:
    return html.unescape(re.sub(r"<[^>]+>", "", rich_text)).strip()


def get_survey_definition(survey_id) -> dict:
    return _get(f"/api/v1/management/surveys/{survey_id}")["data"]


def _headline_text(headline) -> str:
    if isinstance(headline, dict):
        headline = headline.get("default") or next(iter(headline.values()), "")
    return _strip_html(headline or "")


def survey_labels(survey: dict) -> dict:
    """A survey's questions in the order asked, {question_id: label}.

    Questions live under data.blocks[].elements[] and each headline is a
    localised rich-text object ({"default": "<p>...</p>"}), as checked against
    a live Formbricks instance; the documented flat "questions" array is
    empty on current versions.
    """
    labels = {}
    for block in survey.get("blocks") or []:
        for element in block.get("elements") or []:
            labels[element["id"]] = _headline_text(element.get("headline"))
    for question in survey.get("questions") or []:
        # Older Formbricks versions: a flat list with plain-text headlines.
        labels.setdefault(question["id"], _headline_text(question.get("headline")))
    return labels


def survey_hidden_fields(survey: dict) -> set:
    hidden = survey.get("hiddenFields") or {}
    if hidden.get("enabled") is False:
        return set()
    return set(hidden.get("fieldIds") or [])


def get_survey(survey_id) -> dict:
    return survey_labels(get_survey_definition(survey_id))


def _choice_labels(element) -> list:
    return [
        _headline_text(choice.get("label")) for choice in element.get("choices") or []
    ]


def survey_questions(survey: dict) -> list:
    """A survey's questions in the order asked, for showing in Waldur:
    [{id, type, label, choices}]."""
    questions = []
    for block in survey.get("blocks") or []:
        for element in block.get("elements") or []:
            questions.append(
                {
                    "id": element["id"],
                    "type": element.get("type", ""),
                    "label": _headline_text(element.get("headline")),
                    "choices": _choice_labels(element),
                }
            )
    if not questions:
        # Older Formbricks versions: a flat list of questions.
        for question in survey.get("questions") or []:
            questions.append(
                {
                    "id": question["id"],
                    "type": question.get("type", ""),
                    "label": _headline_text(question.get("headline")),
                    "choices": _choice_labels(question),
                }
            )
    return questions


SURVEY_PAGE_SIZE = 100


def list_surveys(conn=None) -> list:
    """Every survey the API key can see, across its projects and
    environments."""
    surveys = []
    offset = 0
    while True:
        page = _get(
            "/api/v1/management/surveys",
            conn,
            params={"limit": SURVEY_PAGE_SIZE, "offset": offset},
        )["data"]
        surveys.extend(page)
        if len(page) < SURVEY_PAGE_SIZE:
            return surveys
        offset += SURVEY_PAGE_SIZE


def mint_single_use_link(survey_id) -> str:
    """A new single-use link to the survey, from Formbricks (which signs it
    on versions that do). The survey must have single-use links on."""
    links = _get(
        f"/api/v1/management/surveys/{survey_id}/singleUseIds", params={"limit": 1}
    )["data"]
    if not links or not single_use_id(links[0]):
        raise FormbricksError(f"Formbricks gave no single-use link for {survey_id}.")
    return links[0]


RESPONSE_PAGE_SIZE = 100
# Responses come newest first; an open link's response is recent, so a fetch
# looks no further back than this many.
RESPONSE_PAGES_SCANNED = 20


def iter_survey_responses(survey_id):
    """A survey's responses, newest first, up to RESPONSE_PAGES_SCANNED
    pages."""
    for page_number in range(RESPONSE_PAGES_SCANNED):
        offset = page_number * RESPONSE_PAGE_SIZE
        page = _get(
            "/api/v1/management/responses",
            params={
                "surveyId": survey_id,
                "limit": RESPONSE_PAGE_SIZE,
                # "skip" on Formbricks 4.9, "offset" later.
                "skip": offset,
                "offset": offset,
            },
        )["data"]
        yield from page
        if len(page) < RESPONSE_PAGE_SIZE:
            return


def get_response_record(response_id) -> dict:
    """A whole response, as the webhook would carry it."""
    return _get(f"/api/v1/management/responses/{response_id}")["data"]


def delete_response(response_id):
    """Delete a response Waldur recorded. A response already gone counts as
    deleted."""
    try:
        _request("DELETE", f"/api/v1/management/responses/{response_id}")
    except FormbricksError as e:
        if "(404)" in str(e):
            return
        raise


def update_survey(survey_id, changes: dict) -> dict:
    """Change only the given survey settings: Formbricks merges an update
    into the stored survey, so anything not named is left as it is."""
    return _request("PUT", f"/api/v1/management/surveys/{survey_id}", json=changes)[
        "data"
    ]


# --- webhook signatures ---------------------------------------------------


def _signing_key(secret: str) -> bytes | None:
    """The secret as Formbricks uses it: base64-decoded, with or without
    the "whsec_" prefix. None if it does not decode.

    Treating an unprefixed secret as raw text - as the first version of this
    integration did - gives a different key from the one Formbricks signs
    with, and every signature fails.
    """
    encoded = secret[len("whsec_") :] if secret.startswith("whsec_") else secret
    try:
        return base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        return None


def sign(secret: str, webhook_id: str, timestamp: str, body: bytes) -> str:
    """The base64 signature Formbricks would send for this request."""
    key = _signing_key(secret)
    if key is None:
        raise ValueError("The webhook secret is not valid base64.")
    content = f"{webhook_id}.{timestamp}.".encode() + body
    return base64.b64encode(hmac.new(key, content, hashlib.sha256).digest()).decode()


def verify_signature(request) -> bool:
    """Whether the request was signed by Formbricks with our webhook secret.

    Always False while no secret is configured: an empty key would let anyone
    sign a request. On a mismatch, only what is safe to keep is logged - never
    the signature that was expected, which would let anyone who reads the
    logs forge a request within the timestamp window.
    """
    secret = connection().webhook_secret
    key = _signing_key(secret) if secret else None
    if not key:
        logger.warning("Formbricks webhook refused: no usable webhook secret set.")
        return False

    webhook_id = request.headers.get(WEBHOOK_ID_HEADER, "")
    timestamp = request.headers.get(WEBHOOK_TIMESTAMP_HEADER, "")
    signature_header = request.headers.get(WEBHOOK_SIGNATURE_HEADER, "")
    if not (webhook_id and timestamp and signature_header):
        logger.warning(
            "Formbricks webhook refused: missing headers (id=%s timestamp=%s "
            "signature=%s).",
            bool(webhook_id),
            bool(timestamp),
            bool(signature_header),
        )
        return False

    try:
        skew = abs(time.time() - int(timestamp))
    except ValueError:
        return False
    if skew > WEBHOOK_TIMESTAMP_TOLERANCE_SECONDS:
        logger.warning("Formbricks webhook refused: timestamp %ss off.", int(skew))
        return False

    content = f"{webhook_id}.{timestamp}.".encode() + request.body
    expected = base64.b64encode(hmac.new(key, content, hashlib.sha256).digest())
    # The header may carry several space-separated "v1,<sig>" entries while
    # a secret is being rotated; any one matching is enough.
    for entry in signature_header.split():
        version, _, provided = entry.partition(",")
        if version == "v1" and hmac.compare_digest(provided.encode(), expected):
            return True

    logger.warning(
        "Formbricks webhook refused: signature mismatch (%s signature(s) offered, "
        "body %s bytes). Check the webhook secret matches the one in Formbricks.",
        len(signature_header.split()),
        len(request.body),
    )
    return False
