"""Talking to Formbricks: survey links, the Management API, webhook signatures.

Everything is read from the FormbricksConnection row, so the server, the API
key and the webhook secret are set through the API rather than deployment
settings.

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
from urllib.parse import urlencode

import requests
from django.core import signing

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

# Signs redirect_token, the hidden field that carries "this user, this
# proposal" through the chain of surveys and back. Formbricks' "Redirect to
# URL" ending is a plain browser GET, which carries neither the frontend's
# Authorization header nor a session, so this is how the redirect endpoint
# knows who is applying - and, in the webhook, that the answers really are
# for the proposal they name.
REDIRECT_TOKEN_SALT = "waldur_mastermind.proposal_forms.redirect_token"
# A survey link can sit in a browser tab for days; a round's application
# window is the natural bound.
REDIRECT_TOKEN_MAX_AGE_SECONDS = 30 * 24 * 60 * 60


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


# --- redirect tokens ------------------------------------------------------


def build_redirect_token(user, proposal) -> str:
    """Sign (user, proposal) together, so a token only ever speaks for one
    applicant on one proposal."""
    return signing.TimestampSigner(salt=REDIRECT_TOKEN_SALT).sign(
        f"{user.pk}:{proposal.uuid.hex}"
    )


def verify_redirect_token(token, proposal_uuid) -> int | None:
    """The user's pk the token was issued to, if it is genuine, unexpired and
    issued for this proposal; otherwise None."""
    if not token or not proposal_uuid:
        return None
    try:
        value = signing.TimestampSigner(salt=REDIRECT_TOKEN_SALT).unsign(
            token, max_age=REDIRECT_TOKEN_MAX_AGE_SECONDS
        )
    except signing.BadSignature:
        return None
    user_pk, _, token_proposal = value.partition(":")
    if token_proposal != _uuid_hex(proposal_uuid):
        return None
    try:
        return int(user_pk)
    except ValueError:
        return None


def _uuid_hex(value) -> str:
    return str(value).replace("-", "").lower()


# --- survey links ---------------------------------------------------------


def hidden_fields(user, proposal) -> dict:
    """The hidden fields every survey link carries.

    Each survey in a flow must declare these as Hidden Fields in Formbricks,
    or they are not passed on to its ending and the webhook. proposal_uuid
    and redirect_token are what the webhook trusts; the lead's name and email
    only help a call manager find responses inside Formbricks.
    """
    return {
        "proposal_uuid": proposal.uuid.hex,
        "call_uuid": proposal.round.call.uuid.hex,
        "round_uuid": proposal.round.uuid.hex,
        "redirect_token": build_redirect_token(user, proposal),
        "lead_name": user.full_name,
        "lead_email": user.email,
    }


# Hidden fields this app adds itself: echoed back as answers in the webhook,
# but not something the applicant answered.
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


def build_survey_url(survey_id, fields: dict, prefill: dict | None = None) -> str:
    """A link to a survey, with hidden fields - and, to edit an earlier
    answer, the answers to prefill - as query parameters."""
    params = {**(prefill or {}), **{k: v for k, v in fields.items() if v is not None}}
    return f"{connection().public_base_url}/s/{survey_id}?{urlencode(params)}"


def prefill_from_answers(answers: dict) -> dict:
    """Earlier answers as URL prefill parameters, for editing a step.

    Formbricks prefills a question from a query parameter named by its id;
    a multiple choice takes its labels comma-separated. Answers that cannot
    be prefilled (files, matrices, addresses) are left for the applicant to
    give again, as are this app's own hidden fields, which are set afresh.
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
        raise FormbricksError(f"Formbricks {method} {path} failed: {e}") from e
    except (requests.RequestException, ValueError) as e:
        raise FormbricksError(f"Formbricks {method} {path} failed: {e}") from e


def _get(path, conn=None, params=None):
    return _request("GET", path, conn, params=params)


def check_connection(conn) -> dict:
    """What the Management API says about this key: raises FormbricksError if
    it cannot be reached or rejects the key."""
    return _get("/api/v1/management/me", conn)


def get_response(response_id) -> dict:
    """A response's current answers, {question_id: answer}."""
    return _get(f"/api/v1/management/responses/{response_id}")["data"]["data"]


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
