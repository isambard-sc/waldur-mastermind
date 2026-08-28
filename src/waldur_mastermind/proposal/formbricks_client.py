"""Thin client for Formbricks.

Covers: inbound webhook signature verification, outbound Management API
calls (fetching a response's answers / a survey's question schema), and
survey-URL builders for redirecting applicants into a fresh or prefilled
survey.

Webhook signing is verified against
https://formbricks.com/docs/platform/features/integrations/webhooks -
Formbricks implements the Standard Webhooks spec. get_response()/get_survey()
are verified against this deployment's live Management API (2026-08-26) -
see their docstrings for what the real response shape actually looks like,
which differs from what the public docs describe.
"""

import base64
import hashlib
import hmac
import html
import logging
import re
import time
from urllib.parse import urlencode

import requests
from django.conf import settings

logger = logging.getLogger(__name__)

# Standard Webhooks spec (https://www.standardwebhooks.com/) - Formbricks
# sends all three of these on every webhook request.
WEBHOOK_ID_HEADER = "webhook-id"
WEBHOOK_TIMESTAMP_HEADER = "webhook-timestamp"
WEBHOOK_SIGNATURE_HEADER = "webhook-signature"

# Reject requests whose webhook-timestamp is further from "now" than this,
# per the spec's replay-attack guidance.
WEBHOOK_TIMESTAMP_TOLERANCE_SECONDS = 5 * 60

REQUEST_TIMEOUT_SECONDS = 10


def _proposal_settings():
    return settings.WALDUR_PROPOSAL


def _base_url():
    return _proposal_settings()["FORMBRICKS_BASE_URL"].rstrip("/")


def _management_api_base_url():
    # Deliberately distinct from _base_url(): this one needs to be reachable
    # from inside the waldur-mastermind containers (server-side Management
    # API calls), whereas _base_url() needs to be reachable from a Lead's
    # browser (survey links). See the FORMBRICKS_MANAGEMENT_API_URL comment
    # in extension.py for why these can't be the same value.
    return _proposal_settings()["FORMBRICKS_MANAGEMENT_API_URL"].rstrip("/")


def _api_headers():
    return {"x-api-key": _proposal_settings()["FORMBRICKS_API_KEY"]}


def _signing_key(secret):
    # Standard Webhooks secrets are conventionally "whsec_" + base64; fall
    # back to treating the secret as a raw passphrase if that prefix is
    # absent, since Formbricks' UI may hand out either form.
    if secret.startswith("whsec_"):
        return base64.b64decode(secret[len("whsec_") :])
    return secret.encode()


def verify_signature(request) -> bool:
    """Verify an inbound webhook request per the Standard Webhooks spec.

    signed_content = f"{webhook_id}.{webhook_timestamp}.{raw_body}"
    signature = base64(HMAC-SHA256(secret, signed_content))
    webhook-signature header value: "v1,{signature}" (space-separated if
    Formbricks ever signs with multiple secrets during rotation - accept
    any one of them matching).
    """
    webhook_id = request.headers.get(WEBHOOK_ID_HEADER, "")
    webhook_timestamp = request.headers.get(WEBHOOK_TIMESTAMP_HEADER, "")
    signature_header = request.headers.get(WEBHOOK_SIGNATURE_HEADER, "")
    if not (webhook_id and webhook_timestamp and signature_header):
        return False

    try:
        if (
            abs(time.time() - int(webhook_timestamp))
            > WEBHOOK_TIMESTAMP_TOLERANCE_SECONDS
        ):
            logger.warning("Formbricks webhook timestamp outside tolerance window.")
            return False
    except ValueError:
        return False

    secret = _proposal_settings()["FORMBRICKS_WEBHOOK_SECRET"]
    signed_content = f"{webhook_id}.{webhook_timestamp}.{request.body.decode()}"
    expected_signature = base64.b64encode(
        hmac.new(_signing_key(secret), signed_content.encode(), hashlib.sha256).digest()
    ).decode()

    provided_signatures = [
        part.split(",", 1)[1] for part in signature_header.split() if "," in part
    ]
    return any(
        hmac.compare_digest(provided, expected_signature)
        for provided in provided_signatures
    )


def lead_hidden_fields(user):
    """Hidden fields identifying the Lead, merged into every survey URL.

    Lets the call manager filter/search responses inside Formbricks itself
    by who submitted them, without cross-referencing Waldur.
    """
    return {"lead_name": user.full_name, "lead_email": user.email}


def build_survey_url(survey_id, **hidden_fields):
    """URL for a fresh (non-edit) attempt at a survey.

    hidden_fields (e.g. proposal_uuid=..., call_uuid=..., round_uuid=...)
    are passed as query params, matching Formbricks' hidden-field URL
    prefill convention.
    """
    query = urlencode({k: v for k, v in hidden_fields.items() if v is not None})
    return f"{_base_url()}/s/{survey_id}?{query}"


def build_prefilled_url(survey_id, response_data, **hidden_fields):
    """URL prefilling `response_data` ({question_id: answer}) plus hidden fields.

    Used only for editing - each question ID doubles as its own prefill
    query parameter, per Formbricks' URL prefill convention.
    """
    params = {
        **response_data,
        **{k: v for k, v in hidden_fields.items() if v is not None},
    }
    query = urlencode(params)
    return f"{_base_url()}/s/{survey_id}?{query}"


def get_response(survey_id, response_id):
    """Fetch a single response's answers from the Formbricks Management API.

    Returns {question_id: answer}. Used only by the edit-link builder -
    never by the reviewer view, which reads the stored FormStepResponse
    snapshot instead. `survey_id` isn't required by the lookup itself
    (Formbricks response IDs are addressed directly) but is accepted for a
    stable call-site signature and for logging context.

    Verified against a live response on this deployment: GET .../responses/{id}
    returns {"data": {..., "data": {question_id: answer, ...}, ...}} - i.e.
    exactly the shape assumed here. No change needed from the original
    best-effort implementation.
    """
    url = f"{_management_api_base_url()}/api/v1/management/responses/{response_id}"
    logger.debug("Fetching Formbricks response %s (survey %s)", response_id, survey_id)
    resp = requests.get(url, headers=_api_headers(), timeout=REQUEST_TIMEOUT_SECONDS)
    resp.raise_for_status()
    return resp.json()["data"]["data"]


def _strip_html(rich_text: str) -> str:
    return html.unescape(re.sub(r"<[^>]+>", "", rich_text)).strip()


def get_survey(survey_id):
    """Fetch a survey's question schema from the Formbricks Management API.

    Returns {question_id: label}.

    The original implementation assumed GET .../surveys/{id} returns
    questions as a flat "data.questions" array with a plain-string
    "headline" per question, matching the public docs. Checked against a
    live survey on this deployment (2026-08-26) and that's wrong on this
    version: "questions" is always an empty array. The actual question data
    lives under "data.blocks[].elements[]", and each element's "headline"
    is a localized rich-text object ({"<locale>": "<p>...</p>", ...}), not
    a plain string - so labels need HTML stripped to be usable as reviewer-
    facing text. This survey had no languages configured, so "default" is
    used as the locale key, falling back to whatever key is present for
    multi-language surveys.
    """
    url = f"{_management_api_base_url()}/api/v1/management/surveys/{survey_id}"
    resp = requests.get(url, headers=_api_headers(), timeout=REQUEST_TIMEOUT_SECONDS)
    resp.raise_for_status()
    survey = resp.json()["data"]

    labels = {}
    for block in survey.get("blocks", []):
        for element in block.get("elements", []):
            headline = element.get("headline") or {}
            raw_label = headline.get("default") or next(iter(headline.values()), "")
            labels[element["id"]] = _strip_html(raw_label)
    return labels
