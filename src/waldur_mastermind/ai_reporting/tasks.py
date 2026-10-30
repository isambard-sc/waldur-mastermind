import logging

import requests
from celery import shared_task
from constance import config
from django.conf import settings
from django.core.files.base import ContentFile

from waldur_mastermind.ai_reporting.models import ReportingFile, ReportingMessage

logger = logging.getLogger(__name__)

# A single file fetch is just a read of bytes the harness already produced -
# nowhere near as slow as a /query turn, but still bounded so one bad
# download can't hold up the task indefinitely. Not Constance-driven like the
# /query timeout below - it's a much smaller, less variable operation with no
# admin-facing reason to tune it separately.
_HARNESS_FILE_TIMEOUT_SECONDS = 60


def _harness_overrides() -> dict:
    """The admin-configurable AI_REPORTING_* Constance overrides, as the
    optional fields http_service.py's /query accepts - only included when
    set away from their "no override" default (empty string / -1), so an
    admin who hasn't touched a setting gets exactly today's harness
    behavior, not a value that happens to match its own hardcoded default."""
    overrides = {}
    if config.AI_REPORTING_MODEL:
        overrides["model"] = config.AI_REPORTING_MODEL
    if config.AI_REPORTING_NAME:
        overrides["name"] = config.AI_REPORTING_NAME
    if config.AI_REPORTING_CUSTOM_INSTRUCTIONS:
        overrides["custom_instructions"] = config.AI_REPORTING_CUSTOM_INSTRUCTIONS
    if config.AI_REPORTING_MAX_TURNS != -1:
        overrides["max_turns"] = config.AI_REPORTING_MAX_TURNS
    if config.AI_REPORTING_HISTORY_LIMIT != -1:
        overrides["history_limit"] = config.AI_REPORTING_HISTORY_LIMIT
    return overrides


def _copy_files_from_harness(message: ReportingMessage, user, filenames: list[str]) -> None:
    """Copy each file the harness reported into its own ReportingFile row.

    Best-effort per file: one failing download is logged and skipped rather
    than failing the whole message - the text answer is still good even if a
    chart didn't copy across.
    """
    for filename in filenames:
        try:
            response = requests.get(
                f"{settings.AI_REPORTING_HARNESS_URL}/files/{filename}",
                # Same headers as the /query call above - the harness keys
                # its conversation store on the user id alone today, but
                # sending both keeps this call consistent with that one.
                headers={
                    "X-Waldur-User-Id": str(user.uuid),
                    "X-Waldur-Session-Id": str(message.session.uuid),
                },
                timeout=_HARNESS_FILE_TIMEOUT_SECONDS,
            )
            response.raise_for_status()
        except requests.RequestException:
            logger.exception(
                "ask_harness: could not fetch file %r for message %s", filename, message.pk
            )
            continue
        ReportingFile.objects.create(
            message=message, name=filename, file=ContentFile(response.content, name=filename)
        )


@shared_task(name="waldur_mastermind.ai_reporting.ask_harness")
def ask_harness(message_id: int):
    """Call the AI reporting harness for one ReportingMessage and record the result.

    Runs in a Celery worker, not a web request - this is what lets run() take
    minutes without tying up a Django web worker (see the design discussion in
    PROJECT_LOG.md / this app's docstrings for why).
    """
    try:
        message = ReportingMessage.objects.select_related("session__user").get(
            pk=message_id
        )
    except ReportingMessage.DoesNotExist:
        logger.error("ask_harness: ReportingMessage %s does not exist", message_id)
        return

    user = message.session.user

    try:
        response = requests.post(
            f"{settings.AI_REPORTING_HARNESS_URL}/query",
            headers={
                # Keys the harness's own conversation store - a user may have
                # several sessions (one per browser tab) running concurrently,
                # each with its own harness-side conversation. The user id is
                # sent too, even though the harness doesn't act on it yet,
                # since it's real identity (unlike the session uuid) and is
                # useful in the harness's own logs.
                "X-Waldur-User-Id": str(user.uuid),
                "X-Waldur-Session-Id": str(message.session.uuid),
            },
            json={"prompt": message.prompt, **_harness_overrides()},
            timeout=config.AI_REPORTING_REQUEST_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        payload = response.json()
    except requests.RequestException as exc:
        logger.exception(
            "ask_harness: request to the harness failed for message %s", message_id
        )
        message.status = ReportingMessage.Status.FAILED
        message.error_message = str(exc)
        message.save(update_fields=["status", "error_message", "modified"])
        return
    except ValueError:
        logger.exception(
            "ask_harness: harness returned a non-JSON response for message %s",
            message_id,
        )
        message.status = ReportingMessage.Status.FAILED
        message.error_message = "The harness returned an unexpected response."
        message.save(update_fields=["status", "error_message", "modified"])
        return

    message.status = ReportingMessage.Status.DONE
    message.answer = payload.get("answer", "")
    message.new_files = payload.get("new_files", [])
    message.save(
        update_fields=["status", "answer", "new_files", "modified"]
    )

    if message.new_files:
        _copy_files_from_harness(message, user, message.new_files)
