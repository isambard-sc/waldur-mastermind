import json
import logging
from datetime import timedelta

import requests
from celery import shared_task
from constance import config
from django.core.files.base import ContentFile
from django.utils import timezone

from waldur_mastermind.ai_reporting import signing
from waldur_mastermind.ai_reporting.models import (
    HarnessConnection,
    ReportingFile,
    ReportingMessage,
    ReportingUsageRecord,
)

logger = logging.getLogger(__name__)

# Files are deleted in chunks: each delete also removes the stored file, so
# one big delete would hold a long transaction open.
_FILE_CLEANUP_CHUNK_SIZE = 100

# Fetching a finished file is quick; this just stops one bad download from
# hanging the task.
_HARNESS_FILE_TIMEOUT_SECONDS = 60


def _harness_overrides() -> dict:
    """Admin overrides for the harness, sent only when set, so untouched
    settings keep the harness's own defaults."""
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


def _copy_files_from_harness(
    message: ReportingMessage, user, filenames: list[str]
) -> None:
    """Copy each reported file into a ReportingFile. A failed download is
    logged and skipped - the text answer is still useful without it."""
    harness_url = HarnessConnection.get().base_url
    for filename in filenames:
        path = f"/files/{filename}"
        try:
            response = requests.get(
                f"{harness_url}{path}",
                # Same headers as the /query call in ask_harness.
                headers={
                    "X-Waldur-User-Id": str(user.uuid),
                    "X-Waldur-Session-Id": str(message.session.uuid),
                    **signing.sign_request(str(user.uuid), path, b""),
                },
                timeout=_HARNESS_FILE_TIMEOUT_SECONDS,
            )
            response.raise_for_status()
        except requests.RequestException:
            logger.exception(
                "ask_harness: could not fetch file %r for message %s",
                filename,
                message.pk,
            )
            continue
        ReportingFile.objects.create(
            message=message,
            name=filename,
            file=ContentFile(response.content, name=filename),
        )


def _record_usage(message: ReportingMessage, user) -> None:
    """Write the permanent usage record for a finished message, whether it
    succeeded or failed."""
    ReportingUsageRecord.objects.create(
        user=user,
        status=message.status,
        input_tokens=message.input_tokens,
        output_tokens=message.output_tokens,
    )


@shared_task(name="waldur_mastermind.ai_reporting.ask_harness")
def ask_harness(message_id: int):
    """Ask the harness one question and save the result. Runs in Celery
    because a single question can take several minutes."""
    try:
        message = ReportingMessage.objects.select_related("session__user").get(
            pk=message_id
        )
    except ReportingMessage.DoesNotExist:
        logger.error("ask_harness: ReportingMessage %s does not exist", message_id)
        return

    user = message.session.user

    try:
        # Encoded by hand so we sign exactly the bytes that are sent.
        body = json.dumps({"prompt": message.prompt, **_harness_overrides()}).encode(
            "utf-8"
        )
        response = requests.post(
            f"{HarnessConnection.get().base_url}/query",
            headers={
                # The harness keys conversations on the user id; it doesn't
                # read the session id yet.
                "X-Waldur-User-Id": str(user.uuid),
                "X-Waldur-Session-Id": str(message.session.uuid),
                "Content-Type": "application/json",
                **signing.sign_request(str(user.uuid), "/query", body),
            },
            data=body,
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
        _record_usage(message, user)
        return
    except ValueError:
        logger.exception(
            "ask_harness: harness returned a non-JSON response for message %s",
            message_id,
        )
        message.status = ReportingMessage.Status.FAILED
        message.error_message = "The harness returned an unexpected response."
        message.save(update_fields=["status", "error_message", "modified"])
        _record_usage(message, user)
        return

    usage = payload.get("usage") or {}
    message.status = ReportingMessage.Status.DONE
    message.answer = payload.get("answer", "")
    message.new_files = payload.get("new_files", [])
    message.input_tokens = usage.get("input_tokens", 0)
    message.output_tokens = usage.get("output_tokens", 0)
    message.save(
        update_fields=[
            "status",
            "answer",
            "new_files",
            "input_tokens",
            "output_tokens",
            "modified",
        ]
    )
    _record_usage(message, user)

    if message.new_files:
        _copy_files_from_harness(message, user, message.new_files)


@shared_task(name="waldur_mastermind.ai_reporting.cleanup_old_reporting_messages")
def cleanup_old_reporting_messages():
    """Delete messages older than AI_REPORTING_MESSAGE_RETENTION_DAYS. Their
    files are deleted too, including the stored bytes. Usage records are
    kept."""
    retention_days = config.AI_REPORTING_MESSAGE_RETENTION_DAYS
    if retention_days < 0:
        logger.info("Reporting message cleanup skipped: retention is disabled")
        return {"status": "disabled", "deleted_count": 0}

    cutoff = timezone.now() - timedelta(days=retention_days)
    old_messages = ReportingMessage.objects.filter(created__lt=cutoff)
    count = old_messages.count()
    if count:
        old_messages.delete()

    logger.info(
        "Deleted %d AI reporting message(s) older than %d days (cutoff %s)",
        count,
        retention_days,
        cutoff.date(),
    )
    return {"status": "ok", "deleted_count": count}


@shared_task(name="waldur_mastermind.ai_reporting.cleanup_old_reporting_files")
def cleanup_old_reporting_files():
    """Delete generated files older than AI_REPORTING_FILE_RETENTION_DAYS.
    Usually shorter than message retention, since files are bigger."""
    retention_days = config.AI_REPORTING_FILE_RETENTION_DAYS
    if retention_days < 0:
        logger.info("Reporting file cleanup skipped: retention is disabled")
        return {"status": "disabled", "deleted_count": 0}

    cutoff = timezone.now() - timedelta(days=retention_days)
    total_deleted = 0
    while True:
        pks = list(
            ReportingFile.objects.filter(created__lt=cutoff)
            .order_by()
            .values_list("pk", flat=True)[:_FILE_CLEANUP_CHUNK_SIZE]
        )
        if not pks:
            break
        ReportingFile.objects.filter(pk__in=pks).delete()
        total_deleted += len(pks)

    logger.info(
        "Deleted %d AI reporting file(s) older than %d days (cutoff %s)",
        total_deleted,
        retention_days,
        cutoff.date(),
    )
    return {"status": "ok", "deleted_count": total_deleted}
