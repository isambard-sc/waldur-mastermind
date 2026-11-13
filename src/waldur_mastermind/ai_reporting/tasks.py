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
    connection = HarnessConnection.get()
    for filename in filenames:
        path = f"/files/{filename}"
        try:
            response = requests.get(
                connection.endpoint(path),
                # Same headers as the /query call.
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


_FAILED_MESSAGE = (
    "The AI reporting service couldn't answer this question. Please try again later."
)
_TIMEOUT_MESSAGE = "This question took too long to answer. Try a narrower question."
_INTERRUPTED_MESSAGE = "This question was interrupted. Please ask it again."

# How long past the request timeout a message may stay pending before
# fail_stale_reporting_messages gives up on it.
_STALE_PENDING_MARGIN = timedelta(minutes=5)


def _count(usage: dict, key: str) -> int:
    value = usage.get(key)
    return value if isinstance(value, int) and value >= 0 else 0


def _finish(message: ReportingMessage, user, usage: dict, **fields) -> bool:
    """Save the outcome and its usage record, but only if the message is
    still pending - the stale check may already have failed it."""
    fields["modified"] = timezone.now()
    updated = ReportingMessage.objects.filter(
        pk=message.pk, status=ReportingMessage.Status.PENDING
    ).update(**fields)
    if not updated:
        return False
    for name, value in fields.items():
        setattr(message, name, value)
    ReportingUsageRecord.objects.create(
        user=user,
        status=message.status,
        input_tokens=message.input_tokens,
        output_tokens=message.output_tokens,
        cache_read_tokens=_count(usage, "cache_read_tokens"),
        cache_write_tokens=_count(usage, "cache_write_tokens"),
    )
    return True


def _fail(message: ReportingMessage, user, error: str) -> None:
    _finish(
        message, user, {}, status=ReportingMessage.Status.FAILED, error_message=error
    )


def _query_harness(message: ReportingMessage, user) -> dict:
    body = {"prompt": message.prompt, **_harness_overrides()}
    # The harness keeps one conversation per user, so a session's first
    # question restarts it.
    if not message.session.messages.filter(
        pk__lt=message.pk, status=ReportingMessage.Status.DONE
    ).exists():
        body["new_session"] = True
    # Encoded by hand so we sign exactly the bytes that are sent.
    data = json.dumps(body).encode("utf-8")
    response = requests.post(
        HarnessConnection.get().endpoint("/query"),
        headers={
            # The harness keys conversations on the user id; it doesn't
            # read the session id yet.
            "X-Waldur-User-Id": str(user.uuid),
            "X-Waldur-Session-Id": str(message.session.uuid),
            "Content-Type": "application/json",
            **signing.sign_request(str(user.uuid), "/query", data),
        },
        data=data,
        timeout=config.AI_REPORTING_REQUEST_TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    payload = response.json()
    if not isinstance(payload, dict):
        raise ValueError("The harness response is not a JSON object.")
    return payload


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
    if message.status != ReportingMessage.Status.PENDING:
        return

    user = message.session.user
    try:
        payload = _query_harness(message, user)
    except requests.Timeout:
        logger.exception("ask_harness: harness timed out for message %s", message_id)
        _fail(message, user, _TIMEOUT_MESSAGE)
        return
    # Anything else, including Celery's soft time limit, must still end the
    # message, or it would stay pending and block the user's next question.
    except Exception:
        logger.exception("ask_harness: harness call failed for message %s", message_id)
        _fail(message, user, _FAILED_MESSAGE)
        return

    usage = payload.get("usage")
    if not isinstance(usage, dict):
        usage = {}
    new_files = [
        name for name in payload.get("new_files") or [] if isinstance(name, str)
    ]
    finished = _finish(
        message,
        user,
        usage,
        status=ReportingMessage.Status.DONE,
        answer=payload.get("answer") or "",
        new_files=new_files,
        input_tokens=_count(usage, "input_tokens"),
        output_tokens=_count(usage, "output_tokens"),
    )
    if finished and new_files:
        _copy_files_from_harness(message, user, new_files)


@shared_task(name="waldur_mastermind.ai_reporting.fail_stale_reporting_messages")
def fail_stale_reporting_messages():
    """Fail messages still pending well past the request timeout. Their task
    was lost, for example to a worker restart."""
    cutoff = (
        timezone.now()
        - timedelta(seconds=config.AI_REPORTING_REQUEST_TIMEOUT_SECONDS)
        - _STALE_PENDING_MARGIN
    )
    stale = ReportingMessage.objects.filter(
        status=ReportingMessage.Status.PENDING, created__lt=cutoff
    ).select_related("session__user")
    count = 0
    for message in stale:
        _fail(message, message.session.user, _INTERRUPTED_MESSAGE)
        count += 1
    if count:
        logger.info("Failed %d AI reporting message(s) left pending", count)
    return {"failed_count": count}


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
