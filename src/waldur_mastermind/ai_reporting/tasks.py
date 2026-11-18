import json
import logging
import re
import time
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
from waldur_mastermind.ai_reporting.permissions import role_denial

logger = logging.getLogger(__name__)

# Files are deleted in chunks: each delete also removes the stored file, so
# one big delete would hold a long transaction open.
_FILE_CLEANUP_CHUNK_SIZE = 100

# Fetching a finished file is quick; this just stops one bad download from
# hanging the task.
_HARNESS_FILE_TIMEOUT_SECONDS = 60

# Waldur doesn't rely on the harness to behave: it may be compromised, or
# steered by text planted in Waldur data. So files are capped and checked.
_MAX_FILES = 20
_MAX_FILE_BYTES = 20 * 1024 * 1024
_MAX_ANSWER_CHARS = 100_000
_FILE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}")
# Allowed types, checked by content as well as name: an SVG or HTML file,
# even one named .png, could run script in the portal. None means text.
_FILE_SIGNATURES = {
    "png": (b"\x89PNG\r\n\x1a\n",),
    "jpg": (b"\xff\xd8\xff",),
    "jpeg": (b"\xff\xd8\xff",),
    "gif": (b"GIF87a", b"GIF89a"),
    "pdf": (b"%PDF-",),
    "xlsx": (b"PK\x03\x04",),
    "csv": None,
    "txt": None,
}


def _allowed_name(name) -> bool:
    return (
        isinstance(name, str)
        and bool(_FILE_NAME.fullmatch(name))
        and name.rsplit(".", 1)[-1].lower() in _FILE_SIGNATURES
    )


def _content_matches(name: str, content: bytes) -> bool:
    signatures = _FILE_SIGNATURES[name.rsplit(".", 1)[-1].lower()]
    if signatures is None:
        # Text: refuse markup, which a browser could render as a page.
        return not content.lstrip().startswith(b"<")
    return content.startswith(signatures)


def _check_status(response) -> None:
    # Redirects are never followed: the harness must answer itself, not send
    # Waldur on to some other address.
    if 300 <= response.status_code < 400:
        raise requests.HTTPError(
            f"Unexpected redirect from the harness ({response.status_code}).",
            response=response,
        )
    response.raise_for_status()


def _read_capped(response, limit: int) -> bytes:
    content = b""
    for chunk in response.iter_content(chunk_size=64 * 1024):
        content += chunk
        if len(content) > limit:
            raise ValueError(f"File is larger than {limit} bytes.")
    return content


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
        # The session is in the signed path, so it can't be swapped.
        path = f"/files/{filename}?session={message.session.uuid}"
        try:
            response = requests.get(
                connection.endpoint(path),
                headers={
                    "X-Waldur-User-Id": str(user.uuid),
                    **signing.sign_request(str(user.uuid), path, b""),
                },
                timeout=_HARNESS_FILE_TIMEOUT_SECONDS,
                allow_redirects=False,
                stream=True,
            )
            try:
                _check_status(response)
                content = _read_capped(response, _MAX_FILE_BYTES)
            finally:
                response.close()
        except (requests.RequestException, ValueError):
            logger.exception(
                "ask_harness: could not fetch file %r for message %s",
                filename,
                message.pk,
            )
            continue
        if not _content_matches(filename, content):
            logger.warning(
                "ask_harness: dropped file %r for message %s: content doesn't match its type",
                filename,
                message.pk,
            )
            continue
        ReportingFile.objects.create(
            message=message,
            name=filename,
            file=ContentFile(content, name=filename),
        )


_FAILED_MESSAGE = (
    "The AI reporting service couldn't answer this question. Please try again later."
)
_TIMEOUT_MESSAGE = "This question took too long to answer. Try a narrower question."
_INTERRUPTED_MESSAGE = "This question was interrupted. Please ask it again."
_NOT_AVAILABLE_MESSAGE = "AI reporting is not available to you."

# How long past twice the request timeout a message may stay pending before
# fail_stale_reporting_messages gives up on it. Twice, because a stream can
# run one more read timeout past its deadline.
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
    # The harness keeps a separate conversation per session.
    body = {
        "prompt": message.prompt,
        "session": str(message.session.uuid),
        **_harness_overrides(),
    }
    # A harness from before per-session conversations keeps one per user, so
    # a session's first question restarts it.
    if not message.session.messages.filter(
        pk__lt=message.pk, status=ReportingMessage.Status.DONE
    ).exists():
        body["new_session"] = True
    # Encoded by hand so we sign exactly the bytes that are sent.
    data = json.dumps(body).encode("utf-8")
    timeout = config.AI_REPORTING_REQUEST_TIMEOUT_SECONDS
    # With stream=True the timeout only limits the gap between chunks, so the
    # whole question gets its own deadline.
    deadline = time.monotonic() + timeout
    response = requests.post(
        HarnessConnection.get().endpoint("/query"),
        headers={
            "X-Waldur-User-Id": str(user.uuid),
            "Content-Type": "application/json",
            # A harness that can't stream ignores this and sends one JSON body.
            "Accept": "application/x-ndjson, application/json",
            **signing.sign_request(str(user.uuid), "/query", data),
        },
        data=data,
        timeout=timeout,
        stream=True,
        allow_redirects=False,
    )
    try:
        _check_status(response)
        if "application/x-ndjson" in response.headers.get("Content-Type", ""):
            payload = _read_events(message, response, deadline)
        else:
            payload = response.json()
    finally:
        response.close()
    if not isinstance(payload, dict):
        raise ValueError("The harness response is not a JSON object.")
    return payload


def _read_events(message: ReportingMessage, response, deadline: float) -> dict:
    """Save each progress line on the message until the answer arrives."""
    last_progress = None
    for line in response.iter_lines():
        event = json.loads(line) if line else None
        kind = event.get("type") if isinstance(event, dict) else None
        # An answer is kept even if it arrives just after the deadline.
        if kind == "done":
            return event
        if time.monotonic() > deadline:
            raise requests.Timeout("The question ran past the request timeout.")
        if not line:
            continue
        if kind == "error":
            raise ValueError(f"The harness reported an error: {event.get('error')}")
        text = event.get("text") if kind == "progress" else None
        if isinstance(text, str) and text != last_progress:
            ReportingMessage.objects.filter(
                pk=message.pk, status=ReportingMessage.Status.PENDING
            ).update(progress=text[:200], modified=timezone.now())
            last_progress = text
    raise ValueError("The harness stream ended without an answer.")


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
    # It may have waited in the queue: check access again before sending.
    if not config.AI_REPORTING_ENABLED or not user.is_active or role_denial(user):
        _fail(message, user, _NOT_AVAILABLE_MESSAGE)
        return
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
    new_files = [name for name in payload.get("new_files") or [] if _allowed_name(name)]
    new_files = new_files[:_MAX_FILES]
    finished = _finish(
        message,
        user,
        usage,
        status=ReportingMessage.Status.DONE,
        answer=str(payload.get("answer") or "")[:_MAX_ANSWER_CHARS],
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
        - 2 * timedelta(seconds=config.AI_REPORTING_REQUEST_TIMEOUT_SECONDS)
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
