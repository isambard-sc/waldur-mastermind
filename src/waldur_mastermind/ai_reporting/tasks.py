import json
import logging
import re
import time
from datetime import timedelta

import requests
from celery import shared_task
from constance import config
from django.core.files.base import ContentFile
from django.db import transaction
from django.utils import timezone

from waldur_mastermind.ai_reporting import signing
from waldur_mastermind.ai_reporting.models import (
    HarnessConnection,
    ReportingFile,
    ReportingMessage,
    ReportingSession,
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
# All of a message's files together. The message stays pending meanwhile.
_FILES_DEADLINE_SECONDS = 180

# Waldur doesn't rely on the harness to behave: it may be compromised, or
# steered by text planted in Waldur data. So files are capped and checked.
_MAX_FILES = 20
_MAX_FILE_BYTES = 20 * 1024 * 1024
# All of one message's files, and any single line or body from the harness.
_MAX_TOTAL_FILE_BYTES = 50 * 1024 * 1024
_MAX_LINE_BYTES = 1024 * 1024
_MAX_ANSWER_CHARS = 100_000
_MAX_TITLE_CHARS = 100
# Messages are deleted in chunks for the same reason as files: each one
# deletes its stored files too.
_MESSAGE_CLEANUP_CHUNK_SIZE = 100
# Far above any real question; keeps totals clear of the integer columns.
_MAX_TOKEN_COUNT = 10_000_000
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
    content = bytearray()
    for chunk in response.iter_content(chunk_size=64 * 1024):
        content += chunk
        if len(content) > limit:
            raise ValueError(f"File is larger than {limit} bytes.")
    return bytes(content)


def _harness_overrides() -> dict:
    """The settings the harness takes from Waldur. The model is the harness's
    own (WALDUR_AGENT_MODEL), next to the IAM policy that allows it."""
    overrides = {"max_turns": config.AI_REPORTING_MAX_TURNS}
    if config.AI_REPORTING_NAME:
        overrides["name"] = config.AI_REPORTING_NAME
    if config.AI_REPORTING_CUSTOM_INSTRUCTIONS:
        overrides["custom_instructions"] = config.AI_REPORTING_CUSTOM_INSTRUCTIONS
    if config.AI_REPORTING_HISTORY_QUESTIONS != -1:
        overrides["history_questions"] = config.AI_REPORTING_HISTORY_QUESTIONS
    return overrides


def _clean_title(value) -> str:
    if not isinstance(value, str):
        return ""
    return " ".join(value.split())[:_MAX_TITLE_CHARS]


def _new_file_names(payload: dict) -> list[str]:
    names = payload.get("new_files")
    if not isinstance(names, list):
        return []
    allowed = dict.fromkeys(name for name in names if _allowed_name(name))
    return list(allowed)[:_MAX_FILES]


def _fetch_files(
    message: ReportingMessage, user, filenames: list[str]
) -> list[tuple[str, bytes]]:
    """Download and check each reported file. A failed download is logged
    and skipped - the text answer is still useful without it."""
    connection = HarnessConnection.get()
    deadline = time.monotonic() + _FILES_DEADLINE_SECONDS
    files = []
    total = 0
    for filename in filenames:
        if total >= _MAX_TOTAL_FILE_BYTES:
            logger.warning(
                "ask_harness: the files of message %s are over the total size cap",
                message.pk,
            )
            break
        if time.monotonic() > deadline:
            logger.warning(
                "ask_harness: ran out of time for the files of message %s",
                message.pk,
            )
            break
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
                content = _read_capped(
                    response, min(_MAX_FILE_BYTES, _MAX_TOTAL_FILE_BYTES - total)
                )
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
        files.append((filename, content))
        total += len(content)
    return files


_FAILED_MESSAGE = (
    "The AI reporting service couldn't answer this question. Please try again later."
)
_TIMEOUT_MESSAGE = "This question took too long to answer. Try a narrower question."
_INTERRUPTED_MESSAGE = "This question was interrupted. Please ask it again."
_BUSY_MESSAGE = (
    "AI reporting is busy answering other questions. Please try again in a few minutes."
)
_NOT_AVAILABLE_MESSAGE = "AI reporting is not available to you."
_NOT_CONFIGURED_MESSAGE = (
    "AI reporting isn't set up yet: the harness signing key is missing. "
    "Ask an administrator."
)

# Time limits; docs/guides/ai-reporting.md has the full table. Waldur owns the
# deadline and sends the harness a shorter one, so the harness's "ran out of
# time" answer arrives first. Timeout + one read gap + the files (180 s) stays
# below Celery's 1200 s soft limit.
_REQUEST_TIMEOUT_SECONDS = 600
_HARNESS_DEADLINE_SECONDS = 540
# The longest the harness goes quiet: it reports progress before every model
# call, tool and fetched page, and a model call is cut to the time left.
_MAX_READ_GAP_SECONDS = 360
# A pending message with no progress for the timeout plus this has lost its
# task (fail_stale_reporting_messages).
_STALE_PENDING_MARGIN = timedelta(minutes=5)


class _RetryDelete(Exception):
    """A harness delete worth trying again: busy (409), down or unreachable."""


class HarnessFailed(Exception):
    """The harness gave up on the question, with the tokens it used so far."""

    def __init__(self, error, usage):
        super().__init__(f"The harness reported an error: {error}")
        self.usage = usage if isinstance(usage, dict) else {}


def _count(usage: dict, key: str) -> int:
    value = usage.get(key)
    # bool is an int in Python.
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        return 0
    return min(value, _MAX_TOKEN_COUNT)


def _finish(message: ReportingMessage, user, usage: dict, files=(), **fields) -> bool:
    """Save the outcome, its files and its usage record together, but only
    if the message is still pending - the stale check may have failed it."""
    fields["modified"] = timezone.now()
    with transaction.atomic():
        updated = ReportingMessage.objects.filter(
            pk=message.pk, status=ReportingMessage.Status.PENDING
        ).update(**fields)
        if not updated:
            return False
        for name, value in fields.items():
            setattr(message, name, value)
        for filename, content in files:
            ReportingFile.objects.create(
                message=message,
                name=filename,
                file=ContentFile(content, name=filename),
            )
        ReportingUsageRecord.objects.create(
            user=user,
            status=message.status,
            input_tokens=message.input_tokens,
            output_tokens=message.output_tokens,
            cache_read_tokens=_count(usage, "cache_read_tokens"),
            cache_write_tokens=_count(usage, "cache_write_tokens"),
        )
    return True


def _fail(
    message: ReportingMessage, user, error: str, usage: dict | None = None
) -> None:
    usage = usage or {}
    _finish(
        message,
        user,
        usage,
        status=ReportingMessage.Status.FAILED,
        error_message=error,
        input_tokens=_count(usage, "input_tokens"),
        output_tokens=_count(usage, "output_tokens"),
    )


def _query_harness(message: ReportingMessage, user, seen_usage: dict) -> dict:
    # The harness keeps a separate conversation per session.
    body = {
        "prompt": message.prompt,
        "session": str(message.session.uuid),
        "deadline_seconds": _HARNESS_DEADLINE_SECONDS,
        **_harness_overrides(),
    }
    # Encoded by hand so we sign exactly the bytes that are sent.
    data = json.dumps(body).encode("utf-8")
    timeout = _REQUEST_TIMEOUT_SECONDS
    # With stream=True the timeout only limits the gap between chunks, so the
    # whole question gets its own deadline.
    deadline = time.monotonic() + timeout
    response = requests.post(
        HarnessConnection.get().endpoint("/query"),
        headers={
            "X-Waldur-User-Id": str(user.uuid),
            "Content-Type": "application/json",
            "Accept": "application/x-ndjson",
            **signing.sign_request(str(user.uuid), "/query", data),
        },
        data=data,
        timeout=(10, min(timeout, _MAX_READ_GAP_SECONDS)),
        stream=True,
        allow_redirects=False,
    )
    try:
        _check_status(response)
        if "application/x-ndjson" not in response.headers.get("Content-Type", ""):
            raise ValueError("The harness did not reply with a stream.")
        payload = _read_events(message, response, deadline, seen_usage)
    finally:
        response.close()
    if not isinstance(payload, dict):
        raise ValueError("The harness response is not a JSON object.")
    return payload


def _lines(response):
    """The stream's lines, each capped at _MAX_LINE_BYTES. A read timeout
    inside the stream surfaces as a ConnectionError, so it's turned back into
    a timeout."""
    pending = b""
    try:
        for chunk in response.iter_content(chunk_size=64 * 1024):
            pending += chunk
            *lines, pending = pending.split(b"\n")
            yield from lines
            if len(pending) > _MAX_LINE_BYTES:
                raise ValueError("A line from the harness is too long.")
    except requests.ConnectionError as exc:
        raise requests.Timeout("The harness stopped sending.") from exc
    if pending:
        yield pending


def _read_events(
    message: ReportingMessage, response, deadline: float, seen_usage: dict
) -> dict:
    """Save each progress line, and the token totals so far, on the message
    until the answer arrives. seen_usage keeps the latest totals, so they can
    still be recorded if the question fails."""
    last_progress = last_usage = None
    for line in _lines(response):
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
            raise HarnessFailed(event.get("error"), event.get("usage"))
        if kind != "progress":
            continue
        fields = {}
        text = event.get("text")
        if isinstance(text, str) and text != last_progress:
            fields["progress"] = text[:200]
            last_progress = text
        usage = event.get("usage")
        if isinstance(usage, dict) and usage != last_usage:
            seen_usage.clear()
            seen_usage.update(usage)
            fields["input_tokens"] = _count(usage, "input_tokens")
            fields["output_tokens"] = _count(usage, "output_tokens")
            last_usage = usage
        if fields:
            ReportingMessage.objects.filter(
                pk=message.pk, status=ReportingMessage.Status.PENDING
            ).update(**fields, modified=timezone.now())
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
    # The harness rejects unsigned requests, so say what's wrong instead.
    if not HarnessConnection.get().is_signing_configured:
        logger.error("ask_harness: no signing key is set (AI reporting > Connection)")
        _fail(message, user, _NOT_CONFIGURED_MESSAGE)
        return
    # Tokens spent before a failure still count towards the limits, so each
    # failure records the latest totals the harness sent.
    seen_usage: dict = {}
    try:
        payload = _query_harness(message, user, seen_usage)
    except requests.Timeout:
        logger.exception("ask_harness: harness timed out for message %s", message_id)
        _fail(message, user, _TIMEOUT_MESSAGE, seen_usage)
        return
    except HarnessFailed as exc:
        logger.exception("ask_harness: harness failed for message %s", message_id)
        _fail(message, user, _FAILED_MESSAGE, exc.usage or seen_usage)
        return
    except requests.HTTPError as exc:
        logger.exception("ask_harness: harness call failed for message %s", message_id)
        busy = exc.response is not None and exc.response.status_code == 429
        _fail(message, user, _BUSY_MESSAGE if busy else _FAILED_MESSAGE, seen_usage)
        return
    # Anything else, including Celery's soft time limit, must still end the
    # message, or it would stay pending and block the user's next question.
    except Exception:
        logger.exception("ask_harness: harness call failed for message %s", message_id)
        _fail(message, user, _FAILED_MESSAGE, seen_usage)
        return

    usage = seen_usage
    try:
        if isinstance(payload.get("usage"), dict):
            usage = payload["usage"]
        new_files = _new_file_names(payload)
        # Fetched before the message is done: the page stops checking at
        # done, and the user can't ask again (and keep the harness busy)
        # while it's still pending.
        files = _fetch_files(message, user, new_files) if new_files else []
        _finish(
            message,
            user,
            usage,
            files=files,
            status=ReportingMessage.Status.DONE,
            # Postgres can't store NUL bytes.
            answer=str(payload.get("answer") or "").replace("\x00", "")[
                :_MAX_ANSWER_CHARS
            ],
            title=_clean_title(payload.get("title")).replace("\x00", ""),
            new_files=new_files,
            input_tokens=_count(usage, "input_tokens"),
            output_tokens=_count(usage, "output_tokens"),
        )
    except Exception:
        logger.exception(
            "ask_harness: could not save the answer to message %s", message_id
        )
        _fail(message, user, _FAILED_MESSAGE, usage)


@shared_task(
    name="waldur_mastermind.ai_reporting.delete_harness_session",
    autoretry_for=(_RetryDelete,),
    retry_backoff=60,
    retry_backoff_max=3600,
    max_retries=8,
)
def delete_harness_session(user_uuid: str, session_uuid: str):
    """Delete a conversation's files, history and transcript on the harness
    once Waldur has deleted the conversation. Retried, with backoff, while a
    question is still running there or the harness can't be reached. The
    harness's own retention (SESSION_RETENTION_DAYS) catches anything this misses."""
    path = f"/sessions/{session_uuid}"
    try:
        response = requests.delete(
            HarnessConnection.get().endpoint(path),
            headers={
                "X-Waldur-User-Id": user_uuid,
                **signing.sign_request(user_uuid, path, b""),
            },
            timeout=_HARNESS_FILE_TIMEOUT_SECONDS,
            allow_redirects=False,
        )
    except requests.RequestException as exc:
        logger.warning(
            "delete_harness_session: harness unreachable for session %s, will retry",
            session_uuid,
        )
        raise _RetryDelete() from exc
    if response.status_code == 409 or response.status_code >= 500:
        logger.warning(
            "delete_harness_session: harness answered %s for session %s, will retry",
            response.status_code,
            session_uuid,
        )
        raise _RetryDelete()
    try:
        _check_status(response)
    except requests.HTTPError:
        logger.exception(
            "delete_harness_session: could not delete session %s on the harness",
            session_uuid,
        )


@shared_task(name="waldur_mastermind.ai_reporting.fail_stale_reporting_messages")
def fail_stale_reporting_messages():
    """Fail messages still pending well past the request timeout. Their task
    was lost, for example to a worker restart."""
    # From the last progress, which a running question updates every step.
    cutoff = (
        timezone.now()
        - timedelta(seconds=_REQUEST_TIMEOUT_SECONDS)
        - _STALE_PENDING_MARGIN
    )
    stale = ReportingMessage.objects.filter(
        status=ReportingMessage.Status.PENDING, modified__lt=cutoff
    ).select_related("session__user")
    count = 0
    for message in stale:
        # The worker is gone, so the totals saved from progress are the best left.
        usage = {
            "input_tokens": message.input_tokens,
            "output_tokens": message.output_tokens,
        }
        _fail(message, message.session.user, _INTERRUPTED_MESSAGE, usage)
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
    count = 0
    while True:
        pks = list(
            ReportingMessage.objects.filter(created__lt=cutoff)
            # A running question is left for the stale check, which records its usage.
            .exclude(status=ReportingMessage.Status.PENDING)
            .order_by()
            .values_list("pk", flat=True)[:_MESSAGE_CLEANUP_CHUNK_SIZE]
        )
        if not pks:
            break
        ReportingMessage.objects.filter(pk__in=pks).delete()
        count += len(pks)
    # A conversation is only a label for its messages.
    ReportingSession.objects.filter(created__lt=cutoff, messages__isnull=True).delete()

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
