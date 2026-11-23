"""Token and request limits for AI reporting (the AI_REPORTING_TOKEN_LIMIT_*
and AI_REPORTING_GLOBAL_* settings).

A simple query-based check rather than chat's locked counter: this is a
low-volume internal tool, so two requests racing past a limit together is
acceptable. -1 means unlimited.
"""

from datetime import timedelta

from constance import config
from django.db.models import Sum
from django.utils import timezone
from rest_framework.exceptions import Throttled

from waldur_mastermind.ai_reporting.models import (
    HarnessConnection,
    ReportingMessage,
    ReportingUsageRecord,
)

UNLIMITED = -1

# (Constance setting name, rolling window, label used in the error message).
_PER_USER_TOKEN_LIMITS = (
    ("AI_REPORTING_TOKEN_LIMIT_DAILY", timedelta(days=1), "daily"),
)


def _tokens_used_since(since, **filters) -> int:
    # Reads usage records, not messages: messages can be cleaned up before
    # the window ends, which would reset the limit early.
    # Counts cache tokens too, since most input is served from cache.
    # Each column is summed on its own: adding columns inside a row would be
    # done in the columns' integer type, which can overflow.
    columns = (
        "input_tokens",
        "output_tokens",
        "cache_read_tokens",
        "cache_write_tokens",
    )
    totals = ReportingUsageRecord.objects.filter(
        created__gte=since, **filters
    ).aggregate(**{column: Sum(column) for column in columns})
    return sum(value or 0 for value in totals.values())


def lock_asks() -> None:
    """Makes every ask take its turn until the transaction ends, so two can't
    both see no question pending, or both see a free slot. The harness
    connection is the one row every ask shares."""
    connection = HarnessConnection.get()
    HarnessConnection.objects.select_for_update().filter(pk=connection.pk).first()


def enforce_per_user_limit(user) -> None:
    """Raise Throttled (429) if `user` already has as many questions running
    as AI_REPORTING_MAX_QUESTIONS_PER_USER, each in its own conversation.
    Call after lock_asks()."""
    limit = max(config.AI_REPORTING_MAX_QUESTIONS_PER_USER, 1)
    running = ReportingMessage.objects.filter(
        session__user=user, status=ReportingMessage.Status.PENDING
    ).count()
    if running >= limit:
        raise Throttled(
            wait=60,
            detail=f"You already have {running} questions running. Wait for one to finish.",
        )


def enforce_concurrency_limit() -> None:
    """Raise Throttled (429) if too many questions are already running. Each
    one holds a Celery worker shared with the rest of Waldur, so there is no
    unlimited. Call after lock_asks()."""
    limit = max(config.AI_REPORTING_MAX_CONCURRENT_QUESTIONS, 1)
    running = ReportingMessage.objects.filter(
        status=ReportingMessage.Status.PENDING
    ).count()
    if running >= limit:
        raise Throttled(
            wait=60,
            detail="AI reporting is busy answering other questions. Please try again in a few minutes.",
        )


def enforce_usage_limits(user) -> None:
    """Raise Throttled (429) if a new question from `user` would exceed a
    limit. Called before the message is created, so nothing is spent."""
    now = timezone.now()

    for setting_name, window, label in _PER_USER_TOKEN_LIMITS:
        limit = getattr(config, setting_name)
        if limit == UNLIMITED:
            continue
        used = _tokens_used_since(now - window, user=user)
        if used >= limit:
            raise Throttled(
                detail=f"You've reached your {label} AI reporting token limit. Please try again later.",
            )

    global_budget = config.AI_REPORTING_GLOBAL_DAILY_TOKEN_BUDGET
    if global_budget != UNLIMITED:
        # Per calendar day (UTC), so "try again tomorrow" is actually true.
        today = now.replace(hour=0, minute=0, second=0, microsecond=0)
        used = _tokens_used_since(today)
        if used >= global_budget:
            next_midnight = today + timedelta(days=1)
            raise Throttled(
                wait=int((next_midnight - now).total_seconds()),
                detail="AI reporting has reached its site-wide daily token budget. Please try again tomorrow.",
            )
