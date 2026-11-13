"""Token and request limits for AI reporting (the AI_REPORTING_TOKEN_LIMIT_*
and AI_REPORTING_GLOBAL_* settings).

A simple query-based check rather than chat's locked counter: this is a
low-volume internal tool, so two requests racing past a limit together is
acceptable. -1 means unlimited.
"""

from datetime import timedelta

from constance import config
from django.db.models import F, Sum
from django.utils import timezone
from rest_framework.exceptions import Throttled

from waldur_mastermind.ai_reporting.models import ReportingMessage, ReportingUsageRecord

UNLIMITED = -1

# (Constance setting name, rolling window, label used in the error message).
_PER_USER_TOKEN_LIMITS = (
    ("AI_REPORTING_TOKEN_LIMIT_DAILY", timedelta(days=1), "daily"),
    ("AI_REPORTING_TOKEN_LIMIT_WEEKLY", timedelta(weeks=1), "weekly"),
    ("AI_REPORTING_TOKEN_LIMIT_MONTHLY", timedelta(days=30), "monthly"),
)


def _tokens_used_since(since, **filters) -> int:
    # Reads usage records, not messages: messages can be cleaned up before
    # the weekly/monthly window ends, which would reset the limit early.
    total = (
        ReportingUsageRecord.objects.filter(created__gte=since, **filters)
        .aggregate(total=Sum(F("input_tokens") + F("output_tokens")))
        .get("total")
    )
    return total or 0


def enforce_usage_limits(user) -> None:
    """Raise Throttled (429) if a new question from `user` would exceed a
    limit. Called before the message is created, so nothing is spent."""
    now = timezone.now()

    burst_limit = config.AI_REPORTING_GLOBAL_REQUESTS_PER_MINUTE
    if burst_limit != UNLIMITED:
        # Reads messages, not usage records: messages are created when the
        # question arrives, usage records only once it's answered.
        recent_requests = ReportingMessage.objects.filter(
            created__gte=now - timedelta(minutes=1)
        ).count()
        if recent_requests >= burst_limit:
            raise Throttled(
                wait=60,
                detail="AI reporting is receiving too many requests right now. Please try again in a minute.",
            )

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
