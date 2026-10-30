"""Token/request limits for the AI reporting feature.

See the AI_REPORTING_TOKEN_LIMIT_*/AI_REPORTING_GLOBAL_* Constance settings.

Deliberately a simple query-based check against ReportingMessage rows, not
chat's budget_gate.py's locked singleton-counter model: ai_reporting is a
low-volume, staff/support-only internal tool, not public-facing, so the tiny
race window of two concurrent requests both reading "under limit" before
either is recorded is an acceptable trade-off against the real cost of
replicating that machinery here. The actual purpose of these limits is a
credible, visible safety net answering a wider-team perception that this
feature is expensive, not hard real-time enforcement against genuine abuse -
see PROJECT_LOG.md (harness repo) section 22. All limits default to -1
(unlimited) except the global daily budget and the per-minute burst cap,
which default to the AI Assistant's own already-chosen numbers.
"""

from datetime import timedelta

from constance import config
from django.db.models import F, Sum
from django.utils import timezone
from rest_framework.exceptions import Throttled

from waldur_mastermind.ai_reporting.models import ReportingMessage

UNLIMITED = -1

# (Constance setting name, rolling window, label used in the error message).
_PER_USER_TOKEN_LIMITS = (
    ("AI_REPORTING_TOKEN_LIMIT_DAILY", timedelta(days=1), "daily"),
    ("AI_REPORTING_TOKEN_LIMIT_WEEKLY", timedelta(weeks=1), "weekly"),
    ("AI_REPORTING_TOKEN_LIMIT_MONTHLY", timedelta(days=30), "monthly"),
)


def _tokens_used_since(since, **filters) -> int:
    total = (
        ReportingMessage.objects.filter(created__gte=since, **filters)
        .aggregate(total=Sum(F("input_tokens") + F("output_tokens")))
        .get("total")
    )
    return total or 0


def enforce_usage_limits(user) -> None:
    """Raise rest_framework.exceptions.Throttled (429) if `user` asking a
    question right now would exceed any configured limit. Call before
    creating a ReportingMessage/dispatching ask_harness - rejecting up front
    is better UX than creating a message a Celery task later fails, and
    avoids paying for a Bedrock call that was always going to be over
    budget."""
    now = timezone.now()

    burst_limit = config.AI_REPORTING_GLOBAL_REQUESTS_PER_MINUTE
    if burst_limit != UNLIMITED:
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
        used = _tokens_used_since(now - window, session__user=user)
        if used >= limit:
            raise Throttled(
                detail=f"You've reached your {label} AI reporting token limit. Please try again later.",
            )

    global_budget = config.AI_REPORTING_GLOBAL_DAILY_TOKEN_BUDGET
    if global_budget != UNLIMITED:
        used = _tokens_used_since(now - timedelta(days=1))
        if used >= global_budget:
            next_midnight = (now + timedelta(days=1)).replace(
                hour=0, minute=0, second=0, microsecond=0
            )
            raise Throttled(
                wait=int((next_midnight - now).total_seconds()),
                detail="AI reporting has reached its site-wide daily token budget. Please try again tomorrow.",
            )
