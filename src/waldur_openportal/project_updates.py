"""The regular project usage update emailed to project members.

Sent through Waldur's notification system as ``openportal.project_usage_update``,
so operators can switch it on and off and override its templates like any other
notification. How often each project receives it is set per project by
models.ProjectNotification (every 14 days by default; 0 turns it off).

Who gets one:

- Projects holding an award from this portal on a remote portal (a
  RemoteProject that is active, pending or stale), and projects with active
  allocations on this portal and a project credit.
- Never a project that is *remotely managed*, meaning one that holds a
  ManagedProject because an awarding portal granted it. That portal sends its
  own update for the award, and members should not get two.

For each award, the email carries the same figures as HomePort's award pace
card, computed by award_pace, so the two cannot disagree.
"""

import datetime
import logging

from constance import config as constance_config
from django.db.models import Q
from django.utils import timezone

from waldur_core.core import utils as core_utils
from waldur_core.core.models import Notification
from waldur_core.structure import models as structure_models
from waldur_mastermind.invoices import models as invoice_models

from . import award_pace, models, utils

NOTIFICATION_APP = "openportal"
NOTIFICATION_EVENT = "project_usage_update"

# Updates go out between these hours, local time, inclusive.
OFFICE_HOURS = (10, 15)

# A ceiling on how many emails one run may send, so a misconfiguration cannot
# flood the mail relay. Projects not reached are picked up by the next run.
MAX_EMAILS_PER_RUN = 500

# A change to the grace period has to be requested this long before the data is
# scheduled for deletion.
GRACE_CHANGE_NOTICE_DAYS = 14

ONE_DAY = datetime.timedelta(days=1)

# Awards that are paced. Not only active ones: an award waiting on approval of
# a change, or one whose portal has gone quiet, still has a window, an
# allocation and the usage reported so far. An errored one's figures are not to
# be trusted, and a deleted one is gone. Matches PACED_STATES in HomePort.
PACED_STATES = (
    models.RemoteProjectState.ACTIVE,
    models.RemoteProjectState.PENDING,
    models.RemoteProjectState.STALE,
)

STATUS_LABELS = {
    award_pace.PaceStatus.SETTLING: "Just getting started",
    award_pace.PaceStatus.BEHIND: "Behind pace",
    award_pace.PaceStatus.ON_TRACK: "On pace",
    award_pace.PaceStatus.AHEAD: "Ahead of pace",
    award_pace.PaceStatus.EXHAUSTED: "Allocation used up",
    award_pace.PaceStatus.ENDED: "Award has ended",
}

logger = logging.getLogger(__name__)


def is_remotely_managed(project) -> bool:
    """Whether an awarding portal manages this project, and so emails it."""
    return models.ManagedProject.objects.filter(project=project).exists()


def candidate_projects():
    """Projects that hold something to report on, and are not remotely managed."""
    with_allocations = models.Allocation.objects.filter(
        is_active=True, project__isnull=False
    ).values("project_id")
    with_awards = models.RemoteProject.objects.filter(
        state__in=PACED_STATES, current_project__isnull=False
    ).values("current_project_id")
    managed = models.ManagedProject.objects.filter(project__isnull=False).values(
        "project_id"
    )
    return (
        structure_models.Project.objects.filter(
            Q(id__in=with_allocations) | Q(id__in=with_awards)
        )
        .exclude(id__in=managed)
        .order_by("id")
    )


def _amount(value: float, unit: str, digits: int = 1) -> str:
    text = f"{value:,.{digits}f}"
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return f"{text} {unit}".strip()


def _percent(fraction: float) -> int:
    return round(fraction * 100)


def _remote_project_pace(remote_project, project_end, today):
    """(pace, unit) for one award, as HomePort's buildRemoteProjectPace."""
    try:
        details = remote_project.award_details()
    except OSError as exc:
        logger.error(
            "Cannot derive award details for remote project %s: %s",
            remote_project.uuid,
            exc,
        )
        return None, ""

    allocation, unit = award_pace.split_allocation(
        str(details.allocation) if details.allocation else None
    )
    if allocation <= 0 and remote_project.current_allocation:
        allocation, unit = float(remote_project.current_allocation), ""

    start, end = award_pace.resolve_award_window(
        details.start_date,
        details.end_date,
        remote_project.created.date() if remote_project.created else None,
        project_end,
    )
    used = utils.get_remote_project_total_hours(remote_project)
    return award_pace.build_award_pace(start, end, allocation, used, today), unit


def award_entries(project, today: datetime.date) -> list[dict]:
    """One entry per award held by the project, busiest first, as on HomePort."""
    entries = []
    remote_projects = models.RemoteProject.objects.filter(
        current_project=project, state__in=PACED_STATES
    ).select_related("remote_allocation")
    for remote_project in remote_projects:
        try:
            pace, unit = _remote_project_pace(remote_project, project.end_date, today)
        except Exception:
            logger.exception(
                "Cannot work out the pace of remote project %s", remote_project.uuid
            )
            continue
        if pace is None:
            continue
        name = (
            remote_project.remote_allocation.name
            if remote_project.remote_allocation
            else remote_project.destination
        )
        entries.append(
            (
                pace.used_fraction,
                {
                    "name": name,
                    "allocation": _amount(pace.allocation, unit),
                    "used": _amount(pace.used, unit),
                    "used_percent": _percent(pace.used_fraction),
                    "expected_percent": _percent(pace.elapsed_fraction),
                    "status": pace.status,
                    "status_label": STATUS_LABELS[pace.status],
                    "start_date": pace.start_date,
                    "end_date": pace.end_date,
                    "last_access_date": pace.end_date - ONE_DAY,
                    "remaining_days": pace.remaining_days,
                    "actual_per_day": _amount(pace.actual_per_day, unit, 2),
                    "required_per_day": (
                        _amount(pace.required_per_day, unit, 2)
                        if pace.required_per_day is not None
                        else None
                    ),
                    "projected_total": _amount(pace.projected_total, unit),
                    "projected_loss": _amount(pace.projected_loss, unit),
                    "projected_loss_percent": _percent(
                        pace.projected_loss / pace.allocation
                    ),
                    "exhaustion_date": pace.exhaustion_date,
                },
            )
        )
    # Busiest first; sorted() is stable, so ties keep the query's order.
    return [entry for _, entry in sorted(entries, key=lambda pair: -pair[0])]


def local_usage(project) -> dict | None:
    """This month's usage of the project's allocations on this portal itself.

    Only for a project with a project credit, as before: the credit is what the
    usage is drawn against. Local allocations record this month's usage only,
    and have no award window, so there is no pace to report for them - HomePort
    shows them the monthly credit card rather than the award pace card.
    """
    allocations = models.Allocation.objects.filter(project=project, is_active=True)
    if not allocations.exists():
        return None
    credit = invoice_models.ProjectCredit.objects.filter(project=project).first()
    if credit is None:
        return None
    usage = sum(float(allocation.node_usage) for allocation in allocations)
    remaining = max(float(credit.value) - usage, 0.0)
    return {
        "usage_this_month": _amount(usage, "", 2),
        "credit_remaining": _amount(remaining, "", 2),
    }


def _frequency_in_words(days: int) -> str:
    days = max(days, 1)
    return {1: "day", 7: "week", 14: "fortnight"}.get(days, f"{days} days")


def build_context(project, frequency: int, today: datetime.date) -> dict | None:
    """The notification context for one project, or None if it has nothing to say."""
    awards = award_entries(project, today)
    local = local_usage(project)
    if not awards and local is None:
        return None

    # End dates are exclusive, as everywhere in Waldur: Project.is_expired is
    # effective_end_date <= today, so on the date itself access has already
    # gone and the last usable day is the one before. People read "ends on the
    # 31st" as "I have until the 31st" and lose a day to it, so the email names
    # the last day of access wherever it tells someone how long they have, as
    # HomePort does (lastAccessDate in its core/dateUtils.ts).
    end_date = project.end_date
    deletion_date = project.get_effective_end_date()
    in_grace_period = end_date is not None and end_date <= today
    last_access_date = end_date - ONE_DAY if end_date else None
    grace_change_deadline = (
        deletion_date - datetime.timedelta(days=GRACE_CHANGE_NOTICE_DAYS)
        if deletion_date
        else None
    )

    return {
        "site_name": constance_config.SITE_NAME,
        "project_name": project.name,
        "project_url": core_utils.format_homeport_link(
            "/projects/{uuid}/", uuid=project.uuid.hex
        ),
        "today": today,
        "update_frequency": _frequency_in_words(frequency),
        "end_date": end_date,
        "last_access_date": last_access_date,
        "days_until_last_access": (
            (last_access_date - today).days
            if last_access_date is not None and not in_grace_period
            else None
        ),
        "in_grace_period": in_grace_period,
        "grace_period_days": project.get_grace_period_days(),
        "deletion_date": deletion_date,
        "data_last_access_date": deletion_date - ONE_DAY if deletion_date else None,
        "grace_change_deadline": grace_change_deadline,
        "grace_change_deadline_passed": (
            grace_change_deadline is not None and grace_change_deadline < today
        ),
        "awards": awards,
        "local_usage": local,
        "docs_url": constance_config.DOCS_URL or "",
        "support_url": constance_config.SUPPORT_PORTAL_URL or "",
    }


def recipient_emails(project) -> list[str]:
    emails = set()
    for user in project.get_users():
        if user.is_active and user.email and not core_utils.is_robot_user(user):
            emails.add(user.email)
    return sorted(emails)


def is_due(notification: models.ProjectNotification, today: datetime.date) -> bool:
    if notification.frequency == 0:
        return False
    if notification.last_notification is None:
        return True
    return (
        notification.last_notification + datetime.timedelta(days=notification.frequency)
        <= today
    )


def send_project_updates(now: datetime.datetime | None = None) -> int:
    """Send every update that is due. Returns how many emails were sent."""
    local_now = timezone.localtime(now or timezone.now())
    if not OFFICE_HOURS[0] <= local_now.hour <= OFFICE_HOURS[1]:
        logger.debug("Not sending project updates - outside office hours")
        return 0

    key = f"{NOTIFICATION_APP}.{NOTIFICATION_EVENT}"
    if not Notification.objects.filter(key=key, enabled=True).exists():
        # Checked up front, not left to broadcast_mail: a disabled notification
        # sends nothing, and recording a send that did not happen would hold
        # the project back a whole period once it is switched on.
        logger.info("Notification '%s' is not enabled - no project updates", key)
        return 0

    # Everything below is judged as of local_now, including expiry, so a run
    # is decided by the time it is given and not by when it happens to read
    # the clock.
    today = local_now.date()
    sent = 0
    for project in candidate_projects():
        if sent >= MAX_EMAILS_PER_RUN:
            logger.warning(
                "Sent %s project update emails this run - the rest wait for the next",
                sent,
            )
            break
        effective_end = project.get_effective_end_date()
        if project.is_removed or (effective_end and effective_end <= today):
            continue

        notification, _ = models.ProjectNotification.objects.get_or_create(
            project=project
        )
        if not is_due(notification, today):
            continue

        context = build_context(project, notification.frequency, today)
        if context is None:
            continue
        emails = recipient_emails(project)
        if not emails:
            continue

        core_utils.broadcast_mail(NOTIFICATION_APP, NOTIFICATION_EVENT, context, emails)
        sent += len(emails)
        notification.last_notification = today
        notification.save(update_fields=["last_notification"])
    return sent
