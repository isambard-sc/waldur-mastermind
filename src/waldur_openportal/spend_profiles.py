"""Award spend profiles: dated minimum and/or maximum spends on an award.

An awarding portal (AIRR) sets a profile on a RemoteProject and sends it to
the site in AwardDetails.spend_profile; the site (a ManagedProject) enforces
it. OpenPortal carries the profile and checks only that it is well formed
(valid dates and allocations, no duplicate dates, maximum >= minimum, the
same units within an entry). The rules here are the ones the portals agree:

- each entry applies from its date until the next entry's (the last until the
  award's end date), and a control an entry leaves out does not apply in its
  period;
- the amounts are in the award's allocation units, and the dates fall within
  the award;
- a period that has ended, or begun, is not rewritten: entries dated today or
  earlier keep their dates, those whose period has ended keep their controls,
  and new entries start today or later.

Entries are held as JSON, [{"from": "YYYY-MM-DD", "minimum": "250 NHR",
"maximum": "250 NHR"}, ...], sorted by date, exactly as AwardDetails sends
them. Needs an openportal release with spend profiles (0.94); with an older
one a profile cannot be set or read.
"""

import datetime
import decimal
import logging

import openportal
from django.utils import timezone

from . import models, utils

logger = logging.getLogger(__name__)

# Feature names a site portal reports through get_supported_features.
AWARD_SPEND_MINIMUMS = "award_spend_minimums"
AWARD_SPEND_MAXIMUMS = "award_spend_maximums"

# The user and component a forfeit is billed to in a usage report: a
# convention between portals (OpenPortal site-portal-api.md, "Reporting a
# forfeit"). No person may have this name (UserInfo.shortname refuses it).
FORFEIT_USER = "forfeit"
FORFEIT_COMPONENT = "forfeit"

# What this portal, as a site, does with an award's spend profile: a feature
# is added here only once it is enforced. Answered to is_feature_supported
# and get_supported_features. Maximums are enforced through the limit sync
# (withheld_credits), minimums by charging forfeits (add_forfeits).
SUPPORTED_FEATURES: frozenset[str] = frozenset(
    {AWARD_SPEND_MAXIMUMS, AWARD_SPEND_MINIMUMS}
)


def today() -> datetime.date:
    """Today, in UTC: a period's days start at midnight UTC."""
    return timezone.now().astimezone(datetime.UTC).date()


class SpendProfileError(ValueError):
    """A spend profile that cannot be accepted; the message says why."""


def is_supported() -> bool:
    """Whether the installed openportal library knows spend profiles. Without
    it a profile would be dropped silently when an award is sent or read."""
    return hasattr(openportal, "SpendProfileEntry")


def _date(value) -> datetime.date:
    if isinstance(value, datetime.date):
        return value
    try:
        return datetime.date.fromisoformat(str(value))
    except ValueError:
        raise SpendProfileError(f"'{value}' is not a date (YYYY-MM-DD).")


def entry_json(entry) -> dict:
    """An openportal.SpendProfileEntry as the JSON AwardDetails carries."""
    data = {"from": entry.from_date.isoformat()}
    if entry.minimum is not None:
        data["minimum"] = str(entry.minimum)
    if entry.maximum is not None:
        data["maximum"] = str(entry.maximum)
    return data


def parse(raw) -> list:
    """The profile's entries as openportal.SpendProfileEntry, sorted by date,
    checked as OpenPortal checks them. ``raw`` is the JSON list."""
    if not is_supported():
        raise SpendProfileError(
            "This portal's OpenPortal library does not support spend profiles "
            "(it needs openportal 0.94 or later)."
        )
    entries = []
    for item in raw or []:
        if not isinstance(item, dict) or "from" not in item:
            raise SpendProfileError("Each entry needs a 'from' date.")
        from_date = _date(item["from"])
        try:
            entries.append(
                openportal.SpendProfileEntry(
                    from_date,
                    item.get("minimum") or None,
                    item.get("maximum") or None,
                )
            )
        except Exception as e:
            raise SpendProfileError(f"Invalid entry from {from_date}: {e}")
    entries.sort(key=lambda e: e.from_date)
    for earlier, later in zip(entries, entries[1:]):
        if earlier.from_date == later.from_date:
            raise SpendProfileError(f"Two entries start on {later.from_date}.")
    return entries


def normalise(raw) -> list:
    """The profile as canonical JSON: checked, sorted, and spelt as
    AwardDetails spells it."""
    return [entry_json(e) for e in parse(raw)]


def _units(allocation) -> str:
    return str(allocation.units).strip().lower()


def validate_for_award(entries, details) -> None:
    """The portals' rules for a profile on this award: amounts in the award's
    allocation units, dates within the award."""
    allocation = getattr(details, "allocation", None)
    start = getattr(details, "start_date", None)
    end = getattr(details, "end_date", None)
    for entry in entries:
        for name in ("minimum", "maximum"):
            amount = getattr(entry, name)
            if amount is not None and allocation is not None:
                if _units(amount) != _units(allocation):
                    raise SpendProfileError(
                        f"The {name} from {entry.from_date} is in "
                        f"{amount.units}, but the award is in {allocation.units}."
                    )
        if start is not None and entry.from_date < start:
            raise SpendProfileError(
                f"The entry from {entry.from_date} starts before the award ({start})."
            )
        if end is not None and entry.from_date > end:
            raise SpendProfileError(
                f"The entry from {entry.from_date} starts after the award ends ({end})."
            )


def periods(raw, end_date=None) -> list[dict]:
    """Each entry as a period: {"from", "to" (inclusive, or None if open),
    "minimum", "maximum"}. An entry runs until the day before the next one's,
    the last until ``end_date``."""
    items = sorted(raw or [], key=lambda item: str(item["from"]))
    result = []
    for index, item in enumerate(items):
        start = _date(item["from"])
        if index + 1 < len(items):
            to = _date(items[index + 1]["from"]) - datetime.timedelta(days=1)
        else:
            to = end_date
        result.append(
            {
                "from": start,
                "to": to,
                "minimum": item.get("minimum"),
                "maximum": item.get("maximum"),
            }
        )
    return result


def validate_change(old_raw, new_raw, today: datetime.date, end_date=None) -> None:
    """Refuse a change that rewrites history: only ended periods are fixed.

    A period has ended when its last day is before today (UTC): its forfeit
    has been worked out. It is current when it has begun and not ended. The
    controls act on the past only when a period ends, so:

    - an ended period keeps its date and controls, and its end: the entry
      straight after it keeps its date;
    - the current period's controls may change, and when it ends moves with
      the next entry's date. After an ended period its date is fixed by the
      rule above, so to drop its controls it is sent with none; with nothing
      ended before it, it may be left out;
    - upcoming periods may be added, changed or removed, and any new entry
      starts today or later;
    - [] removes the profile only while no period has ended.
    """
    old_periods = periods(old_raw, end_date)
    new_dates = sorted(_date(item["from"]) for item in (new_raw or []))
    new = {_date(item["from"]): item for item in (new_raw or [])}

    ended = [p for p in old_periods if p["to"] is not None and p["to"] < today]
    if ended and not new_dates:
        raise SpendProfileError(
            f"The period from {ended[0]['from']} has ended, so the profile "
            "cannot be removed. To end the controls, add an entry with no "
            "controls from today."
        )

    for period in ended:
        start = period["from"]
        if start not in new:
            raise SpendProfileError(
                f"The period from {start} has ended, so it cannot be removed."
            )
        if (period["minimum"] or None) != (new[start].get("minimum") or None) or (
            period["maximum"] or None
        ) != (new[start].get("maximum") or None):
            raise SpendProfileError(
                f"The period from {start} has ended, so its controls cannot change."
            )
        following = [d for d in new_dates if d > start]
        next_start = following[0] if following else None
        old_next = period["to"] + datetime.timedelta(days=1)
        if next_start != old_next and not (
            next_start is None and period["to"] == end_date
        ):
            raise SpendProfileError(
                f"The period from {start} has ended on {period['to']}, so the "
                f"next period must still start on {old_next}. To remove the "
                f"controls from then, keep an entry from {old_next} with no "
                "controls."
            )

    old_dates = {p["from"] for p in old_periods}
    for start in new_dates:
        if start not in old_dates and start < today:
            raise SpendProfileError(
                f"A new period cannot start in the past ({start}); start it "
                f"today ({today}) or later."
            )


def _amount(value) -> float | None:
    """An entry's amount ("250 NHR") as a number in the award's units; the
    units were checked against the award's when the profile was set."""
    if not value:
        return None
    return float(openportal.Allocation.from_string(str(value)).size)


def _award_scale(managed_project, units: str) -> float:
    """Award units per node-hour of usage: the factor the usage reports to
    the awarding portal are scaled by (board.get_usage_report), and that
    ProjectTemplate.convert_to_credits divides by. 1 if there is none."""
    template = managed_project.project_template
    if template is None:
        return 1.0
    try:
        scale = float(template.get_allocation_mapping_for(units))
    except Exception:
        return 1.0
    return scale if scale > 0 else 1.0


def progress(managed_project, today: datetime.date) -> dict | None:
    """The award's spend profile, period by period, with its spend so far.

    None if the award has no profile. Otherwise {"units", "allocation",
    "spend", "periods": [...]}, every amount in the award's units, where each
    period has:

    - "from", "to" (inclusive), "minimum", "maximum": the profile's entry;
    - "status": "ended", "current" or "upcoming";
    - "spend": what was charged on the period's days, up to today;
    - "cumulative_spend": what was charged from the award's start to the end
      of the period (or today), the charges the period's controls compare to;
    - "cumulative_minimum": the minimums so far, None if there are none;
    - "cap": the limit during the period: the maximums so far, with a period
      that had no maximum, and the days before the first, counted at what
      they charged; the whole award if the period has no maximum;
    - "headroom": cap less cumulative_spend, for a period begun;
    - "forfeit": the forfeit charged when the period ended, None if none
      has been.

    Charges are the award's usage (utils.get_award_usage_hours, in node-hours
    converted to the award's units with the project template's factor).
    """
    details = managed_project.details or {}
    raw = details.get("spend_profile")
    if not raw:
        return None

    award_details = managed_project.get_details()
    award = getattr(award_details, "allocation", None)
    units = str(award.units) if award is not None else None
    award_size = float(award.size) if award is not None else None
    scale = _award_scale(managed_project, units) if units else 1.0
    end_date = getattr(award_details, "end_date", None)

    def charged(start=None, end=None) -> float:
        hours = utils.get_award_usage_hours(
            managed_project, range_start=start, range_end=end
        )
        return hours * scale

    award_spend = charged(end=today)
    forfeits = {
        forfeit.period_from: float(forfeit.amount)
        for forfeit in models.AwardForfeit.objects.filter(
            managed_project=managed_project
        )
    }
    result_periods = []
    first = periods(raw, end_date)
    # The days before the first period are uncontrolled, and count towards
    # later caps at what they charged.
    counted = charged(end=first[0]["from"] - datetime.timedelta(days=1))
    cumulative_minimum = None

    for period in first:
        start, to = period["from"], period["to"]
        minimum = _amount(period["minimum"])
        maximum = _amount(period["maximum"])
        if start > today:
            status = "upcoming"
        elif to is not None and to < today:
            status = "ended"
        else:
            status = "current"

        if minimum is not None:
            cumulative_minimum = (cumulative_minimum or 0.0) + minimum

        if status == "upcoming":
            spend = None
            cumulative_spend = None
        else:
            last = to if status == "ended" else today
            spend = charged(start, last)
            cumulative_spend = charged(end=last)

        if maximum is None:
            cap = award_size
        else:
            cap = counted + maximum
            if award_size is not None:
                cap = min(cap, award_size)

        # What the period adds to the caps after it: its maximum, or, with
        # none, what it charged (an upcoming period without one is unknown,
        # and every later cap is then the award's or its own maximum's).
        if maximum is not None:
            counted += maximum
        else:
            counted += spend or 0.0

        result_periods.append(
            {
                "from": start,
                "to": to,
                "minimum": period["minimum"],
                "maximum": period["maximum"],
                "status": status,
                "spend": spend,
                "cumulative_spend": cumulative_spend,
                "cumulative_minimum": cumulative_minimum,
                "cap": cap,
                "headroom": (
                    cap - cumulative_spend
                    if cap is not None and cumulative_spend is not None
                    else None
                ),
                "forfeit": forfeits.get(start),
            }
        )

    return {
        "units": units,
        "allocation": award_size,
        "spend": award_spend,
        "periods": result_periods,
    }


def current_period(result: dict | None) -> dict | None:
    """The period of a progress() result that today falls in, or None (no
    profile, before its first period, or after the award has ended)."""
    for period in (result or {}).get("periods", []):
        if period["status"] == "current":
            return period
    return None


def withheld_credits(managed_project, today: datetime.date) -> float:
    """How far the award's spend profile lowers its limit today, in credits.

    The award's allocation, and so the project's credits, are never changed
    by a profile: the awarding portal reads the allocation back from them,
    and their review rules are about the award. What the maximums change is
    what may be spent now: during a period with a maximum the award behaves
    as if it were only its cap, so the limit sync takes this much (the award
    less the cap) off the credits it lets the project use. 0 when no maximum
    applies today."""
    if AWARD_SPEND_MAXIMUMS not in SUPPORTED_FEATURES:
        return 0.0
    result = progress(managed_project, today)
    period = current_period(result)
    if period is None or period["cap"] is None or result["allocation"] is None:
        return 0.0
    withheld = result["allocation"] - period["cap"]
    if withheld <= 0:
        return 0.0
    return withheld / _award_scale(managed_project, result["units"])


def _forfeit_carrier(project):
    """The one allocation of a project its forfeits are added to: a project
    with more than one would otherwise be charged each forfeit on each."""
    return (
        models.Allocation.objects.filter(project=project, is_active=True)
        .order_by("pk")
        .first()
    )


def _cumulative_minimum(raw, until: datetime.date) -> float:
    """The sum of the minimums of the periods starting on or before until."""
    total = 0.0
    for period in periods(raw):
        if period["from"] <= until and period["minimum"]:
            total += _amount(period["minimum"])
    return total


def _hours_in(report, windows, start, end) -> float:
    """A report's usage on the days of windows within start..end."""
    if report is None:
        return 0.0
    hours = 0.0
    for window_start, window_end in windows:
        clipped = utils._clip_window_to_range(window_start, window_end, start, end)
        if clipped is not None:
            hours += float(
                report.filter(openportal.DateRange(*clipped)).total_usage.hours
            )
    return hours


def _charged_hours(managed_project, project, report, resource, month, to) -> float:
    """What the award has been charged up to and including ``to``, in
    node-hours: its cached usage, with this allocation's report for the
    month taken from the fresh ``report`` rather than the cache."""
    hours = utils.get_award_usage_hours(managed_project, range_end=to)
    windows = [
        (start, end)
        for _, start, end in utils._get_managed_project_attachment_windows(
            managed_project, project, from_award_start=True
        )
    ]
    cached = models.CachedProjectUsageReport.objects.filter(
        year=month.start_date.year,
        month=month.start_date.month,
        project_identifier=str(report.project),
        resource=resource,
    ).first()
    stale = _hours_in(
        cached.get_report() if cached else None, windows, month.start_date, to
    )
    fresh = _hours_in(report, windows, month.start_date, to)
    return hours - stale + fresh


def _charge_forfeit(managed_project, allocation, report, resource, month, period):
    """Work out the forfeit for a period that has ended, and record it."""
    raw = managed_project.details["spend_profile"]
    award = managed_project.get_details().allocation
    units = str(award.units) if award is not None else ""
    scale = _award_scale(managed_project, units) if units else 1.0
    to = period["to"]

    charged = (
        _charged_hours(managed_project, allocation.project, report, resource, month, to)
        * scale
    )
    minimums = _cumulative_minimum(raw, period["from"])
    amount = decimal.Decimal(str(max(0.0, minimums - charged))).quantize(
        decimal.Decimal("0.0001")
    )
    hours = (amount / decimal.Decimal(str(scale))).quantize(decimal.Decimal("0.0001"))

    forfeit = models.AwardForfeit.objects.create(
        managed_project=managed_project,
        project=allocation.project,
        project_identifier=str(report.project),
        period_from=period["from"],
        date=to,
        amount=amount,
        units=units,
        hours=hours,
        working={
            "period": {
                "from": period["from"].isoformat(),
                "to": to.isoformat(),
                "minimum": period["minimum"],
                "maximum": period["maximum"],
            },
            "cumulative_minimum": minimums,
            "cumulative_charges": charged,
            "scale": scale,
            "charged_on": today().isoformat(),
        },
    )
    models.ManagedProjectAuditEntry.record(
        managed_project,
        models.ManagedProjectAuditEventType.FORFEIT_CHARGED,
        note=(
            f"Spend profile period {period['from']} to {to} ended: minimums so far "
            f"{minimums:g} {units}, charged so far {charged:g} {units}, so a "
            f"forfeit of {amount} {units} is charged on {to}."
        ),
    )
    return forfeit


def _local_group(allocation, report) -> str:
    group = (
        models.Association.objects.filter(allocation=allocation)
        .exclude(groupname="")
        .exclude(groupname=None)
        .values_list("groupname", flat=True)
        .first()
    )
    return group or str(report.project).split(".")[0]


def _forfeit_usage(report, forfeit):
    """The forfeit as a Usage in the report's unit: node-hours for a
    cluster's NHR report, or the award's amount for a report in its unit."""
    unit = report.unit
    if unit.name == "NHR":
        return unit.usage(float(forfeit.hours))
    if unit.name == models.usage_unit_name(forfeit.units):
        return unit.usage(float(forfeit.amount))
    raise ValueError(
        f"cannot add a forfeit in {forfeit.units} to a report in {unit.name}"
    )


def _add_forfeit_day(report, forfeit, group):
    usage = _forfeit_usage(report, forfeit)
    day = openportal.DailyProjectUsageReport()
    day.add_usage(FORFEIT_USER, usage)
    day.add_component_usage(FORFEIT_COMPONENT, FORFEIT_USER, usage)
    # Complete, so the day stays as complete as the cluster says it is: a
    # summed day is complete when both parts are.
    day.set_complete()
    report.add_report(forfeit.date, day)
    report.add_mapping(
        openportal.UserMapping(
            f"{FORFEIT_USER}.{report.project}:{FORFEIT_USER}:{group}"
        )
    )


def _hold_incomplete(report, date):
    """Keep the month open: an incomplete day makes the report incomplete,
    so the awarding portal keeps asking until the forfeit is in."""
    report.add_report(date, openportal.DailyProjectUsageReport())


def add_forfeits(allocation, report, month, resource: str):
    """The month's usage report from the cluster, with the award's forfeits
    added: as usage by FORFEIT_USER, under the FORFEIT_COMPONENT component, on
    each period's last day.

    Called on every sync, with each report as it arrives, so the forfeits
    are counted from then on like any other usage: billed, taken off the
    credit, cached, shown and reported to the awarding portal.

    - A forfeit already charged to this report (AwardForfeit) is added back,
      whatever has happened to the award since.
    - A period of the attached award that ended in this month, before today
      (UTC), is charged now, if it had a minimum: the minimums so far less
      everything charged so far, never less than 0, recorded with its working.
    - If that fails, the month is held incomplete until it succeeds.
    """
    if AWARD_SPEND_MINIMUMS not in SUPPORTED_FEATURES:
        return report

    models.declare_time_unit(report, "NHR")
    start, end = month.start_date, month.end_date
    identifier = str(report.project)
    group = None

    def add(forfeit):
        nonlocal group
        if forfeit.hours > 0:
            if group is None:
                group = _local_group(allocation, report)
            try:
                _add_forfeit_day(report, forfeit, group)
            except Exception as e:
                logger.error("Could not add %s to its report: %s", forfeit, e)
                _hold_incomplete(report, forfeit.date)

    charged = models.AwardForfeit.objects.filter(
        project_identifier=identifier, date__gte=start, date__lte=end
    ).order_by("date")
    known = set()
    for forfeit in charged:
        known.add((forfeit.managed_project_id, forfeit.period_from))
        add(forfeit)

    managed_project = models.ManagedProject.objects.filter(
        project=allocation.project
    ).first()
    if managed_project is None or not (managed_project.details or {}).get(
        "spend_profile"
    ):
        return report
    carrier = _forfeit_carrier(allocation.project)
    if carrier is None or carrier.pk != allocation.pk:
        return report

    now = today()
    end_date = getattr(managed_project.get_details(), "end_date", None)
    for period in periods(managed_project.details["spend_profile"], end_date):
        to = period["to"]
        if to is None or not (start <= to <= end) or to >= now:
            continue
        if not period["minimum"]:
            continue
        if (managed_project.pk, period["from"]) in known:
            continue
        if models.AwardForfeit.objects.filter(
            managed_project=managed_project, period_from=period["from"]
        ).exists():
            # Charged to another report (the award has moved since).
            continue
        try:
            add(
                _charge_forfeit(
                    managed_project, allocation, report, resource, month, period
                )
            )
        except Exception as e:
            logger.error(
                "Could not charge the forfeit of %s for the period from %s: %s",
                managed_project,
                period["from"],
                e,
            )
            _hold_incomplete(report, to)
    return report
