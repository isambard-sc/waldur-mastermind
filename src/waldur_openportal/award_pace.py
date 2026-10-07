"""How an award is tracking against its own window.

A port of HomePort's award pace card logic (src/openportal/award-pace/
awardPace.ts and src/openportal/remote-projects/remotePace.ts), so that the
project usage email and the card on the project dashboard tell a team the same
thing. Keep the two in step: the thresholds and the order the statuses are
decided in are what make them agree.
"""

import dataclasses
import datetime

# How long a project gets before it can be told it is behind. An award is
# typically granted, attached and first looked at some days later, so measured
# strictly a team would be behind on its second day. The figures stay honest
# throughout; only the verdict waits.
SETTLING_IN_DAYS = 14

# The settling-in period never takes more than this much of the award, so a
# short award is not half over before it can report anything.
SETTLING_IN_MAX_FRACTION = 0.25

# How far from the ideal line counts as off it.
PACE_TOLERANCE = 0.05


class PaceStatus:
    SETTLING = "settling"
    BEHIND = "behind"
    ON_TRACK = "on-track"
    AHEAD = "ahead"
    EXHAUSTED = "exhausted"
    ENDED = "ended"


@dataclasses.dataclass(frozen=True)
class AwardPace:
    start_date: datetime.date
    end_date: datetime.date
    allocation: float
    used: float
    remaining: float
    total_days: int
    elapsed_days: int
    remaining_days: int
    # Where the award is in its window, 0-1.
    elapsed_fraction: float
    # How much of the allocation is gone, 0 upwards - over 1 when overspent.
    used_fraction: float
    # Spend per day from today that uses up what is left by the end date.
    # None on the last day, when there are no days left to spread it over.
    required_per_day: float | None
    required_per_day_overall: float
    # Spend per day so far, over the elapsed part of the window.
    actual_per_day: float
    # Where the current rate lands by the end date.
    projected_total: float
    # Positive when the current rate overspends, negative when it underspends.
    projected_difference: float
    # When the allocation runs out at the current rate; None when that falls
    # after the award ends, because the award closes first and the rest is lost.
    exhaustion_date: datetime.date | None
    status: str

    @property
    def projected_loss(self) -> float:
        """Allocation left unspent at the end date if today's rate carries on."""
        return max(0.0, -self.projected_difference)


def build_award_pace(
    start_date: datetime.date | None,
    end_date: datetime.date | None,
    allocation: float | None,
    used: float | None,
    today: datetime.date,
) -> AwardPace | None:
    """The pace of an award over [start_date, end_date], as of today.

    Returns None when there is nothing to pace: no window, a window that does
    not run forwards, or no allocation to measure against. A pace built on a
    guessed window is worse than none.
    """
    if start_date is None or end_date is None or allocation is None:
        return None
    allocation = float(allocation)
    if allocation <= 0:
        return None

    total_days = (end_date - start_date).days
    if total_days <= 0:
        return None

    used = max(0.0, float(used or 0))
    elapsed_days = min(max((today - start_date).days, 0), total_days)
    remaining_days = total_days - elapsed_days

    elapsed_fraction = elapsed_days / total_days
    used_fraction = used / allocation
    required_per_day_overall = allocation / total_days
    actual_per_day = used / elapsed_days if elapsed_days > 0 else 0.0
    projected_total = actual_per_day * total_days

    remaining = allocation - used
    required_per_day = (
        max(0.0, remaining) / remaining_days if remaining_days > 0 else None
    )

    exhaustion_date = None
    if actual_per_day > 0 and remaining > 0:
        runs_out_on = today + datetime.timedelta(days=remaining / actual_per_day)
        # A run-out date past the end of the award is not an event: the award
        # closes first, and the balance still sitting there is lost.
        if runs_out_on <= end_date:
            exhaustion_date = runs_out_on

    settling_days = min(SETTLING_IN_DAYS, int(total_days * SETTLING_IN_MAX_FRACTION))

    delta = used_fraction - elapsed_fraction
    if today >= end_date:
        status = PaceStatus.ENDED
    elif used >= allocation:
        status = PaceStatus.EXHAUSTED
    elif elapsed_days < settling_days:
        status = PaceStatus.SETTLING
    elif delta < -PACE_TOLERANCE:
        status = PaceStatus.BEHIND
    elif delta > PACE_TOLERANCE:
        status = PaceStatus.AHEAD
    else:
        status = PaceStatus.ON_TRACK

    return AwardPace(
        start_date=start_date,
        end_date=end_date,
        allocation=allocation,
        used=used,
        remaining=remaining,
        total_days=total_days,
        elapsed_days=elapsed_days,
        remaining_days=remaining_days,
        elapsed_fraction=elapsed_fraction,
        used_fraction=used_fraction,
        required_per_day=required_per_day,
        required_per_day_overall=required_per_day_overall,
        actual_per_day=actual_per_day,
        projected_total=projected_total,
        projected_difference=projected_total - allocation,
        exhaustion_date=exhaustion_date,
        status=status,
    )


def resolve_award_window(
    award_start: datetime.date | None,
    award_end: datetime.date | None,
    first_attached: datetime.date | None,
    project_end: datetime.date | None,
) -> tuple[datetime.date | None, datetime.date | None]:
    """The window to pace an award against.

    The award's own dates, where it has them. Otherwise the start falls back to
    when the award was first attached (usage is only counted from then) and the
    end to the project's end date. With no end date there is no window.
    """
    return award_start or first_attached, award_end or project_end


def split_allocation(text: str | None) -> tuple[float, str]:
    """The number and the unit of an allocation string: "15000 GPUHR"."""
    parts = (text or "").strip().split()
    if not parts:
        return 0.0, ""
    try:
        total = float(parts[0])
    except ValueError:
        return 0.0, ""
    return total, " ".join(parts[1:])
