# Award spend profiles

An award can carry a **spend profile**: dated periods, each with an optional
minimum and maximum spend. The awarding portal (AIRR) sets it on a
`RemoteProject` and sends it to the site in `AwardDetails.spend_profile`
(OpenPortal 0.94). The site (a `ManagedProject`) enforces it. Code:
`src/waldur_openportal/spend_profiles.py`.

## The profile

- Each entry applies from its `from` date until the day before the next
  entry's; the last runs to the award's end date.
- Amounts are in the award's allocation units, and dates fall within the
  award.
- A control an entry leaves out does not apply in its period. Nothing
  carries over from an earlier entry. An entry with neither control means
  "no controls from this date".
- Days start at midnight UTC.

## Changing a profile

Only ended periods are history. A period has **ended** when its last day is
before today: its forfeit has been worked out (possibly 0), and possibly
charged. It is **current** when it has begun and not ended. The awarding
portal's `set-spend-profile` (`spend_profiles.validate_change`) allows:

1. changing or clearing the current period's `minimum` and `maximum`;
2. moving when the current period ends, by moving the next entry's `from`
   to any date from today;
3. adding, changing and removing upcoming periods, with `from` today or
   later;
4. removing the current period: after an ended period it is sent as
   `{from}` with no controls, because leaving it out would stretch the
   ended period; with nothing before it, it may be left out;
5. removing the whole profile (`[]`) while no period has ended.

It refuses, with a 400 saying why: any change to an ended period (its
`from`, controls, or leaving it out); moving an ended period's last day
(the `from` of the entry after it); a new entry dated before today; and
`[]` once a period has ended. After an award has ended, its last period
has ended too.

The site uses the controls it holds when they act: a new cap applies at
the next limit sync, and a period's forfeit is worked out from the
minimums as they stand when it ends.

## The rules both portals agree

**The award's allocation is never changed by a profile.** Every charge
(usage, and later forfeits) counts against the whole award.

**Maximums.** During a period, the award behaves as if its allocation were
its *cap*:

- the cap is the sum of the maximums so far, never more than the award;
- the days before the first period, and any period with no maximum, count
  towards later caps at what they actually charged;
- a period with no maximum has no cap: the whole award is available.

Overspend is not double-counted: it is already in the charges, so it
already reduces what is left under the cap. Unspent cap is not carried
forward as such; under-spend against a minimum becomes a forfeit (below).

**Minimums.** On the first day of a new period the site charges a forfeit
of the sum of the minimums so far, less everything charged so far (usage
and earlier forfeits), if that is positive. A period with no minimum adds
nothing to the sum, so no forfeit is charged at its end. Spending above a
minimum counts towards later periods. The forfeit is dated the last day of
the period that ended.

## How the site enforces maximums

The project's credits stay the award's: the awarding portal reads the
allocation back from them, and allocation review compares against them.
Instead, `sync_allocation_limits` (every 17 minutes) takes
`withheld_credits()` (the award less the current cap, in credits) off the
credits it lets the project use on the cluster. A new period's cap
therefore applies within 17 minutes of UTC midnight.

## How the site charges forfeits

A forfeit is usage like any other. `backend.sync_usage` fetches this
month's and last month's usage report from the cluster, and
`spend_profiles.add_forfeits()` adds the award's forfeits to it before
anything else reads it. From then on it is billed, taken off the credit,
cached, shown and reported to the awarding portal like the rest of the
report. As OpenPortal's convention says (`site-portal-api.md`, "Reporting a
forfeit"), it is usage by the user `forfeit`, under the component
`forfeit`, on the period's last day, in the award's units once the report
is scaled for the awarding portal. It is not a job.

- **When.** On the first sync after the period's last day (UTC), if the
  period has a minimum, and the award is on the project then.
- **Recorded once.** An `AwardForfeit` keeps the amount and how it was
  worked out (a forfeit of 0 too), with a `forfeit_charged` audit entry.
  The cluster's report is fetched afresh on every sync, so the record is
  what puts the same forfeit back into the month's report each time,
  whether or not the period lines up with the month, and even after the
  award has moved. Corrections are made to the record.
- **One allocation.** A project with more than one allocation has its
  forfeits added to the report of the first (lowest id), so they are
  counted once.
- **Completeness.** Adding a forfeit leaves the day as complete as the
  cluster says. If a forfeit cannot be charged, the month is held
  incomplete, so the awarding portal keeps asking until it is in.
- **Reserved name.** No person may have the shortname `forfeit`, and a
  `forfeit.*` user identifier is never resolved to a person.

## Billing a month after it ends

Usage is billed as it is reported, for the current month. Usage that
arrives for last month after it ended (the cluster's last hours, or a
forfeit dated the last day of last month) is billed when that month's
report is complete: `UsageReconciliationMixin` corrects the month's
`ComponentUsage` to the report and the project's credit by the change. The
site and the awarding side share it.

## Usage units

Since openportal 0.95 a usage report says which unit its figures are in
(`usage_unit`). Waldur relies on it like this:

- **Reports from before units** were all time, 3600 counts per hour. One read
  from the cache (`CachedProjectUsageReport.get_report`) without a unit is
  declared `NHR` on a site and the award's unit on an awarding portal. It is
  not written back.
- **On a site,** a cluster report without a unit (an older agent) is declared
  `NHR`. The report sent to the awarding portal is built in `NHR` and
  converted to the award's unit with the project template's factor, so it is
  labelled as what it is. Forfeits are added in the report's unit.
- **On an awarding portal,** a site's report is billed as an amount of its
  unit, which must be the award's. One in another unit is logged and not
  counted. Currency units are read as amounts, not hours.

## Features

A site answers `is_feature_supported` / `get_supported_features` from
`spend_profiles.SUPPORTED_FEATURES`. It claims `award_spend_maximums` and
`award_spend_minimums`. The awarding portal records a site's answer on
each `RemoteProject` (`site_features`), refreshed daily.

## Progress

`/api/openportal-managed-project-accounting-summary/<project_uuid>/` has a
`spend_profile` field: each period's dates, controls and status, its spend,
the cumulative spend and minimums, the cap, the headroom, and the forfeit.
Amounts are in the award's units, converted from node-hours with the
project template's factor, as the usage reports are.
