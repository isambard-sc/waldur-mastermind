# Company domain report

`company_domain_report.py` estimates **how many companies use the Waldur
instance** (portal-api.isambard.ac.uk by default) and how many **Isambard-AI
Phase 2 node hours** each one has used, broken down by organisation, project
and month. It writes an Excel workbook.

`verify_usage_totals.py` is a separate cross-check of the usage numbers (see
[Verifying the usage totals](#verifying-the-usage-totals)).

Both scripts are read-only: they only issue `GET` requests.

## Contents

- [Quick start](#quick-start)
- [Why this is an estimate](#why-this-is-an-estimate)
- [How a domain is classified](#how-a-domain-is-classified)
- [domain_overrides.csv](#domain_overridescsv)
- [Where the data comes from](#where-the-data-comes-from)
- [How usage is attributed](#how-usage-is-attributed)
- [Workbook sheets and columns](#workbook-sheets-and-columns)
- [Monthly workflow](#monthly-workflow)
- [Command-line options](#command-line-options)
- [Backend load](#backend-load)
- [Privacy](#privacy)
- [Verifying the usage totals](#verifying-the-usage-totals)
- [Known limitations](#known-limitations)
- [Files](#files)

## Quick start

The script declares its own dependencies (`requests`, `openpyxl`) in a
[PEP 723](https://peps.python.org/pep-0723/) header, so `uv` runs it in a
throwaway environment. Python 3.11 or newer is needed.

```bash
cd us_project_reporting
WALDUR_TOKEN=<staff token> uv run company_domain_report.py
```

- The token **must belong to a staff user**: the script reads all users, all
  projects and revoked project roles (`show_inactive=true`), which are staff-only.
  The token can also be passed with `--token`, or typed in when prompted.
- Run it as `uv run company_domain_report.py`, not `uv run python ...`. Inside a
  checkout of the main project, `uv run python` picks up the project's own
  `pyproject.toml` and tries to build its dependencies.
- It writes `company_domains_YYYY-MM-DD.xlsx` in the current directory (today's
  date, so two runs in one month do not overwrite each other). Progress and a
  summary go to stderr.
- A run takes a few minutes. The usage fetch is the slow part, and grows with
  the number of months of history.
- The **first** run downloads the eduGAIN metadata (about 100 MB, one or two
  minutes) and caches the scopes in `edugain_scopes.json` (about 180 KB). Later
  runs reuse the cache for 30 days. The cache is not committed; it is created
  next to the script on first use. `--refresh-edugain` forces a re-download and
  `--no-edugain` skips that rule entirely.

Emails are **not** written to the workbook unless you pass `--include-emails`.

## Why this is an estimate

"How many companies use the system" has no authoritative field in Waldur.
`Project.is_industry` looked like a candidate but is not set in practice (a live
check came back 0), so it is not used.

Instead the script works bottom-up: it takes every user's email address, groups
users by the domain after the `@`, discards domains that are clearly not
companies (universities, government, consumer mail providers, ...), and counts
each remaining domain as one company. Usernames here are professional email
addresses, which is what makes this workable.

The result is a **list for a human to review**, not ground truth. It can:

- **undercount** a company whose employee signed up with a personal Gmail address;
- **overcount** a company that uses two domains (rebrand, subsidiary, typo),
  unless the two are merged with `same_as` in `domain_overrides.csv`;
- **misfile** a contractor, charity or public body that behaves like a company.

## How a domain is classified

Each domain gets exactly one category. Rules are tried in this order and the
first match wins:

| # | Rule | Category |
|---|------|----------|
| 1 | `domain_overrides.csv` (the domain or any parent domain) | whatever the row says |
| 2 | Built-in list of consumer mail providers (gmail.com, outlook.com, yahoo, icloud, proton, gmx, qq.com, ...) | `generic` |
| 3 | Suffix rules: `.edu`, `.ac.*`, `.edu.*` | `academic` |
| 3 | `.gov`, `.gov.*`, `.mil`, `.int`, `gov.uk`, `gov.scot`, `gov.wales`, `police.uk`, `parliament.uk`, `mod.uk`, `ukri.org`, `gouv.*`, `govt.*` | `government` |
| 3 | `nhs.uk`, `nhs.net`, `nhs.scot` | `health` |
| 4 | eduGAIN scope: the domain (or a parent) is declared as a scope by an identity provider in the eduGAIN federation metadata | `academic` |
| 5 | None of the above | `company` |

Notes:

- **Subdomains match.** Every rule matches a domain and all its subdomains, so
  `mail.mcgill.ca` is caught by `mcgill.ca`, and `eng.ox.ac.uk` by `.ac.uk`.
- **`research` and `nonprofit` only come from overrides.** Nothing in the
  automatic rules can tell a research institute or charity from a company.
- **eduGAIN** is the federation of university and research identity providers.
  Its metadata (<https://mds.edugain.org/edugain-v2.xml>) is streamed once and
  every IdP's `shibmd:Scope` is collected (about 11,000 of them). Regular-expression
  scopes are skipped because they cannot be suffix-matched. The cache file records
  the source and fetch time, and is refreshed when older than 30 days.
- Only `company` domains count towards the company total. Everything else goes to
  the **Excluded** sheet, which is kept for reference.

## domain_overrides.csv

This is the **only** file of human decisions. It sits next to the script (or use
`--overrides PATH`) and wins over every automatic rule above.

```
domain,category,same_as,note
```

| Column | Meaning |
|--------|---------|
| `domain` | Matches this domain and all of its subdomains. |
| `category` | `company`, `academic`, `research`, `government`, `health`, `nonprofit` or `generic`. Only `company` keeps the domain in the company count. |
| `same_as` | For **company** rows: count this domain as part of another company domain (e.g. a typo or rebrand), so the two merge into one row. For **excluded** rows: group this domain under another in the Excluded sheet's `institution` column (e.g. `gla.ac.uk` -> `glasgow.ac.uk`). Optional. |
| `note` | Free text, shown in the report. Prefix it with `guess:` if unverified. |

Lines starting with `#` are comments. An unknown category stops the run with an
error rather than being silently ignored.

Typical reasons to add a row:

- a domain that was wrongly excluded, forced back in with `company`;
- a university or institute that is not in eduGAIN and has no `.ac`/`.edu`
  suffix (`academic`);
- a research institute, lab or charity (`research` / `nonprofit`);
- a public body without a `.gov` suffix (`government`);
- two domains of one company (`company` with `same_as`).

Many of the current rows were pre-filled as best guesses from the domain name
alone. The ones marked `guess:` deserve a second look before quoting numbers.

## Where the data comes from

All data comes from the Waldur REST API with `Authorization: Token ...`. List
endpoints are paged 300 rows at a time (the server maximum) and the `Link:
rel="next"` header is followed. Where possible the request asks only for the
fields the script needs (`field=`), and pins a sort order so that paging is stable.

| Endpoint | Used for |
|----------|----------|
| `/api/users/` (uuid, email) | Every user and their email domain. Includes users whose project/organisation role has expired or been revoked: revoking a role does not delete the user. Users are only deactivated, never hard-deleted. |
| `/api/marketplace-provider-offerings/` (name_exact) | Resolve the offering name (default `Isambard-AI Phase 2`) to its UUID. Skipped with `--offering-uuid`. |
| `/api/marketplace-offering-users/` | The offering's users: links each cluster username and offering user to a Waldur user, and so to an email domain. This is also what `users_with_access` counts. |
| `/api/marketplace-component-user-usages/` (type=node) | Per-user monthly node hours: one row per cluster username, allocation and billing month. |
| `/api/marketplace-resources/` | The projects (and their organisations) that have a resource (allocation) on the offering, and when each project's first resource was created. |
| `/api/projects/?include_terminated=true` | Project creation, start and end dates, including projects that have since ended and been soft-deleted. |
| `/api/user-permissions/?scope_type=project&show_inactive=true` | Current **and revoked** project memberships, to list former members and the projects of companies with no usage. |

`verify_usage_totals.py` additionally uses `/api/marketplace-component-usages/`
(allocation level).

If anything is requested but missing on a server (for instance `show_inactive`
on an older Waldur), the script falls back to what the server returns, so the
membership columns may then only reflect current roles.

## How usage is attributed

Usage is **per user, per month**. Waldur records it per billing period, not per
job, so the report's finest time resolution is a month. The current month is
still accumulating and is partial.

For each per-user usage row:

1. The row points to an **offering user** (the user's account on the
   offering). That offering user belongs to a Waldur user, and that user's
   email gives the domain.
2. If the link is missing, the script falls back to the cluster username.
3. If it still cannot be resolved to an email it goes to the **Unmatched usage**
   sheet.
4. Each row carries the project and organisation it was recorded against, so
   hours are attributed to the (company, organisation, project, month) it
   happened in.
5. Rows are then routed to the company the domain belongs to (after merging
   `same_as` domains), or to the excluded domain's own row.

Only **node hours on one offering** are counted (`type=node`; the unit comes
from the API and is normally hours). Zero-usage rows are ignored, so a user with
a zero in a month is not counted as active in that month.

**Companies with no usage stay in the list** with 0 hours. Their organisations
and projects are still shown if they were ever members of an offering project.

### Which projects are listed against a domain

A project is listed against a domain if the domain's users either **recorded
usage** in it or **were members** of it. A project counts as an "offering
project" only if it has a resource on the offering. Past memberships come from
revoked roles; a revoked role counts only if it was still active after the
project's first resource on the offering was created. Hard-deleted users and
offering users leave no trace in any of this.

### Column definitions that are easy to confuse

| Column | Counts |
|--------|--------|
| `user_count` | Waldur users with an email at this domain, whether or not they ever touched the offering. |
| `users_with_access` | Of those, users who have an account (offering user) on the offering. |
| `users_with_usage` | Of those, users with non-zero node hours on the offering. |

Pre-created users (added to a project before they have logged in) can show up
with placeholder names; they still count as users of their email domain.

## Workbook sheets and columns

All sheets are written to one `.xlsx`. The three domain sheets share one layout.

### Company domains

One row per surviving company (domains merged with `same_as` are one row),
sorted by `user_count` descending, then domain A-Z. This is **not** the order
companies joined.

| Column | Meaning |
|--------|---------|
| `domain` | The company's domain. |
| `new` | Only with a previous report (see [Monthly workflow](#monthly-workflow)). `yes` = not in the previous report; `changed (was X)` = it was, under another category; blank = unchanged, or decided by an override. |
| `user_count` | See above. |
| `node_hours` | Total node hours on the offering. |
| `first_project_added` | Date the **earliest** of the listed projects was created in Waldur. Often earlier than the company's first access to Phase 2, as projects are created before they get an allocation. |
| `first_usage_month` / `last_usage_month` | First and last month (`YYYY-MM`) with non-zero usage. Blank without usage. |
| `active_months` | Number of months with non-zero usage. |
| `users_with_access` / `users_with_usage` | See above. |
| `organisations` | Organisations (Waldur customers) of the listed projects. |
| `project_count` | Number of listed projects. |
| `projects` | The listed projects. |
| `merged_domains` | Other domains merged into this row via `same_as`. |
| `note` | Notes from `domain_overrides.csv`. |
| `emails` | Only with `--include-emails`. |

The `organisations` and `projects` cells show the **10 most-used** (most node
hours first) followed by `(+N more)`, to keep rows readable. `project_count` gives
the full number. `LIST_LIMIT` at the top of the script changes the cap. For
companies the full list is on the **Projects** sheet.

### Sovereign AI

Same columns, for companies whose users recorded usage in, or were members of, an
offering project belonging to the **Sovereign AI** organisation. Usage,
organisation and project columns count **only** those projects; `user_count`,
`users_with_access`, `merged_domains`, `note` and emails stay company-wide.

### Excluded

Same layout for every domain that was **not** counted as a company, so the data
can be reused later. Differences: `category` follows `domain`, and in place of
`merged_domains`/`note` there are:

| Column | Meaning |
|--------|---------|
| `category` | `academic`, `research`, `government`, `health`, `nonprofit` or `generic`. |
| `institution` | A key for pivoting by institution: the override's `same_as`, else the override or eduGAIN scope that matched (`mail.mcgill.ca` -> `mcgill.ca`), else the registrable domain (`eng.ox.ac.uk` -> `ox.ac.uk`). Generic providers stay as they are. |
| `matched_by` | The rule that put it here (`override ...`, `generic provider list`, suffix rule, `eduGAIN scope ...`). |
| `note` | The override's note. |

Sorted by category, then `user_count`. Nothing here is in any company count. As the
excluded `projects` cell is capped, the full per-project list for excluded
domains is not in the workbook.

### Monthly usage

Node hours and active users per company per month.

### By month

Per month across all companies: node hours, companies active, users active.

### Projects

One row per company per offering project: organisation, project, project start and
end date, node hours (0 if none), users with usage, current members, former
members, first and last month with usage. Companies only.

### Unmatched usage

Usage rows whose user could not be resolved to an email. Cluster usernames only
appear with `--include-emails`.

### Sector totals

Node hours, share of total, domains with usage and users with usage per sector
(`company`, and each excluded category), plus an `unmatched` row and a `TOTAL`.
The TOTAL is the per-user grand total across all projects that ever had Phase 2
usage; it is what `verify_usage_totals.py` compares against allocation-level
usage.

With `--no-usage` the Sovereign AI sheet, the last five sheets and all usage
columns are left out.

## Monthly workflow

1. **Run the script** with a staff token. It saves a dated workbook and
   automatically compares it with the most recent earlier dated
   `company_domains_*.xlsx` in the same folder. Use `--previous FILE` to choose a
   different baseline, or `--no-previous` to skip the comparison. The very first
   dated run needs `--previous` pointing at an older, undated report.
2. **Look at the `new` column** on Company domains and Excluded (the end of the
   run's output lists the same domains). Flagged rows are domains that appeared
   since last month, or whose category changed.
3. **Decide for each flagged domain** whether its category is right, using the
   domain, organisations and projects, the note, `matched_by`, and a web search if
   needed.
4. **If wrong, add a row to `domain_overrides.csv`** and re-run. Nothing needs
   recording for correct classifications: the next run compares against this
   month's report.
5. Borderline cases (non-profits, public bodies run like companies, personal
   domains) are judgement calls. Flag them to the people who own the number
   rather than deciding alone.

A separate list of reviewed domains was deliberately not kept: nobody would
maintain it, and last month's report already records what is new.

## Command-line options

| Option | Effect |
|--------|--------|
| `--token TOKEN` | Waldur API token (or `WALDUR_TOKEN`, or typed at a prompt). |
| `--base-url URL` | API base URL (default `https://portal-api.isambard.ac.uk`, or `WALDUR_BASE_URL`). |
| `--output FILE` | Output path (default `company_domains_YYYY-MM-DD.xlsx`). |
| `--include-emails` | Add individual emails (and cluster usernames on the Unmatched sheet). Off by default. |
| `--overrides FILE` | Overrides CSV (default `domain_overrides.csv` next to the script). |
| `--previous FILE` | Report to compare against for the `new` column. |
| `--no-previous` | No comparison, no `new` column. |
| `--no-edugain` | Skip the eduGAIN rule (and the download). |
| `--refresh-edugain` | Re-download the eduGAIN scopes even if the cache is fresh. |
| `--no-usage` | Domain list only; skip every usage, project and membership request. |
| `--offering-name NAME` | Offering to report usage for (default `Isambard-AI Phase 2`). |
| `--offering-uuid UUID` | Same, by UUID (skips the name lookup). |

## Backend load

The script is meant to be run about once a month, so it is deliberately simple
rather than fully optimised: the aim is to avoid anything wasteful, not to shave
every request. The load was reviewed in detail while building it.

### What a run does

A run makes a handful of **bulk, paged, read-only** requests (see
[Where the data comes from](#where-the-data-comes-from)), never one request per
user, project or usage row. Each endpoint is read once, in pages of 300, so the
number of requests for an endpoint is roughly its row count divided by 300. The
requests that grow with history are the per-user usage rows (one per cluster
username, allocation and billing month) and the project memberships.

| Endpoint | How it is requested | Notes |
|----------|---------------------|-------|
| `/api/users/` | `field=uuid,email` | Only the two fields needed. |
| `/api/marketplace-offering-users/` | `offering_uuid`, `field=uuid,username,user_uuid` | One offering only. |
| `/api/marketplace-component-user-usages/` | `offering_uuid`, `type=node`, field-restricted | The largest request. One extra one-row request reads the unit and `X-Result-Count`. |
| `/api/marketplace-resources/` | `offering_uuid`, field-restricted | |
| `/api/projects/` | `include_terminated=true`, `field=uuid,created,start_date,end_date` | Needed for ended projects too. |
| `/api/user-permissions/` | `scope_type=project`, `show_inactive=true` | **The heaviest per row**: this serializer does not support `field=`, so every row comes back in full. It is one pass over all project roles. |

Other measures:

- **Server-side filtering and field restriction.** Waldur's list endpoints accept
  `field=` (a restricted serializer), so each request names the fields it needs.
  Usage is filtered to one offering and one component type rather than fetched in
  full and filtered locally.
- **Maximum page size.** The server's pagination caps `page_size` at 300, which
  is what is requested, so the number of round trips is minimal.
- **`--no-usage`** skips every usage, project and membership request and gives
  only the domain list from `/api/users/`.
- **eduGAIN** is downloaded at most once every 30 days (`edugain_scopes.json`),
  and it is a public URL, not Waldur.
- **Retries.** Transient 502/503/504 responses on `GET`s are retried with
  backoff (3 retries), so a gateway blip part-way through does not force a full
  re-fetch.
- **Request timeout** of 120 seconds per page.

### Pagination stability

Paging through a large list while the system keeps writing can skip or repeat
rows, which would silently change totals. Several of the default orderings are
poor keys, so the script sets its own:

- Offering users default to ordering by username, which is often null, so they
  are fetched `o=created` (effectively unique).
- Per-user usage defaults to ordering by component usage date, which has many
  ties, and the current month's dates change as usage is reported. It is fetched
  ordered by billing period and username, which does not change and puts newly
  added rows at the end.
- Waldur's pagination adds a primary-key tie-breaker to any ordering
  (`ensure_total_ordering`), so ties are still stable.
- Usage and allocation rows are **de-duplicated by UUID**, and the number of rows
  received is compared with the server's `X-Result-Count`. A mismatch prints a
  warning telling you to re-run if the totals matter.

### Things checked about what the system does on read

- Listing users with `USER_DATA_ACCESS_LOGGING_ENABLED` on writes GDPR
  access-log entries, so each run would appear there. It is off by default.
- `user_email` on an offering user is hidden unless the offering's
  `OfferingUserAttributeConfig` exposes email. The script therefore does not rely
  on it: it joins offering users to Waldur users by `user_uuid` and takes the
  email from `/api/users/`.
### Alternatives considered for usage

Two sources of per-user usage exist: the marketplace's own records
(`/api/marketplace-component-user-usages/`, written when the OpenPortal plugin
syncs a project's usage) and OpenPortal's own allocation-user usage. The
marketplace records were chosen because they keep history:

- Marketplace usage rows survive allocation termination. Terminating an
  allocation deletes the OpenPortal allocation, which cascades to its
  allocation-user usage, but the marketplace rows remain. Earlier usage (for
  example from last year) is therefore still available only from the marketplace
  records.
- Their one weak point is that per-user rows cascade when the offering user they
  belong to is hard-deleted. Offering users are only hard-deleted by a staff
  deletion through the API, by deleting the Waldur user, or by the remote sync.
  Revoking a project role does not delete them. Users are deactivated, not
  deleted, in normal operation, so this is rare.

## Privacy

- The report contains **no email addresses** unless `--include-emails` is passed.
- Cluster usernames on the Unmatched usage sheet likewise only appear with
  `--include-emails`.
- `verify_usage_totals.py` prints aggregates only: no names or emails.
- Even without emails, the workbook names organisations and projects, and
  per-domain usage can identify small companies. Treat workbooks as internal.
  They are intentionally not committed to the repository.

## Verifying the usage totals

### Why a separate check exists

The report attributes usage **per user**, because that is the only way to tie
node hours to a company: a user has an email, an email has a domain. The system
also records usage at **allocation level**, as the project's total for a month
(one record per allocation per month). Both come from the same OpenPortal usage
report for each project and **should agree**:

- **allocation level** (`/api/marketplace-component-usages/`): the project's
  total for the month;
- **per user** (`/api/marketplace-component-user-usages/`): that total split by
  user, written for the users linked to the allocation at the time of each sync.
  This is what the report uses.

The report does not use allocation-level usage for attribution. A project total
cannot say which company's users earned the hours, and the report is built
around users. But the allocation total is an independent measure of how much was
used, so comparing the two answers "did the per-user numbers capture everything?"
The check is a separate script rather than part of the report so that the
report stays focused and does not fetch a second large set of rows on every run.
Run it when the totals need defending, after a change to the usage logic, or
occasionally as a sanity check.

### Running it

```bash
WALDUR_TOKEN=<staff token> uv run verify_usage_totals.py
```

Options: `--base-url`, and `--offering-name` / `--offering-uuid` (same defaults
as the report). It is read-only and prints aggregates only: no names or emails.

It compares the two views month by month and prints:

- a table of allocation, per-user, difference, per-user percentage, number of
  allocations and number of mismatched allocations per month, flagging the
  current (partial) month;
- the grand TOTAL;
- the ten largest allocation-month differences, each labelled
  `organisation / project`, and marked `[no per-user rows]` where an allocation
  has a total but no per-user data.

Differences under 0.05 hours are treated as rounding. The comparison is done
per (allocation, month), so a gap can be pinned to the project that caused it
and positive and negative differences do not cancel out in the monthly total.

### Reading a gap

Usual reasons for a difference:

- **A user left mid-month.** Their per-user figure stops updating while the
  project total keeps counting later hours (per-user is lower).
- **Late usage for a closed month.** Syncs refresh last month's per-user figures
  but only write the project total for the current month (per-user can end up
  slightly higher).
- **Usage by a cluster account not linked to any Waldur user.** It is only in the
  total.
- **An allocation with a total but no per-user rows at all** (for example one
  with no active plan period). Those hours are in the allocation total but cannot
  be attributed to any company.

When last run, per-user usage covered about 99.8% of the allocation-level total.
The largest gap was one allocation in January 2026 (about 8,000 node hours) with
no per-user rows. Per-user rows cannot be reconstructed for it, so the report was
left unchanged rather than guessing; the gap is visible in this check instead.
Re-run it to get current figures before quoting one.

The report's own **Sector totals** sheet ends with the per-user grand total, which
is the number to compare against this script's per-user TOTAL: they should match.

## Known limitations

- **Estimate, not ground truth** (see [Why this is an estimate](#why-this-is-an-estimate)).
- **Monthly resolution only.** Waldur stores usage per billing period, not per
  job. The current month is partial.
- **Hours without per-user rows are not attributed.** They show in the
  verification script's gap, not in any company.
- **Hard-deleted records leave no trace.** Users are only deactivated in normal
  operation, but a hard-deleted user or offering user takes its usage rows with it.
- **Membership is approximate for past roles.** A revoked role counts only if it
  ended after the project's first resource on the offering was created.
- **`first_project_added` is project creation**, not first access to Phase 2.
- **Classification rules are heuristics.** Suffix and eduGAIN matching can both
  miss a university (add an override) or catch something that is not one.
- **Capped project lists.** Domain sheets show the 10 most-used organisations and
  projects. The Projects sheet has the full list for companies only.

## Files

| File | Purpose |
|------|---------|
| `company_domain_report.py` | The report. |
| `domain_overrides.csv` | Manual domain decisions. Commit changes. |
| `verify_usage_totals.py` | Cross-check against allocation-level usage. Imports helpers from the report script, so keep them together. |
| `edugain_scopes.json` | Generated cache of eduGAIN scopes. Not committed. |
| `company_domains_YYYY-MM-DD.xlsx` | Generated reports. Not committed. |
