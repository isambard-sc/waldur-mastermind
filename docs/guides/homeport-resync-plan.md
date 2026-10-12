# waldur-homeport Resync Plan

Companion to `upstream-resync-plan.md`. That document covers resynchronising
this repository (`chryswoods/waldur-mastermind`) against
`waldur/waldur-mastermind`; this one covers the matching work in
`chryswoods/waldur-homeport` against `waldur/waldur-homeport`.

**This document is temporary.** Delete it once the homeport resync is done —
it lives here only because the two repositories have to be reasoned about
together, and this repository is where the analysis was carried out.

The figures below come from reading `chryswoods/waldur-homeport` at
`e3872e5` (2026-08-19) against `upstream/develop` as of 2026-09-03.

## 1. Correcting the expectation

The natural assumption is that homeport is the easier half, being "just a
React app, all presentation". The measurements say otherwise, and it is worth
being clear about this before anyone plans around it.

Presentation is precisely what upstream rewrote. Since the fork point,
upstream has landed 1879 commits touching `src/`, including:

| Commit | Date | Migration |
| --- | --- | --- |
| `fcb894c01` | 2026-06-12 | New `waldur-js-client`, and a move to `tsgo` |
| `81467d882` | 2026-06-15 | `react-final-form` removed from table filters |
| `62ee6c79e` | 2026-06-17 | TabbedSection and EditField architecture |
| `ea0b44c23` | 2026-06-18 | Form controls migrated to the Group pattern |
| `bf9b1416b` | 2026-07-14 | `count()` HEAD helper replaced by SDK count methods |
| `95eb6cce7` | 2026-08-17 | Tailwind/shadcn migration, Phase 0 |
| `3bf9221c1` | 2026-08-27 | AppShell bootstrap consolidated into `waldur-shell` |

Every custom component in this fork was written against the pre-migration
form, table and shell APIs. So while there is no database to reconcile and no
migration graph to untangle, the component-level rework is larger than the
mastermind resync's was. Budget accordingly: the mastermind side was ~1-2
weeks; homeport is unlikely to be less.

## 2. Divergence

| Fact | Value |
| --- | --- |
| Fork point | `e506ac8e1`, 2025-11-02 (the same day as mastermind) |
| This fork ahead | 4777 commits |
| Upstream ahead | 2851 commits |
| Local diff since fork | 325 files, +29,488 / -662 |

By area, largest first:

| Area | Local change |
| --- | --- |
| `src/openportal` | 128 files (upstream has 65) |
| `src/proposals` | 47 modified, 23 added (198 files vs upstream's 344) |
| `src/openportal-remote` | 26 files (upstream has 4) |
| `src/project` | 25 files, +936 |
| `src/user` | 9 files, +273 |
| `src/customer` | 8 files, +252 |
| `src/broadcasts` | 11 files, +1052 |
| `src/marketplace` | 6 files, +138 |
| `src/administration` | 4 files, +153 |
| `src/navigation` | 2 files, +71 |
| `src/invitations` | 3 files, +44 |
| `src/auth` | 4 files, +20 |
| `src/permissions` | 2 files, +15 |

The commit counts come from a bounded fetch (`--depth=6000`), so treat them as
indicative; the file-level figures are exact.

## 3. Strategy

The same four categories as the mastermind plan.

### 3.1 Adopt upstream wholesale

**`src/proposals`.** Upstream's is 344 files against this fork's 198, and
backs the far more advanced proposal system described in the mastermind plan
(reviewer pools, bids, conflict-of-interest detection, ORCID, affinity
matrices, compliance checklists, workflow steps). Bespoke proposal work lives
in a separate fork. Take upstream's entirely and discard all local proposal
changes.

**`src/broadcasts`.** The local changes here are the broadcast message
attachment UI and the proposal-round recipient targeting, both dropped on the
mastermind side. Confirmed with the fork owner that this fork does not use the
`send_to_me` / `additional_recipients` / `excluded_recipients` options either,
so there is nothing to preserve.

### 3.2 OpenPortal: mostly local, unlike mastermind

This is where homeport differs most from mastermind, and the difference runs
the other way.

Upstream ported the OpenPortal frontend in `0b0171df3` (2026-08-06, one day
after the mastermind port), but took much less of it:

| Comparison | Count |
| --- | --- |
| Files in both (by path) | 56 |
| Local only (by path) | 72 |
| Upstream only (by path) | 9 |
| Files in both (by basename) | 58 |
| Local only (by basename) | 63 |

Comparing by basename as well as by path matters because upstream reorganised
the module into subdirectories — `PullAllocationAction.tsx` sits at
`src/openportal/` locally and `src/openportal/actions/` upstream — so a
path-only comparison overstates what is missing.

Of the 72 local-only paths: 28 are hand-written types under `bindings/`, 2 are
Jest snapshots, and **42 are real components upstream did not take**, among
them `ManagedProjectDashboardCards.tsx`, `ProjectTemplateDetail.tsx`,
`ProjectTemplateCreateDialog.tsx`, `AllocationUsersTable.tsx`,
`ManagedProjectAuditFilter.tsx`, the autocomplete fields, and the quota pie.

So unlike mastermind — where upstream's OpenPortal was a superset and the
local delta was two commits — here a substantial body of local OpenPortal UI
has to be carried forward and reworked onto upstream's new form, table and
shell APIs. Treat this as the bulk of the job.

`src/openportal-remote` is the same shape, more starkly: 26 local files
against upstream's 4.

The `bindings/` types deserve a decision of their own. Upstream has no such
directory, relying on the generated client's types instead. Prefer deleting
them in favour of `waldur-js-client` types wherever the generated client
covers the shape, and keep only what it genuinely does not.

### 3.3 Delete permanently

Both fields dropped from mastermind have UI here that must go with them.
Upstream has zero references to either.

**`unix_username`** — 8 files, including a dedicated dialog:

- `src/user/dashboard/SetUnixShortNameDialog.tsx` (delete the component)
- `src/user/dashboard/UserProfile.tsx`
- `src/user/support/UserDetailsTable.tsx`
- `src/user/support/UserEditRows.tsx`
- `src/customer/team/CustomerUsersList.tsx`
- `src/customer/team/TeamTableComponent.tsx`
- `src/project/team/ProjectUsersList.tsx`
- `src/resource/actions/base.test.ts`

**`Project.short_name`** — 4 files:

- `src/project/create/ProjectShortNameGroup.tsx` (delete the component)
- `src/project/create/ProjectCreateDialog.tsx`
- `src/project/manage/ProjectMetadata.tsx`
- `src/user/support/UserEditRows.tsx`

Take care here: `short_name` also appears in
`src/openportal/AccessForEmail.tsx` and the two report chart option files.
Those are the **OpenPortal API's own** `userData.short_name`, unrelated to
`Project.short_name`, and upstream keeps them (`AccessForEmail.tsx` lines 75
and 79). Do not remove those.

### 3.4 Carry forward

The local work outside proposals, broadcasts and OpenPortal is small and
mostly pairs with something kept on the mastermind side.

In `src/project`:

| File | Pairs with |
| --- | --- |
| `ProjectDashboardBalance.tsx` | The `ProjectCredit` list scoping kept in mastermind |
| `AwardLockedDialog.tsx`, `MembershipLockedDialog.tsx`, `DomainRestrictionNotice.tsx`, `useProjectEmailPolicy.ts` | The `enforce_allowed_domains` enforcement hooks kept in mastermind |
| `useProjectAwardDetails.ts` | OpenPortal award details |
| `ProjectGracePeriodBanner.tsx` | Needs rebuilding — see below |
| `create/ProjectShortNameGroup.tsx` | Delete, per 3.3 |

Plus the smaller deltas in `src/user`, `src/customer`, `src/marketplace`,
`src/invitations`, `src/auth`, `src/administration`, `src/permissions` and
`src/navigation`. Review each against upstream before carrying: on the
mastermind side roughly half of what looked like a local fix turned out to
have been fixed better upstream in the interim, and the same is likely here.

## 4. The grace period, and why the banner must be rebuilt

Upstream reimplemented project grace periods as a per-project value with a
customer-level fallback (`Project.grace_period_days`,
`Customer.grace_period_days`, `get_grace_period_days()`), superseding this
fork's hardcoded 30-day constant. The mastermind resync adopted upstream's
version and reworked its two local dependents onto it.

The frontend has to follow, and the field usage shows the mismatch plainly:

| Field | Upstream | This fork |
| --- | --- | --- |
| `grace_period_days` | 22 | 0 |
| `is_in_grace_period` | 24 | 7 |
| `end_date_with_grace` | 0 | 3 |

`ProjectGracePeriodBanner.tsx` and the "extend grace period" button from
`e3872e5` are built on `end_date_with_grace`, which upstream's API no longer
leads with. Rebuild them on `grace_period_days` and `is_in_grace_period`, and
check what upstream already renders in
`src/marketplace/resources/details/ResourceFlags.tsx`,
`src/marketplace/resources/list/utils.tsx` and
`src/customer/details/CustomerDetailsPanel.tsx` before writing anything new —
some of the banner may already exist upstream in another form.

Note also that `grace_coefficient` in `src/customer/credits/` is a **different
concept** (credit consumption, not project lifetime). Do not conflate them.

## 5. The generated client is the coupling point

`waldur-js-client` is a published npm package generated from mastermind's
OpenAPI schema, and it is where the two repositories meet:

| | Version |
| --- | --- |
| This fork | `^7.8.6-dev.11` |
| Upstream | `8.1.3-rc.7.dev.20260901180117.270` |

That is a major version jump, and it carries the same role in this resync that
the `openportal` 0.32 → 0.92 upgrade carried in mastermind: settle it first,
because it constrains everything else.

Two things need checking against whichever client version is adopted:

1. **The endpoints added in the mastermind resync.** The
   `openportal-accounting-summary` endpoint gained an `offering_name` filter
   and an `include_offering_names` option when the local tail commits were
   reapplied. If the published client predates those, either regenerate it
   from the resynced mastermind schema or call them without the generated
   helper.
2. **The feature flags.** Mastermind kept 8 flags that upstream does not have:
   `show_openportal_remote_projects`, `enforce_allowed_domains`,
   `show_openportal_accounting_pages`, `credentials`, `disable_long_tokens`,
   `show_slug_as_id`, `minimal_user_profile` and `allow_user_creation`.
   Homeport reads these, so they must keep matching across the two repos.

Also note `src/table/generated/*` — homeport has its own codegen step
(`generate-filters.cjs`), including a generated `ProposalProposalsFilter.tsx`.
Regenerate rather than hand-editing anything under that directory.

## 6. Endpoint inventory: no cross-contamination

The mastermind plan flagged that discarding the local proposal work would drop
API surface with no upstream equivalent, and that homeport would need auditing
for anything depending on it. That audit is done, and the result is clean.

Every dropped endpoint this fork calls is confined to `src/proposals/`, which
is being replaced wholesale anyway:

| Dropped endpoint or field | Hits | Location |
| --- | --- | --- |
| `fixed_review_end_date` | 15 | `src/proposals/round/review/`, `src/proposals/update/rounds/` |
| `default_reapply_*` | 12 | `src/proposals/round/submission/`, `src/proposals/update/rounds/` |
| `minimum_required_uploads` | 7 | `src/proposals/proposal/create/`, `src/proposals/round/submission/` |
| `return_to_applicant` | 2 | `src/proposals/proposal/create/utils.ts` |
| `proposal-add-user` | 1 | `src/proposals/team/api.ts` |

Nothing outside `src/proposals` references any of them, and there are no
references at all to `resource_adjustments`, `effective_allocation`,
`detach_document`, `stale_reminder`, `return_to_reviewer`, or the broadcast
attachment endpoints.

So the only deletions needed outside the wholesale-replaced directories are
the `unix_username` and `short_name` UI in section 3.3.

## 7. Sequencing

1. Settle the `waldur-js-client` 7 → 8 move, and confirm whether the client
   needs regenerating from the resynced mastermind schema for the
   accounting-summary additions.
2. Reset onto `upstream/develop`. Adopt upstream for `src/proposals` and
   `src/broadcasts`.
3. Delete the `unix_username` and `short_name` UI, keeping OpenPortal's own
   `short_name` usage.
4. Rework the OpenPortal and OpenPortal-remote components onto upstream's
   current form, table and shell APIs. This is the bulk of the work; expect
   the EditField, Group-pattern and table-filter migrations to touch nearly
   every carried component.
5. Rebuild the grace-period banner on `grace_period_days` /
   `is_in_grace_period`, after checking what upstream already renders.
6. Carry the remaining small deltas, reviewing each against upstream first.
7. Typecheck, lint, run the test suite, and exercise the UI against the
   resynced mastermind branch.

## 8. Verification

Run against the resynced mastermind branch
(`claude/waldur-mastermind-resync-analysis-w824hs`), not against production.

Structural checks first, since they are fast and catch most of the fallout
from a reset of this size:

- typecheck (`tsgo` upstream, so expect new diagnostics against the old
  components)
- lint and format
- the Jest suite, including the snapshots carried with the OpenPortal
  components — regenerate rather than hand-edit, and read the diffs

Then exercise, at minimum:

- the OpenPortal project and allocation views, and the accounting pages
- the project dashboard balance widget, against the reworked `ProjectCredit`
  list endpoint
- the grace-period banner in and out of grace, with the grace period set at
  project level, inherited from the customer, and unset
- project team management with `enforce_allowed_domains` both on and off,
  since mastermind's enforcement hooks have no upstream test coverage
- project creation, confirming no short-name field remains
- the user profile and team lists, confirming no unix-username field remains

## 9. What the mastermind side already did

For reference while working here — the details are in
`upstream-resync-plan.md`:

- Adopted upstream wholesale for `waldur_openportal`, the marketplace
  OpenPortal modules and `proposal`; dropped the vendored `op.py` shim and
  moved to `openportal>=0.92.0`.
- Deleted `unix_username`, `short_name` and `BroadcastMessageAttachment`.
- Adopted upstream's per-project grace period, token rotation fix and
  project-ending notification, all of which superseded local versions.
- Carried forward the project date filters, the `ProjectCredit` list scoping
  (reimplemented to scope by role rather than bypass filtering), the 8 feature
  flags, the `enforce_allowed_domains` hooks, and assorted email and
  eager-loading fixes.
- Reapplied the two OpenPortal tail commits, one of which fixes a genuine
  upstream break against openportal 0.92 (`Status.PENDING` no longer exists).
- Left `scripts/resync_reconcile_db.sql` for the database, to be rehearsed
  against a restored dump before the live database.
