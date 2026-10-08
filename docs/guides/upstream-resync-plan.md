# Upstream Resync Plan

Resynchronising this fork (`chryswoods/waldur-mastermind`) against
`waldur/waldur-mastermind` `develop`.

## 1. Situation

| Fact | Value |
| --- | --- |
| Fork point | `8da8593be`, 2025-11-02 |
| This fork ahead | 604 commits |
| Upstream ahead | 3358 commits |
| Trial-merge conflicts | 66 files (29 `add/add`, 37 content) |

Upstream absorbed the OpenPortal extension from this fork in three passes:

| Commit | Date | Description |
| --- | --- | --- |
| `ac3a13b6f` | 2026-04-15 | Merge isambard changes into `waldur_openportal` [1/3] |
| `9b68095b7` | 2026-04-20 | Final merge of OpenPortal extension from Isambard fork |
| `912542505` | 2026-08-05 | Port OpenPortal 0.90 features and enhancements from Isambard fork |

`waldur_openportal/models.py` has **identical class sets, identical field
names and identical field definitions** between this fork and upstream, so the
OpenPortal database schema has genuinely converged. Upstream additionally
contributes `config.py`, `exceptions.py` and 13 test modules where this fork
had one.

## 2. Strategy

Reset onto `upstream/develop` and treat upstream as the source of truth.
Re-apply only a small, explicitly enumerated set of local changes on top.

Four categories:

1. **Adopt upstream wholesale** — `waldur_openportal`,
   `marketplace_openportal`, `marketplace_openportal_remote`,
   `waldur_mastermind/proposal`.
2. **Delete permanently** — `unix_username`, `short_name`, all proposal work,
   `BroadcastMessageAttachment`, `waldur_openportal/op.py`.
3. **Carry forward** — local bug fixes, feature flags, and the endpoints that
   waldur-homeport's visualisations depend on.
4. **One-time database reconciliation** — a script, not a merged migration
   history.

## 3. Adopt upstream wholesale

### 3.1 OpenPortal

Take upstream's tree for all three modules, then re-apply the only two local
commits that postdate upstream's 2026-08-05 port:

- `ae6a7628a` — offering filter on the allocation fetch, plus the project
  accounting summary view and serializer fields.
- `54854f7bb` — one-line `tasks.py` bug fix.

These need reshaping onto upstream's refactored code rather than a clean
cherry-pick.

### 3.2 The `openportal` client library

This fork imports a vendored 602-line shim, `waldur_openportal/op.py`, via
`from . import op as openportal` in every module. Upstream deleted the shim
and imports the real package: `import openportal`, pinned `openportal>=0.91.0`
against this fork's `>=0.32.2`.

Adopt upstream's approach and move the pin to `openportal>=0.92.0`. The
deployed OpenPortal *service* must be upgraded in step — this is a
coordinated, cross-repository change and the main scheduling risk in the whole
resync.

### 3.3 Proposal

Upstream's proposal app is a different and far more advanced system
(`views.py` 2,388 → 6,770 lines; `models.py` 1,051 → 3,132; 56 → 83
migrations) with reviewer pools, bids, conflict-of-interest detection, ORCID
integration, affinity matrices, compliance checklists and workflow steps.

Bespoke proposal development lives in a separate fork. Here, upstream's
version is adopted in full and all local proposal work is discarded.

## 4. Delete permanently

### 4.1 `unix_username` and `short_name`

Superseded by shortname handling inside `waldur_openportal` (`UserInfo.shortname`
and `ProjectInfo.shortname`, synced to `User.slug` / `Project.slug`). Remove:

- `core.User.unix_username` — field, `save()` sync logic, `core/admin.py`,
  `permissions/serializers.py` (`user_unix_username`),
  `structure/serializers.py`.
- `structure.Project.short_name` — field, `save()` sync logic,
  `structure/admin.py`, `structure/filters.py` search field,
  `structure/serializers.py`.

Upstream's OpenPortal code guards both with `hasattr`, so removing the columns
makes it fall back to `slug` with no code change on upstream's side. Upstream
files are deliberately left untouched.

No migration is needed for either removal. Adopting upstream's model state and
migration graph wholesale means neither column was ever part of that state, and
`makemigrations --check` confirms nothing is pending. The deployed database
keeps the columns until the reconciliation script drops them.

### 4.2 Proposal

All of `waldur_mastermind/proposal`, plus the local changes that only exist to
serve it:

- `notifications/utils.py` — `get_proposal_team_members`, `get_proposal_reviewers`
- `notifications/serializers.py` — `round`, `proposal_states`, `include_reviewers`
- `structure/notifications.py` — `StaleProposalReminderContext` and related
- `users/filters.py` — Call-invitation manager filtering
- `users/serializers.py` — `PROPOSAL.MANAGER` invitation guard
- `permissions/enums.py` — `MANAGE_PROPOSAL` remapping

### 4.3 `BroadcastMessageAttachment`

The whole `notifications` app is reset to upstream. The local delta there was
the attachment model, serializer and `attach_file` action, `format_attachment_links`
in `tasks.py`, and the proposal-round recipient targeting in `utils.py` and
`serializers.py` — all of it dropped. `format_mastermind_link` in
`core/utils.py` was its only remaining consumer and is removed as dead code.

This also drops three generic broadcast conveniences that came in on the same
serializer and have no upstream equivalent: `send_to_me`,
`additional_recipients` and `excluded_recipients`. Confirmed with the fork
owner that the homeport broadcast composer does not use them, so they are gone
for good rather than pending a decision.

### 4.4 Obsolete Dockerfile hack

`RUN pip install django-cors-headers` is no longer needed: upstream's
`pyproject.toml` now declares `django-cors-headers>=4.5.0,<5.0.0`.

## 5. Carry forward

Local bug fixes and homeport support. None of these are present upstream
unless noted.

### 5.1 Bug fixes

| Location | Change |
| --- | --- |
| `core/utils.py` | Collapse blank lines in rendered email templates; warn instead of failing on an unknown notification key; double-slash hardening in `format_homeport_link`. |
| `billing/serializers.py` | `_original_eager_load` fix so credit and billing eager-load optimisations compose instead of double-applying. |

The local `Token.objects.get_or_create` race fix in `core/authentication.py` is
**not** carried forward: upstream's own fix wraps the rotation in a savepoint
and tolerates a concurrent rotation via `IntegrityError`, covering the call
site the local fix missed.

### 5.2 Homeport support

| Location | Change |
| --- | --- |
| `structure/filters.py` | Project date filters: `start_date_after/before`, `end_date_after/before`, `active_during`, `started`, `ended`, `in_grace`. |
| `structure/serializers.py` | Grace-period-aware project end date (commit `95486ab`). |
| `invoices/views.py` | `ProjectCredit.list` so project members can read their own credits — needed by the homeport accounting widget. |
| `core/features.py` | 8 feature flags, none upstream: `show_openportal_remote_projects`, `enforce_allowed_domains`, `show_openportal_accounting_pages`, `credentials`, `disable_long_tokens`, `show_slug_as_id`, `minimal_user_profile`, `allow_user_creation`. |
| `users/templates` | Invitation email template improvements. |

Two items in this group turned out to be superseded rather than carried:

- **Grace periods.** Upstream implements them per project with a
  customer-level fallback (`Project.grace_period_days`,
  `Customer.grace_period_days`, `get_grace_period_days()`,
  `get_effective_end_date()`, `is_in_grace_period`, `end_date_with_grace`),
  exposes them on the serializer including a staff-only write path, and covers
  them with a `GracePeriodTest` suite. That is strictly better than the local
  hardcoded `PROJECT_GRACE_PERIOD_DAYS = 30`, which is dropped. The two local
  dependents are reworked onto upstream's API: `validate_end_date` reads
  `self.instance.get_grace_period_days()` (a project being created has no
  grace period, so a past end date is rejected as upstream does), and
  `filter_in_grace` resolves each project's own grace period in the database
  via `Coalesce` over the project and customer columns.
- **The project-ending notification and grace-period-aware termination.**
  Upstream reimplemented all of this more thoroughly — deletion moved to a
  Celery task, resources paused while inside the grace period where the
  offering supports it, and a per-offering opt-out — so `marketplace/`
  handlers, tasks, templates and tests are all upstream's.

### 5.3 OpenPortal domain enforcement

Upstream took `assert_email_allowed_for_project` and
`check_managed_project_membership_control` into `waldur_openportal/utils.py`,
but **not the callers**. Upstream only mentions `enforce_allowed_domains` in a
docstring, and never declares the feature flag, so the functionality is
currently unreachable upstream. Carry forward:

- `permissions/views.py` — enforcement on role grant and role change
- `users/views.py` — enforcement on invitation
- `core/features.py` — the `enforce_allowed_domains` flag itself

Good candidate to offer upstream as a follow-up.

### 5.4 Operations

| Location | Change |
| --- | --- |
| `logging/tasks.py` | `purge_old_events` batched cleanup task. |
| `server/celery_settings.py` | `purge-old-events` schedule, every 3 days. |
| `server/admin/menu.py` | `waldur_openportal.*` admin menu entry. |
| `docker/rootfs/etc/nginx/*` | Local nginx configuration. |
| `docker/rootfs/etc/waldur/` | `permissions.yaml`, `notifications.json`. |

### 5.5 Known duplication

Upstream inlined its own `PROJECT_GRACE_PERIOD_DAYS = 30` in
`waldur_openportal/board.py` rather than importing from
`structure/models.py`. Both values agree at 30. Leave upstream's copy alone
and propose the shared import upstream later.

## 6. Database reconciliation

A one-time script, `scripts/resync_reconcile_db.sql`, run against a restored
production dump before going near the live database. This fork is the only
deployment, so recording upstream's migrations as applied plus targeted DDL is
sufficient. The script is one transaction and is safe to re-run.

### 6.1 OpenPortal — almost all bookkeeping

Migration *numbers* collide (local `0034`–`0043` against upstream
`0034`–`0039`), and the two routes reach the same objects with one exception:

1. Delete the `waldur_openportal` rows for local `0034`–`0043` from
   `django_migrations`.
2. Record upstream `0035`–`0039` as already-applied. Upstream `0035` creates
   the two cached report tables and their indexes, which local `0034`–`0036`
   already created; `0036` creates the five remote-project models that local
   `0037`–`0043` created; `0037`–`0039` are `AlterModelOptions` only.
3. Let upstream `0034` **run for real**. It adds `can_be_managed` to
   `allocation` and `remoteallocation`, which upstream's models inherit from
   `core_models.AvailableMixin` — a base class this fork never had, so those
   columns genuinely do not exist here.
4. Verify with `makemigrations --check --dry-run` that no changes are pending.

The `AvailableMixin` case is worth dwelling on, because the original analysis
missed it and only `migrate` on a real database caught it. Comparing the two
trees' `models.py` showed identical class sets and identical field
*definitions*, which was read as "the schema has converged". That comparison
only saw fields **declared in that file**; it was blind to fields arriving
through a base class, and `can_be_managed` is declared on `AvailableMixin` in
`waldur_core`.

Diffing the model **base classes** as well as their declared fields catches
this, and confirms `AvailableMixin` on `Allocation` and `RemoteAllocation` is
the only such difference in the app.

**The faking cannot be done in SQL.** An earlier version of the reconciliation
inserted the five `django_migrations` rows directly. That is wrong, and only a
database in production's migration state shows it:

```text
InconsistentMigrationHistory: Migration waldur_openportal.0036_remote_projects
is applied before its dependency structure.0078_alter_servicesettings_certificate
```

Upstream's `0036_remote_projects` depends on
`structure.0078_alter_servicesettings_certificate`, which production has not
applied. Django checks that every applied migration has its dependencies
applied *before doing anything at all*, so those rows make every `migrate`
invocation fail -- including `migrate --plan`. Recording a migration as applied
at a point where the graph allows it is something only Django can get right,
because only Django knows the graph.

So the faking lives in `scripts/resync_migrate.sh`, which runs after the
reconciliation instead of a plain `migrate`, **with the application down and
only the database up**:

```bash
docker compose up -d waldur-db
docker compose exec -T waldur-db psql -U waldur -d waldur < scripts/resync_reconcile_db.sql
scripts/resync_migrate.sh --manage \
    'docker compose run --rm --no-deps -T --entrypoint waldur waldur-mastermind-api'
docker compose up -d
```

`run --rm`, not `exec`: Waldur migrates at startup, so a running API container
has already migrated -- or tried to and failed -- and would be racing this.
`--no-deps` keeps `docker compose run` from starting the queue, worker and beat
alongside it, which would otherwise be reading and writing a schema changing
underneath them. The steps are:

1. `migrate structure` -- forward, no target, bringing in `0078`.
2. `migrate waldur_openportal 0034` -- for real, adding `can_be_managed`.
3. `migrate waldur_openportal 0039 --fake` -- recording `0035`-`0039`.
4. `migrate` -- everything else.
5. `scripts/set_default_grace_period.py` -- restore the 30-day grace period.
6. `makemigrations --check --dry-run` -- proof the fakes matched reality.

Step 5 is data, not schema, and it matters as much as the rest. Upstream's
`structure/0067` replaced `Project.grace_period_days` -- a property returning a
fixed 30 days -- with nullable columns on `Customer` and `Project` carrying no
default and no backfill. `get_grace_period_days()` falls through project ->
customer -> **0**, so on an upgraded database every row means zero: a project's
effective end date collapses onto its end date, `is_in_grace_period` can never
be true, and
`marketplace.terminate_resources_if_project_end_date_has_been_reached`
terminates its resources the day it ends -- then schedules the project itself
for deletion once nothing active is left. Deploying past `0067` without this
silently expires everything sitting in its grace period. Caught in local
testing against the sanitised copy, where losing a few projects cost nothing.

It is a script rather than a migration deliberately: a local migration under
`src/waldur_core/structure/migrations/` is upstream's directory, and one stray
merge request away from being pushed back to them. Only NULL rows are touched,
so it is idempotent and keeps any value set on purpose.

Two traps that shaped it. `migrate app NNNN` migrates *to* that migration, so
on a database already past it Django starts **unapplying** -- reversing real
migrations and removing fields. Steps 2 and 3 therefore check first, which
also makes the script re-runnable after a failure. And both apps are squashed
(`structure/0041_squashed_0085`, `waldur_openportal/0001_squashed_0039`), so
naming `0078` as a target is not reliably a node Django will accept; migrating
the app forward sidesteps the question.

A third trap, found by running the script twice rather than once. That check
used to grep `showmigrations`, which lists only the squash once it is applied

```text
 [X] 0001_squashed_0039 (12 squashed migrations)
```

and never the individual migrations it replaced -- so on a database the script
had already migrated, the guard reported `0034` as *not* applied, step 2 ran
`migrate waldur_openportal 0034`, and the unapply the guard exists to prevent
happened anyway (`KeyError: 'competence'`). The first run on production is
unaffected: it has the individual migrations recorded and no squash applied.
It is the re-run that broke. The guard now asks Django's migration loader,
which resolves replacements -- a replaced migration reads as applied when its
squash is -- and the migration name it is given has to be exact, where the
grep tolerated a prefix.

Why this was not caught earlier: the dev database used for the first
rehearsals already had `structure` at `0085` and upstream
`waldur_openportal.0034` applied, left behind by the first, failed migration
attempt. It was never a faithful starting state. Only the sanitised copy of
production was.

### 6.2 Proposal — clean reset

The portal holds no proposals, so the app is reset rather than migrated:

1. Drop the tables and columns added by local `0047`–`0054`, including
   `ProposalIdGenerator` and `ProposalResourceAdjustment`.
2. Delete the local `0047`–`0054` rows from `django_migrations`.
3. `migrate proposal` to replay upstream `0047`–`0077`.

Verified safe: there are **no column-name collisions** on the same model.
Upstream's `submitted_at` is on `ReviewerBid`, not `Proposal`, and its notes
fields are `internal_notes` / `review_notes` / `manager_notes`, distinct from
the local `Proposal.notes`.

**Expect a WARN on `local_proposal_rows_to_delete`.** Production applied seven
of the eight local proposal migrations: it was deployed from a commit before
`0054_round_fixed_review_end_date`, so that row is absent and so is the column
it would have added. The reconciliation copes by construction -- every drop is
`IF EXISTS` and every delete is keyed on rows that may already be gone -- so
seven of eight is a pass, not a problem.

What would NOT be benign is an *extra* `proposal` migration at 0047 or above
that the reconciliation does not name. A `django_migrations` row pointing at a
migration file no longer in the tree makes `migrate` fail on an unknown node.
Check for one with:

```sql
SELECT name FROM django_migrations
WHERE app = 'proposal' AND name >= '0047' ORDER BY name;
```

### 6.3 Dropped columns

`core.User.unix_username`, `structure.Project.short_name` and the broadcast
attachment table are dropped by the script rather than by migrations — the
adopted model state never contained them, so there is nothing for Django to
generate. The migration rows that added them, and the merge nodes that
stitched the local branch into upstream's history, are deleted with them.

Confirm OpenPortal shortnames have fully migrated to `UserInfo.shortname` /
`ProjectInfo.shortname` **before** dropping; the script carries the two
verification queries in a comment, and the data is not recoverable afterwards.

### 6.4 Squashes

Upstream added `0001_squashed_0039` (openportal) and `0001_squashed_0074`
(proposal), regenerated as state diffs in `80437de2c`. Harmless for an
existing database, but confirm a fresh `migrate` does not take a different
route than the reconciled one.

## 6.5 Production scale

Measured from the sanitised copy of production (September 2026), so these are
the real numbers the deployment has to get through:

| | rows |
| --- | --- |
| people (`core_user`) | 4,276 |
| organisations | 23 |
| projects | 1,651 |
| resources | 1,956 |
| events (`logging_event`) | 2,851,926 |
| invoices | 473 |

What that means for the migration window:

- **No expensive DDL lands on the big table.** The recent `logging` migrations
  touch `emaillog` and model options, not `event`, so the 2.85 million events
  are not rewritten or reindexed. The index-creating migrations on `event`
  (`0015`, `0018`) long predate this branch and are already applied.
- **The proposal replay is free**, however long the series. Production holds no
  proposals, so upstream's `0047`-`0077` run against empty tables.
- **The two column drops are cheap.** `ALTER TABLE ... DROP COLUMN` in
  PostgreSQL only marks the attribute dropped; it does not rewrite the table.
  1,651 projects and 4,276 users would be quick even if it did.
- **The data migrations that scale with these counts** are
  `core/0041_backfill_user_initial_revisions` (one revision per user, so 4,276)
  and `core/0048_backfill_notificationtemplate_initial_revisions`. Both are
  exercised representatively by the sanitised copy, since it keeps the user and
  template counts.

### What the sanitised copy does NOT rehearse

The sanitiser empties or blanks three things, so the copy cannot time the
migrations that read them. All three are worth knowing before the deployment
rather than during it:

| dropped by the sanitiser | migration that reads it | risk |
| --- | --- | --- |
| `reversion_version`, `reversion_revision` | `marketplace/0270_scrub_secret_options_from_reversion` | Low. It filters with `serialized_data__contains` and walks id-ordered keyset batches, so only Offering versions mentioning the key reach Python. But the copy has no history at all, so the copy proves nothing either way. |
| `structure_servicesettings.password`, `.token`, `.options` | `structure/0080`, `structure/0081` (encrypt in place) | Low: few rows. |
| `marketplace_offering.secret_options` | `marketplace/0269_encrypt_existing_secret_options` | Low: few rows. |

`reversion_version` is the one to check, because it is plausibly the second
largest table in production after `logging_event` and nothing here measures it.
`scripts/resync_preflight_check.sql` reports the ten largest tables with sizes,
which settles it.

## 6.6 Rehearsal result

The whole sequence has been run against a sanitised copy of production
(4,276 users, 1,651 projects, 1,956 resources, 2.85 million events), on
PostgreSQL 17 to match production's 17.2:

| step | outcome |
| --- | --- |
| `resync_preflight_check.sql` | One WARN, explained in 6.2. **`irreversible_gate` passed** -- no user or project would lose a value the two column drops cannot recover. |
| `resync_reconcile_db.sql` | Applied clean |
| `resync_migrate.sh` | **5m58s**, ending in `No changes detected` |

`No changes detected` is the result that matters: it proves the five faked
openportal migrations really did correspond to objects already present in the
shape upstream expects. A fake that did not match would show up here as a
migration Django wants to create.

So the deployment window is **about six minutes of migration**, plus the
restore-and-reconcile time, plus whatever margin you want. Two things that
figure does not include:

- `marketplace/0270_scrub_secret_options_from_reversion`, which walks reversion
  history. The sanitiser empties `reversion_version`, so it completed instantly
  here and this rehearsal says nothing about it. See 6.5; the pre-flight's
  `largest_table` output is what sizes it.
- The `VACUUM`/autovacuum catch-up after a migration that rewrites table data.

What the rehearsal also established, which no amount of reading could:

- The reconciliation could not fake migrations in SQL (6.1). That surfaced only
  against production's migration graph.
- The dev database used for the earlier rehearsals was not a faithful starting
  state -- it carried `structure` at `0085` and upstream
  `waldur_openportal.0034`, left by the first failed attempt.

## 6.7 Periodic tasks the resync adds

43 new beat-scheduled tasks arrive with upstream and 6 go away. Most are
harmless, but several delete or terminate things on a schedule, and they start
running the moment the workers come back up. Enumerate them with:

```bash
git grep -h -A2 '"task":' <ref> -- '*extension.py' | grep '"task":'
```

**Destroys or revokes data. Look at these before the first beat cycle.**

| Task | Schedule | What it does |
|---|---|---|
| `marketplace.cleanup_stale_offering_users` | daily | Schedules offering-user *deletion* for every user with no active role on the project. Runs over **every** OfferingUser not already deleting, so the first run after the resync is the big one. |
| `marketplace.reconcile_robot_account_access` | 02:30 daily | Removes users from robot accounts where no active `UserRole` on the project exists. A backstop for the signal-driven path, so it acts on historical drift the first time it runs. |
| `marketplace.revoke_outdated_consents` | daily | Revokes `UserOfferingConsent` rows for any active ToS with `requires_reconsent` whose grace period has passed. |
| `marketplace_openstack.terminate_child_resources_of_terminated_tenants` | daily | Marks Instance/Volume resources TERMINATED under an already-terminated tenant. Mark-only -- no backend call, no quota release, no plugin rows deleted -- and writes a DONE terminate `Order` for the audit trail. |
| `marketplace.cleanup_usage_poll_records` | daily | Deletes `ComponentUsagePollRecord` older than `USAGE_POLL_RECORD_RETENTION_MONTHS` (default 3). |
| `policy.cleanup_slurm_evaluation_logs` | daily | Deletes `SlurmPolicyEvaluationLog` past its retention. |
| `logging.cleanup_orphan_subscription_queues`, `marketplace_site_agent.cleanup_{stale,dangling}_agent_queues` | 6h / 24h / 1h | Delete RabbitMQ queues with no matching database row, or whose owner is inactive. RMQ state, not Waldur data. |
| `marketplace_script.cleanup_orphaned_k8s_resources` | -- | Deletes Waldur-created Kubernetes Jobs and ConfigMaps older than an hour. |

The two that change *resource lifetimes* rather than clean up after them:

- `marketplace_remote.reconcile_resource_end_dates` (daily) walks every
  non-terminated remote resource and reconciles its `end_date` against the
  remote. An end date pulled from a remote feeds straight into project expiry.
- `terminate_resources_if_project_end_date_has_been_reached` is not new, but
  its behaviour changed completely -- see the grace period step in §5 of the migrate script. It
  **deletes** a project outright once its effective end date has passed and no
  active resources remain.

**Accounting, at the month boundary.** Invoice finalisation is now two-phase:

- `invoices.create_monthly_invoices` still runs at 00:00 on the 1st, but with
  `INVOICE_FINALIZATION_GRACE_PERIOD_HOURS > 0` it moves invoices to
  `PENDING_FINALIZATION` instead of `CREATED`.
- `invoices.finalize_previous_invoices` (new, hourly on the 1st-3rd) does the
  `CREATED` transition once the grace period has elapsed.
- The default is **0**, i.e. finalise immediately, which is the old behaviour.
- `send_monthly_invoicing_reports_about_customers` **no longer has a cron
  entry**. It is now triggered programmatically at the end of whichever of the
  two tasks finalises. If reports stop arriving on the 2nd, that is where to
  look.
- `set_to_zero_overdue_credits` now takes an `effective_date` and refuses a
  future one, and records an `EXPIRY` credit transaction against the month the
  balance was forfeited in.

**New pulls worth knowing about before they surprise you:**
`marketplace.ServicePropertiesListPullTask` (24h) and
`ServiceResourcesListPullTask` (hourly, on the hour) both start pulling against
every provider; `openstack.TenantUsageBillingPoll` and
`billing.refresh_estimates` are new; `marketplace.sync_component_usage_summaries`
and `re_evaluate_usage_limit_restrictions` recompute usage state hourly/daily.

**Removed:** `invoices.send_monthly_invoicing_reports_about_customers` (see
above), `marketplace_remote.pull_invoices`, and four proposal tasks including
`proposal.delete_stale_proposals` -- so one deletion path goes away.

### What this deployment is actually exposed to

Checked against the sanitised production copy, with only OpenPortal offerings
connected. Three of the destructive tasks cannot touch it:

- `terminate_child_resources_of_terminated_tenants` is filtered to OpenStack
  tenant offerings.
- `reconcile_resource_end_dates` is filtered to `REMOTE_OFFERING`, which is
  `"Waldur.RemoteOffering"` -- **not** `Marketplace.OpenPortalRemote`. The
  names invite the opposite conclusion.
- `terminate_resources_in_state_erred_without_backend_id_...` is filtered to
  `"Marketplace.Slurm"`.

Of the three that are not type-filtered:

- `cleanup_stale_offering_users` narrows its deletions to
  `offering__plugin_options__offering_user_auto_deletion=True`. All six
  OpenPortal offerings have the key unset, and a missing key is SQL NULL, so
  nothing is deleted. It still fans out one Celery task per user holding any
  offering user -- thousands daily, each a no-op.
- `reconcile_robot_account_access`: no robot accounts have users, so it is a
  no-op.
- `revoke_outdated_consents`: **five** active reconsent ToS exist, so this one
  has live input. `scripts/dryrun_revoke_outdated_consents.py` reports what it
  would revoke without writing.

A conservative first deployment can leave beat down, bring the API up, and
start beat only after spot-checking what the first cycle of the destructive
tasks would do.

### Project deletion is not only a periodic task

Two paths delete projects, both keyed on `Project.is_expired` and therefore
both fixed by the grace-period backfill -- but only one is in a beat schedule:

1. `terminate_resources_if_project_end_date_has_been_reached`, daily at 01:40.
2. `delete_expired_project_if_every_resource_has_been_terminated`, a **signal
   handler** on `Resource` state changes, which fires whenever the last
   resource of an expired project reaches TERMINATED. Auditing the beat
   schedule alone will not find it.

The resync changed the second one's guard. It used to test the grace period
explicitly (`if today <= project.end_date_with_grace: return`); it now relies
on `is_expired` alone, whose meaning changed to include the grace period.
Equivalent *provided* `grace_period_days` is set -- which is why zero removed
the guard from both paths at once.

Both are **soft** deletes: `Project.delete()` sets `is_removed=True`. Hard
deletion happens only from `Customer.delete()` and the `cleanup_structure`
management command, both manual. The only other project deletion in any task
is the throwaway project a marketplace_script dry run creates.

## 7. Sequencing

1. Scope the OpenPortal 0.32 → 0.92 library and service upgrade. This can
   change the whole timeline, so settle it first.
2. Reset onto `upstream/develop`; adopt upstream for openportal, marketplace
   openportal modules, and proposal.
3. Re-apply the two OpenPortal tail commits.
4. Re-apply the section 5 carry-forward set.
5. Add migrations dropping `unix_username`, `short_name` and the attachment
   table.
6. Write and rehearse the reconciliation script against a production dump.
   For a rehearsal at production scale rather than against dev data, sanitise
   a production dump first - see `docs/guides/production-data-sanitisation.md`.
7. Run and extend the test suite.
8. Resync waldur-homeport, per `homeport-resync-plan.md`. The removed-endpoint
   inventory that step depended on is done and recorded there: every dropped
   endpoint homeport calls sits inside `src/proposals`, which is replaced
   wholesale, so nothing outside it needs reworking.

## 7.1 On deployment day: the production-data actions

Migrating the schema is not the whole deployment. These act on production's
own data and are easy to lose track of, because most were found while
debugging the sanitised copy and fixed there first.

**`scripts/repair_managed_project_local_portal.py` must be run against
production.** This is the one most easily missed. `OpenPortalBoard` minted
`ManagedProject.local_identifier` with the portal at the head of the board's
destination -- the remote portal that raised the award -- so awards arriving
through the AIRR gateway were stored as `u6dj.airr` where they should be
`u6dj.brics`. The board no longer does this, but that only fixes awards minted
from now on. The rows already in production are wrong, and nothing finds them:
`filters._identifiers_for_project_uuid` builds the identifier from
`get_portal()`, and `tasks.refresh_remote_award` discards an identifier whose
portal is not this one. Around 400 rows needed rewriting on the sanitised copy,
which is the same number production carries. Dry run first; it refuses a
rewrite that would collide with another `ManagedProject`.

**`waldur-openportal-sync-user-slugs` clears slugs on its first run, and it
is scheduled.** 02:20 daily, no-op unless `user.show_openportal_identifier`
is on. With the feature on it makes every `User.slug` equal the user's
OpenPortal username (`UserInfo.shortname`) and sets it to NULL for everyone
who has not chosen one -- including the username-derived slugs the old fork
generated, which is the point: homeport shows the slug *as* the OpenPortal
username, so a plausible-looking wrong value is worse than none. Turning the
feature on and letting beat run is the deployment action. Count what it will
change first:

```bash
DJANGO_SETTINGS_MODULE=waldur_core.server.my_test_settings uv run waldur shell -c "
from waldur_core.core.models import User
from waldur_openportal.models import UserInfo
shortnames = dict(UserInfo.objects.exclude(shortname=None).exclude(shortname='').values_list('user_id', 'shortname'))
rows = list(User.objects.values_list('id', 'slug'))
print('users', len(rows))
print('slug will be set or corrected', sum(1 for i, s in rows if shortnames.get(i) and s != shortnames[i]))
print('slug will be cleared', sum(1 for i, s in rows if not shortnames.get(i) and s))
print('unchanged', sum(1 for i, s in rows if s == shortnames.get(i)))
"
```

It only ever writes `User.slug`. Projects are deliberately untouched: for them
`set_default_project_shortname()` derives `ProjectInfo.shortname` *from*
`Project.slug` and raises without one, so the dependency runs the other way
and clearing a project slug would break the shortname it feeds.

**`marketplace/0270` -- measured, negligible.** It scrubs plaintext
`secret_options` from Offering versions in the reversion history, and the
sanitiser empties `reversion_version`, so every rehearsal ran it against an
empty table and the 5m58s figure in §6.6 excluded it. Measured on production:

| | |
|---|---|
| `reversion_version` rows | 110 (232 kB) |
| Offering versions | 12 |
| rows `0270` rewrites | 12 |

One batch, one `bulk_update`, effectively instant. The 5m58s figure stands.
Note the other side of that 12: production's reversion history currently holds
twelve Offering versions with **cleartext** `secret_options`, which is what
the migration exists to remove.

Measure it on PRODUCTION, not on a sanitised copy -- the sanitiser wipes
`reversion_version` and `reversion_revision`, so a copy answers 0 by
construction, and any rows it does show were generated locally since the
restore.

**The OpenPortal service upgrade -- done.** Production already runs the latest
OpenPortal, and it serves older clients, so moving the library pin to
`>=0.93.0` brings Waldur up to what is deployed rather than requiring a
coordinated change. This was sequencing step 1 and the main scheduling risk;
it is closed.

**How marketplace/0281 will classify this database.** `0281` re-runs the data
migrations a replacement squash skipped, and infers which databases need that
from `django_migrations` -- rows this deployment edits by hand. Run
`scripts/check_0281_classification.py` against a restore of production *before*
the window: it reports, per squash, which of the four conditions
`applied_as_replacement()` tests actually hold, and therefore whether the
backfills re-run against live data.

The reconciliation should not perturb it: `resync_reconcile_db.sql` only ever
DELETEs from `django_migrations`, never INSERTs, and the rows it removes
(`waldur_openportal`, `proposal`, `core.0011_user_unix_username`, `structure`,
`notifications`) are in none of the blocks `0281` inspects -- deleting an
unrelated row does not move the ids of the rows in a block. A database that
applied the originals one by one over months fails the contiguous-ids and
one-second tests and is left alone, which is the right answer because its
backfills did run. The script proves that rather than assuming it.

**The test suite.** The OpenPortal app is covered -- 268 tests pass against the
merge, the local-portal fix and the `RemoteOpenPortalClient` removal. The rest
of the suite has not been run against this branch end to end, and should be
before the window.

**The three backfills `0281` cannot recover -- checked, nothing at risk.**
`0281` WILL re-run on this deployment: `check_0281_classification.py` reports
all four conditions true for `marketplace.0226_squashed_0263`,
`marketplace.0264_squashed_0279` and `core.0033_squashed_0045`. That is
correct, not a misclassification -- those are upstream migrations this fork
never carried, so Django applies each squash as a replacement and the
backfills genuinely never ran. Condition 4 separates it from a fresh install
because the oldest `django_migrations` row is production's own (2024-05-23)
while the blocks are written by the deployment's `migrate`.

Three of its steps can only report, because the same squash dropped their
inputs. Checked on production before migrating, while the columns still
exist:

| Step | Source | Rows at risk |
|---|---|---|
| `0245_plancomponent_discount_formula` | `plancomponent.discount_threshold` / `.discount_rate` | **0** |
| `0271_missing_usage_policy` | `componentusage.recurring` | **0** |
| `0259_access_subnet_offering_scopes` | `marketplace_resourceaccesssubnet` | n/a -- the table never existed here |

The third needs no query: `0226_squashed_0263` both creates and deletes
`ResourceAccessSubnet` (added by `0251`, collapsed by `0259`), and production
never applied `0251`. The other two pre-date the squashed range -- the
squashes carry only `RemoveField` for them, no `AddField` -- so production does
have the columns, and both are empty. Nothing to capture; `0281` re-running is
pure upside.

**Not resync-related, but open.** One project shows an invoice month charged
with no credit compensation recorded (2026-06, mid-life for a Feb-Nov project),
while every other month nets to zero correctly. `scripts/debug_credit_consumption.py`
reports this per project. Worth understanding before it becomes a pattern.

## 8. Testing

Upstream requires Python 3.13 (`requires-python = ">=3.13,<3.14"`, from
`bbc7909be`, which also moved to Debian Bookworm), so the toolchain moves with
the resync.

Upstream ships `waldur_core.server.test_settings`, which points at a `db`
host. `waldur_core/server/my_test_settings.py` overrides that to a local
PostgreSQL instance, keeping the command in `CLAUDE.md` working:

```bash
DJANGO_SETTINGS_MODULE=waldur_core.server.my_test_settings uv run pytest --no-migrations
uv run pre-commit run --all-files
```

**`--no-migrations` is not optional.** CI runs the suite through
`tests/waldur-test`, whose base command carries `--no-migrations -m 'not slow'`:
the schema is built from the models rather than by replaying the migration
graph. Several tests are written against that (they say so in comments), and
two groups fail outright without it:

- `GenerateSlugTest` (10 tests) uses `TestSlugModel`, a test-only model with
  `app_label = "core"` and no migration, so with migrations enabled its table
  is never created (`relation "core_testslugmodel" does not exist`).
- `test_no_missing_migrations` calls `makemigrations --check` in-process. That
  same test-only model is registered by the time it runs, so the autodetector
  reports a model change with no migration -- while the identical command on
  the command line, where the test module is never imported, says
  "No changes detected". `--no-migrations` empties `MIGRATION_MODULES`, which
  puts every app in the autodetector's *unmigrated* set and skips the check.

A full run in this resync (19,232 passed) produced 21 failures, 20 of which
were this flag being missing. The 21st was real: `ManagedProjectAttachment`,
added by the `feature_snags` merge, had `ordering = ["-attached_at"]` with no
unique tie-breaker, which `PaginationOrderingTest::test_ordering_is_a_total_order`
rejects. Fixed to `["-attached_at", "-id"]` in
`waldur_openportal/0041_alter_managedprojectattachment_options`.

One more test behaves differently under the two modes:
`test_no_reuse_of_deleted_migration_names` walks git history for deleted
migration files and compares them against the live graph. Under
`--no-migrations` the graph is empty so it passes vacuously; with migrations it
flags `openstack.0036_merge_volume_type` (moved between directories inside the
same Django app) and `logging.0028_split_openstack_resource_event_groups`
(deleted and restored by this resync's rewind commits). Both are the same
migration under the same identity, not a reused name, and are now listed in the
test's `known_reused` set with that reasoning.

Note that `uv sync` needs LDAP headers (`libldap2-dev`, `libsasl2-dev`) to
build `python-ldap`.

### Generate the OpenAPI schema — treat this as a required gate

```bash
DJANGO_SETTINGS_MODULE=waldur_core.server.doc_settings \
  uv run waldur spectacular --api-version "$VERSION" \
  --file waldur-openapi-schema.yaml --fail-on-warn
```

This is what CI runs (`.gitlab-ci.yml`, the `spectacular` job, which also does
a second pass with `SKIP_MAKE_FIELDS_OPTIONAL=true` for the TypeScript
schema). It takes ~10 minutes and it is the **only** check that exercises the
whole API surface, which is also the contract waldur-homeport consumes through
the generated `waldur-js-client`.

It earned its place here. After the merge, the migration graph built, Django
system checks passed, `makemigrations --check` reported nothing pending, ruff
was clean, the tree byte-compiled and the test subset passed — and schema
generation still failed with four errors. The cause was residue: where a file
changed on both sides without a textual conflict, git auto-merged it and kept
the local lines, so `proposal/filters.py` carried a stray `project_uuid`
filter with no `view_name` and a fields entry for the dropped `submitted_at`.
None of the other checks can see a filter on a column that no longer exists.

Two habits follow from that:

- After adopting a directory wholesale, verify it: diff every file in it
  against `upstream/develop` and reset anything that differs. A clean merge is
  not evidence that a file matches upstream.
- Regenerate the schema before asking anyone to build a client from the
  branch.

Coverage to add for the carried-forward code, which currently has little:

- `structure/filters.py` — the project date filters, especially
  `active_during` boundaries and `in_grace`, whose database-resolved grace
  period should be checked against `Project.get_grace_period_days()` for the
  project-level, customer-fallback and zero cases.
- `invoices/views.py` — that a project member can list their own project
  credits and cannot see another project's.
- `permissions/views.py` and `users/views.py` — domain enforcement both on and
  off, given upstream has no coverage for these paths.
- `billing/serializers.py` — that the composed eager-load runs the original
  method exactly once.

`validate_end_date` is already covered: the local test was rewritten as
`test_validate_end_date_on_creation_has_no_grace_period`,
`test_validate_end_date_uses_project_grace_period` and
`test_validate_end_date_falls_back_to_customer_grace_period`. Upstream's own
`GracePeriodTest` covers the model-level grace behaviour.

## 8.1 Rehearsing against production-scale data

`scripts/resync_rehearse_migration.sh` runs the whole deployment sequence
against a copy of the sanitised production database:

```bash
scripts/resync_rehearse_migration.sh --datadir <the sanitise cluster>
```

Pre-flight, reconcile, `migrate`, `makemigrations --check`. It works on
`waldur_rehearsal`, created from `waldur_sanitise` with `CREATE DATABASE ...
TEMPLATE` -- a filesystem copy, so it costs disk rather than the hours a
re-restore would, and the sanitised database is left untouched. The rehearsal
is therefore repeatable: every fix gets a clean starting point in seconds.

Two things it gives that a rehearsal against dev data cannot:

- **The pre-flight's verdict on real data.** Whether any of the 1,651 projects
  would lose a `short_name` that is not recoverable from a slug or a
  `ProjectInfo` row. On the dev database 16 of 31 projects had `short_name` and
  `slug` differing, so this is not hypothetical, and the drop is irreversible.
- **Per-migration timings**, which is what a deployment window is built from.
  Django does not report them, so the script timestamps each `Applying ...` line
  and reports the slowest by subtraction.

A copy needs as much space again as the database, and the sanitising run has
usually just filled a good part of the disk -- so the script checks free space
first and refuses with the way out rather than running out half way through.
`--in-place` skips the copy and rehearses on the sanitised database itself.
That is destructive to it, which is acceptable because the sanitised *dump*
reproduces it in minutes against the hours the sanitising took: have that dump,
ideally off the machine, first.

A full disk is worth ruling out before anything else here. PostgreSQL's errors
under it point somewhere else entirely -- a `CREATE DATABASE ... TEMPLATE` on a
full filesystem reported `buffer is pinned in InvalidateBuffer`, which reads
like a concurrency problem and is not one.

It runs with `waldur_core.server.rehearsal_settings`, which is `base_settings`
plus a database connection from the environment. Deliberately **not**
`test_settings`: that adds `waldur_core.quotas.tests`,
`waldur_core.structure.tests` and `waldur_pid.tests` to `INSTALLED_APPS`, whose
migrations would then run and create tables production never has -- which
applies migrations the real deployment does not, and can mask a real one. If
the deployment's own settings module is importable, `DJANGO_SETTINGS_MODULE`
overrides it and is closer still.

Steps 1 and 2 need only `psql`. If no Python that can import waldur is found,
the script stops after them with the reconciled copy in place and prints what
to run -- worth doing on its own, since the pre-flight is the part that decides
whether the irreversible drops are safe.

## 9. Effort

| Task | Estimate |
| --- | --- |
| OpenPortal adoption + 2 tail commits | ~1 day |
| Carry-forward set (~40 hunks, mostly additive) | 1–2 days |
| Deletions (proposal, `unix_username`, `short_name`, attachments) | ~0.5 day |
| Reconciliation script + dump rehearsal | 1–2 days |
| Test suite and Python 3.13 | 1–3 days |
| **Total** | **~1–2 weeks** |

Excludes the OpenPortal service upgrade, which is scoped separately and is the
main unknown.

Net gain: 13 upstream test modules covering OpenPortal code written here that
previously had almost no coverage, and a base from which `waldur_openportal`
can be developed against upstream directly.

## 10. The upstream base is pinned to a release candidate

This branch tracks the tag **`8.1.3-rc.15`** (merged 2026-09-18), not
`develop`. Merging a moving branch head is not reproducible: the same command a
day later gives a different base, and the delta measured against it silently
changes shape. A tag fixes that.

**Moving to a newer tag: the revert trap.** The rewind onto `rc.8` was done by
reverting the 23 commits past the tag, not by rewriting history, so
`git merge-base HEAD <tag>` is still `b00cd9b18`. Merging a later tag then
behaves in two ways, and only one of them is visible:

* where the newer tag CHANGED a file the revert had touched, git conflicts and
  you see it;
* where it did NOT, git reads "they did nothing since the base, we removed it"
  and **silently keeps the removal**.

Merging `rc.15` raised 11 conflicts -- 10 of them files this fork has never
touched, resolved by taking the tag -- and behind them left **9 files absent
and 38 more file contents diverged**, with nothing to flag them. Two only
surfaced by accident: `waldur_vmware/vim_utils.py` as an `ImportError` when
`waldur` started, and openstack `Instance.metadata` as `makemigrations`
wanting to remove a field.

`scripts/resync_check_merge_completeness.sh` makes it systematic. Everything
this fork deliberately changes is the delta between the old tag and the
pre-merge commit; anything else differing from the new tag is a revert
leftover. Run it after resolving conflicts, before committing:

```bash
scripts/resync_check_merge_completeness.sh 8.1.3-rc.8 8.1.3-rc.15 <pre-merge-sha>
```

Then `makemigrations --check` as well -- a silently dropped model field shows
up there and not in the file comparison.

Regenerate the audit below against the tag, not the branch:

```bash
git fetch upstream --tags
git diff --name-status 8.1.3-rc.8 HEAD
git diff --shortstat 8.1.3-rc.8 HEAD
```

The resync was originally merged against `b00cd9b18` (2026-09-03), 23 commits
past the tag, and was rewound onto it. `rc.8` is an ancestor of that commit, so
the rewind removed upstream work and added none: 59 files, mostly the VMware
pyVmomi backend rewrite, Nova instance metadata, ToS consent gating and two
migrations (`logging.0028`, `openstack.0082`) that no longer exist here.

**One consequence, now resolved.** `rc.8` predates `8a474ddcb`, which bumped
djangorestframework to 3.18.0 and pyVmomi to 9.1.0.0, so the rewind left the
branch on **DRF 3.16.1** and **pyVmomi 8.0.3.0.1**. Merging `rc.15` should have
lifted both, and did not: the completeness check treats `pyproject.toml` and
`uv.lock` as files this fork changes on purpose (it does: the `openportal`
floor and the archive extension), so the rewind's hunks in them were kept
along with the fork's own. They were found and corrected while merging
`rc.21`, by checking every file the rewind touched against the new tag:

```bash
for f in $(git diff --name-only 8.1.3-rc.8 b00cd9b18); do
    git diff --quiet <new-tag> HEAD -- "$f" || echo "$f"
done
```

Only `pyproject.toml` and `uv.lock` were reported, and after the fix the lock
differs from `rc.21` in `openportal` alone. Run this after every merge, next to
the completeness check.

So until `rc.21` the branch was exposed to the two advisories the DRF bump
addressed, both published 2026-08-05 and both affecting 3.17.1 and earlier:

| Advisory | Severity | Applied here? |
| --- | --- | --- |
| [CVE-2026-73228](https://github.com/encode/django-rest-framework/security/advisories/GHSA-2m8g-3cmr-wg3w) — DRF's JSON and urlencoded parsers read the request stream directly, bypassing Django's `DATA_UPLOAD_MAX_MEMORY_SIZE` on `request.data` | Moderate, CVSS 5.3 | **Yes, until rc.21**, but bounded. Availability only, and the local nginx caps bodies at `client_max_body_size 10M`. Fixed by 3.18.0. |
| [CVE-2026-73229](https://github.com/encode/django-rest-framework/security/advisories/GHSA-g47c-3xmw-q6m2) — `AdminRenderer` calls the view's GET handler without a permission check when rendering an invalid write | Moderate, CVSS 4.3 | **No.** It requires `AdminRenderer`, which appears nowhere in the tree. |

**Django, by contrast, is improved substantially by the resync.** The fork ran
**4.2.24** (published 2025-09-03) on a branch whose extended support ended
**2026-04-07**, with 4.2.30 as its final release — so it had missed the 4.2
patches issued after 4.2.24 and, from April 2026 onwards, was receiving nothing
at all. Django's own advisories now carry the line that unsupported series
"were not evaluated and may also be affected", which is the real problem with
sitting on 4.2: the exposure is not a list you can enumerate.

This branch runs **6.0.8** (2026-08-04), which is the newest 6.0.x on PyPI and
postdates every published Django advisory — the most recent, CVE-2026-53877,
is patched in 6.0.7. Django is identical between `rc.8` and `develop`, so the
tag choice does not affect this.

`openportal` is pinned at **>=0.93.0** and locked to 0.93.0, the version
released and tested on 2026-09-04. Because the pin is a floor rather than an
equality, re-locking will drift to whatever is newest; move it deliberately
with `uv lock --upgrade-package openportal`, and re-run the API surface check
afterwards — every `openportal.*` attribute the OpenPortal modules reference
must still resolve:

```bash
grep -rhoP "(?<![\w.])openportal\.\K[A-Za-z_][A-Za-z0-9_]*" \
    src/waldur_openportal/ src/waldur_mastermind/marketplace_openportal*/ | sort -u
```

That check is what caught `Status.PENDING` no longer existing in 0.92, which
upstream still calls in `sync_board`. Two names it reports are false
positives: a notification key in a test, and a mention in a comment.

Moving to a newer tag is cheap: the delta is 37 files, and the same rewind is
`git read-tree -u --reset <tag>` followed by re-checking out those files.

## 11. Current delta versus upstream

An audit of where the branch actually sits, rather than what was intended.
Regenerate it with:

```bash
git fetch upstream --tags
git diff --name-status 8.1.3-rc.8 HEAD
git diff --shortstat 8.1.3-rc.8 HEAD
```

At the time of writing: **37 files, +2,926 / -37**, and — importantly —
**nothing upstream has that this branch deletes**. Every difference is either
an addition or a local modification, so there is no risk of having silently
dropped upstream code.

### Files only in this branch (13)

| File | Purpose |
| --- | --- |
| `docs/guides/upstream-resync-plan.md` | This document |
| `docs/guides/homeport-resync-plan.md` | The frontend companion, temporary |
| `scripts/resync_reconcile_db.sql` | One-time database reconciliation |
| `scripts/resync_preflight_check.sql` | Read-only pre-flight for the above |
| `scripts/resync_migrate.sh` | Applies the migration in the one order that works |
| `scripts/resync_rehearse_migration.sh` | Rehearses the whole sequence against a copy of production |
| `src/waldur_core/server/rehearsal_settings.py` | Settings for that rehearsal |
| `scripts/sanitise_production_dump.sh` | Turning a production dump into local test data |
| `scripts/sanitise_production_dump.sql` | The sanitisation itself |
| `scripts/sanitise_verify.sql` | Proving the sanitised copy carries nothing |
| `docs/guides/production-data-sanitisation.md` | How to use the three above |
| `scripts/docker-test-entrypoint.sh` | Stale-image guard for the test container |
| `docker-compose.test.yml` | Running the suite in Docker |
| `src/waldur_core/server/my_test_settings.py` | Test database from the environment |
| `src/waldur_core/structure/tests/test_project_date_filters.py` | Coverage for the project date filters |
| `src/waldur_mastermind/invoices/tests/test_project_credit_list_scoping.py` | Coverage for the ProjectCredit list scoping |
| `src/waldur_openportal/tests/test_project_accounting_summary.py` | Coverage for the accounting summary additions |
| `docker/rootfs/etc/nginx/*` (3 files) | Local nginx configuration |

The first six and `my_test_settings.py` are resync scaffolding: the two plans
and the homeport companion are deletable once the work is done, the rest are
worth keeping.

### Files modified (25)

Functional carry-forwards:

| File | Change |
| --- | --- |
| `structure/filters.py` | Project date filters, `in_grace` resolving grace per row |
| `structure/serializers.py` | Grace-aware `validate_end_date`, `disable_long_tokens` |
| `structure/tests/test_project.py` | End-date tests rewritten for per-project grace |
| `billing/serializers.py`, `invoices/serializers.py` | Composed eager-load fix |
| `invoices/views.py` | `ProjectCredit` list scoped by role |
| `core/features.py`, `core/tests/test_features.py` | 8 feature flags and their coverage |
| `core/utils.py` | Email blank-line collapsing, unknown-key warning, link hardening |
| `permissions/views.py`, `users/views.py` | `enforce_allowed_domains` enforcement |
| `permissions/serializers.py` | `user_slug`, pairing with `show_slug_as_id` |
| `logging/tasks.py`, `server/celery_settings.py` | `purge_old_events` and its schedule |
| `users/templates/invitation_created_message.*` | Invitation email improvements |
| `openportal/{views,serializers,filters}.py` | The `offering_name` filter and `include_offering_names` |
| `openportal/tasks.py` | `Status.pending()` fix for openportal 0.92 |

Configuration and packaging:

| File | Change |
| --- | --- |
| `pyproject.toml`, `uv.lock` | `openportal>=0.92.0` |
| `docker/rootfs/etc/waldur/notifications.json` | Local notification configuration |
| `docs/guides/build-commands.md` | Running the suite in Docker |

### Auditing for residue

Most defects found after the merge were residue: a file changed on both sides
without a textual conflict, auto-merged, keeping the local version. A clean
merge is not evidence that a file matches upstream.

The check that finds it is to diff **every** file present in both trees, not
just the directories adopted wholesale, and to account for each difference:

```bash
git diff --name-only upstream/develop HEAD | while read f; do
    [ -f "$f" ] || continue
    git cat-file -e "upstream/develop:$f" 2>/dev/null && echo "$f"
done
```

Anything on that list without a reason in the tables above is residue. That
sweep found the project-ending notification templates (which failed upstream's
own test), Call-scope filtering in `logging/filters.py`, a proposal-creator
guard in `permissions/serializers.py`, a `PROPOSAL.DELETE_PERMISSION` grant in
`permissions.yaml`, and two stray blank lines.

## 12. Known issue left unfixed: `is_in_grace_period` is a day off at both ends

Recorded in October 2026 and **deliberately not fixed**, to avoid changing
production behaviour. It is upstream code (`waldur_core`), so the same issue
exists in every Waldur deployment.

### The rule everything else follows

End dates are exclusive. `Project.is_expired` is
`effective_end_date <= today`, where `effective_end_date` is the end date
plus the grace period. So:

- on the **end date** itself, access to the project has already ended, and
  the grace period has begun (its first day);
- on the **effective end date** itself, access to the data has already been
  lost, and the data is scheduled for deletion.

HomePort (`lastAccessDate` in `src/core/dateUtils.ts`) and the OpenPortal
project emails (`waldur_openportal/project_updates.py`) both follow this rule.

### What `is_in_grace_period` says instead

`Project.is_in_grace_period` (`src/waldur_core/structure/models.py`) is
`end_date < today <= effective_end_date`, so it is wrong on both boundary
days:

| Day | Actually | `is_in_grace_period` | `is_expired` |
| --- | --- | --- | --- |
| End date | first day of the grace period | **false** | false |
| Effective end date | access to data lost | **true** | true |

On the end date the project looks fully active. On the effective end date it
looks both expired and in its grace period.

### Where that matters

| Caller | Effect on the end date | Effect on the effective end date |
| --- | --- | --- |
| `waldur_openportal/tasks.py` `sync_allocation_limits` (`is_in_grace_period` branch) | Limits are **not** zeroed, so the project can keep computing for the day | None (limits are zero) |
| `marketplace/tasks.py` `terminate_resources_if_project_end_date_has_been_reached` (pausing in the grace period, daily at 01:40) | Resources are **not** paused until the next day's run | None |
| `waldur_openportal/tasks.py` `sync_remote_for_destination` (`is_expired and not is_in_grace_period`) | None | Remote allocations are deleted a day late (lenient) |
| `waldur_openportal/board.py` award updates, `tasks.py` `create_default_resources` | Allocation changes are treated as for an active project | Updates and resource creation still accepted |
| API (`is_in_grace_period`, `project_is_in_grace_period`), policy tasks, chat tools | Reported as not in grace | Reported as in grace |

So in practice a project gets up to one extra day of compute on its end
date, contrary to what HomePort and the emails tell its members. Removal of
data a day late errs on the lenient side.

### What is already protected from it

- **HomePort** no longer trusts `is_in_grace_period` for the project profile
  line or the grace period banner; both are computed from `end_date` and
  `effective_end_date`.
- **The OpenPortal project emails** never use it. `GracePeriodEmailsTest` and
  `test_nothing_is_sent_once_access_to_the_data_is_lost` in
  `waldur_openportal/tests/test_project_updates.py` pin both boundary days.

### The fix, if it is wanted later

One line, upstreamable: make `is_in_grace_period` return
`end_date <= today < effective_end_date`. Every caller above then becomes
correct, and the API agrees with HomePort.

It changes production behaviour: on the end date, allocation limits are
zeroed and resources paused, one day earlier than now. Before making it,
check upstream's tests for assertions on the current boundaries, add tests
for both boundary days, and tell users, since some will have been relying on
the extra day.
