# Awards site: upgrade plan

The awards site is a separate Waldur deployment from the OpenPortal portal. It
runs only the proposal app, and reaches the other sites through OpenPortal
remote offerings. It was deployed from the fork's own proposal code, which the
upstream resync deleted wholesale in favour of upstream's far more advanced
version (`upstream-resync-plan.md` §3.3).

So this site cannot take the portal's upgrade path. The portal held no
proposals; this one holds two and a half thousand.

The plan here is to **archive rather than migrate**. Calls can all be closed
before the upgrade and new ones created afterwards, so no proposal has to
survive as a *working* proposal — only as a readable record.

## 1. What is actually there

Measured September 2026:

| Table | Rows |
|---|---|
| `proposal_proposaldocumentation` | 3403 |
| `proposal_requestedresource` | 2271 |
| `proposal_proposal` | 2258 |
| `proposal_review` | 1780 |
| `proposal_proposalresourceadjustment` | 223 |
| `proposal_call_documents` | 22 |
| `proposal_calldocument` | 22 |
| `proposal_proposalprojectrolemapping` | 18 |
| `proposal_requestedoffering` | 16 |
| `proposal_round` | 11 |
| `proposal_callresourcetemplate` | 8 |
| `proposal_call` | 7 |
| `proposal_callmanagingorganisation` | 3 |
| `proposal_proposalidgenerator` | 2 |
| `proposal_resourceallocator` | 0 |
| `proposal_reviewcomment` | 0 |

About 7,700 rows in total, across 16 tables. That is small enough that the
archive can be real models with real columns and a copy script, rather than
opaque JSON blobs: the copy will run in seconds and can be re-run as often as
it takes to get right.

Two shapes are worth noticing. **Seven calls and eleven rounds** carry all of
it, so the call- and round-level archive can afford to be generous. And
`proposal_reviewcomment` is empty while `proposal_review` holds 1,780 rows, so
the review conversation feature was never used — the reviews themselves are
where the sensitive text lives.

### 1.1 The migration history

All 56 `proposal` rows are applied, up to and including
`0054_round_fixed_review_end_date`. Note that this differs from the portal,
which stopped at seven of the eight local migrations and therefore never
gained the `fixed_review_end_date` column.

The history is also not linear. Both `0001_initial` and
`0001_initial_squashed_0033_call_organizer` are recorded, and there are two
`0027` nodes (`0027_call_manager_role` and `0027_proposal_member_role`) from a
branch point in the fork's history.

Under the portal's in-place reconciliation that would all need unpicking.
Under the approach below it is simply deleted, which is one of the reasons to
prefer it.

### 1.2 What must not be run here

`scripts/resync_reconcile_db.sql` §2 is written for a portal with no
proposals. It keeps the proposal tables and strips the fork's columns from
them:

```sql
ALTER TABLE proposal_proposal DROP COLUMN IF EXISTS notes;
ALTER TABLE proposal_proposal DROP COLUMN IF EXISTS submitted_at;
ALTER TABLE proposal_round DROP COLUMN IF EXISTS fixed_review_end_date;
```

Run unmodified on the awards site, that destroys the columns this plan exists
to preserve, before anything has been archived. **The awards site needs its own
reconciliation script.** It is a different script, not a flag on the existing
one, so that neither can be pointed at the wrong database by accident.

## 2. The approach

Three components, in this order of confidence:

1. **Rename the old tables out of the way** during the upgrade window. This is
   the mechanical trick that makes everything else unhurried.
2. **An archive app** — real models, no foreign keys to live data — plus a copy
   script that fills it from the renamed tables.
3. **A read-only API and a HomePort viewer**, so archived calls, rounds and
   proposals stay browsable.

### 2.1 Why renaming works

**Nothing outside the proposal app points into it.** Checked on both the fork's
code and upstream's: no other app's models declare a foreign key to
`proposal.Call`, `Round`, `Proposal` or `Review`. Every dependency runs
outward — proposal → `structure.Customer`/`Project`, `marketplace.Offering`/
`Plan`, `core.User`.

So `ALTER TABLE proposal_call RENAME TO ...` is a metadata-only operation that
breaks no constraint and rewrites no data. It is instant on tables this size
(and would be instant on tables a thousand times this size), and it is
reversible by renaming back.

That decouples the upgrade from the archive. The upgrade window needs only the
rename; the copy happens afterwards, at leisure, against a database that is
already serving the new code. Nothing is dropped until the copy has been
verified — and dropping is a separate decision that can wait months.

## 3. The upgrade sequence

1. **Close all open calls** and let any in-flight work settle.
2. **Take a dump.** This is the archive's backstop: every later step is
   recoverable from it.
3. **Reconcile the database**: `scripts/resync_preflight_check.sql` first,
   then `scripts/resync_reconcile_db.sql`. The same two scripts the portal
   uses — see §3.1 for what they do differently here.
4. **Migrate with `scripts/resync_migrate.sh`, application down**, not by
   bringing the new code up and letting it migrate at startup. Five upstream
   `waldur_openportal` migrations have to be faked at a point where Django's
   dependency graph is satisfied, which only Django can do — see §3.4. With no
   proposal tables and no proposal history, upstream's `0001_squashed_0074`
   then applies as a single unit against a clean slate, which is the easiest
   case for the squash rather than the hardest.

   The archive is not a separate pass afterwards: it is *steps 4–6 of that
   script*, and it has to be, because the roles it captures are deleted before
   the replay can run at all (§3.5). The script creates the archive tables,
   runs the copy, deletes the fork's proposal roles, and only then migrates
   everything else. All three steps no-op on the portal, so it stays one
   script for both sites.
5. **Leave the renamed tables in place** until the archive has been exercised
   in anger. Dropping them is a later, separate change.

Steps 3 and 4 are the only ones inside the maintenance window.

### 3.1 The reconciliation script

**One script for both sites.** `scripts/resync_reconcile_db.sql` is the
portal's script and the awards site's; §2 picks its path from the data rather
than from a flag, so there is nothing to keep in step and nothing to point at
the wrong database:

| `proposal_proposal` | Path |
|---|---|
| absent, or `old_proposal_*` already present | nothing to do |
| present, 0 rows (the portal) | undo the local `0047`–`0054` series in place; upstream's replays over the same tables |
| present, with rows (the awards site) | rename the whole app aside to `old_proposal_*` and delete the entire proposal history |

A proposal table carrying rows is never stripped of its columns, which is the
property that matters: the portal's reset would have destroyed exactly the data
this plan exists to preserve. All four paths are tested, including re-running
each.

The awards path has three details worth knowing.

**It renames the indexes, constraints and sequences too.** Easy to miss and
expensive to find: index and sequence names are unique per schema, so
`proposal_call_pkey` and `proposal_call_id_seq` left attached to the renamed
table collide with the `CREATE TABLE` that upstream's migrations run next — and
the failure reads as "relation already exists" with nothing to connect it to the
rename. Verified by recreating the original tables afterwards.

**It handles PostgreSQL's 63-byte identifier limit.** Several of Django's
generated constraint names are already at it, so `old_` + name would be
silently truncated, and two long names differing only at the end would truncate
onto each other. Past 59 characters the script keeps a readable prefix and adds
a hash: `old_proposal_proposalprojectrolemapping_call_id_pr_412a0ecc`.

**It deletes the whole proposal history, not just the fork's `0047`–`0054`.**
The awards site's history is not linear (§1.1), and with the tables renamed
there is nothing left for any of it to describe.

### 3.2 The rest of the reconciliation applies here too

The awards site was deployed from the same fork, so everything else in
`resync_reconcile_db.sql` applies unchanged: the `waldur_openportal`
`0034`–`0043` bookkeeping (§1), the vestigial `core.User.unix_username` and
`structure.Project.short_name` columns (§3), and the broadcast attachment table
(§4). The pre-flight run of September 2026 confirms it — `10 of 10` local
openportal rows and `7 of 7` core/structure rows to delete.

**The `short_name` gate fails here where it passed on the portal.** The
pre-flight reported `projects_losing_short_name: FAIL 21`: of 1,079 projects
with a `short_name`, 1,058 have it preserved as a `ProjectInfo.shortname`,
leaving 21 whose value would be destroyed by the §3 drop. That must be resolved
before reconciling — the column is not recoverable afterwards.
`users_losing_unix_username` passes trivially: this site never used the field at
all (`users_with_unix_username: 0`).

The gate allows two homes for the value, the `ProjectInfo.shortname` or the
slug. **On this site only the first one counts**, which is why
`projects_preserved_via_slug_only` reads 0 and always will — see §3.3.

### 3.3 Project.slug here is the award identifier

On the awards site `Project.slug` holds the award ID — `0251-4064-4677-1` —
and has nothing to do with OpenPortal shortnames. That is what the
`deployment.application_portal_only` feature is for ("Configure Waldur to
function as an application and awards portal only"), and
`ProjectInfo.set_shortname()` reads it before deciding whether to copy a
shortname into the slug:

```python
if not application_portal_only:
    self.project.slug = shortname
    self.project.save(update_fields=["slug"])
```

**Confirm that feature is on before anything writes a project shortname here.**
It defaults to False when the row is missing, and with it off, setting a
shortname silently overwrites the award identifier that every link and every
award refers to.

`utils.sync_openportal_shortnames_to_slugs()` had no such guard — it wrote
`project.slug = shortname` for every project at once. It has never been called
(nothing in the tree calls it), but it is the more dangerous of the two
precisely because it acts on everything, and an upgrade like this one is when
somebody goes looking for a function with that name. It now refuses on an
application portal, and says so.

The same reasoning does not apply to `User.slug`: this site has no
`unix_username` values at all, and `sync_user_slugs()` is gated on
`user.show_openportal_identifier`, which an awards portal would leave off.

The pre-flight itself now survives being run after the rename: its proposal
section counts through dynamic SQL and reads the `old_proposal_*` tables when
they are there, reporting `PASS | N archived`. Before that it named the tables
directly, and a missing relation failed at parse time — which aborted the
read-only transaction and took every later check with it, including the gate
above.

### 3.4 The migration itself

`scripts/resync_migrate.sh` replaces a plain `migrate`, and all six of its
steps apply to this site unchanged:

| | |
|---|---|
| 1 | `structure` forward, which brings in openportal `0036`'s dependency |
| 2 | openportal `0034` for real — it adds `can_be_managed`, which this fork never had |
| 3 | openportal `0035`–`0039` faked, their objects already existing |
| 4 | everything else |
| 5 | the 30-day grace-period backfill |
| 6 | `makemigrations --check`, which catches a fake whose objects did not match |

Run it with the **application down and the database only**. Waldur migrates at
startup, so an API container that is up has already migrated — or failed to —
and the workers would be reading a schema changing underneath them:

```bash
docker compose up -d waldur-db
scripts/resync_migrate.sh --manage \
    'docker compose run --rm --no-deps -T --entrypoint waldur waldur-mastermind-api'
docker compose up -d
```

One difference from the portal worth expecting: the script's step 4 describes
upstream's proposal series as running "against empty tables". Here the tables
are not empty but *absent*, and the history is gone with them, so the whole app
is created from scratch. Same outcome, shorter route.

### 3.5 Proposal roles block the replay, and their assignments are archive material

The first full run of `resync_migrate.sh` reached the proposal squash and died
inside `0040_migrate_default_project_role`:

```
Role.objects.get(name="PROPOSAL.MANAGER", content_type=proposal_ct)
MultipleObjectsReturned: get() returned more than one Role -- it returned 2!
```

**Roles are not proposal tables.** They live in `permissions_role`, which the
reconciliation does not touch, so this site's `PROPOSAL.MANAGER` and
`PROPOSAL.MEMBER` survive from its previous life. The replay then creates its
own inside the squash's transaction, `0040` finds two, and the whole squash
rolls back — which is why the database afterwards shows only one of each, and
why nothing is damaged. On the portal this cannot happen: no proposals, no
proposal roles, virgin ground. It is the same shape as the pre-flight aborting:
the replay assumes a clean slate, and the slate is clean only for the proposal
app.

The roles therefore have to go before the replay can succeed. What makes that a
decision rather than a fix is what hangs off them (September 2026):

| Role | System | Assignments |
|---|---|---|
| `PROPOSAL.MANAGER` | yes | 3576 |
| `PROPOSAL.MEMBER` | yes | 2334 |
| `PROPOSAL.COLEAD` | no | 1214 |
| `CALL.REVIEWER` | yes | 269 |
| `CALL.MANAGER` | yes | 30 |
| `CUSTOMER.CALL_ORGANIZER` | yes | 6 |
| `Call Reader` | no | 5 |

Deleting a role cascades its `UserRole` rows away, so that is 7,434 records of
**who managed, co-led, reviewed and belonged to each proposal and call** — and
they are exactly the kind of thing an archive is for. They are also already
half-detached: `UserRole` scopes through a generic foreign key, so those rows
now point at object ids that exist only in `old_proposal_*`.

They divide by scope like this:

| Scope | Role | Total | Active |
|---|---|---|---|
| proposal | `PROPOSAL.MANAGER` | 3576 | 3378 |
| proposal | `PROPOSAL.MEMBER` | 2334 | 2052 |
| proposal | `PROPOSAL.COLEAD` | 1214 | 1034 |
| call | `CALL.REVIEWER` | 269 | 260 |
| call | `CALL.MANAGER` | 30 | 27 |
| callmanagingorganisation | `CUSTOMER.CALL_ORGANIZER` | 6 | 6 |
| callmanagingorganisation | `Call Reader` | 5 | 5 |

**1,537 of the 7,124 proposal-scoped rows do not resolve at all** — their
`object_id` matches no row in `old_proposal_proposal`. Only 660 assignments are
inactive in total, so most of those orphans are *active* permission rows
pointing at proposals that were deleted at some point and took no permissions
with them. That is pre-existing cruft in the live system rather than anything
this upgrade does, but it decides a design question: `ArchivedMembership`
attaches the **5,587 resolvable** rows to their archived proposal and reports
the orphans as a count. Archiving a reference to a proposal that no longer
exists anywhere would be storing a number, not a record.

So the archive gains a model, and the sequence gains a step: **capture the
memberships before the roles are deleted.** `ArchivedMembership` — the archived
call or proposal, the user's uuid and username, the role name, whether it was
active, and when it was granted and revoked — denormalised like everything else
in §4.1, so it survives the roles it came from. Two of the seven roles are
custom rather than system (`PROPOSAL.COLEAD`, `Call Reader`), so the role name
has to be carried as text rather than assumed from an enum.

Only then are the proposal-scoped roles deleted, and only then does the replay
have a clean slate in the sense it assumes.

Both halves are management commands rather than more SQL, because both need the
live tables the ORM already knows — `structure_customer`, `core_user`,
`marketplace_offering` — alongside the renamed ones:

```bash
waldur archive_old_proposals          # copies everything, memberships included
waldur delete_old_proposal_roles      # refuses until the above has run
```

`delete_old_proposal_roles` detaches the roles' references in **SQL rather than
through the ORM**, which is not a style choice. `queryset.delete()` makes
Django's collector query every model with a foreign key to `Role`, and this
command runs on a database part-way through the resync: the proposal app's own
tables have been renamed to `old_proposal_*`, and apps whose migrations have not
been applied yet have no tables at all. The first production run died on

```
relation "waldur_sram_sramprojectrule" does not exist
```

having deleted nothing, and `proposal_proposalprojectrolemapping` would have
been next. So the model graph decides the policy — `CASCADE` or `SET_NULL`,
exactly what Django would have done — while PostgreSQL's catalog decides which
tables are really there.

The table existing is not enough either: a table can predate the migration that
added its role column, which is how the second attempt failed —
`column "customer_role_id" does not exist` on a `waldur_autoprovisioning_rule`
that was there but older. Both are checked, and a relation whose table or
column is absent is reported and skipped, which is always correct: a reference
cannot exist in a column that does not.

### 3.6 Renaming the tables aside did not detach them

`ALTER TABLE ... RENAME` preserves constraints. So after the reconciliation the
`old_proposal_*` tables still hold live foreign keys — into `permissions_role`,
`core_user`, `structure_customer`, `marketplace_offering`, and each other.

`old_proposal_proposalprojectrolemapping.proposal_role_id` is `NOT NULL` and
points at the fork's proposal roles for eighteen rows, so the role deletion
fails on a foreign-key violation until it is gone. But the wider problem
outlasts the upgrade: every one of those constraints is a trap set for some
future deletion. A customer removed years from now would either be blocked by
an archived proposal or cascade into what is supposed to be an immutable
record — which is precisely what §4.1 was written to prevent, undone by the
tables the archive was copied *from*.

So `archive_old_proposals` drops every foreign key on an `old_proposal_*` table
once the copy is done, and `delete_old_proposal_roles` does the same before it
deletes, in case it is run alone. Idempotent, and the rows are untouched.

One PostgreSQL detail: dropping a foreign key locks the *referenced* table too,
and PostgreSQL refuses to `ALTER` a table with pending trigger events. A
transaction that writes to `permissions_role` and then detaches a table
referencing it dies with `ObjectInUse`, so the detach issues
`SET CONSTRAINTS ALL IMMEDIATE` first to flush the queue.

`delete_old_proposal_roles` **will not run while the archive is empty**. It
counts what it is about to cascade away, counts what has been captured, and
stops rather than making an irreversible deletion on the strength of a copy
that may have copied nothing. `--force` exists for a site that genuinely never
had any assignments; `--dry-run` prints the roles and the assignment counts and
touches nothing.

`resync_migrate.sh` runs both, between the openportal fakes and the main
`migrate`. It skips them where there is nothing to archive — which is the
portal — and skips them again once the proposal app *is* migrated, because from
that point on the roles in `permissions_role` are upstream's, and deleting
those on a careless re-run would take the new site's own assignments with
them.

## 4. The archive app

A new app, `waldur_mastermind.proposal_archive`, holding what the old app held,
flattened:

| Archive model | Source | Notes |
|---|---|---|
| `ArchivedCall` | `Call`, `CallManagingOrganisation` | organisation denormalised onto the call |
| `ArchivedRound` | `Round` | |
| `ArchivedProposal` | `Proposal` | the fork's `notes`, `submitted_at`, `allocation_comment` all preserved |
| `ArchivedRequestedResource` | `RequestedResource`, `RequestedOffering`, `CallResourceTemplate` | offering and plan denormalised to uuid + name |
| `ArchivedReview` | `Review`, `ReviewComment` | staff-only, see §4.2 |
| `ArchivedCallDocument` | `CallDocument` | |
| `ArchivedProposalDocument` | `ProposalDocumentation` | |
| `ArchivedMembership` | `permissions.UserRole` scoped to a call or proposal | who held which role, and when — see §3.5 |

Documents ended up as two models rather than the one with a `kind` column this
section first proposed. A `FileField` has a single `upload_to`, and §5 needs the
two kinds on *different* prefixes so their access rules can differ; one model
would have meant a callable `upload_to`, which `access.upload_prefix()`
explicitly refuses to derive a prefix from.

`ProposalIDGenerator` (2 rows, a counter) is not archived: it is a counter for
proposals that will never be issued again. `ProposalResourceAdjustment` (223
rows) is, folded into `ArchivedProposal.payload["resource_adjustments"]`.

Every field holding copied text is a `TextField`, even where the source column
was a bounded `CharField`. This is not tidiness: the first real run of the copy
died on `value too long for type character varying(2000)` at proposal 12 of
2,258, because the fork's `DescribableMixin` capped descriptions at 2,000
characters and production proposals exceed it. An archive that inherits the
live schema's limits will refuse the very rows most worth keeping. The only
bounded fields left are `scope_kind`, which the archive invents rather than
copies, and the two `FileField`s, which cannot be text and are capped at 255 to
match `media_file.name`.

The app's migration has **`dependencies = []`**. That is not an accident of
having no foreign keys — it is the requirement that lets `migrate
proposal_archive` run on the awards site while the proposal app is absent from
the history and upstream's squash has not yet replayed. A dependency on
`structure` or `permissions` would have been harmless; one on `proposal` would
have made the archive unbuildable at the only moment it can be built.

### 4.1 No foreign keys to live data

Every reference out of the archive is denormalised to a UUID plus a display
value: `customer_uuid` + `customer_name`, `created_by_uuid` +
`created_by_username`, `project_uuid` + `project_name`, `offering_uuid` +
`offering_name`.

This matters more than it looks. A real FK would mean an archived proposal
`PROTECT`s the user who wrote it, or worse, gets `CASCADE`-deleted when someone
tidies up a customer years from now. Denormalised, the archive is inert: it
cannot block a deletion and cannot be destroyed by one.

Each archive row also carries a `payload` JSONB column holding the original row
verbatim, including any column not modelled explicitly. It costs almost
nothing at this scale and it is the difference between "we didn't archive that
field" and "it's in the payload".

**The original UUIDs are preserved**, which is what makes §6 possible.

### 4.2 Who can read what

The archive is read-only, but it is not public: proposals carry
`project_is_confidential`, and reviews carry reviewer identities and candid
private comments.

| Object | Visible to |
|---|---|
| Archived call, round | staff, support, the call's managing organisation |
| Archived proposal | the above, plus the proposal's creator |
| Archived document | as for its parent call or proposal |
| Archived review, review comment | staff, support, the call's managing organisation only |

Reviewer identity and review text are **never** exposed to applicants in the
archive, regardless of what the old call's
`reviewer_identity_visible_to_submitters` / `reviews_visible_to_submitters`
flags said. The archive is a record for administrators, not a continuation of
the review process, and the cost of being wrong is asymmetric.

This is the one place a read-only archive still needs real access control, and
it is why §4.1's denormalised `created_by_uuid` and the call's organisation
uuid have to be captured during the copy rather than inferred later.

### 4.3 The endpoints

| Route | Holds |
|---|---|
| `proposal-archive-calls` | calls; detail adds rounds, documents, proposal count |
| `proposal-archive-rounds` | rounds |
| `proposal-archive-proposals` | proposals; detail adds resources, documents, memberships |
| `proposal-archive-reviews` | reviews — the narrow audience of §4.2 |
| `proposal-archive-memberships` | who held which role |
| `proposal-archive-resolve` | an original uuid → what the archive now holds |

Access is by **queryset filter rather than `permission_factory`**: there are no
actions to authorise, only rows to hide, and the rules are per-row. Each
viewset narrows through the matching function in `permissions.py` — the same
functions `media_access.py` uses, so a document can never be downloadable by
someone who cannot see the record it hangs off.

Two decisions worth recording:

- **`notes` are not a field on the proposal.** The applicant can read their own
  proposal; `notes` were only ever visible to call managers and staff. They get
  a separate action behind the review-level check, so the wider proposal
  audience cannot pick them up by accident.
- **`resolve` answers 404 for "you may not see it"** as well as for "unknown".
  Distinguishing them would make it an existence oracle for confidential
  proposals, which is a poor trade for a marginally better error message.

`ArchivedMembership` gets a top-level endpoint rather than only a nested field,
because the question actually asked of it — "what did this person have access
to?" — is a query across proposals, not within one.

One schema requirement to know about: every UUID query parameter must declare
which endpoint its value refers to, via `core_filters.RelatedUUIDFilter`, or
`spectacular --validate` fails. Note what that declaration does *not* claim:
`created_by_uuid` really is a user uuid, so `user-detail` is the right kind,
but the archive still makes no promise the user exists. Naming the kind costs
nothing; resolving it is the caller's problem, by design.

## 5. Documents, and a collision to avoid

Uploaded files in Waldur live **in the database** — `media_file.content` is a
`BinaryField` — and are served by `/api/media/<uuid>/`, which is deny by
default. A `FileField` stores the path; `media_file.name` matches it.

That is good news: archiving documents moves no bytes. But there is a trap.

Upstream's proposal app already registers media access rules for exactly the
prefixes the old documents sit under:

```python
access.register_public(access.upload_prefix(CallDocument, "file"))
access.register(access.upload_prefix(ProposalDocumentation, "file"),
                user_can_access_proposal_documentation)
```

and `access.register()` **raises `ImproperlyConfigured` on a duplicate
prefix**. So the archive cannot declare `upload_to="call_documents"` or
`upload_to="proposal_project_supporting_documentation"` to match the existing
files — the prefix is taken. Worse, if it did nothing, the old files would be
resolved by *upstream's* rule, which queries upstream's now-empty tables and
returns False: every archived document would 403.

So the copy renames the media rows onto the archive's own prefixes:

```
call_documents/<file>                          -> archived_call_documents/<file>
proposal_project_supporting_documentation/<f>  -> archived_proposal_documentation/<f>
```

`media_file.name` is unique and indexed, the update touches ~3,425 rows, and
the bytes are untouched. The archive app then declares those prefixes as its
own and registers a rule matching §4.2. Without this step `CoverageTest` fails
and every document download 403s.

Note also that upstream registers call documents as **public**. Archived call
documents should not be: default them to the §4.2 rule and revisit only if
someone asks.

## 6. URLs

Proposal links are `/proposals/{proposal_uuid}` (the shape is confirmed by the
formbricks `FRONTEND_FLOW_COMPLETE_URL_TEMPLATE` default).

Because archive rows keep the original UUIDs, old links can keep working
without touching any stored data: the resolver looks for a live proposal, and
falls back to the archive when there is no match. Either HomePort's proposal
route handles the 404 by redirecting to the archive view, or the backend
exposes `GET /api/proposal-archive/resolve/<uuid>/` returning the kind and the
archive URL.

A database search-and-replace is the fallback, not the plan: it can only fix
links already stored in Waldur, and does nothing for the ones in people's
email, tickets and bookmarks.

## 7. Formbricks

The formbricks work on `isambard/application_forms` (~1,900 lines over 11
files, 723 of them tests) was never deployed, so there is no data to migrate —
only code to re-point at upstream's proposal app.

**It moves to its own app.** Its couplings to the proposal app are just two
model-level things:

- `Call.formbricks_flow_key` — a column on the old `Call`;
- `FormStepResponse.proposal` — a FK to the old `Proposal`.

In its own app the first becomes a `CallFormConfig` row (call uuid → flow key)
and the second keeps a FK to upstream's `Proposal`. `formbricks_client.py`,
`formbricks_flows.py` and `formbricks_mapper.py` (557 lines) port unchanged;
the work is in the ~380 lines of views, which have to be re-pointed at
upstream's proposal states.

The reason to do this rather than re-apply the patch to `proposal/` is the one
the resync just taught: fork code living inside an app that is adopted wholesale
from upstream has to be re-merged, by hand, every time upstream moves. Formbricks
in its own app never conflicts again. It also dissolves a collision that exists
today — the branch carries
`0054_call_formbricks_flow_key_formstepresponse`, the same number as the
deployed `0054_round_fixed_review_end_date`.

Its configuration lives in the `WALDUR_PROPOSAL` extension settings
(`FORMBRICKS_BASE_URL`, `FORMBRICKS_MANAGEMENT_API_URL`,
`FORMBRICKS_WEBHOOK_SECRET`, `FORMBRICKS_API_KEY`), all placeholders at
present. They move with the app.

### 7.1 The end-of-project survey is separate, and is in neither merge

There is a second piece of Formbricks work, unrelated to application forms: the
project dashboard renders an end-of-project feedback survey once a project
reaches its end date. It is worth being precise about where it lives, because
it is **not** in either repository's merged history.

It lives on the `feature_airrportal` branch of `isambard-sc/waldur-homeport`,
which is what the awards portal deploys. **That branch's entire delta over
`devel` is one file** — `src/project/ProjectDashboard.tsx`, +92/-1 — so the
survey is the only thing missing, and the check is complete: everything else
`feature_airrportal` carries came in from `devel` and `feature_snags`, both of
which the resync already has. (`devel` is an ancestor of it, and the two forks'
`devel` are the same commit, `e3872e52f`.)

Frontend only: there is no backend code for it anywhere, in any branch of this
repository.

What it does: shows an `<iframe>` of a hardcoded Formbricks survey
(`forms-airr.isambard.ac.uk`) when `project.end_date` has passed and the viewer
holds `CREATE_PROJECT_PERMISSION` on the project or its customer (the PI or an
organisation owner). The survey URL carries the project name and slug, the
user's name and email, and a call reference assembled from the proposal call's
`reference_code` and the round's start date.

**The tip of `feature_airrportal` is broken.** `proposalProposalsList` and
`proposalProtectedCallsRetrieve` are called at lines 151 and 161 but imported
nowhere: the last `feature_snags` merge (`ed573bcd9`, 19 August 2026) rewrote
the `waldur-js-client` import line and dropped them, keeping the call sites.
Every earlier commit on the branch has the import. What that costs depends on
the build: a type-checking build fails outright, while a plain esbuild
transform emits it and throws at runtime, where React Query swallows the error
and the survey still renders — with `call_reference` silently degraded to the
award's call id and no round start date. Worth checking against what is
actually deployed before assuming the live survey is reporting what it looks
like it reports.

So, when re-applying:

- **Take the pre-merge version of the logic** (`45e030eec` or earlier), not the
  tip, or re-add the two imports.
- **It is a re-write, not a cherry-pick.** `ProjectDashboard.tsx` moved a long
  way in the resync.
- **Re-check the proposal API dependency.** `proposalProposalsList`,
  `proposalProtectedCallsRetrieve` and `round.start_time` all come from the
  proposal app, which is exactly what this upgrade replaces. Upstream's
  equivalents will not be the same endpoints.
- **Move the survey URL out of the component.** It is hardcoded, so test and
  production cannot point at different surveys.
- **Mind the CSP if one is ever added.** A `Content-Security-Policy` meta tag
  was added for the iframe in `4db811926` and removed again in `a8957ce8f`
  ("remove unnecessary metadata") once the survey moved to its production host,
  so there is nothing to carry across today — but any CSP introduced later
  needs `frame-src https://forms-airr.isambard.ac.uk`.

It also wants its own gate rather than sharing the application-forms one:
`project.show_end_of_project_survey` in `ProjectSection` describes what it is
and where it renders, and keeps the two Formbricks features independently
switchable.

### 7.2 Three gates, not one

As written, formbricks has exactly one switch: `Call.formbricks_flow_key`, null
meaning "use the legacy Waldur-native form". It is **not** behind a feature
flag today, though it is often described as if it were.

Per-call is the right granularity for choosing a form, but it is the wrong
granularity for two other questions, so the port adds two more gates. The
codebase already has the pattern for an integration — see
`sram.integration` and `project.show_matrix_chat`, both of which say in their
own description that backend access is gated separately:

| Gate | Answers | Where |
|---|---|---|
| `proposal.formbricks_forms` feature | Does this portal offer Formbricks forms at all? | `core/features.py`, new `ProposalSection` |
| `FORMBRICKS_ENABLED` setting | May the backend talk to Formbricks and accept its webhooks? | the new app's extension settings |
| `formbricks_flow_key` | Which survey chain does *this call* use? | per call, as now |

The feature flag is presentational, as core features are: HomePort reads it
through `isFeatureVisible` to decide whether to offer a Formbricks form when
configuring a call, and whether to render the survey step in the applicant's
flow. Its one backend consequence is the same as everywhere else — none.

**The backend gate is the one that matters, and it is not the feature flag.**
The integration exposes an inbound webhook that accepts survey responses and
writes them against proposals. That is an ingress point, so it must be off by
default and gated server-side, on a setting an operator controls, rather than
on a feature entry that staff can flip from the UI. The precedent is exact:
`invoices.utils.affiliates_feature_enabled()` reads the Constance setting and
says in its docstring that the matching core feature "only controls homeport
element visibility and is not consulted here". Formbricks should read the same
way: views and tasks check the setting; nothing server-side reads the feature.

With all three in place the rollout is stepwise — deploy dormant, enable the
backend setting once the Formbricks instance and webhook secret are real, turn
the feature on to expose it in HomePort, and then opt calls in one at a time.
Any of the three turns it off again.

Adding the flag means regenerating HomePort's `src/FeaturesEnums.ts` and
`src/features/FeaturesDescription.ts` with `waldur print_features_enums` and
`waldur print_features_description`; the descriptions must match HomePort's
copy exactly or the next regeneration shows a spurious diff. Both generators
sort alphabetically, so declaration order in `features.py` does not matter.

Sequencing: formbricks lands **after** the upgrade. It has no bearing on the
archive, and mixing the two means debugging a survey integration and a
migration at the same time.

## 8. Sanitising this site

The rehearsal needs a sanitised copy, the same way the portal's did — see
`production-data-sanitisation.md` for the method and the lessons.

`scripts/sanitise_production_dump.sql` now carries a proposal stage, so there
is one sanitiser for both sites rather than two to keep in step. Every
statement in it is guarded by `sanitise.exec_if`, which skips a missing table
or column with a notice, so on a portal database the stage is a no-op:
verified by running both scripts against a fork-shaped fixture and an
upstream-shaped one, where the latter logs 15 skips and exits 0.

What it covers:

- **Free text written by people** — `proposal_proposal.project_summary`,
  `.description`, `.allocation_comment`, all eleven `proposal_review` comment
  columns, `proposal_reviewcomment.message` and
  `proposal_proposalresourceadjustment.comment`. These go in the stage-5 filler
  list, which replaces prose with same-length filler rather than trying to
  rewrite names out of it. This is the most sensitive text in any Waldur
  database: unpublished research plans, and candid assessments of them written
  by named reviewers.
- **`proposal_proposal.notes`** is a JSONB list of `{timestamp, author, text}`
  — the same shape as OpenPortal's remote-project notes — so it gets the same
  bespoke treatment: the timestamps and the number of notes survive so the
  audit trail still looks like one, the author is mapped through the name map,
  and the text is filled. The stage-7b sweep would have rewritten addresses
  inside it and left the prose.
- **Documents are blanked.** `media_file.content` and `media_file.name` are
  already emptied by the existing script, so what is left is the path column,
  which applicants write their own names into ("Jane-Smith-CV.pdf"). The rows
  stay, so the listings and the media access rules are still exercised;
  only the path goes.
- **Names and emails** are handled by the existing identity map and the
  stage-7b sweep, as long as the script is run against this database with those
  stages intact.
- **Titles are deliberately kept.** `proposal_proposal.name` is the project
  title, and the sanitiser already keeps `structure_project.name`; filling one
  and not the other would be inconsistent without being safer, since the
  project is created from the proposal. One line in the stage-5 list changes
  that if you disagree.

`scripts/sanitise_verify.sql` gained nine matching checks, which assert on
shape rather than on a list: a prose column fails unless its value is exactly
what `filler()` would have written for its length, so **a column the sanitiser
does not know about fails the run** rather than passing silently. Each was
tested by introducing a leak of its own and confirming it turns red. The
checks are split where the two schemas differ — upstream's `Review` lacks
`comment_project_is_confidential` and `comment_project_has_civilian_purpose`,
and a check skips entirely when one of its columns is absent, so keeping them
together would have quietly stopped verifying the other nine on the portal.

Two lessons from the portal's sanitiser apply directly and are worth
re-reading before writing this one: anything blanked because it is a
*credential* will be missed by some feature that assumes it exists, and the
error will name something other than the credential; and a pseudonym has to be
valid in every format the real value was.

## 9. Rehearsal

### 9.1 First clean run, September 2026

`resync_migrate.sh` completed all nine steps against the sanitised copy of the
awards database, in four minutes, ending on `No changes detected` — the schema
matches the models, so nothing that was faked in steps 2–3 was faked wrongly.
The grace period backfilled. **Upstream's `proposal.0001_squashed_0074` applied
against the empty tables**, which is what the whole archive detour exists to
make possible.

What the archive captured:

| | Copied | Source (Sept measurement) |
|---|---|---|
| Calls | 7 | 7 |
| Rounds | 11 | 11 |
| Proposals | 2263 | 2258 |
| Requested resources | 2274 | 2271 |
| Reviews | 1783 | 1780 |
| Call documents | 22 | 22 |
| Proposal documents | 3412 | 3403 |
| Memberships | 5897 | — |
| Memberships on a missing proposal | 1537 | 1537 |

The membership figures reconcile exactly: 5,897 + 1,537 = 7,434, every
assignment the seven roles carried. The 5,897 is §3.5's 5,587 resolvable
proposal-scoped rows plus the 310 call- and organisation-scoped ones. The small
excesses elsewhere are the dump being newer than the measurement.

It took four attempts to get there, each failing on the same underlying
mistake in a different guise: **code written against the schema as it will be,
running against the schema as it is mid-upgrade.** A field width inherited
from the live model (§4), Django's delete collector querying tables that do not
exist yet (§3.5), a table that exists without its newest column (§3.5), and
foreign keys that a rename preserved (§3.6). Anything reading or writing during
this window has to treat the database, not the model graph, as the authority.

### 9.2 Not yet proved

One thing the sanitised copy cannot establish, and it matters on production:

- **The media rename.** It reported `media paths moved: 0`, because the
  sanitiser blanks document paths. On production it should move roughly 3,425
  rows; if it reports 0 there, every archived document will 403. This is the
  one number to check in the production run.

A second was an open question and is now settled. The cascade deletes 2,468
`users_invitation` rows referencing the fork's proposal roles — as Django's own
`CASCADE` would have done — and does **not** archive them. Confirmed September
2026 that this is wanted: the invitations are to calls that are closed, so they
carry nothing worth keeping. No `ArchivedInvitation` model, and the count in the
command's output is informational rather than a warning.

### 9.3 Still to rehearse

The rest of §3 should be rehearsed on the sanitised copy before it is run
anywhere else, including the parts that are easy to skip:

- a document download through `/api/media/<uuid>/` as each class of user in
  §4.2 — this is where the prefix collision of §5 shows up if it has been got
  wrong;
- an old `/proposals/{uuid}` link, to prove the fallback resolves;
- `waldur check`, `makemigrations --check`, and schema generation with
  `--fail-on-warn`, as for any change.

## 10. Open questions

Settled during the build, kept here because the reasoning is easy to lose:

- **`ProposalResourceAdjustment`** (223 rows) is folded into
  `ArchivedProposal.payload["resource_adjustments"]` rather than given a model.
  `ProposalIDGenerator` is not archived at all — it is a counter for proposals
  that will never be issued again.
- **Invitations to the fork's proposal roles** are deleted with the roles, not
  archived (§9.2).

Still open:

- **Dropping the renamed tables**: after how long, and on whose say-so?
- **Archived call documents**: upstream serves the live ones publicly. The
  archive serves them under the §4.2 rule instead. Is anything lost by that?
  Nobody has asked for them to be public, so it stays as it is until someone
  does.
- **Retention**: is there a point at which archived proposals should be deleted
  outright — and does anything (funding body, institutional policy) require
  them to be kept for a set period?
- **Whether the live survey is reporting a real call reference** (§7.1): the
  tip of `feature_airrportal` calls two proposal endpoints it does not import.
