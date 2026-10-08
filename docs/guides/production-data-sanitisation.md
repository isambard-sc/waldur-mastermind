### Loading it into a local deployment

Check first that the PostgreSQL which will read the dump is not older than the
one that wrote it. **Match the version of the cluster the sanitiser runs in to
production's**, or this bites: a production database on 17.2, sanitised in a
cluster built from PostgreSQL 18.4, produces an output dump that a `postgres:16`
image -- which is what `docker-compose.yml` defaults to -- cannot
straightforwardly read. The script now says so when it notices the mismatch,
early enough to act on. A dump from a newer major version can carry syntax an older
server rejects, and recent minor versions of `pg_dump` emit `\restrict` and
`\unrestrict` meta-commands that an older `psql` does not know -- harmless in
themselves, since the restore continues, but a sign the versions do not match:

```bash
gzip -dc sanitised.sql.gz | head -20 | grep -i version
docker compose exec -T waldur-db psql --version
```

Then, with the containers down apart from the database, since Waldur migrates
at startup. **The `DROP` destroys whatever is in the local `waldur` database
now:**

```bash
docker compose up -d waldur-db
docker compose exec -T waldur-db psql -U waldur -d postgres \
    -c 'DROP DATABASE waldur' -c 'CREATE DATABASE waldur OWNER waldur'
gzip -dc sanitised.sql.gz | docker compose exec -T waldur-db psql -U waldur -d waldur
docker compose exec -T waldur-db psql -U waldur -d waldur < scripts/resync_preflight_check.sql
docker compose exec -T waldur-db psql -U waldur -d waldur < scripts/resync_reconcile_db.sql
docker compose up -d
docker compose exec waldur-mastermind-api waldur makemigrations --check --dry-run
docker compose exec waldur-mastermind-api \
    waldur createsuperuser --username admin --email admin@example.com
```

Read the pre-flight output rather than just running it: it must report no
`FAIL` before the reconciliation, which drops two columns irreversibly. And do
not skip `makemigrations --check` -- it is what catches a migration recorded as
applied whose DDL never actually ran.

`scripts/resync_rehearse_migration.sh` is **not** for this path. It exists for a
sanitised database sitting in a bare cluster. The sequence above is closer to
production, because it uses the deployment's own settings and its own startup
path rather than a settings module written for rehearsing.

# Sanitising a production dump for local testing

A production database makes far better test data than anything generated: real
row counts, real distributions, real awkward records. Two things stop you
loading one into a local deployment.

1. **It is that deployment.** Constance keeps the portal's settings in the
   database, so a restored dump points your local instance at the production
   homeport, the production helpdesk, and the production identity provider,
   with the client secrets to reach them.
2. **It is personal data.** Names, addresses, national identity numbers, dates
   of birth, phone numbers, identity-provider claim sets, and the whole audit
   trail of who did what.

`scripts/sanitise_production_dump.sh` produces a dump with neither.

## Running it

```bash
# On a machine that can reach a PostgreSQL server. The scratch database is
# created and dropped for you.
scripts/sanitise_production_dump.sh production.sql.gz sanitised.sql.gz
```

Take the input with `pg_dump`, not `pg_dumpall` -- a cluster dump carries
`CREATE DATABASE` and cannot be restored into one database:

```bash
pg_dump --no-owner --no-privileges -d waldur -Fp | gzip > production.sql.gz
```

### Without touching an existing PostgreSQL

`--own-server` runs `initdb` into a temporary directory, starts a private
server there, does everything against that, and destroys the cluster on the way
out. Nothing existing is touched -- no scratch database on a production server,
nothing on a shared access node's own PostgreSQL:

```bash
scripts/sanitise_production_dump.sh --own-server production.sql.gz sanitised.sql.gz
```

It needs no superuser rights and no configuration; the cluster belongs to
whoever runs the script. It needs `initdb` and `pg_ctl`, which come with the
server package rather than the client one -- the script looks for them on
`PATH` and then under `/usr/lib/postgresql/*/bin` and `/usr/pgsql-*/bin`, and
`PG_BIN` points it somewhere else.

Three things worth knowing about that mode:

- **Space.** The cluster holds the whole database, plus whatever `VACUUM` has
  not reclaimed. Allow roughly ten times the compressed input. It goes next to
  the output file by default; `SANITISE_PGDATA` moves it elsewhere. The script
  prints what it expects to need and what is free before it starts.
- **It is not reachable.** The temporary cluster trusts every connection, so it
  is started with `listen_addresses=''` -- no TCP socket at all -- and its unix
  socket lives inside the 0700 data directory. On a shared node that is the
  difference between a private scratch database and an open one.
- **Run it under tmux.** The script tears the cluster down if its shell goes
  away, which is right for a Ctrl-C but means a dropped SSH connection would
  end a long run. `tmux`, `screen` or `nohup` keeps it alive.

Because the cluster is thrown away, it runs with `fsync`, `full_page_writes`,
`synchronous_commit` and `autovacuum` all off, which roughly halves the restore
time. There is nothing to crash-recover to.

A dump carries `ALTER TABLE ... OWNER TO waldur` for whatever role owns the
production database, and a cluster created seconds ago has no such role. Under
`--own-server` the script reads the role names out of the dump's own header
comments and creates them as login-less placeholders first, so the restore is
silent instead of emitting one error per object. `--no-owner` on the original
`pg_dump` avoids the issue entirely.

The script restores the dump into a scratch database, rewrites it, verifies the
result, and only writes the output dump if every check passes. On failure it
leaves the scratch database behind so you can look at it.

The sanitiser **commits before the verification runs**, so a failure in the
verifier or in the output scan costs only the checking, not the rewriting.
`SKIP_SANITISE=1` picks up an already-sanitised database and does just the
verify, dump and scan -- seconds rather than hours.
`scripts/sanitise_repair_urls.sql` goes with it: it redacts leaked URLs in an
already-sanitised database at the text level rather than by walking JSON
structure, which is minutes rather than the hours the full rewrite takes. Combined with
`KEEP_SCRATCH=1` so that a successful run does not drop the database you may
still want:

```bash
KEEP_SCRATCH=1 SKIP_SANITISE=1 scripts/sanitise_production_dump.sh \
    --reuse-server <datadir> production.sql.gz sanitised.sql.gz
```

## How long it takes

Long enough on a production database to be worth knowing before you start, so
the script tells you. Run it under `tmux` if it is going to be hours. Every step is stamped with the wall-clock time and the
elapsed total, and the progress is teed to `<output>.sanitise.log`, so an
unattended run reads back as a log afterwards.

The JSON sweep dominates. Before doing any of it, the script measures the real
work -- the rows it will walk and the bytes of JSON in them, per column -- and
prints a plan:

```text
[08:56:12] JSON sweep: sizing 188 columns (one scan each, then the real work)
[08:56:12] JSON sweep: 27 non-empty columns, 33,780 rows, 24 MB of JSON.
[08:56:12]   first estimate ~61s (0.4 MB/s, 700 rows/s) - refined after every column
[08:56:12]   [1/27] waldur_openportal_remoteprojectauditentry.new_details (31,355 rows, 20.8 MB)
[08:56:48]         31,355 rows rewritten in 36s | 84% done | ETA ~7s
...
[08:57:02] JSON sweep done: 27 columns, 33,780 rows, 24 MB, in 50s (0.50 MB/s, 682 rows/s)
```

Columns are done biggest-first, so the worst of it is underway in the first
minute and the ETA is projected from representative work rather than from a run
of empty columns. The cost tracks **bytes of JSON, not rows** -- three payload
columns on an audit table can have identical row counts and take 36s, 4s and
0s, because two of them are empty on most rows -- which is why the sizing pass
exists and why the projection is byte-weighted.

Measured throughput on a real dump is **0.4-0.55 MB/s and 700-900 rows/s**, so
for a first guess of your own, take the total size of the JSON columns in your
database and divide by 0.4 MB/s. The built-in first estimate uses the
pessimistic end of both bounds on purpose: it is the number you would use to
decide whether to leave it overnight, and an optimistic guess is worse than a
vague one.

The sizing pass costs one sequential scan per JSON column -- a rounding error
against a walk three orders of magnitude slower per row, but minutes on a very
large database. `SANITISE_SKIP_MEASURE=1` skips it and starts immediately, at
the cost of a much vaguer ETA.

Install `pv` if you want a throughput bar on the restore and the final dump as
well; without it those two steps run silently.

### Rehearsing the migration without moving the dump

If the sanitised database is still sitting in the temporary cluster, rehearse
the migration there rather than shipping the dump somewhere first:

```bash
scripts/resync_rehearse_migration.sh --datadir <the cluster>
```

It copies `waldur_sanitise` to `waldur_rehearsal` with `CREATE DATABASE ...
TEMPLATE`, then runs the pre-flight, the reconciliation, `migrate` and
`makemigrations --check` against the copy, reporting per-migration timings. The
sanitised database is untouched, so the rehearsal can be repeated as often as
it takes. See `docs/guides/upstream-resync-plan.md`.

Loading the result is the same rehearsal the resync plan describes -- bring up
only the database, load, reconcile, then start the rest:

```bash
docker compose up -d waldur-db
docker compose exec -T waldur-db psql -U waldur -d postgres \
    -c 'DROP DATABASE waldur' -c 'CREATE DATABASE waldur OWNER waldur'
gzip -dc sanitised.sql.gz | docker compose exec -T waldur-db psql -U waldur -d waldur
docker compose exec -T waldur-db psql -U waldur -d waldur < scripts/resync_reconcile_db.sql
docker compose up -d
```

No password in the copy is usable and there is no identity provider, so make an
account:

```bash
docker compose exec waldur-mastermind-api \
    waldur createsuperuser --username admin --email admin@example.com
```

## What the pseudonyms look like

Every individual becomes `Person NumberN`, addressed as
`personN@example-orgM.com`, where `N` counts individuals and `M` counts
distinct email domains -- so two people at the same institution share a
domain:

| before | after |
| --- | --- |
| `Ada Lovelace <ada@some.ac.uk>` | `Person Number1 <person1@example-org1.com>` |
| `Alan Turing <alan@other.ac.uk>` | `Person Number2 <person2@example-org2.com>` |
| `Grace Hopper <grace@some.ac.uk>` | `Person Number3 <person3@example-org1.com>` |

`N` follows `core_user.id`, so `Person Number1` is the oldest account and the
numbering is the same every time you run the script against the same dump.
People who never became users -- an invitation nobody accepted, a service
account's contact address -- are numbered after the registered ones.

The mapping is consistent across the whole database. One person keeps one
identity in `core_user`, in their OpenPortal shortname, in their SLURM and
FreeIPA and per-offering account names, in the invitation that created them,
and in the rendered text of their event log. **Accounting that joins users to
allocations by account name still joins**, which is the point: the data has to
stay usable.

Compound account names keep their non-personal parts, because everything
downstream is keyed on them:

```text
jsmith                             ->  person12
jsmith.someproject                 ->  person12.someproject
jsmith.someproject.somecluster     ->  person12.someproject.somecluster
```

## What is removed rather than rewritten

Some things have no pseudonym worth having.

- **Prose.** Support tickets, comments, broadcast messages, staff notes and
  audit notes are replaced with filler of the same length. Substituting the
  names we know about would leave everything else the writer typed, so the
  text goes and the shape stays: a description that filled a panel still
  fills it.
- **Deployment settings.** `constance_constance` is reduced to a named
  allowlist of keys that only affect how data is presented. A deleted key
  falls back to the default in the local `CONSTANCE_CONFIG`, which is the same
  as adopting the local value -- there is nothing to merge in from a local
  dump.
- **Identity providers**, including the keycloak client secret and every realm
  endpoint.
- **Credentials and telemetry**: sessions, API tokens, personal access tokens,
  passkeys, OAuth tokens, service-settings passwords and backend URLs, login
  attempt logs.
- **`django-reversion` history**, which is a serialised snapshot of every
  earlier version of every object -- a complete second copy of the
  pre-sanitisation data with no way to rewrite it reliably.
- **File contents** stored in `media_file`. The rows stay so references
  resolve; the bytes could be anything a user uploaded.
- **URLs**, rewritten to `https://example.com/redacted` unless the host is
  localhost, an `example.*` domain, or a well-known public one.

Mail relay credentials were never in the database: Waldur reads `EMAIL_HOST`,
`EMAIL_HOST_USER` and `EMAIL_HOST_PASSWORD` from settings and the environment
(see `src/waldur_core/core/email_diagnostics.py`).

## What is *not* removed, deliberately

- **Organisation and project names**, and their slugs. They are what makes the
  copy recognisable enough to debug against. A project named after its
  principal investigator would carry that name through; if that matters for
  your data, extend the sanitiser.
- **Cluster and system identifiers** such as an OpenPortal `destination`.
  Deployment-specific, but not a secret, and the accounting views are hard to
  read without them.
- **Everything structural**: dates, costs, usage, quotas, states, row counts,
  and `django_migrations`. The migration history is left strictly alone --
  rehearsing the migration is what this data is for.

## Things production data does that a test database does not

Every one of these was found by running against a real dump, not by reading the
schema, and each is worth knowing if you extend the script.

- **Two accounts on one address.** `core_user.email` has no unique constraint,
  and a real installation has people with a second account, or one left over
  from a rename. Both keep their own name and login -- they must, because
  `core_user.username` *is* unique -- and they go on sharing an address, the
  lower person number naming it. Giving them separate addresses would be tidier
  and would quietly destroy the condition `OIDC_MATCHMAKING_BY_EMAIL` exists to
  handle.
- **Addresses that are not addresses**, stored with stray whitespace, in mixed
  case, with nothing after the `@`, or with no `@` at all. All of them are
  harvested and mapped; none reach the sink.
- **Short surnames.** Substituting a name into prose with a plain `replace()`
  turns "Maybe" into "Person Number7be" for anyone called May. Names are
  substituted on word boundaries only.
- **Keys that look personal and are not.** The event log carries
  `resource_full_name`, which is a *resource's* name. Matching every
  `*_full_name` key replaced those with "Person Number0" and destroyed a field
  the homeport UI renders, so the fallback applies only to keys with a
  person-ish prefix.
- **URLs in prose, not just in URL fields.** The check for a deployment URL
  inside JSON was anchored to the start of the value, so it caught a `link_url`
  field and missed `"see https://some.ac.uk/data for detail"` in a project
  description. Plain text columns were covered and JSON leaves were not. Found
  by the output scan on a production dump, with nothing in any test resembling
  it.

  What it turned up was not deployment configuration at all: 263 occurrences
  of `doi.org`, `arxiv.org`, `turing.ac.uk`, `opendata.cern.ch` and a dozen
  research-group sites, typed by applicants into project descriptions. They
  are redacted anyway -- a few of them name small organisations, and 263
  occurrences against 2.8 million events is no loss of realism -- but the
  premise the scan started from, that any external URL is a deployment
  endpoint, is worth knowing to be wrong. If you would rather keep public
  reference hosts, add them to `sanitise.is_local_url` in the sanitiser AND to
  `ALLOW_URL` in the driver.
- **JSON stored in a text column.** Waldur has its own
  `waldur_core.core.fields.JSONField`, which is a `TextField` to the database
  and JSON to the ORM -- `structure_project.termination_metadata` is one.
  Filling it with prose, because the column type said `text`, made every read
  of the row raise `ValidationError: ['Enter valid JSON']`, surfacing as a 500
  on the projects list. Choosing columns by name cannot tell prose from
  JSON-in-a-text-column, so `sanitise.filler()` now decides from the value:
  anything parsing as a JSON object or array becomes an empty one of the same
  kind.

  Value-sniffing turned out to be the wrong tool for the one column that
  mattered. `structure_project.termination_metadata` is a JSON-backed text
  column *by declaration*, so it is now emptied by name rather than by what
  `filler()` makes of its contents -- a guess is the wrong thing to rely on
  where a wrong answer breaks every read of the row. Behind that, the
  sanitiser ends with a pass over every column of this kind (the list comes
  from Django's field registry) that empties anything no longer parsing,
  whichever earlier stage broke it, and says which column it had to repair so
  the real cause can be fixed. The verifier asserts the same thing with
  `IS JSON`, so the next one of these fails the run rather than the browser.
  `scripts/repair_sanitised_json_text.py` does the same repair on a copy that
  is already loaded, deriving the column list live from the ORM:

  ```bash
  docker compose exec -T waldur-mastermind-api waldur shell \
      -c "$(cat scripts/repair_sanitised_json_text.py)"
  ```

  It took a browser to find it, which is why `scripts/resync_smoke_test.py`
  exists -- it reads every model through the ORM, and the rehearsal script runs
  it as a last step. Note that it reads through `_base_manager`: the corrupted
  row was a *terminated* project, so only `?include_terminated=true` reached
  it, and a smoke test using the soft-delete-filtered default manager walks
  straight past exactly the rows most likely to be damaged.
- **A pseudonym that is not valid input.** The addresses were originally
  `personN@example_orgM.com`. An underscore is not legal in a DNS label, so
  those were not valid email addresses at all -- Django's own
  `validate_email` rejects them. Anything that *validates* rather than merely
  stores an address then failed, and the failures surfaced nowhere near the
  cause: `openportal` parsing an `AwardDetails` document containing one raised

  ```text
  OSError: Parse("Domain label 'example_org27' contains invalid characters
  (only letters, digits, and hyphens allowed) at line 1 column 2852")
  ```

  which `/api/openportal-managed-project-accounting-summary/` catches and
  reports as a null allocation and zero usage -- an accounting bug with no
  accounting cause, on one project out of hundreds. The hyphen in
  `example-orgM.com` is therefore load-bearing, not cosmetic. The general
  lesson: a pseudonym has to be valid in every format the real value was, or
  it moves the failure from "obviously fake data" to "mysterious bug in the
  code under test". `scripts/repair_sanitised_email_domain.sql` fixes a copy
  made before this, rewriting text columns, JSON values, JSON object keys and
  text arrays.
- **A credential whose absence looks like a bug.** Impersonating a user on the
  copy fails with

  ```text
  403: Unable to impersonate user that does not have an active session.
  ```

  The message misdirects: `core/authentication.py` `set_user_context()` tests
  `Token.objects.filter(user=user).exists()` -- a DRF authtoken row, not a
  session. Waldur mints one per user at creation, so every user on a real
  deployment has one; the sanitiser wipes `authtoken_token` and
  `core_personalaccesstoken`, and the verifier fails the run unless both are
  empty. That is right and should stay: a token is a live credential, and a
  dump carrying production's tokens would let anyone hold it authenticate as
  those users.

  The repair belongs after the restore, not in the dump.
  `scripts/restore_impersonation_tokens.py` mints fresh random tokens locally
  -- values that never existed in production:

  ```bash
  docker compose exec -T -e TOKENS_APPLY=1 waldur-mastermind-api waldur shell \
      -c "$(cat scripts/restore_impersonation_tokens.py)"
  ```

  The general shape, again: anything the sanitiser removes *because* it is a
  credential will be missed by some feature that assumes it exists, and the
  error will name something other than the credential.
- **Columns that mix secrets with configuration.**
  `structure_servicesettings.options` holds credentials *and* the settings a
  backend needs to work -- OpenPortal reads `instance_name`,
  `project_template` and the allocation limits from it. Blanking the column
  wholesale, which is the obvious thing to do with a column full of
  credentials, left every OpenPortal sync task failing with `Instance name
  cannot be None`: an error that looks exactly like a bug in the code under
  test and is not. Only secret-shaped keys are removed now. It also has to
  parse-or-blank rather than assume JSON, since the same column is an
  `EncryptedOptionsField` on installations that have applied
  `structure/0081`.

  A copy already loaded from a dump made by the version that blanked the
  column does not need re-dumping:
  `scripts/repair_sanitised_openportal_options.py` puts `instance_name` back,
  deriving it from `RemoteProject.destination` and from the `resource` on the
  cached usage reports (joined to `ServiceSettings` through
  `Allocation.backend_id`). It is a dry run unless `REPAIR_APPLY=1`, reports
  rather than guesses where it cannot derive, and takes the rest as
  `REPAIR_EXTRA='<settings-id>=<identifier>'`. It writes through the ORM
  because `structure/0081` encrypts that column, so a raw `UPDATE` would
  store something the application cannot decrypt.

  ```bash
  docker compose exec -T waldur-mastermind-api waldur shell \
      -c "$(cat scripts/repair_sanitised_openportal_options.py)"
  ```
- **A PostgreSQL built without libxml.** `query_to_xml()` is the standard
  trick for running dynamic SQL from a read-only transaction, and a
  source-built server frequently does not have it. An earlier verifier used it
  and died *after* two hours of sanitising had already committed. The checks
  now run as `EXECUTE ... INTO` inside a `DO` block, which is a read, needs no
  extensions, and works on any build; results come out as notices.
- **A schema older than the one you developed against.** The first production
  run reached the end of the event-log rewrite -- the expensive part -- and
  then died on `core_user.organization_address`, a column added after the
  snapshot the script was written against. Both the sanitiser and the verifier
  now build their statements from the columns that are actually there, and say
  which ones they skipped. A verifier that hard-codes column names fails at the
  worst possible moment: after all the work, before the dump is written.
- **Robot accounts whose names collide with type strings.** An account called
  "OpenPortal Robot" put the bare word "OpenPortal" in the name map, which then
  rewrote every `"service_settings_type": "OpenPortal"` into a person's
  pseudonym. Whole JSON leaves are matched only against multi-token names; bare
  first and last names stay available to the prose substitution, where they
  legitimately appear mid-sentence.

The last three are over-replacements: they fail safe for privacy but damage
exactly the realism the copy exists for, and none of them announce themselves.
Diffing two consecutive runs is what surfaces them, because anything that is
not a fixed point shows up immediately.

## Why not merge two dumps

The obvious approach is to splice the local dump's settings into the production
dump. That means editing `COPY` blocks as text, keeping foreign keys in order
and fixing up sequences, and one missed row leaks exactly the thing the
exercise was meant to remove. Restoring into a scratch database and rewriting
it with SQL lets the database enforce consistency, and lets the result be
checked before anyone sees it.

## How it avoids missing a column

Naming the columns that hold personal data does not work: the leaks are not in
the columns anyone would name. In this codebase they were in

- OpenPortal's project payloads, which keep membership as a JSON object whose
  **keys** are addresses -- a walk that rewrites JSON values leaves every one
  of them;
- a job queue whose payload is a JSON document embedded in a command string,
  so the addresses and note authors inside it are two levels down;
- `core_user.query_field`, a denormalised search string, and
  `core_user.details`, the raw claim set from the identity provider;
- a database cache table keyed on `LOGIN_FAILURES_OF_<address>`.

So the script works by shape, in three layers:

1. **Named columns**, for the fields that hold a person's details directly.
2. **A sweep**, over every JSON column and every text column in the database,
   whatever app declared it. The JSON walk recurses through objects, arrays,
   keys, and documents nested inside strings, mapping a leaf when the whole
   leaf is recognisable. This is the slowest step; on a large installation
   expect it to dominate the run.
3. **Two independent checks.** `scripts/sanitise_verify.sql` asserts that
   every remaining address matches `personN@example-orgM.com` and every
   remaining name matches `Person NumberN` -- so a column nobody thought about
   fails rather than passing quietly. Then the driver greps the bytes of the
   finished dump for anything address- or URL-shaped that is not on an
   allowlist, and refuses to hand over a dump that still has any.

Every one of the leaks listed above was found by layer 3, not by reading the
schema. If you extend the script, keep that order: add the column, then check
that the scan agrees.

### The same field is not the same type everywhere

Both scripts carry an inventory of columns that are `text` in the database and
JSON to the ORM, and check each one still parses. Both used to guard only on
the table and column *existing*. That is half the story: the same Waldur field
is `text` on one deployment and native `json`/`jsonb` on another -
`logging_emailhook.event_groups` is `text` on the portal and `jsonb` on the
awards site - and each script broke differently on the one it did not expect.

```
ERROR:  function sanitise.is_json(jsonb) does not exist
ERROR:  invalid input syntax for type json
```

The first is `sanitise.is_json()` taking `text`. The second is subtler and
worth remembering on its own account: the check reads
`nullif(col, '') IS NOT NULL`, and `nullif` coerces the empty string to the
column's type, so on a `jsonb` column PostgreSQL tries to parse `''` as JSON
and raises before the check ever runs.

Both now guard on `udt_name` and skip anything that is not `text`, `varchar`
or `bpchar` - a native JSON column needs no check, since the database already
guarantees it parses. **When adding a column to either inventory, guard on its
type, not just on its name.**

The cost of getting this wrong is measured in hours, so it is worth knowing
where each failure leaves you:

- **The sanitiser is one transaction**, so a failure there rolls back
  completely and the restored copy is pristine. `--reuse-server <datadir>`
  picks the cluster back up and skips the restore.
- **The verifier runs after the commit**, so a failure there costs only the
  checking. `KEEP_SCRATCH=1 SKIP_SANITISE=1` with the same `--reuse-server`
  re-runs the verify, dump and scan against the already-sanitised database, in
  seconds.

## Rehearsed against

A full run against a real dump: 188 JSON columns sized and the 27 non-empty
ones walked (33,780 rows, 24 MB, 50s), 29 identifier columns mapped, 1,555 text
columns swept, both checks clean, and the result loads, reconciles and migrates
to the resynced schema with `makemigrations --check` reporting no changes.
Re-running the sanitiser over its own output changes nothing -- verified by
diffing two consecutive dumps, which is the only way to be sure of it -- so an
interrupted run can simply be repeated. `--reuse-server` re-runs against a
cluster a previous attempt left behind, skipping the restore.
