-- One-time database reconciliation for the upstream resync.
--
-- This fork is the only deployment, so rather than merging two migration
-- histories, it adopts upstream's history wholesale and reconciles the
-- database to match. Run this ONCE, against a restored production dump
-- first, before ever running it against the live database.
--
-- Order of operations:
--
--   1. Take a full dump.
--   2. Run this script. It is a single transaction, so it either applies
--      completely or not at all.
--   3. Run:  scripts/resync_migrate.sh
--      NOT a plain `migrate`. Five upstream openportal migrations have to be
--      faked, and one of them depends on a structure migration production has
--      not applied, so the order matters and only Django can enforce it.
--      Where migrations run automatically at startup, bring up only the
--      database first, run this script and then that one, and start the rest
--      afterwards - otherwise startup migrates before the reconciliation
--      lands.
--   4. Verify:  python -m waldur_core.server.manage makemigrations --check --dry-run
--      must report "No changes detected".
--
-- Every drop uses IF EXISTS and every delete is keyed on rows that may
-- already be gone, so the script can be re-run safely.

BEGIN;

-- ---------------------------------------------------------------------------
-- 1. waldur_openportal: bookkeeping only.
--
-- The local 0034-0043 series and upstream's 0035-0039 reach the same objects
-- by a different route, so those five must be recorded as applied without
-- running - otherwise they re-run against tables that already exist. That
-- FAKING happens in scripts/resync_migrate.sh, not here; this section only
-- clears the local rows. See the note further down for why.
--
-- What the five upstream migrations would do, and why faking them is right:
--
--   upstream 0035  creates the two cached report tables and their indexes,
--                  which local 0034, 0035 and 0036 already created
--   upstream 0036  creates RemoteProject, RemoteProjectAllocationEntry,
--                  RemoteProjectAuditEntry, RemoteProjectAttachment and
--                  ManagedProjectAuditEntry, which local 0037-0043 created
--   upstream 0037-0039  AlterModelOptions only, so no DDL either way
--
-- Upstream 0034 is deliberately NOT in that list. It adds can_be_managed to
-- allocation and remoteallocation, which upstream's Allocation and
-- RemoteAllocation gain from core_models.AvailableMixin - a base class this
-- fork's models never had. Those two columns genuinely do not exist here, so
-- 0034 must be allowed to run for real in step 3. Faking it would leave the
-- columns missing and the schema quietly wrong.
--
-- AvailableMixin is the only base-class difference between the two trees'
-- openportal models; every other model has identical bases and identical
-- declared fields, which is why the rest of the series is safe to fake.
-- ---------------------------------------------------------------------------

DELETE FROM django_migrations
WHERE app = 'waldur_openportal'
  AND name IN (
    '0034_cachedprojectusagereport',
    '0035_cachedprojectstoragereport',
    '0036_cachedprojectstoragereport_waldur_open_project_077226_idx_and_more',
    '0037_remoteproject_remoteprojectallocationentry_and_more',
    '0038_alter_remoteproject_unique_together_and_more',
    '0039_alter_remoteprojectauditentry_event_type_and_more',
    '0040_remoteproject_error_message',
    '0041_alter_remoteprojectauditentry_event_type',
    '0042_alter_remoteproject_notes',
    '0043_alter_remoteproject_allowed_domains'
  );

-- The five upstream migrations that reach the same objects by a different
-- route are NOT recorded as applied here. An earlier version of this script
-- inserted them, and that is wrong: upstream's 0036_remote_projects depends on
-- structure.0078_alter_servicesettings_certificate, and production has not
-- applied that yet. Django's check_consistent_history then refuses every
-- migrate invocation - including migrate --plan - with
--
--   InconsistentMigrationHistory: Migration waldur_openportal.0036_remote_projects
--   is applied before its dependency structure.0078_alter_servicesettings_certificate
--
-- Recording a migration as applied before its dependencies are applied is
-- something only Django can get right, because only Django knows the graph.
-- So the faking moved to scripts/resync_migrate.sh, which applies the
-- dependency first and then fakes with `migrate ... --fake`.
--
-- This DELETE is here so that a database reconciled by the older version of
-- this script is put back into the state the migrate script expects. It is a
-- no-op on a database that never had them.
DELETE FROM django_migrations
WHERE app = 'waldur_openportal'
  AND name IN (
    '0035_add_cached_reports_and_available_mixin',
    '0036_remote_projects',
    '0037_alter_allocation_options_and_more',
    '0038_alter_managedprojectauditentry_options_and_more',
    '0039_alter_remoteprojectattachment_options'
  );

-- ---------------------------------------------------------------------------
-- 2. proposal: clean reset, or archive, depending on the site.
--
-- The two deployments diverge here and nowhere else, so this section picks its
-- own path rather than there being two scripts to keep in step:
--
--   * The PORTAL holds no proposals. The local 0047-0054 series is undone in
--     place and upstream's 0047-0077 replays over the same tables.
--
--   * The AWARDS SITE holds thousands. Its tables are renamed to
--     old_proposal_*, with their indexes, constraints and sequences, and the
--     whole proposal history is deleted so upstream's schema is created from
--     scratch beside the old data. Nothing is dropped and nothing is
--     rewritten; the archive app copies out of the old_* tables afterwards.
--     See docs/guides/awards-site-upgrade-plan.md.
--
-- Which path is taken is decided from the data, not from a flag: a proposal
-- table carrying rows is never stripped of its columns. Already done, either
-- way, is a no-op.
--
-- Checked for collisions before writing the portal path: none of these names
-- clash with upstream's proposal schema. Upstream's only submitted_at is on
-- ReviewerBid, not Proposal, and its notes fields are internal_notes,
-- review_notes and manager_notes - all distinct from the local Proposal.notes.
-- ---------------------------------------------------------------------------
-- The new name for an object being moved aside. PostgreSQL identifiers stop at
-- 63 bytes and several of Django's generated constraint names are close to it,
-- so a plain 'old_' || name would be silently truncated - and two long names
-- that differ only at the end would truncate onto each other. Past the limit,
-- keep a readable prefix and make it unique with a hash of the original.
--
-- pg_temp so it disappears with the session; nothing is left behind.
CREATE FUNCTION pg_temp.rename_target(name text)
RETURNS text LANGUAGE sql IMMUTABLE AS $fn$
    SELECT CASE
        WHEN length($1) <= 59 THEN 'old_' || $1
        ELSE 'old_' || substr($1, 1, 46) || '_' || substr(md5($1), 1, 8)
    END
$fn$;


DO $$
DECLARE
    tbl text;
    targets text[];
    obj record;
    new_name text;
    tables_renamed int := 0;
    objects_renamed int := 0;
    rows_deleted int;
    proposal_rows bigint := 0;
BEGIN
    IF EXISTS (SELECT 1 FROM pg_tables
               WHERE schemaname = 'public'
                 AND tablename LIKE 'old\_proposal\_%') THEN
        RAISE NOTICE 'proposal: already moved aside, nothing to do';
        RETURN;
    END IF;

    IF to_regclass('public.proposal_proposal') IS NULL THEN
        RAISE NOTICE 'proposal: no proposal_proposal table, nothing to do';
        RETURN;
    END IF;

    EXECUTE 'SELECT count(*) FROM public.proposal_proposal' INTO proposal_rows;

    IF proposal_rows = 0 THEN
        ----------------------------------------------------------
        -- The portal: undo the local series in place.
        ----------------------------------------------------------
        RAISE NOTICE 'proposal: % rows, resetting in place', proposal_rows;

        DROP TABLE IF EXISTS proposal_proposalresourceadjustment;
        DROP TABLE IF EXISTS proposal_proposalidgenerator;

        ALTER TABLE proposal_proposal DROP COLUMN IF EXISTS stale_reminder_sent_at;
        ALTER TABLE proposal_proposal DROP COLUMN IF EXISTS submitted_at;
        ALTER TABLE proposal_proposal DROP COLUMN IF EXISTS notes;

        ALTER TABLE proposal_round DROP COLUMN IF EXISTS minimum_required_uploads;
        ALTER TABLE proposal_round DROP COLUMN IF EXISTS default_allowed_domains;
        ALTER TABLE proposal_round DROP COLUMN IF EXISTS default_membership_control;
        ALTER TABLE proposal_round DROP COLUMN IF EXISTS default_reapply_text;
        ALTER TABLE proposal_round DROP COLUMN IF EXISTS default_reapply_url;
        ALTER TABLE proposal_round DROP COLUMN IF EXISTS fixed_review_end_date;

        DELETE FROM django_migrations
        WHERE app = 'proposal'
          AND name IN (
            '0047_proposal_stale_reminder_sent_at',
            '0048_proposalidgenerator',
            '0049_round_minimum_required_uploads',
            '0050_proposal_submitted_at',
            '0051_proposalresourceadjustment',
            '0052_proposal_notes_round_default_allowed_domains_and_more',
            '0053_round_default_reapply_text_round_default_reapply_url',
            '0054_round_fixed_review_end_date'
          );
        GET DIAGNOSTICS rows_deleted = ROW_COUNT;
        RAISE NOTICE 'proposal: % local migration rows deleted', rows_deleted;
        RETURN;
    END IF;

    ----------------------------------------------------------
    -- The awards site: move the whole app aside, keeping the data.
    ----------------------------------------------------------
    RAISE NOTICE 'proposal: % rows, archiving rather than resetting',
        proposal_rows;

    ------------------------------------------------------------------
    -- Rename, one table at a time.
    --
    -- The indexes, constraints and sequences have to move too. Renaming only
    -- the table leaves proposal_call_pkey, proposal_call_id_seq and the rest
    -- attached to it, and the CREATE TABLE that upstream's migrations run next
    -- wants those very names: index and sequence names are unique per schema,
    -- so the migration would fail on "relation already exists" with no obvious
    -- connection to what this script did.
    ------------------------------------------------------------------
    -- Collected before any renaming rather than iterated as a cursor: the
    -- loop body renames the very rows the query selects from, and a scan that
    -- reads the catalogue as it changes underneath itself is not something to
    -- depend on.
    SELECT array_agg(tablename ORDER BY tablename) INTO targets
    FROM pg_tables
    WHERE schemaname = 'public' AND tablename LIKE 'proposal\_%';

    FOREACH tbl IN ARRAY coalesce(targets, ARRAY[]::text[])
    LOOP
        -- Constraints first: renaming a constraint renames the index that
        -- backs it, so doing indexes first would rename some of them twice.
        FOR obj IN
            SELECT conname AS name FROM pg_constraint
            WHERE conrelid = ('public.' || quote_ident(tbl))::regclass
        LOOP
            new_name := pg_temp.rename_target(obj.name);
            EXECUTE format('ALTER TABLE public.%I RENAME CONSTRAINT %I TO %I',
                           tbl, obj.name, new_name);
            objects_renamed := objects_renamed + 1;
        END LOOP;

        FOR obj IN
            SELECT indexname AS name FROM pg_indexes
            WHERE schemaname = 'public' AND tablename = tbl
              AND indexname NOT LIKE 'old\_%'
        LOOP
            new_name := pg_temp.rename_target(obj.name);
            EXECUTE format('ALTER INDEX public.%I RENAME TO %I',
                           obj.name, new_name);
            objects_renamed := objects_renamed + 1;
        END LOOP;

        -- Sequences owned by this table's columns, which is how Django's
        -- AutoField primary keys are backed.
        FOR obj IN
            SELECT s.relname AS name
            FROM pg_class s
            JOIN pg_depend d ON d.objid = s.oid AND d.deptype = 'a'
            JOIN pg_class t ON t.oid = d.refobjid
            WHERE s.relkind = 'S' AND t.relname = tbl
              AND t.relnamespace = 'public'::regnamespace
        LOOP
            new_name := pg_temp.rename_target(obj.name);
            EXECUTE format('ALTER SEQUENCE public.%I RENAME TO %I',
                           obj.name, new_name);
            objects_renamed := objects_renamed + 1;
        END LOOP;

        EXECUTE format('ALTER TABLE public.%I RENAME TO %I',
                       tbl, pg_temp.rename_target(tbl));
        tables_renamed := tables_renamed + 1;
        RAISE NOTICE 'renamed %  ->  %', tbl, pg_temp.rename_target(tbl);
    END LOOP;

    ------------------------------------------------------------------
    -- Forget the app's migration history entirely.
    --
    -- Not just the fork's 0047-0054: the whole series. The awards site's
    -- history is not linear -- it records both 0001_initial and
    -- 0001_initial_squashed_0033_call_organizer, and two 0027 nodes -- and
    -- with the tables gone there is nothing for any of it to describe.
    -- Deleting all of it lets upstream's 0001_squashed_0074 apply as a single
    -- unit against a clean slate, which is the easiest case for a squash
    -- rather than the hardest.
    ------------------------------------------------------------------
    DELETE FROM django_migrations WHERE app = 'proposal';
    GET DIAGNOSTICS rows_deleted = ROW_COUNT;


    RAISE NOTICE '% tables renamed, % indexes/constraints/sequences with them,'
        ' % migration rows deleted. Nothing dropped; the data is in'
        ' old_proposal_*.', tables_renamed, objects_renamed, rows_deleted;
END $$;

-- ---------------------------------------------------------------------------
-- 3. Vestigial columns: core.User.unix_username, structure.Project.short_name.
--
-- Superseded by shortname handling inside waldur_openportal
-- (UserInfo.shortname and ProjectInfo.shortname, synced to User.slug and
-- Project.slug). Upstream's OpenPortal code guards both with hasattr and falls
-- back to slug, so dropping them changes no upstream behaviour.
--
-- BEFORE RUNNING: confirm no value would be lost. Run
-- scripts/resync_preflight_check.sql, whose irreversible_gate section must
-- report PASS for both users_losing_unix_username and
-- projects_losing_short_name. The data is not recoverable once the columns
-- are gone.
--
-- The gate allows two homes for the value, because upstream's OpenPortal code
-- reads either: the matching UserInfo/ProjectInfo shortname, or the slug it
-- falls back to when no info row exists. Requiring the info row alone gives
-- false failures - a rehearsal against a real database flagged a user who had
-- no UserInfo row but whose slug already carried the value, so nothing would
-- have been lost.
-- ---------------------------------------------------------------------------

ALTER TABLE core_user DROP COLUMN IF EXISTS unix_username;
ALTER TABLE structure_project DROP COLUMN IF EXISTS short_name;

-- The migrations that added those columns, and the merge nodes that stitched
-- the local branch into upstream's history, are gone from the tree; their rows
-- must go too, or migrate will fail on unknown nodes.
DELETE FROM django_migrations
WHERE (app = 'core' AND name = '0011_user_unix_username')
   OR (app = 'structure' AND name IN (
        '0046_project_short_name',
        '0053_alter_project_short_name',
        '0054_merge_20250612_0633',
        '0062_merge_20251006_0729',
        '0063_merge_20251014_0410',
        '0067_merge_20251110_0435'
      ));

-- ---------------------------------------------------------------------------
-- 4. Broadcast message attachments.
--
-- Dropped along with the feature. The attached files themselves stay in media
-- storage; remove them separately if that storage matters.
-- ---------------------------------------------------------------------------

DROP TABLE IF EXISTS notifications_broadcastmessageattachment;

DELETE FROM django_migrations
WHERE app = 'notifications' AND name = '0010_broadcastmessageattachment';

COMMIT;

-- After step 3, this should show a plausible count per app and nothing for the
-- removed local migrations:
--
--   SELECT app, count(*) FROM django_migrations GROUP BY app ORDER BY app;
