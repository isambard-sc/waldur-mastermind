-- Read-only pre-flight check for the upstream resync reconciliation.
--
-- Run this against a database BEFORE running resync_reconcile_db.sql, at each
-- stage (dev, test, production). It writes nothing: it opens a read-only
-- transaction and only counts and inspects the catalog.
--
--   psql -U waldur -d waldur -f resync_preflight_check.sql
--
-- or through docker compose:
--
--   docker compose exec -T waldur-db psql -U waldur -d waldur \
--     < scripts/resync_preflight_check.sql
--
-- WHAT IT EMITS, AND WHY THAT IS SAFE TO SHARE
--
-- Every row is a check name, a status, and either a count or a migration
-- name. It deliberately emits no column values, no user or project
-- identifiers, no emails and no free text from the database, so the output
-- carries no personal data and can be pasted into a ticket or shared with
-- someone helping debug.
--
-- HOW TO READ IT
--
--   PASS    expected state, nothing to do
--   FAIL    must be resolved before running the reconciliation
--   WARN    needs a decision, but not necessarily a blocker
--   INFO    context, no judgement
--
-- Any FAIL means stop and work out why before reconciling.

\pset border 2
\pset format aligned
\timing off

BEGIN;
SET TRANSACTION READ ONLY;

\echo ''
\echo '=================================================================='
\echo ' Resync pre-flight check (read-only)'
\echo '=================================================================='

-- ---------------------------------------------------------------------------
-- Environment
-- ---------------------------------------------------------------------------
SELECT
    'environment' AS section,
    'postgres_version' AS check,
    'INFO' AS status,
    current_setting('server_version') AS value;

-- ---------------------------------------------------------------------------
-- 1. Migration state per affected app.
--
-- The reconciliation assumes the local history: openportal at 0043, proposal
-- at 0054, and the local structure merge nodes present. A different head means
-- the database is not where the script expects and its DELETE and INSERT lists
-- need revisiting.
-- ---------------------------------------------------------------------------
SELECT
    'migration_state' AS section,
    'head_' || app AS check,
    'INFO' AS status,
    max(name) AS value
FROM django_migrations
WHERE app IN ('waldur_openportal', 'proposal', 'core', 'structure', 'notifications')
GROUP BY app
ORDER BY 2;

-- Local openportal migrations the script expects to delete. Anything other
-- than 10 means the local history differs from the one it was written for.
SELECT
    'migration_state' AS section,
    'local_openportal_rows_to_delete' AS check,
    CASE WHEN count(*) = 10 THEN 'PASS' ELSE 'FAIL' END AS status,
    count(*)::text || ' of 10 expected' AS value
FROM django_migrations
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

-- Local proposal migrations the script expects to delete.
SELECT
    'migration_state' AS section,
    'local_proposal_rows_to_delete' AS check,
    CASE WHEN count(*) = 8 THEN 'PASS' ELSE 'WARN' END AS status,
    count(*)::text || ' of 8 expected' AS value
FROM django_migrations
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

-- Local core and structure rows the script expects to delete.
SELECT
    'migration_state' AS section,
    'local_core_structure_rows_to_delete' AS check,
    CASE WHEN count(*) = 7 THEN 'PASS' ELSE 'WARN' END AS status,
    count(*)::text || ' of 7 expected' AS value
FROM django_migrations
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
-- 2. Evidence of a previously interrupted migration.
--
-- If a migrate has already been attempted against upstream's code, some of
-- upstream's migrations will already be recorded. That is recoverable, but the
-- reconciliation behaves differently and you need to know before starting.
-- ---------------------------------------------------------------------------
SELECT
    'interrupted_run' AS section,
    'upstream_openportal_rows_present' AS check,
    CASE WHEN count(*) = 0 THEN 'PASS' ELSE 'WARN' END AS status,
    CASE WHEN count(*) = 0
         THEN 'none: no prior attempt'
         ELSE count(*)::text || ' present, see next rows' END AS value
FROM django_migrations
WHERE app = 'waldur_openportal'
  AND name IN (
    '0034_allocation_can_be_managed_and_more',
    '0035_add_cached_reports_and_available_mixin',
    '0036_remote_projects',
    '0037_alter_allocation_options_and_more',
    '0038_alter_managedprojectauditentry_options_and_more',
    '0039_alter_remoteprojectattachment_options',
    '0001_squashed_0039'
  );

SELECT
    'interrupted_run' AS section,
    'upstream_openportal_row' AS check,
    'WARN' AS status,
    name AS value
FROM django_migrations
WHERE app = 'waldur_openportal'
  AND name IN (
    '0034_allocation_can_be_managed_and_more',
    '0035_add_cached_reports_and_available_mixin',
    '0036_remote_projects',
    '0037_alter_allocation_options_and_more',
    '0038_alter_managedprojectauditentry_options_and_more',
    '0039_alter_remoteprojectattachment_options',
    '0001_squashed_0039'
  )
ORDER BY name;

-- Proposal beyond the local 0054 means upstream's proposal history has partly
-- or fully replayed already.
SELECT
    'interrupted_run' AS section,
    'proposal_rows_beyond_local_0054' AS check,
    CASE WHEN count(*) = 0 THEN 'PASS' ELSE 'WARN' END AS status,
    count(*)::text || ' upstream proposal migrations already applied' AS value
FROM django_migrations
WHERE app = 'proposal'
  AND name ~ '^00(5[5-9]|6[0-9]|7[0-9])_';

-- An invalid index is the fingerprint of a migration killed mid-flight.
-- Django wraps each migration in a transaction on PostgreSQL, so this should
-- be empty even after a failed run.
SELECT
    'interrupted_run' AS section,
    'invalid_indexes' AS check,
    CASE WHEN count(*) = 0 THEN 'PASS' ELSE 'FAIL' END AS status,
    count(*)::text AS value
FROM pg_index
WHERE NOT indisvalid;

-- ---------------------------------------------------------------------------
-- 3. Objects behind the faked migrations.
--
-- The script records upstream 0035 and 0036 as already-applied on the grounds
-- that the local history already created what they create. If any of these
-- objects is MISSING, faking them would leave the schema incomplete and the
-- error would not surface until something touched the missing table.
-- ---------------------------------------------------------------------------
SELECT
    'faked_objects' AS section,
    'upstream_0035_tables' AS check,
    CASE WHEN count(*) = 2 THEN 'PASS' ELSE 'FAIL' END AS status,
    count(*)::text || ' of 2 cached report tables' AS value
FROM information_schema.tables
WHERE table_schema = 'public'
  AND table_name IN (
    'waldur_openportal_cachedprojectstoragereport',
    'waldur_openportal_cachedprojectusagereport'
  );

SELECT
    'faked_objects' AS section,
    'upstream_0035_indexes' AS check,
    CASE WHEN count(*) = 2 THEN 'PASS' ELSE 'FAIL' END AS status,
    count(*)::text || ' of 2 expected indexes' AS value
FROM pg_indexes
WHERE schemaname = 'public'
  AND indexname IN (
    'waldur_open_project_077226_idx',
    'waldur_open_project_c1652b_idx'
  );

SELECT
    'faked_objects' AS section,
    'upstream_0036_tables' AS check,
    CASE WHEN count(*) = 5 THEN 'PASS' ELSE 'FAIL' END AS status,
    count(*)::text || ' of 5 remote-project tables' AS value
FROM information_schema.tables
WHERE table_schema = 'public'
  AND table_name IN (
    'waldur_openportal_remoteproject',
    'waldur_openportal_remoteprojectallocationentry',
    'waldur_openportal_remoteprojectauditentry',
    'waldur_openportal_remoteprojectattachment',
    'waldur_openportal_managedprojectauditentry'
  );

-- ---------------------------------------------------------------------------
-- 4. Upstream 0034 is NOT faked, so it must be able to run.
--
-- It adds can_be_managed to allocation and remoteallocation, from
-- core_models.AvailableMixin. If the columns already exist, 0034 has already
-- run (a prior attempt) and the script's WHERE NOT EXISTS will leave its row
-- alone; if they do not, 0034 will add them, which is the intended path.
-- ---------------------------------------------------------------------------
SELECT
    'upstream_0034' AS section,
    'can_be_managed_columns' AS check,
    'INFO' AS status,
    count(*)::text || ' of 2 present'
      || CASE WHEN count(*) = 0 THEN ' (0034 will run and add them)'
              WHEN count(*) = 2 THEN ' (0034 already applied)'
              ELSE ' (UNEXPECTED: partially present)' END AS value
FROM information_schema.columns
WHERE table_schema = 'public'
  AND column_name = 'can_be_managed'
  AND table_name IN ('waldur_openportal_allocation', 'waldur_openportal_remoteallocation');

-- ---------------------------------------------------------------------------
-- 5. Columns and tables the script drops.
--
-- Reported so you can see the drops will actually do something, and so a
-- second run is recognisable (everything already gone).
-- ---------------------------------------------------------------------------
SELECT
    'to_drop' AS section,
    'columns_present' AS check,
    'INFO' AS status,
    count(*)::text || ' of 11 local columns still present' AS value
FROM information_schema.columns
WHERE table_schema = 'public'
  AND (
    (table_name = 'core_user' AND column_name = 'unix_username')
    OR (table_name = 'structure_project' AND column_name = 'short_name')
    OR (table_name = 'proposal_proposal' AND column_name IN ('stale_reminder_sent_at', 'submitted_at', 'notes'))
    OR (table_name = 'proposal_round' AND column_name IN (
        'minimum_required_uploads', 'default_allowed_domains',
        'default_membership_control', 'default_reapply_text',
        'default_reapply_url', 'fixed_review_end_date'))
  );

SELECT
    'to_drop' AS section,
    'tables_present' AS check,
    'INFO' AS status,
    count(*)::text || ' of 3 local tables still present' AS value
FROM information_schema.tables
WHERE table_schema = 'public'
  AND table_name IN (
    'proposal_proposalresourceadjustment',
    'proposal_proposalidgenerator',
    'notifications_broadcastmessageattachment'
  );

-- ---------------------------------------------------------------------------
-- 6. THE IRREVERSIBLE GATE.
--
-- unix_username and short_name are dropped and cannot be recovered
-- afterwards. Dropping is only safe when the value still lives somewhere
-- upstream's OpenPortal code will read it: either the matching
-- UserInfo/ProjectInfo shortname, or the slug it falls back to.
--
-- Both of these MUST be zero. Non-zero means a value would be lost.
-- ---------------------------------------------------------------------------
SELECT
    'irreversible_gate' AS section,
    'users_losing_unix_username' AS check,
    CASE WHEN count(*) = 0 THEN 'PASS' ELSE 'FAIL' END AS status,
    count(*)::text AS value
FROM core_user u
WHERE u.unix_username IS NOT NULL
  AND u.unix_username <> ''
  AND coalesce(u.slug, '') <> u.unix_username
  AND NOT EXISTS (
    SELECT 1 FROM waldur_openportal_userinfo i
    WHERE i.user_id = u.id AND i.shortname = u.unix_username
  );

SELECT
    'irreversible_gate' AS section,
    'projects_losing_short_name' AS check,
    CASE WHEN count(*) = 0 THEN 'PASS' ELSE 'FAIL' END AS status,
    count(*)::text AS value
FROM structure_project p
WHERE p.short_name IS NOT NULL
  AND p.short_name <> ''
  AND coalesce(p.slug, '') <> p.short_name
  AND NOT EXISTS (
    SELECT 1 FROM waldur_openportal_projectinfo i
    WHERE i.project_id = p.id AND i.shortname = p.short_name
  );

-- Context for the gate: how the values are currently preserved. Counts only.
SELECT 'irreversible_gate' AS section, 'users_with_unix_username' AS check, 'INFO' AS status, count(*)::text AS value FROM core_user WHERE unix_username IS NOT NULL AND unix_username <> ''
UNION ALL
SELECT 'irreversible_gate', 'users_preserved_via_userinfo', 'INFO', count(*)::text FROM core_user u WHERE u.unix_username IS NOT NULL AND u.unix_username <> '' AND EXISTS (SELECT 1 FROM waldur_openportal_userinfo i WHERE i.user_id = u.id AND i.shortname = u.unix_username)
UNION ALL
SELECT 'irreversible_gate', 'users_preserved_via_slug_only', 'INFO', count(*)::text FROM core_user u WHERE u.unix_username IS NOT NULL AND u.unix_username <> '' AND coalesce(u.slug,'') = u.unix_username AND NOT EXISTS (SELECT 1 FROM waldur_openportal_userinfo i WHERE i.user_id = u.id AND i.shortname = u.unix_username)
UNION ALL
SELECT 'irreversible_gate', 'projects_with_short_name', 'INFO', count(*)::text FROM structure_project WHERE short_name IS NOT NULL AND short_name <> ''
UNION ALL
SELECT 'irreversible_gate', 'projects_preserved_via_projectinfo', 'INFO', count(*)::text FROM structure_project p WHERE p.short_name IS NOT NULL AND p.short_name <> '' AND EXISTS (SELECT 1 FROM waldur_openportal_projectinfo i WHERE i.project_id = p.id AND i.shortname = p.short_name)
UNION ALL
SELECT 'irreversible_gate', 'projects_preserved_via_slug_only', 'INFO', count(*)::text FROM structure_project p WHERE p.short_name IS NOT NULL AND p.short_name <> '' AND coalesce(p.slug,'') = p.short_name AND NOT EXISTS (SELECT 1 FROM waldur_openportal_projectinfo i WHERE i.project_id = p.id AND i.shortname = p.short_name);

-- ---------------------------------------------------------------------------
-- 7. Proposal data.
--
-- The reconciliation resets the proposal app and replays upstream's history.
-- That is only safe on empty tables. If these are non-zero, decide explicitly
-- whether the data is disposable, and purge it before reconciling.
-- ---------------------------------------------------------------------------
-- Counted through dynamic SQL because the tables may not be there to name.
-- On the awards site the reconciliation renames them to old_proposal_*, and a
-- plain SELECT against a missing relation fails at parse time -- which aborted
-- the whole read-only transaction and took every later check with it.
DO $proposal$
DECLARE
    spec record;
    src text;
    n bigint;
    archived boolean;
BEGIN
    archived := EXISTS (SELECT 1 FROM pg_tables
                        WHERE schemaname = 'public'
                          AND tablename LIKE 'old\_proposal\_%');

    FOR spec IN
        SELECT * FROM (VALUES
            ('proposal_rows',            'proposal_proposal'),
            ('round_rows',               'proposal_round'),
            ('call_rows',                'proposal_call'),
            ('resource_adjustment_rows', 'proposal_proposalresourceadjustment')
        ) AS t(label, tbl)
    LOOP
        src := CASE WHEN archived THEN 'old_' || spec.tbl ELSE spec.tbl END;

        IF to_regclass('public.' || quote_ident(src)) IS NULL THEN
            RAISE NOTICE '| proposal_data | % | SKIP | no such table |',
                rpad(spec.label, 24);
            CONTINUE;
        END IF;

        EXECUTE format('SELECT count(*) FROM public.%I', src) INTO n;

        IF spec.label <> 'proposal_rows' THEN
            RAISE NOTICE '| proposal_data | % | INFO | % |',
                rpad(spec.label, 24), n;
        ELSIF archived THEN
            -- Already moved aside: the rows are the archive's input, not a
            -- decision to make.
            RAISE NOTICE '| proposal_data | % | PASS | % archived |',
                rpad(spec.label, 24), n;
        ELSIF n = 0 THEN
            RAISE NOTICE '| proposal_data | % | PASS | 0 |',
                rpad(spec.label, 24);
        ELSE
            RAISE NOTICE '| proposal_data | % | WARN | % (archived by the '
                'reconciliation; see awards-site-upgrade-plan.md) |',
                rpad(spec.label, 24), n;
        END IF;
    END LOOP;
END $proposal$;

-- Purging proposal data is only self-contained if nothing outside the app
-- points at it. Any row here must be considered before truncating.
SELECT
    'proposal_data' AS section,
    'external_fks_into_proposal' AS check,
    CASE WHEN count(*) = 0 THEN 'PASS' ELSE 'WARN' END AS status,
    count(*)::text AS value
FROM (
    SELECT DISTINCT tc.table_name, ccu.table_name AS target
    FROM information_schema.table_constraints tc
    JOIN information_schema.constraint_column_usage ccu
      ON tc.constraint_name = ccu.constraint_name
    WHERE tc.constraint_type = 'FOREIGN KEY'
      AND ccu.table_name LIKE 'proposal_%'
      AND tc.table_name NOT LIKE 'proposal_%'
) x;

SELECT
    'proposal_data' AS section,
    'external_fk_detail' AS check,
    'WARN' AS status,
    table_name || ' -> ' || target AS value
FROM (
    SELECT DISTINCT tc.table_name, ccu.table_name AS target
    FROM information_schema.table_constraints tc
    JOIN information_schema.constraint_column_usage ccu
      ON tc.constraint_name = ccu.constraint_name
    WHERE tc.constraint_type = 'FOREIGN KEY'
      AND ccu.table_name LIKE 'proposal_%'
      AND tc.table_name NOT LIKE 'proposal_%'
) x
ORDER BY 4;

-- ---------------------------------------------------------------------------
-- 8. Scale, for judging how long the run will take.
-- ---------------------------------------------------------------------------
SELECT
    'scale' AS section,
    'database_size' AS check,
    'INFO' AS status,
    pg_size_pretty(pg_database_size(current_database())) AS value
UNION ALL
SELECT 'scale', 'table_count', 'INFO', count(*)::text FROM information_schema.tables WHERE table_schema = 'public'
UNION ALL
SELECT 'scale', 'django_migrations_rows', 'INFO', count(*)::text FROM django_migrations;

-- Biggest tables, since the proposal replay and the two column drops rewrite
-- table data. Names and sizes only.
SELECT
    'scale' AS section,
    'largest_table' AS check,
    'INFO' AS status,
    relname || ' = ' || pg_size_pretty(pg_total_relation_size(c.oid)) AS value
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public' AND c.relkind = 'r'
ORDER BY pg_total_relation_size(c.oid) DESC
LIMIT 10;

COMMIT;

\echo ''
\echo 'Pre-flight complete. Any FAIL must be resolved before reconciling.'
\echo 'A WARN on proposal_rows or on the interrupted_run checks needs a'
\echo 'decision, not necessarily a fix.'
\echo ''
