-- Redact deployment URLs in an already-sanitised database.
--
-- A repair, not part of the pipeline. Use it when the output scan in
-- scripts/sanitise_production_dump.sh reports leaked URLs and the sanitiser
-- has already committed: rewriting the whole database again can be hours,
-- and URLs need none of the identity mapping that made it slow.
--
--   psql -d waldur_sanitise -f scripts/sanitise_repair_urls.sql
--
-- It rewrites URLs at the text level rather than walking JSON structure, so
-- running it over every column is minutes rather than hours. Give it a list
-- and it does only those:
--
--   psql -d waldur_sanitise \
--        -c "SET waldur.repair_columns =
--            'waldur_openportal_remoteproject.link_award,
--             waldur_openportal_job.job_data'" \
--        -f scripts/sanitise_repair_urls.sql
--
-- Find the list with the commands the failing scan prints, or:
--
--   zcat out.sql.gz | awk '/^COPY /{t=$2} /https?:\/\//{print t}' \
--     | sort | uniq -c | sort -rn | head
--
-- Afterwards re-verify and re-dump without redoing the sanitising:
--
--   KEEP_SCRATCH=1 SKIP_SANITISE=1 scripts/sanitise_production_dump.sh \
--       --reuse-server <datadir> in.sql.gz out.sql.gz
--
-- Idempotent: a URL already replaced is on the allowlist, so a second run
-- leaves it alone.

\set ON_ERROR_STOP on

BEGIN;

DROP SCHEMA IF EXISTS repair CASCADE;
CREATE SCHEMA repair;

-- Kept identical to sanitise.is_local_url in
-- scripts/sanitise_production_dump.sql. If you change one, change both.
CREATE FUNCTION repair.is_local_url(val text)
RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
    SELECT val ~* ('^https?://([^/]*\.)?('
        || 'localhost|127\.0\.0\.1|example\.com|example\.org|example\.net'
        || '|w3\.org|schema\.org|json-schema\.org|creativecommons\.org'
        || '|opensource\.org|github\.com|waldur\.com)([:/]|$)')
$$;

CREATE FUNCTION repair.scrub_urls(val text)
RETURNS text LANGUAGE plpgsql STABLE AS $$
DECLARE
    m text;
BEGIN
    IF val IS NULL OR position('http' IN val) = 0 THEN
        RETURN val;
    END IF;
    FOR m IN
        SELECT DISTINCT match[1]
        FROM regexp_matches(val, '(https?://[A-Za-z0-9._~:/?#@!$&()*+,;=%-]+)',
                            'g') AS match
        ORDER BY 1
    LOOP
        IF NOT repair.is_local_url(m) THEN
            val := replace(val, m, 'https://example.com/redacted');
        END IF;
    END LOOP;
    RETURN val;
END $$;

-- No JSON walking. A URL is a URL wherever it sits in the document, and
-- replacing one URL with another introduces no quote, backslash or brace, so
-- the text form of a jsonb value can be rewritten and cast straight back.
-- That matters: the columns holding these URLs are the OpenPortal payloads,
-- and a recursive walk of them is the step that takes hours. A regex pass over
-- the same bytes takes minutes.
--
-- Safe because jsonb's text output does not escape forward slashes, so
-- https:// appears literally and the pattern matches it.

DO $$
DECLARE
    wanted text := coalesce(
        current_setting('waldur.repair_columns', true), '');
    wanted_cols text[] := NULL;
    r record;
    n bigint;
    total bigint := 0;
    started timestamptz := clock_timestamp();
BEGIN
    IF btrim(wanted) <> '' THEN
        SELECT array_agg(btrim(x)) INTO wanted_cols
        FROM regexp_split_to_table(wanted, ',') AS x
        WHERE btrim(x) <> '';
        RAISE NOTICE 'repairing % named columns', cardinality(wanted_cols);
    ELSE
        RAISE NOTICE 'repairing every JSON and text column '
                     '(set waldur.repair_columns to narrow it)';
    END IF;

    FOR r IN
        SELECT c.table_name AS tbl, c.column_name AS col, c.udt_name AS udt
        FROM information_schema.columns c
        JOIN information_schema.tables t
          ON t.table_schema = c.table_schema
         AND t.table_name = c.table_name
         AND t.table_type = 'BASE TABLE'
        WHERE c.table_schema = 'public'
          AND c.udt_name IN ('json', 'jsonb', 'varchar', 'text', 'bpchar')
          AND c.is_generated = 'NEVER'
          AND c.is_updatable = 'YES'
          AND c.table_name <> 'django_migrations'
          AND (wanted_cols IS NULL
               OR (c.table_name || '.' || c.column_name) = ANY (wanted_cols))
        ORDER BY c.table_name, c.column_name
    LOOP
        IF r.udt IN ('json', 'jsonb') THEN
            EXECUTE format(
                'UPDATE public.%I SET %I =
                     repair.scrub_urls(%I::text)::%s
                 WHERE %I::text LIKE ''%%http%%''',
                r.tbl, r.col, r.col, r.udt, r.col);
        ELSE
            EXECUTE format(
                'UPDATE public.%I SET %I = repair.scrub_urls(%I)
                 WHERE %I LIKE ''%%http%%''',
                r.tbl, r.col, r.col, r.col);
        END IF;
        GET DIAGNOSTICS n = ROW_COUNT;
        IF n > 0 THEN
            total := total + n;
            -- Rows TOUCHED, not rows changed. The prefilter matches any row
            -- containing "http", and most of those hold only allowlisted URLs
            -- that scrub_urls leaves alone - but rewriting a row to the same
            -- value still counts as an update. Reading these as a leak count
            -- overstates it by orders of magnitude; the output scan is what
            -- says how much actually leaked.
            RAISE NOTICE '  %.%: % rows examined', r.tbl, r.col, n;
        END IF;
    END LOOP;

    RAISE NOTICE 'repair done: % rows examined in % - re-run the output scan',
        total, clock_timestamp() - started;
    RAISE NOTICE 'to see how many URLs actually needed redacting';

    IF wanted_cols IS NOT NULL THEN
        -- A named list only fixes what it names. Say so, because the output
        -- scan is the thing that decides, not this notice.
        RAISE NOTICE 'only the named columns were touched; re-run the output';
        RAISE NOTICE 'scan to confirm nothing else is leaking';
    END IF;
END $$;

DROP SCHEMA repair CASCADE;

COMMIT;

VACUUM (ANALYZE);
