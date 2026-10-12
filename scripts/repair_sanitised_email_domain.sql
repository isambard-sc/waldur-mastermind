-- Make the sanitised email domains valid: example_orgN -> example-orgN.
--
-- An earlier version of scripts/sanitise_production_dump.sql wrote addresses
-- as personN@example_orgM.com. An underscore is not legal in a DNS label, so
-- those are not valid email addresses, and anything that VALIDATES rather
-- than merely stores one fails on the copy. Django's own validate_email
-- rejects them; so does openportal parsing an AwardDetails document that
-- carries one:
--
--   OSError: Parse("Domain label 'example_org27' contains invalid characters
--   (only letters, digits, and hyphens allowed) at line 1 column 2852")
--
-- which /api/openportal-managed-project-accounting-summary/ catches and
-- reports as a null allocation and zero usage - an accounting bug with no
-- accounting cause.
--
-- The sanitiser now uses a hyphen. This repairs a copy already loaded from a
-- dump that used an underscore, without re-dumping.
--
--   docker compose exec -T waldur-db psql -U waldur -d waldur \
--       < scripts/repair_sanitised_email_domain.sql
--
-- A literal, unambiguous substitution: "example_org" followed by digits only
-- ever came from the sanitiser. Text and JSON columns both, since addresses
-- live inside JSON documents as values AND as object keys.
--
-- Safe to re-run: once rewritten there is nothing left to match.

\timing on

BEGIN;

CREATE OR REPLACE FUNCTION pg_temp.fix_domain(v text)
RETURNS text LANGUAGE sql IMMUTABLE AS $$
    SELECT regexp_replace(v, 'example_org([0-9])', 'example-org\1', 'g')
$$;

CREATE OR REPLACE FUNCTION pg_temp.fix_domain_json(v jsonb)
RETURNS jsonb LANGUAGE plpgsql IMMUTABLE AS $$
BEGIN
    RETURN CASE jsonb_typeof(v)
        WHEN 'string' THEN to_jsonb(pg_temp.fix_domain(v #>> '{}'))
        WHEN 'array' THEN coalesce(
            (SELECT jsonb_agg(pg_temp.fix_domain_json(e))
             FROM jsonb_array_elements(v) AS e), '[]'::jsonb)
        WHEN 'object' THEN coalesce(
            (SELECT jsonb_object_agg(
                        pg_temp.fix_domain(k), pg_temp.fix_domain_json(val))
             FROM jsonb_each(v) AS t(k, val)), '{}'::jsonb)
        ELSE v
    END;
END $$;

DO $$
DECLARE
    r record;
    updated bigint;
    total bigint := 0;
    cols int := 0;
BEGIN
    FOR r IN
        SELECT c.table_name AS tbl, c.column_name AS col, c.udt_name AS udt
        FROM information_schema.columns c
        JOIN information_schema.tables t
          ON t.table_schema = c.table_schema
         AND t.table_name = c.table_name
         AND t.table_type = 'BASE TABLE'
        WHERE c.table_schema = 'public'
          AND c.udt_name IN ('varchar', 'text', 'bpchar', 'json', 'jsonb')
          AND c.is_generated = 'NEVER'
          AND c.is_updatable = 'YES'
          -- django_migrations is the migration history; never rewrite it.
          AND c.table_name <> 'django_migrations'
        ORDER BY c.table_name, c.column_name
    LOOP
        IF r.udt IN ('json', 'jsonb') THEN
            EXECUTE format(
                'UPDATE public.%I SET %I = pg_temp.fix_domain_json(%I::jsonb)::%s
                 WHERE %I::text LIKE ''%%example\_org%%''',
                r.tbl, r.col, r.col, r.udt, r.col);
        ELSE
            EXECUTE format(
                'UPDATE public.%I SET %I = pg_temp.fix_domain(%I)
                 WHERE %I LIKE ''%%example\_org%%''',
                r.tbl, r.col, r.col, r.col);
        END IF;
        GET DIAGNOSTICS updated = ROW_COUNT;
        cols := cols + 1;
        IF updated > 0 THEN
            total := total + updated;
            RAISE NOTICE '  %.%: % rows', r.tbl, r.col, updated;
        END IF;
    END LOOP;
    RAISE NOTICE '% columns checked, % rows rewritten', cols, total;
END $$;

-- Array-of-text columns are not reachable by the sweep above.
UPDATE public.logging_emaillog
SET emails = (SELECT array_agg(pg_temp.fix_domain(e)) FROM unnest(emails) AS e)
WHERE array_to_string(emails, ',') LIKE '%example\_org%';

COMMIT;
