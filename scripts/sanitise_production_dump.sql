-- Sanitise a restored production Waldur database so it can be used as local
-- test data.
--
-- DO NOT run this against production. It rewrites and deletes rows. It is
-- meant to be run against a THROWAWAY database that a production dump has
-- just been restored into. scripts/sanitise_production_dump.sh does that for
-- you and refuses to run against anything that looks like a live database.
--
-- WHAT IT GUARANTEES
--
--   1. Nothing deployment-specific survives: no URLs, no credentials, no
--      identity-provider configuration, no tokens, no sessions.
--   2. No personal data survives: every person becomes "Person NumberN" with
--      the address personN@example-orgM.com, where N counts individuals and M
--      counts distinct email domains, both in first-seen order.
--
-- Both are done by allowlist wherever a denylist would silently miss a column
-- added by a later Waldur release: the deployment config is reduced to a named
-- set of keys, and the verification script asserts on shape (every remaining
-- address matches personN@example-orgM.com) rather than on a list of things to
-- look for.
--
-- REFERENTIAL CONSISTENCY
--
-- One person maps to one identity everywhere they appear: core_user, their
-- OpenPortal shortname, their SLURM/FreeIPA/offering usernames, the invitation
-- that created them, and the rendered text of their event log. Accounting that
-- joins users to allocations by username still joins after sanitisation, which
-- is the point - the data has to stay usable.
--
-- The mapping tables hold original values while the rewrite runs and are
-- dropped inside the same transaction, so a dump taken afterwards cannot
-- contain them even if the process dies midway (the transaction rolls back).
--
-- IDEMPOTENCE
--
-- Re-running is safe: on the second pass every value already matches the
-- target shape, so the rewrites are no-ops. Every statement is guarded on the
-- table and columns actually existing, so this runs against both the
-- pre-resync production schema and the post-resync one.

\set ON_ERROR_STOP on

BEGIN;

-- ---------------------------------------------------------------------------
-- 0. Guard rails and helpers.
-- ---------------------------------------------------------------------------

DO $$
BEGIN
    IF current_database() NOT LIKE '%sanitise%'
       AND current_setting('waldur.sanitise_confirmed', true) IS DISTINCT FROM 'yes'
    THEN
        RAISE EXCEPTION
            'Refusing to run: database % is not named *sanitise* and '
            'waldur.sanitise_confirmed is not set. Run this through '
            'scripts/sanitise_production_dump.sh.', current_database();
    END IF;
END $$;

-- Every helper below is called as SELECT, which would print an empty row per
-- call. Discard those; notices and errors are unaffected, since they go to
-- stderr.
\o /dev/null

DROP SCHEMA IF EXISTS sanitise CASCADE;
CREATE SCHEMA sanitise;

CREATE FUNCTION sanitise.has_col(tbl text, col text)
RETURNS boolean LANGUAGE sql STABLE AS $$
    SELECT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_schema = 'public' AND table_name = tbl
                     AND column_name = col)
$$;

-- Is this value already one this script wrote? Every rewrite consults this
-- first, so that a second pass is a genuine no-op rather than pseudonymising
-- the pseudonyms. Getting this wrong is not cosmetic: an earlier version
-- turned "Person Number8" into "Person Number1 Number8" on a re-run, and
-- compounded it further on every run after that.
CREATE FUNCTION sanitise.is_pseudonym(val text)
RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
    SELECT val ~ '^Person Number[0-9]+$'
        OR val ~ '^person[0-9]+([._-][A-Za-z0-9._-]*)?$'
        OR val ~ '^person[0-9]+@example-org[0-9]+\.com$'
        OR val = 'Person'
        OR val ~ '^Number[0-9]+$'
        OR val = '198.51.100.1'
        OR val = 'Mozilla/5.0 (redacted)'
        OR val = 'https://example.com/redacted'
$$;

-- Replace whole words only.
--
-- The naive replace() is wrong for substituting a name into prose: a real
-- surname of three or four letters - May, Cook, Green - occurs inside ordinary
-- words, and "Maybe" would become "Person Number7be". Word boundaries are
-- added only at ends that actually start or end with a word character, since
-- \y next to punctuation would never match.
--
-- The needle is a literal, so its regex metacharacters are escaped; the
-- replacement's only special character in this position is a backslash.
CREATE FUNCTION sanitise.replace_word(hay text, needle text, sub text)
RETURNS text LANGUAGE sql IMMUTABLE AS $$
    SELECT CASE
        WHEN hay IS NULL OR needle IS NULL OR needle = '' THEN hay
        ELSE regexp_replace(
            hay,
            CASE WHEN needle ~ '^\w' THEN '\y' ELSE '' END
            || regexp_replace(needle, '([\\^$.|?*+()\[\]{}])', '\\\1', 'g')
            || CASE WHEN needle ~ '\w$' THEN '\y' ELSE '' END,
            regexp_replace(sub, '\\', '\\\\', 'g'),
            'g')
    END
$$;

-- Progress reporting.
--
-- Notices reach the client as they are raised rather than at commit, so these
-- appear live even though the whole script is one transaction. They go to
-- stderr, which is why the \o above does not silence them.
--
-- This matters because the JSON sweep is linear in row count and on a large
-- installation can run for hours; without output there is no way to tell a
-- long run from a stuck one.
CREATE FUNCTION sanitise.say(msg text)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    RAISE NOTICE '[%] %', to_char(clock_timestamp(), 'HH24:MI:SS'), msg;
END $$;

-- A duration as something readable at a glance: 42s, 7m11s, 2h13m.
CREATE FUNCTION sanitise.human(d interval)
RETURNS text LANGUAGE sql IMMUTABLE AS $$
    SELECT CASE
        WHEN d IS NULL THEN '?'
        WHEN extract(epoch FROM d) < 90
            THEN round(extract(epoch FROM d))::text || 's'
        WHEN extract(epoch FROM d) < 5400
            THEN floor(extract(epoch FROM d) / 60)::text || 'm'
                 || lpad(round(extract(epoch FROM d))::int % 60 || '', 2, '0')
                 || 's'
        ELSE floor(extract(epoch FROM d) / 3600)::text || 'h'
             || lpad(floor((extract(epoch FROM d) % 3600) / 60)::int || '',
                     2, '0') || 'm'
    END
$$;

-- Thousands separators, so a seven-figure row count is readable.
CREATE FUNCTION sanitise.commas(n bigint)
RETURNS text LANGUAGE sql IMMUTABLE AS $$
    SELECT to_char(n, 'FM999,999,999,999')
$$;

-- Run a statement only if the table and every named column exist. Waldur's
-- schema moves between releases and this script has to work either side of the
-- resync, so a missing column is a skip rather than an error.
CREATE FUNCTION sanitise.exec_if(tbl text, cols text[], stmt text)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    missing text;
BEGIN
    IF to_regclass('public.' || quote_ident(tbl)) IS NULL THEN
        RAISE NOTICE 'skip: no table %', tbl;
        RETURN;
    END IF;
    SELECT c INTO missing FROM unnest(cols) AS c
    WHERE NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = tbl AND column_name = c
    ) LIMIT 1;
    IF missing IS NOT NULL THEN
        RAISE NOTICE 'skip: no column %.%', tbl, missing;
        RETURN;
    END IF;
    EXECUTE stmt;
END $$;

-- Blank a column on every row of a table, if it is there.
--
-- The default is NULL, but plenty of Waldur's text and JSON columns are NOT
-- NULL with an empty-string or empty-object default, so a bare NULL would
-- violate the constraint. Rather than hand-specify an empty value at every
-- call site - and get it wrong on the one column that differs - look the
-- column up and pick an empty value for its type.
CREATE FUNCTION sanitise.blank(tbl text, col text, value text DEFAULT 'NULL')
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    nullable text;
    dtype text;
    udt text;
BEGIN
    IF value = 'NULL' THEN
        SELECT is_nullable, data_type, udt_name
        INTO nullable, dtype, udt
        FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = tbl
          AND column_name = col;
        IF nullable = 'NO' THEN
            value := CASE
                WHEN dtype = 'ARRAY' THEN '''{}'''
                WHEN udt IN ('json', 'jsonb') THEN '''{}'''
                WHEN udt = 'bytea' THEN ''''''''
                WHEN dtype IN ('character varying', 'text', 'character')
                    THEN ''''''
                ELSE NULL
            END;
            IF value IS NULL THEN
                RAISE NOTICE
                    'skip (%.% is NOT NULL and has no empty value for type %)',
                    tbl, col, coalesce(udt, dtype);
                RETURN;
            END IF;
        END IF;
    END IF;
    PERFORM sanitise.exec_if(tbl, ARRAY[col], format(
        'UPDATE public.%I SET %I = %s WHERE %I IS NOT NULL',
        tbl, col, value, col));
END $$;

-- Empty a table, if it is there. Used for telemetry and credential tables
-- whose contents are of no value to a test database.
CREATE FUNCTION sanitise.wipe(tbl text)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    IF to_regclass('public.' || quote_ident(tbl)) IS NULL THEN
        RAISE NOTICE 'skip (no table %)', tbl;
        RETURN;
    END IF;
    EXECUTE format('DELETE FROM public.%I', tbl);
END $$;

-- Filler of the same length as the original, so a description that filled a
-- panel still fills it. Preserves shape without preserving content.
--
-- JSON-aware, and that is not a nicety. Waldur has a text-backed JSONField
-- (waldur_core.core.fields.JSONField) whose columns are `text` in the database
-- and JSON to the ORM - structure_project.termination_metadata is one. Writing
-- prose into one of those makes EVERY read of the row fail:
--
--   django.core.exceptions.ValidationError: ['Enter valid JSON']
--
-- which surfaces as a 500 on the projects list, looking for all the world like
-- a bug in the code under test. Choosing columns by name cannot tell prose
-- from JSON-in-a-text-column, so the value itself decides: anything parsing as
-- a JSON object or array becomes an empty one of the same kind, and only
-- genuine prose gets prose.
CREATE FUNCTION sanitise.filler(original text)
RETURNS text LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
    parsed jsonb;
BEGIN
    IF original IS NULL OR original = '' THEN
        RETURN original;
    END IF;

    IF left(btrim(original), 1) IN ('{', '[') THEN
        BEGIN
            parsed := original::jsonb;
        EXCEPTION WHEN others THEN
            parsed := NULL;
        END;
        IF parsed IS NOT NULL THEN
            RETURN CASE jsonb_typeof(parsed) WHEN 'array' THEN '[]'
                                             ELSE '{}' END;
        END IF;
    END IF;

    RETURN left(
        repeat('redacted placeholder text ', (length(original) / 26) + 1),
        length(original));
END $$;


-- ---------------------------------------------------------------------------
-- 1. Build the identity map.
--
-- Person numbers come from core_user.id order, so Person Number1 is the
-- oldest account and the numbering is stable across re-runs of the whole
-- pipeline against the same dump.
--
-- Individuals who never became users - an invitation to someone who never
-- accepted, a service-account contact address - are counted after the users,
-- ordered by address, so they get stable numbers too.
-- ---------------------------------------------------------------------------

SELECT sanitise.say('Building the identity map from core_user');

CREATE TABLE sanitise.person (
    n            int PRIMARY KEY,
    user_id      int,
    user_uuid    text,
    orig_email   text,
    new_name     text,
    new_username text
);

-- btrim as well as lower, because map_email() btrims its lookup key: an
-- address stored with a stray leading space would otherwise be harvested in
-- one form and looked up in another, and quietly land on the sink.
INSERT INTO sanitise.person (n, user_id, user_uuid, orig_email)
SELECT row_number() OVER (ORDER BY id), id, uuid::text,
       lower(btrim(nullif(btrim(email), '')))
FROM public.core_user;

-- Every address anywhere in the database, so that domains are numbered across
-- the whole dataset and not just across registered users.
CREATE TABLE sanitise.found_email (email text);

DO $$
DECLARE
    spec text;
BEGIN
    FOREACH spec IN ARRAY ARRAY[
        'core_user.email',
        'core_changeemailrequest.email',
        'users_invitation.email',
        'structure_customer.email',
        'structure_affiliatedorganization.email',
        'marketplace_serviceprovider.lead_email',
        'marketplace_courseaccount.email',
        'marketplace_customerserviceaccount.email',
        'marketplace_projectserviceaccount.email',
        'proposal_callreviewerpool.invited_email',
        'logging_emailhook.email',
        'support_providerhelpdesk.notification_email',
        'waldur_rancher_keycloakusergroupmembership.email'
    ] LOOP
        PERFORM sanitise.exec_if(
            split_part(spec, '.', 1), ARRAY[split_part(spec, '.', 2)],
            format('INSERT INTO sanitise.found_email
                    SELECT lower(btrim(%I)) FROM public.%I
                    WHERE %I IS NOT NULL AND btrim(%I) <> %L',
                   split_part(spec, '.', 2), split_part(spec, '.', 1),
                   split_part(spec, '.', 2), split_part(spec, '.', 2), ''));
    END LOOP;
END $$;

-- Multi-valued address columns: a text[], a jsonb array, and a comma or
-- newline separated string.
SELECT sanitise.exec_if('logging_emaillog', ARRAY['emails'],
    $$INSERT INTO sanitise.found_email
      SELECT lower(btrim(e)) FROM public.logging_emaillog, unnest(emails) AS e
      WHERE btrim(e) <> ''$$);

SELECT sanitise.exec_if('notifications_broadcastmessage', ARRAY['emails'],
    $$INSERT INTO sanitise.found_email
      SELECT lower(btrim(e)) FROM public.notifications_broadcastmessage,
             jsonb_array_elements_text(
                 CASE WHEN jsonb_typeof(emails) = 'array' THEN emails
                      ELSE '[]'::jsonb END) AS e
      WHERE btrim(e) <> ''$$);

SELECT sanitise.exec_if('structure_customer', ARRAY['notification_emails'],
    $$INSERT INTO sanitise.found_email
      SELECT lower(btrim(e)) FROM public.structure_customer,
             regexp_split_to_table(notification_emails, '[,;\s]+') AS e
      WHERE btrim(e) <> ''$$);

-- Anything that reached found_email without an @ is not an address; drop it
-- rather than inventing a domain for it.
DELETE FROM sanitise.found_email WHERE email IS NULL OR email NOT LIKE '%@%';

-- Addresses belonging to nobody in core_user become extra people.
INSERT INTO sanitise.person (n, orig_email)
SELECT (SELECT coalesce(max(n), 0) FROM sanitise.person)
           + row_number() OVER (ORDER BY f.email),
       f.email
FROM (SELECT DISTINCT email FROM sanitise.found_email) f
WHERE NOT EXISTS (
    SELECT 1 FROM sanitise.person p WHERE p.orig_email = f.email
);

UPDATE sanitise.person
SET new_name = 'Person Number' || n,
    new_username = 'person' || n;

-- Domains, numbered in first-seen order: the domain of Person Number1 is
-- example-org1, and a domain first seen on Person Number9 gets whatever number
-- is next. This reproduces the requested shape - person1@example-org1.com,
-- person2@example-org2.com, person3@example-org1.com - where the third person
-- shares the first person's domain.
--
-- THE HYPHEN IS LOAD-BEARING. It was originally example_org1.com, and an
-- underscore is not legal in a DNS label, so those addresses were not valid
-- email addresses at all. Anything that VALIDATES rather than merely stores
-- one then failed on the sanitised copy - Django's own validate_email rejects
-- example_org1.com - and the failures surfaced far from the cause:
--
--   OSError: Parse("Domain label 'example_org27' contains invalid characters
--   (only letters, digits, and hyphens allowed) at line 1 column 2852")
--
-- raised by openportal parsing an AwardDetails document with an address
-- inside it, which
-- /api/openportal-managed-project-accounting-summary/ catches and reports as
-- a null allocation and zero usage - a plausible-looking accounting bug with
-- no accounting cause. A hyphen parses everywhere and keeps the numbering
-- scheme exactly.
CREATE TABLE sanitise.domain (
    orig_domain text PRIMARY KEY,
    m           int NOT NULL
);

INSERT INTO sanitise.domain (orig_domain, m)
SELECT orig_domain, row_number() OVER (ORDER BY first_seen, orig_domain)
FROM (
    SELECT split_part(orig_email, '@', 2) AS orig_domain, min(n) AS first_seen
    FROM sanitise.person
    WHERE orig_email LIKE '%@%'
    GROUP BY 1
) d;

CREATE TABLE sanitise.email_map (
    orig_email text PRIMARY KEY,
    new_email  text NOT NULL
);

-- One row per DISTINCT address, not one per person: core_user.email carries no
-- unique constraint, and a real installation has people with two accounts on
-- one address, or one account left over from a rename.
--
-- Both of those accounts keep their own name and login - Person Number5 and
-- Person Number9, person5 and person9, which they must, because
-- core_user.username IS unique - but they keep SHARING an address, the lower
-- person number naming it. Giving them separate addresses would be tidier and
-- would quietly destroy a property of the data worth testing against:
-- OIDC_MATCHMAKING_BY_EMAIL exists precisely to decide what to do when two
-- accounts share an address.
-- LEFT JOIN, not JOIN: a stored address with nothing after the @, or no @ at
-- all, has no domain to number. Those still need a pseudonym - dropping them
-- here would send them to the sink and make the verifier's count of genuinely
-- unharvested addresses useless - so they get domain zero.
INSERT INTO sanitise.email_map (orig_email, new_email)
SELECT DISTINCT ON (p.orig_email)
       p.orig_email,
       'person' || p.n || '@example-org' || coalesce(d.m, 0) || '.com'
FROM sanitise.person p
LEFT JOIN sanitise.domain d
       ON d.orig_domain = split_part(p.orig_email, '@', 2)
WHERE p.orig_email IS NOT NULL
ORDER BY p.orig_email, p.n;

DO $$
DECLARE
    shared int;
BEGIN
    SELECT count(*) INTO shared FROM (
        SELECT orig_email FROM sanitise.person
        WHERE orig_email IS NOT NULL
        GROUP BY orig_email HAVING count(*) > 1
    ) dupes;
    IF shared > 0 THEN
        PERFORM sanitise.say(format(
            '  %s addresses are shared by more than one account; each keeps'
            || ' its own name and login and they go on sharing an address',
            shared));
    END IF;
END $$;

CREATE INDEX ON sanitise.email_map (orig_email);

CREATE FUNCTION sanitise.map_email(addr text)
RETURNS text LANGUAGE sql STABLE AS $$
    SELECT coalesce(
        -- Already mapped: return it unchanged, or a second pass would fold it
        -- onto the sink. This is what makes the whole script idempotent.
        CASE WHEN addr ~ '^person[0-9]+@example-org[0-9]+\.com$'
             THEN addr END,
        (SELECT new_email FROM sanitise.email_map
         WHERE orig_email = lower(btrim(addr))),
        -- An address that reached a column this script does not harvest from.
        -- Rather than leave it, fold it onto a sink that still satisfies the
        -- verification shape; the verifier's count of sink addresses says how
        -- often this happened.
        CASE WHEN addr IS NULL OR addr = '' THEN addr
             ELSE 'person0@example-org0.com' END
    )
$$;

-- ---------------------------------------------------------------------------
-- 2. The login-name map.
--
-- A person carries several login names: core_user.username (from the identity
-- provider), core_user.slug and the OpenPortal shortname (the HPC account
-- name), the FreeIPA profile, and one per offering. They are stored as bare
-- strings in a dozen tables with no foreign key back to the user, so every one
-- of a person's names must map to the same personN or those tables stop
-- joining.
-- ---------------------------------------------------------------------------

SELECT sanitise.say('Building the login-name map');

CREATE TABLE sanitise.token_map (
    orig  text PRIMARY KEY,
    new   text NOT NULL
);

-- Resolve one account identifier, or NULL when it is not one.
--
-- Two forms have to resolve. A bare login name - "jsmith", or "john.smith"
-- where that is literally the login - matches the map outright. A COMPOUND
-- identifier does not: OpenPortal and SLURM build account names by joining the
-- login to the project and the system, so the same person appears as
-- "jsmith.someproject" in one column and "jsmith.someproject.somecluster" in
-- the next, and as a "jsmith.someproject.somecluster" KEY inside a cached
-- usage report. Mapping only whole values renames the login column and leaves
-- those, which both leaks the login and breaks every join that goes through
-- it.
--
-- So: try the whole value first, which is what makes a dotted login map to a
-- single pseudonym rather than being split, and only then try the leading
-- segment and keep the rest of the string.
CREATE FUNCTION sanitise.map_identifier(val text)
RETURNS text LANGUAGE plpgsql STABLE AS $$
DECLARE
    hit text;
    delim text;
    head text;
BEGIN
    IF val IS NULL OR val = '' THEN
        RETURN NULL;
    END IF;
    -- Already mapped, in either form.
    IF val ~ '^person[0-9]+([._-]|$)' THEN
        RETURN val;
    END IF;

    SELECT new INTO hit FROM sanitise.token_map WHERE orig = val;
    IF hit IS NOT NULL THEN
        RETURN hit;
    END IF;

    FOREACH delim IN ARRAY ARRAY['.', '_', '-'] LOOP
        head := split_part(val, delim, 1);
        IF head <> val AND head <> '' THEN
            SELECT new INTO hit FROM sanitise.token_map WHERE orig = head;
            IF hit IS NOT NULL THEN
                RETURN hit || substr(val, length(head) + 1);
            END IF;
        END IF;
    END LOOP;

    RETURN NULL;
END $$;

-- As above, but for a column that is known to hold an account name, so an
-- unrecognised value is still an account name and must not be left as it is.
CREATE FUNCTION sanitise.map_token(tok text)
RETURNS text LANGUAGE sql STABLE AS $$
    SELECT coalesce(
        sanitise.map_identifier(tok),
        CASE WHEN tok IS NULL OR tok = '' THEN tok ELSE 'person0' END)
$$;

-- Names we can attribute to a person, from whichever of core_user's login-name
-- columns this installation has: username is always there, slug and
-- unix_username depend on the release.
DO $$
DECLARE
    cols text[] := ARRAY[]::text[];
    col text;
BEGIN
    FOREACH col IN ARRAY ARRAY['username', 'slug', 'unix_username'] LOOP
        IF sanitise.has_col('core_user', col) THEN
            cols := cols || format('(nullif(u.%I, %L))', col, '');
        END IF;
    END LOOP;

    EXECUTE format($q$
        INSERT INTO sanitise.token_map (orig, new)
        SELECT DISTINCT ON (t.orig) t.orig, p.new_username
        FROM sanitise.person p
        JOIN public.core_user u ON u.id = p.user_id
        CROSS JOIN LATERAL (VALUES %s) AS t(orig)
        WHERE t.orig IS NOT NULL
        ORDER BY t.orig, p.n
    $q$, array_to_string(cols, ', '));
END $$;

DO $$
BEGIN
    PERFORM sanitise.exec_if('waldur_openportal_userinfo',
        ARRAY['shortname', 'user_id'],
        $q$INSERT INTO sanitise.token_map (orig, new)
           SELECT DISTINCT ON (i.shortname) i.shortname, p.new_username
           FROM public.waldur_openportal_userinfo i
           JOIN sanitise.person p ON p.user_id = i.user_id
           WHERE nullif(i.shortname, '') IS NOT NULL
             AND NOT EXISTS (SELECT 1 FROM sanitise.token_map m
                             WHERE m.orig = i.shortname)
           ORDER BY i.shortname, p.n$q$);

    PERFORM sanitise.exec_if('marketplace_offeringuser',
        ARRAY['username', 'user_id'],
        $q$INSERT INTO sanitise.token_map (orig, new)
           SELECT DISTINCT ON (o.username) o.username, p.new_username
           FROM public.marketplace_offeringuser o
           JOIN sanitise.person p ON p.user_id = o.user_id
           WHERE nullif(o.username, '') IS NOT NULL
             AND NOT EXISTS (SELECT 1 FROM sanitise.token_map m
                             WHERE m.orig = o.username)
           ORDER BY o.username, p.n$q$);

    PERFORM sanitise.exec_if('waldur_freeipa_profile',
        ARRAY['username', 'user_id'],
        $q$INSERT INTO sanitise.token_map (orig, new)
           SELECT DISTINCT ON (f.username) f.username, p.new_username
           FROM public.waldur_freeipa_profile f
           JOIN sanitise.person p ON p.user_id = f.user_id
           WHERE nullif(f.username, '') IS NOT NULL
             AND NOT EXISTS (SELECT 1 FROM sanitise.token_map m
                             WHERE m.orig = f.username)
           ORDER BY f.username, p.n$q$);
END $$;

-- Names we cannot attribute to anyone: an HPC account whose Waldur user was
-- deleted, a name only ever seen in an accounting feed. They still identify a
-- person, so they get their own numbers, continuing after the people above.
CREATE TABLE sanitise.found_token (token text);

DO $$
DECLARE
    spec text;
BEGIN
    FOREACH spec IN ARRAY ARRAY[
        'marketplace_offeringuser.username',
        'marketplace_componentuserusage.username',
        'marketplace_customerserviceaccount.username',
        'marketplace_projectserviceaccount.username',
        'waldur_openportal_association.username',
        'waldur_openportal_allocationuserusage.username',
        'waldur_slurm_association.username',
        'waldur_slurm_allocationuserusage.username',
        'waldur_freeipa_profile.username',
        'waldur_rancher_keycloakusergroupmembership.username'
    ] LOOP
        PERFORM sanitise.exec_if(
            split_part(spec, '.', 1), ARRAY[split_part(spec, '.', 2)],
            format('INSERT INTO sanitise.found_token
                    SELECT DISTINCT %I FROM public.%I
                    WHERE nullif(%I, %L) IS NOT NULL',
                   split_part(spec, '.', 2), split_part(spec, '.', 1),
                   split_part(spec, '.', 2), ''));
    END LOOP;
END $$;

-- map_identifier is defined below and resolves a compound name from its
-- leading segment, so a value like "jsmith.someproject" is already covered by
-- jsmith's entry and must NOT be counted as another person - doing so would
-- collapse the project part of the name and break the joins that use it.
INSERT INTO sanitise.token_map (orig, new)
SELECT t.token,
       'person' || ((SELECT coalesce(max(n), 0) FROM sanitise.person)
                    + row_number() OVER (ORDER BY t.token))
FROM (SELECT DISTINCT token FROM sanitise.found_token) t
WHERE sanitise.map_identifier(t.token) IS NULL;

-- ---------------------------------------------------------------------------
-- 3. The written-name map, for substitution inside free text.
-- ---------------------------------------------------------------------------

SELECT sanitise.say('Building the written-name map');

UPDATE sanitise.person p
SET user_uuid = u.uuid::text
FROM public.core_user u WHERE u.id = p.user_id AND p.user_uuid IS NULL;

CREATE TABLE sanitise.name_map (
    orig text PRIMARY KEY,
    new  text NOT NULL
);

-- Long strings first: replacing "Ada Lovelace" before "Ada" avoids leaving a
-- surname stranded next to a pseudonym.
--
-- Built dynamically for the same reason as the login-name map: native_name is
-- Waldur's own column and not every release has it.
DO $$
DECLARE
    parts text[] := ARRAY[
        $q$(nullif(btrim(u.first_name || ' ' || u.last_name), ''))$q$,
        $q$(nullif(btrim(u.last_name || ' ' || u.first_name), ''))$q$,
        $q$(nullif(btrim(split_part(btrim(u.first_name), ' ', 1)
                         || ' ' || u.last_name), ''))$q$,
        $q$(nullif(btrim(u.last_name || ' '
                         || split_part(btrim(u.first_name), ' ', 1)), ''))$q$,
        $q$(nullif(btrim(u.last_name || ', ' || u.first_name), ''))$q$,
        $q$(nullif(btrim(u.first_name), ''))$q$,
        $q$(nullif(btrim(u.last_name), ''))$q$
    ];
BEGIN
    IF sanitise.has_col('core_user', 'native_name') THEN
        parts := array_append(parts,
            $q$(nullif(btrim(u.native_name), ''))$q$);
    END IF;

    EXECUTE format($q$
        INSERT INTO sanitise.name_map (orig, new)
        SELECT DISTINCT ON (t.orig) t.orig, p.new_name
        FROM sanitise.person p
        JOIN public.core_user u ON u.id = p.user_id
        CROSS JOIN LATERAL (
            -- Not only first_name || ' ' || last_name: a display name
            -- assembled elsewhere often uses just the first given name, so
            -- "Christopher John" and "Woods" also have to combine as
            -- "Christopher Woods". Both orders, because some backends render
            -- surname first.
            VALUES %s
        ) AS t(orig)
        WHERE t.orig IS NOT NULL AND length(t.orig) >= 3
          -- Skip users this script has already pseudonymised, at the ROW
          -- level rather than by filtering the candidates. On a re-run
          -- core_user holds first_name 'Person' and last_name 'NumberN', and
          -- the combinations above then include the reversed 'Number8
          -- Person', which the substitution pass would find inside
          -- "...Person Number8 Person Number13..." and rewrite - compounding
          -- further on every run after that. Filtering candidate strings
          -- means enumerating every form the VALUES list can produce and
          -- missing one; this says the thing actually meant, which is that an
          -- already-pseudonymised account contributes no names at all.
          AND NOT (u.first_name = 'Person' AND u.last_name ~ '^Number[0-9]+$')
          AND NOT sanitise.is_pseudonym(t.orig)
        ORDER BY t.orig, p.n
    $q$, array_to_string(parts, ', '));
END $$;

CREATE INDEX ON sanitise.name_map (length(orig) DESC);

-- ---------------------------------------------------------------------------
-- 3b. Generic scrubbers.
--
-- The columns this script names by hand are the ones that hold a person's
-- details as a field. They are not where the leaks are: an extension that
-- posts a project definition to a remote service keeps whole member lists as
-- JSON, and an audit trail of those posts keeps two copies of each. Naming
-- those columns one by one is exactly the losing game the rest of this script
-- avoids, so instead every JSON and text column in the database is walked.
--
-- The JSON walk maps a string leaf when the whole leaf is recognisable - an
-- address, a login name, a person's name - and leaves anything else alone. It
-- deliberately does not guess from key names, because "name" on a project
-- object is the project's name.
-- ---------------------------------------------------------------------------

-- Replace every address occurrence in a string, consistently with everywhere
-- else the same address appears.
-- Is this URL one that may stay? A public standards or documentation host, or
-- something local. Everything else names a host of this deployment's - the
-- portal, the helpdesk, whatever an integration was pointed at.
--
-- Its own function because scrub_leaf and scrub_urls both need the decision,
-- and having one ask the other made them mutually recursive: an allowlisted
-- URL fell past scrub_leaf's early return, into scrub_urls, which asked
-- scrub_leaf again, forever.
--
-- The list mirrors the one in scripts/sanitise_production_dump.sh; keep them
-- in step.
CREATE FUNCTION sanitise.is_local_url(val text)
RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
    SELECT val ~* ('^https?://([^/]*\.)?('
        || 'localhost|127\.0\.0\.1|example\.com|example\.org|example\.net'
        || '|w3\.org|schema\.org|json-schema\.org|creativecommons\.org'
        || '|opensource\.org|github\.com|waldur\.com)([:/]|$)')
$$;

-- Replace every deployment URL occurrence in a string.
CREATE FUNCTION sanitise.scrub_urls(val text)
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
        IF NOT sanitise.is_local_url(m) THEN
            val := replace(val, m, 'https://example.com/redacted');
        END IF;
    END LOOP;
    RETURN val;
END $$;

CREATE FUNCTION sanitise.scrub_emails(val text)
RETURNS text LANGUAGE plpgsql STABLE AS $$
DECLARE
    m text;
BEGIN
    IF val IS NULL OR position('@' IN val) = 0 THEN
        RETURN val;
    END IF;
    FOR m IN
        SELECT DISTINCT match[1]
        FROM regexp_matches(val,
            '([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})', 'g') AS match
        ORDER BY 1
    LOOP
        val := replace(val, m, sanitise.map_email(m));
    END LOOP;
    RETURN val;
END $$;

-- One string leaf of a JSON document.
CREATE FUNCTION sanitise.scrub_leaf(k text, val text)
RETURNS text LANGUAGE plpgsql STABLE AS $$
DECLARE
    mapped text;
    nested jsonb;
    brace int;
BEGIN
    IF val IS NULL OR val = '' OR sanitise.is_pseudonym(val) THEN
        RETURN val;
    END IF;

    -- A leaf that CONTAINS a JSON document. OpenPortal's job payloads keep a
    -- whole nested document inside a string, sometimes behind a command
    -- prefix - "somecluster update_project someproject {...}" - so the
    -- addresses, login names and note authors inside it are two levels down
    -- and a single-level walk sees only an opaque blob. Recurse into the
    -- document, keep whatever came before it, and re-serialise.
    --
    -- Recursion is unbounded on purpose: a payload can nest again.
    brace := position('{' IN val);
    IF brace = 0 THEN
        brace := position('[' IN val);
    END IF;
    IF brace > 0 AND length(val) - brace > 1 THEN
        BEGIN
            nested := substr(val, brace)::jsonb;
        EXCEPTION WHEN others THEN
            nested := NULL;
        END;
        IF nested IS NOT NULL
           AND jsonb_typeof(nested) IN ('object', 'array') THEN
            RETURN sanitise.scrub_leaf(k, left(val, brace - 1))
                   || sanitise.scrub_json(nested)::text;
        END IF;
    END IF;

    IF position('@' IN val) > 0 THEN
        val := sanitise.scrub_emails(val);
    END IF;

    -- A URL mentioned INSIDE a longer string. The check above is anchored, so
    -- it only catches a leaf that is nothing but a URL; a note field reading
    -- "See https://portal.example.ac.uk/awards/1 for detail" went straight
    -- through it. Plain text columns were covered by the sweep's scrub_urls
    -- and JSON leaves were not, which is a gap the output scan found on a
    -- production dump and no test had.
    IF position('http' IN val) > 0 THEN
        val := sanitise.scrub_urls(val);
    END IF;

    -- A leaf that IS a login name or a person's name, rather than one that
    -- mentions one. Whole-value matching keeps member lists joinable while
    -- leaving project and offering names intact.
    mapped := sanitise.map_identifier(val);
    IF mapped IS NULL THEN
        -- Multi-token names only. A single-token entry is a bare first or last
        -- name, and matching a whole JSON leaf against those is how a robot
        -- account called "OpenPortal Robot" turned every
        -- "service_settings_type": "OpenPortal" into a person's pseudonym.
        -- Bare names stay available to the prose substitution, where they
        -- legitimately appear mid-sentence.
        mapped := (SELECT new FROM sanitise.name_map
                   WHERE orig = val AND orig LIKE '% %');
    END IF;
    IF mapped IS NOT NULL THEN
        RETURN mapped;
    END IF;

    -- A URL naming a host of this deployment's - the portal itself, the
    -- helpdesk, whatever an integration was pointed at. Kept as a URL so the
    -- UI still renders a link, pointing nowhere. The host allowlist mirrors
    -- the one in scripts/sanitise_production_dump.sh; keep them in step.
    IF val ~ '^https?://' AND NOT sanitise.is_local_url(val) THEN
        RETURN 'https://example.com/redacted';
    END IF;

    -- A key that can only name a person, holding something the maps did not
    -- recognise: a display name assembled somewhere else, a name typed by
    -- hand. It is still a person, so it does not survive just because it was
    -- not recognised.
    IF k IS NOT NULL
       AND k ~* '(^|_)(author|owner|reviewer|approver|manager|contact)$'
       OR k ~* '_by$' THEN
        IF val ~ '[A-Za-z]' AND val !~ '^https?://'
           AND NOT sanitise.is_pseudonym(val) THEN
            RETURN 'Person Number0';
        END IF;
    END IF;

    -- Keys that can only hold a personal attribute, whatever the value.
    IF k IS NOT NULL AND k ~*
        '(^|_)(phone|phone_number|civil_number|birth_date|postcode|national_id)$'
    THEN
        RETURN '';
    END IF;

    RETURN val;
END $$;

CREATE FUNCTION sanitise.scrub_json(j jsonb, k text DEFAULT NULL)
RETURNS jsonb LANGUAGE plpgsql STABLE AS $$
DECLARE
    out_obj jsonb;
    child_key text;
    child jsonb;
BEGIN
    IF j IS NULL THEN
        RETURN j;
    END IF;
    CASE jsonb_typeof(j)
        WHEN 'object' THEN
            out_obj := '{}'::jsonb;
            FOR child_key, child IN SELECT key, value FROM jsonb_each(j) LOOP
                -- Keys are scrubbed as well as values. OpenPortal keeps a
                -- project's membership as {address: role}, so the addresses
                -- are the object's KEYS - a walk that only rewrites values
                -- leaves every one of them in place. This was found by the
                -- output scan in scripts/sanitise_production_dump.sh, which
                -- is why that scan exists.
                out_obj := out_obj || jsonb_build_object(
                    sanitise.scrub_leaf(NULL, child_key),
                    sanitise.scrub_json(child, child_key));
            END LOOP;
            RETURN out_obj;
        WHEN 'array' THEN
            RETURN coalesce((
                SELECT jsonb_agg(sanitise.scrub_json(e, k) ORDER BY ord)
                FROM jsonb_array_elements(j) WITH ORDINALITY AS a(e, ord)
            ), '[]'::jsonb);
        WHEN 'string' THEN
            RETURN to_jsonb(sanitise.scrub_leaf(k, j #>> '{}'));
        ELSE
            RETURN j;
    END CASE;
END $$;

-- A text column that holds a JSON document rather than prose. Parsed and
-- walked when it parses, left to the address pass when it does not.
CREATE FUNCTION sanitise.scrub_json_text(val text)
RETURNS text LANGUAGE plpgsql STABLE AS $$
DECLARE
    parsed jsonb;
BEGIN
    IF val IS NULL OR val = '' THEN
        RETURN val;
    END IF;
    BEGIN
        parsed := val::jsonb;
    EXCEPTION WHEN others THEN
        RETURN sanitise.scrub_emails(val);
    END;
    RETURN sanitise.scrub_json(parsed)::text;
END $$;

-- ---------------------------------------------------------------------------
-- 4. Deployment configuration.
--
-- Constance keeps this deployment's settings in the database, which is why a
-- restored production dump points a local instance at the production homeport,
-- the production helpdesk and the production identity provider.
--
-- Rather than list the keys to remove - a list that goes stale the moment
-- upstream adds a setting - keep a named set of keys that only affect how data
-- is presented, and delete the rest. Deleted keys fall back to the defaults in
-- CONSTANCE_CONFIG, which are the local deployment's own settings. Add to this
-- list if a local instance needs something else; never add a key that holds a
-- URL, a host, an address or a credential.
-- ---------------------------------------------------------------------------

SELECT sanitise.say('Removing deployment configuration and credentials');

SELECT sanitise.exec_if('constance_constance', ARRAY['key'], $$
    DELETE FROM public.constance_constance
    WHERE key NOT IN (
        -- presentation
        'BRAND_COLOR', 'SIDEBAR_STYLE', 'SHORT_PAGE_TITLE', 'FULL_PAGE_TITLE',
        'SITE_NAME', 'SITE_DESCRIPTION',
        -- COMMON_FOOTER_TEXT and COMMON_FOOTER_HTML are deliberately not here:
        -- a footer almost always carries a contact address or a link.
        'CURRENCY_NAME', 'LANGUAGE_CHOICES', 'COUNTRIES',
        -- behaviour that changes how existing data renders or validates
        'PROJECT_END_DATE_MANDATORY', 'ENABLE_ORDER_START_DATE',
        'MANDATORY_USER_ATTRIBUTES', 'ENFORCE_MANDATORY_USER_ATTRIBUTES',
        'DEFAULT_CALL_USER_ATTRIBUTES', 'ENFORCE_USER_CONSENT_FOR_OFFERINGS',
        'AFFILIATION_REQUIRED_AT_PROJECT_CREATION', 'AFFILIATES_ENABLED',
        'ANONYMOUS_USER_CAN_VIEW_OFFERINGS', 'DEACTIVATE_USER_IF_NO_ROLES',
        'FREEIPA_ENABLED', 'PROPOSAL_REVIEW_DURATION',
        'NOTIFY_ABOUT_RESOURCE_CHANGE', 'ENABLE_STALE_RESOURCE_NOTIFICATIONS',
        'DISABLE_SENDING_NOTIFICATIONS_ABOUT_RESOURCE_UPDATE',
        'SYSTEM_LOG_ENABLED', 'USER_DATA_ACCESS_LOGGING_ENABLED',
        'OIDC_MATCHMAKING_BY_EMAIL', 'SCIM_MEMBERSHIP_SYNC_ENABLED',
        'WALDUR_SUPPORT_ENABLED', 'WALDUR_SUPPORT_DISPLAY_REQUEST_TYPE',
        'WALDUR_SUPPORT_PROVIDER_ROUTING_ENABLED',
        'SITE_AGENT_LOG_MAX_ROWS_PER_IDENTITY', 'CHECK_FOR_UPDATES'
    )
$$);

-- Identity providers: client secrets, and every endpoint of the production
-- keycloak realm. A local instance configures its own.
SELECT sanitise.wipe('waldur_auth_social_identityprovider');
SELECT sanitise.wipe('waldur_auth_social_oauthtoken');
SELECT sanitise.wipe('waldur_auth_saml2_identityprovider');

-- Everything that is a live credential, a session, or telemetry about who
-- logged in from where. None of it has any value in a test database.
SELECT sanitise.wipe('django_session');
SELECT sanitise.wipe('authtoken_token');
SELECT sanitise.wipe('core_personalaccesstoken');
SELECT sanitise.wipe('core_tokenexchangecode');
SELECT sanitise.wipe('passkeys_passkeyverifiedsession');
SELECT sanitise.wipe('passkeys_passkeycredential');
SELECT sanitise.wipe('google_googlecredentials');
SELECT sanitise.wipe('matrix_chat_matrixuserprofile');
SELECT sanitise.wipe('axes_accessattempt');
SELECT sanitise.wipe('axes_accessfailurelog');
SELECT sanitise.wipe('axes_accesslog');
SELECT sanitise.wipe('logging_userdataaccesslog');
SELECT sanitise.wipe('logging_webhook');
SELECT sanitise.wipe('logging_eventconsumer');
SELECT sanitise.wipe('waldur_auth_valimo_authresult');
SELECT sanitise.wipe('waldur_arrow_arrowsettings');
SELECT sanitise.wipe('marketplace_remote_remotesynchronisation');

-- Chat holds whole conversations, which are free text written by users.
SELECT sanitise.wipe('chat_message');
SELECT sanitise.wipe('chat_threadsession');
SELECT sanitise.wipe('chat_sessionbinding');
SELECT sanitise.wipe('chat_anonymouschatfeedback');
SELECT sanitise.wipe('chat_anonymouschatinteraction');
SELECT sanitise.wipe('chat_anonymouschatbudget');
SELECT sanitise.wipe('chat_globalassistantbudget');

-- django-reversion stores serialised snapshots of earlier versions of objects,
-- which is a complete copy of the pre-sanitisation names and addresses. There
-- is no way to rewrite it reliably, so it goes.
SELECT sanitise.wipe('reversion_version');
SELECT sanitise.wipe('reversion_revision');

-- Service settings and offering secrets: backend URLs, passwords, tokens,
-- certificates and the encrypted options blob. Encrypted with this
-- deployment's key, so they would not decrypt locally in any case.
SELECT sanitise.blank('structure_servicesettings', 'password');
SELECT sanitise.blank('structure_servicesettings', 'token');
SELECT sanitise.blank('structure_servicesettings', 'certificate');
SELECT sanitise.blank('structure_servicesettings', 'username');
SELECT sanitise.blank('structure_servicesettings', 'backend_url');
SELECT sanitise.blank('structure_servicesettings', 'domain');
-- NOT blanked wholesale. structure_servicesettings.options mixes credentials
-- with plain configuration, and emptying it takes out both: OpenPortal reads
-- instance_name, project_template and the allocation settings from here, so a
-- copy with an empty options column fails every sync task with "Instance name
-- cannot be None" - an error that looks like a bug in the resync and is not.
--
-- Only secret-shaped keys are removed. URLs and addresses inside the
-- remaining keys are still caught by the JSON sweep further down, so this is
-- narrower than it looks.
--
-- The residual risk is a real credential stored under a key whose name does
-- not say so. The separate password, token and certificate columns are
-- blanked outright, so anything here is already a second home for one.
CREATE FUNCTION sanitise.scrub_options(val text)
RETURNS text LANGUAGE plpgsql STABLE AS $$
DECLARE
    parsed jsonb;
BEGIN
    IF val IS NULL OR btrim(val) = '' THEN
        RETURN val;
    END IF;
    BEGIN
        parsed := val::jsonb;
    EXCEPTION WHEN others THEN
        -- Not JSON. Either an EncryptedOptionsField value from an installation
        -- that has applied structure/0081, or something unexpected. Either way
        -- it cannot be inspected, so it is treated as an opaque secret.
        RETURN '{}';
    END;
    IF jsonb_typeof(parsed) <> 'object' THEN
        RETURN '{}';
    END IF;
    RETURN coalesce((
        SELECT jsonb_object_agg(
            key,
            CASE WHEN key ~* ('(password|passwd|secret|token|api_?key'
                              || '|credential|passphrase|private|cert)')
                 THEN '""'::jsonb
                 ELSE value END)
        FROM jsonb_each(parsed)
    ), '{}'::jsonb)::text;
END $$;

SELECT sanitise.exec_if('structure_servicesettings', ARRAY['options'],
    $$UPDATE public.structure_servicesettings
      SET options = sanitise.scrub_options(options)
      WHERE nullif(btrim(options), '') IS NOT NULL$$);

SELECT sanitise.blank('marketplace_offering', 'secret_options', $$'{}'$$);
SELECT sanitise.blank('openstack_tenant', 'user_password');
SELECT sanitise.blank('openstack_tenant', 'user_username');
SELECT sanitise.blank('waldur_azure_virtualmachine', 'password');
SELECT sanitise.blank('waldur_azure_sqlserver', 'password');
SELECT sanitise.blank('waldur_rancher_catalog', 'password');
SELECT sanitise.blank('waldur_rancher_catalog', 'username');
SELECT sanitise.blank('marketplace_serviceprovider', 'api_secret_code');
SELECT sanitise.blank('support_providerhelpdesk', 'webhook_secret');
SELECT sanitise.blank('proposal_reviewerprofile', 'orcid_access_token');
SELECT sanitise.blank('proposal_reviewerprofile', 'orcid_refresh_token');
SELECT sanitise.blank('proposal_assignmentbatch', 'invitation_token');
SELECT sanitise.blank('proposal_callreviewerpool', 'invitation_token');

-- django_site is what Django's absolute-URL helpers fall back to.
SELECT sanitise.exec_if('django_site', ARRAY['domain', 'name'],
    $$UPDATE public.django_site
      SET domain = 'localhost:8000', name = 'localhost'$$);

-- Addresses that mail would actually be sent to, or callbacks that a local
-- instance would fire at production.
SELECT sanitise.wipe('logging_emailhook');
SELECT sanitise.blank('marketplace_order', 'callback_url');
SELECT sanitise.blank('invoices_invoice', 'payment_url');
SELECT sanitise.blank('marketplace_order', 'provider_message_url');
SELECT sanitise.blank('marketplace_offeringuser', 'service_provider_comment_url');
SELECT sanitise.blank('marketplace_offeringaccessendpoint', 'url', $$''$$);
SELECT sanitise.blank('marketplace_resourceaccessendpoint', 'url', $$''$$);

-- Files stored in the database. The bytes may be anything a user uploaded -
-- a CV, a signed agreement - and dropping them also makes the dump far
-- smaller. The rows stay so that references still resolve.
SELECT sanitise.blank('media_file', 'content', $$''::bytea$$);
-- media_file.name is unique, so it has to stay distinct per row.
SELECT sanitise.blank('media_file', 'name', $$'redacted-' || id$$);
SELECT sanitise.blank('media_file', 'hash', $$''$$);

-- Domain allowlists name the real institution and gate who may be invited.
SELECT sanitise.blank('marketplace_serviceprovider', 'allowed_domains', $$'[]'$$);
SELECT sanitise.blank('waldur_openportal_remoteproject', 'allowed_domains', $$'[]'$$);
SELECT sanitise.blank('proposal_round', 'default_allowed_domains', $$'[]'$$);
SELECT sanitise.blank('structure_customer', 'user_email_patterns', $$'[]'$$);
SELECT sanitise.blank('structure_project', 'user_email_patterns', $$'[]'$$);
SELECT sanitise.blank('proposal_call', 'user_email_patterns', $$'[]'$$);
SELECT sanitise.blank('users_groupinvitation', 'user_email_patterns', $$'[]'$$);
SELECT sanitise.blank('waldur_autoprovisioning_rule', 'user_email_patterns', $$'[]'$$);

-- ---------------------------------------------------------------------------
-- 5. Free text written by people.
--
-- Support tickets, comments and broadcast messages are prose: they contain
-- names, addresses, phone numbers and whatever else the writer put in them,
-- with no structure to key a rewrite off. Substituting known names would still
-- leave everything else, so the text is replaced with filler of the same
-- length - the UI still looks like it holds a real conversation, and nothing
-- of the conversation survives.
-- ---------------------------------------------------------------------------

SELECT sanitise.say('Replacing free text written by people');

DO $$
DECLARE
    spec text;
BEGIN
    FOREACH spec IN ARRAY ARRAY[
        'support_issue.summary',
        'support_issue.description',
        'support_issue.resolution',
        'support_issue.escalation_reason',
        'support_comment.description',
        'notifications_broadcastmessage.subject',
        'notifications_broadcastmessage.body',
        'logging_emaillog.subject',
        'logging_emaillog.body',
        'marketplace_offeringuser.service_provider_comment',
        'structure_customer.contact_details',
        'core_user.description',
        -- Proposals. The awards site is nothing but these, and they are the
        -- most sensitive text in any Waldur database: unpublished research
        -- plans, written by the applicant, and candid assessments of them
        -- written by named reviewers. The columns below exist only on the
        -- fork's own proposal app, which upstream replaced, so every one of
        -- them is a skip on a portal database.
        'proposal_proposal.project_summary',
        'proposal_proposal.description',
        'proposal_proposal.allocation_comment',
        'proposal_proposalresourceadjustment.comment',
        'proposal_review.summary_private_comment',
        'proposal_review.summary_public_comment',
        'proposal_review.comment_project_title',
        'proposal_review.comment_project_summary',
        'proposal_review.comment_project_description',
        'proposal_review.comment_project_duration',
        'proposal_review.comment_project_is_confidential',
        'proposal_review.comment_project_has_civilian_purpose',
        'proposal_review.comment_project_supporting_documentation',
        'proposal_review.comment_resource_requests',
        'proposal_review.comment_team',
        'proposal_reviewcomment.message',
        -- Prose written by staff about a person or a project. Rewriting the
        -- names that happen to be in the maps would still leave everything
        -- else the writer typed, so the text goes.
        'structure_project.staff_notes',
        'waldur_openportal_remoteprojectauditentry.note',
        'waldur_openportal_managedprojectauditentry.note',
        'waldur_openportal_managedproject.review_comment'
    ] LOOP
        PERFORM sanitise.exec_if(
            split_part(spec, '.', 1), ARRAY[split_part(spec, '.', 2)],
            format('UPDATE public.%I SET %I = sanitise.filler(%I)
                    WHERE %I IS NOT NULL AND %I <> %L',
                   split_part(spec, '.', 1), split_part(spec, '.', 2),
                   split_part(spec, '.', 2), split_part(spec, '.', 2),
                   split_part(spec, '.', 2), ''));
    END LOOP;
END $$;

-- structure_project.termination_metadata records who terminated a project and
-- which roles the members had, so it cannot stay. It is EMPTIED rather than
-- filled, because it is a text column that the ORM reads as JSON: filler()
-- recognises a JSON document and empties it, but that is a guess made from the
-- value, and a guess is the wrong thing to rely on where a wrong answer breaks
-- every read of the row. Here the column is known, so say so.
SELECT sanitise.blank('structure_project', 'termination_metadata');

-- OpenPortal's remote-project notes are an append-only list of
-- {timestamp, author, text}. Keep the timestamps and the number of notes, so
-- the audit trail still looks like one, and rewrite the two fields that carry
-- anything about a person.
SELECT sanitise.exec_if('waldur_openportal_remoteproject', ARRAY['notes'], $$
    UPDATE public.waldur_openportal_remoteproject p
    SET notes = coalesce((
        SELECT jsonb_agg(
            note
            || jsonb_build_object(
                'author',
                CASE
                    WHEN sanitise.is_pseudonym(note->>'author')
                        THEN note->>'author'
                    ELSE coalesce(
                        (SELECT new FROM sanitise.name_map
                         WHERE orig = note->>'author'),
                        (SELECT new FROM sanitise.token_map
                         WHERE orig = note->>'author'),
                        -- An author is a person's rendered name, so the sink
                        -- is a name, not a login.
                        'Person Number0')
                END)
            || jsonb_build_object('text',
                                  sanitise.filler(note->>'text'))
            ORDER BY ord)
        FROM jsonb_array_elements(p.notes) WITH ORDINALITY AS n(note, ord)
    ), '[]'::jsonb)
    WHERE jsonb_typeof(p.notes) = 'array' AND p.notes <> '[]'::jsonb
$$);

-- The fork's proposal notes are the same shape as the remote-project notes
-- above - an append-only list of {timestamp, author, text}, here visible only
-- to call managers and staff - so they get the same treatment: the timestamps
-- and the number of notes survive, the author is mapped, the text goes.
SELECT sanitise.exec_if('proposal_proposal', ARRAY['notes'], $$
    UPDATE public.proposal_proposal p
    SET notes = coalesce((
        SELECT jsonb_agg(
            note
            || jsonb_build_object(
                'author',
                CASE
                    WHEN sanitise.is_pseudonym(note->>'author')
                        THEN note->>'author'
                    ELSE coalesce(
                        (SELECT new FROM sanitise.name_map
                         WHERE orig = note->>'author'),
                        (SELECT new FROM sanitise.token_map
                         WHERE orig = note->>'author'),
                        'Person Number0')
                END)
            || jsonb_build_object('text',
                                  sanitise.filler(note->>'text'))
            ORDER BY ord)
        FROM jsonb_array_elements(p.notes) WITH ORDINALITY AS n(note, ord)
    ), '[]'::jsonb)
    WHERE jsonb_typeof(p.notes) = 'array' AND p.notes <> '[]'::jsonb
$$);

-- Uploaded proposal and call documents. The bytes are already gone -
-- media_file.content is emptied above - so what is left is the file NAME,
-- which applicants routinely write their own name into
-- ("Jane-Smith-CV.pdf"). The rows stay so that the listings and the media
-- access rules are still exercised; only the path goes.
SELECT sanitise.blank('proposal_proposaldocumentation', 'file');
SELECT sanitise.blank('proposal_calldocument', 'file');

-- Opaque blobs of provider or identity-provider data. core_user.details is the
-- raw userinfo claim set from the identity provider, so it is a second copy of
-- everything about the person, in whatever shape that provider uses.
SELECT sanitise.blank('core_user', 'details', $$'{}'$$);
SELECT sanitise.blank('core_user', 'attribute_sources', $$'{}'$$);
SELECT sanitise.blank('core_user', 'affiliations', $$'[]'$$);
SELECT sanitise.blank('core_user', 'image', $$''$$);
SELECT sanitise.blank('marketplace_order', 'attributes', $$'{}'$$);
SELECT sanitise.blank('marketplace_resource', 'attributes', $$'{}'$$);
SELECT sanitise.blank('marketplace_resource', 'backend_metadata', $$'{}'$$);
SELECT sanitise.blank('marketplace_offeringuser', 'backend_metadata', $$'{}'$$);
SELECT sanitise.blank('proposal_reviewerprofile', 'alternative_names', $$'[]'$$);

-- SSH keys identify a person and are often reused elsewhere. The rows stay so
-- that the UI still shows the right number of keys per user.
SELECT sanitise.exec_if('core_sshpublickey',
    ARRAY['name', 'public_key', 'fingerprint_md5'],
    $$UPDATE public.core_sshpublickey SET
        name = 'key-' || id,
        public_key = 'ssh-ed25519 '
            || 'AAAAC3NzaC1lZDI1NTE5AAAAIN0000000000000000000000000000000000000'
            || '00000 redacted',
        fingerprint_md5 = md5(id::text)$$);
SELECT sanitise.exec_if('core_sshpublickey', ARRAY['fingerprint_sha256'],
    $$UPDATE public.core_sshpublickey
      SET fingerprint_sha256 = encode(sha256(id::text::bytea), 'base64')$$);
SELECT sanitise.exec_if('core_sshpublickey', ARRAY['fingerprint_sha512'],
    $$UPDATE public.core_sshpublickey
      SET fingerprint_sha512 = encode(sha512(id::text::bytea), 'base64')$$);

-- ---------------------------------------------------------------------------
-- 6. The event log.
--
-- logging_event is usually the largest table and the one the activity feeds
-- render, so it is worth rewriting rather than emptying. Each row carries a
-- context object whose keys are typed - user_uuid alongside user_full_name,
-- created_by_uuid alongside created_by_username, and so on - which is enough
-- to rewrite it exactly.
--
-- The rendered message is handled from the same row: the values in that row's
-- context are precisely the names that appear in its message, so substituting
-- them is bounded work per row rather than a scan of every person against
-- every event.
-- ---------------------------------------------------------------------------

CREATE FUNCTION sanitise.rewrite_event(ctx jsonb, msg text,
                                       OUT new_ctx jsonb, OUT new_msg text)
LANGUAGE plpgsql STABLE AS $$
DECLARE
    k text;
    v text;
    replacement text;
BEGIN
    new_ctx := ctx;
    new_msg := msg;
    IF ctx IS NULL OR jsonb_typeof(ctx) <> 'object' THEN
        RETURN;
    END IF;

    FOR k, v IN SELECT key, value FROM jsonb_each_text(ctx) LOOP
        IF v IS NULL OR v = '' OR sanitise.is_pseudonym(v) THEN
            CONTINUE;
        END IF;

        replacement := NULL;

        IF k = 'ip_address' THEN
            replacement := '198.51.100.1';
        ELSIF k = 'user_agent' THEN
            replacement := 'Mozilla/5.0 (redacted)';
        ELSIF k ~ '(^|_)email$' OR k ~ '(^|_)emails$' THEN
            replacement := sanitise.map_email(v);
        ELSIF k = 'username' OR k ~ '_username$' THEN
            replacement := sanitise.map_token(v);
        -- A person's rendered name, on a key that can only be about a
        -- person. The event log also carries resource_full_name, which is a
        -- RESOURCE's name: matching every *_full_name key replaced those with
        -- "Person Number0" and quietly destroyed a field the homeport UI
        -- renders. So the sink applies only to these prefixes.
        ELSIF k ~ ('^(user|affected_user|created_by|initiated_by|author'
                   || '|owner|reviewer|approver|manager|caller|assignee'
                   || '|reporter|consumer_reviewed_by|provider_reviewed_by'
                   || '|performed_by|requested_by|submitted_by)'
                   || '_(full_name|native_name)$')
              OR k IN ('full_name', 'native_name') THEN
            replacement := coalesce(
                (SELECT new FROM sanitise.name_map WHERE orig = v),
                'Person Number0');
        -- Any other *_full_name: replace it if it really is a name we know,
        -- and otherwise leave it alone rather than assuming.
        ELSIF k ~ '_full_name$' OR k ~ '_native_name$' THEN
            replacement := (SELECT new FROM sanitise.name_map WHERE orig = v);
        ELSIF k ~ '(^|_)(contact_details|phone_number|civil_number|address)$'
        THEN
            replacement := '';
        ELSIF k = 'initiated_by' THEN
            -- Rendered as a name or a login name depending on the event.
            replacement := coalesce(
                (SELECT new FROM sanitise.name_map WHERE orig = v),
                (SELECT new FROM sanitise.token_map WHERE orig = v));
        END IF;

        IF replacement IS NOT NULL AND replacement <> v THEN
            new_ctx := jsonb_set(new_ctx, ARRAY[k], to_jsonb(replacement));
            IF new_msg IS NOT NULL AND length(v) >= 3 THEN
                new_msg := sanitise.replace_word(new_msg, v, replacement);
            END IF;
        END IF;
    END LOOP;
END $$;

SELECT sanitise.say('Rewriting the event log');

-- Done in batches by id so that it reports progress. It is one statement's
-- worth of work either way, but on a production event log it runs for a long
-- time, and a single silent UPDATE is indistinguishable from a hang.
DO $$
DECLARE
    lo bigint;
    hi bigint;
    batch bigint;
    cur bigint;
    total bigint;
    done bigint := 0;
    n bigint;
    started timestamptz := clock_timestamp();
    eta interval;
    last_pct int := -1;
    pct int;
BEGIN
    IF to_regclass('public.logging_event') IS NULL
       OR NOT sanitise.has_col('logging_event', 'context') THEN
        RETURN;
    END IF;

    SELECT min(id), max(id), count(*) INTO lo, hi, total
    FROM public.logging_event WHERE context IS NOT NULL;

    IF total IS NULL OR total = 0 THEN
        PERFORM sanitise.say('  no events with context to rewrite');
        RETURN;
    END IF;

    PERFORM sanitise.say(format('  %s events to rewrite',
        sanitise.commas(total)));

    -- Sized for roughly fifty batches, so the progress is readable whether
    -- there are ten thousand events or ten million.
    batch := greatest(10000, (hi - lo + 1) / 50);
    cur := lo;
    WHILE cur <= hi LOOP
        UPDATE public.logging_event e
        SET context = r.new_ctx, message = r.new_msg
        FROM (
            SELECT src.id, w.new_ctx, w.new_msg
            FROM public.logging_event src,
                 LATERAL sanitise.rewrite_event(src.context, src.message) AS w
            WHERE src.context IS NOT NULL
              AND src.id >= cur AND src.id < cur + batch
        ) r
        WHERE e.id = r.id;
        GET DIAGNOSTICS n = ROW_COUNT;
        done := done + n;
        cur := cur + batch;

        pct := round(100.0 * least(cur - lo, hi - lo + 1)
                     / greatest(hi - lo + 1, 1));
        IF pct <> last_pct THEN
            last_pct := pct;
            eta := ((100 - pct) / greatest(pct, 1)::numeric)
                   * (clock_timestamp() - started);
            PERFORM sanitise.say(format(
                '  %s%% | %s events rewritten | ETA ~%s',
                pct, sanitise.commas(done), sanitise.human(eta)));
        END IF;
    END LOOP;

    PERFORM sanitise.say(format('  event contexts done: %s in %s',
        sanitise.commas(done), sanitise.human(clock_timestamp() - started)));
END $$;

-- A message on an event with no context names someone the pass above had no
-- way to identify, so it is caught by substituting every known name.
--
-- Two things make this affordable. It is restricted to the rows the pass above
-- could not have covered, which the previous version claimed in a comment and
-- did not do. And the candidates are copied into a temporary table first: the
-- loop is one statement per name, and with a few thousand users the name map
-- holds tens of thousands of entries, so running those against the real
-- logging_event meant tens of thousands of sequential scans of the largest
-- table in the database. That is what made this step take hours.
DO $$
DECLARE
    r record;
    candidates bigint;
    names bigint;
    seen bigint := 0;
    started timestamptz := clock_timestamp();
    last_pct int := -1;
    pct int;
    changed bigint;
BEGIN
    IF to_regclass('public.logging_event') IS NULL THEN
        RETURN;
    END IF;

    CREATE TEMP TABLE fallback_events ON COMMIT DROP AS
    SELECT id, message
    FROM public.logging_event
    WHERE nullif(message, '') IS NOT NULL
      AND (context IS NULL
           OR jsonb_typeof(context) <> 'object'
           OR context = '{}'::jsonb);
    GET DIAGNOSTICS candidates = ROW_COUNT;

    SELECT count(*) INTO names FROM sanitise.name_map;

    IF candidates = 0 OR names = 0 THEN
        PERFORM sanitise.say(format(
            '  no context-less events to sweep for names (%s rows, %s names)',
            sanitise.commas(candidates), sanitise.commas(names)));
        RETURN;
    END IF;

    PERFORM sanitise.say(format(
        '  sweeping %s context-less events for %s names',
        sanitise.commas(candidates), sanitise.commas(names)));

    -- Long strings first: replacing "Ada Lovelace" before "Ada" avoids
    -- leaving a surname stranded next to a pseudonym.
    FOR r IN SELECT orig, new FROM sanitise.name_map
             ORDER BY length(orig) DESC, orig
    LOOP
        UPDATE fallback_events
        SET message = sanitise.replace_word(message, r.orig, r.new)
        WHERE message LIKE '%' || r.orig || '%';
        seen := seen + 1;
        pct := round(100.0 * seen / names);
        IF pct <> last_pct AND pct % 10 = 0 THEN
            last_pct := pct;
            PERFORM sanitise.say(format('  %s%% of names', pct));
        END IF;
    END LOOP;

    UPDATE public.logging_event e
    SET message = f.message
    FROM fallback_events f
    WHERE e.id = f.id AND e.message IS DISTINCT FROM f.message;
    GET DIAGNOSTICS changed = ROW_COUNT;

    PERFORM sanitise.say(format(
        '  context-less sweep done: %s messages changed, in %s',
        sanitise.commas(changed),
        sanitise.human(clock_timestamp() - started)));
END $$;

-- ---------------------------------------------------------------------------
-- 7. People.
--
-- Done last, so that the maps above were built from the original values.
-- ---------------------------------------------------------------------------

SELECT sanitise.say('Pseudonymising people');

-- Built from the columns this installation actually has.
--
-- Naming them in a literal UPDATE fails outright on an older schema - the
-- first production run died here on organization_address, a column added after
-- the snapshot this was developed against - and it fails only after the event
-- log has been rewritten, which is the expensive part. A column that is not
-- there is now simply not set.
DO $$
DECLARE
    sets text[] := ARRAY[]::text[];
    spec record;
BEGIN
    FOR spec IN
        SELECT * FROM (VALUES
            ('first_name',           $q$'Person'$q$),
            ('last_name',            $q$'Number' || p.n$q$),
            ('native_name',          $q$p.new_name$q$),
            ('username',             $q$p.new_username$q$),
            ('slug',                 $q$p.new_username$q$),
            ('email',                $q$CASE WHEN nullif(u.email, '') IS NULL
                                            THEN u.email
                                            ELSE sanitise.map_email(u.email)
                                       END$q$),
            -- Rendered by the search box; a concatenation of name and login.
            ('query_field',          $q$p.new_name || ' ' || p.new_username$q$),
            -- An unusable hash: Django rejects any password against it, so
            -- the copy cannot be logged into with a password guessed from
            -- production.
            ('password',             $q$'!'$q$),
            ('civil_number',         $q$NULL$q$),
            ('birth_date',           $q$NULL$q$),
            ('phone_number',         $q$''$q$),
            ('job_title',            $q$''$q$),
            ('organization',         $q$''$q$),
            ('organization_address', $q$''$q$),
            ('address',              $q$''$q$),
            ('backend_id',           $q$'redacted-' || p.n$q$),
            ('last_login',           $q$NULL$q$)
        ) AS t(col, expr)
    LOOP
        IF sanitise.has_col('core_user', spec.col) THEN
            sets := sets || format('%I = %s', spec.col, spec.expr);
        ELSE
            RAISE NOTICE 'skip: no column core_user.%', spec.col;
        END IF;
    END LOOP;

    EXECUTE 'UPDATE public.core_user u SET ' || array_to_string(sets, ', ')
            || ' FROM sanitise.person p WHERE p.user_id = u.id';
END $$;

-- Columns that only exist on some releases, and the rest of the identity
-- attributes an identity provider may have supplied.
SELECT sanitise.blank('core_user', 'unix_username');
SELECT sanitise.blank('core_user', 'country_of_residence', $$''$$);
SELECT sanitise.blank('core_user', 'place_of_birth', $$''$$);
SELECT sanitise.blank('core_user', 'nationality', $$''$$);
SELECT sanitise.blank('core_user', 'nationalities', $$'[]'$$);
SELECT sanitise.blank('core_user', 'gender', $$''$$);
SELECT sanitise.blank('core_user', 'personal_title', $$''$$);
SELECT sanitise.blank('core_user', 'eduperson_assurance', $$'[]'$$);
SELECT sanitise.blank('core_user', 'organization_registry_code', $$''$$);
SELECT sanitise.blank('core_user', 'organization_vat_code', $$''$$);
SELECT sanitise.blank('core_user', 'deactivation_reason', $$''$$);

-- Invitations: an address and a name for someone who may never have become a
-- user, which is why they were counted as people in their own right above.
SELECT sanitise.exec_if('users_invitation', ARRAY['email'], $$
    UPDATE public.users_invitation
    SET email = sanitise.map_email(email)
    WHERE nullif(email, '') IS NOT NULL
$$);
SELECT sanitise.exec_if('users_invitation', ARRAY['email', 'full_name'], $$
    UPDATE public.users_invitation
    SET full_name = CASE
        WHEN email LIKE 'person%@%'
            THEN 'Person Number' || split_part(split_part(email, '@', 1),
                                               'person', 2)
        ELSE 'Person Redacted' END
    WHERE nullif(full_name, '') IS NOT NULL
$$);
SELECT sanitise.blank('users_invitation', 'native_name', $$''$$);
SELECT sanitise.blank('users_invitation', 'civil_number');
SELECT sanitise.blank('users_invitation', 'phone_number', $$''$$);
SELECT sanitise.blank('users_invitation', 'job_title', $$''$$);
SELECT sanitise.blank('users_invitation', 'organization', $$''$$);

-- Every remaining single-address column.
DO $$
DECLARE
    spec text;
BEGIN
    FOREACH spec IN ARRAY ARRAY[
        'core_changeemailrequest.email',
        'structure_customer.email',
        'structure_affiliatedorganization.email',
        'marketplace_serviceprovider.lead_email',
        'marketplace_courseaccount.email',
        'marketplace_customerserviceaccount.email',
        'marketplace_projectserviceaccount.email',
        'proposal_callreviewerpool.invited_email',
        'support_providerhelpdesk.notification_email',
        'waldur_rancher_keycloakusergroupmembership.email'
    ] LOOP
        PERFORM sanitise.exec_if(
            split_part(spec, '.', 1), ARRAY[split_part(spec, '.', 2)],
            format('UPDATE public.%I SET %I = sanitise.map_email(%I)
                    WHERE nullif(%I, %L) IS NOT NULL',
                   split_part(spec, '.', 1), split_part(spec, '.', 2),
                   split_part(spec, '.', 2), split_part(spec, '.', 2), ''));
    END LOOP;
END $$;

-- Multi-valued address columns.
SELECT sanitise.exec_if('logging_emaillog', ARRAY['emails'], $$
    UPDATE public.logging_emaillog l
    SET emails = (SELECT array_agg(sanitise.map_email(e))
                  FROM unnest(l.emails) AS e)
    WHERE l.emails IS NOT NULL AND cardinality(l.emails) > 0
$$);

SELECT sanitise.exec_if('notifications_broadcastmessage', ARRAY['emails'], $$
    UPDATE public.notifications_broadcastmessage b
    SET emails = coalesce(
        (SELECT jsonb_agg(sanitise.map_email(e))
         FROM jsonb_array_elements_text(b.emails) AS e),
        '[]'::jsonb)
    WHERE jsonb_typeof(b.emails) = 'array'
$$);
SELECT sanitise.blank('notifications_broadcastmessage', 'query', $$'{}'$$);

SELECT sanitise.exec_if('structure_customer', ARRAY['notification_emails'], $$
    UPDATE public.structure_customer c
    SET notification_emails = coalesce((
        SELECT string_agg(sanitise.map_email(btrim(e)), ', ')
        FROM regexp_split_to_table(c.notification_emails, '[,;\s]+') AS e
        WHERE btrim(e) <> ''), '')
    WHERE nullif(c.notification_emails, '') IS NOT NULL
$$);

-- Every remaining login-name column.
DO $$
DECLARE
    spec text;
BEGIN
    FOREACH spec IN ARRAY ARRAY[
        'marketplace_offeringuser.username',
        'marketplace_componentuserusage.username',
        'marketplace_customerserviceaccount.username',
        'marketplace_projectserviceaccount.username',
        'waldur_openportal_association.username',
        'waldur_openportal_allocationuserusage.username',
        'waldur_openportal_userinfo.shortname',
        'waldur_slurm_association.username',
        'waldur_slurm_allocationuserusage.username',
        'waldur_freeipa_profile.username',
        'waldur_rancher_keycloakusergroupmembership.username',
        'marketplace_robotaccount.username'
    ] LOOP
        PERFORM sanitise.exec_if(
            split_part(spec, '.', 1), ARRAY[split_part(spec, '.', 2)],
            format('UPDATE public.%I SET %I = sanitise.map_token(%I)
                    WHERE nullif(%I, %L) IS NOT NULL',
                   split_part(spec, '.', 1), split_part(spec, '.', 2),
                   split_part(spec, '.', 2), split_part(spec, '.', 2), ''));
    END LOOP;
END $$;

SELECT sanitise.blank('waldur_rancher_keycloakusergroupmembership',
                      'first_name', $$'Person'$$);
SELECT sanitise.blank('waldur_rancher_keycloakusergroupmembership',
                      'last_name', $$'Redacted'$$);

-- Organisation contact details: a switchboard number and a postal address are
-- not personal data, but a "contact details" free-text field on a small
-- research group usually names a person.
SELECT sanitise.blank('structure_customer', 'phone_number', $$''$$);
SELECT sanitise.blank('structure_customer', 'bank_account', $$''$$);
SELECT sanitise.blank('structure_affiliatedorganization', 'address', $$''$$);

-- ---------------------------------------------------------------------------
-- 7b. The sweep.
--
-- Everything above targets a column because someone knew it was there. This
-- pass targets every column there is, so a leak in a table this script has
-- never heard of - a new upstream model, a provider extension, the next thing
-- OpenPortal adds - is caught anyway.
--
-- Two passes, both cheap to skip:
--
--   * every json and jsonb column, walked by sanitise.scrub_json;
--   * every text column that contains an @, rewritten by sanitise.scrub_emails.
--
-- The text pass is prefiltered on LIKE '%@%', which uses an index where there
-- is one and is a cheap sequential test where there is not. The JSON pass has
-- no such shortcut and is the slowest step in the script; on a large
-- installation expect it to dominate the run.
--
-- Columns already reduced to a constant above are skipped by the prefilters,
-- so this costs nothing extra for them.
-- ---------------------------------------------------------------------------

-- A cache table is a copy of things computed elsewhere, keyed by strings that
-- in Waldur's case include addresses (LOGIN_FAILURES_OF_<address>). Nothing
-- needs it.
SELECT sanitise.say('Sweeping every JSON and text column in the database');

SELECT sanitise.wipe('waldur_cache');

-- Text columns that hold a JSON document. Walked as JSON so that login names
-- and personal names inside them map consistently, rather than only the
-- addresses being caught by the pass below.
SELECT sanitise.exec_if('waldur_openportal_job', ARRAY['job_data'],
    $$UPDATE public.waldur_openportal_job
      SET job_data = sanitise.scrub_json_text(job_data)
      WHERE job_data IS NOT NULL AND job_data <> ''$$);

-- The plan is built and reported before any of it runs, so the size of the job
-- is known up front rather than discovered at 3am.
--
-- The measurement is a real one: a count of the rows that will actually be
-- walked and the number of bytes of JSON in them, per column. Estimating from
-- pg_class.reltuples instead would be free but useless - the three payload
-- columns on an audit table have identical row counts and wildly different
-- costs, because two of them are empty on most rows. Cost tracks BYTES of
-- JSON, not rows, so that is what the projection is weighted by.
--
-- It costs one sequential scan per JSON column. That is a rounding error
-- against the walk itself, which is three orders of magnitude slower per row,
-- but on a very large database it is still minutes: set
-- waldur.sanitise_skip_measure to 'yes' to fall back to row estimates and
-- start immediately with a vaguer ETA.
CREATE TABLE sanitise.json_plan (
    seq       int,
    tbl       text,
    col       text,
    udt       text,
    rows_todo bigint,
    bytes     bigint
);

DO $$
DECLARE
    r record;
    measured int := 0;
    total int;
    n bigint;
    b bigint;
    skip boolean := current_setting('waldur.sanitise_skip_measure', true)
                    = 'yes';
    started timestamptz := clock_timestamp();
BEGIN
    CREATE TEMP TABLE json_columns AS
    SELECT c.table_name AS tbl, c.column_name AS col, c.udt_name AS udt,
           greatest(cls.reltuples, 0)::bigint AS est_rows
    FROM information_schema.columns c
    JOIN information_schema.tables t
      ON t.table_schema = c.table_schema
     AND t.table_name = c.table_name
     AND t.table_type = 'BASE TABLE'
    JOIN pg_class cls
      ON cls.oid = to_regclass('public.' || quote_ident(c.table_name))
    WHERE c.table_schema = 'public'
      AND c.udt_name IN ('json', 'jsonb')
      AND c.is_generated = 'NEVER'
      AND c.is_updatable = 'YES';

    SELECT count(*) INTO total FROM json_columns;

    IF skip THEN
        PERFORM sanitise.say(format(
            'JSON sweep: %s columns, sizing skipped - ETA will be rough',
            total));
        INSERT INTO sanitise.json_plan (seq, tbl, col, udt, rows_todo, bytes)
        SELECT row_number() OVER (ORDER BY est_rows DESC, tbl, col),
               tbl, col, udt, est_rows, est_rows * 2000
        FROM json_columns;
    ELSE
        PERFORM sanitise.say(format(
            'JSON sweep: sizing %s columns (one scan each, then the real work)',
            total));
        FOR r IN SELECT * FROM json_columns ORDER BY est_rows DESC, tbl, col
        LOOP
            EXECUTE format(
                'SELECT count(*), coalesce(sum(pg_column_size(%I)), 0)
                 FROM public.%I
                 WHERE %I IS NOT NULL
                   AND %I::text NOT IN (''{}'', ''[]'', ''null'')',
                r.col, r.tbl, r.col, r.col) INTO n, b;
            INSERT INTO sanitise.json_plan (tbl, col, udt, rows_todo, bytes)
            VALUES (r.tbl, r.col, r.udt, n, b);
            measured := measured + 1;
            IF measured % 50 = 0 THEN
                PERFORM sanitise.say(format('  sized %s/%s columns',
                    measured, total));
            END IF;
        END LOOP;
        -- Biggest first: the worst of it is underway early, and the
        -- projection is then based on representative work rather than on a
        -- run of empty columns.
        UPDATE sanitise.json_plan p
        SET seq = ranked.seq
        FROM (SELECT tbl, col,
                     row_number() OVER (ORDER BY bytes DESC, rows_todo DESC,
                                        tbl, col) AS seq
              FROM sanitise.json_plan) ranked
        WHERE p.tbl = ranked.tbl AND p.col = ranked.col;
        PERFORM sanitise.say(format('  sizing took %s',
            sanitise.human(clock_timestamp() - started)));
    END IF;

    DROP TABLE json_columns;

    -- Columns with nothing in them are dropped from the plan rather than
    -- walked and logged: on a fresh install most of the 188 are empty.
    DELETE FROM sanitise.json_plan WHERE rows_todo = 0;
END $$;

DO $$
DECLARE
    r record;
    started timestamptz := clock_timestamp();
    now_ts timestamptz;
    total_cols int;
    total_rows bigint;
    total_bytes bigint;
    bytes_done bigint := 0;
    rows_done bigint := 0;
    col_elapsed interval;
    col_started timestamptz;
    updated bigint;
    rate numeric;
    eta interval;
BEGIN
    SELECT count(*), coalesce(sum(rows_todo), 0), coalesce(sum(bytes), 0)
    INTO total_cols, total_rows, total_bytes FROM sanitise.json_plan;

    IF total_cols = 0 THEN
        PERFORM sanitise.say('JSON sweep: nothing to walk');
        RETURN;
    END IF;

    PERFORM sanitise.say(format(
        'JSON sweep: %s non-empty columns, %s rows, %s MB of JSON.'
        || ' This is the slow step.',
        total_cols, sanitise.commas(total_rows),
        sanitise.commas(total_bytes / 1048576)));
    -- Measured on a real dump at 0.4-0.55 MB of JSON per second and 700-900
    -- rows per second, so both bounds are applied and the worse one wins - a
    -- table of many tiny documents is row-bound, one of large payloads is
    -- byte-bound. Deliberately the pessimistic end: this is the number
    -- someone uses to decide whether to leave it running overnight, and an
    -- optimistic first guess is worse than a vague one.
    --
    -- Superseded by the observed rate as soon as the first column finishes.
    PERFORM sanitise.say(format(
        '  first estimate ~%s (0.4 MB/s, 700 rows/s) - refined after every'
        || ' column',
        sanitise.human(greatest(total_bytes / 419430.4,
                                total_rows / 700.0) * interval '1 second')));

    FOR r IN SELECT * FROM sanitise.json_plan ORDER BY seq LOOP
        PERFORM sanitise.say(format('  [%s/%s] %s.%s (%s rows, %s MB)',
            r.seq, total_cols, r.tbl, r.col,
            sanitise.commas(r.rows_todo),
            round(r.bytes / 1048576.0, 1)));

        col_started := clock_timestamp();
        EXECUTE format(
            'UPDATE public.%I SET %I = sanitise.scrub_json(%I::jsonb)::%s
             WHERE %I IS NOT NULL
               AND %I::text NOT IN (''{}'', ''[]'', ''null'')',
            r.tbl, r.col, r.col, r.udt, r.col, r.col);
        GET DIAGNOSTICS updated = ROW_COUNT;
        now_ts := clock_timestamp();
        col_elapsed := now_ts - col_started;

        bytes_done := bytes_done + r.bytes;
        rows_done := rows_done + r.rows_todo;

        IF bytes_done < total_bytes THEN
            rate := bytes_done / greatest(
                extract(epoch FROM (now_ts - started)), 0.001);
            eta := ((total_bytes - bytes_done) / greatest(rate, 1.0))
                   * interval '1 second';
            PERFORM sanitise.say(format(
                '        %s rows rewritten in %s | %s%% done | ETA ~%s',
                sanitise.commas(updated), sanitise.human(col_elapsed),
                round(100.0 * bytes_done / greatest(total_bytes, 1)),
                sanitise.human(eta)));
        ELSE
            PERFORM sanitise.say(format('        %s rows rewritten in %s',
                sanitise.commas(updated), sanitise.human(col_elapsed)));
        END IF;
    END LOOP;

    PERFORM sanitise.say(format(
        'JSON sweep done: %s columns, %s rows, %s MB, in %s (%s MB/s,'
        || ' %s rows/s)',
        total_cols, sanitise.commas(rows_done),
        sanitise.commas(total_bytes / 1048576),
        sanitise.human(clock_timestamp() - started),
        round((total_bytes / 1048576.0)
              / greatest(extract(epoch FROM (clock_timestamp() - started)),
                         0.001), 2),
        round(rows_done
              / greatest(extract(epoch FROM (clock_timestamp() - started)),
                         0.001))));
END $$;

-- Every column whose NAME says it holds an account identifier, whichever app
-- declared it. Restricted to those names on purpose: applied to text columns
-- in general it would rewrite a role or a project that happens to be spelled
-- like someone's login, and a role rename breaks permission lookups.
--
-- Unrecognised values are left alone here rather than folded onto the sink,
-- because a column matched by name may hold something that is not an account
-- at all.
DO $$
DECLARE
    r record;
    started timestamptz := clock_timestamp();
    updated bigint;
    touched int := 0;
BEGIN
    PERFORM sanitise.say('Mapping account-identifier columns');
    FOR r IN
        SELECT c.table_name AS tbl, c.column_name AS col
        FROM information_schema.columns c
        JOIN information_schema.tables t
          ON t.table_schema = c.table_schema
         AND t.table_name = c.table_name
         AND t.table_type = 'BASE TABLE'
        WHERE c.table_schema = 'public'
          AND c.udt_name IN ('varchar', 'text', 'bpchar')
          AND c.is_generated = 'NEVER'
          AND c.is_updatable = 'YES'
          AND c.column_name ~ (
              '^(username|useridentifier|user_identifier|shortname|login'
              || '|account_name|unix_username|identifier|local_identifier)$')
        ORDER BY c.table_name, c.column_name
    LOOP
        EXECUTE format(
            'UPDATE public.%I SET %I = coalesce(sanitise.map_identifier(%I), %I)
             WHERE nullif(%I, '''') IS NOT NULL',
            r.tbl, r.col, r.col, r.col, r.col);
        GET DIAGNOSTICS updated = ROW_COUNT;
        touched := touched + 1;
        IF updated > 0 THEN
            PERFORM sanitise.say(format('  %s.%s: %s rows',
                r.tbl, r.col, sanitise.commas(updated)));
        END IF;
    END LOOP;
    PERFORM sanitise.say(format(
        'Identifier columns done: %s columns in %s',
        touched, sanitise.human(clock_timestamp() - started)));
END $$;

DO $$
DECLARE
    r record;
    started timestamptz := clock_timestamp();
    updated bigint;
    changed bigint := 0;
    total_cols int;
    touched int := 0;
BEGIN
    SELECT count(*) INTO total_cols
    FROM information_schema.columns c
    JOIN information_schema.tables t
      ON t.table_schema = c.table_schema AND t.table_name = c.table_name
     AND t.table_type = 'BASE TABLE'
    WHERE c.table_schema = 'public'
      AND c.udt_name IN ('varchar', 'text', 'bpchar')
      AND c.is_generated = 'NEVER' AND c.is_updatable = 'YES'
      AND c.table_name <> 'django_migrations';

    PERFORM sanitise.say(format(
        'Text sweep: %s columns to check for addresses and URLs', total_cols));
    FOR r IN
        SELECT c.table_name AS tbl, c.column_name AS col
        FROM information_schema.columns c
        JOIN information_schema.tables t
          ON t.table_schema = c.table_schema
         AND t.table_name = c.table_name
         AND t.table_type = 'BASE TABLE'
        WHERE c.table_schema = 'public'
          AND c.udt_name IN ('varchar', 'text', 'bpchar')
          AND c.is_generated = 'NEVER'
          AND c.is_updatable = 'YES'
          -- django_migrations is the migration history; rewriting it would
          -- break the migration rehearsal this data exists for.
          AND c.table_name <> 'django_migrations'
        ORDER BY c.table_name, c.column_name
    LOOP
        EXECUTE format(
            'UPDATE public.%I SET %I =
                 sanitise.scrub_urls(sanitise.scrub_emails(%I))
             WHERE %I LIKE ''%%@%%'' OR %I LIKE ''%%http%%''',
            r.tbl, r.col, r.col, r.col, r.col);
        GET DIAGNOSTICS updated = ROW_COUNT;
        touched := touched + 1;
        IF updated > 0 THEN
            changed := changed + updated;
            PERFORM sanitise.say(format('  %s.%s: %s rows',
                r.tbl, r.col, sanitise.commas(updated)));
        -- There are well over a thousand text columns and most hold nothing
        -- of interest, so a line each would bury the ones that matter. A
        -- heartbeat instead, to show it is still moving.
        ELSIF touched % 250 = 0 THEN
            PERFORM sanitise.say(format('  ... %s/%s columns',
                touched, total_cols));
        END IF;
    END LOOP;
    PERFORM sanitise.say(format(
        'Text sweep done: %s columns, %s rows rewritten, in %s',
        touched, sanitise.commas(changed),
        sanitise.human(clock_timestamp() - started)));
END $$;

-- ---------------------------------------------------------------------------
-- 7c. Make every text column that the ORM reads as JSON parse as JSON.
--
-- waldur_core.core.fields.JSONField is a text column to PostgreSQL and a JSON
-- document to Django: from_db_value() runs json.loads on every READ. Anything
-- in one of these columns that is not JSON therefore breaks reading the row,
-- not writing it, and the failure surfaces as
--
--   django.core.exceptions.ValidationError: ['Enter valid JSON']
--
-- wherever the row is touched - a 500 on a list endpoint, a task that cannot
-- load its own object - looking exactly like a bug in the code under test.
-- That is the worst possible way for a sanitising artefact to present itself,
-- because the whole point of the copy is to test the code against it.
--
-- Every stage above is careful not to do this. This is the net under all of
-- them: a column named here is checked and emptied if it no longer parses,
-- whichever stage broke it, and the column list comes from Django's field
-- registry rather than from guesswork (scripts/repair_sanitised_json_text.py
-- derives the same list live, and repairs a copy that is already loaded).
--
-- Columns that do not exist on this release are skipped, so it is safe either
-- side of the resync.
-- ---------------------------------------------------------------------------

SELECT sanitise.say('Checking the text columns that the ORM reads as JSON');

-- A cast that reports rather than raises.
CREATE FUNCTION sanitise.is_json(v text)
RETURNS boolean LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
    parsed jsonb;
BEGIN
    IF v IS NULL OR v = '' THEN
        RETURN true;
    END IF;
    BEGIN
        parsed := v::jsonb;
    EXCEPTION WHEN others THEN
        RETURN false;
    END;
    RETURN true;
END $$;

DO $$
DECLARE
    spec record;
    nullable text;
    udt text;
    empty text;
    n bigint;
    bad_total bigint := 0;
    skipped_native int := 0;
BEGIN
    FOR spec IN
        SELECT * FROM (VALUES
            ('structure_project',                  'termination_metadata'),
            ('structure_projectdigestconfiguration', 'enabled_sections'),
            ('logging_alert',                      'context'),
            ('logging_emailhook',                  'event_groups'),
            ('logging_emailhook',                  'event_types'),
            ('logging_pushhook',                   'event_groups'),
            ('logging_pushhook',                   'event_types'),
            ('logging_webhook',                    'event_groups'),
            ('logging_webhook',                    'event_types'),
            ('logging_systemnotification',         'event_groups'),
            ('logging_systemnotification',         'event_types'),
            ('logging_systemnotification',         'roles'),
            ('user_actions_useraction',            'corrective_actions'),
            ('user_actions_useraction',            'metadata'),
            ('user_actions_useraction',            'route_params'),
            ('user_actions_useractionexecution',   'execution_metadata'),
            ('waldur_auth_saml2_identityprovider', 'metadata'),
            ('waldur_aws_instance',                'private_ips'),
            ('waldur_aws_instance',                'public_ips'),
            ('waldur_azure_virtualmachine',        'private_ips'),
            ('waldur_azure_virtualmachine',        'public_ips'),
            ('openstack_backup',                   'metadata'),
            ('openstack_instance',                 'action_details'),
            ('openstack_port',                     'allowed_address_pairs'),
            ('openstack_port',                     'fixed_ips'),
            ('openstack_router',                   'external_fixed_ips'),
            ('openstack_router',                   'fixed_ips'),
            ('openstack_router',                   'routes'),
            ('openstack_snapshot',                 'action_details'),
            ('openstack_snapshot',                 'metadata'),
            ('openstack_subnet',                   'allocation_pools'),
            ('openstack_subnet',                   'dns_nameservers'),
            ('openstack_subnet',                   'host_routes'),
            ('openstack_volume',                   'action_details'),
            ('openstack_volume',                   'image_metadata'),
            ('openstack_volume',                   'metadata'),
            ('waldur_openstack_replication_migration', 'mappings')
            -- structure_servicesettings.options is one of these too, and is
            -- deliberately absent. It is an EncryptedOptionsField: only the
            -- values under credential-shaped keys are encrypted, so the
            -- column is still JSON either way, and emptying it is what broke
            -- OpenPortal's instance_name once already. scrub_options() owns
            -- that column and parses-or-blanks it there.
        ) AS t(tbl, col)
    LOOP
        CONTINUE WHEN to_regclass('public.' || quote_ident(spec.tbl)) IS NULL;

        SELECT is_nullable, udt_name INTO nullable, udt
        FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = spec.tbl
          AND column_name = spec.col;
        CONTINUE WHEN nullable IS NULL;

        -- Only text-backed columns. The same field is a native json/jsonb
        -- column on some releases and on some deployments - the awards site
        -- has logging_emailhook.event_groups as jsonb where the portal has it
        -- as text - and there is nothing to check when the database itself
        -- guarantees the value parses. Without this the run dies here on
        -- `function sanitise.is_json(jsonb) does not exist`, hours in.
        IF udt NOT IN ('text', 'varchar', 'bpchar') THEN
            skipped_native := skipped_native + 1;
            CONTINUE;
        END IF;

        EXECUTE format(
            'SELECT count(*) FROM public.%I WHERE NOT sanitise.is_json(%I)',
            spec.tbl, spec.col) INTO n;
        CONTINUE WHEN n = 0;

        -- NULL where the column allows it, an empty document otherwise. The
        -- content is gone either way; what matters is that the row reads.
        empty := CASE WHEN nullable = 'YES' THEN 'NULL' ELSE '''{}''' END;
        EXECUTE format(
            'UPDATE public.%I SET %I = %s WHERE NOT sanitise.is_json(%I)',
            spec.tbl, spec.col, empty, spec.col);

        bad_total := bad_total + n;
        PERFORM sanitise.say(format(
            '  %s.%s: %s rows did not parse, emptied', spec.tbl, spec.col,
            sanitise.commas(n)));
    END LOOP;

    IF skipped_native > 0 THEN
        PERFORM sanitise.say(format(
            '  %s of them are native json columns on this release, so the'
            || ' database already guarantees they parse', skipped_native));
    END IF;

    IF bad_total = 0 THEN
        PERFORM sanitise.say('  all of them parse');
    ELSE
        -- Not an error - the row is readable again - but it means a stage
        -- above wrote something it should not have, and the next person
        -- should know which column to look at.
        PERFORM sanitise.say(format(
            '  %s rows repaired. A stage above wrote non-JSON into a'
            || ' JSON-backed column; worth fixing at the source.',
            sanitise.commas(bad_total)));
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 8. Drop the maps.
--
-- They hold original addresses and names, so they must not outlive the
-- transaction. Because this is inside the transaction, a dump taken after a
-- failed run cannot contain them either - the run rolled back entirely.
-- ---------------------------------------------------------------------------

SELECT sanitise.say('Dropping the maps and committing');

DROP SCHEMA sanitise CASCADE;

COMMIT;

\o

-- Reclaim the space freed by the rewrites, so the dump that follows is not
-- carrying dead tuples. Outside the transaction, since VACUUM cannot run in
-- one. On a large database this takes a while and reports nothing while it
-- runs; it is the last step.
\echo 'Vacuuming (last step, no output until it finishes)...'
VACUUM (ANALYZE);
\echo 'Sanitisation complete.'
