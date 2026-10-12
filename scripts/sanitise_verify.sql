-- Verify that a sanitised database carries nothing from production.
--
-- Read-only. Run after scripts/sanitise_production_dump.sql, against the same
-- throwaway database. scripts/sanitise_production_dump.sh runs it for you and
-- refuses to write the output dump if anything FAILs.
--
-- The checks assert on SHAPE, not on a list of things to look for: every
-- remaining address must match personN@example-orgM.com and every remaining
-- personal name must match "Person NumberN". A column that the sanitiser does
-- not know about therefore fails these checks rather than passing silently,
-- which is the property that matters as upstream adds columns.
--
--   FAIL  a real leak; do not use the dump
--   WARN  needs a look, not necessarily a leak
--   PASS  nothing found
--   SKIP  this release has no such table or column, so nothing can leak
--         through it
--
-- Output is counts and check names only, so it is safe to paste anywhere.
--
-- WHY THIS IS ALL ONE plpgsql BLOCK
--
-- Every check needs the same two things: to know whether a table and its
-- columns exist on this release, and then to count rows matching a predicate
-- over them. That is dynamic SQL. The three ways to do it in plain SQL all
-- fail here:
--
--   * a helper function or a temp table is a WRITE, and this runs in a
--     read-only transaction on purpose;
--   * query_to_xml() needs the server to be built with libxml, and a
--     source-built PostgreSQL frequently is not - which is exactly how an
--     earlier version of this file died after two hours of sanitising had
--     already committed;
--   * naming the columns statically is what this file is trying to avoid.
--
-- EXECUTE ... INTO inside a DO block is a read, needs no extensions, and
-- works on any build. Results come out as notices, which is why they are
-- formatted as pipe-delimited rows: the driver greps them for FAIL.

\pset border 2
\pset format aligned
\timing off

BEGIN;
SET TRANSACTION READ ONLY;

\echo ''
\echo '=================================================================='
\echo ' Sanitisation verification (read-only)'
\echo '=================================================================='
\echo ''

DO $verify$
DECLARE
    -- personN@example-orgM.com, alone or as a comma-separated list.
    email_shape text :=
        '^person[0-9]+@example-org[0-9]+\.com'
        '(, ?person[0-9]+@example-org[0-9]+\.com)*$';
    -- personN, and the compound account names that keep their project and
    -- system parts: personN.project, personN.project.cluster.
    login_shape text := '^person[0-9]+([._-][A-Za-z0-9][A-Za-z0-9._-]*)?$';

    -- What sanitise.filler() leaves behind, as a predicate that matches a
    -- column it did NOT write. Expressed as SQL rather than a regex because
    -- the filler is the original's own length, so its last phrase is cut off
    -- mid-word and a prefix match would reject a legitimately short value.
    -- filler() also empties anything that parses as JSON, hence the pair.
    prose_leak text :=
        $p$(nullif(%1$I, '') IS NOT NULL
            AND %1$I NOT IN ('{}', '[]')
            AND %1$I <> left(repeat('redacted placeholder text ',
                                    (length(%1$I) / 26) + 1), length(%1$I)))$p$;

    -- The fork's proposal app: unpublished research plans and the reviews of
    -- them. Named here so the same list drives the existence check and the
    -- predicate, and so a column added to either escapes neither.
    -- Same reasoning: upstream's Proposal has project_summary and
    -- allocation_comment, but its description lives elsewhere.
    proposal_prose text[] := ARRAY['project_summary', 'allocation_comment'];
    proposal_prose_fork text[] := ARRAY['description'];
    -- Split because a check skips entirely when one of its columns is absent:
    -- upstream's Review has the nine below but not the fork's two, so keeping
    -- them together would silently stop verifying the nine on a portal
    -- database.
    review_prose text[] := ARRAY[
        'summary_public_comment', 'summary_private_comment',
        'comment_project_title', 'comment_project_summary',
        'comment_project_description', 'comment_project_duration',
        'comment_project_supporting_documentation',
        'comment_resource_requests', 'comment_team'];
    review_prose_fork text[] := ARRAY[
        'comment_project_is_confidential',
        'comment_project_has_civilian_purpose'];

    r record;
    spec text;
    present boolean;
    col_type text;
    n bigint;
    pass int := 0;
    fail int := 0;
    warn int := 0;
    skip int := 0;
BEGIN
    RAISE NOTICE '| %      | %  | % |', rpad('status', 6), rpad('check', 38),
        lpad('rows', 12);
    RAISE NOTICE '|--------|----------------------------------------|--------------|';

    ------------------------------------------------------------------
    -- The mapping schema must be gone: it is the one place original values
    -- were held.
    ------------------------------------------------------------------
    SELECT count(*) INTO n
    FROM information_schema.tables WHERE table_schema = 'sanitise';
    IF n = 0 THEN
        pass := pass + 1;
        RAISE NOTICE '| PASS   | % | % |',
            rpad('sanitise_schema_removed', 38), lpad(n::text, 12);
    ELSE
        fail := fail + 1;
        RAISE NOTICE '| FAIL   | % | % |',
            rpad('sanitise_schema_removed', 38), lpad(n::text, 12);
    END IF;

    ------------------------------------------------------------------
    -- Every check: (name, table, required columns, predicate that must match
    -- no rows, and whether a match is a failure or only a warning).
    ------------------------------------------------------------------
    FOR r IN
        SELECT * FROM (VALUES
        -- addresses
        ('address_core_user',              'core_user', ARRAY['email'],
         format($p$nullif(email, '') IS NOT NULL AND email !~ %L$p$,
                email_shape), 'FAIL'),
        ('address_change_request',         'core_changeemailrequest',
         ARRAY['email'],
         format($p$nullif(email, '') IS NOT NULL AND email !~ %L$p$,
                email_shape), 'FAIL'),
        ('address_invitation',             'users_invitation', ARRAY['email'],
         format($p$nullif(email, '') IS NOT NULL AND email !~ %L$p$,
                email_shape), 'FAIL'),
        ('address_customer',               'structure_customer',
         ARRAY['email'],
         format($p$nullif(email, '') IS NOT NULL AND email !~ %L$p$,
                email_shape), 'FAIL'),
        ('address_customer_notifications', 'structure_customer',
         ARRAY['notification_emails'],
         format($p$nullif(notification_emails, '') IS NOT NULL
                  AND notification_emails !~ %L$p$, email_shape), 'FAIL'),
        ('address_affiliated_org',         'structure_affiliatedorganization',
         ARRAY['email'],
         format($p$nullif(email, '') IS NOT NULL AND email !~ %L$p$,
                email_shape), 'FAIL'),
        ('address_service_provider_lead',  'marketplace_serviceprovider',
         ARRAY['lead_email'],
         format($p$nullif(lead_email, '') IS NOT NULL
                  AND lead_email !~ %L$p$, email_shape), 'FAIL'),
        ('address_course_account',          'marketplace_courseaccount',
         ARRAY['email'],
         format($p$nullif(email, '') IS NOT NULL AND email !~ %L$p$,
                email_shape), 'FAIL'),
        ('address_customer_service_acct',   'marketplace_customerserviceaccount',
         ARRAY['email'],
         format($p$nullif(email, '') IS NOT NULL AND email !~ %L$p$,
                email_shape), 'FAIL'),
        ('address_project_service_acct',    'marketplace_projectserviceaccount',
         ARRAY['email'],
         format($p$nullif(email, '') IS NOT NULL AND email !~ %L$p$,
                email_shape), 'FAIL'),
        ('address_reviewer_pool',           'proposal_callreviewerpool',
         ARRAY['invited_email'],
         format($p$nullif(invited_email, '') IS NOT NULL
                  AND invited_email !~ %L$p$, email_shape), 'FAIL'),
        ('address_email_hook',              'logging_emailhook',
         ARRAY['email'],
         format($p$nullif(email, '') IS NOT NULL AND email !~ %L$p$,
                email_shape), 'FAIL'),
        ('address_provider_helpdesk',       'support_providerhelpdesk',
         ARRAY['notification_email'],
         format($p$nullif(notification_email, '') IS NOT NULL
                  AND notification_email !~ %L$p$, email_shape), 'FAIL'),
        ('address_keycloak_membership',
         'waldur_rancher_keycloakusergroupmembership', ARRAY['email'],
         format($p$nullif(email, '') IS NOT NULL AND email !~ %L$p$,
                email_shape), 'FAIL'),
        ('no_addresses_in_event_log',       'logging_event', ARRAY['message'],
         $p$message ~ '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
            AND message !~ 'person[0-9]+@example-org[0-9]+\.com'$p$, 'FAIL'),

        -- login names, which other tables join on
        ('login_offering_user',      'marketplace_offeringuser',
         ARRAY['username'],
         format($p$nullif(username, '') IS NOT NULL AND username !~ %L$p$,
                login_shape), 'FAIL'),
        ('login_component_usage',    'marketplace_componentuserusage',
         ARRAY['username'],
         format($p$nullif(username, '') IS NOT NULL AND username !~ %L$p$,
                login_shape), 'FAIL'),
        ('login_customer_svc_acct',  'marketplace_customerserviceaccount',
         ARRAY['username'],
         format($p$nullif(username, '') IS NOT NULL AND username !~ %L$p$,
                login_shape), 'FAIL'),
        ('login_project_svc_acct',   'marketplace_projectserviceaccount',
         ARRAY['username'],
         format($p$nullif(username, '') IS NOT NULL AND username !~ %L$p$,
                login_shape), 'FAIL'),
        ('login_op_association',     'waldur_openportal_association',
         ARRAY['username'],
         format($p$nullif(username, '') IS NOT NULL AND username !~ %L$p$,
                login_shape), 'FAIL'),
        ('login_op_alloc_usage',     'waldur_openportal_allocationuserusage',
         ARRAY['username'],
         format($p$nullif(username, '') IS NOT NULL AND username !~ %L$p$,
                login_shape), 'FAIL'),
        ('login_op_shortname',       'waldur_openportal_userinfo',
         ARRAY['shortname'],
         format($p$nullif(shortname, '') IS NOT NULL AND shortname !~ %L$p$,
                login_shape), 'FAIL'),
        ('login_slurm_association',  'waldur_slurm_association',
         ARRAY['username'],
         format($p$nullif(username, '') IS NOT NULL AND username !~ %L$p$,
                login_shape), 'FAIL'),
        ('login_slurm_alloc_usage',  'waldur_slurm_allocationuserusage',
         ARRAY['username'],
         format($p$nullif(username, '') IS NOT NULL AND username !~ %L$p$,
                login_shape), 'FAIL'),
        ('login_freeipa',            'waldur_freeipa_profile',
         ARRAY['username'],
         format($p$nullif(username, '') IS NOT NULL AND username !~ %L$p$,
                login_shape), 'FAIL'),
        ('login_keycloak_membership',
         'waldur_rancher_keycloakusergroupmembership', ARRAY['username'],
         format($p$nullif(username, '') IS NOT NULL AND username !~ %L$p$,
                login_shape), 'FAIL'),
        ('login_robot_account',      'marketplace_robotaccount',
         ARRAY['username'],
         format($p$nullif(username, '') IS NOT NULL AND username !~ %L$p$,
                login_shape), 'FAIL'),
        ('login_unix_username',      'core_user', ARRAY['unix_username'],
         format($p$nullif(unix_username, '') IS NOT NULL
                  AND unix_username !~ %L$p$, login_shape), 'FAIL'),

        -- names and personal attributes
        ('user_names_pseudonymised', 'core_user',
         ARRAY['first_name', 'last_name'],
         $p$first_name <> 'Person' OR last_name !~ '^Number[0-9]+$'$p$,
         'FAIL'),
        ('user_native_names_pseudonymised', 'core_user',
         ARRAY['native_name'],
         $p$nullif(native_name, '') IS NOT NULL
            AND native_name !~ '^Person Number[0-9]+$'$p$, 'FAIL'),
        ('usernames_pseudonymised',  'core_user', ARRAY['username'],
         format($p$username !~ %L$p$, login_shape), 'FAIL'),
        ('slugs_pseudonymised',      'core_user', ARRAY['slug'],
         format($p$slug !~ %L$p$, login_shape), 'FAIL'),
        ('invitation_names_pseudonymised', 'users_invitation',
         ARRAY['full_name'],
         $p$nullif(full_name, '') IS NOT NULL
            AND full_name !~ '^Person (Number[0-9]+|Redacted)$'$p$, 'FAIL'),
        ('civil_numbers_cleared',    'core_user', ARRAY['civil_number'],
         $p$civil_number IS NOT NULL$p$, 'FAIL'),
        ('birth_dates_cleared',      'core_user', ARRAY['birth_date'],
         $p$birth_date IS NOT NULL$p$, 'FAIL'),
        ('phone_numbers_cleared',    'core_user', ARRAY['phone_number'],
         $p$nullif(phone_number, '') IS NOT NULL$p$, 'FAIL'),
        ('idp_claim_blobs_cleared',  'core_user', ARRAY['details'],
         $p$details IS NOT NULL AND details::text NOT IN ('{}', 'null')$p$,
         'FAIL'),
        ('passwords_unusable',       'core_user', ARRAY['password'],
         $p$password <> '!'$p$, 'FAIL'),
        ('search_field_pseudonymised', 'core_user', ARRAY['query_field'],
         $p$nullif(query_field, '') IS NOT NULL
            AND query_field !~ '^Person Number[0-9]+ person[0-9]+$'$p$,
         'FAIL'),

        -- deployment configuration
        ('constance_holds_no_endpoints', 'constance_constance',
         ARRAY['key', 'value'],
         $p$(value ~ 'https?://'
             AND value !~ 'localhost|127\.0\.0\.1|example\.(com|org|net)')
            OR value ~ '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'$p$,
         'FAIL'),
        ('constance_deployment_keys_removed', 'constance_constance',
         ARRAY['key'],
         $p$key IN ('HOMEPORT_URL', 'SITE_EMAIL', 'SITE_PHONE',
                    'TELEMETRY_URL', 'DOCS_URL', 'SUPPORT_PORTAL_URL',
                    'K8S_NAMESPACE', 'DOCKER_SCRIPT_DIR',
                    'COMMON_FOOTER_TEXT', 'COMMON_FOOTER_HTML',
                    'JIRA_WEBHOOK_SHARED_SECRET', 'ORCID_CLIENT_SECRET',
                    'SEMANTIC_SCHOLAR_API_KEY', 'SCIM_API_URL',
                    'SCIM_API_KEY')
            OR key LIKE 'ATLASSIAN\_%' OR key LIKE 'ZAMMAD\_%'
            OR key LIKE 'SMAX\_%'$p$, 'FAIL'),
        ('django_site_is_local',     'django_site', ARRAY['domain'],
         $p$domain <> 'localhost:8000'$p$, 'FAIL'),
        ('service_settings_secrets_cleared', 'structure_servicesettings',
         ARRAY['password', 'token', 'backend_url'],
         $p$nullif(password, '') IS NOT NULL
            OR nullif(token, '') IS NOT NULL
            OR nullif(backend_url, '') IS NOT NULL$p$, 'FAIL'),
        ('stored_file_contents_dropped', 'media_file', ARRAY['content'],
         $p$octet_length(content) > 0$p$, 'FAIL'),

        -- the fork's proposal app, which exists only on the awards site: a
        -- skip everywhere else, and the whole of the database there
        ('proposal_text_filled',    'proposal_proposal', proposal_prose,
         (SELECT string_agg(format(prose_leak, c), ' OR ')
          FROM unnest(proposal_prose) AS c), 'FAIL'),
        ('proposal_description_filled', 'proposal_proposal',
         proposal_prose_fork,
         (SELECT string_agg(format(prose_leak, c), ' OR ')
          FROM unnest(proposal_prose_fork) AS c), 'FAIL'),
        ('proposal_reviews_filled', 'proposal_review',   review_prose,
         (SELECT string_agg(format(prose_leak, c), ' OR ')
          FROM unnest(review_prose) AS c), 'FAIL'),
        ('proposal_review_extras_filled', 'proposal_review', review_prose_fork,
         (SELECT string_agg(format(prose_leak, c), ' OR ')
          FROM unnest(review_prose_fork) AS c), 'FAIL'),
        ('proposal_review_comments_filled', 'proposal_reviewcomment',
         ARRAY['message'], format(prose_leak, 'message'), 'FAIL'),
        ('proposal_adjustments_filled', 'proposal_proposalresourceadjustment',
         ARRAY['comment'], format(prose_leak, 'comment'), 'FAIL'),
        -- The notes are a list of {timestamp, author, text}: the timestamps
        -- and the count survive on purpose, the text must not.
        ('proposal_notes_filled',   'proposal_proposal', ARRAY['notes'],
         $p$jsonb_typeof(notes) = 'array' AND EXISTS (
             SELECT 1 FROM jsonb_array_elements(notes) AS e
             WHERE nullif(e->>'text', '') IS NOT NULL
               AND e->>'text' <> left(
                     repeat('redacted placeholder text ',
                            (length(e->>'text') / 26) + 1),
                     length(e->>'text')))$p$, 'FAIL'),
        -- Applicants write their own names into filenames.
        ('proposal_docs_pathless',  'proposal_proposaldocumentation',
         ARRAY['file'], $p$nullif(file, '') IS NOT NULL$p$, 'FAIL'),
        ('proposal_call_docs_pathless', 'proposal_calldocument',
         ARRAY['file'], $p$nullif(file, '') IS NOT NULL$p$, 'FAIL'),

        -- tables that must be empty
        ('no_identity_providers', 'waldur_auth_social_identityprovider',
         ARRAY['id'], 'true', 'FAIL'),
        ('no_sessions',           'django_session', ARRAY['session_key'],
         'true', 'FAIL'),
        ('no_api_tokens',         'authtoken_token', ARRAY['key'],
         'true', 'FAIL'),
        ('no_personal_access_tokens', 'core_personalaccesstoken',
         ARRAY['id'], 'true', 'FAIL'),
        ('no_object_version_history', 'reversion_version', ARRAY['id'],
         'true', 'FAIL'),
        ('no_login_attempt_log',  'axes_accessattempt', ARRAY['id'],
         'true', 'FAIL'),
        ('no_email_hooks',        'logging_emailhook', ARRAY['email'],
         'true', 'FAIL'),
        ('no_database_cache',     'waldur_cache', ARRAY['cache_key'],
         'true', 'FAIL'),

        -- worth a look rather than a failure: the sink is where an address
        -- the harvest step does not read ends up. Safe, but it collapses
        -- distinct people onto one pseudonym.
        ('unmapped_address_sink', 'core_user', ARRAY['email'],
         $p$email = 'person0@example-org0.com'$p$, 'WARN')
        ) AS t(name, tbl, cols, pred, severity)
    LOOP
        SELECT to_regclass('public.' || quote_ident(r.tbl)) IS NOT NULL
               AND NOT EXISTS (
                   SELECT 1 FROM unnest(r.cols) AS c
                   WHERE NOT EXISTS (
                       SELECT 1 FROM information_schema.columns ic
                       WHERE ic.table_schema = 'public'
                         AND ic.table_name = r.tbl
                         AND ic.column_name = c))
        INTO present;

        IF NOT present THEN
            skip := skip + 1;
            RAISE NOTICE '| SKIP   | % | % |',
                rpad(r.name, 38), lpad('n/a', 12);
            CONTINUE;
        END IF;

        EXECUTE format('SELECT count(*) FROM public.%I WHERE %s',
                       r.tbl, r.pred) INTO n;

        IF n = 0 THEN
            pass := pass + 1;
            RAISE NOTICE '| PASS   | % | % |',
                rpad(r.name, 38), lpad(n::text, 12);
        ELSIF r.severity = 'WARN' THEN
            warn := warn + 1;
            RAISE NOTICE '| WARN   | % | % |',
                rpad(r.name, 38), lpad(n::text, 12);
        ELSE
            fail := fail + 1;
            RAISE NOTICE '| FAIL   | % | % |',
                rpad(r.name, 38), lpad(n::text, 12);
        END IF;
    END LOOP;

    ------------------------------------------------------------------
    -- The text columns that the ORM reads as JSON.
    --
    -- waldur_core.core.fields.JSONField is `text` in the database and a JSON
    -- document to Django, parsed on every READ. A value in one of these that
    -- does not parse breaks reading the row, and presents as a 500 that looks
    -- like a bug in the code rather than like bad data - which is the worst
    -- way for a sanitising artefact to show up, given the copy exists to test
    -- that code. The sanitiser repairs these; this is the assertion that it
    -- did.
    --
    -- IS JSON needs PostgreSQL 16. On an older server the check is skipped
    -- rather than approximated: a check that cannot run must not report PASS.
    ------------------------------------------------------------------
    FOREACH spec IN ARRAY ARRAY[
        'structure_project.termination_metadata',
        'structure_projectdigestconfiguration.enabled_sections',
        'logging_alert.context',
        'logging_emailhook.event_groups',
        'logging_emailhook.event_types',
        'logging_pushhook.event_groups',
        'logging_pushhook.event_types',
        'logging_webhook.event_groups',
        'logging_webhook.event_types',
        'logging_systemnotification.event_groups',
        'logging_systemnotification.event_types',
        'logging_systemnotification.roles',
        'user_actions_useraction.corrective_actions',
        'user_actions_useraction.metadata',
        'user_actions_useraction.route_params',
        'user_actions_useractionexecution.execution_metadata',
        'waldur_auth_saml2_identityprovider.metadata',
        'waldur_aws_instance.private_ips',
        'waldur_aws_instance.public_ips',
        'waldur_azure_virtualmachine.private_ips',
        'waldur_azure_virtualmachine.public_ips',
        'openstack_backup.metadata',
        'openstack_instance.action_details',
        'openstack_port.allowed_address_pairs',
        'openstack_port.fixed_ips',
        'openstack_router.external_fixed_ips',
        'openstack_router.fixed_ips',
        'openstack_router.routes',
        'openstack_snapshot.action_details',
        'openstack_snapshot.metadata',
        'openstack_subnet.allocation_pools',
        'openstack_subnet.dns_nameservers',
        'openstack_subnet.host_routes',
        'openstack_volume.action_details',
        'openstack_volume.image_metadata',
        'openstack_volume.metadata',
        'waldur_openstack_replication_migration.mappings'
    ] LOOP
        SELECT ic.udt_name INTO col_type
        FROM information_schema.columns ic
        WHERE ic.table_schema = 'public'
          AND ic.table_name = split_part(spec, '.', 1)
          AND ic.column_name = split_part(spec, '.', 2);

        -- Skip when the column is absent on this release, when the server is
        -- too old for IS JSON, or when this deployment declares the field as
        -- native json/jsonb rather than text. The last one is not just
        -- unnecessary - the database already guarantees such a value parses -
        -- but actively breaks the check: nullif(col, '') casts the empty
        -- string to the column's type, and ''::jsonb raises
        -- `invalid input syntax for type json`. The same field is text on one
        -- deployment and jsonb on another; logging_emailhook.event_groups is
        -- text on the portal and jsonb on the awards site.
        IF col_type IS NULL
           OR col_type NOT IN ('text', 'varchar', 'bpchar')
           OR current_setting('server_version_num')::int < 160000
        THEN
            skip := skip + 1;
            RAISE NOTICE '| SKIP   | % | % |',
                rpad(right('json:' || spec, 38), 38), lpad('n/a', 12);
            CONTINUE;
        END IF;

        EXECUTE format(
            'SELECT count(*) FROM public.%I
             WHERE nullif(%I, '''') IS NOT NULL AND %I IS NOT JSON',
            split_part(spec, '.', 1), split_part(spec, '.', 2),
            split_part(spec, '.', 2)) INTO n;

        IF n = 0 THEN
            pass := pass + 1;
            RAISE NOTICE '| PASS   | % | % |',
                rpad(right('json:' || spec, 38), 38), lpad(n::text, 12);
        ELSE
            fail := fail + 1;
            RAISE NOTICE '| FAIL   | % | % |',
                rpad(right('json:' || spec, 38), 38), lpad(n::text, 12);
        END IF;
    END LOOP;

    RAISE NOTICE '|--------|----------------------------------------|--------------|';
    RAISE NOTICE '';
    RAISE NOTICE '% checks: % passed, % failed, % warned, % skipped',
        pass + fail + warn + skip, pass, fail, warn, skip;

    ------------------------------------------------------------------
    -- Scale, so the copy can be compared against production for realism.
    ------------------------------------------------------------------
    RAISE NOTICE '';
    RAISE NOTICE '-- scale --';
    FOR r IN
        SELECT * FROM (VALUES
            ('people',        'core_user'),
            ('organisations', 'structure_customer'),
            ('projects',      'structure_project'),
            ('resources',     'marketplace_resource'),
            ('events',        'logging_event'),
            ('invoices',      'invoices_invoice')
        ) AS t(metric, tbl)
    LOOP
        IF to_regclass('public.' || quote_ident(r.tbl)) IS NULL THEN
            RAISE NOTICE '  % %', rpad(r.metric, 16), 'n/a';
            CONTINUE;
        END IF;
        EXECUTE format('SELECT count(*) FROM public.%I', r.tbl) INTO n;
        RAISE NOTICE '  % %', rpad(r.metric, 16), n;
    END LOOP;

    RAISE NOTICE '';
    IF fail > 0 THEN
        RAISE NOTICE 'There are failures above. The dump must not be used:';
        RAISE NOTICE 'fix the sanitiser and re-run from the original dump.';
    ELSE
        RAISE NOTICE 'Nothing failed.';
    END IF;
    RAISE NOTICE '';
END $verify$;

COMMIT;
