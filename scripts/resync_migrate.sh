#!/bin/bash
# Apply the upstream-resync migration, in the one order that works.
#
# Run this AFTER scripts/resync_reconcile_db.sql, instead of a plain `migrate`.
#
#   scripts/resync_migrate.sh --manage \
#       'docker compose run --rm --no-deps -T --entrypoint waldur waldur-mastermind-api'
#
#   scripts/resync_migrate.sh --manage 'uv run python -m waldur_core.server.manage'
#
# RUN THIS WITH THE APPLICATION DOWN, DATABASE ONLY
#
# `run --rm`, not `exec`: exec needs a container already running, and a running
# API container is precisely what you do not want. Waldur migrates at startup,
# so an API container that is up has already migrated - or tried to and failed -
# and this script would be racing it. The workers and beat are worse: they would
# be reading and writing a schema that is changing underneath them.
#
# --no-deps stops `docker compose run` starting the queue, worker and beat as
# linked services. Bring up waldur-db on its own, run the reconciliation, run
# this, then `docker compose up -d`. By then every migration is applied and the
# API's own startup migrate is a no-op.
#
# WHY NOT JUST `migrate`
#
# Five upstream waldur_openportal migrations (0035-0039) create objects this
# fork's own 0034-0043 already created, so they have to be recorded as applied
# without running. The obvious way to do that - INSERT the rows into
# django_migrations alongside the rest of the reconciliation - is wrong:
#
#   upstream 0036_remote_projects depends on
#   structure.0078_alter_servicesettings_certificate
#
# which production has not applied. Django checks that every applied migration
# has its dependencies applied, before doing anything at all, so inserting
# those rows makes EVERY migrate invocation fail - including migrate --plan:
#
#   InconsistentMigrationHistory: Migration waldur_openportal.0036_remote_projects
#   is applied before its dependency structure.0078_alter_servicesettings_certificate
#
# Only Django knows the dependency graph, so only Django can fake a migration
# at a point where the graph is satisfied. Hence this script rather than more
# SQL.
#
# THE ORDER
#
#   1. migrate structure          forward, no target. This brings in
#                                 0078_alter_servicesettings_certificate, which
#                                 openportal 0036 depends on. That migration is
#                                 an AlterField adding validators to a
#                                 FileField, so it is DDL-free - but Django
#                                 still requires it recorded before anything
#                                 that depends on it.
#   2. migrate waldur_openportal 0034
#                                 for real: it adds can_be_managed to allocation
#                                 and remoteallocation, columns this fork never
#                                 had, because upstream's models gain them from
#                                 core_models.AvailableMixin. Faking it would
#                                 leave the columns missing and the schema
#                                 quietly wrong.
#   3. migrate waldur_openportal 0039 --fake
#                                 records 0035-0039 without running them.
#   4. migrate proposal_archive   creates the archive tables. Its migration
#                                 depends on nothing, deliberately, so it can
#                                 be applied while the proposal app is absent
#                                 from the history - which is exactly where the
#                                 awards site is at this point.
#   5. archive_old_proposals      copies old_proposal_* into the archive, and
#                                 captures the role assignments that step 6 is
#                                 about to cascade away. Skipped where there is
#                                 nothing to archive, i.e. on the portal.
#   6. delete_old_proposal_roles  the fork's PROPOSAL.* and CALL.* roles live in
#                                 permissions_role, which the reconciliation
#                                 does not touch, so on a site that ran the
#                                 fork's proposal app they survive. Upstream's
#                                 0040_migrate_default_project_role then does
#                                 Role.objects.get(name="PROPOSAL.MANAGER") and
#                                 dies with MultipleObjectsReturned, rolling the
#                                 whole squash back. A no-op on the portal,
#                                 which never had them.
#   7. migrate                    everything else, including upstream's
#                                 proposal 0047-0077 against empty tables.
#   8. seed_award_id_generator    raises the new award ID counters past every
#                                 award ID already issued. A new counter starts
#                                 at zero, so without this the first proposal
#                                 of the year would be given the award ID of
#                                 the first old one. After step 7 because the
#                                 counter's table is created there. Finds
#                                 nothing to do on the portal, which never
#                                 issued award IDs.
#   9. backfill_remote_project_attachments
#                                 gives every award's attachments the key its
#                                 usage is cached under, and a true start date.
#                                 An award's usage is filed under the identifier
#                                 of whichever project held it, so without the
#                                 keys an award's history cannot be found; and
#                                 an award predating attachment tracking has a
#                                 first attachment stamped when tracking began,
#                                 which would clip away all its earlier usage.
#                                 After step 7, which adds the key column.
#                                 Idempotent.
#  10. grace period backfill      structure/0067 added Customer.grace_period_days
#                                 and Project.grace_period_days as nullable
#                                 columns with no default, replacing a property
#                                 that returned a fixed 30 days. Every existing
#                                 row is therefore NULL, which means zero, and
#                                 everything sitting in its grace period expires
#                                 the moment this deployment lands. Backfilled
#                                 here rather than in a migration under
#                                 waldur_core/structure: that directory is
#                                 upstream's, and a local migration in it is one
#                                 stray merge request away from being pushed
#                                 back. scripts/ is unambiguously ours.
#  11. makemigrations --check     proves the result matches the models, which
#                                 is what catches a fake whose objects did not
#                                 actually match.
set -euo pipefail

usage() {
    sed -n '2,/^set -euo/p' "$0" | sed 's/^# \?//;$d'
    exit "${1:-1}"
}

MANAGE=""
while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help) usage 0 ;;
        --manage) MANAGE="${2:-}"; shift 2 ;;
        *) echo "ERROR: unexpected argument $1" >&2; usage ;;
    esac
done

if [ -z "$MANAGE" ]; then
    MANAGE="${WALDUR_MANAGE:-}"
fi
if [ -z "$MANAGE" ]; then
    echo "ERROR: give --manage with whatever runs Waldur's manage command," >&2
    echo "       e.g. --manage 'docker compose exec -T waldur-mastermind-api waldur'" >&2
    exit 1
fi

START_EPOCH=$(date +%s)
say() {
    local secs=$(( $(date +%s) - START_EPOCH ))
    printf '\n==> [%s | +%dm%02ds] %s\n' "$(date +%H:%M:%S)" \
        $((secs / 60)) $((secs % 60)) "$*"
}

# `migrate app NNNN` migrates TO that migration - which on a database already
# past it means UNAPPLYING everything after it. On a production database
# behind 0078 that is what we want; on one already ahead it would start
# reversing real migrations and removing fields. So every step checks first,
# which also makes the script safe to re-run after a failure part-way through.
is_applied() {
    # NOT showmigrations. Once a squashed migration is applied it lists only
    # the squash - " [X] 0001_squashed_0039 (12 squashed migrations)" - and
    # never the individual migrations it replaced, so grepping for the name of
    # a replaced migration finds nothing and the guard reports "not applied"
    # for something that is. Steps 2 and 3 then run `migrate app NNNN` against
    # a database already past NNNN, which is a migrate-TO, i.e. an UNAPPLY, and
    # it dies building the historical state:
    #
    #   KeyError: 'competence'
    #
    # exactly the failure these guards exist to prevent. Found by running this
    # script a second time against a database it had already migrated.
    #
    # Django's own loader resolves replacements - a replaced migration reads as
    # applied when its squash is - so ask it rather than parsing output meant
    # for humans.
    #
    # The name must be EXACT, unlike the prefix match the grep allowed.
    $MANAGE shell -c "
from django.db import connection
from django.db.migrations.loader import MigrationLoader
loader = MigrationLoader(connection)
print('APPLIED' if ('$1', '$2') in loader.applied_migrations else 'PENDING')
" 2>/dev/null | grep -q '^APPLIED$'
}

# What `run` echoes before the command. A payload passed with `shell -c` is a
# whole script, and echoing it buries the step's real output under a hundred
# lines of source in a log someone reads during a deployment window.
RUN_LABEL=""

run() {
    echo "    \$ ${RUN_LABEL:-$MANAGE $*}"
    # Timestamped, so subtracting gives the per-migration cost that a
    # deployment window is built from. Django does not report it.
    $MANAGE "$@" 2>&1 | while IFS= read -r line; do
        printf '    %s %s\n' "$(date +%H:%M:%S)" "$line"
    done
    return "${PIPESTATUS[0]}"
}

say "1/11  structure forward (brings in openportal 0036's dependency)"
# `migrate structure` with no target, deliberately. Naming 0078 would be
# precise but breaks two ways: on a database already past it, migrating TO a
# migration means UNAPPLYING everything after it - Django starts reversing real
# migrations and removing fields - and structure is squashed
# (0041_squashed_0085 replaces 0042-0085, 0078 among them), so the name may not
# even be a node Django will accept as a target. Migrating the app forward is
# idempotent, never unapplies, and needs no knowledge of the squash.
run migrate structure

say "2/11  openportal 0034 for real (adds can_be_managed)"
if is_applied waldur_openportal 0034_allocation_can_be_managed_and_more; then
    echo "    already applied, skipping"
else
    run migrate waldur_openportal 0034
fi

say "3/11  openportal 0035-0039 faked (their objects already exist)"
if is_applied waldur_openportal 0039_alter_remoteprojectattachment_options; then
    echo "    already recorded, skipping"
else
    run migrate waldur_openportal 0039 --fake
fi

say "4/11  create the proposal archive tables"
run migrate proposal_archive

# Steps 5 and 6 belong to the awards site. The portal has no old_proposal_*
# tables and no proposal roles, so both are no-ops there and the script stays
# one script for both sites.
#
# They also have to be skipped once the replay has run: after step 7 the
# proposal roles in permissions_role are UPSTREAM's, and deleting those on a
# re-run would take the new site's own role assignments with them.
if is_applied proposal 0001_squashed_0074; then
    say "5/11  archive the fork's proposal data"
    echo "    the proposal app is already migrated, so any roles now present"
    echo "    are upstream's - skipping the archive and the role deletion"
    say "6/11  delete the fork's proposal roles"
    echo "    skipped, see above"
elif ! $MANAGE shell -c "
from django.db import connection
with connection.cursor() as cursor:
    cursor.execute(\"SELECT to_regclass('old_proposal_call')\")
    print('PRESENT' if cursor.fetchone()[0] else 'ABSENT')
" 2>/dev/null | grep -q '^PRESENT$'; then
    say "5/11  archive the fork's proposal data"
    echo "    no old_proposal_* tables - nothing to archive"
    say "6/11  delete the fork's proposal roles"
    run delete_old_proposal_roles
else
    say "5/11  archive the fork's proposal data"
    run archive_old_proposals

    say "6/11  delete the fork's proposal roles"
    # Refuses unless step 5 captured the memberships, so an archive that
    # silently copied nothing cannot be followed by an irreversible delete.
    run delete_old_proposal_roles
fi

say "7/11  everything else"
run migrate --noinput

say "8/11  seed the award ID counters"
# Only ever raises a counter, never lowers one, so it is safe to re-run.
run seed_award_id_generator

say "9/11  give award attachments their usage keys and true start dates"
run backfill_remote_project_attachments

say "10/11  restore the 30-day grace period"
# scripts/set_default_grace_period.py reads GRACE_APPLY from the environment,
# and $MANAGE may well be a `docker compose run` that passes none through, so
# the variable is set in the payload itself rather than around the command.
# Only NULL rows are touched, so this is idempotent and safe to re-run.
GRACE_SCRIPT="$(dirname "$0")/set_default_grace_period.py"
if [ ! -f "$GRACE_SCRIPT" ]; then
    echo "ERROR: cannot find $GRACE_SCRIPT" >&2
    exit 1
fi
RUN_LABEL="$MANAGE shell -c \"\$(cat scripts/set_default_grace_period.py)\""
run shell -c "import os; os.environ['GRACE_APPLY'] = '1'
$(cat "$GRACE_SCRIPT")"
RUN_LABEL=""

say "11/11  does the schema match the models?"
if run makemigrations --check --dry-run; then
    say "Done. No changes detected: the schema matches the models."
else
    echo >&2
    echo "ERROR: makemigrations wants to create a migration, so the schema" >&2
    echo "       does not match the models. Something that was faked did not" >&2
    echo "       in fact already exist in the shape upstream expects. Do not" >&2
    echo "       deploy on this result; send the diff for a look." >&2
    exit 1
fi
