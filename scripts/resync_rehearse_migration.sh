#!/bin/bash
# Rehearse the upstream-resync migration against a copy of production.
#
#   scripts/resync_rehearse_migration.sh --datadir <the sanitise cluster>
#
#   scripts/resync_rehearse_migration.sh --datadir <dir> --in-place
#
# --in-place skips the copy and rehearses on the sanitised database itself.
# Use it when the filesystem cannot hold a second copy - a copy needs as much
# space again as the database, and the sanitising run will already have filled
# a good part of the disk. It is destructive to the sanitised database, which
# is acceptable because the sanitised DUMP reproduces it in minutes; make sure
# you have that dump, and preferably off this machine, first.
#
# Runs, in order, against a COPY of the sanitised database:
#
#   1. scripts/resync_preflight_check.sql   (read-only)
#   2. scripts/resync_reconcile_db.sql      (the one-time reconciliation)
#   3. manage.py migrate                    (upstream's history replayed)
#   4. manage.py makemigrations --check     (must report no changes)
#   5. scripts/resync_smoke_test.py         (every model reads back)
#
# WHY A COPY
#
# It works on waldur_rehearsal, created from waldur_sanitise with CREATE
# DATABASE ... TEMPLATE - a filesystem copy, so it costs disk rather than the
# hours a re-restore would. The sanitised database is left untouched, which
# means the rehearsal can be repeated as often as it takes: every fix gets a
# clean starting point, and the copy takes seconds.
#
# The point of rehearsing here rather than after shipping the dump to a laptop
# is that this is the same data at the same scale, and it is already in a
# database. If something is wrong with it, you find out before the slow path.
#
# WHAT IT NEEDS
#
# psql, and a Python that can import waldur. It looks for, in order:
#
#   $WALDUR_MANAGE    a command prefix you provide, e.g.
#                     "uv run python -m waldur_core.server.manage" or
#                     "docker run --rm ... waldur"
#   .venv/bin/python  in the checkout
#   uv                in which case it runs uv run
#
# Steps 1 and 2 need only psql. If no Python is found the script stops after
# them, having left the reconciled copy in place and told you what to run.
# That is still worth doing on its own: the pre-flight is what says whether the
# irreversible column drops would lose anything.
#
# SETTINGS
#
# waldur_core.server.rehearsal_settings, which is base_settings plus a database
# connection from the environment - deliberately NOT test_settings, which adds
# three test apps whose migrations would create tables production never has.
# Override with DJANGO_SETTINGS_MODULE if your deployment's own settings module
# is importable here; that is closer still.
#
# ENVIRONMENT
#
#   --datadir DIR      the temporary cluster from sanitise_production_dump.sh
#                      --own-server; started if it is not running
#   SOURCE_DB          database to copy from (default waldur_sanitise)
#   REHEARSAL_DB       database to create        (default waldur_rehearsal)
#   KEEP_REHEARSAL=1   keep an existing REHEARSAL_DB instead of recreating it,
#                      to resume after a failure part-way through migrate
#   --in-place         rehearse on the sanitised database itself, no copy
#   PG_BIN             directory holding pg_ctl, if not on PATH
#   REHEARSAL_LOG_DIR  where the three logs go (default: working directory)
set -euo pipefail

usage() {
    sed -n '2,/^set -euo/p' "$0" | sed 's/^# \?//;$d'
    exit "${1:-1}"
}

DATADIR=""
IN_PLACE=0
while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help) usage 0 ;;
        --datadir) DATADIR="${2:-}"; shift 2 ;;
        --in-place) IN_PLACE=1; shift ;;
        *) echo "ERROR: unexpected argument $1" >&2; usage ;;
    esac
done

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
# Not the repo root: logs there turn up in git status. The working directory by
# default, so they land wherever you ran this from.
LOG_DIR="${REHEARSAL_LOG_DIR:-$PWD}"
mkdir -p "$LOG_DIR"
SOURCE_DB="${SOURCE_DB:-waldur_sanitise}"
REHEARSAL_DB="${REHEARSAL_DB:-waldur_rehearsal}"

START_EPOCH=$(date +%s)
elapsed() {
    local secs=$(( $(date +%s) - START_EPOCH ))
    printf '%dh%02dm%02ds' $((secs / 3600)) $(((secs % 3600) / 60)) \
        $((secs % 60))
}
say() {
    printf '\n==> [%s | +%s] %s\n' "$(date +%H:%M:%S)" "$(elapsed)" "$*"
}

find_pg_bin() {
    if [ -n "${PG_BIN:-}" ]; then echo "$PG_BIN"; return 0; fi
    if command -v pg_ctl >/dev/null 2>&1; then
        dirname "$(command -v pg_ctl)"; return 0
    fi
    local dir
    # shellcheck disable=SC2012
    for dir in $(ls -d /usr/lib/postgresql/*/bin /usr/pgsql-*/bin \
                       /usr/local/pgsql/bin 2>/dev/null | sort -rV); do
        if [ -x "$dir/pg_ctl" ]; then echo "$dir"; return 0; fi
    done
    return 1
}

if [ -n "$DATADIR" ]; then
    DATADIR="$(cd "$DATADIR" && pwd)"
    if [ ! -f "$DATADIR/PG_VERSION" ]; then
        echo "ERROR: $DATADIR is not a PostgreSQL data directory." >&2
        exit 1
    fi
    BIN="$(find_pg_bin)" || { echo "ERROR: no pg_ctl found." >&2; exit 1; }
    if ! "$BIN/pg_ctl" -D "$DATADIR" status >/dev/null 2>&1; then
        say "Starting the cluster in $DATADIR"
        "$BIN/pg_ctl" -D "$DATADIR" -l "$DATADIR.server.log" -w \
            -o "-c listen_addresses='' -k $DATADIR -c fsync=off" start \
            >/dev/null
    fi
    export PGHOST="$DATADIR"
    export PGPORT=5432
    PGUSER="$(id -un)"
    export PGUSER
    unset PGPASSWORD PGSERVICE PGDATABASE PGPASSFILE
fi

# Where the data actually lives, for the free-space check. The data directory
# when we know it, otherwise ask the server.
if [ -n "$DATADIR" ]; then
    DATADIR_FOR_DF="$DATADIR"
else
    DATADIR_FOR_DF="$(psql -tAq -d postgres -c 'SHOW data_directory' \
        2>/dev/null || echo /)"
fi

if ! psql -tAq -d postgres -c 'SELECT 1' >/dev/null 2>&1; then
    echo "ERROR: cannot connect to PostgreSQL. Pass --datadir, or set" >&2
    echo "       PGHOST/PGPORT/PGUSER for the cluster holding $SOURCE_DB." >&2
    exit 1
fi

exists() {
    [ "$(psql -tAq -d postgres -c \
        "SELECT count(*) FROM pg_database WHERE datname = '$1'")" = "1" ]
}

if ! exists "$SOURCE_DB"; then
    echo "ERROR: no database called $SOURCE_DB in this cluster." >&2
    echo "       Set SOURCE_DB, or check you passed the right --datadir." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# The copy.
# ---------------------------------------------------------------------------
SOURCE_BYTES="$(psql -tAq -d postgres -c \
    "SELECT pg_database_size('$SOURCE_DB')")"
SOURCE_MB=$(( SOURCE_BYTES / 1048576 ))

if [ "$IN_PLACE" = "1" ]; then
    say "Rehearsing IN PLACE on $SOURCE_DB (no copy)"
    echo "    this is destructive to $SOURCE_DB. It is reproducible from the"
    echo "    sanitised dump in minutes, so make sure you have that dump -"
    echo "    ideally off this machine - before continuing."
    REHEARSAL_DB="$SOURCE_DB"
elif exists "$REHEARSAL_DB" && [ "${KEEP_REHEARSAL:-0}" = "1" ]; then
    say "Reusing the existing $REHEARSAL_DB (KEEP_REHEARSAL=1)"
else
    # A TEMPLATE copy needs as much space again as the database, and the
    # sanitising run has usually just filled a good part of the disk. Checking
    # first turns "out of space half way through" into a clear refusal, and
    # names the way out.
    AVAIL_MB=$(df -Pk "$DATADIR_FOR_DF" 2>/dev/null \
        | awk 'NR==2 {print int($4 / 1024)}')
    say "Copying $SOURCE_DB to $REHEARSAL_DB"
    echo "    $SOURCE_DB is ${SOURCE_MB} MB; ${AVAIL_MB:-?} MB free"
    if [ -n "${AVAIL_MB:-}" ] && [ "$AVAIL_MB" -lt "$SOURCE_MB" ]; then
        echo >&2
        echo "ERROR: not enough space for a copy: the database is" >&2
        echo "       ${SOURCE_MB} MB and only ${AVAIL_MB} MB is free." >&2
        echo >&2
        echo "       Either free some space, or rehearse without a copy:" >&2
        echo >&2
        echo "         $0 ${DATADIR:+--datadir $DATADIR} --in-place" >&2
        echo >&2
        echo "       --in-place is destructive to $SOURCE_DB, which is fine" >&2
        echo "       if you still have the sanitised dump: restoring it takes" >&2
        echo "       minutes against the hours the sanitising took." >&2
        exit 1
    fi
    echo "    a TEMPLATE copy: a filesystem copy, not a restore"
    psql -q -d postgres -c "DROP DATABASE IF EXISTS \"$REHEARSAL_DB\""
    # CREATE DATABASE ... TEMPLATE needs no other session connected to the
    # template.
    if ! psql -q -d postgres \
        -c "CREATE DATABASE \"$REHEARSAL_DB\" TEMPLATE \"$SOURCE_DB\""; then
        echo >&2
        echo "ERROR: the copy failed. Check, in this order:" >&2
        echo "  1. free space - df on the filesystem holding the cluster." >&2
        echo "     A full disk breaks this in ways whose error messages point" >&2
        echo "     somewhere else entirely, including 'buffer is pinned in" >&2
        echo "     InvalidateBuffer'." >&2
        echo "  2. another session connected to $SOURCE_DB, which a TEMPLATE" >&2
        echo "     copy does not allow. Check with:" >&2
        echo "       psql -d postgres -c \"SELECT pid, application_name FROM" >&2
        echo "         pg_stat_activity WHERE datname = '$SOURCE_DB'\"" >&2
        echo >&2
        echo "  Or skip the copy entirely with --in-place." >&2
        exit 1
    fi
    echo "    $(psql -tAq -d "$REHEARSAL_DB" -c \
        "SELECT pg_size_pretty(pg_database_size('$REHEARSAL_DB'))") copied"
fi

# ---------------------------------------------------------------------------
# 1. Pre-flight. Read-only, and its output carries no personal data, so it is
#    safe to share.
# ---------------------------------------------------------------------------
say "Pre-flight check (read-only)"
PREFLIGHT_LOG="$LOG_DIR/rehearsal-preflight.log"
psql -v ON_ERROR_STOP=1 -d "$REHEARSAL_DB" \
     -f "$HERE/resync_preflight_check.sql" 2>&1 | tee "$PREFLIGHT_LOG"

# The status cell of a result row, not the word FAIL in the closing
# explanation the pre-flight prints - which an earlier version matched.
if grep -qE '\| *FAIL *\|' "$PREFLIGHT_LOG"; then
    echo >&2
    echo "The pre-flight reported FAIL. That is the point of running it:" >&2
    echo "resolve it before reconciling, here and in production." >&2
    echo "Output saved to $PREFLIGHT_LOG" >&2
    exit 1
fi
echo "    saved to $PREFLIGHT_LOG"

# ---------------------------------------------------------------------------
# 2. The reconciliation.
# ---------------------------------------------------------------------------
say "Reconciling (scripts/resync_reconcile_db.sql)"
psql -v ON_ERROR_STOP=1 -d "$REHEARSAL_DB" \
     -f "$HERE/resync_reconcile_db.sql"

# ---------------------------------------------------------------------------
# 3. migrate, if there is a Python that can run it.
# ---------------------------------------------------------------------------
MANAGE=""
if [ -n "${WALDUR_MANAGE:-}" ]; then
    MANAGE="$WALDUR_MANAGE"
elif [ -x "$ROOT/.venv/bin/python" ]; then
    MANAGE="$ROOT/.venv/bin/python -m waldur_core.server.manage"
elif command -v uv >/dev/null 2>&1; then
    MANAGE="uv run python -m waldur_core.server.manage"
fi

if [ -z "$MANAGE" ]; then
    say "No Python found, so stopping before migrate"
    cat <<EOT

The copy is reconciled and ready. To finish the rehearsal, run the migration
against it from anywhere that can import waldur:

  export WALDUR_DB_HOST='${PGHOST:-localhost}'
  export WALDUR_DB_PORT='${PGPORT:-5432}'
  export WALDUR_DB_NAME='$REHEARSAL_DB'
  export WALDUR_DB_USER='${PGUSER:-waldur}'
  export DJANGO_SETTINGS_MODULE=waldur_core.server.rehearsal_settings
  <python> -m waldur_core.server.manage migrate
  <python> -m waldur_core.server.manage makemigrations --check --dry-run

Or re-run this script with WALDUR_MANAGE set to whatever runs it, plus
KEEP_REHEARSAL=1 so it does not start over:

  KEEP_REHEARSAL=1 WALDUR_MANAGE='uv run python -m waldur_core.server.manage' \\
      $0 ${DATADIR:+--datadir $DATADIR}

The pre-flight output is the part worth reading either way: $PREFLIGHT_LOG
EOT
    exit 0
fi

export WALDUR_DB_HOST="${PGHOST:-localhost}"
export WALDUR_DB_PORT="${PGPORT:-5432}"
export WALDUR_DB_NAME="$REHEARSAL_DB"
export WALDUR_DB_USER="${PGUSER:-waldur}"
export WALDUR_DB_PASSWORD="${PGPASSWORD:-}"
export DJANGO_SETTINGS_MODULE="${DJANGO_SETTINGS_MODULE:-waldur_core.server.rehearsal_settings}"

say "Migrating with: $MANAGE"
echo "    settings: $DJANGO_SETTINGS_MODULE"

MIGRATE_LOG="$LOG_DIR/rehearsal-migrate.log"
cd "$ROOT"

say "What will run"
$MANAGE migrate --plan 2>&1 | tee "$LOG_DIR/rehearsal-plan.log" | tail -5
# The plan lists each migration as app.NNNN_name at column zero, with its
# operations indented beneath - no [ ] markers to count.
echo "    $(grep -cE '^[a-z_]+\.[0-9]{4}' "$LOG_DIR/rehearsal-plan.log" \
        || true) migrations in the plan; full list in" \
     "$LOG_DIR/rehearsal-plan.log"

say "Applying"
# Each line is stamped, so subtracting timestamps gives the per-migration cost
# - which is the number the deployment window is built from. Django does not
# report it itself.
$MANAGE migrate --noinput 2>&1 \
    | while IFS= read -r line; do
          printf '%s %s\n' "$(date +%H:%M:%S)" "$line"
      done \
    | tee "$MIGRATE_LOG"

if grep -qiE 'Traceback|^[0-9:]+ *[A-Za-z.]*Error' "$MIGRATE_LOG"; then
    echo >&2
    echo "ERROR: migrate reported a failure; see $MIGRATE_LOG" >&2
    exit 1
fi

say "The slowest migrations"
# Timestamps in, durations out. Anything over a second is worth knowing about.
awk '{
    t = $1; split(t, p, ":"); now = p[1] * 3600 + p[2] * 60 + p[3]
    if (prev_line ~ /Applying/) {
        d = now - prev
        if (d < 0) d += 86400
        if (d >= 1) printf "%6ds  %s\n", d, prev_desc
    }
    prev = now; prev_line = $0
    prev_desc = $0; sub(/^[0-9:]+ +/, "", prev_desc)
}' "$MIGRATE_LOG" | sort -rn | head -15
echo "    (nothing listed means every migration took under a second)"

say "Checking the schema matches the models"
if $MANAGE makemigrations --check --dry-run; then
    echo "    No changes detected - the schema matches the models."
else
    echo >&2
    echo "ERROR: makemigrations wants to create a migration, which means the" >&2
    echo "       reconciled schema does not match the models. Resolve this" >&2
    echo "       before deploying: it is the check that catches a faked" >&2
    echo "       migration whose DDL never actually ran." >&2
    exit 1
fi

say "6/6  Reading every model through the ORM"
# Django's field converters run on READ. A column holding something its field
# cannot parse is invisible until something reads the row, and then it is a
# 500 from whatever page touched it - nothing in the migration itself looks.
if $MANAGE shell -c "$(cat "$HERE/resync_smoke_test.py")"; then
    :
else
    echo >&2
    echo "ERROR: at least one model could not be read. On a database that has" >&2
    echo "       been rewritten by hand, the usual cause is a column holding" >&2
    echo "       something its field cannot parse - a text-backed JSONField" >&2
    echo "       with prose in it, say. Fix that before drawing conclusions" >&2
    echo "       about the migration." >&2
    exit 1
fi

say "Rehearsal complete in $(elapsed)"
cat <<EOT

  pre-flight   $PREFLIGHT_LOG
  plan         $LOG_DIR/rehearsal-plan.log
  migrate      $MIGRATE_LOG

$REHEARSAL_DB is left in place, now migrated.
EOT
if [ "$IN_PLACE" = "1" ]; then
    cat <<EOT
That was $SOURCE_DB itself, so there is no longer an unmigrated sanitised
database here. Restore the sanitised dump if you need one again - minutes,
against the hours the sanitising took.
EOT
else
    cat <<EOT
To rehearse again from the unmigrated copy, just re-run this script: it
recreates the copy from $SOURCE_DB, which is untouched.
EOT
fi
