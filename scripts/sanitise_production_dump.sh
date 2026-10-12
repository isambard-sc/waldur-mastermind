#!/bin/bash
# Turn a production Waldur dump into test data that can be loaded locally.
#
#   scripts/sanitise_production_dump.sh production.sql.gz sanitised.sql.gz
#
# It restores the production dump into a throwaway database, rewrites it, checks
# the result, and only then writes the output dump. If any check fails it stops
# and writes nothing.
#
#   scripts/sanitise_production_dump.sh --own-server prod.sql.gz clean.sql.gz
#
#   scripts/sanitise_production_dump.sh --reuse-server <datadir> \
#       prod.sql.gz clean.sql.gz
#
# --reuse-server picks up a cluster an earlier --own-server run left behind and
# skips the restore. The sanitiser is one transaction, so a failure rolls back
# completely and leaves the restored copy pristine: after fixing whatever went
# wrong, this re-runs against it in seconds rather than restoring tens of
# gigabytes again. It starts the cluster if it is not running, and leaves it
# alone afterwards - you named it, so removing it is your call.
#
# --own-server does not touch any existing PostgreSQL: it runs initdb into a
# temporary directory, starts a private server there, does the work, and
# destroys the whole cluster afterwards. Use this anywhere you would rather not
# be creating scratch databases - a production server, or a shared access node.
# It needs no superuser rights and no configuration: the cluster belongs to
# whoever runs the script.
#
# WHY NOT MERGE TWO DUMPS
#
# The obvious shape for this is "splice the local dump's settings into the
# production dump", but that means editing COPY blocks as text, keeping foreign
# keys in order and fixing up sequences, and a single missed row leaks the thing
# the exercise was meant to remove. Restoring into a scratch database and
# rewriting it with SQL gets the database itself to enforce consistency, and the
# result can be verified before anyone sees it.
#
# NOTHING FROM THE LOCAL DUMP IS NEEDED
#
# The deployment-specific settings you were worried about are not merged in from
# the local dump - they are removed, and a local instance then falls back to its
# own configuration:
#
#   * Constance settings (HOMEPORT_URL, the helpdesk URLs and tokens, the SCIM
#     and ORCID credentials) live in constance_constance. Deleting a row makes
#     Constance use the default from the local CONSTANCE_CONFIG, so removing
#     them is the same as adopting the local values, without having to graft
#     rows between two databases.
#   * The identity providers, including the keycloak client secret and every
#     realm endpoint, are deleted. Configure the local instance's own.
#   * Mail relay credentials are NOT in the database at all. Waldur reads
#     EMAIL_HOST, EMAIL_HOST_USER and EMAIL_HOST_PASSWORD from settings and the
#     environment (see src/waldur_core/core/email_diagnostics.py), so a dump
#     never carried them.
#
# You will have no way to log in to the result, because every password is
# replaced with an unusable hash and every identity provider is gone. Create an
# account after loading it:
#
#   docker compose exec waldur-mastermind-api \
#       waldur createsuperuser --username admin --email admin@example.com
#
# REQUIREMENTS
#
#   psql and pg_dump, plus either a PostgreSQL server you can create databases
#   on, or - with --own-server - initdb and pg_ctl, which ship with the server
#   package. The scratch database, or the whole temporary cluster, is created
#   and destroyed by this script.
#
# DISK SPACE FOR --own-server
#
# The temporary cluster holds the whole database twice over by the end (the
# restored copy, plus what VACUUM has not yet reclaimed), so allow roughly ten
# times the size of the compressed input, and more if the dump compresses
# unusually well. By default it goes next to the OUTPUT file, on the assumption
# that you chose somewhere with room for the result; SANITISE_PGDATA moves it.
# The script prints what it needs and what is free before starting.
#
# HOW LONG IT TAKES
#
# The JSON sweep dominates and is linear in row count - roughly 900 rows per
# second on documents the size of OpenPortal's project payloads. It reports its
# plan before starting (column count, total rows, a first estimate) and then a
# refined ETA after each column, so within a minute of that step beginning you
# know whether this is a coffee or an overnight job.
#
# Every step is stamped with the wall-clock time and the elapsed total, so the
# output of an unattended run reads back as a log. Install `pv` if you want a
# live throughput bar on the restore and the final dump as well.
#
# For a run that will take hours, start it under tmux or screen (or nohup): the
# script cleans up after itself if its shell goes away, which means a dropped
# SSH connection would otherwise end the run.
#
# ENVIRONMENT
#
#   PGHOST, PGPORT, PGUSER, PGPASSWORD  as for any libpq client. Ignored under
#                    --own-server, which points them at its own cluster.
#   SANITISE_DB      name of the scratch database (default waldur_sanitise)
#   KEEP_SCRATCH=1   leave the scratch database - or the whole temporary
#                    cluster, still running - behind for inspection
#   SKIP_RESTORE=1   the scratch database is already populated; just sanitise
#   SKIP_SANITISE=1  the scratch database is already SANITISED; just verify,
#                    dump and scan. The sanitiser commits before the
#                    verification runs, so a failure in the verifier or the
#                    output scan costs you nothing but the checking - use this
#                    rather than repeating hours of rewriting
#   SANITISE_PGDATA  where --own-server puts its cluster
#                    (default alongside OUTPUT)
#   OVERWRITE=1      replace an existing OUTPUT rather than refusing
#   PG_BIN           directory holding initdb and pg_ctl, if they are not on
#                    PATH and not somewhere this script looks
#   SANITISE_LOG     where to write the progress log
#                    (default <output>.sanitise.log)
#   SANITISE_SKIP_MEASURE=1
#                    skip the up-front sizing pass and start work immediately,
#                    at the cost of a much vaguer ETA
set -euo pipefail

usage() {
    sed -n '2,/^set -euo/p' "$0" | sed 's/^# \?//;$d'
    exit "${1:-1}"
}

OWN_SERVER=0
REUSE_SERVER=""
while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help) usage 0 ;;
        --own-server) OWN_SERVER=1; shift ;;
        --reuse-server)
            REUSE_SERVER="${2:-}"
            if [ -z "$REUSE_SERVER" ]; then
                echo "ERROR: --reuse-server needs a data directory." >&2
                exit 1
            fi
            shift 2 ;;
        --) shift; break ;;
        -*) echo "ERROR: unknown option $1" >&2; usage ;;
        *) break ;;
    esac
done

if [ $# -eq 0 ]; then
    usage 0
fi

INPUT="$1"
OUTPUT="${2:-}"
if [ -z "$OUTPUT" ]; then
    echo "ERROR: give an output path for the sanitised dump." >&2
    usage
fi

if [ ! -r "$INPUT" ]; then
    echo "ERROR: cannot read input dump $INPUT" >&2
    exit 1
fi
if [ -e "$OUTPUT" ] && [ "${OVERWRITE:-0}" != "1" ]; then
    echo "ERROR: $OUTPUT already exists; refusing to overwrite." >&2
    echo "       Re-run with OVERWRITE=1 if that is what you want." >&2
    exit 1
fi
rm -f "$OUTPUT"

HERE="$(cd "$(dirname "$0")" && pwd)"
SANITISE_DB="${SANITISE_DB:-waldur_sanitise}"

# The scratch database name has to contain "sanitise": the SQL script refuses to
# run anywhere else unless explicitly overridden, which is what stops this being
# pointed at a live database by mistake.
case "$SANITISE_DB" in
    *sanitise*) ;;
    *) echo "ERROR: SANITISE_DB must contain 'sanitise'." >&2; exit 1 ;;
esac

START_EPOCH=$(date +%s)

# Wall-clock and elapsed on every step, so an overnight run leaves a log you
# can read back to see where the time went.
elapsed() {
    local secs=$(( $(date +%s) - START_EPOCH ))
    printf '%dh%02dm%02ds' $((secs / 3600)) $(((secs % 3600) / 60)) \
        $((secs % 60))
}
say() {
    printf '\n==> [%s | +%s] %s\n' "$(date +%H:%M:%S)" "$(elapsed)" "$*"
}

# pv gives a live throughput and percentage on the two steps that just move
# bytes. Optional: without it the steps run silently, as before.
pipe_through() {
    if command -v pv >/dev/null 2>&1; then
        pv "$@"
    else
        cat
    fi
}

decompress() {
    case "$1" in
        *.gz)  gzip -dc  -- "$1" ;;
        *.bz2) bzip2 -dc -- "$1" ;;
        *.xz)  xz -dc    -- "$1" ;;
        *.zst) zstd -dc  -- "$1" ;;
        *)     cat       -- "$1" ;;
    esac
}

OWN_PGDATA=""
OWN_STARTED=0
OWN_INITDB_LOG=""
OWN_SERVER_LOG=""

# Find initdb and pg_ctl. They are not on PATH on most distributions - Debian
# hides them under /usr/lib/postgresql/<version>/bin and Red Hat under
# /usr/pgsql-<version>/bin - so look there too, newest version first.
find_pg_bin() {
    if [ -n "${PG_BIN:-}" ]; then
        if [ -x "$PG_BIN/initdb" ] && [ -x "$PG_BIN/pg_ctl" ]; then
            echo "$PG_BIN"
            return 0
        fi
        echo "ERROR: PG_BIN=$PG_BIN has no initdb and pg_ctl in it." >&2
        return 1
    fi
    if command -v initdb >/dev/null 2>&1 \
       && command -v pg_ctl >/dev/null 2>&1; then
        dirname "$(command -v initdb)"
        return 0
    fi
    local dir
    # shellcheck disable=SC2012
    for dir in $(ls -d /usr/lib/postgresql/*/bin /usr/pgsql-*/bin \
                       /usr/local/pgsql/bin /opt/homebrew/opt/postgresql*/bin \
                       2>/dev/null | sort -rV); do
        if [ -x "$dir/initdb" ] && [ -x "$dir/pg_ctl" ]; then
            echo "$dir"
            return 0
        fi
    done
    echo "ERROR: cannot find initdb and pg_ctl. They ship with the server" >&2
    echo "       package, not the client one. Set PG_BIN to the directory" >&2
    echo "       holding them, or drop --own-server and point PGHOST at a" >&2
    echo "       server you can create databases on." >&2
    return 1
}

# The durability settings are off because the cluster is thrown away at the end
# - there is nothing to crash-recover to - and they roughly halve the time the
# restore takes. autovacuum is off for the same reason; the sanitiser runs one
# VACUUM ANALYZE at the end.
#
# listen_addresses='' means no TCP socket at all, and the unix socket lives
# inside the 0700 data directory. On a shared access node that matters: this
# cluster trusts every connection, so it must not be reachable by anyone but
# its owner.
server_opts() {
    local datadir="$1" opts
    opts="-c listen_addresses='' -k $datadir"
    opts="$opts -c fsync=off -c full_page_writes=off"
    opts="$opts -c synchronous_commit=off -c autovacuum=off"
    opts="$opts -c maintenance_work_mem=512MB -c work_mem=64MB"
    opts="$opts -c max_wal_size=4GB"
    printf '%s' "$opts"
}

reuse_server() {
    local bin datadir
    bin="$(find_pg_bin)" || exit 1
    datadir="$(cd "$REUSE_SERVER" 2>/dev/null && pwd)" || {
        echo "ERROR: $REUSE_SERVER is not a directory." >&2
        exit 1
    }
    if [ ! -f "$datadir/PG_VERSION" ]; then
        echo "ERROR: $datadir is not a PostgreSQL data directory." >&2
        exit 1
    fi

    say "Reusing the cluster in $datadir"
    if "$bin/pg_ctl" -D "$datadir" status >/dev/null 2>&1; then
        echo "    already running"
    else
        echo "    not running; starting it"
        "$bin/pg_ctl" -D "$datadir" -l "$datadir.server.log" -w \
            -o "$(server_opts "$datadir")" start >/dev/null || {
            echo "ERROR: could not start it; see $datadir.server.log" >&2
            exit 1
        }
    fi

    export PGHOST="$datadir"
    export PGPORT=5432
    PGUSER="$(id -un)"
    export PGUSER
    export PG_CTL="$bin/pg_ctl"
    unset PGPASSWORD PGSERVICE PGDATABASE PGPASSFILE

    # Deliberately NOT recorded in OWN_PGDATA: cleanup must not destroy a
    # cluster the caller named and may want to re-run against again.
    echo "    left in place on exit; remove it yourself with:"
    echo "      $bin/pg_ctl -D $datadir stop && rm -rf $datadir"
}

start_own_server() {
    local bin datadir needed avail
    bin="$(find_pg_bin)" || exit 1

    # initdb refuses to run as root, and rightly: this would leave a
    # root-owned cluster and a root-owned dump behind.
    if [ "$(id -u)" -eq 0 ]; then
        echo "ERROR: --own-server cannot run as root; initdb refuses to." >&2
        echo "       Run it as the user who should own the output." >&2
        exit 1
    fi

    if [ -n "${SANITISE_PGDATA:-}" ]; then
        datadir="$SANITISE_PGDATA"
    else
        # Alongside the output file, on the assumption that you chose
        # somewhere with room for the result.
        datadir="$(cd "$(dirname "$OUTPUT")" && pwd)/waldur-sanitise-pgdata.$$"
    fi
    if [ -e "$datadir" ]; then
        echo "ERROR: $datadir already exists; refusing to reuse it." >&2
        exit 1
    fi

    # The restored copy plus what VACUUM has not reclaimed, against whatever is
    # free where the cluster is going. A warning rather than a refusal: the
    # multiplier depends entirely on how well the dump compressed, and getting
    # it wrong in either direction is worse than letting an informed user
    # decide.
    needed=$(( $(du -k "$INPUT" | cut -f1) * 10 / 1024 ))
    avail=$(df -Pk "$(dirname "$datadir")" | awk 'NR==2 {print int($4 / 1024)}')
    say "Starting a private PostgreSQL for this run"
    echo "    binaries: $bin"
    echo "    cluster:  $datadir (destroyed on exit)"
    echo "    space:    ~${needed} MB likely needed, ${avail} MB free here"
    if [ "$avail" -lt "$needed" ]; then
        echo "    WARNING: that may not be enough. Point SANITISE_PGDATA at a" \
             "bigger filesystem" >&2
        echo "             if the restore fails with 'no space left on" \
             "device'." >&2
    fi

    # initdb creates the directory itself, with the 0700 the server insists
    # on. Its own log and the server's go NEXT to it, not inside: initdb
    # refuses to run in a directory that is not empty, so a log file written
    # there first is enough to stop it.
    OWN_PGDATA="$datadir"
    OWN_INITDB_LOG="$datadir.initdb.log"
    OWN_SERVER_LOG="$datadir.server.log"

    # C.UTF-8 where it exists, C otherwise. The dump's own collation does not
    # have to match: nothing here depends on text ordering, and a plain
    # pg_dump carries no CREATE DATABASE to disagree with.
    local locale_flag="--locale=C.UTF-8"
    if ! locale -a 2>/dev/null | grep -qiE '^(C\.utf-?8|C\.UTF-?8)$'; then
        locale_flag="--locale=C"
    fi
    "$bin/initdb" -D "$datadir" --encoding=UTF8 $locale_flag \
        --auth=trust -U "$(id -un)" >"$OWN_INITDB_LOG" 2>&1 || {
        echo "ERROR: initdb failed; see $OWN_INITDB_LOG" >&2
        exit 1
    }

    local opts
    opts="$(server_opts "$datadir")"
    "$bin/pg_ctl" -D "$datadir" -l "$OWN_SERVER_LOG" -w -o "$opts" \
        start >/dev/null || {
        echo "ERROR: could not start the temporary server; see" \
             "$OWN_SERVER_LOG" >&2
        exit 1
    }
    OWN_STARTED=1

    # Point every client in this script at the cluster we just made, and clear
    # anything in the environment that would send them somewhere else.
    export PGHOST="$datadir"
    export PGPORT=5432
    PGUSER="$(id -un)"
    export PGUSER
    export PG_CTL="$bin/pg_ctl"
    unset PGPASSWORD PGSERVICE PGDATABASE PGPASSFILE
    echo "    started, socket in $datadir"
}

cleanup() {
    local rc=$?
    if [ -n "$OWN_PGDATA" ] && [ "$OWN_STARTED" != "1" ]; then
        # initdb or the server never came up, so there is nothing running to
        # leave behind and nothing in the cluster worth keeping. The logs stay:
        # they are the only record of why it failed.
        rm -rf "$OWN_PGDATA"
        echo "Temporary cluster removed. Logs kept:" >&2
        echo "  $OWN_INITDB_LOG" >&2
        [ -e "$OWN_SERVER_LOG" ] && echo "  $OWN_SERVER_LOG" >&2
        return
    fi
    if [ -n "$OWN_PGDATA" ]; then
        if [ "${KEEP_SCRATCH:-0}" = "1" ]; then
            echo "Temporary cluster left running in $OWN_PGDATA" \
                 "(KEEP_SCRATCH=1)."
            echo "Stop and remove it with:"
            echo "  ${PG_CTL:-pg_ctl} -D $OWN_PGDATA stop && rm -rf" \
                 "$OWN_PGDATA"
            return
        fi
        if [ "$rc" -ne 0 ]; then
            echo "Failed. The temporary cluster is left running in" \
                 "$OWN_PGDATA so you can" >&2
            echo "look at it:  psql -h $OWN_PGDATA -d $SANITISE_DB" >&2
            echo "Remove it with:  ${PG_CTL:-pg_ctl} -D $OWN_PGDATA stop &&" \
                 "rm -rf $OWN_PGDATA" >&2
            return
        fi
        echo "Removing the temporary cluster"
        "${PG_CTL:-pg_ctl}" -D "$OWN_PGDATA" -m immediate stop >/dev/null \
            2>&1 || true
        rm -rf "$OWN_PGDATA" "$OWN_INITDB_LOG" "$OWN_SERVER_LOG"
        return
    fi
    if [ "${KEEP_SCRATCH:-0}" = "1" ]; then
        echo "Scratch database $SANITISE_DB left in place (KEEP_SCRATCH=1)."
    elif [ "$rc" -ne 0 ]; then
        echo "Failed; scratch database $SANITISE_DB left in place so you can" \
             "look at it. Drop it with: dropdb $SANITISE_DB" >&2
    else
        psql -q -d postgres -c "DROP DATABASE IF EXISTS \"$SANITISE_DB\"" \
            >/dev/null
    fi
}
# INT, TERM and HUP as well as EXIT. The likely way to run this is over SSH on
# an access node, and an uncaught Ctrl-C or a dropped connection would
# otherwise leave a PostgreSQL running and a data directory the size of the
# database behind, with nothing to say what they were for.
#
# The flip side is that a dropped connection takes the run down with it. For
# something that will run for hours, start it under tmux or screen, or with
# nohup, so the shell going away does not reach it.
trap cleanup EXIT INT TERM HUP

if [ "$OWN_SERVER" = "1" ] && [ -n "$REUSE_SERVER" ]; then
    echo "ERROR: --own-server and --reuse-server are contradictory." >&2
    exit 1
fi
if [ "$OWN_SERVER" = "1" ]; then
    if [ "${SKIP_RESTORE:-0}" = "1" ]; then
        echo "ERROR: --own-server and SKIP_RESTORE are contradictory: a" >&2
        echo "       cluster this script just created has nothing in it." >&2
        exit 1
    fi
    start_own_server
fi
if [ -n "$REUSE_SERVER" ]; then
    reuse_server
    # The whole point of reusing a cluster is that it already holds the
    # restored copy.
    SKIP_RESTORE=1
fi

if [ "${SKIP_RESTORE:-0}" != "1" ]; then
    say "Creating scratch database $SANITISE_DB"
    psql -q -d postgres -c "DROP DATABASE IF EXISTS \"$SANITISE_DB\""
    psql -q -d postgres -c "CREATE DATABASE \"$SANITISE_DB\""

    say "Restoring $INPUT"
    # A pg_dumpall cluster dump carries CREATE DATABASE and \connect, so it has
    # to be restored at the cluster level rather than into one database. A
    # per-database pg_dump restores straight into the scratch database.
    if decompress "$INPUT" | head -200 | grep -q '^CREATE DATABASE'; then
        echo "ERROR: $INPUT looks like a pg_dumpall cluster dump." >&2
        echo "       Take a single-database dump instead:" >&2
        echo "         pg_dump --no-owner --no-privileges -d waldur -Fp | gzip > production.sql.gz" >&2
        echo "       or restore the cluster dump yourself and re-run with" >&2
        echo "       SKIP_RESTORE=1 SANITISE_DB=<the restored database>." >&2
        exit 1
    fi
    # A dump carries "ALTER TABLE ... OWNER TO waldur" for whatever role owns
    # the production database. A cluster this script just created has no such
    # role, so every one of those statements fails - harmlessly, but there can
    # be thousands of them, and an overnight log full of ERROR lines is
    # indistinguishable from a run that actually went wrong.
    #
    # The role names are in the dump's own header comments ("; Owner: waldur"),
    # which appear within the first few hundred lines, so they can be read from
    # the same peek that checks the dump type - no second pass over what may be
    # tens of gigabytes. Creating them costs nothing: they are login-less roles
    # in a cluster that is deleted at the end.
    #
    # Only under --own-server. On a server that is not ours, creating roles is
    # not something this script should be doing.
    if [ "$OWN_SERVER" = "1" ]; then
        roles="$(decompress "$INPUT" | head -2000 \
            | sed -nE 's/^-- .*; Owner: ([A-Za-z0-9_-]+)$/\1/p;
                        s/^ALTER [A-Z ]+ OWNER TO ([A-Za-z0-9_-]+);$/\1/p' \
            | sort -u | grep -v '^-$' || true)"
        for role in $roles; do
            [ "$role" = "$PGUSER" ] && continue
            psql -q -d postgres \
                -c "CREATE ROLE \"$role\" NOLOGIN" >/dev/null 2>&1 || true
        done
        if [ -n "$roles" ]; then
            echo "    created placeholder roles: $(echo "$roles" | tr '\n' ' ')"
        fi
    fi

    # The output dump is written by the LOCAL pg_dump, so it is flavoured for
    # the local server's version - not production's. pg_dump's contract is that
    # its output restores into a server of the same or a NEWER version, so a
    # local cluster newer than production makes an output dump that is harder
    # to load anywhere production-shaped, including the deployment you are
    # rehearsing against.
    #
    # This bit us: an 18.4 initdb on the staging box, holding a dump from a
    # 17.2 production server, produced an output dump that a PostgreSQL 16
    # docker image could not straightforwardly read.
    # || true on both: head closes the pipe early, and under pipefail that
    # SIGPIPE is a non-zero status that set -e would treat as fatal. A version
    # check must not be able to abort the run.
    src_ver="$(decompress "$INPUT" 2>/dev/null | head -40 \
        | sed -nE 's/^-- Dumped from database version ([0-9]+).*/\1/p' \
        | head -1 || true)"
    local_ver="$(psql -tAq -d postgres -c 'SHOW server_version_num' || true)"
    local_major=$(( ${local_ver:-0} / 10000 ))
    if [ -n "$src_ver" ] && [ "$local_major" -gt 0 ] \
       && [ "$src_ver" != "$local_major" ]; then
        echo "    NOTE: the dump came from PostgreSQL $src_ver, this cluster is" \
             "$local_major."
        if [ "$local_major" -gt "$src_ver" ]; then
            echo "          The output dump will be written by pg_dump" \
                 "$local_major, and pg_dump output only loads into a server of" >&2
            echo "          the same version or newer - so it may not load into" \
                 "a $src_ver-or-older" >&2
            echo "          target. Either use a PostgreSQL $src_ver for this" \
                 "cluster (PG_BIN), or make sure" >&2
            echo "          whatever restores the result is $local_major or" \
                 "newer." >&2
        fi
    fi

    echo "    input is $(du -h "$INPUT" | cut -f1) compressed; the restore is"
    echo "    usually the second-longest step after the JSON sweep."

    # ON_ERROR_STOP is deliberately off: a dump taken as a non-superuser
    # normally fails on extension and ownership statements that do not matter
    # here. Missing tables would be caught by the sanitiser and the verifier.
    #
    # Diagnostics go to a log and are then summarised, rather than streamed:
    # thousands of repetitions of one harmless error are noise, a count of
    # each distinct one is information. stdout is dropped - a plain dump's
    # stdout is one result row per setval, which is not diagnostics.
    RESTORE_LOG="${OUTPUT%.gz}.restore.log"
    decompress "$INPUT" | pipe_through -N restore \
        | psql -q -d "$SANITISE_DB" >/dev/null 2>"$RESTORE_LOG" || true

    if [ -s "$RESTORE_LOG" ]; then
        echo "    the restore reported:"
        # Strip the row-specific detail so that the same error on ten thousand
        # rows counts as one kind of error.
        sed -E 's/^(ERROR|WARNING|DETAIL|HINT):  //; s/"[^"]*"/"..."/g' \
            "$RESTORE_LOG" | sort | uniq -c | sort -rn | head -8 \
            | sed 's/^/      /'
        echo "    full output in $RESTORE_LOG"
    else
        # Nothing on stderr at all: do not leave an empty file behind.
        rm -f "$RESTORE_LOG"
        echo "    the restore reported no errors"
    fi

    # A restore that produced no tables did not work, whatever it printed.
    tables="$(psql -tAq -d "$SANITISE_DB" -c "SELECT count(*) FROM
        information_schema.tables WHERE table_schema = 'public'")"
    if [ "${tables:-0}" -lt 50 ]; then
        echo "ERROR: only ${tables:-0} tables in the restored database; the" >&2
        echo "       restore did not work. See $RESTORE_LOG." >&2
        exit 1
    fi
    echo "    restored $tables tables"
fi

if [ "${SKIP_SANITISE:-0}" = "1" ]; then
    say "Skipping sanitisation (SKIP_SANITISE=1); the database is already done"
else
    say "Sanitising (reports progress as it goes; the JSON sweep is the slow step)"
    # The sanitiser's progress goes out as psql notices, which arrive prefixed
    # with the script path and line number - longer than the messages
    # themselves. Strip that from notices only, so warnings and errors keep
    # their location. Tee to a log as well, since this is the step people leave
    # running unattended.
    LOG="${SANITISE_LOG:-${OUTPUT%.gz}.sanitise.log}"
    echo "    progress is also being written to $LOG"
    echo "    (tail -f it, or read it back afterwards to see where time went)"

    PGOPTIONS="-c waldur.sanitise_confirmed=yes${SANITISE_SKIP_MEASURE:+ -c waldur.sanitise_skip_measure=yes}" \
        psql -v ON_ERROR_STOP=1 -d "$SANITISE_DB" \
             -f "$HERE/sanitise_production_dump.sql" 2>&1 \
        | sed -uE 's/^psql:[^ ]+: (NOTICE|INFO):  //' \
        | tee "$LOG"

    # psql's status is what matters, not sed's or tee's.
    if [ "${PIPESTATUS[0]}" -ne 0 ]; then
        echo "ERROR: sanitisation failed; see $LOG" >&2
        exit 1
    fi
fi

say "Verifying"
VERIFY_OUT="$(mktemp)"
# The verifier reports through notices as well, for the reasons its header
# explains, so its output needs the same prefix stripping.
psql -v ON_ERROR_STOP=1 -d "$SANITISE_DB" \
     -f "$HERE/sanitise_verify.sql" 2>&1 \
    | sed -uE 's/^psql:[^ ]+: (NOTICE|INFO):  //' \
    | tee "$VERIFY_OUT"

if [ "${PIPESTATUS[0]}" -ne 0 ]; then
    echo "ERROR: the verifier itself failed to run; see above." >&2
    exit 1
fi

# Match the status cell of a result row, not the word FAIL in the closing
# explanation the verifier prints.
if grep -qE '\| *FAIL *\|' "$VERIFY_OUT"; then
    echo >&2
    echo "ERROR: verification reported FAIL. No dump written." >&2
    echo "       The scratch database is kept so you can investigate." >&2
    KEEP_SCRATCH=1
    rm -f "$VERIFY_OUT"
    exit 1
fi
rm -f "$VERIFY_OUT"

say "Writing $OUTPUT"
# --no-owner and --no-privileges so the result loads as whatever role the local
# deployment uses, rather than needing production's roles to exist.
case "$OUTPUT" in
    *.gz) pg_dump --no-owner --no-privileges -d "$SANITISE_DB" \
              | pipe_through -N dump | gzip > "$OUTPUT" ;;
    *)    pg_dump --no-owner --no-privileges -d "$SANITISE_DB" \
              | pipe_through -N dump > "$OUTPUT" ;;
esac

# A last belt-and-braces pass over the bytes that are actually leaving. The SQL
# checks assert on shape per column; this catches an address or a URL in a
# column nobody thought to check.
say "Scanning the output for anything that looks like a live address or URL"
# One definition each, shared by the scan and by the hint printed on failure.
RE_EMAIL='[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
ALLOW_EMAIL='^person[0-9]+@example-org[0-9]+\.com$|^admin@example\.com$'
RE_URL='https?://[A-Za-z0-9._~:/?#@!$&()*+,;=%-]+'
ALLOW_URL='localhost|127\.0\.0\.1|example\.(com|org|net)|www\.w3\.org|schemas\.|creativecommons\.org|docs\.waldur\.com|waldur\.com|github\.com|opensource\.org|json-schema\.org'
leak_email=""
leak_url=""
leaks=0
scan() {
    local label="$1" pattern="$2" allow="${3:-}"
    local n
    if [ -n "$allow" ]; then
        n="$(decompress "$OUTPUT" | grep -Eo "$pattern" | grep -Evc "$allow" \
             || true)"
    else
        n="$(decompress "$OUTPUT" | grep -Eoc "$pattern" || true)"
    fi
    if [ "${n:-0}" -gt 0 ]; then
        printf '  LEAK  %-24s %s occurrences\n' "$label" "$n"
        leaks=$((leaks + 1))
        return 0
    fi
    printf '  ok    %-24s\n' "$label"
    return 1
}
scan "email addresses" "$RE_EMAIL" "$ALLOW_EMAIL" && leak_email=yes
scan "http(s) URLs" "$RE_URL" "$ALLOW_URL" && leak_url=yes

if [ "$leaks" -gt 0 ]; then
    echo >&2
    echo "ERROR: the output dump still contains addresses or URLs that are" >&2
    echo "       not on the allowlist. It has been left in place so you can" >&2
    echo "       look at what matched. For whichever line above says LEAK:" >&2
    echo >&2
    # One command per scan, so the hint matches what actually failed. Printing
    # the address command for a URL failure - which an earlier version did -
    # sends you looking for something that is not there.
    if [ -n "$leak_email" ]; then
        echo "         # addresses" >&2
        echo "         zgrep -Eo '$RE_EMAIL' $OUTPUT \\" >&2
        echo "           | grep -Ev '$ALLOW_EMAIL' | sort | uniq -c |" \
             "sort -rn | head -20" >&2
        echo >&2
    fi
    if [ -n "$leak_url" ]; then
        echo "         # URLs, reduced to their hosts" >&2
        echo "         zgrep -Eo '$RE_URL' $OUTPUT \\" >&2
        echo "           | grep -Ev '$ALLOW_URL' \\" >&2
        echo "           | sed -E 's#(https?://[^/]+).*#\\1#' | sort |" \
             "uniq -c | sort -rn | head -20" >&2
        echo >&2
    fi
    echo "       And to find which table a match is in:" >&2
    echo >&2
    echo "         zcat $OUTPUT | awk '/^COPY /{t=\$2} /<the match>/{print t}' \\" >&2
    echo "           | sort | uniq -c | sort -rn | head" >&2
    echo >&2
    echo "       Either add the column to the sanitiser or add the host to" >&2
    echo "       the allowlist in this script. The sanitiser has already" >&2
    echo "       committed, so after a fix you can re-run with" >&2
    echo "       SKIP_SANITISE=1 only if the fix was to the allowlist here;" >&2
    echo "       a change to the sanitiser needs the data rewritten again." >&2
    KEEP_SCRATCH=1
    exit 1
fi

say "Done: $OUTPUT ($(du -h "$OUTPUT" | cut -f1)), total $(elapsed)"
cat <<EOT

FIRST, check the version that will read this dump is not older than the one
that wrote it. A dump from a newer PostgreSQL can carry syntax an older server
rejects, and recent minor versions emit \\restrict meta-commands that an older
psql does not know:

  gzip -dc $(basename "$OUTPUT") | head -20 | grep -i version
  docker compose exec -T waldur-db psql --version

Load it into a local deployment with the containers down apart from the
database, since Waldur migrates at startup. NOTE the DROP: this destroys
whatever is in your local waldur database now.

  docker compose up -d waldur-db
  docker compose exec -T waldur-db psql -U waldur -d postgres \\
      -c 'DROP DATABASE waldur' -c 'CREATE DATABASE waldur OWNER waldur'
  gzip -dc $(basename "$OUTPUT") | docker compose exec -T waldur-db \\
      psql -U waldur -d waldur

Then the pre-flight. Read it: it must report no FAIL before you reconcile,
because the reconciliation drops two columns irreversibly and the pre-flight
is what says whether anything would be lost.

  docker compose exec -T waldur-db psql -U waldur -d waldur \\
      < scripts/resync_preflight_check.sql

  docker compose exec -T waldur-db psql -U waldur -d waldur \\
      < scripts/resync_reconcile_db.sql

Now let the stack start, which migrates:

  docker compose up -d

And confirm the schema matches the models. This is the check that catches a
migration recorded as applied whose DDL never actually ran, so do not skip it:

  docker compose exec waldur-mastermind-api \\
      waldur makemigrations --check --dry-run

Finally, make an account, since no password in the copy is usable:

  docker compose exec waldur-mastermind-api \\
      waldur createsuperuser --username admin --email admin@example.com

scripts/resync_rehearse_migration.sh is NOT the tool for this path - it is for
a sanitised database sitting in a bare cluster. The sequence above is closer to
production, because it uses the deployment's own settings and its own startup
path rather than a settings module written for rehearsing.
EOT
