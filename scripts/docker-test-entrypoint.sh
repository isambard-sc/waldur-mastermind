#!/bin/bash
# Entrypoint for the test service in docker-compose.test.yml.
#
# docker-compose.test.yml mounts the working tree over /usr/src/waldur, so the
# CODE under test comes from the checkout but the INSTALLED DEPENDENCIES come
# from the image. If the image predates the branch, those disagree, and the
# failures that follow are confusing: import errors and AttributeErrors deep in
# unrelated tests rather than anything pointing at the real cause.
#
# The resync moved openportal from 0.32 to 0.92 and changed 1400-odd lines of
# uv.lock, so an image built before it cannot run this branch's tests.
#
# This checks the one dependency that pins the whole thing down and fails
# loudly if it disagrees, rather than letting the suite run against the wrong
# packages. Set WALDUR_TEST_SYNC_DEPS=1 to install the checkout's locked
# dependencies into the container first instead, which is slower per run but
# needs no image rebuild.
set -euo pipefail

cd /usr/src/waldur

if [ "${WALDUR_TEST_SYNC_DEPS:-0}" = "1" ]; then
    echo "==> Syncing dependencies from uv.lock (WALDUR_TEST_SYNC_DEPS=1)"
    UV_PROJECT_ENVIRONMENT="$(python -c 'import sysconfig; print(sysconfig.get_config_var("prefix"))')" \
        uv sync --frozen
else
    required="$(sed -n 's/.*"openportal>=\([0-9][0-9.]*\)".*/\1/p' pyproject.toml | head -1)"
    installed="$(python - <<'PY'
try:
    from importlib.metadata import version
    print(version("openportal"))
except Exception:
    print("")
PY
)"
    if [ -z "$installed" ]; then
        echo "ERROR: openportal is not installed in this image." >&2
        echo "       The image cannot run this branch's tests." >&2
        echo "       Rebuild it from this checkout, or re-run with" >&2
        echo "       WALDUR_TEST_SYNC_DEPS=1 to install the locked deps." >&2
        exit 1
    fi
    # Compare as version tuples, not strings, so 0.9 does not beat 0.92.
    if ! python - "$installed" "$required" <<'PY'
import sys
def parts(v):
    return tuple(int(x) for x in v.split(".") if x.isdigit())
sys.exit(0 if parts(sys.argv[1]) >= parts(sys.argv[2]) else 1)
PY
    then
        echo "ERROR: openportal $installed is installed, but this checkout needs >= $required." >&2
        echo "       The image predates this branch, so the code under test and the" >&2
        echo "       installed dependencies disagree. Rebuild the image from this" >&2
        echo "       checkout, or re-run with WALDUR_TEST_SYNC_DEPS=1." >&2
        exit 1
    fi
    echo "==> openportal $installed satisfies >= $required"
fi

exec python -m pytest "$@"
