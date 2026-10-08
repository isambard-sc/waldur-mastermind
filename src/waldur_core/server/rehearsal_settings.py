"""Settings for rehearsing the upstream-resync migration against a copy of
production.

Deliberately NOT test_settings: that adds waldur_core.quotas.tests,
waldur_core.structure.tests and waldur_pid.tests to INSTALLED_APPS, whose
migrations would then run and create tables production will never have. For a
rehearsal whose whole purpose is to reproduce what happens on deployment, that
is the wrong shape - it applies migrations the real run does not, and it can
mask a real one.

This is base_settings plus a database connection read from the environment,
which is what the deployment actually runs. See
docs/guides/production-data-sanitisation.md and
scripts/resync_rehearse_migration.sh.
"""

import os

from waldur_core.server.base_settings import *  # noqa: F401,F403

# Throwaway values. The rehearsal never serves a request and never issues a
# token, so these only need to exist for Django to start; nothing that
# survives the rehearsal is protected by them.
SECRET_KEY = os.environ.get("SECRET_KEY", "rehearsal-only-not-a-secret")

# Must be a valid Fernet key, or the encryption migrations cannot import. The
# sanitiser blanks the columns they encrypt, so this key encrypts nothing -
# but a rehearsal against unsanitised data would need the real key, and would
# then write values only that key can read.
FIELD_ENCRYPTION_KEY = os.environ.get(
    "FIELD_ENCRYPTION_KEY", "0_MF86u8HjafXHqQSf9jm5r0Rbhn_jOcwTHk1f-3OqY="
)

DEBUG = False

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "HOST": os.environ.get("WALDUR_DB_HOST", "localhost"),
        "PORT": os.environ.get("WALDUR_DB_PORT", "5432"),
        "NAME": os.environ.get("WALDUR_DB_NAME", "waldur_rehearsal"),
        "USER": os.environ.get("WALDUR_DB_USER", "waldur"),
        "PASSWORD": os.environ.get("WALDUR_DB_PASSWORD", ""),
    },
}

# A rehearsal must not reach anything outside itself: no mail, no cache shared
# with a running instance, no Celery broker.
EMAIL_BACKEND = "django.core.mail.backends.locmem.EmailBackend"
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "rehearsal",
    }
}
CELERY_TASK_ALWAYS_EAGER = True
