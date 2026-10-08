# Local test settings. Upstream's test_settings points at a "db" host, which
# suits the containerised test setup but nothing else; this overrides the
# database connection from the environment so the same settings module works
# against a local PostgreSQL, a throwaway container, or CI.
#
# See docker-compose.test.yml for running the suite in Docker.
import os

from waldur_core.server.test_settings import *  # noqa: F401,F403

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "HOST": os.environ.get("WALDUR_TEST_DB_HOST", "127.0.0.1"),
        "PORT": os.environ.get("WALDUR_TEST_DB_PORT", "5432"),
        "NAME": os.environ.get("WALDUR_TEST_DB_NAME", "test_postgres"),
        "USER": os.environ.get("WALDUR_TEST_DB_USER", "postgres"),
        "PASSWORD": os.environ.get("WALDUR_TEST_DB_PASSWORD", "postgres"),
    },
}

# Building this test database takes ~15 minutes (700-odd migrations), so pass
# --reuse-db to keep it between runs; --create-db without it drops the database
# at teardown and the next run pays the full cost again.
