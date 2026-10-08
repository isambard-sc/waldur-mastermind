"""Repair text columns the ORM reads as JSON but that hold something else.

Waldur has a text-backed JSON field, waldur_core.core.fields.JSONField: the
column is `text` in the database and a JSON document to the ORM, because
from_db_value() runs json.loads on every read. Anything in such a column that
is not JSON therefore breaks READING the row, not just writing it:

    django.core.exceptions.ValidationError: ['Enter valid JSON']

and the failure surfaces wherever the row is touched -- a 500 on a list
endpoint, a task that cannot load its own object -- looking exactly like a
bug in the code rather than like bad data.

An earlier version of scripts/sanitise_production_dump.sql wrote prose into
structure_project.termination_metadata, which is one of these columns. The
sanitiser no longer does that and now repairs the whole class of column
before it writes the dump. This fixes a copy that was already loaded from a
dump made before that, without re-dumping.

Nothing is hardcoded: the columns come from Django's own field registry, so
this is right for whatever release the database has been migrated to, and it
covers every app rather than the one that happened to break.

    # see what it would do
    docker compose exec -T waldur-mastermind-api waldur shell \
        -c "$(cat scripts/repair_sanitised_json_text.py)"

    # do it
    docker compose exec -T -e REPAIR_APPLY=1 waldur-mastermind-api waldur shell \
        -c "$(cat scripts/repair_sanitised_json_text.py)"

Values that cannot be parsed are replaced with the field's own default -- NULL
where the column is nullable, otherwise the empty document of the right shape
({} or []), taken from the field declaration rather than guessed. The content
is gone either way; the point is that the row becomes readable again.

Fields that encrypt part of their value (EncryptedOptionsField, which backs
ServiceSettings.options) are checked but never written: their plaintext
structure is still JSON, so a failure there means something other than
sanitising and blanking the column would take real configuration with it.
"""

import json
import os

from django.apps import apps
from django.db import connection

from waldur_core.core.fields import JSONField, SelectiveEncryptionMixin

APPLY = os.environ.get("REPAIR_APPLY") == "1"

targets = []
for model in apps.get_models():
    if model._meta.proxy or not model._meta.managed:
        continue
    # local_fields only: an inherited field belongs to the parent's table and
    # would otherwise be checked once per subclass.
    for field in model._meta.local_fields:
        if isinstance(field, JSONField):
            targets.append((model._meta.db_table, field, model))

targets.sort(key=lambda t: (t[0], t[1].column))
print(f"{len(targets)} text-backed JSON columns to check\n")

bad_total = repaired_total = 0
skipped_encrypted = []

# A cast that reports rather than raises. In pg_temp so it disappears with the
# connection instead of being left behind in the schema.
with connection.cursor() as cursor:
    cursor.execute("""
        CREATE OR REPLACE FUNCTION pg_temp.is_json(v text)
        RETURNS boolean LANGUAGE plpgsql IMMUTABLE AS $fn$
        DECLARE parsed jsonb;
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
        END $fn$;
    """)

    for table, field, model in targets:
        column = field.column
        cursor.execute(
            f'SELECT count(*) FROM "{table}" WHERE NOT pg_temp.is_json("{column}")'
        )
        (bad,) = cursor.fetchone()
        if not bad:
            continue

        bad_total += bad
        label = f"{model._meta.label}.{field.name}"

        if isinstance(field, SelectiveEncryptionMixin):
            skipped_encrypted.append((label, table, column, bad))
            print(f"  [SKIP]  {label}: {bad} rows - encrypted field, not touched")
            continue

        if field.null:
            replacement, shown = None, "NULL"
        else:
            default = field.get_default()
            # get_default() returns the Python value, not the stored text;
            # the column holds the serialised form.
            replacement = json.dumps(default if default is not None else {})
            shown = replacement

        verb = "repair" if APPLY else "would repair"
        print(f"  [{verb}] {label}: {bad} rows -> {shown}")

        if APPLY:
            cursor.execute(
                f'UPDATE "{table}" SET "{column}" = %s'
                f' WHERE NOT pg_temp.is_json("{column}")',
                [replacement],
            )
            repaired_total += cursor.rowcount

if not bad_total:
    print("Nothing to repair: every one of these columns parses as JSON.")
elif APPLY:
    print(f"\n{repaired_total} rows repaired.")
else:
    print(f"\n{bad_total} unreadable rows. Re-run with REPAIR_APPLY=1 to write.")

if skipped_encrypted:
    print(
        "\nThe encrypted fields above were left alone deliberately: only the"
        "\nvalues under credential-shaped keys are encrypted, so the column is"
        "\nstill JSON, and a parse failure there is not a sanitising artefact."
        "\nBlanking one would take real backend configuration with it."
    )
