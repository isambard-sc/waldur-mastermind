"""Read every model through the ORM, and report the ones that fail.

Run this AFTER the migration, not before: on an unmigrated database it
reports every model whose table is missing a column a pending migration adds,
which is true but not interesting.

Django's field converters run on read, not on write, so a column holding
something the field cannot parse is invisible until something reads the row -
at which point it is a 500 from whatever page touched it. The case that
prompted this: waldur_core.core.fields.JSONField stores JSON in a `text`
column, the sanitiser filled one with prose, and the projects list started
returning 500 with "Enter valid JSON".

Nothing in the migration rehearsal reads rows, so nothing caught it. This
does, in about the time it takes to make a cup of tea, and it is worth running
against any database that has been rewritten by hand.

    waldur shell -c "$(cat scripts/resync_smoke_test.py)"

or through the rehearsal script, which runs it as its last step.
"""

import traceback

from django.apps import apps

# _base_manager, NOT _default_manager. Several models use a soft-delete
# manager that hides is_removed rows, and those rows are exactly where this
# kind of damage hides: the 500 that prompted this script came from
# /api/projects/?include_terminated=true, the one query that reaches them. A
# smoke test that cannot see a row cannot vouch for it.

LIMIT = 200

failures = []
checked = 0
skipped = 0

for model in sorted(apps.get_models(), key=lambda m: m._meta.label):
    if model._meta.abstract or model._meta.proxy:
        continue
    try:
        # Touch every concrete field, so field converters actually run. Just
        # counting rows would read nothing and prove nothing.
        names = [f.attname for f in model._meta.concrete_fields]
        rows = 0
        for obj in model._base_manager.all()[:LIMIT]:
            for name in names:
                getattr(obj, name)
            rows += 1
        checked += 1
        if rows == 0:
            skipped += 1
    except Exception as exc:  # noqa: BLE001 - reporting, not handling
        failures.append((model._meta.label, exc, traceback.format_exc()))

print(f"smoke test: {checked} models read, {skipped} of them empty")

if failures:
    print(f"\n{len(failures)} MODEL(S) COULD NOT BE READ:\n")
    for label, exc, tb in failures:
        print(f"  {label}: {type(exc).__name__}: {exc}")
    print("\nFirst traceback in full:\n")
    print(failures[0][2])
    raise SystemExit(1)

print("Every model read cleanly.")
