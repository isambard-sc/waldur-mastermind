"""Report how marketplace/0281 will classify this database, before it runs.

marketplace/0281_rerun_data_migrations_skipped_by_squashes re-runs the data
migrations that a replacement squash skipped. Which databases need that is not
configured - it is INFERRED from django_migrations, by
``applied_as_replacement()``:

    1. every replaced migration AND the squash are recorded;
    2. sorted by id the squash is last, and the ids are contiguous;
    3. neighbouring rows' `applied` timestamps are within 1 second;
    4. the block starts more than 1 day after the database's oldest row.

All four true -> the squash was applied IN PLACE of the originals on an
upgrade, so the backfills never ran and 0281 runs them now, against live data.
Any one false -> left alone.

That inference reads rows this deployment edits by hand:
scripts/resync_reconcile_db.sql deletes from django_migrations. It never
INSERTs, and the rows it removes (waldur_openportal, proposal,
core.0011_user_unix_username, structure, notifications) are not in any block
0281 inspects - and deleting an unrelated row does not move the ids of the
rows in a block. So it should not perturb the verdict. This proves that rather
than assuming it.

Run it BEFORE the migration, against a restore of production as it is now:

    docker compose exec -T waldur-mastermind-api waldur shell \
        -c "$(cat scripts/check_0281_classification.py)"

Read-only. Reports, per squash, which of the four conditions hold and what
0281 would therefore do.
"""

from django.db import connection
from django.db.migrations.recorder import MigrationRecorder

from waldur_mastermind.marketplace.migrations import (
    __name__ as _migrations_package,
)

module = __import__(
    f"{_migrations_package}.0281_rerun_data_migrations_skipped_by_squashes",
    fromlist=[
        "REPAIRS",
        "applied_as_replacement",
        "NEIGHBOUR_GAP",
        "FRESH_INSTALL_WINDOW",
    ],
)

rows = MigrationRecorder(connection).migration_qs
oldest = rows.order_by("applied").values_list("applied", flat=True).first()
print(f"oldest migration row: {oldest}")
print(f"total rows: {rows.count()}\n")

for squash, replaces, _steps in module.REPAIRS:
    keys = list(replaces) + [squash]
    recorded = {
        (row.app, row.name): row
        for row in rows.filter(
            app__in={a for a, _ in keys}, name__in={n for _, n in keys}
        )
    }
    print(f"{squash[0]}.{squash[1]}  ({len(replaces)} replaced)")

    absent = [k for k in keys if k not in recorded]
    if absent:
        print(f"  1. all recorded    : NO - {len(absent)} missing, e.g. {absent[0][1]}")
        print("  -> LEFT ALONE\n")
        continue
    print("  1. all recorded    : yes")

    block = sorted((recorded[k] for k in keys), key=lambda r: r.id)
    contiguous = (
        block[-1].name == squash[1] and block[-1].id - block[0].id == len(keys) - 1
    )
    print(
        f"  2. contiguous ids  : {'yes' if contiguous else 'NO'}"
        f"  (ids {block[0].id}..{block[-1].id}, span"
        f" {block[-1].id - block[0].id + 1} for {len(keys)} rows;"
        f" last is {block[-1].name})"
    )

    gaps = [
        (later.applied - earlier.applied) for earlier, later in zip(block, block[1:])
    ]
    biggest = max(gaps) if gaps else None
    together = biggest is not None and biggest <= module.NEIGHBOUR_GAP
    print(
        f"  3. within 1 second : {'yes' if together else 'NO'}"
        f"  (largest neighbour gap {biggest})"
    )

    age = block[0].applied - oldest
    old_enough = age > module.FRESH_INSTALL_WINDOW
    print(
        f"  4. not a fresh db  : {'yes' if old_enough else 'NO'}"
        f"  (block starts {age} after the oldest row)"
    )

    verdict = module.applied_as_replacement(connection, squash, replaces)
    print(
        f"  -> {'RE-RUNS its backfills on this database' if verdict else 'LEFT ALONE'}\n"
    )

print(
    "A database that applied the originals one by one over months fails (2)"
    "\nand (3), and is left alone - which is right, because its backfills did"
    "\nrun. A database that jumped the range in one migrate matches all four."
    "\nIf any squash above says RE-RUNS, read what those steps do before the"
    "\nwindow: 0281's own docstring names three whose inputs the squash"
    "\ndropped, which no re-run can recover."
)
