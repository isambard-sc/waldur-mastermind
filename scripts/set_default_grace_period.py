"""Give every organisation and project a 30-day grace period, in place.

The same backfill as structure/0086_backfill_grace_period_days, for a database
that has already been migrated past it (or that you would rather fix now than
re-migrate). Running the migration does this too; this is for a copy that is
already at the head.

Why it is needed: structure/0067 turned grace_period_days from a property
returning a fixed 30 days into a nullable column with no default, so on an
upgraded database Project.get_grace_period_days() falls through
project -> customer -> 0. A project's effective end date then collapses onto
its end date, its resources are terminated the day it ends, and a project left
with no active resources is scheduled for deletion.

    # see what it would change
    docker compose exec -T waldur-mastermind-api waldur shell \
        -c "$(cat scripts/set_default_grace_period.py)"

    # do it
    docker compose exec -T -e GRACE_APPLY=1 waldur-mastermind-api waldur shell \
        -c "$(cat scripts/set_default_grace_period.py)"

    # a different number of days
    docker compose exec -T -e GRACE_APPLY=1 -e GRACE_DAYS=14 ...

scripts/resync_migrate.sh runs this as its step 5, so a resync deployment gets
the backfill without anyone remembering to. It lives here rather than as a
migration under waldur_core/structure because that directory is upstream's,
and a local migration sitting in it is one stray merge request away from being
pushed back to them.

Only rows where the value is NULL are touched, so anything set deliberately is
kept and re-running changes nothing.

It also reports the projects whose expiry status this changes - the ones that
are currently treated as expired but would be inside the restored grace period.
Those are the ones worth looking at afterwards: a project already terminated or
deleted by the scheduled task is not brought back by this.
"""

import os

from django.utils import timezone

from waldur_core.structure.models import Customer, Project

APPLY = os.environ.get("GRACE_APPLY") == "1"
DAYS = int(os.environ.get("GRACE_DAYS", "30"))

today = timezone.now().date()

customers = Customer.objects.filter(grace_period_days__isnull=True)
# _base_manager: the default manager filters out soft-deleted projects, and a
# terminated project is exactly the kind this is meant to protect.
projects = Project._base_manager.filter(grace_period_days__isnull=True)

customer_count = customers.count()
project_count = projects.count()

print(f"grace period to set: {DAYS} days\n")
print(f"  organisations with no grace period set: {customer_count}")
print(f"  projects with no grace period set:      {project_count}")

# Projects that end_date says are over but that the restored grace period would
# still cover. Evaluated before the write, while the old values are in place.
would_change = [
    project
    for project in Project._base_manager.exclude(end_date=None)
    if project.get_grace_period_days() == 0
    and project.end_date <= today
    and project.end_date + timezone.timedelta(days=DAYS) > today
]

if would_change:
    print(
        f"\n{len(would_change)} projects are currently past their end date but"
        f" would be inside a {DAYS}-day grace period:"
    )
    for project in sorted(would_change, key=lambda p: p.end_date):
        print(f"  {project.end_date}  {project.uuid}  {project.name!r}")
    print(
        "\nThese stop counting as expired once this runs. It does NOT undo a"
        "\ntermination or deletion that has already happened - check their"
        "\nresources."
    )

if not APPLY:
    print("\nDry run. Re-run with GRACE_APPLY=1 to write.")
else:
    updated_customers = customers.update(grace_period_days=DAYS)
    updated_projects = projects.update(grace_period_days=DAYS)
    print(
        f"\nSet on {updated_customers} organisations and {updated_projects} projects."
    )
