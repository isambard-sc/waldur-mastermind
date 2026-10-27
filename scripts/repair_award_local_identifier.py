"""Re-point each award's local_identifier at the project it is attached to.

ManagedProject.local_identifier should name the project an award is attached
to: "{ProjectInfo shortname}.{this portal}". It used to be minted once, for
the project the award was first accepted onto, and never updated - so an
award accepted onto a new project and then moved to the right one (often
with the new project deleted) kept naming the first. ManagedProject.
set_project() now keeps it in step; this repairs the awards moved before.

For every award attached to a project whose shortname is known, sets
local_identifier to that project's identifier where it differs. Awards not
attached to any project are left as they are: their identifier names the
last project they held.

    # see what it would change
    waldur shell < scripts/repair_award_local_identifier.py

    # do it
    REPAIR_APPLY=1 waldur shell < scripts/repair_award_local_identifier.py

    # in a pod, the script being in the image:
    kubectl exec -i -n "$NS" deploy/waldur-mastermind-api -- sh -c \\
      'waldur shell < /usr/src/waldur/scripts/repair_award_local_identifier.py'

Applying also sends each changed award's awarding portal an "award_changed"
notification, as attaching a project through the API does, so it picks up
the new mapping without waiting for its next poll.

Prints award ids, dates and project identifiers (project shortnames, not
personal data). Stops before looking at anything if the OpenPortal config
cannot be loaded, since the portal half of every identifier comes from it.
"""

import os

from waldur_openportal import config, models, utils

APPLY = os.environ.get("REPAIR_APPLY") == "1"

if not config.ensure_config_loaded():
    print("OpenPortal configuration is not available; cannot work out")
    print("identifiers. Nothing examined, nothing written.")
else:
    ok = changed = no_shortname = 0

    for managed_project in (
        models.ManagedProject.objects.exclude(project=None)
        .select_related("project")
        .order_by("id")
    ):
        project = managed_project.project
        info = models.ProjectInfo.objects.filter(project=project).first()
        if info is None or not info.has_shortname():
            no_shortname += 1
            print(
                f"  [SKIP]  {managed_project.id:6d} awarded "
                f"{managed_project.created.date()}: its project has no "
                f"shortname yet (currently {managed_project.local_identifier!r})"
            )
            continue

        expected = str(utils.get_local_project_identifier(project))
        if managed_project.local_identifier == expected:
            ok += 1
            continue

        others = (
            models.ManagedProject.objects.filter(local_identifier=expected)
            .exclude(id=managed_project.id)
            .count()
        )
        note = f"  (also held by {others} other award(s))" if others else ""
        verb = "change" if APPLY else "would change"
        print(
            f"  [{verb}] {managed_project.id:6d} awarded "
            f"{managed_project.created.date()}"
            f" {managed_project.local_identifier!r} -> {expected!r}"
            f"{' (project deleted)' if project.is_removed else ''}{note}"
        )

        if APPLY:
            # update() rather than save(): nothing else on the row changes,
            # and this must not fire the model's save-side handlers.
            models.ManagedProject.objects.filter(id=managed_project.id).update(
                local_identifier=expected
            )
            managed_project.refresh_from_db()
            managed_project.notify_changed()
        changed += 1

    print(
        f"\n{ok} already correct, {changed} "
        f"{'changed' if APPLY else 'to change'}, {no_shortname} skipped "
        "(no project shortname)"
    )
    if changed and not APPLY:
        print("\nDry run. Re-run with REPAIR_APPLY=1 to write.")
