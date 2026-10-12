"""Explain why get_award_usage_info() reports the usage it does for a project.

The managed-project accounting summary reports allocation_credits from the
award itself and usage_credits from the cached usage reports. Those are
reached by two completely different routes, so allocation can be right while
usage is zero. This walks the usage route step by step and says which step
produced nothing.

    docker compose exec -T -e AWARD_PROJECT=<uuid-or-name> \
        waldur-mastermind-api waldur shell \
        -c "$(cat scripts/debug_award_usage.py)"

With no AWARD_PROJECT it reports on every project that has an award and a
non-zero allocation, which is the quickest way to tell a single bad row from
a systematic break.

Read-only: it calls nothing that writes. Note that get_award_usage_info() is
NOT read-only in this respect - ManagedProject.get_attachments() reconstructs
the attachment history from the audit log on first read - so this reports the
attachment count without forcing that reconstruction, and says so when there
is none yet.
"""

import os

from waldur_core.structure.models import Project
from waldur_openportal import models, utils
from waldur_openportal.filters import _identifiers_for_project_uuid

SELECTOR = os.environ.get("AWARD_PROJECT", "").strip()


def describe(project):
    print(f"\n=== {project.name!r} ({project.uuid}) ===")

    try:
        award = models.ManagedProject.objects.get(project=project)
    except models.ManagedProject.DoesNotExist:
        print("  no ManagedProject attached -> (None, 0.0) by design")
        return
    except models.ManagedProject.MultipleObjectsReturned:
        print("  MORE THAN ONE ManagedProject points at this project;")
        print("  get_award_usage_info() raises rather than choosing.")
        return

    print(f"  award identifier    : {award.identifier!r}")
    print(f"  local_identifier    : {award.local_identifier!r}")
    print(f"  destination         : {award.destination!r}")

    # --- allocation side -------------------------------------------------
    # get_award_usage_info reads .project_template DIRECTLY rather than calling
    # get_project_template(), because that method can DELETE the ManagedProject
    # as a side effect of failing to resolve one. So a null allocation_credits
    # can mean the FK is null even though a template is resolvable - report
    # both.
    template = award.project_template
    if template is None:
        print("  project_template    : NULL on the row -> allocation_credits is None")
        print(
            "                        (get_award_usage_info reads the FK directly"
            " and does not resolve)"
        )
    else:
        print(f"  project_template    : {template.name!r}")

    try:
        details = award.get_details()
    except Exception as e:
        details = None
        print(f"  details             : get_details() raised {type(e).__name__}: {e}")

    if details is None:
        print("  details             : None -> allocation_credits is None")
    elif details.allocation is None:
        print("  details.allocation  : None -> allocation_credits is None")
        print(f"  raw details keys    : {sorted((award.details or {}).keys())}")
    else:
        print(
            f"  details.allocation  : {details.allocation.size}"
            f" {details.allocation.units}"
        )
        if template is not None:
            print(
                f"  allocation_credits  : "
                f"{template.convert_to_credits(details.allocation)}"
            )
            print(f"  units mapping       : {template.allocation_units_mapping}")

    # --- usage side ------------------------------------------------------
    # Counted directly rather than through get_attachments(), which would
    # reconstruct the history as a side effect and change what we are
    # measuring.
    stored = award.attachments.count()
    if stored:
        windows = utils._get_managed_project_windows(award)
        print(f"  attachment windows  : {stored} rows -> {len(windows)} windows")
        for start, end in windows:
            print(f"      {start} .. {end or 'open'}")
    else:
        audit = models.ManagedProjectAuditEntry.objects.filter(
            managed_project=award
        ).count()
        print(
            f"  attachment windows  : 0 rows stored; {audit} audit entries to"
            " reconstruct from"
        )
        if award.project is None:
            print("      and project is None, so nothing can be reconstructed")
        windows = utils._get_managed_project_windows(award)
        print(f"      reconstructed to {len(windows)} windows")
        for start, end in windows:
            print(f"      {start} .. {end or 'open'}")

    if not windows:
        print("  -> usage is 0 because there are NO WINDOWS to count over.")
        return

    # The two endpoints do not use the same key, which is the usual reason one
    # shows usage and the other does not:
    #
    #   /api/openportal-project-usage-reports/?project_uuid=...
    #       -> filters._identifiers_for_project_uuid(), which is every
    #          Allocation.backend_id on the project PLUS
    #          "{ProjectInfo.shortname}.{get_portal()}"
    #   get_award_usage_info
    #       -> ManagedProject.local_identifier, and nothing else
    #
    # So an award whose local_identifier is blank, or differs from the
    # identifier the reports were written under, reports zero usage while the
    # reports endpoint happily returns them.
    endpoint_ids = _identifiers_for_project_uuid(project.uuid)
    print(f"  identifiers the reports endpoint uses: {sorted(endpoint_ids)}")
    if not award.local_identifier:
        print("  -> local_identifier is EMPTY, so usage can only ever be 0.")
    elif award.local_identifier not in endpoint_ids:
        print(
            f"  -> MISMATCH: local_identifier {award.local_identifier!r} is not"
            " among them."
        )
        for candidate in sorted(endpoint_ids):
            n = models.CachedProjectUsageReport.objects.filter(
                project_identifier=candidate
            ).count()
            print(f"       {candidate!r}: {n} cached reports")
    else:
        print("  -> local_identifier agrees with the reports endpoint.")

    # The lookup _sum_usage_over_windows now does: project_identifier alone.
    exact = models.CachedProjectUsageReport.objects.filter(
        project_identifier=award.local_identifier
    )
    print(f"  cached reports on local_identifier : {exact.count()}")

    if exact.exists():
        print("  -> the join matches; if usage is still 0 the reports are empty")
        print("     or their months fall outside every window:")
        for r in exact.order_by("year", "month")[:24]:
            print(f"      {r.year}-{r.month:02d} complete={r.is_complete}")
        return

    # Nothing matched. Which half of the key is wrong?
    by_resource = models.CachedProjectUsageReport.objects.filter(
        resource=award.destination
    )
    by_identifier = models.CachedProjectUsageReport.objects.filter(
        project_identifier=award.local_identifier
    )
    print(f"  cached reports (resource only)   : {by_resource.count()}")
    print(f"  cached reports (identifier only) : {by_identifier.count()}")

    if by_resource.exists() and not by_identifier.exists():
        seen = sorted(
            set(
                by_resource.values_list("project_identifier", flat=True).distinct()[:20]
            )
        )
        print("  -> the DESTINATION matches but the IDENTIFIER does not.")
        print(f"     local_identifier on the award : {award.local_identifier!r}")
        print("     project_identifier values on reports for that destination:")
        for value in seen:
            print(f"       {value!r}")
    elif by_identifier.exists() and not by_resource.exists():
        seen = sorted(
            set(by_identifier.values_list("resource", flat=True).distinct()[:20])
        )
        print("  -> the IDENTIFIER matches but the DESTINATION does not.")
        print(f"     destination on the award : {award.destination!r}")
        print("     resource values on reports for that identifier:")
        for value in seen:
            print(f"       {value!r}")
    else:
        print("  -> neither key matches any cached report.")
        print(
            f"     total cached reports in the database: "
            f"{models.CachedProjectUsageReport.objects.count()}"
        )


if SELECTOR:
    projects = (
        Project.objects.filter(uuid=SELECTOR)
        if len(SELECTOR) == 32
        else Project.objects.filter(name=SELECTOR)
    )
    if not projects:
        print(f"No project matching {SELECTOR!r}")
    for project in projects:
        describe(project)
else:
    award_project_ids = models.ManagedProject.objects.exclude(project=None).values_list(
        "project_id", flat=True
    )
    projects = Project.objects.filter(id__in=list(award_project_ids))
    print(f"{projects.count()} projects with an award attached")
    for project in projects[:20]:
        describe(project)
