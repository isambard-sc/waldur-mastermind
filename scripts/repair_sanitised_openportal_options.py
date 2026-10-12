"""Put instance_name back into OpenPortal service settings after sanitising.

An earlier version of scripts/sanitise_production_dump.sql blanked
structure_servicesettings.options wholesale. That column holds credentials AND
the configuration a backend needs, so the copy loses OpenPortal's
instance_name, and two things break quietly:

  * every sync task fails with "Instance name cannot be None";
  * /api/openportal/offering_mapping/ returns 200 with every identifier mapped
    to null, so the OpenPortal usage reports render empty with no error to
    explain it.

The sanitiser no longer does this. This repairs a copy made by the version
that did, without re-dumping.

The identifier is recoverable: RemoteProject.destination holds the same string
that belongs in options["instance_name"], and RemoteProject reaches
ServiceSettings through remote_allocation. Where a setting has no remote
projects to derive from, it is reported rather than guessed.

    # see what it would do
    docker compose exec -T waldur-mastermind-api waldur shell \
        -c "$(cat scripts/repair_sanitised_openportal_options.py)"

    # do it
    docker compose exec -T -e REPAIR_APPLY=1 waldur-mastermind-api waldur shell \
        -c "$(cat scripts/repair_sanitised_openportal_options.py)"

    # supply the ones it could not derive, as id=identifier pairs
    docker compose exec -T -e REPAIR_APPLY=1 \
        -e REPAIR_EXTRA='17=brics.aip2.clusters.shared,18=brics.other' \
        waldur-mastermind-api waldur shell \
        -c "$(cat scripts/repair_sanitised_openportal_options.py)"

Writing through Django, not SQL, is deliberate: structure/0081 turns options
into an EncryptedOptionsField, so a raw UPDATE would store something the
application cannot decrypt.
"""

import os
from collections import Counter

from waldur_core.structure.models import ServiceSettings
from waldur_openportal import models as op_models

APPLY = os.environ.get("REPAIR_APPLY") == "1"
EXTRA = {}
for pair in os.environ.get("REPAIR_EXTRA", "").split(","):
    if "=" in pair:
        key, _, value = pair.partition("=")
        EXTRA[key.strip()] = value.strip()

# Every setting that backs an OpenPortal allocation - the same set
# offering_mapping builds its lookup from.
settings_ids = set(
    op_models.Allocation.objects.values_list("service_settings_id", flat=True)
) | set(
    op_models.RemoteAllocation.objects.values_list("service_settings_id", flat=True)
)
settings = {s.id: s for s in ServiceSettings.objects.filter(id__in=settings_ids)}

derived: dict[int, Counter] = {}
sources: dict[int, set[str]] = {}

# Source A: the destinations the remote projects already carry. RemoteProject
# reaches ServiceSettings through remote_allocation.
for rp in op_models.RemoteProject.objects.exclude(
    remote_allocation=None
).select_related("remote_allocation"):
    ss_id = rp.remote_allocation.service_settings_id
    if rp.destination:
        derived.setdefault(ss_id, Counter())[rp.destination] += 1
        sources.setdefault(ss_id, set()).add("remote projects")

# Source B: the cached reports. Their `resource` is the same identifier, and
# their `project_identifier` matches Allocation.backend_id - which is what
# ties them back to a ServiceSettings. This covers settings that have local
# allocations but no remote projects, which source A cannot reach.
# values_list, not .only(): Allocation has an FSM state field whose tracker
# raises on a deferred attribute, and this never needs a model instance.
backend_id_to_ss = {
    backend_id: ss_id
    for backend_id, ss_id in op_models.Allocation.objects.values_list(
        "backend_id", "service_settings_id"
    )
    if backend_id
}
all_identifiers: set[str] = set()
for report_model in (
    op_models.CachedProjectUsageReport,
    op_models.CachedProjectStorageReport,
):
    for pid, resource in report_model.objects.values_list(
        "project_identifier", "resource"
    ):
        if not resource:
            continue
        all_identifiers.add(resource)
        ss_id = backend_id_to_ss.get(pid)
        if ss_id:
            derived.setdefault(ss_id, Counter())[resource] += 1
            sources.setdefault(ss_id, set()).add("cached reports")

print(f"{len(settings)} OpenPortal service settings\n")

ok = missing = ambiguous = repaired = 0
chosen_values: set[str] = set()

for ss_id in sorted(settings):
    ss = settings[ss_id]
    options = ss.options if isinstance(ss.options, dict) else {}
    current = options.get("instance_name")

    if current:
        ok += 1
        print(f"  [ok]      {ss_id:5d} {ss.name!r} -> {current}")
        continue

    counts = derived.get(ss_id, Counter())
    chosen = EXTRA.get(str(ss_id))
    source = "given"

    if not chosen:
        if len(counts) == 1:
            chosen = next(iter(counts))
            source = (
                f"{counts[chosen]} rows via "
                f"{' and '.join(sorted(sources.get(ss_id, {'?'})))}"
            )
        elif len(counts) > 1:
            ambiguous += 1
            print(
                f"  [AMBIG]   {ss_id:5d} {ss.name!r} -> several destinations: "
                f"{dict(counts)}"
            )
            print(f"            pass REPAIR_EXTRA='{ss_id}=<the right one>'")
            continue
        else:
            missing += 1
            print(
                f"  [MISSING] {ss_id:5d} {ss.name!r} -> nothing to derive from; "
                f"pass REPAIR_EXTRA='{ss_id}=<identifier>'"
            )
            continue

    chosen_values.add(chosen)
    verb = "set" if APPLY else "would set"
    print(f"  [{verb}]  {ss_id:5d} {ss.name!r} -> {chosen}  ({source})")
    if APPLY:
        ss.options = {**options, "instance_name": chosen}
        ss.save(update_fields=["options"])
        repaired += 1

print(
    f"\n{ok} already set, {repaired} repaired, "
    f"{ambiguous} ambiguous, {missing} underivable"
)

if missing or ambiguous:
    # Every identifier the cached reports have ever mentioned, minus the ones
    # already accounted for. The one you need is almost certainly in here, so
    # it can be picked from a real list rather than from memory.
    claimed = {
        s.options.get("instance_name")
        for s in settings.values()
        if isinstance(s.options, dict) and s.options.get("instance_name")
    }
    # Including the ones this run is about to set, or the list suggests
    # identifiers that are in fact already spoken for.
    claimed |= set(EXTRA.values()) | chosen_values
    unclaimed = sorted(all_identifiers - claimed)
    if unclaimed:
        print("\nIdentifiers seen in cached reports and not yet claimed:")
        for name in unclaimed:
            print(f"  {name}")

if not APPLY:
    print("\nDry run. Re-run with REPAIR_APPLY=1 to write.")
else:
    # Rebuild the map the way offering_mapping does, so the result is checked
    # against the thing that was actually broken rather than against itself.
    resolved = {
        s.options.get("instance_name")
        for s in ServiceSettings.objects.filter(id__in=settings_ids)
        if isinstance(s.options, dict) and s.options.get("instance_name")
    }
    print(f"\noffering_mapping will now resolve {len(resolved)} identifiers:")
    for name in sorted(resolved):
        print(f"  {name}")
