"""Point awards at the identifier the receiving portal now reports. Run on the AWARDING portal.

From May to September 2026 a receiving portal (here, brics) named the
projects it made for awards after the SENDING portal ("u6uk.airr") instead of
itself ("u6uk.brics"), and the sending portal stored that identifier twice:
as the allocation's remote_project_identifier and as the award record's key,
RemoteProject.identifier. Once the receiving portal was repaired
(scripts/repair_managed_project_local_portal.py, run there) it answers with
the corrected identifier, which update_mapping refuses - so every update for
those awards fails at its last step and the award sits in "Pending".

This rewrites both stored copies, for live awards (those with an allocation)
whose destination's receiving portal is REPAIR_PORTAL and whose identifier
names this portal instead. Awards to any other receiving portal are never
touched, and nor are deleted or rejected ones, which nothing syncs. A rewrite
that would collide with another award record already holding the corrected
identifier is refused and reported.

    # see what it would change
    waldur shell < scripts/repair_remote_award_identifiers.py

    # do it
    REPAIR_APPLY=1 waldur shell < scripts/repair_remote_award_identifiers.py

    # the receiving portal to repair for (default brics)
    REPAIR_PORTAL=brics waldur shell < scripts/repair_remote_award_identifiers.py

Written to run on older code as well as current: it uses only fields both
have. Prints award identifiers and destinations, not personal data.
"""

import os
from collections import Counter

from django.db import transaction

from waldur_openportal import models

APPLY = os.environ.get("REPAIR_APPLY") == "1"
RECEIVING_PORTAL = os.environ.get("REPAIR_PORTAL", "brics")


def split_identifier(identifier):
    """("u6uk", "airr") for "u6uk.airr"; None if it does not have two parts."""
    project, _, portal = (identifier or "").rpartition(".")
    return (project, portal) if project and portal else None


summary = Counter()

for remote_project in (
    models.RemoteProject.objects.exclude(identifier=None)
    .exclude(remote_allocation=None)
    .select_related("remote_allocation")
    .order_by("destination", "identifier")
):
    agents = remote_project.destination.split(".")
    if len(agents) < 2 or agents[1] != RECEIVING_PORTAL:
        summary["other receiving portal: left alone"] += 1
        continue

    parts = split_identifier(remote_project.identifier)
    if parts is None:
        summary["unparsable identifier: left alone"] += 1
        continue
    project, portal = parts
    if portal == RECEIVING_PORTAL:
        summary["already correct"] += 1
        continue
    if portal != agents[0]:
        # Not the bug's signature (the sender's own portal): leave it.
        summary["names some other portal: left alone"] += 1
        print(
            f"  [SKIP]  {remote_project.identifier} @ {remote_project.destination}: "
            f"names portal {portal!r}, expected {agents[0]!r} or {RECEIVING_PORTAL!r}"
        )
        continue

    old = remote_project.identifier
    new = f"{project}.{RECEIVING_PORTAL}"
    allocation = remote_project.remote_allocation

    clash = (
        models.RemoteProject.objects.filter(
            destination=remote_project.destination, identifier=new
        )
        .exclude(pk=remote_project.pk)
        .first()
    )
    if clash is not None:
        summary["blocked: corrected identifier already held"] += 1
        print(
            f"  [CLASH] {old} -> {new} @ {remote_project.destination}: already "
            f"held by another award record (state {clash.state}); not touched"
        )
        continue

    if allocation.remote_project_identifier not in (old, None, ""):
        summary["blocked: allocation names something else"] += 1
        print(
            f"  [SKIP]  {old} @ {remote_project.destination}: its allocation holds "
            f"{allocation.remote_project_identifier!r}; not touched"
        )
        continue

    summary["changed" if APPLY else "to change"] += 1
    print(
        f"  [{'change' if APPLY else 'would change'}] {old} -> {new} "
        f"@ {remote_project.destination} (state {remote_project.state})"
    )
    if APPLY:
        # update() rather than save(): nothing else changes, and save-side
        # handlers must not fire. Both copies move together or not at all.
        with transaction.atomic():
            models.RemoteProject.objects.filter(pk=remote_project.pk).update(
                identifier=new
            )
            type(allocation).objects.filter(pk=allocation.pk).update(
                remote_project_identifier=new
            )

print()
for label, count in sorted(summary.items()):
    print(f"  {count:>6}  {label}")
if summary["to change"]:
    print("\nDry run. Re-run with REPAIR_APPLY=1 to write.")
elif APPLY:
    print(
        "\nThe next sync sends each changed award again; it should come back "
        "Active once the receiving portal confirms it."
    )
