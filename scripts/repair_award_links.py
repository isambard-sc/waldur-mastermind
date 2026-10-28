"""Restore award links wiped by updates from the awarding portal that left them out.

ManagedProject.merge_details used to take an award's award, call and renewal
links straight from each incoming update, so an update without them removed
the stored ones - and with them HomePort's "Go to award" button. It now keeps
a stored link unless an update brings a new one. This puts back the links
already lost, from the award's own audit history: for each award with no
award, call or renewal link now, the most recent value it had.

    # see what it would change
    waldur shell < scripts/repair_award_links.py

    # do it
    REPAIR_APPLY=1 waldur shell < scripts/repair_award_links.py

    # in a pod, the script being in the image:
    kubectl exec -i -n "$NS" deploy/waldur-mastermind-api -- sh -c \\
      'waldur shell < /usr/src/waldur/scripts/repair_award_links.py'

Writes through ManagedProject.set_details, so each repair is itself recorded
in the award's audit log. Prints award ids, dates and the links restored
(links to awards and calls, not personal data).
"""

import os

from waldur_openportal import models

APPLY = os.environ.get("REPAIR_APPLY") == "1"

checked = repaired = 0

for managed_project in models.ManagedProject.objects.order_by("id"):
    checked += 1
    details = dict(managed_project.details or {})
    missing = [
        link for link in models.ManagedProject.LINK_FIELDS if not details.get(link)
    ]
    if not missing:
        continue

    restored = {}
    for entry in models.ManagedProjectAuditEntry.objects.filter(
        managed_project=managed_project, new_details__isnull=False
    ).order_by("-timestamp", "-id"):
        for link in missing:
            if link not in restored and (entry.new_details or {}).get(link):
                restored[link] = entry.new_details[link]
        if len(restored) == len(missing):
            break
    if not restored:
        continue

    repaired += 1
    verb = "restore" if APPLY else "would restore"
    for link, value in restored.items():
        print(
            f"  [{verb}] {managed_project.id:6d} awarded "
            f"{managed_project.created.date()}  {link}: {value}"
        )
    if APPLY:
        details.update(restored)
        managed_project.set_details(details)

print(f"\n{checked} awards checked, {repaired} {'repaired' if APPLY else 'to repair'}")
if repaired and not APPLY:
    print("\nDry run. Re-run with REPAIR_APPLY=1 to write.")
