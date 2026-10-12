"""Re-point ManagedProject.local_identifier at the local portal.

OpenPortalBoard._get_local_identifier minted local identifiers through
_to_project_identifier, which qualifies a bare shortname with the portal at
the head of the BOARD's destination - the remote portal that raised the
award. An award arriving through a gateway ("airr.brics.isambard-ai") was
therefore stored as "u6vf.airr" where it should have been "u6vf.brics".

Nothing finds such a project: filters._identifiers_for_project_uuid builds
the identifier from openportal.get_portal(), and tasks.refresh_remote_award
and the notification handler both discard an identifier whose portal is not
this one. The board now uses _to_local_project_identifier, so new awards are
right; this repairs the ones already stored.

    # see what it would change
    docker compose exec -T waldur-mastermind-api waldur shell \
        -c "$(cat scripts/repair_managed_project_local_portal.py)"

    # do it
    docker compose exec -T -e REPAIR_APPLY=1 waldur-mastermind-api waldur shell \
        -c "$(cat scripts/repair_managed_project_local_portal.py)"

Only the portal part is rewritten; the shortname is untouched. The local
portal comes from openportal.get_portal() rather than being hardcoded, and
the run stops before writing anything if that cannot be resolved - renaming
identifiers onto a guessed portal would be worse than leaving them wrong.

A rewrite is refused, and reported, where it would collide with another
ManagedProject that already holds the corrected identifier: local_identifier
is not unique in the schema, so the database would accept the duplicate and
leave two awards claiming one project identifier.
"""

import os

import openportal

from waldur_openportal import config, models

APPLY = os.environ.get("REPAIR_APPLY") == "1"

if not config.ensure_config_loaded():
    print("OpenPortal configuration is not available; cannot resolve the local")
    print("portal. Nothing examined, nothing written.")
else:
    local_portal = str(openportal.get_portal())
    print(f"local portal: {local_portal!r}\n")

    rows = [
        (pk, identifier)
        for pk, identifier in models.ManagedProject.objects.exclude(
            local_identifier=None
        )
        .exclude(local_identifier="")
        .values_list("id", "local_identifier")
    ]
    print(f"{len(rows)} ManagedProject rows with a local_identifier")

    # Every identifier already in use, so a rewrite cannot be made to collide
    # with one. Keyed by identifier -> the row holding it.
    held_by = {identifier: pk for pk, identifier in rows}

    ok = wrong = unparsable = blocked = changed = 0

    for pk, identifier in sorted(rows, key=lambda r: r[1]):
        try:
            parsed = openportal.ProjectIdentifier(identifier)
        except Exception:
            unparsable += 1
            print(f"  [SKIP]  {pk:6d} {identifier!r} does not parse as an identifier")
            continue

        if str(parsed.portal) == local_portal:
            ok += 1
            continue

        wrong += 1
        corrected = f"{parsed.project}.{local_portal}"

        other = held_by.get(corrected)
        if other is not None and other != pk:
            blocked += 1
            print(
                f"  [CLASH] {pk:6d} {identifier!r} -> {corrected!r}"
                f" is already held by ManagedProject {other}; not touched"
            )
            continue

        verb = "change" if APPLY else "would change"
        print(f"  [{verb}] {pk:6d} {identifier!r} -> {corrected!r}")

        if APPLY:
            # update() rather than save(): nothing else on the row is being
            # touched, and this must not fire the model's save-side handlers.
            models.ManagedProject.objects.filter(id=pk).update(
                local_identifier=corrected
            )
            held_by[corrected] = pk
            del held_by[identifier]
            changed += 1

    print(
        f"\n{ok} already on {local_portal!r}, {wrong} on another portal"
        f" ({blocked} blocked by a clash), {unparsable} unparsable"
    )

    if wrong and not APPLY:
        print("\nDry run. Re-run with REPAIR_APPLY=1 to write.")
    elif APPLY:
        print(f"{changed} rows rewritten.")
