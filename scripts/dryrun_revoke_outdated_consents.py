"""Report what marketplace.revoke_outdated_consents would revoke. Writes nothing.

The task runs daily and stamps revocation_date on every UserOfferingConsent
whose version differs from the current active ToS, for any active
requires_reconsent ToS whose grace period (created + grace_period_days) has
passed. Consents already on the current version are left alone.

The first run after an upgrade acts on however much has accumulated, so it is
worth knowing the number before the workers come back up.

    docker compose exec -T waldur-mastermind-api waldur shell \
        -c "$(cat scripts/dryrun_revoke_outdated_consents.py)"
"""

from django.utils import timezone

from waldur_mastermind.marketplace import models

now = timezone.now()
expired = [
    tos
    for tos in models.OfferingTermsOfService.objects.filter(
        is_active=True, requires_reconsent=True
    ).select_related("offering")
    if tos.grace_period_end and tos.grace_period_end <= now
]
print(f"{len(expired)} of the active reconsent ToS have an expired grace period")

total = 0
for tos in expired:
    consents = models.UserOfferingConsent.objects.filter(
        offering=tos.offering, revocation_date__isnull=True
    )
    stale = [c for c in consents if c.version != tos.version]
    total += len(stale)
    print(
        f"  {tos.offering.name!r}: ToS v{tos.version}, grace ended "
        f"{tos.grace_period_end:%Y-%m-%d}, {consents.count()} live consents, "
        f"{len(stale)} would be REVOKED"
    )

still_in_grace = [
    tos
    for tos in models.OfferingTermsOfService.objects.filter(
        is_active=True, requires_reconsent=True
    )
    if tos.grace_period_end and tos.grace_period_end > now
]
for tos in still_in_grace:
    print(
        f"  (still in grace until {tos.grace_period_end:%Y-%m-%d}: {tos.offering.name!r})"
    )

print(f"\n{total} consents would be revoked on the first run.")
