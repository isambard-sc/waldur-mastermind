"""Report how counting only the current award's spend will change project credit.

An award's project credit is its allocation less the spend excluding the
current month. That spend used to be every invoice the project had ever had;
it is now only the share falling on the days the CURRENT award has been
attached to the project (utils.get_project_spend_info(..., award_only=True)).
A project that held an earlier award, or that had spend before its award
arrived, therefore gets credit back the next time set_project_credits runs -
on an allocation change, or in the nightly fix_total_allocation.

Run this with the NEW code deployed but before that reconciliation runs, to
see what it will do. Writes nothing:

    waldur shell < scripts/dryrun_award_only_credit.py

Prints dates, counts and credit amounts only: no names or identifiers.
"""

import decimal

from waldur_mastermind.invoices import models as invoice_models
from waldur_openportal import models, utils

ZERO = decimal.Decimal(0)
TOLERANCE = decimal.Decimal("0.01")

unchanged = gains = losses = skipped = 0
total_gain = total_loss = ZERO
rows = []

for managed_project in models.ManagedProject.objects.exclude(project=None):
    project = managed_project.project
    if project.is_removed or project.is_expired:
        continue
    template = managed_project.project_template
    details = managed_project.get_details()
    if template is None or details is None or details.allocation is None:
        skipped += 1
        continue

    allocation = decimal.Decimal(str(template.convert_to_credits(details.allocation)))
    _, lifetime = utils.get_project_spend_info(
        project, include_current_month=False, silent=True
    )
    _, award = utils.get_project_spend_info(
        project, include_current_month=False, silent=True, award_only=True
    )
    before = max(allocation - lifetime, ZERO)
    after = max(allocation - award, ZERO)
    credit = invoice_models.ProjectCredit.objects.filter(project=project).first()
    current = credit.value if credit else None

    change = after - before
    if abs(change) < TOLERANCE:
        unchanged += 1
        continue
    if change > 0:
        gains += 1
        total_gain += change
    else:
        losses += 1
        total_loss += change
    rows.append(
        (
            managed_project.created.date(),
            managed_project.attachments.count(),
            allocation,
            lifetime,
            award,
            current,
            after,
        )
    )

print(
    f"awards checked: {unchanged + gains + losses} (skipped, no allocation: {skipped})"
)
print(f"credit unchanged: {unchanged}")
print(f"credit goes UP:   {gains}  (total +{total_gain:.2f})")
print(f"credit goes DOWN: {losses}  (total {total_loss:.2f})")
if rows:
    print(
        "\nawarded     attach  allocation  lifetime spend  award spend"
        "  credit now  credit after"
    )
    for created, attachments, allocation, lifetime, award, current, after in sorted(
        rows
    ):
        now = f"{current:.2f}" if current is not None else "none"
        print(
            f"{created}  {attachments:>6}  {allocation:>10.2f}  {lifetime:>14.2f}"
            f"  {award:>11.2f}  {now:>10}  {after:>12.2f}"
        )
