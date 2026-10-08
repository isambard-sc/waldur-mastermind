"""Explain what the "Credit consumption" graph reads, and whether zero is real.

The graph is fed by /api/customer-credits/<uuid>/consumptions/, which is

    InvoiceItem.objects.filter(credit=customer_credit, unit_price__lt=0)

grouped by invoice month. Those negative items are not resource usage: they
are the credit APPLIED against an invoice, written by
invoices.compensations.MonthlyCompensation.apply_compensations() when an
invoice is finalised. It walks each project's cost on the invoice, decrements
ProjectCredit.value by it, and records an InvoiceItem with
unit_price = -compensation and credit = the customer credit.

So an empty graph means no credit was ever applied - which is NOT the same as
"the project stayed within its allocation". Staying within allocation is
exactly when credit IS applied: cost is met from credit, the balance drops,
and a compensation item is written. The graph would legitimately be empty
only if the invoices carry no cost for these projects at all.

This reports, per month: the project's invoice cost, and the compensation
actually recorded. Read-only.

    docker compose exec -T -e CREDIT_PROJECT=<project-uuid> \
        waldur-mastermind-api waldur shell \
        -c "$(cat scripts/debug_credit_consumption.py)"
"""

import os
from collections import defaultdict

from waldur_core.structure.models import Project
from waldur_mastermind.invoices import models as invoice_models

SELECTOR = os.environ.get("CREDIT_PROJECT", "").strip()

project = Project._base_manager.filter(uuid=SELECTOR).first()
if project is None:
    print(f"No project matching {SELECTOR!r}")
else:
    customer = project.customer
    print(f"project  : {project.name!r} ({project.uuid})")
    print(f"customer : {customer.name!r}")

    pc = invoice_models.ProjectCredit.objects.filter(project=project).first()
    cc = invoice_models.CustomerCredit.objects.filter(customer=customer).first()
    print(f"ProjectCredit.value  : {pc.value if pc else 'no row'}")
    print(f"CustomerCredit.value : {cc.value if cc else 'no row'}")
    if pc:
        print(f"minimal_consumption  : {pc.minimal_consumption}")

    # Charges and credit applications are BOTH InvoiceItems on the project -
    # the credit application is one with a negative unit_price - so summing
    # price over all of them gives the NET, which is zero in exactly the
    # healthy case where the cost was fully met from credit. Separate them, or
    # the table reads as "never billed" for the months that worked properly.
    charged = defaultdict(lambda: 0)
    credited = defaultdict(lambda: 0)
    for item in invoice_models.InvoiceItem.objects.filter(
        project=project
    ).select_related("invoice"):
        key = (item.invoice.year, item.invoice.month)
        if item.unit_price < 0:
            credited[key] += item.price
        else:
            charged[key] += item.price

    # Credit applied, per month. Keyed on the CUSTOMER credit, which is what
    # the graph reads - a compensation item carries the project it was for.
    applied = defaultdict(lambda: 0)
    applied_here = defaultdict(lambda: 0)
    if cc:
        for item in invoice_models.InvoiceItem.objects.filter(
            credit=cc, unit_price__lt=0
        ).select_related("invoice"):
            applied[(item.invoice.year, item.invoice.month)] += item.price
            if item.project_id == project.id:
                applied_here[(item.invoice.year, item.invoice.month)] += item.price

    months = sorted(set(charged) | set(credited) | set(applied))
    if not months:
        print("\nNo invoice items at all for this project.")
    else:
        print(
            f"\n{'month':>9} | {'charged':>11} | {'credited':>11}"
            f" | {'net':>10} | {'customer applied':>17}"
        )
        for year, month in months:
            key = (year, month)
            net = charged[key] + credited[key]
            flag = (
                "  <- charged, nothing credited"
                if (charged[key] and not credited[key])
                else ""
            )
            print(
                f"  {year}-{month:02d} | {charged[key]:11.2f}"
                f" | {-credited[key]:11.2f} | {net:10.2f}"
                f" | {-applied[key]:17.2f}{flag}"
            )

    # The new ledger, for comparison. Empty for months that predate it.
    txns = (
        invoice_models.CreditTransaction.objects.filter(project_credit=pc)
        if pc
        else invoice_models.CreditTransaction.objects.none()
    )
    print(f"\nCreditTransaction rows for this project's credit: {txns.count()}")
    by_type = defaultdict(lambda: 0)
    for t in txns:
        by_type[t.transaction_type] += 1
    for name, n in sorted(by_type.items()):
        print(f"  {name}: {n}")

    print(
        "\nReading this:"
        "\n  charged ~= credited, net ~0  healthy - usage billed, met from credit"
        "\n  charged, nothing credited    that invoice was never compensated"
        "\n                               (the current month is expected)"
        "\n  nothing charged at all       the offerings are not billed, and an"
        "\n                               empty consumption graph is correct"
        "\n"
        "\nCreditTransaction is the ledger the resync added. It records only"
        "\nmovements made after it was wired up, so zero rows means no history,"
        "\nNOT no consumption - the invoice items above are the record."
        "\n`waldur backfill_credit_ledger --dry-run` reconstructs what is"
        "\nrecoverable."
    )
