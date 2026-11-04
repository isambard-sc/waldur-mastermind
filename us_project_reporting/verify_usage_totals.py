#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = ["requests", "openpyxl"]
# ///
"""
Verification for company_domain_report.py: compare one offering's per-user
node hours with its allocation-level node hours, month by month.

Both come from the same OpenPortal usage report for each project:
  allocation-level  /api/marketplace-component-usages/ — the project's total for
                    the month, one record per resource (allocation) per month
  per-user          /api/marketplace-component-user-usages/ — that total split by
                    user, written for the users linked to the allocation at the
                    time of each sync; this is what company_domain_report.py uses

They should agree. Where they don't, the usual reasons are:
  - a user left mid-month: their per-user figure stops updating, the project
    total keeps counting their later hours (per-user < allocation-level)
  - late usage for a closed month: syncs refresh last month's per-user figures
    but only write the project total for the current month (per-user can end up
    slightly > allocation-level)
  - usage by a cluster account not linked to any Waldur user (only in the total)
  - no allocation-level record for a month (e.g. no active plan period), in
    which case per-user figures are skipped too

Prints aggregates only (no names or emails) to stdout. Read-only.

Usage:
    WALDUR_TOKEN=... uv run verify_usage_totals.py [--offering-name NAME | --offering-uuid UUID]
"""

import argparse
import getpass
import os
import sys
from collections import defaultdict
from datetime import date
from decimal import Decimal

# Shared API helpers; `uv run` puts this script's directory on sys.path.
from company_domain_report import (
    DEFAULT_BASE_URL,
    DEFAULT_OFFERING_NAME,
    USAGE_COMPONENT_TYPE,
    eprint,
    make_session,
    paginate,
    resolve_offering_uuid,
)

# Resource names are just the offering name here, so identify allocations by project/organisation.
ALLOCATION_FIELDS = ["uuid", "usage", "billing_period", "resource_uuid", "project_name", "customer_name"]
PER_USER_FIELDS = ["uuid", "usage", "billing_period", "resource_uuid"]
TOLERANCE = Decimal("0.05")  # hours; differences below this are rounding


def fetch(session, label, url, params) -> list[dict]:
    eprint(f"Fetching {label} ...")
    rows = {}
    for r in paginate(session, url, params):
        rows.setdefault(r["uuid"], r)
    eprint(f"Fetched {len(rows)} {label} row(s).")
    return list(rows.values())


def main():
    parser = argparse.ArgumentParser(description="Compare per-user and allocation-level node hours for one offering.")
    parser.add_argument("--token", help="Waldur API token (or set WALDUR_TOKEN env variable)")
    parser.add_argument(
        "--base-url",
        default=os.environ.get("WALDUR_BASE_URL", DEFAULT_BASE_URL),
        help=f"Waldur API base URL (default: {DEFAULT_BASE_URL}, or WALDUR_BASE_URL env var)",
    )
    offering = parser.add_mutually_exclusive_group()
    offering.add_argument("--offering-name", default=DEFAULT_OFFERING_NAME, help=f"default: {DEFAULT_OFFERING_NAME!r}")
    offering.add_argument("--offering-uuid", help="Offering UUID (skips the name lookup)")
    args = parser.parse_args()

    token = args.token or os.environ.get("WALDUR_TOKEN") or getpass.getpass("Enter your Waldur API token: ").strip()
    if not token:
        sys.exit("Error: Waldur API token is required")
    session = make_session(token)
    base_url = args.base_url.rstrip("/")
    offering_uuid = args.offering_uuid or resolve_offering_uuid(session, base_url, args.offering_name)
    label = args.offering_uuid or args.offering_name
    eprint(f"Offering: {label} ({offering_uuid})")

    usage_filter = {"offering_uuid": offering_uuid, "type": USAGE_COMPONENT_TYPE}
    allocation_rows = fetch(
        session, "allocation-level usage", f"{base_url}/api/marketplace-component-usages/",
        {**usage_filter, "field": ALLOCATION_FIELDS, "o": "billing_period"},
    )
    per_user_rows = fetch(
        session, "per-user usage", f"{base_url}/api/marketplace-component-user-usages/",
        {**usage_filter, "field": PER_USER_FIELDS, "o": "component_usage__billing_period,username"},
    )

    # (resource, month) -> totals, so mismatches can be pinned to allocations.
    allocation = defaultdict(Decimal)
    per_user = defaultdict(Decimal)
    names = {}
    for r in allocation_rows:
        key = (r.get("resource_uuid"), (r.get("billing_period") or "")[:7])
        allocation[key] += Decimal(str(r.get("usage") or 0))
        names[r.get("resource_uuid")] = f"{r.get('customer_name') or '?'} / {r.get('project_name') or '?'}"
    for r in per_user_rows:
        key = (r.get("resource_uuid"), (r.get("billing_period") or "")[:7])
        per_user[key] += Decimal(str(r.get("usage") or 0))

    keys = set(allocation) | set(per_user)
    by_month = defaultdict(lambda: {"allocation": Decimal(0), "per_user": Decimal(0), "mismatched": 0, "allocations": 0})
    for resource, month in keys:
        m = by_month[month]
        a, u = allocation.get((resource, month), Decimal(0)), per_user.get((resource, month), Decimal(0))
        m["allocation"] += a
        m["per_user"] += u
        if a or u:
            m["allocations"] += 1
        if abs(a - u) > TOLERANCE:
            m["mismatched"] += 1

    current_month = date.today().strftime("%Y-%m")
    print(f"\n{label}: {USAGE_COMPONENT_TYPE} hours, allocation-level vs per-user\n")
    print(f"{'month':9} {'allocation':>13} {'per-user':>13} {'difference':>12} {'per-user %':>11} {'allocations':>12} {'mismatched':>11}")
    total = defaultdict(Decimal)
    for month in sorted(by_month):
        m = by_month[month]
        diff = m["allocation"] - m["per_user"]
        pct = f"{100 * m['per_user'] / m['allocation']:.1f}%" if m["allocation"] else "-"
        flag = "  (current month, partial)" if month == current_month else ""
        print(
            f"{month:9} {m['allocation']:13,.2f} {m['per_user']:13,.2f} {diff:12,.2f} {pct:>11} "
            f"{m['allocations']:12} {m['mismatched']:11}{flag}"
        )
        total["allocation"] += m["allocation"]
        total["per_user"] += m["per_user"]
    diff = total["allocation"] - total["per_user"]
    pct = f"{100 * total['per_user'] / total['allocation']:.1f}%" if total["allocation"] else "-"
    print(f"{'TOTAL':9} {total['allocation']:13,.2f} {total['per_user']:13,.2f} {diff:12,.2f} {pct:>11}")

    worst = sorted(
        ((abs(allocation.get(k, Decimal(0)) - per_user.get(k, Decimal(0))), k) for k in keys),
        reverse=True,
    )[:10]
    worst = [(d, k) for d, k in worst if d > TOLERANCE]
    if worst:
        print("\nLargest allocation-month differences (allocation-level − per-user):")
        for d, (resource, month) in worst:
            a, u = allocation.get((resource, month), Decimal(0)), per_user.get((resource, month), Decimal(0))
            note = "  [no per-user rows]" if a and not u else ""
            print(f"  {month}  {names.get(resource) or resource}: {a:,.2f} vs {u:,.2f} ({a - u:+,.2f}){note}")
    else:
        print("\nEvery allocation-month agrees within rounding.")


if __name__ == "__main__":
    main()
