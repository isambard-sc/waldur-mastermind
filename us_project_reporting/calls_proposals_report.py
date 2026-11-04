#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = ["requests"]
# ///
"""
Report on calls and proposals in the Waldur portal.

For each call, shows:
  - Total proposals and breakdown by state
  - How many proposals were awarded (state=accepted, linked to a project)

Usage:
    python calls_proposals_report.py [--token TOKEN] [--base-url URL] [--call-uuid UUID]

Token can also be provided via the WALDUR_TOKEN environment variable.

Example:
    WALDUR_TOKEN=abc123 python calls_proposals_report.py
    WALDUR_TOKEN=abc123 python calls_proposals_report.py --call-uuid <uuid>
"""

import argparse
import csv
import getpass
import os
import sys

import requests

BASE_URL = "https://portal-airr-api.isambard.ac.uk"


def paginate(session, url, params=None):
    """Yield all items from a paginated Waldur API endpoint."""
    params = {**(params or {}), "page_size": 100, "page": 1}
    while True:
        resp = session.get(url, params=params)
        if resp.status_code == 401:
            sys.exit("Error: invalid or expired API token")
        resp.raise_for_status()
        data = resp.json()
        yield from data
        if 'rel="next"' not in resp.headers.get("Link", ""):
            break
        params["page"] += 1


def main():
    parser = argparse.ArgumentParser(
        description="Report on calls and proposals"
    )
    parser.add_argument("--token", help="API token (or set WALDUR_TOKEN)")
    parser.add_argument("--base-url", default=BASE_URL, help="Waldur API base URL")
    parser.add_argument(
        "--call-uuid",
        help="Filter to a single call UUID (default: all calls)",
    )
    parser.add_argument(
        "--csv",
        dest="csv_output",
        action="store_true",
        help="Output CSV instead of human-readable text",
    )
    args = parser.parse_args()

    base_url = args.base_url.rstrip("/")

    token = args.token or os.environ.get("WALDUR_TOKEN")
    if not token:
        token = getpass.getpass("Enter your API token: ").strip()
    if not token:
        sys.exit("Error: API token is required")

    session = requests.Session()
    session.headers["Authorization"] = f"Token {token}"

    # ── 1. Fetch calls ──────────────────────────────────────────────────────
    print("Fetching calls...", file=sys.stderr)
    call_params = {}
    if args.call_uuid:
        call_params["uuid"] = args.call_uuid

    calls = list(paginate(session, f"{base_url}/api/proposal-protected-calls/", call_params))
    print(f"  Found {len(calls)} call(s)", file=sys.stderr)

    # ── 2. For each call, fetch proposals ───────────────────────────────────
    rows = []  # one row per call

    for call in calls:
        call_uuid = call["uuid"]
        call_name = call.get("name", call_uuid)
        call_state = call.get("state", "")

        print(f"  Processing call: {call_name} ({call_state})", file=sys.stderr)

        proposals = list(
            paginate(
                session,
                f"{base_url}/api/proposal-proposals/",
                {"call_uuid": call_uuid},
            )
        )

        # Count proposals by state
        state_counts = {}
        awarded = []
        for p in proposals:
            state = p.get("state", "unknown")
            state_counts[state] = state_counts.get(state, 0) + 1
            if state == "accepted":
                awarded.append(p)

        rows.append(
            {
                "call_uuid": call_uuid,
                "call_name": call_name,
                "call_state": call_state,
                "total_proposals": len(proposals),
                "state_counts": state_counts,
                "awarded_count": len(awarded),
            }
        )

    # ── 4. Output ───────────────────────────────────────────────────────────
    if args.csv_output:
        _output_csv(rows)
    else:
        _output_text(rows)


def _output_text(rows):
    for row in rows:
        print(f"\n{'='*70}")
        print(f"Call:   {row['call_name']}")
        print(f"UUID:   {row['call_uuid']}")
        print(f"State:  {row['call_state']}")
        print(f"Total proposals: {row['total_proposals']}")

        if row["state_counts"]:
            print("  By state:")
            for state, count in sorted(row["state_counts"].items()):
                print(f"    {state:20s}: {count}")

        print(f"Awarded to project: {row['awarded_count']}")

    print(f"\n{'='*70}")


def _output_csv(rows):
    fieldnames = [
        "call_name",
        "call_uuid",
        "call_state",
        "total_proposals",
        "awarded_count",
    ]

    writer = csv.DictWriter(sys.stdout, fieldnames=fieldnames)
    writer.writeheader()

    for row in rows:
        writer.writerow(
            {
                "call_name": row["call_name"],
                "call_uuid": row["call_uuid"],
                "call_state": row["call_state"],
                "total_proposals": row["total_proposals"],
                "awarded_count": row["awarded_count"],
            }
        )


if __name__ == "__main__":
    main()
