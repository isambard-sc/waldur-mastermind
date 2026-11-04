#!/usr/bin/env python3
"""
Count user account creations per month, based on the date_joined field
returned by the Waldur /api/users/ endpoint.

Usage:
    python user_signups_by_month.py [--token TOKEN]

Token can also be provided via the WALDUR_TOKEN environment variable,
or entered interactively when prompted.

Example:
    WALDUR_TOKEN=abc123 python user_signups_by_month.py
"""

import argparse
import getpass
import os
import sys
from collections import Counter
from datetime import datetime

import requests

BASE_URL = "https://portal-api.isambard.ac.uk"


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
        description="Count user account creations per month"
    )
    parser.add_argument(
        "--token",
        help="API token (or set WALDUR_TOKEN environment variable)",
    )
    args = parser.parse_args()

    token = args.token or os.environ.get("WALDUR_TOKEN")
    if not token:
        token = getpass.getpass("Enter your API token: ").strip()
    if not token:
        sys.exit("Error: API token is required")

    session = requests.Session()
    session.headers["Authorization"] = f"Token {token}"

    print("Fetching users...")
    users = list(paginate(session, f"{BASE_URL}/api/users/"))
    print(f"Found {len(users)} user(s).\n")

    counts = Counter()
    for user in users:
        date_joined = user.get("date_joined")
        if not date_joined:
            continue
        month_key = datetime.fromisoformat(date_joined).strftime("%Y-%m")
        counts[month_key] += 1

    print("Month,New Accounts")
    for month in sorted(counts):
        print(f"{month},{counts[month]}")


if __name__ == "__main__":
    main()
