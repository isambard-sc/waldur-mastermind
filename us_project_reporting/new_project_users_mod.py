#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = ["requests"]
# ///
"""
Generate a list of users on active Isambard-AI projects who need to be onboarded
to Bristol Portal (i.e. need an AWS account set up for them).

Background
----------
There are two connected Waldur portals:
  - AIRRPortal: https://portal-airr-api.isambard.ac.uk
    Users join projects here. Projects are submitted to Bristol Portal for approval.
  - Bristol Portal: receives projects from AIRRPortal and approves them.
    Users need an AWS account to log in to Bristol Portal.

A project in AIRRPortal has a corresponding RemoteProject record that tracks its
state in Bristol Portal. Projects may have an earliest_approve embargo date — Bristol
Portal will not approve them until that date is reached.

This script identifies users who need to be onboarded, covering two cases:
  1. Projects that recently became active in Bristol Portal (within last N days):
     captures ALL current members, including those who joined AIRRPortal earlier
     but were waiting for the embargo to lift.
  2. Projects already active in Bristol Portal: captures members who joined recently.

Note: the current version also checks each user against Keycloak and splits the
output into those who already have an account and those who do not. This check
is for development/testing only and will be removed from the final version.

Usage:
    python new_project_users_mod.py [--token TOKEN]

The AIRRPortal API token can also be provided via WALDUR_TOKEN environment variable,
or entered interactively when prompted.

Output:
    Tab-separated user rows go to stdout; all progress messages go to stderr.
    To copy the data to the clipboard while still seeing it in the terminal:

    WSL:             uv run new_project_users_mod.py | tee /dev/tty | clip.exe
    macOS:           uv run new_project_users_mod.py | tee /dev/tty | pbcopy
    Linux (X11):     uv run new_project_users_mod.py | tee /dev/tty | xclip -selection clipboard
    Linux (Wayland): uv run new_project_users_mod.py | tee /dev/tty | wl-copy

Example:
    WALDUR_TOKEN=abc123 python new_project_users_mod.py
"""

import argparse
import csv
import getpass
import os
import sys
import time
from datetime import datetime, timezone, timedelta

import requests

# All status/progress output goes to stderr so stdout carries only TSV data rows.
# This lets you pipe stdout to clip.exe/pbcopy without mixing in prose.
eprint = lambda *a, **k: print(*a, **{**k, "file": sys.stderr})

# AIRRPortal (Portal A) — the Waldur instance where users join projects
BASE_URL = "https://portal-airr-api.isambard.ac.uk"

# Only include projects that have this string in their marketplace resource name.
# All Isambard-AI projects carry an offering with this prefix.
RESOURCE_FILTER = "Isambard-AI"

# Bristol Portal's Keycloak instance — used to check whether users already have
# an account registered via MyAccessID (OIDC).
KEYCLOAK_BASE = "https://keycloak-dev.isambard.ac.uk/realms/isambard/protocol/openid-connect"
KEYCLOAK_ADMIN = "https://keycloak-dev.isambard.ac.uk/admin/realms/isambard"
KEYCLOAK_DEVICE_ENDPOINT = f"{KEYCLOAK_BASE}/auth/device"
KEYCLOAK_TOKEN_ENDPOINT = f"{KEYCLOAK_BASE}/token"


def paginate(session, url, params=None):
    """Yield all items from a paginated Waldur API endpoint.

    Waldur defaults to 10 items per page. We request 100 to reduce round trips
    and follow the Link header to fetch subsequent pages automatically.
    """
    params = {**(params or {}), "page_size": 100, "page": 1}
    while True:
        resp = session.get(url, params=params)
        if resp.status_code == 401:
            sys.exit("Error: invalid or expired AIRRPortal API token")
        resp.raise_for_status()
        data = resp.json()
        yield from data
        if 'rel="next"' not in resp.headers.get("Link", ""):
            break
        params["page"] += 1


def keycloak_device_auth(client_id: str) -> str:
    """Authenticate via Keycloak device flow and return an access token.

    Device flow is used because this is a CLI script with no redirect URI.
    The user opens a URL in their browser; the script polls until confirmed.
    """
    resp = requests.post(
        KEYCLOAK_DEVICE_ENDPOINT,
        data={"client_id": client_id},
    )
    resp.raise_for_status()
    device = resp.json()

    verification_uri = device.get("verification_uri_complete") or device.get("verification_uri")
    user_code = device.get("user_code")
    device_code = device["device_code"]
    expires_in = device.get("expires_in", 600)
    interval = device.get("interval", 5)

    eprint("\n--- Keycloak Device Authentication ---")
    eprint(f"Open this URL in your browser and sign in:\n\n  {verification_uri}\n")
    if not device.get("verification_uri_complete"):
        eprint(f"Then enter the code: {user_code}")
    eprint("Waiting for authentication", end="", flush=True)

    deadline = time.time() + expires_in
    while time.time() < deadline:
        time.sleep(interval)
        token_resp = requests.post(
            KEYCLOAK_TOKEN_ENDPOINT,
            data={
                "client_id": client_id,
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": device_code,
            },
        )
        if token_resp.status_code == 200:
            eprint(" done.\n")
            return token_resp.json()["access_token"]
        error = token_resp.json().get("error", "")
        if error == "authorization_pending":
            eprint(".", end="", flush=True)
        elif error == "slow_down":
            interval += 5
            eprint(".", end="", flush=True)
        else:
            eprint()
            sys.exit(f"Keycloak auth error: {error}")

    sys.exit("Error: Keycloak device code expired before authentication completed")


def keycloak_user_exists(kc_session: requests.Session, email: str) -> bool:
    """Return True if a user with the given email exists in the Keycloak realm."""
    resp = kc_session.get(
        f"{KEYCLOAK_ADMIN}/users",
        params={"email": email, "exact": "true"},
    )
    if resp.status_code == 403:
        sys.exit("Error: Keycloak token lacks the view-users role")
    resp.raise_for_status()
    return len(resp.json()) > 0


# Domains that are likely federated via MyAccessID or an external IdP configured
# in the Bristol Keycloak realm. Users from these domains may be able to log in
# without a separately created account, but should be manually verified.
_INSTITUTIONAL_EXACT = {"ukri.org", "dsit.gov.uk"}
_INSTITUTIONAL_SUFFIXES = (".ac.uk", ".edu")


def is_institutional(email: str) -> bool:
    if "@" not in email:
        return False
    domain = email.lower().rsplit("@", 1)[1]
    return domain in _INSTITUTIONAL_EXACT or domain.endswith(_INSTITUTIONAL_SUFFIXES)


def main():
    parser = argparse.ArgumentParser(
        description=f"List users who joined an active '{RESOURCE_FILTER}' project and check their Keycloak status"
    )
    parser.add_argument("--token", help="AIRRPortal API token (or set WALDUR_TOKEN env variable)")
    args = parser.parse_args()

    token = args.token or os.environ.get("WALDUR_TOKEN")
    if not token:
        token = getpass.getpass("Enter your AIRRPortal API token: ").strip()
    if not token:
        sys.exit("Error: AIRRPortal API token is required")

    sys.stderr.write("How many days back to look? (max 7, press Enter for 1): ")
    sys.stderr.flush()
    raw = sys.stdin.readline().strip()
    if raw == "":
        days = 1
    elif raw.isdigit() and 1 <= int(raw) <= 7:
        days = int(raw)
    else:
        sys.exit("Error: please enter a number between 1 and 7")

    session = requests.Session()
    session.headers["Authorization"] = f"Token {token}"

    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    # since is midnight N days ago — day-granular, not a rolling 24h window.
    # e.g. at 14:00 UTC with days=1, since=yesterday 00:00, covering ~38 hours.
    since = today_start - timedelta(days=days)

    # --- Step 1: Fetch all active RemoteProjects from AIRRPortal ---
    # A RemoteProject is AIRRPortal's record of a project that has been submitted
    # to Bristol Portal. state=active means Bristol Portal has confirmed the project
    # and any earliest_approve embargo has passed — users can now be onboarded.
    eprint(f"\nFetching active RemoteProjects from AIRRPortal...")
    all_active_remote = list(paginate(
        session,
        f"{BASE_URL}/api/openportal-remote-projects/",
        {"state": "active"},
    ))

    # Set of Waldur project UUIDs that are currently active in Bristol Portal
    # (i.e. RemoteProject.state=active, which means Bristol Portal has confirmed
    # the project and any earliest_approve embargo has passed).
    # Used in Case 2 to skip projects a user has joined in AIRRPortal but that
    # Bristol Portal has not yet approved — creating accounts before approval is
    # premature since those users cannot log in yet.
    # Note: has_isambard() checks whether a project has an Isambard-AI resource in
    # AIRRPortal, which is true from project creation. active_project_uuids is a
    # separate, stricter check: Bristol Portal approval status. Both are needed.
    # active_project_uuids comes for free from the same response that builds
    # remote_uuid_to_project_uuid, so no extra API call is required.
    active_project_uuids = {
        str(rp["current_project_uuid"])
        for rp in all_active_remote
        if rp.get("current_project_uuid")
    }

    # Lookup from RemoteProject UUID -> Waldur project UUID. Needed because the
    # audit log identifies projects by their RemoteProject UUID, but user-permissions
    # uses the underlying Waldur project UUID.
    remote_uuid_to_project_uuid = {
        str(rp["uuid"]): str(rp["current_project_uuid"])
        for rp in all_active_remote
        if rp.get("uuid") and rp.get("current_project_uuid")
    }

    # --- Step 1b: Find recently activated projects via the audit log ---
    # We use the audit log rather than RemoteProject.modified to identify projects
    # that recently became active. RemoteProject.modified is updated on any field
    # change (allocation extensions, end_date updates, etc.) and would give false
    # positives. The award_created audit event is written exactly once when a project
    # first transitions to ACTIVE — when Bristol Portal confirms the award — regardless
    # of whether an earliest_approve embargo was set.
    eprint(f"Fetching audit log for projects activated since {since.date()}...")
    audit_entries = list(paginate(
        session,
        f"{BASE_URL}/api/openportal-remote-project-audit/",
        {"event_type": "award_created", "timestamp_after": since.isoformat()},
    ))
    recently_activated_project_uuids = set()
    for entry in audit_entries:
        rp_uuid = str(entry.get("remote_project_uuid", ""))
        if rp_uuid in remote_uuid_to_project_uuid:
            recently_activated_project_uuids.add(remote_uuid_to_project_uuid[rp_uuid])
        else:
            # Project was activated within the window but is no longer in state=active
            # (e.g. deleted or errored since). Its users are not included in Case 1.
            eprint(f"  WARNING: audit entry for RemoteProject {rp_uuid} not found in "
                  f"active projects — skipping (project may have been deleted or errored)")
    eprint(f"Found {len(active_project_uuids)} active project(s), "
          f"{len(recently_activated_project_uuids)} activated since {since.date()}.")

    # --- Step 2: Fetch recent project memberships for Case 2 ---
    # user-permissions is the Waldur model tracking all role assignments across
    # all scope types (customer, project, call, etc.). scope_type=project narrows
    # this to project memberships only. The `created` filter is gte-only (no lte
    # on the API), so we drop anything timestamped after now client-side to guard
    # against clock skew or anomalous future-dated records.
    eprint(f"\nFetching project memberships since {since.date()} (UTC)...")
    recent_permissions = [
        p for p in paginate(
            session,
            f"{BASE_URL}/api/user-permissions/",
            {"scope_type": "project", "created": since.isoformat()},
        )
        if datetime.fromisoformat(p["created"]) <= now
    ]
    eprint(f"Found {len(recent_permissions)} recent project membership(s).")

    # --- Shared caches and helpers ---
    # marketplace-resources holds the compute/service allocations attached to a
    # project in AIRRPortal. We use it to confirm a project has an Isambard-AI
    # offering — not all projects in AIRRPortal are Isambard-AI projects.
    # Cached per project_uuid to avoid redundant API calls.
    resource_cache = {}

    # The user-permissions endpoint (PermissionSerializer) returns only a combined
    # full_name string, not separate first_name/last_name or email. We fetch those
    # from /api/users/<uuid>/ which uses the full User model. Cached per UUID.
    user_details_cache = {}
    seen_users = set()
    users = []

    def has_isambard(project_uuid):
        if project_uuid not in resource_cache:
            resources = list(paginate(
                session,
                f"{BASE_URL}/api/marketplace-resources/",
                {"project_uuid": project_uuid},
            ))
            resource_cache[project_uuid] = any(
                RESOURCE_FILTER in r.get("name", "") for r in resources
            )
        return resource_cache[project_uuid]

    def collect_user(user_uuid):
        """Fetch user details from AIRRPortal and add to the output list if not already seen."""
        user_uuid = str(user_uuid)
        if user_uuid in seen_users:
            return
        seen_users.add(user_uuid)
        if user_uuid not in user_details_cache:
            resp = session.get(f"{BASE_URL}/api/users/{user_uuid}/")
            if resp.status_code == 401:
                sys.exit("Error: invalid or expired AIRRPortal API token")
            resp.raise_for_status()
            user_details_cache[user_uuid] = resp.json()
        user = user_details_cache[user_uuid]
        users.append({
            "email": user.get("email", ""),
            "first_name": user.get("first_name", ""),
            "last_name": user.get("last_name", ""),
        })

    # Case 1: all members of projects that recently became active in Bristol Portal.
    # A user may have joined AIRRPortal weeks ago but their project was under an
    # earliest_approve embargo. Now that Bristol Portal has approved it, we need
    # to onboard everyone — not just those who joined recently.
    # scope_uuid filter on user-permissions returns all role assignments for one project.
    eprint(f"\nCase 1: fetching all members of projects activated since {since.date()}...")
    for project_uuid in recently_activated_project_uuids:
        if not has_isambard(project_uuid):
            continue
        all_members = list(paginate(
            session,
            f"{BASE_URL}/api/user-permissions/",
            {"scope_type": "project", "scope_uuid": project_uuid},
        ))
        for perm in all_members:
            user_uuid = perm.get("user_uuid")
            if user_uuid:
                collect_user(user_uuid)

    # Case 2: users who recently joined a project that is already active in Bristol Portal.
    # We check active_project_uuids to skip projects still pending approval —
    # setting up accounts before Bristol Portal approves the project serves no purpose.
    eprint(f"Case 2: checking recent memberships against active projects...")
    for perm in recent_permissions:
        user_uuid = perm.get("user_uuid")
        if not user_uuid:
            continue
        project_uuid = str(perm["scope_uuid"])
        if project_uuid not in active_project_uuids:
            continue  # project not yet approved by Bristol Portal
        if not has_isambard(project_uuid):
            continue
        collect_user(user_uuid)

    eprint(f"\nFound {len(users)} unique user(s) matching the filter.\n")

    if not users:
        return

    # DEV/TEST ONLY: check each user against Keycloak and split the output into
    # those already registered and those who are not. This will be removed from
    # the final version — the script's primary output is the user list itself.
    # Device flow is used because this is a CLI script with no redirect URI.
    kc_token = keycloak_device_auth("waldur-invite-check")

    kc_session = requests.Session()
    kc_session.headers["Authorization"] = f"Bearer {kc_token}"

    eprint("Checking users against Keycloak Isambard realm...")
    has_account = []
    no_account = []

    for user in users:
        email = user["email"]
        exists = keycloak_user_exists(kc_session, email)
        (has_account if exists else no_account).append(user)

    writer = csv.writer(sys.stdout, delimiter="\t")
    sort_key = lambda u: (u["email"].lower().rsplit("@", 1)[-1], u["email"].lower())

    for section_title, user_list in [
        ("=== Users WITH a Keycloak account ===", has_account),
        # DEV/TEST ONLY: institutional split on no_account will be removed in prod
        ("=== Users WITHOUT a Keycloak account ===", no_account),
    ]:
        regular = [u for u in user_list if not is_institutional(u["email"])]
        institutional = [u for u in user_list if is_institutional(u["email"])]

        eprint(f"\n{section_title}")

        if regular:
            for u in sorted(regular, key=sort_key):
                writer.writerow([u["email"], u["first_name"], u["last_name"]])
        elif not institutional:
            eprint("(none)")

        if institutional:
            # Blank row + short label written to stdout so they stay ordered with
            # data rows in the spreadsheet; easy to spot and delete on review.
            writer.writerow([])
            writer.writerow(["--- institutional users ---"])
            for u in sorted(institutional, key=sort_key):
                writer.writerow([u["email"], u["first_name"], u["last_name"]])


if __name__ == "__main__":
    main()
