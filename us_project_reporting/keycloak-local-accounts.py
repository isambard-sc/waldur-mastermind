#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["requests"]
# ///
"""
List details of Keycloak users that have NO federated identity link
("local" accounts, per the idp_local_per_month.csv bucket from the main
signup report script).

READ-ONLY: only GET calls against the Admin API. The only POST requests
are the OAuth2 device-authorization and token endpoints (authentication).

Reuses the fed_identity_cache.jsonl produced by keycloak_signup_report_v2.py
(if present in --output-dir) to avoid re-querying federated-identity for
every user -- only users NOT in that cache get a fresh lookup.

Usage:
  uv run keycloak_local_accounts.py \\
      --host https://keycloak.isambard.ac.uk \\
      --realm isambard \\
      --client-id security-admin-console \\
      --output-dir ./report \\
      [--month 2026-01]

If --month is omitted, prints/writes ALL local accounts regardless of
creation month. --output-dir should point at the same directory you used
for the main report, so it can reuse the cache; if there's no cache there
yet, it'll just fetch federated-identity for every user from scratch.
"""

import argparse
import csv
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

CACHE_FILENAME = "fed_identity_cache.jsonl"
MAX_RETRIES = 4
BASE_BACKOFF_SECONDS = 1.5


def device_authorize(host: str, realm: str, client_id: str) -> dict:
    url = f"{host}/realms/{realm}/protocol/openid-connect/auth/device"
    resp = requests.post(url, data={"client_id": client_id, "scope": "openid roles offline_access"})
    resp.raise_for_status()
    return resp.json()


def poll_for_token(host: str, realm: str, client_id: str, device_code: str,
                    interval: int, expires_in: int) -> dict:
    url = f"{host}/realms/{realm}/protocol/openid-connect/token"
    deadline = time.time() + expires_in
    while time.time() < deadline:
        resp = requests.post(url, data={
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "client_id": client_id,
            "device_code": device_code,
        })
        if resp.status_code == 200:
            return resp.json()
        try:
            err = resp.json().get("error")
        except ValueError:
            err = None
        if err == "authorization_pending":
            time.sleep(interval)
            continue
        if err == "slow_down":
            interval += 2
            time.sleep(interval)
            continue
        resp.raise_for_status()
    raise TimeoutError("Device code expired before authorization completed.")


def authenticate(host: str, realm: str, client_id: str) -> str:
    device = device_authorize(host, realm, client_id)
    verification_uri = device.get("verification_uri_complete") or device["verification_uri"]
    print("\n--- Keycloak device authorization ---")
    print(f"Open this URL and sign in (code: {device.get('user_code', 'n/a')}):")
    print(f"  {verification_uri}\n")
    print("Waiting for you to complete sign-in...")
    token_response = poll_for_token(
        host, realm, client_id,
        device["device_code"],
        device.get("interval", 5),
        device.get("expires_in", 600),
    )
    print("Authenticated.\n")
    return token_response["access_token"]


def get_with_retries(session: requests.Session, url: str, headers: dict,
                      params: dict | None = None) -> requests.Response:
    last_exc = None
    for attempt in range(MAX_RETRIES + 1):
        try:
            resp = session.get(url, headers=headers, params=params, timeout=30)
        except (requests.ConnectionError, requests.Timeout) as exc:
            last_exc = exc
            time.sleep(BASE_BACKOFF_SECONDS * (2 ** attempt))
            continue
        if resp.status_code in (200, 404):
            return resp
        if resp.status_code == 429 or resp.status_code >= 500:
            retry_after = resp.headers.get("Retry-After")
            wait = float(retry_after) if retry_after else BASE_BACKOFF_SECONDS * (2 ** attempt)
            time.sleep(wait)
            continue
        resp.raise_for_status()
    if last_exc:
        raise last_exc
    resp.raise_for_status()
    return resp


def fetch_all_users(host: str, realm: str, token: str, session: requests.Session,
                     page_size: int = 100) -> list[dict]:
    users = []
    first = 0
    url = f"{host}/admin/realms/{realm}/users"
    headers = {"Authorization": f"Bearer {token}"}
    while True:
        params = {"first": first, "max": page_size, "briefRepresentation": "true"}
        resp = get_with_retries(session, url, headers, params=params)
        page = resp.json()
        if not page:
            break
        users.extend(page)
        print(f"  fetched {len(users)} users so far...", end="\r")
        if len(page) < page_size:
            break
        first += page_size
    print()
    return users


def fetch_federated_identities(host: str, realm: str, token: str, session: requests.Session,
                                user_id: str) -> list[dict]:
    url = f"{host}/admin/realms/{realm}/users/{user_id}/federated-identity"
    headers = {"Authorization": f"Bearer {token}"}
    resp = get_with_retries(session, url, headers)
    if resp.status_code == 404:
        return []
    return resp.json()


def load_cache(cache_path: Path) -> dict[str, list[dict]]:
    cache: dict[str, list[dict]] = {}
    if not cache_path.exists():
        return cache
    with cache_path.open("r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            cache[entry["user_id"]] = entry["federated_identities"]
    return cache


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", required=True)
    parser.add_argument("--realm", required=True)
    parser.add_argument("--client-id", required=True)
    parser.add_argument("--output-dir", default="./keycloak_report",
                         help="Directory containing (or to reuse) fed_identity_cache.jsonl from the main report")
    parser.add_argument("--month", default=None, help="Filter to a single YYYY-MM creation month (default: all local accounts)")
    parser.add_argument("--csv", action="store_true", help="Also write results to local_accounts.csv in --output-dir")
    args = parser.parse_args()

    host = args.host.rstrip("/")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    cache_path = output_dir / CACHE_FILENAME
    cache = load_cache(cache_path)
    if cache:
        print(f"Reusing federated-identity cache with {len(cache)} entries from {cache_path}")

    token = authenticate(host, args.realm, args.client_id)
    session = requests.Session()

    print("Fetching all users...")
    users = fetch_all_users(host, args.realm, token, session)
    print(f"Total users fetched: {len(users)}")

    local_accounts = []
    for user in users:
        created_ts = user.get("createdTimestamp")
        if created_ts is None:
            continue
        month = datetime.fromtimestamp(created_ts / 1000, tz=timezone.utc).strftime("%Y-%m")
        if args.month and month != args.month:
            continue

        user_id = user["id"]
        if user_id in cache:
            fed_ids = cache[user_id]
        else:
            fed_ids = fetch_federated_identities(host, args.realm, token, session, user_id)

        if not fed_ids:  # no upstream IdP link => "local"
            local_accounts.append({
                "username": user.get("username", ""),
                "email": user.get("email", ""),
                "firstName": user.get("firstName", ""),
                "lastName": user.get("lastName", ""),
                "enabled": user.get("enabled"),
                "emailVerified": user.get("emailVerified"),
                "created": datetime.fromtimestamp(created_ts / 1000, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                "id": user_id,
            })

    print(f"\nFound {len(local_accounts)} local (non-federated) account(s)"
          + (f" created in {args.month}" if args.month else "") + ":\n")

    for acc in local_accounts:
        print(f"  username: {acc['username']}")
        print(f"    name:            {acc['firstName']} {acc['lastName']}".rstrip())
        print(f"    email:           {acc['email']} (verified: {acc['emailVerified']})")
        print(f"    enabled:         {acc['enabled']}")
        print(f"    created:         {acc['created']}")
        print(f"    user id:         {acc['id']}")
        print()

    if args.csv:
        csv_path = output_dir / "local_accounts.csv"
        with csv_path.open("w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["username", "email", "firstName", "lastName",
                                                     "enabled", "emailVerified", "created", "id"])
            writer.writeheader()
            writer.writerows(local_accounts)
        print(f"Wrote {csv_path}")


if __name__ == "__main__":
    try:
        main()
    except requests.HTTPError as e:
        print(f"\nHTTP error: {e}\nResponse body: {e.response.text}", file=sys.stderr)
        sys.exit(1)
    except (TimeoutError, KeyboardInterrupt) as e:
        print(f"\n{e}", file=sys.stderr)
        sys.exit(1)
