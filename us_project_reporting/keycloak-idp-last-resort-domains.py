#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["requests"]
# ///
"""
Count users in a Keycloak realm whose identity provider is
"idp_last_resort", grouped by the domain portion of their username
(usernames are email addresses).

READ-ONLY: only GET calls against the Admin API. The only POST requests
are the OAuth2 device-authorization and token endpoints (authentication).

No per-user detail is printed or written -- only domain -> user count,
plus a final total.

Reuses the fed_identity_cache.jsonl produced by keycloak_signup_report_v2.py
(if present in --output-dir) to avoid re-querying federated-identity for
every user -- only users NOT in that cache get a fresh lookup.

Usage:
  uv run keycloak-idp-last-resort-domains.py \\
      --host https://keycloak.isambard.ac.uk \\
      --realm isambard \\
      --client-id security-admin-console \\
      --idp-alias idp_last_resort \\
      --output-dir ./report \\
      [--csv domains.csv]
"""

import argparse
import csv
import json
import sys
import time
from collections import Counter
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


def domain_of(username: str) -> str:
    if "@" not in username:
        return "(no domain)"
    return username.rsplit("@", 1)[1].lower()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", required=True)
    parser.add_argument("--realm", default="isambard")
    parser.add_argument("--client-id", required=True)
    parser.add_argument("--idp-alias", default="idp_last_resort",
                         help="Identity provider alias to filter users by (default: idp_last_resort)")
    parser.add_argument("--output-dir", default="./keycloak_report",
                         help="Directory containing (or to reuse) fed_identity_cache.jsonl from the main report")
    parser.add_argument("--csv", default=None, help="Optional path to write domain counts as CSV")
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

    print(f"Fetching all users in realm '{args.realm}'...")
    users = fetch_all_users(host, args.realm, token, session)
    print(f"Total users fetched: {len(users)}")

    domain_counts = Counter()
    matched_count = 0
    for user in users:
        user_id = user["id"]
        if user_id in cache:
            fed_ids = cache[user_id]
        else:
            fed_ids = fetch_federated_identities(host, args.realm, token, session, user_id)

        if any(fed.get("identityProvider") == args.idp_alias for fed in fed_ids):
            matched_count += 1
            domain_counts[domain_of(user.get("username", ""))] += 1

    print(f"\nUser count by domain for IdP '{args.idp_alias}' ({len(domain_counts)} domain(s)):\n")
    for domain, count in sorted(domain_counts.items(), key=lambda kv: (-kv[1], kv[0])):
        print(f"  {domain:<40} {count}")

    print(f"\nTotal users using this IdP: {matched_count}")

    if args.csv:
        with open(args.csv, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["domain", "count"])
            for domain, count in sorted(domain_counts.items(), key=lambda kv: (-kv[1], kv[0])):
                writer.writerow([domain, count])
            writer.writerow(["TOTAL", matched_count])
        print(f"Wrote {args.csv}")


if __name__ == "__main__":
    try:
        main()
    except requests.HTTPError as e:
        print(f"\nHTTP error: {e}\nResponse body: {e.response.text}", file=sys.stderr)
        sys.exit(1)
    except (TimeoutError, KeyboardInterrupt) as e:
        print(f"\n{e}", file=sys.stderr)
        sys.exit(1)
