#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["requests"]
# ///
"""
Keycloak signup report generator.

READ-ONLY: every Keycloak Admin API call in this script is a GET. The only
POST requests are to the OAuth2 device-authorization and token endpoints
(authentication), which do not modify any Keycloak resource.

Authenticates via OAuth2 Device Authorization Grant (works for brokered /
passwordless accounts), then:

  1. Pages through GET /admin/realms/{realm}/users, bucketing
     createdTimestamp by month.
  2. For each user, calls GET /users/{id}/federated-identity (in a small
     bounded thread pool) to find which upstream IdP they're linked to.
  3. Writes:
       - all_users_per_month.csv    (month, total_count)
       - idp_<alias>_per_month.csv  (month, count) per upstream IdP
       - idp_local_per_month.csv    (month, count) for users with no
                                     federated identity link, if any

Built for realms with thousands of users:
  - federated-identity lookups run concurrently (small bounded pool)
  - transient errors (connection issues, 429, 5xx) are retried with backoff
  - results are checkpointed to a local cache file as they're fetched, so
    the script is safely resumable if it's interrupted or the token expires
  - if the access token can't be refreshed (e.g. the client doesn't issue
    refresh tokens), the script automatically re-runs the device-flow login
    instead of failing -- your browser session with the upstream IdP is
    normally still active, so this is usually a single click, not a full
    re-login. Nothing already fetched is re-requested thanks to the cache.

Usage:
  uv run keycloak_signup_report_v2.py \\
      --host https://keycloak.example.ac.uk \\
      --realm myrealm \\
      --client-id admin-cli \\
      --output-dir ./report \\
      --workers 8 \\
      [--date-from 2025-01-01] [--date-to 2026-08-01]

Requires the target client to have "OAuth 2.0 Device Authorization Grant"
enabled, and your user needs at least the view-users role in the realm.

Re-running with the same --output-dir resumes from the local cache file
(fed_identity_cache.jsonl) instead of re-fetching everything from scratch.
Delete that file if you want a completely fresh run.
"""

import argparse
import csv
import json
import re
import sys
import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

import requests

MAX_RETRIES = 4
BASE_BACKOFF_SECONDS = 1.5
CACHE_FILENAME = "fed_identity_cache.jsonl"


class TokenManager:
    """
    Thread-safe holder for the OAuth token.

    Prefers refreshing via refresh_token when available. If no refresh_token
    was issued (some clients don't support this for the device grant) or a
    refresh attempt fails, falls back to transparently re-running the device
    authorization flow -- this pauses all callers (they're blocked on the
    lock) until you approve the new login in your browser, then resumes.
    """

    def __init__(self, host: str, realm: str, client_id: str, token_response: dict):
        self.host = host
        self.realm = realm
        self.client_id = client_id
        self._lock = threading.Lock()
        self._set_tokens(token_response)

    def _set_tokens(self, token_response: dict) -> None:
        now = time.monotonic()
        self.access_token = token_response["access_token"]
        self.refresh_token = token_response.get("refresh_token")
        # renew a bit before actual expiry to leave headroom for in-flight requests
        expires_in = token_response.get("expires_in", 60)
        self._expires_at = now + max(expires_in - 15, 5)

    def _refresh_via_refresh_token(self) -> None:
        url = f"{self.host}/realms/{self.realm}/protocol/openid-connect/token"
        resp = requests.post(url, data={
            "grant_type": "refresh_token",
            "client_id": self.client_id,
            "refresh_token": self.refresh_token,
        })
        resp.raise_for_status()
        self._set_tokens(resp.json())

    def _reauthenticate_via_device_flow(self) -> None:
        print("\nAccess token expired and could not be refreshed -- "
              "re-authenticating via device login (your browser session "
              "with the IdP is likely still active, so this should be quick).")
        device = device_authorize(self.host, self.realm, self.client_id)
        verification_uri = device.get("verification_uri_complete") or device["verification_uri"]
        print(f"Open this URL and approve (code: {device.get('user_code', 'n/a')}):")
        print(f"  {verification_uri}\n")
        token_response = poll_for_token(
            self.host, self.realm, self.client_id,
            device["device_code"],
            device.get("interval", 5),
            device.get("expires_in", 600),
        )
        self._set_tokens(token_response)
        print("Re-authenticated, resuming...\n")

    def invalidate(self) -> None:
        """Force the next get_token() call to renew, regardless of expiry."""
        with self._lock:
            self._expires_at = 0

    def get_token(self) -> str:
        with self._lock:
            if time.monotonic() >= self._expires_at:
                if self.refresh_token:
                    try:
                        self._refresh_via_refresh_token()
                        return self.access_token
                    except requests.HTTPError:
                        pass  # refresh_token itself may be expired/invalid; fall through
                self._reauthenticate_via_device_flow()
            return self.access_token


def device_authorize(host: str, realm: str, client_id: str) -> dict:
    url = f"{host}/realms/{realm}/protocol/openid-connect/auth/device"
    # Explicitly request "roles" (in case it's an Optional rather than
    # Default client scope -- Optional scopes are only included when named
    # here) and "offline_access" (for a refresh_token, if the realm/client
    # permits it). Both are silently ignored if not configured/allowed.
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


def authenticate(host: str, realm: str, client_id: str) -> TokenManager:
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
    return TokenManager(host, realm, client_id, token_response)


def get_with_retries(session: requests.Session, url: str, token_mgr: TokenManager,
                      params: dict | None = None) -> requests.Response:
    """GET with bounded retries on transient failures. Read-only by construction."""
    last_exc = None
    for attempt in range(MAX_RETRIES + 1):
        try:
            headers = {"Authorization": f"Bearer {token_mgr.get_token()}"}
            resp = session.get(url, headers=headers, params=params, timeout=30)
        except (requests.ConnectionError, requests.Timeout) as exc:
            last_exc = exc
            time.sleep(BASE_BACKOFF_SECONDS * (2 ** attempt))
            continue

        if resp.status_code == 200 or resp.status_code == 404:
            return resp

        if resp.status_code == 401:
            # token might have just expired (or been rejected) between
            # get_token() and this request landing; force renewal (refresh
            # or re-auth, whichever TokenManager can manage) and retry
            token_mgr.invalidate()
            time.sleep(BASE_BACKOFF_SECONDS)
            continue

        if resp.status_code == 429 or resp.status_code >= 500:
            retry_after = resp.headers.get("Retry-After")
            wait = float(retry_after) if retry_after else BASE_BACKOFF_SECONDS * (2 ** attempt)
            time.sleep(wait)
            continue

        # any other status: not a transient condition, surface it
        resp.raise_for_status()

    if last_exc:
        raise last_exc
    resp.raise_for_status()
    return resp  # unreachable, keeps type-checkers happy


def fetch_all_users(host: str, realm: str, token_mgr: TokenManager, session: requests.Session,
                     page_size: int = 100) -> list[dict]:
    users = []
    first = 0
    url = f"{host}/admin/realms/{realm}/users"
    while True:
        params = {"first": first, "max": page_size, "briefRepresentation": "true"}
        resp = get_with_retries(session, url, token_mgr, params=params)
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


def fetch_federated_identities(host: str, realm: str, token_mgr: TokenManager,
                                session: requests.Session, user_id: str) -> list[dict]:
    url = f"{host}/admin/realms/{realm}/users/{user_id}/federated-identity"
    resp = get_with_retries(session, url, token_mgr)
    if resp.status_code == 404:
        return []
    return resp.json()


def load_cache(cache_path: Path) -> dict[str, list[dict]]:
    """Load previously-fetched federated-identity results, keyed by user id."""
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
                continue  # tolerate a partially-written last line from a prior crash
            cache[entry["user_id"]] = entry["federated_identities"]
    return cache


class CacheWriter:
    """Thread-safe append-only writer so progress survives a crash/interrupt."""

    def __init__(self, cache_path: Path):
        self._lock = threading.Lock()
        self._file = cache_path.open("a")

    def append(self, user_id: str, federated_identities: list[dict]) -> None:
        line = json.dumps({"user_id": user_id, "federated_identities": federated_identities})
        with self._lock:
            self._file.write(line + "\n")
            self._file.flush()

    def close(self) -> None:
        self._file.close()


def month_bucket(created_timestamp_ms: int) -> str:
    dt = datetime.fromtimestamp(created_timestamp_ms / 1000, tz=timezone.utc)
    return dt.strftime("%Y-%m")


def sanitize_filename(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_-]+", "_", name).strip("_") or "unknown"


def write_month_count_csv(path: Path, counts: dict[str, int]) -> None:
    with path.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["month", "count"])
        for month in sorted(counts):
            writer.writerow([month, counts[month]])


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", required=True, help="Keycloak base URL, e.g. https://keycloak.example.ac.uk")
    parser.add_argument("--realm", required=True, help="Realm name")
    parser.add_argument("--client-id", required=True, help="Client ID with device grant enabled (e.g. admin-cli)")
    parser.add_argument("--output-dir", default="./keycloak_report", help="Directory to write CSV reports to")
    parser.add_argument("--date-from", default=None, help="Only include users created on/after this date (YYYY-MM-DD)")
    parser.add_argument("--date-to", default=None, help="Only include users created before this date (YYYY-MM-DD)")
    parser.add_argument("--workers", type=int, default=8,
                         help="Concurrent workers for federated-identity lookups (default: 8)")
    args = parser.parse_args()

    host = args.host.rstrip("/")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    date_from = datetime.strptime(args.date_from, "%Y-%m-%d").replace(tzinfo=timezone.utc) if args.date_from else None
    date_to = datetime.strptime(args.date_to, "%Y-%m-%d").replace(tzinfo=timezone.utc) if args.date_to else None

    token_mgr = authenticate(host, args.realm, args.client_id)
    session = requests.Session()

    print("Fetching all users...")
    users = fetch_all_users(host, args.realm, token_mgr, session)
    print(f"Total users fetched: {len(users)}")

    # Pre-filter by date and build the month bucket up front (cheap, sequential)
    eligible_users = []
    total_per_month: dict[str, int] = defaultdict(int)
    skipped_no_timestamp = 0
    filtered_out = 0

    for user in users:
        created_ts = user.get("createdTimestamp")
        if created_ts is None:
            skipped_no_timestamp += 1
            continue
        created_dt = datetime.fromtimestamp(created_ts / 1000, tz=timezone.utc)
        if date_from and created_dt < date_from:
            filtered_out += 1
            continue
        if date_to and created_dt >= date_to:
            filtered_out += 1
            continue
        month = month_bucket(created_ts)
        total_per_month[month] += 1
        eligible_users.append((user["id"], month))

    idp_per_month: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    idp_lock = threading.Lock()

    cache_path = output_dir / CACHE_FILENAME
    cache = load_cache(cache_path)
    if cache:
        print(f"Found existing cache with {len(cache)} users already fetched "
              f"(from a prior run) -- these will be reused, not re-requested.")
    cache_writer = CacheWriter(cache_path)

    def apply_result(month: str, fed_ids: list[dict]) -> None:
        with idp_lock:
            if not fed_ids:
                idp_per_month["local"][month] += 1
            else:
                for fed in fed_ids:
                    alias = fed.get("identityProvider", "unknown")
                    idp_per_month[alias][month] += 1

    def process_user(user_id: str, month: str) -> None:
        if user_id in cache:
            apply_result(month, cache[user_id])
            return
        fed_ids = fetch_federated_identities(host, args.realm, token_mgr, session, user_id)
        cache_writer.append(user_id, fed_ids)
        apply_result(month, fed_ids)

    already_cached = sum(1 for uid, _ in eligible_users if uid in cache)
    to_fetch = len(eligible_users) - already_cached
    print(f"Fetching federated identity for {to_fetch} users not yet cached "
          f"({already_cached} reused from cache) using {args.workers} concurrent workers...")
    completed = 0
    errors = []
    try:
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = {
                executor.submit(process_user, user_id, month): user_id
                for user_id, month in eligible_users
            }
            for future in as_completed(futures):
                completed += 1
                try:
                    future.result()
                except Exception as exc:
                    errors.append((futures[future], str(exc)))
                if completed % 50 == 0 or completed == len(eligible_users):
                    print(f"  processed {completed}/{len(eligible_users)} users...", end="\r")
    finally:
        cache_writer.close()
    print()

    if skipped_no_timestamp:
        print(f"Note: {skipped_no_timestamp} users had no createdTimestamp and were skipped.")
    if filtered_out:
        print(f"Note: {filtered_out} users fell outside the --date-from/--date-to window.")
    if errors:
        print(f"\nWarning: {len(errors)} users failed federated-identity lookup after retries:")
        for user_id, msg in errors[:20]:
            print(f"  {user_id}: {msg}")
        if len(errors) > 20:
            print(f"  ...and {len(errors) - 20} more.")
        print("These users are still counted in all_users_per_month.csv but are NOT")
        print("reflected in any idp_*_per_month.csv file.")
        print(f"Just re-run the same command (same --output-dir) to retry only these -- "
              f"everyone else is cached in {cache_path.name} and won't be re-fetched.")

    all_users_path = output_dir / "all_users_per_month.csv"
    write_month_count_csv(all_users_path, total_per_month)
    print(f"\nWrote {all_users_path}")

    for idp_alias, counts in idp_per_month.items():
        safe_name = sanitize_filename(idp_alias)
        idp_path = output_dir / f"idp_{safe_name}_per_month.csv"
        write_month_count_csv(idp_path, counts)
        print(f"Wrote {idp_path}")

    print("\nDone.")


if __name__ == "__main__":
    try:
        main()
    except requests.HTTPError as e:
        print(f"\nHTTP error: {e}\nResponse body: {e.response.text}", file=sys.stderr)
        sys.exit(1)
    except (TimeoutError, KeyboardInterrupt, RuntimeError) as e:
        print(f"\n{e}", file=sys.stderr)
        sys.exit(1)
