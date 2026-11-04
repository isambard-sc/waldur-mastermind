#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = ["requests", "openpyxl"]
# ///
"""
Estimate how many companies use the Waldur instance, and how many node hours
on one offering (default: Isambard-AI Phase 2) each has used.

Groups users by email domain, drops domains that are not companies (consumer
mail, universities, government, ...) using domain_overrides.csv, suffix rules
and the eduGAIN federation metadata, then adds per-user node-hour usage per
company, organisation, project and month. Writes an .xlsx workbook; emails are
only included with --include-emails.

Usage:
    python company_domain_report.py [--token TOKEN] [--base-url URL] [--output FILE]
                                     [--include-emails] [--overrides FILE] [--previous FILE]
                                     [--no-previous] [--no-edugain] [--refresh-edugain]
                                     [--no-usage] [--offering-name NAME | --offering-uuid UUID]

The Waldur API token (staff) can also be provided via the WALDUR_TOKEN
environment variable, or entered interactively when prompted.

Example (monthly run; writes company_domains_<today>.xlsx and compares it with
the most recent earlier dated report in the same folder):
    WALDUR_TOKEN=abc123 uv run company_domain_report.py

How domains are classified, what each sheet and column means, where the data
comes from and the monthly review workflow are documented in
README_company_domain_report.md.
"""

import argparse
import csv
import getpass
import json
import os
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

import requests
from openpyxl import Workbook, load_workbook
from openpyxl.utils import get_column_letter
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

eprint = lambda *a, **k: print(*a, **{**k, "file": sys.stderr})

DEFAULT_BASE_URL = "https://portal-api.isambard.ac.uk"

# --- Domains that don't tell you anything about "which company" ---

# Suffix rules. A domain matches if it equals one of these or is a subdomain
# of one. Second-level labels like "ac"/"gov" are handled separately below
# so that .ac.jp, .gov.au etc. are covered without listing every country.
_SUFFIX_CATEGORIES = {
    "edu": "academic",
    "gov": "government",
    "mil": "government",
    "int": "government",
    "gov.uk": "government",
    "gov.scot": "government",
    "gov.wales": "government",
    "police.uk": "government",
    "parliament.uk": "government",
    "mod.uk": "government",
    "ukri.org": "government",
    "nhs.uk": "health",
    "nhs.net": "health",
    "nhs.scot": "health",
}
_SECOND_LEVEL_CATEGORIES = {
    "ac": "academic",
    "edu": "academic",
    "gov": "government",
    "gouv": "government",
    "govt": "government",
    "mil": "government",
}

# Free/generic consumer mail providers. Not exhaustive — if the domain list
# this script prints out contains other obvious generic providers, add them
# here and re-run rather than hand-editing the output.
_GENERIC_PROVIDERS = {
    "gmail.com",
    "googlemail.com",
    "outlook.com",
    "hotmail.com",
    "hotmail.co.uk",
    "live.com",
    "live.co.uk",
    "yahoo.com",
    "yahoo.co.uk",
    "icloud.com",
    "me.com",
    "aol.com",
    "protonmail.com",
    "proton.me",
    "msn.com",
    "mail.com",
    "gmx.com",
    "gmx.de",
    "gmx.net",
    "web.de",
    "ymail.com",
    "btinternet.com",
    "btopenworld.com",
    "sky.com",
    "virginmedia.com",
    "talktalk.net",
    "fastmail.com",
    "tutanota.com",
    "zoho.com",
    "yandex.com",
    "yandex.ru",
    "mail.ru",
    "qq.com",
    "163.com",
    "126.com",
}

OVERRIDES_PATH = Path(__file__).with_name("domain_overrides.csv")
REPORT_PREFIX = "company_domains_"  # default report name: company_domains_YYYY-MM-DD.xlsx
OVERRIDE_CATEGORIES = {
    "company",
    "academic",
    "research",
    "government",
    "health",
    "nonprofit",
    "generic",
}

EDUGAIN_METADATA_URL = "https://mds.edugain.org/edugain-v2.xml"
EDUGAIN_CACHE_PATH = Path(__file__).with_name("edugain_scopes.json")
EDUGAIN_MAX_AGE = timedelta(days=30)

DEFAULT_OFFERING_NAME = "Isambard-AI Phase 2"
SOVEREIGN_AI_ORGANISATION = "Sovereign AI"  # organisation (Waldur customer) name
# Organisations/projects listed in a sheet cell, most-used first; the rest is
# summarised as "(+N more)" (project_count has the full number, and the Projects
# sheet lists every company project).
LIST_LIMIT = 10
USAGE_COMPONENT_TYPE = "node"  # node hours

REQUEST_TIMEOUT = 120  # seconds per API request

# Only ask the API for the fields we use. Most serialized fields on these
# endpoints cost extra database queries per row (on /api/users/: the user's
# roles, pending email change, ...; on usages: component usage -> resource ->
# project -> customer, offering, component, ... with no select_related).
USER_FIELDS = ["uuid", "email"]
RESOURCE_FIELDS = ["project_uuid", "project_name", "customer_name", "created"]
PROJECT_FIELDS = ["uuid", "created", "start_date", "end_date"]
# Sector order on the Sector totals sheet (company first, then excluded categories).
SECTORS = ["company", "academic", "research", "government", "health", "nonprofit", "generic"]
# user_uuid rather than user_email: offering users only include user_email when
# the offering's user attribute config exposes "email" (even to staff), while
# user_uuid is always present and maps to the email via /api/users/.
OFFERING_USER_FIELDS = ["uuid", "username", "user_uuid"]
USAGE_FIELDS = [
    "uuid",
    "user",
    "username",
    "usage",
    "billing_period",
    "project_uuid",
    "project_name",
    "customer_name",
]


def domain_of(email: str) -> str | None:
    if not email or "@" not in email:
        return None
    return email.strip().lower().rsplit("@", 1)[1]


def parent_domains(domain: str):
    """Yield domain and each parent with at least two labels, most specific first.

    a.b.example.com -> a.b.example.com, b.example.com, example.com
    """
    labels = domain.split(".")
    for i in range(len(labels) - 1):
        yield ".".join(labels[i:])


def suffix_category(domain: str) -> tuple[str, str] | None:
    labels = domain.split(".")
    for i in range(1, len(labels)):
        suffix = ".".join(labels[i:])
        if suffix in _SUFFIX_CATEGORIES:
            return _SUFFIX_CATEGORIES[suffix], f"suffix .{suffix}"
    if domain in _SUFFIX_CATEGORIES:  # e.g. ukri.org itself
        return _SUFFIX_CATEGORIES[domain], f"domain {domain}"
    # .ac.uk, .ac.jp, .edu.cn, .gov.au, .gouv.fr, ... (second-to-last label)
    if len(labels) >= 3 and labels[-2] in _SECOND_LEVEL_CATEGORIES:
        return _SECOND_LEVEL_CATEGORIES[labels[-2]], f"suffix .{labels[-2]}.{labels[-1]}"
    return None


def load_overrides(path: Path) -> dict[str, dict]:
    """Read domain_overrides.csv: domain,category,same_as,note ('#' lines are comments)."""
    if not path.exists():
        eprint(f"Warning: no overrides file at {path} — continuing without it.")
        return {}
    with path.open(newline="") as f:
        lines = [line for line in f if line.strip() and not line.lstrip().startswith("#")]
    overrides = {}
    for row in csv.DictReader(lines):
        domain = (row.get("domain") or "").strip().lower()
        category = (row.get("category") or "").strip().lower()
        if not domain:
            continue
        if category not in OVERRIDE_CATEGORIES:
            sys.exit(
                f"Error: {path}: domain {domain!r} has unknown category {category!r} "
                f"(expected one of: {', '.join(sorted(OVERRIDE_CATEGORIES))})"
            )
        overrides[domain] = {
            "category": category,
            "same_as": (row.get("same_as") or "").strip().lower(),
            "note": (row.get("note") or "").strip(),
        }
    eprint(f"Loaded {len(overrides)} override(s) from {path}.")
    return overrides


def find_previous_report(output: Path) -> Path | None:
    """The most recent dated report next to output, other than output itself."""
    dated = []
    for path in output.parent.glob(f"{REPORT_PREFIX}????-??-??.xlsx"):
        try:
            report_date = date.fromisoformat(path.stem.removeprefix(REPORT_PREFIX))
        except ValueError:
            continue
        if path.resolve() != output.resolve():
            dated.append((report_date, path))
    return max(dated)[1] if dated else None


def load_previous_report(path: Path) -> dict[str, str]:
    """{domain: category} from an earlier report: Company domains -> "company", Excluded -> its category."""
    if not path.exists():
        sys.exit(f"Error: previous report {path} not found")
    wb = load_workbook(path, read_only=True)
    categories = {}
    for sheet_name, fixed_category in (("Company domains", "company"), ("Excluded", None)):
        if sheet_name not in wb.sheetnames:
            continue
        rows = wb[sheet_name].iter_rows(values_only=True)
        header = list(next(rows, ()))
        domain_col = header.index("domain")
        category_col = header.index("category") if fixed_category is None else None
        for row in rows:
            if row[domain_col]:
                categories[row[domain_col]] = fixed_category or row[category_col]
    wb.close()
    eprint(f"Loaded {len(categories)} domain(s) from previous report {path}.")
    return categories


def fetch_edugain_scopes() -> list[str]:
    """Stream the eduGAIN metadata aggregate and collect every IdP's scopes."""
    md = "{urn:oasis:names:tc:SAML:2.0:metadata}"
    shibmd = "{urn:mace:shibboleth:metadata:1.0}"
    eprint(f"Downloading eduGAIN metadata from {EDUGAIN_METADATA_URL} (~100 MB) ...")
    resp = requests.get(EDUGAIN_METADATA_URL, stream=True, timeout=60)
    resp.raise_for_status()
    resp.raw.decode_content = True
    scopes = set()
    for _, el in ET.iterparse(resp.raw, events=("end",)):
        if el.tag == md + "IDPSSODescriptor":
            for scope in el.iter(shibmd + "Scope"):
                # regexp scopes are rare (a handful) and can't be suffix-matched.
                if scope.get("regexp", "false").lower() != "true" and scope.text:
                    scopes.add(scope.text.strip().lower())
        elif el.tag == md + "EntityDescriptor":
            el.clear()  # keep memory flat while streaming
    return sorted(scopes)


def load_edugain_scopes(cache_path: Path, refresh: bool) -> set[str]:
    cached = None
    if cache_path.exists():
        cached = json.loads(cache_path.read_text())
        age = datetime.now(timezone.utc) - datetime.fromisoformat(cached["fetched"])
        if not refresh and age < EDUGAIN_MAX_AGE:
            eprint(
                f"Using cached eduGAIN scopes from {cache_path} "
                f"({len(cached['scopes'])} scopes, fetched {cached['fetched'][:10]})."
            )
            return set(cached["scopes"])
    try:
        scopes = fetch_edugain_scopes()
    except (requests.RequestException, ET.ParseError) as e:
        if cached:
            eprint(f"Warning: eduGAIN refresh failed ({e}); using stale cache from {cached['fetched'][:10]}.")
            return set(cached["scopes"])
        sys.exit(f"Error: could not download eduGAIN metadata ({e}). Re-run with --no-edugain to skip it.")
    cache_path.write_text(
        json.dumps(
            {
                "source": EDUGAIN_METADATA_URL,
                "fetched": datetime.now(timezone.utc).isoformat(),
                "scopes": scopes,
            },
            indent=0,
        )
    )
    eprint(f"Extracted {len(scopes)} eduGAIN scopes; cached to {cache_path}.")
    return set(scopes)


def edugain_scope_for(domain: str, scopes: set[str]) -> str | None:
    for candidate in parent_domains(domain):
        # Guard against an over-broad scope such as "ac.uk" swallowing a whole TLD.
        first, *rest = candidate.split(".")
        if len(rest) == 1 and first in {"ac", "edu", "gov", "co", "com", "org", "net"}:
            continue
        if candidate in scopes:
            return candidate
    return None


def classify(domain: str, overrides: dict, edugain_scopes: set[str]) -> dict:
    """Return {category, matched_by, same_as, note}; category "company" means kept."""
    for candidate in parent_domains(domain):
        if candidate in overrides:
            o = overrides[candidate]
            return {
                "category": o["category"],
                "matched_by": f"override {candidate}",
                "same_as": o["same_as"] if candidate == domain else "",
                "override_same_as": o["same_as"],
                "note": o["note"],
            }
    if domain in _GENERIC_PROVIDERS:
        return {"category": "generic", "matched_by": "generic provider list"}
    hit = suffix_category(domain)
    if hit:
        return {"category": hit[0], "matched_by": hit[1]}
    scope = edugain_scope_for(domain, edugain_scopes)
    if scope:
        return {"category": "academic", "matched_by": f"eduGAIN scope {scope}"}
    return {"category": "company", "matched_by": ""}


def registrable_domain(domain: str) -> str:
    """eng.ox.ac.uk -> ox.ac.uk, andrew.cmu.edu -> cmu.edu, metoffice.gov.uk stays."""
    labels = domain.split(".")
    if len(labels) >= 3 and labels[-2] in {*_SECOND_LEVEL_CATEGORIES, "co", "org", "net", "nhs"}:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def institution_of(domain: str, c: dict) -> str:
    """Key grouping an excluded domain's rows by institution (for pivoting).

    The override's same_as if set (for aliases like gla.ac.uk -> glasgow.ac.uk),
    else the override or eduGAIN scope that matched (mail.mcgill.ca -> mcgill.ca),
    else the registrable domain (eng.ox.ac.uk -> ox.ac.uk). Generic providers
    stay as they are.
    """
    if c.get("override_same_as"):
        return c["override_same_as"]
    matched_by = c.get("matched_by", "")
    if matched_by.startswith(("override ", "eduGAIN scope ")):
        return matched_by.split()[-1]
    if c.get("category") == "generic":
        return domain
    return registrable_domain(domain)


def paginate(session, url, params=None):
    """Yield all items from a paginated Waldur API endpoint."""
    params = {**(params or {}), "page_size": 300, "page": 1}
    while True:
        resp = session.get(url, params=params, timeout=REQUEST_TIMEOUT)
        if resp.status_code == 401:
            sys.exit("Error: invalid or expired API token")
        resp.raise_for_status()
        data = resp.json()
        yield from data
        if 'rel="next"' not in resp.headers.get("Link", ""):
            break
        params["page"] += 1


def make_session(token: str) -> requests.Session:
    """API session with the token, retrying transient gateway errors on GETs."""
    session = requests.Session()
    session.headers["Authorization"] = f"Token {token}"
    # Retry transient gateway errors with backoff rather than failing a run
    # (and re-fetching everything) part-way through. Read-only GETs only.
    retry = Retry(total=3, backoff_factor=5, status_forcelist=[502, 503, 504], allowed_methods=["GET"])
    session.mount("https://", HTTPAdapter(max_retries=retry))
    session.mount("http://", HTTPAdapter(max_retries=retry))
    return session


def uuid_from_url(url: str | None) -> str | None:
    """.../marketplace-offering-users/<uuid>/ -> <uuid>"""
    if not url:
        return None
    return url.rstrip("/").rsplit("/", 1)[-1]


def resolve_offering_uuid(session, base_url: str, name: str) -> str:
    resp = session.get(
        f"{base_url}/api/marketplace-provider-offerings/",
        # Only uuid/name: the full offering serializer is heavy (plans,
        # components, endpoints, ...).
        params={"name_exact": name, "page_size": 10, "field": ["uuid", "name"]},
        timeout=REQUEST_TIMEOUT,
    )
    if resp.status_code == 401:
        sys.exit("Error: invalid or expired API token")
    resp.raise_for_status()
    offerings = resp.json()
    if len(offerings) != 1:
        found = ", ".join(f"{o['name']} ({o['uuid']})" for o in offerings) or "none"
        sys.exit(
            f"Error: expected exactly one offering named {name!r}, found: {found}. "
            f"Pass --offering-uuid instead."
        )
    return offerings[0]["uuid"]


def fetch_offering_usage(session, base_url: str, offering_uuid: str, email_by_user_uuid: dict[str, str]):
    """Fetch an offering's users and their non-zero per-user node usage.

    Returns (emails of all offering users, usage rows, unit). Each usage row
    gets an "email" key: the Waldur email of its user, resolved through the
    offering-user link (falling back to the cluster username), or None.
    """
    eprint("Fetching offering users ...")
    email_by_offering_user = {}
    email_by_username = {}
    for ou in paginate(
        session,
        f"{base_url}/api/marketplace-offering-users/",
        # Default order is by username, which is often null — not a stable
        # order to page through. created is effectively unique.
        {"offering_uuid": offering_uuid, "field": OFFERING_USER_FIELDS, "o": "created"},
    ):
        email = email_by_user_uuid.get(str(ou.get("user_uuid") or "").replace("-", ""), "")
        email_by_offering_user[ou["uuid"]] = email
        if ou.get("username"):
            email_by_username[ou["username"]] = email
    eprint(f"Fetched {len(email_by_offering_user)} offering user(s).")
    if email_by_offering_user and not any(email_by_offering_user.values()):
        eprint("Warning: no offering user could be matched to a Waldur user's email.")

    usage_url = f"{base_url}/api/marketplace-component-user-usages/"
    usage_filter = {"offering_uuid": offering_uuid, "type": USAGE_COMPONENT_TYPE}
    # The unit is a property of the component, so one row is enough to read it;
    # the same response's X-Result-Count is used below to check completeness.
    resp = session.get(
        usage_url, params={**usage_filter, "field": "measured_unit", "page_size": 1}, timeout=REQUEST_TIMEOUT
    )
    resp.raise_for_status()
    sample = resp.json()
    unit = (sample[0].get("measured_unit") if sample else None) or "hours"
    expected = int(resp.headers.get("X-Result-Count", -1))

    eprint(f"Fetching per-user '{USAGE_COMPONENT_TYPE}' usage (this can take a minute) ...")
    # The default order (by component usage date) has many ties and the
    # current month's dates change as usage is reported, so rows could shift
    # between pages mid-run. Billing period + username doesn't change and puts
    # newly added rows at the end; uuid de-duplication covers the rare ties.
    seen = set()
    rows = []
    for r in paginate(
        session, usage_url, {**usage_filter, "field": USAGE_FIELDS, "o": "component_usage__billing_period,username"}
    ):
        if r["uuid"] in seen:
            continue
        seen.add(r["uuid"])
        r["usage"] = Decimal(str(r.get("usage") or 0))
        if r["usage"] == 0:
            continue  # zero rows would otherwise count a user as active that month
        r["email"] = email_by_offering_user.get(uuid_from_url(r.get("user"))) or email_by_username.get(
            r.get("username")
        )
        rows.append(r)
    eprint(f"Fetched {len(seen)} usage row(s), {len(rows)} non-zero.")
    if expected >= 0 and len(seen) < expected:
        eprint(
            f"Warning: expected {expected} usage rows but received {len(seen)} — rows may have "
            f"shifted between pages while fetching. Re-run if the totals matter."
        )
    return {e for e in email_by_offering_user.values() if e}, rows, unit


def fetch_project_dates(session, base_url: str) -> dict[str, dict]:
    """project_uuid -> {created, start_date, end_date}, including ended (soft-deleted) projects."""
    eprint("Fetching project dates ...")
    dates = {}
    for p in paginate(
        session,
        f"{base_url}/api/projects/",
        # include_terminated: projects are soft-deleted once their end date
        # (plus grace period) has passed and nothing is left running.
        {"include_terminated": "true", "field": PROJECT_FIELDS},
    ):
        dates[p["uuid"]] = {
            k: date.fromisoformat(p[k]) if p.get(k) else None for k in ("start_date", "end_date")
        }
        # created is a timestamp; the date is enough for the report.
        dates[p["uuid"]]["created"] = datetime.fromisoformat(p["created"]).date() if p.get("created") else None
    eprint(f"Fetched dates for {len(dates)} project(s).")
    return dates


def fetch_offering_projects(session, base_url: str, offering_uuid: str) -> dict[str, dict]:
    """Projects with a resource on the offering: project_uuid -> {project, organisation}."""
    eprint("Fetching the offering's resources ...")
    projects = {}
    for r in paginate(
        session,
        f"{base_url}/api/marketplace-resources/",
        {"offering_uuid": offering_uuid, "field": RESOURCE_FIELDS, "o": "created"},
    ):
        if r.get("project_uuid"):
            created = datetime.fromisoformat(r["created"]) if r.get("created") else None
            known = projects.get(r["project_uuid"])
            if known and known["first_created"] and (created is None or known["first_created"] <= created):
                created = known["first_created"]
            projects[r["project_uuid"]] = {
                "project": r.get("project_name") or "",
                "organisation": r.get("customer_name") or "",
                "first_created": created,
            }
    eprint(f"Found {len(projects)} project(s) with a resource on the offering.")
    return projects


def fetch_project_members(session, base_url: str) -> list[dict]:
    """Project memberships, current and revoked: [{user_uuid, project_uuid, is_active, ended}].

    show_inactive=true (staff only) adds revoked roles; ended is the role's
    expiration_time, which revoking also sets. A server without show_inactive
    just returns the current roles. The serializer doesn't support field
    restriction, so this is the heavier of the membership requests — one pass
    over all project roles.
    """
    eprint("Fetching project memberships (current and revoked) ...")
    members = []
    for p in paginate(
        session,
        f"{base_url}/api/user-permissions/",
        {"scope_type": "project", "show_inactive": "true", "o": "created"},
    ):
        if p.get("user_uuid") and p.get("scope_uuid"):
            members.append({
                "user_uuid": str(p["user_uuid"]).replace("-", ""),
                "project_uuid": str(p["scope_uuid"]).replace("-", ""),
                "is_active": p.get("is_active", True) is not False,
                "ended": datetime.fromisoformat(p["expiration_time"]) if p.get("expiration_time") else None,
            })
    active = sum(1 for m in members if m["is_active"])
    eprint(f"Fetched {len(members)} project membership(s): {active} current, {len(members) - active} revoked.")
    return members


def months_with_usage(hours_by_month: dict) -> list[str]:
    return sorted(m for m, h in hours_by_month.items() if h > 0)


def main():
    parser = argparse.ArgumentParser(
        description="Estimate the number of distinct companies that have used the system, "
        "grouping all known users (active and expired) by email domain."
    )
    parser.add_argument("--token", help="Waldur API token (or set WALDUR_TOKEN env variable)")
    parser.add_argument(
        "--base-url",
        default=os.environ.get("WALDUR_BASE_URL", DEFAULT_BASE_URL),
        help=f"Waldur API base URL (default: {DEFAULT_BASE_URL}, or WALDUR_BASE_URL env var)",
    )
    parser.add_argument(
        "--output",
        help=f"Path to write the .xlsx report to (default: {REPORT_PREFIX}YYYY-MM-DD.xlsx, today's date)",
    )
    parser.add_argument(
        "--include-emails",
        action="store_true",
        help="Include the individual email addresses in the report "
        "(omitted by default, only domains and user counts are written)",
    )
    parser.add_argument(
        "--overrides",
        type=Path,
        default=OVERRIDES_PATH,
        help=f"CSV of manual domain decisions (default: {OVERRIDES_PATH.name} next to this script)",
    )
    parser.add_argument(
        "--previous",
        type=Path,
        help="Earlier report to compare with for the 'new' column "
        f"(default: the most recent earlier {REPORT_PREFIX}YYYY-MM-DD.xlsx next to the output)",
    )
    parser.add_argument(
        "--no-previous",
        action="store_true",
        help="Don't compare with a previous report (no 'new' column)",
    )
    parser.add_argument(
        "--no-edugain",
        action="store_true",
        help="Don't use eduGAIN identity-provider scopes to detect universities/research institutes",
    )
    parser.add_argument(
        "--refresh-edugain",
        action="store_true",
        help=f"Re-download the eduGAIN metadata even if {EDUGAIN_CACHE_PATH.name} is recent",
    )
    parser.add_argument(
        "--no-usage",
        action="store_true",
        help="Skip node-hour usage (fewer API requests; domain list only)",
    )
    offering = parser.add_mutually_exclusive_group()
    offering.add_argument(
        "--offering-name",
        default=DEFAULT_OFFERING_NAME,
        help=f"Exact name of the offering to report usage for (default: {DEFAULT_OFFERING_NAME!r})",
    )
    offering.add_argument("--offering-uuid", help="Offering UUID (skips the name lookup)")
    args = parser.parse_args()

    overrides = load_overrides(args.overrides)
    args.output = Path(args.output or f"{REPORT_PREFIX}{date.today().isoformat()}.xlsx")
    if args.no_previous:
        args.previous = None
    elif args.previous is None:
        args.previous = find_previous_report(args.output)
        if args.previous:
            eprint(f"Comparing with previous report {args.previous} (override with --previous / --no-previous).")
    previous = load_previous_report(args.previous) if args.previous else None
    edugain_scopes = set() if args.no_edugain else load_edugain_scopes(EDUGAIN_CACHE_PATH, args.refresh_edugain)

    token = args.token or os.environ.get("WALDUR_TOKEN")
    if not token:
        token = getpass.getpass("Enter your Waldur API token: ").strip()
    if not token:
        sys.exit("Error: Waldur API token is required")

    session = make_session(token)
    base_url = args.base_url.rstrip("/")

    # --- Step 1: pull every user the system knows about ---
    # /api/users/ is backed by User.all_objects for staff/support callers (see
    # UserViewSet.get_queryset in waldur_core/structure/views.py), so it is
    # unfiltered by is_active by default and needs no separate "expired users"
    # query: a user whose project/customer role has been revoked or expired
    # still has a User row and still shows up here.
    eprint(f"Fetching all users from {base_url}/api/users/ ...")
    all_users = list(paginate(session, f"{base_url}/api/users/", {"field": USER_FIELDS}))
    eprint(f"Fetched {len(all_users)} user(s).")

    domain_users = defaultdict(list)
    email_by_user_uuid = {u["uuid"]: u.get("email") or "" for u in all_users if u.get("uuid")}
    no_email = 0
    for u in all_users:
        email = u.get("email") or ""
        domain = domain_of(email)
        if domain is None:
            no_email += 1
            continue
        domain_users[domain].append(email)

    if no_email:
        eprint(f"  ({no_email} user(s) had no usable email address — skipped.)")

    # --- Step 2: classify every domain; merge same_as aliases into one company ---
    companies = defaultdict(lambda: {"emails": [], "merged": [], "notes": []})
    excluded_rows = []
    classification = {}
    for domain, emails in domain_users.items():
        c = classification[domain] = classify(domain, overrides, edugain_scopes)
        if c["category"] == "company":
            company = companies[c.get("same_as") or domain]
            company["emails"].extend(emails)
            if c.get("same_as"):
                company["merged"].append(domain)
            if c.get("note"):
                company["notes"].append(c["note"])
        else:
            excluded_rows.append((domain, emails, c))

    by_category = defaultdict(int)
    by_layer = defaultdict(int)
    for _, _, c in excluded_rows:
        by_category[c["category"]] += 1
        by_layer[c["matched_by"].split()[0]] += 1

    eprint(f"\nTotal distinct email domains seen: {len(domain_users)}")
    eprint(f"  excluded: {len(excluded_rows)}")
    for category, n in sorted(by_category.items(), key=lambda kv: -kv[1]):
        eprint(f"    {category}: {n}")
    eprint("  excluded, by what matched:")
    for layer, n in sorted(by_layer.items(), key=lambda kv: -kv[1]):
        eprint(f"    {layer}: {n}")
    if args.no_edugain:
        eprint("    (eduGAIN layer disabled with --no-edugain)")
    merged = sum(len(c["merged"]) for c in companies.values())
    eprint(f"  => candidate companies: {len(companies)}" + (f" ({merged} alias domain(s) merged)" if merged else ""))

    generic_user_total = sum(len(e) for _, e, c in excluded_rows if c["category"] == "generic")
    if generic_user_total:
        eprint(
            f"\nNote: {generic_user_total} user(s) are on generic providers "
            f"(e.g. a company contact who used personal Gmail) and are excluded "
            f"from the domain-distinct count — see the 'Excluded' sheet in the "
            f"output file if you want to hand-attribute any of them to a company."
        )

    # --- Step 3: node-hour usage per company on one offering ---
    usage_enabled = not args.no_usage
    access = defaultdict(set)  # company -> emails with an account on the offering
    hours = defaultdict(lambda: defaultdict(Decimal))  # company -> month -> hours
    month_users = defaultdict(lambda: defaultdict(set))  # company -> month -> emails
    # (company, project_uuid) -> project/organisation names, month -> hours,
    # emails with usage, emails of current and former members
    def new_project():
        return {
            "uuid": None, "organisation": "", "project": "", "hours": defaultdict(Decimal),
            "users": set(), "members": set(), "former_members": set(),
        }

    company_projects = defaultdict(new_project)
    # Same, for excluded domains: (domain, project_uuid) -> ...
    excluded_access = defaultdict(set)
    excluded_projects = defaultdict(new_project)
    unmatched = []
    non_company_hours = Decimal(0)
    current_month = date.today().strftime("%Y-%m")
    if usage_enabled:
        offering_uuid = args.offering_uuid or resolve_offering_uuid(session, base_url, args.offering_name)
        offering_label = args.offering_uuid or args.offering_name
        eprint(f"\nUsage offering: {offering_label} ({offering_uuid})")
        access_emails, usage_rows, unit = fetch_offering_usage(session, base_url, offering_uuid, email_by_user_uuid)
        offering_projects = fetch_offering_projects(session, base_url, offering_uuid)
        project_dates = fetch_project_dates(session, base_url)
        memberships = fetch_project_members(session, base_url)

        def classified(email: str | None) -> tuple[str, dict] | None:
            """(domain, classification) for an email, or None without a usable domain."""
            domain = domain_of(email or "")
            if domain is None:
                return None
            if domain not in classification:  # not in /api/users/ — classify anyway
                classification[domain] = classify(domain, overrides, edugain_scopes)
            return domain, classification[domain]

        def company_of(email: str | None) -> str | None:
            """Company key for an email, or None if it isn't a company domain."""
            hit = classified(email)
            if hit and hit[1]["category"] == "company":
                return hit[1].get("same_as") or hit[0]
            return None

        def excluded_of(email: str | None) -> str | None:
            """Domain for an email whose domain is excluded (not a company)."""
            hit = classified(email)
            if hit and hit[1]["category"] != "company":
                return hit[0]
            return None

        def add_usage(projects, key, r, month):
            p = projects[(key, r.get("project_uuid"))]
            p["uuid"] = r.get("project_uuid")
            p["organisation"] = r.get("customer_name") or ""
            p["project"] = r.get("project_name") or ""
            p["hours"][month] += r["usage"]
            p["users"].add(r["email"])

        def add_member(projects, key, project_uuid, email, is_active):
            p = projects[(key, project_uuid)]
            p["uuid"] = project_uuid
            p["project"] = p["project"] or offering_projects[project_uuid]["project"]
            p["organisation"] = p["organisation"] or offering_projects[project_uuid]["organisation"]
            p["members" if is_active else "former_members"].add(email)

        for email in access_emails:
            if company := company_of(email):
                access[company].add(email)
            elif domain := excluded_of(email):
                excluded_access[domain].add(email)
        for r in usage_rows:
            if not domain_of(r["email"] or ""):
                unmatched.append(r)
                continue
            month = (r.get("billing_period") or "")[:7]  # YYYY-MM
            company = company_of(r["email"])
            if not company:
                non_company_hours += r["usage"]
                if domain := excluded_of(r["email"]):
                    add_usage(excluded_projects, domain, r, month)
                continue
            hours[company][month] += r["usage"]
            month_users[company][month].add(r["email"])
            add_usage(company_projects, company, r, month)
        for m in memberships:
            project = offering_projects.get(m["project_uuid"])
            if project is None:
                continue
            # A revoked role only counts if it outlived the project's first
            # resource on the offering, i.e. the user was a member while the
            # project had access to it.
            if (
                not m["is_active"]
                and m["ended"] is not None
                and project["first_created"] is not None
                and m["ended"] < project["first_created"]
            ):
                continue
            email = email_by_user_uuid.get(m["user_uuid"])
            if company := company_of(email):
                add_member(company_projects, company, m["project_uuid"], email, m["is_active"])
            elif domain := excluded_of(email):
                add_member(excluded_projects, domain, m["project_uuid"], email, m["is_active"])

        # A domain found only through the offering (user missing from
        # /api/users/) still gets a row, with user_count 0.
        for company in [*access, *hours, *(c for c, _ in company_projects)]:
            companies.setdefault(company, companies.default_factory())
        listed = {domain for domain, _, _ in excluded_rows}
        for domain in dict.fromkeys([*excluded_access, *(d for d, _ in excluded_projects)]):
            if domain not in listed:
                excluded_rows.append((domain, [], classification[domain]))
        company_hours = {c: sum(m.values(), Decimal(0)) for c, m in hours.items()}
        total_hours = sum(company_hours.values(), Decimal(0))
        unmatched_hours = sum((r["usage"] for r in unmatched), Decimal(0))

        # Per sector: hours, domains and users with usage. Companies are keyed
        # by company (aliases merged), excluded domains by domain.
        sector_hours = defaultdict(Decimal)
        sector_domains = defaultdict(set)
        sector_users = defaultdict(set)
        for r in usage_rows:
            hit = classified(r["email"])
            if hit is None:
                continue  # unmatched; reported separately
            domain, c = hit
            sector = c["category"]
            sector_hours[sector] += r["usage"]
            sector_domains[sector].add((c.get("same_as") or domain) if sector == "company" else domain)
            sector_users[sector].add(r["email"])

    eprint(f"\n=== Summary ===")
    eprint(f"Domain-distinct company count: {len(companies)}")

    def review_status(domain: str, category: str) -> str:
        """'' if unchanged since the previous report or decided by an override, else 'yes' / 'changed (...)'."""
        if previous is None or any(d in overrides for d in parent_domains(domain)):
            return ""
        if domain not in previous:
            return "yes"
        if previous[domain] != category:
            return f"changed (was {previous[domain]})"
        return ""

    new_header = ["new"] if previous is not None else []
    new_width = [16] if previous is not None else []
    if usage_enabled:
        eprint(f"Companies with an account on {offering_label}: {len(access)}")
        eprint(f"Companies with usage on {offering_label}: {sum(1 for h in company_hours.values() if h > 0)}")
        eprint(f"Company {USAGE_COMPONENT_TYPE} {unit}: {total_hours:,.2f}")
        eprint(f"Non-company {USAGE_COMPONENT_TYPE} {unit} (academic, government, ...): {non_company_hours:,.2f}")
        all_hours = sum((r["usage"] for r in usage_rows), Decimal(0))
        eprint(
            f"All {offering_label} {USAGE_COMPONENT_TYPE} {unit}: {all_hours:,.2f} "
            f"(= company + non-company + unmatched: {total_hours + non_company_hours + unmatched_hours:,.2f})"
        )
        if unmatched:
            eprint(
                f"Unmatched: {len(unmatched)} usage row(s), {unmatched_hours:,.2f} {unit} — "
                f"no email could be found for the user; see the 'Unmatched usage' sheet."
            )
        if any(current_month in m for m in hours.values()):
            eprint(f"Note: {current_month} is the current month and still accumulating usage.")

    # --- Output: company domain list for manual review ---
    # Sorted by user_count desc so the biggest, most-obviously-real companies
    # are at the top and the single-user long tail (most likely to contain
    # the false positives/negatives called out above) is at the bottom where
    # it's easiest to eyeball in one pass.
    wb = Workbook()

    ws = wb.active
    ws.title = "Company domains"
    if usage_enabled:
        # Per company: projects (and their organisations) ordered by the hours
        # recorded against them, then by name for member-only projects.
        def project_order(p):
            return (-sum(p["hours"].values(), Decimal(0)), p["organisation"], p["project"])

        projects_by_company = defaultdict(list)
        for (company, _), p in sorted(company_projects.items(), key=lambda kv: project_order(kv[1])):
            projects_by_company[company].append(p)
        projects_by_excluded = defaultdict(list)
        for (domain, _), p in sorted(excluded_projects.items(), key=lambda kv: project_order(kv[1])):
            projects_by_excluded[domain].append(p)

    usage_header = (
        [f"{USAGE_COMPONENT_TYPE}_{unit}", "first_project_added", "first_usage_month", "last_usage_month", "active_months",
         "users_with_access", "users_with_usage", "organisations", "project_count", "projects"]
        if usage_enabled
        else []
    )
    usage_widths = [16, 20, 18, 18, 14, 18, 17, 50, 14, 60] if usage_enabled else []

    def capped(items: list[str]) -> str:
        """The first LIST_LIMIT items (most-used first), then '(+N more)'."""
        shown = ", ".join(items[:LIST_LIMIT])
        return shown + (f" (+{len(items) - LIST_LIMIT} more)" if len(items) > LIST_LIMIT else "")

    def usage_cells(access_emails: set, projects: list) -> list:
        """The usage columns, computed from the given projects only."""
        hours_by_month = defaultdict(Decimal)
        for p in projects:
            for month, h in p["hours"].items():
                hours_by_month[month] += h
        used = months_with_usage(hours_by_month)
        added = [d for p in projects if (d := project_dates.get(p["uuid"], {}).get("created"))]
        return [
            float(sum(hours_by_month.values(), Decimal(0))),
            min(added, default=None),
            used[0] if used else None,
            used[-1] if used else None,
            len(used),
            len(access_emails),
            len(set().union(*(p["users"] for p in projects))),
            capped(list(dict.fromkeys(p["organisation"] for p in projects))),
            len(projects),
            capped([p["project"] for p in projects]),
        ]

    def write_domain_sheet(sheet, rows, lead_header, lead_widths, tail_header, tail_widths):
        """Shared layout of the Company domains, Sovereign AI and Excluded sheets.

        domain, [new], <lead columns>, user_count, <usage columns>, <tail columns>, [emails].
        rows: (domain, review category, lead cells, emails, access emails, projects, tail cells),
        written in the given order; usage columns are computed from the projects only.
        """
        sheet.append(
            ["domain", *new_header, *lead_header, "user_count"] + usage_header + tail_header
            + (["emails"] if args.include_emails else [])
        )
        for domain, review_category, lead, emails, access_emails, projects, tail in rows:
            row = [domain, *([review_status(domain, review_category)] if new_header else []), *lead, len(emails)]
            if usage_enabled:
                row += usage_cells(access_emails, projects)
            row += tail
            if args.include_emails:
                row.append(", ".join(sorted(emails)))
            sheet.append(row)
        widths = [30, *new_width, *lead_widths, 12] + usage_widths + tail_widths + ([80] if args.include_emails else [])
        for i, width in enumerate(widths):
            sheet.column_dimensions[get_column_letter(i + 1)].width = width

    def company_rows(projects_for):
        return [
            (d, "company", [], c["emails"], access.get(d, set()), projects_for(d),
             [", ".join(sorted(c["merged"])), "; ".join(c["notes"])])
            for d, c in sorted(companies.items(), key=lambda kv: (-len(kv[1]["emails"]), kv[0]))
            if projects_for(d) is not None
        ]

    # Every company usage row lands in exactly one project, so summing a
    # company's projects gives the same totals as its overall usage.
    company_tail = (["merged_domains", "note"], [30, 50])
    write_domain_sheet(
        ws, company_rows(lambda d: projects_by_company[d] if usage_enabled else []), [], [], *company_tail
    )

    if usage_enabled:
        def sovereign_projects(d):
            projects = [p for p in projects_by_company[d] if p["organisation"] == SOVEREIGN_AI_ORGANISATION]
            return projects or None

        sovereign_rows = company_rows(sovereign_projects)
        write_domain_sheet(wb.create_sheet("Sovereign AI"), sovereign_rows, [], [], *company_tail)
        eprint(f"{SOVEREIGN_AI_ORGANISATION}: {len(sovereign_rows)} company domain(s) with projects in the organisation.")

    write_domain_sheet(
        wb.create_sheet("Excluded"),
        [
            (d, c["category"], [c["category"]], emails, excluded_access.get(d, set()),
             projects_by_excluded[d] if usage_enabled else [],
             [institution_of(d, c), c["matched_by"], c.get("note", "")])
            for d, emails, c in sorted(excluded_rows, key=lambda r: (r[2]["category"], -len(r[1]), r[0]))
        ],
        ["category"], [14],
        ["institution", "matched_by", "note"], [30, 30, 50],
    )

    if usage_enabled:
        monthly = wb.create_sheet("Monthly usage")
        monthly.append(["company", "month", f"{USAGE_COMPONENT_TYPE}_{unit}", "users", "partial_month"])
        for company in sorted(hours, key=lambda c: (-company_hours[c], c)):
            for month in sorted(hours[company]):
                monthly.append([
                    company,
                    month,
                    float(hours[company][month]),
                    len(month_users[company][month]),
                    "yes" if month == current_month else "",
                ])
        for col, width in zip("ABCDE", (30, 10, 16, 8, 14)):
            monthly.column_dimensions[col].width = width

        by_month = wb.create_sheet("By month")
        by_month.append(["month", f"{USAGE_COMPONENT_TYPE}_{unit}", "companies_active", "users_active", "partial_month"])
        for month in sorted({m for c in hours.values() for m in c}):
            active = [c for c in hours if hours[c].get(month, 0) > 0]
            by_month.append([
                month,
                float(sum((hours[c][month] for c in active), Decimal(0))),
                len(active),
                len(set().union(*(month_users[c][month] for c in active))),
                "yes" if month == current_month else "",
            ])
        for col, width in zip("ABCDE", (10, 16, 18, 14, 14)):
            by_month.column_dimensions[col].width = width

        by_project = wb.create_sheet("Projects")
        by_project.append([
            "company", "organisation", "project", "project_start_date", "project_end_date",
            f"{USAGE_COMPONENT_TYPE}_{unit}",
            "users_with_usage", "current_members", "former_members", "first_usage_month", "last_usage_month",
        ])
        for company in sorted(projects_by_company, key=lambda c: (-company_hours.get(c, 0), c)):
            for p in projects_by_company[company]:
                used = months_with_usage(p["hours"])
                by_project.append([
                    company,
                    p["organisation"],
                    p["project"],
                    project_dates.get(p["uuid"], {}).get("start_date"),
                    project_dates.get(p["uuid"], {}).get("end_date"),
                    float(sum(p["hours"].values(), Decimal(0))),
                    len(p["users"]),
                    len(p["members"]),
                    len(p["former_members"] - p["members"]),
                    used[0] if used else None,
                    used[-1] if used else None,
                ])
        for col, width in zip("ABCDEFGHIJK", (30, 40, 40, 18, 18, 16, 16, 16, 16, 18, 18)):
            by_project.column_dimensions[col].width = width

        unmatched_ws = wb.create_sheet("Unmatched usage")
        unmatched_ws.append(
            ["month", f"{USAGE_COMPONENT_TYPE}_{unit}", "organisation", "project"] + (["username"] if args.include_emails else [])
        )
        for r in sorted(unmatched, key=lambda r: (r.get("billing_period") or "", r.get("project_name") or "")):
            row = [(r.get("billing_period") or "")[:7], float(r["usage"]), r.get("customer_name"), r.get("project_name")]
            if args.include_emails:
                row.append(r.get("username"))
            unmatched_ws.append(row)
        for col, width in zip("ABCDE", (10, 16, 40, 40, 30)):
            unmatched_ws.column_dimensions[col].width = width

        totals = wb.create_sheet("Sector totals")
        hours_col = f"{USAGE_COMPONENT_TYPE}_{unit}"
        totals.append(["sector", hours_col, "share_of_per_user_total", "domains_with_usage", "users_with_usage"])

        def share(h):
            return round(float(h / all_hours), 4) if all_hours else None

        for sector in SECTORS:
            h = sector_hours.get(sector, Decimal(0))
            totals.append([sector, float(h), share(h), len(sector_domains[sector]), len(sector_users[sector])])
        totals.append(["unmatched (no email)", float(unmatched_hours), share(unmatched_hours), None, None])
        totals.append(["TOTAL (per-user usage)", float(all_hours), share(all_hours), None, None])
        for row in totals.iter_rows(min_row=2, min_col=3, max_col=3):
            for cell in row:
                cell.number_format = "0.0%"
        for col, width in zip("ABCDE", (28, 16, 24, 20, 18)):
            totals.column_dimensions[col].width = width

    wb.save(args.output)

    to_review = sorted(
        [(d, "company", len(c["emails"])) for d, c in companies.items()]
        + [(d, c["category"], len(e)) for d, e, c in excluded_rows]
    )
    flagged = [(d, cat, n, status) for d, cat, n in to_review if (status := review_status(d, cat))]
    if previous is None:
        eprint("\n(Pass --previous LAST_MONTH.xlsx to flag domains that are new since that report.)")
    elif flagged:
        eprint(
            f"\n{len(flagged)} domain(s) new or changed since {args.previous.name} (new column in the sheet); "
            f"add an override to {args.overrides.name} for any that are classified wrongly:"
        )
        for d, cat, n, status in flagged:
            eprint(f"  {d}: {cat}, {n} user(s) [{status}]")
    else:
        eprint(f"\nNo domains new or changed since {args.previous.name}.")

    eprint(
        f"\n{len(companies)} candidate company domain(s) written to {args.output}. "
        f"Review single-user domains especially closely — they're the likeliest "
        f"false positives (personal-looking domain, contractor, typo) or, if a "
        f"generic-looking address was actually a company alias, false negatives."
    )


if __name__ == "__main__":
    main()
