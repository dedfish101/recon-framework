"""
recon_engine.py
================
Master control pipeline for the Full-Spectrum Recon Framework.

This module is intentionally decoupled from the TUI: it exposes an async
`ReconEngine` class that runs each stage of the pipeline and reports
progress via a callback, so it can be driven by the Textual UI, a plain
CLI, or a test harness.

Design principles:
- Every external tool call goes through `_run_tool`, which enforces a
  timeout, captures stdout/stderr, and NEVER raises on failure — it
  returns a `StageResult` so the pipeline can keep going with whatever
  data it already has.
- Each stage writes its raw tool output to /output/<domain>/raw/ and its
  merged/deduplicated result to /output/<domain>/ for auditability.
- Stages are pure functions of "what stage N produced" -> "what stage
  N+1 needs", so any stage can be skipped/rerun independently.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import shlex
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Awaitable, Callable, Iterable, Optional
from urllib.parse import parse_qs, urlencode, urlsplit
import urllib.request

from ipwhois import IPWhois

# --------------------------------------------------------------------------
# Data structures
# --------------------------------------------------------------------------

@dataclass
class StageResult:
    """Outcome of a single tool invocation. Never raises — always returned."""
    tool: str
    ok: bool
    returncode: Optional[int]
    duration_s: float
    output_path: Optional[Path] = None
    error: Optional[str] = None
    lines: int = 0


@dataclass
class ReconStats:
    """Live counters the TUI binds to. Updated in place as the pipeline runs."""
    subdomains_found: int = 0
    live_targets: int = 0
    forbidden_403_found: int = 0
    urls_found: int = 0
    sensitive_urls_found: int = 0
    screenshots_taken: int = 0
    vulnerabilities_found: int = 0
    js_vulnerabilities_found: int = 0
    outdated_tech_found: int = 0
    attack_surface_categorized: int = 0
    attack_surface_by_path_categorized: int = 0
    attack_surface_by_extension_categorized: int = 0
    asns_found: int = 0
    related_organizations_found: int = 0
    hosts_with_open_ports: int = 0
    open_ports_found: int = 0
    cert_new_subdomains_found: int = 0
    js_endpoints_found: int = 0
    secrets_found: int = 0
    js_files_skipped: int = 0
    unique_params_found: int = 0
    errors: list[str] = field(default_factory=list)


ProgressCallback = Callable[[str, str, str], Awaitable[None]]
# signature: (stage_name, status, message) -> None
#   status in {"running", "ok", "warn", "error", "done"}

LogCallback = Callable[[str], Awaitable[None]]
# signature: (line_of_text) -> None


# --------------------------------------------------------------------------
# Passive data-processing helpers
#
# Pure functions — no I/O, no subprocess calls — so they can be unit
# tested or reused outside the ReconEngine pipeline (e.g. a batch
# reprocessing job over existing raw/ output). Engine methods only handle
# reading raw tool output and writing the processed result to workdir/.
# --------------------------------------------------------------------------

def categorize_http_results(records: list[dict]) -> dict[str, list[dict]]:
    """
    Split httpx JSON records into three buckets:
      - "active": any host that returned an HTTP response, regardless of
        status code (200s through 5xx) — actionable data.
      - "forbidden_403": active hosts specifically returning 403, isolated
        for manual review (access-controlled content worth a closer look).
      - "unreachable": DNS failures, connection timeouts, or no response
        at all — kept only for audit, not actionable.
    """
    active: list[dict] = []
    forbidden_403: list[dict] = []
    unreachable: list[dict] = []

    for rec in records:
        status = rec.get("status_code")
        if rec.get("failed") or status is None:
            unreachable.append(rec)
        elif status == 403:
            forbidden_403.append(rec)
        else:
            active.append(rec)

    return {"active": active, "forbidden_403": forbidden_403, "unreachable": unreachable}


def extract_resolved_ip(rec: dict) -> Optional[str]:
    """
    Pull the resolved IP out of an httpx JSON record. httpx's field name
    for this has changed across versions — pre-1.7.3 put the IP in
    "host" (name resolution) when `-ip` was passed; 1.7.3+ moved the
    hostname into "host" and added a dedicated "host_ip" field. Checking
    both and validating with `ipaddress` keeps this working regardless
    of which httpx version the image ends up with, rather than pinning
    to one field name.
    """
    for key in ("host_ip", "host"):
        val = rec.get(key)
        if val:
            try:
                ipaddress.ip_address(val)
                return val
            except ValueError:
                continue
    return None


def merge_tech_stack(
    httpx_tech: dict[str, list[str]],
    whatweb_path: Path,
    wappalyzer_path: Optional[Path] = None,
) -> dict[str, list[str]]:
    """
    Merge technology fingerprints from httpx's -tech-detect, WhatWeb's
    --log-json output, and (if present) a Wappalyzer JSON dump into a
    single host -> sorted[tech,...] map.

    Each source is read defensively: a missing file or malformed JSON is
    skipped rather than raised, since this always runs after best-effort
    tool invocations that may not have produced output.
    """
    merged: dict[str, set[str]] = {host: set(techs) for host, techs in httpx_tech.items()}

    if whatweb_path.exists():
        try:
            entries = json.loads(whatweb_path.read_text(errors="replace") or "[]")
        except json.JSONDecodeError:
            entries = []
        for entry in entries:
            host = entry.get("target", "")
            if host:
                merged.setdefault(host, set()).update(entry.get("plugins", {}).keys())

    if wappalyzer_path and wappalyzer_path.exists():
        try:
            entries = json.loads(wappalyzer_path.read_text(errors="replace") or "{}")
        except json.JSONDecodeError:
            entries = {}
        # Accept either {"<url>": {"technologies": [...]}} or
        # [{"url": "<url>", "technologies": [...]}] — CLI/library versions differ.
        items = entries.items() if isinstance(entries, dict) else (
            (e.get("url", ""), e) for e in entries if isinstance(e, dict)
        )
        for host, data in items:
            if not host or not isinstance(data, dict):
                continue
            names = [t.get("name", "") if isinstance(t, dict) else t for t in data.get("technologies", [])]
            merged.setdefault(host, set()).update(n for n in names if n)

    return {host: sorted(techs) for host, techs in merged.items() if techs}


# Query-parameter name patterns worth flagging for manual review. Matched
# against parameter *names* only (never values) — classification, not
# exploitation.
SENSITIVE_PARAM_PATTERNS: dict[str, re.Pattern] = {
    "identifiers": re.compile(r"(?i)^(id|uid|pid|uuid|user_?id|account_?id|acct|customer_?id|order_?id)$"),
    "tokens": re.compile(r"(?i)^(token|access_token|refresh_token|jwt|bearer|csrf)$"),
    "auth_secrets": re.compile(r"(?i)^(api_?key|apikey|secret|password|pwd|passwd|auth)$"),
    "session": re.compile(r"(?i)^(session|sid|sessid|phpsessid|jsessionid)$"),
}


def filter_sensitive_urls(urls: set[str]) -> dict[str, list[str]]:
    """
    Classify already-collected URLs (from gau/waybackurls) by whether
    their query parameters match known-sensitive name patterns —
    identifiers, tokens, auth secrets, session IDs. Read-only inspection
    of static strings; issues no requests. Returns category -> sorted[url,...].
    """
    hits: dict[str, set[str]] = {cat: set() for cat in SENSITIVE_PARAM_PATTERNS}

    for url in urls:
        query = urlsplit(url).query
        if not query:
            continue
        for param_name in parse_qs(query, keep_blank_values=True):
            for category, pattern in SENSITIVE_PARAM_PATTERNS.items():
                if pattern.match(param_name):
                    hits[category].add(url)

    return {cat: sorted(u) for cat, u in hits.items() if u}


# Vulnerability-class triage buckets for Stage 10. These are heuristic
# signals from parameter *names* only (never values, never sent
# anywhere) — a manual-review starting point, not a confirmed finding.
ATTACK_SURFACE_PATTERNS: dict[str, re.Pattern] = {
    "sqli": re.compile(r"(?i)^(id|cat|category|view|pid|item_?id|product_?id|page_?id)$"),
    "xss": re.compile(r"(?i)^(q|search|query|s|keyword|term|name|comment)$"),
    "ssrf": re.compile(r"(?i)^(url|uri|redirect|next|dest|destination|return|callback|target|out|path)$"),
    "sensitive": re.compile(r"(?i)^(token|auth|secret|user|username|email|password|pwd|apikey|api_?key)$"),
}


def categorize_urls_by_param(
    urls: Iterable[str],
    categories: dict[str, re.Pattern] = ATTACK_SURFACE_PATTERNS,
) -> dict[str, list[str]]:
    """
    Bucket URLs by query-parameter *name* against a category -> pattern
    map. Parses with urllib.parse only — no requests, no payload
    injection. A URL can land in multiple buckets (e.g. ?id=1&token=abc
    matches both "sqli" and "sensitive"). Every category key is always
    present in the result, even with an empty list, so callers can write
    one file per category unconditionally.
    """
    buckets: dict[str, set[str]] = {cat: set() for cat in categories}
    for url in urls:
        query = urlsplit(url).query
        if not query:
            continue
        for param_name in parse_qs(query, keep_blank_values=True):
            for category, pattern in categories.items():
                if pattern.match(param_name):
                    buckets[category].add(url)
    return {cat: sorted(u) for cat, u in buckets.items()}


# Path-segment patterns for a second attack-surface axis, independent of
# query parameters — catches URLs that carry no query string at all
# (e.g. a bare /admin/ or /api/v2/users). Matched against the URL's
# path via `re.search`, case-insensitively.
PATH_SURFACE_PATTERNS: dict[str, re.Pattern] = {
    "admin_panels": re.compile(r"(?i)/(admin|administrator|wp-admin|cpanel|manage|dashboard)(/|$)"),
    "api_endpoints": re.compile(r"(?i)/(api|graphql|rest)(/|$)|/v[0-9]+(/|$)"),
    "auth_endpoints": re.compile(
        r"(?i)/(login|signin|sign-in|signup|sign-up|register|auth|oauth|sso|"
        r"password-?reset|forgot-?password)(/|$)"
    ),
    "file_uploads": re.compile(r"(?i)/(upload|uploads|file|files|media|attachment|attachments)(/|$)"),
    "internal_tools": re.compile(
        r"(?i)/(jenkins|grafana|kibana|swagger|swagger-ui|actuator|debug|internal|staging)(/|$)"
    ),
    "vcs_exposure": re.compile(r"(?i)/\.(git|svn|hg)(/|$)"),
}

# File-extension patterns for a third attack-surface axis — the
# "forgotten file" surface (leaked configs, DB dumps, backups) that
# neither the param nor the path axis catches.
EXTENSION_SURFACE_PATTERNS: dict[str, re.Pattern] = {
    "config_files": re.compile(r"(?i)^\.(env|ya?ml|ini|conf|config|toml|properties)$"),
    "backup_files": re.compile(r"(?i)^\.(bak|old|orig|swp|save|tmp|backup)$"),
    "archive_files": re.compile(r"(?i)^\.(zip|tar|tgz|gz|rar|7z)$"),
    "database_files": re.compile(r"(?i)^\.(sql|db|sqlite|sqlite3|mdb)$"),
    "log_files": re.compile(r"(?i)^\.(log|out)$"),
}


def categorize_urls_by_path(
    urls: Iterable[str],
    categories: dict[str, re.Pattern] = PATH_SURFACE_PATTERNS,
) -> dict[str, list[str]]:
    """
    Bucket URLs by matching path segments against a category -> pattern
    map (admin panels, API endpoints, auth flows, upload handlers,
    internal tooling, exposed VCS directories). Unlike
    `categorize_urls_by_param`, this catches URLs with no query string
    at all. Matches against urlsplit(url).path only — no requests. A URL
    can land in multiple buckets.
    """
    buckets: dict[str, set[str]] = {cat: set() for cat in categories}
    for url in urls:
        path = urlsplit(url).path
        if not path:
            continue
        for category, pattern in categories.items():
            if pattern.search(path):
                buckets[category].add(url)
    return {cat: sorted(u) for cat, u in buckets.items()}


def categorize_urls_by_extension(
    urls: Iterable[str],
    categories: dict[str, re.Pattern] = EXTENSION_SURFACE_PATTERNS,
) -> dict[str, list[str]]:
    """
    Bucket URLs by the file extension on their path (config/backup/
    archive/database/log files) — the classic "forgotten file" surface
    that neither param- nor path-based triage catches. Extension is
    taken from the last path segment via a plain string split, matched
    case-insensitively; no requests are made.
    """
    buckets: dict[str, set[str]] = {cat: set() for cat in categories}
    for url in urls:
        path = urlsplit(url).path
        last_segment = path.rsplit("/", 1)[-1]
        if "." not in last_segment:
            continue
        ext = "." + last_segment.rsplit(".", 1)[-1]
        for category, pattern in categories.items():
            if pattern.match(ext):
                buckets[category].add(url)
    return {cat: sorted(u) for cat, u in buckets.items()}


def build_parameter_inventory(urls: Iterable[str]) -> dict[str, list[str]]:
    """
    Group already-collected URLs by every distinct query-parameter name
    they carry (not just the four vuln-class buckets from
    `categorize_urls_by_param`) — e.g. {"company_id": [url, ...]}. Meant
    for manual review: business-logic-relevant parameters like
    ?debug=true or ?admin=false are exactly what fixed vuln-class
    buckets miss and automated scanners don't flag. Read-only parsing
    via urllib.parse, no requests.
    """
    inventory: dict[str, set[str]] = {}
    for url in urls:
        query = urlsplit(url).query
        if not query:
            continue
        for param_name in parse_qs(query, keep_blank_values=True):
            inventory.setdefault(param_name, set()).add(url)
    return {name: sorted(u) for name, u in sorted(inventory.items())}


# LinkFinder-style heuristic: quoted strings that look like an absolute
# URL or an absolute/relative path. Not an exact port of LinkFinder's
# regex — a simplified pattern tuned for low false-negatives over exact
# precision, since output here feeds manual review, not automation.
JS_ENDPOINT_PATTERN = re.compile(
    r"""["'](
        [a-zA-Z][a-zA-Z0-9+.\-]*://[^\s"'<>]+          # absolute URL
        |/(?:[a-zA-Z0-9_\-.]+/)*[a-zA-Z0-9_\-.]+        # absolute/relative path
    )["']""",
    re.VERBOSE,
)


def extract_js_endpoints(js_path: Path) -> Optional[list[str]]:
    """
    Heuristic extraction of endpoint/path-looking strings from a local
    JS file's source text — static regex over bytes already on disk, no
    execution, no network calls. Returns `None` (not an empty list) for
    files that are unreadable or empty, so callers can tell "found
    nothing" apart from "couldn't process this one" and log accordingly.
    """
    try:
        text = js_path.read_text(errors="replace")
    except OSError:
        return None
    if not text.strip():
        return None
    return sorted({m.group(1) for m in JS_ENDPOINT_PATTERN.finditer(text)})


def extract_tech_versions(
    whatweb_path: Path,
    wappalyzer_path: Optional[Path] = None,
) -> dict[str, dict[str, str]]:
    """
    Parse WhatWeb --log-json output and (optional) Wappalyzer JSON into
    host -> {tech_name: version_string}. Only fingerprints with an
    explicit version are kept — unversioned matches aren't audit-able
    against a version database.
    """
    versions: dict[str, dict[str, str]] = {}

    if whatweb_path.exists():
        try:
            entries = json.loads(whatweb_path.read_text(errors="replace") or "[]")
        except json.JSONDecodeError:
            entries = []
        for entry in entries:
            host = entry.get("target", "")
            if not host:
                continue
            for name, plugin in entry.get("plugins", {}).items():
                vers = plugin.get("version") if isinstance(plugin, dict) else None
                if vers:
                    versions.setdefault(host, {})[name] = vers[0] if isinstance(vers, list) else str(vers)

    if wappalyzer_path and wappalyzer_path.exists():
        try:
            entries = json.loads(wappalyzer_path.read_text(errors="replace") or "{}")
        except json.JSONDecodeError:
            entries = {}
        items = entries.items() if isinstance(entries, dict) else (
            (e.get("url", ""), e) for e in entries if isinstance(e, dict)
        )
        for host, data in items:
            if not host or not isinstance(data, dict):
                continue
            for tech in data.get("technologies", []):
                if not isinstance(tech, dict):
                    continue
                name, vers = tech.get("name"), tech.get("version")
                if name and vers:
                    versions.setdefault(host, {})[name] = vers

    return versions


def _version_tuple(v: str) -> tuple[int, ...]:
    """Best-effort dotted-version parse for comparison; non-numeric segments become 0."""
    out = []
    for part in re.split(r"[.\-+]", v):
        m = re.match(r"\d+", part)
        out.append(int(m.group()) if m else 0)
    return tuple(out) or (0,)


def _version_lt(a: str, b: str) -> bool:
    ta, tb = _version_tuple(a), _version_tuple(b)
    pad = max(len(ta), len(tb))
    ta += (0,) * (pad - len(ta))
    tb += (0,) * (pad - len(tb))
    return ta < tb


# Technology name (as reported by WhatWeb/Wappalyzer, matched
# case-insensitively) -> the version it was fixed in. Any detected
# version strictly below that is flagged. Lives in vuln_version_db.json
# next to this file so it can be edited/replaced (e.g. with a
# periodically-refreshed OSV/NVD export) without touching code; the
# dict literal below is only the fallback used if that file is missing
# or unparseable.
_VULN_VERSION_DB_PATH = Path(__file__).resolve().parent / "vuln_version_db.json"
_VULN_VERSION_DB_FALLBACK: dict[str, dict] = {
    "jquery": {"fixed_in": "3.5.0", "advisory": "Prototype pollution / XSS (CVE-2020-11022, CVE-2020-11023)"},
    "wordpress": {"fixed_in": "6.4.2", "advisory": "Multiple core CVEs patched before 6.4.2"},
    "apache": {"fixed_in": "2.4.58", "advisory": "Multiple httpd CVEs patched before 2.4.58"},
    "nginx": {"fixed_in": "1.25.3", "advisory": "Multiple nginx CVEs patched before 1.25.3"},
    "openssl": {"fixed_in": "3.0.13", "advisory": "Multiple OpenSSL CVEs patched before 3.0.13"},
    "php": {"fixed_in": "8.1.27", "advisory": "Multiple PHP CVEs patched before 8.1.27"},
    "lodash": {"fixed_in": "4.17.21", "advisory": "Prototype pollution (CVE-2020-8203, CVE-2020-28500)"},
    "bootstrap": {"fixed_in": "4.3.1", "advisory": "XSS in data-target/data-container (CVE-2019-8331)"},
}


def _load_vuln_version_db() -> dict[str, dict]:
    if _VULN_VERSION_DB_PATH.exists():
        try:
            return json.loads(_VULN_VERSION_DB_PATH.read_text(errors="replace"))
        except json.JSONDecodeError:
            pass
    return _VULN_VERSION_DB_FALLBACK


VULN_VERSION_DB: dict[str, dict] = _load_vuln_version_db()


def audit_tech_versions(
    tech_versions: dict[str, dict[str, str]],
    vuln_db: dict[str, dict],
) -> list[dict]:
    """
    Compare each host's detected tech versions against `vuln_db`. Pure
    data comparison — no requests made. Returns a flat findings list.
    """
    findings = []
    for host, techs in tech_versions.items():
        for name, version in techs.items():
            entry = vuln_db.get(name.lower())
            if entry and _version_lt(version, entry["fixed_in"]):
                findings.append({
                    "host": host,
                    "technology": name,
                    "detected_version": version,
                    "fixed_in": entry["fixed_in"],
                    "advisory": entry["advisory"],
                })
    return findings


# --------------------------------------------------------------------------
# Network/organization enrichment helpers (Stage 5 — BGP/ASN lookup)
#
# Both functions are blocking network calls, so callers run them via
# `asyncio.to_thread` (same pattern as `_download_js_files`'s `_fetch`).
# Both are strictly best-effort: they query public registries/APIs about
# already-known IPs or org names, never touch the scan target itself, and
# swallow every failure rather than raising, since a missing RDAP record
# or an org name with no Wikidata match is an expected, common outcome —
# not a pipeline error.
# --------------------------------------------------------------------------

def lookup_org_context(ip: str, timeout_s: int = 8) -> Optional[dict]:
    """
    RDAP lookup (ASN, CIDR, org/network name) for a single IP via the
    `ipwhois` package. Purely informational — this is metadata *about*
    the IP from public registries, not a request to the IP itself beyond
    the RDAP query.
    """
    try:
        result = IPWhois(ip, timeout=timeout_s).lookup_rdap(depth=1)
    except Exception:
        return None
    network = result.get("network") or {}
    org = network.get("name") or result.get("asn_description")
    if not result.get("asn") and not org:
        return None
    return {
        "asn": result.get("asn"),
        "asn_cidr": result.get("asn_cidr"),
        "asn_description": result.get("asn_description"),
        "org": org,
    }


def lookup_related_orgs(org_name: str, timeout_s: int = 8) -> list[dict]:
    """
    Best-effort Wikidata lookup for parent/subsidiary organizations of
    `org_name` (as reported by RDAP) and their official websites —
    surfaces acquisition/subsidiary infrastructure a human might want to
    scope into a *separate*, separately-authorized engagement. Results
    are informational only: nothing this returns is ever merged into
    `self.subdomains` or scanned automatically. Returns [] on any
    failure or when the org has no clean Wikidata match, which is the
    common case for most domains.
    """
    if not org_name:
        return []

    def _fetch_json(url: str) -> Optional[dict]:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (recon-framework)"})
        try:
            with urllib.request.urlopen(req, timeout=timeout_s) as resp:
                return json.loads(resp.read())
        except Exception:
            return None

    search = _fetch_json(
        "https://www.wikidata.org/w/api.php?" + urlencode({
            "action": "wbsearchentities", "search": org_name, "language": "en",
            "format": "json", "type": "item", "limit": 1,
        })
    )
    hits = (search or {}).get("search") or []
    if not hits:
        return []
    entity_id = hits[0]["id"]

    entity = _fetch_json(f"https://www.wikidata.org/wiki/Special:EntityData/{entity_id}.json")
    if not entity:
        return []
    claims = entity.get("entities", {}).get(entity_id, {}).get("claims", {})

    related_ids: set[str] = set()
    for prop in ("P749", "P355"):  # parent organization, subsidiary
        for claim in claims.get(prop, []):
            value = claim.get("mainsnak", {}).get("datavalue", {}).get("value", {})
            if isinstance(value, dict) and value.get("id"):
                related_ids.add(value["id"])

    results: list[dict] = []
    for related_id in related_ids:
        related = _fetch_json(f"https://www.wikidata.org/wiki/Special:EntityData/{related_id}.json")
        if not related:
            continue
        related_entity = related.get("entities", {}).get(related_id, {})
        website = None
        for claim in related_entity.get("claims", {}).get("P856", []):  # official website
            website = claim.get("mainsnak", {}).get("datavalue", {}).get("value")
            if website:
                break
        name = related_entity.get("labels", {}).get("en", {}).get("value", related_id)
        results.append({"name": name, "wikidata_id": related_id, "website": website})
    return results


def parse_nmap_xml(xml_path: Path) -> dict[str, list[int]]:
    """
    Parse nmap's -oX output (written as part of -oA) into
    ip -> [open_port,...]. Structured XML parsing via the stdlib rather
    than regex over the .gnmap text — nmap's XML has an explicit
    state="open" attribute per port, so there's no ambiguity about what
    counts as open. Returns {} if the file is missing or unparseable
    (nmap wasn't run, or was killed mid-write by a timeout).
    """
    if not xml_path.exists():
        return {}
    try:
        root = ET.parse(xml_path).getroot()
    except ET.ParseError:
        return {}

    open_ports: dict[str, list[int]] = {}
    for host_el in root.findall("host"):
        address_el = host_el.find("address")
        if address_el is None or not address_el.get("addr"):
            continue
        ip = address_el.get("addr")

        ports: list[int] = []
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                portid = port_el.get("portid")
                if state_el is not None and state_el.get("state") == "open" and portid and portid.isdigit():
                    ports.append(int(portid))
        if ports:
            open_ports[ip] = sorted(ports)
    return open_ports


class ReconEngine:
    """
    Orchestrates the recon pipeline against a single target
    domain. All state (stats, output paths) lives on the instance so a
    fresh ReconEngine should be created per target/run.
    """

    # Per-tool timeouts (seconds). Generous but bounded so a single hung
    # process never stalls the whole pipeline indefinitely.
    TIMEOUTS = {
        "assetfinder": 180,
        "subfinder": 300,
        "bbot": 900,
        "httpx": 300,
        "whatweb": 600,
        "gau": 300,
        "waybackurls": 300,
        "gowitness": 900,
        "naabu": 300,
        "nmap": 900,
        "tlsx": 300,
        "nuclei": 1800,
        "retire": 300,
        "gitleaks": 300,
    }

    MODES = ("quick", "deep")

    def __init__(
        self,
        domain: str,
        output_root: Path,
        on_progress: Optional[ProgressCallback] = None,
        on_log: Optional[LogCallback] = None,
        mode: str = "quick",
    ):
        if mode not in self.MODES:
            raise ValueError(f"mode must be one of {self.MODES}, got {mode!r}")

        self.domain = domain.strip().lower()
        self.output_root = Path(output_root)
        self.mode = mode
        self.workdir = self.output_root / self.domain
        self.raw_dir = self.workdir / "raw"
        # "Discovery" (stages 1-10, always run) writes directly under
        # workdir/, as before. "Deep Analysis" (stages 11-12, mode="deep"
        # only) writes under its own subdirectory so a priority-target
        # deep-dive is clearly separated from the fast, wildcard-friendly
        # baseline pipeline's output.
        self.deep_dir = self.workdir / "deep_analysis"
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.raw_dir.mkdir(parents=True, exist_ok=True)

        self.stats = ReconStats()
        self._on_progress = on_progress or self._noop_progress
        self._on_log = on_log or self._noop_log

        # Populated as stages complete; later stages read from these.
        self.subdomains: set[str] = set()
        self.live_targets: list[dict] = []
        self.active_targets: list[dict] = []       # live_targets minus 403s/unreachable
        self.forbidden_403: list[dict] = []        # isolated for manual review
        self.unreachable_targets: list[dict] = []  # DNS/timeout failures, audit only
        self.urls: set[str] = set()
        self.sensitive_urls: dict[str, list[str]] = {}  # category -> [url,...]
        self.categorized_urls: dict[str, list[str]] = {}  # sqli/xss/ssrf/sensitive -> [url,...]
        self.categorized_urls_by_path: dict[str, list[str]] = {}  # admin_panels/api_endpoints/... -> [url,...]
        self.categorized_urls_by_extension: dict[str, list[str]] = {}  # config_files/backup_files/... -> [url,...]
        self.tech_stack: dict[str, list[str]] = {}  # host -> [tech,...]
        self.resolved_ips: dict[str, str] = {}       # host -> ip, populated in stage2
        self.asn_info: dict[str, dict] = {}          # ip -> {asn, asn_cidr, org}, informational only
        self.related_organizations: list[dict] = []  # informational only, never auto-scanned
        self.open_ports: dict[str, list[int]] = {}   # ip -> [port,...]
        self.cert_findings: list[dict] = []           # [{ip, port, cn, sans: [...]}, ...]

        # Deep-mode-only results (empty unless stage8/9 have run).
        self.js_endpoints: dict[str, list[str]] = {}     # js filename -> [endpoint,...]
        self.secrets_findings: list[dict] = []            # gitleaks findings
        self.parameter_inventory: dict[str, list[str]] = {}  # param name -> [url,...]

    # ---------------------------------------------------------------- utils

    @staticmethod
    async def _noop_progress(stage: str, status: str, message: str) -> None:
        return None

    @staticmethod
    async def _noop_log(line: str) -> None:
        return None

    async def _emit(self, stage: str, status: str, message: str = "") -> None:
        await self._on_progress(stage, status, message)

    async def _log(self, line: str) -> None:
        await self._on_log(line)

    async def _run_tool(
        self,
        tool: str,
        cmd: list[str],
        output_file: Optional[Path] = None,
    ) -> StageResult:
        """
        Run a subprocess with a timeout, streaming stdout to both the log
        callback (for the TUI) and an output file. stderr is captured on
        its own pipe and kept separate: it's never written to
        `output_file` and never streamed live to the log during normal
        execution, so a tool's warnings (e.g. gau's missing-config
        notice) can't corrupt a results file or clutter the TUI. On
        non-zero exit or timeout, the last 20 stderr lines are surfaced
        via the log/error path so failures stay debuggable. Never
        raises; failures and timeouts are captured in the returned
        StageResult so the calling stage can decide how to fall back.
        """
        start = time.monotonic()
        await self._log(f"$ {' '.join(shlex.quote(c) for c in cmd)}")

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError:
            err = f"{tool}: binary not found on PATH"
            await self._log(f"[ERROR] {err}")
            self.stats.errors.append(err)
            return StageResult(tool, False, None, 0.0, error=err)
        except Exception as e:  # pragma: no cover - defensive
            err = f"{tool}: failed to launch ({e})"
            await self._log(f"[ERROR] {err}")
            self.stats.errors.append(err)
            return StageResult(tool, False, None, 0.0, error=err)

        collected: list[str] = []
        stderr_lines: list[str] = []
        fh = output_file.open("w", encoding="utf-8") if output_file else None

        async def _drain_stdout():
            assert proc.stdout is not None
            async for raw_line in proc.stdout:
                line = raw_line.decode(errors="replace").rstrip("\n")
                collected.append(line)
                if fh:
                    fh.write(line + "\n")
                await self._log(line)

        async def _drain_stderr():
            assert proc.stderr is not None
            async for raw_line in proc.stderr:
                stderr_lines.append(raw_line.decode(errors="replace").rstrip("\n"))

        try:
            await asyncio.wait_for(
                asyncio.gather(_drain_stdout(), _drain_stderr(), proc.wait()),
                timeout=self.TIMEOUTS.get(tool, 300),
            )
            ok = proc.returncode == 0
            duration = time.monotonic() - start
            if not ok:
                msg = f"{tool} exited with code {proc.returncode}"
                self.stats.errors.append(msg)
                await self._log(f"[WARN] {msg}")
                for line in stderr_lines[-20:]:
                    await self._log(f"[STDERR] {line}")
            return StageResult(
                tool, ok, proc.returncode, duration,
                output_path=output_file, lines=len(collected),
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            duration = time.monotonic() - start
            msg = f"{tool} timed out after {self.TIMEOUTS.get(tool, 300)}s — using partial data"
            self.stats.errors.append(msg)
            await self._log(f"[TIMEOUT] {msg}")
            for line in stderr_lines[-20:]:
                await self._log(f"[STDERR] {line}")
            return StageResult(
                tool, False, None, duration,
                output_path=output_file, error="timeout", lines=len(collected),
            )
        finally:
            if fh:
                fh.close()

    # -------------------------------------------------------------- stages

    async def stage1_subdomain_discovery(self) -> None:
        """Assetfinder, Subfinder, bbot -> merged/deduped subdomain set."""
        await self._emit("subdomains", "running", "Enumerating subdomains...")

        bbot_dir = self.raw_dir / "bbot"
        results = await asyncio.gather(
            self._run_tool(
                "assetfinder",
                ["assetfinder", "--subs-only", self.domain],
                output_file=self.raw_dir / "assetfinder.txt",
            ),
            self._run_tool(
                "subfinder",
                # -all pulls in every configured source, including any
                # provider-config.yaml keys entrypoint.sh wrote from
                # SUBFINDER_* env vars (chaos/github/dnsdumpster/c99) —
                # sources with no key configured are skipped by subfinder
                # itself, so this is safe with or without keys present.
                ["subfinder", "-d", self.domain, "-all", "-silent", "-o",
                 str(self.raw_dir / "subfinder.txt")],
            ),
            self._run_tool(
                "bbot",
                # -rf passive restricts to passive-only modules (no active
                # probing of the target beyond what subdomain-enum's
                # passive sources already do); -y skips the interactive
                # scan-confirmation prompt for unattended runs; -om
                # subdomains writes a flat, resolved, in-scope hostname
                # list to <output>/<name>/subdomains.txt.
                ["bbot", "-t", self.domain, "-f", "subdomain-enum", "-rf", "passive",
                 "-om", "subdomains", "-o", str(bbot_dir), "-n", "scan", "-y", "--silent"],
            ),
            return_exceptions=False,
        )

        ok_count = sum(1 for r in results if r.ok)
        merged: set[str] = set()
        for fname in ("assetfinder.txt", "subfinder.txt"):
            fpath = self.raw_dir / fname
            if fpath.exists():
                for line in fpath.read_text(errors="replace").splitlines():
                    line = line.strip().lower()
                    if line and self.domain in line:
                        merged.add(line)

        # bbot writes its own results file rather than printing plain
        # lines to stdout like the other two tools, so it's read
        # separately here instead of via _run_tool's output_file capture.
        bbot_subdomains = bbot_dir / "scan" / "subdomains.txt"
        if bbot_subdomains.exists():
            for line in bbot_subdomains.read_text(errors="replace").splitlines():
                line = line.strip().lower()
                if line and self.domain in line:
                    merged.add(line)

        # Always include the apex domain itself.
        merged.add(self.domain)
        self.subdomains = merged
        self.stats.subdomains_found = len(merged)

        (self.workdir / "subdomains.txt").write_text("\n".join(sorted(merged)))

        status = "ok" if ok_count > 0 else "warn"
        await self._emit(
            "subdomains", status,
            f"{len(merged)} unique subdomains ({ok_count}/3 tools succeeded)",
        )

    async def stage2_probing_fingerprinting(self) -> None:
        """Httpx + WhatWeb -> live hosts, status codes, tech stack."""
        if not self.subdomains:
            await self._emit("probing", "warn", "No subdomains to probe, skipping")
            return

        await self._emit("probing", "running", "Probing live hosts...")

        httpx_out = self.raw_dir / "httpx.jsonl"
        httpx_result = await self._run_tool(
            "httpx",
            ["httpx", "-l", str(self.workdir / "subdomains.txt"),
             "-json", "-status-code", "-tech-detect", "-title", "-ip",
             "-silent", "-o", str(httpx_out)],
        )

        live: list[dict] = []
        if httpx_out.exists():
            for line in httpx_out.read_text(errors="replace").splitlines():
                try:
                    rec = json.loads(line)
                    live.append(rec)
                    host = rec.get("input") or rec.get("url", "")
                    self.tech_stack[host] = rec.get("tech", [])
                    ip = extract_resolved_ip(rec)
                    if host and ip:
                        self.resolved_ips[host] = ip
                except json.JSONDecodeError:
                    continue

        self.live_targets = live
        self.stats.live_targets = len(live)
        (self.workdir / "live_targets.json").write_text(json.dumps(live, indent=2))

        # WhatWeb as a secondary/backup fingerprinting pass — best-effort,
        # only runs against hosts httpx already confirmed live to save time.
        if live:
            urls_file = self.raw_dir / "live_urls.txt"
            urls_file.write_text(
                "\n".join(sorted({rec.get("url", "") for rec in live if rec.get("url")}))
            )
            await self._run_tool(
                "whatweb",
                ["whatweb", "--input-file", str(urls_file), "--log-json",
                 str(self.raw_dir / "whatweb.json"), "-q"],
            )

        # Categorize by reachability/status: 403s go to a manual-review
        # bucket, DNS/timeout failures are dropped from actionable data
        # but kept on disk for audit.
        categorized = categorize_http_results(live)
        self.active_targets = categorized["active"]
        self.forbidden_403 = categorized["forbidden_403"]
        self.unreachable_targets = categorized["unreachable"]
        self.stats.forbidden_403_found = len(self.forbidden_403)

        (self.workdir / "active_targets.json").write_text(json.dumps(self.active_targets, indent=2))
        (self.workdir / "forbidden_403.json").write_text(json.dumps(self.forbidden_403, indent=2))
        if self.unreachable_targets:
            (self.workdir / "unreachable_targets.json").write_text(
                json.dumps(self.unreachable_targets, indent=2)
            )

        # Merge httpx's inline tech-detect with WhatWeb (and Wappalyzer, if
        # a raw/wappalyzer.json dump exists) into one clean mapping.
        self.tech_stack = merge_tech_stack(
            self.tech_stack,
            whatweb_path=self.raw_dir / "whatweb.json",
            wappalyzer_path=self.raw_dir / "wappalyzer.json",
        )
        (self.workdir / "tech_stack.json").write_text(json.dumps(self.tech_stack, indent=2))

        status = "ok" if httpx_result.ok or live else "warn"
        await self._emit(
            "probing", status,
            f"{len(live)} live targets ({len(self.forbidden_403)} 403s, "
            f"{len(self.unreachable_targets)} unreachable)",
        )

    async def stage3_url_scraping(self) -> None:
        """Gau + Waybackurls -> historical endpoints, params, JS files."""
        if not self.subdomains:
            await self._emit("urls", "warn", "No subdomains to scrape, skipping")
            return

        await self._emit("urls", "running", "Scraping archived URLs...")

        gau_out = self.raw_dir / "gau.txt"
        wayback_out = self.raw_dir / "waybackurls.txt"

        results = await asyncio.gather(
            self._run_tool(
                "gau", ["gau", "--subs", self.domain], output_file=gau_out,
            ),
            self._run_tool(
                "waybackurls", ["waybackurls", self.domain], output_file=wayback_out,
            ),
        )

        merged: set[str] = set()
        for fpath in (gau_out, wayback_out):
            if fpath.exists():
                for line in fpath.read_text(errors="replace").splitlines():
                    line = line.strip()
                    if line:
                        merged.add(line)

        self.urls = merged
        self.stats.urls_found = len(merged)
        (self.workdir / "all_urls.txt").write_text("\n".join(sorted(merged)))

        # Split out JS files specifically — useful for later manual review
        # or JS-focused nuclei templates.
        js_urls = sorted(u for u in merged if u.split("?")[0].endswith(".js"))
        (self.workdir / "js_files.txt").write_text("\n".join(js_urls))

        # Flag URLs whose query params look like user identifiers, tokens,
        # auth secrets, or session IDs — worth a manual look for IDOR/leak
        # potential. Classification only, no requests are made.
        self.sensitive_urls = filter_sensitive_urls(merged)
        sensitive_count = sum(len(v) for v in self.sensitive_urls.values())
        self.stats.sensitive_urls_found = sensitive_count
        (self.workdir / "sensitive_urls.json").write_text(json.dumps(self.sensitive_urls, indent=2))

        ok_count = sum(1 for r in results if r.ok)
        status = "ok" if ok_count > 0 else "warn"
        await self._emit(
            "urls", status,
            f"{len(merged)} unique URLs collected ({len(js_urls)} JS files, "
            f"{sensitive_count} with sensitive params)",
        )

    async def stage4_visual_recon(self) -> None:
        """Gowitness -> screenshots of every live subdomain."""
        if not self.live_targets:
            await self._emit("screenshots", "warn", "No live targets to screenshot, skipping")
            return

        await self._emit("screenshots", "running", "Capturing screenshots...")

        urls_file = self.workdir / "live_urls_for_screenshots.txt"
        urls_file.write_text(
            "\n".join(sorted({rec.get("url", "") for rec in self.live_targets if rec.get("url")}))
        )

        shots_dir = self.workdir / "screenshots"
        shots_dir.mkdir(exist_ok=True)

        # gowitness v3 rewrote its CLI entirely: screenshotting now lives
        # under the "scan" subcommand, the screenshot-path flag is -s (not
        # -P), and the default output format is jpeg (not png) — all three
        # differ from the old v2 syntax.
        result = await self._run_tool(
            "gowitness",
            ["gowitness", "scan", "file", "-f", str(urls_file),
             "--chrome-path", "/usr/bin/chromium",
             "-s", str(shots_dir),
             "--screenshot-format", "png"],
        )

        shot_count = len(list(shots_dir.glob("*.png")))
        self.stats.screenshots_taken = shot_count

        status = "ok" if shot_count > 0 else "warn"
        await self._emit("screenshots", status, f"{shot_count} screenshots captured")

    async def stage5_bgp_asn_lookup(self) -> None:
        """
        Informational-only enrichment: RDAP lookups (ASN, CIDR, org
        name) for every unique IP behind a live target, plus a
        best-effort Wikidata lookup for parent/subsidiary organizations
        of whatever org names those RDAP lookups turn up. Every network
        call here targets a public registry/API about an IP or org name
        already known from Stage 2 — never the scan target itself.
        Nothing discovered here is fed into `self.subdomains` or scanned
        automatically: it's a lead for a human to follow up on with a
        separately-authorized engagement, not something this run pivots
        into (Stage 6/7 stay bounded to Stage 2's confirmed live-host
        IPs for exactly this reason — see their docstrings).
        """
        unique_ips = sorted(set(self.resolved_ips.values()))
        if not unique_ips:
            await self._emit("bgp_asn", "warn", "No resolved IPs to look up, skipping")
            return

        await self._emit("bgp_asn", "running", f"Looking up ASN/org context for {len(unique_ips)} IPs...")

        sem = asyncio.Semaphore(8)

        async def _lookup(ip: str) -> tuple[str, Optional[dict]]:
            async with sem:
                return ip, await asyncio.to_thread(lookup_org_context, ip)

        results = await asyncio.gather(*(_lookup(ip) for ip in unique_ips))
        self.asn_info = {ip: info for ip, info in results if info}
        (self.workdir / "asn_info.json").write_text(json.dumps(self.asn_info, indent=2))
        self.stats.asns_found = len({info["asn"] for info in self.asn_info.values() if info.get("asn")})

        # Best-effort acquisition/subsidiary lookup, one call per unique
        # org name RDAP turned up — kept small since most domains
        # resolve to only a handful of distinct orgs (hosting/CDN plus
        # the target itself, at most).
        org_names = sorted({info["org"] for info in self.asn_info.values() if info.get("org")})[:5]
        related: list[dict] = []
        for org_name in org_names:
            found = await asyncio.to_thread(lookup_related_orgs, org_name)
            for entry in found:
                entry["source_org"] = org_name
            related.extend(found)
        self.related_organizations = related
        self.stats.related_organizations_found = len(related)
        (self.workdir / "related_organizations.json").write_text(json.dumps(related, indent=2))

        status = "ok" if self.asn_info else "warn"
        await self._emit(
            "bgp_asn", status,
            f"{len(self.asn_info)}/{len(unique_ips)} IPs resolved to {self.stats.asns_found} ASNs, "
            f"{len(related)} related orgs found",
        )

    async def stage6_port_scanning(self) -> None:
        """
        Port discovery scoped to the exact IPs behind Stage 2's
        confirmed live targets — never a CIDR/ASN sweep (see Stage 5's
        docstring for why: shared-hosting ASNs would otherwise pull in
        thousands of unrelated IPs). naabu does a fast top-1000 SYN
        sweep first; nmap then does version detection (-sV) scoped to
        the union of ports naabu found open across all hosts, which is
        far faster than nmap re-probing 1000 ports fresh on every host.
        If naabu is unavailable or finds nothing, nmap runs the full
        -top-ports 1000 sweep itself as a fallback. Both tools' default
        scan mode needs CAP_NET_RAW (see README) — a permission failure
        here is caught by `_run_tool`'s normal best-effort handling like
        any other tool failure, not special-cased.
        """
        unique_ips = sorted(set(self.resolved_ips.values()))
        if not unique_ips:
            await self._emit("port_scan", "warn", "No resolved IPs to scan, skipping")
            return

        await self._emit("port_scan", "running", f"Scanning ports on {len(unique_ips)} hosts...")

        targets_file = self.raw_dir / "port_scan_targets.txt"
        targets_file.write_text("\n".join(unique_ips))

        naabu_out = self.raw_dir / "naabu.jsonl"
        naabu_result = await self._run_tool(
            "naabu",
            ["naabu", "-list", str(targets_file), "-top-ports", "1000",
             "-json", "-o", str(naabu_out), "-silent"],
        )

        naabu_ports: set[int] = set()
        if naabu_out.exists():
            for line in naabu_out.read_text(errors="replace").splitlines():
                try:
                    rec = json.loads(line)
                    port = rec.get("port")
                    if isinstance(port, int):
                        naabu_ports.add(port)
                except json.JSONDecodeError:
                    continue

        nmap_out_base = self.raw_dir / "nmap_ports"
        if naabu_result.ok and naabu_ports:
            port_list = ",".join(str(p) for p in sorted(naabu_ports))
            await self._log(f"[INFO] naabu found {len(naabu_ports)} distinct open ports — scoping nmap to those")
            await self._run_tool(
                "nmap",
                ["nmap", "-iL", str(targets_file), "-p", port_list,
                 "-sV", "--open", "-T4", "-oA", str(nmap_out_base)],
            )
        else:
            await self._log("[INFO] naabu unavailable or found nothing — falling back to nmap -top-ports 1000")
            await self._run_tool(
                "nmap",
                ["nmap", "-iL", str(targets_file), "-top-ports", "1000",
                 "-sV", "--open", "-T4", "-oA", str(nmap_out_base)],
            )

        self.open_ports = parse_nmap_xml(Path(f"{nmap_out_base}.xml"))
        lines = [f"{ip}:{port}" for ip, ports in sorted(self.open_ports.items()) for port in ports]
        (self.workdir / "open_ports.txt").write_text("\n".join(lines))

        self.stats.hosts_with_open_ports = len(self.open_ports)
        self.stats.open_ports_found = sum(len(v) for v in self.open_ports.values())

        status = "ok" if self.open_ports else "warn"
        await self._emit(
            "port_scan", status,
            f"{self.stats.open_ports_found} open ports across {self.stats.hosts_with_open_ports} hosts",
        )

    async def stage7_cert_recon(self) -> None:
        """
        Certificate SAN/CN scraping via tlsx, scoped to Stage 2's live
        hosts (their open TLS-looking ports from Stage 6, falling back
        to each host's own :443 if Stage 6 found nothing for it — so
        cert recon still works in a minimal run where naabu/nmap aren't
        available). Discovered SAN/CN hostnames are filtered to the same
        apex domain before being folded into `self.subdomains` — a
        cert's SAN list can legitimately list unrelated customer domains
        on shared/CDN certificates, and those must never be silently
        pulled into scope. In-scope new hostnames get one incremental
        httpx probe (not the full pipeline) so they appear in
        `live_targets.json`/`tech_stack.json` for *this* run, which lets
        Stages 8-10 (running right after) pick them up automatically —
        full gau/waybackurls treatment of a newly discovered host is
        deliberately left for a follow-up run, same philosophy as deep
        mode being an explicit second pass rather than automatic.
        """
        if not self.live_targets:
            await self._emit("cert_recon", "warn", "No live targets for cert recon, skipping")
            return

        await self._emit("cert_recon", "running", "Scraping TLS certificates for SAN/CN hostnames...")

        cert_targets: set[str] = set()
        for rec in self.live_targets:
            host = rec.get("input") or rec.get("url", "")
            ip = self.resolved_ips.get(host)
            if not ip:
                continue
            ports = self.open_ports.get(ip) or [443]
            for port in ports:
                cert_targets.add(f"{ip}:{port}")

        if not cert_targets:
            await self._emit("cert_recon", "warn", "No IP:port targets available for cert recon, skipping")
            return

        targets_file = self.raw_dir / "cert_targets.txt"
        targets_file.write_text("\n".join(sorted(cert_targets)))

        tlsx_out = self.raw_dir / "tlsx.jsonl"
        await self._run_tool(
            "tlsx",
            ["tlsx", "-list", str(targets_file), "-san", "-cn",
             "-json", "-silent", "-o", str(tlsx_out)],
        )

        findings: list[dict] = []
        new_hostnames: set[str] = set()
        if tlsx_out.exists():
            for line in tlsx_out.read_text(errors="replace").splitlines():
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                cn = rec.get("subject_cn", "")
                sans = rec.get("subject_an") or []
                findings.append({"host": rec.get("host", ""), "port": rec.get("port", ""), "cn": cn, "sans": sans})
                for name in [cn, *sans]:
                    name = (name or "").strip().lower()
                    if name and self.domain in name and name not in self.subdomains:
                        new_hostnames.add(name)

        self.cert_findings = findings
        (self.workdir / "cert_findings.json").write_text(json.dumps(findings, indent=2))

        if new_hostnames:
            self.subdomains |= new_hostnames
            (self.workdir / "subdomains.txt").write_text("\n".join(sorted(self.subdomains)))

            new_hosts_file = self.raw_dir / "cert_new_hosts.txt"
            new_hosts_file.write_text("\n".join(sorted(new_hostnames)))
            incremental_out = self.raw_dir / "httpx_cert_incremental.jsonl"
            await self._run_tool(
                "httpx",
                ["httpx", "-l", str(new_hosts_file), "-json", "-status-code",
                 "-tech-detect", "-title", "-ip", "-silent", "-o", str(incremental_out)],
            )
            if incremental_out.exists():
                for line in incremental_out.read_text(errors="replace").splitlines():
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    self.live_targets.append(rec)
                    host = rec.get("input") or rec.get("url", "")
                    self.tech_stack[host] = rec.get("tech", [])
                    ip = extract_resolved_ip(rec)
                    if host and ip:
                        self.resolved_ips[host] = ip
                (self.workdir / "live_targets.json").write_text(json.dumps(self.live_targets, indent=2))
                (self.workdir / "tech_stack.json").write_text(json.dumps(self.tech_stack, indent=2))
                self.stats.live_targets = len(self.live_targets)

        self.stats.cert_new_subdomains_found = len(new_hostnames)
        status = "ok" if findings else "warn"
        await self._emit(
            "cert_recon", status,
            f"{len(findings)} certs inspected, {len(new_hostnames)} new in-scope subdomains discovered",
        )

    async def stage8_vulnerability_scan(self) -> None:
        """
        Nuclei, targeted using the tech stack fingerprinted in Stage 2.
        Falls back to a conservative default template set if no tech
        stack data is available.
        """
        if not self.live_targets:
            await self._emit("vulnscan", "warn", "No live targets to scan, skipping")
            return

        await self._emit("vulnscan", "running", "Running vulnerability scan...")

        targets_file = self.workdir / "nuclei_targets.txt"
        targets_file.write_text(
            "\n".join(sorted({rec.get("url", "") for rec in self.live_targets if rec.get("url")}))
        )

        # Build a tag list from fingerprinted tech so nuclei only runs
        # relevant templates instead of the entire template library.
        all_tech = {t.lower() for techs in self.tech_stack.values() for t in techs}
        tag_map = {
            "wordpress": "wordpress", "apache": "apache", "nginx": "nginx",
            "php": "php", "iis": "iis", "jquery": "jquery", "react": "react",
            "laravel": "laravel", "django": "django", "tomcat": "tomcat",
        }
        tags = sorted({tag for key, tag in tag_map.items() if key in all_tech})

        cmd = [
            "nuclei", "-l", str(targets_file),
            "-severity", "low,medium,high,critical",
            "-jsonl", "-o", str(self.raw_dir / "nuclei.jsonl"),
            "-silent",
        ]
        if tags:
            cmd += ["-tags", ",".join(tags)]
            await self._log(f"[INFO] Scoping nuclei to tags: {','.join(tags)}")
        else:
            await self._log("[INFO] No tech fingerprints matched — running default template set")

        result = await self._run_tool("nuclei", cmd)

        findings = []
        nuclei_out = self.raw_dir / "nuclei.jsonl"
        if nuclei_out.exists():
            for line in nuclei_out.read_text(errors="replace").splitlines():
                try:
                    findings.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

        self.stats.vulnerabilities_found = len(findings)
        (self.workdir / "vulnerabilities.json").write_text(json.dumps(findings, indent=2))

        status = "ok" if result.ok or findings else "warn"
        await self._emit("vulnscan", status, f"{len(findings)} findings")

    async def _download_js_files(
        self,
        js_urls: list[str],
        dest_dir: Path,
        max_files: int = 40,
        max_bytes: int = 2_000_000,
        timeout_s: int = 15,
        concurrency: int = 8,
    ) -> list[Path]:
        """
        Cache a bounded subset of already-discovered JS asset URLs to
        local disk so retire.js has file content to scan (it does static
        analysis on bytes, not URLs). Each fetch is a single ordinary GET
        with no parameter mutation or retries — the same class of request
        httpx/whatweb/gowitness already make elsewhere in this pipeline,
        just bounded in count (`max_files`), size (`max_bytes`), and
        concurrency so it stays a light, one-shot pass.
        """
        dest_dir.mkdir(parents=True, exist_ok=True)
        sem = asyncio.Semaphore(concurrency)
        saved: list[Path] = []

        def _fetch(url: str, out_path: Path) -> Optional[Path]:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (recon-framework)"})
            try:
                with urllib.request.urlopen(req, timeout=timeout_s) as resp:
                    data = resp.read(max_bytes + 1)
            except Exception:
                return None
            if len(data) > max_bytes:
                return None
            out_path.write_bytes(data)
            return out_path

        async def _worker(url: str, idx: int) -> None:
            async with sem:
                out_path = dest_dir / f"{idx}.js"
                result = await asyncio.to_thread(_fetch, url, out_path)
                if result:
                    saved.append(result)

        await asyncio.gather(*(_worker(u, i) for i, u in enumerate(js_urls[:max_files])))
        return saved

    async def stage9_js_and_tech_analysis(self) -> None:
        """
        Static analysis pass over data already collected by earlier
        stages: retire.js scans cached copies of discovered JS files for
        known-vulnerable library signatures, and tech-stack versions
        parsed from whatweb/wappalyzer are checked against a local
        outdated-version database. Strictly passive: no fuzzing, no
        exploitation — just a bounded, one-shot GET per JS asset (see
        `_download_js_files`) followed by offline comparison.
        """
        await self._emit("tech_audit", "running", "Analyzing JS libraries and tech versions...")

        js_file_path = self.workdir / "js_files.txt"
        js_urls = [
            u for u in js_file_path.read_text(errors="replace").splitlines() if u.strip()
        ] if js_file_path.exists() else []

        js_findings: list[dict] = []
        if js_urls:
            cache_dir = self.raw_dir / "js_cache"
            cached = await self._download_js_files(js_urls, cache_dir)
            if cached:
                retire_out = self.raw_dir / "retire.json"
                await self._run_tool(
                    "retire",
                    ["retire", "--path", str(cache_dir), "--js",
                     "--outputformat", "json", "--outputpath", str(retire_out),
                     "--exitwith", "0", "--severity", "low"],
                )
                if retire_out.exists():
                    try:
                        report = json.loads(retire_out.read_text(errors="replace") or "{}")
                        js_findings = report.get("data", [])
                    except json.JSONDecodeError:
                        pass

        tech_versions = extract_tech_versions(
            whatweb_path=self.raw_dir / "whatweb.json",
            wappalyzer_path=self.raw_dir / "wappalyzer.json",
        )
        version_findings = audit_tech_versions(tech_versions, VULN_VERSION_DB)

        audit = {
            "domain": self.domain,
            "js_vulnerabilities": js_findings,
            "outdated_tech": version_findings,
        }
        (self.workdir / "tech_audit.json").write_text(json.dumps(audit, indent=2))

        self.stats.js_vulnerabilities_found = len(js_findings)
        self.stats.outdated_tech_found = len(version_findings)

        status = "ok" if (js_findings or version_findings or js_urls) else "warn"
        await self._emit(
            "tech_audit", status,
            f"{len(js_findings)} JS library issues, {len(version_findings)} outdated tech versions",
        )

    async def stage10_attack_surface_categorization(self) -> None:
        """
        Passive triage of URLs already collected by Stage 3 (gau +
        waybackurls) into likely-vulnerability-class buckets, across
        three independent axes: query-parameter name, URL path segment,
        and file extension — each catches URLs the other two miss (a
        param-only view misses a bare /admin/ with no query string; a
        path-only view misses ?redirect=). 100% local file processing —
        no network requests, no payload injection. A starting point for
        manual review, not a confirmed finding.
        """
        await self._emit("attack_surface", "running", "Categorizing URLs by parameter, path, and extension...")

        urls_path = self.workdir / "all_urls.txt"
        if self.urls:
            urls = self.urls
        elif urls_path.exists():
            urls = {u.strip() for u in urls_path.read_text(errors="replace").splitlines() if u.strip()}
        else:
            urls = set()

        out_dir = self.workdir / "categorized_urls"
        by_path_dir = out_dir / "by_path"
        by_ext_dir = out_dir / "by_extension"
        out_dir.mkdir(parents=True, exist_ok=True)
        by_path_dir.mkdir(parents=True, exist_ok=True)
        by_ext_dir.mkdir(parents=True, exist_ok=True)

        self.categorized_urls = categorize_urls_by_param(urls) if urls else {
            cat: [] for cat in ATTACK_SURFACE_PATTERNS
        }
        self.categorized_urls_by_path = categorize_urls_by_path(urls) if urls else {
            cat: [] for cat in PATH_SURFACE_PATTERNS
        }
        self.categorized_urls_by_extension = categorize_urls_by_extension(urls) if urls else {
            cat: [] for cat in EXTENSION_SURFACE_PATTERNS
        }

        for category, matched in self.categorized_urls.items():
            (out_dir / f"{category}.txt").write_text("\n".join(matched))
        for category, matched in self.categorized_urls_by_path.items():
            (by_path_dir / f"{category}.txt").write_text("\n".join(matched))
        for category, matched in self.categorized_urls_by_extension.items():
            (by_ext_dir / f"{category}.txt").write_text("\n".join(matched))

        total = sum(len(v) for v in self.categorized_urls.values())
        total_path = sum(len(v) for v in self.categorized_urls_by_path.values())
        total_ext = sum(len(v) for v in self.categorized_urls_by_extension.values())
        self.stats.attack_surface_categorized = total
        self.stats.attack_surface_by_path_categorized = total_path
        self.stats.attack_surface_by_extension_categorized = total_ext

        if not urls:
            await self._emit(
                "attack_surface", "warn",
                "No URLs available to categorize (all_urls.txt missing or empty)",
            )
            return

        status = "ok" if (total or total_path or total_ext) else "warn"
        await self._emit(
            "attack_surface", status,
            f"{total} by param, {total_path} by path, {total_ext} by extension",
        )

    # ---------------------------------------------------------- deep mode

    async def stage11_deep_js_api_intelligence(self) -> None:
        """
        Deep-mode only. Two passive passes over the JS files already
        cached to disk by Stage 9 (raw/js_cache/, downloaded once, bounded):
          - LinkFinder-style regex extraction of endpoint/path strings
            from each file's source text.
          - gitleaks in --no-git mode against that same local directory,
            to flag hardcoded credentials/tokens.
        Neither issues any new network request — both operate purely on
        bytes already on disk. Unreadable or empty files are skipped and
        recorded rather than raising, per-file, so one bad file can't
        drop the whole pass.
        """
        await self._emit("deep_js", "running", "Extracting JS endpoints and scanning for secrets...")

        self.deep_dir.mkdir(parents=True, exist_ok=True)
        cache_dir = self.raw_dir / "js_cache"
        js_files = sorted(cache_dir.glob("*.js")) if cache_dir.exists() else []

        endpoints: dict[str, list[str]] = {}
        skipped: list[str] = []
        for js_path in js_files:
            found = extract_js_endpoints(js_path)
            if found is None:
                skipped.append(js_path.name)
                continue
            if found:
                endpoints[js_path.name] = found

        self.js_endpoints = endpoints
        self.stats.js_files_skipped = len(skipped)
        self.stats.js_endpoints_found = sum(len(v) for v in endpoints.values())
        if skipped:
            self.stats.errors.append(
                f"[deep_js] skipped {len(skipped)} empty/unreadable JS file(s): {', '.join(skipped[:10])}"
                + (f" (+{len(skipped) - 10} more)" if len(skipped) > 10 else "")
            )
        (self.deep_dir / "js_endpoints.json").write_text(json.dumps(endpoints, indent=2))

        secrets_findings: list[dict] = []
        if js_files:
            gitleaks_out = self.raw_dir / "gitleaks.json"
            await self._run_tool(
                "gitleaks",
                ["gitleaks", "detect", "--no-git", "--source", str(cache_dir),
                 "--report-format", "json", "--report-path", str(gitleaks_out),
                 "--exit-code", "0"],
            )
            if gitleaks_out.exists():
                try:
                    secrets_findings = json.loads(gitleaks_out.read_text(errors="replace") or "[]")
                except json.JSONDecodeError:
                    secrets_findings = []

        self.secrets_findings = secrets_findings
        self.stats.secrets_found = len(secrets_findings)
        (self.deep_dir / "secrets_findings.json").write_text(json.dumps(secrets_findings, indent=2))

        status = "ok" if (endpoints or secrets_findings) else "warn"
        await self._emit(
            "deep_js", status,
            f"{self.stats.js_endpoints_found} endpoints, {self.stats.secrets_found} potential secrets, "
            f"{len(skipped)} JS files skipped",
        )

    async def stage12_deep_parameter_map(self) -> None:
        """
        Deep-mode only. Builds a full parameter-name -> [url,...]
        inventory from all_urls.txt (every distinct query parameter
        found across all collected URLs — not just the fixed
        sqli/xss/ssrf/sensitive buckets from Stage 10). Meant for manual
        review on a single priority target: parameters like
        ?debug=true, ?admin=false, or ?company_id=123 are exactly what
        fixed buckets and automated scanners miss.
        """
        await self._emit("deep_params", "running", "Building parameter inventory...")

        self.deep_dir.mkdir(parents=True, exist_ok=True)
        urls_path = self.workdir / "all_urls.txt"
        if self.urls:
            urls = self.urls
        elif urls_path.exists():
            urls = {u.strip() for u in urls_path.read_text(errors="replace").splitlines() if u.strip()}
        else:
            urls = set()

        self.parameter_inventory = build_parameter_inventory(urls)
        (self.deep_dir / "parameter_inventory.json").write_text(json.dumps(self.parameter_inventory, indent=2))

        self.stats.unique_params_found = len(self.parameter_inventory)
        status = "ok" if self.parameter_inventory else "warn"
        await self._emit(
            "deep_params", status,
            f"{self.stats.unique_params_found} unique parameter names inventoried",
        )

    # -------------------------------------------------------------- runner

    async def run_full_pipeline(self) -> ReconStats:
        """
        Runs the Discovery pipeline (stages 1-10) sequentially, with
        fault isolation between stages: if a stage raises unexpectedly
        (bug, not tool failure), it's logged and the pipeline still
        proceeds to the next stage using whatever data exists so far.

        Certificate recon (Stage 7) is deliberately placed before
        vulnscan/tech-audit/attack-surface (8-10) so that any new
        in-scope subdomains it discovers automatically flow through
        those stages too — they just read `self.live_targets` fresh, per
        this file's stages-are-pure-functions design (see module
        docstring), with no special-cased re-run needed.

        When `self.mode == "deep"`, two further Deep Analysis stages
        (11-12) run afterward — heavier, single-target passes (JS
        endpoint extraction, secret scanning, full parameter inventory)
        that aren't worth paying for on every wildcard domain in a
        fast/quick run.
        """
        stages = [
            ("subdomains", self.stage1_subdomain_discovery),
            ("probing", self.stage2_probing_fingerprinting),
            ("urls", self.stage3_url_scraping),
            ("screenshots", self.stage4_visual_recon),
            ("bgp_asn", self.stage5_bgp_asn_lookup),
            ("port_scan", self.stage6_port_scanning),
            ("cert_recon", self.stage7_cert_recon),
            ("vulnscan", self.stage8_vulnerability_scan),
            ("tech_audit", self.stage9_js_and_tech_analysis),
            ("attack_surface", self.stage10_attack_surface_categorization),
        ]
        if self.mode == "deep":
            stages += [
                ("deep_js", self.stage11_deep_js_api_intelligence),
                ("deep_params", self.stage12_deep_parameter_map),
            ]
        for name, fn in stages:
            try:
                await fn()
            except Exception as e:  # pragma: no cover - defensive isolation
                msg = f"Stage '{name}' crashed unexpectedly: {e}"
                self.stats.errors.append(msg)
                await self._emit(name, "error", msg)
                await self._log(f"[FATAL] {msg}")

        await self._emit("pipeline", "done", "Recon pipeline complete")
        self._write_summary()
        return self.stats

    def _write_summary(self) -> None:
        summary = {
            "domain": self.domain,
            "mode": self.mode,
            "subdomains_found": self.stats.subdomains_found,
            "live_targets": self.stats.live_targets,
            "forbidden_403_found": self.stats.forbidden_403_found,
            "urls_found": self.stats.urls_found,
            "sensitive_urls_found": self.stats.sensitive_urls_found,
            "screenshots_taken": self.stats.screenshots_taken,
            "vulnerabilities_found": self.stats.vulnerabilities_found,
            "js_vulnerabilities_found": self.stats.js_vulnerabilities_found,
            "outdated_tech_found": self.stats.outdated_tech_found,
            "attack_surface_categorized": self.stats.attack_surface_categorized,
            "attack_surface_by_path_categorized": self.stats.attack_surface_by_path_categorized,
            "attack_surface_by_extension_categorized": self.stats.attack_surface_by_extension_categorized,
            "asns_found": self.stats.asns_found,
            "related_organizations_found": self.stats.related_organizations_found,
            "hosts_with_open_ports": self.stats.hosts_with_open_ports,
            "open_ports_found": self.stats.open_ports_found,
            "cert_new_subdomains_found": self.stats.cert_new_subdomains_found,
            "categorized_urls": {cat: len(v) for cat, v in self.categorized_urls.items()},
            "categorized_urls_by_path": {cat: len(v) for cat, v in self.categorized_urls_by_path.items()},
            "categorized_urls_by_extension": {
                cat: len(v) for cat, v in self.categorized_urls_by_extension.items()
            },
            "errors": self.stats.errors,
        }
        if self.mode == "deep":
            summary["deep_analysis"] = {
                "js_endpoints_found": self.stats.js_endpoints_found,
                "js_files_skipped": self.stats.js_files_skipped,
                "secrets_found": self.stats.secrets_found,
                "unique_params_found": self.stats.unique_params_found,
            }
        (self.workdir / "summary.json").write_text(json.dumps(summary, indent=2))


async def run_deep_scan(
    target: str,
    output_root: Path,
    on_progress: Optional[ProgressCallback] = None,
    on_log: Optional[LogCallback] = None,
) -> ReconStats:
    """
    Convenience entry point for a deep-dive run against a single
    priority target: equivalent to `ReconEngine(target, output_root,
    mode="deep").run_full_pipeline()`, spelled out for callers (CLI,
    TUI, scripts) that want the deep-mode pipeline without constructing
    the engine themselves.
    """
    engine = ReconEngine(target, output_root, on_progress, on_log, mode="deep")
    return await engine.run_full_pipeline()


# ------------------------------------------------------------------------
# Standalone CLI fallback (no TUI) — useful for scripted/headless runs.
# ------------------------------------------------------------------------
async def _cli_main():
    import argparse

    parser = argparse.ArgumentParser(description="Run the recon pipeline headlessly.")
    parser.add_argument("domain", help="Target domain, e.g. example.com")
    parser.add_argument("--output", default="/output", help="Output root directory")
    parser.add_argument(
        "--mode", choices=ReconEngine.MODES, default="quick",
        help="'quick' runs stages 1-10; 'deep' adds JS/API intel, secret "
             "scanning, and a full parameter inventory (stages 11-12) — "
             "meant for a single priority target, not wildcard sweeps.",
    )
    args = parser.parse_args()

    async def on_progress(stage, status, message):
        print(f"[{status.upper():7}] {stage:12} {message}")

    async def on_log(line):
        print(f"    {line}")

    engine = ReconEngine(args.domain, Path(args.output), on_progress, on_log, mode=args.mode)
    stats = await engine.run_full_pipeline()
    print(json.dumps(stats.__dict__, indent=2, default=str))


if __name__ == "__main__":
    asyncio.run(_cli_main())
