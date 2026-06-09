#!/usr/bin/env python3
"""
Generate CVE rules from Open Source Vulnerabilities (OSV) database.

Queries the OSV API (https://api.osv.dev/v1/) for a curated list of
language-ecosystem packages and generates ecosystem-tagged CVE rules.

No authentication required. No rate limits.
"""

import json
import sys
import urllib.request
import urllib.error
import hashlib
from datetime import datetime, timezone
from pathlib import Path

OSV_BASE = "https://api.osv.dev/v1"
OSV_TIMEOUT = 30

# Tracked packages: (ecosystem, package_name) pairs
OSV_PACKAGES = [
    # npm (JavaScript)
    ("npm", "lodash"),
    ("npm", "axios"),
    ("npm", "express"),
    ("npm", "jsonwebtoken"),
    ("npm", "minimist"),
    ("npm", "semver"),
    ("npm", "braces"),
    ("npm", "ws"),
    ("npm", "node-fetch"),
    ("npm", "serialize-javascript"),
    ("npm", "moment"),
    ("npm", "underscore"),
    ("npm", "request"),
    ("npm", "debug"),
    # PyPI (Python)
    ("PyPI", "requests"),
    ("PyPI", "urllib3"),
    ("PyPI", "cryptography"),
    ("PyPI", "paramiko"),
    ("PyPI", "Pillow"),
    ("PyPI", "setuptools"),
    ("PyPI", "PyYAML"),
    ("PyPI", "Django"),
    ("PyPI", "Flask"),
    ("PyPI", "aiohttp"),
    ("PyPI", "Jinja2"),
    ("PyPI", "click"),
    # crates.io (Rust)
    ("crates.io", "openssl"),
    ("crates.io", "tokio"),
    ("crates.io", "hyper"),
    ("crates.io", "rustls"),
    ("crates.io", "regex"),
    # RubyGems (Ruby)
    ("RubyGems", "rails"),
    ("RubyGems", "rack"),
    ("RubyGems", "nokogiri"),
    ("RubyGems", "json"),
    # NuGet (.NET)
    ("NuGet", "Newtonsoft.Json"),
    ("NuGet", "log4net"),
    ("NuGet", "Microsoft.AspNetCore"),
    ("NuGet", "System.Net.Http"),
    # Maven (Java)
    ("Maven", "org.apache.logging.log4j:log4j-core"),
    ("Maven", "org.springframework:spring-webmvc"),
    ("Maven", "commons-collections:commons-collections"),
    # Debian (Linux)
    ("Debian", "openssl"),
    ("Debian", "curl"),
    ("Debian", "openssh-server"),
]

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def log_stderr(msg: str) -> None:
    """Write message to stderr."""
    print(msg, file=sys.stderr)


def osv_querybatch(packages: list[tuple[str, str]]) -> dict:
    """
    Query OSV for vulnerabilities affecting multiple packages.
    Returns the parsed response with index-aligned results.
    """
    body = {
        "queries": [
            {"package": {"ecosystem": eco, "name": name}} for eco, name in packages
        ]
    }
    req = urllib.request.Request(
        f"{OSV_BASE}/querybatch",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", "User-Agent": "yuzu-osv-gen/1.0"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=OSV_TIMEOUT) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        log_stderr(f"HTTP {e.code} querying OSV batch: {e.reason}")
        raise
    except Exception as e:
        log_stderr(f"Error querying OSV batch: {e}")
        raise


def osv_get_vuln(vuln_id: str) -> dict:
    """Fetch full vulnerability record from OSV by ID."""
    url = f"{OSV_BASE}/vulns/{vuln_id}"
    req = urllib.request.Request(
        url, headers={"User-Agent": "yuzu-osv-gen/1.0"}, method="GET"
    )
    try:
        with urllib.request.urlopen(req, timeout=OSV_TIMEOUT) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        log_stderr(f"HTTP {e.code} fetching {vuln_id}: {e.reason}")
        raise
    except Exception as e:
        log_stderr(f"Error fetching {vuln_id}: {e}")
        raise


def get_cve_id(vuln: dict) -> str:
    """Extract CVE ID from aliases, or fallback to OSV/GHSA ID."""
    for alias in vuln.get("aliases", []):
        if alias.startswith("CVE-"):
            return alias
    return vuln.get("id", "UNKNOWN")


def extract_severity(vuln: dict) -> str:
    """Extract severity from CVSS or database-specific field."""
    severity_list = vuln.get("severity", [])
    for s in severity_list:
        # Check database_specific.severity first (pre-computed label)
        db_sev = s.get("database_specific", {}).get("severity")
        if db_sev:
            return db_sev.upper()

    # Fallback to CVSS score parsing
    for s in severity_list:
        if s.get("type") == "CVSS_V3":
            score_str = s.get("score", "")
            # CVSS:3.1/AV:N/AC:L/... format; extract base score (first float)
            try:
                import re

                match = re.search(r"CVSS:[\d.]+/AV:[A-Z]/AC:[A-Z]/.*?/.*?/([0-9.]+)", score_str)
                if not match:
                    # Try simpler pattern: look for /something/ and extract score
                    parts = score_str.split("/")
                    if len(parts) > 0:
                        try:
                            # Base CVSS score is the first numeric value after CVSS version
                            score = float(parts[0].replace("CVSS:", "").replace("CVSS3.", ""))
                            if score >= 9.0:
                                return "CRITICAL"
                            if score >= 7.0:
                                return "HIGH"
                            if score >= 4.0:
                                return "MEDIUM"
                        except ValueError:
                            pass
            except Exception:
                pass

    return "MEDIUM"


def extract_version_bounds(affected: list[dict]) -> list[tuple[str, str, bool]]:
    """
    Extract (affected_below, fixed_in, affected_inclusive) version triples from OSV affected ranges.
    Returns list of tuples; empty list if no concrete bounds found.
    affected_inclusive is True when the boundary came from last_affected (boundary itself is vulnerable).
    """
    bounds = []
    for entry in affected:
        for rng in entry.get("ranges", []):
            if rng.get("type") not in ("SEMVER", "ECOSYSTEM"):
                continue

            events = rng.get("events", [])
            if not events:
                continue

            # Process events sequentially, pairing introduced with fixed/last_affected
            i = 0
            while i < len(events):
                ev = events[i]

                if "introduced" in ev:
                    introduced_ver = ev["introduced"]
                    # Look for the next fixed or last_affected event
                    j = i + 1
                    while j < len(events):
                        next_ev = events[j]
                        if "fixed" in next_ev:
                            # fixed = boundary not inclusive (versions < fixed are vulnerable)
                            bounds.append((next_ev["fixed"], next_ev["fixed"], False))
                            i = j
                            break
                        elif "last_affected" in next_ev:
                            # last_affected = boundary inclusive (versions <= last_affected are vulnerable)
                            bounds.append((next_ev["last_affected"], next_ev["last_affected"], True))
                            i = j
                            break
                        j += 1
                    else:
                        # No fixed/last_affected found after this introduced
                        # Still add it (vulnerability unfixed)
                        bounds.append((introduced_ver, "unfixed", False))
                        i = j - 1

                i += 1

    return bounds


def build_rules(min_severity: str = "HIGH") -> list[dict]:
    """
    Query OSV for tracked packages and build CVE rules.
    Filters by minimum severity.
    """
    rules = []
    seen_cves = set()
    severity_filter = SEVERITY_ORDER.get(min_severity, SEVERITY_ORDER["MEDIUM"])

    log_stderr(f"Querying OSV for {len(OSV_PACKAGES)} packages...")

    try:
        # Batch query all packages
        batch_response = osv_querybatch(OSV_PACKAGES)
        results = batch_response.get("results", [])

        # Map vuln IDs to their packages for later
        vuln_to_packages = {}
        for pkg_idx, (ecosystem, package_name) in enumerate(OSV_PACKAGES):
            if pkg_idx < len(results):
                for vuln in results[pkg_idx].get("vulns", []):
                    vuln_id = vuln["id"]
                    if vuln_id not in vuln_to_packages:
                        vuln_to_packages[vuln_id] = []
                    vuln_to_packages[vuln_id].append((ecosystem, package_name))

        log_stderr(f"Found {len(vuln_to_packages)} unique vulnerabilities, fetching details...")

        # Fetch full details for each vuln
        for vuln_id in sorted(vuln_to_packages.keys()):
            try:
                vuln = osv_get_vuln(vuln_id)
            except Exception:
                continue

            cve_id = get_cve_id(vuln)
            if cve_id in seen_cves:
                continue

            severity = extract_severity(vuln)
            severity_val = SEVERITY_ORDER.get(severity, SEVERITY_ORDER["MEDIUM"])
            if severity_val > severity_filter:
                continue  # Skip if below minimum severity

            # Get description
            description = vuln.get("summary", "")
            if not description:
                # Fallback to details
                details = vuln.get("details", "")
                if details:
                    description = details.split("\n")[0]
            description = description[:120].replace("\n", " ").strip()

            # Extract version bounds from vuln record
            affected_list = vuln.get("affected", [])
            if not affected_list:
                # No version info, use affected packages from batch query
                for ecosystem, package_name in vuln_to_packages.get(vuln_id, []):
                    rule = {
                        "cve_id": cve_id,
                        "product": package_name,
                        "affected_below": "0",  # Mark all affected; no specific bound
                        "fixed_in": "unfixed",
                        "severity": severity,
                        "description": description,
                        "ecosystem": ecosystem,
                    }
                    rules.append(rule)
                    seen_cves.add(cve_id)
                continue

            # Try to extract version bounds from affected entries
            # These may or may not have ecosystem/package info
            bounds = extract_version_bounds(affected_list)

            if bounds:
                # Use bounds from vuln record, but pair with batch-discovered packages
                for ecosystem, package_name in vuln_to_packages.get(vuln_id, []):
                    for affected_below, fixed_in, affected_inclusive in bounds:
                        rule = {
                            "cve_id": cve_id,
                            "product": package_name,
                            "affected_below": affected_below,
                            "fixed_in": fixed_in,
                            "severity": severity,
                            "description": description,
                            "ecosystem": ecosystem,
                            "affected_inclusive": affected_inclusive,
                        }
                        rules.append(rule)
                        seen_cves.add(cve_id)
            else:
                # No specific version bounds; mark all versions affected
                for ecosystem, package_name in vuln_to_packages.get(vuln_id, []):
                    rule = {
                        "cve_id": cve_id,
                        "product": package_name,
                        "affected_below": "0",
                        "fixed_in": "unfixed",
                        "severity": severity,
                        "description": description,
                        "ecosystem": ecosystem,
                        "affected_inclusive": False,
                    }
                    rules.append(rule)
                    seen_cves.add(cve_id)

    except Exception as e:
        log_stderr(f"Error building rules: {e}")
        return []

    return rules


def write_rules(rules: list[dict], output_path: str) -> None:
    """Write rules to JSON file with schema v2."""
    output = {
        "schema_version": 2,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "rule_count": len(rules),
        "rules": sorted(
            rules, key=lambda r: (SEVERITY_ORDER.get(r["severity"], 999), r["cve_id"])
        ),
    }

    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)
    log_stderr(f"Wrote {len(rules)} rules to {output_path}")

    # Write SHA-256 sidecar
    with open(output_path, "rb") as f:
        sha256_hash = hashlib.sha256(f.read()).hexdigest()
    sha_path = f"{output_path}.sha256"
    with open(sha_path, "w") as f:
        f.write(f"{sha256_hash}  {Path(output_path).name}\n")
    log_stderr(f"Wrote SHA-256 to {sha_path}")


def main() -> int:
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Generate CVE rules from OSV database"
    )
    parser.add_argument(
        "--output",
        default="osv_rules.json",
        help="Output JSON file (default: osv_rules.json)",
    )
    parser.add_argument(
        "--min-severity",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default="HIGH",
        help="Minimum severity to include (default: HIGH)",
    )
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Validate output file and exit",
    )

    args = parser.parse_args()

    if args.validate_only:
        # Validate existing output
        try:
            with open(args.output) as f:
                data = json.load(f)
            if data.get("schema_version") != 2:
                log_stderr(f"Error: schema_version must be 2, got {data.get('schema_version')}")
                return 1
            if not data.get("rules"):
                log_stderr("Error: no rules in file")
                return 1
            log_stderr(f"Valid: {data['rule_count']} rules, schema v{data['schema_version']}")
            return 0
        except Exception as e:
            log_stderr(f"Validation failed: {e}")
            return 1

    # Generate rules
    rules = build_rules(args.min_severity)
    if not rules:
        log_stderr("Warning: no rules generated")

    write_rules(rules, args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
