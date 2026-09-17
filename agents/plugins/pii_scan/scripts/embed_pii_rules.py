#!/usr/bin/env python3
"""Build-time YAML->JSON->C++ embed for the pii_scan plugin's ruleset.

Mirrors server/core/scripts/embed_content.py's rationale exactly (PyYAML
is a hard build dependency already; embedding a build-time-converted JSON
blob avoids adding a C++ YAML parser dependency and keeps the air-gapped
install story whole — see that file's docstring).

content/pii-rules/*.yaml is authored in several different shapes because
each source domain reads more naturally that way for a human editor
(generic identifiers, ICAO passport MRZ line layouts, all-50-US-states
driver's licences, multi-section international driver's licences,
country-grouped national IDs). This script NORMALIZES every shape into
one flat JSON array of rule objects with a single consistent schema,
which is the only shape agents/plugins/pii_scan/src/pii_rules.hpp needs
to know how to parse — the per-source-file normalization logic lives
here, once, rather than as parallel special-casing in C++.

00-manifest.yaml is deliberately NOT embedded: it documents the checksum
ALGORITHMS (their exact math, sources, confidence) that
agents/plugins/pii_scan/src/pii_checksum.hpp implements as C++ functions
— the manifest is the human-readable spec justifying that code, not
runtime data. Only files 01-07 (the actual rule sets) are embedded.

Usage:
    embed_pii_rules.py <pii_rules_content_root> <output.cpp>
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

try:
    import yaml  # type: ignore[import-not-found]
except ImportError:
    print(
        "ERROR: embed_pii_rules.py: PyYAML is required to embed the "
        "pii_scan ruleset. Install with `pip install pyyaml` (Linux/macOS) "
        "or `pacman -S python-yaml` (MSYS2).",
        file=sys.stderr,
    )
    sys.exit(1)


DEFAULT_SEVERITY = "medium"
DEFAULT_CONFIDENCE_KEYWORDS: list[str] = []
DEFAULT_COMPLIANCE_TAGS: list[str] = []


def flat_rule(
    *,
    id_: str,
    display_name: str,
    jurisdiction: str | None,
    category: str,
    pattern: str | None,
    checksum: str | None,
    severity: str = DEFAULT_SEVERITY,
    compliance_tags: list[str] | None = None,
    confidence_keywords: list[str] | None = None,
    source_confidence: str = "MEDIUM",
    notes: str | None = None,
    known_test_values: list[str] | None = None,
    require_keyword: bool = False,
    source_file: str,
) -> dict | None:
    if not pattern:
        # Deliberately-unshipped entries (Puerto Rico DL, Nunavut DL, UK
        # driving licence check chars, etc.) carry no pattern — skip them
        # from the runtime rule set rather than emit an unmatchable rule.
        return None
    return {
        "id": id_,
        "displayName": display_name,
        "jurisdiction": jurisdiction,
        "category": category,
        "pattern": pattern,
        "checksum": checksum,
        "severity": severity,
        "complianceTags": compliance_tags or list(DEFAULT_COMPLIANCE_TAGS),
        "confidenceKeywords": confidence_keywords or list(DEFAULT_CONFIDENCE_KEYWORDS),
        "sourceConfidence": source_confidence,
        "notes": notes,
        "knownTestValues": known_test_values or [],
        "requireKeyword": require_keyword,
        "sourceFile": source_file,
    }


def normalize_generic(doc: dict, source_file: str) -> list[dict]:
    out = []
    for r in doc.get("rules", []) or []:
        rule = flat_rule(
            id_=r["id"],
            display_name=r.get("displayName", r["id"]),
            jurisdiction=None,
            category=r.get("category", "generic"),
            pattern=r.get("pattern"),
            checksum=r.get("checksum"),
            severity=r.get("severity", DEFAULT_SEVERITY),
            compliance_tags=r.get("complianceTags"),
            confidence_keywords=r.get("confidenceKeywords"),
            source_confidence=r.get("sourceConfidence", "MEDIUM"),
            notes=r.get("notes"),
            known_test_values=r.get("knownTestValues"),
            require_keyword=r.get("requireKeyword", False),
            source_file=source_file,
        )
        if rule:
            out.append(rule)
    return out


def normalize_passports(doc: dict, source_file: str) -> list[dict]:
    out = []
    for mrz in doc.get("mrzFormats", []) or []:
        pattern = mrz.get("pattern", {})
        base_id = mrz["id"]
        for line_name, line_pattern in pattern.items():
            if not line_pattern:
                continue
            # Only TD3's line2 gets a real composite checksum — see
            # pii_checksum.hpp mrz_td3_line2_valid(). Other MRZ lines are
            # structural candidate-detectors only.
            checksum = "icao_mrz_td3_line2" if (base_id == "passport.mrz.td3" and line_name == "line2") else None
            out.append(flat_rule(
                id_=f"{base_id}.{line_name}",
                display_name=f"{mrz['displayName']} ({line_name})",
                jurisdiction=None,
                category="passport_mrz",
                pattern=line_pattern,
                checksum=checksum,
                severity=mrz.get("severity", "critical"),
                compliance_tags=mrz.get("complianceTags"),
                confidence_keywords=["passport", "mrz"],
                source_confidence=mrz.get("sourceConfidence", "HIGH"),
                notes="Structural line-shape match; full multi-field composite check digit only validated for TD3 line2." if checksum is None else None,
                source_file=source_file,
            ) or {})
    out = [r for r in out if r]

    for nm in doc.get("nonMrzFormats", []) or []:
        country = nm["country"]
        rule = flat_rule(
            id_=f"passport.nonmrz.{country.lower()}",
            display_name=f"Passport Number — {country}",
            jurisdiction=country,
            category="passport",
            pattern=nm.get("pattern"),
            checksum=None,
            severity="high",
            compliance_tags=["GDPR", "CCPA"],
            confidence_keywords=["passport", "passport no", "passport number"],
            source_confidence=nm.get("sourceConfidence", "MEDIUM"),
            notes=nm.get("notes"),
            source_file=source_file,
        )
        if rule:
            out.append(rule)
    return out


def normalize_us_dl(doc: dict, source_file: str) -> list[dict]:
    out = []
    for r in doc.get("rules", []) or []:
        state = r["state"]
        name = r.get("name", state)
        common = dict(
            jurisdiction=f"US-{state}",
            category="drivers_license",
            severity=r.get("severity", "high"),
            compliance_tags=["GDPR", "CCPA"],
            confidence_keywords=["driver's license", "driver license", "dl number", "license number"],
            source_file=source_file,
        )
        primary = flat_rule(
            id_=f"us_dl.{state.lower()}",
            display_name=f"{name} Driver's Licence",
            pattern=r.get("pattern"),
            checksum=r.get("checksum"),
            source_confidence=r.get("sourceConfidence", "MEDIUM"),
            notes=r.get("notes"),
            **common,
        )
        if primary:
            out.append(primary)
        for legacy_key, checksum_key in (("legacyPattern", "legacyChecksum"),
                                          ("currentIssuePattern", "checksum"),
                                          ("looseLegacyPattern", None)):
            if legacy_key in r:
                legacy = flat_rule(
                    id_=f"us_dl.{state.lower()}.{legacy_key.lower()}",
                    display_name=f"{name} Driver's Licence ({legacy_key})",
                    pattern=r.get(legacy_key),
                    checksum=r.get(checksum_key) if checksum_key else None,
                    source_confidence=r.get("sourceConfidence", "MEDIUM"),
                    notes=r.get("notes"),
                    **common,
                )
                if legacy:
                    out.append(legacy)
    return out


def normalize_intl_dl(doc: dict, source_file: str) -> list[dict]:
    out = []
    common = dict(category="drivers_license", severity="high",
                   compliance_tags=["GDPR"],
                   confidence_keywords=["driver's licence", "driving licence", "driver license"],
                   source_file=source_file)

    for r in doc.get("canada", []) or []:
        prov = r["province"]
        rule = flat_rule(
            id_=f"ca_dl.{prov.lower()}",
            display_name=f"{r.get('name', prov)} Driver's Licence",
            jurisdiction=f"CA-{prov}",
            pattern=r.get("pattern"),
            checksum=r.get("checksum"),
            source_confidence=r.get("sourceConfidence", "MEDIUM"),
            notes=r.get("notes"),
            **common,
        )
        if rule:
            out.append(rule)

    for r in doc.get("unitedKingdom", []) or []:
        rule = flat_rule(
            id_=r["id"],
            display_name=r.get("displayName", r["id"]),
            jurisdiction="GB",
            pattern=r.get("pattern"),
            checksum=r.get("checksum"),
            source_confidence=r.get("sourceConfidence", "MEDIUM"),
            notes=r.get("notes"),
            **common,
        )
        if rule:
            out.append(rule)

    for r in doc.get("australia", []) or []:
        state = r.get("state")
        if not state:
            continue
        rule = flat_rule(
            id_=f"au_dl.{state.lower()}",
            display_name=f"{state} Driver's Licence",
            jurisdiction=f"AU-{state}",
            pattern=r.get("pattern"),
            checksum=r.get("checksum"),
            source_confidence=r.get("sourceConfidence", "MEDIUM"),
            notes=r.get("notes"),
            **common,
        )
        if rule:
            out.append(rule)
    return out


def normalize_national_ids(doc: dict, source_file: str) -> list[dict]:
    out = []
    for country_block in doc.get("countries", []) or []:
        country = country_block["country"]
        for r in country_block.get("rules", []) or []:
            rule = flat_rule(
                id_=r["id"],
                display_name=r.get("displayName", r["id"]),
                jurisdiction=country,
                category=r.get("category", "national_id"),
                pattern=r.get("pattern"),
                checksum=r.get("checksum"),
                severity=r.get("severity", "high"),
                compliance_tags=r.get("complianceTags"),
                confidence_keywords=r.get("confidenceKeywords"),
                source_confidence=r.get("sourceConfidence", "MEDIUM"),
                notes=r.get("notes"),
                source_file=source_file,
            )
            if rule:
                out.append(rule)
    return out


NORMALIZERS = {
    "01-generic.yaml": normalize_generic,
    "02-passports.yaml": normalize_passports,
    "03-drivers-licenses-us.yaml": normalize_us_dl,
    "04-drivers-licenses-intl.yaml": normalize_intl_dl,
    "05-national-ids-europe.yaml": normalize_national_ids,
    "06-national-ids-americas.yaml": normalize_national_ids,
    "07-national-ids-apac-mea.yaml": normalize_national_ids,
}


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: embed_pii_rules.py <pii_rules_content_root> <output.cpp>", file=sys.stderr)
        return 1
    root = Path(sys.argv[1])
    out_path = Path(sys.argv[2])

    if not root.is_dir():
        print(f"ERROR: embed_pii_rules.py: content root {root} does not exist.", file=sys.stderr)
        return 1

    all_rules: list[dict] = []
    seen_ids: set[str] = set()
    dup_ids: list[str] = []

    for filename, normalizer in NORMALIZERS.items():
        path = root / filename
        if not path.is_file():
            print(f"ERROR: embed_pii_rules.py: expected file not found: {path}", file=sys.stderr)
            return 1
        text = path.read_text(encoding="utf-8")
        try:
            doc = yaml.safe_load(text)
        except yaml.YAMLError as e:
            print(f"ERROR: embed_pii_rules.py: {path}: YAML parse error: {e}", file=sys.stderr)
            return 1
        rules = normalizer(doc, filename)
        for r in rules:
            if r["id"] in seen_ids:
                dup_ids.append(r["id"])
                continue
            seen_ids.add(r["id"])
            all_rules.append(r)

    if dup_ids:
        print(f"ERROR: embed_pii_rules.py: duplicate rule id(s): {sorted(set(dup_ids))}", file=sys.stderr)
        return 1

    if not all_rules:
        print("ERROR: embed_pii_rules.py: normalized zero rules — refusing to emit an empty bundle.",
              file=sys.stderr)
        return 1

    payload = json.dumps(all_rules, separators=(",", ":"))

    # Emit C++: one raw-string literal. MSVC caps a single string-literal
    # token at 16380 bytes (error C2026), so split into adjacent chunks —
    # the compiler concatenates them into one std::string transparently,
    # exactly as embed_content.py does for the same reason.
    DELIM = "PIIRULES"
    CHUNK = 12000
    if f"){DELIM}\"" in payload:
        print(f"ERROR: embed_pii_rules.py: payload contains the raw-string delimiter {DELIM}",
              file=sys.stderr)
        return 1

    parts = [payload[i:i + CHUNK] for i in range(0, len(payload), CHUNK)] or [""]
    literal = b"R\"" + DELIM.encode() + b"("
    literal_pieces = []
    for k, part in enumerate(parts):
        literal_pieces.append(
            b'R"' + DELIM.encode() + b"(" + part.encode("utf-8") + b")" + DELIM.encode() + b'"'
        )
    literal = b" ".join(literal_pieces)

    out = bytearray()
    out += f"// AUTO-GENERATED from {root.name}/ by embed_pii_rules.py — do not edit.\n".encode("utf-8")
    out += f"// Rules embedded: {len(all_rules)}.\n\n".encode("ascii")
    out += b"#include <string_view>\n\n"
    out += b"namespace yuzu::pii {\n\n"
    out += b"extern const std::string_view kEmbeddedPiiRulesJson = " + literal + b";\n\n"
    out += b"}  // namespace yuzu::pii\n"

    out_path.write_bytes(bytes(out))
    print(f"embed_pii_rules.py: wrote {out_path} ({len(all_rules)} rules)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
