#!/usr/bin/env python3
"""filter-codeql-sarif.py — Drop CodeQL noise from SARIF before upload.

Replaces the original jq-based filter (still committed alongside as
``filter-codeql-sarif.sh`` for reference) because ``jq`` is not on
PATH in the MSYS2 environment used by the Windows self-hosted runner,
whereas Python is already required by the workflow's toolchain
assertion step.

WHY THIS EXISTS:
    CodeQL's ``paths`` / ``paths-ignore`` config keys do NOT reliably
    suppress C/C++ findings whose location is a transitively-included
    header. The C/C++ extractor follows every ``#include`` chain
    during the traced build; structural rules then fire on the AST of
    vendored/generated headers, and the post-analysis filter does not
    strip them. Full writeup:
      https://gist.github.com/Tr3kkR/73fbe826634f97e97ebb138f4c6b98d8

CONTRACT:
    Input  : a CodeQL SARIF v2.1.0 file written by
             github/codeql-action/analyze.
    Output : the same file in place, with results array filtered.
    Filter : drop a result iff EITHER
             (A) location is in vendored/generated path
                 AND rule has no security-severity (or it is null)
             OR
             (B) ruleId is ``cpp/unused-static-function``
                 AND location is under ``tests/``
                 — Catch2 TEST_CASE / SECTION / SCENARIO / GIVEN /
                 WHEN / THEN macros emit a static function whose
                 only "caller" is a runtime test-registry function-
                 pointer indirection that CodeQL cannot see across.
                 Uniformly false-positive on the project's Catch2
                 tests. Full writeup:
                   https://gist.github.com/Tr3kkR/1a31108d32e7d98dab2e30fc38e78311
    Keep   : every result with security-severity, regardless of path.
             Every first-party result, except condition (B) above.
             ``cpp/unused-static-function`` in ``agents/`` /
             ``server/`` / ``sdk/`` / ``proto/`` stays visible — only
             ``tests/`` is suppressed.

USAGE:
    filter-codeql-sarif.py <path-to-sarif-file>
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

# Vendored / generated path prefixes. Mirrors codeql-config.yml's
# paths-ignore plus the vcpkg buildtrees directory that ends up under
# `vcpkg/buildtrees/...` when ports are rebuilt from source.
_VENDORED_PREFIXES = (
    "vcpkg_installed/",
    "vcpkg/",
    "build-",
    "builddir",
    "_build/",
)
_GENERATED_PROTO_RE = re.compile(r"\.pb\.(cc|h)$")


def _is_vendored_or_generated(uri: str) -> bool:
    if not uri:
        return False
    if uri.startswith(_VENDORED_PREFIXES):
        return True
    if _GENERATED_PROTO_RE.search(uri):
        return True
    return False


def _is_catch2_unused_static_function(rule_id: str, uri: str) -> bool:
    return rule_id == "cpp/unused-static-function" and (uri or "").startswith(
        "tests/"
    )


def _result_uri(result: dict) -> str:
    locations = result.get("locations") or []
    if not locations:
        return ""
    physical = locations[0].get("physicalLocation") or {}
    artifact = physical.get("artifactLocation") or {}
    return artifact.get("uri") or ""


def _rule_has_security_severity(
    rule_index: int, rules: list[dict]
) -> bool:
    if rule_index is None or rule_index < 0 or rule_index >= len(rules):
        return False
    rule = rules[rule_index] or {}
    properties = rule.get("properties") or {}
    return properties.get("security-severity") is not None


def _filter_results(run: dict) -> int:
    """Filter run['results'] in place. Return number of dropped results."""
    rules = ((run.get("tool") or {}).get("driver") or {}).get("rules") or []
    original = run.get("results") or []
    kept: list[dict] = []
    for result in original:
        uri = _result_uri(result)
        rule_index = result.get("ruleIndex", -1)
        rule_id = result.get("ruleId") or ""
        # (A) vendored/generated AND no security-severity → drop
        if _is_vendored_or_generated(uri) and not _rule_has_security_severity(
            rule_index, rules
        ):
            continue
        # (B) Catch2 TEST_CASE false-positive → drop
        if _is_catch2_unused_static_function(rule_id, uri):
            continue
        kept.append(result)
    run["results"] = kept
    return len(original) - len(kept)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"usage: {argv[0]} <sarif-file>", file=sys.stderr)
        return 2
    path = Path(argv[1])
    if not path.is_file():
        print(f"error: SARIF file not found: {path}", file=sys.stderr)
        return 2

    with path.open("r", encoding="utf-8") as fh:
        sarif = json.load(fh)

    runs = sarif.get("runs") or []
    before = sum(len(r.get("results") or []) for r in runs)
    dropped = sum(_filter_results(r) for r in runs)
    after = before - dropped

    with path.open("w", encoding="utf-8") as fh:
        json.dump(sarif, fh)

    print(f"filter-codeql-sarif.py: {path}")
    print(f"  before:  {before} results")
    print(f"  after:   {after} results")
    print(
        f"  dropped: {dropped} (non-security in vendored/generated paths "
        f"+ Catch2 TEST_CASE noise in tests/)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
