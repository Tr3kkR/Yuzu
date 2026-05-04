#!/usr/bin/env bash
# filter-codeql-sarif.sh — Drop non-security CodeQL findings whose
# locations resolve into vendored or generated paths.
#
# WHY THIS EXISTS:
#   CodeQL's `paths` / `paths-ignore` config keys are documented to
#   filter alerts in the SARIF output, but for compiled C/C++ they do
#   NOT reliably suppress findings whose location is a transitively-
#   included header. The C/C++ extractor follows every `#include`
#   chain during the traced build; structural rules (cpp/commented-
#   out-code, cpp/array-in-interface, etc.) then fire on the AST of
#   vendored/generated headers, and the post-analysis filter does not
#   strip them.
#
#   Full writeup of the upstream limitation, the symptom (alert flood
#   on `vcpkg_installed/` and `build-*/`), how ccache normally masks
#   the issue, and the SARIF-post-processing pattern this script
#   implements:
#     https://gist.github.com/Tr3kkR/73fbe826634f97e97ebb138f4c6b98d8
#
#   Without this filter the Security tab fills with hundreds of
#   findings on `vcpkg_installed/`, `build-*/`, and generated proto
#   code that are not actionable in-tree. With it, the SARIF only
#   contains findings on first-party code OR security-severity findings
#   anywhere (including vendored — those are kept so we stay aware of
#   real exposure even when we cannot patch upstream).
#
# CONTRACT:
#   Input  : a CodeQL SARIF v2.1.0 file written by
#            github/codeql-action/analyze.
#   Output : the same file in place, with results array filtered.
#   Filter : drop a result iff EITHER
#            (A) location is in vendored/generated path
#                AND rule has no security-severity (or it's null/absent)
#            OR
#            (B) ruleId is `cpp/unused-static-function`
#                AND location is under `tests/`
#                — Catch2 TEST_CASE / SECTION / SCENARIO / GIVEN / WHEN /
#                THEN macros emit a static function whose only "caller"
#                is a runtime test-registry function-pointer indirection
#                that CodeQL cannot see across. Uniformly false-positive
#                for every Catch2 test in the project. Full writeup:
#                https://gist.github.com/Tr3kkR/1a31108d32e7d98dab2e30fc38e78311
#   Keep   : every result with security-severity, regardless of path
#            every result on first-party code, regardless of severity
#            (except condition B above)
#            cpp/unused-static-function in agents/server/sdk/proto stays
#            visible — only `tests/` is suppressed
#
# USAGE:
#   filter-codeql-sarif.sh <path-to-sarif-file>

set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 <sarif-file>" >&2
    exit 2
fi

SARIF="$1"

if [[ ! -f "$SARIF" ]]; then
    echo "error: SARIF file not found: $SARIF" >&2
    exit 2
fi

# Vendored and generated path prefixes. Any result whose primary
# location URI matches one of these is "in third-party / generated
# code" and gets stripped UNLESS the rule has a security-severity.
#
# Mirrors codeql-config.yml's paths-ignore plus the vcpkg buildtrees
# directory that ends up under `vcpkg/buildtrees/...` when ports are
# rebuilt from source.
read -r -d '' JQ_FILTER <<'JQ' || true
def is_vendored_or_generated(uri):
    (uri // "")
    | (
        startswith("vcpkg_installed/")
        or startswith("vcpkg/")
        or startswith("build-")
        or startswith("builddir")
        or startswith("_build/")
        or test("\\.pb\\.(cc|h)$")
      );

def has_security_severity(rule_index; rules):
    rules
    | (.[rule_index] // {})
    | .properties
    | (.["security-severity"] // null)
    | . != null;

def is_catch2_unused_static_function(rule_id; uri):
    rule_id == "cpp/unused-static-function"
    and ((uri // "") | startswith("tests/"));

# Walk every run; rebuild .results dropping (A) vendored/generated
# non-security findings and (B) Catch2 TEST_CASE false-positives.
.runs |= map(
    . as $run
    | .results = (
        .results // []
        | map(
            . as $result
            | (.locations[0].physicalLocation.artifactLocation.uri // "") as $uri
            | (.ruleIndex // -1) as $idx
            | (.ruleId // "") as $rid
            | if (is_vendored_or_generated($uri)
                  and ($idx < 0 or (has_security_severity($idx; $run.tool.driver.rules // []) | not)))
              then empty
              elif is_catch2_unused_static_function($rid; $uri)
              then empty
              else .
              end
          )
      )
)
JQ

before=$(jq '[.runs[].results[]] | length' "$SARIF")
filtered=$(mktemp)
trap 'rm -f "$filtered"' EXIT

jq "$JQ_FILTER" "$SARIF" > "$filtered"
mv "$filtered" "$SARIF"
trap - EXIT

after=$(jq '[.runs[].results[]] | length' "$SARIF")
dropped=$((before - after))

echo "filter-codeql-sarif.sh: ${SARIF}"
echo "  before:  ${before} results"
echo "  after:   ${after} results"
echo "  dropped: ${dropped} (non-security in vendored/generated paths + Catch2 TEST_CASE noise in tests/)"
