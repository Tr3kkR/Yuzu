#!/usr/bin/env bash
# test_detect_code_change.sh — fixture tests for scripts/ci/detect-code-change.sh
#
# The classifier is the docs-only gate for ci.yml (issue #1978): it decides
# whether a PR skips the self-hosted build matrix. A silent regression (an
# ignore arm dropped, `*.md` accidentally matching nested paths, the truncation
# guard removed) would either block every docs PR again or, worse, let real
# code merge without the required build. This exercises the code/docs/mixed,
# root-vs-nested pattern semantics, the ignore set, and the 3000-file
# truncation guard hermetically — no network, no GitHub.
#
# Run:  bash tests/shell/test_detect_code_change.sh
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || { cd "$(dirname "$0")/../.." && pwd; })"
SCRIPT="$ROOT/scripts/ci/detect-code-change.sh"
[ -f "$SCRIPT" ] || { echo "missing $SCRIPT" >&2; exit 2; }

pass=0 fail=0
# expect <want true|false> <desc> <authoritative-total> <newline-separated files>
expect() {
  local want="$1" desc="$2" total="$3" files="$4"
  local got
  got=$(printf '%s' "$files" | bash "$SCRIPT" "$total")
  if [ "$got" = "$want" ]; then
    printf '  [pass] %s\n' "$desc"; pass=$((pass + 1))
  else
    printf '  [FAIL] %s (want %s, got %s)\n' "$desc" "$want" "$got"; fail=$((fail + 1))
  fi
}

# --- docs-only: skip the build ---
expect false "adr + nested docs (docs/**)"        2 $'docs/adr/0022-headless.md\ndocs/adr-0022-execution-plan.md'
expect false "root markdown README.md"            1 $'README.md'
expect false "root LICENSE"                        1 $'LICENSE'
expect false "root .gitignore"                     1 $'.gitignore'
expect false "runner-inventory ignore files"      2 $'.github/runner-inventory.json\n.github/workflows/runner-inventory-sentinel.yml'

# --- code-side: run the full matrix ---
expect true  "single C++ source"                  1 $'server/core/src/server.cpp'
expect true  "mixed docs + code"                  2 $'docs/x.md\nserver/a.cpp'
expect true  "workflow change (ci.yml itself)"    1 $'.github/workflows/ci.yml'

# --- root-anchored semantics (C3 / K1): nested != root ---
expect true  "nested markdown is code-side"       1 $'sdk/README.md'
expect true  "changelog fragment (nested .md)"    1 $'changelog.d/1978-fix.fixed.md'
expect true  "nested LICENSE is code-side"        1 $'gateway/_checkouts/grpcbox/LICENSE'

# --- more root-anchored / boundary cases (K3) ---
expect false "root LICENSE.md (root *.md, not README)" 1 $'LICENSE.md'
expect true  "docs + nested markdown mixed"       2 $'docs/guide.md\nsdk/README.md'

# --- fail-closed guards ---
expect true  "truncation guard: 3 seen of 4"      4 $'docs/a.md\ndocs/b.md\ndocs/c.md'
expect false "3000 docs files at cap boundary"    3000 "$(printf 'docs/f%d.md\n' $(seq 1 3000))"
expect true  "empty file list"                     0 ''

echo "----"
echo "detect-code-change: pass=$pass fail=$fail"
[ "$fail" -eq 0 ]
