#!/usr/bin/env bash
# test_detect_code_change.sh — fixture tests for scripts/ci/detect-code-change.sh
#
# The classifier is the docs-only gate for ci.yml (issue #1978): it decides
# whether a PR skips the self-hosted build matrix. A silent regression (an
# ignore arm dropped, `*.md` accidentally matching nested paths, the truncation
# guard removed) would either block every docs PR again or, worse, let real
# code merge without the required build. This exercises the code/docs/mixed,
# root-vs-nested pattern semantics, the ignore set, and the 3000-file
# truncation guard hermetically — no network, no GitHub. It also exercises the
# named CI-infrastructure class against a temporary git repository, including
# the former false-green: an unresolvable diff base must select the canary.
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
expect false "adr + nested docs (docs/**)"        2 $'docs/adr/1005-headless.md\ndocs/adr-1005-execution-plan.md'
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
expect true  "invalid authoritative total"       nope $'docs/a.md'

# --- named CI-infrastructure class ---
# --- hermetic git-diff acquisition: match, proven empty, and failure ---
tmp_repo=$(mktemp -d "${TMPDIR:-/tmp}/yuzu-change-classifier.XXXXXX")
trap 'rm -rf "$tmp_repo"' EXIT
git_fixture() {
  GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
    git -C "$tmp_repo" "$@"
}
git_fixture init -q
git_fixture -c user.name=Yuzu -c user.email=yuzu@example.invalid \
  -c commit.gpgsign=false -c core.hooksPath=/dev/null \
  commit --allow-empty -qm base
base=$(git_fixture rev-parse HEAD)
mkdir -p "$tmp_repo/.github/workflows"
printf '%s\n' 'name: fixture' > "$tmp_repo/.github/workflows/fixture.yml"
git_fixture add .github/workflows/fixture.yml
git_fixture -c user.name=Yuzu -c user.email=yuzu@example.invalid \
  -c commit.gpgsign=false -c core.hooksPath=/dev/null commit -qm infra-change
infra_commit=$(git_fixture rev-parse HEAD)

mkdir -p "$tmp_repo/server"
printf '%s\n' '// fixture' > "$tmp_repo/server/fixture.cpp"
git_fixture add server/fixture.cpp
git_fixture -c user.name=Yuzu -c user.email=yuzu@example.invalid \
  -c commit.gpgsign=false -c core.hooksPath=/dev/null commit -qm non-ci-change
non_ci_commit=$(git_fixture rev-parse HEAD)

# Git's default rename display reports only the destination for a detected
# rename. Moving a workflow out of the owned tree must still expose its source
# path and select the canary.
mkdir -p "$tmp_repo/docs"
git_fixture mv .github/workflows/fixture.yml docs/fixture.yml
git_fixture -c user.name=Yuzu -c user.email=yuzu@example.invalid \
  -c commit.gpgsign=false -c core.hooksPath=/dev/null commit -qm rename-out
rename_commit=$(git_fixture rev-parse HEAD)

# A line-oriented classifier cannot prove the prefix of Git's C-quoted output
# for a control-character filename. It must run the canary fail-closed.
odd_path=$'docs/line\nbreak.md'
printf '%s\n' 'fixture' > "$tmp_repo/$odd_path"
git_fixture add -- "$odd_path"
git_fixture -c user.name=Yuzu -c user.email=yuzu@example.invalid \
  -c commit.gpgsign=false -c core.hooksPath=/dev/null commit -qm quoted-path
quoted_commit=$(git_fixture rev-parse HEAD)

expect_diff() {
  local want="$1" desc="$2" base_ref="$3" head_ref="$4"
  local got
  got=$(cd "$tmp_repo" && GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
    bash "$SCRIPT" --class ci-infrastructure --git-diff "$base_ref" "$head_ref")
  if [ "$got" = "$want" ]; then
    printf '  [pass] %s\n' "$desc"; pass=$((pass + 1))
  else
    printf '  [FAIL] %s (want %s, got %s)\n' "$desc" "$want" "$got"; fail=$((fail + 1))
  fi
}

expect_diff true  "git diff success: CI change selects canary" "$base" "$infra_commit"
expect_diff false "non-empty non-CI diff may skip canary"       "$infra_commit" "$non_ci_commit"
expect_diff true  "rename out of CI tree selects canary"        "$non_ci_commit" "$rename_commit"
expect_diff true  "quoted path runs canary fail-closed"          "$rename_commit" "$quoted_commit"
expect_diff false "git diff no-change: canary may skip"          HEAD HEAD
expect_diff true  "git diff failure: canary runs fail-closed"    missing-base HEAD

echo "----"
echo "detect-code-change: pass=$pass fail=$fail"
[ "$fail" -eq 0 ]
