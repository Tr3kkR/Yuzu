#!/usr/bin/env bash
# test_trusted_fork_purge.sh — contract net for trusted-fork-ci.yml's
# `purge-quarantine-cache` job body (#4471): after a trusted-fork run, every
# GitHub Actions cache entry the approved fork revision wrote into the run's
# quarantine scope must be deleted, and only that scope may ever be purged.
#
# WHY THIS EXISTS. The job cannot be exercised until the workflow reaches main,
# and its wiring test in scripts/ci/test_runner_health_check.py pins structure
# only (permissions, no checkout, `if: always()`, `needs:`). This executes the
# real step body against a stateful stub `gh` that behaves like the caches API.
#
# WHAT IT PINS:
#   wrong ref (main)          -> exit non-zero, ZERO API calls
#   empty scope               -> exit 0, "purged 0"
#   101 entries, two pages    -> every id deleted, exit 0
#   one DELETE fails          -> exit non-zero
#   an entry that never goes  -> exit non-zero with the residual ::error::
#
# Run:  bash tests/shell/test_trusted_fork_purge.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WF="$ROOT/.github/workflows/trusted-fork-ci.yml"
[ -f "$WF" ] || { echo "missing $WF" >&2; exit 2; }
command -v jq >/dev/null 2>&1 || { echo "  [skip] jq not installed (the step itself uses it)"; exit 0; }

TMP="$(mktemp -d "${TMPDIR:-/tmp}/yuzu-fork-purge.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
pass=0 fail=0
check() { if [ "$2" = "$3" ]; then printf '  [pass] %s\n' "$1"; pass=$((pass+1)); else printf '  [FAIL] %s\n         expected: %s\n         actual:   %s\n' "$1" "$2" "$3"; fail=$((fail+1)); fi; }

python3 "$ROOT/tests/shell/extract_run_block.py" "$WF" "$TMP/purge.sh" \
  --name "Delete every cache entry in this run's ref scope" || exit 2
grep -q 'actions/caches' "$TMP/purge.sh" || { echo "extracted body does not look like the purge step" >&2; exit 2; }

# Stateful stub: $STATE holds the remaining cache ids, one per line; $LOG every
# call; FAIL_ID makes that DELETE fail; STICKY_ID is never removed (residual).
mkdir -p "$TMP/bin"
cat > "$TMP/bin/gh" <<'STUB'
#!/usr/bin/env bash
echo "$*" >> "$LOG"
if [ "$1" = api ] && [ "$2" = -X ] && [ "$3" = GET ]; then
  ref=""; for a in "$@"; do case "$a" in ref=*) ref="${a#ref=}";; esac; done
  python3 - "$STATE" "$ref" <<'PY'
import json, sys
ids = [i for i in open(sys.argv[1]).read().split() if i][:100]
print(json.dumps({"actions_caches": [{"id": int(i), "ref": sys.argv[2]} for i in ids]}))
PY
  exit 0
fi
if [ "$1" = api ] && [ "$2" = -X ] && [ "$3" = DELETE ]; then
  id="${4##*/}"
  [ "$id" = "${FAIL_ID:-}" ] && { echo "HTTP 500" >&2; exit 1; }
  [ "$id" = "${STICKY_ID:-}" ] && exit 0
  grep -vx "$id" "$STATE" > "$STATE.n" || true; mv "$STATE.n" "$STATE"; exit 0
fi
echo "stub gh: unexpected invocation: $*" >&2; exit 99
STUB
chmod +x "$TMP/bin/gh"

run_purge() { # run_purge <ref> <n-ids>  (env FAIL_ID / STICKY_ID optional)
  : > "$TMP/state"; : > "$TMP/log"
  [ "$2" -gt 0 ] && python3 -c "import sys; print('\n'.join(str(i) for i in range(1, int(sys.argv[1]) + 1)))" "$2" > "$TMP/state"
  ( set +e
    export PATH="$TMP/bin:$PATH" REPOSITORY=Tr3kkR/Yuzu GH_TOKEN="" GITHUB_REF="$1" \
           STATE="$TMP/state" LOG="$TMP/log" FAIL_ID="${FAIL_ID:-}" STICKY_ID="${STICKY_ID:-}"
    bash "$TMP/purge.sh" >"$TMP/out" 2>"$TMP/err"; echo $? > "$TMP/rc" )
  rc=$(cat "$TMP/rc")
}
calls() { wc -l < "$TMP/log" | tr -d ' '; }
deletes() { grep -c DELETE "$TMP/log" || true; }
remaining() { wc -w < "$TMP/state" | tr -d ' '; }

echo "-- wrong ref: refused before any API call --"
run_purge refs/heads/main 3
check "main: exits non-zero"  "1" "$([ "$rc" != 0 ] && echo 1 || echo 0)"
check "main: zero API calls"  "0" "$(calls)"
run_purge refs/heads/dev 3
check "dev: exits non-zero"   "1" "$([ "$rc" != 0 ] && echo 1 || echo 0)"
check "dev: zero API calls"   "0" "$(calls)"

echo "-- empty quarantine scope --"
run_purge refs/heads/trusted-fork/pr-7 0
check "exits 0"               "0" "$rc"
check "reports purged 0"      "purged 0 cache entries from scope refs/heads/trusted-fork/pr-7" "$(cat "$TMP/out")"

echo "-- 101 entries across two pages: all deleted --"
run_purge refs/heads/trusted-fork/pr-7-3333333 101
check "exits 0"               "0"   "$rc"
check "101 DELETE calls"      "101" "$(deletes)"
check "nothing remains"       "0"   "$(remaining)"

echo "-- a DELETE failure propagates --"
FAIL_ID=2 run_purge refs/heads/trusted-fork/pr-7 3
check "exits non-zero"        "1" "$([ "$rc" != 0 ] && echo 1 || echo 0)"

echo "-- an entry that survives every pass is reported, not ignored --"
STICKY_ID=5 run_purge refs/heads/trusted-fork/pr-7 6
check "exits non-zero"        "1" "$([ "$rc" != 0 ] && echo 1 || echo 0)"
check "names the residual"    "1" "$(grep -c 'still present' "$TMP/out" || true)"

echo "  ---"
echo "  ${pass} passed, ${fail} failed"
[ "$fail" = 0 ]
