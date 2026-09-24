#!/usr/bin/env bash
# test_suite_selection_wiring.sh — contract net for the ci.yml step bodies that DECIDE and APPLY
# PR-time test selection (docs/ci-architecture.md, "PR-time test selection").
#
# No skip branch can run in the PR that introduces it (a PR touching .github/ or scripts/ is class
# `both`), so a swapped flag would first act on a LATER PR. This extracts the REAL step bodies from
# ci.yml (tests/shell/extract_run_block.py, as test_trusted_inputs_validate.sh does) and runs them:
# the preflight chain (changed-path list, docs-only gate, `affected`) on a real merge commit in a
# scratch repository, every leg's test step for every skip combination against stubs that record
# argv, and the linux-pr-gate step for every result combination. Lexical pins cover what a body
# cannot show: `if:` gates, env mappings, the matrix axis and excludes, check names, the leg-only
# step guards, the closure-guard steps and this test's own registration. No build, no network.
#
# Where it runs: ci.yml's preflight "Shell gate tests" step, on every PR (Windows never runs it).
# Run:  bash tests/shell/test_suite_selection_wiring.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CI_YML="$ROOT/.github/workflows/ci.yml"
EXTRACT="$ROOT/tests/shell/extract_run_block.py"
[ -f "$CI_YML" ] || { echo "missing $CI_YML" >&2; exit 2; }
BASH_BIN="$(command -v bash)"
GIT_BIN="$(command -v git)"

TMP="$(mktemp -d "${TMPDIR:-/tmp}/yuzu-suite-wiring.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
pass=0 fail=0
check() { # check <desc> <expected> <actual>
  if [ "$2" = "$3" ]; then printf '  [pass] %s\n' "$1"; pass=$((pass + 1))
  else printf '  [FAIL] %s\n         expected: %s\n         actual:   %s\n' "$1" "$2" "$3"; fail=$((fail + 1)); fi
}

# ── extract the real step bodies ─────────────────────────────────────────────
BODY="$TMP/body"; mkdir -p "$BODY"
MATRIX_SUBST=(--subst matrix.compiler=MATRIX_COMPILER --subst matrix.build_type=MATRIX_BUILD_TYPE)
extract() { python3 "$EXTRACT" "$CI_YML" "$@" || { echo "extraction failed: $*" >&2; exit 2; }; }
extract "$BODY/prpaths.sh"     --job preflight --name 'List the paths this pull request changes'
extract "$BODY/codegate.sh"    --job preflight --name 'Determine code-vs-docs change set (docs-only gate)'
extract "$BODY/affected.sh"    --job preflight --name 'Determine affected test suites (skip families this PR cannot reach)'
extract "$BODY/linux_nonpg.sh" --job linux   --name 'Test (non-pg suites)'   "${MATRIX_SUBST[@]}"
extract "$BODY/linux_pg.sh"    --job linux   --name 'Test (pg shards, full)' "${MATRIX_SUBST[@]}"
extract "$BODY/win_nonpg.sh"   --job windows --name 'Test (non-pg suites)'   --subst matrix.build_type=MATRIX_BUILD_TYPE
extract "$BODY/mac_test.sh"    --job macos   --name Test
extract "$BODY/gate.sh"        --job linux-pr-gate --name 'Require every Linux leg'

# ── stubs: record argv, run nothing ──────────────────────────────────────────
STUBS="$TMP/bin"; mkdir -p "$STUBS"
cat > "$STUBS/recorder" <<'EOF'
#!/usr/bin/env bash
# One line per call: "<name> <args>". STUB_RC_<name> sets the exit code (default 0).
printf '%s %s\n' "$(basename "$0")" "$*" >> "${STUB_LOG:?}"
rcvar="STUB_RC_$(basename "$0")"
exit "${!rcvar:-0}"
EOF
chmod +x "$STUBS/recorder"
for name in python3 python meson; do ln -s recorder "$STUBS/$name"; done

# A work tree the non-preflight bodies run in: with-test-slot.sh only execs what follows `--`.
W="$TMP/work"; mkdir -p "$W/scripts/ci"
cat > "$W/scripts/ci/with-test-slot.sh" <<'EOF'
#!/usr/bin/env bash
shift 2      # <slots> --
exec "$@"
EOF
LOG="$TMP/calls.log"

# run_body <cwd> <body> [VAR=value ...]  — the body runs under `bash -e` (Actions' default), with a
# scrubbed environment so the host cannot leak a value into it. Sets RC; the recorded calls are in $LOG.
run_body() {
  local cwd="$1" body="$2"; shift 2
  : > "$LOG"; : > "$TMP/out"; : > "$TMP/err"
  ( cd "$cwd" && env -i PATH="$STUBS:$(dirname "$BASH_BIN"):$(dirname "$GIT_BIN"):/usr/bin:/bin" \
      HOME="$TMP" GIT_CONFIG_NOSYSTEM=1 STUB_LOG="$LOG" \
      GITHUB_WORKSPACE="$W" MATRIX_COMPILER=gcc-15 MATRIX_BUILD_TYPE=debug "$@" \
      "$BASH_BIN" -e "$body" ) > "$TMP/out" 2> "$TMP/err"
  RC=$?
}
calls() { sed 's/  */ /g' "$LOG"; }

# ── Linux: non-pg suites ─────────────────────────────────────────────────────
LIN="python3 scripts/ci/flake-retry.py --builddir build-linux-gcc-15-debug -- --print-errorlogs --num-processes 2"
SERVER_BY_NAME="server unit tests shard A server unit tests shard B server unit tests shard C server unit tests shard D mcp bridge teardown allocation budget server pg shard partition invariant"
for sv in "" true; do for ag in "" true; do
  run_body "$W" "$BODY/linux_nonpg.sh" SKIP_SERVER_SUITES="$sv" SKIP_AGENT_SUITES="$ag"
  want="$LIN --suite docs --suite proto --suite gateway"
  [ "$ag" = true ] || want="$want --suite agent --suite tar"
  [ "$sv" = true ] || want="$want
$LIN $SERVER_BY_NAME"
  check "linux non-pg  skip_server='${sv:-}' skip_agent='${ag:-}'" "$want" "$(calls)"
  check "linux non-pg  exits 0" 0 "$RC"
done; done

# ── Linux: pg shards ─────────────────────────────────────────────────────────
PGB="build-linux-gcc-15-debug"
pg_case() { # pg_case <desc> <event> <pg_part> <expected suite>
  run_body "$W" "$BODY/linux_pg.sh" GITHUB_EVENT_NAME="$2" PG_PART="$3"
  check "linux pg      $1: exit 0" 0 "$RC"
  check "linux pg      $1: the selector is checked, then run" \
    "meson test -C $PGB --list --no-rebuild --suite $4
python3 scripts/ci/flake-retry.py --builddir $PGB -- --print-errorlogs --num-processes 2 --suite $4" "$(calls)"
}
pg_case "PR, pg-a leg -> the first half"  pull_request pg-a server-pg-a
pg_case "PR, pg-b leg -> the second half" pull_request pg-b server-pg-b
pg_case "push -> the whole suite"         push          pg-a server-pg
pg_case "dispatch -> the whole suite"     workflow_dispatch pg-a server-pg
run_body "$W" "$BODY/linux_pg.sh" GITHUB_EVENT_NAME=pull_request PG_PART=bogus
check "linux pg      an unknown pg_part on a PR fails before any test runs" "1|" "$RC|$(calls)"
run_body "$W" "$BODY/linux_pg.sh" GITHUB_EVENT_NAME=pull_request PG_PART=pg-b STUB_RC_meson=1
check "linux pg      a selector matching nothing fails and runs no test" \
  "1|meson test -C $PGB --list --no-rebuild --suite server-pg-b" "$RC|$(calls)"

# ── Windows: the cover guard and the real run ────────────────────────────────
WIN_UNIVERSE="agent docs gateway proto server-checks server-nonpg server-pg server-pg-smoke tar"
for sv in "" true; do for ag in "" true; do
  run_body "$W" "$BODY/win_nonpg.sh" SKIP_SERVER_SUITES="$sv" SKIP_AGENT_SUITES="$ag"
  suites="--suite docs --suite proto --suite gateway"; skipped=""; excluded=""
  if [ "$ag" = true ]; then skipped="$skipped --skipped-suite agent --skipped-suite tar"
  else suites="$suites --suite agent --suite tar"; fi
  if [ "$sv" = true ]; then
    skipped="$skipped --skipped-suite server-nonpg --skipped-suite server-checks --skipped-suite server-pg --skipped-suite server-pg-smoke"
  else
    suites="$suites --suite server-nonpg --suite server-checks"
    excluded=" --exclude-suite server-pg --exclude-suite server-pg-smoke"
  fi
  want="python scripts/ci/assert-suite-cover.py --builddir build-windows-debug $suites$skipped$excluded
python scripts/ci/flake-retry.py --builddir build-windows-debug -- --print-errorlogs --num-processes 4 $suites"
  d="windows non-pg skip_server='${sv:-}' skip_agent='${ag:-}'"
  check "$d: the exact argv of the guard and the run" "$want" "$(calls)"
  # structural: ONE suites array feeds both, and every suite is in exactly one bucket
  guard_suites="$(sed -n 1p "$LOG" | tr ' ' '\n' | awk '$0=="--suite"{getline; print}' | sort | tr '\n' ' ')"
  run_suites="$(sed -n 2p "$LOG" | tr ' ' '\n' | awk '$0=="--suite"{getline; print}' | sort | tr '\n' ' ')"
  check "$d: the guard and the run select the same suites" "$guard_suites" "$run_suites"
  buckets="$(sed -n 1p "$LOG" | tr ' ' '\n' | awk '$0=="--suite"||$0=="--skipped-suite"||$0=="--exclude-suite"{getline; print}' | sort | tr '\n' ' ')"
  check "$d: every suite is in exactly one bucket" "$(printf '%s\n' $WIN_UNIVERSE | sort | tr '\n' ' ')" "$buckets"
done; done

# ── macOS ────────────────────────────────────────────────────────────────────
MAC="python3 scripts/ci/flake-retry.py --builddir build-macos -- --print-errorlogs --timeout-multiplier 2"
for sv in "" true; do for ag in "" true; do
  run_body "$W" "$BODY/mac_test.sh" SKIP_SERVER_SUITES="$sv" SKIP_AGENT_SUITES="$ag"
  want="$MAC"
  [ "$ag" = true ] && want="$want --no-suite agent --no-suite tar"
  [ "$sv" = true ] && want="$want --no-suite server"
  check "macos         skip_server='${sv:-}' skip_agent='${ag:-}'" "$want" "$(calls)"
done; done

# ── linux-pr-gate: the required Linux context ────────────────────────────────
gate() { # gate <desc> <want rc> <preflight result> <code_changed> <linux result>
  run_body "$W" "$BODY/gate.sh" PREFLIGHT_RESULT="$3" CODE_CHANGED="$4" LINUX_RESULT="$5"
  check "linux gate    $1" "$2" "$RC"
}
gate "every leg green -> green"                    0 success true  success
gate "a failed leg -> red"                         1 success true  failure
gate "a cancelled leg -> red"                      1 success true  cancelled
gate "legs skipped on a code PR -> red"            1 success true  skipped
gate "docs-only PR, no leg ran -> green"           0 success false skipped
gate "preflight failed -> red, whatever else"      1 failure false skipped
gate "preflight failed, legs green -> still red"   1 failure true  success
gate "preflight cancelled -> red"                  1 cancelled true success
gate "no code_changed verdict -> red"              1 success ""    skipped

# ── preflight chain on a real merge commit ───────────────────────────────────
# The three real scripts in a scratch repository; each case merges a PR branch into `base` with
# --no-ff, the shape of GitHub's test merge commit (first parent base, second the PR head).
REPO="$TMP/repo"; RT="$TMP/rt"; mkdir -p "$REPO" "$RT"
fgit() { env -i PATH="$(dirname "$GIT_BIN"):/usr/bin:/bin" HOME="$TMP" GIT_CONFIG_NOSYSTEM=1 \
  GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@example.invalid GIT_COMMITTER_NAME=t \
  GIT_COMMITTER_EMAIL=t@example.invalid "$GIT_BIN" -C "$REPO" "$@"; }
fgit init -q -b base
mkdir -p "$REPO/scripts/ci" "$REPO/tests/unit/server" "$REPO/server/core/src" "$REPO/docs/user-manual" \
         "$REPO/.github"
for f in pr-changed-paths.sh detect-code-change.sh affected-suites.sh; do
  cp "$ROOT/scripts/ci/$f" "$REPO/scripts/ci/$f"
done
printf '# test registrations\n' > "$REPO/tests/meson.build"
printf '// a server test\n' > "$REPO/tests/unit/server/test_s.cpp"
printf '// an agent test that reads docs/user-manual/metrics.md\n' > "$REPO/tests/unit/test_a.cpp"
printf 'metrics\n' > "$REPO/docs/user-manual/metrics.md"
printf 'guide\n' > "$REPO/docs/guide.md"
printf 'int x;\n' > "$REPO/server/core/src/x.cpp"
printf '{}\n' > "$REPO/.github/runner-inventory.json"
fgit add -A && fgit commit -q -m base

# pr <name> <edit, run in the repository>: sets PR_HEAD and MERGE, and leaves MERGE checked out.
pr() {
  fgit checkout -q -b "pr-$1" base
  (cd "$REPO" && eval "$2")
  fgit add -A && fgit commit -q -m "pr $1"
  PR_HEAD="$(fgit rev-parse HEAD)"
  fgit checkout -q -b "m-$1" base
  fgit merge -q --no-ff -m "merge $1" "pr-$1"
  MERGE="$(fgit rev-parse HEAD)"
}
out() { sed -n "s/^$1=//p" "$2"; }
# chain <desc> <want code_changed> <want "skip_server skip_agent", or "-" when affected is skipped>
#       [run commit] [PR head]   — the last two default to the merge commit and the PR head
chain() {
  local desc="$1" want_cc="$2" want_skip="$3" sha="${4:-$MERGE}" head="${5:-$PR_HEAD}" ok cc n
  : > "$TMP/o_paths"; : > "$TMP/o_gate"; : > "$TMP/o_aff"
  run_body "$REPO" "$BODY/prpaths.sh" GITHUB_SHA="$sha" PR_HEAD_SHA="$head" RUNNER_TEMP="$RT" \
    GITHUB_OUTPUT="$TMP/o_paths"
  check "chain         $desc: the list step exits 0" 0 "$RC"
  ok="$(out ok "$TMP/o_paths")"
  run_body "$REPO" "$BODY/codegate.sh" GITHUB_EVENT_NAME=pull_request PATHS_OK="$ok" RUNNER_TEMP="$RT" \
    GITHUB_OUTPUT="$TMP/o_gate"
  check "chain         $desc: the docs-only gate exits 0" 0 "$RC"
  cc="$(out code_changed "$TMP/o_gate")"
  check "chain         $desc: code_changed" "$want_cc" "$cc"
  if [ "$cc" = true ]; then
    : > "$TMP/summary"
    run_body "$REPO" "$BODY/affected.sh" GITHUB_SHA="$sha" PATHS_OK="$ok" RUNNER_TEMP="$RT" \
      GITHUB_OUTPUT="$TMP/o_aff" GITHUB_STEP_SUMMARY="$TMP/summary"
    check "chain         $desc: affected exits 0" 0 "$RC"
    check "chain         $desc: skip_server skip_agent" "$want_skip" \
      "$(out skip_server_suites "$TMP/o_aff") $(out skip_agent_suites "$TMP/o_aff")"
    grep -q '^::notice title=Suite selection::' "$TMP/out" && n=1 || n=0
    check "chain         $desc: the verdict is recorded as a notice" 1 "$n"
  else
    check "chain         $desc: affected would not run" "$want_skip" "-"
  fi
  fgit checkout -q base
}
pr docs      'printf "more\n" >> docs/guide.md'
chain "a docs-only PR builds nothing"                          false "-"
pr inventory 'printf "{\"x\":1}\n" > .github/runner-inventory.json'
chain "the runner inventory is docs-only to both gates"        false "-"
pr metrics   'printf "more\n" >> docs/user-manual/metrics.md'
chain "a doc a test reads builds, and runs that family"        true  "true false"
pr gitattr   'printf "capability-registries/*.tsv text eol=crlf\n" > docs/.gitattributes'
chain "a .gitattributes under docs/ builds and runs both"      true  "false false"
pr rename    'mv server/core/src/x.cpp docs/x.md'
chain "a rename out of server/ into docs/ runs the server family" true "false true"
pr agent     'printf "// more\n" >> tests/unit/test_a.cpp'
chain "an agent test alone skips the server family"            true  "true false"
pr server    'printf "int y;\n" >> server/core/src/x.cpp'
chain "server code alone skips the agent family"               true  "false true"
# a path is data: printed with a prefix, so a file named like a workflow command cannot become one
pr inject    'printf "x\n" > "::warning title=injected::x"'
run_body "$REPO" "$BODY/prpaths.sh" GITHUB_SHA="$MERGE" PR_HEAD_SHA="$PR_HEAD" RUNNER_TEMP="$RT" GITHUB_OUTPUT="$TMP/o_paths"
check "chain         a path is never printed at the start of a line" "0|1" \
  "$(grep -c '^::warning title=injected' "$TMP/out")|$(grep -c '^- ::warning title=injected::x$' "$TMP/out")"
fgit checkout -q base
# binding failures: the list is refused, and both gates fail closed
pr bind      'printf "more\n" >> docs/guide.md'
chain "a PR head that is not the merge's second parent fails closed" true "false false" "$MERGE" "$(fgit rev-parse base)"
pr bind2     'printf "more\n" >> docs/guide.md'
chain "a run commit that is not HEAD fails closed"             true  "false false" "$(fgit rev-parse base)"
pr bind3     'printf "more\n" >> docs/guide.md'
fgit checkout -q pr-bind3                        # HEAD is the PR head itself: one parent
MERGE="$(fgit rev-parse HEAD)"
chain "a HEAD that is not a merge commit fails closed"         true  "false false"
: > "$TMP/o_paths"
run_body "$REPO" "$BODY/prpaths.sh" GITHUB_SHA="" PR_HEAD_SHA="" RUNNER_TEMP="$RT" GITHUB_OUTPUT="$TMP/o_paths"
check "chain         a missing PR head is refused: ok=false" "false" "$(out ok "$TMP/o_paths")"
grep -q '^::warning title=Changed paths unavailable::' "$TMP/out" && n=1 || n=0
check "chain         a refused list is announced as a warning" 1 "$n"
: > "$TMP/o_gate"
run_body "$REPO" "$BODY/codegate.sh" GITHUB_EVENT_NAME=push PATHS_OK="" RUNNER_TEMP="$RT" GITHUB_OUTPUT="$TMP/o_gate"
check "chain         a push always builds" "true" "$(out code_changed "$TMP/o_gate")"

# ── preflight `affected`: a classifier the step cannot trust ─────────────────
printf 'docs/z.md\n' > "$RT/pr-changed-paths.txt"
aff_case() { # aff_case <desc> <cwd> <PATHS_OK> <want server> <want agent>
  : > "$TMP/o_aff"; : > "$TMP/summary"
  run_body "$2" "$BODY/affected.sh" GITHUB_SHA=0123 PATHS_OK="$3" RUNNER_TEMP="$RT" \
    GITHUB_OUTPUT="$TMP/o_aff" GITHUB_STEP_SUMMARY="$TMP/summary"
  check "preflight     $1: outputs" "skip_server_suites=$4|skip_agent_suites=$5" \
    "$(tr '\n' '|' < "$TMP/o_aff" | sed 's/|$//')"
  check "preflight     $1: exits 0 (a failure here must never block the workflow)" 0 "$RC"
  grep -q '^### Suite selection' "$TMP/summary" && s=1 || s=0
  check "preflight     $1: writes the step summary" 1 "$s"
}
aff_case "no list fails closed" "$ROOT" false false false
grep -q '^::warning title=Suite selection::' "$TMP/out" && n=1 || n=0
check "preflight     the fail-closed path is announced as a warning" 1 "$n"
mkdir -p "$TMP/w2/scripts/ci"
printf '#!/usr/bin/env bash\necho "skip_server=maybe"\necho "skip_agent=true"\n' > "$TMP/w2/scripts/ci/affected-suites.sh"
aff_case "garbled classifier output fails closed" "$TMP/w2" true false false
printf '#!/usr/bin/env bash\necho boom >&2\nexit 3\n' > "$TMP/w2/scripts/ci/affected-suites.sh"
aff_case "a classifier that exits non-zero fails closed" "$TMP/w2" true false false
printf '#!/usr/bin/env bash\necho "skip_server=true"\necho "skip_agent=true"\necho "extra"\n' > "$TMP/w2/scripts/ci/affected-suites.sh"
aff_case "a classifier with an extra line is still read line by line" "$TMP/w2" true true true
# the docs-only gate: a classifier that errors, or answers anything but skip-both, makes the PR build
printf '#!/usr/bin/env bash\nexit 3\n' > "$TMP/w2/scripts/ci/affected-suites.sh"
cp "$ROOT/scripts/ci/detect-code-change.sh" "$TMP/w2/scripts/ci/detect-code-change.sh"
: > "$TMP/o_gate"
run_body "$TMP/w2" "$BODY/codegate.sh" GITHUB_EVENT_NAME=pull_request PATHS_OK=true RUNNER_TEMP="$RT" GITHUB_OUTPUT="$TMP/o_gate"
check "docs gate     a docs-only list with a failing classifier builds" "true" "$(out code_changed "$TMP/o_gate")"

# ── lexical pins: what no step body can show ─────────────────────────────────
flat="$(tr '\n' ' ' < "$CI_YML" | tr -s ' ')"
count() { printf '%s' "$flat" | grep -o -F -- "$1" | wc -l | tr -d ' '; }
check "env: SKIP_SERVER_SUITES is mapped from skip_server_suites on the three consumers" 3 \
  "$(count 'SKIP_SERVER_SUITES: ${{ needs.preflight.outputs.skip_server_suites }}')"
check "env: SKIP_AGENT_SUITES is mapped from skip_agent_suites on the three consumers" 3 \
  "$(count 'SKIP_AGENT_SUITES: ${{ needs.preflight.outputs.skip_agent_suites }}')"
check "env: no consumer maps a family's variable from the other family's output" 0 \
  "$(( $(count 'SKIP_SERVER_SUITES: ${{ needs.preflight.outputs.skip_agent_suites }}') + $(count 'SKIP_AGENT_SUITES: ${{ needs.preflight.outputs.skip_server_suites }}') ))"
check "env: both gates read the list step's verdict" 2 "$(count 'PATHS_OK: ${{ steps.prpaths.outputs.ok }}')"
check "env: the list is bound to the event's PR head" 1 \
  "$(sed -n '/- name: List the paths this pull request changes/,/run: |/p' "$CI_YML" | grep -c -F 'PR_HEAD_SHA: ${{ github.event.pull_request.head.sha }}')"
check "gate: the pg and smoke steps of both legs are off only when the server family is skipped" 4 \
  "$(count "&& needs.preflight.outputs.skip_server_suites != 'true'")"
check "gate: affected runs only on a PR into anything but main, with code changes" 1 \
  "$(count "if: github.event_name == 'pull_request' && github.base_ref != 'main' && steps.codegate.outputs.code_changed == 'true'")"
check "gate: the list step runs on pull requests" 1 \
  "$(sed -n '/- name: List the paths this pull request changes/,/run: |/p' "$CI_YML" | grep -c "if: github.event_name == 'pull_request'")"
check "checkout: preflight fetches the merge commit's parents" 1 \
  "$(sed -n '/^  preflight:/,/^      - name: /p' "$CI_YML" | grep -c 'fetch-depth: 2')"
# every mention of a skip output is a job output, an env mapping or one of those gates: a bare
# truthiness test or `!= 'false'` would treat an EMPTY output (a push, a docs-only PR) as "skip"
stray="$(grep -n 'skip_server_suites\|skip_agent_suites' "$CI_YML" | grep -v \
  -e '^[0-9]*: *skip_\(server\|agent\)_suites: \${{ steps.affected.outputs' \
  -e 'SKIP_\(SERVER\|AGENT\)_SUITES: \${{ needs.preflight.outputs.skip_\(server\|agent\)_suites }}' \
  -e "&& needs.preflight.outputs.skip_server_suites != 'true'" \
  -e "- pg_part: \${{ (github.event_name != 'pull_request' || needs.preflight.outputs.skip_server_suites == 'true') && 'pg-b' || 'NONE' }}" \
  -e 'echo "skip_\(server\|agent\)_suites=\$skip_' \
  -e '^[0-9]*: *#' || true)"
check "gate: no other use of a skip output (an empty output must always mean run)" "" "$stray"
check "matrix: pg_part is the axis pg-a / pg-b" 1 "$(count 'pg_part: [pg-a, pg-b]')"
check "matrix: pg-b only on a pull request that can reach the server family" 1 \
  "$(count "- pg_part: \${{ (github.event_name != 'pull_request' || needs.preflight.outputs.skip_server_suites == 'true') && 'pg-b' || 'NONE' }}")"
LEG_NAME="Linux \${{ matrix.compiler }} \${{ matrix.build_type }}\${{ github.event_name == 'pull_request' && (matrix.pg_part == 'pg-b' && ' (pg B)' || ' (pg A)') || '' }}"
check "name: a PR's legs are (pg A) / (pg B); any other event keeps the plain names" 1 "$(count "name: \"$LEG_NAME\"")"
check "name: the telemetry leg name is the same template" 1 "$(count "YUZU_LEG_NAME: \"$LEG_NAME\"")"
gate_block="$(sed -n '/^  linux-pr-gate:/,/^    steps:/p' "$CI_YML")"
check "linux gate: it is the required context on a PR, under another name elsewhere" 1 \
  "$(printf '%s\n' "$gate_block" | grep -c -F "name: \${{ github.event_name == 'pull_request' && 'Linux gcc-15 debug' || 'Linux PR gate (pull requests only)' }}")"
check "linux gate: it waits for preflight and every Linux leg" 1 \
  "$(printf '%s\n' "$gate_block" | grep -c -F 'needs: [preflight, linux]')"
check "linux gate: it runs on every pull request, even after a failure or a cancel" 1 \
  "$(printf '%s\n' "$gate_block" | grep -c -F "if: always() && github.event_name == 'pull_request'")"
check "linux gate: exactly one job carries the required Linux name" 1 "$(count "'Linux gcc-15 debug' ||")"
# the docs-only stub must emit the names the Windows and macOS matrices render on a PR
stub="$(sed -n '/^  docs-required-checks:/,/^  [a-z-]*:$/p' "$CI_YML" | grep '^ *- "' | sed 's/^ *- //' | tr '\n' ' ')"
check "stubs: docs-required-checks lists the Windows and macOS contexts" \
  '"Windows MSVC debug" "macOS debug" ' "$stub"
# the steps only the pg-a leg runs: adding a heavy step without this guard makes the pg-b leg run
# it too, and dropping the guard from one of these gives the pg-b leg work it must not do
guarded="$(awk '/^  linux:/{j=1} /^  windows:/{j=0}
  j&&/^      - name: /{n=$0; sub(/^      - name: /,"",n)}
  j&&/^        if: matrix.pg_part != .pg-b.$/{print n}' "$CI_YML" | tr '\n' '|')"
want_guarded="Install Erlang/OTP and rebar3|Verify vendored grpcbox integrity|Compile gateway (warm _build for the codegen check)|Verify gateway proto codegen is up to date|Verify test-family separation (affected-suites class table)|Capability matrix drift gate (#2204)|Capability matrix gate tests (#2204 F10)|Assert canary libpq link provenance (static on Linux)|Test (non-pg suites)|Break-glass CLI test|Agent graceful-shutdown smoke test|"
check "legs: the steps skipped on the pg-b leg are exactly the intended eleven" "$want_guarded" "$guarded"
# the closure guard: present on the Linux and macOS jobs, and neither step can be made to pass anyway
guard_steps="$(awk '/^      - name: Verify test-family separation/{g=1; print "STEP"; next}
  g&&/^      - /{g=0} g&&/^      #/{g=0} g' "$CI_YML")"
check "closure guard: one step on Linux, one on macOS" 2 "$(printf '%s\n' "$guard_steps" | grep -c '^STEP$')"
check "closure guard: both run the checker, and nothing lets them pass on a failure" "2|0" \
  "$(printf '%s\n' "$guard_steps" | grep -c 'run: python3 scripts/ci/check-suite-input-closure.py --builddir ')|$(printf '%s\n' "$guard_steps" | grep -c -e 'continue-on-error' -e '|| true' -e '|| :')"
# these tests are what pin the wiring; a deleted registration would silently stop them
shell_gates="$(sed -n '/- name: Shell gate tests/,/^      - name: /p' "$CI_YML")"
check "registration: the classifier test and this test run in preflight" "1|1" \
  "$(printf '%s\n' "$shell_gates" | grep -c '^ *bash tests/shell/test_affected_suites.sh')|$(printf '%s\n' "$shell_gates" | grep -c '^ *bash tests/shell/test_suite_selection_wiring.sh')"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" = 0 ]
