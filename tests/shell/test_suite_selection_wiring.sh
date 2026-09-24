#!/usr/bin/env bash
# test_suite_selection_wiring.sh — contract net for the ci.yml step bodies that APPLY
# scripts/ci/affected-suites.sh's verdict (docs/ci-architecture.md, "PR-time test selection").
#
# WHY THIS EXISTS. The classifier has its own fixture tests, but the wiring decides which suites a
# leg ACTUALLY runs, and no skip branch can run in the pull request that introduces it: a PR that
# touches .github/ or scripts/ is class `both`, so its own CI never skips anything. A swapped flag
# (the server verdict wired to the agent suites) would first run on a LATER PR and silently skip the
# wrong family. So this extracts the REAL step bodies from ci.yml (tests/shell/extract_run_block.py,
# the idiom test_trusted_inputs_validate.sh uses, so it cannot assert a copy of the logic) and runs
# them against stubs that record their argv. Pinned:
#
#   preflight `affected`   the two output lines for a real classifier verdict, and false/false on
#                          every failure path: API error, count mismatch, classifier error, garbage
#   Linux non-pg suites    agent/tar dropped only when the agent family is skipped; the by-name
#                          server call only when the server family is not
#   Linux pg shards        server-pg-a / server-pg-b on a PR, the whole server-pg on a push, and a
#                          selector that matches nothing is an error (meson would exit 0)
#   Windows non-pg suites  the cover guard and the real run share ONE suites array, and every suite
#                          is in exactly one of selected / skipped / excluded
#   macOS test             --no-suite for exactly the skipped family
#
# plus lexical pins for what a step body cannot show: the `if:` gates, the env mapping between the
# preflight outputs and the consumers, the matrix axis, the leg-only step guards, and the check-name
# contract with docs-required-checks. A stub `python3`/`python`/`meson`/`gh` records its argv and
# never runs anything, so this needs no build and no network.
#
# Where it runs: ci.yml's preflight "Shell gate tests" step, on every PR (Windows never runs it).
# Run:  bash tests/shell/test_suite_selection_wiring.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CI_YML="$ROOT/.github/workflows/ci.yml"
EXTRACT="$ROOT/tests/shell/extract_run_block.py"
[ -f "$CI_YML" ] || { echo "missing $CI_YML" >&2; exit 2; }
BASH_BIN="$(command -v bash)"

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
extract "$BODY/affected.sh"    --job preflight --name 'Determine affected test suites (skip families this PR cannot reach)'
extract "$BODY/linux_nonpg.sh" --job linux   --name 'Test (non-pg suites)'   "${MATRIX_SUBST[@]}"
extract "$BODY/linux_pg.sh"    --job linux   --name 'Test (pg shards, full)' "${MATRIX_SUBST[@]}"
extract "$BODY/win_nonpg.sh"   --job windows --name 'Test (non-pg suites)'   --subst matrix.build_type=MATRIX_BUILD_TYPE
extract "$BODY/mac_test.sh"    --job macos   --name Test

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
cat > "$STUBS/gh" <<'EOF'
#!/usr/bin/env bash
# Answers only the PR-files read, from a fixture that is already the jq-processed TSV.
[ -n "${GH_STUB_FAIL:-}" ] && exit 1
cat "${GH_STUB_FILE:?}"
EOF
chmod +x "$STUBS/gh"

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
  ( cd "$cwd" && env -i PATH="$STUBS:$(dirname "$BASH_BIN"):/usr/bin:/bin" HOME="$TMP" STUB_LOG="$LOG" \
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
  # structural, independent of the string above: ONE suites array feeds both, and every suite the
  # build registers is in exactly one bucket, so the proof the guard runs is about the run that follows
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

# ── preflight `affected` ─────────────────────────────────────────────────────
RT="$TMP/rt"; mkdir -p "$RT"
pre_case() { # pre_case <desc> <cwd> <fixture tsv text> <changed_files> <want server> <want agent> [VAR=val ...]
  local desc="$1" cwd="$2" tsv="$3" total="$4" ws="$5" wa="$6"; shift 6
  printf '%b' "$tsv" > "$TMP/files.tsv"
  : > "$TMP/gho"; : > "$TMP/summary"
  run_body "$cwd" "$BODY/affected.sh" GH_STUB_FILE="$TMP/files.tsv" GH_TOKEN=x PR_NUMBER=7 \
    CHANGED_FILES="$total" GITHUB_REPOSITORY=o/r RUNNER_TEMP="$RT" GITHUB_OUTPUT="$TMP/gho" \
    GITHUB_STEP_SUMMARY="$TMP/summary" "$@"
  check "preflight     $desc: outputs" "skip_server_suites=$ws|skip_agent_suites=$wa" \
    "$(tr '\n' '|' < "$TMP/gho" | sed 's/|$//')"
  check "preflight     $desc: exits 0 (a failure here must never block the workflow)" 0 "$RC"
  grep -q '^### Suite selection' "$TMP/summary" && s=1 || s=0
  check "preflight     $desc: writes the step summary" 1 "$s"
}
pre_case "skills + ledger only skip both"      "$ROOT" '.claude/skills/x/SKILL.md\t\ngovernance.d/1.jsonl\t\n' 2 true true
pre_case "a server change skips the agent family" "$ROOT" 'server/core/src/a.cpp\t\ndocs/z.md\t\n' 2 false true
pre_case "shared code runs both"               "$ROOT" 'common/include/yuzu/x.hpp\t\n' 1 false false
pre_case "a list shorter than changed_files fails closed" "$ROOT" '.claude/x\t\n' 5 false false
pre_case "an API failure fails closed"         "$ROOT" '.claude/x\t\n' 1 false false GH_STUB_FAIL=1
# a classifier the step cannot trust: garbage output, and a non-zero exit — both fail closed
mkdir -p "$TMP/w2/scripts/ci"
printf '#!/usr/bin/env bash\necho "skip_server=maybe"\necho "skip_agent=true"\n' > "$TMP/w2/scripts/ci/affected-suites.sh"
pre_case "garbled classifier output fails closed" "$TMP/w2" '.claude/x\t\n' 1 false false
printf '#!/usr/bin/env bash\necho boom >&2\nexit 3\n' > "$TMP/w2/scripts/ci/affected-suites.sh"
pre_case "a classifier that exits non-zero fails closed" "$TMP/w2" '.claude/x\t\n' 1 false false
printf '#!/usr/bin/env bash\necho "skip_server=true"\necho "skip_agent=true"\necho "extra"\n' > "$TMP/w2/scripts/ci/affected-suites.sh"
pre_case "a classifier with an extra line is still read line by line" "$TMP/w2" '.claude/x\t\n' 1 true true

# ── lexical pins: what no step body can show ─────────────────────────────────
flat="$(tr '\n' ' ' < "$CI_YML" | tr -s ' ')"
count() { printf '%s' "$flat" | grep -o -F -- "$1" | wc -l | tr -d ' '; }
check "env: SKIP_SERVER_SUITES is mapped from skip_server_suites on the three consumers" 3 \
  "$(count 'SKIP_SERVER_SUITES: ${{ needs.preflight.outputs.skip_server_suites }}')"
check "env: SKIP_AGENT_SUITES is mapped from skip_agent_suites on the three consumers" 3 \
  "$(count 'SKIP_AGENT_SUITES: ${{ needs.preflight.outputs.skip_agent_suites }}')"
check "env: no consumer maps a family's variable from the other family's output" 0 \
  "$(( $(count 'SKIP_SERVER_SUITES: ${{ needs.preflight.outputs.skip_agent_suites }}') + $(count 'SKIP_AGENT_SUITES: ${{ needs.preflight.outputs.skip_server_suites }}') ))"
check "gate: the pg and smoke steps of both legs are off only when the server family is skipped" 4 \
  "$(count "&& needs.preflight.outputs.skip_server_suites != 'true'")"
# every mention of a skip output is a job output, an env mapping or one of those gates: a bare
# truthiness test or `!= 'false'` would treat an EMPTY output (a push, a docs-only PR) as "skip"
stray="$(grep -n 'skip_server_suites\|skip_agent_suites' "$CI_YML" | grep -v \
  -e '^[0-9]*: *skip_\(server\|agent\)_suites: \${{ steps.affected.outputs' \
  -e 'SKIP_\(SERVER\|AGENT\)_SUITES: \${{ needs.preflight.outputs.skip_\(server\|agent\)_suites }}' \
  -e "&& needs.preflight.outputs.skip_server_suites != 'true'" \
  -e 'echo "skip_\(server\|agent\)_suites=\$skip_' \
  -e '^[0-9]*: *#' || true)"
check "gate: no other use of a skip output (an empty output must always mean run)" "" "$stray"
check "matrix: pg_part is the axis pg-a / pg-b" 1 "$(count 'pg_part: [pg-a, pg-b]')"
check "matrix: pg-b is excluded on every non-PR event" 1 \
  "$(count "- pg_part: \${{ github.event_name == 'pull_request' && 'NONE' || 'pg-b' }}")"
check "name: the pg-b leg is the only one whose check name changes" 1 \
  "$(count "name: \"Linux \${{ matrix.compiler }} \${{ matrix.build_type }}\${{ matrix.pg_part == 'pg-b' && ' (pg B)' || '' }}\"")"
# the docs-only stub must emit the names the matrix renders: three unchanged contexts + the pg B one
stub="$(sed -n '/^  docs-required-checks:/,/^  [a-z-]*:$/p' "$CI_YML" | grep '^ *- "' | sed 's/^ *- //' | tr '\n' ' ')"
check "stubs: docs-required-checks lists the three existing contexts and the pg B context" \
  '"Linux gcc-15 debug" "Linux gcc-15 debug (pg B)" "Windows MSVC debug" "macOS debug" ' "$stub"
# the steps only the pg-a leg runs: adding a heavy step without this guard makes the pg-b leg run
# it too, and dropping the guard from one of these gives the pg-b leg work it must not do
guarded="$(awk '/^  linux:/{j=1} /^  windows:/{j=0}
  j&&/^      - name: /{n=$0; sub(/^      - name: /,"",n)}
  j&&/^        if: matrix.pg_part != .pg-b.$/{print n}' "$CI_YML" | tr '\n' '|')"
want_guarded="Install Erlang/OTP and rebar3|Verify vendored grpcbox integrity|Compile gateway (warm _build for the codegen check)|Verify gateway proto codegen is up to date|Verify test-family separation (affected-suites class table)|Capability matrix drift gate (#2204)|Capability matrix gate tests (#2204 F10)|Assert canary libpq link provenance (static on Linux)|Test (non-pg suites)|Break-glass CLI test|Agent graceful-shutdown smoke test|"
check "legs: the steps skipped on the pg-b leg are exactly the intended eleven" "$want_guarded" "$guarded"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" = 0 ]
