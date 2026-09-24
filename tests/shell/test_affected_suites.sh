#!/usr/bin/env bash
# test_affected_suites.sh — fixture tests for scripts/ci/affected-suites.sh
#
# The classifier decides which heavy test suites a pull request may skip (docs/ci-architecture.md,
# "PR-time suite selection"). Its two failure directions cost very different amounts: a false RUN
# costs minutes, a false SKIP lets a break reach dev. So this pins, hermetically (no network, no
# build, a throwaway tests tree):
#   - the class table, including the case-arm ordering traps (`*` in a case pattern matches `/`)
#   - the run-time-read rule: a path that a test source names verbatim affects that test's family
#   - every fail-closed input: empty list, count mismatch, unreadable path, missing tests tree
#   - renames: the SOURCE of a rename out of a heavy directory still counts
# and finally runs the classifier over the real repository as a smoke test.
#
# Run:  bash tests/shell/test_affected_suites.sh
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || { cd "$(dirname "$0")/../.." && pwd; })"
SCRIPT="$ROOT/scripts/ci/affected-suites.sh"
[ -f "$SCRIPT" ] || { echo "missing $SCRIPT" >&2; exit 2; }

T="$(mktemp -d "${TMPDIR:-/tmp}/yuzu-affected-suites-test.XXXXXX")"
trap 'chmod -R u+rwx "$T" 2>/dev/null || true; rm -rf "$T"' EXIT

# A miniature tests tree: one server test, one agent test, one nested agent test, and a meson file.
mkdir -p "$T/tests/unit/server" "$T/tests/unit/agent" "$T/tests/unit/fixtures"
cat > "$T/tests/meson.build" <<'EOF'
# a docs-suite entry names docs/named-by-meson.md
EOF
cat > "$T/tests/unit/server/test_s.cpp" <<'EOF'
// reads docs/read-by-server.md and mentions docs/user-manual/policy-engine.md in an error string
EOF
cat > "$T/tests/unit/test_a.cpp" <<'EOF'
// reads docs/user-manual/metrics.md
EOF
cat > "$T/tests/unit/agent/test_b.cpp" <<'EOF'
// reads .claude/read-by-agent.md
EOF
TR="$T/tests/unit"

pass=0 fail=0
report() {   # report <ok 0|1> <desc> <detail>
  if [ "$1" = 0 ]; then printf '  [pass] %s\n' "$2"; pass=$((pass + 1))
  else printf '  [FAIL] %s (%s)\n' "$2" "$3"; fail=$((fail + 1)); fi
}

# run_list <stdin-text> [args...] -> "skip_server skip_agent" on one line
run_list() {
  local input="$1"; shift
  printf '%b' "$input" | bash "$SCRIPT" --tests-root "$TR" "$@" 2>/dev/null \
    | sed -e 's/skip_server=//' -e 's/skip_agent=//' | tr '\n' ' ' | sed 's/ $//'
}
# expect <want "S A"> <desc> <stdin-text> [args...]   S/A are skip_server / skip_agent
expect() {
  local want="$1" desc="$2" input="$3"; shift 3
  local got; got="$(run_list "$input" "$@")"
  if [ "$got" = "$want" ]; then report 0 "$desc"; else report 1 "$desc" "want '$want', got '$got'"; fi
}
expect_class() {   # expect_class <want> <path>
  local got; got="$(bash "$SCRIPT" --tests-root "$TR" --classify "$2")"
  if [ "$got" = "$1" ]; then report 0 "class of $2 is $1"; else report 1 "class of $2" "want $1, got $got"; fi
}

# --- the class table, one path each --------------------------------------------------------------
# both: the build graph and CI infrastructure
for p in meson.build meson.options vcpkg.json vcpkg-configuration.json triplets/x64-linux.cmake \
         meson/native/linux-gcc15.ini requirements-ci.txt subdir/meson.build tests/meson.build \
         .github/workflows/ci.yml scripts/ci/flake-retry.py tools/capmatrix-gen/x.cpp; do
  expect_class both "$p"
done
# both: code both binaries are built from, and shared test-tree files
for p in agents/core/src/agent.cpp agents/plugins/x/src/x.cpp common/include/yuzu/x.hpp sdk/include/x.h \
         proto/agent.proto tests/unit/test_helpers.hpp tests/unit/test_runner_main.cpp \
         tests/unit/fixtures/wave9/x.bin tests/fixtures/abi4/x.cpp tests/fuzz/x.cpp; do
  expect_class both "$p"
done
# server / agent
for p in server/core/src/server.cpp server/core/meson.build content/definitions/x.yaml \
         tests/unit/server/test_x.cpp tests/unit/server/x.hpp; do
  [ "${p##*/}" = meson.build ] && continue      # a meson.build is `both` whatever directory it is in
  expect_class server "$p"
done
expect_class both  server/core/meson.build
for p in tests/unit/test_tar_store.cpp tests/unit/agent/test_b.cpp; do expect_class agent "$p"; done
# none
for p in docs/x.md docs/adr/1.md changelog.d/1-x.fixed.md governance.d/1.jsonl .claude/skills/x/SKILL.md \
         .codex/x gateway/apps/x.erl deploy/windows/x.ps1 site/index.html tests/shell/x.sh \
         tests/prometheus/x.yml tests/puppeteer/x.js tests/test_x.py README.md LICENSE NOTICE .gitignore \
         .dockerignore .editorconfig .pre-commit-config.yaml docker-compose.uat.yml cliff.toml \
         Synthetic-UAT-Puppeteer.js; do
  expect_class none "$p"
done
# root files not on the allowlist are unknown: .gitattributes changes line endings on checkout
for p in .gitattributes .clang-tidy .clang-format some-new-root-file.cfg; do
  expect_class both "$p"
done
# the traps: `*` in a case pattern crosses `/`, so arm order is part of the contract
expect_class both  tests/unit/sub/deeper/x.cpp        # not `tests/unit/*.cpp` (agent)
expect_class both  tests/weird/x.txt                  # not `tests/*` (none)
expect_class both  docs/capability-registries/a.tsv   # not `docs/*` (none)
expect_class both  unknown-dir/x                      # any other directory is unknown, so both
expect_class both  agents/README.md                   # a doc inside agents/ is still both

# --- list-level results: "skip_server skip_agent" -------------------------------------------------
expect "false true"  "server code alone skips the agent suites"        'server/core/src/a.cpp\t\n'
expect "true false"  "an agent test alone skips the server suites"     'tests/unit/test_x.cpp\t\n'
expect "false false" "shared code runs both"                           'common/include/x.hpp\t\n'
expect "false false" "server + agent test run both"                    'server/core/src/a.cpp\t\ntests/unit/test_x.cpp\t\n'
expect "true true"   "skills, ledger, changelog, docs skip both"       '.claude/skills/x.md\t\ngovernance.d/1.jsonl\t\nchangelog.d/1-x.fixed.md\t\ndocs/z.md\t\n'
expect "true true"   "gateway-only and deploy-only PRs skip both"      'gateway/apps/x.erl\t\ndeploy/windows/x.ps1\t\n'
expect "false false" "one build file among docs runs both"             'docs/z.md\t\nserver/core/meson.build\t\n'
expect "false false" "an unknown directory runs both"                  'weird/x\t\n'
expect "false false" "a CI script runs both"                           'scripts/ci/affected-suites.sh\t\n'
expect "false true"  "plain paths without the TAB column are accepted" 'server/core/src/a.cpp\ndocs/z.md\n'
expect "false true"  "a file with no trailing newline is still read"   'server/core/src/a.cpp\t'

# --- run-time reads: a test naming a path verbatim makes it affect that family ----------------------
expect "false true"  "a doc a SERVER test names runs the server family"   'docs/read-by-server.md\t\n'
expect "false true"  "an error-string mention counts too (over-broad by design)" 'docs/user-manual/policy-engine.md\t\n'
expect "true false"  "a doc an AGENT test names runs the agent family"    'docs/user-manual/metrics.md\t\n'
expect "true false"  "a nested agent test's read counts (agent/ is not server/)" '.claude/read-by-agent.md\t\n'
expect "false false" "tests/meson.build naming a path runs both"          'docs/named-by-meson.md\t\n'
expect "true true"   "a doc no test names skips both"                     'docs/user-manual/unread.md\t\n'
expect "false false" "capability registries always run both"              'docs/capability-registries/x.tsv\t\n'
expect "true true"   "a changed path that merely extends a named path is not named" 'docs/user-manual/metrics.md.bak\t\n'

# --- renames: the source path counts -------------------------------------------------------------
expect "false true"  "rename server code -> docs still runs the server family" 'docs/x.md\tserver/core/src/x.cpp\n'
expect "false false" "rename agents/ -> docs runs both"                        'docs/x.md\tagents/core/src/x.cpp\n'
expect "true true"   "rename docs -> docs skips both"                          'docs/new.md\tdocs/old.md\n'

# --- fail closed ---------------------------------------------------------------------------------
expect "false false" "empty list"                          ''
expect "false false" "only blank lines"                    '\n\n'
expect "false false" "list shorter than --total"           'docs/z.md\t\n'               --total 2
expect "false false" "list longer than --total"            'docs/z.md\t\ndocs/y.md\t\n'  --total 1
expect "false false" "non-numeric --total"                 'docs/z.md\t\n'               --total many
expect "true true"   "matching --total keeps the result"   'docs/z.md\t\n'               --total 1
expect "false false" "backslash from @tsv escaping"        'docs/a\\\\tb.md\t\n'
expect "false false" "C-quoted path"                       '"docs/a b.md"\t\n'
expect "false false" "absolute path"                       '/etc/passwd\t\n'
expect "false false" "parent-directory escape"             'docs/../server/x.cpp\t\n'
expect "false false" "a heavy path hidden behind a doc rename column" 'docs/x.md\t"server/a b.cpp"\n'
expect "false false" "tests root missing"                  'docs/z.md\t\n'               --tests-root "$T/nope"
rm -rf "$T/none-server" && mkdir -p "$T/none-server/tests/unit"
expect "false false" "tests/unit/server missing, so reads cannot be checked" 'docs/z.md\t\n' --tests-root "$T/none-server/tests/unit"
# ...but a list that is already decided needs no scan, so it does not depend on the tests tree
expect "false false" "a decided list does not need the tests tree" 'common/include/x.hpp\t\n' --tests-root "$T/nope"

# A grep that cannot read the tests tree must not read as "nothing names this path". Root can read
# a mode-000 directory, so this case only means something for an ordinary user.
if [ "$(id -u)" != 0 ]; then
  chmod 000 "$T/tests/unit/server"
  expect "false false" "an unreadable server test dir fails closed" 'docs/z.md\t\n'
  chmod 755 "$T/tests/unit/server"
else
  printf '  [skip] unreadable-directory case (running as root)\n'
fi

# --- usage errors are not results ----------------------------------------------------------------
rc=0; bash "$SCRIPT" --bogus >/dev/null 2>&1 </dev/null || rc=$?
[ "$rc" = 2 ] && report 0 "unknown flag exits 2" || report 1 "unknown flag exits 2" "rc=$rc"
rc=0; bash "$SCRIPT" --total >/dev/null 2>&1 </dev/null || rc=$?
[ "$rc" = 2 ] && report 0 "flag without a value exits 2" || report 1 "flag without a value exits 2" "rc=$rc"

# --- the real repository -------------------------------------------------------------------------
# Not a result to assert (it moves with the tree) but a robustness check: the run-time-read scan must
# finish over the real tests tree with every tracked path as input, and emit exactly two lines.
if git -C "$ROOT" rev-parse --git-dir >/dev/null 2>&1; then
  real="$(git -C "$ROOT" ls-files | (cd "$ROOT" && bash "$SCRIPT" 2>/dev/null))" || real=""
  lines="$(printf '%s\n' "$real" | grep -c '^skip_\(server\|agent\)=\(true\|false\)$' || true)"
  [ "$lines" = 2 ] && report 0 "real tree: two well-formed result lines" || report 1 "real tree: two well-formed result lines" "got: $real"
  # Every doc a real test reads must classify as affecting; the two known readers are the pin.
  got="$(printf 'docs/user-manual/metrics.md\t\n' | (cd "$ROOT" && bash "$SCRIPT" 2>/dev/null) | tr '\n' ' ')"
  case "$got" in
    *skip_agent=false*) report 0 "real tree: docs/user-manual/metrics.md (read by an agent test) runs the agent family" ;;
    *) report 1 "real tree: metrics.md runs the agent family" "got: $got" ;;
  esac
  got="$(printf 'docs/capability-registries/dex_obs_platforms.tsv\t\n' | (cd "$ROOT" && bash "$SCRIPT" 2>/dev/null) | tr '\n' ' ')"
  case "$got" in
    *skip_server=false*skip_agent=false*) report 0 "real tree: a capability registry table runs both" ;;
    *) report 1 "real tree: a capability registry table runs both" "got: $got" ;;
  esac
fi

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" = 0 ]
