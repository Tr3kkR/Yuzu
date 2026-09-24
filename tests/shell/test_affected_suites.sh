#!/usr/bin/env bash
# test_affected_suites.sh — fixture tests for scripts/ci/affected-suites.sh
#
# A false RUN costs minutes, a false SKIP lets a break reach dev. So this pins, hermetically (a
# throwaway tests tree, no network, no build): the class table and its arm-order traps; the
# run-time-read rule in both directions; every fail-closed input; renames (the source path arrives
# as its own line); and finally the classifier over the real repository. The real-tree cases are
# deliberate tripwires: they fail if the tests stop naming the docs they read. They take about 45 s
# on macOS (BSD grep) and under a second in preflight (GNU grep).
#
# Where it runs: ci.yml's preflight "Shell gate tests" step on every PR, like
# tests/shell/test_detect_code_change.sh; not a meson `docs` suite entry, because it spawns a process
# per case and chmods a directory.
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
// and names tests/unit/test_named_by_server.cpp (an agent-class path)
EOF
cat > "$T/tests/unit/test_a.cpp" <<'EOF'
// reads docs/user-manual/metrics.md
EOF
cat > "$T/tests/unit/agent/test_b.cpp" <<'EOF'
// reads .claude/read-by-agent.md, content/definitions/read-by-agent.yaml (a server-class path)
// and docs/a[1].md (a literal path a regular expression would not match)
EOF
# a helper header directly under tests/unit/ is compiled into the server binary too
cat > "$T/tests/unit/test_helpers.hpp" <<'EOF'
// a shared helper that reads docs/read-by-helper.md
EOF
# a source grep would call binary (NULs); GNU grep >= 3.5 prints nothing for one without -a
printf 'docs/read-by-binary.md\000\001\002 blob\n' > "$T/tests/unit/server/blob.bin"
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
         .github/workflows/ci.yml scripts/ci/flake-retry.py tools/capmatrix-gen/x.cpp \
         enterprise/x.cpp .clusterfuzzlite/Dockerfile; do
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
# ...and a .gitattributes anywhere, even under an inert directory: it changes checkout bytes there
for p in docs/.gitattributes docs/capability-registries/.gitattributes gateway/.gitattributes \
         .claude/x/.gitattributes; do
  expect_class both "$p"
done
# the runner inventory is inert here, as it is to the docs-only gate (ci.yml needs the two to agree)
expect_class none .github/runner-inventory.json
expect_class none .github/workflows/runner-inventory-sentinel.yml
expect_class both .github/workflows/other.yml
# the traps: `*` in a case pattern crosses `/`, so arm order is part of the contract
expect_class both  tests/unit/sub/deeper/x.cpp        # not `tests/unit/*.cpp` (agent)
expect_class both  tests/weird/x.txt                  # not `tests/*` (none)
expect_class both  docs/capability-registries/a.tsv   # not `docs/*` (none)
expect_class both  unknown-dir/x                      # any other directory is unknown, so both
expect_class both  agents/README.md                   # a doc inside agents/ is still both

# --- list-level results: "skip_server skip_agent" -------------------------------------------------
expect "false true"  "server code alone skips the agent suites"        'server/core/src/a.cpp\n'
expect "true false"  "an agent test alone skips the server suites"     'tests/unit/test_x.cpp\n'
expect "false false" "shared code runs both"                           'common/include/x.hpp\n'
expect "false false" "server + agent test run both"                    'server/core/src/a.cpp\ntests/unit/test_x.cpp\n'
expect "true true"   "skills, ledger, changelog, docs skip both"       '.claude/skills/x.md\ngovernance.d/1.jsonl\nchangelog.d/1-x.fixed.md\ndocs/z.md\n'
expect "true true"   "gateway-only and deploy-only PRs skip both"      'gateway/apps/x.erl\ndeploy/windows/x.ps1\n'
expect "false false" "one build file among docs runs both"             'docs/z.md\nserver/core/meson.build\n'
expect "false false" "an unknown directory runs both"                  'weird/x\n'
expect "false false" "a CI script runs both"                           'scripts/ci/affected-suites.sh\n'
expect "false true"  "a file with no trailing newline is still read"   'server/core/src/a.cpp'

# --- run-time reads: a test naming a path verbatim makes it affect that family ----------------------
expect "false true"  "a doc a SERVER test names runs the server family"   'docs/read-by-server.md\n'
expect "false true"  "an error-string mention counts too (over-broad by design)" 'docs/user-manual/policy-engine.md\n'
expect "true false"  "a doc an AGENT test names runs the agent family"    'docs/user-manual/metrics.md\n'
expect "true false"  "a nested agent test's read counts (agent/ is not server/)" '.claude/read-by-agent.md\n'
expect "false false" "tests/meson.build naming a path runs both"          'docs/named-by-meson.md\n'
expect "true true"   "a doc no test names skips both"                     'docs/user-manual/unread.md\n'
expect "false false" "capability registries always run both"              'docs/capability-registries/x.tsv\n'
expect "true true"   "a changed path that merely extends a named path is not named" 'docs/user-manual/metrics.md.bak\n'
expect "false false" "a path a shared helper header names runs both families" 'docs/read-by-helper.md\n'
expect "false true"  "a path named only inside a binary-looking server source is still found" 'docs/read-by-binary.md\n'
# the scan still runs for the family pass 1 left skippable, and reads BOTH directions
expect "false false" "a mixed list still scans for the family the class table left open" 'server/core/src/a.cpp\ndocs/user-manual/metrics.md\n'
expect "false false" "a server-class path an agent test names runs the agent family too" 'content/definitions/read-by-agent.yaml\n'
expect "false false" "an agent-class path a server test names runs the server family too" 'tests/unit/test_named_by_server.cpp\n'
expect "true false"  "a path is matched literally, never as a pattern"  'docs/a[1].md\n'

# --- renames: the source path counts -------------------------------------------------------------
expect "false true"  "rename server code -> docs still runs the server family" 'docs/x.md\nserver/core/src/x.cpp\n'
expect "false false" "rename agents/ -> docs runs both"                        'agents/core/src/x.cpp\ndocs/x.md\n'
expect "true true"   "rename docs -> docs skips both"                          'docs/new.md\ndocs/old.md\n'

# --- fail closed ---------------------------------------------------------------------------------
expect "false false" "empty list"                          ''
expect "false false" "only blank lines"                    '\n\n'
expect "false false" "a TAB in a line (not a list git printed)" 'docs/x.md\tserver/core/src/x.cpp\n'
expect "false false" "a raw backslash"                     'docs/a\\\\b.md\n'
expect "false false" "C-quoted path"                       '"docs/a\\tb.md"\n'
expect "false false" "absolute path"                       '/etc/passwd\n'
expect "false false" "parent-directory escape"             'docs/../server/x.cpp\n'
expect "false false" "a bare parent directory"             '..\n'
expect "false false" "tests root missing"                  'docs/z.md\n'               --tests-root "$T/nope"
rm -rf "$T/none-server" && mkdir -p "$T/none-server/tests/unit" && : > "$T/none-server/tests/meson.build"
expect "false false" "tests/unit/server missing, so reads cannot be checked" 'docs/z.md\n' --tests-root "$T/none-server/tests/unit"
rm -rf "$T/no-meson" && mkdir -p "$T/no-meson/tests/unit/server"
expect "false false" "tests/meson.build missing, so its reads cannot be checked" 'docs/z.md\n' --tests-root "$T/no-meson/tests/unit"
# ...but a list that is already decided needs no scan, so it does not depend on the tests tree
expect "false false" "a decided list does not need the tests tree" 'common/include/x.hpp\n' --tests-root "$T/nope"
# grep -r does not follow a symlink inside the tree, so the classifier refuses to scan one
rm -rf "$T/linked" && mkdir -p "$T/linked/tests/unit/server" && : > "$T/linked/tests/meson.build"
printf '// reads docs/behind-a-link.md\n' > "$T/linked/reader.cpp"
ln -s ../../../reader.cpp "$T/linked/tests/unit/server/test_linked.cpp"
expect "false false" "a symlink in the tests tree fails closed" 'docs/behind-a-link.md\n' --tests-root "$T/linked/tests/unit"
# no temporary directory: the scan cannot run, so nothing may be skipped (and the script still answers)
got="$(printf 'docs/z.md\n' | TMPDIR="$T/no-such-dir" bash "$SCRIPT" --tests-root "$TR" 2>/dev/null | tr '\n' ' ')"
if [ "$got" = "skip_server=false skip_agent=false " ]; then report 0 "no temporary directory fails closed"
else report 1 "no temporary directory fails closed" "got '$got'"; fi

# A grep that cannot read the tests tree must not read as "nothing names this path". Root can read
# a mode-000 directory, so this case only means something for an ordinary user.
if [ "$(id -u)" != 0 ]; then
  chmod 000 "$T/tests/unit/server"
  expect "false false" "an unreadable server test dir fails closed" 'docs/z.md\n'
  chmod 755 "$T/tests/unit/server"
else
  printf '  [skip] unreadable-directory case (running as root)\n'
fi

# --- usage errors are not results ----------------------------------------------------------------
rc=0; bash "$SCRIPT" --bogus >/dev/null 2>&1 </dev/null || rc=$?
[ "$rc" = 2 ] && report 0 "unknown flag exits 2" || report 1 "unknown flag exits 2" "rc=$rc"
rc=0; bash "$SCRIPT" --tests-root >/dev/null 2>&1 </dev/null || rc=$?
[ "$rc" = 2 ] && report 0 "flag without a value exits 2" || report 1 "flag without a value exits 2" "rc=$rc"

# --classify-many is what scripts/ci/check-suite-input-closure.py calls, so its shape is a contract.
got="$(printf 'server/x\nagents/y\ndocs/z.md\ndocs/capability-registries/t.tsv\nunknown-file\n' | bash "$SCRIPT" --classify-many)"
want="$(printf 'server/x\tserver\nagents/y\tboth\ndocs/z.md\tnone\ndocs/capability-registries/t.tsv\tboth\nunknown-file\tboth')"
if [ "$got" = "$want" ]; then report 0 "--classify-many prints one path<TAB>class line per input"
else report 1 "--classify-many prints one path<TAB>class line per input" "got: $got"; fi

# --- the real repository -------------------------------------------------------------------------
# Robustness on the real tests tree. The input must be inert-only: `git ls-files` as a whole is decided
# by its first `both` path, so the run-time-read scan (pass 2) would never run. docs/ minus the
# capability registries is all class `none`, so every path goes through the scan, against the real
# tests/unit, with a real-sized pattern set; the scan having run is asserted through its diagnostic.
if git -C "$ROOT" rev-parse --git-dir >/dev/null 2>&1; then
  inert="$(git -C "$ROOT" ls-files docs | grep -v '^docs/capability-registries/' || true)"
  if [ -z "$inert" ]; then
    report 1 "real tree: there are tracked docs paths to scan" "git ls-files docs was empty"
  else
    rc=0
    printf '%s\n' "$inert" | (cd "$ROOT" && bash "$SCRIPT" >"$T/real.out" 2>"$T/real.err") || rc=$?
    lines="$(grep -c '^skip_\(server\|agent\)=\(true\|false\)$' "$T/real.out" || true)"
    if [ "$rc" = 0 ] && [ "$lines" = 2 ]; then report 0 "real tree: the scan finishes over every tracked docs path"
    else report 1 "real tree: the scan finishes over every tracked docs path" "rc=$rc lines=$lines"; fi
    if grep -q "named by" "$T/real.err"; then report 0 "real tree: the run-time-read scan ran and found real readers"
    else report 1 "real tree: the run-time-read scan ran and found real readers" "$(head -c 300 "$T/real.err")"; fi
  fi
  # Every doc a real test reads must classify as affecting; the two known readers are the pin.
  got="$(printf 'docs/user-manual/metrics.md\n' | (cd "$ROOT" && bash "$SCRIPT" 2>/dev/null) | tr '\n' ' ')"
  case "$got" in
    *skip_agent=false*) report 0 "real tree: docs/user-manual/metrics.md (read by an agent test) runs the agent family" ;;
    *) report 1 "real tree: metrics.md runs the agent family" "got: $got" ;;
  esac
  got="$(printf 'docs/capability-registries/dex_obs_platforms.tsv\n' | (cd "$ROOT" && bash "$SCRIPT" 2>/dev/null) | tr '\n' ' ')"
  case "$got" in
    *skip_server=false*skip_agent=false*) report 0 "real tree: a capability registry table runs both (class row)" ;;
    *) report 1 "real tree: a capability registry table runs both (class row)" "got: $got" ;;
  esac
fi

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" = 0 ]
