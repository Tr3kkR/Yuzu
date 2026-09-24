#!/usr/bin/env bash
# affected-suites.sh — fail-closed classifier: which heavy meson test suites can a PR reach?
#
# Without it, ci.yml's PR fast-path would run every suite on every leg. The two heavy families are
#
#   server  suites server-nonpg, server-pg, server-pg-smoke (yuzu_server_tests: 12 Postgres shards,
#           the slowest step on Windows and Linux) and server-checks
#   agent   suites agent, tar (the agent and tar test binaries: the single longest test entry on
#           macOS and Windows)
#
# A PR whose changed paths cannot reach a family's build inputs or run-time inputs cannot change
# that family's results, and every push to dev/main still runs the full matrix, so the PR run skips
# the family. The docs, proto and gateway suites always run.
#
# Input (stdin): one changed path per line, as scripts/ci/pr-changed-paths.sh prints it from the
#   merge commit CI builds (a rename is two lines, the old path and the new, so the source of a
#   rename out of a heavy directory is classified too).
# Output (stdout): exactly two lines
#     skip_server=true|false
#     skip_agent=true|false
# Diagnostics go to stderr. Every uncertainty prints false/false (run everything): an empty list; a
# path that cannot be read back exactly (C-quoted by git, a TAB or backslash in it, absolute, or a
# `..` component); a missing or unreadable tests tree or tests/meson.build, or a symlink inside the
# tests tree; a scan or temp-directory failure.
#
# THE CLASS TABLE lives in classify_path below and nowhere else: this comment,
# docs/ci-architecture.md and `--classify PATH` all defer to it. What the classes mean (the first
# matching arm wins; a path no arm names is `both`, so an unknown path runs everything):
#   both    can affect either family: the build graph and CI infrastructure, the code both
#           binaries are built from (agents/ is `both` because the server test binary includes 15
#           agents/core headers), the test-tree files they share, docs/capability-registries/,
#           any .gitattributes (it changes line endings on checkout), and anything unrecognised
#   server  reaches only the server family (server/, content/, tests/unit/server/)
#   agent   reaches only the agent family (the agent/tar test translation units)
#   none    text no compiled test reads at build time: docs, changelog and ledger fragments,
#           agent-config directories, gateway, deploy, site, the non-C++ test drivers, the runner
#           inventory, and an explicit allowlist of inert root files
#
# The one derived rule (RUN-TIME READS). A test can read a file that is in no build graph — the
# tables under docs/capability-registries/, docs/user-manual/metrics.md. So a path that would leave
# a family unaffected still affects it when a test source of that family names the path verbatim:
# the server tests are tests/unit/server/ plus the shared helper headers directly under
# tests/unit/, the agent tests are the rest of tests/unit/, and tests/meson.build counts for both.
# The scan is deliberately over-broad — an error string that merely mentions a path counts —
# because a false run costs minutes and a false skip costs a red dev. Its blind spots: a path
# assembled at run time from parts (`base + "user-manual/x.md"`), so keep a run-time read to one
# literal path; tests/meson.build names files relative to tests/ (`unit/x`, `prometheus/y`), which
# never equal a repo-relative path; and production code under server/ or agents/ that names a path
# is not scanned, only tests are.
#
# The class table is proven against the real build by scripts/ci/check-suite-input-closure.py,
# which classifies every compile-time input of both families through --classify-many (no
# agent-family object may depend on a `server` or `none` path, no server-family object on an
# `agent` or `none` path). This file's own cases are tests/shell/test_affected_suites.sh; the
# ci.yml step bodies that apply the verdict are tests/shell/test_suite_selection_wiring.sh.
#
# Usage:
#   affected-suites.sh [--tests-root DIR] < changed-paths
#   affected-suites.sh --classify PATH             print one path's class (both|server|agent|none)
#   affected-suites.sh --classify-many < paths     one `path<TAB>class` line per input path
# Locally, for a branch (GNU grep expected; BSD grep is quadratic in the number of changed paths):
#   git diff --no-renames --name-only origin/dev...HEAD | bash scripts/ci/affected-suites.sh
#
# Run tests:  bash tests/shell/test_affected_suites.sh
set -euo pipefail

tests_root="tests/unit"
classify_only=""
classify_many=false

usage() {
  cat >&2 <<'EOF'
usage:
  affected-suites.sh [--tests-root DIR] < changed-paths
  affected-suites.sh --classify PATH
  affected-suites.sh --classify-many < paths
EOF
  exit 2
}

while (( $# )); do
  case "$1" in
    --tests-root)    (( $# >= 2 )) || usage; tests_root="$2"; shift 2 ;;
    --classify)      (( $# >= 2 )) || usage; classify_only="$2"; shift 2 ;;
    --classify-many) classify_many=true; shift ;;
    *)               usage ;;
  esac
done

emit_all_run() {
  printf 'skip_server=false\nskip_agent=false\n'
  exit 0
}

# classify_path PATH -> both | server | agent | none
classify_path() {
  case "$1" in
    # --- line endings on checkout: can change what any test reads, wherever the file sits ---
    .gitattributes|*/.gitattributes) echo both ;;
    # --- build graph and CI infrastructure: decides how ANY suite is built or run ---
    meson.build|*/meson.build|meson.options|meson/*|vcpkg.json|vcpkg-configuration.json|vcpkg-native.ini|triplets/*|requirements-ci.*|setup_msvc_env.sh|Makefile) echo both ;;
    # the runner inventory feeds only preflight's health check; the docs-only gate treats it as
    # docs, and ci.yml builds any PR this table says a test family can reach, so the two must agree
    .github/runner-inventory.json|.github/workflows/runner-inventory-sentinel.yml) echo none ;;
    .github/*|scripts/*|tools/*|.clusterfuzzlite/*) echo both ;;
    # --- code the binaries are built from ---
    agents/*|common/*|sdk/*|proto/*|enterprise/*) echo both ;;
    server/*|content/*) echo server ;;
    # --- the test tree ---
    tests/unit/server/*) echo server ;;
    tests/unit/agent/*) echo agent ;;
    tests/unit/test_runner_main.cpp) echo both ;;      # the one non-server file the server binary compiles
    tests/unit/*/*) echo both ;;                       # fixtures and any subdirectory not named above
    tests/unit/*.cpp) echo agent ;;
    tests/unit/*) echo both ;;                         # shared helper headers (test_helpers.hpp, ...)
    tests/meson.build|tests/fixtures/*|tests/fuzz/*) echo both ;;
    tests/shell/*|tests/prometheus/*|tests/puppeteer/*) echo none ;;
    tests/*/*) echo both ;;                            # an unrecognised test subtree
    tests/*) echo none ;;                              # top-level tests/*.py etc: the docs suite
    # --- text and tooling no compiled test reads (subject to the run-time-read rule) ---
    docs/capability-registries/*) echo both ;;         # read as data by server and agent tests
    docs/*|changelog.d/*|governance.d/*|.claude/*|.codex/*|gateway/*|deploy/*|site/*) echo none ;;
    */*) echo both ;;                                  # any other directory: unknown
    # --- root-level files: only an explicit allowlist is inert; .clang-* and any file not named
    # here are unknown, so both ---
    *.md|LICENSE|NOTICE|.gitignore|.dockerignore|.editorconfig|.pre-commit-config.yaml) echo none ;;
    docker-compose*.yml|cliff.toml|Synthetic-UAT-Puppeteer.js) echo none ;;
    *) echo both ;;
  esac
}

if [[ -n "$classify_only" ]]; then
  classify_path "$classify_only"
  exit 0
fi

if [[ "$classify_many" == true ]]; then
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -z "$line" ]] && continue
    printf '%s\t%s\n' "$line" "$(classify_path "$line")"
  done
  exit 0
fi

# --- read the list -------------------------------------------------------------------------------
paths=()
while IFS= read -r line || [[ -n "$line" ]]; do
  [[ -z "$line" ]] && continue
  # Not readable back exactly: git C-quotes a path holding a quote, backslash or control character
  # (it then starts with `"`), and a raw TAB or backslash means the list did not come from git.
  # An absolute path or a `..` component cannot be a repository-relative name either.
  if [[ "$line" == *\\* || "$line" == *$'\t'* || "$line" == \"* || "$line" == /* ||
        "$line" == .. || "$line" == ../* || "$line" == */../* || "$line" == */.. ]]; then
    echo "affected-suites: path cannot be classified exactly ($line) -> running everything (fail-closed)" >&2
    emit_all_run
  fi
  paths+=("$line")
done

if (( ${#paths[@]} == 0 )); then
  echo "affected-suites: empty path list -> running everything (fail-closed)" >&2
  emit_all_run
fi
meson_file="$(dirname "$tests_root")/meson.build"
if [[ ! -d "$tests_root" || ! -f "$meson_file" ]]; then
  echo "affected-suites: tests tree '$tests_root' or '$meson_file' not found, so run-time reads cannot be checked -> running everything (fail-closed)" >&2
  emit_all_run
fi

# --- pass 1: the class table --------------------------------------------------------------------
server_why=""   # first path that forces the server family to run
agent_why=""
candidates=()   # paths that pass 1 leaves unaffecting for at least one family
for p in "${paths[@]}"; do
  cls="$(classify_path "$p")"
  case "$cls" in
    both)   [[ -n "$server_why" ]] || server_why="$p (class both)"
            [[ -n "$agent_why" ]]  || agent_why="$p (class both)" ;;
    server) [[ -n "$server_why" ]] || server_why="$p (class server)"
            candidates+=("$p") ;;
    agent)  [[ -n "$agent_why" ]]  || agent_why="$p (class agent)"
            candidates+=("$p") ;;
    *)      candidates+=("$p") ;;
  esac
done

# --- pass 2: run-time reads ---------------------------------------------------------------------
# One fixed-string scan per family over every candidate path. Only paths that some family would
# still skip are worth scanning, and once both families are already forced to run there is nothing
# left to decide.
if [[ ( -z "$server_why" || -z "$agent_why" ) && ${#candidates[@]} -gt 0 ]]; then
  if [[ ! -d "$tests_root/server" ]]; then
    echo "affected-suites: '$tests_root/server' not found, so run-time reads cannot be checked -> running everything (fail-closed)" >&2
    emit_all_run
  fi
  # grep -r does not follow a symlink inside the tree, so a read behind one would go unseen.
  if [[ -n "$(find "$tests_root" -type l 2>/dev/null | head -n 1)" ]]; then
    echo "affected-suites: a symlink under '$tests_root' cannot be scanned reliably -> running everything (fail-closed)" >&2
    emit_all_run
  fi
  work="$(mktemp -d "${TMPDIR:-/tmp}/yuzu-affected-suites.XXXXXX")" || {
    echo "affected-suites: no temporary directory -> running everything (fail-closed)" >&2
    emit_all_run
  }
  trap 'rm -rf "$work"' EXIT
  printf '%s\n' "${candidates[@]}" > "$work/patterns"

  # scan_to <out-file> <grep path args...>: the candidate paths a set of sources names verbatim.
  # -a: a source grep would call binary (a NUL, or invalid UTF-8 under a UTF-8 locale) is still
  # searched; GNU grep >= 3.5 otherwise prints nothing for it, which would read as "not named".
  # grep exits 1 for "no match", which is the normal case; anything above 1 is an error, and an
  # error must not read as "no reader found". Called in the main shell, never inside $(...), so
  # the fail-closed exit really ends the script.
  scan_to() {
    local out="$1" rc=0
    shift
    grep -rahoF -f "$work/patterns" "$@" > "$out" 2>/dev/null || rc=$?
    if (( rc > 1 )); then
      echo "affected-suites: scan of '$*' failed (grep exit $rc) -> running everything (fail-closed)" >&2
      emit_all_run
    fi
  }

  scan_to "$work/meson" "$meson_file"
  # The server binary compiles tests/unit/server/ AND the helper headers directly under tests/unit/
  # (test_helpers.hpp, ...), so a read placed in a shared helper belongs to the server family too.
  server_sources=("$tests_root/server")
  for helper in "$tests_root"/*.hpp; do
    if [[ -f "$helper" ]]; then server_sources+=("$helper"); fi
  done
  scan_to "$work/server" "${server_sources[@]}"
  scan_to "$work/agent" --exclude-dir=server "$tests_root"

  if [[ -z "$server_why" ]]; then
    hit="$(cat "$work/server" "$work/meson" | sed -n 1p)"
    [[ -z "$hit" ]] || server_why="$hit (named by a server test, a shared test helper or tests/meson.build)"
  fi
  if [[ -z "$agent_why" ]]; then
    hit="$(cat "$work/agent" "$work/meson" | sed -n 1p)"
    [[ -z "$hit" ]] || agent_why="$hit (named by an agent test, a shared test helper or tests/meson.build)"
  fi
fi

if [[ -n "$server_why" ]]; then
  echo "affected-suites: server suites run - $server_why" >&2
else
  echo "affected-suites: server suites SKIPPED - no changed path reaches them" >&2
fi
if [[ -n "$agent_why" ]]; then
  echo "affected-suites: agent suites run - $agent_why" >&2
else
  echo "affected-suites: agent suites SKIPPED - no changed path reaches them" >&2
fi

printf 'skip_server=%s\n' "$([[ -z "$server_why" ]] && echo true || echo false)"
printf 'skip_agent=%s\n'  "$([[ -z "$agent_why" ]] && echo true || echo false)"
