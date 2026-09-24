#!/usr/bin/env bash
# affected-suites.sh — fail-closed classifier: which heavy meson test suites can a PR reach?
#
# ci.yml's PR fast-path runs every suite on every leg. The two heavy families are
#
#   server  the yuzu_server_tests binary — suites server-nonpg, server-pg, server-pg-smoke,
#           server-checks (12 Postgres shards, the slowest step on Windows and Linux)
#   agent   the yuzu_agent_tests / yuzu_tar_tests binaries — suites agent, tar (the single
#           longest test entry on macOS and Windows)
#
# A PR whose changed paths cannot reach a family's build inputs or run-time inputs cannot change
# that family's results, and every push to dev/main still runs the full matrix, so the PR run skips
# the family. The docs, proto and gateway suites always run.
#
# Input (stdin): one changed FILE per line, `path` or `path<TAB>previous_path` (the latter for a
#   rename, so the source of a rename out of a heavy directory is classified too — the GitHub files
#   API reports only the new name in `.filename`). Produce it with:
#     gh api --paginate repos/O/R/pulls/N/files \
#       --jq '.[] | [.filename, (.previous_filename // "")] | @tsv'
# Output (stdout): exactly two lines
#     skip_server=true|false
#     skip_agent=true|false
# Diagnostics go to stderr. Every uncertainty prints false/false (run everything): an empty list, a
# list shorter or longer than --total (the API caps a PR's file list at 3000), a path that cannot be
# read back exactly (a backslash from jq's @tsv escaping, a C-quoted path), an unreadable tests root.
#
# Classes (first match wins; a path in none of them is `both`, so an unknown path runs everything):
#   both    build graph and CI infrastructure (any meson.build, meson.options, vcpkg*, triplets,
#           .github, scripts, tools), everything in agents/ common/ sdk/ proto/ (server tests include
#           15 agents/core headers; nothing narrower than the directory is proven), and the test-tree
#           files both binaries share (tests/meson.build, tests/unit/*.hpp, test_runner_main.cpp,
#           fixtures)
#   server  server/, content/ (embedded into the server binary), tests/unit/server/
#   agent   tests/unit/*.cpp and tests/unit/agent/* — the agent/tar test translation units
#   none    text no compiled test reads: docs/, changelog.d/, governance.d/, .claude/, .codex/,
#           gateway/, deploy/, site/, tests/{shell,prometheus,puppeteer}/, top-level tests/* files,
#           root *.md, LICENSE, NOTICE and the inert dotfiles (.gitignore, .dockerignore,
#           .editorconfig, .pre-commit-config.yaml); any other root file is `both`
#
# The one derived rule (RUN-TIME READS). A test can read a file that is in no build graph — the
# tables under docs/capability-registries/, docs/user-manual/metrics.md. So a path that would leave
# a family unaffected still affects it when a test source of that family names the path verbatim:
# the server tests are tests/unit/server/, the agent tests are the rest of tests/unit/, and
# tests/meson.build counts for both. The scan is deliberately over-broad — an error string that
# merely mentions a path counts — because a false run costs minutes and a false skip costs a red
# dev. Its blind spot is a path assembled at run time from parts (`base + "user-manual/x.md"`): keep
# a run-time read to one literal path, or the reader is invisible to this script.
#
# Soundness of the class table is checked against the real build by
# scripts/ci/check-suite-input-closure.py (no agent-side object includes a server-side file, no
# server-side object compiles an agent test); this file's own cases are tests/shell/test_affected_suites.sh.
#
# Usage:
#   affected-suites.sh [--total N] [--tests-root DIR] < changed-files
#   affected-suites.sh --classify PATH             print one path's class (both|server|agent|none)
# Locally, for a branch:
#   git diff --no-renames --name-only origin/dev...HEAD | bash scripts/ci/affected-suites.sh
#
# Run tests:  bash tests/shell/test_affected_suites.sh
set -euo pipefail

tests_root="tests/unit"
expected_total=""
classify_only=""

usage() {
  cat >&2 <<'EOF'
usage:
  affected-suites.sh [--total N] [--tests-root DIR] < changed-files
  affected-suites.sh --classify PATH [--tests-root DIR]
EOF
  exit 2
}

while (( $# )); do
  case "$1" in
    --total)       (( $# >= 2 )) || usage; expected_total="$2"; shift 2 ;;
    --tests-root)  (( $# >= 2 )) || usage; tests_root="$2"; shift 2 ;;
    --classify)    (( $# >= 2 )) || usage; classify_only="$2"; shift 2 ;;
    *)             usage ;;
  esac
done

emit_all_run() {
  printf 'skip_server=false\nskip_agent=false\n'
  exit 0
}

# classify_path PATH -> both | server | agent | none
classify_path() {
  case "$1" in
    # --- build graph and CI infrastructure: decides how ANY suite is built or run ---
    meson.build|*/meson.build|meson.options|meson/*|vcpkg.json|vcpkg-configuration.json|vcpkg-native.ini|triplets/*|requirements-ci.*|setup_msvc_env.sh|Makefile) echo both ;;
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
    # --- root-level files: only an explicit allowlist is inert; .gitattributes (line endings on
    # checkout), .clang-*, and any file not named here are unknown, so both ---
    *.md|LICENSE|NOTICE|.gitignore|.dockerignore|.editorconfig|.pre-commit-config.yaml) echo none ;;
    docker-compose*.yml|cliff.toml|Synthetic-UAT-Puppeteer.js) echo none ;;
    *) echo both ;;
  esac
}

if [[ -n "$classify_only" ]]; then
  classify_path "$classify_only"
  exit 0
fi

# --- read the list -------------------------------------------------------------------------------
paths=()
n_files=0
while IFS= read -r line || [[ -n "$line" ]]; do
  [[ -z "$line" ]] && continue
  n_files=$((n_files + 1))
  new_path="${line%%$'\t'*}"
  old_path=""
  [[ "$line" == *$'\t'* ]] && old_path="${line#*$'\t'}"
  for p in "$new_path" "$old_path"; do
    [[ -z "$p" ]] && continue
    # Not readable back exactly: jq's @tsv turns tab/newline/backslash into a backslash escape and
    # git C-quotes control characters. Either way the prefix cannot be trusted.
    if [[ "$p" == *\\* || "$p" == \"* || "$p" == /* || "$p" == ../* || "$p" == */../* ]]; then
      echo "affected-suites: path cannot be classified exactly ($p) -> running everything (fail-closed)" >&2
      emit_all_run
    fi
    paths+=("$p")
  done
done

if (( n_files == 0 )); then
  echo "affected-suites: empty file list -> running everything (fail-closed)" >&2
  emit_all_run
fi
if [[ -n "$expected_total" ]]; then
  if [[ ! "$expected_total" =~ ^[0-9]+$ ]]; then
    echo "affected-suites: invalid --total '$expected_total' -> running everything (fail-closed)" >&2
    emit_all_run
  fi
  if (( n_files != expected_total )); then
    echo "affected-suites: received $n_files of $expected_total files (truncated or inconsistent) -> running everything (fail-closed)" >&2
    emit_all_run
  fi
fi
if [[ ! -d "$tests_root" ]]; then
  echo "affected-suites: tests root '$tests_root' not found, so run-time reads cannot be checked -> running everything (fail-closed)" >&2
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
  work="$(mktemp -d "${TMPDIR:-/tmp}/yuzu-affected-suites.XXXXXX")"
  trap 'rm -rf "$work"' EXIT
  printf '%s\n' "${candidates[@]}" > "$work/patterns"

  # scan_to <out-file> <grep path args...>: the candidate paths a set of sources names verbatim.
  # grep exits 1 for "no match", which is the normal case; anything above 1 is an error, and an
  # error must not read as "no reader found". Called in the main shell, never inside $(...), so the
  # fail-closed exit really ends the script.
  scan_to() {
    local out="$1" rc=0
    shift
    grep -rhoF -f "$work/patterns" "$@" > "$out" 2>/dev/null || rc=$?
    if (( rc > 1 )); then
      echo "affected-suites: scan of '$*' failed (grep exit $rc) -> running everything (fail-closed)" >&2
      emit_all_run
    fi
  }

  : > "$work/meson"
  meson_file="$(dirname "$tests_root")/meson.build"
  if [[ -f "$meson_file" ]]; then scan_to "$work/meson" "$meson_file"; fi
  scan_to "$work/server" "$tests_root/server"
  scan_to "$work/agent" --exclude-dir=server "$tests_root"

  if [[ -z "$server_why" ]]; then
    hit="$(cat "$work/server" "$work/meson" | sed -n 1p)"
    [[ -z "$hit" ]] || server_why="$hit (named by a server test or tests/meson.build)"
  fi
  if [[ -z "$agent_why" ]]; then
    hit="$(cat "$work/agent" "$work/meson" | sed -n 1p)"
    [[ -z "$hit" ]] || agent_why="$hit (named by an agent test or tests/meson.build)"
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
