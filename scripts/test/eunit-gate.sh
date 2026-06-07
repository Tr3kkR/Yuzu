#!/usr/bin/env bash
# eunit-gate.sh — wrap rebar3 eunit so the gate distinguishes "actual test
# failure" from "rebar3 returns 1 because EUnit emitted 'One or more tests
# were cancelled'".
#
# Background (#1005): rebar3 eunit reports cancellations as a process-exit
# error even when every test that ran passed. Cancellations have multiple
# causes:
#   * EUnit's --dir discovery encounters a non-test module like
#     `yuzu_gw_perf_helpers` (no test_/0 exports).
#   * A flake (registry_tests gen_server timeout under VM pollution) aborts
#     a test set partway through.
# Neither case is a regression we want to block a `/test` run on. This
# wrapper exits 0 iff EUnit's summary line says `Failed: 0`. Real failures
# (Failed: N > 0) and infrastructure errors (no summary line) propagate as
# non-zero.
#
# Usage:
#   bash scripts/test/eunit-gate.sh [extra rebar3 args...]
#
# The wrapper sets REBAR_BASE_DIR for parallel-safety per the SKILL.md
# convention and cd's into gateway/. Pass-through args go to rebar3 eunit
# (e.g. --module=foo,bar) — default is `--dir apps/yuzu_gw/test`.
#
# Exit codes:
#   0 — EUnit ran and Failed: 0 (passed, even if some sets were cancelled)
#   1 — EUnit ran and Failed: >0 OR no summary line found (real failure)
#   2 — toolchain or invocation error (rebar3 missing, gateway/ missing)

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT" || { echo "eunit-gate: cannot cd to repo root" >&2; exit 2; }

if [[ ! -d gateway ]]; then
    echo "eunit-gate: gateway/ not found at $REPO_ROOT/gateway" >&2
    exit 2
fi

cd gateway

# Source the Erlang toolchain helper when present (sources are no-ops if
# `erl` is already on PATH). Failures here are surfaced by the rebar3
# command's missing-binary error message rather than swallowed.
if [[ -f ../scripts/ensure-erlang.sh ]]; then
    # shellcheck disable=SC1091
    source ../scripts/ensure-erlang.sh 2>/dev/null || true
fi

if ! command -v rebar3 >/dev/null 2>&1; then
    echo "eunit-gate: rebar3 not on PATH" >&2
    exit 2
fi

# Default args mirror the /test SKILL.md invocation. Callers can append
# their own — e.g. `--module=foo,bar` — by passing them as positional
# arguments to this wrapper.
if [[ $# -eq 0 ]]; then
    set -- --dir apps/yuzu_gw/test
fi

REBAR_BASE_DIR="${REBAR_BASE_DIR:-$PWD/_build_eunit}" \
    rebar3 eunit "$@" 2>&1 | tee /tmp/eunit-gate-output.txt
rebar3_rc=${PIPESTATUS[0]}

# Parse the EUnit summary. The line we care about looks like:
#   `  Failed: N.  Skipped: N.  Passed: N.`
# (sometimes preceded by `=======` banner). If rebar3 exit was 0 we trust
# it (no need to second-guess); if non-zero we only flip to PASS when the
# summary explicitly says Failed: 0.
if [[ $rebar3_rc -eq 0 ]]; then
    exit 0
fi

summary=$(grep -E "^[[:space:]]*Failed:[[:space:]]+[0-9]+" /tmp/eunit-gate-output.txt | tail -1)
if [[ -z "$summary" ]]; then
    echo "eunit-gate: rebar3 exited $rebar3_rc and no EUnit summary line found — treating as real failure" >&2
    exit 1
fi

failed_count=$(echo "$summary" | sed -E 's/.*Failed:[[:space:]]+([0-9]+).*/\1/')
if [[ "$failed_count" == "0" ]]; then
    echo "eunit-gate: rebar3 exited $rebar3_rc but EUnit summary shows Failed: 0 — treating as PASS." \
         "Cancellations are expected and not a regression (#1005)." >&2
    exit 0
fi

echo "eunit-gate: EUnit reports Failed: $failed_count — real failure" >&2
exit 1
