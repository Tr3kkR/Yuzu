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
# wrapper exits 0 iff EUnit's summary line says `Failed: 0` AND at least one
# test EXECUTED. Real failures (Failed: N > 0), infrastructure errors (no
# summary line) and zero-executed runs propagate as non-zero. The executed
# check matters because a set-up that crashes in EVERY module prints
# `Failed: 0.  Skipped: 0.  Passed: 0.` plus "One or more tests were
# cancelled" -- an all-cancelled run that would otherwise read as a pass
# (the #4800 false-green class; scripts/test_gateway.py applies the same rule
# via scripts/gateway_test_summary.py).
#
# Usage:
#   bash scripts/test/eunit-gate.sh [extra rebar3 args...]
#
# The wrapper sets REBAR_BASE_DIR for parallel-safety per the SKILL.md
# convention and cd's into gateway/. Pass-through args go to rebar3 eunit
# (e.g. --module=foo,bar) — default is `--dir apps/yuzu_gw/test`.
#
# Exit codes:
#   0 — EUnit ran, Failed: 0, and >= 1 test executed (passed, even if some
#       sets were cancelled)
#   1 — EUnit ran and Failed: >0, OR no summary line found, OR 0 tests
#       executed (real failure)
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

# Parse the EUnit summary. It is one of:
#   `  All N tests passed.`                      (rc 0)
#   `  Test passed.`                             (rc 0, exactly one test)
#   `  Failed: N.  Skipped: N.  Passed: N.`      (failures and/or cancellations)
#   `  There were no tests to run.`
# Neither rc 0 nor Failed: 0 proves anything ran, so both paths also require
# a nonzero executed (failed + passed) count (#4800).
out=$(sed -E 's/\x1b\[[0-9;]*[A-Za-z]//g' /tmp/eunit-gate-output.txt)
executed=""
if line=$(grep -E "All [0-9]+ tests? passed\." <<<"$out" | tail -1) && [[ -n "$line" ]]; then
    executed=$(sed -E 's/.*All ([0-9]+) tests? passed\..*/\1/' <<<"$line")
elif grep -qE "(^|[^A-Za-z])Test passed\." <<<"$out"; then
    executed=1
fi
summary=$(grep -E "^[[:space:]]*Failed:[[:space:]]+[0-9]+" <<<"$out" | tail -1)
if [[ -n "$summary" ]]; then
    failed_count=$(sed -E 's/.*Failed:[[:space:]]+([0-9]+).*/\1/' <<<"$summary")
    passed_count=$(sed -E 's/.*Passed:[[:space:]]+([0-9]+).*/\1/' <<<"$summary")
    executed=$(( failed_count + passed_count ))
fi

if [[ -z "$executed" ]]; then
    echo "eunit-gate: rebar3 exited $rebar3_rc and no EUnit summary line found — treating as real failure" >&2
    exit 1
fi
if [[ "$executed" -eq 0 ]]; then
    echo "eunit-gate: EUnit executed ZERO tests (every set cancelled, or nothing discovered) — treating as real failure (#4800)" >&2
    exit 1
fi

if [[ $rebar3_rc -eq 0 ]]; then
    exit 0
fi

if [[ -z "$summary" ]]; then
    echo "eunit-gate: rebar3 exited $rebar3_rc with no Failed/Passed summary — treating as real failure" >&2
    exit 1
fi
if [[ "$failed_count" == "0" ]]; then
    echo "eunit-gate: rebar3 exited $rebar3_rc but EUnit summary shows Failed: 0 — treating as PASS." \
         "Cancellations are expected and not a regression (#1005)." >&2
    exit 0
fi

echo "eunit-gate: EUnit reports Failed: $failed_count — real failure" >&2
exit 1
