#!/usr/bin/env bash
# test_runner.sh — Run Erlang gateway tests
#
# Usage:
#   ./test_runner.sh                 # Run all tests
#   ./test_runner.sh eunit           # Run only EUnit tests
#   ./test_runner.sh ct              # Run only Common Test suites
#   ./test_runner.sh cover           # Run with coverage
#
# `ct` includes yuzu_gw_perf_SUITE at its FULL default sizing (10k agents,
# 50k heartbeats, 300 s endurance) unless YUZU_PERF_* is set, so expect it
# to run for many minutes -- it is not hung. For a quick functional pass use
# the reduced sizing the Meson gate uses (scripts/test_gateway.py), e.g.
#   YUZU_PERF_AGENTS=10 YUZU_PERF_HEARTBEATS=100 YUZU_PERF_FANOUT=10 \
#   YUZU_PERF_CHURN_AGENTS=10 YUZU_PERF_CHURN_CYCLES=1 \
#   YUZU_PERF_ENDURANCE_AGENTS=10 YUZU_PERF_ENDURANCE_SECS=1 ./test_runner.sh ct
# The full-sizing run is tracked in #4821.
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

log() { echo "[$(date +%H:%M:%S)] $*"; }

# Ensure rebar3 is available
if ! command -v rebar3 &>/dev/null; then
    echo "ERROR: rebar3 not found in PATH"
    exit 1
fi

# Default: run both
RUN_EUNIT=true
RUN_CT=true
RUN_COVER=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        eunit)
            RUN_CT=false
            shift
            ;;
        ct)
            RUN_EUNIT=false
            shift
            ;;
        cover)
            RUN_COVER=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [eunit|ct|cover]"
            echo ""
            echo "  eunit  — Run only EUnit tests"
            echo "  ct     — Run only Common Test suites"
            echo "  cover  — Enable coverage reporting"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Compile first
log "Compiling..."
rebar3 compile

FAILURES=0

# Run EUnit tests
if $RUN_EUNIT; then
    log "Running EUnit tests..."
    if $RUN_COVER; then
        rebar3 as test do eunit --dir apps/yuzu_gw/test,cover || FAILURES=$((FAILURES + 1))
    else
        rebar3 as test eunit --dir apps/yuzu_gw/test || FAILURES=$((FAILURES + 1))
    fi
fi

# Run Common Test suites. They live in apps/yuzu_gw/test/ct/ and ct does not
# recurse: without this --dir, rebar3 discovers zero suites, prints
# "All 0 tests passed." and exits 0, and this script would report ALL TESTS
# PASSED having run nothing (#4800).
if $RUN_CT; then
    log "Running Common Test suites..."
    if $RUN_COVER; then
        rebar3 as test do ct --dir apps/yuzu_gw/test/ct,cover || FAILURES=$((FAILURES + 1))
    else
        rebar3 as test ct --dir apps/yuzu_gw/test/ct || FAILURES=$((FAILURES + 1))
    fi
fi

# Summary
echo ""
log "═══════════════════════════════════════════"
if [[ $FAILURES -eq 0 ]]; then
    log "  ALL TESTS PASSED"
else
    log "  SOME TESTS FAILED"
fi
log "═══════════════════════════════════════════"

exit $FAILURES
