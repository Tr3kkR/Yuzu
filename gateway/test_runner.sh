#!/usr/bin/env bash
# test_runner.sh — Run Erlang gateway tests
#
# Usage:
#   ./test_runner.sh                 # Run all tests
#   ./test_runner.sh eunit           # Run only EUnit tests
#   ./test_runner.sh ct              # Run only Common Test suites
#   ./test_runner.sh cover           # Run with coverage
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
        rebar3 as test do eunit,cover || FAILURES=$((FAILURES + 1))
    else
        rebar3 as test eunit || FAILURES=$((FAILURES + 1))
    fi
fi

# Run Common Test suites
if $RUN_CT; then
    log "Running Common Test suites..."
    if $RUN_COVER; then
        rebar3 as test do ct,cover || FAILURES=$((FAILURES + 1))
    else
        rebar3 as test ct || FAILURES=$((FAILURES + 1))
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
