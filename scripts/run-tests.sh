#!/usr/bin/env bash
# run-tests.sh — Orchestrate all Yuzu test suites
#
# Usage:
#   ./scripts/run-tests.sh                    # Run all test tiers
#   ./scripts/run-tests.sh unit               # C++ unit tests only
#   ./scripts/run-tests.sh erlang-unit        # Erlang EUnit tests only
#   ./scripts/run-tests.sh erlang-ct          # Erlang Common Test suites only
#   ./scripts/run-tests.sh erlang-perf        # Erlang performance tests only
#   ./scripts/run-tests.sh integration        # Full-stack integration tests
#   ./scripts/run-tests.sh all                # Everything (same as no args)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILDDIR="$PROJECT_ROOT/builddir"
GATEWAY_DIR="$PROJECT_ROOT/gateway"
TIER="${1:-all}"

PASS=0
FAIL=0
SKIP=0

banner() { echo ""; echo "══════════════════════════════════════════════════"; echo "  $1"; echo "══════════════════════════════════════════════════"; }
pass()   { PASS=$((PASS + 1)); echo "  ✓ $1"; }
fail()   { FAIL=$((FAIL + 1)); echo "  ✗ $1"; }
skip()   { SKIP=$((SKIP + 1)); echo "  ⊘ $1 (skipped)"; }

# ── Tier 1: C++ Unit Tests ──────────────────────────────────────────
run_cpp_unit() {
    banner "C++ UNIT TESTS (Catch2)"

    if [[ ! -d "$BUILDDIR" ]]; then
        fail "Build directory not found. Run: meson setup builddir -Dbuild_tests=true"
        return
    fi

    # Compile tests
    echo "  Building test executables..."
    if ! meson compile -C "$BUILDDIR" yuzu_agent_tests yuzu_server_tests 2>&1 | tail -5; then
        fail "C++ test compilation failed"
        return
    fi

    # Run agent tests
    echo ""
    echo "  Running agent unit tests..."
    if "$BUILDDIR/tests/yuzu_agent_tests" --reporter compact 2>&1; then
        pass "Agent unit tests"
    else
        fail "Agent unit tests"
    fi

    # Run server tests
    echo ""
    echo "  Running server unit tests..."
    if "$BUILDDIR/tests/yuzu_server_tests" --reporter compact 2>&1; then
        pass "Server unit tests"
    else
        fail "Server unit tests"
    fi
}

# ── Tier 2: Erlang EUnit Tests ──────────────────────────────────────
run_erlang_unit() {
    banner "ERLANG EUNIT TESTS"

    if ! command -v rebar3 &>/dev/null; then
        skip "rebar3 not found"
        return
    fi

    cd "$GATEWAY_DIR"
    echo "  Running EUnit tests..."
    if rebar3 eunit 2>&1 | tail -20; then
        pass "Erlang EUnit tests"
    else
        fail "Erlang EUnit tests"
    fi
    cd "$PROJECT_ROOT"
}

# ── Tier 3: Erlang Common Test Suites ───────────────────────────────
run_erlang_ct() {
    banner "ERLANG COMMON TEST SUITES"

    if ! command -v rebar3 &>/dev/null; then
        skip "rebar3 not found"
        return
    fi

    cd "$GATEWAY_DIR"

    CT_DIR="apps/yuzu_gw/test"

    # E2E suite
    echo "  Running e2e suite..."
    if rebar3 ct --dir "$CT_DIR" --suite=yuzu_gw_e2e_SUITE 2>&1 | tail -10; then
        pass "Gateway E2E suite"
    else
        fail "Gateway E2E suite"
    fi

    # Integration suite
    echo ""
    echo "  Running integration suite..."
    if rebar3 ct --dir "$CT_DIR" --suite=yuzu_gw_integration_SUITE 2>&1 | tail -10; then
        pass "Gateway integration suite"
    else
        fail "Gateway integration suite"
    fi

    # Metrics E2E suite
    echo ""
    echo "  Running metrics E2E suite..."
    if rebar3 ct --dir "$CT_DIR" --suite=yuzu_gw_metrics_e2e_SUITE 2>&1 | tail -10; then
        pass "Gateway metrics E2E suite"
    else
        fail "Gateway metrics E2E suite"
    fi

    # Prometheus endpoint suite
    echo ""
    echo "  Running Prometheus endpoint suite..."
    if rebar3 ct --dir "$CT_DIR" --suite=yuzu_gw_prometheus_SUITE 2>&1 | tail -10; then
        pass "Gateway Prometheus endpoint suite"
    else
        fail "Gateway Prometheus endpoint suite"
    fi

    cd "$PROJECT_ROOT"
}

# ── Tier 4: Erlang Performance Tests ───────────────────────────────
run_erlang_perf() {
    banner "ERLANG PERFORMANCE TESTS"

    if ! command -v rebar3 &>/dev/null; then
        skip "rebar3 not found"
        return
    fi

    cd "$GATEWAY_DIR"
    echo "  Running performance suite (this may take several minutes)..."
    echo "  Configure with: YUZU_PERF_AGENTS=N YUZU_PERF_HEARTBEATS=N"
    if rebar3 ct --suite=yuzu_gw_perf_SUITE --verbose 2>&1 | tail -30; then
        pass "Gateway performance tests"
    else
        fail "Gateway performance tests"
    fi
    cd "$PROJECT_ROOT"
}

# ── Tier 5: Full-Stack Integration Tests ────────────────────────────
run_integration() {
    banner "FULL-STACK INTEGRATION TESTS"

    if [[ ! -x "$SCRIPT_DIR/integration-test.sh" ]]; then
        fail "integration-test.sh not found"
        return
    fi

    echo "  Running full-stack integration test (Agent → Gateway → Server)..."
    if "$SCRIPT_DIR/integration-test.sh" --agents 2 2>&1; then
        pass "Full-stack integration test"
    else
        fail "Full-stack integration test"
    fi
}

# ── Dispatch ────────────────────────────────────────────────────────
case "$TIER" in
    unit)          run_cpp_unit ;;
    erlang-unit)   run_erlang_unit ;;
    erlang-ct)     run_erlang_ct ;;
    erlang-perf)   run_erlang_perf ;;
    integration)   run_integration ;;
    all)
        run_cpp_unit
        run_erlang_unit
        run_erlang_ct
        run_integration
        # Perf tests are opt-in (slow)
        echo ""
        echo "  Note: Performance tests skipped by default."
        echo "  Run:  ./scripts/run-tests.sh erlang-perf"
        ;;
    *)
        echo "Unknown tier: $TIER"
        echo "Usage: $0 [unit|erlang-unit|erlang-ct|erlang-perf|integration|all]"
        exit 1
        ;;
esac

# ── Summary ─────────────────────────────────────────────────────────
banner "TEST SUMMARY"
TOTAL=$((PASS + FAIL + SKIP))
echo ""
echo "  Passed:  $PASS"
echo "  Failed:  $FAIL"
echo "  Skipped: $SKIP"
echo "  Total:   $TOTAL"
echo ""

if [[ $FAIL -gt 0 ]]; then
    echo "  RESULT: FAILED"
    exit 1
else
    echo "  RESULT: PASSED"
    exit 0
fi
