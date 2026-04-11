#!/usr/bin/env bash
# release-preflight.sh — validate that the repo is ready to tag a release.
# Usage: bash scripts/release-preflight.sh v0.9.0 [--full]
#   --full  also compiles C++ and Erlang (adds ~2 min)
set -euo pipefail

TAG="${1:?Usage: release-preflight.sh <tag> [--full]}"
FULL="${2:-}"
VERSION="${TAG#v}"
BASE_VERSION="${VERSION%%-*}"

echo "=== Release Preflight for $TAG (base: $BASE_VERSION) ==="
echo ""

FAILURES=0
pass() { printf "  \033[32mPASS\033[0m  %s\n" "$1"; }
fail() { printf "  \033[31mFAIL\033[0m  %s\n" "$1"; FAILURES=$((FAILURES + 1)); }

# ── 1. CRLF in scripts / Erlang ──────────────────────────────────────────
if grep -rPl '\r$' scripts/*.sh gateway/rebar.config 2>/dev/null; then
    fail "CRLF line endings found (see files above)"
else
    pass "No CRLF in scripts or gateway config"
fi

# ── 2. meson.build version matches tag ────────────────────────────────────
MESON_VER=$(sed -n "s/.*version: '\([^']*\)'.*/\1/p" meson.build | head -1)
if [ "$MESON_VER" = "$BASE_VERSION" ]; then
    pass "meson.build version is $MESON_VER"
else
    fail "meson.build version is '$MESON_VER', expected '$BASE_VERSION'"
fi

# ── 3. CHANGELOG has matching section ─────────────────────────────────────
if grep -q "## \[${BASE_VERSION}\]" CHANGELOG.md; then
    pass "CHANGELOG.md has ## [$BASE_VERSION] section"
else
    fail "CHANGELOG.md missing ## [$BASE_VERSION] section"
fi

# ── 4. Changelog extraction produces content (same AWK as release.yml) ────
EXTRACTED=$(awk "/^## \[${BASE_VERSION}\]/{found=1;next} /^## \[/{if(found) exit} found{print}" CHANGELOG.md)
LINE_COUNT=$(echo "$EXTRACTED" | grep -c '.' || true)
if [ "$LINE_COUNT" -gt 0 ]; then
    pass "Changelog extraction produced $LINE_COUNT lines"
else
    fail "Changelog extraction produced empty output"
fi

# ── 5. Clean working tree ─────────────────────────────────────────────────
if git diff --quiet HEAD && git diff --cached --quiet; then
    pass "Working tree clean (no uncommitted changes)"
else
    fail "Uncommitted changes present — commit or stash first"
fi

# ── 6. Dockerfile.server has --data-dir ───────────────────────────────────
if grep -q 'data-dir' deploy/docker/Dockerfile.server; then
    pass "Dockerfile.server CMD includes --data-dir"
else
    fail "Dockerfile.server CMD missing --data-dir"
fi

# ── 7. All cache steps in release.yml have save-always ────────────────────
CACHE_COUNT=$(grep -c 'actions/cache@v4' .github/workflows/release.yml)
SAVE_ALWAYS_COUNT=$(grep -c 'save-always: true' .github/workflows/release.yml)
if [ "$CACHE_COUNT" -eq "$SAVE_ALWAYS_COUNT" ]; then
    pass "All $CACHE_COUNT cache steps have save-always: true"
else
    fail "$SAVE_ALWAYS_COUNT/$CACHE_COUNT cache steps have save-always: true"
fi

# ── 8. docker-compose.full-uat.yml has --data-dir ─────────────────────────
if grep -q 'data-dir' deploy/docker/docker-compose.full-uat.yml; then
    pass "docker-compose.full-uat.yml includes --data-dir"
else
    fail "docker-compose.full-uat.yml missing --data-dir"
fi

# ── 9. Full build validation (optional) ──────────────────────────────────
if [ "$FULL" = "--full" ]; then
    echo ""
    echo "  --- Full build validation ---"

    # C++ compile
    if [ -d "builddir" ]; then
        echo "  Compiling C++ (meson compile -C builddir)..."
        if meson compile -C builddir > /dev/null 2>&1; then
            pass "C++ compiles"
        else
            fail "C++ compilation failed"
        fi
    else
        fail "No builddir found — run meson setup first"
    fi

    # Erlang compile + dialyzer
    if [ -d "gateway" ]; then
        echo "  Compiling Erlang (rebar3 compile + dialyzer)..."
        if (cd gateway && rebar3 compile > /dev/null 2>&1); then
            pass "Erlang compiles"
        else
            fail "Erlang compilation failed"
        fi
        if (cd gateway && rebar3 dialyzer > /dev/null 2>&1); then
            pass "Dialyzer passes"
        else
            fail "Dialyzer failed"
        fi
    else
        fail "No gateway directory found"
    fi
fi

# ── Summary ───────────────────────────────────────────────────────────────
echo ""
if [ "$FAILURES" -eq 0 ]; then
    printf "=== \033[32mPREFLIGHT PASSED\033[0m for %s ===\n" "$TAG"
    exit 0
else
    printf "=== \033[31mPREFLIGHT FAILED: %d issue(s)\033[0m ===\n" "$FAILURES"
    exit 1
fi
