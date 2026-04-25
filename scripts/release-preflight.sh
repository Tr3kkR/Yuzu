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
# grep -c returns 1 when it finds 0 matches; with `set -e` that kills the
# script. `|| true` keeps the preflight going and lets the equality check
# below report the actual issue. Match any cache version (@v4, @v5, ...).
CACHE_COUNT=$(grep -cE 'actions/cache@v[0-9]+' .github/workflows/release.yml || true)
SAVE_ALWAYS_COUNT=$(grep -c 'save-always: true' .github/workflows/release.yml || true)
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

# ── 9. dev / main reconciliation ──────────────────────────────────────────
# Releases tag from main. If main is missing commits that are on dev, the
# tag will not include them — and worse, if main has commits not on dev
# (typical leftover release-prep commits from prior releases), continued
# work on dev keeps diverging silently. This check is hard FAIL per the
# /release skill's "this catches us every time" lesson — surface the
# divergence at preflight rather than at tag-time-or-later.
if git ls-remote --exit-code --heads origin main >/dev/null 2>&1 \
   && git ls-remote --exit-code --heads origin dev >/dev/null 2>&1; then
    git fetch --quiet origin main dev 2>/dev/null || true
    DEV_AHEAD=$(git rev-list --count origin/main..origin/dev 2>/dev/null || echo 0)
    MAIN_AHEAD=$(git rev-list --count origin/dev..origin/main 2>/dev/null || echo 0)
    if [ "$DEV_AHEAD" = "0" ] && [ "$MAIN_AHEAD" = "0" ]; then
        pass "origin/dev and origin/main reconciled (no divergence)"
    else
        fail "origin/dev and origin/main diverged: dev is $DEV_AHEAD ahead, main is $MAIN_AHEAD ahead — reconcile before tagging (see /release skill 'Phase 0.5 — Branch reconciliation')"
    fi
else
    pass "skipping dev/main reconciliation check (one or both branches missing on origin)"
fi

# ── 10. Full build validation (optional) ─────────────────────────────────
if [ "$FULL" = "--full" ]; then
    echo ""
    echo "  --- Full build validation ---"

    # Per-OS canonical build directory (mirrors scripts/setup.sh).
    if [[ "$(uname -s)" == MINGW* ]] || [[ "$(uname -s)" == MSYS* ]] || [[ "${OS:-}" == "Windows_NT" ]]; then
        BUILDDIR="build-windows"
    elif [[ "$(uname -s)" == "Darwin" ]]; then
        BUILDDIR="build-macos"
    else
        BUILDDIR="build-linux"
    fi

    # Erlang toolchain — required by both the standalone rebar3 step and the
    # gateway custom_target inside meson, so it must be on PATH before the C++
    # compile too. ensure-erlang.sh probes kerl, asdf, Homebrew, and the MSYS2
    # installer paths in turn; it always returns 0, so we verify with command -v.
    # The explicit "28" arg is load-bearing: a sourced script inherits the
    # caller's positional args, so without it the helper would receive "$1"
    # from THIS script (e.g. "v0.10.0") and search for a kerl install with
    # that name. Pass the major version explicitly to track release.yml's
    # erlef/setup-beam otp-version.
    # shellcheck source=ensure-erlang.sh
    source "$(dirname "$0")/ensure-erlang.sh" 28
    HAVE_ERL=0
    if command -v erl > /dev/null 2>&1; then
        HAVE_ERL=1
        pass "Erlang on PATH ($(erl -version 2>&1 | tr -d '\n'))"
    else
        fail "Erlang not on PATH after ensure-erlang.sh — install via kerl/asdf/brew or activate manually"
    fi

    # C++ compile
    if [ -d "$BUILDDIR" ]; then
        echo "  Compiling C++ (meson compile -C $BUILDDIR)..."
        if meson compile -C "$BUILDDIR" > /dev/null 2>&1; then
            pass "C++ compiles"
        else
            fail "C++ compilation failed"
        fi
    else
        fail "No $BUILDDIR found — run scripts/setup.sh first"
    fi

    # Erlang compile + dialyzer (skipped if erl missing — already failed above)
    if [ "$HAVE_ERL" -eq 1 ] && [ -d "gateway" ]; then
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
    elif [ ! -d "gateway" ]; then
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
