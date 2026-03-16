#!/bin/bash
# lint.sh — Run clang-format and/or clang-tidy on Yuzu source files.
#
# Usage:
#   ./scripts/lint.sh              # run both format + tidy checks
#   ./scripts/lint.sh --format     # format check only
#   ./scripts/lint.sh --tidy       # tidy check only (needs builddir)
#   ./scripts/lint.sh --fix        # auto-fix format issues in-place
#   ./scripts/lint.sh --all-files  # check all files, not just changed ones
set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
RUN_FORMAT=false
RUN_TIDY=false
FIX_MODE=false
ALL_FILES=false
BUILDDIR="builddir"

# ── Parse args ────────────────────────────────────────────────────────────────
if [ $# -eq 0 ]; then
    RUN_FORMAT=true
    RUN_TIDY=true
fi

while [ $# -gt 0 ]; do
    case "$1" in
        --format)    RUN_FORMAT=true ;;
        --tidy)      RUN_TIDY=true ;;
        --all)       RUN_FORMAT=true; RUN_TIDY=true ;;
        --fix)       FIX_MODE=true; RUN_FORMAT=true ;;
        --all-files) ALL_FILES=true ;;
        --builddir)  shift; BUILDDIR="$1" ;;
        -h|--help)
            sed -n '2,8p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
    shift
done

# ── Locate tools ──────────────────────────────────────────────────────────────
find_tool() {
    local name="$1"
    local min_ver="$2"
    # Try versioned name first (e.g. clang-format-17), then plain name
    for candidate in "${name}-17" "${name}-18" "${name}"; do
        if command -v "$candidate" &>/dev/null; then
            local ver
            ver=$("$candidate" --version 2>&1 | grep -oP '\d+' | head -1)
            if [ "$ver" -ge "$min_ver" ] 2>/dev/null; then
                echo "$candidate"
                return 0
            fi
        fi
    done
    return 1
}

# ── Parallelism ───────────────────────────────────────────────────────────────
if command -v nproc &>/dev/null; then
    JOBS=$(nproc)
elif command -v sysctl &>/dev/null; then
    JOBS=$(sysctl -n hw.ncpu 2>/dev/null || echo 4)
else
    JOBS=4
fi

# ── Collect source files ─────────────────────────────────────────────────────
SOURCE_DIRS="agents server sdk tests"
EXTENSIONS="cpp hpp h"

collect_files() {
    if [ "$ALL_FILES" = true ]; then
        # All project source files
        for dir in $SOURCE_DIRS; do
            for ext in $EXTENSIONS; do
                find "$dir" -name "*.$ext" -not -path '*/builddir/*' 2>/dev/null || true
            done
        done | grep -v '\.pb\.' | sort -u
    else
        # Only files changed vs main (or HEAD if main doesn't exist)
        local base
        base=$(git rev-parse --verify main 2>/dev/null || git rev-parse --verify origin/main 2>/dev/null || echo "HEAD~1")
        git diff --name-only --diff-filter=ACMR "$base" -- \
            'agents/*.cpp' 'agents/*.hpp' 'agents/*.h' \
            'server/*.cpp' 'server/*.hpp' 'server/*.h' \
            'sdk/*.cpp' 'sdk/*.hpp' 'sdk/*.h' \
            'tests/*.cpp' 'tests/*.hpp' 'tests/*.h' \
            2>/dev/null | grep -v '\.pb\.' | sort -u
    fi
}

ERRORS=0

# ── Format check ─────────────────────────────────────────────────────────────
if [ "$RUN_FORMAT" = true ]; then
    CLANG_FORMAT=$(find_tool clang-format 17) || {
        echo "ERROR: clang-format >= 17 not found. Install with: apt install clang-format-17"
        exit 1
    }
    echo "Using $CLANG_FORMAT ($($CLANG_FORMAT --version | head -1))"

    FILES=$(collect_files)
    if [ -z "$FILES" ]; then
        echo "Format: no files to check."
    elif [ "$FIX_MODE" = true ]; then
        echo "Format: fixing files in-place..."
        echo "$FILES" | xargs -P "$JOBS" "$CLANG_FORMAT" -i
        echo "Format: done."
    else
        echo "Format: checking..."
        FMT_ERRORS=0
        while IFS= read -r f; do
            if ! "$CLANG_FORMAT" --dry-run --Werror "$f" 2>/dev/null; then
                FMT_ERRORS=$((FMT_ERRORS + 1))
            fi
        done <<< "$FILES"
        if [ "$FMT_ERRORS" -gt 0 ]; then
            echo "Format: $FMT_ERRORS file(s) need formatting. Run: ./scripts/lint.sh --fix"
            ERRORS=$((ERRORS + FMT_ERRORS))
        else
            echo "Format: all files OK."
        fi
    fi
fi

# ── Tidy check ───────────────────────────────────────────────────────────────
if [ "$RUN_TIDY" = true ]; then
    CLANG_TIDY=$(find_tool clang-tidy 17) || {
        echo "ERROR: clang-tidy >= 17 not found. Install with: apt install clang-tidy-17"
        exit 1
    }
    echo "Using $CLANG_TIDY ($($CLANG_TIDY --version 2>&1 | grep version | head -1))"

    if [ ! -f "$BUILDDIR/compile_commands.json" ]; then
        echo "ERROR: $BUILDDIR/compile_commands.json not found."
        echo "Run: meson setup $BUILDDIR --buildtype=debug -Dbuild_tests=true"
        exit 1
    fi

    FILES=$(collect_files | grep -E '\.(cpp|cc)$' || true)
    if [ -z "$FILES" ]; then
        echo "Tidy: no source files to check."
    else
        echo "Tidy: checking $(echo "$FILES" | wc -l) file(s)..."
        TIDY_FAIL=0
        echo "$FILES" | xargs -P "$JOBS" -I{} "$CLANG_TIDY" -p "$BUILDDIR" {} 2>&1 \
            | tee /dev/stderr \
            | grep -c "warning:" > /tmp/tidy_count 2>/dev/null || true
        TIDY_FAIL=$(cat /tmp/tidy_count 2>/dev/null || echo 0)
        if [ "$TIDY_FAIL" -gt 0 ]; then
            echo "Tidy: $TIDY_FAIL warning(s) found."
            ERRORS=$((ERRORS + 1))
        else
            echo "Tidy: all files OK."
        fi
    fi
fi

# ── Summary ───────────────────────────────────────────────────────────────────
if [ "$ERRORS" -gt 0 ]; then
    echo ""
    echo "FAILED: lint issues found."
    exit 1
fi
echo ""
echo "OK: all checks passed."
