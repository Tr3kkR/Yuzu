#!/usr/bin/env bash
# check-platform-guards.sh — prove a platform-guarded TU is EMPTY under the
# other platform's preprocessing.
#
# WHY THIS EXISTS. A test appended to a `#ifdef _WIN32` / `#ifndef _WIN32` file
# lands after the closing `#endif` unless you look, and the local build cannot
# see it: the POSIX file compiles fine on macOS whether or not its new case is
# inside the guard, and the Windows file is never compiled here at all. On
# PR6.0c this produced TWO guard defects in one change — the Windows test placed
# outside its guard, and then the POSIX test placed outside ITS guard one commit
# later, the second caught only by external review.
#
# The check is cheap and needs no SDK: preprocess each file under the OPPOSITE
# platform's macro and require it to be syntactically empty, because a correctly
# guarded file has nothing left to parse.
#
# Usage: bash scripts/dev/check-platform-guards.sh

set -uo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo_root" || exit 1
CXX=${CXX:-/usr/bin/clang++}

# file:macro-that-should-make-it-empty
checks=(
  "tests/unit/test_confined_fs_posix.cpp:-D_WIN32"
  "tests/unit/test_confined_fs_win.cpp:-U_WIN32"
)

rc=0
for spec in "${checks[@]}"; do
    f="${spec%%:*}"; flag="${spec##*:}"
    [ -f "$f" ] || { echo "  SKIP  $f (not present)"; continue; }
    if "$CXX" -std=c++23 "$flag" -fsyntax-only "$f" 2>/dev/null; then
        echo "  ok    $f is empty under $flag"
    else
        echo "  FAIL  $f has code OUTSIDE its platform guard (compiled under $flag)"
        "$CXX" -std=c++23 "$flag" -fsyntax-only "$f" 2>&1 | head -5 | sed 's/^/        /'
        rc=1
    fi
done
[ "$rc" -eq 0 ] && echo "check-platform-guards: all guarded TUs are correctly scoped."
exit "$rc"
