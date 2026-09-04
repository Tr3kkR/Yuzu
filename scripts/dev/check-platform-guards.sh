#!/usr/bin/env bash
# check-platform-guards.sh — prove a platform-guarded TU produces NO CODE under
# the other platform's preprocessing.
#
# WHY THIS EXISTS. A test appended to a `#ifdef _WIN32` / `#ifndef _WIN32` file
# lands after the closing `#endif` unless you look, and the local build cannot
# see it: the POSIX file compiles fine on macOS whether or not its new case is
# inside the guard, and the Windows file is never compiled here at all. On
# PR6.0c this produced TWO guard defects in one change — the Windows test placed
# outside its guard, and then the POSIX test placed outside ITS guard one commit
# later, the second caught only by external review.
#
# IT CHECKS EMPTINESS, NOT COMPILABILITY, and that distinction is the whole
# point. An earlier revision of this script ran `-fsyntax-only` and treated a
# successful compile as proof of emptiness. Both external reviewers broke it
# within minutes by appending self-contained-but-valid code after the guard —
# `static_assert(true, ...)`, a free function in an anonymous namespace — which
# compiles happily and was reported as "ok ... is empty". A check that
# false-passes the exact class it exists to catch is worse than no check,
# because it is trusted. It now preprocesses with `-E -P` and rejects ANY
# non-whitespace output, which is what "nothing is left" actually means.
#
# Needs no SDK: a correctly guarded file preprocesses to nothing regardless of
# what headers the other platform would have required.
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
    if [ ! -f "$f" ]; then
        # A configured file that has vanished is a FAILURE, not a skip: a rename
        # would otherwise drop its coverage silently.
        echo "  FAIL  $f is configured for this check but does not exist (renamed or removed?)"
        rc=1
        continue
    fi
    # -E -P: preprocess only, no linemarkers. Anything surviving is real code.
    leaked=$("$CXX" -std=c++23 "$flag" -E -P "$f" 2>/dev/null | tr -d '[:space:]')
    if [ -z "$leaked" ]; then
        echo "  ok    $f preprocesses to nothing under $flag"
    else
        echo "  FAIL  $f leaves code OUTSIDE its platform guard (under $flag)"
        "$CXX" -std=c++23 "$flag" -E -P "$f" 2>/dev/null | grep -vE '^\s*$' | head -5 \
            | sed 's/^/        /'
        rc=1
    fi
done
[ "$rc" -eq 0 ] && echo "check-platform-guards: all guarded TUs preprocess to nothing."
exit "$rc"
