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

# A missing or broken compiler produces NO OUTPUT, which the emptiness test below
# would otherwise read as "correctly guarded" and report as a pass. That is this
# script's own declared failure class, and it shipped anyway -- the sibling
# check-windows-tu-syntax.sh guards this correctly and this one did not.
if ! command -v "$CXX" >/dev/null 2>&1; then
    echo "check-platform-guards: compiler '$CXX' not found." >&2
    echo "  Set CXX to a C++ compiler, e.g. CXX=clang++ or CXX=g++." >&2
    exit 2
fi

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
    #
    # The compiler's STATUS is captured separately from its OUTPUT: a preprocess
    # that fails also emits nothing, and conflating the two is how "broken" reads
    # as "clean".
    if ! out=$("$CXX" -std=c++23 "$flag" -E -P "$f" 2>&1); then
        echo "  FAIL  $f: $CXX could not preprocess it under $flag"
        printf '%s\n' "$out" | head -5 | sed 's/^/        /'
        rc=1
        continue
    fi
    leaked=$(printf '%s' "$out" | tr -d '[:space:]')
    if [ -z "$leaked" ]; then
        echo "  ok    $f preprocesses to nothing under $flag"
    else
        echo "  FAIL  $f leaves code OUTSIDE its platform guard (under $flag)"
        printf '%s\n' "$out" | grep -vE '^[[:space:]]*$' | head -5 | sed 's/^/        /'
        rc=1
    fi
done
[ "$rc" -eq 0 ] && echo "check-platform-guards: all guarded TUs preprocess to nothing."
exit "$rc"
