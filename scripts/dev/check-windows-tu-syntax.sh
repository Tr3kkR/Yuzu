#!/usr/bin/env bash
# check-windows-tu-syntax.sh — syntax-check the Windows-only plugin TUs on a
# non-Windows dev box, using the mingw-w64 cross compiler.
#
# WHY THIS EXISTS. A `#if defined(_WIN32)` translation unit compiles to NOTHING
# on macOS and Linux, so a full local `meson test` can be 100% green while the
# Windows leg does not compile at all. That is not hypothetical: PR #3967 passed
# 40/40 local targets and every review gate, then failed Windows MSVC CI on a
# deleted-copy-constructor error in a function no local build had ever seen.
#
# This is a SYNTAX check, not a build. It cannot validate MSVC-specific
# behaviour, link correctness, or device IOCTL semantics — CI remains the
# enforcement point. What it does catch is the large class of ordinary C++
# errors in code the local toolchain never reads.
#
# -fno-elide-constructors is deliberate: it forces the compiler to require a
# viable move/copy constructor for a by-value return of a named local, which is
# what MSVC debug does and what release-mode NRVO would otherwise hide.
#
# Usage:  bash scripts/dev/check-windows-tu-syntax.sh [extra TU paths...]
# Install: brew install mingw-w64   (or apt-get install g++-mingw-w64-x86-64)

set -uo pipefail

CXX=${MINGW_CXX:-x86_64-w64-mingw32-g++}
if ! command -v "$CXX" >/dev/null 2>&1; then
    echo "check-windows-tu-syntax: $CXX not found — install mingw-w64 to use this check." >&2
    echo "  macOS: brew install mingw-w64" >&2
    exit 127
fi

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo_root" || exit 1

# Minimal stubs for third-party headers the plugin TUs include. We are checking
# OUR code, not vendored headers, and vcpkg's x64-windows tree is not present on
# a non-Windows box.
shim=$(mktemp -d)
trap 'rm -rf "$shim"' EXIT
mkdir -p "$shim/spdlog"
cat > "$shim/spdlog/spdlog.h" <<'SHIM'
#pragma once
#include <string_view>
namespace spdlog {
template <class... A> void warn(std::string_view, A&&...) {}
template <class... A> void info(std::string_view, A&&...) {}
template <class... A> void error(std::string_view, A&&...) {}
template <class... A> void debug(std::string_view, A&&...) {}
}
SHIM

# Windows-only TUs worth checking. Extend as new ones land.
tus=(
    agents/plugins/disk_actions/src/disk_actions_win.cpp
)
[ "$#" -gt 0 ] && tus+=("$@")

rc=0
for tu in "${tus[@]}"; do
    [ -f "$tu" ] || { echo "  SKIP  $tu (not present)"; continue; }
    src_dir=$(dirname "$tu")
    if "$CXX" -std=c++23 -fsyntax-only -fno-elide-constructors \
        -I "$shim" -I "$src_dir" -I agents/shared -I sdk/include \
        "$tu" 2>"$shim/err.log"; then
        echo "  ok    $tu"
    else
        echo "  FAIL  $tu"
        sed 's/^/        /' "$shim/err.log"
        rc=1
    fi
done

if [ "$rc" -eq 0 ]; then
    echo "check-windows-tu-syntax: all Windows TUs syntax-check clean."
else
    echo "check-windows-tu-syntax: at least one Windows TU does not compile." >&2
fi
exit "$rc"
