#!/bin/bash
# setup.sh — Configure and prepare a Yuzu build directory using Meson.
#
# Wraps vcpkg install + meson setup into a single command.
# On Windows, source setup_msvc_env.sh first.
#
# Usage:
#   ./scripts/setup.sh [--buildtype debug|release] [--tests] [--lto]
#                       [--native-file FILE] [--cross-file FILE]
#                       [--builddir DIR] [-- extra meson args...]
#
# Examples:
#   ./scripts/setup.sh                              # debug build, default compiler
#   ./scripts/setup.sh --buildtype release --lto    # release + LTO
#   ./scripts/setup.sh --tests                      # enable tests
#   ./scripts/setup.sh --native-file meson/native/linux-gcc13.ini
#   ./scripts/setup.sh --cross-file meson/cross/aarch64-linux-gnu.ini
#   ./scripts/setup.sh -- -Dbuild_agent=false       # pass extra args to meson

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ── Defaults ──────────────────────────────────────────────────────────────────
BUILDDIR="builddir"
BUILDTYPE="debug"
TESTS=false
LTO=false
NATIVE_FILE=""
CROSS_FILE=""
EXTRA_ARGS=()

# ── Parse arguments ───────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --builddir)    BUILDDIR="$2"; shift 2 ;;
    --buildtype)   BUILDTYPE="$2"; shift 2 ;;
    --tests)       TESTS=true; shift ;;
    --lto)         LTO=true; shift ;;
    --native-file) NATIVE_FILE="$2"; shift 2 ;;
    --cross-file)  CROSS_FILE="$2"; shift 2 ;;
    --)            shift; EXTRA_ARGS+=("$@"); break ;;
    *)             echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

# ── Detect platform and vcpkg triplet ────────────────────────────────────────
if [[ -n "$CROSS_FILE" ]]; then
  # Cross-compile: infer triplet from cross file name
  case "$CROSS_FILE" in
    *aarch64*) TRIPLET="arm64-linux" ;;
    *armv7*)   TRIPLET="arm-linux" ;;
    *)         echo "Warning: could not infer vcpkg triplet from cross file." >&2
               TRIPLET="" ;;
  esac
elif [[ "$(uname -s)" == MINGW* ]] || [[ "$(uname -s)" == MSYS* ]] || [[ "${OS:-}" == "Windows_NT" ]]; then
  TRIPLET="x64-windows"
elif [[ "$(uname -s)" == "Darwin" ]]; then
  if [[ "$(uname -m)" == "arm64" ]]; then
    TRIPLET="arm64-osx"
  else
    TRIPLET="x64-osx"
  fi
else
  TRIPLET="x64-linux"
fi

# ── vcpkg install ─────────────────────────────────────────────────────────────
if [[ -z "${VCPKG_ROOT:-}" ]]; then
  echo "Error: VCPKG_ROOT is not set. Set it to your vcpkg installation directory." >&2
  exit 1
fi

# Normalize to Unix-style path for MSYS2 compatibility
VCPKG_EXE="$VCPKG_ROOT/vcpkg"
if [[ ! -x "$VCPKG_EXE" ]] && [[ -f "$VCPKG_ROOT/vcpkg.exe" ]]; then
  VCPKG_EXE="$VCPKG_ROOT/vcpkg.exe"
fi

echo "── Installing vcpkg packages (triplet: ${TRIPLET}) ──"
VCPKG_INSTALL_ARGS=(
  install
  --x-manifest-root="$PROJECT_ROOT"
)
if [[ -n "$TRIPLET" ]]; then
  VCPKG_INSTALL_ARGS+=(--triplet="$TRIPLET")
fi
"$VCPKG_EXE" "${VCPKG_INSTALL_ARGS[@]}"

# ── Determine cmake_prefix_path for Meson ────────────────────────────────────
if [[ -n "$TRIPLET" ]]; then
  VCPKG_INSTALLED="$VCPKG_ROOT/installed/$TRIPLET"
else
  VCPKG_INSTALLED="$VCPKG_ROOT/installed"
fi

# ── Build meson setup command ─────────────────────────────────────────────────
MESON_ARGS=(
  setup "$BUILDDIR"
  --buildtype="$BUILDTYPE"
)

# Native / cross files
if [[ -n "$NATIVE_FILE" ]]; then
  MESON_ARGS+=(--native-file "$NATIVE_FILE")
fi
if [[ -n "$CROSS_FILE" ]]; then
  MESON_ARGS+=(--cross-file "$CROSS_FILE")
fi

# vcpkg integration: pass cmake_prefix_path so Meson's cmake dependency method
# can find packages installed by vcpkg.
MESON_ARGS+=(-Dcmake_prefix_path="$VCPKG_INSTALLED")

# Options
if $TESTS; then
  MESON_ARGS+=(-Dbuild_tests=true)
fi
if $LTO; then
  MESON_ARGS+=(-Db_lto=true)
fi

# Extra args from user
if [[ ${#EXTRA_ARGS[@]} -gt 0 ]]; then
  MESON_ARGS+=("${EXTRA_ARGS[@]}")
fi

# Wipe existing builddir if present (meson setup fails if it already exists
# with a different configuration).
if [[ -d "$PROJECT_ROOT/$BUILDDIR" ]]; then
  echo "── Wiping existing build directory: $BUILDDIR ──"
  MESON_ARGS+=(--wipe)
fi

echo "── Running: meson ${MESON_ARGS[*]} ──"
cd "$PROJECT_ROOT"
meson "${MESON_ARGS[@]}"

echo ""
echo "Build configured. Next steps:"
echo "  meson compile -C $BUILDDIR"
if $TESTS; then
  echo "  meson test -C $BUILDDIR --print-errorlogs"
fi
