#!/bin/bash
# setup.sh — Configure and prepare a Yuzu build directory using Meson.
#
# Wraps vcpkg install + meson setup into a single command.
# On Windows, source setup_msvc_env.sh first.
#
# This script picks a per-OS default build directory (build-linux,
# build-windows, build-macos) so the same source tree can be configured
# concurrently from WSL2 and a native Windows shell — and from a separate
# macOS host — without the build dirs trampling each other.
#
# Usage:
#   ./scripts/setup.sh [--buildtype debug|release] [--tests] [--lto]
#                       [--native-file FILE] [--cross-file FILE]
#                       [--builddir DIR] [--wipe] [-- extra meson args...]
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

# ── Detect platform and vcpkg triplet ────────────────────────────────────────
# (Detected before BUILDDIR default so the per-OS name is correct.)
HOST_OS=""
if [[ "$(uname -s)" == MINGW* ]] || [[ "$(uname -s)" == MSYS* ]] || [[ "${OS:-}" == "Windows_NT" ]]; then
  HOST_OS="windows"
  TRIPLET="x64-windows"
elif [[ "$(uname -s)" == "Darwin" ]]; then
  HOST_OS="macos"
  if [[ "$(uname -m)" == "arm64" ]]; then
    TRIPLET="arm64-osx"
  else
    TRIPLET="x64-osx"
  fi
else
  HOST_OS="linux"
  TRIPLET="x64-linux"
fi

# ── Defaults ──────────────────────────────────────────────────────────────────
BUILDDIR="build-${HOST_OS}"
BUILDTYPE="debug"
TESTS=false
LTO=false
WIPE=false
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
    --wipe)        WIPE=true; shift ;;
    --native-file) NATIVE_FILE="$2"; shift 2 ;;
    --cross-file)  CROSS_FILE="$2"; shift 2 ;;
    --)            shift; EXTRA_ARGS+=("$@"); break ;;
    *)             echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

# Cross-compile overrides the host triplet (but keeps the host-named builddir
# unless the caller passed --builddir explicitly).
if [[ -n "$CROSS_FILE" ]]; then
  case "$CROSS_FILE" in
    *aarch64*) TRIPLET="arm64-linux" ;;
    *armv7*)   TRIPLET="arm-linux" ;;
    *)         echo "Warning: could not infer vcpkg triplet from cross file." >&2 ;;
  esac
fi

# ── Reject reusing a build dir from a different host OS ──────────────────────
# meson-info.json records the absolute source path of the configuring host.
# Windows builds record "C:\...", POSIX builds record "/mnt/c/..." or "/Users/...".
# Mixing them produces opaque ninja errors deep into the build, so detect early.
MESON_INFO="$PROJECT_ROOT/$BUILDDIR/meson-info/meson-info.json"
if [[ -f "$MESON_INFO" ]] && ! $WIPE; then
  RECORDED_SRC="$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(d.get('directories',{}).get('source',''))" "$MESON_INFO" 2>/dev/null || true)"
  if [[ -n "$RECORDED_SRC" ]]; then
    case "$HOST_OS" in
      windows) EXPECTED_PREFIX_RE='^[A-Za-z]:[\\/]' ;;
      *)       EXPECTED_PREFIX_RE='^/' ;;
    esac
    if ! [[ "$RECORDED_SRC" =~ $EXPECTED_PREFIX_RE ]]; then
      echo "Error: $BUILDDIR was configured from a different host (source=$RECORDED_SRC)." >&2
      echo "       This script is running on $HOST_OS. Either:" >&2
      echo "         - re-run with --wipe to start fresh, or" >&2
      echo "         - re-run with --builddir build-${HOST_OS}-alt to keep both." >&2
      exit 1
    fi
  fi
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
# vcpkg manifest mode installs to <manifest-root>/vcpkg_installed/ (not
# $VCPKG_ROOT/installed/).  Prefer the manifest-local directory when it exists.
VCPKG_INSTALLED_ROOT="$PROJECT_ROOT/vcpkg_installed"
if [[ ! -d "$VCPKG_INSTALLED_ROOT" ]]; then
  VCPKG_INSTALLED_ROOT="$VCPKG_ROOT/installed"
fi
if [[ -n "$TRIPLET" ]]; then
  VCPKG_INSTALLED="$VCPKG_INSTALLED_ROOT/$TRIPLET"
else
  VCPKG_INSTALLED="$VCPKG_INSTALLED_ROOT"
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

# Reuse the existing build dir if present and same-host: meson reconfigures
# in place. Only wipe if --wipe was passed (no silent destruction of work).
if [[ -d "$PROJECT_ROOT/$BUILDDIR" ]]; then
  if $WIPE; then
    echo "── Wiping existing build directory: $BUILDDIR ──"
    MESON_ARGS+=(--wipe)
  else
    echo "── Reconfiguring existing build directory: $BUILDDIR ──"
    MESON_ARGS+=(--reconfigure)
  fi
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
