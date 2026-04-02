#!/bin/bash
# Yuzu CI entrypoint — run configure + build + test matching ci.yml
#
# Usage:
#   ci-entrypoint.sh gcc-13 debug     # GCC 13 debug build
#   ci-entrypoint.sh clang-18 release # Clang 18 release build
#   ci-entrypoint.sh bash             # interactive shell

set -euo pipefail

# If first arg is "bash" or "sh", drop into shell
if [[ "${1:-}" == "bash" || "${1:-}" == "sh" ]]; then
    exec "$@"
fi

COMPILER="${1:-gcc-13}"
BUILD_TYPE="${2:-debug}"

echo "════════════════════════════════════════════════════════"
echo "  Yuzu CI — $COMPILER $BUILD_TYPE"
echo "════════════════════════════════════════════════════════"

# ── Copy source to writable build dir ────────────────────────────────────
if [[ -d /src ]]; then
    echo "[1/4] Copying source..."
    cp -r /src /build/src
    cd /build/src
else
    echo "ERROR: Mount your source at /src: docker run -v \$(pwd):/src ..."
    exit 1
fi

# ── Link pre-built vcpkg packages ────────────────────────────────────────
echo "[2/4] Linking pre-built vcpkg packages..."
cp -r /opt/vcpkg_installed ./vcpkg_installed

# ── Set compiler ─────────────────────────────────────────────────────────
case "$COMPILER" in
    gcc-13)
        export CC="ccache gcc-13"
        export CXX="ccache g++-13"
        NATIVE_FILE="meson/native/linux-gcc13.ini"
        ;;
    clang-18)
        export CC="ccache clang-18"
        export CXX="ccache clang++-18"
        NATIVE_FILE="meson/native/linux-clang18.ini"
        ;;
    *)
        echo "Unknown compiler: $COMPILER (use gcc-13 or clang-18)"
        exit 1
        ;;
esac

LTO_FLAG=""
if [[ "$BUILD_TYPE" == "release" ]]; then
    LTO_FLAG="-Db_lto=true"
fi

# ── Configure ────────────────────────────────────────────────────────────
echo "[3/4] Configuring ($COMPILER $BUILD_TYPE)..."
export PKG_CONFIG_PATH="$(pwd)/vcpkg_installed/x64-linux/lib/pkgconfig"
meson setup builddir \
    --native-file "$NATIVE_FILE" \
    --buildtype="$BUILD_TYPE" \
    -Dcmake_prefix_path="$(pwd)/vcpkg_installed/x64-linux" \
    -Dbuild_tests=true \
    $LTO_FLAG

# ── Build ────────────────────────────────────────────────────────────────
echo "[4/4] Building..."
meson compile -C builddir

# ── Test ─────────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════"
echo "  Running tests..."
echo "════════════════════════════════════════════════════════"
meson test -C builddir --print-errorlogs

echo ""
echo "════════════════════════════════════════════════════════"
echo "  ✓ $COMPILER $BUILD_TYPE — all tests passed"
echo "════════════════════════════════════════════════════════"

# ── ccache stats ─────────────────────────────────────────────────────────
echo ""
ccache -s
