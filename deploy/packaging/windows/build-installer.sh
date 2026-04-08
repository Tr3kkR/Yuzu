#!/usr/bin/env bash
# Build the Yuzu Agent Windows installer.
#
# Usage:
#   bash deploy/packaging/windows/build-installer.sh [--builddir DIR] [--version VER]
#
# Defaults:
#   --builddir  builddir       (relative to repo root)
#   --version   extracted from meson.build
#
# Requires: InnoSetup 6 (ISCC.exe on PATH, or installed via Chocolatey)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# Defaults
BUILD_DIR="$REPO_ROOT/builddir"
VERSION=""

# Parse args
while [[ $# -gt 0 ]]; do
    case "$1" in
        --builddir) BUILD_DIR="$2"; shift 2 ;;
        --version)  VERSION="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 [--builddir DIR] [--version VER]"
            exit 0
            ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

# Extract version from meson.build if not provided
if [[ -z "$VERSION" ]]; then
    VERSION=$(grep -oP "version:\s*'\K[^']+" "$REPO_ROOT/meson.build" | head -1)
    if [[ -z "$VERSION" ]]; then
        echo "ERROR: Could not extract version from meson.build" >&2
        exit 1
    fi
fi

echo "=== Yuzu Agent Installer Builder ==="
echo "Version:   $VERSION"
echo "Build dir: $BUILD_DIR"
echo ""

# Verify build artifacts exist
if [[ ! -f "$BUILD_DIR/agents/core/yuzu-agent.exe" ]]; then
    echo "ERROR: yuzu-agent.exe not found in $BUILD_DIR/agents/core/" >&2
    echo "Run 'meson compile -C builddir' first." >&2
    exit 1
fi

PLUGIN_COUNT=$(ls "$BUILD_DIR/plugins/"*.dll 2>/dev/null | wc -l)
if [[ "$PLUGIN_COUNT" -eq 0 ]]; then
    echo "ERROR: No plugin DLLs found in $BUILD_DIR/plugins/" >&2
    exit 1
fi

DLL_COUNT=$(ls "$BUILD_DIR/agents/core/"*.dll 2>/dev/null | wc -l)
echo "Agent exe:    found"
echo "Runtime DLLs: $DLL_COUNT"
echo "Plugin DLLs:  $PLUGIN_COUNT"
echo ""

# Find ISCC.exe
ISCC=""
if command -v ISCC &>/dev/null; then
    ISCC="ISCC"
elif [[ -f "/c/ProgramData/chocolatey/bin/ISCC.exe" ]]; then
    ISCC="/c/ProgramData/chocolatey/bin/ISCC.exe"
elif [[ -f "/c/Program Files (x86)/Inno Setup 6/ISCC.exe" ]]; then
    ISCC="/c/Program Files (x86)/Inno Setup 6/ISCC.exe"
elif [[ -f "/c/Program Files/Inno Setup 6/ISCC.exe" ]]; then
    ISCC="/c/Program Files/Inno Setup 6/ISCC.exe"
else
    echo "ERROR: ISCC.exe not found. Install InnoSetup: choco install innosetup" >&2
    exit 1
fi

echo "ISCC: $ISCC"
echo ""

# Create output directory
mkdir -p "$SCRIPT_DIR/output"

# Convert paths to Windows format for ISCC
WIN_BUILD_DIR=$(cygpath -w "$BUILD_DIR" 2>/dev/null || echo "$BUILD_DIR")
WIN_ISS=$(cygpath -w "$SCRIPT_DIR/yuzu-agent.iss" 2>/dev/null || echo "$SCRIPT_DIR/yuzu-agent.iss")

echo "Building installer..."
# MSYS_NO_PATHCONV prevents MSYS2 from mangling /D flags into Unix paths
MSYS_NO_PATHCONV=1 "$ISCC" \
    "/DAppVersion=$VERSION" \
    "/DBuildDir=$WIN_BUILD_DIR" \
    "$WIN_ISS"

echo ""
echo "=== Build complete ==="
OUTPUT="$SCRIPT_DIR/output/YuzuAgentSetup-$VERSION.exe"
if [[ -f "$OUTPUT" ]]; then
    SIZE=$(du -h "$OUTPUT" | cut -f1)
    echo "Output: $OUTPUT ($SIZE)"
else
    echo "Output: $SCRIPT_DIR/output/YuzuAgentSetup-$VERSION.exe"
fi
