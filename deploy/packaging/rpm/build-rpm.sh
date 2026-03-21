#!/usr/bin/env bash
set -euo pipefail

# Build Yuzu RPMs from pre-compiled binaries.
# Usage: build-rpm.sh --bin-dir DIR --version VERSION [--output DIR]

BIN_DIR=""
VERSION=""
OUTPUT="."

while [[ $# -gt 0 ]]; do
    case "$1" in
        --bin-dir)  BIN_DIR="$2"; shift 2 ;;
        --version)  VERSION="$2"; shift 2 ;;
        --output)   OUTPUT="$2"; shift 2 ;;
        --help)     echo "Usage: $0 --bin-dir DIR --version VERSION [--output DIR]"; exit 0 ;;
        *)          echo "Unknown: $1"; exit 1 ;;
    esac
done

[[ -z "$BIN_DIR" || -z "$VERSION" ]] && { echo "Error: --bin-dir and --version required"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TOPDIR="$(mktemp -d)"
trap "rm -rf $TOPDIR" EXIT

mkdir -p "$TOPDIR"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

# Copy sources
cp "$BIN_DIR/yuzu-server" "$TOPDIR/SOURCES/"
cp "$BIN_DIR/yuzu-agent" "$TOPDIR/SOURCES/"
cp "$SCRIPT_DIR/../../../deploy/systemd/yuzu-server.service" "$TOPDIR/SOURCES/"
cp "$SCRIPT_DIR/../../../deploy/systemd/yuzu-agent.service" "$TOPDIR/SOURCES/"

if [[ -d "$BIN_DIR/plugins" ]]; then
    mkdir -p "$TOPDIR/SOURCES/plugins"
    cp "$BIN_DIR/plugins/"*.so "$TOPDIR/SOURCES/plugins/" 2>/dev/null || true
fi

# Build server RPM
echo "=== Building yuzu-server-${VERSION} RPM ==="
sed "s/^Version:.*/Version:        $VERSION/" "$SCRIPT_DIR/yuzu-server.spec" > "$TOPDIR/SPECS/yuzu-server.spec"
rpmbuild --define "_topdir $TOPDIR" -bb "$TOPDIR/SPECS/yuzu-server.spec"

# Build agent RPM
echo "=== Building yuzu-agent-${VERSION} RPM ==="
sed "s/^Version:.*/Version:        $VERSION/" "$SCRIPT_DIR/yuzu-agent.spec" > "$TOPDIR/SPECS/yuzu-agent.spec"
rpmbuild --define "_topdir $TOPDIR" -bb "$TOPDIR/SPECS/yuzu-agent.spec"

# Copy output
mkdir -p "$OUTPUT"
find "$TOPDIR/RPMS" -name "*.rpm" -exec cp {} "$OUTPUT/" \;

echo "=== Done ==="
ls -la "$OUTPUT"/*.rpm 2>/dev/null
