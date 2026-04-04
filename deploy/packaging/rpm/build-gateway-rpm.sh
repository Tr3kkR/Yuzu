#!/usr/bin/env bash
set -euo pipefail

# Build yuzu-gateway RPM from a rebar3 release.
# Usage: build-gateway-rpm.sh --rel-dir DIR --version VERSION [--output DIR]

REL_DIR=""
VERSION=""
OUTPUT="."

while [[ $# -gt 0 ]]; do
    case "$1" in
        --rel-dir)  REL_DIR="$2"; shift 2 ;;
        --version)  VERSION="$2"; shift 2 ;;
        --output)   OUTPUT="$2"; shift 2 ;;
        --help)     echo "Usage: $0 --rel-dir DIR --version VERSION [--output DIR]"; exit 0 ;;
        *)          echo "Unknown: $1"; exit 1 ;;
    esac
done

[[ -z "$REL_DIR" || -z "$VERSION" ]] && { echo "Error: --rel-dir and --version required"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TOPDIR="$(mktemp -d)"
trap "rm -rf $TOPDIR" EXIT

mkdir -p "$TOPDIR"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

# Copy the Erlang release as source
mkdir -p "$TOPDIR/SOURCES/yuzu_gw"
cp -a "$REL_DIR"/* "$TOPDIR/SOURCES/yuzu_gw/"

# Systemd service
cp "$SCRIPT_DIR/../../../deploy/systemd/yuzu-gateway.service" "$TOPDIR/SOURCES/"

# Build RPM
echo "=== Building yuzu-gateway-${VERSION} RPM ==="
sed "s/^Version:.*/Version:        $VERSION/" "$SCRIPT_DIR/yuzu-gateway.spec" > "$TOPDIR/SPECS/yuzu-gateway.spec"
rpmbuild --define "_topdir $TOPDIR" -bb "$TOPDIR/SPECS/yuzu-gateway.spec"

# Copy output
mkdir -p "$OUTPUT"
find "$TOPDIR/RPMS" -name "*.rpm" -exec cp {} "$OUTPUT/" \;

echo "=== Done ==="
ls -la "$OUTPUT"/yuzu-gateway*.rpm 2>/dev/null
