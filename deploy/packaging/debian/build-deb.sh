#!/usr/bin/env bash
set -euo pipefail

# Build Yuzu .deb packages from pre-compiled binaries.
# Usage: build-deb.sh --bin-dir DIR --version VERSION [--output DIR]
#
# Expects bin-dir to contain: yuzu-server, yuzu-agent, plugins/, content/

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
ARCH=$(dpkg --print-architecture 2>/dev/null || echo "amd64")

# --- yuzu-server .deb ---
echo "=== Building yuzu-server_${VERSION}_${ARCH}.deb ==="
PKG="$OUTPUT/yuzu-server_${VERSION}_${ARCH}"
rm -rf "$PKG"
mkdir -p "$PKG/DEBIAN"
mkdir -p "$PKG/usr/local/bin"
mkdir -p "$PKG/usr/lib/systemd/system"
mkdir -p "$PKG/etc/yuzu"
mkdir -p "$PKG/var/lib/yuzu"
mkdir -p "$PKG/var/log/yuzu"
mkdir -p "$PKG/usr/share/yuzu/content/definitions"

cp "$BIN_DIR/yuzu-server" "$PKG/usr/local/bin/"
cp "$SCRIPT_DIR/../../../deploy/systemd/yuzu-server.service" "$PKG/usr/lib/systemd/system/"

if [[ -d "$BIN_DIR/content/definitions" ]]; then
    cp "$BIN_DIR/content/definitions/"*.yaml "$PKG/usr/share/yuzu/content/definitions/" 2>/dev/null || true
fi

cat > "$PKG/DEBIAN/control" <<EOF
Package: yuzu-server
Version: $VERSION
Architecture: $ARCH
Maintainer: Yuzu Team <noreply@yuzu.io>
Depends: adduser
Section: admin
Priority: optional
Homepage: https://github.com/Tr3kkR/Yuzu
Description: Yuzu endpoint management server
 Enterprise endpoint management platform — server component.
EOF

cp "$SCRIPT_DIR/postinst" "$PKG/DEBIAN/"
cp "$SCRIPT_DIR/prerm" "$PKG/DEBIAN/"
chmod 0755 "$PKG/DEBIAN/postinst" "$PKG/DEBIAN/prerm"

dpkg-deb --build --root-owner-group "$PKG"
echo "Built: ${PKG}.deb"

# --- yuzu-agent .deb ---
echo "=== Building yuzu-agent_${VERSION}_${ARCH}.deb ==="
PKG="$OUTPUT/yuzu-agent_${VERSION}_${ARCH}"
rm -rf "$PKG"
mkdir -p "$PKG/DEBIAN"
mkdir -p "$PKG/usr/local/bin"
mkdir -p "$PKG/usr/lib/yuzu/plugins"
mkdir -p "$PKG/usr/lib/systemd/system"
mkdir -p "$PKG/var/lib/yuzu-agent"

cp "$BIN_DIR/yuzu-agent" "$PKG/usr/local/bin/"
cp "$SCRIPT_DIR/../../../deploy/systemd/yuzu-agent.service" "$PKG/usr/lib/systemd/system/"

if [[ -d "$BIN_DIR/plugins" ]]; then
    cp "$BIN_DIR/plugins/"*.so "$PKG/usr/lib/yuzu/plugins/" 2>/dev/null || true
fi

cat > "$PKG/DEBIAN/control" <<EOF
Package: yuzu-agent
Version: $VERSION
Architecture: $ARCH
Maintainer: Yuzu Team <noreply@yuzu.io>
Depends: adduser
Section: admin
Priority: optional
Homepage: https://github.com/Tr3kkR/Yuzu
Description: Yuzu endpoint management agent
 Enterprise endpoint management platform — agent component.
EOF

cp "$SCRIPT_DIR/postinst" "$PKG/DEBIAN/"
cp "$SCRIPT_DIR/prerm" "$PKG/DEBIAN/"
chmod 0755 "$PKG/DEBIAN/postinst" "$PKG/DEBIAN/prerm"

dpkg-deb --build --root-owner-group "$PKG"
echo "Built: ${PKG}.deb"

echo "=== Done ==="
