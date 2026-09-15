#!/usr/bin/env bash
# Build either the legacy loose-binary package or an opt-in signed app bundle.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR=""
BUNDLE_DIR=""
VERSION=""
OUTPUT_DIR="."
IDENTIFIER="com.yuzu.agent"

usage() { echo "Usage: $0 (--bin-dir DIR | --bundle-dir DIR) --version VER [--output DIR]" >&2; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --bin-dir) BIN_DIR="$2"; shift 2 ;;
        --bundle-dir) BUNDLE_DIR="$2"; shift 2 ;;
        --version) VERSION="$2"; shift 2 ;;
        --output) OUTPUT_DIR="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "ERROR: unknown option: $1" >&2; usage; exit 1 ;;
    esac
done
if [[ -z "$VERSION" || ( -z "$BIN_DIR" && -z "$BUNDLE_DIR" ) || ( -n "$BIN_DIR" && -n "$BUNDLE_DIR" ) ]]; then
    echo "ERROR: exactly one of --bin-dir or --bundle-dir and --version are required" >&2
    usage; exit 1
fi

STAGING="$(mktemp -d)"
SCRIPTS="$(mktemp -d)"
COMPONENT_DIR="$(mktemp -d)"
trap 'rm -rf "$STAGING" "$SCRIPTS" "$COMPONENT_DIR"' EXIT
install -m 755 "$SCRIPT_DIR/preinstall" "$SCRIPTS/preinstall"
install -m 755 "$SCRIPT_DIR/postinstall" "$SCRIPTS/postinstall"
install -d "${STAGING}/usr/local/lib/yuzu/.plugins.incoming"
install -m 755 "$SCRIPT_DIR/merge-launchd-plist.py" "$STAGING/usr/local/lib/yuzu/merge-launchd-plist.py"

PACKAGE_MODE="loose"
AGENT_BIN=""
PLUGIN_COUNT=0
if [[ -n "$BUNDLE_DIR" ]]; then
    PACKAGE_MODE="bundle"
    APP="$BUNDLE_DIR/YuzuAgent.app"
    PLUGINS="$BUNDLE_DIR/plugins"
    AGENT_BIN="$APP/Contents/MacOS/yuzu-agent"
    [[ -d "$APP" && -x "$AGENT_BIN" && -d "$PLUGINS" ]] || {
        echo "ERROR: --bundle-dir must contain YuzuAgent.app and plugins/" >&2; exit 1; }
    ACTUAL_VERSION="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$APP/Contents/Info.plist")"
    [[ "$ACTUAL_VERSION" == "$VERSION" ]] || { echo "ERROR: bundle version does not match --version" >&2; exit 1; }
    codesign --verify --deep --strict --verbose=2 "$APP"
    install -d "${STAGING}/Library/Application Support/YuzuAgent"
    install -d "${STAGING}/Library/LaunchDaemons"
    cp -R "$APP" "${STAGING}/Library/Application Support/YuzuAgent/.YuzuAgent.incoming.app"
    POLICY_ARGS=()
    if [[ -f "$PLUGINS/plugin-signing-policy.json" ]]; then
        POLICY_ARGS=(--plugin-signing-policy "$PLUGINS/plugin-signing-policy.json")
        install -m 644 "$PLUGINS/plugin-signing-policy.json" \
            "${STAGING}/usr/local/lib/yuzu/plugin-signing-policy.json"
    fi
    python3 "$SCRIPT_DIR/generate-launchd-plist.py" --source "$SCRIPT_DIR/com.yuzu.agent.plist" \
        --output "${STAGING}/Library/LaunchDaemons/.com.yuzu.agent.incoming.plist" \
        --bundle-executable "/Library/Application Support/YuzuAgent/YuzuAgent.app/Contents/MacOS/yuzu-agent" \
        "${POLICY_ARGS[@]}"
    for plugin in "$PLUGINS"/*.dylib; do
        [[ -f "$plugin" ]] || continue
        codesign --verify --strict --verbose=2 "$plugin"
        install -m 755 "$plugin" "${STAGING}/usr/local/lib/yuzu/.plugins.incoming/$(basename "$plugin")"
        [[ ! -f "$plugin.sig" ]] || install -m 644 "$plugin.sig" "${STAGING}/usr/local/lib/yuzu/.plugins.incoming/$(basename "$plugin").sig"
        if [[ -f "$plugin.sig" && ! -f "$PLUGINS/plugin-signing-policy.json" ]]; then
            echo "ERROR: plugin CMS sidecars require a verified signing policy" >&2
            exit 1
        fi
        printf 'plugins/%s\n' "$(basename "$plugin")" >> "${STAGING}/usr/local/lib/yuzu/.package-files.incoming"
        PLUGIN_COUNT=$((PLUGIN_COUNT + 1))
    done
    [[ "$PLUGIN_COUNT" -gt 0 ]] || { echo "ERROR: bundle has no external plugins" >&2; exit 1; }
else
    AGENT_BIN="$BIN_DIR/yuzu-agent"
    [[ -f "$AGENT_BIN" ]] || AGENT_BIN="$BIN_DIR/agents/core/yuzu-agent"
    [[ -f "$AGENT_BIN" ]] || { echo "ERROR: yuzu-agent not found in $BIN_DIR" >&2; exit 1; }
    install -d "${STAGING}/usr/local/bin"
    install -m 755 "$AGENT_BIN" "${STAGING}/usr/local/bin/.yuzu-agent.incoming"
    for candidate in "$BIN_DIR/libyuzu_agent_core.dylib" "$BIN_DIR/agents/core/libyuzu_agent_core.dylib"; do
        [[ -f "$candidate" ]] || continue
        install -d "${STAGING}/usr/local/lib"
        install -m 755 "$candidate" "${STAGING}/usr/local/lib/.libyuzu_agent_core.incoming.dylib"
        break
    done
    if [[ -d "$BIN_DIR/plugins" ]]; then
        for plugin in "$BIN_DIR/plugins"/*.dylib; do
            [[ -f "$plugin" ]] || continue
            install -m 755 "$plugin" "${STAGING}/usr/local/lib/yuzu/.plugins.incoming/"
            printf 'plugins/%s\n' "$(basename "$plugin")" >> "${STAGING}/usr/local/lib/yuzu/.package-files.incoming"
            PLUGIN_COUNT=$((PLUGIN_COUNT + 1))
        done
    fi
    install -d "${STAGING}/Library/LaunchDaemons"
    install -m 644 "$SCRIPT_DIR/com.yuzu.agent.plist" "${STAGING}/Library/LaunchDaemons/.com.yuzu.agent.incoming.plist"
fi

install -d "${STAGING}/Library/LaunchDaemons" "${STAGING}/Library/Application Support/YuzuAgent" "${STAGING}/Library/Logs/Yuzu"
install -m 755 "$SCRIPT_DIR/uninstall.sh" "${STAGING}/usr/local/lib/yuzu/uninstall.sh"
printf '%s\n' "$PACKAGE_MODE" > "${STAGING}/usr/local/lib/yuzu/.package-mode.incoming"

ARCHES="$(lipo -archs "$AGENT_BIN")"
case "$ARCHES" in
    arm64) ARCH="arm64" ;;
    x86_64) ARCH="x86_64" ;;
    *) echo "ERROR: package must contain one supported architecture, got: $ARCHES" >&2; exit 1 ;;
esac
COMPONENT_PKG="$COMPONENT_DIR/yuzu-agent-component.pkg"
pkgbuild --root "$STAGING" --identifier "$IDENTIFIER" --version "$VERSION" --scripts "$SCRIPTS" --install-location / "$COMPONENT_PKG"
mkdir -p "$OUTPUT_DIR"
PRODUCT_PKG="$OUTPUT_DIR/YuzuAgent-${VERSION}-macos-${ARCH}.pkg"
DIST_XML="$COMPONENT_DIR/distribution.xml"
cat > "$DIST_XML" <<XML
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2"><title>Yuzu Agent ${VERSION}</title><organization>${IDENTIFIER}</organization><domains enable_localSystem="true"/><options customize="never" require-scripts="true" rootVolumeOnly="true"/><volume-check><allowed-os-versions><os-version min="13.3"/></allowed-os-versions></volume-check><choices-outline><line choice="default"><line choice="${IDENTIFIER}"/></line></choices-outline><choice id="default"/><choice id="${IDENTIFIER}" visible="false"><pkg-ref id="${IDENTIFIER}"/></choice><pkg-ref id="${IDENTIFIER}" version="${VERSION}" onConclusion="none">yuzu-agent-component.pkg</pkg-ref></installer-gui-script>
XML
productbuild --distribution "$DIST_XML" --package-path "$COMPONENT_DIR" "$PRODUCT_PKG"
echo "Built $PACKAGE_MODE package: $PRODUCT_PKG"
