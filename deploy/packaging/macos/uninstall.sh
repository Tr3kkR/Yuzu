#!/bin/bash
# Remove only Yuzu package-owned code and service files; retain operational data.
set -eu

PLIST="/Library/LaunchDaemons/com.yuzu.agent.plist"
MODE_FILE="/usr/local/lib/yuzu/package-mode"
MANIFEST="/usr/local/lib/yuzu/package-files.list"
launchctl bootout "system/com.yuzu.agent" >/dev/null 2>&1 || true
if [[ -f "$MANIFEST" ]]; then
    while IFS= read -r relative; do
        [[ "$relative" == plugins/* ]] || continue
        plugin="${relative#plugins/}"
        [[ -n "$plugin" && "$plugin" != */* && "$plugin" != .* ]] || {
            echo "ERROR: invalid package plugin manifest entry" >&2; exit 1; }
        rm -f "/usr/local/lib/yuzu/plugins/$plugin" "/usr/local/lib/yuzu/plugins/$plugin.sig"
    done < "$MANIFEST"
fi
# Both lanes are package-owned. Remove both so a loose-to-bundle (or reverse)
# transition cannot leave executable code behind.
rm -rf "/Library/Application Support/Yuzu/YuzuAgent.app" \
       "/Library/Application Support/Yuzu/.YuzuAgent.incoming.app" \
       /usr/local/lib/yuzu/.plugins.incoming
rm -f /usr/local/bin/yuzu-agent /usr/local/bin/.yuzu-agent.incoming \
      /usr/local/lib/libyuzu_agent_core.dylib /usr/local/lib/.libyuzu_agent_core.incoming.dylib \
      "$PLIST" /Library/LaunchDaemons/.com.yuzu.agent.incoming.plist \
      "$MODE_FILE" /usr/local/lib/yuzu/.package-mode.incoming \
      "$MANIFEST" /usr/local/lib/yuzu/.package-files.incoming /usr/local/lib/yuzu/uninstall.sh
pkgutil --forget com.yuzu.agent >/dev/null 2>&1 || true
echo "Yuzu Agent code removed. Data, logs, configuration, and trust anchors were preserved."
