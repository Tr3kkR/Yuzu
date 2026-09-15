#!/bin/bash
# Remove only Yuzu package-owned code and service files; retain operational data.
set -eu

PLIST="/Library/LaunchDaemons/com.yuzu.agent.plist"
MODE_FILE="/usr/local/lib/yuzu/package-mode"
MANIFEST="/usr/local/lib/yuzu/package-files.list"
LEGACY_APP="/Library/Application Support/Yuzu/YuzuAgent.app"
LEGACY_TEAM_ID="7RLSYL2JM7"
LEGACY_APP_ID="7RLSYL2JM7.co.uk.devnullsecurity.yuzu-agent"
LEGACY_SIGNING_AUTHORITY="Mac Developer: Nathan Dornbrook (YA95685L8R)"
LEGACY_PROFILE_SHA256="3e764aafaa5cd29398ef6646b98c7b00332404c5ea57f79b92663695acdd70e1"
STATE_DIR="/var/db/yuzu-agent"

legacy_app_is_managed() {
    local candidate="$1"
    [[ -d "$candidate" && ! -L "$candidate" ]] || return 1
    [[ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$candidate/Contents/Info.plist" 2>/dev/null || true)" \
        == "${LEGACY_APP_ID#*.}" ]] || return 1
    codesign --verify --deep --strict --verbose=2 "$candidate" >/dev/null 2>&1
    [[ "$(codesign -dvv "$candidate" 2>&1 | awk -F= '/^TeamIdentifier=/{print $2; exit}')" \
        == "$LEGACY_TEAM_ID" ]] || return 1
    [[ "$(codesign -dvv "$candidate" 2>&1 | awk -F= '/^Authority=/{print $2; exit}')" \
        == "$LEGACY_SIGNING_AUTHORITY" ]] || return 1
    [[ -f "$candidate/Contents/embedded.provisionprofile" ]] || return 1
    [[ "$(shasum -a 256 "$candidate/Contents/embedded.provisionprofile" | awk '{print $1}')" \
        == "$LEGACY_PROFILE_SHA256" ]]
}

retire_legacy_app() {
    local recovery retired
    [[ ! -e "$LEGACY_APP" && ! -L "$LEGACY_APP" ]] && return 0
    mkdir -p "$STATE_DIR"
    recovery="$(mktemp -d "${STATE_DIR}/uninstall-legacy.XXXXXX")"
    retired="$recovery/YuzuAgent.app"
    mv "$LEGACY_APP" "$retired"
    if legacy_app_is_managed "$retired"; then
        rm -rf "$retired" "$recovery"
        return 0
    fi
    echo "ERROR: retained unrecognized legacy app in $recovery; uninstall stopped before deleting package code" >&2
    return 1
}
launchctl bootout "system/com.yuzu.agent" >/dev/null 2>&1 || true
retire_legacy_app
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
rm -rf "/Library/Application Support/YuzuAgent/YuzuAgent.app" \
       "/Library/Application Support/YuzuAgent/.YuzuAgent.incoming.app" \
       /usr/local/lib/yuzu/.plugins.incoming
rm -f /usr/local/bin/yuzu-agent /usr/local/bin/.yuzu-agent.incoming \
      /usr/local/lib/libyuzu_agent_core.dylib /usr/local/lib/.libyuzu_agent_core.incoming.dylib \
      "$PLIST" /Library/LaunchDaemons/.com.yuzu.agent.incoming.plist \
      "$MODE_FILE" /usr/local/lib/yuzu/.package-mode.incoming \
      "$MANIFEST" /usr/local/lib/yuzu/.package-files.incoming \
      /usr/local/lib/yuzu/merge-launchd-plist.py \
      /usr/local/lib/yuzu/plugin-signing-policy.json /usr/local/lib/yuzu/uninstall.sh
pkgutil --forget com.yuzu.agent >/dev/null 2>&1 || true
echo "Yuzu Agent code removed. Data, logs, configuration, and trust anchors were preserved."
