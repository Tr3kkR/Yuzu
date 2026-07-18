#!/bin/bash
# Uninstall the Yuzu Agent from macOS.
# Run as: sudo bash /usr/local/lib/yuzu/uninstall.sh

set -e

echo "Uninstalling Yuzu Agent..."

# ── pf quarantine anchor teardown ────────────────────────────────────────
#
# scripts/install-agent-user.sh's macOS provisioning step hooks a
# "yuzu-quarantine" pf anchor into /etc/pf.conf's active main ruleset.
# The quarantine plugin (agents/plugins/quarantine/src/quarantine_plugin.
# cpp) mirrors whatever `block all` ruleset it loads live into that
# anchor out to /etc/pf.anchors/yuzu-quarantine too, so the quarantine is
# DURABLE — it survives a reboot or `pfctl -f /etc/pf.conf` reload. If
# this uninstall script doesn't undo that, uninstalling the agent on a
# host that happens to be quarantined at that moment leaves it blocked
# FOREVER: every future reboot / pf reload re-imposes `block all` with no
# agent left to release it. This teardown MUST run before we stop/remove
# the agent below.
#
# This block is self-contained (no dependency on scripts/install-agent-
# user.sh being present at uninstall time — this .pkg-driven path may run
# standalone) but keeps the exact same contract: anchor name
# "yuzu-quarantine", anchor file /etc/pf.anchors/yuzu-quarantine, and the
# same empty/released anchor body + two-line pf.conf hook the installer
# writes. Every step tolerates "already clean" (pf disabled, anchor
# absent, hook absent) so this is a safe no-op on a host that was never
# provisioned, or on a second uninstall run.

PF_ANCHOR_NAME="yuzu-quarantine"
PF_ANCHOR_FILE="/etc/pf.anchors/yuzu-quarantine"
PF_CONF="/etc/pf.conf"

if command -v pfctl >/dev/null 2>&1; then
    # 1. Flush whatever quarantine rules are loaded LIVE in the anchor.
    #    Safe even if the anchor was never hooked into the main ruleset,
    #    was never populated, or pf is administratively disabled — pfctl
    #    just no-ops in those cases.
    pfctl -a "$PF_ANCHOR_NAME" -F rules >/dev/null 2>&1 || true

    # 2. Reset the persistent anchor file back to the same empty/released
    #    body scripts/install-agent-user.sh's generate_pf_anchor_content()
    #    writes for a brand-new install — byte-for-byte — so a reboot or
    #    `pfctl -f /etc/pf.conf` after uninstall reconstructs an EMPTY
    #    anchor, never a stale `block all`. Written via `install` to a
    #    staged temp file first (same safe-replace idiom
    #    install-agent-user.sh uses) so a reload racing this uninstall
    #    can never observe a half-written file.
    if [ -f "$PF_ANCHOR_FILE" ]; then
        PF_ANCHOR_TMP="$(mktemp -t yuzu-pf-anchor-uninstall.XXXXXX)"
        cat > "$PF_ANCHOR_TMP" <<EOF
# Yuzu agent quarantine anchor — provisioned by scripts/install-agent-user.sh.
#
# Initial state is empty (no rules — a deliberate no-op): an anchor with
# no filter rules matches nothing, so hooking it into the main ruleset
# cannot itself pass or block any traffic. A future quarantine_plugin.cpp
# rework (tracked as A-1.18) is expected to overwrite this anchor's rules
# via \`pfctl -a $PF_ANCHOR_NAME -f <tempfile>\` on quarantine / whitelist /
# unquarantine dispatch — treat this file's on-disk contents as a build
# artifact between dispatches once that lands, not source of truth.
#
# Anchor name and this file's path are PINNED in
# docs/agent-privilege-model.md — do not rename either without updating
# quarantine_plugin.cpp in lockstep.
EOF
        if ! install -m 0644 -o root -g wheel "$PF_ANCHOR_TMP" "$PF_ANCHOR_FILE" 2>/dev/null; then
            echo "WARNING: could not reset $PF_ANCHOR_FILE to its empty/released form — the live anchor was already flushed above, but a future pf reload may not reconstruct it as empty. Reset it by hand." >&2
        fi
        rm -f "$PF_ANCHOR_TMP"
    fi

    # 3. Remove ONLY the exact two-line hook (plus its banner comment)
    #    scripts/install-agent-user.sh appends to /etc/pf.conf — never
    #    touch any other line, including pre-existing operator-authored
    #    pf rules/anchors. Idempotent: a no-op if the hook isn't present.
    if [ -f "$PF_CONF" ]; then
        ANCHOR_LINE="anchor \"$PF_ANCHOR_NAME\""
        LOAD_LINE="load anchor \"$PF_ANCHOR_NAME\" from \"$PF_ANCHOR_FILE\""
        BANNER_LINE="# --- Yuzu agent quarantine anchor (scripts/install-agent-user.sh) ---"

        if grep -qxF "$ANCHOR_LINE" "$PF_CONF" 2>/dev/null && \
           grep -qxF "$LOAD_LINE" "$PF_CONF" 2>/dev/null; then
            PF_CONF_TMP="$(mktemp -t yuzu-pf-conf-uninstall.XXXXXX)"
            grep -vxF -e "$BANNER_LINE" -e "$ANCHOR_LINE" -e "$LOAD_LINE" "$PF_CONF" > "$PF_CONF_TMP" || true

            if pfctl -nf "$PF_CONF_TMP" >/dev/null 2>&1; then
                if install -m 0644 -o root -g wheel "$PF_CONF_TMP" "$PF_CONF" 2>/dev/null; then
                    # 4. Reload so pf picks up both the cleared anchor and
                    #    the unhooked main ruleset.
                    if ! pfctl -f "$PF_CONF" >/dev/null 2>&1; then
                        echo "WARNING: pfctl -f $PF_CONF failed after removing the quarantine anchor hook — verify manually with 'pfctl -s rules' that no stale hook remains loaded." >&2
                    fi
                else
                    echo "WARNING: could not update $PF_CONF to remove the quarantine anchor hook — the live anchor rules were already flushed above, so this host is not blocked right now, but remove the hook from $PF_CONF by hand to fully finish uninstalling." >&2
                fi
            else
                echo "WARNING: could not validate $PF_CONF after removing the quarantine anchor hook (pfctl -nf failed) — left the hook in place. The live anchor rules were already flushed above, so this host is not blocked right now." >&2
            fi
            rm -f "$PF_CONF_TMP"
        fi
    fi
else
    echo "pfctl not found — skipping pf quarantine anchor teardown (nothing to undo)."
fi

# Stop and unload the launch daemon
if launchctl list com.yuzu.agent &>/dev/null; then
    launchctl unload /Library/LaunchDaemons/com.yuzu.agent.plist 2>/dev/null || true
    sleep 2
fi

# Remove files
rm -f /usr/local/bin/yuzu-agent
rm -f /usr/local/lib/libyuzu_agent_core.dylib
rm -rf /usr/local/lib/yuzu/
rm -f /Library/LaunchDaemons/com.yuzu.agent.plist

# Forget the package receipt
pkgutil --forget com.yuzu.agent 2>/dev/null || true

echo "Yuzu Agent uninstalled."
echo ""
echo "Data directory preserved: /Library/Application Support/Yuzu"
echo "Log directory preserved:  /Library/Logs/Yuzu"
echo "Remove manually if no longer needed."
