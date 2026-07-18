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
# BR-002: a live-only flush is NOT sufficient to allow agent removal.
# The live flush restores reachability right now, but if the DURABLE
# on-disk state (the anchor file's contents, and/or the pf.conf hook)
# still exists, the very next reboot or `pfctl -f /etc/pf.conf`
# reconstructs the block — and with the agent gone, nothing is left to
# release it. So each durable leg's outcome is TRACKED below, and agent
# removal is gated: we only proceed past this block once at least one
# durable leg is CONFIRMED safe (anchor file confirmed empty/released,
# OR the pf.conf hook confirmed absent). If neither can be confirmed —
# including the case where pfctl itself is missing while Yuzu pf
# artifacts are still present, so teardown can't even be verified — we
# ABORT with a nonzero exit BEFORE touching launchd or deleting any
# files, and tell the operator how to finish by hand.
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
ANCHOR_LINE="anchor \"$PF_ANCHOR_NAME\""
LOAD_LINE="load anchor \"$PF_ANCHOR_NAME\" from \"$PF_ANCHOR_FILE\""
BANNER_LINE="# --- Yuzu agent quarantine anchor (scripts/install-agent-user.sh) ---"

# generate_released_anchor_body — the exact byte-for-byte empty/released
# form scripts/install-agent-user.sh's generate_pf_anchor_content()
# writes for a brand-new install. Used both to reset the anchor file and
# to detect whether it is ALREADY in that state (nothing to tear down).
generate_released_anchor_body() {
    cat <<EOF
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
}

# anchor_file_is_released — true (0) if the anchor file is absent, or
# present and byte-for-byte identical to the empty/released template
# above (i.e. no durable rules on disk). False (1) if it exists and
# holds something else.
anchor_file_is_released() {
    if [ ! -f "$PF_ANCHOR_FILE" ]; then
        return 0
    fi
    ANCHOR_EXPECTED_TMP="$(mktemp -t yuzu-pf-anchor-expected.XXXXXX)"
    generate_released_anchor_body > "$ANCHOR_EXPECTED_TMP"
    if diff -q "$ANCHOR_EXPECTED_TMP" "$PF_ANCHOR_FILE" >/dev/null 2>&1; then
        rm -f "$ANCHOR_EXPECTED_TMP"
        return 0
    fi
    rm -f "$ANCHOR_EXPECTED_TMP"
    return 1
}

# pf_conf_has_hook — true (0) if /etc/pf.conf currently wires in the
# Yuzu anchor (both exact lines present — same pairing the installer
# requires, see scripts/install-agent-user.sh's pf_conf_has_full_hook).
pf_conf_has_hook() {
    [ -f "$PF_CONF" ] || return 1
    grep -qxF "$ANCHOR_LINE" "$PF_CONF" 2>/dev/null && \
        grep -qxF "$LOAD_LINE" "$PF_CONF" 2>/dev/null
}

PF_ABORT=0

if ! command -v pfctl >/dev/null 2>&1; then
    # pfctl missing entirely. If there is genuinely nothing to tear down
    # (anchor file absent/already-released AND the pf.conf hook absent),
    # this is a safe no-op — proceed. Otherwise we cannot verify OR
    # complete teardown at all: proceeding would risk stranding the host
    # durably blocked with no agent left to release it. Fail closed.
    ANCHOR_RELEASED=1
    anchor_file_is_released || ANCHOR_RELEASED=0
    HOOK_PRESENT=0
    pf_conf_has_hook && HOOK_PRESENT=1

    if [ "$ANCHOR_RELEASED" -eq 1 ] && [ "$HOOK_PRESENT" -eq 0 ]; then
        echo "pfctl not found — no Yuzu pf quarantine artifacts present, nothing to tear down."
    else
        PF_ABORT=1
    fi
else
    # 1. Flush whatever quarantine rules are loaded LIVE in the anchor,
    #    first, for temporary reachability. Safe even if the anchor was
    #    never hooked into the main ruleset, was never populated, or pf
    #    is administratively disabled — pfctl just no-ops in those
    #    cases. NOTE: this alone does not clear the durable legs below,
    #    and is not sufficient by itself to allow agent removal.
    pfctl -a "$PF_ANCHOR_NAME" -F rules >/dev/null 2>&1 || true

    # 2. Reset the persistent anchor file back to the same empty/released
    #    body scripts/install-agent-user.sh's generate_pf_anchor_content()
    #    writes for a brand-new install — byte-for-byte — so a reboot or
    #    `pfctl -f /etc/pf.conf` after uninstall reconstructs an EMPTY
    #    anchor, never a stale `block all`. Written via `install` to a
    #    staged temp file first (same safe-replace idiom
    #    install-agent-user.sh uses) so a reload racing this uninstall
    #    can never observe a half-written file. TRACKED: ANCHOR_SAFE
    #    reflects whether this leg is confirmed to leave no durable
    #    rules on disk.
    ANCHOR_SAFE=0
    if [ ! -f "$PF_ANCHOR_FILE" ]; then
        ANCHOR_SAFE=1
    else
        PF_ANCHOR_TMP="$(mktemp -t yuzu-pf-anchor-uninstall.XXXXXX)"
        generate_released_anchor_body > "$PF_ANCHOR_TMP"
        if install -m 0644 -o root -g wheel "$PF_ANCHOR_TMP" "$PF_ANCHOR_FILE" 2>/dev/null; then
            ANCHOR_SAFE=1
        else
            echo "WARNING: could not reset $PF_ANCHOR_FILE to its empty/released form — the live anchor was already flushed above, but a future pf reload may not reconstruct it as empty. Reset it by hand." >&2
        fi
        rm -f "$PF_ANCHOR_TMP"
    fi

    # 3. Remove ONLY the exact two-line hook (plus its banner comment)
    #    scripts/install-agent-user.sh appends to /etc/pf.conf — never
    #    touch any other line, including pre-existing operator-authored
    #    pf rules/anchors. Idempotent: a no-op if the hook isn't present.
    #    TRACKED: HOOK_SAFE reflects whether this leg is confirmed to
    #    leave the hook out of pf.conf.
    HOOK_SAFE=0
    if [ ! -f "$PF_CONF" ]; then
        HOOK_SAFE=1
    elif ! pf_conf_has_hook; then
        HOOK_SAFE=1
    else
        PF_CONF_TMP="$(mktemp -t yuzu-pf-conf-uninstall.XXXXXX)"
        grep -vxF -e "$BANNER_LINE" -e "$ANCHOR_LINE" -e "$LOAD_LINE" "$PF_CONF" > "$PF_CONF_TMP" || true

        if pfctl -nf "$PF_CONF_TMP" >/dev/null 2>&1; then
            if install -m 0644 -o root -g wheel "$PF_CONF_TMP" "$PF_CONF" 2>/dev/null; then
                HOOK_SAFE=1
                # 4. Reload so pf picks up both the cleared anchor and
                #    the unhooked main ruleset. Best-effort: a reload
                #    failure here doesn't undo the fact that the hook
                #    itself is already gone from disk, so it does not
                #    flip HOOK_SAFE back off.
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

    # Gate: only continue toward agent removal if at least one durable
    # leg is CONFIRMED to leave no reconstructable quarantine state
    # behind. If BOTH legs failed, a future reload/reboot could still
    # rebuild the stale `block all` with the agent already gone.
    if [ "$ANCHOR_SAFE" -ne 1 ] && [ "$HOOK_SAFE" -ne 1 ]; then
        PF_ABORT=1
    fi
fi

if [ "$PF_ABORT" -eq 1 ]; then
    echo "" >&2
    echo "ERROR: could not confirm the durable pf quarantine teardown is safe — ABORTING before removing the Yuzu Agent." >&2
    echo "       Neither the anchor file ($PF_ANCHOR_FILE) could be confirmed reset to its empty/released form, nor could" >&2
    echo "       the anchor hook be confirmed removed from $PF_CONF (or pfctl is missing while Yuzu pf artifacts are" >&2
    echo "       still present, so teardown could not even be verified)." >&2
    echo "       Removing the agent now could strand this host: a future reboot or 'pfctl -f $PF_CONF' reload could" >&2
    echo "       reconstruct a stale quarantine block with no agent left to release it." >&2
    echo "" >&2
    echo "       To finish manually, then re-run this uninstall:" >&2
    echo "         1. If the agent is still running, release any active quarantine first (the" >&2
    echo "            quarantine.unquarantine action), or" >&2
    echo "         2. As root: pfctl -a $PF_ANCHOR_NAME -F rules" >&2
    echo "         3. Reset $PF_ANCHOR_FILE to an empty anchor body (no filter rules)." >&2
    echo "         4. Remove the '$BANNER_LINE' banner and its two lines" >&2
    echo "            ($ANCHOR_LINE / $LOAD_LINE) from $PF_CONF, then run: pfctl -f $PF_CONF" >&2
    exit 1
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
