#!/usr/bin/env bash
###############################################################################
# install-agent-user.sh — provision the unprivileged account the Yuzu agent
#                        runs under, plus the narrow privilege grants it
#                        needs to operate plugins like quarantine,
#                        services.set_start_mode, and network_actions.flush_dns.
#
# AUTHORITY
# ─────────
# This script is the implementation of the privilege model defined in
# docs/agent-privilege-model.md. If the doc and the script disagree,
# the doc wins — fix the script, then re-run.
#
# WHAT THIS SCRIPT DOES
# ─────────────────────
# 1.  Creates a dedicated system user the agent runs under:
#       macOS:  _yuzu      (UID/GID auto-assigned in the 200-400 system range,
#                          following the Apple convention of leading-underscore
#                          names for system daemons — _postgres, _www, etc.)
#       Linux:  yuzu       (UID/GID auto-assigned by `useradd --system` in
#                          the distro's system-user range, typically <1000)
# 2.  Creates the agent's filesystem hierarchy with correct ownership:
#       /var/lib/yuzu-agent/    or  /Library/Application Support/Yuzu/   (state)
#       /var/cache/yuzu-agent/  or  /Library/Caches/Yuzu/                (staging)
#       /var/log/yuzu-agent/    or  /Library/Logs/Yuzu/                  (logs)
# 3.  Adds the user to the platform-specific groups it needs:
#       Linux:  systemd-journal (read journal), adm (read /var/log/*)
#       macOS:  (no extra group memberships needed beyond the user record)
# 4.  Installs /etc/sudoers.d/yuzu-agent with NOPASSWD entries for the
#       narrow set of privileged commands plugins shell out to.
#       The file is validated with `visudo -cf` before being moved into
#       place — a syntactically broken sudoers file would brick the
#       entire sudo subsystem on this host, so we never write to
#       /etc/sudoers.d/ directly.
# 5.  (Linux only) Sets file capabilities on the agent binary so plugins
#       that need raw sockets, ptrace, or ip-route management can do
#       so without an extra sudo round-trip:
#         cap_net_admin,cap_net_raw,cap_dac_read_search,cap_sys_ptrace +eip
# 6.  (macOS only) Provisions the pf-anchor ACTIVATION prerequisite the
#       quarantine plugin depends on: installs /etc/pf.anchors/yuzu-quarantine
#       (initial pass-all), idempotently hooks `anchor "yuzu-quarantine"` +
#       `load anchor ... from ...` into the active /etc/pf.conf main
#       ruleset, then loads and enables pf. Without this hook, rules the
#       plugin loads into the anchor at runtime have no effect on live
#       traffic — see docs/agent-privilege-model.md.
# 7.  (Optional) On both platforms, prints a verifying summary that the
#       operator can spot-check.
#
# WHAT THIS SCRIPT DOES NOT DO
# ─────────────────────────────
# - Install the agent binary itself. Use `meson install` or the platform
#   installer (`.pkg` on macOS, `.deb`/`.rpm` on Linux) for that.
# - Register the agent with launchd / systemd. Those plists/units belong
#   alongside the binary install, not the user provisioning.
# - Touch the `interaction` plugin's per-session helper. Popups need a
#   logged-in user's GUI session, which a daemon running as _yuzu cannot
#   reach. The interaction helper is a separate (future) per-user agent
#   process loaded by launchd at login / systemd --user. Out of scope here.
# - Generate the agent's mTLS cert/key. That comes from the server
#   enrollment flow, not the install step.
#
# IDEMPOTENCY
# ───────────
# Every step probes for the existing target state and skips if already
# present. Running this script twice is safe and changes nothing on the
# second pass. The sudoers file is overwritten each run (so you can
# update the privilege list and re-run), but only after passing
# `visudo -cf`.
#
# UNINSTALL
# ─────────
# Pass --uninstall to reverse:
#   - (macOS only) tears down the pf quarantine anchor FIRST: flushes any
#     live rules from the "yuzu-quarantine" anchor, resets the persistent
#     anchor file back to its empty/released form, and removes the
#     anchor hook from /etc/pf.conf, reloading pf — so a host that is
#     quarantined at uninstall time is released, not left blocked forever
#     across future reboots / pf reloads
#   - removes /etc/sudoers.d/yuzu-agent
#   - removes the agent's filesystem hierarchy (logs are preserved
#     under /var/log/yuzu-agent.removed-<timestamp>/ for forensics)
#   - deletes the user account
# Capabilities applied to the agent binary are NOT removed because the
# binary itself is not owned by this script — uninstall the package to
# remove the binary, capabilities go with it.
#
# ARGUMENTS
# ─────────
#   --dry-run        Print every command the script would run, without
#                    executing any of them. Use this first.
#   --check          Verify the install is correct (user exists with
#                    expected attributes, sudoers file present + valid,
#                    state dirs exist with correct ownership). Exits
#                    non-zero on any drift.
#   --uninstall      Remove the user, sudoers file, and state dirs.
#   --account-name N Override the default account name (_yuzu / yuzu).
#                    Useful for parallel test environments.
#   --binary-path P  Override the path to the agent binary for setcap.
#                    Default: /usr/local/bin/yuzu-agent (Linux) or
#                    /Library/Application\ Support/Yuzu/yuzu-agent (macOS).
#                    On macOS this is a no-op (no setcap equivalent).
#   --no-sudoers     Skip the sudoers file install. Useful in test
#                    environments where you don't want any privilege
#                    grants; the agent will still run but quarantine
#                    and other privileged plugins will fail at dispatch
#                    time (which the test ladder catches).
#   --no-setcap      Skip the setcap step on Linux. Useful if you set
#                    capabilities via a packaging tool (.deb postinst,
#                    .rpm %post).
#
# EXIT CODES
# ──────────
#   0  - install/check/uninstall succeeded
#   1  - install/check/uninstall failed; details on stderr
#   2  - argument or precondition error (not run as root, unsupported OS)
#   3  - sudoers file failed visudo validation; install was rolled back
#
# THIS SCRIPT MUST BE RUN AS ROOT.
# We don't try to be cute about that — every action below requires root.
###############################################################################

set -uo pipefail

# ── argument defaults ────────────────────────────────────────────────────────

ACTION="install"           # install | check | uninstall
DRY_RUN=0
ACCOUNT_NAME=""            # filled in based on platform if not specified
BINARY_PATH=""             # filled in based on platform if not specified
SKIP_SUDOERS=0
SKIP_SETCAP=0

# ── platform detection ───────────────────────────────────────────────────────
# We support exactly two platforms in this script: macOS and Linux. The
# Windows path is install-agent-user.ps1; this script's --help refuses to
# proceed on anything else so a misuse on FreeBSD / OpenBSD / etc. fails
# fast with a clear message rather than silently corrupting state.

OS="$(uname -s)"
case "$OS" in
    Darwin)
        PLATFORM="macos"
        DEFAULT_ACCOUNT="_yuzu"
        # macOS canonical paths for system daemons follow the Apple File
        # System Programming Guide. /Library/* is system-wide; ~/Library/*
        # is per-user. Daemon state, caches, and logs all under /Library/.
        STATE_DIR="/Library/Application Support/Yuzu"
        CACHE_DIR="/Library/Caches/Yuzu"
        LOG_DIR="/Library/Logs/Yuzu"
        DEFAULT_BINARY_PATH="/Library/Application Support/Yuzu/yuzu-agent"
        # pf-anchor ACTIVATION prerequisite for the quarantine plugin (see
        # docs/agent-privilege-model.md, "macOS pf-anchor provisioning").
        # PINNED for agents/plugins/quarantine/src/quarantine_plugin.cpp to
        # match byte-for-byte — do not rename either in isolation.
        PF_ANCHOR_NAME="yuzu-quarantine"
        PF_ANCHOR_FILE="/etc/pf.anchors/yuzu-quarantine"
        PF_CONF="/etc/pf.conf"
        ;;
    Linux)
        PLATFORM="linux"
        DEFAULT_ACCOUNT="yuzu"
        # Linux canonical paths follow the Filesystem Hierarchy Standard.
        # /var/lib/<pkg>/   - persistent state
        # /var/cache/<pkg>/ - regenerable cache (staging area for content_dist)
        # /var/log/<pkg>/   - log files (managed by logrotate in production)
        STATE_DIR="/var/lib/yuzu-agent"
        CACHE_DIR="/var/cache/yuzu-agent"
        LOG_DIR="/var/log/yuzu-agent"
        DEFAULT_BINARY_PATH="/usr/local/bin/yuzu-agent"
        ;;
    *)
        echo "error: unsupported platform: $OS" >&2
        echo "       this script supports macOS (Darwin) and Linux only." >&2
        echo "       for Windows, use scripts/install-agent-user.ps1." >&2
        exit 2
        ;;
esac

# ── argument parsing ─────────────────────────────────────────────────────────

usage() {
    sed -n '/^# install-agent-user.sh/,/^# THIS SCRIPT MUST BE RUN AS ROOT/p' "$0" \
        | sed 's/^# \?//' | sed '$d'
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)        DRY_RUN=1; shift ;;
        --check)          ACTION="check"; shift ;;
        --uninstall)      ACTION="uninstall"; shift ;;
        --account-name)   ACCOUNT_NAME="$2"; shift 2 ;;
        --binary-path)    BINARY_PATH="$2"; shift 2 ;;
        --no-sudoers)     SKIP_SUDOERS=1; shift ;;
        --no-setcap)      SKIP_SETCAP=1; shift ;;
        -h|--help)        usage; exit 0 ;;
        *)                echo "unknown arg: $1" >&2; echo "use --help for usage." >&2; exit 2 ;;
    esac
done

ACCOUNT_NAME="${ACCOUNT_NAME:-$DEFAULT_ACCOUNT}"
BINARY_PATH="${BINARY_PATH:-$DEFAULT_BINARY_PATH}"

# ── helpers ──────────────────────────────────────────────────────────────────

# run() executes a command (or just prints it under --dry-run). Shell
# quoting matters here: the array form preserves argument boundaries so
# paths with spaces (macOS "/Library/Application Support/Yuzu") survive
# unmangled.
run() {
    if [[ "$DRY_RUN" -eq 1 ]]; then
        printf '[dry-run] '
        printf '%q ' "$@"
        printf '\n'
    else
        "$@"
    fi
}

# log() — info messages on stdout, distinct from command output.
log() { printf '[install-agent-user] %s\n' "$*"; }
warn() { printf '[install-agent-user] WARN: %s\n' "$*" >&2; }
fail() { printf '[install-agent-user] ERROR: %s\n' "$*" >&2; exit 1; }

# require_root — most actions need root; we fail early rather than
# half-running and leaving a partially-installed state. --dry-run and
# --check are exempt: dry-run only prints what would happen, and check
# only reads state.
require_root() {
    if [[ "$DRY_RUN" -eq 1 ]]; then
        return 0
    fi
    if [[ "$EUID" -ne 0 ]]; then
        fail "must be run as root (use sudo). EUID=$EUID"
    fi
}

# ── platform-specific user management ────────────────────────────────────────
#
# macOS uses Directory Services (`dscl`) to manage local accounts, not
# /etc/passwd. The local DS database lives under /var/db/dslocal/ and
# is what `dscl . -list /Users` queries.
#
# Linux uses /etc/passwd + /etc/group via useradd/groupadd. Service-mode
# users are created with `--system` to get a UID/GID below SYS_UID_MAX
# (usually 999) and with --no-create-home + --shell /usr/sbin/nologin so
# the account can't be used for login.

macos_user_exists() {
    dscl . -read "/Users/$ACCOUNT_NAME" >/dev/null 2>&1
}

macos_group_exists() {
    dscl . -read "/Groups/$ACCOUNT_NAME" >/dev/null 2>&1
}

# Pick an ID >= 200 that is free in BOTH the user and group namespaces.
# macOS user UIDs and group GIDs are independent number spaces — Apple
# ships `_guest` at GID 201 and `_yuzu` at no UID, so naively assuming
# UID==GID lands on a collision. We scan both lists and find the first
# integer that's used by neither, so the resulting account has matching
# UID and GID for ergonomic consistency with the Linux convention.
macos_pick_free_id() {
    {
        dscl . -list /Users UniqueID 2>/dev/null | awk '{print $2}'
        dscl . -list /Groups PrimaryGroupID 2>/dev/null | awk '{print $2}'
    } \
        | sort -un \
        | awk 'BEGIN{u=200} $1==u{u++} END{print u}'
}

macos_create_user() {
    local user_exists group_exists
    macos_user_exists && user_exists=1 || user_exists=0
    macos_group_exists && group_exists=1 || group_exists=0

    # If both records are present AND the user's PrimaryGroupID actually
    # resolves to the `_yuzu` group (not, say, `_guest` because a prior
    # collision left the user's PGID pointing somewhere else), skip the
    # whole sequence. Otherwise fall through to the repair path below.
    if [[ "$user_exists" -eq 1 && "$group_exists" -eq 1 ]]; then
        local user_pgid group_pgid
        user_pgid=$(dscl . -read "/Users/$ACCOUNT_NAME" PrimaryGroupID 2>/dev/null \
                        | awk '/PrimaryGroupID:/ {print $2}')
        group_pgid=$(dscl . -read "/Groups/$ACCOUNT_NAME" PrimaryGroupID 2>/dev/null \
                         | awk '/PrimaryGroupID:/ {print $2}')
        if [[ -n "$user_pgid" && -n "$group_pgid" && "$user_pgid" == "$group_pgid" ]]; then
            log "user and group $ACCOUNT_NAME already consistent (gid=$user_pgid) — skipping"
            return 0
        fi
        log "user and group $ACCOUNT_NAME exist but inconsistent " \
            "(user pgid='${user_pgid:-<missing>}', group pgid='${group_pgid:-<missing>}') — repairing"
    fi

    local next_id
    next_id=$(macos_pick_free_id)
    log "selected ID $next_id (free in both /Users UniqueID and /Groups PrimaryGroupID)"

    if [[ "$user_exists" -eq 0 ]]; then
        log "creating macOS user $ACCOUNT_NAME (UID=$next_id, hidden, no shell)"
        run dscl . -create "/Users/$ACCOUNT_NAME"
        run dscl . -create "/Users/$ACCOUNT_NAME" UserShell /usr/bin/false
        run dscl . -create "/Users/$ACCOUNT_NAME" RealName "Yuzu Agent Daemon"
        run dscl . -create "/Users/$ACCOUNT_NAME" UniqueID "$next_id"
        run dscl . -create "/Users/$ACCOUNT_NAME" PrimaryGroupID "$next_id"
        run dscl . -create "/Users/$ACCOUNT_NAME" NFSHomeDirectory /var/empty
        run dscl . -create "/Users/$ACCOUNT_NAME" Password "*"
        # Hide from the login window's user picker (cosmetic but expected).
        run dscl . -create "/Users/$ACCOUNT_NAME" IsHidden 1
    else
        log "user $ACCOUNT_NAME exists — repointing PrimaryGroupID to $next_id"
        # Self-heal a partial install where the user record exists but
        # its PrimaryGroupID points at someone else's GID (commonly
        # `_guest` if a prior run grabbed UID 201 without checking the
        # group namespace).
        run dscl . -create "/Users/$ACCOUNT_NAME" PrimaryGroupID "$next_id"
    fi

    # Matching group entry. Without it, anything that maps gid → name
    # (ls -l, `ps`, install -g) prints the bare GID instead of `_yuzu` —
    # or, worse, fails outright with "unknown group".
    if [[ "$group_exists" -eq 0 ]]; then
        log "creating macOS group $ACCOUNT_NAME (GID=$next_id)"
        run dscl . -create "/Groups/$ACCOUNT_NAME"
        run dscl . -create "/Groups/$ACCOUNT_NAME" PrimaryGroupID "$next_id"
        run dscl . -create "/Groups/$ACCOUNT_NAME" Password "*"
        run dscl . -create "/Groups/$ACCOUNT_NAME" RealName "Yuzu Agent Daemon"
    else
        log "group $ACCOUNT_NAME exists — repairing PrimaryGroupID to $next_id"
        # Self-heal a partial install where the group record was created
        # but its PrimaryGroupID couldn't be set (e.g., earlier dscl
        # collision on the chosen GID). Without a PrimaryGroupID, the
        # group is invisible to getgrnam() and `install -g` fails.
        run dscl . -create "/Groups/$ACCOUNT_NAME" PrimaryGroupID "$next_id"
    fi

    # Flush the Directory Services cache so getpwnam() / getgrnam() see
    # the new records immediately. Without this, the very next `install
    # -o _yuzu -g _yuzu` call after group creation fails with
    # "install: unknown group _yuzu" because the cache hasn't picked
    # up the new dscl record yet. dscacheutil is idempotent and harmless.
    run dscacheutil -flushcache
}

macos_delete_user() {
    if macos_user_exists; then
        log "deleting macOS user $ACCOUNT_NAME"
        run dscl . -delete "/Users/$ACCOUNT_NAME" || true
        run dscl . -delete "/Groups/$ACCOUNT_NAME" || true
    fi
}

linux_user_exists() {
    getent passwd "$ACCOUNT_NAME" >/dev/null 2>&1
}

linux_create_user() {
    log "creating Linux system user $ACCOUNT_NAME"
    # --system  : pick UID/GID from the system range
    # --no-create-home : don't auto-create a home dir; we manage state
    #                    dirs explicitly below.
    # --shell /usr/sbin/nologin : refuse interactive logins.
    # --home <dir> : the home dir we create separately as the state dir.
    run useradd \
        --system \
        --no-create-home \
        --shell /usr/sbin/nologin \
        --home "$STATE_DIR" \
        --comment "Yuzu Agent Daemon" \
        "$ACCOUNT_NAME"

    # Group memberships — the install adds these unconditionally because
    # the cost of being-in-a-group-you-don't-need is zero, but the cost
    # of being-NOT-in-a-group-you-do-need is a runtime failure that
    # operators have to debug. We only add to groups that exist on this
    # host (some distros don't ship `adm`, for example).
    for group in systemd-journal adm; do
        if getent group "$group" >/dev/null 2>&1; then
            log "  adding $ACCOUNT_NAME to group $group"
            run usermod -aG "$group" "$ACCOUNT_NAME"
        else
            warn "  group $group not present on this host — skipping"
        fi
    done
}

linux_delete_user() {
    if linux_user_exists; then
        log "deleting Linux system user $ACCOUNT_NAME"
        # --remove deletes the home dir; we created the home dir ourselves,
        # but we'll deliberately handle that under remove_state_dirs() so
        # we get the audit-preserve behavior.
        run userdel "$ACCOUNT_NAME" || true
    fi
}

# ── state-dir management ─────────────────────────────────────────────────────

create_state_dirs() {
    for dir in "$STATE_DIR" "$CACHE_DIR" "$LOG_DIR"; do
        if [[ ! -d "$dir" ]]; then
            log "creating $dir"
            run install -d -m 0750 -o "$ACCOUNT_NAME" -g "$ACCOUNT_NAME" "$dir"
        else
            # Already exists — re-set ownership in case a previous run
            # left it root-owned, but leave the mode bits alone (operator
            # might have tightened them).
            log "ensuring ownership of $dir"
            run chown -R "$ACCOUNT_NAME:$ACCOUNT_NAME" "$dir"
        fi
    done
}

remove_state_dirs() {
    for dir in "$STATE_DIR" "$CACHE_DIR"; do
        if [[ -d "$dir" ]]; then
            log "removing $dir"
            run rm -rf "$dir"
        fi
    done
    # Logs are preserved on uninstall — we rename rather than delete so
    # forensic / post-mortem investigation can still reach them. Operator
    # decides when to delete them.
    if [[ -d "$LOG_DIR" ]]; then
        local archive="${LOG_DIR}.removed-$(date -u +%Y%m%dT%H%M%SZ)"
        log "preserving $LOG_DIR -> $archive"
        run mv "$LOG_DIR" "$archive"
    fi
}

# ── sudoers management ───────────────────────────────────────────────────────
#
# /etc/sudoers.d/ files are sourced by sudo on every invocation. A
# syntactically broken file in this directory will cause EVERY sudo call
# on the system to fail — including the one you'd use to fix the broken
# file. So:
#
#  1. We always write to a temp file under /tmp first.
#  2. We validate with `visudo -cf <tempfile>` and refuse to install if
#     it doesn't pass.
#  3. We use `install` with mode 0440 owner root:root. Any other ownership
#     or any group/other write bit causes sudo to refuse to load the file
#     (visible in `journalctl -u sudo` / Console.app).
#  4. We never echo the sudoers contents into the live file directly —
#     a pipe failure mid-write would leave half a file in place.

generate_sudoers_content() {
    cat <<EOF
# Yuzu agent — privileged commands the agent shells out to from plugin code.
#
# This file is owned by scripts/install-agent-user.sh — DO NOT edit by hand.
# Re-run the installer with an updated privilege list to change it; the
# installer validates with visudo -cf before atomic replace.
#
# Audit trail for this file is the install script's git history.
#
# All commands are NOPASSWD because the agent runs non-interactively as
# a daemon. Each entry uses an absolute binary path to prevent
# PATH-injection sudo bypass.
#
# DELIBERATELY NOT GRANTED:
#   - generic ALL=(ALL) sudo (would make the audit surface infinite)
#   - script_exec.exec / script_exec.bash / script_exec.powershell
#     (these run in the agent's own context; if an operator wants to
#     run a privileged script they should approve a quarantine-class
#     instruction that wraps the specific command)
#   - SeLoadDriverPrivilege equivalent (kernel driver loading)
#   - chown / chmod (agent should never rewrite ACLs)

EOF

    if [[ "$PLATFORM" == "macos" ]]; then
        cat <<EOF
# quarantine plugin — pf firewall management
$ACCOUNT_NAME ALL=(root) NOPASSWD: /sbin/pfctl

# services.set_start_mode — launchd system domain
$ACCOUNT_NAME ALL=(root) NOPASSWD: /bin/launchctl bootstrap system *
$ACCOUNT_NAME ALL=(root) NOPASSWD: /bin/launchctl bootout system *
$ACCOUNT_NAME ALL=(root) NOPASSWD: /bin/launchctl enable system/*
$ACCOUNT_NAME ALL=(root) NOPASSWD: /bin/launchctl disable system/*

# network_actions.flush_dns
$ACCOUNT_NAME ALL=(root) NOPASSWD: /usr/bin/dscacheutil -flushcache
$ACCOUNT_NAME ALL=(root) NOPASSWD: /usr/bin/killall -HUP mDNSResponder

# certificates.delete (system keychain only — user keychain is non-privileged)
$ACCOUNT_NAME ALL=(root) NOPASSWD: /usr/bin/security delete-certificate -t /Library/Keychains/System.keychain *

EOF
    else  # linux
        cat <<EOF
# quarantine plugin — iptables / ip6tables / nftables
$ACCOUNT_NAME ALL=(root) NOPASSWD: /usr/sbin/iptables, /usr/sbin/iptables-save, /usr/sbin/iptables-restore
$ACCOUNT_NAME ALL=(root) NOPASSWD: /usr/sbin/ip6tables, /usr/sbin/ip6tables-save, /usr/sbin/ip6tables-restore
$ACCOUNT_NAME ALL=(root) NOPASSWD: /usr/sbin/nft

# services.set_start_mode — systemd unit lifecycle
$ACCOUNT_NAME ALL=(root) NOPASSWD: /bin/systemctl enable *,  /bin/systemctl disable *
$ACCOUNT_NAME ALL=(root) NOPASSWD: /bin/systemctl mask *,    /bin/systemctl unmask *
$ACCOUNT_NAME ALL=(root) NOPASSWD: /usr/bin/systemctl enable *,  /usr/bin/systemctl disable *
$ACCOUNT_NAME ALL=(root) NOPASSWD: /usr/bin/systemctl mask *,    /usr/bin/systemctl unmask *

# network_actions.flush_dns
$ACCOUNT_NAME ALL=(root) NOPASSWD: /usr/bin/systemd-resolve --flush-caches
$ACCOUNT_NAME ALL=(root) NOPASSWD: /usr/bin/resolvectl flush-caches

EOF
    fi

    cat <<EOF
# Pre-requisites for daemon-style invocation:
Defaults:$ACCOUNT_NAME    !requiretty
Defaults:$ACCOUNT_NAME    env_keep += "YUZU_*"
EOF
}

install_sudoers() {
    if [[ "$SKIP_SUDOERS" -eq 1 ]]; then
        log "skipping sudoers install (--no-sudoers)"
        return 0
    fi

    local target="/etc/sudoers.d/yuzu-agent"
    local tmp=""
    tmp=$(mktemp -t yuzu-sudoers.XXXXXX)
    # Cleanup on any exit path: the temp file should never linger. A RETURN
    # trap set inside a function is NOT scoped to that function's own
    # return — it stays armed for the rest of the script and fires on
    # every LATER function return too, in whatever caller happens to be
    # unwinding. Left as `rm -f "$tmp"`, that later fire expands $tmp from
    # a caller's own scope (unset, since `local tmp` only exists inside
    # this function) and aborts the whole installer under `set -u`
    # (partial host mutation already applied by then). Two changes make
    # this safe: `${tmp:-}` tolerates the unset case, and `trap - RETURN`
    # disarms the trap the first time it fires so it never fires again.
    trap 'rm -f "${tmp:-}"; trap - RETURN' RETURN

    log "generating sudoers file at $tmp"
    if [[ "$DRY_RUN" -eq 1 ]]; then
        echo "[dry-run] would write the following to $target:"
        generate_sudoers_content | sed 's/^/[dry-run]   /'
    else
        generate_sudoers_content > "$tmp"
    fi

    log "validating with visudo -cf"
    if [[ "$DRY_RUN" -eq 0 ]]; then
        if ! visudo -cf "$tmp" >/dev/null; then
            warn "sudoers file failed visudo validation — NOT installing"
            visudo -cf "$tmp" >&2 || true
            return 3
        fi
    fi

    # macOS uses `wheel` (GID 0) as root's primary group; there is no
    # group named `root` on Darwin. Linux uses `root:root`. The sudoers
    # file must end up owner=root:wheel on macOS, owner=root:root on
    # Linux — without the right ownership sudo refuses to load it.
    local root_group
    if [[ "$PLATFORM" == "macos" ]]; then
        root_group="wheel"
    else
        root_group="root"
    fi

    log "installing $tmp -> $target (mode 0440, root:$root_group)"
    run install -m 0440 -o root -g "$root_group" "$tmp" "$target"
}

remove_sudoers() {
    local target="/etc/sudoers.d/yuzu-agent"
    if [[ -f "$target" ]]; then
        log "removing $target"
        run rm -f "$target"
    fi
}

# ── linux capabilities ──────────────────────────────────────────────────────
# Capabilities granted to the agent binary directly. These avoid a
# sudo round-trip for syscalls the agent makes itself (raw sockets,
# routing-table writes, ptrace). They do NOT transfer through execve,
# so plugins that shell out to /usr/sbin/iptables still need the
# sudoers entry above — capabilities cover only the agent's own
# syscalls, not its child processes.
#
# +eip means the capability is in the binary's effective, inheritable,
# AND permitted sets. eip is the right combination for a daemon
# binary; +ep alone wouldn't survive setuid (we don't setuid) and +ei
# alone wouldn't be effective without explicit cap_set_proc().

apply_setcap() {
    if [[ "$PLATFORM" != "linux" ]]; then return 0; fi
    if [[ "$SKIP_SETCAP" -eq 1 ]]; then
        log "skipping setcap (--no-setcap)"
        return 0
    fi
    if ! command -v setcap >/dev/null 2>&1; then
        warn "setcap not installed — skipping (apt: libcap2-bin, dnf: libcap)"
        return 0
    fi
    if [[ ! -f "$BINARY_PATH" ]]; then
        warn "agent binary not found at $BINARY_PATH — skipping setcap"
        warn "  re-run with --binary-path PATH after the agent is installed,"
        warn "  or set capabilities from your packaging tool (postinst hook)."
        return 0
    fi

    log "applying capabilities to $BINARY_PATH"
    log "  cap_net_admin, cap_net_raw, cap_dac_read_search, cap_sys_ptrace +eip"
    run setcap "cap_net_admin,cap_net_raw,cap_dac_read_search,cap_sys_ptrace+eip" "$BINARY_PATH"
}

# ── macOS pf-anchor provisioning ─────────────────────────────────────────────
#
# ACTIVATION prerequisite, pinned ahead of a FUTURE pf-anchor rework of the
# quarantine plugin (tracked as A-1.18; not yet landed as of this writing —
# agents/plugins/quarantine/src/quarantine_plugin.cpp:518's macos_load_ruleset
# still does `pfctl -f <tempfile>`, replacing the whole main ruleset, not
# `-a $PF_ANCHOR_NAME`). Once A-1.18 switches to loading rules into
# `pfctl -a yuzu-quarantine -f <tempfile>`, that load has NO EFFECT on live
# traffic unless the active MAIN ruleset also invokes that anchor via
# `anchor "yuzu-quarantine"` + `load anchor ... from ...` in /etc/pf.conf —
# without this one-time hook, the plugin's pfctl calls would return 0 and
# look like a successful quarantine, but nothing would actually be blocked.
# This whole section is idempotent — detect-before-repair on the two-line
# pf.conf hook, leave-alone-if-present on the anchor file — and re-running
# the installer only reloads pf when it actually changed the on-disk hook
# or anchor file, so a routine re-run never clobbers a live anchor A-1.18
# may have loaded via `pfctl -a` since the last reload.
#
# Every write here is validated (pfctl -nf) against a staged copy before
# it touches the live file, same discipline as install_sudoers above: a
# syntactically broken /etc/pf.conf fails pf closed.
#
# Reload discipline: macos_install_pf_anchor_file and macos_hook_pf_conf
# each return 0 when nothing needed to change (already present/hooked) and
# 2 when this invocation actually wrote something. macos_provision_pf_anchor
# only reloads pf (macos_enable_pf, which does `pfctl -f`) when one of them
# returned 2 — an unconditional reload on every re-run would re-source the
# on-disk anchor FILE over whatever quarantine_plugin.cpp last loaded live
# via `pfctl -a yuzu-quarantine -f <tempfile>`, silently releasing an
# active quarantine on a routine, documented-idempotent re-install.

generate_pf_anchor_content() {
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

macos_install_pf_anchor_file() {
    if [[ -f "$PF_ANCHOR_FILE" ]]; then
        log "pf anchor file already present: $PF_ANCHOR_FILE — leaving contents alone"
        return 0
    fi

    local tmp=""
    tmp=$(mktemp -t yuzu-pf-anchor.XXXXXX)
    # Self-clearing, nounset-safe RETURN trap — see the matching comment
    # in install_sudoers() for why both `${tmp:-}` and `trap - RETURN`
    # are required, not just one or the other.
    trap 'rm -f "${tmp:-}"; trap - RETURN' RETURN

    log "generating pf anchor file at $tmp"
    if [[ "$DRY_RUN" -eq 1 ]]; then
        echo "[dry-run] would write the following to $PF_ANCHOR_FILE:"
        generate_pf_anchor_content | sed 's/^/[dry-run]   /'
    else
        generate_pf_anchor_content > "$tmp"
    fi

    log "installing $tmp -> $PF_ANCHOR_FILE (mode 0644, root:wheel)"
    run install -m 0644 -o root -g wheel "$tmp" "$PF_ANCHOR_FILE"
    # Signal "changed" (see the reload-discipline note above
    # macos_install_pf_anchor_file's block comment) whether this was a
    # real write or a dry-run preview, so a dry run's summary reflects
    # what a real run would do.
    return 2
}

# Both lines of the two-line hook contract are required, exact-line-matched
# (grep -qxF): a bare `anchor "yuzu-quarantine"` with no `load anchor ...`
# — or one pointing at a different file — leaves the pinned anchor FILE
# never wired into a main-ruleset reload, so quarantine loads would still
# be a false quarantine even though a naive substring check on `anchor
# "..."` alone would call the host already provisioned.
pf_conf_has_full_hook() {
    local anchor_line="anchor \"$PF_ANCHOR_NAME\""
    local load_line="load anchor \"$PF_ANCHOR_NAME\" from \"$PF_ANCHOR_FILE\""
    grep -qxF "$anchor_line" "$PF_CONF" 2>/dev/null && \
        grep -qxF "$load_line" "$PF_CONF" 2>/dev/null
}

macos_hook_pf_conf() {
    if [[ ! -f "$PF_CONF" ]]; then
        warn "$PF_CONF does not exist — cannot hook the quarantine anchor into it" \
             "(unexpected on macOS; pf.conf ships with the OS)"
        return 1
    fi

    if pf_conf_has_full_hook; then
        log "$PF_CONF already hooks anchor \"$PF_ANCHOR_NAME\" — skipping (idempotent)"
        return 0
    fi

    local tmp=""
    tmp=$(mktemp -t yuzu-pf-conf.XXXXXX)
    # Self-clearing, nounset-safe RETURN trap — see the matching comment
    # in install_sudoers() for why both `${tmp:-}` and `trap - RETURN`
    # are required, not just one or the other.
    trap 'rm -f "${tmp:-}"; trap - RETURN' RETURN

    log "staging hooked $PF_CONF at $tmp"
    cp "$PF_CONF" "$tmp"
    {
        printf '\n# --- Yuzu agent quarantine anchor (scripts/install-agent-user.sh) ---\n'
        printf 'anchor "%s"\n' "$PF_ANCHOR_NAME"
        printf 'load anchor "%s" from "%s"\n' "$PF_ANCHOR_NAME" "$PF_ANCHOR_FILE"
    } >> "$tmp"

    if [[ "$DRY_RUN" -eq 1 ]]; then
        echo "[dry-run] would append to $PF_CONF:"
        tail -n 3 "$tmp" | sed 's/^/[dry-run]   /'
        return 2
    fi

    log "validating hooked $PF_CONF with pfctl -nf"
    if ! pfctl -nf "$tmp" >/dev/null 2>&1; then
        warn "hooked $PF_CONF failed pfctl -nf syntax validation — NOT installing; leaving the original untouched"
        pfctl -nf "$tmp" >&2 || true
        return 1
    fi

    log "installing $tmp -> $PF_CONF (mode 0644, root:wheel)"
    run install -m 0644 -o root -g wheel "$tmp" "$PF_CONF"
    return 2
}

macos_enable_pf() {
    log "loading $PF_CONF and enabling pf"
    if [[ "$DRY_RUN" -eq 1 ]]; then
        printf '[dry-run] pfctl -f %s\n' "$PF_CONF"
        printf '[dry-run] pfctl -e\n'
        return 0
    fi
    if ! pfctl -f "$PF_CONF"; then
        fail "pfctl -f $PF_CONF failed — refusing to continue with the quarantine anchor hook unloaded"
    fi
    # -e (enable) exits non-zero with a harmless "pf already enabled"
    # warning on stderr when pf is already running — same idempotency
    # pattern quarantine_plugin.cpp already relies on in macos_load_ruleset.
    pfctl -e 2>/dev/null || true
}

macos_provision_pf_anchor() {
    local anchor_rc hook_rc

    macos_install_pf_anchor_file
    anchor_rc=$?
    [[ "$anchor_rc" -eq 1 ]] && fail "failed to install pf anchor file $PF_ANCHOR_FILE"

    macos_hook_pf_conf
    hook_rc=$?
    [[ "$hook_rc" -eq 1 ]] && fail "failed to hook anchor \"$PF_ANCHOR_NAME\" into $PF_CONF" \
        "— without this hook, quarantine anchor loads have no effect on live traffic (false quarantine)"

    # Only reload/enable pf when this invocation actually changed the
    # anchor file or the pf.conf hook (rc 2 from either helper above).
    # An unconditional reload here would re-source the on-disk anchor
    # file's initial (empty) contents over whatever quarantine_plugin.cpp
    # last loaded live via `pfctl -a yuzu-quarantine -f <tempfile>`,
    # silently clearing an active quarantine on a routine re-install.
    if [[ "$anchor_rc" -eq 2 || "$hook_rc" -eq 2 ]]; then
        macos_enable_pf
    else
        log "pf anchor file and $PF_CONF hook already provisioned — leaving the running pf ruleset untouched"
    fi
}

# ── macOS pf-anchor teardown (uninstall) ─────────────────────────────────────
#
# Mirror image of macos_provision_pf_anchor above, run in reverse at
# uninstall time. This matters because the quarantine anchor is made
# DURABLE by design: quarantine_plugin.cpp mirrors whatever `block all`
# ruleset it loads live into the anchor out to $PF_ANCHOR_FILE too, so a
# reboot or `pfctl -f /etc/pf.conf` replays the same quarantine instead of
# silently releasing it (see quarantine_plugin.cpp's BR-002 comments). If
# uninstall doesn't undo that, uninstalling the agent on a host that
# happens to be quarantined at that moment leaves it blocked FOREVER —
# every future reboot / pf reload re-imposes a `block all` with no agent
# left to release it.
#
# Every step here tolerates "already clean" (pf disabled, anchor absent,
# hook absent) so uninstalling a host that was never provisioned, or
# re-running uninstall, is always a safe no-op — same idempotency
# discipline as the install-side helpers.

# 1. Flush whatever quarantine rules are loaded LIVE in the anchor. Safe
#    even if the anchor was never hooked into the main ruleset, was never
#    populated, or pf itself is absent/disabled — pfctl just no-ops.
macos_flush_pf_anchor_rules() {
    if ! command -v pfctl >/dev/null 2>&1; then
        log "pfctl not found — skipping live pf anchor flush (nothing to undo)"
        return 0
    fi

    log "flushing live rules from pf anchor \"$PF_ANCHOR_NAME\" (if loaded)"
    if [[ "$DRY_RUN" -eq 1 ]]; then
        printf '[dry-run] pfctl -a %s -F rules\n' "$PF_ANCHOR_NAME"
        return 0
    fi
    # Tolerate errors: an anchor that was never loaded, or pf being
    # disabled entirely, both make this a harmless no-op rather than a
    # failure worth aborting uninstall over.
    pfctl -a "$PF_ANCHOR_NAME" -F rules >/dev/null 2>&1 || true
}

# 2. Reset the persistent anchor file back to the same empty/released body
#    the installer writes for a brand-new install (generate_pf_anchor_
#    content) — byte-for-byte, so a reboot or `pfctl -f /etc/pf.conf`
#    after uninstall reconstructs an EMPTY anchor, never a stale
#    `block all`.
macos_reset_pf_anchor_file() {
    if [[ ! -f "$PF_ANCHOR_FILE" ]]; then
        log "pf anchor file $PF_ANCHOR_FILE already absent — nothing to reset"
        return 0
    fi

    local tmp=""
    tmp=$(mktemp -t yuzu-pf-anchor-reset.XXXXXX)
    trap 'rm -f "${tmp:-}"; trap - RETURN' RETURN

    generate_pf_anchor_content > "$tmp"

    if [[ "$DRY_RUN" -eq 1 ]]; then
        echo "[dry-run] would reset $PF_ANCHOR_FILE to its empty/released form:"
        sed 's/^/[dry-run]   /' "$tmp"
        return 0
    fi

    log "resetting $PF_ANCHOR_FILE to its empty/released form"
    run install -m 0644 -o root -g wheel "$tmp" "$PF_ANCHOR_FILE"
}

# 3. Remove ONLY the exact hook block macos_hook_pf_conf appends (banner
#    comment + the two pinned `anchor` / `load anchor` lines) — never
#    touch any other line in pf.conf, including rules an operator or
#    other tooling added. Idempotent: a no-op if the hook isn't present.
macos_unhook_pf_conf() {
    if [[ ! -f "$PF_CONF" ]]; then
        log "$PF_CONF does not exist — nothing to unhook"
        return 0
    fi

    if ! pf_conf_has_full_hook; then
        log "$PF_CONF does not hook anchor \"$PF_ANCHOR_NAME\" — nothing to unhook"
        return 0
    fi

    local banner_line="# --- Yuzu agent quarantine anchor (scripts/install-agent-user.sh) ---"
    local anchor_line="anchor \"$PF_ANCHOR_NAME\""
    local load_line="load anchor \"$PF_ANCHOR_NAME\" from \"$PF_ANCHOR_FILE\""

    local tmp=""
    tmp=$(mktemp -t yuzu-pf-conf-unhook.XXXXXX)
    trap 'rm -f "${tmp:-}"; trap - RETURN' RETURN

    log "staging unhooked $PF_CONF at $tmp"
    # Drop only the three exact lines the installer added; everything
    # else — including surrounding blank lines and any pre-existing
    # operator-authored rules/anchors — is copied through untouched.
    grep -vxF -e "$banner_line" -e "$anchor_line" -e "$load_line" "$PF_CONF" > "$tmp" || true

    if [[ "$DRY_RUN" -eq 1 ]]; then
        echo "[dry-run] would remove the Yuzu quarantine anchor hook from $PF_CONF"
        return 0
    fi

    log "validating unhooked $PF_CONF with pfctl -nf"
    if ! pfctl -nf "$tmp" >/dev/null 2>&1; then
        warn "unhooked $PF_CONF failed pfctl -nf syntax validation — NOT installing; leaving the hook in place" \
             "(the live anchor was already flushed above, so this host is not blocked — finish removing the hook from $PF_CONF by hand)"
        pfctl -nf "$tmp" >&2 || true
        return 1
    fi

    log "installing $tmp -> $PF_CONF (mode 0644, root:wheel) — removed the Yuzu quarantine anchor hook"
    run install -m 0644 -o root -g wheel "$tmp" "$PF_CONF"
}

macos_teardown_pf_anchor() {
    log "tearing down macOS pf quarantine anchor (account: $ACCOUNT_NAME)"

    macos_flush_pf_anchor_rules
    macos_reset_pf_anchor_file

    if macos_unhook_pf_conf; then
        if [[ "$DRY_RUN" -eq 0 ]] && command -v pfctl >/dev/null 2>&1 && [[ -f "$PF_CONF" ]]; then
            log "reloading $PF_CONF after removing the quarantine anchor hook"
            if ! pfctl -f "$PF_CONF" >/dev/null 2>&1; then
                warn "pfctl -f $PF_CONF failed while tearing down the quarantine anchor" \
                     "— verify manually with 'pfctl -s rules' that no stale hook/anchor remains loaded"
            fi
        fi
    else
        warn "failed to remove the quarantine anchor hook from $PF_CONF during uninstall" \
             "— the live anchor rules were already flushed, so this host is not blocked right now," \
             "but a future reboot / pfctl -f $PF_CONF reload will reconstruct an EMPTY anchor" \
             "(step 2 already reset $PF_ANCHOR_FILE) via a hook that still points at it — finish" \
             "removing the hook from $PF_CONF by hand to fully undo the install."
    fi
}

# ── verification ────────────────────────────────────────────────────────────
# --check exits non-zero on ANY drift so the caller can rely on it as a
# pre-flight gate (e.g., scripts/start-UAT.sh checks before launching
# the agent).

check_install() {
    local errs=0

    # 1. user exists
    if [[ "$PLATFORM" == "macos" ]]; then
        macos_user_exists || { warn "user $ACCOUNT_NAME does not exist (macOS)"; ((errs++)); }
    else
        linux_user_exists || { warn "user $ACCOUNT_NAME does not exist (Linux)"; ((errs++)); }
    fi

    # 2. state dirs exist with correct ownership
    for dir in "$STATE_DIR" "$CACHE_DIR" "$LOG_DIR"; do
        if [[ ! -d "$dir" ]]; then
            warn "missing dir: $dir"; ((errs++)); continue
        fi
        local owner
        owner=$(stat -f '%Su' "$dir" 2>/dev/null || stat -c '%U' "$dir")
        if [[ "$owner" != "$ACCOUNT_NAME" ]]; then
            warn "wrong owner on $dir: got $owner, expected $ACCOUNT_NAME"
            ((errs++))
        fi
    done

    # 3. sudoers file is present and valid
    #
    # The file is installed mode 0440 root:<wheel|root>, so a non-root
    # user can't read it (correct — sudoers files MUST refuse access
    # below their group, sudo refuses to load them otherwise). When we
    # invoke visudo -cf without read access, it returns non-zero with
    # EACCES — that's NOT a validation failure, it's a permissions
    # condition this user can't resolve here. Detect explicitly and
    # report a SKIP-with-instructions instead of a misleading FAIL.
    if [[ "$SKIP_SUDOERS" -eq 0 ]]; then
        if [[ ! -f /etc/sudoers.d/yuzu-agent ]]; then
            warn "/etc/sudoers.d/yuzu-agent is missing"; ((errs++))
        elif [[ ! -r /etc/sudoers.d/yuzu-agent ]]; then
            log "/etc/sudoers.d/yuzu-agent present but not readable by $(id -un)"
            log "  (mode 0440 root:wheel/root is correct; rerun --check as root to validate)"
        else
            if ! visudo -cf /etc/sudoers.d/yuzu-agent >/dev/null 2>&1; then
                warn "/etc/sudoers.d/yuzu-agent fails visudo validation"; ((errs++))
            else
                log "/etc/sudoers.d/yuzu-agent present and visudo-valid"
            fi
        fi
    fi

    # 4. capabilities (Linux only)
    if [[ "$PLATFORM" == "linux" && "$SKIP_SETCAP" -eq 0 && -f "$BINARY_PATH" ]]; then
        if command -v getcap >/dev/null 2>&1; then
            local caps
            caps=$(getcap "$BINARY_PATH" 2>/dev/null || true)
            if [[ -z "$caps" ]]; then
                warn "no capabilities set on $BINARY_PATH"; ((errs++))
            else
                log "capabilities on $BINARY_PATH: $caps"
            fi
        fi
    fi

    # 5. pf-anchor ACTIVATION hook (macOS only) — see docs/agent-privilege-
    # model.md, "macOS pf-anchor provisioning". Loading quarantine rules
    # into `pfctl -a yuzu-quarantine -f <file>` has no effect on live
    # traffic unless this anchor is hooked into pf's active MAIN ruleset;
    # catching a missing/unloaded hook here is the whole point of this
    # check — a passing --check is what tells the operator quarantine
    # will actually work, not just that pfctl calls will return 0.
    if [[ "$PLATFORM" == "macos" ]]; then
        if [[ ! -f "$PF_ANCHOR_FILE" ]]; then
            warn "pf anchor file missing: $PF_ANCHOR_FILE"; ((errs++))
        else
            log "pf anchor file present: $PF_ANCHOR_FILE"
        fi

        if [[ ! -f "$PF_CONF" ]] || ! pf_conf_has_full_hook; then
            warn "$PF_CONF does not hook anchor \"$PF_ANCHOR_NAME\" — quarantine loads would be a FALSE QUARANTINE (no effect on live traffic)" \
                 "(both \`anchor \"$PF_ANCHOR_NAME\"\` and \`load anchor \"$PF_ANCHOR_NAME\" from \"$PF_ANCHOR_FILE\"\` are required)"
            ((errs++))
        else
            log "$PF_CONF hooks anchor \"$PF_ANCHOR_NAME\""

            # Confirm the hook is actually LOADED into pf's running
            # ruleset, not just written to the on-disk pf.conf — pf must
            # be reloaded after editing pf.conf for the hook to take
            # effect. `pfctl -s rules` requires root to query live kernel
            # state; degrade to a SKIP-with-instructions rather than a
            # false FAIL when run unprivileged, same pattern as the
            # sudoers-file readability check above.
            if [[ "$EUID" -ne 0 ]]; then
                log "  (skipping active-ruleset verification — pfctl -s rules requires root;" \
                    "rerun --check as root/sudo to confirm the anchor is actually loaded, not just written to $PF_CONF)"
            elif ! pfctl -s rules 2>/dev/null | grep -qF "anchor \"$PF_ANCHOR_NAME\""; then
                warn "anchor \"$PF_ANCHOR_NAME\" is not present in pf's ACTIVE ruleset (pfctl -s rules)" \
                     "— pf.conf may need reloading (pfctl -f $PF_CONF), or pf is disabled (pfctl -e)"
                ((errs++))
            elif ! pfctl -s info 2>/dev/null | grep -qE '^Status:[[:space:]]+Enabled'; then
                # The anchor can be present in the loaded ruleset while pf
                # itself is administratively disabled (`pfctl -d`) — rules
                # are parsed but not enforced, so this is still a false
                # quarantine even though the previous check passed.
                warn "anchor \"$PF_ANCHOR_NAME\" is loaded but pf is DISABLED (pfctl -s info) — quarantine rules will not affect live traffic until pf is enabled (pfctl -e)"
                ((errs++))
            else
                log "anchor \"$PF_ANCHOR_NAME\" confirmed active in pf's running, enabled ruleset"
            fi
        fi
    fi

    if [[ "$errs" -eq 0 ]]; then
        log "check passed — install looks correct"
        return 0
    else
        warn "check failed — $errs issue(s) found"
        return 1
    fi
}

# ── action dispatch ─────────────────────────────────────────────────────────

case "$ACTION" in
    install)
        require_root
        log "installing Yuzu agent user on $PLATFORM (account: $ACCOUNT_NAME)"
        # macos_create_user / linux_create_user are themselves idempotent —
        # they probe existing state, create what's missing, repair what's
        # broken. Don't short-circuit here (we used to, which meant a
        # half-installed account couldn't be self-healed by re-running).
        if [[ "$PLATFORM" == "macos" ]]; then
            macos_create_user
        else
            if linux_user_exists; then
                log "user $ACCOUNT_NAME already exists — skipping create"
            else
                linux_create_user
            fi
        fi
        create_state_dirs
        install_sudoers
        apply_setcap
        if [[ "$PLATFORM" == "macos" ]]; then
            macos_provision_pf_anchor
        fi
        log "install complete. Verify with: $0 --check"
        ;;

    check)
        check_install
        ;;

    uninstall)
        require_root
        log "uninstalling Yuzu agent user on $PLATFORM (account: $ACCOUNT_NAME)"
        # pf teardown MUST run before anything else below: a host that is
        # currently quarantined must be released before we remove the
        # agent/user that would otherwise be relied on to release it —
        # see macos_teardown_pf_anchor's block comment.
        if [[ "$PLATFORM" == "macos" ]]; then
            macos_teardown_pf_anchor
        fi
        remove_sudoers
        remove_state_dirs
        if [[ "$PLATFORM" == "macos" ]]; then
            macos_delete_user
        else
            linux_delete_user
        fi
        log "uninstall complete."
        ;;
esac

exit 0
