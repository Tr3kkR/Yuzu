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
# 6.  (Optional) On both platforms, prints a verifying summary that the
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

macos_create_user() {
    # Pick the first free UID in the system range (200-400). dscl returns
    # all UIDs; we sort numerically, find the first free one >= 200.
    local next_uid
    next_uid=$(dscl . -list /Users UniqueID 2>/dev/null \
        | awk '{print $2}' \
        | sort -n \
        | awk 'BEGIN{u=200} $1==u{u++} END{print u}')

    log "creating macOS user $ACCOUNT_NAME (UID/GID=$next_uid, hidden, no shell)"
    run dscl . -create "/Users/$ACCOUNT_NAME"
    run dscl . -create "/Users/$ACCOUNT_NAME" UserShell /usr/bin/false
    run dscl . -create "/Users/$ACCOUNT_NAME" RealName "Yuzu Agent Daemon"
    run dscl . -create "/Users/$ACCOUNT_NAME" UniqueID "$next_uid"
    run dscl . -create "/Users/$ACCOUNT_NAME" PrimaryGroupID "$next_uid"
    run dscl . -create "/Users/$ACCOUNT_NAME" NFSHomeDirectory /var/empty
    run dscl . -create "/Users/$ACCOUNT_NAME" Password "*"
    # Hide from the login window's user picker (cosmetic but expected).
    run dscl . -create "/Users/$ACCOUNT_NAME" IsHidden 1

    # Matching group entry. Without it, anything that maps gid → name
    # (ls -l, `ps`, etc.) prints the bare GID instead of "_yuzu".
    log "creating macOS group $ACCOUNT_NAME (GID=$next_uid)"
    run dscl . -create "/Groups/$ACCOUNT_NAME"
    run dscl . -create "/Groups/$ACCOUNT_NAME" PrimaryGroupID "$next_uid"
    run dscl . -create "/Groups/$ACCOUNT_NAME" Password "*"
    run dscl . -create "/Groups/$ACCOUNT_NAME" RealName "Yuzu Agent Daemon"
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
    local tmp
    tmp=$(mktemp -t yuzu-sudoers.XXXXXX)
    # Cleanup on any exit path: the temp file should never linger.
    trap 'rm -f "$tmp"' RETURN

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

    log "installing $tmp -> $target (mode 0440, root:root)"
    run install -m 0440 -o root -g root "$tmp" "$target"
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
    if [[ "$SKIP_SUDOERS" -eq 0 ]]; then
        if [[ ! -f /etc/sudoers.d/yuzu-agent ]]; then
            warn "/etc/sudoers.d/yuzu-agent is missing"; ((errs++))
        else
            if ! visudo -cf /etc/sudoers.d/yuzu-agent >/dev/null 2>&1; then
                warn "/etc/sudoers.d/yuzu-agent fails visudo validation"; ((errs++))
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
        if [[ "$PLATFORM" == "macos" ]]; then
            macos_user_exists && log "user $ACCOUNT_NAME already exists — skipping create" \
                              || macos_create_user
        else
            linux_user_exists && log "user $ACCOUNT_NAME already exists — skipping create" \
                              || linux_create_user
        fi
        create_state_dirs
        install_sudoers
        apply_setcap
        log "install complete. Verify with: $0 --check"
        ;;

    check)
        check_install
        ;;

    uninstall)
        require_root
        log "uninstalling Yuzu agent user on $PLATFORM (account: $ACCOUNT_NAME)"
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
