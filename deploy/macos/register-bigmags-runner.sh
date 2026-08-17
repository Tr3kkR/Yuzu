#!/bin/bash
# register-bigmags-runner.sh — register ONE BigMags CI agent as a launchd service.
#
#   ./register-bigmags-runner.sh <index>        # index 0 or 1
#   ./register-bigmags-runner.sh <index> --force # skip the drain gate
#
# Run as an ADMIN user that has `gh` authenticated with repo-admin rights (to
# mint the registration token). Runner file ops + config run as the dedicated
# non-admin `yuzuci`; the launchd service install needs root (via sudo).
#
# Peer of deploy/windows/Provision-Windows-Runner.ps1's registration path. macOS
# uses the actions/runner built-in launchd service (svc.sh) — analogous to Big
# Tam's systemd — because there is no CPU-pin wrapper to interpose (no CCD
# affinity on Apple Silicon).
#
# NOTE: validate end-to-end during the Phase 3 cutover — GitHub was mid-incident
# when this was authored, so the token-mint + config + svc paths are drafted
# against the documented actions/runner flow, not yet exercised on BigMags.
set -euo pipefail

REPO="Tr3kkR/Yuzu"
CI_USER="yuzuci"
CI_ROOT="/opt/ci"
POOL_LABELS="self-hosted,macOS,ARM64,yuzu-bigmags-macos"
# Latest actions/runner osx-arm64 release (override by exporting RUNNER_VERSION).
RUNNER_VERSION="${RUNNER_VERSION:-$(gh api repos/actions/runner/releases/latest --jq .tag_name | sed 's/^v//')}"

idx="${1:?usage: register-bigmags-runner.sh <index> [--force]}"
force="${2:-}"
name="yuzu-bigmags-macos-${idx}"
rdir="${CI_ROOT}/actions-runner/r${idx}"
work="${CI_ROOT}/work-${idx}"

[ -n "$RUNNER_VERSION" ] || { echo "Could not resolve RUNNER_VERSION (gh api failed?)." >&2; exit 1; }

# --- drain gate: never reconfigure a runner that may be executing CI ----------
# (mirrors the Windows provisioner's listener-liveness gate — gate on the
# LISTENER, not just the worker: an idle listener can still accept a job.)
if [ "$force" != "--force" ] && pgrep -f "actions-runner/r${idx}/.*Runner.Listener" >/dev/null 2>&1; then
  echo "Agent r${idx} has a live Runner.Listener — refusing (pass --force to override at an idle window)." >&2
  exit 2
fi

# --- registration token (as the admin user with gh auth) ----------------------
echo "Minting registration token for ${REPO}…"
token="$(gh api -X POST "repos/${REPO}/actions/runners/registration-token" --jq .token)"
[ -n "$token" ] || { echo "Failed to mint registration token (is gh authed as a repo admin?)" >&2; exit 1; }

# --- lay down the runner (owned by yuzuci) ------------------------------------
sudo install -d -o "$CI_USER" -g staff "$rdir" "$work"
tarball="actions-runner-osx-arm64-${RUNNER_VERSION}.tar.gz"
url="https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/${tarball}"
echo "Downloading ${tarball}…"
sudo -u "$CI_USER" bash -c "cd '$rdir' && curl -fSL --retry 10 --retry-all-errors -o '$tarball' '$url' && tar xzf '$tarball' && rm -f '$tarball'"

# --- per-agent env / path (read by the launchd service at job start) ----------
# RUNNER_TOOL_CACHE: shared binary-cache + telemetry root (both agents share it).
# YUZU_BUILD_JOBS: per-agent parallelism — THE knob to tune against 24 GiB memory
#   pressure; drop to 4 if the telemetry DB shows swap under 2 concurrent builds.
sudo -u "$CI_USER" tee "$rdir/.env" >/dev/null <<EOF
RUNNER_TOOL_CACHE=${CI_ROOT}/tool_cache
YUZU_BUILD_JOBS=6
EOF
# brew on PATH so the job's dependency-install step resolves brew/pipx/python3.
sudo -u "$CI_USER" tee "$rdir/.path" >/dev/null <<EOF
/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin
EOF

# --- configure + install the launchd service ----------------------------------
echo "Configuring ${name}…"
sudo -u "$CI_USER" bash -c "cd '$rdir' && ./config.sh --unattended --replace \
  --url 'https://github.com/${REPO}' \
  --name '${name}' \
  --labels '${POOL_LABELS}' \
  --work '${work}' \
  --token '${token}'"

# Headless LaunchDaemon — NOT the runner's svc.sh. On macOS svc.sh installs a
# per-USER LaunchAgent that only runs when that user has an active GUI session;
# the headless yuzuci service account never does. A system LaunchDaemon runs
# run.sh as yuzuci at boot with no login. (Phase B codesigning will need keychain
# access, which is fiddlier from a daemon — solve then.)
echo "Installing LaunchDaemon com.yuzu.ci-runner.r${idx}…"
sudo -u "$CI_USER" mkdir -p "$rdir/_diag"
plist="/Library/LaunchDaemons/com.yuzu.ci-runner.r${idx}.plist"
sudo tee "$plist" >/dev/null <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.yuzu.ci-runner.r${idx}</string>
  <key>UserName</key><string>${CI_USER}</string>
  <key>WorkingDirectory</key><string>${rdir}</string>
  <key>ProgramArguments</key>
  <array><string>${rdir}/run.sh</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>EnvironmentVariables</key>
  <dict><key>PATH</key><string>/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin</string></dict>
  <key>StandardOutPath</key><string>${rdir}/_diag/daemon.out.log</string>
  <key>StandardErrorPath</key><string>${rdir}/_diag/daemon.err.log</string>
</dict>
</plist>
PLIST
sudo chown root:wheel "$plist"; sudo chmod 644 "$plist"
sudo launchctl bootout "system/com.yuzu.ci-runner.r${idx}" 2>/dev/null || true
sudo launchctl bootstrap system "$plist"
sleep 3
sudo launchctl print "system/com.yuzu.ci-runner.r${idx}" | grep -iE 'state =|pid =' || true

echo "Registered ${name}. Confirm it reports 'online' with labels ${POOL_LABELS}"
echo "before merging the inventory rows (avoids sentinel UNKNOWN/OFFLINE drift)."
