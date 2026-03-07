#!/usr/bin/env bash
# Yuzu Plugin Roadmap — Create GitHub Issues
# Run from repo root: bash scripts/create_issues.sh
set -euo pipefail

echo "Creating labels..."
gh label create plugin --description "Agent plugin" --color 0075ca --force
gh label create enhancement --description "Enhancement" --color a2eeef --force

echo ""
echo "Creating issues..."

echo "[1/23] Agent Status"
gh issue create --title "Plugin: Agent Status" --label "enhancement,plugin" --body-file scripts/issues/01-agent-status.md

echo "[2/23] Agent Diagnostics"
gh issue create --title "Plugin: Agent Diagnostics" --label "enhancement,plugin" --body-file scripts/issues/02-agent-diagnostics.md

echo "[3/23] Agent Actions"
gh issue create --title "Plugin: Agent Actions" --label "enhancement,plugin" --body-file scripts/issues/03-agent-actions.md

echo "[4/23] Device Identity"
gh issue create --title "Plugin: Device Identity" --label "enhancement,plugin" --body-file scripts/issues/04-device-identity.md

echo "[5/23] Hardware Inventory"
gh issue create --title "Plugin: Hardware Inventory" --label "enhancement,plugin" --body-file scripts/issues/05-hardware.md

echo "[6/23] Operating System Info"
gh issue create --title "Plugin: Operating System Info" --label "enhancement,plugin" --body-file scripts/issues/06-operating-system.md

echo "[7/23] User Accounts"
gh issue create --title "Plugin: User Accounts" --label "enhancement,plugin" --body-file scripts/issues/07-users.md

echo "[8/23] Installed Applications"
gh issue create --title "Plugin: Installed Applications" --label "enhancement,plugin" --body-file scripts/issues/08-installed-apps.md

echo "[9/23] MSI Packages"
gh issue create --title "Plugin: MSI Packages" --label "enhancement,plugin" --body-file scripts/issues/09-msi-packages.md

echo "[10/23] Software Actions"
gh issue create --title "Plugin: Software Actions" --label "enhancement,plugin" --body-file scripts/issues/10-software-actions.md

echo "[11/23] Process Management"
gh issue create --title "Plugin: Process Management" --label "enhancement,plugin" --body-file scripts/issues/11-processes.md

echo "[12/23] Service Management"
gh issue create --title "Plugin: Service Management" --label "enhancement,plugin" --body-file scripts/issues/12-services.md

echo "[13/23] File System Operations"
gh issue create --title "Plugin: File System Operations" --label "enhancement,plugin" --body-file scripts/issues/13-filesystem.md

echo "[14/23] Network Configuration"
gh issue create --title "Plugin: Network Configuration" --label "enhancement,plugin" --body-file scripts/issues/14-network-config.md

echo "[15/23] Network Diagnostics"
gh issue create --title "Plugin: Network Diagnostics" --label "enhancement,plugin" --body-file scripts/issues/15-network-diag.md

echo "[16/23] Network Actions"
gh issue create --title "Plugin: Network Actions" --label "enhancement,plugin" --body-file scripts/issues/16-network-actions.md

echo "[17/23] Firewall Management"
gh issue create --title "Plugin: Firewall Management" --label "enhancement,plugin" --body-file scripts/issues/17-firewall.md

echo "[18/23] Antivirus Status"
gh issue create --title "Plugin: Antivirus Status" --label "enhancement,plugin" --body-file scripts/issues/18-antivirus.md

echo "[19/23] BitLocker Encryption"
gh issue create --title "Plugin: BitLocker Encryption" --label "enhancement,plugin" --body-file scripts/issues/19-bitlocker.md

echo "[20/23] Windows Updates"
gh issue create --title "Plugin: Windows Updates" --label "enhancement,plugin" --body-file scripts/issues/20-windows-updates.md

echo "[21/23] Event Logs"
gh issue create --title "Plugin: Event Logs" --label "enhancement,plugin" --body-file scripts/issues/21-event-logs.md

echo "[22/23] SCCM Client"
gh issue create --title "Plugin: SCCM Client" --label "enhancement,plugin" --body-file scripts/issues/22-sccm.md

echo "[23/23] Script Execution"
gh issue create --title "Plugin: Script Execution" --label "enhancement,plugin" --body-file scripts/issues/23-script-execution.md

echo ""
echo "Done! All 23 issues created."
