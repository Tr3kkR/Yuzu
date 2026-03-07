# Yuzu Plugin Roadmap — Create GitHub Issues (PowerShell)
# Can be run from any directory.

$issuesDir = Join-Path $PSScriptRoot "issues"

Write-Host "Creating labels..."
gh label create plugin --description "Agent plugin" --color 0075ca --force
gh label create enhancement --description "Enhancement" --color a2eeef --force

Write-Host ""
Write-Host "Creating issues..."

Write-Host "[1/23] Agent Status"
gh issue create --title "Plugin: Agent Status" --label "enhancement,plugin" --body-file "$issuesDir\01-agent-status.md"

Write-Host "[2/23] Agent Diagnostics"
gh issue create --title "Plugin: Agent Diagnostics" --label "enhancement,plugin" --body-file "$issuesDir\02-agent-diagnostics.md"

Write-Host "[3/23] Agent Actions"
gh issue create --title "Plugin: Agent Actions" --label "enhancement,plugin" --body-file "$issuesDir\03-agent-actions.md"

Write-Host "[4/23] Device Identity"
gh issue create --title "Plugin: Device Identity" --label "enhancement,plugin" --body-file "$issuesDir\04-device-identity.md"

Write-Host "[5/23] Hardware Inventory"
gh issue create --title "Plugin: Hardware Inventory" --label "enhancement,plugin" --body-file "$issuesDir\05-hardware.md"

Write-Host "[6/23] Operating System Info"
gh issue create --title "Plugin: Operating System Info" --label "enhancement,plugin" --body-file "$issuesDir\06-operating-system.md"

Write-Host "[7/23] User Accounts"
gh issue create --title "Plugin: User Accounts" --label "enhancement,plugin" --body-file "$issuesDir\07-users.md"

Write-Host "[8/23] Installed Applications"
gh issue create --title "Plugin: Installed Applications" --label "enhancement,plugin" --body-file "$issuesDir\08-installed-apps.md"

Write-Host "[9/23] MSI Packages"
gh issue create --title "Plugin: MSI Packages" --label "enhancement,plugin" --body-file "$issuesDir\09-msi-packages.md"

Write-Host "[10/23] Software Actions"
gh issue create --title "Plugin: Software Actions" --label "enhancement,plugin" --body-file "$issuesDir\10-software-actions.md"

Write-Host "[11/23] Process Management"
gh issue create --title "Plugin: Process Management" --label "enhancement,plugin" --body-file "$issuesDir\11-processes.md"

Write-Host "[12/23] Service Management"
gh issue create --title "Plugin: Service Management" --label "enhancement,plugin" --body-file "$issuesDir\12-services.md"

Write-Host "[13/23] File System Operations"
gh issue create --title "Plugin: File System Operations" --label "enhancement,plugin" --body-file "$issuesDir\13-filesystem.md"

Write-Host "[14/23] Network Configuration"
gh issue create --title "Plugin: Network Configuration" --label "enhancement,plugin" --body-file "$issuesDir\14-network-config.md"

Write-Host "[15/23] Network Diagnostics"
gh issue create --title "Plugin: Network Diagnostics" --label "enhancement,plugin" --body-file "$issuesDir\15-network-diag.md"

Write-Host "[16/23] Network Actions"
gh issue create --title "Plugin: Network Actions" --label "enhancement,plugin" --body-file "$issuesDir\16-network-actions.md"

Write-Host "[17/23] Firewall Management"
gh issue create --title "Plugin: Firewall Management" --label "enhancement,plugin" --body-file "$issuesDir\17-firewall.md"

Write-Host "[18/23] Antivirus Status"
gh issue create --title "Plugin: Antivirus Status" --label "enhancement,plugin" --body-file "$issuesDir\18-antivirus.md"

Write-Host "[19/23] BitLocker Encryption"
gh issue create --title "Plugin: BitLocker Encryption" --label "enhancement,plugin" --body-file "$issuesDir\19-bitlocker.md"

Write-Host "[20/23] Windows Updates"
gh issue create --title "Plugin: Windows Updates" --label "enhancement,plugin" --body-file "$issuesDir\20-windows-updates.md"

Write-Host "[21/23] Event Logs"
gh issue create --title "Plugin: Event Logs" --label "enhancement,plugin" --body-file "$issuesDir\21-event-logs.md"

Write-Host "[22/23] SCCM Client"
gh issue create --title "Plugin: SCCM Client" --label "enhancement,plugin" --body-file "$issuesDir\22-sccm.md"

Write-Host "[23/23] Script Execution"
gh issue create --title "Plugin: Script Execution" --label "enhancement,plugin" --body-file "$issuesDir\23-script-execution.md"

Write-Host ""
Write-Host "Done! All 23 issues created."
