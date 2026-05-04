<#
.SYNOPSIS
    Read-only diagnostic for Windows autologon / sign-in configuration.

.DESCRIPTION
    Collects the registry, account, and credential-provider state needed
    to figure out why Sysinternals Autologon (or netplwiz) is rejecting
    valid credentials. Does NOT change any settings -- every command is
    a Get-* / read. Safe to run in any session.

    Captures output both to the console and to a transcript file in
    %TEMP%\yuzu-autologon-diagnose-<timestamp>.log so you can paste it
    back without having to rerun and copy by hand.

    The seven sections map 1:1 to the diagnostic table from the
    Yuzu /release skill conversation that produced this script:

      1. Current autologon state (Winlogon registry)
      2. Passwordless-mode flag (DevicePasswordLessBuildVersion)
      3. Local account properties (Get-LocalUser)
      4. WMI account properties (Win32_UserAccount cross-check)
      5. Hello / NGC / Passport policy state
      6. Azure AD / work-account hybrid state (dsregcmd /status)
      7. Credential providers presented at the lock screen

.PARAMETER User
    Local user name to inspect. Defaults to the current user.

.NOTES
    Elevation is not required for read-only inspection, but some fields
    may show up only if the running user has read access to those keys
    (which is the default for Authenticated Users).

    ASCII-only by design -- runs on both Windows PowerShell 5.1 (which
    misreads UTF-8 without BOM as Windows-1252 and mangles em-dashes)
    and pwsh 7+. No Unicode box-drawing or special characters.

    Output also goes to %TEMP%\yuzu-autologon-diagnose-<timestamp>.log.
    Share that file (or its contents) when reporting results.
#>

[CmdletBinding()]
param(
    [string]$User = $env:USERNAME
)

# Don't trip on individual cmdlet failures -- keep going so the operator
# gets the full picture in one pass.
$ErrorActionPreference = 'Continue'

$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$logPath = Join-Path $env:TEMP "yuzu-autologon-diagnose-$timestamp.log"

# Mirror everything to a transcript file. Stop-Transcript at end so the
# file flushes even if the script body blows up.
try { Stop-Transcript | Out-Null } catch {}
Start-Transcript -Path $logPath -Force | Out-Null

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
}

Write-Host "Yuzu autologon diagnostic -- read-only" -ForegroundColor Green
Write-Host "  Host:        $env:COMPUTERNAME"
Write-Host "  User:        $User"
Write-Host "  whoami:      $(whoami)"
Write-Host "  PS version:  $($PSVersionTable.PSVersion)"
Write-Host "  OS:          $((Get-CimInstance Win32_OperatingSystem).Caption) $((Get-CimInstance Win32_OperatingSystem).Version)"
Write-Host "  Transcript:  $logPath"

# == 1. Winlogon autologon state =========================================
Write-Section "1. Winlogon autologon state (current configuration)"
$winlogonPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
Get-ItemProperty $winlogonPath -ErrorAction SilentlyContinue |
    Select-Object AutoAdminLogon, DefaultUserName, DefaultDomainName,
                  AutoLogonCount, ForceAutoLogon, AutoLogonChecked,
                  AutoRestartShell, Shell |
    Format-List
Write-Host "  (DefaultPassword intentionally not displayed -- it's stored as an LSA secret, not a registry value)"

# == 2. Passwordless-mode flag ===========================================
Write-Section "2. DevicePasswordLessBuildVersion (Windows 11 lock-screen passwordless flag)"
$plPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PasswordLess\Device'
$pl = Get-ItemProperty $plPath -ErrorAction SilentlyContinue
if ($pl) {
    Write-Host "  DevicePasswordLessBuildVersion = $($pl.DevicePasswordLessBuildVersion)"
    switch ($pl.DevicePasswordLessBuildVersion) {
        0 { Write-Host "  >> Password sign-in IS available at the lock screen." -ForegroundColor Green }
        2 { Write-Host "  >> Password sign-in is HIDDEN at the lock screen." -ForegroundColor Yellow
            Write-Host "     This is the most common reason 'only Authenticator/PIN' appears." -ForegroundColor Yellow
            Write-Host "     Fix: from elevated PowerShell," -ForegroundColor Yellow
            Write-Host "       reg add `"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PasswordLess\Device`" /v DevicePasswordLessBuildVersion /t REG_DWORD /d 0 /f" -ForegroundColor Yellow
            Write-Host "     Then Win+L -- password option should appear." -ForegroundColor Yellow }
        default { Write-Host "  >> Unexpected value; expected 0 or 2." -ForegroundColor Yellow }
    }
} else {
    Write-Host "  Key not present. Default behaviour: password sign-in available."
}

# == 3. Local account properties =========================================
Write-Section "3. Get-LocalUser '$User' -- local SAM properties"
try {
    Get-LocalUser -Name $User -ErrorAction Stop |
        Format-List Name, Enabled, PasswordRequired, PasswordLastSet,
                    PasswordExpires, PrincipalSource, SID, Description, FullName
} catch {
    Write-Host "  Get-LocalUser failed for '$User': $($_.Exception.Message)" -ForegroundColor Yellow
}

# == 4. WMI cross-check ==================================================
Write-Section "4. Win32_UserAccount WMI properties (cross-check)"
Get-CimInstance -ClassName Win32_UserAccount -Filter "Name='$User'" -ErrorAction SilentlyContinue |
    Select-Object Name, FullName, AccountType, Disabled, Domain, LocalAccount,
                  PasswordRequired, PasswordChangeable, PasswordExpires, SID, SIDType, Status |
    Format-List

# == 5. Hello / NGC / Passport policy state ==============================
Write-Section "5. Windows Hello / Passport policy state"
$pwPathHKLM = 'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork'
$pwPathPolicy = 'HKLM:\SOFTWARE\Microsoft\Policies\Microsoft\PassportForWork'
foreach ($p in $pwPathHKLM, $pwPathPolicy) {
    if (Test-Path $p) {
        Write-Host "  $p :"
        Get-ItemProperty $p | Format-List
    } else {
        Write-Host "  $p -- not present (no Hello-for-Business policy applied)"
    }
}
# NGC (Next Generation Credentials = PIN/biometric/FIDO2) container state.
$ngcPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\PasswordLess'
if (Test-Path $ngcPath) {
    Write-Host ""
    Write-Host "  $ngcPath :"
    Get-ChildItem $ngcPath -ErrorAction SilentlyContinue |
        ForEach-Object { Write-Host "    subkey: $($_.PSChildName)" }
}

# == 6. Azure AD / hybrid state ==========================================
Write-Section "6. dsregcmd /status -- Azure AD / work-account state"
Write-Host "  (raw output below; key fields: AzureAdJoined, EnterpriseJoined,"
Write-Host "   DomainJoined, WorkplaceJoined, AzureAdPrt)"
Write-Host ""
$dsregOut = & dsregcmd /status 2>&1
$dsregOut | Out-String | Write-Host
# Also pull the headline booleans for at-a-glance reading
Write-Host ""
Write-Host "  Headline booleans (extracted):"
$dsregOut | Where-Object { $_ -match '^\s+(AzureAdJoined|EnterpriseJoined|DomainJoined|WorkplaceJoined|AzureAdPrt)\s*:' } |
    ForEach-Object { Write-Host "    $($_.Trim())" }

# == 7. Credential providers presented at the lock screen ================
Write-Section "7. Credential providers (what the lock screen can show)"
$cpRoot = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers'
if (Test-Path $cpRoot) {
    Get-ChildItem $cpRoot -ErrorAction SilentlyContinue | ForEach-Object {
        $key = $_
        $name = (Get-ItemProperty $key.PSPath -ErrorAction SilentlyContinue).'(default)'
        $disabled = (Get-ItemProperty $key.PSPath -Name Disabled -ErrorAction SilentlyContinue).Disabled
        [PSCustomObject]@{
            GUID     = $key.PSChildName
            Name     = $name
            Disabled = if ($null -eq $disabled) { '(default = enabled)' } else { $disabled }
        }
    } | Format-Table -AutoSize | Out-String | Write-Host
} else {
    Write-Host "  Credential Providers key not present -- unusual, expect this on Windows 10/11."
}

# Also surface filters (which can hide otherwise-enabled providers)
$filterRoot = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Provider Filters'
if (Test-Path $filterRoot) {
    Write-Host ""
    Write-Host "  Credential Provider Filters (these can HIDE providers from #7):"
    Get-ChildItem $filterRoot -ErrorAction SilentlyContinue | ForEach-Object {
        $name = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).'(default)'
        Write-Host "    $($_.PSChildName)  $name"
    }
}

# == Summary footer ======================================================
Write-Section "Summary"
Write-Host "  Transcript saved to:" -ForegroundColor Green
Write-Host "    $logPath" -ForegroundColor Green
Write-Host ""
Write-Host "  Share the contents of that file:"
Write-Host "    Get-Content '$logPath' | Set-Clipboard"
Write-Host ""
Write-Host "  Most common findings:"
Write-Host "    - DevicePasswordLessBuildVersion = 2 -> password hidden at lock screen"
Write-Host "    - Account is Microsoft Account-linked (Get-LocalUser shows"
Write-Host "      PrincipalSource = MicrosoftAccount) -> use the cloud password"
Write-Host "      with domain 'MicrosoftAccount' instead of the computer name"
Write-Host "    - Account is Azure AD-joined (dsregcmd /status shows"
Write-Host "      AzureAdJoined : YES) -> Sysinternals Autologon historically does"
Write-Host "      not work; use netplwiz, or create a separate local account"
Write-Host "      for runner / autologon purposes."

Stop-Transcript | Out-Null
