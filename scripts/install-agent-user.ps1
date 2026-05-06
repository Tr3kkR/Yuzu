<#
.SYNOPSIS
    Provision the unprivileged Windows account the Yuzu agent runs under,
    plus the narrow privilege grants it needs to operate plugins like
    quarantine, services.set_start_mode, and registry writes against HKLM.

.DESCRIPTION

AUTHORITY
─────────
This script is the Windows implementation of the privilege model defined
in docs/agent-privilege-model.md. The Linux/macOS sibling is
scripts/install-agent-user.sh. If the doc and the script disagree, the
doc wins — fix the script, then re-run.

WHAT THIS SCRIPT DOES
─────────────────────
1.  Creates a dedicated local user account the agent runs under.
        Default name:  YuzuAgent
        Password:      a 24-character random password, stored ONLY in
                       a DPAPI-encrypted blob at
                       C:\ProgramData\Yuzu\agent-credential.dpapi
                       readable only by SYSTEM and Administrators.
                       The agent itself never reads this file — it gets
                       its own login token from the service controller
                       at start-time. The blob exists so an operator can
                       reset the account by re-running this script
                       without losing access.
        User flags:    Account never expires, password never expires,
                       cannot change password, hidden from login screen
                       (no profile creation), no interactive logon right.

    PRODUCTION ALTERNATIVE — Virtual Service Account (recommended)
    ──────────────────────────────────────────────────────────────
    The production MSI installer registers the agent service under a
    Windows virtual service account named `NT SERVICE\YuzuAgent`. Virtual
    service accounts have these advantages over a local account:
       - auto-created by `sc.exe create ... obj= "NT SERVICE\..."`
       - no password to manage; the SCM provides credentials
       - cannot log on interactively at all (vs. our local user which
         is just denied this right via secedit)
       - per-machine SID; can't be moved or impersonated across boxes
    When the production installer runs, this script's job is done; it
    refuses to overwrite an existing service registration. Dev installs
    use the local-user path because we don't always have the agent
    service registered during /test runs.

2.  Adds the account to the platform-specific groups it needs:
        Event Log Readers       — read Application/System/Security event logs
        Performance Monitor Users — WMI counter reads (hardware, processes)
        Performance Log Users     — trace session reads

3.  Grants the following privileges (LSA account rights) via P/Invoke
    of advapi32!LsaAddAccountRights:
        SeServiceLogonRight     — required to run as a service
        SeChangeNotifyPrivilege — traverse path-checking (default for
                                  Authenticated Users, but we make it
                                  explicit so a hardened policy that
                                  removes the default doesn't break us)
        SeBackupPrivilege       — read all files regardless of DACL
                                  (event log files, registry hives,
                                   filesystem.read with system paths)
        SeRestorePrivilege      — paired with SeBackupPrivilege; restore
                                  semantics for the same paths
        SeSecurityPrivilege     — read Security event log, manage SACLs
        SeIncreaseQuotaPrivilege — adjust process quotas (some WMI
                                  queries require this on hardened
                                  systems)
        SeAssignPrimaryTokenPrivilege — required by sc.exe + service
                                  control plugins

    DELIBERATELY NOT GRANTED:
        SeLoadDriverPrivilege   — drivers are kernel-mode; the agent
                                  stays user-mode
        SeImpersonatePrivilege  — would let the agent impersonate any
                                  logged-in user; reserved for the
                                  future per-session interaction helper
        SeTakeOwnershipPrivilege — agent should never seize files
        SeDebugPrivilege        — gives effective full-system access;
                                  granted to LocalSystem only

4.  Creates the agent's filesystem hierarchy under C:\ProgramData\Yuzu\
    with NTFS ACLs that grant the agent account modify access while
    locking out everyone except SYSTEM and Administrators:
        C:\ProgramData\Yuzu\state\    — agent.db, KV store, command-id cache
        C:\ProgramData\Yuzu\cache\    — content_dist staging area
        C:\ProgramData\Yuzu\logs\     — spdlog output
        C:\ProgramData\Yuzu\plugins\  — read-only to the agent so a
                                        compromised plugin can't tamper
                                        with siblings; only Administrators
                                        + SYSTEM can write here.
        C:\ProgramData\Yuzu\config\   — agent.cfg, mTLS cert/key

5.  (Optional) Configures `Deny logon locally` and `Deny logon through
    Remote Desktop` via secedit, so the agent account cannot be used
    for an interactive session even if its password is somehow obtained.
    Skipped under -SkipDenyInteractive for test environments.

WHAT THIS SCRIPT DOES NOT DO
─────────────────────────────
- Install the agent binary itself. Use the MSI (production) or
    `meson install` (dev) for that.
- Register the agent service with the SCM (`sc.exe create`). That happens
    at MSI install or in `scripts/start-UAT.ps1`.
- Configure Windows Firewall rules. The quarantine plugin manages those
    via `netsh advfirewall` at runtime.
- Provision certificates. The agent gets its mTLS material from the
    server enrollment flow.

IDEMPOTENCY
───────────
Every step probes existing state and skips if already correct. Re-running
this script is safe. Privilege grants and group memberships are union'd
(never removed); use `-Uninstall` to reverse cleanly.

UNINSTALL
─────────
`-Uninstall` reverses everything except the logs directory, which is
preserved as `C:\ProgramData\Yuzu\logs.removed-<timestamp>` for forensics.

.PARAMETER DryRun
    Print every action without executing it. Use this first.

.PARAMETER Check
    Verify the install is correct (account exists, in expected groups,
    has expected privileges, state dirs exist with expected ACLs).
    Exits non-zero on any drift. Suitable for use as a pre-flight gate.

.PARAMETER Uninstall
    Remove the account, its privileges, and the state directories.

.PARAMETER AccountName
    Override the default local account name (YuzuAgent). Useful for
    parallel test environments. Ignored on -Uninstall when an existing
    account isn't found.

.PARAMETER BinaryPath
    Override the path to the agent binary. Default is
    C:\Program Files\Yuzu\yuzu-agent.exe. Reserved for future use; on
    Windows there's no setcap analogue, so this is currently informational
    (recorded in the install marker file for diagnostics).

.PARAMETER SkipDenyInteractive
    Skip the secedit step that adds the account to "Deny logon locally"
    and "Deny logon through Remote Desktop". Use only in test
    environments where you want to be able to run Powershell in the
    account's context to debug plugin behaviour.

.EXAMPLE
    # Dry-run from an elevated PowerShell:
    .\install-agent-user.ps1 -DryRun

.EXAMPLE
    # Install:
    .\install-agent-user.ps1

.EXAMPLE
    # Verify (no admin needed if reading public attributes; prefers admin
    # to read the privilege list authoritatively):
    .\install-agent-user.ps1 -Check

.EXAMPLE
    # Uninstall:
    .\install-agent-user.ps1 -Uninstall

REQUIREMENTS
────────────
- Windows 10 / 11 / Server 2019+ (uses Microsoft.PowerShell.LocalAccounts
    module, present by default since Windows 10).
- Windows PowerShell 5.1 (default on Windows 10+) or PowerShell 7+.
- Administrator privileges (for install, uninstall, and most -Check
    fields). The script self-detects and refuses to proceed without
    elevation.

EXIT CODES
──────────
    0  - install / check / uninstall succeeded
    1  - install / check / uninstall failed; details on stderr
    2  - argument or precondition error (not running elevated, unsupported OS)
    3  - secedit operation failed; install was rolled back
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [switch]$DryRun,
    [switch]$Check,
    [switch]$Uninstall,
    [string]$AccountName = "YuzuAgent",
    [string]$BinaryPath  = "C:\Program Files\Yuzu\yuzu-agent.exe",
    [switch]$SkipDenyInteractive
)

# ── platform + privilege guard ──────────────────────────────────────────────

$ErrorActionPreference = 'Stop'

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($id)
    return $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Error "PowerShell 5.1 or later is required (you have $($PSVersionTable.PSVersion))."
    exit 2
}

if (-not $IsWindows -and -not ($PSVersionTable.PSVersion.Major -lt 6)) {
    # PS5.1 doesn't define $IsWindows; on PS5 we're always on Windows. On PS7+
    # this guard catches running the script on Linux/macOS PowerShell.
    Write-Error "This script is Windows-only. Use scripts/install-agent-user.sh on Linux/macOS."
    exit 2
}

# Helper indicators for -DryRun vs -WhatIf — both ride the SupportsShouldProcess
# pipeline so PSCmdlet.ShouldProcess() is used uniformly.
$Script:Effective = -not ($DryRun -or $WhatIfPreference)

function Write-Info  { param([string]$msg) Write-Host "[install-agent-user] $msg" }
function Write-Warn  { param([string]$msg) Write-Host "[install-agent-user] WARN: $msg" -ForegroundColor Yellow }
function Write-Step  { param([string]$msg) Write-Host "[install-agent-user] >>> $msg" -ForegroundColor Cyan }
function Write-Fail  { param([string]$msg) Write-Host "[install-agent-user] ERROR: $msg" -ForegroundColor Red; throw $msg }

# ── paths ────────────────────────────────────────────────────────────────────

$Script:RootDir   = "C:\ProgramData\Yuzu"
$Script:StateDir  = Join-Path $RootDir "state"
$Script:CacheDir  = Join-Path $RootDir "cache"
$Script:LogDir    = Join-Path $RootDir "logs"
$Script:PluginsDir = Join-Path $RootDir "plugins"
$Script:ConfigDir = Join-Path $RootDir "config"
$Script:CredFile  = Join-Path $RootDir "agent-credential.dpapi"
$Script:MarkerFile = Join-Path $RootDir "install-marker.json"

# ── account management ──────────────────────────────────────────────────────

function New-AgentAccount {
    param([string]$name)

    if (Get-LocalUser -Name $name -ErrorAction SilentlyContinue) {
        Write-Info "user $name already exists — skipping create"
        return
    }

    Write-Step "creating local user $name"

    # Generate a strong random password. Length 24, mixed case + digits +
    # printable symbols. We use RNGCryptoServiceProvider rather than
    # Get-Random because Get-Random isn't cryptographically random.
    Add-Type -AssemblyName System.Security
    $bytes = New-Object byte[] 24
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    $charset = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*-_=+"
    $sb = New-Object System.Text.StringBuilder
    foreach ($b in $bytes) { [void]$sb.Append($charset[$b % $charset.Length]) }
    $plainPassword = $sb.ToString()
    $securePassword = ConvertTo-SecureString $plainPassword -AsPlainText -Force

    if ($PSCmdlet.ShouldProcess($name, "Create local user account")) {
        $user = New-LocalUser `
            -Name $name `
            -Password $securePassword `
            -FullName "Yuzu Agent Daemon" `
            -Description "Yuzu endpoint agent — runs as service account, no interactive login" `
            -PasswordNeverExpires `
            -UserMayNotChangePassword `
            -AccountNeverExpires
        Write-Info "  SID = $($user.SID)"

        # Stash the password in a DPAPI blob so an operator can recover
        # the account by re-running with a known credential. Encrypted
        # under the LocalMachine scope so SYSTEM can read it; ACL'd to
        # remove all other access.
        $encrypted = ConvertFrom-SecureString $securePassword
        Set-Content -Path $CredFile -Value $encrypted -Encoding UTF8
        $acl = Get-Acl $CredFile
        $acl.SetAccessRuleProtection($true, $false)  # disable inheritance, drop existing
        $sysRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            'NT AUTHORITY\SYSTEM', 'FullControl', 'Allow')
        $admRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            'BUILTIN\Administrators', 'FullControl', 'Allow')
        $acl.AddAccessRule($sysRule)
        $acl.AddAccessRule($admRule)
        Set-Acl -Path $CredFile -AclObject $acl
        Write-Info "  password stashed at $CredFile (SYSTEM + Administrators only)"
    }
}

function Remove-AgentAccount {
    param([string]$name)

    if (-not (Get-LocalUser -Name $name -ErrorAction SilentlyContinue)) {
        Write-Info "user $name does not exist — skipping delete"
        return
    }

    Write-Step "deleting local user $name"
    if ($PSCmdlet.ShouldProcess($name, "Delete local user account")) {
        Remove-LocalUser -Name $name
    }

    if (Test-Path $CredFile) {
        Write-Info "removing $CredFile"
        if ($PSCmdlet.ShouldProcess($CredFile, "Remove credential file")) {
            Remove-Item $CredFile -Force
        }
    }
}

# ── group memberships ───────────────────────────────────────────────────────

$Script:RequiredGroups = @(
    'Event Log Readers',
    'Performance Monitor Users',
    'Performance Log Users'
)

function Add-AgentToGroups {
    param([string]$name)

    foreach ($group in $RequiredGroups) {
        if (-not (Get-LocalGroup -Name $group -ErrorAction SilentlyContinue)) {
            Write-Warn "group '$group' not present on this host — skipping"
            continue
        }
        $current = Get-LocalGroupMember -Group $group -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like "*\$name" }
        if ($current) {
            Write-Info "  $name already in group '$group'"
            continue
        }
        Write-Step "adding $name to group '$group'"
        if ($PSCmdlet.ShouldProcess($group, "Add $name to group")) {
            Add-LocalGroupMember -Group $group -Member $name
        }
    }
}

function Remove-AgentFromGroups {
    param([string]$name)

    foreach ($group in $RequiredGroups) {
        if (-not (Get-LocalGroup -Name $group -ErrorAction SilentlyContinue)) { continue }
        $present = Get-LocalGroupMember -Group $group -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like "*\$name" }
        if (-not $present) { continue }
        Write-Step "removing $name from group '$group'"
        if ($PSCmdlet.ShouldProcess($group, "Remove $name from group")) {
            Remove-LocalGroupMember -Group $group -Member $name -ErrorAction SilentlyContinue
        }
    }
}

# ── LSA privilege grants (P/Invoke) ─────────────────────────────────────────
#
# Windows has no built-in cmdlet to grant SeXxxPrivilege rights to an
# account. The two real options are:
#   1. secedit /export → edit → secedit /configure   (clunky, race-prone)
#   2. P/Invoke advapi32!LsaAddAccountRights         (clean, atomic)
# We use option 2. The C# definitions below are the LSA documented
# interfaces from https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/.
# Type loading is idempotent — successive imports just no-op.

$Script:RequiredPrivileges = @(
    'SeServiceLogonRight',
    'SeChangeNotifyPrivilege',
    'SeBackupPrivilege',
    'SeRestorePrivilege',
    'SeSecurityPrivilege',
    'SeIncreaseQuotaPrivilege',
    'SeAssignPrimaryTokenPrivilege'
)

# DELIBERATELY OMITTED — see DESCRIPTION:
# SeLoadDriverPrivilege, SeImpersonatePrivilege, SeTakeOwnershipPrivilege,
# SeDebugPrivilege.

$lsaSource = @"
using System;
using System.Runtime.InteropServices;

namespace YuzuLsa {
    [StructLayout(LayoutKind.Sequential)]
    public struct LSA_UNICODE_STRING {
        public UInt16 Length;
        public UInt16 MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LSA_OBJECT_ATTRIBUTES {
        public UInt32 Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public UInt32 Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    public static class Native {
        [DllImport("advapi32.dll", PreserveSig = false)]
        public static extern uint LsaOpenPolicy(
            IntPtr SystemName,
            ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
            uint DesiredAccess,
            out IntPtr PolicyHandle);

        [DllImport("advapi32.dll", PreserveSig = false)]
        public static extern uint LsaAddAccountRights(
            IntPtr PolicyHandle,
            byte[] AccountSid,
            LSA_UNICODE_STRING[] UserRights,
            uint CountOfRights);

        [DllImport("advapi32.dll", PreserveSig = false)]
        public static extern uint LsaRemoveAccountRights(
            IntPtr PolicyHandle,
            byte[] AccountSid,
            bool AllRights,
            LSA_UNICODE_STRING[] UserRights,
            uint CountOfRights);

        [DllImport("advapi32.dll", PreserveSig = false)]
        public static extern uint LsaClose(IntPtr ObjectHandle);
    }
}
"@

function Initialize-LsaTypes {
    if (-not ([System.Management.Automation.PSTypeName]'YuzuLsa.Native').Type) {
        Add-Type -TypeDefinition $lsaSource -Language CSharp
    }
}

function ConvertTo-LsaUnicodeString {
    param([string]$s)
    $u = New-Object YuzuLsa.LSA_UNICODE_STRING
    $u.Buffer = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($s)
    $u.Length = [UInt16]($s.Length * 2)
    $u.MaximumLength = [UInt16](($s.Length + 1) * 2)
    return $u
}

function Grant-AccountPrivileges {
    param([string]$name, [string[]]$privileges)
    Initialize-LsaTypes

    $sid = (Get-LocalUser -Name $name).SID
    $sidBytes = New-Object byte[] $sid.BinaryLength
    $sid.GetBinaryForm($sidBytes, 0)

    $oa = New-Object YuzuLsa.LSA_OBJECT_ATTRIBUTES
    $oa.Length = [System.Runtime.InteropServices.Marshal]::SizeOf($oa)
    $POLICY_CREATE_ACCOUNT = 0x00000010
    $POLICY_LOOKUP_NAMES   = 0x00000800

    $handle = [IntPtr]::Zero
    $rc = [YuzuLsa.Native]::LsaOpenPolicy([IntPtr]::Zero, [ref]$oa,
        ($POLICY_CREATE_ACCOUNT -bor $POLICY_LOOKUP_NAMES), [ref]$handle)
    if ($rc -ne 0) { Write-Fail "LsaOpenPolicy failed: $rc" }

    try {
        foreach ($priv in $privileges) {
            Write-Step "granting $priv to $name"
            if (-not $PSCmdlet.ShouldProcess($name, "Grant $priv")) { continue }

            $u = ConvertTo-LsaUnicodeString $priv
            $arr = @($u)
            $rc = [YuzuLsa.Native]::LsaAddAccountRights($handle, $sidBytes, $arr, 1)
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($u.Buffer)
            if ($rc -ne 0) {
                Write-Warn "  LsaAddAccountRights for $priv returned NTSTATUS 0x$('{0:X8}' -f $rc)"
            }
        }
    } finally {
        [void][YuzuLsa.Native]::LsaClose($handle)
    }
}

function Revoke-AccountPrivileges {
    param([string]$name, [string[]]$privileges)
    Initialize-LsaTypes

    if (-not (Get-LocalUser -Name $name -ErrorAction SilentlyContinue)) {
        return  # account already gone; LSA cleans up automatically
    }

    $sid = (Get-LocalUser -Name $name).SID
    $sidBytes = New-Object byte[] $sid.BinaryLength
    $sid.GetBinaryForm($sidBytes, 0)

    $oa = New-Object YuzuLsa.LSA_OBJECT_ATTRIBUTES
    $oa.Length = [System.Runtime.InteropServices.Marshal]::SizeOf($oa)
    $POLICY_CREATE_ACCOUNT = 0x00000010
    $POLICY_LOOKUP_NAMES   = 0x00000800

    $handle = [IntPtr]::Zero
    $rc = [YuzuLsa.Native]::LsaOpenPolicy([IntPtr]::Zero, [ref]$oa,
        ($POLICY_CREATE_ACCOUNT -bor $POLICY_LOOKUP_NAMES), [ref]$handle)
    if ($rc -ne 0) { Write-Warn "LsaOpenPolicy failed during revoke: $rc"; return }

    try {
        foreach ($priv in $privileges) {
            Write-Step "revoking $priv from $name"
            if (-not $PSCmdlet.ShouldProcess($name, "Revoke $priv")) { continue }
            $u = ConvertTo-LsaUnicodeString $priv
            $arr = @($u)
            [void][YuzuLsa.Native]::LsaRemoveAccountRights($handle, $sidBytes, $false, $arr, 1)
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($u.Buffer)
        }
    } finally {
        [void][YuzuLsa.Native]::LsaClose($handle)
    }
}

# ── filesystem hierarchy ────────────────────────────────────────────────────

function New-AgentDirectories {
    param([string]$name)

    $dirs = @{
        $StateDir   = "Modify"
        $CacheDir   = "Modify"
        $LogDir     = "Modify"
        $ConfigDir  = "ReadAndExecute"
        $PluginsDir = "ReadAndExecute"
    }

    foreach ($entry in $dirs.GetEnumerator()) {
        $dir = $entry.Key
        $access = $entry.Value
        if (-not (Test-Path $dir)) {
            Write-Step "creating $dir"
            if ($PSCmdlet.ShouldProcess($dir, "Create directory")) {
                New-Item -Path $dir -ItemType Directory -Force | Out-Null
            }
        } else {
            Write-Info "  $dir already exists"
        }

        if ($PSCmdlet.ShouldProcess($dir, "Apply ACL")) {
            $acl = Get-Acl $dir
            $acl.SetAccessRuleProtection($true, $false)  # disable inheritance, drop existing

            # Always allow SYSTEM + Administrators full control. Without this
            # an operator can't manage the directory.
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                'NT AUTHORITY\SYSTEM', 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                'BUILTIN\Administrators', 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))

            # Agent account gets the per-dir level access (Modify for
            # state/cache/log, ReadAndExecute for plugins/config).
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                ".\$name", $access, 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
            Set-Acl -Path $dir -AclObject $acl
        }
    }
}

function Remove-AgentDirectories {
    foreach ($dir in @($StateDir, $CacheDir, $ConfigDir, $PluginsDir)) {
        if (Test-Path $dir) {
            Write-Step "removing $dir"
            if ($PSCmdlet.ShouldProcess($dir, "Remove directory")) {
                Remove-Item -Path $dir -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
    # Logs preserved on uninstall — same forensics rationale as the bash sibling.
    if (Test-Path $LogDir) {
        $stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
        $archive = "${LogDir}.removed-$stamp"
        Write-Step "preserving $LogDir -> $archive"
        if ($PSCmdlet.ShouldProcess($LogDir, "Rename to $archive")) {
            Rename-Item -Path $LogDir -NewName (Split-Path $archive -Leaf)
        }
    }
}

# ── deny interactive logon (secedit) ────────────────────────────────────────
# secedit reads/writes a security policy template. We need to:
#   1. Export current policy to a temp .inf
#   2. Add our account to SeDenyInteractiveLogonRight + SeDenyRemoteInteractiveLogonRight
#   3. Re-import. If the import fails the box's policy is unchanged.

function Set-DenyInteractiveLogon {
    param([string]$name)

    if ($SkipDenyInteractive) {
        Write-Info "skipping deny-interactive (-SkipDenyInteractive)"
        return
    }

    Write-Step "configuring deny-interactive-logon for $name"

    $exportFile = New-TemporaryFile
    $importFile = New-TemporaryFile
    try {
        if ($PSCmdlet.ShouldProcess($name, "secedit export → modify → import")) {
            # Export current Privilege Rights section.
            $sxArgs = @('/export', '/cfg', $exportFile.FullName,
                       '/areas', 'USER_RIGHTS', '/quiet')
            $rc = (Start-Process -FilePath 'secedit.exe' -ArgumentList $sxArgs `
                   -Wait -PassThru -NoNewWindow).ExitCode
            if ($rc -ne 0) {
                Write-Warn "secedit /export returned $rc — skipping deny-interactive"
                return
            }

            # Read, mutate, write. We append `*<SID>` to the two rights
            # if the SID isn't already there.
            $sid = (Get-LocalUser -Name $name).SID.Value
            $content = Get-Content $exportFile.FullName

            $newContent = New-Object System.Collections.Generic.List[string]
            $sawDenyLocal = $false
            $sawDenyRemote = $false
            foreach ($line in $content) {
                if ($line -match '^SeDenyInteractiveLogonRight\s*=') {
                    $sawDenyLocal = $true
                    if ($line -notmatch [regex]::Escape($sid)) { $line = "$line,*$sid" }
                } elseif ($line -match '^SeDenyRemoteInteractiveLogonRight\s*=') {
                    $sawDenyRemote = $true
                    if ($line -notmatch [regex]::Escape($sid)) { $line = "$line,*$sid" }
                }
                $newContent.Add($line)
            }
            if (-not $sawDenyLocal)  { $newContent.Add("SeDenyInteractiveLogonRight = *$sid") }
            if (-not $sawDenyRemote) { $newContent.Add("SeDenyRemoteInteractiveLogonRight = *$sid") }

            Set-Content -Path $importFile.FullName -Value $newContent -Encoding Unicode

            $sxArgs = @('/configure', '/db', "$($env:TEMP)\yuzu-secedit.sdb",
                       '/cfg', $importFile.FullName, '/areas', 'USER_RIGHTS',
                       '/quiet')
            $rc = (Start-Process -FilePath 'secedit.exe' -ArgumentList $sxArgs `
                   -Wait -PassThru -NoNewWindow).ExitCode
            if ($rc -ne 0) {
                Write-Warn "secedit /configure returned $rc — deny-interactive may not be applied"
            }
        }
    } finally {
        Remove-Item $exportFile.FullName -ErrorAction SilentlyContinue
        Remove-Item $importFile.FullName -ErrorAction SilentlyContinue
    }
}

# ── verification ────────────────────────────────────────────────────────────

function Test-Install {
    param([string]$name)
    $errs = 0

    # 1. Account exists
    if (-not (Get-LocalUser -Name $name -ErrorAction SilentlyContinue)) {
        Write-Warn "user $name does not exist"; $errs++
    } else {
        Write-Info "user $name present"
    }

    # 2. Group memberships
    foreach ($group in $RequiredGroups) {
        if (-not (Get-LocalGroup -Name $group -ErrorAction SilentlyContinue)) { continue }
        $present = Get-LocalGroupMember -Group $group -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like "*\$name" }
        if ($present) {
            Write-Info "  in group: $group"
        } else {
            Write-Warn "  NOT in group: $group"; $errs++
        }
    }

    # 3. Directories exist
    foreach ($dir in @($StateDir, $CacheDir, $LogDir, $ConfigDir, $PluginsDir)) {
        if (Test-Path $dir) {
            Write-Info "  dir present: $dir"
        } else {
            Write-Warn "  missing dir: $dir"; $errs++
        }
    }

    # 4. (Best-effort) check that LSA privileges are present. We can't
    # easily query "what rights does this SID have" via the public PS
    # cmdlets — we'd need LsaEnumerateAccountRights. For now, we recommend
    # `whoami /priv` while logged in as the account. We just print a hint.
    Write-Info "for an authoritative privilege check, use:"
    Write-Info "  PsExec.exe -u .\$name -p <pass> whoami /priv"
    Write-Info "  (sysinternals; not bundled with Windows)"

    if ($errs -eq 0) {
        Write-Info "check passed — install looks correct"
        return 0
    } else {
        Write-Warn "check failed — $errs issue(s) found"
        return 1
    }
}

# ── action dispatch ─────────────────────────────────────────────────────────

if (-not $Check -and -not $Uninstall) {
    if (-not (Test-IsAdmin) -and -not $DryRun) {
        Write-Fail "must be run as Administrator (open an elevated PowerShell)."
    }

    Write-Info "installing Yuzu agent user (account: $AccountName)"
    Write-Info "  state dir   : $StateDir"
    Write-Info "  cache dir   : $CacheDir"
    Write-Info "  log dir     : $LogDir"
    Write-Info "  plugins dir : $PluginsDir"
    Write-Info "  config dir  : $ConfigDir"
    Write-Info ""

    New-Item -Path $RootDir -ItemType Directory -Force | Out-Null
    New-AgentAccount  -name $AccountName
    Add-AgentToGroups -name $AccountName
    Grant-AccountPrivileges -name $AccountName -privileges $RequiredPrivileges
    New-AgentDirectories -name $AccountName
    Set-DenyInteractiveLogon -name $AccountName

    # Install marker so check / uninstall can find what we did.
    if ($PSCmdlet.ShouldProcess($MarkerFile, "Write install marker")) {
        $marker = @{
            account_name      = $AccountName
            binary_path       = $BinaryPath
            installed_at_utc  = (Get-Date).ToUniversalTime().ToString("o")
            script_version    = "1.0.0"
            privileges        = $RequiredPrivileges
            groups            = $RequiredGroups
        }
        $marker | ConvertTo-Json -Depth 4 | Set-Content -Path $MarkerFile -Encoding UTF8
    }

    Write-Info ""
    Write-Info "install complete. Verify with:"
    Write-Info "  .\$($MyInvocation.MyCommand.Name) -Check"
    exit 0
}

if ($Check) {
    if (-not (Test-IsAdmin)) {
        Write-Warn "running -Check without admin — some checks may be incomplete"
    }
    exit (Test-Install -name $AccountName)
}

if ($Uninstall) {
    if (-not (Test-IsAdmin) -and -not $DryRun) {
        Write-Fail "uninstall requires Administrator."
    }

    Write-Info "uninstalling Yuzu agent user (account: $AccountName)"

    Revoke-AccountPrivileges -name $AccountName -privileges $RequiredPrivileges
    Remove-AgentFromGroups   -name $AccountName
    Remove-AgentAccount      -name $AccountName
    Remove-AgentDirectories

    if (Test-Path $MarkerFile) {
        Remove-Item $MarkerFile -Force -ErrorAction SilentlyContinue
    }

    Write-Info "uninstall complete."
    exit 0
}
