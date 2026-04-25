<#
.SYNOPSIS
    Verify the yuzu-local-windows runner host is fully provisioned for
    persistent unattended operation: autologon active, Defender
    exclusions applied, scheduled tasks registered + running, NordVPN
    Meshnet up, WSL2 alive, tmux reachable.

.DESCRIPTION
    Read-only status check. Run after a reboot to confirm the runner
    came back online with every persistence mechanism intact. Each
    section reports PASS / WARN / FAIL with a short reason; the
    summary at the end aggregates and exits with:

        0  every check PASS
        1  one or more FAIL  (something is broken)
        2  one or more WARN  (degraded; runner usable but not ideal)

    Pass -FailOnWarn to treat WARN as a hard failure (CI-friendly).

    Captures a transcript to %TEMP%\yuzu-runner-status-<timestamp>.log
    so you can paste it back when troubleshooting.

    ASCII-only by design -- runs on Windows PowerShell 5.1 and pwsh 7+
    without parser surprises.

.PARAMETER WslDistro
    WSL distro name to probe for tmux liveness. Default: 'Ubuntu'.

.PARAMETER WslUser
    WSL user to run the tmux probe as. Default: 'dornbrn'.

.PARAMETER TmuxSession
    tmux session name to expect. Default: 'main'.

.PARAMETER FailOnWarn
    Promote WARN to FAIL for the exit code. Useful if the runner
    inventory sentinel (or any external monitor) wants any
    non-perfect state to alert.

.NOTES
    Read-only. No registry writes, no service control, no process
    starts. Safe to run repeatedly.

    Output schema for each check:
        [PASS] <name>: <one-line detail>
        [WARN] <name>: <one-line detail>  (followed by remediation hint)
        [FAIL] <name>: <one-line detail>  (followed by remediation hint)

    Designed for visual scanning AND grep-friendly automation:
        & windows-runner-status.ps1 | Select-String -Pattern '^\[FAIL\]'
#>

[CmdletBinding()]
param(
    [string]$WslDistro = 'Ubuntu',
    [string]$WslUser = 'dornbrn',
    [string]$TmuxSession = 'main',
    [switch]$FailOnWarn
)

$ErrorActionPreference = 'Continue'

$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$logPath = Join-Path $env:TEMP "yuzu-runner-status-$timestamp.log"
try { Stop-Transcript | Out-Null } catch {}
Start-Transcript -Path $logPath -Force | Out-Null

# == Result accumulator ==================================================
$results = New-Object System.Collections.Generic.List[object]

function Add-Result {
    param(
        [Parameter(Mandatory)] [ValidateSet('PASS','WARN','FAIL')] [string]$Status,
        [Parameter(Mandatory)] [string]$Name,
        [Parameter(Mandatory)] [string]$Detail,
        [string]$Remediation
    )
    $results.Add([pscustomobject]@{
        Status = $Status; Name = $Name; Detail = $Detail; Remediation = $Remediation
    })
    $color = @{ PASS='Green'; WARN='Yellow'; FAIL='Red' }[$Status]
    Write-Host ("[{0}] {1}: {2}" -f $Status, $Name, $Detail) -ForegroundColor $color
    if ($Remediation -and $Status -ne 'PASS') {
        Write-Host ("       -> {0}" -f $Remediation) -ForegroundColor DarkGray
    }
}

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host ("=" * 70)
    Write-Host ("  {0}" -f $Title)
    Write-Host ("=" * 70)
}

# Header
Write-Host ""
Write-Host "Yuzu runner host status check"
Write-Host ("  Host:        {0}" -f $env:COMPUTERNAME)
Write-Host ("  User:        {0}" -f $env:USERNAME)
Write-Host ("  whoami:      {0}" -f (whoami))
Write-Host ("  PS version:  {0}" -f $PSVersionTable.PSVersion)
Write-Host ("  Time:        {0}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
$bootTime = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
$uptime = (Get-Date) - $bootTime
Write-Host ("  Boot:        {0} ({1:F1} hours ago)" -f $bootTime.ToString('yyyy-MM-dd HH:mm:ss'), $uptime.TotalHours)
Write-Host ("  Transcript:  {0}" -f $logPath)

# == 1. Autologon configured =============================================
Write-Section "1. Autologon configuration (Winlogon registry)"
$winlogon = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue
if (-not $winlogon) {
    Add-Result FAIL "autologon-registry" "Winlogon key unreadable" `
        "Read access to HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon is required."
} elseif ($winlogon.AutoAdminLogon -ne '1' -and $winlogon.AutoAdminLogon -ne 1) {
    Add-Result FAIL "autologon-registry" "AutoAdminLogon is '$($winlogon.AutoAdminLogon)' (expected 1)" `
        "Run Sysinternals Autologon: & `$env:TEMP\Autologon64.exe /accepteula"
} elseif (-not $winlogon.DefaultUserName) {
    Add-Result FAIL "autologon-registry" "AutoAdminLogon=1 but DefaultUserName empty" `
        "Re-run Autologon to populate DefaultUserName + DefaultDomainName."
} else {
    Add-Result PASS "autologon-registry" ("AutoAdminLogon=1, user={0}\{1}" -f $winlogon.DefaultDomainName, $winlogon.DefaultUserName)
}

# Lock-screen passwordless flag (informational; doesn't break autologon
# but does surface why the lock screen UI hides the password field).
$pl = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PasswordLess\Device' -ErrorAction SilentlyContinue
if ($pl -and $pl.DevicePasswordLessBuildVersion -eq 2) {
    Add-Result WARN "lock-screen-password-hidden" "DevicePasswordLessBuildVersion=2 (password hidden at lock screen)" `
        "Cosmetic for an autologon'd runner. Set to 0 if you ever need RDP password fallback."
} else {
    Add-Result PASS "lock-screen-password-hidden" "DevicePasswordLessBuildVersion=$(if ($pl) { $pl.DevicePasswordLessBuildVersion } else { '(not set)' })"
}

# == 2. Defender exclusions ==============================================
Write-Section "2. Defender exclusions (paths + processes)"
$mp = Get-MpPreference -ErrorAction SilentlyContinue
if (-not $mp) {
    Add-Result FAIL "defender-mpprefs" "Get-MpPreference returned null (Defender not installed?)" `
        "Defender is required for the runner's standard exclusion set; check with Get-MpComputerStatus."
} else {
    $expectedPaths = @(
        'C:\actions-runner\_work',
        # USERPROFILE-relative ccache path will resolve below
        'C:\WINDOWS\SystemTemp\yuzu_*',
        'C:\WINDOWS\SystemTemp\yuzu_test_guardian',
        'C:\WINDOWS\SystemTemp\yuzu_test_kv'
    )
    $ccachePath = Join-Path $env:USERPROFILE 'AppData\Local\ccache'
    $expectedPaths += $ccachePath

    $expectedProcs = @(
        'cl.exe','link.exe','MSBuild.exe','ninja.exe',
        'tar.exe','zstd.exe','ccache.exe','vcpkg.exe',
        'yuzu_agent_tests.exe','yuzu_server_tests.exe','yuzu_tar_tests.exe',
        'yuzu-agent.exe','yuzu-server.exe'
    )

    $missingPaths = @($expectedPaths | Where-Object { $mp.ExclusionPath -notcontains $_ })
    $missingProcs = @($expectedProcs | Where-Object { $mp.ExclusionProcess -notcontains $_ })

    if ($missingPaths.Count -eq 0) {
        Add-Result PASS "defender-paths" ("{0}/{0} expected paths present" -f $expectedPaths.Count)
    } else {
        Add-Result FAIL "defender-paths" ("{0} expected paths missing: {1}" -f $missingPaths.Count, ($missingPaths -join ', ')) `
            "Re-run scripts\windows-runner-defender-exclusions.ps1 elevated."
    }
    if ($missingProcs.Count -eq 0) {
        Add-Result PASS "defender-processes" ("{0}/{0} expected processes present" -f $expectedProcs.Count)
    } else {
        Add-Result FAIL "defender-processes" ("{0} expected processes missing: {1}" -f $missingProcs.Count, ($missingProcs -join ', ')) `
            "Re-run scripts\windows-runner-defender-exclusions.ps1 elevated."
    }
}

# == 3. Scheduled tasks ===================================================
Write-Section "3. Scheduled tasks (auto-reapply + WSL keep-alive)"
$tasksToCheck = @(
    [pscustomobject]@{ Name = 'Yuzu-Runner-Defender-Exclusions';
                       Why  = 'Re-applies Defender exclusions at every logon';
                       Fix  = 'Re-run scripts\windows-runner-defender-exclusions.ps1 -RegisterAtLogon (elevated pwsh).' }
    [pscustomobject]@{ Name = 'Yuzu-WSL-KeepAlive';
                       Why  = 'Holds wsl.exe handle open so the WSL2 distro survives idle';
                       Fix  = 'Re-register per memory project_shulgi_tmux_persistence.md.' }
)
foreach ($t in $tasksToCheck) {
    $task = Get-ScheduledTask -TaskName $t.Name -ErrorAction SilentlyContinue
    if (-not $task) {
        Add-Result FAIL ("task-" + $t.Name.ToLower()) "Task not registered" $t.Fix
        continue
    }
    if ($task.State -eq 'Disabled') {
        Add-Result FAIL ("task-" + $t.Name.ToLower()) "Task registered but disabled" `
            "Enable-ScheduledTask -TaskName '$($t.Name)' (elevated)"
        continue
    }
    $info = Get-ScheduledTaskInfo -TaskName $t.Name -ErrorAction SilentlyContinue
    if (-not $info) {
        Add-Result WARN ("task-" + $t.Name.ToLower()) "TaskInfo unavailable; task is registered+enabled" $t.Fix
        continue
    }
    # LastTaskResult: 0 = success, 0x41301 (267009) = currently running, anything else = failure code
    $resultCode = $info.LastTaskResult
    $resultHex = '0x{0:X}' -f $resultCode
    if ($resultCode -eq 0) {
        $age = if ($info.LastRunTime) { ((Get-Date) - $info.LastRunTime).TotalMinutes } else { -1 }
        $ageStr = if ($age -ge 0) { ("{0:F0}m ago" -f $age) } else { "never" }
        Add-Result PASS ("task-" + $t.Name.ToLower()) ("State={0}, LastResult=0 (success), LastRunTime={1}" -f $task.State, $ageStr)
    } elseif ($resultCode -eq 267009) {
        Add-Result PASS ("task-" + $t.Name.ToLower()) ("State={0}, currently running" -f $task.State)
    } elseif ($resultCode -eq 267011) {
        # 0x41303 = task has not yet run
        Add-Result WARN ("task-" + $t.Name.ToLower()) "Task registered but never executed (no LastRunTime)" `
            "Trigger via Start-ScheduledTask -TaskName '$($t.Name)' to verify the task runs cleanly."
    } else {
        Add-Result FAIL ("task-" + $t.Name.ToLower()) ("LastTaskResult={0} ({1})" -f $resultCode, $resultHex) `
            "Inspect Event Viewer -> Microsoft -> Windows -> TaskScheduler -> Operational for failure detail."
    }
}

# == 4. NordVPN service + Meshnet ========================================
Write-Section "4. NordVPN service + Meshnet adapter"
$nordSvc = Get-Service -Name 'NordVPN Service' -ErrorAction SilentlyContinue
if (-not $nordSvc) {
    Add-Result FAIL "nordvpn-service" "Service 'NordVPN Service' not installed" `
        "Install NordVPN client; service is the WireGuard daemon for Meshnet."
} elseif ($nordSvc.Status -ne 'Running') {
    Add-Result FAIL "nordvpn-service" ("Status={0} (expected Running)" -f $nordSvc.Status) `
        "Start-Service 'NordVPN Service' (elevated). If StartType != Automatic, set: Set-Service 'NordVPN Service' -StartupType Automatic."
} elseif ($nordSvc.StartType -ne 'Automatic') {
    Add-Result WARN "nordvpn-service" ("Status=Running but StartType={0} (expected Automatic)" -f $nordSvc.StartType) `
        "Set-Service 'NordVPN Service' -StartupType Automatic to survive future reboots."
} else {
    Add-Result PASS "nordvpn-service" "Status=Running, StartType=Automatic"
}

# NordVPN tray app in user session -- required for Meshnet auth context
$nordTray = Get-Process -Name 'NordVPN' -ErrorAction SilentlyContinue
if (-not $nordTray) {
    Add-Result WARN "nordvpn-tray" "NordVPN.exe process not found in this session" `
        "The tray app holds the signed-in MSA-equivalent NordVPN identity. Without it Meshnet cannot enable on a fresh logon. Verify it's in user-startup; alternatively register a scheduled task that launches it AtLogon."
} else {
    Add-Result PASS "nordvpn-tray" ("NordVPN.exe running (PID {0})" -f $nordTray[0].Id)
}

# Meshnet adapter has an IP
$meshAdapter = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceDescription -like '*Meshnet*' -or $_.Name -like '*Meshnet*' -or $_.Name -like '*NordLynx*' }
if (-not $meshAdapter) {
    Add-Result FAIL "meshnet-adapter" "No NordVPN/Meshnet network adapter found" `
        "Open NordVPN client, sign in, enable Meshnet. Verify with: Get-NetAdapter | ? Name -like '*Mesh*'"
} elseif ($meshAdapter.Status -ne 'Up') {
    Add-Result FAIL "meshnet-adapter" ("Adapter '{0}' status={1} (expected Up)" -f $meshAdapter.Name, $meshAdapter.Status) `
        "NordVPN client may have lost the Meshnet session. Re-toggle Meshnet in the tray UI."
} else {
    $meshIP = Get-NetIPAddress -InterfaceIndex $meshAdapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                Where-Object { $_.IPAddress -notmatch '^169\.254' }
    if (-not $meshIP) {
        Add-Result WARN "meshnet-adapter" ("Adapter '{0}' Up but no usable IPv4" -f $meshAdapter.Name) `
            "Check NordVPN client; Meshnet may need a re-toggle to acquire its node IP."
    } else {
        Add-Result PASS "meshnet-adapter" ("Adapter '{0}' Up, IP={1}" -f $meshAdapter.Name, $meshIP[0].IPAddress)
    }
}

# == 5. WSL2 distro alive ================================================
Write-Section ("5. WSL2 distro '" + $WslDistro + "' liveness")
# wsl.exe --list --running emits UTF-16; capture to byte stream then decode.
$wslList = & wsl.exe --list --running --quiet 2>$null
if ($LASTEXITCODE -ne 0) {
    Add-Result WARN "wsl-running" "wsl.exe --list --running failed" `
        "WSL feature may not be installed or wsl.exe is not on PATH."
} else {
    # The output is UTF-16 with potential null bytes; normalize.
    $clean = ($wslList -join "`n") -replace "`0", '' -replace "`r", ''
    $running = $clean -split "`n" | Where-Object { $_ -match '\S' } | ForEach-Object { $_.Trim() }
    if ($running -contains $WslDistro) {
        Add-Result PASS "wsl-running" ("Distro '{0}' is running" -f $WslDistro)
    } else {
        Add-Result FAIL "wsl-running" ("Distro '{0}' is NOT running. Running list: {1}" -f $WslDistro, ($running -join ', ')) `
            "Yuzu-WSL-KeepAlive scheduled task should hold the distro open. Manually: wsl -d $WslDistro -u $WslUser --exec /usr/bin/sleep 1"
    }
}

# == 6. tmux session reachable ===========================================
Write-Section ("6. tmux session '" + $TmuxSession + "' inside WSL")
$tmuxProbe = & wsl.exe -d $WslDistro -u $WslUser --exec /usr/bin/tmux ls 2>$null
if ($LASTEXITCODE -ne 0 -or -not $tmuxProbe) {
    Add-Result WARN "wsl-tmux" "tmux ls returned no sessions or wsl invocation failed" `
        "From a separate SSH/console: wsl -d $WslDistro -u $WslUser; tmux new -d -s $TmuxSession"
} else {
    $hasSession = ($tmuxProbe | Where-Object { $_ -match ('^' + [regex]::Escape($TmuxSession) + ':') }).Count -gt 0
    if ($hasSession) {
        Add-Result PASS "wsl-tmux" ("Session '{0}' present in tmux ls" -f $TmuxSession)
    } else {
        Add-Result WARN "wsl-tmux" ("tmux running but no '{0}' session. Found: {1}" -f $TmuxSession, ($tmuxProbe -join '; ')) `
            "From inside WSL: tmux new -d -s $TmuxSession (or rely on tmux@main systemd-user unit per project_shulgi_tmux_persistence.md)."
    }
}

# == 7. GitHub Actions runner service ====================================
Write-Section "7. GitHub Actions runner service"
$runnerSvc = Get-Service -Name 'actions.runner.*' -ErrorAction SilentlyContinue
if (-not $runnerSvc) {
    Add-Result WARN "gha-runner-service" "No actions.runner.* service found" `
        "Runner may be configured to run interactively, not as a service. If you want it to auto-start, run config.cmd --runasservice in the runner install dir."
} else {
    foreach ($svc in $runnerSvc) {
        if ($svc.Status -eq 'Running') {
            Add-Result PASS ("gha-runner-" + $svc.Name) ("Status=Running, StartType={0}" -f $svc.StartType)
        } else {
            Add-Result FAIL ("gha-runner-" + $svc.Name) ("Status={0} (expected Running)" -f $svc.Status) `
                "Start-Service '$($svc.Name)' (elevated). Verify it has the right service-account credentials."
        }
    }
}

# == Summary =============================================================
Write-Section "Summary"
$pass = ($results | Where-Object Status -eq 'PASS').Count
$warn = ($results | Where-Object Status -eq 'WARN').Count
$fail = ($results | Where-Object Status -eq 'FAIL').Count
$total = $results.Count

Write-Host ""
Write-Host ("  Total checks: {0}" -f $total)
Write-Host ("    PASS: {0}" -f $pass) -ForegroundColor Green
Write-Host ("    WARN: {0}" -f $warn) -ForegroundColor Yellow
Write-Host ("    FAIL: {0}" -f $fail) -ForegroundColor Red

# Concise failure-only digest for grep / clipboard sharing
if ($fail -gt 0 -or $warn -gt 0) {
    Write-Host ""
    Write-Host "Items needing attention:"
    foreach ($r in $results | Where-Object { $_.Status -in 'WARN','FAIL' }) {
        $color = @{ WARN='Yellow'; FAIL='Red' }[$r.Status]
        Write-Host ("  [{0}] {1}: {2}" -f $r.Status, $r.Name, $r.Detail) -ForegroundColor $color
    }
}

Write-Host ""
Write-Host ("  Transcript: {0}" -f $logPath)
Write-Host "  Share with: Get-Content '$logPath' | Set-Clipboard"

Stop-Transcript | Out-Null

# Exit code
if ($fail -gt 0) {
    exit 1
} elseif ($warn -gt 0 -and $FailOnWarn) {
    exit 1
} elseif ($warn -gt 0) {
    exit 2
} else {
    exit 0
}
