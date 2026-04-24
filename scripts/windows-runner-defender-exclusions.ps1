<#
.SYNOPSIS
    Apply the Windows Defender exclusion set required by the yuzu-local-windows
    self-hosted GitHub Actions runner.

.DESCRIPTION
    Without these exclusions, Defender realtime-scans every file vcpkg
    installs, every .obj MSVC writes, every file tar.exe extracts from
    the vcpkg cache archive, and every SQLite temp DB the test suite
    creates under C:\WINDOWS\SystemTemp. That scanning activity:

      * stalls the release workflow's Build Windows x64 job until the
        60-min timeout kills it (diagnosed 2026-04-18 during v0.11.0-rc1
        — MsMpEng was running at 40.9% CPU during a stuck vcpkg cache
        extraction);
      * has been implicated in flaky Guardian engine unit tests where
        SQLite write-then-list returns inconsistent results on the
        Windows runner (observed on PR #473 Windows MSVC debug job
        72502796929, passed on re-run without code changes once runner
        load eased, with SystemTemp\yuzu_test_guardian_* not in the
        exclusion list).

    Re-running this script is idempotent — Defender deduplicates
    exclusion entries.

.NOTES
    Run elevated under PowerShell 7+ (`pwsh.exe -ExecutionPolicy Bypass`).
    Stock Windows PowerShell 5.1 is not supported — the repo saves .ps1
    files as UTF-8 without BOM (POSIX/git convention), which PS 5.1
    misreads as the system ANSI codepage and mangles any non-ASCII
    characters. See docs/windows-build.md for the project-wide PS 7+
    standard and issue #517 for the migration history.

    Defender persists the preference across reboots. Reversible with
    Remove-MpPreference.

    Source of record for the required set:
        docs/build-windows-runner.md   (narrative)
        scripts/windows-runner-defender-exclusions.ps1   (this script)
#>

[CmdletBinding()]
param(
    [switch]$DryRun,

    # Hostname pattern that is permitted to apply these exclusions. Default
    # is the Shulgi physical host that carries the yuzu-local-windows
    # GitHub Actions runner role; $env:COMPUTERNAME is the Windows
    # machine name ("SHULGI"), NOT the runner label ("yuzu-local-windows").
    # Override only when provisioning a new runner host.
    [string]$AllowedHostPattern = '^SHULGI$'
)

# Fail loudly on stock Windows PowerShell 5.1. The script body below uses
# Unicode box-drawing characters in Write-Host banners that only render
# correctly under PS 7+ (see .NOTES above and issue #517). Without this
# guard, the symptom is a cryptic "string missing terminator" parse error
# at the banner lines rather than a clean actionable message. Must live
# AFTER the param() block because PS requires [CmdletBinding()]/param()
# to be the first non-comment statement.
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Error ("This script requires PowerShell 7+. Detected " +
                 $PSVersionTable.PSVersion.ToString() +
                 ". Use pwsh.exe, not powershell.exe.")
    exit 1
}

# Hostname allowlist. Path exclusions below include real dev-workstation
# locations (%USERPROFILE%\AppData\Local\ccache, C:\WINDOWS\SystemTemp\yuzu_test_*)
# — running this script on a dev box silently weakens Defender coverage
# for those directories with no self-revert path. Refuse to proceed unless
# we are on a known runner host.
if ($env:COMPUTERNAME -notmatch $AllowedHostPattern) {
    Write-Error ("Host '$($env:COMPUTERNAME)' does not match the runner allowlist " +
                 "'$AllowedHostPattern'. This script excludes paths that exist on " +
                 "dev workstations; refusing to run. Pass -AllowedHostPattern to " +
                 "override when provisioning a new runner.")
    exit 1
}

# Require admin.
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "Run as Administrator (elevated PowerShell)."
    exit 1
}

$paths = @(
    # GitHub Actions runner workspace — covers every build-* directory
    # (build-windows-ci, build-linux under WSL2 passthrough, etc.),
    # vcpkg_installed, gateway/_build*, meson-logs, ccache output, and
    # the `Cache vcpkg installed packages` step's tar/zstd extraction.
    'C:\actions-runner\_work',

    # MSVC ccache — out-of-tree by default on modern vcpkg.
    (Join-Path $env:USERPROFILE 'AppData\Local\ccache'),

    # SQLite test temp paths for the unit test suite. These are
    # fs::temp_directory_path() resolved as LocalSystem (SystemTemp),
    # not the interactive user's %TEMP%. Wildcards required because
    # the test suite appends a process-identity suffix at runtime
    # (yuzu_test_guardian_SHULGI$, yuzu_test_kv_SHULGI$), which the
    # exact-path entries we used to carry did NOT match. The yuzu_*
    # wildcard also picks up yuzu_trigger_test and the
    # yuzu_test_reserved_plugin_<random> directories the plugin-loader
    # tests create on the fly. Observed on #501 testlogs (2026-04-24).
    'C:\WINDOWS\SystemTemp\yuzu_*',

    # Retain the legacy exact entries — Defender deduplicates, and
    # keeping them makes it obvious in `Get-MpPreference` output that
    # the wildcard above is a superset rather than a replacement.
    'C:\WINDOWS\SystemTemp\yuzu_test_guardian',
    'C:\WINDOWS\SystemTemp\yuzu_test_kv',
    'C:\WINDOWS\SystemTemp\yuzu_test_updater_rollback_needed',
    'C:\WINDOWS\SystemTemp\yuzu_test_updater_cleanup_present'
)

$processes = @(
    # MSVC toolchain — one exclusion per binary that writes intermediate
    # files frequently enough that Defender scanning visibly slows the
    # build.
    'cl.exe',
    'link.exe',
    'MSBuild.exe',
    'ninja.exe',

    # actions/cache extraction — tar unpacks ~25k files from the vcpkg
    # archive and Defender scans each. This is the single biggest win.
    'tar.exe',
    'zstd.exe',

    # ccache + vcpkg helpers.
    'ccache.exe',
    'vcpkg.exe',

    # Yuzu test binaries. Defender has been observed retaining file
    # handles on freshly-written .obj / .pdb siblings after these
    # processes exit, producing EBUSY during actions/checkout cleanup
    # on the next CI job (#501 rerun loop 2026-04-24 — locked
    # unit_test_guardian_engine.cpp.obj for >30 min).
    'yuzu_agent_tests.exe',
    'yuzu_server_tests.exe',
    'yuzu_tar_tests.exe',

    # Yuzu release binaries — for any native UAT or runtime test that
    # launches them directly on the runner (rare, but the zombie
    # yuzu-agent.exe PID 36472 that survived 3 days on Shulgi was
    # exactly this case).
    'yuzu-agent.exe',
    'yuzu-server.exe'
)

function Add-ExclusionPath-Idempotent($p) {
    $existing = (Get-MpPreference).ExclusionPath
    if ($existing -contains $p) {
        Write-Host "  [skip] path already excluded: $p"
        return
    }
    if ($DryRun) {
        Write-Host "  [dry] would add path: $p"
    } else {
        Add-MpPreference -ExclusionPath $p
        Write-Host "  [add]  path: $p"
    }
}

function Add-ExclusionProcess-Idempotent($proc) {
    $existing = (Get-MpPreference).ExclusionProcess
    if ($existing -contains $proc) {
        Write-Host "  [skip] process already excluded: $proc"
        return
    }
    if ($DryRun) {
        Write-Host "  [dry] would add process: $proc"
    } else {
        Add-MpPreference -ExclusionProcess $proc
        Write-Host "  [add]  process: $proc"
    }
}

# Unicode box-drawing banners — safe under PS 7+ (UTF-8 default). The
# preflight above refuses PS 5.1, which would misread these as ANSI
# codepage and break the parser.
Write-Host "`n── Applying Defender path exclusions ───────────────────────" -ForegroundColor Cyan
foreach ($p in $paths) { Add-ExclusionPath-Idempotent $p }

Write-Host "`n── Applying Defender process exclusions ────────────────────" -ForegroundColor Cyan
foreach ($proc in $processes) { Add-ExclusionProcess-Idempotent $proc }

Write-Host "`n── Current Defender configuration (post-update) ────────────" -ForegroundColor Cyan
Write-Host "ExclusionPath:"
(Get-MpPreference).ExclusionPath | ForEach-Object { Write-Host "  $_" }
Write-Host "ExclusionProcess:"
(Get-MpPreference).ExclusionProcess | ForEach-Object { Write-Host "  $_" }

# `<path>` in a double-quoted string trips PS's redirection parser; use a
# single-quoted string (no backtick expansion needed — we concatenate the
# leading newline via "+ "`n"").
Write-Host ('Done. Reversible with Remove-MpPreference -ExclusionPath <path>.')
