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
    Run elevated (`powershell.exe -ExecutionPolicy Bypass`). Defender
    persists the preference across reboots. Reversible with
    Remove-MpPreference.

    Source of record for the required set:
        docs/build-windows-runner.md   (narrative)
        scripts/windows-runner-defender-exclusions.ps1   (this script)
#>

[CmdletBinding()]
param(
    [switch]$DryRun
)

# Require admin.
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "Run as Administrator (elevated PowerShell)."
    exit 1
}

$paths = @(
    # GitHub Actions runner workspace — covers vcpkg_installed, build
    # output, ccache, and the `Cache vcpkg installed packages` step's
    # tar/zstd extraction.
    'C:\actions-runner\_work',

    # MSVC ccache — out-of-tree by default on modern vcpkg.
    (Join-Path $env:USERPROFILE 'AppData\Local\ccache'),

    # SQLite test temp paths for the unit test suite. These are
    # fs::temp_directory_path() resolved as LocalSystem (SystemTemp),
    # not the interactive user's %TEMP%. The yuzu_test_* prefix
    # covers all current stores (guardian, kv, updater, etc.).
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
    'vcpkg.exe'
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

Write-Host "`n── Applying Defender path exclusions ───────────────────────" -ForegroundColor Cyan
foreach ($p in $paths) { Add-ExclusionPath-Idempotent $p }

Write-Host "`n── Applying Defender process exclusions ────────────────────" -ForegroundColor Cyan
foreach ($proc in $processes) { Add-ExclusionProcess-Idempotent $proc }

Write-Host "`n── Current Defender configuration (post-update) ────────────" -ForegroundColor Cyan
Write-Host "ExclusionPath:"
(Get-MpPreference).ExclusionPath | ForEach-Object { Write-Host "  $_" }
Write-Host "ExclusionProcess:"
(Get-MpPreference).ExclusionProcess | ForEach-Object { Write-Host "  $_" }

Write-Host "`nDone. Reversible with Remove-MpPreference -ExclusionPath <path>."
