<#
  Assert-Toolchain.ps1 — runner self-test. Verifies that the toolchain manifest
  emitted by Provision-Windows-Runner.ps1 still holds: every required tool is
  present at its recorded path and every contract env var is set.

  Run it (a) at the end of provisioning, and (b) as a registration / preflight
  gate, so a mis-provisioned box fails in SECONDS rather than 90 minutes into a
  build. This is the catch for the cutover faults (toolchain off PATH, MSYS2
  /usr/bin missing, gateway escript/rebar3 unresolved).

  Exit 0 = healthy; exit 1 = at least one required tool/env missing.
#>
[CmdletBinding()]
param(
  [string]$ManifestPath = 'C:\actions-runner\toolchain-manifest.json'
)
$ErrorActionPreference = 'Stop'

if(-not (Test-Path $ManifestPath)){
  Write-Host "FAIL: no manifest at $ManifestPath — run Provision-Windows-Runner.ps1 first." -ForegroundColor Red
  exit 1
}
$m = Get-Content $ManifestPath -Raw | ConvertFrom-Json
$fail = 0

Write-Host "Toolchain manifest: $ManifestPath" -ForegroundColor Cyan
Write-Host ("  host=$($m.host)  generated=$($m.generated)")

Write-Host "`n-- tools --"
foreach($t in $m.tools){
  $ok = $t.path -and (Test-Path -LiteralPath $t.path)
  $req = if($t.required){ 'required' } else { 'optional' }
  if($ok){
    Write-Host ("  [OK]   {0,-11} {1}  ({2})" -f $t.name, $t.path, ($t.version ?? '?')) -ForegroundColor Green
  } elseif($t.required){
    Write-Host ("  [MISS] {0,-11} {1}" -f $t.name, ($t.path ?? '<unset>')) -ForegroundColor Red
    $fail++
  } else {
    Write-Host ("  [warn] {0,-11} {1} (optional)" -f $t.name, ($t.path ?? '<unset>')) -ForegroundColor Yellow
  }
}

# Contract env vars must be visible to a freshly-launched process. Check the live
# machine registry (what Start-PinnedRunner.ps1 refreshes into the runner).
Write-Host "`n-- env (machine) --"
foreach($k in $m.env.PSObject.Properties.Name){
  $live = [Environment]::GetEnvironmentVariable($k,'Machine')
  if($live){
    Write-Host ("  [OK]   {0,-22} {1}" -f $k, $live) -ForegroundColor Green
  } else {
    Write-Host ("  [MISS] {0,-22} (expected {1})" -f $k, $m.env.$k) -ForegroundColor Red
    $fail++
  }
}

# MSYS2 coreutils must be reachable the way the CI bash scripts use them
# (full path); this is the `head: command not found` regression guard.
$bash = ($m.tools | Where-Object name -eq 'msys2_bash').path
if($bash -and (Test-Path $bash)){
  $head = & $bash --noprofile --norc -c 'command -v head' 2>$null
  if($head){ Write-Host "`n  [OK]   msys2 bash resolves coreutils (head=$head)" -ForegroundColor Green }
  else     { Write-Host "`n  [MISS] msys2 bash cannot resolve 'head'" -ForegroundColor Red; $fail++ }
}

if($fail -eq 0){
  Write-Host "`nPASS: toolchain healthy." -ForegroundColor Green
  exit 0
} else {
  Write-Host "`nFAIL: $fail required item(s) missing — fix before registering this runner." -ForegroundColor Red
  exit 1
}
