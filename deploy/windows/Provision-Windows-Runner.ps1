#Requires -RunAsAdministrator
<#
  Provision-Windows-Runner.ps1 — versioned, idempotent spec for a Yuzu native
  Windows CI build host. This is the Windows analog of
  deploy/docker/Dockerfile.ci-linux: the single source of truth for what a
  Windows runner's toolchain must contain. Run it on a fresh box (or re-run to
  reconcile) and you get a runner that matches every other Windows runner —
  no per-host archaeology.

  RUN IN AN ELEVATED PowerShell 7 (pwsh) SESSION over RDP / console. winget's
  source catalog does not work over headless SSH, so this is hand-run, not
  agent-run.

  What it does:
    - installs the pinned toolchain (Python+Meson+Ninja, Git, CMake, ccache,
      MSYS2, Erlang/OTP + rebar3, VS 2022 Build Tools C++ workload,
      PostgreSQL, vcpkg @ pinned baseline);
    - sets machine env + PATH, INCLUDING the de-Shulgi-ified gateway contract
      (YUZU_ESCRIPT / YUZU_REBAR3 — scripts/build_gateway.py reads these instead
      of assuming a C:\Erlang junction + Chocolatey path) and the shared CI
      cache location (RUNNER_TOOL_CACHE -> one machine-level dir so the 4
      CCD-pinned runners share ONE vcpkg binary cache instead of fragmenting it
      4x; mirrors CCACHE_DIR);
    - emits a machine-readable toolchain manifest that
      deploy/windows/Assert-Toolchain.ps1 (the runner self-test) verifies at
      registration, so a mis-provisioned box fails in seconds, not 90 min into
      a build.

  After this, register the runners + the CCD-pin wrapper — see
  deploy/windows/README.md and deploy/windows/Start-PinnedRunner.ps1.
#>
[CmdletBinding()]
param(
  # --- pinned toolchain versions (the "spec"); bump deliberately ---
  [string]$PythonVersion   = '3.14.6',
  [string]$MesonVersion    = '1.11.1',   # CLAUDE.md build minimum
  [string]$ErlangVersion   = '28.4.2',
  [string]$Rebar3Version   = '3.24.0',
  [string]$PostgresVersion = '18.4',
  [string]$VcpkgBaseline   = '4b77da7fed37817f124936239197833469f1b9a8',  # == vcpkg.json builtin-baseline

  # --- machine layout (conventions; keep in sync with Start-PinnedRunner.ps1) ---
  [string]$CacheRoot       = 'D:\ci',     # ccache + shared tool_cache live here (fast data drive)
  [string]$Rebar3Dir       = 'C:\tools\rebar3',
  [string]$VcpkgRoot       = 'C:\vcpkg',
  [string]$Msys2Root       = 'C:\msys64',
  [int]   $PostgresPort    = 5433,
  [int]   $PostgresMaxConnections = 400,  # shared 4-runner instance: the default 100 exhausts (CH-9)
  [string]$ManifestPath    = 'C:\actions-runner\toolchain-manifest.json'
)
$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
New-Item -ItemType Directory -Force 'C:\ProvisionLogs' | Out-Null
Start-Transcript -Path "C:\ProvisionLogs\provision-$(Get-Date -Format yyyyMMdd-HHmmss).log" | Out-Null

function Step([string]$name,[scriptblock]$body){
  Write-Host "`n===== $name =====" -ForegroundColor Cyan
  try   { & $body; Write-Host "[OK]  $name" -ForegroundColor Green }
  catch { Write-Host "[FAIL] $name :: $($_.Exception.Message)" -ForegroundColor Red }
}
function WG([string]$id,[string]$ver='',[string]$override='',[string]$scope='machine'){
  $a=@('install','--id',$id,'-e','--source','winget','--accept-source-agreements','--accept-package-agreements','--disable-interactivity')
  if($ver)     { $a+=@('--version',$ver) }
  if($scope)   { $a+=@('--scope',$scope) }
  if($override){ $a+=@('--override',$override) }
  Write-Host ("winget " + ($a -join ' '))
  winget @a
}
function Add-MachinePath([string]$dir){
  if(-not (Test-Path $dir)){ return }
  $p=[Environment]::GetEnvironmentVariable('Path','Machine')
  if($p -notmatch [regex]::Escape($dir)){
    [Environment]::SetEnvironmentVariable('Path', ($p.TrimEnd(';')+';'+$dir), 'Machine')
    Write-Host "PATH (machine) += $dir"
  }
}
function Set-MachineEnv([string]$k,[string]$v){ [Environment]::SetEnvironmentVariable($k,$v,'Machine'); Write-Host "$k = $v" }
function Find-RealEscript {
  # The real erts escript.exe (NOT the top-level launcher stub — see
  # scripts/build_gateway.py for why). Search common OTP install roots.
  $roots = @('C:\Erlang') + (Get-ChildItem 'C:\Program Files' -Directory -EA SilentlyContinue |
            Where-Object { $_.Name -like 'Erlang*' -or $_.Name -like 'erl*' } | ForEach-Object FullName)
  foreach($r in $roots){
    $e = Get-ChildItem $r -Filter escript.exe -Recurse -EA SilentlyContinue |
         Where-Object { $_.DirectoryName -match 'erts-' } | Select-Object -First 1
    if($e){ return $e.FullName }
  }
  return $null
}

Step 'winget sanity' { "winget " + (winget --version) }

Step 'Python + Meson + Ninja + PyYAML' {
  # PyYAML is a HARD configure-time dep (embed_content.py); install it apt-style.
  if(-not (Get-Command python -EA SilentlyContinue)){ WG -id 'Python.Python.3.14' -ver $PythonVersion }
  $py = (Get-Command python -EA SilentlyContinue).Source
  if($py){
    & $py -m pip install --upgrade pip | Out-Null
    & $py -m pip install "meson==$MesonVersion" ninja pyyaml | Out-Null
  } else { throw 'python not found after install' }
}

Step 'Git + CMake' {
  if(-not (Get-Command git   -EA SilentlyContinue)){ WG -id 'Git.Git' }
  if(-not (Get-Command cmake -EA SilentlyContinue)){ WG -id 'Kitware.CMake' }
}

Step 'ccache' {
  if(Get-Command ccache -EA SilentlyContinue){ 'already on PATH' } else { WG -id 'ccache.ccache' }
}

Step "MSYS2 (CI shell = $Msys2Root\usr\bin\bash.exe)" {
  if(-not (Test-Path "$Msys2Root\usr\bin\bash.exe")){ WG -id 'MSYS2.MSYS2' }
  if(Test-Path "$Msys2Root\usr\bin\bash.exe"){ 'bash present' } else { throw "MSYS2 not at $Msys2Root" }
}

Step "Erlang/OTP $ErlangVersion" {
  $erl = Get-ChildItem 'C:\Program Files\Erlang*','C:\Program Files\erl*' -Filter erl.exe -Recurse -EA SilentlyContinue | Select-Object -First 1
  if(-not $erl){ WG -id 'Erlang.ErlangOTP' -ver $ErlangVersion
                 $erl = Get-ChildItem 'C:\Program Files\Erlang*','C:\Program Files\erl*' -Filter erl.exe -Recurse -EA SilentlyContinue | Select-Object -First 1 }
  if($erl){ Add-MachinePath $erl.DirectoryName; "erl: $($erl.FullName)" } else { throw 'erl.exe not found after install' }
}

Step "rebar3 $Rebar3Version (de-Shulgi-ified: env vars, NOT a C:\Erlang junction)" {
  New-Item -ItemType Directory -Force $Rebar3Dir | Out-Null
  if(-not (Test-Path "$Rebar3Dir\rebar3")){
    Invoke-WebRequest -UseBasicParsing "https://github.com/erlang/rebar3/releases/download/$Rebar3Version/rebar3" -OutFile "$Rebar3Dir\rebar3"
  }
  Set-Content "$Rebar3Dir\rebar3.cmd" '@escript "%~dp0rebar3" %*' -Encoding Ascii
  Add-MachinePath $Rebar3Dir
  # scripts/build_gateway.py resolves the gateway toolchain from these env vars
  # (YUZU_ESCRIPT / YUZU_REBAR3), so we no longer replicate Shulgi's C:\Erlang
  # junction or the Chocolatey rebar3 path. THIS is the de-hardcoding fix (B1).
  $escript = Find-RealEscript
  if(-not $escript){ throw 'real erts escript.exe not found' }
  Set-MachineEnv 'YUZU_ESCRIPT' $escript
  Set-MachineEnv 'YUZU_REBAR3'  "$Rebar3Dir\rebar3"
  "escript: $escript ; rebar3: $Rebar3Dir\rebar3"
}

Step 'VS 2022 Build Tools (C++ workload)' {
  $vsw="${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
  $have = (Test-Path $vsw) -and (& $vsw -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath)
  if($have){ "already: $have" }
  else { WG -id 'Microsoft.VisualStudio.2022.BuildTools' -scope '' `
            -override '--quiet --wait --norestart --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended' }
}

Step "PostgreSQL $PostgresVersion (service :$PostgresPort, role yuzu, db yuzu_test)" {
  $major = $PostgresVersion.Split('.')[0]
  $pgbin = "C:\Program Files\PostgreSQL\$major\bin"
  if(-not (Test-Path "$pgbin\psql.exe")){
    WG -id "PostgreSQL.PostgreSQL.$major" -ver $PostgresVersion -scope '' `
       -override "--mode unattended --unattendedmodeui none --superpassword postgres --servicename postgresql-x64-$major-yuzu-ci --serverport $PostgresPort"
  }
  if(-not (Test-Path "$pgbin\psql.exe")){ throw "psql not found at $pgbin" }
  $svc = "postgresql-x64-$major-yuzu-ci"
  $deadline=(Get-Date).AddSeconds(90)
  while(((Get-Service $svc -EA SilentlyContinue).Status -ne 'Running') -and ((Get-Date) -lt $deadline)){ Start-Sleep 2 }
  $env:PGPASSWORD='postgres'
  $psql="$pgbin\psql.exe"; $H=@('-U','postgres','-h','127.0.0.1','-p',"$PostgresPort")
  if((& $psql @H -tAc 'SELECT 1 FROM pg_roles WHERE rolname=''yuzu''') -ne '1'){
    & $psql @H -c 'CREATE ROLE yuzu LOGIN SUPERUSER PASSWORD ''yuzu'''
  }
  if((& $psql @H -tAc 'SELECT 1 FROM pg_database WHERE datname=''yuzu_test''') -ne '1'){
    & $psql @H -c 'CREATE DATABASE yuzu_test OWNER yuzu'
  }
  # Tune for the shared 4-runner instance: server-test suites across concurrent
  # CCD-pinned runners exhaust the default max_connections=100, so PgPool.acquire()
  # returns an empty lease (the CH-9 [pg][chaos] flake). logging_collector=on so a
  # future exhaustion is diagnosable (off by default leaves no log files). Both are
  # postmaster params -> restart to apply. Idempotent (ALTER SYSTEM -> auto.conf).
  & $psql @H -c "ALTER SYSTEM SET max_connections = $PostgresMaxConnections"
  & $psql @H -c 'ALTER SYSTEM SET logging_collector = on'
  Restart-Service $svc -Force
  $deadline=(Get-Date).AddSeconds(90)
  while(((Get-Service $svc -EA SilentlyContinue).Status -ne 'Running') -and ((Get-Date) -lt $deadline)){ Start-Sleep 2 }
  Remove-Item Env:\PGPASSWORD
  "PG $PostgresVersion on :$PostgresPort, role yuzu, db yuzu_test ready (max_connections=$PostgresMaxConnections, logging_collector=on)"
}

Step "vcpkg @ pinned baseline $($VcpkgBaseline.Substring(0,7))" {
  $git=(Get-Command git -EA SilentlyContinue).Source
  if(-not (Test-Path "$VcpkgRoot\.git")){ & $git clone https://github.com/microsoft/vcpkg $VcpkgRoot }
  & $git -C $VcpkgRoot fetch --depth 1 origin $VcpkgBaseline
  & $git -C $VcpkgRoot checkout $VcpkgBaseline
  if(-not (Test-Path "$VcpkgRoot\vcpkg.exe")){ & "$VcpkgRoot\bootstrap-vcpkg.bat" -disableMetrics }
  "vcpkg bootstrapped at $VcpkgRoot"
}

Step 'machine env vars + PATH' {
  Set-MachineEnv 'VCPKG_ROOT'             $VcpkgRoot
  Set-MachineEnv 'CCACHE_DIR'             "$CacheRoot\ccache"
  Set-MachineEnv 'CCACHE_MAXSIZE'         '30G'
  Set-MachineEnv 'CCACHE_COMPRESS'        'true'
  Set-MachineEnv 'CCACHE_COMPRESSLEVEL'   '1'
  Set-MachineEnv 'YUZU_TEST_POSTGRES_DSN' "postgresql://yuzu:yuzu@127.0.0.1:$PostgresPort/yuzu_test"
  # Shared CI tool cache (P0): one machine-level dir so the 4 CCD-pinned runners
  # share ONE vcpkg binary cache instead of 4 per-runner copies. Each runner's
  # .env also pins RUNNER_TOOL_CACHE to this (see deploy/windows/README.md);
  # this machine env is the default for anything that reads it directly.
  New-Item -ItemType Directory -Force "$CacheRoot\ccache","$CacheRoot\tool_cache" | Out-Null
  Set-MachineEnv 'RUNNER_TOOL_CACHE'      "$CacheRoot\tool_cache"
  Add-MachinePath $VcpkgRoot
  # NOTE: deliberately NOT adding $Msys2Root\usr\bin to the machine PATH (it would
  # shadow Windows find/sort/etc.); Start-PinnedRunner.ps1 prepends it only inside
  # the runner's process env, and CI invokes bash by full path.
}

Step "emit toolchain manifest -> $ManifestPath" {
  function Ver([scriptblock]$b){ try { (& $b 2>&1 | Select-Object -First 1) -replace '\s+$','' } catch { $null } }
  $vsw="${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
  $msvc = if(Test-Path $vsw){ (& $vsw -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath | Select-Object -First 1) } else { $null }
  $major = $PostgresVersion.Split('.')[0]
  $tools = @(
    @{ name='python';     path=(Get-Command python -EA SilentlyContinue).Source; version=(Ver { python --version }); required=$true }
    @{ name='meson';      path=(Get-Command meson  -EA SilentlyContinue).Source; version=(Ver { meson --version });  required=$true }
    @{ name='ninja';      path=(Get-Command ninja  -EA SilentlyContinue).Source; version=(Ver { ninja --version });  required=$true }
    @{ name='cmake';      path=(Get-Command cmake  -EA SilentlyContinue).Source; version=(Ver { cmake --version });  required=$true }
    @{ name='git';        path=(Get-Command git    -EA SilentlyContinue).Source; version=(Ver { git --version });    required=$true }
    @{ name='ccache';     path=(Get-Command ccache -EA SilentlyContinue).Source; version=(Ver { ccache --version }); required=$true }
    @{ name='escript';    path=[Environment]::GetEnvironmentVariable('YUZU_ESCRIPT','Machine'); version=(Ver { erl -version }); required=$true }
    @{ name='rebar3';     path=[Environment]::GetEnvironmentVariable('YUZU_REBAR3','Machine');  version=$Rebar3Version; required=$true }
    @{ name='msvc';       path=$msvc; version=$null; required=$true }
    @{ name='msys2_bash'; path="$Msys2Root\usr\bin\bash.exe"; version=(Ver { & "$Msys2Root\usr\bin\bash.exe" --version }); required=$true }
    @{ name='vcpkg';      path="$VcpkgRoot\vcpkg.exe"; version=(Ver { & "$VcpkgRoot\vcpkg.exe" version }); required=$true }
    @{ name='postgres';   path="C:\Program Files\PostgreSQL\$major\bin\psql.exe"; version=$PostgresVersion; required=$true }
  )
  $manifest = [ordered]@{
    generated = (Get-Date).ToUniversalTime().ToString('o')
    host      = $env:COMPUTERNAME
    pins      = [ordered]@{ python=$PythonVersion; meson=$MesonVersion; erlang=$ErlangVersion; rebar3=$Rebar3Version; postgres=$PostgresVersion; vcpkg_baseline=$VcpkgBaseline }
    env       = [ordered]@{
      VCPKG_ROOT=$VcpkgRoot; CCACHE_DIR="$CacheRoot\ccache"; RUNNER_TOOL_CACHE="$CacheRoot\tool_cache"
      YUZU_ESCRIPT=[Environment]::GetEnvironmentVariable('YUZU_ESCRIPT','Machine')
      YUZU_REBAR3=[Environment]::GetEnvironmentVariable('YUZU_REBAR3','Machine')
      YUZU_TEST_POSTGRES_DSN="postgresql://yuzu:yuzu@127.0.0.1:$PostgresPort/yuzu_test"
    }
    tools     = $tools
  }
  New-Item -ItemType Directory -Force (Split-Path $ManifestPath) | Out-Null
  $manifest | ConvertTo-Json -Depth 6 | Set-Content -Path $ManifestPath -Encoding UTF8
  "wrote $ManifestPath ($($tools.Count) tools)"
}

Stop-Transcript | Out-Null
Write-Host "`nDone. Transcript in C:\ProvisionLogs\. Open a NEW shell so machine PATH/env take effect." -ForegroundColor Yellow
Write-Host "Verify: pwsh -File deploy\windows\Assert-Toolchain.ps1 -ManifestPath $ManifestPath" -ForegroundColor Yellow
Write-Host "Next: register the 4 CCD-pinned runners — see deploy\windows\README.md + Start-PinnedRunner.ps1." -ForegroundColor Yellow
