; Yuzu Agent — Windows Installer (InnoSetup 6)
; Build: ISCC.exe yuzu-agent.iss
; Silent: YuzuAgentSetup-0.7.0.exe /VERYSILENT /SERVER=myserver:50051 /TOKEN=abc123

#ifndef AppVersion
  #define AppVersion "0.7.0"
#endif

; Build output directory — override with /DBuildDir=...
#ifndef BuildDir
  #define BuildDir "..\..\..\build-windows"
#endif

[Setup]
AppId={{B7F3A2E1-9C4D-4F6A-8E2B-1D3C5A7F9E0B}
AppName=Yuzu Agent
AppVersion={#AppVersion}
AppVerName=Yuzu Agent {#AppVersion}
AppPublisher=Yuzu Project
AppPublisherURL=https://github.com/YuzuProject/yuzu
DefaultDirName={autopf}\Yuzu
DefaultGroupName=Yuzu
OutputBaseFilename=YuzuAgentSetup-{#AppVersion}
OutputDir=output
Compression=lzma2/ultra64
SolidCompression=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
UninstallDisplayIcon={app}\bin\yuzu-agent.exe
SetupIconFile=yuzu.ico
WizardStyle=modern
DisableProgramGroupPage=yes
LicenseFile=..\..\..\LICENSE
CloseApplications=force
RestartApplications=no
; Upgrade: stop service before file replacement
CloseApplicationsFilter=yuzu-agent.exe

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Types]
Name: "full"; Description: "Full installation (all plugins)"
Name: "minimal"; Description: "Minimal installation (core plugins only)"
Name: "custom"; Description: "Custom installation"; Flags: iscustom

[Components]
Name: "core"; Description: "Yuzu Agent core"; Types: full minimal custom; Flags: fixed
Name: "plugins"; Description: "Agent plugins"; Types: full custom
Name: "plugins\system"; Description: "System info (OS, hardware, storage, users)"; Types: full custom
Name: "plugins\network"; Description: "Network (config, diagnostics, actions, WiFi, WoL)"; Types: full custom
Name: "plugins\security"; Description: "Security (antivirus, BitLocker, certificates, firewall)"; Types: full custom
Name: "plugins\windows"; Description: "Windows (event logs, registry, WMI, updates, SCCM)"; Types: full custom
Name: "plugins\management"; Description: "Management (processes, services, software, scripts)"; Types: full custom
Name: "plugins\advanced"; Description: "Advanced (discovery, IOC, vuln scan, quarantine)"; Types: full custom

[Files]
; --- Core agent ---
Source: "{#BuildDir}\agents\core\yuzu-agent.exe"; DestDir: "{app}\bin"; Components: core; Flags: ignoreversion
Source: "{#BuildDir}\agents\core\*.dll"; DestDir: "{app}\bin"; Components: core; Flags: ignoreversion

; --- Plugins: core (always installed) ---
Source: "{#BuildDir}\agents\plugins\status\status.dll"; DestDir: "{app}\plugins"; Components: core; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\agent_actions\agent_actions.dll"; DestDir: "{app}\plugins"; Components: core; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\agent_logging\agent_logging.dll"; DestDir: "{app}\plugins"; Components: core; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\tags\tags.dll"; DestDir: "{app}\plugins"; Components: core; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\diagnostics\diagnostics.dll"; DestDir: "{app}\plugins"; Components: core; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\content_dist\content_dist.dll"; DestDir: "{app}\plugins"; Components: core; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\device_identity\device_identity.dll"; DestDir: "{app}\plugins"; Components: core; Flags: ignoreversion

; --- Plugins: system ---
Source: "{#BuildDir}\agents\plugins\os_info\os_info.dll"; DestDir: "{app}\plugins"; Components: plugins\system; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\hardware\hardware.dll"; DestDir: "{app}\plugins"; Components: plugins\system; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\storage\storage.dll"; DestDir: "{app}\plugins"; Components: plugins\system; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\filesystem\filesystem.dll"; DestDir: "{app}\plugins"; Components: plugins\system; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\users\users.dll"; DestDir: "{app}\plugins"; Components: plugins\system; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\installed_apps\installed_apps.dll"; DestDir: "{app}\plugins"; Components: plugins\system; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\msi_packages\msi_packages.dll"; DestDir: "{app}\plugins"; Components: plugins\system; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\asset_tags\asset_tags.dll"; DestDir: "{app}\plugins"; Components: plugins\system; Flags: ignoreversion

; --- Plugins: network ---
Source: "{#BuildDir}\agents\plugins\network_config\network_config.dll"; DestDir: "{app}\plugins"; Components: plugins\network; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\network_diag\network_diag.dll"; DestDir: "{app}\plugins"; Components: plugins\network; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\network_actions\network_actions.dll"; DestDir: "{app}\plugins"; Components: plugins\network; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\netstat\netstat.dll"; DestDir: "{app}\plugins"; Components: plugins\network; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\sockwho\sockwho.dll"; DestDir: "{app}\plugins"; Components: plugins\network; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\wifi\wifi.dll"; DestDir: "{app}\plugins"; Components: plugins\network; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\wol\wol.dll"; DestDir: "{app}\plugins"; Components: plugins\network; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\http_client\http_client.dll"; DestDir: "{app}\plugins"; Components: plugins\network; Flags: ignoreversion

; --- Plugins: security ---
Source: "{#BuildDir}\agents\plugins\antivirus\antivirus.dll"; DestDir: "{app}\plugins"; Components: plugins\security; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\bitlocker\bitlocker.dll"; DestDir: "{app}\plugins"; Components: plugins\security; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\certificates\certificates.dll"; DestDir: "{app}\plugins"; Components: plugins\security; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\firewall\firewall.dll"; DestDir: "{app}\plugins"; Components: plugins\security; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\quarantine\quarantine.dll"; DestDir: "{app}\plugins"; Components: plugins\security; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\ioc\ioc.dll"; DestDir: "{app}\plugins"; Components: plugins\advanced; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\vuln_scan\vuln_scan.dll"; DestDir: "{app}\plugins"; Components: plugins\advanced; Flags: ignoreversion

; --- Plugins: windows ---
Source: "{#BuildDir}\agents\plugins\event_logs\event_logs.dll"; DestDir: "{app}\plugins"; Components: plugins\windows; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\registry\registry.dll"; DestDir: "{app}\plugins"; Components: plugins\windows; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\wmi\wmi.dll"; DestDir: "{app}\plugins"; Components: plugins\windows; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\windows_updates\windows_updates.dll"; DestDir: "{app}\plugins"; Components: plugins\windows; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\sccm\sccm.dll"; DestDir: "{app}\plugins"; Components: plugins\windows; Flags: ignoreversion

; --- Plugins: management ---
Source: "{#BuildDir}\agents\plugins\processes\processes.dll"; DestDir: "{app}\plugins"; Components: plugins\management; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\services\services.dll"; DestDir: "{app}\plugins"; Components: plugins\management; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\software_actions\software_actions.dll"; DestDir: "{app}\plugins"; Components: plugins\management; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\script_exec\script_exec.dll"; DestDir: "{app}\plugins"; Components: plugins\management; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\interaction\interaction.dll"; DestDir: "{app}\plugins"; Components: plugins\management; Flags: ignoreversion

; --- Plugins: advanced ---
Source: "{#BuildDir}\agents\plugins\discovery\discovery.dll"; DestDir: "{app}\plugins"; Components: plugins\advanced; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\tar\tar.dll"; DestDir: "{app}\plugins"; Components: plugins\advanced; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\procfetch\procfetch.dll"; DestDir: "{app}\plugins"; Components: plugins\advanced; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\chargen\chargen.dll"; DestDir: "{app}\plugins"; Components: plugins\advanced; Flags: ignoreversion
Source: "{#BuildDir}\agents\plugins\example\example.dll"; DestDir: "{app}\plugins"; Components: plugins\advanced; Flags: ignoreversion

[Dirs]
Name: "{app}\logs"; Permissions: service-full
Name: "{commonappdata}\Yuzu"; Permissions: service-full

[Run]
; Register and start the service after install
Filename: "{app}\bin\yuzu-agent.exe"; Parameters: "--install-service"; StatusMsg: "Registering Yuzu Agent service..."; Flags: runhidden waituntilterminated
Filename: "sc.exe"; Parameters: "config YuzuAgent binPath= ""{app}\bin\yuzu-agent.exe"" --server {code:GetServerAddress} --data-dir ""{commonappdata}\Yuzu"" --plugin-dir ""{app}\plugins"" --log-file ""{app}\logs\yuzu-agent.log"" {code:GetExtraArgs}"; StatusMsg: "Configuring service..."; Flags: runhidden waituntilterminated shellexec
Filename: "sc.exe"; Parameters: "start YuzuAgent"; StatusMsg: "Starting Yuzu Agent service..."; Flags: runhidden waituntilterminated shellexec; Check: ShouldStartService

[UninstallRun]
Filename: "sc.exe"; Parameters: "stop YuzuAgent"; Flags: runhidden waituntilterminated; RunOnceId: "StopService"
; Small delay to let service stop
Filename: "cmd.exe"; Parameters: "/c timeout /t 3 /nobreak >nul"; Flags: runhidden waituntilterminated; RunOnceId: "WaitStop"
Filename: "{app}\bin\yuzu-agent.exe"; Parameters: "--remove-service"; Flags: runhidden waituntilterminated; RunOnceId: "RemoveService"

[UninstallDelete]
Type: filesandordirs; Name: "{app}\logs"

[Code]
var
  ConfigPage: TInputQueryWizardPage;
  ServerAddress: string;
  EnrollmentToken: string;
  NoTLS: Boolean;
  StartService: Boolean;

function GetCommandlineParam(const ParamName: string): string;
var
  I: Integer;
  Param: string;
  Prefix: string;
begin
  Result := '';
  Prefix := '/' + ParamName + '=';
  for I := 1 to ParamCount do
  begin
    Param := ParamStr(I);
    if CompareText(Copy(Param, 1, Length(Prefix)), Prefix) = 0 then
    begin
      Result := Copy(Param, Length(Prefix) + 1, MaxInt);
      Exit;
    end;
  end;
end;

function HasCommandlineFlag(const FlagName: string): Boolean;
var
  I: Integer;
begin
  Result := False;
  for I := 1 to ParamCount do
  begin
    if CompareText(ParamStr(I), '/' + FlagName) = 0 then
    begin
      Result := True;
      Exit;
    end;
  end;
end;

procedure InitializeWizard;
begin
  ConfigPage := CreateInputQueryPage(wpSelectComponents,
    'Yuzu Server Connection',
    'Configure how this agent connects to the Yuzu server.',
    'Enter the server address and optional enrollment token.');

  ConfigPage.Add('Server address (host:port):', False);
  ConfigPage.Add('Enrollment token (optional):', False);

  { Defaults — can be overridden via /SERVER= and /TOKEN= }
  ConfigPage.Values[0] := GetCommandlineParam('SERVER');
  if ConfigPage.Values[0] = '' then
    ConfigPage.Values[0] := 'localhost:50051';

  ConfigPage.Values[1] := GetCommandlineParam('TOKEN');

  NoTLS := HasCommandlineFlag('NOTLS');
  StartService := not HasCommandlineFlag('NOSTART');
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if CurPageID = ConfigPage.ID then
  begin
    ServerAddress := ConfigPage.Values[0];
    EnrollmentToken := ConfigPage.Values[1];
    if ServerAddress = '' then
    begin
      MsgBox('Server address is required.', mbError, MB_OK);
      Result := False;
    end;
  end;
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := False;
  { Skip config page in silent mode — values come from command line }
  if (PageID = ConfigPage.ID) and WizardSilent then
    Result := True;
end;

function GetServerAddress(Param: string): string;
begin
  if WizardSilent then
  begin
    Result := GetCommandlineParam('SERVER');
    if Result = '' then
      Result := 'localhost:50051';
  end
  else
    Result := ServerAddress;
end;

function GetExtraArgs(Param: string): string;
begin
  Result := '';

  { Enrollment token }
  if WizardSilent then
    EnrollmentToken := GetCommandlineParam('TOKEN');
  if EnrollmentToken <> '' then
    Result := Result + ' --enrollment-token ' + EnrollmentToken;

  { No TLS }
  if WizardSilent then
    NoTLS := HasCommandlineFlag('NOTLS');
  if NoTLS then
    Result := Result + ' --no-tls';
end;

function ShouldStartService: Boolean;
begin
  if WizardSilent then
    Result := not HasCommandlineFlag('NOSTART')
  else
    Result := StartService;
end;

function PrepareToInstall(var NeedsRestart: Boolean): string;
var
  ResultCode: Integer;
begin
  Result := '';
  { Stop existing service before upgrade }
  Exec('sc.exe', 'stop YuzuAgent', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  { Give it a moment to stop }
  Sleep(2000);
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
  begin
    { Ask about data directory }
    if MsgBox('Remove agent data directory?' + #13#10 +
              ExpandConstant('{commonappdata}\Yuzu') + #13#10#13#10 +
              'This includes agent identity, local storage, and cached state.',
              mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
    begin
      DelTree(ExpandConstant('{commonappdata}\Yuzu'), True, True, True);
    end;
  end;
end;
