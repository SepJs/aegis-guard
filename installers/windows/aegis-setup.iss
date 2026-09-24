; ==============================================================================
;  Aegis-Guard Enterprise Security Suite - Inno Setup Script
;  Standard Windows Installer (used by VS Code, Git for Windows, etc.)
;  Compiles with: Inno Setup 6 (iscc aegis-setup.iss)
; ==============================================================================

#define MyAppName "Aegis-Guard"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "Aegis Security Research"
#define MyAppURL "https://github.com/SepJs/aegis-guard"
#define MyAppExeName "aegis-guard.exe"
#define MyServiceExeName "aegis-process-engine.exe"
#define MyObserverExeName "aegis-network-observer.exe"

[Setup]
; Basic Application Info
AppId={{D8A1C52E-9714-4632-B89B-1FE8196E7C4A}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}/issues
AppUpdatesURL={#MyAppURL}/releases
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes

; Administrative elevation required for Windows services & packet filters
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=dialog

; Output Configuration
OutputDir=..\dist
OutputBaseFilename=AegisGuard-Setup-x64
SetupIconFile=..\resources\icons\icon.ico
Compression=lzma2/ultra64
SolidCompression=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

; Modern Visual Styling
WizardStyle=modern
WizardSizePercent=115
WizardImageFile=..\resources\installer-banner.bmp
WizardSmallImageFile=..\resources\installer-small.bmp

; Uninstaller Configuration
UninstallDisplayIcon={app}\{#MyAppExeName}
UninstallDisplayName={#MyAppName} Endpoint Protection & IDS Suite
VersionInfoVersion={#MyAppVersion}
VersionInfoCompany={#MyAppPublisher}
VersionInfoDescription={#MyAppName} Installer
CloseApplications=yes
RestartApplications=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "startservice"; Description: "Register and start Aegis-Guard background security service"; GroupDescription: "System Integration:"
Name: "firewall"; Description: "Configure Windows Defender Firewall rules for IDS Packet Sniffer"; GroupDescription: "System Integration:"

[Files]
; Core Binaries
Source: "..\target\release\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion signonce; Check: FileExists('..\target\release\' + '{#MyAppExeName}')
Source: "..\target\release\{#MyServiceExeName}"; DestDir: "{app}"; Flags: ignoreversion signonce; Check: FileExists('..\target\release\' + '{#MyServiceExeName}')
Source: "..\target\release\{#MyObserverExeName}"; DestDir: "{app}"; Flags: ignoreversion signonce; Check: FileExists('..\target\release\' + '{#MyObserverExeName}')

; Resources & Configs
Source: "..\resources\*"; DestDir: "{app}\resources"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\proto\*"; DestDir: "{app}\proto"; Flags: ignoreversion recursesubdirs createallsubdirs

; Documentation
Source: "..\README.md"; DestDir: "{app}"; Flags: isreadme
Source: "..\INSTALLATION.md"; DestDir: "{app}"; Flags: ignoreversion

[Dirs]
Name: "{commonappdata}\Aegis-Guard"; Permissions: system-full administrators-full
Name: "{commonappdata}\Aegis-Guard\quarantine"; Permissions: system-full administrators-full
Name: "{commonappdata}\Aegis-Guard\sandbox"; Permissions: system-full administrators-full
Name: "{commonappdata}\Aegis-Guard\logs"; Permissions: system-full administrators-full
Name: "{commonappdata}\Aegis-Guard\canaries"; Permissions: system-full administrators-full

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\resources\icons\icon.ico"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\resources\icons\icon.ico"; Tasks: desktopicon

[Registry]
; Run on Windows Startup
Root: HKLM; Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "AegisGuard"; ValueData: """{app}\{#MyAppExeName}"" --minimized"; Flags: uninsdeletevalue

[Run]
; Windows Firewall rule registration
Filename: "netsh.exe"; Parameters: "advfirewall firewall add rule name=""Aegis-Guard IDS Observer"" dir=in action=allow program=""{app}\{#MyObserverExeName}"" enable=yes"; Flags: runhidden; Tasks: firewall

; Background Service Registration via sc.exe
Filename: "{sys}\sc.exe"; Parameters: "create AegisProcessEngine binPath= ""{app}\{#MyServiceExeName}"" start= auto DisplayName= ""Aegis-Guard Real-Time Process Monitor"""; Flags: runhidden; Tasks: startservice
Filename: "{sys}\sc.exe"; Parameters: "start AegisProcessEngine"; Flags: runhidden; Tasks: startservice

; Launch application post-install
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; Stop and remove background services cleanly
Filename: "{sys}\sc.exe"; Parameters: "stop AegisProcessEngine"; Flags: runhidden
Filename: "{sys}\sc.exe"; Parameters: "delete AegisProcessEngine"; Flags: runhidden
Filename: "netsh.exe"; Parameters: "advfirewall firewall delete rule name=""Aegis-Guard IDS Observer"""; Flags: runhidden

[UninstallDelete]
Type: filesandordirs; Name: "{app}"
Type: filesandordirs; Name: "{commonappdata}\Aegis-Guard\logs"
Type: filesandordirs; Name: "{commonappdata}\Aegis-Guard\sandbox"

[Code]
// Pre-installation check to close any running instances
function InitializeSetup(): Boolean;
var
  ResultCode: Integer;
begin
  Result := True;
  Exec('taskkill.exe', '/F /IM ' + '{#MyAppExeName}', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec('taskkill.exe', '/F /IM ' + '{#MyServiceExeName}', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec('taskkill.exe', '/F /IM ' + '{#MyObserverExeName}', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;
