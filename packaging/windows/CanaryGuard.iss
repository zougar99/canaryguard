; CanaryGuard installer script for Inno Setup 6+
; Build order:  build-desktop-exe.ps1  ->  ISCC CanaryGuard.iss  ->  dist\CanaryGuard-Setup.exe
#define MyAppName "CanaryGuard"
#define MyAppVersion "1.1.0"
#define MyAppPublisher "CanaryGuard Project"
#define MyAppURL "https://github.com/zougar99/canaryguard"
#define MyAppExeName "CanaryGuard.exe"
#define MyAppDesktopExeName "CanaryGuardApp.exe"

[Setup]
AppId={{5A748073-1962-4A9D-9456-B9990486B8E8}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
DefaultDirName={localappdata}\Programs\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
OutputDir=..\..\dist
OutputBaseFilename=CanaryGuard-Setup-{#MyAppVersion}
Compression=lzma2
SolidCompression=yes
PrivilegesRequired=lowest
ArchitecturesInstallIn64BitMode=x64
SetupIconFile=..\..\static\icons\icon.ico
UninstallDisplayIcon={app}\{#MyAppDesktopExeName}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "french"; MessagesFile: "compiler:Languages\French.isl"

[Tasks]
Name: "startup"; Description: "Start CanaryGuard at logon (scheduled tasks)"; GroupDescription: "Background protection:"; Flags: checked
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Shortcuts:"

[Files]
; prebuilt executables from PyInstaller (run build-desktop-exe.ps1 first)
Source: "..\..\dist\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\dist\{#MyAppDesktopExeName}"; DestDir: "{app}"; Flags: ignoreversion
; support files the services need relative to the repo layout
Source: "..\..\canaryguard"; DestDir: "{app}\canaryguard"; Flags: recursesubdirs ignoreversion createallsubdirs
Source: "..\..\templates"; DestDir: "{app}\templates"; Flags: recursesubdirs ignoreversion
Source: "..\..\static"; DestDir: "{app}\static"; Flags: recursesubdirs ignoreversion
Source: "..\..\config.example.json"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\*.ps1"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs; Excludes: "run-setup.ps1"
Source: "..\..\deploy-pi.sh"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\docs"; DestDir: "{app}\docs"; Flags: recursesubdirs ignoreversion

[Icons]
Name: "{autoprograms}\{#MyAppName}\{#MyAppName} Desktop App"; Filename: "{app}\{#MyAppDesktopExeName}"; WorkingDir: "{app}"
Name: "{autoprograms}\{#MyAppName}\{#MyAppName} Service"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"
Name: "{autoprograms}\{#MyAppName}\README"; Filename: "{app}\README.md"
Name: "{autoprograms}\{#MyAppName}\Uninstall"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppDesktopExeName}"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppDesktopExeName}"; Description: "Launch CanaryGuard"; Flags: nowait postinstall skipifsilent
Filename: "pwsh.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\setup-background.ps1"""; Description: "Register background tasks (CanaryGuard + watchdog)"; Flags: postinstall shellexec skipifsilent unchecked; Tasks: startup

[UninstallRun]
Filename: "schtasks"; Parameters: "/delete /tn CanaryGuard /f"; Flags: runhidden; RunOnceId: "DelSvc"
Filename: "schtasks"; Parameters: "/delete /tn OpenCanaryHoneypot /f"; Flags: runhidden; RunOnceId: "DelOc"
Filename: "schtasks"; Parameters: "/delete /tn TamperGuard /f"; Flags: runhidden; RunOnceId: "DelTamper"
Filename: "schtasks"; Parameters: "/delete /tn CanaryGuardControl /f"; Flags: runhidden; RunOnceId: "DelCtl"
