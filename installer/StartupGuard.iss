; =========================================================================
; StartupGuard - Windows 10/11 Inno Setup 6.4+ 安装脚本
; 支持 x64 / arm64 与 self-contained / framework-dependent 统一构建
; =========================================================================

#ifndef ProductVersion
  #define ProductVersion "1.0.3"
#endif
#ifndef TargetArch
  #define TargetArch "x64"
#endif
#ifndef DeployMode
  #define DeployMode "self-contained"
#endif
#ifndef PublishDir
  #define PublishDir "..\artifacts\publish\win-" + TargetArch + "-" + DeployMode
#endif
#ifndef OutputDir
  #define OutputDir "..\dist"
#endif
#ifndef OutputBaseFilename
  #define OutputBaseFilename "StartupGuard-" + ProductVersion + "-" + TargetArch + "-" + DeployMode + "-Setup"
#endif

#if (TargetArch != "x64") && (TargetArch != "arm64")
  #error Unsupported TargetArch (expected x64 or arm64)
#endif
#if (DeployMode != "self-contained") && (DeployMode != "framework-dependent")
  #error Unsupported DeployMode (expected self-contained or framework-dependent)
#endif

#define MyAppId "B8E9B7D2-9F5C-4D3B-9C0A-5F1A7D2E410B"
#define MyAppName "StartupGuard"
#define MyAppDisplayName "StartupGuard (启动项与上下文菜单原生守护)"
#define MyAppPublisher "PhoebeCLS"
#define MyAppURL "https://github.com/PhoebeCLS/StartupGuard"
#define MyAppExeName "StartupGuard.App.exe"
#define MyTrayExeName "StartupGuard.TrayHost.exe"
#define MyProbeExeName "StartupGuard.ProbeHost.exe"
#define MyServiceExeName "StartupGuard.Service.exe"
#define MyServiceName "StartupGuardService"

#if TargetArch == "arm64"
  #define InnoArchAllowed "arm64"
  #define InnoArch64BitMode "arm64"
  #define DotNetDownloadUrl "https://aka.ms/dotnet/10.0/windowsdesktop-runtime-win-arm64.exe"
  #define DotNetInstallerName "windowsdesktop-runtime-10-win-arm64.exe"
#else
  #define InnoArchAllowed "x64compatible"
  #define InnoArch64BitMode "x64compatible"
  #define DotNetDownloadUrl "https://aka.ms/dotnet/10.0/windowsdesktop-runtime-win-x64.exe"
  #define DotNetInstallerName "windowsdesktop-runtime-10-win-x64.exe"
#endif

[Setup]
AppId={{{#MyAppId}}
AppName={#MyAppName}
AppVersion={#ProductVersion}
AppVerName={#MyAppName} v{#ProductVersion}
VersionInfoVersion={#ProductVersion}.0
VersionInfoProductVersion={#ProductVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}/issues
AppUpdatesURL={#MyAppURL}/releases
DefaultDirName={code:GetDefaultInstallDir}
DefaultGroupName={#MyAppName}
UsePreviousAppDir=yes
UsePreviousTasks=yes
DisableDirPage=auto
DisableProgramGroupPage=yes
DisableWelcomePage=no
DisableReadyPage=no
ShowLanguageDialog=auto
ArchitecturesAllowed={#InnoArchAllowed}
ArchitecturesInstallIn64BitMode={#InnoArch64BitMode}
OutputDir={#OutputDir}
OutputBaseFilename={#OutputBaseFilename}
SetupIconFile=app.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
UninstallDisplayName={#MyAppDisplayName}
Compression=lzma2/fast
SolidCompression=yes
LZMAUseSeparateProcess=yes
WizardStyle=modern dynamic
PrivilegesRequired=admin
CloseApplications=no
RestartApplications=no
MinVersion=10.0.19041

[Languages]
Name: "chinesesimplified"; MessagesFile: "Languages\ChineseSimplified.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "创建桌面快捷方式"; GroupDescription: "附加任务："
Name: "startmenu"; Description: "创建开始菜单快捷方式"; GroupDescription: "附加任务："

[Dirs]
Name: "{commonappdata}\{#MyAppName}"
Name: "{commonappdata}\{#MyAppName}\data"
Name: "{commonappdata}\{#MyAppName}\logs"

[Files]
Source: "{#PublishDir}\*"; Excludes: "*.pdb"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "app.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "app.ico"; DestDir: "{app}\Assets"; Flags: ignoreversion

[Icons]
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\Assets\app.ico"; Tasks: desktopicon
Name: "{autoprograms}\{#MyAppName}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\Assets\app.ico"; Tasks: startmenu
Name: "{autoprograms}\{#MyAppName}\卸载 {#MyAppName}"; Filename: "{uninstallexe}"; IconFilename: "{app}\Assets\app.ico"; Tasks: startmenu

[Registry]
; 清理旧版 32 位托盘自启残留并写入 64 位 HKLM Run
Root: HKLM32; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: none; ValueName: "StartupGuardTray"; Flags: deletevalue
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "StartupGuardTray"; ValueData: """{app}\{#MyTrayExeName}"""; Flags: uninsdeletevalue
Root: HKLM; Subkey: "Software\{#MyAppName}"; ValueType: string; ValueName: "InstallDir"; ValueData: "{app}"; Flags: uninsdeletevalue uninsdeletekeyifempty

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "立即启动 StartupGuard"; Flags: nowait postinstall skipifsilent runasoriginaluser

[Code]
var
  UninstDeleteUserData: Boolean;
  ProcessesStopped: Boolean;
#if DeployMode == "framework-dependent"
  DotNetDownloadPage: TDownloadWizardPage;
#endif

function RunHidden(const FileName, Params: string): Integer;
var
  ResultCode: Integer;
begin
  if Exec(FileName, Params, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    Result := ResultCode
  else
    Result := -1;
end;

function GetPreviousInstalledDir: string;
var
  Dir: string;
begin
  Result := '';
  if RegQueryStringValue(HKLM, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{' + '{#MyAppId}' + '}_is1', 'InstallLocation', Dir) and (Dir <> '') then
  begin
    Result := RemoveBackslashUnlessRoot(Dir);
    exit;
  end;
  if RegQueryStringValue(HKLM, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{' + '{#MyAppId}' + '}}_is1', 'InstallLocation', Dir) and (Dir <> '') then
  begin
    Result := RemoveBackslashUnlessRoot(Dir);
    exit;
  end;
  if RegQueryStringValue(HKLM, 'SOFTWARE\{#MyAppName}', 'InstallDir', Dir) and (Dir <> '') then
  begin
    Result := RemoveBackslashUnlessRoot(Dir);
    exit;
  end;
end;

function GetDefaultInstallDir(Param: string): string;
var
  PrevDir: string;
begin
  PrevDir := GetPreviousInstalledDir;
  if PrevDir <> '' then
    Result := PrevDir
  else
    Result := ExpandConstant('{autopf}\{#MyAppName}');
end;

function GetPreviousInstalledVersion: string;
var
  Ver: string;
begin
  Result := '';
  if RegQueryStringValue(HKLM, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{' + '{#MyAppId}' + '}_is1', 'DisplayVersion', Ver) and (Ver <> '') then
  begin
    Result := Ver;
    exit;
  end;
  if RegQueryStringValue(HKLM, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{' + '{#MyAppId}' + '}}_is1', 'DisplayVersion', Ver) and (Ver <> '') then
  begin
    Result := Ver;
    exit;
  end;
end;

procedure StopRunningProcessesAndService(SleepAfterMs: Integer);
var
  ScExe, KillExe, LogmanExe: string;
  ScResult: Integer;
begin
  ScExe := ExpandConstant('{sys}\sc.exe');
  KillExe := ExpandConstant('{sys}\taskkill.exe');
  LogmanExe := ExpandConstant('{sys}\logman.exe');

  ScResult := RunHidden(ScExe, 'stop {#MyServiceName}');
  RunHidden(KillExe, '/F /T /IM {#MyTrayExeName} /IM {#MyAppExeName} /IM {#MyProbeExeName} /IM {#MyServiceExeName}');
  RunHidden(LogmanExe, 'stop StartupGuard_KernelRegistry_Trace -ets');
  if (ScResult = 0) and (SleepAfterMs > 0) then
    Sleep(SleepAfterMs);
end;

procedure CleanWildcardFiles(const DirPath, Pattern: string);
var
  FindRec: TFindRec;
begin
  if FindFirst(AddBackslash(DirPath) + Pattern, FindRec) then
  begin
    try
      repeat
        if (FindRec.Attributes and FILE_ATTRIBUTE_DIRECTORY) = 0 then
          DeleteFile(AddBackslash(DirPath) + FindRec.Name);
      until not FindNext(FindRec);
    finally
      FindClose(FindRec);
    end;
  end;
end;

procedure RemoveDirectoryCompletely(const DirPath: string);
var
  CmdExe: string;
begin
  if not DirExists(DirPath) then
    exit;

  RunHidden(ExpandConstant('{sys}\attrib.exe'), '-r -s -h "' + DirPath + '\*" /s /d');
  DelTree(DirPath, True, True, True);
  if DirExists(DirPath) then
  begin
    CmdExe := ExpandConstant('{cmd}');
    RunHidden(CmdExe, '/c rmdir /s /q "' + DirPath + '"');
  end;
end;

#if DeployMode == "framework-dependent"
function HasDotNet10DesktopInDir(const BaseDir: string): Boolean;
var
  FindRec: TFindRec;
begin
  Result := False;
  if not DirExists(BaseDir) then
    exit;

  if FindFirst(AddBackslash(BaseDir) + '10.*', FindRec) then
  begin
    try
      repeat
        if (FindRec.Attributes and FILE_ATTRIBUTE_DIRECTORY) <> 0 then
        begin
          Result := True;
          exit;
        end;
      until not FindNext(FindRec);
    finally
      FindClose(FindRec);
    end;
  end;
end;

function IsDotNet10DesktopInstalled: Boolean;
var
  RegKey, TmpListPath, CmdArgs: string;
  ValueNames: TArrayOfString;
  Lines: TArrayOfString;
  I: Integer;
begin
  Result := HasDotNet10DesktopInDir(ExpandConstant('{commonpf}\dotnet\shared\Microsoft.WindowsDesktop.App'));
  if Result then
    exit;

  RegKey := 'SOFTWARE\dotnet\Setup\InstalledVersions\{#TargetArch}\sharedfx\Microsoft.WindowsDesktop.App';
  if RegGetValueNames(HKLM, RegKey, ValueNames) then
  begin
    for I := 0 to GetArrayLength(ValueNames) - 1 do
    begin
      if Copy(ValueNames[I], 1, 3) = '10.' then
      begin
        Result := True;
        exit;
      end;
    end;
  end;

  TmpListPath := ExpandConstant('{tmp}\dotnet_runtimes.txt');
  DeleteFile(TmpListPath);
  CmdArgs := '/c dotnet --list-runtimes > "' + TmpListPath + '" 2>nul';
  if (RunHidden(ExpandConstant('{cmd}'), CmdArgs) = 0) and LoadStringsFromFile(TmpListPath, Lines) then
  begin
    for I := 0 to GetArrayLength(Lines) - 1 do
    begin
      if Pos('Microsoft.WindowsDesktop.App 10.', Lines[I]) > 0 then
      begin
        Result := True;
        DeleteFile(TmpListPath);
        exit;
      end;
    end;
  end;
  DeleteFile(TmpListPath);
end;

function OnDotNetDownloadProgress(const Url, FileName: string; const Progress, ProgressMax: Int64): Boolean;
begin
  Result := True;
end;

function EnsureDotNet10DesktopRuntime: string;
var
  InstallerPath, InstallArgs: string;
  ExitCode: Integer;
begin
  Result := '';
  if IsDotNet10DesktopInstalled then
    exit;

  InstallerPath := ExpandConstant('{tmp}\{#DotNetInstallerName}');
  try
    if WizardSilent then
    begin
      DownloadTemporaryFile('{#DotNetDownloadUrl}', '{#DotNetInstallerName}', '', @OnDotNetDownloadProgress);
    end
    else
    begin
      DotNetDownloadPage.Clear;
      DotNetDownloadPage.Add('{#DotNetDownloadUrl}', '{#DotNetInstallerName}', '');
      DotNetDownloadPage.Show;
      try
        DotNetDownloadPage.Download;
      finally
        DotNetDownloadPage.Hide;
      end;
    end;
  except
    if DotNetDownloadPage.AbortedByUser then
      Result := '用户取消了 .NET 10 桌面运行时下载。'
    else
      Result := '无法下载 .NET 10 桌面运行时：' + GetExceptionMessage + #13#10 + '请检查网络连接后重试，或改用 self-contained 安装包。';
    exit;
  end;

  if not FileExists(InstallerPath) then
  begin
    Result := '未找到已下载的 .NET 10 桌面运行时安装程序，请改用 self-contained 安装包。';
    exit;
  end;

  if WizardSilent then
    InstallArgs := '/install /quiet /norestart'
  else
    InstallArgs := '/install /passive /norestart';

  if not Exec(InstallerPath, InstallArgs, '', SW_SHOW, ewWaitUntilTerminated, ExitCode) then
  begin
    Result := '无法启动 .NET 10 桌面运行时安装程序。';
    exit;
  end;

  if not IsDotNet10DesktopInstalled then
    Result := '.NET 10 桌面运行时安装未完成 (ExitCode=' + IntToStr(ExitCode) + ')，请手动安装后重试或改用 self-contained 版本。';
end;
#endif

procedure InitializeWizard;
var
  PrevVer: string;
begin
#if DeployMode == "framework-dependent"
  DotNetDownloadPage := CreateDownloadPage(
    '.NET 10 桌面运行时',
    '正在准备下载并安装 .NET 10 Desktop Runtime ({#TargetArch})...',
    @OnDotNetDownloadProgress);
  DotNetDownloadPage.ShowBaseNameInsteadOfUrl := True;
#endif
  PrevVer := GetPreviousInstalledVersion;
  if PrevVer <> '' then
  begin
    WizardForm.WelcomeLabel2.Caption :=
      '检测到当前已安装 StartupGuard v' + PrevVer + '。' + #13#10 + #13#10 +
      '点击“下一步”将自动覆盖升级程序与后台服务至 v{#ProductVersion}，并完整保留您原有的拦截规则、审计日志与个人设置。';
  end;
end;

procedure CleanupLegacyUninstallArtifacts(const AppDir: string);
var
  LegacyDoubleBraceKey: string;
begin
  // 1.0.2 安装脚本误写了额外右花括号，导致卸载注册表键为 {GUID}}_is1；升级前先清除以免产生双条卸载记录与 unins001 残留
  LegacyDoubleBraceKey := 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{' + '{#MyAppId}' + '}}_is1';
  if RegKeyExists(HKLM64, LegacyDoubleBraceKey) or RegKeyExists(HKLM32, LegacyDoubleBraceKey) then
  begin
    CleanWildcardFiles(AppDir, 'unins00*.exe');
    CleanWildcardFiles(AppDir, 'unins00*.dat');
    CleanWildcardFiles(AppDir, 'unins00*.msg');
    RegDeleteKeyIncludingSubkeys(HKLM64, LegacyDoubleBraceKey);
    RegDeleteKeyIncludingSubkeys(HKLM32, LegacyDoubleBraceKey);
  end;

  if FileExists(AppDir + '\Uninstall.exe') then
    DeleteFile(AppDir + '\Uninstall.exe');
  RegDeleteKeyIncludingSubkeys(HKLM64, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\StartupGuard');
  RegDeleteKeyIncludingSubkeys(HKLM32, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\StartupGuard');
end;

procedure CleanupSatelliteCultureDirs(const AppDir: string);
var
  Cultures: TArrayOfString;
  I: Integer;
  TargetDir: string;
begin
  SetArrayLength(Cultures, 13);
  Cultures[0] := 'cs';
  Cultures[1] := 'de';
  Cultures[2] := 'es';
  Cultures[3] := 'fr';
  Cultures[4] := 'it';
  Cultures[5] := 'ja';
  Cultures[6] := 'ko';
  Cultures[7] := 'pl';
  Cultures[8] := 'pt-BR';
  Cultures[9] := 'ru';
  Cultures[10] := 'tr';
  Cultures[11] := 'zh-Hans';
  Cultures[12] := 'zh-Hant';

  for I := 0 to GetArrayLength(Cultures) - 1 do
  begin
    TargetDir := AddBackslash(AppDir) + Cultures[I];
    if DirExists(TargetDir) then
      DelTree(TargetDir, True, True, True);
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): string;
begin
  Result := '';
#if DeployMode == "framework-dependent"
  Result := EnsureDotNet10DesktopRuntime;
  if Result <> '' then
    exit;
#endif
  StopRunningProcessesAndService(250);
  ProcessesStopped := True;
  CleanupLegacyUninstallArtifacts(ExpandConstant('{app}'));
end;

procedure CleanupBeforeFileExtraction;
var
  AppDir: string;
begin
  AppDir := ExpandConstant('{app}');
  if not ProcessesStopped then
  begin
    StopRunningProcessesAndService(250);
    ProcessesStopped := True;
  end;

  if not DirExists(AppDir) then
    exit;

  // 跨部署模式或自旧版升级时清理遗留运行库、附属语言目录与旧卸载程序，防止残留与双条卸载记录
  DeleteFile(AppDir + '\{#MyServiceExeName}');
  DeleteFile(AppDir + '\{#MyTrayExeName}');
  DeleteFile(AppDir + '\{#MyProbeExeName}');
  DeleteFile(AppDir + '\{#MyAppExeName}');
  DeleteFile(AppDir + '\createdump.exe');
  CleanWildcardFiles(AppDir, '*.dll');
  CleanWildcardFiles(AppDir, '*.json');
  CleanWildcardFiles(AppDir, '*.xml');
  CleanWildcardFiles(AppDir, '*.deps.json');
  CleanWildcardFiles(AppDir, '*.runtimeconfig.json');
  if DirExists(AppDir + '\runtimes') then
    DelTree(AppDir + '\runtimes', True, True, True);
  CleanupSatelliteCultureDirs(AppDir);
  CleanupLegacyUninstallArtifacts(AppDir);
end;

procedure ConfigureSharedDataPermissionsAndService;
var
  AppDataRoot, ScExe, ServiceExePath: string;
begin
  AppDataRoot := ExpandConstant('{commonappdata}\{#MyAppName}');
  RunHidden(ExpandConstant('{sys}\icacls.exe'), '"' + AppDataRoot + '" /grant *S-1-5-32-545:(OI)(CI)F *S-1-1-0:(OI)(CI)F /T /Q /C');

  ScExe := ExpandConstant('{sys}\sc.exe');
  ServiceExePath := ExpandConstant('{app}\{#MyServiceExeName}');

  if RunHidden(ScExe, 'query {#MyServiceName}') <> 0 then
    RunHidden(ScExe, 'create {#MyServiceName} binPath= "\"' + ServiceExePath + '\" --service" start= auto DisplayName= "StartupGuard Core Monitoring Service"')
  else
    RunHidden(ScExe, 'config {#MyServiceName} binPath= "\"' + ServiceExePath + '\" --service" start= auto DisplayName= "StartupGuard Core Monitoring Service"');
  RunHidden(ScExe, 'description {#MyServiceName} "Windows 11 原生底层启动项与上下文菜单安全守护服务 (StartupGuard)"');
  RunHidden(ScExe, 'start {#MyServiceName}');
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  case CurStep of
    ssInstall:
      CleanupBeforeFileExtraction;
    ssPostInstall:
      ConfigureSharedDataPermissionsAndService;
  end;
end;

procedure CleanAllAutoStartRegistryKeys;
begin
  RegDeleteValue(HKLM64, 'Software\Microsoft\Windows\CurrentVersion\Run', 'StartupGuardTray');
  RegDeleteValue(HKCU64, 'Software\Microsoft\Windows\CurrentVersion\Run', 'StartupGuardTray');
  RegDeleteValue(HKLM64, 'Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run', 'StartupGuardTray');
  RegDeleteValue(HKCU64, 'Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run', 'StartupGuardTray');

  RegDeleteValue(HKLM32, 'Software\Microsoft\Windows\CurrentVersion\Run', 'StartupGuardTray');
  RegDeleteValue(HKCU32, 'Software\Microsoft\Windows\CurrentVersion\Run', 'StartupGuardTray');
  RegDeleteValue(HKLM32, 'Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32', 'StartupGuardTray');
  RegDeleteValue(HKCU32, 'Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32', 'StartupGuardTray');
end;

procedure CleanAllShortcuts;
var
  Dirs: TArrayOfString;
  I: Integer;
begin
  DeleteFile(ExpandConstant('{commondesktop}\StartupGuard.lnk'));
  DeleteFile(ExpandConstant('{userdesktop}\StartupGuard.lnk'));

  SetArrayLength(Dirs, 2);
  Dirs[0] := ExpandConstant('{commonprograms}\StartupGuard');
  Dirs[1] := ExpandConstant('{userprograms}\StartupGuard');
  for I := 0 to GetArrayLength(Dirs) - 1 do
  begin
    if DirExists(Dirs[I]) then
      DelTree(Dirs[I], True, True, True);
  end;
end;

function InitializeUninstall: Boolean;
begin
  UninstDeleteUserData := Lowercase(ExpandConstant('{param:DELETEUSERDATA|1}')) <> '0';
  Result := True;
end;

function PromptUninstallUserDataOption: Boolean;
var
  Form: TSetupForm;
  InfoLabel, HintLabel: TNewStaticText;
  DeleteChk: TNewCheckBox;
  OkButton: TNewButton;
begin
  Result := UninstDeleteUserData;
  Form := CreateCustomForm(ScaleX(420), ScaleY(172), False, True);
  try
    Form.Caption := '卸载个人数据选项';
    Form.BorderIcons := [];

    InfoLabel := TNewStaticText.Create(Form);
    InfoLabel.Parent := Form;
    InfoLabel.Left := ScaleX(18);
    InfoLabel.Top := ScaleY(16);
    InfoLabel.Width := Form.ClientWidth - ScaleX(36);
    InfoLabel.AutoSize := False;
    InfoLabel.WordWrap := True;
    InfoLabel.Height := ScaleY(36);
    InfoLabel.Caption := '将移除 StartupGuard 主程序、后台守护服务、开机自启项与快捷方式。';

    DeleteChk := TNewCheckBox.Create(Form);
    DeleteChk.Parent := Form;
    DeleteChk.Left := ScaleX(18);
    DeleteChk.Top := ScaleY(60);
    DeleteChk.Width := Form.ClientWidth - ScaleX(36);
    DeleteChk.Height := ScaleY(22);
    DeleteChk.Caption := '同时删除全部个人数据';
    DeleteChk.Checked := Result;

    HintLabel := TNewStaticText.Create(Form);
    HintLabel.Parent := Form;
    HintLabel.Left := ScaleX(18);
    HintLabel.Top := ScaleY(90);
    HintLabel.Width := Form.ClientWidth - ScaleX(36);
    HintLabel.AutoSize := False;
    HintLabel.WordWrap := True;
    HintLabel.Height := ScaleY(34);
    HintLabel.Caption := '提示：不会还原您已优化的系统自启与右键菜单状态。';

    OkButton := TNewButton.Create(Form);
    OkButton.Parent := Form;
    OkButton.Caption := '继续卸载';
    OkButton.Width := ScaleX(96);
    OkButton.Height := ScaleY(26);
    OkButton.Left := Form.ClientWidth - OkButton.Width - ScaleX(18);
    OkButton.Top := Form.ClientHeight - OkButton.Height - ScaleY(14);
    OkButton.ModalResult := mrOk;
    OkButton.Default := True;

    Form.ActiveControl := OkButton;
    Form.ShowModal;
    Result := DeleteChk.Checked;
  finally
    Form.Free;
  end;
end;

procedure CleanTempFallbackFiles(const TempDir: string);
var
  BaseDir: string;
begin
  if TempDir = '' then
    Exit;
  BaseDir := AddBackslash(TempDir);
  DeleteFile(BaseDir + 'startupguard_rules.db');
  DeleteFile(BaseDir + 'startupguard_rules.db-wal');
  DeleteFile(BaseDir + 'startupguard_rules.db-shm');
  DeleteFile(BaseDir + 'startupguard_rules.bin');
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  ServiceExe, AppDir, ScExe: string;
  DummyCode: Integer;
begin
  case CurUninstallStep of
    usUninstall:
      begin
        if not UninstallSilent then
          UninstDeleteUserData := PromptUninstallUserDataOption;

        SetCurrentDir(ExpandConstant('{tmp}'));
        StopRunningProcessesAndService(800);

        ServiceExe := ExpandConstant('{app}\{#MyServiceExeName}');
        if UninstDeleteUserData and FileExists(ServiceExe) then
          RunHidden(ServiceExe, '--uninstall-reset');

        ScExe := ExpandConstant('{sys}\sc.exe');
        RunHidden(ScExe, 'delete {#MyServiceName}');
        CleanAllAutoStartRegistryKeys;
        RegDeleteKeyIncludingSubkeys(HKLM64, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{' + '{#MyAppId}' + '}}_is1');
        RegDeleteKeyIncludingSubkeys(HKLM32, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{' + '{#MyAppId}' + '}}_is1');
        RegDeleteKeyIncludingSubkeys(HKLM64, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\StartupGuard');
        RegDeleteKeyIncludingSubkeys(HKLM32, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\StartupGuard');
      end;

    usPostUninstall:
      begin
        CleanAllShortcuts;
        CleanTempFallbackFiles(GetEnv('TEMP'));
        CleanTempFallbackFiles(GetEnv('TMP'));
        CleanTempFallbackFiles(ExpandConstant('{localappdata}\Temp'));
        AppDir := ExpandConstant('{app}');
        CleanWildcardFiles(AppDir, '*.*');
        DelTree(AppDir, True, True, True);
        if DirExists(AppDir) then
          Exec(ExpandConstant('{cmd}'), '/c ping -n 2 127.0.0.1 >nul & rmdir /s /q "' + AppDir + '"', '', SW_HIDE, ewNoWait, DummyCode);

        if UninstDeleteUserData then
        begin
          RegDeleteKeyIncludingSubkeys(HKCU64, 'Software\{#MyAppName}');
          RegDeleteKeyIncludingSubkeys(HKLM64, 'Software\{#MyAppName}');
          RegDeleteKeyIncludingSubkeys(HKCU32, 'Software\{#MyAppName}');
          RegDeleteKeyIncludingSubkeys(HKLM32, 'Software\{#MyAppName}');

          RemoveDirectoryCompletely(ExpandConstant('{localappdata}\{#MyAppName}'));
          RemoveDirectoryCompletely(ExpandConstant('{userappdata}\{#MyAppName}'));
          RemoveDirectoryCompletely(ExpandConstant('{commonappdata}\{#MyAppName}'));
        end;
      end;
  end;
end;
