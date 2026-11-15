; =========================================================================
; StartupGuard - Windows 10/11 x64 NSIS 安装程序脚本
; 支持服务注册 (sc create)、托盘自启 (Run 键)、桌面快捷方式与干净卸载
; =========================================================================

Unicode true
!include "MUI2.nsh"
!include "FileFunc.nsh"

; 基本元数据定义
!define PRODUCT_NAME "StartupGuard"
!ifndef PRODUCT_VERSION
  !define PRODUCT_VERSION "1.0.0"
!endif
!define PRODUCT_PUBLISHER "StartupGuard Security Team"
!define PRODUCT_WEB_SITE "https://github.com/PhoebeCLS/StartupGuard"
!define PRODUCT_UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}"
!define PRODUCT_DIR_REGKEY "Software\${PRODUCT_NAME}"

Name "${PRODUCT_NAME} v${PRODUCT_VERSION}"
OutFile "..\dist\StartupGuard-Setup-v${PRODUCT_VERSION}-win-x64.exe"
InstallDir "$PROGRAMFILES64\StartupGuard"
InstallDirRegKey HKLM "${PRODUCT_DIR_REGKEY}" "InstallDir"
RequestExecutionLevel admin

; 界面视觉配置
!define MUI_ABORTWARNING
!define MUI_ICON "app.ico"
!define MUI_UNICON "app.ico"

; 安装页面流
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_INSTFILES

; 安装完成页可选启动项 (单一入口 StartupGuard.App.exe，自动带起托盘与核心服务)
!define MUI_FINISHPAGE_RUN "$INSTDIR\StartupGuard.App.exe"
!define MUI_FINISHPAGE_RUN_TEXT "立即启动 StartupGuard"
!insertmacro MUI_PAGE_FINISH

; 卸载页面流
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

; 多语言设置 (简体中文)
!insertmacro MUI_LANGUAGE "SimpChinese"

; =========================================================================
; 安装区段 (支持自定义是否创建桌面与开始菜单快捷方式)
; =========================================================================
Section "StartupGuard 核心程序与守护服务 (必需)" SEC_CORE
    SectionIn RO
    SetRegView 64
    SetOutPath "$INSTDIR"
    SetOverwrite on

    ; 覆盖安装/升级前先停止既有后台服务与驻留进程，防止旧服务继续占用文件或沿用旧二进制
    DetailPrint "正在检查并停止运行中的 StartupGuard 服务与进程..."
    ExecWait 'sc.exe stop StartupGuardService'
    ExecWait 'taskkill.exe /F /IM StartupGuard.TrayHost.exe'
    ExecWait 'taskkill.exe /F /IM StartupGuard.App.exe'
    ExecWait 'taskkill.exe /F /IM StartupGuard.ProbeHost.exe'
    ExecWait 'taskkill.exe /F /IM StartupGuard.Service.exe'
    Sleep 300

    ; 释放全链路 4 大核心 Win-x64 可执行程序与自包含 (Self-Contained) 完整运行库
    File "..\artifacts\publish\win-x64\StartupGuard.Service.exe"
    File "..\artifacts\publish\win-x64\StartupGuard.TrayHost.exe"
    File "..\artifacts\publish\win-x64\StartupGuard.ProbeHost.exe"
    File "..\artifacts\publish\win-x64\StartupGuard.App.exe"
    File /nonfatal "..\artifacts\publish\win-x64\*.dll"
    File /nonfatal "..\artifacts\publish\win-x64\*.json"

    ; 释放多尺寸 Fluent 高清图标
    CreateDirectory "$INSTDIR\Assets"
    File /oname=$INSTDIR\Assets\app.ico "app.ico"
    File "app.ico"

    ; 创建 ProgramData 配置与 MMF 存储根目录，并授权所有用户读写权限以支持普通用户运行 UI
    SetShellVarContext all
    CreateDirectory "$APPDATA\StartupGuard"
    CreateDirectory "$APPDATA\StartupGuard\data"
    CreateDirectory "$APPDATA\StartupGuard\logs"
    ExecWait 'icacls "$APPDATA\StartupGuard" /grant *S-1-5-32-545:(OI)(CI)F /T'
    ExecWait 'icacls "$APPDATA\StartupGuard" /grant Users:(OI)(CI)F /T'
    ExecWait 'icacls "$APPDATA\StartupGuard" /grant *S-1-1-0:(OI)(CI)F /T'
    SetShellVarContext current

    ; 1. 注册核心守护 Windows 服务 (LocalSystem 权限，开机自启)
    DetailPrint "正在配置 StartupGuard 后台核心监控服务..."
    ExecWait 'sc.exe create StartupGuardService binPath= "\"$INSTDIR\StartupGuard.Service.exe\" --service" start= auto DisplayName= "StartupGuard Core Monitoring Service"'
    ExecWait 'sc.exe config StartupGuardService binPath= "\"$INSTDIR\StartupGuard.Service.exe\" --service" start= auto DisplayName= "StartupGuard Core Monitoring Service"'
    ExecWait 'sc.exe description StartupGuardService "Windows 11 原生底层启动项与上下文菜单安全守护服务 (StartupGuard)"'
    ExecWait 'sc.exe start StartupGuardService'

    ; 2. 配置交互式托盘宿主开机自启 (统一写入 64 位 HKLM Run，清理历史 32 位残留)
    DetailPrint "正在配置桌面托盘自启动项..."
    SetRegView 32
    DeleteRegValue HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "StartupGuardTray"
    SetRegView 64
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "StartupGuardTray" '"$INSTDIR\StartupGuard.TrayHost.exe"'

    ; 3. 写入卸载程序与控制面板程序列表注册表
    WriteUninstaller "$INSTDIR\Uninstall.exe"
    WriteRegStr HKLM "${PRODUCT_DIR_REGKEY}" "InstallDir" "$INSTDIR"
    WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "DisplayName" "StartupGuard (启动项与上下文菜单原生守护)"
    WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "UninstallString" '"$INSTDIR\Uninstall.exe"'
    WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "DisplayIcon" "$INSTDIR\StartupGuard.App.exe"
    WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "DisplayVersion" "${PRODUCT_VERSION}"
    WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "Publisher" "${PRODUCT_PUBLISHER}"
    WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "URLInfoAbout" "${PRODUCT_WEB_SITE}"

    ; 计算安装占用空间
    ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
    IntFmt $0 "0x%08X" $0
    WriteRegDWORD HKLM "${PRODUCT_UNINST_KEY}" "EstimatedSize" "$0"
SectionEnd

Section "创建桌面快捷方式" SEC_DESKTOP
    DetailPrint "正在创建桌面快捷方式..."
    CreateShortcut "$DESKTOP\StartupGuard.lnk" "$INSTDIR\StartupGuard.App.exe" "" "$INSTDIR\Assets\app.ico" 0
SectionEnd

Section "创建开始菜单快捷方式" SEC_STARTMENU
    DetailPrint "正在创建开始菜单快捷方式..."
    CreateDirectory "$SMPROGRAMS\StartupGuard"
    CreateShortcut "$SMPROGRAMS\StartupGuard\StartupGuard.lnk" "$INSTDIR\StartupGuard.App.exe" "" "$INSTDIR\Assets\app.ico" 0
    CreateShortcut "$SMPROGRAMS\StartupGuard\卸载 StartupGuard.lnk" "$INSTDIR\Uninstall.exe"
SectionEnd

; 组件描述文案
!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
    !insertmacro MUI_DESCRIPTION_TEXT ${SEC_CORE} "安装 StartupGuard 主程序、托盘守护进程与底层系统监控服务（必选）。"
    !insertmacro MUI_DESCRIPTION_TEXT ${SEC_DESKTOP} "在桌面生成 StartupGuard 启动快捷方式，取消勾选可不创建。"
    !insertmacro MUI_DESCRIPTION_TEXT ${SEC_STARTMENU} "在开始菜单程序列表中创建 StartupGuard 文件夹及快捷方式。"
!insertmacro MUI_FUNCTION_DESCRIPTION_END

; =========================================================================
; 卸载区段
; =========================================================================
Section "Uninstall"
    SetRegView 64
    ; 先将工作目录切换到系统临时目录，释放对安装目录 $INSTDIR 的目录句柄占用
    SetOutPath "$TEMP"
    DetailPrint "正在停止并清理 StartupGuard 服务与进程..."

    ; 1. 停止后台服务与运行中的交互式进程（解除对 rules.db 与安装目录的占用）
    ExecWait 'sc.exe stop StartupGuardService'
    ExecWait 'taskkill.exe /F /IM StartupGuard.TrayHost.exe'
    ExecWait 'taskkill.exe /F /IM StartupGuard.App.exe'
    ExecWait 'taskkill.exe /F /IM StartupGuard.ProbeHost.exe'
    ExecWait 'taskkill.exe /F /IM StartupGuard.Service.exe'
    Sleep 300

    ; 2. 清理 StartupGuard 自身配置与缓存（保留用户已做的右键菜单与自启项优化状态）
    DetailPrint "正在清理 StartupGuard 数据、设置与缓存残留..."
    ExecWait '"$INSTDIR\StartupGuard.Service.exe" --uninstall-reset'

    ; 3. 删除后台服务
    ExecWait 'sc.exe delete StartupGuardService'

    ; 4. 清理开机自启注册表（同时清理 64 位与 32 位视图下的 StartupGuardTray）
    SetRegView 64
    DeleteRegValue HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "StartupGuardTray"
    SetRegView 32
    DeleteRegValue HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "StartupGuardTray"
    SetRegView 64

    ; 5. 清理桌面与开始菜单快捷方式
    SetShellVarContext all
    Delete "$DESKTOP\StartupGuard.lnk"
    Delete "$SMPROGRAMS\StartupGuard\StartupGuard.lnk"
    Delete "$SMPROGRAMS\StartupGuard\StartupGuard 规则管理面板.lnk"
    Delete "$SMPROGRAMS\StartupGuard\StartupGuard 托盘守护.lnk"
    Delete "$SMPROGRAMS\StartupGuard\卸载 StartupGuard.lnk"
    RMDir /r "$SMPROGRAMS\StartupGuard"
    SetShellVarContext current
    Delete "$DESKTOP\StartupGuard.lnk"
    RMDir /r "$SMPROGRAMS\StartupGuard"

    ; 6. 清理安装目录与文件，确保安装根目录彻底移除
    Delete "$INSTDIR\StartupGuard.Service.exe"
    Delete "$INSTDIR\StartupGuard.TrayHost.exe"
    Delete "$INSTDIR\StartupGuard.ProbeHost.exe"
    Delete "$INSTDIR\StartupGuard.App.exe"
    Delete "$INSTDIR\*.dll"
    Delete "$INSTDIR\*.json"
    Delete "$INSTDIR\*.pdb"
    Delete "$INSTDIR\Assets\app.ico"
    Delete "$INSTDIR\app.ico"
    RMDir /r "$INSTDIR\Assets"
    Delete "$INSTDIR\Uninstall.exe"
    RMDir /r "$INSTDIR"
    RMDir /REBOOTOK "$INSTDIR"

    ; 若 Uninstall.exe 自身进程尚未完全释放根目录句柄，退出 1 秒后无感移除空安装目录
    ExpandEnvStrings $0 "%COMSPEC%"
    StrCmp $0 "" 0 +2
    StrCpy $0 "cmd.exe"
    ExecShell "" "$0" '/c ping -n 2 127.0.0.1 >nul & if exist "$INSTDIR" rmdir /s /q "$INSTDIR"' SW_HIDE

    ; 7. 兜底清理用户级与系统级注册表及数据目录（确保卸载零残留）
    SetRegView 64
    DeleteRegKey HKCU "Software\StartupGuard"
    DeleteRegKey HKLM "Software\StartupGuard"
    DeleteRegKey HKLM "${PRODUCT_UNINST_KEY}"
    DeleteRegKey HKLM "${PRODUCT_DIR_REGKEY}"
    SetRegView 32
    DeleteRegKey HKCU "Software\StartupGuard"
    DeleteRegKey HKLM "Software\StartupGuard"
    DeleteRegKey HKLM "${PRODUCT_UNINST_KEY}"
    DeleteRegKey HKLM "${PRODUCT_DIR_REGKEY}"
    SetRegView 64

    SetShellVarContext current
    RMDir /r "$LOCALAPPDATA\StartupGuard"
    RMDir /r "$APPDATA\StartupGuard"
    SetShellVarContext all
    RMDir /r "$APPDATA\StartupGuard"

    SetAutoClose true
SectionEnd
