; =========================================================================
; StartupGuard - Windows 10/11 x64 NSIS 安装程序脚本
; 支持服务注册 (sc create)、托盘自启 (Run 键)、桌面快捷方式与干净卸载
; =========================================================================

Unicode true
!include "MUI2.nsh"
!include "FileFunc.nsh"
!include "nsDialogs.nsh"
!include "LogicLib.nsh"

; 基本元数据定义
!define PRODUCT_NAME "StartupGuard"
!ifndef PRODUCT_VERSION
  !define PRODUCT_VERSION "1.0.1"
!endif
!ifndef TARGET_ARCH
  !define TARGET_ARCH "x64"
!endif
!ifndef DEPLOY_MODE
  !define DEPLOY_MODE "self-contained"
!endif
!ifndef PUBLISH_DIR
  !define PUBLISH_DIR "..\artifacts\publish\win-${TARGET_ARCH}-${DEPLOY_MODE}"
!endif
!ifndef OUT_FILE
  !define OUT_FILE "..\dist\StartupGuard-${PRODUCT_VERSION}-${TARGET_ARCH}-${DEPLOY_MODE}-Setup.exe"
!endif
!define PRODUCT_PUBLISHER "StartupGuard Security Team"
!define PRODUCT_WEB_SITE "https://github.com/PhoebeCLS/StartupGuard"
!define PRODUCT_UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}"
!define PRODUCT_DIR_REGKEY "Software\${PRODUCT_NAME}"

Name "${PRODUCT_NAME} v${PRODUCT_VERSION}"
OutFile "${OUT_FILE}"
InstallDir "$PROGRAMFILES64\StartupGuard"
InstallDirRegKey HKLM "${PRODUCT_DIR_REGKEY}" "InstallDir"
RequestExecutionLevel admin

; 卸载页面状态变量（默认勾选：卸载时同步彻底删除个人规则、日志、配置与共享数据）
Var UninstDeleteDataDialog
Var UninstDeleteDataCheckbox
Var UninstDeleteUserData

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
UninstPage custom un.DeleteDataPageCreate un.DeleteDataPageLeave
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

; 多语言设置 (简体中文)
!insertmacro MUI_LANGUAGE "SimpChinese"

; =========================================================================
; 卸载自定义页：询问是否同时删除个人数据（默认勾选）
; =========================================================================
Function un.onInit
    StrCpy $UninstDeleteUserData "1"
FunctionEnd

Function un.DeleteDataPageCreate
    !insertmacro MUI_HEADER_TEXT "个人数据清理选项" "选择是否在卸载时清理本地个人数据"
    nsDialogs::Create 1018
    Pop $UninstDeleteDataDialog
    ${If} $UninstDeleteDataDialog == error
        Abort
    ${EndIf}

    ${NSD_CreateLabel} 0 0 100% 22u "卸载程序将移除 StartupGuard 主程序、后台守护服务、开机自启项与快捷方式。"
    Pop $0

    ${NSD_CreateCheckbox} 0 28u 100% 18u "同时删除全部个人数据"
    Pop $UninstDeleteDataCheckbox
    ${NSD_SetState} $UninstDeleteDataCheckbox ${BST_CHECKED}

    ${NSD_CreateLabel} 0 54u 100% 28u "提示：勾选后将一并清空本地规则库、日志与配置；不会还原您已优化的系统自启与右键菜单状态。"
    Pop $0

    nsDialogs::Show
FunctionEnd

Function un.DeleteDataPageLeave
    ${NSD_GetState} $UninstDeleteDataCheckbox $0
    ${If} $0 == ${BST_CHECKED}
        StrCpy $UninstDeleteUserData "1"
    ${Else}
        StrCpy $UninstDeleteUserData "0"
    ${EndIf}
FunctionEnd

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
    ExecWait 'taskkill.exe /F /T /IM StartupGuard.TrayHost.exe'
    ExecWait 'taskkill.exe /F /T /IM StartupGuard.App.exe'
    ExecWait 'taskkill.exe /F /T /IM StartupGuard.ProbeHost.exe'
    ExecWait 'taskkill.exe /F /T /IM StartupGuard.Service.exe'
    Sleep 500

    ; 升级或跨部署模式覆盖安装时先清理旧程序与运行库，避免 framework-dependent 与 self-contained 残留冲突
    Delete "$INSTDIR\StartupGuard.Service.exe"
    Delete "$INSTDIR\StartupGuard.TrayHost.exe"
    Delete "$INSTDIR\StartupGuard.ProbeHost.exe"
    Delete "$INSTDIR\StartupGuard.App.exe"
    Delete "$INSTDIR\*.dll"
    Delete "$INSTDIR\*.json"
    RMDir /r "$INSTDIR\runtimes"

    ; 释放 4 大核心可执行程序及对应部署模式运行库 (${TARGET_ARCH} / ${DEPLOY_MODE})
    File /nonfatal /r /x *.pdb "${PUBLISH_DIR}\*.*"

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
    ExecWait 'taskkill.exe /F /T /IM StartupGuard.TrayHost.exe'
    ExecWait 'taskkill.exe /F /T /IM StartupGuard.App.exe'
    ExecWait 'taskkill.exe /F /T /IM StartupGuard.ProbeHost.exe'
    ExecWait 'taskkill.exe /F /T /IM StartupGuard.Service.exe'
    Sleep 800

    ; 2. 若用户勾选了“同时删除全部个人数据”，先执行全量数据重置（必须在删除 Service.exe 之前完成）
    ${If} $UninstDeleteUserData == "1"
        DetailPrint "正在彻底清除 StartupGuard 个人规则库、拦截日志、配置与共享数据..."
        ${If} ${FileExists} "$INSTDIR\StartupGuard.Service.exe"
            ExecWait '"$INSTDIR\StartupGuard.Service.exe" --uninstall-reset'
        ${EndIf}
    ${Else}
        DetailPrint "按用户选择保留个人规则库、拦截日志与偏好设置..."
    ${EndIf}

    ; 3. 删除后台服务
    ExecWait 'sc.exe delete StartupGuardService'

    ; 4. 清理开机自启注册表（同时清理 HKLM 与 HKCU 的 64/32 位 Run 及 StartupApproved）
    SetRegView 64
    DeleteRegValue HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "StartupGuardTray"
    DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "StartupGuardTray"
    DeleteRegValue HKLM "Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" "StartupGuardTray"
    DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" "StartupGuardTray"
    SetRegView 32
    DeleteRegValue HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "StartupGuardTray"
    DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "StartupGuardTray"
    DeleteRegValue HKLM "Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32" "StartupGuardTray"
    DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32" "StartupGuardTray"
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

    ; 7. 清理系统应用卸载注册表与安装路径键（无论是否删除个人数据，程序卸载注册表必须清除）
    SetRegView 64
    DeleteRegKey HKLM "${PRODUCT_UNINST_KEY}"
    DeleteRegKey HKLM "${PRODUCT_DIR_REGKEY}"
    SetRegView 32
    DeleteRegKey HKLM "${PRODUCT_UNINST_KEY}"
    DeleteRegKey HKLM "${PRODUCT_DIR_REGKEY}"
    SetRegView 64

    ; 8. 仅当用户明确勾选时，彻底移除个人配置注册表、AppData 及 C:\ProgramData\StartupGuard 全目录（不留空目录与锁文件）
    ${If} $UninstDeleteUserData == "1"
        SetRegView 64
        DeleteRegKey HKCU "Software\StartupGuard"
        DeleteRegKey HKLM "Software\StartupGuard"
        SetRegView 32
        DeleteRegKey HKCU "Software\StartupGuard"
        DeleteRegKey HKLM "Software\StartupGuard"
        SetRegView 64

        SetShellVarContext current
        RMDir /r "$LOCALAPPDATA\StartupGuard"
        RMDir /r "$APPDATA\StartupGuard"
        ExecWait '"$0" /c if exist "$LOCALAPPDATA\StartupGuard" (attrib -r -s -h "$LOCALAPPDATA\StartupGuard\*.*" /s /d >nul 2>&1 & rmdir /s /q "$LOCALAPPDATA\StartupGuard") & if exist "$APPDATA\StartupGuard" (attrib -r -s -h "$APPDATA\StartupGuard\*.*" /s /d >nul 2>&1 & rmdir /s /q "$APPDATA\StartupGuard")'

        SetShellVarContext all
        RMDir /r "$APPDATA\StartupGuard"
        ExpandEnvStrings $1 "%ProgramData%"
        ExecWait '"$0" /c if exist "$APPDATA\StartupGuard" (attrib -r -s -h "$APPDATA\StartupGuard\*.*" /s /d >nul 2>&1 & rmdir /s /q "$APPDATA\StartupGuard") & if exist "$1\StartupGuard" (attrib -r -s -h "$1\StartupGuard\*.*" /s /d >nul 2>&1 & rmdir /s /q "$1\StartupGuard")'
        SetShellVarContext current
    ${EndIf}

    SetAutoClose true
SectionEnd
