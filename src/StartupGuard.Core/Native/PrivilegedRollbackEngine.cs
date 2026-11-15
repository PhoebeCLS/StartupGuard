using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using StartupGuard.Core.ContextMenu;
using StartupGuard.Core.Models;
using StartupGuard.Core.Storage;

namespace StartupGuard.Core.Native;

/// <summary>
/// 高权限回滚执行器 (Privileged Rollback Engine)
/// 使用 SeTakeOwnershipPrivilege / SeRestorePrivilege 提权处理只读 ACL，
/// 对内核驱动仅调整 Start=3/4 而不物理删除 .sys 文件。
/// </summary>
public static unsafe partial class PrivilegedRollbackEngine
{
    private const string AdvApi32Dll = "advapi32.dll";
    private const string Kernel32Dll = "kernel32.dll";

    public static readonly nint HKEY_CLASSES_ROOT = new(unchecked((int)0x80000000));
    public static readonly nint HKEY_CURRENT_USER = new(unchecked((int)0x80000001));
    public static readonly nint HKEY_LOCAL_MACHINE = new(unchecked((int)0x80000002));
    public static readonly nint HKEY_USERS = new(unchecked((int)0x80000003));

    [LibraryImport(Kernel32Dll)]
    private static partial nint GetCurrentProcess();

    [LibraryImport(AdvApi32Dll, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool OpenProcessToken(nint processHandle, uint desiredAccess, out nint tokenHandle);

    [LibraryImport(AdvApi32Dll, EntryPoint = "LookupPrivilegeValueW", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool LookupPrivilegeValueW(string? lpSystemName, string lpName, out long lpLuid);

    [LibraryImport(AdvApi32Dll, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool AdjustTokenPrivileges(
        nint tokenHandle,
        [MarshalAs(UnmanagedType.Bool)] bool disableAllPrivileges,
        void* newState,
        uint bufferLength,
        void* previousState,
        uint* returnLength);

    [LibraryImport(AdvApi32Dll, EntryPoint = "SetNamedSecurityInfoW", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    private static partial uint SetNamedSecurityInfoW(
        string pObjectName,
        uint objectType,
        uint securityInfo,
        nint psidOwner,
        nint psidGroup,
        nint pDacl,
        nint pSacl);

    [LibraryImport(AdvApi32Dll, EntryPoint = "ConvertStringSidToSidW", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool ConvertStringSidToSidW(string stringSid, out nint pSid);

    [LibraryImport(Kernel32Dll)]
    private static partial nint LocalFree(nint hMem);

    [LibraryImport(AdvApi32Dll, EntryPoint = "RegOpenKeyExW", StringMarshalling = StringMarshalling.Utf16)]
    private static partial int RegOpenKeyExW(nint hKey, string lpSubKey, uint ulOptions, uint samDesired, out nint phkResult);

    [LibraryImport(AdvApi32Dll, EntryPoint = "RegCreateKeyExW", StringMarshalling = StringMarshalling.Utf16)]
    private static partial int RegCreateKeyExW(
        nint hKey,
        string lpSubKey,
        uint reserved,
        string? lpClass,
        uint dwOptions,
        uint samDesired,
        nint lpSecurityAttributes,
        out nint phkResult,
        out uint lpdwDisposition);

    [LibraryImport(AdvApi32Dll, EntryPoint = "RegSetValueExW", StringMarshalling = StringMarshalling.Utf16)]
    private static partial int RegSetValueExW(nint hKey, string? lpValueName, uint reserved, uint dwType, byte* lpData, uint cbData);

    [LibraryImport(AdvApi32Dll, EntryPoint = "RegDeleteValueW", StringMarshalling = StringMarshalling.Utf16)]
    private static partial int RegDeleteValueW(nint hKey, string lpValueName);

    [LibraryImport(AdvApi32Dll, EntryPoint = "RegDeleteKeyExW", StringMarshalling = StringMarshalling.Utf16)]
    internal static partial int RegDeleteKeyExW(nint hKey, string lpSubKey, uint samDesired, uint reserved);

    [LibraryImport(AdvApi32Dll)]
    private static partial int RegCloseKey(nint hKey);

    [LibraryImport(AdvApi32Dll, EntryPoint = "OpenSCManagerW", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    private static partial nint OpenSCManagerW(string? lpMachineName, string? lpDatabaseName, uint dwDesiredAccess);

    [LibraryImport(AdvApi32Dll, EntryPoint = "OpenServiceW", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    private static partial nint OpenServiceW(nint hSCManager, string lpServiceName, uint dwDesiredAccess);

    [LibraryImport(AdvApi32Dll, EntryPoint = "ChangeServiceConfigW", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool ChangeServiceConfigW(
        nint hService,
        uint dwServiceType,
        uint dwStartType,
        uint dwErrorControl,
        string? lpBinaryPathName,
        string? lpLoadOrderGroup,
        nint lpdwTagId,
        string? lpDependencies,
        string? lpServiceStartName,
        string? lpPassword,
        string? lpDisplayName);

    [LibraryImport(AdvApi32Dll)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseServiceHandle(nint hSCObject);

    [LibraryImport(AdvApi32Dll, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool DeleteService(nint hService);

    [LibraryImport(Kernel32Dll)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseHandle(nint hObject);

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    private struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        public long Luid;
        public uint Attributes;
    }

    private const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    private const uint TOKEN_QUERY = 0x0008;
    private const uint SE_PRIVILEGE_ENABLED = 0x00000002;
    private const uint KEY_ALL_ACCESS = 0xF003F;
    private const uint KEY_SET_VALUE = 0x0002;
    private const uint KEY_WOW64_64KEY = 0x0100;
    private const uint REG_OPTION_BACKUP_RESTORE = 0x00000004; // 穿透一切 ACL 限制！
    private const uint REG_SZ = 1;
    private const uint REG_BINARY = 3;
    private const uint REG_DWORD = 4;
    private const uint REG_MULTI_SZ = 7;
    private const uint SERVICE_NO_CHANGE = 0xFFFFFFFF;
    private const uint OWNER_SECURITY_INFORMATION = 0x00000001;
    private const uint DACL_SECURITY_INFORMATION = 0x00000004;

    /// <summary>
    /// 激活当前 LocalSystem 进程的 SeBackupPrivilege、SeRestorePrivilege 与 SeTakeOwnershipPrivilege
    /// 使得 RegCreateKeyExW 配合 REG_OPTION_BACKUP_RESTORE 可无视任何恶意只读 ACL 直接回滚！
    /// </summary>
    public static void EnableAllSystemRollbackPrivileges()
    {
        if (!OperatingSystem.IsWindows())
            return;

        try
        {
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out nint hToken))
                return;

            try
            {
                EnableSinglePrivilege(hToken, "SeTakeOwnershipPrivilege");
                EnableSinglePrivilege(hToken, "SeRestorePrivilege");
                EnableSinglePrivilege(hToken, "SeBackupPrivilege");
                EnableSinglePrivilege(hToken, "SeSecurityPrivilege");
            }
            finally
            {
                CloseHandle(hToken);
            }
        }
        catch
        {
            // Non-elevated or non-Windows environment
        }
    }

    private static void EnableSinglePrivilege(nint hToken, string privilegeName)
    {
        if (!LookupPrivilegeValueW(null, privilegeName, out long luid))
            return;

        TOKEN_PRIVILEGES tp = new()
        {
            PrivilegeCount = 1,
            Luid = luid,
            Attributes = SE_PRIVILEGE_ENABLED
        };

        AdjustTokenPrivileges(hToken, false, &tp, (uint)sizeof(TOKEN_PRIVILEGES), null, null);
    }

    /// <summary>
    /// 夺取被恶意锁定的注册表键或文件对象的所有权并赋予管理员访问权限 (SetNamedSecurityInfoW)
    /// objectType: 4 = SE_REGISTRY_KEY, 1 = SE_FILE_OBJECT
    /// </summary>
    public static bool TakeOwnershipAndGrantAdminAccess(string objectName, uint objectType = 4)
    {
        if (string.IsNullOrWhiteSpace(objectName) || !OperatingSystem.IsWindows())
            return false;

        EnableAllSystemRollbackPrivileges();

        // S-1-5-32-544 = Built-in Administrators
        if (!ConvertStringSidToSidW("S-1-5-32-544", out nint pAdminSid) || pAdminSid == 0)
            return false;

        try
        {
            uint statusOwner = SetNamedSecurityInfoW(
                objectName,
                objectType,
                OWNER_SECURITY_INFORMATION,
                pAdminSid,
                0,
                0,
                0);

            uint statusDacl = SetNamedSecurityInfoW(
                objectName,
                objectType,
                DACL_SECURITY_INFORMATION,
                0,
                0,
                0,
                0);

            return statusOwner == 0 || statusDacl == 0;
        }
        catch
        {
            return false;
        }
        finally
        {
            LocalFree(pAdminSid);
        }
    }

    /// <summary>
    /// 校验并限制内核驱动的回滚动作（内核驱动禁止物理删除 .sys 或删除注册表键，仅允许 Start=3 Demand 或 Start=4 Disabled）
    /// </summary>
    public static (InterceptionAction SanitizedAction, uint TargetStartType) EnforceDriverSafetyRedLine(
        InterceptionAction requestedAction,
        bool isKernelDriver)
    {
        if (isKernelDriver)
        {
            return requestedAction switch
            {
                InterceptionAction.RollbackToDemand => (InterceptionAction.RollbackToDemand, 3u),
                InterceptionAction.RollbackToDisabled => (InterceptionAction.RollbackToDisabled, 4u),
                // DeleteEntry / RestorePreviousSnapshot on KernelDriver is strictly clamped to Disabled (4) or Demand (3)
                InterceptionAction.DeleteEntry => (InterceptionAction.RollbackToDisabled, 4u),
                _ => (InterceptionAction.RollbackToDemand, 3u)
            };
        }

        uint startType = requestedAction switch
        {
            InterceptionAction.RollbackToDemand => 3u,   // SERVICE_DEMAND_START (手动)
            InterceptionAction.RollbackToDisabled => 4u, // SERVICE_DISABLED (禁用)
            InterceptionAction.RollbackToDelayedAuto => 2u, // SERVICE_AUTO_START (自动延迟)
            _ => 3u
        };
        return (requestedAction, startType);
    }

    /// <summary>
    /// 针对服务或内核驱动执行安全回滚（驱动仅修改 Start 启动类型为 Demand=3 或 Disabled=4，不删除 .sys 文件）
    /// </summary>
    public static bool RollbackServiceOrDriverStartType(string serviceName, InterceptionAction action, bool isKernelDriver = true)
    {
        if (action == InterceptionAction.RollbackToDelayedAuto && !isKernelDriver)
        {
            return RollbackServiceOrDriverStartType(serviceName, 2u, isKernelDriver: false, delayedAutoStart: true);
        }
        var (_, targetStartType) = EnforceDriverSafetyRedLine(action, isKernelDriver);
        return RollbackServiceOrDriverStartType(serviceName, targetStartType, isKernelDriver, delayedAutoStart: false);
    }

    /// <summary>
    /// 强特权删除指定 Windows 服务 (仅限 Win32Service，严禁用于 KernelDriver)
    /// </summary>
    public static bool DeleteServiceByName(string serviceName)
    {
        if (string.IsNullOrWhiteSpace(serviceName) || !OperatingSystem.IsWindows())
            return false;

        string cleanName = ExtractLeafKeyName(serviceName);
        EnableAllSystemRollbackPrivileges();

        nint hScm = OpenSCManagerW(null, null, 0x000F003F);
        if (hScm != 0)
        {
            try
            {
                nint hSvc = OpenServiceW(hScm, cleanName, 0x00010000 /* DELETE */ | 0x0002);
                if (hSvc != 0)
                {
                    try
                    {
                        if (DeleteService(hSvc))
                            return true;
                    }
                    finally
                    {
                        CloseServiceHandle(hSvc);
                    }
                }
            }
            finally
            {
                CloseServiceHandle(hScm);
            }
        }

        // 兜底使用 sc.exe delete
        try
        {
            using var proc = Process.Start(new ProcessStartInfo
            {
                FileName = "sc.exe",
                Arguments = $"delete \"{cleanName}\"",
                CreateNoWindow = true,
                UseShellExecute = false
            });
            proc?.WaitForExit(3000);
            return proc?.ExitCode == 0;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// 精确指定 StartType (0=Boot, 1=System, 2=Auto, 3=Demand, 4=Disabled) 及 DelayedAutostart
    /// </summary>
    public static bool RollbackServiceOrDriverStartType(string serviceName, uint targetStartType, bool delayedAutoStart)
    {
        return RollbackServiceOrDriverStartType(serviceName, targetStartType, isKernelDriver: false, delayedAutoStart: delayedAutoStart);
    }

    /// <summary>
    /// 精确指定 StartType (0=Boot, 1=System, 2=Auto, 3=Demand, 4=Disabled) 及 DelayedAutostart
    /// </summary>
    public static bool RollbackServiceOrDriverStartType(
        string serviceName,
        uint targetStartType,
        bool isKernelDriver = false,
        bool delayedAutoStart = false)
    {
        if (string.IsNullOrWhiteSpace(serviceName))
            return false;

        string cleanServiceName = ExtractLeafKeyName(serviceName);

        if (!OperatingSystem.IsWindows())
            return false;

        EnableAllSystemRollbackPrivileges();

        // 1. 优先尝试 SCM ChangeServiceConfigW
        nint hScm = OpenSCManagerW(null, null, 0x000F003F); // SC_MANAGER_ALL_ACCESS
        if (hScm != 0)
        {
            try
            {
                nint hSvc = OpenServiceW(hScm, cleanServiceName, 0x0002); // SERVICE_CHANGE_CONFIG
                if (hSvc != 0)
                {
                    try
                    {
                        ChangeServiceConfigW(hSvc, SERVICE_NO_CHANGE, targetStartType, SERVICE_NO_CHANGE, null, null, 0, null, null, null, null);
                    }
                    finally
                    {
                        CloseServiceHandle(hSvc);
                    }
                }
            }
            finally
            {
                CloseServiceHandle(hScm);
            }
        }

        // 2. 直写注册表 Start 与 DelayedAutostart 值 (REG_OPTION_BACKUP_RESTORE 强权限)
        string subKey = $@"SYSTEM\CurrentControlSet\Services\{cleanServiceName}";
        bool ok = WriteDwordWithBackupRestorePrivilege(HKEY_LOCAL_MACHINE, subKey, "Start", targetStartType);
        if (!ok)
        {
            TakeOwnershipAndGrantAdminAccess($@"MACHINE\{subKey}", 4);
            ok = WriteDwordWithBackupRestorePrivilege(HKEY_LOCAL_MACHINE, subKey, "Start", targetStartType);
        }

        if (!isKernelDriver)
        {
            WriteDwordWithBackupRestorePrivilege(HKEY_LOCAL_MACHINE, subKey, "DelayedAutostart", delayedAutoStart ? 1u : 0u);
        }

        // 3. 兜底通过 sc.exe config 刷新 SCM 内存配置
        try
        {
            string scStart = targetStartType switch
            {
                2u => delayedAutoStart ? "delayed-auto" : "auto",
                3u => "demand",
                4u => "disabled",
                _ => "demand"
            };
            using var proc = Process.Start(new ProcessStartInfo
            {
                FileName = "sc.exe",
                Arguments = $"config \"{cleanServiceName}\" start= {scStart}",
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            });
            proc?.WaitForExit(1500);
        }
        catch { }

        return ok;
    }

    /// <summary>
    /// 复核指定服务或驱动的 StartType 与 DelayedAutostart 是否与目标一致
    /// </summary>
    public static bool VerifyServiceStartType(string serviceNameOrLocation, uint expectedStartType, bool expectedDelayedAuto = false)
    {
        if (!OperatingSystem.IsWindows())
            return true;

        try
        {
            string svcName = ExtractLeafKeyName(serviceNameOrLocation);
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{svcName}", false);
            if (key == null) return false;
            if (key.GetValue("Start") is int startVal)
            {
                if (startVal != (int)expectedStartType) return false;
                if (expectedStartType == 2 && expectedDelayedAuto)
                {
                    int delayed = key.GetValue("DelayedAutostart") is int d ? d : 0;
                    return delayed == 1;
                }
                return true;
            }
            return false;
        }
        catch
        {
            return true;
        }
    }

    /// <summary>
    /// 复核指定目标的操作状态是否真正生效（涵盖阻止/禁用/删除/放行恢复全动作）
    /// </summary>
    public static bool VerifyRollbackState(
        TargetProgramFeatures target,
        InterceptionAction expectedAction,
        string? activeUserSid = null)
    {
        if (!OperatingSystem.IsWindows())
            return true;

        try
        {
            if (target.Category is MonitorCategory.Win32Service or MonitorCategory.KernelDriver)
            {
                string svcName = ExtractLeafKeyName(target.LocationKeyOrIdentifier);
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{svcName}", false);
                if (key == null)
                    return expectedAction == InterceptionAction.DeleteEntry;

                if (expectedAction == InterceptionAction.DeleteEntry)
                    return false;

                if (key.GetValue("Start") is int startVal)
                {
                    if (expectedAction == InterceptionAction.Allow)
                        return startVal is 1 or 2 or 3;
                    if (expectedAction == InterceptionAction.RollbackToDemand)
                        return startVal == 3;
                    if (expectedAction == InterceptionAction.RollbackToDisabled)
                        return startVal == 4;
                    if (expectedAction == InterceptionAction.RollbackToDelayedAuto)
                    {
                        int delayed = key.GetValue("DelayedAutostart") is int d ? d : 0;
                        return startVal == 2 && delayed == 1;
                    }
                }
                return false;
            }

            if (target.Category == MonitorCategory.StartupItem)
            {
                if (IsUwpStartupLocation(target.LocationKeyOrIdentifier))
                {
                    return VerifyUwpStartupState(target.LocationKeyOrIdentifier, expectedAction, activeUserSid);
                }

                if (target.LocationKeyOrIdentifier.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase) ||
                    target.LocationKeyOrIdentifier.Contains(@"\Start Menu\Programs\Startup", StringComparison.OrdinalIgnoreCase))
                {
                    if (expectedAction == InterceptionAction.DeleteEntry)
                        return !File.Exists(target.LocationKeyOrIdentifier);

                    string fileName = Path.GetFileName(target.LocationKeyOrIdentifier);
                    string approvedPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder";
                    using var appKey = !target.LocationKeyOrIdentifier.Contains("ProgramData", StringComparison.OrdinalIgnoreCase)
                        ? (!string.IsNullOrEmpty(activeUserSid)
                            ? Microsoft.Win32.Registry.Users.OpenSubKey($@"{activeUserSid}\{approvedPath}", false)
                            : Microsoft.Win32.Registry.CurrentUser.OpenSubKey(approvedPath, false))
                        : Microsoft.Win32.Registry.LocalMachine.OpenSubKey(approvedPath, false);
                    byte[]? b = appKey?.GetValue(fileName) as byte[];
                    if (expectedAction == InterceptionAction.Allow)
                        return b == null || b.Length == 0 || b[0] == 0x02;
                    return b is { Length: > 0 } && b[0] == 0x03;
                }

                var (hive, subKey, valName) = SplitRegistryLocation(target.LocationKeyOrIdentifier, activeUserSid);
                using var baseHive = hive == HKEY_USERS ? Microsoft.Win32.Registry.Users :
                                     hive == HKEY_CURRENT_USER ? Microsoft.Win32.Registry.CurrentUser :
                                     Microsoft.Win32.Registry.LocalMachine;
                using var runKey = baseHive.OpenSubKey(subKey, false);
                bool valueExists = runKey?.GetValue(valName) != null;

                if (expectedAction == InterceptionAction.DeleteEntry)
                    return !valueExists;

                if (!valueExists)
                    return expectedAction != InterceptionAction.Allow;

                string runApproved = subKey.Contains("WOW6432Node", StringComparison.OrdinalIgnoreCase)
                    ? @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32"
                    : @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";
                using var approvedRunKey = hive == HKEY_USERS && !string.IsNullOrEmpty(activeUserSid)
                    ? Microsoft.Win32.Registry.Users.OpenSubKey($@"{activeUserSid}\{runApproved}", false)
                    : (hive == HKEY_CURRENT_USER
                        ? Microsoft.Win32.Registry.CurrentUser.OpenSubKey(runApproved, false)
                        : Microsoft.Win32.Registry.LocalMachine.OpenSubKey(runApproved, false));
                byte[]? bytes = approvedRunKey?.GetValue(valName) as byte[];
                if (expectedAction == InterceptionAction.Allow)
                    return bytes == null || bytes.Length == 0 || bytes[0] == 0x02;
                return bytes is { Length: > 0 } && bytes[0] == 0x03;
            }

            if (IsApprovedShellExtensionLocation(target.LocationKeyOrIdentifier) ||
                target.Category == MonitorCategory.ModernContextMenu)
            {
                string clsid = ExtractClsidOrIdentifier(target.LocationKeyOrIdentifier);
                if (!string.IsNullOrEmpty(clsid))
                {
                    string blockedPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked";
                    using var hkcuBlocked = !string.IsNullOrEmpty(activeUserSid)
                        ? Microsoft.Win32.Registry.Users.OpenSubKey($@"{activeUserSid}\{blockedPath}", false)
                        : Microsoft.Win32.Registry.CurrentUser.OpenSubKey(blockedPath, false);
                    using var hklmBlocked = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(blockedPath, false);
                    bool isBlocked = hkcuBlocked?.GetValue(clsid) != null || hklmBlocked?.GetValue(clsid) != null;
                    return expectedAction == InterceptionAction.Allow ? !isBlocked : isBlocked;
                }
            }

            if (target.Category == MonitorCategory.ClassicContextMenu)
            {
                if (File.Exists(target.LocationKeyOrIdentifier))
                {
                    if (expectedAction == InterceptionAction.DeleteEntry)
                        return false;
                    bool isHidden = (File.GetAttributes(target.LocationKeyOrIdentifier) & FileAttributes.Hidden) != 0;
                    return expectedAction == InterceptionAction.Allow ? !isHidden : isHidden;
                }

                var (hive, subKey, _) = SplitRegistryLocation(target.LocationKeyOrIdentifier, activeUserSid);
                using var baseHive = hive == HKEY_USERS ? Microsoft.Win32.Registry.Users :
                                     hive == HKEY_CURRENT_USER ? Microsoft.Win32.Registry.CurrentUser :
                                     hive == HKEY_CLASSES_ROOT ? Microsoft.Win32.Registry.ClassesRoot :
                                     Microsoft.Win32.Registry.LocalMachine;
                int lastSlash = subKey.LastIndexOf('\\');
                string parentSub = lastSlash > 0 ? subKey[..lastSlash] : string.Empty;
                string leaf = lastSlash >= 0 && lastSlash + 1 < subKey.Length ? subKey[(lastSlash + 1)..] : subKey;
                string cleanLeaf = leaf.TrimStart('-');

                if (subKey.Contains(@"\shellex\", StringComparison.OrdinalIgnoreCase))
                {
                    var (enabledHandlerSub, disabledHandlerSub) = ResolveShellExPairPaths(subKey);
                    string legacyDisabledLeafSub = string.IsNullOrEmpty(parentSub) ? $"-{cleanLeaf}" : $@"{parentSub.Replace(@"\-ContextMenuHandlers", @"\ContextMenuHandlers", StringComparison.OrdinalIgnoreCase).Replace(@"\-DragDropHandlers", @"\DragDropHandlers", StringComparison.OrdinalIgnoreCase)}\-{cleanLeaf}";
                    using var kEnabled = !string.IsNullOrEmpty(enabledHandlerSub) ? baseHive.OpenSubKey(enabledHandlerSub, false) : null;
                    using var kDisabled = !string.IsNullOrEmpty(disabledHandlerSub) ? baseHive.OpenSubKey(disabledHandlerSub, false) : null;
                    using var kLegacyLeafDisabled = !string.Equals(legacyDisabledLeafSub, disabledHandlerSub, StringComparison.OrdinalIgnoreCase)
                        ? baseHive.OpenSubKey(legacyDisabledLeafSub, false)
                        : null;

                    if (expectedAction == InterceptionAction.DeleteEntry)
                        return kEnabled == null && kDisabled == null && kLegacyLeafDisabled == null;

                    string enabledDef = kEnabled?.GetValue(null)?.ToString()?.Trim() ?? string.Empty;
                    string disabledDef = kDisabled?.GetValue(null)?.ToString()?.Trim() ?? string.Empty;
                    string clsid = cleanLeaf.StartsWith('{') && cleanLeaf.EndsWith('}')
                        ? cleanLeaf
                        : (!string.IsNullOrEmpty(enabledDef) ? enabledDef.TrimStart('-').Trim() : disabledDef.TrimStart('-').Trim());

                    bool isBlockedByGuid = false;
                    if (clsid.StartsWith('{') && clsid.EndsWith('}'))
                    {
                        string blockedPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked";
                        using var hkcuBlocked = !string.IsNullOrEmpty(activeUserSid)
                            ? Microsoft.Win32.Registry.Users.OpenSubKey($@"{activeUserSid}\{blockedPath}", false)
                            : Microsoft.Win32.Registry.CurrentUser.OpenSubKey(blockedPath, false);
                        using var hklmBlocked = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(blockedPath, false);
                        isBlockedByGuid = hkcuBlocked?.GetValue(clsid) != null || hklmBlocked?.GetValue(clsid) != null;
                    }

                    bool hasDisabledFolder = kDisabled != null || kLegacyLeafDisabled != null;
                    bool isPrefixDisabled = enabledDef.StartsWith('-') || disabledDef.StartsWith('-');
                    if (expectedAction == InterceptionAction.Allow)
                    {
                        return kEnabled != null && !hasDisabledFolder && !enabledDef.StartsWith('-') && !isBlockedByGuid;
                    }

                    // ContextMenuManager 标准禁用方式：移动到 \-ContextMenuHandlers\<Key> (或 \-DragDropHandlers\<Key>)
                    return (hasDisabledFolder && kEnabled == null) || isPrefixDisabled || isBlockedByGuid || kEnabled == null;
                }

                if (subKey.Contains(@"\Applications\", StringComparison.OrdinalIgnoreCase))
                {
                    using var appKey = baseHive.OpenSubKey(subKey, false);
                    if (expectedAction == InterceptionAction.DeleteEntry)
                        return appKey == null;
                    if (appKey == null)
                        return expectedAction != InterceptionAction.Allow;
                    bool hasNoOpenWith = appKey.GetValue("NoOpenWith") != null;
                    return expectedAction == InterceptionAction.Allow ? !hasNoOpenWith : hasNoOpenWith;
                }

                string enabledSub = string.IsNullOrEmpty(parentSub) ? cleanLeaf : $@"{parentSub}\{cleanLeaf}";
                using var verbKey = baseHive.OpenSubKey(enabledSub, false);
                if (expectedAction == InterceptionAction.DeleteEntry)
                    return verbKey == null;
                if (verbKey == null)
                    return expectedAction != InterceptionAction.Allow;

                bool isVerbDisabled = verbKey.GetValue("LegacyDisable") != null ||
                                      verbKey.GetValue("ProgrammaticAccessOnly") != null ||
                                      (verbKey.GetValue("HideBasedOnVelocityId") is int vel && vel == 0x639bc8) ||
                                      (verbKey.GetValue("CommandFlags") is int cf && (cf % 16) >= 8);
                return expectedAction == InterceptionAction.Allow ? !isVerbDisabled : isVerbDisabled;
            }

            if (target.Category == MonitorCategory.ScheduledTask)
            {
                if (!TryQueryScheduledTaskState(target.LocationKeyOrIdentifier, out bool exists, out bool isEnabled))
                    return false;

                if (expectedAction == InterceptionAction.DeleteEntry)
                    return !exists;

                if (!exists)
                    return false;

                return expectedAction == InterceptionAction.Allow ? isEnabled : !isEnabled;
            }
        }
        catch
        {
            return false;
        }

        return true;
    }

    /// <summary>
    /// 对常规注册表 Run 键执行 StartupApproved 禁用或删除值
    /// </summary>
    public static bool RollbackStartupRegistryEntry(
        nint rootHive,
        string runSubKey,
        string approvedSubKey,
        string valueName,
        InterceptionAction action)
    {
        if (!OperatingSystem.IsWindows())
            return false;

        EnableAllSystemRollbackPrivileges();

        if (action == InterceptionAction.DeleteEntry)
        {
            if (RegCreateKeyExW(rootHive, runSubKey, 0, null, REG_OPTION_BACKUP_RESTORE, KEY_SET_VALUE | KEY_WOW64_64KEY, 0, out nint hKey, out _) == 0)
            {
                try
                {
                    return RegDeleteValueW(hKey, valueName) == 0;
                }
                finally
                {
                    RegCloseKey(hKey);
                }
            }
            return false;
        }

        // 回滚为 StartupApproved 禁用状态 (12字节二进制: 03 00 00 00 + 8字节时间戳)
        if (RegCreateKeyExW(rootHive, approvedSubKey, 0, null, REG_OPTION_BACKUP_RESTORE, KEY_SET_VALUE | KEY_WOW64_64KEY, 0, out nint hAppKey, out _) == 0)
        {
            try
            {
                byte* disabledBlob = stackalloc byte[12];
                disabledBlob[0] = 0x03; // 0x03 表示在任务管理器启动项中被禁用
                for (int i = 1; i < 12; i++) disabledBlob[i] = 0;

                return RegSetValueExW(hAppKey, valueName, 0, REG_BINARY, disabledBlob, 12) == 0;
            }
            finally
            {
                RegCloseKey(hAppKey);
            }
        }

        return false;
    }

    /// <summary>
    /// 对物理启动文件夹 (%AppData%\...\Startup 或 %ProgramData%\...\Startup) 中的快捷方式或程序执行禁用或删除
    /// </summary>
    public static bool RollbackStartupFolderEntry(
        string shortcutOrFilePath,
        string? activeUserSid,
        InterceptionAction action)
    {
        if (string.IsNullOrWhiteSpace(shortcutOrFilePath))
            return false;

        if (action == InterceptionAction.DeleteEntry)
        {
            try
            {
                if (File.Exists(shortcutOrFilePath))
                {
                    File.SetAttributes(shortcutOrFilePath, FileAttributes.Normal);
                    File.Delete(shortcutOrFilePath);
                    return true;
                }
            }
            catch
            {
                return false;
            }
        }

        if (!OperatingSystem.IsWindows())
            return false;

        EnableAllSystemRollbackPrivileges();
        string itemName = Path.GetFileName(shortcutOrFilePath);
        if (string.IsNullOrEmpty(itemName))
            return false;

        bool isCommonStartup = shortcutOrFilePath.Contains("ProgramData", StringComparison.OrdinalIgnoreCase);
        nint rootHive = HKEY_LOCAL_MACHINE;
        string approvedKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder";

        if (!isCommonStartup && !string.IsNullOrEmpty(activeUserSid))
        {
            rootHive = HKEY_USERS;
            approvedKey = InteractiveUserHiveResolver.ResolveUserRegistryPath(
                activeUserSid,
                @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder");
        }

        if (RegCreateKeyExW(rootHive, approvedKey, 0, null, REG_OPTION_BACKUP_RESTORE, KEY_SET_VALUE | KEY_WOW64_64KEY, 0, out nint hAppKey, out _) == 0)
        {
            try
            {
                byte* disabledBlob = stackalloc byte[12];
                disabledBlob[0] = 0x03;
                for (int i = 1; i < 12; i++) disabledBlob[i] = 0;

                return RegSetValueExW(hAppKey, itemName, 0, REG_BINARY, disabledBlob, 12) == 0;
            }
            finally
            {
                RegCloseKey(hAppKey);
            }
        }

        return false;
    }

    /// <summary>
    /// 对任务计划程序项执行禁用或删除 (schtasks.exe /Change /Disable 或 /Delete /F)
    /// </summary>
    public static bool RollbackScheduledTask(string taskLocationOrName, InterceptionAction action)
    {
        if (string.IsNullOrWhiteSpace(taskLocationOrName))
            return false;

        if (!OperatingSystem.IsWindows())
        {
            if (action == InterceptionAction.DeleteEntry && File.Exists(taskLocationOrName))
            {
                try
                {
                    File.Delete(taskLocationOrName);
                    return true;
                }
                catch
                {
                    return false;
                }
            }
            return false;
        }

        EnableAllSystemRollbackPrivileges();

        string normalizedTaskName = NormalizeScheduledTaskName(taskLocationOrName);

        string args = action == InterceptionAction.DeleteEntry
            ? $"/Delete /TN \"{normalizedTaskName}\" /F"
            : $"/Change /TN \"{normalizedTaskName}\" /Disable";

        try
        {
            using var proc = Process.Start(new ProcessStartInfo
            {
                FileName = "schtasks.exe",
                Arguments = args,
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            });

            if (proc is not null)
            {
                proc.WaitForExit(5000);
                if (proc.ExitCode == 0)
                    return true;
            }
        }
        catch
        {
            // Fall through to registry TaskCache manipulation
        }

        // 若 schtasks 受阻，尝试通过 REG_OPTION_BACKUP_RESTORE 处理 TaskCache\Tree
        string treeSubKey = $@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\{normalizedTaskName.TrimStart('\\')}";
        if (action == InterceptionAction.DeleteEntry)
        {
            return RegDeleteKeyExW(HKEY_LOCAL_MACHINE, treeSubKey, KEY_WOW64_64KEY, 0) == 0;
        }

        return false;
    }

    public static string NormalizeScheduledTaskName(string rawLocation)
    {
        string trimmed = (rawLocation ?? string.Empty).Trim().Trim('"');
        if (trimmed.StartsWith("Task:", StringComparison.OrdinalIgnoreCase))
        {
            trimmed = trimmed[5..].Trim();
        }

        const string tasksDir = @"Windows\System32\Tasks\";
        int idx = trimmed.IndexOf(tasksDir, StringComparison.OrdinalIgnoreCase);
        if (idx >= 0)
        {
            trimmed = trimmed[(idx + tasksDir.Length)..];
        }

        const string treePrefix = @"TaskCache\Tree\";
        int treeIdx = trimmed.IndexOf(treePrefix, StringComparison.OrdinalIgnoreCase);
        if (treeIdx >= 0)
        {
            trimmed = trimmed[(treeIdx + treePrefix.Length)..];
        }

        trimmed = trimmed.Trim();
        if (string.IsNullOrEmpty(trimmed))
            return @"\";

        return trimmed.StartsWith('\\') ? trimmed : @"\" + trimmed;
    }

    public static bool TryQueryScheduledTaskState(string rawLocation, out bool exists, out bool isEnabled)
    {
        exists = false;
        isEnabled = false;
        if (!OperatingSystem.IsWindows())
            return false;

        string normalized = NormalizeScheduledTaskName(rawLocation);
        string rel = normalized.TrimStart('\\');
        if (string.IsNullOrEmpty(rel))
            return false;

        try
        {
            using var proc = Process.Start(new ProcessStartInfo
            {
                FileName = "schtasks.exe",
                Arguments = $"/Query /TN \"{normalized}\" /XML",
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            });

            if (proc is not null)
            {
                string xml = proc.StandardOutput.ReadToEnd();
                proc.WaitForExit(3500);
                if (proc.ExitCode == 0 && !string.IsNullOrWhiteSpace(xml))
                {
                    exists = true;
                    if (TryParseScheduledTaskXml(xml, isXmlContent: true, out _, out _, out bool parsedEnabled))
                    {
                        isEnabled = parsedEnabled;
                    }
                    else
                    {
                        isEnabled = !xml.Contains("<Enabled>false</Enabled>", StringComparison.OrdinalIgnoreCase);
                    }
                    return true;
                }
            }
        }
        catch
        {
            // Fall through to XML file check
        }

        string xmlPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), @"System32\Tasks", rel);
        if (!File.Exists(xmlPath))
        {
            exists = false;
            return true;
        }

        exists = true;
        try
        {
            if (TryParseScheduledTaskXml(xmlPath, isXmlContent: false, out _, out _, out bool fileEnabled))
            {
                isEnabled = fileEnabled;
                return true;
            }
            string xml = File.ReadAllText(xmlPath);
            isEnabled = !xml.Contains("<Enabled>false</Enabled>", StringComparison.OrdinalIgnoreCase);
            return true;
        }
        catch
        {
            isEnabled = true;
            return false;
        }
    }

    /// <summary>
    /// 从计划任务 XML（或 Task 文件路径）安全提取执行命令、作者与启用状态（App/Service 共用）
    /// </summary>
    public static bool TryParseScheduledTaskXml(
        string xmlOrFilePath,
        bool isXmlContent,
        out string commandLine,
        out string author,
        out bool enabled)
    {
        commandLine = string.Empty;
        author = string.Empty;
        enabled = true;

        try
        {
            string xmlText = isXmlContent
                ? xmlOrFilePath
                : (File.Exists(xmlOrFilePath) ? File.ReadAllText(xmlOrFilePath) : string.Empty);

            if (string.IsNullOrWhiteSpace(xmlText))
                return false;

            var doc = System.Xml.Linq.XDocument.Parse(xmlText);
            var root = doc.Root;
            if (root == null) return false;

            var enabledEl = root.Descendants().FirstOrDefault(e => e.Name.LocalName.Equals("Enabled", StringComparison.OrdinalIgnoreCase) &&
                                                                   e.Parent?.Name.LocalName.Equals("Settings", StringComparison.OrdinalIgnoreCase) == true);
            if (enabledEl != null && bool.TryParse(enabledEl.Value.Trim(), out bool enVal))
                enabled = enVal;

            var authorEl = root.Descendants().FirstOrDefault(e => e.Name.LocalName.Equals("Author", StringComparison.OrdinalIgnoreCase));
            if (authorEl != null)
                author = authorEl.Value.Trim();

            var execEl = root.Descendants().FirstOrDefault(e => e.Name.LocalName.Equals("Exec", StringComparison.OrdinalIgnoreCase));
            if (execEl != null)
            {
                string cmd = execEl.Elements().FirstOrDefault(e => e.Name.LocalName.Equals("Command", StringComparison.OrdinalIgnoreCase))?.Value.Trim() ?? string.Empty;
                string args = execEl.Elements().FirstOrDefault(e => e.Name.LocalName.Equals("Arguments", StringComparison.OrdinalIgnoreCase))?.Value.Trim() ?? string.Empty;
                if (!string.IsNullOrEmpty(cmd))
                {
                    cmd = Environment.ExpandEnvironmentVariables(cmd);
                    commandLine = string.IsNullOrEmpty(args) ? cmd : $"{cmd} {args}";
                }
            }
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// 计算 Windows 策略与映像劫持项的安全修复方案 (供跨平台验证与底层执行复用)
    /// </summary>
    public static (string SubKeyPath, string ValueName, string? RestoredSafeStringValue, uint ValueType, bool DeleteValue)
        ComputePolicyHijackRemediationPlan(string locationKey, string valueName)
    {
        string loc = locationKey.Trim();
        string val = valueName.Trim();

        // 1. IFEO 映像劫持: 删除 Debugger 值
        if (loc.Contains("Image File Execution Options", StringComparison.OrdinalIgnoreCase))
        {
            string targetVal = string.IsNullOrEmpty(val) || val.Contains('\\') ? "Debugger" : val;
            return (loc, targetVal, null, REG_SZ, DeleteValue: true);
        }

        // 2. Winlogon Shell / Userinit 劫持修复
        if (loc.Contains("Winlogon", StringComparison.OrdinalIgnoreCase))
        {
            if (val.Equals("Userinit", StringComparison.OrdinalIgnoreCase) ||
                loc.EndsWith(@"\Userinit", StringComparison.OrdinalIgnoreCase))
            {
                return (@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "Userinit", @"C:\Windows\system32\userinit.exe,", REG_SZ, DeleteValue: false);
            }

            return (@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "Shell", "explorer.exe", REG_SZ, DeleteValue: false);
        }

        // 3. AppInit_DLLs 注入清理
        if (loc.Contains(@"CurrentVersion\Windows", StringComparison.OrdinalIgnoreCase) ||
            val.Equals("AppInit_DLLs", StringComparison.OrdinalIgnoreCase) ||
            val.Equals("LoadAppInit_DLLs", StringComparison.OrdinalIgnoreCase))
        {
            return (@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", "AppInit_DLLs", string.Empty, REG_SZ, DeleteValue: false);
        }

        // 4. Session Manager BootExecute 恢复默认自检命令
        if (loc.Contains("Session Manager", StringComparison.OrdinalIgnoreCase) ||
            val.Equals("BootExecute", StringComparison.OrdinalIgnoreCase))
        {
            return (@"SYSTEM\CurrentControlSet\Control\Session Manager", "BootExecute", "autocheck autochk *", REG_MULTI_SZ, DeleteValue: false);
        }

        // 5. Policies\Explorer\Run 或其他组策略自启值: 删除恶意键值
        return (loc, val, null, REG_SZ, DeleteValue: true);
    }

    /// <summary>
    /// 回滚 Windows 策略劫持项 (IFEO Debugger、Winlogon Shell/Userinit、AppInit_DLLs、BootExecute、Policies\Explorer\Run)
    /// </summary>
    public static bool RollbackWindowsPolicyHijack(
        string locationKey,
        string valueName,
        InterceptionAction action,
        byte[]? oldSnapshot = null,
        uint regType = REG_SZ)
    {
        if (string.IsNullOrWhiteSpace(locationKey))
            return false;

        if (!OperatingSystem.IsWindows())
            return false;

        EnableAllSystemRollbackPrivileges();

        if (action == InterceptionAction.RestorePreviousSnapshot && oldSnapshot is { Length: > 0 })
        {
            return RestoreRegistryValueSnapshot((nuint)HKEY_LOCAL_MACHINE, locationKey, valueName, regType, oldSnapshot);
        }

        var plan = ComputePolicyHijackRemediationPlan(locationKey, valueName);

        // 对 AppInit_DLLs 额外将 LoadAppInit_DLLs 置 0
        if (plan.ValueName.Equals("AppInit_DLLs", StringComparison.OrdinalIgnoreCase))
        {
            WriteDwordWithBackupRestorePrivilege(HKEY_LOCAL_MACHINE, plan.SubKeyPath, "LoadAppInit_DLLs", 0u);
        }

        if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, plan.SubKeyPath, 0, null, REG_OPTION_BACKUP_RESTORE, KEY_SET_VALUE | KEY_WOW64_64KEY, 0, out nint hKey, out _) != 0)
            return false;

        try
        {
            if (plan.DeleteValue)
            {
                int err = RegDeleteValueW(hKey, plan.ValueName);
                return err == 0 || err == 2;
            }

            string safeText = plan.RestoredSafeStringValue ?? string.Empty;
            if (plan.ValueType == REG_MULTI_SZ)
            {
                string multiSz = safeText + "\0\0";
                fixed (char* pMulti = multiSz)
                {
                    return RegSetValueExW(hKey, plan.ValueName, 0, REG_MULTI_SZ, (byte*)pMulti, (uint)(multiSz.Length * 2)) == 0;
                }
            }
            else
            {
                fixed (char* pStr = safeText)
                {
                    return RegSetValueExW(hKey, plan.ValueName, 0, REG_SZ, (byte*)pStr, (uint)((safeText.Length + 1) * 2)) == 0;
                }
            }
        }
        finally
        {
            RegCloseKey(hKey);
        }
    }

    /// <summary>
    /// 将注册表值精确还原为变更前的原始字节快照 (OldRawSnapshot)
    /// </summary>
    public static bool RestoreRegistryValueSnapshot(
        nuint rootHive,
        string subKeyPath,
        string valueName,
        uint valueType,
        ReadOnlySpan<byte> oldRawSnapshot)
        => RestoreRegistryValueSnapshot((nint)rootHive, subKeyPath, valueName, valueType, oldRawSnapshot);

    public static bool RestoreRegistryValueSnapshot(
        nint rootHive,
        string subKeyPath,
        string valueName,
        uint valueType,
        ReadOnlySpan<byte> oldRawSnapshot)
    {
        if (string.IsNullOrWhiteSpace(subKeyPath) || oldRawSnapshot.IsEmpty || !OperatingSystem.IsWindows())
            return false;

        EnableAllSystemRollbackPrivileges();

        if (RegCreateKeyExW(rootHive, subKeyPath, 0, null, REG_OPTION_BACKUP_RESTORE, KEY_SET_VALUE | KEY_WOW64_64KEY, 0, out nint hKey, out _) != 0)
            return false;

        try
        {
            fixed (byte* pData = oldRawSnapshot)
            {
                return RegSetValueExW(hKey, valueName, 0, valueType, pData, (uint)oldRawSnapshot.Length) == 0;
            }
        }
        finally
        {
            RegCloseKey(hKey);
        }
    }

    /// <summary>
    /// 将被拦截/禁用的项目恢复为启用状态或用户指定的启动类型（用于日志撤销与手动启用）
    /// </summary>
    public static bool RestoreItemEnabled(
        TargetProgramFeatures target,
        uint targetStartType = 2,
        bool delayedAutostart = false,
        string? activeUserSid = null)
    {
        if (!OperatingSystem.IsWindows())
            return true;

        EnableAllSystemRollbackPrivileges();

        switch (target.Category)
        {
            case MonitorCategory.KernelDriver:
            {
                uint clamped = targetStartType is 0 or 1 or 2 or 3 or 4 ? targetStartType : 3u;
                return RollbackServiceOrDriverStartType(target.LocationKeyOrIdentifier, clamped, isKernelDriver: true, delayedAutoStart: false);
            }

            case MonitorCategory.Win32Service:
            {
                uint clamped = targetStartType is 2 or 3 or 4 ? targetStartType : 2u;
                return RollbackServiceOrDriverStartType(target.LocationKeyOrIdentifier, clamped, isKernelDriver: false, delayedAutoStart: delayedAutostart);
            }

            case MonitorCategory.ScheduledTask:
            {
                string norm = NormalizeScheduledTaskName(target.LocationKeyOrIdentifier);
                try
                {
                    using var proc = Process.Start(new ProcessStartInfo
                    {
                        FileName = "schtasks.exe",
                        Arguments = $"/Change /TN \"{norm}\" /Enable",
                        CreateNoWindow = true,
                        UseShellExecute = false
                    });
                    proc?.WaitForExit(4000);
                    return proc?.ExitCode == 0;
                }
                catch { return false; }
            }

            case MonitorCategory.ModernContextMenu:
            {
                var cmEngine = new ContextMenuManagerEngine();
                string clsid = ExtractClsidOrIdentifier(target.LocationKeyOrIdentifier);
                return cmEngine.SetWin11ModernMenuBlockedState(clsid, blockItem: false, activeUserSid);
            }

            case MonitorCategory.ClassicContextMenu:
            {
                var cmEngine = new ContextMenuManagerEngine();
                if (File.Exists(target.LocationKeyOrIdentifier))
                {
                    return cmEngine.SetContextMenuItemEnabledState(new ContextMenuItemEntry
                    {
                        IdKey = target.LocationKeyOrIdentifier,
                        DisplayTitle = Path.GetFileNameWithoutExtension(target.LocationKeyOrIdentifier),
                        RegistryPath = target.LocationKeyOrIdentifier,
                        ScopeScene = target.LocationKeyOrIdentifier.Contains("WinX", StringComparison.OrdinalIgnoreCase) ? "WinX (Win+X 菜单)" : "SendTo (发送到)",
                        MenuCategory = MonitorCategory.ClassicContextMenu
                    }, enable: true, activeUserSid);
                }
                if (IsApprovedShellExtensionLocation(target.LocationKeyOrIdentifier))
                {
                    string clsid = ExtractClsidOrIdentifier(target.LocationKeyOrIdentifier);
                    return !string.IsNullOrEmpty(clsid) && cmEngine.SetWin11ModernMenuBlockedState(clsid, blockItem: false, activeUserSid);
                }
                var (hive, subKey, _) = SplitRegistryLocation(target.LocationKeyOrIdentifier, activeUserSid);
                if (subKey.Contains(@"\shellex\ContextMenuHandlers", StringComparison.OrdinalIgnoreCase) ||
                    subKey.Contains(@"\shellex\-ContextMenuHandlers", StringComparison.OrdinalIgnoreCase) ||
                    subKey.Contains(@"\shellex\DragDropHandlers", StringComparison.OrdinalIgnoreCase) ||
                    subKey.Contains(@"\shellex\-DragDropHandlers", StringComparison.OrdinalIgnoreCase))
                {
                    string handlerClsid = ContextMenuManagerEngine.TryExtractHandlerClsid(hive, subKey);
                    return cmEngine.SetClassicContextMenuHandlerState(hive, subKey, handlerClsid, enable: true, activeUserSid);
                }
                if (subKey.Contains(@"\Applications\", StringComparison.OrdinalIgnoreCase))
                {
                    return cmEngine.SetOpenWithApplicationState(target.LocationKeyOrIdentifier, enable: true, activeUserSid);
                }
                return cmEngine.SetClassicShellVerbState(hive, subKey, disableVerb: false);
            }

            case MonitorCategory.StartupItem:
            default:
            {
                if (IsUwpStartupLocation(target.LocationKeyOrIdentifier))
                {
                    return SetUwpStartupTaskState(target.LocationKeyOrIdentifier, activeUserSid, enable: true);
                }

                byte* enabledBlob = stackalloc byte[12];
                enabledBlob[0] = 0x02;
                for (int i = 1; i < 12; i++) enabledBlob[i] = 0;

                if (target.LocationKeyOrIdentifier.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase) ||
                    target.LocationKeyOrIdentifier.Contains(@"\Start Menu\Programs\Startup", StringComparison.OrdinalIgnoreCase))
                {
                    string itemName = Path.GetFileName(target.LocationKeyOrIdentifier);
                    bool isCommon = target.LocationKeyOrIdentifier.Contains("ProgramData", StringComparison.OrdinalIgnoreCase);
                    nint appHive = isCommon || string.IsNullOrEmpty(activeUserSid) ? HKEY_LOCAL_MACHINE : HKEY_USERS;
                    string appKey = isCommon || string.IsNullOrEmpty(activeUserSid)
                        ? @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder"
                        : InteractiveUserHiveResolver.ResolveUserRegistryPath(activeUserSid, @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder");
                    int errFolder = RegCreateKeyExW(appHive, appKey, 0, null, REG_OPTION_BACKUP_RESTORE, KEY_SET_VALUE | KEY_WOW64_64KEY, 0, out nint hAppKey, out _);
                    if (errFolder == 0)
                    {
                        try
                        {
                            int setErr = RegSetValueExW(hAppKey, itemName, 0, REG_BINARY, enabledBlob, 12);
                            SharedStorageHelper.LogDiagnostic("RollbackEngine", $"RestoreStartupFolder item={itemName} err={setErr}");
                            return setErr == 0;
                        }
                        finally { RegCloseKey(hAppKey); }
                    }
                    SharedStorageHelper.LogDiagnostic("RollbackEngine", $"RestoreStartupFolder RegCreateKeyExW failed err={errFolder}");
                    return false;
                }

                var (runHive, runSubKey, valName) = SplitRegistryLocation(target.LocationKeyOrIdentifier, activeUserSid);
                string approvedRel = runSubKey.Contains("WOW6432Node", StringComparison.OrdinalIgnoreCase)
                    ? @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32"
                    : @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";
                string approvedRun = runHive == HKEY_USERS && !string.IsNullOrEmpty(activeUserSid)
                    ? InteractiveUserHiveResolver.ResolveUserRegistryPath(activeUserSid, approvedRel)
                    : approvedRel.Replace("Software\\", "SOFTWARE\\", StringComparison.Ordinal);
                int errKey = RegCreateKeyExW(runHive, approvedRun, 0, null, REG_OPTION_BACKUP_RESTORE, KEY_SET_VALUE | KEY_WOW64_64KEY, 0, out nint hRunApp, out _);
                if (errKey == 0)
                {
                    try
                    {
                        int setErr = RegSetValueExW(hRunApp, valName, 0, REG_BINARY, enabledBlob, 12);
                        SharedStorageHelper.LogDiagnostic("RollbackEngine", $"RestoreStartupRun val={valName} approved={approvedRun} err={setErr}");
                        return setErr == 0;
                    }
                    finally { RegCloseKey(hRunApp); }
                }
                SharedStorageHelper.LogDiagnostic("RollbackEngine", $"RestoreStartupRun RegCreateKeyExW failed approved={approvedRun} err={errKey}");
                return false;
            }
        }
    }

    /// <summary>
    /// 统一分派执行 6 大监控类别的强权限回滚 (在进入任何处理逻辑前严格实施驱动安全红线保护)
    /// </summary>
    public static bool ExecuteRollback(
        TargetProgramFeatures target,
        InterceptionAction action,
        string? activeUserSid = null,
        Func<TargetProgramFeatures, InterceptionAction, bool>? customTestHandler = null)
    {
        if (action == InterceptionAction.Allow)
            return true;

        // 内核驱动禁止物理删除 .sys 或执行 DeleteEntry，统一收敛为 RollbackToDisabled (Start=4) 或 RollbackToDemand (Start=3)
        if (target.Category == MonitorCategory.KernelDriver)
        {
            (action, _) = EnforceDriverSafetyRedLine(action, isKernelDriver: true);
        }

        if (customTestHandler is not null)
        {
            return customTestHandler(target, action);
        }

        if (action == InterceptionAction.RestorePreviousSnapshot &&
            target.Category != MonitorCategory.KernelDriver &&
            target.OldRawSnapshot is { Length: > 0 })
        {
            var (hive, subKey, valName) = SplitRegistryLocation(target.LocationKeyOrIdentifier, activeUserSid);
            return RestoreRegistryValueSnapshot(hive, subKey, valName, target.RegistryValueType, target.OldRawSnapshot);
        }

        switch (target.Category)
        {
            case MonitorCategory.KernelDriver:
                return RollbackServiceOrDriverStartType(target.LocationKeyOrIdentifier, action, isKernelDriver: true);

            case MonitorCategory.Win32Service:
                if (action == InterceptionAction.DeleteEntry)
                {
                    return DeleteServiceByName(target.LocationKeyOrIdentifier);
                }
                return RollbackServiceOrDriverStartType(target.LocationKeyOrIdentifier, action, isKernelDriver: false);

            case MonitorCategory.ScheduledTask:
                return RollbackScheduledTask(target.LocationKeyOrIdentifier, action);

            case MonitorCategory.WindowsPolicy:
            {
                var (_, subKey, valName) = SplitRegistryLocation(target.LocationKeyOrIdentifier, activeUserSid);
                return RollbackWindowsPolicyHijack(subKey, valName, action, target.OldRawSnapshot, target.RegistryValueType);
            }

            case MonitorCategory.ModernContextMenu:
            {
                var cmEngine = new ContextMenuManagerEngine();
                if (action == InterceptionAction.DeleteEntry)
                {
                    return cmEngine.DeleteContextMenuEntry(target.LocationKeyOrIdentifier, activeUserSid);
                }
                string clsid = ExtractClsidOrIdentifier(target.LocationKeyOrIdentifier);
                return cmEngine.SetWin11ModernMenuBlockedState(
                    clsid,
                    blockItem: true,
                    activeUserSid);
            }

            case MonitorCategory.ClassicContextMenu:
            {
                var cmEngine = new ContextMenuManagerEngine();
                if (action == InterceptionAction.DeleteEntry)
                {
                    return cmEngine.DeleteContextMenuEntry(target.LocationKeyOrIdentifier, activeUserSid);
                }
                if (File.Exists(target.LocationKeyOrIdentifier))
                {
                    return cmEngine.SetContextMenuItemEnabledState(new ContextMenuItemEntry
                    {
                        IdKey = target.LocationKeyOrIdentifier,
                        DisplayTitle = Path.GetFileNameWithoutExtension(target.LocationKeyOrIdentifier),
                        RegistryPath = target.LocationKeyOrIdentifier,
                        ScopeScene = target.LocationKeyOrIdentifier.Contains("WinX", StringComparison.OrdinalIgnoreCase) ? "WinX (Win+X 菜单)" : "SendTo (发送到)",
                        MenuCategory = MonitorCategory.ClassicContextMenu
                    }, enable: false, activeUserSid);
                }
                if (IsApprovedShellExtensionLocation(target.LocationKeyOrIdentifier))
                {
                    string clsid = ExtractClsidOrIdentifier(target.LocationKeyOrIdentifier);
                    return !string.IsNullOrEmpty(clsid) && cmEngine.SetWin11ModernMenuBlockedState(clsid, blockItem: true, activeUserSid);
                }
                var (hive, subKey, _) = SplitRegistryLocation(target.LocationKeyOrIdentifier, activeUserSid);
                if (subKey.Contains(@"\shellex\ContextMenuHandlers", StringComparison.OrdinalIgnoreCase) ||
                    subKey.Contains(@"\shellex\-ContextMenuHandlers", StringComparison.OrdinalIgnoreCase) ||
                    subKey.Contains(@"\shellex\DragDropHandlers", StringComparison.OrdinalIgnoreCase) ||
                    subKey.Contains(@"\shellex\-DragDropHandlers", StringComparison.OrdinalIgnoreCase))
                {
                    string handlerClsid = ContextMenuManagerEngine.TryExtractHandlerClsid(hive, subKey);
                    return cmEngine.SetClassicContextMenuHandlerState(hive, subKey, handlerClsid, enable: false, activeUserSid);
                }
                if (subKey.Contains(@"\Applications\", StringComparison.OrdinalIgnoreCase))
                {
                    return cmEngine.SetOpenWithApplicationState(target.LocationKeyOrIdentifier, enable: false, activeUserSid);
                }
                return cmEngine.SetClassicShellVerbState(hive, subKey, disableVerb: true);
            }

            case MonitorCategory.StartupItem:
            default:
            {
                if (IsUwpStartupLocation(target.LocationKeyOrIdentifier))
                {
                    return SetUwpStartupTaskState(target.LocationKeyOrIdentifier, activeUserSid, enable: false);
                }

                if (target.LocationKeyOrIdentifier.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase) ||
                    target.LocationKeyOrIdentifier.Contains(@"\Start Menu\Programs\Startup", StringComparison.OrdinalIgnoreCase))
                {
                    return RollbackStartupFolderEntry(target.LocationKeyOrIdentifier, activeUserSid, action);
                }

                var (hive, subKey, valName) = SplitRegistryLocation(target.LocationKeyOrIdentifier, activeUserSid);
                string approvedRel = subKey.Contains("WOW6432Node", StringComparison.OrdinalIgnoreCase)
                    ? @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32"
                    : @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";
                string approvedKey = hive == HKEY_USERS && !string.IsNullOrEmpty(activeUserSid)
                    ? InteractiveUserHiveResolver.ResolveUserRegistryPath(activeUserSid, approvedRel)
                    : approvedRel.Replace("Software\\", "SOFTWARE\\", StringComparison.Ordinal);

                bool okRun = RollbackStartupRegistryEntry(hive, subKey, approvedKey, valName, action);
                SharedStorageHelper.LogDiagnostic("RollbackEngine", $"ExecuteRollbackStartup val={valName} approved={approvedKey} ok={okRun}");
                return okRun;
            }
        }
    }

    public static bool IsApprovedShellExtensionLocation(string? locationKey)
    {
        if (string.IsNullOrWhiteSpace(locationKey))
            return false;
        return locationKey.StartsWith("Approved:", StringComparison.OrdinalIgnoreCase) ||
               locationKey.Contains(@"\Shell Extensions\Approved", StringComparison.OrdinalIgnoreCase);
    }

    public static (nint Hive, string SubKey, string ValueName) SplitRegistryLocation(string locationKey, string? activeUserSid)
    {
        nint hive = HKEY_LOCAL_MACHINE;
        string rest = locationKey.Trim();
        foreach (string prefix in new[] { @"计算机\", @"電腦\", @"Computer\" })
        {
            if (rest.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                rest = rest[prefix.Length..];
                break;
            }
        }

        if (rest.StartsWith(@"HKLM\", StringComparison.OrdinalIgnoreCase))
        {
            hive = HKEY_LOCAL_MACHINE;
            rest = rest[5..];
        }
        else if (rest.StartsWith(@"HKEY_LOCAL_MACHINE\", StringComparison.OrdinalIgnoreCase))
        {
            hive = HKEY_LOCAL_MACHINE;
            rest = rest[19..];
        }
        else if (rest.StartsWith(@"HKCR\", StringComparison.OrdinalIgnoreCase))
        {
            hive = HKEY_CLASSES_ROOT;
            rest = rest[5..];
        }
        else if (rest.StartsWith(@"HKEY_CLASSES_ROOT\", StringComparison.OrdinalIgnoreCase))
        {
            hive = HKEY_CLASSES_ROOT;
            rest = rest[18..];
        }
        else if (rest.StartsWith(@"HKCU\", StringComparison.OrdinalIgnoreCase))
        {
            rest = rest[5..];
            if (!string.IsNullOrEmpty(activeUserSid))
            {
                hive = HKEY_USERS;
                rest = InteractiveUserHiveResolver.ResolveUserRegistryPath(activeUserSid, rest);
            }
            else
            {
                hive = HKEY_CURRENT_USER;
            }
        }
        else if (rest.StartsWith(@"HKEY_USERS\", StringComparison.OrdinalIgnoreCase) ||
                 rest.StartsWith(@"HKU\", StringComparison.OrdinalIgnoreCase))
        {
            hive = HKEY_USERS;
            int firstSlash = rest.IndexOf('\\');
            rest = firstSlash >= 0 ? rest[(firstSlash + 1)..] : rest;
        }

        int colonIdx = rest.LastIndexOf("::", StringComparison.Ordinal);
        if (colonIdx > 0)
        {
            return (hive, rest[..colonIdx], rest[(colonIdx + 2)..]);
        }

        bool isSubKeyLocation =
            hive == HKEY_CLASSES_ROOT ||
            rest.Contains(@"Software\Classes\", StringComparison.OrdinalIgnoreCase) ||
            rest.Contains(@"\Classes\", StringComparison.OrdinalIgnoreCase) ||
            rest.Contains(@"\shellex\", StringComparison.OrdinalIgnoreCase) ||
            rest.Contains(@"\shell\", StringComparison.OrdinalIgnoreCase);

        int lastSlash = rest.LastIndexOf('\\');
        if (lastSlash > 0 && !isSubKeyLocation)
        {
            return (hive, rest[..lastSlash], rest[(lastSlash + 1)..]);
        }

        return (hive, rest, string.Empty);
    }

    public static string ExtractLeafKeyName(string pathOrName)
    {
        string trimmed = pathOrName.Trim().TrimEnd('\\');
        int lastSlash = trimmed.LastIndexOf('\\');
        return lastSlash >= 0 ? trimmed[(lastSlash + 1)..] : trimmed;
    }

    public static (string EnabledSubKey, string DisabledSubKey) ResolveShellExPairPaths(string subKey)
    {
        string normalized = (subKey ?? string.Empty).Trim().TrimStart('\\');
        if (normalized.StartsWith(@"计算机\", StringComparison.OrdinalIgnoreCase))
            normalized = normalized[4..];

        foreach (string prefix in new[]
        {
            @"HKEY_LOCAL_MACHINE\", @"HKLM\",
            @"HKEY_CURRENT_USER\", @"HKCU\",
            @"HKEY_CLASSES_ROOT\", @"HKCR\",
            @"HKEY_USERS\", @"HKU\"
        })
        {
            if (normalized.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                normalized = normalized[prefix.Length..];
                break;
            }
        }
        normalized = normalized.Trim('\\');

        if (normalized.Contains(@"\-ContextMenuHandlers\", StringComparison.OrdinalIgnoreCase))
        {
            return (
                normalized.Replace(@"\-ContextMenuHandlers\", @"\ContextMenuHandlers\", StringComparison.OrdinalIgnoreCase),
                normalized);
        }
        if (normalized.Contains(@"\ContextMenuHandlers\", StringComparison.OrdinalIgnoreCase))
        {
            return (
                normalized,
                normalized.Replace(@"\ContextMenuHandlers\", @"\-ContextMenuHandlers\", StringComparison.OrdinalIgnoreCase));
        }
        if (normalized.Contains(@"\-DragDropHandlers\", StringComparison.OrdinalIgnoreCase))
        {
            return (
                normalized.Replace(@"\-DragDropHandlers\", @"\DragDropHandlers\", StringComparison.OrdinalIgnoreCase),
                normalized);
        }
        if (normalized.Contains(@"\DragDropHandlers\", StringComparison.OrdinalIgnoreCase))
        {
            return (
                normalized,
                normalized.Replace(@"\DragDropHandlers\", @"\-DragDropHandlers\", StringComparison.OrdinalIgnoreCase));
        }
        return (normalized, string.Empty);
    }

    /// <summary>
    /// 使用 REG_OPTION_BACKUP_RESTORE 绕过 DACL 直接写入 DWORD
    /// </summary>
    public static bool WriteDwordWithBackupRestorePrivilege(nint rootHive, string subKey, string valueName, uint value)
    {
        if (!OperatingSystem.IsWindows())
            return false;

        if (RegCreateKeyExW(rootHive, subKey, 0, null, REG_OPTION_BACKUP_RESTORE, KEY_SET_VALUE | KEY_WOW64_64KEY, 0, out nint hKey, out _) != 0)
            return false;

        try
        {
            uint val = value;
            return RegSetValueExW(hKey, valueName, 0, REG_DWORD, (byte*)&val, sizeof(uint)) == 0;
        }
        finally
        {
            RegCloseKey(hKey);
        }
    }

    public static bool IsUwpStartupLocation(string? locationKey)
    {
        return !string.IsNullOrWhiteSpace(locationKey) &&
               locationKey.Contains(@"\AppModel\SystemAppData\", StringComparison.OrdinalIgnoreCase);
    }

    public static bool SetUwpStartupTaskState(string locationKey, string? activeUserSid, bool enable)
    {
        if (!OperatingSystem.IsWindows() || string.IsNullOrWhiteSpace(locationKey))
            return false;

        EnableAllSystemRollbackPrivileges();
        string normalized = locationKey.EndsWith("::State", StringComparison.OrdinalIgnoreCase)
            ? locationKey
            : locationKey.TrimEnd('\\') + "::State";
        var (hive, subKey, valueName) = SplitRegistryLocation(normalized, activeUserSid);
        if (string.IsNullOrWhiteSpace(subKey))
            return false;

        if (hive == HKEY_CURRENT_USER && !string.IsNullOrEmpty(activeUserSid))
        {
            hive = HKEY_USERS;
            subKey = InteractiveUserHiveResolver.ResolveUserRegistryPath(activeUserSid, subKey);
        }

        // UWP StartupTask State: 2 = Enabled, 1 = DisabledByUser
        uint newState = enable ? 2u : 1u;
        return WriteDwordWithBackupRestorePrivilege(hive, subKey, valueName, newState);
    }

    public static bool VerifyUwpStartupState(string locationKey, InterceptionAction expectedAction, string? activeUserSid)
    {
        if (!OperatingSystem.IsWindows())
            return true;

        string normalized = locationKey.EndsWith("::State", StringComparison.OrdinalIgnoreCase)
            ? locationKey
            : locationKey.TrimEnd('\\') + "::State";
        var (hive, subKey, valueName) = SplitRegistryLocation(normalized, activeUserSid);
        using var baseHive = hive == HKEY_USERS ? Microsoft.Win32.Registry.Users :
                             hive == HKEY_CURRENT_USER ? Microsoft.Win32.Registry.CurrentUser :
                             Microsoft.Win32.Registry.LocalMachine;
        using var key = baseHive.OpenSubKey(subKey, false);
        if (key == null)
            return expectedAction != InterceptionAction.Allow;

        if (key.GetValue(valueName) is int stateVal)
        {
            return expectedAction == InterceptionAction.Allow
                ? (stateVal == 2 || stateVal == 4)
                : (stateVal == 0 || stateVal == 1 || stateVal == 3);
        }

        return expectedAction != InterceptionAction.Allow;
    }

    /// <summary>
    /// 从 PackagedCom 路径、Approved:、Win11Modern: 或任意标识符中精准提取 {GUID} CLSID
    /// </summary>
    public static string ExtractClsidOrIdentifier(string? locationKey)
    {
        if (string.IsNullOrWhiteSpace(locationKey))
            return string.Empty;

        string s = locationKey.Trim();
        var match = System.Text.RegularExpressions.Regex.Match(
            s,
            @"\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}");
        if (match.Success)
            return match.Value;

        if (s.StartsWith("Approved:", StringComparison.OrdinalIgnoreCase))
            return s["Approved:".Length..].Trim();

        return s;
    }

    public static string DescribeActionShortChinese(InterceptionAction action) => action switch
    {
        InterceptionAction.Allow => "放行启用",
        InterceptionAction.RollbackToDemand => "设为手动",
        InterceptionAction.RollbackToDelayedAuto => "延迟启动",
        InterceptionAction.RollbackToDisabled => "禁止启动",
        InterceptionAction.DeleteEntry => "删除移除",
        InterceptionAction.RestorePreviousSnapshot => "恢复原状",
        _ => "处置"
    };
}

