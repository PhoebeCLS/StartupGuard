using System.Runtime.InteropServices;

namespace StartupGuard.Core.Native;

/// <summary>
/// 跨会话用户注册表定向解析器（在 LocalSystem 服务中避免直接使用 HKCU，改用 HKEY_USERS\&lt;InteractiveUserSID&gt;）
/// </summary>
public static unsafe partial class InteractiveUserHiveResolver
{
    private const string Kernel32Dll = "kernel32.dll";
    private const string WtsApi32Dll = "wtsapi32.dll";
    private const string AdvApi32Dll = "advapi32.dll";

    [LibraryImport(Kernel32Dll)]
    private static partial uint WTSGetActiveConsoleSessionId();

    [LibraryImport(WtsApi32Dll, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool WTSQueryUserToken(uint sessionId, out nint phToken);

    [LibraryImport(AdvApi32Dll, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetTokenInformation(
        nint tokenHandle,
        int tokenInformationClass,
        void* tokenInformation,
        uint tokenInformationLength,
        out uint returnLength);

    [LibraryImport(AdvApi32Dll, EntryPoint = "ConvertSidToStringSidW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool ConvertSidToStringSidW(nint pSid, out nint strSid);

    [LibraryImport(Kernel32Dll)]
    private static partial nint LocalFree(nint hMem);

    [LibraryImport(Kernel32Dll)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseHandle(nint hObject);

    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_USER
    {
        public nint Sid;
        public uint Attributes;
    }

    private const int TokenUserClass = 1;

    /// <summary>
    /// 获取当前活跃桌面会话的 SessionId 与用户 SID 字符串 (如 "S-1-5-21-0000000000-...-1001")
    /// </summary>
    public static (uint SessionId, string? UserSid) TryGetActiveInteractiveUserSid()
    {
        if (!OperatingSystem.IsWindows())
            return (0, null);

        try
        {
            uint sessionId = WTSGetActiveConsoleSessionId();
            if (sessionId == 0xFFFFFFFF)
                return (0, null);

            if (!WTSQueryUserToken(sessionId, out nint hToken) || hToken == 0)
                return (sessionId, null);

            try
            {
                GetTokenInformation(hToken, TokenUserClass, null, 0, out uint neededLen);
                if (neededLen == 0 || neededLen > 4096)
                    return (sessionId, null);

                byte* buffer = stackalloc byte[(int)neededLen];
                if (!GetTokenInformation(hToken, TokenUserClass, buffer, neededLen, out _))
                    return (sessionId, null);

                TOKEN_USER* pTokenUser = (TOKEN_USER*)buffer;
                if (!ConvertSidToStringSidW(pTokenUser->Sid, out nint pStrSid) || pStrSid == 0)
                    return (sessionId, null);

                try
                {
                    string? sidString = Marshal.PtrToStringUni(pStrSid);
                    return (sessionId, sidString);
                }
                finally
                {
                    LocalFree(pStrSid);
                }
            }
            finally
            {
                CloseHandle(hToken);
            }
        }
        catch
        {
            return (0, null);
        }
    }

    /// <summary>
    /// 获取当前系统中所有已加载的用户 Hive SID 集合 (S-1-5-21-*)
    /// 无论物理机、VMware/Hyper-V 还是远程桌面，只要用户登录，其 HKCU 必挂载在 HKEY_USERS\<SID> 下！
    /// </summary>
    public static List<string> GetAllLoadedUserSids()
    {
        var result = new List<string>();
        if (!OperatingSystem.IsWindows())
            return result;

        try
        {
            using var hkUsers = Microsoft.Win32.Registry.Users;
            foreach (string name in hkUsers.GetSubKeyNames())
            {
                // 仅筛选以 S-1-5-21- 开头且不以 _Classes 结尾的真实用户 SID
                if (name.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase) &&
                    !name.EndsWith("_Classes", StringComparison.OrdinalIgnoreCase))
                {
                    result.Add(name);
                }
            }
        }
        catch
        {
            // 防御式容错
        }

        // 若上述枚举为空，尝试通过 WTS 会话补充
        var (_, consoleSid) = TryGetActiveInteractiveUserSid();
        if (!string.IsNullOrEmpty(consoleSid) && !result.Contains(consoleSid, StringComparer.OrdinalIgnoreCase))
        {
            result.Add(consoleSid);
        }

        return result;
    }

    /// <summary>
    /// 将逻辑 HKCU 子路径转换为 HKEY_USERS\&lt;SID&gt; 下的物理路径
    /// </summary>
    public static string ResolveUserRegistryPath(string userSid, string relativeSubKey)
    {
        if (string.IsNullOrWhiteSpace(userSid))
            throw new ArgumentException("Interactive user SID must not be empty.", nameof(userSid));

        return $@"{userSid.Trim()}\{(relativeSubKey ?? string.Empty).TrimStart('\\')}";
    }
}

