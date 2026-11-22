using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Data.Sqlite;
using Microsoft.Win32;
using StartupGuard.Core.Models;
using StartupGuard.Core.Native;
using StartupGuard.Core.Storage;

namespace StartupGuard.Core.Configuration;

/// <summary>
/// 全局用户环境设置持久化管理中心
/// 支持跨会话读写 HKCU\Software\StartupGuard\Settings 与 JSON 文件双轨容灾存储
/// </summary>
public static class UserSettingsStore
{
    private const string RegistrySubKey = @"Software\StartupGuard\Settings";
    private static readonly JsonSerializerOptions IndentedJsonOptions = new() { WriteIndented = true };

    public static string LocalSettingsFilePath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "StartupGuard",
        "settings.json");

    public static string SharedSettingsFilePath => Path.Combine(
        SharedStorageHelper.GetSharedDataDirectory(),
        "settings.json");

    /// <summary>
    /// 读取当前用户或指定用户 SID 的右键菜单拦截策略 (false = 先拦截后审核模式 [默认], true = 弹窗即时审核模式)
    /// </summary>
    public static bool GetContextMenuPromptMode(string? userSid = null)
        => ReadBoolSetting("ContextMenuPromptMode", legacyKey: null, defaultValue: false, userSid: userSid);

    /// <summary>
    /// 写入右键菜单拦截策略
    /// </summary>
    public static void SetContextMenuPromptMode(bool promptMode)
        => WriteBoolSetting("ContextMenuPromptMode", promptMode);

    public static string GetThemePreference()
    {
        string theme = ReadStringSetting("Theme", "System");
        return string.IsNullOrWhiteSpace(theme) ? "System" : theme;
    }

    public static void SetThemePreference(string theme)
        => WriteStringSetting("Theme", theme);

    /// <summary>
    /// 检测当前 Windows 系统应用主题是否为浅色模式（AppsUseLightTheme != 0）。
    /// </summary>
    public static bool IsSystemAppsLightTheme()
    {
        if (!OperatingSystem.IsWindows())
            return true;

        try
        {
            using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize", false);
            if (key?.GetValue("AppsUseLightTheme") is int val)
                return val != 0;
        }
        catch { }

        return true;
    }

    /// <summary>
    /// 根据应用内主题偏好（Light/Dark/System）解析当前生效的浅色/深色状态。
    /// </summary>
    public static bool IsEffectiveLightTheme()
    {
        string pref = GetThemePreference();
        if (string.Equals(pref, "Light", StringComparison.OrdinalIgnoreCase))
            return true;
        if (string.Equals(pref, "Dark", StringComparison.OrdinalIgnoreCase))
            return false;
        return IsSystemAppsLightTheme();
    }

    public static bool GetHideMicrosoftPreference()
        => ReadBoolSetting("HideMicrosoft", legacyKey: null, defaultValue: true);

    public static void SetHideMicrosoftPreference(bool hide)
        => WriteBoolSetting("HideMicrosoft", hide);

    public static bool GetHideContextMenuSystemPreference()
        => ReadBoolSetting("HideContextMenuSystem", legacyKey: null, defaultValue: false);

    public static void SetHideContextMenuSystemPreference(bool hide)
        => WriteBoolSetting("HideContextMenuSystem", hide);

    public static int GetLogRetentionDays()
    {
        int val = ReadIntSetting("LogRetentionDays", 30);
        return val <= 0 ? 30 : val;
    }

    public static void SetLogRetentionDays(int days)
        => WriteIntSetting("LogRetentionDays", days <= 0 ? 30 : days);

    public static bool GetLogPermanentRetention(string? userSid = null)
    {
        if (!string.IsNullOrEmpty(userSid))
        {
            if (TryReadJsonBool(SharedSettingsFilePath, "LogPermanentRetention", out bool sharedPerm))
                return sharedPerm;
            if (TryReadJsonInt(SharedSettingsFilePath, "LogRetentionDays", out int sharedDays) && sharedDays == 0)
                return true;
        }

        if (OperatingSystem.IsWindows())
        {
            try
            {
                using var key = !string.IsNullOrEmpty(userSid)
                    ? Registry.Users.OpenSubKey($@"{userSid}\{RegistrySubKey}")
                    : Registry.CurrentUser.OpenSubKey(RegistrySubKey);
                if (key?.GetValue("LogPermanentRetention") is int val)
                    return val == 1;
                if (key?.GetValue("LogRetentionDays") is int legacyDays && legacyDays == 0)
                    return true;
            }
            catch { }
        }

        foreach (string path in new[] { LocalSettingsFilePath, SharedSettingsFilePath })
        {
            if (TryReadJsonBool(path, "LogPermanentRetention", out bool perm))
                return perm;
            if (TryReadJsonInt(path, "LogRetentionDays", out int days) && days == 0)
                return true;
        }

        return false;
    }

    public static void SetLogPermanentRetention(bool permanent)
        => WriteBoolSetting("LogPermanentRetention", permanent);

    public static int GetLogMaxCount()
        => ReadIntSetting("LogMaxCount", 1000);

    public static void SetLogMaxCount(int maxCount)
        => WriteIntSetting("LogMaxCount", maxCount);

    private sealed record CachedJsonSettings(long CheckedTickMs, long LastWriteUtcTicks, long FileLength, Dictionary<string, object> Values);
    private static readonly ConcurrentDictionary<string, CachedJsonSettings> _jsonCache = new(StringComparer.OrdinalIgnoreCase);
    private static readonly object _diagCacheLock = new();
    private static long _diagCachedUntilTickMs;
    private static bool _diagCachedValue;

    public static bool GetDiagnosticLoggingEnabled()
    {
        long nowTick = Environment.TickCount64;
        lock (_diagCacheLock)
        {
            if (nowTick < _diagCachedUntilTickMs)
                return _diagCachedValue;
        }

        bool val = ReadBoolSetting("DiagnosticLogging", legacyKey: null, defaultValue: false);
        lock (_diagCacheLock)
        {
            _diagCachedValue = val;
            _diagCachedUntilTickMs = Environment.TickCount64 + 2000;
        }
        return val;
    }

    public static void SetDiagnosticLoggingEnabled(bool enabled)
    {
        WriteBoolSetting("DiagnosticLogging", enabled);
        lock (_diagCacheLock)
        {
            _diagCachedValue = enabled;
            _diagCachedUntilTickMs = Environment.TickCount64 + 2000;
        }
    }

    public static bool GetMd5ValidationEnabled()
        => ReadBoolSetting("Md5ValidationEnabled", legacyKey: null, defaultValue: true);

    public static void SetMd5ValidationEnabled(bool enabled)
        => WriteBoolSetting("Md5ValidationEnabled", enabled);

    public static int GetMd5ValidationIntervalDays()
    {
        int val = ReadIntSetting("Md5ValidationIntervalDays", 3);
        return Math.Clamp(val <= 0 ? 3 : val, 1, 360);
    }

    public static void SetMd5ValidationIntervalDays(int days)
        => WriteIntSetting("Md5ValidationIntervalDays", Math.Clamp(days, 1, 360));

    /// <summary>
    /// 读取拦截与自动阻止系统通知开关 (覆盖规则自动拦截与右键菜单先拦截后审核)
    /// </summary>
    public static bool GetBlockedNotificationsEnabled(string? userSid = null)
    {
        return GetRuleHitNotificationsEnabled(userSid) || GetContextMenuNotificationsEnabled(userSid);
    }

    public static void SetBlockedNotificationsEnabled(bool enabled)
    {
        SetRuleHitNotificationsEnabled(enabled);
        SetContextMenuNotificationsEnabled(enabled);
    }

    /// <summary>
    /// 读取「命中规则拦截」桌面通知开关（默认开启，兼容读取旧 BlockedNotifications 配置）
    /// </summary>
    public static bool GetRuleHitNotificationsEnabled(string? userSid = null)
        => ReadBoolSetting("RuleHitNotifications", legacyKey: "BlockedNotifications", defaultValue: true, userSid: userSid);

    public static void SetRuleHitNotificationsEnabled(bool enabled)
        => WriteBoolSetting("RuleHitNotifications", enabled);

    /// <summary>
    /// 读取「右键菜单静默拦截」桌面通知开关（默认开启，兼容读取旧 BlockedNotifications 配置）
    /// </summary>
    public static bool GetContextMenuNotificationsEnabled(string? userSid = null)
        => ReadBoolSetting("ContextMenuNotifications", legacyKey: "BlockedNotifications", defaultValue: true, userSid: userSid);

    public static void SetContextMenuNotificationsEnabled(bool enabled)
        => WriteBoolSetting("ContextMenuNotifications", enabled);

    /// <summary>
    /// 在“弹窗即时审核”模式下返回 false，但保留用户在“先拦截后审核”下的通知开关设定。
    /// </summary>
    public static bool GetEffectiveContextMenuNotificationsEnabled(bool promptMode, string? userSid = null)
        => !promptMode && GetContextMenuNotificationsEnabled(userSid);

    private static bool ReadBoolSetting(string regValueName, string? legacyKey, bool defaultValue, string? userSid = null)
    {
        if (!string.IsNullOrEmpty(userSid))
        {
            if (TryReadJsonBool(SharedSettingsFilePath, regValueName, out bool sharedVal))
                return sharedVal;
            if (!string.IsNullOrEmpty(legacyKey) && TryReadJsonBool(SharedSettingsFilePath, legacyKey, out bool sharedLegacy))
                return sharedLegacy;
        }

        if (OperatingSystem.IsWindows())
        {
            try
            {
                using var key = !string.IsNullOrEmpty(userSid)
                    ? Registry.Users.OpenSubKey($@"{userSid}\{RegistrySubKey}")
                    : Registry.CurrentUser.OpenSubKey(RegistrySubKey);
                if (key?.GetValue(regValueName) is int val)
                    return val == 1;
                if (!string.IsNullOrEmpty(legacyKey) && key?.GetValue(legacyKey) is int legacyVal)
                    return legacyVal == 1;
            }
            catch { }
        }

        foreach (string path in new[] { LocalSettingsFilePath, SharedSettingsFilePath })
        {
            if (TryReadJsonBool(path, regValueName, out bool localVal))
                return localVal;
            if (!string.IsNullOrEmpty(legacyKey) && TryReadJsonBool(path, legacyKey, out bool localLegacy))
                return localLegacy;
        }

        return defaultValue;
    }

    private static void WriteBoolSetting(string regValueName, bool enabled)
    {
        if (OperatingSystem.IsWindows())
        {
            try
            {
                using var key = Registry.CurrentUser.CreateSubKey(RegistrySubKey);
                key?.SetValue(regValueName, enabled ? 1 : 0, RegistryValueKind.DWord);
            }
            catch { }
        }

        UpdateJsonSettings(dict => dict[regValueName] = enabled);
    }

    private static void InvalidateSettingsCaches()
    {
        _jsonCache.Clear();
        lock (_diagCacheLock)
        {
            _diagCachedUntilTickMs = 0;
        }
    }

    /// <summary>
    /// 清理运行日志、崩溃日志与临时探测缓存（不删除规则数据库和用户设置）
    /// </summary>
    public static (int DeletedFiles, long FreedBytes) PurgeLocalLogsAndCaches()
    {
        InvalidateSettingsCaches();
        int deletedFiles = 0;
        long freedBytes = 0;

        string[] logDirs =
        [
            SharedStorageHelper.GetSharedLogsDirectory(),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "StartupGuard", "logs"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "StartupGuard", "cache"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "StartupGuard", "cache")
        ];

        foreach (string dir in logDirs.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (string.IsNullOrWhiteSpace(dir) || !Directory.Exists(dir))
                continue;
            try
            {
                foreach (string file in Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories))
                {
                    try
                    {
                        var fi = new FileInfo(file);
                        long len = fi.Exists ? fi.Length : 0;
                        fi.IsReadOnly = false;
                        File.Delete(file);
                        deletedFiles++;
                        freedBytes += len;
                    }
                    catch
                    {
                        // 若日志文件正被系统服务独占锁定，尝试截断清空而非跳过
                        try
                        {
                            long prevLen = new FileInfo(file).Length;
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Write, FileShare.ReadWrite);
                            fs.SetLength(0);
                            if (prevLen > 0)
                            {
                                deletedFiles++;
                                freedBytes += prevLen;
                            }
                        }
                        catch { }
                    }
                }
            }
            catch { }
        }

        return (deletedFiles, freedBytes);
    }

    /// <summary>
    /// 卸载前彻底清理当前用户及公共数据目录与 HKCU\Software\StartupGuard 注册表项，防止卸载残留
    /// </summary>
    public static int PurgeAllUserAndSharedDataForUninstall()
    {
        InvalidateSettingsCaches();
        int removedCount = 0;
        if (OperatingSystem.IsWindows())
        {
            try
            {
                Registry.CurrentUser.DeleteSubKeyTree("Software\\StartupGuard", throwOnMissingSubKey: false);
                removedCount++;
            }
            catch { }

            try
            {
                Registry.LocalMachine.DeleteSubKeyTree("Software\\StartupGuard", throwOnMissingSubKey: false);
                removedCount++;
            }
            catch { }
        }

        try { SqliteConnection.ClearAllPools(); } catch { }

        string? sharedDataParent = Directory.GetParent(SharedStorageHelper.GetSharedDataDirectory())?.FullName;
        string? sharedLogsParent = Directory.GetParent(SharedStorageHelper.GetSharedLogsDirectory())?.FullName;

        string?[] dirsToDelete =
        [
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "StartupGuard"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "StartupGuard"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "StartupGuard"),
            sharedDataParent,
            sharedLogsParent,
            SharedStorageHelper.GetSharedDataDirectory()
        ];

        foreach (string dir in dirsToDelete
                     .Where(static p => !string.IsNullOrWhiteSpace(p))
                     .Select(static p => p!)
                     .Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (PurgeDirectoryCompletely(dir))
                removedCount++;
        }

        return removedCount;
    }

    /// <summary>
    /// 彻底清除指定目录及其全部子文件、子目录与根目录自身（含清除文件属性与释放 SQLite 连接池）
    /// </summary>
    public static bool PurgeDirectoryCompletely(string? dir)
    {
        if (string.IsNullOrWhiteSpace(dir))
            return false;

        try { SqliteConnection.ClearAllPools(); } catch { }
        if (!Directory.Exists(dir))
            return false;

        for (int attempt = 0; attempt < 3; attempt++)
        {
            try
            {
                ClearDirectoryAttributes(dir);
                Directory.Delete(dir, recursive: true);
            }
            catch
            {
                DeleteFilesAndSubdirectoriesBestEffort(dir);
            }

            if (!Directory.Exists(dir))
                return true;

            if (attempt < 2)
                Thread.Sleep(150);
        }

        return !Directory.Exists(dir);
    }

    private static void ClearDirectoryAttributes(string dir)
    {
        try
        {
            var dirInfo = new DirectoryInfo(dir);
            if ((dirInfo.Attributes & (FileAttributes.ReadOnly | FileAttributes.Hidden | FileAttributes.System)) != 0)
                dirInfo.Attributes = FileAttributes.Normal;
        }
        catch { }

        try
        {
            foreach (string entry in Directory.EnumerateFileSystemEntries(dir, "*", SearchOption.AllDirectories))
            {
                try { File.SetAttributes(entry, FileAttributes.Normal); } catch { }
            }
        }
        catch { }
    }

    private static void DeleteFilesAndSubdirectoriesBestEffort(string dir)
    {
        try
        {
            foreach (string file in Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories))
            {
                try { File.SetAttributes(file, FileAttributes.Normal); File.Delete(file); } catch { }
            }
            foreach (string subDir in Directory.EnumerateDirectories(dir, "*", SearchOption.AllDirectories)
                         .OrderByDescending(static p => p.Length))
            {
                try { File.SetAttributes(subDir, FileAttributes.Normal); Directory.Delete(subDir, recursive: true); } catch { }
            }
            try { File.SetAttributes(dir, FileAttributes.Normal); Directory.Delete(dir, recursive: true); } catch { }
        }
        catch { }
    }

    public static bool GetMd5ValidationIdleOnly()
        => ReadBoolSetting("Md5ValidationIdleOnly", legacyKey: null, defaultValue: true);

    public static void SetMd5ValidationIdleOnly(bool idleOnly)
        => WriteBoolSetting("Md5ValidationIdleOnly", idleOnly);

    public static DateTime GetLastMd5ValidationTime()
    {
        string s = ReadStringSetting("LastMd5ValidationTime", string.Empty);
        return DateTime.TryParse(s, out var dt) ? dt : DateTime.MinValue;
    }

    public static void SetLastMd5ValidationTime(DateTime time)
        => WriteStringSetting("LastMd5ValidationTime", time.ToString("o"));

    public static InterceptionAction GetDefaultPopupAction(MonitorCategory category)
    {
        string raw = ReadStringSetting($"DefaultPopupAction_{category}", string.Empty);
        if (Enum.TryParse<InterceptionAction>(raw, ignoreCase: true, out var parsed) &&
            parsed != InterceptionAction.Allow)
        {
            return parsed;
        }
        return InterceptionAction.RollbackToDisabled;
    }

    public static void SetDefaultPopupAction(MonitorCategory category, InterceptionAction action)
    {
        var safeAction = action == InterceptionAction.Allow ? InterceptionAction.RollbackToDisabled : action;
        WriteStringSetting($"DefaultPopupAction_{category}", safeAction.ToString());
    }

    private static int ReadIntSetting(string regValueName, int defaultValue)
    {
        if (OperatingSystem.IsWindows())
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(RegistrySubKey);
                if (key?.GetValue(regValueName) is int val)
                    return val;
            }
            catch { }
        }

        foreach (string path in new[] { LocalSettingsFilePath, SharedSettingsFilePath })
        {
            if (TryReadJsonInt(path, regValueName, out int val))
                return val;
        }

        return defaultValue;
    }

    private static void WriteIntSetting(string regValueName, int value)
    {
        if (OperatingSystem.IsWindows())
        {
            try
            {
                using var key = Registry.CurrentUser.CreateSubKey(RegistrySubKey);
                key?.SetValue(regValueName, value, RegistryValueKind.DWord);
            }
            catch { }
        }

        UpdateJsonSettings(obj => obj[regValueName] = value);
    }

    private static string ReadStringSetting(string regValueName, string defaultValue)
    {
        if (OperatingSystem.IsWindows())
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(RegistrySubKey);
                if (key?.GetValue(regValueName) is string s && !string.IsNullOrWhiteSpace(s))
                    return s;
            }
            catch { }
        }

        foreach (string path in new[] { LocalSettingsFilePath, SharedSettingsFilePath })
        {
            if (TryReadJsonString(path, regValueName, out string s))
                return s;
        }

        return defaultValue;
    }

    private static void WriteStringSetting(string regValueName, string value)
    {
        if (OperatingSystem.IsWindows())
        {
            try
            {
                using var key = Registry.CurrentUser.CreateSubKey(RegistrySubKey);
                key?.SetValue(regValueName, value, RegistryValueKind.String);
            }
            catch { }
        }

        UpdateJsonSettings(obj => obj[regValueName] = value);
    }

    private static Dictionary<string, object>? TryGetCachedJsonValues(string path)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(path))
                return null;

            long nowTick = Environment.TickCount64;
            if (_jsonCache.TryGetValue(path, out var existing) &&
                nowTick - existing.CheckedTickMs < 1500)
            {
                return existing.Values;
            }

            if (!File.Exists(path))
            {
                _jsonCache.TryRemove(path, out _);
                return null;
            }

            var fi = new FileInfo(path);
            long writeTicks = fi.LastWriteTimeUtc.Ticks;
            long fileLen = fi.Length;

            if (existing != null &&
                existing.LastWriteUtcTicks == writeTicks &&
                existing.FileLength == fileLen)
            {
                _jsonCache[path] = existing with { CheckedTickMs = nowTick };
                return existing.Values;
            }

            using var doc = JsonDocument.Parse(File.ReadAllText(path));
            var dict = new Dictionary<string, object>(StringComparer.Ordinal);
            if (doc.RootElement.ValueKind == JsonValueKind.Object)
            {
                foreach (var prop in doc.RootElement.EnumerateObject())
                {
                    switch (prop.Value.ValueKind)
                    {
                        case JsonValueKind.True:
                            dict[prop.Name] = true;
                            break;
                        case JsonValueKind.False:
                            dict[prop.Name] = false;
                            break;
                        case JsonValueKind.Number when prop.Value.TryGetInt32(out int intVal):
                            dict[prop.Name] = intVal;
                            break;
                        case JsonValueKind.String:
                            string? s = prop.Value.GetString();
                            if (s != null)
                                dict[prop.Name] = s;
                            break;
                    }
                }
            }

            _jsonCache[path] = new CachedJsonSettings(nowTick, writeTicks, fileLen, dict);
            return dict;
        }
        catch
        {
            return null;
        }
    }

    private static bool TryReadJsonBool(string path, string key, out bool value)
    {
        value = false;
        var dict = TryGetCachedJsonValues(path);
        if (dict != null && dict.TryGetValue(key, out object? obj) && obj is bool b)
        {
            value = b;
            return true;
        }
        return false;
    }

    private static bool TryReadJsonInt(string path, string key, out int value)
    {
        value = 0;
        var dict = TryGetCachedJsonValues(path);
        if (dict != null && dict.TryGetValue(key, out object? obj) && obj is int i)
        {
            value = i;
            return true;
        }
        return false;
    }

    private static bool TryReadJsonString(string path, string key, out string value)
    {
        value = string.Empty;
        var dict = TryGetCachedJsonValues(path);
        if (dict != null && dict.TryGetValue(key, out object? obj) && obj is string s && !string.IsNullOrWhiteSpace(s))
        {
            value = s;
            return true;
        }
        return false;
    }

    private static void UpdateJsonSettings(Action<JsonObject> modifier)
    {
        WriteJsonSettingsToPath(LocalSettingsFilePath, modifier, ensureSharedAcl: false);
        WriteJsonSettingsToPath(SharedSettingsFilePath, modifier, ensureSharedAcl: true);
    }

    private static void WriteJsonSettingsToPath(string path, Action<JsonObject> modifier, bool ensureSharedAcl)
    {
        try
        {
            string? dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(dir))
                Directory.CreateDirectory(dir);

            JsonObject root = [];
            if (File.Exists(path))
            {
                try
                {
                    if (JsonNode.Parse(File.ReadAllText(path)) is JsonObject existing)
                        root = existing;
                }
                catch { }
            }

            modifier(root);
            File.WriteAllText(path, root.ToJsonString(IndentedJsonOptions));
            _jsonCache.TryRemove(path, out _);
            if (ensureSharedAcl)
                SharedStorageHelper.EnsureFilePermissions(path);
        }
        catch { }
    }
}
