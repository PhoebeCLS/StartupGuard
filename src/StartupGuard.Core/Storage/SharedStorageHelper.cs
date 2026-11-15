using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;

namespace StartupGuard.Core.Storage;

/// <summary>
/// 全局统一共享存储与跨特权安全访问辅助器
/// 确保 Windows Service (LocalSystem) 与桌面交互式程序 (非提权标准用户) 统一访问同一份 SQLite 数据库与 MMF 映射
/// </summary>
public static class SharedStorageHelper
{
    private static readonly object LogLock = new();
    private static string? _cachedDataDir;
    private static string? _cachedLogsDir;

    public static bool IsPackagedMsixApp()
    {
        return AppContext.BaseDirectory.Contains(@"\WindowsApps\", StringComparison.OrdinalIgnoreCase);
    }

    public static string GetSafeWorkingDirectory()
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (!string.IsNullOrWhiteSpace(userProfile) && Directory.Exists(userProfile))
            return userProfile;
        return Path.GetTempPath();
    }

    public static string GetSharedDataDirectory()
    {
        if (!string.IsNullOrEmpty(_cachedDataDir) && Directory.Exists(_cachedDataDir))
            return _cachedDataDir;

        string baseDir = OperatingSystem.IsWindows()
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "StartupGuard", "data")
            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "StartupGuard", "data");

        if (EnsureDirectoryWritable(baseDir))
        {
            _cachedDataDir = baseDir;
            return baseDir;
        }

        string fallbackDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "StartupGuard", "data");
        EnsureDirectoryWritable(fallbackDir);
        _cachedDataDir = fallbackDir;
        return fallbackDir;
    }

    public static string GetSharedDatabasePath()
    {
        string dataDir = GetSharedDataDirectory();
        string dbPath = Path.Combine(dataDir, "rules.db");
        EnsureFilePermissions(dbPath);
        return dbPath;
    }

    public static string GetSharedLogsDirectory()
    {
        if (!string.IsNullOrEmpty(_cachedLogsDir) && Directory.Exists(_cachedLogsDir))
            return _cachedLogsDir;

        string logDir = OperatingSystem.IsWindows()
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "StartupGuard", "logs")
            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "StartupGuard", "logs");

        if (EnsureDirectoryWritable(logDir))
        {
            _cachedLogsDir = logDir;
            return logDir;
        }

        string fallbackLogDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "StartupGuard", "logs");
        EnsureDirectoryWritable(fallbackLogDir);
        _cachedLogsDir = fallbackLogDir;
        return fallbackLogDir;
    }

    private static bool EnsureDirectoryWritable(string dirPath)
    {
        try
        {
            if (!Directory.Exists(dirPath))
                Directory.CreateDirectory(dirPath);
            EnsureDirectoryPermissions(dirPath);
            if (!Directory.Exists(dirPath))
                return false;

            string probePath = Path.Combine(dirPath, $".sg_write_probe_{Environment.ProcessId}.tmp");
            using (var fs = new FileStream(probePath, FileMode.Create, FileAccess.Write, FileShare.Delete))
            {
                fs.WriteByte(0);
            }
            File.Delete(probePath);
            return true;
        }
        catch
        {
            return false;
        }
    }

    public static string GetSharedLogDirectory() => GetSharedLogsDirectory();

    public static string GetSharedLogFilePath()
    {
        return Path.Combine(GetSharedLogsDirectory(), "startupguard.log");
    }

    public static void EnsureDirectoryPermissions(string dirPath)
    {
        try
        {
            if (!Directory.Exists(dirPath))
            {
                Directory.CreateDirectory(dirPath);
            }

            if (!OperatingSystem.IsWindows())
                return;

            var dInfo = new DirectoryInfo(dirPath);
            var dSec = dInfo.GetAccessControl();

            // 赋予所有标准用户组 (BuiltinUsersSid) 与 Everyone 完全控制权
            var usersSid = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);
            var worldSid = new SecurityIdentifier(WellKnownSidType.WorldSid, null);

            var ruleUsers = new FileSystemAccessRule(
                usersSid,
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow);

            var ruleWorld = new FileSystemAccessRule(
                worldSid,
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow);

            dSec.AddAccessRule(ruleUsers);
            dSec.AddAccessRule(ruleWorld);
            dInfo.SetAccessControl(dSec);
        }
        catch
        {
            // 忽略权限设定失败（如受限环境）
        }
    }

    public static void EnsureFilePermissions(string filePath)
    {
        try
        {
            if (!OperatingSystem.IsWindows() || !File.Exists(filePath))
                return;

            var fInfo = new FileInfo(filePath);
            var fSec = fInfo.GetAccessControl();

            var usersSid = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);
            var worldSid = new SecurityIdentifier(WellKnownSidType.WorldSid, null);

            fSec.AddAccessRule(new FileSystemAccessRule(usersSid, FileSystemRights.FullControl, AccessControlType.Allow));
            fSec.AddAccessRule(new FileSystemAccessRule(worldSid, FileSystemRights.FullControl, AccessControlType.Allow));
            fInfo.SetAccessControl(fSec);
        }
        catch
        {
        }
    }

    public static void LogDiagnostic(string source, string message)
    {
        try
        {
            if (!StartupGuard.Core.Configuration.UserSettingsStore.GetDiagnosticLoggingEnabled())
                return;

            lock (LogLock)
            {
                string logFile = GetSharedLogFilePath();
                string line = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] [PID:{Environment.ProcessId}|TID:{Environment.CurrentManagedThreadId}] [{source}] {message}{Environment.NewLine}";
                File.AppendAllText(logFile, line);
            }
        }
        catch
        {
        }
    }
}
