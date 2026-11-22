using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using StartupGuard.Core.ContextMenu;
using StartupGuard.Core.Models;
using StartupGuard.Core.Scoring;

namespace StartupGuard.Core.Native;

/// <summary>
/// 跨模块共享的文件定位、注册表跳转、Shell 属性框与在线搜索辅助类
/// </summary>
public static unsafe partial class ShellNavigationHelper
{
    [StructLayout(LayoutKind.Sequential)]
    private struct SHELLEXECUTEINFOW
    {
        public int cbSize;
        public uint fMask;
        public nint hwnd;
        public char* lpVerb;
        public char* lpFile;
        public char* lpParameters;
        public char* lpDirectory;
        public int nShow;
        public nint hInstApp;
        public nint lpIDList;
        public char* lpClass;
        public nint hkeyClass;
        public uint dwHotKey;
        public nint hIconOrMonitor;
        public nint hProcess;
    }

    [LibraryImport("shell32.dll", EntryPoint = "ShellExecuteExW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool ShellExecuteExW(SHELLEXECUTEINFOW* lpExecInfo);

    private const uint SEE_MASK_INVOKEIDLIST = 0x0000000C;
    private const int SW_SHOW = 5;

    private static bool ContainsWildcardTemplate(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return false;

        return path.Contains("<ver>", StringComparison.OrdinalIgnoreCase) ||
               path.Contains("<hash>", StringComparison.OrdinalIgnoreCase) ||
               path.Contains("<guid>", StringComparison.OrdinalIgnoreCase) ||
               path.Contains("<user>", StringComparison.OrdinalIgnoreCase) ||
               path.Contains("<drive>", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// 将规则中保存的归一化占位符（&lt;drive&gt;: 与 &lt;user&gt;）展开为当前系统真实路径，避免在界面和校验中出现原始占位符
    /// </summary>
    public static string ExpandNormalizedPathTemplate(string? pathOrCommand)
    {
        if (string.IsNullOrWhiteSpace(pathOrCommand))
            return string.Empty;

        string expanded = pathOrCommand.Trim();
        if (!string.IsNullOrWhiteSpace(Environment.UserName))
            expanded = expanded.Replace(@"\<user>\", $@"\{Environment.UserName}\", StringComparison.OrdinalIgnoreCase);

        if (!expanded.Contains("<drive>:", StringComparison.OrdinalIgnoreCase))
            return expanded;

        string systemDrive = Path.GetPathRoot(Environment.SystemDirectory)?.TrimEnd('\\', '/') ?? "C:";
        if (string.IsNullOrWhiteSpace(systemDrive))
            systemDrive = "C:";

        string systemCandidate = expanded.Replace("<drive>:", systemDrive, StringComparison.OrdinalIgnoreCase);
        try
        {
            string splitExe = PathNormalizerAndSimilarity
                .SplitCommandLine(Environment.ExpandEnvironmentVariables(systemCandidate))
                .ExecutablePath;
            if (string.IsNullOrWhiteSpace(splitExe))
                splitExe = systemCandidate.Trim('"');

            string suffix = splitExe.StartsWith(systemDrive, StringComparison.OrdinalIgnoreCase) && splitExe.Length > systemDrive.Length
                ? splitExe[systemDrive.Length..]
                : string.Empty;

            if (!string.IsNullOrEmpty(suffix) && !ContainsWildcardTemplate(suffix))
            {
                foreach (DriveInfo drive in DriveInfo.GetDrives())
                {
                    try
                    {
                        if (!drive.IsReady || drive.DriveType != DriveType.Fixed)
                            continue;
                        string driveRoot = drive.Name.TrimEnd('\\', '/');
                        string probe = driveRoot + suffix;
                        if (File.Exists(probe) || Directory.Exists(probe))
                            return expanded.Replace("<drive>:", driveRoot, StringComparison.OrdinalIgnoreCase);
                    }
                    catch { }
                }

                string? parentRel = Path.GetDirectoryName(suffix);
                if (!string.IsNullOrEmpty(parentRel) && parentRel.Trim('\\').Contains('\\'))
                {
                    foreach (DriveInfo drive in DriveInfo.GetDrives())
                    {
                        try
                        {
                            if (!drive.IsReady || drive.DriveType != DriveType.Fixed)
                                continue;
                            string driveRoot = drive.Name.TrimEnd('\\', '/');
                            if (Directory.Exists(driveRoot + parentRel))
                                return expanded.Replace("<drive>:", driveRoot, StringComparison.OrdinalIgnoreCase);
                        }
                        catch { }
                    }
                }
            }
        }
        catch { }

        return systemCandidate;
    }

    /// <summary>
    /// 综合 RawCommand、NormalizedPath 与 LocationKey 解析规则对应的物理文件路径
    /// </summary>
    public static string ResolveRuleTargetFilePath(string? rawCommand, string? normalizedPath, string? locationKey = null)
    {
        string preferred = !string.IsNullOrWhiteSpace(rawCommand) && !ContainsWildcardTemplate(rawCommand)
            ? rawCommand
            : (!string.IsNullOrWhiteSpace(rawCommand) ? rawCommand : (normalizedPath ?? string.Empty));

        string expanded = ExpandNormalizedPathTemplate(preferred);
        string resolved = ResolvePhysicalFilePath(expanded);

        if ((string.IsNullOrWhiteSpace(resolved) || !File.Exists(resolved)) &&
            !string.IsNullOrWhiteSpace(locationKey) &&
            (locationKey.StartsWith("Approved:", StringComparison.OrdinalIgnoreCase) ||
             locationKey.StartsWith("Win11Modern:", StringComparison.OrdinalIgnoreCase) ||
             (locationKey.Trim().StartsWith('{') && locationKey.Trim().EndsWith('}'))))
        {
            string fromLoc = ResolvePhysicalFilePath(locationKey);
            if (!string.IsNullOrWhiteSpace(fromLoc))
                return fromLoc;
        }

        return resolved;
    }

    /// <summary>
    /// 从命令行、驱动路径或 CLSID 解析物理文件真实路径（优先解析真实 DLL/EXE 与 App Paths）
    /// </summary>
    public static string ResolvePhysicalFilePath(string? commandOrPath)
    {
        if (string.IsNullOrWhiteSpace(commandOrPath))
            return string.Empty;

        string trimmed = ExpandNormalizedPathTemplate(commandOrPath);
        if (trimmed.StartsWith("Approved:", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("Win11Modern:", StringComparison.OrdinalIgnoreCase) ||
            (trimmed.StartsWith('{') && trimmed.EndsWith('}')))
        {
            string clsid = PrivilegedRollbackEngine.ExtractClsidOrIdentifier(trimmed);
            string resolvedClsidPath = ContextMenuGuidResolver.GetClsidFilePath(clsid);
            if (!string.IsNullOrWhiteSpace(resolvedClsidPath))
                return resolvedClsidPath;
        }

        string extracted = ContextMenuGuidResolver.ExtractPhysicalFilePath(trimmed);
        if (!string.IsNullOrWhiteSpace(extracted) && (File.Exists(extracted) || Directory.Exists(extracted)))
            return extracted;

        string raw = Environment.ExpandEnvironmentVariables(trimmed);
        string exe = PathNormalizerAndSimilarity.SplitCommandLine(raw).ExecutablePath;
        if (string.IsNullOrWhiteSpace(exe))
            exe = raw.Trim('"');

        if (exe.StartsWith(@"\??\", StringComparison.OrdinalIgnoreCase))
            exe = exe[4..];

        string winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (exe.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
            exe = Path.Combine(winDir, exe[12..]);
        else if (exe.StartsWith(@"System32\", StringComparison.OrdinalIgnoreCase) ||
                 exe.StartsWith(@"SysWOW64\", StringComparison.OrdinalIgnoreCase))
            exe = Path.Combine(winDir, exe);

        exe = exe.Trim('"');
        if (File.Exists(exe) || Directory.Exists(exe))
            return exe;

        // 兜底检查 System32、drivers 与 .sys/.exe 缺省扩展名
        string sys32Dir = Environment.GetFolderPath(Environment.SpecialFolder.System);
        if (!exe.Contains('\\') && !exe.Contains('/'))
        {
            string sys32 = Path.Combine(sys32Dir, exe);
            if (File.Exists(sys32))
                return sys32;
        }
        else if (!string.IsNullOrEmpty(exe))
        {
            string fileName = Path.GetFileName(exe);
            if (!string.IsNullOrEmpty(fileName))
            {
                string inSys32 = Path.Combine(sys32Dir, fileName);
                if (File.Exists(inSys32)) return inSys32;

                string inDrivers = Path.Combine(sys32Dir, "drivers", fileName);
                if (File.Exists(inDrivers)) return inDrivers;
                if (File.Exists(inDrivers + ".sys")) return inDrivers + ".sys";
            }
            if (File.Exists(exe + ".sys")) return exe + ".sys";
            if (File.Exists(exe + ".exe")) return exe + ".exe";
        }

        return exe;
    }

    private static void StartShellProcess(string fileName, string arguments = "", string? workingDirectory = null)
    {
        string safeCwd = !string.IsNullOrWhiteSpace(workingDirectory) && Directory.Exists(workingDirectory)
            ? workingDirectory
            : Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        using var proc = Process.Start(new ProcessStartInfo
        {
            FileName = fileName,
            Arguments = arguments,
            WorkingDirectory = safeCwd,
            UseShellExecute = true
        });
    }

    /// <summary>
    /// 优先在资源管理器中选中真实物理文件（DLL/EXE）；若无物理文件或位于 MSIX 受限目录，则回退到打开其存储或注册表位置
    /// </summary>
    public static bool OpenFileLocationOrFallback(string? commandOrPath, string? locationKey, MonitorCategory category)
    {
        string resolved = ResolvePhysicalFilePath(commandOrPath);
        if ((string.IsNullOrWhiteSpace(resolved) || !File.Exists(resolved)) && !string.IsNullOrWhiteSpace(locationKey))
        {
            string clsid = PrivilegedRollbackEngine.ExtractClsidOrIdentifier(locationKey);
            if (!string.IsNullOrWhiteSpace(clsid))
            {
                string clsidPath = ContextMenuGuidResolver.GetClsidFilePath(clsid);
                if (!string.IsNullOrWhiteSpace(clsidPath) && File.Exists(clsidPath))
                    resolved = clsidPath;
            }
            else if (locationKey.Contains(@"\Services\", StringComparison.OrdinalIgnoreCase) &&
                     category is MonitorCategory.Win32Service or MonitorCategory.KernelDriver)
            {
                string svcName = PrivilegedRollbackEngine.ExtractLeafKeyName(locationKey);
                try
                {
                    using var svcKey = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{svcName}", false);
                    string? img = svcKey?.GetValue("ImagePath")?.ToString();
                    string fromSvc = ResolvePhysicalFilePath(img);
                    if (!string.IsNullOrWhiteSpace(fromSvc) && File.Exists(fromSvc))
                        resolved = fromSvc;
                }
                catch { }
            }
        }

        try
        {
            if (!string.IsNullOrEmpty(resolved) &&
                !resolved.Contains(@"\WindowsApps\", StringComparison.OrdinalIgnoreCase))
            {
                if (File.Exists(resolved))
                {
                    StartShellProcess("explorer.exe", $"/select,\"{resolved}\"", Path.GetDirectoryName(resolved));
                    return true;
                }
                if (Directory.Exists(resolved))
                {
                    StartShellProcess("explorer.exe", $"\"{resolved}\"", resolved);
                    return true;
                }

                string? dir = Path.GetDirectoryName(resolved);
                if (!string.IsNullOrEmpty(dir) && Directory.Exists(dir))
                {
                    StartShellProcess("explorer.exe", $"\"{dir}\"", dir);
                    return true;
                }
            }
        }
        catch { }

        return LocateStorageLocation(locationKey, commandOrPath, category);
    }

    /// <summary>
    /// 打开自启项/右键菜单的存储位置（注册表项定位到 Regedit，文件路径定位到资源管理器）
    /// </summary>
    public static bool LocateStorageLocation(string? locationKey, string? commandOrPath, MonitorCategory category)
    {
        if (!OperatingSystem.IsWindows())
            return false;

        string loc = (locationKey ?? string.Empty).Trim();

        if (!string.IsNullOrEmpty(loc) &&
            !loc.Contains(@"\WindowsApps\", StringComparison.OrdinalIgnoreCase) &&
            (File.Exists(loc) || Directory.Exists(loc)))
        {
            try
            {
                string? dir = Directory.Exists(loc) ? loc : Path.GetDirectoryName(loc);
                StartShellProcess("explorer.exe", File.Exists(loc) ? $"/select,\"{loc}\"" : $"\"{loc}\"", dir);
                return true;
            }
            catch { }
        }

        if (loc.StartsWith("Task:", StringComparison.OrdinalIgnoreCase))
        {
            string taskRel = loc[5..].Trim().TrimStart('\\');
            if (!string.IsNullOrEmpty(taskRel))
            {
                string taskCacheRegPath = $@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\{taskRel}";
                if (LocateInRegistry(taskCacheRegPath))
                    return true;

                string taskFile = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), @"System32\Tasks", taskRel);
                if (File.Exists(taskFile))
                {
                    try
                    {
                        StartShellProcess("explorer.exe", $"/select,\"{taskFile}\"", Path.GetDirectoryName(taskFile));
                        return true;
                    }
                    catch { }
                }
            }
        }

        if (loc.StartsWith("UWPStartup:", StringComparison.OrdinalIgnoreCase))
        {
            return OpenManagementConsole(MonitorCategory.StartupItem, loc, commandOrPath);
        }

        if (!string.IsNullOrEmpty(loc))
        {
            return LocateInRegistry(loc);
        }

        string resolved = ResolvePhysicalFilePath(commandOrPath);
        if (!string.IsNullOrEmpty(resolved) &&
            !resolved.Contains(@"\WindowsApps\", StringComparison.OrdinalIgnoreCase) &&
            File.Exists(resolved))
        {
            try
            {
                StartShellProcess("explorer.exe", $"/select,\"{resolved}\"", Path.GetDirectoryName(resolved));
                return true;
            }
            catch { }
        }

        return false;
    }

    /// <summary>
    /// 打开对应项目的系统管理控制台（services.msc / taskschd.msc / 任务管理器或系统启动设置）
    /// </summary>
    public static bool OpenManagementConsole(MonitorCategory category, string? locationKey, string? commandOrPath)
    {
        if (!OperatingSystem.IsWindows())
            return false;

        string loc = (locationKey ?? string.Empty).Trim();
        try
        {
            if (category == MonitorCategory.ScheduledTask || loc.StartsWith("Task:", StringComparison.OrdinalIgnoreCase))
            {
                StartShellProcess("taskschd.msc", "/s");
                return true;
            }

            if (category == MonitorCategory.Win32Service || category == MonitorCategory.KernelDriver)
            {
                StartShellProcess("services.msc");
                return true;
            }

            if (category == MonitorCategory.StartupItem)
            {
                try
                {
                    StartShellProcess("ms-settings:startupapps");
                    return true;
                }
                catch
                {
                    StartShellProcess("taskmgr.exe");
                    return true;
                }
            }

            return LocateStorageLocation(locationKey, commandOrPath, category);
        }
        catch
        {
            return LocateStorageLocation(locationKey, commandOrPath, category);
        }
    }

    /// <summary>
    /// 精准跳转到 Windows 注册表编辑器指定键（自动处理值名尾缀、多语言根名以及不存在键的父键回溯）
    /// </summary>
    public static bool LocateInRegistry(string? regPath)
    {
        if (string.IsNullOrWhiteSpace(regPath) || !OperatingSystem.IsWindows())
            return false;

        try
        {
            string normalized = NormalizeFullRegistryPath(regPath);
            string existingKeyPath = FindDeepestExistingRegistryPath(normalized);

            bool anyRegeditLeft = false;
            try
            {
                foreach (var p in Process.GetProcessesByName("regedit"))
                {
                    try { p.Kill(); p.WaitForExit(300); }
                    catch { anyRegeditLeft = true; }
                    finally { p.Dispose(); }
                }
            }
            catch { }

            using var regeditKey = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Applets\Regedit");
            if (regeditKey != null)
            {
                string computerRoot = ResolveLocalizedRegeditRoot(regeditKey);
                regeditKey.SetValue("LastKey", $"{computerRoot}\\{existingKeyPath}", RegistryValueKind.String);
            }

            using var proc = Process.Start(new ProcessStartInfo
            {
                FileName = "regedit.exe",
                Arguments = anyRegeditLeft ? "-m" : string.Empty,
                WorkingDirectory = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                UseShellExecute = true
            });
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static string StripComputerPrefix(string path)
    {
        foreach (string prefix in new[] { @"计算机\", @"電腦\", @"Computer\" })
        {
            if (path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                return path[prefix.Length..];
        }
        return path;
    }

    /// <summary>
    /// 将任意形式的注册表路径规范化为以完整根键（HKEY_...）开头且去除 ::ValueName 的路径
    /// </summary>
    public static string NormalizeFullRegistryPath(string regPath)
    {
        string path = StripComputerPrefix(regPath.Trim().Trim('"'));
        int colonIdx = path.LastIndexOf("::", StringComparison.Ordinal);
        if (colonIdx > 0)
            path = path[..colonIdx];

        if (path.StartsWith(@"HKLM\", StringComparison.OrdinalIgnoreCase))
            path = @"HKEY_LOCAL_MACHINE\" + path[5..];
        else if (path.StartsWith(@"HKCU\", StringComparison.OrdinalIgnoreCase))
            path = @"HKEY_CURRENT_USER\" + path[5..];
        else if (path.StartsWith(@"HKCR\", StringComparison.OrdinalIgnoreCase))
            path = @"HKEY_CLASSES_ROOT\" + path[5..];
        else if (path.StartsWith(@"HKU\", StringComparison.OrdinalIgnoreCase))
            path = @"HKEY_USERS\" + path[4..];
        else if (path.StartsWith(@"\Registry\Machine\", StringComparison.OrdinalIgnoreCase))
            path = @"HKEY_LOCAL_MACHINE\" + path[18..];
        else if (path.StartsWith(@"\Registry\User\", StringComparison.OrdinalIgnoreCase))
            path = @"HKEY_USERS\" + path[15..];
        else if (!path.StartsWith("HKEY_", StringComparison.OrdinalIgnoreCase))
        {
            if (path.StartsWith(@"SOFTWARE\", StringComparison.OrdinalIgnoreCase) ||
                path.StartsWith(@"SYSTEM\", StringComparison.OrdinalIgnoreCase))
                path = @"HKEY_LOCAL_MACHINE\" + path.TrimStart('\\');
            else
                path = @"HKEY_CLASSES_ROOT\" + path.TrimStart('\\');
        }

        return path.TrimEnd('\\');
    }

    /// <summary>
    /// 转换为可直接复制并粘贴到 Windows 注册表编辑器（regedit.exe）地址栏的完整路径（含“计算机\”前缀）
    /// </summary>
    public static string FormatForRegeditDisplay(string? locationKey)
    {
        if (string.IsNullOrWhiteSpace(locationKey))
            return string.Empty;

        string computerPrefix = ResolveComputerRootPrefix();
        string trimmed = locationKey.Trim();
        if (trimmed.StartsWith("Approved:", StringComparison.OrdinalIgnoreCase))
            return $@"{computerPrefix}\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved";

        if (trimmed.StartsWith("Win11Modern:", StringComparison.OrdinalIgnoreCase))
        {
            int c1 = trimmed.IndexOf('{');
            int c2 = c1 >= 0 ? trimmed.IndexOf('}', c1) : -1;
            if (c1 >= 0 && c2 > c1)
                return $@"{computerPrefix}\HKEY_LOCAL_MACHINE\SOFTWARE\Classes\PackagedCom\ClassIndex\{trimmed[c1..(c2 + 1)]}";
        }

        string clean = StripComputerPrefix(trimmed);
        bool isRegistry =
            clean.StartsWith("HK", StringComparison.OrdinalIgnoreCase) ||
            clean.StartsWith(@"\Registry\", StringComparison.OrdinalIgnoreCase) ||
            clean.StartsWith(@"SOFTWARE\", StringComparison.OrdinalIgnoreCase) ||
            clean.StartsWith(@"SYSTEM\CurrentControlSet\", StringComparison.OrdinalIgnoreCase) ||
            clean.Contains(@"Software\Classes\", StringComparison.OrdinalIgnoreCase) ||
            clean.Contains(@"\shellex\", StringComparison.OrdinalIgnoreCase) ||
            clean.Contains(@"\shell\", StringComparison.OrdinalIgnoreCase);

        if (!isRegistry)
            return trimmed;

        string fullHkey = NormalizeFullRegistryPath(clean);
        return $"{computerPrefix}\\{fullHkey}";
    }

    private static string FindDeepestExistingRegistryPath(string fullPath)
    {
        int firstSlash = fullPath.IndexOf('\\');
        if (firstSlash <= 0) return fullPath;

        string rootName = fullPath[..firstSlash];
        string subKey = fullPath[(firstSlash + 1)..];
        RegistryHive? hiveEnum = rootName.ToUpperInvariant() switch
        {
            "HKEY_LOCAL_MACHINE" => RegistryHive.LocalMachine,
            "HKEY_CURRENT_USER" => RegistryHive.CurrentUser,
            "HKEY_CLASSES_ROOT" => RegistryHive.ClassesRoot,
            "HKEY_USERS" => RegistryHive.Users,
            _ => null
        };

        if (hiveEnum == null) return fullPath;

        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(hiveEnum.Value, view);
                string candidate = subKey;
                while (!string.IsNullOrEmpty(candidate))
                {
                    try
                    {
                        using var opened = baseKey.OpenSubKey(candidate, false);
                        if (opened != null)
                            return $"{rootName}\\{candidate}";
                    }
                    catch { }

                    int lastSlash = candidate.LastIndexOf('\\');
                    if (lastSlash <= 0) break;
                    candidate = candidate[..lastSlash];
                }
            }
            catch { }
        }

        return fullPath;
    }

    private static string ResolveComputerRootPrefix()
    {
        string uiName = CultureInfo.CurrentUICulture.Name;
        if (uiName.StartsWith("zh-CN", StringComparison.OrdinalIgnoreCase) ||
            uiName.StartsWith("zh-SG", StringComparison.OrdinalIgnoreCase) ||
            uiName.StartsWith("zh-Hans", StringComparison.OrdinalIgnoreCase))
            return "计算机";

        if (uiName.StartsWith("zh-TW", StringComparison.OrdinalIgnoreCase) ||
            uiName.StartsWith("zh-HK", StringComparison.OrdinalIgnoreCase) ||
            uiName.StartsWith("zh-Hant", StringComparison.OrdinalIgnoreCase))
            return "電腦";

        return "Computer";
    }

    private static string ResolveLocalizedRegeditRoot(RegistryKey regeditKey)
    {
        try
        {
            if (regeditKey.GetValue("LastKey") is string existing && !string.IsNullOrWhiteSpace(existing))
            {
                int idx = existing.IndexOf(@"\HKEY_", StringComparison.OrdinalIgnoreCase);
                if (idx > 0)
                    return existing[..idx];
            }
        }
        catch { }

        return ResolveComputerRootPrefix();
    }

    /// <summary>
    /// 弹出 Windows 原生文件属性对话框
    /// </summary>
    public static bool ShowFileProperties(string? commandOrPath)
    {
        string path = ResolvePhysicalFilePath(commandOrPath);
        if (string.IsNullOrEmpty(path) || (!File.Exists(path) && !Directory.Exists(path)) || !OperatingSystem.IsWindows())
            return false;

        try
        {
            fixed (char* pVerb = "properties")
            fixed (char* pFile = path)
            {
                var sei = new SHELLEXECUTEINFOW
                {
                    cbSize = sizeof(SHELLEXECUTEINFOW),
                    fMask = SEE_MASK_INVOKEIDLIST,
                    lpVerb = pVerb,
                    lpFile = pFile,
                    nShow = SW_SHOW
                };
                if (ShellExecuteExW(&sei))
                    return true;
            }
        }
        catch { }

        try
        {
            using var proc = Process.Start(new ProcessStartInfo
            {
                FileName = path,
                Verb = "properties",
                UseShellExecute = true
            });
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// 使用系统默认浏览器联网检索目标项
    /// </summary>
    public static void SearchOnline(string displayName, string publisher)
    {
        string query = Uri.EscapeDataString($"{displayName} {publisher}".Trim());
        string url = $"https://www.bing.com/search?q={query}";
        try { using var proc = Process.Start(new ProcessStartInfo(url) { UseShellExecute = true }); } catch { }
    }

    public static IReadOnlyList<T> SelectCheckedItems<T>(IEnumerable<T>? items, Func<T, bool> isSelected)
    {
        if (items == null) return [];
        ArgumentNullException.ThrowIfNull(isSelected);
        return items.Where(isSelected).ToList();
    }

    public readonly record struct AiPromptItemInfo(
        string CategoryName,
        string DisplayName,
        string? Publisher,
        string? CommandOrPath,
        string? LocationKey,
        string? MenuScene = null,
        string? Clsid = null,
        string? CreatorProcess = null,
        IReadOnlyList<string>? SupportedActions = null,
        MonitorCategory? Category = null);

    public static IReadOnlyList<string> GetDefaultSupportedActions(MonitorCategory? category, string? categoryName = null)
    {
        MonitorCategory? resolved = category;
        if (resolved == null && !string.IsNullOrWhiteSpace(categoryName))
        {
            string name = categoryName.Trim();
            if (name.Contains("服务", StringComparison.OrdinalIgnoreCase))
                resolved = MonitorCategory.Win32Service;
            else if (name.Contains("驱动", StringComparison.OrdinalIgnoreCase))
                resolved = MonitorCategory.KernelDriver;
            else if (name.Contains("任务", StringComparison.OrdinalIgnoreCase))
                resolved = MonitorCategory.ScheduledTask;
            else if (name.Contains("Win11", StringComparison.OrdinalIgnoreCase) || name.Contains("现代", StringComparison.OrdinalIgnoreCase))
                resolved = MonitorCategory.ModernContextMenu;
            else if (name.Contains("右键", StringComparison.OrdinalIgnoreCase) || name.Contains("菜单", StringComparison.OrdinalIgnoreCase))
                resolved = MonitorCategory.ClassicContextMenu;
            else if (name.Contains("策略", StringComparison.OrdinalIgnoreCase))
                resolved = MonitorCategory.WindowsPolicy;
            else if (name.Contains("自启", StringComparison.OrdinalIgnoreCase) || name.Contains("启动", StringComparison.OrdinalIgnoreCase))
                resolved = MonitorCategory.StartupItem;
        }

        return resolved switch
        {
            MonitorCategory.Win32Service => ["允许", "回滚为手动启动", "回滚为延迟启动", "禁止服务", "删除服务"],
            MonitorCategory.KernelDriver => ["允许", "回滚为手动加载", "禁止驱动"],
            MonitorCategory.ScheduledTask => ["允许", "禁止计划任务", "删除计划任务"],
            MonitorCategory.ClassicContextMenu or MonitorCategory.ModernContextMenu => ["允许", "拦截并屏蔽", "删除注册项"],
            MonitorCategory.WindowsPolicy => ["允许", "禁止项目", "删除项目"],
            _ => ["允许", "禁止启动项", "删除启动项"]
        };
    }

    private static string ResolveSupportedActionsText(AiPromptItemInfo item)
    {
        IEnumerable<string> source = item.SupportedActions is { Count: > 0 }
            ? item.SupportedActions
            : GetDefaultSupportedActions(item.Category, item.CategoryName);

        var distinct = new List<string>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (string raw in source)
        {
            if (string.IsNullOrWhiteSpace(raw))
                continue;
            string trimmed = raw.Trim();
            if (seen.Add(trimmed))
                distinct.Add(trimmed);
        }

        if (distinct.Count == 0)
            distinct.AddRange(GetDefaultSupportedActions(item.Category, item.CategoryName));

        return string.Join(" / ", distinct);
    }

    public static string BuildAiAgentPrompt(AiPromptItemInfo item)
    {
        var sb = new System.Text.StringBuilder(256);
        sb.AppendLine("请帮我判断以下 Windows 启动项/扩展项是否安全、所属软件与作用，并结合该项支持的操作给出最合适的处置建议：");
        AppendAiPromptFields(sb, item, multiMode: false);
        return sb.ToString().TrimEnd();
    }

    public static string BuildAiAgentPrompt(IReadOnlyList<AiPromptItemInfo> items)
    {
        if (items == null || items.Count == 0)
            return string.Empty;
        if (items.Count == 1)
            return BuildAiAgentPrompt(items[0]);

        var sb = new System.Text.StringBuilder(items.Count * 192);
        sb.AppendLine($"请帮我逐项判断以下 {items.Count} 个 Windows 启动项/扩展项是否安全、所属软件与作用，并结合各项支持的操作给出简明处置建议：");
        for (int i = 0; i < items.Count; i++)
        {
            sb.Append($"[{i + 1}] ");
            AppendAiPromptFields(sb, items[i], multiMode: true);
        }
        return sb.ToString().TrimEnd();
    }

    private static void AppendAiPromptFields(System.Text.StringBuilder sb, AiPromptItemInfo item, bool multiMode)
    {
        string cat = string.IsNullOrWhiteSpace(item.CategoryName) ? "系统启动/扩展项" : item.CategoryName.Trim();
        string sceneSuffix = !string.IsNullOrWhiteSpace(item.MenuScene) ? $" (菜单位置: {item.MenuScene.Trim()})" : string.Empty;
        string name = string.IsNullOrWhiteSpace(item.DisplayName) ? "(未命名)" : item.DisplayName.Trim();
        string pub = string.IsNullOrWhiteSpace(item.Publisher) ? "未知发布者/未签名" : item.Publisher.Trim();
        string cmd = item.CommandOrPath?.Trim() ?? string.Empty;
        string loc = FormatForRegeditDisplay(item.LocationKey?.Trim() ?? string.Empty);
        string clsid = item.Clsid?.Trim() ?? string.Empty;
        string creator = item.CreatorProcess?.Trim() ?? string.Empty;
        string actionsText = ResolveSupportedActionsText(item);

        if (multiMode)
        {
            sb.Append($"{cat}{sceneSuffix} | 名称: {name} | 签名: {pub}");
            if (!string.IsNullOrEmpty(creator))
                sb.Append($" | 创建来源: {creator}");
            if (!string.IsNullOrEmpty(cmd))
                sb.Append($" | 路径: {cmd}");
            if (!string.IsNullOrEmpty(loc) && !string.Equals(loc, cmd, StringComparison.OrdinalIgnoreCase))
                sb.Append($" | 位置: {loc}");
            if (!string.IsNullOrEmpty(clsid))
                sb.Append($" | CLSID: {clsid}");
            sb.Append($" | 支持操作: {actionsText}");
            sb.AppendLine();
            return;
        }

        sb.AppendLine($"- 类别: {cat}{sceneSuffix}");
        sb.AppendLine($"- 名称: {name}");
        sb.AppendLine($"- 签名/发布者: {pub}");
        if (!string.IsNullOrEmpty(creator))
            sb.AppendLine($"- 安装/创建进程: {creator}");
        if (!string.IsNullOrEmpty(cmd))
            sb.AppendLine($"- 命令/路径: {cmd}");
        if (!string.IsNullOrEmpty(loc) && !string.Equals(loc, cmd, StringComparison.OrdinalIgnoreCase))
            sb.AppendLine($"- 注册表/位置: {loc}");
        if (!string.IsNullOrEmpty(clsid))
            sb.AppendLine($"- CLSID: {clsid}");
        sb.AppendLine($"- 支持操作: {actionsText}");
    }

    public static IEnumerable<string> ExpandDisabledRegistryVariants(string subKey)
    {
        if (string.IsNullOrWhiteSpace(subKey))
            yield break;

        yield return subKey;
        string toggledLeaf = ToggleDisabledPrefixInLeaf(subKey);
        if (!toggledLeaf.Equals(subKey, StringComparison.OrdinalIgnoreCase))
            yield return toggledLeaf;

        string? swappedFolder = null;
        if (subKey.Contains(@"\ContextMenuHandlers\", StringComparison.OrdinalIgnoreCase))
            swappedFolder = subKey.Replace(@"\ContextMenuHandlers\", @"\-ContextMenuHandlers\", StringComparison.OrdinalIgnoreCase);
        else if (subKey.Contains(@"\-ContextMenuHandlers\", StringComparison.OrdinalIgnoreCase))
            swappedFolder = subKey.Replace(@"\-ContextMenuHandlers\", @"\ContextMenuHandlers\", StringComparison.OrdinalIgnoreCase);
        else if (subKey.Contains(@"\DragDropHandlers\", StringComparison.OrdinalIgnoreCase))
            swappedFolder = subKey.Replace(@"\DragDropHandlers\", @"\-DragDropHandlers\", StringComparison.OrdinalIgnoreCase);
        else if (subKey.Contains(@"\-DragDropHandlers\", StringComparison.OrdinalIgnoreCase))
            swappedFolder = subKey.Replace(@"\-DragDropHandlers\", @"\DragDropHandlers\", StringComparison.OrdinalIgnoreCase);

        if (!string.IsNullOrEmpty(swappedFolder))
        {
            yield return swappedFolder;
            string swappedLeaf = ToggleDisabledPrefixInLeaf(swappedFolder);
            if (!swappedLeaf.Equals(swappedFolder, StringComparison.OrdinalIgnoreCase))
                yield return swappedLeaf;
        }
    }

    private static string ToggleDisabledPrefixInLeaf(string subKey)
    {
        int lastSlash = subKey.LastIndexOf('\\');
        if (lastSlash < 0 || lastSlash >= subKey.Length - 1) return subKey;
        string leaf = subKey[(lastSlash + 1)..];
        return leaf.StartsWith('-')
            ? subKey[..(lastSlash + 1)] + leaf[1..]
            : subKey[..(lastSlash + 1)] + "-" + leaf;
    }

    /// <summary>
    /// 核验待审核条目对应的底层注册表项、计划任务或目标程序是否仍然存在（优先验证真实注册表位置，防止卸载后因残留文件而无法自动核销）
    /// </summary>
    public static bool IsPendingAuditTargetStillInstalled(
        string? locationKey,
        string? targetProgram,
        MonitorCategory category,
        bool matchedLiveItemExists)
    {
        if (!OperatingSystem.IsWindows())
            return true;

        bool locationExists = DoesPendingLocationStillExist(locationKey, targetProgram);
        if (!locationExists)
            return false;

        if (!matchedLiveItemExists && category != MonitorCategory.StartupItem && category != MonitorCategory.ClassicContextMenu && category != MonitorCategory.ModernContextMenu)
        {
            // 已确认注册表/任务存在即可
            return true;
        }

        // 若目标程序本身是明确的第三方绝对路径（且非 System32/SysWOW64 宿主）却已从磁盘删除（例如软件卸载删除了 DLL 但 -ContextMenuHandlers 备份键残留），同样视为已卸载
        if (!string.IsNullOrWhiteSpace(targetProgram))
        {
            string physicalPath = ResolvePhysicalFilePath(targetProgram);
            if (!string.IsNullOrWhiteSpace(physicalPath) &&
                Path.IsPathRooted(physicalPath) &&
                !physicalPath.Contains(@"\Windows\System32\", StringComparison.OrdinalIgnoreCase) &&
                !physicalPath.Contains(@"\Windows\SysWOW64\", StringComparison.OrdinalIgnoreCase) &&
                !File.Exists(physicalPath))
            {
                return false;
            }
        }

        return true;
    }

    public static bool DoesPendingLocationStillExist(string? locationKey, string? targetProgram = null)
    {
        if (!OperatingSystem.IsWindows())
            return true;

        try
        {
            string rawLoc = StripComputerPrefix((locationKey ?? string.Empty).Trim());

            if (rawLoc.StartsWith("Approved:", StringComparison.OrdinalIgnoreCase) ||
                rawLoc.StartsWith("Blocked:", StringComparison.OrdinalIgnoreCase))
            {
                string clsid = PrivilegedRollbackEngine.ExtractClsidOrIdentifier(rawLoc);
                return !string.IsNullOrEmpty(clsid) &&
                       (RegistryValueExistsAnyView(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved", clsid) ||
                        RegistryValueExistsAnyView(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked", clsid) ||
                        RegistryValueExistsAnyView(RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked", clsid));
            }

            if (rawLoc.StartsWith("Win11Modern:", StringComparison.OrdinalIgnoreCase) ||
                rawLoc.StartsWith("PackagedCom:", StringComparison.OrdinalIgnoreCase))
            {
                string clsid = PrivilegedRollbackEngine.ExtractClsidOrIdentifier(rawLoc);
                if (string.IsNullOrEmpty(clsid))
                    return false;

                return RegistrySubKeyExistsAnyView(RegistryHive.LocalMachine, $@"SOFTWARE\Classes\PackagedCom\ClassIndex\{clsid}") ||
                       RegistrySubKeyExistsAnyView(RegistryHive.CurrentUser, $@"Software\Classes\PackagedCom\ClassIndex\{clsid}") ||
                       RegistrySubKeyExistsAnyView(RegistryHive.LocalMachine, $@"SOFTWARE\Classes\CLSID\{clsid}") ||
                       RegistrySubKeyExistsAnyView(RegistryHive.CurrentUser, $@"Software\Classes\CLSID\{clsid}");
            }

            if (rawLoc.StartsWith('{') && rawLoc.EndsWith('}'))
            {
                return RegistrySubKeyExistsAnyView(RegistryHive.ClassesRoot, $@"CLSID\{rawLoc}") ||
                       RegistrySubKeyExistsAnyView(RegistryHive.LocalMachine, $@"SOFTWARE\Classes\CLSID\{rawLoc}") ||
                       RegistrySubKeyExistsAnyView(RegistryHive.CurrentUser, $@"Software\Classes\CLSID\{rawLoc}") ||
                       RegistrySubKeyExistsAnyView(RegistryHive.LocalMachine, $@"SOFTWARE\Classes\PackagedCom\ClassIndex\{rawLoc}") ||
                       RegistrySubKeyExistsAnyView(RegistryHive.CurrentUser, $@"Software\Classes\PackagedCom\ClassIndex\{rawLoc}");
            }

            if (rawLoc.StartsWith("Task:", StringComparison.OrdinalIgnoreCase) ||
                rawLoc.Contains(@"\System32\Tasks\", StringComparison.OrdinalIgnoreCase) ||
                rawLoc.Contains(@"\Schedule\TaskCache\Tree\", StringComparison.OrdinalIgnoreCase))
            {
                string taskRel = PrivilegedRollbackEngine.NormalizeScheduledTaskName(rawLoc).TrimStart('\\');
                if (string.IsNullOrWhiteSpace(taskRel))
                    return false;

                string taskFile = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), @"System32\Tasks", taskRel);
                if (File.Exists(taskFile))
                    return true;

                return RegistrySubKeyExistsAnyView(
                    RegistryHive.LocalMachine,
                    $@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\{taskRel}");
            }

            if (rawLoc.StartsWith("HK", StringComparison.OrdinalIgnoreCase) ||
                rawLoc.StartsWith(@"\Registry\", StringComparison.OrdinalIgnoreCase) ||
                rawLoc.StartsWith(@"SOFTWARE\", StringComparison.OrdinalIgnoreCase) ||
                rawLoc.StartsWith(@"SYSTEM\CurrentControlSet\", StringComparison.OrdinalIgnoreCase) ||
                rawLoc.Contains(@"Software\Classes\", StringComparison.OrdinalIgnoreCase) ||
                rawLoc.Contains(@"\SOFTWARE\", StringComparison.OrdinalIgnoreCase) ||
                rawLoc.Contains(@"\SYSTEM\CurrentControlSet\", StringComparison.OrdinalIgnoreCase))
            {
                string explicitValueName = string.Empty;
                string keyPart = rawLoc;
                int valSep = rawLoc.IndexOf("::", StringComparison.Ordinal);
                if (valSep > 0)
                {
                    keyPart = rawLoc[..valSep];
                    explicitValueName = rawLoc[(valSep + 2)..];
                }

                string full = NormalizeFullRegistryPath(keyPart);
                int slash = full.IndexOf('\\');
                if (slash <= 0)
                    return false;

                string root = full[..slash].ToUpperInvariant();
                string sub = full[(slash + 1)..];
                RegistryHive? hive = root switch
                {
                    "HKEY_LOCAL_MACHINE" => RegistryHive.LocalMachine,
                    "HKEY_CURRENT_USER" => RegistryHive.CurrentUser,
                    "HKEY_CLASSES_ROOT" => RegistryHive.ClassesRoot,
                    "HKEY_USERS" => RegistryHive.Users,
                    _ => null
                };
                if (!hive.HasValue)
                    return false;

                if (RegistryLocationExists(hive.Value, sub, explicitValueName))
                    return true;

                if (hive.Value == RegistryHive.CurrentUser)
                {
                    foreach (string sid in EnumerateInteractiveUserSids())
                    {
                        if (RegistryLocationExists(RegistryHive.Users, $@"{sid}\{sub}", explicitValueName))
                            return true;
                    }
                }

                return false;
            }

            if (!string.IsNullOrWhiteSpace(rawLoc))
            {
                string expandedLoc = ExpandNormalizedPathTemplate(rawLoc);
                string unquoted = Environment.ExpandEnvironmentVariables(expandedLoc.Trim('"'));
                if (Path.IsPathRooted(unquoted))
                    return File.Exists(unquoted) || Directory.Exists(unquoted);
            }

            if (!string.IsNullOrWhiteSpace(targetProgram))
            {
                string physical = ResolvePhysicalFilePath(targetProgram);
                return !string.IsNullOrWhiteSpace(physical) && File.Exists(physical);
            }
        }
        catch { }

        return false;
    }

    private static bool RegistryLocationExists(RegistryHive hive, string sub, string explicitValueName)
    {
        bool isServiceSubKey =
            sub.StartsWith(@"SYSTEM\CurrentControlSet\Services\", StringComparison.OrdinalIgnoreCase) ||
            sub.StartsWith(@"SYSTEM\ControlSet001\Services\", StringComparison.OrdinalIgnoreCase);

        var subCandidates = new List<string> { sub };
        if (isServiceSubKey &&
            (sub.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
             sub.EndsWith(".sys", StringComparison.OrdinalIgnoreCase)))
        {
            subCandidates.Add(sub[..^4]);
        }

        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(hive, view);
                foreach (string candidateSub in subCandidates)
                {
                    foreach (string variant in ExpandDisabledRegistryVariants(candidateSub))
                    {
                        using var opened = baseKey.OpenSubKey(variant, false);
                        if (!string.IsNullOrEmpty(explicitValueName))
                        {
                            if (opened?.GetValue(explicitValueName) != null)
                                return true;
                        }
                        else
                        {
                            if (opened != null)
                                return true;

                            if (!isServiceSubKey)
                            {
                                int lastSlash = variant.LastIndexOf('\\');
                                if (lastSlash > 0 && lastSlash < variant.Length - 1)
                                {
                                    string parent = variant[..lastSlash];
                                    string leafVal = variant[(lastSlash + 1)..];
                                    using var parentKey = baseKey.OpenSubKey(parent, false);
                                    if (parentKey?.GetValue(leafVal) != null)
                                        return true;
                                }
                            }
                        }
                    }
                }
            }
            catch { }
        }

        return false;
    }

    private static List<string> EnumerateInteractiveUserSids()
    {
        var sids = new List<string>();
        try
        {
            (_, string? activeSid) = InteractiveUserHiveResolver.TryGetActiveInteractiveUserSid();
            if (!string.IsNullOrWhiteSpace(activeSid))
                sids.Add(activeSid);
            foreach (string sid in InteractiveUserHiveResolver.GetAllLoadedUserSids())
            {
                if (!sids.Contains(sid, StringComparer.OrdinalIgnoreCase))
                    sids.Add(sid);
            }
        }
        catch { }
        return sids;
    }

    private static bool RegistrySubKeyExistsAnyView(RegistryHive hive, string subKey)
    {
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(hive, view);
                using var opened = baseKey.OpenSubKey(subKey, false);
                if (opened != null)
                    return true;
            }
            catch { }
        }

        if (hive == RegistryHive.CurrentUser)
        {
            foreach (string sid in EnumerateInteractiveUserSids())
            {
                if (RegistrySubKeyExistsAnyView(RegistryHive.Users, $@"{sid}\{subKey}"))
                    return true;
            }
        }

        return false;
    }

    private static bool RegistryValueExistsAnyView(RegistryHive hive, string subKey, string valueName)
    {
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(hive, view);
                using var opened = baseKey.OpenSubKey(subKey, false);
                if (opened?.GetValue(valueName) != null)
                    return true;
            }
            catch { }
        }

        if (hive == RegistryHive.CurrentUser)
        {
            foreach (string sid in EnumerateInteractiveUserSids())
            {
                if (RegistryValueExistsAnyView(RegistryHive.Users, $@"{sid}\{subKey}", valueName))
                    return true;
            }
        }

        return false;
    }
}
