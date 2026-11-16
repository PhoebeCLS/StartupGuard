using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Security.Principal;
using Microsoft.Win32;
using StartupGuard.Core.ContextMenu;
using StartupGuard.Core.Models;
using StartupGuard.Core.Native;
using StartupGuard.Core.Rules;
using StartupGuard.Core.Scoring;

namespace StartupGuard.App.Services;

/// <summary>
/// 全量自启项全景管控引擎
/// 支持枚举、状态切换 (启用/禁用)、删除、定位文件与注册表
/// </summary>
public sealed class SystemStartupItemsManager
{
    public sealed class ManagedStartupItem
    {
        public string Id { get; set; } = Guid.NewGuid().ToString("N");
        public string DisplayName { get; set; } = string.Empty;
        public string Publisher { get; set; } = "未知发布者";
        public bool HasSignature { get; set; }
        public string CommandOrPath { get; set; } = string.Empty;
        public string LocationKey { get; set; } = string.Empty;
        public MonitorCategory Category { get; set; }
        public string CategoryName { get; set; } = string.Empty;
        public string CategoryIcon { get; set; } = "Rocket24";
        public bool IsEnabled { get; set; }
        public string StatusSummary { get; set; } = string.Empty;
        public string RawState { get; set; } = string.Empty;
        public bool IsMicrosoftOrSystemBuiltIn { get; set; }
        public System.Windows.Media.ImageSource? RealIconSource { get; set; }
        public bool HasRealIcon => RealIconSource != null;
        public string Clsid { get; set; } = string.Empty;
        public string MenuIdKey { get; set; } = string.Empty;
        public string ScopeScene { get; set; } = string.Empty;
        public string Note { get; set; } = string.Empty;
        public string ProductName { get; set; } = string.Empty;
        public string SourceProcess { get; set; } = string.Empty;
        public bool HasNote => !string.IsNullOrWhiteSpace(Note);
        public bool CanDeleteItem => Category != MonitorCategory.KernelDriver;
        public bool IsShellExtension => !string.IsNullOrEmpty(Clsid) || LocationKey.Contains("shellex", StringComparison.OrdinalIgnoreCase);
        public bool CanDeepAnalyze => IsShellExtension || Category is MonitorCategory.ClassicContextMenu or MonitorCategory.ModernContextMenu;
        public string GlobalSearchTypeLabel => GlobalSearchHelper.GetTypeBadgeText(Category, LocationKey, ScopeScene);

        public sealed record StartupStateOption(string Title, InterceptionAction Action, uint StartType, bool DelayedAuto)
        {
            public override string ToString() => Title;
        }

        private static readonly StartupStateOption[] ServiceStateOptions =
        [
            new("自动", InterceptionAction.Allow, 2, false),
            new("延迟启动", InterceptionAction.RollbackToDelayedAuto, 2, true),
            new("手动", InterceptionAction.RollbackToDemand, 3, false),
            new("禁止", InterceptionAction.RollbackToDisabled, 4, false)
        ];

        private static readonly StartupStateOption[] DriverStateOptions =
        [
            new("自动", InterceptionAction.Allow, 2, false),
            new("手动", InterceptionAction.RollbackToDemand, 3, false),
            new("禁止", InterceptionAction.RollbackToDisabled, 4, false)
        ];

        public bool IsMultiStateCategory => Category is MonitorCategory.Win32Service or MonitorCategory.KernelDriver;
        public bool IsBinaryStateCategory => !IsMultiStateCategory;
        public InterceptionAction CurrentStateAction { get; set; } = InterceptionAction.Allow;
        public IReadOnlyList<StartupStateOption> AvailableStateOptions => Category switch
        {
            MonitorCategory.Win32Service => ServiceStateOptions,
            MonitorCategory.KernelDriver => DriverStateOptions,
            _ => []
        };
        public StartupStateOption? SelectedStateOption => AvailableStateOptions.FirstOrDefault(o => o.Action == CurrentStateAction)
                                                          ?? (AvailableStateOptions.Count > 0 ? AvailableStateOptions[0] : null);
    }

    public static string CleanDisplayName(string? raw, string fallback)
    {
        if (string.IsNullOrWhiteSpace(raw)) return fallback;
        string s = raw.Trim();
        string resolved = ContextMenuManagerEngine.ResolveMuiString(s);
        if (!string.IsNullOrWhiteSpace(resolved))
            return resolved;
        return (s.StartsWith('@') && (s.Contains('%') || s.Contains(','))) ? fallback : s;
    }

    public static bool IsThirdPartyWhqlPublisher(string? publisher)
    {
        if (string.IsNullOrWhiteSpace(publisher))
            return false;

        return publisher.Contains("Third Party Component", StringComparison.OrdinalIgnoreCase) ||
               publisher.Contains("Hardware Compatibility", StringComparison.OrdinalIgnoreCase) ||
               publisher.Contains("Third-Party", StringComparison.OrdinalIgnoreCase);
    }

    private static readonly HashSet<string> BuiltInWindowsContextVerbs = new(StringComparer.OrdinalIgnoreCase)
    {
        "open", "opennewtab", "opennewwindow", "opennewprocess", "explore", "find",
        "pintohome", "pintostartscreen", "removeproperties", "edit", "print", "printto",
        "runas", "runasuser", "eject", "format", "share", "modernsharing", "manage", "mount", "burn",
        "play", "preview", "setdesktopwallpaper", "powershell", "windowsterminal",
        "launchworkfolderscontrol", "workfolders", "updateencryption", "encrypt-bde", "decrypt-bde", "lock-bde",
        "shell32", "windows.storage", "efscore", "zipfldr", "wpdshext", "stobject",
        "display", "themecpl", "twext", "propsys", "twinui"
    };

    private static readonly string[] BuiltInWinXNames =
    [
        "Command Prompt", "Windows PowerShell", "Windows Terminal", "Terminal",
        "Computer Management", "Disk Management", "Device Manager", "Network Connections",
        "NetworkStatus", "Task Manager", "Settings", "File Explorer", "Run",
        "Search", "Desktop", "Mobility Center", "Event Viewer", "Installed Apps",
        "Programs and Features", "Power Options", "Control Panel", "System", "Shutdown",
        "命令提示符", "终端", "计算机管理", "磁盘管理", "设备管理器", "网络连接",
        "任务管理器", "设置", "文件资源管理器", "运行", "搜索", "桌面", "移动中心",
        "事件查看器", "已安装的应用", "应用和功能", "程序和功能", "电源选项", "控制面板", "系统", "关机"
    ];

    public static bool DetectIsMicrosoftOrSystem(
        string publisher,
        string displayName,
        string path,
        MonitorCategory category,
        string locationKey = "")
    {
        if (category == MonitorCategory.WindowsPolicy) return true;

        // 微软 WHQL / 第三方硬件认证签名 (如 "Microsoft Windows Third Party Component CA 2014" - Dokan2) 属于第三方软件，绝不可当作系统自带项隐藏！
        if (IsThirdPartyWhqlPublisher(publisher))
            return false;

        // Edge / EdgeUpdate / OneDrive / Teams / 电脑管家等非 OS 核心可卸载微软软件，绝不当作系统自带项隐藏
        if (NativeSecurityExtractor.IsNonCoreOptionalMicrosoftApp($"{publisher} {displayName} {path} {locationKey}"))
            return false;

        // UWP / Microsoft Store 自启项：仅隐藏微软第一方包，第三方商店软件保留显示
        if (!string.IsNullOrWhiteSpace(path) && path.Contains("WindowsApps", StringComparison.OrdinalIgnoreCase))
        {
            return UwpStartupScanner.IsFirstPartyMicrosoftUwpPackage(path, publisher);
        }

        if (publisher.Contains("Microsoft", StringComparison.OrdinalIgnoreCase) ||
            publisher.Contains("Sysinternals", StringComparison.OrdinalIgnoreCase))
            return true;

        if (publisher.Equals("Microsoft Windows", StringComparison.OrdinalIgnoreCase) ||
            publisher.StartsWith("Microsoft Corporation", StringComparison.OrdinalIgnoreCase))
            return true;

        if (displayName.StartsWith("Microsoft ", StringComparison.OrdinalIgnoreCase) ||
            displayName.StartsWith("Windows ", StringComparison.OrdinalIgnoreCase))
            return true;

        string lowerPath = (path ?? string.Empty).ToLowerInvariant();
        string lowerLoc = (locationKey ?? string.Empty).ToLowerInvariant();
        if (category is MonitorCategory.ClassicContextMenu or MonitorCategory.ModernContextMenu)
        {
            // 提取注册表键尾段动词名（如 pintohome、LaunchWorkfoldersControl、runas）
            string locLeaf = string.Empty;
            if (!string.IsNullOrWhiteSpace(locationKey))
            {
                string trimmedLoc = locationKey.TrimEnd('\\');
                int sep = trimmedLoc.LastIndexOf('\\');
                locLeaf = sep >= 0 && sep + 1 < trimmedLoc.Length ? trimmedLoc[(sep + 1)..] : trimmedLoc;
            }

            // 右键菜单“隐藏系统项”模式：识别全部 Windows 系统内置项（含 WinX、内置 SendTo、内置 ShellNew、系统自带动词/OpenWith、System32/SysWOW64、Microsoft 扩展）
            if ((lowerPath.Contains(@"\microsoft\windows\winx\", StringComparison.OrdinalIgnoreCase) ||
                 lowerLoc.Contains(@"\microsoft\windows\winx\", StringComparison.OrdinalIgnoreCase)) &&
                (BuiltInWinXNames.Any(k => displayName.Contains(k, StringComparison.OrdinalIgnoreCase)) ||
                 lowerPath.Contains(@"\winx\group", StringComparison.OrdinalIgnoreCase)))
            {
                return true;
            }

            // Windows 内置 SendTo 项目 (.DeskLink, .MAPIMail, .ZFSendToTarget, .mydocs, 传真收件人, 蓝牙文件传送)
            if (lowerPath.Contains(@"\microsoft\windows\sendto\", StringComparison.OrdinalIgnoreCase) &&
                (lowerPath.EndsWith(".desklink", StringComparison.OrdinalIgnoreCase) ||
                 lowerPath.EndsWith(".mapimail", StringComparison.OrdinalIgnoreCase) ||
                 lowerPath.EndsWith(".zfsendtotarget", StringComparison.OrdinalIgnoreCase) ||
                 lowerPath.EndsWith(".mydocs", StringComparison.OrdinalIgnoreCase) ||
                 displayName.Contains("传真", StringComparison.OrdinalIgnoreCase) ||
                 displayName.Contains("Fax", StringComparison.OrdinalIgnoreCase) ||
                 displayName.Contains("蓝牙", StringComparison.OrdinalIgnoreCase) ||
                 displayName.Contains("Bluetooth", StringComparison.OrdinalIgnoreCase) ||
                 displayName.Contains("文档", StringComparison.OrdinalIgnoreCase) ||
                 displayName.Contains("Documents", StringComparison.OrdinalIgnoreCase) ||
                 displayName.Contains("桌面", StringComparison.OrdinalIgnoreCase) ||
                 displayName.Contains("Desktop", StringComparison.OrdinalIgnoreCase) ||
                 displayName.Contains("邮件", StringComparison.OrdinalIgnoreCase) ||
                 displayName.Contains("Mail", StringComparison.OrdinalIgnoreCase) ||
                 displayName.Contains("压缩", StringComparison.OrdinalIgnoreCase) ||
                 displayName.Contains("Compressed", StringComparison.OrdinalIgnoreCase)))
            {
                return true;
            }

            // Windows 系统核心目录命令 (cmd.exe / powershell.exe / explorer.exe / rundll32.exe 等)
            string trimmedName = (displayName ?? string.Empty).Trim();
            string cleanBin = Path.GetFileName(PathNormalizerAndSimilarity.SplitCommandLine(path ?? string.Empty).ExecutablePath).ToLowerInvariant();
            if (cleanBin is "cmd.exe" or "powershell.exe" or "pwsh.exe" or "wsl.exe" or "explorer.exe" or "notepad.exe" or "mspaint.exe" or "wordpad.exe" or "wmplayer.exe" or "fsquirt.exe" or "wfs.exe" or "print.exe" or "rundll32.exe")
            {
                return true;
            }

            // Windows 原生扩展/动词/ShellNew 系统内置项
            if (BuiltInWindowsContextVerbs.Contains(trimmedName) ||
                (!string.IsNullOrEmpty(locLeaf) && BuiltInWindowsContextVerbs.Contains(locLeaf)) ||
                trimmedName.Equals("在此处打开命令窗口", StringComparison.OrdinalIgnoreCase) ||
                trimmedName.Equals("在此处打开 PowerShell 窗口", StringComparison.OrdinalIgnoreCase) ||
                trimmedName.Equals("在终端中打开", StringComparison.OrdinalIgnoreCase) ||
                trimmedName.Equals("管理员取得所有权", StringComparison.OrdinalIgnoreCase) ||
                trimmedName.Equals("工作文件夹", StringComparison.OrdinalIgnoreCase) ||
                trimmedName.Equals("固定到快速访问", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            if (lowerPath.StartsWith('.') && (lowerPath is ".txt" or ".bmp" or ".rtf" or ".library-ms" or ".zip" or ".lnk"))
                return true;

            if (lowerPath.Contains(@"\windows\system32\") ||
                lowerPath.Contains(@"\windows\syswow64\") ||
                lowerPath.EndsWith(@"\windows\explorer.exe", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            if (string.IsNullOrWhiteSpace(lowerPath) &&
                (publisher.Equals("外壳扩展", StringComparison.OrdinalIgnoreCase) ||
                 publisher.Equals("未知发布者", StringComparison.OrdinalIgnoreCase)))
            {
                // 纯内置系统动词（无对应第三方二进制），如 open / print / runas / pintohome / OpenWith\WordPad.exe
                if (trimmedName is "WordPad.exe" or "notepad.exe" or "mspaint.exe" or "IEXPLORE.EXE" or "wmplayer.exe")
                    return true;
            }
        }

        if (lowerPath.Contains(@"\windows\system32\") ||
            lowerPath.Contains(@"\windows\syswow64\"))
        {
            if (publisher == "Microsoft Windows")
                return true;
        }
        return false;
    }

    private readonly ContextMenuManagerEngine _contextMenuEngine = new();

    /// <summary>
    /// 全量抓取当前系统的所有自启项、服务、驱动、任务、右键菜单和策略
    /// </summary>
    public List<ManagedStartupItem> GetAllSystemStartupItems()
    {
        var result = new List<ManagedStartupItem>();
        if (!OperatingSystem.IsWindows())
            return GenerateMockItems();

        try
        {
            List<ManagedStartupItem> r1 = [], r2 = [], r3 = [], r4 = [], r5 = [], r6 = [];
            Parallel.Invoke(
                () => r1 = ScanStartupRunItems(),
                () => (r2, r3) = ScanServicesAndDrivers(),
                () => r4 = ScanScheduledTasks(),
                () => r5 = ScanContextMenus(),
                () => r6 = ScanPolicies());

            result.EnsureCapacity(r1.Count + r2.Count + r3.Count + r4.Count + r5.Count + r6.Count);
            result.AddRange(r1);
            result.AddRange(r2);
            result.AddRange(r3);
            result.AddRange(r4);
            result.AddRange(r5);
            result.AddRange(r6);

            Parallel.ForEach(
                result,
                new ParallelOptions { MaxDegreeOfParallelism = Math.Min(4, Environment.ProcessorCount) },
                item =>
                {
                    item.RealIconSource = ProgramIconResolver.ResolveIcon(item.CommandOrPath, item.Category);
                });
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[SystemStartupItemsManager] Scan error: {ex.Message}");
        }

        return result;
    }

    private List<ManagedStartupItem> ScanStartupRunItems()
    {
        var list = new List<ManagedStartupItem>();

        // HKLM Run & RunOnce
        ScanRegistryKeyItems(Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", MonitorCategory.StartupItem, "自启程序", "Rocket24", list);
        ScanRegistryKeyItems(Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", MonitorCategory.StartupItem, "自启程序", "Rocket24", list);
        ScanRegistryKeyItems(Registry.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", MonitorCategory.StartupItem, "自启程序(32位)", "Rocket24", list);

        // 当前用户与已加载用户的 Run（跳过与 HKCU 重复的当前交互用户 SID）
        ScanRegistryKeyItems(Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Run", MonitorCategory.StartupItem, "用户自启", "Rocket24", list);
        ScanRegistryKeyItems(Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\RunOnce", MonitorCategory.StartupItem, "用户自启", "Rocket24", list);
        ScanRegistryKeyItems(Registry.CurrentUser, @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", MonitorCategory.StartupItem, "用户自启(32位)", "Rocket24", list);

        string? currentUserSid = GetCurrentProcessUserSid();
        foreach (var sid in InteractiveUserHiveResolver.GetAllLoadedUserSids())
        {
            if (!string.IsNullOrEmpty(currentUserSid) &&
                string.Equals(sid, currentUserSid, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }
            ScanRegistryKeyItems(Registry.Users, $@"{sid}\Software\Microsoft\Windows\CurrentVersion\Run", MonitorCategory.StartupItem, $"用户自启({sid[..Math.Min(12, sid.Length)]}..)", "Rocket24", list);
            ScanRegistryKeyItems(Registry.Users, $@"{sid}\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", MonitorCategory.StartupItem, $"用户自启(32位,{sid[..Math.Min(12, sid.Length)]}..)", "Rocket24", list);
        }

        // 物理启动文件夹
        string commonStartup = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"Microsoft\Windows\Start Menu\Programs\Startup");
        ScanDirectoryShortcuts(commonStartup, "公共启动文件夹", list);

        string userStartup = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), @"Microsoft\Windows\Start Menu\Programs\Startup");
        ScanDirectoryShortcuts(userStartup, "用户启动文件夹", list);

        // UWP / Microsoft Store 应用自启项 (StartupTask)
        ScanUwpStartupTasks(list);

        return list;
    }

    private void ScanUwpStartupTasks(List<ManagedStartupItem> list)
    {
        try
        {
            var sids = InteractiveUserHiveResolver.GetAllLoadedUserSids().Cast<string?>().ToList();
            foreach (var uwp in UwpStartupScanner.ScanForUserSids(sids))
            {
                string pathOrPkg = !string.IsNullOrWhiteSpace(uwp.ExecutablePath)
                    ? uwp.ExecutablePath
                    : (!string.IsNullOrWhiteSpace(uwp.PackageInstallPath) ? uwp.PackageInstallPath : uwp.PackageFamilyName);
                bool isFirstParty = UwpStartupScanner.IsFirstPartyMicrosoftUwpPackage(uwp.LocationKey + " " + pathOrPkg, uwp.Publisher);

                list.Add(new ManagedStartupItem
                {
                    DisplayName = uwp.DisplayName,
                    Publisher = uwp.Publisher,
                    HasSignature = true,
                    CommandOrPath = pathOrPkg,
                    LocationKey = uwp.LocationKey,
                    Category = MonitorCategory.StartupItem,
                    CategoryName = "Store / UWP 自启",
                    CategoryIcon = "AppFolder24",
                    IsEnabled = uwp.IsEnabled,
                    StatusSummary = uwp.IsEnabled ? "商店应用开机自启" : "已在 UWP 自启中禁止",
                    RawState = $"State={uwp.State}, PFN={uwp.PackageFamilyName}",
                    IsMicrosoftOrSystemBuiltIn = isFirstParty
                });
            }
        }
        catch { }
    }

    private void ScanRegistryKeyItems(RegistryKey root, string subKey, MonitorCategory cat, string catName, string icon, List<ManagedStartupItem> list)
    {
        try
        {
            using var key = root.OpenSubKey(subKey, false);
            if (key is null) return;

            string rootPrefix = root == Registry.LocalMachine ? "HKLM" : (root == Registry.CurrentUser ? "HKCU" : "HKU");
            foreach (string valName in key.GetValueNames())
            {
                object? val = key.GetValue(valName);
                string strVal = val?.ToString() ?? string.Empty;

                bool isEnabled = CheckIfStartupApproved(root, subKey, valName);
                string fullLoc = $@"{rootPrefix}\{subKey}\{valName}";

                var (publisher, hasSig) = ExtractPublisher(strVal);

                list.Add(new ManagedStartupItem
                {
                    DisplayName = string.IsNullOrWhiteSpace(valName) ? "(默认值)" : valName,
                    Publisher = publisher,
                    HasSignature = hasSig,
                    CommandOrPath = strVal,
                    LocationKey = fullLoc,
                    Category = cat,
                    CategoryName = catName,
                    CategoryIcon = icon,
                    IsEnabled = isEnabled,
                    StatusSummary = isEnabled ? "正常自启" : "已在 StartupApproved 中禁止",
                    RawState = strVal,
                    IsMicrosoftOrSystemBuiltIn = DetectIsMicrosoftOrSystem(publisher, valName, strVal, cat)
                });
            }
        }
        catch { }
    }

    private static string? GetCurrentProcessUserSid()
    {
        if (!OperatingSystem.IsWindows())
            return null;
        try { return WindowsIdentity.GetCurrent().User?.Value; }
        catch { return null; }
    }

    private static bool CheckIfStartupApproved(RegistryKey root, string subKey, string valName)
    {
        try
        {
            string approvedRel = subKey.Contains("WOW6432Node", StringComparison.OrdinalIgnoreCase)
                ? @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32"
                : @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";

            RegistryKey? appKey = null;
            if (root == Registry.Users)
            {
                int slash = subKey.IndexOf('\\');
                string sidPrefix = slash > 0 ? subKey[..slash] : string.Empty;
                if (!string.IsNullOrEmpty(sidPrefix))
                    appKey = root.OpenSubKey($@"{sidPrefix}\{approvedRel}", false);
            }
            else
            {
                appKey = root.OpenSubKey(approvedRel, false);
            }

            using (appKey)
            {
                if (appKey?.GetValue(valName) is byte[] bytes && bytes.Length > 0)
                {
                    // 首字节 0x02 = 启用，0x03/0x01 = 禁用
                    return bytes[0] == 0x02;
                }
            }
        }
        catch { }
        return true;
    }

    private void ScanDirectoryShortcuts(string dirPath, string catName, List<ManagedStartupItem> list)
    {
        if (!Directory.Exists(dirPath)) return;
        try
        {
            bool isCommon = dirPath.Contains("ProgramData", StringComparison.OrdinalIgnoreCase);
            RegistryKey approvedRoot = isCommon ? Registry.LocalMachine : Registry.CurrentUser;
            const string folderApprovedKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder";
            using var appFolderKey = approvedRoot.OpenSubKey(folderApprovedKey, false);

            foreach (var file in Directory.EnumerateFiles(dirPath))
            {
                string fileName = Path.GetFileName(file);
                if (fileName.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase))
                    continue;
                bool isEnabled = true;
                if (appFolderKey?.GetValue(fileName) is byte[] bytes && bytes.Length > 0)
                {
                    isEnabled = bytes[0] == 0x02;
                }
                var (publisher, hasSig) = ExtractPublisher(file);
                list.Add(new ManagedStartupItem
                {
                    DisplayName = fileName,
                    Publisher = publisher,
                    HasSignature = hasSig,
                    CommandOrPath = file,
                    LocationKey = file,
                    Category = MonitorCategory.StartupItem,
                    CategoryName = catName,
                    CategoryIcon = "FolderOpen24",
                    IsEnabled = isEnabled,
                    StatusSummary = isEnabled ? "文件夹内有效" : "已在 StartupApproved 中禁止",
                    RawState = file,
                    IsMicrosoftOrSystemBuiltIn = DetectIsMicrosoftOrSystem(publisher, Path.GetFileName(file), file, MonitorCategory.StartupItem)
                });
            }
        }
        catch { }
    }

    private (List<ManagedStartupItem> Services, List<ManagedStartupItem> Drivers) ScanServicesAndDrivers()
    {
        var services = new List<ManagedStartupItem>();
        var drivers = new List<ManagedStartupItem>();
        try
        {
            using var servicesKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services", false);
            if (servicesKey is null) return (services, drivers);

            foreach (string name in servicesKey.GetSubKeyNames())
            {
                try
                {
                    using var single = servicesKey.OpenSubKey(name, false);
                    if (single is null) continue;

                    int type = Convert.ToInt32(single.GetValue("Type") ?? 0);
                    bool isWin32Service = (type & 0x10) != 0 || (type & 0x20) != 0;
                    bool isKernelDriver = !isWin32Service && ((type & 0x01) != 0 || (type & 0x02) != 0 || (type & 0x08) != 0);
                    if (!isWin32Service && !isKernelDriver) continue;

                    int start = Convert.ToInt32(single.GetValue("Start") ?? 3);
                    int delayed = Convert.ToInt32(single.GetValue("DelayedAutostart") ?? 0);
                    string imagePath = single.GetValue("ImagePath")?.ToString() ?? string.Empty;
                    string rawDisplayName = single.GetValue("DisplayName")?.ToString() ?? string.Empty;
                    string displayName = CleanDisplayName(rawDisplayName, name);

                    bool isEnabled = start != 4;
                    var (publisher, hasSig) = ExtractPublisher(imagePath);
                    var category = isWin32Service ? MonitorCategory.Win32Service : MonitorCategory.KernelDriver;
                    InterceptionAction stateAction = start switch
                    {
                        4 => InterceptionAction.RollbackToDisabled,
                        3 => InterceptionAction.RollbackToDemand,
                        2 when isWin32Service && delayed == 1 => InterceptionAction.RollbackToDelayedAuto,
                        _ => InterceptionAction.Allow
                    };

                    var item = new ManagedStartupItem
                    {
                        DisplayName = displayName,
                        Publisher = publisher,
                        HasSignature = hasSig,
                        CommandOrPath = imagePath,
                        LocationKey = $@"HKLM\SYSTEM\CurrentControlSet\Services\{name}",
                        Category = category,
                        CategoryName = isWin32Service ? "系统服务" : "内核驱动",
                        CategoryIcon = isWin32Service ? "Settings24" : "ShieldKeyhole24",
                        IsEnabled = isEnabled,
                        CurrentStateAction = stateAction,
                        StatusSummary = isWin32Service
                            ? start switch
                            {
                                2 when delayed == 1 => "延迟自动启动",
                                2 => "自动启动",
                                3 => "手动启动",
                                4 => "已禁止",
                                _ => $"Start={start}"
                            }
                            : start switch
                            {
                                0 => "引导加载 (Boot)",
                                1 => "系统加载 (System)",
                                2 => "自动加载 (Auto)",
                                3 => "按需加载 (Demand)",
                                4 => "已禁止",
                                _ => $"Start={start}"
                            },
                        RawState = $"Start={start}, Delayed={delayed}, Type=0x{type:X}",
                        IsMicrosoftOrSystemBuiltIn = DetectIsMicrosoftOrSystem(publisher, displayName, imagePath, category)
                    };

                    if (isWin32Service)
                        services.Add(item);
                    else
                        drivers.Add(item);
                }
                catch { }
            }
        }
        catch { }
        return (services, drivers);
    }

    private List<ManagedStartupItem> ScanScheduledTasks()
    {
        var list = new List<ManagedStartupItem>();
        var seenRelPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // 1. 优先通过 Task Scheduler COM (Schedule.Service) 读取真实 Enabled 状态与 XML
        try
        {
            Type? comType = Type.GetTypeFromProgID("Schedule.Service");
            if (comType != null)
            {
                dynamic svc = Activator.CreateInstance(comType)!;
                svc.Connect();
                dynamic rootFolder = svc.GetFolder(@"\");
                CollectComScheduledTasks(rootFolder, seenRelPaths, list);
            }
        }
        catch { }

        // 2. 补充扫描 System32\Tasks 文件目录中未被 COM 枚举到的任务
        string tasksDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), @"System32\Tasks");
        if (Directory.Exists(tasksDir))
        {
            try
            {
                foreach (var file in Directory.EnumerateFiles(tasksDir, "*", SearchOption.AllDirectories))
                {
                    string relName = Path.GetRelativePath(tasksDir, file).TrimStart('\\');
                    if (seenRelPaths.Contains(relName))
                        continue;

                    string cmd = file;
                    string author = string.Empty;
                    bool isEnabled = true;
                    if (PrivilegedRollbackEngine.TryParseScheduledTaskXml(file, isXmlContent: false, out string parsedCmd, out string parsedAuthor, out bool parsedEnabled))
                    {
                        if (!string.IsNullOrWhiteSpace(parsedCmd)) cmd = parsedCmd;
                        author = parsedAuthor;
                        isEnabled = parsedEnabled;
                    }

                    AddScheduledTaskItem(relName, Path.GetFileName(file), cmd, author, isEnabled, file, list);
                }
            }
            catch { }
        }

        return list;
    }

    private void CollectComScheduledTasks(dynamic folder, HashSet<string> seenRelPaths, List<ManagedStartupItem> list)
    {
        try
        {
            dynamic tasks = folder.GetTasks(1 /* TASK_ENUM_HIDDEN */);
            foreach (dynamic task in tasks)
            {
                try
                {
                    string fullTaskPath = (string)task.Path;
                    string relName = fullTaskPath.TrimStart('\\');
                    if (string.IsNullOrEmpty(relName) || !seenRelPaths.Add(relName))
                        continue;

                    bool isEnabled = (bool)task.Enabled;
                    string name = (string)task.Name;
                    string xml = string.Empty;
                    try { xml = (string)task.Xml; } catch { }

                    string cmd = string.Empty;
                    string author = string.Empty;
                    if (!string.IsNullOrEmpty(xml))
                    {
                        PrivilegedRollbackEngine.TryParseScheduledTaskXml(xml, isXmlContent: true, out cmd, out author, out _);
                    }
                    if (string.IsNullOrWhiteSpace(cmd))
                    {
                        string xmlFile = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), @"System32\Tasks", relName);
                        if (File.Exists(xmlFile))
                            cmd = xmlFile;
                    }

                    AddScheduledTaskItem(relName, name, cmd, author, isEnabled, xml, list);
                }
                catch { }
            }

            dynamic subFolders = folder.GetFolders(0);
            foreach (dynamic sub in subFolders)
            {
                CollectComScheduledTasks(sub, seenRelPaths, list);
            }
        }
        catch { }
    }

    private void AddScheduledTaskItem(
        string relName,
        string displayName,
        string commandOrPath,
        string xmlAuthor,
        bool isEnabled,
        string rawState,
        List<ManagedStartupItem> list)
    {
        var (publisher, hasSig) = !string.IsNullOrWhiteSpace(commandOrPath)
            ? ExtractPublisher(commandOrPath)
            : ("未知发布者", false);

        if ((publisher == "未知发布者" || publisher == "第三方未签名") && !string.IsNullOrWhiteSpace(xmlAuthor))
        {
            publisher = xmlAuthor.StartsWith("Microsoft", StringComparison.OrdinalIgnoreCase)
                ? "Microsoft Corporation"
                : xmlAuthor;
        }

        string locationKey = $@"Task: \{relName}";
        list.Add(new ManagedStartupItem
        {
            DisplayName = string.IsNullOrWhiteSpace(displayName) ? Path.GetFileName(relName) : displayName,
            Publisher = publisher,
            HasSignature = hasSig,
            CommandOrPath = string.IsNullOrWhiteSpace(commandOrPath) ? locationKey : commandOrPath,
            LocationKey = locationKey,
            Category = MonitorCategory.ScheduledTask,
            CategoryName = "计划任务",
            CategoryIcon = "Clock24",
            IsEnabled = isEnabled,
            CurrentStateAction = isEnabled ? InterceptionAction.Allow : InterceptionAction.RollbackToDisabled,
            StatusSummary = isEnabled ? "已启用" : "已禁用",
            RawState = rawState,
            IsMicrosoftOrSystemBuiltIn = DetectIsMicrosoftOrSystem(publisher, relName, commandOrPath, MonitorCategory.ScheduledTask, locationKey)
        });
    }

    private List<ManagedStartupItem> ScanContextMenus()
    {
        var list = new List<ManagedStartupItem>();
        try
        {
            var menus = _contextMenuEngine.ScanAllContextMenus(null);
            foreach (var menu in menus)
            {
                var (pub, hasSig, prodName) = ExtractPublisherDetails(menu.TargetBinaryOrCommand);
                string cleanTitle = CleanDisplayName(menu.DisplayTitle, menu.IdKey);
                string publisher = !string.IsNullOrEmpty(pub) && pub != "未知发布者" ? pub : (!string.IsNullOrEmpty(menu.Publisher) ? menu.Publisher : "外壳扩展");

                // WinX / SendTo 内置系统快捷方式纠正归属为 Microsoft Windows（避免 .lnk/.MAPIMail 无签名被误标“第三方未签名”）
                bool isSystemWinX = (menu.RegistryPath.Contains(@"\Microsoft\Windows\WinX\", StringComparison.OrdinalIgnoreCase) ||
                    menu.RegistryPath.Contains(@"\WinX\Group", StringComparison.OrdinalIgnoreCase)) &&
                    BuiltInWinXNames.Any(k => cleanTitle.Contains(k, StringComparison.OrdinalIgnoreCase));
                bool isSystemSendTo = menu.RegistryPath.Contains(@"\Microsoft\Windows\SendTo\", StringComparison.OrdinalIgnoreCase) &&
                    (menu.RegistryPath.EndsWith(".DeskLink", StringComparison.OrdinalIgnoreCase) ||
                     menu.RegistryPath.EndsWith(".MAPIMail", StringComparison.OrdinalIgnoreCase) ||
                     menu.RegistryPath.EndsWith(".ZFSendToTarget", StringComparison.OrdinalIgnoreCase) ||
                     menu.RegistryPath.EndsWith(".mydocs", StringComparison.OrdinalIgnoreCase) ||
                     cleanTitle.Contains("传真", StringComparison.OrdinalIgnoreCase) ||
                     cleanTitle.Contains("Fax", StringComparison.OrdinalIgnoreCase) ||
                     cleanTitle.Contains("蓝牙", StringComparison.OrdinalIgnoreCase) ||
                     cleanTitle.Contains("Bluetooth", StringComparison.OrdinalIgnoreCase));

                if (isSystemWinX || isSystemSendTo)
                {
                    publisher = "Microsoft Windows";
                    hasSig = true;
                }

                list.Add(new ManagedStartupItem
                {
                    DisplayName = cleanTitle,
                    Publisher = publisher,
                    HasSignature = hasSig,
                    ProductName = prodName,
                    CommandOrPath = menu.TargetBinaryOrCommand,
                    LocationKey = menu.RegistryPath,
                    Category = menu.MenuCategory,
                    CategoryName = ContextMenuSceneHelper.DescribeScene(menu.MenuCategory, menu.RegistryPath, menu.ScopeScene),
                    CategoryIcon = "AppsListDetail24",
                    IsEnabled = menu.IsEnabled,
                    StatusSummary = menu.IsEnabled ? "已启用" : "已禁止/屏蔽",
                    RawState = menu.TargetBinaryOrCommand,
                    Clsid = menu.Clsid,
                    MenuIdKey = menu.IdKey,
                    ScopeScene = menu.ScopeScene,
                    RealIconSource = ProgramIconResolver.ResolveIcon(menu.TargetBinaryOrCommand, menu.MenuCategory),
                    IsMicrosoftOrSystemBuiltIn = DetectIsMicrosoftOrSystem(publisher, cleanTitle, menu.TargetBinaryOrCommand, menu.MenuCategory, menu.RegistryPath)
                });
            }
        }
        catch { }
        return list;
    }

    public List<ManagedStartupItem> ScanFileTypeContextMenus(string fileTypeMode, string? param)
    {
        var list = new List<ManagedStartupItem>();
        if (!OperatingSystem.IsWindows())
            return list;

        try
        {
            foreach (var menu in _contextMenuEngine.ScanFileTypeScene(fileTypeMode, param, null))
            {
                string cleanTitle = CleanDisplayName(menu.DisplayTitle, menu.DisplayTitle);
                var (publisher, hasSig, prodName) = ExtractPublisherDetails(menu.TargetBinaryOrCommand);
                list.Add(new ManagedStartupItem
                {
                    DisplayName = cleanTitle,
                    Publisher = publisher,
                    HasSignature = hasSig,
                    ProductName = prodName,
                    CommandOrPath = menu.TargetBinaryOrCommand,
                    LocationKey = menu.RegistryPath,
                    Category = menu.MenuCategory,
                    CategoryName = ContextMenuSceneHelper.DescribeScene(menu.MenuCategory, menu.RegistryPath, menu.ScopeScene),
                    CategoryIcon = "AppsListDetail24",
                    IsEnabled = menu.IsEnabled,
                    StatusSummary = menu.IsEnabled ? "已启用" : "已禁止/屏蔽",
                    RawState = menu.TargetBinaryOrCommand,
                    Clsid = menu.Clsid,
                    MenuIdKey = menu.IdKey,
                    ScopeScene = menu.ScopeScene,
                    RealIconSource = ProgramIconResolver.ResolveIcon(menu.TargetBinaryOrCommand, menu.MenuCategory),
                    IsMicrosoftOrSystemBuiltIn = DetectIsMicrosoftOrSystem(publisher, cleanTitle, menu.TargetBinaryOrCommand, menu.MenuCategory, menu.RegistryPath)
                });
            }
        }
        catch { }
        return list;
    }

    public (string OpenModeProgId, string PerceivedType) GetExtensionOpenModeAndPerceivedType(string ext)
        => _contextMenuEngine.GetExtensionOpenModeAndPerceivedType(ext, null);

    public bool SetExtensionPerceivedType(string ext, string? perceivedType)
        => _contextMenuEngine.SetExtensionPerceivedType(ext, perceivedType, null);

    public List<ContextMenuManagerEngine.MenuAnalysisMatch> AnalyzeContextMenuTarget(string targetPath, bool isFolder)
        => _contextMenuEngine.AnalyzeTargetForContextMenu(targetPath, isFolder, null);

    public int GetDefaultDropEffect() => _contextMenuEngine.GetDefaultDropEffect();

    public bool SetDefaultDropEffect(int effect) => _contextMenuEngine.SetDefaultDropEffect(effect);

    public string InspectOpenWithRegistrationSources(string ext)
        => _contextMenuEngine.InspectOpenWithRegistrationSources(ext, null);

    public bool AddGuidBlockedEntry(string rawGuid)
        => _contextMenuEngine.AddGuidBlockedEntry(rawGuid, null);

    public List<ManagedStartupItem> ScanGuidBlockedEntries()
    {
        var list = new List<ManagedStartupItem>();
        try
        {
            foreach (var entry in _contextMenuEngine.ScanGuidBlockedEntries(null))
            {
                var (pub, hasSig, prodName) = ExtractPublisherDetails(entry.TargetBinaryOrCommand);
                string cleanTitle = CleanDisplayName(entry.DisplayTitle, entry.Clsid);
                string publisher = !string.IsNullOrEmpty(pub) && pub != "未知发布者" ? pub : "外壳扩展 (CLSID)";
                list.Add(new ManagedStartupItem
                {
                    DisplayName = cleanTitle,
                    Publisher = publisher,
                    HasSignature = hasSig,
                    ProductName = prodName,
                    CommandOrPath = entry.TargetBinaryOrCommand,
                    LocationKey = entry.RegistryPath,
                    Category = entry.MenuCategory,
                    CategoryName = "GUID 锁 (Blocked)",
                    CategoryIcon = "LockClosed24",
                    IsEnabled = entry.IsEnabled,
                    StatusSummary = "已锁定阻止",
                    RawState = entry.TargetBinaryOrCommand,
                    Clsid = entry.Clsid,
                    MenuIdKey = entry.IdKey,
                    ScopeScene = "Scene_GuidBlocked",
                    RealIconSource = ProgramIconResolver.ResolveIcon(entry.TargetBinaryOrCommand, entry.MenuCategory),
                    IsMicrosoftOrSystemBuiltIn = false
                });
            }
        }
        catch { }
        return list;
    }

    private List<ManagedStartupItem> ScanPolicies()
    {
        var list = new List<ManagedStartupItem>();
        try
        {
            // IFEO Debugger
            using var ifeo = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", false);
            if (ifeo is not null)
            {
                foreach (string sub in ifeo.GetSubKeyNames())
                {
                    using var itemKey = ifeo.OpenSubKey(sub);
                    string debugger = itemKey?.GetValue("Debugger")?.ToString() ?? string.Empty;
                    if (!string.IsNullOrEmpty(debugger))
                    {
                        list.Add(new ManagedStartupItem
                        {
                            DisplayName = $"IFEO 映像劫持: {sub}",
                            Publisher = "系统调试器劫持",
                            HasSignature = false,
                            CommandOrPath = debugger,
                            LocationKey = $@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\{sub}\Debugger",
                            Category = MonitorCategory.WindowsPolicy,
                            CategoryName = "系统策略/劫持",
                            CategoryIcon = "Warning24",
                            IsEnabled = true,
                            StatusSummary = $"劫持目标: {debugger}",
                            RawState = debugger,
                            IsMicrosoftOrSystemBuiltIn = true
                        });
                    }
                }
            }
        }
        catch { }
        return list;
    }

    /// <summary>
    /// 切换某个自启项的状态 (启用 / 禁止)
    /// </summary>
    public bool ToggleItemEnabled(ManagedStartupItem item, bool enable)
    {
        var targetAction = enable
            ? (item.Category == MonitorCategory.KernelDriver ? InterceptionAction.RollbackToDemand : InterceptionAction.Allow)
            : InterceptionAction.RollbackToDisabled;
        return SetItemAction(item, targetAction);
    }

    /// <summary>
    /// 设置项目的具体状态动作（支持服务自动/延迟/手动/禁止，驱动自动/手动/禁止，计划任务/自启项/右键启用与禁止等全操作）
    /// </summary>
    public bool SetItemAction(ManagedStartupItem item, InterceptionAction targetAction)
    {
        bool enable = targetAction != InterceptionAction.RollbackToDisabled &&
                      targetAction != InterceptionAction.DeleteEntry;

        if (!OperatingSystem.IsWindows())
        {
            item.IsEnabled = enable;
            item.CurrentStateAction = targetAction;
            item.StatusSummary = targetAction switch
            {
                InterceptionAction.RollbackToDelayedAuto => "延迟自动启动 (模拟)",
                InterceptionAction.RollbackToDemand => "手动启动 (模拟)",
                InterceptionAction.RollbackToDisabled => "已禁止 (模拟)",
                _ => "已启用 (模拟)"
            };
            return true;
        }

        if (string.Equals(item.ScopeScene, "Scene_GuidBlocked", StringComparison.OrdinalIgnoreCase))
        {
            bool ok = _contextMenuEngine.SetWin11ModernMenuBlockedState(item.Clsid, blockItem: enable, null);
            if (ok)
            {
                item.IsEnabled = enable;
                item.CurrentStateAction = targetAction;
                item.StatusSummary = enable ? "已锁定阻止" : "已解除锁定";
            }
            return ok;
        }

        try
        {
            // 先同步告知后台服务本次变更为本程序内用户主动操作，防止误拦截弹窗
            StartupGuard.Core.Ipc.BinaryPipeSerializer.NotifyServiceSuppressSelfMutation(
                item.LocationKey,
                item.Category,
                item.CommandOrPath,
                20.0);
            if (!string.IsNullOrWhiteSpace(item.Clsid))
            {
                StartupGuard.Core.Ipc.BinaryPipeSerializer.NotifyServiceSuppressSelfMutation(
                    $"Approved:{item.Clsid}",
                    item.Category,
                    item.CommandOrPath,
                    20.0);
            }

            // 优先委托给 LocalSystem 后台服务执行提权操作（解决 HKLM/Run、服务/驱动、计划任务与 Shell Extensions\Blocked 无权限写入问题）
            if (!PrivilegedRollbackEngine.IsUwpStartupLocation(item.LocationKey) &&
                StartupGuard.Core.Ipc.BinaryPipeSerializer.TrySendManualMutation(
                    new StartupGuard.Core.Models.ManualItemMutationPayload
                    {
                        Category = item.Category,
                        LocationKey = item.LocationKey,
                        TargetBinaryPath = item.CommandOrPath,
                        Action = targetAction,
                        DisplayName = item.DisplayName
                    },
                    out bool serviceSucceeded))
            {
                if (serviceSucceeded)
                {
                    ApplyStateLabelToItem(item, targetAction);
                }
                return serviceSucceeded;
            }

            switch (item.Category)
            {
                case MonitorCategory.StartupItem:
                {
                    if (PrivilegedRollbackEngine.IsUwpStartupLocation(item.LocationKey))
                    {
                        bool uwpOk = PrivilegedRollbackEngine.SetUwpStartupTaskState(item.LocationKey, null, enable);
                        if (uwpOk)
                        {
                            item.IsEnabled = enable;
                            item.CurrentStateAction = targetAction;
                            item.StatusSummary = enable ? "商店应用开机自启" : "已在 UWP 自启中禁止";
                        }
                        return uwpOk;
                    }

                    // 从 LocationKey 解析准确的值名与 Hive（修复 HKLM\...\Run 与 Run32 未写入对应根键的漏洞）
                    byte[] approvedData = enable
                        ? [0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
                        : [0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

                    bool isStartupFolder = item.LocationKey.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase) ||
                                           item.LocationKey.Contains(@"\Start Menu\Programs\Startup", StringComparison.OrdinalIgnoreCase);
                    if (isStartupFolder)
                    {
                        string fileName = Path.GetFileName(item.LocationKey);
                        bool isCommon = item.LocationKey.Contains("ProgramData", StringComparison.OrdinalIgnoreCase);
                        RegistryKey folderRoot = isCommon ? Registry.LocalMachine : Registry.CurrentUser;
                        using var fKey = folderRoot.CreateSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder");
                        if (fKey == null) return false;
                        fKey.SetValue(fileName, approvedData, RegistryValueKind.Binary);
                        ApplyStateLabelToItem(item, targetAction);
                        return true;
                    }

                    var (hive, subKey, valName) = PrivilegedRollbackEngine.SplitRegistryLocation(item.LocationKey, null);
                    if (string.IsNullOrWhiteSpace(valName))
                        valName = item.DisplayName;
                    string approvedSubKey = subKey.Contains("WOW6432Node", StringComparison.OrdinalIgnoreCase)
                        ? @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32"
                        : @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";
                    RegistryKey regRoot = hive == PrivilegedRollbackEngine.HKEY_LOCAL_MACHINE
                        ? Registry.LocalMachine
                        : Registry.CurrentUser;
                    using var key = regRoot.CreateSubKey(approvedSubKey);
                    if (key == null) return false;
                    key.SetValue(valName, approvedData, RegistryValueKind.Binary);
                    ApplyStateLabelToItem(item, targetAction);
                    return true;
                }

                case MonitorCategory.Win32Service:
                case MonitorCategory.KernelDriver:
                {
                    bool ok = PrivilegedRollbackEngine.RollbackServiceOrDriverStartType(
                        item.LocationKey,
                        targetAction,
                        item.Category == MonitorCategory.KernelDriver);
                    if (ok)
                    {
                        ApplyStateLabelToItem(item, targetAction);
                    }
                    return ok;
                }

                case MonitorCategory.ScheduledTask:
                {
                    var dummy = NativeSecurityExtractor.BuildTargetProgramFeatures(
                        MonitorCategory.ScheduledTask,
                        item.LocationKey,
                        item.CommandOrPath);
                    bool ok = targetAction == InterceptionAction.Allow
                        ? PrivilegedRollbackEngine.RestoreItemEnabled(dummy)
                        : PrivilegedRollbackEngine.RollbackScheduledTask(item.LocationKey, InterceptionAction.RollbackToDisabled);
                    if (ok)
                    {
                        ApplyStateLabelToItem(item, targetAction);
                    }
                    return ok;
                }

                case MonitorCategory.ClassicContextMenu:
                case MonitorCategory.ModernContextMenu:
                {
                    string effectiveIdKey = !string.IsNullOrWhiteSpace(item.MenuIdKey) ? item.MenuIdKey : item.Clsid;
                    var entry = new ContextMenuItemEntry
                    {
                        IdKey = effectiveIdKey,
                        DisplayTitle = item.DisplayName,
                        MenuCategory = item.Category,
                        ScopeScene = item.ScopeScene,
                        RegistryPath = item.LocationKey,
                        Clsid = item.Clsid,
                        TargetBinaryOrCommand = item.CommandOrPath,
                        IsEnabled = item.IsEnabled
                    };
                    bool ok = _contextMenuEngine.SetContextMenuItemEnabledState(entry, enable, null);
                    if (ok)
                    {
                        item.IsEnabled = enable;
                        item.CurrentStateAction = targetAction;
                        item.LocationKey = entry.RegistryPath;
                        item.StatusSummary = enable ? "已启用" : "已屏蔽";
                    }
                    return ok;
                }

                default:
                    item.IsEnabled = enable;
                    item.CurrentStateAction = targetAction;
                    return true;
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[SystemStartupItemsManager] SetItemAction failed: {ex.Message}");
            return false;
        }
    }

    private static void ApplyStateLabelToItem(ManagedStartupItem item, InterceptionAction action)
    {
        item.CurrentStateAction = action;
        item.IsEnabled = action != InterceptionAction.RollbackToDisabled && action != InterceptionAction.DeleteEntry;
        if (item.Category == MonitorCategory.Win32Service)
        {
            item.StatusSummary = action switch
            {
                InterceptionAction.Allow => "自动启动",
                InterceptionAction.RollbackToDelayedAuto => "延迟自动启动",
                InterceptionAction.RollbackToDemand => "手动启动",
                InterceptionAction.RollbackToDisabled => "已禁止",
                _ => item.StatusSummary
            };
        }
        else if (item.Category == MonitorCategory.KernelDriver)
        {
            item.StatusSummary = action switch
            {
                InterceptionAction.Allow => "自动加载 (Auto)",
                InterceptionAction.RollbackToDemand => "按需加载 (Demand)",
                InterceptionAction.RollbackToDisabled => "已禁止",
                _ => item.StatusSummary
            };
        }
        else if (item.Category == MonitorCategory.ScheduledTask)
        {
            item.StatusSummary = item.IsEnabled ? "已启用" : "已禁用";
        }
        else
        {
            item.StatusSummary = item.IsEnabled ? "已恢复启用" : "已禁止/屏蔽";
        }
    }

    /// <summary>
    /// 删除指定启动项或右键菜单项
    /// </summary>
    public bool DeleteItem(ManagedStartupItem item)
    {
        if (item.Category == MonitorCategory.KernelDriver)
            return false;

        if (!OperatingSystem.IsWindows())
            return true;

        try
        {
            StartupGuard.Core.Ipc.BinaryPipeSerializer.NotifyServiceSuppressSelfMutation(
                item.LocationKey,
                item.Category,
                item.CommandOrPath,
                20.0);
            if (!string.IsNullOrWhiteSpace(item.Clsid))
            {
                StartupGuard.Core.Ipc.BinaryPipeSerializer.NotifyServiceSuppressSelfMutation(
                    $"Approved:{item.Clsid}",
                    item.Category,
                    item.CommandOrPath,
                    20.0);
            }

            if (item.Category == MonitorCategory.StartupItem &&
                PrivilegedRollbackEngine.IsUwpStartupLocation(item.LocationKey))
            {
                return PrivilegedRollbackEngine.SetUwpStartupTaskState(item.LocationKey, null, enable: false);
            }

            if (string.Equals(item.ScopeScene, "Scene_GuidBlocked", StringComparison.OrdinalIgnoreCase))
            {
                return _contextMenuEngine.SetWin11ModernMenuBlockedState(item.Clsid, blockItem: false, null);
            }

            if (item.Category is MonitorCategory.ClassicContextMenu or MonitorCategory.ModernContextMenu)
            {
                return _contextMenuEngine.DeleteContextMenuEntry(item.LocationKey, null);
            }

            if (item.Category == MonitorCategory.StartupItem && File.Exists(item.LocationKey))
            {
                File.Delete(item.LocationKey);
                return true;
            }

            if (item.Category == MonitorCategory.Win32Service)
            {
                return PrivilegedRollbackEngine.DeleteServiceByName(item.LocationKey);
            }

            if (item.Category == MonitorCategory.ScheduledTask)
            {
                return PrivilegedRollbackEngine.RollbackScheduledTask(item.LocationKey, InterceptionAction.DeleteEntry);
            }

            if (item.LocationKey.StartsWith("HKCU\\", StringComparison.OrdinalIgnoreCase))
            {
                string path = item.LocationKey[5..];
                int lastSlash = path.LastIndexOf('\\');
                string subKey = path[..lastSlash];
                string valName = path[(lastSlash + 1)..];
                using var key = Registry.CurrentUser.OpenSubKey(subKey, true);
                key?.DeleteValue(valName, false);
                return true;
            }

            if (item.LocationKey.StartsWith("HKLM\\", StringComparison.OrdinalIgnoreCase))
            {
                string path = item.LocationKey[5..];
                int lastSlash = path.LastIndexOf('\\');
                string subKey = path[..lastSlash];
                string valName = path[(lastSlash + 1)..];
                using var key = Registry.LocalMachine.OpenSubKey(subKey, true);
                key?.DeleteValue(valName, false);
                return true;
            }
        }
        catch { }
        return false;
    }

    private static readonly ConcurrentDictionary<string, (string Publisher, bool HasSig, string ProductName)> _publisherCache = new(StringComparer.OrdinalIgnoreCase);

    private static (string Publisher, bool HasSig) ExtractPublisher(string rawPath)
    {
        var (pub, sig, _) = ExtractPublisherDetails(rawPath);
        return (pub, sig);
    }

    public static (string Publisher, bool HasSig, string ProductName) ExtractPublisherDetails(string rawPath)
    {
        if (string.IsNullOrWhiteSpace(rawPath))
            return ("未知发布者", false, string.Empty);

        if (_publisherCache.TryGetValue(rawPath, out var cached))
            return cached;

        string cleanPath = ShellNavigationHelper.ResolvePhysicalFilePath(rawPath);
        if (!string.IsNullOrEmpty(cleanPath) && _publisherCache.TryGetValue(cleanPath, out cached))
        {
            _publisherCache[rawPath] = cached;
            return cached;
        }

        if (!string.IsNullOrEmpty(cleanPath) && File.Exists(cleanPath))
        {
            string productName = string.Empty;
            string company = string.Empty;
            try
            {
                var info = FileVersionInfo.GetVersionInfo(cleanPath);
                productName = info.ProductName?.Trim() ?? string.Empty;
                company = info.CompanyName?.Trim() ?? string.Empty;
            }
            catch { }

            try
            {
                // 1. 优先提取 Authenticode 数字签名 (WinVerifyTrust / Crypt32 / PE Security Directory)
                var (hasSig, signerSubject, _) = NativeSecurityExtractor.ExtractAuthenticodeDetails(cleanPath);
                if (!string.IsNullOrWhiteSpace(signerSubject))
                {
                    string friendlySubject = signerSubject;
                    if (friendlySubject.Contains("CN=", StringComparison.OrdinalIgnoreCase))
                    {
                        int cnIdx = friendlySubject.IndexOf("CN=", StringComparison.OrdinalIgnoreCase);
                        int endCn = friendlySubject.IndexOf(',', cnIdx);
                        friendlySubject = endCn > cnIdx ? friendlySubject.Substring(cnIdx + 3, endCn - cnIdx - 3).Trim() : friendlySubject.Substring(cnIdx + 3).Trim();
                    }
                    var res = (friendlySubject, true, productName);
                    _publisherCache[cleanPath] = res;
                    _publisherCache[rawPath] = res;
                    return res;
                }
            }
            catch { }

            if (!string.IsNullOrEmpty(company))
            {
                var res = (company, false, productName);
                _publisherCache[cleanPath] = res;
                _publisherCache[rawPath] = res;
                return res;
            }

            // 3. 检查是否位于 Windows 核心系统目录
            string winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            if (cleanPath.StartsWith(winDir, StringComparison.OrdinalIgnoreCase))
            {
                var res = ("Microsoft Windows", false, productName);
                _publisherCache[cleanPath] = res;
                _publisherCache[rawPath] = res;
                return res;
            }

            var def = ("第三方未签名", false, productName);
            _publisherCache[cleanPath] = def;
            _publisherCache[rawPath] = def;
            return def;
        }

        // 文件物理不存在时的合理推断
        string lower = rawPath.ToLowerInvariant();
        if (lower.Contains("microsoft") || lower.Contains("windows"))
        {
            var res = ("Microsoft Windows", false, string.Empty);
            _publisherCache[rawPath] = res;
            return res;
        }

        var unknown = ("未知发布者", false, string.Empty);
        _publisherCache[rawPath] = unknown;
        return unknown;
    }

    private static List<ManagedStartupItem> GenerateMockItems()
    {
        return
        [
            new()
            {
                DisplayName = "Sample 办公套件",
                Publisher = "Sample Vendor Co., Ltd.",
                HasSignature = true,
                CommandOrPath = @"C:\Program Files\SampleVendor\SampleSuite\SampleSuite.exe --autostart",
                LocationKey = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\SampleSuite",
                Category = MonitorCategory.StartupItem,
                CategoryName = "自启程序",
                CategoryIcon = "Rocket24",
                IsEnabled = true,
                StatusSummary = "正常开机自启"
            },
            new()
            {
                DisplayName = "SampleSuiteService",
                Publisher = "Sample Vendor Co., Ltd.",
                HasSignature = true,
                CommandOrPath = @"C:\Program Files\SampleVendor\SampleSuite\SampleService.exe",
                LocationKey = @"HKLM\SYSTEM\CurrentControlSet\Services\SampleSuiteService",
                Category = MonitorCategory.Win32Service,
                CategoryName = "系统服务",
                CategoryIcon = "Settings24",
                IsEnabled = true,
                StatusSummary = "自动启动 (Start=2)"
            },
            new()
            {
                DisplayName = "Sample 互联外壳扩展 (PackagedCom)",
                Publisher = "Sample Vendor Co., Ltd.",
                HasSignature = true,
                CommandOrPath = @"C:\Program Files\SampleVendor\SampleSuite\ShellExt.dll",
                LocationKey = @"HKLM\Software\Classes\PackagedCom\ClassIndex\{E821B2A1-80E1-4D90-8C31-29C496ACD581}",
                Category = MonitorCategory.ModernContextMenu,
                CategoryName = "Win11现代右键菜单",
                CategoryIcon = "AppsListDetail24",
                IsEnabled = true,
                StatusSummary = "右键菜单已启用"
            }
        ];
    }
}
