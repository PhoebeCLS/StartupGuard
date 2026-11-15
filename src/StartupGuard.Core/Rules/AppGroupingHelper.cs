using System.Text.RegularExpressions;
using StartupGuard.Core.Models;
using StartupGuard.Core.Scoring;

namespace StartupGuard.Core.Rules;

/// <summary>
/// 多信号应用归因与聚合辅助类（参考 GPL-3.0 开源项目 PLFJY/ContextMenuMgr 与 BluePointLilac/ContextMenuManager 按应用分组思路扩展实现）。
/// 综合安装根目录、UWP 包族、Authenticode/PE 发布者与可执行词干，
/// 将同一应用旗下的内核驱动、Win32 服务、自启程序、计划任务与右键菜单归并到统一应用分组。
/// </summary>
public static partial class AppGroupingHelper
{
    public sealed record AppAttributionInput<T>(
        T Item,
        MonitorCategory Category,
        string DisplayName,
        string PathOrCommand,
        string LocationKey,
        string Publisher,
        string Clsid = "",
        string ProductName = "",
        bool IsMicrosoftBuiltIn = false);

    public sealed record AppClusterGroup<T>(
        string AppKey,
        string AppTitle,
        string Subtitle,
        IReadOnlyList<T> Items);

    private static readonly HashSet<string> GenericFolders = new(StringComparer.OrdinalIgnoreCase)
    {
        "program files", "program files (x86)", "programdata", "appdata", "local", "roaming",
        "locallow", "users", "documents and settings", "public", "default", "common",
        "downloads", "download", "desktop", "documents", "my documents", "pictures", "videos", "music",
        "userdata", "profiles", "profile", "temp", "tmp", "cache",
        "windows", "system32", "syswow64", "drivers", "servicing",
        "windowsapps", "common files", "bin", "bin64", "bin32", "x64", "x86", "amd64",
        "win64", "win32", "arm64", "app", "apps", "application", "programs", "program",
        "root", "release", "debug", "shellextension", "shellextensions", "shellex",
        "extension", "extensions", "resources", "updater", "update", "service", "services",
        "daemon", "runtime", "current", "latest", "plugins", "plugin", "components"
    };

    private static readonly HashSet<string> NestedContainerFolders = new(StringComparer.OrdinalIgnoreCase)
    {
        "archive", "archives", "archieve", "portable", "portableapps",
        "soft", "software", "softwares", "green", "tools", "tool", "utilities", "myapps"
    };

    private static readonly HashSet<string> MultiProductVendorFolders = new(StringComparer.OrdinalIgnoreCase)
    {
        "microsoft", "adobe", "tencent", "alibaba", "bytedance", "netease", "baidu",
        "google", "autodesk", "jetbrains", "oracle", "intel", "amd", "nvidia", "realtek",
        "lenovo", "dell", "hp", "asus", "huawei", "xiaomi", "kingsoft", "360",
        "iobit", "wondershare", "easeus"
    };

    private static readonly HashSet<string> GenericRoleTokens = new(StringComparer.OrdinalIgnoreCase)
    {
        "driver", "scheduler", "service", "services", "updater", "update",
        "helper", "monitor", "manager", "launcher", "assistant", "skipuac",
        "lists", "windows", "sync"
    };

    private static readonly HashSet<string> GenericPublishers = new(StringComparer.OrdinalIgnoreCase)
    {
        "", "未知发布者", "第三方未签名", "外壳扩展", "系统内置",
        "microsoft windows", "microsoft corporation", "microsoft", "unknown"
    };

    private static readonly string[] GenericSuffixTokens =
    [
        "shellextensionx64", "shellextensionx86", "shellextension", "shellext",
        "contextmenu", "ctxmenu", "handler", "extension", "ext",
        "service", "svc", "driver", "drv", "helper", "updater", "update",
        "tray", "daemon", "agent", "broker", "host", "monitor", "worker",
        "startup", "launcher", "client", "x64", "x86", "amd64", "win64", "win32"
    ];

    [GeneratedRegex(@"^(v?\d+(\.\d+){1,4}|office\d+|net\d+\.\d+)$", RegexOptions.IgnoreCase)]
    private static partial Regex VersionFolderRegex();

    [GeneratedRegex(@"(?i)(co\.,?\s*ltd\.?|ltd\.?|inc\.?|corp\.?|corporation|llc|gmbh|s\.a\.|company|technologies|technology|software)")]
    private static partial Regex PublisherNoiseRegex();

    [GeneratedRegex(@"[_\-\.\s\\/:;,()\[\]{}""']+")]
    private static partial Regex TokenSplitRegex();

    /// <summary>
    /// 提取用于 ContextMenuManager“按应用查看”自动检索的精简关键词
    /// </summary>
    public static string ExtractAppSearchKeyword(
        string? displayName,
        string? pathOrCommand,
        string? locationKey = null,
        string? publisher = null,
        string? clsid = null)
    {
        var signals = AnalyzeSignals(pathOrCommand ?? string.Empty, locationKey ?? string.Empty, displayName ?? string.Empty, publisher ?? string.Empty, string.Empty, false);

        if (!string.IsNullOrWhiteSpace(signals.UwpAppName))
            return signals.UwpAppName;

        if (!string.IsNullOrWhiteSpace(signals.InstallRootLabel))
            return signals.InstallRootLabel;

        if (!string.IsNullOrWhiteSpace(signals.RawExeStem) && !IsGenericBinaryName(signals.RawExeStem))
            return CleanStemForKeyword(signals.RawExeStem);

        if (!string.IsNullOrWhiteSpace(publisher) && !IsGenericPublisher(publisher))
            return PublisherNoiseRegex().Replace(publisher, string.Empty).Trim(' ', ',', '.', '-');

        if (!string.IsNullOrWhiteSpace(displayName))
            return CleanStemForKeyword(displayName);

        return string.IsNullOrWhiteSpace(clsid) ? string.Empty : clsid.Trim();
    }

    /// <summary>
    /// 使用多信号融合（安装目录 + UWP 包族 + 签名主体 + 词干令牌）将异构条目按所属应用聚类
    /// </summary>
    public static List<AppClusterGroup<T>> ClusterByApplication<T>(IReadOnlyList<AppAttributionInput<T>> inputs)
    {
        if (inputs.Count == 0)
            return [];

        int n = inputs.Count;
        var signals = new ItemSignals[n];
        for (int i = 0; i < n; i++)
        {
            var inp = inputs[i];
            signals[i] = AnalyzeSignals(
                inp.PathOrCommand,
                inp.LocationKey,
                inp.DisplayName,
                inp.Publisher,
                inp.ProductName,
                inp.IsMicrosoftBuiltIn);
        }

        int[] parent = new int[n];
        for (int i = 0; i < n; i++) parent[i] = i;

        int Find(int x)
        {
            while (parent[x] != x)
            {
                parent[x] = parent[parent[x]];
                x = parent[x];
            }
            return x;
        }

        void Union(int a, int b)
        {
            int ra = Find(a);
            int rb = Find(b);
            if (ra != rb) parent[rb] = ra;
        }

        // Pass 1: 强归属信号合并 (UWP 包名前缀、同安装目录根、系统内置池)
        var byStrongKey = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < n; i++)
        {
            string key = !string.IsNullOrEmpty(signals[i].UwpKey)
                ? $"uwp:{signals[i].UwpKey}"
                : (!string.IsNullOrEmpty(signals[i].InstallRootKey)
                    ? $"dir:{signals[i].InstallRootKey}"
                    : (signals[i].TreatAsWindowsBuiltIn ? "sys:windows_builtin" : string.Empty));

            if (string.IsNullOrEmpty(key)) continue;

            if (byStrongKey.TryGetValue(key, out int existing))
                Union(existing, i);
            else
                byStrongKey[key] = i;
        }

        // 统计每个规范化发布者关联到的不同强安装目录数量 (防止大型多产品厂商误并，但允许单产品/关联内核驱动跨目录合并)
        var publisherInstallRoots = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < n; i++)
        {
            string pub = signals[i].NormalizedPublisher;
            if (string.IsNullOrEmpty(pub) || string.IsNullOrEmpty(signals[i].InstallRootKey))
                continue;

            if (!publisherInstallRoots.TryGetValue(pub, out var set))
            {
                set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                publisherInstallRoots[pub] = set;
            }
            set.Add(signals[i].InstallRootKey);
        }

        // Pass 2: 同非通用发布者合并 (解决 System32\drivers\*.sys 驱动与 App 目录内服务/主程序无法靠目录匹配的问题)
        var byPublisher = new Dictionary<string, List<int>>(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < n; i++)
        {
            string pub = signals[i].NormalizedPublisher;
            if (string.IsNullOrEmpty(pub) || signals[i].TreatAsWindowsBuiltIn)
                continue;

            if (!byPublisher.TryGetValue(pub, out var list))
            {
                list = [];
                byPublisher[pub] = list;
            }
            list.Add(i);
        }

        foreach (var (pub, indices) in byPublisher)
        {
            if (indices.Count <= 1) continue;
            int distinctRoots = publisherInstallRoots.TryGetValue(pub, out var roots) ? roots.Count : 0;

            if (distinctRoots <= 1)
            {
                // 同签名且仅存在 0~1 个安装目录 (例如某应用主程序 + 服务 + System32 驱动 + 右键扩展): 直接合并
                for (int k = 1; k < indices.Count; k++)
                    Union(indices[0], indices[k]);
            }
            else
            {
                // 若同发布者存在多个独立安装目录 (如 Adobe Acrobat vs Photoshop)，
                // 仅将无目录的关联驱动/服务并入与其产品词干重叠度最高的那个已有目录条目，绝不桥接两个不同的安装目录
                foreach (int noDirIdx in indices.Where(idx => string.IsNullOrEmpty(signals[idx].InstallRootKey)))
                {
                    int bestDirIdx = -1;
                    int bestOverlap = 0;
                    foreach (int dirIdx in indices.Where(idx => !string.IsNullOrEmpty(signals[idx].InstallRootKey)))
                    {
                        int overlap = CountDistinctiveTokenOverlap(signals[noDirIdx], signals[dirIdx]);
                        if (overlap > bestOverlap)
                        {
                            bestOverlap = overlap;
                            bestDirIdx = dirIdx;
                        }
                    }
                    if (bestDirIdx >= 0 && bestOverlap >= 1)
                    {
                        Union(bestDirIdx, noDirIdx);
                    }
                }
            }
        }

        // Pass 3: 无目录/无签名条目 (如 OpenWith / 已失效残留 / 纯注册表项) 通过高置信词干令牌桥接
        for (int i = 0; i < n; i++)
        {
            if (!string.IsNullOrEmpty(signals[i].InstallRootKey) ||
                !string.IsNullOrEmpty(signals[i].UwpKey) ||
                signals[i].TreatAsWindowsBuiltIn)
                continue;

            int bestTarget = -1;
            int bestScore = 0;
            for (int j = 0; j < n; j++)
            {
                if (i == j || Find(i) == Find(j) || signals[j].TreatAsWindowsBuiltIn)
                    continue;

                int overlap = CountDistinctiveTokenOverlap(signals[i], signals[j]);
                if (overlap > bestScore)
                {
                    bestScore = overlap;
                    bestTarget = j;
                }
            }

            if (bestTarget >= 0 && bestScore >= 1)
            {
                Union(bestTarget, i);
            }
        }

        // 构建最终分组与人类可读应用名
        var clusters = new Dictionary<int, List<int>>();
        for (int i = 0; i < n; i++)
        {
            int root = Find(i);
            if (!clusters.TryGetValue(root, out var members))
            {
                members = [];
                clusters[root] = members;
            }
            members.Add(i);
        }

        var result = new List<AppClusterGroup<T>>(clusters.Count);
        foreach (var (_, members) in clusters)
        {
            string appTitle = SelectClusterTitle(members, inputs, signals);
            string appKey = !string.IsNullOrEmpty(signals[members[0]].InstallRootKey)
                ? signals[members[0]].InstallRootKey
                : appTitle;
            string subtitle = BuildCategorySummary(members.Select(idx => inputs[idx].Category));

            var orderedItems = members
                .OrderBy(idx => CategorySortOrder(inputs[idx].Category))
                .ThenBy(idx => inputs[idx].DisplayName, StringComparer.CurrentCultureIgnoreCase)
                .Select(idx => inputs[idx].Item)
                .ToList();

            result.Add(new AppClusterGroup<T>(appKey, appTitle, subtitle, orderedItems));
        }

        return result
            .OrderBy(g => g.AppKey.Equals("sys:windows_builtin", StringComparison.OrdinalIgnoreCase) || g.AppTitle == "Windows 系统内置组件" ? 1 : 0)
            .ThenByDescending(g => g.Items.Count)
            .ThenBy(g => g.AppTitle, StringComparer.CurrentCultureIgnoreCase)
            .ToList();
    }

    public static string CategoryDisplayLabel(MonitorCategory category) => category switch
    {
        MonitorCategory.KernelDriver => "内核驱动",
        MonitorCategory.Win32Service => "Win32服务",
        MonitorCategory.StartupItem => "自启程序",
        MonitorCategory.ScheduledTask => "计划任务",
        MonitorCategory.ClassicContextMenu => "经典右键菜单",
        MonitorCategory.ModernContextMenu => "Win11 现代菜单",
        MonitorCategory.WindowsPolicy => "系统策略",
        _ => "其他"
    };

    private static int CategorySortOrder(MonitorCategory category) => category switch
    {
        MonitorCategory.StartupItem => 0,
        MonitorCategory.Win32Service => 1,
        MonitorCategory.KernelDriver => 2,
        MonitorCategory.ScheduledTask => 3,
        MonitorCategory.ModernContextMenu => 4,
        MonitorCategory.ClassicContextMenu => 5,
        MonitorCategory.WindowsPolicy => 6,
        _ => 7
    };

    private sealed class ItemSignals
    {
        public string UwpKey = string.Empty;
        public string UwpAppName = string.Empty;
        public string InstallRootKey = string.Empty;
        public string InstallRootLabel = string.Empty;
        public string NormalizedPublisher = string.Empty;
        public string RawExeStem = string.Empty;
        public string ProductName = string.Empty;
        public bool TreatAsWindowsBuiltIn;
        public HashSet<string> DistinctiveTokens = new(StringComparer.OrdinalIgnoreCase);
    }

    private static ItemSignals AnalyzeSignals(
        string pathOrCommand,
        string locationKey,
        string displayName,
        string publisher,
        string productName,
        bool isMicrosoftBuiltIn)
    {
        var sig = new ItemSignals
        {
            ProductName = (productName ?? string.Empty).Trim()
        };

        string cleanCmd = pathOrCommand ?? string.Empty;
        string exePath = PathNormalizerAndSimilarity.SplitCommandLine(cleanCmd).ExecutablePath;
        if (string.IsNullOrWhiteSpace(exePath))
            exePath = cleanCmd.Trim().Trim('"');

        exePath = Environment.ExpandEnvironmentVariables(exePath);
        if (exePath.StartsWith(@"\??\", StringComparison.OrdinalIgnoreCase))
            exePath = exePath[4..];
        else if (exePath.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
            exePath = Path.Combine(@"C:\Windows", exePath[@"\SystemRoot\".Length..]);

        sig.RawExeStem = TryGetFileNameWithoutExtensionSafe(exePath);

        // 1. 检查 WindowsApps (UWP / MSIX)
        string combinedPaths = $"{exePath} {locationKey}";
        int winAppsIdx = combinedPaths.IndexOf("WindowsApps\\", StringComparison.OrdinalIgnoreCase);
        if (winAppsIdx >= 0)
        {
            string rest = combinedPaths[(winAppsIdx + "WindowsApps\\".Length)..];
            int slash = rest.IndexOfAny(['\\', '/', ' ']);
            string pkgFolder = slash > 0 ? rest[..slash] : rest;
            int firstUnderscore = pkgFolder.IndexOf('_');
            string pkgFamilyPrefix = firstUnderscore > 0 ? pkgFolder[..firstUnderscore] : pkgFolder;
            if (!string.IsNullOrWhiteSpace(pkgFamilyPrefix))
            {
                sig.UwpKey = pkgFamilyPrefix.ToLowerInvariant();
                int lastDot = pkgFamilyPrefix.LastIndexOf('.');
                sig.UwpAppName = lastDot >= 0 && lastDot < pkgFamilyPrefix.Length - 1
                    ? pkgFamilyPrefix[(lastDot + 1)..]
                    : pkgFamilyPrefix;
            }
        }

        // 2. 提取非系统安装根目录
        TryExtractInstallRoot(exePath, out sig.InstallRootKey, out sig.InstallRootLabel);

        // 3. 发布者规范化 (保留非通用出版商；区分 Windows 内置与拥有独立安装目录的微软大型应用如 Office/PCManager/Edge)
        string trimmedPub = (publisher ?? string.Empty).Trim();
        bool isGenericPub = IsGenericPublisher(trimmedPub) || trimmedPub.Contains("Third Party Component CA", StringComparison.OrdinalIgnoreCase);
        if (!isGenericPub)
        {
            string normPub = PublisherNoiseRegex().Replace(trimmedPub, string.Empty).Trim();
            normPub = Regex.Replace(normPub, @"[\s,\.\-]+", "").ToLowerInvariant();
            if (normPub.Length >= 2)
                sig.NormalizedPublisher = normPub;
        }

        bool isWinSystemPath = exePath.Contains(@"\Windows\System32\", StringComparison.OrdinalIgnoreCase) ||
                               exePath.Contains(@"\Windows\SysWOW64\", StringComparison.OrdinalIgnoreCase) ||
                               exePath.Contains(@"\Windows\servicing\", StringComparison.OrdinalIgnoreCase) ||
                               locationKey.Contains(@"\Microsoft\Windows\WinX\", StringComparison.OrdinalIgnoreCase);
        sig.TreatAsWindowsBuiltIn = (isMicrosoftBuiltIn || (isWinSystemPath && string.IsNullOrEmpty(sig.NormalizedPublisher))) &&
                                    string.IsNullOrEmpty(sig.InstallRootKey) &&
                                    string.IsNullOrEmpty(sig.UwpKey);

        // 4. 提取用于桥接的高辨识度词干令牌 (过滤多产品厂商通用词以免 Adobe/Microsoft/Tencent 跨产品误合并)
        AddTokens(sig.DistinctiveTokens, sig.InstallRootLabel);
        AddTokens(sig.DistinctiveTokens, sig.UwpAppName);
        if (!IsGenericBinaryName(sig.RawExeStem))
            AddTokens(sig.DistinctiveTokens, CleanStemForKeyword(sig.RawExeStem));
        if (!string.IsNullOrWhiteSpace(sig.ProductName) && !IsGenericPublisher(sig.ProductName))
            AddTokens(sig.DistinctiveTokens, CleanStemForKeyword(sig.ProductName));
        if (string.IsNullOrEmpty(sig.InstallRootKey) && !sig.TreatAsWindowsBuiltIn)
            AddTokens(sig.DistinctiveTokens, CleanStemForKeyword(displayName ?? string.Empty));
        if (!string.IsNullOrEmpty(sig.NormalizedPublisher))
            sig.DistinctiveTokens.Remove(sig.NormalizedPublisher);

        return sig;
    }

    private static void TryExtractInstallRoot(string fullPath, out string rootKey, out string rootLabel)
    {
        rootKey = string.Empty;
        rootLabel = string.Empty;

        if (string.IsNullOrWhiteSpace(fullPath) || !fullPath.Contains('\\'))
            return;

        string? dir;
        try
        {
            dir = Path.GetDirectoryName(fullPath.Trim().Trim('"'));
        }
        catch
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(dir)) return;

        // 跳过 Windows 系统核心目录与浏览器运行时目录
        if (dir.Contains(@"\Windows\System32", StringComparison.OrdinalIgnoreCase) ||
            dir.Contains(@"\Windows\SysWOW64", StringComparison.OrdinalIgnoreCase) ||
            dir.Contains(@"\Windows\servicing", StringComparison.OrdinalIgnoreCase) ||
            dir.Contains(@"\Microsoft\Windows\WinX", StringComparison.OrdinalIgnoreCase) ||
            dir.EndsWith(@"\Windows", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        string[] segments = dir.Split(['\\', '/'], StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length <= 1) return;

        // 从根目录向叶节点寻找有意义的应用根目录
        for (int i = 1; i < segments.Length; i++)
        {
            string seg = segments[i].Trim();

            // 跳过 Windows 用户档案目录段 (C:\Users\<Username>\...)，防止同一用户名下的所有软件被误聚为同一应用
            if (seg.Equals("Users", StringComparison.OrdinalIgnoreCase) ||
                seg.Equals("Documents and Settings", StringComparison.OrdinalIgnoreCase))
            {
                if (i + 1 < segments.Length)
                    i++;
                continue;
            }

            if (GenericFolders.Contains(seg) ||
                VersionFolderRegex().IsMatch(seg) ||
                (i + 1 < segments.Length && NestedContainerFolders.Contains(seg)))
                continue;

            // 如 Program Files\Microsoft\Edge 或 AppData\Local\Tencent\WeChat -> 多产品厂商目录向下一级取具体产品
            if (MultiProductVendorFolders.Contains(seg) && i + 1 < segments.Length)
            {
                string next = segments[i + 1].Trim();
                if (!GenericFolders.Contains(next) && !VersionFolderRegex().IsMatch(next))
                {
                    rootKey = $"{seg.ToLowerInvariant()}\\{next.ToLowerInvariant()}";
                    rootLabel = next;
                    return;
                }
            }

            rootKey = seg.ToLowerInvariant();
            rootLabel = seg;
            return;
        }
    }

    private static void AddTokens(HashSet<string> target, string raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return;
        foreach (string part in TokenSplitRegex().Split(raw))
        {
            string cleaned = CleanStemForKeyword(part);
            if (cleaned.Length >= 4 &&
                !GenericFolders.Contains(cleaned) &&
                !NestedContainerFolders.Contains(cleaned) &&
                !MultiProductVendorFolders.Contains(cleaned) &&
                !GenericRoleTokens.Contains(cleaned) &&
                !IsGenericBinaryName(cleaned))
                target.Add(cleaned.ToLowerInvariant());
        }
        string whole = CleanStemForKeyword(raw);
        if (whole.Length >= 4 &&
            !GenericFolders.Contains(whole) &&
            !NestedContainerFolders.Contains(whole) &&
            !MultiProductVendorFolders.Contains(whole) &&
            !GenericRoleTokens.Contains(whole) &&
            !IsGenericBinaryName(whole))
            target.Add(whole.ToLowerInvariant());
    }

    private static string CleanStemForKeyword(string raw)
    {
        string s = (raw ?? string.Empty).Trim();
        if (s.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
            s.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ||
            s.EndsWith(".sys", StringComparison.OrdinalIgnoreCase) ||
            s.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase))
        {
            s = Path.GetFileNameWithoutExtension(s);
        }

        foreach (string suffix in GenericSuffixTokens)
        {
            if (s.Length > suffix.Length + 2 && s.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
            {
                s = s[..^suffix.Length].TrimEnd(' ', '-', '_', '.');
            }
        }
        return s.Trim();
    }

    private static bool SharesDistinctiveToken(ItemSignals a, ItemSignals b)
    {
        return CountDistinctiveTokenOverlap(a, b) > 0;
    }

    private static int CountDistinctiveTokenOverlap(ItemSignals a, ItemSignals b)
    {
        if (a.DistinctiveTokens.Count == 0 || b.DistinctiveTokens.Count == 0)
            return 0;

        int matches = 0;
        foreach (string t in a.DistinctiveTokens)
        {
            if (b.DistinctiveTokens.Contains(t))
                matches++;
        }
        return matches;
    }

    private static string SelectClusterTitle<T>(
        List<int> members,
        IReadOnlyList<AppAttributionInput<T>> inputs,
        ItemSignals[] signals)
    {
        if (members.All(i => signals[i].TreatAsWindowsBuiltIn))
            return "Windows 系统内置组件";

        // 优先: ProductName -> InstallRootLabel -> UwpAppName -> 非 CLSID 清晰 DisplayName -> Publisher
        string? productName = members
            .Select(i => signals[i].ProductName)
            .FirstOrDefault(p => !string.IsNullOrWhiteSpace(p) && !p.Contains("Microsoft Windows Operating System", StringComparison.OrdinalIgnoreCase));
        if (!string.IsNullOrWhiteSpace(productName))
            return productName;

        string? installLabel = members
            .Select(i => signals[i].InstallRootLabel)
            .FirstOrDefault(l => !string.IsNullOrWhiteSpace(l));
        if (!string.IsNullOrWhiteSpace(installLabel))
            return installLabel;

        string? uwpName = members
            .Select(i => signals[i].UwpAppName)
            .FirstOrDefault(l => !string.IsNullOrWhiteSpace(l));
        if (!string.IsNullOrWhiteSpace(uwpName))
            return uwpName;

        string? cleanDisplay = members
            .Select(i => inputs[i].DisplayName?.Trim())
            .FirstOrDefault(d => !string.IsNullOrWhiteSpace(d) && !d.StartsWith('{'));
        if (!string.IsNullOrWhiteSpace(cleanDisplay))
            return CleanStemForKeyword(cleanDisplay);

        return "未命名应用";
    }

    private static string BuildCategorySummary(IEnumerable<MonitorCategory> categories)
    {
        var counts = categories
            .GroupBy(c => c)
            .OrderBy(g => CategorySortOrder(g.Key))
            .Select(g => $"{ShortCategoryLabel(g.Key)} {g.Count()}");
        return string.Join(" · ", counts);
    }

    private static string ShortCategoryLabel(MonitorCategory category) => category switch
    {
        MonitorCategory.KernelDriver => "驱动",
        MonitorCategory.Win32Service => "服务",
        MonitorCategory.StartupItem => "自启",
        MonitorCategory.ScheduledTask => "任务",
        MonitorCategory.ClassicContextMenu or MonitorCategory.ModernContextMenu => "右键",
        MonitorCategory.WindowsPolicy => "策略",
        _ => "其他"
    };

    private static bool IsGenericPublisher(string publisher)
    {
        string p = publisher.Trim();
        return GenericPublishers.Contains(p);
    }

    private static bool IsGenericBinaryName(string stem)
    {
        if (string.IsNullOrWhiteSpace(stem)) return true;
        return stem.Equals("cmd", StringComparison.OrdinalIgnoreCase) ||
               stem.Equals("powershell", StringComparison.OrdinalIgnoreCase) ||
               stem.Equals("pwsh", StringComparison.OrdinalIgnoreCase) ||
               stem.Equals("rundll32", StringComparison.OrdinalIgnoreCase) ||
               stem.Equals("regsvr32", StringComparison.OrdinalIgnoreCase) ||
               stem.Equals("conhost", StringComparison.OrdinalIgnoreCase) ||
               stem.Equals("svchost", StringComparison.OrdinalIgnoreCase) ||
               stem.Equals("explorer", StringComparison.OrdinalIgnoreCase) ||
               stem.Equals("shell32", StringComparison.OrdinalIgnoreCase);
    }

    private static string TryGetFileNameWithoutExtensionSafe(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return string.Empty;
        try
        {
            return Path.GetFileNameWithoutExtension(path.Trim().Trim('"'));
        }
        catch
        {
            return string.Empty;
        }
    }

    /// <summary>
    /// 生成防护规则视图内容签名，仅当过滤条件、分组模式或规则清单发生变化时才重建 Expander 列表，避免审计日志写入触发无关刷新动画。
    /// </summary>
    public static string ComputeRulesRenderSignature(
        IReadOnlyList<RuleRecord> filteredRules,
        string groupMode,
        string searchTerm,
        IReadOnlyCollection<MonitorCategory> activeCategories)
    {
        var sb = new System.Text.StringBuilder(256);
        sb.Append(groupMode ?? string.Empty).Append('|');
        sb.Append(searchTerm?.Trim() ?? string.Empty).Append('|');
        if (activeCategories != null && activeCategories.Count > 0)
        {
            foreach (var cat in activeCategories.OrderBy(c => (int)c))
                sb.Append((int)cat).Append(',');
        }
        sb.Append('#');

        if (filteredRules != null)
        {
            foreach (var r in filteredRules.OrderBy(x => x.RuleId).ThenBy(x => x.LocationKey, StringComparer.OrdinalIgnoreCase))
            {
                sb.Append(r.RuleId).Append(':')
                  .Append((int)r.Category).Append(':')
                  .Append((int)r.ActionType).Append(':')
                  .Append((int)r.RuleMode).Append(':')
                  .Append(r.DisplayName).Append(':')
                  .Append(r.ProductName).Append(':')
                  .Append(r.LocationKey).Append(':')
                  .Append(r.TargetBinaryOrCommand).Append(':')
                  .Append(r.CurrentMD5).Append(';');
            }
        }

        return sb.ToString();
    }
}
