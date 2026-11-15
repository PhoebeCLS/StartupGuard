using StartupGuard.Core.ContextMenu;
using StartupGuard.Core.Models;
using StartupGuard.Core.Native;

namespace StartupGuard.Core.Rules;

/// <summary>
/// 全局搜索输入提取字段与导航路由结果（纯静态无 UI 依赖，便于单元测试与跨页复用）
/// </summary>
public readonly record struct GlobalSearchFields(
    MonitorCategory Category,
    string DisplayName,
    string Publisher,
    string ProductName,
    string CommandOrPath,
    string LocationKey,
    string ScopeScene,
    string Clsid,
    string SourceProcess,
    string StatusSummary);

public readonly record struct GlobalSearchNavigationTarget(
    string MainPageTag,
    string? ContextMenuSubTag);

/// <summary>
/// 顶部全局搜索过滤、类型/场景标签与跳转定位路由辅助器。
/// 全局搜索始终包含系统内置项与微软组件，不受“隐藏系统项”开关影响。
/// </summary>
public static class GlobalSearchHelper
{
    /// <summary>
    /// 与侧边栏及页内横向标签一致的分类顺序：
    /// 自启程序 -> 系统服务 -> 内核驱动 -> 计划任务 -> 系统策略 -> 经典右键 -> Win11 右键
    /// </summary>
    public static readonly MonitorCategory[] OrderedFilterCategories =
    [
        MonitorCategory.StartupItem,
        MonitorCategory.Win32Service,
        MonitorCategory.KernelDriver,
        MonitorCategory.ScheduledTask,
        MonitorCategory.WindowsPolicy,
        MonitorCategory.ClassicContextMenu,
        MonitorCategory.ModernContextMenu
    ];

    public static readonly MonitorCategory[] StartupFilterCategories =
    [
        MonitorCategory.StartupItem,
        MonitorCategory.Win32Service,
        MonitorCategory.KernelDriver,
        MonitorCategory.ScheduledTask,
        MonitorCategory.WindowsPolicy
    ];

    public static readonly MonitorCategory[] ContextMenuFilterCategories =
    [
        MonitorCategory.ClassicContextMenu,
        MonitorCategory.ModernContextMenu
    ];
    public static string GetTypeBadgeText(MonitorCategory category, string? locationKey, string? scopeScene)
    {
        return category switch
        {
            MonitorCategory.StartupItem => PrivilegedRollbackEngine.IsUwpStartupLocation(locationKey ?? string.Empty)
                ? "自启 · UWP 应用"
                : "自启 · 启动项",
            MonitorCategory.Win32Service => "自启 · 系统服务",
            MonitorCategory.KernelDriver => "自启 · 内核驱动",
            MonitorCategory.ScheduledTask => "自启 · 计划任务",
            MonitorCategory.WindowsPolicy => "自启 · 系统策略",
            MonitorCategory.ModernContextMenu => "右键 · Win11 现代菜单",
            MonitorCategory.ClassicContextMenu => $"右键 · {ContextMenuSceneHelper.DescribeScene(category, locationKey, scopeScene)}",
            _ => "系统项目"
        };
    }

    public static GlobalSearchNavigationTarget ResolveNavigationTarget(
        MonitorCategory category,
        string? locationKey,
        string? scopeScene)
    {
        if (category == MonitorCategory.ModernContextMenu)
            return new GlobalSearchNavigationTarget("PageContextMenu", "Win11Modern");

        if (category != MonitorCategory.ClassicContextMenu)
            return new GlobalSearchNavigationTarget("PageStartupManager", null);

        string loc = (locationKey ?? string.Empty).ToLowerInvariant();
        string scope = (scopeScene ?? string.Empty).ToLowerInvariant();

        if (string.Equals(scope, "scene_guidblocked", StringComparison.OrdinalIgnoreCase) ||
            (loc.Contains(@"\shell extensions\blocked", StringComparison.OrdinalIgnoreCase) && !loc.Contains(@"\classes\")))
            return new GlobalSearchNavigationTarget("PageContextMenu", "Scene_GuidBlocked");

        if (loc.Contains("dragdrophandlers") || scope.Contains("dragdrop"))
            return new GlobalSearchNavigationTarget("PageContextMenu", "Scene_DragDrop");
        if (loc.Contains("desktopbackground") || scope.Contains("desktop"))
            return new GlobalSearchNavigationTarget("PageContextMenu", "Scene_DesktopBackground");
        if (loc.Contains(@"directory\background") || scope.Contains("dirbackground"))
            return new GlobalSearchNavigationTarget("PageContextMenu", "Scene_DirBackground");
        if (loc.Contains(@"classes\directory\"))
            return new GlobalSearchNavigationTarget("PageContextMenu", "Scene_Directory");
        if (loc.Contains(@"classes\folder\"))
            return new GlobalSearchNavigationTarget("PageContextMenu", "Scene_Folder");
        if (loc.Contains("allfilesystemobjects") || scope.Contains("allobjects"))
            return new GlobalSearchNavigationTarget("PageContextMenu", "Scene_AllObjects");
        if (loc.Contains(@"classes\*") || scope.StartsWith("allfiles"))
            return new GlobalSearchNavigationTarget("PageContextMenu", "Scene_File");
        if (loc.Contains(@"classes\drive\"))
            return new GlobalSearchNavigationTarget("PageContextMenu", "Scene_Drive");
        if (loc.Contains("libraryfolder") || loc.Contains("userlibraryfolder") || scope.Contains("library"))
            return new GlobalSearchNavigationTarget("PageContextMenu", "Scene_Library");
        if (loc.Contains("20d04fe0") || scope.Contains("thispc"))
            return new GlobalSearchNavigationTarget("PageContextMenu", "Scene_Computer");
        if (loc.Contains("645ff040") || scope.Contains("recyclebin"))
            return new GlobalSearchNavigationTarget("PageContextMenu", "Scene_RecycleBin");
        if (loc.Contains("sendto") || scope.Contains("sendto"))
            return new GlobalSearchNavigationTarget("PageContextMenu", "Scene_SendTo");
        if (loc.Contains(@"\winx\") || scope.Contains("winx"))
            return new GlobalSearchNavigationTarget("PageContextMenu", "Scene_WinX");
        if (loc.Contains("openwith") || scope.Contains("openwith"))
            return new GlobalSearchNavigationTarget("PageContextMenu", "Scene_OpenWith");
        if (loc.Contains("commandstore") || scope.Equals("commandstore"))
            return new GlobalSearchNavigationTarget("PageContextMenu", "Scene_CommandStore");
        if (loc.Contains(@"\lnkfile\") || loc.Contains("launcher.immersiveapplication") || loc.Contains(@"\exefile\") || loc.Contains(@"classes\unknown\"))
            return new GlobalSearchNavigationTarget("PageContextMenu", "FileTypes");

        return new GlobalSearchNavigationTarget("PageContextMenu", "ByApp");
    }

    public static List<T> SearchItems<T>(
        IEnumerable<T> startupItems,
        IEnumerable<T> contextMenuItems,
        IEnumerable<T>? guidBlockedItems,
        string? query,
        Func<T, GlobalSearchFields> selector,
        int maxResults = 60,
        IReadOnlySet<MonitorCategory>? allowedCategories = null,
        bool allowEmptyQueryWhenFiltered = false)
    {
        if (allowedCategories is { Count: 0 })
            return [];

        bool hasQuery = !string.IsNullOrWhiteSpace(query);
        if (!hasQuery && !allowEmptyQueryWhenFiltered)
            return [];

        string[] tokens = hasQuery
            ? query!.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            : [];

        var results = new List<T>();
        var seenKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void CollectFrom(IEnumerable<T>? source)
        {
            if (source == null) return;
            foreach (var item in source)
            {
                var fields = selector(item);
                if (allowedCategories != null && !allowedCategories.Contains(fields.Category))
                    continue;

                string typeBadge = GetTypeBadgeText(fields.Category, fields.LocationKey, fields.ScopeScene);

                string dedupKey = $"{(int)fields.Category}|{fields.ScopeScene}|{fields.LocationKey}|{fields.Clsid}|{fields.DisplayName}";
                if (!seenKeys.Add(dedupKey))
                    continue;

                bool allMatched = true;
                foreach (string token in tokens)
                {
                    if (!ContainsIgnoreCase(fields.DisplayName, token) &&
                        !ContainsIgnoreCase(fields.Publisher, token) &&
                        !ContainsIgnoreCase(fields.ProductName, token) &&
                        !ContainsIgnoreCase(fields.CommandOrPath, token) &&
                        !ContainsIgnoreCase(fields.LocationKey, token) &&
                        !ContainsIgnoreCase(fields.Clsid, token) &&
                        !ContainsIgnoreCase(fields.SourceProcess, token) &&
                        !ContainsIgnoreCase(fields.StatusSummary, token) &&
                        !ContainsIgnoreCase(typeBadge, token))
                    {
                        allMatched = false;
                        break;
                    }
                }

                if (allMatched)
                {
                    results.Add(item);
                    if (results.Count >= maxResults)
                        return;
                }
            }
        }

        CollectFrom(startupItems);
        if (results.Count < maxResults)
            CollectFrom(contextMenuItems);
        if (results.Count < maxResults)
            CollectFrom(guidBlockedItems);

        return results;
    }

    private static bool ContainsIgnoreCase(string? text, string token)
        => !string.IsNullOrEmpty(text) && text.Contains(token, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// 生成常见分页器页码槽位（1-based 页码；null 表示 "..." 省略号）
    /// </summary>
    public static IReadOnlyList<int?> BuildPaginationSlots(int currentPage, int totalPages, int windowRadius = 2)
    {
        if (totalPages <= 1)
            return [];

        int page = Math.Clamp(currentPage, 1, totalPages);
        int radius = Math.Max(1, windowRadius);
        var slots = new List<int?>();

        int winStart = Math.Max(2, page - radius);
        int winEnd = Math.Min(totalPages - 1, page + radius);

        slots.Add(1);
        if (winStart > 2)
            slots.Add(null);

        for (int p = winStart; p <= winEnd; p++)
            slots.Add(p);

        if (winEnd < totalPages - 1)
            slots.Add(null);

        if (totalPages > 1)
            slots.Add(totalPages);

        return slots;
    }

    /// <summary>
    /// 规范化位置标识符以用于日志与实时系统项的跨表示法精准比对
    /// （如统一 Task: 前缀空格、Services 短名及 HKU/&lt;SID&gt; 与 HKCU 前缀）
    /// </summary>
    public static string NormalizeLocationForLookup(MonitorCategory category, string? locationKey)
    {
        if (string.IsNullOrWhiteSpace(locationKey))
            return string.Empty;

        string loc = ShellNavigationHelper.NormalizeFullRegistryPath(locationKey.Trim());
        if (loc.StartsWith("Task:", StringComparison.OrdinalIgnoreCase))
        {
            string rel = loc[5..].Trim();
            if (!rel.StartsWith('\\'))
                rel = "\\" + rel;
            return "TASK:" + rel.ToUpperInvariant();
        }

        if (category is MonitorCategory.Win32Service or MonitorCategory.KernelDriver)
        {
            if (loc.StartsWith(@"SERVICES\", StringComparison.OrdinalIgnoreCase))
                return @"HKEY_LOCAL_MACHINE\SYSTEM\CURRENTCONTROLSET\" + loc.ToUpperInvariant();
            if (!loc.Contains('\\') && !loc.Contains('/'))
                return @"HKEY_LOCAL_MACHINE\SYSTEM\CURRENTCONTROLSET\SERVICES\" + loc.ToUpperInvariant();
        }

        if (loc.StartsWith(@"HKEY_USERS\", StringComparison.OrdinalIgnoreCase))
        {
            int secondSlash = loc.IndexOf('\\', @"HKEY_USERS\".Length);
            if (secondSlash > 0)
            {
                string sid = loc[@"HKEY_USERS\".Length..secondSlash];
                if (sid.StartsWith("S-1-5-", StringComparison.OrdinalIgnoreCase))
                {
                    return ("HKEY_CURRENT_USER" + loc[secondSlash..]).ToUpperInvariant();
                }
            }
        }

        return loc.ToUpperInvariant();
    }

    /// <summary>
    /// 根据拦截日志记录在当前活动系统项集合中查找最匹配的对应管理项
    /// </summary>
    public static T? FindBestMatchingItemForLog<T>(
        MonitorCategory logCategory,
        string? logLocationKey,
        string? logTargetProgram,
        IEnumerable<T> candidates,
        Func<T, GlobalSearchFields> selector) where T : class
    {
        string normLogLoc = NormalizeLocationForLookup(logCategory, logLocationKey);
        string logLeaf = PrivilegedRollbackEngine.ExtractLeafKeyName(logLocationKey ?? string.Empty);
        string normLogBin = ShellNavigationHelper.ResolvePhysicalFilePath(logTargetProgram);

        T? bestMatch = null;
        int bestScore = 0;

        foreach (var item in candidates)
        {
            var fields = selector(item);
            bool sameCategory = fields.Category == logCategory;
            string normItemLoc = NormalizeLocationForLookup(fields.Category, fields.LocationKey);

            int score = 0;
            if (!string.IsNullOrEmpty(normLogLoc) &&
                string.Equals(normLogLoc, normItemLoc, StringComparison.OrdinalIgnoreCase))
            {
                score = sameCategory ? 1000 : 300;
            }
            else if (sameCategory)
            {
                string itemLeaf = PrivilegedRollbackEngine.ExtractLeafKeyName(fields.LocationKey);
                string normItemBin = ShellNavigationHelper.ResolvePhysicalFilePath(fields.CommandOrPath);
                bool leafMatches = !string.IsNullOrEmpty(logLeaf) &&
                                   string.Equals(logLeaf, itemLeaf, StringComparison.OrdinalIgnoreCase);
                bool binMatches = !string.IsNullOrEmpty(normLogBin) &&
                                  !string.IsNullOrEmpty(normItemBin) &&
                                  string.Equals(normLogBin, normItemBin, StringComparison.OrdinalIgnoreCase);

                if (leafMatches && binMatches)
                    score = 800;
                else if (leafMatches)
                    score = 550;
                else if (binMatches)
                    score = 450;
            }

            if (score > bestScore)
            {
                bestScore = score;
                bestMatch = item;
            }
        }

        return bestScore >= 450 ? bestMatch : null;
    }
}
