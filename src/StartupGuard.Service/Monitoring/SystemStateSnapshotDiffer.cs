using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using StartupGuard.Core.ContextMenu;
using StartupGuard.Core.Models;
using StartupGuard.Core.Native;
using StartupGuard.Core.Scoring;
using StartupGuard.Core.Storage;

namespace StartupGuard.Service.Monitoring;

/// <summary>
/// 6 大监控分类的系统状态快照与增量 Diff 引擎
/// 覆盖：
/// 1. 启动项 (Run/RunOnce/StartupApproved/ActiveSetup/Startup 文件夹)
/// 2. Win32 服务 (Services Type 0x10/0x20, Start, ImagePath, ServiceDll)
/// 3. 内核驱动 (Services Type 0x1/0x2/0x8, Start, Filters)
/// 4. 任务计划程序 (System32\Tasks, TaskCache)
/// 5. 上下文菜单 (经典 shell/shellex 与 Win11 PackagedCom)
/// 6. Windows 策略与劫持点 (IFEO, Winlogon, Policies\Explorer\Run, AppInit_DLLs)
/// </summary>
public sealed unsafe partial class SystemStateSnapshotDiffer
{
    private const string AdvApi32Dll = "advapi32.dll";
    private const uint KEY_READ = 0x20019;
    private const uint KEY_WOW64_64KEY = 0x0100;

    [LibraryImport(AdvApi32Dll, EntryPoint = "RegOpenKeyExW", StringMarshalling = StringMarshalling.Utf16)]
    private static partial int RegOpenKeyExW(nint hKey, string lpSubKey, uint ulOptions, uint samDesired, out nint phkResult);

    [LibraryImport(AdvApi32Dll, EntryPoint = "RegQueryValueExW", StringMarshalling = StringMarshalling.Utf16)]
    private static partial int RegQueryValueExW(nint hKey, string? lpValueName, nint lpReserved, out uint lpType, byte* lpData, ref uint lpcbData);

    [LibraryImport(AdvApi32Dll, EntryPoint = "RegEnumValueW", StringMarshalling = StringMarshalling.Utf16)]
    private static partial int RegEnumValueW(nint hKey, uint dwIndex, char* lpValueName, ref uint lpcchValueName, nint lpReserved, out uint lpType, byte* lpData, ref uint lpcbData);

    [LibraryImport(AdvApi32Dll, EntryPoint = "RegEnumKeyExW", StringMarshalling = StringMarshalling.Utf16)]
    private static partial int RegEnumKeyExW(nint hKey, uint dwIndex, char* lpName, ref uint lpcchName, nint lpReserved, nint lpClass, nint lpcchClass, out long lpftLastWriteTime);

    [LibraryImport(AdvApi32Dll, EntryPoint = "RegQueryInfoKeyW")]
    private static partial int RegQueryInfoKeyW(
        nint hKey,
        nint lpClass,
        nint lpcchClass,
        nint lpReserved,
        nint lpcSubKeys,
        nint lpcbMaxSubKeyLen,
        nint lpcbMaxClassLen,
        nint lpcValues,
        nint lpcbMaxValueNameLen,
        nint lpcbMaxValueLen,
        nint lpcbSecurityDescriptor,
        out long lpftLastWriteTime);

    [LibraryImport(AdvApi32Dll)]
    private static partial int RegCloseKey(nint hKey);

    public sealed record SnapshotItem(
        MonitorCategory Category,
        string LocationKey,
        string CommandOrBinaryPath,
        string RawState,
        uint RegistryValueType = 1,
        byte[]? RawBytes = null,
        string DisplayName = "");

    private readonly ConcurrentDictionary<string, SnapshotItem> _cachedSnapshot = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, (DateTime Expiry, bool? ExpectedEnabled)> _suppressedRollbackMutations = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, bool> _hydratedUserSids = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, bool> _hydratedUserClassesSids = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, DateTime> _userHydratedUtc = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, KnownBaselineRecord> _persistedBaselines = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, (SnapshotItem Item, DateTime RemovedUtc)> _recentlyRemovedItems = new(StringComparer.OrdinalIgnoreCase);
    private static readonly ConcurrentDictionary<string, (DateTime Expiry, TargetProgramFeatures? Probed)> _probedDllCache = new(StringComparer.OrdinalIgnoreCase);
    private static readonly ConcurrentDictionary<string, (long LastWriteFt, SnapshotItem Item)> _serviceScanCache = new(StringComparer.OrdinalIgnoreCase);
    private static readonly ConcurrentDictionary<string, (long LastWriteFt, SnapshotItem? Item)> _ifeoScanCache = new(StringComparer.OrdinalIgnoreCase);
    private static readonly ConcurrentDictionary<string, (long LastWriteUtcTicks, long FileLength, SnapshotItem Item)> _taskFileCache = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _diffSyncLock = new();

    internal DateTime BaselineEstablishedUtc { get; set; } = DateTime.UtcNow;

    public IReadOnlyDictionary<string, SnapshotItem> CurrentSnapshot => _cachedSnapshot;

    public bool IsUserFullyHydrated(string? userSid)
    {
        if (string.IsNullOrWhiteSpace(userSid))
            return true;

        if (!_hydratedUserSids.ContainsKey(userSid))
            return false;

        return !IsUserClassesHiveMounted(userSid) || _hydratedUserClassesSids.ContainsKey(userSid);
    }

    public void LoadPersistedBaselines(IEnumerable<KnownBaselineRecord> records)
    {
        if (records == null)
            return;

        foreach (var rec in records)
        {
            if (string.IsNullOrWhiteSpace(rec.LocationKey))
                continue;
            _persistedBaselines[rec.LocationKey] = rec;
        }
    }

    public List<KnownBaselineRecord> ExportCurrentSnapshotAsBaselines(IEnumerable<SnapshotItem>? subset = null)
    {
        var nowUtc = DateTime.UtcNow;
        SnapshotItem[] items = subset != null
            ? subset.ToArray()
            : _cachedSnapshot.Values.ToArray();

        var result = new List<KnownBaselineRecord>(items.Length);
        foreach (var item in items)
        {
            bool resolveDiskStamp = item.Category is MonitorCategory.StartupItem
                or MonitorCategory.ScheduledTask
                or MonitorCategory.ClassicContextMenu
                or MonitorCategory.ModernContextMenu
                or MonitorCategory.WindowsPolicy;

            long ticks = 0;
            long len = 0;
            if (resolveDiskStamp && !string.IsNullOrWhiteSpace(item.CommandOrBinaryPath))
            {
                (_, ticks, len) = ResolvePhysicalFileStamp(item.CommandOrBinaryPath);
            }
            else if (_persistedBaselines.TryGetValue(item.LocationKey, out var existingRec) &&
                     existingRec.FileLastWriteUtcTicks > 0)
            {
                ticks = existingRec.FileLastWriteUtcTicks;
                len = existingRec.FileLength;
            }

            string normPath = !string.IsNullOrWhiteSpace(item.CommandOrBinaryPath)
                ? PathNormalizerAndSimilarity.NormalizeProgramPath(item.CommandOrBinaryPath)
                : string.Empty;

            DateTime firstSeen = _persistedBaselines.TryGetValue(item.LocationKey, out var prev)
                ? prev.FirstSeenUtc
                : nowUtc;

            var record = new KnownBaselineRecord
            {
                LocationKey = item.LocationKey,
                Category = item.Category,
                TargetBinaryPath = item.CommandOrBinaryPath ?? string.Empty,
                NormalizedPath = normPath,
                RawState = item.RawState ?? string.Empty,
                FileLastWriteUtcTicks = ticks,
                FileLength = len,
                FirstSeenUtc = firstSeen,
                LastSeenUtc = nowUtc
            };
            _persistedBaselines[item.LocationKey] = record;
            result.Add(record);
        }

        return result;
    }

    public KnownBaselineRecord? BuildAndTrackPersistedBaseline(TargetProgramFeatures target, string rawState)
    {
        if (target == null || string.IsNullOrWhiteSpace(target.LocationKeyOrIdentifier))
            return null;

        var nowUtc = DateTime.UtcNow;
        (_, long ticks, long len) = ResolvePhysicalFileStamp(
            !string.IsNullOrWhiteSpace(target.TargetBinaryPath) ? target.TargetBinaryPath : target.RawCommandLine);
        string normPath = !string.IsNullOrWhiteSpace(target.NormalizedPath)
            ? target.NormalizedPath
            : PathNormalizerAndSimilarity.NormalizeProgramPath(target.TargetBinaryPath);

        DateTime firstSeen = TryGetPersistedBaselineRecord(target.LocationKeyOrIdentifier, out var prev)
            ? prev.FirstSeenUtc
            : nowUtc;

        var rec = new KnownBaselineRecord
        {
            LocationKey = target.LocationKeyOrIdentifier,
            Category = target.Category,
            TargetBinaryPath = !string.IsNullOrWhiteSpace(target.TargetBinaryPath) ? target.TargetBinaryPath : target.RawCommandLine,
            NormalizedPath = normPath,
            RawState = rawState ?? string.Empty,
            FileLastWriteUtcTicks = ticks,
            FileLength = len,
            FirstSeenUtc = firstSeen,
            LastSeenUtc = nowUtc
        };
        _persistedBaselines[rec.LocationKey] = rec;
        return rec;
    }

    public void RemovePersistedBaseline(string locationKey)
    {
        if (string.IsNullOrWhiteSpace(locationKey))
            return;

        foreach (string variant in BuildSuppressionKeyVariants(locationKey, activeUserSid: null))
        {
            _persistedBaselines.TryRemove(variant, out _);
        }
        _persistedBaselines.TryRemove(locationKey, out _);
    }

    public List<string> FindOrphanedPersistedBaselineKeys()
    {
        var orphaned = new List<string>();
        foreach (var kv in _persistedBaselines)
        {
            var rec = kv.Value;
            if (rec.FileLastWriteUtcTicks <= 0 || rec.FileLength <= 0 || string.IsNullOrWhiteSpace(rec.TargetBinaryPath))
                continue;

            string phys = ShellNavigationHelper.ResolvePhysicalFilePath(rec.TargetBinaryPath);
            if (!string.IsNullOrWhiteSpace(phys) &&
                Path.IsPathRooted(phys) &&
                !phys.Contains(@"\System32\", StringComparison.OrdinalIgnoreCase) &&
                !phys.Contains(@"\SysWOW64\", StringComparison.OrdinalIgnoreCase) &&
                !File.Exists(phys))
            {
                orphaned.Add(kv.Key);
            }
        }
        return orphaned;
    }

    internal static (bool Exists, long LastWriteUtcTicks, long FileLength) ResolvePhysicalFileStamp(string? commandOrPath)
    {
        if (string.IsNullOrWhiteSpace(commandOrPath))
            return (false, 0, 0);

        try
        {
            string physical = ShellNavigationHelper.ResolvePhysicalFilePath(commandOrPath);
            if (string.IsNullOrWhiteSpace(physical) || !File.Exists(physical))
                return (false, 0, 0);

            var fi = new FileInfo(physical);
            return (true, fi.LastWriteTimeUtc.Ticks, fi.Length);
        }
        catch
        {
            return (false, 0, 0);
        }
    }

    private static bool IsGlobalClsidTargetKey(string locationKey)
    {
        if (string.IsNullOrWhiteSpace(locationKey))
            return false;

        return locationKey.Contains("Shell Extensions", StringComparison.OrdinalIgnoreCase)
            || locationKey.Contains("PackagedCom", StringComparison.OrdinalIgnoreCase)
            || locationKey.StartsWith("Win11Modern:", StringComparison.OrdinalIgnoreCase)
            || locationKey.StartsWith("Approved:", StringComparison.OrdinalIgnoreCase)
            || locationKey.StartsWith("Blocked:", StringComparison.OrdinalIgnoreCase);
    }

    private static bool? TryParseLiveEnabledState(SnapshotItem live)
    {
        if (string.IsNullOrEmpty(live.RawState))
            return null;

        if (live.RawState.Contains("Enabled=False", StringComparison.OrdinalIgnoreCase))
            return false;

        if (live.RawState.Contains("Enabled=True", StringComparison.OrdinalIgnoreCase))
            return true;

        return null;
    }

    /// <summary>
    /// 对指定位置键登记特权回滚或本程序自操作免检抑制期 (默认30秒)，避免自身操作或回滚引发二次误判弹窗。
    /// 不再按二进制路径 (BIN|) 跨场景泛化抑制，且经典 ShellEx 不跨场景传播 CLSID| 抑制；
    /// 若指定 expectedEnabledState，则仅在实时状态匹配预期方向时抑制，避免安装器回滚后立即复写被静默放过。
    /// </summary>
    public void SuppressLocationKeyMutation(
        string locationKey,
        double durationSeconds = 30.0,
        string? activeUserSid = null,
        string? targetBinaryPath = null,
        bool? expectedEnabledState = null)
    {
        if (string.IsNullOrWhiteSpace(locationKey))
            return;

        _ = targetBinaryPath; // 禁止跨位置使用 BIN| 泛化抑制，防止多场景共用同一 DLL（如 */Directory/Folder）被连带漏报
        var expiry = DateTime.UtcNow.AddSeconds(Math.Max(1.0, durationSeconds));
        var entry = (Expiry: expiry, ExpectedEnabled: expectedEnabledState);
        foreach (var variant in BuildSuppressionKeyVariants(locationKey, activeUserSid))
        {
            _suppressedRollbackMutations[variant] = entry;
        }

        // 仅当回滚或操作直接作用于全局 Shell Extensions Approved/Blocked / PackagedCom / Win11Modern 时，
        // 才按 CLSID| 联动抑制；经典 ContextMenuHandlers / shell 各自独立，禁止按 CLSID| 跨场景误抑制。
        if (IsGlobalClsidTargetKey(locationKey))
        {
            string directClsid = PrivilegedRollbackEngine.ExtractClsidOrIdentifier(locationKey);
            if (directClsid.StartsWith('{') && directClsid.EndsWith('}'))
            {
                foreach (var cv in BuildSuppressionKeyVariants($"Approved:{directClsid}", activeUserSid))
                {
                    _suppressedRollbackMutations[cv] = entry;
                }
                _suppressedRollbackMutations["CLSID|" + directClsid] = entry;
            }
        }
    }

    internal static IEnumerable<string> BuildSuppressionKeyVariants(string rawKey, string? activeUserSid)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        void AddWithHiveAliases(string key)
        {
            if (string.IsNullOrWhiteSpace(key)) return;
            string k = key.Trim();
            set.Add(k);

            if (k.StartsWith("HKEY_LOCAL_MACHINE\\", StringComparison.OrdinalIgnoreCase))
                set.Add("HKLM\\" + k["HKEY_LOCAL_MACHINE\\".Length..]);
            else if (k.StartsWith("HKLM\\", StringComparison.OrdinalIgnoreCase))
                set.Add("HKEY_LOCAL_MACHINE\\" + k["HKLM\\".Length..]);

            if (k.StartsWith("HKEY_CURRENT_USER\\", StringComparison.OrdinalIgnoreCase))
                k = "HKCU\\" + k["HKEY_CURRENT_USER\\".Length..];
            set.Add(k);

            if (!string.IsNullOrWhiteSpace(activeUserSid))
            {
                if (k.StartsWith("HKCU\\", StringComparison.OrdinalIgnoreCase))
                {
                    string tail = k["HKCU\\".Length..];
                    set.Add($"HKU\\{activeUserSid}\\{tail}");
                    set.Add($"HKEY_USERS\\{activeUserSid}\\{tail}");
                }
                else
                {
                    string uPrefix = $"HKU\\{activeUserSid}\\";
                    string huPrefix = $"HKEY_USERS\\{activeUserSid}\\";
                    if (k.StartsWith(uPrefix, StringComparison.OrdinalIgnoreCase))
                    {
                        set.Add("HKCU\\" + k[uPrefix.Length..]);
                        set.Add("HKEY_CURRENT_USER\\" + k[uPrefix.Length..]);
                    }
                    else if (k.StartsWith(huPrefix, StringComparison.OrdinalIgnoreCase))
                    {
                        set.Add("HKCU\\" + k[huPrefix.Length..]);
                        set.Add("HKEY_CURRENT_USER\\" + k[huPrefix.Length..]);
                    }
                }
            }
        }

        string trimmed = rawKey.Trim();
        AddWithHiveAliases(trimmed);
        if (trimmed.EndsWith("::State", StringComparison.OrdinalIgnoreCase))
        {
            AddWithHiveAliases(trimmed[..^7]);
        }
        else if (trimmed.Contains(@"\AppModel\SystemAppData\", StringComparison.OrdinalIgnoreCase))
        {
            AddWithHiveAliases(trimmed.TrimEnd('\\') + "::State");
        }

        // 右键菜单启用/禁止切换时，注册表子项名称会在 Name 与 -Name 之间变化；
        // 且 Classic ShellEx 启用/禁用会在 \shellex\ContextMenuHandlers\ 与 \shellex\-ContextMenuHandlers\ 之间移动
        if (trimmed.Contains(@"\shellex\ContextMenuHandlers\", StringComparison.OrdinalIgnoreCase))
        {
            AddWithHiveAliases(trimmed.Replace(@"\shellex\ContextMenuHandlers\", @"\shellex\-ContextMenuHandlers\", StringComparison.OrdinalIgnoreCase));
        }
        else if (trimmed.Contains(@"\shellex\-ContextMenuHandlers\", StringComparison.OrdinalIgnoreCase))
        {
            AddWithHiveAliases(trimmed.Replace(@"\shellex\-ContextMenuHandlers\", @"\shellex\ContextMenuHandlers\", StringComparison.OrdinalIgnoreCase));
        }

        int lastSlash = trimmed.LastIndexOf('\\');
        if (lastSlash >= 0 && lastSlash < trimmed.Length - 1)
        {
            string parent = trimmed[..(lastSlash + 1)];
            string leaf = trimmed[(lastSlash + 1)..];
            string toggledLeaf = leaf.StartsWith('-') ? leaf[1..] : "-" + leaf;
            AddWithHiveAliases(parent + toggledLeaf);

            // 系统服务键别名：HKLM\SYSTEM\CurrentControlSet\Services\<Name>
            if (trimmed.Contains("\\Services\\", StringComparison.OrdinalIgnoreCase))
            {
                AddWithHiveAliases($"Services\\{leaf}");
                AddWithHiveAliases($"HKLM\\SYSTEM\\CurrentControlSet\\Services\\{leaf}");
            }
        }

        // 计划任务前缀变体：Task:\Folder\Name / Task: \Folder\Name / C:\Windows\System32\Tasks\Folder\Name
        string taskClean = trimmed;
        if (taskClean.StartsWith("Task:", StringComparison.OrdinalIgnoreCase))
            taskClean = taskClean[5..].Trim();
        if (trimmed.StartsWith("Task:", StringComparison.OrdinalIgnoreCase) || trimmed.StartsWith("\\"))
        {
            string normalizedTask = taskClean.StartsWith('\\') ? taskClean : "\\" + taskClean;
            set.Add("Task:" + normalizedTask);
            set.Add("Task: " + normalizedTask);
            set.Add(normalizedTask);
            set.Add(@"C:\Windows\System32\Tasks" + normalizedTask);
        }
        else if (trimmed.StartsWith(@"C:\Windows\System32\Tasks\", StringComparison.OrdinalIgnoreCase))
        {
            string normalizedTask = trimmed[@"C:\Windows\System32\Tasks".Length..];
            set.Add("Task:" + normalizedTask);
            set.Add("Task: " + normalizedTask);
            set.Add(normalizedTask);
        }

        // Shell Extension CLSID Approved/Blocked/PackagedCom 变体
        int braceStart = trimmed.IndexOf('{');
        int braceEnd = trimmed.IndexOf('}');
        if (braceStart >= 0 && braceEnd > braceStart &&
            (trimmed.Contains("Shell Extensions", StringComparison.OrdinalIgnoreCase) ||
             trimmed.Contains("PackagedCom", StringComparison.OrdinalIgnoreCase) ||
             trimmed.StartsWith("Win11Modern:", StringComparison.OrdinalIgnoreCase) ||
             trimmed.StartsWith("Approved:", StringComparison.OrdinalIgnoreCase) ||
             trimmed.StartsWith("Blocked:", StringComparison.OrdinalIgnoreCase)))
        {
            string clsid = trimmed[braceStart..(braceEnd + 1)];
            set.Add($"Approved:{clsid}");
            set.Add($"Blocked:{clsid}");
            set.Add($"CLSID|{clsid}");
            AddWithHiveAliases($@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved\{clsid}");
            AddWithHiveAliases($@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved::{clsid}");
            AddWithHiveAliases($@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked\{clsid}");
            AddWithHiveAliases($@"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked\{clsid}");
        }

        return set;
    }

    internal bool IsLiveItemSuppressed(SnapshotItem live)
    {
        var now = DateTime.UtcNow;
        bool? liveEnabled = TryParseLiveEnabledState(live);

        foreach (var candidate in BuildSuppressionKeyVariants(live.LocationKey, activeUserSid: null))
        {
            if (TryCheckSuppressionEntry(candidate, liveEnabled, now))
                return true;
        }

        // 如果 _suppressedRollbackMutations 使用默认大小写比较器，兜底做一次忽略大小写比对
        foreach (var kv in _suppressedRollbackMutations)
        {
            if (now >= kv.Value.Expiry)
            {
                _suppressedRollbackMutations.TryRemove(kv.Key, out _);
                continue;
            }
            if (!kv.Key.StartsWith("BIN|", StringComparison.Ordinal) &&
                !kv.Key.StartsWith("CLSID|", StringComparison.Ordinal) &&
                string.Equals(kv.Key, live.LocationKey, StringComparison.OrdinalIgnoreCase) &&
                IsExpectedDirectionMatch(kv.Value.ExpectedEnabled, liveEnabled))
            {
                return true;
            }
        }

        // 仅当实时条目本身为全局 CLSID 键（ModernContextMenu / Shell Extensions Approved/Blocked / PackagedCom）时，
        // 才按 CLSID| 抑制；经典 ShellEx (\shellex\ContextMenuHandlers) 或 \shell\ 不参与跨场景 CLSID 抑制。
        bool isGlobalClsidLive = live.Category == MonitorCategory.ModernContextMenu || IsGlobalClsidTargetKey(live.LocationKey);
        if (isGlobalClsidLive)
        {
            int braceStart = live.LocationKey.IndexOf('{');
            int braceEnd = live.LocationKey.IndexOf('}');
            if (braceStart >= 0 && braceEnd > braceStart)
            {
                string clsid = live.LocationKey[braceStart..(braceEnd + 1)];
                if (TryCheckSuppressionEntry("CLSID|" + clsid, liveEnabled, now))
                    return true;
            }
            else if (!string.IsNullOrEmpty(live.RawState) && live.RawState.Contains("Clsid={", StringComparison.OrdinalIgnoreCase))
            {
                int cs = live.RawState.IndexOf("Clsid={", StringComparison.OrdinalIgnoreCase) + 6;
                int ce = live.RawState.IndexOf('}', cs);
                if (ce > cs)
                {
                    string clsid = live.RawState[cs..(ce + 1)];
                    if (TryCheckSuppressionEntry("CLSID|" + clsid, liveEnabled, now))
                        return true;
                }
            }
        }

        return false;
    }

    private static bool IsExpectedDirectionMatch(bool? expectedEnabled, bool? liveEnabled)
    {
        if (expectedEnabled.HasValue && liveEnabled.HasValue)
            return expectedEnabled.Value == liveEnabled.Value;
        return true;
    }

    private void SyncSuppressedSnapshotAliases(SnapshotItem live)
    {
        _cachedSnapshot[live.LocationKey] = live;
        foreach (var alias in BuildSuppressionKeyVariants(live.LocationKey, activeUserSid: null))
        {
            if (!string.Equals(alias, live.LocationKey, StringComparison.OrdinalIgnoreCase))
            {
                _cachedSnapshot.TryRemove(alias, out _);
            }
        }
    }

    private bool TryCheckSuppressionEntry(string key, bool? liveEnabled, DateTime now)
    {
        if (!_suppressedRollbackMutations.TryGetValue(key, out var entry))
            return false;
        if (now < entry.Expiry)
            return IsExpectedDirectionMatch(entry.ExpectedEnabled, liveEnabled);
        _suppressedRollbackMutations.TryRemove(key, out _);
        return false;
    }

    /// <summary>
    /// 更新内存快照中指定条目的状态，使其与实际回滚/恢复结果保持同步（保留现有 Scene/Clsid 等元数据令牌）
    /// </summary>
    public void UpdateSnapshotItemState(string locationKey, string newRawState)
    {
        if (string.IsNullOrWhiteSpace(locationKey))
            return;

        if (_cachedSnapshot.TryGetValue(locationKey, out var existing))
        {
            string merged = MergeRawStatePreservingMetadata(existing.RawState, newRawState);
            _cachedSnapshot[locationKey] = new SnapshotItem(existing.Category, existing.LocationKey, existing.CommandOrBinaryPath, merged, existing.RegistryValueType, existing.RawBytes, existing.DisplayName);
        }
    }

    public void UpdateContextMenuEnabledInSnapshot(string locationKey, bool enabled)
    {
        if (string.IsNullOrWhiteSpace(locationKey))
            return;

        if (_cachedSnapshot.TryGetValue(locationKey, out var existing))
        {
            string updated = ReplaceEnabledToken(existing.RawState, enabled);
            _cachedSnapshot[locationKey] = new SnapshotItem(existing.Category, existing.LocationKey, existing.CommandOrBinaryPath, updated, existing.RegistryValueType, existing.RawBytes, existing.DisplayName);
        }

        string directClsid = PrivilegedRollbackEngine.ExtractClsidOrIdentifier(locationKey);
        if (directClsid.StartsWith('{') && directClsid.EndsWith('}') && IsGlobalClsidTargetKey(locationKey))
        {
            foreach (var kv in _cachedSnapshot.ToArray())
            {
                if (kv.Value.Category == MonitorCategory.ModernContextMenu &&
                    kv.Key.Contains(directClsid, StringComparison.OrdinalIgnoreCase))
                {
                    string updated = ReplaceEnabledToken(kv.Value.RawState, enabled);
                    _cachedSnapshot[kv.Key] = new SnapshotItem(kv.Value.Category, kv.Value.LocationKey, kv.Value.CommandOrBinaryPath, updated, kv.Value.RegistryValueType, kv.Value.RawBytes, kv.Value.DisplayName);
                }
            }
        }
    }

    private static string MergeRawStatePreservingMetadata(string oldRawState, string newRawState)
    {
        if (string.Equals(newRawState, "Enabled=True", StringComparison.OrdinalIgnoreCase))
            return ReplaceEnabledToken(oldRawState, true);
        if (string.Equals(newRawState, "Enabled=False", StringComparison.OrdinalIgnoreCase))
            return ReplaceEnabledToken(oldRawState, false);
        return newRawState;
    }

    /// <summary>
    /// 同步经典 ShellEx 移动式禁用/启用后的内存快照键位置，避免已移动键残留导致并发扫描误判状态跳变
    /// </summary>
    public void SyncMovedContextMenuSnapshot(string locationKey, bool disabled)
    {
        if (string.IsNullOrWhiteSpace(locationKey))
            return;

        lock (_diffSyncLock)
        {
            string? targetKey = null;
            if (locationKey.Contains(@"\ContextMenuHandlers\", StringComparison.OrdinalIgnoreCase) && disabled)
                targetKey = locationKey.Replace(@"\ContextMenuHandlers\", @"\-ContextMenuHandlers\", StringComparison.OrdinalIgnoreCase);
            else if (locationKey.Contains(@"\-ContextMenuHandlers\", StringComparison.OrdinalIgnoreCase) && !disabled)
                targetKey = locationKey.Replace(@"\-ContextMenuHandlers\", @"\ContextMenuHandlers\", StringComparison.OrdinalIgnoreCase);
            else if (locationKey.Contains(@"\DragDropHandlers\", StringComparison.OrdinalIgnoreCase) && disabled)
                targetKey = locationKey.Replace(@"\DragDropHandlers\", @"\-DragDropHandlers\", StringComparison.OrdinalIgnoreCase);
            else if (locationKey.Contains(@"\-DragDropHandlers\", StringComparison.OrdinalIgnoreCase) && !disabled)
                targetKey = locationKey.Replace(@"\-DragDropHandlers\", @"\DragDropHandlers\", StringComparison.OrdinalIgnoreCase);

            if (string.IsNullOrEmpty(targetKey))
                return;

            if (_cachedSnapshot.TryRemove(locationKey, out var oldItem))
            {
                string updatedRaw = ReplaceEnabledToken(oldItem.RawState, !disabled);
                _cachedSnapshot[targetKey] = new SnapshotItem(
                    oldItem.Category,
                    targetKey,
                    oldItem.CommandOrBinaryPath,
                    updatedRaw,
                    oldItem.RegistryValueType,
                    oldItem.RawBytes,
                    oldItem.DisplayName);
            }
        }
    }

    private static string ReplaceEnabledToken(string rawState, bool enabled)
    {
        if (string.IsNullOrWhiteSpace(rawState))
            return $"Enabled={enabled}";
        if (rawState.Contains("Enabled=True", StringComparison.OrdinalIgnoreCase))
            return rawState.Replace("Enabled=True", $"Enabled={enabled}", StringComparison.OrdinalIgnoreCase);
        if (rawState.Contains("Enabled=False", StringComparison.OrdinalIgnoreCase))
            return rawState.Replace("Enabled=False", $"Enabled={enabled}", StringComparison.OrdinalIgnoreCase);
        return rawState;
    }

    /// <summary>
    /// 全量抓取系统 6 大类目当前物理与注册表状态并建立快照字典
    /// </summary>
    public List<SnapshotItem> CaptureFullSnapshot(string? activeUserSid, ContextMenuManagerEngine contextMenuEngine)
    {
        var items = new List<SnapshotItem>();

        // 1. 扫描启动项
        items.AddRange(ScanStartupItems(activeUserSid));

        // 2 & 3. 扫描 Win32 服务与内核驱动
        var (services, drivers) = ScanServicesAndDrivers();
        items.AddRange(services);
        items.AddRange(drivers);

        // 4. 扫描任务计划程序
        items.AddRange(ScanScheduledTasks());

        // 5. 扫描右键菜单 (经典 Shell 与 Win11 PackagedCom)
        items.AddRange(ScanContextMenus(activeUserSid, contextMenuEngine));

        // 6. 扫描 Windows 策略与劫持点
        items.AddRange(ScanWindowsPolicies(activeUserSid));

        lock (_diffSyncLock)
        {
            BaselineEstablishedUtc = DateTime.UtcNow;
            _cachedSnapshot.Clear();
            foreach (var item in items)
            {
                _cachedSnapshot[item.LocationKey] = item;
            }

            var nowUtc = DateTime.UtcNow;
            _hydratedUserSids.Clear();
            _hydratedUserClassesSids.Clear();
            if (!string.IsNullOrWhiteSpace(activeUserSid))
            {
                _hydratedUserSids[activeUserSid] = true;
                _userHydratedUtc[activeUserSid] = nowUtc;
                if (IsUserClassesHiveMounted(activeUserSid))
                    _hydratedUserClassesSids[activeUserSid] = true;
            }
            foreach (string loadedSid in InteractiveUserHiveResolver.GetAllLoadedUserSids())
            {
                _hydratedUserSids[loadedSid] = true;
                _userHydratedUtc[loadedSid] = nowUtc;
                if (IsUserClassesHiveMounted(loadedSid))
                    _hydratedUserClassesSids[loadedSid] = true;
            }
        }

        return items;
    }

    /// <summary>
    /// 当交互用户登录后 SID 才被加载或 UsrClass.dat 延迟挂载完成时，
    /// 静默吸收该用户已有的启动项、右键菜单与策略至基线快照，避免重启登录瞬间误报安装前旧项。
    /// </summary>
    public int AbsorbUserBaselineSnapshot(string? userSid, ContextMenuManagerEngine contextMenuEngine)
    {
        if (string.IsNullOrWhiteSpace(userSid))
            return 0;

        bool classesMounted = IsUserClassesHiveMounted(userSid);
        var items = new List<SnapshotItem>();
        items.AddRange(ScanStartupItems(userSid));
        items.AddRange(ScanContextMenus(userSid, contextMenuEngine));
        items.AddRange(ScanWindowsPolicies(userSid));

        int added = 0;
        lock (_diffSyncLock)
        {
            foreach (var item in items)
            {
                if (!_cachedSnapshot.ContainsKey(item.LocationKey))
                {
                    _cachedSnapshot[item.LocationKey] = item;
                    added++;
                }
            }

            _hydratedUserSids[userSid] = true;
            _userHydratedUtc[userSid] = DateTime.UtcNow;
            if (classesMounted)
                _hydratedUserClassesSids[userSid] = true;
        }

        return added;
    }

    private void EnsureAllActiveUsersHydratedLocked(string? activeUserSid, ContextMenuManagerEngine contextMenuEngine)
    {
        var candidateSids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (!string.IsNullOrWhiteSpace(activeUserSid))
            candidateSids.Add(activeUserSid);
        foreach (string sid in InteractiveUserHiveResolver.GetAllLoadedUserSids())
            candidateSids.Add(sid);

        foreach (string sid in candidateSids)
        {
            bool needsUserHydration = !_hydratedUserSids.ContainsKey(sid);
            bool classesReady = IsUserClassesHiveMounted(sid);
            bool needsClassesHydration = classesReady && !_hydratedUserClassesSids.ContainsKey(sid);

            if (!needsUserHydration && !needsClassesHydration)
                continue;

            var absorbed = new List<SnapshotItem>();
            if (needsUserHydration)
            {
                absorbed.AddRange(ScanStartupItems(sid));
                absorbed.AddRange(ScanWindowsPolicies(sid));
            }
            absorbed.AddRange(ScanContextMenus(sid, contextMenuEngine));

            foreach (var item in absorbed)
            {
                _cachedSnapshot.TryAdd(item.LocationKey, item);
            }

            _hydratedUserSids[sid] = true;
            _userHydratedUtc[sid] = DateTime.UtcNow;
            if (classesReady)
                _hydratedUserClassesSids[sid] = true;
        }
    }

    private static bool IsUserClassesHiveMounted(string userSid)
    {
        if (!OperatingSystem.IsWindows() || string.IsNullOrWhiteSpace(userSid))
            return false;

        try
        {
            using var classesKey = Microsoft.Win32.Registry.Users.OpenSubKey($@"{userSid}_Classes", writable: false);
            return classesKey != null;
        }
        catch
        {
            return false;
        }
    }

    internal bool HasToggleSiblingInSnapshot(string locationKey)
    {
        if (string.IsNullOrWhiteSpace(locationKey))
            return false;

        foreach (string variant in BuildToggleSiblingKeys(locationKey))
        {
            if (!string.Equals(variant, locationKey, StringComparison.OrdinalIgnoreCase) &&
                _cachedSnapshot.ContainsKey(variant))
            {
                return true;
            }
        }
        return false;
    }

    private static IEnumerable<string> BuildToggleSiblingKeys(string locationKey)
    {
        if (locationKey.Contains(@"\shellex\ContextMenuHandlers\", StringComparison.OrdinalIgnoreCase))
            yield return locationKey.Replace(@"\shellex\ContextMenuHandlers\", @"\shellex\-ContextMenuHandlers\", StringComparison.OrdinalIgnoreCase);
        else if (locationKey.Contains(@"\shellex\-ContextMenuHandlers\", StringComparison.OrdinalIgnoreCase))
            yield return locationKey.Replace(@"\shellex\-ContextMenuHandlers\", @"\shellex\ContextMenuHandlers\", StringComparison.OrdinalIgnoreCase);

        int lastSlash = locationKey.LastIndexOf('\\');
        if (lastSlash >= 0 && lastSlash < locationKey.Length - 1)
        {
            string parent = locationKey[..(lastSlash + 1)];
            string leaf = locationKey[(lastSlash + 1)..];
            string toggledLeaf = leaf.StartsWith('-') ? leaf[1..] : "-" + leaf;
            yield return parent + toggledLeaf;
        }
    }

    internal static bool TryGetLocationLastWriteUtc(string locationKey, out DateTime lastWriteUtc)
    {
        lastWriteUtc = default;
        if (!OperatingSystem.IsWindows() || string.IsNullOrWhiteSpace(locationKey))
            return false;

        string trimmed = locationKey.Trim();
        if (trimmed.EndsWith("::State", StringComparison.OrdinalIgnoreCase))
        {
            trimmed = trimmed[..^7];
        }

        if (trimmed.StartsWith("Task:", StringComparison.OrdinalIgnoreCase))
        {
            string rel = trimmed[5..].Trim().TrimStart('\\');
            string taskFile = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), @"System32\Tasks", rel);
            if (File.Exists(taskFile))
            {
                lastWriteUtc = File.GetLastWriteTimeUtc(taskFile);
                return true;
            }
            return false;
        }

        if (Path.IsPathRooted(trimmed) && File.Exists(trimmed))
        {
            lastWriteUtc = File.GetLastWriteTimeUtc(trimmed);
            return true;
        }

        nint rootHive = 0;
        string subKey = string.Empty;
        if (trimmed.StartsWith("HKEY_LOCAL_MACHINE\\", StringComparison.OrdinalIgnoreCase))
        {
            rootHive = PrivilegedRollbackEngine.HKEY_LOCAL_MACHINE;
            subKey = trimmed["HKEY_LOCAL_MACHINE\\".Length..];
        }
        else if (trimmed.StartsWith("HKLM\\", StringComparison.OrdinalIgnoreCase))
        {
            rootHive = PrivilegedRollbackEngine.HKEY_LOCAL_MACHINE;
            subKey = trimmed["HKLM\\".Length..];
        }
        else if (trimmed.StartsWith("HKEY_USERS\\", StringComparison.OrdinalIgnoreCase))
        {
            rootHive = PrivilegedRollbackEngine.HKEY_USERS;
            subKey = trimmed["HKEY_USERS\\".Length..];
        }
        else if (trimmed.StartsWith("HKU\\", StringComparison.OrdinalIgnoreCase))
        {
            rootHive = PrivilegedRollbackEngine.HKEY_USERS;
            subKey = trimmed["HKU\\".Length..];
        }

        if (rootHive == 0 || string.IsNullOrWhiteSpace(subKey))
            return false;

        // 仅直接打开完整 LocationKey 作为子键读取其自身的 lpftLastWriteTime；
        // 若末段是 ValueName（如 Run\MyApp），RegOpenKeyExW 会返回非 0，避免误用父键时间戳。
        if (RegOpenKeyExW(rootHive, subKey, 0, KEY_READ | KEY_WOW64_64KEY, out nint hKey) != 0 &&
            RegOpenKeyExW(rootHive, subKey, 0, KEY_READ, out hKey) != 0)
        {
            return false;
        }

        try
        {
            if (RegQueryInfoKeyW(hKey, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, out long fileTime) == 0 && fileTime > 0)
            {
                lastWriteUtc = DateTime.FromFileTimeUtc(fileTime);
                return true;
            }
        }
        finally
        {
            RegCloseKey(hKey);
        }

        return false;
    }

    internal bool IsPreExistingUnmonitoredEntry(SnapshotItem live)
    {
        if (HasToggleSiblingInSnapshot(live.LocationKey))
            return false;

        if (!TryGetLocationLastWriteUtc(live.LocationKey, out DateTime writeUtc))
            return false;

        return writeUtc < BaselineEstablishedUtc.AddSeconds(-5);
    }

    private bool TryGetPersistedBaselineRecord(string locationKey, out KnownBaselineRecord record)
    {
        if (_persistedBaselines.TryGetValue(locationKey, out record!))
            return true;

        string canonical = SqliteRuleRepository.CanonicalizeLocationForStorage(locationKey);
        if (!string.IsNullOrEmpty(canonical) && _persistedBaselines.TryGetValue(canonical, out record!))
            return true;

        foreach (string variant in BuildSuppressionKeyVariants(locationKey, activeUserSid: null))
        {
            if (_persistedBaselines.TryGetValue(variant, out record!))
                return true;
        }

        record = null!;
        return false;
    }

    private static bool IsRawStateExplicitlyDisabled(string? rawState)
    {
        if (string.IsNullOrWhiteSpace(rawState))
            return false;

        return rawState.Contains("Enabled=False", StringComparison.OrdinalIgnoreCase)
            || rawState.Contains("Start: 4", StringComparison.OrdinalIgnoreCase)
            || rawState.Contains("Start=4", StringComparison.OrdinalIgnoreCase)
            || string.Equals(rawState.Trim(), "Deleted", StringComparison.OrdinalIgnoreCase);
    }

    private bool ShouldSuppressAsPreExistingOrUnchangedBaseline(SnapshotItem live, DateTime nowUtc)
    {
        if (HasToggleSiblingInSnapshot(live.LocationKey))
            return false;

        bool? liveEnabled = TryParseLiveEnabledState(live);
        bool liveDisabled = liveEnabled == false || IsRawStateExplicitlyDisabled(live.RawState);

        // 1. 瞬态删建复用判定（典型如 OneDrive 开机检查先删 Run 值后 50ms 写回同路径）：30 秒内曾移除且非从禁用变启用
        if (_recentlyRemovedItems.TryGetValue(live.LocationKey, out var removed))
        {
            if ((nowUtc - removed.RemovedUtc).TotalSeconds <= 30.0)
            {
                bool prevDisabled = TryParseLiveEnabledState(removed.Item) == false ||
                                    IsRawStateExplicitlyDisabled(removed.Item.RawState);
                if (prevDisabled && !liveDisabled)
                    return false;

                string prevNorm = PathNormalizerAndSimilarity.NormalizeProgramPath(removed.Item.CommandOrBinaryPath);
                string liveNorm = PathNormalizerAndSimilarity.NormalizeProgramPath(live.CommandOrBinaryPath);
                if (string.Equals(prevNorm, liveNorm, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            else
            {
                _recentlyRemovedItems.TryRemove(live.LocationKey, out _);
            }
        }

        // 2. 持久化基线判定：既已存在且物理文件未发生版本更新，并且之前非用户明确禁止状态
        if (TryGetPersistedBaselineRecord(live.LocationKey, out var persisted))
        {
            bool prevDisabled = IsRawStateExplicitlyDisabled(persisted.RawState);
            if (prevDisabled && !liveDisabled)
                return false;

            if (persisted.FileLength > 0 && persisted.FileLastWriteUtcTicks > 0)
            {
                var (exists, liveTicks, liveLen) = ResolvePhysicalFileStamp(live.CommandOrBinaryPath);
                if (!exists || liveTicks != persisted.FileLastWriteUtcTicks || liveLen != persisted.FileLength)
                    return false;
            }

            return true;
        }

        // 3. 注册表子键 / UWP 子键 / Task XML 原生写入时间明确早于基线建立前
        if (IsPreExistingUnmonitoredEntry(live))
            return true;

        // 4. 开机登录延迟初始化兜底：服务启动前 120 秒内，HKU 用户配置单元刚延迟写入但物理文件早就存在于硬盘上（2 分钟前）
        bool withinBootWindow = (nowUtc - BaselineEstablishedUtc).TotalSeconds <= 120.0;
        if (!withinBootWindow)
        {
            foreach (var dt in _userHydratedUtc.Values)
            {
                if ((nowUtc - dt).TotalSeconds <= 45.0)
                {
                    withinBootWindow = true;
                    break;
                }
            }
        }

        if (withinBootWindow &&
            (live.LocationKey.StartsWith(@"HKU\", StringComparison.OrdinalIgnoreCase) ||
             live.LocationKey.StartsWith(@"HKCU\", StringComparison.OrdinalIgnoreCase) ||
             live.Category == MonitorCategory.StartupItem))
        {
            var (exists, liveTicks, _) = ResolvePhysicalFileStamp(live.CommandOrBinaryPath);
            if (exists && liveTicks > 0 && new DateTime(liveTicks, DateTimeKind.Utc) < BaselineEstablishedUtc.AddMinutes(-2))
                return true;
        }

        return false;
    }

    private void CollectDiffCandidateLocked(
        SnapshotItem live,
        List<(SnapshotItem Live, SnapshotItem? Previous)> changedList,
        HashSet<string>? trackedKeys = null)
    {
        if (trackedKeys != null && trackedKeys.Contains(live.LocationKey))
            return;

        if (IsLiveItemSuppressed(live))
        {
            SyncSuppressedSnapshotAliases(live);
            return;
        }

        if (!_cachedSnapshot.TryGetValue(live.LocationKey, out var existing))
        {
            if (ShouldSuppressAsPreExistingOrUnchangedBaseline(live, DateTime.UtcNow))
            {
                _cachedSnapshot[live.LocationKey] = live;
                return;
            }

            changedList.Add((live, null));
            trackedKeys?.Add(live.LocationKey);
        }
        else if (!string.Equals(existing.RawState, live.RawState, StringComparison.OrdinalIgnoreCase))
        {
            // 若前后均处于已启用状态（仅 Scene/描述文本等元数据差异），静默吸收至基线，不重复触发拦截弹窗
            bool bothEnabled = TryParseLiveEnabledState(existing) == true && TryParseLiveEnabledState(live) == true;
            if (!bothEnabled)
            {
                changedList.Add((live, existing));
                trackedKeys?.Add(live.LocationKey);
            }
        }
    }

    /// <summary>
    /// 当底层监控通知某分支发生变更时，与快照对比提取真实变更的目标特征
    /// </summary>
    public TargetProgramFeatures? DiffTargetMutated(
        NativeSystemMonitorMatrix.MonitoredRegistryTarget target,
        uint writerPid,
        string? activeUserSid,
        ContextMenuManagerEngine contextMenuEngine)
    {
        return DiffAllMutatedTargets(target, writerPid, activeUserSid, contextMenuEngine).FirstOrDefault();
    }

    public List<TargetProgramFeatures> DiffAllMutatedTargets(
        NativeSystemMonitorMatrix.MonitoredRegistryTarget target,
        uint writerPid,
        string? activeUserSid,
        ContextMenuManagerEngine contextMenuEngine)
    {
        List<(SnapshotItem Live, SnapshotItem? Previous)> changedList;
        lock (_diffSyncLock)
        {
            EnsureAllActiveUsersHydratedLocked(activeUserSid, contextMenuEngine);
            var (liveItems, coveredCategories) = ScanSingleTargetCategory(target, activeUserSid, contextMenuEngine);
            changedList = new List<(SnapshotItem Live, SnapshotItem? Previous)>();

            foreach (var live in liveItems)
            {
                CollectDiffCandidateLocked(live, changedList);
            }

            // 仅当确实发现新建/状态变更项时，才对右键菜单多场景或空路径做一次 120ms 稳态二次确认，零变更事件零额外休眠
            bool hasChanges = changedList.Count > 0;
            bool needsContextMenuSettle = hasChanges &&
                (target.Category == MonitorCategory.ClassicContextMenu || target.Category == MonitorCategory.ModernContextMenu);
            bool needsEmptyPathRetry = hasChanges && changedList.Any(c => string.IsNullOrEmpty(c.Live.CommandOrBinaryPath) &&
                (c.Live.Category == MonitorCategory.Win32Service ||
                 c.Live.Category == MonitorCategory.KernelDriver ||
                 c.Live.Category == MonitorCategory.ClassicContextMenu ||
                 c.Live.Category == MonitorCategory.ModernContextMenu));

            if (needsContextMenuSettle || needsEmptyPathRetry)
            {
                Thread.Sleep(120);
                (liveItems, coveredCategories) = ScanSingleTargetCategory(target, activeUserSid, contextMenuEngine);
                var map = new Dictionary<string, SnapshotItem>(StringComparer.OrdinalIgnoreCase);
                foreach (var item in liveItems)
                {
                    map[item.LocationKey] = item;
                }
                var trackedKeys = new HashSet<string>(
                    changedList.Select(c => c.Live.LocationKey),
                    StringComparer.OrdinalIgnoreCase);

                for (int i = 0; i < changedList.Count; i++)
                {
                    if (map.TryGetValue(changedList[i].Live.LocationKey, out var refItem))
                    {
                        changedList[i] = (refItem, changedList[i].Previous);
                    }
                }

                // 合并等待期间同期新落盘的同批变更项，防止多场景写入分步到达时漏检
                foreach (var live in liveItems)
                {
                    CollectDiffCandidateLocked(live, changedList, trackedKeys);
                }
            }

            // 保持快照字典在锁内原子同步，避免并发事件覆盖尚未报告的变更项
            foreach (var live in liveItems)
            {
                _cachedSnapshot[live.LocationKey] = live;
            }

            // 同步清理已消失项目并登记 30s 瞬态删建保护，确保既支持卸载重装复检，又防止 OneDrive 等自检删建误报
            var liveKeys = new HashSet<string>(liveItems.Select(x => x.LocationKey), StringComparer.OrdinalIgnoreCase);
            var coveredSet = new HashSet<MonitorCategory>(coveredCategories);
            var removedKeys = _cachedSnapshot
                .Where(kv => coveredSet.Contains(kv.Value.Category))
                .Select(kv => kv.Key)
                .Where(k => !liveKeys.Contains(k))
                .ToList();

            var nowUtc = DateTime.UtcNow;
            foreach (var remKey in removedKeys)
            {
                if (_cachedSnapshot.TryRemove(remKey, out var remItem))
                {
                    _recentlyRemovedItems[remKey] = (remItem, nowUtc);
                }
            }

            // 惰性清理过期的瞬态移除记录
            if (_recentlyRemovedItems.Count > 64)
            {
                foreach (var kv in _recentlyRemovedItems)
                {
                    if ((nowUtc - kv.Value.RemovedUtc).TotalSeconds > 60.0)
                        _recentlyRemovedItems.TryRemove(kv.Key, out _);
                }
            }
        }

        var results = new List<TargetProgramFeatures>(changedList.Count);
        foreach (var (changedItem, previousItem) in changedList)
        {
            var feat = BuildFeaturesForSnapshotItem(changedItem, previousItem, writerPid, activeUserSid);
            if (feat is not null)
            {
                results.Add(feat);
            }
        }

        return results;
    }

    private static TargetProgramFeatures BuildFeaturesForSnapshotItem(
        SnapshotItem changedItem,
        SnapshotItem? previousItem,
        uint writerPid,
        string? activeUserSid = null)
    {
        string oldSummary = previousItem is not null ? previousItem.RawState : "(None - 新建项)";
        string newSummary = changedItem.RawState;

        // 若为外壳扩展 DLL，使用 ProbeHost 隔离沙盒安全探测 (10秒内同 DLL 路径复用结果，避免多场景同时注册触发串行多进程探测超时)
        TargetProgramFeatures? probed = null;
        if ((changedItem.Category == MonitorCategory.ClassicContextMenu ||
             changedItem.Category == MonitorCategory.ModernContextMenu) &&
            !string.IsNullOrEmpty(changedItem.CommandOrBinaryPath) &&
            File.Exists(changedItem.CommandOrBinaryPath) &&
            changedItem.CommandOrBinaryPath.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
        {
            var nowUtc = DateTime.UtcNow;
            if (_probedDllCache.TryGetValue(changedItem.CommandOrBinaryPath, out var cachedProbe) &&
                nowUtc < cachedProbe.Expiry)
            {
                probed = cachedProbe.Probed;
            }
            else
            {
                try
                {
                    probed = ContextMenuManagerEngine.ProbeUnknownDllIsolatedAsync(changedItem.CommandOrBinaryPath).GetAwaiter().GetResult();
                }
                catch
                {
                    // 沙盒探针超时或异常时安全隔离，主服务 100% 免疫崩溃
                }
                _probedDllCache[changedItem.CommandOrBinaryPath] = (nowUtc.AddSeconds(10), probed);
            }
        }

        string svcDisplayName = string.Empty;
        if (!string.IsNullOrWhiteSpace(changedItem.DisplayName))
        {
            svcDisplayName = changedItem.DisplayName;
        }
        else if (changedItem.Category == MonitorCategory.Win32Service || changedItem.Category == MonitorCategory.KernelDriver)
        {
            string svcKeyName = Path.GetFileName(changedItem.LocationKey);
            if (changedItem.RawState.Contains("DisplayName="))
            {
                var idx = changedItem.RawState.IndexOf("DisplayName=", StringComparison.Ordinal);
                svcDisplayName = changedItem.RawState.Substring(idx + 12).Trim();
            }
            if (string.IsNullOrEmpty(svcDisplayName))
            {
                svcDisplayName = svcKeyName;
            }
        }
        else if (probed is not null && !string.IsNullOrWhiteSpace(probed.FileDescription))
        {
            svcDisplayName = probed.FileDescription;
        }
        else
        {
            svcDisplayName = Path.GetFileNameWithoutExtension(changedItem.CommandOrBinaryPath);
        }

        // 针对右键菜单：若解析出的名称为空、仍为 CLSID 或包含内部前缀，提取 CLSID 并调用 ContextMenuManager 引擎深度解析
        if (svcDisplayName.StartsWith("ClassicHandler:", StringComparison.OrdinalIgnoreCase) ||
            svcDisplayName.StartsWith("ClassicVerb:", StringComparison.OrdinalIgnoreCase))
        {
            int lastColon = svcDisplayName.LastIndexOf(':');
            if (lastColon >= 0 && lastColon < svcDisplayName.Length - 1)
            {
                svcDisplayName = svcDisplayName[(lastColon + 1)..].Trim();
            }
        }

        if ((changedItem.Category == MonitorCategory.ClassicContextMenu || changedItem.Category == MonitorCategory.ModernContextMenu) &&
            (string.IsNullOrWhiteSpace(svcDisplayName) || svcDisplayName.StartsWith('{') || svcDisplayName.StartsWith("ClassicHandler:")))
        {
            string loc = changedItem.LocationKey;
            int clsidStart = loc.IndexOf('{');
            int clsidEnd = loc.IndexOf('}', clsidStart >= 0 ? clsidStart : 0);
            if (clsidStart < 0 && changedItem.RawState.Contains("Clsid={"))
            {
                int cs = changedItem.RawState.IndexOf("Clsid={", StringComparison.Ordinal) + 6;
                int ce = changedItem.RawState.IndexOf('}', cs);
                if (ce > cs)
                {
                    loc = changedItem.RawState.Substring(cs, ce - cs + 1);
                    clsidStart = 0;
                    clsidEnd = loc.Length - 1;
                }
            }
            if (clsidStart >= 0 && clsidEnd > clsidStart)
            {
                string clsid = loc.Substring(clsidStart, clsidEnd - clsidStart + 1);
                string friendly = ContextMenuManagerEngine.ResolveClsidFriendlyName(PrivilegedRollbackEngine.HKEY_LOCAL_MACHINE, clsid, activeUserSid);
                if (!string.IsNullOrWhiteSpace(friendly) && !friendly.StartsWith('{'))
                {
                    svcDisplayName = friendly;
                }
            }
            if (string.IsNullOrWhiteSpace(svcDisplayName) || svcDisplayName.StartsWith('{'))
            {
                string fileFallback = Path.GetFileNameWithoutExtension(changedItem.CommandOrBinaryPath);
                if (!string.IsNullOrWhiteSpace(fileFallback))
                    svcDisplayName = fileFallback;
            }
        }

        var (creatorPid, creatorProcName) = NativeSecurityExtractor.ResolveCreatorProcessInfo(
            writerPid,
            changedItem.CommandOrBinaryPath,
            svcDisplayName,
            probed?.SignerSubject ?? string.Empty);

        if (probed is not null)
        {
            var (_, argsTemplate) = PathNormalizerAndSimilarity.SplitCommandLine(changedItem.CommandOrBinaryPath);
            return new TargetProgramFeatures
            {
                Category = changedItem.Category,
                TargetBinaryPath = changedItem.CommandOrBinaryPath,
                NormalizedPath = PathNormalizerAndSimilarity.NormalizeProgramPath(changedItem.CommandOrBinaryPath),
                NormalizedPathHash = MmfBinaryStore.ComputeFnv1a64(PathNormalizerAndSimilarity.NormalizeProgramPath(changedItem.CommandOrBinaryPath)),
                RawCommandLine = changedItem.CommandOrBinaryPath,
                CommandLineArgsTemplate = argsTemplate,
                LocationKeyOrIdentifier = changedItem.LocationKey,
                DisplayName = !string.IsNullOrWhiteSpace(svcDisplayName) ? svcDisplayName : (probed.FileDescription ?? probed.ProductName ?? Path.GetFileNameWithoutExtension(changedItem.CommandOrBinaryPath)),
                MD5Hex = probed.MD5Hex,
                SHA256Hex = probed.SHA256Hex,
                HasValidSignature = probed.HasValidSignature,
                SignerSubject = probed.SignerSubject,
                RootCertThumbprint = probed.RootCertThumbprint,
                OriginalFilename = probed.OriginalFilename,
                ProductName = probed.ProductName ?? string.Empty,
                CompanyName = probed.CompanyName ?? string.Empty,
                InternalName = probed.InternalName ?? string.Empty,
                FileDescription = probed.FileDescription ?? string.Empty,
                ImpHash = probed.ImpHash,
                IconPerceptualHash = probed.IconPerceptualHash,
                SourceProcessId = creatorPid,
                SourceProcessName = creatorProcName,
                OldStateSummary = oldSummary,
                NewStateSummary = newSummary,
                OldRawSnapshot = previousItem?.RawBytes,
                RegistryValueType = changedItem.RegistryValueType
            };
        }

        return NativeSecurityExtractor.BuildTargetProgramFeatures(
            changedItem.Category,
            changedItem.LocationKey,
            changedItem.CommandOrBinaryPath,
            displayName: svcDisplayName,
            oldState: oldSummary,
            newState: newSummary,
            sourcePid: creatorPid,
            sourceProcessName: creatorProcName,
            oldRawSnapshot: previousItem?.RawBytes,
            registryValueType: changedItem.RegistryValueType);
    }

    /// <summary>
    /// 在某个监控分类从禁用重新启用时，重新抓取该分类的实时系统状态并覆盖其内存基线快照，
    /// 确保监控关闭期间新安装或变更的项目不会在后续变更时被误判为新建项而弹窗。
    /// </summary>
    public int RefreshCategoryBaseline(
        MonitorCategory category,
        string? activeUserSid,
        ContextMenuManagerEngine contextMenuEngine)
    {
        List<SnapshotItem> liveItems = category switch
        {
            MonitorCategory.StartupItem => ScanStartupItems(activeUserSid),
            MonitorCategory.Win32Service => ScanServicesAndDrivers().Services,
            MonitorCategory.KernelDriver => ScanServicesAndDrivers().Drivers,
            MonitorCategory.ScheduledTask => ScanScheduledTasks(),
            MonitorCategory.ClassicContextMenu or MonitorCategory.ModernContextMenu =>
                ScanContextMenus(activeUserSid, contextMenuEngine)
                    .Where(x => x.Category == category)
                    .ToList(),
            MonitorCategory.WindowsPolicy => ScanWindowsPolicies(activeUserSid),
            _ => []
        };

        return ApplyCategoryBaselineSnapshot(category, liveItems);
    }

    public int ApplyCategoryBaselineSnapshot(MonitorCategory category, IReadOnlyList<SnapshotItem> liveItems)
    {
        lock (_diffSyncLock)
        {
            var oldKeys = _cachedSnapshot
                .Where(kv => kv.Value.Category == category)
                .Select(kv => kv.Key)
                .ToList();

            foreach (var oldKey in oldKeys)
            {
                _cachedSnapshot.TryRemove(oldKey, out _);
            }

            int syncedCount = 0;
            foreach (var item in liveItems)
            {
                if (item.Category != category)
                    continue;
                _cachedSnapshot[item.LocationKey] = item;
                syncedCount++;
            }

            return syncedCount;
        }
    }

    private static (List<SnapshotItem> Items, MonitorCategory[] CoveredCategories) ScanSingleTargetCategory(
        NativeSystemMonitorMatrix.MonitoredRegistryTarget target,
        string? activeUserSid,
        ContextMenuManagerEngine contextMenuEngine)
    {
        switch (target.Category)
        {
            case MonitorCategory.StartupItem:
                return (ScanStartupItems(activeUserSid), [MonitorCategory.StartupItem]);

            case MonitorCategory.Win32Service:
            case MonitorCategory.KernelDriver:
                return (ScanServicesAndDriversSubset(target.Category), [MonitorCategory.Win32Service, MonitorCategory.KernelDriver]);

            case MonitorCategory.ScheduledTask:
                return (ScanScheduledTasks(), [MonitorCategory.ScheduledTask]);

            case MonitorCategory.ClassicContextMenu:
                if (target.SubKeyPath.Contains("Shell Extensions", StringComparison.OrdinalIgnoreCase))
                {
                    return (ScanContextMenus(activeUserSid, contextMenuEngine),
                        [MonitorCategory.ClassicContextMenu, MonitorCategory.ModernContextMenu]);
                }
                return (ScanClassicOnlyContextMenusSnapshot(activeUserSid, contextMenuEngine),
                    [MonitorCategory.ClassicContextMenu]);

            case MonitorCategory.ModernContextMenu:
                return (ScanModernOnlyContextMenusSnapshot(activeUserSid, contextMenuEngine),
                    [MonitorCategory.ModernContextMenu]);

            case MonitorCategory.WindowsPolicy:
                return (ScanWindowsPolicies(activeUserSid), [MonitorCategory.WindowsPolicy]);

            default:
                return ([], []);
        }
    }

    private static List<SnapshotItem> ScanStartupItems(string? activeUserSid)
    {
        var list = new List<SnapshotItem>();
        if (!OperatingSystem.IsWindows())
            return list;

        nint hklm = PrivilegedRollbackEngine.HKEY_LOCAL_MACHINE;
        nint hku = PrivilegedRollbackEngine.HKEY_USERS;

        // HKLM Run & RunOnce
        ReadRegistryValuesToSnapshot(hklm, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", MonitorCategory.StartupItem, list);
        ReadRegistryValuesToSnapshot(hklm, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", MonitorCategory.StartupItem, list);
        ReadRegistryValuesToSnapshot(hklm, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", MonitorCategory.StartupItem, list);

        // HKEY_USERS\<SID> Run & RunOnce (动态支持系统中所有活跃用户)
        var sids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (!string.IsNullOrEmpty(activeUserSid))
            sids.Add(activeUserSid);
        foreach (var sid in InteractiveUserHiveResolver.GetAllLoadedUserSids())
            sids.Add(sid);

        foreach (var sid in sids)
        {
            ReadRegistryValuesToSnapshot(hku, $@"{sid}\Software\Microsoft\Windows\CurrentVersion\Run", MonitorCategory.StartupItem, list);
            ReadRegistryValuesToSnapshot(hku, $@"{sid}\Software\Microsoft\Windows\CurrentVersion\RunOnce", MonitorCategory.StartupItem, list);
            ReadRegistryValuesToSnapshot(hku, $@"{sid}\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", MonitorCategory.StartupItem, list);
            ReadRegistryValuesToSnapshot(hku, $@"{sid}\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce", MonitorCategory.StartupItem, list);
        }

        // 物理启动文件夹
        string commonStartup = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"Microsoft\Windows\Start Menu\Programs\Startup");
        ScanStartupFolder(commonStartup, list);

        string userStartup = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), @"Microsoft\Windows\Start Menu\Programs\Startup");
        ScanStartupFolder(userStartup, list);

        // UWP / Microsoft Store 应用自启任务 (AppModel\SystemAppData)
        foreach (var uwp in UwpStartupScanner.ScanForUserSids(sids))
        {
            string binOrPkg = !string.IsNullOrWhiteSpace(uwp.ExecutablePath)
                ? uwp.ExecutablePath
                : (!string.IsNullOrWhiteSpace(uwp.PackageInstallPath) ? uwp.PackageInstallPath : uwp.PackageFamilyName);
            list.Add(new SnapshotItem(
                MonitorCategory.StartupItem,
                uwp.LocationKey,
                binOrPkg,
                $"UwpState={uwp.State}, Enabled={uwp.IsEnabled}, PFN={uwp.PackageFamilyName}, Task={uwp.TaskId}",
                RegistryValueType: 4,
                DisplayName: uwp.DisplayName));
        }

        return list;
    }

    private static void ScanStartupFolder(string folderPath, List<SnapshotItem> list)
    {
        if (!Directory.Exists(folderPath))
            return;

        try
        {
            foreach (var file in Directory.EnumerateFiles(folderPath))
            {
                list.Add(new SnapshotItem(
                    MonitorCategory.StartupItem,
                    file,
                    file,
                    $"File: {Path.GetFileName(file)}"));
            }
        }
        catch
        {
            // 安全防崩溃
        }
    }

    private static (List<SnapshotItem> Services, List<SnapshotItem> Drivers) ScanServicesAndDrivers()
    {
        var services = new List<SnapshotItem>();
        var drivers = new List<SnapshotItem>();
        if (!OperatingSystem.IsWindows())
            return (services, drivers);

        nint hklm = PrivilegedRollbackEngine.HKEY_LOCAL_MACHINE;
        const string servicesKey = @"SYSTEM\CurrentControlSet\Services";

        if (RegOpenKeyExW(hklm, servicesKey, 0, KEY_READ | KEY_WOW64_64KEY, out nint hServices) != 0)
            return (services, drivers);

        try
        {
            char* subKeyName = stackalloc char[260];
            uint index = 0;
            var seenServices = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            while (true)
            {
                uint cchName = 260;
                int err = RegEnumKeyExW(hServices, index++, subKeyName, ref cchName, 0, 0, 0, out long lastWriteFt);
                if (err != 0) break;

                string svcName = new(subKeyName, 0, (int)cchName);
                seenServices.Add(svcName);

                if (lastWriteFt != 0 &&
                    _serviceScanCache.TryGetValue(svcName, out var cached) &&
                    cached.LastWriteFt == lastWriteFt)
                {
                    if (cached.Item.Category == MonitorCategory.KernelDriver)
                        drivers.Add(cached.Item);
                    else
                        services.Add(cached.Item);
                    continue;
                }

                string singleSvcPath = $@"{servicesKey}\{svcName}";

                if (RegOpenKeyExW(hklm, singleSvcPath, 0, KEY_READ | KEY_WOW64_64KEY, out nint hSingle) == 0)
                {
                    try
                    {
                        uint svcType = ReadRegistryDword(hSingle, "Type");
                        uint startType = ReadRegistryDword(hSingle, "Start");
                        string imagePath = ReadRegistryString(hSingle, "ImagePath");
                        string displayName = ReadRegistryString(hSingle, "DisplayName");

                        bool isDriver = (svcType & 0x01) != 0 || (svcType & 0x02) != 0 || (svcType & 0x08) != 0;
                        var cat = isDriver ? MonitorCategory.KernelDriver : MonitorCategory.Win32Service;

                        var item = new SnapshotItem(
                            cat,
                            $@"HKLM\{singleSvcPath}",
                            imagePath,
                            $"Start={startType}, Type=0x{svcType:X}, Name={svcName}, DisplayName={displayName}");

                        if (lastWriteFt != 0)
                            _serviceScanCache[svcName] = (lastWriteFt, item);

                        if (isDriver)
                            drivers.Add(item);
                        else
                            services.Add(item);
                    }
                    finally
                    {
                        RegCloseKey(hSingle);
                    }
                }
            }

            if (_serviceScanCache.Count > seenServices.Count + 16)
            {
                foreach (string key in _serviceScanCache.Keys)
                {
                    if (!seenServices.Contains(key))
                        _serviceScanCache.TryRemove(key, out _);
                }
            }
        }
        finally
        {
            RegCloseKey(hServices);
        }

        return (services, drivers);
    }

    private static List<SnapshotItem> ScanServicesAndDriversSubset(MonitorCategory category)
    {
        var (services, drivers) = ScanServicesAndDrivers();
        var list = new List<SnapshotItem>(services.Count + drivers.Count);
        list.AddRange(services);
        list.AddRange(drivers);
        return list;
    }

    private static List<SnapshotItem> ScanScheduledTasks()
    {
        var list = new List<SnapshotItem>();
        if (!OperatingSystem.IsWindows())
            return list;

        string tasksDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), @"System32\Tasks");
        if (Directory.Exists(tasksDir))
        {
            try
            {
                var seenTasks = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var file in Directory.EnumerateFiles(tasksDir, "*", SearchOption.AllDirectories))
                {
                    seenTasks.Add(file);
                    long ticks = 0;
                    long length = 0;
                    try
                    {
                        var fi = new FileInfo(file);
                        ticks = fi.LastWriteTimeUtc.Ticks;
                        length = fi.Length;
                    }
                    catch { }

                    if (ticks > 0 &&
                        _taskFileCache.TryGetValue(file, out var cached) &&
                        cached.LastWriteUtcTicks == ticks &&
                        cached.FileLength == length)
                    {
                        list.Add(cached.Item);
                        continue;
                    }

                    string relName = Path.GetRelativePath(tasksDir, file);
                    string cmd = file;
                    if (PrivilegedRollbackEngine.TryParseScheduledTaskXml(file, isXmlContent: false, out string parsedCmd, out _, out _ ) &&
                        !string.IsNullOrWhiteSpace(parsedCmd))
                    {
                        cmd = parsedCmd;
                    }

                    var item = new SnapshotItem(
                        MonitorCategory.ScheduledTask,
                        $@"Task: \{relName}",
                        cmd,
                        $"TaskFile: {relName}",
                        DisplayName: Path.GetFileName(file));
                    if (ticks > 0)
                        _taskFileCache[file] = (ticks, length, item);
                    list.Add(item);
                }

                if (_taskFileCache.Count > seenTasks.Count + 16)
                {
                    foreach (string key in _taskFileCache.Keys)
                    {
                        if (!seenTasks.Contains(key))
                            _taskFileCache.TryRemove(key, out _);
                    }
                }
            }
            catch
            {
                // 忽略系统受保护任务文件夹
            }
        }

        return list;
    }

    private static List<SnapshotItem> ScanContextMenus(string? activeUserSid, ContextMenuManagerEngine contextMenuEngine)
    {
        var list = new List<SnapshotItem>();
        var menus = contextMenuEngine.ScanAllContextMenus(activeUserSid);

        foreach (var m in menus)
        {
            string locKey = !string.IsNullOrWhiteSpace(m.RegistryPath) ? m.RegistryPath : m.IdKey;
            list.Add(new SnapshotItem(
                m.MenuCategory,
                locKey,
                m.TargetBinaryOrCommand,
                $"Enabled={m.IsEnabled}, Scene={m.ScopeScene}, Clsid={m.Clsid}",
                DisplayName: m.DisplayTitle));
        }

        return list;
    }

    private static List<SnapshotItem> ScanClassicOnlyContextMenusSnapshot(string? activeUserSid, ContextMenuManagerEngine contextMenuEngine)
    {
        var list = new List<SnapshotItem>();
        foreach (var m in contextMenuEngine.ScanClassicOnlyContextMenus(activeUserSid))
        {
            if (m.MenuCategory != MonitorCategory.ClassicContextMenu)
                continue;
            string locKey = !string.IsNullOrWhiteSpace(m.RegistryPath) ? m.RegistryPath : m.IdKey;
            list.Add(new SnapshotItem(
                MonitorCategory.ClassicContextMenu,
                locKey,
                m.TargetBinaryOrCommand,
                $"Enabled={m.IsEnabled}, Scene={m.ScopeScene}, Clsid={m.Clsid}",
                DisplayName: m.DisplayTitle));
        }
        return list;
    }

    private static List<SnapshotItem> ScanModernOnlyContextMenusSnapshot(string? activeUserSid, ContextMenuManagerEngine contextMenuEngine)
    {
        var list = new List<SnapshotItem>();
        foreach (var m in contextMenuEngine.ScanWindows11ModernMenus(activeUserSid))
        {
            string locKey = !string.IsNullOrWhiteSpace(m.RegistryPath) ? m.RegistryPath : m.IdKey;
            list.Add(new SnapshotItem(
                MonitorCategory.ModernContextMenu,
                locKey,
                m.TargetBinaryOrCommand,
                $"Enabled={m.IsEnabled}, Scene={m.ScopeScene}, Clsid={m.Clsid}",
                DisplayName: m.DisplayTitle));
        }
        return list;
    }

    private static List<SnapshotItem> ScanWindowsPolicies(string? activeUserSid)
    {
        var list = new List<SnapshotItem>();
        if (!OperatingSystem.IsWindows())
            return list;

        nint hklm = PrivilegedRollbackEngine.HKEY_LOCAL_MACHINE;
        nint hku = PrivilegedRollbackEngine.HKEY_USERS;

        // 1. IFEO 映像劫持（按子键 LastWriteTime 增量缓存，跳过未变动的上千个空 IFEO 子键）
        const string ifeoKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
        if (RegOpenKeyExW(hklm, ifeoKey, 0, KEY_READ | KEY_WOW64_64KEY, out nint hIfeo) == 0)
        {
            try
            {
                char* subKeyName = stackalloc char[260];
                uint index = 0;
                var seenIfeo = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                while (true)
                {
                    uint cchName = 260;
                    if (RegEnumKeyExW(hIfeo, index++, subKeyName, ref cchName, 0, 0, 0, out long lastWriteFt) != 0) break;
                    string exeName = new(subKeyName, 0, (int)cchName);
                    seenIfeo.Add(exeName);

                    if (lastWriteFt != 0 &&
                        _ifeoScanCache.TryGetValue(exeName, out var cached) &&
                        cached.LastWriteFt == lastWriteFt)
                    {
                        if (cached.Item != null)
                            list.Add(cached.Item);
                        continue;
                    }

                    string targetSubKey = $@"{ifeoKey}\{exeName}";
                    SnapshotItem? foundItem = null;
                    if (RegOpenKeyExW(hklm, targetSubKey, 0, KEY_READ | KEY_WOW64_64KEY, out nint hExe) == 0)
                    {
                        try
                        {
                            string debugger = ReadRegistryString(hExe, "Debugger");
                            if (!string.IsNullOrEmpty(debugger))
                            {
                                foundItem = new SnapshotItem(
                                    MonitorCategory.WindowsPolicy,
                                    $@"HKLM\{targetSubKey}\Debugger",
                                    debugger,
                                    $"IFEO Debugger: {debugger}");
                                list.Add(foundItem);
                            }
                        }
                        finally
                        {
                            RegCloseKey(hExe);
                        }
                    }

                    if (lastWriteFt != 0)
                        _ifeoScanCache[exeName] = (lastWriteFt, foundItem);
                }

                if (_ifeoScanCache.Count > seenIfeo.Count + 32)
                {
                    foreach (string key in _ifeoScanCache.Keys)
                    {
                        if (!seenIfeo.Contains(key))
                            _ifeoScanCache.TryRemove(key, out _);
                    }
                }
            }
            finally
            {
                RegCloseKey(hIfeo);
            }
        }

        // 2. Winlogon Shell 与 Userinit
        ReadRegistryValuesToSnapshot(hklm, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", MonitorCategory.WindowsPolicy, list);

        // 3. Policies\Explorer\Run
        ReadRegistryValuesToSnapshot(hklm, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", MonitorCategory.WindowsPolicy, list);
        if (!string.IsNullOrEmpty(activeUserSid))
        {
            ReadRegistryValuesToSnapshot(hku, $@"{activeUserSid}\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", MonitorCategory.WindowsPolicy, list);
        }

        // 4. Windows AppInit_DLLs
        ReadRegistryValuesToSnapshot(hklm, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", MonitorCategory.WindowsPolicy, list);

        return list;
    }

    private static void ReadRegistryValuesToSnapshot(
        nint rootHive,
        string subKeyPath,
        MonitorCategory category,
        List<SnapshotItem> list)
    {
        int errOpen = RegOpenKeyExW(rootHive, subKeyPath, 0, KEY_READ | KEY_WOW64_64KEY, out nint hKey);
        if (errOpen != 0 || hKey == 0)
        {
            errOpen = RegOpenKeyExW(rootHive, subKeyPath, 0, KEY_READ, out hKey);
            if (errOpen != 0 || hKey == 0)
                return;
        }

        try
        {
            char* valNameBuf = stackalloc char[260];
            byte* dataBuf = stackalloc byte[4096];
            uint index = 0;

            while (true)
            {
                uint cchValName = 260;
                uint cbData = 4096;
                int err = RegEnumValueW(hKey, index++, valNameBuf, ref cchValName, 0, out uint valType, dataBuf, ref cbData);
                if (err != 0) break;

                string valName = new(valNameBuf, 0, (int)cchValName);
                string strVal = (valType == 1 || valType == 2)
                    ? Marshal.PtrToStringUni((nint)dataBuf, (int)(cbData / 2)).TrimEnd('\0')
                    : $"Binary({cbData} bytes)";

                byte[] rawBytes = new byte[cbData];
                Marshal.Copy((nint)dataBuf, rawBytes, 0, (int)cbData);

                string prefix = rootHive == PrivilegedRollbackEngine.HKEY_USERS ? "HKU" : "HKLM";
                string locationKey = $@"{prefix}\{subKeyPath}\{valName}";

                list.Add(new SnapshotItem(
                    category,
                    locationKey,
                    strVal,
                    $"ValName={valName}, Data={strVal}, Type={valType}",
                    valType,
                    rawBytes));
            }
        }
        finally
        {
            RegCloseKey(hKey);
        }
    }

    private static uint ReadRegistryDword(nint hKey, string valueName)
    {
        uint data = 0;
        uint cbData = 4;
        if (RegQueryValueExW(hKey, valueName, 0, out uint type, (byte*)&data, ref cbData) == 0 && type == 4)
        {
            return data;
        }
        return 0;
    }

    private static string ReadRegistryString(nint hKey, string valueName)
    {
        byte* buf = stackalloc byte[1024];
        uint cbData = 1024;
        if (RegQueryValueExW(hKey, valueName, 0, out uint type, buf, ref cbData) == 0 && (type == 1 || type == 2))
        {
            return Marshal.PtrToStringUni((nint)buf, (int)(cbData / 2)).TrimEnd('\0');
        }
        return string.Empty;
    }
}
