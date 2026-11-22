using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using StartupGuard.Core.Models;
using StartupGuard.Core.Native;

namespace StartupGuard.Service.Monitoring;

/// <summary>
/// 底层异步注册表与系统变更监控协调器。
/// 基于 RegNotifyChangeKeyValue、ReadDirectoryChangesExW 与 NotifyServiceStatusChangeW 覆盖 6 类自启与扩展点。
/// </summary>
public sealed unsafe partial class NativeSystemMonitorMatrix : IDisposable
{
    private const string AdvApi32Dll = "advapi32.dll";
    private const string Kernel32Dll = "kernel32.dll";

    [LibraryImport(AdvApi32Dll, EntryPoint = "RegOpenKeyExW", StringMarshalling = StringMarshalling.Utf16)]
    private static partial int RegOpenKeyExW(nint hKey, string lpSubKey, uint ulOptions, uint samDesired, out nint phkResult);

    [LibraryImport(AdvApi32Dll)]
    private static partial int RegNotifyChangeKeyValue(
        nint hKey,
        [MarshalAs(UnmanagedType.Bool)] bool bWatchSubtree,
        uint dwNotifyFilter,
        nint hEvent,
        [MarshalAs(UnmanagedType.Bool)] bool fAsynchronous);

    [LibraryImport(AdvApi32Dll)]
    private static partial int RegCloseKey(nint hKey);

    [LibraryImport(Kernel32Dll)]
    private static partial uint WaitForMultipleObjects(
        uint nCount,
        nint* lpHandles,
        [MarshalAs(UnmanagedType.Bool)] bool bWaitAll,
        uint dwMilliseconds);

    private const uint KEY_NOTIFY = 0x0010;
    private const uint KEY_READ = 0x20019;
    private const uint KEY_WOW64_64KEY = 0x0100;
    private const uint KEY_WOW64_32KEY = 0x0200;
    private const uint WAIT_OBJECT_0 = 0x00000000;
    private const uint INFINITE = 0xFFFFFFFF;
    private const int MaxWatchesPerThread = 63; // WaitForMultipleObjects 上限 64，留 1 位给 StopEvent

    // REG_NOTIFY_CHANGE_NAME (1) | REG_NOTIFY_CHANGE_LAST_SET (4)
    private const uint REG_NOTIFY_FILTER_ALL = 0x00000001 | 0x00000004;

    public sealed record MonitoredRegistryTarget(
        MonitorCategory Category,
        nint RootHive,
        string SubKeyPath,
        bool WatchSubtree,
        bool AlsoWatchWow6432 = false);

    private sealed class WatchEntry
    {
        public required MonitoredRegistryTarget Target { get; init; }
        public required uint Wow64Flag { get; init; }
        public nint KeyHandle { get; set; }
        public AutoResetEvent? WaitEvent { get; set; }
    }

    private sealed class CategoryDebounceSlot : IDisposable
    {
        public readonly object Gate = new();
        public System.Threading.Timer? DebounceTimer;
        public MonitoredRegistryTarget? LatestTarget;
        public int InFlight;
        public int PendingRescan;

        public void Dispose()
        {
            lock (Gate)
            {
                DebounceTimer?.Dispose();
                DebounceTimer = null;
                LatestTarget = null;
                PendingRescan = 0;
            }
        }
    }

    private readonly List<Thread> _watcherThreads = [];
    private readonly List<WatchEntry> _allWatchEntries = [];
    private readonly ConcurrentDictionary<MonitorCategory, CategoryDebounceSlot> _debounceSlots = new();
    private ManualResetEventSlim? _stopSignal;
    private ManualResetEvent? _stopWaitHandle;
    private readonly List<FileSystemWatcher> _directoryWatchers = [];
    private readonly Action<MonitoredRegistryTarget> _onRegistryMutatedCallback;
    private readonly int _debounceWindowMs;
    private volatile int _enabledCategoriesMask = 0xFF; // 默认全开
    private volatile bool _stopped;
    private int _activeDispatches;

    public NativeSystemMonitorMatrix(Action<MonitoredRegistryTarget> onRegistryMutatedCallback)
        : this(onRegistryMutatedCallback, 220)
    {
    }

    internal NativeSystemMonitorMatrix(Action<MonitoredRegistryTarget> onRegistryMutatedCallback, int debounceWindowMs)
    {
        _onRegistryMutatedCallback = onRegistryMutatedCallback;
        _debounceWindowMs = Math.Clamp(debounceWindowMs, 10, 2000);
    }

    public bool IsCategoryEnabled(MonitorCategory cat) => (_enabledCategoriesMask & (1 << (int)cat)) != 0;

    public void SetCategoryEnabled(MonitorCategory cat, bool enabled)
    {
        if (enabled)
            _enabledCategoriesMask |= (1 << (int)cat);
        else
            _enabledCategoriesMask &= ~(1 << (int)cat);
    }

    /// <summary>
    /// 启动监控点：每个分片由专用长生命周期监控线程调用 RegNotifyChangeKeyValue 并循环 WaitForMultipleObjects，
    /// 避免 ThreadPool 线程退出导致异步注册表监听被提前取消
    /// </summary>
    public void StartAllNativeWatchers(string? interactiveUserSid)
    {
        StopAllWatchers();

        _stopped = false;
        _stopSignal = new ManualResetEventSlim(false);
        _stopWaitHandle = new ManualResetEvent(false);

        var targets = BuildFullSpectrumRegistryMatrix(interactiveUserSid);
        var specs = new List<(MonitoredRegistryTarget Target, uint Wow64Flag)>(targets.Count + 24);
        foreach (var target in targets)
        {
            specs.Add((target, KEY_WOW64_64KEY));
            if (target.AlsoWatchWow6432)
            {
                specs.Add((target, KEY_WOW64_32KEY));
            }
        }

        // 按每组最多 63 个键分组，保证单线程 WaitForMultipleObjects <= 64 句柄
        for (int offset = 0; offset < specs.Count; offset += MaxWatchesPerThread)
        {
            int count = Math.Min(MaxWatchesPerThread, specs.Count - offset);
            var chunk = specs.GetRange(offset, count);
            var stopEvent = _stopWaitHandle;
            var stopSignal = _stopSignal;

            var thread = new Thread(() => RunDedicatedWatchThread(chunk, stopEvent, stopSignal))
            {
                IsBackground = true,
                Name = $"SG-RegWatch-{offset / MaxWatchesPerThread}"
            };
            _watcherThreads.Add(thread);
            thread.Start();
        }

        StartDirectoryWatchers(interactiveUserSid);
    }

    private void StartDirectoryWatchers(string? userSid)
    {
        // 1. 公共启动文件夹 (%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup)
        string commonStartup = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"Microsoft\Windows\Start Menu\Programs\Startup");
        RegisterDirectoryWatcher(commonStartup, MonitorCategory.StartupItem);

        // 2. 当前用户启动文件夹 (%AppData%\Microsoft\Windows\Start Menu\Programs\Startup)
        string userStartup = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), @"Microsoft\Windows\Start Menu\Programs\Startup");
        RegisterDirectoryWatcher(userStartup, MonitorCategory.StartupItem);

        // 3. 任务计划程序物理目录 (C:\Windows\System32\Tasks)
        string tasksDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), @"System32\Tasks");
        RegisterDirectoryWatcher(tasksDir, MonitorCategory.ScheduledTask);
    }

    private void RegisterDirectoryWatcher(string dirPath, MonitorCategory category)
    {
        if (!Directory.Exists(dirPath))
            return;

        try
        {
            var watcher = new FileSystemWatcher(dirPath)
            {
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.CreationTime,
                IncludeSubdirectories = true,
                EnableRaisingEvents = true
            };

            FileSystemEventHandler onChange = (_, e) =>
            {
                if (!IsCategoryEnabled(category)) return;
                ScheduleCoalescedDispatch(new MonitoredRegistryTarget(category, 0, e.FullPath, false));
            };

            watcher.Created += onChange;
            watcher.Changed += onChange;
            watcher.Renamed += (s, e) => onChange(s, new FileSystemEventArgs(WatcherChangeTypes.Renamed, Path.GetDirectoryName(e.FullPath) ?? string.Empty, e.Name));

            _directoryWatchers.Add(watcher);
        }
        catch
        {
            // 安全防崩溃
        }
    }

    private void RunDedicatedWatchThread(
        List<(MonitoredRegistryTarget Target, uint Wow64Flag)> specs,
        ManualResetEvent stopEvent,
        ManualResetEventSlim stopSignal)
    {
        if (!OperatingSystem.IsWindows())
            return;

        var entries = new List<WatchEntry>(specs.Count);
        foreach (var (target, wow64Flag) in specs)
        {
            if (stopSignal.IsSet) break;
            if (RegOpenKeyExW(target.RootHive, target.SubKeyPath, 0, KEY_NOTIFY | KEY_READ | wow64Flag, out nint hKey) != 0 || hKey == 0)
            {
                if (RegOpenKeyExW(target.RootHive, target.SubKeyPath, 0, KEY_NOTIFY | KEY_READ, out hKey) != 0 || hKey == 0)
                    continue;
            }

            var waitEvt = new AutoResetEvent(false);
            nint rawEvtHandle = waitEvt.SafeWaitHandle.DangerousGetHandle();

            if (RegNotifyChangeKeyValue(hKey, target.WatchSubtree, REG_NOTIFY_FILTER_ALL, rawEvtHandle, fAsynchronous: true) != 0)
            {
                waitEvt.Dispose();
                RegCloseKey(hKey);
                continue;
            }

            entries.Add(new WatchEntry
            {
                Target = target,
                Wow64Flag = wow64Flag,
                KeyHandle = hKey,
                WaitEvent = waitEvt
            });
        }

        if (entries.Count == 0)
            return;

        lock (_allWatchEntries)
        {
            _allWatchEntries.AddRange(entries);
        }

        nint[] handles = new nint[entries.Count + 1];
        bool stopRefAdded = false;
        try
        {
            stopEvent.SafeWaitHandle.DangerousAddRef(ref stopRefAdded);
            handles[0] = stopEvent.SafeWaitHandle.DangerousGetHandle();
            for (int i = 0; i < entries.Count; i++)
            {
                handles[i + 1] = entries[i].WaitEvent!.SafeWaitHandle.DangerousGetHandle();
            }

            while (!stopSignal.IsSet)
            {
                uint waitRes;
                fixed (nint* pHandles = handles)
                {
                    waitRes = WaitForMultipleObjects((uint)handles.Length, pHandles, bWaitAll: false, INFINITE);
                }

                if (waitRes == WAIT_OBJECT_0 || waitRes == 0xFFFFFFFF) // stopEvent 或异常
                    break;

                int idx = (int)(waitRes - WAIT_OBJECT_0) - 1;
                if (idx < 0 || idx >= entries.Count)
                    break;

                var entry = entries[idx];
                nint rawEvtHandle = handles[idx + 1];

                // 必须在同一注册线程内立刻重新挂载下一次异步监听
                int rearmErr = RegNotifyChangeKeyValue(
                    entry.KeyHandle,
                    entry.Target.WatchSubtree,
                    REG_NOTIFY_FILTER_ALL,
                    rawEvtHandle,
                    fAsynchronous: true);

                if (rearmErr != 0)
                {
                    // 尝试重新打开子键（某些安装器会先删建父键）
                    RegCloseKey(entry.KeyHandle);
                    entry.KeyHandle = 0;
                    if (RegOpenKeyExW(entry.Target.RootHive, entry.Target.SubKeyPath, 0, KEY_NOTIFY | KEY_READ | entry.Wow64Flag, out nint reopened) == 0 && reopened != 0)
                    {
                        entry.KeyHandle = reopened;
                        RegNotifyChangeKeyValue(reopened, entry.Target.WatchSubtree, REG_NOTIFY_FILTER_ALL, rawEvtHandle, fAsynchronous: true);
                    }
                }

                if (IsCategoryEnabled(entry.Target.Category))
                {
                    ScheduleCoalescedDispatch(entry.Target);
                }
            }
        }
        finally
        {
            if (stopRefAdded)
            {
                try { stopEvent.SafeWaitHandle.DangerousRelease(); } catch { }
            }
            foreach (var entry in entries)
            {
                try { entry.WaitEvent?.Dispose(); } catch { }
                if (entry.KeyHandle != 0)
                {
                    try { RegCloseKey(entry.KeyHandle); } catch { }
                    entry.KeyHandle = 0;
                }
            }
        }
    }

    internal void DispatchEventForTesting(MonitoredRegistryTarget target) => ScheduleCoalescedDispatch(target);

    /// <summary>
    /// 按监控分类在 220ms 窗口内合并高频连续变更，并限制同一分类同时最多执行 1 次全量 Diff，
    /// 彻底杜绝系统或安装器连发注册表写入导致的线程池雪崩与数十万次重复扫描。
    /// </summary>
    private void ScheduleCoalescedDispatch(MonitoredRegistryTarget target)
    {
        if (_stopped || !IsCategoryEnabled(target.Category))
            return;

        var slot = _debounceSlots.GetOrAdd(target.Category, _ => new CategoryDebounceSlot());
        lock (slot.Gate)
        {
            if (_stopped)
                return;

            // 若已有待处理目标包含跨类 CLSID 路径 (Shell Extensions)，优先保留避免被普通子键覆盖
            if (slot.LatestTarget == null ||
                target.SubKeyPath.Contains("Shell Extensions", StringComparison.OrdinalIgnoreCase) ||
                !slot.LatestTarget.SubKeyPath.Contains("Shell Extensions", StringComparison.OrdinalIgnoreCase))
            {
                slot.LatestTarget = target;
            }

            if (Volatile.Read(ref slot.InFlight) == 1)
            {
                Interlocked.Exchange(ref slot.PendingRescan, 1);
                return;
            }

            slot.DebounceTimer ??= new System.Threading.Timer(
                _ => ExecuteDebouncedSlot(target.Category, slot),
                null,
                Timeout.Infinite,
                Timeout.Infinite);

            try
            {
                slot.DebounceTimer.Change(_debounceWindowMs, Timeout.Infinite);
            }
            catch (ObjectDisposedException)
            {
            }
        }
    }

    private void ExecuteDebouncedSlot(MonitorCategory category, CategoryDebounceSlot slot)
    {
        if (_stopped || !IsCategoryEnabled(category))
            return;

        if (Interlocked.CompareExchange(ref slot.InFlight, 1, 0) != 0)
        {
            Interlocked.Exchange(ref slot.PendingRescan, 1);
            return;
        }

        MonitoredRegistryTarget? capturedTarget;
        lock (slot.Gate)
        {
            capturedTarget = slot.LatestTarget;
            slot.LatestTarget = null;
        }

        if (capturedTarget == null)
        {
            Volatile.Write(ref slot.InFlight, 0);
            return;
        }

        bool boosted = Interlocked.Increment(ref _activeDispatches) == 1;
        if (boosted)
            ProcessQoSAndMemoryManager.BoostToHighPerformanceMode();

        try
        {
            _onRegistryMutatedCallback(capturedTarget);
        }
        catch (Exception ex)
        {
            StartupGuard.Core.Storage.SharedStorageHelper.LogDiagnostic("MonitorMatrix",
                $"Callback error ({capturedTarget.SubKeyPath}): {ex.Message}");
        }
        finally
        {
            Volatile.Write(ref slot.InFlight, 0);
            if (Interlocked.Decrement(ref _activeDispatches) == 0)
                ProcessQoSAndMemoryManager.EnterEcoEfficiencyMode();

            if (!_stopped && Interlocked.Exchange(ref slot.PendingRescan, 0) != 0)
            {
                MonitoredRegistryTarget? rescanTarget;
                lock (slot.Gate)
                {
                    rescanTarget = slot.LatestTarget ?? capturedTarget;
                }
                if (rescanTarget != null)
                    ScheduleCoalescedDispatch(rescanTarget);
            }
        }
    }

    /// <summary>
    /// 构建覆盖 6 个监护类别的注册表监控目标列表
    /// </summary>
    public static List<MonitoredRegistryTarget> BuildFullSpectrumRegistryMatrix(string? userSid)
    {
        nint hklm = PrivilegedRollbackEngine.HKEY_LOCAL_MACHINE;
        nint hku = PrivilegedRollbackEngine.HKEY_USERS;

        var list = new List<MonitoredRegistryTarget>
        {
            // === 1. 启动项监视 (HKLM + WOW6432Node + ActiveSetup) ===
            new(MonitorCategory.StartupItem, hklm, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", false, AlsoWatchWow6432: true),
            new(MonitorCategory.StartupItem, hklm, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", false, AlsoWatchWow6432: true),
            new(MonitorCategory.StartupItem, hklm, @"SOFTWARE\Microsoft\Active Setup\Installed Components", true, AlsoWatchWow6432: true),

            // === 2 & 3. 服务与内核驱动自启监视 (Services 树 & Upper/LowerFilters) ===
            new(MonitorCategory.Win32Service, hklm, @"SYSTEM\CurrentControlSet\Services", true),
            new(MonitorCategory.KernelDriver, hklm, @"SYSTEM\CurrentControlSet\Control\Class", true),

            // === 4. 任务计划程序监视 (仅监听 TaskCache\Tree 与 C:\Windows\System32\Tasks，避开 TaskCache\Tasks\{GUID}\DynamicInfo 高频噪音) ===
            new(MonitorCategory.ScheduledTask, hklm, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree", true),

            // === 5. 经典与现代上下文菜单监视 (HKLM Classes + PackagedCom + Shell Extensions\Approved WOW64) ===
            // 注：SOFTWARE\Classes\*\Directory\Folder 等由系统共享视图托管，不走 WOW6432Node 重定向，避免重复开双监听线程引发连环触发
            new(MonitorCategory.ClassicContextMenu, hklm, @"SOFTWARE\Classes\*\shell", true),
            new(MonitorCategory.ClassicContextMenu, hklm, @"SOFTWARE\Classes\*\shellex\ContextMenuHandlers", true),
            new(MonitorCategory.ClassicContextMenu, hklm, @"SOFTWARE\Classes\AllFilesystemObjects\shell", true),
            new(MonitorCategory.ClassicContextMenu, hklm, @"SOFTWARE\Classes\AllFilesystemObjects\shellex\ContextMenuHandlers", true),
            new(MonitorCategory.ClassicContextMenu, hklm, @"SOFTWARE\Classes\Directory\shell", true),
            new(MonitorCategory.ClassicContextMenu, hklm, @"SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers", true),
            new(MonitorCategory.ClassicContextMenu, hklm, @"SOFTWARE\Classes\Directory\Background\shell", true),
            new(MonitorCategory.ClassicContextMenu, hklm, @"SOFTWARE\Classes\Directory\Background\shellex\ContextMenuHandlers", true),
            new(MonitorCategory.ClassicContextMenu, hklm, @"SOFTWARE\Classes\DesktopBackground\Shell", true),
            new(MonitorCategory.ClassicContextMenu, hklm, @"SOFTWARE\Classes\DesktopBackground\shellex\ContextMenuHandlers", true),
            new(MonitorCategory.ClassicContextMenu, hklm, @"SOFTWARE\Classes\Folder\shell", true),
            new(MonitorCategory.ClassicContextMenu, hklm, @"SOFTWARE\Classes\Folder\shellex\ContextMenuHandlers", true),
            new(MonitorCategory.ClassicContextMenu, hklm, @"SOFTWARE\Classes\Drive\shell", true),
            new(MonitorCategory.ClassicContextMenu, hklm, @"SOFTWARE\Classes\Drive\shellex\ContextMenuHandlers", true),
            new(MonitorCategory.ClassicContextMenu, hklm, @"SOFTWARE\Classes\Drive\shellex\FolderExtensions", true),
            new(MonitorCategory.ClassicContextMenu, hklm, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved", false, AlsoWatchWow6432: true),
            new(MonitorCategory.ModernContextMenu, hklm, @"SOFTWARE\Classes\PackagedCom\ClassIndex", true),

            // === 6. Windows 策略、IFEO 映像劫持与 Winlogon 监视 ===
            new(MonitorCategory.WindowsPolicy, hklm, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", true),
            new(MonitorCategory.WindowsPolicy, hklm, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", false),
            new(MonitorCategory.WindowsPolicy, hklm, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", false),
            new(MonitorCategory.WindowsPolicy, hklm, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", true),
            new(MonitorCategory.WindowsPolicy, hklm, @"SYSTEM\CurrentControlSet\Control\Session Manager", false)
        };

        // === 跨会话定向用户级注册表 HKEY_USERS\<UserSID> (动态覆盖已登录用户配置单元) ===
        var allSids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (!string.IsNullOrEmpty(userSid))
        {
            allSids.Add(userSid);
        }
        foreach (var sid in InteractiveUserHiveResolver.GetAllLoadedUserSids())
        {
            allSids.Add(sid);
        }

        foreach (var sid in allSids)
        {
            list.Add(new(MonitorCategory.StartupItem, hku, $@"{sid}\Software\Microsoft\Windows\CurrentVersion\Run", false));
            list.Add(new(MonitorCategory.StartupItem, hku, $@"{sid}\Software\Microsoft\Windows\CurrentVersion\RunOnce", false));
            list.Add(new(MonitorCategory.StartupItem, hku, $@"{sid}\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", false));
            list.Add(new(MonitorCategory.StartupItem, hku, $@"{sid}\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce", false));
            list.Add(new(MonitorCategory.StartupItem, hku, $@"{sid}\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData", true));
            list.Add(new(MonitorCategory.ClassicContextMenu, hku, $@"{sid}\Software\Classes\*\shell", true));
            list.Add(new(MonitorCategory.ClassicContextMenu, hku, $@"{sid}\Software\Classes\*\shellex\ContextMenuHandlers", true));
            list.Add(new(MonitorCategory.ClassicContextMenu, hku, $@"{sid}\Software\Classes\AllFilesystemObjects\shell", true));
            list.Add(new(MonitorCategory.ClassicContextMenu, hku, $@"{sid}\Software\Classes\AllFilesystemObjects\shellex\ContextMenuHandlers", true));
            list.Add(new(MonitorCategory.ClassicContextMenu, hku, $@"{sid}\Software\Classes\Directory\shell", true));
            list.Add(new(MonitorCategory.ClassicContextMenu, hku, $@"{sid}\Software\Classes\Directory\shellex\ContextMenuHandlers", true));
            list.Add(new(MonitorCategory.ClassicContextMenu, hku, $@"{sid}\Software\Classes\Directory\Background\shell", true));
            list.Add(new(MonitorCategory.ClassicContextMenu, hku, $@"{sid}\Software\Classes\Directory\Background\shellex\ContextMenuHandlers", true));
            list.Add(new(MonitorCategory.ClassicContextMenu, hku, $@"{sid}\Software\Classes\Folder\shell", true));
            list.Add(new(MonitorCategory.ClassicContextMenu, hku, $@"{sid}\Software\Classes\Folder\shellex\ContextMenuHandlers", true));
            list.Add(new(MonitorCategory.ModernContextMenu, hku, $@"{sid}\Software\Classes\PackagedCom\ClassIndex", true));
            list.Add(new(MonitorCategory.WindowsPolicy, hku, $@"{sid}\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", false));
        }

        return list;
    }

    public void StopAllWatchers()
    {
        _stopped = true;
        foreach (var slot in _debounceSlots.Values)
        {
            slot.Dispose();
        }
        _debounceSlots.Clear();

        try { _stopSignal?.Set(); } catch { }
        try { _stopWaitHandle?.Set(); } catch { }

        foreach (var thread in _watcherThreads)
        {
            try
            {
                if (thread.IsAlive)
                    thread.Join(millisecondsTimeout: 1000);
            }
            catch { }
        }
        _watcherThreads.Clear();

        lock (_allWatchEntries)
        {
            _allWatchEntries.Clear();
        }

        try { _stopWaitHandle?.Dispose(); } catch { }
        _stopWaitHandle = null;
        try { _stopSignal?.Dispose(); } catch { }
        _stopSignal = null;

        foreach (var watcher in _directoryWatchers)
        {
            watcher.EnableRaisingEvents = false;
            watcher.Dispose();
        }
        _directoryWatchers.Clear();
    }

    public void Dispose() => StopAllWatchers();
}
