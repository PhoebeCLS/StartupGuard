using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using StartupGuard.Core.Configuration;
using StartupGuard.Core.ContextMenu;
using StartupGuard.Core.Ipc;
using StartupGuard.Core.Models;
using StartupGuard.Core.Native;
using StartupGuard.Core.Rules;
using StartupGuard.Core.Scoring;
using StartupGuard.Core.Storage;
using StartupGuard.Service.Monitoring;

namespace StartupGuard.Service;

/// <summary>
/// StartupGuard.Service.exe 后台守卫服务：
/// 1. 启动基准扫描 (baseline.bin)
/// 2. Windows 异步注册表与文件变更监控 + ETW 进程溯源
/// 3. 规则自动处理与用户授权回滚
/// 4. Auto Game Mode 全屏游戏防抖延后审核
/// 5. 多维可信度评估与规则匹配
/// 6. SCM Windows Service 支持与 CLI (--console, --service, --install, --uninstall, --scan-once)
/// </summary>
public static class Program
{
    private const string ServiceName = "StartupGuardService";
    private const string PipeName = "StartupGuard_Control_Pipe";
    private static readonly string AppDataRoot = SharedStorageHelper.GetSharedDataDirectory();

    private static MmfBinaryStore _rulesMmf = null!;
    private static SqliteRuleRepository _sqliteRepo = null!;
    private static ConfidenceScoringEngine _scoringEngine = null!;
    private static ContextMenuManagerEngine _contextMenuEngine = null!;
    private static EtwKernelRegistryTracker _etwTracker = null!;
    private static NativeSystemMonitorMatrix _monitorMatrix = null!;
    private static GameModeDebounceController _gameModeController = null!;
    private static SystemStateSnapshotDiffer _differ = null!;

    private static readonly ConcurrentDictionary<ulong, ConfidenceEvaluationResult> _pendingDecisions = new();
    private static readonly ConcurrentQueue<ulong> _alertDispatchQueue = new();
    private static readonly ConcurrentQueue<string> _rollbackFailureQueue = new();
    private static readonly ConcurrentQueue<string> _ruleBlockedNotificationQueue = new();
    private static readonly ConcurrentDictionary<string, DateTime> _recentlyEvaluated = new(StringComparer.OrdinalIgnoreCase);
    private static readonly ConcurrentDictionary<string, (DateTime Expiry, InterceptionAction Action)> _recentUserDecisionEnforcement = new(StringComparer.OrdinalIgnoreCase);
    private static volatile List<RuleRecord> _cachedRules = [];
    private static volatile bool _rulesCacheDirty = true;
    private static ulong _nextCorrelationId = 1;
    private static bool _contextMenuPromptMode = false;
    private static string? _activeInteractiveUserSid;

    public static async Task<int> Main(string[] args)
    {
        Directory.CreateDirectory(AppDataRoot);

        // CLI 参数分发
        if (args.Length > 0)
        {
            string flag = args[0].ToLowerInvariant();
            switch (flag)
            {
                case "--install":
                    return InstallService();

                case "--uninstall":
                    return UninstallService();

                case "--uninstall-reset":
                    return RunUninstallReset();

                case "--scan-once":
                    return RunScanOnce();

                case "--service":
                    return RunAsWindowsService();
            }
        }

        // 默认模式或 --console 模式：作为交互式/控制台服务运行
        return await RunServiceCoreAsync();
    }

    private static int InstallService()
    {
        Console.WriteLine("[StartupGuard.Service] Installing Windows Service...");
        if (!OperatingSystem.IsWindows())
        {
            Console.WriteLine("[StartupGuard.Service] Not running on Windows; install simulated successfully.");
            return 0;
        }

        try
        {
            string exePath = Process.GetCurrentProcess().MainModule?.FileName ?? "StartupGuard.Service.exe";
            var psi = new ProcessStartInfo("sc.exe", $"create {ServiceName} binPath= \"{exePath} --service\" start= auto DisplayName= \"StartupGuard Core Monitoring Service\"")
            {
                UseShellExecute = false,
                RedirectStandardOutput = true
            };
            using var p = Process.Start(psi);
            p?.WaitForExit();
            Console.WriteLine($"[StartupGuard.Service] Service created. Exit code: {p?.ExitCode ?? 0}");
            return p?.ExitCode ?? 0;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[StartupGuard.Service] Error installing service: {ex.Message}");
            return 1;
        }
    }

    private static int UninstallService()
    {
        Console.WriteLine("[StartupGuard.Service] Uninstalling Windows Service...");
        if (!OperatingSystem.IsWindows())
        {
            Console.WriteLine("[StartupGuard.Service] Not running on Windows; uninstall simulated successfully.");
            return 0;
        }

        try
        {
            var stopPsi = new ProcessStartInfo("sc.exe", $"stop {ServiceName}") { UseShellExecute = false };
            using (var stopProc = Process.Start(stopPsi)) { stopProc?.WaitForExit(); }

            var delPsi = new ProcessStartInfo("sc.exe", $"delete {ServiceName}") { UseShellExecute = false };
            using (var delProc = Process.Start(delPsi)) { delProc?.WaitForExit(); }

            Console.WriteLine("[StartupGuard.Service] Service deleted successfully.");
            return 0;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[StartupGuard.Service] Error uninstalling service: {ex.Message}");
            return 1;
        }
    }

    private static int RunUninstallReset()
    {
        Console.WriteLine("[StartupGuard.Service] Clearing StartupGuard settings, caches and leftover state (preserving user context menu preferences)...");
        try
        {
            // 仅清理 StartupGuard 自身配置与缓存，不还原用户已手动或通过规则优化的右键菜单禁用项

            if (OperatingSystem.IsWindows())
            {
                try { Microsoft.Win32.Registry.CurrentUser.DeleteSubKeyTree(@"Software\StartupGuard", throwOnMissingSubKey: false); } catch { }
                try { Microsoft.Win32.Registry.LocalMachine.DeleteSubKeyTree(@"Software\StartupGuard", throwOnMissingSubKey: false); } catch { }
                try
                {
                    foreach (string sid in Microsoft.Win32.Registry.Users.GetSubKeyNames())
                    {
                        if (!sid.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase) || sid.EndsWith("_Classes", StringComparison.OrdinalIgnoreCase))
                            continue;
                        try { Microsoft.Win32.Registry.Users.DeleteSubKeyTree($@"{sid}\Software\StartupGuard", throwOnMissingSubKey: false); } catch { }
                        try
                        {
                            using var runKey = Microsoft.Win32.Registry.Users.OpenSubKey($@"{sid}\Software\Microsoft\Windows\CurrentVersion\Run", writable: true);
                            runKey?.DeleteValue("StartupGuardTray", throwOnMissingValue: false);
                        }
                        catch { }
                        try
                        {
                            using var approvedKey = Microsoft.Win32.Registry.Users.OpenSubKey($@"{sid}\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run", writable: true);
                            approvedKey?.DeleteValue("StartupGuardTray", throwOnMissingValue: false);
                        }
                        catch { }
                        try
                        {
                            using var approved32Key = Microsoft.Win32.Registry.Users.OpenSubKey($@"{sid}\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32", writable: true);
                            approved32Key?.DeleteValue("StartupGuardTray", throwOnMissingValue: false);
                        }
                        catch { }
                    }
                }
                catch { }
            }

            UserSettingsStore.PurgeAllUserAndSharedDataForUninstall();

            try
            {
                string usersRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows)[..3], "Users");
                if (Directory.Exists(usersRoot))
                {
                    foreach (string profileDir in Directory.EnumerateDirectories(usersRoot))
                    {
                        foreach (string sub in new[] { @"AppData\Local\StartupGuard", @"AppData\Roaming\StartupGuard" })
                        {
                            string candidate = Path.Combine(profileDir, sub);
                            UserSettingsStore.PurgeDirectoryCompletely(candidate);
                        }
                    }
                }
            }
            catch { }

            Console.WriteLine("[StartupGuard.Service] Uninstall reset completed.");
            return 0;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[StartupGuard.Service] Error during --uninstall-reset: {ex.Message}");
            return 1;
        }
    }

    private static int RunScanOnce()
    {
        Console.WriteLine("[StartupGuard.Service] Executing --scan-once verification across all 6 categories...");
        InitializeAllComponents();

        // 捕获全量基准快照并验证
        var snapshot = _differ.CaptureFullSnapshot(_activeInteractiveUserSid, _contextMenuEngine);
        Console.WriteLine($"[StartupGuard.Service] Captured {snapshot.Count} snapshot entries across all 6 categories.");

        // 读取当前已有规则状态
        var allRules = _sqliteRepo.GetAllRulesWithWeightsAndAliases();
        Console.WriteLine($"[StartupGuard.Service] rules.db loaded with {allRules.Count} existing rules.");

        // 同步 rules.bin
        var ruleEntries = allRules.Select(MmfRecordEntry.FromRule).ToArray();
        _rulesMmf.SaveEntriesAtomically(ruleEntries);
        Console.WriteLine($"[StartupGuard.Service] rules.bin written. Item count: {_rulesMmf.Count}.");

        Console.WriteLine("[StartupGuard.Service] --scan-once completed successfully.");
        return 0;
    }

    public static async Task<int> RunServiceCoreAsync(CancellationToken externalCt = default)
    {
        InitializeAllComponents();

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(externalCt);
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
        };

        // 启动后台定时 MD5 规则时效性探测与自动清理循环 (不阻塞主循环)
        _ = Task.Run(() => StartPeriodicMd5ValidationLoopAsync(cts.Token));

        // 启动异步命名管道 IPC 服务端循环
        await RunNamedPipeServerLoopAsync(cts.Token);
        return 0;
    }

    private static void InitializeAllComponents()
    {
        // 1. 激活系统最高回滚特权 (SeTakeOwnership / SeRestore / SeBackup)
        PrivilegedRollbackEngine.EnableAllSystemRollbackPrivileges();

        // 2. 初始化核心组件与 SQLite 存储引擎
        _rulesMmf = new MmfBinaryStore(Path.Combine(AppDataRoot, "rules.bin"));
        _sqliteRepo = new SqliteRuleRepository(SharedStorageHelper.GetSharedDatabasePath());
        _scoringEngine = new ConfidenceScoringEngine(_sqliteRepo);
        _contextMenuEngine = new ContextMenuManagerEngine();
        _etwTracker = new EtwKernelRegistryTracker();
        _differ = new SystemStateSnapshotDiffer();

        // 3. 解析当前交互式桌面用户的 SID (跨会话定向 HKEY_USERS\<SID>)
        (_, _activeInteractiveUserSid) = InteractiveUserHiveResolver.TryGetActiveInteractiveUserSid();
        _contextMenuPromptMode = UserSettingsStore.GetContextMenuPromptMode(_activeInteractiveUserSid);
        try
        {
            var asm = System.Reflection.Assembly.GetExecutingAssembly();
            string ver = asm.GetName().Version?.ToString() ?? "unknown";
            string exeTime = File.Exists(Environment.ProcessPath)
                ? File.GetLastWriteTime(Environment.ProcessPath!).ToString("yyyy-MM-dd HH:mm:ss")
                : "unknown";
            var startupRules = _sqliteRepo.GetAllRulesWithWeightsAndAliases();
            _cachedRules = startupRules;
            _rulesCacheDirty = false;
            if (UserSettingsStore.GetDiagnosticLoggingEnabled())
            {
                string ruleSummary = startupRules.Count == 0
                    ? "none"
                    : string.Join(", ", startupRules.Take(10).Select(r => $"{r.RuleId}:{r.Category}:{r.DisplayName}"));
                SharedStorageHelper.LogDiagnostic("Service",
                    $"Startup banner ver={ver} buildTime={exeTime} sid={_activeInteractiveUserSid ?? "(none)"} " +
                    $"promptMode={_contextMenuPromptMode} dbRules={startupRules.Count} [{ruleSummary}]");
            }
        }
        catch { }

        // 4. 根据用户策略清理超期日志（不在生产服务启动时预置真实软件演示规则，避免静默误拦截）
        try
        {
            int effectiveRetentionDays = UserSettingsStore.GetLogPermanentRetention(_activeInteractiveUserSid)
                ? 0
                : UserSettingsStore.GetLogRetentionDays();
            _sqliteRepo.PruneAuditLogs(effectiveRetentionDays, UserSettingsStore.GetLogMaxCount());
        }
        catch { }

        // 5. 开机首态抓取系统全量快照到内存 differ (建立初始稳态，开机已有启动项视作可信基线，绝不重复报警)
        try
        {
            var initialSnapshot = _differ.CaptureFullSnapshot(_activeInteractiveUserSid, _contextMenuEngine);
            SharedStorageHelper.LogDiagnostic("Service", $"Initial memory baseline captured: {initialSnapshot.Count} items.");
        }
        catch (Exception ex)
        {
            SharedStorageHelper.LogDiagnostic("Service", $"Initial snapshot capture error: {ex.Message}");
        }

        // 6. 载入或更新 rules.bin
        if (!_rulesMmf.LoadIntoMemory())
        {
            var rules = _sqliteRepo.GetAllRulesWithWeightsAndAliases();
            var entries = rules.Select(MmfRecordEntry.FromRule).ToArray();
            _rulesMmf.SaveEntriesAtomically(entries);
        }

        // 7. 初始化 Auto Game Mode 45秒防抖控制器 (标记为 Session 0 服务模式，严禁调用桌面 SHQueryUserNotificationState)
        _gameModeController = new GameModeDebounceController(OnFlushDeferredGameModeAudits);
        _gameModeController.IsSession0Service = true;

        // 8. 启动 Windows 原生异步注册表与文件监视器
        _monitorMatrix = new NativeSystemMonitorMatrix(OnRegistryTargetMutated);
        _monitorMatrix.StartAllNativeWatchers(_activeInteractiveUserSid);

        // 9. 进入 EcoQoS 能效核调度模式并压缩物理内存工作集 (< 8MB)
        ProcessQoSAndMemoryManager.EnterEcoEfficiencyMode();
    }

    /// <summary>
    /// 当底层异步监控捕获到某分支发生变更时触发
    /// </summary>
    private static void OnRegistryTargetMutated(NativeSystemMonitorMatrix.MonitoredRegistryTarget target)
    {
        if (_monitorMatrix != null)
        {
            bool shouldProcess = target.Category is MonitorCategory.Win32Service or MonitorCategory.KernelDriver
                ? (_monitorMatrix.IsCategoryEnabled(MonitorCategory.Win32Service) ||
                   _monitorMatrix.IsCategoryEnabled(MonitorCategory.KernelDriver))
                : _monitorMatrix.IsCategoryEnabled(target.Category);
            if (!shouldProcess)
                return;
        }

        ulong pathHash = MmfBinaryStore.ComputeFnv1a64(target.SubKeyPath);
        uint writerPid = _etwTracker.ResolveRecentWriterPid(pathHash, target.SubKeyPath);

        // 真实 Diff 提取变更目标特征列表 (支持单次安装并发写入多个服务/驱动/自启项)
        if (_rulesCacheDirty)
        {
            _cachedRules = _sqliteRepo.GetAllRulesWithWeightsAndAliases();
            _rulesCacheDirty = false;
        }
        var allRules = _cachedRules;
        var capturedFeatures = _differ.DiffAllMutatedTargets(target, writerPid, _activeInteractiveUserSid, _contextMenuEngine);
        if (capturedFeatures.Count > 0 && UserSettingsStore.GetDiagnosticLoggingEnabled())
        {
            SharedStorageHelper.LogDiagnostic("DiffBatch",
                $"target={target.Category}:{target.SubKeyPath} writerPid={writerPid} count={capturedFeatures.Count} " +
                $"rules={allRules.Count} promptMode={ResolveEffectiveContextMenuPromptMode()} " +
                $"locs=[{string.Join(" | ", capturedFeatures.Select(f => f.LocationKeyOrIdentifier))}]");
        }

        foreach (var capturedFeature in capturedFeatures)
        {
            try
            {
                ProcessSingleCapturedFeature(capturedFeature, allRules);
            }
            catch (Exception ex)
            {
                SharedStorageHelper.LogDiagnostic("InterceptError",
                    $"Unhandled exception on {capturedFeature.Category} loc={capturedFeature.LocationKeyOrIdentifier}: {ex}");
            }
        }
    }

    private static void ProcessSingleCapturedFeature(TargetProgramFeatures capturedFeature, List<RuleRecord> allRules)
    {
        if (_monitorMatrix != null && !_monitorMatrix.IsCategoryEnabled(capturedFeature.Category))
        {
            return;
        }

        SharedStorageHelper.LogDiagnostic("InterceptTrace",
            $"cat={capturedFeature.Category} srcPid={capturedFeature.SourceProcessId}({capturedFeature.SourceProcessName}) " +
            $"bin={capturedFeature.TargetBinaryPath} sig={capturedFeature.HasValidSignature}({capturedFeature.SignerSubject}) " +
            $"md5={capturedFeature.MD5Hex} loc={capturedFeature.LocationKeyOrIdentifier} " +
            $"old=[{capturedFeature.OldStateSummary}] new=[{capturedFeature.NewStateSummary}]");

        // 本程序自身进程与自有组件操作免检放行，避免自我拦截或主面板内操作误报警
        if (IsStartupGuardSelfOperation(capturedFeature))
        {
            SharedStorageHelper.LogDiagnostic("InterceptTrace", $"Bypassed self-operation: {capturedFeature.LocationKeyOrIdentifier}");
            return;
        }

        // 若该位置在过去 12 秒内刚刚由用户在弹窗中处置完毕，严禁因安装器/系统延迟触碰同一键而弹出第二个重复审核窗口；
        // 若用户刚选择阻止/回滚且目标又回弹启用，静默重申回滚即可。
        if (TryGetRecentUserDecision(capturedFeature.LocationKeyOrIdentifier, out var recentDecisionAction))
        {
            SharedStorageHelper.LogDiagnostic("Service", $"Suppressed post-decision re-alert ({recentDecisionAction}): {capturedFeature.LocationKeyOrIdentifier}");
            if (recentDecisionAction != InterceptionAction.Allow &&
                !capturedFeature.NewStateSummary.Contains("Enabled=False", StringComparison.OrdinalIgnoreCase))
            {
                ExecuteRollbackForTarget(capturedFeature, recentDecisionAction);
            }
            return;
        }

        // 若目标状态已经处于明确禁用/屏蔽状态（如右键菜单 Enabled=False 或 UWP 已禁用），严禁再次触发回滚/通知循环
        if ((capturedFeature.Category is MonitorCategory.ClassicContextMenu or MonitorCategory.ModernContextMenu &&
             capturedFeature.NewStateSummary.Contains("Enabled=False", StringComparison.OrdinalIgnoreCase)) ||
            (PrivilegedRollbackEngine.IsUwpStartupLocation(capturedFeature.LocationKeyOrIdentifier) &&
             capturedFeature.NewStateSummary.Contains("Enabled=False", StringComparison.OrdinalIgnoreCase)))
        {
            SharedStorageHelper.LogDiagnostic("Service", $"Skip already-disabled state mutation: {capturedFeature.LocationKeyOrIdentifier}");
            return;
        }

        // 2.5秒内重复路径/位置防抖（置于前置忽略分支之后，防止已禁用态提前占坑导致后续启用跳变被吞）
        if (_recentlyEvaluated.TryGetValue(capturedFeature.LocationKeyOrIdentifier, out var lastTime) &&
            (DateTime.UtcNow - lastTime).TotalSeconds < 2.5)
        {
            return;
        }
        _recentlyEvaluated[capturedFeature.LocationKeyOrIdentifier] = DateTime.UtcNow;

        // 系统底层核心必要自启/服务组件检查 (囊括全面，确保永不拦截 svchost、CredentialEnrollmentManager 等核心组件；同时严格排除微软电脑管家、手机远控等)
        if (NativeSecurityExtractor.IsWindowsEssentialOperatingSystemComponent(capturedFeature))
        {
            return;
        }

        // 纯名称、位置与MD5精确研判 (通过严格类别与规范化位置匹配，避免同 DLL 多场景或空字段串扰)
        RuleRecord? matchedRule = EvaluateRuleMatch(allRules, capturedFeature);

        // 1. 命中已有规则
        if (matchedRule != null)
        {
            if (matchedRule.ActionType == InterceptionAction.Allow)
            {
                SharedStorageHelper.LogDiagnostic("Service", $"Rule matched (Allow): {matchedRule.DisplayName} on {capturedFeature.LocationKeyOrIdentifier}");
                return;
            }

            // 规则命中自动执行强权限回滚并启动后台多次复核（防止安装器收尾回写 Start=2）
            bool initialOk = ExecuteRollbackForTarget(capturedFeature, matchedRule.ActionType);
            SharedStorageHelper.LogDiagnostic("RuleRollback",
                $"ruleId={matchedRule.RuleId}({matchedRule.DisplayName}) mode={matchedRule.RuleMode} action={matchedRule.ActionType} initialOk={initialOk} loc={capturedFeature.LocationKeyOrIdentifier}");
            _ = Task.Run(() => VerifyAndRetryRollbackAsync(capturedFeature, matchedRule.ActionType, matchedRule.DisplayName));

            string displayName = !string.IsNullOrWhiteSpace(capturedFeature.DisplayName)
                ? capturedFeature.DisplayName
                : Path.GetFileName(capturedFeature.TargetBinaryPath);
            if (string.IsNullOrWhiteSpace(displayName))
                displayName = capturedFeature.LocationKeyOrIdentifier;

            if (UserSettingsStore.GetRuleHitNotificationsEnabled(_activeInteractiveUserSid))
            {
                string desc = $"[RULE]{displayName} (已根据规则拦截)";
                _ruleBlockedNotificationQueue.Enqueue(desc);
            }

            string actionDesc = matchedRule.ActionType switch
            {
                InterceptionAction.RollbackToDemand => "规则命中自动拦截：已设为手动启动",
                InterceptionAction.RollbackToDelayedAuto => "规则命中自动拦截：已设为自动延迟启动",
                InterceptionAction.RollbackToDisabled => "规则命中自动拦截：已阻止并禁止",
                InterceptionAction.DeleteEntry => "规则命中自动拦截：已删除",
                _ => $"规则命中自动拦截：{matchedRule.ActionType}"
            };

            // 更新快照记录
            matchedRule.CurrentMD5 = capturedFeature.MD5Hex;
            matchedRule.CurrentSHA256 = capturedFeature.SHA256Hex;
            if (_sqliteRepo.InsertOrUpdateRule(matchedRule) == 0)
            {
                _rulesCacheDirty = true;
                SharedStorageHelper.LogDiagnostic("Service", $"Detected deleted ruleId={matchedRule.RuleId} in memory cache; marked rules cache dirty.");
            }

            _sqliteRepo.WriteAuditLog(
                matchedRule.RuleId,
                capturedFeature.Category,
                capturedFeature.TargetBinaryPath,
                capturedFeature.LocationKeyOrIdentifier,
                capturedFeature.OldStateSummary,
                capturedFeature.NewStateSummary,
                actionDesc,
                100.0,
                initialOk
                    ? $"命中规则【{matchedRule.DisplayName}】已自动执行处置"
                    : $"命中规则【{matchedRule.DisplayName}】首次处置未完成，已进入后台复核重试");

            SharedStorageHelper.LogDiagnostic("Service", $"Rule hit auto-intercept: {actionDesc} (initialOk={initialOk}) for {capturedFeature.LocationKeyOrIdentifier}");
            return;
        }

        // 2. 检测是否处于 Auto Game Mode (全屏 3D 游戏 / 免打扰状态)
        var evaluation = new ConfidenceEvaluationResult
        {
            FinalScore = 100.0,
            MatchedRule = null,
            CurrentTarget = capturedFeature,
            Severity = DiagnosticSeverity.NormalNew,
            DiagnosticOpinion = "新注册系统启动或扩展项，请确认是否允许常驻",
            DiffItems = []
        };

        if (_gameModeController.IsCurrentlyInGameOrBusy())
        {
            _gameModeController.EnqueueDeferredAuditItem(evaluation);
            _sqliteRepo.WriteAuditLog(
                null,
                capturedFeature.Category,
                capturedFeature.TargetBinaryPath,
                capturedFeature.LocationKeyOrIdentifier,
                capturedFeature.OldStateSummary,
                capturedFeature.NewStateSummary,
                "全屏游戏免打扰暂存 (默认放行)",
                100.0,
                "全屏游戏期间捕获，已暂存延后审核队列",
                capturedFeature.SourceProcessName);
            SharedStorageHelper.LogDiagnostic("Service", $"GameMode deferred audit item for {capturedFeature.LocationKeyOrIdentifier}");
            return;
        }

        // 3. 右键菜单拦截策略：实时同步配置，防止开关切换竞争窗口内仍按旧策略静默拦截或通知
        bool contextMenuPrompt = ResolveEffectiveContextMenuPromptMode();
        if ((capturedFeature.Category == MonitorCategory.ClassicContextMenu ||
             capturedFeature.Category == MonitorCategory.ModernContextMenu) && !contextMenuPrompt)
        {
            bool firstOk = ExecuteRollbackForTarget(capturedFeature, InterceptionAction.RollbackToDisabled);
            if (!firstOk)
            {
                Thread.Sleep(80);
                ExecuteRollbackForTarget(capturedFeature, InterceptionAction.RollbackToDisabled);
            }
            _ = Task.Run(() => VerifyAndRetryRollbackAsync(capturedFeature, InterceptionAction.RollbackToDisabled));
            string menuTitle = !string.IsNullOrWhiteSpace(capturedFeature.DisplayName) ? capturedFeature.DisplayName : Path.GetFileName(capturedFeature.TargetBinaryPath);
            _sqliteRepo.WriteAuditLog(
                null,
                capturedFeature.Category,
                capturedFeature.TargetBinaryPath,
                capturedFeature.LocationKeyOrIdentifier,
                capturedFeature.OldStateSummary,
                capturedFeature.NewStateSummary,
                "先拦截待审核",
                100.0,
                $"检测到新右键菜单【{menuTitle}】，已先拦截屏蔽并加入待审核中心",
                capturedFeature.SourceProcessName);

            if (UserSettingsStore.GetContextMenuNotificationsEnabled(_activeInteractiveUserSid))
            {
                _ruleBlockedNotificationQueue.Enqueue($"[CTX]{menuTitle} (新右键菜单已屏蔽，可前往待审核中心查看)");
            }
            SharedStorageHelper.LogDiagnostic("Service", $"ContextMenu intercepted silently (先拦截后审核): {menuTitle}");
            return;
        }

        // 4. 常规桌面状态：推入待决策表并通过 IPC 唤起 TrayHost 弹窗 (包括即时审核右键菜单及各类自启变动)
        ulong corrId = Interlocked.Increment(ref _nextCorrelationId);
        _pendingDecisions[corrId] = evaluation;
        _alertDispatchQueue.Enqueue(corrId);
        _sqliteRepo.WriteAuditLog(
            null,
            capturedFeature.Category,
            capturedFeature.TargetBinaryPath,
            capturedFeature.LocationKeyOrIdentifier,
            capturedFeature.OldStateSummary,
            capturedFeature.NewStateSummary,
            "已捕获等待用户审核",
            100.0,
            "检测到新自启/服务/右键菜单注册，已弹出提示窗口等待用户处置",
            capturedFeature.SourceProcessName);

        SharedStorageHelper.LogDiagnostic("Service", $"Alert dispatched to queue: corrId={corrId}, target={capturedFeature.LocationKeyOrIdentifier}");
    }

    /// <summary>
    /// 结合类别、规范化位置键、名称与版本 MD5 进行精确规则匹配（防止同 DLL 多场景误命中）
    /// </summary>
    internal static bool IsDirectoryRuleTarget(RuleRecord rule)
    {
        string raw = !string.IsNullOrWhiteSpace(rule.RawCommand) ? rule.RawCommand : rule.NormalizedPath;
        string trimmed = raw.Trim().Trim('"');
        if (string.IsNullOrEmpty(trimmed))
            return false;

        if (trimmed.EndsWith('\\') || trimmed.EndsWith('/'))
            return true;

        string expanded = ShellNavigationHelper.ExpandNormalizedPathTemplate(trimmed);
        return !string.IsNullOrEmpty(expanded) && Directory.Exists(expanded);
    }

    internal static string NormalizeDirectoryPrefix(string rawOrNormalizedPath)
    {
        if (string.IsNullOrWhiteSpace(rawOrNormalizedPath))
            return string.Empty;

        string norm = PathNormalizerAndSimilarity.NormalizeProgramPath(rawOrNormalizedPath);
        if (string.IsNullOrWhiteSpace(norm))
            return string.Empty;

        norm = norm.Replace('/', '\\').TrimEnd('\\');
        return string.IsNullOrEmpty(norm) ? string.Empty : norm + @"\";
    }

    internal static RuleRecord? EvaluateRuleMatch(IReadOnlyList<RuleRecord> allRules, TargetProgramFeatures capturedFeature)
    {
        if (allRules == null || allRules.Count == 0)
            return null;

        string featureLoc = SqliteRuleRepository.CanonicalizeLocationForStorage(capturedFeature.LocationKeyOrIdentifier);
        string featureStem = Path.GetFileNameWithoutExtension(capturedFeature.TargetBinaryPath) ?? string.Empty;
        string featureNormPath = PathNormalizerAndSimilarity.NormalizeProgramPath(
            !string.IsNullOrEmpty(capturedFeature.TargetBinaryPath) ? capturedFeature.TargetBinaryPath : capturedFeature.NormalizedPath)
            .Replace('/', '\\');

        foreach (var rule in allRules)
        {
            if (rule.Category != capturedFeature.Category)
                continue;

            string ruleLoc = SqliteRuleRepository.CanonicalizeLocationForStorage(rule.LocationKey);
            bool hasRuleLoc = !string.IsNullOrWhiteSpace(ruleLoc);
            bool locationMatches = hasRuleLoc &&
                                   !string.IsNullOrWhiteSpace(featureLoc) &&
                                   string.Equals(ruleLoc, featureLoc, StringComparison.OrdinalIgnoreCase);

            if (IsDirectoryRuleTarget(rule))
            {
                string ruleDirSource = !string.IsNullOrWhiteSpace(rule.NormalizedPath) ? rule.NormalizedPath : rule.RawCommand;
                string folderPrefix = NormalizeDirectoryPrefix(ruleDirSource);
                bool folderMatches = !string.IsNullOrEmpty(folderPrefix) &&
                                     !string.IsNullOrEmpty(featureNormPath) &&
                                     (featureNormPath.StartsWith(folderPrefix, StringComparison.OrdinalIgnoreCase) ||
                                      string.Equals(featureNormPath + @"\", folderPrefix, StringComparison.OrdinalIgnoreCase));
                if (folderMatches && (!hasRuleLoc || locationMatches))
                    return rule;

                continue;
            }

            string ruleNormPath = (!string.IsNullOrWhiteSpace(rule.NormalizedPath)
                ? rule.NormalizedPath
                : PathNormalizerAndSimilarity.NormalizeProgramPath(rule.RawCommand)).Replace('/', '\\');
            bool pathMatches = !string.IsNullOrEmpty(ruleNormPath) &&
                               !string.IsNullOrEmpty(featureNormPath) &&
                               string.Equals(ruleNormPath, featureNormPath, StringComparison.OrdinalIgnoreCase);

            bool nameMatches = (!string.IsNullOrWhiteSpace(rule.DisplayName) &&
                                (string.Equals(rule.DisplayName, capturedFeature.DisplayName, StringComparison.OrdinalIgnoreCase) ||
                                 (!string.IsNullOrWhiteSpace(capturedFeature.ProductName) &&
                                  string.Equals(rule.DisplayName, capturedFeature.ProductName, StringComparison.OrdinalIgnoreCase)) ||
                                 (!string.IsNullOrWhiteSpace(featureStem) &&
                                  string.Equals(rule.DisplayName, featureStem, StringComparison.OrdinalIgnoreCase)))) ||
                               (!string.IsNullOrWhiteSpace(rule.ProductName) &&
                                !string.IsNullOrWhiteSpace(capturedFeature.ProductName) &&
                                string.Equals(rule.ProductName, capturedFeature.ProductName, StringComparison.OrdinalIgnoreCase));

            if (rule.RuleMode == RuleMatchMode.StrictCurrentVersion)
            {
                bool md5Matches = !string.IsNullOrEmpty(rule.CurrentMD5) &&
                                  !string.IsNullOrEmpty(capturedFeature.MD5Hex) &&
                                  string.Equals(rule.CurrentMD5, capturedFeature.MD5Hex, StringComparison.OrdinalIgnoreCase);
                if (!md5Matches)
                    continue;

                if (hasRuleLoc ? locationMatches : (pathMatches || nameMatches))
                    return rule;
            }
            else
            {
                if ((locationMatches && (nameMatches || pathMatches)) ||
                    (locationMatches && string.IsNullOrWhiteSpace(rule.DisplayName)) ||
                    (!hasRuleLoc && (pathMatches || nameMatches)))
                {
                    return rule;
                }
            }
        }

        return null;
    }

    private static bool ResolveEffectiveContextMenuPromptMode()
    {
        try
        {
            if (File.Exists(UserSettingsStore.SharedSettingsFilePath))
            {
                bool live = UserSettingsStore.GetContextMenuPromptMode(_activeInteractiveUserSid);
                _contextMenuPromptMode = live;
                return live;
            }
        }
        catch { }
        return _contextMenuPromptMode;
    }

    private static void DrainPendingContextMenuSilentNotifications()
    {
        if (_ruleBlockedNotificationQueue.IsEmpty)
            return;

        var kept = new List<string>();
        while (_ruleBlockedNotificationQueue.TryDequeue(out string? msg))
        {
            if (!string.IsNullOrEmpty(msg) && !msg.StartsWith("[CTX]", StringComparison.Ordinal))
                kept.Add(msg);
        }
        foreach (string item in kept)
        {
            _ruleBlockedNotificationQueue.Enqueue(item);
        }
    }

    /// <summary>
    /// 处理用户在弹窗中做出的最终决策 (默认不操作则放行；点击阻止则立刻调用强权限回滚)
    /// </summary>
    private static void HandleUserDecision(UserDecisionPayload decision)
    {
        TargetProgramFeatures? target = null;
        ConfidenceEvaluationResult? eval = null;

        if (_pendingDecisions.TryRemove(decision.CorrelationId, out eval))
        {
            target = eval.CurrentTarget;
        }
        else if (!string.IsNullOrEmpty(decision.LocationKey) || !string.IsNullOrEmpty(decision.TargetBinaryPath))
        {
            // 兜底：若 correlationId 为 0 或已超时，使用决策载荷中携带的目标信息构建 TargetProgramFeatures
            target = NativeSecurityExtractor.BuildTargetProgramFeatures(
                decision.Category,
                decision.LocationKey,
                decision.TargetBinaryPath,
                displayName: decision.DisplayName);
        }

        if (target == null)
            return;

        // 登记 12 秒主动决策保护窗，防止同一批次中用户在思考/点击“阻止所选”期间触发同一位置二次弹窗
        bool isDismiss = decision.ChosenAction == InterceptionAction.DismissWithoutChange;
        bool effectiveRememberRule = decision.RememberRule && !isDismiss;

        RecordRecentUserDecision(target.LocationKeyOrIdentifier, decision.ChosenAction);
        _differ.SuppressLocationKeyMutation(
            target.LocationKeyOrIdentifier,
            12.0,
            _activeInteractiveUserSid,
            target.TargetBinaryPath,
            expectedEnabledState: isDismiss ? null : (decision.ChosenAction == InterceptionAction.Allow));

        // 仅当用户明确选择了阻止/回滚动作时执行强权限修改；允许与关闭弹窗均不改动系统状态
        if (decision.ChosenAction is not (InterceptionAction.Allow or InterceptionAction.DismissWithoutChange))
        {
            ExecuteRollbackForTarget(target, decision.ChosenAction);
            _ = Task.Run(() => VerifyAndRetryRollbackAsync(target, decision.ChosenAction));
        }

        // 若用户勾选了“创建规则”且未取消操作，持久化至 SQLite 规则库
        if (effectiveRememberRule)
        {
            var newRule = new RuleRecord
            {
                DisplayName = !string.IsNullOrEmpty(target.ProductName)
                    ? target.ProductName
                    : (!string.IsNullOrEmpty(decision.DisplayName) ? decision.DisplayName : Path.GetFileNameWithoutExtension(target.TargetBinaryPath)),
                Category = target.Category,
                ActionType = decision.ChosenAction,
                RuleMode = decision.ChosenRuleMode,
                ConfidenceThreshold = 85.0f,
                HasSignature = target.HasValidSignature,
                SignerSubject = target.SignerSubject,
                RootCertThumbprint = target.RootCertThumbprint,
                OriginalFilename = target.OriginalFilename,
                ProductName = target.ProductName,
                CompanyName = target.CompanyName,
                InternalName = target.InternalName,
                NormalizedPath = target.NormalizedPath,
                RawCommand = !string.IsNullOrWhiteSpace(target.RawCommandLine) ? target.RawCommandLine : target.TargetBinaryPath,
                LocationKey = target.LocationKeyOrIdentifier,
                CommandLineArgs = target.CommandLineArgsTemplate,
                ImpHash = target.ImpHash,
                IconPHash = target.IconPerceptualHash,
                CurrentMD5 = target.MD5Hex,
                CurrentSHA256 = target.SHA256Hex
            };
            _sqliteRepo.InsertOrUpdateRule(newRule);
            _rulesCacheDirty = true;

            // 同步 rules.bin
            var allRules = _sqliteRepo.GetAllRulesWithWeightsAndAliases();
            _cachedRules = allRules;
            _rulesCacheDirty = false;
            var entries = allRules.Select(MmfRecordEntry.FromRule).ToArray();
            _rulesMmf.SaveEntriesAtomically(entries);
        }

        // 记录审计日志 - 采用通俗易懂的标准中文状态
        string readableAction = decision.ChosenAction switch
        {
            InterceptionAction.RollbackToDemand => "用户弹窗阻止：已回滚为手动启动",
            InterceptionAction.RollbackToDelayedAuto => "用户弹窗阻止：已回滚为自动延迟启动",
            InterceptionAction.RollbackToDisabled => "用户弹窗阻止：已禁止启动",
            InterceptionAction.DeleteEntry => "用户弹窗阻止：已删除",
            InterceptionAction.RestorePreviousSnapshot => "用户弹窗阻止：已恢复快照",
            InterceptionAction.Allow => "用户弹窗放行：允许启动",
            InterceptionAction.DismissWithoutChange => "已关闭弹窗（未处置）",
            _ => decision.ChosenAction.ToString()
        };

        string diagnosticText = decision.ChosenAction == InterceptionAction.DismissWithoutChange
            ? "用户关闭弹窗或未勾选处置项，未修改系统或规则，可在日志中手动操作"
            : (effectiveRememberRule
                ? (decision.ChosenAction == InterceptionAction.Allow
                    ? "用户在拦截提示弹窗中选择允许并沉淀规则"
                    : "用户在拦截提示弹窗中选择阻止并沉淀永久规则")
                : "用户在拦截提示弹窗中做出的处置决策");

        _sqliteRepo.WriteAuditLog(
            eval?.MatchedRule?.RuleId,
            target.Category,
            target.TargetBinaryPath,
            target.LocationKeyOrIdentifier,
            target.OldStateSummary,
            target.NewStateSummary,
            readableAction,
            100.0,
            diagnosticText,
            target.SourceProcessName);

        SharedStorageHelper.LogDiagnostic("Service",
            $"HandleUserDecision processed: {readableAction} for {target.LocationKeyOrIdentifier}, " +
            $"remember={effectiveRememberRule}, mode={decision.ChosenRuleMode}, ruleId={eval?.MatchedRule?.RuleId ?? 0}");

        ProcessQoSAndMemoryManager.TrimWorkingSetMemory();
    }

    private static bool IsStartupGuardSelfOperation(TargetProgramFeatures feature)
    {
        try
        {
            string baseDir = AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            string binPath = (feature.TargetBinaryPath ?? string.Empty).Trim().Trim('"');
            if (!string.IsNullOrEmpty(binPath))
            {
                if (!string.IsNullOrEmpty(baseDir) &&
                    binPath.StartsWith(baseDir + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }

                string fileName = Path.GetFileName(binPath);
                if (fileName.Equals("StartupGuard.App.exe", StringComparison.OrdinalIgnoreCase) ||
                    fileName.Equals("StartupGuard.Service.exe", StringComparison.OrdinalIgnoreCase) ||
                    fileName.Equals("StartupGuard.TrayHost.exe", StringComparison.OrdinalIgnoreCase) ||
                    fileName.Equals("StartupGuard.ProbeHost.exe", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            if (string.Equals(feature.LocationKeyOrIdentifier, @"Services\StartupGuardService", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(feature.LocationKeyOrIdentifier, @"HKLM\SYSTEM\CurrentControlSet\Services\StartupGuardService", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(feature.DisplayName, "StartupGuardService", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            if (feature.SourceProcessId > 0)
            {
                using var proc = System.Diagnostics.Process.GetProcessById((int)feature.SourceProcessId);
                string procName = proc.ProcessName;
                if (procName.Equals("StartupGuard.App", StringComparison.OrdinalIgnoreCase) ||
                    procName.Equals("StartupGuard.Service", StringComparison.OrdinalIgnoreCase) ||
                    procName.Equals("StartupGuard.TrayHost", StringComparison.OrdinalIgnoreCase) ||
                    procName.Equals("StartupGuard.ProbeHost", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
        }
        catch { }

        return false;
    }

    internal static void RecordRecentUserDecision(string locationKey, InterceptionAction action, double ttlSeconds = 12.0)
    {
        if (string.IsNullOrWhiteSpace(locationKey))
            return;

        var expiry = DateTime.UtcNow.AddSeconds(ttlSeconds);
        foreach (string variant in SystemStateSnapshotDiffer.BuildSuppressionKeyVariants(locationKey, _activeInteractiveUserSid))
        {
            if (variant.StartsWith("BIN|", StringComparison.Ordinal) || variant.StartsWith("CLSID|", StringComparison.Ordinal))
                continue;
            _recentUserDecisionEnforcement[variant] = (expiry, action);
        }
        _recentUserDecisionEnforcement[locationKey] = (expiry, action);
    }

    internal static bool TryGetRecentUserDecision(string locationKey, out InterceptionAction action)
    {
        action = InterceptionAction.Allow;
        if (string.IsNullOrWhiteSpace(locationKey))
            return false;

        var now = DateTime.UtcNow;
        foreach (string variant in SystemStateSnapshotDiffer.BuildSuppressionKeyVariants(locationKey, _activeInteractiveUserSid))
        {
            if (_recentUserDecisionEnforcement.TryGetValue(variant, out var entry))
            {
                if (now < entry.Expiry)
                {
                    action = entry.Action;
                    return true;
                }
                _recentUserDecisionEnforcement.TryRemove(variant, out _);
            }
        }

        if (_recentUserDecisionEnforcement.TryGetValue(locationKey, out var direct))
        {
            if (now < direct.Expiry)
            {
                action = direct.Action;
                return true;
            }
            _recentUserDecisionEnforcement.TryRemove(locationKey, out _);
        }

        return false;
    }

    private static bool ExecuteRollbackForTarget(TargetProgramFeatures target, InterceptionAction action)
    {
        // 登记免检抑制 (12秒)，避免自身写注册表/计划任务/服务引发二次误判弹窗
        bool expectedEnabled = action == InterceptionAction.Allow;
        _differ.SuppressLocationKeyMutation(
            target.LocationKeyOrIdentifier,
            12.0,
            _activeInteractiveUserSid,
            target.TargetBinaryPath,
            expectedEnabledState: expectedEnabled);

        // 核心特权回滚器调用 (在进入任何处理逻辑前严格实施驱动安全红线保护：Start=3/4，绝不删 .sys)
        bool ok = PrivilegedRollbackEngine.ExecuteRollback(target, action, _activeInteractiveUserSid);

        if (ok)
        {
            if (target.Category is MonitorCategory.ClassicContextMenu or MonitorCategory.ModernContextMenu)
            {
                _differ.SyncMovedContextMenuSnapshot(target.LocationKeyOrIdentifier, disabled: action != InterceptionAction.Allow);
                _differ.UpdateContextMenuEnabledInSnapshot(target.LocationKeyOrIdentifier, action == InterceptionAction.Allow);
            }
            else
            {
                string rolledBackState = action switch
                {
                    InterceptionAction.RollbackToDemand => "Start: 3, Delayed: False",
                    InterceptionAction.RollbackToDelayedAuto => "Start: 2, Delayed: True",
                    InterceptionAction.RollbackToDisabled => target.Category == MonitorCategory.StartupItem &&
                        PrivilegedRollbackEngine.IsUwpStartupLocation(target.LocationKeyOrIdentifier)
                        ? "Enabled=False"
                        : "Start: 4, Delayed: False",
                    InterceptionAction.DeleteEntry => "Deleted",
                    _ => "Rollback"
                };
                _differ.UpdateSnapshotItemState(target.LocationKeyOrIdentifier, rolledBackState);
            }
        }
        return ok;
    }

    private static TargetProgramFeatures? ExtractChangedTargetFeatures(
        NativeSystemMonitorMatrix.MonitoredRegistryTarget target,
        uint writerPid)
    {
        return _differ.DiffTargetMutated(target, writerPid, _activeInteractiveUserSid, _contextMenuEngine);
    }

    private static void ExecuteAuditRollback(AuditRollbackRequestPayload req)
    {
        try
        {
            _differ.SuppressLocationKeyMutation(req.LocationKey, 12.0, _activeInteractiveUserSid);
            var target = NativeSecurityExtractor.BuildTargetProgramFeatures(
                req.Category,
                req.LocationKey,
                req.LocationKey,
                oldState: req.OldStateSummary);

            InterceptionAction verifyAction = req.TargetAction;
            if (req.Category is MonitorCategory.Win32Service or MonitorCategory.KernelDriver)
            {
                bool isDriver = req.Category == MonitorCategory.KernelDriver;
                if (req.TargetAction == InterceptionAction.DeleteEntry && !isDriver)
                {
                    PrivilegedRollbackEngine.DeleteServiceByName(req.LocationKey);
                }
                else
                {
                    uint targetStart = req.TargetStartType is 0 or 1 or 2 or 3 or 4
                        ? req.TargetStartType
                        : (req.TargetAction == InterceptionAction.RollbackToDisabled ? 4u : (req.TargetAction == InterceptionAction.RollbackToDemand ? 3u : 2u));
                    if (isDriver && targetStart == 4) verifyAction = InterceptionAction.RollbackToDisabled;
                    else if (targetStart == 3) verifyAction = InterceptionAction.RollbackToDemand;
                    else if (targetStart == 2 && req.DelayedAutostart) verifyAction = InterceptionAction.RollbackToDelayedAuto;
                    else if (targetStart == 4) verifyAction = InterceptionAction.RollbackToDisabled;
                    else verifyAction = InterceptionAction.Allow;

                    PrivilegedRollbackEngine.RollbackServiceOrDriverStartType(req.LocationKey, targetStart, isDriver, req.DelayedAutostart);
                }
            }
            else if (req.TargetAction == InterceptionAction.Allow)
            {
                PrivilegedRollbackEngine.RestoreItemEnabled(target, req.TargetStartType, req.DelayedAutostart, _activeInteractiveUserSid);
            }
            else
            {
                ExecuteRollbackForTarget(target, req.TargetAction);
            }

            _ = Task.Run(() => VerifyAndRetryRestoreOrRollbackAsync(target, verifyAction, req.TargetStartType, req.DelayedAutostart));

            string targetSummary = req.Category is MonitorCategory.Win32Service or MonitorCategory.KernelDriver
                ? (verifyAction == InterceptionAction.DeleteEntry ? "Deleted" : $"Start={req.TargetStartType}" + (req.DelayedAutostart ? " (Delayed)" : ""))
                : req.TargetAction.ToString();

            string readableAction = verifyAction switch
            {
                InterceptionAction.Allow => "已恢复启动",
                InterceptionAction.RollbackToDemand => "已恢复为手动",
                InterceptionAction.RollbackToDelayedAuto => "已恢复为延迟启动",
                InterceptionAction.RollbackToDisabled => "已设为禁止",
                InterceptionAction.DeleteEntry => "已删除",
                _ => "已恢复处理"
            };

            _sqliteRepo.WriteAuditLog(
                null,
                req.Category,
                req.LocationKey,
                req.LocationKey,
                "User Restore",
                $"Reverted ({targetSummary})",
                readableAction,
                100.0,
                $"用户在日志中心执行了恢复操作：{readableAction}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[StartupGuard.Service] Rollback error: {ex.Message}");
        }
    }

    private static async Task VerifyAndRetryRestoreOrRollbackAsync(
        TargetProgramFeatures target,
        InterceptionAction expectedAction,
        uint targetStartType,
        bool delayedAutostart)
    {
        int[] checkDelaysMs = [800, 1700, 2500];
        for (int attempt = 0; attempt < checkDelaysMs.Length; attempt++)
        {
            await Task.Delay(checkDelaysMs[attempt]);
            bool ok = target.Category is MonitorCategory.Win32Service or MonitorCategory.KernelDriver && expectedAction != InterceptionAction.DeleteEntry
                ? PrivilegedRollbackEngine.VerifyServiceStartType(target.LocationKeyOrIdentifier, targetStartType, delayedAutostart)
                : PrivilegedRollbackEngine.VerifyRollbackState(target, expectedAction, _activeInteractiveUserSid);
            if (ok)
            {
                ProcessQoSAndMemoryManager.TrimWorkingSetMemory();
                return;
            }

            try
            {
                if (expectedAction == InterceptionAction.Allow || target.Category is MonitorCategory.Win32Service or MonitorCategory.KernelDriver)
                    PrivilegedRollbackEngine.RestoreItemEnabled(target, targetStartType, delayedAutostart, _activeInteractiveUserSid);
                else
                    ExecuteRollbackForTarget(target, expectedAction);
            }
            catch { }
        }

        await Task.Delay(800);
        bool finalOk = target.Category is MonitorCategory.Win32Service or MonitorCategory.KernelDriver && expectedAction != InterceptionAction.DeleteEntry
            ? PrivilegedRollbackEngine.VerifyServiceStartType(target.LocationKeyOrIdentifier, targetStartType, delayedAutostart)
            : PrivilegedRollbackEngine.VerifyRollbackState(target, expectedAction, _activeInteractiveUserSid);

        if (!finalOk)
        {
            string name = !string.IsNullOrEmpty(target.DisplayName) ? target.DisplayName : target.LocationKeyOrIdentifier;
            string actionZh = PrivilegedRollbackEngine.DescribeActionShortChinese(expectedAction);
            _rollbackFailureQueue.Enqueue($"「{name}」设为{actionZh}未生效，请手动核查。");
        }
        ProcessQoSAndMemoryManager.TrimWorkingSetMemory();
    }

    private static void OnFlushDeferredGameModeAudits(IReadOnlyList<ConfidenceEvaluationResult> batch)
    {
        foreach (var item in batch)
        {
            ulong corrId = Interlocked.Increment(ref _nextCorrelationId);
            _pendingDecisions[corrId] = item;
            _alertDispatchQueue.Enqueue(corrId);
        }
    }

    private static bool TryGetNextAlertToDispatch(out ulong corrId, out ConfidenceEvaluationResult? eval)
    {
        while (_alertDispatchQueue.TryDequeue(out ulong id))
        {
            if (_pendingDecisions.TryGetValue(id, out var foundEval))
            {
                corrId = id;
                eval = foundEval;
                return true;
            }
        }
        corrId = 0;
        eval = null;
        return false;
    }

    private static async Task VerifyAndRetryRollbackAsync(
        TargetProgramFeatures target,
        InterceptionAction expectedAction,
        string? ruleName = null)
    {
        int[] checkDelaysMs = [800, 1700, 2500, 4000];
        for (int attempt = 0; attempt < checkDelaysMs.Length; attempt++)
        {
            await Task.Delay(checkDelaysMs[attempt]);
            if (VerifyRollbackSucceeded(target, expectedAction))
            {
                if (attempt > 0)
                {
                    SharedStorageHelper.LogDiagnostic("Service", $"Rollback verified on retry #{attempt}: {target.LocationKeyOrIdentifier} -> {expectedAction}");
                }
                return;
            }

            SharedStorageHelper.LogDiagnostic("Service", $"Rollback check #{attempt + 1} failed or reverted by installer, retrying: {target.LocationKeyOrIdentifier} -> {expectedAction}");
            try
            {
                ExecuteRollbackForTarget(target, expectedAction);
            }
            catch { }
        }

        await Task.Delay(1000);
        if (!VerifyRollbackSucceeded(target, expectedAction))
        {
            string targetName = !string.IsNullOrEmpty(target.DisplayName)
                ? target.DisplayName
                : (!string.IsNullOrEmpty(target.ProductName) ? target.ProductName : Path.GetFileName(target.TargetBinaryPath));
            if (string.IsNullOrWhiteSpace(targetName))
                targetName = target.LocationKeyOrIdentifier;

            string actionZh = PrivilegedRollbackEngine.DescribeActionShortChinese(expectedAction);
            string failMsg = $"「{targetName}」设为{actionZh}未生效，可能受安装程序或权限锁定，请手动核查。";

            _sqliteRepo.WriteAuditLog(
                null,
                target.Category,
                target.TargetBinaryPath,
                target.LocationKeyOrIdentifier,
                target.OldStateSummary,
                $"状态未生效 ({actionZh})",
                "拦截异常",
                0.0,
                string.IsNullOrEmpty(ruleName)
                    ? $"多次尝试将目标设为{actionZh}未生效，请手动核查"
                    : $"规则【{ruleName}】多次尝试设为{actionZh}未生效，请手动核查");

            SharedStorageHelper.LogDiagnostic("Service", $"ROLLBACK VERIFY EXCEPTION after retries: {target.LocationKeyOrIdentifier} ({expectedAction})");
            _rollbackFailureQueue.Enqueue(failMsg);
        }
    }

    private static bool VerifyRollbackSucceeded(TargetProgramFeatures target, InterceptionAction expectedAction)
    {
        return PrivilegedRollbackEngine.VerifyRollbackState(target, expectedAction, _activeInteractiveUserSid);
    }

    private static async Task WriteNextResponseAsync(NamedPipeServerStream pipeServer, byte[] headerBuf, CancellationToken ct)
    {
        if (TryGetNextAlertToDispatch(out ulong nextCorrId, out var nextEval))
        {
            byte[] alertBytes = BinaryPipeSerializer.SerializeAlert(nextCorrId, nextEval!);
            var respHdr = PipeMessageHeader.Create(
                PipeMessageType.InterceptionAlertRequest,
                (uint)alertBytes.Length,
                nextCorrId);
            BinaryPipeSerializer.WriteHeader(headerBuf, in respHdr);
            await pipeServer.WriteAsync(headerBuf, ct);
            await pipeServer.WriteAsync(alertBytes, ct);
            await pipeServer.FlushAsync(ct);
        }
        else if (_rollbackFailureQueue.TryDequeue(out var failMsg))
        {
            byte[] failBytes = System.Text.Encoding.UTF8.GetBytes(failMsg);
            var respHdr = PipeMessageHeader.Create(
                PipeMessageType.RollbackFailureAlert,
                (uint)failBytes.Length,
                0);
            BinaryPipeSerializer.WriteHeader(headerBuf, in respHdr);
            await pipeServer.WriteAsync(headerBuf, ct);
            await pipeServer.WriteAsync(failBytes, ct);
            await pipeServer.FlushAsync(ct);
        }
        else if (_ruleBlockedNotificationQueue.TryDequeue(out var blockedMsg))
        {
            byte[] msgBytes = System.Text.Encoding.UTF8.GetBytes(blockedMsg);
            var respHdr = PipeMessageHeader.Create(
                PipeMessageType.BlockedItemNotification,
                (uint)msgBytes.Length,
                0);
            BinaryPipeSerializer.WriteHeader(headerBuf, in respHdr);
            await pipeServer.WriteAsync(headerBuf, ct);
            await pipeServer.WriteAsync(msgBytes, ct);
            await pipeServer.FlushAsync(ct);
        }
        else
        {
            var respHdr = PipeMessageHeader.Create(PipeMessageType.Heartbeat, 0, 0);
            BinaryPipeSerializer.WriteHeader(headerBuf, in respHdr);
            await pipeServer.WriteAsync(headerBuf, ct);
            await pipeServer.FlushAsync(ct);
        }
    }

    private static NamedPipeServerStream CreateNamedPipeServer()
    {
        if (OperatingSystem.IsWindows())
        {
            try
            {
                var pipeSecurity = new PipeSecurity();
                pipeSecurity.AddAccessRule(new PipeAccessRule(
                    new SecurityIdentifier(WellKnownSidType.WorldSid, null),
                    PipeAccessRights.ReadWrite,
                    AccessControlType.Allow));
                pipeSecurity.AddAccessRule(new PipeAccessRule(
                    new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null),
                    PipeAccessRights.ReadWrite | PipeAccessRights.CreateNewInstance,
                    AccessControlType.Allow));
                pipeSecurity.AddAccessRule(new PipeAccessRule(
                    new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                    PipeAccessRights.FullControl,
                    AccessControlType.Allow));
                pipeSecurity.AddAccessRule(new PipeAccessRule(
                    new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                    PipeAccessRights.FullControl,
                    AccessControlType.Allow));

                return NamedPipeServerStreamAcl.Create(
                    PipeName,
                    PipeDirection.InOut,
                    NamedPipeServerStream.MaxAllowedServerInstances,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous,
                    inBufferSize: 65536,
                    outBufferSize: 65536,
                    pipeSecurity: pipeSecurity);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[StartupGuard.Service] PipeSecurity init warning: {ex.Message}; fallback to standard pipe.");
            }
        }

        return new NamedPipeServerStream(
            PipeName,
            PipeDirection.InOut,
            NamedPipeServerStream.MaxAllowedServerInstances,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous);
    }

    private static async Task RunNamedPipeServerLoopAsync(CancellationToken ct)
    {
        byte[] headerBuf = new byte[64];
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await using var pipeServer = CreateNamedPipeServer();

                await pipeServer.WaitForConnectionAsync(ct);

                int read = await pipeServer.ReadAsync(headerBuf.AsMemory(0, 64), ct);
                if (read == 64)
                {
                    var hdr = BinaryPipeSerializer.ReadHeader(headerBuf);
                    if (hdr.IsValid && hdr.PayloadLength <= 65536)
                    {
                        byte[] payload = new byte[hdr.PayloadLength];
                        if (hdr.PayloadLength > 0)
                        {
                            await pipeServer.ReadExactlyAsync(payload, ct);
                        }

                        switch (hdr.MessageType)
                        {
                            case PipeMessageType.UserDecisionResponse:
                            {
                                var decision = BinaryPipeSerializer.DeserializeDecision(payload);
                                HandleUserDecision(decision);
                                break;
                            }

                            case PipeMessageType.UpdateMonitorToggles:
                            {
                                var toggles = BinaryPipeSerializer.DeserializeMonitorToggles(payload);
                                ApplyMonitorToggleUpdate(MonitorCategory.StartupItem, toggles.MonitorStartup);
                                ApplyMonitorToggleUpdate(MonitorCategory.Win32Service, toggles.MonitorService);
                                ApplyMonitorToggleUpdate(MonitorCategory.KernelDriver, toggles.MonitorDriver);
                                ApplyMonitorToggleUpdate(MonitorCategory.ScheduledTask, toggles.MonitorScheduledTask);
                                ApplyMonitorToggleUpdate(MonitorCategory.ClassicContextMenu, toggles.MonitorContextMenu);
                                ApplyMonitorToggleUpdate(MonitorCategory.ModernContextMenu, toggles.MonitorContextMenu);
                                ApplyMonitorToggleUpdate(MonitorCategory.WindowsPolicy, toggles.MonitorWindowsPolicy);
                                _gameModeController.IsAutoGameModeEnabled = toggles.AutoGameMode;
                                _contextMenuPromptMode = toggles.ContextMenuPromptMode;
                                SharedStorageHelper.LogDiagnostic("Service",
                                    $"UpdateMonitorToggles applied: promptMode={_contextMenuPromptMode}, ctx={toggles.MonitorContextMenu}, " +
                                    $"startup={toggles.MonitorStartup}, svc={toggles.MonitorService}, drv={toggles.MonitorDriver}, " +
                                    $"task={toggles.MonitorScheduledTask}, policy={toggles.MonitorWindowsPolicy}, gameMode={toggles.AutoGameMode}");
                                if (_contextMenuPromptMode)
                                {
                                    DrainPendingContextMenuSilentNotifications();
                                }
                                break;
                            }

                            case PipeMessageType.ReloadRulesCache:
                            {
                                var allRules = _sqliteRepo.GetAllRulesWithWeightsAndAliases();
                                _cachedRules = allRules;
                                _rulesCacheDirty = false;
                                var ruleEntries = allRules.Select(MmfRecordEntry.FromRule).ToArray();
                                _rulesMmf.SaveEntriesAtomically(ruleEntries);
                                SharedStorageHelper.LogDiagnostic("Service", $"ReloadRulesCache completed: activeRules={allRules.Count}");
                                break;
                            }

                            case PipeMessageType.ExecuteManualItemMutation:
                            {
                                var mutation = BinaryPipeSerializer.DeserializeManualMutation(payload);
                                var target = NativeSecurityExtractor.BuildTargetProgramFeatures(
                                    mutation.Category,
                                    mutation.LocationKey,
                                    mutation.TargetBinaryPath,
                                    displayName: mutation.DisplayName);

                                _differ.SuppressLocationKeyMutation(
                                    mutation.LocationKey,
                                    20.0,
                                    _activeInteractiveUserSid,
                                    mutation.TargetBinaryPath,
                                    expectedEnabledState: mutation.Action == InterceptionAction.Allow);
                                bool execOk = mutation.Action == InterceptionAction.Allow
                                    ? PrivilegedRollbackEngine.RestoreItemEnabled(target, 2, false, _activeInteractiveUserSid)
                                    : ExecuteRollbackForTarget(target, mutation.Action);

                                bool verified = PrivilegedRollbackEngine.VerifyRollbackState(target, mutation.Action, _activeInteractiveUserSid);
                                if (!verified)
                                {
                                    execOk = mutation.Action == InterceptionAction.Allow
                                        ? PrivilegedRollbackEngine.RestoreItemEnabled(target, 2, false, _activeInteractiveUserSid)
                                        : ExecuteRollbackForTarget(target, mutation.Action);
                                    verified = PrivilegedRollbackEngine.VerifyRollbackState(target, mutation.Action, _activeInteractiveUserSid);
                                }

                                if (verified || execOk)
                                {
                                    if (mutation.Category is MonitorCategory.ClassicContextMenu or MonitorCategory.ModernContextMenu)
                                    {
                                        bool enabled = mutation.Action == InterceptionAction.Allow;
                                        _differ.SyncMovedContextMenuSnapshot(mutation.LocationKey, disabled: !enabled);
                                        _differ.UpdateContextMenuEnabledInSnapshot(mutation.LocationKey, enabled);
                                    }
                                    else if (mutation.Action == InterceptionAction.Allow)
                                    {
                                        string restoredState = mutation.Category == MonitorCategory.StartupItem &&
                                            PrivilegedRollbackEngine.IsUwpStartupLocation(mutation.LocationKey)
                                            ? "Enabled=True"
                                            : "Start: 2, Delayed: False";
                                        _differ.UpdateSnapshotItemState(mutation.LocationKey, restoredState);
                                    }
                                }

                                SharedStorageHelper.LogDiagnostic("PipeManualMutation",
                                    $"cat={mutation.Category} act={mutation.Action} loc={mutation.LocationKey} execOk={execOk} verified={verified} sid={_activeInteractiveUserSid ?? "-"}");

                                try
                                {
                                    pipeServer.WriteByte((byte)(verified ? 1 : 2));
                                    await pipeServer.FlushAsync(ct);
                                }
                                catch { }

                                string manualActionZh = PrivilegedRollbackEngine.DescribeActionShortChinese(mutation.Action);
                                if (!verified)
                                {
                                    _ = Task.Run(() => VerifyAndRetryRollbackAsync(target, mutation.Action));
                                }
                                _sqliteRepo.WriteAuditLog(
                                    null,
                                    mutation.Category,
                                    mutation.TargetBinaryPath,
                                    mutation.LocationKey,
                                    "面板操作",
                                    manualActionZh,
                                    $"手动{manualActionZh}",
                                    100.0,
                                    verified ? "用户在主面板执行了状态变更" : "用户在主面板执行了状态变更（待复核）");
                                break;
                            }

                            case PipeMessageType.UserSessionReport:
                            {
                                var report = BinaryPipeSerializer.DeserializeUserSessionReport(payload);
                                if (!string.IsNullOrEmpty(report.UserSid) && !string.Equals(_activeInteractiveUserSid, report.UserSid, StringComparison.OrdinalIgnoreCase))
                                {
                                    _activeInteractiveUserSid = report.UserSid;
                                    _contextMenuPromptMode = UserSettingsStore.GetContextMenuPromptMode(_activeInteractiveUserSid);
                                    _monitorMatrix.StartAllNativeWatchers(_activeInteractiveUserSid);
                                }
                                _gameModeController.ExternalReportedInGame = report.InGame;

                                await WriteNextResponseAsync(pipeServer, headerBuf, ct);
                                break;
                            }

                            case PipeMessageType.ExecuteAuditRollback:
                            {
                                var req = BinaryPipeSerializer.DeserializeAuditRollbackRequest(payload);
                                ExecuteAuditRollback(req);
                                break;
                            }

                            case PipeMessageType.SuppressSelfMutation:
                            {
                                var sup = BinaryPipeSerializer.DeserializeSelfMutationSuppression(payload);
                                _differ.SuppressLocationKeyMutation(sup.LocationKey, Math.Max(sup.DurationSeconds, 20.0), _activeInteractiveUserSid, sup.TargetBinaryPath);
                                pipeServer.WriteByte(1);
                                await pipeServer.FlushAsync(ct);
                                break;
                            }

                            case PipeMessageType.Heartbeat:
                            {
                                await WriteNextResponseAsync(pipeServer, headerBuf, ct);
                                break;
                            }
                        }
                    }
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch
            {
                await Task.Delay(200, ct);
            }
        }
    }

    private static void ApplyMonitorToggleUpdate(MonitorCategory category, bool enabled)
    {
        bool wasEnabled = _monitorMatrix.IsCategoryEnabled(category);
        if (!wasEnabled && enabled)
        {
            int syncedCount = _differ.RefreshCategoryBaseline(category, _activeInteractiveUserSid, _contextMenuEngine);
            SharedStorageHelper.LogDiagnostic("Service",
                $"Monitor category re-enabled baseline synced: cat={category}, items={syncedCount}");
        }
        _monitorMatrix.SetCategoryEnabled(category, enabled);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LASTINPUTINFO
    {
        public uint cbSize;
        public uint dwTime;
    }

    [DllImport("user32.dll")]
    private static extern bool GetLastInputInfo(ref LASTINPUTINFO plii);

    private static bool IsSystemIdle(int idleSecondsThreshold = 30)
    {
        if (!OperatingSystem.IsWindows()) return true;
        try
        {
            var lii = new LASTINPUTINFO { cbSize = (uint)Marshal.SizeOf<LASTINPUTINFO>() };
            if (GetLastInputInfo(ref lii))
            {
                uint idleTicks = (uint)Environment.TickCount - lii.dwTime;
                return idleTicks >= (uint)(idleSecondsThreshold * 1000);
            }
        }
        catch { }
        return true;
    }

    private static void ExecuteMd5RulesValidation()
    {
        try
        {
            var res = Md5RuleValidator.ValidateAndCleanObsoleteMd5Rules(_sqliteRepo, _rulesMmf);
            if (res.DeletedCount > 0)
            {
                _cachedRules = _sqliteRepo.GetAllRulesWithWeightsAndAliases();
                _rulesCacheDirty = false;
                SharedStorageHelper.LogDiagnostic("Service",
                    $"Periodic MD5 rule validation cleaned {res.DeletedCount} obsolete rules; memory cache refreshed ({_cachedRules.Count} active).");
            }
        }
        catch (Exception ex)
        {
            SharedStorageHelper.LogDiagnostic("Service", $"ExecuteMd5RulesValidation error: {ex.Message}");
        }
    }

    private static void ExecuteOrphanedContextMenuCleanup()
    {
        try
        {
            int cleanedBlocks = _contextMenuEngine.CleanupOrphanedContextMenuBlocks(_activeInteractiveUserSid);
            int removedRules = 0;

            var allRules = _sqliteRepo.GetAllRulesWithWeightsAndAliases();
            foreach (var rule in allRules)
            {
                if (rule.Category is not (MonitorCategory.ClassicContextMenu or MonitorCategory.ModernContextMenu))
                    continue;

                string extracted = PrivilegedRollbackEngine.ExtractClsidOrIdentifier(rule.LocationKey);
                bool hasRealClsid = extracted.StartsWith('{') && extracted.EndsWith('}') && Guid.TryParse(extracted, out _);
                string resolvedBin = ShellNavigationHelper.ResolveRuleTargetFilePath(rule.RawCommand, rule.NormalizedPath, rule.LocationKey);
                bool hasRootedFile = !string.IsNullOrWhiteSpace(resolvedBin) &&
                                     !resolvedBin.Contains('<') &&
                                     Path.IsPathRooted(resolvedBin) &&
                                     !resolvedBin.Contains(@"\System32\", StringComparison.OrdinalIgnoreCase) &&
                                     !resolvedBin.Contains(@"\SysWOW64\", StringComparison.OrdinalIgnoreCase);
                bool fileExists = hasRootedFile && File.Exists(resolvedBin);

                bool stillInstalled;
                string reason;
                if (hasRealClsid)
                {
                    bool comInstalled = _contextMenuEngine.IsComHandlerOrPackageInstalled(extracted, _activeInteractiveUserSid);
                    stillInstalled = comInstalled && (!hasRootedFile || fileExists);
                    reason = $"comInstalled={comInstalled}, hasRootedFile={hasRootedFile}, fileExists={fileExists}";
                }
                else if (rule.LocationKey.StartsWith("HK", StringComparison.OrdinalIgnoreCase) ||
                         rule.LocationKey.StartsWith("HKEY_", StringComparison.OrdinalIgnoreCase))
                {
                    bool regExists = ShellNavigationHelper.DoesPendingLocationStillExist(rule.LocationKey, resolvedBin);
                    stillInstalled = regExists && (!hasRootedFile || fileExists);
                    reason = $"regExists={regExists}, hasRootedFile={hasRootedFile}, fileExists={fileExists}";
                }
                else if (hasRootedFile)
                {
                    stillInstalled = fileExists;
                    reason = $"fileExists={fileExists}";
                }
                else
                {
                    continue;
                }

                if (!stillInstalled && _sqliteRepo.DeleteRule(rule.RuleId))
                {
                    removedRules++;
                    SharedStorageHelper.LogDiagnostic("Service",
                        $"Orphaned context-menu rule deleted: id={rule.RuleId} name={rule.DisplayName} loc={rule.LocationKey} bin={resolvedBin} ({reason})");
                }
            }

            if (removedRules > 0)
            {
                var refreshed = _sqliteRepo.GetAllRulesWithWeightsAndAliases();
                _cachedRules = refreshed;
                _rulesCacheDirty = false;
                var updated = refreshed.Select(MmfRecordEntry.FromRule).ToArray();
                _rulesMmf.SaveEntriesAtomically(updated);
            }

            if (cleanedBlocks > 0)
            {
                _differ.RefreshCategoryBaseline(MonitorCategory.ClassicContextMenu, _activeInteractiveUserSid, _contextMenuEngine);
                _differ.RefreshCategoryBaseline(MonitorCategory.ModernContextMenu, _activeInteractiveUserSid, _contextMenuEngine);
            }

            if (cleanedBlocks > 0 || removedRules > 0)
            {
                SharedStorageHelper.LogDiagnostic("Service", $"Orphaned context-menu cleanup: blocks={cleanedBlocks}, rules={removedRules}");
            }
        }
        catch (Exception ex)
        {
            SharedStorageHelper.LogDiagnostic("Service", $"ExecuteOrphanedContextMenuCleanup error: {ex.Message}");
        }
    }

    private static async Task StartPeriodicMd5ValidationLoopAsync(CancellationToken ct)
    {
        // 服务启动后 10 秒执行首次单版本失效巡检，之后按周期巡检
        try { await Task.Delay(TimeSpan.FromSeconds(10), ct); } catch { return; }

        bool startupChecked = false;
        while (!ct.IsCancellationRequested)
        {
            try
            {
                ExecuteOrphanedContextMenuCleanup();

                if (UserSettingsStore.GetMd5ValidationEnabled())
                {
                    int intervalDays = UserSettingsStore.GetMd5ValidationIntervalDays();
                    if (intervalDays <= 0) intervalDays = 3;

                    DateTime lastTime = UserSettingsStore.GetLastMd5ValidationTime();
                    bool dueBySchedule = !startupChecked || DateTime.UtcNow - lastTime >= TimeSpan.FromDays(intervalDays);
                    if (dueBySchedule)
                    {
                        bool idleOnly = UserSettingsStore.GetMd5ValidationIdleOnly();
                        bool canRun = true;
                        if (idleOnly && startupChecked)
                        {
                            // 检查是否全屏游戏、忙碌或处于用户活跃操作状态
                            if (_gameModeController.IsCurrentlyInGameOrBusy() || !IsSystemIdle(30))
                            {
                                canRun = false;
                            }
                        }

                        if (canRun)
                        {
                            ExecuteMd5RulesValidation();
                            startupChecked = true;
                        }
                    }
                }
                else
                {
                    startupChecked = true;
                }

                // 周期性休眠 5 分钟后再次评估
                await Task.Delay(TimeSpan.FromMinutes(5), ct);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                SharedStorageHelper.LogDiagnostic("Service", $"Periodic MD5 validation loop error: {ex.Message}");
                await Task.Delay(TimeSpan.FromMinutes(5), ct);
            }
        }
    }

    private static int RunAsWindowsService()
    {
        if (!OperatingSystem.IsWindows())
        {
            Console.WriteLine("[StartupGuard.Service] SCM service mode running outside Windows; starting console loop.");
            return RunServiceCoreAsync().GetAwaiter().GetResult();
        }

        try
        {
            return StartupGuardNativeScmHost.StartServiceDispatcher(ServiceName);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[StartupGuard.Service] SCM dispatcher exception, falling back to console loop: {ex.Message}");
            return RunServiceCoreAsync().GetAwaiter().GetResult();
        }
    }
}

/// <summary>
/// 原生 Win32 SCM 调度宿主 (基于 StartServiceCtrlDispatcherW，零外部 NuGet 依赖，原生 AOT 兼容)
/// </summary>
internal static unsafe partial class StartupGuardNativeScmHost
{
    private const string AdvApi32Dll = "advapi32.dll";

    [StructLayout(LayoutKind.Sequential)]
    private struct SERVICE_TABLE_ENTRY
    {
        public nint lpServiceName;
        public nint lpServiceProc;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SERVICE_STATUS
    {
        public uint dwServiceType;
        public uint dwCurrentState;
        public uint dwControlsAccepted;
        public uint dwWin32ExitCode;
        public uint dwServiceSpecificExitCode;
        public uint dwCheckPoint;
        public uint dwWaitHint;
    }

    private const uint SERVICE_WIN32_OWN_PROCESS = 0x00000010;
    private const uint SERVICE_START_PENDING = 0x00000002;
    private const uint SERVICE_RUNNING = 0x00000004;
    private const uint SERVICE_STOP_PENDING = 0x00000003;
    private const uint SERVICE_STOPPED = 0x00000001;
    private const uint SERVICE_ACCEPT_STOP = 0x00000001;
    private const uint SERVICE_ACCEPT_SHUTDOWN = 0x00000004;

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate void ServiceMainDelegate(uint argc, nint argv);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate uint ServiceCtrlHandlerExDelegate(uint control, uint eventType, nint eventData, nint context);

    [LibraryImport(AdvApi32Dll, EntryPoint = "StartServiceCtrlDispatcherW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool StartServiceCtrlDispatcherW(nint lpServiceStartTable);

    [LibraryImport(AdvApi32Dll, EntryPoint = "RegisterServiceCtrlHandlerExW", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    private static partial nint RegisterServiceCtrlHandlerExW(string lpServiceName, nint lpHandlerProc, nint lpContext);

    [LibraryImport(AdvApi32Dll, EntryPoint = "SetServiceStatus", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetServiceStatus(nint hServiceStatus, in SERVICE_STATUS lpServiceStatus);

    private static CancellationTokenSource? _serviceCts;
    private static Task? _workerTask;
    private static nint _statusHandle;

    private static readonly ServiceMainDelegate _serviceMain = ServiceMain;
    private static readonly ServiceCtrlHandlerExDelegate _ctrlHandler = HandlerEx;

    public static int StartServiceDispatcher(string serviceName)
    {
        nint pServiceName = Marshal.StringToHGlobalUni(serviceName);
        nint pServiceProc = Marshal.GetFunctionPointerForDelegate(_serviceMain);

        try
        {
            SERVICE_TABLE_ENTRY* table = stackalloc SERVICE_TABLE_ENTRY[2];
            table[0].lpServiceName = pServiceName;
            table[0].lpServiceProc = pServiceProc;
            table[1].lpServiceName = 0;
            table[1].lpServiceProc = 0;

            if (!StartServiceCtrlDispatcherW((nint)table))
            {
                return Program.RunServiceCoreAsync().GetAwaiter().GetResult();
            }
            return 0;
        }
        finally
        {
            Marshal.FreeHGlobal(pServiceName);
        }
    }

    private static void ServiceMain(uint argc, nint argv)
    {
        _statusHandle = RegisterServiceCtrlHandlerExW("StartupGuardService", Marshal.GetFunctionPointerForDelegate(_ctrlHandler), 0);

        SERVICE_STATUS status = new()
        {
            dwServiceType = SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState = SERVICE_START_PENDING,
            dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN,
            dwWaitHint = 3000
        };
        SetServiceStatus(_statusHandle, in status);

        _serviceCts = new CancellationTokenSource();
        _workerTask = Task.Run(() => Program.RunServiceCoreAsync(_serviceCts.Token));

        status.dwCurrentState = SERVICE_RUNNING;
        SetServiceStatus(_statusHandle, in status);

        _workerTask.Wait();

        status.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(_statusHandle, in status);
    }

    private static uint HandlerEx(uint control, uint eventType, nint eventData, nint context)
    {
        if (control == 1 /* SERVICE_CONTROL_STOP */ || control == 5 /* SERVICE_CONTROL_SHUTDOWN */)
        {
            SERVICE_STATUS status = new()
            {
                dwServiceType = SERVICE_WIN32_OWN_PROCESS,
                dwCurrentState = SERVICE_STOP_PENDING,
                dwWaitHint = 3000
            };
            SetServiceStatus(_statusHandle, in status);
            _serviceCts?.Cancel();
            return 0;
        }
        return 0;
    }
}
