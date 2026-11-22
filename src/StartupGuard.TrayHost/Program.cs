using System.Diagnostics;
using System.Drawing;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using StartupGuard.Core.Configuration;
using StartupGuard.Core.Ipc;
using StartupGuard.Core.Models;
using StartupGuard.Core.Native;
using StartupGuard.Core.Storage;

namespace StartupGuard.TrayHost;

/// <summary>
/// StartupGuard.TrayHost.exe (轻量 Win32 托盘与拦截/状态对比弹窗宿主)
/// 常驻物理内存 < 5MB，弹窗响应延迟 < 50ms
/// 支持 6 大监控勾选开关、阻止通知、提示音与 Auto Game Mode，
/// 以及红绿状态演化 Diff 卡片与快速处置 SplitButton
/// </summary>
internal static partial class Program
{
    private const string PipeName = "StartupGuard_Control_Pipe";

    [LibraryImport("shell32.dll")]
    private static partial int SHQueryUserNotificationState(out int pquns);

    [LibraryImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool DestroyIcon(nint hIcon);

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool SetForegroundWindow(nint hWnd);

    public static bool CheckIsD3DFullScreenGame()
    {
        if (!OperatingSystem.IsWindows()) return false;
        try
        {
            if (SHQueryUserNotificationState(out int state) == 0)
            {
                return state == 3; // QUNS_RUNNING_D3D_FULL_SCREEN only
            }
        }
        catch { }
        return false;
    }

    public static string? GetCurrentUserSid()
    {
        if (!OperatingSystem.IsWindows()) return null;
        try
        {
            return System.Security.Principal.WindowsIdentity.GetCurrent().User?.Value;
        }
        catch
        {
            return null;
        }
    }

    public static bool IsSystemLightTheme()
        => UserSettingsStore.IsEffectiveLightTheme();

    [STAThread]
    public static void Main(string[] args)
    {
        // 启动后立即进入 EcoQoS 并压缩物理工作集至 < 5MB (WPF 资源延迟至首次弹窗时按需加载)
        ProcessQoSAndMemoryManager.EnterEcoEfficiencyMode();
        ProcessQoSAndMemoryManager.TrimWorkingSetMemory();

        ApplicationConfiguration.Initialize();
        Application.Run(new TrayApplicationContext());
    }

    internal static void EnsureWpfApplicationInitialized()
    {
        if (System.Windows.Application.Current != null)
            return;

        var wpfApp = new System.Windows.Application { ShutdownMode = System.Windows.ShutdownMode.OnExplicitShutdown };
        try
        {
            wpfApp.Resources.MergedDictionaries.Add(new Wpf.Ui.Markup.ThemesDictionary
            {
                Theme = IsSystemLightTheme() ? Wpf.Ui.Appearance.ApplicationTheme.Light : Wpf.Ui.Appearance.ApplicationTheme.Dark
            });
            wpfApp.Resources.MergedDictionaries.Add(new Wpf.Ui.Markup.ControlsDictionary());
            wpfApp.Resources.MergedDictionaries.Add(new System.Windows.ResourceDictionary
            {
                Source = new Uri("pack://application:,,,/Themes/FluentSharedStyles.xaml", UriKind.Absolute)
            });
        }
        catch { }
    }
}

/// <summary>
/// 托盘主应用程序上下文，管理 NotifyIcon、右键菜单、IPC 管道客户端与 45s Game Mode 防抖
/// </summary>
internal sealed class TrayApplicationContext : ApplicationContext
{
    private const string PipeName = "StartupGuard_Control_Pipe";
    private static readonly SemaphoreSlim _decisionSendGate = new(1, 1);

    private readonly NotifyIcon _notifyIcon;
    private readonly ContextMenuStrip _contextMenu;
    private readonly CancellationTokenSource _cts = new();

    private bool _monStartup = true;
    private bool _monService = true;
    private bool _monDriver = true;
    private bool _monTask = true;
    private bool _monContextMenu = true;
    private bool _monPolicy = true;
    private readonly bool _enableSound = false;
    private readonly bool _autoGameMode = true;
    private volatile string _lastSentTogglesSignature = string.Empty;
    private string _cachedUserSid = string.Empty;
    private DateTime _lastGameCheckUtc = DateTime.MinValue;
    private bool _cachedInGame;
    private DateTime _lastTogglesCheckUtc = DateTime.MinValue;

    private readonly ToolStripMenuItem _itemStartup;
    private readonly ToolStripMenuItem _itemService;
    private readonly ToolStripMenuItem _itemDriver;
    private readonly ToolStripMenuItem _itemTask;
    private readonly ToolStripMenuItem _itemContextMenu;
    private readonly ToolStripMenuItem _itemPolicy;
    private readonly ToolStripMenuItem _itemExit;

    private readonly System.Collections.Concurrent.ConcurrentQueue<(string Title, string Message, ToolTipIcon Icon, bool PlayErrorSound)> _balloonQueue = new();
    private readonly SemaphoreSlim _balloonSignal = new(0);
    private readonly GameModeDebounceController _gameModeController;
    private readonly SynchronizationContext? _syncContext;
    private InterceptionDiffDialogWindow? _currentDialog;
    private bool _lastMenuIsLight;

    public TrayApplicationContext()
    {
        _syncContext = SynchronizationContext.Current ?? new WindowsFormsSynchronizationContext();

        // 1. 初始化 45s Auto Game Mode 稳态防抖控制器
        _gameModeController = new GameModeDebounceController(OnFlushDeferredGameModeBatch);

        // 2. 构建现代视觉轻量原生右键菜单 (纯 GDI+ 自定义渲染，深浅主题自适应，零 WPF 驻留开销)
        bool isLight = Program.IsSystemLightTheme();
        _lastMenuIsLight = isLight;
        _contextMenu = new ContextMenuStrip
        {
            ShowCheckMargin = true,
            ShowImageMargin = false,
            DropShadowEnabled = true,
            BackColor = isLight ? Color.FromArgb(0xFC, 0xFC, 0xFC) : Color.FromArgb(0x2B, 0x2B, 0x2E),
            ForeColor = isLight ? Color.FromArgb(0x1E, 0x1E, 0x1E) : Color.FromArgb(0xF3, 0xF3, 0xF3),
            Font = new Font("Microsoft YaHei UI", 9.2F),
            Padding = new Padding(6, 6, 6, 6),
            Renderer = new ModernTrayMenuRenderer(isLight)
        };

        _itemStartup = CreateCheckItem("“启动”项监视", _monStartup, (v) => { _monStartup = v; SendTogglesUpdate(); });
        _itemService = CreateCheckItem("“服务”项监视", _monService, (v) => { _monService = v; SendTogglesUpdate(); });
        _itemDriver = CreateCheckItem("“驱动”自启监视", _monDriver, (v) => { _monDriver = v; SendTogglesUpdate(); });
        _itemTask = CreateCheckItem("“任务计划程序”监视", _monTask, (v) => { _monTask = v; SendTogglesUpdate(); });
        _itemContextMenu = CreateCheckItem("“上下文菜单”监视", _monContextMenu, (v) => { _monContextMenu = v; SendTogglesUpdate(); });
        _itemPolicy = CreateCheckItem("Windows策略监视", _monPolicy, (v) => { _monPolicy = v; SendTogglesUpdate(); });

        _contextMenu.Items.Add(_itemStartup);
        _contextMenu.Items.Add(_itemService);
        _contextMenu.Items.Add(_itemDriver);
        _contextMenu.Items.Add(_itemTask);
        _contextMenu.Items.Add(_itemContextMenu);
        _contextMenu.Items.Add(_itemPolicy);
        _contextMenu.Items.Add(new ToolStripSeparator());

        var itemSettings = new ToolStripMenuItem("设置") { Padding = new Padding(2, 3, 6, 3) };
        itemSettings.Click += (_, _) => LaunchMainRuleManagerApp("--page=PageSettings");
        _contextMenu.Items.Add(itemSettings);

        var itemOpenApp = new ToolStripMenuItem("打开规则管理面板...") { Padding = new Padding(2, 3, 6, 3) };
        itemOpenApp.Click += (_, _) => LaunchMainRuleManagerApp();
        _contextMenu.Items.Add(itemOpenApp);

        _itemExit = new ToolStripMenuItem("退出") { Padding = new Padding(2, 3, 6, 3) };
        _itemExit.Click += (_, _) => ExitApplication();
        _contextMenu.Items.Add(_itemExit);
        ApplyContextMenuTheme(isLight, force: true);

        // 3. 构建 Shell_NotifyIconW 托盘图标（Win11 托盘及折叠区右键采用 MouseUp + SetForegroundWindow 显式弹出）
        _notifyIcon = new NotifyIcon
        {
            Text = "StartupGuard 守护已启用",
            Icon = CreateDefaultShieldIcon(),
            Visible = true
        };
        _notifyIcon.MouseUp += (_, e) =>
        {
            if (e.Button == MouseButtons.Right)
            {
                ShowTrayContextMenuAtCursor();
            }
        };
        _notifyIcon.DoubleClick += (_, _) => LaunchMainRuleManagerApp();

        // 4. 启动后台 Named Pipe IPC 客户端循环与通知队列有序播报
        Task.Run(() => RunIpcClientLoopAsync(_cts.Token));
        Task.Run(() => RunNotificationPacingLoopAsync(_cts.Token));
    }

    private void ShowTrayContextMenuAtCursor()
    {
        try
        {
            ApplyContextMenuTheme(Program.IsSystemLightTheme());
            nint hwnd = _contextMenu.Handle;
            if (hwnd != 0)
            {
                Program.SetForegroundWindow(hwnd);
            }
            _contextMenu.Show(Cursor.Position);
            if (_contextMenu.Handle != 0)
            {
                Program.SetForegroundWindow(_contextMenu.Handle);
            }
        }
        catch { }
    }

    private void ApplyContextMenuTheme(bool isLight, bool force = false)
    {
        if (!force && _lastMenuIsLight == isLight)
            return;

        _lastMenuIsLight = isLight;
        Color backColor = isLight ? Color.FromArgb(0xFC, 0xFC, 0xFC) : Color.FromArgb(0x2B, 0x2B, 0x2E);
        Color foreColor = isLight ? Color.FromArgb(0x1E, 0x1E, 0x1E) : Color.FromArgb(0xF3, 0xF3, 0xF3);

        _contextMenu.BackColor = backColor;
        _contextMenu.ForeColor = foreColor;
        _contextMenu.Renderer = new ModernTrayMenuRenderer(isLight);

        foreach (var item in _contextMenu.Items.OfType<ToolStripMenuItem>())
        {
            item.ForeColor = foreColor;
        }
    }

    private ToolStripMenuItem CreateCheckItem(string text, bool initialCheck, Action<bool> onToggled)
    {
        var item = new ToolStripMenuItem(text)
        {
            Checked = initialCheck,
            CheckOnClick = true,
            Padding = new Padding(6, 5, 12, 5)
        };
        item.CheckedChanged += (_, _) => onToggled(item.Checked);
        return item;
    }

    private static Icon CreateDefaultShieldIcon()
    {
        try
        {
            string icoPath = Path.Combine(AppContext.BaseDirectory, "Assets", "app.ico");
            if (!File.Exists(icoPath))
                icoPath = Path.Combine(AppContext.BaseDirectory, "app.ico");
            if (File.Exists(icoPath))
            {
                return new Icon(icoPath, 16, 16);
            }
        }
        catch { }

        // 动态生成原生 16x16 守护盾牌图标 (零外部资源文件依赖兜底)
        using var bmp = new Bitmap(16, 16);
        using (var g = Graphics.FromImage(bmp))
        {
            g.Clear(Color.Transparent);
            using var brush = new SolidBrush(Color.FromArgb(0x00, 0x78, 0xD4));
            g.FillPolygon(brush, [
                new Point(8, 1),
                new Point(14, 3),
                new Point(14, 9),
                new Point(8, 15),
                new Point(2, 9),
                new Point(2, 3)
            ]);
            using var innerBrush = new SolidBrush(Color.White);
            g.FillPolygon(innerBrush, [
                new Point(8, 4),
                new Point(11, 5),
                new Point(11, 8),
                new Point(8, 12),
                new Point(5, 8),
                new Point(5, 5)
            ]);
        }
        nint hIcon = bmp.GetHicon();
        try
        {
            return (Icon)Icon.FromHandle(hIcon).Clone();
        }
        finally
        {
            Program.DestroyIcon(hIcon);
        }
    }

    private MonitorTogglesPayload BuildCurrentTogglesPayload() => new()
    {
        MonitorStartup = _monStartup,
        MonitorService = _monService,
        MonitorDriver = _monDriver,
        MonitorScheduledTask = _monTask,
        MonitorContextMenu = _monContextMenu,
        MonitorWindowsPolicy = _monPolicy,
        BlockNotifications = UserSettingsStore.GetRuleHitNotificationsEnabled() || UserSettingsStore.GetContextMenuNotificationsEnabled(),
        EnableSound = _enableSound,
        AutoGameMode = _autoGameMode,
        ContextMenuPromptMode = UserSettingsStore.GetContextMenuPromptMode()
    };

    private static string BuildTogglesSignature(MonitorTogglesPayload payload) =>
        $"{payload.MonitorStartup}|{payload.MonitorService}|{payload.MonitorDriver}|{payload.MonitorScheduledTask}|{payload.MonitorContextMenu}|{payload.MonitorWindowsPolicy}|{payload.BlockNotifications}|{payload.EnableSound}|{payload.AutoGameMode}|{payload.ContextMenuPromptMode}";

    private void SendTogglesUpdate()
    {
        var payload = BuildCurrentTogglesPayload();
        string sig = BuildTogglesSignature(payload);
        _lastSentTogglesSignature = sig;

        Task.Run(async () =>
        {
            try
            {
                await using var client = new NamedPipeClientStream(".", PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
                await client.ConnectAsync(300);
                byte[] data = BinaryPipeSerializer.SerializeMonitorToggles(payload);
                var hdr = PipeMessageHeader.Create(PipeMessageType.UpdateMonitorToggles, (uint)data.Length, 0);
                byte[] hdrBytes = new byte[64];
                BinaryPipeSerializer.WriteHeader(hdrBytes, in hdr);
                await client.WriteAsync(hdrBytes);
                await client.WriteAsync(data);
                await client.FlushAsync();
                SharedStorageHelper.LogDiagnostic("TrayHost",
                    $"SendTogglesUpdate sent: promptMode={payload.ContextMenuPromptMode}, ctx={payload.MonitorContextMenu}, startup={payload.MonitorStartup}");
            }
            catch (Exception ex)
            {
                _lastSentTogglesSignature = string.Empty;
                SharedStorageHelper.LogDiagnostic("TrayHost", $"SendTogglesUpdate failed: {ex.Message}");
            }
        });
    }

    private void SendSessionReportUpdate()
    {
        Task.Run(async () =>
        {
            try
            {
                await using var client = new NamedPipeClientStream(".", PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
                await client.ConnectAsync(300);
                bool inGame = _autoGameMode && Program.CheckIsD3DFullScreenGame();
                string userSid = Program.GetCurrentUserSid() ?? string.Empty;
                var report = new UserSessionReportPayload
                {
                    InGame = inGame,
                    UserSid = userSid
                };
                byte[] reportBytes = BinaryPipeSerializer.SerializeUserSessionReport(report);
                var hdr = PipeMessageHeader.Create(PipeMessageType.UserSessionReport, (uint)reportBytes.Length, 0);
                byte[] hdrBytes = new byte[64];
                BinaryPipeSerializer.WriteHeader(hdrBytes, in hdr);
                await client.WriteAsync(hdrBytes);
                await client.WriteAsync(reportBytes);
                await client.FlushAsync();
            }
            catch { }
        });
    }

    private async Task RunIpcClientLoopAsync(CancellationToken ct)
    {
        byte[] hdrBuf = new byte[64];

        while (!ct.IsCancellationRequested)
        {
            bool receivedPayload = false;
            try
            {
                await using var pipeClient = new NamedPipeClientStream(".", PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
                await pipeClient.ConnectAsync(1000, ct);

                var nowUtc = DateTime.UtcNow;
                if (string.IsNullOrEmpty(_cachedUserSid))
                {
                    _cachedUserSid = Program.GetCurrentUserSid() ?? string.Empty;
                }

                if (_autoGameMode && (nowUtc - _lastGameCheckUtc).TotalSeconds >= 3.0)
                {
                    _cachedInGame = Program.CheckIsD3DFullScreenGame();
                    _lastGameCheckUtc = nowUtc;
                }

                // 发送用户态会话状态上报 (含节流后的 3D 全屏检测与缓存用户 SID) 并拉取待审核弹窗
                var report = new UserSessionReportPayload
                {
                    InGame = _autoGameMode && _cachedInGame,
                    UserSid = _cachedUserSid
                };
                byte[] reportBytes = BinaryPipeSerializer.SerializeUserSessionReport(report);
                var pingHdr = PipeMessageHeader.Create(PipeMessageType.UserSessionReport, (uint)reportBytes.Length, 0);
                BinaryPipeSerializer.WriteHeader(hdrBuf, in pingHdr);
                await pipeClient.WriteAsync(hdrBuf, ct);
                await pipeClient.WriteAsync(reportBytes, ct);
                await pipeClient.FlushAsync(ct);

                // 仅在首次建立连接或每 15 秒检查一次策略/开关变化，避免高频轮询重复读注册表
                if (string.IsNullOrEmpty(_lastSentTogglesSignature) ||
                    (nowUtc - _lastTogglesCheckUtc).TotalSeconds >= 15.0)
                {
                    _lastTogglesCheckUtc = nowUtc;
                    string currentSig = BuildTogglesSignature(BuildCurrentTogglesPayload());
                    if (!string.Equals(currentSig, _lastSentTogglesSignature, StringComparison.Ordinal))
                    {
                        SendTogglesUpdate();
                    }
                }

                int read = await pipeClient.ReadAsync(hdrBuf.AsMemory(0, 64), ct);
                if (read == 64)
                {
                    var respHdr = BinaryPipeSerializer.ReadHeader(hdrBuf);
                    if (respHdr.IsValid && respHdr.PayloadLength > 0 && respHdr.PayloadLength <= 65536)
                    {
                        receivedPayload = true;
                        byte[] payload = new byte[respHdr.PayloadLength];
                        await pipeClient.ReadExactlyAsync(payload, ct);

                        if (respHdr.MessageType == PipeMessageType.InterceptionAlertRequest)
                        {
                            var eval = BinaryPipeSerializer.DeserializeAlert(payload, out ulong corrId);
                            OnInterceptionAlertReceived(corrId, eval);
                        }
                        else if (respHdr.MessageType == PipeMessageType.RollbackFailureAlert)
                        {
                            string msg = System.Text.Encoding.UTF8.GetString(payload);
                            _balloonQueue.Enqueue(("StartupGuard 执行异常提醒", msg, ToolTipIcon.Error, PlayErrorSound: true));
                            try { _balloonSignal.Release(); } catch (ObjectDisposedException) { }
                        }
                        else if (respHdr.MessageType == PipeMessageType.BlockedItemNotification)
                        {
                            string raw = System.Text.Encoding.UTF8.GetString(payload);
                            bool isRuleHit = raw.StartsWith("[RULE]", StringComparison.Ordinal);
                            bool isCtxSilent = raw.StartsWith("[CTX]", StringComparison.Ordinal);
                            string cleanMsg = isRuleHit ? raw[6..] : (isCtxSilent ? raw[5..] : raw);

                            bool allowed = isRuleHit
                                ? UserSettingsStore.GetRuleHitNotificationsEnabled()
                                : (isCtxSilent
                                    ? UserSettingsStore.GetContextMenuNotificationsEnabled() && !UserSettingsStore.GetContextMenuPromptMode()
                                    : UserSettingsStore.GetBlockedNotificationsEnabled());

                            if (allowed && !string.IsNullOrWhiteSpace(cleanMsg))
                            {
                                _balloonQueue.Enqueue(("StartupGuard 已拦截", cleanMsg, ToolTipIcon.Info, PlayErrorSound: false));
                                try { _balloonSignal.Release(); } catch (ObjectDisposedException) { }
                            }
                        }
                        else if (respHdr.MessageType == PipeMessageType.GameModeBatchAuditNotify)
                        {
                            var batch = BinaryPipeSerializer.DeserializeBatchAlerts(payload, out _);
                            OnFlushDeferredGameModeBatch(batch);
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
                // 服务未启动或断开，重置已发送状态签名并等待 1000ms 重连
                _lastSentTogglesSignature = string.Empty;
                await Task.Delay(1000, ct);
                continue;
            }

            // 有待取消息时 50ms 连续拉取；空闲时降频至 1000ms 降低 CPU 与管道开销
            await Task.Delay(receivedPayload ? 50 : 1000, ct);
        }
    }

    private void OnInterceptionAlertReceived(ulong correlationId, ConfidenceEvaluationResult eval)
    {
        _syncContext?.Post(_ =>
        {
            if (NativeSecurityExtractor.IsWindowsEssentialOperatingSystemComponent(eval.Target))
            {
                // 系统底层核心必要组件直接豁免，静默放行建立基线
                SendUserDecisionResponse(new UserDecisionPayload
                {
                    CorrelationId = correlationId,
                    ChosenAction = InterceptionAction.Allow,
                    RememberRule = false,
                    ChosenRuleMode = RuleMatchMode.StrictCurrentVersion
                });
                return;
            }

            if (_enableSound)
            {
                try { System.Media.SystemSounds.Exclamation.Play(); } catch { }
            }

            // 1. 若当前拦截决策窗口正在显示，实时向其下方追加该项并提供批量勾选！
            SharedStorageHelper.LogDiagnostic("TrayHost",
                $"Alert UI dispatch: corrId={correlationId}, cat={eval.CurrentTarget.Category}, loc={eval.CurrentTarget.LocationKeyOrIdentifier}, appendToVisible={_currentDialog != null && _currentDialog.IsVisible}");
            if (_currentDialog != null && _currentDialog.IsVisible)
            {
                _currentDialog.AppendCapturedItem(correlationId, eval);
                if (_currentDialog.WindowState == System.Windows.WindowState.Minimized)
                    _currentDialog.WindowState = System.Windows.WindowState.Normal;
                _currentDialog.Topmost = true;
                _currentDialog.Activate();
                return;
            }

            // 2. 否则按需初始化 WPF 资源并展示弹窗
            Program.EnsureWpfApplicationInitialized();
            _currentDialog = new InterceptionDiffDialogWindow(correlationId, eval, SendUserDecisionBatch);

            _currentDialog.Closed += (_, _) =>
            {
                _currentDialog = null;
                ProcessQoSAndMemoryManager.TrimWorkingSetMemory();
            };

            _currentDialog.Topmost = true;
            _currentDialog.Show();
            _currentDialog.Activate();
        }, null);
    }

    private void OnFlushDeferredGameModeBatch(IReadOnlyList<ConfidenceEvaluationResult> batch)
    {
        if (batch.Count == 0)
            return;

        _syncContext?.Post(_ =>
        {
            _notifyIcon.ShowBalloonTip(
                5000,
                "StartupGuard 游戏免打扰汇总",
                $"全屏游戏期间捕获到 {batch.Count} 项自启或菜单变更，请勾选审核。",
                ToolTipIcon.Info);

            for (int i = 0; i < batch.Count; i++)
            {
                if (i == 0 && (_currentDialog == null || !_currentDialog.IsVisible))
                {
                    Program.EnsureWpfApplicationInitialized();
                    _currentDialog = new InterceptionDiffDialogWindow(0, batch[0], SendUserDecisionBatch);
                    _currentDialog.Closed += (_, _) =>
                    {
                        _currentDialog = null;
                        ProcessQoSAndMemoryManager.TrimWorkingSetMemory();
                    };
                    _currentDialog.Topmost = true;
                    _currentDialog.Show();
                    _currentDialog.Activate();
                }
                else if (_currentDialog != null && _currentDialog.IsVisible)
                {
                    _currentDialog.AppendCapturedItem(0, batch[i]);
                }
            }
        }, null);
    }

    private static void SendUserDecisionBatch(IEnumerable<UserDecisionPayload> decisions)
    {
        var snapshot = decisions.ToList();
        if (snapshot.Count == 0)
            return;

        // 单批次串行化投递至守护服务命名管道，防止多决策并发争抢管道触发超时回退与二次弹窗竞态
        Task.Run(async () =>
        {
            await _decisionSendGate.WaitAsync().ConfigureAwait(false);
            try
            {
                foreach (var decision in snapshot)
                {
                    await SendSingleDecisionWithFallbackAsync(decision).ConfigureAwait(false);
                }
            }
            finally
            {
                _decisionSendGate.Release();
            }
        });
    }

    private static void SendUserDecisionResponse(UserDecisionPayload decision)
        => SendUserDecisionBatch([decision]);

    private static async Task SendSingleDecisionWithFallbackAsync(UserDecisionPayload decision)
    {
        bool pipeSuccess = false;
        for (int attempt = 0; attempt < 2 && !pipeSuccess; attempt++)
        {
            try
            {
                await using var client = new NamedPipeClientStream(".", PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
                await client.ConnectAsync(2500).ConfigureAwait(false);
                byte[] data = BinaryPipeSerializer.SerializeDecision(decision);
                var hdr = PipeMessageHeader.Create(PipeMessageType.UserDecisionResponse, (uint)data.Length, decision.CorrelationId);
                byte[] hdrBytes = new byte[64];
                BinaryPipeSerializer.WriteHeader(hdrBytes, in hdr);
                await client.WriteAsync(hdrBytes).ConfigureAwait(false);
                await client.WriteAsync(data).ConfigureAwait(false);
                await client.FlushAsync().ConfigureAwait(false);
                pipeSuccess = true;
            }
            catch
            {
                pipeSuccess = false;
                if (attempt == 0)
                    await Task.Delay(120).ConfigureAwait(false);
            }
        }

        // 若后台守护服务尚未就绪或 IPC 超时，本地直接执行强权限回滚并即时写入 SQLite 审计日志！
        SharedStorageHelper.LogDiagnostic("TrayHost", $"SendUserDecisionResponse: pipeSuccess={pipeSuccess}, corrId={decision.CorrelationId}, action={decision.ChosenAction}, remember={decision.RememberRule}");

        if (!pipeSuccess)
        {
            try
            {
                bool isDismiss = decision.ChosenAction == InterceptionAction.DismissWithoutChange;
                bool effectiveRemember = decision.RememberRule && !isDismiss;

                if (decision.ChosenAction is not (InterceptionAction.Allow or InterceptionAction.DismissWithoutChange) &&
                    !string.IsNullOrEmpty(decision.LocationKey))
                {
                    BinaryPipeSerializer.NotifyServiceSuppressSelfMutation(
                        decision.LocationKey,
                        decision.Category,
                        decision.TargetBinaryPath ?? string.Empty,
                        12.0);
                    var target = NativeSecurityExtractor.BuildTargetProgramFeatures(
                        decision.Category,
                        decision.LocationKey,
                        decision.TargetBinaryPath ?? "",
                        displayName: decision.DisplayName);
                    PrivilegedRollbackEngine.ExecuteRollback(target, decision.ChosenAction, Program.GetCurrentUserSid());
                }

                string dbPath = SharedStorageHelper.GetSharedDatabasePath();
                using var repo = new SqliteRuleRepository(dbPath);

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

                string diagnosticText = isDismiss
                    ? "用户关闭弹窗或未勾选处置项，未修改系统或规则，可在日志中手动操作"
                    : (effectiveRemember ? "用户在拦截提示弹窗中选择阻止并沉淀永久规则" : "用户在拦截提示弹窗中做出的处置决策");

                repo.WriteAuditLog(
                    null,
                    decision.Category,
                    decision.TargetBinaryPath ?? "",
                    decision.LocationKey,
                    "Initial Intercept",
                    decision.ChosenAction.ToString(),
                    readableAction,
                    100.0,
                    diagnosticText);

                SharedStorageHelper.LogDiagnostic("TrayHost", $"Direct audit log written: {readableAction} for {decision.LocationKey}");

                if (effectiveRemember)
                {
                    var newRule = new RuleRecord
                    {
                        DisplayName = !string.IsNullOrEmpty(decision.DisplayName) ? decision.DisplayName : Path.GetFileNameWithoutExtension(decision.TargetBinaryPath ?? ""),
                        Category = decision.Category,
                        ActionType = decision.ChosenAction,
                        RuleMode = decision.ChosenRuleMode,
                        ConfidenceThreshold = 85.0f,
                        LocationKey = decision.LocationKey,
                        NormalizedPath = decision.TargetBinaryPath ?? "",
                        RawCommand = decision.TargetBinaryPath ?? ""
                    };
                    repo.InsertOrUpdateRule(newRule);
                }
            }
            catch (Exception ex)
            {
                SharedStorageHelper.LogDiagnostic("TrayHost", $"Direct rollback/audit error: {ex}");
            }
        }
    }

    private async Task RunNotificationPacingLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await _balloonSignal.WaitAsync(ct);
                if (_balloonQueue.TryDequeue(out var item))
                {
                    _syncContext?.Post(_ =>
                    {
                        if (item.PlayErrorSound)
                        {
                            try { System.Media.SystemSounds.Hand.Play(); } catch { }
                        }
                        else if (_enableSound)
                        {
                            try { System.Media.SystemSounds.Asterisk.Play(); } catch { }
                        }
                        _notifyIcon.ShowBalloonTip(4000, item.Title, item.Message, item.Icon);
                    }, null);

                    // 安装大量软件时延迟按序弹出通知，防止瞬间堆叠覆盖丢失
                    await Task.Delay(2200, ct);
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (ObjectDisposedException)
            {
                break;
            }
            catch
            {
                await Task.Delay(500, ct);
            }
        }
    }

    private static void LaunchMainRuleManagerApp(string? arguments = null)
    {
        string appExe = Path.Combine(AppContext.BaseDirectory, "StartupGuard.App.exe");
        if (File.Exists(appExe))
        {
            using var proc = Process.Start(new ProcessStartInfo
            {
                FileName = appExe,
                Arguments = arguments ?? string.Empty,
                UseShellExecute = true
            });
        }
    }

    private void ExitApplication()
    {
        _cts.Cancel();
        _notifyIcon.Visible = false;
        _notifyIcon.Dispose();
        _contextMenu.Dispose();
        try { _balloonSignal.Dispose(); } catch { }

        // 用户在托盘点击“退出”时，完整关闭后台监控服务及相关子进程
        try
        {
            using var scProc = Process.Start(new ProcessStartInfo
            {
                FileName = "sc.exe",
                Arguments = "stop StartupGuardService",
                CreateNoWindow = true,
                UseShellExecute = false
            });
            scProc?.WaitForExit(3000);
        }
        catch { }

        foreach (string procName in new[] { "StartupGuard.App", "StartupGuard.ProbeHost", "StartupGuard.Service" })
        {
            try
            {
                foreach (var p in Process.GetProcessesByName(procName))
                {
                    try { p.Kill(entireProcessTree: true); } catch { }
                    finally { p.Dispose(); }
                }
            }
            catch { }
        }

        try
        {
            _currentDialog?.Dispatcher.Invoke(() => _currentDialog.Close());
            System.Windows.Application.Current?.Dispatcher.Invoke(() => System.Windows.Application.Current.Shutdown());
        }
        catch { }
        ExitThread();
    }
}

/// <summary>
/// 轻量原生 GDI+ 现代托盘右键菜单渲染器（圆角悬停高光 + 平滑对勾 + 深浅主题自适应）
/// </summary>
internal sealed class ModernTrayMenuRenderer : ToolStripProfessionalRenderer
{
    private readonly bool _isLight;

    public ModernTrayMenuRenderer(bool isLight) : base(new ModernColorTable(isLight))
    {
        _isLight = isLight;
        RoundedEdges = true;
    }

    protected override void OnRenderToolStripBackground(ToolStripRenderEventArgs e)
    {
        var rect = new Rectangle(Point.Empty, e.AffectedBounds.Size);
        using var bgBrush = new SolidBrush(_isLight ? Color.FromArgb(0xFC, 0xFC, 0xFC) : Color.FromArgb(0x2B, 0x2B, 0x2E));
        e.Graphics.FillRectangle(bgBrush, rect);
        using var borderPen = new Pen(_isLight ? Color.FromArgb(0xE0, 0xE0, 0xE0) : Color.FromArgb(0x45, 0x45, 0x49));
        e.Graphics.DrawRectangle(borderPen, 0, 0, rect.Width - 1, rect.Height - 1);
    }

    protected override void OnRenderMenuItemBackground(ToolStripItemRenderEventArgs e)
    {
        if (!e.Item.Selected) return;
        e.Graphics.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
        var rect = new Rectangle(4, 2, e.Item.Width - 8, e.Item.Height - 4);
        using var path = CreateRoundedRect(rect, 5);
        using var hoverBrush = new SolidBrush(_isLight ? Color.FromArgb(0xEF, 0xEF, 0xF2) : Color.FromArgb(0x3D, 0x3D, 0x42));
        e.Graphics.FillPath(hoverBrush, path);
    }

    protected override void OnRenderSeparator(ToolStripSeparatorRenderEventArgs e)
    {
        int y = e.Item.Height / 2;
        using var pen = new Pen(_isLight ? Color.FromArgb(0xE6, 0xE6, 0xE8) : Color.FromArgb(0x40, 0x40, 0x44));
        e.Graphics.DrawLine(pen, 10, y, e.Item.Width - 10, y);
    }

    protected override void OnRenderItemCheck(ToolStripItemImageRenderEventArgs e)
    {
        e.Graphics.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
        float cy = e.Item.Height / 2f;
        using var checkPen = new Pen(_isLight ? Color.FromArgb(0x1E, 0x1E, 0x1E) : Color.FromArgb(0xF3, 0xF3, 0xF3), 1.8f)
        {
            StartCap = System.Drawing.Drawing2D.LineCap.Round,
            EndCap = System.Drawing.Drawing2D.LineCap.Round,
            LineJoin = System.Drawing.Drawing2D.LineJoin.Round
        };
        e.Graphics.DrawLines(checkPen, [
            new PointF(11.5f, cy + 0.5f),
            new PointF(14.5f, cy + 3.5f),
            new PointF(20.0f, cy - 3.0f)
        ]);
    }

    private static System.Drawing.Drawing2D.GraphicsPath CreateRoundedRect(Rectangle rect, int radius)
    {
        var path = new System.Drawing.Drawing2D.GraphicsPath();
        int d = radius * 2;
        path.AddArc(rect.X, rect.Y, d, d, 180, 90);
        path.AddArc(rect.Right - d, rect.Y, d, d, 270, 90);
        path.AddArc(rect.Right - d, rect.Bottom - d, d, d, 0, 90);
        path.AddArc(rect.X, rect.Bottom - d, d, d, 90, 90);
        path.CloseFigure();
        return path;
    }

    private sealed class ModernColorTable(bool isLight) : ProfessionalColorTable
    {
        public override Color MenuBorder => isLight ? Color.FromArgb(0xE0, 0xE0, 0xE0) : Color.FromArgb(0x45, 0x45, 0x49);
        public override Color MenuStripGradientBegin => isLight ? Color.FromArgb(0xFC, 0xFC, 0xFC) : Color.FromArgb(0x2B, 0x2B, 0x2E);
        public override Color MenuStripGradientEnd => MenuStripGradientBegin;
        public override Color ToolStripDropDownBackground => MenuStripGradientBegin;
        public override Color ImageMarginGradientBegin => MenuStripGradientBegin;
        public override Color ImageMarginGradientMiddle => MenuStripGradientBegin;
        public override Color ImageMarginGradientEnd => MenuStripGradientBegin;
    }
}
