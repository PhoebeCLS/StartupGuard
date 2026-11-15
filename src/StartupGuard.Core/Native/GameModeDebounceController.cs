using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using StartupGuard.Core.Models;

namespace StartupGuard.Core.Native;

/// <summary>
/// Auto Game Mode 全屏/免打扰检测器与 45秒退出防抖状态机 (State Debounce Engine)
/// 基于 Win32 SHQueryUserNotificationState 零开销检测 QUNS_RUNNING_D3D_FULL_SCREEN / QUNS_BUSY
/// 当退出游戏时，严格执行 45 秒稳态防抖确认，防止用户临时 Alt+Tab 切屏弹出通知！
/// </summary>
public sealed partial class GameModeDebounceController : IDisposable
{
    private const string Shell32Dll = "shell32.dll";

    [LibraryImport(Shell32Dll)]
    private static partial int SHQueryUserNotificationState(out int pquns);

    // QUERY_USER_NOTIFICATION_STATE 枚举常量
    public const int QUNS_NOT_PRESENT = 1;
    public const int QUNS_BUSY = 2;
    public const int QUNS_RUNNING_D3D_FULL_SCREEN = 3;
    public const int QUNS_PRESENTATION_MODE = 4;
    public const int QUNS_ACCEPTS_NOTIFICATIONS = 5;
    public const int QUNS_QUIET_TIME = 6;
    public const int QUNS_APP = 7;

    /// <summary>退出游戏后的稳态防抖确认时长 (45秒)</summary>
    public static readonly TimeSpan ExitDebounceDuration = TimeSpan.FromSeconds(45);

    private readonly ConcurrentQueue<ConfidenceEvaluationResult> _pendingGameModeQueue = new();
    private readonly Action<IReadOnlyList<ConfidenceEvaluationResult>> _onFlushDeferredAudits;
    private readonly Func<int> _queryNotificationStateProvider;
    private readonly Func<DateTime> _utcNowProvider;
    private readonly Timer _monitorTimer;
    private readonly object _stateLock = new();

    private bool _autoGameModeEnabled = true;
    private bool _wasInFullScreenOrBusy;
    private DateTime? _leftFullScreenAtUtc;

    public GameModeDebounceController(
        Action<IReadOnlyList<ConfidenceEvaluationResult>> onFlushDeferredAudits,
        Func<int>? queryNotificationStateProvider = null,
        Func<DateTime>? utcNowProvider = null)
    {
        _onFlushDeferredAudits = onFlushDeferredAudits ?? (_ => { });
        _queryNotificationStateProvider = queryNotificationStateProvider ?? QueryNativeNotificationState;
        _utcNowProvider = utcNowProvider ?? (() => DateTime.UtcNow);

        TimeSpan period = (queryNotificationStateProvider is null && utcNowProvider is null)
            ? TimeSpan.FromSeconds(3)
            : Timeout.InfiniteTimeSpan;
        _monitorTimer = new Timer(OnStateCheckTick, null, period, period);
    }

    private static int QueryNativeNotificationState()
    {
        if (!OperatingSystem.IsWindows())
            return QUNS_ACCEPTS_NOTIFICATIONS;

        try
        {
            return SHQueryUserNotificationState(out int state) == 0 ? state : QUNS_ACCEPTS_NOTIFICATIONS;
        }
        catch
        {
            return QUNS_ACCEPTS_NOTIFICATIONS;
        }
    }

    private volatile bool _externalReportedInGame;
    private bool _isSession0Service;

    public bool IsSession0Service
    {
        get => _isSession0Service;
        set => _isSession0Service = value;
    }

    public bool ExternalReportedInGame
    {
        get => _externalReportedInGame;
        set
        {
            _externalReportedInGame = value;
            EvaluateStateTick();
        }
    }

    public bool IsAutoGameModeEnabled
    {
        get => _autoGameModeEnabled;
        set
        {
            bool old = _autoGameModeEnabled;
            _autoGameModeEnabled = value;
            if (old && !value)
            {
                // 用户显式关闭 Auto Game Mode：立即全量释放积压队列，绝不延时等待 45 秒！
                FlushAllDeferredAuditsImmediately();
            }
        }
    }

    public int PendingQueueCount => _pendingGameModeQueue.Count;

    public bool IsDebounceTimerActive
    {
        get
        {
            lock (_stateLock)
            {
                return _leftFullScreenAtUtc.HasValue;
            }
        }
    }

    /// <summary>
    /// 零开销判断当前是否处于全屏 3D 游戏
    /// 修复：在 Session 0 (服务) 下严禁调用 SHQueryUserNotificationState (会恒定返回 QUNS_BUSY 导致所有事件被误吞)；
    /// 必须以用户会话 (TrayHost) 上报的状态为准。
    /// 修复：严格仅将 QUNS_RUNNING_D3D_FULL_SCREEN 视作全屏游戏，防止虚拟机窗口最大化被误判为 Game Mode。
    /// </summary>
    public bool IsCurrentlyInGameOrBusy()
    {
        if (!_autoGameModeEnabled)
            return false;

        if (_isSession0Service)
        {
            return _externalReportedInGame;
        }

        int state = _queryNotificationStateProvider();
        return state is QUNS_RUNNING_D3D_FULL_SCREEN;
    }

    /// <summary>
    /// 立即清空并弹出所有积压的延后审核项
    /// </summary>
    public void FlushAllDeferredAuditsImmediately()
    {
        List<ConfidenceEvaluationResult>? batchToFlush = null;
        lock (_stateLock)
        {
            _wasInFullScreenOrBusy = false;
            _leftFullScreenAtUtc = null;
            if (!_pendingGameModeQueue.IsEmpty)
            {
                batchToFlush = new List<ConfidenceEvaluationResult>();
                while (_pendingGameModeQueue.TryDequeue(out var item))
                {
                    batchToFlush.Add(item);
                }
            }
        }

        if (batchToFlush is { Count: > 0 })
        {
            _onFlushDeferredAudits(batchToFlush);
        }
    }

    /// <summary>
    /// 在游戏全屏期间捕获到变更时：保持默认放行，推入延后审核队列，零弹窗零打扰
    /// </summary>
    public void EnqueueDeferredAuditItem(ConfidenceEvaluationResult item)
    {
        if (item is null)
            return;

        lock (_stateLock)
        {
            _pendingGameModeQueue.Enqueue(item);
            _wasInFullScreenOrBusy = true;
            _leftFullScreenAtUtc = null;
        }
    }

    private void OnStateCheckTick(object? state) => EvaluateStateTick();

    /// <summary>
    /// 执行单次全屏状态与 45 秒稳态退出防抖评估 (支持后台定时器与确定性单元测试直接驱动)
    /// </summary>
    public void EvaluateStateTick()
    {
        List<ConfidenceEvaluationResult>? batchToFlush = null;

        lock (_stateLock)
        {
            bool currentlyBusy = IsCurrentlyInGameOrBusy();

            if (currentlyBusy)
            {
                // 用户正处于全屏游戏或 45 秒内从 Alt+Tab 重返游戏：立即取消防抖倒计时！
                _wasInFullScreenOrBusy = true;
                _leftFullScreenAtUtc = null;
                return;
            }

            // 当前处于正常桌面状态 (QUNS_ACCEPTS_NOTIFICATIONS)
            if (_wasInFullScreenOrBusy && !_pendingGameModeQueue.IsEmpty)
            {
                DateTime nowUtc = _utcNowProvider();
                if (_leftFullScreenAtUtc is null)
                {
                    // 刚离开全屏：启动 45 秒防抖冷却计时器
                    _leftFullScreenAtUtc = nowUtc;
                    return;
                }

                if (nowUtc - _leftFullScreenAtUtc.Value >= ExitDebounceDuration)
                {
                    // 连续 45 秒保持非全屏状态 -> 确认用户已彻底退出游戏，批量推送延后审核通知！
                    _wasInFullScreenOrBusy = false;
                    _leftFullScreenAtUtc = null;

                    batchToFlush = new List<ConfidenceEvaluationResult>();
                    while (_pendingGameModeQueue.TryDequeue(out var item))
                    {
                        batchToFlush.Add(item);
                    }
                }
            }
        }

        if (batchToFlush is { Count: > 0 })
        {
            _onFlushDeferredAudits(batchToFlush);
        }
    }

    public void Dispose()
    {
        _monitorTimer.Dispose();
    }
}
