using StartupGuard.Core.Models;
using StartupGuard.Core.Native;
using StartupGuard.Tests.TestHelpers;

namespace StartupGuard.Tests.Tier1_FeatureCoverage;

public class GameModeDebounceTests
{
    [Fact]
    public void IsCurrentlyInGameOrBusy_RecognizesFullScreenAndBusyStates()
    {
        int currentState = GameModeDebounceController.QUNS_RUNNING_D3D_FULL_SCREEN;
        using var controller = new GameModeDebounceController(
            onFlushDeferredAudits: _ => { },
            queryNotificationStateProvider: () => currentState);

        Assert.True(controller.IsCurrentlyInGameOrBusy());

        // 修复：普通窗口繁忙/最大化 (QUNS_BUSY) 不应误触游戏模式 (根治虚拟机误判)
        currentState = GameModeDebounceController.QUNS_BUSY;
        Assert.False(controller.IsCurrentlyInGameOrBusy());

        currentState = GameModeDebounceController.QUNS_ACCEPTS_NOTIFICATIONS;
        Assert.False(controller.IsCurrentlyInGameOrBusy());

        // Session 0 隔离测试
        controller.IsSession0Service = true;
        controller.ExternalReportedInGame = true;
        Assert.True(controller.IsCurrentlyInGameOrBusy());
        controller.ExternalReportedInGame = false;
        Assert.False(controller.IsCurrentlyInGameOrBusy());
    }

    [Fact]
    public void IsCurrentlyInGameOrBusy_WhenDisabled_AlwaysReturnsFalse()
    {
        using var controller = new GameModeDebounceController(
            onFlushDeferredAudits: _ => { },
            queryNotificationStateProvider: () => GameModeDebounceController.QUNS_RUNNING_D3D_FULL_SCREEN);

        controller.IsAutoGameModeEnabled = false;
        Assert.False(controller.IsCurrentlyInGameOrBusy());
    }

    [Fact]
    public void EnqueueDeferredAuditItem_InGame_SilentlyEnqueuesWithoutFlushing()
    {
        var flushedBatches = new List<IReadOnlyList<ConfidenceEvaluationResult>>();
        int state = GameModeDebounceController.QUNS_RUNNING_D3D_FULL_SCREEN;

        using var controller = new GameModeDebounceController(
            onFlushDeferredAudits: batch => flushedBatches.Add(batch),
            queryNotificationStateProvider: () => state);

        var sample = new ConfidenceEvaluationResult
        {
            FinalScore = 100.0,
            CurrentTarget = TestModelHelpers.CreateSampleTarget(),
            Severity = DiagnosticSeverity.LikelySameSoftware,
            DiagnosticOpinion = "Test"
        };

        controller.EnqueueDeferredAuditItem(sample);
        Assert.Equal(1, controller.PendingQueueCount);

        // Tick while still in game
        controller.EvaluateStateTick();
        Assert.Empty(flushedBatches);
        Assert.Equal(1, controller.PendingQueueCount);
    }

    [Fact]
    public void DebounceStateMachine_AltTabWithin45Seconds_CancelsDebounceTimer()
    {
        var flushedBatches = new List<IReadOnlyList<ConfidenceEvaluationResult>>();
        int state = GameModeDebounceController.QUNS_RUNNING_D3D_FULL_SCREEN;
        var currentTime = new DateTime(2026, 11, 9, 12, 0, 0, DateTimeKind.Utc);

        using var controller = new GameModeDebounceController(
            onFlushDeferredAudits: batch => flushedBatches.Add(batch),
            queryNotificationStateProvider: () => state,
            utcNowProvider: () => currentTime);

        var item = new ConfidenceEvaluationResult
        {
            FinalScore = 80.0,
            CurrentTarget = TestModelHelpers.CreateSampleTarget(),
            Severity = DiagnosticSeverity.LikelySameSoftware,
            DiagnosticOpinion = "Deferred item"
        };
        controller.EnqueueDeferredAuditItem(item);

        // User temporarily Alt+Tabs to desktop at t = 0s
        state = GameModeDebounceController.QUNS_ACCEPTS_NOTIFICATIONS;
        controller.EvaluateStateTick();
        Assert.True(controller.IsDebounceTimerActive);
        Assert.Empty(flushedBatches);

        // At t = 20s (less than 45s), user returns to fullscreen game!
        currentTime = currentTime.AddSeconds(20);
        state = GameModeDebounceController.QUNS_RUNNING_D3D_FULL_SCREEN;
        controller.EvaluateStateTick();

        // Timer must be cancelled!
        Assert.False(controller.IsDebounceTimerActive);
        Assert.Empty(flushedBatches);
        Assert.Equal(1, controller.PendingQueueCount);
    }

    [Fact]
    public void DebounceStateMachine_Continuous45SecondsNonBusy_FlushesAllDeferredItems()
    {
        var flushedBatches = new List<IReadOnlyList<ConfidenceEvaluationResult>>();
        int state = GameModeDebounceController.QUNS_RUNNING_D3D_FULL_SCREEN;
        var t0 = new DateTime(2026, 11, 9, 12, 0, 0, DateTimeKind.Utc);
        var currentTime = t0;

        using var controller = new GameModeDebounceController(
            onFlushDeferredAudits: batch => flushedBatches.Add(batch),
            queryNotificationStateProvider: () => state,
            utcNowProvider: () => currentTime);

        controller.EnqueueDeferredAuditItem(new ConfidenceEvaluationResult
        {
            FinalScore = 90.0,
            CurrentTarget = TestModelHelpers.CreateSampleTarget(),
            Severity = DiagnosticSeverity.LikelySameSoftware,
            DiagnosticOpinion = "Item 1"
        });
        controller.EnqueueDeferredAuditItem(new ConfidenceEvaluationResult
        {
            FinalScore = 75.0,
            CurrentTarget = TestModelHelpers.CreateSampleTarget(),
            Severity = DiagnosticSeverity.SuspiciousDeviation,
            DiagnosticOpinion = "Item 2"
        });

        // User permanently exits game at t = 0s
        state = GameModeDebounceController.QUNS_ACCEPTS_NOTIFICATIONS;
        controller.EvaluateStateTick();
        Assert.True(controller.IsDebounceTimerActive);
        Assert.Empty(flushedBatches);

        // At t = 44.9s, still waiting
        currentTime = t0.AddSeconds(44.9);
        controller.EvaluateStateTick();
        Assert.Empty(flushedBatches);

        // At t = 45.0s, debounce completes!
        currentTime = t0.AddSeconds(45.0);
        controller.EvaluateStateTick();

        Assert.Single(flushedBatches);
        Assert.Equal(2, flushedBatches[0].Count);
        Assert.Equal(0, controller.PendingQueueCount);
        Assert.False(controller.IsDebounceTimerActive);
    }

    [Fact]
    public void DebounceStateMachine_ExactBoundary44_9sVs45_0s()
    {
        var flushedBatches = new List<IReadOnlyList<ConfidenceEvaluationResult>>();
        int state = GameModeDebounceController.QUNS_RUNNING_D3D_FULL_SCREEN;
        var t0 = new DateTime(2026, 11, 9, 15, 0, 0, DateTimeKind.Utc);
        var t = t0;

        using var controller = new GameModeDebounceController(
            onFlushDeferredAudits: batch => flushedBatches.Add(batch),
            queryNotificationStateProvider: () => state,
            utcNowProvider: () => t);

        controller.EnqueueDeferredAuditItem(new ConfidenceEvaluationResult
        {
            FinalScore = 100.0,
            CurrentTarget = TestModelHelpers.CreateSampleTarget(),
            Severity = DiagnosticSeverity.LikelySameSoftware,
            DiagnosticOpinion = "Boundary item"
        });

        // Exit game -> normal desktop
        state = GameModeDebounceController.QUNS_ACCEPTS_NOTIFICATIONS;
        controller.EvaluateStateTick();

        // Step to 44.999s
        t = t0.AddSeconds(44.999);
        controller.EvaluateStateTick();
        Assert.Empty(flushedBatches);

        // Step to exactly 45.000s
        t = t0.AddSeconds(45.0);
        controller.EvaluateStateTick();
        Assert.Single(flushedBatches);
    }
}
