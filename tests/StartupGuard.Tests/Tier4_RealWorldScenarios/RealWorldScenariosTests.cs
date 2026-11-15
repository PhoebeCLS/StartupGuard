using StartupGuard.Core.Models;
using StartupGuard.Core.Native;
using StartupGuard.Core.Scoring;
using StartupGuard.Core.Storage;
using StartupGuard.Tests.TestHelpers;

namespace StartupGuard.Tests.Tier4_RealWorldScenarios;

public class RealWorldScenariosTests : IDisposable
{
    private readonly string _tempDbPath;
    private readonly SqliteRuleRepository _repository;
    private readonly ConfidenceScoringEngine _engine;

    public RealWorldScenariosTests()
    {
        _repository = TestModelHelpers.CreateTemporarySqliteRepository(out _tempDbPath);
        _engine = new ConfidenceScoringEngine(_repository);
    }

    public void Dispose()
    {
        _repository.Dispose();
        try { if (File.Exists(_tempDbPath)) File.Delete(_tempDbPath); } catch { }
    }

    [Fact]
    public void Scenario1_OneDriveVersionUpgrade_SilentlyMatchesAt100Percent()
    {
        // Historical Rule: OneDrive version 26.198.1011.0006
        string oldPath = @"C:\Users\DemoUser\AppData\Local\Microsoft\OneDrive\26.198.1011.0006\FileSyncShell64.dll";
        var rule = TestModelHelpers.CreateSampleRule(
            name: "OneDrive Sync Shell Extension",
            category: MonitorCategory.ClassicContextMenu,
            normPath: PathNormalizerAndSimilarity.NormalizeProgramPath(oldPath),
            signer: "Microsoft Corporation",
            rootThumb: "3B1FE8794821CDA9821734289417823901489123",
            origFile: "FileSyncShell64.dll",
            prodName: "Microsoft OneDrive",
            location: @"Software\Classes\CLSID\{CB3D0F55-BC2C-480A-8534-EE63886D2D05}\InprocServer32",
            args: string.Empty,
            md5: "OLD_MD5_111111111111111111111111");
        rule.RuleId = _repository.InsertOrUpdateRule(rule);

        // New Version: 26.205.1102.0001
        string newPath = @"C:\Users\DemoUser\AppData\Local\Microsoft\OneDrive\26.205.1102.0001\FileSyncShell64.dll";
        var target = TestModelHelpers.CreateSampleTarget(
            targetBin: newPath,
            normPath: PathNormalizerAndSimilarity.NormalizeProgramPath(newPath),
            rawCmd: newPath,
            args: string.Empty,
            locKey: @"Software\Classes\CLSID\{CB3D0F55-BC2C-480A-8534-EE63886D2D05}\InprocServer32",
            category: MonitorCategory.ClassicContextMenu,
            md5: "NEW_MD5_222222222222222222222222",
            signer: "Microsoft Corporation",
            rootThumb: "3B1FE8794821CDA9821734289417823901489123",
            origFile: "FileSyncShell64.dll",
            prodName: "Microsoft OneDrive");

        var result = _engine.EvaluateTarget(target, [rule]);

        // Path normalization abstracts away version folders to <ver>, matching perfectly
        Assert.NotNull(result.MatchedRule);
        Assert.Equal(100.0, result.FinalScore);
        Assert.True(result.IsHighConfidenceHit);
        Assert.False(result.IsInGrayZone); // Silent continuation, zero annoying popup!
    }

    [Fact]
    public void Scenario2_EverythingCrossDriveMigration_GrayZoneDiffAndAdaptiveWeightTuning()
    {
        // Historical Rule: Everything installed under C:\Program Files (x86)\...
        string oldRawCmd = @"C:\Program Files (x86)\samplesuite\drivers\x64\Everything\Everything.exe -svc";
        var (oldExe, oldArgs) = PathNormalizerAndSimilarity.SplitCommandLine(oldRawCmd);

        var rule = TestModelHelpers.CreateSampleRule(
            name: "Everything",
            normPath: PathNormalizerAndSimilarity.NormalizeProgramPath(oldExe),
            location: @"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\SS_Everything",
            args: oldArgs,
            signer: "voidtools",
            origFile: "Everything.exe",
            prodName: "Everything",
            md5: "OLD_MD5_111111111111111111111111");
        rule.RuleId = _repository.InsertOrUpdateRule(rule);

        // Target: Migrated across drive to D:\Tools\Everything\Everything.exe
        string newRawCmd = @"D:\Tools\Everything\Everything.exe -svc";
        var (newExe, newArgs) = PathNormalizerAndSimilarity.SplitCommandLine(newRawCmd);

        var target = TestModelHelpers.CreateSampleTarget(
            targetBin: newExe,
            normPath: PathNormalizerAndSimilarity.NormalizeProgramPath(newExe),
            rawCmd: newRawCmd,
            args: newArgs,
            locKey: @"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\Everything",
            signer: "voidtools",
            origFile: "Everything.exe",
            prodName: "Everything",
            md5: "NEW_MD5_222222222222222222222222");

        var result = _engine.EvaluateTarget(target, [rule]);

        // Score should fall in Gray-Zone [45, 85) (typically ~78.7%)
        Assert.NotNull(result.MatchedRule);
        Assert.True(result.FinalScore >= 45.0 && result.FinalScore < 85.0,
            $"Expected Gray-Zone score in [45, 85) but got {result.FinalScore}");
        Assert.True(result.IsInGrayZone);
        Assert.NotEmpty(result.DiffItems);

        // User confirms positive: confirmedSameSoftware = true
        _engine.ApplyUserFeedbackReinforcement(rule, target, result.DiffItems, confirmedSameSoftware: true);

        Assert.Equal(1, rule.EvolutionCount);
        Assert.Single(rule.Aliases);
        Assert.Equal(target.NormalizedPath, rule.Aliases[0].ObservedNormalizedPath);

        // Future evaluation from the new location now hits with high confidence!
        var reloadedRules = _repository.GetAllRulesWithWeightsAndAliases();
        var subsequentEval = _engine.EvaluateTarget(target, reloadedRules);
        Assert.True(subsequentEval.FinalScore >= 85.0 || subsequentEval.FinalScore == 98.0,
            $"Subsequent score should be high confidence, got {subsequentEval.FinalScore}");
    }

    [Fact]
    public void Scenario3_TrojanBinaryReplacement_PenaltyMinus25AndCriticalSignatureLost()
    {
        // Legitimate rule: System tool with valid digital signature
        var rule = TestModelHelpers.CreateSampleRule(
            name: "ProcExp",
            hasSig: true,
            signer: "Microsoft Corporation",
            rootThumb: "11223344556677889900AABBCCDDEEFF11223344",
            origFile: "procexp.exe",
            prodName: "Process Explorer",
            normPath: @"<drive>:\tools\sysinternals\procexp.exe",
            location: @"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\ProcExp",
            args: "/t",
            md5: "LEGIT_MD5_11111111111111111111");
        rule.RuleId = _repository.InsertOrUpdateRule(rule);

        // Trojan payload: exact same path, same filename, same location, same args, BUT signature stripped!
        var target = TestModelHelpers.CreateSampleTarget(
            targetBin: @"C:\Tools\Sysinternals\procexp.exe",
            normPath: @"<drive>:\tools\sysinternals\procexp.exe",
            rawCmd: @"C:\Tools\Sysinternals\procexp.exe /t",
            args: "/t",
            locKey: @"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\ProcExp",
            origFile: "procexp.exe",
            prodName: "Process Explorer",
            hasSig: false, // Signature STRIPPED!
            signer: string.Empty,
            rootThumb: string.Empty,
            md5: "TROJAN_MD5_99999999999999999999");

        var result = _engine.EvaluateTarget(target, [rule]);

        // Must trigger CriticalSignatureLost red alert
        Assert.NotNull(result.MatchedRule);
        Assert.Equal(DiagnosticSeverity.CriticalSignatureLost, result.Severity);
        Assert.Contains("🚨 【高危安全警告", result.DiagnosticOpinion);
        Assert.Contains("原有的合法数字签名", result.DiagnosticOpinion);
        Assert.True(result.FinalScore < rule.ConfidenceThreshold);

        // Red-Line check: privileged rollback forces deletion of startup entry
        var (action, _) = PrivilegedRollbackEngine.EnforceDriverSafetyRedLine(
            InterceptionAction.DeleteEntry,
            isKernelDriver: false);
        Assert.Equal(InterceptionAction.DeleteEntry, action);
    }

    [Fact]
    public void Scenario4_Fullscreen3DGamingWithAltTabDebounce_BatchesCorrectly()
    {
        var flushedBatches = new List<IReadOnlyList<ConfidenceEvaluationResult>>();
        int state = GameModeDebounceController.QUNS_RUNNING_D3D_FULL_SCREEN;
        var clock = new DateTime(2026, 11, 9, 21, 0, 0, DateTimeKind.Utc);

        using var controller = new GameModeDebounceController(
            onFlushDeferredAudits: batch => flushedBatches.Add(batch),
            queryNotificationStateProvider: () => state,
            utcNowProvider: () => clock);

        // Game starts. Epic Games Launcher attempts to register an autostart updater
        var epicTarget = TestModelHelpers.CreateSampleTarget(
            targetBin: @"C:\Program Files (x86)\Epic Games\Launcher\Portal\Binaries\Win64\EpicGamesLauncher.exe",
            rawCmd: @"""C:\Program Files (x86)\Epic Games\Launcher\Portal\Binaries\Win64\EpicGamesLauncher.exe"" -Silent");

        controller.EnqueueDeferredAuditItem(new ConfidenceEvaluationResult
        {
            FinalScore = 100.0,
            CurrentTarget = epicTarget,
            Severity = DiagnosticSeverity.LikelySameSoftware,
            DiagnosticOpinion = "Epic Games Launcher Autostart"
        });

        // 1. In-game: zero notifications
        controller.EvaluateStateTick();
        Assert.Empty(flushedBatches);
        Assert.Equal(1, controller.PendingQueueCount);

        // 2. Alt+Tab at t = 15s
        clock = clock.AddSeconds(15);
        state = GameModeDebounceController.QUNS_ACCEPTS_NOTIFICATIONS;
        controller.EvaluateStateTick();
        Assert.True(controller.IsDebounceTimerActive);
        Assert.Empty(flushedBatches);

        // 3. User returns to game at t = 25s (10s later, < 45s)
        clock = clock.AddSeconds(10);
        state = GameModeDebounceController.QUNS_RUNNING_D3D_FULL_SCREEN;
        controller.EvaluateStateTick();
        Assert.False(controller.IsDebounceTimerActive); // Debounce cancelled!
        Assert.Empty(flushedBatches);

        // 4. True game exit at t = 120s
        clock = clock.AddSeconds(95);
        state = GameModeDebounceController.QUNS_ACCEPTS_NOTIFICATIONS;
        controller.EvaluateStateTick();
        Assert.True(controller.IsDebounceTimerActive);
        Assert.Empty(flushedBatches);

        // 5. Continues for 45s uninterrupted -> t = 165s
        clock = clock.AddSeconds(45.0);
        controller.EvaluateStateTick();

        // 6. Batch summary notification flushed!
        Assert.Single(flushedBatches);
        Assert.Single(flushedBatches[0]);
        Assert.Contains("EpicGamesLauncher.exe", flushedBatches[0][0].CurrentTarget.TargetBinaryPath);
        Assert.Equal(0, controller.PendingQueueCount);
    }

    [Fact]
    public void Scenario5_KernelDriverInterception_SafelyClampedToStartType3Or4()
    {
        // An unknown kernel driver registration is intercepted:
        // C:\Windows\System32\drivers\suspicious_filter.sys
        var target = TestModelHelpers.CreateSampleTarget(
            targetBin: @"C:\Windows\System32\drivers\suspicious_filter.sys",
            locKey: @"SYSTEM\CurrentControlSet\Services\suspicious_filter",
            category: MonitorCategory.KernelDriver);

        // User or automated rule requests: DeleteEntry
        var (clampedAction, clampedStart) = PrivilegedRollbackEngine.EnforceDriverSafetyRedLine(
            InterceptionAction.DeleteEntry,
            isKernelDriver: true);

        // CRITICAL RED-LINE: Must be clamped to RollbackToDisabled (Start = 4)
        // NEVER physically delete .sys file from disk!
        Assert.Equal(InterceptionAction.RollbackToDisabled, clampedAction);
        Assert.Equal(4u, clampedStart);

        // If requested action is RollbackToDemand
        var (demandAction, demandStart) = PrivilegedRollbackEngine.EnforceDriverSafetyRedLine(
            InterceptionAction.RollbackToDemand,
            isKernelDriver: true);

        Assert.Equal(InterceptionAction.RollbackToDemand, demandAction);
        Assert.Equal(3u, demandStart);
    }
}
