using StartupGuard.Core.Ipc;
using StartupGuard.Core.Models;
using StartupGuard.Core.Native;
using StartupGuard.Core.Scoring;
using StartupGuard.Core.Storage;
using StartupGuard.Tests.TestHelpers;

namespace StartupGuard.Tests.Tier3_CrossFeatureCombinations;

public class CrossFeatureIntegrationTests : IDisposable
{
    private readonly string _tempDbPath;
    private readonly string _tempMmfPath;
    private readonly SqliteRuleRepository _repository;
    private readonly MmfBinaryStore _mmfStore;
    private readonly ConfidenceScoringEngine _engine;

    public CrossFeatureIntegrationTests()
    {
        _repository = TestModelHelpers.CreateTemporarySqliteRepository(out _tempDbPath);
        _mmfStore = TestModelHelpers.CreateTemporaryMmfStore(out _tempMmfPath);
        _engine = new ConfidenceScoringEngine(_repository);
    }

    public void Dispose()
    {
        _repository.Dispose();
        _mmfStore.Dispose();
        try { if (File.Exists(_tempDbPath)) File.Delete(_tempDbPath); } catch { }
        try { if (File.Exists(_tempMmfPath)) File.Delete(_tempMmfPath); } catch { }
    }

    [Fact]
    public void Interaction1_Scoring_SqlitePersistence_MmfBinaryCacheSync()
    {
        // 1. Initial rule in SQLite
        var initialRule = TestModelHelpers.CreateSampleRule(
            id: 0,
            name: "FileSyncEx",
            md5: "INITIAL_MD5_11111111111111111111");
        int ruleId = _repository.InsertOrUpdateRule(initialRule);
        initialRule.RuleId = ruleId;

        // 2. Target evaluation: new version of FileSyncEx
        var target = TestModelHelpers.CreateSampleTarget(
            normPath: initialRule.NormalizedPath,
            md5: "22222222222222222222222222222222");
        var eval = _engine.EvaluateTarget(target, [initialRule]);
        Assert.NotNull(eval.MatchedRule);

        // 3. User feedback reinforcement: positive adoption
        _engine.ApplyUserFeedbackReinforcement(initialRule, target, eval.DiffItems, confirmedSameSoftware: true);

        // 4. Reload from SQLite and synchronize MMF store
        var allRules = _repository.GetAllRulesWithWeightsAndAliases();
        var mmfEntries = allRules.Select(MmfRecordEntry.FromRule).ToArray();
        _mmfStore.SaveEntriesAtomically(mmfEntries);

        // 5. Verify MMF zero-copy lookup immediately locates the updated MD5
        byte[] upgradedMd5Bytes = Convert.FromHexString("22222222222222222222222222222222");

        Assert.Equal(1, _mmfStore.Count);
        bool foundByMd5 = _mmfStore.TryFindByMd5OrLocation(
            upgradedMd5Bytes,
            0,
            out var matchedEntry);

        Assert.True(foundByMd5);
        Assert.Equal((uint)ruleId, matchedEntry.RuleId);
        Assert.Equal(1u, matchedEntry.EvolutionCount);
    }

    [Fact]
    public void Interaction2_GameModeDebounce_BatchFlush_IpcSerialization()
    {
        var flushedBatches = new List<IReadOnlyList<ConfidenceEvaluationResult>>();
        int state = GameModeDebounceController.QUNS_RUNNING_D3D_FULL_SCREEN;
        var clock = new DateTime(2026, 11, 9, 20, 0, 0, DateTimeKind.Utc);

        using var gameController = new GameModeDebounceController(
            onFlushDeferredAudits: batch => flushedBatches.Add(batch),
            queryNotificationStateProvider: () => state,
            utcNowProvider: () => clock);

        // 3 deferred items queued during gameplay
        for (int i = 1; i <= 3; i++)
        {
            gameController.EnqueueDeferredAuditItem(new ConfidenceEvaluationResult
            {
                FinalScore = 80.0 + i,
                CurrentTarget = TestModelHelpers.CreateSampleTarget(targetBin: $"tool{i}.exe"),
                Severity = DiagnosticSeverity.LikelySameSoftware,
                DiagnosticOpinion = $"Deferred alert {i}"
            });
        }

        // Leave fullscreen
        state = GameModeDebounceController.QUNS_ACCEPTS_NOTIFICATIONS;
        gameController.EvaluateStateTick();

        // 45s debounce elapse
        clock = clock.AddSeconds(45.0);
        gameController.EvaluateStateTick();

        Assert.Single(flushedBatches);
        var batch = flushedBatches[0];
        Assert.Equal(3, batch.Count);

        // IPC Serialization
        ulong corrId = 77777UL;
        byte[] ipcPacket = BinaryPipeSerializer.SerializeBatchAlerts(corrId, batch);
        Assert.NotEmpty(ipcPacket);

        // IPC Deserialization
        var deserializedBatch = BinaryPipeSerializer.DeserializeBatchAlerts(ipcPacket, out ulong readCorrId);
        Assert.Equal(corrId, readCorrId);
        Assert.Equal(3, deserializedBatch.Count);
        Assert.Equal("tool1.exe", deserializedBatch[0].CurrentTarget.TargetBinaryPath);
        Assert.Equal("tool2.exe", deserializedBatch[1].CurrentTarget.TargetBinaryPath);
        Assert.Equal("tool3.exe", deserializedBatch[2].CurrentTarget.TargetBinaryPath);
    }

    [Fact]
    public void Interaction3_OnlineNegativeFeedback_NegativePairsPersistence_ImmediateShortCircuit()
    {
        var rule = TestModelHelpers.CreateSampleRule(id: 0, name: "LegitimateSoftware");
        int ruleId = _repository.InsertOrUpdateRule(rule);
        rule.RuleId = ruleId;

        // Gray-zone candidate target
        var target = TestModelHelpers.CreateSampleTarget(
            normPath: @"<drive>:\suspicious\fake.exe",
            md5: "SUSPICIOUS_MD5_99999999999999999");

        var firstEval = _engine.EvaluateTarget(target, [rule]);
        Assert.NotNull(firstEval.MatchedRule);

        // User explicit rejection: "Not the same software" (y = -1)
        _engine.ApplyUserFeedbackReinforcement(rule, target, firstEval.DiffItems, confirmedSameSoftware: false);

        // Verify NegativePairs persisted in DB
        Assert.True(_repository.IsNegativePair(ruleId, target.MD5Hex, target.NormalizedPath));

        // Subsequent evaluation with new engine instance (fresh cache)
        var freshEngine = new ConfidenceScoringEngine(_repository);
        var reloadedRules = _repository.GetAllRulesWithWeightsAndAliases();

        var subsequentEval = freshEngine.EvaluateTarget(target, reloadedRules);

        // Must immediately short-circuit to 0 / null
        Assert.Null(subsequentEval.MatchedRule);
        Assert.Equal(DiagnosticSeverity.NormalNew, subsequentEval.Severity);
    }

    [Fact]
    public void Interaction4_PeExtraction_BuildFeatures_Scoring_MmfBaselineUpdate()
    {
        // 1. Build a synthetic PE with imports and icons on disk
        var imports = new (string DllName, string[] Functions)[]
        {
            ("shell32.dll", ["ShellExecuteExW"]),
            ("ole32.dll", ["CoInitializeEx"])
        };
        byte[] iconData = SyntheticPeBuilder.GenerateMockIconBytes(200);
        byte[] peBytes = SyntheticPeBuilder.BuildSyntheticPe64(imports, iconData);

        string tempPe = TestModelHelpers.CreateTempFilePath(".exe");
        try
        {
            File.WriteAllBytes(tempPe, peBytes);

            // 2. Extract features via NativeSecurityExtractor
            var features = NativeSecurityExtractor.BuildTargetProgramFeatures(
                rawCommandLine: $@"""{tempPe}"" /autorun",
                locationKey: @"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\ShellHelper",
                category: MonitorCategory.StartupItem,
                displayName: "ShellHelper");

            Assert.NotEmpty(features.MD5Hex);
            Assert.NotEmpty(features.ImpHash);
            Assert.NotEqual(0UL, features.IconPerceptualHash);

            // 3. Score against empty rules (new item)
            var eval = _engine.EvaluateTarget(features, []);
            Assert.Null(eval.MatchedRule);
            Assert.Equal(DiagnosticSeverity.NormalNew, eval.Severity);

            // 4. Update baseline MMF store
            var baselineEntry = MmfRecordEntry.FromBaselineFeatures(features, InterceptionAction.Allow);
            _mmfStore.SaveEntriesAtomically([baselineEntry]);

            // 5. Verify MMF baseline lookup finds the new item
            bool found = _mmfStore.TryFindByMd5OrLocation(
                ReadOnlySpan<byte>.Empty,
                MmfBinaryStore.ComputeFnv1a64(features.LocationKeyOrIdentifier),
                out var record);

            Assert.True(found);
            Assert.Equal(MonitorCategory.StartupItem, record.Category);
            Assert.Equal(InterceptionAction.Allow, record.TargetAction);
        }
        finally
        {
            try { File.Delete(tempPe); } catch { }
        }
    }
}
