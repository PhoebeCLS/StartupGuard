using System.Runtime.InteropServices;
using StartupGuard.Core.Models;
using StartupGuard.Core.Storage;
using StartupGuard.Tests.TestHelpers;

namespace StartupGuard.Tests.Tier1_FeatureCoverage;

public class DualLayerStorageTests : IDisposable
{
    private readonly string _tempDbPath;
    private readonly string _tempMmfPath;
    private readonly SqliteRuleRepository _repository;
    private readonly MmfBinaryStore _mmfStore;

    public DualLayerStorageTests()
    {
        _repository = TestModelHelpers.CreateTemporarySqliteRepository(out _tempDbPath);
        _mmfStore = TestModelHelpers.CreateTemporaryMmfStore(out _tempMmfPath);
    }

    public void Dispose()
    {
        _repository.Dispose();
        _mmfStore.Dispose();
        try { if (File.Exists(_tempDbPath)) File.Delete(_tempDbPath); } catch { }
        try { if (File.Exists(_tempMmfPath)) File.Delete(_tempMmfPath); } catch { }
    }

    [Fact]
    public void StructLayout_HeaderAndRecord_MatchRequiredByteSizes()
    {
        Assert.Equal(64, Marshal.SizeOf<MmfSnapshotHeader>());
        Assert.Equal(256, Marshal.SizeOf<MmfRecordEntry>());
    }

    [Fact]
    public void MmfRecordEntry_FromRule_CorrectlyPopulatesBinaryFields()
    {
        var rule = TestModelHelpers.CreateSampleRule(
            id: 42,
            hasSig: true,
            md5: "0123456789ABCDEF0123456789ABCDEF",
            sha256: "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
            rootThumb: "1122334455667788990011223344556677889900");

        var entry = MmfRecordEntry.FromRule(rule);

        Assert.Equal(42u, entry.RuleId);
        Assert.Equal(rule.Category, entry.Category);
        Assert.Equal(rule.ActionType, entry.TargetAction);
        Assert.Equal(rule.RuleMode, entry.MatchMode);
        Assert.True(entry.HasSignature);
        Assert.Equal(rule.ConfidenceThreshold, entry.ConfidenceThreshold);
        Assert.Equal(rule.Weights.W_Signature, entry.Weights.W_Signature);
    }

    [Fact]
    public void MmfRecordEntry_FromBaselineFeatures_SetsFlagsAndDefaultWeights()
    {
        var target = TestModelHelpers.CreateSampleTarget(
            hasSig: true,
            category: MonitorCategory.KernelDriver);

        var entry = MmfRecordEntry.FromBaselineFeatures(target, InterceptionAction.RollbackToDemand);

        Assert.Equal(MonitorCategory.KernelDriver, entry.Category);
        Assert.Equal(InterceptionAction.RollbackToDemand, entry.TargetAction);
        Assert.True(entry.HasSignature);
        Assert.True(entry.IsWhqlCertified);
        Assert.Equal(30.0f, entry.Weights.W_Signature);
    }

    [Fact]
    public void MmfBinaryStore_SaveAndLookup_PerformsAtomicZeroCopyLookups()
    {
        var rule1 = TestModelHelpers.CreateSampleRule(
            id: 101,
            location: "HKLM_RUN_APP1",
            md5: "11111111111111111111111111111111");
        var rule2 = TestModelHelpers.CreateSampleRule(
            id: 102,
            location: "HKLM_RUN_APP2",
            md5: "22222222222222222222222222222222");

        MmfRecordEntry[] entries = [MmfRecordEntry.FromRule(rule1), MmfRecordEntry.FromRule(rule2)];

        _mmfStore.SaveEntriesAtomically(entries);
        Assert.Equal(2, _mmfStore.Count);

        // Lookup by LocationHash
        ulong hash1 = MmfBinaryStore.ComputeFnv1a64("HKLM_RUN_APP1");
        bool foundLoc = _mmfStore.TryFindByMd5OrLocation(ReadOnlySpan<byte>.Empty, hash1, out var match1);
        Assert.True(foundLoc);
        Assert.Equal(101u, match1.RuleId);

        // Lookup by MD5
        byte[] md5Bytes2 = Convert.FromHexString("22222222222222222222222222222222");
        bool foundMd5 = _mmfStore.TryFindByMd5OrLocation(md5Bytes2, 0, out var match2);
        Assert.True(foundMd5);
        Assert.Equal(102u, match2.RuleId);

        // Non-existent lookup
        byte[] md5Unknown = Convert.FromHexString("99999999999999999999999999999999");
        bool notFound = _mmfStore.TryFindByMd5OrLocation(md5Unknown, 999999, out _);
        Assert.False(notFound);
    }

    [Fact]
    public void SqliteRuleRepository_CRUD_InsertsUpdatesAndDeletesRules()
    {
        var rule = TestModelHelpers.CreateSampleRule(
            id: 0,
            name: "TestApp",
            category: MonitorCategory.StartupItem,
            action: InterceptionAction.Allow,
            threshold: 88.0f);

        int newId = _repository.InsertOrUpdateRule(rule);
        Assert.True(newId > 0);

        var allRules = _repository.GetAllRulesWithWeightsAndAliases();
        var fetched = allRules.FirstOrDefault(r => r.RuleId == newId);
        Assert.NotNull(fetched);
        Assert.Equal("TestApp", fetched.DisplayName);
        Assert.Equal(88.0f, fetched.ConfidenceThreshold);

        // Update action and mode
        bool updated = _repository.UpdateRuleActionAndMode(newId, InterceptionAction.RollbackToDisabled, RuleMatchMode.StrictCurrentVersion, 92.0f);
        Assert.True(updated);

        var updatedRule = _repository.GetAllRulesWithWeightsAndAliases().First(r => r.RuleId == newId);
        Assert.Equal(InterceptionAction.RollbackToDisabled, updatedRule.ActionType);
        Assert.Equal(RuleMatchMode.StrictCurrentVersion, updatedRule.RuleMode);
        Assert.Equal(92.0f, updatedRule.ConfidenceThreshold);

        // Delete rule
        bool deleted = _repository.DeleteRule(newId);
        Assert.True(deleted);
        Assert.DoesNotContain(_repository.GetAllRulesWithWeightsAndAliases(), r => r.RuleId == newId);
    }

    [Fact]
    public void SqliteRuleRepository_AliasesAndNegativePairs_PersistAndRetrieve()
    {
        var rule = TestModelHelpers.CreateSampleRule(id: 0, name: "MultiVersionApp");
        int ruleId = _repository.InsertOrUpdateRule(rule);

        _repository.AddPolymorphicAlias(ruleId, "ALIAS_MD5_1", "<drive>:\\alias\\path1.exe", "Publisher1", "-arg1");
        _repository.AddPolymorphicAlias(ruleId, "ALIAS_MD5_2", "<drive>:\\alias\\path2.exe", "Publisher1", "-arg2");

        var rulesWithAliases = _repository.GetAllRulesWithWeightsAndAliases();
        var targetRule = rulesWithAliases.First(r => r.RuleId == ruleId);
        Assert.Equal(2, targetRule.Aliases.Count);

        // Negative pair
        _repository.AddNegativePair(ruleId, "BAD_MD5_1", "<drive>:\\bad\\path.exe", "Unknown", "User explicitly rejected");
        Assert.True(_repository.IsNegativePair(ruleId, "BAD_MD5_1", "<drive>:\\bad\\path.exe"));
        Assert.False(_repository.IsNegativePair(ruleId, "GOOD_MD5", "<drive>:\\good\\path.exe"));

        var negList = _repository.GetNegativePairs(ruleId);
        Assert.Single(negList);
        Assert.Equal("BAD_MD5_1", negList[0].RejectedMD5);
    }

    [Fact]
    public void SqliteRuleRepository_AuditLogs_InsertsAndRetrievesDescending()
    {
        _repository.WriteAuditLog(
            ruleId: 1,
            category: MonitorCategory.StartupItem,
            program: "C:\\Tools\\App.exe",
            location: "HKLM_Run",
            oldState: "None",
            newState: "C:\\Tools\\App.exe",
            action: "Blocked",
            score: 72.5,
            diagnostic: "SuspiciousDeviation");

        var logs = _repository.GetRecentAuditLogs(10);
        Assert.NotEmpty(logs);
        var entry = logs[0];
        Assert.Equal("C:\\Tools\\App.exe", entry.TargetProgram);
        Assert.Equal("Blocked", entry.ActionTaken);
        Assert.Equal(72.5, entry.MatchedScore);
    }

    [Fact]
    public void SqliteRuleRepository_StartsEmpty_AndDoesNotSeedBuiltInRules()
    {
        // 全新规则库初始必须为空，不得内置任何预置规则
        Assert.Empty(_repository.GetAllRulesWithWeightsAndAliases());

        int countSeeded = _repository.SeedDefaultShowcaseRulesIfEmpty();
        Assert.Equal(0, countSeeded);
        Assert.Empty(_repository.GetAllRulesWithWeightsAndAliases());
    }
}
