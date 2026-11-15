using StartupGuard.Core.Configuration;
using StartupGuard.Core.Models;
using StartupGuard.Core.Rules;
using StartupGuard.Core.Storage;
using Xunit;

namespace StartupGuard.Tests.Tier1_FeatureCoverage;

public class Md5RuleValidatorTests : IDisposable
{
    private readonly string _tempDbPath;
    private readonly string _tempFilePath;
    private readonly SqliteRuleRepository _repo;

    public Md5RuleValidatorTests()
    {
        _tempDbPath = Path.Combine(Path.GetTempPath(), $"sg_test_{Guid.NewGuid():N}.db");
        _tempFilePath = Path.Combine(Path.GetTempPath(), $"sg_target_{Guid.NewGuid():N}.exe");
        File.WriteAllBytes(_tempFilePath, [1, 2, 3, 4, 5]);

        _repo = new SqliteRuleRepository(_tempDbPath);
    }

    public void Dispose()
    {
        try { if (File.Exists(_tempDbPath)) File.Delete(_tempDbPath); } catch { }
        try { if (File.Exists(_tempFilePath)) File.Delete(_tempFilePath); } catch { }
    }

    [Fact]
    public void ValidateAndCleanObsoleteMd5Rules_WhenMd5Changed_DeletesRuleAndWritesLog()
    {
        // 1. 插入一条 StrictCurrentVersion 的规则，记录旧的 MD5
        var rule = new RuleRecord
        {
            DisplayName = "TestUpdateApp",
            Category = MonitorCategory.StartupItem,
            ActionType = InterceptionAction.RollbackToDisabled,
            RuleMode = RuleMatchMode.StrictCurrentVersion,
            NormalizedPath = _tempFilePath,
            CurrentMD5 = "00000000000000000000000000000000", // 不匹配当前文件内容
            CurrentSHA256 = "dummy"
        };
        _repo.InsertOrUpdateRule(rule);

        // 2. 执行校验
        var result = Md5RuleValidator.ValidateAndCleanObsoleteMd5Rules(_repo);

        // 3. 验证发现哈希变动并删除
        Assert.True(result.DeletedCount >= 1);
        Assert.Contains("TestUpdateApp", result.DeletedRuleNames);

        var allRules = _repo.GetAllRulesWithWeightsAndAliases();
        Assert.DoesNotContain(allRules, r => r.DisplayName == "TestUpdateApp");
    }

    [Fact]
    public void ValidateAndCleanObsoleteMd5Rules_WhenPermanentAdaptive_PreservesRule()
    {
        // 永久拦截规则不因 MD5 改变而自动删除
        var rule = new RuleRecord
        {
            DisplayName = "PermanentApp",
            Category = MonitorCategory.StartupItem,
            ActionType = InterceptionAction.RollbackToDisabled,
            RuleMode = RuleMatchMode.PermanentAdaptive,
            NormalizedPath = _tempFilePath,
            CurrentMD5 = "00000000000000000000000000000000",
            CurrentSHA256 = "dummy"
        };
        _repo.InsertOrUpdateRule(rule);

        var result = Md5RuleValidator.ValidateAndCleanObsoleteMd5Rules(_repo);

        var allRules = _repo.GetAllRulesWithWeightsAndAliases();
        Assert.Contains(allRules, r => r.DisplayName == "PermanentApp");
    }

    [Fact]
    public void ValidateAndCleanObsoleteMd5Rules_WhenBinaryMissing_DeletesStrictCurrentVersionRule()
    {
        string missingPath = Path.Combine(Path.GetTempPath(), $"sg_missing_{Guid.NewGuid():N}.exe");
        var rule = new RuleRecord
        {
            DisplayName = "UninstalledStrictApp",
            Category = MonitorCategory.StartupItem,
            ActionType = InterceptionAction.RollbackToDisabled,
            RuleMode = RuleMatchMode.StrictCurrentVersion,
            NormalizedPath = missingPath,
            CurrentMD5 = "ABCDEF1234567890ABCDEF1234567890",
            CurrentSHA256 = "dummy"
        };
        _repo.InsertOrUpdateRule(rule);

        var result = Md5RuleValidator.ValidateAndCleanObsoleteMd5Rules(_repo);

        Assert.True(result.DeletedCount >= 1);
        Assert.Contains("UninstalledStrictApp", result.DeletedRuleNames);
        var allRules = _repo.GetAllRulesWithWeightsAndAliases();
        Assert.DoesNotContain(allRules, r => r.DisplayName == "UninstalledStrictApp");
    }
}
