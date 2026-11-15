using StartupGuard.Core.Models;
using StartupGuard.Core.Scoring;
using StartupGuard.Core.Storage;
using StartupGuard.Tests.TestHelpers;

namespace StartupGuard.Tests.Tier1_FeatureCoverage;

public class ConfidenceScoringAndLearningTests : IDisposable
{
    private readonly SqliteRuleRepository _repository;
    private readonly string _tempDbPath;
    private readonly ConfidenceScoringEngine _engine;

    public ConfidenceScoringAndLearningTests()
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
    public void EvaluateTarget_ExactMD5Match_Returns100PercentAndSameSoftware()
    {
        var rule = TestModelHelpers.CreateSampleRule(md5: "AABBCCDDEEFF00112233445566778899");
        _repository.InsertOrUpdateRule(rule);

        var target = TestModelHelpers.CreateSampleTarget(md5: "AABBCCDDEEFF00112233445566778899");
        var result = _engine.EvaluateTarget(target, [rule]);

        Assert.Equal(100.0, result.FinalScore);
        Assert.NotNull(result.MatchedRule);
        Assert.Equal(rule.RuleId, result.MatchedRule.RuleId);
        Assert.Equal(DiagnosticSeverity.LikelySameSoftware, result.Severity);
        Assert.True(result.IsHighConfidenceHit);
    }

    [Fact]
    public void EvaluateTarget_Mode0StrictCurrentVersion_DifferentMD5_DoesNotMatch()
    {
        var rule = TestModelHelpers.CreateSampleRule(
            mode: RuleMatchMode.StrictCurrentVersion,
            md5: "11111111111111111111111111111111");
        _repository.InsertOrUpdateRule(rule);

        var target = TestModelHelpers.CreateSampleTarget(md5: "22222222222222222222222222222222");
        var result = _engine.EvaluateTarget(target, [rule]);

        // Mode 0 must skip non-matching MD5
        Assert.Null(result.MatchedRule);
        Assert.Equal(DiagnosticSeverity.NormalNew, result.Severity);
    }

    [Fact]
    public void EvaluateTarget_Mode1PermanentAdaptive_Computes6DWeightedScore()
    {
        var rule = TestModelHelpers.CreateSampleRule(
            mode: RuleMatchMode.PermanentAdaptive,
            md5: "AAAAAAAAAAAA11111111111111111111");
        _repository.InsertOrUpdateRule(rule);

        // Same publisher, same PE info, same path, same args, same impHash/pHash, but upgraded MD5
        var target = TestModelHelpers.CreateSampleTarget(md5: "BBBBBBBBBBBB22222222222222222222");
        var result = _engine.EvaluateTarget(target, [rule]);

        Assert.NotNull(result.MatchedRule);
        Assert.True(result.FinalScore >= 85.0, $"Expected >= 85.0 but got {result.FinalScore}");
        Assert.True(result.IsHighConfidenceHit);
        Assert.Equal(7, result.DiffItems.Count); // F1..F6 + MD5
    }

    [Fact]
    public void EvaluateTarget_PolymorphicAliasHit_Returns98PercentScore()
    {
        var rule = TestModelHelpers.CreateSampleRule(md5: "ORIGINAL_MD5_1111111111111111111");
        int ruleId = _repository.InsertOrUpdateRule(rule);
        rule.RuleId = ruleId;
        rule.Aliases.Add(new RuleAliasEntry
        {
            RuleId = ruleId,
            ObservedMD5 = "ALIASED_MD5_22222222222222222222",
            ObservedNormalizedPath = rule.NormalizedPath,
            SignerSubject = rule.SignerSubject
        });
        _repository.AddPolymorphicAlias(ruleId, "ALIASED_MD5_22222222222222222222", rule.NormalizedPath, rule.SignerSubject, rule.CommandLineArgs);

        var target = TestModelHelpers.CreateSampleTarget(md5: "ALIASED_MD5_22222222222222222222");
        var result = _engine.EvaluateTarget(target, [rule]);

        Assert.Equal(98.0, result.FinalScore);
        Assert.NotNull(result.MatchedRule);
        Assert.Equal(DiagnosticSeverity.LikelySameSoftware, result.Severity);
    }

    [Fact]
    public void EvaluateTarget_SignatureLoss_Applies25PenaltyAndTriggersCriticalSignatureLost()
    {
        // Rule had valid digital signature
        var rule = TestModelHelpers.CreateSampleRule(
            hasSig: true,
            signer: "Microsoft Corporation",
            rootThumb: "11223344556677889900AABBCCDDEEFF11223344",
            md5: "OLD_MD5_111111111111111111111111");
        rule.RuleId = _repository.InsertOrUpdateRule(rule);

        // New binary at same path, same PE metadata, same args, but signature is STRIPPED / INVALID
        var target = TestModelHelpers.CreateSampleTarget(
            hasSig: false,
            signer: string.Empty,
            rootThumb: string.Empty,
            md5: "NEW_TROJAN_MD5_99999999999999999");

        var result = _engine.EvaluateTarget(target, [rule]);

        Assert.NotNull(result.MatchedRule);
        Assert.Equal(DiagnosticSeverity.CriticalSignatureLost, result.Severity);
        Assert.Contains("高危安全警告", result.DiagnosticOpinion);
        Assert.Contains("已丢失", result.DiagnosticOpinion);
        // The score must be severely penalized (below threshold)
        Assert.True(result.FinalScore < rule.ConfidenceThreshold, $"Score {result.FinalScore} should be less than {rule.ConfidenceThreshold}");
    }

    [Fact]
    public void EvaluateTarget_GrayZoneEvaluation_GeneratesDiffCardAndOpinion()
    {
        // Setup a rule and target that differ moderately (cross-drive migration: F3 path JW ~0.68, F4 loc = 0)
        var rule = TestModelHelpers.CreateSampleRule(
            normPath: @"<drive>:\program files (x86)\samplesuite\drivers\x64\everything\everything.exe",
            location: @"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\SS_Driver",
            md5: "OLD_MD5_111111111111111111111111");
        rule.RuleId = _repository.InsertOrUpdateRule(rule);

        var target = TestModelHelpers.CreateSampleTarget(
            normPath: @"<drive>:\tools\everything\everything.exe",
            locKey: @"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\Everything",
            md5: "NEW_MD5_222222222222222222222222");

        var result = _engine.EvaluateTarget(target, [rule]);

        Assert.NotNull(result.MatchedRule);
        Assert.True(result.IsInGrayZone, $"Score {result.FinalScore} should be in gray zone [45, {rule.ConfidenceThreshold})");
        Assert.True(result.IsGrayZoneRequiresDiffPopup);
        Assert.NotEmpty(result.DiffItems);

        // Check opinion formatting
        if (result.FinalScore >= 70.0)
        {
            Assert.Equal(DiagnosticSeverity.LikelySameSoftware, result.Severity);
            Assert.Contains("倾向于同一软件", result.DiagnosticOpinion);
        }
        else
        {
            Assert.Equal(DiagnosticSeverity.SuspiciousDeviation, result.Severity);
            Assert.Contains("灰区特征偏离较大", result.DiagnosticOpinion);
        }
    }

    [Fact]
    public void EvaluateTarget_NegativePairPreExisting_ShortCircuitsToZero()
    {
        var rule = TestModelHelpers.CreateSampleRule(md5: "RULE_MD5_77777777777777777777777");
        rule.RuleId = _repository.InsertOrUpdateRule(rule);

        var target = TestModelHelpers.CreateSampleTarget(
            normPath: @"<drive>:\tools\malicious\tool.exe",
            md5: "REJECTED_MD5_8888888888888888888");

        // Record as negative pair
        _repository.AddNegativePair(rule.RuleId, target.MD5Hex, target.NormalizedPath, target.SignerSubject, "Rejected");

        var result = _engine.EvaluateTarget(target, [rule]);

        Assert.Null(result.MatchedRule);
        Assert.Equal(DiagnosticSeverity.NormalNew, result.Severity);
    }

    [Fact]
    public void ApplyUserFeedbackReinforcement_PositiveConfirmation_BoostsWeightsAndInsertsAlias()
    {
        var rule = TestModelHelpers.CreateSampleRule(md5: "ORIGINAL_MD5_8888888888888888888");
        rule.RuleId = _repository.InsertOrUpdateRule(rule);

        var target = TestModelHelpers.CreateSampleTarget(
            normPath: @"<drive>:\newpath\everything\everything.exe",
            md5: "ADOPTED_MD5_9999999999999999999");

        var initialResult = _engine.EvaluateTarget(target, [rule]);
        int initialEvolution = rule.EvolutionCount;
        float initialPathWeight = rule.Weights.W_PathTemplate;

        // User confirms positive (y = +1)
        _engine.ApplyUserFeedbackReinforcement(rule, target, initialResult.DiffItems, confirmedSameSoftware: true);

        Assert.Equal(initialEvolution + 1, rule.EvolutionCount);
        Assert.Equal(target.MD5Hex, rule.CurrentMD5);
        Assert.Single(rule.Aliases);
        Assert.Equal(target.MD5Hex, rule.Aliases[0].ObservedMD5);

        // Verify weights normalized to 100
        float sum = rule.Weights.W_Signature + rule.Weights.W_PEMetadata + rule.Weights.W_PathTemplate +
                    rule.Weights.W_LocationKey + rule.Weights.W_CommandArgs + rule.Weights.W_ImpAndPHash;
        Assert.Equal(100.0f, sum, 1);

        // Verify repository was updated
        var reloadedRules = _repository.GetAllRulesWithWeightsAndAliases();
        var reloaded = reloadedRules.FirstOrDefault(r => r.RuleId == rule.RuleId);
        Assert.NotNull(reloaded);
        Assert.Equal(rule.EvolutionCount, reloaded.EvolutionCount);
        Assert.Single(reloaded.Aliases);
    }

    [Fact]
    public void ApplyUserFeedbackReinforcement_NegativeConfirmation_RaisesThresholdAndBlacklists()
    {
        var rule = TestModelHelpers.CreateSampleRule(threshold: 85.0f, md5: "RULE_MD5_99999999999999999999999");
        rule.RuleId = _repository.InsertOrUpdateRule(rule);

        var target = TestModelHelpers.CreateSampleTarget(
            normPath: @"<drive>:\unrelated\fake.exe",
            md5: "UNRELATED_MD5_0000000000000000000");

        var initialResult = _engine.EvaluateTarget(target, [rule]);

        // User rejects (y = -1)
        _engine.ApplyUserFeedbackReinforcement(rule, target, initialResult.DiffItems, confirmedSameSoftware: false);

        Assert.Equal(90.0f, rule.ConfidenceThreshold);

        // Negative pair recorded in repository
        var negativePairs = _repository.GetNegativePairs(rule.RuleId);
        Assert.Single(negativePairs);
        Assert.Equal(target.MD5Hex, negativePairs[0].RejectedMD5);

        // Subsequent evaluation must short-circuit
        var subsequentResult = _engine.EvaluateTarget(target, [rule]);
        Assert.Null(subsequentResult.MatchedRule);
    }

    [Fact]
    public void SixDimensionWeights_Normalize_ZeroSumFallsBackToDefault()
    {
        var weights = new SixDimensionWeights
        {
            W_Signature = 0f,
            W_PEMetadata = 0f,
            W_PathTemplate = 0f,
            W_LocationKey = 0f,
            W_CommandArgs = 0f,
            W_ImpAndPHash = 0f
        };

        weights.Normalize();

        Assert.Equal(30.0f, weights.W_Signature);
        Assert.Equal(25.0f, weights.W_PEMetadata);
        Assert.Equal(20.0f, weights.W_PathTemplate);
        Assert.Equal(15.0f, weights.W_LocationKey);
        Assert.Equal(5.0f, weights.W_CommandArgs);
        Assert.Equal(5.0f, weights.W_ImpAndPHash);
    }
}
