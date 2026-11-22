using System.Numerics;
using System.Text;
using StartupGuard.Core.Models;
using StartupGuard.Core.Storage;

namespace StartupGuard.Core.Scoring;

/// <summary>
/// 双模式规则引擎与“六维可信度评估 + 灰区 Diff 生成 + 在线权重自学习”核心引擎
/// </summary>
public sealed class ConfidenceScoringEngine
{
    private readonly SqliteRuleRepository _repository;

    public ConfidenceScoringEngine(SqliteRuleRepository repository)
    {
        _repository = repository;
    }

    /// <summary>
    /// 对新捕获的启动项/服务/驱动/右键菜单执行可信度评分与规则匹配
    /// </summary>
    public ConfidenceEvaluationResult EvaluateTarget(TargetProgramFeatures target, IReadOnlyList<RuleRecord> allRules)
    {
        RuleRecord? bestRule = null;
        double bestScore = -1.0;
        List<FeatureDiffItem>? bestDiffs = null;
        bool signatureLostOnBest = false;

        foreach (var rule in allRules)
        {
            // 1. 互斥负样本对短路检查：若曾被用户显式判定为“不是同一软件”，直接跳过 (得分=0)
            if (_repository.IsNegativePair(rule.RuleId, target.MD5Hex, target.NormalizedPath))
                continue;

            // 2. 严格 MD5 命中检查 (无论模式一或模式二，MD5 完全一致均 100% 命中)
            if (string.Equals(rule.CurrentMD5, target.MD5Hex, StringComparison.OrdinalIgnoreCase) &&
                !string.IsNullOrEmpty(target.MD5Hex))
            {
                return new ConfidenceEvaluationResult
                {
                    FinalScore = 100.0,
                    MatchedRule = rule,
                    CurrentTarget = target,
                    Severity = DiagnosticSeverity.LikelySameSoftware,
                    DiagnosticOpinion = $"目标文件 MD5 指纹 ({target.MD5Hex[..8]}...) 与历史规则「{rule.DisplayName}」100% 精确吻合。"
                };
            }

            // 若该规则仅限“模式一：当前版本严格 MD5”，且 MD5 未命中，则不进入永久自适应评分
            if (rule.RuleMode == RuleMatchMode.StrictCurrentVersion)
                continue;

            // 检查是否直接命中多态特征别名集中的某个历史版本 MD5
            foreach (var alias in rule.Aliases)
            {
                if (string.Equals(alias.ObservedMD5, target.MD5Hex, StringComparison.OrdinalIgnoreCase) &&
                    !string.IsNullOrEmpty(target.MD5Hex))
                {
                    return new ConfidenceEvaluationResult
                    {
                        FinalScore = 98.0,
                        MatchedRule = rule,
                        CurrentTarget = target,
                        Severity = DiagnosticSeverity.LikelySameSoftware,
                        DiagnosticOpinion = $"目标程序命中历史规则「{rule.DisplayName}」的多态演化特征集。"
                    };
                }
            }

            // 3. 计算六维加权相似度 S(R, C)
            var (score, diffs, sigLost) = ComputeSixDimensionScore(rule, target);
            if (score > bestScore)
            {
                bestScore = score;
                bestRule = rule;
                bestDiffs = diffs;
                signatureLostOnBest = sigLost;
            }
        }

        // 若无任何规则得分 >= 45 (且未触发历史规则签名丢失高危告警)，判定为全新无关项
        if (bestRule is null || (bestScore < 45.0 && !(signatureLostOnBest && bestScore >= 25.0)))
        {
            return new ConfidenceEvaluationResult
            {
                FinalScore = Math.Max(0, bestScore),
                MatchedRule = null,
                CurrentTarget = target,
                Severity = DiagnosticSeverity.NormalNew,
                DiagnosticOpinion = "未匹配到相似的历史永久规则，判定为全新自启或扩展项目。"
            };
        }

        // 生成自然语言综合研判参考意见
        var (severity, opinion) = SynthesizeNaturalLanguageOpinion(bestRule, target, bestScore, signatureLostOnBest, bestDiffs!);

        return new ConfidenceEvaluationResult
        {
            FinalScore = bestScore,
            MatchedRule = bestRule,
            CurrentTarget = target,
            Severity = severity,
            DiagnosticOpinion = opinion,
            DiffItems = bestDiffs!
        };
    }

    /// <summary>
    /// 计算六维特征相似度与安全惩罚项
    /// </summary>
    private static (double TotalScore, List<FeatureDiffItem> Diffs, bool SignatureLost) ComputeSixDimensionScore(
        RuleRecord rule,
        TargetProgramFeatures current)
    {
        var w = rule.Weights;
        var diffs = new List<FeatureDiffItem>(7);
        double penalty = 0.0;
        bool sigLost = false;

        // --- F1: 数字签名指纹 (默认 30%) ---
        double sim1;
        if (rule.HasSignature && !current.HasValidSignature)
        {
            // 原有合法数字签名丢失 -> 触发安全重罚 -25 分！
            sim1 = 0.0;
            penalty = -25.0;
            sigLost = true;
        }
        else if (rule.HasSignature && current.HasValidSignature)
        {
            bool sameSubject = string.Equals(rule.SignerSubject, current.SignerSubject, StringComparison.OrdinalIgnoreCase);
            bool sameRoot = string.Equals(rule.RootCertThumbprint, current.RootCertThumbprint, StringComparison.OrdinalIgnoreCase) ||
                            string.IsNullOrEmpty(rule.RootCertThumbprint) ||
                            string.IsNullOrEmpty(current.RootCertThumbprint);
            sim1 = (sameSubject && sameRoot) ? 1.0 : (sameSubject ? 0.85 : 0.0);
        }
        else if (!rule.HasSignature && !current.HasValidSignature)
        {
            sim1 = 0.5;
        }
        else
        {
            // 原先无签名，新版本补签了正规签名
            sim1 = 0.75;
        }

        diffs.Add(new FeatureDiffItem
        {
            DimensionName = "数字签名发布者",
            HistoricalValue = rule.HasSignature ? $"{rule.SignerSubject} (有效)" : "无数字签名",
            CurrentValue = current.HasValidSignature ? $"{current.SignerSubject} (有效)" : "⚠️ 无数字签名",
            IsMatched = sim1 >= 0.8,
            SimilarityScore = sim1
        });

        // --- F2: PE 版本资源元数据 (默认 25%) ---
        double eqOrig = (!string.IsNullOrEmpty(rule.OriginalFilename) &&
                         string.Equals(rule.OriginalFilename, current.OriginalFilename, StringComparison.OrdinalIgnoreCase)) ? 1.0 : 0.0;
        double eqProd = (!string.IsNullOrEmpty(rule.ProductName) &&
                         string.Equals(rule.ProductName, current.ProductName, StringComparison.OrdinalIgnoreCase)) ? 1.0 : 0.0;
        double eqInt = (!string.IsNullOrEmpty(rule.InternalName) &&
                        string.Equals(rule.InternalName, current.InternalName, StringComparison.OrdinalIgnoreCase)) ? 1.0 : 0.0;
        double sim2 = 0.4 * eqOrig + 0.3 * eqProd + 0.3 * eqInt;

        // 若文件名本身完全相同给予保底分
        string ruleFileName = Path.GetFileName(rule.NormalizedPath);
        string curFileName = Path.GetFileName(current.NormalizedPath);
        if (sim2 < 0.5 && !string.IsNullOrEmpty(ruleFileName) &&
            ruleFileName.Equals(curFileName, StringComparison.OrdinalIgnoreCase))
        {
            sim2 = Math.Max(sim2, 0.7);
        }

        diffs.Add(new FeatureDiffItem
        {
            DimensionName = "PE 产品与原始文件名",
            HistoricalValue = $"{rule.ProductName} ({rule.OriginalFilename})",
            CurrentValue = $"{current.ProductName} ({current.OriginalFilename})",
            IsMatched = sim2 >= 0.7,
            SimilarityScore = sim2
        });

        // --- F3: 归一化路径模板与目录编辑距离 (默认 20%) ---
        double sim3 = PathNormalizerAndSimilarity.ComputeJaroWinkler(rule.NormalizedPath, current.NormalizedPath);
        foreach (var alias in rule.Aliases)
        {
            double aliasPathSim = PathNormalizerAndSimilarity.ComputeJaroWinkler(alias.ObservedNormalizedPath, current.NormalizedPath);
            if (aliasPathSim > sim3) sim3 = aliasPathSim;
        }

        diffs.Add(new FeatureDiffItem
        {
            DimensionName = "归一化安装路径",
            HistoricalValue = rule.NormalizedPath,
            CurrentValue = current.NormalizedPath,
            IsMatched = sim3 >= 0.90,
            SimilarityScore = sim3
        });

        // --- F4: 启动项注册位置与键名/服务名/CLSID (默认 15%) ---
        double sim4 = 0.0;
        if (!string.IsNullOrEmpty(rule.LocationKey) && !string.IsNullOrEmpty(current.LocationKeyOrIdentifier))
        {
            if (string.Equals(rule.LocationKey, current.LocationKeyOrIdentifier, StringComparison.OrdinalIgnoreCase))
                sim4 = 1.0;
            else if (current.LocationKeyOrIdentifier.Contains(rule.LocationKey, StringComparison.OrdinalIgnoreCase) ||
                     rule.LocationKey.Contains(current.LocationKeyOrIdentifier, StringComparison.OrdinalIgnoreCase))
                sim4 = 0.7;
        }

        diffs.Add(new FeatureDiffItem
        {
            DimensionName = "注册位置/服务标识",
            HistoricalValue = rule.LocationKey,
            CurrentValue = current.LocationKeyOrIdentifier,
            IsMatched = sim4 >= 0.7,
            SimilarityScore = sim4
        });

        // --- F5: 命令行参数模板相似度 (默认 5%) ---
        double sim5 = PathNormalizerAndSimilarity.ComputeArgsJaccard(rule.CommandLineArgs, current.CommandLineArgsTemplate);
        diffs.Add(new FeatureDiffItem
        {
            DimensionName = "启动参数开关",
            HistoricalValue = string.IsNullOrEmpty(rule.CommandLineArgs) ? "(无参数)" : rule.CommandLineArgs,
            CurrentValue = string.IsNullOrEmpty(current.CommandLineArgsTemplate) ? "(无参数)" : current.CommandLineArgsTemplate,
            IsMatched = sim5 >= 0.8,
            SimilarityScore = sim5
        });

        // --- F6: ImpHash / 图标感知哈希 pHash (默认 5%) ---
        double impMatch;
        if (string.IsNullOrEmpty(rule.ImpHash) && string.IsNullOrEmpty(current.ImpHash))
        {
            impMatch = 0.5;
        }
        else if (!string.IsNullOrEmpty(rule.ImpHash) &&
                 !string.IsNullOrEmpty(current.ImpHash) &&
                 string.Equals(rule.ImpHash, current.ImpHash, StringComparison.OrdinalIgnoreCase))
        {
            impMatch = 1.0;
        }
        else
        {
            impMatch = 0.0;
        }

        int hamming = BitOperations.PopCount(rule.IconPHash ^ current.IconPerceptualHash);
        double pHashSim = Math.Max(0.0, 1.0 - hamming / 32.0);
        double sim6 = 0.6 * impMatch + 0.4 * pHashSim;

        diffs.Add(new FeatureDiffItem
        {
            DimensionName = "ImpHash / 图标 pHash",
            HistoricalValue = $"{(string.IsNullOrEmpty(rule.ImpHash) ? "(无)" : rule.ImpHash)} / 0x{rule.IconPHash:x16}",
            CurrentValue = $"{(string.IsNullOrEmpty(current.ImpHash) ? "(无)" : current.ImpHash)} / 0x{current.IconPerceptualHash:x16}",
            IsMatched = sim6 >= 0.7,
            SimilarityScore = sim6
        });

        bool md5Equal = !string.IsNullOrEmpty(rule.CurrentMD5) &&
                        string.Equals(rule.CurrentMD5, current.MD5Hex, StringComparison.OrdinalIgnoreCase);
        diffs.Add(new FeatureDiffItem
        {
            DimensionName = "文件 MD5",
            HistoricalValue = string.IsNullOrEmpty(rule.CurrentMD5) ? "(无)" : rule.CurrentMD5,
            CurrentValue = string.IsNullOrEmpty(current.MD5Hex) ? "(无)" : current.MD5Hex,
            IsMatched = md5Equal,
            SimilarityScore = md5Equal ? 1.0 : 0.0
        });

        double weightedSum =
            w.W_Signature * sim1 +
            w.W_PEMetadata * sim2 +
            w.W_PathTemplate * sim3 +
            w.W_LocationKey * sim4 +
            w.W_CommandArgs * sim5 +
            w.W_ImpAndPHash * sim6 +
            penalty;

        double clampedScore = Math.Clamp(weightedSum, 0.0, 100.0);
        return (clampedScore, diffs, sigLost);
    }

    /// <summary>
    /// 基于各维度得分动态合成【程序研判参考意见】
    /// </summary>
    private static (DiagnosticSeverity Severity, string Opinion) SynthesizeNaturalLanguageOpinion(
        RuleRecord rule,
        TargetProgramFeatures current,
        double score,
        bool sigLost,
        List<FeatureDiffItem> diffs)
    {
        if (sigLost)
        {
            return (
                DiagnosticSeverity.CriticalSignatureLost,
                $"🚨 【高危安全警告 (可信度已扣减至 {score:F0}%)】：目标程序的文件名与路径结构与历史规则「{rule.DisplayName}」高度重合，但原有的合法数字签名 ({rule.SignerSubject}) 已丢失！疑似被恶意木马篡改替换，强烈建议立即阻止！"
            );
        }

        var matchedNames = diffs.Where(d => d.IsMatched).Select(d => d.DimensionName).ToList();
        var changedNames = diffs.Where(d => !d.IsMatched).Select(d => d.DimensionName).ToList();

        if (score >= 70.0)
        {
            string matchedStr = matchedNames.Count > 0 ? string.Join("、", matchedNames) : "核心指纹";
            string changedStr = changedNames.Count > 0 ? string.Join("、", changedNames) : "文件版本哈希";
            return (
                DiagnosticSeverity.LikelySameSoftware,
                $"💡 【系统研判意见 (可信度 {score:F0}% - 倾向于同一软件迁移/更新)】：目标程序的 {matchedStr} 与历史规则「{rule.DisplayName}」完全一致；仅 {changedStr} 发生变更。建议判定为【同一软件】并延续永久规则。"
            );
        }

        return (
            DiagnosticSeverity.SuspiciousDeviation,
            $"⚠️ 【系统研判意见 (可信度 {score:F0}% - 灰区特征偏离较大)】：目标程序与历史规则「{rule.DisplayName}」存在部分相似特征，但 {string.Join("、", changedNames)} 发生显著改变。请仔细核对下方红绿 Diff 卡片后再做决定。"
        );
    }

    /// <summary>
    /// 用户反馈闭环在线学习算法 (On-Device Adaptive Weight Tuning)
    /// </summary>
    public void ApplyUserFeedbackReinforcement(
        RuleRecord rule,
        TargetProgramFeatures current,
        IReadOnlyList<FeatureDiffItem> diffs,
        bool confirmedSameSoftware)
    {
        const float learningRate = 0.06f;

        if (confirmedSameSoftware)
        {
            // 1. 正向强化：将新路径/新签名记入该规则的多态特征集 (Polymorphic Alias Set)
            _repository.AddPolymorphicAlias(
                rule.RuleId,
                current.MD5Hex,
                current.NormalizedPath,
                current.SignerSubject,
                current.CommandLineArgsTemplate);

            rule.Aliases.Add(new RuleAliasEntry
            {
                RuleId = rule.RuleId,
                ObservedMD5 = current.MD5Hex,
                ObservedNormalizedPath = current.NormalizedPath,
                SignerSubject = current.SignerSubject,
                CommandLineArgs = current.CommandLineArgsTemplate
            });

            // 2. 在线调整该规则专属 24 字节权重：提升保持一致维度的置信权重，降低本次容忍变动维度的惩罚
            var w = rule.Weights;
            foreach (var d in diffs)
            {
                if (d.DimensionName.Contains("MD5", StringComparison.OrdinalIgnoreCase))
                    continue;

                float delta = d.IsMatched ? (1.0f + learningRate) : (1.0f - learningRate * 0.5f);
                if (d.DimensionName.Contains("签名")) w.W_Signature *= delta;
                else if (d.DimensionName.Contains("PE")) w.W_PEMetadata *= delta;
                else if (d.DimensionName.Contains("路径")) w.W_PathTemplate *= delta;
                else if (d.DimensionName.Contains("位置")) w.W_LocationKey *= delta;
                else if (d.DimensionName.Contains("参数")) w.W_CommandArgs *= delta;
                else if (d.DimensionName.Contains("ImpHash") || d.DimensionName.Contains("pHash")) w.W_ImpAndPHash *= delta;
            }
            w.Normalize();
            rule.Weights = w;

            // 3. 更新主规则的最新 MD5、SHA256 与演化计数
            rule.CurrentMD5 = current.MD5Hex;
            rule.CurrentSHA256 = current.SHA256Hex;
            rule.NormalizedPath = current.NormalizedPath;
            rule.EvolutionCount++;
            _repository.UpdateRuleWeightsAndThreshold(
                rule.RuleId,
                rule.Weights,
                rule.ConfidenceThreshold,
                rule.EvolutionCount,
                rule.CurrentMD5,
                rule.CurrentSHA256);
            _repository.InsertOrUpdateRule(rule);
        }
        else
        {
            // 1. 负向隔离：将两者记入互斥负样本对 (NegativePairs)，永不再将两者归为同一软件
            _repository.AddNegativePair(
                rule.RuleId,
                current.MD5Hex,
                current.NormalizedPath,
                current.SignerSubject,
                "User explicitly rejected in Gray-Zone Diff dialog");

            // 2. 筑高该规则的匹配阈值 θ_rule (例如从 85 提升至 90，最高 95)
            rule.ConfidenceThreshold = Math.Min(95.0f, rule.ConfidenceThreshold + 5.0f);

            // 3. 惩罚导致误判的相似维度 (*= 0.94f)，拉高存在差异的区分维度 (*= 1.08f)，并归一化
            var w = rule.Weights;
            foreach (var d in diffs)
            {
                if (d.DimensionName.Contains("MD5", StringComparison.OrdinalIgnoreCase))
                    continue;

                float factor = d.IsMatched ? 0.94f : 1.08f;
                if (d.DimensionName.Contains("签名")) w.W_Signature *= factor;
                else if (d.DimensionName.Contains("PE")) w.W_PEMetadata *= factor;
                else if (d.DimensionName.Contains("路径")) w.W_PathTemplate *= factor;
                else if (d.DimensionName.Contains("位置")) w.W_LocationKey *= factor;
                else if (d.DimensionName.Contains("参数")) w.W_CommandArgs *= factor;
                else if (d.DimensionName.Contains("ImpHash") || d.DimensionName.Contains("pHash")) w.W_ImpAndPHash *= factor;
            }
            w.Normalize();
            rule.Weights = w;

            _repository.UpdateRuleWeightsAndThreshold(
                rule.RuleId,
                rule.Weights,
                rule.ConfidenceThreshold,
                rule.EvolutionCount,
                rule.CurrentMD5,
                rule.CurrentSHA256);
            _repository.InsertOrUpdateRule(rule);
        }
    }
}

