using System.Security.Cryptography;
using StartupGuard.Core.Configuration;
using StartupGuard.Core.Models;
using StartupGuard.Core.Native;
using StartupGuard.Core.Storage;

namespace StartupGuard.Core.Rules;

/// <summary>
/// 单版本规则（StrictCurrentVersion）时效性探测与自动清理引擎：
/// 当目标文件不存在、对应系统项目（服务/自启项/计划任务/右键菜单）不存在、或文件 MD5 已更新时，自动移除已失效的单版本规则。
/// </summary>
public static class Md5RuleValidator
{
    public sealed class ValidationResult
    {
        public int CheckedCount { get; set; }
        public int DeletedCount { get; set; }
        public List<string> DeletedRuleNames { get; } = [];
    }

    /// <summary>
    /// 补全历史规则中缺失的文件 MD5 与数字签名（例如早期未展开 \SystemRoot\ 的内核驱动规则）
    /// </summary>
    public static int BackfillMissingRuleMetadata(
        SqliteRuleRepository repo,
        MmfBinaryStore? rulesMmf = null)
    {
        int updatedCount = 0;
        var allRules = repo.GetAllRulesWithWeightsAndAliases();
        foreach (var rule in allRules)
        {
            if (!string.IsNullOrWhiteSpace(rule.CurrentMD5) &&
                !string.IsNullOrWhiteSpace(rule.SignerSubject))
            {
                continue;
            }

            string targetPath = ShellNavigationHelper.ResolveRuleTargetFilePath(
                rule.RawCommand,
                rule.NormalizedPath,
                rule.LocationKey);

            if (string.IsNullOrWhiteSpace(targetPath) ||
                ContainsWildcardPlaceholder(targetPath) ||
                !Path.IsPathRooted(targetPath) ||
                !File.Exists(targetPath))
            {
                continue;
            }

            try
            {
                var (md5, sha256) = string.IsNullOrWhiteSpace(rule.CurrentMD5)
                    ? NativeSecurityExtractor.ComputeFileHashesCng(targetPath)
                    : (rule.CurrentMD5, rule.CurrentSHA256);

                bool hasSig = rule.HasSignature;
                string signer = rule.SignerSubject;
                string thumb = rule.RootCertThumbprint;
                if (string.IsNullOrWhiteSpace(signer))
                {
                    (hasSig, signer, thumb) = NativeSecurityExtractor.ExtractAuthenticodeDetails(targetPath);
                }

                if ((!string.IsNullOrEmpty(md5) && string.IsNullOrWhiteSpace(rule.CurrentMD5)) ||
                    (!string.IsNullOrEmpty(signer) && string.IsNullOrWhiteSpace(rule.SignerSubject)))
                {
                    if (repo.UpdateRuleBinaryMetadata(rule.RuleId, md5, sha256, hasSig, signer, thumb))
                    {
                        updatedCount++;
                    }
                }
            }
            catch { }
        }

        if (updatedCount > 0 && rulesMmf != null)
        {
            var refreshed = repo.GetAllRulesWithWeightsAndAliases();
            rulesMmf.SaveEntriesAtomically(refreshed.Select(MmfRecordEntry.FromRule).ToArray());
        }

        return updatedCount;
    }

    /// <summary>
    /// 执行全量单版本规则时效性探测与自动清理
    /// </summary>
    public static ValidationResult ValidateAndCleanObsoleteMd5Rules(
        SqliteRuleRepository repo,
        MmfBinaryStore? rulesMmf = null)
    {
        BackfillMissingRuleMetadata(repo, rulesMmf);
        var result = new ValidationResult();
        var allRules = repo.GetAllRulesWithWeightsAndAliases();
        bool anyDeleted = false;
        bool diag = UserSettingsStore.GetDiagnosticLoggingEnabled();

        foreach (var rule in allRules)
        {
            // 仅探测单版本规则 (StrictCurrentVersion)，永久拦截规则 (PermanentAdaptive) 绝不自动删除
            if (rule.RuleMode != RuleMatchMode.StrictCurrentVersion)
                continue;

            result.CheckedCount++;

            string targetPath = ShellNavigationHelper.ResolveRuleTargetFilePath(
                rule.RawCommand,
                rule.NormalizedPath,
                rule.LocationKey);

            bool hasUnresolvedWildcard = ContainsWildcardPlaceholder(targetPath);
            bool hasConcreteRootedFile = !hasUnresolvedWildcard &&
                                         !string.IsNullOrWhiteSpace(targetPath) &&
                                         Path.IsPathRooted(targetPath);
            bool fileExists = hasConcreteRootedFile && File.Exists(targetPath);

            if (hasConcreteRootedFile && !fileExists)
            {
                DeleteObsoleteRule(
                    repo,
                    rule,
                    targetPath,
                    "(Missing)",
                    "目标缺失自动清理",
                    $"检测到程序【{rule.DisplayName}】对应文件（{targetPath}）已不存在，单版本规则已自动失效并清理",
                    $"Single-version rule {rule.DisplayName} (ID={rule.RuleId}) deleted: target file missing ({targetPath})",
                    result);
                anyDeleted = true;
                continue;
            }

            bool locationExists = IsRuleSystemTargetStillPresent(rule, targetPath, out bool hasKnownLocation);
            bool preserveDeleteEntryBecauseBinaryExists =
                hasConcreteRootedFile &&
                fileExists &&
                rule.ActionType == InterceptionAction.DeleteEntry;

            if ((!hasKnownLocation && !hasConcreteRootedFile) ||
                (hasKnownLocation && !locationExists && !preserveDeleteEntryBecauseBinaryExists))
            {
                string displayTarget = !string.IsNullOrWhiteSpace(targetPath) ? targetPath : rule.LocationKey;
                DeleteObsoleteRule(
                    repo,
                    rule,
                    displayTarget,
                    "(MissingTarget)",
                    "目标缺失自动清理",
                    $"检测到项目【{rule.DisplayName}】对应的系统项（{rule.LocationKey}）已不存在，单版本规则已自动失效并清理",
                    $"Single-version rule {rule.DisplayName} (ID={rule.RuleId}) deleted: system target missing (loc={rule.LocationKey})",
                    result);
                anyDeleted = true;
                continue;
            }

            if (!hasConcreteRootedFile || !fileExists || string.IsNullOrWhiteSpace(rule.CurrentMD5))
            {
                if (diag)
                {
                    SharedStorageHelper.LogDiagnostic("Rules",
                        $"Single-version check kept id={rule.RuleId} name={rule.DisplayName}: locationExists={locationExists}, fileExists={fileExists}, md5={(string.IsNullOrEmpty(rule.CurrentMD5) ? "none" : rule.CurrentMD5)}");
                }
                continue;
            }

            try
            {
                var (currentMd5, _) = NativeSecurityExtractor.ComputeFileHashesCng(targetPath);
                if (!string.IsNullOrEmpty(currentMd5) &&
                    !string.Equals(currentMd5, rule.CurrentMD5, StringComparison.OrdinalIgnoreCase))
                {
                    DeleteObsoleteRule(
                        repo,
                        rule,
                        targetPath,
                        currentMd5,
                        "MD5失效自动清理",
                        $"检测到程序【{rule.DisplayName}】已更新升级（MD5由 {rule.CurrentMD5} 变更为 {currentMd5}），单版本规则已自动失效并清理",
                        $"MD5 rule {rule.DisplayName} (ID={rule.RuleId}) invalidated & deleted: MD5 changed from {rule.CurrentMD5} to {currentMd5}",
                        result);
                    anyDeleted = true;
                }
                else if (diag)
                {
                    SharedStorageHelper.LogDiagnostic("Rules", $"MD5 check kept id={rule.RuleId} name={rule.DisplayName}: hash unchanged ({currentMd5})");
                }
            }
            catch (Exception ex)
            {
                SharedStorageHelper.LogDiagnostic("Rules", $"Error validating MD5 for {rule.DisplayName}: {ex.Message}");
            }
        }

        if (anyDeleted && rulesMmf != null)
        {
            var updated = repo.GetAllRulesWithWeightsAndAliases();
            rulesMmf.SaveEntriesAtomically(updated.Select(MmfRecordEntry.FromRule).ToArray());
        }

        UserSettingsStore.SetLastMd5ValidationTime(DateTime.UtcNow);
        return result;
    }

    private static void DeleteObsoleteRule(
        SqliteRuleRepository repo,
        RuleRecord rule,
        string targetDisplay,
        string newState,
        string actionTaken,
        string diagnosticText,
        string diagLogLine,
        ValidationResult result)
    {
        repo.DeleteRule(rule.RuleId);
        result.DeletedCount++;
        result.DeletedRuleNames.Add(rule.DisplayName);

        repo.WriteAuditLog(
            rule.RuleId,
            rule.Category,
            targetDisplay,
            rule.LocationKey,
            rule.CurrentMD5,
            newState,
            actionTaken,
            100.0,
            diagnosticText);

        SharedStorageHelper.LogDiagnostic("Rules", diagLogLine);
    }

    private static bool ContainsWildcardPlaceholder(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return false;

        return path.Contains("<ver>", StringComparison.OrdinalIgnoreCase) ||
               path.Contains("<hash>", StringComparison.OrdinalIgnoreCase) ||
               path.Contains("<guid>", StringComparison.OrdinalIgnoreCase) ||
               path.Contains("<user>", StringComparison.OrdinalIgnoreCase) ||
               path.Contains("<drive>", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsRuleSystemTargetStillPresent(RuleRecord rule, string resolvedFilePath, out bool hasKnownLocation)
    {
        string loc = rule.LocationKey?.Trim() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(loc))
        {
            hasKnownLocation = false;
            return false;
        }

        hasKnownLocation = true;

        if (rule.Category is MonitorCategory.Win32Service or MonitorCategory.KernelDriver &&
            !loc.Contains('\\') &&
            !loc.Contains('/'))
        {
            return ShellNavigationHelper.DoesPendingLocationStillExist(
                $@"HKLM\SYSTEM\CurrentControlSet\Services\{loc}",
                resolvedFilePath);
        }

        return ShellNavigationHelper.DoesPendingLocationStillExist(loc, resolvedFilePath);
    }
}
