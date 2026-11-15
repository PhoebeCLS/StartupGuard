using System.Runtime.InteropServices;

namespace StartupGuard.Core.Models;

/// <summary>
/// 规则与拦截处置动作选项条目 (用于 ComboBox 下拉数据绑定)
/// </summary>
public sealed class ActionOptionItem
{
    public required string Title { get; init; }
    public required InterceptionAction Action { get; init; }
}

/// <summary>
/// 目标程序六维特征快照载体
/// </summary>
public sealed class TargetProgramFeatures
{
    public required string TargetBinaryPath { get; init; }
    public required string NormalizedPath { get; init; }
    public required ulong NormalizedPathHash { get; init; }
    public required string RawCommandLine { get; init; }
    public required string CommandLineArgsTemplate { get; init; }
    public required string LocationKeyOrIdentifier { get; init; }
    public string DisplayName { get; init; } = string.Empty;
    public MonitorCategory Category { get; init; }

    // 哈希与签名 (Dimension F1)
    public required string MD5Hex { get; init; }
    public required string SHA256Hex { get; init; }
    public bool HasValidSignature { get; init; }
    public string SignerSubject { get; init; } = string.Empty;
    public string RootCertThumbprint { get; init; } = string.Empty;
    public bool IsWhqlCertified { get; init; }

    // PE 资源元数据 (Dimension F2)
    public string OriginalFilename { get; init; } = string.Empty;
    public string ProductName { get; init; } = string.Empty;
    public string CompanyName { get; init; } = string.Empty;
    public string InternalName { get; init; } = string.Empty;
    public string FileDescription { get; init; } = string.Empty;

    // 结构与视觉哈希 (Dimension F6)
    public string ImpHash { get; init; } = string.Empty;
    public ulong IconPerceptualHash { get; init; }

    // 变更上下文 (用于回滚与展示)
    public uint SourceProcessId { get; init; }
    public string SourceProcessName { get; init; } = string.Empty;
    public string OldStateSummary { get; init; } = string.Empty;
    public string NewStateSummary { get; init; } = string.Empty;
    public byte[]? OldRawSnapshot { get; init; }
    public uint RegistryValueType { get; init; }
}

/// <summary>
/// 规则专属六维演化权重 (24 字节紧凑结构)
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 4)]
public struct SixDimensionWeights
{
    public float W_Signature;    // F1 默认 30.0
    public float W_PEMetadata;   // F2 默认 25.0
    public float W_PathTemplate; // F3 默认 20.0
    public float W_LocationKey;  // F4 默认 15.0
    public float W_CommandArgs;  // F5 默认 5.0
    public float W_ImpAndPHash;  // F6 默认 5.0

    public static SixDimensionWeights CreateDefault() => new()
    {
        W_Signature = 30.0f,
        W_PEMetadata = 25.0f,
        W_PathTemplate = 20.0f,
        W_LocationKey = 15.0f,
        W_CommandArgs = 5.0f,
        W_ImpAndPHash = 5.0f
    };

    public void Normalize()
    {
        float sum = W_Signature + W_PEMetadata + W_PathTemplate + W_LocationKey + W_CommandArgs + W_ImpAndPHash;
        if (sum <= 0.001f)
        {
            this = CreateDefault();
            return;
        }
        float factor = 100.0f / sum;
        W_Signature *= factor;
        W_PEMetadata *= factor;
        W_PathTemplate *= factor;
        W_LocationKey *= factor;
        W_CommandArgs *= factor;
        W_ImpAndPHash *= factor;
    }
}

/// <summary>
/// 持久化规则记录模型
/// </summary>
public sealed class RuleRecord
{
    public int RuleId { get; set; }
    public required string DisplayName { get; set; }
    public MonitorCategory Category { get; set; }
    public InterceptionAction ActionType { get; set; }
    public RuleMatchMode RuleMode { get; set; }
    public float ConfidenceThreshold { get; set; } = 85.0f;
    public int EvolutionCount { get; set; }

    public bool HasSignature { get; set; }
    public string SignerSubject { get; set; } = string.Empty;
    public string RootCertThumbprint { get; set; } = string.Empty;

    public string OriginalFilename { get; set; } = string.Empty;
    public string ProductName { get; set; } = string.Empty;
    public string CompanyName { get; set; } = string.Empty;
    public string InternalName { get; set; } = string.Empty;

    public string NormalizedPath { get; set; } = string.Empty;
    public string RawCommand { get; set; } = string.Empty;
    public string LocationKey { get; set; } = string.Empty;
    public string CommandLineArgs { get; set; } = string.Empty;
    public string ImpHash { get; set; } = string.Empty;
    public ulong IconPHash { get; set; }

    public string CurrentMD5 { get; set; } = string.Empty;
    public string CurrentSHA256 { get; set; } = string.Empty;

    public SixDimensionWeights Weights { get; set; } = SixDimensionWeights.CreateDefault();
    public List<RuleAliasEntry> Aliases { get; } = [];
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

    // HiBit 风格全信息展示属性
    public string RuleName => DisplayName;
    public string CategoryName => Category switch
    {
        MonitorCategory.StartupItem => "启动程序",
        MonitorCategory.Win32Service => "Win32服务",
        MonitorCategory.KernelDriver => "内核驱动",
        MonitorCategory.ScheduledTask => "任务调度程序",
        MonitorCategory.ClassicContextMenu => "右键菜单",
        MonitorCategory.ModernContextMenu => "Win11右键",
        MonitorCategory.WindowsPolicy => "系统策略",
        _ => Category.ToString()
    };

    public string CategoryIcon => Category switch
    {
        MonitorCategory.StartupItem => "Rocket24",
        MonitorCategory.Win32Service => "Settings24",
        MonitorCategory.KernelDriver => "ShieldKeyhole24",
        MonitorCategory.ScheduledTask => "Clock24",
        MonitorCategory.ClassicContextMenu => "DocumentTable24",
        MonitorCategory.ModernContextMenu => "Sparkle24",
        MonitorCategory.WindowsPolicy => "Shield24",
        _ => "Shield24"
    };

    public string ActionTypeText => ActionType switch
    {
        InterceptionAction.DeleteEntry => "阻止自启",
        InterceptionAction.Allow => "允许自启",
        InterceptionAction.RollbackToDemand => "设为手动",
        InterceptionAction.RollbackToDelayedAuto => "设为延迟自启",
        InterceptionAction.RollbackToDisabled => "设为禁止",
        InterceptionAction.RestorePreviousSnapshot => "恢复快照",
        _ => ActionType.ToString()
    };

    public string ActionBadgeBackground => ActionType switch
    {
        InterceptionAction.DeleteEntry => "#26D13438",
        InterceptionAction.RollbackToDisabled => "#26D13438",
        InterceptionAction.Allow => "#26107C41",
        _ => "#26FFB900"
    };

    public string ActionBadgeForeground => ActionType switch
    {
        InterceptionAction.DeleteEntry => "#D13438",
        InterceptionAction.RollbackToDisabled => "#D13438",
        InterceptionAction.Allow => "#107C41",
        _ => "#FFB900"
    };

    public string RuleModeText => RuleMode == RuleMatchMode.StrictCurrentVersion ? "仅此版本" : "永久拦截";

    public string TargetBinaryOrCommand
    {
        get
        {
            string raw = !string.IsNullOrEmpty(RawCommand)
                ? RawCommand
                : (!string.IsNullOrEmpty(NormalizedPath) ? NormalizedPath : LocationKey);
            return Native.ShellNavigationHelper.ExpandNormalizedPathTemplate(raw);
        }
    }

    public string DisplayLocationKey => Native.ShellNavigationHelper.FormatForRegeditDisplay(LocationKey);
    public string PublisherDisplay => string.IsNullOrWhiteSpace(SignerSubject) ? "未签名 / 未知发布者" : SignerSubject;
    public string Md5Display => string.IsNullOrWhiteSpace(CurrentMD5) ? "无文件哈希" : CurrentMD5;
    public DateTime LastUpdatedLocal => UpdatedAt.Kind == DateTime.UtcNow.Kind ? UpdatedAt.ToLocalTime() : UpdatedAt;
}

/// <summary>
/// 沙盒解析的右键菜单项明细 (用于深入分析)
/// </summary>
public sealed class ResolvedMenuItemInfo
{
    public string Text { get; init; } = string.Empty;
    public string Verb { get; init; } = string.Empty;
    public string HelpText { get; init; } = string.Empty;
    public bool IsSeparator { get; init; }
    public int Depth { get; init; }
    public bool HasSubMenu { get; init; }
}

/// <summary>
/// 多态特征别名项 (历史更新中接纳的路径/签名/哈希)
/// </summary>
public sealed class RuleAliasEntry
{
    public int AliasId { get; init; }
    public int RuleId { get; set; }
    public string ObservedMD5 { get; init; } = string.Empty;
    public string ObservedNormalizedPath { get; init; } = string.Empty;
    public string ObservedPath
    {
        get => ObservedNormalizedPath;
        init => ObservedNormalizedPath = value;
    }
    public string SignerSubject { get; init; } = string.Empty;
    public string CommandLineArgs { get; init; } = string.Empty;
    public DateTime AdoptedAt { get; init; } = DateTime.UtcNow;
}

/// <summary>
/// 灰区 Diff 对比明细项
/// </summary>
public sealed class FeatureDiffItem
{
    public required string DimensionName { get; init; }
    public required string HistoricalValue { get; init; }
    public required string CurrentValue { get; init; }
    public required bool IsMatched { get; init; }
    public double SimilarityScore { get; init; }
}

/// <summary>
/// 可信度评估与 Diff 研判输出结构
/// </summary>
public sealed class ConfidenceEvaluationResult
{
    public required double FinalScore { get; init; }
    public RuleRecord? MatchedRule { get; init; }
    public required TargetProgramFeatures CurrentTarget { get; init; }
    public TargetProgramFeatures Target => CurrentTarget;
    public required DiagnosticSeverity Severity { get; init; }
    public required string DiagnosticOpinion { get; init; }
    public List<FeatureDiffItem> DiffItems { get; init; } = [];
    public List<FeatureDiffItem> DimensionDiffs => DiffItems;

    /// <summary>是否处于 45 &lt;= S &lt; Threshold 的灰区</summary>
    public bool IsInGrayZone =>
        MatchedRule is not null &&
        FinalScore >= 45.0 &&
        FinalScore < MatchedRule.ConfidenceThreshold;

    public bool IsGrayZoneRequiresDiffPopup => IsInGrayZone;

    /// <summary>是否命中高可信区间 (S &gt;= Threshold)</summary>
    public bool IsHighConfidenceHit =>
        MatchedRule is not null &&
        FinalScore >= MatchedRule.ConfidenceThreshold;

    public bool IsHighConfidenceMatch => IsHighConfidenceHit;
}

/// <summary>
/// 拦截与审计日志记录模型
/// </summary>
public sealed class AuditLogRecord
{
    public int LogId { get; init; }
    public int? RuleId { get; init; }
    public DateTime EventTime { get; init; } = DateTime.UtcNow;
    public MonitorCategory Category { get; init; }
    public string TargetProgram { get; init; } = string.Empty;
    public string TargetLocation { get; init; } = string.Empty;
    public string OldState { get; init; } = string.Empty;
    public string NewState { get; init; } = string.Empty;
    public string ActionTaken { get; init; } = string.Empty;
    public double MatchedScore { get; init; }
    public string DiagnosticText { get; init; } = string.Empty;
    public string SourceProcess { get; init; } = string.Empty;

    // 兼容各层消费的标准命名别名
    public string TargetBinaryPath => TargetProgram;
    public string LocationKey => TargetLocation;
    public string OldStateSummary => OldState;
    public string NewStateSummary => NewState;
    public string DiagnosticOpinion => DiagnosticText;

    public string CategoryName => Category switch
    {
        MonitorCategory.StartupItem => "自启程序",
        MonitorCategory.Win32Service => "系统服务",
        MonitorCategory.KernelDriver => "内核驱动",
        MonitorCategory.ScheduledTask => "计划任务",
        MonitorCategory.ClassicContextMenu => "经典右键菜单",
        MonitorCategory.ModernContextMenu => "Win11现代菜单",
        MonitorCategory.WindowsPolicy => "Windows策略",
        _ => "自启与扩展"
    };

    public string CategoryIcon => Category switch
    {
        MonitorCategory.StartupItem => "Rocket24",
        MonitorCategory.Win32Service => "Settings24",
        MonitorCategory.KernelDriver => "ShieldKeyhole24",
        MonitorCategory.ScheduledTask => "Clock24",
        MonitorCategory.ClassicContextMenu or MonitorCategory.ModernContextMenu => "DocumentTable24",
        MonitorCategory.WindowsPolicy => "Shield24",
        _ => "Apps24"
    };

    public string DisplayActionText
    {
        get
        {
            string raw = (ActionTaken ?? string.Empty).Trim();
            if (string.IsNullOrEmpty(raw)) return "已记录";

            if (raw.Contains("失败", StringComparison.OrdinalIgnoreCase) ||
                raw.Contains("异常", StringComparison.OrdinalIgnoreCase) ||
                raw.Contains("未生效", StringComparison.OrdinalIgnoreCase) ||
                raw.Contains("Fail", StringComparison.OrdinalIgnoreCase) ||
                raw.Contains("Error", StringComparison.OrdinalIgnoreCase))
                return "执行异常";

            if (raw.Contains("待审", StringComparison.OrdinalIgnoreCase) ||
                raw.Contains("暂存", StringComparison.OrdinalIgnoreCase) ||
                raw.Contains("等待", StringComparison.OrdinalIgnoreCase) ||
                raw.Contains("未处置", StringComparison.OrdinalIgnoreCase) ||
                raw.Contains("关闭", StringComparison.OrdinalIgnoreCase) ||
                raw.Contains("Dismiss", StringComparison.OrdinalIgnoreCase) ||
                raw.Contains("Pending", StringComparison.OrdinalIgnoreCase))
                return "待审核";

            if (raw.Contains("延迟", StringComparison.OrdinalIgnoreCase) ||
                raw.Contains("Delayed", StringComparison.OrdinalIgnoreCase))
                return "延迟自启";

            if (raw.Contains("手动", StringComparison.OrdinalIgnoreCase) ||
                raw.Contains("Demand", StringComparison.OrdinalIgnoreCase) ||
                raw.Contains("Manual", StringComparison.OrdinalIgnoreCase))
                return "设为手动";

            if (raw.Contains("删除", StringComparison.OrdinalIgnoreCase) ||
                raw.Contains("移除", StringComparison.OrdinalIgnoreCase) ||
                raw.Contains("Delete", StringComparison.OrdinalIgnoreCase))
                return "已移除";

            if (raw.Contains("放行", StringComparison.OrdinalIgnoreCase) ||
                raw.Contains("允许", StringComparison.OrdinalIgnoreCase) ||
                raw.Contains("恢复", StringComparison.OrdinalIgnoreCase) ||
                raw.Contains("Allow", StringComparison.OrdinalIgnoreCase) ||
                raw.Contains("Revert", StringComparison.OrdinalIgnoreCase))
                return "已放行";

            if (raw.Contains("阻止", StringComparison.OrdinalIgnoreCase) ||
                raw.Contains("禁止", StringComparison.OrdinalIgnoreCase) ||
                raw.Contains("禁用", StringComparison.OrdinalIgnoreCase) ||
                raw.Contains("屏蔽", StringComparison.OrdinalIgnoreCase) ||
                raw.Contains("拦截", StringComparison.OrdinalIgnoreCase) ||
                raw.Contains("Block", StringComparison.OrdinalIgnoreCase) ||
                raw.Contains("Rollback", StringComparison.OrdinalIgnoreCase) ||
                raw.Contains("Intercepted", StringComparison.OrdinalIgnoreCase))
                return "已阻止";

            return raw.Replace("禁用", "禁止");
        }
    }

    public string ActionBadgeBackground => (DisplayActionText is "已阻止" or "已移除" or "执行异常")
        ? "#26D13438"
        : (DisplayActionText is "设为手动" or "延迟自启" or "待审核" ? "#26FFB900" : "#26107C41");

    public string ActionBadgeForeground => (DisplayActionText is "已阻止" or "已移除" or "执行异常")
        ? "#D13438"
        : (DisplayActionText is "设为手动" or "延迟自启" or "待审核" ? "#FFB900" : "#107C41");

    public bool IsPendingManualAction =>
        ActionTaken.Contains("未处置", StringComparison.OrdinalIgnoreCase) ||
        ActionTaken.Contains("待审", StringComparison.OrdinalIgnoreCase) ||
        ActionTaken.Contains("关闭", StringComparison.OrdinalIgnoreCase) ||
        ActionTaken.Contains("Dismiss", StringComparison.OrdinalIgnoreCase);

    public bool CanUndo =>
        IsPendingManualAction ||
        ActionTaken.Contains("阻止") || ActionTaken.Contains("Block") || ActionTaken.Contains("Rollback") ||
        ActionTaken.Contains("手动") || ActionTaken.Contains("禁用") || ActionTaken.Contains("禁止") ||
        ActionTaken.Contains("延迟") || ActionTaken.Contains("Intercepted");

    public string LogActionButtonText => IsPendingManualAction ? "手动处置" : "恢复状态";
}

/// <summary>
/// 互斥负样本对记录模型
/// </summary>
public sealed class NegativePairRecord
{
    public int PairId { get; init; }
    public int RuleId { get; init; }
    public string RejectedMD5 { get; init; } = string.Empty;
    public string RejectedPath { get; init; } = string.Empty;
    public string RejectedSigner { get; init; } = string.Empty;
    public string Reason { get; init; } = string.Empty;
    public DateTime CreatedAt { get; init; } = DateTime.UtcNow;
}

/// <summary>
/// 托盘 6 大监控类别开关与全局免打扰状态载荷
/// </summary>
public sealed class MonitorTogglesPayload
{
    public bool MonitorStartup { get; set; } = true;
    public bool MonitorService { get; set; } = true;
    public bool MonitorDriver { get; set; } = true;
    public bool MonitorScheduledTask { get; set; } = true;
    public bool MonitorContextMenu { get; set; } = true;
    public bool MonitorWindowsPolicy { get; set; } = true;
    public bool BlockNotifications { get; set; }
    public bool EnableSound { get; set; } = true;
    public bool AutoGameMode { get; set; } = true;
    /// <summary>右键菜单拦截策略: false = 先拦截后审核模式 (默认推荐); true = 弹窗即时审核模式</summary>
    public bool ContextMenuPromptMode { get; set; } = false;
}

/// <summary>
/// 主界面手动对指定自启项/服务/驱动/任务/右键菜单执行强权限状态切换载荷
/// </summary>
public sealed class ManualItemMutationPayload
{
    public MonitorCategory Category { get; set; }
    public string LocationKey { get; set; } = string.Empty;
    public string TargetBinaryPath { get; set; } = string.Empty;
    public InterceptionAction Action { get; set; }
    public string DisplayName { get; set; } = string.Empty;
}

