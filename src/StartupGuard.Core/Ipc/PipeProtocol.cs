using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using StartupGuard.Core.Models;

namespace StartupGuard.Core.Ipc;

/// <summary>
/// IPC 命名管道消息命令类型
/// </summary>
public enum PipeMessageType : byte
{
    Heartbeat = 0,
    /// <summary>Service -> TrayHost: 请求弹出实时拦截或灰区 Diff 弹窗</summary>
    InterceptionAlertRequest = 1,
    /// <summary>TrayHost -> Service: 用户在弹窗中做出的决策响应</summary>
    UserDecisionResponse = 2,
    /// <summary>Service -> TrayHost: 退出全屏游戏 45s 后推送批量延后审核汇总</summary>
    GameModeBatchAuditNotify = 3,
    /// <summary>TrayHost -> Service: 切换 6 大监控类别开关或 Auto Game Mode</summary>
    UpdateMonitorToggles = 4,
    /// <summary>App -> Service: 通知规则库发生变更，重新映射 MMF 缓存</summary>
    ReloadRulesCache = 5,
    /// <summary>App -> Service: 手动对指定启动项/右键菜单执行强权限状态切换</summary>
    ExecuteManualItemMutation = 6,
    /// <summary>TrayHost -> Service: 上报交互式会话状态 (UserSid, 是否处于全屏游戏)</summary>
    UserSessionReport = 7,
    /// <summary>App -> Service: 从拦截日志中请求对指定项目执行强权限回滚</summary>
    ExecuteAuditRollback = 8,
    /// <summary>Service -> TrayHost: 强权限回滚验证重试3次均失败的警报广播</summary>
    RollbackFailureAlert = 9,
    /// <summary>Service -> TrayHost: 命中规则自动阻止项广播 (受托盘“阻止的通知”开关单独控制)</summary>
    BlockedItemNotification = 10,
    /// <summary>App/TrayHost -> Service: 自身变更操作预通知（抑制自我操作误拦截并等待 ACK）</summary>
    SuppressSelfMutation = 11
}

public sealed class SelfMutationSuppressionPayload
{
    public string LocationKey { get; init; } = string.Empty;
    public MonitorCategory Category { get; init; }
    public string TargetBinaryPath { get; init; } = string.Empty;
    public double DurationSeconds { get; init; } = 15.0;
}

/// <summary>
/// 64字节定长零分配 IPC 消息头 (Blittable Struct)
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1, Size = 64)]
public struct PipeMessageHeader
{
    public const uint MagicValue = 0x50495053; // "SPIP"
    public const ushort CurrentProtocolVersion = 1;

    public uint Magic;
    public ushort Version;
    public PipeMessageType MessageType;
    public byte Flags;
    public uint PayloadLength;
    public ulong CorrelationId;
    public uint SourceSessionId;
    public long TimestampUtcTicks;

    // 预留对齐填充至 64 字节
    private ulong _reserved1;
    private ulong _reserved2;
    private ulong _reserved3;
    private ulong _reserved4;

    public uint SessionId
    {
        readonly get => SourceSessionId;
        set => SourceSessionId = value;
    }

    public long TimestampUtcMs
    {
        readonly get => TimestampUtcTicks / TimeSpan.TicksPerMillisecond;
        set => TimestampUtcTicks = value * TimeSpan.TicksPerMillisecond;
    }

    public static PipeMessageHeader Create(PipeMessageType type, uint payloadLen, ulong correlationId, uint sessionId = 0)
    {
        return new PipeMessageHeader
        {
            Magic = MagicValue,
            Version = CurrentProtocolVersion,
            MessageType = type,
            Flags = 0,
            PayloadLength = payloadLen,
            CorrelationId = correlationId,
            SourceSessionId = sessionId,
            TimestampUtcTicks = DateTime.UtcNow.Ticks
        };
    }

    public readonly bool IsValid => Magic == MagicValue && Version == CurrentProtocolVersion;
}

/// <summary>
/// 用户弹窗决策响应载荷
/// </summary>
public class UserDecisionPayload
{
    public ulong CorrelationId { get; init; }
    public InterceptionAction ChosenAction { get; init; }
    public bool RememberRule { get; init; }
    public RuleMatchMode ChosenRuleMode { get; init; }
    /// <summary>当处于灰区弹窗时：true=确认为同一软件延续规则，false=不是同一软件</summary>
    public bool? ConfirmedSameSoftwareInGrayZone { get; init; }
    public int MatchedRuleId { get; init; }
    public string TargetBinaryPath { get; init; } = string.Empty;
    public string LocationKey { get; init; } = string.Empty;
    public MonitorCategory Category { get; init; }
    public string DisplayName { get; init; } = string.Empty;
}

/// <summary>
/// 交互式桌面会话状态上报载荷 (TrayHost -> Service)
/// </summary>
public sealed class UserSessionReportPayload
{
    public string UserSid { get; set; } = string.Empty;
    public bool InGame { get; set; }
}

/// <summary>
/// 拦截审计日志回滚请求载荷 (App -> Service)
/// </summary>
public sealed class AuditRollbackRequestPayload
{
    public int AuditLogId { get; set; }
    public string LocationKey { get; set; } = string.Empty;
    public MonitorCategory Category { get; set; }
    public InterceptionAction TargetAction { get; set; }
    public string OldStateSummary { get; set; } = string.Empty;
    public uint TargetStartType { get; set; } = 4;
    public bool DelayedAutostart { get; set; }
}

/// <summary>
/// UserInterceptionDecision 兼容类型别名
/// </summary>
public sealed class UserInterceptionDecision : UserDecisionPayload
{
}

/// <summary>
/// 零反射二进制序列化器 (专为 NativeAOT 高性能管道传输设计)
/// </summary>
public static class BinaryPipeSerializer
{
    public static byte[] SerializeAlert(ConfidenceEvaluationResult eval, ulong correlationId = 0)
        => SerializeAlert(correlationId, eval);

    public static byte[] SerializeAlert(
        ulong correlationId,
        ConfidenceEvaluationResult eval)
    {
        using var ms = new MemoryStream(1024);
        using var bw = new BinaryWriter(ms, Encoding.UTF8, leaveOpen: true);
        WriteAlertToWriter(bw, correlationId, eval);
        bw.Flush();
        return ms.ToArray();
    }

    public static ConfidenceEvaluationResult DeserializeAlert(ReadOnlySpan<byte> payload)
        => DeserializeAlert(payload, out _);

    public static ConfidenceEvaluationResult DeserializeAlert(
        ReadOnlySpan<byte> payload,
        out ulong correlationId)
    {
        using var ms = new MemoryStream(payload.ToArray(), writable: false);
        using var br = new BinaryReader(ms, Encoding.UTF8, leaveOpen: true);
        return ReadAlertFromReader(br, out correlationId);
    }

    private static void WriteAlertToWriter(
        BinaryWriter bw,
        ulong correlationId,
        ConfidenceEvaluationResult eval)
    {
        bw.Write(correlationId);
        bw.Write(eval.FinalScore);
        bw.Write((byte)eval.Severity);
        bw.Write(eval.DiagnosticOpinion ?? string.Empty);

        // Matched rule info
        bw.Write(eval.MatchedRule is not null);
        if (eval.MatchedRule is not null)
        {
            var r = eval.MatchedRule;
            bw.Write(r.RuleId);
            bw.Write(r.DisplayName ?? string.Empty);
            bw.Write((byte)r.Category);
            bw.Write((byte)r.ActionType);
            bw.Write((byte)r.RuleMode);
            bw.Write(r.ConfidenceThreshold);
            bw.Write(r.EvolutionCount);
            bw.Write(r.HasSignature);
            bw.Write(r.SignerSubject ?? string.Empty);
            bw.Write(r.RootCertThumbprint ?? string.Empty);
            bw.Write(r.OriginalFilename ?? string.Empty);
            bw.Write(r.ProductName ?? string.Empty);
            bw.Write(r.CompanyName ?? string.Empty);
            bw.Write(r.InternalName ?? string.Empty);
            bw.Write(r.NormalizedPath ?? string.Empty);
            bw.Write(r.LocationKey ?? string.Empty);
            bw.Write(r.CommandLineArgs ?? string.Empty);
            bw.Write(r.ImpHash ?? string.Empty);
            bw.Write(r.IconPHash);
            bw.Write(r.CurrentMD5 ?? string.Empty);
            bw.Write(r.CurrentSHA256 ?? string.Empty);
            bw.Write(r.Weights.W_Signature);
            bw.Write(r.Weights.W_PEMetadata);
            bw.Write(r.Weights.W_PathTemplate);
            bw.Write(r.Weights.W_LocationKey);
            bw.Write(r.Weights.W_CommandArgs);
            bw.Write(r.Weights.W_ImpAndPHash);
        }

        // Target features
        var t = eval.CurrentTarget;
        bw.Write((byte)t.Category);
        bw.Write(t.TargetBinaryPath ?? string.Empty);
        bw.Write(t.NormalizedPath ?? string.Empty);
        bw.Write(t.NormalizedPathHash);
        bw.Write(t.RawCommandLine ?? string.Empty);
        bw.Write(t.CommandLineArgsTemplate ?? string.Empty);
        bw.Write(t.LocationKeyOrIdentifier ?? string.Empty);
        bw.Write(t.MD5Hex ?? string.Empty);
        bw.Write(t.SHA256Hex ?? string.Empty);
        bw.Write(t.HasValidSignature);
        bw.Write(t.SignerSubject ?? string.Empty);
        bw.Write(t.RootCertThumbprint ?? string.Empty);
        bw.Write(t.IsWhqlCertified);
        bw.Write(t.OriginalFilename ?? string.Empty);
        bw.Write(t.ProductName ?? string.Empty);
        bw.Write(t.CompanyName ?? string.Empty);
        bw.Write(t.InternalName ?? string.Empty);
        bw.Write(t.FileDescription ?? string.Empty);
        bw.Write(t.ImpHash ?? string.Empty);
        bw.Write(t.IconPerceptualHash);
        bw.Write(t.SourceProcessId);
        bw.Write(t.SourceProcessName ?? string.Empty);
        bw.Write(t.OldStateSummary ?? string.Empty);
        bw.Write(t.NewStateSummary ?? string.Empty);
        bw.Write(t.RegistryValueType);
        bw.Write(t.DisplayName ?? string.Empty);

        // Diff items
        bw.Write(eval.DiffItems.Count);
        foreach (var diff in eval.DiffItems)
        {
            bw.Write(diff.DimensionName ?? string.Empty);
            bw.Write(diff.HistoricalValue ?? string.Empty);
            bw.Write(diff.CurrentValue ?? string.Empty);
            bw.Write(diff.IsMatched);
            bw.Write(diff.SimilarityScore);
        }
    }

    private static ConfidenceEvaluationResult ReadAlertFromReader(
        BinaryReader br,
        out ulong correlationId)
    {
        correlationId = br.ReadUInt64();
        double finalScore = br.ReadDouble();
        var severity = (DiagnosticSeverity)br.ReadByte();
        string opinion = br.ReadString();

        bool hasRule = br.ReadBoolean();
        RuleRecord? matchedRule = null;
        if (hasRule)
        {
            int ruleId = br.ReadInt32();
            string displayName = br.ReadString();
            var ruleCat = (MonitorCategory)br.ReadByte();
            var actType = (InterceptionAction)br.ReadByte();
            var ruleMode = (RuleMatchMode)br.ReadByte();
            float threshold = br.ReadSingle();
            int evoCount = br.ReadInt32();
            bool hasSig = br.ReadBoolean();
            string sigSubj = br.ReadString();
            string rootThumb = br.ReadString();
            string origFile = br.ReadString();
            string prodName = br.ReadString();
            string compName = br.ReadString();
            string intName = br.ReadString();
            string normPath = br.ReadString();
            string locKey = br.ReadString();
            string cmdArgs = br.ReadString();
            string impHash = br.ReadString();
            ulong iconPHash = br.ReadUInt64();
            string curMd5 = br.ReadString();
            string curSha = br.ReadString();
            var weights = new SixDimensionWeights
            {
                W_Signature = br.ReadSingle(),
                W_PEMetadata = br.ReadSingle(),
                W_PathTemplate = br.ReadSingle(),
                W_LocationKey = br.ReadSingle(),
                W_CommandArgs = br.ReadSingle(),
                W_ImpAndPHash = br.ReadSingle()
            };

            matchedRule = new RuleRecord
            {
                RuleId = ruleId,
                DisplayName = displayName,
                Category = ruleCat,
                ActionType = actType,
                RuleMode = ruleMode,
                ConfidenceThreshold = threshold,
                EvolutionCount = evoCount,
                HasSignature = hasSig,
                SignerSubject = sigSubj,
                RootCertThumbprint = rootThumb,
                OriginalFilename = origFile,
                ProductName = prodName,
                CompanyName = compName,
                InternalName = intName,
                NormalizedPath = normPath,
                LocationKey = locKey,
                CommandLineArgs = cmdArgs,
                ImpHash = impHash,
                IconPHash = iconPHash,
                CurrentMD5 = curMd5,
                CurrentSHA256 = curSha,
                Weights = weights
            };
        }

        var cat = (MonitorCategory)br.ReadByte();
        string targetBin = br.ReadString();
        string targetNormPath = br.ReadString();
        ulong targetNormHash = br.ReadUInt64();
        string rawCmd = br.ReadString();
        string cmdArgsTemplate = br.ReadString();
        string locKeyId = br.ReadString();
        string md5Hex = br.ReadString();
        string sha256Hex = br.ReadString();
        bool hasValidSig = br.ReadBoolean();
        string signerSubject = br.ReadString();
        string rootCertThumbprint = br.ReadString();
        bool isWhql = br.ReadBoolean();
        string tOrigFile = br.ReadString();
        string tProdName = br.ReadString();
        string tCompName = br.ReadString();
        string tIntName = br.ReadString();
        string tFileDesc = br.ReadString();
        string tImpHash = br.ReadString();
        ulong tIconPHash = br.ReadUInt64();
        uint srcPid = br.ReadUInt32();
        string srcProcName = br.ReadString();
        string oldState = br.ReadString();
        string newState = br.ReadString();
        uint regValType = br.ReadUInt32();
        string tDisplayName = br.ReadString();

        var target = new TargetProgramFeatures
        {
            Category = cat,
            DisplayName = tDisplayName,
            TargetBinaryPath = targetBin,
            NormalizedPath = targetNormPath,
            NormalizedPathHash = targetNormHash,
            RawCommandLine = rawCmd,
            CommandLineArgsTemplate = cmdArgsTemplate,
            LocationKeyOrIdentifier = locKeyId,
            MD5Hex = md5Hex,
            SHA256Hex = sha256Hex,
            HasValidSignature = hasValidSig,
            SignerSubject = signerSubject,
            RootCertThumbprint = rootCertThumbprint,
            IsWhqlCertified = isWhql,
            OriginalFilename = tOrigFile,
            ProductName = tProdName,
            CompanyName = tCompName,
            InternalName = tIntName,
            FileDescription = tFileDesc,
            ImpHash = tImpHash,
            IconPerceptualHash = tIconPHash,
            SourceProcessId = srcPid,
            SourceProcessName = srcProcName,
            OldStateSummary = oldState,
            NewStateSummary = newState,
            RegistryValueType = regValType
        };

        int diffCount = br.ReadInt32();
        var diffs = new List<FeatureDiffItem>(Math.Max(0, diffCount));
        for (int i = 0; i < diffCount; i++)
        {
            diffs.Add(new FeatureDiffItem
            {
                DimensionName = br.ReadString(),
                HistoricalValue = br.ReadString(),
                CurrentValue = br.ReadString(),
                IsMatched = br.ReadBoolean(),
                SimilarityScore = br.ReadDouble()
            });
        }

        return new ConfidenceEvaluationResult
        {
            FinalScore = finalScore,
            MatchedRule = matchedRule,
            CurrentTarget = target,
            Severity = severity,
            DiagnosticOpinion = opinion,
            DiffItems = diffs
        };
    }

    public static byte[] SerializeBatchAlerts(
        IReadOnlyList<ConfidenceEvaluationResult> alerts,
        ulong correlationId = 0)
    {
        using var ms = new MemoryStream(2048);
        using var bw = new BinaryWriter(ms, Encoding.UTF8, leaveOpen: true);

        bw.Write(correlationId);
        bw.Write(alerts.Count);
        for (int i = 0; i < alerts.Count; i++)
        {
            WriteAlertToWriter(bw, correlationId + (ulong)i, alerts[i]);
        }

        bw.Flush();
        return ms.ToArray();
    }

    public static byte[] SerializeBatchAlerts(
        ulong correlationId,
        IReadOnlyList<ConfidenceEvaluationResult> alerts)
        => SerializeBatchAlerts(alerts, correlationId);

    public static List<ConfidenceEvaluationResult> DeserializeBatchAlerts(ReadOnlySpan<byte> payload)
        => DeserializeBatchAlerts(payload, out _);

    public static List<ConfidenceEvaluationResult> DeserializeBatchAlerts(
        ReadOnlySpan<byte> payload,
        out ulong correlationId)
    {
        using var ms = new MemoryStream(payload.ToArray(), writable: false);
        using var br = new BinaryReader(ms, Encoding.UTF8, leaveOpen: true);

        correlationId = br.ReadUInt64();
        int count = br.ReadInt32();
        var list = new List<ConfidenceEvaluationResult>(Math.Max(0, count));
        for (int i = 0; i < count; i++)
        {
            list.Add(ReadAlertFromReader(br, out _));
        }

        return list;
    }

    public static byte[] SerializeMonitorToggles(MonitorTogglesPayload toggles)
    {
        byte[] buffer = new byte[10];
        buffer[0] = toggles.MonitorStartup ? (byte)1 : (byte)0;
        buffer[1] = toggles.MonitorService ? (byte)1 : (byte)0;
        buffer[2] = toggles.MonitorDriver ? (byte)1 : (byte)0;
        buffer[3] = toggles.MonitorScheduledTask ? (byte)1 : (byte)0;
        buffer[4] = toggles.MonitorContextMenu ? (byte)1 : (byte)0;
        buffer[5] = toggles.MonitorWindowsPolicy ? (byte)1 : (byte)0;
        buffer[6] = toggles.BlockNotifications ? (byte)1 : (byte)0;
        buffer[7] = toggles.EnableSound ? (byte)1 : (byte)0;
        buffer[8] = toggles.AutoGameMode ? (byte)1 : (byte)0;
        buffer[9] = toggles.ContextMenuPromptMode ? (byte)1 : (byte)0;
        return buffer;
    }

    public static MonitorTogglesPayload DeserializeMonitorToggles(ReadOnlySpan<byte> payload)
    {
        if (payload.Length < 9)
        {
            return new MonitorTogglesPayload();
        }

        return new MonitorTogglesPayload
        {
            MonitorStartup = payload[0] != 0,
            MonitorService = payload[1] != 0,
            MonitorDriver = payload[2] != 0,
            MonitorScheduledTask = payload[3] != 0,
            MonitorContextMenu = payload[4] != 0,
            MonitorWindowsPolicy = payload[5] != 0,
            BlockNotifications = payload[6] != 0,
            EnableSound = payload[7] != 0,
            AutoGameMode = payload[8] != 0,
            ContextMenuPromptMode = payload.Length >= 10 && payload[9] != 0
        };
    }

    public static byte[] SerializeManualMutation(ManualItemMutationPayload mutation)
    {
        using var ms = new MemoryStream(256);
        using var bw = new BinaryWriter(ms, Encoding.UTF8, leaveOpen: true);

        bw.Write((byte)mutation.Category);
        bw.Write(mutation.LocationKey ?? string.Empty);
        bw.Write(mutation.TargetBinaryPath ?? string.Empty);
        bw.Write((byte)mutation.Action);
        bw.Write(mutation.DisplayName ?? string.Empty);

        bw.Flush();
        return ms.ToArray();
    }

    public static ManualItemMutationPayload DeserializeManualMutation(ReadOnlySpan<byte> payload)
    {
        using var ms = new MemoryStream(payload.ToArray(), writable: false);
        using var br = new BinaryReader(ms, Encoding.UTF8, leaveOpen: true);

        var cat = (MonitorCategory)br.ReadByte();
        string locKey = br.ReadString();
        string binPath = br.ReadString();
        var action = (InterceptionAction)br.ReadByte();
        string displayName = br.ReadString();

        return new ManualItemMutationPayload
        {
            Category = cat,
            LocationKey = locKey,
            TargetBinaryPath = binPath,
            Action = action,
            DisplayName = displayName
        };
    }

    public static byte[] SerializeDecision(UserDecisionPayload decision)
    {
        byte[] targetBytes = Encoding.UTF8.GetBytes(decision.TargetBinaryPath ?? string.Empty);
        byte[] locBytes = Encoding.UTF8.GetBytes(decision.LocationKey ?? string.Empty);
        byte[] nameBytes = Encoding.UTF8.GetBytes(decision.DisplayName ?? string.Empty);

        byte[] buffer = new byte[17 + 2 + targetBytes.Length + 2 + locBytes.Length + 2 + nameBytes.Length];
        Span<byte> span = buffer;
        BinaryPrimitives.WriteUInt64LittleEndian(span[0..8], decision.CorrelationId);
        span[8] = (byte)decision.ChosenAction;
        span[9] = decision.RememberRule ? (byte)1 : (byte)0;
        span[10] = (byte)decision.ChosenRuleMode;
        span[11] = decision.ConfirmedSameSoftwareInGrayZone switch
        {
            null => (byte)0,
            true => (byte)1,
            false => (byte)2
        };
        BinaryPrimitives.WriteInt32LittleEndian(span[12..16], decision.MatchedRuleId);
        span[16] = (byte)decision.Category;

        int offset = 17;
        BinaryPrimitives.WriteUInt16LittleEndian(span.Slice(offset, 2), (ushort)targetBytes.Length);
        offset += 2;
        targetBytes.CopyTo(buffer, offset);
        offset += targetBytes.Length;

        BinaryPrimitives.WriteUInt16LittleEndian(span.Slice(offset, 2), (ushort)locBytes.Length);
        offset += 2;
        locBytes.CopyTo(buffer, offset);
        offset += locBytes.Length;

        BinaryPrimitives.WriteUInt16LittleEndian(span.Slice(offset, 2), (ushort)nameBytes.Length);
        offset += 2;
        nameBytes.CopyTo(buffer, offset);

        return buffer;
    }

    public static UserDecisionPayload DeserializeDecision(ReadOnlySpan<byte> span)
    {
        ulong corrId = BinaryPrimitives.ReadUInt64LittleEndian(span[0..8]);
        var action = (InterceptionAction)span[8];
        bool remember = span[9] != 0;
        var mode = (RuleMatchMode)span[10];
        bool? sameSw = span[11] switch
        {
            1 => true,
            2 => false,
            _ => null
        };
        int ruleId = BinaryPrimitives.ReadInt32LittleEndian(span[12..16]);
        var category = span.Length > 16 ? (MonitorCategory)span[16] : MonitorCategory.StartupItem;
        string targetPath = string.Empty;
        string locKey = string.Empty;
        string dispName = string.Empty;

        if (span.Length >= 23)
        {
            int offset = 17;
            ushort targetLen = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(offset, 2));
            offset += 2;
            if (offset + targetLen <= span.Length)
            {
                targetPath = Encoding.UTF8.GetString(span.Slice(offset, targetLen));
                offset += targetLen;
            }
            if (offset + 2 <= span.Length)
            {
                ushort locLen = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(offset, 2));
                offset += 2;
                if (offset + locLen <= span.Length)
                {
                    locKey = Encoding.UTF8.GetString(span.Slice(offset, locLen));
                    offset += locLen;
                }
            }
            if (offset + 2 <= span.Length)
            {
                ushort nameLen = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(offset, 2));
                offset += 2;
                if (offset + nameLen <= span.Length)
                {
                    dispName = Encoding.UTF8.GetString(span.Slice(offset, nameLen));
                }
            }
        }

        return new UserDecisionPayload
        {
            CorrelationId = corrId,
            ChosenAction = action,
            RememberRule = remember,
            ChosenRuleMode = mode,
            ConfirmedSameSoftwareInGrayZone = sameSw,
            MatchedRuleId = ruleId,
            Category = category,
            TargetBinaryPath = targetPath,
            LocationKey = locKey,
            DisplayName = dispName
        };
    }

    public static byte[] SerializeUserSessionReport(UserSessionReportPayload report)
    {
        byte[] sidBytes = Encoding.UTF8.GetBytes(report.UserSid ?? string.Empty);
        byte[] buffer = new byte[1 + 2 + sidBytes.Length];
        buffer[0] = (byte)(report.InGame ? 1 : 0);
        BinaryPrimitives.WriteUInt16LittleEndian(buffer.AsSpan(1, 2), (ushort)sidBytes.Length);
        sidBytes.CopyTo(buffer, 3);
        return buffer;
    }

    public static UserSessionReportPayload DeserializeUserSessionReport(ReadOnlySpan<byte> span)
    {
        bool inGame = span[0] != 0;
        ushort sidLen = BinaryPrimitives.ReadUInt16LittleEndian(span[1..3]);
        string sid = Encoding.UTF8.GetString(span.Slice(3, sidLen));
        return new UserSessionReportPayload { InGame = inGame, UserSid = sid };
    }

    public static byte[] SerializeAuditRollbackRequest(AuditRollbackRequestPayload req)
    {
        byte[] locBytes = Encoding.UTF8.GetBytes(req.LocationKey ?? string.Empty);
        byte[] oldStateBytes = Encoding.UTF8.GetBytes(req.OldStateSummary ?? string.Empty);
        byte[] buffer = new byte[4 + 1 + 1 + 2 + locBytes.Length + 2 + oldStateBytes.Length + 4 + 1];
        int offset = 0;
        BinaryPrimitives.WriteInt32LittleEndian(buffer.AsSpan(offset, 4), req.AuditLogId);
        offset += 4;
        buffer[offset++] = (byte)req.Category;
        buffer[offset++] = (byte)req.TargetAction;
        BinaryPrimitives.WriteUInt16LittleEndian(buffer.AsSpan(offset, 2), (ushort)locBytes.Length);
        offset += 2;
        locBytes.CopyTo(buffer, offset);
        offset += locBytes.Length;
        BinaryPrimitives.WriteUInt16LittleEndian(buffer.AsSpan(offset, 2), (ushort)oldStateBytes.Length);
        offset += 2;
        oldStateBytes.CopyTo(buffer, offset);
        offset += oldStateBytes.Length;
        BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(offset, 4), req.TargetStartType);
        offset += 4;
        buffer[offset++] = (byte)(req.DelayedAutostart ? 1 : 0);
        return buffer;
    }

    public static AuditRollbackRequestPayload DeserializeAuditRollbackRequest(ReadOnlySpan<byte> span)
    {
        int offset = 0;
        int logId = BinaryPrimitives.ReadInt32LittleEndian(span[offset..(offset + 4)]);
        offset += 4;
        var cat = (MonitorCategory)span[offset++];
        var act = (InterceptionAction)span[offset++];
        ushort locLen = BinaryPrimitives.ReadUInt16LittleEndian(span[offset..(offset + 2)]);
        offset += 2;
        string loc = Encoding.UTF8.GetString(span.Slice(offset, locLen));
        offset += locLen;
        ushort oldLen = BinaryPrimitives.ReadUInt16LittleEndian(span[offset..(offset + 2)]);
        offset += 2;
        string oldState = Encoding.UTF8.GetString(span.Slice(offset, oldLen));
        offset += oldLen;

        uint startType = 4;
        bool delayed = false;
        if (span.Length >= offset + 5)
        {
            startType = BinaryPrimitives.ReadUInt32LittleEndian(span[offset..(offset + 4)]);
            offset += 4;
            delayed = span[offset++] != 0;
        }

        return new AuditRollbackRequestPayload
        {
            AuditLogId = logId,
            Category = cat,
            TargetAction = act,
            LocationKey = loc,
            OldStateSummary = oldState,
            TargetStartType = startType,
            DelayedAutostart = delayed
        };
    }

    public static byte[] SerializeSelfMutationSuppression(SelfMutationSuppressionPayload req)
    {
        byte[] locBytes = Encoding.UTF8.GetBytes(req.LocationKey ?? string.Empty);
        byte[] pathBytes = Encoding.UTF8.GetBytes(req.TargetBinaryPath ?? string.Empty);
        byte[] buffer = new byte[1 + 8 + 2 + locBytes.Length + 2 + pathBytes.Length];
        int offset = 0;
        buffer[offset++] = (byte)req.Category;
        BitConverter.TryWriteBytes(buffer.AsSpan(offset, 8), req.DurationSeconds);
        offset += 8;
        BinaryPrimitives.WriteUInt16LittleEndian(buffer.AsSpan(offset, 2), (ushort)locBytes.Length);
        offset += 2;
        locBytes.CopyTo(buffer, offset);
        offset += locBytes.Length;
        BinaryPrimitives.WriteUInt16LittleEndian(buffer.AsSpan(offset, 2), (ushort)pathBytes.Length);
        offset += 2;
        pathBytes.CopyTo(buffer, offset);
        return buffer;
    }

    public static SelfMutationSuppressionPayload DeserializeSelfMutationSuppression(ReadOnlySpan<byte> span)
    {
        int offset = 0;
        var cat = (MonitorCategory)span[offset++];
        double duration = BitConverter.ToDouble(span.Slice(offset, 8));
        offset += 8;
        ushort locLen = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(offset, 2));
        offset += 2;
        string loc = Encoding.UTF8.GetString(span.Slice(offset, locLen));
        offset += locLen;
        ushort pathLen = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(offset, 2));
        offset += 2;
        string path = Encoding.UTF8.GetString(span.Slice(offset, pathLen));
        return new SelfMutationSuppressionPayload
        {
            Category = cat,
            DurationSeconds = duration > 0 ? duration : 15.0,
            LocationKey = loc,
            TargetBinaryPath = path
        };
    }

    public static void NotifyServiceSuppressSelfMutation(
        string locationKey,
        MonitorCategory category,
        string targetBinaryPath = "",
        double durationSeconds = 15.0)
    {
        if (string.IsNullOrWhiteSpace(locationKey))
            return;

        try
        {
            using var client = new System.IO.Pipes.NamedPipeClientStream(".", "StartupGuard_Control_Pipe", System.IO.Pipes.PipeDirection.InOut);
            client.Connect(800);
            byte[] body = SerializeSelfMutationSuppression(new SelfMutationSuppressionPayload
            {
                LocationKey = locationKey,
                Category = category,
                TargetBinaryPath = targetBinaryPath ?? string.Empty,
                DurationSeconds = durationSeconds
            });
            var hdr = PipeMessageHeader.Create(PipeMessageType.SuppressSelfMutation, (uint)body.Length, 0);
            byte[] hdrBytes = new byte[64];
            WriteHeader(hdrBytes, in hdr);
            client.Write(hdrBytes);
            client.Write(body);
            client.Flush();

            // 同步等待 Service 1 字节 ACK，确保拦截抑制窗口在本地写注册表前已 100% 生效
            client.ReadByte();
        }
        catch
        {
            // 服务未运行或超时时静默继续
        }
    }

    /// <summary>
    /// 将面板手动状态切换（放行/禁用/删除）委托给高权限后台服务执行，并等待 1 字节执行回执
    /// </summary>
    /// <returns>true 表示已成功与后台服务完成交互；false 表示后台服务未连接或未响应</returns>
    public static bool TrySendManualMutation(ManualItemMutationPayload mutation, out bool mutationSucceeded)
    {
        mutationSucceeded = false;
        if (mutation == null || string.IsNullOrWhiteSpace(mutation.LocationKey))
            return false;

        try
        {
            using var client = new System.IO.Pipes.NamedPipeClientStream(".", "StartupGuard_Control_Pipe", System.IO.Pipes.PipeDirection.InOut);
            client.Connect(1200);
            byte[] body = SerializeManualMutation(mutation);
            var hdr = PipeMessageHeader.Create(PipeMessageType.ExecuteManualItemMutation, (uint)body.Length, 0);
            byte[] hdrBytes = new byte[64];
            WriteHeader(hdrBytes, in hdr);
            client.Write(hdrBytes);
            client.Write(body);
            client.Flush();

            int ack = client.ReadByte();
            if (ack == 1 || ack == 2)
            {
                mutationSucceeded = ack == 1;
                return true;
            }
            return false;
        }
        catch
        {
            return false;
        }
    }


    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe void WriteHeader(Span<byte> destination, in PipeMessageHeader header)
    {
        fixed (byte* pDst = destination)
        fixed (PipeMessageHeader* pHdr = &header)
        {
            Buffer.MemoryCopy(pHdr, pDst, 64, 64);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe PipeMessageHeader ReadHeader(ReadOnlySpan<byte> source)
    {
        PipeMessageHeader hdr = default;
        fixed (byte* pSrc = source)
        {
            Buffer.MemoryCopy(pSrc, &hdr, 64, 64);
        }
        return hdr;
    }
}

