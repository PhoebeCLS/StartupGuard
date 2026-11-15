using System.Runtime.InteropServices;
using StartupGuard.Core.Ipc;
using StartupGuard.Core.Models;
using StartupGuard.Tests.TestHelpers;

namespace StartupGuard.Tests.Tier1_FeatureCoverage;

public class NamedPipeProtocolTests
{
    [Fact]
    public void PipeMessageHeader_BlittableSize_MustBeExactly64Bytes()
    {
        Assert.Equal(64, Marshal.SizeOf<PipeMessageHeader>());
    }

    [Fact]
    public void PipeMessageHeader_CreateAndValidate_SetsMagicAndVersion()
    {
        var hdr = PipeMessageHeader.Create(
            type: PipeMessageType.InterceptionAlertRequest,
            payloadLen: 1024,
            correlationId: 0xDEADBEEFCAFEBABEUL,
            sessionId: 1);

        Assert.Equal(PipeMessageHeader.MagicValue, hdr.Magic);
        Assert.Equal(PipeMessageHeader.CurrentProtocolVersion, hdr.Version);
        Assert.Equal(PipeMessageType.InterceptionAlertRequest, hdr.MessageType);
        Assert.Equal(1024u, hdr.PayloadLength);
        Assert.Equal(0xDEADBEEFCAFEBABEUL, hdr.CorrelationId);
        Assert.Equal(1u, hdr.SourceSessionId);
        Assert.True(hdr.IsValid);

        // Header byte round-trip
        Span<byte> buffer = stackalloc byte[64];
        BinaryPipeSerializer.WriteHeader(buffer, in hdr);
        var readHdr = BinaryPipeSerializer.ReadHeader(buffer);

        Assert.Equal(hdr.Magic, readHdr.Magic);
        Assert.Equal(hdr.Version, readHdr.Version);
        Assert.Equal(hdr.MessageType, readHdr.MessageType);
        Assert.Equal(hdr.PayloadLength, readHdr.PayloadLength);
        Assert.Equal(hdr.CorrelationId, readHdr.CorrelationId);
        Assert.Equal(hdr.SourceSessionId, readHdr.SourceSessionId);
    }

    [Fact]
    public void SerializeAlert_DeserializeAlert_RoundTripPreservesAllFields()
    {
        var target = TestModelHelpers.CreateSampleTarget();
        var rule = TestModelHelpers.CreateSampleRule();
        var alert = new ConfidenceEvaluationResult
        {
            FinalScore = 78.5,
            MatchedRule = rule,
            CurrentTarget = target,
            Severity = DiagnosticSeverity.LikelySameSoftware,
            DiagnosticOpinion = "Diff Opinion Text",
            DiffItems =
            [
                new FeatureDiffItem
                {
                    DimensionName = "F1 签名",
                    HistoricalValue = "voidtools",
                    CurrentValue = "voidtools",
                    IsMatched = true,
                    SimilarityScore = 1.0
                },
                new FeatureDiffItem
                {
                    DimensionName = "F3 路径",
                    HistoricalValue = "<drive>:\\path1",
                    CurrentValue = "<drive>:\\path2",
                    IsMatched = false,
                    SimilarityScore = 0.65
                }
            ]
        };

        ulong correlationId = 987654321UL;
        byte[] payload = BinaryPipeSerializer.SerializeAlert(alert, correlationId);
        Assert.NotNull(payload);
        Assert.True(payload.Length > 0);

        var deserialized = BinaryPipeSerializer.DeserializeAlert(payload, out ulong readCorrId);
        Assert.Equal(correlationId, readCorrId);
        Assert.Equal(alert.FinalScore, deserialized.FinalScore, 2);
        Assert.Equal(alert.Severity, deserialized.Severity);
        Assert.Equal(alert.DiagnosticOpinion, deserialized.DiagnosticOpinion);
        Assert.NotNull(deserialized.MatchedRule);
        Assert.Equal(rule.RuleId, deserialized.MatchedRule.RuleId);
        Assert.Equal(rule.DisplayName, deserialized.MatchedRule.DisplayName);
        Assert.Equal(target.TargetBinaryPath, deserialized.CurrentTarget.TargetBinaryPath);
        Assert.Equal(target.MD5Hex, deserialized.CurrentTarget.MD5Hex);
        Assert.Equal(2, deserialized.DiffItems.Count);
        Assert.Equal("F1 签名", deserialized.DiffItems[0].DimensionName);
        Assert.True(deserialized.DiffItems[0].IsMatched);
        Assert.False(deserialized.DiffItems[1].IsMatched);
    }

    [Fact]
    public void SerializeDecision_DeserializeDecision_RoundTripPreservesGrayZoneChoice()
    {
        var decision = new UserDecisionPayload
        {
            CorrelationId = 0x1122334455667788UL,
            ChosenAction = InterceptionAction.RollbackToDisabled,
            RememberRule = true,
            ChosenRuleMode = RuleMatchMode.PermanentAdaptive,
            ConfirmedSameSoftwareInGrayZone = true,
            MatchedRuleId = 15
        };

        byte[] bytes = BinaryPipeSerializer.SerializeDecision(decision);
        var read = BinaryPipeSerializer.DeserializeDecision(bytes);

        Assert.Equal(decision.CorrelationId, read.CorrelationId);
        Assert.Equal(decision.ChosenAction, read.ChosenAction);
        Assert.Equal(decision.RememberRule, read.RememberRule);
        Assert.Equal(decision.ChosenRuleMode, read.ChosenRuleMode);
        Assert.Equal(decision.ConfirmedSameSoftwareInGrayZone, read.ConfirmedSameSoftwareInGrayZone);
        Assert.Equal(decision.MatchedRuleId, read.MatchedRuleId);
    }

    [Fact]
    public void SerializeBatchAlerts_DeserializeBatchAlerts_RoundTripPreservesMultipleAlerts()
    {
        var alerts = new List<ConfidenceEvaluationResult>
        {
            new()
            {
                FinalScore = 100.0,
                CurrentTarget = TestModelHelpers.CreateSampleTarget(targetBin: "app1.exe"),
                Severity = DiagnosticSeverity.LikelySameSoftware,
                DiagnosticOpinion = "Op1"
            },
            new()
            {
                FinalScore = 42.0,
                CurrentTarget = TestModelHelpers.CreateSampleTarget(targetBin: "app2.exe"),
                Severity = DiagnosticSeverity.CriticalSignatureLost,
                DiagnosticOpinion = "Op2"
            }
        };

        ulong correlationId = 12345UL;
        byte[] batchBytes = BinaryPipeSerializer.SerializeBatchAlerts(alerts, correlationId);
        var deserializedBatch = BinaryPipeSerializer.DeserializeBatchAlerts(batchBytes, out ulong readId);

        Assert.Equal(correlationId, readId);
        Assert.Equal(2, deserializedBatch.Count);
        Assert.Equal(100.0, deserializedBatch[0].FinalScore);
        Assert.Equal(42.0, deserializedBatch[1].FinalScore);
        Assert.Equal("app1.exe", deserializedBatch[0].CurrentTarget.TargetBinaryPath);
        Assert.Equal("app2.exe", deserializedBatch[1].CurrentTarget.TargetBinaryPath);
    }

    [Fact]
    public void SerializeMonitorToggles_DeserializeMonitorToggles_Preserves9CategoryFlags()
    {
        var toggles = new MonitorTogglesPayload
        {
            MonitorStartup = true,
            MonitorService = false,
            MonitorDriver = true,
            MonitorScheduledTask = false,
            MonitorContextMenu = true,
            MonitorWindowsPolicy = false,
            BlockNotifications = true,
            EnableSound = false,
            AutoGameMode = true
        };

        byte[] bytes = BinaryPipeSerializer.SerializeMonitorToggles(toggles);
        Assert.Equal(10, bytes.Length);

        var restored = BinaryPipeSerializer.DeserializeMonitorToggles(bytes);
        Assert.True(restored.MonitorStartup);
        Assert.False(restored.MonitorService);
        Assert.True(restored.MonitorDriver);
        Assert.False(restored.MonitorScheduledTask);
        Assert.True(restored.MonitorContextMenu);
        Assert.False(restored.MonitorWindowsPolicy);
        Assert.True(restored.BlockNotifications);
        Assert.False(restored.EnableSound);
        Assert.True(restored.AutoGameMode);
        Assert.False(restored.ContextMenuPromptMode);
    }

    [Fact]
    public void SerializeManualMutation_DeserializeManualMutation_RoundTripPreservesPayload()
    {
        var mutation = new ManualItemMutationPayload
        {
            Category = MonitorCategory.Win32Service,
            LocationKey = "SYSTEM\\CurrentControlSet\\Services\\TestSvc",
            TargetBinaryPath = @"C:\Windows\System32\svchost.exe",
            Action = InterceptionAction.RollbackToDemand,
            DisplayName = "Test Svc"
        };

        byte[] bytes = BinaryPipeSerializer.SerializeManualMutation(mutation);
        var restored = BinaryPipeSerializer.DeserializeManualMutation(bytes);

        Assert.Equal(mutation.Category, restored.Category);
        Assert.Equal(mutation.LocationKey, restored.LocationKey);
        Assert.Equal(mutation.TargetBinaryPath, restored.TargetBinaryPath);
        Assert.Equal(mutation.Action, restored.Action);
        Assert.Equal(mutation.DisplayName, restored.DisplayName);
    }
}
