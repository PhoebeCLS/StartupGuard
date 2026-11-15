using StartupGuard.Core.Ipc;
using StartupGuard.Core.Models;
using StartupGuard.Core.Native;
using StartupGuard.Core.Scoring;
using StartupGuard.Core.Storage;
using StartupGuard.Tests.TestHelpers;

namespace StartupGuard.Tests.Tier2_BoundaryAndCornerCases;

public class BoundaryAndCornerCasesTests : IDisposable
{
    private readonly SqliteRuleRepository _repository;
    private readonly string _tempDbPath;

    public BoundaryAndCornerCasesTests()
    {
        _repository = TestModelHelpers.CreateTemporarySqliteRepository(out _tempDbPath);
    }

    public void Dispose()
    {
        _repository.Dispose();
        try { if (File.Exists(_tempDbPath)) File.Delete(_tempDbPath); } catch { }
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    public void NormalizeProgramPath_NullOrWhitespace_ReturnsEmptyString(string? input)
    {
        string result = PathNormalizerAndSimilarity.NormalizeProgramPath(input!);
        Assert.Equal(string.Empty, result);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    public void SplitCommandLine_NullOrWhitespace_ReturnsEmptyTuple(string? input)
    {
        var (exe, args) = PathNormalizerAndSimilarity.SplitCommandLine(input!);
        Assert.Equal(string.Empty, exe);
        Assert.Equal(string.Empty, args);
    }

    [Fact]
    public void SplitCommandLine_MalformedUnclosedQuote_HandlesGracefully()
    {
        string malformed = "\"C:\\Program Files\\Broken Path\\app.exe -arg1 -arg2";
        var (exe, args) = PathNormalizerAndSimilarity.SplitCommandLine(malformed);
        Assert.NotEmpty(exe);
    }

    [Fact]
    public void NormalizeProgramPath_ExtremePathLength_HandlesWithoutException()
    {
        string veryLongDirectory = new('a', 1500);
        string longPath = $@"C:\Users\JohnDoe\AppData\Local\{veryLongDirectory}\test.exe";
        string result = PathNormalizerAndSimilarity.NormalizeProgramPath(longPath);
        Assert.Contains(@"users\<user>\", result);
        Assert.EndsWith("test.exe", result);
    }

    [Fact]
    public void JaroWinkler_ExtremeStringLengths_HandlesGracefully()
    {
        string longA = new('x', 2000);
        string longB = new('x', 2000);
        double sim = PathNormalizerAndSimilarity.ComputeJaroWinkler(longA, longB);
        Assert.Equal(1.0, sim);
    }

    [Fact]
    public void ConfidenceScoringEngine_MultipleNegativeFeedbacks_ThresholdCappedAt95()
    {
        var rule = TestModelHelpers.CreateSampleRule(threshold: 85.0f);
        rule.RuleId = _repository.InsertOrUpdateRule(rule);
        var engine = new ConfidenceScoringEngine(_repository);

        var diffs = new List<FeatureDiffItem>
        {
            new() { DimensionName = "签名", HistoricalValue = "A", CurrentValue = "B", IsMatched = false, SimilarityScore = 0.0 }
        };

        // Apply negative feedback 5 times (+5 each time: 85 -> 90 -> 95 -> cap at 95)
        for (int i = 0; i < 5; i++)
        {
            var target = TestModelHelpers.CreateSampleTarget(md5: $"REJECTED_{i}_{Guid.NewGuid():N}");
            engine.ApplyUserFeedbackReinforcement(rule, target, diffs, confirmedSameSoftware: false);
        }

        Assert.Equal(95.0f, rule.ConfidenceThreshold);
    }

    [Fact]
    public void MmfBinaryStore_CorruptOrTruncatedFile_LoadFailsGracefully()
    {
        string tempMmf = TestModelHelpers.CreateTempFilePath(".bin");
        try
        {
            // Write fewer than 64 bytes (truncated header)
            File.WriteAllBytes(tempMmf, new byte[32]);

            using var store = new MmfBinaryStore(tempMmf);
            bool loaded = store.LoadIntoMemory();
            Assert.False(loaded);
            Assert.Equal(0, store.Count);

            // Write 64 bytes with corrupt Magic
            byte[] corruptHeader = new byte[64];
            corruptHeader[0] = 0xFF; corruptHeader[1] = 0xFF;
            File.WriteAllBytes(tempMmf, corruptHeader);

            using var store2 = new MmfBinaryStore(tempMmf);
            bool loaded2 = store2.LoadIntoMemory();
            Assert.False(loaded2);
            Assert.Equal(0, store2.Count);
        }
        finally
        {
            try { File.Delete(tempMmf); } catch { }
        }
    }

    [Fact]
    public void NamedPipeProtocol_InvalidMagicOrVersion_FlagsInvalidHeader()
    {
        var invalidHdr = new PipeMessageHeader
        {
            Magic = 0x12345678, // Invalid
            Version = 99,
            MessageType = PipeMessageType.Heartbeat
        };

        Assert.False(invalidHdr.IsValid);
    }

    [Fact]
    public void NamedPipeProtocol_TruncatedPayloads_DoNotCrashDeserializers()
    {
        byte[] emptySpan = [];

        var decision = BinaryPipeSerializer.DeserializeDecision(new byte[16]);
        Assert.Equal(0UL, decision.CorrelationId);
        Assert.Equal(InterceptionAction.Allow, decision.ChosenAction);

        var toggles = BinaryPipeSerializer.DeserializeMonitorToggles(emptySpan);
        Assert.NotNull(toggles);
    }

    [Fact]
    public void NativeSecurityExtractor_TruncatedAndNonPeFiles_HandledSafely()
    {
        string tempFile = TestModelHelpers.CreateTempFilePath(".dat");
        try
        {
            // 1. Empty file
            File.WriteAllBytes(tempFile, []);
            var (imp1, icon1) = NativeSecurityExtractor.ExtractPeImportAndIconHashes(tempFile);
            Assert.Empty(imp1);
            Assert.Equal(0UL, icon1);

            // 2. File with only "MZ" but no PE header
            File.WriteAllBytes(tempFile, [0x4D, 0x5A, 0x00, 0x00]);
            var (imp2, icon2) = NativeSecurityExtractor.ExtractPeImportAndIconHashes(tempFile);
            Assert.Empty(imp2);
            Assert.Equal(0UL, icon2);

            // 3. Authenticode extraction on arbitrary non-PE text file
            File.WriteAllText(tempFile, "This is not a PE file");
            var (hasSig, subject, thumb) = NativeSecurityExtractor.ExtractAuthenticodeDetails(tempFile);
            Assert.False(hasSig);
            Assert.Empty(subject);
            Assert.Empty(thumb);
        }
        finally
        {
            try { File.Delete(tempFile); } catch { }
        }
    }
}
