using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using StartupGuard.Core.Models;
using StartupGuard.Core.Storage;

namespace StartupGuard.Tests.TestHelpers;

public static class TestModelHelpers
{
    public static string CreateTempFilePath(string extension = ".tmp")
    {
        string dir = Path.Combine(Path.GetTempPath(), "StartupGuardTests_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return Path.Combine(dir, "testfile_" + Guid.NewGuid().ToString("N") + extension);
    }

    public static SqliteRuleRepository CreateTemporarySqliteRepository(out string tempDbPath)
    {
        tempDbPath = CreateTempFilePath(".db");
        return new SqliteRuleRepository(tempDbPath);
    }

    public static MmfBinaryStore CreateTemporaryMmfStore(out string tempMmfPath)
    {
        tempMmfPath = CreateTempFilePath(".bin");
        return new MmfBinaryStore(tempMmfPath);
    }

    public static RuleRecord CreateSampleRule(
        int id = 0,
        string name = "Everything",
        MonitorCategory category = MonitorCategory.StartupItem,
        InterceptionAction action = InterceptionAction.Allow,
        RuleMatchMode mode = RuleMatchMode.PermanentAdaptive,
        float threshold = 85.0f,
        bool hasSig = true,
        string signer = "voidtools",
        string rootThumb = "3A1F45CD78E102938475AABBCCDDEEFF11223344",
        string origFile = "Everything.exe",
        string prodName = "Everything",
        string normPath = @"<drive>:\program files\everything\everything.exe",
        string location = @"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\Everything",
        string args = "-svc",
        string md5 = "112233445566778899AABBCCDDEEFF00",
        string sha256 = "112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00",
        string impHash = "c7482381283712837128371283712837",
        ulong iconPHash = 0x1234567890ABCDEF)
    {
        return new RuleRecord
        {
            RuleId = id,
            DisplayName = name,
            Category = category,
            ActionType = action,
            RuleMode = mode,
            ConfidenceThreshold = threshold,
            EvolutionCount = 0,
            HasSignature = hasSig,
            SignerSubject = signer,
            RootCertThumbprint = rootThumb,
            OriginalFilename = origFile,
            ProductName = prodName,
            CompanyName = signer,
            InternalName = origFile,
            NormalizedPath = normPath,
            RawCommand = $@"""C:\Program Files\Everything\Everything.exe"" {args}",
            LocationKey = location,
            CommandLineArgs = args,
            ImpHash = impHash,
            IconPHash = iconPHash,
            CurrentMD5 = md5,
            CurrentSHA256 = sha256,
            Weights = SixDimensionWeights.CreateDefault(),
            UpdatedAt = DateTime.UtcNow
        };
    }

    public static TargetProgramFeatures CreateSampleTarget(
        string targetBin = @"C:\Program Files\Everything\Everything.exe",
        string normPath = @"<drive>:\program files\everything\everything.exe",
        string rawCmd = @"""C:\Program Files\Everything\Everything.exe"" -svc",
        string args = "-svc",
        string locKey = @"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\Everything",
        MonitorCategory category = MonitorCategory.StartupItem,
        string md5 = "112233445566778899AABBCCDDEEFF00",
        string sha256 = "112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00",
        bool hasSig = true,
        string signer = "voidtools",
        string rootThumb = "3A1F45CD78E102938475AABBCCDDEEFF11223344",
        string origFile = "Everything.exe",
        string prodName = "Everything",
        string impHash = "c7482381283712837128371283712837",
        ulong iconPHash = 0x1234567890ABCDEF)
    {
        return new TargetProgramFeatures
        {
            Category = category,
            TargetBinaryPath = targetBin,
            NormalizedPath = normPath,
            NormalizedPathHash = MmfBinaryStore.ComputeFnv1a64(normPath),
            RawCommandLine = rawCmd,
            CommandLineArgsTemplate = args,
            LocationKeyOrIdentifier = locKey,
            MD5Hex = md5,
            SHA256Hex = sha256,
            HasValidSignature = hasSig,
            SignerSubject = signer,
            RootCertThumbprint = rootThumb,
            IsWhqlCertified = hasSig && category == MonitorCategory.KernelDriver,
            OriginalFilename = origFile,
            ProductName = prodName,
            CompanyName = signer,
            InternalName = origFile,
            FileDescription = $"{prodName} Service",
            ImpHash = impHash,
            IconPerceptualHash = iconPHash,
            SourceProcessId = 1234,
            SourceProcessName = "setup.exe",
            OldStateSummary = "None",
            NewStateSummary = rawCmd,
            RegistryValueType = 1
        };
    }
}
