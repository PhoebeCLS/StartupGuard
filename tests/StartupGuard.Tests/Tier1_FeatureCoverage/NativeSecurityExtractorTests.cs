using System.Security.Cryptography;
using System.Text;
using StartupGuard.Core.Models;
using StartupGuard.Core.Native;
using StartupGuard.Tests.TestHelpers;

namespace StartupGuard.Tests.Tier1_FeatureCoverage;

public class NativeSecurityExtractorTests
{
    [Fact]
    public void ComputeFileHashesCng_CalculatesAccurateMd5AndSha256()
    {
        string tempFile = TestModelHelpers.CreateTempFilePath(".txt");
        try
        {
            byte[] content = "StartupGuard Security Engine Test Payload"u8.ToArray();
            File.WriteAllBytes(tempFile, content);

            var (md5, sha256) = NativeSecurityExtractor.ComputeFileHashesCng(tempFile);

            string expectedMd5 = Convert.ToHexStringLower(MD5.HashData(content));
            string expectedSha256 = Convert.ToHexStringLower(SHA256.HashData(content));

            Assert.Equal(expectedMd5, md5.ToLowerInvariant());
            Assert.Equal(expectedSha256, sha256.ToLowerInvariant());
        }
        finally
        {
            try { File.Delete(tempFile); } catch { }
        }
    }

    [Fact]
    public void ComputeFileHashesCng_NonExistentFile_ReturnsEmpty()
    {
        var (md5, sha256) = NativeSecurityExtractor.ComputeFileHashesCng(@"C:\NonExistent\file.txt");
        Assert.Empty(md5);
        Assert.Empty(sha256);
    }

    [Fact]
    public void ExtractPeImportAndIconHashes_SyntheticPeWithImports_ExtractsDeterministicImpHash()
    {
        var imports = new (string DllName, string[] Functions)[]
        {
            ("kernel32.dll", ["CreateFileW", "ExitProcess"]),
            ("user32.dll", ["MessageBoxW"])
        };

        byte[] iconData = SyntheticPeBuilder.GenerateMockIconBytes(100);
        byte[] peBytes = SyntheticPeBuilder.BuildSyntheticPe64(imports, iconData);

        string tempPe = TestModelHelpers.CreateTempFilePath(".exe");
        try
        {
            File.WriteAllBytes(tempPe, peBytes);

            var (impHash, iconPHash) = NativeSecurityExtractor.ExtractPeImportAndIconHashes(tempPe);

            Assert.NotEmpty(impHash);
            Assert.Equal(32, impHash.Length);
            Assert.NotEqual(0UL, iconPHash);

            // Compute expected impHash: md5 of "kernel32.createfilew,kernel32.exitprocess,user32.messageboxw"
            string expectedImpStr = "kernel32.createfilew,kernel32.exitprocess,user32.messageboxw";
            string expectedImpHash = Convert.ToHexStringLower(MD5.HashData(Encoding.ASCII.GetBytes(expectedImpStr)));
            Assert.Equal(expectedImpHash, impHash.ToLowerInvariant());
        }
        finally
        {
            try { File.Delete(tempPe); } catch { }
        }
    }

    [Fact]
    public void ComputeIconPerceptualHashFromBytes_SameBytes_YieldsIdenticalHash()
    {
        byte[] icon1 = SyntheticPeBuilder.GenerateMockIconBytes(150);
        byte[] icon2 = SyntheticPeBuilder.GenerateMockIconBytes(150);
        byte[] iconDifferent = SyntheticPeBuilder.GenerateMockIconBytes(50);

        ulong hash1 = NativeSecurityExtractor.ComputeIconPerceptualHashFromBytes(icon1);
        ulong hash2 = NativeSecurityExtractor.ComputeIconPerceptualHashFromBytes(icon2);
        ulong hashDiff = NativeSecurityExtractor.ComputeIconPerceptualHashFromBytes(iconDifferent);

        Assert.NotEqual(0UL, hash1);
        Assert.Equal(hash1, hash2);
        // Different luminance patterns produce different hashes
        Assert.NotEqual(hash1, hashDiff);
    }

    [Fact]
    public void ExtractAuthenticodeDetails_SyntheticPeWithEmbeddedCert_ExtractsSubject()
    {
        using var cert = SyntheticPeBuilder.GenerateSelfSignedCertificate("StartupGuard Security Root");
        byte[] peBytes = SyntheticPeBuilder.BuildSyntheticPe64(imports: null, iconBytes: null, cert: cert);

        string tempPe = TestModelHelpers.CreateTempFilePath(".dll");
        try
        {
            File.WriteAllBytes(tempPe, peBytes);

            var (hasValidSig, signerSubject, rootThumb) = NativeSecurityExtractor.ExtractAuthenticodeDetails(tempPe);

            Assert.True(hasValidSig);
            Assert.Contains("StartupGuard Security Root", signerSubject);
            Assert.NotEmpty(rootThumb);
        }
        finally
        {
            try { File.Delete(tempPe); } catch { }
        }
    }

    [Fact]
    public void BuildTargetProgramFeatures_ValidBinary_PopulatesAll6DDimensions()
    {
        var imports = new (string DllName, string[] Functions)[]
        {
            ("advapi32.dll", ["RegOpenKeyExW", "RegCloseKey"])
        };
        byte[] peBytes = SyntheticPeBuilder.BuildSyntheticPe64(imports);

        string tempBin = TestModelHelpers.CreateTempFilePath(".exe");
        try
        {
            File.WriteAllBytes(tempBin, peBytes);

            string rawCommand = $@"""{tempBin}"" --daemon -v";
            var features = NativeSecurityExtractor.BuildTargetProgramFeatures(
                rawCommandLine: rawCommand,
                locationKey: @"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\MyDaemon",
                category: MonitorCategory.StartupItem,
                displayName: "MyDaemon",
                sourcePid: 4567,
                sourceProcessName: "updater.exe");

            Assert.Equal(tempBin, features.TargetBinaryPath);
            Assert.NotEmpty(features.NormalizedPath);
            Assert.NotEqual(0UL, features.NormalizedPathHash);
            Assert.Equal(rawCommand, features.RawCommandLine);
            Assert.Contains("--daemon", features.CommandLineArgsTemplate);
            Assert.NotEmpty(features.MD5Hex);
            Assert.NotEmpty(features.SHA256Hex);
            Assert.NotEmpty(features.ImpHash);
            Assert.Equal(4567u, features.SourceProcessId);
            Assert.Equal("updater.exe", features.SourceProcessName);
        }
        finally
        {
            try { File.Delete(tempBin); } catch { }
        }
    }
}
