using StartupGuard.Core.Scoring;

namespace StartupGuard.Tests.Tier1_FeatureCoverage;

public class PathNormalizationAndSimilarityTests
{
    [Fact]
    public void NormalizeProgramPath_DriveLetter_ReplacedWithPlaceholder()
    {
        string input = @"D:\Tools\ProcessMonitor\procmon.exe";
        string normalized = PathNormalizerAndSimilarity.NormalizeProgramPath(input);
        Assert.StartsWith(@"<drive>:\", normalized);
        Assert.EndsWith(@"procmon.exe", normalized);
    }

    [Fact]
    public void NormalizeProgramPath_UserDirectory_ReplacedWithPlaceholder()
    {
        string input = @"C:\Users\JohnDoe\AppData\Local\Programs\App\app.exe";
        string normalized = PathNormalizerAndSimilarity.NormalizeProgramPath(input);
        Assert.Contains(@"users\<user>\", normalized);
    }

    [Fact]
    public void NormalizeProgramPath_VersionFolder_ReplacedWithPlaceholder()
    {
        string input = @"C:\Users\DemoUser\AppData\Local\Microsoft\OneDrive\26.198.1011.0006\FileSyncShell64.dll";
        string normalized = PathNormalizerAndSimilarity.NormalizeProgramPath(input);
        Assert.Equal(@"<drive>:\users\<user>\appdata\local\microsoft\onedrive\<ver>\filesyncshell64.dll", normalized);
    }

    [Fact]
    public void NormalizeProgramPath_GuidAndHexHash_ReplacedWithPlaceholders()
    {
        string guidInput = @"C:\ProgramData\{12345678-ABCD-1234-CDEF-123456789ABC}\agent.exe";
        string guidNorm = PathNormalizerAndSimilarity.NormalizeProgramPath(guidInput);
        Assert.Contains("<guid>", guidNorm);

        string hashInput = @"C:\AppData\Local\1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d\helper.exe";
        string hashNorm = PathNormalizerAndSimilarity.NormalizeProgramPath(hashInput);
        Assert.Contains(@"\<hash>\", hashNorm);
    }

    [Fact]
    public void SplitCommandLine_PlainAndQuotedPaths_ParsedCorrectly()
    {
        var (exe1, args1) = PathNormalizerAndSimilarity.SplitCommandLine(@"C:\Windows\System32\notepad.exe C:\test.txt");
        Assert.Equal(@"C:\Windows\System32\notepad.exe", exe1);
        Assert.Equal("c:\\test.txt", args1);

        var (exe2, args2) = PathNormalizerAndSimilarity.SplitCommandLine(@"""C:\Program Files\Git\bin\git.exe"" status --short");
        Assert.Equal(@"C:\Program Files\Git\bin\git.exe", exe2);
        Assert.Equal("--short", args2);
    }

    [Fact]
    public void SplitCommandLine_Rundll32Wrapper_UnwrapsTargetDll()
    {
        string cmd = @"rundll32.exe ""C:\Program Files\Vendor\Plugin.dll"",DllRegisterServer -silent";
        var (exe, args) = PathNormalizerAndSimilarity.SplitCommandLine(cmd);
        Assert.Equal(@"C:\Program Files\Vendor\Plugin.dll", exe);
        Assert.Contains("-silent", args);
    }

    [Fact]
    public void SplitCommandLine_CmdAndPowershellWrappers_UnwrapsInnerScriptOrExecutable()
    {
        string cmdWrapper = @"cmd.exe /c ""C:\Tools\deploy.bat"" /quiet";
        var (exe1, args1) = PathNormalizerAndSimilarity.SplitCommandLine(cmdWrapper);
        Assert.Equal(@"C:\Tools\deploy.bat", exe1);
        Assert.Equal("/quiet", args1);

        string psWrapper = @"powershell.exe -ExecutionPolicy Bypass -File C:\Scripts\audit.ps1 -Full";
        var (exe2, args2) = PathNormalizerAndSimilarity.SplitCommandLine(psWrapper);
        Assert.Equal(@"C:\Scripts\audit.ps1", exe2);
        Assert.Contains("-executionpolicy", args2);
    }

    [Fact]
    public void SplitCommandLine_WscriptAndCscript_UnwrapsScript()
    {
        string wscriptCmd = @"wscript.exe //B //nologo C:\Windows\System32\slmgr.vbs /dli";
        var (exe, args) = PathNormalizerAndSimilarity.SplitCommandLine(wscriptCmd);
        Assert.Equal(@"C:\Windows\System32\slmgr.vbs", exe);
        Assert.Equal("/dli", args);
    }

    [Fact]
    public void ComputeJaroWinkler_IdenticalAndSimilarStrings_EvaluatedCorrectly()
    {
        Assert.Equal(1.0, PathNormalizerAndSimilarity.ComputeJaroWinkler("same", "same"));
        Assert.Equal(0.0, PathNormalizerAndSimilarity.ComputeJaroWinkler(string.Empty, "text"));

        double simHigh = PathNormalizerAndSimilarity.ComputeJaroWinkler(
            @"<drive>:\program files\everything\everything.exe",
            @"<drive>:\program files\everything_v2\everything.exe");
        Assert.True(simHigh >= 0.85, $"Expected >= 0.85 but got {simHigh}");

        double simLow = PathNormalizerAndSimilarity.ComputeJaroWinkler(
            "everything.exe",
            "acpi.sys");
        Assert.True(simLow < 0.60, $"Expected < 0.60 but got {simLow}");
        Assert.True(simHigh > simLow);
    }

    [Fact]
    public void ComputeArgsJaccard_OrderInvariant_ComputesAccurateIntersectionOverUnion()
    {
        string argsA = "-svc -update -background";
        string argsB = "-background -svc -update";
        Assert.Equal(1.0, PathNormalizerAndSimilarity.ComputeArgsJaccard(argsA, argsB));

        string argsPartial = "-svc -debug";
        // setA: { -svc, -update, -background }, setB: { -svc, -debug }
        // intersection: { -svc } (1), union: { -svc, -update, -background, -debug } (4) -> 0.25
        double jaccard = PathNormalizerAndSimilarity.ComputeArgsJaccard(argsA, argsPartial);
        Assert.Equal(0.25, jaccard, 3);

        Assert.Equal(1.0, PathNormalizerAndSimilarity.ComputeArgsJaccard(string.Empty, string.Empty));
        Assert.Equal(0.0, PathNormalizerAndSimilarity.ComputeArgsJaccard("-a", "-b"));
    }
}
