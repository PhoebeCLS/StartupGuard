using Microsoft.Win32;
using StartupGuard.Core.Configuration;
using StartupGuard.Core.ContextMenu;
using StartupGuard.Core.Ipc;
using StartupGuard.Core.Models;
using StartupGuard.Core.Native;
using StartupGuard.Core.Scoring;
using StartupGuard.Tests.TestHelpers;
using Xunit;

namespace StartupGuard.Tests.Tier1_FeatureCoverage;

public sealed class Feedback16RegressionTests
{
    [Fact]
    public void UserSettingsStore_SplitNotificationSettings_Roundtrip()
    {
        bool prevRuleHit = UserSettingsStore.GetRuleHitNotificationsEnabled();
        bool prevContextMenu = UserSettingsStore.GetContextMenuNotificationsEnabled();
        try
        {
            UserSettingsStore.SetRuleHitNotificationsEnabled(false);
            UserSettingsStore.SetContextMenuNotificationsEnabled(true);
            Assert.False(UserSettingsStore.GetRuleHitNotificationsEnabled());
            Assert.True(UserSettingsStore.GetContextMenuNotificationsEnabled());
            Assert.True(UserSettingsStore.GetBlockedNotificationsEnabled());

            UserSettingsStore.SetContextMenuNotificationsEnabled(false);
            Assert.False(UserSettingsStore.GetRuleHitNotificationsEnabled());
            Assert.False(UserSettingsStore.GetContextMenuNotificationsEnabled());
            Assert.False(UserSettingsStore.GetBlockedNotificationsEnabled());
        }
        finally
        {
            UserSettingsStore.SetRuleHitNotificationsEnabled(prevRuleHit);
            UserSettingsStore.SetContextMenuNotificationsEnabled(prevContextMenu);
        }
    }

    [Fact]
    public void UwpStartupScanner_FirstPartyAndPublisherResolution_WorksCorrectly()
    {
        Assert.Equal("Microsoft Corporation", UwpStartupScanner.ResolvePublisherFromPfn("Microsoft.Todos_8wekyb3d8bbwe"));
        Assert.True(UwpStartupScanner.IsFirstPartyMicrosoftUwpPackage(
            @"HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\MicrosoftWindows.Client.WebExperience_cw5n1h2txyewy\StartupTask::State",
            string.Empty));

        string thirdPartyPublisher = UwpStartupScanner.ResolvePublisherFromPfn("Contoso.SampleHotkeyOSD_x12345");
        Assert.Contains("Contoso", thirdPartyPublisher);
        Assert.False(UwpStartupScanner.IsFirstPartyMicrosoftUwpPackage(
            @"HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\Contoso.SampleHotkeyOSD_x12345\StartupId::State",
            thirdPartyPublisher));
    }

    [Fact]
    public void PrivilegedRollbackEngine_UwpAndActionLocalization_WorksCorrectly()
    {
        Assert.True(PrivilegedRollbackEngine.IsUwpStartupLocation(
            @"HKU\S-1-5-21-1000\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\App_123\Task::State"));
        Assert.False(PrivilegedRollbackEngine.IsUwpStartupLocation(
            @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run::Demo"));

        Assert.Equal("放行启用", PrivilegedRollbackEngine.DescribeActionShortChinese(InterceptionAction.Allow));
        Assert.Equal("设为手动", PrivilegedRollbackEngine.DescribeActionShortChinese(InterceptionAction.RollbackToDemand));
        Assert.Equal("延迟启动", PrivilegedRollbackEngine.DescribeActionShortChinese(InterceptionAction.RollbackToDelayedAuto));
        Assert.Equal("禁止启动", PrivilegedRollbackEngine.DescribeActionShortChinese(InterceptionAction.RollbackToDisabled));
        Assert.Equal("删除移除", PrivilegedRollbackEngine.DescribeActionShortChinese(InterceptionAction.DeleteEntry));
        Assert.Equal("恢复原状", PrivilegedRollbackEngine.DescribeActionShortChinese(InterceptionAction.RestorePreviousSnapshot));

        var (hive, subKey, valueName) = PrivilegedRollbackEngine.SplitRegistryLocation(
            @"HKLM\SOFTWARE\Classes\Folder\shellex\ContextMenuHandlers\Sample Context Menu ShellExtension",
            null);
        Assert.Equal(PrivilegedRollbackEngine.HKEY_LOCAL_MACHINE, hive);
        Assert.Equal(@"SOFTWARE\Classes\Folder\shellex\ContextMenuHandlers\Sample Context Menu ShellExtension", subKey);
        Assert.Equal(string.Empty, valueName);
    }

    [Fact]
    public void ContextMenuAndVerifyRollbackState_ClassicHandlerDefaultPrefix_VerifiedAccurately()
    {
        if (!OperatingSystem.IsWindows())
            return;

        string uniqueRoot = $@"Software\StartupGuard_UnitTest_{Guid.NewGuid():N}";
        string handlerSubKey = $@"{uniqueRoot}\Folder\shellex\ContextMenuHandlers\DemoShellExt";
        const string clsid = "{2FF28EB9-7F8B-4A6A-A8E1-1234567890AB}";
        try
        {
            using (var key = Registry.CurrentUser.CreateSubKey(handlerSubKey))
            {
                key?.SetValue(null, "-" + clsid, RegistryValueKind.String);
            }

            string extracted = ContextMenuManagerEngine.TryExtractHandlerClsid(
                PrivilegedRollbackEngine.HKEY_CURRENT_USER,
                handlerSubKey);
            Assert.Equal(clsid, extracted);

            var target = TestModelHelpers.CreateSampleTarget(
                locKey: $@"HKCU\{handlerSubKey}",
                category: MonitorCategory.ClassicContextMenu);

            Assert.True(PrivilegedRollbackEngine.VerifyRollbackState(target, InterceptionAction.RollbackToDisabled));
            Assert.False(PrivilegedRollbackEngine.VerifyRollbackState(target, InterceptionAction.Allow));

            using (var key = Registry.CurrentUser.CreateSubKey(handlerSubKey))
            {
                key?.SetValue(null, clsid, RegistryValueKind.String);
            }

            Assert.True(PrivilegedRollbackEngine.VerifyRollbackState(target, InterceptionAction.Allow));
            Assert.False(PrivilegedRollbackEngine.VerifyRollbackState(target, InterceptionAction.RollbackToDisabled));
        }
        finally
        {
            try { Registry.CurrentUser.DeleteSubKeyTree(uniqueRoot, throwOnMissingSubKey: false); } catch { }
        }
    }

    [Fact]
    public void SqliteRuleRepository_CompactDatabase_RunsCleanlyAfterCleanup()
    {
        using var repo = TestModelHelpers.CreateTemporarySqliteRepository(out string dbPath);
        try
        {
            repo.WriteAuditLog(null, MonitorCategory.StartupItem, @"C:\demo.exe", @"HKCU\...\Run\Demo", "New", "Blocked", "已禁止", 100.0, "diag");
            repo.ClearAuditLogs();
            repo.CompactDatabase();

            Assert.True(File.Exists(dbPath));
            Assert.Empty(repo.GetRecentAuditLogs(10));
        }
        finally
        {
            try
            {
                string? dir = Path.GetDirectoryName(dbPath);
                if (!string.IsNullOrEmpty(dir) && Directory.Exists(dir))
                    Directory.Delete(dir, true);
            }
            catch { }
        }
    }

    [Fact]
    public void PipeProtocol_AlertSerialization_PreservesDisplayName()
    {
        var target = TestModelHelpers.CreateSampleTarget(
            targetBin: @"C:\Program Files\WindowsApps\Microsoft.MicrosoftPCManager_3.23.2.0_x64__8wekyb3d8bbwe\MSPCManager.exe",
            locKey: @"HKU\S-1-5-21-1000\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\Microsoft.MicrosoftPCManager_8wekyb3d8bbwe\PCManagerStartup::State");
        target = new TargetProgramFeatures
        {
            Category = target.Category,
            DisplayName = "Microsoft PC Manager",
            TargetBinaryPath = target.TargetBinaryPath,
            NormalizedPath = target.NormalizedPath,
            NormalizedPathHash = target.NormalizedPathHash,
            RawCommandLine = target.RawCommandLine,
            CommandLineArgsTemplate = target.CommandLineArgsTemplate,
            LocationKeyOrIdentifier = target.LocationKeyOrIdentifier,
            MD5Hex = target.MD5Hex,
            SHA256Hex = target.SHA256Hex,
            HasValidSignature = true,
            SignerSubject = "Microsoft Corporation"
        };

        var eval = new ConfidenceEvaluationResult
        {
            FinalScore = 100.0,
            CurrentTarget = target,
            Severity = DiagnosticSeverity.NormalNew,
            DiagnosticOpinion = "Test",
            DiffItems = []
        };

        byte[] payload = BinaryPipeSerializer.SerializeAlert(42, eval);
        var restored = BinaryPipeSerializer.DeserializeAlert(payload, out ulong corrId);

        Assert.Equal(42UL, corrId);
        Assert.Equal("Microsoft PC Manager", restored.CurrentTarget.DisplayName);
        Assert.Equal(target.TargetBinaryPath, restored.CurrentTarget.TargetBinaryPath);
    }

    [Fact]
    public void PathNormalizer_ExistingDirectoryWithSpaces_NotTruncatedAtSpace()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), $"Startup Guard WindowsApps {Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);
        try
        {
            var (exePath, args) = PathNormalizerAndSimilarity.SplitCommandLine(tempDir);
            Assert.Equal(tempDir, exePath);
            Assert.Equal(string.Empty, args);
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    [Fact]
    public void ShellNavigationHelper_FormatForRegeditDisplay_ExpandsAbbreviatedHivesAndStripsValueSuffix()
    {
        static void AssertRegeditPath(string expectedBody, string input)
        {
            string actual = ShellNavigationHelper.FormatForRegeditDisplay(input);
            Assert.True(
                actual.StartsWith(@"计算机\", StringComparison.Ordinal) ||
                actual.StartsWith(@"電腦\", StringComparison.Ordinal) ||
                actual.StartsWith(@"Computer\", StringComparison.Ordinal),
                $"Expected regedit computer root prefix, got: {actual}");
            Assert.Equal(expectedBody, actual[(actual.IndexOf('\\') + 1)..]);
        }

        AssertRegeditPath(
            @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run::DemoApp");

        AssertRegeditPath(
            @"HKEY_USERS\S-1-5-21-1000\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\App\Task",
            @"HKU\S-1-5-21-1000\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\App\Task::State");

        AssertRegeditPath(
            @"HKEY_LOCAL_MACHINE\SOFTWARE\Classes\PackagedCom\ClassIndex\{11223344-5566-7788-99AA-BBCCDDEEFF00}",
            @"Win11Modern:{11223344-5566-7788-99AA-BBCCDDEEFF00}:Microsoft.MicrosoftPCManager_1.0_x64__8wekyb3d8bbwe");
    }

    [Fact]
    public void PrivilegedRollbackEngine_ExtractClsidOrIdentifier_HandlesPackagedComAndModernIds()
    {
        const string expected = "{11223344-5566-7788-99AA-BBCCDDEEFF00}";
        Assert.Equal(expected, PrivilegedRollbackEngine.ExtractClsidOrIdentifier(
            $@"HKLM\SOFTWARE\Classes\PackagedCom\ClassIndex\{expected}\Microsoft.MicrosoftPCManager_3.23.2.0_x64__8wekyb3d8bbwe"));
        Assert.Equal(expected, PrivilegedRollbackEngine.ExtractClsidOrIdentifier(
            $"Win11Modern:{expected}:Microsoft.MicrosoftPCManager"));
        Assert.Equal(expected, PrivilegedRollbackEngine.ExtractClsidOrIdentifier(
            $"Approved:{expected}"));
    }
}
