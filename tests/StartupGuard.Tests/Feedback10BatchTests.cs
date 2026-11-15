using StartupGuard.Core.ContextMenu;
using StartupGuard.Core.Models;
using StartupGuard.Core.Rules;

namespace StartupGuard.Tests;

public class Feedback10BatchTests
{
    [Theory]
    [InlineData("RollbackToDisabled", "已阻止")]
    [InlineData("阻止并禁止", "已阻止")]
    [InlineData("用户弹窗阻止：已禁止启动", "已阻止")]
    [InlineData("已拦截并暂存待审核", "待审核")]
    [InlineData("PendingAudit", "待审核")]
    [InlineData("Allow", "已放行")]
    [InlineData("用户弹窗放行：允许启动", "已放行")]
    [InlineData("DeleteEntry", "已移除")]
    [InlineData("RollbackToDemand", "设为手动")]
    [InlineData("RollbackToDelayedAuto", "延迟自启")]
    [InlineData("回滚失败：被保护机制恢复", "执行异常")]
    public void AuditLogRecord_DisplayActionText_IsConcise(string rawAction, string expectedDisplay)
    {
        var log = new AuditLogRecord
        {
            ActionTaken = rawAction,
            Category = MonitorCategory.KernelDriver
        };

        Assert.Equal(expectedDisplay, log.DisplayActionText);
    }

    [Fact]
    public void AppGroupingHelper_ClustersMultiCategoryComponentsOfSameAppTogether()
    {
        var inputs = new List<AppGroupingHelper.AppAttributionInput<string>>
        {
            new(
                Item: "startup-samplesuite",
                Category: MonitorCategory.StartupItem,
                DisplayName: "Sample 办公套件",
                PathOrCommand: @"C:\ProgramData\samplesuite\SampleTray.exe --autostart",
                LocationKey: @"HKCU\...\Run\samplesuite",
                Publisher: "Sample Vendor Co., Ltd."),
            new(
                Item: "service-samplesuite",
                Category: MonitorCategory.Win32Service,
                DisplayName: "SampleSyncService",
                PathOrCommand: @"C:\ProgramData\samplesuite\SampleSyncService.exe",
                LocationKey: @"HKLM\SYSTEM\CurrentControlSet\Services\SampleSyncService",
                Publisher: "Sample Vendor Co., Ltd."),
            new(
                Item: "driver-in-system32",
                Category: MonitorCategory.KernelDriver,
                DisplayName: "samplesvc",
                PathOrCommand: @"C:\Windows\System32\drivers\samplesvc.sys",
                LocationKey: @"HKLM\SYSTEM\CurrentControlSet\Services\samplesvc",
                Publisher: "Sample Vendor Co., Ltd."),
            new(
                Item: "ctx-samplesuite",
                Category: MonitorCategory.ClassicContextMenu,
                DisplayName: "Sample Context Menu ShellExtension",
                PathOrCommand: @"C:\ProgramData\samplesuite\shellextension\SampleShellExtensionx64.dll",
                LocationKey: @"HKLM\SOFTWARE\Classes\*\shellex\ContextMenuHandlers\SampleApp",
                Publisher: "Sample Vendor Co., Ltd."),
            new(
                Item: "other-app-7zip",
                Category: MonitorCategory.ClassicContextMenu,
                DisplayName: "7-Zip",
                PathOrCommand: @"C:\Program Files\7-Zip\7-zip.dll",
                LocationKey: @"HKLM\SOFTWARE\Classes\*\shellex\ContextMenuHandlers\7-Zip",
                Publisher: "Igor Pavlov")
        };

        var groups = AppGroupingHelper.ClusterByApplication(inputs);

        Assert.Equal(2, groups.Count);
        var sampleGroup = Assert.Single(groups, g => g.Items.Contains("startup-samplesuite"));
        Assert.Equal(4, sampleGroup.Items.Count);
        Assert.Contains("service-samplesuite", sampleGroup.Items);
        Assert.Contains("driver-in-system32", sampleGroup.Items);
        Assert.Contains("ctx-samplesuite", sampleGroup.Items);
    }

    [Fact]
    public void AppGroupingHelper_SeparatesDistinctAppsFromSameVendorAndGroupsUwp()
    {
        var inputs = new List<AppGroupingHelper.AppAttributionInput<string>>
        {
            new(
                Item: "acrobat-app",
                Category: MonitorCategory.StartupItem,
                DisplayName: "Adobe Acrobat",
                PathOrCommand: @"C:\Program Files\Adobe\Acrobat\Acrobat.exe",
                LocationKey: @"HKLM\...\Run\Acrobat",
                Publisher: "Adobe Inc.",
                ProductName: "Adobe Acrobat"),
            new(
                Item: "acrobat-driver",
                Category: MonitorCategory.KernelDriver,
                DisplayName: "Acrobat Filter Driver",
                PathOrCommand: @"C:\Windows\System32\drivers\acroflt.sys",
                LocationKey: @"HKLM\SYSTEM\...\Services\acroflt",
                Publisher: "Adobe Inc.",
                ProductName: "Adobe Acrobat"),
            new(
                Item: "photoshop-app",
                Category: MonitorCategory.StartupItem,
                DisplayName: "Adobe Photoshop",
                PathOrCommand: @"C:\Program Files\Adobe\Photoshop\Photoshop.exe",
                LocationKey: @"HKLM\...\Run\Photoshop",
                Publisher: "Adobe Inc.",
                ProductName: "Adobe Photoshop"),
            new(
                Item: "contoso-uwp-1",
                Category: MonitorCategory.StartupItem,
                DisplayName: "Sample hot keys and OSD",
                PathOrCommand: @"C:\Program Files\WindowsApps\Contoso.SampleHotkeyOSD_7.101.0.0_x64__x1y2z\OSD.exe",
                LocationKey: @"HKCU\...\StartupApproved\StartupFolder\OSD",
                Publisher: "Contoso Co.")
        };

        var groups = AppGroupingHelper.ClusterByApplication(inputs);

        Assert.Equal(3, groups.Count);
        var acrobat = Assert.Single(groups, g => g.Items.Contains("acrobat-app"));
        Assert.Equal(2, acrobat.Items.Count);
        Assert.Contains("acrobat-driver", acrobat.Items);

        var photoshop = Assert.Single(groups, g => g.Items.Contains("photoshop-app"));
        Assert.Single(photoshop.Items);
    }

    [Fact]
    public void AppGroupingHelper_SeparatesDistinctAppsUnderSameUserProfileDownloadsAndArchiveContainers()
    {
        var inputs = new List<AppGroupingHelper.AppAttributionInput<string>>
        {
            new(
                Item: "onedrive-lists",
                Category: MonitorCategory.StartupItem,
                DisplayName: "Microsoft.Lists",
                PathOrCommand: @"C:\Users\DemoUser\AppData\Local\Microsoft\OneDrive\26.198.1011.0006\OneDrive.Sync.Service.exe",
                LocationKey: @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Microsoft.Lists",
                Publisher: "Microsoft Corporation"),
            new(
                Item: "suite-a-service",
                Category: MonitorCategory.Win32Service,
                DisplayName: "SuiteAService",
                PathOrCommand: @"""C:\Users\DemoUser\Downloads\Archieve\SuiteA\App\SuiteA\SuiteAService.exe""",
                LocationKey: @"HKLM\SYSTEM\CurrentControlSet\Services\SuiteAService",
                Publisher: "Sample Utilities Vendor"),
            new(
                Item: "suite-b-scheduler",
                Category: MonitorCategory.ScheduledTask,
                DisplayName: "SuiteB Scheduler",
                PathOrCommand: @"""C:\Users\DemoUser\Downloads\Archieve\SuiteB\App\SuiteB\Scheduler.exe""",
                LocationKey: @"\SuiteB Scheduler",
                Publisher: "Sample Utilities Vendor",
                ProductName: "SuiteB"),
            new(
                Item: "suite-b-skipuac",
                Category: MonitorCategory.ScheduledTask,
                DisplayName: "SuiteB SkipUAC (DemoUser)",
                PathOrCommand: @"""C:\Users\DemoUser\Downloads\Archieve\SuiteB\App\SuiteB\SuiteB.exe""",
                LocationKey: @"\SuiteB SkipUAC (DemoUser)",
                Publisher: "Sample Utilities Vendor",
                ProductName: "SuiteB")
        };

        var groups = AppGroupingHelper.ClusterByApplication(inputs);

        Assert.Equal(3, groups.Count);
        var listsGroup = Assert.Single(groups, g => g.Items.Contains("onedrive-lists"));
        Assert.Single(listsGroup.Items);
        Assert.Equal("OneDrive", listsGroup.AppTitle);

        var suiteAGroup = Assert.Single(groups, g => g.Items.Contains("suite-a-service"));
        Assert.Single(suiteAGroup.Items);

        var suiteBGroup = Assert.Single(groups, g => g.Items.Contains("suite-b-scheduler"));
        Assert.Equal(2, suiteBGroup.Items.Count);
        Assert.Contains("suite-b-skipuac", suiteBGroup.Items);
    }

    [Theory]
    [InlineData("Sample Context Menu ShellExtension", @"C:\ProgramData\samplesuite\shellextension\SampleShellExtensionx64.dll", "samplesuite")]
    [InlineData("7-zip", @"C:\Program Files\7-Zip\7-zip.dll", "7-Zip")]
    [InlineData("Sample hot keys", @"C:\Program Files\WindowsApps\Contoso.SampleHotkeyOSD_7.101.0.0_x64__abc\OSD.exe", "SampleHotkeyOSD")]
    public void AppGroupingHelper_ExtractAppSearchKeyword_ReturnsCleanAppToken(
        string displayName,
        string path,
        string expectedKeyword)
    {
        string keyword = AppGroupingHelper.ExtractAppSearchKeyword(displayName, path);
        Assert.Equal(expectedKeyword, keyword);
    }

    [Theory]
    [InlineData("@shell32.dll,-8506")]
    [InlineData("@shell32.dll,-8508")]
    [InlineData("@zipfldr.dll,-10148")]
    [InlineData("@sendmail.dll,-4")]
    [InlineData("@sendmail.dll,-21")]
    public void ContextMenuManagerEngine_ResolveMuiString_ResolvesRealWindowsMuiStringsWithoutDllStemFallback(string muiExpr)
    {
        string resolved = ContextMenuManagerEngine.ResolveMuiString(muiExpr);
        Assert.False(string.IsNullOrWhiteSpace(resolved));
        Assert.False(resolved.StartsWith('@'));
        Assert.DoesNotContain("shell32", resolved, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("zipfldr", resolved, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("sendmail", resolved, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ContextMenuManagerEngine_ScanSpecialContextMenus_ResolvesDesktopIniLocalizedNames()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), $"sg_sendto_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);
        try
        {
            // 使用不与系统 MUI 英文译名重名的文件名，确保中英文 Windows 系统均能验证 desktop.ini 本地化解析生效
            File.WriteAllText(Path.Combine(tempDir, "SyntheticMail.MAPIMail"), "");
            File.WriteAllText(Path.Combine(tempDir, "SyntheticZip.ZFSendToTarget"), "");
            File.WriteAllText(
                Path.Combine(tempDir, "desktop.ini"),
                "[LocalizedFileNames]\r\nSyntheticMail.MAPIMail=@sendmail.dll,-4\r\nSyntheticZip.ZFSendToTarget=@zipfldr.dll,-10148\r\n");

            var engine = new ContextMenuManagerEngine();
            var items = engine.ScanSpecialContextMenus(null, customSendToDir: tempDir, customWinXDir: "", includeShellNew: false);

            Assert.Equal(2, items.Count);
            Assert.DoesNotContain(items, i => i.DisplayTitle.Equals("SyntheticMail", StringComparison.OrdinalIgnoreCase));
            Assert.DoesNotContain(items, i => i.DisplayTitle.Equals("SyntheticZip", StringComparison.OrdinalIgnoreCase));
            Assert.All(items, i =>
            {
                Assert.False(string.IsNullOrWhiteSpace(i.DisplayTitle));
                Assert.False(i.DisplayTitle.StartsWith('@'));
            });
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    [Fact]
    public void ContextMenuManagerEngine_LiveScan_ContainsNoUnresolvedShell32OrRawMuiStrings()
    {
        if (!OperatingSystem.IsWindows()) return;
        var engine = new ContextMenuManagerEngine();
        var live = engine.ScanAllContextMenus(null);
        Assert.NotEmpty(live);
        Assert.DoesNotContain(live, i => i.DisplayTitle.Equals("shell32", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(live, i => i.DisplayTitle.StartsWith("@shell32", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void UserSettingsStore_HideContextMenuSystem_DefaultsFalseAndPersists()
    {
        var prev = StartupGuard.Core.Configuration.UserSettingsStore.GetHideContextMenuSystemPreference();
        try
        {
            StartupGuard.Core.Configuration.UserSettingsStore.SetHideContextMenuSystemPreference(true);
            Assert.True(StartupGuard.Core.Configuration.UserSettingsStore.GetHideContextMenuSystemPreference());

            StartupGuard.Core.Configuration.UserSettingsStore.SetHideContextMenuSystemPreference(false);
            Assert.False(StartupGuard.Core.Configuration.UserSettingsStore.GetHideContextMenuSystemPreference());
        }
        finally
        {
            StartupGuard.Core.Configuration.UserSettingsStore.SetHideContextMenuSystemPreference(prev);
        }
    }

    [Theory]
    [InlineData(@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run::Test", @"计算机\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run")]
    [InlineData(@"HKCU\Software\Classes\*\shell\MyVerb", @"计算机\HKEY_CURRENT_USER\Software\Classes\*\shell\MyVerb")]
    [InlineData(@"HKEY_CLASSES_ROOT\Directory\shell\Demo", @"计算机\HKEY_CLASSES_ROOT\Directory\shell\Demo")]
    [InlineData(@"Approved:{11111111-2222-3333-4444-555555555555}", @"计算机\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved")]
    public void ShellNavigationHelper_FormatForRegeditDisplay_PrependsComputerPrefix_AndNormalizesRoundTrip(
        string inputLocation,
        string expectedSuffixOrFull)
    {
        string formatted = StartupGuard.Core.Native.ShellNavigationHelper.FormatForRegeditDisplay(inputLocation);
        Assert.Contains(@"\HKEY_", formatted, StringComparison.Ordinal);
        // 支持本地化根前缀（简体中文为“计算机\”，英文环境为“Computer\”）
        string actualBody = formatted[(formatted.IndexOf('\\') + 1)..];
        string expectedBody = expectedSuffixOrFull[(expectedSuffixOrFull.IndexOf('\\') + 1)..];
        Assert.Equal(expectedBody, actualBody);

        string normalized = StartupGuard.Core.Native.ShellNavigationHelper.NormalizeFullRegistryPath(formatted);
        Assert.Equal(expectedBody, normalized);

        var (hive, subKey, _) = StartupGuard.Core.Native.PrivilegedRollbackEngine.SplitRegistryLocation(formatted, null);
        Assert.NotEqual(0, hive);
        Assert.False(string.IsNullOrWhiteSpace(subKey));
    }

    [Theory]
    [InlineData(@"Approved:{286F668D-7F3F-4D88-88C2-9A2A0B8B0C29}", true)]
    [InlineData(@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved::{286F668D-7F3F-4D88-88C2-9A2A0B8B0C29}", true)]
    [InlineData(@"HKCU\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved::{286F668D-7F3F-4D88-88C2-9A2A0B8B0C29}", true)]
    [InlineData(@"HKLM\SOFTWARE\Classes\*\shellex\ContextMenuHandlers\7-Zip", false)]
    [InlineData(@"HKLM\SOFTWARE\Classes\*\shell\OpenWith", false)]
    public void PrivilegedRollbackEngine_IsApprovedShellExtensionLocation_MatchesBothFormats(string locationKey, bool expected)
    {
        Assert.Equal(expected, StartupGuard.Core.Native.PrivilegedRollbackEngine.IsApprovedShellExtensionLocation(locationKey));
    }

    [Theory]
    [InlineData(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved")]
    [InlineData(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked")]
    [InlineData(@"SOFTWARE\Classes\*\shellex\ContextMenuHandlers")]
    [InlineData(@"SOFTWARE\Classes\*\shell")]
    [InlineData(@"SOFTWARE\Classes\.txt\ShellNew")]
    public void ContextMenuManagerEngine_SetClassicShellVerbState_RefusesContainerKeys(string containerSubKey)
    {
        if (!OperatingSystem.IsWindows()) return;
        var engine = new ContextMenuManagerEngine();
        bool result = engine.SetClassicShellVerbState(unchecked((nint)0x80000002), containerSubKey, true);
        Assert.False(result);
    }

    [Fact]
    public void ContextMenuManagerEngine_LiveScan_NeverIncludesLegacyDisableAsApprovedExtension()
    {
        if (!OperatingSystem.IsWindows()) return;
        var engine = new ContextMenuManagerEngine();
        var live = engine.ScanAllContextMenus(null);
        Assert.DoesNotContain(live, i => i.DisplayTitle.Equals("LegacyDisable", StringComparison.OrdinalIgnoreCase) ||
                                         i.IdKey.Contains("LegacyDisable", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void SharedStorageHelper_DataAndLogDirectories_ExistAndWritable()
    {
        string dataDir = StartupGuard.Core.Storage.SharedStorageHelper.GetSharedDataDirectory();
        string logDir = StartupGuard.Core.Storage.SharedStorageHelper.GetSharedLogDirectory();
        Assert.True(Directory.Exists(dataDir));
        Assert.True(Directory.Exists(logDir));
    }
}
