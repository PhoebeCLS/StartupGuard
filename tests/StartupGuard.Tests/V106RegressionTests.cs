using System.Collections.Concurrent;
using System.Reflection;
using StartupGuard.Core.ContextMenu;
using StartupGuard.Core.Models;
using StartupGuard.Core.Native;
using StartupGuard.Core.Scoring;
using StartupGuard.Core.Storage;
using StartupGuard.Service.Monitoring;

namespace StartupGuard.Tests;

public sealed class V106RegressionTests
{
    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null)
        {
            if (File.Exists(Path.Combine(dir.FullName, "StartupGuard.slnx")))
                return dir.FullName;
            dir = dir.Parent;
        }
        throw new DirectoryNotFoundException("Cannot locate StartupGuard.slnx root directory.");
    }

    [Fact]
    public void V106_PermanentRuleModeText_UsesConciseWordingAndZeroLegacyPhraseInSrc()
    {
        var perm = new RuleRecord { DisplayName = "Demo", RuleMode = RuleMatchMode.PermanentAdaptive };
        Assert.Equal("永久", perm.RuleModeText);

        string srcRoot = Path.Combine(FindRepoRoot(), "src");
        var files = Directory.EnumerateFiles(srcRoot, "*.*", SearchOption.AllDirectories)
            .Where(p => p.EndsWith(".cs", StringComparison.OrdinalIgnoreCase) ||
                        p.EndsWith(".xaml", StringComparison.OrdinalIgnoreCase));

        foreach (string file in files)
        {
            string text = File.ReadAllText(file);
            Assert.DoesNotContain("永久拦截", text);
        }
    }

    [Fact]
    public void V106_SqliteKnownBaselines_UpsertLoadAndRemoveWorkCorrectly()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), $"StartupGuardTests_v106_db_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);
        string dbPath = Path.Combine(tempDir, "rules.db");
        try
        {
            using var repo = new SqliteRuleRepository(dbPath);
            const string runLoc = @"HKEY_USERS\S-1-5-21-1001\Software\Microsoft\Windows\CurrentVersion\Run\OneDrive";
            const string uwpLoc = @"HKEY_USERS\S-1-5-21-1001\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\AppXDemo\FnKeyStartupId::State";

            var nowUtc = DateTime.UtcNow;
            repo.UpsertKnownBaselinesBatch(
            [
                new KnownBaselineRecord
                {
                    LocationKey = runLoc,
                    Category = MonitorCategory.StartupItem,
                    TargetBinaryPath = @"C:\Apps\OneDrive\OneDrive.exe",
                    NormalizedPath = @"c:\apps\onedrive\onedrive.exe",
                    RawState = "Enabled=True",
                    FileLastWriteUtcTicks = 1234567890L,
                    FileLength = 4096L,
                    FirstSeenUtc = nowUtc,
                    LastSeenUtc = nowUtc
                },
                new KnownBaselineRecord
                {
                    LocationKey = uwpLoc,
                    Category = MonitorCategory.StartupItem,
                    TargetBinaryPath = "FnKeyStartupId",
                    NormalizedPath = "fnkeystartupid",
                    RawState = "Enabled=True, State=2",
                    FileLastWriteUtcTicks = 0L,
                    FileLength = 0L,
                    FirstSeenUtc = nowUtc,
                    LastSeenUtc = nowUtc
                }
            ]);

            var loaded = repo.LoadAllKnownBaselines();
            Assert.Equal(2, loaded.Count);
            var runRec = Assert.Single(loaded, r => string.Equals(r.LocationKey, runLoc, StringComparison.OrdinalIgnoreCase));
            Assert.Equal(1234567890L, runRec.FileLastWriteUtcTicks);
            Assert.Equal(4096L, runRec.FileLength);

            // 更新时传入 0 时间戳/长度，不应覆盖已记录的有效磁盘时间戳
            repo.UpsertKnownBaselinesBatch(
            [
                new KnownBaselineRecord
                {
                    LocationKey = runLoc,
                    Category = MonitorCategory.StartupItem,
                    TargetBinaryPath = @"C:\Apps\OneDrive\OneDrive.exe",
                    NormalizedPath = @"c:\apps\onedrive\onedrive.exe",
                    RawState = "Enabled=True",
                    FileLastWriteUtcTicks = 0L,
                    FileLength = 0L,
                    FirstSeenUtc = nowUtc.AddMinutes(1),
                    LastSeenUtc = nowUtc.AddMinutes(1)
                }
            ]);

            loaded = repo.LoadAllKnownBaselines();
            runRec = Assert.Single(loaded, r => string.Equals(r.LocationKey, runLoc, StringComparison.OrdinalIgnoreCase));
            Assert.Equal(1234567890L, runRec.FileLastWriteUtcTicks);

            repo.RemoveKnownBaseline(@"HKU\S-1-5-21-1001\Software\Microsoft\Windows\CurrentVersion\Run\OneDrive");
            Assert.Single(repo.LoadAllKnownBaselines());

            int removed = repo.RemoveKnownBaselinesBatch([uwpLoc]);
            Assert.True(removed >= 1);
            Assert.Empty(repo.LoadAllKnownBaselines());
        }
        finally
        {
            try { Directory.Delete(tempDir, recursive: true); } catch { }
        }
    }

    [Fact]
    public void V106_TransientDeleteRecreateAndPersistedBaseline_SuppressUnlessBinaryUpdatedOrResurrected()
    {
        if (!OperatingSystem.IsWindows()) return;

        string tempDir = Path.Combine(Path.GetTempPath(), $"StartupGuardTests_v106_bin_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);
        try
        {
            string oneDriveExe = Path.Combine(tempDir, "OneDrive.exe");
            string uwpExe = Path.Combine(tempDir, "FnHotkeys.exe");
            File.WriteAllText(oneDriveExe, "v1-onedrive");
            File.WriteAllText(uwpExe, "v1-fnhotkeys");

            var oldWriteUtc = DateTime.UtcNow.AddDays(-5);
            File.SetLastWriteTimeUtc(oneDriveExe, oldWriteUtc);
            File.SetLastWriteTimeUtc(uwpExe, oldWriteUtc);

            // ::State 后缀剥离后应能准确提取物理文件时间
            Assert.True(SystemStateSnapshotDiffer.TryGetLocationLastWriteUtc(uwpExe + "::State", out DateTime strippedWriteUtc));
            Assert.True(Math.Abs((strippedWriteUtc - oldWriteUtc).TotalSeconds) < 2.0);

            var differ = new SystemStateSnapshotDiffer
            {
                BaselineEstablishedUtc = DateTime.UtcNow.AddMinutes(-10)
            };

            var suppressMethod = typeof(SystemStateSnapshotDiffer).GetMethod(
                "ShouldSuppressAsPreExistingOrUnchangedBaseline",
                BindingFlags.NonPublic | BindingFlags.Instance);
            Assert.NotNull(suppressMethod);

            var removedField = typeof(SystemStateSnapshotDiffer).GetField(
                "_recentlyRemovedItems",
                BindingFlags.NonPublic | BindingFlags.Instance);
            Assert.NotNull(removedField);
            var removedDict = Assert.IsType<ConcurrentDictionary<string, (SystemStateSnapshotDiffer.SnapshotItem Item, DateTime RemovedUtc)>>(
                removedField!.GetValue(differ));

            const string oneDriveKey = @"HKEY_USERS\S-1-5-21-1001\Software\Microsoft\Windows\CurrentVersion\Run\OneDrive";
            var nowUtc = DateTime.UtcNow;

            var oldOneDrive = new SystemStateSnapshotDiffer.SnapshotItem(
                MonitorCategory.StartupItem,
                oneDriveKey,
                $"\"{oneDriveExe}\" /background",
                "Enabled=True");
            removedDict[oneDriveKey] = (oldOneDrive, nowUtc.AddSeconds(-4));

            var liveOneDrive = new SystemStateSnapshotDiffer.SnapshotItem(
                MonitorCategory.StartupItem,
                oneDriveKey,
                $"\"{oneDriveExe}\" /background",
                "Enabled=True");

            // 1. 30 秒内同路径删建复用应静默吸收
            bool suppressedTransient = (bool)suppressMethod!.Invoke(differ, [liveOneDrive, nowUtc])!;
            Assert.True(suppressedTransient);

            // 若原本为禁用而现改为启用，不得豁免
            removedDict[oneDriveKey] = (
                new SystemStateSnapshotDiffer.SnapshotItem(MonitorCategory.StartupItem, oneDriveKey, oneDriveExe, "Enabled=False"),
                nowUtc.AddSeconds(-4));
            bool suppressedResurrect = (bool)suppressMethod.Invoke(differ, [liveOneDrive, nowUtc])!;
            Assert.False(suppressedResurrect);

            // 超过 30 秒后删建不再作为瞬态豁免
            removedDict[oneDriveKey] = (oldOneDrive, nowUtc.AddSeconds(-45));
            bool suppressedExpired = (bool)suppressMethod.Invoke(differ, [liveOneDrive, nowUtc])!;
            Assert.False(suppressedExpired);
            removedDict.Clear();

            // 2. 持久化基线对延迟水合 UWP/开机自启项应放行，但程序更新或从禁用复活必须报警
            const string uwpKey = @"HKEY_USERS\S-1-5-21-1001\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\DemoPkg\FnKeyStartupId::State";
            var baselineFeature = new TargetProgramFeatures
            {
                Category = MonitorCategory.StartupItem,
                LocationKeyOrIdentifier = uwpKey,
                TargetBinaryPath = uwpExe,
                RawCommandLine = uwpExe,
                NormalizedPath = PathNormalizerAndSimilarity.NormalizeProgramPath(uwpExe),
                NormalizedPathHash = 0,
                CommandLineArgsTemplate = string.Empty,
                MD5Hex = string.Empty,
                SHA256Hex = string.Empty
            };
            var baselineRecord = differ.BuildAndTrackPersistedBaseline(baselineFeature, "Enabled=True");
            Assert.NotNull(baselineRecord);
            Assert.True(baselineRecord!.FileLength > 0);

            var liveUwp = new SystemStateSnapshotDiffer.SnapshotItem(
                MonitorCategory.StartupItem,
                uwpKey,
                uwpExe,
                "Enabled=True");
            Assert.True((bool)suppressMethod.Invoke(differ, [liveUwp, nowUtc])!);

            // 二进制文件发生版本更新后必须再次捕获告警
            File.WriteAllText(uwpExe, "v2-fnhotkeys-updated-binary");
            File.SetLastWriteTimeUtc(uwpExe, DateTime.UtcNow);
            Assert.False((bool)suppressMethod.Invoke(differ, [liveUwp, nowUtc])!);

            // 同步更新基线但旧状态为禁用、实时变为启用（复活）也必须报警
            var disabledRecord = new KnownBaselineRecord
            {
                LocationKey = uwpKey,
                Category = MonitorCategory.StartupItem,
                TargetBinaryPath = uwpExe,
                NormalizedPath = PathNormalizerAndSimilarity.NormalizeProgramPath(uwpExe),
                RawState = "Enabled=False",
                FileLastWriteUtcTicks = new FileInfo(uwpExe).LastWriteTimeUtc.Ticks,
                FileLength = new FileInfo(uwpExe).Length,
                FirstSeenUtc = nowUtc,
                LastSeenUtc = nowUtc
            };
            differ.LoadPersistedBaselines([disabledRecord]);
            Assert.False((bool)suppressMethod.Invoke(differ, [liveUwp, nowUtc])!);
        }
        finally
        {
            try { Directory.Delete(tempDir, recursive: true); } catch { }
        }
    }

    [Fact]
    public async Task V106_Performance_UserHydrationDebouncingAndIncrementalRepeatScan()
    {
        if (!OperatingSystem.IsWindows()) return;

        var differ = new SystemStateSnapshotDiffer();
        var engine = new ContextMenuManagerEngine();
        Assert.True(differ.IsUserFullyHydrated(null));

        const string syntheticSid = "S-1-5-21-999999999-888888888-1001";
        Assert.False(differ.IsUserFullyHydrated(syntheticSid));
        differ.AbsorbUserBaselineSnapshot(syntheticSid, engine);
        Assert.True(differ.IsUserFullyHydrated(syntheticSid));

        int callbackCount = 0;
        using var matrix = new NativeSystemMonitorMatrix(
            _ => Interlocked.Increment(ref callbackCount),
            debounceWindowMs: 40);

        var target = new NativeSystemMonitorMatrix.MonitoredRegistryTarget(
            MonitorCategory.StartupItem,
            PrivilegedRollbackEngine.HKEY_LOCAL_MACHINE,
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            false);

        for (int i = 0; i < 50; i++)
        {
            matrix.DispatchEventForTesting(target);
        }

        await Task.Delay(250);
        int finalCount = Volatile.Read(ref callbackCount);
        Assert.InRange(finalCount, 1, 2);

        // 连续两次服务/驱动扫描应平稳完成且数量保持一致（覆盖 lpftLastWriteTime 增量缓存热路径）
        var scanSvcMethod = typeof(SystemStateSnapshotDiffer).GetMethod(
            "ScanServicesAndDrivers",
            BindingFlags.NonPublic | BindingFlags.Static);
        Assert.NotNull(scanSvcMethod);

        var first = ((List<SystemStateSnapshotDiffer.SnapshotItem> Services, List<SystemStateSnapshotDiffer.SnapshotItem> Drivers))
            scanSvcMethod!.Invoke(null, null)!;
        var second = ((List<SystemStateSnapshotDiffer.SnapshotItem> Services, List<SystemStateSnapshotDiffer.SnapshotItem> Drivers))
            scanSvcMethod.Invoke(null, null)!;

        Assert.True(first.Services.Count > 10);
        Assert.True(second.Services.Count > 10);
        Assert.InRange(Math.Abs(first.Services.Count - second.Services.Count), 0, 2);
    }

    [Fact]
    public void V106_WinUi3UiContracts_AllVisualFixesPreserved()
    {
        string repoRoot = FindRepoRoot();
        string appDir = Path.Combine(repoRoot, "src", "StartupGuard.App");
        string themesDir = Path.Combine(appDir, "Themes");

        string mainXaml = File.ReadAllText(Path.Combine(appDir, "MainWindow.xaml"));
        string mainCs = File.ReadAllText(Path.Combine(appDir, "MainWindow.xaml.cs"));
        string backdropCs = File.ReadAllText(Path.Combine(themesDir, "FluentBackdropHelper.cs"));
        string comboCs = File.ReadAllText(Path.Combine(themesDir, "FluentComboBoxBehavior.cs"));
        string dialogCs = File.ReadAllText(Path.Combine(themesDir, "FluentDialogBehavior.cs"));
        string sharedStyles = File.ReadAllText(Path.Combine(themesDir, "FluentSharedStyles.xaml"));

        Assert.Contains("DialogContentMessageHost", mainXaml);
        Assert.Contains("ScaleNavBack", mainXaml);
        Assert.Contains("BtnNavBack_PreviewMouseLeftButtonDown", mainXaml);

        Assert.DoesNotContain("Wpf.Ui.Controls.MessageBox", mainCs);
        Assert.Contains("FluentDialogBehavior.PlayOpenAnimation", mainCs);
        Assert.Contains("FromMilliseconds(320)", mainCs);

        Assert.Contains("DwmwaWindowCornerPreference", backdropCs);
        Assert.Contains("DwmwcpRound", backdropCs);

        Assert.Contains("CustomPopupPlacementCallback", comboCs);
        Assert.Contains("FromMilliseconds(183)", comboCs);
        Assert.DoesNotContain("FromMilliseconds(140)", comboCs);
        Assert.Contains("KeySpline(0.1, 0.9, 0.2, 1.0)", comboCs);
        Assert.DoesNotContain("DropDownMorphStroke", comboCs);

        Assert.Contains("PlayOpenAnimation", dialogCs);

        Assert.DoesNotContain("RotateTransform", sharedStyles);
        Assert.DoesNotContain("ScaleTransform", sharedStyles);
        Assert.Contains("CacheMode=\"BitmapCache\"", sharedStyles);
        Assert.DoesNotContain("DropDownMorphStroke", sharedStyles);
        Assert.Contains("Placement=\"Custom\"", sharedStyles);
        Assert.Contains("ClickMode=\"Release\"", sharedStyles);
        Assert.Contains("<Thickness x:Key=\"ComboBoxItemMargin\">4,2,4,2</Thickness>", sharedStyles);
        Assert.Contains("Padding=\"0,2\"", sharedStyles);

        string trayCs = File.ReadAllText(Path.Combine(repoRoot, "src", "StartupGuard.TrayHost", "Program.cs"));
        Assert.Contains("_balloonSignal.WaitAsync", trayCs);
    }
}
