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

    [Fact]
    public void V106_ServiceUninstallAndReinstall_NeverSuppressedByBaselineOrTransientCache()
    {
        if (!OperatingSystem.IsWindows()) return;

        string tempDir = Path.Combine(Path.GetTempPath(), $"StartupGuardTests_v106_svc_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);
        try
        {
            string svcExe = Path.Combine(tempDir, "vivoesService_x64.exe");
            string appRunExe = Path.Combine(tempDir, "OneDriveTransient.exe");
            string uninstalledExe = Path.Combine(tempDir, "RemovedStartup.exe");
            File.WriteAllText(svcExe, "pcsuite-service-v1");
            File.WriteAllText(appRunExe, "onedrive-v1");
            var fixedWriteUtc = DateTime.UtcNow.AddDays(-2);
            File.SetLastWriteTimeUtc(svcExe, fixedWriteUtc);
            File.SetLastWriteTimeUtc(appRunExe, fixedWriteUtc);
            long svcTicks = new FileInfo(svcExe).LastWriteTimeUtc.Ticks;
            long svcLen = new FileInfo(svcExe).Length;

            var differ = new SystemStateSnapshotDiffer
            {
                BaselineEstablishedUtc = DateTime.UtcNow.AddMinutes(-10)
            };

            string svcKey = $@"HKLM\SYSTEM\CurrentControlSet\Services\SGUnitTestSvc_{Guid.NewGuid():N}";
            string drvKey = $@"HKLM\SYSTEM\CurrentControlSet\Services\SGUnitTestDrv_{Guid.NewGuid():N}";
            const string runKey = @"HKEY_USERS\S-1-5-21-1001\Software\Microsoft\Windows\CurrentVersion\Run\OneDriveTransient";
            const string missingRunKey = @"HKEY_USERS\S-1-5-21-1001\Software\Microsoft\Windows\CurrentVersion\Run\RemovedApp";

            // 1. ExportCurrentSnapshotAsBaselines 与 BuildAndTrackPersistedBaseline 不得将 Win32Service/KernelDriver 纳入持久化基线
            var exported = differ.ExportCurrentSnapshotAsBaselines(
            [
                new SystemStateSnapshotDiffer.SnapshotItem(MonitorCategory.Win32Service, svcKey, svcExe, "Start=2, Delayed=False, Type=0x10, Name=vivoesService"),
                new SystemStateSnapshotDiffer.SnapshotItem(MonitorCategory.KernelDriver, drvKey, @"C:\Windows\System32\drivers\demo.sys", "Start=3, Type=0x1, Name=DemoKernelDrv"),
                new SystemStateSnapshotDiffer.SnapshotItem(MonitorCategory.StartupItem, runKey, appRunExe, "Enabled=True")
            ]);
            var onlyExported = Assert.Single(exported);
            Assert.Equal(MonitorCategory.StartupItem, onlyExported.Category);

            Assert.Null(differ.BuildAndTrackPersistedBaseline(new TargetProgramFeatures
            {
                Category = MonitorCategory.Win32Service,
                LocationKeyOrIdentifier = svcKey,
                TargetBinaryPath = svcExe,
                RawCommandLine = svcExe,
                NormalizedPath = PathNormalizerAndSimilarity.NormalizeProgramPath(svcExe),
                NormalizedPathHash = 0,
                CommandLineArgsTemplate = string.Empty,
                MD5Hex = string.Empty,
                SHA256Hex = string.Empty
            }, "Start: 3, Delayed: False"));

            Assert.Null(differ.BuildAndTrackPersistedBaseline(new TargetProgramFeatures
            {
                Category = MonitorCategory.KernelDriver,
                LocationKeyOrIdentifier = drvKey,
                TargetBinaryPath = @"C:\Windows\System32\drivers\demo.sys",
                RawCommandLine = @"C:\Windows\System32\drivers\demo.sys",
                NormalizedPath = "demo.sys",
                NormalizedPathHash = 0,
                CommandLineArgsTemplate = string.Empty,
                MD5Hex = string.Empty,
                SHA256Hex = string.Empty
            }, "Start: 3, Delayed: False"));

            var suppressMethod = typeof(SystemStateSnapshotDiffer).GetMethod(
                "ShouldSuppressAsPreExistingOrUnchangedBaseline",
                BindingFlags.NonPublic | BindingFlags.Instance);
            Assert.NotNull(suppressMethod);

            var parseEnabledMethod = typeof(SystemStateSnapshotDiffer).GetMethod(
                "TryParseLiveEnabledState",
                BindingFlags.NonPublic | BindingFlags.Static);
            Assert.NotNull(parseEnabledMethod);

            var removedField = typeof(SystemStateSnapshotDiffer).GetField(
                "_recentlyRemovedItems",
                BindingFlags.NonPublic | BindingFlags.Instance);
            Assert.NotNull(removedField);
            var removedDict = Assert.IsType<ConcurrentDictionary<string, (SystemStateSnapshotDiffer.SnapshotItem Item, DateTime RemovedUtc)>>(
                removedField!.GetValue(differ));

            var nowUtc = DateTime.UtcNow;
            var liveSvc = new SystemStateSnapshotDiffer.SnapshotItem(
                MonitorCategory.Win32Service,
                svcKey,
                svcExe,
                "Start=2, Delayed=False, Type=0x10, Name=vivoesService");
            var liveDrv = new SystemStateSnapshotDiffer.SnapshotItem(
                MonitorCategory.KernelDriver,
                drvKey,
                @"C:\Windows\System32\drivers\demo.sys",
                "Start=1, Type=0x1, Name=DemoKernelDrv");

            // 2. 即使旧库 KnownBaselineItems 遗留服务回滚记录（Start:3 / Delayed:True / Start:4 / ticks=0）且 4 秒前刚被移除，重装也必须拦截
            string[] legacyStates = ["Start: 3, Delayed: False", "Start: 2, Delayed: True", "Start: 4, Delayed: False", "Start=2, Type=0x10"];
            foreach (string oldState in legacyStates)
            {
                differ.LoadPersistedBaselines(
                [
                    new KnownBaselineRecord
                    {
                        LocationKey = svcKey,
                        Category = MonitorCategory.Win32Service,
                        TargetBinaryPath = svcExe,
                        NormalizedPath = PathNormalizerAndSimilarity.NormalizeProgramPath(svcExe),
                        RawState = oldState,
                        FileLastWriteUtcTicks = oldState.StartsWith("Start=") ? 0 : svcTicks,
                        FileLength = oldState.StartsWith("Start=") ? 0 : svcLen,
                        FirstSeenUtc = nowUtc.AddHours(-1),
                        LastSeenUtc = nowUtc.AddMinutes(-5)
                    }
                ]);

                removedDict[svcKey] = (
                    new SystemStateSnapshotDiffer.SnapshotItem(MonitorCategory.Win32Service, svcKey, svcExe, oldState),
                    nowUtc.AddSeconds(-4));

                Assert.False((bool)suppressMethod!.Invoke(differ, [liveSvc, nowUtc])!);
            }

            differ.LoadPersistedBaselines(
            [
                new KnownBaselineRecord
                {
                    LocationKey = drvKey,
                    Category = MonitorCategory.KernelDriver,
                    TargetBinaryPath = @"C:\Windows\System32\drivers\demo.sys",
                    NormalizedPath = "demo.sys",
                    RawState = "Start: 3, Delayed: False",
                    FileLastWriteUtcTicks = 0,
                    FileLength = 0,
                    FirstSeenUtc = nowUtc.AddHours(-1),
                    LastSeenUtc = nowUtc.AddMinutes(-5)
                }
            ]);
            Assert.False((bool)suppressMethod!.Invoke(differ, [liveDrv, nowUtc])!);

            // 3. 验证服务 TryParseLiveEnabledState 区分手动/延迟/禁用 vs 自动启动
            Assert.Equal(false, (bool?)parseEnabledMethod!.Invoke(null, [
                new SystemStateSnapshotDiffer.SnapshotItem(MonitorCategory.Win32Service, svcKey, svcExe, "Start=3, Delayed=False, Type=0x10")
            ]));
            Assert.Equal(false, (bool?)parseEnabledMethod.Invoke(null, [
                new SystemStateSnapshotDiffer.SnapshotItem(MonitorCategory.Win32Service, svcKey, svcExe, "Start=2, Delayed=True, Type=0x10")
            ]));
            Assert.Equal(false, (bool?)parseEnabledMethod.Invoke(null, [
                new SystemStateSnapshotDiffer.SnapshotItem(MonitorCategory.Win32Service, svcKey, svcExe, "Start=4, Delayed=False, Type=0x10")
            ]));
            Assert.Equal(true, (bool?)parseEnabledMethod.Invoke(null, [liveSvc]));

            // 4. StartupItem 卸载删除文件后再重写不走瞬态豁免；文件仍在磁盘上的 4s 瞬态删建仍静默吸收
            removedDict.Clear();
            removedDict[missingRunKey] = (
                new SystemStateSnapshotDiffer.SnapshotItem(MonitorCategory.StartupItem, missingRunKey, uninstalledExe, "Enabled=True"),
                nowUtc.AddSeconds(-4));
            var liveMissingRun = new SystemStateSnapshotDiffer.SnapshotItem(
                MonitorCategory.StartupItem,
                missingRunKey,
                uninstalledExe,
                "Enabled=True");
            Assert.False((bool)suppressMethod.Invoke(differ, [liveMissingRun, nowUtc])!);

            removedDict[runKey] = (
                new SystemStateSnapshotDiffer.SnapshotItem(MonitorCategory.StartupItem, runKey, $"\"{appRunExe}\" /bg", "Enabled=True"),
                nowUtc.AddSeconds(-4));
            var liveExistingRun = new SystemStateSnapshotDiffer.SnapshotItem(
                MonitorCategory.StartupItem,
                runKey,
                $"\"{appRunExe}\" /bg",
                "Enabled=True");
            Assert.True((bool)suppressMethod.Invoke(differ, [liveExistingRun, nowUtc])!);
        }
        finally
        {
            try { Directory.Delete(tempDir, recursive: true); } catch { }
        }
    }

    [Fact]
    public void V106_AiPrompt_IncludesCategorySpecificSupportedActionsAcrossAllEntryPoints()
    {
        var categoryCases = new (MonitorCategory Category, string CatName, string[] MustContain, string[] MustNotContain)[]
        {
            (MonitorCategory.Win32Service, "系统服务", ["回滚为手动启动", "回滚为延迟启动", "禁止服务", "删除服务"], ["（允许/禁止/删除）"]),
            (MonitorCategory.KernelDriver, "内核驱动", ["回滚为手动加载", "禁止驱动"], ["删除", "（允许/禁止/删除）"]),
            (MonitorCategory.ScheduledTask, "计划任务", ["禁止计划任务", "删除计划任务"], ["（允许/禁止/删除）"]),
            (MonitorCategory.StartupItem, "自启程序", ["禁止启动项", "删除启动项"], ["（允许/禁止/删除）"]),
            (MonitorCategory.ClassicContextMenu, "经典右键菜单", ["拦截并屏蔽", "删除注册项"], ["（允许/禁止/删除）"]),
            (MonitorCategory.ModernContextMenu, "Win11 右键菜单", ["拦截并屏蔽", "删除注册项"], ["（允许/禁止/删除）"]),
            (MonitorCategory.WindowsPolicy, "Windows 策略", ["禁止项目", "删除项目"], ["（允许/禁止/删除）"])
        };

        var batchItems = new List<ShellNavigationHelper.AiPromptItemInfo>();
        foreach (var (cat, catName, mustContain, mustNotContain) in categoryCases)
        {
            var info = new ShellNavigationHelper.AiPromptItemInfo(
                catName,
                $"Demo_{cat}",
                "Demo Publisher",
                $@"C:\Demo\{cat}.exe",
                $@"HKLM\Software\Demo\{cat}",
                Category: cat);
            batchItems.Add(info);

            string single = ShellNavigationHelper.BuildAiAgentPrompt(info);
            Assert.Contains("- 支持操作:", single);
            foreach (string token in mustContain)
                Assert.Contains(token, single);
            foreach (string forbidden in mustNotContain)
                Assert.DoesNotContain(forbidden, single);
        }

        string batch = ShellNavigationHelper.BuildAiAgentPrompt(batchItems);
        Assert.DoesNotContain("（允许/禁止/删除）", batch);
        Assert.Contains("回滚为延迟启动", batch);
        Assert.Contains("回滚为手动加载", batch);
        Assert.Contains("拦截并屏蔽", batch);

        // 显式传入 UI 下拉菜单选项时（如主界面服务：自动/延迟启动/手动/禁止/删除）应原样输出
        string customServicePrompt = ShellNavigationHelper.BuildAiAgentPrompt(
            new ShellNavigationHelper.AiPromptItemInfo(
                "系统服务",
                "vivoesService",
                "vivo Mobile Communication Co., Ltd",
                @"C:\Program Files (x86)\pcsuite\vivoesService\x64\vivoesService_x64.exe",
                @"HKLM\SYSTEM\CurrentControlSet\Services\vivoesService",
                SupportedActions: ["自动", "延迟启动", "手动", "禁止", "删除"],
                Category: MonitorCategory.Win32Service));
        Assert.Contains("支持操作: 自动 / 延迟启动 / 手动 / 禁止 / 删除", customServicePrompt);

        // 核对各端代码均已接入 SupportedActions 且不存在旧固定文案
        string repoRoot = FindRepoRoot();
        string trayDialogCs = File.ReadAllText(Path.Combine(repoRoot, "src", "StartupGuard.TrayHost", "InterceptionDiffDialogWindow.xaml.cs"));
        string appMainCs = File.ReadAllText(Path.Combine(repoRoot, "src", "StartupGuard.App", "MainWindow.xaml.cs"));
        string helperCs = File.ReadAllText(Path.Combine(repoRoot, "src", "StartupGuard.Core", "Native", "ShellNavigationHelper.cs"));

        Assert.Contains("SupportedActions:", trayDialogCs);
        Assert.Contains("SupportedActions: supportedActions", appMainCs);
        Assert.Contains("SupportedActions: BuildManagedItemSupportedActions", appMainCs);
        Assert.DoesNotContain("（允许/禁止/删除）", helperCs);
    }

    [Fact]
    public void V106_StartupItemUninstallAndReinstall_EvictsBaselineEvenIfExeStillOnDiskAndPreservesLogoutAndTransient()
    {
        if (!OperatingSystem.IsWindows()) return;

        string tempDir = Path.Combine(Path.GetTempPath(), $"StartupGuardTests_v106_startup_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);
        try
        {
            string appExe = Path.Combine(tempDir, "MyApp.exe");
            File.WriteAllText(appExe, "startup-app-v1");
            var oldWriteUtc = DateTime.UtcNow.AddDays(-3);
            File.SetLastWriteTimeUtc(appExe, oldWriteUtc);
            var fi = new FileInfo(appExe);

            var differ = new SystemStateSnapshotDiffer
            {
                BaselineEstablishedUtc = DateTime.UtcNow.AddMinutes(-10)
            };
            var evictedKeys = new List<string>();
            differ.OnPersistedBaselinesEvicted = keys => evictedKeys.AddRange(keys);

            const string activeSyntheticSid = "S-1-5-21-999999999-888888888-1001";
            string runLoc = $@"HKU\{activeSyntheticSid}\Software\Microsoft\Windows\CurrentVersion\Run\MyTestStartupApp";
            string logoutLoc = @"HKU\S-1-5-21-999999999-888888888-2026\Software\Microsoft\Windows\CurrentVersion\Run\LogoutOnlyApp";
            string uwpLoc = $@"HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\SGTestUwp_{Guid.NewGuid():N}\StartupTaskId::State";

            var engine = new ContextMenuManagerEngine();
            var nowUtc = DateTime.UtcNow;

            // 先预置基线与快照：模拟正常装过 StartupItem（文件仍在硬盘）、UWP 无单文件时间戳项、以及另一注销用户 SID 项
            differ.LoadPersistedBaselines(
            [
                new KnownBaselineRecord
                {
                    LocationKey = runLoc,
                    Category = MonitorCategory.StartupItem,
                    TargetBinaryPath = appExe,
                    NormalizedPath = PathNormalizerAndSimilarity.NormalizeProgramPath(appExe),
                    RawState = $"ValName=MyTestStartupApp, Data={appExe}, Type=1, Enabled=True",
                    FileLastWriteUtcTicks = fi.LastWriteTimeUtc.Ticks,
                    FileLength = fi.Length,
                    FirstSeenUtc = nowUtc.AddHours(-1),
                    LastSeenUtc = nowUtc.AddMinutes(-1)
                },
                new KnownBaselineRecord
                {
                    LocationKey = logoutLoc,
                    Category = MonitorCategory.StartupItem,
                    TargetBinaryPath = appExe,
                    NormalizedPath = PathNormalizerAndSimilarity.NormalizeProgramPath(appExe),
                    RawState = $"ValName=LogoutOnlyApp, Data={appExe}, Type=1, Enabled=True",
                    FileLastWriteUtcTicks = fi.LastWriteTimeUtc.Ticks,
                    FileLength = fi.Length,
                    FirstSeenUtc = nowUtc.AddHours(-1),
                    LastSeenUtc = nowUtc.AddMinutes(-1)
                },
                new KnownBaselineRecord
                {
                    LocationKey = uwpLoc,
                    Category = MonitorCategory.StartupItem,
                    TargetBinaryPath = "StartupTaskId",
                    NormalizedPath = "startuptaskid",
                    RawState = "UwpState=2, Enabled=True",
                    FileLastWriteUtcTicks = 0,
                    FileLength = 0,
                    FirstSeenUtc = nowUtc.AddHours(-1),
                    LastSeenUtc = nowUtc.AddMinutes(-1)
                }
            ]);

            differ.ApplyCategoryBaselineSnapshot(MonitorCategory.StartupItem,
            [
                new SystemStateSnapshotDiffer.SnapshotItem(MonitorCategory.StartupItem, runLoc, appExe, $"ValName=MyTestStartupApp, Data={appExe}, Type=1, Enabled=True"),
                new SystemStateSnapshotDiffer.SnapshotItem(MonitorCategory.StartupItem, logoutLoc, appExe, $"ValName=LogoutOnlyApp, Data={appExe}, Type=1, Enabled=True"),
                new SystemStateSnapshotDiffer.SnapshotItem(MonitorCategory.StartupItem, uwpLoc, "StartupTaskId", "UwpState=2, Enabled=True")
            ]);

            // 1. 触发 StartupItem 差异扫描（仅传入 activeSyntheticSid，真实注册表无上述三项 -> 触发消失）
            var target = new NativeSystemMonitorMatrix.MonitoredRegistryTarget(
                MonitorCategory.StartupItem,
                PrivilegedRollbackEngine.HKEY_USERS,
                $@"{activeSyntheticSid}\Software\Microsoft\Windows\CurrentVersion\Run",
                false);
            differ.DiffAllMutatedTargets(target, 0, activeSyntheticSid, engine);

            // 即使 appExe 此时依然在磁盘上，普通 Run 与无单文件时间戳的 UWP 基线也必须当场驱逐；
            // 而未加载 SID (LogoutOnlyApp) 属于注销卸载 Hive，绝不可误清持久化基线。
            Assert.Contains(runLoc, evictedKeys);
            Assert.Contains(uwpLoc, evictedKeys);
            Assert.DoesNotContain(logoutLoc, evictedKeys);

            var suppressMethod = typeof(SystemStateSnapshotDiffer).GetMethod(
                "ShouldSuppressAsPreExistingOrUnchangedBaseline",
                BindingFlags.NonPublic | BindingFlags.Instance);
            Assert.NotNull(suppressMethod);

            // 超过 5 秒瞬态与 45 秒登录水合窗后用同安装包重装：普通 StartupItem 与 UWP 均必须拦截（返回 false）
            var reinstalledRun = new SystemStateSnapshotDiffer.SnapshotItem(
                MonitorCategory.StartupItem, runLoc, appExe, $"ValName=MyTestStartupApp, Data={appExe}, Type=1, Enabled=True");
            var reinstalledUwp = new SystemStateSnapshotDiffer.SnapshotItem(
                MonitorCategory.StartupItem, uwpLoc, "StartupTaskId", "UwpState=2, Enabled=True");
            var restoredLogout = new SystemStateSnapshotDiffer.SnapshotItem(
                MonitorCategory.StartupItem, logoutLoc, appExe, $"ValName=LogoutOnlyApp, Data={appExe}, Type=1, Enabled=True");

            DateTime afterReinstallUtc = DateTime.UtcNow.AddSeconds(50);
            Assert.False((bool)suppressMethod!.Invoke(differ, [reinstalledRun, afterReinstallUtc])!);
            Assert.False((bool)suppressMethod.Invoke(differ, [reinstalledUwp, afterReinstallUtc])!);
            // 注销用户的持久化基线仍在：重新挂载后免误报（返回 true）
            Assert.True((bool)suppressMethod.Invoke(differ, [restoredLogout, afterReinstallUtc])!);

            // 2. 4 秒内物理文件仍存在磁盘的瞬态删建（如 OneDrive 自检）仍应被吸收且标记需回写基线
            var removedField = typeof(SystemStateSnapshotDiffer).GetField(
                "_recentlyRemovedItems",
                BindingFlags.NonPublic | BindingFlags.Instance);
            Assert.NotNull(removedField);
            var removedDict = Assert.IsType<ConcurrentDictionary<string, (SystemStateSnapshotDiffer.SnapshotItem Item, DateTime RemovedUtc)>>(
                removedField!.GetValue(differ));

            string transientRunLoc = $@"HKU\{activeSyntheticSid}\Software\Microsoft\Windows\CurrentVersion\Run\OneDriveTransientSync";
            var transientLive = new SystemStateSnapshotDiffer.SnapshotItem(
                MonitorCategory.StartupItem, transientRunLoc, appExe, $"ValName=OneDriveTransientSync, Data={appExe}, Type=1, Enabled=True");
            removedDict[transientRunLoc] = (transientLive, DateTime.UtcNow.AddSeconds(-4));

            var collectMethod = typeof(SystemStateSnapshotDiffer).GetMethod(
                "CollectDiffCandidateLocked",
                BindingFlags.NonPublic | BindingFlags.Instance);
            Assert.NotNull(collectMethod);

            var changed = new List<(SystemStateSnapshotDiffer.SnapshotItem Live, SystemStateSnapshotDiffer.SnapshotItem? Previous)>();
            var transientRestored = new List<SystemStateSnapshotDiffer.SnapshotItem>();
            var disabledUpdates = new List<SystemStateSnapshotDiffer.SnapshotItem>();

            collectMethod!.Invoke(differ, [transientLive, changed, null, transientRestored, disabledUpdates]);
            Assert.Empty(changed);
            Assert.Single(transientRestored);
            Assert.Equal(transientRunLoc, transientRestored[0].LocationKey);

            var persistedTransient = differ.ExportCurrentSnapshotAsBaselines(transientRestored);
            Assert.Single(persistedTransient);
            Assert.Equal(transientRunLoc, persistedTransient[0].LocationKey);

            // 3. StartupItem / ScheduledTask 从 Enabled=True 变为 Enabled=False：静默同步进基线，绝不误弹窗；此后复活为 Enabled=True 必拦截
            string manualRunLoc = $@"HKU\{activeSyntheticSid}\Software\Microsoft\Windows\CurrentVersion\Run\DisabledLaterApp";
            string taskLoc = $@"Task: \SGTestDisabledTask_{Guid.NewGuid():N}";
            differ.ApplyCategoryBaselineSnapshot(MonitorCategory.StartupItem,
            [
                new SystemStateSnapshotDiffer.SnapshotItem(MonitorCategory.StartupItem, manualRunLoc, appExe, $"ValName=DisabledLaterApp, Data={appExe}, Type=1, Enabled=True")
            ]);
            differ.ApplyCategoryBaselineSnapshot(MonitorCategory.ScheduledTask,
            [
                new SystemStateSnapshotDiffer.SnapshotItem(MonitorCategory.ScheduledTask, taskLoc, appExe, "TaskFile: SGTestDisabledTask, Enabled=True")
            ]);

            var runNowDisabled = new SystemStateSnapshotDiffer.SnapshotItem(
                MonitorCategory.StartupItem, manualRunLoc, appExe, $"ValName=DisabledLaterApp, Data={appExe}, Type=1, Enabled=False");
            var taskNowDisabled = new SystemStateSnapshotDiffer.SnapshotItem(
                MonitorCategory.ScheduledTask, taskLoc, appExe, "TaskFile: SGTestDisabledTask, Enabled=False");

            changed.Clear();
            disabledUpdates.Clear();
            collectMethod.Invoke(differ, [runNowDisabled, changed, null, null, disabledUpdates]);
            collectMethod.Invoke(differ, [taskNowDisabled, changed, null, null, disabledUpdates]);
            Assert.Empty(changed);
            Assert.Equal(2, disabledUpdates.Count);

            var persistedAfterDisable = differ.ExportCurrentSnapshotAsBaselines(disabledUpdates);
            Assert.Equal(2, persistedAfterDisable.Count);
            Assert.Contains("Enabled=False", persistedAfterDisable[0].RawState);
            Assert.Contains("Enabled=False", persistedAfterDisable[1].RawState);

            var runRevived = new SystemStateSnapshotDiffer.SnapshotItem(
                MonitorCategory.StartupItem, manualRunLoc, appExe, $"ValName=DisabledLaterApp, Data={appExe}, Type=1, Enabled=True");
            Assert.False((bool)suppressMethod.Invoke(differ, [runRevived, DateTime.UtcNow.AddSeconds(10)])!);

            // 4. TryExtractUserSidFromLocationKey 准确识别普通 HKU 项与 UWP Classes 项
            Assert.True(SystemStateSnapshotDiffer.TryExtractUserSidFromLocationKey(runLoc, out string parsedSid, out bool needsClasses));
            Assert.Equal(activeSyntheticSid, parsedSid);
            Assert.False(needsClasses);

            Assert.True(SystemStateSnapshotDiffer.TryExtractUserSidFromLocationKey(
                $@"HKU\{activeSyntheticSid}\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\Pkg\Id::State",
                out parsedSid,
                out needsClasses));
            Assert.Equal(activeSyntheticSid, parsedSid);
            Assert.True(needsClasses);
        }
        finally
        {
            try { Directory.Delete(tempDir, recursive: true); } catch { }
        }
    }

    [Fact]
    public void V106_BackgroundPerf_ZeroAllocEtwSpanAndCachedSettingsAndOnDemandGameTimer()
    {
        // 1. ETW 零分配 Span 提示哈希匹配精度与 ResolveRecentWriterPid 行为一致性
        Assert.Equal(
            MmfBinaryStore.ComputeFnv1a64("hint:run"),
            EtwKernelRegistryTracker.ComputeLowerHintHash(@"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run".AsSpan()));
        Assert.Equal(
            MmfBinaryStore.ComputeFnv1a64("hint:services"),
            EtwKernelRegistryTracker.ComputeLowerHintHash(@"\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\vivoesService".AsSpan()));
        Assert.Equal(
            MmfBinaryStore.ComputeFnv1a64("hint:tasks"),
            EtwKernelRegistryTracker.ComputeLowerHintHash(@"\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Demo".AsSpan()));
        Assert.Equal(
            MmfBinaryStore.ComputeFnv1a64("hint:contextmenu"),
            EtwKernelRegistryTracker.ComputeLowerHintHash(@"\SOFTWARE\Classes\PackagedCom\ClassIndex\{1234}".AsSpan()));

        using (var tracker = new EtwKernelRegistryTracker())
        {
            tracker.RecordRegistryWriteEvent(MmfBinaryStore.ComputeFnv1a64("hint:services"), 4321);
            uint pid = tracker.ResolveRecentWriterPid(0, @"SYSTEM\CurrentControlSet\Services\Demo");
            Assert.Equal(4321u, pid);
        }

        // 2. UserSettingsStore 缓存写后即读一致性
        bool prevDiag = StartupGuard.Core.Configuration.UserSettingsStore.GetDiagnosticLoggingEnabled();
        try
        {
            StartupGuard.Core.Configuration.UserSettingsStore.SetDiagnosticLoggingEnabled(true);
            Assert.True(StartupGuard.Core.Configuration.UserSettingsStore.GetDiagnosticLoggingEnabled());
            StartupGuard.Core.Configuration.UserSettingsStore.SetDiagnosticLoggingEnabled(false);
            Assert.False(StartupGuard.Core.Configuration.UserSettingsStore.GetDiagnosticLoggingEnabled());
        }
        finally
        {
            StartupGuard.Core.Configuration.UserSettingsStore.SetDiagnosticLoggingEnabled(prevDiag);
        }

        // 3. GameModeDebounceController 按需定时器：空闲不激活、入队后 45 秒稳态退出后释放并回归空闲
        int state = GameModeDebounceController.QUNS_RUNNING_D3D_FULL_SCREEN;
        DateTime now = new(2026, 11, 22, 12, 0, 0, DateTimeKind.Utc);
        var flushed = new List<ConfidenceEvaluationResult>();
        using (var controller = new GameModeDebounceController(
            batch => flushed.AddRange(batch),
            () => state,
            () => now))
        {
            controller.EvaluateStateTick();
            Assert.Equal(0, controller.PendingQueueCount);
            Assert.False(controller.IsDebounceTimerActive);

            controller.EnqueueDeferredAuditItem(new ConfidenceEvaluationResult
            {
                FinalScore = 100,
                Severity = DiagnosticSeverity.NormalNew,
                DiagnosticOpinion = "Demo",
                CurrentTarget = new TargetProgramFeatures
                {
                    Category = MonitorCategory.StartupItem,
                    TargetBinaryPath = @"C:\Demo\game_updater.exe",
                    NormalizedPath = "c:\\demo\\game_updater.exe",
                    NormalizedPathHash = 0,
                    RawCommandLine = @"C:\Demo\game_updater.exe",
                    CommandLineArgsTemplate = string.Empty,
                    LocationKeyOrIdentifier = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\GameUpdater",
                    MD5Hex = string.Empty,
                    SHA256Hex = string.Empty
                }
            });

            state = GameModeDebounceController.QUNS_ACCEPTS_NOTIFICATIONS;
            controller.EvaluateStateTick();
            Assert.True(controller.IsDebounceTimerActive);
            Assert.Empty(flushed);

            now = now.AddSeconds(46);
            controller.EvaluateStateTick();
            Assert.Single(flushed);
            Assert.False(controller.IsDebounceTimerActive);
            Assert.Equal(0, controller.PendingQueueCount);
        }

        // 4. 关键后台优化契约检查
        string repoRoot = FindRepoRoot();
        string trayCs = File.ReadAllText(Path.Combine(repoRoot, "src", "StartupGuard.TrayHost", "Program.cs"));
        string svcCs = File.ReadAllText(Path.Combine(repoRoot, "src", "StartupGuard.Service", "Program.cs"));
        string settingsCs = File.ReadAllText(Path.Combine(repoRoot, "src", "StartupGuard.Core", "Configuration", "UserSettingsStore.cs"));
        string iconCs = File.ReadAllText(Path.Combine(repoRoot, "src", "StartupGuard.App", "Services", "ProgramIconResolver.cs"));

        Assert.DoesNotContain("new GameModeDebounceController", trayCs);
        Assert.Contains("SharedPipeSecurity", svcCs);
        Assert.Contains("PurgeExpiredRuntimeCaches", svcCs);
        Assert.Contains("CachedJsonSettings", settingsCs);
        Assert.Contains("_iconCache.Count >= 512", iconCs);
    }
}
