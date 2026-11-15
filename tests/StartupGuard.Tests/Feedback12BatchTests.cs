using System.Text.RegularExpressions;
using Microsoft.Win32;
using StartupGuard.Core.Configuration;
using StartupGuard.Core.ContextMenu;
using StartupGuard.Core.Models;
using StartupGuard.Core.Native;
using StartupGuard.Core.Rules;
using StartupGuard.Core.Scoring;
using StartupGuard.Core.Storage;
using StartupGuard.Service.Monitoring;
using StartupGuard.Tests.TestHelpers;

namespace StartupGuard.Tests;

public class Feedback12BatchTests
{
    [Fact]
    public void UserSettingsStore_DefaultPopupAction_RoundTripsAllCategories()
    {
        if (!OperatingSystem.IsWindows()) return;

        var testMap = new Dictionary<MonitorCategory, InterceptionAction>
        {
            [MonitorCategory.StartupItem] = InterceptionAction.RollbackToDisabled,
            [MonitorCategory.Win32Service] = InterceptionAction.RollbackToDisabled,
            [MonitorCategory.KernelDriver] = InterceptionAction.DeleteEntry,
            [MonitorCategory.ScheduledTask] = InterceptionAction.RollbackToDisabled,
            [MonitorCategory.ClassicContextMenu] = InterceptionAction.RollbackToDisabled,
            [MonitorCategory.ModernContextMenu] = InterceptionAction.DeleteEntry,
            [MonitorCategory.WindowsPolicy] = InterceptionAction.DeleteEntry
        };

        var originals = testMap.Keys.ToDictionary(c => c, UserSettingsStore.GetDefaultPopupAction);
        try
        {
            foreach (var (cat, action) in testMap)
            {
                UserSettingsStore.SetDefaultPopupAction(cat, action);
                Assert.Equal(action, UserSettingsStore.GetDefaultPopupAction(cat));
            }

            // Fix 1: 写入 Allow 应自动回落为 RollbackToDisabled（不勾选即允许放行）
            UserSettingsStore.SetDefaultPopupAction(MonitorCategory.StartupItem, InterceptionAction.Allow);
            Assert.Equal(InterceptionAction.RollbackToDisabled, UserSettingsStore.GetDefaultPopupAction(MonitorCategory.StartupItem));
        }
        finally
        {
            foreach (var (cat, prev) in originals)
            {
                UserSettingsStore.SetDefaultPopupAction(cat, prev);
            }
        }
    }

    [Fact]
    public void PrivilegedRollbackEngine_ResolveShellExPairPaths_MapsEnabledAndDisabledFolders()
    {
        var (en1, dis1) = PrivilegedRollbackEngine.ResolveShellExPairPaths(
            @"计算机\HKLM\SOFTWARE\Classes\*\shellex\ContextMenuHandlers\WinRAR");
        Assert.Equal(@"SOFTWARE\Classes\*\shellex\ContextMenuHandlers\WinRAR", en1);
        Assert.Equal(@"SOFTWARE\Classes\*\shellex\-ContextMenuHandlers\WinRAR", dis1);

        var (en2, dis2) = PrivilegedRollbackEngine.ResolveShellExPairPaths(
            @"HKCU\Software\Classes\Directory\shellex\-DragDropHandlers\7Zip");
        Assert.Equal(@"Software\Classes\Directory\shellex\DragDropHandlers\7Zip", en2);
        Assert.Equal(@"Software\Classes\Directory\shellex\-DragDropHandlers\7Zip", dis2);

        var (_, dis3) = PrivilegedRollbackEngine.ResolveShellExPairPaths(
            @"SOFTWARE\Classes\*\shell\CustomVerb");
        Assert.Equal(string.Empty, dis3);
    }

    [Fact]
    public void ContextMenuManagerEngine_SetClassicContextMenuHandlerState_MovesBetweenEnabledAndDashFolder()
    {
        if (!OperatingSystem.IsWindows()) return;

        string rootSub = $@"Software\StartupGuard_UnitTest_{Guid.NewGuid():N}";
        string enabledSub = $@"{rootSub}\shellex\ContextMenuHandlers\SampleExt";
        string disabledSub = $@"{rootSub}\shellex\-ContextMenuHandlers\SampleExt";
        const string fakeClsid = "{11111111-2222-3333-4444-555555555555}";

        try
        {
            using (var key = Registry.CurrentUser.CreateSubKey(enabledSub))
            {
                key.SetValue(null, fakeClsid);
                key.SetValue("ExtraMeta", "KeepMe");
            }

            var engine = new ContextMenuManagerEngine();
            bool disabledOk = engine.SetClassicContextMenuHandlerState(
                PrivilegedRollbackEngine.HKEY_CURRENT_USER,
                $@"HKCU\{enabledSub}",
                fakeClsid,
                enable: false);

            Assert.True(disabledOk);
            Assert.Null(Registry.CurrentUser.OpenSubKey(enabledSub));
            using (var movedKey = Registry.CurrentUser.OpenSubKey(disabledSub))
            {
                Assert.NotNull(movedKey);
                Assert.Equal(fakeClsid, movedKey!.GetValue(null)?.ToString());
                Assert.Equal("KeepMe", movedKey.GetValue("ExtraMeta")?.ToString());
            }

            bool enabledOk = engine.SetClassicContextMenuHandlerState(
                PrivilegedRollbackEngine.HKEY_CURRENT_USER,
                $@"HKCU\{disabledSub}",
                fakeClsid,
                enable: true);

            Assert.True(enabledOk);
            Assert.Null(Registry.CurrentUser.OpenSubKey(disabledSub));
            using (var restoredKey = Registry.CurrentUser.OpenSubKey(enabledSub))
            {
                Assert.NotNull(restoredKey);
                Assert.Equal(fakeClsid, restoredKey!.GetValue(null)?.ToString());
                Assert.Equal("KeepMe", restoredKey.GetValue("ExtraMeta")?.ToString());
            }
        }
        finally
        {
            try { Registry.CurrentUser.DeleteSubKeyTree(rootSub, throwOnMissingSubKey: false); } catch { }
        }
    }

    [Fact]
    public void ContextMenuManagerEngine_SetClassicShellVerbState_WritesExpectedMarkersAndProtectsOpenNewWindow()
    {
        if (!OperatingSystem.IsWindows()) return;

        string rootSub = $@"Software\StartupGuard_UnitTest_{Guid.NewGuid():N}";
        string normalVerbSub = $@"{rootSub}\shell\CustomAction";
        string openNewWindowSub = $@"{rootSub}\Folder\shell\opennewwindow";

        try
        {
            using (Registry.CurrentUser.CreateSubKey(normalVerbSub)) { }
            using (Registry.CurrentUser.CreateSubKey(openNewWindowSub)) { }

            var engine = new ContextMenuManagerEngine();

            Assert.True(engine.SetClassicShellVerbState(PrivilegedRollbackEngine.HKEY_CURRENT_USER, normalVerbSub, disableVerb: true));
            using (var vk = Registry.CurrentUser.OpenSubKey(normalVerbSub))
            {
                Assert.NotNull(vk);
                Assert.Equal(0x639bc8, Convert.ToInt32(vk!.GetValue("HideBasedOnVelocityId")));
                Assert.NotNull(vk.GetValue("ProgrammaticAccessOnly"));
                Assert.NotNull(vk.GetValue("LegacyDisable"));
            }

            Assert.True(engine.SetClassicShellVerbState(PrivilegedRollbackEngine.HKEY_CURRENT_USER, normalVerbSub, disableVerb: false));
            using (var vk = Registry.CurrentUser.OpenSubKey(normalVerbSub))
            {
                Assert.NotNull(vk);
                Assert.Null(vk!.GetValue("HideBasedOnVelocityId"));
                Assert.Null(vk.GetValue("ProgrammaticAccessOnly"));
                Assert.Null(vk.GetValue("LegacyDisable"));
            }

            Assert.True(engine.SetClassicShellVerbState(PrivilegedRollbackEngine.HKEY_CURRENT_USER, openNewWindowSub, disableVerb: true));
            using (var wk = Registry.CurrentUser.OpenSubKey(openNewWindowSub))
            {
                Assert.NotNull(wk);
                Assert.Equal(0x639bc8, Convert.ToInt32(wk!.GetValue("HideBasedOnVelocityId")));
                Assert.NotNull(wk.GetValue("ProgrammaticAccessOnly"));
                Assert.Null(wk.GetValue("LegacyDisable"));
            }
        }
        finally
        {
            try { Registry.CurrentUser.DeleteSubKeyTree(rootSub, throwOnMissingSubKey: false); } catch { }
        }
    }

    [Fact]
    public void ContextMenuManagerEngine_AnalyzeTargetForContextMenu_And_OrphanedComCheck()
    {
        var engine = new ContextMenuManagerEngine();

        var exeMatches = engine.AnalyzeTargetForContextMenu(@"C:\Tools\demo.exe", isFolder: false, null);
        Assert.Contains(exeMatches, m => m.NavTag == "ClassicAllObjects");
        Assert.Contains(exeMatches, m => m.NavTag == "ClassicFile");
        Assert.Contains(exeMatches, m => m.NavTag == "FileTypes" && m.FileTypeTab == "ExeFile");

        var txtMatches = engine.AnalyzeTargetForContextMenu(@"C:\Docs\readme.txt", isFolder: false, null);
        Assert.Contains(txtMatches, m => m.NavTag == "FileTypes" && m.FileTypeTab == "CustomExtension" && m.Parameter == ".txt");

        var folderMatches = engine.AnalyzeTargetForContextMenu(@"C:\Projects", isFolder: true, null);
        Assert.Contains(folderMatches, m => m.NavTag == "ClassicFolder");
        Assert.Contains(folderMatches, m => m.NavTag == "ClassicDirectory");
        Assert.Contains(folderMatches, m => m.NavTag == "ClassicDirBackground");
        Assert.Contains(folderMatches, m => m.NavTag == "FileTypes" && m.FileTypeTab == "DirectoryType");

        if (OperatingSystem.IsWindows())
        {
            Assert.False(engine.IsComHandlerOrPackageInstalled("{DEADBEEF-0000-0000-0000-000000000099}", null));
            Assert.False(ShellNavigationHelper.LocateStorageLocation(null, @"C:\NonExistent\FakeBinary_999.exe", MonitorCategory.Win32Service));
        }
    }

    [Fact]
    public void XamlStaticResources_AllReferencedKeysExistInWindowOrAppResources()
    {
        string? dir = AppContext.BaseDirectory;
        string? repoRoot = null;
        while (!string.IsNullOrEmpty(dir))
        {
            if (File.Exists(Path.Combine(dir, "StartupGuard.slnx")))
            {
                repoRoot = dir;
                break;
            }
            dir = Directory.GetParent(dir)?.FullName;
        }

        Assert.False(string.IsNullOrEmpty(repoRoot));
        string srcDir = Path.Combine(repoRoot!, "src");

        var xamlFiles = Directory.EnumerateFiles(srcDir, "*.xaml", SearchOption.AllDirectories)
            .Where(p => !p.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.OrdinalIgnoreCase)
                     && !p.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.OrdinalIgnoreCase))
            .ToList();

        Assert.NotEmpty(xamlFiles);

        var appKeys = new HashSet<string>(StringComparer.Ordinal);
        string appXaml = Path.Combine(srcDir, "StartupGuard.App", "App.xaml");
        if (File.Exists(appXaml))
        {
            foreach (Match m in Regex.Matches(File.ReadAllText(appXaml), @"x:Key=""([^""]+)"""))
                appKeys.Add(m.Groups[1].Value);
        }

        var missing = new List<string>();
        foreach (string xamlPath in xamlFiles)
        {
            string content = File.ReadAllText(xamlPath);
            var localKeys = new HashSet<string>(appKeys, StringComparer.Ordinal);
            foreach (Match m in Regex.Matches(content, @"x:Key=""([^""]+)"""))
                localKeys.Add(m.Groups[1].Value);

            foreach (Match r in Regex.Matches(content, @"\{StaticResource\s+([^\}\s,]+)"))
            {
                string key = r.Groups[1].Value;
                if (!localKeys.Contains(key))
                    missing.Add($"{Path.GetFileName(xamlPath)}: {key}");
            }
        }

        Assert.Empty(missing);
    }

    [Fact]
    public void ShellNavigationHelper_BuildAiAgentPrompt_FormatsSingleAndBatchConcisePrompts()
    {
        var item1 = new ShellNavigationHelper.AiPromptItemInfo(
            "经典右键菜单",
            "QuickEdit",
            "Contoso Ltd.",
            @"C:\Program Files\Contoso\edit.dll",
            @"HKLM\SOFTWARE\Classes\*\shellex\ContextMenuHandlers\QuickEdit",
            "所有文件 (*)",
            "{12345678-1234-1234-1234-1234567890AB}");

        string singlePrompt = ShellNavigationHelper.BuildAiAgentPrompt(item1);
        Assert.Contains("经典右键菜单", singlePrompt);
        Assert.Contains("所有文件 (*)", singlePrompt);
        Assert.Contains("QuickEdit", singlePrompt);
        Assert.Contains("Contoso Ltd.", singlePrompt);
        Assert.Contains(@"C:\Program Files\Contoso\edit.dll", singlePrompt);
        string expectedRegeditPath = ShellNavigationHelper.FormatForRegeditDisplay(item1.LocationKey);
        Assert.EndsWith(@"\HKEY_LOCAL_MACHINE\SOFTWARE\Classes\*\shellex\ContextMenuHandlers\QuickEdit", expectedRegeditPath);
        Assert.Contains(expectedRegeditPath, singlePrompt);
        Assert.Contains("{12345678-1234-1234-1234-1234567890AB}", singlePrompt);
        Assert.True(singlePrompt.Length < 400);

        var item2 = new ShellNavigationHelper.AiPromptItemInfo(
            "自启程序",
            "Updater",
            null,
            @"C:\Tools\updater.exe --silent",
            @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater");

        string batchPrompt = ShellNavigationHelper.BuildAiAgentPrompt([item1, item2]);
        Assert.Contains("[1]", batchPrompt);
        Assert.Contains("[2]", batchPrompt);
        Assert.Contains("QuickEdit", batchPrompt);
        Assert.Contains("Updater", batchPrompt);
        Assert.Contains("未知发布者/未签名", batchPrompt);
        Assert.Equal(string.Empty, ShellNavigationHelper.BuildAiAgentPrompt(Array.Empty<ShellNavigationHelper.AiPromptItemInfo>()));
    }

    [Fact]
    public void ResolveMuiString_And_ExtractPublisherDetails_CacheByNormalizedPath()
    {
        if (!OperatingSystem.IsWindows()) return;

        string firstMui = ContextMenuManagerEngine.ResolveMuiString(@"@shell32.dll,-8508");
        string secondMui = ContextMenuManagerEngine.ResolveMuiString(@"@shell32.dll,-8508");
        Assert.Equal(firstMui, secondMui);
        Assert.False(string.IsNullOrWhiteSpace(firstMui));

        string p1 = ShellNavigationHelper.ResolvePhysicalFilePath("svchost.exe -k netsvcs -p");
        string p2 = ShellNavigationHelper.ResolvePhysicalFilePath("\"%SystemRoot%\\System32\\svchost.exe\" -k LocalService");
        Assert.Equal(p1, p2, ignoreCase: true);
        Assert.True(File.Exists(p1));

        var (hasSig, signer, _) = NativeSecurityExtractor.ExtractAuthenticodeDetails(p1);
        Assert.True(hasSig);
        Assert.False(string.IsNullOrWhiteSpace(signer));
    }

    [Fact]
    public void RuleModels_DisplayActionText_MapsPendingWaitingAuditAndBadgeColors()
    {
        var interceptedPending = new AuditLogRecord { ActionTaken = "先拦截待审核" };
        Assert.Equal("待审核", interceptedPending.DisplayActionText);
        Assert.Equal("#FFB900", interceptedPending.ActionBadgeForeground);

        var popupWaiting = new AuditLogRecord { ActionTaken = "已捕获等待用户审核" };
        Assert.Equal("待审核", popupWaiting.DisplayActionText);
        Assert.Equal("#FFB900", popupWaiting.ActionBadgeForeground);
    }

    [Fact]
    public void UserSettingsStore_DefaultPopupAction_SplitsClassicAndModernContextMenusIndependently()
    {
        if (!OperatingSystem.IsWindows()) return;

        var origClassic = UserSettingsStore.GetDefaultPopupAction(MonitorCategory.ClassicContextMenu);
        var origModern = UserSettingsStore.GetDefaultPopupAction(MonitorCategory.ModernContextMenu);
        try
        {
            UserSettingsStore.SetDefaultPopupAction(MonitorCategory.ClassicContextMenu, InterceptionAction.DeleteEntry);
            UserSettingsStore.SetDefaultPopupAction(MonitorCategory.ModernContextMenu, InterceptionAction.RollbackToDisabled);

            Assert.Equal(InterceptionAction.DeleteEntry, UserSettingsStore.GetDefaultPopupAction(MonitorCategory.ClassicContextMenu));
            Assert.Equal(InterceptionAction.RollbackToDisabled, UserSettingsStore.GetDefaultPopupAction(MonitorCategory.ModernContextMenu));
        }
        finally
        {
            UserSettingsStore.SetDefaultPopupAction(MonitorCategory.ClassicContextMenu, origClassic);
            UserSettingsStore.SetDefaultPopupAction(MonitorCategory.ModernContextMenu, origModern);
        }
    }

    [Fact]
    public void ContextMenuManagerEngine_OpenWith_DropEffect_And_GuidBlocked_Contracts()
    {
        var engine = new ContextMenuManagerEngine();
        Assert.Equal(["*", "AllFilesystemObjects", "Folder", "Directory"], ContextMenuManagerEngine.DefaultDropEffectClassSubKeys);
        Assert.False(engine.SetDefaultDropEffect(99));
        Assert.False(engine.AddGuidBlockedEntry("not-a-guid"));

        if (OperatingSystem.IsWindows())
        {
            string report = engine.InspectOpenWithRegistrationSources(".txt");
            Assert.Contains("扩展名: .txt", report);

            int dropEffect = engine.GetDefaultDropEffect();
            Assert.True(dropEffect is 0 or 1 or 2 or 4);

            var blocked = engine.ScanGuidBlockedEntries();
            Assert.All(blocked, item =>
            {
                Assert.Equal("Scene_GuidBlocked", item.ScopeScene);
                Assert.Contains(@"Shell Extensions\Blocked", item.RegistryPath, StringComparison.OrdinalIgnoreCase);
                Assert.StartsWith("{", item.Clsid);
            });
        }
    }

    [Fact]
    public void MainWindowAndTrayHost_Feedback13Contracts()
    {
        string? dir = AppContext.BaseDirectory;
        string? repoRoot = null;
        while (!string.IsNullOrEmpty(dir))
        {
            if (File.Exists(Path.Combine(dir, "StartupGuard.slnx")))
            {
                repoRoot = dir;
                break;
            }
            dir = Directory.GetParent(dir)?.FullName;
        }
        Assert.False(string.IsNullOrEmpty(repoRoot));

        string mainXaml = File.ReadAllText(Path.Combine(repoRoot!, "src", "StartupGuard.App", "MainWindow.xaml"));
        string mainCs = File.ReadAllText(Path.Combine(repoRoot!, "src", "StartupGuard.App", "MainWindow.xaml.cs"));
        string trayDialogCs = File.ReadAllText(Path.Combine(repoRoot!, "src", "StartupGuard.TrayHost", "InterceptionDiffDialogWindow.xaml.cs"));

        // 1 & 3. 侧边栏顺序：Win11 现代菜单置顶（唯一特例），随后严格对齐 MGR
        string[] expectedNavOrder =
        [
            "SubNavWin11Modern",
            "SubNavClassicFile",
            "SubNavClassicAllObj",
            "SubNavClassicFolder",
            "SubNavClassicDirectory",
            "SubNavClassicDirBg",
            "SubNavClassicDesktopBg",
            "SubNavClassicDrive",
            "SubNavClassicLibrary",
            "SubNavClassicComputer",
            "SubNavClassicRecycleBin",
            "SubNavContextByApp",
            "SubNavFileTypes",
            "SubNavMenuAnalysis",
            "SubNavClassicSendTo",
            "SubNavClassicWinX",
            "SubNavClassicOpenWith",
            "SubNavClassicDragDrop",
            "SubNavClassicCommandStore",
            "SubNavClassicGuidBlocked"
        ];
        int lastPos = -1;
        foreach (string name in expectedNavOrder)
        {
            int pos = mainXaml.IndexOf($"x:Name=\"{name}\"", StringComparison.Ordinal);
            Assert.True(pos > lastPos, $"Expected {name} after previous index {lastPos}, got {pos}");
            lastPos = pos;
        }

        // 2. 驱动不显示管理按钮
        int detailIdx = mainCs.IndexOf("BtnItemDetailManage.Visibility =", StringComparison.Ordinal);
        Assert.True(detailIdx > 0);
        string detailSlice = mainCs.Substring(detailIdx, Math.Min(300, mainCs.Length - detailIdx));
        Assert.DoesNotContain("MonitorCategory.KernelDriver", detailSlice);

        // 4. 缩窗自适应与自定义扩展名精简
        Assert.Contains("MinWidth=\"600\"", mainXaml);
        Assert.DoesNotContain("TxtExtensionOpenMode", mainXaml);
        Assert.DoesNotContain("CmbCustomExtPerceivedType", mainXaml);
        Assert.DoesNotContain("CmbCustomExtPerceivedType", mainCs);

        // 5 & 6. 打开方式检查 / 右键拖拽默认效果 / GUID 锁 / 默认动作拆分
        Assert.Contains("PanelOpenWithInspector", mainXaml);
        Assert.Contains("PanelDragDropEffect", mainXaml);
        Assert.Contains("PanelGuidBlockedBar", mainXaml);
        Assert.Contains("CmbDefaultActionClassicMenu", mainXaml);
        Assert.Contains("CmbDefaultActionModernMenu", mainXaml);
        Assert.DoesNotContain("CmbDefaultActionContextMenu", mainXaml);

        // 7. FindMatchingLiveItem 处理 \-ContextMenuHandlers\ 且弹窗不去重 TargetBinaryPath
        Assert.Contains(@"\-ContextMenuHandlers\", mainCs);
        Assert.DoesNotContain("x.TargetPath, target.TargetBinaryPath", trayDialogCs);
    }

    [Fact]
    public void SqliteRuleRepository_ResolvePendingAuditLogs_MatchesContextMenuVariantAndStoresProvenance()
    {
        string dbPath = Path.Combine(Path.GetTempPath(), $"sg_test_{Guid.NewGuid():N}.db");
        try
        {
            using var repo = new SqliteRuleRepository(dbPath);
            repo.WriteAuditLog(
                ruleId: null,
                category: MonitorCategory.ClassicContextMenu,
                program: "Sample Context Menu ShellExtension",
                location: @"HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Directory\shellex\-ContextMenuHandlers\Sample Context Menu ShellExtension",
                oldState: "新增拦截",
                newState: "已屏蔽(待审核)",
                action: "等待审核",
                score: 0.9,
                diagnostic: "检测到新右键菜单",
                sourceProcess: @"C:\Downloads\samplesuite_setup.exe (SampleSetup)");

            string provenance = repo.GetItemProvenance(
                @"HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers\Sample Context Menu ShellExtension");
            Assert.Contains("samplesuite_setup.exe", provenance);

            repo.ResolvePendingAuditLogs(
                @"HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers\Sample Context Menu ShellExtension",
                "已禁止");

            var logs = repo.GetRecentAuditLogs(10);
            Assert.Single(logs);
            Assert.Equal("已禁止", logs[0].ActionTaken);
            Assert.Contains("samplesuite_setup.exe", logs[0].SourceProcess);
        }
        finally
        {
            if (File.Exists(dbPath))
            {
                try { File.Delete(dbPath); } catch { }
            }
        }
    }

    [Fact]
    public void ShellNavigationHelper_And_ScheduledTaskNormalization_And_OptionalMicrosoftExclusion()
    {
        // Fix 3: AI 提示词包含创建来源
        string prompt = ShellNavigationHelper.BuildAiAgentPrompt(
            new ShellNavigationHelper.AiPromptItemInfo(
                CategoryName: "计划任务",
                DisplayName: "TestHelper",
                Publisher: "Microsoft Corporation",
                CommandOrPath: @"C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe",
                LocationKey: @"Task: \MicrosoftEdgeUpdateTaskMachineCore",
                CreatorProcess: @"C:\Downloads\installer.exe (PID: 1234)"));
        Assert.Contains("installer.exe", prompt);
        Assert.Contains("安装/创建进程", prompt);

        static TargetProgramFeatures MakeFeature(string binPath, string displayName, string signer, bool isWhql = false) => new()
        {
            TargetBinaryPath = binPath,
            NormalizedPath = binPath.ToLowerInvariant(),
            NormalizedPathHash = 0,
            RawCommandLine = binPath,
            CommandLineArgsTemplate = string.Empty,
            LocationKeyOrIdentifier = displayName,
            MD5Hex = string.Empty,
            SHA256Hex = string.Empty,
            DisplayName = displayName,
            SignerSubject = signer,
            IsWhqlCertified = isWhql
        };

        // Fix 5a: Edge / EdgeUpdate / OneDrive / Teams / PCManager 不再被当成操作系统核心组件隐藏
        Assert.False(NativeSecurityExtractor.IsWindowsEssentialOperatingSystemComponent(
            MakeFeature(@"C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe", "MicrosoftEdgeUpdateTaskMachineCore", "Microsoft Corporation")));
        Assert.False(NativeSecurityExtractor.IsWindowsEssentialOperatingSystemComponent(
            MakeFeature(@"C:\Users\Test\AppData\Local\Microsoft\OneDrive\OneDrive.exe", "OneDrive", "Microsoft Corporation")));
        Assert.True(NativeSecurityExtractor.IsWindowsEssentialOperatingSystemComponent(
            MakeFeature(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), @"System32\svchost.exe"), "RpcSs", "Microsoft Windows", isWhql: true)));

        // Fix 5b: NormalizeScheduledTaskName 正确剥离 "Task: " 前缀与路径前缀
        Assert.Equal(@"\MicrosoftEdgeUpdateTaskMachineCore",
            PrivilegedRollbackEngine.NormalizeScheduledTaskName(@"Task: \MicrosoftEdgeUpdateTaskMachineCore"));
        Assert.Equal(@"\Microsoft\Windows\Defrag\ScheduledDefrag",
            PrivilegedRollbackEngine.NormalizeScheduledTaskName(@"C:\Windows\System32\Tasks\Microsoft\Windows\Defrag\ScheduledDefrag"));

        // Fix 5c: XML 解析 <Exec><Command>, <Author>, <Enabled>
        const string sampleXml = """
            <?xml version="1.0" encoding="UTF-16"?>
            <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
              <RegistrationInfo><Author>Microsoft Corporation</Author></RegistrationInfo>
              <Settings><Enabled>false</Enabled></Settings>
              <Actions Context="Author">
                <Exec>
                  <Command>C:\Windows\System32\cmd.exe</Command>
                  <Arguments>/c echo ok</Arguments>
                </Exec>
              </Actions>
            </Task>
            """;
        bool parsed = PrivilegedRollbackEngine.TryParseScheduledTaskXml(sampleXml, isXmlContent: true, out string cmd, out string author, out bool enabled);
        Assert.True(parsed);
        Assert.Equal(@"C:\Windows\System32\cmd.exe /c echo ok", cmd);
        Assert.Equal("Microsoft Corporation", author);
        Assert.False(enabled);
    }

    [Fact]
    public void Batch12Fixes_UiAndScannerContracts_Satisfied()
    {
        string? dir = AppContext.BaseDirectory;
        string? repoRoot = null;
        while (dir is not null)
        {
            if (File.Exists(Path.Combine(dir, "StartupGuard.slnx")))
            {
                repoRoot = dir;
                break;
            }
            dir = Directory.GetParent(dir)?.FullName;
        }
        Assert.NotNull(repoRoot);

        string mainXaml = File.ReadAllText(Path.Combine(repoRoot!, "src", "StartupGuard.App", "MainWindow.xaml"));
        string mainCs = File.ReadAllText(Path.Combine(repoRoot!, "src", "StartupGuard.App", "MainWindow.xaml.cs"));
        string trayCs = File.ReadAllText(Path.Combine(repoRoot!, "src", "StartupGuard.TrayHost", "InterceptionDiffDialogWindow.xaml.cs"));
        string mgrCs = File.ReadAllText(Path.Combine(repoRoot!, "src", "StartupGuard.App", "Services", "SystemStartupItemsManager.cs"));

        // Fix 1: 弹窗与默认设置不提供 Allow 选项
        Assert.DoesNotContain("Tag=\"Allow\"", mainXaml);
        Assert.DoesNotContain("InterceptionAction.Allow, \"允许", trayCs);

        // Fix 4: 自启项扫描跳过当前进程用户的 SID 以免与 HKCU 重复
        Assert.Contains("WindowsIdentity.GetCurrent().User?.Value", mgrCs);

        // Fix 6: 状态控件按类型互斥显示；待审核中心无重复单项允许/阻止按钮，收纳进更多菜单
        Assert.Contains("IsMultiStateCategory", mainXaml);
        Assert.Contains("CmbStartupItemState_SelectionChanged", mainCs);
        Assert.DoesNotContain("BtnAuditApprove_Click", mainXaml);
        Assert.DoesNotContain("BtnAuditDeny_Click", mainXaml);
        Assert.Contains("MenuAuditApproveItem_Click", mainXaml);
        Assert.Contains("MenuAuditSetDelayedItem_Click", mainXaml);
        Assert.Contains("MenuAuditSetManualItem_Click", mainXaml);
        Assert.Contains("MenuAuditBlockItem_Click", mainXaml);
    }

    [Fact]
    public void SystemStateSnapshotDiffer_ClassicContextMenuMultiScene_DoesNotCrossSuppressOrMaskReEnable()
    {
        var differ = new StartupGuard.Service.Monitoring.SystemStateSnapshotDiffer();
        const string dllPath = @"C:\ProgramData\samplesuite\shellextension\SampleShellExtensionx64.dll";
        const string clsid = "{2FF28EB9-3CFE-420A-810B-852C410F771E}";
        const string dirLoc = @"HKLM\Software\Classes\Directory\shellex\ContextMenuHandlers\Sample Context Menu ShellExtension";
        const string dirDisabledLoc = @"HKLM\Software\Classes\Directory\shellex\-ContextMenuHandlers\Sample Context Menu ShellExtension";
        const string folderLoc = @"HKLM\Software\Classes\Folder\shellex\ContextMenuHandlers\Sample Context Menu ShellExtension";
        const string starLoc = @"HKLM\Software\Classes\*\shellex\ContextMenuHandlers\Sample Context Menu ShellExtension";

        differ.SuppressLocationKeyMutation(
            dirLoc,
            durationSeconds: 12.0,
            activeUserSid: null,
            targetBinaryPath: dllPath,
            expectedEnabledState: false);

        // 自身回滚后移动到 \-ContextMenuHandlers\ 且 Enabled=False，应被精确抑制，避免自触发循环
        var disabledDirSnapshot = new StartupGuard.Service.Monitoring.SystemStateSnapshotDiffer.SnapshotItem(
            MonitorCategory.ClassicContextMenu,
            dirDisabledLoc,
            dllPath,
            $"Scene=Directory, Enabled=False, Clsid={clsid}",
            DisplayName: "Sample Context Menu ShellExtension");
        Assert.True(differ.IsLiveItemSuppressed(disabledDirSnapshot));

        // 若安装器随后将同一场景复写为 Enabled=True，方向不匹配，不得吞掉再次捕获
        var reEnabledDirSnapshot = new StartupGuard.Service.Monitoring.SystemStateSnapshotDiffer.SnapshotItem(
            MonitorCategory.ClassicContextMenu,
            dirLoc,
            dllPath,
            $"Scene=Directory, Enabled=True, Clsid={clsid}",
            DisplayName: "Sample Context Menu ShellExtension");
        Assert.False(differ.IsLiveItemSuppressed(reEnabledDirSnapshot));

        // 共享同一 DLL 与 CLSID 的 Folder 与 * 场景绝不能被 BIN| 或 CLSID| 跨场景连带抑制
        var folderSnapshot = new StartupGuard.Service.Monitoring.SystemStateSnapshotDiffer.SnapshotItem(
            MonitorCategory.ClassicContextMenu,
            folderLoc,
            dllPath,
            $"Scene=Folder, Enabled=True, Clsid={clsid}",
            DisplayName: "Sample Context Menu ShellExtension");
        var starSnapshot = new StartupGuard.Service.Monitoring.SystemStateSnapshotDiffer.SnapshotItem(
            MonitorCategory.ClassicContextMenu,
            starLoc,
            dllPath,
            $"Scene=*, Enabled=True, Clsid={clsid}",
            DisplayName: "Sample Context Menu ShellExtension");
        Assert.False(differ.IsLiveItemSuppressed(folderSnapshot));
        Assert.False(differ.IsLiveItemSuppressed(starSnapshot));
    }

    [Fact]
    public void PendingAudit_MultiSceneContextMenu_AllThreeScenesRetainedAndUiContractSatisfied()
    {
        string dbPath = Path.Combine(Path.GetTempPath(), $"sg_ctx_test_{Guid.NewGuid():N}.db");
        try
        {
            using var repo = new SqliteRuleRepository(dbPath);
            string[] scenes = { "*", "Directory", "Folder" };
            foreach (string s in scenes)
            {
                repo.WriteAuditLog(
                    ruleId: null,
                    category: MonitorCategory.ClassicContextMenu,
                    program: @"C:\ProgramData\samplesuite\shellextension\SampleShellExtensionx64.dll",
                    location: $@"HKLM\Software\Classes\{s}\shellex\ContextMenuHandlers\Sample Context Menu ShellExtension",
                    oldState: "(None - 新建项)",
                    newState: $"Scene={s}, Enabled=True",
                    action: "先拦截待审核",
                    score: 100.0,
                    diagnostic: "检测到新右键菜单【Sample Context Menu ShellExtension】，已先拦截屏蔽并加入待审核中心",
                    sourceProcess: @"C:\Downloads\samplesuite_setup.exe");
            }

            var logs = repo.GetRecentAuditLogs(20);
            Assert.Equal(3, logs.Count(l => l.ActionTaken == "先拦截待审核"));
            Assert.Contains(logs, l => l.LocationKey.Contains(@"\*\", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(logs, l => l.LocationKey.Contains(@"\Directory\", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(logs, l => l.LocationKey.Contains(@"\Folder\", StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            if (File.Exists(dbPath))
            {
                try { File.Delete(dbPath); } catch { }
            }
        }

        string? dir = AppContext.BaseDirectory;
        string? repoRoot = null;
        while (dir is not null)
        {
            if (File.Exists(Path.Combine(dir, "StartupGuard.slnx")))
            {
                repoRoot = dir;
                break;
            }
            dir = Directory.GetParent(dir)?.FullName;
        }
        Assert.NotNull(repoRoot);

        string mainCs = File.ReadAllText(Path.Combine(repoRoot!, "src", "StartupGuard.App", "MainWindow.xaml.cs"));
        Assert.Contains("withinSettlingGrace", mainCs);
        Assert.Contains("_allAuditItems = BuildPendingAuditItems", mainCs);
    }

    [Fact]
    public void ServiceRecentUserDecisionEnforcement_SuppressesDuplicatePopupAcrossVariants()
    {
        string folderEnabled = $@"HKLM\SOFTWARE\Classes\Folder\shellex\ContextMenuHandlers\TestCtx_{Guid.NewGuid():N}";
        string folderDisabled = folderEnabled.Replace(@"\ContextMenuHandlers\", @"\-ContextMenuHandlers\", StringComparison.OrdinalIgnoreCase);

        StartupGuard.Service.Program.RecordRecentUserDecision(folderEnabled, InterceptionAction.RollbackToDisabled, ttlSeconds: 12.0);
        Assert.True(StartupGuard.Service.Program.TryGetRecentUserDecision(folderEnabled, out var action1));
        Assert.Equal(InterceptionAction.RollbackToDisabled, action1);
        Assert.True(StartupGuard.Service.Program.TryGetRecentUserDecision(folderDisabled, out var action2));
        Assert.Equal(InterceptionAction.RollbackToDisabled, action2);

        StartupGuard.Service.Program.RecordRecentUserDecision(folderEnabled, InterceptionAction.RollbackToDisabled, ttlSeconds: -1.0);
        Assert.False(StartupGuard.Service.Program.TryGetRecentUserDecision(folderEnabled, out _));
    }

    [Fact]
    public void Differ_SyncMovedContextMenuSnapshot_MovesKeyAndFlipsEnabledState()
    {
        var differ = new SystemStateSnapshotDiffer();
        string enabledKey = @"HKLM\SOFTWARE\Classes\*\shellex\ContextMenuHandlers\TestHandler";
        string disabledKey = @"HKLM\SOFTWARE\Classes\*\shellex\-ContextMenuHandlers\TestHandler";

        var field = typeof(SystemStateSnapshotDiffer).GetField("_cachedSnapshot", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        Assert.NotNull(field);
        var dict = Assert.IsType<System.Collections.Concurrent.ConcurrentDictionary<string, SystemStateSnapshotDiffer.SnapshotItem>>(field!.GetValue(differ));
        dict[enabledKey] = new SystemStateSnapshotDiffer.SnapshotItem(
            MonitorCategory.ClassicContextMenu,
            enabledKey,
            @"C:\ProgramData\samplesuite\shellextension\SampleShellExtensionx64.dll",
            "Enabled=True, Scene=File (*), Clsid={2FF28EB9-3CFE-420A-810B-852C410F771E}");

        differ.SyncMovedContextMenuSnapshot(enabledKey, disabled: true);

        Assert.False(dict.ContainsKey(enabledKey));
        Assert.True(dict.TryGetValue(disabledKey, out var moved));
        Assert.Contains("Enabled=False", moved!.RawState);
    }

    [Fact]
    public void NativeSystemMonitorMatrix_ClassesKeysDoNotDuplicateWow64Watchers()
    {
        var matrix = StartupGuard.Service.Monitoring.NativeSystemMonitorMatrix.BuildFullSpectrumRegistryMatrix(userSid: null);

        var classesCtxTargets = matrix
            .Where(t => t.Category == MonitorCategory.ClassicContextMenu &&
                        t.SubKeyPath.StartsWith(@"SOFTWARE\Classes\", StringComparison.OrdinalIgnoreCase))
            .ToList();
        Assert.NotEmpty(classesCtxTargets);
        Assert.DoesNotContain(classesCtxTargets, t => t.AlsoWatchWow6432);

        Assert.Contains(matrix, t => t.SubKeyPath.EndsWith(@"CurrentVersion\Run", StringComparison.OrdinalIgnoreCase) && t.AlsoWatchWow6432);
        Assert.Contains(matrix, t => t.SubKeyPath.EndsWith(@"Shell Extensions\Approved", StringComparison.OrdinalIgnoreCase) && t.AlsoWatchWow6432);
    }

    [Fact]
    public void RulesRenderSignature_StableAcrossAuditChanges_ChangesOnRuleMutation()
    {
        var rules = new List<RuleRecord>
        {
            new()
            {
                RuleId = 1,
                DisplayName = "Sample Context Menu ShellExtension",
                Category = MonitorCategory.ClassicContextMenu,
                ActionType = InterceptionAction.RollbackToDisabled,
                RuleMode = RuleMatchMode.PermanentAdaptive,
                LocationKey = @"HKLM\SOFTWARE\Classes\Folder\shellex\ContextMenuHandlers\Sample Context Menu ShellExtension",
                NormalizedPath = @"C:\ProgramData\samplesuite\shellextension\SampleShellExtensionx64.dll"
            }
        };

        string sig1 = AppGroupingHelper.ComputeRulesRenderSignature(rules, "ByCategory", string.Empty, []);
        string sig2 = AppGroupingHelper.ComputeRulesRenderSignature(rules, "ByCategory", string.Empty, []);
        string sigByApp = AppGroupingHelper.ComputeRulesRenderSignature(rules, "ByApp", string.Empty, []);
        Assert.Equal(sig1, sig2);
        Assert.NotEqual(sig1, sigByApp);

        rules[0].ActionType = InterceptionAction.Allow;
        string sigChanged = AppGroupingHelper.ComputeRulesRenderSignature(rules, "ByCategory", string.Empty, []);
        Assert.NotEqual(sig1, sigChanged);

        string? dir = AppContext.BaseDirectory;
        string? repoRoot = null;
        while (dir is not null)
        {
            if (File.Exists(Path.Combine(dir, "StartupGuard.slnx")))
            {
                repoRoot = dir;
                break;
            }
            dir = Directory.GetParent(dir)?.FullName;
        }
        Assert.NotNull(repoRoot);
        string mainCs = File.ReadAllText(Path.Combine(repoRoot!, "src", "StartupGuard.App", "MainWindow.xaml.cs"));
        Assert.Contains("_lastRulesRenderSignature", mainCs);
    }

    [Fact]
    public void AboutAcknowledgements_ClickableStoreButtons_AndVerifiedLicensesOnly()
    {
        string? dir = AppContext.BaseDirectory;
        string? repoRoot = null;
        while (dir is not null)
        {
            if (File.Exists(Path.Combine(dir, "StartupGuard.slnx")))
            {
                repoRoot = dir;
                break;
            }
            dir = Directory.GetParent(dir)?.FullName;
        }
        Assert.NotNull(repoRoot);

        string xaml = File.ReadAllText(Path.Combine(repoRoot!, "src", "StartupGuard.App", "MainWindow.xaml"));
        int start = xaml.IndexOf("<!-- 开放源代码库与致谢", StringComparison.Ordinal);
        int end = xaml.IndexOf("</ScrollViewer>", start, StringComparison.Ordinal);
        Assert.True(start > 0 && end > start);
        string ackSection = xaml[start..end];

        Assert.Contains("Style=\"{StaticResource StoreLinkButtonStyle}\" Content=\"WPF-UI (MIT)\"", ackSection);
        Assert.Contains("Tag=\"https://github.com/lepoco/wpfui\"", ackSection);
        Assert.Contains("Style=\"{StaticResource StoreLinkButtonStyle}\" Content=\"ContextMenuMgr (GPL-3.0)\"", ackSection);
        Assert.Contains("Tag=\"https://github.com/PLFJY/ContextMenuMgr\"", ackSection);
        Assert.DoesNotContain("ElasticEase", xaml);
        Assert.Contains("Style=\"{StaticResource StoreLinkButtonStyle}\" Content=\"Microsoft.Data.Sqlite (MIT)\"", ackSection);
        Assert.Contains("Tag=\"https://github.com/dotnet/efcore\"", ackSection);

        Assert.DoesNotContain("System.Management", ackSection);
        Assert.DoesNotContain("TaskScheduler", ackSection);
        Assert.DoesNotContain("CommunityToolkit.Mvvm", ackSection);
        Assert.DoesNotContain("C#/Win32", ackSection);
    }

    [Fact]
    public void ContextMenuGuidResolver_DoesNotPoisonEmptyCacheBeforeInprocServerWritten()
    {
        if (!OperatingSystem.IsWindows()) return;

        Guid testGuid = Guid.NewGuid();
        string clsidSubKey = $@"Software\Classes\CLSID\{testGuid:B}";
        string tempDll = Path.Combine(Path.GetTempPath(), $"sg_delay_{testGuid:N}.dll");

        try
        {
            // 1. 模拟安装器先探测、此时 CLSID\InprocServer32 与 DLL 尚未落盘
            Assert.Equal(string.Empty, ContextMenuGuidResolver.GetClsidFilePath(testGuid));
            Assert.Equal(string.Empty, ContextMenuGuidResolver.GetClsidText(testGuid));
            Assert.Equal(string.Empty, ContextMenuGuidResolver.GetClsidIconLocation(testGuid));

            // 2. 安装器稍后写入物理 DLL、InprocServer32 与 LocalizedString
            File.WriteAllBytes(tempDll, [0x4D, 0x5A, 0x90, 0x00]);
            using var clsidKey = Registry.CurrentUser.CreateSubKey(clsidSubKey);
            clsidKey.SetValue(null, "Delayed Test Context Menu");
            using var inproc = clsidKey.CreateSubKey("InprocServer32");
            inproc.SetValue(null, tempDll);

            // 3. 再次解析必须命中真实路径和显示名，严禁被空缓存永久毒化
            Assert.Equal(tempDll, ContextMenuGuidResolver.GetClsidFilePath(testGuid));
            Assert.Equal("Delayed Test Context Menu", ContextMenuGuidResolver.GetClsidText(testGuid));
            Assert.Equal(tempDll, ContextMenuGuidResolver.GetClsidIconLocation(testGuid));
        }
        finally
        {
            try { Registry.CurrentUser.DeleteSubKeyTree(clsidSubKey, throwOnMissingSubKey: false); } catch { }
            try { if (File.Exists(tempDll)) File.Delete(tempDll); } catch { }
        }
    }

    [Fact]
    public void PendingAuditAndServiceInterception_NoShowcaseSeed_AndNo100LogTruncation()
    {
        string tempDb = Path.Combine(Path.GetTempPath(), $"sg_pending_{Guid.NewGuid():N}.db");
        try
        {
            var repo = new SqliteRuleRepository(tempDb);
            // 插入 1 条最老的先拦截待审记录，再插入 130 条新日志（超过 100 条截断线）
            repo.WriteAuditLog(
                null,
                MonitorCategory.ClassicContextMenu,
                @"C:\ProgramData\samplesuite\shellextension\SampleShellExtensionx64.dll",
                @"HKLM\SOFTWARE\Classes\Folder\shellex\ContextMenuHandlers\Sample Context Menu ShellExtension",
                "",
                "Enabled=True",
                "先拦截待审核",
                100.0,
                "检测到新右键菜单【Sample Context Menu ShellExtension】");

            for (int i = 0; i < 130; i++)
            {
                repo.WriteAuditLog(
                    null,
                    MonitorCategory.StartupItem,
                    $@"C:\App\tool_{i}.exe",
                    $@"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Tool{i}",
                    "",
                    "Enabled=True",
                    "放行",
                    100.0,
                    "log filler");
            }

            var pending = repo.GetPendingAuditLogs();
            Assert.Single(pending);
            Assert.Contains("Folder", pending[0].LocationKey, StringComparison.OrdinalIgnoreCase);

            // 校验服务不自启植入 showcase 规则、Session 0 不回写 PromptMode、Policy 掩码默认 0xFF
            string repoRoot = FindRepoRoot();
            string serviceCs = File.ReadAllText(Path.Combine(repoRoot, "src", "StartupGuard.Service", "Program.cs"));
            Assert.DoesNotContain("SeedDefaultShowcaseRulesIfEmpty()", serviceCs);
            Assert.DoesNotContain("UserSettingsStore.SetContextMenuPromptMode", serviceCs);

            string matrixCs = File.ReadAllText(Path.Combine(repoRoot, "src", "StartupGuard.Service", "Monitoring", "NativeSystemMonitorMatrix.cs"));
            Assert.Contains("_enabledCategoriesMask = 0xFF", matrixCs);

            string differCs = File.ReadAllText(Path.Combine(repoRoot, "src", "StartupGuard.Service", "Monitoring", "SystemStateSnapshotDiffer.cs"));
            Assert.DoesNotContain("liveItems.ToDictionary(", differCs);
        }
        finally
        {
            try { if (File.Exists(tempDb)) File.Delete(tempDb); } catch { }
            try { if (File.Exists(tempDb + "-wal")) File.Delete(tempDb + "-wal"); } catch { }
            try { if (File.Exists(tempDb + "-shm")) File.Delete(tempDb + "-shm"); } catch { }
        }
    }

    [Fact]
    public void GlobalSearchHelper_IncludesSystemItems_ResolvesBadgesAndRoutes_AndMainWindowSupportsInlineActions()
    {
        var startupItems = new[]
        {
            new GlobalSearchFields(
                MonitorCategory.Win32Service,
                "Windows Update",
                "Microsoft Windows",
                "Windows Update",
                @"C:\Windows\system32\svchost.exe -k netsvcs",
                @"HKLM\SYSTEM\CurrentControlSet\Services\wuauserv",
                string.Empty,
                string.Empty,
                string.Empty,
                "手动"),
            new GlobalSearchFields(
                MonitorCategory.StartupItem,
                "Sample Sync",
                "Sample Vendor",
                "samplesuite",
                @"C:\Program Files (x86)\samplesuite\sync.exe",
                @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\SampleSync",
                string.Empty,
                string.Empty,
                string.Empty,
                "已启用")
        };

        var ctxItems = new[]
        {
            new GlobalSearchFields(
                MonitorCategory.ClassicContextMenu,
                "Sample Context Menu ShellExtension",
                "Sample Vendor",
                "samplesuite",
                @"C:\ProgramData\samplesuite\shellextension\SampleShellExtensionx64.dll",
                @"HKLM\Software\Classes\Folder\shellex\ContextMenuHandlers\Sample Context Menu ShellExtension",
                "Folder",
                "{2FF28EB9-3CFE-420A-810B-852C410F771E}",
                string.Empty,
                "已启用"),
            new GlobalSearchFields(
                MonitorCategory.ModernContextMenu,
                "Terminal",
                "Microsoft Corporation",
                "Windows Terminal",
                @"C:\Program Files\WindowsApps\Microsoft.WindowsTerminal\wt.exe",
                @"Approved:{9F156763-7844-4DC4-B2B1-901F640F5155}",
                "Win11PackagedCom",
                "{9F156763-7844-4DC4-B2B1-901F640F5155}",
                string.Empty,
                "已启用")
        };

        // 1. 不受隐藏系统项限制：能同时命中微软系统服务、Run 路径及 Win11 现代菜单
        var winMatches = GlobalSearchHelper.SearchItems(startupItems, ctxItems, null, "Windows", x => x);
        Assert.Equal(3, winMatches.Count);

        var msMatches = GlobalSearchHelper.SearchItems(startupItems, ctxItems, null, "Microsoft", x => x);
        Assert.Contains(msMatches, x => x.DisplayName == "Windows Update");
        Assert.Contains(msMatches, x => x.DisplayName == "Terminal");

        // 2. 类型与场景徽章精准区分自启 vs 右键与具体场景
        Assert.Equal("自启 · 系统服务", GlobalSearchHelper.GetTypeBadgeText(MonitorCategory.Win32Service, startupItems[0].LocationKey, ""));
        Assert.Equal("右键 · 文件夹", GlobalSearchHelper.GetTypeBadgeText(MonitorCategory.ClassicContextMenu, ctxItems[0].LocationKey, ctxItems[0].ScopeScene));
        Assert.Equal("右键 · Win11 现代菜单", GlobalSearchHelper.GetTypeBadgeText(MonitorCategory.ModernContextMenu, ctxItems[1].LocationKey, ctxItems[1].ScopeScene));

        // 3. 跳转详情目标页与子导航一致
        var folderNav = GlobalSearchHelper.ResolveNavigationTarget(MonitorCategory.ClassicContextMenu, ctxItems[0].LocationKey, ctxItems[0].ScopeScene);
        Assert.Equal(new GlobalSearchNavigationTarget("PageContextMenu", "Scene_Folder"), folderNav);
        var modernNav = GlobalSearchHelper.ResolveNavigationTarget(MonitorCategory.ModernContextMenu, ctxItems[1].LocationKey, ctxItems[1].ScopeScene);
        Assert.Equal(new GlobalSearchNavigationTarget("PageContextMenu", "Win11Modern"), modernNav);
        var svcNav = GlobalSearchHelper.ResolveNavigationTarget(MonitorCategory.Win32Service, startupItems[0].LocationKey, "");
        Assert.Equal(new GlobalSearchNavigationTarget("PageStartupManager", null), svcNav);

        // 4. UI 与代码后置契约：顶部搜索框 + 内联开关/下拉框 + 查看详情跳转
        string repoRoot = FindRepoRoot();
        string xaml = File.ReadAllText(Path.Combine(repoRoot, "src", "StartupGuard.App", "MainWindow.xaml"));
        string mainCs = File.ReadAllText(Path.Combine(repoRoot, "src", "StartupGuard.App", "MainWindow.xaml.cs"));
        Assert.Contains("x:Name=\"TxtGlobalSearch\"", xaml);
        Assert.Contains("x:Name=\"GlobalSearchOverlay\"", xaml);
        Assert.Contains("x:Name=\"ListViewGlobalSearch\"", xaml);
        Assert.Contains("Click=\"BtnGlobalSearchViewDetail_Click\"", xaml);
        Assert.Contains("Click=\"TglStartupItem_Click\"", xaml);
        Assert.Contains("SelectionChanged=\"CmbStartupItemState_SelectionChanged\"", xaml);
        Assert.Contains("OpenItemDetailDialog(item);", mainCs);
    }

    [Fact]
    public void GlobalSearchHelper_SupportsCategoryFiltersAndUnifiedOrderWithPolicyAfterTask()
    {
        Assert.Equal(
            [
                MonitorCategory.StartupItem,
                MonitorCategory.Win32Service,
                MonitorCategory.KernelDriver,
                MonitorCategory.ScheduledTask,
                MonitorCategory.WindowsPolicy,
                MonitorCategory.ClassicContextMenu,
                MonitorCategory.ModernContextMenu
            ],
            GlobalSearchHelper.OrderedFilterCategories);

        var startup = new[]
        {
            new GlobalSearchFields(MonitorCategory.StartupItem, "AppRun", "Corp", "App", "app.exe", @"HKCU\Run\App", "", "", "", "已启用"),
            new GlobalSearchFields(MonitorCategory.ScheduledTask, "DailyTask", "Corp", "Task", "task.exe", @"Task\DailyTask", "", "", "", "已启用"),
            new GlobalSearchFields(MonitorCategory.WindowsPolicy, "PolicyLock", "Microsoft", "Policy", "policy", @"HKLM\Policies\System", "", "", "", "已启用")
        };
        var ctx = new[]
        {
            new GlobalSearchFields(MonitorCategory.ClassicContextMenu, "ClassicExt", "Corp", "Ctx", "ext.dll", @"HKLM\Classes\*\shell\Ext", "AllFiles", "", "", "已启用"),
            new GlobalSearchFields(MonitorCategory.ModernContextMenu, "ModernExt", "Corp", "Pkg", "pkg.dll", @"Approved:{11111111-1111-1111-1111-111111111111}", "Win11", "{11111111-1111-1111-1111-111111111111}", "", "已启用")
        };

        var startupOnly = GlobalSearchHelper.SearchItems(
            startup, ctx, null, string.Empty, x => x,
            allowedCategories: GlobalSearchHelper.StartupFilterCategories.ToHashSet(),
            allowEmptyQueryWhenFiltered: true);
        Assert.Equal(3, startupOnly.Count);
        Assert.DoesNotContain(startupOnly, x => x.Category is MonitorCategory.ClassicContextMenu or MonitorCategory.ModernContextMenu);

        var contextOnly = GlobalSearchHelper.SearchItems(
            startup, ctx, null, string.Empty, x => x,
            allowedCategories: GlobalSearchHelper.ContextMenuFilterCategories.ToHashSet(),
            allowEmptyQueryWhenFiltered: true);
        Assert.Equal(2, contextOnly.Count);
        Assert.All(contextOnly, x => Assert.True(x.Category is MonitorCategory.ClassicContextMenu or MonitorCategory.ModernContextMenu));

        var policyOnly = GlobalSearchHelper.SearchItems(
            startup, ctx, null, "Policy", x => x,
            allowedCategories: new HashSet<MonitorCategory> { MonitorCategory.WindowsPolicy });
        Assert.Single(policyOnly);

        var emptyFilter = GlobalSearchHelper.SearchItems(
            startup, ctx, null, "Corp", x => x,
            allowedCategories: new HashSet<MonitorCategory>());
        Assert.Empty(emptyFilter);

        // XAML 内日志筛选与全局搜索筛选顺序：系统策略均在计划任务之后、右键之前
        string xaml = File.ReadAllText(Path.Combine(FindRepoRoot(), "src", "StartupGuard.App", "MainWindow.xaml"));
        int logTask = xaml.IndexOf("x:Name=\"ChkCatScheduledTask\"", StringComparison.Ordinal);
        int logPolicy = xaml.IndexOf("x:Name=\"ChkCatWindowsPolicy\"", StringComparison.Ordinal);
        int logClassic = xaml.IndexOf("x:Name=\"ChkCatClassicMenu\"", StringComparison.Ordinal);
        Assert.True(logTask > 0 && logTask < logPolicy && logPolicy < logClassic);

        int gsTask = xaml.IndexOf("x:Name=\"ChkGlobalCatScheduledTask\"", StringComparison.Ordinal);
        int gsPolicy = xaml.IndexOf("x:Name=\"ChkGlobalCatWindowsPolicy\"", StringComparison.Ordinal);
        int gsClassic = xaml.IndexOf("x:Name=\"ChkGlobalCatClassicMenu\"", StringComparison.Ordinal);
        Assert.True(gsTask > 0 && gsTask < gsPolicy && gsPolicy < gsClassic);

        Assert.Contains("Click=\"ChkGlobalGroupStartup_Click\"", xaml);
        Assert.Contains("Click=\"ChkGlobalGroupContextMenu_Click\"", xaml);
        Assert.Contains("Click=\"ChkLogsGroupStartup_Click\"", xaml);
        Assert.Contains("Click=\"ChkLogsGroupContextMenu_Click\"", xaml);
        Assert.DoesNotContain("BtnGlobalSearchSelectAll_Click", xaml);
        Assert.Contains("x:Name=\"BtnGlobalSearchFilterToggle\"", xaml);
        Assert.Contains("x:Name=\"TxtGlobalSearch\"", xaml);
        Assert.Contains("Height=\"34\"", xaml);
        Assert.Contains("<ColumnDefinition Width=\"*\" MinWidth=\"190\"/>", xaml);
    }

    [Fact]
    public void WinXMenuService_GroupOrderMoveHideRenameDeleteAndRestoreWorkInIsolatedTempDir()
    {
        string tempRoot = Path.Combine(Path.GetTempPath(), $"StartupGuard_WinX_Test_{Guid.NewGuid():N}");
        string liveDir = Path.Combine(tempRoot, "LiveWinX");
        string defaultDir = Path.Combine(tempRoot, "DefaultWinX");

        try
        {
            string g1 = Path.Combine(liveDir, "Group1");
            string g3 = Path.Combine(liveDir, "Group3");
            string defG3 = Path.Combine(defaultDir, "Group3");
            Directory.CreateDirectory(g1);
            Directory.CreateDirectory(g3);
            Directory.CreateDirectory(defG3);

            File.WriteAllText(Path.Combine(g1, "01 - Desktop.lnk"), "dummy");
            File.WriteAllText(Path.Combine(g3, "01 - Shell.lnk"), "dummy");
            File.WriteAllText(Path.Combine(g3, "02 - Disk.lnk"), "dummy");
            File.WriteAllText(Path.Combine(defG3, "01 - DefaultTool.lnk"), "dummy");

            File.WriteAllText(Path.Combine(g3, "desktop.ini"), "[LocalizedFileNames]\r\n01 - Shell.lnk=命令提示符\r\n02 - Disk.lnk=磁盘管理\r\n");

            var groups = WinXMenuService.ScanGroups(liveDir, defaultDir, autoNormalizePrefixes: true, out _);
            Assert.Equal(["Group3", "Group1"], groups.Select(g => g.GroupName).ToArray());
            Assert.Equal(["磁盘管理", "命令提示符"], groups[0].Items.Select(i => i.DisplayName).ToArray());
            Assert.False(groups[0].Items[0].CanMoveUp);
            Assert.True(groups[0].Items[0].CanMoveDown);
            Assert.True(groups[0].Items[1].CanMoveUp);
            Assert.False(groups[0].Items[1].CanMoveDown);
            Assert.True(groups[0].CanRestoreDefault);
            Assert.False(groups[1].CanRestoreDefault);

            // 上移 "命令提示符" (Index 1 -> 0)
            bool moved = WinXMenuService.MoveItem(g3, groups[0].Items[1].FilePath, moveUp: true);
            Assert.True(moved);

            var afterMove = WinXMenuService.ScanGroups(liveDir, defaultDir, autoNormalizePrefixes: false, out _);
            Assert.Equal(["命令提示符", "磁盘管理"], afterMove[0].Items.Select(i => i.DisplayName).ToArray());

            // 隐藏/显示开关
            Assert.True(WinXMenuService.SetItemEnabled(afterMove[0].Items[0].FilePath, enable: false));
            Assert.False(WinXMenuService.ScanGroups(liveDir, defaultDir, autoNormalizePrefixes: false, out _)[0].Items[0].IsEnabled);
            Assert.True(WinXMenuService.SetGroupEnabled(g1, enable: false));
            Assert.False(WinXMenuService.ScanGroups(liveDir, defaultDir, autoNormalizePrefixes: false, out _)[1].IsEnabled);

            // 恢复默认组
            Assert.True(WinXMenuService.RestoreDefaultGroup(g3, defaultDir));
            var restored = WinXMenuService.ScanGroups(liveDir, defaultDir, autoNormalizePrefixes: false, out _);
            Assert.Single(restored[0].Items);
            Assert.Equal("DefaultTool", restored[0].Items[0].DisplayName);

            // 新建分组 + 重命名 + 删除
            string? created = WinXMenuService.CreateNewGroup(liveDir);
            Assert.NotNull(created);
            string? renamed = WinXMenuService.RenameGroup(created!, "GroupCustom");
            Assert.NotNull(renamed);
            Assert.True(Directory.Exists(renamed!));
            Assert.True(WinXMenuService.DeleteGroup(renamed!));
            Assert.False(Directory.Exists(renamed!));
        }
        finally
        {
            try
            {
                if (Directory.Exists(tempRoot))
                {
                    foreach (string f in Directory.EnumerateFiles(tempRoot, "*", SearchOption.AllDirectories))
                        try { File.SetAttributes(f, FileAttributes.Normal); } catch { }
                    foreach (string d in Directory.EnumerateDirectories(tempRoot, "*", SearchOption.AllDirectories))
                        try { File.SetAttributes(d, FileAttributes.Normal); } catch { }
                    Directory.Delete(tempRoot, recursive: true);
                }
            }
            catch { }
        }
    }

    [Fact]
    public void ThemeNotificationLoadingAndLicenseComplianceContractsHold()
    {
        string repoRoot = FindRepoRoot();
        string mainCs = File.ReadAllText(Path.Combine(repoRoot, "src", "StartupGuard.App", "MainWindow.xaml.cs"));
        string mainXaml = File.ReadAllText(Path.Combine(repoRoot, "src", "StartupGuard.App", "MainWindow.xaml"));
        string nsi = File.ReadAllText(Path.Combine(repoRoot, "installer", "StartupGuard.nsi"));

        // 1. 跟随系统主题实时监听广播 + 标题栏与搜索框点击穿透
        Assert.Contains("UserPreferenceChanged +=", mainCs);
        Assert.Contains("WM_SETTINGCHANGE", mainCs);
        Assert.Contains("WM_NCHITTEST", mainCs);
        Assert.Contains("AppTitleBar_WndProcInvoked", mainCs);
        Assert.Contains("WndProcInvoked=\"AppTitleBar_WndProcInvoked\"", mainXaml);
        Assert.Contains("IsScreenPointOverElement", mainCs);

        // 2. 通知开关在弹窗模式下视觉关闭并置灰，且切回先拦截还原
        Assert.Contains("ToggleContextMenuNotification.IsChecked = promptMode", mainCs);
        Assert.False(UserSettingsStore.GetEffectiveContextMenuNotificationsEnabled(promptMode: true));

        // 3. 加载动画零强制等待 + 队列未结束不提前隐藏
        Assert.DoesNotContain("minimumOverlayMs: 380", mainCs);
        Assert.Contains("_queuedShowOverlay", mainCs);

        // 4. NSIS 卸载先退出目录锁并清理根目录
        Assert.Contains("SetOutPath \"$TEMP\"", nsi);
        Assert.Contains("RMDir /REBOOTOK \"$INSTDIR\"", nsi);
        Assert.Contains("rmdir /s /q \"$INSTDIR\"", nsi);

        // 5. 注释洁净检查
        Assert.DoesNotContain("铁律", mainCs);
        Assert.DoesNotContain("全谱系", mainCs);
    }

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null)
        {
            if (File.Exists(Path.Combine(dir.FullName, "StartupGuard.slnx")))
                return dir.FullName;
            dir = dir.Parent;
        }
        throw new DirectoryNotFoundException("Could not locate StartupGuard.slnx from test base directory.");
    }

    private static TargetProgramFeatures CreateFeatureForRuleMatchTest(
        MonitorCategory category,
        string displayName,
        string binaryPath,
        string locationKey,
        string md5Hex) => new()
        {
            Category = category,
            DisplayName = displayName,
            TargetBinaryPath = binaryPath,
            NormalizedPath = binaryPath.ToLowerInvariant(),
            NormalizedPathHash = 1,
            RawCommandLine = binaryPath,
            CommandLineArgsTemplate = string.Empty,
            LocationKeyOrIdentifier = locationKey,
            MD5Hex = md5Hex,
            SHA256Hex = new string('A', 64)
        };

    [Fact]
    public void RuleMatchIsolation_PendingUninstallCleanup_AndSearchDragFiltersHold()
    {
        // 1. StrictCurrentVersion / PermanentAdaptive 不可因共享 DLL MD5 或同名而在 */Folder/Directory 或跨类别串扰
        var sharedMd5 = "0123456789ABCDEF0123456789ABCDEF";
        var ruleOnStar = new RuleRecord
        {
            RuleId = 101,
            Category = MonitorCategory.ClassicContextMenu,
            DisplayName = "Sample Context Menu ShellExtension",
            NormalizedPath = @"C:\ProgramData\samplesuite\shellextension\SampleShellExtensionx64.dll",
            LocationKey = @"HKLM\SOFTWARE\Classes\*\shellex\ContextMenuHandlers\Sample Context Menu ShellExtension",
            CurrentMD5 = sharedMd5,
            RuleMode = RuleMatchMode.StrictCurrentVersion,
            ActionType = InterceptionAction.RollbackToDisabled
        };

        var folderFeature = CreateFeatureForRuleMatchTest(
            MonitorCategory.ClassicContextMenu,
            "Sample Context Menu ShellExtension",
            @"C:\ProgramData\samplesuite\shellextension\SampleShellExtensionx64.dll",
            @"HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Folder\shellex\ContextMenuHandlers\Sample Context Menu ShellExtension",
            sharedMd5);
        var starDisabledFeature = CreateFeatureForRuleMatchTest(
            MonitorCategory.ClassicContextMenu,
            "Sample Context Menu ShellExtension",
            @"C:\ProgramData\samplesuite\shellextension\SampleShellExtensionx64.dll",
            @"HKEY_LOCAL_MACHINE\SOFTWARE\Classes\*\shellex\-ContextMenuHandlers\Sample Context Menu ShellExtension",
            sharedMd5);
        var startupFeatureSameMd5 = CreateFeatureForRuleMatchTest(
            MonitorCategory.StartupItem,
            "Sample Context Menu ShellExtension",
            @"C:\ProgramData\samplesuite\shellextension\SampleShellExtensionx64.dll",
            @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SampleApp",
            sharedMd5);

        Assert.Null(StartupGuard.Service.Program.EvaluateRuleMatch([ruleOnStar], folderFeature));
        Assert.Null(StartupGuard.Service.Program.EvaluateRuleMatch([ruleOnStar], startupFeatureSameMd5));
        Assert.NotNull(StartupGuard.Service.Program.EvaluateRuleMatch([ruleOnStar], starDisabledFeature));

        ruleOnStar.RuleMode = RuleMatchMode.PermanentAdaptive;
        Assert.Null(StartupGuard.Service.Program.EvaluateRuleMatch([ruleOnStar], folderFeature));
        Assert.NotNull(StartupGuard.Service.Program.EvaluateRuleMatch([ruleOnStar], starDisabledFeature));

        // 2. 注册表已删除但目标 DLL 仍残留磁盘，或 DLL 已删除但 -ContextMenuHandlers 备份键残留时，均应判定为已移除并核销待审核
        if (OperatingSystem.IsWindows())
        {
            string testId = Guid.NewGuid().ToString("N");
            string rootSub = $@"Software\StartupGuard\TestPendingClean_{testId}";
            string disabledHandlerSub = $@"{rootSub}\-ContextMenuHandlers\TestHandler";
            string enabledHandlerLoc = $@"HKCU\{rootSub}\ContextMenuHandlers\TestHandler";
            string tempDll = Path.Combine(Path.GetTempPath(), $"sg_uninstall_test_{testId}.dll");
            File.WriteAllText(tempDll, "dummy");

            try
            {
                using (var key = Registry.CurrentUser.CreateSubKey(disabledHandlerSub, writable: true))
                {
                    key?.SetValue(null, "{11111111-2222-3333-4444-555555555555}");
                }

                // 场景 A：注册表变体与目标 DLL 均存在 -> 保留待审核
                Assert.True(ShellNavigationHelper.DoesPendingLocationStillExist(enabledHandlerLoc, tempDll));
                Assert.True(ShellNavigationHelper.IsPendingAuditTargetStillInstalled(
                    enabledHandlerLoc, tempDll, MonitorCategory.ClassicContextMenu, matchedLiveItemExists: true));

                // 场景 B：卸载删除了 DLL，但 -ContextMenuHandlers 孤儿备份键仍在 -> 应判定已卸载
                File.Delete(tempDll);
                Assert.False(ShellNavigationHelper.IsPendingAuditTargetStillInstalled(
                    enabledHandlerLoc, tempDll, MonitorCategory.ClassicContextMenu, matchedLiveItemExists: true));

                // 场景 C：重建 DLL 但删除注册表键（DLL 被占用残留在磁盘）-> 不得因 DLL 残留而滞留待审核
                File.WriteAllText(tempDll, "dummy-locked");
                Registry.CurrentUser.DeleteSubKeyTree(rootSub, throwOnMissingSubKey: false);
                Assert.False(ShellNavigationHelper.DoesPendingLocationStillExist(enabledHandlerLoc, tempDll));
                Assert.False(ShellNavigationHelper.IsPendingAuditTargetStillInstalled(
                    enabledHandlerLoc, tempDll, MonitorCategory.ClassicContextMenu, matchedLiveItemExists: false));
            }
            finally
            {
                try { Registry.CurrentUser.DeleteSubKeyTree(rootSub, throwOnMissingSubKey: false); } catch { }
                try { if (File.Exists(tempDll)) File.Delete(tempDll); } catch { }
            }
        }

        // 3. 搜索框按住拖动/点击搜索、去焦点误弹出、筛选文字精简与安装前停服契约
        string repoRoot = FindRepoRoot();
        string mainCs = File.ReadAllText(Path.Combine(repoRoot, "src", "StartupGuard.App", "MainWindow.xaml.cs"));
        string mainXaml = File.ReadAllText(Path.Combine(repoRoot, "src", "StartupGuard.App", "MainWindow.xaml"));
        string nsi = File.ReadAllText(Path.Combine(repoRoot, "installer", "StartupGuard.nsi"));

        Assert.DoesNotContain("TxtGlobalSearch_GotFocus", mainXaml);
        Assert.DoesNotContain("TxtGlobalSearch_GotFocus", mainCs);
        Assert.Contains("TxtGlobalSearch_PreviewMouseMove", mainXaml);
        Assert.Contains("TxtGlobalSearch_PreviewMouseLeftButtonUp", mainXaml);
        Assert.Contains("DragMove()", mainCs);

        Assert.DoesNotContain("Content=\"全部自启\"", mainXaml);
        Assert.DoesNotContain("Content=\"全部右键\"", mainXaml);
        Assert.DoesNotContain("分类筛选（勾选左侧大类可一键全选或取消该类）", mainXaml);

        Assert.Contains("sc.exe stop StartupGuardService", nsi);
    }

    [Fact]
    public void StaleRuleCacheForeignKeySafetyAndNoAutoSearchPopupContractsHold()
    {
        // 1. SQLite 更新不存在/已被清理的 RuleId 时不得因插入 RuleWeights 抛出 FOREIGN KEY constraint failed
        string tempDb = Path.Combine(Path.GetTempPath(), $"sg_fk_test_{Guid.NewGuid():N}.db");
        try
        {
            using var repo = new StartupGuard.Core.Storage.SqliteRuleRepository(tempDb);
            var staleRule = new RuleRecord
            {
                RuleId = 99999,
                DisplayName = "DeletedStaleRule",
                Category = MonitorCategory.ClassicContextMenu,
                ActionType = InterceptionAction.RollbackToDisabled,
                RuleMode = RuleMatchMode.PermanentAdaptive,
                LocationKey = @"HKLM\Software\Classes\*\shellex\ContextMenuHandlers\DeletedStaleRule",
                NormalizedPath = @"C:\Temp\DeletedStaleRule.dll"
            };
            int savedId = repo.InsertOrUpdateRule(staleRule);
            Assert.Equal(0, savedId);
        }
        finally
        {
            try { if (File.Exists(tempDb)) File.Delete(tempDb); } catch { }
            try { if (File.Exists(tempDb + "-wal")) File.Delete(tempDb + "-wal"); } catch { }
            try { if (File.Exists(tempDb + "-shm")) File.Delete(tempDb + "-shm"); } catch { }
        }

        // 2. RefreshGlobalSearchResults(false) 绝不在搜索浮层未打开时因筛选子集/残留关键词而自动弹出，且暗黑模式全选框无外层边框
        string repoRoot = FindRepoRoot();
        string mainCs = File.ReadAllText(Path.Combine(repoRoot, "src", "StartupGuard.App", "MainWindow.xaml.cs"));
        string mainXaml = File.ReadAllText(Path.Combine(repoRoot, "src", "StartupGuard.App", "MainWindow.xaml"));
        string serviceCs = File.ReadAllText(Path.Combine(repoRoot, "src", "StartupGuard.Service", "Program.cs"));

        Assert.Contains("if (!overlayCurrentlyOpen && !forceOpenOverlay)", mainCs);
        Assert.DoesNotContain("if (!overlayCurrentlyOpen && !forceOpenOverlay && string.IsNullOrWhiteSpace(query) && !isSubsetFiltered)", mainCs);
        Assert.Contains("Keyboard.ClearFocus()", mainCs);

        Assert.Contains("<CheckBox Grid.Column=\"0\" x:Name=\"ChkLogsGroupStartup\"", mainXaml);
        Assert.Contains("<CheckBox Grid.Column=\"0\" x:Name=\"ChkLogsGroupContextMenu\"", mainXaml);
        Assert.Contains("<CheckBox Grid.Column=\"0\" x:Name=\"ChkGlobalGroupStartup\"", mainXaml);
        Assert.Contains("<CheckBox Grid.Column=\"0\" x:Name=\"ChkGlobalGroupContextMenu\"", mainXaml);

        // 3. 孤儿清理需严格区分支撑 GUID 与普通经典注册表路径，并在清理后同步刷新内存规则缓存及单条异常隔离
        Assert.Contains("Guid.TryParse(extracted, out _)", serviceCs);
        Assert.Contains("ShellNavigationHelper.DoesPendingLocationStillExist(rule.LocationKey, resolvedBin)", serviceCs);
        Assert.Contains("_cachedRules = refreshed;", serviceCs);
        Assert.Contains("SharedStorageHelper.LogDiagnostic(\"InterceptError\"", serviceCs);
    }

    [Fact]
    public void GlobalSearchUnifiedHeaderPaginationAndDiagnosticLoggingDefaultOffHold()
    {
        // 1. 分页槽位算法验证
        Assert.Empty(GlobalSearchHelper.BuildPaginationSlots(1, 1));
        Assert.Equal([1, 2, 3], GlobalSearchHelper.BuildPaginationSlots(2, 3));
        Assert.Equal([1, null, 3, 4, 5, 6, 7, null, 10], GlobalSearchHelper.BuildPaginationSlots(5, 10));
        Assert.Equal([1, 2, 3, 4, null, 10], GlobalSearchHelper.BuildPaginationSlots(2, 10));
        Assert.Equal([1, null, 7, 8, 9, 10], GlobalSearchHelper.BuildPaginationSlots(9, 10));

        // 2. 全局搜索统一标题为“全局搜索”，无前80项与右侧副标题，且支持全量分页
        string repoRoot = FindRepoRoot();
        string mainCs = File.ReadAllText(Path.Combine(repoRoot, "src", "StartupGuard.App", "MainWindow.xaml.cs"));
        string mainXaml = File.ReadAllText(Path.Combine(repoRoot, "src", "StartupGuard.App", "MainWindow.xaml"));
        string settingsCs = File.ReadAllText(Path.Combine(repoRoot, "src", "StartupGuard.Core", "Configuration", "UserSettingsStore.cs"));

        Assert.DoesNotContain("前 80 项", mainCs);
        Assert.DoesNotContain("全局浏览", mainCs);
        Assert.DoesNotContain("已包含系统内置项与全部右键菜单", mainXaml);
        Assert.DoesNotContain("Text=\"全局搜索\"", mainXaml);
        Assert.Contains("maxResults: int.MaxValue", mainCs);
        Assert.Contains("GlobalSearchPagerBar", mainXaml);
        Assert.Contains("TxtGlobalPageInput", mainXaml);
        Assert.Contains("VerticalContentAlignment=\"Center\"", mainXaml);
        Assert.Contains("ListViewGlobalSearch_ScrollChanged", mainCs);
        Assert.Contains("CommitGlobalSearchPageInput", mainCs);

        // 3. 诊断运行日志默认关闭，避免占用普通用户磁盘
        Assert.Contains("ReadBoolSetting(\"DiagnosticLogging\", legacyKey: null, defaultValue: false)", settingsCs);
        Assert.Contains("x:Name=\"TglDiagnosticLogging\" IsChecked=\"False\"", mainXaml);
    }

    [Fact]
    public void PopupSelectedOnlyAiPrompt_AutoStartControls_TrayDarkThemeAndCleanCheckmark_Hold()
    {
        // 1. 仅复制勾选项目辅助筛选（绝不回退返回未勾选项）
        var sample = new[]
        {
            ("A", true),
            ("B", false),
            ("C", true)
        };
        var partialSelected = ShellNavigationHelper.SelectCheckedItems(sample, x => x.Item2);
        Assert.Equal(2, partialSelected.Count);
        Assert.Equal("A", partialSelected[0].Item1);
        Assert.Equal("C", partialSelected[1].Item1);

        var noneSelected = ShellNavigationHelper.SelectCheckedItems(new[] { ("B", false) }, x => x.Item2);
        Assert.Empty(noneSelected);
        Assert.Empty(ShellNavigationHelper.SelectCheckedItems<string>(null, _ => true));

        // 2. 应用内主题偏好同步解析 (Light / Dark / System)
        if (OperatingSystem.IsWindows())
        {
            string prevTheme = UserSettingsStore.GetThemePreference();
            try
            {
                UserSettingsStore.SetThemePreference("Dark");
                Assert.False(UserSettingsStore.IsEffectiveLightTheme());

                UserSettingsStore.SetThemePreference("Light");
                Assert.True(UserSettingsStore.IsEffectiveLightTheme());

                UserSettingsStore.SetThemePreference("System");
                Assert.Equal(UserSettingsStore.IsSystemAppsLightTheme(), UserSettingsStore.IsEffectiveLightTheme());
            }
            finally
            {
                UserSettingsStore.SetThemePreference(prevTheme);
            }
        }

        // 3. 源码契约：弹窗 AI 提示词、设置双自启开关、托盘右键深浅主题 + 无框单对勾 + 句柄释放
        string repoRoot = FindRepoRoot();
        string diffCs = File.ReadAllText(Path.Combine(repoRoot, "src", "StartupGuard.TrayHost", "InterceptionDiffDialogWindow.xaml.cs"));
        string trayCs = File.ReadAllText(Path.Combine(repoRoot, "src", "StartupGuard.TrayHost", "Program.cs"));
        string mainXaml = File.ReadAllText(Path.Combine(repoRoot, "src", "StartupGuard.App", "MainWindow.xaml"));
        string mainCs = File.ReadAllText(Path.Combine(repoRoot, "src", "StartupGuard.App", "MainWindow.xaml.cs"));
        string iconResolverCs = File.ReadAllText(Path.Combine(repoRoot, "src", "StartupGuard.App", "Services", "ProgramIconResolver.cs"));

        Assert.Contains("GetSelectedItemsForAiPrompt", diffCs);
        Assert.Contains("请先勾选项目", diffCs);
        Assert.DoesNotContain("targets = [.. _capturedItems]", diffCs);

        Assert.Contains("x:Name=\"TglTrayAutoStart\"", mainXaml);
        Assert.Contains("x:Name=\"TglServiceAutoStart\"", mainXaml);
        Assert.Contains("TglTrayAutoStart_Click", mainCs);
        Assert.Contains("TglServiceAutoStart_Click", mainCs);

        Assert.Contains("UserSettingsStore.IsEffectiveLightTheme()", trayCs);
        Assert.Contains("ApplyContextMenuTheme", trayCs);
        Assert.Contains("DestroyIcon(hIcon)", trayCs);
        int checkIdx = trayCs.IndexOf("protected override void OnRenderItemCheck", StringComparison.Ordinal);
        Assert.True(checkIdx > 0);
        string checkMethodSlice = trayCs.Substring(checkIdx, Math.Min(650, trayCs.Length - checkIdx));
        Assert.DoesNotContain("FillPath", checkMethodSlice);
        Assert.DoesNotContain("DrawPath", checkMethodSlice);

        Assert.DoesNotContain("DestroyIcon(icon.Handle)", iconResolverCs);
    }

    [Fact]
    public void SingleVersionRuleCleanup_And_RuleDetailFormatting_WorkForUninstalledAppsAndFilelessEntries()
    {
        if (!OperatingSystem.IsWindows()) return;

        string tempDir = Path.Combine(Path.GetTempPath(), $"StartupGuard_RuleTest_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);
        string dbPath = Path.Combine(tempDir, "rules.db");
        string existingExe = Path.Combine(tempDir, "installed_app.exe");
        File.WriteAllBytes(existingExe, "DummyPEPayloadForMd5Check"u8.ToArray());
        var (existingMd5, existingSha) = NativeSecurityExtractor.ComputeFileHashesCng(existingExe);

        try
        {
            using var repo = new SqliteRuleRepository(dbPath);

            // 1. 模拟旧版已入库但软件已卸载的 <drive>:\ 单版本服务规则
            var sampleRule = new RuleRecord
            {
                DisplayName = "sample_remote_watch",
                Category = MonitorCategory.Win32Service,
                ActionType = InterceptionAction.RollbackToDemand,
                RuleMode = RuleMatchMode.StrictCurrentVersion,
                SignerSubject = "Sample Vendor Co., Ltd",
                NormalizedPath = @"<drive>:\program files (x86)\samplesuite\samplecontrol\depends\sample_remote_watch.exe",
                RawCommand = string.Empty,
                LocationKey = $@"HKLM\SYSTEM\CurrentControlSet\Services\sample_remote_watch_Missing_{Guid.NewGuid():N}.exe",
                CurrentMD5 = "16412ee2367a39d5e21ffe9ca2051294",
                CurrentSHA256 = ""
            };
            Assert.DoesNotContain("<drive>:", sampleRule.TargetBinaryOrCommand, StringComparison.OrdinalIgnoreCase);
            Assert.EndsWith(@"\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\" + Path.GetFileName(sampleRule.LocationKey), sampleRule.DisplayLocationKey);

            // 2. 无文件/无 MD5 但注册表目标已不存在的单版本自启与右键规则
            var filelessStartupRule = new RuleRecord
            {
                DisplayName = "FilelessMissingStartup",
                Category = MonitorCategory.StartupItem,
                ActionType = InterceptionAction.RollbackToDisabled,
                RuleMode = RuleMatchMode.StrictCurrentVersion,
                NormalizedPath = string.Empty,
                RawCommand = string.Empty,
                LocationKey = $@"HKCU\Software\StartupGuard_MissingRule_{Guid.NewGuid():N}\MissingVal",
                CurrentMD5 = string.Empty,
                CurrentSHA256 = string.Empty
            };

            var filelessContextRule = new RuleRecord
            {
                DisplayName = "FilelessMissingCtx",
                Category = MonitorCategory.ClassicContextMenu,
                ActionType = InterceptionAction.DeleteEntry,
                RuleMode = RuleMatchMode.StrictCurrentVersion,
                NormalizedPath = string.Empty,
                RawCommand = string.Empty,
                LocationKey = $@"HKCU\Software\Classes\*\shell\StartupGuard_MissingCtx_{Guid.NewGuid():N}",
                CurrentMD5 = string.Empty,
                CurrentSHA256 = string.Empty
            };

            // 3. 启动项 DeleteEntry 规则（注册表 Run 已被规则自身删除，但磁盘主程序仍存在且 MD5 未变）应暂保留
            var preservedDeleteRule = new RuleRecord
            {
                DisplayName = "PreservedInstalledApp",
                Category = MonitorCategory.StartupItem,
                ActionType = InterceptionAction.DeleteEntry,
                RuleMode = RuleMatchMode.StrictCurrentVersion,
                NormalizedPath = existingExe,
                RawCommand = existingExe,
                LocationKey = $@"HKCU\Software\StartupGuard_DeletedRun_{Guid.NewGuid():N}\PreservedApp",
                CurrentMD5 = existingMd5,
                CurrentSHA256 = existingSha
            };

            // 4. 永久拦截规则即便目标均不存在也绝不自动清理
            var permanentRule = new RuleRecord
            {
                DisplayName = "PermanentRuleKeep",
                Category = MonitorCategory.Win32Service,
                ActionType = InterceptionAction.RollbackToDisabled,
                RuleMode = RuleMatchMode.PermanentAdaptive,
                NormalizedPath = @"C:\NonExistent\perm_missing.exe",
                RawCommand = @"C:\NonExistent\perm_missing.exe",
                LocationKey = $@"HKLM\SYSTEM\CurrentControlSet\Services\PermMissing_{Guid.NewGuid():N}",
                CurrentMD5 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                CurrentSHA256 = ""
            };

            repo.InsertOrUpdateRule(sampleRule);
            repo.InsertOrUpdateRule(filelessStartupRule);
            repo.InsertOrUpdateRule(filelessContextRule);
            repo.InsertOrUpdateRule(preservedDeleteRule);
            repo.InsertOrUpdateRule(permanentRule);

            var res1 = Md5RuleValidator.ValidateAndCleanObsoleteMd5Rules(repo);
            Assert.Equal(4, res1.CheckedCount);
            Assert.Equal(3, res1.DeletedCount);

            var after1 = repo.GetAllRulesWithWeightsAndAliases();
            Assert.Equal(2, after1.Count);
            Assert.Contains(after1, r => r.DisplayName == "PreservedInstalledApp");
            Assert.Contains(after1, r => r.DisplayName == "PermanentRuleKeep");

            // 卸载后主程序被删除，再次清理应自动移除 PreservedInstalledApp
            File.Delete(existingExe);
            var res2 = Md5RuleValidator.ValidateAndCleanObsoleteMd5Rules(repo);
            Assert.Equal(1, res2.CheckedCount);
            Assert.Equal(1, res2.DeletedCount);

            var after2 = repo.GetAllRulesWithWeightsAndAliases();
            Assert.Single(after2);
            Assert.Equal("PermanentRuleKeep", after2[0].DisplayName);
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            try { Directory.Delete(tempDir, true); } catch { }
        }

        // UI 与 IPC 轮询日志契约断言
        string repoRoot = FindRepoRoot();
        string mainXaml = File.ReadAllText(Path.Combine(repoRoot, "src", "StartupGuard.App", "MainWindow.xaml"));
        string mainCs = File.ReadAllText(Path.Combine(repoRoot, "src", "StartupGuard.App", "MainWindow.xaml.cs"));
        string trayCs = File.ReadAllText(Path.Combine(repoRoot, "src", "StartupGuard.TrayHost", "Program.cs"));

        Assert.Contains("Binding Rule.DisplayLocationKey", mainXaml);
        Assert.Contains("Binding Rule.LastUpdatedLocal", mainXaml);
        Assert.Contains("BtnRuleOpenFile_Click", mainXaml);
        Assert.Contains("BtnRuleOpenLocation_Click", mainXaml);
        Assert.Contains("BtnRuleViewDetail_Click", mainXaml);
        Assert.Contains("BtnRuleCopyAiPrompt_Click", mainXaml);
        Assert.Contains("BtnRuleSearchWeb_Click", mainXaml);
        Assert.Contains("_lastSentTogglesSignature", trayCs);
        Assert.Contains("Md5RuleValidator.ValidateAndCleanObsoleteMd5Rules(_sqliteRepo)", mainCs);
    }

    [Fact]
    public void DriverSystemRootPath_ExtractsMd5AndBackfillsMissingRuleMetadata()
    {
        if (!OperatingSystem.IsWindows())
            return;

        string driversDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "drivers");
        string? anyDriver = Directory.Exists(driversDir)
            ? Directory.EnumerateFiles(driversDir, "*.sys").FirstOrDefault()
            : null;
        if (string.IsNullOrEmpty(anyDriver))
            return;

        string driverFileName = Path.GetFileName(anyDriver);
        string systemRootCmd = $@"\SystemRoot\system32\drivers\{driverFileName}";

        var features = NativeSecurityExtractor.BuildTargetProgramFeatures(
            MonitorCategory.KernelDriver,
            $@"HKLM\SYSTEM\CurrentControlSet\Services\{Path.GetFileNameWithoutExtension(driverFileName)}",
            systemRootCmd,
            displayName: Path.GetFileNameWithoutExtension(driverFileName));

        Assert.False(string.IsNullOrWhiteSpace(features.MD5Hex));
        Assert.False(string.IsNullOrWhiteSpace(features.SHA256Hex));
        Assert.Equal(systemRootCmd, features.RawCommandLine);
        Assert.True(File.Exists(features.TargetBinaryPath));

        string tempDir = Path.Combine(Path.GetTempPath(), "SG_DriverMeta_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        try
        {
            var repo = new SqliteRuleRepository(Path.Combine(tempDir, "rules.db"));
            repo.InsertOrUpdateRule(new RuleRecord
            {
                DisplayName = "LegacyDriverRule",
                Category = MonitorCategory.KernelDriver,
                ActionType = InterceptionAction.RollbackToDemand,
                RuleMode = RuleMatchMode.StrictCurrentVersion,
                NormalizedPath = systemRootCmd,
                RawCommand = systemRootCmd,
                LocationKey = $@"HKLM\SYSTEM\CurrentControlSet\Services\{Path.GetFileNameWithoutExtension(driverFileName)}",
                CurrentMD5 = string.Empty,
                CurrentSHA256 = string.Empty,
                HasSignature = false,
                SignerSubject = string.Empty
            });

            int backfilled = Md5RuleValidator.BackfillMissingRuleMetadata(repo);
            Assert.Equal(1, backfilled);

            var updated = Assert.Single(repo.GetAllRulesWithWeightsAndAliases());
            Assert.Equal(features.MD5Hex, updated.CurrentMD5);
            Assert.Equal(features.SHA256Hex, updated.CurrentSHA256);
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    [Fact]
    public void DifferApplyCategoryBaselineSnapshot_AbsorbsOnlyTargetCategory()
    {
        var differ = new StartupGuard.Service.Monitoring.SystemStateSnapshotDiffer();
        var svc = new StartupGuard.Service.Monitoring.SystemStateSnapshotDiffer.SnapshotItem(
            MonitorCategory.Win32Service,
            @"HKLM\SYSTEM\CurrentControlSet\Services\SvcA",
            @"C:\Tools\svcA.exe",
            "Start=2");
        Assert.Equal(1, differ.ApplyCategoryBaselineSnapshot(MonitorCategory.Win32Service, [svc]));

        var ctx1 = new StartupGuard.Service.Monitoring.SystemStateSnapshotDiffer.SnapshotItem(
            MonitorCategory.ClassicContextMenu,
            @"HKLM\Software\Classes\*\shellex\ContextMenuHandlers\Ctx1",
            @"C:\ProgramData\samplesuite\SampleShellExtensionx64.dll",
            "Enabled=True");
        Assert.Equal(1, differ.ApplyCategoryBaselineSnapshot(MonitorCategory.ClassicContextMenu, [ctx1]));

        // 重新同步 ClassicContextMenu 基线仅更新该分类，不应误删 Win32Service 基线
        var ctx2 = new StartupGuard.Service.Monitoring.SystemStateSnapshotDiffer.SnapshotItem(
            MonitorCategory.ClassicContextMenu,
            @"HKLM\Software\Classes\Directory\shellex\ContextMenuHandlers\Ctx2",
            @"C:\ProgramData\samplesuite\SampleShellExtensionx64.dll",
            "Enabled=True");
        Assert.Equal(1, differ.ApplyCategoryBaselineSnapshot(MonitorCategory.ClassicContextMenu, [ctx2]));
    }

    private sealed record LogNavCandidate(GlobalSearchFields Fields);

    [Fact]
    public void AuditLogJumpLookup_And_MsixUiContracts_Hold()
    {
        var candidates = new[]
        {
            new LogNavCandidate(new GlobalSearchFields(
                MonitorCategory.KernelDriver,
                "Dokan2",
                "Dokan",
                "Dokan",
                @"\SystemRoot\system32\drivers\dokan2.sys",
                @"HKLM\SYSTEM\CurrentControlSet\Services\Dokan2",
                string.Empty,
                string.Empty,
                string.Empty,
                "手动启动")),
            new LogNavCandidate(new GlobalSearchFields(
                MonitorCategory.ScheduledTask,
                "EdgeUpdate",
                "Microsoft",
                "Edge",
                @"C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe",
                @"Task: \MicrosoftEdgeUpdateTaskMachineUA{FDA886F6}",
                string.Empty,
                string.Empty,
                string.Empty,
                "已禁用")),
            new LogNavCandidate(new GlobalSearchFields(
                MonitorCategory.StartupItem,
                "msedge",
                "Microsoft",
                "Edge",
                @"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\msedge_test",
                string.Empty,
                string.Empty,
                string.Empty,
                "已启用"))
        };

        var matchDriver = GlobalSearchHelper.FindBestMatchingItemForLog(
            MonitorCategory.KernelDriver,
            @"Services\Dokan2",
            @"\SystemRoot\system32\drivers\dokan2.sys",
            candidates,
            x => x.Fields);
        Assert.NotNull(matchDriver);
        Assert.Equal("Dokan2", matchDriver!.Fields.DisplayName);

        var matchTask = GlobalSearchHelper.FindBestMatchingItemForLog(
            MonitorCategory.ScheduledTask,
            @"Task:\MicrosoftEdgeUpdateTaskMachineUA{FDA886F6}",
            "",
            candidates,
            x => x.Fields);
        Assert.NotNull(matchTask);
        Assert.Equal("EdgeUpdate", matchTask!.Fields.DisplayName);

        var matchHku = GlobalSearchHelper.FindBestMatchingItemForLog(
            MonitorCategory.StartupItem,
            @"HKU\S-1-5-21-1000-2000-3000-500\Software\Microsoft\Windows\CurrentVersion\Run\msedge_test",
            "",
            candidates,
            x => x.Fields);
        Assert.NotNull(matchHku);
        Assert.Equal("msedge", matchHku!.Fields.DisplayName);

        Assert.DoesNotContain(@"\WindowsApps\", SharedStorageHelper.GetSharedLogsDirectory(), StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(@"\WindowsApps\", SharedStorageHelper.GetSharedDataDirectory(), StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(@"\WindowsApps\", SharedStorageHelper.GetSafeWorkingDirectory(), StringComparison.OrdinalIgnoreCase);

        string repoRoot = FindRepoRoot();
        string mainXaml = File.ReadAllText(Path.Combine(repoRoot, "src", "StartupGuard.App", "MainWindow.xaml"));
        string mainCs = File.ReadAllText(Path.Combine(repoRoot, "src", "StartupGuard.App", "MainWindow.xaml.cs"));
        string appCs = File.ReadAllText(Path.Combine(repoRoot, "src", "StartupGuard.App", "App.xaml.cs"));
        string svcCs = File.ReadAllText(Path.Combine(repoRoot, "src", "StartupGuard.Service", "Program.cs"));

        Assert.Contains("AuditLogCard_MouseLeftButtonUp", mainXaml);
        Assert.Contains("AuditLogCard_MouseLeftButtonUp", mainCs);
        Assert.Contains("ToolTip=\"点击跳转到对应项进行管理\"", mainXaml);
        Assert.DoesNotContain("点击管理", mainXaml);
        Assert.Contains("Text=\"自启与服务管理\"", mainXaml);
        Assert.DoesNotContain("Text=\"开机自启\"", mainXaml);
        Assert.DoesNotContain("BtnRefreshServiceStatus", mainXaml);
        Assert.Contains("ServiceManagementContainer\" Visibility=\"Collapsed\"", mainXaml);
        Assert.Contains("SharedStorageHelper.GetSharedLogsDirectory()", appCs);
        Assert.Contains("_differ.RefreshCategoryBaseline", svcCs);
        Assert.Contains("ApplyMonitorToggleUpdate", svcCs);
    }

    [Fact]
    public void FollowUp_SearchUiPolish_And_MergedCollapsibleServiceCard_Hold()
    {
        string repoRoot = FindRepoRoot();
        string mainXaml = File.ReadAllText(Path.Combine(repoRoot, "src", "StartupGuard.App", "MainWindow.xaml"));
        string mainCs = File.ReadAllText(Path.Combine(repoRoot, "src", "StartupGuard.App", "MainWindow.xaml.cs"));

        // 1. 搜索框右侧隐藏筛选按钮、无全选全部/全局搜索/关闭叉号、组标签文案
        Assert.Contains("x:Name=\"BtnGlobalSearchFilterToggle\"", mainXaml);
        Assert.Contains("x:Name=\"GlobalSearchFilterPanel\" Grid.Row=\"0\"", mainXaml);
        Assert.Contains("Visibility=\"Collapsed\"", mainXaml);
        Assert.DoesNotContain("全选全部", mainXaml);
        Assert.DoesNotContain("BtnCloseGlobalSearch_Click", mainXaml);
        Assert.Contains("x:Name=\"ChkGlobalGroupStartup\" Content=\"自启项\"", mainXaml);
        Assert.Contains("x:Name=\"ChkGlobalGroupContextMenu\" Content=\"右键菜单\"", mainXaml);

        // 2. 点击标题栏空白处退出搜索
        Assert.Contains("TitleBarContainer_PreviewMouseLeftButtonDown", mainXaml);
        Assert.Contains("TryDismissGlobalSearchOnTitleBarNonClientClick", mainCs);

        // 3. 分页输入框垂直居中 & 翻到最下方显示页数选择器
        Assert.Contains("x:Name=\"TxtGlobalPageInput\"", mainXaml);
        Assert.Contains("ListViewGlobalSearch_ScrollChanged", mainXaml);
        Assert.Contains("SyncGlobalSearchPagerVisibility", mainCs);

        // 4. 自启与服务管理合并、默认折叠且自动刷新状态
        Assert.Contains("Text=\"自启与服务管理\"", mainXaml);
        Assert.Contains("HeaderToggleServiceManagement_MouseLeftButtonUp", mainXaml);
        Assert.DoesNotContain("BtnRefreshServiceStatus_Click", mainCs);
        Assert.Contains("if (PageSettings?.Visibility == Visibility.Visible)\n                UpdateServiceStatusUI();", mainCs.Replace("\r\n", "\n"));
        Assert.Contains("Dispatcher.InvokeAsync(UpdateServiceStatusUI);", mainCs);
    }

    [Fact]
    public void FollowUp_DriverThirdPartyWhqlNotSkipped_And_TrayMonochromeMenuHold()
    {
        var dokanDriver = new TargetProgramFeatures
        {
            TargetBinaryPath = @"C:\Windows\System32\drivers\dokan2.sys",
            NormalizedPath = @"C:\Windows\System32\drivers\dokan2.sys",
            NormalizedPathHash = 0x1001,
            RawCommandLine = @"\SystemRoot\system32\drivers\dokan2.sys",
            CommandLineArgsTemplate = string.Empty,
            LocationKeyOrIdentifier = @"HKLM\SYSTEM\CurrentControlSet\Services\Dokan2",
            DisplayName = "Dokan2",
            Category = MonitorCategory.KernelDriver,
            MD5Hex = "0123456789abcdef0123456789abcdef",
            SHA256Hex = new string('a', 64),
            HasValidSignature = true,
            IsWhqlCertified = true,
            SignerSubject = "Microsoft Windows Third Party Component CA 2014"
        };

        var vendorDriver = new TargetProgramFeatures
        {
            TargetBinaryPath = @"C:\Windows\System32\drivers\acme_drv.sys",
            NormalizedPath = @"C:\Windows\System32\drivers\acme_drv.sys",
            NormalizedPathHash = 0x1002,
            RawCommandLine = @"\SystemRoot\system32\drivers\acme_drv.sys",
            CommandLineArgsTemplate = string.Empty,
            LocationKeyOrIdentifier = @"HKLM\SYSTEM\CurrentControlSet\Services\AcmeDrv",
            DisplayName = "AcmeDrv",
            Category = MonitorCategory.KernelDriver,
            MD5Hex = "fedcba9876543210fedcba9876543210",
            SHA256Hex = new string('b', 64),
            HasValidSignature = true,
            IsWhqlCertified = false,
            SignerSubject = "Acme Vendor Inc."
        };

        Assert.False(NativeSecurityExtractor.IsWindowsEssentialOperatingSystemComponent(dokanDriver));
        Assert.False(NativeSecurityExtractor.IsWindowsEssentialOperatingSystemComponent(vendorDriver));

        string repoRoot = FindRepoRoot();
        string trayCs = File.ReadAllText(Path.Combine(repoRoot, "src", "StartupGuard.TrayHost", "Program.cs"));
        Assert.Contains("Color.FromArgb(0x1E, 0x1E, 0x1E)", trayCs);
        Assert.Contains("Color.FromArgb(0xF3, 0xF3, 0xF3)", trayCs);
        Assert.DoesNotContain("exitColor", trayCs);
        Assert.DoesNotContain("0xC4, 0x2B, 0x1C", trayCs);
        Assert.DoesNotContain("0x00, 0x67, 0xC0", trayCs);
    }

    [Fact]
    public void FollowUp_WinXHiddenDesktopIni_AppDeactivatedSearchClose_And_CompactExpandPagerHold()
    {
        // 1. 真实复现 Hidden | System | ReadOnly + 非 Unicode 的 WinX desktop.ini 在自动编号规范化时不抛 UnauthorizedAccessException
        string tempRoot = Path.Combine(Path.GetTempPath(), $"StartupGuard_WinX_AttrTest_{Guid.NewGuid():N}");
        string liveDir = Path.Combine(tempRoot, "LiveWinX");
        string defaultDir = Path.Combine(tempRoot, "DefaultWinX");
        string g3 = Path.Combine(liveDir, "Group3");
        string iniPath = Path.Combine(g3, "desktop.ini");

        try
        {
            Directory.CreateDirectory(g3);
            Directory.CreateDirectory(defaultDir);
            File.WriteAllText(Path.Combine(g3, "01 - Shell.lnk"), "dummy");
            File.WriteAllText(Path.Combine(g3, "03 - TaskMgr.lnk"), "dummy");
            File.WriteAllText(iniPath, "[LocalizedFileNames]\r\n01 - Shell.lnk=终端\r\n03 - TaskMgr.lnk=任务管理器\r\n", System.Text.Encoding.UTF8);
            File.SetAttributes(iniPath, FileAttributes.Hidden | FileAttributes.System | FileAttributes.ReadOnly);

            var groups = WinXMenuService.ScanGroups(liveDir, defaultDir, autoNormalizePrefixes: true, out bool normalized);
            Assert.True(normalized);
            Assert.Single(groups);
            Assert.Equal(["任务管理器", "终端"], groups[0].Items.Select(i => i.DisplayName).ToArray());

            FileAttributes restoredAttrs = File.GetAttributes(iniPath);
            Assert.True((restoredAttrs & FileAttributes.Hidden) == FileAttributes.Hidden);
            Assert.True((restoredAttrs & FileAttributes.System) == FileAttributes.System);
        }
        finally
        {
            try
            {
                if (File.Exists(iniPath))
                    File.SetAttributes(iniPath, FileAttributes.Normal);
                if (Directory.Exists(tempRoot))
                    Directory.Delete(tempRoot, true);
            }
            catch { }
        }

        // 2. 验证应用失焦关闭搜索、初始紧凑高度+向下滚动动画展开、首开不显示翻页器
        string repoRoot = FindRepoRoot();
        string mainXaml = File.ReadAllText(Path.Combine(repoRoot, "src", "StartupGuard.App", "MainWindow.xaml"));
        string mainCs = File.ReadAllText(Path.Combine(repoRoot, "src", "StartupGuard.App", "MainWindow.xaml.cs"));
        string winXCs = File.ReadAllText(Path.Combine(repoRoot, "src", "StartupGuard.Core", "ContextMenu", "WinXMenuService.cs"));

        Assert.Contains("RunWithWritableIniAttributes", winXCs);
        Assert.Contains("Deactivated += (_, _) =>", mainCs);
        Assert.Contains("CompactGlobalSearchMaxWidth", mainCs);
        Assert.Contains("CompactGlobalSearchMaxHeight", mainCs);
        Assert.Contains("EnsureGlobalSearchCardExpanded", mainCs);
        Assert.Contains("BorderGlobalSearchCard_PreviewMouseWheel", mainXaml);
        Assert.Contains("MaxWidth=\"480\"", mainXaml);
        Assert.Contains("MaxHeight=\"185\"", mainXaml);
        Assert.Contains("sv.VerticalOffset > 0.5", mainCs);
    }

    [Fact]
    public void ManualRuleCreation_FolderAndFileEvaluation_AndUiContracts_WorkSafely()
    {
        string tempRoot = Path.Combine(Path.GetTempPath(), $"sg_folder_rule_{Guid.NewGuid():N}");
        string targetFolder = Path.Combine(tempRoot, "SampleSuite");
        string subFolder = Path.Combine(targetFolder, "bin");
        string siblingFolder = Path.Combine(tempRoot, "SampleSuite2");
        string targetExe = Path.Combine(subFolder, "agent.exe");
        string siblingExe = Path.Combine(siblingFolder, "agent.exe");
        Directory.CreateDirectory(subFolder);
        Directory.CreateDirectory(siblingFolder);

        try
        {
            // 1. 文件夹规则：仅命中同类别该目录及子目录下程序，严格隔离同前缀兄弟目录与不同类别
            string folderWithSlash = targetFolder + "\\";
            var folderRule = new RuleRecord
            {
                RuleId = 901,
                DisplayName = "SampleSuite",
                Category = MonitorCategory.StartupItem,
                ActionType = InterceptionAction.RollbackToDisabled,
                RuleMode = RuleMatchMode.PermanentAdaptive,
                NormalizedPath = PathNormalizerAndSimilarity.NormalizeProgramPath(folderWithSlash),
                RawCommand = folderWithSlash,
                LocationKey = string.Empty
            };

            Assert.True(StartupGuard.Service.Program.IsDirectoryRuleTarget(folderRule));

            var insideTarget = TestModelHelpers.CreateSampleTarget(
                category: MonitorCategory.StartupItem,
                targetBin: targetExe,
                normPath: PathNormalizerAndSimilarity.NormalizeProgramPath(targetExe),
                rawCmd: $"\"{targetExe}\" --silent",
                locKey: @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\CustomAgent",
                prodName: "Arbitrary Agent Name",
                origFile: "agent.exe");
            Assert.Same(folderRule, StartupGuard.Service.Program.EvaluateRuleMatch([folderRule], insideTarget));

            var siblingTarget = TestModelHelpers.CreateSampleTarget(
                category: MonitorCategory.StartupItem,
                targetBin: siblingExe,
                normPath: PathNormalizerAndSimilarity.NormalizeProgramPath(siblingExe),
                rawCmd: siblingExe,
                locKey: @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\SiblingAgent",
                prodName: "Sibling Agent",
                origFile: "agent.exe");
            Assert.Null(StartupGuard.Service.Program.EvaluateRuleMatch([folderRule], siblingTarget));

            var wrongCategoryTarget = TestModelHelpers.CreateSampleTarget(
                category: MonitorCategory.Win32Service,
                targetBin: targetExe,
                normPath: PathNormalizerAndSimilarity.NormalizeProgramPath(targetExe),
                rawCmd: targetExe,
                locKey: @"HKLM\SYSTEM\CurrentControlSet\Services\CustomAgentSvc",
                prodName: "CustomAgentSvc",
                origFile: "agent.exe");
            Assert.Null(StartupGuard.Service.Program.EvaluateRuleMatch([folderRule], wrongCategoryTarget));

            // 文件夹规则即便目录已不存在（仅末尾斜杠标记）也绝不误匹配同名非该目录下程序
            var deletedDirRule = new RuleRecord
            {
                RuleId = 902,
                DisplayName = "Agent",
                Category = MonitorCategory.StartupItem,
                ActionType = InterceptionAction.DeleteEntry,
                RuleMode = RuleMatchMode.PermanentAdaptive,
                NormalizedPath = @"<drive>:\deletedapps\agent\",
                RawCommand = @"C:\DeletedApps\Agent\",
                LocationKey = string.Empty
            };
            Assert.True(StartupGuard.Service.Program.IsDirectoryRuleTarget(deletedDirRule));
            var unrelatedSameName = TestModelHelpers.CreateSampleTarget(
                category: MonitorCategory.StartupItem,
                targetBin: @"C:\OtherTools\Agent.exe",
                normPath: @"<drive>:\othertools\agent.exe",
                rawCmd: @"C:\OtherTools\Agent.exe",
                locKey: @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Agent",
                prodName: "Agent",
                origFile: "Agent.exe");
            Assert.Null(StartupGuard.Service.Program.EvaluateRuleMatch([deletedDirRule], unrelatedSameName));

            // 2. 手工单文件规则（LocationKey 留空）：Strict MD5 与跨版本 PermanentAdaptive 路径均可命中
            var strictFileRule = new RuleRecord
            {
                RuleId = 903,
                DisplayName = "自定义单文件拦截",
                Category = MonitorCategory.ScheduledTask,
                ActionType = InterceptionAction.RollbackToDisabled,
                RuleMode = RuleMatchMode.StrictCurrentVersion,
                NormalizedPath = @"<drive>:\tools\updater\updater.exe",
                RawCommand = @"C:\Tools\Updater\updater.exe",
                LocationKey = string.Empty,
                CurrentMD5 = "0123456789abcdef0123456789abcdef"
            };
            var strictMatched = TestModelHelpers.CreateSampleTarget(
                category: MonitorCategory.ScheduledTask,
                targetBin: @"C:\Tools\Updater\updater.exe",
                normPath: @"<drive>:\tools\updater\updater.exe",
                rawCmd: @"C:\Tools\Updater\updater.exe",
                locKey: @"Task:\CustomUpdaterTask",
                prodName: "Some Task Name",
                origFile: "updater.exe",
                md5: "0123456789ABCDEF0123456789ABCDEF");
            Assert.Same(strictFileRule, StartupGuard.Service.Program.EvaluateRuleMatch([strictFileRule], strictMatched));

            var adaptiveFileRule = new RuleRecord
            {
                RuleId = 904,
                DisplayName = "跨版本用户目录工具",
                Category = MonitorCategory.StartupItem,
                ActionType = InterceptionAction.RollbackToDisabled,
                RuleMode = RuleMatchMode.PermanentAdaptive,
                NormalizedPath = PathNormalizerAndSimilarity.NormalizeProgramPath(@"C:\Users\DemoUser\AppData\Local\SampleTool\1.0.0\helper.exe"),
                RawCommand = @"C:\Users\DemoUser\AppData\Local\SampleTool\1.0.0\helper.exe",
                LocationKey = string.Empty
            };
            var upgradedTarget = TestModelHelpers.CreateSampleTarget(
                category: MonitorCategory.StartupItem,
                targetBin: @"C:\Users\AnotherUser\AppData\Local\SampleTool\2.3.4\helper.exe",
                normPath: PathNormalizerAndSimilarity.NormalizeProgramPath(@"C:\Users\AnotherUser\AppData\Local\SampleTool\2.3.4\helper.exe"),
                rawCmd: @"C:\Users\AnotherUser\AppData\Local\SampleTool\2.3.4\helper.exe",
                locKey: @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\HelperV2",
                prodName: "Helper V2",
                origFile: "helper.exe");
            Assert.Same(adaptiveFileRule, StartupGuard.Service.Program.EvaluateRuleMatch([adaptiveFileRule], upgradedTarget));
        }
        finally
        {
            try { Directory.Delete(tempRoot, true); } catch { }
        }

        // 3. UI 契约断言：所有分类筛选均显示“自启项”与“右键菜单”，支持手动创建全类型弹窗规则与浏览文件夹
        string repoRoot = FindRepoRoot();
        string mainXaml = File.ReadAllText(Path.Combine(repoRoot, "src", "StartupGuard.App", "MainWindow.xaml"));
        string mainCs = File.ReadAllText(Path.Combine(repoRoot, "src", "StartupGuard.App", "MainWindow.xaml.cs"));

        Assert.Contains("x:Name=\"ChkLogsGroupStartup\" Content=\"自启项\"", mainXaml);
        Assert.Contains("x:Name=\"ChkLogsGroupContextMenu\" Content=\"右键菜单\"", mainXaml);
        Assert.Contains("x:Name=\"ChkGlobalGroupStartup\" Content=\"自启项\"", mainXaml);
        Assert.Contains("x:Name=\"ChkGlobalGroupContextMenu\" Content=\"右键菜单\"", mainXaml);

        Assert.Contains("x:Name=\"BtnOpenCreateRuleDialog\"", mainXaml);
        Assert.Contains("x:Name=\"DialogCreateRuleHost\"", mainXaml);
        Assert.Contains("x:Name=\"BtnCreateRuleBrowseFile\"", mainXaml);
        Assert.Contains("x:Name=\"BtnCreateRuleBrowseFolder\"", mainXaml);
        Assert.Contains("Tag=\"StartupItem\"", mainXaml);
        Assert.Contains("Tag=\"Win32Service\"", mainXaml);
        Assert.Contains("Tag=\"KernelDriver\"", mainXaml);
        Assert.Contains("Tag=\"ScheduledTask\"", mainXaml);
        Assert.Contains("Tag=\"WindowsPolicy\"", mainXaml);
        Assert.Contains("Tag=\"ClassicContextMenu\"", mainXaml);
        Assert.Contains("Tag=\"ModernContextMenu\"", mainXaml);

        Assert.Contains("BuildRuleActionOptions(", mainCs);
        Assert.Contains("TryValidateSafeFolderRuleTarget(", mainCs);
        Assert.Contains("Microsoft.Win32.OpenFolderDialog", mainCs);

        int driverCaseStart = mainCs.IndexOf("MonitorCategory.KernelDriver =>", StringComparison.Ordinal);
        int driverCaseEnd = mainCs.IndexOf("MonitorCategory.ScheduledTask =>", driverCaseStart, StringComparison.Ordinal);
        Assert.True(driverCaseStart > 0 && driverCaseEnd > driverCaseStart);
        string driverBlock = mainCs[driverCaseStart..driverCaseEnd];
        Assert.DoesNotContain("DeleteEntry", driverBlock);
    }
}
