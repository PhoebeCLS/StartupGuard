using StartupGuard.Core.Configuration;
using StartupGuard.Core.ContextMenu;
using StartupGuard.Core.Ipc;
using StartupGuard.Core.Models;
using StartupGuard.Core.Native;
using StartupGuard.Core.Storage;
using Xunit;

namespace StartupGuard.Tests.Tier1_FeatureCoverage;

public sealed class Request12RegressionTests
{
    [Fact]
    public void UserSettingsStore_Md5ValidationInterval_ClampsTo1Through360Days()
    {
        int prev = UserSettingsStore.GetMd5ValidationIntervalDays();
        try
        {
            UserSettingsStore.SetMd5ValidationIntervalDays(0);
            Assert.Equal(1, UserSettingsStore.GetMd5ValidationIntervalDays());

            UserSettingsStore.SetMd5ValidationIntervalDays(500);
            Assert.Equal(360, UserSettingsStore.GetMd5ValidationIntervalDays());

            UserSettingsStore.SetMd5ValidationIntervalDays(45);
            Assert.Equal(45, UserSettingsStore.GetMd5ValidationIntervalDays());
        }
        finally
        {
            UserSettingsStore.SetMd5ValidationIntervalDays(prev);
        }
    }

    [Fact]
    public void UserSettingsStore_BlockedNotifications_Roundtrip()
    {
        bool prev = UserSettingsStore.GetBlockedNotificationsEnabled();
        try
        {
            UserSettingsStore.SetBlockedNotificationsEnabled(false);
            Assert.False(UserSettingsStore.GetBlockedNotificationsEnabled());

            UserSettingsStore.SetBlockedNotificationsEnabled(true);
            Assert.True(UserSettingsStore.GetBlockedNotificationsEnabled());
        }
        finally
        {
            UserSettingsStore.SetBlockedNotificationsEnabled(prev);
        }
    }

    [Fact]
    public void ShellNavigationHelper_NormalizeFullRegistryPath_HandlesRootsAndValueSuffix()
    {
        Assert.Equal(
            @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved",
            ShellNavigationHelper.NormalizeFullRegistryPath(@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved::{1234}"));

        Assert.Equal(
            @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run",
            ShellNavigationHelper.NormalizeFullRegistryPath(@"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"));

        Assert.Equal(
            @"HKEY_CLASSES_ROOT\*\shellex\ContextMenuHandlers\7-Zip",
            ShellNavigationHelper.NormalizeFullRegistryPath(@"*\shellex\ContextMenuHandlers\7-Zip"));
    }

    [Fact]
    public void SqliteRuleRepository_ItemNotesAndPendingAuditResolution_WorkCorrectly()
    {
        string tempDb = Path.Combine(Path.GetTempPath(), $"sg_req12_{Guid.NewGuid():N}.db");
        try
        {
            using var repo = new SqliteRuleRepository(tempDb);
            const string loc = @"HKLM\SOFTWARE\Classes\*\shellex\ContextMenuHandlers\DemoExt";

            repo.SaveItemNote(loc, "工作常用工具");
            Assert.Equal("工作常用工具", repo.GetItemNote(loc));

            repo.SaveItemNote(loc, string.Empty);
            Assert.Equal(string.Empty, repo.GetItemNote(loc));

            repo.WriteAuditLog(null, MonitorCategory.ClassicContextMenu, @"C:\demo.dll", loc, "New", "Blocked", "先拦截待审核", 100.0, "待审核");
            repo.ResolvePendingAuditLogs(loc, "已审核放行");

            var logs = repo.GetRecentAuditLogs(10);
            Assert.Single(logs);
            Assert.Equal("已审核放行", logs[0].ActionTaken);
        }
        finally
        {
            try { File.Delete(tempDb); } catch { }
        }
    }

    [Fact]
    public void RuleModels_RuleModeText_OmitsImplementationDetails()
    {
        var perm = new RuleRecord { DisplayName = "Demo", RuleMode = RuleMatchMode.PermanentAdaptive };
        var strict = new RuleRecord { DisplayName = "Demo", RuleMode = RuleMatchMode.StrictCurrentVersion };

        Assert.Equal("永久", perm.RuleModeText);
        Assert.Equal("仅此版本", strict.RuleModeText);
    }

    [Fact]
    public async Task ContextMenuManagerEngine_AnalyzeMenuAsync_HandlesUnknownClsidGracefully()
    {
        var items = await ContextMenuManagerEngine.AnalyzeShellExtensionMenuAsync("{00000000-0000-0000-0000-000000000000}", "AllFiles");
        Assert.NotNull(items);
        Assert.Empty(items);
    }

    [Fact]
    public void NativeSecurityExtractor_EssentialWindowsComponent_ExemptsTrustedInstaller()
    {
        string winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (string.IsNullOrEmpty(winDir)) winDir = @"C:\Windows";

        var target = new TargetProgramFeatures
        {
            Category = MonitorCategory.Win32Service,
            TargetBinaryPath = Path.Combine(winDir, "servicing", "TrustedInstaller.exe"),
            NormalizedPath = Path.Combine(winDir, "servicing", "TrustedInstaller.exe"),
            NormalizedPathHash = 0,
            RawCommandLine = Path.Combine(winDir, "servicing", "TrustedInstaller.exe"),
            CommandLineArgsTemplate = string.Empty,
            LocationKeyOrIdentifier = @"HKLM\SYSTEM\CurrentControlSet\Services\TrustedInstaller",
            DisplayName = "Windows Modules Installer",
            MD5Hex = string.Empty,
            SHA256Hex = string.Empty,
            HasValidSignature = true,
            SignerSubject = "CN=Microsoft Windows, O=Microsoft Corporation"
        };

        Assert.True(NativeSecurityExtractor.IsWindowsEssentialOperatingSystemComponent(target));
    }

    [Fact]
    public void SqliteRuleRepository_WriteAuditLog_RetainsOnlyLatestLogPerTargetLocation()
    {
        string tempDb = Path.Combine(Path.GetTempPath(), $"sg_dedup_{Guid.NewGuid():N}.db");
        try
        {
            using var repo = new SqliteRuleRepository(tempDb);
            string loc = @"HKLM\SYSTEM\CurrentControlSet\Services\DemoSvc";

            repo.WriteAuditLog(null, MonitorCategory.Win32Service, @"C:\DemoSvc.exe", loc, "New", "Blocked", "已捕获等待用户审核", 100.0, "step1");
            repo.WriteAuditLog(null, MonitorCategory.Win32Service, @"C:\DemoSvc.exe", loc.ToLowerInvariant(), "Auto", "Demand", "用户弹窗阻止：已回滚为手动启动", 100.0, "step2");
            repo.WriteAuditLog(null, MonitorCategory.Win32Service, @"C:\DemoSvc.exe", loc, "Demand", "Reverted", "已恢复为自动启动", 100.0, "step3");

            // Another unrelated target should not be touched
            repo.WriteAuditLog(null, MonitorCategory.StartupItem, @"C:\Other.exe", @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Other", "New", "Blocked", "先拦截待审", 100.0, "other");

            var logs = repo.GetRecentAuditLogs(20);
            Assert.Equal(2, logs.Count);

            var demoLog = Assert.Single(logs, l => l.LocationKey.Equals(loc, StringComparison.OrdinalIgnoreCase));
            Assert.Equal("已恢复为自动启动", demoLog.ActionTaken);
            Assert.Equal("step3", demoLog.DiagnosticText);
        }
        finally
        {
            try { File.Delete(tempDb); } catch { }
        }
    }

    [Fact]
    public void BinaryPipeSerializer_AuditRollbackRequest_RoundTripsStartTypeAndDelayedAuto()
    {
        var req = new AuditRollbackRequestPayload
        {
            AuditLogId = 42,
            LocationKey = @"HKLM\SYSTEM\CurrentControlSet\Services\TestSvc",
            Category = MonitorCategory.Win32Service,
            TargetAction = InterceptionAction.RollbackToDelayedAuto,
            TargetStartType = 2,
            DelayedAutostart = true,
            OldStateSummary = "Start=4"
        };

        byte[] bytes = BinaryPipeSerializer.SerializeAuditRollbackRequest(req);
        var decoded = BinaryPipeSerializer.DeserializeAuditRollbackRequest(bytes);

        Assert.Equal(42, decoded.AuditLogId);
        Assert.Equal(req.LocationKey, decoded.LocationKey);
        Assert.Equal(MonitorCategory.Win32Service, decoded.Category);
        Assert.Equal(InterceptionAction.RollbackToDelayedAuto, decoded.TargetAction);
        Assert.Equal(2u, decoded.TargetStartType);
        Assert.True(decoded.DelayedAutostart);
        Assert.Equal("Start=4", decoded.OldStateSummary);
    }

    [Fact]
    public void PrivilegedRollbackEngine_VerifyServiceStartType_ReadsLiveReadOnlyService()
    {
        if (!OperatingSystem.IsWindows()) return;

        using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\TrustedInstaller", false);
        if (key?.GetValue("Start") is int startVal)
        {
            int delayed = key.GetValue("DelayedAutostart") is int d ? d : 0;
            Assert.True(PrivilegedRollbackEngine.VerifyServiceStartType("TrustedInstaller", (uint)startVal, startVal == 2 && delayed == 1));
            uint different = startVal == 4 ? 3u : 4u;
            Assert.False(PrivilegedRollbackEngine.VerifyServiceStartType("TrustedInstaller", different, false));
        }
    }

    [Fact]
    public void ContextMenuSceneHelper_DescribeScene_MapsClassicAndModernLocations()
    {
        Assert.Equal(
            "目录背景",
            ContextMenuSceneHelper.DescribeScene(MonitorCategory.ClassicContextMenu, @"HKLM\SOFTWARE\Classes\Directory\Background\shellex\ContextMenuHandlers\Demo"));

        Assert.Equal(
            "桌面背景",
            ContextMenuSceneHelper.DescribeScene(MonitorCategory.ClassicContextMenu, @"HKCU\Software\Classes\DesktopBackground\Shell\Demo"));

        Assert.Equal(
            "Win11 现代菜单",
            ContextMenuSceneHelper.DescribeScene(MonitorCategory.ModernContextMenu, @"HKCU\Software\Classes\PackagedCom\Package\Foo"));
    }

    [Fact]
    public void BinaryPipeSerializer_SelfMutationSuppression_RoundTripsCleanly()
    {
        var req = new SelfMutationSuppressionPayload
        {
            LocationKey = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            TargetBinaryPath = @"C:\Tools\demo.exe",
            Category = MonitorCategory.StartupItem,
            DurationSeconds = 15.0
        };

        byte[] data = BinaryPipeSerializer.SerializeSelfMutationSuppression(req);
        var decoded = BinaryPipeSerializer.DeserializeSelfMutationSuppression(data);

        Assert.Equal(req.LocationKey, decoded.LocationKey);
        Assert.Equal(req.TargetBinaryPath, decoded.TargetBinaryPath);
        Assert.Equal(MonitorCategory.StartupItem, decoded.Category);
        Assert.Equal(15.0, decoded.DurationSeconds);
    }

    [Fact]
    public void UserSettingsStore_LogPermanentRetention_RoundTripsWithoutPollutingRetentionDays()
    {
        bool prevPerm = UserSettingsStore.GetLogPermanentRetention();
        int prevDays = UserSettingsStore.GetLogRetentionDays();
        try
        {
            UserSettingsStore.SetLogPermanentRetention(true);
            Assert.True(UserSettingsStore.GetLogPermanentRetention());

            UserSettingsStore.SetLogPermanentRetention(false);
            Assert.False(UserSettingsStore.GetLogPermanentRetention());

            UserSettingsStore.SetLogRetentionDays(0);
            Assert.True(UserSettingsStore.GetLogRetentionDays() >= 1);
        }
        finally
        {
            UserSettingsStore.SetLogPermanentRetention(prevPerm);
            UserSettingsStore.SetLogRetentionDays(prevDays);
        }
    }

    [Fact]
    public void RuleAndAuditModels_UseProhibitWordingWhileSupportingLegacyDisabledUndo()
    {
        var rule = new RuleRecord { DisplayName = "Demo", ActionType = InterceptionAction.RollbackToDisabled };
        Assert.Equal("设为禁止", rule.ActionTypeText);

        var legacyLog = new AuditLogRecord { ActionTaken = "用户弹窗阻止：已禁用启动" };
        Assert.Equal("已阻止", legacyLog.DisplayActionText);
        Assert.True(legacyLog.CanUndo);

        string tempDb = Path.Combine(Path.GetTempPath(), $"sg_localtime_{Guid.NewGuid():N}.db");
        try
        {
            using var repo = new SqliteRuleRepository(tempDb);
            repo.WriteAuditLog(null, MonitorCategory.StartupItem, @"C:\demo.exe", @"HKCU\...\Run\Demo", "New", "Blocked", "已禁止", 100.0, "diag");
            var logs = repo.GetRecentAuditLogs(5);
            Assert.Single(logs);
            Assert.Equal(DateTimeKind.Local, logs[0].EventTime.Kind);
            Assert.Equal(DateTime.Now.Date, logs[0].EventTime.Date);
        }
        finally
        {
            try { File.Delete(tempDb); } catch { }
        }
    }
}
