using StartupGuard.Core.Ipc;
using StartupGuard.Core.Models;
using StartupGuard.Core.Native;
using Xunit;

namespace StartupGuard.Tests.Tier1_FeatureCoverage;

public class RollbackAndDisplayNameTests
{
    [Fact]
    public void AuditRollbackRequest_SerializationRoundtrip_PreservesTargetStartTypeAndDelayed()
    {
        var original = new AuditRollbackRequestPayload
        {
            AuditLogId = 12345,
            LocationKey = @"HKLM\SYSTEM\CurrentControlSet\Services\Dokan2",
            Category = MonitorCategory.KernelDriver,
            TargetAction = InterceptionAction.RollbackToDisabled,
            TargetStartType = 4, // Disabled
            DelayedAutostart = false,
            OldStateSummary = "Start=2, Type=0x2"
        };

        byte[] serialized = BinaryPipeSerializer.SerializeAuditRollbackRequest(original);
        var restored = BinaryPipeSerializer.DeserializeAuditRollbackRequest(serialized);

        Assert.Equal(original.AuditLogId, restored.AuditLogId);
        Assert.Equal(original.LocationKey, restored.LocationKey);
        Assert.Equal(original.Category, restored.Category);
        Assert.Equal(original.TargetAction, restored.TargetAction);
        Assert.Equal(original.TargetStartType, restored.TargetStartType);
        Assert.Equal(original.DelayedAutostart, restored.DelayedAutostart);
        Assert.Equal(original.OldStateSummary, restored.OldStateSummary);
    }

    [Fact]
    public void AuditRollbackRequest_DelayedAutostart_Roundtrip()
    {
        var serviceReq = new AuditRollbackRequestPayload
        {
            AuditLogId = 999,
            LocationKey = @"HKLM\SYSTEM\CurrentControlSet\Services\SampleService",
            Category = MonitorCategory.Win32Service,
            TargetAction = InterceptionAction.Allow,
            TargetStartType = 2, // Auto
            DelayedAutostart = true,
            OldStateSummary = "Start=3"
        };

        byte[] bytes = BinaryPipeSerializer.SerializeAuditRollbackRequest(serviceReq);
        var res = BinaryPipeSerializer.DeserializeAuditRollbackRequest(bytes);

        Assert.Equal(2u, res.TargetStartType);
        Assert.True(res.DelayedAutostart);
    }

    [Fact]
    public void AuditLogRecord_CategoryNameAndIcon_FormattedCorrectly()
    {
        var driverLog = new AuditLogRecord
        {
            Category = MonitorCategory.KernelDriver,
            TargetProgram = @"C:\Windows\System32\drivers\dokan2.sys",
            TargetLocation = @"HKLM\SYSTEM\CurrentControlSet\Services\Dokan2"
        };

        Assert.Equal("内核驱动", driverLog.CategoryName);
        Assert.Equal("ShieldKeyhole24", driverLog.CategoryIcon);

        var serviceLog = new AuditLogRecord
        {
            Category = MonitorCategory.Win32Service,
            TargetProgram = @"C:\Program Files\SampleVendor\SampleSuite\SampleService.exe",
            TargetLocation = @"HKLM\SYSTEM\CurrentControlSet\Services\SampleService"
        };

        Assert.Equal("系统服务", serviceLog.CategoryName);
        Assert.Equal("Settings24", serviceLog.CategoryIcon);

        var startupLog = new AuditLogRecord
        {
            Category = MonitorCategory.StartupItem,
            TargetProgram = @"C:\Program Files\SampleVendor\SampleSuite\SampleApp.exe",
            TargetLocation = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\SampleApp"
        };

        Assert.Equal("自启程序", startupLog.CategoryName);
        Assert.Equal("Rocket24", startupLog.CategoryIcon);
    }

    [Fact]
    public void PrivilegedRollbackEngine_RollbackServiceOrDriverStartType_SafeExecution()
    {
        // 空入参在任何环境下都应安全返回 false
        Assert.False(PrivilegedRollbackEngine.RollbackServiceOrDriverStartType(string.Empty, 4, false));

        bool isElevatedWindows = OperatingSystem.IsWindows() &&
            new System.Security.Principal.WindowsPrincipal(
                System.Security.Principal.WindowsIdentity.GetCurrent())
                .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);

        const string dummyKey = @"SYSTEM\CurrentControlSet\Services\NonExistentTestService";
        try
        {
            // 验证执行无异常
            bool result = PrivilegedRollbackEngine.RollbackServiceOrDriverStartType(
                $@"HKLM\{dummyKey}",
                targetStartType: 4,
                delayedAutoStart: false);

            // 管理员提权环境（如 Windows CI Runner）可创建写入测试键值，非提权/非 Windows 安全返回 false
            Assert.Equal(isElevatedWindows, result);
        }
        finally
        {
            if (isElevatedWindows)
            {
                try { Microsoft.Win32.Registry.LocalMachine.DeleteSubKeyTree(dummyKey, throwOnMissingSubKey: false); } catch { }
            }
        }
    }

    [Fact]
    public void UserSettingsStore_ContextMenuPromptMode_DefaultIsFalse()
    {
        // 默认先拦截后审核模式 (ContextMenuManager 规范)
        bool defaultMode = StartupGuard.Core.Configuration.UserSettingsStore.GetContextMenuPromptMode();
        // 默认或已持久化值为布尔值且不抛异常
        Assert.False(defaultMode);
    }

    [Fact]
    public void UserSettingsStore_ThemePreference_Roundtrip()
    {
        StartupGuard.Core.Configuration.UserSettingsStore.SetThemePreference("Dark");
        string theme = StartupGuard.Core.Configuration.UserSettingsStore.GetThemePreference();
        Assert.Equal("Dark", theme);

        StartupGuard.Core.Configuration.UserSettingsStore.SetThemePreference("System");
        Assert.Equal("System", StartupGuard.Core.Configuration.UserSettingsStore.GetThemePreference());
    }
}
