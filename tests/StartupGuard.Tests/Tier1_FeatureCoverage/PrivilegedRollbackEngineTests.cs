using StartupGuard.Core.Models;
using StartupGuard.Core.Native;
using StartupGuard.Tests.TestHelpers;

namespace StartupGuard.Tests.Tier1_FeatureCoverage;

public class PrivilegedRollbackEngineTests
{
    [Fact]
    public void DriverSafetyRedLine_KernelDriverDeleteEntry_StrictlyClampedToRollbackToDisabled()
    {
        // Red-Line Rule: KernelDriver attempting DeleteEntry must NEVER delete .sys file or service key!
        // It must be clamped to Disabled (4) or Demand (3)
        var (sanitizedAction, startType) = PrivilegedRollbackEngine.EnforceDriverSafetyRedLine(
            requestedAction: InterceptionAction.DeleteEntry,
            isKernelDriver: true);

        Assert.Equal(InterceptionAction.RollbackToDisabled, sanitizedAction);
        Assert.Equal(4u, startType);
    }

    [Fact]
    public void DriverSafetyRedLine_KernelDriverDemandAndDisabled_PreservedSafely()
    {
        var (action1, startType1) = PrivilegedRollbackEngine.EnforceDriverSafetyRedLine(
            requestedAction: InterceptionAction.RollbackToDemand,
            isKernelDriver: true);
        Assert.Equal(InterceptionAction.RollbackToDemand, action1);
        Assert.Equal(3u, startType1);

        var (action2, startType2) = PrivilegedRollbackEngine.EnforceDriverSafetyRedLine(
            requestedAction: InterceptionAction.RollbackToDisabled,
            isKernelDriver: true);
        Assert.Equal(InterceptionAction.RollbackToDisabled, action2);
        Assert.Equal(4u, startType2);
    }

    [Fact]
    public void DriverSafetyRedLine_NonDriver_AllowsDeleteEntry()
    {
        var (sanitizedAction, _) = PrivilegedRollbackEngine.EnforceDriverSafetyRedLine(
            requestedAction: InterceptionAction.DeleteEntry,
            isKernelDriver: false);

        Assert.Equal(InterceptionAction.DeleteEntry, sanitizedAction);
    }

    [Fact]
    public void InteractiveUserHiveResolver_ResolveUserRegistryPath_MapsToUserSidHive()
    {
        string sid = "S-1-5-21-0000000000-123456789-1001";
        string subKey = @"\Software\Microsoft\Windows\CurrentVersion\Run";

        string resolved = InteractiveUserHiveResolver.ResolveUserRegistryPath(sid, subKey);
        Assert.Equal(@"S-1-5-21-0000000000-123456789-1001\Software\Microsoft\Windows\CurrentVersion\Run", resolved);
    }

    [Fact]
    public void InteractiveUserHiveResolver_EmptySid_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() => InteractiveUserHiveResolver.ResolveUserRegistryPath("", "Software\\Run"));
    }

    [Fact]
    public void ComputePolicyHijackRemediationPlan_IfeoDebugger_PlansValueDeletion()
    {
        string ifeoKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe";
        var plan = PrivilegedRollbackEngine.ComputePolicyHijackRemediationPlan(ifeoKey, "Debugger");

        Assert.True(plan.DeleteValue);
        Assert.Equal("Debugger", plan.ValueName);
    }

    [Fact]
    public void ComputePolicyHijackRemediationPlan_WinlogonShellAndUserinit_RestoresSafeDefaults()
    {
        string winlogonKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";

        var shellPlan = PrivilegedRollbackEngine.ComputePolicyHijackRemediationPlan(winlogonKey, "Shell");
        Assert.False(shellPlan.DeleteValue);
        Assert.Equal("Shell", shellPlan.ValueName);
        Assert.Equal("explorer.exe", shellPlan.RestoredSafeStringValue);

        var userinitPlan = PrivilegedRollbackEngine.ComputePolicyHijackRemediationPlan(winlogonKey, "Userinit");
        Assert.False(userinitPlan.DeleteValue);
        Assert.Equal("Userinit", userinitPlan.ValueName);
        Assert.Equal(@"C:\Windows\system32\userinit.exe,", userinitPlan.RestoredSafeStringValue);
    }

    [Fact]
    public void ComputePolicyHijackRemediationPlan_AppInitAndBootExecute_RestoresDefaults()
    {
        var appInitPlan = PrivilegedRollbackEngine.ComputePolicyHijackRemediationPlan(
            @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", "AppInit_DLLs");
        Assert.False(appInitPlan.DeleteValue);
        Assert.Equal(string.Empty, appInitPlan.RestoredSafeStringValue);

        var bootPlan = PrivilegedRollbackEngine.ComputePolicyHijackRemediationPlan(
            @"SYSTEM\CurrentControlSet\Control\Session Manager", "BootExecute");
        Assert.False(bootPlan.DeleteValue);
        Assert.Equal("autocheck autochk *", bootPlan.RestoredSafeStringValue);
    }
}
