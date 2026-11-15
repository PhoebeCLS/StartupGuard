using StartupGuard.Core.Configuration;
using StartupGuard.Core.ContextMenu;
using StartupGuard.Core.Ipc;
using StartupGuard.Core.Models;
using StartupGuard.Core.Native;

namespace StartupGuard.Tests;

public class Feedback11BatchTests
{
    [Fact]
    public void ContextMenuGuidResolver_LoadsEmbeddedDictionaryAndDefaultVerbs()
    {
        Assert.True(ContextMenuGuidResolver.LoadedDictionaryEntryCount > 0);
        Assert.True(ContextMenuGuidResolver.DefaultVerbResourceIds.ContainsKey("open"));
        Assert.True(ContextMenuGuidResolver.DefaultVerbResourceIds.ContainsKey("edit"));

        if (!OperatingSystem.IsWindows()) return;

        bool gotOpen = ContextMenuGuidResolver.TryGetDefaultVerbDisplayName("open", out string openText);
        Assert.True(gotOpen);
        Assert.False(string.IsNullOrWhiteSpace(openText));
        Assert.False(openText.StartsWith('@'));
        Assert.NotEqual("shell32", openText, StringComparer.OrdinalIgnoreCase);
    }

    [Fact]
    public void ContextMenuManagerEngine_ResolveMuiString_NeverFallsBackToBareDllName()
    {
        if (!OperatingSystem.IsWindows()) return;

        string res = ContextMenuManagerEngine.ResolveMuiString(@"@shell32.dll,-8508");
        Assert.False(string.Equals(res, "shell32", StringComparison.OrdinalIgnoreCase));
        Assert.False(string.Equals(res, "windows.storage", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void ContextMenuGuidResolver_And_ShellNavigationHelper_ExtractRealPhysicalFilePath()
    {
        if (!OperatingSystem.IsWindows()) return;

        string resolvedCmd = ShellNavigationHelper.ResolvePhysicalFilePath("\"C:\\Windows\\System32\\cmd.exe\" /c echo hi");
        Assert.Equal(@"C:\Windows\System32\cmd.exe", resolvedCmd, ignoreCase: true);

        string resolvedShort = ShellNavigationHelper.ResolvePhysicalFilePath("cmd.exe /k dir");
        Assert.EndsWith(@"\cmd.exe", resolvedShort, StringComparison.OrdinalIgnoreCase);
        Assert.True(File.Exists(resolvedShort));

        string extracted = ContextMenuGuidResolver.ExtractPhysicalFilePath(@"System32\notepad.exe");
        Assert.EndsWith(@"\notepad.exe", extracted, StringComparison.OrdinalIgnoreCase);

        Assert.Equal(string.Empty, ContextMenuGuidResolver.ExtractPhysicalFilePath("ms-settings:notifications"));
    }

    [Fact]
    public void UserSettingsStore_DiagnosticLogging_RoundTripsAndRestoresState()
    {
        bool prev = UserSettingsStore.GetDiagnosticLoggingEnabled();
        try
        {
            UserSettingsStore.SetDiagnosticLoggingEnabled(false);
            Assert.False(UserSettingsStore.GetDiagnosticLoggingEnabled());

            UserSettingsStore.SetDiagnosticLoggingEnabled(true);
            Assert.True(UserSettingsStore.GetDiagnosticLoggingEnabled());
        }
        finally
        {
            UserSettingsStore.SetDiagnosticLoggingEnabled(prev);
        }
    }

    [Fact]
    public void PipeProtocol_ManualItemMutationPayload_RoundTripsAccurately()
    {
        var input = new ManualItemMutationPayload
        {
            Category = MonitorCategory.ClassicContextMenu,
            Action = InterceptionAction.RollbackToDisabled,
            LocationKey = @"HKLM\SOFTWARE\Classes\*\shell\CustomVerb",
            TargetBinaryPath = @"C:\Program Files\Demo\demo.exe",
            DisplayName = "示例右键菜单"
        };

        byte[] bytes = BinaryPipeSerializer.SerializeManualMutation(input);
        var output = BinaryPipeSerializer.DeserializeManualMutation(bytes);

        Assert.Equal(input.Category, output.Category);
        Assert.Equal(input.Action, output.Action);
        Assert.Equal(input.LocationKey, output.LocationKey);
        Assert.Equal(input.TargetBinaryPath, output.TargetBinaryPath);
        Assert.Equal(input.DisplayName, output.DisplayName);
    }

    [Fact]
    public void ContextMenuManagerEngine_ClassicShellScenes_MatchContextMenuManagerScopeList()
    {
        var sceneNames = ContextMenuManagerEngine.ClassicShellScenes.Select(s => s.SceneName).ToHashSet(StringComparer.OrdinalIgnoreCase);

        Assert.Contains("LnkFile", sceneNames);
        Assert.Contains("UwpLnk", sceneNames);
        Assert.Contains("ExeFile", sceneNames);
        Assert.Contains("UnknownType", sceneNames);
        Assert.Contains("CommandStore", sceneNames);
        Assert.Contains("Library", sceneNames);
        Assert.Contains("LibraryBackground", sceneNames);
        Assert.Contains("UserLibrary", sceneNames);
        Assert.Contains("DragDrop File", sceneNames);
        Assert.Contains("DragDrop Folder", sceneNames);
    }

    [Fact]
    public void ContextMenuManagerEngine_ScanSpecialContextMenus_ExcludesShellNewByDefault_AndTogglesLnkHiddenAttribute()
    {
        if (!OperatingSystem.IsWindows()) return;

        string tempRoot = Path.Combine(Path.GetTempPath(), $"StartupGuard_CtxTest_{Guid.NewGuid():N}");
        string sendToDir = Path.Combine(tempRoot, "SendTo");
        string winXDir = Path.Combine(tempRoot, "WinX", "Group3");
        Directory.CreateDirectory(sendToDir);
        Directory.CreateDirectory(winXDir);

        try
        {
            string sendToLnk = Path.Combine(sendToDir, "DemoTarget.lnk");
            string winXLnk = Path.Combine(winXDir, "01 - DemoWinX.lnk");
            File.WriteAllText(sendToLnk, "dummy-lnk");
            File.WriteAllText(winXLnk, "dummy-winx");

            var engine = new ContextMenuManagerEngine();
            var defaultSpecial = engine.ScanSpecialContextMenus(null, sendToDir, Path.Combine(tempRoot, "WinX"), includeShellNew: false);

            Assert.DoesNotContain(defaultSpecial, i => i.ScopeScene.Contains("ShellNew", StringComparison.OrdinalIgnoreCase));
            var sendToItem = Assert.Single(defaultSpecial, i => i.RegistryPath.Equals(sendToLnk, StringComparison.OrdinalIgnoreCase));
            var winXItem = Assert.Single(defaultSpecial, i => i.RegistryPath.Equals(winXLnk, StringComparison.OrdinalIgnoreCase));

            Assert.True(sendToItem.IsEnabled);
            Assert.True(winXItem.IsEnabled);

            Assert.True(engine.SetContextMenuItemEnabledState(sendToItem, enable: false));
            Assert.True((File.GetAttributes(sendToLnk) & FileAttributes.Hidden) != 0);

            Assert.True(engine.SetContextMenuItemEnabledState(winXItem, enable: false));
            Assert.True((File.GetAttributes(winXLnk) & FileAttributes.Hidden) != 0);

            Assert.True(engine.SetContextMenuItemEnabledState(winXItem, enable: true));
            Assert.True((File.GetAttributes(winXLnk) & FileAttributes.Hidden) == 0);
        }
        finally
        {
            try { Directory.Delete(tempRoot, recursive: true); } catch { }
        }
    }
}
