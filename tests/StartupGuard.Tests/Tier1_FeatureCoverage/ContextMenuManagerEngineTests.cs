using StartupGuard.Core.ContextMenu;
using StartupGuard.Core.Models;
using StartupGuard.Tests.TestHelpers;

namespace StartupGuard.Tests.Tier1_FeatureCoverage;

public class ContextMenuManagerEngineTests
{
    [Fact]
    public void DeduplicateByLastWriteTime_RetainsNewestEntryPerLogicalKey()
    {
        var olderEntry = new ContextMenuItemEntry
        {
            IdKey = "old",
            DisplayTitle = "Git Bash Here",
            MenuCategory = MonitorCategory.ClassicContextMenu,
            ScopeScene = "DirectoryBackground",
            RegistryPath = @"Software\Classes\Directory\Background\shell\git_shell",
            Clsid = "{B5A24978-B500-4743-A28F-091FA88835B1}",
            IsEnabled = false,
            LastWriteTimeFileTime = 130000000000000000L
        };

        var newerEntry = new ContextMenuItemEntry
        {
            IdKey = "new",
            DisplayTitle = "Git Bash Here",
            MenuCategory = MonitorCategory.ClassicContextMenu,
            ScopeScene = "DirectoryBackground",
            RegistryPath = @"Software\Classes\Directory\Background\shell\git_shell",
            Clsid = "{B5A24978-B500-4743-A28F-091FA88835B1}",
            IsEnabled = true,
            LastWriteTimeFileTime = 133000000000000000L // Newer timestamp
        };

        var distinctEntry = new ContextMenuItemEntry
        {
            IdKey = "other",
            DisplayTitle = "Open with Code",
            MenuCategory = MonitorCategory.ClassicContextMenu,
            ScopeScene = "DirectoryBackground",
            RegistryPath = @"Software\Classes\Directory\Background\shell\VSCode",
            Clsid = "{A0000000-0000-0000-0000-000000000000}",
            IsEnabled = true,
            LastWriteTimeFileTime = 131000000000000000L
        };

        var result = ContextMenuManagerEngine.DeduplicateByLastWriteTime([olderEntry, newerEntry, distinctEntry]);

        Assert.Equal(2, result.Count);
        var gitEntry = result.FirstOrDefault(e => e.DisplayTitle == "Git Bash Here");
        Assert.NotNull(gitEntry);
        Assert.True(gitEntry.IsEnabled);
        Assert.Equal(133000000000000000L, gitEntry.LastWriteTimeFileTime);
    }

    [Fact]
    public void ClassicShellScenes_ContainsAllRequiredAlignmentScenes()
    {
        var scenes = ContextMenuManagerEngine.ClassicShellScenes;
        var sceneNames = scenes.Select(s => s.SceneName).ToList();

        Assert.Contains(sceneNames, s => s.Contains("AllFiles"));
        Assert.Contains(sceneNames, s => s.Contains("Folder"));
        Assert.Contains(sceneNames, s => s.Contains("Directory"));
        Assert.Contains(sceneNames, s => s.Contains("DesktopBackground"));
        Assert.Contains(sceneNames, s => s.Contains("Drive"));
        Assert.Contains(sceneNames, s => s.Contains("AllFilesystemObjects"));
        Assert.Contains(sceneNames, s => s.Contains("RecycleBin"));
    }

    [Fact]
    public void Win11PackagedComSubKeys_ContainsClassIndexAndPackage()
    {
        var keys = ContextMenuManagerEngine.Win11PackagedComSubKeys;
        Assert.Contains(keys, k => k.Contains("PackagedCom\\ClassIndex"));
        Assert.Contains(keys, k => k.Contains("PackagedCom\\Package"));
    }

    [Fact]
    public void ScanSpecialContextMenus_SendToFolder_ScansFilesAndDetectsDisabledStatus()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "SendToTest_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        try
        {
            string enabledFile = Path.Combine(tempDir, "Bluetooth.lnk");
            File.WriteAllText(enabledFile, "fake lnk content");

            string disabledFile = Path.Combine(tempDir, "Mail.lnk.disabled");
            File.WriteAllText(disabledFile, "disabled shortcut");

            var engine = new ContextMenuManagerEngine();
            var results = engine.ScanSpecialContextMenus(activeUserSid: null, customSendToDir: tempDir, customWinXDir: tempDir);

            var sendToItems = results.Where(r => r.ScopeScene.Contains("SendTo")).ToList();
            Assert.Equal(2, sendToItems.Count);

            var active = sendToItems.FirstOrDefault(i => i.DisplayTitle == "Bluetooth");
            Assert.NotNull(active);
            Assert.True(active.IsEnabled);

            var disabled = sendToItems.FirstOrDefault(i => i.DisplayTitle.Contains("Mail"));
            Assert.NotNull(disabled);
            Assert.False(disabled.IsEnabled);
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    [Fact]
    public void ContextMenuItemEntry_ModelInstantiation_SupportsModernPackagedCom()
    {
        var item = new ContextMenuItemEntry
        {
            IdKey = "PackagedCom:{12345678-0000-0000-0000-000000000000}",
            DisplayTitle = "Clipchamp Video Editor",
            MenuCategory = MonitorCategory.ModernContextMenu,
            ScopeScene = "Win11PackagedCom",
            RegistryPath = @"SOFTWARE\Classes\PackagedCom\ClassIndex\{12345678-0000-0000-0000-000000000000}",
            Clsid = "{12345678-0000-0000-0000-000000000000}",
            PackageFullName = "Clipchamp.Clipchamp_3.0.1.0_x64__yxz",
            Publisher = "Microsoft Corporation",
            IsEnabled = true,
            LastWriteTimeFileTime = DateTime.UtcNow.ToFileTimeUtc()
        };

        Assert.Equal(MonitorCategory.ModernContextMenu, item.MenuCategory);
        Assert.Equal("{12345678-0000-0000-0000-000000000000}", item.Clsid);
        Assert.Equal("Microsoft Corporation", item.Publisher);
    }
}
