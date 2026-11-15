using System.IO;
using System.Reflection;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using StartupGuard.App.Services;
using StartupGuard.Core.Models;
using StartupGuard.Core.Scoring;
using Wpf.Ui.Appearance;
using Wpf.Ui.Controls;

namespace StartupGuard.App;

public partial class MainWindow
{
    private void SyncAboutVersionDisplay()
    {
        try
        {
            if (TxtAppAboutVersion == null)
                return;

            var ver = Assembly.GetExecutingAssembly().GetName().Version;
            if (ver != null)
            {
                string formatted = ver.Build > 0
                    ? $"{ver.Major}.{ver.Minor}.{ver.Build}"
                    : $"{ver.Major}.{ver.Minor}.0";
                TxtAppAboutVersion.Text = $"版本 {formatted}";
            }
        }
        catch { }
    }

    private async Task RunAutomatedScreenshotModeAsync(string outputDirectory)
    {
        try
        {
            ShowInTaskbar = false;
            WindowState = WindowState.Normal;
            ResizeMode = ResizeMode.NoResize;
            Width = 1120;
            Height = 720;

            SetLoadingOverlaysVisible(false);
            if (BtnSystemNotifyWarning != null)
                BtnSystemNotifyWarning.Visibility = Visibility.Collapsed;

            PopulateShowcaseScreenshotData();
            Directory.CreateDirectory(outputDirectory);

            await RenderSideBySideComparisonAsync(
                Path.Combine(outputDirectory, "preview_startup.jpg"),
                () =>
                {
                    NavigateAndSelectPage("PageStartupManager");
                    ApplyStartupFilter();
                    ApplicationThemeManager.Apply(ApplicationTheme.Dark, WindowBackdropType.Mica, true);
                },
                () =>
                {
                    NavigateAndSelectPage("PageStartupManager");
                    ApplyStartupFilter();
                    ApplicationThemeManager.Apply(ApplicationTheme.Light, WindowBackdropType.Mica, true);
                });

            await RenderSideBySideComparisonAsync(
                Path.Combine(outputDirectory, "preview_contextmenu.jpg"),
                () =>
                {
                    NavigateAndSelectPage("PageContextMenu");
                    _currentClassicFilter = "Scene_File";
                    _currentClassicScene = "Scene_File";
                    ApplyClassicMenuFilter();
                    ApplicationThemeManager.Apply(ApplicationTheme.Dark, WindowBackdropType.Mica, true);
                },
                () =>
                {
                    NavigateAndSelectPage("PageContextMenu");
                    _currentClassicFilter = "Scene_File";
                    _currentClassicScene = "Scene_File";
                    ApplyClassicMenuFilter();
                    ApplicationThemeManager.Apply(ApplicationTheme.Light, WindowBackdropType.Mica, true);
                });

            await RenderSideBySideComparisonAsync(
                Path.Combine(outputDirectory, "preview_review_logs.jpg"),
                () =>
                {
                    ToggleContextMenuSubMenu(expand: false);
                    NavigateAndSelectPage("PageAuditCenter");
                    ApplyAuditFilter();
                    ApplicationThemeManager.Apply(ApplicationTheme.Dark, WindowBackdropType.Mica, true);
                },
                () =>
                {
                    ToggleContextMenuSubMenu(expand: false);
                    NavigateAndSelectPage("PageLogs");
                    ApplyLogsFilter();
                    ApplyRulesFilter();
                    foreach (var dayGroup in _displayedLogDayGroups)
                        dayGroup.IsExpanded = true;
                    ApplicationThemeManager.Apply(ApplicationTheme.Light, WindowBackdropType.Mica, true);
                });
        }
        catch (Exception ex)
        {
            App.LogCrash("AutomatedScreenshotMode", ex);
        }
        finally
        {
            Application.Current?.Shutdown(0);
        }
    }

    private async Task RenderSideBySideComparisonAsync(
        string outputPath,
        Action configureLeftDark,
        Action configureRightLight)
    {
        const int singleWidth = 1120;
        const int singleHeight = 720;
        const int spacing = 24;

        configureLeftDark();
        await WaitForUiRenderFlushAsync();
        var leftBitmap = CaptureWindowWithBackdrop(singleWidth, singleHeight, Color.FromRgb(0x1C, 0x1F, 0x26));

        configureRightLight();
        await WaitForUiRenderFlushAsync();
        var rightBitmap = CaptureWindowWithBackdrop(singleWidth, singleHeight, Color.FromRgb(0xF3, 0xF5, 0xF8));

        int totalWidth = singleWidth * 2 + spacing;
        var compositeVisual = new DrawingVisual();
        using (DrawingContext dc = compositeVisual.RenderOpen())
        {
            dc.DrawRectangle(
                new SolidColorBrush(Color.FromRgb(0x12, 0x15, 0x1B)),
                null,
                new Rect(0, 0, totalWidth, singleHeight));
            dc.DrawImage(leftBitmap, new Rect(0, 0, singleWidth, singleHeight));
            dc.DrawImage(rightBitmap, new Rect(singleWidth + spacing, 0, singleWidth, singleHeight));
        }

        var composite = new RenderTargetBitmap(totalWidth, singleHeight, 96, 96, PixelFormats.Pbgra32);
        composite.Render(compositeVisual);

        var encoder = new JpegBitmapEncoder { QualityLevel = 94 };
        encoder.Frames.Add(BitmapFrame.Create(composite));
        using var fs = File.Create(outputPath);
        encoder.Save(fs);
    }

    private RenderTargetBitmap CaptureWindowWithBackdrop(int width, int height, Color fallbackBackdrop)
    {
        TryApplyFluentBackdrop();
        if (Content is UIElement root)
        {
            root.InvalidateMeasure();
            root.InvalidateArrange();
            root.InvalidateVisual();
        }
        InvalidateVisual();
        UpdateLayout();

        var visual = new DrawingVisual();
        using (DrawingContext dc = visual.RenderOpen())
        {
            dc.DrawRectangle(new SolidColorBrush(fallbackBackdrop), null, new Rect(0, 0, width, height));
            var brush = new VisualBrush(this)
            {
                Stretch = Stretch.None,
                AlignmentX = AlignmentX.Left,
                AlignmentY = AlignmentY.Top
            };
            dc.DrawRectangle(brush, null, new Rect(0, 0, width, height));
        }

        var rtb = new RenderTargetBitmap(width, height, 96, 96, PixelFormats.Pbgra32);
        rtb.Render(visual);
        return rtb;
    }

    private async Task WaitForUiRenderFlushAsync()
    {
        await Dispatcher.InvokeAsync(() => { }, DispatcherPriority.Render);
        await Task.Delay(260);
        await Dispatcher.InvokeAsync(() => { }, DispatcherPriority.ApplicationIdle);
    }

    private void PopulateShowcaseScreenshotData()
    {
        _allStartupItems =
        [
            new SystemStartupItemsManager.ManagedStartupItem
            {
                DisplayName = "StartupGuardTray",
                Publisher = "StartupGuard Security Team",
                HasSignature = true,
                CommandOrPath = "\"C:\\Program Files\\StartupGuard\\StartupGuard.TrayHost.exe\"",
                LocationKey = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\StartupGuardTray",
                Category = MonitorCategory.StartupItem,
                CategoryName = "启动程序",
                CategoryIcon = "Rocket24",
                IsEnabled = true,
                CurrentStateAction = InterceptionAction.Allow,
                StatusSummary = "正常自启"
            },
            new SystemStartupItemsManager.ManagedStartupItem
            {
                DisplayName = "Visual Studio Code Background Update",
                Publisher = "Microsoft Corporation",
                HasSignature = true,
                CommandOrPath = "\"C:\\Program Files\\Microsoft VS Code\\Code.exe\" --background-update",
                LocationKey = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\VSCodeUpdater",
                Category = MonitorCategory.StartupItem,
                CategoryName = "启动程序",
                CategoryIcon = "Rocket24",
                IsEnabled = false,
                CurrentStateAction = InterceptionAction.RollbackToDisabled,
                StatusSummary = "已按规则禁用"
            },
            new SystemStartupItemsManager.ManagedStartupItem
            {
                DisplayName = "Everything Indexing Service",
                Publisher = "voidtools",
                HasSignature = true,
                CommandOrPath = "\"C:\\Program Files\\Everything\\Everything.exe\" -svc",
                LocationKey = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Everything",
                Category = MonitorCategory.Win32Service,
                CategoryName = "系统服务",
                CategoryIcon = "Settings24",
                IsEnabled = true,
                CurrentStateAction = InterceptionAction.RollbackToDemand,
                StatusSummary = "手动启动 (Demand)"
            },
            new SystemStartupItemsManager.ManagedStartupItem
            {
                DisplayName = "Docker Desktop Service",
                Publisher = "Docker Inc.",
                HasSignature = true,
                CommandOrPath = "\"C:\\Program Files\\Docker\\Docker\\com.docker.service\"",
                LocationKey = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\com.docker.service",
                Category = MonitorCategory.Win32Service,
                CategoryName = "系统服务",
                CategoryIcon = "Settings24",
                IsEnabled = true,
                CurrentStateAction = InterceptionAction.RollbackToDelayedAuto,
                StatusSummary = "延迟自启 (DelayedAuto)"
            },
            new SystemStartupItemsManager.ManagedStartupItem
            {
                DisplayName = "Dokan2 File System Driver",
                Publisher = "Microsoft Windows Third Party Component CA",
                HasSignature = true,
                CommandOrPath = "\\SystemRoot\\system32\\drivers\\dokan2.sys",
                LocationKey = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Dokan2",
                Category = MonitorCategory.KernelDriver,
                CategoryName = "内核驱动",
                CategoryIcon = "ShieldKeyhole24",
                IsEnabled = true,
                CurrentStateAction = InterceptionAction.RollbackToDemand,
                StatusSummary = "按需加载 (Demand)"
            },
            new SystemStartupItemsManager.ManagedStartupItem
            {
                DisplayName = "OneDrive Standalone Update Task",
                Publisher = "Microsoft Corporation",
                HasSignature = true,
                CommandOrPath = "%localappdata%\\Microsoft\\OneDrive\\OneDriveStandaloneUpdater.exe /reporting",
                LocationKey = "\\OneDrive Reporting Task-S-1-5-21-0000000000-0000000000-0000000000-1001",
                Category = MonitorCategory.ScheduledTask,
                CategoryName = "计划任务",
                CategoryIcon = "Clock24",
                IsEnabled = false,
                CurrentStateAction = InterceptionAction.RollbackToDisabled,
                StatusSummary = "已禁用"
            }
        ];

        _allClassicMenuItems =
        [
            new SystemStartupItemsManager.ManagedStartupItem
            {
                DisplayName = "7-Zip 压缩与校验",
                Publisher = "Igor Pavlov",
                HasSignature = true,
                CommandOrPath = "\"C:\\Program Files\\7-Zip\\7-zip.dll\"",
                LocationKey = "HKLM\\SOFTWARE\\Classes\\*\\shellex\\ContextMenuHandlers\\7-Zip",
                Clsid = "{23170F69-40C1-278A-1000-000100020000}",
                Category = MonitorCategory.ClassicContextMenu,
                CategoryName = "经典右键菜单",
                CategoryIcon = "DocumentTable24",
                ScopeScene = "*",
                IsEnabled = true,
                StatusSummary = "已启用"
            },
            new SystemStartupItemsManager.ManagedStartupItem
            {
                DisplayName = "通过 Code 打开",
                Publisher = "Microsoft Corporation",
                HasSignature = true,
                CommandOrPath = "\"C:\\Program Files\\Microsoft VS Code\\Code.exe\" \"%1\"",
                LocationKey = "HKCU\\Software\\Classes\\*\\shell\\VSCode",
                Category = MonitorCategory.ClassicContextMenu,
                CategoryName = "经典右键菜单",
                CategoryIcon = "DocumentTable24",
                ScopeScene = "*",
                IsEnabled = true,
                StatusSummary = "已启用"
            },
            new SystemStartupItemsManager.ManagedStartupItem
            {
                DisplayName = "Git Bash Here",
                Publisher = "The Git Development Community",
                HasSignature = true,
                CommandOrPath = "\"C:\\Program Files\\Git\\git-bash.exe\" --cd=\"%v.\"",
                LocationKey = "HKLM\\SOFTWARE\\Classes\\*\\shell\\git_shell",
                Category = MonitorCategory.ClassicContextMenu,
                CategoryName = "经典右键菜单",
                CategoryIcon = "DocumentTable24",
                ScopeScene = "*",
                IsEnabled = true,
                StatusSummary = "已启用"
            },
            new SystemStartupItemsManager.ManagedStartupItem
            {
                DisplayName = "Notepad++ 快速编辑",
                Publisher = "Notepad++ Team",
                HasSignature = true,
                CommandOrPath = "\"C:\\Program Files\\Notepad++\\NppShell.dll\"",
                LocationKey = "HKLM\\SOFTWARE\\Classes\\*\\shellex\\ContextMenuHandlers\\ANotepad++64",
                Clsid = "{B298D29A-A6ED-11DE-BA8C-A68E55D89593}",
                Category = MonitorCategory.ClassicContextMenu,
                CategoryName = "经典右键菜单",
                CategoryIcon = "DocumentTable24",
                ScopeScene = "*",
                IsEnabled = false,
                StatusSummary = "已拦截禁用"
            },
            new SystemStartupItemsManager.ManagedStartupItem
            {
                DisplayName = "在终端中打开 (Windows Terminal)",
                Publisher = "Microsoft Corporation",
                HasSignature = true,
                CommandOrPath = "C:\\Program Files\\WindowsApps\\Microsoft.WindowsTerminal\\WindowsTerminal.exe",
                LocationKey = "PackagedCom\\Class\\{9F156763-7844-4DC4-B2B1-901F640F5155}",
                Clsid = "{9F156763-7844-4DC4-B2B1-901F640F5155}",
                Category = MonitorCategory.ModernContextMenu,
                CategoryName = "Win11 现代菜单",
                CategoryIcon = "Sparkle24",
                ScopeScene = "*",
                IsEnabled = true,
                StatusSummary = "已启用"
            }
        ];

        _guidBlockedItems = [];

        DateTime now = DateTime.UtcNow;
        _allAuditItems =
        [
            new PendingAuditItem
            {
                DisplayName = "CloudDrive Shell Extension",
                Publisher = "未签名 / 未知发布者",
                HasSignature = false,
                CommandOrPath = "C:\\Program Files (x86)\\CloudDrive\\ShellExt64.dll",
                LocationKey = "HKLM\\SOFTWARE\\Classes\\*\\shellex\\ContextMenuHandlers\\CloudDriveExt",
                Category = MonitorCategory.ClassicContextMenu,
                CategoryName = "经典右键菜单",
                CategoryIcon = "DocumentTable24",
                Clsid = "{7A8B9C0D-1122-3344-5566-778899AABBCC}",
                MenuSceneText = "所有文件 (*)",
                SourceProcess = "installer.exe",
                Reason = "安装程序尝试新增全局右键菜单扩展，系统已先行隔离禁用，等待人工审核",
                AuditSource = "先拦截待审",
                EventTime = now.AddMinutes(-3)
            },
            new PendingAuditItem
            {
                DisplayName = "ThirdParty Helper Service",
                Publisher = "Example Software Ltd.",
                HasSignature = true,
                CommandOrPath = "\"C:\\Program Files\\ExampleApp\\HelperService.exe\" --daemon",
                LocationKey = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\ExampleHelperSvc",
                Category = MonitorCategory.Win32Service,
                CategoryName = "系统服务",
                CategoryIcon = "Settings24",
                SourceProcess = "setup.exe",
                Reason = "检测到开机自动服务写入 (Start=2)，已暂设为禁用并进入待审核队列",
                AuditSource = "先拦截待审",
                EventTime = now.AddMinutes(-12)
            }
        ];

        _allRules =
        [
            new RuleRecord
            {
                RuleId = 1,
                DisplayName = "StartupGuardTray",
                Category = MonitorCategory.StartupItem,
                ActionType = InterceptionAction.Allow,
                RuleMode = RuleMatchMode.PermanentAdaptive,
                HasSignature = true,
                SignerSubject = "StartupGuard Security Team",
                RawCommand = "\"C:\\Program Files\\StartupGuard\\StartupGuard.TrayHost.exe\"",
                NormalizedPath = "<drive>:\\program files\\startupguard\\startupguard.trayhost.exe",
                LocationKey = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\StartupGuardTray",
                ProductName = "StartupGuard",
                UpdatedAt = now.AddHours(-2)
            },
            new RuleRecord
            {
                RuleId = 2,
                DisplayName = "Everything Service",
                Category = MonitorCategory.Win32Service,
                ActionType = InterceptionAction.RollbackToDemand,
                RuleMode = RuleMatchMode.PermanentAdaptive,
                HasSignature = true,
                SignerSubject = "voidtools",
                RawCommand = "\"C:\\Program Files\\Everything\\Everything.exe\" -svc",
                NormalizedPath = "<drive>:\\program files\\everything\\everything.exe",
                LocationKey = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Everything",
                ProductName = "Everything",
                UpdatedAt = now.AddHours(-1)
            },
            new RuleRecord
            {
                RuleId = 3,
                DisplayName = "Notepad++ Context Menu",
                Category = MonitorCategory.ClassicContextMenu,
                ActionType = InterceptionAction.RollbackToDisabled,
                RuleMode = RuleMatchMode.StrictCurrentVersion,
                HasSignature = true,
                SignerSubject = "Notepad++ Team",
                RawCommand = "\"C:\\Program Files\\Notepad++\\NppShell.dll\"",
                NormalizedPath = "<drive>:\\program files\\notepad++\\nppshell.dll",
                LocationKey = "HKLM\\SOFTWARE\\Classes\\*\\shellex\\ContextMenuHandlers\\ANotepad++64",
                ProductName = "Notepad++",
                UpdatedAt = now.AddMinutes(-18)
            }
        ];

        _allLogs =
        [
            new AuditLogRecord
            {
                LogId = 1,
                RuleId = 2,
                EventTime = now.AddMinutes(-5),
                Category = MonitorCategory.Win32Service,
                TargetProgram = "\"C:\\Program Files\\Everything\\Everything.exe\" -svc",
                TargetLocation = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Everything",
                OldState = "Start=2 (Auto)",
                NewState = "Start=3 (Demand)",
                ActionTaken = "已设为手动",
                MatchedScore = 98.4,
                DiagnosticText = "命中高可信演进规则【Everything Service】，已自动回调为手动启动",
                SourceProcess = "services.exe"
            },
            new AuditLogRecord
            {
                LogId = 2,
                RuleId = 3,
                EventTime = now.AddMinutes(-18),
                Category = MonitorCategory.ClassicContextMenu,
                TargetProgram = "\"C:\\Program Files\\Notepad++\\NppShell.dll\"",
                TargetLocation = "HKLM\\SOFTWARE\\Classes\\*\\shellex\\ContextMenuHandlers\\ANotepad++64",
                OldState = "Enabled",
                NewState = "Disabled (-ContextMenuHandlers)",
                ActionTaken = "已阻止并隔离",
                MatchedScore = 100.0,
                DiagnosticText = "命中强约束规则【Notepad++ Context Menu】，已自动隔离右键扩展",
                SourceProcess = "msiexec.exe"
            },
            new AuditLogRecord
            {
                LogId = 3,
                RuleId = 1,
                EventTime = now.AddHours(-2),
                Category = MonitorCategory.StartupItem,
                TargetProgram = "\"C:\\Program Files\\StartupGuard\\StartupGuard.TrayHost.exe\"",
                TargetLocation = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\StartupGuardTray",
                OldState = "Disabled",
                NewState = "Enabled",
                ActionTaken = "已允许放行",
                MatchedScore = 99.6,
                DiagnosticText = "命中白名单规则【StartupGuardTray】，保持自动守护运行",
                SourceProcess = "StartupGuard.App.exe"
            }
        ];

        if (TxtPendingCount != null)
            TxtPendingCount.Text = _allAuditItems.Count.ToString();
        if (BadgePendingCount != null)
            BadgePendingCount.Visibility = _allAuditItems.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
        if (TxtPendingSummary != null)
            TxtPendingSummary.Text = $"共有 {_allAuditItems.Count} 项待审核";
    }
}
