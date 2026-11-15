using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using StartupGuard.App.Services;
using StartupGuard.Core.Configuration;
using StartupGuard.Core.ContextMenu;
using StartupGuard.Core.Ipc;
using StartupGuard.Core.Models;
using StartupGuard.Core.Native;
using StartupGuard.Core.Rules;
using StartupGuard.Core.Scoring;
using StartupGuard.Core.Storage;
using System.Windows.Media;
using System.Windows.Media.Animation;
using Wpf.Ui.Appearance;
using Wpf.Ui.Controls;

namespace StartupGuard.App;

public partial class MainWindow : FluentWindow
{
    public sealed class PendingAuditItem : INotifyPropertyChanged
    {
        private bool _isSelected;
        public bool IsSelected
        {
            get => _isSelected;
            set
            {
                if (_isSelected != value)
                {
                    _isSelected = value;
                    PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsSelected)));
                }
            }
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        public string Id { get; set; } = Guid.NewGuid().ToString("N");
        public string DisplayName { get; set; } = string.Empty;
        public string Publisher { get; set; } = "未知发布者";
        public bool HasSignature { get; set; }
        public string CommandOrPath { get; set; } = string.Empty;
        public string LocationKey { get; set; } = string.Empty;
        public MonitorCategory Category { get; set; }
        public string CategoryName { get; set; } = string.Empty;
        public string CategoryIcon { get; set; } = "Clock24";
        public string Reason { get; set; } = string.Empty;
        public string AuditSource { get; set; } = "先拦截待审";
        public DateTime EventTime { get; set; } = DateTime.UtcNow;
        public SystemStartupItemsManager.ManagedStartupItem? RawItem { get; set; }
        public AuditLogRecord? RawLog { get; set; }
        public System.Windows.Media.ImageSource? RealIconSource { get; set; }
        public bool HasRealIcon => RealIconSource != null;
        public string Clsid { get; set; } = string.Empty;
        public string MenuSceneText { get; set; } = string.Empty;
        public string SourceProcess { get; set; } = string.Empty;
        public bool IsContextMenu => Category is MonitorCategory.ClassicContextMenu or MonitorCategory.ModernContextMenu;
        public bool IsServiceCategory => Category == MonitorCategory.Win32Service;
        public bool IsServiceOrDriverCategory => Category is MonitorCategory.Win32Service or MonitorCategory.KernelDriver;
        public bool CanDeleteAuditItem => Category != MonitorCategory.KernelDriver;
        public bool HasMenuScene => IsContextMenu && !string.IsNullOrWhiteSpace(MenuSceneText);
        public bool HasClsid => !string.IsNullOrWhiteSpace(Clsid);
    }

    public sealed class AuditLogDayGroup : INotifyPropertyChanged
    {
        public string DateKey { get; init; } = string.Empty;
        public string HeaderTitle { get; init; } = string.Empty;
        public string CountText { get; init; } = string.Empty;
        public ObservableCollection<AuditLogRecord> Items { get; } = [];

        private bool _isExpanded;
        public bool IsExpanded
        {
            get => _isExpanded;
            set
            {
                if (_isExpanded != value)
                {
                    _isExpanded = value;
                    PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsExpanded)));
                }
            }
        }

        public event PropertyChangedEventHandler? PropertyChanged;
    }

    public sealed class AppCategorySection
    {
        public string CategoryTitle { get; init; } = string.Empty;
        public ObservableCollection<SystemStartupItemsManager.ManagedStartupItem> Items { get; } = [];
    }

    public sealed class AppStartupGroup : INotifyPropertyChanged
    {
        public string AppKey { get; init; } = string.Empty;
        public string AppTitle { get; init; } = string.Empty;
        public string CategorySummary { get; init; } = string.Empty;
        public string CountText { get; init; } = string.Empty;
        public System.Windows.Media.ImageSource? AppIconSource { get; init; }
        public bool HasAppIcon => AppIconSource != null;
        public ObservableCollection<AppCategorySection> CategorySections { get; } = [];
        public ObservableCollection<SystemStartupItemsManager.ManagedStartupItem> AllItems { get; } = [];

        private bool _isExpanded;
        public bool IsExpanded
        {
            get => _isExpanded;
            set
            {
                if (_isExpanded != value)
                {
                    _isExpanded = value;
                    PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsExpanded)));
                }
            }
        }

        public event PropertyChangedEventHandler? PropertyChanged;
    }

    public sealed class RuleDisplayItem : INotifyPropertyChanged
    {
        public required RuleRecord Rule { get; init; }

        public string ShortTitle => Rule.DisplayName.Contains('|')
            ? Rule.DisplayName.Split('|')[0].Trim()
            : Rule.DisplayName;

        private bool _isDetailsExpanded;
        public bool IsDetailsExpanded
        {
            get => _isDetailsExpanded;
            set
            {
                if (_isDetailsExpanded != value)
                {
                    _isDetailsExpanded = value;
                    PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsDetailsExpanded)));
                    PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(DetailsToggleLabel)));
                }
            }
        }

        public string DetailsToggleLabel => IsDetailsExpanded ? "收起 ▴" : "详情 ▾";

        public event PropertyChangedEventHandler? PropertyChanged;
    }

    public sealed class RuleDisplayGroup : INotifyPropertyChanged
    {
        public string GroupKey { get; init; } = string.Empty;
        public string HeaderTitle { get; init; } = string.Empty;
        public string Subtitle { get; init; } = string.Empty;
        public string IconSymbol { get; init; } = "Shield24";
        public string CountText { get; init; } = string.Empty;
        public System.Windows.Media.ImageSource? AppIconSource { get; init; }
        public bool HasAppIcon => AppIconSource != null;
        public ObservableCollection<RuleDisplayItem> Items { get; } = [];

        private bool _isExpanded = true;
        public bool IsExpanded
        {
            get => _isExpanded;
            set
            {
                if (_isExpanded != value)
                {
                    _isExpanded = value;
                    PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsExpanded)));
                }
            }
        }

        public event PropertyChangedEventHandler? PropertyChanged;
    }

    public sealed class AnalyzedMenuNode
    {
        public string Text { get; init; } = string.Empty;
        public string Verb { get; init; } = string.Empty;
        public Thickness IndentMargin { get; init; }
        public bool HasVerb => !string.IsNullOrWhiteSpace(Verb);
    }

    private readonly SystemStartupItemsManager _startupManager = new();
    private readonly SqliteRuleRepository _sqliteRepo;

    // 自启项、传统右键菜单、Win11现代菜单、待审核中心集合
    private readonly ObservableCollection<SystemStartupItemsManager.ManagedStartupItem> _displayedStartupItems = [];
    private readonly ObservableCollection<AppStartupGroup> _displayedStartupAppGroups = [];
    private readonly ObservableCollection<SystemStartupItemsManager.ManagedStartupItem> _displayedClassicMenuItems = [];
    private readonly ObservableCollection<AppStartupGroup> _displayedClassicMenuAppGroups = [];
    private readonly ObservableCollection<PendingAuditItem> _displayedAuditItems = [];
    private readonly ObservableCollection<RuleDisplayGroup> _displayedRuleGroups = [];
    private readonly ObservableCollection<AuditLogDayGroup> _displayedLogDayGroups = [];
    private readonly ObservableCollection<SystemStartupItemsManager.ManagedStartupItem> _displayedGlobalSearchItems = [];
    private const int GlobalSearchPageSize = 50;
    private const double CompactGlobalSearchMaxWidth = 480;
    private const double FullGlobalSearchMaxWidth = 840;
    private const double CompactGlobalSearchMaxHeight = 185;
    private List<SystemStartupItemsManager.ManagedStartupItem> _allGlobalSearchMatches = [];
    private int _globalSearchCurrentPage = 1;
    private int _globalSearchTotalPages = 1;
    private bool _globalSearchPagerRevealed;
    private bool _globalSearchCardExpanded;
    private readonly ObservableCollection<WinXGroupViewModel> _displayedWinXGroups = [];
    private Point _globalSearchPressScreenPoint;
    private bool _globalSearchDragPending;
    private bool _globalSearchDidDrag;

    public sealed class WinXShortcutViewModel : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler? PropertyChanged;

        private bool _isEnabled;
        public string FilePath { get; set; } = string.Empty;
        public string GroupName { get; set; } = string.Empty;
        public string GroupPath { get; set; } = string.Empty;
        public string DisplayName { get; set; } = string.Empty;
        public string TargetPath { get; set; } = string.Empty;
        public bool CanMoveUp { get; set; }
        public bool CanMoveDown { get; set; }
        public ImageSource? RealIconSource { get; set; }
        public bool HasRealIcon => RealIconSource != null;

        public bool IsEnabled
        {
            get => _isEnabled;
            set
            {
                if (_isEnabled != value)
                {
                    _isEnabled = value;
                    PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsEnabled)));
                }
            }
        }
    }

    public sealed class WinXGroupViewModel : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler? PropertyChanged;

        private bool _isEnabled;
        private bool _isExpanded = true;

        public string GroupName { get; set; } = string.Empty;
        public string GroupPath { get; set; } = string.Empty;
        public bool CanRestoreDefault { get; set; }
        public ObservableCollection<WinXShortcutViewModel> Items { get; } = [];
        public string CountText => $"{Items.Count} 项";

        public bool IsEnabled
        {
            get => _isEnabled;
            set
            {
                if (_isEnabled != value)
                {
                    _isEnabled = value;
                    PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsEnabled)));
                }
            }
        }

        public bool IsExpanded
        {
            get => _isExpanded;
            set
            {
                if (_isExpanded != value)
                {
                    _isExpanded = value;
                    PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsExpanded)));
                }
            }
        }
    }

    private WinXGroupViewModel? _pendingRenameWinXGroup;
    private WinXShortcutViewModel? _pendingRenameWinXShortcut;
    private System.Windows.Threading.DispatcherTimer? _detailCopyFeedbackTimer;

    private List<SystemStartupItemsManager.ManagedStartupItem> _allStartupItems = [];
    private List<SystemStartupItemsManager.ManagedStartupItem> _allClassicMenuItems = [];
    private List<SystemStartupItemsManager.ManagedStartupItem> _guidBlockedItems = [];
    private List<PendingAuditItem> _allAuditItems = [];
    private List<RuleRecord> _allRules = [];
    private List<AuditLogRecord> _allLogs = [];

    // 筛选状态
    private string _currentStartupFilter = "All";
    private string _currentStartupSearchTerm = string.Empty;

    private string _currentClassicFilter = "Scene_File";
    private string _currentClassicScene = "Scene_File";
    private string _currentClassicSearchTerm = string.Empty;
    private string _currentFileTypeTab = "LnkFile";
    private string _currentFileTypeParam = ".txt";
    private List<SystemStartupItemsManager.ManagedStartupItem> _fileTypeCachedItems = [];
    private readonly ObservableCollection<AnalysisMatchViewModel> _displayedAnalysisMatches = [];

    public sealed class AnalysisMatchViewModel
    {
        public string Title { get; init; } = string.Empty;
        public string Subtitle { get; init; } = string.Empty;
        public string BreadcrumbText { get; init; } = string.Empty;
        public string NavTag { get; init; } = string.Empty;
        public string FileTypeTab { get; init; } = string.Empty;
        public string Parameter { get; init; } = string.Empty;
    }

    private string _currentAuditFilter = "AuditAll";
    private string _rulesGroupMode = "ByCategory";
    private string _lastRulesRenderSignature = string.Empty;
    private readonly HashSet<MonitorCategory> _activeLogsCategories = [];
    private readonly HashSet<string> _activeLogStatuses = [];
    private string _currentLogsSearchTerm = string.Empty;
    private bool _isInitialized = false;
    private volatile bool _initialLoadCompleted = false;

    private FileSystemWatcher? _sharedDataWatcher;
    private CancellationTokenSource? _debounceRefreshCts;
    private readonly CancellationTokenSource _lifecycleCts = new();
    private DateTime _lastRefreshUtc = DateTime.MinValue;
    private int _isRefreshingFlag;
    private int _refreshQueuedFlag;
    private int _queuedShowOverlay;

    public MainWindow()
    {
        InitializeComponent();
        _isInitialized = true;
        SyncAboutVersionDisplay();

        string dbPath = ResolveDatabasePath();
        try
        {
            _sqliteRepo = new SqliteRuleRepository(dbPath);
        }
        catch (Exception ex)
        {
            App.LogCrash("SqliteRepoInit", ex);
            string fallbackPath = Path.Combine(Path.GetTempPath(), "startupguard_rules.db");
            _sqliteRepo = new SqliteRuleRepository(fallbackPath);
        }

        ListViewStartup.ItemsSource = _displayedStartupItems;
        ListViewStartupByApp.ItemsSource = _displayedStartupAppGroups;
        ListViewClassicMenu.ItemsSource = _displayedClassicMenuItems;
        ListViewContextMenuByApp.ItemsSource = _displayedClassicMenuAppGroups;
        ListViewAuditCenter.ItemsSource = _displayedAuditItems;
        ListViewRules.ItemsSource = _displayedRuleGroups;
        ListViewLogs.ItemsSource = _displayedLogDayGroups;
        ListViewGlobalSearch.ItemsSource = _displayedGlobalSearchItems;
        ListViewWinXGroups.ItemsSource = _displayedWinXGroups;

        SourceInitialized += OnMainWindowSourceInitialized;
        SizeChanged += (_, _) => UpdateGlobalSearchLayoutBounds();
        Loaded += async (_, _) =>
        {
            TryApplyFluentBackdrop();
            UpdateGlobalSearchLayoutBounds();
            if (App.IsScreenshotMode)
            {
                await RunAutomatedScreenshotModeAsync(App.ScreenshotOutputDirectory!);
                return;
            }

            LoadUserPreferences();
            Microsoft.Win32.SystemEvents.DisplaySettingsChanged += OnDisplaySettingsChanged;
            Microsoft.Win32.SystemEvents.UserPreferenceChanged += OnSystemUserPreferenceChanged;
            _ = Task.Run(() => RunActivatePipeServerAsync(_lifecycleCts.Token));
            EnsureTrayHostRunning();
            EnsureServiceRunning();
            UpdateServiceStatusUI();
            StartSharedDataWatcher();

            if (!string.IsNullOrWhiteSpace(App.InitialNavigationPage))
            {
                NavigateAndSelectPage(App.InitialNavigationPage);
            }

            await RefreshAllDataAsync(showOverlay: _allStartupItems.Count == 0, minimumOverlayMs: 0);
            _initialLoadCompleted = true;
        };

        Activated += async (_, _) =>
        {
            if (!_isInitialized || App.IsScreenshotMode) return;
            // 从系统设置返回主面板时立即刷新系统通知权限横幅与服务自启状态
            UpdateSystemNotificationStatusBanner();
            if (PageSettings?.Visibility == Visibility.Visible)
                UpdateServiceStatusUI();

            if (!_initialLoadCompleted) return;
            if ((DateTime.UtcNow - _lastRefreshUtc).TotalSeconds >= 5)
            {
                await RefreshAllDataAsync(showOverlay: false);
            }
        };

        Deactivated += (_, _) =>
        {
            if (_isInitialized && GlobalSearchOverlay?.Visibility == Visibility.Visible)
            {
                CloseGlobalSearchOverlay(clearQuery: false);
            }
        };

        Closed += (_, _) =>
        {
            try
            {
                Microsoft.Win32.SystemEvents.DisplaySettingsChanged -= OnDisplaySettingsChanged;
                Microsoft.Win32.SystemEvents.UserPreferenceChanged -= OnSystemUserPreferenceChanged;
                _lifecycleCts.Cancel();
                _lifecycleCts.Dispose();
                _debounceRefreshCts?.Cancel();
                _debounceRefreshCts?.Dispose();
                _debounceRefreshCts = null;
                _sharedDataWatcher?.Dispose();
                _sharedDataWatcher = null;
            }
            catch { }
            Application.Current?.Shutdown();
        };
    }

    private void OnMainWindowSourceInitialized(object? sender, EventArgs e)
    {
        try
        {
            var source = System.Windows.Interop.HwndSource.FromVisual(this) as System.Windows.Interop.HwndSource;
            source?.AddHook(WndProc);
        }
        catch { }
    }

    private static bool IsScreenPointOverElement(FrameworkElement? element, IntPtr lParam)
    {
        if (element == null || !element.IsVisible || element.ActualWidth <= 0 || element.ActualHeight <= 0)
            return false;

        try
        {
            long lp = lParam.ToInt64();
            int screenX = unchecked((short)(lp & 0xFFFF));
            int screenY = unchecked((short)((lp >> 16) & 0xFFFF));
            Point pt = element.PointFromScreen(new Point(screenX, screenY));
            return pt.X >= 0 && pt.Y >= 0 && pt.X <= element.ActualWidth && pt.Y <= element.ActualHeight;
        }
        catch
        {
            return false;
        }
    }

    private bool IsPointOverTitleBarSearchControls(IntPtr lParam)
        => IsScreenPointOverElement(TxtGlobalSearch, lParam)
        || IsScreenPointOverElement(BtnGlobalSearchFilterToggle, lParam);

    private void TryDismissGlobalSearchOnTitleBarNonClientClick(int msg, IntPtr wParam, IntPtr lParam)
    {
        const int WM_NCLBUTTONDOWN = 0x00A1;
        const int HTCAPTION = 2;
        if (msg == WM_NCLBUTTONDOWN && wParam.ToInt32() == HTCAPTION &&
            GlobalSearchOverlay?.Visibility == Visibility.Visible &&
            !IsPointOverTitleBarSearchControls(lParam))
        {
            CloseGlobalSearchOverlay(clearQuery: false);
        }
    }

    private void TitleBarContainer_PreviewMouseLeftButtonDown(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        if (!_isInitialized || GlobalSearchOverlay?.Visibility != Visibility.Visible || TitleBarContainer == null)
            return;

        if (e.OriginalSource is DependencyObject source)
        {
            if (IsVisualOrAncestor(source, TxtGlobalSearch) || IsVisualOrAncestor(source, BtnGlobalSearchFilterToggle))
                return;
            if (IsClickInsideInnerButton(source, TitleBarContainer))
                return;
        }

        CloseGlobalSearchOverlay(clearQuery: false);
    }

    private static bool IsVisualOrAncestor(DependencyObject? source, DependencyObject? target)
    {
        DependencyObject? cur = source;
        while (cur != null)
        {
            if (ReferenceEquals(cur, target))
                return true;
            cur = VisualTreeHelper.GetParent(cur);
        }
        return false;
    }

    private void AppTitleBar_WndProcInvoked(object? sender, Wpf.Ui.Controls.HwndProcEventArgs e)
    {
        const int WM_NCHITTEST = 0x0084;
        const int HTCLIENT = 1;
        TryDismissGlobalSearchOnTitleBarNonClientClick(e.Message, e.WParam, e.LParam);
        if (e.Message == WM_NCHITTEST && IsPointOverTitleBarSearchControls(e.LParam))
        {
            e.ReturnValue = new IntPtr(HTCLIENT);
            e.Handled = true;
        }
    }

    private IntPtr WndProc(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
    {
        const int WM_SETTINGCHANGE = 0x001A;
        const int WM_DISPLAYCHANGE = 0x007E;
        const int WM_NCHITTEST = 0x0084;
        const int WM_DPICHANGED = 0x02E0;
        const int WM_THEMECHANGED = 0x031A;
        const int HTCLIENT = 1;

        TryDismissGlobalSearchOnTitleBarNonClientClick(msg, wParam, lParam);

        if (msg == WM_NCHITTEST && IsPointOverTitleBarSearchControls(lParam))
        {
            handled = true;
            return new IntPtr(HTCLIENT);
        }
        else if (msg == WM_THEMECHANGED)
        {
            ScheduleSystemThemeRefresh();
        }
        else if (msg == WM_SETTINGCHANGE)
        {
            string? changedSection = lParam != IntPtr.Zero ? Marshal.PtrToStringUni(lParam) : null;
            if (changedSection == null || string.Equals(changedSection, "ImmersiveColorSet", StringComparison.OrdinalIgnoreCase))
            {
                ScheduleSystemThemeRefresh();
            }
        }
        else if (msg == WM_DISPLAYCHANGE || msg == WM_DPICHANGED)
        {
            ScheduleDisplayLayoutRefresh();
        }
        return IntPtr.Zero;
    }

    private void OnSystemUserPreferenceChanged(object? sender, Microsoft.Win32.UserPreferenceChangedEventArgs e)
    {
        if (e.Category is Microsoft.Win32.UserPreferenceCategory.General or Microsoft.Win32.UserPreferenceCategory.VisualStyle)
        {
            ScheduleSystemThemeRefresh();
        }
    }

    private void ScheduleSystemThemeRefresh()
    {
        try
        {
            Dispatcher.BeginInvoke(System.Windows.Threading.DispatcherPriority.Normal, () =>
            {
                if (string.Equals(UserSettingsStore.GetThemePreference(), "System", StringComparison.OrdinalIgnoreCase))
                {
                    ApplyThemePreference("System");
                }
            });
        }
        catch { }
    }

    private void ApplyThemePreference(string theme)
    {
        try
        {
            ApplicationTheme resolvedTheme = theme switch
            {
                "Light" => ApplicationTheme.Light,
                "Dark" => ApplicationTheme.Dark,
                _ => UserSettingsStore.IsSystemAppsLightTheme() ? ApplicationTheme.Light : ApplicationTheme.Dark
            };
            ApplicationThemeManager.Apply(resolvedTheme, WindowBackdropType.Mica, true);
            TryApplyFluentBackdrop();
        }
        catch { }
    }

    private void OnDisplaySettingsChanged(object? sender, EventArgs e)
    {
        ScheduleDisplayLayoutRefresh();
    }

    private void ScheduleDisplayLayoutRefresh()
    {
        try
        {
            Dispatcher.BeginInvoke(System.Windows.Threading.DispatcherPriority.Render, () =>
            {
                try
                {
                    TryApplyFluentBackdrop();
                    if (Content is UIElement rootContent)
                    {
                        rootContent.InvalidateMeasure();
                        rootContent.InvalidateArrange();
                        rootContent.InvalidateVisual();
                    }
                    InvalidateVisual();
                    UpdateLayout();
                }
                catch { }
            });
        }
        catch { }
    }

    private async Task RunActivatePipeServerAsync(CancellationToken ct)
    {
        byte[] buf = new byte[256];
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await using var server = new NamedPipeServerStream(
                    App.ActivatePipeName,
                    PipeDirection.In,
                    NamedPipeServerStream.MaxAllowedServerInstances,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous);

                await server.WaitForConnectionAsync(ct);
                int read = await server.ReadAsync(buf, ct);
                string cmd = read > 0 ? System.Text.Encoding.UTF8.GetString(buf, 0, read).Trim() : "ACTIVATE";

                await Dispatcher.InvokeAsync(() =>
                {
                    if (WindowState == WindowState.Minimized)
                        WindowState = WindowState.Normal;
                    Show();
                    Activate();
                    Topmost = true;
                    Topmost = false;

                    if (!string.IsNullOrEmpty(cmd) && !cmd.Equals("ACTIVATE", StringComparison.OrdinalIgnoreCase))
                    {
                        NavigateAndSelectPage(cmd);
                    }
                });
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch
            {
                await Task.Delay(200, ct);
            }
        }
    }

    private void NavigateAndSelectPage(string pageTag)
    {
        if (string.Equals(pageTag, "PageSettings", StringComparison.OrdinalIgnoreCase))
        {
            if (NavSettings != null) NavSettings.IsChecked = true;
            SwitchToPage("PageSettings");
        }
        else if (string.Equals(pageTag, "PageAuditCenter", StringComparison.OrdinalIgnoreCase))
        {
            if (NavAuditCenter != null) NavAuditCenter.IsChecked = true;
            SwitchToPage("PageAuditCenter");
        }
        else if (string.Equals(pageTag, "PageLogs", StringComparison.OrdinalIgnoreCase))
        {
            if (NavLogs != null) NavLogs.IsChecked = true;
            SwitchToPage("PageLogs");
        }
        else if (string.Equals(pageTag, "PageContextMenu", StringComparison.OrdinalIgnoreCase))
        {
            if (NavContextMenu != null) NavContextMenu.IsChecked = true;
            SwitchToPage("PageContextMenu");
        }
        else
        {
            if (NavStartupManager != null) NavStartupManager.IsChecked = true;
            SwitchToPage("PageStartupManager");
        }
    }

    private void StartSharedDataWatcher()
    {
        try
        {
            string dataDir = SharedStorageHelper.GetSharedDataDirectory();
            if (!Directory.Exists(dataDir)) return;

            _sharedDataWatcher = new FileSystemWatcher(dataDir)
            {
                NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.FileName,
                IncludeSubdirectories = false,
                EnableRaisingEvents = true
            };

            FileSystemEventHandler onChanged = (_, e) =>
            {
                if (e.Name == null) return;
                if (!e.Name.EndsWith(".db", StringComparison.OrdinalIgnoreCase) &&
                    !e.Name.EndsWith(".db-wal", StringComparison.OrdinalIgnoreCase) &&
                    !e.Name.EndsWith("rules.bin", StringComparison.OrdinalIgnoreCase))
                {
                    return;
                }

                ScheduleDebouncedRefresh();
            };

            _sharedDataWatcher.Changed += onChanged;
            _sharedDataWatcher.Created += onChanged;
            _sharedDataWatcher.Renamed += (_, e) =>
            {
                if (e.Name != null && e.Name.EndsWith(".bin", StringComparison.OrdinalIgnoreCase))
                {
                    ScheduleDebouncedRefresh();
                }
            };
        }
        catch { }
    }

    private void ScheduleDebouncedRefresh()
    {
        try
        {
            var prev = Interlocked.Exchange(ref _debounceRefreshCts, new CancellationTokenSource());
            prev?.Cancel();
            prev?.Dispose();

            var token = _debounceRefreshCts?.Token ?? CancellationToken.None;
            _ = Task.Run(async () =>
            {
                try
                {
                    await Task.Delay(700, token);
                    if (token.IsCancellationRequested) return;
                    await Dispatcher.InvokeAsync(async () => await RefreshAllDataAsync());
                }
                catch (OperationCanceledException) { }
                catch { }
            }, token);
        }
        catch { }
    }

    private static string ResolveDatabasePath()
    {
        return SharedStorageHelper.GetSharedDatabasePath();
    }

    private void TryApplyFluentBackdrop()
    {
        try
        {
            ExtendsContentIntoTitleBar = true;
            if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 22000))
            {
                if (WindowBackdrop.IsSupported(WindowBackdropType.Mica))
                {
                    WindowBackdrop.ApplyBackdrop(this, WindowBackdropType.Mica);
                }
                else
                {
                    WindowBackdrop.ApplyBackdrop(this, WindowBackdropType.Acrylic);
                }
            }
        }
        catch { }
    }

    private void LoadUserPreferences()
    {
        try
        {
            // 加载主题
            string theme = UserSettingsStore.GetThemePreference();
            SelectComboBoxItemByTag(CmbTheme, theme);
            ApplyThemePreference(theme);

            // 加载右键菜单拦截策略
            bool promptMode = UserSettingsStore.GetContextMenuPromptMode();
            SelectComboBoxItemByTag(CmbContextMenuStrategy, promptMode ? "PromptImmediate" : "InterceptAndAudit");

            // 加载隐藏系统项设置（自启管理默认隐藏微软项）
            bool hideStartup = UserSettingsStore.GetHideMicrosoftPreference();
            if (TglHideMicrosoft != null) TglHideMicrosoft.IsChecked = hideStartup;

            // 加载日志保留限制 (TglLogAutoPrune = true 代表启用自动清理)
            bool autoPruneLogs = !UserSettingsStore.GetLogPermanentRetention();
            if (TglLogAutoPrune != null)
            {
                TglLogAutoPrune.IsChecked = autoPruneLogs;
            }

            int days = Math.Clamp(UserSettingsStore.GetLogRetentionDays(), 1, 3650);
            if (NumLogRetentionDays != null)
            {
                NumLogRetentionDays.IsEnabled = autoPruneLogs;
                NumLogRetentionDays.Value = days;
            }

            int maxCount = Math.Clamp(UserSettingsStore.GetLogMaxCount(), 0, 100000);
            if (NumLogMaxCount != null)
            {
                NumLogMaxCount.IsEnabled = autoPruneLogs;
                NumLogMaxCount.Value = maxCount;
            }

            if (TglDiagnosticLogging != null)
            {
                TglDiagnosticLogging.IsChecked = UserSettingsStore.GetDiagnosticLoggingEnabled();
            }

            // 加载通知与 MD5 规则时效性探测设置
            if (ToggleRuleHitNotification != null)
                ToggleRuleHitNotification.IsChecked = UserSettingsStore.GetRuleHitNotificationsEnabled();
            if (ToggleContextMenuNotification != null)
                ToggleContextMenuNotification.IsChecked = UserSettingsStore.GetContextMenuNotificationsEnabled();
            UpdateContextMenuNotificationControlState(promptMode);
            UpdateSystemNotificationStatusBanner();

            // 加载弹窗默认处置动作（经典与现代完全独立配置）
            SelectComboBoxItemByTag(CmbDefaultActionStartup, UserSettingsStore.GetDefaultPopupAction(MonitorCategory.StartupItem).ToString());
            SelectComboBoxItemByTag(CmbDefaultActionService, UserSettingsStore.GetDefaultPopupAction(MonitorCategory.Win32Service).ToString());
            SelectComboBoxItemByTag(CmbDefaultActionDriver, UserSettingsStore.GetDefaultPopupAction(MonitorCategory.KernelDriver).ToString());
            SelectComboBoxItemByTag(CmbDefaultActionTask, UserSettingsStore.GetDefaultPopupAction(MonitorCategory.ScheduledTask).ToString());
            SelectComboBoxItemByTag(CmbDefaultActionClassicMenu, UserSettingsStore.GetDefaultPopupAction(MonitorCategory.ClassicContextMenu).ToString());
            SelectComboBoxItemByTag(CmbDefaultActionModernMenu, UserSettingsStore.GetDefaultPopupAction(MonitorCategory.ModernContextMenu).ToString());

            if (TglMd5Validation != null)
                TglMd5Validation.IsChecked = UserSettingsStore.GetMd5ValidationEnabled();

            int md5Days = Math.Clamp(UserSettingsStore.GetMd5ValidationIntervalDays(), 1, 360);
            if (NumMd5ValidationDays != null)
                NumMd5ValidationDays.Value = md5Days;

            if (ChkMd5ValidationIdleOnly != null)
                ChkMd5ValidationIdleOnly.IsChecked = UserSettingsStore.GetMd5ValidationIdleOnly();
        }
        catch { }
    }

    private static void SelectComboBoxItemByTag(System.Windows.Controls.ComboBox? cmb, string? tag)
    {
        if (cmb == null || string.IsNullOrEmpty(tag)) return;
        foreach (var item in cmb.Items)
        {
            if (item is System.Windows.Controls.ComboBoxItem ci && ci.Tag?.ToString() == tag)
            {
                ci.IsSelected = true;
                break;
            }
        }
    }

    private static System.Windows.Controls.TextBlock CreateDialogTextBlock(string content)
    {
        return new System.Windows.Controls.TextBlock
        {
            Text = content,
            TextWrapping = TextWrapping.Wrap,
            TextAlignment = TextAlignment.Left,
            VerticalAlignment = VerticalAlignment.Top,
            HorizontalAlignment = HorizontalAlignment.Stretch,
            LineHeight = 22,
            FontSize = 13.5,
            MaxWidth = 420
        };
    }

    private async Task<bool> ShowWinUiConfirmDialogAsync(string title, string content, string primaryText = "确定", string closeText = "取消")
    {
        try
        {
            var msgBox = new Wpf.Ui.Controls.MessageBox
            {
                Title = title,
                Content = CreateDialogTextBlock(content),
                PrimaryButtonText = primaryText,
                CloseButtonText = closeText,
                MinHeight = 120,
                Owner = this
            };
            var result = await msgBox.ShowDialogAsync();
            return result == Wpf.Ui.Controls.MessageBoxResult.Primary;
        }
        catch
        {
            return System.Windows.MessageBox.Show(this, content, title, System.Windows.MessageBoxButton.OKCancel, MessageBoxImage.Question) == System.Windows.MessageBoxResult.OK;
        }
    }

    private async Task ShowWinUiInfoDialogAsync(string title, string content)
    {
        try
        {
            var msgBox = new Wpf.Ui.Controls.MessageBox
            {
                Title = title,
                Content = CreateDialogTextBlock(content),
                CloseButtonText = "确定",
                MinHeight = 120,
                Owner = this
            };
            await msgBox.ShowDialogAsync();
        }
        catch
        {
            System.Windows.MessageBox.Show(this, content, title, System.Windows.MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }

    #region Data Loading & Refresh

    private async Task RefreshAllDataAsync(bool showOverlay = false, int minimumOverlayMs = 0)
    {
        if (Interlocked.CompareExchange(ref _isRefreshingFlag, 1, 0) != 0)
        {
            if (showOverlay)
            {
                Interlocked.Exchange(ref _queuedShowOverlay, 1);
                SetLoadingOverlaysVisible(true);
            }
            Interlocked.Exchange(ref _refreshQueuedFlag, 1);
            return;
        }

        bool activeOverlay = showOverlay || Interlocked.Exchange(ref _queuedShowOverlay, 0) == 1;
        if (activeOverlay)
        {
            SetLoadingOverlaysVisible(true);
        }

        try
        {
            while (true)
            {
                Interlocked.Exchange(ref _refreshQueuedFlag, 0);
                var sw = activeOverlay && minimumOverlayMs > 0 ? Stopwatch.StartNew() : null;

                var snapshot = await Task.Run(() =>
                {
                    if (UserSettingsStore.GetMd5ValidationEnabled())
                    {
                        try
                        {
                            var md5Auto = Md5RuleValidator.ValidateAndCleanObsoleteMd5Rules(_sqliteRepo);
                            if (md5Auto.DeletedCount > 0)
                            {
                                SyncRulesBinaryAndNotifyService(_sqliteRepo);
                            }
                        }
                        catch { }
                    }
                    else
                    {
                        try
                        {
                            if (Md5RuleValidator.BackfillMissingRuleMetadata(_sqliteRepo) > 0)
                            {
                                SyncRulesBinaryAndNotifyService(_sqliteRepo);
                            }
                        }
                        catch { }
                    }

                    var allItems = _startupManager.GetAllSystemStartupItems();

                    try
                    {
                        var notes = _sqliteRepo.GetAllItemNotes();
                        foreach (var item in allItems)
                        {
                            if (notes.TryGetValue(item.LocationKey, out string? note))
                            {
                                item.Note = note;
                            }
                        }
                    }
                    catch { }

                    // 1. 系统自启项 (排除右键菜单)
                    var startupItems = allItems.Where(i =>
                        i.Category != MonitorCategory.ClassicContextMenu &&
                        i.Category != MonitorCategory.ModernContextMenu).ToList();

                    // 2. 经典与 Win11 现代右键菜单 + GUID 锁清单
                    var classicItems = allItems.Where(i =>
                        i.Category is MonitorCategory.ClassicContextMenu or MonitorCategory.ModernContextMenu).ToList();
                    var guidBlockedItems = _startupManager.ScanGuidBlockedEntries();

                    // 3. 汇总待审核项目
                    var auditItems = BuildPendingAuditItems(allItems);

                    return (startupItems, classicItems, guidBlockedItems, auditItems);
                });

                _allStartupItems = snapshot.startupItems;
                _allClassicMenuItems = snapshot.classicItems;
                _guidBlockedItems = snapshot.guidBlockedItems;
                _allAuditItems = snapshot.auditItems;

                TxtPendingCount.Text = _allAuditItems.Count.ToString();
                BadgePendingCount.Visibility = _allAuditItems.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
                TxtPendingSummary.Text = $"共有 {_allAuditItems.Count} 项待审核";

                _lastRefreshUtc = DateTime.UtcNow;
                if (_currentClassicFilter == "FileTypes")
                {
                    LoadActiveFileTypeItems();
                }
                else
                {
                    _fileTypeCachedItems.Clear();
                }
                ApplyStartupFilter();
                ApplyClassicMenuFilter();
                ApplyAuditFilter();
                RefreshRules();
                RefreshLogs();
                RefreshGlobalSearchResults();

                if (sw != null && minimumOverlayMs > 0)
                {
                    int remaining = minimumOverlayMs - (int)sw.ElapsedMilliseconds;
                    if (remaining > 0)
                        await Task.Delay(remaining);
                }

                if (Interlocked.CompareExchange(ref _refreshQueuedFlag, 0, 1) == 0)
                    break;

                if (Interlocked.Exchange(ref _queuedShowOverlay, 0) == 1 && !activeOverlay)
                {
                    activeOverlay = true;
                    SetLoadingOverlaysVisible(true);
                }
            }
        }
        finally
        {
            SetLoadingOverlaysVisible(false);
            Interlocked.Exchange(ref _queuedShowOverlay, 0);
            Interlocked.Exchange(ref _isRefreshingFlag, 0);
        }
    }

    private void SetLoadingOverlaysVisible(bool visible)
    {
        Visibility targetVis = visible ? Visibility.Visible : Visibility.Collapsed;
        if (OverlayStartupLoading != null && OverlayStartupLoading.Visibility != targetVis)
            OverlayStartupLoading.Visibility = targetVis;
        if (OverlayContextMenuLoading != null && OverlayContextMenuLoading.Visibility != targetVis)
            OverlayContextMenuLoading.Visibility = targetVis;
    }

    private List<PendingAuditItem> BuildPendingAuditItems(List<SystemStartupItemsManager.ManagedStartupItem> allItems)
    {
        var auditList = new List<PendingAuditItem>();

        try
        {
            var logs = _sqliteRepo.GetPendingAuditLogs();
            foreach (var log in logs)
            {
                if (log.ActionTaken.Contains("Pending Audit", StringComparison.OrdinalIgnoreCase) ||
                    log.ActionTaken.Contains("暂存", StringComparison.OrdinalIgnoreCase) ||
                    log.ActionTaken.Contains("待审", StringComparison.OrdinalIgnoreCase) ||
                    log.ActionTaken.Contains("先拦截待审", StringComparison.OrdinalIgnoreCase))
                {
                    bool withinSettlingGrace = (DateTime.Now - log.EventTime).TotalSeconds < 12.0;

                    // 在实时枚举项中查找匹配项，核验注册表项与背后载体是否仍然存在于系统中 (软件卸载后应自动核销；12秒稳态缓冲期内不提前核销)
                    var matchedLive = FindMatchingLiveItem(allItems, log.LocationKey, log.TargetProgram);
                    if (!withinSettlingGrace &&
                        !ShellNavigationHelper.IsPendingAuditTargetStillInstalled(
                            log.LocationKey,
                            log.TargetProgram,
                            log.Category,
                            matchedLive != null))
                    {
                        SharedStorageHelper.LogDiagnostic("PendingAudit", $"Auto-resolved missing target: cat={log.Category} loc={log.LocationKey} bin={log.TargetProgram}");
                        try { _sqliteRepo.ResolvePendingAuditLogs(log.LocationKey, "项目已移除"); } catch { }
                        continue;
                    }

                    string resolvedLoc = matchedLive?.LocationKey ?? log.LocationKey;
                    string resolvedCmd = !string.IsNullOrWhiteSpace(log.TargetProgram)
                        ? log.TargetProgram
                        : (matchedLive?.CommandOrPath ?? string.Empty);

                    string srcProc = !string.IsNullOrWhiteSpace(log.SourceProcess)
                        ? log.SourceProcess
                        : _sqliteRepo.GetItemProvenance(resolvedLoc);
                    if (matchedLive != null && !string.IsNullOrWhiteSpace(srcProc))
                        matchedLive.SourceProcess = srcProc;

                    // 排重：同位置键或同一扩展 DLL 避免重复卡片
                    if (!auditList.Any(a => a.LocationKey.Equals(resolvedLoc, StringComparison.OrdinalIgnoreCase)))
                    {
                        string dispName = matchedLive?.DisplayName ?? string.Empty;
                        if (string.IsNullOrWhiteSpace(dispName) && log.DiagnosticText.Contains('【') && log.DiagnosticText.Contains('】'))
                        {
                            int start = log.DiagnosticText.IndexOf('【') + 1;
                            int end = log.DiagnosticText.IndexOf('】', start);
                            if (end > start)
                                dispName = log.DiagnosticText.Substring(start, end - start);
                        }
                        if (string.IsNullOrWhiteSpace(dispName))
                            dispName = Path.GetFileName(resolvedCmd);
                        if (string.IsNullOrWhiteSpace(dispName))
                            dispName = resolvedLoc;

                        string clsid = matchedLive?.Clsid ?? PrivilegedRollbackEngine.ExtractClsidOrIdentifier(resolvedLoc);
                        if (string.IsNullOrEmpty(clsid) && resolvedLoc.Contains("shellex", StringComparison.OrdinalIgnoreCase))
                        {
                            clsid = ResolveClsidFromRegistryLocation(resolvedLoc);
                        }

                        string publisher = matchedLive?.Publisher ?? string.Empty;
                        bool hasSig = matchedLive?.HasSignature ?? false;
                        if (string.IsNullOrWhiteSpace(publisher) || publisher == "未知发布者" || publisher == "系统拦截暂存")
                        {
                            (publisher, hasSig, _) = SystemStartupItemsManager.ExtractPublisherDetails(resolvedCmd);
                        }

                        string menuScene = log.Category is MonitorCategory.ClassicContextMenu or MonitorCategory.ModernContextMenu
                            ? ContextMenuSceneHelper.DescribeScene(log.Category, resolvedLoc, matchedLive?.ScopeScene)
                            : string.Empty;

                        auditList.Add(new PendingAuditItem
                        {
                            DisplayName = dispName,
                            Publisher = publisher,
                            HasSignature = hasSig,
                            CommandOrPath = resolvedCmd,
                            LocationKey = resolvedLoc,
                            Category = log.Category,
                            CategoryName = log.CategoryName,
                            CategoryIcon = log.CategoryIcon,
                            Reason = log.DiagnosticText,
                            AuditSource = log.ActionTaken.Contains("游戏") ? "游戏模式暂存" : "先拦截后审核",
                            EventTime = log.EventTime,
                            RawItem = matchedLive,
                            RawLog = log,
                            Clsid = clsid,
                            MenuSceneText = menuScene,
                            SourceProcess = srcProc,
                            RealIconSource = matchedLive?.RealIconSource ?? ProgramIconResolver.ResolveIcon(resolvedCmd, log.Category)
                        });
                    }
                }
            }
        }
        catch { }

        return auditList;
    }

    internal static SystemStartupItemsManager.ManagedStartupItem? FindMatchingLiveItem(
        List<SystemStartupItemsManager.ManagedStartupItem> allItems,
        string locationKey,
        string targetProgram)
    {
        if (!string.IsNullOrWhiteSpace(locationKey))
        {
            var exact = allItems.FirstOrDefault(i => i.LocationKey.Equals(locationKey, StringComparison.OrdinalIgnoreCase));
            if (exact != null) return exact;

            string normLoc = NormalizeLocationKeyForMatch(ShellNavigationHelper.NormalizeFullRegistryPath(locationKey));
            var byNorm = allItems.FirstOrDefault(i =>
                NormalizeLocationKeyForMatch(ShellNavigationHelper.NormalizeFullRegistryPath(i.LocationKey))
                    .Equals(normLoc, StringComparison.OrdinalIgnoreCase));
            return byNorm;
        }

        if (!string.IsNullOrWhiteSpace(targetProgram))
        {
            return allItems.FirstOrDefault(i => i.CommandOrPath.Equals(targetProgram, StringComparison.OrdinalIgnoreCase));
        }

        return null;
    }

    internal static string NormalizeLocationKeyForMatch(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return string.Empty;

        string normalized = path
            .Replace(@"\-ContextMenuHandlers\", @"\ContextMenuHandlers\", StringComparison.OrdinalIgnoreCase)
            .Replace(@"\-DragDropHandlers\", @"\DragDropHandlers\", StringComparison.OrdinalIgnoreCase);

        int lastSlash = normalized.LastIndexOf('\\');
        if (lastSlash < 0 || lastSlash >= normalized.Length - 1)
            return normalized;

        string leaf = normalized[(lastSlash + 1)..].TrimStart('-');
        return normalized[..(lastSlash + 1)] + leaf;
    }

    private static string ResolveClsidFromRegistryLocation(string locationKey)
    {
        if (!OperatingSystem.IsWindows() || string.IsNullOrWhiteSpace(locationKey))
            return string.Empty;

        try
        {
            string full = ShellNavigationHelper.NormalizeFullRegistryPath(locationKey);
            int slash = full.IndexOf('\\');
            if (slash <= 0) return string.Empty;

            string rootName = full[..slash].ToUpperInvariant();
            string subKey = full[(slash + 1)..];
            Microsoft.Win32.RegistryHive? hive = rootName switch
            {
                "HKEY_LOCAL_MACHINE" => Microsoft.Win32.RegistryHive.LocalMachine,
                "HKEY_CURRENT_USER" => Microsoft.Win32.RegistryHive.CurrentUser,
                "HKEY_CLASSES_ROOT" => Microsoft.Win32.RegistryHive.ClassesRoot,
                "HKEY_USERS" => Microsoft.Win32.RegistryHive.Users,
                _ => null
            };
            if (hive == null) return string.Empty;

            foreach (var view in new[] { Microsoft.Win32.RegistryView.Registry64, Microsoft.Win32.RegistryView.Registry32 })
            {
                using var baseKey = Microsoft.Win32.RegistryKey.OpenBaseKey(hive.Value, view);
                foreach (string candidate in ShellNavigationHelper.ExpandDisabledRegistryVariants(subKey))
                {
                    using var key = baseKey.OpenSubKey(candidate, false);
                    string val = key?.GetValue(null)?.ToString()?.Trim().TrimStart('-') ?? string.Empty;
                    if (val.StartsWith('{') && val.EndsWith('}'))
                        return val;
                }
            }
        }
        catch { }

        return string.Empty;
    }

    private void RefreshRules()
    {
        try
        {
            _allRules = _sqliteRepo.GetAllRulesWithWeightsAndAliases();
        }
        catch
        {
            _allRules = [];
        }
        ApplyRulesFilter();
    }

    private void RefreshLogs()
    {
        try
        {
            _allLogs = _sqliteRepo.GetRecentAuditLogs(500);
        }
        catch
        {
            _allLogs = [];
        }
        ApplyLogsFilter();
    }

    private void ApplyRulesFilter()
    {
        var filtered = _allRules.Where(r =>
        {
            if (_activeLogsCategories.Count > 0 && !_activeLogsCategories.Contains(r.Category))
            {
                return false;
            }

            if (!string.IsNullOrWhiteSpace(_currentLogsSearchTerm))
            {
                string term = _currentLogsSearchTerm;
                return r.DisplayName.Contains(term, StringComparison.OrdinalIgnoreCase) ||
                       r.TargetBinaryOrCommand.Contains(term, StringComparison.OrdinalIgnoreCase) ||
                       r.NormalizedPath.Contains(term, StringComparison.OrdinalIgnoreCase) ||
                       r.LocationKey.Contains(term, StringComparison.OrdinalIgnoreCase) ||
                       r.SignerSubject.Contains(term, StringComparison.OrdinalIgnoreCase) ||
                       r.RuleModeText.Contains(term, StringComparison.OrdinalIgnoreCase) ||
                       r.CategoryName.Contains(term, StringComparison.OrdinalIgnoreCase);
            }

            return true;
        }).ToList();

        string renderSignature = AppGroupingHelper.ComputeRulesRenderSignature(
            filtered,
            _rulesGroupMode,
            _currentLogsSearchTerm,
            _activeLogsCategories);

        if (!string.IsNullOrEmpty(_lastRulesRenderSignature) &&
            string.Equals(renderSignature, _lastRulesRenderSignature, StringComparison.Ordinal))
        {
            UpdateLogsFilterSummary();
            return;
        }
        _lastRulesRenderSignature = renderSignature;

        _displayedRuleGroups.Clear();

        if (_rulesGroupMode == "ByApp")
        {
            var inputs = filtered.Select(r => new AppGroupingHelper.AppAttributionInput<RuleRecord>(
                Item: r,
                Category: r.Category,
                DisplayName: r.DisplayName,
                PathOrCommand: r.TargetBinaryOrCommand,
                LocationKey: r.LocationKey,
                Publisher: r.SignerSubject,
                ProductName: r.ProductName)).ToList();

            var clusters = AppGroupingHelper.ClusterByApplication(inputs);
            bool expandAppGroup = !string.IsNullOrWhiteSpace(_currentLogsSearchTerm) || _activeLogsCategories.Count > 0;
            foreach (var cluster in clusters)
            {
                System.Windows.Media.ImageSource? resolvedIcon = null;
                foreach (var rule in cluster.Items)
                {
                    resolvedIcon = ProgramIconResolver.ResolveIcon(rule.TargetBinaryOrCommand, rule.Category);
                    if (resolvedIcon != null) break;
                }

                var grp = new RuleDisplayGroup
                {
                    GroupKey = cluster.AppKey,
                    HeaderTitle = cluster.AppTitle,
                    Subtitle = cluster.Subtitle,
                    IconSymbol = "Apps24",
                    CountText = $"{cluster.Items.Count} 条",
                    AppIconSource = resolvedIcon,
                    IsExpanded = expandAppGroup
                };
                foreach (var rule in cluster.Items)
                    grp.Items.Add(new RuleDisplayItem { Rule = rule, IsDetailsExpanded = false });
                _displayedRuleGroups.Add(grp);
            }
        }
        else
        {
            var categoryOrder = GlobalSearchHelper.OrderedFilterCategories;

            var byCat = filtered.GroupBy(r => r.Category).ToDictionary(g => g.Key, g => g.OrderBy(x => x.DisplayName, StringComparer.CurrentCultureIgnoreCase).ToList());
            foreach (var cat in categoryOrder)
            {
                if (!byCat.TryGetValue(cat, out var rules) || rules.Count == 0) continue;
                var first = rules[0];
                var grp = new RuleDisplayGroup
                {
                    GroupKey = cat.ToString(),
                    HeaderTitle = first.CategoryName,
                    Subtitle = string.Empty,
                    IconSymbol = first.CategoryIcon,
                    CountText = $"{rules.Count} 条",
                    IsExpanded = true
                };
                foreach (var rule in rules)
                    grp.Items.Add(new RuleDisplayItem { Rule = rule, IsDetailsExpanded = false });
                _displayedRuleGroups.Add(grp);
            }
        }

        UpdateLogsFilterSummary();
    }

    private void RulesGroupMode_Checked(object sender, RoutedEventArgs e)
    {
        if (!_isInitialized) return;
        if (sender is not System.Windows.Controls.RadioButton rb || rb.Tag is not string mode)
            return;
        _rulesGroupMode = mode;
        ApplyRulesFilter();
        PlayTabSwitchAnimation(RulesScrollViewer);
    }

    private void BtnToggleRuleItemDetails_Click(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: RuleDisplayItem vm })
        {
            vm.IsDetailsExpanded = !vm.IsDetailsExpanded;
        }
    }

    private static RuleRecord? ResolveRuleFromSender(object sender) => sender is FrameworkElement fe
        ? (fe.Tag is RuleDisplayItem vm ? vm.Rule : fe.Tag as RuleRecord)
        : null;

    private static SystemStartupItemsManager.ManagedStartupItem BuildTempManagedItemFromRule(RuleRecord rule)
    {
        string clsid = PrivilegedRollbackEngine.ExtractClsidOrIdentifier(rule.LocationKey);
        if (!(clsid.StartsWith('{') && clsid.EndsWith('}')))
            clsid = string.Empty;

        return new SystemStartupItemsManager.ManagedStartupItem
        {
            DisplayName = rule.DisplayName,
            Publisher = rule.PublisherDisplay,
            HasSignature = rule.HasSignature,
            CommandOrPath = rule.TargetBinaryOrCommand,
            LocationKey = rule.LocationKey,
            Category = rule.Category,
            CategoryName = rule.CategoryName,
            CategoryIcon = rule.CategoryIcon,
            Clsid = clsid,
            IsEnabled = rule.ActionType == InterceptionAction.Allow,
            StatusSummary = $"{rule.ActionTypeText} · {rule.RuleModeText} · MD5: {rule.Md5Display}"
        };
    }

    private void BtnRuleOpenFile_Click(object sender, RoutedEventArgs e)
    {
        RuleRecord? rule = ResolveRuleFromSender(sender);
        if (rule == null) return;
        ShellNavigationHelper.OpenFileLocationOrFallback(rule.TargetBinaryOrCommand, rule.LocationKey, rule.Category);
    }

    private void BtnRuleOpenLocation_Click(object sender, RoutedEventArgs e)
    {
        RuleRecord? rule = ResolveRuleFromSender(sender);
        if (rule == null) return;
        ShellNavigationHelper.LocateStorageLocation(rule.LocationKey, rule.TargetBinaryOrCommand, rule.Category);
    }

    private void BtnRuleViewDetail_Click(object sender, RoutedEventArgs e)
    {
        RuleRecord? rule = ResolveRuleFromSender(sender);
        if (rule == null) return;
        OpenItemDetailDialog(BuildTempManagedItemFromRule(rule));
    }

    private void BtnRuleCopyAiPrompt_Click(object sender, RoutedEventArgs e)
    {
        RuleRecord? rule = ResolveRuleFromSender(sender);
        if (rule == null) return;

        string clsid = PrivilegedRollbackEngine.ExtractClsidOrIdentifier(rule.LocationKey);
        if (!(clsid.StartsWith('{') && clsid.EndsWith('}')))
            clsid = string.Empty;

        var info = new ShellNavigationHelper.AiPromptItemInfo(
            rule.CategoryName,
            rule.DisplayName,
            rule.PublisherDisplay,
            rule.TargetBinaryOrCommand,
            rule.LocationKey,
            null,
            string.IsNullOrEmpty(clsid) ? null : clsid,
            null);
        string prompt = ShellNavigationHelper.BuildAiAgentPrompt(info);
        if (string.IsNullOrWhiteSpace(prompt)) return;

        try
        {
            System.Windows.Clipboard.SetText(prompt);
            if (sender is Wpf.Ui.Controls.Button btn)
            {
                btn.Content = "已复制 ✓";
                var timer = new System.Windows.Threading.DispatcherTimer
                {
                    Interval = TimeSpan.FromMilliseconds(1500)
                };
                timer.Tick += (_, _) =>
                {
                    timer.Stop();
                    btn.Content = "复制 AI 提示词";
                };
                timer.Start();
            }
        }
        catch { }
    }

    private void BtnRuleSearchWeb_Click(object sender, RoutedEventArgs e)
    {
        RuleRecord? rule = ResolveRuleFromSender(sender);
        if (rule == null) return;
        ShellNavigationHelper.SearchOnline(rule.DisplayName, rule.SignerSubject);
    }

    private void ApplyLogsFilter()
    {
        bool hasActiveFilter = _activeLogsCategories.Count > 0 ||
                               _activeLogStatuses.Count > 0 ||
                               !string.IsNullOrWhiteSpace(_currentLogsSearchTerm);

        var filtered = _allLogs.Where(l =>
        {
            if (_activeLogsCategories.Count > 0 && !_activeLogsCategories.Contains(l.Category))
            {
                return false;
            }

            if (_activeLogStatuses.Count > 0 && !MatchesLogStatusFilter(l, _activeLogStatuses))
            {
                return false;
            }

            if (!string.IsNullOrWhiteSpace(_currentLogsSearchTerm))
            {
                string term = _currentLogsSearchTerm;
                return l.TargetProgram.Contains(term, StringComparison.OrdinalIgnoreCase) ||
                       l.LocationKey.Contains(term, StringComparison.OrdinalIgnoreCase) ||
                       l.DiagnosticText.Contains(term, StringComparison.OrdinalIgnoreCase) ||
                       l.ActionTaken.Contains(term, StringComparison.OrdinalIgnoreCase) ||
                       l.DisplayActionText.Contains(term, StringComparison.OrdinalIgnoreCase) ||
                       l.CategoryName.Contains(term, StringComparison.OrdinalIgnoreCase);
            }

            return true;
        });

        var today = DateTime.Now.Date;
        var yesterday = today.AddDays(-1);
        var groups = filtered
            .GroupBy(l => l.EventTime.Date)
            .OrderByDescending(g => g.Key);

        _displayedLogDayGroups.Clear();
        foreach (var grp in groups)
        {
            bool isToday = grp.Key == today;
            string header = grp.Key == today
                ? $"今天 · {grp.Key:yyyy-MM-dd}"
                : grp.Key == yesterday
                    ? $"昨天 · {grp.Key:yyyy-MM-dd}"
                    : $"{grp.Key:yyyy-MM-dd}";

            var itemsList = grp.OrderByDescending(x => x.EventTime).ToList();
            var dayGroup = new AuditLogDayGroup
            {
                DateKey = grp.Key.ToString("yyyy-MM-dd"),
                HeaderTitle = header,
                CountText = $"{itemsList.Count} 条",
                IsExpanded = isToday || hasActiveFilter
            };
            foreach (var item in itemsList)
            {
                dayGroup.Items.Add(item);
            }
            _displayedLogDayGroups.Add(dayGroup);
        }

        UpdateLogsFilterSummary();
    }

    private static bool MatchesLogStatusFilter(AuditLogRecord log, HashSet<string> statuses)
    {
        string raw = $"{log.ActionTaken} {log.DisplayActionText}";
        bool isFailed = raw.Contains("失败", StringComparison.OrdinalIgnoreCase) || raw.Contains("异常", StringComparison.OrdinalIgnoreCase) || raw.Contains("未生效", StringComparison.OrdinalIgnoreCase) || raw.Contains("Fail", StringComparison.OrdinalIgnoreCase);
        bool isPending = raw.Contains("待审", StringComparison.OrdinalIgnoreCase)
            || raw.Contains("暂存", StringComparison.OrdinalIgnoreCase)
            || raw.Contains("未处置", StringComparison.OrdinalIgnoreCase)
            || raw.Contains("关闭", StringComparison.OrdinalIgnoreCase)
            || raw.Contains("Dismiss", StringComparison.OrdinalIgnoreCase)
            || raw.Contains("Pending", StringComparison.OrdinalIgnoreCase);
        bool isAllowed = raw.Contains("放行", StringComparison.OrdinalIgnoreCase) || raw.Contains("恢复", StringComparison.OrdinalIgnoreCase) || raw.Contains("Allow", StringComparison.OrdinalIgnoreCase) || raw.Contains("Revert", StringComparison.OrdinalIgnoreCase) || raw.Contains("Manual", StringComparison.OrdinalIgnoreCase);
        bool isBlocked = raw.Contains("阻止", StringComparison.OrdinalIgnoreCase) || raw.Contains("禁止", StringComparison.OrdinalIgnoreCase) || raw.Contains("禁用", StringComparison.OrdinalIgnoreCase) || raw.Contains("回滚", StringComparison.OrdinalIgnoreCase) || raw.Contains("删除", StringComparison.OrdinalIgnoreCase) || raw.Contains("移除", StringComparison.OrdinalIgnoreCase) || raw.Contains("屏蔽", StringComparison.OrdinalIgnoreCase) || raw.Contains("Block", StringComparison.OrdinalIgnoreCase) || raw.Contains("Rollback", StringComparison.OrdinalIgnoreCase) || raw.Contains("Delete", StringComparison.OrdinalIgnoreCase);

        if (statuses.Contains("Failed") && isFailed) return true;
        if (statuses.Contains("Pending") && isPending) return true;
        if (statuses.Contains("Allowed") && isAllowed) return true;
        if (statuses.Contains("Blocked") && isBlocked) return true;
        return false;
    }

    private void UpdateLogsFilterSummary()
    {
        if (BtnToggleLogsFilter == null || TxtLogsFilterSummary == null) return;

        bool isRulesTab = FilterRulesShowRules?.IsChecked == true;
        int condCount = _activeLogsCategories.Count
            + (isRulesTab ? 0 : _activeLogStatuses.Count)
            + (string.IsNullOrWhiteSpace(_currentLogsSearchTerm) ? 0 : 1);

        if (condCount > 0)
        {
            BtnToggleLogsFilter.Appearance = ControlAppearance.Primary;
            TxtLogsFilterSummary.Text = $"已应用 {condCount} 项筛选";
        }
        else
        {
            BtnToggleLogsFilter.Appearance = PanelLogsFilterDrawer?.Visibility == Visibility.Visible
                ? ControlAppearance.Primary
                : ControlAppearance.Secondary;
            TxtLogsFilterSummary.Text = string.Empty;
        }
    }

    #endregion

    #region Left Navigation & Submenu Switching

    private void Nav_Checked(object sender, RoutedEventArgs e)
    {
        if (!_isInitialized) return;
        if (sender is not System.Windows.Controls.RadioButton rb || rb.Tag is not string tag)
            return;

        CloseGlobalSearchOverlay(clearQuery: false);
        SwitchToPage(tag);

        if (tag == "PageContextMenu")
        {
            if (ContextMenuSubListPanel != null && ContextMenuSubListPanel.Visibility != Visibility.Visible)
            {
                ToggleContextMenuSubMenu(expand: true);
            }
            if (string.IsNullOrEmpty(_currentClassicScene) && _currentClassicFilter is not ("ByApp" or "FileTypes" or "MenuAnalysis" or "Win11Modern"))
            {
                _currentClassicScene = "Scene_File";
                _currentClassicFilter = "Scene_File";
                if (SubNavClassicFile != null) SubNavClassicFile.IsChecked = true;
            }
            ApplyClassicMenuFilter();
        }
        else
        {
            _currentClassicScene = string.Empty;
        }
    }

    private void NavContextMenu_PreviewMouseDown(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        if (!_isInitialized) return;
        if (NavContextMenu.IsChecked == true)
        {
            ToggleContextMenuSubMenu();
        }
        else
        {
            if (ContextMenuSubListPanel != null && ContextMenuSubListPanel.Visibility != Visibility.Visible)
            {
                ToggleContextMenuSubMenu(expand: true);
            }
        }
    }

    private void ToggleContextMenuSubMenu(bool? expand = null)
    {
        if (ContextMenuSubListPanel == null || RotateContextMenuChevron == null) return;
        bool targetState = expand ?? (ContextMenuSubListPanel.Visibility != Visibility.Visible);

        var rotateAnim = new DoubleAnimation(targetState ? 180 : 0, TimeSpan.FromMilliseconds(200))
        {
            EasingFunction = new CubicEase { EasingMode = EasingMode.EaseInOut }
        };
        RotateContextMenuChevron.BeginAnimation(RotateTransform.AngleProperty, rotateAnim);

        if (targetState)
        {
            ContextMenuSubListPanel.Visibility = Visibility.Visible;
            var opacityAnim = new DoubleAnimation(0.0, 1.0, TimeSpan.FromMilliseconds(200))
            {
                EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
            };
            ContextMenuSubListPanel.BeginAnimation(UIElement.OpacityProperty, opacityAnim);
        }
        else
        {
            var opacityAnim = new DoubleAnimation(1.0, 0.0, TimeSpan.FromMilliseconds(150))
            {
                EasingFunction = new CubicEase { EasingMode = EasingMode.EaseIn }
            };
            opacityAnim.Completed += (_, _) =>
            {
                if (RotateContextMenuChevron.Angle < 90)
                {
                    ContextMenuSubListPanel.Visibility = Visibility.Collapsed;
                }
            };
            ContextMenuSubListPanel.BeginAnimation(UIElement.OpacityProperty, opacityAnim);
        }
    }

    private void SubNavContextMenu_Checked(object sender, RoutedEventArgs e)
    {
        if (!_isInitialized) return;
        if (sender is System.Windows.Controls.RadioButton rb && rb.Tag is string tag)
        {
            SwitchToPage("PageContextMenu");
            if (tag.StartsWith("Scene_", StringComparison.OrdinalIgnoreCase))
            {
                _currentClassicScene = tag;
                _currentClassicFilter = tag;
            }
            else
            {
                _currentClassicScene = string.Empty;
                _currentClassicFilter = tag;
            }
            ApplyClassicMenuFilter();
        }
    }

    private void NavScene_Checked(object sender, RoutedEventArgs e)
    {
        if (!_isInitialized) return;
        if (sender is not System.Windows.Controls.RadioButton rb || rb.Tag is not string tag)
            return;

        // 点击二级场景项自动切换到右键菜单页面
        SwitchToPage("PageContextMenu");
        _currentClassicScene = tag;
        ApplyClassicMenuFilter();
    }

    private void SwitchToPage(string pageTag)
    {
        if (!_isInitialized || PageStartupManager == null || PageContextMenu == null || PageAuditCenter == null || PageLogs == null || PageSettings == null)
            return;

        string normalizedTag = pageTag switch
        {
            "PageClassicMenu" or "PageWin11Menu" => "PageContextMenu",
            "PageRules" => "PageLogs",
            _ => pageTag
        };

        var pages = new (string Tag, FrameworkElement Page)[]
        {
            ("PageStartupManager", PageStartupManager),
            ("PageContextMenu", PageContextMenu),
            ("PageAuditCenter", PageAuditCenter),
            ("PageLogs", PageLogs),
            ("PageSettings", PageSettings)
        };

        foreach (var (tag, page) in pages)
        {
            if (tag == normalizedTag)
            {
                if (page.Visibility != Visibility.Visible)
                {
                    page.Visibility = Visibility.Visible;

                    // Microsoft Store 标准平滑页面进入动效 (Fade-in + Slide-up)
                    try
                    {
                        var fadeIn = new System.Windows.Media.Animation.DoubleAnimation(0.0, 1.0, TimeSpan.FromMilliseconds(200))
                        {
                            EasingFunction = new System.Windows.Media.Animation.CubicEase { EasingMode = System.Windows.Media.Animation.EasingMode.EaseOut }
                        };
                        var slideUp = new System.Windows.Media.Animation.DoubleAnimation(12.0, 0.0, TimeSpan.FromMilliseconds(200))
                        {
                            EasingFunction = new System.Windows.Media.Animation.CubicEase { EasingMode = System.Windows.Media.Animation.EasingMode.EaseOut }
                        };
                        var transform = new System.Windows.Media.TranslateTransform();
                        page.RenderTransform = transform;
                        page.BeginAnimation(UIElement.OpacityProperty, fadeIn);
                        transform.BeginAnimation(System.Windows.Media.TranslateTransform.YProperty, slideUp);
                    }
                    catch { }
                }

                if (normalizedTag == "PageLogs")
                {
                    SyncLogsPageHeaderActionButtons(FilterRulesShowRules?.IsChecked == true);
                }

                if (!App.IsScreenshotMode)
                {
                    if (normalizedTag == "PageLogs")
                    {
                        RefreshLogs();
                        RefreshRules();
                    }
                    else if (normalizedTag == "PageAuditCenter")
                    {
                        _allAuditItems = BuildPendingAuditItems(_allStartupItems.Concat(_allClassicMenuItems).ToList());
                        TxtPendingCount.Text = _allAuditItems.Count.ToString();
                        BadgePendingCount.Visibility = _allAuditItems.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
                        TxtPendingSummary.Text = $"共有 {_allAuditItems.Count} 项待审核";
                        ApplyAuditFilter();
                    }
                    else if (normalizedTag == "PageSettings")
                    {
                        UpdateSystemNotificationStatusBanner();
                        UpdateServiceStatusUI();
                    }
                }
            }
            else
            {
                page.Visibility = Visibility.Collapsed;
            }
        }
    }

    #endregion

    #region Filtering Logic

    private void ApplyStartupFilter()
    {
        bool hideMicrosoft = TglHideMicrosoft?.IsChecked ?? true;

        if (_currentStartupFilter == "ByApp")
        {
            if (ListViewStartup != null) ListViewStartup.Visibility = Visibility.Collapsed;
            if (StartupByAppScrollViewer != null) StartupByAppScrollViewer.Visibility = Visibility.Visible;

            var combined = _allStartupItems.Where(item =>
            {
                if (hideMicrosoft && item.IsMicrosoftOrSystemBuiltIn)
                    return false;

                if (!string.IsNullOrWhiteSpace(_currentStartupSearchTerm))
                {
                    string term = _currentStartupSearchTerm.ToLowerInvariant();
                    return item.DisplayName.ToLowerInvariant().Contains(term) ||
                           item.Publisher.ToLowerInvariant().Contains(term) ||
                           item.ProductName.ToLowerInvariant().Contains(term) ||
                           item.CommandOrPath.ToLowerInvariant().Contains(term) ||
                           item.LocationKey.ToLowerInvariant().Contains(term);
                }

                return true;
            }).ToList();

            PopulateAppStartupGroups(combined, _displayedStartupAppGroups, includeCategorySections: true, forceExpandAll: !string.IsNullOrWhiteSpace(_currentStartupSearchTerm));
            return;
        }

        if (ListViewStartup != null) ListViewStartup.Visibility = Visibility.Visible;
        if (StartupByAppScrollViewer != null) StartupByAppScrollViewer.Visibility = Visibility.Collapsed;

        var filtered = _allStartupItems.Where(item =>
        {
            if (hideMicrosoft && item.IsMicrosoftOrSystemBuiltIn)
                return false;

            if (_currentStartupFilter != "All")
            {
                string catName = item.Category.ToString();
                if (!catName.Equals(_currentStartupFilter, StringComparison.OrdinalIgnoreCase))
                    return false;
            }

            if (!string.IsNullOrWhiteSpace(_currentStartupSearchTerm))
            {
                string term = _currentStartupSearchTerm.ToLowerInvariant();
                return item.DisplayName.ToLowerInvariant().Contains(term) ||
                       item.Publisher.ToLowerInvariant().Contains(term) ||
                       item.CommandOrPath.ToLowerInvariant().Contains(term);
            }

            return true;
        }).ToList();

        _displayedStartupItems.Clear();
        foreach (var item in filtered)
        {
            _displayedStartupItems.Add(item);
        }
        ListViewStartup?.UpdateLayout();
    }

    private static void PopulateAppStartupGroups(
        IReadOnlyList<SystemStartupItemsManager.ManagedStartupItem> items,
        ObservableCollection<AppStartupGroup> target,
        bool includeCategorySections,
        bool forceExpandAll)
    {
        var inputs = items.Select(i => new AppGroupingHelper.AppAttributionInput<SystemStartupItemsManager.ManagedStartupItem>(
            Item: i,
            Category: i.Category,
            DisplayName: i.DisplayName,
            PathOrCommand: i.CommandOrPath,
            LocationKey: i.LocationKey,
            Publisher: i.Publisher,
            Clsid: i.Clsid,
            ProductName: i.ProductName,
            IsMicrosoftBuiltIn: i.IsMicrosoftOrSystemBuiltIn)).ToList();

        var clusters = AppGroupingHelper.ClusterByApplication(inputs);
        target.Clear();
        for (int idx = 0; idx < clusters.Count; idx++)
        {
            var cluster = clusters[idx];
            // 只要同一应用下任一关联条目拥有图标，即提取作为应用组主图标
            System.Windows.Media.ImageSource? groupIcon = cluster.Items.FirstOrDefault(x => x.HasRealIcon)?.RealIconSource;
            if (groupIcon == null)
            {
                foreach (var candidate in cluster.Items)
                {
                    groupIcon = ProgramIconResolver.ResolveIcon(candidate.CommandOrPath, candidate.Category);
                    if (groupIcon != null)
                    {
                        candidate.RealIconSource ??= groupIcon;
                        break;
                    }
                }
            }

            var grp = new AppStartupGroup
            {
                AppKey = cluster.AppKey,
                AppTitle = cluster.AppTitle,
                CategorySummary = cluster.Subtitle,
                CountText = $"{cluster.Items.Count} 项",
                AppIconSource = groupIcon,
                IsExpanded = forceExpandAll
            };

            if (includeCategorySections)
            {
                foreach (var sec in cluster.Items.GroupBy(i => AppGroupingHelper.CategoryDisplayLabel(i.Category)))
                {
                    var catSection = new AppCategorySection { CategoryTitle = $"{sec.Key} ({sec.Count()})" };
                    foreach (var m in sec)
                        catSection.Items.Add(m);
                    grp.CategorySections.Add(catSection);
                }
            }
            else
            {
                foreach (var m in cluster.Items)
                    grp.AllItems.Add(m);
            }

            target.Add(grp);
        }
    }

    private void UpdateSceneExtensionToolPanels()
    {
        bool showOpenWith = _currentClassicScene == "Scene_OpenWith" && _currentClassicFilter != "MenuAnalysis" && _currentClassicFilter != "FileTypes" && _currentClassicFilter != "ByApp";
        bool showDragDrop = _currentClassicScene == "Scene_DragDrop" && _currentClassicFilter != "MenuAnalysis" && _currentClassicFilter != "FileTypes" && _currentClassicFilter != "ByApp";
        bool showGuidBlocked = _currentClassicScene == "Scene_GuidBlocked" && _currentClassicFilter != "MenuAnalysis" && _currentClassicFilter != "FileTypes" && _currentClassicFilter != "ByApp";

        if (PanelOpenWithInspector != null)
            PanelOpenWithInspector.Visibility = showOpenWith ? Visibility.Visible : Visibility.Collapsed;
        if (PanelDragDropEffect != null)
        {
            PanelDragDropEffect.Visibility = showDragDrop ? Visibility.Visible : Visibility.Collapsed;
            if (showDragDrop)
                SyncDragDropEffectComboFromSystem();
        }
        if (PanelGuidBlockedBar != null)
            PanelGuidBlockedBar.Visibility = showGuidBlocked ? Visibility.Visible : Visibility.Collapsed;
    }

    private void SyncDragDropEffectComboFromSystem()
    {
        if (CmbDefaultDropEffect == null) return;
        int currentEffect = _startupManager.GetDefaultDropEffect();
        bool prevInit = _isInitialized;
        _isInitialized = false;
        SelectComboBoxItemByTag(CmbDefaultDropEffect, currentEffect.ToString());
        _isInitialized = prevInit;
    }

    private void ApplyClassicMenuFilter()
    {
        UpdateSceneExtensionToolPanels();

        if (_currentClassicFilter == "MenuAnalysis")
        {
            if (ListViewClassicMenu != null) ListViewClassicMenu.Visibility = Visibility.Collapsed;
            if (ContextMenuByAppScrollViewer != null) ContextMenuByAppScrollViewer.Visibility = Visibility.Collapsed;
            if (WinXGroupedScrollViewer != null) WinXGroupedScrollViewer.Visibility = Visibility.Collapsed;
            if (FileTypesHeaderPanel != null) FileTypesHeaderPanel.Visibility = Visibility.Collapsed;
            if (MenuAnalysisPanel != null) MenuAnalysisPanel.Visibility = Visibility.Visible;
            if (ListAnalysisMatches != null && ListAnalysisMatches.ItemsSource == null)
                ListAnalysisMatches.ItemsSource = _displayedAnalysisMatches;
            return;
        }

        if (MenuAnalysisPanel != null) MenuAnalysisPanel.Visibility = Visibility.Collapsed;

        if (_currentClassicFilter == "FileTypes")
        {
            if (FileTypesHeaderPanel != null) FileTypesHeaderPanel.Visibility = Visibility.Visible;
            if (ListViewClassicMenu != null) ListViewClassicMenu.Visibility = Visibility.Visible;
            if (ContextMenuByAppScrollViewer != null) ContextMenuByAppScrollViewer.Visibility = Visibility.Collapsed;
            if (WinXGroupedScrollViewer != null) WinXGroupedScrollViewer.Visibility = Visibility.Collapsed;
            UpdateFileTypeParamBarVisibility();
            if (_fileTypeCachedItems.Count == 0)
                LoadActiveFileTypeItems();

            var matchedFileTypes = _fileTypeCachedItems.Where(item =>
            {
                if (!string.IsNullOrWhiteSpace(_currentClassicSearchTerm))
                {
                    string term = _currentClassicSearchTerm.ToLowerInvariant();
                    return item.DisplayName.ToLowerInvariant().Contains(term) ||
                           item.Publisher.ToLowerInvariant().Contains(term) ||
                           item.ProductName.ToLowerInvariant().Contains(term) ||
                           item.CommandOrPath.ToLowerInvariant().Contains(term) ||
                           item.LocationKey.ToLowerInvariant().Contains(term);
                }
                return true;
            }).ToList();

            _displayedClassicMenuItems.Clear();
            foreach (var it in matchedFileTypes)
                _displayedClassicMenuItems.Add(it);
            return;
        }

        if (FileTypesHeaderPanel != null) FileTypesHeaderPanel.Visibility = Visibility.Collapsed;

        if (_currentClassicFilter == "ByApp")
        {
            if (ListViewClassicMenu != null) ListViewClassicMenu.Visibility = Visibility.Collapsed;
            if (WinXGroupedScrollViewer != null) WinXGroupedScrollViewer.Visibility = Visibility.Collapsed;
            if (ContextMenuByAppScrollViewer != null) ContextMenuByAppScrollViewer.Visibility = Visibility.Visible;

            var byAppItems = _allClassicMenuItems.Where(item =>
            {
                string scope = item.ScopeScene ?? string.Empty;
                if (scope.Contains("WinX", StringComparison.OrdinalIgnoreCase))
                    return false;

                if (!string.IsNullOrWhiteSpace(_currentClassicSearchTerm))
                {
                    string term = _currentClassicSearchTerm.ToLowerInvariant();
                    string appKeyword = AppGroupingHelper.ExtractAppSearchKeyword(
                        item.DisplayName, item.CommandOrPath, item.LocationKey, item.Publisher, item.Clsid);
                    return item.DisplayName.ToLowerInvariant().Contains(term) ||
                           item.Publisher.ToLowerInvariant().Contains(term) ||
                           item.ProductName.ToLowerInvariant().Contains(term) ||
                           item.CommandOrPath.ToLowerInvariant().Contains(term) ||
                           item.LocationKey.ToLowerInvariant().Contains(term) ||
                           item.Clsid.ToLowerInvariant().Contains(term) ||
                           appKeyword.Contains(term, StringComparison.OrdinalIgnoreCase);
                }

                return true;
            }).ToList();

            PopulateAppStartupGroups(
                byAppItems,
                _displayedClassicMenuAppGroups,
                includeCategorySections: false,
                forceExpandAll: !string.IsNullOrWhiteSpace(_currentClassicSearchTerm));
            return;
        }

        if (_currentClassicScene == "Scene_WinX")
        {
            if (ListViewClassicMenu != null) ListViewClassicMenu.Visibility = Visibility.Collapsed;
            if (ContextMenuByAppScrollViewer != null) ContextMenuByAppScrollViewer.Visibility = Visibility.Collapsed;
            if (WinXGroupedScrollViewer != null) WinXGroupedScrollViewer.Visibility = Visibility.Visible;
            LoadWinXGroups();
            return;
        }

        if (WinXGroupedScrollViewer != null) WinXGroupedScrollViewer.Visibility = Visibility.Collapsed;
        if (ListViewClassicMenu != null) ListViewClassicMenu.Visibility = Visibility.Visible;
        if (ContextMenuByAppScrollViewer != null) ContextMenuByAppScrollViewer.Visibility = Visibility.Collapsed;

        // GUID 锁场景：独立数据源仅展示 Shell Extensions\Blocked 项
        if (_currentClassicScene == "Scene_GuidBlocked")
        {
            var blockedFiltered = _guidBlockedItems.Where(item =>
            {
                if (!string.IsNullOrWhiteSpace(_currentClassicSearchTerm))
                {
                    string term = _currentClassicSearchTerm.ToLowerInvariant();
                    return item.DisplayName.ToLowerInvariant().Contains(term) ||
                           item.Publisher.ToLowerInvariant().Contains(term) ||
                           item.Clsid.ToLowerInvariant().Contains(term) ||
                           item.CommandOrPath.ToLowerInvariant().Contains(term) ||
                           item.LocationKey.ToLowerInvariant().Contains(term);
                }
                return true;
            })
            .OrderBy(item => item.DisplayName, StringComparer.CurrentCultureIgnoreCase)
            .ToList();

            _displayedClassicMenuItems.Clear();
            foreach (var item in blockedFiltered)
                _displayedClassicMenuItems.Add(item);
            return;
        }

        var filtered = _allClassicMenuItems.Where(item =>
        {
            string loc = item.LocationKey.ToLowerInvariant();
            string scope = item.ScopeScene ?? "";

            // 1. 左侧二级菜单场景筛选
            if (!string.IsNullOrEmpty(_currentClassicScene))
            {
                switch (_currentClassicScene)
                {
                    case "Scene_File":
                    case "Scene_AllFiles":
                        if (!loc.Contains(@"classes\*\") && !scope.StartsWith("AllFiles", StringComparison.OrdinalIgnoreCase)) return false;
                        if (loc.Contains("dragdrop") || loc.Contains("openwith")) return false;
                        break;
                    case "Scene_Folder":
                        if (!loc.Contains(@"classes\folder\")) return false;
                        if (loc.Contains("dragdrop")) return false;
                        break;
                    case "Scene_Directory":
                        if (!loc.Contains(@"classes\directory\shell") && !loc.Contains(@"classes\directory\shellex\contextmenuhandlers")) return false;
                        break;
                    case "Scene_DirBackground":
                        if (!loc.Contains(@"directory\background")) return false;
                        break;
                    case "Scene_DesktopBackground":
                        if (!loc.Contains("desktopbackground")) return false;
                        break;
                    case "Scene_Drive":
                        if (!loc.Contains(@"classes\drive\")) return false;
                        if (loc.Contains("dragdrop")) return false;
                        break;
                    case "Scene_AllObjects":
                        if (!loc.Contains("allfilesystemobjects")) return false;
                        break;
                    case "Scene_Computer":
                    case "Scene_ThisPC":
                        if (!loc.Contains("20d04fe0")) return false;
                        break;
                    case "Scene_RecycleBin":
                        if (!loc.Contains("645ff040")) return false;
                        break;
                    case "Scene_Library":
                        if (!loc.Contains("libraryfolder") && !loc.Contains("userlibraryfolder")) return false;
                        break;
                    case "Scene_SendTo":
                        if (!scope.Contains("SendTo", StringComparison.OrdinalIgnoreCase) && !loc.Contains("sendto")) return false;
                        break;
                    case "Scene_OpenWith":
                        if (!scope.Contains("OpenWith", StringComparison.OrdinalIgnoreCase) && !loc.Contains("openwith")) return false;
                        break;
                    case "Scene_WinX":
                        if (!scope.Contains("WinX", StringComparison.OrdinalIgnoreCase) && !loc.Contains(@"\winx\")) return false;
                        break;
                    case "Scene_LnkFile":
                        if (!loc.Contains(@"\lnkfile\")) return false;
                        break;
                    case "Scene_UwpLnk":
                        if (!loc.Contains("launcher.immersiveapplication")) return false;
                        break;
                    case "Scene_ExeFile":
                        if (!loc.Contains(@"\exefile\")) return false;
                        break;
                    case "Scene_UnknownType":
                        if (!loc.Contains(@"classes\unknown\")) return false;
                        break;
                    case "Scene_DragDrop":
                        if (!loc.Contains("dragdrophandlers") && !scope.Contains("DragDrop", StringComparison.OrdinalIgnoreCase)) return false;
                        break;
                    case "Scene_CommandStore":
                        if (!loc.Contains("commandstore") && !scope.Equals("CommandStore", StringComparison.OrdinalIgnoreCase)) return false;
                        break;
                    case "Scene_GuidBlocked":
                        if (item.IsEnabled || string.IsNullOrWhiteSpace(item.Clsid)) return false;
                        break;
                }
            }

            // 严格分离：全部旧版菜单与各旧版子项均不展示 Win11 现代菜单项，也不展示 Win+X（仅在 Win+X 独立菜单显示）
            if (_currentClassicFilter != "Win11Modern" &&
                _currentClassicFilter != "AllMenusIncludeWin11" &&
                item.Category == MonitorCategory.ModernContextMenu)
                return false;

            if (string.IsNullOrEmpty(_currentClassicScene) &&
                _currentClassicFilter == "ClassicAll")
            {
                if (scope.Contains("WinX", StringComparison.OrdinalIgnoreCase) ||
                    scope.Contains("深入分析", StringComparison.OrdinalIgnoreCase))
                    return false;
            }

            switch (_currentClassicFilter)
            {
                case "Win11Modern":
                    if (item.Category != MonitorCategory.ModernContextMenu && !scope.Contains("Win11")) return false;
                    break;
                case "MenuAnalysis":
                    if (!scope.Contains("深入分析") && !scope.Contains("Approved") && string.IsNullOrEmpty(item.Clsid)) return false;
                    break;
                case "ClassicBlocked":
                    if (item.IsEnabled) return false;
                    break;
            }

            // 3. 搜索词筛选
            if (!string.IsNullOrWhiteSpace(_currentClassicSearchTerm))
            {
                string term = _currentClassicSearchTerm.ToLowerInvariant();
                return item.DisplayName.ToLowerInvariant().Contains(term) ||
                       item.Publisher.ToLowerInvariant().Contains(term) ||
                       item.CommandOrPath.ToLowerInvariant().Contains(term) ||
                       item.LocationKey.ToLowerInvariant().Contains(term);
            }

            return true;
        })
        .OrderBy(item => item.DisplayName, StringComparer.CurrentCultureIgnoreCase)
        .ThenBy(item => item.CategoryName, StringComparer.CurrentCultureIgnoreCase)
        .ToList();

        _displayedClassicMenuItems.Clear();
        foreach (var item in filtered)
        {
            _displayedClassicMenuItems.Add(item);
        }
    }



    private void ApplyAuditFilter()
    {
        var filtered = _allAuditItems.Where(item =>
        {
            switch (_currentAuditFilter)
            {
                case "AuditContextMenu":
                    return item.Category is MonitorCategory.ClassicContextMenu or MonitorCategory.ModernContextMenu;
                case "AuditStartup":
                    return item.Category is MonitorCategory.StartupItem or MonitorCategory.Win32Service or MonitorCategory.KernelDriver;
                case "AuditGameMode":
                    return item.AuditSource.Contains("游戏");
                case "AuditHistory":
                    return item.RawLog != null;
                default:
                    return true;
            }
        }).ToList();

        foreach (var prev in _displayedAuditItems)
        {
            prev.PropertyChanged -= OnAuditItemSelectionChanged;
        }
        _displayedAuditItems.Clear();
        foreach (var item in filtered)
        {
            item.PropertyChanged -= OnAuditItemSelectionChanged;
            item.PropertyChanged += OnAuditItemSelectionChanged;
            _displayedAuditItems.Add(item);
        }
        UpdateAuditSelectionToolbar();
    }

    private void OnAuditItemSelectionChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(PendingAuditItem.IsSelected))
        {
            UpdateAuditSelectionToolbar();
        }
    }

    private void UpdateAuditSelectionToolbar()
    {
        int totalCount = _displayedAuditItems.Count;
        int selectedCount = _displayedAuditItems.Count(x => x.IsSelected);
        bool hasSelection = selectedCount > 0;

        if (BtnBatchApproveSelected != null)
            BtnBatchApproveSelected.Visibility = hasSelection ? Visibility.Visible : Visibility.Collapsed;
        if (BtnBatchBlockSelected != null)
            BtnBatchBlockSelected.Visibility = hasSelection ? Visibility.Visible : Visibility.Collapsed;
        if (BtnAuditSelectAll != null)
            BtnAuditSelectAll.Content = hasSelection ? "反选" : "全选";
    }

    #endregion

    #region Tab Filter Handlers (Top Horizontal Tabs)

    private static void PlayTabSwitchAnimation(UIElement? element)
    {
        if (element == null) return;
        var storyboard = new Storyboard();

        var opacityAnim = new DoubleAnimation(0.35, 1.0, TimeSpan.FromMilliseconds(200))
        {
            EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
        };
        Storyboard.SetTarget(opacityAnim, element);
        Storyboard.SetTargetProperty(opacityAnim, new PropertyPath("Opacity"));
        storyboard.Children.Add(opacityAnim);

        if (element.RenderTransform is not TranslateTransform)
        {
            element.RenderTransform = new TranslateTransform();
        }

        var slideAnim = new DoubleAnimation(10.0, 0.0, TimeSpan.FromMilliseconds(200))
        {
            EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
        };
        Storyboard.SetTarget(slideAnim, element);
        Storyboard.SetTargetProperty(slideAnim, new PropertyPath("(UIElement.RenderTransform).(TranslateTransform.Y)"));
        storyboard.Children.Add(slideAnim);

        storyboard.Begin();
    }

    private void Filter_Checked(object sender, RoutedEventArgs e)
    {
        if (sender is not System.Windows.Controls.RadioButton rb || rb.Tag is not string tag)
            return;
        _currentStartupFilter = tag;
        ApplyStartupFilter();
        PlayTabSwitchAnimation(tag == "ByApp" ? StartupByAppScrollViewer : ListViewStartup);
    }

    private void FilterClassic_Checked(object sender, RoutedEventArgs e)
    {
        if (sender is not System.Windows.Controls.RadioButton rb || rb.Tag is not string tag)
            return;
        _currentClassicFilter = tag;
        ApplyClassicMenuFilter();
        PlayTabSwitchAnimation(ListViewClassicMenu);
    }

    private void FilterAudit_Checked(object sender, RoutedEventArgs e)
    {
        if (sender is not System.Windows.Controls.RadioButton rb || rb.Tag is not string tag)
            return;
        _currentAuditFilter = tag;
        ApplyAuditFilter();
        PlayTabSwitchAnimation(ListViewAuditCenter);
    }

    private void SyncLogsPageHeaderActionButtons(bool showingRules)
    {
        if (BtnOpenCreateRuleDialog != null)
            BtnOpenCreateRuleDialog.Visibility = showingRules ? Visibility.Visible : Visibility.Collapsed;
        if (BtnClearAllLogs != null)
            BtnClearAllLogs.Visibility = showingRules ? Visibility.Collapsed : Visibility.Visible;
    }

    private void FilterRules_Checked(object sender, RoutedEventArgs e)
    {
        if (!_isInitialized) return;
        if (sender is not System.Windows.Controls.RadioButton rb || rb.Tag is not string tag)
            return;

        if (tag == "ShowRules")
        {
            RulesScrollViewer.Visibility = Visibility.Visible;
            LogsDayScrollViewer.Visibility = Visibility.Collapsed;
            if (PanelLogStatusFilters != null) PanelLogStatusFilters.Visibility = Visibility.Collapsed;
            if (PanelRulesGroupSwitch != null) PanelRulesGroupSwitch.Visibility = Visibility.Visible;
            SyncLogsPageHeaderActionButtons(showingRules: true);
            RefreshRules();
            PlayTabSwitchAnimation(RulesScrollViewer);
        }
        else
        {
            RulesScrollViewer.Visibility = Visibility.Collapsed;
            LogsDayScrollViewer.Visibility = Visibility.Visible;
            if (PanelLogStatusFilters != null) PanelLogStatusFilters.Visibility = Visibility.Visible;
            if (PanelRulesGroupSwitch != null) PanelRulesGroupSwitch.Visibility = Visibility.Collapsed;
            SyncLogsPageHeaderActionButtons(showingRules: false);
            RefreshLogs();
            PlayTabSwitchAnimation(LogsDayScrollViewer);
        }
        UpdateLogsFilterSummary();
    }

    private void BtnToggleLogsFilter_Click(object sender, RoutedEventArgs e)
    {
        if (PanelLogsFilterDrawer == null) return;
        PanelLogsFilterDrawer.Visibility = PanelLogsFilterDrawer.Visibility == Visibility.Visible
            ? Visibility.Collapsed
            : Visibility.Visible;
        UpdateLogsFilterSummary();
    }

    private void LogsFilterInput_Changed(object sender, RoutedEventArgs e)
    {
        if (!_isInitialized) return;
        SyncLogsCategoryGroupStates();
        CollectAndApplyLogsFilter();
    }

    private void ChkLogsGroupStartup_Click(object sender, RoutedEventArgs e)
    {
        if (!_isInitialized) return;
        System.Windows.Controls.CheckBox?[] items = [ChkCatStartupItem, ChkCatWin32Service, ChkCatKernelDriver, ChkCatScheduledTask, ChkCatWindowsPolicy];
        bool target = ComputeGroupToggleTarget(items);
        foreach (var cb in items)
        {
            if (cb != null) cb.IsChecked = target;
        }
        SyncLogsCategoryGroupStates();
        CollectAndApplyLogsFilter();
    }

    private void ChkLogsGroupContextMenu_Click(object sender, RoutedEventArgs e)
    {
        if (!_isInitialized) return;
        System.Windows.Controls.CheckBox?[] items = [ChkCatClassicMenu, ChkCatModernMenu];
        bool target = ComputeGroupToggleTarget(items);
        foreach (var cb in items)
        {
            if (cb != null) cb.IsChecked = target;
        }
        SyncLogsCategoryGroupStates();
        CollectAndApplyLogsFilter();
    }

    private void SyncLogsCategoryGroupStates()
    {
        SyncGroupCheckState(ChkLogsGroupStartup, ChkCatStartupItem, ChkCatWin32Service, ChkCatKernelDriver, ChkCatScheduledTask, ChkCatWindowsPolicy);
        SyncGroupCheckState(ChkLogsGroupContextMenu, ChkCatClassicMenu, ChkCatModernMenu);
    }

    private void BtnResetLogsFilter_Click(object sender, RoutedEventArgs e)
    {
        if (TxtSearchLogsOrRules != null) TxtSearchLogsOrRules.Text = string.Empty;
        if (ChkLogStatusBlocked != null) ChkLogStatusBlocked.IsChecked = false;
        if (ChkLogStatusPending != null) ChkLogStatusPending.IsChecked = false;
        if (ChkLogStatusAllowed != null) ChkLogStatusAllowed.IsChecked = false;
        if (ChkLogStatusFailed != null) ChkLogStatusFailed.IsChecked = false;
        if (ChkCatStartupItem != null) ChkCatStartupItem.IsChecked = false;
        if (ChkCatWin32Service != null) ChkCatWin32Service.IsChecked = false;
        if (ChkCatKernelDriver != null) ChkCatKernelDriver.IsChecked = false;
        if (ChkCatScheduledTask != null) ChkCatScheduledTask.IsChecked = false;
        if (ChkCatClassicMenu != null) ChkCatClassicMenu.IsChecked = false;
        if (ChkCatModernMenu != null) ChkCatModernMenu.IsChecked = false;
        if (ChkCatWindowsPolicy != null) ChkCatWindowsPolicy.IsChecked = false;
        SyncLogsCategoryGroupStates();

        _currentLogsSearchTerm = string.Empty;
        _activeLogStatuses.Clear();
        _activeLogsCategories.Clear();

        ApplyLogsFilter();
        ApplyRulesFilter();
    }

    private void CollectAndApplyLogsFilter()
    {
        _currentLogsSearchTerm = TxtSearchLogsOrRules?.Text.Trim() ?? string.Empty;

        _activeLogStatuses.Clear();
        if (ChkLogStatusBlocked?.IsChecked == true) _activeLogStatuses.Add("Blocked");
        if (ChkLogStatusPending?.IsChecked == true) _activeLogStatuses.Add("Pending");
        if (ChkLogStatusAllowed?.IsChecked == true) _activeLogStatuses.Add("Allowed");
        if (ChkLogStatusFailed?.IsChecked == true) _activeLogStatuses.Add("Failed");

        _activeLogsCategories.Clear();
        if (ChkCatStartupItem?.IsChecked == true) _activeLogsCategories.Add(MonitorCategory.StartupItem);
        if (ChkCatWin32Service?.IsChecked == true) _activeLogsCategories.Add(MonitorCategory.Win32Service);
        if (ChkCatKernelDriver?.IsChecked == true) _activeLogsCategories.Add(MonitorCategory.KernelDriver);
        if (ChkCatScheduledTask?.IsChecked == true) _activeLogsCategories.Add(MonitorCategory.ScheduledTask);
        if (ChkCatClassicMenu?.IsChecked == true) _activeLogsCategories.Add(MonitorCategory.ClassicContextMenu);
        if (ChkCatModernMenu?.IsChecked == true) _activeLogsCategories.Add(MonitorCategory.ModernContextMenu);
        if (ChkCatWindowsPolicy?.IsChecked == true) _activeLogsCategories.Add(MonitorCategory.WindowsPolicy);

        ApplyLogsFilter();
        ApplyRulesFilter();
    }

    private void BtnRefreshLogs_Click(object sender, RoutedEventArgs e)
    {
        RefreshLogs();
        RefreshRules();
    }

    private async void BtnClearAllLogs_Click(object sender, RoutedEventArgs e)
    {
        bool confirm = await ShowWinUiConfirmDialogAsync(
            "清空历史日志",
            "确定要永久清空全部历史拦截与审核日志吗？该操作不可撤销。",
            "清空日志",
            "取消");
        if (!confirm) return;

        await Task.Run(() =>
        {
            _sqliteRepo.ClearAuditLogs();
            _sqliteRepo.CompactDatabase();
        });
        RefreshLogs();
        await RefreshAllDataAsync();
    }

    private void TglHideMicrosoft_Click(object sender, RoutedEventArgs e)
    {
        bool hide = TglHideMicrosoft.IsChecked ?? true;
        UserSettingsStore.SetHideMicrosoftPreference(hide);
        ApplyStartupFilter();
    }

    private void TxtSearchStartup_TextChanged(object sender, TextChangedEventArgs e)
    {
        _currentStartupSearchTerm = TxtSearchStartup.Text.Trim();
        ApplyStartupFilter();
    }

    private void TxtSearchClassicMenu_TextChanged(object sender, TextChangedEventArgs e)
    {
        _currentClassicSearchTerm = TxtSearchClassicMenu.Text.Trim();
        ApplyClassicMenuFilter();
    }

    private async void BtnRefreshStartup_Click(object sender, RoutedEventArgs e) => await RefreshAllDataAsync(showOverlay: true, minimumOverlayMs: 0);
    private async void BtnRefreshClassicMenu_Click(object sender, RoutedEventArgs e) => await RefreshAllDataAsync(showOverlay: true, minimumOverlayMs: 0);
    private async void BtnRefreshAudit_Click(object sender, RoutedEventArgs e) => await RefreshAllDataAsync(showOverlay: true, minimumOverlayMs: 0);

    #endregion

    #region Item Operations (Toggle / Open / Delete)

    private async Task<bool> VerifyOperationWithRetryAsync(
        string displayName,
        string locationKey,
        Func<bool> retryAction,
        Func<bool> verifyFunc,
        bool showAlertOnFailure = true)
    {
        int[] delaysMs = [150, 500, 1200];
        for (int attempt = 0; attempt < delaysMs.Length; attempt++)
        {
            await Task.Delay(delaysMs[attempt]);
            bool ok = await Task.Run(() =>
            {
                try { return verifyFunc(); }
                catch { return false; }
            });
            if (ok) return true;

            if (attempt < delaysMs.Length - 1)
            {
                await Task.Run(() =>
                {
                    try { retryAction(); }
                    catch { }
                });
            }
        }

        try
        {
            _sqliteRepo.WriteAuditLog(
                null,
                MonitorCategory.StartupItem,
                displayName,
                locationKey,
                "状态异常",
                "需要手动核查",
                $"多次延迟复核后仍未生效，请以管理员身份手动核查：{locationKey}",
                100.0,
                "App 操作复核未生效");
        }
        catch { }

        if (showAlertOnFailure)
        {
            await ShowWinUiInfoDialogAsync(
                "操作未生效，请手动核查",
                $"已自动重试 2 次，但「{displayName}」的状态仍未按预期变更（可能受系统权限或安全策略锁定）。\n位置：{locationKey}");
        }

        return false;
    }

    private static void SyncRulesBinaryAndNotifyService(SqliteRuleRepository repo)
    {
        try
        {
            string binPath = ResolveRulesBinPath();
            using var mmf = new MmfBinaryStore(binPath);
            var allRules = repo.GetAllRulesWithWeightsAndAliases();
            var entries = allRules.Select(MmfRecordEntry.FromRule).ToArray();
            mmf.SaveEntriesAtomically(entries);
        }
        catch { }

        _ = Task.Run(async () =>
        {
            try
            {
                await using var client = new NamedPipeClientStream(".", "StartupGuard_Control_Pipe", PipeDirection.InOut, PipeOptions.Asynchronous);
                await client.ConnectAsync(500);
                var hdr = PipeMessageHeader.Create(PipeMessageType.ReloadRulesCache, 0, 0);
                byte[] hdrBytes = new byte[64];
                BinaryPipeSerializer.WriteHeader(hdrBytes, in hdr);
                await client.WriteAsync(hdrBytes);
                await client.FlushAsync();
            }
            catch { }
        });
    }

    private async void TglStartupItem_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Wpf.Ui.Controls.ToggleSwitch toggle || toggle.Tag is not SystemStartupItemsManager.ManagedStartupItem item)
            return;

        bool targetState = toggle.IsChecked ?? false;
        toggle.IsEnabled = false;
        try
        {
            bool toggleResult = await Task.Run(() => _startupManager.ToggleItemEnabled(item, targetState));

            bool verified;
            if (string.Equals(item.ScopeScene, "Scene_GuidBlocked", StringComparison.OrdinalIgnoreCase))
            {
                // GuidBlocked 场景：IsEnabled 代表是否仍存在 Shell Extensions\Blocked 中，已由 ToggleItemEnabled 完成写删验证
                verified = toggleResult;
            }
            else
            {
                var target = NativeSecurityExtractor.BuildTargetProgramFeatures(
                    item.Category,
                    item.LocationKey,
                    item.CommandOrPath);
                var expectedAction = targetState ? InterceptionAction.Allow : InterceptionAction.RollbackToDisabled;

                verified = toggleResult && await Task.Run(() => PrivilegedRollbackEngine.VerifyRollbackState(target, expectedAction));
                if (!verified)
                {
                    verified = await VerifyOperationWithRetryAsync(
                        item.DisplayName,
                        item.LocationKey,
                        () => _startupManager.ToggleItemEnabled(item, targetState),
                        () => PrivilegedRollbackEngine.VerifyRollbackState(target, expectedAction));
                }
            }

            if (!verified)
            {
                // 操作未生效时必须把绑定属性与开关 UI 立即回退为真实系统状态，防止下次刷新前呈现假“开启”
                item.IsEnabled = !targetState;
                item.StatusSummary = !targetState ? "已启用" : "已禁止/屏蔽";
                toggle.IsChecked = !targetState;
            }
        }
        finally
        {
            toggle.IsEnabled = true;
        }

        await RefreshAllDataAsync();
    }

    private async void CmbStartupItemState_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (sender is not System.Windows.Controls.ComboBox combo ||
            combo.Tag is not SystemStartupItemsManager.ManagedStartupItem item ||
            combo.SelectedItem is not SystemStartupItemsManager.ManagedStartupItem.StartupStateOption option)
        {
            return;
        }

        if (option.Action == item.CurrentStateAction)
            return;

        combo.IsEnabled = false;
        var previousAction = item.CurrentStateAction;
        try
        {
            bool opOk = await Task.Run(() => _startupManager.SetItemAction(item, option.Action));
            var target = NativeSecurityExtractor.BuildTargetProgramFeatures(
                item.Category,
                item.LocationKey,
                item.CommandOrPath);

            bool VerifyExact()
            {
                if (item.Category is MonitorCategory.Win32Service or MonitorCategory.KernelDriver)
                    return PrivilegedRollbackEngine.VerifyServiceStartType(item.LocationKey, option.StartType, option.DelayedAuto);
                return PrivilegedRollbackEngine.VerifyRollbackState(target, option.Action);
            }

            bool verified = opOk && await Task.Run(VerifyExact);
            if (!verified)
            {
                verified = await VerifyOperationWithRetryAsync(
                    item.DisplayName,
                    item.LocationKey,
                    () => _startupManager.SetItemAction(item, option.Action),
                    VerifyExact);
            }

            if (!verified)
            {
                item.CurrentStateAction = previousAction;
                combo.SelectedItem = item.SelectedStateOption;
            }
        }
        finally
        {
            combo.IsEnabled = true;
        }

        await RefreshAllDataAsync();
    }

    private SystemStartupItemsManager.ManagedStartupItem? _currentDetailItem;

    private void BtnOpenLocation_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Wpf.Ui.Controls.Button btn || btn.Tag is not SystemStartupItemsManager.ManagedStartupItem item)
            return;

        OpenItemDetailDialog(item);
    }

    private void OpenItemDetailDialog(SystemStartupItemsManager.ManagedStartupItem item)
    {
        _currentDetailItem = item;
        string srcProc = !string.IsNullOrWhiteSpace(item.SourceProcess)
            ? item.SourceProcess
            : _sqliteRepo.GetItemProvenance(item.LocationKey);
        item.SourceProcess = srcProc;

        TxtItemDetailTitle.Text = item.DisplayName;
        TxtItemDetailCategory.Text = item.CategoryName;
        TxtItemDetailPublisher.Text = string.IsNullOrWhiteSpace(item.Publisher) ? "未知发布者" : item.Publisher;
        TxtItemDetailStatus.Text = item.StatusSummary;
        if (PanelItemDetailSourceProcess != null && TxtItemDetailSourceProcess != null)
        {
            if (!string.IsNullOrWhiteSpace(srcProc))
            {
                TxtItemDetailSourceProcess.Text = srcProc;
                PanelItemDetailSourceProcess.Visibility = Visibility.Visible;
            }
            else
            {
                PanelItemDetailSourceProcess.Visibility = Visibility.Collapsed;
            }
        }
        TxtItemDetailCommand.Text = string.IsNullOrWhiteSpace(item.CommandOrPath) ? "(无关联命令行)" : item.CommandOrPath;
        TxtItemDetailLocation.Text = string.IsNullOrWhiteSpace(item.LocationKey) ? "(无注册表或存储位置)" : ShellNavigationHelper.FormatForRegeditDisplay(item.LocationKey);
        if (BtnItemDetailManage != null)
        {
            BtnItemDetailManage.Visibility = item.Category is MonitorCategory.Win32Service
                                                             or MonitorCategory.ScheduledTask
                                                             or MonitorCategory.StartupItem
                ? Visibility.Visible
                : Visibility.Collapsed;
        }
        DialogItemDetailHost.Visibility = Visibility.Visible;
    }

    private void BtnItemDetailOpenFile_Click(object sender, RoutedEventArgs e)
    {
        if (_currentDetailItem == null) return;
        ShellNavigationHelper.OpenFileLocationOrFallback(_currentDetailItem.CommandOrPath, _currentDetailItem.LocationKey, _currentDetailItem.Category);
    }

    private void BtnItemDetailOpenLocation_Click(object sender, RoutedEventArgs e)
    {
        if (_currentDetailItem == null) return;
        ShellNavigationHelper.LocateStorageLocation(_currentDetailItem.LocationKey, _currentDetailItem.CommandOrPath, _currentDetailItem.Category);
    }

    private void BtnItemDetailManage_Click(object sender, RoutedEventArgs e)
    {
        if (_currentDetailItem == null) return;
        string leaf = PrivilegedRollbackEngine.ExtractLeafKeyName(
            !string.IsNullOrWhiteSpace(_currentDetailItem.LocationKey)
                ? _currentDetailItem.LocationKey
                : _currentDetailItem.DisplayName);
        if (!string.IsNullOrWhiteSpace(leaf))
        {
            try { System.Windows.Clipboard.SetText(leaf); } catch { }
        }
        ShellNavigationHelper.OpenManagementConsole(_currentDetailItem.Category, _currentDetailItem.LocationKey, _currentDetailItem.CommandOrPath);
    }

    private void BtnItemDetailCopyAiPrompt_Click(object sender, RoutedEventArgs e)
    {
        if (_currentDetailItem == null) return;
        string? scene = _currentDetailItem.Category is MonitorCategory.ClassicContextMenu or MonitorCategory.ModernContextMenu
            ? ContextMenuSceneHelper.DescribeScene(_currentDetailItem.Category, _currentDetailItem.LocationKey, _currentDetailItem.ScopeScene)
            : null;
        string? srcProc = !string.IsNullOrWhiteSpace(_currentDetailItem.SourceProcess)
            ? _currentDetailItem.SourceProcess
            : _sqliteRepo.GetItemProvenance(_currentDetailItem.LocationKey);
        var info = new ShellNavigationHelper.AiPromptItemInfo(
            _currentDetailItem.CategoryName,
            _currentDetailItem.DisplayName,
            _currentDetailItem.Publisher,
            _currentDetailItem.CommandOrPath,
            _currentDetailItem.LocationKey,
            scene,
            string.IsNullOrWhiteSpace(_currentDetailItem.Clsid) ? null : _currentDetailItem.Clsid,
            string.IsNullOrWhiteSpace(srcProc) ? null : srcProc);
        string prompt = ShellNavigationHelper.BuildAiAgentPrompt(info);
        if (string.IsNullOrWhiteSpace(prompt)) return;

        try
        {
            System.Windows.Clipboard.SetText(prompt);
            if (_detailCopyFeedbackTimer == null)
            {
                _detailCopyFeedbackTimer = new System.Windows.Threading.DispatcherTimer
                {
                    Interval = TimeSpan.FromMilliseconds(1500)
                };
                _detailCopyFeedbackTimer.Tick += (_, _) =>
                {
                    _detailCopyFeedbackTimer?.Stop();
                    BtnItemDetailCopyAiPrompt.Content = "复制 AI 提示词";
                };
            }
            else
            {
                _detailCopyFeedbackTimer.Stop();
            }

            BtnItemDetailCopyAiPrompt.Content = "已复制 ✓";
            _detailCopyFeedbackTimer.Start();
        }
        catch { }
    }

    private void BtnItemDetailClose_Click(object sender, RoutedEventArgs e)
    {
        DialogItemDetailHost.Visibility = Visibility.Collapsed;
        _currentDetailItem = null;
    }

    private async void BtnDeleteItem_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Wpf.Ui.Controls.Button btn || btn.Tag is not SystemStartupItemsManager.ManagedStartupItem item)
            return;

        if (item.Category == MonitorCategory.KernelDriver)
        {
            await ShowWinUiInfoDialogAsync("安全限制", "为保护系统稳定性，内核驱动仅支持设为手动或禁止，不可删除。");
            return;
        }

        bool confirm = await ShowWinUiConfirmDialogAsync(
            "删除项目确认",
            $"确定要删除「{item.DisplayName}」吗？\n位置：{item.LocationKey}",
            "删除",
            "取消");

        if (confirm)
        {
            _startupManager.DeleteItem(item);
            await RefreshAllDataAsync();
        }
    }

    #region Context Menu Deep Analysis & More Actions (ContextMenuManager Alignment)

    private SystemStartupItemsManager.ManagedStartupItem? _currentAnalyzedItem;
    private SystemStartupItemsManager.ManagedStartupItem? _currentEditingNoteItem;

    private void BtnAnalyzeItem_Click(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement elem && elem.Tag is SystemStartupItemsManager.ManagedStartupItem item)
        {
            OpenDeepAnalysisDialog(item);
        }
    }

    private void MenuAnalyze_Click(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement elem && elem.Tag is SystemStartupItemsManager.ManagedStartupItem item)
        {
            OpenDeepAnalysisDialog(item);
        }
    }

    private async void OpenDeepAnalysisDialog(SystemStartupItemsManager.ManagedStartupItem item)
    {
        _currentAnalyzedItem = item;

        string clsid = item.Clsid;
        if (string.IsNullOrEmpty(clsid) && item.LocationKey.Contains("shellex", StringComparison.OrdinalIgnoreCase))
        {
            clsid = ResolveClsidFromRegistryLocation(item.LocationKey);
            if (!string.IsNullOrEmpty(clsid)) item.Clsid = clsid;
        }

        string publisher = item.Publisher;
        if (string.IsNullOrWhiteSpace(publisher) || publisher == "未知发布者" || publisher == "系统拦截暂存" || publisher == "未知厂商")
        {
            (publisher, _, _) = SystemStartupItemsManager.ExtractPublisherDetails(item.CommandOrPath);
        }

        string path = ShellNavigationHelper.ResolvePhysicalFilePath(item.CommandOrPath);
        bool fileExists = !string.IsNullOrEmpty(path) && File.Exists(path);

        TxtAnalyzeTitle.Text = item.DisplayName;
        TxtAnalyzeScene.Text = !string.IsNullOrEmpty(clsid) ? "Shell Extension" : item.CategoryName;
        TxtAnalyzeClsid.Text = string.IsNullOrEmpty(clsid) ? "(未指定 CLSID)" : clsid;
        TxtAnalyzeDllPath.Text = string.IsNullOrEmpty(item.CommandOrPath)
            ? "(无关联模块路径)"
            : (fileExists ? item.CommandOrPath : $"{item.CommandOrPath}（文件缺失）");
        TxtAnalyzeRegPath.Text = string.IsNullOrEmpty(item.LocationKey) ? "-" : item.LocationKey;
        TxtAnalyzePublisher.Text = publisher;

        TxtAnalyzeProbeBadge.Text = !string.IsNullOrEmpty(clsid) ? "正在探测..." : "单个处理程序";
        ListAnalyzeMenuItems.ItemsSource = new[]
        {
            new AnalyzedMenuNode { Text = !string.IsNullOrEmpty(clsid) ? "正在沙盒中解析菜单项..." : "非 COM 外壳扩展（直接命令式菜单项）" }
        };

        DialogDeepAnalysisHost.Visibility = Visibility.Visible;

        if (!string.IsNullOrEmpty(clsid))
        {
            var probed = await ContextMenuManagerEngine.AnalyzeShellExtensionMenuAsync(clsid, item.ScopeScene);
            if (_currentAnalyzedItem != item) return;

            if (probed.Count > 0)
            {
                TxtAnalyzeProbeBadge.Text = $"完整菜单探测 ({probed.Count})";
                ListAnalyzeMenuItems.ItemsSource = probed.Select(p => new AnalyzedMenuNode
                {
                    Text = p.Text,
                    Verb = p.Verb,
                    IndentMargin = new Thickness(p.Depth * 16 + 4, 3, 4, 3)
                }).ToList();
            }
            else
            {
                TxtAnalyzeProbeBadge.Text = "单个处理程序";
                ListAnalyzeMenuItems.ItemsSource = new[]
                {
                    new AnalyzedMenuNode { Text = "未在沙盒中枚举到静态菜单项（可能为自绘菜单或需要特定文件上下文）" }
                };
            }
        }
    }

    private void BtnAnalyzeClose_Click(object sender, RoutedEventArgs e)
    {
        DialogDeepAnalysisHost.Visibility = Visibility.Collapsed;
        _currentAnalyzedItem = null;
    }

    private void BtnAnalyzeOpenExplorer_Click(object sender, RoutedEventArgs e)
    {
        if (_currentAnalyzedItem != null)
        {
            ShellNavigationHelper.OpenFileLocationOrFallback(_currentAnalyzedItem.CommandOrPath, _currentAnalyzedItem.LocationKey, _currentAnalyzedItem.Category);
        }
    }

    private void BtnAnalyzeOpenReg_Click(object sender, RoutedEventArgs e)
    {
        if (_currentAnalyzedItem != null)
        {
            ShellNavigationHelper.LocateStorageLocation(_currentAnalyzedItem.LocationKey, _currentAnalyzedItem.CommandOrPath, _currentAnalyzedItem.Category);
        }
    }

    private void BtnAnalyzeProperties_Click(object sender, RoutedEventArgs e)
    {
        if (_currentAnalyzedItem != null)
        {
            if (!ShellNavigationHelper.ShowFileProperties(_currentAnalyzedItem.CommandOrPath))
            {
                _ = ShowWinUiInfoDialogAsync("文件不存在", $"未找到目标物理文件：{_currentAnalyzedItem.CommandOrPath}");
            }
        }
    }

    private void BtnAnalyzeWebSearch_Click(object sender, RoutedEventArgs e)
    {
        if (_currentAnalyzedItem != null)
        {
            ShellNavigationHelper.SearchOnline(_currentAnalyzedItem.DisplayName, _currentAnalyzedItem.Publisher);
        }
    }

    private void BtnMoreActions_Click(object sender, RoutedEventArgs e)
    {
        if (sender is System.Windows.Controls.Button btn && btn.ContextMenu != null)
        {
            btn.ContextMenu.PlacementTarget = btn;
            btn.ContextMenu.Placement = System.Windows.Controls.Primitives.PlacementMode.Bottom;
            btn.ContextMenu.IsOpen = true;
        }
    }

    private void MenuManageApp_Click(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement elem && elem.Tag is SystemStartupItemsManager.ManagedStartupItem item)
        {
            string resolved = ShellNavigationHelper.ResolvePhysicalFilePath(item.CommandOrPath);
            string filterTerm = AppGroupingHelper.ExtractAppSearchKeyword(
                item.DisplayName,
                !string.IsNullOrEmpty(resolved) ? resolved : item.CommandOrPath,
                item.LocationKey,
                item.Publisher,
                item.Clsid);

            NavigateToContextMenuByApp(filterTerm);
        }
    }

    private void MenuAuditManageApp_Click(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement elem && elem.Tag is PendingAuditItem audit)
        {
            string resolved = ShellNavigationHelper.ResolvePhysicalFilePath(audit.CommandOrPath);
            string filterTerm = AppGroupingHelper.ExtractAppSearchKeyword(
                audit.DisplayName,
                !string.IsNullOrEmpty(resolved) ? resolved : audit.CommandOrPath,
                audit.LocationKey,
                audit.RawItem?.Publisher ?? string.Empty,
                audit.Clsid);

            NavigateToContextMenuByApp(filterTerm);
        }
    }

    private void NavigateToContextMenuByApp(string searchTerm)
    {
        SwitchToPage("PageContextMenu");
        if (NavContextMenu != null) NavContextMenu.IsChecked = true;
        ToggleContextMenuSubMenu(expand: true);

        _currentClassicScene = string.Empty;
        _currentClassicFilter = "ByApp";
        if (SubNavContextByApp != null) SubNavContextByApp.IsChecked = true;
        TxtSearchClassicMenu.Text = searchTerm;
        _currentClassicSearchTerm = searchTerm.Trim();
        ApplyClassicMenuFilter();
        PlayTabSwitchAnimation(ContextMenuByAppScrollViewer);
    }

    private async void MenuDelete_Click(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement elem && elem.Tag is SystemStartupItemsManager.ManagedStartupItem item)
        {
            bool confirm = await ShowWinUiConfirmDialogAsync("删除右键菜单项", $"确定要删除右键菜单项「{item.DisplayName}」吗？\n删除后可在日志与规则中查看记录。", "删除", "取消");
            if (confirm)
            {
                _startupManager.DeleteItem(item);
                await RefreshAllDataAsync();
            }
        }
    }

    private void MenuEditNote_Click(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement elem && elem.Tag is SystemStartupItemsManager.ManagedStartupItem item)
        {
            _currentEditingNoteItem = item;
            TxtEditNoteItemName.Text = item.DisplayName;
            TxtEditNoteInput.Text = _sqliteRepo.GetItemNote(item.LocationKey);
            DialogEditNoteHost.Visibility = Visibility.Visible;
        }
    }

    private async void BtnSaveNote_Click(object sender, RoutedEventArgs e)
    {
        if (_currentEditingNoteItem == null)
        {
            DialogEditNoteHost.Visibility = Visibility.Collapsed;
            return;
        }

        try
        {
            string note = TxtEditNoteInput.Text?.Trim() ?? string.Empty;
            _sqliteRepo.SaveItemNote(_currentEditingNoteItem.LocationKey, note);
            _currentEditingNoteItem.Note = note;
        }
        catch { }

        DialogEditNoteHost.Visibility = Visibility.Collapsed;
        _currentEditingNoteItem = null;
        await RefreshAllDataAsync();
    }

    private void BtnCancelNote_Click(object sender, RoutedEventArgs e)
    {
        DialogEditNoteHost.Visibility = Visibility.Collapsed;
        _currentEditingNoteItem = null;
    }

    private void MenuSearchWeb_Click(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement elem && elem.Tag is SystemStartupItemsManager.ManagedStartupItem item)
        {
            ShellNavigationHelper.SearchOnline(item.DisplayName, item.Publisher);
        }
    }

    private void MenuProperties_Click(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement elem && elem.Tag is SystemStartupItemsManager.ManagedStartupItem item)
        {
            if (!ShellNavigationHelper.ShowFileProperties(item.CommandOrPath))
            {
                _ = ShowWinUiInfoDialogAsync("文件不存在", $"未找到目标物理文件：{item.CommandOrPath}");
            }
        }
    }

    private void MenuOpenFileLocation_Click(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement elem && elem.Tag is SystemStartupItemsManager.ManagedStartupItem item)
        {
            ShellNavigationHelper.OpenFileLocationOrFallback(item.CommandOrPath, item.LocationKey, item.Category);
        }
    }

    private void MenuOpenRegLocation_Click(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement elem && elem.Tag is SystemStartupItemsManager.ManagedStartupItem item)
        {
            ShellNavigationHelper.LocateStorageLocation(item.LocationKey, item.CommandOrPath, item.Category);
        }
    }

    private async void MenuExportReg_Click(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement elem && elem.Tag is SystemStartupItemsManager.ManagedStartupItem item)
        {
            try
            {
                string safeName = Path.GetInvalidFileNameChars().Aggregate(item.DisplayName, (c, invalid) => c.Replace(invalid, '_'));
                string desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
                string exportFile = Path.Combine(desktop, $"{safeName}_Backup.reg");
                string regPath = ShellNavigationHelper.NormalizeFullRegistryPath(item.LocationKey);
                using var proc = Process.Start(new ProcessStartInfo
                {
                    FileName = "reg.exe",
                    Arguments = $"export \"{regPath}\" \"{exportFile}\" /y",
                    CreateNoWindow = true,
                    UseShellExecute = false
                });
                proc?.WaitForExit();
                await ShowWinUiInfoDialogAsync("注册表已导出", $"已导出至桌面：\n{exportFile}");
            }
            catch (Exception ex)
            {
                await ShowWinUiInfoDialogAsync("导出失败", $"导出注册表时出错：{ex.Message}");
            }
        }
    }

    private void MenuOpenClsidLocation_Click(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement elem && elem.Tag is SystemStartupItemsManager.ManagedStartupItem item && !string.IsNullOrEmpty(item.Clsid))
        {
            ShellNavigationHelper.LocateInRegistry($@"HKEY_CLASSES_ROOT\CLSID\{item.Clsid}");
        }
    }

    private static void LocateFileInExplorer(string? targetPath)
    {
        ShellNavigationHelper.OpenFileLocationOrFallback(targetPath, null, MonitorCategory.StartupItem);
    }

    private static void LocateInRegistry(string? regPath)
    {
        ShellNavigationHelper.LocateInRegistry(regPath);
    }

    private static void ShowFileProperties(string filePath)
    {
        ShellNavigationHelper.ShowFileProperties(filePath);
    }

    #endregion

    #endregion

    #region Audit Center Actions (Approve / Manual / Block / Delete / Persist / Batch)

    private bool ExecuteAuditActionLocally(PendingAuditItem audit, InterceptionAction action)
    {
        BinaryPipeSerializer.NotifyServiceSuppressSelfMutation(
            audit.LocationKey,
            audit.Category,
            audit.CommandOrPath,
            15.0);

        bool enable = action is InterceptionAction.Allow or InterceptionAction.RollbackToDemand or InterceptionAction.RollbackToDelayedAuto;
        if (action == InterceptionAction.DeleteEntry)
        {
            if (audit.Category == MonitorCategory.KernelDriver) return false;
            if (audit.RawItem != null) return _startupManager.DeleteItem(audit.RawItem);
            var dummy = NativeSecurityExtractor.BuildTargetProgramFeatures(audit.Category, audit.LocationKey, audit.CommandOrPath);
            return PrivilegedRollbackEngine.ExecuteRollback(dummy, InterceptionAction.DeleteEntry);
        }

        if (audit.RawItem != null)
        {
            return _startupManager.SetItemAction(audit.RawItem, action);
        }

        if (audit.Category is MonitorCategory.Win32Service or MonitorCategory.KernelDriver)
        {
            bool isDriver = audit.Category == MonitorCategory.KernelDriver;
            uint startType = action switch
            {
                InterceptionAction.RollbackToDemand => 3u,
                InterceptionAction.RollbackToDisabled => 4u,
                _ => 2u
            };
            return PrivilegedRollbackEngine.RollbackServiceOrDriverStartType(
                audit.LocationKey,
                startType,
                isDriver,
                action == InterceptionAction.RollbackToDelayedAuto && !isDriver);
        }

        if (audit.IsContextMenu)
        {
            var cmEngine = new ContextMenuManagerEngine();
            return cmEngine.SetContextMenuItemEnabledState(new ContextMenuItemEntry
            {
                IdKey = audit.Clsid,
                DisplayTitle = audit.DisplayName,
                MenuCategory = audit.Category,
                ScopeScene = audit.MenuSceneText,
                RegistryPath = audit.LocationKey,
                Clsid = audit.Clsid,
                TargetBinaryOrCommand = audit.CommandOrPath
            }, enable: enable);
        }

        var target = NativeSecurityExtractor.BuildTargetProgramFeatures(audit.Category, audit.LocationKey, audit.CommandOrPath);
        return action == InterceptionAction.Allow
            ? PrivilegedRollbackEngine.RestoreItemEnabled(target)
            : PrivilegedRollbackEngine.ExecuteRollback(target, action);
    }

    private void ResolveAuditRecordAndRemoveFromView(PendingAuditItem audit, string resolvedLabel)
    {
        try
        {
            _sqliteRepo.ResolvePendingAuditLogs(audit.LocationKey, resolvedLabel);
            if (audit.RawLog != null &&
                !string.Equals(audit.RawLog.LocationKey, audit.LocationKey, StringComparison.OrdinalIgnoreCase))
            {
                _sqliteRepo.ResolvePendingAuditLogs(audit.RawLog.LocationKey, resolvedLabel);
            }
        }
        catch { }

        _allAuditItems.Remove(audit);
        _displayedAuditItems.Remove(audit);
        TxtPendingCount.Text = _allAuditItems.Count.ToString();
        BadgePendingCount.Visibility = _allAuditItems.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
        TxtPendingSummary.Text = $"共有 {_allAuditItems.Count} 项待审核";
        UpdateAuditSelectionToolbar();
    }

    private void BtnAuditSelectAll_Click(object sender, RoutedEventArgs e)
    {
        if (_displayedAuditItems.Count == 0) return;
        bool anySelected = _displayedAuditItems.Any(x => x.IsSelected);
        if (!anySelected)
        {
            foreach (var item in _displayedAuditItems)
                item.IsSelected = true;
        }
        else
        {
            // “全选”在有选中项时变为“反选”，点击对全部勾选状态取反
            foreach (var item in _displayedAuditItems)
                item.IsSelected = !item.IsSelected;
        }
        UpdateAuditSelectionToolbar();
    }

    private async void BtnBatchApproveSelected_Click(object sender, RoutedEventArgs e)
    {
        var items = _displayedAuditItems.Where(x => x.IsSelected).ToList();
        if (items.Count == 0)
        {
            await ShowWinUiInfoDialogAsync("提示", "请先勾选需要放行的待审核项目。");
            return;
        }

        bool confirm = await ShowWinUiConfirmDialogAsync(
            "放行确认",
            $"确定要放行并恢复已勾选的 {items.Count} 项待审核条目吗？",
            "放行",
            "取消");

        if (!confirm) return;

        var failed = new List<string>();
        foreach (var audit in items)
        {
            ExecuteAuditActionLocally(audit, InterceptionAction.Allow);
        }

        foreach (var audit in items)
        {
            var target = NativeSecurityExtractor.BuildTargetProgramFeatures(audit.Category, audit.LocationKey, audit.CommandOrPath);
            bool ok = await VerifyOperationWithRetryAsync(
                audit.DisplayName,
                audit.LocationKey,
                () => ExecuteAuditActionLocally(audit, InterceptionAction.Allow),
                () => PrivilegedRollbackEngine.VerifyRollbackState(target, InterceptionAction.Allow),
                showAlertOnFailure: false);
            if (ok)
                ResolveAuditRecordAndRemoveFromView(audit, "已审核放行");
            else
                failed.Add(audit.DisplayName);
        }

        await RefreshAllDataAsync();
        if (failed.Count > 0)
            await ShowWinUiInfoDialogAsync("部分项目未生效", $"以下项目经重试后仍未生效，请手动核查：\n{string.Join("\n", failed)}");
        else
            await ShowWinUiInfoDialogAsync("放行完成", $"已放行所选 {items.Count} 项并确认状态生效。");
    }

    private async void BtnBatchBlockSelected_Click(object sender, RoutedEventArgs e)
    {
        var items = _displayedAuditItems.Where(x => x.IsSelected).ToList();
        if (items.Count == 0)
        {
            await ShowWinUiInfoDialogAsync("提示", "请先勾选需要阻止的待审核项目。");
            return;
        }

        bool confirm = await ShowWinUiConfirmDialogAsync(
            "阻止确认",
            $"确定要阻止并禁止已勾选的 {items.Count} 项待审核条目吗？",
            "阻止",
            "取消");

        if (!confirm) return;

        var failed = new List<string>();
        foreach (var audit in items)
        {
            ExecuteAuditActionLocally(audit, InterceptionAction.RollbackToDisabled);
        }

        foreach (var audit in items)
        {
            var target = NativeSecurityExtractor.BuildTargetProgramFeatures(audit.Category, audit.LocationKey, audit.CommandOrPath);
            bool ok = await VerifyOperationWithRetryAsync(
                audit.DisplayName,
                audit.LocationKey,
                () => ExecuteAuditActionLocally(audit, InterceptionAction.RollbackToDisabled),
                () => PrivilegedRollbackEngine.VerifyRollbackState(target, InterceptionAction.RollbackToDisabled),
                showAlertOnFailure: false);
            if (ok)
                ResolveAuditRecordAndRemoveFromView(audit, "已审核阻止");
            else
                failed.Add(audit.DisplayName);
        }

        await RefreshAllDataAsync();
        if (failed.Count > 0)
            await ShowWinUiInfoDialogAsync("部分项目未生效", $"以下项目经重试后仍未生效，请手动核查：\n{string.Join("\n", failed)}");
        else
            await ShowWinUiInfoDialogAsync("阻止完成", $"已禁止所选 {items.Count} 项并确认状态生效。");
    }

    private SystemStartupItemsManager.ManagedStartupItem BuildTempManagedItemFromAudit(PendingAuditItem audit)
    {
        return audit.RawItem ?? new SystemStartupItemsManager.ManagedStartupItem
        {
            DisplayName = audit.DisplayName,
            Publisher = audit.Publisher,
            HasSignature = audit.HasSignature,
            CommandOrPath = audit.CommandOrPath,
            LocationKey = audit.LocationKey,
            Category = audit.Category,
            CategoryName = audit.HasMenuScene ? audit.MenuSceneText : audit.CategoryName,
            CategoryIcon = audit.CategoryIcon,
            Clsid = audit.Clsid,
            ScopeScene = audit.MenuSceneText,
            IsEnabled = false,
            StatusSummary = audit.AuditSource
        };
    }

    private void BtnAuditAnalyzeItem_Click(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: PendingAuditItem audit })
        {
            OpenDeepAnalysisDialog(BuildTempManagedItemFromAudit(audit));
        }
    }

    private void BtnAuditDetailItem_Click(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: PendingAuditItem audit })
        {
            OpenItemDetailDialog(BuildTempManagedItemFromAudit(audit));
        }
    }

    private void MenuAuditOpenFile_Click(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: PendingAuditItem audit })
        {
            ShellNavigationHelper.OpenFileLocationOrFallback(audit.CommandOrPath, audit.LocationKey, audit.Category);
        }
    }

    private void MenuAuditOpenReg_Click(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: PendingAuditItem audit })
        {
            ShellNavigationHelper.LocateStorageLocation(audit.LocationKey, audit.CommandOrPath, audit.Category);
        }
    }

    private void MenuAuditProperties_Click(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: PendingAuditItem audit })
        {
            if (!ShellNavigationHelper.ShowFileProperties(audit.CommandOrPath))
            {
                _ = ShowWinUiInfoDialogAsync("文件不存在", $"未找到目标物理文件：{audit.CommandOrPath}");
            }
        }
    }

    private void MenuAuditSearchWeb_Click(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: PendingAuditItem audit })
        {
            ShellNavigationHelper.SearchOnline(audit.DisplayName, audit.Publisher);
        }
    }

    private void MenuAuditOpenClsid_Click(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: PendingAuditItem audit } && !string.IsNullOrEmpty(audit.Clsid))
        {
            ShellNavigationHelper.LocateInRegistry($@"HKEY_CLASSES_ROOT\CLSID\{audit.Clsid}");
        }
    }

    private async Task ExecuteSingleAuditDisposalAsync(PendingAuditItem audit, InterceptionAction action, string resolvedLabel)
    {
        ExecuteAuditActionLocally(audit, action);
        var target = NativeSecurityExtractor.BuildTargetProgramFeatures(audit.Category, audit.LocationKey, audit.CommandOrPath);
        bool ok = await VerifyOperationWithRetryAsync(
            audit.DisplayName,
            audit.LocationKey,
            () => ExecuteAuditActionLocally(audit, action),
            () => PrivilegedRollbackEngine.VerifyRollbackState(target, action));

        if (ok)
            ResolveAuditRecordAndRemoveFromView(audit, resolvedLabel);

        await RefreshAllDataAsync();
    }

    private async void MenuAuditApproveItem_Click(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: PendingAuditItem audit })
            await ExecuteSingleAuditDisposalAsync(audit, InterceptionAction.Allow, "已审核放行");
    }

    private async void MenuAuditSetDelayedItem_Click(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: PendingAuditItem audit })
            await ExecuteSingleAuditDisposalAsync(audit, InterceptionAction.RollbackToDelayedAuto, "已设为延迟启动");
    }

    private async void MenuAuditSetManualItem_Click(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: PendingAuditItem audit })
            await ExecuteSingleAuditDisposalAsync(audit, InterceptionAction.RollbackToDemand, "已设为手动");
    }

    private async void MenuAuditBlockItem_Click(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: PendingAuditItem audit })
            await ExecuteSingleAuditDisposalAsync(audit, InterceptionAction.RollbackToDisabled, "已确认阻止");
    }

    private async void MenuAuditDeleteItem_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not FrameworkElement { Tag: PendingAuditItem audit })
            return;

        if (audit.Category == MonitorCategory.KernelDriver)
        {
            await ShowWinUiInfoDialogAsync("安全限制", "内核驱动仅支持设为手动或禁止，不可删除。");
            return;
        }

        bool confirm = await ShowWinUiConfirmDialogAsync(
            "删除项目确认",
            $"确定要删除待审核项「{audit.DisplayName}」吗？",
            "删除",
            "取消");

        if (confirm)
        {
            await ExecuteSingleAuditDisposalAsync(audit, InterceptionAction.DeleteEntry, "已删除");
        }
    }

    private async void MenuAuditPersistRule_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not FrameworkElement { Tag: PendingAuditItem audit })
            return;

        string targetPath = audit.CommandOrPath;
        string pattern = PathNormalizerAndSimilarity.NormalizeProgramPath(targetPath);
        if (string.IsNullOrEmpty(pattern)) pattern = audit.LocationKey;

        var rule = new RuleRecord
        {
            DisplayName = $"永久阻止 - {audit.DisplayName}",
            NormalizedPath = pattern,
            RawCommand = targetPath,
            LocationKey = audit.LocationKey,
            SignerSubject = audit.Publisher,
            HasSignature = audit.HasSignature,
            Category = audit.Category,
            ActionType = InterceptionAction.RollbackToDisabled,
            RuleMode = RuleMatchMode.PermanentAdaptive,
            ConfidenceThreshold = 85.0f
        };

        try
        {
            _sqliteRepo.InsertOrUpdateRule(rule);
            SyncRulesBinaryAndNotifyService(_sqliteRepo);
            await ShowWinUiInfoDialogAsync("保存成功", $"已为「{audit.DisplayName}」创建永久拦截规则！");
            await RefreshAllDataAsync();
        }
        catch (Exception ex)
        {
            await ShowWinUiInfoDialogAsync("错误", $"保存规则失败: {ex.Message}");
        }
    }

    #endregion

    #region Rules & Settings Actions

    private async void BtnDeleteRule_Click(object sender, RoutedEventArgs e)
    {
        RuleRecord? rule = sender is Wpf.Ui.Controls.Button btn
            ? (btn.Tag is RuleDisplayItem vm ? vm.Rule : btn.Tag as RuleRecord)
            : null;
        if (rule == null)
            return;

        string shortName = rule.DisplayName.Contains('|')
            ? rule.DisplayName.Split('|')[0].Trim()
            : rule.DisplayName;

        bool confirm = await ShowWinUiConfirmDialogAsync(
            "删除规则确认",
            $"确定要删除针对「{shortName}」的拦截规则吗？",
            "确定删除",
            "取消");

        if (confirm)
        {
            try
            {
                _sqliteRepo.DeleteRule(rule.RuleId);
                SyncRulesBinaryAndNotifyService(_sqliteRepo);
                RefreshRules();
            }
            catch { }
        }
    }

    private void CmbTheme_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!_isInitialized) return;
        if (CmbTheme?.SelectedItem is not ComboBoxItem item || item.Tag is not string tag)
            return;

        UserSettingsStore.SetThemePreference(tag);
        ApplyThemePreference(tag);
    }

    private void CmbContextMenuStrategy_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!_isInitialized) return;
        if (CmbContextMenuStrategy?.SelectedItem is not ComboBoxItem item || item.Tag is not string tag)
            return;

        bool promptMode = tag == "PromptImmediate";
        UserSettingsStore.SetContextMenuPromptMode(promptMode);
        UpdateContextMenuNotificationControlState(promptMode);
        SendTogglesUpdateToService();
    }

    private void UpdateContextMenuNotificationControlState(bool promptMode)
    {
        if (ToggleContextMenuNotification == null) return;
        ToggleContextMenuNotification.IsEnabled = !promptMode;
        ToggleContextMenuNotification.IsChecked = promptMode
            ? false
            : UserSettingsStore.GetContextMenuNotificationsEnabled();
        ToggleContextMenuNotification.Opacity = promptMode ? 0.5 : 1.0;
        if (TxtCtxNotifyHint != null)
        {
            TxtCtxNotifyHint.Text = promptMode
                ? "当前已开启“弹窗即时审核”，此通知已自动关闭；切回先拦截模式时将还原原有设置"
                : "先拦截后审核模式下屏蔽新右键菜单时弹出系统通知";
        }
    }

    private void ToggleAutoGameMode_Click(object sender, RoutedEventArgs e)
    {
        SendTogglesUpdateToService();
    }

    #region 顶部全局搜索 (跨自启项与右键菜单、支持分类筛选、不受隐藏系统项限制)

    private static bool ComputeGroupToggleTarget(params System.Windows.Controls.CheckBox?[] children)
        => children.Any(c => c?.IsChecked != true);

    private static void SyncGroupCheckState(System.Windows.Controls.CheckBox? groupBox, params System.Windows.Controls.CheckBox?[] children)
    {
        if (groupBox == null) return;
        int checkedCount = children.Count(c => c?.IsChecked == true);
        groupBox.IsChecked = checkedCount == 0
            ? false
            : (checkedCount == children.Length ? true : null);
    }

    private double GetFullGlobalSearchCardMaxWidth()
        => ActualWidth > 0 ? Math.Clamp(ActualWidth - 48, 380, FullGlobalSearchMaxWidth) : FullGlobalSearchMaxWidth;

    private double GetTargetGlobalSearchCardMaxWidth()
    {
        double fullWidth = GetFullGlobalSearchCardMaxWidth();
        if (_globalSearchCardExpanded)
            return fullWidth;

        return Math.Min(fullWidth, CompactGlobalSearchMaxWidth);
    }

    private double GetFullGlobalSearchCardMaxHeight()
        => ActualHeight > 0 ? Math.Max(280, ActualHeight - 78) : 560;

    private double GetTargetGlobalSearchCardMaxHeight()
    {
        double fullHeight = GetFullGlobalSearchCardMaxHeight();
        if (_globalSearchCardExpanded)
            return fullHeight;

        if (GlobalSearchFilterPanel?.Visibility == Visibility.Visible)
            return Math.Min(fullHeight, 290);

        return Math.Min(fullHeight, CompactGlobalSearchMaxHeight);
    }

    private void AnimateGlobalSearchCardBound(
        DependencyProperty property,
        double currentValue,
        double fallbackValue,
        double targetValue,
        Func<double> getFinalValue)
    {
        if (BorderGlobalSearchCard == null) return;

        if (double.IsNaN(currentValue) || double.IsInfinity(currentValue) || currentValue <= 0)
            currentValue = fallbackValue;

        if (Math.Abs(currentValue - targetValue) <= 1.0)
        {
            BorderGlobalSearchCard.BeginAnimation(property, null);
            BorderGlobalSearchCard.SetValue(property, targetValue);
            return;
        }

        var anim = new DoubleAnimation(currentValue, targetValue, TimeSpan.FromMilliseconds(240))
        {
            EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
        };
        anim.Completed += (_, _) =>
        {
            if (BorderGlobalSearchCard == null) return;
            BorderGlobalSearchCard.BeginAnimation(property, null);
            BorderGlobalSearchCard.SetValue(property, getFinalValue());
        };
        BorderGlobalSearchCard.BeginAnimation(property, anim);
    }

    private void AnimateGlobalSearchCardMaxHeight(double targetMaxHeight)
    {
        if (BorderGlobalSearchCard == null) return;

        double currentHeight = BorderGlobalSearchCard.ActualHeight > 0
            ? BorderGlobalSearchCard.ActualHeight
            : BorderGlobalSearchCard.MaxHeight;
        AnimateGlobalSearchCardBound(
            FrameworkElement.MaxHeightProperty,
            currentHeight,
            CompactGlobalSearchMaxHeight,
            targetMaxHeight,
            GetTargetGlobalSearchCardMaxHeight);
    }

    private void AnimateGlobalSearchCardMaxWidth(double targetMaxWidth)
    {
        if (BorderGlobalSearchCard == null) return;

        double currentWidth = BorderGlobalSearchCard.ActualWidth > 0
            ? BorderGlobalSearchCard.ActualWidth
            : BorderGlobalSearchCard.MaxWidth;
        AnimateGlobalSearchCardBound(
            FrameworkElement.MaxWidthProperty,
            currentWidth,
            CompactGlobalSearchMaxWidth,
            targetMaxWidth,
            GetTargetGlobalSearchCardMaxWidth);
    }

    private void EnsureGlobalSearchCardExpanded()
    {
        if (_globalSearchCardExpanded) return;
        _globalSearchCardExpanded = true;
        AnimateGlobalSearchCardMaxWidth(GetFullGlobalSearchCardMaxWidth());
        AnimateGlobalSearchCardMaxHeight(GetFullGlobalSearchCardMaxHeight());
    }

    private void BorderGlobalSearchCard_PreviewMouseWheel(object sender, System.Windows.Input.MouseWheelEventArgs e)
    {
        if (e.Delta < 0 && !_globalSearchCardExpanded && GlobalSearchOverlay?.Visibility == Visibility.Visible)
        {
            EnsureGlobalSearchCardExpanded();
        }
    }

    private void UpdateGlobalSearchLayoutBounds()
    {
        if (TxtGlobalSearch != null && ActualWidth > 0)
        {
            // 左右各留出品牌标题、筛选按钮与窗口控制按钮安全区，保证搜索框始终在窗口正中不撞边
            double targetWidth = Math.Clamp(ActualWidth - 380, 200, 380);
            if (Math.Abs(TxtGlobalSearch.Width - targetWidth) > 0.5)
                TxtGlobalSearch.Width = targetWidth;
        }
        if (BorderGlobalSearchCard != null)
        {
            if (ActualWidth > 0)
            {
                double maxCardWidth = GetTargetGlobalSearchCardMaxWidth();
                if (Math.Abs(BorderGlobalSearchCard.MaxWidth - maxCardWidth) > 0.5)
                    BorderGlobalSearchCard.MaxWidth = maxCardWidth;
            }
            if (ActualHeight > 0)
            {
                double maxCardHeight = GetTargetGlobalSearchCardMaxHeight();
                if (Math.Abs(BorderGlobalSearchCard.MaxHeight - maxCardHeight) > 0.5)
                    BorderGlobalSearchCard.MaxHeight = maxCardHeight;
            }
        }
    }

    private static bool IsClickInsideInnerButton(DependencyObject? source, DependencyObject stopAt)
    {
        DependencyObject? cur = source;
        while (cur != null && cur != stopAt)
        {
            if (cur is System.Windows.Controls.Primitives.ButtonBase)
                return true;
            cur = VisualTreeHelper.GetParent(cur);
        }
        return false;
    }

    private void TxtGlobalSearch_PreviewMouseLeftButtonDown(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        if (!_isInitialized || TxtGlobalSearch == null) return;
        if (IsClickInsideInnerButton(e.OriginalSource as DependencyObject, TxtGlobalSearch))
        {
            _globalSearchDragPending = false;
            _globalSearchDidDrag = false;
            return;
        }

        _globalSearchPressScreenPoint = TxtGlobalSearch.PointToScreen(e.GetPosition(TxtGlobalSearch));
        _globalSearchDragPending = true;
        _globalSearchDidDrag = false;
    }

    private void TxtGlobalSearch_PreviewMouseMove(object sender, System.Windows.Input.MouseEventArgs e)
    {
        if (!_globalSearchDragPending || TxtGlobalSearch == null) return;
        if (e.LeftButton != System.Windows.Input.MouseButtonState.Pressed)
        {
            _globalSearchDragPending = false;
            return;
        }

        Point currentScreenPoint = TxtGlobalSearch.PointToScreen(e.GetPosition(TxtGlobalSearch));
        double dx = Math.Abs(currentScreenPoint.X - _globalSearchPressScreenPoint.X);
        double dy = Math.Abs(currentScreenPoint.Y - _globalSearchPressScreenPoint.Y);
        if (dx >= SystemParameters.MinimumHorizontalDragDistance || dy >= SystemParameters.MinimumVerticalDragDistance)
        {
            _globalSearchDragPending = false;
            _globalSearchDidDrag = true;
            e.Handled = true;
            try
            {
                System.Windows.Input.Mouse.Capture(null);
                DragMove();
            }
            catch { }
        }
    }

    private void TxtGlobalSearch_PreviewMouseLeftButtonUp(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        bool wasClick = _globalSearchDragPending && !_globalSearchDidDrag;
        _globalSearchDragPending = false;
        _globalSearchDidDrag = false;
        if (!_isInitialized || !wasClick || TxtGlobalSearch == null) return;

        if (!TxtGlobalSearch.IsKeyboardFocusWithin)
        {
            TxtGlobalSearch.Focus();
        }
        if (BtnGlobalSearchFilterToggle != null)
        {
            BtnGlobalSearchFilterToggle.Visibility = Visibility.Visible;
        }
        if (GlobalSearchOverlay != null && GlobalSearchOverlay.Visibility != Visibility.Visible)
        {
            RefreshGlobalSearchResults(forceOpenOverlay: true, resetScroll: true);
        }
    }

    private void TxtGlobalSearch_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
    {
        if (!_isInitialized) return;
        if (!string.IsNullOrEmpty(TxtGlobalSearch?.Text) ||
            (GlobalSearchOverlay != null && GlobalSearchOverlay.Visibility == Visibility.Visible))
        {
            _globalSearchCurrentPage = 1;
            if (BtnGlobalSearchFilterToggle != null)
            {
                BtnGlobalSearchFilterToggle.Visibility = Visibility.Visible;
            }
            RefreshGlobalSearchResults(forceOpenOverlay: true, resetScroll: true);
        }
    }

    private void TxtGlobalSearch_PreviewKeyDown(object sender, System.Windows.Input.KeyEventArgs e)
    {
        if (e.Key == System.Windows.Input.Key.Escape)
        {
            CloseGlobalSearchOverlay(clearQuery: false);
            e.Handled = true;
        }
    }

    private void BtnGlobalSearchFilterToggle_Click(object sender, RoutedEventArgs e)
    {
        if (!_isInitialized || GlobalSearchFilterPanel == null) return;

        bool open = GlobalSearchFilterPanel.Visibility != Visibility.Visible;
        GlobalSearchFilterPanel.Visibility = open ? Visibility.Visible : Visibility.Collapsed;
        if (BtnGlobalSearchFilterToggle != null)
        {
            BtnGlobalSearchFilterToggle.Appearance = open
                ? Wpf.Ui.Controls.ControlAppearance.Primary
                : Wpf.Ui.Controls.ControlAppearance.Secondary;
        }
        if (open && GlobalSearchOverlay != null && GlobalSearchOverlay.Visibility != Visibility.Visible)
        {
            RefreshGlobalSearchResults(forceOpenOverlay: true, resetScroll: true);
        }
        else if (!_globalSearchCardExpanded)
        {
            AnimateGlobalSearchCardMaxHeight(GetTargetGlobalSearchCardMaxHeight());
        }
    }

    private void GlobalSearchFilter_Changed(object sender, RoutedEventArgs e)
    {
        if (!_isInitialized) return;
        _globalSearchCurrentPage = 1;
        SyncGlobalSearchGroupCheckBoxes();
        RefreshGlobalSearchResults(forceOpenOverlay: true, resetScroll: true);
    }

    private void ChkGlobalGroupStartup_Click(object sender, RoutedEventArgs e)
    {
        if (!_isInitialized) return;
        _globalSearchCurrentPage = 1;
        System.Windows.Controls.CheckBox?[] items = [ChkGlobalCatStartupItem, ChkGlobalCatWin32Service, ChkGlobalCatKernelDriver, ChkGlobalCatScheduledTask, ChkGlobalCatWindowsPolicy];
        bool target = ComputeGroupToggleTarget(items);
        foreach (var cb in items)
        {
            if (cb != null) cb.IsChecked = target;
        }
        SyncGlobalSearchGroupCheckBoxes();
        RefreshGlobalSearchResults(forceOpenOverlay: true, resetScroll: true);
    }

    private void ChkGlobalGroupContextMenu_Click(object sender, RoutedEventArgs e)
    {
        if (!_isInitialized) return;
        _globalSearchCurrentPage = 1;
        System.Windows.Controls.CheckBox?[] items = [ChkGlobalCatClassicMenu, ChkGlobalCatModernMenu];
        bool target = ComputeGroupToggleTarget(items);
        foreach (var cb in items)
        {
            if (cb != null) cb.IsChecked = target;
        }
        SyncGlobalSearchGroupCheckBoxes();
        RefreshGlobalSearchResults(forceOpenOverlay: true, resetScroll: true);
    }

    private void SyncGlobalSearchGroupCheckBoxes()
    {
        SyncGroupCheckState(ChkGlobalGroupStartup, ChkGlobalCatStartupItem, ChkGlobalCatWin32Service, ChkGlobalCatKernelDriver, ChkGlobalCatScheduledTask, ChkGlobalCatWindowsPolicy);
        SyncGroupCheckState(ChkGlobalGroupContextMenu, ChkGlobalCatClassicMenu, ChkGlobalCatModernMenu);
    }

    private HashSet<MonitorCategory> GetSelectedGlobalSearchCategories()
    {
        var selected = new HashSet<MonitorCategory>();
        if (ChkGlobalCatStartupItem?.IsChecked ?? true) selected.Add(MonitorCategory.StartupItem);
        if (ChkGlobalCatWin32Service?.IsChecked ?? true) selected.Add(MonitorCategory.Win32Service);
        if (ChkGlobalCatKernelDriver?.IsChecked ?? true) selected.Add(MonitorCategory.KernelDriver);
        if (ChkGlobalCatScheduledTask?.IsChecked ?? true) selected.Add(MonitorCategory.ScheduledTask);
        if (ChkGlobalCatWindowsPolicy?.IsChecked ?? true) selected.Add(MonitorCategory.WindowsPolicy);
        if (ChkGlobalCatClassicMenu?.IsChecked ?? true) selected.Add(MonitorCategory.ClassicContextMenu);
        if (ChkGlobalCatModernMenu?.IsChecked ?? true) selected.Add(MonitorCategory.ModernContextMenu);
        return selected;
    }

    private void GlobalSearchBackdrop_MouseDown(object sender, System.Windows.Input.MouseButtonEventArgs e)
        => CloseGlobalSearchOverlay(clearQuery: false);

    private void GlobalSearchCard_MouseDown(object sender, System.Windows.Input.MouseButtonEventArgs e)
        => e.Handled = true;

    private void CloseGlobalSearchOverlay(bool clearQuery)
    {
        _globalSearchPagerRevealed = false;
        _globalSearchCardExpanded = false;
        if (GlobalSearchOverlay != null)
            GlobalSearchOverlay.Visibility = Visibility.Collapsed;
        if (GlobalSearchFilterPanel != null)
            GlobalSearchFilterPanel.Visibility = Visibility.Collapsed;
        if (GlobalSearchPagerBar != null)
            GlobalSearchPagerBar.Visibility = Visibility.Collapsed;
        if (BorderGlobalSearchCard != null)
        {
            BorderGlobalSearchCard.BeginAnimation(FrameworkElement.MaxWidthProperty, null);
            BorderGlobalSearchCard.BeginAnimation(FrameworkElement.MaxHeightProperty, null);
            BorderGlobalSearchCard.MaxWidth = CompactGlobalSearchMaxWidth;
            BorderGlobalSearchCard.MaxHeight = CompactGlobalSearchMaxHeight;
        }
        if (BtnGlobalSearchFilterToggle != null)
        {
            BtnGlobalSearchFilterToggle.Visibility = Visibility.Collapsed;
            BtnGlobalSearchFilterToggle.Appearance = Wpf.Ui.Controls.ControlAppearance.Secondary;
        }
        if (clearQuery && TxtGlobalSearch != null)
            TxtGlobalSearch.Text = string.Empty;
        if (TxtGlobalSearch?.IsKeyboardFocusWithin == true)
            System.Windows.Input.Keyboard.ClearFocus();
    }

    private void RefreshGlobalSearchResults(bool forceOpenOverlay = false, bool resetScroll = false)
    {
        if (GlobalSearchOverlay == null || TxtGlobalSearch == null) return;

        string query = TxtGlobalSearch.Text?.Trim() ?? string.Empty;
        var allowedCategories = GetSelectedGlobalSearchCategories();
        bool overlayCurrentlyOpen = GlobalSearchOverlay.Visibility == Visibility.Visible;

        // 后台刷新与窗口重新激活仅同步已打开的搜索结果，绝不自动弹出搜索浮层
        if (!overlayCurrentlyOpen && !forceOpenOverlay)
        {
            return;
        }

        var matches = GlobalSearchHelper.SearchItems(
            _allStartupItems,
            _allClassicMenuItems,
            _guidBlockedItems,
            query,
            ToGlobalSearchFields,
            maxResults: int.MaxValue,
            allowedCategories: allowedCategories,
            allowEmptyQueryWhenFiltered: true);

        _allGlobalSearchMatches = matches;

        if (forceOpenOverlay && GlobalSearchOverlay.Visibility != Visibility.Visible)
        {
            _globalSearchCardExpanded = false;
            UpdateGlobalSearchLayoutBounds();
            GlobalSearchOverlay.Visibility = Visibility.Visible;
            if (BtnGlobalSearchFilterToggle != null)
                BtnGlobalSearchFilterToggle.Visibility = Visibility.Visible;
        }

        ApplyGlobalSearchPage(scrollToTop: resetScroll);
    }

    private void ApplyGlobalSearchPage(bool scrollToTop)
    {
        int totalCount = _allGlobalSearchMatches.Count;
        _globalSearchTotalPages = Math.Max(1, (totalCount + GlobalSearchPageSize - 1) / GlobalSearchPageSize);
        _globalSearchCurrentPage = Math.Clamp(_globalSearchCurrentPage, 1, _globalSearchTotalPages);

        if (scrollToTop)
        {
            _globalSearchPagerRevealed = false;
            if (GlobalSearchPagerBar != null)
                GlobalSearchPagerBar.Visibility = Visibility.Collapsed;
        }

        int skip = (_globalSearchCurrentPage - 1) * GlobalSearchPageSize;
        _displayedGlobalSearchItems.Clear();
        for (int i = skip; i < totalCount && i < skip + GlobalSearchPageSize; i++)
        {
            _displayedGlobalSearchItems.Add(_allGlobalSearchMatches[i]);
        }

        if (TxtGlobalSearchEmpty != null)
            TxtGlobalSearchEmpty.Visibility = totalCount == 0 ? Visibility.Visible : Visibility.Collapsed;
        if (ListViewGlobalSearch != null)
        {
            ListViewGlobalSearch.Visibility = totalCount == 0 ? Visibility.Collapsed : Visibility.Visible;
            if (scrollToTop)
            {
                if (FindVisualChild<ScrollViewer>(ListViewGlobalSearch) is { } sv)
                    sv.ScrollToTop();
                else if (_displayedGlobalSearchItems.Count > 0)
                    ListViewGlobalSearch.ScrollIntoView(_displayedGlobalSearchItems[0]);
            }
        }

        RenderGlobalSearchPager();
    }

    private void RenderGlobalSearchPager()
    {
        if (GlobalSearchPagerBar == null || PanelGlobalPageNumbers == null) return;

        if (_globalSearchTotalPages <= 1)
        {
            _globalSearchPagerRevealed = false;
            GlobalSearchPagerBar.Visibility = Visibility.Collapsed;
            PanelGlobalPageNumbers.Children.Clear();
            return;
        }

        GlobalSearchPagerBar.Visibility = _globalSearchPagerRevealed ? Visibility.Visible : Visibility.Collapsed;
        if (BtnGlobalPageFirst != null) BtnGlobalPageFirst.IsEnabled = _globalSearchCurrentPage > 1;
        if (BtnGlobalPagePrev != null) BtnGlobalPagePrev.IsEnabled = _globalSearchCurrentPage > 1;
        if (BtnGlobalPageNext != null) BtnGlobalPageNext.IsEnabled = _globalSearchCurrentPage < _globalSearchTotalPages;
        if (BtnGlobalPageLast != null) BtnGlobalPageLast.IsEnabled = _globalSearchCurrentPage < _globalSearchTotalPages;
        if (TxtGlobalPageInput != null) TxtGlobalPageInput.Text = _globalSearchCurrentPage.ToString();
        if (TxtGlobalPageInfo != null) TxtGlobalPageInfo.Text = $"/ {_globalSearchTotalPages} 页";

        PanelGlobalPageNumbers.Children.Clear();
        foreach (int? slot in GlobalSearchHelper.BuildPaginationSlots(_globalSearchCurrentPage, _globalSearchTotalPages))
        {
            if (slot == null)
            {
                PanelGlobalPageNumbers.Children.Add(new System.Windows.Controls.TextBlock
                {
                    Text = "…",
                    FontSize = 12,
                    VerticalAlignment = VerticalAlignment.Center,
                    Margin = new Thickness(4, 0, 4, 0),
                    Foreground = TryFindResource("TextFillColorSecondaryBrush") as System.Windows.Media.Brush
                });
                continue;
            }

            int pageNum = slot.Value;
            bool isCurrent = pageNum == _globalSearchCurrentPage;
            var btn = new Wpf.Ui.Controls.Button
            {
                Content = pageNum.ToString(),
                Appearance = isCurrent ? Wpf.Ui.Controls.ControlAppearance.Primary : Wpf.Ui.Controls.ControlAppearance.Secondary,
                Padding = new Thickness(8, 0, 8, 0),
                Height = 28,
                MinWidth = 28,
                FontSize = 11.5,
                VerticalContentAlignment = VerticalAlignment.Center,
                Margin = new Thickness(2, 0, 2, 0),
                Tag = pageNum
            };
            btn.Click += (_, _) => NavigateGlobalSearchPage(pageNum);
            PanelGlobalPageNumbers.Children.Add(btn);
        }

        Dispatcher.BeginInvoke(System.Windows.Threading.DispatcherPriority.Loaded, () =>
        {
            if (FindVisualChild<ScrollViewer>(ListViewGlobalSearch) is { } sv)
                SyncGlobalSearchPagerVisibility(sv, verticalChange: 0);
        });
    }

    private void ListViewGlobalSearch_ScrollChanged(object sender, ScrollChangedEventArgs e)
    {
        if (e.OriginalSource is ScrollViewer sv)
        {
            if (!_globalSearchCardExpanded &&
                GlobalSearchOverlay?.Visibility == Visibility.Visible &&
                (e.VerticalChange > 0.1 || sv.VerticalOffset > 0.5))
            {
                EnsureGlobalSearchCardExpanded();
            }
            SyncGlobalSearchPagerVisibility(sv, e.VerticalChange);
        }
    }

    private void SyncGlobalSearchPagerVisibility(ScrollViewer sv, double verticalChange)
    {
        if (GlobalSearchPagerBar == null || _globalSearchTotalPages <= 1 || _displayedGlobalSearchItems.Count == 0 || sv.ViewportHeight <= 0)
            return;

        bool isShortLastPageWithoutScroll = sv.ExtentHeight > 0 &&
            sv.ScrollableHeight <= 0.5 &&
            (_globalSearchCurrentPage == _globalSearchTotalPages || _displayedGlobalSearchItems.Count <= 12);
        bool isScrolledToBottom = sv.ScrollableHeight > 0.5 &&
            sv.VerticalOffset > 0.5 &&
            sv.VerticalOffset >= sv.ScrollableHeight - 0.5;
        bool atBottom = isShortLastPageWithoutScroll || isScrolledToBottom;

        if (!_globalSearchPagerRevealed && atBottom)
        {
            _globalSearchPagerRevealed = true;
            GlobalSearchPagerBar.Visibility = Visibility.Visible;
            if (sv.ScrollableHeight > 0.5)
            {
                Dispatcher.BeginInvoke(System.Windows.Threading.DispatcherPriority.Loaded, () =>
                {
                    if (_globalSearchPagerRevealed)
                        sv.ScrollToEnd();
                });
            }
        }
        else if (_globalSearchPagerRevealed && sv.ScrollableHeight > 0.5 && verticalChange < -0.5 && sv.VerticalOffset < sv.ScrollableHeight - 2.0)
        {
            _globalSearchPagerRevealed = false;
            GlobalSearchPagerBar.Visibility = Visibility.Collapsed;
        }
    }

    private static T? FindVisualChild<T>(DependencyObject? parent) where T : DependencyObject
    {
        if (parent == null) return null;
        int count = VisualTreeHelper.GetChildrenCount(parent);
        for (int i = 0; i < count; i++)
        {
            var child = VisualTreeHelper.GetChild(parent, i);
            if (child is T typed)
                return typed;
            if (FindVisualChild<T>(child) is { } nested)
                return nested;
        }
        return null;
    }

    private void NavigateGlobalSearchPage(int targetPage)
    {
        int clamped = Math.Clamp(targetPage, 1, _globalSearchTotalPages);
        if (clamped == _globalSearchCurrentPage) return;
        _globalSearchCurrentPage = clamped;
        ApplyGlobalSearchPage(scrollToTop: true);
    }

    private void BtnGlobalPageFirst_Click(object sender, RoutedEventArgs e) => NavigateGlobalSearchPage(1);
    private void BtnGlobalPagePrev_Click(object sender, RoutedEventArgs e) => NavigateGlobalSearchPage(_globalSearchCurrentPage - 1);
    private void BtnGlobalPageNext_Click(object sender, RoutedEventArgs e) => NavigateGlobalSearchPage(_globalSearchCurrentPage + 1);
    private void BtnGlobalPageLast_Click(object sender, RoutedEventArgs e) => NavigateGlobalSearchPage(_globalSearchTotalPages);

    private void TxtGlobalPageInput_PreviewTextInput(object sender, System.Windows.Input.TextCompositionEventArgs e)
    {
        e.Handled = string.IsNullOrEmpty(e.Text) || !e.Text.All(char.IsDigit);
    }

    private void TxtGlobalPageInput_KeyDown(object sender, System.Windows.Input.KeyEventArgs e)
    {
        if (e.Key == System.Windows.Input.Key.Enter)
        {
            CommitGlobalSearchPageInput();
            e.Handled = true;
        }
        else if (e.Key == System.Windows.Input.Key.Escape && TxtGlobalPageInput != null)
        {
            TxtGlobalPageInput.Text = _globalSearchCurrentPage.ToString();
            e.Handled = true;
        }
    }

    private void TxtGlobalPageInput_LostFocus(object sender, RoutedEventArgs e)
        => CommitGlobalSearchPageInput();

    private void CommitGlobalSearchPageInput()
    {
        if (TxtGlobalPageInput == null) return;
        if (int.TryParse(TxtGlobalPageInput.Text?.Trim(), out int requestedPage))
        {
            int clamped = Math.Clamp(requestedPage, 1, _globalSearchTotalPages);
            TxtGlobalPageInput.Text = clamped.ToString();
            if (clamped != _globalSearchCurrentPage)
            {
                NavigateGlobalSearchPage(clamped);
            }
        }
        else
        {
            TxtGlobalPageInput.Text = _globalSearchCurrentPage.ToString();
        }
    }

    private static GlobalSearchFields ToGlobalSearchFields(SystemStartupItemsManager.ManagedStartupItem item)
        => new(
            item.Category,
            item.DisplayName,
            item.Publisher,
            item.ProductName,
            item.CommandOrPath,
            item.LocationKey,
            item.ScopeScene,
            item.Clsid,
            item.SourceProcess,
            item.StatusSummary);

    private void NavigateToManagedItem(SystemStartupItemsManager.ManagedStartupItem item, bool openDetail = true)
    {
        var target = GlobalSearchHelper.ResolveNavigationTarget(item.Category, item.LocationKey, item.ScopeScene);
        if (target.MainPageTag == "PageContextMenu")
        {
            if (NavContextMenu != null) NavContextMenu.IsChecked = true;
            if (ContextMenuSubListPanel != null)
            {
                if (ContextMenuSubListPanel.Visibility != Visibility.Visible)
                    ToggleContextMenuSubMenu(expand: true);

                if (!string.IsNullOrEmpty(target.ContextMenuSubTag))
                {
                    foreach (object child in ContextMenuSubListPanel.Children)
                    {
                        if (child is System.Windows.Controls.RadioButton rb &&
                            string.Equals(rb.Tag?.ToString(), target.ContextMenuSubTag, StringComparison.OrdinalIgnoreCase))
                        {
                            rb.IsChecked = true;
                            break;
                        }
                    }

                    if (target.ContextMenuSubTag.StartsWith("Scene_", StringComparison.OrdinalIgnoreCase))
                    {
                        _currentClassicScene = target.ContextMenuSubTag;
                        _currentClassicFilter = target.ContextMenuSubTag;
                    }
                    else
                    {
                        _currentClassicScene = string.Empty;
                        _currentClassicFilter = target.ContextMenuSubTag;
                    }
                }
            }

            if (TxtSearchClassicMenu != null && !string.IsNullOrEmpty(TxtSearchClassicMenu.Text))
            {
                TxtSearchClassicMenu.Text = string.Empty;
                _currentClassicSearchTerm = string.Empty;
            }

            SwitchToPage("PageContextMenu");
            ApplyClassicMenuFilter();

            if (ListViewClassicMenu != null)
            {
                Dispatcher.BeginInvoke(System.Windows.Threading.DispatcherPriority.Loaded, () =>
                {
                    if (ListViewClassicMenu.Items.Contains(item))
                    {
                        ListViewClassicMenu.SelectedItem = item;
                        ListViewClassicMenu.ScrollIntoView(item);
                    }
                });
            }
        }
        else
        {
            if (item.IsMicrosoftOrSystemBuiltIn && TglHideMicrosoft?.IsChecked == true)
            {
                TglHideMicrosoft.IsChecked = false;
                UserSettingsStore.SetHideMicrosoftPreference(false);
            }

            if (NavStartupManager != null) NavStartupManager.IsChecked = true;

            var categoryRadio = item.Category switch
            {
                MonitorCategory.StartupItem => FilterRun,
                MonitorCategory.Win32Service => FilterService,
                MonitorCategory.KernelDriver => FilterDriver,
                MonitorCategory.ScheduledTask => FilterTask,
                MonitorCategory.WindowsPolicy => FilterPolicy,
                _ => FilterAll
            };
            if (categoryRadio != null)
            {
                categoryRadio.IsChecked = true;
                _currentStartupFilter = categoryRadio.Tag?.ToString() ?? "All";
            }
            else if (FilterAll != null)
            {
                FilterAll.IsChecked = true;
                _currentStartupFilter = "All";
            }

            if (TxtSearchStartup != null && !string.IsNullOrEmpty(TxtSearchStartup.Text))
            {
                TxtSearchStartup.Text = string.Empty;
                _currentStartupSearchTerm = string.Empty;
            }

            SwitchToPage("PageStartupManager");
            ApplyStartupFilter();

            if (ListViewStartup != null)
            {
                Dispatcher.BeginInvoke(System.Windows.Threading.DispatcherPriority.Loaded, () =>
                {
                    if (ListViewStartup.Items.Contains(item))
                    {
                        ListViewStartup.SelectedItem = item;
                        ListViewStartup.ScrollIntoView(item);
                    }
                });
            }
        }

        if (openDetail)
        {
            OpenItemDetailDialog(item);
        }
    }

    private void BtnGlobalSearchViewDetail_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not System.Windows.FrameworkElement fe || fe.Tag is not SystemStartupItemsManager.ManagedStartupItem item)
            return;

        CloseGlobalSearchOverlay(clearQuery: false);
        NavigateToManagedItem(item, openDetail: true);
    }

    private async void AuditLogCard_MouseLeftButtonUp(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        if (IsClickInsideButton(e.OriginalSource as DependencyObject))
            return;

        if (sender is not System.Windows.FrameworkElement fe || fe.Tag is not AuditLogRecord log)
            return;

        var matched = GlobalSearchHelper.FindBestMatchingItemForLog(
            log.Category,
            log.LocationKey,
            log.TargetProgram,
            _allStartupItems.Concat(_allClassicMenuItems).Concat(_guidBlockedItems),
            ToGlobalSearchFields);

        if (matched != null)
        {
            NavigateToManagedItem(matched, openDetail: false);
            return;
        }

        string leaf = PrivilegedRollbackEngine.ExtractLeafKeyName(log.LocationKey);
        string displayTarget = !string.IsNullOrWhiteSpace(leaf)
            ? leaf
            : Path.GetFileName(ShellNavigationHelper.ResolvePhysicalFilePath(log.TargetProgram));
        var target = GlobalSearchHelper.ResolveNavigationTarget(log.Category, log.LocationKey, null);

        if (target.MainPageTag == "PageContextMenu")
        {
            if (NavContextMenu != null) NavContextMenu.IsChecked = true;
            ToggleContextMenuSubMenu(expand: true);
            if (!string.IsNullOrEmpty(target.ContextMenuSubTag) && ContextMenuSubListPanel != null)
            {
                foreach (object child in ContextMenuSubListPanel.Children)
                {
                    if (child is System.Windows.Controls.RadioButton rb &&
                        string.Equals(rb.Tag?.ToString(), target.ContextMenuSubTag, StringComparison.OrdinalIgnoreCase))
                    {
                        rb.IsChecked = true;
                        break;
                    }
                }
            }
            SwitchToPage("PageContextMenu");
        }
        else
        {
            if (NavStartupManager != null) NavStartupManager.IsChecked = true;
            SwitchToPage("PageStartupManager");
        }

        await ShowWinUiInfoDialogAsync(
            "未找到对应活动项",
            $"当前活动系统项中未找到「{displayTarget}」（该项可能已被阻止删除或关联软件已卸载）。\n位置：{ShellNavigationHelper.FormatForRegeditDisplay(log.LocationKey)}");
    }

    #endregion

    private void ToggleNotificationSetting_Click(object sender, RoutedEventArgs e)
    {
        if (!_isInitialized) return;
        if (ToggleRuleHitNotification != null)
            UserSettingsStore.SetRuleHitNotificationsEnabled(ToggleRuleHitNotification.IsChecked == true);
        if (ToggleContextMenuNotification != null && ToggleContextMenuNotification.IsEnabled)
            UserSettingsStore.SetContextMenuNotificationsEnabled(ToggleContextMenuNotification.IsChecked == true);
        SendTogglesUpdateToService();
    }

    private void TglLogAutoPrune_Click(object sender, RoutedEventArgs e)
    {
        if (!_isInitialized) return;
        bool autoPrune = TglLogAutoPrune?.IsChecked == true;
        UserSettingsStore.SetLogPermanentRetention(!autoPrune);
        if (NumLogRetentionDays != null)
            NumLogRetentionDays.IsEnabled = autoPrune;
        if (NumLogMaxCount != null)
            NumLogMaxCount.IsEnabled = autoPrune;
    }

    private void NumLogRetention_ValueChanged(object sender, Wpf.Ui.Controls.NumberBoxValueChangedEventArgs e)
    {
        if (!_isInitialized) return;
        if (NumLogRetentionDays?.Value is double d && !double.IsNaN(d))
        {
            int days = Math.Clamp((int)Math.Round(d), 1, 3650);
            UserSettingsStore.SetLogRetentionDays(days);
        }

        if (NumLogMaxCount?.Value is double c && !double.IsNaN(c))
        {
            int count = Math.Clamp((int)Math.Round(c), 0, 100000);
            UserSettingsStore.SetLogMaxCount(count);
        }
    }

    private async void BtnUnifiedCleanup_Click(object sender, RoutedEventArgs e)
    {
        if (BtnUnifiedCleanup == null) return;
        bool cleanLogs = ChkCleanAuditLogs?.IsChecked == true;
        bool cleanRules = ChkCleanInvalidRules?.IsChecked == true;
        bool cleanCaches = ChkCleanLocalCaches?.IsChecked == true;

        if (!cleanLogs && !cleanRules && !cleanCaches)
        {
            await ShowWinUiInfoDialogAsync("提示", "请至少勾选一项要清理的内容。");
            return;
        }

        if (cleanLogs)
        {
            bool confirm = await ShowWinUiConfirmDialogAsync(
                "确认立即清理",
                "已勾选“清空全部历史日志”，继续执行将永久清除所有历史拦截记录。确定继续吗？",
                "立即清理",
                "取消");
            if (!confirm) return;
        }

        BtnUnifiedCleanup.IsEnabled = false;
        try
        {
            int beforeLogCount = 0;
            int checkedRules = 0;
            int deletedRules = 0;
            int deletedFiles = 0;
            long freedBytes = 0;

            await Task.Run(() =>
            {
                if (cleanLogs)
                {
                    beforeLogCount = _sqliteRepo.GetRecentAuditLogs(100000).Count;
                    _sqliteRepo.ClearAuditLogs();
                }

                if (cleanRules)
                {
                    var md5Res = Md5RuleValidator.ValidateAndCleanObsoleteMd5Rules(_sqliteRepo);
                    checkedRules = md5Res.CheckedCount;
                    deletedRules = md5Res.DeletedCount;
                    if (deletedRules > 0)
                    {
                        SyncRulesBinaryAndNotifyService(_sqliteRepo);
                    }
                }

                if (cleanCaches)
                {
                    (deletedFiles, freedBytes) = UserSettingsStore.PurgeLocalLogsAndCaches();
                }

                _sqliteRepo.CompactDatabase();
            });

            RefreshRules();
            RefreshLogs();
            await RefreshAllDataAsync();

            string sizeDesc = freedBytes >= 1024 * 1024
                ? $"{freedBytes / (1024.0 * 1024.0):F2} MB"
                : $"{freedBytes / 1024.0:F1} KB";
            var summaryLines = new List<string>();
            if (cleanLogs) summaryLines.Add($"• 历史日志：已清空全部 {beforeLogCount} 条历史记录");
            if (cleanRules) summaryLines.Add($"• 单版本规则：已检测 {checkedRules} 条，移除 {deletedRules} 条已失效规则");
            if (cleanCaches) summaryLines.Add($"• 日志与缓存：清理 {deletedFiles} 个文件（释放 {sizeDesc}），数据库已压缩");

            await ShowWinUiInfoDialogAsync("清理完成", string.Join("\n", summaryLines));
        }
        catch (Exception ex)
        {
            await ShowWinUiInfoDialogAsync("清理异常", $"执行立即清理时发生异常：{ex.Message}");
        }
        finally
        {
            BtnUnifiedCleanup.IsEnabled = true;
        }
    }

    private void TglMd5Validation_Click(object sender, RoutedEventArgs e)
    {
        if (!_isInitialized) return;
        UserSettingsStore.SetMd5ValidationEnabled(TglMd5Validation.IsChecked == true);
    }

    private void NumMd5ValidationDays_ValueChanged(object sender, Wpf.Ui.Controls.NumberBoxValueChangedEventArgs e)
    {
        if (!_isInitialized || NumMd5ValidationDays == null) return;
        if (NumMd5ValidationDays.Value is double v && !double.IsNaN(v))
        {
            int days = Math.Clamp((int)Math.Round(v), 1, 360);
            UserSettingsStore.SetMd5ValidationIntervalDays(days);
        }
    }

    private void ChkMd5ValidationIdleOnly_Click(object sender, RoutedEventArgs e)
    {
        if (!_isInitialized) return;
        UserSettingsStore.SetMd5ValidationIdleOnly(ChkMd5ValidationIdleOnly.IsChecked == true);
    }

    private bool _isCleanupExpanded = true;
    private bool _isAboutExpanded = true;
    private bool _isNotificationsExpanded = false;
    private bool _isDefaultActionsExpanded = false;
    private bool _isServiceManagementExpanded = false;

    private static bool IsClickInsideButton(DependencyObject? source)
    {
        while (source != null)
        {
            if (source is System.Windows.Controls.Primitives.ButtonBase)
                return true;
            source = VisualTreeHelper.GetParent(source);
        }
        return false;
    }

    private void HeaderToggleDefaultActions_MouseLeftButtonUp(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        if (IsClickInsideButton(e.OriginalSource as DependencyObject)) return;
        BtnToggleDefaultActions_Click(sender, e);
    }

    private void BtnToggleDefaultActions_Click(object sender, RoutedEventArgs e)
    {
        _isDefaultActionsExpanded = !_isDefaultActionsExpanded;
        AnimateCollapsibleSection(_isDefaultActionsExpanded, RotateDefaultActionsChevron, DefaultActionsContainer, () => _isDefaultActionsExpanded);
    }

    private void HeaderToggleServiceManagement_MouseLeftButtonUp(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        if (IsClickInsideButton(e.OriginalSource as DependencyObject)) return;
        BtnToggleServiceManagement_Click(sender, e);
    }

    private void BtnToggleServiceManagement_Click(object sender, RoutedEventArgs e)
    {
        _isServiceManagementExpanded = !_isServiceManagementExpanded;
        if (_isServiceManagementExpanded)
            UpdateServiceStatusUI();
        AnimateCollapsibleSection(_isServiceManagementExpanded, RotateServiceManagementChevron, ServiceManagementContainer, () => _isServiceManagementExpanded);
    }

    private void CmbDefaultPopupAction_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!_isInitialized) return;
        if (sender is not System.Windows.Controls.ComboBox cmb ||
            cmb.Tag is not string catStr ||
            cmb.SelectedItem is not System.Windows.Controls.ComboBoxItem item ||
            item.Tag is not string actionStr)
            return;

        if (!Enum.TryParse<MonitorCategory>(catStr, out var cat) ||
            !Enum.TryParse<InterceptionAction>(actionStr, out var action))
            return;

        UserSettingsStore.SetDefaultPopupAction(cat, action);
    }

    #region FileTypes & MenuAnalysis Handlers

    private void UpdateFileTypeParamBarVisibility()
    {
        if (PanelFileTypeParamBar == null) return;
        bool showExt = _currentFileTypeTab == "CustomExtension";
        bool showPerceived = _currentFileTypeTab == "PerceivedType";
        bool showDir = _currentFileTypeTab == "DirectoryType";

        PanelCustomExtensionInput.Visibility = showExt ? Visibility.Visible : Visibility.Collapsed;
        PanelPerceivedTypeInput.Visibility = showPerceived ? Visibility.Visible : Visibility.Collapsed;
        PanelDirectoryTypeInput.Visibility = showDir ? Visibility.Visible : Visibility.Collapsed;
        PanelFileTypeParamBar.Visibility = (showExt || showPerceived || showDir) ? Visibility.Visible : Visibility.Collapsed;
    }

    private string GetSelectedComboTag(System.Windows.Controls.ComboBox? cmb, string fallback)
        => (cmb?.SelectedItem as System.Windows.Controls.ComboBoxItem)?.Tag?.ToString() ?? fallback;

    private void LoadActiveFileTypeItems()
    {
        string? param = _currentFileTypeTab switch
        {
            "CustomExtension" => string.IsNullOrWhiteSpace(TxtCustomExtension?.Text) ? _currentFileTypeParam : TxtCustomExtension.Text.Trim(),
            "PerceivedType" => GetSelectedComboTag(CmbPerceivedTypeSelector, string.IsNullOrWhiteSpace(_currentFileTypeParam) ? "text" : _currentFileTypeParam),
            "DirectoryType" => GetSelectedComboTag(CmbDirectoryTypeSelector, string.IsNullOrWhiteSpace(_currentFileTypeParam) ? "Document" : _currentFileTypeParam),
            _ => null
        };

        if (_currentFileTypeTab == "CustomExtension")
        {
            string ext = string.IsNullOrWhiteSpace(param) ? ".txt" : param.Trim();
            if (!ext.StartsWith('.')) ext = "." + ext;
            _currentFileTypeParam = ext;
            if (TxtCustomExtension != null && !string.Equals(TxtCustomExtension.Text, ext, StringComparison.OrdinalIgnoreCase))
                TxtCustomExtension.Text = ext;
        }
        else if (_currentFileTypeTab is "PerceivedType" or "DirectoryType")
        {
            _currentFileTypeParam = param ?? string.Empty;
        }

        _fileTypeCachedItems = _startupManager.ScanFileTypeContextMenus(_currentFileTypeTab, param);
    }

    private void BtnCheckOpenWithSource_Click(object sender, RoutedEventArgs e)
    {
        ExecuteOpenWithSourceInspection();
    }

    private void TxtOpenWithCheckExt_KeyDown(object sender, System.Windows.Input.KeyEventArgs e)
    {
        if (e.Key == System.Windows.Input.Key.Enter)
        {
            ExecuteOpenWithSourceInspection();
        }
    }

    private void ExecuteOpenWithSourceInspection()
    {
        if (TxtOpenWithCheckResult == null) return;
        string ext = TxtOpenWithCheckExt?.Text?.Trim() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(ext)) ext = ".txt";
        if (!ext.StartsWith('.')) ext = "." + ext;
        if (TxtOpenWithCheckExt != null && !string.Equals(TxtOpenWithCheckExt.Text, ext, StringComparison.OrdinalIgnoreCase))
            TxtOpenWithCheckExt.Text = ext;

        TxtOpenWithCheckResult.Text = _startupManager.InspectOpenWithRegistrationSources(ext);
        TxtOpenWithCheckResult.Visibility = Visibility.Visible;
    }

    private void BtnCancelOpenWithCheck_Click(object sender, RoutedEventArgs e)
    {
        if (TxtOpenWithCheckResult != null)
        {
            TxtOpenWithCheckResult.Text = string.Empty;
            TxtOpenWithCheckResult.Visibility = Visibility.Collapsed;
        }
    }

    private async void CmbDefaultDropEffect_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!_isInitialized) return;
        string tag = GetSelectedComboTag(CmbDefaultDropEffect, "0");
        if (!int.TryParse(tag, out int effect)) return;

        bool ok = await Task.Run(() => _startupManager.SetDefaultDropEffect(effect));
        if (!ok)
        {
            SyncDragDropEffectComboFromSystem();
            await ShowWinUiInfoDialogAsync("设置未完全生效", "无法写入系统 DefaultDropEffect 注册表键值，请检查是否拥有权限。");
        }
    }

    private async void BtnAddBlockedGuid_Click(object sender, RoutedEventArgs e)
    {
        string raw = TxtNewBlockedGuid?.Text?.Trim() ?? string.Empty;
        if (!Guid.TryParse(raw, out Guid parsed))
        {
            await ShowWinUiInfoDialogAsync("GUID 格式错误", "请输入合法的 {CLSID}（例如 {A1B2C3D4-...}）。");
            return;
        }

        string normClsid = parsed.ToString("B").ToUpperInvariant();
        bool ok = await Task.Run(() => _startupManager.AddGuidBlockedEntry(normClsid));
        if (ok)
        {
            if (TxtNewBlockedGuid != null) TxtNewBlockedGuid.Text = string.Empty;
            await RefreshAllDataAsync();
        }
        else
        {
            await ShowWinUiInfoDialogAsync("添加失败", $"无法将 {normClsid} 写入 Shell Extensions\\Blocked。");
        }
    }

    private void FileTypeTab_Checked(object sender, RoutedEventArgs e)
    {
        if (!_isInitialized) return;
        if (sender is not System.Windows.Controls.RadioButton rb || rb.Tag is not string tabTag)
            return;

        _currentFileTypeTab = tabTag;
        if (tabTag == "PerceivedType" && CmbPerceivedTypeSelector != null && CmbPerceivedTypeSelector.SelectedIndex < 0)
        {
            bool prev = _isInitialized; _isInitialized = false;
            CmbPerceivedTypeSelector.SelectedIndex = 0;
            _isInitialized = prev;
        }
        else if (tabTag == "DirectoryType" && CmbDirectoryTypeSelector != null && CmbDirectoryTypeSelector.SelectedIndex < 0)
        {
            bool prev = _isInitialized; _isInitialized = false;
            CmbDirectoryTypeSelector.SelectedIndex = 0;
            _isInitialized = prev;
        }

        UpdateFileTypeParamBarVisibility();
        LoadActiveFileTypeItems();
        ApplyClassicMenuFilter();
        PlayTabSwitchAnimation(ListViewClassicMenu);
    }

    private void BtnLoadCustomExtension_Click(object sender, RoutedEventArgs e)
    {
        LoadActiveFileTypeItems();
        ApplyClassicMenuFilter();
    }

    private void TxtCustomExtension_KeyDown(object sender, System.Windows.Input.KeyEventArgs e)
    {
        if (e.Key == System.Windows.Input.Key.Enter)
        {
            LoadActiveFileTypeItems();
            ApplyClassicMenuFilter();
        }
    }

    private void CmbPerceivedTypeSelector_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!_isInitialized) return;
        LoadActiveFileTypeItems();
        ApplyClassicMenuFilter();
    }

    private void CmbDirectoryTypeSelector_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!_isInitialized) return;
        LoadActiveFileTypeItems();
        ApplyClassicMenuFilter();
    }

    private void BtnAnalyzeTargetFile_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.OpenFileDialog
        {
            Title = "选择要分析右键菜单的文件或快捷方式",
            Filter = "所有文件 (*.*)|*.*",
            DereferenceLinks = false
        };
        if (dlg.ShowDialog(this) == true && !string.IsNullOrWhiteSpace(dlg.FileName))
        {
            RunMenuTargetAnalysis(dlg.FileName, isFolder: false);
        }
    }

    private void BtnAnalyzeTargetFolder_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.OpenFolderDialog
        {
            Title = "选择要分析右键菜单的文件夹"
        };
        if (dlg.ShowDialog(this) == true && !string.IsNullOrWhiteSpace(dlg.FolderName))
        {
            RunMenuTargetAnalysis(dlg.FolderName, isFolder: true);
        }
    }

    private void MenuAnalysis_DragOver(object sender, System.Windows.DragEventArgs e)
    {
        if (e.Data.GetDataPresent(System.Windows.DataFormats.FileDrop))
        {
            e.Effects = System.Windows.DragDropEffects.Link;
            e.Handled = true;
        }
    }

    private void MenuAnalysis_Drop(object sender, System.Windows.DragEventArgs e)
    {
        if (e.Data.GetData(System.Windows.DataFormats.FileDrop) is string[] paths && paths.Length > 0)
        {
            string p = paths[0];
            RunMenuTargetAnalysis(p, isFolder: Directory.Exists(p));
        }
    }

    private void RunMenuTargetAnalysis(string targetPath, bool isFolder)
    {
        if (PanelAnalyzedTargetInfo != null) PanelAnalyzedTargetInfo.Visibility = Visibility.Visible;
        if (TxtAnalyzedTargetPath != null) TxtAnalyzedTargetPath.Text = targetPath;

        var matches = _startupManager.AnalyzeContextMenuTarget(targetPath, isFolder);
        _displayedAnalysisMatches.Clear();
        foreach (var m in matches)
        {
            _displayedAnalysisMatches.Add(new AnalysisMatchViewModel
            {
                Title = m.Title,
                Subtitle = m.Subtitle,
                BreadcrumbText = string.Join(" ▶ ", m.Breadcrumbs),
                NavTag = m.NavTag,
                FileTypeTab = m.FileTypeTab,
                Parameter = m.Parameter
            });
        }
        if (ListAnalysisMatches != null && ListAnalysisMatches.ItemsSource == null)
        {
            ListAnalysisMatches.ItemsSource = _displayedAnalysisMatches;
        }
    }

    private void BtnJumpAnalysisMatch_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not FrameworkElement fe || fe.Tag is not AnalysisMatchViewModel match)
            return;

        if (match.NavTag == "FileTypes")
        {
            _currentClassicScene = string.Empty;
            _currentClassicFilter = "FileTypes";
            if (SubNavFileTypes != null) SubNavFileTypes.IsChecked = true;

            _currentFileTypeTab = string.IsNullOrEmpty(match.FileTypeTab) ? "LnkFile" : match.FileTypeTab;
            switch (_currentFileTypeTab)
            {
                case "LnkFile": if (TabFileTypeLnk != null) TabFileTypeLnk.IsChecked = true; break;
                case "UwpLnk": if (TabFileTypeUwpLnk != null) TabFileTypeUwpLnk.IsChecked = true; break;
                case "ExeFile": if (TabFileTypeExe != null) TabFileTypeExe.IsChecked = true; break;
                case "CustomExtension":
                    if (!string.IsNullOrEmpty(match.Parameter) && TxtCustomExtension != null)
                    {
                        TxtCustomExtension.Text = match.Parameter;
                        _currentFileTypeParam = match.Parameter;
                    }
                    if (TabFileTypeCustomExt != null) TabFileTypeCustomExt.IsChecked = true;
                    break;
                case "PerceivedType":
                    if (!string.IsNullOrEmpty(match.Parameter) && CmbPerceivedTypeSelector != null)
                    {
                        bool prev = _isInitialized; _isInitialized = false;
                        SelectComboBoxItemByTag(CmbPerceivedTypeSelector, match.Parameter);
                        _currentFileTypeParam = match.Parameter;
                        _isInitialized = prev;
                    }
                    if (TabFileTypePerceived != null) TabFileTypePerceived.IsChecked = true;
                    break;
                case "DirectoryType":
                    if (CmbDirectoryTypeSelector != null && CmbDirectoryTypeSelector.SelectedIndex < 0)
                    {
                        bool prev = _isInitialized; _isInitialized = false;
                        CmbDirectoryTypeSelector.SelectedIndex = 0;
                        _isInitialized = prev;
                    }
                    if (TabFileTypeDirType != null) TabFileTypeDirType.IsChecked = true;
                    break;
                case "UnknownType": if (TabFileTypeUnknown != null) TabFileTypeUnknown.IsChecked = true; break;
            }

            UpdateFileTypeParamBarVisibility();
            LoadActiveFileTypeItems();
            ApplyClassicMenuFilter();
            return;
        }

        _currentClassicScene = match.NavTag switch
        {
            "ClassicAllObjects" => "Scene_AllObjects",
            "ClassicFolder" => "Scene_Folder",
            "ClassicDirectory" => "Scene_Directory",
            "ClassicDirBackground" => "Scene_DirBackground",
            "ClassicFile" => "Scene_File",
            _ => "Scene_File"
        };
        _currentClassicFilter = _currentClassicScene;

        var navBtn = _currentClassicScene switch
        {
            "Scene_AllObjects" => SubNavClassicAllObj,
            "Scene_Folder" => SubNavClassicFolder,
            "Scene_Directory" => SubNavClassicDirectory,
            "Scene_DirBackground" => SubNavClassicDirBg,
            _ => SubNavClassicFile
        };
        if (navBtn != null) navBtn.IsChecked = true;
        ApplyClassicMenuFilter();
    }

    #endregion

    private void HeaderToggleNotifications_MouseLeftButtonUp(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        if (IsClickInsideButton(e.OriginalSource as DependencyObject)) return;
        BtnToggleNotificationsDetails_Click(sender, e);
    }

    private void HeaderToggleCleanupDetails_MouseLeftButtonUp(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        if (IsClickInsideButton(e.OriginalSource as DependencyObject)) return;
        BtnToggleCleanupDetails_Click(sender, e);
    }

    private void HeaderToggleAboutDetails_MouseLeftButtonUp(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        if (IsClickInsideButton(e.OriginalSource as DependencyObject)) return;
        BtnToggleAboutDetails_Click(sender, e);
    }

    private void BtnToggleNotificationsDetails_Click(object sender, RoutedEventArgs e)
    {
        _isNotificationsExpanded = !_isNotificationsExpanded;
        AnimateCollapsibleSection(_isNotificationsExpanded, RotateNotificationsChevron, NotificationsDetailsContainer, () => _isNotificationsExpanded);
    }

    private void BtnToggleCleanupDetails_Click(object sender, RoutedEventArgs e)
    {
        _isCleanupExpanded = !_isCleanupExpanded;
        AnimateCollapsibleSection(_isCleanupExpanded, RotateCleanupChevron, CleanupDetailsContainer, () => _isCleanupExpanded);
    }

    private void BtnToggleAboutDetails_Click(object sender, RoutedEventArgs e)
    {
        _isAboutExpanded = !_isAboutExpanded;
        AnimateCollapsibleSection(_isAboutExpanded, RotateAboutChevron, AboutDetailsContainer, () => _isAboutExpanded);
    }

    private static void AnimateCollapsibleSection(bool expand, RotateTransform chevron, FrameworkElement container, Func<bool> currentExpandedState)
    {
        var rotateAnim = new DoubleAnimation(expand ? 180 : 0, TimeSpan.FromMilliseconds(200))
        {
            EasingFunction = new CubicEase { EasingMode = EasingMode.EaseInOut }
        };
        chevron.BeginAnimation(RotateTransform.AngleProperty, rotateAnim);

        if (expand)
        {
            container.Visibility = Visibility.Visible;
            var opacityAnim = new DoubleAnimation(0.0, 1.0, TimeSpan.FromMilliseconds(200))
            {
                EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
            };
            container.BeginAnimation(UIElement.OpacityProperty, opacityAnim);
        }
        else
        {
            var opacityAnim = new DoubleAnimation(1.0, 0.0, TimeSpan.FromMilliseconds(150))
            {
                EasingFunction = new CubicEase { EasingMode = EasingMode.EaseIn }
            };
            opacityAnim.Completed += (_, _) =>
            {
                if (!currentExpandedState())
                {
                    container.Visibility = Visibility.Collapsed;
                }
            };
            container.BeginAnimation(UIElement.OpacityProperty, opacityAnim);
        }
    }

    private void UpdateSystemNotificationStatusBanner()
    {
        if (BtnSystemNotifyWarning == null) return;
        BtnSystemNotifyWarning.Visibility = IsWindowsToastNotificationsEnabled()
            ? Visibility.Collapsed
            : Visibility.Visible;
    }

    private static bool IsWindowsToastNotificationsEnabled()
    {
        try
        {
            using var pushKey = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\PushNotifications", false);
            if (pushKey?.GetValue("ToastEnabled") is int toastEnabled && toastEnabled == 0)
                return false;

            using var cuPolicy = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications", false);
            if (cuPolicy?.GetValue("NoToastApplicationNotification") is int cuBlock && cuBlock == 1)
                return false;

            using var lmPolicy = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications", false);
            if (lmPolicy?.GetValue("NoToastApplicationNotification") is int lmBlock && lmBlock == 1)
                return false;
        }
        catch { }

        return true;
    }

    private void BtnSystemNotifyWarning_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            using var proc = Process.Start(new ProcessStartInfo("ms-settings:notifications")
            {
                UseShellExecute = true,
                WorkingDirectory = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)
            });
        }
        catch (Exception ex)
        {
            App.LogCrash("OpenNotificationSettings", ex);
        }
    }

    private void BtnStoreLink_Click(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: string url } && !string.IsNullOrEmpty(url))
        {
            try
            {
                using var proc = Process.Start(new ProcessStartInfo
                {
                    FileName = url,
                    UseShellExecute = true
                });
            }
            catch { }
        }
    }

    #region Service Control & Management (Aligned with ContextMenuManager)

    private static void EnsureTrayHostRunning()
    {
        Process[]? existing = null;
        try
        {
            existing = Process.GetProcessesByName("StartupGuard.TrayHost");
            if (existing.Length == 0)
            {
                string trayExe = Path.Combine(AppContext.BaseDirectory, "StartupGuard.TrayHost.exe");
                if (File.Exists(trayExe))
                {
                    using var proc = Process.Start(new ProcessStartInfo
                    {
                        FileName = trayExe,
                        UseShellExecute = true,
                        WorkingDirectory = SharedStorageHelper.GetSafeWorkingDirectory()
                    });
                }
            }
        }
        catch { }
        finally
        {
            if (existing != null)
            {
                foreach (var p in existing)
                    p.Dispose();
            }
        }
    }

    private static bool IsRunEntryEnabledInRegistry(Microsoft.Win32.RegistryHive hive, Microsoft.Win32.RegistryView view)
    {
        try
        {
            using var baseKey = Microsoft.Win32.RegistryKey.OpenBaseKey(hive, view);
            using var runKey = baseKey.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", false);
            string? raw = runKey?.GetValue("StartupGuardTray")?.ToString();
            if (string.IsNullOrWhiteSpace(raw))
                return false;

            string approvedPath = view == Microsoft.Win32.RegistryView.Registry32 && hive == Microsoft.Win32.RegistryHive.LocalMachine
                ? @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32"
                : @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";
            using var appKey = baseKey.OpenSubKey(approvedPath, false);
            if (appKey?.GetValue("StartupGuardTray") is byte[] bytes && bytes.Length > 0)
                return bytes[0] == 0x02;

            return true;
        }
        catch
        {
            return false;
        }
    }

    private static bool QueryTrayAutoStartState()
    {
        if (!OperatingSystem.IsWindows()) return false;
        return IsRunEntryEnabledInRegistry(Microsoft.Win32.RegistryHive.LocalMachine, Microsoft.Win32.RegistryView.Registry64)
            || IsRunEntryEnabledInRegistry(Microsoft.Win32.RegistryHive.LocalMachine, Microsoft.Win32.RegistryView.Registry32)
            || IsRunEntryEnabledInRegistry(Microsoft.Win32.RegistryHive.CurrentUser, Microsoft.Win32.RegistryView.Registry64);
    }

    private static bool QueryServiceAutoStartState()
    {
        if (!OperatingSystem.IsWindows()) return false;
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\StartupGuardService", false);
            if (key?.GetValue("Start") is object rawVal && int.TryParse(rawVal.ToString(), out int startType))
                return startType == 2;
        }
        catch { }
        return false;
    }

    private static void TryDeleteRegistryValue(Microsoft.Win32.RegistryHive hive, Microsoft.Win32.RegistryView view, string subKey, string valueName)
    {
        try
        {
            using var baseKey = Microsoft.Win32.RegistryKey.OpenBaseKey(hive, view);
            using var key = baseKey.OpenSubKey(subKey, writable: true);
            key?.DeleteValue(valueName, throwOnMissingValue: false);
        }
        catch { }
    }

    private static (bool Installed, bool Running) QueryServiceStatusFast()
    {
        if (!OperatingSystem.IsWindows()) return (false, false);
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\StartupGuardService");
            if (key == null) return (false, false);

            var psi = new ProcessStartInfo
            {
                FileName = "sc.exe",
                Arguments = "query StartupGuardService",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var proc = Process.Start(psi);
            if (proc != null)
            {
                string output = proc.StandardOutput.ReadToEnd();
                proc.WaitForExit(1000);
                if (output.Contains("RUNNING", StringComparison.OrdinalIgnoreCase))
                {
                    return (true, true);
                }
                return (true, false);
            }
            return (true, false);
        }
        catch
        {
            return (false, false);
        }
    }

    private void EnsureServiceRunning()
    {
        if (!OperatingSystem.IsWindows()) return;
        Task.Run(() =>
        {
            try
            {
                var (installed, running) = QueryServiceStatusFast();
                if (installed && !running)
                {
                    using var proc = Process.Start(new ProcessStartInfo
                    {
                        FileName = "sc.exe",
                        Arguments = "start StartupGuardService",
                        CreateNoWindow = true,
                        UseShellExecute = false
                    });
                    proc?.WaitForExit(2000);
                    Dispatcher.InvokeAsync(UpdateServiceStatusUI);
                }
            }
            catch { }
        });
    }

    private void UpdateServiceStatusUI()
    {
        if (!OperatingSystem.IsWindows())
        {
            TxtServiceStatusDot.Foreground = new SolidColorBrush(Color.FromRgb(0x88, 0x88, 0x88));
            TxtServiceStatusText.Text = "非 Windows 环境";
            if (TglTrayAutoStart != null) TglTrayAutoStart.IsChecked = false;
            if (TglServiceAutoStart != null) { TglServiceAutoStart.IsChecked = false; TglServiceAutoStart.IsEnabled = false; }
            return;
        }

        try
        {
            var (installed, running) = QueryServiceStatusFast();
            bool svcAuto = installed && QueryServiceAutoStartState();
            if (!installed)
            {
                TxtServiceStatusDot.Foreground = new SolidColorBrush(Color.FromRgb(0x88, 0x88, 0x88));
                TxtServiceStatusText.Text = "未安装";
            }
            else if (running)
            {
                TxtServiceStatusDot.Foreground = new SolidColorBrush(Color.FromRgb(0x10, 0x7C, 0x10));
                TxtServiceStatusText.Text = svcAuto ? "运行中（开机自启已启用）" : "运行中（手动启动）";
            }
            else
            {
                TxtServiceStatusDot.Foreground = new SolidColorBrush(Color.FromRgb(0xD1, 0x34, 0x38));
                TxtServiceStatusText.Text = svcAuto ? "已停止（开机自启已启用）" : "已停止（手动启动）";
            }

            if (TglTrayAutoStart != null)
                TglTrayAutoStart.IsChecked = QueryTrayAutoStartState();

            if (TglServiceAutoStart != null)
            {
                TglServiceAutoStart.IsEnabled = installed;
                TglServiceAutoStart.IsChecked = svcAuto;
            }
        }
        catch (Exception ex)
        {
            TxtServiceStatusDot.Foreground = new SolidColorBrush(Color.FromRgb(0x88, 0x88, 0x88));
            TxtServiceStatusText.Text = $"检测失败: {ex.Message}";
        }
    }

    private async void TglTrayAutoStart_Click(object sender, RoutedEventArgs e)
    {
        if (!OperatingSystem.IsWindows() || TglTrayAutoStart == null) return;
        bool enable = TglTrayAutoStart.IsChecked == true;
        string trayExe = Path.Combine(AppContext.BaseDirectory, "StartupGuard.TrayHost.exe");
        string quotedPath = $"\"{trayExe}\"";

        BinaryPipeSerializer.NotifyServiceSuppressSelfMutation(
            @"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\StartupGuardTray",
            MonitorCategory.StartupItem, trayExe, 15.0);
        BinaryPipeSerializer.NotifyServiceSuppressSelfMutation(
            @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\StartupGuardTray",
            MonitorCategory.StartupItem, trayExe, 15.0);

        const string runSubKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
        const string approvedRun = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";
        const string approvedRun32 = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32";

        if (enable)
        {
            TryDeleteRegistryValue(Microsoft.Win32.RegistryHive.LocalMachine, Microsoft.Win32.RegistryView.Registry32, runSubKey, "StartupGuardTray");
            TryDeleteRegistryValue(Microsoft.Win32.RegistryHive.LocalMachine, Microsoft.Win32.RegistryView.Registry32, approvedRun32, "StartupGuardTray");
            TryDeleteRegistryValue(Microsoft.Win32.RegistryHive.LocalMachine, Microsoft.Win32.RegistryView.Registry64, approvedRun, "StartupGuardTray");
            TryDeleteRegistryValue(Microsoft.Win32.RegistryHive.CurrentUser, Microsoft.Win32.RegistryView.Registry64, approvedRun, "StartupGuardTray");

            bool wroteHklm = false;
            try
            {
                using var baseKey = Microsoft.Win32.RegistryKey.OpenBaseKey(Microsoft.Win32.RegistryHive.LocalMachine, Microsoft.Win32.RegistryView.Registry64);
                using var runKey = baseKey.CreateSubKey(runSubKey, writable: true);
                runKey?.SetValue("StartupGuardTray", quotedPath, Microsoft.Win32.RegistryValueKind.String);
                wroteHklm = runKey != null;
            }
            catch { }

            if (wroteHklm)
            {
                TryDeleteRegistryValue(Microsoft.Win32.RegistryHive.CurrentUser, Microsoft.Win32.RegistryView.Registry64, runSubKey, "StartupGuardTray");
            }
            else
            {
                try
                {
                    using var runKeyCu = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(runSubKey, writable: true);
                    runKeyCu?.SetValue("StartupGuardTray", quotedPath, Microsoft.Win32.RegistryValueKind.String);
                }
                catch { }
            }

            EnsureTrayHostRunning();
        }
        else
        {
            TryDeleteRegistryValue(Microsoft.Win32.RegistryHive.CurrentUser, Microsoft.Win32.RegistryView.Registry64, runSubKey, "StartupGuardTray");
            TryDeleteRegistryValue(Microsoft.Win32.RegistryHive.CurrentUser, Microsoft.Win32.RegistryView.Registry64, approvedRun, "StartupGuardTray");
            TryDeleteRegistryValue(Microsoft.Win32.RegistryHive.LocalMachine, Microsoft.Win32.RegistryView.Registry64, runSubKey, "StartupGuardTray");
            TryDeleteRegistryValue(Microsoft.Win32.RegistryHive.LocalMachine, Microsoft.Win32.RegistryView.Registry32, runSubKey, "StartupGuardTray");
            TryDeleteRegistryValue(Microsoft.Win32.RegistryHive.LocalMachine, Microsoft.Win32.RegistryView.Registry64, approvedRun, "StartupGuardTray");
            TryDeleteRegistryValue(Microsoft.Win32.RegistryHive.LocalMachine, Microsoft.Win32.RegistryView.Registry32, approvedRun32, "StartupGuardTray");

            if (QueryTrayAutoStartState())
            {
                try
                {
                    await RunCommandElevatedAsync(
                        "cmd.exe",
                        "/c reg delete \"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v StartupGuardTray /f /reg:64 & reg delete \"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v StartupGuardTray /f /reg:32",
                        "关闭托盘开机自启");
                }
                catch { }
            }
        }

        UpdateServiceStatusUI();
    }

    private async void TglServiceAutoStart_Click(object sender, RoutedEventArgs e)
    {
        if (!OperatingSystem.IsWindows() || TglServiceAutoStart == null) return;
        bool enable = TglServiceAutoStart.IsChecked == true;
        string svcExe = Path.Combine(AppContext.BaseDirectory, "StartupGuard.Service.exe");

        BinaryPipeSerializer.NotifyServiceSuppressSelfMutation(
            @"HKLM\SYSTEM\CurrentControlSet\Services\StartupGuardService",
            MonitorCategory.Win32Service, svcExe, 15.0);

        bool applied = PrivilegedRollbackEngine.RollbackServiceOrDriverStartType(
            "StartupGuardService",
            enable ? 2u : 3u,
            isKernelDriver: false);

        if (!applied)
        {
            await RunServiceCommandAsync(
                $"config StartupGuardService start= {(enable ? "auto" : "demand")}",
                enable ? "开启服务开机自启" : "关闭服务开机自启",
                silent: true);
        }

        if (enable)
        {
            EnsureServiceRunning();
        }

        UpdateServiceStatusUI();
    }

    private void TglDiagnosticLogging_Click(object sender, RoutedEventArgs e)
    {
        UserSettingsStore.SetDiagnosticLoggingEnabled(TglDiagnosticLogging.IsChecked == true);
    }

    private void BtnViewDiagnosticLog_Click(object sender, RoutedEventArgs e)
    {
        string logDir = SharedStorageHelper.GetSharedLogDirectory();
        string logFile = Path.Combine(logDir, "startupguard.log");
        if (!File.Exists(logFile))
        {
            File.WriteAllText(logFile, $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] [App] 运行日志已初始化。\n");
        }
        try
        {
            using var proc = Process.Start(new ProcessStartInfo("notepad.exe", $"\"{logFile}\"")
            {
                UseShellExecute = true,
                WorkingDirectory = Directory.Exists(logDir) ? logDir : Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)
            });
        }
        catch (Exception ex)
        {
            App.LogCrash("OpenLogFile", ex);
        }
    }

    private void BtnOpenLogFolder_Click(object sender, RoutedEventArgs e)
    {
        string logDir = SharedStorageHelper.GetSharedLogDirectory();
        try
        {
            if (!Directory.Exists(logDir))
                Directory.CreateDirectory(logDir);

            using var proc = Process.Start(new ProcessStartInfo("explorer.exe", $"\"{logDir}\"")
            {
                UseShellExecute = true,
                WorkingDirectory = logDir
            });
        }
        catch (Exception ex)
        {
            App.LogCrash("OpenLogFolder", ex);
        }
    }

    private async void BtnRestartService_Click(object sender, RoutedEventArgs e)
    {
        await RunCommandElevatedAsync("powershell.exe", "-WindowStyle Hidden -NoProfile -Command \"Restart-Service -Name 'StartupGuardService' -Force\"", "重启服务");
        await Task.Delay(1000);
        UpdateServiceStatusUI();
    }

    private async void BtnInstallService_Click(object sender, RoutedEventArgs e)
    {
        string svcExe = Path.Combine(AppContext.BaseDirectory, "StartupGuard.Service.exe");
        string cmd = $"create StartupGuardService binPath= \"\\\"{svcExe}\\\" --service\" start= auto DisplayName= \"StartupGuard Core Monitoring Service\"";
        await RunServiceCommandAsync(cmd, "安装服务");
    }

    private async void BtnUninstallService_Click(object sender, RoutedEventArgs e)
    {
        bool confirm = await ShowWinUiConfirmDialogAsync("卸载服务确认", "确定要卸载 StartupGuardService 后台监控服务吗？\n卸载后系统底层自启与右键拦截将失效。", "卸载", "取消");
        if (confirm)
        {
            await RunServiceCommandAsync("stop StartupGuardService", "停止服务", silent: true);
            await RunServiceCommandAsync("delete StartupGuardService", "卸载服务");
        }
    }

    private async void BtnRestartExplorer_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            await RunCommandElevatedAsync("powershell.exe", "-WindowStyle Hidden -NoProfile -Command \"Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue; Start-Process explorer.exe\"", "重启文件资源管理器");
        }
        catch (Exception ex)
        {
            await ShowWinUiInfoDialogAsync("错误", $"重启资源管理器失败: {ex.Message}");
        }
    }

    private async Task RunServiceCommandAsync(string scArguments, string actionName, bool silent = false)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "sc.exe",
                Arguments = scArguments,
                Verb = "runas",
                UseShellExecute = true,
                WindowStyle = ProcessWindowStyle.Hidden
            };
            using var proc = Process.Start(psi);
            if (proc != null) await proc.WaitForExitAsync();
            await Task.Delay(500);
            UpdateServiceStatusUI();
            if (!silent)
            {
                await ShowWinUiInfoDialogAsync("执行完成", $"已成功执行 [{actionName}] 操作。");
            }
        }
        catch (Exception ex)
        {
            if (!silent)
            {
                await ShowWinUiInfoDialogAsync("执行失败", $"执行 [{actionName}] 时出现异常: {ex.Message}");
            }
        }
    }

    private static async Task RunCommandElevatedAsync(string exe, string args, string actionName)
    {
        var psi = new ProcessStartInfo
        {
            FileName = exe,
            Arguments = args,
            Verb = "runas",
            UseShellExecute = true,
            WindowStyle = ProcessWindowStyle.Hidden,
            CreateNoWindow = true
        };
        using var proc = Process.Start(psi);
        if (proc != null) await proc.WaitForExitAsync();
    }

    #endregion

    private sealed class RestoreOptionItem
    {
        public string Title { get; init; } = string.Empty;
        public string SummaryText { get; init; } = string.Empty;
        public InterceptionAction Action { get; init; } = InterceptionAction.Allow;
        public uint StartType { get; init; } = 2;
        public bool DelayedAuto { get; init; }
    }

    private AuditLogRecord? _currentRestoringLog;

    private void BtnUndoLog_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not FrameworkElement { Tag: AuditLogRecord log })
            return;

        _currentRestoringLog = log;
        bool isPendingManual = log.IsPendingManualAction;
        TxtRestoreDialogTitle.Text = isPendingManual ? "手动处置项目" : "选择恢复方式";
        TxtRestoreActionLabel.Text = isPendingManual ? "选择处置状态" : "恢复目标状态";
        BtnConfirmRestore.Content = isPendingManual ? "确认执行" : "确认恢复";

        TxtRestoreTargetName.Text = string.IsNullOrWhiteSpace(log.TargetProgram) ? log.LocationKey : log.TargetProgram;
        TxtRestoreTargetCategory.Text = $"类别: {log.CategoryName}";
        TxtRestoreTargetLocation.Text = log.LocationKey;

        var options = new List<RestoreOptionItem>();
        switch (log.Category)
        {
            case MonitorCategory.Win32Service:
                options.Add(new RestoreOptionItem { Title = isPendingManual ? "设为禁止启动" : "保持禁止状态", SummaryText = "已设为禁止", Action = InterceptionAction.RollbackToDisabled, StartType = 4, DelayedAuto = false });
                options.Add(new RestoreOptionItem { Title = "设为手动按需启动", SummaryText = "已调整为手动启动", Action = InterceptionAction.RollbackToDemand, StartType = 3, DelayedAuto = false });
                options.Add(new RestoreOptionItem { Title = "设为自动(延迟启动)", SummaryText = "已恢复为延迟启动", Action = InterceptionAction.RollbackToDelayedAuto, StartType = 2, DelayedAuto = true });
                options.Add(new RestoreOptionItem { Title = "设为自动启动", SummaryText = "已恢复为自动启动", Action = InterceptionAction.Allow, StartType = 2, DelayedAuto = false });
                options.Add(new RestoreOptionItem { Title = "删除该服务项", SummaryText = "已删除服务项", Action = InterceptionAction.DeleteEntry, StartType = 4, DelayedAuto = false });
                break;

            case MonitorCategory.KernelDriver:
                options.Add(new RestoreOptionItem { Title = "恢复为手动按需加载 (Start=3)", SummaryText = "已恢复为手动启动", Action = InterceptionAction.RollbackToDemand, StartType = 3, DelayedAuto = false });
                options.Add(new RestoreOptionItem { Title = "恢复为自动加载 (Start=2)", SummaryText = "已恢复为自动加载", Action = InterceptionAction.Allow, StartType = 2, DelayedAuto = false });
                options.Add(new RestoreOptionItem { Title = "恢复为系统启动加载 (Start=1)", SummaryText = "已恢复为系统启动", Action = InterceptionAction.Allow, StartType = 1, DelayedAuto = false });
                options.Add(new RestoreOptionItem { Title = isPendingManual ? "设为禁止加载 (Start=4)" : "保持禁止状态 (Start=4)", SummaryText = "已保持禁止", Action = InterceptionAction.RollbackToDisabled, StartType = 4, DelayedAuto = false });
                break;

            default:
                options.Add(new RestoreOptionItem { Title = isPendingManual ? "设为禁止 / 屏蔽状态" : "保持禁止/屏蔽状态", SummaryText = "已设为禁止", Action = InterceptionAction.RollbackToDisabled, StartType = 4, DelayedAuto = false });
                options.Add(new RestoreOptionItem { Title = "设为启用状态（放行）", SummaryText = "已设为启用", Action = InterceptionAction.Allow, StartType = 2, DelayedAuto = false });
                options.Add(new RestoreOptionItem { Title = "删除此项（移除注册表或任务）", SummaryText = "已删除移除", Action = InterceptionAction.DeleteEntry, StartType = 4, DelayedAuto = false });
                break;
        }

        CmbRestoreActionOption.ItemsSource = options;
        CmbRestoreActionOption.SelectedIndex = isPendingManual
            ? 0
            : (log.Category == MonitorCategory.Win32Service ? 3 : (log.Category == MonitorCategory.KernelDriver ? 0 : 1));
        DialogRestoreActionHost.Visibility = Visibility.Visible;
    }

    private void BtnCancelRestore_Click(object sender, RoutedEventArgs e)
    {
        _currentRestoringLog = null;
        DialogRestoreActionHost.Visibility = Visibility.Collapsed;
    }

    private static bool ExecuteRestoreLocally(AuditLogRecord log, RestoreOptionItem option)
    {
        BinaryPipeSerializer.NotifyServiceSuppressSelfMutation(
            log.LocationKey,
            log.Category,
            log.TargetProgram,
            15.0);

        var target = NativeSecurityExtractor.BuildTargetProgramFeatures(
            log.Category,
            log.LocationKey,
            log.TargetProgram,
            oldState: log.OldStateSummary);

        if (log.Category is MonitorCategory.Win32Service or MonitorCategory.KernelDriver)
        {
            return PrivilegedRollbackEngine.RollbackServiceOrDriverStartType(
                log.LocationKey,
                option.StartType,
                log.Category == MonitorCategory.KernelDriver,
                option.DelayedAuto);
        }

        return option.Action == InterceptionAction.Allow
            ? PrivilegedRollbackEngine.RestoreItemEnabled(target, option.StartType, option.DelayedAuto)
            : PrivilegedRollbackEngine.ExecuteRollback(target, option.Action);
    }

    private async void BtnConfirmRestore_Click(object sender, RoutedEventArgs e)
    {
        var log = _currentRestoringLog;
        var option = CmbRestoreActionOption.SelectedItem as RestoreOptionItem;
        DialogRestoreActionHost.Visibility = Visibility.Collapsed;
        _currentRestoringLog = null;

        if (log == null || option == null)
            return;

        try
        {
            var payload = new AuditRollbackRequestPayload
            {
                AuditLogId = log.LogId,
                LocationKey = log.LocationKey,
                Category = log.Category,
                TargetAction = option.Action,
                TargetStartType = option.StartType,
                DelayedAutostart = option.DelayedAuto,
                OldStateSummary = log.OldStateSummary
            };

            bool pipeSuccess = false;
            try
            {
                await using var client = new NamedPipeClientStream(".", "StartupGuard_Control_Pipe", PipeDirection.InOut, PipeOptions.Asynchronous);
                await client.ConnectAsync(800);
                byte[] body = BinaryPipeSerializer.SerializeAuditRollbackRequest(payload);
                var hdr = PipeMessageHeader.Create(PipeMessageType.ExecuteAuditRollback, (uint)body.Length, 0);
                byte[] hdrBytes = new byte[64];
                BinaryPipeSerializer.WriteHeader(hdrBytes, in hdr);
                await client.WriteAsync(hdrBytes);
                await client.WriteAsync(body);
                await client.FlushAsync();
                pipeSuccess = true;
            }
            catch
            {
                pipeSuccess = false;
            }

            if (!pipeSuccess)
            {
                ExecuteRestoreLocally(log, option);
                _sqliteRepo.WriteAuditLog(
                    null,
                    log.Category,
                    log.TargetProgram,
                    log.LocationKey,
                    option.SummaryText,
                    "Reverted",
                    $"用户已将项目恢复为：{option.Title}",
                    100.0,
                    $"本地执行恢复 ({option.SummaryText})");
            }

            var target = NativeSecurityExtractor.BuildTargetProgramFeatures(
                log.Category,
                log.LocationKey,
                log.TargetProgram,
                oldState: log.OldStateSummary);

            bool verified = await VerifyOperationWithRetryAsync(
                string.IsNullOrWhiteSpace(log.TargetProgram) ? log.LocationKey : log.TargetProgram,
                log.LocationKey,
                () => ExecuteRestoreLocally(log, option),
                () => log.Category is MonitorCategory.Win32Service or MonitorCategory.KernelDriver
                    ? PrivilegedRollbackEngine.VerifyServiceStartType(log.LocationKey, option.StartType, option.DelayedAuto)
                    : PrivilegedRollbackEngine.VerifyRollbackState(target, option.Action));

            RefreshLogs();
            await RefreshAllDataAsync();

            if (verified)
            {
                await ShowWinUiInfoDialogAsync("恢复完成", $"已将「{log.TargetProgram}」{option.SummaryText}，并完成状态校验。");
            }
        }
        catch (Exception ex)
        {
            await ShowWinUiInfoDialogAsync("恢复失败", $"恢复过程中出现异常: {ex.Message}");
        }
    }

    private RuleRecord? _currentEditingRule;

    private void BtnEditRule_Click(object sender, RoutedEventArgs e)
    {
        RuleRecord? rule = sender is FrameworkElement fe
            ? (fe.Tag is RuleDisplayItem vm ? vm.Rule : fe.Tag as RuleRecord)
            : null;
        if (rule == null)
            return;

        _currentEditingRule = rule;
        TxtEditRuleTitle.Text = rule.DisplayName;
        TxtEditRuleCategory.Text = $"类别: {rule.CategoryName}";
        TxtEditRuleCommand.Text = rule.TargetBinaryOrCommand;

        var options = BuildRuleActionOptions(rule.Category);

        CmbEditRuleAction.ItemsSource = options;
        var selected = options.FirstOrDefault(o => o.Action == rule.ActionType) ?? options.First();
        CmbEditRuleAction.SelectedItem = selected;

        CmbEditRuleMode.SelectedIndex = rule.RuleMode == RuleMatchMode.StrictCurrentVersion ? 1 : 0;

        DialogEditRuleHost.Visibility = Visibility.Visible;
    }

    internal static List<ActionOptionItem> BuildRuleActionOptions(MonitorCategory category) => category switch
    {
        MonitorCategory.Win32Service =>
        [
            new ActionOptionItem { Title = "设为手动", Action = InterceptionAction.RollbackToDemand },
            new ActionOptionItem { Title = "设为自动延迟", Action = InterceptionAction.RollbackToDelayedAuto },
            new ActionOptionItem { Title = "设为禁止", Action = InterceptionAction.RollbackToDisabled },
            new ActionOptionItem { Title = "删除服务", Action = InterceptionAction.DeleteEntry },
            new ActionOptionItem { Title = "允许服务", Action = InterceptionAction.Allow }
        ],
        MonitorCategory.KernelDriver =>
        [
            new ActionOptionItem { Title = "设为手动", Action = InterceptionAction.RollbackToDemand },
            new ActionOptionItem { Title = "设为禁止", Action = InterceptionAction.RollbackToDisabled },
            new ActionOptionItem { Title = "允许驱动", Action = InterceptionAction.Allow }
        ],
        MonitorCategory.ScheduledTask =>
        [
            new ActionOptionItem { Title = "禁止任务", Action = InterceptionAction.RollbackToDisabled },
            new ActionOptionItem { Title = "删除任务", Action = InterceptionAction.DeleteEntry },
            new ActionOptionItem { Title = "允许任务", Action = InterceptionAction.Allow }
        ],
        MonitorCategory.ClassicContextMenu or MonitorCategory.ModernContextMenu =>
        [
            new ActionOptionItem { Title = "屏蔽菜单", Action = InterceptionAction.RollbackToDisabled },
            new ActionOptionItem { Title = "删除菜单", Action = InterceptionAction.DeleteEntry },
            new ActionOptionItem { Title = "允许菜单", Action = InterceptionAction.Allow }
        ],
        MonitorCategory.WindowsPolicy =>
        [
            new ActionOptionItem { Title = "禁止策略", Action = InterceptionAction.RollbackToDisabled },
            new ActionOptionItem { Title = "删除策略", Action = InterceptionAction.DeleteEntry },
            new ActionOptionItem { Title = "允许策略", Action = InterceptionAction.Allow }
        ],
        _ =>
        [
            new ActionOptionItem { Title = "禁止自启", Action = InterceptionAction.RollbackToDisabled },
            new ActionOptionItem { Title = "删除自启", Action = InterceptionAction.DeleteEntry },
            new ActionOptionItem { Title = "允许自启", Action = InterceptionAction.Allow }
        ]
    };

    private void BtnCancelRuleEdit_Click(object sender, RoutedEventArgs e)
    {
        _currentEditingRule = null;
        DialogEditRuleHost.Visibility = Visibility.Collapsed;
    }

    private async void BtnSaveRuleEdit_Click(object sender, RoutedEventArgs e)
    {
        if (_currentEditingRule == null)
        {
            DialogEditRuleHost.Visibility = Visibility.Collapsed;
            return;
        }

        var selectedOption = CmbEditRuleAction.SelectedItem as ActionOptionItem;
        var act = selectedOption?.Action ?? InterceptionAction.RollbackToDisabled;

        var mode = CmbEditRuleMode.SelectedIndex == 1
            ? RuleMatchMode.StrictCurrentVersion
            : RuleMatchMode.PermanentAdaptive;

        _currentEditingRule.ActionType = act;
        _currentEditingRule.RuleMode = mode;
        _currentEditingRule.ConfidenceThreshold = 85.0f;
        _currentEditingRule.UpdatedAt = DateTime.UtcNow;

        try
        {
            _sqliteRepo.InsertOrUpdateRule(_currentEditingRule);
            SyncRulesBinaryAndNotifyService(_sqliteRepo);

            RefreshRules();
            await ShowWinUiInfoDialogAsync("规则已更新", $"规则 [{_currentEditingRule.DisplayName}] 已成功保存并同步至防护引擎。");
        }
        catch (Exception ex)
        {
            App.LogCrash("SaveRuleEdit", ex);
        }

        DialogEditRuleHost.Visibility = Visibility.Collapsed;
        _currentEditingRule = null;
    }

    private static string ResolveRulesBinPath()
    {
        try
        {
            return Path.Combine(SharedStorageHelper.GetSharedDataDirectory(), "rules.bin");
        }
        catch
        {
            return Path.Combine(Path.GetTempPath(), "startupguard_rules.bin");
        }
    }

    private void Hyperlink_RequestNavigate(object sender, System.Windows.Navigation.RequestNavigateEventArgs e)
    {
        try
        {
            using var proc = Process.Start(new ProcessStartInfo(e.Uri.AbsoluteUri) { UseShellExecute = true });
            e.Handled = true;
        }
        catch { }
    }

    #region Win+X Group Management (ContextMenuManager Alignment)

    private void LoadWinXGroups(bool preserveExpandState = true)
    {
        var prevExpandMap = preserveExpandState
            ? _displayedWinXGroups.ToDictionary(g => g.GroupName, g => g.IsExpanded, StringComparer.OrdinalIgnoreCase)
            : new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);

        var rawGroups = WinXMenuService.ScanGroups(autoNormalizePrefixes: true, out bool normalized);
        string searchTerm = _currentClassicSearchTerm?.Trim() ?? string.Empty;

        _displayedWinXGroups.Clear();
        foreach (var grp in rawGroups)
        {
            var matchedItems = string.IsNullOrEmpty(searchTerm)
                ? grp.Items
                : grp.Items.Where(i =>
                    i.DisplayName.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ||
                    i.TargetPath.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ||
                    grp.GroupName.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)).ToList();

            if (!string.IsNullOrEmpty(searchTerm) && matchedItems.Count == 0 &&
                !grp.GroupName.Contains(searchTerm, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            bool isExpanded = prevExpandMap.TryGetValue(grp.GroupName, out bool savedExpand) ? savedExpand : true;
            var groupVm = new WinXGroupViewModel
            {
                GroupName = grp.GroupName,
                GroupPath = grp.GroupPath,
                IsEnabled = grp.IsEnabled,
                CanRestoreDefault = grp.CanRestoreDefault,
                IsExpanded = isExpanded
            };

            foreach (var sc in matchedItems)
            {
                groupVm.Items.Add(new WinXShortcutViewModel
                {
                    FilePath = sc.FilePath,
                    GroupName = sc.GroupName,
                    GroupPath = sc.GroupPath,
                    DisplayName = sc.DisplayName,
                    TargetPath = sc.TargetPath,
                    IsEnabled = sc.IsEnabled,
                    CanMoveUp = sc.CanMoveUp,
                    CanMoveDown = sc.CanMoveDown,
                    RealIconSource = ProgramIconResolver.ResolveIcon(sc.TargetPath, MonitorCategory.ClassicContextMenu)
                        ?? ProgramIconResolver.ResolveIcon(sc.FilePath, MonitorCategory.ClassicContextMenu)
                });
            }

            _displayedWinXGroups.Add(groupVm);
        }

        if (normalized)
        {
            MarkWinXRestartRequired();
        }
    }

    private void MarkWinXRestartRequired()
    {
        if (TxtWinXStatusHint != null)
        {
            TxtWinXStatusHint.Text = "检测到 Win+X 菜单已修改，请点击右侧“重启资源管理器”立即生效";
        }
        if (BtnWinXRestartExplorer != null)
        {
            BtnWinXRestartExplorer.Appearance = ControlAppearance.Primary;
        }
    }

    private void TglWinXGroup_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Wpf.Ui.Controls.ToggleSwitch tgl || tgl.Tag is not WinXGroupViewModel grp)
            return;

        bool targetState = tgl.IsChecked == true;
        if (!WinXMenuService.SetGroupEnabled(grp.GroupPath, targetState))
        {
            tgl.IsChecked = !targetState;
            grp.IsEnabled = !targetState;
            _ = ShowWinUiInfoDialogAsync("操作失败", $"无法修改分组「{grp.GroupName}」属性。");
            return;
        }

        grp.IsEnabled = targetState;
        if (grp.Items.Count > 0)
            MarkWinXRestartRequired();
    }

    private void BtnWinXRenameGroup_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not FrameworkElement fe || fe.Tag is not WinXGroupViewModel grp)
            return;

        _pendingRenameWinXGroup = grp;
        _pendingRenameWinXShortcut = null;
        if (TxtWinXRenameTitle != null) TxtWinXRenameTitle.Text = "重命名 Win+X 分组";
        if (TxtWinXRenameOriginal != null) TxtWinXRenameOriginal.Text = $"原分组名：{grp.GroupName}";
        if (TxtWinXRenameInput != null) TxtWinXRenameInput.Text = grp.GroupName;
        if (DialogWinXRenameHost != null) DialogWinXRenameHost.Visibility = Visibility.Visible;
    }

    private async void BtnWinXRestoreGroup_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not FrameworkElement fe || fe.Tag is not WinXGroupViewModel grp)
            return;

        bool confirm = await ShowWinUiConfirmDialogAsync(
            "恢复默认 Win+X 分组",
            $"确定将分组「{grp.GroupName}」恢复为系统默认快捷方式吗？当前该组内的自定义更改将被覆盖。",
            "恢复默认",
            "取消");
        if (!confirm) return;

        if (!WinXMenuService.RestoreDefaultGroup(grp.GroupPath))
        {
            await ShowWinUiInfoDialogAsync("恢复失败", "未找到系统默认分组模板或目录正在被占用。");
            return;
        }

        LoadWinXGroups();
        MarkWinXRestartRequired();
    }

    private async void BtnWinXDeleteGroup_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not FrameworkElement fe || fe.Tag is not WinXGroupViewModel grp)
            return;

        if (grp.Items.Count > 0)
        {
            bool confirm = await ShowWinUiConfirmDialogAsync(
                "删除 Win+X 分组",
                $"分组「{grp.GroupName}」内包含 {grp.Items.Count} 个快捷方式，确定永久删除整个分组吗？",
                "删除",
                "取消");
            if (!confirm) return;
        }

        if (!WinXMenuService.DeleteGroup(grp.GroupPath))
        {
            await ShowWinUiInfoDialogAsync("删除失败", $"无法删除分组「{grp.GroupName}」。");
            return;
        }

        LoadWinXGroups();
        MarkWinXRestartRequired();
    }

    private void BtnWinXCreateGroup_Click(object sender, RoutedEventArgs e)
    {
        if (WinXMenuService.CreateNewGroup() == null)
        {
            _ = ShowWinUiInfoDialogAsync("新建失败", "无法创建新的 Win+X 分组目录。");
            return;
        }

        LoadWinXGroups();
    }

    private async void BtnWinXRestartExplorer_Click(object sender, RoutedEventArgs e)
    {
        await Task.Run(WinXMenuService.RestartExplorerProcess);
        if (TxtWinXStatusHint != null)
            TxtWinXStatusHint.Text = "资源管理器已重启，Win+X 菜单更改已生效";
        if (BtnWinXRestartExplorer != null)
            BtnWinXRestartExplorer.Appearance = ControlAppearance.Secondary;
    }

    private void TglWinXItem_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Wpf.Ui.Controls.ToggleSwitch tgl || tgl.Tag is not WinXShortcutViewModel sc)
            return;

        bool targetState = tgl.IsChecked == true;
        if (!WinXMenuService.SetItemEnabled(sc.FilePath, targetState))
        {
            tgl.IsChecked = !targetState;
            sc.IsEnabled = !targetState;
            _ = ShowWinUiInfoDialogAsync("操作失败", $"无法修改「{sc.DisplayName}」的显示状态。");
            return;
        }

        sc.IsEnabled = targetState;
        MarkWinXRestartRequired();
    }

    private void BtnWinXRenameItem_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not FrameworkElement fe || fe.Tag is not WinXShortcutViewModel sc)
            return;

        _pendingRenameWinXShortcut = sc;
        _pendingRenameWinXGroup = null;
        if (TxtWinXRenameTitle != null) TxtWinXRenameTitle.Text = "重命名 Win+X 快捷方式";
        if (TxtWinXRenameOriginal != null) TxtWinXRenameOriginal.Text = $"当前名称：{sc.DisplayName}";
        if (TxtWinXRenameInput != null) TxtWinXRenameInput.Text = sc.DisplayName;
        if (DialogWinXRenameHost != null) DialogWinXRenameHost.Visibility = Visibility.Visible;
    }

    private void BtnWinXMoveUp_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not FrameworkElement fe || fe.Tag is not WinXShortcutViewModel sc)
            return;

        if (WinXMenuService.MoveItem(sc.GroupPath, sc.FilePath, moveUp: true))
        {
            LoadWinXGroups();
            MarkWinXRestartRequired();
        }
    }

    private void BtnWinXMoveDown_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not FrameworkElement fe || fe.Tag is not WinXShortcutViewModel sc)
            return;

        if (WinXMenuService.MoveItem(sc.GroupPath, sc.FilePath, moveUp: false))
        {
            LoadWinXGroups();
            MarkWinXRestartRequired();
        }
    }

    private async void BtnWinXDeleteItem_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not FrameworkElement fe || fe.Tag is not WinXShortcutViewModel sc)
            return;

        bool confirm = await ShowWinUiConfirmDialogAsync(
            "删除 Win+X 项目",
            $"确定删除「{sc.DisplayName}」吗？删除后可在所在分组点击“恢复默认”找回系统默认项。",
            "删除",
            "取消");
        if (!confirm) return;

        if (!WinXMenuService.DeleteItem(sc.FilePath))
        {
            await ShowWinUiInfoDialogAsync("删除失败", $"无法删除「{sc.DisplayName}」。");
            return;
        }

        LoadWinXGroups();
        MarkWinXRestartRequired();
    }

    private void BtnWinXOpenTarget_Click(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement fe && fe.Tag is WinXShortcutViewModel sc)
        {
            LocateFileInExplorer(sc.TargetPath);
        }
    }

    private void BtnWinXOpenLnkFolder_Click(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement fe && fe.Tag is WinXShortcutViewModel sc)
        {
            LocateFileInExplorer(sc.FilePath);
        }
    }

    private void BtnWinXSaveRename_Click(object sender, RoutedEventArgs e)
    {
        string newName = TxtWinXRenameInput?.Text?.Trim() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(newName))
            return;

        bool ok = false;
        if (_pendingRenameWinXGroup != null)
        {
            ok = WinXMenuService.RenameGroup(_pendingRenameWinXGroup.GroupPath, newName) != null;
        }
        else if (_pendingRenameWinXShortcut != null)
        {
            ok = WinXMenuService.RenameItem(_pendingRenameWinXShortcut.FilePath, newName);
        }

        if (DialogWinXRenameHost != null) DialogWinXRenameHost.Visibility = Visibility.Collapsed;
        _pendingRenameWinXGroup = null;
        _pendingRenameWinXShortcut = null;

        if (!ok)
        {
            _ = ShowWinUiInfoDialogAsync("重命名失败", "名称包含无效字符或与已有项目重名。");
            return;
        }

        LoadWinXGroups();
        MarkWinXRestartRequired();
    }

    private void BtnWinXCancelRename_Click(object sender, RoutedEventArgs e)
    {
        if (DialogWinXRenameHost != null) DialogWinXRenameHost.Visibility = Visibility.Collapsed;
        _pendingRenameWinXGroup = null;
        _pendingRenameWinXShortcut = null;
    }

    #endregion

    private void SendTogglesUpdateToService()
    {
        bool contextMenuPromptMode = (CmbContextMenuStrategy?.SelectedItem as ComboBoxItem)?.Tag?.ToString() == "PromptImmediate";
        bool effectiveCtxNotify = !contextMenuPromptMode && (ToggleContextMenuNotification?.IsChecked ?? UserSettingsStore.GetContextMenuNotificationsEnabled());
        bool blockNotifications = (ToggleRuleHitNotification?.IsChecked ?? UserSettingsStore.GetRuleHitNotificationsEnabled()) || effectiveCtxNotify;
        bool autoGameMode = ToggleAutoGameMode?.IsChecked ?? true;

        Task.Run(async () =>
        {
            try
            {
                await using var client = new NamedPipeClientStream(".", "StartupGuard_Control_Pipe", PipeDirection.InOut, PipeOptions.Asynchronous);
                await client.ConnectAsync(300);
                var payload = new MonitorTogglesPayload
                {
                    MonitorStartup = true,
                    MonitorService = true,
                    MonitorDriver = true,
                    MonitorScheduledTask = true,
                    MonitorContextMenu = true,
                    MonitorWindowsPolicy = true,
                    BlockNotifications = blockNotifications,
                    EnableSound = false,
                    AutoGameMode = autoGameMode,
                    ContextMenuPromptMode = contextMenuPromptMode
                };
                byte[] data = BinaryPipeSerializer.SerializeMonitorToggles(payload);
                var hdr = PipeMessageHeader.Create(PipeMessageType.UpdateMonitorToggles, (uint)data.Length, 0);
                byte[] hdrBytes = new byte[64];
                BinaryPipeSerializer.WriteHeader(hdrBytes, in hdr);
                await client.WriteAsync(hdrBytes);
                await client.WriteAsync(data);
                await client.FlushAsync();
            }
            catch { }
        });
    }

    #region Manual Rule Creation

    private int _createRuleInspectSeq;
    private bool _suppressCreateRulePathChanged;
    private string _lastAutoCreateRuleName = string.Empty;
    private string _inspectedRuleFilePath = string.Empty;
    private TargetProgramFeatures? _createRuleExtractedFeatures;

    private void BtnOpenCreateRuleDialog_Click(object sender, RoutedEventArgs e)
    {
        _createRuleInspectSeq++;
        _createRuleExtractedFeatures = null;
        _inspectedRuleFilePath = string.Empty;
        _lastAutoCreateRuleName = string.Empty;

        _suppressCreateRulePathChanged = true;
        try
        {
            TxtCreateRuleName.Text = string.Empty;
            TxtCreateRuleTargetPath.Text = string.Empty;
            TxtCreateRuleLocationKey.Text = string.Empty;
            TxtCreateRuleMd5.Text = string.Empty;
        }
        finally
        {
            _suppressCreateRulePathChanged = false;
        }

        TxtCreateRuleMetaHint.Text = "提示：选择文件将自动提取签名、PE 元数据与哈希；选择文件夹则对该目录下所有同类别目标生效。";
        TxtCreateRuleError.Text = string.Empty;
        TxtCreateRuleError.Visibility = Visibility.Collapsed;

        CmbCreateRuleCategory.SelectedIndex = 0;
        PopulateCreateRuleActions(MonitorCategory.StartupItem, InterceptionAction.RollbackToDisabled);
        CmbCreateRuleMode.SelectedIndex = 0;

        DialogCreateRuleHost.Visibility = Visibility.Visible;
    }

    private MonitorCategory GetSelectedCreateRuleCategory()
    {
        if (CmbCreateRuleCategory?.SelectedItem is ComboBoxItem item &&
            item.Tag is string tag &&
            Enum.TryParse<MonitorCategory>(tag, ignoreCase: false, out var category))
        {
            return category;
        }

        return MonitorCategory.StartupItem;
    }

    private void PopulateCreateRuleActions(MonitorCategory category, InterceptionAction? preferredAction = null)
    {
        if (CmbCreateRuleAction == null)
            return;

        var options = BuildRuleActionOptions(category);
        CmbCreateRuleAction.ItemsSource = options;
        var targetAction = preferredAction ?? InterceptionAction.RollbackToDisabled;
        CmbCreateRuleAction.SelectedItem = options.FirstOrDefault(o => o.Action == targetAction) ?? options.First();
    }

    private void CmbCreateRuleCategory_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!IsLoaded || CmbCreateRuleAction == null)
            return;

        var prevAction = (CmbCreateRuleAction.SelectedItem as ActionOptionItem)?.Action;
        PopulateCreateRuleActions(GetSelectedCreateRuleCategory(), prevAction);
    }

    private void CmbCreateRuleMode_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!IsLoaded || TxtCreateRuleError == null || TxtCreateRuleTargetPath == null)
            return;

        TxtCreateRuleError.Visibility = Visibility.Collapsed;
        string path = TxtCreateRuleTargetPath.Text.Trim().Trim('"');
        if (CmbCreateRuleMode.SelectedIndex == 1 && !string.IsNullOrEmpty(path) && IsFolderPathCandidate(path))
        {
            ShowCreateRuleError("文件夹规则不支持「仅此版本严格 MD5」模式，请切回「永久拦截」。");
        }
    }

    private void TxtCreateRuleTargetPath_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (_suppressCreateRulePathChanged || !IsLoaded)
            return;

        if (TxtCreateRuleError != null)
            TxtCreateRuleError.Visibility = Visibility.Collapsed;

        string currentPath = TxtCreateRuleTargetPath.Text.Trim().Trim('"');
        if (!string.Equals(currentPath, _inspectedRuleFilePath, StringComparison.OrdinalIgnoreCase))
        {
            _createRuleInspectSeq++;
            _createRuleExtractedFeatures = null;
            _inspectedRuleFilePath = string.Empty;
        }

        if (TxtCreateRuleMetaHint == null)
            return;

        if (string.IsNullOrEmpty(currentPath))
        {
            TxtCreateRuleMetaHint.Text = "提示：选择文件将自动提取签名、PE 元数据与哈希；选择文件夹则对该目录下所有同类别目标生效。";
        }
        else if (IsFolderPathCandidate(currentPath))
        {
            TxtCreateRuleMetaHint.Text = "已识别为文件夹路径：保存后将对该文件夹及其子目录下所有同类别目标自动应用此规则。";
        }
        else if (File.Exists(currentPath))
        {
            TxtCreateRuleMetaHint.Text = "检测到本地文件：点击「创建并保存」时将自动提取签名、PE 元数据与 MD5。";
        }
    }

    private async void BtnCreateRuleBrowseFile_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.OpenFileDialog
        {
            Title = "选择要添加到防护规则的程序或组件",
            Filter = "可执行与扩展组件 (*.exe;*.dll;*.sys;*.ocx;*.cpl;*.scr;*.bat;*.cmd;*.ps1;*.vbs)|*.exe;*.dll;*.sys;*.ocx;*.cpl;*.scr;*.bat;*.cmd;*.ps1;*.vbs|所有文件 (*.*)|*.*",
            DereferenceLinks = true
        };

        if (dlg.ShowDialog(this) != true || string.IsNullOrWhiteSpace(dlg.FileName))
            return;

        string filePath = dlg.FileName.Trim();
        TxtCreateRuleError.Visibility = Visibility.Collapsed;

        _suppressCreateRulePathChanged = true;
        try
        {
            TxtCreateRuleTargetPath.Text = filePath;
        }
        finally
        {
            _suppressCreateRulePathChanged = false;
        }

        await InspectManualRuleFileAsync(filePath, GetSelectedCreateRuleCategory());
    }

    private void BtnCreateRuleBrowseFolder_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.OpenFolderDialog
        {
            Title = "选择要整目录匹配的文件夹"
        };

        if (dlg.ShowDialog(this) != true || string.IsNullOrWhiteSpace(dlg.FolderName))
            return;

        if (!TryValidateSafeFolderRuleTarget(dlg.FolderName, out string normalizedFolder, out string? errorMsg))
        {
            ShowCreateRuleError(errorMsg ?? "所选文件夹范围过大，请选择具体软件目录。");
            return;
        }

        _createRuleInspectSeq++;
        _createRuleExtractedFeatures = null;
        _inspectedRuleFilePath = string.Empty;
        TxtCreateRuleError.Visibility = Visibility.Collapsed;

        _suppressCreateRulePathChanged = true;
        try
        {
            TxtCreateRuleTargetPath.Text = normalizedFolder;
            TxtCreateRuleMd5.Text = string.Empty;
        }
        finally
        {
            _suppressCreateRulePathChanged = false;
        }

        CmbCreateRuleMode.SelectedIndex = 0;

        string folderName = Path.GetFileName(normalizedFolder.TrimEnd('\\', '/'));
        if (string.IsNullOrWhiteSpace(folderName))
            folderName = "指定目录";

        TryAutoFillCreateRuleName($"{folderName} 文件夹规则");
        TxtCreateRuleMetaHint.Text = $"已选定文件夹规则：将对「{normalizedFolder}」及子目录下的所有【{(CmbCreateRuleCategory.SelectedItem as ComboBoxItem)?.Content ?? "当前类别"}】目标自动匹配。";
    }

    private async Task InspectManualRuleFileAsync(string filePath, MonitorCategory category)
    {
        int seq = ++_createRuleInspectSeq;
        _createRuleExtractedFeatures = null;
        _inspectedRuleFilePath = string.Empty;
        TxtCreateRuleMetaHint.Text = "正在提取目标文件的数字签名、PE 元数据与 MD5 哈希...";

        TargetProgramFeatures? features = null;
        try
        {
            string locationHint = TxtCreateRuleLocationKey.Text.Trim();
            string nameHint = TxtCreateRuleName.Text.Trim();
            features = await Task.Run(() =>
                NativeSecurityExtractor.BuildTargetProgramFeatures(category, locationHint, filePath, nameHint));
        }
        catch (Exception ex)
        {
            App.LogCrash("InspectManualRuleFile", ex);
        }

        if (seq != _createRuleInspectSeq || DialogCreateRuleHost.Visibility != Visibility.Visible)
            return;

        if (features == null)
        {
            TxtCreateRuleMetaHint.Text = "文件特征提取失败，您仍可手动填写规则名称并保存。";
            return;
        }

        _createRuleExtractedFeatures = features;
        _inspectedRuleFilePath = filePath;

        if (!string.IsNullOrEmpty(features.MD5Hex))
            TxtCreateRuleMd5.Text = features.MD5Hex;

        string suggestedName = !string.IsNullOrWhiteSpace(features.ProductName)
            ? features.ProductName.Trim()
            : Path.GetFileNameWithoutExtension(filePath);
        TryAutoFillCreateRuleName(suggestedName);

        string sigSummary = features.HasValidSignature && !string.IsNullOrWhiteSpace(features.SignerSubject)
            ? $"有效签名: {features.SignerSubject}"
            : "数字签名: 无有效签名";
        string peSummary = !string.IsNullOrWhiteSpace(features.OriginalFilename)
            ? $" | 原始文件名: {features.OriginalFilename}"
            : string.Empty;
        string md5Summary = !string.IsNullOrWhiteSpace(features.MD5Hex)
            ? $" | MD5: {features.MD5Hex}"
            : string.Empty;
        TxtCreateRuleMetaHint.Text = $"{sigSummary}{peSummary}{md5Summary}";
    }

    private void TryAutoFillCreateRuleName(string suggestedName)
    {
        if (string.IsNullOrWhiteSpace(suggestedName))
            return;

        string current = TxtCreateRuleName.Text.Trim();
        if (string.IsNullOrEmpty(current) || string.Equals(current, _lastAutoCreateRuleName, StringComparison.Ordinal))
        {
            TxtCreateRuleName.Text = suggestedName;
            _lastAutoCreateRuleName = suggestedName;
        }
    }

    private void ShowCreateRuleError(string message)
    {
        TxtCreateRuleError.Text = message;
        TxtCreateRuleError.Visibility = Visibility.Visible;
    }

    private static bool IsFolderPathCandidate(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return false;

        string trimmed = path.Trim().Trim('"');
        if (trimmed.EndsWith('\\') || trimmed.EndsWith('/'))
            return true;

        try
        {
            return Directory.Exists(Environment.ExpandEnvironmentVariables(trimmed));
        }
        catch
        {
            return false;
        }
    }

    internal static bool TryValidateSafeFolderRuleTarget(
        string folderPath,
        out string normalizedFolderWithTrailingSlash,
        out string? errorMessage)
    {
        normalizedFolderWithTrailingSlash = string.Empty;
        errorMessage = null;

        if (string.IsNullOrWhiteSpace(folderPath))
        {
            errorMessage = "请输入或选择有效的文件夹路径。";
            return false;
        }

        string cleaned = Environment.ExpandEnvironmentVariables(folderPath.Trim().Trim('"')).Replace('/', '\\');
        string fullPath;
        try
        {
            fullPath = Path.GetFullPath(cleaned).TrimEnd('\\');
        }
        catch
        {
            errorMessage = "文件夹路径格式无效。";
            return false;
        }

        if (string.IsNullOrEmpty(fullPath))
        {
            errorMessage = "文件夹路径不能为空。";
            return false;
        }

        string? root = Path.GetPathRoot(fullPath + "\\")?.TrimEnd('\\');
        if (!string.IsNullOrEmpty(root) && string.Equals(fullPath, root, StringComparison.OrdinalIgnoreCase))
        {
            errorMessage = "禁止将磁盘根目录设为整目录规则，以免误拦截整个分区的正常程序。";
            return false;
        }

        var blockedPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        void AddBlocked(Environment.SpecialFolder sf, params string[] suffixes)
        {
            string p = Environment.GetFolderPath(sf).TrimEnd('\\');
            if (string.IsNullOrEmpty(p)) return;
            blockedPaths.Add(p);
            foreach (string s in suffixes)
            {
                blockedPaths.Add(Path.Combine(p, s).TrimEnd('\\'));
            }
        }

        AddBlocked(Environment.SpecialFolder.Windows, "System32", "SysWOW64", @"System32\drivers");
        AddBlocked(Environment.SpecialFolder.System);
        AddBlocked(Environment.SpecialFolder.SystemX86);
        AddBlocked(Environment.SpecialFolder.ProgramFiles);
        AddBlocked(Environment.SpecialFolder.ProgramFilesX86);
        AddBlocked(Environment.SpecialFolder.CommonApplicationData);
        AddBlocked(Environment.SpecialFolder.UserProfile);

        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile).TrimEnd('\\');
        if (!string.IsNullOrEmpty(userProfile))
        {
            string? usersRoot = Path.GetDirectoryName(userProfile)?.TrimEnd('\\');
            if (!string.IsNullOrEmpty(usersRoot))
                blockedPaths.Add(usersRoot);
        }

        if (blockedPaths.Contains(fullPath))
        {
            errorMessage = "为防止影响系统稳定，禁止将系统根目录、Program Files、ProgramData 或用户主目录直接作为整目录规则，请选择具体软件子目录。";
            return false;
        }

        normalizedFolderWithTrailingSlash = fullPath + "\\";
        return true;
    }

    private async void BtnSaveCreateRule_Click(object sender, RoutedEventArgs e)
    {
        TxtCreateRuleError.Visibility = Visibility.Collapsed;

        string ruleName = TxtCreateRuleName.Text.Trim();
        if (string.IsNullOrWhiteSpace(ruleName))
        {
            ShowCreateRuleError("请填写规则名称。");
            return;
        }

        string targetInput = TxtCreateRuleTargetPath.Text.Trim().Trim('"');
        string locationKey = TxtCreateRuleLocationKey.Text.Trim();
        if (string.IsNullOrEmpty(targetInput) && string.IsNullOrEmpty(locationKey))
        {
            ShowCreateRuleError("请至少填写「目标文件/文件夹路径」或「注册表 / 服务 / 任务 / CLSID 位置」中的一项。");
            return;
        }

        var category = GetSelectedCreateRuleCategory();
        var action = (CmbCreateRuleAction.SelectedItem as ActionOptionItem)?.Action ?? InterceptionAction.RollbackToDisabled;
        var mode = CmbCreateRuleMode.SelectedIndex == 1
            ? RuleMatchMode.StrictCurrentVersion
            : RuleMatchMode.PermanentAdaptive;

        bool isFolderTarget = !string.IsNullOrEmpty(targetInput) && IsFolderPathCandidate(targetInput);
        string rawCommand = targetInput;
        string normalizedPath = string.Empty;
        string md5Input = TxtCreateRuleMd5.Text.Trim().ToLowerInvariant();
        TargetProgramFeatures? features = null;

        if (isFolderTarget)
        {
            if (!TryValidateSafeFolderRuleTarget(targetInput, out string normalizedFolder, out string? folderErr))
            {
                ShowCreateRuleError(folderErr ?? "文件夹路径不安全或无效。");
                return;
            }

            if (mode == RuleMatchMode.StrictCurrentVersion)
            {
                ShowCreateRuleError("文件夹规则不支持「仅此版本严格 MD5」模式，请切回「永久拦截」。");
                return;
            }

            rawCommand = normalizedFolder;
            normalizedPath = PathNormalizerAndSimilarity.NormalizeProgramPath(normalizedFolder);
            md5Input = string.Empty;
        }
        else
        {
            if (!string.IsNullOrEmpty(md5Input) &&
                !System.Text.RegularExpressions.Regex.IsMatch(md5Input, "^[0-9a-f]{32}$"))
            {
                ShowCreateRuleError("MD5 格式无效，请输入 32 位十六进制字符或留空自动计算。");
                return;
            }

            if (!string.IsNullOrEmpty(targetInput))
            {
                bool alreadyInspected = _createRuleExtractedFeatures != null &&
                                        string.Equals(targetInput, _inspectedRuleFilePath, StringComparison.OrdinalIgnoreCase) &&
                                        _createRuleExtractedFeatures.Category == category;
                if (alreadyInspected)
                {
                    features = _createRuleExtractedFeatures;
                }
                else
                {
                    try
                    {
                        features = await Task.Run(() =>
                            NativeSecurityExtractor.BuildTargetProgramFeatures(category, locationKey, targetInput, ruleName));
                    }
                    catch (Exception ex)
                    {
                        App.LogCrash("CreateRuleExtractFeatures", ex);
                    }
                }

                normalizedPath = features != null && !string.IsNullOrEmpty(features.NormalizedPath)
                    ? features.NormalizedPath
                    : PathNormalizerAndSimilarity.NormalizeProgramPath(targetInput);
            }

            string effectiveMd5 = !string.IsNullOrEmpty(md5Input) ? md5Input : (features?.MD5Hex ?? string.Empty);
            if (mode == RuleMatchMode.StrictCurrentVersion && string.IsNullOrEmpty(effectiveMd5))
            {
                ShowCreateRuleError("「仅此版本」模式必须具备有效的文件 MD5，请选择本地存在的文件或手动填写 32 位 MD5。");
                return;
            }

            md5Input = effectiveMd5;
        }

        var rule = new RuleRecord
        {
            DisplayName = ruleName,
            Category = category,
            ActionType = action,
            RuleMode = mode,
            ConfidenceThreshold = 85.0f,
            HasSignature = features?.HasValidSignature ?? false,
            SignerSubject = features?.SignerSubject ?? string.Empty,
            RootCertThumbprint = features?.RootCertThumbprint ?? string.Empty,
            OriginalFilename = features?.OriginalFilename ?? string.Empty,
            ProductName = !string.IsNullOrWhiteSpace(features?.ProductName) ? features.ProductName : ruleName,
            CompanyName = features?.CompanyName ?? string.Empty,
            InternalName = features?.InternalName ?? string.Empty,
            NormalizedPath = normalizedPath,
            RawCommand = rawCommand,
            LocationKey = locationKey,
            CommandLineArgs = features?.CommandLineArgsTemplate ?? string.Empty,
            ImpHash = features?.ImpHash ?? string.Empty,
            IconPHash = features?.IconPerceptualHash ?? 0UL,
            CurrentMD5 = md5Input,
            CurrentSHA256 = features?.SHA256Hex ?? string.Empty,
            UpdatedAt = DateTime.UtcNow
        };

        try
        {
            _sqliteRepo.InsertOrUpdateRule(rule);
            SyncRulesBinaryAndNotifyService(_sqliteRepo);
            RefreshRules();

            DialogCreateRuleHost.Visibility = Visibility.Collapsed;
            _createRuleExtractedFeatures = null;
            _inspectedRuleFilePath = string.Empty;

            await ShowWinUiInfoDialogAsync("规则已创建", $"规则 [{rule.DisplayName}] 已成功添加并同步至防护引擎。");
        }
        catch (Exception ex)
        {
            App.LogCrash("CreateManualRule", ex);
            ShowCreateRuleError($"保存规则失败: {ex.Message}");
        }
    }

    private void BtnCancelCreateRule_Click(object sender, RoutedEventArgs e)
    {
        _createRuleInspectSeq++;
        _createRuleExtractedFeatures = null;
        _inspectedRuleFilePath = string.Empty;
        if (TxtCreateRuleError != null) TxtCreateRuleError.Visibility = Visibility.Collapsed;
        if (DialogCreateRuleHost != null) DialogCreateRuleHost.Visibility = Visibility.Collapsed;
    }

    #endregion

    #endregion
}
