using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using StartupGuard.Core.Configuration;
using StartupGuard.Core.ContextMenu;
using StartupGuard.Core.Ipc;
using StartupGuard.Core.Models;
using StartupGuard.Core.Native;
using Wpf.Ui.Appearance;
using Wpf.Ui.Controls;

namespace StartupGuard.TrayHost;

public sealed class AnalyzedMenuNode
{
    public string Text { get; init; } = string.Empty;
    public string Verb { get; init; } = string.Empty;
    public Thickness IndentMargin { get; init; }
    public bool HasVerb => !string.IsNullOrWhiteSpace(Verb);
}

public sealed class CapturedItemViewModel : INotifyPropertyChanged
{
    public required ulong CorrelationId { get; set; }
    public required ConfidenceEvaluationResult Evaluation { get; set; }

    private bool _isSelected = true;
    public bool IsSelected
    {
        get => _isSelected;
        set { _isSelected = value; OnPropertyChanged(nameof(IsSelected)); }
    }

    public required string DisplayName { get; init; }
    public required string CategoryName { get; init; }
    public required string CategoryShortLabel { get; init; }
    public required SymbolRegular CategoryIcon { get; init; }
    public required System.Windows.Media.Brush CategoryAccentBrush { get; init; }
    public required System.Windows.Media.Brush CategoryTintBrush { get; init; }
    public required string Publisher { get; init; }
    public required string TargetPath { get; init; }
    public required string CommandLineText { get; init; }
    public required string LocationKey { get; init; }
    public string DisplayLocationKey => ShellNavigationHelper.FormatForRegeditDisplay(LocationKey);
    public string Clsid { get; init; } = string.Empty;
    public bool HasClsid => !string.IsNullOrWhiteSpace(Clsid);
    public string MenuSceneText { get; init; } = string.Empty;
    public bool HasMenuScene => !string.IsNullOrWhiteSpace(MenuSceneText);
    public string CreatorProcessText { get; init; } = string.Empty;
    public bool HasCreatorProcess => !string.IsNullOrWhiteSpace(CreatorProcessText);
    public bool IsContextMenuItem { get; init; }

    public ObservableCollection<ActionOptionItem> AvailableActions { get; } = [];

    private ActionOptionItem? _selectedAction;
    public ActionOptionItem? SelectedAction
    {
        get => _selectedAction;
        set { _selectedAction = value; OnPropertyChanged(nameof(SelectedAction)); }
    }

    private bool _isDetailsExpanded;
    public bool IsDetailsExpanded
    {
        get => _isDetailsExpanded;
        set
        {
            _isDetailsExpanded = value;
            OnPropertyChanged(nameof(IsDetailsExpanded));
            OnPropertyChanged(nameof(DetailsVisibility));
            OnPropertyChanged(nameof(DetailButtonText));
        }
    }

    public Visibility DetailsVisibility => _isDetailsExpanded ? Visibility.Visible : Visibility.Collapsed;
    public string DetailButtonText => _isDetailsExpanded ? "收起详情" : "查看详情";

    public void UpdateEvaluation(ulong correlationId, ConfidenceEvaluationResult eval)
    {
        CorrelationId = correlationId;
        Evaluation = eval;
        OnPropertyChanged(nameof(CorrelationId));
        OnPropertyChanged(nameof(Evaluation));
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    private void OnPropertyChanged(string propName) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propName));
}

public partial class InterceptionDiffDialogWindow : FluentWindow
{
    private readonly ObservableCollection<CapturedItemViewModel> _capturedItems = [];
    private readonly Action<IReadOnlyList<UserDecisionPayload>> _onBatchDecisionMade;
    private bool _decisionSent = false;
    private System.Windows.Threading.DispatcherTimer? _copyFeedbackTimer;

    public InterceptionDiffDialogWindow(
        ulong correlationId,
        ConfidenceEvaluationResult initialEval,
        Action<IReadOnlyList<UserDecisionPayload>> onBatchDecisionMade)
    {
        InitializeComponent();
        _onBatchDecisionMade = onBatchDecisionMade;
        CardsItemsControl.ItemsSource = _capturedItems;

        AppendCapturedItem(correlationId, initialEval);

        SourceInitialized += (_, _) =>
        {
            StartupGuard.Themes.FluentBackdropHelper.ApplyMica(this, !UserSettingsStore.IsEffectiveLightTheme());
        };

        Loaded += (_, _) =>
        {
            ApplyConfiguredTheme();
            Microsoft.Win32.SystemEvents.UserPreferenceChanged += OnSystemUserPreferenceChanged;
        };

        Closed += (_, _) =>
        {
            Microsoft.Win32.SystemEvents.UserPreferenceChanged -= OnSystemUserPreferenceChanged;
            foreach (var item in _capturedItems)
            {
                item.PropertyChanged -= OnCapturedItemPropertyChanged;
            }

            if (!_decisionSent)
            {
                _decisionSent = true;
                _onBatchDecisionMade(BuildDismissDecisions(_capturedItems));
            }
        };
    }

    private void OnSystemUserPreferenceChanged(object? sender, Microsoft.Win32.UserPreferenceChangedEventArgs e)
    {
        if (e.Category is Microsoft.Win32.UserPreferenceCategory.General or Microsoft.Win32.UserPreferenceCategory.VisualStyle)
        {
            Dispatcher.BeginInvoke(ApplyConfiguredTheme);
        }
    }

    private void ApplyConfiguredTheme()
    {
        try
        {
            bool isLight = UserSettingsStore.IsEffectiveLightTheme();
            ApplicationTheme theme = isLight
                ? ApplicationTheme.Light
                : ApplicationTheme.Dark;
            ApplicationThemeManager.Apply(theme, WindowBackdropType.Mica, true);
            StartupGuard.Themes.FluentBackdropHelper.ApplyMica(this, !isLight);
        }
        catch { }
    }

    public void AppendCapturedItem(ulong correlationId, ConfidenceEvaluationResult eval)
    {
        if (Dispatcher.CheckAccess())
        {
            AddViewModel(correlationId, eval);
        }
        else
        {
            Dispatcher.Invoke(() => AddViewModel(correlationId, eval));
        }
    }

    private void AddViewModel(ulong correlationId, ConfidenceEvaluationResult eval)
    {
        var target = eval.CurrentTarget;

        // 仅按精确 LocationKey 更新同一项（防止同程序注册的不同服务/驱动/Run自启项互相覆盖吞并）
        var existing = _capturedItems.FirstOrDefault(x =>
            string.Equals(x.LocationKey, target.LocationKeyOrIdentifier, StringComparison.OrdinalIgnoreCase));

        if (existing != null)
        {
            existing.UpdateEvaluation(correlationId, eval);
            return;
        }

        string name = CleanDisplayName(target.DisplayName, target.TargetBinaryPath, target.LocationKeyOrIdentifier);
        var (catName, shortLabel, icon, accentBrush, tintBrush) = MapCategory(target.Category);
        string publisher = string.IsNullOrWhiteSpace(target.SignerSubject) ? "未签名 / 未知发布者" : target.SignerSubject;
        string cmdLine = !string.IsNullOrWhiteSpace(target.RawCommandLine)
            ? target.RawCommandLine
            : (!string.IsNullOrWhiteSpace(target.TargetBinaryPath) ? target.TargetBinaryPath : "(无关联命令行)");

        string clsid = ExtractClsid(target.LocationKeyOrIdentifier, target.RawCommandLine);
        bool isContextMenu = target.Category is MonitorCategory.ClassicContextMenu or MonitorCategory.ModernContextMenu;
        string menuScene = isContextMenu
            ? ContextMenuSceneHelper.DescribeScene(target.Category, target.LocationKeyOrIdentifier)
            : string.Empty;
        string creatorProc = !string.IsNullOrWhiteSpace(target.SourceProcessName)
            ? target.SourceProcessName
            : (target.SourceProcessId > 0 ? $"PID {target.SourceProcessId}" : string.Empty);

        var vm = new CapturedItemViewModel
        {
            CorrelationId = correlationId,
            Evaluation = eval,
            IsSelected = true,
            DisplayName = name,
            CategoryName = catName,
            CategoryShortLabel = shortLabel,
            CategoryIcon = icon,
            CategoryAccentBrush = accentBrush,
            CategoryTintBrush = tintBrush,
            Publisher = publisher,
            TargetPath = target.TargetBinaryPath,
            CommandLineText = cmdLine,
            LocationKey = target.LocationKeyOrIdentifier,
            Clsid = clsid,
            MenuSceneText = menuScene,
            CreatorProcessText = creatorProc,
            IsContextMenuItem = isContextMenu
        };

        PopulateActionsForCategory(vm, target.Category);

        vm.PropertyChanged += OnCapturedItemPropertyChanged;
        _capturedItems.Add(vm);
        UpdateHeaderSummary();
    }

    private void OnCapturedItemPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(CapturedItemViewModel.IsSelected))
        {
            UpdateHeaderSummary();
        }
    }

    private static string CleanDisplayName(string rawName, string targetPath, string locationKey)
    {
        string s = (rawName ?? string.Empty).Trim();
        if (s.StartsWith("ClassicHandler:", StringComparison.OrdinalIgnoreCase) ||
            s.StartsWith("ClassicVerb:", StringComparison.OrdinalIgnoreCase) ||
            s.StartsWith("Approved:", StringComparison.OrdinalIgnoreCase))
        {
            int idx = s.LastIndexOf(':');
            if (idx >= 0 && idx < s.Length - 1)
                s = s[(idx + 1)..].Trim();
        }

        if (string.IsNullOrWhiteSpace(s) || s.StartsWith('{'))
        {
            string fn = Path.GetFileName(targetPath.TrimEnd('\\', '/'));
            if (!string.IsNullOrWhiteSpace(fn))
                s = fn;
        }

        if (string.IsNullOrWhiteSpace(s))
        {
            if (PrivilegedRollbackEngine.IsUwpStartupLocation(locationKey))
            {
                string trimmed = locationKey.Replace("::State", string.Empty, StringComparison.OrdinalIgnoreCase);
                int idx2 = trimmed.LastIndexOf('\\');
                string parent = idx2 > 0 ? trimmed[..idx2] : trimmed;
                int idx1 = parent.LastIndexOf('\\');
                string pfn = idx1 >= 0 && idx1 < parent.Length - 1 ? parent[(idx1 + 1)..] : parent;
                s = UwpStartupScanner.ExtractShortPackageName(pfn);
            }
            if (string.IsNullOrWhiteSpace(s))
            {
                int slash = locationKey.LastIndexOf('\\');
                s = slash >= 0 && slash < locationKey.Length - 1 ? locationKey[(slash + 1)..] : locationKey;
            }
        }

        return s;
    }

    private static string ExtractClsid(string locationKey, string rawCmd)
    {
        string c1 = PrivilegedRollbackEngine.ExtractClsidOrIdentifier(locationKey);
        if (!string.IsNullOrEmpty(c1)) return c1;
        return PrivilegedRollbackEngine.ExtractClsidOrIdentifier(rawCmd);
    }

    private static ShellNavigationHelper.AiPromptItemInfo ToAiPromptInfo(CapturedItemViewModel vm) => new(
        vm.CategoryName,
        vm.DisplayName,
        vm.Publisher,
        vm.CommandLineText,
        vm.LocationKey,
        vm.HasMenuScene ? vm.MenuSceneText : null,
        vm.HasClsid ? vm.Clsid : null,
        vm.HasCreatorProcess ? vm.CreatorProcessText : null);

    public static IReadOnlyList<CapturedItemViewModel> GetSelectedItemsForAiPrompt(IEnumerable<CapturedItemViewModel>? items)
        => ShellNavigationHelper.SelectCheckedItems(items, static x => x.IsSelected);

    private void ShowCopyButtonFeedback(string text)
    {
        if (_copyFeedbackTimer == null)
        {
            _copyFeedbackTimer = new System.Windows.Threading.DispatcherTimer
            {
                Interval = TimeSpan.FromMilliseconds(1500)
            };
            _copyFeedbackTimer.Tick += (_, _) =>
            {
                _copyFeedbackTimer?.Stop();
                BtnCopyAiPrompt.Content = "复制 AI 提示词";
            };
        }
        else
        {
            _copyFeedbackTimer.Stop();
        }

        BtnCopyAiPrompt.Content = text;
        _copyFeedbackTimer.Start();
    }

    private void CopyAiPromptText(string prompt)
    {
        if (string.IsNullOrWhiteSpace(prompt)) return;
        try
        {
            System.Windows.Clipboard.SetText(prompt);
            ShowCopyButtonFeedback("已复制提示词 ✓");
        }
        catch { }
    }

    private void BtnCopyAiPrompt_Click(object sender, RoutedEventArgs e)
    {
        var targets = GetSelectedItemsForAiPrompt(_capturedItems);
        if (targets.Count == 0)
        {
            ShowCopyButtonFeedback("请先勾选项目");
            return;
        }
        var prompts = targets.Select(ToAiPromptInfo).ToList();
        CopyAiPromptText(ShellNavigationHelper.BuildAiAgentPrompt(prompts));
    }

    private void MenuCopyItemAiPrompt_Click(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: CapturedItemViewModel vm })
        {
            CopyAiPromptText(ShellNavigationHelper.BuildAiAgentPrompt(ToAiPromptInfo(vm)));
        }
    }

    private static void PopulateActionsForCategory(CapturedItemViewModel vm, MonitorCategory category)
    {
        vm.AvailableActions.Clear();

        switch (category)
        {
            case MonitorCategory.Win32Service:
                vm.AvailableActions.Add(new ActionOptionItem { Title = "回滚为手动启动", Action = InterceptionAction.RollbackToDemand });
                vm.AvailableActions.Add(new ActionOptionItem { Title = "回滚为延迟启动", Action = InterceptionAction.RollbackToDelayedAuto });
                vm.AvailableActions.Add(new ActionOptionItem { Title = "禁止服务", Action = InterceptionAction.RollbackToDisabled });
                vm.AvailableActions.Add(new ActionOptionItem { Title = "删除服务", Action = InterceptionAction.DeleteEntry });
                break;

            case MonitorCategory.ScheduledTask:
                vm.AvailableActions.Add(new ActionOptionItem { Title = "禁止计划任务", Action = InterceptionAction.RollbackToDisabled });
                vm.AvailableActions.Add(new ActionOptionItem { Title = "删除计划任务", Action = InterceptionAction.DeleteEntry });
                break;

            case MonitorCategory.StartupItem:
                vm.AvailableActions.Add(new ActionOptionItem { Title = "禁止启动项", Action = InterceptionAction.RollbackToDisabled });
                vm.AvailableActions.Add(new ActionOptionItem { Title = "删除启动项", Action = InterceptionAction.DeleteEntry });
                break;

            case MonitorCategory.KernelDriver:
                vm.AvailableActions.Add(new ActionOptionItem { Title = "回滚为手动加载", Action = InterceptionAction.RollbackToDemand });
                vm.AvailableActions.Add(new ActionOptionItem { Title = "禁止驱动", Action = InterceptionAction.RollbackToDisabled });
                break;

            case MonitorCategory.ClassicContextMenu:
            case MonitorCategory.ModernContextMenu:
                vm.AvailableActions.Add(new ActionOptionItem { Title = "拦截并屏蔽", Action = InterceptionAction.RollbackToDisabled });
                vm.AvailableActions.Add(new ActionOptionItem { Title = "删除注册项", Action = InterceptionAction.DeleteEntry });
                break;

            default:
                vm.AvailableActions.Add(new ActionOptionItem { Title = "禁止项目", Action = InterceptionAction.RollbackToDisabled });
                vm.AvailableActions.Add(new ActionOptionItem { Title = "删除项目", Action = InterceptionAction.DeleteEntry });
                break;
        }

        var defaultAction = StartupGuard.Core.Configuration.UserSettingsStore.GetDefaultPopupAction(category);
        vm.SelectedAction = vm.AvailableActions.FirstOrDefault(a => a.Action == defaultAction)
                            ?? vm.AvailableActions[0];
    }

    public static bool ShouldUseCloseButton(int selectedCount) => selectedCount <= 0;

    public static string ResolveAllowActionButtonText(int totalCount, int selectedCount, bool rememberRule)
    {
        if (rememberRule)
        {
            return "允许并创建规则";
        }

        return "允许选中";
    }

    public static string ResolvePrimaryActionButtonText(int totalCount, int selectedCount, bool rememberRule)
    {
        if (ShouldUseCloseButton(selectedCount))
        {
            return "关闭";
        }

        if (rememberRule)
        {
            return "阻止并创建规则";
        }

        return totalCount > 1 ? "阻止所选" : "阻止";
    }

    public static List<UserDecisionPayload> BuildDismissDecisions(IEnumerable<CapturedItemViewModel> items)
    {
        return items.Select(item => new UserDecisionPayload
        {
            CorrelationId = item.CorrelationId,
            ChosenAction = InterceptionAction.DismissWithoutChange,
            RememberRule = false,
            ChosenRuleMode = RuleMatchMode.PermanentAdaptive,
            Category = item.Evaluation.Target.Category,
            TargetBinaryPath = item.TargetPath,
            LocationKey = item.LocationKey,
            DisplayName = item.DisplayName
        }).ToList();
    }

    public static List<UserDecisionPayload> BuildPartialSelectedDecisions(
        IReadOnlyList<CapturedItemViewModel> selectedItems,
        bool isAllowSelected,
        bool rememberRule,
        RuleMatchMode ruleMode)
    {
        var decisions = new List<UserDecisionPayload>(selectedItems.Count);
        foreach (var item in selectedItems)
        {
            InterceptionAction chosen = isAllowSelected
                ? InterceptionAction.Allow
                : (item.SelectedAction?.Action ?? InterceptionAction.RollbackToDemand);

            decisions.Add(new UserDecisionPayload
            {
                CorrelationId = item.CorrelationId,
                ChosenAction = chosen,
                RememberRule = rememberRule,
                ChosenRuleMode = ruleMode,
                Category = item.Evaluation.Target.Category,
                TargetBinaryPath = item.TargetPath,
                LocationKey = item.LocationKey,
                DisplayName = item.DisplayName
            });
        }

        return decisions;
    }

    public static List<UserDecisionPayload> BuildSubmittedDecisions(
        IReadOnlyList<CapturedItemViewModel> items,
        bool isAllowAll,
        bool rememberRule,
        RuleMatchMode ruleMode)
    {
        if (!isAllowAll && !items.Any(item => item.IsSelected))
        {
            return BuildDismissDecisions(items);
        }

        var decisions = new List<UserDecisionPayload>(items.Count);
        foreach (var item in items)
        {
            InterceptionAction chosen = isAllowAll
                ? InterceptionAction.Allow
                : (item.IsSelected
                    ? (item.SelectedAction?.Action ?? InterceptionAction.RollbackToDemand)
                    : InterceptionAction.Allow);

            decisions.Add(new UserDecisionPayload
            {
                CorrelationId = item.CorrelationId,
                ChosenAction = chosen,
                RememberRule = !isAllowAll && rememberRule && item.IsSelected,
                ChosenRuleMode = ruleMode,
                Category = item.Evaluation.Target.Category,
                TargetBinaryPath = item.TargetPath,
                LocationKey = item.LocationKey,
                DisplayName = item.DisplayName
            });
        }

        return decisions;
    }

    private void UpdateHeaderSummary()
    {
        int totalCount = _capturedItems.Count;
        int selectedCount = _capturedItems.Count(item => item.IsSelected);
        bool rememberRule = ChkPermanentBlock.IsChecked == true;
        bool useClose = ShouldUseCloseButton(selectedCount);

        TxtHeaderTitle.Text = totalCount > 1
            ? $"检测到 {totalCount} 个新增启动或扩展项"
            : "检测到新增启动或扩展项";

        BtnAllowSelected.Content = ResolveAllowActionButtonText(totalCount, selectedCount, rememberRule);
        BtnAllowSelected.IsEnabled = !useClose;
        BtnBlockSelected.Content = ResolvePrimaryActionButtonText(totalCount, selectedCount, rememberRule);
        BtnBlockSelected.Appearance = useClose ? ControlAppearance.Secondary : ControlAppearance.Danger;
        ChkPermanentBlock.IsEnabled = true;
    }

    private void HeaderDragMove_MouseLeftButtonDown(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        if (e.ChangedButton == System.Windows.Input.MouseButton.Left &&
            e.ButtonState == System.Windows.Input.MouseButtonState.Pressed)
        {
            try { DragMove(); } catch { }
        }
    }

    private static (string Name, string ShortLabel, SymbolRegular Icon, System.Windows.Media.Brush AccentBrush, System.Windows.Media.Brush TintBrush) MapCategory(MonitorCategory category) => category switch
    {
        MonitorCategory.StartupItem => ("自启程序", "自启", SymbolRegular.Rocket24, CreateFrozenBrush("#0078D4"), CreateFrozenBrush("#1A0078D4")),
        MonitorCategory.Win32Service => ("系统服务", "服务", SymbolRegular.Settings24, CreateFrozenBrush("#0F7B0F"), CreateFrozenBrush("#1A0F7B0F")),
        MonitorCategory.KernelDriver => ("内核驱动", "驱动", SymbolRegular.Shield24, CreateFrozenBrush("#C42B1C"), CreateFrozenBrush("#1AC42B1C")),
        MonitorCategory.ScheduledTask => ("计划任务", "任务", SymbolRegular.Clock24, CreateFrozenBrush("#881798"), CreateFrozenBrush("#1A881798")),
        MonitorCategory.ClassicContextMenu => ("经典右键菜单", "旧右键", SymbolRegular.DocumentBulletList24, CreateFrozenBrush("#CA5010"), CreateFrozenBrush("#1ACA5010")),
        MonitorCategory.ModernContextMenu => ("Win11 右键菜单", "Win11", SymbolRegular.Apps24, CreateFrozenBrush("#005FB8"), CreateFrozenBrush("#1A005FB8")),
        MonitorCategory.WindowsPolicy => ("Windows 策略", "策略", SymbolRegular.DocumentLock24, CreateFrozenBrush("#5C5C5C"), CreateFrozenBrush("#1A5C5C5C")),
        _ => ("系统启动项", "启动项", SymbolRegular.Shield24, CreateFrozenBrush("#0078D4"), CreateFrozenBrush("#1A0078D4"))
    };

    private static System.Windows.Media.SolidColorBrush CreateFrozenBrush(string hex)
    {
        var brush = (System.Windows.Media.SolidColorBrush)new System.Windows.Media.BrushConverter().ConvertFromString(hex)!;
        brush.Freeze();
        return brush;
    }

    private void BtnSelectAllToggle_Click(object sender, RoutedEventArgs e)
    {
        bool allChecked = _capturedItems.All(x => x.IsSelected);
        foreach (var item in _capturedItems)
        {
            item.IsSelected = !allChecked;
        }
    }

    private void ChkPermanentBlock_CheckedChanged(object sender, RoutedEventArgs e)
    {
        UpdateHeaderSummary();
    }

    private void BtnAllowSelected_Click(object sender, RoutedEventArgs e)
    {
        SubmitSelectedItems(isAllowSelected: true);
    }

    private void BtnBlockSelected_Click(object sender, RoutedEventArgs e)
    {
        SubmitSelectedItems(isAllowSelected: false);
    }

    private void SubmitSelectedItems(bool isAllowSelected)
    {
        if (_decisionSent) return;

        var selectedItems = _capturedItems.Where(item => item.IsSelected).ToList();
        if (selectedItems.Count == 0)
        {
            if (!isAllowSelected)
            {
                // 未勾选任何项目点击“关闭”：对剩余项发送 DismissWithoutChange 并关闭弹窗
                Close();
            }
            return;
        }

        bool rememberRule = ChkPermanentBlock.IsChecked == true;
        var ruleMode = (CmbRuleMode.SelectedIndex == 1)
            ? RuleMatchMode.StrictCurrentVersion
            : RuleMatchMode.PermanentAdaptive;

        var decisions = BuildPartialSelectedDecisions(selectedItems, isAllowSelected, rememberRule, ruleMode);
        _onBatchDecisionMade(decisions);

        foreach (var handled in selectedItems)
        {
            handled.PropertyChanged -= OnCapturedItemPropertyChanged;
            _capturedItems.Remove(handled);
        }

        if (_capturedItems.Count == 0)
        {
            _decisionSent = true;
            Close();
            return;
        }

        UpdateHeaderSummary();
    }

    private void BtnItemDetail_Click(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: CapturedItemViewModel vm })
        {
            vm.IsDetailsExpanded = !vm.IsDetailsExpanded;
        }
    }

    private void BtnOpenTargetFile_Click(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: CapturedItemViewModel vm })
        {
            ShellNavigationHelper.OpenFileLocationOrFallback(vm.CommandLineText, vm.LocationKey, vm.Evaluation.Target.Category);
        }
    }

    private void BtnOpenRegistry_Click(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: CapturedItemViewModel vm })
        {
            ShellNavigationHelper.LocateStorageLocation(vm.LocationKey, vm.CommandLineText, vm.Evaluation.Target.Category);
        }
    }

    private void MenuFileProperties_Click(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: CapturedItemViewModel vm })
        {
            ShellNavigationHelper.ShowFileProperties(vm.TargetPath);
        }
    }

    private void MenuSearchWeb_Click(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: CapturedItemViewModel vm })
        {
            ShellNavigationHelper.SearchOnline(vm.DisplayName, vm.Publisher);
        }
    }

    private void MenuOpenClsid_Click(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: CapturedItemViewModel vm } && !string.IsNullOrEmpty(vm.Clsid))
        {
            ShellNavigationHelper.LocateInRegistry($@"HKEY_CLASSES_ROOT\CLSID\{vm.Clsid}");
        }
    }

    private async void BtnAnalyzeContextMenu_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not FrameworkElement { Tag: CapturedItemViewModel vm })
            return;

        TxtAnalyzeTitle.Text = vm.DisplayName;
        TxtAnalyzeDllPath.Text = string.IsNullOrEmpty(vm.TargetPath) ? "(无关联处理程序文件)" : vm.TargetPath;
        TxtAnalyzeRegPath.Text = ShellNavigationHelper.FormatForRegeditDisplay(vm.LocationKey);
        TxtAnalyzeClsid.Text = string.IsNullOrEmpty(vm.Clsid) ? "(无 CLSID)" : vm.Clsid;
        TxtAnalyzeProbeBadge.Text = "正在沙盒探测...";
        ListAnalyzeMenuItems.ItemsSource = new[] { new AnalyzedMenuNode { Text = "正在加载右键菜单项..." } };
        DialogDeepAnalysisHost.Visibility = Visibility.Visible;

        var probed = !string.IsNullOrEmpty(vm.Clsid)
            ? await ContextMenuManagerEngine.AnalyzeShellExtensionMenuAsync(vm.Clsid, vm.LocationKey)
            : [];

        if (probed.Count > 0)
        {
            TxtAnalyzeProbeBadge.Text = $"已解析 {probed.Count} 项";
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
                new AnalyzedMenuNode { Text = string.IsNullOrEmpty(vm.Clsid) ? "命令式菜单项 (非 COM 扩展)" : "未在沙盒中探测到静态子菜单（可能为自绘菜单或需要特定文件上下文）" }
            };
        }
    }

    private void BtnAnalyzeClose_Click(object sender, RoutedEventArgs e)
    {
        DialogDeepAnalysisHost.Visibility = Visibility.Collapsed;
    }
}
