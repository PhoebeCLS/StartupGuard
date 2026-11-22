using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Threading;

namespace StartupGuard.Themes;

/// <summary>
/// 像素级对齐 WinUI 3 官方 ComboBox (SplitOpenThemeAnimation)：
/// 1. 采用 WPF 原生 CustomPopupPlacementCallback + Per-Monitor DPI 换算，弹出首帧即准确落位零跳变；
/// 2. 已选中项 (SelectedIndex >= 0) 原地中心重合，列表内容静止不位移，仅边框裁切以 183ms KeySpline(0.1,0.9,0.2,1.0) 从按钮高度向两端裂开；
/// 3. 未选中项 (SelectedIndex < 0，如 DataGridDynamicColumnsExample) 贴合下方/上方单向平滑揭开并带轻微内容跟进；
/// 4. 单击打开期间防同次点击松手误闭合，阴影随卡片同步柔和显现。
/// </summary>
public static partial class FluentComboBoxBehavior
{
    public static readonly DependencyProperty IsEnabledProperty =
        DependencyProperty.RegisterAttached(
            "IsEnabled",
            typeof(bool),
            typeof(FluentComboBoxBehavior),
            new PropertyMetadata(false, OnIsEnabledChanged));

    private sealed class OpenGuardState
    {
        public DateTime OpenedUtc { get; set; }
        public bool SuppressOpeningRelease { get; set; }
        public System.Windows.Point OpenMouseScreenPx { get; set; }
        public double LastAnchorCenterInBorderDip { get; set; }
        public double LastRawItemCenterInBorderDip { get; set; }
        public bool LastPlacedAboveButton { get; set; }
    }

    private static readonly ConditionalWeakTable<System.Windows.Controls.ComboBox, OpenGuardState> OpenStates = new();
    private static readonly ConditionalWeakTable<Border, System.Windows.Controls.ComboBox> WiredBorders = new();

    public static bool GetIsEnabled(DependencyObject obj) => (bool)obj.GetValue(IsEnabledProperty);

    public static void SetIsEnabled(DependencyObject obj, bool value) => obj.SetValue(IsEnabledProperty, value);

    private static void OnIsEnabledChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is not System.Windows.Controls.ComboBox comboBox)
            return;

        comboBox.Loaded -= ComboBox_Loaded;
        comboBox.SizeChanged -= ComboBox_SizeChanged;
        comboBox.DropDownOpened -= ComboBox_DropDownOpened;
        comboBox.DropDownClosed -= ComboBox_DropDownClosed;

        if ((bool)e.NewValue)
        {
            comboBox.Loaded += ComboBox_Loaded;
            comboBox.SizeChanged += ComboBox_SizeChanged;
            comboBox.DropDownOpened += ComboBox_DropDownOpened;
            comboBox.DropDownClosed += ComboBox_DropDownClosed;
            if (comboBox.IsLoaded)
            {
                AttachCustomPopupCallback(comboBox);
            }
        }
    }

    private static void ComboBox_Loaded(object sender, RoutedEventArgs e)
    {
        if (sender is System.Windows.Controls.ComboBox comboBox)
        {
            AttachCustomPopupCallback(comboBox);
        }
    }

    private static void ComboBox_SizeChanged(object sender, SizeChangedEventArgs e)
    {
        if (sender is System.Windows.Controls.ComboBox comboBox)
        {
            SyncDropDownMinWidth(comboBox);
        }
    }

    private static void AttachCustomPopupCallback(System.Windows.Controls.ComboBox comboBox)
    {
        if (comboBox.Template?.FindName("Popup", comboBox) is Popup popup)
        {
            popup.Placement = PlacementMode.Custom;
            popup.CustomPopupPlacementCallback = (popupSize, targetSize, _) =>
                PlaceComboPopup(comboBox, popupSize, targetSize);
        }

        SyncDropDownMinWidth(comboBox);
    }

    private static void SyncDropDownMinWidth(System.Windows.Controls.ComboBox comboBox)
    {
        if (comboBox.Template?.FindName("DropDownBorder", comboBox) is not Border dropDownBorder)
            return;

        var contentBorder = comboBox.Template.FindName("ContentBorder", comboBox) as FrameworkElement;
        double buttonWidth = contentBorder != null && contentBorder.ActualWidth > 0
            ? contentBorder.ActualWidth
            : comboBox.ActualWidth;
        if (buttonWidth > 0)
        {
            dropDownBorder.MinWidth = buttonWidth + 8.0;
        }
    }

    private static CustomPopupPlacement[] PlaceComboPopup(
        System.Windows.Controls.ComboBox comboBox,
        System.Windows.Size popupSizePx,
        System.Windows.Size targetSizePx)
    {
        var contentBorder = comboBox.Template?.FindName("ContentBorder", comboBox) as FrameworkElement;
        var shadowHost = comboBox.Template?.FindName("PopupShadowHost", comboBox) as Border;
        var dropDownBorder = comboBox.Template?.FindName("DropDownBorder", comboBox) as Border;
        var state = OpenStates.GetOrCreateValue(comboBox);

        DpiScale dpi = VisualTreeHelper.GetDpi(comboBox);
        double scaleX = dpi.DpiScaleX > 0 ? dpi.DpiScaleX : 1.0;
        double scaleY = dpi.DpiScaleY > 0 ? dpi.DpiScaleY : 1.0;

        Thickness shadowPad = shadowHost != null ? shadowHost.Padding : new Thickness(14, 10, 14, 14);
        double buttonWidthDip = targetSizePx.Width > 0 ? targetSizePx.Width / scaleX : (comboBox.ActualWidth > 0 ? comboBox.ActualWidth : 120.0);
        double buttonHeightDip = targetSizePx.Height > 0 ? targetSizePx.Height / scaleY : (comboBox.ActualHeight > 0 ? comboBox.ActualHeight : 32.0);

        double cardWidthDip = dropDownBorder != null && dropDownBorder.ActualWidth > 0
            ? dropDownBorder.ActualWidth
            : Math.Max(buttonWidthDip + 8.0, (popupSizePx.Width / scaleX) - shadowPad.Left - shadowPad.Right);
        double cardHeightDip = dropDownBorder != null && dropDownBorder.ActualHeight > 0
            ? dropDownBorder.ActualHeight
            : Math.Max(32.0, (popupSizePx.Height / scaleY) - shadowPad.Top - shadowPad.Bottom);

        double desiredX_Dip = -4.0 - shadowPad.Left;
        double desiredY_Dip;
        bool placedAbove = false;

        int selectedIdx = comboBox.SelectedIndex;
        if (selectedIdx >= 0 && comboBox.Items.Count > 0)
        {
            double itemCenterYInBorderDip = EstimateOrMeasureItemCenterDip(comboBox, dropDownBorder, selectedIdx, buttonHeightDip, cardHeightDip);
            desiredY_Dip = (buttonHeightDip / 2.0) - (shadowPad.Top + itemCenterYInBorderDip);
            state.LastRawItemCenterInBorderDip = itemCenterYInBorderDip;
            state.LastAnchorCenterInBorderDip = itemCenterYInBorderDip;
        }
        else
        {
            desiredY_Dip = buttonHeightDip + 2.0 - shadowPad.Top;
            if (ShouldFlipAboveWorkArea(contentBorder ?? comboBox, desiredY_Dip, cardHeightDip, shadowPad.Top, buttonHeightDip, scaleY))
            {
                desiredY_Dip = -cardHeightDip - 2.0 - shadowPad.Top;
                placedAbove = true;
            }
            state.LastRawItemCenterInBorderDip = placedAbove ? cardHeightDip : 0.0;
            state.LastAnchorCenterInBorderDip = state.LastRawItemCenterInBorderDip;
        }

        state.LastPlacedAboveButton = placedAbove;

        double xPx = Math.Round(desiredX_Dip * scaleX);
        double yPx = Math.Round(desiredY_Dip * scaleY);

        ClampPopupPlacementToWorkAreaPx(
            contentBorder ?? comboBox,
            ref xPx,
            ref yPx,
            cardWidthDip * scaleX,
            cardHeightDip * scaleY,
            shadowPad.Left * scaleX,
            shadowPad.Top * scaleY);

        if (selectedIdx >= 0 && comboBox.Items.Count > 0)
        {
            // 若被屏幕边界夹紧微调，根据实际位置重新映射按钮中心在边框内的精确锚点
            double finalCardTopDip = (yPx / scaleY) + shadowPad.Top;
            double buttonCenterInBorderDip = (buttonHeightDip / 2.0) - finalCardTopDip;
            state.LastAnchorCenterInBorderDip = Math.Clamp(buttonCenterInBorderDip, 0.0, cardHeightDip);
        }

        return [new CustomPopupPlacement(new System.Windows.Point(xPx, yPx), PopupPrimaryAxis.Vertical)];
    }

    private static double EstimateOrMeasureItemCenterDip(
        System.Windows.Controls.ComboBox comboBox,
        Border? dropDownBorder,
        int selectedIndex,
        double buttonHeightDip,
        double cardHeightDip)
    {
        if (dropDownBorder != null &&
            comboBox.ItemContainerGenerator.ContainerFromIndex(selectedIndex) is FrameworkElement itemContainer &&
            itemContainer.ActualHeight > 0)
        {
            return itemContainer.TranslatePoint(new System.Windows.Point(0, itemContainer.ActualHeight / 2.0), dropDownBorder).Y;
        }

        double estRowStep = Math.Max(36.0, buttonHeightDip + 4.0);
        double estTopPad = 3.0;
        return Math.Clamp(estTopPad + (selectedIndex + 0.5) * estRowStep, estTopPad + 16.0, Math.Max(estTopPad + 16.0, cardHeightDip - 16.0));
    }

    private static bool ShouldFlipAboveWorkArea(
        FrameworkElement anchor,
        double belowDesiredY_Dip,
        double cardHeightDip,
        double shadowTopDip,
        double buttonHeightDip,
        double scaleY)
    {
        try
        {
            if (PresentationSource.FromVisual(anchor) == null)
                return false;

            System.Windows.Point originPx = anchor.PointToScreen(new System.Windows.Point(0, 0));
            System.Windows.Rect workAreaPx = GetMonitorWorkAreaPx((int)originPx.X, (int)originPx.Y);
            if (workAreaPx.Height <= 0)
                return false;

            double bottomPx = originPx.Y + (belowDesiredY_Dip + shadowTopDip + cardHeightDip) * scaleY;
            bool spaceBelowOk = bottomPx <= workAreaPx.Bottom - 6.0;
            if (spaceBelowOk)
                return false;

            double aboveTopPx = originPx.Y - (cardHeightDip + 2.0) * scaleY;
            return aboveTopPx >= workAreaPx.Top + 6.0;
        }
        catch
        {
            return false;
        }
    }

    private static void ClampPopupPlacementToWorkAreaPx(
        FrameworkElement anchor,
        ref double xPx,
        ref double yPx,
        double cardWidthPx,
        double cardHeightPx,
        double shadowLeftPx,
        double shadowTopPx)
    {
        try
        {
            if (PresentationSource.FromVisual(anchor) == null)
                return;

            System.Windows.Point originScreenPx = anchor.PointToScreen(new System.Windows.Point(0, 0));
            System.Windows.Rect workAreaPx = GetMonitorWorkAreaPx((int)originScreenPx.X, (int)originScreenPx.Y);
            if (workAreaPx.Width <= 0 || workAreaPx.Height <= 0)
                return;

            const double EdgePaddingPx = 8.0;
            double cardLeftPx = originScreenPx.X + xPx + shadowLeftPx;
            double cardRightPx = cardLeftPx + cardWidthPx;
            if (cardRightPx > workAreaPx.Right - EdgePaddingPx)
            {
                xPx -= cardRightPx - (workAreaPx.Right - EdgePaddingPx);
                cardLeftPx = originScreenPx.X + xPx + shadowLeftPx;
            }
            if (cardLeftPx < workAreaPx.Left + EdgePaddingPx)
            {
                xPx += (workAreaPx.Left + EdgePaddingPx) - cardLeftPx;
            }

            double cardTopPx = originScreenPx.Y + yPx + shadowTopPx;
            double cardBottomPx = cardTopPx + cardHeightPx;
            if (cardBottomPx > workAreaPx.Bottom - EdgePaddingPx)
            {
                yPx -= cardBottomPx - (workAreaPx.Bottom - EdgePaddingPx);
                cardTopPx = originScreenPx.Y + yPx + shadowTopPx;
            }
            if (cardTopPx < workAreaPx.Top + EdgePaddingPx)
            {
                yPx += (workAreaPx.Top + EdgePaddingPx) - cardTopPx;
            }

            xPx = Math.Round(xPx);
            yPx = Math.Round(yPx);
        }
        catch
        {
            // 非可视树或无句柄环境保留理论计算偏移
        }
    }

    private static void ComboBox_DropDownOpened(object? sender, EventArgs e)
    {
        if (sender is not System.Windows.Controls.ComboBox comboBox)
            return;

        if (comboBox.Template?.FindName("Popup", comboBox) is not Popup popup
            || comboBox.Template.FindName("ContentBorder", comboBox) is not FrameworkElement contentBorder
            || comboBox.Template.FindName("PopupShadowHost", comboBox) is not FrameworkElement shadowHost
            || comboBox.Template.FindName("DropDownBorder", comboBox) is not Border dropDownBorder)
        {
            return;
        }

        popup.Placement = PlacementMode.Custom;
        popup.CustomPopupPlacementCallback = (popupSize, targetSize, _) =>
            PlaceComboPopup(comboBox, popupSize, targetSize);

        double buttonWidth = contentBorder.ActualWidth > 0 ? contentBorder.ActualWidth : comboBox.ActualWidth;
        if (buttonWidth > 0)
        {
            // 左右各宽出 4px，使 ComboBoxItem (Margin="4,2", Padding="11,5") 的文字水平坐标与闭合按钮完全一致
            dropDownBorder.MinWidth = buttonWidth + 8.0;
        }

        if (comboBox.Template.FindName("ToggleButton", comboBox) is ToggleButton toggleButton)
        {
            toggleButton.IsHitTestVisible = false;
        }

        var state = OpenStates.GetOrCreateValue(comboBox);
        state.OpenedUtc = DateTime.UtcNow;
        state.SuppressOpeningRelease = Mouse.LeftButton == MouseButtonState.Pressed;
        if (TryGetCursorPos(out var cursorPt))
        {
            state.OpenMouseScreenPx = new System.Windows.Point(cursorPt.X, cursorPt.Y);
        }

        if (!WiredBorders.TryGetValue(dropDownBorder, out _))
        {
            WiredBorders.Add(dropDownBorder, comboBox);
            dropDownBorder.AddHandler(
                UIElement.PreviewMouseLeftButtonUpEvent,
                new MouseButtonEventHandler(DropDownBorder_PreviewMouseLeftButtonUp),
                handledEventsToo: true);
        }

        var dropDownShadow = comboBox.Template.FindName("DropDownShadow", comboBox) as Border;
        var scrollViewer = comboBox.Template.FindName("DropDownScrollViewer", comboBox) as ScrollViewer;

        dropDownBorder.BeginAnimation(UIElement.OpacityProperty, null);
        dropDownBorder.Clip = null;
        dropDownBorder.Opacity = 0.0;
        if (dropDownShadow != null)
        {
            dropDownShadow.BeginAnimation(UIElement.OpacityProperty, null);
            dropDownShadow.Clip = null;
            dropDownShadow.Opacity = 0.0;
        }

        int targetIndex = comboBox.SelectedIndex >= 0 ? comboBox.SelectedIndex : 0;
        ScrollTargetItemIntoView(comboBox, scrollViewer, targetIndex);
        shadowHost.UpdateLayout();
        dropDownBorder.UpdateLayout();

        if (IsContainerReady(comboBox, dropDownBorder, targetIndex))
        {
            AnimateSplitOpen(comboBox, contentBorder, dropDownBorder, dropDownShadow, state);
            return;
        }

        RoutedEventHandler? onLoaded = null;
        onLoaded = (_, _) =>
        {
            shadowHost.Loaded -= onLoaded;
            if (!comboBox.IsDropDownOpen)
                return;

            ScrollTargetItemIntoView(comboBox, scrollViewer, targetIndex);
            shadowHost.UpdateLayout();
            dropDownBorder.UpdateLayout();
            AnimateSplitOpen(comboBox, contentBorder, dropDownBorder, dropDownShadow, state);
        };
        shadowHost.Loaded += onLoaded;

        comboBox.Dispatcher.BeginInvoke(DispatcherPriority.Loaded, () =>
        {
            shadowHost.Loaded -= onLoaded;
            if (!comboBox.IsDropDownOpen || dropDownBorder.Opacity > 0.01)
                return;

            ScrollTargetItemIntoView(comboBox, scrollViewer, targetIndex);
            shadowHost.UpdateLayout();
            dropDownBorder.UpdateLayout();
            AnimateSplitOpen(comboBox, contentBorder, dropDownBorder, dropDownShadow, state);
        });
    }

    private static void DropDownBorder_PreviewMouseLeftButtonUp(object sender, MouseButtonEventArgs e)
    {
        if (sender is not Border border || !WiredBorders.TryGetValue(border, out var comboBox))
            return;

        if (!OpenStates.TryGetValue(comboBox, out var state) || !state.SuppressOpeningRelease)
            return;

        state.SuppressOpeningRelease = false;
        double elapsedMs = (DateTime.UtcNow - state.OpenedUtc).TotalMilliseconds;
        if (elapsedMs < 300)
        {
            e.Handled = true;
            return;
        }

        if (TryGetCursorPos(out var nowPt))
        {
            double dx = nowPt.X - state.OpenMouseScreenPx.X;
            double dy = nowPt.Y - state.OpenMouseScreenPx.Y;
            if ((dx * dx + dy * dy) < 144.0)
            {
                e.Handled = true;
            }
        }
    }

    private static bool IsContainerReady(System.Windows.Controls.ComboBox comboBox, Border dropDownBorder, int targetIndex)
    {
        if (dropDownBorder.ActualHeight <= 0 || dropDownBorder.ActualWidth <= 0)
            return false;

        if (comboBox.Items.Count == 0)
            return true;

        return comboBox.ItemContainerGenerator.ContainerFromIndex(targetIndex) is FrameworkElement item && item.ActualHeight > 0;
    }

    private static void ScrollTargetItemIntoView(System.Windows.Controls.ComboBox comboBox, ScrollViewer? scrollViewer, int targetIndex)
    {
        if (comboBox.Items.Count <= 0)
            return;

        if (comboBox.ItemContainerGenerator.ContainerFromIndex(targetIndex) is FrameworkElement preItem)
        {
            preItem.BringIntoView();
        }
        else if (scrollViewer != null)
        {
            double ratio = comboBox.Items.Count > 1 ? (double)targetIndex / (comboBox.Items.Count - 1) : 0.0;
            scrollViewer.ScrollToVerticalOffset(scrollViewer.ScrollableHeight * ratio);
        }
    }

    private static void AnimateSplitOpen(
        System.Windows.Controls.ComboBox comboBox,
        FrameworkElement contentBorder,
        Border dropDownBorder,
        Border? dropDownShadow,
        OpenGuardState state)
    {
        if (!comboBox.IsDropDownOpen)
            return;

        double buttonWidth = contentBorder.ActualWidth > 0 ? contentBorder.ActualWidth : comboBox.ActualWidth;
        double buttonHeight = contentBorder.ActualHeight > 0 ? contentBorder.ActualHeight : comboBox.ActualHeight;
        bool hasSelection = comboBox.SelectedIndex >= 0 && comboBox.Items.Count > 0;
        double fullHeight = dropDownBorder.ActualHeight > 0 ? dropDownBorder.ActualHeight : dropDownBorder.DesiredSize.Height;
        if (hasSelection && comboBox.Template?.FindName("Popup", comboBox) is Popup popup)
        {
            double measuredItemCenter = EstimateOrMeasureItemCenterDip(
                comboBox,
                dropDownBorder,
                comboBox.SelectedIndex,
                buttonHeight,
                fullHeight);
            if (Math.Abs(measuredItemCenter - state.LastRawItemCenterInBorderDip) > 1.5)
            {
                popup.HorizontalOffset = 0.01;
                popup.HorizontalOffset = 0.0;
                fullHeight = dropDownBorder.ActualHeight > 0 ? dropDownBorder.ActualHeight : dropDownBorder.DesiredSize.Height;
            }
        }

        double fullWidth = dropDownBorder.ActualWidth > 0 ? dropDownBorder.ActualWidth : Math.Max(buttonWidth + 8.0, dropDownBorder.DesiredSize.Width);

        if (fullWidth <= 0 || fullHeight <= 0)
        {
            dropDownBorder.Opacity = 1.0;
            if (dropDownShadow != null)
                dropDownShadow.Opacity = 1.0;
            return;
        }

        // WinUI 3 Fluent Motion SplitOpenThemeAnimation：183ms + Cubic-bezier(0.1, 0.9, 0.2, 1.0)
        var winUiSpline = new KeySpline(0.1, 0.9, 0.2, 1.0);
        var openDuration = TimeSpan.FromMilliseconds(183);

        double anchorCenterInBorder = hasSelection
            ? Math.Clamp(state.LastAnchorCenterInBorderDip, 0.0, fullHeight)
            : (state.LastPlacedAboveButton ? fullHeight : 0.0);

        double startHeight = hasSelection
            ? Math.Clamp(buttonHeight, 24.0, fullHeight)
            : Math.Clamp(Math.Min(buttonHeight * 0.5, fullHeight * 0.35), 12.0, fullHeight);
        double startTop = hasSelection
            ? Math.Clamp(anchorCenterInBorder - (startHeight / 2.0), 0.0, Math.Max(0.0, fullHeight - startHeight))
            : (state.LastPlacedAboveButton ? Math.Max(0.0, fullHeight - startHeight) : 0.0);

        var startRect = new System.Windows.Rect(0, startTop, fullWidth, startHeight);
        var fullRect = new System.Windows.Rect(0, 0, fullWidth, fullHeight);

        var clipGeometry = new RectangleGeometry(startRect, 8.0, 8.0);
        dropDownBorder.Clip = clipGeometry;
        dropDownBorder.BeginAnimation(UIElement.OpacityProperty, null);

        if (hasSelection)
        {
            // 已选中项原地对齐时直接显现并向双端裂开，文字保持静止无任何跳动
            dropDownBorder.Opacity = 1.0;
        }
        else
        {
            var fadeAnim = new DoubleAnimation(0.0, 1.0, TimeSpan.FromMilliseconds(100))
            {
                EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
            };
            dropDownBorder.BeginAnimation(UIElement.OpacityProperty, fadeAnim);
        }

        var rectAnim = new RectAnimationUsingKeyFrames();
        rectAnim.KeyFrames.Add(new DiscreteRectKeyFrame(startRect, KeyTime.FromTimeSpan(TimeSpan.Zero)));
        rectAnim.KeyFrames.Add(new SplineRectKeyFrame(fullRect, KeyTime.FromTimeSpan(openDuration), winUiSpline));
        rectAnim.Completed += (_, _) =>
        {
            if (dropDownBorder.Clip == clipGeometry)
            {
                dropDownBorder.Clip = null;
            }
        };
        clipGeometry.BeginAnimation(RectangleGeometry.RectProperty, rectAnim);

        if (comboBox.Template?.FindName("ItemsSlideTransform", comboBox) is TranslateTransform itemsSlide)
        {
            itemsSlide.BeginAnimation(TranslateTransform.YProperty, null);
            if (!hasSelection)
            {
                double slideFrom = state.LastPlacedAboveButton ? 10.0 : -10.0;
                var slideAnim = new DoubleAnimationUsingKeyFrames();
                slideAnim.KeyFrames.Add(new DiscreteDoubleKeyFrame(slideFrom, KeyTime.FromTimeSpan(TimeSpan.Zero)));
                slideAnim.KeyFrames.Add(new SplineDoubleKeyFrame(0.0, KeyTime.FromTimeSpan(openDuration), winUiSpline));
                itemsSlide.BeginAnimation(TranslateTransform.YProperty, slideAnim);
            }
            else
            {
                itemsSlide.Y = 0.0;
            }
        }

        if (dropDownShadow != null)
        {
            dropDownShadow.Clip = null;
            var shadowFade = new DoubleAnimation(0.0, 1.0, TimeSpan.FromMilliseconds(183))
            {
                EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
            };
            dropDownShadow.BeginAnimation(UIElement.OpacityProperty, shadowFade);
        }
    }

    private static void ComboBox_DropDownClosed(object? sender, EventArgs e)
    {
        if (sender is not System.Windows.Controls.ComboBox comboBox || comboBox.Template == null)
            return;

        if (OpenStates.TryGetValue(comboBox, out var state))
        {
            state.SuppressOpeningRelease = false;
        }

        if (comboBox.Template.FindName("Popup", comboBox) is Popup popup)
        {
            popup.HorizontalOffset = 0.0;
        }

        if (comboBox.Template.FindName("ToggleButton", comboBox) is ToggleButton toggleButton)
        {
            comboBox.Dispatcher.BeginInvoke(DispatcherPriority.Input, () =>
            {
                if (!comboBox.IsDropDownOpen)
                {
                    toggleButton.IsHitTestVisible = true;
                }
            });
        }

        if (comboBox.Template.FindName("DropDownBorder", comboBox) is Border dropDownBorder)
        {
            dropDownBorder.BeginAnimation(UIElement.OpacityProperty, null);
            dropDownBorder.Clip = null;
            dropDownBorder.Opacity = 0.0;
        }

        if (comboBox.Template.FindName("DropDownShadow", comboBox) is Border dropDownShadow)
        {
            dropDownShadow.BeginAnimation(UIElement.OpacityProperty, null);
            dropDownShadow.Clip = null;
            dropDownShadow.Opacity = 0.0;
        }
    }

    private static System.Windows.Rect GetMonitorWorkAreaPx(int x, int y)
    {
        nint hMonitor = MonitorFromPoint(new NativePoint { X = x, Y = y }, MonitorDefaultToNearest);
        if (hMonitor != 0)
        {
            var info = new MonitorInfo { Size = Marshal.SizeOf<MonitorInfo>() };
            if (GetMonitorInfoW(hMonitor, ref info))
            {
                return new System.Windows.Rect(
                    info.Work.Left,
                    info.Work.Top,
                    info.Work.Right - info.Work.Left,
                    info.Work.Bottom - info.Work.Top);
            }
        }

        return new System.Windows.Rect(
            SystemParameters.WorkArea.Left,
            SystemParameters.WorkArea.Top,
            SystemParameters.WorkArea.Width,
            SystemParameters.WorkArea.Height);
    }

    private const uint MonitorDefaultToNearest = 2;

    [LibraryImport("user32.dll")]
    private static partial nint MonitorFromPoint(NativePoint pt, uint dwFlags);

    [LibraryImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetMonitorInfoW(nint hMonitor, ref MonitorInfo lpmi);

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetCursorPos(out NativePoint lpPoint);

    private static bool TryGetCursorPos(out NativePoint point) => GetCursorPos(out point);

    [StructLayout(LayoutKind.Sequential)]
    private struct NativePoint
    {
        public int X;
        public int Y;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeRect
    {
        public int Left;
        public int Top;
        public int Right;
        public int Bottom;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MonitorInfo
    {
        public int Size;
        public NativeRect Monitor;
        public NativeRect Work;
        public uint Flags;
    }
}
