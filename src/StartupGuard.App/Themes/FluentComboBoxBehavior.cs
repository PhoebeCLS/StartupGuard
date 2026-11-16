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
/// 对齐 WinUI 3 官方 SplitOpenThemeAnimation 实现（250ms + Cubic-bezier(0, 0, 0, 1)）：
/// 1. 弹出层基于当前选中项与闭合按钮原地垂直居中对齐，并自动避让显示器工作区边缘；
/// 2. 卡片主体与阴影层使用完全同步的裁切几何体（250ms KeySpline(0,0,0,1)）从按钮位置展开，消除阴影先行黑块或位置跳变；
/// 3. 按下展开期间锁定 Trigger ToggleButton 并拦截同次点击松手落回原地选中项导致的误闭合，单击即可稳稳停留在展开态。
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
    }

    private static readonly ConditionalWeakTable<System.Windows.Controls.ComboBox, OpenGuardState> OpenStates = new();
    private static readonly ConditionalWeakTable<Border, System.Windows.Controls.ComboBox> WiredBorders = new();

    public static bool GetIsEnabled(DependencyObject obj) => (bool)obj.GetValue(IsEnabledProperty);

    public static void SetIsEnabled(DependencyObject obj, bool value) => obj.SetValue(IsEnabledProperty, value);

    private static void OnIsEnabledChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is not System.Windows.Controls.ComboBox comboBox)
            return;

        comboBox.DropDownOpened -= ComboBox_DropDownOpened;
        comboBox.DropDownClosed -= ComboBox_DropDownClosed;

        if ((bool)e.NewValue)
        {
            comboBox.DropDownOpened += ComboBox_DropDownOpened;
            comboBox.DropDownClosed += ComboBox_DropDownClosed;
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

        popup.Placement = PlacementMode.Relative;
        popup.PlacementTarget = contentBorder;

        int targetIndex = comboBox.SelectedIndex >= 0 ? comboBox.SelectedIndex : 0;
        ScrollTargetItemIntoView(comboBox, scrollViewer, targetIndex);
        shadowHost.UpdateLayout();
        dropDownBorder.UpdateLayout();

        if (IsContainerReady(comboBox, dropDownBorder, targetIndex))
        {
            PositionAndAnimate(comboBox, popup, contentBorder, shadowHost, dropDownBorder, dropDownShadow, scrollViewer, targetIndex);
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
            PositionAndAnimate(comboBox, popup, contentBorder, shadowHost, dropDownBorder, dropDownShadow, scrollViewer, targetIndex);
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
            PositionAndAnimate(comboBox, popup, contentBorder, shadowHost, dropDownBorder, dropDownShadow, scrollViewer, targetIndex);
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

    private static void PositionAndAnimate(
        System.Windows.Controls.ComboBox comboBox,
        Popup popup,
        FrameworkElement contentBorder,
        FrameworkElement shadowHost,
        Border dropDownBorder,
        Border? dropDownShadow,
        ScrollViewer? scrollViewer,
        int targetIndex)
    {
        if (!comboBox.IsDropDownOpen)
            return;

        ScrollTargetItemIntoView(comboBox, scrollViewer, targetIndex);
        shadowHost.UpdateLayout();
        dropDownBorder.UpdateLayout();

        System.Windows.Point borderOriginInHost = dropDownBorder.TranslatePoint(new System.Windows.Point(0, 0), shadowHost);
        double shadowLeft = borderOriginInHost.X;
        double shadowTop = borderOriginInHost.Y;
        popup.HorizontalOffset = Math.Round(-shadowLeft);

        double buttonWidth = contentBorder.ActualWidth > 0 ? contentBorder.ActualWidth : comboBox.ActualWidth;
        double buttonHeight = contentBorder.ActualHeight > 0 ? contentBorder.ActualHeight : comboBox.ActualHeight;
        double fullWidth = dropDownBorder.ActualWidth > 0 ? dropDownBorder.ActualWidth : Math.Max(buttonWidth, dropDownBorder.DesiredSize.Width);
        double fullHeight = dropDownBorder.ActualHeight > 0 ? dropDownBorder.ActualHeight : dropDownBorder.DesiredSize.Height;

        double itemHeight = Math.Min(32.0, Math.Max(24.0, buttonHeight));
        double itemCenterYInHost = shadowTop + (fullHeight / 2.0);
        double itemCenterYInBorder = fullHeight / 2.0;

        if (comboBox.Items.Count > 0
            && comboBox.ItemContainerGenerator.ContainerFromIndex(targetIndex) is FrameworkElement itemContainer
            && itemContainer.ActualHeight > 0)
        {
            itemHeight = itemContainer.ActualHeight;
            itemCenterYInHost = itemContainer.TranslatePoint(new System.Windows.Point(0, itemHeight / 2.0), shadowHost).Y;
            itemCenterYInBorder = itemContainer.TranslatePoint(new System.Windows.Point(0, itemHeight / 2.0), dropDownBorder).Y;
        }

        double desiredVerticalOffset = (buttonHeight / 2.0) - itemCenterYInHost;
        popup.VerticalOffset = Math.Round(ClampVerticalOffsetToWorkArea(contentBorder, desiredVerticalOffset, fullHeight, shadowTop));

        if (fullWidth <= 0 || fullHeight <= 0)
        {
            dropDownBorder.Opacity = 1.0;
            if (dropDownShadow != null)
                dropDownShadow.Opacity = 1.0;
            return;
        }

        double anchorCenterInBorder = (buttonHeight / 2.0) - (popup.VerticalOffset + shadowTop);
        if (Math.Abs(anchorCenterInBorder - itemCenterYInBorder) < 2.0)
            anchorCenterInBorder = itemCenterYInBorder;

        double startHeight = Math.Clamp(Math.Max(buttonHeight, itemHeight), 24.0, fullHeight);
        double startTop = Math.Clamp(anchorCenterInBorder - (startHeight / 2.0), 0.0, Math.Max(0.0, fullHeight - startHeight));

        var startRect = new System.Windows.Rect(0, startTop, fullWidth, startHeight);
        var fullRect = new System.Windows.Rect(0, 0, fullWidth, fullHeight);

        var clipGeometry = new RectangleGeometry(startRect, 8.0, 8.0);
        dropDownBorder.Clip = clipGeometry;
        dropDownBorder.BeginAnimation(UIElement.OpacityProperty, null);
        dropDownBorder.Opacity = 1.0;

        // WinUI 3 ThemeAnimations.cpp 官方 SplitOpenThemeAnimation 参数：
        // s_OpenDuration = 250ms, Cubic-bezier(0, 0, 0, 1)
        var winUiSplitSpline = new KeySpline(0.0, 0.0, 0.0, 1.0);
        var openDuration = TimeSpan.FromMilliseconds(250);

        var rectAnim = new RectAnimationUsingKeyFrames();
        rectAnim.KeyFrames.Add(new DiscreteRectKeyFrame(startRect, KeyTime.FromTimeSpan(TimeSpan.Zero)));
        rectAnim.KeyFrames.Add(new SplineRectKeyFrame(fullRect, KeyTime.FromTimeSpan(openDuration), winUiSplitSpline));
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
            double midRatio = fullHeight > 0 ? anchorCenterInBorder / fullHeight : 0.5;
            double slideFrom = midRatio < 0.35 ? -10.0 : (midRatio > 0.65 ? 10.0 : 0.0);
            itemsSlide.BeginAnimation(TranslateTransform.YProperty, null);
            if (Math.Abs(slideFrom) > 0.5)
            {
                var slideAnim = new DoubleAnimationUsingKeyFrames();
                slideAnim.KeyFrames.Add(new DiscreteDoubleKeyFrame(slideFrom, KeyTime.FromTimeSpan(TimeSpan.Zero)));
                slideAnim.KeyFrames.Add(new SplineDoubleKeyFrame(0.0, KeyTime.FromTimeSpan(openDuration), winUiSplitSpline));
                itemsSlide.BeginAnimation(TranslateTransform.YProperty, slideAnim);
            }
            else
            {
                itemsSlide.Y = 0.0;
            }
        }

        // 阴影层使用同步扩展裁切（外扩 24px 保留完整模糊边缘）与卡片本体同帧揭开，绝不提前露出孤立黑影
        if (dropDownShadow != null)
        {
            const double Pad = 24.0;
            var shadowStartRect = new System.Windows.Rect(-Pad, startTop - Pad, fullWidth + (Pad * 2.0), startHeight + (Pad * 2.0));
            var shadowFullRect = new System.Windows.Rect(-Pad, -Pad, fullWidth + (Pad * 2.0), fullHeight + (Pad * 2.0));
            var shadowClip = new RectangleGeometry(shadowStartRect);
            dropDownShadow.Clip = shadowClip;
            dropDownShadow.BeginAnimation(UIElement.OpacityProperty, null);
            dropDownShadow.Opacity = 1.0;

            var shadowClipAnim = new RectAnimationUsingKeyFrames();
            shadowClipAnim.KeyFrames.Add(new DiscreteRectKeyFrame(shadowStartRect, KeyTime.FromTimeSpan(TimeSpan.Zero)));
            shadowClipAnim.KeyFrames.Add(new SplineRectKeyFrame(shadowFullRect, KeyTime.FromTimeSpan(openDuration), winUiSplitSpline));
            shadowClipAnim.Completed += (_, _) =>
            {
                if (dropDownShadow.Clip == shadowClip)
                {
                    dropDownShadow.Clip = null;
                }
            };
            shadowClip.BeginAnimation(RectangleGeometry.RectProperty, shadowClipAnim);
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

    private static double ClampVerticalOffsetToWorkArea(
        FrameworkElement target,
        double verticalOffset,
        double cardHeight,
        double shadowTop)
    {
        try
        {
            var source = PresentationSource.FromVisual(target);
            if (source?.CompositionTarget == null)
                return verticalOffset;

            System.Windows.Point originScreenPx = target.PointToScreen(new System.Windows.Point(0, 0));
            System.Windows.Rect workAreaPx = GetMonitorWorkAreaPx((int)originScreenPx.X, (int)originScreenPx.Y);
            if (workAreaPx.Width <= 0 || workAreaPx.Height <= 0)
                return verticalOffset;

            Matrix fromDevice = source.CompositionTarget.TransformFromDevice;
            System.Windows.Point originDip = fromDevice.Transform(originScreenPx);
            System.Windows.Point workTopLeftDip = fromDevice.Transform(workAreaPx.TopLeft);
            System.Windows.Point workBottomRightDip = fromDevice.Transform(workAreaPx.BottomRight);

            const double EdgePadding = 6.0;
            double cardTopDip = originDip.Y + verticalOffset + shadowTop;
            double cardBottomDip = cardTopDip + cardHeight;

            if (cardBottomDip > workBottomRightDip.Y - EdgePadding)
            {
                verticalOffset -= cardBottomDip - (workBottomRightDip.Y - EdgePadding);
                cardTopDip = originDip.Y + verticalOffset + shadowTop;
            }

            if (cardTopDip < workTopLeftDip.Y + EdgePadding)
            {
                verticalOffset += (workTopLeftDip.Y + EdgePadding) - cardTopDip;
            }
        }
        catch
        {
            // 非可视树挂载或离屏截图场景维持理论原地偏移
        }

        return verticalOffset;
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
