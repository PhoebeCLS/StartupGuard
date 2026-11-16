using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Threading;

namespace StartupGuard.Themes;

/// <summary>
/// WinUI 3 风格 ComboBox 原地展开与 SplitOpenThemeAnimation 行为：
/// 1. 在首帧渲染前确保容器完成测量（含首次打开时的延迟 Loaded 测量），精确对齐 Popup 使选中项与原按钮原地重合；
/// 2. 使用 RectangleGeometry 裁剪框从选中项中心向四周丝滑切开展开，绝不缩放扭曲文字像素；
/// 3. 自动对齐当前显示器工作区边界，避免小屏幕下菜单超出视野。
/// </summary>
public static partial class FluentComboBoxBehavior
{
    public static readonly DependencyProperty IsEnabledProperty =
        DependencyProperty.RegisterAttached(
            "IsEnabled",
            typeof(bool),
            typeof(FluentComboBoxBehavior),
            new PropertyMetadata(false, OnIsEnabledChanged));

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

        var dropDownShadow = comboBox.Template.FindName("DropDownShadow", comboBox) as Border;
        var scrollViewer = comboBox.Template.FindName("DropDownScrollViewer", comboBox) as ScrollViewer;

        // 先隐身再定位，防止首次打开容器未生成时闪现错位帧
        dropDownBorder.BeginAnimation(UIElement.OpacityProperty, null);
        dropDownBorder.Clip = null;
        dropDownBorder.Opacity = 0.0;
        if (dropDownShadow != null)
        {
            dropDownShadow.BeginAnimation(UIElement.OpacityProperty, null);
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

        // 首次打开时 ItemsPresenter 会在 Popup 可视树 Loaded 时才生成子项容器
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

        // 双保险：Loaded 若已触发但布局仍在下一优先级队列，则在 Loaded 优先级补齐一次对齐
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

        // 让选中项几何中心与闭合按钮几何中心完全重合（真正原地展开）
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

        // WinUI 3 SplitOpenThemeAnimation 标准 KeySpline(0.1, 0.9, 0.2, 1.0)
        var winUiSpline = new KeySpline(0.1, 0.9, 0.2, 1.0);
        var duration = TimeSpan.FromMilliseconds(167);

        var rectAnim = new RectAnimationUsingKeyFrames();
        rectAnim.KeyFrames.Add(new DiscreteRectKeyFrame(startRect, KeyTime.FromTimeSpan(TimeSpan.Zero)));
        rectAnim.KeyFrames.Add(new SplineRectKeyFrame(fullRect, KeyTime.FromTimeSpan(duration), winUiSpline));
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
            double slideFrom = midRatio < 0.35 ? -8.0 : (midRatio > 0.65 ? 8.0 : 0.0);
            itemsSlide.BeginAnimation(TranslateTransform.YProperty, null);
            if (Math.Abs(slideFrom) > 0.5)
            {
                var slideAnim = new DoubleAnimationUsingKeyFrames();
                slideAnim.KeyFrames.Add(new DiscreteDoubleKeyFrame(slideFrom, KeyTime.FromTimeSpan(TimeSpan.Zero)));
                slideAnim.KeyFrames.Add(new SplineDoubleKeyFrame(0.0, KeyTime.FromTimeSpan(duration), winUiSpline));
                itemsSlide.BeginAnimation(TranslateTransform.YProperty, slideAnim);
            }
            else
            {
                itemsSlide.Y = 0.0;
            }
        }

        if (dropDownShadow != null)
        {
            var shadowAnim = new DoubleAnimationUsingKeyFrames();
            shadowAnim.KeyFrames.Add(new DiscreteDoubleKeyFrame(0.0, KeyTime.FromTimeSpan(TimeSpan.Zero)));
            shadowAnim.KeyFrames.Add(new SplineDoubleKeyFrame(1.0, KeyTime.FromTimeSpan(TimeSpan.FromMilliseconds(140)), winUiSpline));
            dropDownShadow.BeginAnimation(UIElement.OpacityProperty, shadowAnim);
        }
    }

    private static void ComboBox_DropDownClosed(object? sender, EventArgs e)
    {
        if (sender is not System.Windows.Controls.ComboBox comboBox || comboBox.Template == null)
            return;

        if (comboBox.Template.FindName("DropDownBorder", comboBox) is Border dropDownBorder)
        {
            dropDownBorder.BeginAnimation(UIElement.OpacityProperty, null);
            dropDownBorder.Clip = null;
            dropDownBorder.Opacity = 0.0;
        }

        if (comboBox.Template.FindName("DropDownShadow", comboBox) is Border dropDownShadow)
        {
            dropDownShadow.BeginAnimation(UIElement.OpacityProperty, null);
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
