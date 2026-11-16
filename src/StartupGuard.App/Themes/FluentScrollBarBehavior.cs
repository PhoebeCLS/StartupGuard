using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Threading;
using ScrollBar = System.Windows.Controls.Primitives.ScrollBar;

namespace StartupGuard.Themes;

/// <summary>
/// 全局 WinUI 3 / 现代覆盖式自动隐藏滚动条行为：
/// 1. 默认静态时完全隐藏（Opacity = 0），与页面正文零干扰；
/// 2. 仅在发生滚动、滚轮操作或鼠标悬停于滚动条边缘时平滑淡入；
/// 3. 停止滚动或鼠标离开后约 1.1 秒自动淡出隐藏。
/// </summary>
public static class FluentScrollBarBehavior
{
    private const double FadeInMs = 140.0;
    private const double FadeOutMs = 280.0;
    private const double HideDelayMs = 1100.0;

    public static readonly DependencyProperty IsEnabledProperty =
        DependencyProperty.RegisterAttached(
            "IsEnabled",
            typeof(bool),
            typeof(FluentScrollBarBehavior),
            new PropertyMetadata(false, OnIsEnabledChanged));

    private static readonly DependencyProperty ControllerProperty =
        DependencyProperty.RegisterAttached(
            "Controller",
            typeof(ScrollBarAutoHideController),
            typeof(FluentScrollBarBehavior),
            new PropertyMetadata(null));

    public static bool GetIsEnabled(DependencyObject obj) => (bool)obj.GetValue(IsEnabledProperty);

    public static void SetIsEnabled(DependencyObject obj, bool value) => obj.SetValue(IsEnabledProperty, value);

    private static void OnIsEnabledChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is not ScrollBar scrollBar || d is Wpf.Ui.Controls.DynamicScrollBar)
            return;

        if (scrollBar.GetValue(ControllerProperty) is ScrollBarAutoHideController existing)
        {
            existing.Detach();
            scrollBar.ClearValue(ControllerProperty);
        }

        if ((bool)e.NewValue)
        {
            var controller = new ScrollBarAutoHideController(scrollBar);
            scrollBar.SetValue(ControllerProperty, controller);
            controller.Attach();
        }
        else
        {
            scrollBar.BeginAnimation(UIElement.OpacityProperty, null);
            scrollBar.Opacity = 1.0;
        }
    }

    private sealed class ScrollBarAutoHideController
    {
        private readonly ScrollBar _scrollBar;
        private readonly DispatcherTimer _hideTimer;
        private ScrollViewer? _ownerScrollViewer;
        private bool _isDragging;
        private bool _isVisible;

        public ScrollBarAutoHideController(ScrollBar scrollBar)
        {
            _scrollBar = scrollBar;
            _hideTimer = new DispatcherTimer(DispatcherPriority.Background, scrollBar.Dispatcher)
            {
                Interval = TimeSpan.FromMilliseconds(HideDelayMs)
            };
            _hideTimer.Tick += OnHideTimerTick;
        }

        public void Attach()
        {
            _scrollBar.Opacity = 0.0;
            _isVisible = false;

            _scrollBar.Loaded += OnScrollBarLoaded;
            _scrollBar.Unloaded += OnScrollBarUnloaded;
            _scrollBar.MouseEnter += OnScrollBarMouseEnter;
            _scrollBar.MouseLeave += OnScrollBarMouseLeave;
            _scrollBar.AddHandler(Thumb.DragStartedEvent, new DragStartedEventHandler(OnThumbDragStarted), true);
            _scrollBar.AddHandler(Thumb.DragCompletedEvent, new DragCompletedEventHandler(OnThumbDragCompleted), true);

            if (_scrollBar.IsLoaded)
            {
                HookOwnerScrollViewer();
            }
        }

        public void Detach()
        {
            _hideTimer.Stop();
            _hideTimer.Tick -= OnHideTimerTick;

            _scrollBar.Loaded -= OnScrollBarLoaded;
            _scrollBar.Unloaded -= OnScrollBarUnloaded;
            _scrollBar.MouseEnter -= OnScrollBarMouseEnter;
            _scrollBar.MouseLeave -= OnScrollBarMouseLeave;
            _scrollBar.RemoveHandler(Thumb.DragStartedEvent, new DragStartedEventHandler(OnThumbDragStarted));
            _scrollBar.RemoveHandler(Thumb.DragCompletedEvent, new DragCompletedEventHandler(OnThumbDragCompleted));

            UnhookOwnerScrollViewer();
        }

        private void OnScrollBarLoaded(object sender, RoutedEventArgs e)
        {
            HookOwnerScrollViewer();
            if (!_scrollBar.IsMouseOver && !_isDragging)
            {
                _scrollBar.BeginAnimation(UIElement.OpacityProperty, null);
                _scrollBar.Opacity = 0.0;
                _isVisible = false;
            }
        }

        private void OnScrollBarUnloaded(object sender, RoutedEventArgs e)
        {
            _hideTimer.Stop();
            UnhookOwnerScrollViewer();
        }

        private void HookOwnerScrollViewer()
        {
            var found = _scrollBar.TemplatedParent as ScrollViewer ?? FindAncestorScrollViewer(_scrollBar);
            if (ReferenceEquals(found, _ownerScrollViewer))
                return;

            UnhookOwnerScrollViewer();
            _ownerScrollViewer = found;
            if (_ownerScrollViewer != null)
            {
                _ownerScrollViewer.ScrollChanged += OnOwnerScrollChanged;
                _ownerScrollViewer.PreviewMouseWheel += OnOwnerPreviewMouseWheel;
            }
        }

        private void UnhookOwnerScrollViewer()
        {
            if (_ownerScrollViewer == null)
                return;

            _ownerScrollViewer.ScrollChanged -= OnOwnerScrollChanged;
            _ownerScrollViewer.PreviewMouseWheel -= OnOwnerPreviewMouseWheel;
            _ownerScrollViewer = null;
        }

        private void OnScrollBarMouseEnter(object sender, System.Windows.Input.MouseEventArgs e)
        {
            _hideTimer.Stop();
            ShowScrollBar();
        }

        private void OnScrollBarMouseLeave(object sender, System.Windows.Input.MouseEventArgs e)
        {
            if (!_isDragging)
            {
                RestartHideTimer();
            }
        }

        private void OnThumbDragStarted(object sender, DragStartedEventArgs e)
        {
            _isDragging = true;
            _hideTimer.Stop();
            ShowScrollBar();
        }

        private void OnThumbDragCompleted(object sender, DragCompletedEventArgs e)
        {
            _isDragging = false;
            if (!_scrollBar.IsMouseOver)
            {
                RestartHideTimer();
            }
        }

        private void OnOwnerScrollChanged(object sender, ScrollChangedEventArgs e)
        {
            if (!_scrollBar.IsLoaded || _scrollBar.Maximum <= 0)
                return;

            if (Math.Abs(e.VerticalChange) <= 0.1 && Math.Abs(e.HorizontalChange) <= 0.1)
                return;

            ShowScrollBar();
            if (!_scrollBar.IsMouseOver && !_isDragging)
            {
                RestartHideTimer();
            }
        }

        private void OnOwnerPreviewMouseWheel(object sender, MouseWheelEventArgs e)
        {
            if (!_scrollBar.IsLoaded || _scrollBar.Maximum <= 0)
                return;

            ShowScrollBar();
            if (!_scrollBar.IsMouseOver && !_isDragging)
            {
                RestartHideTimer();
            }
        }

        private void OnHideTimerTick(object? sender, EventArgs e)
        {
            _hideTimer.Stop();
            if (_scrollBar.IsMouseOver || _isDragging)
                return;

            HideScrollBar();
        }

        private void RestartHideTimer()
        {
            _hideTimer.Stop();
            _hideTimer.Start();
        }

        private void ShowScrollBar()
        {
            if (_isVisible && _scrollBar.Opacity >= 0.99)
                return;

            _isVisible = true;
            var anim = new DoubleAnimation(1.0, TimeSpan.FromMilliseconds(FadeInMs))
            {
                EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
            };
            _scrollBar.BeginAnimation(UIElement.OpacityProperty, anim);
        }

        private void HideScrollBar()
        {
            _isVisible = false;
            var anim = new DoubleAnimation(0.0, TimeSpan.FromMilliseconds(FadeOutMs))
            {
                EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
            };
            _scrollBar.BeginAnimation(UIElement.OpacityProperty, anim);
        }

        private static ScrollViewer? FindAncestorScrollViewer(DependencyObject start)
        {
            DependencyObject? current = start;
            while (current != null)
            {
                if (current is ScrollViewer sv)
                    return sv;

                current = VisualTreeHelper.GetParent(current);
            }
            return null;
        }
    }
}
