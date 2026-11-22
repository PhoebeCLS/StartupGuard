using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Animation;

namespace StartupGuard.Themes;

/// <summary>
/// WinUI 3 ContentDialog 对齐的弹出动画行为：
/// 遮罩平滑淡入（150ms），居中圆角卡片从 1.04 轻微收敛至 1.0（167ms CubicEase Out）。
/// </summary>
public static class FluentDialogBehavior
{
    public static void PlayOpenAnimation(System.Windows.Controls.Grid? host)
    {
        if (host == null)
            return;

        var fadeEase = new CubicEase { EasingMode = EasingMode.EaseOut };
        var hostFade = new DoubleAnimation(0.0, 1.0, TimeSpan.FromMilliseconds(150))
        {
            EasingFunction = fadeEase
        };
        host.BeginAnimation(UIElement.OpacityProperty, null);
        host.BeginAnimation(UIElement.OpacityProperty, hostFade);

        var card = host.Children.OfType<FrameworkElement>().FirstOrDefault();
        if (card == null)
            return;

        card.RenderTransformOrigin = new System.Windows.Point(0.5, 0.5);
        if (card.RenderTransform is not ScaleTransform scale || scale.IsFrozen)
        {
            scale = new ScaleTransform(1.0, 1.0);
            card.RenderTransform = scale;
        }

        var scaleEase = new CubicEase { EasingMode = EasingMode.EaseOut };
        var scaleDuration = TimeSpan.FromMilliseconds(167);

        var scaleXAnim = new DoubleAnimation(1.04, 1.0, scaleDuration) { EasingFunction = scaleEase };
        var scaleYAnim = new DoubleAnimation(1.04, 1.0, scaleDuration) { EasingFunction = scaleEase };
        var cardFade = new DoubleAnimation(0.0, 1.0, TimeSpan.FromMilliseconds(150)) { EasingFunction = fadeEase };

        scale.BeginAnimation(ScaleTransform.ScaleXProperty, null);
        scale.BeginAnimation(ScaleTransform.ScaleYProperty, null);
        scale.BeginAnimation(ScaleTransform.ScaleXProperty, scaleXAnim);
        scale.BeginAnimation(ScaleTransform.ScaleYProperty, scaleYAnim);

        card.BeginAnimation(UIElement.OpacityProperty, null);
        card.BeginAnimation(UIElement.OpacityProperty, cardFade);
    }
}
