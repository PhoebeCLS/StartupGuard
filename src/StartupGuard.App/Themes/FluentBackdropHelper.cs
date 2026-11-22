using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;
using Wpf.Ui.Controls;

namespace StartupGuard.Themes;

/// <summary>
/// 统一应用 Windows 11 原生 DWM Mica 背景材质：
/// 确保 HWND 合成目标为透明并写入 DWMWA_SYSTEMBACKDROP_TYPE = DWMSBT_MAINWINDOW (Mica)，
/// 避免浅色/深色主题切换或 FluentWindow 默认画刷覆盖导致退化为纯白/纯黑底色。
/// </summary>
public static partial class FluentBackdropHelper
{
    private const int DwmwaUseImmersiveDarkMode = 20;
    private const int DwmwaWindowCornerPreference = 33;
    private const int DwmwaSystemBackdropType = 38;
    private const int DwmwcpRound = 2; // Win11 标准圆角
    private const int DwmsbtMainWindow = 2; // Mica

    public static void ApplyMica(Window window, bool isDarkTheme)
    {
        if (window == null)
            return;

        try
        {
            window.Background = System.Windows.Media.Brushes.Transparent;
            if (window is FluentWindow fw)
            {
                fw.ExtendsContentIntoTitleBar = true;
                fw.WindowBackdropType = WindowBackdropType.Mica;
            }

            if (!OperatingSystem.IsWindowsVersionAtLeast(10, 0, 22000))
                return;

            var helper = new WindowInteropHelper(window);
            nint hwnd = helper.Handle;
            if (hwnd == 0)
                return;

            if (HwndSource.FromHwnd(hwnd)?.CompositionTarget is HwndTarget target)
            {
                target.BackgroundColor = System.Windows.Media.Colors.Transparent;
            }

            int cornerPref = DwmwcpRound;
            _ = DwmSetWindowAttribute(hwnd, DwmwaWindowCornerPreference, ref cornerPref, sizeof(int));

            int darkValue = isDarkTheme ? 1 : 0;
            _ = DwmSetWindowAttribute(hwnd, DwmwaUseImmersiveDarkMode, ref darkValue, sizeof(int));

            var margins = new DwmMargins { Left = -1, Right = -1, Top = -1, Bottom = -1 };
            _ = DwmExtendFrameIntoClientArea(hwnd, ref margins);

            if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 22621))
            {
                int micaValue = DwmsbtMainWindow;
                _ = DwmSetWindowAttribute(hwnd, DwmwaSystemBackdropType, ref micaValue, sizeof(int));
            }
            else if (WindowBackdrop.IsSupported(WindowBackdropType.Mica))
            {
                WindowBackdrop.ApplyBackdrop(window, WindowBackdropType.Mica);
            }
        }
        catch
        {
            try
            {
                if (WindowBackdrop.IsSupported(WindowBackdropType.Mica))
                    WindowBackdrop.ApplyBackdrop(window, WindowBackdropType.Mica);
            }
            catch { }
        }
    }

    [LibraryImport("dwmapi.dll")]
    private static partial int DwmExtendFrameIntoClientArea(nint hwnd, ref DwmMargins pMarInset);

    [LibraryImport("dwmapi.dll")]
    private static partial int DwmSetWindowAttribute(nint hwnd, int dwAttribute, ref int pvAttribute, int cbAttribute);

    [StructLayout(LayoutKind.Sequential)]
    private struct DwmMargins
    {
        public int Left;
        public int Right;
        public int Top;
        public int Bottom;
    }
}
