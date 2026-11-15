using System.Collections.Concurrent;
using System.IO;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using StartupGuard.Core.Models;
using StartupGuard.Core.Native;

namespace StartupGuard.App.Services;

/// <summary>
/// 高性能原生程序图标提取与内存缓存器
/// 为自启程序、Win32服务、计划任务关联程序、外壳扩展 DLL 以及内核驱动智能提取真实应用高清图标
/// </summary>
public static class ProgramIconResolver
{
    private static readonly ConcurrentDictionary<string, ImageSource?> _iconCache = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// 根据路径或命令行解析真实程序的高清图标 ImageSource
    /// </summary>
    public static ImageSource? ResolveIcon(string? pathOrCommand, MonitorCategory category = MonitorCategory.StartupItem)
    {
        if (string.IsNullOrWhiteSpace(pathOrCommand))
            return null;

        if (_iconCache.TryGetValue(pathOrCommand, out var cached))
            return cached;

        if (!OperatingSystem.IsWindows())
            return null;

        try
        {
            string cleanPath = ShellNavigationHelper.ResolvePhysicalFilePath(pathOrCommand);
            if (!string.IsNullOrEmpty(cleanPath) && _iconCache.TryGetValue(cleanPath, out cached))
            {
                _iconCache[pathOrCommand] = cached;
                return cached;
            }

            if (string.IsNullOrEmpty(cleanPath) || !File.Exists(cleanPath))
            {
                _iconCache[pathOrCommand] = null;
                return null;
            }

            using var icon = System.Drawing.Icon.ExtractAssociatedIcon(cleanPath);
            if (icon == null)
            {
                _iconCache[cleanPath] = null;
                _iconCache[pathOrCommand] = null;
                return null;
            }

            var bitmapSource = Imaging.CreateBitmapSourceFromHIcon(
                icon.Handle,
                Int32Rect.Empty,
                BitmapSizeOptions.FromEmptyOptions());

            bitmapSource.Freeze(); // 冻结以确保支持跨线程与虚拟化渲染

            _iconCache[cleanPath] = bitmapSource;
            _iconCache[pathOrCommand] = bitmapSource;
            return bitmapSource;
        }
        catch
        {
            _iconCache[pathOrCommand] = null;
            return null;
        }
    }
}
