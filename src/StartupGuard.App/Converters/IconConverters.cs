using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using StartupGuard.App.Services;
using StartupGuard.Core.Models;

namespace StartupGuard.App.Converters;

/// <summary>
/// 路径或模型到应用高清真实图标的万能转换器
/// </summary>
public sealed class ProgramIconConverter : IValueConverter
{
    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is ImageSource img)
            return img;

        if (value is string path && !string.IsNullOrWhiteSpace(path))
            return ProgramIconResolver.ResolveIcon(path);

        if (value is RuleRecord rule)
            return ProgramIconResolver.ResolveIcon(rule.TargetBinaryOrCommand, rule.Category);

        if (value is AuditLogRecord log)
            return ProgramIconResolver.ResolveIcon(log.TargetProgram, log.Category);

        return null;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw technicalNotSupported();
    private static NotSupportedException technicalNotSupported() => new();
}

/// <summary>
/// 判断是否存在真实图标并控制可见性
/// </summary>
public sealed class HasIconVisibilityConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is bool b)
            return b ? Visibility.Visible : Visibility.Collapsed;

        if (value is ImageSource)
            return Visibility.Visible;

        if (value is string path && !string.IsNullOrWhiteSpace(path))
            return ProgramIconResolver.ResolveIcon(path) != null ? Visibility.Visible : Visibility.Collapsed;

        if (value is RuleRecord rule)
            return ProgramIconResolver.ResolveIcon(rule.TargetBinaryOrCommand, rule.Category) != null ? Visibility.Visible : Visibility.Collapsed;

        if (value is AuditLogRecord log)
            return ProgramIconResolver.ResolveIcon(log.TargetProgram, log.Category) != null ? Visibility.Visible : Visibility.Collapsed;

        return Visibility.Collapsed;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotImplementedException();
}

/// <summary>
/// 反向判断真实图标可见性 (当无真实图标时展示 SymbolIcon 兜底)
/// </summary>
public sealed class InverseHasIconVisibilityConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is bool b)
            return b ? Visibility.Collapsed : Visibility.Visible;

        if (value is ImageSource)
            return Visibility.Collapsed;

        if (value is string path && !string.IsNullOrWhiteSpace(path))
            return ProgramIconResolver.ResolveIcon(path) != null ? Visibility.Collapsed : Visibility.Visible;

        if (value is RuleRecord rule)
            return ProgramIconResolver.ResolveIcon(rule.TargetBinaryOrCommand, rule.Category) != null ? Visibility.Collapsed : Visibility.Visible;

        if (value is AuditLogRecord log)
            return ProgramIconResolver.ResolveIcon(log.TargetProgram, log.Category) != null ? Visibility.Collapsed : Visibility.Visible;

        return Visibility.Visible;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotImplementedException();
}
