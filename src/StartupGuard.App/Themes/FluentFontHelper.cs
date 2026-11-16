using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Media;

namespace StartupGuard.Themes;

/// <summary>
/// 运行时界面字体解析辅助：
/// 在遵循默认 Microsoft YaHei UI / Segoe UI Variable Text 字体链的基础上，
/// 自动兼容系统级字体渲染替代配置（如 MacType FontSubstitutes），避免 WPF 绕过系统字体映射导致视觉不一致。
/// </summary>
public static partial class FluentFontHelper
{
    private const string DefaultFontFamilySpec = "Microsoft YaHei UI, Segoe UI Variable Text, Segoe UI";
    private static readonly object SyncLock = new();
    private static System.Windows.Media.FontFamily? _cachedFontFamily;

    public static System.Windows.Media.FontFamily GetPreferredUiFontFamily()
    {
        if (_cachedFontFamily != null)
            return _cachedFontFamily;

        lock (SyncLock)
        {
            if (_cachedFontFamily != null)
                return _cachedFontFamily;

            string? substituted = TryResolveActiveSubstituteFont();
            string spec = !string.IsNullOrWhiteSpace(substituted)
                ? $"{substituted}, {DefaultFontFamilySpec}"
                : DefaultFontFamilySpec;

            _cachedFontFamily = new System.Windows.Media.FontFamily(spec);
            return _cachedFontFamily;
        }
    }

    public static void ApplyPreferredFont(Window? window = null)
    {
        var fontFamily = GetPreferredUiFontFamily();

        if (System.Windows.Application.Current?.Resources != null)
        {
            System.Windows.Application.Current.Resources["AppFont"] = fontFamily;
        }

        if (window != null)
        {
            window.FontFamily = fontFamily;
        }
    }

    private static string? TryResolveActiveSubstituteFont()
    {
        try
        {
            string? macTypeRoot = FindActiveMacTypeDirectory();
            if (string.IsNullOrEmpty(macTypeRoot))
                return null;

            string mainIniPath = Path.Combine(macTypeRoot, "MacType.ini");
            if (!File.Exists(mainIniPath))
                return null;

            string? exeName = Path.GetFileName(Environment.ProcessPath);
            if (!string.IsNullOrEmpty(exeName) && IsProcessExcluded(mainIniPath, exeName))
                return null;

            string? profilePath = ResolveProfilePath(macTypeRoot, mainIniPath);
            if (string.IsNullOrEmpty(profilePath) || !File.Exists(profilePath))
                return null;

            if (!string.IsNullOrEmpty(exeName) && IsProcessExcluded(profilePath, exeName))
                return null;

            if (!IsFontSubstitutesEnabled(profilePath))
                return null;

            string? targetFont = ReadSubstitutedUiFont(profilePath);
            if (string.IsNullOrWhiteSpace(targetFont))
                return null;

            if (!IsSystemFontInstalled(targetFont))
                return null;

            return targetFont;
        }
        catch
        {
            return null;
        }
    }

    private static string? FindActiveMacTypeDirectory()
    {
        bool moduleLoaded = GetModuleHandleW("MacType64.Core.dll") != 0
                            || GetModuleHandleW("MacType64.dll") != 0
                            || GetModuleHandleW("MacType.dll") != 0;

        string? trayDir = null;
        bool trayRunning = false;
        try
        {
            var procs = Process.GetProcessesByName("MacTray");
            trayRunning = procs.Length > 0;
            foreach (var p in procs)
            {
                try
                {
                    if (trayDir == null)
                    {
                        string? path = p.MainModule?.FileName;
                        if (!string.IsNullOrEmpty(path))
                            trayDir = Path.GetDirectoryName(path);
                    }
                }
                catch { }
                finally
                {
                    p.Dispose();
                }
            }
        }
        catch { }

        if (!moduleLoaded && !trayRunning)
            return null;

        if (!string.IsNullOrEmpty(trayDir) && File.Exists(Path.Combine(trayDir, "MacType.ini")))
            return trayDir;

        string pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        string pf86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        foreach (string dir in new[]
        {
            Path.Combine(pf, "MacType"),
            Path.Combine(pf86, "MacType")
        })
        {
            if (File.Exists(Path.Combine(dir, "MacType.ini")))
                return dir;
        }

        return null;
    }

    private static string? ResolveProfilePath(string macTypeRoot, string mainIniPath)
    {
        string? section = null;
        foreach (string raw in File.ReadLines(mainIniPath))
        {
            string line = raw.Trim();
            if (line.Length == 0 || line[0] is ';' or '#')
                continue;

            if (line.StartsWith('[') && line.EndsWith(']'))
            {
                section = line[1..^1].Trim();
                continue;
            }

            if (string.Equals(section, "General", StringComparison.OrdinalIgnoreCase))
            {
                int eq = line.IndexOf('=');
                if (eq > 0 && string.Equals(line[..eq].Trim(), "AlternativeFile", StringComparison.OrdinalIgnoreCase))
                {
                    string rel = line[(eq + 1)..].Trim().Trim('"');
                    if (!string.IsNullOrEmpty(rel))
                        return Path.IsPathRooted(rel) ? rel : Path.GetFullPath(Path.Combine(macTypeRoot, rel));
                }
            }
        }
        return null;
    }

    private static bool IsProcessExcluded(string iniPath, string exeName)
    {
        string? section = null;
        foreach (string raw in File.ReadLines(iniPath))
        {
            string line = raw.Trim();
            if (line.Length == 0 || line[0] is ';' or '#')
                continue;

            if (line.StartsWith('[') && line.EndsWith(']'))
            {
                section = line[1..^1].Trim();
                continue;
            }

            if (string.Equals(section, "UnloadDll", StringComparison.OrdinalIgnoreCase)
                || string.Equals(section, "ExcludeSub", StringComparison.OrdinalIgnoreCase))
            {
                if (string.Equals(line, exeName, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
        }
        return false;
    }

    private static bool IsFontSubstitutesEnabled(string profilePath)
    {
        string? section = null;
        foreach (string raw in File.ReadLines(profilePath))
        {
            string line = raw.Trim();
            if (line.Length == 0 || line[0] is ';' or '#')
                continue;

            if (line.StartsWith('[') && line.EndsWith(']'))
            {
                section = line[1..^1].Trim();
                continue;
            }

            if (string.Equals(section, "General", StringComparison.OrdinalIgnoreCase))
            {
                int eq = line.IndexOf('=');
                if (eq > 0 && string.Equals(line[..eq].Trim(), "FontSubstitutes", StringComparison.OrdinalIgnoreCase))
                    return line[(eq + 1)..].Trim() == "1";
            }
        }
        return false;
    }

    private static string? ReadSubstitutedUiFont(string profilePath)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        string? section = null;

        foreach (string raw in File.ReadLines(profilePath))
        {
            string line = raw.Trim();
            if (line.Length == 0 || line[0] is ';' or '#')
                continue;

            if (line.StartsWith('[') && line.EndsWith(']'))
            {
                section = line[1..^1].Trim();
                continue;
            }

            if (string.Equals(section, "FontSubstitutes", StringComparison.OrdinalIgnoreCase))
            {
                int eq = line.IndexOf('=');
                if (eq > 0)
                {
                    string key = line[..eq].Trim();
                    string val = line[(eq + 1)..].Trim();
                    if (!string.IsNullOrEmpty(key) && !string.IsNullOrEmpty(val))
                        map[key] = val;
                }
            }
        }

        foreach (string candidate in new[]
        {
            "Microsoft YaHei UI",
            "Microsoft YaHei",
            "Segoe UI Variable Text",
            "Segoe UI"
        })
        {
            if (map.TryGetValue(candidate, out string? mapped) && !string.IsNullOrWhiteSpace(mapped))
                return mapped;
        }

        return null;
    }

    private static bool IsSystemFontInstalled(string fontName)
    {
        foreach (var family in System.Windows.Media.Fonts.SystemFontFamilies)
        {
            if (string.Equals(family.Source, fontName, StringComparison.OrdinalIgnoreCase))
                return true;

            foreach (var name in family.FamilyNames.Values)
            {
                if (string.Equals(name, fontName, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
        }
        return false;
    }

    [LibraryImport("kernel32.dll", StringMarshalling = StringMarshalling.Utf16)]
    private static partial nint GetModuleHandleW(string lpModuleName);
}
