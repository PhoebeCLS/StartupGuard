using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.Reflection;
using Microsoft.Win32;
using StartupGuard.Core.Native;

namespace StartupGuard.Core.ContextMenu;

/// <summary>
/// GUID 字典与资源本地化解析器（参考并遵循 GPL-3.0 开源项目 PLFJY/ContextMenuMgr 与 BluePointLilac/ContextMenuManager 的 GuidInfosDic.ini 与资源解析逻辑适配）
/// </summary>
public static class ContextMenuGuidResolver
{
    private static readonly string[] ClsidRoots =
    [
        @"HKEY_CLASSES_ROOT\CLSID",
        @"HKEY_CLASSES_ROOT\WOW6432Node\CLSID",
        @"HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID",
        @"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Classes\CLSID"
    ];

    /// <summary>
    /// Windows 标准内置动词在 windows.storage.dll 中的字符串资源 ID 映射
    /// </summary>
    public static readonly IReadOnlyDictionary<string, int> DefaultVerbResourceIds =
        new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
        {
            ["open"] = 8496,
            ["edit"] = 8516,
            ["print"] = 8497,
            ["find"] = 8503,
            ["play"] = 8498,
            ["runas"] = 8505,
            ["explore"] = 8502,
            ["preview"] = 8499
        };

    private static readonly Lazy<Dictionary<Guid, Dictionary<string, string>>> EmbeddedGuidDic =
        new(LoadEmbeddedGuidDic, LazyThreadSafetyMode.ExecutionAndPublication);

    private static readonly ConcurrentDictionary<Guid, string> ClsidTextCache = new();
    private static readonly ConcurrentDictionary<Guid, string> ClsidFilePathCache = new();
    private static readonly ConcurrentDictionary<Guid, string> ClsidIconCache = new();

    public static int LoadedDictionaryEntryCount => EmbeddedGuidDic.Value.Count;

    public static bool TryGetDefaultVerbDisplayName(string? verbKeyName, out string localizedName)
    {
        localizedName = string.Empty;
        if (string.IsNullOrWhiteSpace(verbKeyName))
            return false;

        if (!DefaultVerbResourceIds.TryGetValue(verbKeyName.Trim(), out int resId))
            return false;

        string resExpr = $"@windows.storage.dll,-{resId}";
        string resolved = ContextMenuManagerEngine.ResolveMuiString(resExpr);
        if (!string.IsNullOrWhiteSpace(resolved) && !resolved.StartsWith('@'))
        {
            localizedName = resolved;
            return true;
        }

        // 离线兜底映射（与 windows.storage.dll 中文资源一致）
        localizedName = verbKeyName.Trim().ToLowerInvariant() switch
        {
            "open" => "打开",
            "edit" => "编辑",
            "print" => "打印",
            "find" => "查找",
            "play" => "播放",
            "runas" => "以管理员身份运行",
            "explore" => "打开方式为资源管理器",
            "preview" => "预览",
            _ => string.Empty
        };
        return !string.IsNullOrEmpty(localizedName);
    }

    /// <summary>
    /// 参考 ContextMenuManager GuidInfo.GetFilePath 解析 CLSID 对应的真实物理 DLL/EXE 路径
    /// </summary>
    public static string GetClsidFilePath(string? clsidText)
    {
        if (!TryParseGuid(clsidText, out Guid guid))
            return string.Empty;
        return GetClsidFilePath(guid);
    }

    public static string GetClsidFilePath(Guid guid)
    {
        if (guid == Guid.Empty)
            return string.Empty;

        if (ClsidFilePathCache.TryGetValue(guid, out string? cached) &&
            !string.IsNullOrEmpty(cached) &&
            File.Exists(cached))
        {
            return cached;
        }

        string resolved = ResolveClsidFilePathCore(guid);
        if (!string.IsNullOrEmpty(resolved) && File.Exists(resolved))
        {
            ClsidFilePathCache[guid] = resolved;
        }
        else
        {
            ClsidFilePathCache.TryRemove(guid, out _);
        }

        return resolved;
    }

    private static string ResolveClsidFilePathCore(Guid g)
    {
        if (OperatingSystem.IsWindows())
        {
            foreach (string clsidRoot in ClsidRoots)
            {
                string basePath = $@"{clsidRoot}\{g:B}";
                foreach (string subName in new[] { "InprocServer32", "LocalServer32" })
                {
                    string? codeBase = ReadRegistryDefaultOrNamedValue($@"{basePath}\{subName}", "CodeBase");
                    if (!string.IsNullOrWhiteSpace(codeBase))
                    {
                        string cleanCodeBase = codeBase.Replace("file:///", "", StringComparison.OrdinalIgnoreCase).Replace('/', '\\').Trim('"');
                        if (File.Exists(cleanCodeBase))
                            return cleanCodeBase;
                    }

                    string? serverRaw = ReadRegistryDefaultOrNamedValue($@"{basePath}\{subName}", "");
                    string extracted = ExtractPhysicalFilePath(serverRaw);
                    if (!string.IsNullOrWhiteSpace(extracted) && File.Exists(extracted))
                        return extracted;
                }
            }
        }

        if (TryGetDicValue(g, "FilePath", out string dicPath))
        {
            string extracted = ExtractPhysicalFilePath(dicPath);
            if (!string.IsNullOrWhiteSpace(extracted) && File.Exists(extracted))
                return extracted;
        }

        return string.Empty;
    }

    /// <summary>
    /// 参考 ContextMenuManager GuidInfo.GetText 解析 CLSID 的本地化中文/UI名称
    /// </summary>
    public static string GetClsidText(string? clsidText)
    {
        if (!TryParseGuid(clsidText, out Guid guid))
            return string.Empty;
        return GetClsidText(guid);
    }

    public static string GetClsidText(Guid guid)
    {
        if (guid == Guid.Empty)
            return string.Empty;

        if (ClsidTextCache.TryGetValue(guid, out string? cached) && !string.IsNullOrWhiteSpace(cached))
            return cached;

        string resolved = ResolveClsidTextCore(guid);
        if (!string.IsNullOrWhiteSpace(resolved))
        {
            ClsidTextCache[guid] = resolved;
        }
        return resolved;
    }

    private static string ResolveClsidTextCore(Guid g)
    {
        string? resolved = null;

        // 1. 字典 ResText (@dll,-id 或 *,-id)
        if (TryGetDicValue(g, "ResText", out string resText))
        {
            string abs = ResolveRelativeResourcePrefix(g, resText, forceResPrefix: true);
            string direct = ContextMenuManagerEngine.ResolveMuiString(abs);
            if (!IsUnresolvedResourceExpr(direct))
                resolved = direct;
        }

        // 2. 当前 UI 语言 Text（默认回退 zh-CN-Text，然后通用 Text）
        if (string.IsNullOrWhiteSpace(resolved))
        {
            string uiKey = CultureInfo.CurrentUICulture.Name + "-Text";
            if (TryGetDicValue(g, uiKey, out string uiText) && !string.IsNullOrWhiteSpace(uiText))
            {
                resolved = uiText.Trim();
            }
            else if (TryGetDicValue(g, "zh-CN-Text", out string zhText) && !string.IsNullOrWhiteSpace(zhText))
            {
                resolved = zhText.Trim();
            }
            else if (TryGetDicValue(g, "Text", out string fallbackText) && !string.IsNullOrWhiteSpace(fallbackText))
            {
                string abs = ResolveRelativeResourcePrefix(g, fallbackText, forceResPrefix: false);
                string direct = abs.StartsWith('@') ? ContextMenuManagerEngine.ResolveMuiString(abs) : abs;
                if (!IsUnresolvedResourceExpr(direct))
                    resolved = direct;
            }
        }

        // 3. 注册表 CLSID LocalizedString / InfoTip / Default
        if (string.IsNullOrWhiteSpace(resolved) && OperatingSystem.IsWindows())
        {
            foreach (string clsidRoot in ClsidRoots)
            {
                string keyPath = $@"{clsidRoot}\{g:B}";
                foreach (string valName in new[] { "LocalizedString", "InfoTip", "" })
                {
                    string? raw = ReadRegistryDefaultOrNamedValue(keyPath, valName);
                    if (string.IsNullOrWhiteSpace(raw))
                        continue;
                    if (valName == "InfoTip" && !raw.TrimStart().StartsWith('@'))
                        continue;

                    string direct = raw.TrimStart().StartsWith('@')
                        ? ContextMenuManagerEngine.ResolveMuiString(raw)
                        : raw.Trim();
                    if (!string.IsNullOrWhiteSpace(direct) && !IsUnresolvedResourceExpr(direct) && !direct.StartsWith('{'))
                    {
                        resolved = direct;
                        break;
                    }
                }
                if (!string.IsNullOrWhiteSpace(resolved))
                    break;
            }
        }

        // 4. 目标物理文件 FileDescription / 文件名
        if (string.IsNullOrWhiteSpace(resolved))
        {
            string filePath = GetClsidFilePath(g);
            if (!string.IsNullOrWhiteSpace(filePath) && File.Exists(filePath))
            {
                try
                {
                    string? desc = FileVersionInfo.GetVersionInfo(filePath).FileDescription;
                    resolved = !string.IsNullOrWhiteSpace(desc) ? desc.Trim() : Path.GetFileNameWithoutExtension(filePath);
                }
                catch
                {
                    resolved = Path.GetFileNameWithoutExtension(filePath);
                }
            }
        }

        return resolved?.Trim() ?? string.Empty;
    }

    public static string GetClsidIconLocation(Guid guid)
    {
        if (guid == Guid.Empty)
            return string.Empty;

        if (ClsidIconCache.TryGetValue(guid, out string? cached) && !string.IsNullOrWhiteSpace(cached))
            return cached;

        string resolved = string.Empty;
        if (TryGetDicValue(guid, "Icon", out string iconExpr))
        {
            string abs = ResolveRelativeResourcePrefix(guid, iconExpr, forceResPrefix: false);
            if (!string.IsNullOrWhiteSpace(abs))
                resolved = abs;
        }
        if (string.IsNullOrWhiteSpace(resolved))
            resolved = GetClsidFilePath(guid);

        if (!string.IsNullOrWhiteSpace(resolved))
            ClsidIconCache[guid] = resolved;
        return resolved;
    }

    /// <summary>
    /// 参考 ContextMenuManager ObjectPath.ExtractFilePath 从命令行或短可执行名提取物理文件完整路径
    /// </summary>
    public static string ExtractPhysicalFilePath(string? rawCommand)
    {
        if (string.IsNullOrWhiteSpace(rawCommand))
            return string.Empty;

        string cleaned = Environment.ExpandEnvironmentVariables(rawCommand).Trim();
        if (cleaned.StartsWith("ms-settings:", StringComparison.OrdinalIgnoreCase) ||
            cleaned.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
            cleaned.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            return string.Empty;

        // 先移除首引号或拆分前缀参数
        string candidate = cleaned.TrimStart('"');
        if (cleaned.StartsWith('"'))
        {
            int endQuote = cleaned.IndexOf('"', 1);
            if (endQuote > 1)
                candidate = cleaned[1..endQuote];
        }

        if (candidate.StartsWith(@"\??\", StringComparison.OrdinalIgnoreCase))
            candidate = candidate[4..];
        string winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (candidate.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
            candidate = Path.Combine(winDir, candidate[12..]);
        else if (candidate.StartsWith(@"System32\", StringComparison.OrdinalIgnoreCase) ||
                 candidate.StartsWith(@"SysWOW64\", StringComparison.OrdinalIgnoreCase))
            candidate = Path.Combine(winDir, candidate);

        if (File.Exists(candidate))
            return candidate;

        // 逐个查找空格分割片段中的最长存在路径
        string noQuotes = cleaned.Replace("\"", string.Empty);
        for (int len = noQuotes.Length; len > 0; len--)
        {
            if (len < noQuotes.Length && noQuotes[len] != ' ')
                continue;
            string prefix = noQuotes[..len].Trim();
            if (File.Exists(prefix))
                return prefix;
        }

        // 若仅为短程序名（如 powershell.exe / cmd.exe / winword.exe），按 App Paths 与 System32 查找
        string token = candidate;
        int spaceIdx = token.IndexOf(' ');
        if (spaceIdx > 0)
            token = token[..spaceIdx];

        if (!token.Contains('\\') && !token.Contains('/'))
        {
            if (OperatingSystem.IsWindows())
            {
                foreach (string root in new[]
                         {
                             $@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\App Paths\{token}",
                             $@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{token}"
                         })
                {
                    string? appPath = ReadRegistryDefaultOrNamedValue(root, "");
                    if (!string.IsNullOrWhiteSpace(appPath))
                    {
                        string expandedAppPath = Environment.ExpandEnvironmentVariables(appPath).Trim('"');
                        if (File.Exists(expandedAppPath))
                            return expandedAppPath;
                    }
                }
            }

            foreach (string probeDir in new[]
                     {
                         Environment.GetFolderPath(Environment.SpecialFolder.System),
                         Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                         Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"WindowsPowerShell\v1.0")
                     })
            {
                if (string.IsNullOrWhiteSpace(probeDir))
                    continue;
                string full = Path.Combine(probeDir, token);
                if (File.Exists(full))
                    return full;
                if (!token.Contains('.'))
                {
                    string fullExe = Path.Combine(probeDir, token + ".exe");
                    if (File.Exists(fullExe))
                        return fullExe;
                }
            }
        }

        return string.Empty;
    }

    public static bool TryGetDicValue(Guid guid, string key, out string value)
    {
        value = string.Empty;
        if (EmbeddedGuidDic.Value.TryGetValue(guid, out var props) &&
            props.TryGetValue(key, out string? raw) &&
            !string.IsNullOrEmpty(raw))
        {
            value = raw;
            return true;
        }
        return false;
    }

    public static bool TryParseGuid(string? input, out Guid guid)
    {
        guid = Guid.Empty;
        if (string.IsNullOrWhiteSpace(input))
            return false;

        string s = input.Trim().TrimStart('-');
        return Guid.TryParse(s, out guid);
    }

    private static string ResolveRelativeResourcePrefix(Guid guid, string rawValue, bool forceResPrefix)
    {
        if (string.IsNullOrWhiteSpace(rawValue))
            return string.Empty;

        string expanded = Environment.ExpandEnvironmentVariables(rawValue.Trim());
        int starIdx = expanded.IndexOf('*');
        if (starIdx >= 0)
        {
            string filePath = GetClsidFilePath(guid);
            if (!string.IsNullOrEmpty(filePath))
                expanded = expanded.Replace("*", filePath);
        }

        if (forceResPrefix && !expanded.StartsWith('@') && expanded.Contains(','))
            expanded = "@" + expanded;

        return expanded;
    }

    private static bool IsUnresolvedResourceExpr(string? val)
    {
        if (string.IsNullOrWhiteSpace(val))
            return true;
        string s = val.Trim();
        return s.StartsWith('@') || s.StartsWith("ms-resource:", StringComparison.OrdinalIgnoreCase);
    }

    private static string? ReadRegistryDefaultOrNamedValue(string fullKeyPath, string valueName)
    {
        try
        {
            return Registry.GetValue(fullKeyPath, valueName, null)?.ToString();
        }
        catch
        {
            return null;
        }
    }

    private static Dictionary<Guid, Dictionary<string, string>> LoadEmbeddedGuidDic()
    {
        var dic = new Dictionary<Guid, Dictionary<string, string>>();
        try
        {
            var asm = Assembly.GetExecutingAssembly();
            string? resName = asm.GetManifestResourceNames()
                .FirstOrDefault(n => n.EndsWith("GuidInfosDic.ini", StringComparison.OrdinalIgnoreCase));
            if (resName == null)
                return dic;

            using Stream? stream = asm.GetManifestResourceStream(resName);
            if (stream == null)
                return dic;

            using var reader = new StreamReader(stream);
            Dictionary<string, string>? currentSection = null;
            while (reader.ReadLine() is { } rawLine)
            {
                string line = rawLine.Trim();
                if (string.IsNullOrEmpty(line) || line.StartsWith(';') || line.StartsWith('#'))
                    continue;

                if (line.StartsWith('[') && line.EndsWith(']'))
                {
                    string secName = line[1..^1].Trim();
                    if (Guid.TryParse(secName, out Guid g))
                    {
                        if (!dic.TryGetValue(g, out currentSection))
                        {
                            currentSection = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                            dic[g] = currentSection;
                        }
                    }
                    else
                    {
                        currentSection = null;
                    }
                    continue;
                }

                if (currentSection == null)
                    continue;

                int eq = line.IndexOf('=');
                if (eq > 0)
                {
                    string k = line[..eq].Trim();
                    string v = line[(eq + 1)..].Trim();
                    currentSection[k] = v;
                }
            }
        }
        catch
        {
            // Ignore malformed dictionary safely
        }

        return dic;
    }
}
