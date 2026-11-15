using System.Text;
using System.Text.RegularExpressions;
using StartupGuard.Core.Models;
using StartupGuard.Core.Storage;

namespace StartupGuard.Core.Scoring;

/// <summary>
/// 路径模板正则归一化与 Jaro-Winkler / Jaccard 相似度核函数引擎
/// </summary>
public static partial class PathNormalizerAndSimilarity
{
    [GeneratedRegex(@"^[a-zA-Z]:\\", RegexOptions.CultureInvariant)]
    private static partial Regex DrivePrefixRegex();

    [GeneratedRegex(@"Users\\[^\\]+\\", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex UserFolderRegex();

    [GeneratedRegex(@"[_\\/]\d+(\.\d+){1,4}([_\.\-\w]+)?[_\\/]", RegexOptions.CultureInvariant)]
    private static partial Regex VersionFolderRegex();

    [GeneratedRegex(@"\{[0-9a-fA-F\-]{36}\}", RegexOptions.CultureInvariant)]
    private static partial Regex GuidRegex();

    [GeneratedRegex(@"\\[0-9a-fA-F]{16,64}\\", RegexOptions.CultureInvariant)]
    private static partial Regex HexHashFolderRegex();

    /// <summary>
    /// 从原始注册表命令行中剥离出真实的目标 PE 路径与启动参数开关
    /// (支持穿透引号、环境变量与 rundll32/cmd/powershell/wscript 包装宿主)
    /// </summary>
    public static (string ExecutablePath, string ArgumentsTemplate) SplitCommandLine(string rawCommandLine)
    {
        if (string.IsNullOrWhiteSpace(rawCommandLine))
            return (string.Empty, string.Empty);

        var (firstExe, restArgs) = SplitRawExecutableAndRemaining(rawCommandLine);
        if (TryUnwrapHostCommandLine(firstExe, restArgs, out string payloadExe, out string payloadArgs))
        {
            return (payloadExe, NormalizeArguments(payloadArgs));
        }

        return (firstExe, NormalizeArguments(restArgs));
    }

    private static (string ExecutablePath, string RawRemainingArgs) SplitRawExecutableAndRemaining(string rawCommandLine)
    {
        if (string.IsNullOrWhiteSpace(rawCommandLine))
            return (string.Empty, string.Empty);

        string expanded = Environment.ExpandEnvironmentVariables(rawCommandLine.Trim());

        if (expanded.StartsWith('"'))
        {
            int endQuote = expanded.IndexOf('"', 1);
            if (endQuote > 1)
            {
                string exe = expanded[1..endQuote].Trim();
                string args = expanded[(endQuote + 1)..].Trim();
                return (exe, args);
            }
        }

        // 未加引号时探测 .exe / .dll / .sys / .ps1 / .vbs / .bat / .cmd 边界
        string[] extensions = [".exe", ".sys", ".dll", ".ps1", ".vbs", ".bat", ".cmd"];
        int bestExtIdx = -1;
        int bestExtLen = 4;
        foreach (string ext in extensions)
        {
            int idx = expanded.IndexOf(ext, StringComparison.OrdinalIgnoreCase);
            if (idx > 0 && (bestExtIdx < 0 || idx < bestExtIdx))
            {
                bestExtIdx = idx;
                bestExtLen = ext.Length;
            }
        }

        if (bestExtIdx > 0)
        {
            int splitPos = bestExtIdx + bestExtLen;
            string exe = expanded[..splitPos].Trim();
            string args = splitPos < expanded.Length ? expanded[splitPos..].Trim() : string.Empty;
            return (exe, args);
        }

        // 若整体路径本身就是磁盘上存在的目录或文件（如 UWP PackageRootFolder 含空格），禁止按空格截断
        if (Directory.Exists(expanded) || File.Exists(expanded))
            return (expanded, string.Empty);

        int firstSpace = expanded.IndexOf(' ');
        if (firstSpace > 0)
            return (expanded[..firstSpace].Trim(), expanded[(firstSpace + 1)..].Trim());

        return (expanded, string.Empty);
    }

    private static bool TryUnwrapHostCommandLine(
        string hostExe,
        string rawRestArgs,
        out string payloadExe,
        out string payloadArgs)
    {
        payloadExe = string.Empty;
        payloadArgs = string.Empty;

        if (string.IsNullOrWhiteSpace(hostExe) || string.IsNullOrWhiteSpace(rawRestArgs))
            return false;

        string fileName = Path.GetFileName(hostExe.Replace('/', '\\')).ToLowerInvariant();
        if (fileName is "rundll32.exe" or "rundll32")
        {
            // 格式: rundll32.exe "C:\Path\target.dll",EntryPoint args 或 rundll32.exe C:\Path\target.dll,EntryPoint
            string trimmed = rawRestArgs.TrimStart();
            if (trimmed.StartsWith('"'))
            {
                int endQuote = trimmed.IndexOf('"', 1);
                if (endQuote > 1)
                {
                    payloadExe = trimmed[1..endQuote].Trim();
                    payloadArgs = trimmed[(endQuote + 1)..].TrimStart(',', ' ');
                    return !string.IsNullOrEmpty(payloadExe);
                }
            }

            int commaIdx = trimmed.IndexOf(',');
            int dllIdx = trimmed.IndexOf(".dll", StringComparison.OrdinalIgnoreCase);
            int splitAt = commaIdx > 0 ? commaIdx : (dllIdx > 0 ? dllIdx + 4 : -1);
            if (splitAt > 0)
            {
                payloadExe = trimmed[..splitAt].Trim().Trim('"');
                payloadArgs = splitAt < trimmed.Length ? trimmed[splitAt..].TrimStart(',', ' ') : string.Empty;
                return !string.IsNullOrEmpty(payloadExe);
            }
        }
        else if (fileName is "cmd.exe" or "cmd")
        {
            // 剥离 /c 或 /k
            string rest = rawRestArgs.TrimStart();
            while (rest.StartsWith("/c", StringComparison.OrdinalIgnoreCase) ||
                   rest.StartsWith("/k", StringComparison.OrdinalIgnoreCase) ||
                   rest.StartsWith("/q", StringComparison.OrdinalIgnoreCase) ||
                   rest.StartsWith("/s", StringComparison.OrdinalIgnoreCase))
            {
                rest = rest[2..].TrimStart();
            }

            if (rest.StartsWith('"') && rest.EndsWith('"') && rest.Count(c => c == '"') > 2)
            {
                rest = rest[1..^1].Trim();
            }

            var (innerExe, innerArgs) = SplitRawExecutableAndRemaining(rest);
            if (!string.IsNullOrEmpty(innerExe))
            {
                payloadExe = innerExe;
                payloadArgs = innerArgs;
                return true;
            }
        }
        else if (fileName is "powershell.exe" or "powershell" or "pwsh.exe" or "pwsh")
        {
            // 查找 -File / -f 参数后的脚本路径，或直接提取内部路径
            int fileFlagIdx = rawRestArgs.IndexOf("-File", StringComparison.OrdinalIgnoreCase);
            if (fileFlagIdx >= 0)
            {
                string afterFlag = rawRestArgs[(fileFlagIdx + 5)..].TrimStart();
                var (scriptPath, scriptArgs) = SplitRawExecutableAndRemaining(afterFlag);
                if (!string.IsNullOrEmpty(scriptPath))
                {
                    payloadExe = scriptPath;
                    payloadArgs = rawRestArgs[..fileFlagIdx] + " " + scriptArgs;
                    return true;
                }
            }
        }
        else if (fileName is "wscript.exe" or "wscript" or "cscript.exe" or "cscript" or "mshta.exe" or "mshta")
        {
            string rest = rawRestArgs.TrimStart();
            while (rest.StartsWith("//", StringComparison.Ordinal) || rest.StartsWith('/'))
            {
                int nextSpace = rest.IndexOf(' ');
                if (nextSpace < 0) break;
                rest = rest[(nextSpace + 1)..].TrimStart();
            }

            var (innerExe, innerArgs) = SplitRawExecutableAndRemaining(rest);
            if (!string.IsNullOrEmpty(innerExe))
            {
                payloadExe = innerExe;
                payloadArgs = innerArgs;
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// 将绝对路径中的盘符、用户名、软件版本号、随机哈希替换为泛化占位符
    /// 例如: C:\Users\DemoUser\AppData\Local\Microsoft\OneDrive\26.198.1011.0006\FileSyncShell64.dll
    /// -> <drive>:\users\<user>\appdata\local\microsoft\onedrive\<ver>\filesyncshell64.dll
    /// </summary>
    public static string NormalizeProgramPath(string rawPath)
    {
        if (string.IsNullOrWhiteSpace(rawPath))
            return string.Empty;

        string p = rawPath.Trim().Trim('"');
        p = DrivePrefixRegex().Replace(p, @"<drive>:\");
        p = UserFolderRegex().Replace(p, @"Users\<user>\");
        p = VersionFolderRegex().Replace(p, @"\<ver>\");
        p = GuidRegex().Replace(p, @"<guid>");
        p = HexHashFolderRegex().Replace(p, @"\<hash>\");

        return p.ToLowerInvariant();
    }

    public static string NormalizeArguments(string rawArgs)
    {
        if (string.IsNullOrWhiteSpace(rawArgs))
            return string.Empty;

        // 提取开关参数并按字典序排列
        string[] tokens = rawArgs.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var flags = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (string token in tokens)
        {
            if (token.StartsWith('-') || token.StartsWith('/'))
                flags.Add(token.ToLowerInvariant());
        }
        return flags.Count > 0 ? string.Join(' ', flags) : rawArgs.ToLowerInvariant();
    }

    /// <summary>
    /// Jaro-Winkler 字符串相似度算法 (值域 [0.0, 1.0]，针对路径前缀亲和度增强)
    /// </summary>
    public static double ComputeJaroWinkler(ReadOnlySpan<char> s1, ReadOnlySpan<char> s2)
    {
        if (s1.SequenceEqual(s2)) return 1.0;
        if (s1.IsEmpty || s2.IsEmpty) return 0.0;

        int maxDist = Math.Max(s1.Length, s2.Length) / 2 - 1;
        if (maxDist < 0) maxDist = 0;

        Span<bool> s1Matches = s1.Length <= 256 ? stackalloc bool[s1.Length] : new bool[s1.Length];
        Span<bool> s2Matches = s2.Length <= 256 ? stackalloc bool[s2.Length] : new bool[s2.Length];

        int matches = 0;
        for (int i = 0; i < s1.Length; i++)
        {
            int start = Math.Max(0, i - maxDist);
            int end = Math.Min(i + maxDist + 1, s2.Length);
            for (int j = start; j < end; j++)
            {
                if (s2Matches[j] || char.ToLowerInvariant(s1[i]) != char.ToLowerInvariant(s2[j]))
                    continue;
                s1Matches[i] = true;
                s2Matches[j] = true;
                matches++;
                break;
            }
        }

        if (matches == 0) return 0.0;

        double t = 0;
        int k = 0;
        for (int i = 0; i < s1.Length; i++)
        {
            if (!s1Matches[i]) continue;
            while (!s2Matches[k]) k++;
            if (char.ToLowerInvariant(s1[i]) != char.ToLowerInvariant(s2[k]))
                t += 0.5;
            k++;
        }

        double m = matches;
        double jaro = (m / s1.Length + m / s2.Length + (m - t) / m) / 3.0;

        // Winkler 前缀奖励 (最高 4 字符)
        int prefix = 0;
        int maxPrefix = Math.Min(4, Math.Min(s1.Length, s2.Length));
        for (int i = 0; i < maxPrefix; i++)
        {
            if (char.ToLowerInvariant(s1[i]) == char.ToLowerInvariant(s2[i]))
                prefix++;
            else
                break;
        }

        return jaro + prefix * 0.1 * (1.0 - jaro);
    }

    /// <summary>
    /// 命令行开关集合 Jaccard 相似度 (值域 [0.0, 1.0])
    /// </summary>
    public static double ComputeArgsJaccard(string argsA, string argsB)
    {
        if (string.Equals(argsA, argsB, StringComparison.OrdinalIgnoreCase))
            return 1.0;
        if (string.IsNullOrWhiteSpace(argsA) || string.IsNullOrWhiteSpace(argsB))
            return 0.0;

        var setA = new HashSet<string>(argsA.Split(' ', StringSplitOptions.RemoveEmptyEntries), StringComparer.OrdinalIgnoreCase);
        var setB = new HashSet<string>(argsB.Split(' ', StringSplitOptions.RemoveEmptyEntries), StringComparer.OrdinalIgnoreCase);

        if (setA.Count == 0 && setB.Count == 0) return 1.0;

        int intersection = 0;
        foreach (string item in setA)
        {
            if (setB.Contains(item))
                intersection++;
        }

        int union = setA.Count + setB.Count - intersection;
        return union == 0 ? 1.0 : (double)intersection / union;
    }
}
