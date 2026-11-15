using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace StartupGuard.Core.Native;

/// <summary>
/// 共享 UWP / Microsoft Store 应用自启项 (StartupTask) 扫描与元数据解析器
/// 扫描 HKU\&lt;SID&gt;\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\&lt;PFN&gt;\&lt;TaskId&gt;
/// </summary>
public static class UwpStartupScanner
{
    public sealed record UwpStartupEntry(
        string Sid,
        string PackageFamilyName,
        string TaskId,
        string DisplayName,
        string Publisher,
        string PackageInstallPath,
        string LocationKey,
        int State,
        bool IsEnabled,
        string ExecutablePath = "");

    private const string SystemAppDataTail = @"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData";
    private const string AppxRepoTail = @"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages";

    public static List<UwpStartupEntry> ScanForUserSids(IEnumerable<string?> userSids)
    {
        var results = new List<UwpStartupEntry>();
        if (!OperatingSystem.IsWindows())
            return results;

        var seenLocations = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void ScanRoot(RegistryKey hiveRoot, string rootPrefix, string subKeyBase, string sidLabel)
        {
            try
            {
                using var appDataKey = hiveRoot.OpenSubKey(subKeyBase, false);
                if (appDataKey == null) return;

                foreach (string pfn in appDataKey.GetSubKeyNames())
                {
                    if (string.IsNullOrWhiteSpace(pfn)) continue;
                    using var pkgKey = appDataKey.OpenSubKey(pfn, false);
                    if (pkgKey == null) continue;

                    foreach (string taskId in pkgKey.GetSubKeyNames())
                    {
                        if (string.IsNullOrWhiteSpace(taskId)) continue;
                        string taskSubKey = $@"{subKeyBase}\{pfn}\{taskId}";
                        using var taskKey = hiveRoot.OpenSubKey(taskSubKey, false);
                        if (taskKey == null) continue;

                        object? stateObj = taskKey.GetValue("State");
                        if (stateObj == null) continue;

                        int state = Convert.ToInt32(stateObj);
                        // Windows UWP StartupTask State:
                        // 0=Disabled, 1=DisabledByUser, 2=Enabled, 3=DisabledByPolicy, 4=EnabledByPolicy
                        bool isEnabled = state == 2 || state == 4;
                        string locKey = $@"{rootPrefix}\{taskSubKey}::State";
                        if (!seenLocations.Add(locKey))
                            continue;

                        var (friendlyPkgName, installPath) = ResolvePackageMetadata(hiveRoot, sidLabel, pfn);
                        string exePath = TryResolvePackageExecutable(installPath, taskId);
                        string displayName = string.Equals(taskId, pfn, StringComparison.OrdinalIgnoreCase) || taskId.Equals("StartupTask", StringComparison.OrdinalIgnoreCase)
                            ? friendlyPkgName
                            : $"{friendlyPkgName} ({taskId})";
                        string publisher = ResolvePublisherFromPfn(pfn);

                        results.Add(new UwpStartupEntry(
                            sidLabel,
                            pfn,
                            taskId,
                            displayName,
                            publisher,
                            installPath,
                            locKey,
                            state,
                            isEnabled,
                            exePath));
                    }
                }
            }
            catch { }
        }

        bool anySid = false;
        foreach (string? rawSid in userSids)
        {
            if (string.IsNullOrWhiteSpace(rawSid)) continue;
            anySid = true;
            ScanRoot(Registry.Users, "HKU", $@"{rawSid}\{SystemAppDataTail}", rawSid);
        }

        if (!anySid)
        {
            ScanRoot(Registry.CurrentUser, "HKCU", SystemAppDataTail, string.Empty);
        }

        return results;
    }

    public static (string FriendlyName, string InstallPath) ResolvePackageMetadata(RegistryKey hiveRoot, string sid, string pfn)
    {
        string shortName = ExtractShortPackageName(pfn);
        string installPath = string.Empty;

        try
        {
            string repoPath = string.IsNullOrEmpty(sid) ? AppxRepoTail : $@"{sid}\{AppxRepoTail}";
            using var repoKey = hiveRoot.OpenSubKey(repoPath, false);
            if (repoKey != null)
            {
                string prefix = shortName + "_";
                foreach (string fullPkgName in repoKey.GetSubKeyNames())
                {
                    if (!fullPkgName.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                        continue;

                    using var pkgSub = repoKey.OpenSubKey(fullPkgName, false);
                    if (pkgSub == null) continue;

                    string? rootDir = pkgSub.GetValue("PackageRootFolder")?.ToString();
                    if (!string.IsNullOrWhiteSpace(rootDir))
                        installPath = rootDir;

                    string? disp = pkgSub.GetValue("DisplayName")?.ToString();
                    if (!string.IsNullOrWhiteSpace(disp) && !disp.StartsWith("@{", StringComparison.Ordinal))
                        shortName = disp;
                    break;
                }
            }
        }
        catch { }

        return (shortName, installPath);
    }

    /// <summary>
    /// 尝试从 UWP 包安装目录及 AppxManifest.xml 解析出具体自启主程序 .exe 路径
    /// </summary>
    public static string TryResolvePackageExecutable(string installPath, string taskId)
    {
        if (string.IsNullOrWhiteSpace(installPath) || !Directory.Exists(installPath))
            return string.Empty;

        try
        {
            string manifestPath = Path.Combine(installPath, "AppxManifest.xml");
            if (File.Exists(manifestPath))
            {
                string xml = File.ReadAllText(manifestPath);
                if (!string.IsNullOrWhiteSpace(taskId))
                {
                    var taskMatch = System.Text.RegularExpressions.Regex.Match(
                        xml,
                        $@"TaskId\s*=\s*""{System.Text.RegularExpressions.Regex.Escape(taskId)}""[^>]*Executable\s*=\s*""([^""]+)""|Executable\s*=\s*""([^""]+)""[^>]*TaskId\s*=\s*""{System.Text.RegularExpressions.Regex.Escape(taskId)}""",
                        System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                    if (taskMatch.Success)
                    {
                        string rel = !string.IsNullOrEmpty(taskMatch.Groups[1].Value)
                            ? taskMatch.Groups[1].Value
                            : taskMatch.Groups[2].Value;
                        string candidate = Path.Combine(installPath, rel.TrimStart('\\', '/'));
                        if (File.Exists(candidate))
                            return candidate;
                    }
                }

                var appMatch = System.Text.RegularExpressions.Regex.Match(
                    xml,
                    @"<(?:[\w:]+)?Application\b[^>]*\bExecutable\s*=\s*""([^""]+\.exe)""",
                    System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                if (appMatch.Success)
                {
                    string candidate = Path.Combine(installPath, appMatch.Groups[1].Value.TrimStart('\\', '/'));
                    if (File.Exists(candidate))
                        return candidate;
                }
            }

            foreach (string exe in Directory.EnumerateFiles(installPath, "*.exe", SearchOption.TopDirectoryOnly))
            {
                string name = Path.GetFileName(exe);
                if (!name.Contains("uninst", StringComparison.OrdinalIgnoreCase) &&
                    !name.Contains("crash", StringComparison.OrdinalIgnoreCase) &&
                    !name.Contains("helper", StringComparison.OrdinalIgnoreCase))
                {
                    return exe;
                }
            }
        }
        catch { }

        return string.Empty;
    }

    public static string ExtractShortPackageName(string pfn)
    {
        if (string.IsNullOrWhiteSpace(pfn))
            return string.Empty;

        int underscore = pfn.IndexOf('_');
        string core = underscore > 0 ? pfn[..underscore] : pfn;

        // 常见反向域名或厂商前缀精简（保留可读名）
        int dot = core.LastIndexOf('.');
        if (core.StartsWith("Microsoft.", StringComparison.OrdinalIgnoreCase) && dot > 0 && dot < core.Length - 1)
            return core;
        return core;
    }

    public static string ResolvePublisherFromPfn(string pfn)
    {
        if (pfn.StartsWith("Microsoft.", StringComparison.OrdinalIgnoreCase) ||
            pfn.StartsWith("MicrosoftWindows.", StringComparison.OrdinalIgnoreCase) ||
            pfn.StartsWith("MicrosoftCorporation", StringComparison.OrdinalIgnoreCase) ||
            pfn.Contains("_8wekyb3d8bbwe", StringComparison.OrdinalIgnoreCase))
        {
            return "Microsoft Corporation";
        }

        int underscore = pfn.IndexOf('_');
        string core = underscore > 0 ? pfn[..underscore] : pfn;
        int dot = core.IndexOf('.');
        if (dot > 0)
            return core[..dot] + " (Microsoft Store)";

        return "Microsoft Store 应用";
    }

    public static bool IsFirstPartyMicrosoftUwpPackage(string? pfnOrLocation, string? publisher)
    {
        string text = pfnOrLocation ?? string.Empty;
        if (text.Contains("_8wekyb3d8bbwe", StringComparison.OrdinalIgnoreCase) ||
            text.Contains(@"\Microsoft.", StringComparison.OrdinalIgnoreCase) ||
            text.Contains(@"\MicrosoftWindows.", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return !string.IsNullOrWhiteSpace(publisher) &&
               publisher.Equals("Microsoft Corporation", StringComparison.OrdinalIgnoreCase);
    }
}
