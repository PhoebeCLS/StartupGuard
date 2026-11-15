// Copyright (C) StartupGuard Contributors
// Win+X 分组结构、desktop.ini 本地化及 System.Winx.Hash 算法参考并遵循 GNU GPL-3.0
// 开源项目 ContextMenuManager (https://github.com/BluePointLilac/ContextMenuManager) 与
// ContextMenuMgr (https://github.com/PLFJY/ContextMenuMgr)。

using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Text;
using ComTypes = System.Runtime.InteropServices.ComTypes;

namespace StartupGuard.Core.ContextMenu;

public sealed class WinXShortcutEntry
{
    public string FilePath { get; set; } = string.Empty;
    public string FileName => Path.GetFileName(FilePath);
    public string GroupName { get; set; } = string.Empty;
    public string GroupPath { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string TargetPath { get; set; } = string.Empty;
    public string Arguments { get; set; } = string.Empty;
    public bool IsEnabled { get; set; }
    public bool CanMoveUp { get; set; }
    public bool CanMoveDown { get; set; }
}

public sealed class WinXGroupEntry
{
    public string GroupName { get; set; } = string.Empty;
    public string GroupPath { get; set; } = string.Empty;
    public bool IsEnabled { get; set; }
    public bool CanRestoreDefault { get; set; }
    public List<WinXShortcutEntry> Items { get; set; } = [];
}

/// <summary>
/// Windows Win+X 快捷菜单管理器（支持分组展示、排序编号、重命名、隐显开关、恢复默认与分组增删）。
/// </summary>
public static partial class WinXMenuService
{
    public static string DefaultWinXDirectory =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "Windows", "WinX");

    public static string SystemDefaultWinXTemplateDirectory =>
        Environment.ExpandEnvironmentVariables(@"%SystemDrive%\Users\Default\AppData\Local\Microsoft\Windows\WinX");

    public static List<WinXGroupEntry> ScanGroups(
        bool autoNormalizePrefixes,
        out bool anyNormalized)
        => ScanGroups(null, null, autoNormalizePrefixes, out anyNormalized);

    public static List<WinXGroupEntry> ScanGroups(
        string? customWinXDir,
        string? customDefaultWinXDir,
        bool autoNormalizePrefixes,
        out bool anyNormalized)
    {
        anyNormalized = false;
        string rootDir = string.IsNullOrWhiteSpace(customWinXDir) ? DefaultWinXDirectory : customWinXDir;
        string defaultRoot = string.IsNullOrWhiteSpace(customDefaultWinXDir) ? SystemDefaultWinXTemplateDirectory : customDefaultWinXDir;
        var groups = new List<WinXGroupEntry>();

        if (!Directory.Exists(rootDir))
            return groups;

        string[] dirPaths = Directory.GetDirectories(rootDir);
        Array.Sort(dirPaths, StringComparer.OrdinalIgnoreCase);
        Array.Reverse(dirPaths);

        foreach (string dirPath in dirPaths)
        {
            string groupName = Path.GetFileName(dirPath);
            bool groupEnabled = true;
            try
            {
                groupEnabled = (File.GetAttributes(dirPath) & FileAttributes.Hidden) != FileAttributes.Hidden;
            }
            catch { }

            List<string> orderedPaths = autoNormalizePrefixes
                ? GetSortedPaths(dirPath, out bool normalizedThisGroup)
                : GetReversedShortcutPaths(dirPath, out normalizedThisGroup);

            if (normalizedThisGroup)
                anyNormalized = true;

            var groupEntry = new WinXGroupEntry
            {
                GroupName = groupName,
                GroupPath = dirPath,
                IsEnabled = groupEnabled,
                CanRestoreDefault = Directory.Exists(Path.Combine(defaultRoot, groupName))
            };

            var localizedMap = ReadDesktopIniLocalizedNames(dirPath);
            for (int i = 0; i < orderedPaths.Count; i++)
            {
                string lnkPath = orderedPaths[i];
                var shortcut = BuildShortcutEntry(dirPath, groupName, lnkPath, localizedMap);
                shortcut.CanMoveUp = i > 0;
                shortcut.CanMoveDown = i < orderedPaths.Count - 1;
                groupEntry.Items.Add(shortcut);
            }

            groups.Add(groupEntry);
        }

        return groups;
    }

    private static List<string> GetReversedShortcutPaths(string groupPath, out bool normalized)
    {
        normalized = false;
        string[] raw = Directory.GetFiles(groupPath, "*.lnk");
        Array.Sort(raw, StringComparer.OrdinalIgnoreCase);
        Array.Reverse(raw);
        return raw.ToList();
    }

    /// <summary>
    /// 规范化组内快捷方式的 "01 - Name.lnk" 编号，并按显示顺序 (N -> 1) 返回列表。
    /// </summary>
    public static List<string> GetSortedPaths(string groupPath, out bool sorted)
    {
        sorted = false;
        var sortedPaths = new List<string>();
        if (!Directory.Exists(groupPath))
            return sortedPaths;

        string[] paths = Directory.GetFiles(groupPath, "*.lnk");
        Array.Sort(paths, (a, b) =>
        {
            string fa = Path.GetFileName(a);
            string fb = Path.GetFileName(b);
            int ia = fa.IndexOf(" - ", StringComparison.Ordinal);
            int ib = fb.IndexOf(" - ", StringComparison.Ordinal);
            if (ia > 0 && ib > 0 && int.TryParse(fa[..ia], out int na) && int.TryParse(fb[..ib], out int nb))
            {
                int cmp = na.CompareTo(nb);
                if (cmp != 0) return cmp;
            }
            return StringComparer.OrdinalIgnoreCase.Compare(fa, fb);
        });

        for (int i = paths.Length - 1; i >= 0; i--)
        {
            string srcPath = paths[i];
            string name = Path.GetFileName(srcPath);
            int sepIdx = name.IndexOf(" - ", StringComparison.Ordinal);
            if (sepIdx >= 2 && int.TryParse(name[..sepIdx], out int num) && num == i + 1)
            {
                sortedPaths.Add(srcPath);
                continue;
            }

            if (sepIdx >= 0)
                name = name[(sepIdx + 3)..];

            string candidate = Path.Combine(groupPath, $"{(i + 1):D2} - {name}");
            string dstPath = MakeUniqueFilePath(candidate);

            string? value = ReadShortcutDescription(srcPath);
            if (string.IsNullOrWhiteSpace(value))
                value = ReadDesktopIniValue(groupPath, Path.GetFileName(srcPath));
            if (string.IsNullOrWhiteSpace(value))
                value = Path.GetFileNameWithoutExtension(name);

            try
            {
                DeleteDesktopIniValue(groupPath, Path.GetFileName(srcPath));
                SetDesktopIniValue(groupPath, Path.GetFileName(dstPath), value);
                File.Move(srcPath, dstPath);
                WriteShortcutDescription(dstPath, value);
                TryHashLnk(dstPath);

                sortedPaths.Add(dstPath);
                sorted = true;
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
            {
                sortedPaths.Add(srcPath);
            }
        }

        return sortedPaths;
    }

    public static bool SetGroupEnabled(string groupPath, bool enable)
    {
        if (string.IsNullOrWhiteSpace(groupPath) || !Directory.Exists(groupPath))
            return false;

        try
        {
            FileAttributes attrs = File.GetAttributes(groupPath);
            attrs = enable ? attrs & ~FileAttributes.Hidden : attrs | FileAttributes.Hidden;
            File.SetAttributes(groupPath, attrs);
            return true;
        }
        catch
        {
            return false;
        }
    }

    public static string? RenameGroup(string groupPath, string newGroupName)
    {
        if (string.IsNullOrWhiteSpace(groupPath) || !Directory.Exists(groupPath))
            return null;

        string sanitized = SanitizeFileName(newGroupName);
        if (string.IsNullOrWhiteSpace(sanitized))
            return null;

        string? parentDir = Path.GetDirectoryName(groupPath);
        if (string.IsNullOrEmpty(parentDir))
            return null;

        string newPath = Path.Combine(parentDir, sanitized);
        if (string.Equals(groupPath, newPath, StringComparison.OrdinalIgnoreCase))
            return groupPath;
        if (Directory.Exists(newPath))
            return null;

        try
        {
            Directory.Move(groupPath, newPath);
            return newPath;
        }
        catch
        {
            return null;
        }
    }

    public static bool DeleteGroup(string groupPath)
    {
        if (string.IsNullOrWhiteSpace(groupPath) || !Directory.Exists(groupPath))
            return false;

        try
        {
            foreach (string f in Directory.EnumerateFiles(groupPath, "*", SearchOption.AllDirectories))
            {
                try { File.SetAttributes(f, FileAttributes.Normal); } catch { }
            }
            File.SetAttributes(groupPath, FileAttributes.Normal);
            Directory.Delete(groupPath, recursive: true);
            return true;
        }
        catch
        {
            return false;
        }
    }

    public static bool RestoreDefaultGroup(string groupPath, string? customDefaultWinXDir = null)
    {
        if (string.IsNullOrWhiteSpace(groupPath) || !Directory.Exists(groupPath))
            return false;

        string groupName = Path.GetFileName(groupPath);
        string defaultRoot = string.IsNullOrWhiteSpace(customDefaultWinXDir) ? SystemDefaultWinXTemplateDirectory : customDefaultWinXDir;
        string defaultGroupPath = Path.Combine(defaultRoot, groupName);
        if (!Directory.Exists(defaultGroupPath))
            return false;

        try
        {
            foreach (string f in Directory.EnumerateFiles(groupPath, "*", SearchOption.AllDirectories))
            {
                try { File.SetAttributes(f, FileAttributes.Normal); } catch { }
            }
            File.SetAttributes(groupPath, FileAttributes.Normal);
            Directory.Delete(groupPath, recursive: true);
            Directory.CreateDirectory(groupPath);
            try { File.SetAttributes(groupPath, File.GetAttributes(defaultGroupPath)); } catch { }

            foreach (string srcPath in Directory.GetFiles(defaultGroupPath))
            {
                string dstPath = Path.Combine(groupPath, Path.GetFileName(srcPath));
                File.Copy(srcPath, dstPath, overwrite: true);
            }
            return true;
        }
        catch
        {
            return false;
        }
    }

    public static string? CreateNewGroup(string? customWinXDir = null)
    {
        string rootDir = string.IsNullOrWhiteSpace(customWinXDir) ? DefaultWinXDirectory : customWinXDir;
        try
        {
            Directory.CreateDirectory(rootDir);
            int idx = 1;
            string dirPath;
            do
            {
                dirPath = Path.Combine(rootDir, $"Group{idx++}");
            } while (Directory.Exists(dirPath));

            Directory.CreateDirectory(dirPath);
            string iniPath = Path.Combine(dirPath, "desktop.ini");
            File.WriteAllText(iniPath, string.Empty, Encoding.Unicode);
            File.SetAttributes(dirPath, File.GetAttributes(dirPath) | FileAttributes.ReadOnly);
            File.SetAttributes(iniPath, File.GetAttributes(iniPath) | FileAttributes.Hidden | FileAttributes.System);
            return dirPath;
        }
        catch
        {
            return null;
        }
    }

    public static bool SetItemEnabled(string lnkPath, bool enable)
    {
        if (string.IsNullOrWhiteSpace(lnkPath) || !File.Exists(lnkPath))
            return false;

        try
        {
            FileAttributes attrs = File.GetAttributes(lnkPath);
            attrs = enable ? attrs & ~FileAttributes.Hidden : attrs | FileAttributes.Hidden;
            File.SetAttributes(lnkPath, attrs);
            return true;
        }
        catch
        {
            return false;
        }
    }

    public static bool RenameItem(string lnkPath, string newDisplayName)
    {
        if (string.IsNullOrWhiteSpace(lnkPath) || !File.Exists(lnkPath) || string.IsNullOrWhiteSpace(newDisplayName))
            return false;

        string cleanName = newDisplayName.Trim();
        try
        {
            string? groupDir = Path.GetDirectoryName(lnkPath);
            if (!string.IsNullOrEmpty(groupDir))
            {
                SetDesktopIniValue(groupDir, Path.GetFileName(lnkPath), cleanName);
            }
            WriteShortcutDescription(lnkPath, cleanName);
            TryHashLnk(lnkPath);
            return true;
        }
        catch
        {
            return false;
        }
    }

    public static bool MoveItem(string groupPath, string lnkPath, bool moveUp)
    {
        if (string.IsNullOrWhiteSpace(groupPath) || !Directory.Exists(groupPath) || !File.Exists(lnkPath))
            return false;

        try
        {
            List<string> ordered = GetSortedPaths(groupPath, out _);
            int currentIdx = ordered.FindIndex(p => string.Equals(p, lnkPath, StringComparison.OrdinalIgnoreCase));
            if (currentIdx < 0)
                return false;

            int neighborIdx = currentIdx + (moveUp ? -1 : 1);
            if (neighborIdx < 0 || neighborIdx >= ordered.Count)
                return false;

            string pathA = ordered[currentIdx];
            string pathB = ordered[neighborIdx];
            string fileA = Path.GetFileName(pathA);
            string fileB = Path.GetFileName(pathB);
            if (fileA.Length < 2 || fileB.Length < 2)
                return false;

            string? nameA = ReadDesktopIniValue(groupPath, fileA);
            string? nameB = ReadDesktopIniValue(groupPath, fileB);
            DeleteDesktopIniValue(groupPath, fileA);
            DeleteDesktopIniValue(groupPath, fileB);

            string newFileA = $"{fileB[..2]}{fileA[2..]}";
            string newFileB = $"{fileA[..2]}{fileB[2..]}";

            string tempPath = Path.Combine(groupPath, $"__winx_swap_{Guid.NewGuid():N}.tmp");
            string dstA = Path.Combine(groupPath, newFileA);
            string dstB = Path.Combine(groupPath, newFileB);

            File.Move(pathA, tempPath);
            File.Move(pathB, dstB);
            dstA = MakeUniqueFilePath(dstA);
            File.Move(tempPath, dstA);

            if (!string.IsNullOrEmpty(nameA)) SetDesktopIniValue(groupPath, Path.GetFileName(dstA), nameA);
            if (!string.IsNullOrEmpty(nameB)) SetDesktopIniValue(groupPath, Path.GetFileName(dstB), nameB);
            return true;
        }
        catch
        {
            return false;
        }
    }

    public static bool DeleteItem(string lnkPath)
    {
        if (string.IsNullOrWhiteSpace(lnkPath) || !File.Exists(lnkPath))
            return false;

        try
        {
            string? groupDir = Path.GetDirectoryName(lnkPath);
            if (!string.IsNullOrEmpty(groupDir))
            {
                DeleteDesktopIniValue(groupDir, Path.GetFileName(lnkPath));
            }
            try { File.SetAttributes(lnkPath, FileAttributes.Normal); } catch { }
            File.Delete(lnkPath);
            return true;
        }
        catch
        {
            return false;
        }
    }

    public static void RestartExplorerProcess()
    {
        if (!OperatingSystem.IsWindows())
            return;

        try
        {
            foreach (var proc in Process.GetProcessesByName("explorer"))
            {
                try
                {
                    proc.Kill();
                    proc.WaitForExit(1500);
                }
                catch { }
                finally { proc.Dispose(); }
            }
            Thread.Sleep(250);
            Process.Start(new ProcessStartInfo("explorer.exe") { UseShellExecute = true });
        }
        catch { }
    }

    private static WinXShortcutEntry BuildShortcutEntry(
        string groupDir,
        string groupName,
        string lnkPath,
        Dictionary<string, string> localizedMap)
    {
        var fi = new FileInfo(lnkPath);
        string fileName = fi.Name;
        string? rawDesc = ReadShortcutDescription(lnkPath);
        string targetPath = string.Empty;
        string arguments = string.Empty;

        if (OperatingSystem.IsWindows())
        {
            ReadShortcutTarget(lnkPath, out targetPath, out arguments);
        }

        string display = string.Empty;
        if (!string.IsNullOrWhiteSpace(rawDesc))
        {
            display = rawDesc.StartsWith('@') ? ContextMenuManagerEngine.ResolveMuiString(rawDesc) : rawDesc;
        }
        if ((string.IsNullOrWhiteSpace(display) || display.StartsWith('@')) &&
            localizedMap.TryGetValue(fileName, out string? iniVal) && !string.IsNullOrWhiteSpace(iniVal))
        {
            display = iniVal.StartsWith('@') ? ContextMenuManagerEngine.ResolveMuiString(iniVal) : iniVal;
        }
        if (string.IsNullOrWhiteSpace(display) || display.StartsWith('@'))
        {
            string stem = Path.GetFileNameWithoutExtension(fileName);
            int sepIdx = stem.IndexOf(" - ", StringComparison.Ordinal);
            display = sepIdx >= 0 ? stem[(sepIdx + 3)..] : stem;
        }

        bool isEnabled = true;
        try { isEnabled = (fi.Attributes & FileAttributes.Hidden) != FileAttributes.Hidden; } catch { }

        return new WinXShortcutEntry
        {
            FilePath = lnkPath,
            GroupName = groupName,
            GroupPath = groupDir,
            DisplayName = display,
            TargetPath = string.IsNullOrWhiteSpace(targetPath) ? lnkPath : targetPath,
            Arguments = arguments,
            IsEnabled = isEnabled
        };
    }

    private static string MakeUniqueFilePath(string candidatePath)
    {
        if (!File.Exists(candidatePath))
            return candidatePath;

        string dir = Path.GetDirectoryName(candidatePath) ?? string.Empty;
        string stem = Path.GetFileNameWithoutExtension(candidatePath);
        string ext = Path.GetExtension(candidatePath);
        int counter = 2;
        string next;
        do
        {
            next = Path.Combine(dir, $"{stem} ({counter++}){ext}");
        } while (File.Exists(next));
        return next;
    }

    private static string SanitizeFileName(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return string.Empty;
        var invalid = Path.GetInvalidFileNameChars();
        var sb = new StringBuilder(raw.Length);
        foreach (char c in raw.Trim())
        {
            if (Array.IndexOf(invalid, c) < 0)
                sb.Append(c);
        }
        return sb.ToString().Trim();
    }

    private static Dictionary<string, string> ReadDesktopIniLocalizedNames(string directory)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        string iniPath = Path.Combine(directory, "desktop.ini");
        if (!File.Exists(iniPath))
            return map;

        try
        {
            bool inLocalized = false;
            foreach (string rawLine in File.ReadLines(iniPath))
            {
                string line = rawLine.Trim();
                if (string.IsNullOrEmpty(line) || line.StartsWith(';'))
                    continue;
                if (line.StartsWith('[') && line.EndsWith(']'))
                {
                    inLocalized = line.Equals("[LocalizedFileNames]", StringComparison.OrdinalIgnoreCase);
                    continue;
                }
                if (!inLocalized) continue;

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
        catch { }

        return map;
    }

    private static string? ReadDesktopIniValue(string directory, string key)
    {
        var map = ReadDesktopIniLocalizedNames(directory);
        return map.TryGetValue(key, out string? value) ? value : null;
    }

    private static void RunWithWritableIniAttributes(string iniPath, Action writeAction)
    {
        FileAttributes? originalAttrs = null;
        const FileAttributes protectedMask = FileAttributes.Hidden | FileAttributes.System | FileAttributes.ReadOnly;
        try
        {
            if (File.Exists(iniPath))
            {
                FileAttributes attrs = File.GetAttributes(iniPath);
                if ((attrs & protectedMask) != 0)
                {
                    originalAttrs = attrs;
                    File.SetAttributes(iniPath, attrs & ~protectedMask);
                }
            }

            writeAction();
        }
        finally
        {
            if (originalAttrs.HasValue && File.Exists(iniPath))
            {
                try
                {
                    File.SetAttributes(iniPath, originalAttrs.Value);
                }
                catch { }
            }
        }
    }

    private static void EnsureUnicodeIniFile(string iniPath)
    {
        if (!File.Exists(iniPath))
            return;

        byte[] raw = File.ReadAllBytes(iniPath);
        if (raw.Length >= 2 && raw[0] == 0xFF && raw[1] == 0xFE)
            return; // 已经是 UTF-16LE BOM

        Encoding srcEnc = raw.Length >= 3 && raw[0] == 0xEF && raw[1] == 0xBB && raw[2] == 0xBF
            ? Encoding.UTF8
            : new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: false);
        string text = srcEnc.GetString(raw).TrimStart('\uFEFF');
        RunWithWritableIniAttributes(iniPath, () => File.WriteAllText(iniPath, text, Encoding.Unicode));
    }

    private static void SetDesktopIniValue(string directory, string key, string value)
    {
        string iniPath = Path.Combine(directory, "desktop.ini");
        EnsureUnicodeIniFile(iniPath);
        RunWithWritableIniAttributes(iniPath, () => WritePrivateProfileStringW("LocalizedFileNames", key, value, iniPath));
    }

    private static void DeleteDesktopIniValue(string directory, string key)
    {
        string iniPath = Path.Combine(directory, "desktop.ini");
        if (File.Exists(iniPath))
        {
            EnsureUnicodeIniFile(iniPath);
            RunWithWritableIniAttributes(iniPath, () => WritePrivateProfileStringW("LocalizedFileNames", key, null, iniPath));
        }
    }

    private static string? ReadShortcutDescription(string lnkPath)
    {
        if (!OperatingSystem.IsWindows())
            return null;

        try
        {
            var link = (IShellLinkW)new CShellLink();
            try
            {
                ((IPersistFile)link).Load(lnkPath, 0); // STGM_READ
                var sb = new StringBuilder(1024);
                link.GetDescription(sb, sb.Capacity);
                return sb.ToString().Trim();
            }
            finally
            {
                Marshal.FinalReleaseComObject(link);
            }
        }
        catch
        {
            return null;
        }
    }

    private static void ReadShortcutTarget(string lnkPath, out string targetPath, out string arguments)
    {
        targetPath = string.Empty;
        arguments = string.Empty;
        try
        {
            var link = (IShellLinkW)new CShellLink();
            try
            {
                ((IPersistFile)link).Load(lnkPath, 0);
                var sbTarget = new StringBuilder(260);
                var data = new WIN32_FIND_DATAW();
                link.GetPath(sbTarget, sbTarget.Capacity, ref data, 2); // SLGP_UNCPRIORITY
                targetPath = sbTarget.ToString().Trim();

                var sbArgs = new StringBuilder(1024);
                link.GetArguments(sbArgs, sbArgs.Capacity);
                arguments = sbArgs.ToString().Trim();
            }
            finally
            {
                Marshal.FinalReleaseComObject(link);
            }
        }
        catch { }
    }

    private static void WriteShortcutDescription(string lnkPath, string description)
    {
        if (!OperatingSystem.IsWindows())
            return;

        try
        {
            var link = (IShellLinkW)new CShellLink();
            try
            {
                var pf = (IPersistFile)link;
                pf.Load(lnkPath, 2); // STGM_READWRITE
                link.SetDescription(description);
                pf.Save(lnkPath, true);
            }
            finally
            {
                Marshal.FinalReleaseComObject(link);
            }
        }
        catch { }
    }

    /// <summary>
    /// 计算并写入 Explorer 所需的 System.Winx.Hash 属性，使修改后的 .lnk 在 Win+X 菜单中可被加载。
    /// </summary>
    public static void TryHashLnk(string lnkPath)
    {
        if (!OperatingSystem.IsWindows() || string.IsNullOrWhiteSpace(lnkPath) || !File.Exists(lnkPath))
            return;

        IntPtr shellItemPtr = IntPtr.Zero;
        object? shellItemObj = null;
        object? storeObj = null;
        try
        {
            Guid iidShellItem2 = typeof(IShellItem2).GUID;
            int hr = SHCreateItemFromParsingName(lnkPath, IntPtr.Zero, ref iidShellItem2, out shellItemPtr);
            if (hr != 0 || shellItemPtr == IntPtr.Zero)
                return;

            shellItemObj = Marshal.GetObjectForIUnknown(shellItemPtr);
            if (shellItemObj is not IShellItem2 item2)
                return;

            PSGetPropertyKeyFromName("System.Link.TargetParsingPath", out PropertyKey pkTarget);
            string targetPath = string.Empty;
            try { targetPath = item2.GetString(pkTarget) ?? string.Empty; } catch { }

            PSGetPropertyKeyFromName("System.Link.Arguments", out PropertyKey pkArgs);
            string arguments = string.Empty;
            try { arguments = item2.GetString(pkArgs) ?? string.Empty; } catch { }

            string blob = (GeneralizePath(targetPath) + arguments + "do not prehash links.  this should only be done by the user.").ToLowerInvariant();
            byte[] inBytes = Encoding.Unicode.GetBytes(blob);
            byte[] outBytes = new byte[inBytes.Length];
            HashData(inBytes, inBytes.Length, outBytes, outBytes.Length);
            uint hash = BitConverter.ToUInt32(outBytes, 0);

            Guid iidStore = typeof(IPropertyStore).GUID;
            storeObj = item2.GetPropertyStore(2 /* GPS_READWRITE */, ref iidStore);
            if (storeObj is IPropertyStore store)
            {
                PSGetPropertyKeyFromName("System.Winx.Hash", out PropertyKey pkHash);
                var pv = new PropVariant { VarType = VarEnum.VT_UI4, ulVal = hash };
                store.SetValue(ref pkHash, ref pv);
                store.Commit();
            }
        }
        catch { }
        finally
        {
            if (storeObj != null) try { Marshal.ReleaseComObject(storeObj); } catch { }
            if (shellItemObj != null) try { Marshal.ReleaseComObject(shellItemObj); } catch { }
            if (shellItemPtr != IntPtr.Zero) try { Marshal.Release(shellItemPtr); } catch { }
        }
    }

    private static string GeneralizePath(string filePath)
    {
        if (string.IsNullOrEmpty(filePath)) return string.Empty;
        ReadOnlySpan<(string EnvVar, string KnownFolderGuid)> knownFolders =
        [
            ("%ProgramFiles%", "{905e63b6-c1bf-494e-b29c-65b732d3d21a}"),
            (@"%SystemRoot%\System32", "{1ac14e77-02e7-4e5d-b744-2eb1ae5198b7}"),
            ("%SystemRoot%", "{f38bf404-1d43-42f2-9305-67de0b28fc23}")
        ];
        foreach (var (envVar, guid) in knownFolders)
        {
            string expanded = Environment.ExpandEnvironmentVariables(envVar);
            if (filePath.StartsWith(expanded + "\\", StringComparison.OrdinalIgnoreCase))
            {
                return guid + filePath[expanded.Length..];
            }
        }
        return filePath;
    }

    #region Native / COM Interop

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WritePrivateProfileStringW(string lpAppName, string lpKeyName, string? lpString, string lpFileName);

    [DllImport("shlwapi.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int HashData(byte[] pbData, int cbData, byte[] pbHash, int cbHash);

    [DllImport("propsys.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int PSGetPropertyKeyFromName(string pszName, out PropertyKey ppropkey);

    [DllImport("shell32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int SHCreateItemFromParsingName(string pszPath, IntPtr pbc, ref Guid riid, out IntPtr ppv);

    [ComImport, InterfaceType(ComInterfaceType.InterfaceIsIUnknown), Guid("000214F9-0000-0000-C000-000000000046")]
    private interface IShellLinkW
    {
        void GetPath([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszFile, int cchMaxPath, ref WIN32_FIND_DATAW pfd, uint fFlags);
        void GetIDList(out IntPtr ppidl);
        void SetIDList(IntPtr pidl);
        void GetDescription([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszName, int cchMaxName);
        void SetDescription([MarshalAs(UnmanagedType.LPWStr)] string pszName);
        void GetWorkingDirectory([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszDir, int cchMaxPath);
        void SetWorkingDirectory([MarshalAs(UnmanagedType.LPWStr)] string pszDir);
        void GetArguments([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszArgs, int cchMaxPath);
        void SetArguments([MarshalAs(UnmanagedType.LPWStr)] string pszArgs);
        void GetHotKey(out ushort pwHotkey);
        void SetHotKey(ushort wHotKey);
        void GetShowCmd(out int piShowCmd);
        void SetShowCmd(int iShowCmd);
        void GetIconLocation([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszIconPath, int cchIconPath, out int piIcon);
        void SetIconLocation([MarshalAs(UnmanagedType.LPWStr)] string pszIconPath, int iIcon);
        void SetRelativePath([MarshalAs(UnmanagedType.LPWStr)] string pszPathRel, uint dwReserved);
        void Resolve(IntPtr hwnd, uint fFlags);
        void SetPath([MarshalAs(UnmanagedType.LPWStr)] string pszFile);
    }

    [ComImport, ClassInterface(ClassInterfaceType.None), Guid("00021401-0000-0000-C000-000000000046")]
    private class CShellLink { }

    [ComImport, InterfaceType(ComInterfaceType.InterfaceIsIUnknown), Guid("7e9fb0d3-919f-4307-ab2e-9b1860310c93")]
    private interface IShellItem2
    {
        void BindToHandler(IntPtr pbc, ref Guid bhid, ref Guid riid, out IntPtr ppv);
        void GetParent(out IntPtr ppsi);
        void GetDisplayName(uint sigdnName, [MarshalAs(UnmanagedType.LPWStr)] out string ppszName);
        void GetAttributes(uint sfgaoMask, out uint psfgaoAttribs);
        void Compare(IntPtr psi, uint hint, out int piOrder);
        [return: MarshalAs(UnmanagedType.Interface)]
        IPropertyStore GetPropertyStore(int flags, ref Guid riid);
        void GetPropertyStoreWithCreateObject(int flags, [MarshalAs(UnmanagedType.IUnknown)] object punkCreateObject, ref Guid riid, out IntPtr ppv);
        void GetPropertyStoreForKeys(IntPtr rgKeys, uint cKeys, int flags, ref Guid riid, out IntPtr ppv);
        void GetPropertyDescriptionList(PropertyKey keyType, ref Guid riid, out IntPtr ppv);
        void Update(IntPtr pbc);
        void GetProperty(PropertyKey key, out PropVariant pv);
        Guid GetCLSID(PropertyKey key);
        ComTypes.FILETIME GetFileTime(PropertyKey key);
        int GetInt32(PropertyKey key);
        [return: MarshalAs(UnmanagedType.LPWStr)]
        string? GetString(PropertyKey key);
        uint GetUInt32(PropertyKey key);
        ulong GetUInt64(PropertyKey key);
        [return: MarshalAs(UnmanagedType.Bool)]
        bool GetBool(PropertyKey key);
    }

    [ComImport, InterfaceType(ComInterfaceType.InterfaceIsIUnknown), Guid("886d8eeb-8cf2-4446-8d02-cdba1dbdcf99")]
    private interface IPropertyStore
    {
        uint GetCount(out uint cProps);
        uint GetAt(uint iProp, out PropertyKey pkey);
        uint GetValue(ref PropertyKey key, out PropVariant pv);
        uint SetValue(ref PropertyKey key, ref PropVariant pv);
        uint Commit();
    }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    private struct PropertyKey
    {
        public Guid GUID;
        public int PID;
    }

    [StructLayout(LayoutKind.Explicit, Pack = 1)]
    private struct PropVariant
    {
        [FieldOffset(0)] public VarEnum VarType;
        [FieldOffset(2)] public ushort wReserved1;
        [FieldOffset(4)] public ushort wReserved2;
        [FieldOffset(6)] public ushort wReserved3;
        [FieldOffset(8)] public ulong ulVal;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 4, CharSet = CharSet.Unicode)]
    private struct WIN32_FIND_DATAW
    {
        public uint dwFileAttributes;
        public ComTypes.FILETIME ftCreationTime;
        public ComTypes.FILETIME ftLastAccessTime;
        public ComTypes.FILETIME ftLastWriteTime;
        public uint nFileSizeHigh;
        public uint nFileSizeLow;
        public uint dwReserved0;
        public uint dwReserved1;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string cFileName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 14)] public string cAlternateFileName;
    }

    #endregion
}
