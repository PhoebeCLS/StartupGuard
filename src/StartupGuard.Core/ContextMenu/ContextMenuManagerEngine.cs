using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using StartupGuard.Core.Models;
using StartupGuard.Core.Native;
using StartupGuard.Core.Scoring;
using StartupGuard.Core.Storage;

namespace StartupGuard.Core.ContextMenu;

/// <summary>
/// 上下文菜单条目模型 (同时兼容经典 Shell / ContextMenuHandlers 与 Win11 PackagedCom 现代菜单)
/// </summary>
public sealed class ContextMenuItemEntry
{
    public required string IdKey { get; init; }
    public required string DisplayTitle { get; set; }
    public required MonitorCategory MenuCategory { get; init; } // ClassicContextMenu or ModernContextMenu
    public required string ScopeScene { get; init; }            // e.g. "*", "Directory", "DesktopBackground", "Win11PackagedCom"
    public required string RegistryPath { get; set; }
    public string Clsid { get; init; } = string.Empty;
    public string TargetBinaryOrCommand { get; set; } = string.Empty;
    public string PackageFullName { get; init; } = string.Empty;
    public string Publisher { get; set; } = string.Empty;
    public bool IsEnabled { get; set; } = true;
    public long LastWriteTimeFileTime { get; init; }
}

/// <summary>
/// 上下文菜单场景描述映射辅助类
/// </summary>
public static class ContextMenuSceneHelper
{
    public static string DescribeScene(MonitorCategory category, string? locationKey, string? scopeScene = null)
    {
        if (category == MonitorCategory.ModernContextMenu ||
            (locationKey?.StartsWith("Approved:", StringComparison.OrdinalIgnoreCase) == true) ||
            string.Equals(scopeScene, "Win11PackagedCom", StringComparison.OrdinalIgnoreCase))
        {
            return "Win11 现代菜单";
        }

        string loc = (locationKey ?? string.Empty).ToLowerInvariant();
        string raw = (scopeScene ?? string.Empty).ToLowerInvariant();

        if (loc.Contains("dragdrop") || raw.Contains("dragdrop"))
            return "右键拖拽";
        if (loc.Contains(@"\winx\") || raw.Contains("winx"))
            return "Win+X";
        if (loc.Contains("commandstore") || raw == "commandstore")
            return "公共引用";
        if (raw == "scene_guidblocked" || loc.Contains(@"\shell extensions\blocked"))
            return "GUID 锁";
        if (loc.Contains(@"directory\background") || raw.Contains("dirbackground") || raw.Contains("目录背景"))
            return "目录背景";
        if (loc.Contains("desktopbackground") || raw.Contains("desktop"))
            return "桌面背景";
        if (loc.Contains(@"classes\directory\") || raw == "directory" || raw.Contains("目录"))
            return "目录";
        if (loc.Contains(@"classes\folder") || raw == "folder" || raw.Contains("文件夹"))
            return "文件夹";
        if (loc.Contains("allfilesystemobjects") || raw.Contains("allobjects") || raw.Contains("所有对象"))
            return "所有文件系统对象";
        if (loc.Contains(@"classes\*") || raw == "*" || raw.Contains("allfiles") || raw.Contains("所有文件"))
            return "所有文件";
        if (loc.Contains(@"classes\drive") || raw == "drive" || raw.Contains("驱动器"))
            return "磁盘驱动器";
        if (loc.Contains("20d04fe0") || raw.Contains("thispc") || raw.Contains("此电脑"))
            return "此电脑";
        if (loc.Contains("645ff040") || raw.Contains("recyclebin") || raw.Contains("回收站"))
            return "回收站";
        if (loc.Contains("library") || raw.Contains("库"))
            return "库";
        if (loc.Contains("sendto") || raw.Contains("发送到"))
            return "发送到";
        if (loc.Contains("openwith") || raw.Contains("打开方式"))
            return "打开方式";
        if (loc.Contains("shellnew") || raw.Contains("新建"))
            return "新建菜单";
        if (!string.IsNullOrWhiteSpace(scopeScene))
            return scopeScene;

        return "传统右键菜单";
    }
}

/// <summary>
/// Windows 右键菜单扫描与状态管理引擎（支持经典 Shell/ShellEx、Win11 PackagedCom、特殊菜单与深度探测）。
/// 注册表扫描策略、禁用方式及特殊目录规则参考并遵循 GNU GPL-3.0 开源项目 PLFJY/ContextMenuMgr (https://github.com/PLFJY/ContextMenuMgr) 与 BluePointLilac/ContextMenuManager (https://github.com/BluePointLilac/ContextMenuManager)。
/// </summary>
public sealed unsafe partial class ContextMenuManagerEngine
{
    private const string AdvApi32Dll = "advapi32.dll";
    private const string BlockedExtensionsSubKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked";

    [LibraryImport(AdvApi32Dll, EntryPoint = "RegOpenKeyExW", StringMarshalling = StringMarshalling.Utf16)]
    private static partial int RegOpenKeyExW(nint hKey, string lpSubKey, uint ulOptions, uint samDesired, out nint phkResult);

    [LibraryImport(AdvApi32Dll, EntryPoint = "RegCreateKeyExW", StringMarshalling = StringMarshalling.Utf16)]
    private static partial int RegCreateKeyExW(
        nint hKey,
        string lpSubKey,
        uint reserved,
        string? lpClass,
        uint dwOptions,
        uint samDesired,
        nint lpSecurityAttributes,
        out nint phkResult,
        out uint lpdwDisposition);

    [LibraryImport(AdvApi32Dll, EntryPoint = "RegEnumKeyExW", StringMarshalling = StringMarshalling.Utf16)]
    private static partial int RegEnumKeyExW(
        nint hKey,
        uint dwIndex,
        char* lpName,
        ref uint lpcchName,
        nint lpReserved,
        nint lpClass,
        nint lpcchClass,
        out long lpftLastWriteTime);

    [LibraryImport(AdvApi32Dll, EntryPoint = "RegQueryValueExW", StringMarshalling = StringMarshalling.Utf16)]
    private static partial int RegQueryValueExW(
        nint hKey,
        string? lpValueName,
        nint lpReserved,
        out uint lpType,
        byte* lpData,
        ref uint lpcbData);

    [LibraryImport(AdvApi32Dll, EntryPoint = "RegSetValueExW", StringMarshalling = StringMarshalling.Utf16)]
    private static partial int RegSetValueExW(nint hKey, string? lpValueName, uint reserved, uint dwType, byte* lpData, uint cbData);

    [LibraryImport(AdvApi32Dll, EntryPoint = "RegDeleteValueW", StringMarshalling = StringMarshalling.Utf16)]
    private static partial int RegDeleteValueW(nint hKey, string lpValueName);

    [LibraryImport(AdvApi32Dll)]
    private static partial int RegCloseKey(nint hKey);

    [LibraryImport("shlwapi.dll", EntryPoint = "SHLoadIndirectString", StringMarshalling = StringMarshalling.Utf16)]
    private static partial int SHLoadIndirectStringNative(string pszSource, char* pszOutBuf, uint cchOutBuf, nint ppvReserved);

    [LibraryImport("kernel32.dll", EntryPoint = "LoadLibraryExW", StringMarshalling = StringMarshalling.Utf16)]
    private static partial nint LoadLibraryExW(string lpLibFileName, nint hFile, uint dwFlags);

    [LibraryImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool FreeLibrary(nint hLibModule);

    [LibraryImport("user32.dll", EntryPoint = "LoadStringW", StringMarshalling = StringMarshalling.Utf16)]
    private static partial int LoadStringW(nint hInstance, uint uID, char* lpBuffer, int cchBufferMax);

    [LibraryImport("shell32.dll", EntryPoint = "SHGetFileInfoW", StringMarshalling = StringMarshalling.Utf16)]
    private static partial nint SHGetFileInfoW(string pszPath, uint dwFileAttributes, ref SHFILEINFOW psfi, uint cbFileInfo, uint uFlags);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct SHFILEINFOW
    {
        public nint hIcon;
        public int iIcon;
        public uint dwAttributes;
        public fixed char szDisplayName[260];
        public fixed char szTypeName[80];
    }

    private const uint LOAD_LIBRARY_AS_DATAFILE = 0x00000002;
    private const uint SHGFI_DISPLAYNAME = 0x000000200;

    private static readonly ConcurrentDictionary<string, string> _muiStringCache = new(StringComparer.OrdinalIgnoreCase);

    public static string ResolveMuiString(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return string.Empty;
        string s = raw.Trim();

        // 1. 若以分号开头或包含分号 (INF 格式描述，如 @1394.inf,...;1394 OHCI...)
        int semi = s.LastIndexOf(';');
        if (semi >= 0 && semi < s.Length - 1)
        {
            string after = s[(semi + 1)..].Trim();
            if (!string.IsNullOrEmpty(after)) return CleanMenuMnemonic(after);
        }

        // 2. 若以 @ 开头，走缓存并用 shlwapi.dll SHLoadIndirectString（原生 MUI 加载）及 LoadStringW 兜底
        if (s.StartsWith('@'))
        {
            return _muiStringCache.GetOrAdd(s, static key => ResolveAtMuiStringUncached(key));
        }

        return CleanMenuMnemonic(s);
    }

    private static string ResolveAtMuiStringUncached(string s)
    {
        string expanded = Environment.ExpandEnvironmentVariables(s);
        if (OperatingSystem.IsWindows())
        {
            try
            {
                char* outBuf = stackalloc char[1024];
                if (SHLoadIndirectStringNative(expanded, outBuf, 1024, 0) == 0)
                {
                    string res = new string(outBuf).Trim();
                    if (!string.IsNullOrEmpty(res)) return CleanMenuMnemonic(res);
                }
            }
            catch { }

            // 若 SHLoadIndirectString 因路径写法未能解析，尝试 LoadLibraryExW + LoadStringW 直接从 PE 资源提取
            string? resLoaded = TryLoadResourceStringDirect(expanded);
            if (!string.IsNullOrWhiteSpace(resLoaded))
                return CleanMenuMnemonic(resLoaded);

            // 若原资源指向 shell32.dll 且 Win10/11 已迁移至 windows.storage.dll，尝试交叉探测
            if (expanded.Contains("shell32.dll,", StringComparison.OrdinalIgnoreCase))
            {
                int commaIdx = expanded.LastIndexOf(',');
                if (commaIdx > 1)
                {
                    string storageExpr = "@windows.storage.dll," + expanded[(commaIdx + 1)..];
                    try
                    {
                        char* outBuf2 = stackalloc char[1024];
                        if (SHLoadIndirectStringNative(storageExpr, outBuf2, 1024, 0) == 0)
                        {
                            string res2 = new string(outBuf2).Trim();
                            if (!string.IsNullOrEmpty(res2)) return CleanMenuMnemonic(res2);
                        }
                    }
                    catch { }

                    string? storageLoaded = TryLoadResourceStringDirect(storageExpr);
                    if (!string.IsNullOrWhiteSpace(storageLoaded))
                        return CleanMenuMnemonic(storageLoaded);
                }
            }
        }

        // 3. 离线兜底常见内置资源 ID 映射（不再截断返回 "shell32" 这类 DLL 名）
        string lower = expanded.ToLowerInvariant();
        if (lower.Contains("shell32.dll,-8506")) return "在此处打开命令窗口";
        if (lower.Contains("shell32.dll,-8507") || lower.Contains("shell32.dll,-8508")) return "在此处打开 PowerShell 窗口";
        if (lower.Contains("shell32.dll,-30598") || lower.Contains("windowsterminal")) return "在终端中打开";
        if (lower.Contains("display.dll,-4")) return "显示设置";
        if (lower.Contains("display.dll,-1")) return "显示";
        if (lower.Contains("themecpl.dll,-10")) return "个性化";
        if (lower.Contains("themecpl.dll,-1")) return "桌面图标设置";
        if (lower.Contains("zipfldr.dll,-10194")) return "全部提取...";
        if (lower.Contains("zipfldr.dll,-10195")) return "压缩为 ZIP 文件";

        return string.Empty;
    }

    private static string? TryLoadResourceStringDirect(string atResourceExpr)
    {
        if (!atResourceExpr.StartsWith('@')) return null;
        int comma = atResourceExpr.LastIndexOf(',');
        if (comma <= 1 || comma >= atResourceExpr.Length - 1) return null;

        string dllSpec = atResourceExpr[1..comma].Trim().Trim('"');
        string idPart = atResourceExpr[(comma + 1)..].Trim();
        if (!int.TryParse(idPart, out int signedId)) return null;
        uint resId = (uint)Math.Abs(signedId);

        if (!File.Exists(dllSpec) && !dllSpec.Contains('\\'))
        {
            string sysPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), dllSpec);
            if (File.Exists(sysPath)) dllSpec = sysPath;
        }

        nint hMod = LoadLibraryExW(dllSpec, 0, LOAD_LIBRARY_AS_DATAFILE);
        if (hMod == 0) return null;
        try
        {
            char* buf = stackalloc char[1024];
            int len = LoadStringW(hMod, resId, buf, 1024);
            if (len > 0)
                return new string(buf, 0, len).Trim();
        }
        finally
        {
            FreeLibrary(hMod);
        }
        return null;
    }

    private static string CleanMenuMnemonic(string text)
    {
        if (string.IsNullOrWhiteSpace(text)) return string.Empty;
        string cleaned = Regex.Replace(text, @"\(&[A-Za-z0-9]\)", string.Empty);
        cleaned = Regex.Replace(cleaned, @"&([A-Za-z0-9])", "$1");
        return cleaned.Trim();
    }

    private static Dictionary<string, string> ReadDesktopIniLocalizedNames(string directory)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            string iniPath = Path.Combine(directory, "desktop.ini");
            if (!File.Exists(iniPath)) return map;

            bool inLocalizedSection = false;
            foreach (string rawLine in File.ReadAllLines(iniPath))
            {
                string line = rawLine.Trim();
                if (string.IsNullOrEmpty(line) || line.StartsWith(';')) continue;
                if (line.StartsWith('[') && line.EndsWith(']'))
                {
                    inLocalizedSection = line.Equals("[LocalizedFileNames]", StringComparison.OrdinalIgnoreCase);
                    continue;
                }

                if (!inLocalizedSection) continue;
                int eq = line.IndexOf('=');
                if (eq > 0 && eq < line.Length - 1)
                {
                    string fileName = line[..eq].Trim();
                    string muiRef = line[(eq + 1)..].Trim();
                    string resolved = ResolveMuiString(muiRef);
                    if (!string.IsNullOrWhiteSpace(resolved) && !resolved.StartsWith('@'))
                    {
                        map[fileName] = resolved;
                    }
                }
            }
        }
        catch { }
        return map;
    }

    private static string ResolveSpecialFileDisplayName(string fullFilePath, Dictionary<string, string>? desktopIniMap)
    {
        string fileName = Path.GetFileName(fullFilePath);
        if (desktopIniMap != null && desktopIniMap.TryGetValue(fileName, out string? mapped) && !string.IsNullOrWhiteSpace(mapped))
            return mapped;

        if (OperatingSystem.IsWindows())
        {
            try
            {
                SHFILEINFOW shfi = default;
                nint ok = SHGetFileInfoW(fullFilePath, 0, ref shfi, (uint)sizeof(SHFILEINFOW), SHGFI_DISPLAYNAME);
                if (ok != 0)
                {
                    string shellDisplay = new string(shfi.szDisplayName).TrimEnd('\0').Trim();
                    if (!string.IsNullOrWhiteSpace(shellDisplay))
                        return shellDisplay;
                }
            }
            catch { }
        }

        return Path.GetFileNameWithoutExtension(fileName);
    }

    public static string ResolveClsidFriendlyName(nint rootHive, string clsid, string? activeUserSid = null)
    {
        if (string.IsNullOrEmpty(clsid)) return string.Empty;
        string normalized = clsid.StartsWith('{') ? clsid : $"{{{clsid}}}";

        // 1. 优先通过 GUID 字典及 LocalizedString / InfoTip 资源解析中文系统展示名
        string guidResolved = ContextMenuGuidResolver.GetClsidText(normalized);
        if (!string.IsNullOrEmpty(guidResolved) && !guidResolved.StartsWith('@') && !guidResolved.StartsWith('{'))
        {
            return CleanMenuMnemonic(guidResolved);
        }

        // 2. 查询 LocalizedString
        string locString = ReadRegistryStringValue(rootHive, $@"SOFTWARE\Classes\CLSID\{normalized}", "LocalizedString", KEY_WOW64_64KEY);
        if (string.IsNullOrEmpty(locString))
        {
            locString = ReadRegistryStringValue(rootHive, $@"SOFTWARE\Classes\CLSID\{normalized}", "LocalizedString", KEY_WOW64_32KEY);
        }
        if (!string.IsNullOrEmpty(locString))
        {
            string resolved = ResolveMuiString(locString);
            if (!string.IsNullOrEmpty(resolved) && !resolved.StartsWith('@') && !resolved.StartsWith('{')) return resolved;
        }

        // 3. 查询 CLSID (Default) (同时检查 64 位与 32 位 WOW64)
        string title = ReadRegistryStringValue(rootHive, $@"SOFTWARE\Classes\CLSID\{normalized}", null, KEY_WOW64_64KEY);
        if (string.IsNullOrEmpty(title) || title.StartsWith('{'))
        {
            title = ReadRegistryStringValue(rootHive, $@"SOFTWARE\Classes\CLSID\{normalized}", null, KEY_WOW64_32KEY);
        }
        if (string.IsNullOrEmpty(title) || title.StartsWith('{'))
        {
            title = ReadRegistryStringValue(rootHive, $@"SOFTWARE\Classes\WOW6432Node\CLSID\{normalized}", null, KEY_WOW64_64KEY);
        }
        if (string.IsNullOrEmpty(title) || title.StartsWith('{'))
        {
            title = ReadRegistryStringValue(rootHive, $@"SOFTWARE\WOW6432Node\Classes\CLSID\{normalized}", null, KEY_WOW64_64KEY);
        }
        if (!string.IsNullOrEmpty(title) && !title.StartsWith('{'))
        {
            string resolved = ResolveMuiString(title);
            if (!string.IsNullOrEmpty(resolved) && !resolved.StartsWith('@') && !resolved.StartsWith('{')) return resolved;
        }

        // 4. 常见内置 ShellEx CLSID 友好名称映射表
        string mapped = normalized.ToUpperInvariant() switch
        {
            "{645FF040-5081-101B-9F08-00AA002F954E}" => "回收站",
            "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" => "此电脑",
            "{00021401-0000-0000-C000-000000000046}" => "快捷方式",
            "{FBF23B40-E3F0-101B-8488-00AA003E56F8}" => "Internet 快捷方式",
            "{21EC2020-3AEA-1069-A2DD-08002B30309D}" => "控制面板",
            "{85BBD920-42A0-1069-A2E4-08002B30309D}" => "公文包",
            "{BD7082A7-422C-4409-BDC0-D2B83BE78680}" => "桌面背景",
            "{A2A9545D-A0C2-42B4-9708-A0B2BADD77C8}" => "启动器扩展",
            "{09799AFB-AD67-11D1-ABCD-00C04FC6B8B1}" => "桌面清理向导",
            "{E357FCCE-A995-4576-B01F-234630154E96}" => "WMP 播放列表扩展",
            "{B41DB591-3051-4B33-A526-F47E88E454E2}" => "Windows 共享扩展",
            "{F81E9010-6EA4-11CE-A7FF-00AA003CA9F6}" => "格式化扩展",
            "{0F8604A5-4ECE-4DE1-8A7D-CF10F8AA4F48}" => "联系人文件夹",
            _ => string.Empty
        };
        if (!string.IsNullOrEmpty(mapped)) return mapped;

        // 5. 读取真实宿主 DLL 的 FileVersionInfo 描述
        try
        {
            string dll = ResolveClassicComInprocServer32(clsid, activeUserSid);
            if (!string.IsNullOrEmpty(dll) && File.Exists(dll))
            {
                var fvi = FileVersionInfo.GetVersionInfo(dll);
                if (!string.IsNullOrWhiteSpace(fvi.FileDescription))
                    return fvi.FileDescription.Trim();
                if (!string.IsNullOrWhiteSpace(fvi.ProductName))
                    return fvi.ProductName.Trim();
                string fname = Path.GetFileNameWithoutExtension(dll);
                if (!string.IsNullOrWhiteSpace(fname))
                    return fname;
            }
        }
        catch { }

        return string.Empty;
    }

    private const uint KEY_READ = 0x20019;
    private const uint KEY_WRITE = 0x20006;
    private const uint KEY_SET_VALUE = 0x0002;
    private const uint KEY_WOW64_64KEY = 0x0100;
    private const uint KEY_WOW64_32KEY = 0x0200;
    private const uint REG_SZ = 1;
    private const uint REG_OPTION_BACKUP_RESTORE = 0x00000004;

    /// <summary>
    /// 经典右键菜单全场景监控表
    /// </summary>
    public static readonly (string SceneName, string RelativeSubKey)[] ClassicShellScenes =
    [
        ("AllFiles (*)", @"Software\Classes\*\shell"),
        ("AllFiles Handlers", @"Software\Classes\*\shellex\ContextMenuHandlers"),
        ("Folder", @"Software\Classes\Folder\shell"),
        ("Folder Handlers", @"Software\Classes\Folder\shellex\ContextMenuHandlers"),
        ("Directory", @"Software\Classes\Directory\shell"),
        ("Directory Handlers", @"Software\Classes\Directory\shellex\ContextMenuHandlers"),
        ("DirectoryBackground", @"Software\Classes\Directory\Background\shell"),
        ("DirectoryBackground Handlers", @"Software\Classes\Directory\Background\shellex\ContextMenuHandlers"),
        ("DesktopBackground", @"Software\Classes\DesktopBackground\Shell"),
        ("DesktopBackground Handlers", @"Software\Classes\DesktopBackground\shellex\ContextMenuHandlers"),
        ("Drive", @"Software\Classes\Drive\shell"),
        ("Drive Handlers", @"Software\Classes\Drive\shellex\ContextMenuHandlers"),
        ("AllFilesystemObjects Shell", @"Software\Classes\AllFilesystemObjects\shell"),
        ("AllFilesystemObjects", @"Software\Classes\AllFilesystemObjects\shellex\ContextMenuHandlers"),
        ("Computer", @"Software\Classes\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\shell"),
        ("Computer Handlers", @"Software\Classes\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\shellex\ContextMenuHandlers"),
        ("RecycleBin", @"Software\Classes\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}\shell"),
        ("RecycleBin Handlers", @"Software\Classes\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}\shellex\ContextMenuHandlers"),
        ("Library", @"Software\Classes\LibraryFolder\shell"),
        ("Library Handlers", @"Software\Classes\LibraryFolder\shellex\ContextMenuHandlers"),
        ("LibraryBackground", @"Software\Classes\LibraryFolder\background\shell"),
        ("LibraryBackground Handlers", @"Software\Classes\LibraryFolder\background\shellex\ContextMenuHandlers"),
        ("UserLibrary", @"Software\Classes\UserLibraryFolder\shell"),
        ("UserLibrary Handlers", @"Software\Classes\UserLibraryFolder\shellex\ContextMenuHandlers"),
        ("LnkFile", @"Software\Classes\lnkfile\shell"),
        ("LnkFile Handlers", @"Software\Classes\lnkfile\shellex\ContextMenuHandlers"),
        ("UwpLnk", @"Software\Classes\Launcher.ImmersiveApplication\shell"),
        ("UwpLnk Handlers", @"Software\Classes\Launcher.ImmersiveApplication\shellex\ContextMenuHandlers"),
        ("ExeFile", @"Software\Classes\exefile\shell"),
        ("ExeFile Handlers", @"Software\Classes\exefile\shellex\ContextMenuHandlers"),
        ("UnknownType", @"Software\Classes\Unknown\shell"),
        ("UnknownType Handlers", @"Software\Classes\Unknown\shellex\ContextMenuHandlers"),
        ("DragDrop File", @"Software\Classes\*\shellex\DragDropHandlers"),
        ("DragDrop Folder", @"Software\Classes\Folder\shellex\DragDropHandlers"),
        ("DragDrop Directory", @"Software\Classes\Directory\shellex\DragDropHandlers"),
        ("DragDrop Drive", @"Software\Classes\Drive\shellex\DragDropHandlers"),
        ("CommandStore", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell")
    ];

    /// <summary>
    /// Win11 现代右键菜单 PackagedCom ClassIndex 注册位置
    /// </summary>
    public static readonly string[] Win11PackagedComSubKeys =
    [
        @"SOFTWARE\Classes\PackagedCom\ClassIndex",
        @"SOFTWARE\Classes\PackagedCom\Package"
    ];

    /// <summary>
    /// 扫描所有传统 Shell 命令式菜单与 shellex\ContextMenuHandlers 接口式扩展 (跨 HKLM 与 HKEY_USERS\&lt;SID&gt;)
    /// </summary>
    public List<ContextMenuItemEntry> ScanClassicContextMenus(string? activeUserSid)
    {
        var results = new List<ContextMenuItemEntry>();
        if (!OperatingSystem.IsWindows())
            return results;

        var blockedClsids = GetBlockedShellExtensionClsids(activeUserSid);

        foreach (var (sceneName, relativeSubKey) in ClassicShellScenes)
        {
            bool isContextHandler = relativeSubKey.Contains(@"\shellex\ContextMenuHandlers", StringComparison.OrdinalIgnoreCase);
            bool isDragDropHandler = relativeSubKey.Contains(@"\shellex\DragDropHandlers", StringComparison.OrdinalIgnoreCase);
            bool isShellExHandler = isContextHandler || isDragDropHandler;
            string? disabledSiblingRelSubKey = isContextHandler
                ? relativeSubKey.Replace(@"\shellex\ContextMenuHandlers", @"\shellex\-ContextMenuHandlers", StringComparison.OrdinalIgnoreCase)
                : isDragDropHandler
                    ? relativeSubKey.Replace(@"\shellex\DragDropHandlers", @"\shellex\-DragDropHandlers", StringComparison.OrdinalIgnoreCase)
                    : null;

            // CommandStore 仅存在于 HKLM，无需重复扫描用户 Hive
            bool skipUserHive = sceneName.Equals("CommandStore", StringComparison.OrdinalIgnoreCase);

            // 1. HKLM\SOFTWARE\Classes\...
            if (isShellExHandler)
            {
                ScanClassicShellExHandlersHive(PrivilegedRollbackEngine.HKEY_LOCAL_MACHINE, relativeSubKey, sceneName, blockedClsids, results, activeUserSid, isDisabledFolder: false);
                if (!string.IsNullOrEmpty(disabledSiblingRelSubKey))
                    ScanClassicShellExHandlersHive(PrivilegedRollbackEngine.HKEY_LOCAL_MACHINE, disabledSiblingRelSubKey, sceneName, blockedClsids, results, activeUserSid, isDisabledFolder: true);
            }
            else
            {
                ScanClassicShellVerbsHive(PrivilegedRollbackEngine.HKEY_LOCAL_MACHINE, relativeSubKey, sceneName, results);
            }

            // 2. HKEY_USERS\<SID>\Software\Classes\... 或 HKCU
            if (!skipUserHive && !string.IsNullOrEmpty(activeUserSid))
            {
                string userSubKey = InteractiveUserHiveResolver.ResolveUserRegistryPath(activeUserSid, relativeSubKey);
                if (isShellExHandler)
                {
                    ScanClassicShellExHandlersHive(PrivilegedRollbackEngine.HKEY_USERS, userSubKey, sceneName, blockedClsids, results, activeUserSid, isDisabledFolder: false);
                    if (!string.IsNullOrEmpty(disabledSiblingRelSubKey))
                    {
                        string userDisabledSub = InteractiveUserHiveResolver.ResolveUserRegistryPath(activeUserSid, disabledSiblingRelSubKey);
                        ScanClassicShellExHandlersHive(PrivilegedRollbackEngine.HKEY_USERS, userDisabledSub, sceneName, blockedClsids, results, activeUserSid, isDisabledFolder: true);
                    }
                }
                else
                {
                    ScanClassicShellVerbsHive(PrivilegedRollbackEngine.HKEY_USERS, userSubKey, sceneName, results);
                }
            }
            else if (!skipUserHive && string.IsNullOrEmpty(activeUserSid))
            {
                if (isShellExHandler)
                {
                    ScanClassicShellExHandlersHive(PrivilegedRollbackEngine.HKEY_CURRENT_USER, relativeSubKey, sceneName, blockedClsids, results, null, isDisabledFolder: false);
                    if (!string.IsNullOrEmpty(disabledSiblingRelSubKey))
                        ScanClassicShellExHandlersHive(PrivilegedRollbackEngine.HKEY_CURRENT_USER, disabledSiblingRelSubKey, sceneName, blockedClsids, results, null, isDisabledFolder: true);
                }
                else
                {
                    ScanClassicShellVerbsHive(PrivilegedRollbackEngine.HKEY_CURRENT_USER, relativeSubKey, sceneName, results);
                }
            }
        }

        return results;
    }

    private void ScanClassicShellVerbsHive(
        nint rootHive,
        string subKeyPath,
        string sceneName,
        List<ContextMenuItemEntry> output)
    {
        if (RegOpenKeyExW(rootHive, subKeyPath, 0, KEY_READ | KEY_WOW64_64KEY, out nint hSceneKey) != 0)
            return;

        try
        {
            bool isCommandStore = sceneName.Equals("CommandStore", StringComparison.OrdinalIgnoreCase);
            char* nameBuf = stackalloc char[260];
            uint index = 0;
            while (true)
            {
                uint nameLen = 260;
                int err = RegEnumKeyExW(hSceneKey, index++, nameBuf, ref nameLen, 0, 0, 0, out long lastWriteFt);
                if (err != 0) break;

                string verbKeyName = new(nameBuf, 0, (int)nameLen);
                // 公共引用列表默认过滤 Windows.* 系统内置命令
                if (isCommandStore && verbKeyName.StartsWith("Windows.", StringComparison.OrdinalIgnoreCase))
                    continue;

                string verbFullSubKey = $@"{subKeyPath}\{verbKeyName}";

                string muiVerb = ReadRegistryStringValue(rootHive, verbFullSubKey, "MUIVerb");
                string defaultTitle = ReadRegistryStringValue(rootHive, verbFullSubKey, null);
                string displayTitle = !string.IsNullOrEmpty(muiVerb) ? ResolveMuiString(muiVerb) : string.Empty;
                if (string.IsNullOrWhiteSpace(displayTitle) && !string.IsNullOrEmpty(defaultTitle))
                    displayTitle = ResolveMuiString(defaultTitle);

                // 解析 open/edit/print/find/play/runas/explore/preview 等内置动词默认本地化名称
                if (string.IsNullOrWhiteSpace(displayTitle) &&
                    ContextMenuGuidResolver.TryGetDefaultVerbDisplayName(verbKeyName, out string builtInVerbName))
                {
                    displayTitle = builtInVerbName;
                }

                // 若配置了 DelegateExecute / ExplorerCommandHandler / DropTarget，尝试从 CLSID 补全名称与 DLL 路径
                string verbClsid = ReadRegistryStringValue(rootHive, $@"{verbFullSubKey}\command", "DelegateExecute");
                if (string.IsNullOrWhiteSpace(verbClsid))
                    verbClsid = ReadRegistryStringValue(rootHive, verbFullSubKey, "ExplorerCommandHandler");
                if (string.IsNullOrWhiteSpace(verbClsid))
                    verbClsid = ReadRegistryStringValue(rootHive, $@"{verbFullSubKey}\DropTarget", "CLSID");
                if (string.IsNullOrWhiteSpace(verbClsid))
                    verbClsid = ReadRegistryStringValue(rootHive, verbFullSubKey, "CommandStateHandler");

                if (string.IsNullOrWhiteSpace(displayTitle) && !string.IsNullOrWhiteSpace(verbClsid))
                {
                    string clsidText = ResolveClsidFriendlyName(rootHive, verbClsid);
                    if (!string.IsNullOrWhiteSpace(clsidText))
                        displayTitle = clsidText;
                }

                if (string.IsNullOrWhiteSpace(displayTitle) || displayTitle.StartsWith('@'))
                    displayTitle = verbKeyName;

                bool hasLegacyDisable = HasRegistryValue(rootHive, verbFullSubKey, "LegacyDisable");
                bool hasProgrammaticOnly = HasRegistryValue(rootHive, verbFullSubKey, "ProgrammaticAccessOnly");
                bool hasVelocityHide = ReadRegistryDwordValue(rootHive, verbFullSubKey, "HideBasedOnVelocityId") == 0x639bc8;
                int? cmdFlags = ReadRegistryDwordValue(rootHive, verbFullSubKey, "CommandFlags");
                bool hasHiddenFlag = cmdFlags.HasValue && (cmdFlags.Value % 16) >= 8;

                string cmdLine = ReadRegistryStringValue(rootHive, $@"{verbFullSubKey}\command", null);
                if (string.IsNullOrWhiteSpace(cmdLine) && !string.IsNullOrWhiteSpace(verbClsid))
                {
                    cmdLine = ContextMenuGuidResolver.GetClsidFilePath(verbClsid);
                    if (string.IsNullOrWhiteSpace(cmdLine))
                        cmdLine = ResolveClassicComInprocServer32(verbClsid, null);
                }

                output.Add(new ContextMenuItemEntry
                {
                    IdKey = $"ClassicVerb:{sceneName}:{verbKeyName}",
                    DisplayTitle = displayTitle,
                    MenuCategory = MonitorCategory.ClassicContextMenu,
                    ScopeScene = sceneName,
                    RegistryPath = FormatRegistryPath(rootHive, verbFullSubKey),
                    Clsid = verbClsid,
                    TargetBinaryOrCommand = cmdLine,
                    IsEnabled = !hasLegacyDisable && !hasProgrammaticOnly && !hasVelocityHide && !hasHiddenFlag,
                    LastWriteTimeFileTime = lastWriteFt
                });
            }
        }
        finally
        {
            RegCloseKey(hSceneKey);
        }
    }

    private static string ResolveOpenWithExecutablePath(nint rootHive, string subKeyPath, string exeName)
    {
        if (string.IsNullOrWhiteSpace(exeName))
            return string.Empty;

        string cleanExe = exeName.Trim();
        string appPathsKey = $@"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{cleanExe}";
        string pathVal = ReadRegistryStringValue(PrivilegedRollbackEngine.HKEY_LOCAL_MACHINE, appPathsKey, null);
        if (!string.IsNullOrWhiteSpace(pathVal))
            return Environment.ExpandEnvironmentVariables(pathVal.Trim().Trim('"'));

        if (rootHive == PrivilegedRollbackEngine.HKEY_USERS)
        {
            int slash = subKeyPath.IndexOf('\\');
            if (slash > 0)
            {
                string sid = subKeyPath[..slash];
                pathVal = ReadRegistryStringValue(PrivilegedRollbackEngine.HKEY_USERS, $@"{sid}\{appPathsKey}", null);
                if (!string.IsNullOrWhiteSpace(pathVal))
                    return Environment.ExpandEnvironmentVariables(pathVal.Trim().Trim('"'));
            }
        }
        else if (rootHive != PrivilegedRollbackEngine.HKEY_LOCAL_MACHINE)
        {
            pathVal = ReadRegistryStringValue(rootHive, appPathsKey, null);
            if (!string.IsNullOrWhiteSpace(pathVal))
                return Environment.ExpandEnvironmentVariables(pathVal.Trim().Trim('"'));
        }

        string appsCmd = ReadRegistryStringValue(
            PrivilegedRollbackEngine.HKEY_LOCAL_MACHINE,
            $@"SOFTWARE\Classes\Applications\{cleanExe}\shell\open\command",
            null);
        if (!string.IsNullOrWhiteSpace(appsCmd))
            return appsCmd;

        return string.Empty;
    }

    private void ScanClassicShellExHandlersHive(
        nint rootHive,
        string subKeyPath,
        string sceneName,
        HashSet<string> blockedClsids,
        List<ContextMenuItemEntry> output,
        string? activeUserSid = null,
        bool isDisabledFolder = false)
    {
        if (RegOpenKeyExW(rootHive, subKeyPath, 0, KEY_READ | KEY_WOW64_64KEY, out nint hHandlersKey) != 0)
            return;

        try
        {
            char* nameBuf = stackalloc char[260];
            uint index = 0;
            while (true)
            {
                uint nameLen = 260;
                int err = RegEnumKeyExW(hHandlersKey, index++, nameBuf, ref nameLen, 0, 0, 0, out long lastWriteFt);
                if (err != 0) break;

                string handlerKeyName = new(nameBuf, 0, (int)nameLen);
                string handlerFullSubKey = $@"{subKeyPath}\{handlerKeyName}";
                string defaultVal = ReadRegistryStringValue(rootHive, handlerFullSubKey, null).Trim();

                bool isPrefixDisabled = isDisabledFolder || handlerKeyName.StartsWith('-') || defaultVal.StartsWith('-');
                string cleanKeyName = handlerKeyName.TrimStart('-').Trim();
                string cleanDefaultVal = defaultVal.TrimStart('-').Trim();

                string clsid = string.Empty;
                string displayTitle = cleanKeyName;
                if (ContextMenuGuidResolver.TryParseGuid(cleanKeyName, out Guid g1) && g1 != Guid.Empty)
                {
                    clsid = $"{g1:B}";
                    if (!string.IsNullOrEmpty(cleanDefaultVal) && !cleanDefaultVal.StartsWith('{'))
                        displayTitle = ResolveMuiString(cleanDefaultVal);
                }
                else if (ContextMenuGuidResolver.TryParseGuid(cleanDefaultVal, out Guid g2) && g2 != Guid.Empty)
                {
                    clsid = $"{g2:B}";
                }

                // 跳过不含有效 GUID 的外壳扩展子键
                if (string.IsNullOrEmpty(clsid))
                    continue;

                // 优先读取 GUID 字典中文显示名，其次回退到注册表键名或友好名称
                string guidText = ContextMenuGuidResolver.GetClsidText(clsid);
                if (!string.IsNullOrWhiteSpace(guidText) && !guidText.StartsWith('@') && !guidText.StartsWith('{'))
                {
                    displayTitle = CleanMenuMnemonic(guidText);
                }
                else if (displayTitle.StartsWith('{') || string.IsNullOrEmpty(displayTitle) || displayTitle.StartsWith('@'))
                {
                    string friendly = ResolveClsidFriendlyName(PrivilegedRollbackEngine.HKEY_LOCAL_MACHINE, clsid, activeUserSid);
                    if (!string.IsNullOrEmpty(friendly))
                        displayTitle = friendly;
                    else if (displayTitle.StartsWith('@'))
                        displayTitle = ResolveMuiString(displayTitle);
                }

                string dllPath = ContextMenuGuidResolver.GetClsidFilePath(clsid);
                if (string.IsNullOrEmpty(dllPath))
                {
                    dllPath = ResolveClassicComInprocServer32(clsid, activeUserSid);
                }

                if ((string.IsNullOrWhiteSpace(displayTitle) || displayTitle.StartsWith('{')) && !string.IsNullOrEmpty(dllPath))
                {
                    displayTitle = Path.GetFileNameWithoutExtension(dllPath);
                }

                bool isBlocked = blockedClsids.Contains(clsid);

                output.Add(new ContextMenuItemEntry
                {
                    IdKey = $"ClassicHandler:{sceneName}:{clsid}:{displayTitle}",
                    DisplayTitle = displayTitle,
                    MenuCategory = MonitorCategory.ClassicContextMenu,
                    ScopeScene = sceneName,
                    RegistryPath = FormatRegistryPath(rootHive, handlerFullSubKey),
                    Clsid = clsid,
                    TargetBinaryOrCommand = dllPath,
                    IsEnabled = !isBlocked && !isPrefixDisabled,
                    LastWriteTimeFileTime = lastWriteFt
                });
            }
        }
        finally
        {
            RegCloseKey(hHandlersKey);
        }
    }

    /// <summary>
    /// 扫描特殊右键菜单分类 (SendTo 发送到、WinX 系统快捷菜单，按需包含 ShellNew 新建菜单)
    /// </summary>
    public List<ContextMenuItemEntry> ScanSpecialContextMenus(
        string? activeUserSid,
        string? customSendToDir = null,
        string? customWinXDir = null,
        bool includeShellNew = false)
    {
        var results = new List<ContextMenuItemEntry>();

        // 1. SendTo 目录扫描
        string sendToDir = customSendToDir ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "Microsoft", "Windows", "SendTo");
        if (!string.IsNullOrEmpty(sendToDir) && Directory.Exists(sendToDir))
        {
            try
            {
                var sendToLocalized = ReadDesktopIniLocalizedNames(sendToDir);
                foreach (string file in Directory.EnumerateFiles(sendToDir))
                {
                    var fi = new FileInfo(file);
                    if (fi.Name.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase) || fi.Extension.Equals(".ini", StringComparison.OrdinalIgnoreCase))
                        continue;
                    bool isHiddenOrDisabled = (fi.Attributes & FileAttributes.Hidden) != 0 ||
                                              file.EndsWith(".disabled", StringComparison.OrdinalIgnoreCase);
                    string localizedTitle = ResolveSpecialFileDisplayName(file, sendToLocalized);
                    results.Add(new ContextMenuItemEntry
                    {
                        IdKey = $"Special:SendTo:{fi.Name}",
                        DisplayTitle = localizedTitle,
                        MenuCategory = MonitorCategory.ClassicContextMenu,
                        ScopeScene = "SendTo (发送到)",
                        RegistryPath = file,
                        TargetBinaryOrCommand = file,
                        IsEnabled = !isHiddenOrDisabled,
                        LastWriteTimeFileTime = fi.LastWriteTimeUtc.ToFileTimeUtc()
                    });
                }
            }
            catch
            {
                // Ignore inaccessible directory
            }
        }

        // 2. WinX 目录扫描
        string winXDir = customWinXDir ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Microsoft", "Windows", "WinX");
        if (!string.IsNullOrEmpty(winXDir) && Directory.Exists(winXDir))
        {
            try
            {
                var winXLocalizedCache = new Dictionary<string, Dictionary<string, string>>(StringComparer.OrdinalIgnoreCase);
                foreach (string file in Directory.EnumerateFiles(winXDir, "*", SearchOption.AllDirectories))
                {
                    var fi = new FileInfo(file);
                    if (fi.Name.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase) || fi.Extension.Equals(".ini", StringComparison.OrdinalIgnoreCase))
                        continue;
                    string parentDir = fi.DirectoryName ?? winXDir;
                    if (!winXLocalizedCache.TryGetValue(parentDir, out var dirMap))
                    {
                        dirMap = ReadDesktopIniLocalizedNames(parentDir);
                        winXLocalizedCache[parentDir] = dirMap;
                    }
                    string localizedTitle = ResolveSpecialFileDisplayName(file, dirMap);
                    results.Add(new ContextMenuItemEntry
                    {
                        IdKey = $"Special:WinX:{fi.Name}",
                        DisplayTitle = localizedTitle,
                        MenuCategory = MonitorCategory.ClassicContextMenu,
                        ScopeScene = "WinX (Win+X 菜单)",
                        RegistryPath = file,
                        TargetBinaryOrCommand = file,
                        IsEnabled = (fi.Attributes & FileAttributes.Hidden) == 0,
                        LastWriteTimeFileTime = fi.LastWriteTimeUtc.ToFileTimeUtc()
                    });
                }
            }
            catch
            {
                // Ignore inaccessible directory
            }
        }

        // 3. 注册表 ShellNew (新建菜单)
        if (includeShellNew && OperatingSystem.IsWindows())
        {
            ScanShellNewExtensions(PrivilegedRollbackEngine.HKEY_LOCAL_MACHINE, @"SOFTWARE\Classes", results);
        }

        return results;
    }

    private static void ScanShellNewExtensions(nint rootHive, string classesSubKey, List<ContextMenuItemEntry> output)
    {
        if (RegOpenKeyExW(rootHive, classesSubKey, 0, KEY_READ | KEY_WOW64_64KEY, out nint hClasses) != 0)
            return;

        try
        {
            char* nameBuf = stackalloc char[260];
            uint index = 0;
            int maxScanned = 1024;
            while (maxScanned-- > 0)
            {
                uint nameLen = 260;
                int err = RegEnumKeyExW(hClasses, index++, nameBuf, ref nameLen, 0, 0, 0, out _);
                if (err != 0) break;

                if (nameBuf[0] != '.') continue;
                string ext = new(nameBuf, 0, (int)nameLen);
                string shellNewKey = $@"{classesSubKey}\{ext}\ShellNew";

                if (RegOpenKeyExW(rootHive, shellNewKey, 0, KEY_READ | KEY_WOW64_64KEY, out nint hShellNew) == 0)
                {
                    RegCloseKey(hShellNew);
                    string cmd = ReadRegistryStringValue(rootHive, shellNewKey, "Command");

                    // 读取扩展名对应的 ProgID 及其 FriendlyTypeName 本地化名称 (参考 ContextMenuManager 规范)
                    string progId = ReadRegistryStringValue(rootHive, $@"{classesSubKey}\{ext}", null);
                    string friendlyName = string.Empty;
                    if (!string.IsNullOrEmpty(progId))
                    {
                        friendlyName = ReadRegistryStringValue(rootHive, $@"{classesSubKey}\{progId}", "FriendlyTypeName");
                        if (!string.IsNullOrEmpty(friendlyName))
                        {
                            friendlyName = ResolveMuiString(friendlyName);
                        }
                        if (string.IsNullOrEmpty(friendlyName) || friendlyName.StartsWith('@'))
                        {
                            friendlyName = ReadRegistryStringValue(rootHive, $@"{classesSubKey}\{progId}", null);
                        }
                    }

                    if (string.IsNullOrEmpty(friendlyName) || friendlyName.StartsWith('@'))
                    {
                        friendlyName = ext.ToLowerInvariant() switch
                        {
                            ".library-ms" => "库",
                            ".txt" => "文本文档",
                            ".docx" or ".doc" => "Word 文档",
                            ".xlsx" or ".xls" => "Excel 工作表",
                            ".pptx" or ".ppt" => "PowerPoint 演示文稿",
                            ".zip" => "ZIP 压缩文件",
                            ".bmp" => "位图图像",
                            ".rtf" => "富文本格式",
                            _ => ext
                        };
                    }

                    string displayTitle = friendlyName.StartsWith("新建") ? friendlyName : $"新建 {friendlyName}";

                    output.Add(new ContextMenuItemEntry
                    {
                        IdKey = $"Special:ShellNew:{ext}",
                        DisplayTitle = displayTitle,
                        MenuCategory = MonitorCategory.ClassicContextMenu,
                        ScopeScene = "ShellNew (新建菜单)",
                        RegistryPath = FormatRegistryPath(rootHive, shellNewKey),
                        TargetBinaryOrCommand = !string.IsNullOrEmpty(cmd) ? cmd : ext,
                        IsEnabled = true,
                        LastWriteTimeFileTime = DateTime.UtcNow.ToFileTimeUtc()
                    });
                }
            }
        }
        finally
        {
            RegCloseKey(hClasses);
        }
    }

    /// <summary>
    /// 扫描全部右键菜单 (传统 Shell/ShellEx + Win11 PackagedCom 现代菜单 + 特殊菜单) 并按 LastWriteTime 去重
    /// </summary>
    public List<ContextMenuItemEntry> ScanAllContextMenus(string? activeUserSid)
    {
        var combined = new List<ContextMenuItemEntry>();
        combined.AddRange(ScanClassicContextMenus(activeUserSid));
        combined.AddRange(ScanOpenWithApplications(activeUserSid));
        combined.AddRange(ScanWindows11ModernMenus(activeUserSid));
        combined.AddRange(ScanSpecialContextMenus(activeUserSid));
        return DeduplicateByLastWriteTime(combined);
    }

    /// <summary>
    /// 扫描 Approved 注册表中的外壳扩展组件 (用于菜单分析与残存组件深度研判)
    /// </summary>
    public List<ContextMenuItemEntry> ScanApprovedShellExtensions(string? activeUserSid = null)
    {
        var results = new List<ContextMenuItemEntry>();
        if (!OperatingSystem.IsWindows())
            return results;

        const string approvedSubKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved";
        uint[] wowFlags = [KEY_WOW64_64KEY, KEY_WOW64_32KEY];
        var blockedClsids = GetBlockedShellExtensionClsids(activeUserSid);

        char* valName = stackalloc char[260];
        foreach (uint wowFlag in wowFlags)
        {
            if (RegOpenKeyExW(PrivilegedRollbackEngine.HKEY_LOCAL_MACHINE, approvedSubKey, 0, KEY_READ | wowFlag, out nint hAppKey) != 0)
                continue;

            try
            {
                uint idx = 0;
                while (true)
                {
                    uint cch = 260;
                    int err = EnumValueNameOnly(hAppKey, idx++, valName, ref cch);
                    if (err != 0) break;

                    string clsid = new(valName, 0, (int)cch);
                    // Approved 键下合法表项均为 {CLSID} GUID 值名，过滤此前误写入的 LegacyDisable 等非 GUID 杂项
                    if (!clsid.StartsWith('{') || !clsid.EndsWith('}'))
                        continue;
                    if (results.Any(r => r.Clsid.Equals(clsid, StringComparison.OrdinalIgnoreCase)))
                        continue;

                    string desc = ReadRegistryStringValue(PrivilegedRollbackEngine.HKEY_LOCAL_MACHINE, approvedSubKey, clsid);
                    string resolvedTitle = ContextMenuGuidResolver.GetClsidText(clsid);
                    if (string.IsNullOrWhiteSpace(resolvedTitle))
                        resolvedTitle = !string.IsNullOrEmpty(desc) ? ResolveMuiString(desc) : string.Empty;
                    if (string.IsNullOrWhiteSpace(resolvedTitle) || resolvedTitle.StartsWith('@'))
                        resolvedTitle = !string.IsNullOrEmpty(desc) ? desc : clsid;

                    string inprocDll = ContextMenuGuidResolver.GetClsidFilePath(clsid);
                    if (string.IsNullOrEmpty(inprocDll))
                        inprocDll = ResolveClassicComInprocServer32(clsid, activeUserSid);

                    bool isBlocked = blockedClsids.Contains(clsid);
                    string expandedDll = !string.IsNullOrEmpty(inprocDll) ? Environment.ExpandEnvironmentVariables(inprocDll).Trim('"') : string.Empty;
                    bool fileExists = !string.IsNullOrEmpty(expandedDll) && File.Exists(expandedDll);

                    results.Add(new ContextMenuItemEntry
                    {
                        IdKey = $"Approved:{clsid}",
                        DisplayTitle = resolvedTitle,
                        MenuCategory = MonitorCategory.ClassicContextMenu,
                        ScopeScene = "菜单深入分析",
                        RegistryPath = $@"HKLM\{approvedSubKey}::{clsid}",
                        Clsid = clsid,
                        TargetBinaryOrCommand = expandedDll,
                        IsEnabled = !isBlocked && (string.IsNullOrEmpty(expandedDll) || fileExists),
                        LastWriteTimeFileTime = DateTime.UtcNow.ToFileTimeUtc()
                    });
                }
            }
            finally
            {
                RegCloseKey(hAppKey);
            }
        }

        return results;
    }

    /// <summary>
    /// 强特权彻底删除指定右键菜单注册项或 Shell Extension
    /// </summary>
    public bool DeleteContextMenuEntry(string idKeyOrPath, string? activeUserSid)
    {
        if (string.IsNullOrWhiteSpace(idKeyOrPath) || !OperatingSystem.IsWindows())
            return false;

        PrivilegedRollbackEngine.EnableAllSystemRollbackPrivileges();

        if (idKeyOrPath.StartsWith("Approved:", StringComparison.OrdinalIgnoreCase))
        {
            string clsid = idKeyOrPath.Substring("Approved:".Length).Trim();
            const string approvedSubKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved";
            if (RegOpenKeyExW(PrivilegedRollbackEngine.HKEY_LOCAL_MACHINE, approvedSubKey, 0, KEY_SET_VALUE | KEY_WOW64_64KEY, out nint hKey64) == 0)
            {
                RegDeleteValueW(hKey64, clsid);
                RegCloseKey(hKey64);
            }
            if (RegOpenKeyExW(PrivilegedRollbackEngine.HKEY_LOCAL_MACHINE, approvedSubKey, 0, KEY_SET_VALUE | KEY_WOW64_32KEY, out nint hKey32) == 0)
            {
                RegDeleteValueW(hKey32, clsid);
                RegCloseKey(hKey32);
            }
            SetWin11ModernMenuBlockedState(clsid, blockItem: true, activeUserSid);
            return true;
        }

        var (hive, subKey, valName) = PrivilegedRollbackEngine.SplitRegistryLocation(idKeyOrPath, activeUserSid);
        if (!string.IsNullOrEmpty(valName))
        {
            if (RegOpenKeyExW(hive, subKey, 0, KEY_SET_VALUE | KEY_WOW64_64KEY, out nint hValKey) == 0)
            {
                try { return RegDeleteValueW(hValKey, valName) == 0; }
                finally { RegCloseKey(hValKey); }
            }
        }
        else
        {
            return PrivilegedRollbackEngine.RegDeleteKeyExW(hive, subKey, KEY_WOW64_64KEY, 0) == 0;
        }
        return false;
    }

    /// <summary>
    /// 扫描所有 Win11 现代右键菜单扩展 (PackagedCom / IExplorerCommand) 及 Blocked 状态
    /// </summary>
    public List<ContextMenuItemEntry> ScanWindows11ModernMenus(string? activeUserSid)
    {
        var results = new List<ContextMenuItemEntry>();
        if (!OperatingSystem.IsWindows())
            return results;

        var blockedClsids = GetBlockedShellExtensionClsids(activeUserSid);

        // 1. 扫描 HKLM PackagedCom\ClassIndex
        ScanPackagedComHive(PrivilegedRollbackEngine.HKEY_LOCAL_MACHINE, @"SOFTWARE\Classes\PackagedCom\ClassIndex", blockedClsids, results);

        // 2. 扫描当前交互用户的 HKEY_USERS\<SID>\Software\Classes\PackagedCom\ClassIndex
        if (!string.IsNullOrEmpty(activeUserSid))
        {
            string userClassIndex = InteractiveUserHiveResolver.ResolveUserRegistryPath(activeUserSid, @"Software\Classes\PackagedCom\ClassIndex");
            ScanPackagedComHive(PrivilegedRollbackEngine.HKEY_USERS, userClassIndex, blockedClsids, results);
        }

        return results;
    }

    private void ScanPackagedComHive(
        nint rootHive,
        string subKeyPath,
        HashSet<string> blockedClsids,
        List<ContextMenuItemEntry> output)
    {
        if (RegOpenKeyExW(rootHive, subKeyPath, 0, KEY_READ | KEY_WOW64_64KEY, out nint hIndexKey) != 0)
            return;

        try
        {
            char* nameBuf = stackalloc char[260];
            uint index = 0;
            while (true)
            {
                uint nameLen = 260;
                int err = RegEnumKeyExW(hIndexKey, index++, nameBuf, ref nameLen, 0, 0, 0, out long lastWriteFt);
                if (err != 0) break;

                string clsid = new(nameBuf, 0, (int)nameLen);
                if (!clsid.StartsWith('{')) continue;

                // 读取该 CLSID 下绑定的 MSIX PackageFullName 子键
                string clsidSubKey = $@"{subKeyPath}\{clsid}";
                string packageId = TryGetFirstSubKeyName(rootHive, clsidSubKey, out _);
                if (string.IsNullOrEmpty(packageId)) continue;

                // 解析 COM Server DLL 物理路径
                string serverDllPath = ResolvePackagedComServerBinary(rootHive, packageId, clsid);
                bool isBlocked = blockedClsids.Contains(clsid);

                output.Add(new ContextMenuItemEntry
                {
                    IdKey = $"Win11Modern:{clsid}:{packageId}",
                    DisplayTitle = ExtractFriendlyPackageName(packageId),
                    MenuCategory = MonitorCategory.ModernContextMenu,
                    ScopeScene = "Win11 Modern Menu (IExplorerCommand)",
                    RegistryPath = FormatRegistryPath(rootHive, $@"{clsidSubKey}\{packageId}"),
                    Clsid = clsid,
                    PackageFullName = packageId,
                    TargetBinaryOrCommand = serverDllPath,
                    IsEnabled = !isBlocked,
                    LastWriteTimeFileTime = lastWriteFt
                });
            }
        }
        finally
        {
            RegCloseKey(hIndexKey);
        }
    }

    /// <summary>
    /// 启用或禁用 Windows 11 现代右键菜单扩展 (SetWin11BlockedItem / RemoveWin11BlockedItem)
    /// 原理：向 HKCU (HKEY_USERS\&lt;SID&gt; 或当前用户) 与 HKLM 的 Shell Extensions\Blocked 写入/删除 {CLSID}
    /// </summary>
    public bool SetWin11ModernMenuBlockedState(string clsid, bool blockItem, string? activeUserSid)
    {
        if (string.IsNullOrWhiteSpace(clsid) || !OperatingSystem.IsWindows())
            return false;

        PrivilegedRollbackEngine.EnableAllSystemRollbackPrivileges();
        string normalizedClsid = clsid.StartsWith('{') ? clsid : $"{{{clsid}}}";
        bool okMachine = ModifyBlockedValue(PrivilegedRollbackEngine.HKEY_LOCAL_MACHINE, BlockedExtensionsSubKey, normalizedClsid, blockItem);

        bool okUser;
        if (!string.IsNullOrEmpty(activeUserSid))
        {
            string userBlockedPath = InteractiveUserHiveResolver.ResolveUserRegistryPath(activeUserSid, BlockedExtensionsSubKey);
            okUser = ModifyBlockedValue(PrivilegedRollbackEngine.HKEY_USERS, userBlockedPath, normalizedClsid, blockItem);
        }
        else
        {
            // UI 直接调用未传 SID 时，同步修改当前用户 HKCU 下的 Shell Extensions\Blocked
            okUser = ModifyBlockedValue(PrivilegedRollbackEngine.HKEY_CURRENT_USER, BlockedExtensionsSubKey, normalizedClsid, blockItem);
        }

        // 若是解除屏蔽 (enable=true)，额外扫描 HKEY_USERS 下所有已加载交互式会话以彻底消除残留锁
        if (!blockItem)
        {
            try
            {
                using var hku = Registry.Users;
                foreach (string sid in hku.GetSubKeyNames())
                {
                    if (!sid.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase) || sid.EndsWith("_Classes", StringComparison.OrdinalIgnoreCase))
                        continue;
                    string path = $@"{sid}\{BlockedExtensionsSubKey}";
                    ModifyBlockedValue(PrivilegedRollbackEngine.HKEY_USERS, path, normalizedClsid, blockItem: false);
                }
            }
            catch { }
        }

        SharedStorageHelper.LogDiagnostic("ContextMenuEngine",
            $"SetWin11ModernMenuBlockedState clsid={normalizedClsid} block={blockItem} sid={activeUserSid ?? "HKCU"} okMachine={okMachine} okUser={okUser}");
        return okMachine || okUser;
    }

    /// <summary>
    /// 启用或禁用传统 Shell 命令菜单项 (通过 HideBasedOnVelocityId、ProgrammaticAccessOnly 与 LegacyDisable 控制)
    /// </summary>
    public bool SetClassicShellVerbState(nint rootHive, string verbRegistrySubKey, bool disableVerb)
    {
        if (string.IsNullOrWhiteSpace(verbRegistrySubKey) || !OperatingSystem.IsWindows())
            return false;

        // 安全防线：绝不允许向 Shell Extensions\Approved/Blocked、ContextMenuHandlers 或 shell 容器根写入禁用标记
        string trimmedSub = verbRegistrySubKey.TrimEnd('\\');
        if (trimmedSub.EndsWith(@"\Shell Extensions\Approved", StringComparison.OrdinalIgnoreCase) ||
            trimmedSub.EndsWith(@"\Shell Extensions\Blocked", StringComparison.OrdinalIgnoreCase) ||
            trimmedSub.EndsWith(@"\ContextMenuHandlers", StringComparison.OrdinalIgnoreCase) ||
            trimmedSub.EndsWith(@"\-ContextMenuHandlers", StringComparison.OrdinalIgnoreCase) ||
            trimmedSub.EndsWith(@"\DragDropHandlers", StringComparison.OrdinalIgnoreCase) ||
            trimmedSub.EndsWith(@"\-DragDropHandlers", StringComparison.OrdinalIgnoreCase) ||
            trimmedSub.EndsWith(@"\shell", StringComparison.OrdinalIgnoreCase) ||
            trimmedSub.EndsWith(@"\ShellNew", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        PrivilegedRollbackEngine.EnableAllSystemRollbackPrivileges();

        int openRc = RegCreateKeyExW(rootHive, verbRegistrySubKey, 0, null, REG_OPTION_BACKUP_RESTORE, KEY_WRITE | KEY_WOW64_64KEY, 0, out nint hKey, out _);
        if (openRc != 0)
            openRc = RegCreateKeyExW(rootHive, verbRegistrySubKey, 0, null, 0, KEY_WRITE | KEY_WOW64_64KEY, 0, out hKey, out _);
        if (openRc != 0)
            return false;

        try
        {
            if (disableVerb)
            {
                uint velId = 0x639bc8;
                bool okVel = RegSetValueExW(hKey, "HideBasedOnVelocityId", 0, 4, (byte*)&velId, sizeof(uint)) == 0;
                char empty = '\0';
                bool okProg = RegSetValueExW(hKey, "ProgrammaticAccessOnly", 0, REG_SZ, (byte*)&empty, 2) == 0;
                bool isProtectedNewWindow = trimmedSub.EndsWith(@"Folder\shell\opennewwindow", StringComparison.OrdinalIgnoreCase);
                bool okLegacy = isProtectedNewWindow || RegSetValueExW(hKey, "LegacyDisable", 0, REG_SZ, (byte*)&empty, 2) == 0;
                return okVel || okProg || okLegacy;
            }
            else
            {
                int r1 = RegDeleteValueW(hKey, "LegacyDisable");
                int r2 = RegDeleteValueW(hKey, "ProgrammaticAccessOnly");
                int r3 = RegDeleteValueW(hKey, "HideBasedOnVelocityId");
                try
                {
                    using var baseHive = OpenManagedBaseHive(rootHive);
                    using var mk = baseHive.OpenSubKey(verbRegistrySubKey, writable: true);
                    if (mk != null && mk.GetValue("CommandFlags") is int cf && (cf % 16) >= 8)
                    {
                        mk.DeleteValue("CommandFlags", throwOnMissingValue: false);
                    }
                }
                catch { }
                return (r1 == 0 || r1 == 2) && (r2 == 0 || r2 == 2) && (r3 == 0 || r3 == 2);
            }
        }
        finally
        {
            RegCloseKey(hKey);
        }
    }

    /// <summary>
    /// 启用或禁用传统 shellex\ContextMenuHandlers / DragDropHandlers 接口扩展（通过 -ContextMenuHandlers / -DragDropHandlers 容器切换）
    /// </summary>
    public bool SetClassicContextMenuHandlerState(
        nuint rootHive,
        string handlerKeyPath,
        string clsid,
        bool enable,
        string? activeUserSid = null)
        => SetClassicContextMenuHandlerState((nint)rootHive, handlerKeyPath, clsid, enable, activeUserSid);

    public static string TryExtractHandlerClsid(nint rootHive, string handlerKeyPath)
    {
        if (string.IsNullOrWhiteSpace(handlerKeyPath) || !OperatingSystem.IsWindows())
            return string.Empty;

        string leaf = handlerKeyPath.TrimEnd('\\');
        int lastSlash = leaf.LastIndexOf('\\');
        if (lastSlash >= 0 && lastSlash + 1 < leaf.Length)
            leaf = leaf[(lastSlash + 1)..];
        string cleanLeaf = leaf.TrimStart('-').Trim();
        if (cleanLeaf.StartsWith('{') && cleanLeaf.EndsWith('}'))
            return cleanLeaf;

        string defVal = ReadRegistryStringValue(rootHive, handlerKeyPath, null).TrimStart('-').Trim();
        if (defVal.StartsWith('{') && defVal.EndsWith('}'))
            return defVal;

        return string.Empty;
    }

    public bool SetClassicContextMenuHandlerState(
        nint rootHive,
        string handlerKeyPath,
        string clsid,
        bool enable,
        string? activeUserSid = null)
    {
        if (string.IsNullOrWhiteSpace(handlerKeyPath) || !OperatingSystem.IsWindows())
            return false;

        PrivilegedRollbackEngine.EnableAllSystemRollbackPrivileges();
        var (enabledSub, disabledSub) = PrivilegedRollbackEngine.ResolveShellExPairPaths(handlerKeyPath);
        if (string.IsNullOrEmpty(enabledSub) || string.IsNullOrEmpty(disabledSub))
            return false;

        string srcSub = enable ? disabledSub : enabledSub;
        string dstSub = enable ? enabledSub : disabledSub;

        bool moved = false;
        using var baseHive = OpenManagedBaseHive(rootHive);
        using (var srcKey = baseHive.OpenSubKey(srcSub, false))
        {
            if (srcKey != null)
            {
                moved = MoveRegistrySubKey(baseHive, srcSub, dstSub);
            }
            else
            {
                using var alreadyDst = baseHive.OpenSubKey(dstSub, false);
                moved = alreadyDst != null;
            }
        }

        // 若旧版曾在默认键值写入 '-' 前缀或写入 Shell Extensions\Blocked，恢复启用时一并清干净
        if (enable && moved)
        {
            string targetClsid = !string.IsNullOrWhiteSpace(clsid)
                ? clsid.Trim()
                : TryExtractHandlerClsid(rootHive, dstSub);
            if (!string.IsNullOrWhiteSpace(targetClsid))
            {
                try
                {
                    string curDef = ReadRegistryStringValue(rootHive, dstSub, null);
                    if (curDef.StartsWith('-'))
                        SetStringRegistryValue(rootHive, dstSub, string.Empty, curDef.TrimStart('-').Trim());
                }
                catch { }
            }
        }

        return moved;
    }

    private static bool MoveRegistrySubKey(Microsoft.Win32.RegistryKey baseHive, string sourceSubKey, string destSubKey)
    {
        if (string.Equals(sourceSubKey, destSubKey, StringComparison.OrdinalIgnoreCase))
            return true;

        try
        {
            CopyRegistrySubKeyRecursive(baseHive, sourceSubKey, destSubKey);
            baseHive.DeleteSubKeyTree(sourceSubKey, throwOnMissingSubKey: false);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static void CopyRegistrySubKeyRecursive(Microsoft.Win32.RegistryKey baseHive, string sourceSubKey, string destSubKey)
    {
        using var src = baseHive.OpenSubKey(sourceSubKey, false);
        if (src == null) return;

        using var dst = baseHive.CreateSubKey(destSubKey, writable: true);
        if (dst == null) return;

        foreach (string valName in src.GetValueNames())
        {
            object? val = src.GetValue(valName, null, Microsoft.Win32.RegistryValueOptions.DoNotExpandEnvironmentNames);
            if (val != null)
            {
                var kind = src.GetValueKind(valName);
                dst.SetValue(valName, val, kind);
            }
        }

        foreach (string child in src.GetSubKeyNames())
        {
            CopyRegistrySubKeyRecursive(baseHive, $@"{sourceSubKey}\{child}", $@"{destSubKey}\{child}");
        }
    }

    /// <summary>
    /// 统一设置任意右键菜单项 (经典 shell、shellex handler、OpenWith、Win11 PackagedCom) 的启用/禁用状态
    /// </summary>
    public bool SetContextMenuItemEnabledState(ContextMenuItemEntry item, bool enable, string? activeUserSid = null)
    {
        if (item is null)
            return false;

        bool ok;
        if (item.IdKey.StartsWith("Special:WinX:", StringComparison.OrdinalIgnoreCase) ||
            item.IdKey.StartsWith("Special:SendTo:", StringComparison.OrdinalIgnoreCase) ||
            (File.Exists(item.RegistryPath) &&
             (item.RegistryPath.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase) ||
              item.ScopeScene.Contains("WinX", StringComparison.OrdinalIgnoreCase) ||
              item.ScopeScene.Contains("SendTo", StringComparison.OrdinalIgnoreCase))))
        {
            ok = SetFileHiddenAttributeState(item.RegistryPath, hidden: !enable);
        }
        else if (item.IdKey.StartsWith("OpenWith:", StringComparison.OrdinalIgnoreCase) ||
                 item.RegistryPath.Contains(@"\Applications\", StringComparison.OrdinalIgnoreCase))
        {
            string appKeyArg = !string.IsNullOrWhiteSpace(item.RegistryPath) ? item.RegistryPath : item.IdKey;
            ok = SetOpenWithApplicationState(appKeyArg, enable, activeUserSid);
        }
        else if (item.MenuCategory == MonitorCategory.ModernContextMenu)
        {
            ok = SetWin11ModernMenuBlockedState(item.Clsid, blockItem: !enable, activeUserSid);
        }
        else if (item.IdKey.StartsWith("Approved:", StringComparison.OrdinalIgnoreCase) ||
                 PrivilegedRollbackEngine.IsApprovedShellExtensionLocation(item.RegistryPath))
        {
            string targetClsid = !string.IsNullOrWhiteSpace(item.Clsid)
                ? item.Clsid
                : PrivilegedRollbackEngine.ExtractClsidOrIdentifier(item.RegistryPath);
            ok = !string.IsNullOrWhiteSpace(targetClsid) &&
                 SetWin11ModernMenuBlockedState(targetClsid, blockItem: !enable, activeUserSid);
        }
        else if (item.RegistryPath.Contains(@"\shellex\ContextMenuHandlers", StringComparison.OrdinalIgnoreCase) ||
                 item.RegistryPath.Contains(@"\shellex\-ContextMenuHandlers", StringComparison.OrdinalIgnoreCase) ||
                 item.RegistryPath.Contains(@"\shellex\DragDropHandlers", StringComparison.OrdinalIgnoreCase) ||
                 item.RegistryPath.Contains(@"\shellex\-DragDropHandlers", StringComparison.OrdinalIgnoreCase))
        {
            var (hive, subKey, _) = PrivilegedRollbackEngine.SplitRegistryLocation(item.RegistryPath, activeUserSid);
            ok = SetClassicContextMenuHandlerState(
                hive,
                subKey,
                item.Clsid,
                enable,
                activeUserSid);
        }
        else
        {
            var (hive, subKey, _) = PrivilegedRollbackEngine.SplitRegistryLocation(item.RegistryPath, activeUserSid);
            ok = SetClassicShellVerbState(
                hive,
                subKey,
                disableVerb: !enable);
        }

        SharedStorageHelper.LogDiagnostic("ContextMenuEngine",
            $"SetContextMenuItemEnabledState id={item.IdKey} enable={enable} ok={ok} reg={item.RegistryPath}");

        if (ok)
        {
            item.IsEnabled = enable;
            if (item.RegistryPath.Contains(@"\shellex\", StringComparison.OrdinalIgnoreCase))
            {
                if (enable)
                {
                    item.RegistryPath = item.RegistryPath
                        .Replace(@"\shellex\-ContextMenuHandlers\", @"\shellex\ContextMenuHandlers\", StringComparison.OrdinalIgnoreCase)
                        .Replace(@"\shellex\-DragDropHandlers\", @"\shellex\DragDropHandlers\", StringComparison.OrdinalIgnoreCase);
                }
                else
                {
                    item.RegistryPath = item.RegistryPath
                        .Replace(@"\shellex\ContextMenuHandlers\", @"\shellex\-ContextMenuHandlers\", StringComparison.OrdinalIgnoreCase)
                        .Replace(@"\shellex\DragDropHandlers\", @"\shellex\-DragDropHandlers\", StringComparison.OrdinalIgnoreCase);
                }
            }
        }
        return ok;
    }

    private static bool SetFileHiddenAttributeState(string filePath, bool hidden)
    {
        try
        {
            if (!File.Exists(filePath))
                return false;

            var attrs = File.GetAttributes(filePath);
            attrs = hidden ? (attrs | FileAttributes.Hidden) : (attrs & ~FileAttributes.Hidden);
            File.SetAttributes(filePath, attrs);
            return ((File.GetAttributes(filePath) & FileAttributes.Hidden) != 0) == hidden;
        }
        catch
        {
            return false;
        }
    }

    private static string FormatRegistryPath(nint rootHive, string subKey)
    {
        if (string.IsNullOrEmpty(subKey)) return string.Empty;
        if (subKey.StartsWith("HKLM\\", StringComparison.OrdinalIgnoreCase) ||
            subKey.StartsWith("HKEY_", StringComparison.OrdinalIgnoreCase) ||
            subKey.StartsWith("HKCU\\", StringComparison.OrdinalIgnoreCase) ||
            subKey.StartsWith("HKU\\", StringComparison.OrdinalIgnoreCase))
            return subKey;

        if (rootHive == PrivilegedRollbackEngine.HKEY_LOCAL_MACHINE) return $@"HKLM\{subKey}";
        if (rootHive == PrivilegedRollbackEngine.HKEY_CURRENT_USER) return $@"HKCU\{subKey}";
        if (rootHive == PrivilegedRollbackEngine.HKEY_USERS) return $@"HKEY_USERS\{subKey}";
        if (rootHive == PrivilegedRollbackEngine.HKEY_CLASSES_ROOT) return $@"HKEY_CLASSES_ROOT\{subKey}";
        return $@"HKLM\{subKey}";
    }

    /// <summary>
    /// 通过独立沙盒进程探针安全解析指定 CLSID Shell Extension 注册的真实右键菜单项列表
    /// </summary>
    public static Task<List<ResolvedMenuItemInfo>> AnalyzeShellExtensionMenuAsync(
        string clsid,
        string? scopeScene = null,
        string? probeHostExePath = null,
        int timeoutMs = 3500)
        => IsolatedProbeRunner.AnalyzeMenuAsync(clsid, scopeScene ?? string.Empty, probeHostExePath, timeoutMs);

    /// <summary>
    /// ContextMenuMgr 仲裁机制：当存在启用/禁用重复的 ContextMenuHandlers 时，保留 LastWriteTime 较新的一方
    /// </summary>
    public static List<ContextMenuItemEntry> DeduplicateByLastWriteTime(IEnumerable<ContextMenuItemEntry> items)
    {
        var map = new Dictionary<string, ContextMenuItemEntry>(StringComparer.OrdinalIgnoreCase);
        foreach (var item in items)
        {
            string logicalKey = $"{item.ScopeScene}|{item.Clsid}|{item.DisplayTitle}";
            if (!map.TryGetValue(logicalKey, out var existing) ||
                item.LastWriteTimeFileTime > existing.LastWriteTimeFileTime)
            {
                map[logicalKey] = item;
            }
        }
        return [.. map.Values];
    }

    /// <summary>
    /// 通过独立沙盒进程 StartupGuard.ProbeHost 隔离探测未知第三方 Shell Extension DLL (3秒超时强杀 + 崩溃零传染)
    /// </summary>
    public static Task<TargetProgramFeatures> ProbeUnknownDllIsolatedAsync(
        string dllPath,
        string? probeHostExePath = null,
        int timeoutMs = 3000)
        => IsolatedProbeRunner.RunAsync(dllPath, probeHostExePath, timeoutMs);

    private HashSet<string> GetBlockedShellExtensionClsids(string? activeUserSid)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (!OperatingSystem.IsWindows())
            return set;

        ReadBlockedValuesFromHive(PrivilegedRollbackEngine.HKEY_LOCAL_MACHINE, BlockedExtensionsSubKey, set);

        if (!string.IsNullOrEmpty(activeUserSid))
        {
            string userPath = InteractiveUserHiveResolver.ResolveUserRegistryPath(activeUserSid, BlockedExtensionsSubKey);
            ReadBlockedValuesFromHive(PrivilegedRollbackEngine.HKEY_USERS, userPath, set);
        }
        else
        {
            ReadBlockedValuesFromHive(PrivilegedRollbackEngine.HKEY_CURRENT_USER, BlockedExtensionsSubKey, set);
        }
        return set;
    }

    /// <summary>
    /// 卸载时重置由 StartupGuard 写入的所有右键菜单屏蔽/拦截锁定，避免重装后残留屏蔽状态
    /// </summary>
    public static int UnblockAllStartupGuardContextMenuLocks()
    {
        if (!OperatingSystem.IsWindows())
            return 0;

        int cleaned = 0;
        PrivilegedRollbackEngine.EnableAllSystemRollbackPrivileges();

        static int CleanBlockedSubKey(RegistryKey root, string subKeyPath)
        {
            int count = 0;
            try
            {
                using var key = root.OpenSubKey(subKeyPath, writable: true);
                if (key == null) return 0;
                foreach (string valName in key.GetValueNames())
                {
                    if (key.GetValue(valName)?.ToString() is string s &&
                        s.Contains("StartupGuard", StringComparison.OrdinalIgnoreCase))
                    {
                        key.DeleteValue(valName, throwOnMissingValue: false);
                        count++;
                    }
                }
            }
            catch { }
            return count;
        }

        cleaned += CleanBlockedSubKey(Registry.LocalMachine, BlockedExtensionsSubKey);
        cleaned += CleanBlockedSubKey(Registry.CurrentUser, BlockedExtensionsSubKey);

        try
        {
            foreach (string sid in Registry.Users.GetSubKeyNames())
            {
                if (!sid.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase) || sid.EndsWith("_Classes", StringComparison.OrdinalIgnoreCase))
                    continue;
                cleaned += CleanBlockedSubKey(Registry.Users, $@"{sid}\{BlockedExtensionsSubKey}");
            }
        }
        catch { }

        return cleaned;
    }

    private static void ReadBlockedValuesFromHive(nint rootHive, string subKey, HashSet<string> targetSet)
    {
        if (RegOpenKeyExW(rootHive, subKey, 0, KEY_READ | KEY_WOW64_64KEY, out nint hKey) != 0)
            return;

        try
        {
            // Blocked 键下每个 ValueName 即为被屏蔽的 {CLSID}
            char* valName = stackalloc char[128];
            uint idx = 0;
            while (true)
            {
                uint cch = 128;
                int err = EnumValueNameOnly(hKey, idx++, valName, ref cch);
                if (err != 0) break;
                targetSet.Add(new string(valName, 0, (int)cch));
            }
        }
        finally
        {
            RegCloseKey(hKey);
        }
    }

    [LibraryImport(AdvApi32Dll, EntryPoint = "RegEnumValueW", StringMarshalling = StringMarshalling.Utf16)]
    private static partial int EnumValueNameOnly(
        nint hKey,
        uint dwIndex,
        char* lpValueName,
        ref uint lpcchValueName,
        nint lpReserved = 0,
        nint lpType = 0,
        nint lpData = 0,
        nint lpcbData = 0);

    private static bool ModifyBlockedValue(nint rootHive, string subKey, string clsid, bool blockItem)
    {
        if (RegCreateKeyExW(rootHive, subKey, 0, null, REG_OPTION_BACKUP_RESTORE, KEY_WRITE | KEY_WOW64_64KEY, 0, out nint hKey, out _) != 0)
            return false;

        try
        {
            if (blockItem)
            {
                const string marker = "Blocked by StartupGuard";
                fixed (char* pMarker = marker)
                {
                    return RegSetValueExW(hKey, clsid, 0, REG_SZ, (byte*)pMarker, (uint)((marker.Length + 1) * 2)) == 0;
                }
            }
            else
            {
                int res = RegDeleteValueW(hKey, clsid);
                return res == 0 || res == 2;
            }
        }
        finally
        {
            RegCloseKey(hKey);
        }
    }

    private static string TryGetFirstSubKeyName(nint rootHive, string subKey, out long lastWriteTime)
    {
        lastWriteTime = 0;
        if (RegOpenKeyExW(rootHive, subKey, 0, KEY_READ | KEY_WOW64_64KEY, out nint hKey) != 0)
            return string.Empty;

        try
        {
            char* buf = stackalloc char[260];
            uint len = 260;
            if (RegEnumKeyExW(hKey, 0, buf, ref len, 0, 0, 0, out lastWriteTime) == 0)
                return new string(buf, 0, (int)len);
            return string.Empty;
        }
        finally
        {
            RegCloseKey(hKey);
        }
    }

    private static string ResolveClassicComInprocServer32(string clsid, string? activeUserSid)
    {
        string normalized = clsid.StartsWith('{') ? clsid : $"{{{clsid}}}";
        string machineKey = $@"SOFTWARE\Classes\CLSID\{normalized}\InprocServer32";

        // 1. 尝试 64 位注册表
        string path = ReadRegistryStringValue(PrivilegedRollbackEngine.HKEY_LOCAL_MACHINE, machineKey, null, KEY_WOW64_64KEY);
        if (!string.IsNullOrEmpty(path))
            return path;

        // 2. 尝试 32 位 WOW64 注册表
        path = ReadRegistryStringValue(PrivilegedRollbackEngine.HKEY_LOCAL_MACHINE, machineKey, null, KEY_WOW64_32KEY);
        if (!string.IsNullOrEmpty(path))
            return path;

        // 3. 显式 WOW6432Node
        string wowMachineKey = $@"SOFTWARE\Classes\WOW6432Node\CLSID\{normalized}\InprocServer32";
        path = ReadRegistryStringValue(PrivilegedRollbackEngine.HKEY_LOCAL_MACHINE, wowMachineKey, null, KEY_WOW64_64KEY);
        if (!string.IsNullOrEmpty(path))
            return path;

        string wowMachineKey2 = $@"SOFTWARE\WOW6432Node\Classes\CLSID\{normalized}\InprocServer32";
        path = ReadRegistryStringValue(PrivilegedRollbackEngine.HKEY_LOCAL_MACHINE, wowMachineKey2, null, KEY_WOW64_64KEY);
        if (!string.IsNullOrEmpty(path))
            return path;

        // 4. 当前用户 Hive
        if (!string.IsNullOrEmpty(activeUserSid))
        {
            string userKey = InteractiveUserHiveResolver.ResolveUserRegistryPath(activeUserSid, $@"Software\Classes\CLSID\{normalized}\InprocServer32");
            path = ReadRegistryStringValue(PrivilegedRollbackEngine.HKEY_USERS, userKey, null, KEY_WOW64_64KEY);
            if (!string.IsNullOrEmpty(path))
                return path;

            path = ReadRegistryStringValue(PrivilegedRollbackEngine.HKEY_USERS, userKey, null, KEY_WOW64_32KEY);
            if (!string.IsNullOrEmpty(path))
                return path;
        }
        return string.Empty;
    }

    private static bool HasRegistryValue(nint rootHive, string subKey, string valueName)
    {
        if (RegOpenKeyExW(rootHive, subKey, 0, KEY_READ | KEY_WOW64_64KEY, out nint hKey) != 0)
            return false;

        try
        {
            uint cb = 0;
            int err = RegQueryValueExW(hKey, valueName, 0, out _, null, ref cb);
            return err == 0;
        }
        finally
        {
            RegCloseKey(hKey);
        }
    }

    private static string ReadRegistryStringValue(nint rootHive, string subKey, string? valueName, uint wowFlag = KEY_WOW64_64KEY)
    {
        if (RegOpenKeyExW(rootHive, subKey, 0, KEY_READ | wowFlag, out nint hKey) != 0)
            return string.Empty;

        try
        {
            byte* data = stackalloc byte[1024];
            uint cb = 1024;
            if (RegQueryValueExW(hKey, valueName, 0, out uint valType, data, ref cb) == 0 && cb >= 2 && (valType == 1 || valType == 2))
            {
                string raw = Marshal.PtrToStringUni((nint)data)?.TrimEnd('\0') ?? string.Empty;
                return Environment.ExpandEnvironmentVariables(raw);
            }
            return string.Empty;
        }
        finally
        {
            RegCloseKey(hKey);
        }
    }

    private static string ResolvePackagedComServerBinary(nint rootHive, string packageId, string clsid)
    {
        string classKey = $@"SOFTWARE\Classes\PackagedCom\Package\{packageId}\Class\{clsid}";
        if (RegOpenKeyExW(rootHive, classKey, 0, KEY_READ | KEY_WOW64_64KEY, out nint hKey) != 0)
            return string.Empty;

        try
        {
            byte* data = stackalloc byte[1024];
            uint cb = 1024;
            if (RegQueryValueExW(hKey, "DllPath", 0, out _, data, ref cb) == 0 && cb >= 2)
            {
                return Marshal.PtrToStringUni((nint)data)?.TrimEnd('\0') ?? string.Empty;
            }
            return string.Empty;
        }
        finally
        {
            RegCloseKey(hKey);
        }
    }

    private static string ExtractFriendlyPackageName(string packageFullName)
    {
        int underscore = packageFullName.IndexOf('_');
        return underscore > 0 ? packageFullName[..underscore] : packageFullName;
    }

    public sealed class MenuAnalysisMatch
    {
        public string Title { get; init; } = string.Empty;
        public string Subtitle { get; init; } = string.Empty;
        public string[] Breadcrumbs { get; init; } = Array.Empty<string>();
        public string NavTag { get; init; } = string.Empty;
        public string FileTypeTab { get; init; } = string.Empty;
        public string Parameter { get; init; } = string.Empty;
    }

    public static readonly string[] SupportedPerceivedTypes =
        ["text", "document", "image", "video", "audio", "compressed", "system"];

    public static readonly string[] SupportedDirectoryTypes =
        ["Document", "Image", "Video", "Audio"];

    /// <summary>
    /// 扫描 HKLM / 当前交互用户 / HKCU 下 Classes\Applications 中的打开方式关联项
    /// </summary>
    public List<ContextMenuItemEntry> ScanOpenWithApplications(string? activeUserSid)
    {
        var results = new List<ContextMenuItemEntry>();
        if (!OperatingSystem.IsWindows())
            return results;

        var seenApps = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (!string.IsNullOrEmpty(activeUserSid))
        {
            string userApps = InteractiveUserHiveResolver.ResolveUserRegistryPath(activeUserSid, @"Software\Classes\Applications");
            ScanApplicationsHive(PrivilegedRollbackEngine.HKEY_USERS, userApps, seenApps, results, activeUserSid);
        }
        else
        {
            ScanApplicationsHive(PrivilegedRollbackEngine.HKEY_CURRENT_USER, @"Software\Classes\Applications", seenApps, results, activeUserSid);
        }

        ScanApplicationsHive(PrivilegedRollbackEngine.HKEY_LOCAL_MACHINE, @"SOFTWARE\Classes\Applications", seenApps, results, activeUserSid);
        return results;
    }

    private void ScanApplicationsHive(
        nint rootHive,
        string subKeyPath,
        HashSet<string> seenApps,
        List<ContextMenuItemEntry> output,
        string? activeUserSid)
    {
        if (RegOpenKeyExW(rootHive, subKeyPath, 0, KEY_READ | KEY_WOW64_64KEY, out nint hApps) != 0)
            return;

        try
        {
            char* nameBuf = stackalloc char[260];
            uint index = 0;
            while (true)
            {
                uint nameLen = 260;
                if (RegEnumKeyExW(hApps, index++, nameBuf, ref nameLen, 0, 0, 0, out long lastWriteFt) != 0)
                    break;

                string appName = new(nameBuf, 0, (int)nameLen);
                if (!appName.Contains('.') || !seenApps.Add(appName))
                    continue;

                string appSub = $@"{subKeyPath}\{appName}";
                if (HasRegistryValue(rootHive, appSub, "NeverDefault"))
                    continue;

                string command = FindApplicationOpenCommand(rootHive, appSub);
                string exePath = ExtractCommandExecutablePath(command);
                if (string.IsNullOrEmpty(command) && string.IsNullOrEmpty(exePath))
                    continue;
                if (!string.IsNullOrEmpty(exePath) && !File.Exists(exePath))
                    continue;

                bool noOpenWith = HasRegistryValue(rootHive, appSub, "NoOpenWith");
                if (!noOpenWith && rootHive == PrivilegedRollbackEngine.HKEY_LOCAL_MACHINE)
                {
                    string userAppOverride = !string.IsNullOrEmpty(activeUserSid)
                        ? InteractiveUserHiveResolver.ResolveUserRegistryPath(activeUserSid, $@"Software\Classes\Applications\{appName}")
                        : $@"Software\Classes\Applications\{appName}";
                    nint userHive = !string.IsNullOrEmpty(activeUserSid)
                        ? PrivilegedRollbackEngine.HKEY_USERS
                        : PrivilegedRollbackEngine.HKEY_CURRENT_USER;
                    noOpenWith = HasRegistryValue(userHive, userAppOverride, "NoOpenWith");
                }

                string friendly = ReadRegistryStringValue(rootHive, appSub, "FriendlyAppName");
                if (!string.IsNullOrEmpty(friendly))
                    friendly = ResolveMuiString(friendly);
                if ((string.IsNullOrEmpty(friendly) || friendly.StartsWith('@')) && !string.IsNullOrEmpty(exePath) && File.Exists(exePath))
                {
                    try
                    {
                        var fvi = FileVersionInfo.GetVersionInfo(exePath);
                        friendly = !string.IsNullOrWhiteSpace(fvi.FileDescription) ? fvi.FileDescription.Trim()
                                 : !string.IsNullOrWhiteSpace(fvi.ProductName) ? fvi.ProductName.Trim()
                                 : Path.GetFileNameWithoutExtension(appName);
                    }
                    catch { }
                }
                if (string.IsNullOrWhiteSpace(friendly))
                    friendly = Path.GetFileNameWithoutExtension(appName);

                output.Add(new ContextMenuItemEntry
                {
                    IdKey = $"OpenWith:{appName}",
                    DisplayTitle = $"{friendly} ({appName})",
                    MenuCategory = MonitorCategory.ClassicContextMenu,
                    ScopeScene = "OpenWith (打开方式)",
                    RegistryPath = FormatRegistryPath(rootHive, appSub),
                    TargetBinaryOrCommand = !string.IsNullOrEmpty(exePath) ? exePath : command,
                    IsEnabled = !noOpenWith,
                    LastWriteTimeFileTime = lastWriteFt
                });
            }
        }
        finally
        {
            RegCloseKey(hApps);
        }
    }

    private static string FindApplicationOpenCommand(nint rootHive, string appSubKey)
    {
        string openCmd = ReadRegistryStringValue(rootHive, $@"{appSubKey}\shell\open\command", null);
        if (!string.IsNullOrEmpty(openCmd))
            return openCmd;

        string shellSub = $@"{appSubKey}\shell";
        string firstVerb = TryGetFirstSubKeyName(rootHive, shellSub, out _);
        if (!string.IsNullOrEmpty(firstVerb))
            return ReadRegistryStringValue(rootHive, $@"{shellSub}\{firstVerb}\command", null);

        return string.Empty;
    }

    /// <summary>
    /// 启用或禁用“打开方式”应用项 (NoOpenWith)
    /// </summary>
    public bool SetOpenWithApplicationState(string appNameOrRegPath, bool enable, string? activeUserSid)
    {
        if (string.IsNullOrWhiteSpace(appNameOrRegPath) || !OperatingSystem.IsWindows())
            return false;

        PrivilegedRollbackEngine.EnableAllSystemRollbackPrivileges();
        string appName = appNameOrRegPath.Contains('\\')
            ? PrivilegedRollbackEngine.ExtractLeafKeyName(appNameOrRegPath)
            : appNameOrRegPath.Replace("OpenWith:", "", StringComparison.OrdinalIgnoreCase).Trim();

        if (string.IsNullOrEmpty(appName))
            return false;

        string relUserSub = $@"Software\Classes\Applications\{appName}";
        string machineSub = $@"SOFTWARE\Classes\Applications\{appName}";
        (nint userHive, string userSub) = !string.IsNullOrEmpty(activeUserSid)
            ? (PrivilegedRollbackEngine.HKEY_USERS, InteractiveUserHiveResolver.ResolveUserRegistryPath(activeUserSid, relUserSub))
            : (PrivilegedRollbackEngine.HKEY_CURRENT_USER, relUserSub);

        if (!enable)
        {
            // 优先写向用户 override（若 HKLM 键存在也一并写入保证生效）
            bool okUser = SetEmptyStringRegistryValue(userHive, userSub, "NoOpenWith");
            bool okMachine = false;
            if (RegOpenKeyExW(PrivilegedRollbackEngine.HKEY_LOCAL_MACHINE, machineSub, 0, KEY_READ | KEY_WOW64_64KEY, out nint hM) == 0)
            {
                RegCloseKey(hM);
                okMachine = SetEmptyStringRegistryValue(PrivilegedRollbackEngine.HKEY_LOCAL_MACHINE, machineSub, "NoOpenWith");
            }
            return okUser || okMachine;
        }
        else
        {
            bool okUser = DeleteRegistryValue(userHive, userSub, "NoOpenWith");
            bool okMachine = DeleteRegistryValue(PrivilegedRollbackEngine.HKEY_LOCAL_MACHINE, machineSub, "NoOpenWith");
            return okUser || okMachine;
        }
    }

    /// <summary>
    /// 扫描“文件类型”7 个子标签对应的注册表右键菜单
    /// </summary>
    public List<ContextMenuItemEntry> ScanFileTypeScene(string fileTypeMode, string? param, string? activeUserSid)
    {
        var results = new List<ContextMenuItemEntry>();
        if (!OperatingSystem.IsWindows())
            return results;

        var relPaths = new List<(string SceneLabel, string RelativeClassesPath)>();
        switch (fileTypeMode)
        {
            case "LnkFile":
                relPaths.Add(("LnkFile (快捷方式)", @"Software\Classes\lnkfile"));
                break;
            case "UwpLnk":
                relPaths.Add(("UwpLnk (UWP 快捷方式)", @"Software\Classes\Launcher.ImmersiveApplication"));
                break;
            case "ExeFile":
                relPaths.Add(("ExeFile (可执行文件)", @"Software\Classes\exefile"));
                break;
            case "UnknownType":
                relPaths.Add(("UnknownType (未知类型)", @"Software\Classes\Unknown"));
                break;
            case "PerceivedType":
                if (!string.IsNullOrWhiteSpace(param))
                {
                    relPaths.Add(($"PerceivedType ({param})", $@"Software\Classes\SystemFileAssociations\{param.Trim()}"));
                }
                break;
            case "DirectoryType":
                if (!string.IsNullOrWhiteSpace(param))
                {
                    relPaths.Add(($"DirectoryType ({param})", $@"Software\Classes\SystemFileAssociations\Directory.{param.Trim()}"));
                }
                break;
            case "CustomExtension":
            {
                string ext = (param ?? string.Empty).Trim();
                if (!string.IsNullOrEmpty(ext))
                {
                    if (!ext.StartsWith('.'))
                        ext = "." + ext;
                    relPaths.Add(($"Extension ({ext})", $@"Software\Classes\SystemFileAssociations\{ext}"));
                    var (openMode, _) = GetExtensionOpenModeAndPerceivedType(ext, activeUserSid);
                    if (!string.IsNullOrEmpty(openMode))
                    {
                        relPaths.Add(($"Extension ({ext} -> {openMode})", $@"Software\Classes\{openMode}"));
                    }
                }
                break;
            }
        }

        if (relPaths.Count == 0)
            return results;

        var blockedClsids = GetBlockedShellExtensionClsids(activeUserSid);
        foreach (var (sceneLabel, relPath) in relPaths)
        {
            string hklmPath = "SOFTWARE" + relPath["Software".Length..];
            ScanClassicShellVerbsHive(PrivilegedRollbackEngine.HKEY_LOCAL_MACHINE, $@"{hklmPath}\shell", sceneLabel, results);
            ScanClassicShellExHandlersHive(PrivilegedRollbackEngine.HKEY_LOCAL_MACHINE, $@"{hklmPath}\shellex\ContextMenuHandlers", sceneLabel, blockedClsids, results, activeUserSid, isDisabledFolder: false);
            ScanClassicShellExHandlersHive(PrivilegedRollbackEngine.HKEY_LOCAL_MACHINE, $@"{hklmPath}\shellex\-ContextMenuHandlers", sceneLabel, blockedClsids, results, activeUserSid, isDisabledFolder: true);

            if (!string.IsNullOrEmpty(activeUserSid))
            {
                string userPath = InteractiveUserHiveResolver.ResolveUserRegistryPath(activeUserSid, relPath);
                ScanClassicShellVerbsHive(PrivilegedRollbackEngine.HKEY_USERS, $@"{userPath}\shell", sceneLabel, results);
                ScanClassicShellExHandlersHive(PrivilegedRollbackEngine.HKEY_USERS, $@"{userPath}\shellex\ContextMenuHandlers", sceneLabel, blockedClsids, results, activeUserSid, isDisabledFolder: false);
                ScanClassicShellExHandlersHive(PrivilegedRollbackEngine.HKEY_USERS, $@"{userPath}\shellex\-ContextMenuHandlers", sceneLabel, blockedClsids, results, activeUserSid, isDisabledFolder: true);
            }
            else
            {
                ScanClassicShellVerbsHive(PrivilegedRollbackEngine.HKEY_CURRENT_USER, $@"{relPath}\shell", sceneLabel, results);
                ScanClassicShellExHandlersHive(PrivilegedRollbackEngine.HKEY_CURRENT_USER, $@"{relPath}\shellex\ContextMenuHandlers", sceneLabel, blockedClsids, results, activeUserSid, isDisabledFolder: false);
                ScanClassicShellExHandlersHive(PrivilegedRollbackEngine.HKEY_CURRENT_USER, $@"{relPath}\shellex\-ContextMenuHandlers", sceneLabel, blockedClsids, results, activeUserSid, isDisabledFolder: true);
            }
        }

        return results;
    }

    public (string OpenModeProgId, string PerceivedType) GetExtensionOpenModeAndPerceivedType(string extension, string? activeUserSid)
    {
        if (string.IsNullOrWhiteSpace(extension) || !OperatingSystem.IsWindows())
            return (string.Empty, string.Empty);

        string ext = extension.Trim();
        if (!ext.StartsWith('.'))
            ext = "." + ext;

        string userChoiceSub = $@"Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\{ext}\UserChoice";
        string progId = !string.IsNullOrEmpty(activeUserSid)
            ? ReadRegistryStringValue(PrivilegedRollbackEngine.HKEY_USERS, InteractiveUserHiveResolver.ResolveUserRegistryPath(activeUserSid, userChoiceSub), "ProgId")
            : ReadRegistryStringValue(PrivilegedRollbackEngine.HKEY_CURRENT_USER, userChoiceSub, "ProgId");

        if (string.IsNullOrEmpty(progId) && !string.IsNullOrEmpty(activeUserSid))
        {
            progId = ReadRegistryStringValue(PrivilegedRollbackEngine.HKEY_USERS, InteractiveUserHiveResolver.ResolveUserRegistryPath(activeUserSid, $@"Software\Classes\{ext}"), null);
        }
        if (string.IsNullOrEmpty(progId))
        {
            progId = ReadRegistryStringValue(PrivilegedRollbackEngine.HKEY_LOCAL_MACHINE, $@"SOFTWARE\Classes\{ext}", null);
        }

        string perceived = string.Empty;
        if (!string.IsNullOrEmpty(activeUserSid))
        {
            perceived = ReadRegistryStringValue(PrivilegedRollbackEngine.HKEY_USERS, InteractiveUserHiveResolver.ResolveUserRegistryPath(activeUserSid, $@"Software\Classes\{ext}"), "PerceivedType");
        }
        if (string.IsNullOrEmpty(perceived))
        {
            perceived = ReadRegistryStringValue(PrivilegedRollbackEngine.HKEY_CURRENT_USER, $@"Software\Classes\{ext}", "PerceivedType");
        }
        if (string.IsNullOrEmpty(perceived))
        {
            perceived = ReadRegistryStringValue(PrivilegedRollbackEngine.HKEY_LOCAL_MACHINE, $@"SOFTWARE\Classes\{ext}", "PerceivedType");
        }

        return (progId, perceived);
    }

    public bool SetExtensionPerceivedType(string extension, string? perceivedType, string? activeUserSid)
    {
        if (string.IsNullOrWhiteSpace(extension) || !OperatingSystem.IsWindows())
            return false;

        string ext = extension.Trim();
        if (!ext.StartsWith('.'))
            ext = "." + ext;

        string machineSub = $@"SOFTWARE\Classes\{ext}";
        if (string.IsNullOrWhiteSpace(perceivedType))
        {
            bool d1 = DeleteRegistryValue(PrivilegedRollbackEngine.HKEY_LOCAL_MACHINE, machineSub, "PerceivedType");
            bool d2 = DeleteRegistryValue(PrivilegedRollbackEngine.HKEY_CURRENT_USER, $@"Software\Classes\{ext}", "PerceivedType");
            return d1 || d2;
        }

        if (SetStringRegistryValue(PrivilegedRollbackEngine.HKEY_LOCAL_MACHINE, machineSub, "PerceivedType", perceivedType.Trim()))
            return true;

        return SetStringRegistryValue(PrivilegedRollbackEngine.HKEY_CURRENT_USER, $@"Software\Classes\{ext}", "PerceivedType", perceivedType.Trim());
    }

    /// <summary>
    /// 菜单分析：分析文件、文件夹或快捷方式并返回可直接跳转的匹配场景卡片
    /// </summary>
    public List<MenuAnalysisMatch> AnalyzeTargetForContextMenu(string targetPath, bool isFolder, string? activeUserSid)
    {
        var matches = new List<MenuAnalysisMatch>();
        if (string.IsNullOrWhiteSpace(targetPath))
            return matches;

        matches.Add(new MenuAnalysisMatch
        {
            Title = "所有对象",
            Subtitle = "对任意文件与文件夹生效的通用菜单项",
            Breadcrumbs = ["右键菜单", "所有对象"],
            NavTag = "ClassicAllObjects"
        });

        if (isFolder)
        {
            matches.Add(new MenuAnalysisMatch
            {
                Title = "文件夹",
                Subtitle = "Folder 通用文件夹节点右键菜单",
                Breadcrumbs = ["右键菜单", "文件夹"],
                NavTag = "ClassicFolder"
            });
            matches.Add(new MenuAnalysisMatch
            {
                Title = "目录",
                Subtitle = "Directory 文件系统目录右键菜单",
                Breadcrumbs = ["右键菜单", "目录"],
                NavTag = "ClassicDirectory"
            });
            matches.Add(new MenuAnalysisMatch
            {
                Title = "目录背景",
                Subtitle = "在当前文件夹空白处右键时的菜单项",
                Breadcrumbs = ["右键菜单", "目录背景"],
                NavTag = "ClassicDirBackground"
            });
            matches.Add(new MenuAnalysisMatch
            {
                Title = "目录类型",
                Subtitle = "按文件夹内容模板分类的系统感知类型菜单",
                Breadcrumbs = ["右键菜单", "文件类型", "目录类型"],
                NavTag = "FileTypes",
                FileTypeTab = "DirectoryType",
                Parameter = "Document"
            });
            return matches;
        }

        matches.Add(new MenuAnalysisMatch
        {
            Title = "文件",
            Subtitle = "对所有文件 (*) 生效的经典扩展与菜单命令",
            Breadcrumbs = ["右键菜单", "文件"],
            NavTag = "ClassicFile"
        });

        string ext = Path.GetExtension(targetPath).ToLowerInvariant();
        if (ext == ".exe")
        {
            matches.Add(new MenuAnalysisMatch
            {
                Title = "可执行文件 (.exe)",
                Subtitle = "针对可执行程序的专属菜单 (exefile)",
                Breadcrumbs = ["右键菜单", "文件类型", "可执行文件"],
                NavTag = "FileTypes",
                FileTypeTab = "ExeFile"
            });
        }
        else if (!string.IsNullOrEmpty(ext))
        {
            matches.Add(new MenuAnalysisMatch
            {
                Title = $"自定义扩展名 ({ext})",
                Subtitle = "当前扩展名关联及打开方式应用专属菜单",
                Breadcrumbs = ["右键菜单", "文件类型", "自定义扩展名", ext],
                NavTag = "FileTypes",
                FileTypeTab = "CustomExtension",
                Parameter = ext
            });
        }

        var (openMode, perceivedType) = GetExtensionOpenModeAndPerceivedType(ext, activeUserSid);
        if (string.IsNullOrEmpty(openMode) && ext != ".exe" && ext != ".lnk")
        {
            matches.Add(new MenuAnalysisMatch
            {
                Title = "未知类型",
                Subtitle = "未绑定默认打开方式时的扩展菜单 (Unknown)",
                Breadcrumbs = ["右键菜单", "文件类型", "未知类型"],
                NavTag = "FileTypes",
                FileTypeTab = "UnknownType"
            });
        }

        if (!string.IsNullOrEmpty(perceivedType))
        {
            matches.Add(new MenuAnalysisMatch
            {
                Title = $"感知类型 ({perceivedType})",
                Subtitle = $"SystemFileAssociations\\{perceivedType} 类别右键菜单",
                Breadcrumbs = ["右键菜单", "文件类型", "感知类型", perceivedType],
                NavTag = "FileTypes",
                FileTypeTab = "PerceivedType",
                Parameter = perceivedType
            });
        }

        if (ext == ".lnk")
        {
            matches.Add(new MenuAnalysisMatch
            {
                Title = "快捷方式 (.lnk)",
                Subtitle = "快捷方式文件本身关联的右键菜单",
                Breadcrumbs = ["右键菜单", "文件类型", "快捷方式"],
                NavTag = "FileTypes",
                FileTypeTab = "LnkFile"
            });

            string resolvedTarget = ResolveShortcutTarget(targetPath);
            if (!string.IsNullOrEmpty(resolvedTarget))
            {
                if (Directory.Exists(resolvedTarget))
                {
                    matches.Add(new MenuAnalysisMatch
                    {
                        Title = "快捷方式目标 (文件夹)",
                        Subtitle = resolvedTarget,
                        Breadcrumbs = ["右键菜单", "目录"],
                        NavTag = "ClassicDirectory"
                    });
                }
                else if (File.Exists(resolvedTarget))
                {
                    string targetExt = Path.GetExtension(resolvedTarget).ToLowerInvariant();
                    if (targetExt == ".exe")
                    {
                        matches.Add(new MenuAnalysisMatch
                        {
                            Title = "快捷方式目标 (可执行文件)",
                            Subtitle = resolvedTarget,
                            Breadcrumbs = ["右键菜单", "文件类型", "可执行文件"],
                            NavTag = "FileTypes",
                            FileTypeTab = "ExeFile"
                        });
                    }
                    else if (!string.IsNullOrEmpty(targetExt))
                    {
                        matches.Add(new MenuAnalysisMatch
                        {
                            Title = $"快捷方式目标 ({targetExt})",
                            Subtitle = resolvedTarget,
                            Breadcrumbs = ["右键菜单", "文件类型", "自定义扩展名", targetExt],
                            NavTag = "FileTypes",
                            FileTypeTab = "CustomExtension",
                            Parameter = targetExt
                        });
                    }
                }
            }
        }

        return matches;
    }

    /// <summary>
    /// 使用 Windows ShellLink COM 解析 .lnk 快捷方式真实目标路径
    /// </summary>
    public static string ResolveShortcutTarget(string lnkPath)
    {
        if (!OperatingSystem.IsWindows() || string.IsNullOrWhiteSpace(lnkPath) || !File.Exists(lnkPath))
            return string.Empty;

        try
        {
            object? linkObj = new NativeShellLink();
            if (linkObj is not IShellLinkW link || linkObj is not System.Runtime.InteropServices.ComTypes.IPersistFile persist)
                return string.Empty;

            try
            {
                persist.Load(lnkPath, 0);
                var sb = new StringBuilder(520);
                link.GetPath(sb, sb.Capacity, IntPtr.Zero, 0);
                string resolved = sb.ToString().Trim();
                return Environment.ExpandEnvironmentVariables(resolved);
            }
            finally
            {
                Marshal.FinalReleaseComObject(linkObj);
            }
        }
        catch
        {
            return string.Empty;
        }
    }

    [ComImport]
    [Guid("00021401-0000-0000-C000-000000000046")]
    private class NativeShellLink { }

    [ComImport]
    [Guid("000214F9-0000-0000-C000-000000000046")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IShellLinkW
    {
        void GetPath([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszFile, int cchMaxPath, IntPtr pfd, int fFlags);
        void GetIDList(out IntPtr ppidl);
        void SetIDList(IntPtr pidl);
        void GetDescription([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszName, int cchMaxName);
        void SetDescription([MarshalAs(UnmanagedType.LPWStr)] string pszName);
        void GetWorkingDirectory([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszDir, int cchMaxPath);
        void SetWorkingDirectory([MarshalAs(UnmanagedType.LPWStr)] string pszDir);
        void GetArguments([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszArgs, int cchMaxPath);
        void SetArguments([MarshalAs(UnmanagedType.LPWStr)] string pszArgs);
        void GetHotkey(out short pwHotkey);
        void SetHotkey(short wHotkey);
        void GetShowCmd(out int piShowCmd);
        void SetShowCmd(int iShowCmd);
        void GetIconLocation([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszIconPath, int cchIconPath, out int piIcon);
        void SetIconLocation([MarshalAs(UnmanagedType.LPWStr)] string pszIconPath, int iIcon);
        void SetRelativePath([MarshalAs(UnmanagedType.LPWStr)] string pszPathRel, int dwReserved);
        void Resolve(IntPtr hwnd, int fFlags);
        void SetPath([MarshalAs(UnmanagedType.LPWStr)] string pszFile);
    }

    /// <summary>
    /// 自动清理已卸载第三方应用的孤立右键菜单屏蔽项（Blocked GUID 与 -ContextMenuHandlers / -DragDropHandlers），
    /// 即使未加入永久规则也能确保重新安装时恢复正常检测。
    /// </summary>
    public int CleanupOrphanedContextMenuBlocks(string? activeUserSid)
    {
        if (!OperatingSystem.IsWindows())
            return 0;

        int cleaned = 0;
        PrivilegedRollbackEngine.EnableAllSystemRollbackPrivileges();

        // 1. 清理 HKLM 与 User Hive 的 Shell Extensions\Blocked 中宿主已卸载的 {CLSID}
        cleaned += CleanOrphanedBlockedKey(PrivilegedRollbackEngine.HKEY_LOCAL_MACHINE, BlockedExtensionsSubKey, activeUserSid);
        if (!string.IsNullOrEmpty(activeUserSid))
        {
            cleaned += CleanOrphanedBlockedKey(
                PrivilegedRollbackEngine.HKEY_USERS,
                InteractiveUserHiveResolver.ResolveUserRegistryPath(activeUserSid, BlockedExtensionsSubKey),
                activeUserSid);
        }
        else
        {
            cleaned += CleanOrphanedBlockedKey(PrivilegedRollbackEngine.HKEY_CURRENT_USER, BlockedExtensionsSubKey, activeUserSid);
        }

        // 2. 清理 \-ContextMenuHandlers 与 \-DragDropHandlers 中宿主 CLSID 或 DLL 已消失的孤立禁用项
        foreach (var (_, relativeSubKey) in ClassicShellScenes)
        {
            string hklmSub = "SOFTWARE" + relativeSubKey["Software".Length..];
            foreach (string disabledFolder in new[] { "-ContextMenuHandlers", "-DragDropHandlers" })
            {
                cleaned += CleanOrphanedDisabledHandlerFolder(PrivilegedRollbackEngine.HKEY_LOCAL_MACHINE, $@"{hklmSub}\shellex\{disabledFolder}", activeUserSid);
                if (!string.IsNullOrEmpty(activeUserSid))
                {
                    string uSub = InteractiveUserHiveResolver.ResolveUserRegistryPath(activeUserSid, relativeSubKey);
                    cleaned += CleanOrphanedDisabledHandlerFolder(PrivilegedRollbackEngine.HKEY_USERS, $@"{uSub}\shellex\{disabledFolder}", activeUserSid);
                }
                else
                {
                    cleaned += CleanOrphanedDisabledHandlerFolder(PrivilegedRollbackEngine.HKEY_CURRENT_USER, $@"{relativeSubKey}\shellex\{disabledFolder}", activeUserSid);
                }
            }
        }

        return cleaned;
    }

    private int CleanOrphanedBlockedKey(nint rootHive, string blockedSubKey, string? activeUserSid)
    {
        int removed = 0;
        try
        {
            using var baseKey = OpenManagedBaseHive(rootHive);
            using var blockedKey = baseKey.OpenSubKey(blockedSubKey, writable: true);
            if (blockedKey == null)
                return 0;

            foreach (string valName in blockedKey.GetValueNames())
            {
                if (!ContextMenuGuidResolver.TryParseGuid(valName, out Guid g) || g == Guid.Empty)
                    continue;
                string normalized = $"{g:B}";
                if (!IsComHandlerOrPackageInstalled(normalized, activeUserSid))
                {
                    try
                    {
                        blockedKey.DeleteValue(valName, throwOnMissingValue: false);
                        removed++;
                    }
                    catch { }
                }
            }
        }
        catch { }
        return removed;
    }

    private int CleanOrphanedDisabledHandlerFolder(nint rootHive, string handlerFolderSubKey, string? activeUserSid)
    {
        int removed = 0;
        try
        {
            using var baseKey = OpenManagedBaseHive(rootHive);
            using var parentKey = baseKey.OpenSubKey(handlerFolderSubKey, writable: true);
            if (parentKey == null)
                return 0;

            foreach (string subName in parentKey.GetSubKeyNames())
            {
                string clsid = subName.TrimStart('-');
                if (!ContextMenuGuidResolver.TryParseGuid(clsid, out Guid g) || g == Guid.Empty)
                {
                    using var sub = parentKey.OpenSubKey(subName, false);
                    string defVal = sub?.GetValue(null)?.ToString()?.Trim().TrimStart('-') ?? string.Empty;
                    if (!ContextMenuGuidResolver.TryParseGuid(defVal, out g) || g == Guid.Empty)
                        continue;
                    clsid = defVal;
                }

                string normalized = $"{g:B}";
                if (!IsComHandlerOrPackageInstalled(normalized, activeUserSid))
                {
                    try
                    {
                        parentKey.DeleteSubKeyTree(subName, throwOnMissingSubKey: false);
                        removed++;
                    }
                    catch { }
                }
            }
        }
        catch { }
        return removed;
    }

    public bool IsComHandlerOrPackageInstalled(string clsid, string? activeUserSid)
    {
        if (!OperatingSystem.IsWindows())
            return true;

        string normalized = clsid.StartsWith('{') ? clsid : $"{{{clsid}}}";

        // PackagedCom 检查
        using (var hklmPkg = Microsoft.Win32.Registry.LocalMachine.OpenSubKey($@"SOFTWARE\Classes\PackagedCom\ClassIndex\{normalized}", false))
        {
            if (hklmPkg != null)
            {
                string pkgId = hklmPkg.GetValueNames().FirstOrDefault() ?? hklmPkg.GetSubKeyNames().FirstOrDefault() ?? string.Empty;
                if (string.IsNullOrEmpty(pkgId))
                    return true;
                string dll = ResolvePackagedComServerBinary(PrivilegedRollbackEngine.HKEY_LOCAL_MACHINE, pkgId, normalized);
                return string.IsNullOrEmpty(dll) || File.Exists(dll);
            }
        }
        string userClassIdx = !string.IsNullOrEmpty(activeUserSid)
            ? InteractiveUserHiveResolver.ResolveUserRegistryPath(activeUserSid, $@"Software\Classes\PackagedCom\ClassIndex\{normalized}")
            : $@"Software\Classes\PackagedCom\ClassIndex\{normalized}";
        using (var userPkg = (!string.IsNullOrEmpty(activeUserSid) ? Microsoft.Win32.Registry.Users : Microsoft.Win32.Registry.CurrentUser).OpenSubKey(userClassIdx, false))
        {
            if (userPkg != null)
                return true;
        }

        // Classic CLSID 注册表检查
        bool hasAnyClsidReg =
            Microsoft.Win32.Registry.LocalMachine.OpenSubKey($@"SOFTWARE\Classes\CLSID\{normalized}", false) != null ||
            Microsoft.Win32.Registry.LocalMachine.OpenSubKey($@"SOFTWARE\Classes\WOW6432Node\CLSID\{normalized}", false) != null ||
            Microsoft.Win32.Registry.CurrentUser.OpenSubKey($@"Software\Classes\CLSID\{normalized}", false) != null;

        if (!hasAnyClsidReg && !string.IsNullOrEmpty(activeUserSid))
        {
            string uClsid = InteractiveUserHiveResolver.ResolveUserRegistryPath(activeUserSid, $@"Software\Classes\CLSID\{normalized}");
            hasAnyClsidReg = Microsoft.Win32.Registry.Users.OpenSubKey(uClsid, false) != null;
        }

        if (!hasAnyClsidReg)
            return false;

        string serverPath = ResolveClassicComInprocServer32(normalized, activeUserSid);
        string physical = ExtractCommandExecutablePath(serverPath);
        if (!string.IsNullOrEmpty(physical) && Path.IsPathRooted(physical))
        {
            return File.Exists(physical);
        }

        return true;
    }

    private static Microsoft.Win32.RegistryKey OpenManagedBaseHive(nint rootHive) =>
        rootHive == PrivilegedRollbackEngine.HKEY_USERS ? Microsoft.Win32.Registry.Users :
        rootHive == PrivilegedRollbackEngine.HKEY_CURRENT_USER ? Microsoft.Win32.Registry.CurrentUser :
        rootHive == PrivilegedRollbackEngine.HKEY_CLASSES_ROOT ? Microsoft.Win32.Registry.ClassesRoot :
        Microsoft.Win32.Registry.LocalMachine;

    private static string ExtractCommandExecutablePath(string rawCommand)
    {
        if (string.IsNullOrWhiteSpace(rawCommand))
            return string.Empty;
        string s = Environment.ExpandEnvironmentVariables(rawCommand.Trim());
        if (s.StartsWith('"'))
        {
            int endQuote = s.IndexOf('"', 1);
            if (endQuote > 1)
                return s[1..endQuote];
        }
        int exeIdx = s.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        if (exeIdx > 0)
            return s[..(exeIdx + 4)].Trim('"');
        int dllIdx = s.IndexOf(".dll", StringComparison.OrdinalIgnoreCase);
        if (dllIdx > 0)
            return s[..(dllIdx + 4)].Trim('"');
        return s.Trim('"');
    }

    private static bool SetEmptyStringRegistryValue(nint rootHive, string subKey, string valueName)
        => SetStringRegistryValue(rootHive, subKey, valueName, string.Empty);

    private static bool SetStringRegistryValue(nint rootHive, string subKey, string valueName, string val)
    {
        if (RegCreateKeyExW(rootHive, subKey, 0, null, REG_OPTION_BACKUP_RESTORE, KEY_WRITE | KEY_WOW64_64KEY, 0, out nint hKey, out _) != 0)
            return false;
        try
        {
            fixed (char* pVal = val)
            {
                return RegSetValueExW(hKey, valueName, 0, REG_SZ, (byte*)pVal, (uint)((val.Length + 1) * 2)) == 0;
            }
        }
        finally { RegCloseKey(hKey); }
    }

    private static bool DeleteRegistryValue(nint rootHive, string subKey, string valueName)
    {
        if (RegOpenKeyExW(rootHive, subKey, 0, KEY_SET_VALUE | KEY_WOW64_64KEY, out nint hKey) != 0)
            return false;
        try
        {
            int res = RegDeleteValueW(hKey, valueName);
            return res == 0 || res == 2;
        }
        finally { RegCloseKey(hKey); }
    }

    private static int? ReadRegistryDwordValue(nint rootHive, string subKey, string valueName)
    {
        if (RegOpenKeyExW(rootHive, subKey, 0, KEY_READ | KEY_WOW64_64KEY, out nint hKey) != 0)
            return null;
        try
        {
            uint val = 0;
            uint cb = sizeof(uint);
            if (RegQueryValueExW(hKey, valueName, 0, out uint valType, (byte*)&val, ref cb) == 0 && valType == 4)
            {
                return unchecked((int)val);
            }
            return null;
        }
        finally { RegCloseKey(hKey); }
    }

    // ================= 1. 右键拖拽 DefaultDropEffect =================

    public static readonly string[] DefaultDropEffectClassSubKeys =
    [
        "*",
        "AllFilesystemObjects",
        "Folder",
        "Directory"
    ];

    /// <summary>
    /// 读取系统当前默认拖放效果（0=系统默认, 1=复制, 2=移动, 4=创建快捷方式）
    /// </summary>
    public int GetDefaultDropEffect()
    {
        if (!OperatingSystem.IsWindows())
            return 0;

        foreach (string subKey in DefaultDropEffectClassSubKeys)
        {
            try
            {
                using var classesRootKey = Registry.ClassesRoot.OpenSubKey(subKey, false);
                if (classesRootKey?.GetValue("DefaultDropEffect") is int val && val is 0 or 1 or 2 or 4)
                    return val;
            }
            catch { }
        }
        return 0;
    }

    /// <summary>
    /// 设置右键/左键默认拖放效果（写入 *, AllFilesystemObjects, Folder, Directory 的 DefaultDropEffect DWORD）
    /// </summary>
    public bool SetDefaultDropEffect(int effect)
    {
        if (!OperatingSystem.IsWindows() || effect is not (0 or 1 or 2 or 4))
            return false;

        PrivilegedRollbackEngine.EnableAllSystemRollbackPrivileges();
        bool anyWritten = false;
        foreach (string subKey in DefaultDropEffectClassSubKeys)
        {
            bool ok = false;
            try
            {
                using var k = Registry.ClassesRoot.CreateSubKey(subKey, writable: true);
                if (k != null)
                {
                    k.SetValue("DefaultDropEffect", effect, RegistryValueKind.DWord);
                    ok = true;
                }
            }
            catch { }

            if (!ok)
            {
                try
                {
                    using var hkcuKey = Registry.CurrentUser.CreateSubKey($@"Software\Classes\{subKey}", writable: true);
                    if (hkcuKey != null)
                    {
                        hkcuKey.SetValue("DefaultDropEffect", effect, RegistryValueKind.DWord);
                        ok = true;
                    }
                }
                catch { }
            }

            if (ok) anyWritten = true;
        }
        return anyWritten;
    }

    // ================= 2. 打开方式：按文件扩展名检查注册来源（只读） =================

    /// <summary>
    /// 按扩展名只读检索 Windows "打开方式" 全链路注册来源（UserChoice、FileExts、HKCR、ProgID 与 Applications\SupportedTypes）
    /// </summary>
    public string InspectOpenWithRegistrationSources(string rawExtension, string? activeUserSid = null)
    {
        string ext = (rawExtension ?? string.Empty).Trim();
        if (string.IsNullOrEmpty(ext))
            return "请输入有效的文件扩展名（例如 .txt）。";
        if (!ext.StartsWith('.'))
            ext = "." + ext;

        if (!OperatingSystem.IsWindows())
            return $"[{ext}] 非 Windows 环境，无法读取注册表来源。";

        var lines = new List<string> { $"扩展名: {ext}" };
        var candidateProgIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        try
        {
            string fileExtsSub = $@"Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\{ext}";
            string userDisplay = string.IsNullOrEmpty(activeUserSid) ? "HKCU" : $@"HKU\{activeUserSid}";
            using var cuFileExts = !string.IsNullOrEmpty(activeUserSid)
                ? Registry.Users.OpenSubKey($@"{activeUserSid}\{fileExtsSub}", false)
                : Registry.CurrentUser.OpenSubKey(fileExtsSub, false);

            if (cuFileExts != null)
            {
                using var uc = cuFileExts.OpenSubKey("UserChoice", false);
                string ucProgId = uc?.GetValue("ProgId")?.ToString() ?? string.Empty;
                if (!string.IsNullOrEmpty(ucProgId))
                {
                    lines.Add($"• UserChoice 默认 ProgID: {ucProgId} ({userDisplay}\\{fileExtsSub}\\UserChoice)");
                    candidateProgIds.Add(ucProgId);
                }

                using var owl = cuFileExts.OpenSubKey("OpenWithList", false);
                if (owl != null)
                {
                    var items = owl.GetValueNames()
                        .Where(n => !n.Equals("MRUList", StringComparison.OrdinalIgnoreCase))
                        .Select(n => owl.GetValue(n)?.ToString())
                        .Where(v => !string.IsNullOrWhiteSpace(v))
                        .ToList();
                    if (items.Count > 0)
                        lines.Add($"• {userDisplay}\\FileExts\\OpenWithList: {string.Join(", ", items)}");
                }

                using var owp = cuFileExts.OpenSubKey("OpenWithProgids", false);
                if (owp != null)
                {
                    var progIds = owp.GetValueNames().Where(n => !string.IsNullOrWhiteSpace(n)).ToList();
                    if (progIds.Count > 0)
                    {
                        lines.Add($"• {userDisplay}\\FileExts\\OpenWithProgids: {string.Join(", ", progIds)}");
                        foreach (var p in progIds) candidateProgIds.Add(p);
                    }
                }
            }
        }
        catch { }

        try
        {
            using var crExt = Registry.ClassesRoot.OpenSubKey(ext, false);
            if (crExt != null)
            {
                string defProgId = crExt.GetValue(null)?.ToString() ?? string.Empty;
                string perceived = crExt.GetValue("PerceivedType")?.ToString() ?? string.Empty;
                if (!string.IsNullOrEmpty(defProgId))
                {
                    lines.Add($"• HKCR\\{ext} 默认 ProgID: {defProgId}");
                    candidateProgIds.Add(defProgId);
                }
                if (!string.IsNullOrEmpty(perceived))
                    lines.Add($"• HKCR\\{ext} PerceivedType: {perceived}");

                using var crOwl = crExt.OpenSubKey("OpenWithList", false);
                if (crOwl != null)
                {
                    var subApps = crOwl.GetSubKeyNames().ToList();
                    if (subApps.Count > 0)
                        lines.Add($"• HKCR\\{ext}\\OpenWithList 键: {string.Join(", ", subApps)}");
                }

                using var crOwp = crExt.OpenSubKey("OpenWithProgids", false);
                if (crOwp != null)
                {
                    var progIds = crOwp.GetValueNames().Where(n => !string.IsNullOrWhiteSpace(n)).ToList();
                    if (progIds.Count > 0)
                    {
                        lines.Add($"• HKCR\\{ext}\\OpenWithProgids: {string.Join(", ", progIds)}");
                        foreach (var p in progIds) candidateProgIds.Add(p);
                    }
                }
            }
        }
        catch { }

        foreach (string progId in candidateProgIds.OrderBy(p => p, StringComparer.OrdinalIgnoreCase))
        {
            try
            {
                using var pk = Registry.ClassesRoot.OpenSubKey($@"{progId}\shell\open\command", false);
                string cmd = pk?.GetValue(null)?.ToString() ?? string.Empty;
                if (!string.IsNullOrWhiteSpace(cmd))
                    lines.Add($"  ↳ ProgID [{progId}] (HKCR\\{progId}\\shell\\open\\command): {cmd}");
            }
            catch { }
        }

        // 检查 Applications\<exe>\SupportedTypes 显式声明此扩展名的注册项
        try
        {
            var matchedApps = new List<string>();
            using var appsKey = Registry.ClassesRoot.OpenSubKey("Applications", false);
            if (appsKey != null)
            {
                foreach (string appName in appsKey.GetSubKeyNames())
                {
                    using var appSub = appsKey.OpenSubKey(appName, false);
                    if (appSub == null) continue;
                    using var stKey = appSub.OpenSubKey("SupportedTypes", false);
                    if (stKey != null && stKey.GetValueNames().Any(v => v.Equals(ext, StringComparison.OrdinalIgnoreCase)))
                    {
                        bool noOpenWith = appSub.GetValue("NoOpenWith") != null;
                        matchedApps.Add(noOpenWith ? $"{appName} (已屏蔽 NoOpenWith)" : appName);
                    }
                }
            }
            if (matchedApps.Count > 0)
                lines.Add($"• Applications\\*\\SupportedTypes 匹配: {string.Join(", ", matchedApps)}");
        }
        catch { }

        if (lines.Count == 1)
            lines.Add("未检索到该扩展名在注册表中的公开 OpenWith / ProgID 注册记录。");

        return string.Join(Environment.NewLine, lines);
    }

    // ================= 3. GUID 锁 (Shell Extensions\Blocked) =================

    /// <summary>
    /// 扫描 HKLM 与 HKCU/HKU 的 Shell Extensions\Blocked 中被锁定的 CLSID
    /// </summary>
    public List<ContextMenuItemEntry> ScanGuidBlockedEntries(string? activeUserSid = null)
    {
        var results = new List<ContextMenuItemEntry>();
        if (!OperatingSystem.IsWindows())
            return results;

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void ScanHive(RegistryKey baseKey, string rootDisplayName, string subKey)
        {
            try
            {
                using var k = baseKey.OpenSubKey(subKey, false);
                if (k == null) return;
                foreach (string valName in k.GetValueNames())
                {
                    if (string.IsNullOrWhiteSpace(valName)) continue;
                    if (!Guid.TryParse(valName, out Guid g)) continue;
                    string normClsid = g.ToString("B").ToUpperInvariant();
                    if (!seen.Add(normClsid)) continue;

                    string title = ContextMenuGuidResolver.GetClsidText(normClsid);
                    if (string.IsNullOrWhiteSpace(title))
                        title = ResolveClsidFriendlyName(PrivilegedRollbackEngine.HKEY_LOCAL_MACHINE, normClsid, activeUserSid);
                    if (string.IsNullOrWhiteSpace(title))
                        title = normClsid;

                    string dll = ContextMenuGuidResolver.GetClsidFilePath(normClsid);
                    if (string.IsNullOrWhiteSpace(dll))
                        dll = ResolveClassicComInprocServer32(normClsid, activeUserSid);

                    string expandedDll = !string.IsNullOrWhiteSpace(dll)
                        ? Environment.ExpandEnvironmentVariables(dll).Trim('"')
                        : string.Empty;

                    results.Add(new ContextMenuItemEntry
                    {
                        IdKey = $"GuidBlocked:{normClsid}",
                        DisplayTitle = title,
                        MenuCategory = MonitorCategory.ClassicContextMenu,
                        ScopeScene = "Scene_GuidBlocked",
                        RegistryPath = $@"{rootDisplayName}\{subKey}::{normClsid}",
                        Clsid = normClsid,
                        TargetBinaryOrCommand = expandedDll,
                        IsEnabled = true // 在 Blocked 列表中的项即代表“当前锁定已生效”；关闭开关将移除锁定
                    });
                }
            }
            catch { }
        }

        using (var hklm64 = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
            ScanHive(hklm64, "HKLM", BlockedExtensionsSubKey);
        using (var hklm32 = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32))
            ScanHive(hklm32, "HKLM", BlockedExtensionsSubKey);
        ScanHive(Registry.CurrentUser, "HKCU", BlockedExtensionsSubKey);

        if (!string.IsNullOrEmpty(activeUserSid))
        {
            ScanHive(Registry.Users, $@"HKU\{activeUserSid}", $@"{activeUserSid}\{BlockedExtensionsSubKey}");
        }

        return results;
    }

    /// <summary>
    /// 向 Shell Extensions\Blocked 添加新 GUID 锁
    /// </summary>
    public bool AddGuidBlockedEntry(string rawGuid, string? activeUserSid = null)
    {
        if (!Guid.TryParse(rawGuid?.Trim(), out Guid parsed))
            return false;

        string normClsid = parsed.ToString("B").ToUpperInvariant();
        return SetWin11ModernMenuBlockedState(normClsid, blockItem: true, activeUserSid);
    }
}

internal static class IsolatedProbeRunner
{
    public static async Task<TargetProgramFeatures> RunAsync(
        string dllPath,
        string? probeHostExePath,
        int timeoutMs)
    {
        string normalizedPath = PathNormalizerAndSimilarity.NormalizeProgramPath(dllPath ?? string.Empty);
        ulong normHash = MmfBinaryStore.ComputeFnv1a64(normalizedPath);

        TargetProgramFeatures CreateFallbackFeatures(string stateNote) => new()
        {
            Category = MonitorCategory.ClassicContextMenu,
            TargetBinaryPath = dllPath ?? string.Empty,
            NormalizedPath = normalizedPath,
            NormalizedPathHash = normHash,
            RawCommandLine = dllPath ?? string.Empty,
            CommandLineArgsTemplate = string.Empty,
            LocationKeyOrIdentifier = dllPath ?? string.Empty,
            MD5Hex = string.Empty,
            SHA256Hex = string.Empty,
            OldStateSummary = stateNote,
            NewStateSummary = stateNote
        };

        if (string.IsNullOrWhiteSpace(dllPath) || !File.Exists(dllPath))
            return CreateFallbackFeatures("FileNotFound");

        var (fileName, arguments) = ResolveProbeProcessInvocation(dllPath, probeHostExePath);
        if (string.IsNullOrEmpty(fileName))
            return CreateFallbackFeatures("ProbeHostNotFound");

        using var proc = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments,
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = Encoding.UTF8
            }
        };

        try
        {
            if (!proc.Start())
                return CreateFallbackFeatures("ProcessStartFailed");

            using var cts = new CancellationTokenSource(Math.Max(100, timeoutMs));
            Task<string> stdoutTask = proc.StandardOutput.ReadToEndAsync(cts.Token);

            try
            {
                await proc.WaitForExitAsync(cts.Token);
            }
            catch (OperationCanceledException)
            {
                try { proc.Kill(entireProcessTree: true); } catch { }
                return CreateFallbackFeatures("ProbeTimeoutKilled");
            }

            if (proc.ExitCode != 0)
            {
                return CreateFallbackFeatures($"ProbeExitedWithCode:{proc.ExitCode}");
            }

            string stdout = (await stdoutTask).Trim();
            if (string.IsNullOrEmpty(stdout))
                return CreateFallbackFeatures("EmptyProbeOutput");

            string firstLine = stdout.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries)[0];
            string[] parts = firstLine.Split('\t');
            if (parts.Length < 12)
                return CreateFallbackFeatures("MalformedProbeOutput");

            string md5 = parts[0].Trim();
            string sha256 = parts[1].Trim();
            bool hasValidSig = parts[2].Trim() is "1" or "true" or "True";
            string signerSubject = parts[3].Trim();
            string rootCertThumbprint = parts[4].Trim();
            string origName = parts[5].Trim();
            string prodName = parts[6].Trim();
            string compName = parts[7].Trim();
            string intName = parts[8].Trim();
            string desc = parts[9].Trim();
            string impHash = parts[10].Trim();
            ulong.TryParse(parts[11].Trim(), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out ulong iconPHash);

            return new TargetProgramFeatures
            {
                Category = MonitorCategory.ClassicContextMenu,
                TargetBinaryPath = dllPath,
                NormalizedPath = normalizedPath,
                NormalizedPathHash = normHash,
                RawCommandLine = dllPath,
                CommandLineArgsTemplate = string.Empty,
                LocationKeyOrIdentifier = dllPath,
                MD5Hex = md5,
                SHA256Hex = sha256,
                HasValidSignature = hasValidSig,
                SignerSubject = signerSubject,
                RootCertThumbprint = rootCertThumbprint,
                OriginalFilename = !string.IsNullOrEmpty(origName) ? origName : Path.GetFileName(dllPath),
                ProductName = !string.IsNullOrEmpty(prodName) ? prodName : Path.GetFileNameWithoutExtension(dllPath),
                CompanyName = compName,
                InternalName = intName,
                FileDescription = desc,
                ImpHash = impHash,
                IconPerceptualHash = iconPHash,
                OldStateSummary = "IsolatedProbeSuccess",
                NewStateSummary = "IsolatedProbeSuccess"
            };
        }
        catch
        {
            try
            {
                if (!proc.HasExited)
                    proc.Kill(entireProcessTree: true);
            }
            catch
            {
            }
            return CreateFallbackFeatures("ProbeCrashedOrFailed");
        }
    }

    public static async Task<List<ResolvedMenuItemInfo>> AnalyzeMenuAsync(
        string clsid,
        string scopeScene,
        string? probeHostExePath,
        int timeoutMs)
    {
        var result = new List<ResolvedMenuItemInfo>();
        if (string.IsNullOrWhiteSpace(clsid))
            return result;

        var (fileName, baseArgs) = ResolveProbeProcessInvocation(clsid, probeHostExePath);
        if (string.IsNullOrEmpty(fileName))
            return result;

        string safeScene = (scopeScene ?? string.Empty).Replace("\"", "");
        string args = baseArgs.StartsWith('"') && baseArgs.Contains(".dll\"", StringComparison.OrdinalIgnoreCase)
            ? baseArgs.Replace($"\"{clsid}\"", $"--analyze-menu \"{clsid}\" \"{safeScene}\"")
            : $"--analyze-menu \"{clsid}\" \"{safeScene}\"";

        using var proc = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = args,
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = Encoding.UTF8
            }
        };

        try
        {
            if (!proc.Start()) return result;
            using var cts = new CancellationTokenSource(Math.Max(500, timeoutMs));
            Task<string> stdoutTask = proc.StandardOutput.ReadToEndAsync(cts.Token);
            try { await proc.WaitForExitAsync(cts.Token); }
            catch (OperationCanceledException)
            {
                try { proc.Kill(entireProcessTree: true); } catch { }
                return result;
            }

            if (proc.ExitCode != 0) return result;
            string stdout = (await stdoutTask).Trim();
            if (string.IsNullOrEmpty(stdout)) return result;

            using var doc = JsonDocument.Parse(stdout);
            if (doc.RootElement.ValueKind == JsonValueKind.Array)
            {
                foreach (var el in doc.RootElement.EnumerateArray())
                {
                    result.Add(new ResolvedMenuItemInfo
                    {
                        Text = el.TryGetProperty("Text", out var t) ? t.GetString() ?? string.Empty : string.Empty,
                        Verb = el.TryGetProperty("Verb", out var v) ? v.GetString() ?? string.Empty : string.Empty,
                        HelpText = el.TryGetProperty("HelpText", out var h) ? h.GetString() ?? string.Empty : string.Empty,
                        IsSeparator = el.TryGetProperty("IsSeparator", out var s) && s.GetBoolean(),
                        Depth = el.TryGetProperty("Depth", out var d) ? d.GetInt32() : 0,
                        HasSubMenu = el.TryGetProperty("HasSubMenu", out var sm) && sm.GetBoolean()
                    });
                }
            }
        }
        catch { }
        return result;
    }

    private static (string FileName, string Arguments) ResolveProbeProcessInvocation(string dllPath, string? probeHostExePath)
    {
        string candidate = probeHostExePath ?? string.Empty;
        if (string.IsNullOrWhiteSpace(candidate))
        {
            candidate = LocateBuiltProbeHost();
        }

        if (string.IsNullOrWhiteSpace(candidate))
            return (string.Empty, string.Empty);

        if (!OperatingSystem.IsWindows())
        {
            if (candidate.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) && File.Exists(candidate))
            {
                return (ResolveDotnetHostPath(), $"\"{candidate}\" \"{dllPath}\"");
            }

            if (candidate.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            {
                string dllSibling = Path.ChangeExtension(candidate, ".dll");
                if (File.Exists(dllSibling))
                {
                    return (ResolveDotnetHostPath(), $"\"{dllSibling}\" \"{dllPath}\"");
                }
            }
        }

        if (candidate.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
        {
            return (ResolveDotnetHostPath(), $"\"{candidate}\" \"{dllPath}\"");
        }

        return (candidate, $"\"{dllPath}\"");
    }

    private static string ResolveDotnetHostPath()
    {
        if (!string.IsNullOrEmpty(Environment.ProcessPath) &&
            Environment.ProcessPath.EndsWith("dotnet", StringComparison.OrdinalIgnoreCase) &&
            File.Exists(Environment.ProcessPath))
        {
            return Environment.ProcessPath;
        }

        const string localDotnet = "/home/antigravity/.dotnet/dotnet";
        if (File.Exists(localDotnet))
            return localDotnet;

        return "dotnet";
    }

    private static string LocateBuiltProbeHost()
    {
        string baseDir = AppContext.BaseDirectory;
        string[] directCandidates =
        [
            Path.Combine(baseDir, "StartupGuard.ProbeHost.exe"),
            Path.Combine(baseDir, "StartupGuard.ProbeHost.dll"),
            Path.Combine(baseDir, "StartupGuard.ProbeHost")
        ];

        foreach (string c in directCandidates)
        {
            if (File.Exists(c))
                return c;
        }

        string? cur = baseDir;
        for (int depth = 0; depth < 6 && !string.IsNullOrEmpty(cur); depth++)
        {
            string probeBin = Path.Combine(cur, "src", "StartupGuard.ProbeHost", "bin");
            if (Directory.Exists(probeBin))
            {
                var dllFiles = Directory.GetFiles(probeBin, "StartupGuard.ProbeHost.dll", SearchOption.AllDirectories);
                if (dllFiles.Length > 0)
                    return dllFiles[0];

                var exeFiles = Directory.GetFiles(probeBin, "StartupGuard.ProbeHost.exe", SearchOption.AllDirectories);
                if (exeFiles.Length > 0)
                    return exeFiles[0];
            }
            cur = Path.GetDirectoryName(cur);
        }

        return string.Empty;
    }
}

