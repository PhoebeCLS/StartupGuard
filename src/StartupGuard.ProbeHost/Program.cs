using System.Runtime.InteropServices;
using System.Text;
using StartupGuard.Core.Native;

namespace StartupGuard.ProbeHost;

/// <summary>
/// 独立沙盒探针进程 (StartupGuard.ProbeHost.exe)
/// 1. 默认模式 (<dllPath>): 提取 PE 版本、数字签名、ImpHash、图标 pHash 并输出 12 字段制表符结果。
/// 2. 菜单解析模式 (--analyze-menu <clsid> [scene]): 在 STA 沙盒中安全实例化 Shell Extension COM 组件，
///    调用 IShellExtInit / IContextMenu::QueryContextMenu 提取运行时菜单树（文本、Verb、分隔符、子菜单）。
/// </summary>
public static unsafe partial class Program
{
    private const uint CLSCTX_INPROC_SERVER = 0x1;
    private const uint CLSCTX_LOCAL_SERVER = 0x4;
    private const uint MIIM_STATE = 0x00000001;
    private const uint MIIM_ID = 0x00000002;
    private const uint MIIM_SUBMENU = 0x00000004;
    private const uint MIIM_FTYPE = 0x00000100;
    private const uint MIIM_STRING = 0x00000040;
    private const uint MFT_SEPARATOR = 0x00000800;
    private const uint GCS_HELPTEXTW = 0x00000005;
    private const uint GCS_VERBW = 0x00000004;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct MENUITEMINFOW
    {
        public uint cbSize;
        public uint fMask;
        public uint fType;
        public uint fState;
        public uint wID;
        public nint hSubMenu;
        public nint hbmpChecked;
        public nint hbmpUnchecked;
        public nuint dwItemData;
        public char* dwTypeData;
        public uint cch;
        public nint hbmpItem;
    }

    [LibraryImport("ole32.dll")]
    private static partial int OleInitialize(nint pvReserved);

    [LibraryImport("ole32.dll")]
    private static partial void OleUninitialize();

    [LibraryImport("ole32.dll")]
    private static partial int CoCreateInstance(
        ref Guid rclsid,
        nint pUnkOuter,
        uint dwClsContext,
        ref Guid riid,
        out nint ppv);

    [LibraryImport("shell32.dll", StringMarshalling = StringMarshalling.Utf16)]
    private static partial int SHParseDisplayName(string pszName, nint pbc, out nint ppidl, uint sfgaoIn, out uint psfgaoOut);

    [LibraryImport("shell32.dll")]
    private static partial void ILFree(nint pidl);

    [LibraryImport("shell32.dll")]
    private static partial int SHCreateDataObject(
        nint pidlFolder,
        uint cidl,
        nint* apidl,
        nint pdtInner,
        ref Guid riid,
        out nint ppv);

    [LibraryImport("user32.dll")]
    private static partial nint CreatePopupMenu();

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool DestroyMenu(nint hMenu);

    [LibraryImport("user32.dll")]
    private static partial int GetMenuItemCount(nint hMenu);

    [LibraryImport("user32.dll", EntryPoint = "GetMenuItemInfoW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetMenuItemInfoW(nint hMenu, uint item, [MarshalAs(UnmanagedType.Bool)] bool fByPosition, ref MENUITEMINFOW lpmii);

    [LibraryImport("advapi32.dll", EntryPoint = "RegOpenKeyExW", StringMarshalling = StringMarshalling.Utf16)]
    private static partial int RegOpenKeyExW(nint hKey, string lpSubKey, uint ulOptions, uint samDesired, out nint phkResult);

    [LibraryImport("advapi32.dll")]
    private static partial int RegCloseKey(nint hKey);

    public static int Main(string[] args)
    {
        if (args.Length >= 2 && string.Equals(args[0], "--analyze-menu", StringComparison.OrdinalIgnoreCase))
        {
            string clsidStr = args[1];
            string scene = args.Length >= 3 ? args[2] : string.Empty;
            return RunAnalyzeMenuSta(clsidStr, scene);
        }

        if (args.Length == 0 || string.IsNullOrWhiteSpace(args[0]) || !File.Exists(args[0]))
            return 1;

        string targetDllPath = args[0];
        try
        {
            var (md5, sha256) = NativeSecurityExtractor.ComputeFileHashesCng(targetDllPath);
            var (hasValidSig, signerSubject, rootCertThumbprint) = NativeSecurityExtractor.ExtractAuthenticodeDetails(targetDllPath);
            var (origName, prodName, compName, intName, desc) = NativeSecurityExtractor.ExtractPeVersionMetadata(targetDllPath);
            var (impHash, iconPHash) = NativeSecurityExtractor.ExtractPeImportAndIconHashes(targetDllPath);

            Console.Out.WriteLine(
                $"{CleanField(md5)}\t{CleanField(sha256)}\t{(hasValidSig ? 1 : 0)}\t{CleanField(signerSubject)}\t{CleanField(rootCertThumbprint)}\t" +
                $"{CleanField(origName)}\t{CleanField(prodName)}\t{CleanField(compName)}\t{CleanField(intName)}\t{CleanField(desc)}\t" +
                $"{CleanField(impHash)}\t{iconPHash:x16}");
            Console.Out.Flush();
            return 0;
        }
        catch
        {
            return 2;
        }
    }

    private static int RunAnalyzeMenuSta(string clsidStr, string scene)
    {
        if (!OperatingSystem.IsWindows() || !Guid.TryParse(clsidStr.Trim(), out Guid clsid))
        {
            Console.Out.WriteLine("[]");
            return 0;
        }

        string jsonOut = "[]";
        var sta = new Thread(() =>
        {
            jsonOut = AnalyzeComContextMenuInternal(clsid, scene);
        });
        sta.SetApartmentState(ApartmentState.STA);
        sta.Start();
        sta.Join(2800);

        Console.Out.WriteLine(jsonOut);
        Console.Out.Flush();
        return 0;
    }

    private static string AnalyzeComContextMenuInternal(Guid clsid, string scene)
    {
        var items = new List<(string Text, string Verb, string HelpText, bool IsSeparator, int Depth, bool HasSubMenu)>();
        bool oleInit = OleInitialize(0) >= 0;
        nint pContextMenu = 0;
        nint pShellExtInit = 0;
        nint pDataObj = 0;
        nint pidl = 0;
        nint hRegKey = 0;
        nint hMenu = 0;

        try
        {
            Guid iidContextMenu = new("000214E4-0000-0000-C000-000000000046");
            int hr = CoCreateInstance(ref clsid, 0, CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER, ref iidContextMenu, out pContextMenu);
            if (hr != 0 || pContextMenu == 0)
                return "[]";

            // 获取 IShellExtInit 并用真实对象初始化
            Guid iidShellExtInit = new("000214E8-0000-0000-C000-000000000046");
            var unkVtbl = *(nint**)pContextMenu;
            var queryInterface = (delegate* unmanaged[Stdcall]<nint, Guid*, nint*, int>)unkVtbl[0];
            if (queryInterface(pContextMenu, &iidShellExtInit, &pShellExtInit) == 0 && pShellExtInit != 0)
            {
                bool isDirOrBg = scene.Contains("Directory", StringComparison.OrdinalIgnoreCase) ||
                                 scene.Contains("Folder", StringComparison.OrdinalIgnoreCase) ||
                                 scene.Contains("Background", StringComparison.OrdinalIgnoreCase) ||
                                 scene.Contains("Drive", StringComparison.OrdinalIgnoreCase);

                string samplePath = isDirOrBg
                    ? Environment.GetFolderPath(Environment.SpecialFolder.Windows)
                    : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "notepad.exe");

                if (SHParseDisplayName(samplePath, 0, out pidl, 0, out _) == 0 && pidl != 0)
                {
                    Guid iidDataObject = new("0000010E-0000-0000-C000-000000000046");
                    nint pidlLocal = pidl;
                    if (SHCreateDataObject(0, 1, &pidlLocal, 0, ref iidDataObject, out pDataObj) != 0)
                        pDataObj = 0;
                }

                nint HKEY_CLASSES_ROOT = new(unchecked((int)0x80000000));
                string progIdSubKey = isDirOrBg ? "Directory" : "*";
                RegOpenKeyExW(HKEY_CLASSES_ROOT, progIdSubKey, 0, 0x20019, out hRegKey);

                var initVtbl = *(nint**)pShellExtInit;
                var initialize = (delegate* unmanaged[Stdcall]<nint, nint, nint, nint, int>)initVtbl[3];
                initialize(pShellExtInit, isDirOrBg ? pidl : 0, pDataObj, hRegKey);
            }

            hMenu = CreatePopupMenu();
            if (hMenu == 0)
                return "[]";

            var cmVtbl = *(nint**)pContextMenu;
            var queryContextMenu = (delegate* unmanaged[Stdcall]<nint, nint, uint, uint, uint, uint, int>)cmVtbl[3];
            const uint idCmdFirst = 1;
            const uint idCmdLast = 0x7FFF;
            int qhr = queryContextMenu(pContextMenu, hMenu, 0, idCmdFirst, idCmdLast, 0);
            if (qhr < 0)
                return "[]";

            ExtractMenuItemsRecursive(pContextMenu, cmVtbl, hMenu, idCmdFirst, 0, items);
        }
        catch
        {
            // 沙盒内安全吸收异常
        }
        finally
        {
            if (hMenu != 0) DestroyMenu(hMenu);
            if (hRegKey != 0) RegCloseKey(hRegKey);
            if (pidl != 0) ILFree(pidl);
            if (pDataObj != 0) ReleaseCom(pDataObj);
            if (pShellExtInit != 0) ReleaseCom(pShellExtInit);
            if (pContextMenu != 0) ReleaseCom(pContextMenu);
            if (oleInit) OleUninitialize();
        }

        return SerializeMenuItemsJson(items);
    }

    private static void ExtractMenuItemsRecursive(
        nint pContextMenu,
        nint* cmVtbl,
        nint hMenu,
        uint idCmdFirst,
        int depth,
        List<(string Text, string Verb, string HelpText, bool IsSeparator, int Depth, bool HasSubMenu)> output)
    {
        if (depth > 4) return;
        int count = GetMenuItemCount(hMenu);
        if (count <= 0 || count > 100) return;

        var getCommandString = (delegate* unmanaged[Stdcall]<nint, nuint, uint, uint*, nint, uint, int>)cmVtbl[5];
        char* textBuf = stackalloc char[512];
        char* cmdBuf = stackalloc char[256];

        for (uint i = 0; i < (uint)count; i++)
        {
            var mii = new MENUITEMINFOW
            {
                cbSize = (uint)Marshal.SizeOf<MENUITEMINFOW>(),
                fMask = MIIM_FTYPE | MIIM_ID | MIIM_SUBMENU | MIIM_STRING | MIIM_STATE,
                dwTypeData = textBuf,
                cch = 511
            };

            if (!GetMenuItemInfoW(hMenu, i, true, ref mii))
                continue;

            bool isSep = (mii.fType & MFT_SEPARATOR) != 0;
            if (isSep)
            {
                output.Add(("(分隔符)", string.Empty, string.Empty, true, depth, false));
                continue;
            }

            string text = mii.cch > 0 ? new string(textBuf, 0, (int)Math.Min(mii.cch, 511)).Trim() : string.Empty;
            string verb = string.Empty;
            string help = string.Empty;

            if (mii.wID >= idCmdFirst && mii.wID < 0x7FFF)
            {
                nuint offset = mii.wID - idCmdFirst;
                cmdBuf[0] = '\0';
                if (getCommandString(pContextMenu, offset, GCS_VERBW, null, (nint)cmdBuf, 255) == 0)
                {
                    verb = new string(cmdBuf).TrimEnd('\0').Trim();
                }

                cmdBuf[0] = '\0';
                if (getCommandString(pContextMenu, offset, GCS_HELPTEXTW, null, (nint)cmdBuf, 255) == 0)
                {
                    help = new string(cmdBuf).TrimEnd('\0').Trim();
                }
            }

            bool hasSub = mii.hSubMenu != 0;
            if (string.IsNullOrEmpty(text))
                text = !string.IsNullOrEmpty(verb) ? verb : "(自绘菜单项)";

            output.Add((text, verb, help, false, depth, hasSub));
            if (hasSub)
            {
                ExtractMenuItemsRecursive(pContextMenu, cmVtbl, mii.hSubMenu, idCmdFirst, depth + 1, output);
            }
        }
    }

    private static void ReleaseCom(nint pUnk)
    {
        try
        {
            var vtbl = *(nint**)pUnk;
            var release = (delegate* unmanaged[Stdcall]<nint, uint>)vtbl[2];
            release(pUnk);
        }
        catch { }
    }

    private static string SerializeMenuItemsJson(List<(string Text, string Verb, string HelpText, bool IsSeparator, int Depth, bool HasSubMenu)> items)
    {
        var sb = new StringBuilder("[");
        for (int i = 0; i < items.Count; i++)
        {
            var it = items[i];
            if (i > 0) sb.Append(',');
            sb.Append("{\"Text\":\"").Append(EscapeJson(it.Text)).Append('"')
              .Append(",\"Verb\":\"").Append(EscapeJson(it.Verb)).Append('"')
              .Append(",\"HelpText\":\"").Append(EscapeJson(it.HelpText)).Append('"')
              .Append(",\"IsSeparator\":").Append(it.IsSeparator ? "true" : "false")
              .Append(",\"Depth\":").Append(it.Depth)
              .Append(",\"HasSubMenu\":").Append(it.HasSubMenu ? "true" : "false")
              .Append('}');
        }
        sb.Append(']');
        return sb.ToString();
    }

    private static string EscapeJson(string s)
    {
        if (string.IsNullOrEmpty(s)) return string.Empty;
        return s.Replace("\\", "\\\\")
                .Replace("\"", "\\\"")
                .Replace("\r", "\\r")
                .Replace("\n", "\\n")
                .Replace("\t", "\\t");
    }

    private static string CleanField(string? value)
    {
        if (string.IsNullOrEmpty(value))
            return string.Empty;
        return value.Replace('\t', ' ').Replace('\r', ' ').Replace('\n', ' ').Trim();
    }
}
