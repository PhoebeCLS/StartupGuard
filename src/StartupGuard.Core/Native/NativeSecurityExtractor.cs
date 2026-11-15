using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using StartupGuard.Core.Models;
using StartupGuard.Core.Scoring;
using StartupGuard.Core.Storage;

namespace StartupGuard.Core.Native;

/// <summary>
/// Windows 11 原生 CNG (bcrypt.dll) 硬件加速哈希、WinVerifyTrust/Crypt32 数字签名提取、
/// 以及 PE 导入表 ImpHash / 图标感知哈希 pHash / 版本资源提取引擎
/// (完全兼容 NativeAOT 及 Linux 跨平台测试回退)
/// </summary>
public static unsafe partial class NativeSecurityExtractor
{
    private const string BcryptDll = "bcrypt.dll";
    private const string WintrustDll = "wintrust.dll";
    private const string Crypt32Dll = "crypt32.dll";
    private const string VersionDll = "version.dll";

    [LibraryImport(BcryptDll, StringMarshalling = StringMarshalling.Utf16)]
    private static partial int BCryptOpenAlgorithmProvider(
        out nint phAlgorithm,
        string pszAlgId,
        string? pszImplementation,
        uint dwFlags);

    [LibraryImport(BcryptDll)]
    private static partial int BCryptCreateHash(
        nint hAlgorithm,
        out nint phHash,
        nint pbHashObject,
        uint cbHashObject,
        nint pbSecret,
        uint cbSecret,
        uint dwFlags);

    [LibraryImport(BcryptDll)]
    private static partial int BCryptHashData(
        nint hHash,
        byte* pbInput,
        uint cbInput,
        uint dwFlags);

    [LibraryImport(BcryptDll)]
    private static partial int BCryptFinishHash(
        nint hHash,
        byte* pbOutput,
        uint cbOutput,
        uint dwFlags);

    [LibraryImport(BcryptDll)]
    private static partial int BCryptDestroyHash(nint hHash);

    [LibraryImport(BcryptDll)]
    private static partial int BCryptCloseAlgorithmProvider(nint hAlgorithm, uint dwFlags);

    [LibraryImport(WintrustDll)]
    private static partial uint WinVerifyTrust(
        nint hwnd,
        Guid* pgActionID,
        void* pWVTData);

    [LibraryImport(Crypt32Dll, EntryPoint = "CryptQueryObject", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CryptQueryObject(
        uint dwObjectType,
        string pvObject,
        uint dwExpectedContentTypeFlags,
        uint dwExpectedFormatTypeFlags,
        uint dwFlags,
        out uint pdwMsgAndCertEncodingType,
        out uint pdwContentType,
        out uint pdwFormatType,
        out nint phCertStore,
        out nint phMsg,
        out nint ppvContext);

    [LibraryImport(Crypt32Dll)]
    private static partial nint CertEnumCertificatesInStore(nint hCertStore, nint pPrevCertContext);

    [LibraryImport(Crypt32Dll, EntryPoint = "CertGetNameStringW", StringMarshalling = StringMarshalling.Utf16)]
    private static partial uint CertGetNameStringW(
        nint pCertContext,
        uint dwType,
        uint dwFlags,
        void* pvTypePara,
        char* pszNameString,
        uint cchNameString);

    [LibraryImport(Crypt32Dll)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CertGetCertificateContextProperty(
        nint pCertContext,
        uint dwPropId,
        byte* pvData,
        ref uint pcbData);

    [LibraryImport(Crypt32Dll)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CertFreeCertificateContext(nint pCertContext);

    [LibraryImport(Crypt32Dll)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CertCloseStore(nint hCertStore, uint dwFlags);

    [LibraryImport(Crypt32Dll)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CryptMsgClose(nint hCryptMsg);

    [LibraryImport(VersionDll, EntryPoint = "GetFileVersionInfoSizeW", StringMarshalling = StringMarshalling.Utf16)]
    private static partial uint GetFileVersionInfoSizeW(string lptstrFilename, out uint lpdwHandle);

    [LibraryImport(VersionDll, EntryPoint = "GetFileVersionInfoW", StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetFileVersionInfoW(string lptstrFilename, uint dwHandle, uint dwLen, byte* lpData);

    [LibraryImport(VersionDll, EntryPoint = "VerQueryValueW", StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool VerQueryValueW(byte* pBlock, string lpSubBlock, out nint lplpBuffer, out uint puLen);

    // WINTRUST_ACTION_GENERIC_VERIFY_V2
    private static readonly Guid ActionGenericVerifyV2 = new(0x00AAC56B, 0xCD44, 0x11d0, 0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE);

    private const uint CERT_QUERY_OBJECT_FILE = 0x00000001;
    private const uint CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED = 1u << 10;
    private const uint CERT_QUERY_FORMAT_FLAG_BINARY = 1u << 1;
    private const uint CERT_NAME_SIMPLE_DISPLAY_TYPE = 4;
    private const uint CERT_NAME_ISSUER_FLAG = 0x1;
    private const uint CERT_SHA1_HASH_PROP_ID = 3;

    /// <summary>
    /// 使用 Windows CNG (bcrypt.dll) 计算目标文件的 MD5 与 SHA256；
    /// 非 Windows 环境或 CNG 不可用时自动回退至 System.Security.Cryptography
    /// </summary>
    public static (string Md5Hex, string Sha256Hex) ComputeFileHashesCng(string filePath)
    {
        if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
            return (string.Empty, string.Empty);

        if (OperatingSystem.IsWindows())
        {
            nint hAlgMd5 = 0, hAlgSha256 = 0;
            nint hHashMd5 = 0, hHashSha256 = 0;

            try
            {
                if (BCryptOpenAlgorithmProvider(out hAlgMd5, "MD5", null, 0) == 0 &&
                    BCryptOpenAlgorithmProvider(out hAlgSha256, "SHA256", null, 0) == 0 &&
                    BCryptCreateHash(hAlgMd5, out hHashMd5, 0, 0, 0, 0, 0) == 0 &&
                    BCryptCreateHash(hAlgSha256, out hHashSha256, 0, 0, 0, 0, 0) == 0)
                {
                    byte* buffer = stackalloc byte[16384];
                    Span<byte> bufSpan = new(buffer, 16384);

                    using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 16384, FileOptions.SequentialScan))
                    {
                        int bytesRead;
                        while ((bytesRead = fs.Read(bufSpan)) > 0)
                        {
                            BCryptHashData(hHashMd5, buffer, (uint)bytesRead, 0);
                            BCryptHashData(hHashSha256, buffer, (uint)bytesRead, 0);
                        }
                    }

                    byte* md5Out = stackalloc byte[16];
                    byte* shaOut = stackalloc byte[32];
                    if (BCryptFinishHash(hHashMd5, md5Out, 16, 0) == 0 &&
                        BCryptFinishHash(hHashSha256, shaOut, 32, 0) == 0)
                    {
                        string md5Hex = Convert.ToHexStringLower(new ReadOnlySpan<byte>(md5Out, 16));
                        string sha256Hex = Convert.ToHexStringLower(new ReadOnlySpan<byte>(shaOut, 32));
                        return (md5Hex, sha256Hex);
                    }
                }
            }
            catch
            {
                // Fall through to managed implementation
            }
            finally
            {
                if (hHashMd5 != 0) BCryptDestroyHash(hHashMd5);
                if (hHashSha256 != 0) BCryptDestroyHash(hHashSha256);
                if (hAlgMd5 != 0) BCryptCloseAlgorithmProvider(hAlgMd5, 0);
                if (hAlgSha256 != 0) BCryptCloseAlgorithmProvider(hAlgSha256, 0);
            }
        }

        return ComputeFileHashesManagedFallback(filePath);
    }

    private static (string Md5Hex, string Sha256Hex) ComputeFileHashesManagedFallback(string filePath)
    {
        try
        {
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 16384, FileOptions.SequentialScan);
            using var md5 = IncrementalHash.CreateHash(HashAlgorithmName.MD5);
            using var sha256 = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

            Span<byte> buffer = stackalloc byte[16384];
            int bytesRead;
            while ((bytesRead = fs.Read(buffer)) > 0)
            {
                ReadOnlySpan<byte> chunk = buffer[..bytesRead];
                md5.AppendData(chunk);
                sha256.AppendData(chunk);
            }

            Span<byte> md5Bytes = stackalloc byte[16];
            Span<byte> shaBytes = stackalloc byte[32];
            md5.GetHashAndReset(md5Bytes);
            sha256.GetHashAndReset(shaBytes);

            return (Convert.ToHexStringLower(md5Bytes), Convert.ToHexStringLower(shaBytes));
        }
        catch
        {
            return (string.Empty, string.Empty);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        public char* pcwszFilePath;
        public nint hFile;
        public nint pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public nint pPolicyCallbackData;
        public nint pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public void* pFile;
        public uint dwStateAction;
        public nint hWVTStateData;
        public nint pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public nint pSignatureSettings;
    }

    /// <summary>
    /// 调用原生 WinVerifyTrust 验证 Authenticode 数字签名状态 (WTD_UI_NONE = 2, WTD_REVOKE_NONE = 0)
    /// </summary>
    public static bool VerifyAuthenticodeSignature(string filePath)
    {
        if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
            return false;

        if (OperatingSystem.IsWindows())
        {
            try
            {
                fixed (char* pPath = filePath)
                {
                    WINTRUST_FILE_INFO fileInfo = new()
                    {
                        cbStruct = (uint)sizeof(WINTRUST_FILE_INFO),
                        pcwszFilePath = pPath,
                        hFile = 0,
                        pgKnownSubject = 0
                    };

                    WINTRUST_DATA wvtData = new()
                    {
                        cbStruct = (uint)sizeof(WINTRUST_DATA),
                        dwUIChoice = 2,          // WTD_UI_NONE
                        fdwRevocationChecks = 0, // WTD_REVOKE_NONE (仅本地证书链校验，避免网络阻塞)
                        dwUnionChoice = 1,       // WTD_CHOICE_FILE
                        pFile = &fileInfo,
                        dwStateAction = 0,       // WTD_STATEACTION_IGNORE
                        dwProvFlags = 0x00000010 // WTD_CACHE_ONLY_URL_RETRIEVAL
                    };

                    Guid action = ActionGenericVerifyV2;
                    uint result = WinVerifyTrust(new nint(-1), &action, &wvtData);
                    if (result == 0)
                        return true;
                }
            }
            catch
            {
                // Fall back to embedded PE Security Directory inspection
            }
        }

        return TryExtractPeSecurityDirectoryCert(filePath, out bool hasValidEmbedded, out _, out _) && hasValidEmbedded;
    }

    /// <summary>
    /// 提取目标 PE 文件的 Authenticode 数字签名状态、签名者名称 (CN/O) 与根证书指纹
    /// </summary>
    public static (bool HasValidSignature, string SignerSubject, string RootCertThumbprint)
        ExtractAuthenticodeDetails(string filePath)
    {
        if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
            return (false, string.Empty, string.Empty);

        bool winTrustValid = false;
        if (OperatingSystem.IsWindows())
        {
            winTrustValid = VerifyAuthenticodeSignature(filePath);
            if (TryExtractAuthenticodeViaCrypt32(filePath, out string cryptSubject, out string cryptRootThumb))
            {
                return (winTrustValid || !string.IsNullOrEmpty(cryptSubject), cryptSubject, cryptRootThumb);
            }
        }

        if (TryExtractPeSecurityDirectoryCert(filePath, out bool embeddedValid, out string subject, out string rootThumbprint))
        {
            return (winTrustValid || embeddedValid, subject, rootThumbprint);
        }

        return (winTrustValid, string.Empty, string.Empty);
    }

    private static bool TryExtractAuthenticodeViaCrypt32(string filePath, out string signerSubject, out string rootThumbprint)
    {
        signerSubject = string.Empty;
        rootThumbprint = string.Empty;

        nint hCertStore = 0;
        nint hMsg = 0;
        try
        {
            if (!CryptQueryObject(
                CERT_QUERY_OBJECT_FILE,
                filePath,
                CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                CERT_QUERY_FORMAT_FLAG_BINARY,
                0,
                out _,
                out _,
                out _,
                out hCertStore,
                out hMsg,
                out _) || hCertStore == 0)
            {
                return false;
            }

            nint pCert = 0;
            char* nameBuf = stackalloc char[256];
            byte* hashBuf = stackalloc byte[32];

            while ((pCert = CertEnumCertificatesInStore(hCertStore, pCert)) != 0)
            {
                uint subjectLen = CertGetNameStringW(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, null, nameBuf, 256);
                string subj = subjectLen > 1 ? new string(nameBuf, 0, (int)subjectLen - 1) : string.Empty;

                uint issuerLen = CertGetNameStringW(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, null, nameBuf, 256);
                string issuer = issuerLen > 1 ? new string(nameBuf, 0, (int)issuerLen - 1) : string.Empty;

                uint hashLen = 32;
                string thumb = string.Empty;
                if (CertGetCertificateContextProperty(pCert, CERT_SHA1_HASH_PROP_ID, hashBuf, ref hashLen) && hashLen > 0)
                {
                    thumb = Convert.ToHexStringLower(new ReadOnlySpan<byte>(hashBuf, (int)hashLen));
                }

                if (string.IsNullOrEmpty(signerSubject) && !string.IsNullOrEmpty(subj))
                {
                    signerSubject = subj;
                }

                if (!string.IsNullOrEmpty(thumb) &&
                    (string.IsNullOrEmpty(rootThumbprint) || string.Equals(subj, issuer, StringComparison.OrdinalIgnoreCase)))
                {
                    rootThumbprint = thumb;
                }
            }

            return !string.IsNullOrEmpty(signerSubject);
        }
        catch
        {
            return false;
        }
        finally
        {
            if (hCertStore != 0) CertCloseStore(hCertStore, 0);
            if (hMsg != 0) CryptMsgClose(hMsg);
        }
    }

    /// <summary>
    /// 纯 C# 解析 PE Security Directory (IMAGE_DIRECTORY_ENTRY_SECURITY, index 4) 中的 WIN_CERTIFICATE / PKCS#7 / X.509 证书
    /// </summary>
    private static bool TryExtractPeSecurityDirectoryCert(
        string filePath,
        out bool hasValidSignature,
        out string signerSubject,
        out string rootThumbprint)
    {
        hasValidSignature = false;
        signerSubject = string.Empty;
        rootThumbprint = string.Empty;

        try
        {
            byte[] fileBytes = File.ReadAllBytes(filePath);
            ReadOnlySpan<byte> span = fileBytes;
            if (!TryParsePeHeaders(span, out _, out int dataDirOffset, out int numDataDirs, out int sectionTableOffset, out int numSections))
                return false;

            if (numDataDirs <= 4 || dataDirOffset + 5 * 8 > span.Length)
                return false;

            uint secOffset = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(dataDirOffset + 4 * 8, 4));
            uint secSize = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(dataDirOffset + 4 * 8 + 4, 4));
            if (secOffset == 0 || secSize < 8)
                return false;

            int actualSecOffset = (int)secOffset;
            if (actualSecOffset < 0 || actualSecOffset + 8 > span.Length)
            {
                int mapped = RvaToFileOffset(span, secOffset, sectionTableOffset, numSections);
                if (mapped <= 0 || mapped + 8 > span.Length)
                    return false;
                actualSecOffset = mapped;
            }

            int maxAvailable = span.Length - actualSecOffset;
            uint dwLength = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(actualSecOffset, 4));
            ushort wCertType = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(actualSecOffset + 6, 2));
            int blobLen = (int)Math.Min(Math.Max(dwLength, secSize), (uint)maxAvailable);
            if (blobLen <= 8)
                return false;

            ReadOnlySpan<byte> certBlob = span.Slice(actualSecOffset + 8, blobLen - 8);

            // 1. 尝试提取嵌入的 DER X.509 证书集合 (覆盖直接 X.509 证书与 PKCS#7 SignedData 内嵌证书链)
            var certs = ExtractEmbeddedX509Certificates(certBlob);
            if (certs.Count > 0)
            {
                try
                {
                    var leaf = certs[0];
                    var root = certs[^1];
                    foreach (var c in certs)
                    {
                        if (string.Equals(c.Subject, c.Issuer, StringComparison.OrdinalIgnoreCase))
                        {
                            root = c;
                        }
                        else
                        {
                            leaf = c;
                        }
                    }

                    string simpleName = leaf.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
                    signerSubject = !string.IsNullOrWhiteSpace(simpleName) ? simpleName.Trim() : ExtractCnFromSubject(leaf.Subject);
                    rootThumbprint = root.Thumbprint.ToLowerInvariant();
                    hasValidSignature = !string.IsNullOrEmpty(signerSubject) && wCertType != 0;
                    return true;
                }
                finally
                {
                    foreach (var c in certs) c.Dispose();
                }
            }

            // 2. 兼容包含 UTF-8 / UTF-16 签名者属性文本的测试/轻量证书块
            string asciiText = ExtractPrintableText(certBlob);
            if (!string.IsNullOrWhiteSpace(asciiText))
            {
                string parsedCn = ExtractCnFromSubject(asciiText);
                if (!string.IsNullOrEmpty(parsedCn))
                {
                    signerSubject = parsedCn;
                    Span<byte> sha1 = stackalloc byte[20];
                    SHA1.HashData(certBlob, sha1);
                    rootThumbprint = Convert.ToHexStringLower(sha1);
                    hasValidSignature = wCertType != 0;
                    return true;
                }
            }

            return false;
        }
        catch
        {
            return false;
        }
    }

    private static List<X509Certificate2> ExtractEmbeddedX509Certificates(ReadOnlySpan<byte> blob)
    {
        var list = new List<X509Certificate2>();

        // 尝试将整个 blob 作为单个证书加载
        try
        {
            var single = X509CertificateLoader.LoadCertificate(blob);
            if (!string.IsNullOrEmpty(single.Subject))
            {
                list.Add(single);
                return list;
            }
            single.Dispose();
        }
        catch
        {
            // Ignore and scan for ASN.1 SEQUENCE (0x30 0x82) inside PKCS#7 SignedData
        }

        for (int i = 0; i + 16 < blob.Length; i++)
        {
            if (blob[i] != 0x30) continue;

            int seqLen;
            int headerLen;
            if (blob[i + 1] == 0x82 && i + 4 < blob.Length)
            {
                seqLen = (blob[i + 2] << 8) | blob[i + 3];
                headerLen = 4;
            }
            else if (blob[i + 1] == 0x81 && i + 3 < blob.Length)
            {
                seqLen = blob[i + 2];
                headerLen = 3;
            }
            else
            {
                continue;
            }

            int totalLen = headerLen + seqLen;
            if (seqLen < 128 || i + totalLen > blob.Length)
                continue;

            // X.509 Certificate TBSCertificate 也是 SEQUENCE (0x30)
            if (blob[i + headerLen] != 0x30)
                continue;

            try
            {
                var cert = X509CertificateLoader.LoadCertificate(blob.Slice(i, totalLen));
                if (!string.IsNullOrEmpty(cert.Subject))
                {
                    list.Add(cert);
                    i += totalLen - 1;
                }
                else
                {
                    cert.Dispose();
                }
            }
            catch
            {
                // Not an X.509 certificate sequence; continue scanning
            }
        }

        return list;
    }

    private static string ExtractCnFromSubject(string subject)
    {
        if (string.IsNullOrWhiteSpace(subject))
            return string.Empty;

        foreach (string key in new[] { "CN=", "O=", "Subject=" })
        {
            int idx = subject.IndexOf(key, StringComparison.OrdinalIgnoreCase);
            if (idx >= 0)
            {
                string rest = subject[(idx + key.Length)..].Trim();
                if (rest.StartsWith('"'))
                {
                    int endQ = rest.IndexOf('"', 1);
                    if (endQ > 1) return rest[1..endQ];
                }
                int endIdx = rest.IndexOfAny([',', ';', '\r', '\n', '\0']);
                return (endIdx >= 0 ? rest[..endIdx] : rest).Trim();
            }
        }

        return subject.Trim();
    }

    private static string ExtractPrintableText(ReadOnlySpan<byte> blob)
    {
        var sb = new StringBuilder();
        for (int i = 0; i < blob.Length; i++)
        {
            byte b = blob[i];
            if (b >= 0x20 && b <= 0x7E)
                sb.Append((char)b);
            else if (sb.Length > 0 && sb[^1] != ' ')
                sb.Append(' ');
        }
        return sb.ToString().Trim();
    }

    /// <summary>
    /// 提取 PE 文件的导入表哈希 (ImpHash, 小写 MD5) 与图标 64-bit 感知哈希 (IconPerceptualHash)
    /// </summary>
    public static (string ImpHash, ulong IconPerceptualHash) ExtractPeImportAndIconHashes(string filePath)
    {
        if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
            return (string.Empty, 0UL);

        try
        {
            byte[] fileBytes = File.ReadAllBytes(filePath);
            ReadOnlySpan<byte> span = fileBytes;
            if (!TryParsePeHeaders(span, out bool isPe32Plus, out int dataDirOffset, out int numDataDirs, out int sectionTableOffset, out int numSections))
                return (string.Empty, 0UL);

            string impHash = ExtractPeImpHashFromSpan(span, isPe32Plus, dataDirOffset, numDataDirs, sectionTableOffset, numSections);
            ulong iconPHash = ExtractPeIconPerceptualHashFromSpan(span, dataDirOffset, numDataDirs, sectionTableOffset, numSections);
            return (impHash, iconPHash);
        }
        catch
        {
            return (string.Empty, 0UL);
        }
    }

    private static string ExtractPeImpHashFromSpan(
        ReadOnlySpan<byte> span,
        bool isPe32Plus,
        int dataDirOffset,
        int numDataDirs,
        int sectionTableOffset,
        int numSections)
    {
        if (numDataDirs <= 1 || dataDirOffset + 2 * 8 > span.Length)
            return string.Empty;

        uint importRva = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(dataDirOffset + 1 * 8, 4));
        uint importSize = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(dataDirOffset + 1 * 8 + 4, 4));
        if (importRva == 0 || importSize == 0)
            return string.Empty;

        int descOffset = RvaToFileOffset(span, importRva, sectionTableOffset, numSections);
        if (descOffset <= 0 || descOffset + 20 > span.Length)
            return string.Empty;

        var imports = new List<string>(64);
        int maxDescriptors = 256;

        while (descOffset + 20 <= span.Length && maxDescriptors-- > 0)
        {
            uint originalFirstThunk = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(descOffset, 4));
            uint nameRva = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(descOffset + 12, 4));
            uint firstThunk = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(descOffset + 16, 4));

            if (originalFirstThunk == 0 && nameRva == 0 && firstThunk == 0)
                break;

            descOffset += 20;
            if (nameRva == 0)
                continue;

            int nameOffset = RvaToFileOffset(span, nameRva, sectionTableOffset, numSections);
            string dllName = ReadAsciiStringZ(span, nameOffset);
            if (string.IsNullOrEmpty(dllName))
                continue;

            string normalizedDll = NormalizeImportDllName(dllName);
            uint thunkRva = originalFirstThunk != 0 ? originalFirstThunk : firstThunk;
            if (thunkRva == 0)
                continue;

            int thunkOffset = RvaToFileOffset(span, thunkRva, sectionTableOffset, numSections);
            if (thunkOffset <= 0 || thunkOffset >= span.Length)
                continue;

            int maxFunctions = 4096;
            if (isPe32Plus)
            {
                while (thunkOffset + 8 <= span.Length && maxFunctions-- > 0)
                {
                    ulong thunkVal = BinaryPrimitives.ReadUInt64LittleEndian(span.Slice(thunkOffset, 8));
                    if (thunkVal == 0)
                        break;
                    thunkOffset += 8;

                    if ((thunkVal & 0x8000000000000000UL) != 0)
                    {
                        ulong ordinal = thunkVal & 0xFFFFUL;
                        imports.Add($"{normalizedDll}.ord{ordinal}");
                    }
                    else
                    {
                        uint hintNameRva = (uint)(thunkVal & 0x7FFFFFFFUL);
                        int hintNameOffset = RvaToFileOffset(span, hintNameRva, sectionTableOffset, numSections);
                        if (hintNameOffset > 0 && hintNameOffset + 2 < span.Length)
                        {
                            string funcName = ReadAsciiStringZ(span, hintNameOffset + 2).ToLowerInvariant();
                            if (!string.IsNullOrEmpty(funcName))
                                imports.Add($"{normalizedDll}.{funcName}");
                        }
                    }
                }
            }
            else
            {
                while (thunkOffset + 4 <= span.Length && maxFunctions-- > 0)
                {
                    uint thunkVal = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(thunkOffset, 4));
                    if (thunkVal == 0)
                        break;
                    thunkOffset += 4;

                    if ((thunkVal & 0x80000000u) != 0)
                    {
                        uint ordinal = thunkVal & 0xFFFFu;
                        imports.Add($"{normalizedDll}.ord{ordinal}");
                    }
                    else
                    {
                        uint hintNameRva = thunkVal & 0x7FFFFFFFu;
                        int hintNameOffset = RvaToFileOffset(span, hintNameRva, sectionTableOffset, numSections);
                        if (hintNameOffset > 0 && hintNameOffset + 2 < span.Length)
                        {
                            string funcName = ReadAsciiStringZ(span, hintNameOffset + 2).ToLowerInvariant();
                            if (!string.IsNullOrEmpty(funcName))
                                imports.Add($"{normalizedDll}.{funcName}");
                        }
                    }
                }
            }
        }

        if (imports.Count == 0)
            return string.Empty;

        string joined = string.Join(',', imports);
        byte[] asciiBytes = Encoding.ASCII.GetBytes(joined);
        Span<byte> md5Out = stackalloc byte[16];
        MD5.HashData(asciiBytes, md5Out);
        return Convert.ToHexStringLower(md5Out);
    }

    private static string NormalizeImportDllName(string dllName)
    {
        string lower = dllName.Trim().ToLowerInvariant();
        if (lower.EndsWith(".dll", StringComparison.Ordinal) ||
            lower.EndsWith(".ocx", StringComparison.Ordinal) ||
            lower.EndsWith(".sys", StringComparison.Ordinal))
        {
            return lower[..^4];
        }
        return lower;
    }

    private static ulong ExtractPeIconPerceptualHashFromSpan(
        ReadOnlySpan<byte> span,
        int dataDirOffset,
        int numDataDirs,
        int sectionTableOffset,
        int numSections)
    {
        if (numDataDirs <= 2 || dataDirOffset + 3 * 8 > span.Length)
            return 0UL;

        uint rsrcRva = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(dataDirOffset + 2 * 8, 4));
        uint rsrcSize = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(dataDirOffset + 2 * 8 + 4, 4));
        if (rsrcRva == 0 || rsrcSize == 0)
            return 0UL;

        int rsrcBase = RvaToFileOffset(span, rsrcRva, sectionTableOffset, numSections);
        if (rsrcBase <= 0 || rsrcBase + 16 > span.Length)
            return 0UL;

        // 遍历 PE 资源树查找 RT_ICON (Type == 3)
        if (TryFindResourceDataByType(span, rsrcBase, resourceTypeId: 3, out ReadOnlySpan<byte> iconBytes, sectionTableOffset, numSections) &&
            iconBytes.Length >= 8)
        {
            return ComputeIconPerceptualHashFromBytes(iconBytes);
        }

        return 0UL;
    }

    private static bool TryFindResourceDataByType(
        ReadOnlySpan<byte> span,
        int rsrcBase,
        uint resourceTypeId,
        out ReadOnlySpan<byte> dataSpan,
        int sectionTableOffset,
        int numSections)
    {
        dataSpan = default;
        if (rsrcBase < 0 || rsrcBase + 16 > span.Length)
            return false;

        ushort namedCount1 = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(rsrcBase + 12, 2));
        ushort idCount1 = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(rsrcBase + 14, 2));
        int total1 = namedCount1 + idCount1;
        int entry1Offset = rsrcBase + 16;

        for (int i = 0; i < total1 && entry1Offset + 8 <= span.Length; i++, entry1Offset += 8)
        {
            uint nameOrId = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(entry1Offset, 4));
            uint offsetToData1 = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(entry1Offset + 4, 4));
            if (nameOrId != resourceTypeId || (offsetToData1 & 0x80000000u) == 0)
                continue;

            int dir2Offset = rsrcBase + (int)(offsetToData1 & 0x7FFFFFFFu);
            if (dir2Offset < 0 || dir2Offset + 24 > span.Length)
                continue;

            uint offsetToData2 = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(dir2Offset + 20, 4));
            if ((offsetToData2 & 0x80000000u) == 0)
                continue;

            int dir3Offset = rsrcBase + (int)(offsetToData2 & 0x7FFFFFFFu);
            if (dir3Offset < 0 || dir3Offset + 24 > span.Length)
                continue;

            uint offsetToData3 = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(dir3Offset + 20, 4));
            if ((offsetToData3 & 0x80000000u) != 0)
                continue;

            int dataEntryOffset = rsrcBase + (int)offsetToData3;
            if (dataEntryOffset < 0 || dataEntryOffset + 16 > span.Length)
                continue;

            uint dataRva = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(dataEntryOffset, 4));
            uint dataSize = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(dataEntryOffset + 4, 4));
            int fileOffset = RvaToFileOffset(span, dataRva, sectionTableOffset, numSections);
            if (fileOffset > 0 && dataSize > 0 && fileOffset + (int)dataSize <= span.Length)
            {
                dataSpan = span.Slice(fileOffset, (int)dataSize);
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// 基于 8x8 空间采样与均值量化计算确定性 64-bit 图标感知哈希 (pHash)
    /// </summary>
    public static ulong ComputeIconPerceptualHashFromBytes(ReadOnlySpan<byte> iconBytes)
    {
        if (iconBytes.IsEmpty)
            return 0UL;

        Span<double> buckets = stackalloc double[64];
        Span<int> counts = stackalloc int[64];

        for (int i = 0; i < iconBytes.Length; i++)
        {
            int idx = (int)((long)i * 64 / iconBytes.Length);
            if (idx >= 64) idx = 63;
            buckets[idx] += iconBytes[i];
            counts[idx]++;
        }

        double totalSum = 0.0;
        for (int i = 0; i < 64; i++)
        {
            if (counts[i] > 0)
                buckets[i] /= counts[i];
            else
                buckets[i] = iconBytes[i % iconBytes.Length];
            totalSum += buckets[i];
        }

        double mean = totalSum / 64.0;
        ulong hash = 0UL;
        for (int i = 0; i < 64; i++)
        {
            if (buckets[i] >= mean)
                hash |= 1UL << i;
        }

        // 若输入全为相同常量字节导致全 1，混入长度特征保持确定性
        return hash == 0UL ? (ulong)iconBytes.Length : hash;
    }

    private static bool TryParsePeHeaders(
        ReadOnlySpan<byte> span,
        out bool isPe32Plus,
        out int dataDirOffset,
        out int numDataDirs,
        out int sectionTableOffset,
        out int numSections)
    {
        isPe32Plus = false;
        dataDirOffset = 0;
        numDataDirs = 0;
        sectionTableOffset = 0;
        numSections = 0;

        if (span.Length < 64)
            return false;

        ushort mz = BinaryPrimitives.ReadUInt16LittleEndian(span[..2]);
        if (mz != 0x5A4D) // "MZ"
            return false;

        int peOffset = BinaryPrimitives.ReadInt32LittleEndian(span.Slice(0x3C, 4));
        if (peOffset < 0 || peOffset + 24 > span.Length)
            return false;

        uint peSig = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(peOffset, 4));
        if (peSig != 0x00004550u) // "PE\0\0"
            return false;

        numSections = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(peOffset + 6, 2));
        ushort sizeOfOptionalHeader = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(peOffset + 20, 2));

        int optOffset = peOffset + 24;
        if (optOffset + sizeOfOptionalHeader > span.Length || sizeOfOptionalHeader < 96)
            return false;

        ushort optMagic = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(optOffset, 2));
        if (optMagic == 0x020B) // PE32+ (64-bit)
        {
            isPe32Plus = true;
            if (sizeOfOptionalHeader < 112)
                return false;
            numDataDirs = (int)BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(optOffset + 108, 4));
            dataDirOffset = optOffset + 112;
        }
        else if (optMagic == 0x010B) // PE32 (32-bit)
        {
            isPe32Plus = false;
            numDataDirs = (int)BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(optOffset + 92, 4));
            dataDirOffset = optOffset + 96;
        }
        else
        {
            return false;
        }

        numDataDirs = Math.Clamp(numDataDirs, 0, 16);
        sectionTableOffset = optOffset + sizeOfOptionalHeader;
        return true;
    }

    private static int RvaToFileOffset(ReadOnlySpan<byte> span, uint rva, int sectionTableOffset, int numSections)
    {
        if (rva == 0)
            return -1;

        for (int i = 0; i < numSections; i++)
        {
            int secOffset = sectionTableOffset + i * 40;
            if (secOffset + 40 > span.Length)
                break;

            uint virtualSize = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(secOffset + 8, 4));
            uint virtualAddress = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(secOffset + 12, 4));
            uint sizeOfRawData = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(secOffset + 16, 4));
            uint pointerToRawData = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(secOffset + 20, 4));

            uint spanSize = Math.Max(virtualSize, sizeOfRawData);
            if (rva >= virtualAddress && rva < virtualAddress + spanSize)
            {
                long fileOffset = (long)pointerToRawData + (rva - virtualAddress);
                if (fileOffset >= 0 && fileOffset < span.Length)
                    return (int)fileOffset;
            }
        }

        if (rva < span.Length)
            return (int)rva;

        return -1;
    }

    private static string ReadAsciiStringZ(ReadOnlySpan<byte> span, int offset)
    {
        if (offset < 0 || offset >= span.Length)
            return string.Empty;

        int end = offset;
        while (end < span.Length && span[end] != 0 && end - offset < 260)
        {
            end++;
        }

        return end > offset ? Encoding.ASCII.GetString(span.Slice(offset, end - offset)) : string.Empty;
    }

    /// <summary>
    /// 零反射调用 Version.dll (或纯 C# PE VS_VERSION_INFO 扫描器回退) 提取 PE 文件版本资源中的
    /// OriginalFilename / ProductName / CompanyName / InternalName / FileDescription
    /// </summary>
    public static (string OrigFileName, string ProductName, string CompanyName, string InternalName, string Description)
        ExtractPeVersionMetadata(string filePath)
    {
        if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
            return (string.Empty, string.Empty, string.Empty, string.Empty, string.Empty);

        if (OperatingSystem.IsWindows())
        {
            try
            {
                uint size = GetFileVersionInfoSizeW(filePath, out _);
                if (size > 0 && size <= 4 * 1024 * 1024)
                {
                    byte* pBlock = (byte*)NativeMemory.Alloc(size);
                    try
                    {
                        if (GetFileVersionInfoW(filePath, 0, size, pBlock))
                        {
                            string langCodePage = "040904B0"; // 默认 US English Unicode
                            if (VerQueryValueW(pBlock, @"\VarFileInfo\Translation", out nint pTrans, out uint transLen) && transLen >= 4)
                            {
                                ushort langId = *(ushort*)pTrans;
                                ushort codePage = *((ushort*)pTrans + 1);
                                langCodePage = $"{langId:X4}{codePage:X4}";
                            }

                            string origFile = QueryVersionString(pBlock, langCodePage, "OriginalFilename");
                            string prodName = QueryVersionString(pBlock, langCodePage, "ProductName");
                            string compName = QueryVersionString(pBlock, langCodePage, "CompanyName");
                            string intName = QueryVersionString(pBlock, langCodePage, "InternalName");
                            string desc = QueryVersionString(pBlock, langCodePage, "FileDescription");

                            if (!string.IsNullOrEmpty(origFile) || !string.IsNullOrEmpty(prodName) ||
                                !string.IsNullOrEmpty(compName) || !string.IsNullOrEmpty(intName) ||
                                !string.IsNullOrEmpty(desc))
                            {
                                return (origFile, prodName, compName, intName, desc);
                            }
                        }
                    }
                    finally
                    {
                        NativeMemory.Free(pBlock);
                    }
                }
            }
            catch
            {
                // Fall back to pure C# PE version scanner
            }
        }

        return ExtractPeVersionMetadataPureCSharp(filePath);
    }

    private static (string OrigFileName, string ProductName, string CompanyName, string InternalName, string Description)
        ExtractPeVersionMetadataPureCSharp(string filePath)
    {
        try
        {
            byte[] fileBytes = File.ReadAllBytes(filePath);
            ReadOnlySpan<byte> span = fileBytes;
            ReadOnlySpan<byte> targetSpan = span;

            // 优先定位 PE 自身的 IMAGE_DIRECTORY_ENTRY_RESOURCE -> RT_VERSION (Type = 16)，避免单文件打包末尾捆绑的依赖库干扰
            if (TryParsePeHeaders(span, out _, out int dataDirOffset, out int numDataDirs, out int sectionTableOffset, out int numSections) &&
                numDataDirs > 2 && dataDirOffset + 3 * 8 <= span.Length)
            {
                uint rsrcRva = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(dataDirOffset + 2 * 8, 4));
                uint rsrcSize = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(dataDirOffset + 2 * 8 + 4, 4));
                if (rsrcRva != 0 && rsrcSize != 0)
                {
                    int rsrcBase = RvaToFileOffset(span, rsrcRva, sectionTableOffset, numSections);
                    if (TryFindResourceDataByType(span, rsrcBase, resourceTypeId: 16, out ReadOnlySpan<byte> verSpan, sectionTableOffset, numSections) &&
                        !verSpan.IsEmpty)
                    {
                        targetSpan = verSpan;
                    }
                    else if (rsrcBase > 0 && rsrcBase + (int)Math.Min(rsrcSize, (uint)(span.Length - rsrcBase)) <= span.Length)
                    {
                        var rsrcSlice = span.Slice(rsrcBase, (int)Math.Min(rsrcSize, (uint)(span.Length - rsrcBase)));
                        if (!string.IsNullOrEmpty(ExtractUtf16VersionKey(rsrcSlice, "OriginalFilename")) ||
                            !string.IsNullOrEmpty(ExtractUtf16VersionKey(rsrcSlice, "ProductName")))
                        {
                            targetSpan = rsrcSlice;
                        }
                    }
                }
            }

            string origFile = ExtractUtf16VersionKey(targetSpan, "OriginalFilename");
            string prodName = ExtractUtf16VersionKey(targetSpan, "ProductName");
            string compName = ExtractUtf16VersionKey(targetSpan, "CompanyName");
            string intName = ExtractUtf16VersionKey(targetSpan, "InternalName");
            string desc = ExtractUtf16VersionKey(targetSpan, "FileDescription");

            return (origFile, prodName, compName, intName, desc);
        }
        catch
        {
            return (string.Empty, string.Empty, string.Empty, string.Empty, string.Empty);
        }
    }

    private static string ExtractUtf16VersionKey(ReadOnlySpan<byte> span, string keyName)
    {
        Span<byte> pattern = stackalloc byte[(keyName.Length + 1) * 2];
        Encoding.Unicode.GetBytes(keyName.AsSpan(), pattern);
        pattern[^2] = 0;
        pattern[^1] = 0;

        int idx = span.IndexOf(pattern);
        if (idx < 0)
            return string.Empty;

        // 检查标准 VS_VERSION_INFO String 结构的 wValueLength (位于 key 起始前 4 字节)
        if (idx >= 6)
        {
            ushort wValueLength = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(idx - 4, 2));
            ushort wType = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(idx - 2, 2));
            if (wType == 1 && wValueLength == 0)
                return string.Empty;
        }

        int valuePos = idx + pattern.Length;
        // 跳过 DWORD 对齐填充的 UTF-16 '\0' (最多 8 字节)
        int skipped = 0;
        while (valuePos + 2 <= span.Length && skipped < 8 && span[valuePos] == 0 && span[valuePos + 1] == 0)
        {
            valuePos += 2;
            skipped += 2;
        }

        int endPos = valuePos;
        while (endPos + 2 <= span.Length && (span[endPos] != 0 || span[endPos + 1] != 0) && endPos - valuePos < 512)
        {
            ushort ch = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(endPos, 2));
            if (ch < 0x20 || ch == 0xFFFF)
                break;
            endPos += 2;
        }

        if (endPos <= valuePos)
            return string.Empty;

        return Encoding.Unicode.GetString(span.Slice(valuePos, endPos - valuePos)).Trim();
    }

    private static string QueryVersionString(byte* pBlock, string langCodePage, string keyName)
    {
        string subBlock = $@"\StringFileInfo\{langCodePage}\{keyName}";
        if (VerQueryValueW(pBlock, subBlock, out nint pStr, out uint len) && len > 0 && pStr != 0)
        {
            return Marshal.PtrToStringUni(pStr)?.Trim() ?? string.Empty;
        }
        return string.Empty;
    }

    /// <summary>
    /// 统一构建目标程序的六维特征快照载体 (TargetProgramFeatures)
    /// </summary>
    public static TargetProgramFeatures BuildTargetProgramFeatures(
        MonitorCategory category,
        string locationKey,
        string rawCommandLine,
        string displayName = "",
        string oldState = "",
        string newState = "",
        uint sourcePid = 0,
        string sourceProcessName = "",
        byte[]? oldRawSnapshot = null,
        uint registryValueType = 1)
    {
        var (exePath, argsTemplate) = PathNormalizerAndSimilarity.SplitCommandLine(rawCommandLine);
        string targetBin = !string.IsNullOrEmpty(exePath) ? exePath : rawCommandLine.Trim().Trim('"');
        string physicalBin = ShellNavigationHelper.ResolvePhysicalFilePath(!string.IsNullOrEmpty(targetBin) ? targetBin : locationKey);
        if (!string.IsNullOrEmpty(physicalBin) && File.Exists(physicalBin))
        {
            targetBin = physicalBin;
        }
        string normPath = PathNormalizerAndSimilarity.NormalizeProgramPath(targetBin);
        ulong normPathHash = MmfBinaryStore.ComputeFnv1a64(normPath);

        string md5 = string.Empty;
        string sha256 = string.Empty;
        bool hasValidSig = false;
        string signerSubject = string.Empty;
        string rootThumbprint = string.Empty;
        string origFile = string.Empty;
        string prodName = displayName;
        string compName = string.Empty;
        string intName = string.Empty;
        string fileDesc = string.Empty;
        string impHash = string.Empty;
        ulong iconPHash = 0UL;

        if (!string.IsNullOrEmpty(targetBin) && File.Exists(targetBin))
        {
            (md5, sha256) = ComputeFileHashesCng(targetBin);
            (hasValidSig, signerSubject, rootThumbprint) = ExtractAuthenticodeDetails(targetBin);
            var (peOrig, peProd, peComp, peInt, peDesc) = ExtractPeVersionMetadata(targetBin);
            (impHash, iconPHash) = ExtractPeImportAndIconHashes(targetBin);

            origFile = peOrig;
            bool isGenericWrapper = !string.IsNullOrEmpty(peProd) &&
                (peProd.Contains("Wrapper", StringComparison.OrdinalIgnoreCase) ||
                 peProd.Equals("Service", StringComparison.OrdinalIgnoreCase));
            if (!string.IsNullOrEmpty(peProd) && (!isGenericWrapper || string.IsNullOrEmpty(displayName)))
            {
                prodName = peProd;
            }
            compName = peComp;
            intName = peInt;
            fileDesc = peDesc;
        }

        if (string.IsNullOrEmpty(origFile) && !string.IsNullOrEmpty(targetBin))
        {
            origFile = Path.GetFileName(targetBin);
        }

        if (string.IsNullOrEmpty(prodName) && !string.IsNullOrEmpty(origFile))
        {
            prodName = Path.GetFileNameWithoutExtension(origFile);
        }

        return new TargetProgramFeatures
        {
            Category = category,
            TargetBinaryPath = targetBin,
            NormalizedPath = normPath,
            NormalizedPathHash = normPathHash,
            RawCommandLine = rawCommandLine,
            CommandLineArgsTemplate = argsTemplate,
            LocationKeyOrIdentifier = locationKey,
            DisplayName = !string.IsNullOrEmpty(displayName) ? displayName : prodName,
            MD5Hex = md5,
            SHA256Hex = sha256,
            HasValidSignature = hasValidSig,
            SignerSubject = signerSubject,
            RootCertThumbprint = rootThumbprint,
            IsWhqlCertified = hasValidSig && category == MonitorCategory.KernelDriver,
            OriginalFilename = origFile,
            ProductName = (!string.IsNullOrEmpty(prodName) && !prodName.Contains("Wrapper", StringComparison.OrdinalIgnoreCase)) ? prodName : (!string.IsNullOrEmpty(displayName) ? displayName : origFile),
            CompanyName = compName,
            InternalName = intName,
            FileDescription = fileDesc,
            ImpHash = impHash,
            IconPerceptualHash = iconPHash,
            SourceProcessId = sourcePid,
            SourceProcessName = sourceProcessName,
            OldStateSummary = oldState,
            NewStateSummary = newState,
            OldRawSnapshot = oldRawSnapshot,
            RegistryValueType = registryValueType
        };
    }

    /// <summary>
    /// 判断是否为 Windows 操作系统核心必要组件 (永不弹窗拦截)
    /// 确保全面囊括系统底层核心，同时严格排除微软电脑管家、手机远控 (Phone Link)、Edge 更新等非核心/第三方/捆绑组件
    /// </summary>
    public static bool IsWindowsEssentialOperatingSystemComponent(TargetProgramFeatures? target)
    {
        if (target is null) return false;

        string binPath = target.TargetBinaryPath ?? string.Empty;
        string fileName = Path.GetFileName(binPath).ToLowerInvariant();
        string lowerPath = binPath.ToLowerInvariant();
        string displayName = (target.DisplayName ?? string.Empty).ToLowerInvariant();
        string signer = (target.SignerSubject ?? string.Empty).ToLowerInvariant();

        // 1. 严格黑名单与第三方签名排查：绝不豁免微软非核心组件或第三方 WHQL 签名驱动（如 Dokan2: Microsoft Windows Third Party Component CA）
        bool isThirdPartyWhql = signer.Contains("third party component") ||
                                signer.Contains("hardware compatibility") ||
                                signer.Contains("third-party");
        if (isThirdPartyWhql ||
            IsNonCoreOptionalMicrosoftApp($"{fileName} {lowerPath} {displayName}") ||
            lowerPath.Contains(@"\program files\") || lowerPath.Contains(@"\program files (x86)\") ||
            lowerPath.Contains(@"\appdata\") || lowerPath.Contains(@"\programdata\"))
        {
            return false;
        }

        // 2. 核心系统目录校验 (System32, SysWOW64, WinSxS, servicing)
        string winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows).ToLowerInvariant();
        if (string.IsNullOrEmpty(winDir)) winDir = @"c:\windows";

        bool inSystemDir = lowerPath.StartsWith(winDir + @"\system32\") ||
                           lowerPath.StartsWith(winDir + @"\syswow64\") ||
                           lowerPath.StartsWith(winDir + @"\winsxs\") ||
                           lowerPath.StartsWith(winDir + @"\servicing\");

        if (!inSystemDir) return false;

        // 3. 必须具备微软第一方官方签名（不能把任意第三方 HasValidSignature 当成微软核心组件）
        bool isMicrosoftSigned = signer.Contains("microsoft windows") ||
                                 signer.Contains("microsoft corporation");

        if (!isMicrosoftSigned) return false;

        // 4. 确认属于核心 Windows 宿主、关键系统服务或内置驱动
        if (fileName is "svchost.exe" or "services.exe" or "lsass.exe" or "smss.exe" or "csrss.exe" or
            "wininit.exe" or "winlogon.exe" or "sihost.exe" or "ctfmon.exe" or "fontdrvhost.exe" or
            "runtimebroker.exe" or "taskhostw.exe" or "dllhost.exe" or "conhost.exe" or "spoolsv.exe" or
            "credentialenrollmentmanager.exe" or "securityhealthservice.exe" or "msmpeng.exe" or "nissrv.exe" or
            "werfault.exe" or "searchindexer.exe" or "dwm.exe" or "audiodg.exe" or
            "trustedinstaller.exe" or "tiworker.exe")
        {
            return true;
        }

        // 内核驱动 (.sys 且位于 drivers 目录下)
        if (lowerPath.Contains(@"\system32\drivers\") && fileName.EndsWith(".sys") && isMicrosoftSigned)
        {
            return true;
        }

        // 针对 svchost 托管的合法微软 Windows 系统服务
        if (target.Category == MonitorCategory.Win32Service && isMicrosoftSigned && inSystemDir)
        {
            return true;
        }

        return false;
    }

    private static readonly string[] OptionalMicrosoftAppKeywords =
    [
        "pcmanager", "电脑管家", "phoneexperiencehost", "yourphone",
        "microsoftedge", "edgeupdate", "msedge", "edgewebview",
        "onedrive", "teams", "skype", "bingwallpaper", "bingsearch", "copilot"
    ];

    /// <summary>
    /// 识别微软非操作系统核心应用（如 Edge、EdgeUpdate、OneDrive、Teams、电脑管家等），避免被误当作 Windows 内置系统项隐藏
    /// </summary>
    public static bool IsNonCoreOptionalMicrosoftApp(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
            return false;

        foreach (string kw in OptionalMicrosoftAppKeywords)
        {
            if (text.Contains(kw, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial nint OpenProcess(uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwProcessId);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseHandle(nint hObject);

    [LibraryImport("kernel32.dll", EntryPoint = "QueryFullProcessImageNameW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool QueryFullProcessImageNameW(nint hProcess, uint dwFlags, char* lpExeName, ref uint lpdwSize);

    [LibraryImport("ntdll.dll")]
    private static partial int NtQueryInformationProcess(nint processHandle, int processInformationClass, void* processInformation, uint processInformationLength, out uint returnLength);

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessBasicInformation64
    {
        public nint Reserved1;
        public nint PebBaseAddress;
        public nint Reserved2_0;
        public nint Reserved2_1;
        public nint UniqueProcessId;
        public nint InheritedFromUniqueProcessId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct UnicodeStringNative
    {
        public ushort Length;
        public ushort MaximumLength;
        public nint Buffer;
    }

    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    private static readonly HashSet<string> BrokerOrWrapperProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "services.exe", "svchost.exe", "taskhostw.exe", "lsass.exe", "smss.exe",
        "csrss.exe", "wininit.exe", "reg.exe", "cmd.exe", "powershell.exe",
        "pwsh.exe", "schtasks.exe", "rundll32.exe", "regsvr32.exe", "conhost.exe"
    };

    public static string TryGetProcessImagePath(uint pid)
    {
        if (!OperatingSystem.IsWindows() || pid == 0)
            return string.Empty;

        nint hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (hProc == 0) return string.Empty;
        try
        {
            char* buf = stackalloc char[1024];
            uint size = 1024;
            if (QueryFullProcessImageNameW(hProc, 0, buf, ref size) && size > 0)
                return new string(buf, 0, (int)size);
        }
        finally
        {
            CloseHandle(hProc);
        }
        return string.Empty;
    }

    public static uint TryGetParentProcessId(uint pid)
    {
        if (!OperatingSystem.IsWindows() || pid == 0)
            return 0;

        nint hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (hProc == 0) return 0;
        try
        {
            ProcessBasicInformation64 pbi = default;
            if (NtQueryInformationProcess(hProc, 0 /* ProcessBasicInformation */, &pbi, (uint)sizeof(ProcessBasicInformation64), out _) == 0)
            {
                long parent = pbi.InheritedFromUniqueProcessId.ToInt64();
                return parent > 0 && parent <= uint.MaxValue ? (uint)parent : 0;
            }
        }
        finally
        {
            CloseHandle(hProc);
        }
        return 0;
    }

    public static string TryGetProcessCommandLine(uint pid)
    {
        if (!OperatingSystem.IsWindows() || pid == 0)
            return string.Empty;

        nint hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (hProc == 0) return string.Empty;
        try
        {
            uint needed = 0;
            NtQueryInformationProcess(hProc, 60 /* ProcessCommandLineInformation */, null, 0, out needed);
            if (needed < (uint)sizeof(UnicodeStringNative) || needed > 65536)
                return string.Empty;

            byte[] buf = new byte[needed];
            fixed (byte* pBuf = buf)
            {
                if (NtQueryInformationProcess(hProc, 60, pBuf, needed, out _) == 0)
                {
                    var us = *(UnicodeStringNative*)pBuf;
                    if (us.Length > 0 && us.Buffer != 0)
                        return Marshal.PtrToStringUni(us.Buffer, us.Length / 2) ?? string.Empty;
                }
            }
        }
        catch { }
        finally
        {
            CloseHandle(hProc);
        }
        return string.Empty;
    }

    /// <summary>
    /// 综合 ETW 写入 PID、父进程溯源及当前活动安装器特征，推断触发创建启动项/服务/右键菜单的来源进程
    /// </summary>
    public static (uint ProcessId, string DisplayText) ResolveCreatorProcessInfo(
        uint writerPid,
        string targetBinaryPath = "",
        string displayName = "",
        string signerSubject = "")
    {
        if (!OperatingSystem.IsWindows())
            return (0, string.Empty);

        try
        {
            // 1. 优先沿直接写入进程向上追溯一层真实非系统壳/非脚本父进程
            if (writerPid > 4)
            {
                uint candidatePid = writerPid;
                string candidatePath = TryGetProcessImagePath(candidatePid);
                string candidateName = Path.GetFileName(candidatePath);

                for (int depth = 0; depth < 3 && !string.IsNullOrEmpty(candidateName); depth++)
                {
                    if (!BrokerOrWrapperProcessNames.Contains(candidateName))
                        return FormatProcessAttribution(candidatePid, candidatePath);

                    // 若是 cmd/powershell/reg/schtasks，继续向上追父进程（最多 3 层）
                    if (candidateName is "cmd.exe" or "reg.exe" or "powershell.exe" or "pwsh.exe" or "schtasks.exe" or "rundll32.exe" or "regsvr32.exe")
                    {
                        uint parentPid = TryGetParentProcessId(candidatePid);
                        if (parentPid <= 4 || parentPid == candidatePid) break;
                        string parentPath = TryGetProcessImagePath(parentPid);
                        if (string.IsNullOrEmpty(parentPath)) break;
                        candidatePid = parentPid;
                        candidatePath = parentPath;
                        candidateName = Path.GetFileName(parentPath);
                        continue;
                    }
                    break;
                }
            }

            // 2. 若写入者是 services.exe / svchost.exe (如服务/计划任务 API 创建) 或未捕获 PID，关联当前活跃安装器进程
            var correlated = FindBestMatchingActiveInstaller(targetBinaryPath, displayName, signerSubject);
            if (correlated.ProcessId > 0)
                return correlated;
        }
        catch { }

        return (0, string.Empty);
    }

    private static (uint ProcessId, string DisplayText) FormatProcessAttribution(uint pid, string exePath, bool isInferred = false)
    {
        string fileName = Path.GetFileName(exePath);
        if (string.IsNullOrEmpty(fileName))
        {
            try
            {
                using var p = Process.GetProcessById((int)pid);
                fileName = p.ProcessName + ".exe";
            }
            catch
            {
                return (pid, $"PID {pid}");
            }
        }

        if (fileName.Equals("msiexec.exe", StringComparison.OrdinalIgnoreCase))
        {
            string cmd = TryGetProcessCommandLine(pid);
            int msiIdx = cmd.IndexOf(".msi", StringComparison.OrdinalIgnoreCase);
            if (msiIdx > 0)
            {
                int start = cmd.LastIndexOf('"', msiIdx);
                if (start < 0) start = cmd.LastIndexOf(' ', msiIdx);
                string msiPkg = Path.GetFileName(cmd[(start + 1)..(msiIdx + 4)].Trim('"', ' '));
                if (!string.IsNullOrEmpty(msiPkg))
                    return (pid, $"{fileName} ({msiPkg}, PID {pid})");
            }
        }

        string dirTag = isInferred ? "关联安装进程, " : string.Empty;
        return !string.IsNullOrEmpty(exePath)
            ? (pid, $"{fileName} ({dirTag}PID {pid}) — {exePath}")
            : (pid, $"{fileName} ({dirTag}PID {pid})");
    }

    private static (uint ProcessId, string DisplayText) FindBestMatchingActiveInstaller(
        string targetBinaryPath,
        string displayName,
        string signerSubject)
    {
        int selfPid = Environment.ProcessId;
        string winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        string targetDir = !string.IsNullOrEmpty(targetBinaryPath) ? (Path.GetDirectoryName(targetBinaryPath) ?? string.Empty) : string.Empty;

        var tokens = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        static void AddTokens(HashSet<string> set, string? raw)
        {
            if (string.IsNullOrWhiteSpace(raw)) return;
            foreach (string part in raw.Split([' ', '_', '-', '.', '\\', '/', '(', ')'], StringSplitOptions.RemoveEmptyEntries))
            {
                if (part.Length >= 3 &&
                    !part.Equals("exe", StringComparison.OrdinalIgnoreCase) &&
                    !part.Equals("dll", StringComparison.OrdinalIgnoreCase) &&
                    !part.Equals("sys", StringComparison.OrdinalIgnoreCase) &&
                    !part.Equals("com", StringComparison.OrdinalIgnoreCase) &&
                    !part.Equals("co", StringComparison.OrdinalIgnoreCase) &&
                    !part.Equals("ltd", StringComparison.OrdinalIgnoreCase) &&
                    !part.Equals("inc", StringComparison.OrdinalIgnoreCase) &&
                    !part.Equals("program", StringComparison.OrdinalIgnoreCase) &&
                    !part.Equals("files", StringComparison.OrdinalIgnoreCase))
                {
                    set.Add(part);
                }
            }
        }

        AddTokens(tokens, Path.GetFileNameWithoutExtension(targetBinaryPath));
        AddTokens(tokens, Path.GetFileName(targetDir));
        AddTokens(tokens, displayName);
        AddTokens(tokens, signerSubject);

        uint bestPid = 0;
        string bestPath = string.Empty;
        int bestScore = 0;

        foreach (var p in Process.GetProcesses())
        {
            using (p)
            {
                try
                {
                    if (p.Id <= 4 || p.Id == selfPid) continue;
                    string procName = p.ProcessName;
                    if (procName.StartsWith("StartupGuard", StringComparison.OrdinalIgnoreCase) ||
                        BrokerOrWrapperProcessNames.Contains(procName + ".exe"))
                    {
                        if (!procName.Equals("msiexec", StringComparison.OrdinalIgnoreCase))
                            continue;
                    }

                    string exePath = TryGetProcessImagePath((uint)p.Id);
                    if (string.IsNullOrEmpty(exePath)) continue;

                    bool inWindowsDir = !string.IsNullOrEmpty(winDir) && exePath.StartsWith(winDir, StringComparison.OrdinalIgnoreCase);
                    bool isMsiExec = procName.Equals("msiexec", StringComparison.OrdinalIgnoreCase);
                    if (inWindowsDir && !isMsiExec) continue;

                    string lowerPath = exePath.ToLowerInvariant();
                    string lowerName = procName.ToLowerInvariant();
                    int score = 0;

                    if (isMsiExec)
                    {
                        string cmd = TryGetProcessCommandLine((uint)p.Id);
                        if (cmd.Contains("/embedding", StringComparison.OrdinalIgnoreCase)) continue;
                        if (cmd.Contains(".msi", StringComparison.OrdinalIgnoreCase) || cmd.Contains("/i", StringComparison.OrdinalIgnoreCase))
                            score += 40;
                    }

                    if (lowerName.Contains("setup") || lowerName.Contains("install") || lowerName.Contains("unins") ||
                        lowerName.Contains("update") || lowerPath.Contains(@"\appdata\local\temp\") || lowerPath.Contains(@"\downloads\"))
                    {
                        score += 35;
                    }

                    if (!string.IsNullOrEmpty(targetDir) &&
                        exePath.StartsWith(targetDir, StringComparison.OrdinalIgnoreCase))
                    {
                        score += 50;
                    }

                    foreach (string tok in tokens)
                    {
                        if (lowerPath.Contains(tok, StringComparison.OrdinalIgnoreCase))
                            score += 20;
                    }

                    // 优先近期启动（10分钟内）的安装程序
                    try
                    {
                        if ((DateTime.Now - p.StartTime).TotalMinutes <= 10)
                            score += 20;
                    }
                    catch { }

                    if (score > bestScore && score >= 45)
                    {
                        bestScore = score;
                        bestPid = (uint)p.Id;
                        bestPath = exePath;
                    }
                }
                catch { }
            }
        }

        return bestPid > 0 ? FormatProcessAttribution(bestPid, bestPath, isInferred: true) : (0, string.Empty);
    }
}

