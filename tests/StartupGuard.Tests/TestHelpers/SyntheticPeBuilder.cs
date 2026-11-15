using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace StartupGuard.Tests.TestHelpers;

public static class SyntheticPeBuilder
{
    /// <summary>
    /// Constructs a valid in-memory PE32+ (x64) executable with specified imports, an optional icon resource, and an optional embedded cert.
    /// </summary>
    public static byte[] BuildSyntheticPe64(
        (string DllName, string[] Functions)[]? imports = null,
        byte[]? iconBytes = null,
        X509Certificate2? cert = null)
    {
        using var ms = new MemoryStream();
        using var bw = new BinaryWriter(ms, Encoding.UTF8, leaveOpen: true);

        // 1. DOS Header (64 bytes)
        bw.Write((ushort)0x5A4D); // "MZ"
        bw.Write(new byte[0x3A]); // DOS stub padding up to 0x3C
        bw.Write(0x80);           // e_lfanew = 0x80

        // Padding up to e_lfanew
        while (ms.Position < 0x80)
            bw.Write((byte)0);

        // 2. PE Signature (4 bytes)
        bw.Write(0x00004550u); // "PE\0\0"

        // 3. File Header (20 bytes)
        bw.Write((ushort)0x8664); // Machine = IMAGE_FILE_MACHINE_AMD64
        ushort numSections = 2;   // .rdata (imports) and .rsrc (resources/cert)
        bw.Write(numSections);
        bw.Write(0x60000000u);    // TimeDateStamp
        bw.Write(0u);             // PointerToSymbolTable
        bw.Write(0u);             // NumberOfSymbols
        ushort sizeOfOptHeader = 240; // PE32+ optional header size (112 + 16*8)
        bw.Write(sizeOfOptHeader);
        bw.Write((ushort)0x0022); // Characteristics = EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

        // 4. Optional Header (240 bytes)
        long optHeaderStart = ms.Position;
        bw.Write((ushort)0x020B); // Magic = PE32+ (64-bit)
        bw.Write((byte)1);        // MajorLinkerVersion
        bw.Write((byte)0);        // MinorLinkerVersion
        bw.Write(0x1000u);        // SizeOfCode
        bw.Write(0x2000u);        // SizeOfInitializedData
        bw.Write(0u);             // SizeOfUninitializedData
        bw.Write(0x1000u);        // AddressOfEntryPoint
        bw.Write(0x1000u);        // BaseOfCode
        bw.Write(0x0000000140000000UL); // ImageBase
        bw.Write(0x1000u);        // SectionAlignment = 4096
        bw.Write(0x0200u);        // FileAlignment = 512
        bw.Write((ushort)6);      // MajorOSVersion
        bw.Write((ushort)0);      // MinorOSVersion
        bw.Write((ushort)0);      // MajorImageVersion
        bw.Write((ushort)0);      // MinorImageVersion
        bw.Write((ushort)6);      // MajorSubsystemVersion
        bw.Write((ushort)0);      // MinorSubsystemVersion
        bw.Write(0u);             // Win32VersionValue
        bw.Write(0x8000u);        // SizeOfImage
        bw.Write(0x400u);         // SizeOfHeaders
        bw.Write(0u);             // CheckSum
        bw.Write((ushort)2);      // Subsystem = WINDOWS_GUI
        bw.Write((ushort)0x8160); // DllCharacteristics
        bw.Write(0x100000UL);     // SizeOfStackReserve
        bw.Write(0x1000UL);       // SizeOfStackCommit
        bw.Write(0x100000UL);     // SizeOfHeapReserve
        bw.Write(0x1000UL);       // SizeOfHeapCommit
        bw.Write(0u);             // LoaderFlags
        bw.Write(16u);            // NumberOfRvaAndSizes

        // 16 Data Directories (16 * 8 = 128 bytes)
        // [0] Export Table
        bw.Write(0u); bw.Write(0u);

        // [1] Import Table: RVA 0x2000, Size will be calculated
        uint importTableRva = 0x2000u;
        uint importTableSize = 0x1000u;
        bw.Write(importTableRva);
        bw.Write(importTableSize);

        // [2] Resource Table: RVA 0x3000, Size 0x1000
        uint rsrcRva = 0x3000u;
        uint rsrcSize = 0x1000u;
        bw.Write(rsrcRva);
        bw.Write(rsrcSize);

        // [3] Exception Table
        bw.Write(0u); bw.Write(0u);

        // [4] Security Directory (Certificate Table): Note: file offset, not RVA
        // We'll place the cert at file offset 0x800 if present
        uint secDirOffset = cert != null ? 0x800u : 0u;
        uint secDirSize = 0u;
        if (cert != null)
        {
            byte[] rawCert = cert.RawData;
            // WIN_CERTIFICATE: dwLength(4) + wRevision(2) + wCertificateType(2) + rawCert
            secDirSize = (uint)(8 + rawCert.Length);
        }
        bw.Write(secDirOffset);
        bw.Write(secDirSize);

        // [5]..[15] Other data dirs
        for (int i = 5; i < 16; i++)
        {
            bw.Write(0u);
            bw.Write(0u);
        }

        // 5. Section Headers (2 sections * 40 bytes = 80 bytes)
        // Section 1: .rdata (imports), RVA 0x2000, FileOffset 0x400
        byte[] rdataName = Encoding.ASCII.GetBytes(".rdata\0\0");
        bw.Write(rdataName);
        bw.Write(0x1000u); // VirtualSize
        bw.Write(0x2000u); // VirtualAddress (RVA)
        bw.Write(0x0200u); // SizeOfRawData
        bw.Write(0x0400u); // PointerToRawData (FileOffset)
        bw.Write(0u);      // PointerToRelocations
        bw.Write(0u);      // PointerToLinenumbers
        bw.Write((ushort)0); // NumberOfRelocations
        bw.Write((ushort)0); // NumberOfLinenumbers
        bw.Write(0x40000040u); // Characteristics: INITIALIZED_DATA | READ

        // Section 2: .rsrc (resources), RVA 0x3000, FileOffset 0x600
        byte[] rsrcName = Encoding.ASCII.GetBytes(".rsrc\0\0\0");
        bw.Write(rsrcName);
        bw.Write(0x1000u); // VirtualSize
        bw.Write(0x3000u); // VirtualAddress (RVA)
        bw.Write(0x0200u); // SizeOfRawData
        bw.Write(0x0600u); // PointerToRawData (FileOffset)
        bw.Write(0u);      // PointerToRelocations
        bw.Write(0u);      // PointerToLinenumbers
        bw.Write((ushort)0); // NumberOfRelocations
        bw.Write((ushort)0); // NumberOfLinenumbers
        bw.Write(0x40000040u); // Characteristics: INITIALIZED_DATA | READ

        // Pad to FileOffset 0x400 (.rdata)
        while (ms.Position < 0x400)
            bw.Write((byte)0);

        // 6. Section 1 Body (.rdata at 0x400, RVA 0x2000)
        // Build Import Directory Table if imports provided
        if (imports != null && imports.Length > 0)
        {
            using var rdataMs = new MemoryStream();
            using var rdataBw = new BinaryWriter(rdataMs);

            int descBlockSize = (imports.Length + 1) * 20;
            int curRelOffset = descBlockSize;

            var dllDescriptors = new List<(uint NameRva, uint ThunkRva, List<uint> HintRvas)>();

            foreach (var (dllName, funcs) in imports)
            {
                uint thunkRva = 0x2000u + (uint)curRelOffset;
                curRelOffset += (funcs.Length + 1) * 8;

                uint nameRva = 0x2000u + (uint)curRelOffset;
                curRelOffset += Encoding.ASCII.GetByteCount(dllName) + 1;

                var hintRvas = new List<uint>();
                foreach (var f in funcs)
                {
                    uint hintRva = 0x2000u + (uint)curRelOffset;
                    hintRvas.Add(hintRva);
                    curRelOffset += 2 + Encoding.ASCII.GetByteCount(f) + 1;
                }

                dllDescriptors.Add((nameRva, thunkRva, hintRvas));
            }

            // Write descriptors
            for (int i = 0; i < imports.Length; i++)
            {
                var desc = dllDescriptors[i];
                rdataBw.Write(desc.ThunkRva); // OriginalFirstThunk
                rdataBw.Write(0u);            // TimeDateStamp
                rdataBw.Write(0u);            // ForwarderChain
                rdataBw.Write(desc.NameRva);   // NameRva
                rdataBw.Write(desc.ThunkRva);  // FirstThunk
            }
            rdataBw.Write(new byte[20]); // Null descriptor

            // Write tables and strings
            for (int i = 0; i < imports.Length; i++)
            {
                var (dllName, funcs) = imports[i];
                var desc = dllDescriptors[i];

                // 1. ILT array
                for (int j = 0; j < funcs.Length; j++)
                {
                    rdataBw.Write((ulong)desc.HintRvas[j]);
                }
                rdataBw.Write(0UL); // Null thunk

                // 2. DLL name
                rdataBw.Write(Encoding.ASCII.GetBytes(dllName));
                rdataBw.Write((byte)0);

                // 3. Hint-Name entries
                for (int j = 0; j < funcs.Length; j++)
                {
                    rdataBw.Write((ushort)0); // Hint
                    rdataBw.Write(Encoding.ASCII.GetBytes(funcs[j]));
                    rdataBw.Write((byte)0);
                }
            }

            rdataBw.Flush();
            byte[] rdataBytes = rdataMs.ToArray();
            bw.Write(rdataBytes);
        }

        // Pad to FileOffset 0x600 (.rsrc)
        while (ms.Position < 0x600)
            bw.Write((byte)0);

        // 7. Section 2 Body (.rsrc at 0x600, RVA 0x3000)
        // If iconBytes provided, construct a 3-level resource directory tree for RT_ICON (Type 3)
        if (iconBytes != null && iconBytes.Length > 0)
        {
            // Level 1: Type directory
            // Header: 16 bytes (Characteristics(4), TimeDateStamp(4), Major(2), Minor(2), Named(2)=0, IdEntries(2)=1)
            bw.Write(0u); bw.Write(0u); bw.Write((ushort)0); bw.Write((ushort)0);
            bw.Write((ushort)0); // Named entries = 0
            bw.Write((ushort)1); // ID entries = 1 (Type 3 = RT_ICON)
            // Entry 1: ID = 3, OffsetToData = 0x80000000 | 24 (offset to Level 2)
            bw.Write(3u); // ResourceTypeId = 3
            bw.Write(0x80000018u); // Subdirectory at offset 24

            // Level 2: Name/ID directory (offset 24 = 0x18)
            bw.Write(0u); bw.Write(0u); bw.Write((ushort)0); bw.Write((ushort)0);
            bw.Write((ushort)0);
            bw.Write((ushort)1); // ID entries = 1 (Icon ID 1)
            // Entry: ID = 1, OffsetToData = 0x80000000 | 48 (offset to Level 3)
            bw.Write(1u);
            bw.Write(0x80000030u); // Subdirectory at offset 48

            // Level 3: Language directory (offset 48 = 0x30)
            bw.Write(0u); bw.Write(0u); bw.Write((ushort)0); bw.Write((ushort)0);
            bw.Write((ushort)0);
            bw.Write((ushort)1); // ID entries = 1 (Lang 0)
            // Entry: Lang ID = 0, OffsetToData = 72 (Data entry, leaf, no high bit)
            bw.Write(0u); // Lang 0
            bw.Write(72u); // Data entry at offset 72

            // Resource Data Entry (offset 72 = 0x48, size 16 bytes)
            uint iconRva = 0x3000u + 88u; // immediately following data entry
            bw.Write(iconRva);
            bw.Write((uint)iconBytes.Length);
            bw.Write(0u); // CodePage
            bw.Write(0u); // Reserved

            // Write raw icon data (offset 88)
            bw.Write(iconBytes);
        }

        // Pad to FileOffset 0x800 (Security Directory) if cert exists
        if (cert != null)
        {
            while (ms.Position < 0x800)
                bw.Write((byte)0);

            byte[] rawCert = cert.RawData;
            uint dwLength = (uint)(8 + rawCert.Length);
            bw.Write(dwLength);
            bw.Write((ushort)0x0200); // wRevision = WIN_CERT_REVISION_2_0
            bw.Write((ushort)0x0002); // wCertificateType = WIN_CERT_TYPE_PKCS_SIGNED_DATA
            bw.Write(rawCert);
        }

        // Pad to multiple of FileAlignment (512)
        while (ms.Position % 512 != 0)
            bw.Write((byte)0);

        bw.Flush();
        return ms.ToArray();
    }

    /// <summary>
    /// Generates a self-signed X.509 certificate for deterministic Authenticode testing.
    /// </summary>
    public static X509Certificate2 GenerateSelfSignedCertificate(string subjectName)
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest($"CN={subjectName}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(365));
        return cert;
    }

    /// <summary>
    /// Generates a minimal 8x8 luminance byte array representing an icon.
    /// </summary>
    public static byte[] GenerateMockIconBytes(byte baseLuminance = 128)
    {
        byte[] bytes = new byte[64];
        for (int i = 0; i < 64; i++)
        {
            bytes[i] = (byte)((baseLuminance + i * 2) % 256);
        }
        return bytes;
    }
}
