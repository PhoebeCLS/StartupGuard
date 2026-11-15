using System.IO.MemoryMappedFiles;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using StartupGuard.Core.Models;

namespace StartupGuard.Core.Storage;

/// <summary>
/// 64字节 MMF 二进制快照文件头
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1, Size = 64)]
public struct MmfSnapshotHeader
{
    public const uint MagicHeader = 0x47505453; // "STPG"
    public const uint FormatVersion = 1;

    public uint Magic;
    public uint Version;
    public uint ItemCount;
    public uint BucketCount;
    public long LastUpdatedUtcMs;
    private ulong _reserved1;
    private ulong _reserved2;
    private ulong _reserved3;
    private ulong _reserved4;
    private ulong _reserved5;
}

/// <summary>
/// 256字节固定步长记录项 (直接内存指针映射，零堆分配比对)
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1, Size = 256)]
public unsafe struct MmfRecordEntry
{
    public MonitorCategory Category;          // 1 byte
    public InterceptionAction TargetAction;   // 1 byte
    public RuleMatchMode MatchMode;           // 1 byte
    public byte Flags;                        // 1 byte (bit0: HasSig, bit1: IsWhql)
    public float ConfidenceThreshold;         // 4 bytes
    public uint RuleId;                       // 4 bytes
    public uint EvolutionCount;               // 4 bytes
    public ulong NormalizedPathHash;          // 8 bytes (FNV-1a 64-bit)
    public ulong LocationKeyHash;             // 8 bytes (FNV-1a 64-bit)
    public ulong IconPerceptualHash;          // 8 bytes
    public fixed byte RawMD5[16];             // 16 bytes
    public fixed byte RawSHA256[32];          // 32 bytes
    public fixed byte SignerThumbprint[20];   // 20 bytes
    public SixDimensionWeights Weights;       // 24 bytes (6 * float)
    public fixed byte ReservedPayload[124];   // 124 bytes (Total = 256 bytes)

    public readonly bool HasSignature => (Flags & 0x01) != 0;
    public readonly bool IsWhqlCertified => (Flags & 0x02) != 0;

    /// <summary>
    /// 从持久化规则模型转换为 256 字节定长 MMF 记录项
    /// </summary>
    public static MmfRecordEntry FromRule(RuleRecord rule)
    {
        var entry = new MmfRecordEntry
        {
            Category = rule.Category,
            TargetAction = rule.ActionType,
            MatchMode = rule.RuleMode,
            Flags = (byte)(rule.HasSignature ? 0x01 : 0x00),
            ConfidenceThreshold = rule.ConfidenceThreshold,
            RuleId = (uint)Math.Max(0, rule.RuleId),
            EvolutionCount = (uint)Math.Max(0, rule.EvolutionCount),
            NormalizedPathHash = MmfBinaryStore.ComputeFnv1a64(rule.NormalizedPath),
            LocationKeyHash = MmfBinaryStore.ComputeFnv1a64(rule.LocationKey),
            IconPerceptualHash = rule.IconPHash,
            Weights = rule.Weights
        };

        WriteHexToFixedBuffer(rule.CurrentMD5, new Span<byte>(entry.RawMD5, 16));
        WriteHexToFixedBuffer(rule.CurrentSHA256, new Span<byte>(entry.RawSHA256, 32));
        WriteHexToFixedBuffer(rule.RootCertThumbprint, new Span<byte>(entry.SignerThumbprint, 20));
        return entry;
    }

    /// <summary>
    /// 从实时扫描的目标特征转换为 256 字节定长 MMF 基准快照记录项
    /// </summary>
    public static MmfRecordEntry FromBaselineFeatures(TargetProgramFeatures features, InterceptionAction action)
    {
        byte flags = 0;
        if (features.HasValidSignature) flags |= 0x01;
        if (features.IsWhqlCertified) flags |= 0x02;

        var entry = new MmfRecordEntry
        {
            Category = features.Category,
            TargetAction = action,
            MatchMode = RuleMatchMode.PermanentAdaptive,
            Flags = flags,
            ConfidenceThreshold = 85.0f,
            RuleId = 0,
            EvolutionCount = 0,
            NormalizedPathHash = features.NormalizedPathHash != 0
                ? features.NormalizedPathHash
                : MmfBinaryStore.ComputeFnv1a64(features.NormalizedPath),
            LocationKeyHash = MmfBinaryStore.ComputeFnv1a64(features.LocationKeyOrIdentifier),
            IconPerceptualHash = features.IconPerceptualHash,
            Weights = SixDimensionWeights.CreateDefault()
        };

        WriteHexToFixedBuffer(features.MD5Hex, new Span<byte>(entry.RawMD5, 16));
        WriteHexToFixedBuffer(features.SHA256Hex, new Span<byte>(entry.RawSHA256, 32));
        WriteHexToFixedBuffer(features.RootCertThumbprint, new Span<byte>(entry.SignerThumbprint, 20));
        return entry;
    }

    private static void WriteHexToFixedBuffer(string? hex, Span<byte> destination)
    {
        destination.Clear();
        if (string.IsNullOrWhiteSpace(hex))
            return;

        string trimmed = hex.Trim();
        int maxHexChars = Math.Min(trimmed.Length & ~1, destination.Length * 2);
        if (maxHexChars <= 0)
            return;

        try
        {
            byte[] decoded = Convert.FromHexString(trimmed.AsSpan(0, maxHexChars));
            decoded.AsSpan(0, Math.Min(decoded.Length, destination.Length)).CopyTo(destination);
        }
        catch
        {
            destination.Clear();
        }
    }
}

/// <summary>
/// 内存映射规则快照存储（用于 baseline.bin 与 rules.bin 启动初始化比对）
/// </summary>
public sealed unsafe class MmfBinaryStore : IDisposable
{
    private readonly string _filePath;
    private MemoryMappedFile? _mmf;
    private MemoryMappedViewAccessor? _accessor;
    private byte* _basePtr;
    private int _itemCount;

    public MmfBinaryStore(string filePath)
    {
        _filePath = filePath;
    }

    public int Count => _itemCount;

    /// <summary>
    /// 将二进制文件映射至进程虚拟地址空间
    /// </summary>
    public bool LoadIntoMemory()
    {
        Unload();
        if (!File.Exists(_filePath))
            return false;

        var fileInfo = new FileInfo(_filePath);
        if (fileInfo.Length < sizeof(MmfSnapshotHeader))
            return false;

        _mmf = MemoryMappedFile.CreateFromFile(_filePath, FileMode.Open, null, 0, MemoryMappedFileAccess.Read);
        _accessor = _mmf.CreateViewAccessor(0, fileInfo.Length, MemoryMappedFileAccess.Read);
        _accessor.SafeMemoryMappedViewHandle.AcquirePointer(ref _basePtr);

        var header = Unsafe.ReadUnaligned<MmfSnapshotHeader>(_basePtr);
        long expectedMinSize = sizeof(MmfSnapshotHeader) + (long)header.ItemCount * sizeof(MmfRecordEntry);
        if (header.Magic != MmfSnapshotHeader.MagicHeader ||
            header.Version != MmfSnapshotHeader.FormatVersion ||
            fileInfo.Length < expectedMinSize)
        {
            Unload();
            return false;
        }

        _itemCount = (int)header.ItemCount;
        return true;
    }

    /// <summary>
    /// 零分配查找是否存在完全相同的 MD5 或 LocationKeyHash
    /// </summary>
    public bool TryFindByMd5OrLocation(ReadOnlySpan<byte> md5Bytes, ulong locationHash, out MmfRecordEntry matchedEntry)
    {
        matchedEntry = default;
        if (_basePtr == null || _itemCount == 0)
            return false;

        bool hasSearchMd5 = md5Bytes.Length == 16 && IsNonZero(md5Bytes);
        MmfRecordEntry* recordsBase = (MmfRecordEntry*)(_basePtr + sizeof(MmfSnapshotHeader));
        for (int i = 0; i < _itemCount; i++)
        {
            MmfRecordEntry* current = recordsBase + i;
            if (locationHash != 0 && current->LocationKeyHash == locationHash)
            {
                matchedEntry = *current;
                return true;
            }

            if (hasSearchMd5)
            {
                ReadOnlySpan<byte> entryMd5 = new(current->RawMD5, 16);
                if (entryMd5.SequenceEqual(md5Bytes))
                {
                    matchedEntry = *current;
                    return true;
                }
            }
        }

        return false;
    }

    private static bool IsNonZero(ReadOnlySpan<byte> span)
    {
        foreach (byte b in span)
        {
            if (b != 0) return true;
        }
        return false;
    }

    /// <summary>
    /// 原子重写整个快照文件并刷新内存映射 (当 Baseline 或 Rules 更新时调用)
    /// </summary>
    public void SaveEntriesAtomically(ReadOnlySpan<MmfRecordEntry> entries)
    {
        Unload();
        string? dir = Path.GetDirectoryName(_filePath);
        if (!string.IsNullOrEmpty(dir))
            Directory.CreateDirectory(dir);

        string tempPath = _filePath + ".tmp";
        long totalSize = sizeof(MmfSnapshotHeader) + (long)entries.Length * sizeof(MmfRecordEntry);

        using (var fs = new FileStream(tempPath, FileMode.Create, FileAccess.Write, FileShare.None, 4096))
        {
            MmfSnapshotHeader header = new()
            {
                Magic = MmfSnapshotHeader.MagicHeader,
                Version = MmfSnapshotHeader.FormatVersion,
                ItemCount = (uint)entries.Length,
                BucketCount = (uint)Math.Max(16, entries.Length * 2),
                LastUpdatedUtcMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
            };

            Span<byte> headerSpan = new(&header, sizeof(MmfSnapshotHeader));
            fs.Write(headerSpan);

            fixed (MmfRecordEntry* pEntries = entries)
            {
                ReadOnlySpan<byte> bodySpan = new(pEntries, entries.Length * sizeof(MmfRecordEntry));
                fs.Write(bodySpan);
            }
            fs.Flush(true);
        }

        File.Move(tempPath, _filePath, overwrite: true);
        LoadIntoMemory();
    }

    /// <summary>
    /// 64-bit FNV-1a 零分配哈希计算
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong ComputeFnv1a64(ReadOnlySpan<char> text)
    {
        const ulong fnvOffsetBasis = 14695981039346656037UL;
        const ulong fnvPrime = 1099511628211UL;

        ulong hash = fnvOffsetBasis;
        for (int i = 0; i < text.Length; i++)
        {
            char c = char.ToLowerInvariant(text[i]);
            hash ^= (byte)(c & 0xFF);
            hash *= fnvPrime;
            hash ^= (byte)(c >> 8);
            hash *= fnvPrime;
        }
        return hash;
    }

    public void Unload()
    {
        if (_basePtr != null && _accessor != null)
        {
            _accessor.SafeMemoryMappedViewHandle.ReleasePointer();
            _basePtr = null;
        }
        _accessor?.Dispose();
        _accessor = null;
        _mmf?.Dispose();
        _mmf = null;
        _itemCount = 0;
    }

    public void Dispose() => Unload();
}
