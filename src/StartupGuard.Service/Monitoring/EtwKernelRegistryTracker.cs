using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using StartupGuard.Core.Storage;

namespace StartupGuard.Service.Monitoring;

/// <summary>
/// 轻量级 Microsoft-Windows-Kernel-Registry ETW 实时环形缓冲追踪器
/// 用于与 RegNotifyChangeKeyValue 双轨协同，精准溯源发起注册表写入的安装器进程 PID
/// </summary>
public sealed unsafe partial class EtwKernelRegistryTracker : IDisposable
{
    private const string AdvApi32Dll = "advapi32.dll";
    private const string SechostDll = "sechost.dll";

    // Microsoft-Windows-Kernel-Registry Provider GUID: {70EB4F03-C1DE-4F73-A051-33D13D5413BD}
    public static readonly Guid KernelRegistryProviderGuid = new(0x70EB4F03, 0xC1DE, 0x4F73, 0xA0, 0x51, 0x33, 0xD1, 0x3D, 0x54, 0x13, 0xBD);

    [LibraryImport(AdvApi32Dll, EntryPoint = "StartTraceW", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    private static partial uint StartTraceW(out ulong pSessionHandle, string sessionName, void* properties);

    [LibraryImport(AdvApi32Dll, EntryPoint = "ControlTraceW", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    private static partial uint ControlTraceW(ulong sessionHandle, string? sessionName, void* properties, uint controlCode);

    [LibraryImport(AdvApi32Dll, EntryPoint = "EnableTraceEx2", SetLastError = true)]
    private static partial uint EnableTraceEx2(
        ulong traceHandle,
        in Guid providerId,
        uint controlCode,
        byte level,
        ulong matchAnyKeyword,
        ulong matchAllKeyword,
        uint timeout,
        void* enableParameters);

    private const uint EVENT_TRACE_CONTROL_STOP = 1;
    private const uint EVENT_TRACE_REAL_TIME_MODE = 0x00000100;
    private const uint PROCESS_TRACE_MODE_REAL_TIME = 0x00000100;
    private const uint PROCESS_TRACE_MODE_EVENT_RECORD = 0x10000000;
    private const uint WNODE_FLAG_TRACED_GUID = 0x00020000;
    private const ulong INVALID_PROCESSTRACE_HANDLE = unchecked((ulong)-1);
    private const string SessionName = "StartupGuard_KernelRegistry_Trace";

    [LibraryImport(AdvApi32Dll, EntryPoint = "OpenTraceW", SetLastError = true)]
    private static partial ulong OpenTraceW(void* logfile);

    [LibraryImport(AdvApi32Dll, EntryPoint = "ProcessTrace", SetLastError = true)]
    private static partial uint ProcessTrace(ulong* handleArray, uint handleCount, void* startTime, void* endTime);

    [LibraryImport(AdvApi32Dll, EntryPoint = "CloseTrace", SetLastError = true)]
    private static partial uint CloseTrace(ulong traceHandle);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate void EventRecordCallbackDelegate(void* eventRecord);

    /// <summary>
    /// 固定容量无锁环形缓冲区 (128 槽位，记录最近的 [KeyPathHash -> WriterPID])
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct RecentWriteSlot
    {
        public ulong KeyNameHash;
        public uint WriterProcessId;
        public long TimestampTicks;
    }

    private const int RingCapacity = 128;
    private static readonly ulong HintRunHash = MmfBinaryStore.ComputeFnv1a64("hint:run");
    private static readonly ulong HintServicesHash = MmfBinaryStore.ComputeFnv1a64("hint:services");
    private static readonly ulong HintTasksHash = MmfBinaryStore.ComputeFnv1a64("hint:tasks");
    private static readonly ulong HintContextMenuHash = MmfBinaryStore.ComputeFnv1a64("hint:contextmenu");

    private readonly RecentWriteSlot[] _ringBuffer = new RecentWriteSlot[RingCapacity];
    private readonly int _selfPid = Environment.ProcessId;
    private int _writeCursor;
    private ulong _sessionHandle;
    private ulong _consumerHandle = INVALID_PROCESSTRACE_HANDLE;
    private bool _sessionStarted;
    private EventRecordCallbackDelegate? _callbackKeepAlive;
    private GCHandle _sessionNameHandle;
    private Thread? _consumerThread;

    public EtwKernelRegistryTracker()
    {
        TryStartEtwKernelSession();
    }

    private void TryStartEtwKernelSession()
    {
        if (!OperatingSystem.IsWindows() || !Environment.Is64BitProcess)
            return;

        try
        {
            const uint propsStructSize = 120;
            byte[] propBuf = new byte[1024];
            fixed (byte* pProp = propBuf)
            {
                Array.Clear(propBuf);
                *(uint*)pProp = (uint)propBuf.Length;               // Wnode.BufferSize
                *(uint*)(pProp + 44) = WNODE_FLAG_TRACED_GUID;      // Wnode.Flags
                *(uint*)(pProp + 116) = propsStructSize;            // LoggerNameOffset

                // 先停止残留会话
                ControlTraceW(0, SessionName, pProp, EVENT_TRACE_CONTROL_STOP);

                Array.Clear(propBuf);
                *(uint*)pProp = (uint)propBuf.Length;               // Wnode.BufferSize
                *(uint*)(pProp + 40) = 1;                           // Wnode.ClientContext = QPC
                *(uint*)(pProp + 44) = WNODE_FLAG_TRACED_GUID;      // Wnode.Flags
                *(uint*)(pProp + 48) = 64;                          // BufferSize (KB)
                *(uint*)(pProp + 64) = EVENT_TRACE_REAL_TIME_MODE;  // LogFileMode
                *(uint*)(pProp + 68) = 1;                           // FlushTimer (1s)
                *(uint*)(pProp + 116) = propsStructSize;            // LoggerNameOffset

                uint status = StartTraceW(out _sessionHandle, SessionName, pProp);
                if (status != 0)
                    return;

                _sessionStarted = true;
                EnableTraceEx2(
                    _sessionHandle,
                    in KernelRegistryProviderGuid,
                    1 /* EVENT_CONTROL_CODE_ENABLE_PROVIDER */,
                    4 /* TRACE_LEVEL_INFORMATION */,
                    0x20 /* KERNEL_REGISTRY_KEYWORD_WRITE */,
                    0,
                    0,
                    null);

                StartConsumerThread();
            }
        }
        catch
        {
            _sessionStarted = false;
        }
    }

    private void StartConsumerThread()
    {
        try
        {
            _callbackKeepAlive = OnEventRecord;
            IntPtr cbPtr = Marshal.GetFunctionPointerForDelegate(_callbackKeepAlive);

            char[] nameChars = (SessionName + "\0").ToCharArray();
            _sessionNameHandle = GCHandle.Alloc(nameChars, GCHandleType.Pinned);

            // EVENT_TRACE_LOGFILEW 在 x64 下的精确 448 字节布局
            byte[] logfileBuf = new byte[448];
            fixed (byte* pLog = logfileBuf)
            {
                *(nint*)(pLog + 8) = _sessionNameHandle.AddrOfPinnedObject(); // LoggerName
                *(uint*)(pLog + 28) = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD; // ProcessTraceMode
                *(nint*)(pLog + 424) = cbPtr;                                 // EventRecordCallback
                _consumerHandle = OpenTraceW(pLog);
            }

            if (_consumerHandle == INVALID_PROCESSTRACE_HANDLE || _consumerHandle == 0)
            {
                _consumerHandle = INVALID_PROCESSTRACE_HANDLE;
                return;
            }

            _consumerThread = new Thread(() =>
            {
                try
                {
                    ulong h = _consumerHandle;
                    if (h != INVALID_PROCESSTRACE_HANDLE && h != 0)
                    {
                        ProcessTrace(&h, 1, null, null);
                    }
                }
                catch { }
            })
            {
                IsBackground = true,
                Name = "StartupGuard_ETW_RegistryConsumer"
            };
            _consumerThread.Start();
        }
        catch
        {
            _consumerHandle = INVALID_PROCESSTRACE_HANDLE;
        }
    }

    private void OnEventRecord(void* eventRecordPtr)
    {
        if (eventRecordPtr == null) return;
        byte* p = (byte*)eventRecordPtr;

        // EVENT_HEADER: ProcessId offset = 12; UserDataLength offset = 86; UserData pointer offset = 96
        uint pid = *(uint*)(p + 12);
        if (pid <= 4 || pid == (uint)_selfPid)
            return;

        ushort userDataLen = *(ushort*)(p + 86);
        byte* userData = *(byte**)(p + 96);

        ulong keyHash = 0;
        if (userData != null && userDataLen >= 16 && userDataLen <= 2048)
        {
            // 直接在栈上提取可见字符 Span 并计算提示哈希，消除高频 ETW 回调堆字符串分配
            int charCount = userDataLen / 2;
            Span<char> buf = stackalloc char[Math.Min(charCount, 260)];
            int outLen = ExtractAsciiSafeUnicodeSpan(userData, charCount, buf);
            if (outLen >= 6)
            {
                keyHash = ComputeLowerHintHash(buf[..outLen]);
            }
        }

        RecordRegistryWriteEvent(keyHash, pid);
    }

    private static int ExtractAsciiSafeUnicodeSpan(byte* data, int charCount, Span<char> buf)
    {
        int outLen = 0;
        for (int i = 0; i < charCount && outLen < buf.Length; i++)
        {
            char c = *(char*)(data + i * 2);
            if (c >= 0x20 && c < 0x7F)
                buf[outLen++] = c;
            else if (outLen >= 6)
                buf[outLen++] = ' ';
            else
                outLen = 0;
        }
        return outLen;
    }

    internal static ulong ComputeLowerHintHash(ReadOnlySpan<char> text)
    {
        if (text.Contains(@"\Run".AsSpan(), StringComparison.OrdinalIgnoreCase))
            return HintRunHash;
        if (text.Contains(@"\Services\".AsSpan(), StringComparison.OrdinalIgnoreCase))
            return HintServicesHash;
        if (text.Contains(@"\TaskCache\".AsSpan(), StringComparison.OrdinalIgnoreCase))
            return HintTasksHash;
        if (text.Contains(@"\ContextMenuHandlers".AsSpan(), StringComparison.OrdinalIgnoreCase) ||
            text.Contains(@"\DragDropHandlers".AsSpan(), StringComparison.OrdinalIgnoreCase) ||
            text.Contains(@"\shell\".AsSpan(), StringComparison.OrdinalIgnoreCase) ||
            text.Contains("PackagedCom".AsSpan(), StringComparison.OrdinalIgnoreCase))
            return HintContextMenuHash;
        return 0;
    }

    /// <summary>
    /// 记录由 ETW 回调捕获到的注册表键写入事件及源进程 PID
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void RecordRegistryWriteEvent(ulong keyOrValueHash, uint processId)
    {
        int slotIdx = Interlocked.Increment(ref _writeCursor) & (RingCapacity - 1);
        _ringBuffer[slotIdx] = new RecentWriteSlot
        {
            KeyNameHash = keyOrValueHash,
            WriterProcessId = processId,
            TimestampTicks = Environment.TickCount64
        };
    }

    /// <summary>
    /// 当 RegNotifyChangeKeyValue 触发时，在环形缓冲中反查最近 2500ms 内写入该键或其类别提示的进程 PID
    /// </summary>
    public uint ResolveRecentWriterPid(ulong keyOrValueHash, string? subKeyPath = null)
    {
        long now = Environment.TickCount64;
        ulong categoryHintHash = 0;
        if (!string.IsNullOrEmpty(subKeyPath))
        {
            Span<char> prefixed = subKeyPath.Length <= 256
                ? stackalloc char[subKeyPath.Length + 1]
                : new char[subKeyPath.Length + 1];
            prefixed[0] = '\\';
            subKeyPath.AsSpan().CopyTo(prefixed[1..]);
            categoryHintHash = ComputeLowerHintHash(prefixed);
        }

        uint fallbackLatestPid = 0;
        long latestTick = 0;

        for (int i = 0; i < RingCapacity; i++)
        {
            var slot = _ringBuffer[i];
            if (slot.WriterProcessId == 0 || now - slot.TimestampTicks > 2500)
                continue;

            if (slot.KeyNameHash != 0 &&
                (slot.KeyNameHash == keyOrValueHash || (categoryHintHash != 0 && slot.KeyNameHash == categoryHintHash)))
                return slot.WriterProcessId;

            if (slot.TimestampTicks > latestTick)
            {
                latestTick = slot.TimestampTicks;
                fallbackLatestPid = slot.WriterProcessId;
            }
        }

        return fallbackLatestPid;
    }

    public void Dispose()
    {
        if (_consumerHandle != INVALID_PROCESSTRACE_HANDLE && _consumerHandle != 0 && OperatingSystem.IsWindows())
        {
            try { CloseTrace(_consumerHandle); } catch { }
            _consumerHandle = INVALID_PROCESSTRACE_HANDLE;
        }

        if (_sessionStarted && OperatingSystem.IsWindows())
        {
            try
            {
                byte[] propBuf = new byte[1024];
                fixed (byte* pProp = propBuf)
                {
                    *(uint*)pProp = (uint)propBuf.Length;
                    *(uint*)(pProp + 44) = WNODE_FLAG_TRACED_GUID;
                    *(uint*)(pProp + 116) = 120;
                    ControlTraceW(_sessionHandle, null, pProp, EVENT_TRACE_CONTROL_STOP);
                }
            }
            catch { }
            _sessionStarted = false;
        }

        if (_sessionNameHandle.IsAllocated)
        {
            try { _sessionNameHandle.Free(); } catch { }
        }
        Array.Clear(_ringBuffer);
    }
}
