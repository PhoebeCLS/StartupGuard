using System.Runtime.InteropServices;

namespace StartupGuard.Core.Native;

/// <summary>
/// Windows 11 进程级 EcoQoS (能效核调度) 与物理内存工作集极限压缩控制器
/// (确保 StartupGuard.Service.exe < 8MB, StartupGuard.TrayHost.exe < 5MB)
/// </summary>
public static unsafe partial class ProcessQoSAndMemoryManager
{
    private const string Kernel32Dll = "kernel32.dll";

    [LibraryImport(Kernel32Dll)]
    private static partial nint GetCurrentProcess();

    [LibraryImport(Kernel32Dll)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetProcessInformation(
        nint hProcess,
        int processInformationClass,
        void* processInformation,
        uint processInformationSize);

    [LibraryImport(Kernel32Dll)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetPriorityClass(nint hProcess, uint dwPriorityClass);

    [LibraryImport(Kernel32Dll)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetProcessWorkingSetSizeEx(
        nint hProcess,
        nuint dwMinimumWorkingSetSize,
        nuint dwMaximumWorkingSetSize,
        uint flags);

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_POWER_THROTTLING_STATE
    {
        public uint Version;
        public uint ControlMask;
        public uint StateMask;
    }

    private const int ProcessPowerThrottling = 4;
    private const uint PROCESS_POWER_THROTTLING_CURRENT_VERSION = 1;
    private const uint PROCESS_POWER_THROTTLING_EXECUTION_SPEED = 0x1;
    private const uint IDLE_PRIORITY_CLASS = 0x00000040;
    private const uint NORMAL_PRIORITY_CLASS = 0x00000020;
    private const uint HIGH_PRIORITY_CLASS = 0x00000080;

    /// <summary>
    /// 空闲监听态：开启 Windows 11 EcoQoS (Efficiency Mode)，自动将线程调度至 E-Core (能效核)
    /// </summary>
    public static void EnterEcoEfficiencyMode()
    {
        if (!OperatingSystem.IsWindows())
            return;

        nint hProcess = GetCurrentProcess();
        PROCESS_POWER_THROTTLING_STATE state = new()
        {
            Version = PROCESS_POWER_THROTTLING_CURRENT_VERSION,
            ControlMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED,
            StateMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED
        };

        SetProcessInformation(hProcess, ProcessPowerThrottling, &state, (uint)sizeof(PROCESS_POWER_THROTTLING_STATE));
        SetPriorityClass(hProcess, IDLE_PRIORITY_CLASS);
    }

    /// <summary>
    /// 监控触发瞬态：瞬时解除 EcoQoS 并提权至高性能核心 (P-Core)，保障弹窗与回滚 &lt; 50ms
    /// </summary>
    public static void BoostToHighPerformanceMode()
    {
        if (!OperatingSystem.IsWindows())
            return;

        nint hProcess = GetCurrentProcess();
        PROCESS_POWER_THROTTLING_STATE state = new()
        {
            Version = PROCESS_POWER_THROTTLING_CURRENT_VERSION,
            ControlMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED,
            StateMask = 0 // 0 = 关闭限速
        };

        SetProcessInformation(hProcess, ProcessPowerThrottling, &state, (uint)sizeof(PROCESS_POWER_THROTTLING_STATE));
        SetPriorityClass(hProcess, HIGH_PRIORITY_CLASS);
    }

    /// <summary>
    /// 回收无用物理内存页，强制修剪进程 Working Set
    /// </summary>
    public static void TrimWorkingSetMemory()
    {
        GC.Collect(2, GCCollectionMode.Aggressive, blocking: true, compacting: true);
        if (!OperatingSystem.IsWindows())
            return;

        nint hProcess = GetCurrentProcess();
        nuint emptySize = unchecked((nuint)(-1));
        SetProcessWorkingSetSizeEx(hProcess, emptySize, emptySize, 0);
    }
}
