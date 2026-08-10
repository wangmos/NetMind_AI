using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace NetMind.Core;

/// <summary>
/// Windows 作业对象沙箱封装；对跨进程宿主（SandboxHost/CoreHost）公开，供监管长驻工作进程复用。
/// </summary>
public sealed class WindowsJobObject : IDisposable
{
    private const uint JobObjectLimitProcessTime = 0x00000002;
    private const uint JobObjectLimitActiveProcess = 0x00000008;
    private const uint JobObjectLimitProcessMemory = 0x00000100;
    private const uint JobObjectLimitKillOnJobClose = 0x00002000;
    private readonly SafeFileHandle _handle;

    private WindowsJobObject(SafeFileHandle handle)
    {
        _handle = handle;
    }

    public static WindowsJobObject Create(TimeSpan processorTimeLimit, long processMemoryLimitBytes)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Windows Job Object 仅支持 Windows。 ");
        var rawHandle = CreateJobObject(IntPtr.Zero, null);
        if (rawHandle == IntPtr.Zero || rawHandle == new IntPtr(-1)) throw new Win32Exception(Marshal.GetLastWin32Error(), "无法创建 Windows 沙箱作业对象。");
        var handle = new SafeFileHandle(rawHandle, ownsHandle: true);
        try
        {
            var information = new JobObjectExtendedLimitInformation
            {
                BasicLimitInformation = new JobObjectBasicLimitInformation
                {
                    PerProcessUserTimeLimit = Math.Max(1, processorTimeLimit.Ticks),
                    ActiveProcessLimit = 1,
                    LimitFlags = JobObjectLimitProcessTime | JobObjectLimitActiveProcess |
                                 JobObjectLimitProcessMemory | JobObjectLimitKillOnJobClose
                },
                ProcessMemoryLimit = new UIntPtr((ulong)processMemoryLimitBytes)
            };
            var length = Marshal.SizeOf<JobObjectExtendedLimitInformation>();
            var pointer = Marshal.AllocHGlobal(length);
            try
            {
                Marshal.StructureToPtr(information, pointer, false);
                if (!SetInformationJobObject(handle.DangerousGetHandle(), JobObjectInfoClass.ExtendedLimitInformation, pointer, (uint)length))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "无法配置 Windows 沙箱资源限制。");
            }
            finally
            {
                Marshal.FreeHGlobal(pointer);
            }
            return new WindowsJobObject(handle);
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    /// <summary>
    /// 创建长驻模式沙箱作业对象：保留内存上限、单进程限制与宿主句柄关闭即终止（KILL_ON_JOB_CLOSE），
    /// 但不设累计 CPU 时限（PerProcessUserTimeLimit），避免长驻钩子工作进程因累计用户态时间耗尽被杀。
    /// </summary>
    public static WindowsJobObject CreateResident(long processMemoryLimitBytes)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Windows Job Object 仅支持 Windows。 ");
        var rawHandle = CreateJobObject(IntPtr.Zero, null);
        if (rawHandle == IntPtr.Zero || rawHandle == new IntPtr(-1)) throw new Win32Exception(Marshal.GetLastWin32Error(), "无法创建 Windows 沙箱作业对象。");
        var handle = new SafeFileHandle(rawHandle, ownsHandle: true);
        try
        {
            var information = new JobObjectExtendedLimitInformation
            {
                BasicLimitInformation = new JobObjectBasicLimitInformation
                {
                    ActiveProcessLimit = 1,
                    LimitFlags = JobObjectLimitActiveProcess |
                                 JobObjectLimitProcessMemory | JobObjectLimitKillOnJobClose
                },
                ProcessMemoryLimit = new UIntPtr((ulong)processMemoryLimitBytes)
            };
            var length = Marshal.SizeOf<JobObjectExtendedLimitInformation>();
            var pointer = Marshal.AllocHGlobal(length);
            try
            {
                Marshal.StructureToPtr(information, pointer, false);
                if (!SetInformationJobObject(handle.DangerousGetHandle(), JobObjectInfoClass.ExtendedLimitInformation, pointer, (uint)length))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "无法配置 Windows 沙箱资源限制。");
            }
            finally
            {
                Marshal.FreeHGlobal(pointer);
            }
            return new WindowsJobObject(handle);
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    public void Assign(Process process)
    {
        if (process.HasExited) throw new InvalidOperationException("Python 进程在加入 Windows 沙箱前已退出。");
        if (!AssignProcessToJobObject(_handle.DangerousGetHandle(), process.Handle))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "无法把 Python 进程加入 Windows 沙箱。");
    }

    public void Dispose() => _handle.Dispose();

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectBasicLimitInformation
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoCounters
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectExtendedLimitInformation
    {
        public JobObjectBasicLimitInformation BasicLimitInformation;
        public IoCounters IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    private enum JobObjectInfoClass
    {
        ExtendedLimitInformation = 9
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateJobObject(IntPtr jobAttributes, string? name);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetInformationJobObject(IntPtr job, JobObjectInfoClass informationClass, IntPtr information, uint informationLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
}
