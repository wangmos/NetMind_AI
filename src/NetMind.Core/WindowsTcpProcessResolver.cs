using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;

namespace NetMind.Core;

public sealed record TcpProcessIdentity(int ProcessId, string ProcessName)
{
    public string DisplayName => $"{ProcessName}（PID {ProcessId}）";
}

public static class WindowsTcpProcessResolver
{
    private const int AddressFamilyIpv4 = 2;

    // Windows 套接字地址族常量：AF_INET6，用于查询 IPv6 TCP 表。
    private const int AddressFamilyIpv6 = 23;

    // IN6_ADDR 固定尺寸：IPv6 地址占 16 字节。
    private const int Ipv6AddressBytes = 16;
    private const uint ErrorInsufficientBuffer = 122;
    private static readonly TimeSpan CacheLifetime = TimeSpan.FromSeconds(2);
    private const int CacheCapacity = 4096;
    private static readonly object CacheGate = new();
    private static readonly Dictionary<string, (TcpProcessIdentity? Identity, DateTime ExpiresAtUtc)> IdentityCache = new(StringComparer.Ordinal);

    public static TcpProcessIdentity? Resolve(IPEndPoint clientEndpoint, IPEndPoint proxyEndpoint)
    {
        if (!OperatingSystem.IsWindows()) return null;

        Func<IPEndPoint, IPEndPoint, TcpProcessIdentity?> resolver;
        string cacheKey;
        if (clientEndpoint.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork &&
            proxyEndpoint.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            resolver = ResolveIpv4;
            cacheKey = clientEndpoint.Address + ":" + clientEndpoint.Port;
        }
        else if (clientEndpoint.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 &&
                 proxyEndpoint.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
        {
            resolver = ResolveIpv6;
            // IPv6 地址自带冒号，缓存键用方括号包裹避免歧义。
            cacheKey = "[" + clientEndpoint.Address + "]:" + clientEndpoint.Port;
        }
        else
        {
            return null;
        }

        // 短 TTL 缓存同时服务 IPv4 与 IPv6 路径，包含“未找到”结果，避免对同一连接重复全表扫描。
        var now = DateTime.UtcNow;
        lock (CacheGate)
        {
            if (IdentityCache.TryGetValue(cacheKey, out var cached) && cached.ExpiresAtUtc > now) return cached.Identity;
        }
        var identity = resolver(clientEndpoint, proxyEndpoint);
        lock (CacheGate)
        {
            if (IdentityCache.Count >= CacheCapacity) IdentityCache.Clear();
            IdentityCache[cacheKey] = (identity, DateTime.UtcNow.Add(CacheLifetime));
        }
        return identity;
    }

    private static TcpProcessIdentity? ResolveIpv4(IPEndPoint clientEndpoint, IPEndPoint proxyEndpoint)
    {
        var size = 0;
        var result = Native.GetExtendedTcpTable(IntPtr.Zero, ref size, true, AddressFamilyIpv4,
            TcpTableClass.OwnerPidAll, 0);
        if (result != ErrorInsufficientBuffer || size <= sizeof(int)) return null;

        var table = Marshal.AllocHGlobal(size);
        try
        {
            result = Native.GetExtendedTcpTable(table, ref size, true, AddressFamilyIpv4,
                TcpTableClass.OwnerPidAll, 0);
            if (result != 0) return null;

            var count = Marshal.ReadInt32(table);
            var rowSize = Marshal.SizeOf<MibTcpRowOwnerPid>();
            var rowPointer = IntPtr.Add(table, sizeof(int));
            for (var index = 0; index < count; index++, rowPointer = IntPtr.Add(rowPointer, rowSize))
            {
                var row = Marshal.PtrToStructure<MibTcpRowOwnerPid>(rowPointer);
                if (Port(row.LocalPort) != clientEndpoint.Port || Port(row.RemotePort) != proxyEndpoint.Port) continue;
                if (!Address(row.LocalAddress).Equals(clientEndpoint.Address) || !Address(row.RemoteAddress).Equals(proxyEndpoint.Address)) continue;
                try
                {
                    using var process = Process.GetProcessById(unchecked((int)row.OwningProcessId));
                    return new TcpProcessIdentity(process.Id, process.ProcessName);
                }
                catch (Exception exception) when (exception is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
                {
                    return new TcpProcessIdentity(unchecked((int)row.OwningProcessId), "未知进程");
                }
            }
            return null;
        }
        finally
        {
            Marshal.FreeHGlobal(table);
        }
    }

    private static TcpProcessIdentity? ResolveIpv6(IPEndPoint clientEndpoint, IPEndPoint proxyEndpoint)
    {
        var size = 0;
        var result = Native.GetExtendedTcpTable(IntPtr.Zero, ref size, true, AddressFamilyIpv6,
            TcpTableClass.OwnerPidAll, 0);
        if (result != ErrorInsufficientBuffer || size <= sizeof(int)) return null;

        var table = Marshal.AllocHGlobal(size);
        try
        {
            result = Native.GetExtendedTcpTable(table, ref size, true, AddressFamilyIpv6,
                TcpTableClass.OwnerPidAll, 0);
            if (result != 0) return null;

            var count = Marshal.ReadInt32(table);
            var rowSize = Marshal.SizeOf<MibTcp6RowOwnerPid>();
            var rowPointer = IntPtr.Add(table, sizeof(int));
            for (var index = 0; index < count; index++, rowPointer = IntPtr.Add(rowPointer, rowSize))
            {
                var row = Marshal.PtrToStructure<MibTcp6RowOwnerPid>(rowPointer);
                if (Port(row.LocalPort) != clientEndpoint.Port || Port(row.RemotePort) != proxyEndpoint.Port) continue;
                if (!Ipv6Address(row.LocalAddress).Equals(clientEndpoint.Address) ||
                    !Ipv6Address(row.RemoteAddress).Equals(proxyEndpoint.Address)) continue;
                try
                {
                    using var process = Process.GetProcessById(unchecked((int)row.OwningProcessId));
                    return new TcpProcessIdentity(process.Id, process.ProcessName);
                }
                catch (Exception exception) when (exception is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
                {
                    return new TcpProcessIdentity(unchecked((int)row.OwningProcessId), "未知进程");
                }
            }
            return null;
        }
        finally
        {
            Marshal.FreeHGlobal(table);
        }
    }

    private static IPAddress Ipv6Address(byte[] bytes) => new(bytes);

    private static int Port(uint value)
    {
        var bytes = BitConverter.GetBytes(value);
        return bytes[0] * 256 + bytes[1];
    }

    private static IPAddress Address(uint value) => new(BitConverter.GetBytes(value));

    private enum TcpTableClass
    {
        OwnerPidAll = 5
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcpRowOwnerPid
    {
        public uint State;
        public uint LocalAddress;
        public uint LocalPort;
        public uint RemoteAddress;
        public uint RemotePort;
        public uint OwningProcessId;
    }

    // MIB_TCP6ROW_OWNER_PID：按 Windows 官方布局，地址字段为 16 字节 IN6_ADDR。
    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcp6RowOwnerPid
    {
        public uint State;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = Ipv6AddressBytes)]
        public byte[] LocalAddress;
        public uint LocalScopeId;
        public uint LocalPort;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = Ipv6AddressBytes)]
        public byte[] RemoteAddress;
        public uint RemoteScopeId;
        public uint RemotePort;
        public uint OwningProcessId;
    }

    private static class Native
    {
        [DllImport("iphlpapi.dll", SetLastError = true)]
        internal static extern uint GetExtendedTcpTable(IntPtr table, ref int size, [MarshalAs(UnmanagedType.Bool)] bool order,
            int addressFamily, TcpTableClass tableClass, uint reserved);
    }
}
