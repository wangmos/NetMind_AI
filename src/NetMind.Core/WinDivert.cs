using System.Net;
using System.Runtime.InteropServices;

namespace NetMind.Core;

/// <summary>
/// WinDivert 2.x 网络层地址（与 windivert.h 的 WINDIVERT_ADDRESS 布局对齐）：
/// INT64 Timestamp(0)；UINT64 位域(8)：Layer:8/Event:8/Sniffed:1(16)/Outbound:1(17)/Loopback:1(18)/
/// Impostor:1(19)/IPv6:1(20)/IPChecksum:1(21)/TCPChecksum:1(22)/UDPChecksum:1(23)；
/// 联合体(16)：NETWORK 层只携带 IfIdx/SubIfIdx。按 80 字节预留，原生只写前 24 字节。
/// </summary>
[StructLayout(LayoutKind.Explicit, Size = 80)]
public struct WinDivertAddress
{
    [FieldOffset(0)] public long Timestamp;
    // 位域整体占偏移 8 处的 UINT64；所有标志位均落在低 32 位，按 uint 读低半即可。
    [FieldOffset(8)] public uint LayerEventFlags;
    [FieldOffset(16)] public uint IfIdx;
    [FieldOffset(20)] public uint SubIfIdx;

    /// <summary>位域中的 IPv6 位（bit20）；bit21-23 是校验和标志，切勿混用。</summary>
    public const uint FlagIpv6 = 1u << 20;

    /// <summary>位域中的 Outbound 位（bit17）：报文方向为本机发出。</summary>
    public const uint FlagOutbound = 1u << 17;
}

/// <summary>
/// WinDivert 2.x P/Invoke 封装：只以被动嗅探（SNIFF，值为 1）方式捕获，不拦截、不修改、不重注入报文。
/// 注意切勿误用 SEND_ONLY（值为 8）：非嗅探模式会拦截报文等待重注入，未重注入将导致整机断网。
/// 依赖 WinDivert.dll 与 WinDivert64.sys 随采集后台部署；缺失时给出中文指引。
/// </summary>
public static class WinDivert
{
    private const string LibraryName = "WinDivert.dll";
    private const uint LayerNetwork = 0;              // WINDIVERT_LAYER_NETWORK
    private const ulong FlagSniff = 1;                // WINDIVERT_FLAG_SNIFF：只读嗅探，绝不拦截
    private const int ErrorAccessDenied = 5;
    private const int ErrorFileNotFound = 2;
    private const int ErrorDriverBlocked = 577;

    /// <summary>WinDivert 用户态库应部署在采集后台可执行文件同目录。</summary>
    public static string ExpectedLibraryPath => Path.Combine(AppContext.BaseDirectory, NetMindDefaults.WinDivertLibraryFileName);

    public static bool IsLibraryPresent => File.Exists(ExpectedLibraryPath);

    /// <summary>打开网络层嗅探句柄；失败时抛出带中文指引的异常。</summary>
    public static IntPtr Open(string filter)
    {
        EnsureLibraryLoaded();
        var handle = WinDivertOpen(filter, LayerNetwork, 0, FlagSniff);
        // WinDivert 失败返回 INVALID_HANDLE_VALUE(-1) 而非 NULL：只判 Zero 会把 -1 当有效句柄放行，
        // 之后每次 Recv 都报错误 6（无效句柄），表现为“采集正常但永远 0 包”。
        if (handle == IntPtr.Zero || handle == new IntPtr(-1))
            throw new InvalidOperationException(DescribeError(Marshal.GetLastWin32Error()));
        return handle;
    }

    /// <summary>阻塞接收一个报文；句柄关闭时返回 false。失败时保留最后一次 Win32 错误码供诊断。</summary>
    public static bool Recv(IntPtr handle, byte[] buffer, out WinDivertAddress address, out int read)
    {
        address = default;
        var success = WinDivertRecv(handle, buffer, (uint)buffer.Length, out uint received, out address);
        read = checked((int)received);
        if (!success && LastRecvError == 0) LastRecvError = Marshal.GetLastWin32Error();
        return success && read > 0;
    }

    /// <summary>首次 WinDivertRecv 失败的 Win32 错误码（0 表示未失败过）；只记首次，避免停止时句柄关闭的正常失败覆盖运行期真实错误。</summary>
    public static int LastRecvError;

    public static void Close(IntPtr handle) => WinDivertClose(handle);

    public static string DescribeError(int error) => error switch
    {
        ErrorAccessDenied => "缺少管理员权限：WinDivert 驱动需要以管理员身份运行采集后台。",
        ErrorFileNotFound => "未找到 WinDivert 驱动文件（WinDivert.dll / WinDivert64.sys），请将其放入采集后台目录。",
        ErrorDriverBlocked => "WinDivert 驱动被 Windows 安全策略阻止加载（错误 577），请检查驱动签名与设备防护策略。",
        _ => $"WinDivert 调用失败（Win32 错误 {error}）。"
    };

    private static void EnsureLibraryLoaded()
    {
        if (NativeLibrary.TryLoad(ExpectedLibraryPath, out _)) return;
        if (!IsLibraryPresent)
            throw new InvalidOperationException(
                $"未找到静默抓包依赖 {NetMindDefaults.WinDivertLibraryFileName} 与 {NetMindDefaults.WinDivertDriverFileName}，" +
                $"请从 WinDivert 官方发布包取得并放入目录：{AppContext.BaseDirectory}");
    }

    [DllImport(LibraryName, CallingConvention = CallingConvention.StdCall, SetLastError = true)]
    private static extern IntPtr WinDivertOpen(
        [MarshalAs(UnmanagedType.LPStr)] string filter, uint layer, short priority, ulong flags);

    // 参数顺序必须与 windivert.h 完全一致：pPacket, packetLen, pRecvLen, pAddr。
    // 若把 pAddr 与 pRecvLen 写反，原生层会将 80 字节地址结构写进 4 字节长度槽，首个报文到达即栈踩踏崩溃。
    [DllImport(LibraryName, CallingConvention = CallingConvention.StdCall, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WinDivertRecv(
        IntPtr handle, [Out] byte[] pPacket, uint packetLen, out uint pRecvLen, out WinDivertAddress pAddr);

    [DllImport(LibraryName, CallingConvention = CallingConvention.StdCall, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WinDivertClose(IntPtr handle);
}
