using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

namespace NetMind.Core;

/// <summary>
/// Windows 系统代理设置快照（接管前的原始状态），用于会话停止或异常退出后精确还原。
/// </summary>
public sealed record SystemProxySnapshot(int Flags, string? Server, string? Bypass)
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web) { WriteIndented = true };

    /// <summary>序列化为 JSON 文本（供哨兵文件原子持久化）。</summary>
    public string ToJson() => JsonSerializer.Serialize(this, JsonOptions);

    /// <summary>从 JSON 文本反序列化；格式无效时抛出带中文说明的异常。</summary>
    public static SystemProxySnapshot FromJson(string json)
    {
        try
        {
            return JsonSerializer.Deserialize<SystemProxySnapshot>(json, JsonOptions)
                   ?? throw new InvalidDataException("系统代理快照内容为空。");
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("系统代理快照文件格式无效。", exception);
        }
    }
}

/// <summary>
/// 无感抓包：Windows 系统代理自动化接管与还原（双通道：WinINET 每连接选项 + 注册表兜底）。
/// 会话启动时把系统代理指向回环监听端口，停止时依据快照还原；
/// 接管前的原始设置先写入哨兵文件，崩溃后可据此恢复。
/// 本类只读写 WinINET 系统代理，与采集浏览器的进程级 --proxy-server 完全独立。
///
/// 事实来源约定：Win32 系统代理的事实来源是 HKCU 的 Internet Settings 注册表项
/// （ProxyEnable / ProxyServer / ProxyOverride）。WinINET 每连接选项 API 只是官方写入通道之一，
/// 本机实测存在 marshalling 敏感异常（UTF-16 字符串被按 ANSI 解读、返回指针归属存疑），
/// 因此写入采用双通道：先走修正后的 WinINET API，注册表回读与目标不一致时改走注册表直写；
/// 两条路径最终都以注册表回读校验为准，不一致即判定失败（绝不静默）。
/// 读取快照直接读注册表，避免 WinINET 查询返回字符串的字节错乱与释放归属风险。
/// </summary>
public static class SystemProxyAutomation
{
    // ── WinINET 选项常量（Windows SDK 固定值） ────────────────────────────────
    private const int InternetOptionPerConnectionOption = 75;
    private const int InternetOptionSettingsChanged = 39;
    private const int InternetOptionRefresh = 37;
    private const int InternetPerConnOptionFlags = 1;
    private const int InternetPerConnOptionProxyServer = 2;
    private const int InternetPerConnOptionProxyBypass = 3;
    private const int OptionCount = 3;

    // ── PROXY_TYPE 标志位（INTERNET_PER_CONN_FLAGS） ─────────────────────────
    internal const int ProxyTypeDirect = 0x1;
    internal const int ProxyTypeProxy = 0x2;

    // ── advapi32 注册表访问常量（Windows SDK 固定值） ─────────────────────────
    private static readonly IntPtr HkeyCurrentUser = new(0x80000001);
    private const uint RegistryAccessRead = 0x20019;   // STANDARD_RIGHTS_READ | KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY
    private const uint RegistryAccessWrite = 0x20006;  // STANDARD_RIGHTS_READ | KEY_SET_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY
    private const int RegistryTypeDword = 4;           // REG_DWORD
    private const int RegistryTypeString = 1;          // REG_SZ
    private const int ErrorSuccess = 0;
    private const int ErrorFileNotFound = 2;

    /// <summary>
    /// 读取当前 Windows 系统代理设置快照（flags / server / bypass 三项）。
    /// 直接读注册表事实来源：WinINET 每连接查询 API 在本机实测返回字符串字节错乱
    /// （ANSI 字节被按 UTF-16 配对）且返回内存归属存疑，故不再作为读取通道。
    /// </summary>
    public static SystemProxySnapshot Read()
    {
        var (proxyEnable, proxyServer, proxyOverride) = ReadRegistryValues();
        return SnapshotFromRegistryValues(proxyEnable, proxyServer, proxyOverride);
    }

    /// <summary>把系统代理接管为指定的显式代理（PROXY_TYPE_PROXY + 直连兜底），供采集期间使用。</summary>
    public static void Apply(string server, string? bypass)
    {
        if (string.IsNullOrWhiteSpace(server)) throw new ArgumentException("接管系统代理时必须提供代理服务器地址。", nameof(server));
        var (expectedEnable, expectedServer, expectedBypass) = ApplyTargets(server, bypass);
        ApplyDualChannel(ProxyTypeProxy | ProxyTypeDirect, server, bypass ?? string.Empty, expectedEnable, expectedServer, expectedBypass);
    }

    /// <summary>
    /// 按快照还原接管前的系统代理设置：逐字段按快照原值写入，
    /// 快照中为空的 ProxyServer / ProxyOverride 按“值不存在”还原（而非写空串），
    /// ProxyEnable=0 时是否清空 ProxyServer 同样以快照原值为准。
    /// </summary>
    public static void Restore(SystemProxySnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        var (expectedEnable, expectedServer, expectedBypass) = RestoreTargetsFromSnapshot(snapshot);
        ApplyDualChannel(snapshot.Flags, expectedServer ?? string.Empty, expectedBypass ?? string.Empty, expectedEnable, expectedServer, expectedBypass);
    }

    // ── 纯逻辑映射与校验（不触碰系统，供定向测试覆盖） ──────────────────────

    /// <summary>判断快照是否含显式代理标志位（PROXY_TYPE_PROXY，即系统代理当前指向某个代理服务器）。</summary>
    public static bool HasExplicitProxy(SystemProxySnapshot snapshot) =>
        (snapshot.Flags & ProxyTypeProxy) != 0;

    /// <summary>注册表三项值 → 快照：ProxyEnable 非 0 视为显式代理 + 直连，否则仅直连。</summary>
    internal static SystemProxySnapshot SnapshotFromRegistryValues(int proxyEnable, string? proxyServer, string? proxyOverride) =>
        new(proxyEnable != 0 ? ProxyTypeProxy | ProxyTypeDirect : ProxyTypeDirect, proxyServer, proxyOverride);

    /// <summary>快照 → 注册表还原目标（逐字段）；空值保持为“值不存在”语义。</summary>
    internal static (int ProxyEnable, string? ProxyServer, string? ProxyOverride) RestoreTargetsFromSnapshot(SystemProxySnapshot snapshot) =>
        ((snapshot.Flags & ProxyTypeProxy) != 0 ? 1 : 0, snapshot.Server, snapshot.Bypass);

    /// <summary>接管目标 → 注册表目标；空绕过列表按“值不存在”处理。</summary>
    internal static (int ProxyEnable, string? ProxyServer, string? ProxyOverride) ApplyTargets(string server, string? bypass) =>
        (1, server, string.IsNullOrEmpty(bypass) ? null : bypass);

    /// <summary>注册表回读值与目标是否一致（回读校验谓词）。</summary>
    internal static bool RegistryValuesMatch(
        int actualEnable, string? actualServer, string? actualOverride,
        int expectedEnable, string? expectedServer, string? expectedOverride) =>
        actualEnable == expectedEnable
        && string.Equals(actualServer, expectedServer, StringComparison.Ordinal)
        && string.Equals(actualOverride, expectedOverride, StringComparison.Ordinal);

    // ── 双通道写入（WinINET 优先，注册表兜底，最终以注册表回读为准） ─────────

    private static void ApplyDualChannel(
        int wininetFlags, string wininetServer, string wininetBypass,
        int expectedEnable, string? expectedServer, string? expectedBypass)
    {
        // 通道一：修正 marshalling 后的 WinINET 每连接选项 API；失败不抛，交给通道二兜底。
        TryApplyViaWininet(wininetFlags, wininetServer, wininetBypass);
        var (actualEnable, actualServer, actualOverride) = ReadRegistryValues();
        if (!RegistryValuesMatch(actualEnable, actualServer, actualOverride, expectedEnable, expectedServer, expectedBypass))
        {
            // 通道二：WinINET 写入未达目标（本机实测会把 UTF-16 地址写成单字符等错值），
            // 改为直写注册表事实来源，再统一广播变更通知。
            WriteRegistryValues(expectedEnable, expectedServer, expectedBypass);
        }
        BroadcastProxySettingsChanged();

        // 无论走哪条通道，最终都以注册表回读校验为准；不一致即判定失败，绝不静默通过。
        (actualEnable, actualServer, actualOverride) = ReadRegistryValues();
        if (!RegistryValuesMatch(actualEnable, actualServer, actualOverride, expectedEnable, expectedServer, expectedBypass))
            throw new InvalidOperationException(
                $"写入系统代理设置失败：目标 ProxyEnable={expectedEnable}、ProxyServer={expectedServer ?? "（清除）"}、ProxyOverride={expectedBypass ?? "（清除）"}；"
                + $"回读 ProxyEnable={actualEnable}、ProxyServer={actualServer ?? "（未设置）"}、ProxyOverride={actualOverride ?? "（未设置）"}。"
                + "请检查是否有其他软件守护注册表代理项后重试。");
    }

    /// <summary>
    /// WinINET 每连接选项写入通道。修正要点（逐字节对照微软文档）：
    /// 1. INTERNET_PER_CONN_OPTION 的 union 含 DWORD(4) / LPTSTR(8) / FILETIME(8) 三种分支，
    ///    联合尺寸取最大的 8 字节，x64 下整体结构 DWORD + 对齐到 8 的 union = 16 字节；
    ///    C# 侧用显式布局同时声明三个分支（含 FILETIME 双 uint），确保结构尺寸与原生一致，
    ///    否则选项数组整体错位、API 读到相邻字段（本机曾把代理地址写成 "1"）。
    /// 2. 该 API 的字符串按 ANSI（LPTSTR 按当前代码页）处理：写入用 StringToHGlobalAnsi；
    ///    此前用 UTF-16 指针传入，API 读 ANSI 遇第二个字节 0 即截断，导致只写入首字符。
    /// 3. 本通道只写不读：WinINET 查询返回字符串的内存在每连接选项 API 下归属存疑
    ///    （实测 GlobalFree 会崩溃），读取一律走注册表，从根上消除释放风险。
    /// </summary>
    private static bool TryApplyViaWininet(int flags, string server, string bypass)
    {
        var optionSize = Marshal.SizeOf<InternetPerConnOption>();
        var optionsPointer = Marshal.AllocHGlobal(optionSize * OptionCount);
        var serverPointer = Marshal.StringToHGlobalAnsi(server);
        var bypassPointer = Marshal.StringToHGlobalAnsi(bypass);
        var listPointer = Marshal.AllocHGlobal(Marshal.SizeOf<InternetPerConnOptionList>());
        try
        {
            WriteOption(optionsPointer, 0, InternetPerConnOptionFlags, intValue: flags);
            WriteOption(optionsPointer, 1, InternetPerConnOptionProxyServer, serverPointer);
            WriteOption(optionsPointer, 2, InternetPerConnOptionProxyBypass, bypassPointer);
            Marshal.StructureToPtr(new InternetPerConnOptionList
            {
                Size = Marshal.SizeOf<InternetPerConnOptionList>(),
                Connection = IntPtr.Zero,
                OptionCount = OptionCount,
                Options = optionsPointer
            }, listPointer, fDeleteOld: false);

            return InternetSetOption(IntPtr.Zero, InternetOptionPerConnectionOption, listPointer, Marshal.SizeOf<InternetPerConnOptionList>());
        }
        finally
        {
            Marshal.FreeHGlobal(optionsPointer);
            Marshal.FreeHGlobal(serverPointer);
            Marshal.FreeHGlobal(bypassPointer);
            Marshal.FreeHGlobal(listPointer);
        }
    }

    /// <summary>广播代理设置变更（INTERNET_OPTION_SETTINGS_CHANGED + REFRESH），使在运行进程感知新代理。</summary>
    private static void BroadcastProxySettingsChanged()
    {
        if (!InternetSetOption(IntPtr.Zero, InternetOptionSettingsChanged, IntPtr.Zero, 0))
            throw new InvalidOperationException($"通知系统代理设置变更失败（Win32 错误码 {Marshal.GetLastWin32Error()}）。");
        if (!InternetSetOption(IntPtr.Zero, InternetOptionRefresh, IntPtr.Zero, 0))
            throw new InvalidOperationException($"刷新系统代理设置失败（Win32 错误码 {Marshal.GetLastWin32Error()}）。");
    }

    private static void WriteOption(IntPtr optionsPointer, int index, int option, int intValue)
    {
        var entry = new InternetPerConnOption { Option = option };
        entry.Value.intValue = intValue;
        Marshal.StructureToPtr(entry, optionsPointer + index * Marshal.SizeOf<InternetPerConnOption>(), fDeleteOld: false);
    }

    private static void WriteOption(IntPtr optionsPointer, int index, int option, IntPtr pointerValue)
    {
        var entry = new InternetPerConnOption { Option = option };
        entry.Value.ptrValue = pointerValue;
        Marshal.StructureToPtr(entry, optionsPointer + index * Marshal.SizeOf<InternetPerConnOption>(), fDeleteOld: false);
    }

    // ── 注册表事实通道（HKCU Internet Settings：ProxyEnable / ProxyServer / ProxyOverride） ──

    /// <summary>读取注册表三项代理值；值不存在时 ProxyEnable 按 0、字符串按空（快照语义为“未设置”）。</summary>
    internal static (int ProxyEnable, string? ProxyServer, string? ProxyOverride) ReadRegistryValues()
    {
        var key = OpenSettingsKey(RegistryAccessRead);
        try
        {
            return (
                ReadDwordValue(key, NetMindDefaults.SystemProxyRegistryEnableValueName) ?? 0,
                ReadStringValue(key, NetMindDefaults.SystemProxyRegistryServerValueName),
                ReadStringValue(key, NetMindDefaults.SystemProxyRegistryOverrideValueName));
        }
        finally { _ = RegCloseKey(key); }
    }

    /// <summary>直写注册表三项代理值；空（null）表示删除该值。</summary>
    private static void WriteRegistryValues(int proxyEnable, string? proxyServer, string? proxyOverride)
    {
        var key = OpenSettingsKey(RegistryAccessWrite);
        try
        {
            WriteDwordValue(key, NetMindDefaults.SystemProxyRegistryEnableValueName, proxyEnable);
            WriteOrDeleteStringValue(key, NetMindDefaults.SystemProxyRegistryServerValueName, proxyServer);
            WriteOrDeleteStringValue(key, NetMindDefaults.SystemProxyRegistryOverrideValueName, proxyOverride);
        }
        finally { _ = RegCloseKey(key); }
    }

    private static IntPtr OpenSettingsKey(uint access)
    {
        var result = RegOpenKeyEx(HkeyCurrentUser, NetMindDefaults.SystemProxyRegistrySubKey, 0, access, out var key);
        if (result != ErrorSuccess)
            throw new InvalidOperationException($"打开系统代理注册表项失败（Win32 错误码 {result}）。请检查系统状态后重试。");
        return key;
    }

    private static int? ReadDwordValue(IntPtr key, string valueName)
    {
        var buffer = Marshal.AllocHGlobal(sizeof(int));
        try
        {
            var size = sizeof(int);
            var result = RegQueryValueEx(key, valueName, IntPtr.Zero, out var type, buffer, ref size);
            if (result == ErrorFileNotFound) return null;
            if (result != ErrorSuccess || type != RegistryTypeDword || size < sizeof(int)) return null;
            return Marshal.ReadInt32(buffer);
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    private static string? ReadStringValue(IntPtr key, string valueName)
    {
        var size = 0;
        var probe = RegQueryValueEx(key, valueName, IntPtr.Zero, out var type, IntPtr.Zero, ref size);
        if (probe == ErrorFileNotFound || type != RegistryTypeString) return null;
        if (probe != ErrorSuccess || size <= 0) return probe == ErrorSuccess ? string.Empty : null;
        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            var result = RegQueryValueEx(key, valueName, IntPtr.Zero, out _, buffer, ref size);
            if (result != ErrorSuccess) return null;
            // REG_SZ 为 UTF-16 且以 0 结尾；拷入托管缓冲后去掉结尾空字符再返回。
            var bytes = new byte[size];
            Marshal.Copy(buffer, bytes, 0, size);
            return Encoding.Unicode.GetString(bytes).TrimEnd('\0');
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    private static void WriteDwordValue(IntPtr key, string valueName, int value)
    {
        var buffer = Marshal.AllocHGlobal(sizeof(int));
        try
        {
            Marshal.WriteInt32(buffer, value);
            var result = RegSetValueEx(key, valueName, 0, RegistryTypeDword, buffer, sizeof(int));
            if (result != ErrorSuccess)
                throw new InvalidOperationException($"写入系统代理注册表值 {valueName} 失败（Win32 错误码 {result}）。");
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    private static void WriteOrDeleteStringValue(IntPtr key, string valueName, string? value)
    {
        if (value is null)
        {
            var result = RegDeleteValue(key, valueName);
            if (result is not ErrorSuccess and not ErrorFileNotFound)
                throw new InvalidOperationException($"清除系统代理注册表值 {valueName} 失败（Win32 错误码 {result}）。");
            return;
        }
        var bytes = Encoding.Unicode.GetBytes(value + '\0'); // REG_SZ 必须含结尾 0 字符
        var buffer = Marshal.AllocHGlobal(bytes.Length);
        try
        {
            Marshal.Copy(bytes, 0, buffer, bytes.Length);
            var result = RegSetValueEx(key, valueName, 0, RegistryTypeString, buffer, bytes.Length);
            if (result != ErrorSuccess)
                throw new InvalidOperationException($"写入系统代理注册表值 {valueName} 失败（Win32 错误码 {result}）。");
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    // ── 结构体声明（内存布局逐字节对照 Windows SDK 文档） ────────────────────

    /// <summary>
    /// INTERNET_PER_CONN_OPTION_LIST：DWORD + 指针 + DWORD + 指针；
    /// x64 下指针 8 字节对齐，整体 32 字节，Size 字段运行时取 Marshal.SizeOf 保证一致。
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct InternetPerConnOptionList
    {
        public int Size;
        public IntPtr Connection;
        public int OptionCount;
        public IntPtr Options;
    }

    /// <summary>
    /// INTERNET_PER_CONN_OPTION：DWORD 选项号 + union 值。
    /// union 三分支（DWORD 4 字节 / LPTSTR 8 字节 / FILETIME 8 字节）最大 8 字节，
    /// x64 下整体 4 + 对齐填充 + 8 = 16 字节；显式布局同时声明三个分支锁定尺寸，
    /// 避免任一分支缺失导致结构尺寸与原生不符、选项数组整体错位。
    /// </summary>
    [StructLayout(LayoutKind.Explicit)]
    private struct InternetPerConnOption
    {
        [FieldOffset(0)] public int Option;
        [FieldOffset(4)] public InternetPerConnOptionValue Value;
    }

    /// <summary>union 值：DWORD / 指针 / FILETIME 共用偏移 0，尺寸取最大分支 8 字节。</summary>
    [StructLayout(LayoutKind.Explicit)]
    private struct InternetPerConnOptionValue
    {
        [FieldOffset(0)] public int intValue;
        [FieldOffset(0)] public IntPtr ptrValue;
        [FieldOffset(0)] public FileTimeValue ftValue;
    }

    /// <summary>FILETIME：两个 DWORD 共 8 字节，仅用于锁定 union 尺寸。</summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct FileTimeValue
    {
        public uint LowDateTime;
        public uint HighDateTime;
    }

    [DllImport("wininet.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool InternetSetOption(IntPtr handle, int option, IntPtr buffer, int bufferLength);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int RegOpenKeyEx(IntPtr hKey, string lpSubKey, uint ulOptions, uint samDesired, out IntPtr phkResult);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int RegQueryValueEx(IntPtr hKey, string lpValueName, IntPtr lpReserved, out int lpType, IntPtr lpData, ref int lpcbData);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int RegSetValueEx(IntPtr hKey, string lpValueName, uint reserved, int dwType, IntPtr lpData, int cbData);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int RegDeleteValue(IntPtr hKey, string lpValueName);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern int RegCloseKey(IntPtr hKey);
}

/// <summary>
/// 系统代理接管哨兵文件读写；原子写（tmp + File.Move）与设置存储范式一致。
/// 哨兵存在即代表系统代理已被接管，其中保存接管前的原始快照。
/// </summary>
public static class SystemProxySentinel
{
    /// <summary>原子写入哨兵文件（先写临时文件再重命名）。</summary>
    public static async Task WriteAsync(string path, SystemProxySnapshot snapshot, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        var directory = Path.GetDirectoryName(Path.GetFullPath(path)) ?? throw new InvalidOperationException("系统代理哨兵路径无效。");
        Directory.CreateDirectory(directory);
        var temporaryPath = path + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            await File.WriteAllTextAsync(temporaryPath, snapshot.ToJson(), cancellationToken);
            File.Move(temporaryPath, path, overwrite: true);
        }
        finally { if (File.Exists(temporaryPath)) File.Delete(temporaryPath); }
    }

    /// <summary>读取哨兵快照；文件缺失或已损坏时返回空（损坏视同缺失，避免阻断启动）。</summary>
    public static async Task<SystemProxySnapshot?> TryReadAsync(string path, CancellationToken cancellationToken = default)
    {
        if (!File.Exists(path)) return null;
        try
        {
            return SystemProxySnapshot.FromJson(await File.ReadAllTextAsync(path, cancellationToken));
        }
        catch (InvalidDataException) { return null; }
        catch (IOException) { return null; }
    }

    /// <summary>删除哨兵文件；文件不存在视为已完成。</summary>
    public static void Delete(string path)
    {
        try { File.Delete(path); }
        catch (IOException) { /* 文件可能刚被并发删除，不影响还原结果 */ }
    }
}
