using System.Text.Json;

namespace NetMind.Core;

/// <summary>
/// 工作台运行参数设置。默认值全部引用 <see cref="NetMindDefaults"/>；
/// 监听地址保持 Loopback 是安全边界，因此这里只暴露端口，绝不提供绑定地址选项（代理无鉴权）。
/// 刷新间隔、列表窗口条数与 AI 证据条数由用户自行配置，只做范围约束，不再强制回填默认值。
/// </summary>
public sealed record WorkbenchSettings(
    int ListenPort = NetMindDefaults.ListenPort,
    int RefreshIntervalMilliseconds = NetMindDefaults.DefaultRefreshIntervalMilliseconds,
    int TrafficWindowCount = NetMindDefaults.DefaultTrafficWindowCount,
    int SessionWindowCount = NetMindDefaults.DefaultSessionWindowCount,
    int AiEvidenceMaximumTransactions = NetMindDefaults.DefaultAiEvidenceMaximumTransactions,
    int PageHookWindowCount = NetMindDefaults.DefaultPageHookWindowCount,
    bool SystemProxyAutomation = false,
    bool EnableTrafficHooks = false,
    bool UseSilentCapture = false,
    // 仅为旧设置文件保留；证据文件已改为当前分析草稿，不再跨会话恢复。
    string[]? AiAttachedFilePaths = null,
    BrowserEnvironmentProfile? BrowserEnvironment = null,
    string? WorkspaceRootPath = null)
{
    /// <summary>校验各字段取值范围，越界时抛出带中文说明的异常；通过后返回归一化实例。</summary>
    public WorkbenchSettings Validate()
    {
        if (ListenPort is < 1024 or > 65535)
            throw new InvalidOperationException("监听端口必须在 1024–65535 之间。");
        // 越界直接报错而不是静默夹取：这些值决定每轮读多少行、发多少证据，
        // 用户填了 5000 却按 2000 执行会让人以为设置没生效。
        if (RefreshIntervalMilliseconds is < NetMindDefaults.MinimumRefreshIntervalMilliseconds or > NetMindDefaults.MaximumRefreshIntervalMilliseconds)
            throw new InvalidOperationException($"刷新间隔必须在 {NetMindDefaults.MinimumRefreshIntervalMilliseconds}–{NetMindDefaults.MaximumRefreshIntervalMilliseconds} 毫秒之间。");
        if (TrafficWindowCount is < NetMindDefaults.MinimumTrafficWindowCount or > NetMindDefaults.MaximumTrafficWindowCount)
            throw new InvalidOperationException($"流量列表条数必须在 {NetMindDefaults.MinimumTrafficWindowCount}–{NetMindDefaults.MaximumTrafficWindowCount} 之间。");
        if (SessionWindowCount is < NetMindDefaults.MinimumSessionWindowCount or > NetMindDefaults.MaximumSessionWindowCount)
            throw new InvalidOperationException($"会话列表条数必须在 {NetMindDefaults.MinimumSessionWindowCount}–{NetMindDefaults.MaximumSessionWindowCount} 之间。");
        if (PageHookWindowCount is < NetMindDefaults.MinimumPageHookWindowCount or > NetMindDefaults.MaximumPageHookWindowCount)
            throw new InvalidOperationException($"页内 Hook 列表条数必须在 {NetMindDefaults.MinimumPageHookWindowCount}–{NetMindDefaults.MaximumPageHookWindowCount} 之间。");
        if (AiEvidenceMaximumTransactions is < NetMindDefaults.MinimumAiEvidenceMaximumTransactions or > NetMindDefaults.AiMaximumEvidenceTransactions)
            throw new InvalidOperationException($"AI 证据条数上限必须在 {NetMindDefaults.MinimumAiEvidenceMaximumTransactions}–{NetMindDefaults.AiMaximumEvidenceTransactions} 之间。");
        // SystemProxyAutomation（无感抓包开关）为布尔值，无需范围校验，默认关闭。
        // EnableTrafficHooks（流量钩子开关）为布尔值，无需范围校验，默认关闭。
        // UseSilentCapture（底层静默抓包开关）为布尔值，无需范围校验，默认关闭（走回环代理模式）。
        BrowserEnvironment?.Validate();
        var workspaceRoot = string.IsNullOrWhiteSpace(WorkspaceRootPath) ? null : Path.GetFullPath(WorkspaceRootPath.Trim());
        if (workspaceRoot is not null && workspaceRoot.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
                .Equals(Path.GetPathRoot(workspaceRoot)?.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("工作区存储目录不能直接使用磁盘或共享根目录。");
        // 旧设置可缺少浏览器画像；工作台读取时按默认关闭配置处理，保持旧 JSON 往返兼容。
        return this with { WorkspaceRootPath = workspaceRoot };
    }
}

/// <summary>
/// 工作台设置存储；原子写与加载容错范式与 <see cref="AiGatewaySettingsStore"/> 完全一致。
/// </summary>
public sealed class WorkbenchSettingsStore(string path)
{
    // V3 起持久化用户可配置的刷新间隔与各列表/证据条数；V2 文件缺这些字段时按记录默认值加载。
    private const int CurrentSchemaVersion = 3;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web) { WriteIndented = true };
    public string Path { get; } = System.IO.Path.GetFullPath(path);

    public async Task<WorkbenchSettings> LoadAsync(CancellationToken cancellationToken = default)
    {
        if (!File.Exists(Path)) return new WorkbenchSettings();
        try
        {
            await using var stream = new FileStream(Path, FileMode.Open, FileAccess.Read, FileShare.Read, 16 * 1024, FileOptions.Asynchronous);
            return (await JsonSerializer.DeserializeAsync<WorkbenchSettings>(stream, JsonOptions, cancellationToken) ?? new WorkbenchSettings()).Validate();
        }
        catch (JsonException exception) { throw new InvalidDataException("工作台设置文件格式无效。", exception); }
    }

    public async Task SaveAsync(WorkbenchSettings settings, CancellationToken cancellationToken = default)
    {
        settings = settings.Validate();
        var directory = System.IO.Path.GetDirectoryName(Path) ?? throw new InvalidOperationException("工作台设置路径无效。");
        Directory.CreateDirectory(directory);
        var temporaryPath = Path + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            var document = new WorkbenchSettingsDocument(
                CurrentSchemaVersion,
                settings.ListenPort,
                settings.SystemProxyAutomation,
                settings.EnableTrafficHooks,
                settings.UseSilentCapture,
                settings.BrowserEnvironment,
                settings.WorkspaceRootPath,
                settings.RefreshIntervalMilliseconds,
                settings.TrafficWindowCount,
                settings.SessionWindowCount,
                settings.PageHookWindowCount,
                settings.AiEvidenceMaximumTransactions);
            await File.WriteAllTextAsync(temporaryPath, JsonSerializer.Serialize(document, JsonOptions), cancellationToken);
            File.Move(temporaryPath, Path, overwrite: true);
        }
        finally { if (File.Exists(temporaryPath)) File.Delete(temporaryPath); }
    }

    /// <summary>
    /// V2 只持久化会改变采集行为、隐私边界或网络兼容性的参数；
    /// V3 追加用户可配置的刷新间隔与列表/证据条数。旧文件缺这些字段时按记录默认值反序列化。
    /// </summary>
    private sealed record WorkbenchSettingsDocument(
        int SchemaVersion,
        int ListenPort,
        bool SystemProxyAutomation,
        bool EnableTrafficHooks,
        bool UseSilentCapture,
        BrowserEnvironmentProfile? BrowserEnvironment,
        string? WorkspaceRootPath,
        int RefreshIntervalMilliseconds = NetMindDefaults.DefaultRefreshIntervalMilliseconds,
        int TrafficWindowCount = NetMindDefaults.DefaultTrafficWindowCount,
        int SessionWindowCount = NetMindDefaults.DefaultSessionWindowCount,
        int PageHookWindowCount = NetMindDefaults.DefaultPageHookWindowCount,
        int AiEvidenceMaximumTransactions = NetMindDefaults.DefaultAiEvidenceMaximumTransactions);
}
