using System.Net;
using System.Text;
using System.Text.Json;
using NetMind.Core;

Console.OutputEncoding = Encoding.UTF8;

// 全局异常陷阱：runas 提升后 stdout 无法重定向，未处理异常的完整堆栈落到信号目录崩溃日志，
// 便于定位静默抓包等后台场景的进程级崩溃。
AppDomain.CurrentDomain.UnhandledException += (_, eventArgs) =>
    WriteCrashLog("UnhandledException", eventArgs.ExceptionObject as Exception);
TaskScheduler.UnobservedTaskException += (_, eventArgs) =>
{
    WriteCrashLog("UnobservedTaskException", eventArgs.Exception);
    eventArgs.SetObserved();
};

try
{
    if (args.Length == 0 || args[0] is "help" or "--help" or "-h")
    {
        PrintHelp();
        return 0;
    }

    var command = args[0].ToLowerInvariant();
    var workspacePath = Option(args, "--workspace") ?? DefaultWorkspacePath();
    return command switch
    {
        "proxy" => await RunProxyAsync(args, workspacePath),
        "simulate" => await RunSimulationAsync(args, workspacePath),
        "silent" => await RunSilentAsync(args, workspacePath),
        "status" => ShowStatus(workspacePath),
        _ => UnknownCommand(command)
    };
}
catch (OperationCanceledException)
{
    Console.WriteLine("操作已取消。");
    return 0;
}
catch (Exception exception)
{
    Console.Error.WriteLine($"启动失败：{exception.Message}");
    return 1;
}

static async Task<int> RunProxyAsync(string[] arguments, string workspacePath)
{
    var listen = Option(arguments, "--listen") ?? NetMindDefaults.DefaultListenEndpoint;
    var parts = listen.Split(':', 2);
    if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var address) || !int.TryParse(parts[1], out var port) || port is < 0 or > 65535)
        throw new ArgumentException($"--listen 必须为 IP:端口，例如 {NetMindDefaults.DefaultListenEndpoint}。");

    await EnsureWorkspaceAsync(workspacePath);
    using var archive = new TrafficArchive(workspacePath);
    var tlsInspection = arguments.Contains("--tls-inspect", StringComparer.OrdinalIgnoreCase);
    if (tlsInspection)
    {
        using var authority = new WorkspaceCertificateAuthority(workspacePath);
        if (!authority.IsEnabledAndTrusted())
            throw new InvalidOperationException("工作区 HTTPS 解密尚未启用或 CA 未受当前用户信任。");
    }
    var hookEngine = await TryCreateHookEngineAsync(workspacePath);
    if (hookEngine is null)
    {
        await TrafficHookStatusStore.SaveAsync(workspacePath, new ScriptHookMetricsSnapshot(
            "disabled", 0, 0, 0, 0, 0, 0, 0, 0, null, null, null,
            "配置未启用、脚本不可用或沙箱宿主缺失；请检查请求钩子配置。"));
    }
    await using var proxy = new ExplicitHttpProxy(new ProxyOptions(address, port, EnableTlsInspection: tlsInspection, WorkspacePath: workspacePath), archive);
    using var cancellation = new CancellationTokenSource();
    Console.CancelKeyPress += (_, eventArgs) =>
    {
        eventArgs.Cancel = true;
        cancellation.Cancel();
    };
    proxy.TransactionCaptured += (_, traffic) =>
        Console.WriteLine($"[{traffic.Timestamp:HH:mm:ss}] {traffic.Method,-7} {traffic.StatusCode}  {traffic.Endpoint}  {traffic.LatencyMs} 毫秒");

    // 页内 Hook 接收器：仅监听 127.0.0.1，由工作台经 --hook-port 传入端口；未传则不起，启动失败不影响抓包。
    PageHookReceiver? pageHookReceiver = null;
    var hookPortText = Option(arguments, "--hook-port");
    var hookToken = Option(arguments, "--hook-token");
    if (hookPortText is not null && int.TryParse(hookPortText, out var hookPort) && hookPort > 0)
    {
        var receiver = new PageHookReceiver(hookPort, proxy.SessionId,
            events => archive.RecordPageHooksAsync(events, cancellation.Token), hookToken);
        try
        {
            receiver.Start();
            pageHookReceiver = receiver;
            Console.WriteLine($"页内 Hook：接收器已启动（127.0.0.1:{hookPort}）");
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine($"页内 Hook：接收器启动失败（{exception.Message}），抓包继续。");
            await receiver.DisposeAsync();
        }
    }

    var runTask = proxy.RunAsync(cancellation.Token);
    while (proxy.LocalEndpoint is null) await Task.Delay(10, cancellation.Token);
    // 先输出就绪标记再启动钩子引擎：慢机器冷启动 Python 可达十余秒，不得阻塞代理就绪。
    Console.WriteLine("NetMind CoreHost 已启动");
    Console.WriteLine($"{NetMindDefaults.CoreHostReadyMarker}{proxy.LocalEndpoint}");
    Console.WriteLine($"工作区：{workspacePath}");
    Console.WriteLine(tlsInspection
        ? "HTTPS：TLS 解密已启用（HTTP/1.1 正文将持久化）"
        : "HTTPS：加密隧道转发已启用（记录元数据，不解密正文）");

    Task? hookStartTask = null;
    Task? hookDrainTask = null;
    Task? hookStatusTask = null;
    using var hookDrainCancellation = new CancellationTokenSource();
    if (hookEngine is not null)
    {
        Console.WriteLine($"钩子：正在后台启动（{hookEngine.EnabledHookCount} 个钩子点，不阻塞代理就绪）");
        var engine = hookEngine;
        hookStartTask = Task.Run(async () =>
        {
            var started = await engine.StartAsync();
            if (!started)
            {
                // 启动失败时引擎已自行审计 hooks.disabled；代理照常运行。
                Console.Error.WriteLine("钩子工作进程启动失败，钩子保持关闭，代理继续采集（详见审计日志 hooks.disabled）。");
                return;
            }
            proxy.HookEngine = engine; // 后置注入：就绪前事件自然空转，就绪后即生效。
            Console.WriteLine($"钩子：已启用（{engine.EnabledHookCount} 个钩子点 · 隔离工作进程已就绪）");
        });
        var auditStore = new WorkspaceStore(workspacePath);
        hookDrainTask = DrainHookFindingsAsync(engine, auditStore, hookDrainCancellation.Token);
        hookStatusTask = PublishHookStatusAsync(engine, workspacePath, hookDrainCancellation.Token);
    }
    else
    {
        Console.WriteLine("钩子：未启用（开关关闭、配置未启用或脚本不可用）");
    }
    if (tlsInspection)
    {
        var bypassCount = new TlsInspectionPolicyStore(workspacePath).Load().BypassHosts.Count;
        Console.WriteLine($"HTTPS 直通规则：{bypassCount} 条（匹配域名保持端到端加密）");
    }
    Console.WriteLine("按 Ctrl+C 停止。\n");
    var inputTask = Task.Run(Console.ReadLine);
    var completed = await Task.WhenAny(runTask, inputTask);
    if (completed == inputTask) cancellation.Cancel();
    try
    {
        await runTask;
    }
    finally
    {
        // 先停消费循环，再停代理，最后优雅关停钩子引擎（限时清队 flush 后发 shutdown）。
        hookDrainCancellation.Cancel();
        if (hookDrainTask is not null)
        {
            try { await hookDrainTask.WaitAsync(TimeSpan.FromMilliseconds(NetMindDefaults.HookFindingDrainIntervalMilliseconds * 2)); } catch { /* 消费循环收尾不阻塞停机。 */ }
        }
        if (hookStatusTask is not null)
        {
            try { await hookStatusTask.WaitAsync(TimeSpan.FromSeconds(2)); } catch { /* 状态发布收尾不阻塞停机。 */ }
        }
        if (hookEngine is not null) await hookEngine.DisposeAsync();
        if (hookEngine is not null)
        {
            try { await TrafficHookStatusStore.SaveAsync(workspacePath, hookEngine.GetMetricsSnapshot()); } catch { }
        }
        if (pageHookReceiver is not null) await pageHookReceiver.DisposeAsync();
        if (hookStartTask is not null)
        {
            try { await hookStartTask.WaitAsync(TimeSpan.FromMilliseconds(NetMindDefaults.HookShutdownJoinTimeoutMilliseconds)); } catch { /* 后台启动收尾不阻塞停机。 */ }
        }
    }
    Console.WriteLine("代理已安全停止。");
    return 0;
}

/// <summary>周期发布轻量脚本 Hook 指标；状态文件原子替换，工作台读取不会遇到半截 JSON。</summary>
static async Task PublishHookStatusAsync(ScriptHookEngine engine, string workspacePath, CancellationToken cancellationToken)
{
    try
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            await TrafficHookStatusStore.SaveAsync(workspacePath, engine.GetMetricsSnapshot(), cancellationToken);
            await Task.Delay(NetMindDefaults.HookStatusPublishIntervalMilliseconds, cancellationToken);
        }
    }
    catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
    catch
    {
        // 状态展示失败不得影响代理与脚本工作进程。
    }
}

/// <summary>
/// 周期消费钩子观察结论（finding）：逐条经工作区审计落盘（hooks.finding，payload 经同一 Redact 通道脱敏）；
/// 单批条数有上限，取消后把剩余未消费条数并入停机生命周期审计。
/// </summary>
static async Task DrainHookFindingsAsync(ScriptHookEngine engine, WorkspaceStore auditStore, CancellationToken cancellationToken)
{
    try
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            await Task.Delay(NetMindDefaults.HookFindingDrainIntervalMilliseconds, cancellationToken);
            await WriteHookFindingsToAuditAsync(engine, auditStore);
        }
    }
    catch (OperationCanceledException)
    {
        // 正常停止：退出前把剩余观察结论落盘，避免静默丢失。
        try { await WriteHookFindingsToAuditAsync(engine, auditStore); } catch { /* 停机尾批审计失败不影响退出。 */ }
    }
    catch
    {
        // 消费循环异常不得影响代理运行。
    }
}

/// <summary>把当前待取的观察结论逐条写入审计；超过单批上限的剩余条数并入既有队列丢弃语义（下次继续取）。</summary>
static async Task<int> WriteHookFindingsToAuditAsync(ScriptHookEngine engine, WorkspaceStore auditStore)
{
    // 只从队列取本批能够落盘的条数，剩余 finding 留待下一轮；避免先排空再 Take 导致静默丢失。
    var findings = engine.DrainFindings(NetMindDefaults.HookFindingDrainBatchMaximum);
    var written = 0;
    foreach (var finding in findings)
    {
        await auditStore.AppendAuditAsync(NetMindDefaults.AuditEventHooksFinding, new
        {
            @event = finding.Event,
            txnId = finding.TxnId,
            hookName = finding.HookName,
            data = finding.Data,
            truncated = finding.Truncated
        });
        written++;
    }
    return written;
}

static async Task<int> RunSilentAsync(string[] arguments, string workspacePath)
{
    var filter = Option(arguments, "--filter") ?? NetMindDefaults.SilentDefaultFilter;
    // 按进程抓取（工作台“按进程采集”传入）：仅落库归属指定进程的事务，其余包照解析不落库。
    var processName = Option(arguments, "--process-name");
    var sessionTarget = string.IsNullOrWhiteSpace(processName) ? "全部进程" : $"进程：{processName}";
    var signalDirectory = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), NetMindDefaults.SettingsDirectoryName);
    Directory.CreateDirectory(signalDirectory);
    var readyPath = Path.Combine(signalDirectory, NetMindDefaults.SilentReadyFileName);
    var stopPath = Path.Combine(signalDirectory, NetMindDefaults.SilentStopFileName);
    try { File.Delete(stopPath); } catch { /* 旧停止信号清理失败不阻断启动 */ }

    // 提升权限后无法重定向 stdout，就绪/失败事实统一写信号文件供工作台轮询。
    if (!WinDivert.IsLibraryPresent)
    {
        var message = $"未找到 {NetMindDefaults.WinDivertLibraryFileName}：请将 WinDivert.dll 与 {NetMindDefaults.WinDivertDriverFileName} 放入采集后台目录后重试。";
        WriteSilentReady(readyPath, failed: true, message, filter, workspacePath);
        Console.Error.WriteLine(message);
        return 3;
    }
    if (!IsElevated())
    {
        const string message = "静默抓包需要管理员权限：请由工作台以提升权限方式重新启动采集后台。";
        WriteSilentReady(readyPath, failed: true, message, filter, workspacePath);
        Console.Error.WriteLine(message);
        return 4;
    }

    await EnsureWorkspaceAsync(workspacePath);
    using var archive = new TrafficArchive(workspacePath);
    var sessionId = Guid.NewGuid();
    var startedAt = DateTimeOffset.UtcNow;
    await archive.StartSessionAsync(new CaptureSessionRecord(sessionId, startedAt, null, NetMindDefaults.SessionModeSilentCapture, sessionTarget, NetMindDefaults.SessionStateRunning));

    // 静默抓包同样允许采集浏览器页内 Hook。此前接收器只存在于 proxy 命令，
    // 导致 WinDivert 模式下 CDP 即使完成注入也没有任何上报端点。
    PageHookReceiver? pageHookReceiver = null;
    var hookPortText = Option(arguments, "--hook-port");
    var hookToken = Option(arguments, "--hook-token");
    if (hookPortText is not null && int.TryParse(hookPortText, out var hookPort) && hookPort > 0)
    {
        var receiver = new PageHookReceiver(hookPort, sessionId,
            events => archive.RecordPageHooksAsync(events), hookToken);
        try
        {
            receiver.Start();
            pageHookReceiver = receiver;
        }
        catch (Exception exception)
        {
            await receiver.DisposeAsync();
            await new WorkspaceStore(workspacePath).AppendAuditAsync("hooks.page-receiver-failed",
                new { mode = "silent", hookPort, error = exception.Message });
        }
    }

    // 密钥日志：采集浏览器经 SSLKEYLOGFILE 写入同一工作区路径，后台增量读取用于 TLS 解密。
    var keyLogPath = Path.Combine(workspacePath, NetMindDefaults.SilentKeyLogRelativePath);
    try { Directory.CreateDirectory(Path.GetDirectoryName(keyLogPath)!); } catch { /* 目录已存在或不可建时退化为不解密 */ }
    var keyLog = new SilentTlsKeyLog(keyLogPath);
    var engine = new SilentCaptureEngine(filter, transaction =>
    {
        // 进程字段形如“进程名（PID n）”：按名称前缀匹配，同进程重启后 PID 变化不影响过滤。
        if (!string.IsNullOrWhiteSpace(processName) &&
            !transaction.Traffic.Process.StartsWith(processName + "（", StringComparison.Ordinal))
            return Task.CompletedTask;
        return archive.RecordAsync(sessionId, transaction.Traffic, transaction.RequestBody, transaction.ResponseBody);
    }, keyLog);
    using var cancellation = new CancellationTokenSource();
    Console.CancelKeyPress += (_, eventArgs) =>
    {
        eventArgs.Cancel = true;
        cancellation.Cancel();
    };

    Task runTask;
    try
    {
        runTask = engine.RunAsync(cancellation.Token);
        // 句柄打开在首个 await 前同步执行；失败时返回的任务已处于错误态。
        if (runTask.IsFaulted)
            throw runTask.Exception?.InnerException ?? new InvalidOperationException("静默抓包启动失败。");
        WriteSilentReady(readyPath, failed: false, null, filter, workspacePath);
        Console.WriteLine("NetMind CoreHost 静默抓包已启动");
        Console.WriteLine($"过滤表达式：{filter}");
        Console.WriteLine($"工作区：{workspacePath}");
        Console.WriteLine("按 Ctrl+C 或工作台停止信号退出。\n");
    }
    catch (Exception exception)
    {
        WriteSilentReady(readyPath, failed: true, exception.Message, filter, workspacePath);
        if (pageHookReceiver is not null) await pageHookReceiver.DisposeAsync();
        try
        {
            await archive.CompleteSessionAsync(new CaptureSessionRecord(sessionId, startedAt, DateTimeOffset.UtcNow,
                NetMindDefaults.SessionModeSilentCapture, sessionTarget, NetMindDefaults.SessionStateCompleted));
            await new WorkspaceStore(workspacePath).AppendAuditAsync(NetMindDefaults.AuditEventSilentCaptureFailed,
                new { error = exception.Message });
        }
        catch { /* 启动失败收尾审计不阻断退出 */ }
        Console.Error.WriteLine($"静默抓包启动失败：{exception.Message}");
        return 5;
    }

    // 停止途径只有两个：工作台写入停止信号文件，或控制台 Ctrl+C。
    // 绝不能把 stdin EOF 当作停止请求：提升权限（runas）启动的控制台 stdin 可能立即关闭，
    // 会被误判为“用户回车退出”，导致启动后立即自动停止。
    while (!cancellation.IsCancellationRequested && !runTask.IsCompleted)
    {
        await Task.Delay(NetMindDefaults.SilentStopPollIntervalMilliseconds);
        if (File.Exists(stopPath)) cancellation.Cancel();
    }
    string? engineError = null;
    try { await runTask; }
    catch (Exception exception)
    {
        // 引擎主循环异常绝不吞掉：写崩溃日志与审计，并在运行摘要中标记，避免静默断采。
        engineError = exception.ToString();
        WriteCrashLog("silent-engine", exception);
        try
        {
            await new WorkspaceStore(workspacePath).AppendAuditAsync(NetMindDefaults.AuditEventSilentCaptureFailed,
                new { error = exception.Message });
        }
        catch { /* 审计写入失败不阻断退出 */ }
    }

    if (pageHookReceiver is not null) await pageHookReceiver.DisposeAsync();

    await archive.CompleteSessionAsync(new CaptureSessionRecord(sessionId, startedAt, DateTimeOffset.UtcNow,
        NetMindDefaults.SessionModeSilentCapture, sessionTarget, NetMindDefaults.SessionStateCompleted));
    try { File.Delete(readyPath); } catch { /* 信号文件清理失败不阻断退出 */ }
    try { File.Delete(stopPath); } catch { /* 同上 */ }
    WriteSilentLastRun(signalDirectory, engine.TransactionCount, engine.GetDiagnostics(), engineError);
    Console.WriteLine($"静默抓包已安全停止，共结算 {engine.TransactionCount} 条事务。");
    return engineError is null ? 0 : 6;
}

static void WriteCrashLog(string kind, Exception? exception)
{
    try
    {
        var directory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), NetMindDefaults.SettingsDirectoryName);
        Directory.CreateDirectory(directory);
        var line = $"[{DateTimeOffset.UtcNow:O}] {kind}: {exception}" + Environment.NewLine;
        File.AppendAllText(Path.Combine(directory, "silent-crash.log"), line);
    }
    catch { /* 崩溃日志写入失败不再二次抛出 */ }
}

static void WriteSilentReady(string readyPath, bool failed, string? error, string filter, string workspacePath)
{
    var payload = JsonSerializer.Serialize(new { state = failed ? "failed" : "ready", error, filter, workspace = workspacePath,
        timestamp = DateTimeOffset.UtcNow }, new JsonSerializerOptions(JsonSerializerDefaults.Web));
    File.WriteAllText(readyPath, payload);
}

/// <summary>停止后写运行摘要（silent-last-run.json）：结算条数、分层计数与引擎异常，供工作台与排障读取。</summary>
static void WriteSilentLastRun(string signalDirectory, long transactions, string diagnostics, string? error)
{
    try
    {
        var payload = JsonSerializer.Serialize(new { stoppedAt = DateTimeOffset.UtcNow, transactions, diagnostics, error },
            new JsonSerializerOptions(JsonSerializerDefaults.Web));
        File.WriteAllText(Path.Combine(signalDirectory, "silent-last-run.json"), payload);
    }
    catch { /* 摘要写入失败不阻断退出 */ }
}

static bool IsElevated()
{
    if (!OperatingSystem.IsWindows()) return true;
    using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
    return new System.Security.Principal.WindowsPrincipal(identity)
        .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
}

static async Task<int> RunSimulationAsync(string[] arguments, string workspacePath)
{
    var countText = Option(arguments, "--count") ?? "12";
    if (!int.TryParse(countText, out var count) || count is < 1 or > 10000)
        throw new ArgumentException("--count 必须是 1 到 10000 之间的整数。");

    await EnsureWorkspaceAsync(workspacePath);
    using var archive = new TrafficArchive(workspacePath);
    var sessionId = Guid.NewGuid();
    var startedAt = DateTimeOffset.UtcNow;
    await archive.StartSessionAsync(new CaptureSessionRecord(sessionId, startedAt, null, NetMindDefaults.SessionModeSimulation, "全部进程", NetMindDefaults.SessionStateRunning));
    var samples = DemoData.CreateTraffic();
    for (var index = 0; index < count; index++)
    {
        var traffic = index < samples.Count ? samples[index] : DemoData.CreateLiveRecord(index);
        await archive.RecordAsync(sessionId, traffic, Encoding.UTF8.GetBytes(traffic.RequestSummary), Encoding.UTF8.GetBytes(traffic.ResponseSummary));
    }
    await archive.CompleteSessionAsync(new CaptureSessionRecord(sessionId, startedAt, DateTimeOffset.UtcNow, NetMindDefaults.SessionModeSimulation, "全部进程", NetMindDefaults.SessionStateCompleted));
    Console.WriteLine($"模拟采集完成：写入 {count} 条事务。");
    Console.WriteLine($"当前工作区共有 {archive.GetTrafficCount()} 条事务。");
    return 0;
}

static int ShowStatus(string workspacePath)
{
    if (!File.Exists(Path.Combine(workspacePath, NetMindDefaults.WorkspaceManifestFileName)))
    {
        Console.Error.WriteLine("工作区尚未初始化，请先运行 simulate 或 proxy 命令。");
        return 2;
    }

    using var archive = new TrafficArchive(workspacePath);
    Console.WriteLine($"工作区：{workspacePath}");
    Console.WriteLine($"事务数量：{archive.GetTrafficCount()}");
    Console.WriteLine("最近事务：");
    foreach (var item in archive.GetRecentTraffic(10))
    {
        var traffic = item.Traffic;
        Console.WriteLine($"  {traffic.Timestamp:yyyy-MM-dd HH:mm:ss}  {traffic.Method,-7} {traffic.StatusCode}  {traffic.Endpoint}");
    }
    return 0;
}

static async Task EnsureWorkspaceAsync(string workspacePath)
{
    if (File.Exists(Path.Combine(workspacePath, NetMindDefaults.WorkspaceManifestFileName))) return;
    var workspace = new WorkspaceStore(workspacePath);
    await workspace.InitializeAsync("北辰实验室");
}

// ── 脚本钩子系统接线（阶段二） ───────────────────────────────────────

static async Task<ScriptHookEngine?> TryCreateHookEngineAsync(string workspacePath)
{
    // 工作区配置是钩子的唯一启用来源：它同时绑定脚本、挂载点和工作区数据目录。
    // 旧版全局 EnableTrafficHooks 字段仅保留配置兼容，不再形成第二道无语义差异的门控。
    var configPath = Path.Combine(workspacePath, NetMindDefaults.ScriptsDirectoryName, NetMindDefaults.HookConfigFileName);
    if (!File.Exists(configPath))
    {
        Console.Error.WriteLine($"未找到钩子配置文件 {configPath}，钩子保持关闭。");
        return null;
    }
    HookConfiguration? configuration;
    try
    {
        configuration = JsonSerializer.Deserialize<HookConfiguration>(
            await File.ReadAllTextAsync(configPath), new JsonSerializerOptions(JsonSerializerDefaults.Web));
    }
    catch (Exception exception)
    {
        Console.Error.WriteLine($"钩子配置文件损坏，钩子保持关闭：{exception.Message}");
        return null;
    }
    if (configuration is null || !configuration.Enabled)
    {
        Console.Error.WriteLine("钩子配置未启用，钩子保持关闭。");
        return null;
    }
    if (string.IsNullOrWhiteSpace(configuration.ScriptPath))
    {
        Console.Error.WriteLine("钩子配置缺少脚本路径（scriptPath），钩子保持关闭。");
        return null;
    }

    var scriptPath = Path.IsPathRooted(configuration.ScriptPath)
        ? configuration.ScriptPath
        : Path.Combine(workspacePath, NetMindDefaults.ScriptsDirectoryName, configuration.ScriptPath);
    try { scriptPath = Path.GetFullPath(scriptPath); }
    catch (Exception exception)
    {
        Console.Error.WriteLine($"钩子脚本路径无效，钩子保持关闭：{exception.Message}");
        return null;
    }
    if (!File.Exists(scriptPath))
    {
        Console.Error.WriteLine($"钩子脚本不存在：{scriptPath}，钩子保持关闭。");
        return null;
    }

    // 逐项启停：未勾选的钩子点不入队（单点判断在引擎侧）。
    var hookPoints = configuration.Hooks ?? new HookPointSwitches();
    var enabledEvents = new List<string>();
    if (hookPoints.BeforeSend) enabledEvents.Add(HookEventNames.RequestBeforeSend);
    if (hookPoints.AfterSend) enabledEvents.Add(HookEventNames.RequestAfterSend);
    if (hookPoints.BeforeWrite) enabledEvents.Add(HookEventNames.ResponseBeforeWrite);
    if (hookPoints.AfterDeliver) enabledEvents.Add(HookEventNames.ResponseAfterDeliver);
    if (enabledEvents.Count == 0)
    {
        Console.Error.WriteLine("钩子配置未勾选任何钩子点，钩子保持关闭。");
        return null;
    }

    var host = ResolveSandboxHost();
    if (host is null)
    {
        Console.Error.WriteLine("未找到脚本沙箱宿主（NetMind.SandboxHost），钩子保持关闭。");
        return null;
    }

    var dataDirectory = Path.Combine(workspacePath, NetMindDefaults.ScriptsDirectoryName, NetMindDefaults.HookDataDirectoryName);
    var auditWorkspace = new WorkspaceStore(workspacePath);
    // 只构造不启动：实际启动由调用方在代理就绪标记输出后异步执行，避免阻塞就绪。
    return new ScriptHookEngine(host.Value.FileName, host.Value.AssemblyArgument, scriptPath, dataDirectory, enabledEvents,
        async (eventName, detail) => await auditWorkspace.AppendAuditAsync(eventName, new { detail }));
}

/// <summary>解析脚本沙箱宿主：优先exe，次选经 dotnet 运行的 dll；生产布局为同级 SandboxHost 目录。</summary>
static (string FileName, string? AssemblyArgument)? ResolveSandboxHost()
{
    var candidates = new[]
    {
        Path.Combine(AppContext.BaseDirectory, NetMindDefaults.SandboxHostDirectoryName),
        Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", NetMindDefaults.SandboxHostDirectoryName))
    };
    foreach (var directory in candidates)
    {
        var executable = Path.Combine(directory, NetMindDefaults.SandboxHostExecutableName);
        if (File.Exists(executable)) return (executable, null);
        var assembly = Path.Combine(directory, NetMindDefaults.SandboxHostAssemblyName);
        if (File.Exists(assembly)) return (NetMindDefaults.DotnetCommandName, assembly);
    }
    return null;
}

static string DefaultWorkspacePath() => Path.Combine(
    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
    NetMindDefaults.SettingsDirectoryName, "workspaces", "northstar-lab");

static string? Option(string[] arguments, string name)
{
    for (var index = 0; index < arguments.Length - 1; index++)
        if (arguments[index].Equals(name, StringComparison.OrdinalIgnoreCase)) return arguments[index + 1];
    return null;
}

static int UnknownCommand(string command)
{
    Console.Error.WriteLine($"未知命令：{command}");
    PrintHelp();
    return 2;
}

static void PrintHelp()
{
    Console.WriteLine($"""
        NetMind CoreHost · 流量捕获后台

        用法：
          NetMind.CoreHost proxy [--listen {NetMindDefaults.DefaultListenEndpoint}] [--workspace 路径] [--tls-inspect] [--hook-port 端口]
          NetMind.CoreHost silent [--filter tcp] [--workspace 路径]
          NetMind.CoreHost simulate [--count 12] [--workspace 路径]
          NetMind.CoreHost status [--workspace 路径]

        命令：
          proxy      启动 HTTP/1.1 显式代理并保存捕获结果
          silent     底层静默抓包：WinDivert 透明捕获 TCP 并重组 HTTP（需管理员与 WinDivert 驱动）
          simulate   生成确定性模拟流量，用于演示和验证
          status     显示工作区事务统计与最近记录

        安全说明：
          HTTPS 解密默认关闭。--tls-inspect 只在工作区 CA 已由用户明确启用并信任后生效；不绕过证书固定。

        脚本钩子：
          proxy 启动时若工作台已开启流量钩子，且工作区 {NetMindDefaults.ScriptsDirectoryName}/{NetMindDefaults.HookConfigFileName}
          启用、钩子脚本存在，将拉起隔离的 Python 钩子工作进程，在请求发送前后与响应写回前后
          投递观察事件；任一条件不满足时钩子保持关闭，不影响代理正常捕获。

        页内 Hook：
          --hook-port 传入时并行起一个仅监听 127.0.0.1 的接收端点，接收采集浏览器注入脚本
          上报的页面调用事件（XHR/fetch/加密/编码/存储）并写入工作区 page_hooks 表。
        """);
}

// ── 钩子配置 schema 与布局常量 ─────────────────────────────────────────

/// <summary>钩子逐项开关（对应配置文件的 hooks 节点，camelCase 反序列化）。</summary>
sealed record HookPointSwitches(bool BeforeSend = false, bool AfterSend = false, bool BeforeWrite = false, bool AfterDeliver = false);

/// <summary>工作区钩子配置（缺失字段按默认值处理，enabled 默认关闭）。</summary>
sealed record HookConfiguration(bool Enabled = false, string? ScriptPath = null, HookPointSwitches? Hooks = null);
