using System.Collections.Concurrent;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace NetMind.Core;

/// <summary>
/// 钩子事务快照：代理关键路径观察点上的请求/响应切片。
/// 正文数组只存引用不复制；完整 SHA-256 惰性计算并在快照内缓存，
/// 同一事务的多个钩子点（如响应前/响应后）复用同一快照即可避免重复哈希。
/// </summary>
public sealed class HookTransactionSnapshot
{
    private string? _bodySha256;

    public HookTransactionSnapshot(Guid txnId, Guid sessionId, string method, string url, string host, string endpoint,
        IReadOnlyDictionary<string, string>? headers, byte[] body)
    {
        TxnId = txnId;
        SessionId = sessionId;
        Method = method;
        Url = url;
        Host = host;
        Endpoint = endpoint;
        Headers = headers;
        Body = body;
    }

    /// <summary>事务标识（与捕获持久化的事务记录同一标识，便于关联）。</summary>
    public Guid TxnId { get; }

    /// <summary>捕获会话标识。</summary>
    public Guid SessionId { get; }

    public string Method { get; private set; }
    public string Url { get; private set; }
    public string Host { get; private set; }
    public string Endpoint { get; private set; }
    public IReadOnlyDictionary<string, string>? Headers { get; private set; }
    public byte[] Body { get; private set; }
    public long BodySize => Body.LongLength;

    /// <summary>响应状态码；请求发送前不可得，由代理自发送后观察点起补齐。</summary>
    public int? StatusCode { get; set; }

    /// <summary>本次事务是否被脚本改写过。落库证据据此标注，避免把改写后的字节当成客户端原始意图。</summary>
    public bool Mutated { get; private set; }

    /// <summary>改写前的 URL；未被改写时为 null。</summary>
    public string? OriginalUrl { get; private set; }

    /// <summary>改写前的正文；未被改写时为 null。保留它才能同时说明「客户端本来要发什么」与「实际发了什么」。</summary>
    public byte[]? OriginalBody { get; private set; }

    /// <summary>
    /// 用脚本裁决后的内容替换快照。
    /// 之所以就地替换而不是新建快照：同一事务的多个挂载点共用一份快照，
    /// 替换后观察事件与落库证据自然等于「实际上线的字节」。原始值单独留存供对照。
    /// </summary>
    internal void ReplaceForMutation(string method, string url, string host, string endpoint,
        IReadOnlyDictionary<string, string>? headers, byte[] body)
    {
        if (!Mutated)
        {
            OriginalUrl = Url;
            OriginalBody = Body;
            Mutated = true;
        }
        Method = method;
        Url = url;
        Host = host;
        Endpoint = endpoint;
        Headers = headers;
        Body = body;
        _bodySha256 = null; // 正文已变，缓存哈希必须作废
    }

    /// <summary>正文完整 SHA-256（十六进制小写），惰性计算并缓存。</summary>
    public string GetBodySha256() => _bodySha256 ??= Convert.ToHexString(SHA256.HashData(Body)).ToLowerInvariant();
}

/// <summary>钩子工作进程产出的一条观察结论（stdout finding NDJSON 解析结果）。</summary>
public sealed record HookFinding(
    string Event,
    string? TxnId,
    string? HookName,
    JsonElement Data,
    bool Truncated,
    DateTimeOffset ReceivedAtUtc);

/// <summary>脚本 Hook 的只读运行快照；不含请求正文、响应正文或完整 URL。</summary>
public sealed record ScriptHookMetricsSnapshot(
    string State,
    int EnabledHookCount,
    long QueuedEvents,
    long DeliveredEvents,
    long ProcessedEvents,
    long DroppedEvents,
    long Findings,
    long WorkerErrors,
    long Restarts,
    DateTimeOffset? LastProcessedAtUtc,
    string? LastEvent,
    string? LastError,
    string? DisabledReason);

/// <summary>
/// 脚本钩子引擎：拉起 SandboxHost hook-worker 隔离子进程，
/// 把代理关键路径观察事件经双限有界队列泵入其 stdin（NDJSON、无 BOM UTF-8），
/// 持续异步读取 stdout 收集 finding/error（防管道死锁），
/// 周期心跳探活、崩溃按滑动窗口熔断重启、优雅关停时先清队再发 shutdown。
/// 所有对外路径（Emit/审计/启停）绝不向代理关键路径抛出。
/// </summary>
public sealed class ScriptHookEngine : IAsyncDisposable
{
    private static readonly Dictionary<string, string> HookFunctionNames = new(StringComparer.Ordinal)
    {
        [HookEventNames.RequestBeforeSend] = HookEventNames.FunctionBeforeSend,
        [HookEventNames.RequestAfterSend] = HookEventNames.FunctionAfterSend,
        [HookEventNames.ResponseBeforeWrite] = HookEventNames.FunctionBeforeWrite,
        [HookEventNames.ResponseAfterDeliver] = HookEventNames.FunctionAfterDeliver,
    };

    private readonly string _hostFileName;
    private readonly string? _hostAssemblyArgument;
    private readonly string _scriptPath;
    private readonly string _dataDirectory;
    private readonly HashSet<string> _enabledEvents;
    private readonly Func<string, string, Task>? _audit;
    private readonly HookEventQueue _queue = new();
    /// <summary>脚本在 ready 时上报的拦截规则；热路径只读，整体替换而不就地修改。</summary>
    private IReadOnlyList<HookInterceptRule> _interceptRules = [];
    /// <summary>在途拦截：correlationId → 等待裁决的调用方。</summary>
    private readonly ConcurrentDictionary<string, TaskCompletionSource<HookInterceptVerdict?>> _pendingIntercepts = new(StringComparer.Ordinal);
    private long _interceptMutatedCount;
    private long _interceptTimeoutCount;
    private long _interceptRejectedCount;
    private readonly ConcurrentQueue<HookFinding> _findings = new();
    private readonly SemaphoreSlim _sessionGate = new(1, 1);
    private readonly LinkedList<DateTime> _restartTimestamps = new(); // 只在 _sessionGate 内访问
    private readonly CancellationTokenSource _engineCancellation = new();
    private readonly string _heartbeatLine;
    private readonly string _shutdownLine;
    private WorkerSession? _session;
    private Task? _supervisorTask;
    private long _deliveredEventCount;
    private long _processedEventCount;
    private long _findingEventCount;
    private long _workerErrorCount;
    private long _restartCount;
    private long _lastProcessedUtcTicks;
    private string? _lastProcessedEvent;
    private string? _lastWorkerError;
    private string? _disabledReason;
    private volatile bool _stopping;
    private volatile bool _disabled;

    /// <summary>
    /// 构造钩子引擎（不启动子进程；启动见 <see cref="StartAsync"/>）。
    /// </summary>
    /// <param name="hostFileName">SandboxHost 可执行文件；仅存 dll 时传 dotnet 命令。</param>
    /// <param name="hostAssemblyArgument">经 dotnet 运行时启动时的 SandboxHost.dll 路径，否则为 null。</param>
    /// <param name="scriptPath">用户钩子脚本完整路径。</param>
    /// <param name="dataDirectory">钩子键值数据目录（store 落盘处）。</param>
    /// <param name="enabledHookEvents">勾选启用的钩子事件名（未勾选的事件不入队，单点判断在引擎侧）。</param>
    /// <param name="audit">生命周期审计回调（事件名, 脱敏明细）；明细只含状态与计数，引擎保证不抛。</param>
    public ScriptHookEngine(string hostFileName, string? hostAssemblyArgument, string scriptPath, string dataDirectory,
        IEnumerable<string> enabledHookEvents, Func<string, string, Task>? audit = null)
    {
        if (string.IsNullOrWhiteSpace(hostFileName)) throw new ArgumentException("钩子沙箱宿主路径不能为空。", nameof(hostFileName));
        if (string.IsNullOrWhiteSpace(scriptPath)) throw new ArgumentException("钩子脚本路径不能为空。", nameof(scriptPath));
        if (string.IsNullOrWhiteSpace(dataDirectory)) throw new ArgumentException("钩子数据目录不能为空。", nameof(dataDirectory));
        _hostFileName = hostFileName;
        _hostAssemblyArgument = hostAssemblyArgument;
        _scriptPath = scriptPath;
        _dataDirectory = dataDirectory;
        _enabledEvents = new HashSet<string>(enabledHookEvents ?? [], StringComparer.Ordinal);
        _audit = audit;
        _heartbeatLine = JsonSerializer.Serialize(new { type = HookWorkerMessageTypes.Heartbeat }, HookEventEnvelope.JsonOptions);
        _shutdownLine = JsonSerializer.Serialize(new { type = HookWorkerMessageTypes.Shutdown }, HookEventEnvelope.JsonOptions);
    }

    /// <summary>钩子系统当前是否处于启用状态（工作进程已就绪且未被停用/停止）。</summary>
    public bool IsEnabled => !_disabled && !_stopping && _session is { } session && !SafeHasExited(session.Process);

    /// <summary>勾选启用的钩子点数量。</summary>
    public int EnabledHookCount => _enabledEvents.Count;

    /// <summary>因队列限额被丢弃的事件累计条数（供 UI 展示）。</summary>
    public long DroppedEventCount => _queue.DroppedCount;

    /// <summary>当前在队事件条数。</summary>
    public long QueuedEventCount => _queue.Count;

    /// <summary>已成功写入工作进程 stdin 的事件累计条数。</summary>
    public long DeliveredEventCount => Interlocked.Read(ref _deliveredEventCount);

    /// <summary>工作进程已完成、跳过或超时的事件累计条数。</summary>
    public long ProcessedEventCount => Interlocked.Read(ref _processedEventCount);

    /// <summary>工作进程上报的 error 消息累计条数。</summary>
    public long WorkerErrorCount => Interlocked.Read(ref _workerErrorCount);

    /// <summary>待取回的观察结论条数。</summary>
    public int FindingCount => _findings.Count;

    /// <summary>脚本声明的拦截规则条数（0 表示纯观察，不阻塞任何请求）。</summary>
    public int InterceptRuleCount => Volatile.Read(ref _interceptRules).Count;

    /// <summary>脚本实际改写的事务累计条数。</summary>
    public long InterceptMutatedCount => Interlocked.Read(ref _interceptMutatedCount);

    /// <summary>拦截超时或工作进程不可用而按原样放行的累计条数（fail-open 次数）。</summary>
    public long InterceptFailOpenCount => Interlocked.Read(ref _interceptTimeoutCount);

    /// <summary>因改写内容超限被拒绝的累计条数。</summary>
    public long InterceptRejectedCount => Interlocked.Read(ref _interceptRejectedCount);

    /// <summary>
    /// 定向测试专用：直接取出待投递的事件信封。
    /// 代理挂载点是否真的按序触发、信封字段是否正确，只有绕开工作进程才能独立验证——
    /// 否则断言会连带依赖 Python 是否可用。生产路径不使用本方法。
    /// </summary>
    internal bool TryDequeuePendingForTest([NotNullWhen(true)] out HookEventEnvelope? envelope) =>
        _queue.TryDequeue(out envelope);

    /// <summary>返回线程安全的轻量运行指标，不读取或复制任何事务正文。</summary>
    public ScriptHookMetricsSnapshot GetMetricsSnapshot()
    {
        var ticks = Interlocked.Read(ref _lastProcessedUtcTicks);
        return new ScriptHookMetricsSnapshot(
            _stopping ? "stopping" : _disabled ? "disabled" : IsEnabled ? "running" : "starting",
            EnabledHookCount,
            QueuedEventCount,
            DeliveredEventCount,
            ProcessedEventCount,
            DroppedEventCount,
            Interlocked.Read(ref _findingEventCount),
            WorkerErrorCount,
            Interlocked.Read(ref _restartCount),
            ticks <= 0 ? null : new DateTimeOffset(ticks, TimeSpan.Zero),
            Volatile.Read(ref _lastProcessedEvent),
            Volatile.Read(ref _lastWorkerError),
            Volatile.Read(ref _disabledReason));
    }

    /// <summary>
    /// 观察事件投递入口：构建信封入队，供代理关键路径单行 fire-and-forget 调用；
    /// 永不阻塞、永不抛出，引擎停用/未勾选/快照缺失时静默忽略。
    /// </summary>
    /// <param name="statusCode">该观察点已知的响应状态码（发送前钩子传 null）。</param>
    public void Emit(string hookEvent, HookTransactionSnapshot? snapshot, int? statusCode = null)
    {
        try
        {
            if (_stopping || _disabled || snapshot is null) return;
            if (statusCode.HasValue) snapshot.StatusCode = statusCode;
            if (!_enabledEvents.Contains(hookEvent)) return;
            if (!HookFunctionNames.TryGetValue(hookEvent, out var hookName)) return;

            // 关键路径预检：队列已满或字节接近上限时直接跳过整个信封（含预览与哈希计算），
            // 避免在背压下白白消耗代理关键路径 CPU；队内腾出余量后自动恢复投递。
            if (_queue.Count >= NetMindDefaults.HookEventQueueCapacity ||
                _queue.CurrentBytes >= NetMindDefaults.HookEventQueueMaximumBytes * 9 / 10)
            {
                _queue.RecordDrop();
                return;
            }

            var envelope = BuildEnvelope(hookEvent, hookName, snapshot);
            if (envelope is not null) _queue.TryEnqueue(envelope);
        }
        catch
        {
            // 观察路径绝不向代理关键路径抛出。
        }
    }

    /// <summary>构建事件信封。观察投递与阻塞拦截共用同一份构建逻辑，避免两条路径的字段语义漂移。</summary>
    private static HookEventEnvelope? BuildEnvelope(string hookEvent, string hookName, HookTransactionSnapshot snapshot)
    {
        var body = snapshot.Body;
        string? preview = null;
        var truncated = false;
        if (body.Length > 0)
        {
            var previewLength = Math.Min(body.Length, NetMindDefaults.HookBodyPreviewBytes);
            preview = Convert.ToBase64String(body, 0, previewLength);
            truncated = body.Length > NetMindDefaults.HookBodyPreviewBytes;
        }
        return new HookEventEnvelope(
            hookEvent,
            snapshot.TxnId.ToString(),
            snapshot.SessionId.ToString(),
            hookName,
            snapshot.Method,
            snapshot.Url,
            snapshot.Host,
            snapshot.Endpoint,
            snapshot.StatusCode,
            snapshot.Headers,
            preview,
            truncated,
            null, // 正文 SHA-256 推迟到泵线程序列化时惰性计算，不在关键路径同步哈希
            snapshot.BodySize)
        {
            Snapshot = snapshot
        };
    }

    /// <summary>取回并清空当前全部观察结论（供 UI 轮询消费）。</summary>
    public IReadOnlyList<HookFinding> DrainFindings(int maximumCount = int.MaxValue)
    {
        maximumCount = Math.Max(0, maximumCount);
        var taken = new List<HookFinding>(Math.Min(_findings.Count, maximumCount));
        while (taken.Count < maximumCount && _findings.TryDequeue(out var finding)) taken.Add(finding);
        return taken;
    }

    /// <summary>
    /// 启动钩子系统：拉起工作进程并等待就绪。
    /// Python 缺失、脚本缺失、策略拒绝、就绪超时等一律中文审计 hooks.disabled 并静默降级，返回 false，不抛给调用方。
    /// </summary>
    public async Task<bool> StartAsync(CancellationToken cancellationToken = default)
    {
        if (_stopping || _disabled) return false;
        await AuditSafeAsync(NetMindDefaults.AuditEventHooksEnabled, $"计划启用钩子点 {_enabledEvents.Count} 个");
        try
        {
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _engineCancellation.Token);
            var reason = await LaunchSessionAsync(linked.Token);
            if (reason is not null)
            {
                await DisableAsync(reason);
                return false;
            }
            _supervisorTask = Task.Run(SuperviseAsync);
            await AuditSafeAsync(NetMindDefaults.AuditEventHooksStarted,
                $"已启用钩子点 {_enabledEvents.Count} 个 · 队列容量 {NetMindDefaults.HookEventQueueCapacity} 条 · 队列字节上限 {NetMindDefaults.HookEventQueueMaximumBytes} 字节");
            return true;
        }
        catch (Exception) when (cancellationToken.IsCancellationRequested || _engineCancellation.IsCancellationRequested)
        {
            return false;
        }
        catch (Exception exception)
        {
            await DisableAsync("钩子工作进程启动失败 · " + exception.GetType().Name);
            return false;
        }
    }

    public async ValueTask DisposeAsync()
    {
        _stopping = true;
        _engineCancellation.Cancel();
        await _sessionGate.WaitAsync(CancellationToken.None);
        WorkerSession? session;
        try
        {
            session = _session;
            _session = null;
        }
        finally
        {
            _sessionGate.Release();
        }

        var droppedOnFlush = 0L;
        var abandonedOnFlush = false;
        if (session is not null)
        {
            // 先停事件泵，再以条数与总时限双约束清队 flush，超限放弃剩余事件直接发 shutdown 行等待退出，超时杀进程树。
            session.Cancellation.Cancel();
            await SafeJoinAsync(session.PumpTask);
            var flushedCount = 0;
            using (var flushDeadline = new CancellationTokenSource(NetMindDefaults.HookShutdownFlushTimeoutMilliseconds))
            {
                try
                {
                    while (_queue.TryDequeue(out var envelope))
                    {
                        if (flushedCount >= NetMindDefaults.HookShutdownFlushMaximumEvents || flushDeadline.IsCancellationRequested)
                        {
                            // 超限/超时：放弃剩余在队事件（计入既有丢弃计数），立即发 shutdown。
                            abandonedOnFlush = true;
                            while (_queue.TryDequeue(out _)) droppedOnFlush++;
                            break;
                        }
                        var line = JsonSerializer.Serialize(envelope, HookEventEnvelope.JsonOptions);
                        await session.Process.StandardInput.WriteLineAsync(line.AsMemory(), flushDeadline.Token);
                        flushedCount++;
                    }
                    await session.Process.StandardInput.WriteLineAsync(_shutdownLine.AsMemory(), flushDeadline.Token);
                    await session.Process.StandardInput.FlushAsync(flushDeadline.Token);
                }
                catch
                {
                    // 写端已断（工作进程先退出）或时限到：放弃 flush，直接进入强制收尾。
                }
            }
            try
            {
                await session.ExitTask.WaitAsync(TimeSpan.FromMilliseconds(NetMindDefaults.HookShutdownJoinTimeoutMilliseconds));
            }
            catch (TimeoutException)
            {
                TryKill(session);
            }
            catch
            {
                // 退出等待被打断不影响收尾。
            }
            await SafeJoinAsync(session.OutputTask);
            await SafeJoinAsync(session.ErrorTask);
            await SafeJoinAsync(session.HeartbeatTask);
            SafeDisposeProcess(session);
            session.Cancellation.Dispose();
        }

        var supervisor = _supervisorTask;
        if (supervisor is not null) await SafeJoinAsync(supervisor);
        await AuditSafeAsync(NetMindDefaults.AuditEventHooksDisabled,
            $"已随宿主停止 · 累计投递 {DeliveredEventCount} 条 · 丢弃 {DroppedEventCount} 条" +
            (abandonedOnFlush ? $"（关停清队放弃 {droppedOnFlush} 条）" : string.Empty) +
            $" · 工作进程报错 {WorkerErrorCount} 条");
        _engineCancellation.Dispose();
        _sessionGate.Dispose();
    }

    // ── 工作进程会话生命周期 ─────────────────────────────────────────────────

    /// <summary>拉起一次工作进程并等待 ready；成功返回 null 并激活会话，失败返回中文原因。</summary>
    private async Task<string?> LaunchSessionAsync(CancellationToken cancellationToken)
    {
        var startInfo = new ProcessStartInfo(_hostFileName)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
            // 写入工作进程 stdin 必须无 BOM UTF-8，否则首行信封会被 BOM 污染导致 JSON 解析失败。
            StandardInputEncoding = new UTF8Encoding(false)
        };
        if (_hostAssemblyArgument is not null) startInfo.ArgumentList.Add(_hostAssemblyArgument);
        startInfo.ArgumentList.Add("hook-worker");
        startInfo.ArgumentList.Add(_scriptPath);
        startInfo.ArgumentList.Add(_dataDirectory);

        Process process;
        try
        {
            process = new Process { StartInfo = startInfo };
            if (!process.Start())
            {
                process.Dispose();
                return "无法启动钩子沙箱宿主进程。";
            }
        }
        catch (Exception exception) when (exception is Win32Exception or FileNotFoundException)
        {
            return "未找到钩子沙箱宿主或运行时不可用，请重新构建工作台项目。";
        }

        var session = new WorkerSession(process);
        // stdout/stderr 必须持续异步读取，防止管道写满导致工作进程死锁。
        session.OutputTask = Task.Run(() => ReadOutputAsync(session));
        session.ErrorTask = Task.Run(() => DrainErrorAsync(session));

        // 就绪等待时长复用既有心跳常量：间隔 × 最大丢失次数。
        var readyTimeout = TimeSpan.FromMilliseconds((long)NetMindDefaults.HookHeartbeatIntervalMilliseconds * NetMindDefaults.HookHeartbeatMaximumMisses);
        try
        {
            var completed = await Task.WhenAny(session.ReadySignal.Task, session.ExitTask, Task.Delay(readyTimeout, cancellationToken));
            if (completed == session.ReadySignal.Task && await session.ReadySignal.Task)
            {
                ActivateSession(session);
                return null;
            }

            if (completed == session.ExitTask || SafeHasExited(process))
            {
                var exitCode = SafeExitCode(process);
                await TearDownSessionAsync(session, kill: false);
                return exitCode switch
                {
                    2 => "钩子工作进程参数无效或脚本读取失败（退出码 2）。",
                    3 => "钩子脚本未通过策略校验或 Python 运行时不可用（退出码 3）。",
                    4 => "钩子工作进程隔离初始化失败（退出码 4）。",
                    _ => $"钩子工作进程在就绪前退出（退出码 {exitCode}）。"
                };
            }

            await TearDownSessionAsync(session, kill: true);
            return "钩子工作进程就绪超时，已停止该进程。";
        }
        catch (OperationCanceledException)
        {
            await TearDownSessionAsync(session, kill: true);
            throw;
        }
    }

    private void ActivateSession(WorkerSession session)
    {
        if (_stopping)
        {
            TearDownSessionAsync(session, kill: true).GetAwaiter().GetResult();
            return;
        }
        _session = session;
        session.PumpTask = Task.Run(() => PumpAsync(session));
        session.HeartbeatTask = Task.Run(() => HeartbeatAsync(session));
    }

    /// <summary>监管循环：工作进程意外退出即审计 crashed，并按滑动窗口熔断重启。</summary>
    private async Task SuperviseAsync()
    {
        while (!_stopping && !_disabled)
        {
            var session = _session;
            if (session is null) return;
            try { await session.ExitTask; } catch { /* 进程对象被提前释放时按退出处理。 */ }
            if (_stopping || _disabled) return;
            await AuditSafeAsync(NetMindDefaults.AuditEventHooksCrashed,
                $"工作进程退出码 {SafeExitCode(session.Process)} · 累计投递 {DeliveredEventCount} 条 · 丢弃 {DroppedEventCount} 条");
            if (!await TryRestartAsync()) return;
        }
    }

    private async Task<bool> TryRestartAsync()
    {
        await _sessionGate.WaitAsync(CancellationToken.None);
        try
        {
            if (_stopping || _disabled) return false;
            var now = DateTime.UtcNow;
            while (_restartTimestamps.Count > 0 &&
                   (now - _restartTimestamps.First!.Value).TotalSeconds > NetMindDefaults.HookRestartWindowSeconds)
                _restartTimestamps.RemoveFirst();
            if (_restartTimestamps.Count >= NetMindDefaults.HookRestartMaximumPerWindow)
            {
                var previous = _session;
                _session = null;
                await TearDownSessionAsync(previous, kill: true);
                _disabled = true;
                await AuditSafeAsync(NetMindDefaults.AuditEventHooksDisabled,
                    $"滑动窗口 {NetMindDefaults.HookRestartWindowSeconds} 秒内重启达到 {NetMindDefaults.HookRestartMaximumPerWindow} 次上限，钩子已停用");
                return false;
            }
            _restartTimestamps.AddLast(now);
            Interlocked.Increment(ref _restartCount);
            var old = _session;
            _session = null;
            await TearDownSessionAsync(old, kill: true);

            using var linked = CancellationTokenSource.CreateLinkedTokenSource(_engineCancellation.Token);
            string? reason;
            try
            {
                reason = await LaunchSessionAsync(linked.Token);
            }
            catch (OperationCanceledException)
            {
                return false;
            }
            if (_stopping) return false;
            if (reason is not null)
            {
                await DisableAsync(reason);
                return false;
            }
            return true;
        }
        finally
        {
            _sessionGate.Release();
        }
    }

    private async Task DisableAsync(string reason)
    {
        _disabled = true;
        Volatile.Write(ref _disabledReason, reason);
        var previous = _session;
        _session = null;
        await TearDownSessionAsync(previous, kill: true);
        await AuditSafeAsync(NetMindDefaults.AuditEventHooksDisabled,
            $"{reason} · 累计投递 {DeliveredEventCount} 条 · 丢弃 {DroppedEventCount} 条");
    }

    private static async Task TearDownSessionAsync(WorkerSession? session, bool kill)
    {
        if (session is null) return;
        session.Cancellation.Cancel();
        if (kill) TryKill(session);
        // 关停路径上的任务等待统一压缩到短时限，保证优雅关停整体耗时可控。
        await SafeJoinAsync(session.OutputTask);
        await SafeJoinAsync(session.ErrorTask);
        await SafeJoinAsync(session.PumpTask);
        await SafeJoinAsync(session.HeartbeatTask);
        SafeDisposeProcess(session);
        session.Cancellation.Dispose();
    }

    // ── 事件泵 / 输出读取 / 心跳 ────────────────────────────────────────────

    private async Task PumpAsync(WorkerSession session)
    {
        try
        {
            while (await _queue.WaitToReadAsync(session.Cancellation.Token))
            {
                while (_queue.TryDequeue(out var envelope))
                {
                    // 惰性哈希：信封携带快照引用，序列化前才在泵线程补齐 SHA-256（快照内缓存复用）。
                    var serialized = envelope.Snapshot is { } source && envelope.BodySha256 is null
                        ? envelope with { BodySha256 = source.Body.Length > 0 ? source.GetBodySha256() : null, Snapshot = null }
                        : envelope;
                    var line = JsonSerializer.Serialize(serialized, HookEventEnvelope.JsonOptions);
                    await WriteRawLineAsync(session, line, session.Cancellation.Token);
                    Interlocked.Increment(ref _deliveredEventCount);
                }
            }
        }
        catch (OperationCanceledException)
        {
            // 正常停止：剩余事件由 DisposeAsync 的清队 flush 接管。
        }
        catch
        {
            // 写端断开说明工作进程已退出，监管循环负责重启决策。
        }
    }

    private async Task ReadOutputAsync(WorkerSession session)
    {
        try
        {
            string? line;
            while ((line = await session.Process.StandardOutput.ReadLineAsync(session.Cancellation.Token)) is not null)
            {
                Interlocked.Exchange(ref session.StdoutActivityFlag, 1);
                HandleOutputLine(session, line);
            }
        }
        catch
        {
            // 输出读取中断（工作进程先退出或被取消）属正常情形。
        }
        finally
        {
            session.ReadySignal.TrySetResult(false);
        }
    }

    /// <summary>stderr 只持续抽干防管道死锁，不保留原文。</summary>
    private async Task DrainErrorAsync(WorkerSession session)
    {
        try
        {
            while ((await session.Process.StandardError.ReadLineAsync(session.Cancellation.Token)) is not null) { }
        }
        catch
        {
            // 错误流读取中断不影响主流程。
        }
    }

    /// <summary>
    /// 心跳探活：周期写入心跳行，工作进程对每行心跳回一行 heartbeat-ack，
    /// 失联判定只看写端-读端回环（上一周期内是否收到 ack 或任何 stdout 输出），
    /// 与事件投递、钩子命中无关，因此“有流量但命中不了已定义钩子”不会误计失联；
    /// 连续缺失达上限即杀进程交由监管循环重启。
    /// </summary>
    private async Task HeartbeatAsync(WorkerSession session)
    {
        var misses = 0;
        try
        {
            while (!session.Cancellation.IsCancellationRequested)
            {
                await Task.Delay(NetMindDefaults.HookHeartbeatIntervalMilliseconds, session.Cancellation.Token);
                if (SafeHasExited(session.Process)) return;
                try
                {
                    await WriteRawLineAsync(session, _heartbeatLine, session.Cancellation.Token);
                }
                catch
                {
                    return; // 写端已断：工作进程已退出，由监管循环处理。
                }

                var acked = Interlocked.Exchange(ref session.HeartbeatAckFlag, 0) == 1;
                var hadStdoutActivity = Interlocked.Exchange(ref session.StdoutActivityFlag, 0) == 1;
                misses = acked || hadStdoutActivity ? 0 : misses + 1;
                if (misses >= NetMindDefaults.HookHeartbeatMaximumMisses)
                {
                    await AuditSafeAsync(NetMindDefaults.AuditEventHooksCrashed,
                        $"连续 {NetMindDefaults.HookHeartbeatMaximumMisses} 次心跳无应答，判定失联 · 累计投递 {DeliveredEventCount} 条");
                    TryKill(session);
                    return;
                }
            }
        }
        catch (OperationCanceledException)
        {
            // 正常停止。
        }
    }

    private static async Task WriteRawLineAsync(WorkerSession session, string line, CancellationToken cancellationToken)
    {
        // 事件泵与心跳共享同一条 stdin；StreamWriter 不支持并发写，必须把“一行 + flush”作为原子段串行化。
        await session.InputGate.WaitAsync(cancellationToken);
        try
        {
            var stdin = session.Process.StandardInput;
            await stdin.WriteLineAsync(line.AsMemory(), cancellationToken);
            await stdin.FlushAsync(cancellationToken);
        }
        finally
        {
            session.InputGate.Release();
        }
    }

    private void HandleOutputLine(WorkerSession session, string line)
    {
        if (string.IsNullOrWhiteSpace(line)) return;
        try
        {
            using var document = JsonDocument.Parse(line);
            if (document.RootElement.ValueKind != JsonValueKind.Object) return;
            var type = ReadString(document.RootElement, "type");
            if (type == HookWorkerMessageTypes.HeartbeatAck)
            {
                // 心跳回环应答：证明驱动主循环与 stdout 写端存活（StdoutActivityFlag 已由读取循环置位）。
                Interlocked.Exchange(ref session.HeartbeatAckFlag, 1);
                return;
            }
            switch (type)
            {
                case HookWorkerMessageTypes.Ready:
                    // 脚本用模块级 INTERCEPT 声明要拦截什么，随 ready 一次性上报；
                    // 之后每个请求的匹配都在宿主进程内完成，热路径不再问工作进程。
                    Volatile.Write(ref _interceptRules, ReadInterceptRules(document.RootElement));
                    session.ReadySignal.TrySetResult(true);
                    break;
                case HookWorkerMessageTypes.Pass:
                case HookWorkerMessageTypes.Mutate:
                    CompleteIntercept(document.RootElement, type);
                    break;
                case HookWorkerMessageTypes.Finding:
                    HandleFinding(document.RootElement);
                    break;
                case HookWorkerMessageTypes.Error:
                    Interlocked.Increment(ref _workerErrorCount);
                    var error = ReadString(document.RootElement, "message") ?? "钩子工作进程报告错误";
                    Volatile.Write(ref _lastWorkerError, WorkspaceStore.Redact(error[..Math.Min(500, error.Length)]));
                    break;
                case HookWorkerMessageTypes.Processed:
                    Interlocked.Increment(ref _processedEventCount);
                    Interlocked.Exchange(ref _lastProcessedUtcTicks, DateTimeOffset.UtcNow.UtcTicks);
                    Volatile.Write(ref _lastProcessedEvent, ReadString(document.RootElement, "event"));
                    break;
            }
        }
        catch (JsonException)
        {
            // 非协议输出直接忽略。
        }
    }

    /// <summary>解析 ready 消息里脚本声明的拦截规则；缺失、格式错误或声明了不可改写的挂载点都按“不拦截”处理。</summary>
    private static IReadOnlyList<HookInterceptRule> ReadInterceptRules(JsonElement element)
    {
        if (!element.TryGetProperty("intercept", out var array) || array.ValueKind != JsonValueKind.Array) return [];
        var rules = new List<HookInterceptRule>();
        foreach (var item in array.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.Object) continue;
            Dictionary<string, string>? headers = null;
            if (item.TryGetProperty("headers", out var headerElement) && headerElement.ValueKind == JsonValueKind.Object)
            {
                headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                foreach (var property in headerElement.EnumerateObject())
                {
                    if (headers.Count >= NetMindDefaults.HookMaximumMutatedHeaders) break;
                    headers[property.Name] = property.Value.ValueKind == JsonValueKind.String
                        ? property.Value.GetString() ?? string.Empty
                        : string.Empty;
                }
            }
            // 任一模式非法则整条规则作废：部分生效会让脚本以为自己限定了范围，实际却在拦截别的流量。
            var rule = HookInterceptRule.TryCreate(
                ReadString(item, "event"), ReadString(item, "url"), ReadString(item, "method"),
                ReadString(item, "host"), ReadString(item, "endpoint"), ReadString(item, "body"),
                ReadString(item, "status"), headers);
            if (rule is null) continue;
            rules.Add(rule);
            if (rules.Count >= NetMindDefaults.HookMaximumInterceptRules) break;
        }
        return rules;
    }

    /// <summary>
    /// 本次事务是否命中脚本声明的拦截规则。匹配在宿主进程内完成，代理热路径每个请求都会调用；
    /// 未声明任何规则时立刻返回 false，纯观察脚本不付任何代价。
    /// </summary>
    public bool ShouldIntercept(string hookEvent, HookTransactionSnapshot? snapshot)
    {
        if (snapshot is null || _stopping || _disabled || !HookInterceptRule.IsMutable(hookEvent)) return false;
        var rules = Volatile.Read(ref _interceptRules);
        if (rules.Count == 0) return false;
        for (var index = 0; index < rules.Count; index++)
            if (rules[index].Matches(hookEvent, snapshot)) return true;
        return false;
    }

    /// <summary>
    /// 阻塞式拦截：把事务交给脚本，等待改写裁决。
    /// 超时、工作进程不可用、协议错误一律返回 null（fail-open，代理照原样发送）——
    /// 拦截失败绝不能把浏览器挂住，这是本方法唯一不可让步的约束。
    /// </summary>
    public async Task<HookInterceptVerdict?> InterceptAsync(string hookEvent, HookTransactionSnapshot? snapshot,
        int? statusCode = null, CancellationToken cancellationToken = default)
    {
        if (snapshot is null || !IsEnabled) return null;
        if (statusCode.HasValue) snapshot.StatusCode = statusCode;
        if (!HookFunctionNames.TryGetValue(hookEvent, out var hookName)) return null;
        var session = _session;
        if (session is null) return null;

        var correlationId = Guid.NewGuid().ToString("N");
        var pending = new TaskCompletionSource<HookInterceptVerdict?>(TaskCreationOptions.RunContinuationsAsynchronously);
        if (!_pendingIntercepts.TryAdd(correlationId, pending)) return null;
        try
        {
            var envelope = BuildEnvelope(hookEvent, hookName, snapshot);
            if (envelope is null) return null;
            var line = JsonSerializer.Serialize(new
            {
                type = HookWorkerMessageTypes.Intercept,
                correlationId,
                envelope
            }, HookEventEnvelope.JsonOptions);
            await WriteRawLineAsync(session, line, cancellationToken);

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(NetMindDefaults.HookInterceptTimeoutMilliseconds);
            await using (timeout.Token.Register(() => pending.TrySetResult(null)))
            {
                var verdict = await pending.Task;
                if (verdict is null) Interlocked.Increment(ref _interceptTimeoutCount);
                return verdict;
            }
        }
        catch (Exception exception) when (exception is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
        {
            // 工作进程写失败/已退出：按放行处理，绝不把异常抛回代理关键路径。
            Interlocked.Increment(ref _interceptTimeoutCount);
            return null;
        }
        finally
        {
            _pendingIntercepts.TryRemove(correlationId, out _);
        }
    }

    /// <summary>工作进程回执：把裁决交回等待中的拦截调用。</summary>
    private void CompleteIntercept(JsonElement element, string type)
    {
        var correlationId = ReadString(element, "correlationId");
        if (correlationId is null || !_pendingIntercepts.TryRemove(correlationId, out var pending)) return;
        if (type == HookWorkerMessageTypes.Pass)
        {
            pending.TrySetResult(null);
            return;
        }
        IReadOnlyDictionary<string, string?>? headers = null;
        if (element.TryGetProperty("headers", out var headerElement) && headerElement.ValueKind == JsonValueKind.Object)
        {
            var map = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
            foreach (var property in headerElement.EnumerateObject())
            {
                if (map.Count >= NetMindDefaults.HookMaximumMutatedHeaders) break;
                map[property.Name] = property.Value.ValueKind == JsonValueKind.Null ? null : property.Value.GetString();
            }
            headers = map;
        }
        var body = ReadString(element, "body");
        if (body is not null && Encoding.UTF8.GetByteCount(body) > NetMindDefaults.HookMaximumMutatedBodyBytes)
        {
            // 超限改写按放行处理：宁可不改，也不把半截正文发上去。
            Interlocked.Increment(ref _interceptRejectedCount);
            pending.TrySetResult(null);
            return;
        }
        var verdict = new HookInterceptVerdict(
            ReadString(element, "url"),
            ReadString(element, "method"),
            element.TryGetProperty("statusCode", out var status) && status.TryGetInt32(out var parsedStatus) ? parsedStatus : null,
            headers,
            body);
        Interlocked.Increment(ref _interceptMutatedCount);
        pending.TrySetResult(verdict.HasChanges ? verdict : null);
    }

    private void HandleFinding(JsonElement element)
    {
        var finding = new HookFinding(
            ReadString(element, "event") ?? string.Empty,
            ReadString(element, "txnId"),
            ReadString(element, "hookName"),
            element.TryGetProperty("data", out var data) ? data.Clone() : JsonSerializer.SerializeToElement<object?>(null),
            element.TryGetProperty("truncated", out var truncated) && truncated.ValueKind == JsonValueKind.True,
            DateTimeOffset.UtcNow);
        _findings.Enqueue(finding);
        Interlocked.Increment(ref _findingEventCount);
        while (_findings.Count > NetMindDefaults.HookEventQueueCapacity && _findings.TryDequeue(out _)) { }
    }

    // ── 审计与进程辅助 ──────────────────────────────────────────────────────

    private async Task AuditSafeAsync(string eventName, string detail)
    {
        if (_audit is null) return;
        try
        {
            await _audit(eventName, detail);
        }
        catch
        {
            // 审计失败不影响钩子生命周期。
        }
    }

    private static string? ReadString(JsonElement element, string name)
        => element.TryGetProperty(name, out var property) && property.ValueKind == JsonValueKind.String
            ? property.GetString()
            : null;

    private static void TryKill(WorkerSession session)
    {
        try
        {
            if (!session.Process.HasExited) session.Process.Kill(entireProcessTree: true);
        }
        catch
        {
            // 进程可能刚好退出。
        }
    }

    private static bool SafeHasExited(Process process)
    {
        try { return process.HasExited; }
        catch { return true; }
    }

    private static int SafeExitCode(Process process)
    {
        try { return process.HasExited ? process.ExitCode : -1; }
        catch { return -1; }
    }

    private static void SafeDisposeProcess(WorkerSession session)
    {
        try { session.Process.Dispose(); }
        catch { /* 进程句柄释放失败不阻塞收尾。 */ }
    }

    private static async Task SafeJoinAsync(Task? task)
        => await SafeJoinAsync(task, TimeSpan.FromMilliseconds(NetMindDefaults.HookShutdownJoinTimeoutMilliseconds));

    private static async Task SafeJoinAsync(Task? task, TimeSpan timeout)
    {
        if (task is null) return;
        try
        {
            await task.WaitAsync(timeout);
        }
        catch
        {
            // 任务取消、失败或等待超时都不阻塞生命周期收尾。
        }
    }

    /// <summary>单个钩子工作进程会话：进程、stdin 写入依赖的流任务与会话级计数。</summary>
    private sealed class WorkerSession
    {
        public WorkerSession(Process process)
        {
            Process = process;
            ExitTask = process.WaitForExitAsync();
        }

        public Process Process { get; }
        public Task ExitTask { get; }
        public TaskCompletionSource<bool> ReadySignal { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public CancellationTokenSource Cancellation { get; } = new();
        public SemaphoreSlim InputGate { get; } = new(1, 1);
        public Task? PumpTask { get; set; }
        public Task? OutputTask { get; set; }
        public Task? ErrorTask { get; set; }
        public Task? HeartbeatTask { get; set; }

        /// <summary>距上次心跳以来是否收到过 heartbeat-ack（1=收到）。</summary>
        public int HeartbeatAckFlag;

        /// <summary>距上次心跳以来 stdout 是否出现过输出（1=有）。</summary>
        public int StdoutActivityFlag;
    }
}
