using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Threading.Channels;

namespace NetMind.Core;

/// <summary>
/// 钩子事件名常量。事件名是 CoreHost 与钩子工作进程之间的 NDJSON 协议契约，不得改值。
/// </summary>
public static class HookEventNames
{
    /// <summary>请求即将发往后端之前触发。</summary>
    public const string RequestBeforeSend = "request.before_send";

    /// <summary>请求已发往后端之后触发。</summary>
    public const string RequestAfterSend = "request.after_send";

    /// <summary>响应即将写回客户端之前触发。</summary>
    public const string ResponseBeforeWrite = "response.before_write";

    /// <summary>响应已交付客户端之后触发。</summary>
    public const string ResponseAfterDeliver = "response.after_deliver";

    /// <summary>用户脚本中与 <see cref="RequestBeforeSend"/> 对应的钩子函数名。</summary>
    public const string FunctionBeforeSend = "on_before_send";

    /// <summary>用户脚本中与 <see cref="RequestAfterSend"/> 对应的钩子函数名。</summary>
    public const string FunctionAfterSend = "on_after_send";

    /// <summary>用户脚本中与 <see cref="ResponseBeforeWrite"/> 对应的钩子函数名。</summary>
    public const string FunctionBeforeWrite = "on_before_write";

    /// <summary>用户脚本中与 <see cref="ResponseAfterDeliver"/> 对应的钩子函数名。</summary>
    public const string FunctionAfterDeliver = "on_after_deliver";
}

/// <summary>
/// 钩子工作进程 NDJSON 消息类型常量（stdout 逐行输出，协议契约）。
/// </summary>
public static class HookWorkerMessageTypes
{
    /// <summary>工作进程完成初始化、可接收事件。</summary>
    public const string Ready = "ready";

    /// <summary>钩子产出的观察结论。</summary>
    public const string Finding = "finding";

    /// <summary>策略拒绝、事件处理异常或超时等错误。</summary>
    public const string Error = "error";

    /// <summary>一个事件已执行、跳过或超时；用于运行指标与无副作用试跑完成判定。</summary>
    public const string Processed = "processed";

    /// <summary>宿主请求工作进程优雅退出的输入指令类型。</summary>
    public const string Shutdown = "shutdown";

    /// <summary>宿主写入的心跳探活行类型；工作进程收到后回一行 <see cref="HeartbeatAck"/>，写端-读端回环据此判活。</summary>
    public const string Heartbeat = "heartbeat";

    /// <summary>工作进程对心跳行的应答类型，证明驱动主循环与 stdout 写端存活。</summary>
    public const string HeartbeatAck = "heartbeat-ack";

    /// <summary>
    /// 宿主发出的阻塞式拦截请求：与观察事件不同，代理会等待本条的裁决后再决定发往上游/回写的字节。
    /// 只在脚本用 INTERCEPT 声明且规则命中时发出。
    /// </summary>
    public const string Intercept = "intercept";

    /// <summary>工作进程对拦截请求的裁决：放行原始字节。</summary>
    public const string Pass = "pass";

    /// <summary>工作进程对拦截请求的裁决：按携带的字段改写后再向下传播。</summary>
    public const string Mutate = "mutate";
}

/// <summary>
/// 脚本声明的拦截规则（脚本模块级 <c>INTERCEPT</c>，工作进程在 ready 时上报）。
///
/// 规则由脚本自己声明，但匹配放在宿主进程内做纯字符串比较：代理热路径上每个请求都要过一遍，
/// 若下推给 Python 判断，等于所有流量都被单线程 worker 串行化，页面会直接卡死。
/// </summary>
/// <remarks>
/// 条件全部是正则，可同时约束 URL、方法、主机、路径、请求/响应头、正文与状态码；
/// 给出的条件之间是 AND，全部命中才拦截。任一条件均可省略表示不限。
///
/// 正则优先用 <see cref="RegexOptions.NonBacktracking"/> 编译：它由 .NET 保证线性时间，
/// 脚本里写出病态回溯模式也不会在代理热路径上炸掉。只有用到该引擎不支持的构造
/// （反向引用、环视）时才退回普通引擎，并强制带上匹配超时兜底。
/// 模式在 ready 上报时编译一次并缓存，热路径不重复解析。
/// </remarks>
public sealed class HookInterceptRule
{
    private readonly Regex? _url;
    private readonly Regex? _method;
    private readonly Regex? _host;
    private readonly Regex? _endpoint;
    private readonly Regex? _body;
    private readonly Regex? _status;
    private readonly (string Name, Regex Value)[] _headers;

    private HookInterceptRule(string hookEvent, Regex? url, Regex? method, Regex? host, Regex? endpoint,
        Regex? body, Regex? status, (string Name, Regex Value)[] headers)
    {
        Event = hookEvent;
        _url = url;
        _method = method;
        _host = host;
        _endpoint = endpoint;
        _body = body;
        _status = status;
        _headers = headers;
    }

    public string Event { get; }

    /// <summary>只有这两个挂载点在数据尚未发出/写回之前，改写才有意义。</summary>
    public static bool IsMutable(string hookEvent) =>
        hookEvent is HookEventNames.RequestBeforeSend or HookEventNames.ResponseBeforeWrite;

    /// <summary>编译一条规则；事件名不可改写或任一模式非法时返回 null（该条规则整体作废，不做部分生效）。</summary>
    public static HookInterceptRule? TryCreate(string? hookEvent, string? url, string? method, string? host,
        string? endpoint, string? body, string? status, IReadOnlyDictionary<string, string>? headers)
    {
        if (hookEvent is null || !IsMutable(hookEvent)) return null;
        if (!TryCompile(url, out var urlRegex) || !TryCompile(method, out var methodRegex) ||
            !TryCompile(host, out var hostRegex) || !TryCompile(endpoint, out var endpointRegex) ||
            !TryCompile(body, out var bodyRegex) || !TryCompile(status, out var statusRegex)) return null;
        var compiledHeaders = Array.Empty<(string, Regex)>();
        if (headers is { Count: > 0 })
        {
            var list = new List<(string, Regex)>(headers.Count);
            foreach (var (name, pattern) in headers)
            {
                if (!TryCompile(pattern, out var valueRegex)) return null;
                // 值模式为空表示“只要求该头存在”，用永真模式表达，匹配逻辑不必再分叉。
                list.Add((name, valueRegex ?? EmptyMatchesAll));
            }
            compiledHeaders = [.. list];
        }
        return new HookInterceptRule(hookEvent, urlRegex, methodRegex, hostRegex, endpointRegex,
            bodyRegex, statusRegex, compiledHeaders);
    }

    private static readonly Regex EmptyMatchesAll = new(string.Empty, RegexOptions.NonBacktracking | RegexOptions.CultureInvariant);

    private static bool TryCompile(string? pattern, out Regex? regex)
    {
        regex = null;
        if (string.IsNullOrEmpty(pattern)) return true;
        const RegexOptions shared = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant;
        try
        {
            regex = new Regex(pattern, shared | RegexOptions.NonBacktracking);
            return true;
        }
        catch (NotSupportedException)
        {
            // 用到了反向引用/环视等线性引擎不支持的构造：退回普通引擎，必须带匹配超时。
        }
        catch (ArgumentException)
        {
            return false; // 模式本身非法
        }
        try
        {
            regex = new Regex(pattern, shared,
                TimeSpan.FromMilliseconds(NetMindDefaults.HookInterceptRegexTimeoutMilliseconds));
            return true;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    /// <summary>本次事务是否命中。任一正则超时都按“不命中”处理，绝不让匹配拖住代理关键路径。</summary>
    public bool Matches(string hookEvent, HookTransactionSnapshot snapshot)
    {
        if (!string.Equals(Event, hookEvent, StringComparison.Ordinal)) return false;
        try
        {
            if (_method is not null && !_method.IsMatch(snapshot.Method)) return false;
            if (_url is not null && !_url.IsMatch(snapshot.Url)) return false;
            if (_host is not null && !_host.IsMatch(snapshot.Host)) return false;
            if (_endpoint is not null && !_endpoint.IsMatch(snapshot.Endpoint)) return false;
            if (_status is not null &&
                !_status.IsMatch(snapshot.StatusCode?.ToString(CultureInfo.InvariantCulture) ?? string.Empty)) return false;
            foreach (var (name, valuePattern) in _headers)
            {
                if (snapshot.Headers is null || !snapshot.Headers.TryGetValue(name, out var value)) return false;
                if (!valuePattern.IsMatch(value ?? string.Empty)) return false;
            }
            if (_body is not null)
            {
                // 正文可能很大，而这条判断在每个请求上都要跑：只匹配前若干字节，并在文档中写明这个边界。
                var body = snapshot.Body;
                if (body.Length == 0) return false;
                var length = Math.Min(body.Length, NetMindDefaults.HookInterceptBodyMatchBytes);
                if (!_body.IsMatch(Encoding.UTF8.GetString(body, 0, length))) return false;
            }
            return true;
        }
        catch (RegexMatchTimeoutException)
        {
            return false;
        }
    }
}

/// <summary>
/// 拦截裁决：脚本要求如何改写这次事务。字段为 null 表示该项不动。
/// 无论脚本返回什么，宿主都必须能在超时/崩溃/协议错误时退回原始字节（fail-open）——
/// 拦截失败绝不能让浏览器挂住。
/// </summary>
/// <param name="Url">改写后的请求 URL（仅请求侧有效）。</param>
/// <param name="Method">改写后的 HTTP 方法（仅请求侧有效）。</param>
/// <param name="StatusCode">改写后的响应状态码（仅响应侧有效）。</param>
/// <param name="Headers">要覆盖或新增的头；值为 null 表示删除该头。</param>
/// <param name="Body">改写后的正文（UTF-8 文本）。</param>
public sealed record HookInterceptVerdict(
    string? Url = null,
    string? Method = null,
    int? StatusCode = null,
    IReadOnlyDictionary<string, string?>? Headers = null,
    string? Body = null)
{
    /// <summary>没有任何字段被改写时不必重建请求/响应，直接走原路径。</summary>
    public bool HasChanges => Url is not null || Method is not null || StatusCode is not null
                              || Body is not null || Headers is { Count: > 0 };
}

/// <summary>
/// 钩子事件信封：代理关键路径观察点的只读快照，经 NDJSON 逐行投递给钩子工作进程。
/// 序列化采用 camelCase（<see cref="JsonSerializerDefaults.Web"/>），与既有 JSON 约定一致。
/// </summary>
public sealed record HookEventEnvelope(
    string Event,
    string TxnId,
    string SessionId,
    string HookName,
    string Method,
    string Url,
    string Host,
    string Endpoint,
    int? StatusCode,
    IReadOnlyDictionary<string, string>? Headers,
    string? BodyPreviewBase64,
    bool BodyTruncated,
    string? BodySha256,
    long BodySize)
{
    /// <summary>信封协议版本号，当前固定为 <see cref="NetMindDefaults.HookEventSchemaVersion"/>。</summary>
    public int Schema { get; init; } = NetMindDefaults.HookEventSchemaVersion;

    /// <summary>
    /// 产生该信封的事务快照引用（不参与 JSON 序列化与协议契约）；
    /// 供泵线程序列化时惰性取用正文 SHA-256，避免代理关键路径同步哈希。
    /// </summary>
    [JsonIgnore]
    public HookTransactionSnapshot? Snapshot { get; init; }

    /// <summary>钩子信封序列化/反序列化共用的 camelCase 选项。</summary>
    public static JsonSerializerOptions JsonOptions { get; } = new(JsonSerializerDefaults.Web);

    /// <summary>估算信封序列化后的 UTF-8 字节量，供队列字节限额记账；末尾追加每封固定开销的保守上界。</summary>
    public long EstimateBytes()
    {
        long bytes = NetMindDefaults.HookEnvelopeFixedOverheadBytes; // 字段名、引号、逗号等结构性开销的保守上界
        bytes += sizeof(long) + sizeof(int) + sizeof(bool); // BodySize、Schema、BodyTruncated
        bytes += EstimateText(Event) + EstimateText(TxnId) + EstimateText(SessionId) + EstimateText(HookName)
               + EstimateText(Method) + EstimateText(Url) + EstimateText(Host) + EstimateText(Endpoint)
               + EstimateText(BodyPreviewBase64) + EstimateText(BodySha256);
        if (Headers is not null)
            foreach (var header in Headers)
                bytes += EstimateText(header.Key) + EstimateText(header.Value);
        return bytes;
    }

    private static long EstimateText(string? text) => text is null ? 0 : Encoding.UTF8.GetByteCount(text);
}

/// <summary>
/// 钩子事件有界队列：条数与累计字节双限额（均取自 <see cref="NetMindDefaults"/>）。
/// 任一限额不足时先丢弃最旧事件并计数；<see cref="TryEnqueue"/> 永不阻塞、永不抛出。
/// </summary>
public sealed class HookEventQueue
{
    private readonly Channel<HookEventEnvelope> _channel;
    private readonly int _capacity;
    private readonly long _maximumBytes;
    private readonly object _gate = new();
    private long _count;
    private long _currentBytes;
    private long _droppedCount;

    /// <summary>按默认常量（<see cref="NetMindDefaults.HookEventQueueCapacity"/> 条、<see cref="NetMindDefaults.HookEventQueueMaximumBytes"/> 字节）构造。</summary>
    public HookEventQueue() : this(NetMindDefaults.HookEventQueueCapacity, NetMindDefaults.HookEventQueueMaximumBytes)
    {
    }

    /// <summary>按指定条数容量与字节上限构造（仅供测试注入，生产走默认构造）。</summary>
    public HookEventQueue(int capacity, long maximumBytes)
    {
        if (capacity < 1) throw new ArgumentOutOfRangeException(nameof(capacity), "钩子事件队列容量必须为正数。");
        if (maximumBytes < 1) throw new ArgumentOutOfRangeException(nameof(maximumBytes), "钩子事件队列字节上限必须为正数。");
        _capacity = capacity;
        _maximumBytes = maximumBytes;
        _channel = Channel.CreateUnbounded<HookEventEnvelope>(new UnboundedChannelOptions { SingleReader = false, SingleWriter = false });
    }

    /// <summary>条数容量。</summary>
    public int Capacity => _capacity;

    /// <summary>因限额不足被丢弃的事件累计条数。</summary>
    public long DroppedCount => Interlocked.Read(ref _droppedCount);

    /// <summary>当前在队事件条数。</summary>
    public long Count => Interlocked.Read(ref _count);

    /// <summary>当前在队事件的累计估算字节量。</summary>
    public long CurrentBytes => Interlocked.Read(ref _currentBytes);

    /// <summary>记录在构建信封前因背压预检而跳过的一条事件。</summary>
    public void RecordDrop() => Interlocked.Increment(ref _droppedCount);

    /// <summary>
    /// 尝试入队观察事件：永不阻塞、永不抛出。
    /// 条数或字节限额不足时循环丢弃最旧事件（并计入 <see cref="DroppedCount"/>）后写入。
    /// </summary>
    public bool TryEnqueue(HookEventEnvelope? envelope)
    {
        try
        {
            if (envelope is null) return false;
            var size = envelope.EstimateBytes();
            lock (_gate)
            {
                while (_count >= _capacity || _currentBytes + size > _maximumBytes)
                {
                    if (!TryDropOldestLocked())
                    {
                        // 单个信封本身超过字节上限时直接丢弃，不能让账面突破硬限制。
                        Interlocked.Increment(ref _droppedCount);
                        return true;
                    }
                }
                if (!_channel.Writer.TryWrite(envelope)) return false;
                Interlocked.Increment(ref _count);
                Interlocked.Add(ref _currentBytes, size);
                return true;
            }
        }
        catch
        {
            return false; // 入队路径绝不向关键路径抛出。
        }
    }

    /// <summary>尝试取回最旧事件；成功即扣减条数与字节记账。</summary>
    public bool TryDequeue([NotNullWhen(true)] out HookEventEnvelope? envelope)
    {
        envelope = null;
        try
        {
            lock (_gate)
            {
                if (!_channel.Reader.TryRead(out envelope)) return false;
                AccountDequeuedLocked(envelope);
                return true;
            }
        }
        catch
        {
            return false;
        }
    }

    /// <summary>等待并取回下一个事件；成功即扣减条数与字节记账。</summary>
    public async ValueTask<HookEventEnvelope> ReadAsync(CancellationToken cancellationToken = default)
    {
        var envelope = await _channel.Reader.ReadAsync(cancellationToken);
        lock (_gate) AccountDequeuedLocked(envelope);
        return envelope;
    }

    /// <summary>等待队列出现可读事件（不取出）。</summary>
    public ValueTask<bool> WaitToReadAsync(CancellationToken cancellationToken = default)
        => _channel.Reader.WaitToReadAsync(cancellationToken);

    /// <summary>队列全部消费完毕信号。</summary>
    public Task Completion => _channel.Reader.Completion;

    private void AccountDequeuedLocked(HookEventEnvelope envelope)
    {
        Interlocked.Decrement(ref _count);
        Interlocked.Add(ref _currentBytes, -envelope.EstimateBytes());
    }

    private bool TryDropOldestLocked()
    {
        if (!_channel.Reader.TryRead(out var oldest) || oldest is null) return false;
        Interlocked.Decrement(ref _count);
        Interlocked.Add(ref _currentBytes, -oldest.EstimateBytes());
        Interlocked.Increment(ref _droppedCount);
        return true;
    }
}
