using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace NetMind.Core;

public sealed record ProxyOptions(
    IPAddress Address,
    int Port,
    // 名额按连接生命周期持有（隧道/TLS 检查连接可存活数分钟）：视频流、长轮询与多站点浏览会长期占用，
    // 上限过低时新连接在信号量上排队，浏览器握手预算耗尽后主动断开，表现为验证码/二维码/图片零星加载失败。
    int MaximumConcurrentConnections = 256,
    int MaximumBodyBytes = 16 * 1024 * 1024,
    TimeSpan? RequestTimeout = null,
    bool EnableHttpsTunneling = true,
    bool EnableTlsInspection = false,
    string? WorkspacePath = null);

public sealed class ExplicitHttpProxy : IAsyncDisposable
{
    private const int MaximumHeaderBytes = NetMindDefaults.ProxyMaximumHeaderBytes;
    private readonly ProxyOptions _options;
    private readonly TrafficArchive _archive;
    private readonly HttpClient _httpClient;
    private readonly SemaphoreSlim _connectionSlots;
    private readonly WorkspaceCertificateAuthority? _certificateAuthority;
    private volatile ScriptHookEngine? _hookEngine;
    private readonly TlsInspectionPolicy _tlsInspectionPolicy = TlsInspectionPolicy.Empty;
    private readonly object _activeGate = new();
    private readonly HashSet<Task> _activeConnections = [];
    private readonly Guid _sessionId = Guid.NewGuid();
    private TcpListener? _listener;

    public ExplicitHttpProxy(ProxyOptions options, TrafficArchive archive, HttpMessageHandler? httpHandler = null, ScriptHookEngine? hookEngine = null)
    {
        _options = options;
        _archive = archive;
        _hookEngine = hookEngine;
        _connectionSlots = new SemaphoreSlim(options.MaximumConcurrentConnections);
        var handler = httpHandler ?? new HttpClientHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None,
            UseCookies = false,
            UseProxy = false
        };
        _httpClient = new HttpClient(handler) { Timeout = options.RequestTimeout ?? TimeSpan.FromSeconds(30) };
        if (options.EnableTlsInspection)
        {
            if (string.IsNullOrWhiteSpace(options.WorkspacePath)) throw new ArgumentException("启用 TLS 解密时必须提供工作区路径。", nameof(options));
            _certificateAuthority = new WorkspaceCertificateAuthority(options.WorkspacePath);
            _tlsInspectionPolicy = new TlsInspectionPolicyStore(options.WorkspacePath).Load();
        }
    }

    public event EventHandler<TrafficRecord>? TransactionCaptured;
    public Guid SessionId => _sessionId;
    public IPEndPoint? LocalEndpoint => _listener?.LocalEndpoint as IPEndPoint;

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        _listener = new TcpListener(_options.Address, _options.Port);
        _listener.Start(NetMindDefaults.ProxyListenBacklog);
        var startedAt = DateTimeOffset.UtcNow;
        var sessionTarget = LocalEndpoint?.ToString() ?? string.Empty;
        var sessionMode = _options.EnableTlsInspection ? NetMindDefaults.SessionModeDecryptProxy : NetMindDefaults.SessionModeExplicitProxy;
        await _archive.StartSessionAsync(new CaptureSessionRecord(_sessionId, startedAt, null, sessionMode, sessionTarget, NetMindDefaults.SessionStateRunning), cancellationToken);
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                TcpClient client;
                try
                {
                    client = await _listener.AcceptTcpClientAsync(cancellationToken);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    break;
                }

                try
                {
                    await _connectionSlots.WaitAsync(cancellationToken);
                }
                catch
                {
                    client.Dispose();
                    throw;
                }
                var connectionTask = HandleBoundedAsync(client, cancellationToken);
                lock (_activeGate) _activeConnections.Add(connectionTask);
                _ = connectionTask.ContinueWith(completed =>
                {
                    lock (_activeGate) _activeConnections.Remove(completed);
                }, CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
            }
        }
        finally
        {
            _listener.Stop();
            Task[] pending;
            lock (_activeGate) pending = [.. _activeConnections];
            await Task.WhenAll(pending);
            await _archive.CompleteSessionAsync(new CaptureSessionRecord(_sessionId, startedAt, DateTimeOffset.UtcNow,
                sessionMode, sessionTarget, "已停止"), CancellationToken.None);
        }
    }

    private async Task HandleBoundedAsync(TcpClient client, CancellationToken cancellationToken)
    {
        try
        {
            await HandleClientAsync(client, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // 正常停止时不再向已取消的连接写入错误响应。
        }
        catch (Exception exception) when (exception is IOException or HttpRequestException or TaskCanceledException or InvalidDataException)
        {
            try
            {
                if (client.Connected) await WriteErrorAsync(client.GetStream(), 502, "上游请求失败", exception.Message, CancellationToken.None);
            }
            catch
            {
                // 客户端可能已断开，不再二次报告。
            }
        }
        finally
        {
            client.Dispose();
            _connectionSlots.Release();
        }
    }

    private async Task HandleClientAsync(TcpClient client, CancellationToken cancellationToken)
    {
        client.NoDelay = true;
        using var stream = client.GetStream();
        var processName = ResolveClientProcess(client);
        var headerBytes = await ReadHeadersAsync(stream, cancellationToken);
        if (headerBytes.Length == 0) return;

        var headerText = Encoding.Latin1.GetString(headerBytes);
        var lines = headerText.Split("\r\n", StringSplitOptions.None);
        var requestLine = lines[0].Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
        if (requestLine.Length != 3) throw new InvalidDataException("请求行格式无效。");

        var method = requestLine[0].ToUpperInvariant();
        var target = requestLine[1];
        var headers = ParseHeaders(lines.Skip(1));
        if (method == "CONNECT")
        {
            if (!_options.EnableHttpsTunneling)
            {
                await WriteErrorAsync(stream, 501, "HTTPS 隧道未启用", "当前代理未启用 CONNECT 隧道转发。", cancellationToken);
                return;
            }

            var bypassInspection = _options.EnableTlsInspection &&
                                   TlsInspectionPolicyStore.ShouldBypass(_tlsInspectionPolicy, ParseConnectTarget(target).Host);
            if (_options.EnableTlsInspection && !bypassInspection)
                await HandleConnectInspectionAsync(stream, target, headers, processName, cancellationToken);
            else
                await HandleConnectTunnelAsync(client, stream, target, headers, processName, cancellationToken);
            return;
        }

        var uri = ResolveTargetUri(target, headers);
        var requestBody = await ReadRequestBodyAsync(stream, headers, _options.MaximumBodyBytes, cancellationToken);
        var hookTransactionId = Guid.NewGuid();
        var requestSnapshot = CreateHookSnapshot(hookTransactionId, method, uri, headers, requestBody);
        // 拦截优先于观察：命中脚本 INTERCEPT 规则时阻塞等待裁决，改写后再走观察与转发，
        // 这样脚本看到的和实际上线的是同一份字节。未命中或裁决失败时按原样继续（fail-open）。
        IReadOnlyDictionary<string, string> forwardHeaders;
        (method, uri, forwardHeaders, requestBody) =
            await ApplyRequestInterceptAsync(requestSnapshot, method, uri, headers, requestBody, cancellationToken);
        headers = forwardHeaders.ToDictionary(item => item.Key, item => item.Value, StringComparer.OrdinalIgnoreCase);
        _hookEngine?.Emit(HookEventNames.RequestBeforeSend, requestSnapshot);
        using var outbound = BuildRequest(method, uri, headers, requestBody);

        var stopwatch = Stopwatch.StartNew();
        HttpResponseMessage response;
        byte[] responseBody;
        try
        {
            response = await _httpClient.SendAsync(outbound, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            _hookEngine?.Emit(HookEventNames.RequestAfterSend, requestSnapshot, (int)response.StatusCode);
            responseBody = await ReadBoundedAsync(await response.Content.ReadAsStreamAsync(cancellationToken), _options.MaximumBodyBytes, cancellationToken);
        }
        catch (Exception exception) when (!cancellationToken.IsCancellationRequested &&
                                          exception is HttpRequestException or TaskCanceledException or IOException or InvalidDataException)
        {
            stopwatch.Stop();
            await CaptureForwardingFailureAsync(stream, method, uri, headers, requestBody, processName,
                stopwatch.ElapsedMilliseconds, exception, cancellationToken);
            return;
        }
        using (response)
        {
            stopwatch.Stop();

            var responseHeaders = response.Headers.Concat(response.Content.Headers)
                .ToDictionary(item => item.Key, item => string.Join(", ", item.Value), StringComparer.OrdinalIgnoreCase);
            var responseSnapshot = CreateHookSnapshot(hookTransactionId, method, uri, responseHeaders, responseBody);
            int writtenStatus;
            IReadOnlyList<KeyValuePair<string, string>> writtenLines;
            (writtenStatus, writtenLines, responseBody) = await ApplyResponseInterceptAsync(
                responseSnapshot, (int)response.StatusCode, BuildResponseHeaderLines(response), responseBody, cancellationToken);
            responseHeaders = MergeHeaderLines(writtenLines);
            _hookEngine?.Emit(HookEventNames.ResponseBeforeWrite, responseSnapshot, writtenStatus);
            await WriteResponseAsync(stream, writtenStatus, response.ReasonPhrase ?? "响应", writtenLines, responseBody, cancellationToken);
            _hookEngine?.Emit(HookEventNames.ResponseAfterDeliver, responseSnapshot, writtenStatus);
            // 回写给浏览器的字节保持原样；仅落库/分析正文按 Content-Encoding 解压。
            responseBody = ProtocolParsers.DecompressHttpBody(
                responseHeaders.TryGetValue("Content-Encoding", out var coding) ? coding : null, responseBody);
            var traffic = new TrafficRecord(
                hookTransactionId,
                DateTimeOffset.Now,
                method,
                uri.PathAndQuery,
                (int)response.StatusCode,
                (int)Math.Min(int.MaxValue, stopwatch.ElapsedMilliseconds),
                responseBody.LongLength,
                processName,
                $"HTTP/{response.Version.Major}.{response.Version.Minor}",
                $"{headers.Count} 个请求头 · {requestBody.Length} 字节正文",
                $"{response.Content.Headers.ContentType?.MediaType ?? "无类型"} · {responseBody.Length} 字节",
                uri.AbsoluteUri,
                FormatQueryParameters(uri),
                FormatHeaders(headers),
                FormatCookies(headers),
                FormatHeaders(responseHeaders));
            await _archive.RecordAsync(_sessionId, traffic, requestBody, responseBody, cancellationToken);
            TransactionCaptured?.Invoke(this, traffic);
        }
    }

    private async Task CaptureForwardingFailureAsync(Stream clientStream, string method, Uri uri,
        IReadOnlyDictionary<string, string> headers, byte[] requestBody, string processName, long elapsedMilliseconds,
        Exception exception, CancellationToken cancellationToken, string protocol = "HTTP/1.1")
    {
        var detail = string.IsNullOrWhiteSpace(exception.Message) ? "上游服务未返回有效响应。" : exception.Message;
        var errorBody = Encoding.UTF8.GetBytes("上游请求失败\n\n" + detail);
        var traffic = new TrafficRecord(
            Guid.NewGuid(),
            DateTimeOffset.Now,
            method,
            uri.PathAndQuery,
            502,
            (int)Math.Min(int.MaxValue, elapsedMilliseconds),
            errorBody.LongLength,
            processName,
            protocol,
            $"{headers.Count} 个请求头 · {requestBody.Length} 字节正文",
            "代理转发失败 · " + exception.GetType().Name,
            uri.AbsoluteUri,
            FormatQueryParameters(uri),
            FormatHeaders(headers),
            FormatCookies(headers),
            "HTTP/1.1 502 上游请求失败\nContent-Type: text/plain; charset=utf-8");
        await _archive.RecordAsync(_sessionId, traffic, requestBody, errorBody, CancellationToken.None);
        TransactionCaptured?.Invoke(this, traffic);
        await WriteErrorAsync(clientStream, 502, "上游请求失败", detail, cancellationToken);
    }

    private async Task HandleConnectInspectionAsync(NetworkStream clientStream, string target,
        IReadOnlyDictionary<string, string> connectHeaders, string processName, CancellationToken cancellationToken)
    {
        var (host, port) = ParseConnectTarget(target);
        await clientStream.WriteAsync(Encoding.ASCII.GetBytes(
            "HTTP/1.1 200 Connection Established\r\nProxy-Agent: NetMind TLS Inspector\r\n\r\n"), cancellationToken);
        await clientStream.FlushAsync(cancellationToken);

        using var tlsStream = new SslStream(clientStream, leaveInnerStreamOpen: true);
        try
        {
            var certificate = _certificateAuthority?.GetServerCertificate(host)
                              ?? throw new InvalidOperationException("工作区 TLS 证书服务不可用。");
            await tlsStream.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
            {
                ServerCertificate = certificate,
                ClientCertificateRequired = false,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                ApplicationProtocols = [SslApplicationProtocol.Http11]
            }, cancellationToken);
        }
        catch (Exception exception) when (!cancellationToken.IsCancellationRequested &&
                                          exception is AuthenticationException or IOException or InvalidOperationException or CryptographicException)
        {
            var body = Encoding.UTF8.GetBytes("TLS 解密握手失败：" + exception.Message);
            var failed = new TrafficRecord(Guid.NewGuid(), DateTimeOffset.Now, "CONNECT", target, 495, 0, body.LongLength,
                processName, "HTTPS 解密失败", "客户端未接受工作区站点证书", $"{exception.GetType().Name}：{exception.Message}",
                "https://" + target + "/", string.Empty, FormatHeaders(connectHeaders), FormatCookies(connectHeaders), string.Empty);
            await _archive.RecordAsync(_sessionId, failed, ReadOnlyMemory<byte>.Empty, body, CancellationToken.None);
            TransactionCaptured?.Invoke(this, failed);
            return;
        }

        for (var requestNumber = 0; requestNumber < 1_000; requestNumber++)
        {
            var headerBytes = await ReadHeadersAsync(tlsStream, cancellationToken);
            if (headerBytes.Length == 0) return;

            string method;
            string httpVersion;
            IReadOnlyDictionary<string, string> headers;
            Uri uri;
            byte[] requestBody;
            bool closeConnection;
            try
            {
                var lines = Encoding.Latin1.GetString(headerBytes).Split("\r\n", StringSplitOptions.None);
                var requestLine = lines[0].Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
                if (requestLine.Length != 3 || requestLine[2] is not ("HTTP/1.0" or "HTTP/1.1"))
                    throw new InvalidDataException("TLS 解密当前只支持 HTTP/1.0 和 HTTP/1.1 请求。");
                method = requestLine[0].ToUpperInvariant();
                httpVersion = requestLine[2];
                if (method == "CONNECT") throw new InvalidDataException("TLS 隧道内不允许嵌套 CONNECT。");
                headers = ParseHeaders(lines.Skip(1));
                uri = ResolveTlsTargetUri(requestLine[1], headers, host, port);
                closeConnection = ShouldCloseClientConnection(httpVersion, headers);
                requestBody = await ReadRequestBodyAsync(tlsStream, headers, _options.MaximumBodyBytes, cancellationToken);
            }
            catch (Exception exception) when (!cancellationToken.IsCancellationRequested &&
                                              exception is InvalidDataException or EndOfStreamException)
            {
                await CaptureTlsProtocolFailureAsync(tlsStream, target, connectHeaders, processName, exception, cancellationToken);
                return;
            }

            var hookTransactionId = Guid.NewGuid();
            var requestSnapshot = CreateHookSnapshot(hookTransactionId, method, uri, headers, requestBody);
            // 解密路径同样支持拦截改写：语义与明文路径完全一致，脚本不必区分。
            (method, uri, headers, requestBody) =
                await ApplyRequestInterceptAsync(requestSnapshot, method, uri, headers, requestBody, cancellationToken);
            _hookEngine?.Emit(HookEventNames.RequestBeforeSend, requestSnapshot);
            using var outbound = BuildRequest(method, uri, headers, requestBody);
            var stopwatch = Stopwatch.StartNew();
            HttpResponseMessage response;
            byte[] responseBody;
            try
            {
                response = await _httpClient.SendAsync(outbound, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
                _hookEngine?.Emit(HookEventNames.RequestAfterSend, requestSnapshot, (int)response.StatusCode);
                responseBody = await ReadBoundedAsync(await response.Content.ReadAsStreamAsync(cancellationToken), _options.MaximumBodyBytes, cancellationToken);
            }
            catch (Exception exception) when (!cancellationToken.IsCancellationRequested &&
                                              exception is HttpRequestException or TaskCanceledException or IOException or InvalidDataException)
            {
                stopwatch.Stop();
                await CaptureForwardingFailureAsync(tlsStream, method, uri, headers, requestBody, processName,
                    stopwatch.ElapsedMilliseconds, exception, cancellationToken, "HTTPS 解密 · HTTP/1.1");
                return;
            }

            using (response)
            {
                stopwatch.Stop();
                closeConnection |= response.StatusCode == HttpStatusCode.SwitchingProtocols;
                var responseHeaders = response.Headers.Concat(response.Content.Headers)
                    .ToDictionary(item => item.Key, item => string.Join(", ", item.Value), StringComparer.OrdinalIgnoreCase);
                var responseSnapshot = CreateHookSnapshot(hookTransactionId, method, uri, responseHeaders, responseBody);
                int writtenStatus;
                IReadOnlyList<KeyValuePair<string, string>> writtenLines;
                (writtenStatus, writtenLines, responseBody) = await ApplyResponseInterceptAsync(
                    responseSnapshot, (int)response.StatusCode, BuildResponseHeaderLines(response), responseBody, cancellationToken);
                responseHeaders = MergeHeaderLines(writtenLines);
                _hookEngine?.Emit(HookEventNames.ResponseBeforeWrite, responseSnapshot, writtenStatus);
                await WriteResponseAsync(tlsStream, writtenStatus, response.ReasonPhrase ?? "响应", writtenLines, responseBody, cancellationToken, closeConnection);
                _hookEngine?.Emit(HookEventNames.ResponseAfterDeliver, responseSnapshot, writtenStatus);
                // 回写给浏览器的字节保持原样；仅落库/分析正文按 Content-Encoding 解压。
                responseBody = ProtocolParsers.DecompressHttpBody(
                    responseHeaders.TryGetValue("Content-Encoding", out var coding) ? coding : null, responseBody);
                var traffic = new TrafficRecord(
                    hookTransactionId, DateTimeOffset.Now, method, uri.PathAndQuery, (int)response.StatusCode,
                    (int)Math.Min(int.MaxValue, stopwatch.ElapsedMilliseconds), responseBody.LongLength, processName,
                    $"HTTPS 解密 · HTTP/{response.Version.Major}.{response.Version.Minor}",
                    $"{headers.Count} 个请求头 · {requestBody.Length} 字节正文",
                    $"{response.Content.Headers.ContentType?.MediaType ?? "无类型"} · {responseBody.Length} 字节",
                    uri.AbsoluteUri, FormatQueryParameters(uri), FormatHeaders(headers), FormatCookies(headers), FormatHeaders(responseHeaders));
                await _archive.RecordAsync(_sessionId, traffic, requestBody, responseBody, cancellationToken);
                TransactionCaptured?.Invoke(this, traffic);
            }

            if (closeConnection) return;
        }

        await WriteErrorAsync(tlsStream, 429, "连接请求过多", "单条 TLS 连接最多处理 1000 个请求，请重新建立连接。", cancellationToken);
    }

    private async Task CaptureTlsProtocolFailureAsync(Stream tlsStream, string target,
        IReadOnlyDictionary<string, string> connectHeaders, string processName, Exception exception, CancellationToken cancellationToken)
    {
        var detail = string.IsNullOrWhiteSpace(exception.Message) ? "TLS 内部请求格式无效。" : exception.Message;
        var body = Encoding.UTF8.GetBytes("HTTPS 请求解析失败\n\n" + detail);
        var traffic = new TrafficRecord(Guid.NewGuid(), DateTimeOffset.Now, "HTTPS", target, 400, 0, body.LongLength,
            processName, "HTTPS 解密失败", "TLS 已建立 · HTTP 请求解析失败", exception.GetType().Name,
            "https://" + target + "/", string.Empty, FormatHeaders(connectHeaders), FormatCookies(connectHeaders),
            "HTTP/1.1 400 HTTPS 请求解析失败");
        await _archive.RecordAsync(_sessionId, traffic, ReadOnlyMemory<byte>.Empty, body, CancellationToken.None);
        TransactionCaptured?.Invoke(this, traffic);
        await WriteErrorAsync(tlsStream, 400, "HTTPS 请求解析失败", detail, cancellationToken);
    }

    /// <summary>钩子引擎后置注入口：监听就绪后由宿主在引擎启动成功时赋值，null 表示钩子未启用。</summary>
    public ScriptHookEngine? HookEngine
    {
        get => _hookEngine;
        set => _hookEngine = value;
    }

    /// <summary>构建钩子事务快照；未注入钩子引擎时返回 null，保持零开销。</summary>
    /// <summary>
    /// 请求侧拦截：命中脚本规则时等待裁决并改写，随后把快照同步为改写后的内容——
    /// 观察事件与落库证据都必须反映“实际发往上游的字节”，否则证据链会说谎。
    /// 未命中、超时、工作进程不可用一律原样返回（fail-open）。
    /// </summary>
    private async Task<(string Method, Uri Uri, IReadOnlyDictionary<string, string> Headers, byte[] Body)>
        ApplyRequestInterceptAsync(HookTransactionSnapshot? snapshot, string method, Uri uri,
            IReadOnlyDictionary<string, string> headers, byte[] body, CancellationToken cancellationToken)
    {
        var engine = _hookEngine;
        if (engine is null || snapshot is null ||
            !engine.ShouldIntercept(HookEventNames.RequestBeforeSend, snapshot)) return (method, uri, headers, body);

        var verdict = await engine.InterceptAsync(HookEventNames.RequestBeforeSend, snapshot,
            cancellationToken: cancellationToken);
        if (verdict is null || !verdict.HasChanges) return (method, uri, headers, body);

        var mutatedMethod = string.IsNullOrWhiteSpace(verdict.Method) ? method : verdict.Method.Trim().ToUpperInvariant();
        var mutatedUri = uri;
        if (!string.IsNullOrWhiteSpace(verdict.Url) &&
            Uri.TryCreate(verdict.Url, UriKind.Absolute, out var parsed) &&
            (parsed.Scheme == Uri.UriSchemeHttp || parsed.Scheme == Uri.UriSchemeHttps))
            mutatedUri = parsed; // 非法或非 http(s) 的改写 URL 直接忽略，绝不据此发起请求
        var mutatedHeaders = ApplyRequestHeaderChanges(headers, verdict.Headers);
        var mutatedBody = verdict.Body is null ? body : Encoding.UTF8.GetBytes(verdict.Body);

        snapshot.ReplaceForMutation(mutatedMethod, mutatedUri.AbsoluteUri, mutatedUri.Host,
            mutatedUri.PathAndQuery, mutatedHeaders, mutatedBody);
        return (mutatedMethod, mutatedUri, mutatedHeaders, mutatedBody);
    }

    /// <summary>
    /// 响应侧拦截：在写回浏览器之前改写状态码、响应头与正文。
    /// 同样把快照同步为改写后的内容，使观察事件与落库证据等于浏览器真正收到的字节。
    /// </summary>
    private async Task<(int StatusCode, IReadOnlyList<KeyValuePair<string, string>> HeaderLines, byte[] Body)>
        ApplyResponseInterceptAsync(HookTransactionSnapshot? snapshot, int statusCode,
            IReadOnlyList<KeyValuePair<string, string>> headerLines, byte[] body, CancellationToken cancellationToken)
    {
        var engine = _hookEngine;
        if (engine is null || snapshot is null ||
            !engine.ShouldIntercept(HookEventNames.ResponseBeforeWrite, snapshot)) return (statusCode, headerLines, body);

        var verdict = await engine.InterceptAsync(HookEventNames.ResponseBeforeWrite, snapshot, statusCode, cancellationToken);
        if (verdict is null || !verdict.HasChanges) return (statusCode, headerLines, body);

        var mutatedStatus = verdict.StatusCode is >= 100 and <= 599 ? verdict.StatusCode.Value : statusCode;
        var mutatedLines = ApplyHeaderChanges(headerLines, verdict.Headers);
        var mutatedBody = verdict.Body is null ? body : Encoding.UTF8.GetBytes(verdict.Body);

        // 快照给脚本与落库用，按名合并即可；真正写回浏览器的仍是保留多值的 mutatedLines。
        var snapshotHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (name, value) in mutatedLines)
            snapshotHeaders[name] = snapshotHeaders.TryGetValue(name, out var existing) ? existing + ", " + value : value;
        snapshot.ReplaceForMutation(snapshot.Method, snapshot.Url, snapshot.Host, snapshot.Endpoint, snapshotHeaders, mutatedBody);
        snapshot.StatusCode = mutatedStatus;
        return (mutatedStatus, mutatedLines, mutatedBody);
    }

    /// <summary>
    /// 套用响应头改写：值为 null 表示删除该头名的全部行，其余为整体替换或新增。
    /// 以「行」为单位处理才能保住 Set-Cookie 这类多值头；Content-Length 由写出路径按实际正文重算。
    /// </summary>
    private static IReadOnlyList<KeyValuePair<string, string>> ApplyHeaderChanges(
        IReadOnlyList<KeyValuePair<string, string>> headerLines, IReadOnlyDictionary<string, string?>? changes)
    {
        if (changes is not { Count: > 0 }) return headerLines;
        var result = headerLines
            .Where(line => !changes.ContainsKey(line.Key))
            .ToList();
        foreach (var (name, value) in changes)
        {
            if (string.IsNullOrWhiteSpace(name) || value is null) continue;
            result.Add(new KeyValuePair<string, string>(name, value));
        }
        return result;
    }

    /// <summary>把多值头行按名合并，供快照与落库证据使用；写回浏览器仍用未合并的行。</summary>
    private static Dictionary<string, string> MergeHeaderLines(IReadOnlyList<KeyValuePair<string, string>> headerLines)
    {
        var merged = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (name, value) in headerLines)
            merged[name] = merged.TryGetValue(name, out var existing) ? existing + ", " + value : value;
        return merged;
    }

    /// <summary>请求头改写：请求侧本就以字典表达（ParseHeaders 的既有语义），按名覆盖即可。</summary>
    private static IReadOnlyDictionary<string, string> ApplyRequestHeaderChanges(
        IReadOnlyDictionary<string, string> headers, IReadOnlyDictionary<string, string?>? changes)
    {
        if (changes is not { Count: > 0 }) return headers;
        var merged = new Dictionary<string, string>(headers, StringComparer.OrdinalIgnoreCase);
        foreach (var (name, value) in changes)
        {
            if (string.IsNullOrWhiteSpace(name)) continue;
            if (value is null) merged.Remove(name);
            else merged[name] = value;
        }
        return merged;
    }

    private HookTransactionSnapshot? CreateHookSnapshot(Guid transactionId, string method, Uri uri,
        IReadOnlyDictionary<string, string> headers, byte[] body)
        => _hookEngine is null
            ? null
            : new HookTransactionSnapshot(transactionId, _sessionId, method, uri.AbsoluteUri, uri.Host, uri.PathAndQuery, headers, body);

    private static Uri ResolveTlsTargetUri(string target, IReadOnlyDictionary<string, string> headers, string connectHost, int connectPort)
    {
        var authority = headers.TryGetValue("Host", out var hostHeader) && !string.IsNullOrWhiteSpace(hostHeader)
            ? hostHeader
            : connectPort == 443 ? connectHost : $"{connectHost}:{connectPort}";
        if (!Uri.TryCreate("https://" + authority, UriKind.Absolute, out var origin) ||
            !origin.Host.Equals(connectHost, StringComparison.OrdinalIgnoreCase) || origin.Port != connectPort)
            throw new InvalidDataException("TLS 内部请求的 Host 与 CONNECT 目标不一致。");
        if (Uri.TryCreate(target, UriKind.Absolute, out var absolute))
        {
            if (absolute.Scheme != Uri.UriSchemeHttps || !absolute.Host.Equals(connectHost, StringComparison.OrdinalIgnoreCase) || absolute.Port != connectPort)
                throw new InvalidDataException("TLS 内部绝对 URL 与 CONNECT 目标不一致。");
            return absolute;
        }
        if (!target.StartsWith('/')) target = "/" + target;
        return new Uri(origin, target);
    }

    private async Task HandleConnectTunnelAsync(TcpClient client, NetworkStream clientStream, string target,
        IReadOnlyDictionary<string, string> headers, string processName, CancellationToken cancellationToken)
    {
        var (host, port) = ParseConnectTarget(target);
        using var upstream = new TcpClient { NoDelay = true };
        var stopwatch = Stopwatch.StartNew();
        await upstream.ConnectAsync(host, port, cancellationToken);
        stopwatch.Stop();

        await clientStream.WriteAsync(Encoding.ASCII.GetBytes(
            "HTTP/1.1 200 Connection Established\r\nProxy-Agent: NetMind\r\n\r\n"), cancellationToken);
        await clientStream.FlushAsync(cancellationToken);

        var transactionId = Guid.NewGuid();
        var established = new TrafficRecord(
            transactionId,
            DateTimeOffset.Now,
            "CONNECT",
            target,
            200,
            (int)Math.Min(int.MaxValue, stopwatch.ElapsedMilliseconds),
            0,
            processName,
            NetMindDefaults.ProtocolHttpsTunnel,
            $"正在向 {target} 转发加密数据",
            "隧道已建立 · TLS 正文未解密",
            "https://" + target + "/",
            string.Empty,
            FormatHeaders(headers),
            FormatCookies(headers),
            "HTTP/1.1 200 Connection Established\nProxy-Agent: NetMind");
        var stored = await _archive.RecordAsync(_sessionId, established, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, cancellationToken);
        TransactionCaptured?.Invoke(this, established);

        using var upstreamStream = upstream.GetStream();
        var upload = new TunnelByteCounter();
        var download = new TunnelByteCounter();
        var uploadTask = RelayTunnelAsync(clientStream, upstreamStream, upload, cancellationToken);
        var downloadTask = RelayTunnelAsync(upstreamStream, clientStream, download, cancellationToken);
        await Task.WhenAny(uploadTask, downloadTask);
        TryShutdown(client);
        TryShutdown(upstream);
        try { await Task.WhenAll(uploadTask, downloadTask); }
        catch (Exception exception) when (exception is IOException or SocketException or ObjectDisposedException or OperationCanceledException)
        {
            // 任一方向结束后关闭整条隧道，另一方向的中止属于正常收尾。
        }

        var completed = established with
        {
            SizeBytes = download.Value,
            RequestSummary = $"上行 {FormatBytes(upload.Value)} · 加密正文未解密",
            ResponseSummary = $"下行 {FormatBytes(download.Value)} · 加密正文未解密"
        };
        await _archive.UpdateTrafficAsync(stored with { Traffic = completed }, CancellationToken.None);
        TransactionCaptured?.Invoke(this, completed);
    }

    private static async Task RelayTunnelAsync(Stream source, Stream destination, TunnelByteCounter counter, CancellationToken cancellationToken)
    {
        var buffer = new byte[32 * 1024];
        while (true)
        {
            var read = await source.ReadAsync(buffer, cancellationToken);
            if (read == 0) return;
            await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
            await destination.FlushAsync(cancellationToken);
            counter.Add(read);
        }
    }

    private static (string Host, int Port) ParseConnectTarget(string target)
    {
        if (string.IsNullOrWhiteSpace(target) || target.Contains('/') || target.Contains('@') ||
            !Uri.TryCreate("https://" + target, UriKind.Absolute, out var uri) ||
            string.IsNullOrWhiteSpace(uri.Host) || uri.Port is < 1 or > 65535)
            throw new InvalidDataException("CONNECT 目标必须是有效的 主机:端口。");
        return (uri.Host, uri.Port);
    }

    private static void TryShutdown(TcpClient client)
    {
        try { client.Client.Shutdown(SocketShutdown.Both); }
        catch (Exception exception) when (exception is SocketException or ObjectDisposedException) { }
    }

    private static string ResolveClientProcess(TcpClient client)
    {
        if (client.Client.RemoteEndPoint is not IPEndPoint clientEndpoint || client.Client.LocalEndPoint is not IPEndPoint proxyEndpoint)
            return "未知进程";
        return WindowsTcpProcessResolver.Resolve(clientEndpoint, proxyEndpoint)?.DisplayName ?? "未知进程";
    }

    private static string FormatBytes(long value) => value < 1024
        ? $"{value} 字节"
        : value < 1024 * 1024
            ? $"{value / 1024d:0.0} KB"
            : $"{value / 1024d / 1024d:0.0} MB";

    private sealed class TunnelByteCounter
    {
        private long _value;
        public long Value => Interlocked.Read(ref _value);
        public void Add(int value) => Interlocked.Add(ref _value, value);
    }

    private static HttpRequestMessage BuildRequest(string method, Uri uri, IReadOnlyDictionary<string, string> headers, byte[] body)
    {
        var request = new HttpRequestMessage(new HttpMethod(method), uri);
        if (body.Length > 0 || headers.ContainsKey("Content-Length") || headers.ContainsKey("Transfer-Encoding"))
            request.Content = new ByteArrayContent(body);
        var connectionHeaders = headers.TryGetValue("Connection", out var connectionValue)
            ? connectionValue.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            : [];
        foreach (var (name, value) in headers)
        {
            if (name.Equals("Host", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("Proxy-Connection", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("Proxy-Authorization", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("Connection", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("Keep-Alive", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("Trailer", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("Upgrade", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("Expect", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("Content-Length", StringComparison.OrdinalIgnoreCase) ||
                connectionHeaders.Contains(name, StringComparer.OrdinalIgnoreCase)) continue;

            if (!request.Headers.TryAddWithoutValidation(name, value) && request.Content is not null)
                request.Content.Headers.TryAddWithoutValidation(name, value);
        }
        return request;
    }

    private static Task WriteResponseAsync(Stream stream, HttpResponseMessage response, byte[] body,
        CancellationToken cancellationToken, bool closeConnection = true)
        => WriteResponseAsync(stream, (int)response.StatusCode, response.ReasonPhrase ?? "响应",
            BuildResponseHeaderLines(response), body, cancellationToken, closeConnection);

    /// <summary>
    /// 把响应头摊平成「一个值一行」。绝不能按名合并成逗号串：Set-Cookie 天然多值，
    /// 合并后浏览器会把多个 Cookie 解析成一个，是实打实的行为破坏。
    /// </summary>
    private static List<KeyValuePair<string, string>> BuildResponseHeaderLines(HttpResponseMessage response) =>
        [.. response.Headers.Concat(response.Content.Headers)
            .SelectMany(header => header.Value.Select(value => new KeyValuePair<string, string>(header.Key, value)))];

    /// <summary>
    /// 按显式状态码/头/正文写回响应。脚本改写后不能再从 <see cref="HttpResponseMessage"/> 取值，
    /// 必须以改写结果为准；Content-Length 始终按实际正文长度重算，改写正文才不会撕裂消息边界。
    /// </summary>
    private static async Task WriteResponseAsync(Stream stream, int statusCode, string reasonPhrase,
        IReadOnlyList<KeyValuePair<string, string>> headerLines, byte[] body,
        CancellationToken cancellationToken, bool closeConnection = true)
    {
        var builder = new StringBuilder();
        builder.Append("HTTP/1.1 ").Append(statusCode).Append(' ').Append(reasonPhrase).Append("\r\n");
        foreach (var (name, value) in headerLines)
        {
            if (name.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("Content-Length", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("Connection", StringComparison.OrdinalIgnoreCase)) continue;
            builder.Append(name).Append(": ").Append(value).Append("\r\n");
        }
        builder.Append("Content-Length: ").Append(body.Length)
            .Append(closeConnection ? "\r\nConnection: close\r\n\r\n" : "\r\nConnection: keep-alive\r\n\r\n");
        await stream.WriteAsync(Encoding.Latin1.GetBytes(builder.ToString()), cancellationToken);
        await stream.WriteAsync(body, cancellationToken);
        await stream.FlushAsync(cancellationToken);
    }

    private static async Task WriteErrorAsync(Stream stream, int status, string title, string detail, CancellationToken cancellationToken)
    {
        var body = Encoding.UTF8.GetBytes($"{title}\n\n{detail}");
        var header = Encoding.ASCII.GetBytes($"HTTP/1.1 {status} Error\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {body.Length}\r\nConnection: close\r\n\r\n");
        await stream.WriteAsync(header, cancellationToken);
        await stream.WriteAsync(body, cancellationToken);
        await stream.FlushAsync(cancellationToken);
    }

    private static Uri ResolveTargetUri(string target, IReadOnlyDictionary<string, string> headers)
    {
        if (Uri.TryCreate(target, UriKind.Absolute, out var absolute) && absolute.Scheme is "http") return absolute;
        if (!headers.TryGetValue("Host", out var host) || string.IsNullOrWhiteSpace(host))
            throw new InvalidDataException("请求缺少 Host 头。");
        if (!target.StartsWith('/')) target = "/" + target;
        return new Uri($"http://{host}{target}", UriKind.Absolute);
    }

    private static Dictionary<string, string> ParseHeaders(IEnumerable<string> lines)
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in lines)
        {
            if (string.IsNullOrEmpty(line)) break;
            var separator = line.IndexOf(':');
            if (separator <= 0) throw new InvalidDataException("请求头格式无效。");
            var name = line[..separator].Trim();
            var value = line[(separator + 1)..].Trim();
            var separatorText = name.Equals("Cookie", StringComparison.OrdinalIgnoreCase) ? "; " : ", ";
            headers[name] = headers.TryGetValue(name, out var existing) ? existing + separatorText + value : value;
        }
        return headers;
    }

    private static int ParseContentLength(IReadOnlyDictionary<string, string> headers)
    {
        if (!headers.TryGetValue("Content-Length", out var value)) return 0;
        if (!int.TryParse(value, out var length) || length < 0) throw new InvalidDataException("Content-Length 无效。");
        return length;
    }

    private static bool ShouldCloseClientConnection(string httpVersion, IReadOnlyDictionary<string, string> headers)
    {
        var connection = headers.TryGetValue("Connection", out var value) ? value : string.Empty;
        if (connection.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Contains("close", StringComparer.OrdinalIgnoreCase)) return true;
        return httpVersion == "HTTP/1.0" && !connection.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Contains("keep-alive", StringComparer.OrdinalIgnoreCase);
    }

    private static async Task<byte[]> ReadRequestBodyAsync(Stream stream, IReadOnlyDictionary<string, string> headers,
        int maximumBytes, CancellationToken cancellationToken)
    {
        var hasContentLength = headers.ContainsKey("Content-Length");
        var transferEncoding = headers.TryGetValue("Transfer-Encoding", out var value) ? value : string.Empty;
        if (hasContentLength && !string.IsNullOrWhiteSpace(transferEncoding))
            throw new InvalidDataException("请求不能同时包含 Content-Length 和 Transfer-Encoding。");

        if (!string.IsNullOrWhiteSpace(transferEncoding))
        {
            var encodings = transferEncoding.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (encodings.Length != 1 || !encodings[0].Equals("chunked", StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("只支持 chunked 分块请求正文。");
            return await ReadChunkedBodyAsync(stream, maximumBytes, cancellationToken);
        }

        var contentLength = ParseContentLength(headers);
        if (contentLength > maximumBytes) throw new InvalidDataException("请求正文超过工作区允许的大小。");
        if (contentLength > 0 && headers.TryGetValue("Expect", out var expectation) && expectation.Contains("100-continue", StringComparison.OrdinalIgnoreCase))
        {
            await stream.WriteAsync(Encoding.ASCII.GetBytes("HTTP/1.1 100 Continue\r\n\r\n"), cancellationToken);
            await stream.FlushAsync(cancellationToken);
        }
        return contentLength > 0 ? await ReadExactAsync(stream, contentLength, cancellationToken) : [];
    }

    private static async Task<byte[]> ReadChunkedBodyAsync(Stream stream, int maximumBytes, CancellationToken cancellationToken)
    {
        using var output = new MemoryStream();
        while (true)
        {
            var sizeLine = await ReadLineAsync(stream, 8 * 1024, cancellationToken);
            var separator = sizeLine.IndexOf(';');
            var sizeText = (separator >= 0 ? sizeLine[..separator] : sizeLine).Trim();
            if (!int.TryParse(sizeText, System.Globalization.NumberStyles.HexNumber,
                    System.Globalization.CultureInfo.InvariantCulture, out var chunkSize) || chunkSize < 0)
                throw new InvalidDataException("分块请求正文的块大小无效。");
            if (chunkSize == 0)
            {
                while ((await ReadLineAsync(stream, MaximumHeaderBytes, cancellationToken)).Length > 0) { }
                return output.ToArray();
            }
            if (output.Length + chunkSize > maximumBytes)
                throw new InvalidDataException("分块请求正文超过工作区允许的大小。");
            var chunk = await ReadExactAsync(stream, chunkSize, cancellationToken);
            output.Write(chunk);
            var terminator = await ReadExactAsync(stream, 2, cancellationToken);
            if (terminator[0] != '\r' || terminator[1] != '\n') throw new InvalidDataException("分块请求正文缺少 CRLF 结束符。");
        }
    }

    private static async Task<string> ReadLineAsync(Stream stream, int maximumBytes, CancellationToken cancellationToken)
    {
        using var output = new MemoryStream();
        var previousWasCarriageReturn = false;
        while (output.Length < maximumBytes)
        {
            var value = new byte[1];
            if (await stream.ReadAsync(value, cancellationToken) == 0) throw new EndOfStreamException("请求正文提前结束。");
            if (previousWasCarriageReturn && value[0] == '\n')
            {
                var bytes = output.ToArray();
                return Encoding.Latin1.GetString(bytes, 0, bytes.Length - 1);
            }
            output.WriteByte(value[0]);
            previousWasCarriageReturn = value[0] == '\r';
        }
        throw new InvalidDataException("请求正文行超过允许的大小。");
    }

    private static string FormatQueryParameters(Uri uri) => string.Join(Environment.NewLine,
        ParseQuery(uri).Select(item => $"{item.Name} = {item.Value}"));

    private static IReadOnlyList<(string Name, string Value)> ParseQuery(Uri uri)
    {
        if (string.IsNullOrWhiteSpace(uri.Query)) return [];
        return uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries).Select(part =>
        {
            var pieces = part.Split('=', 2);
            return (DecodeQueryPart(pieces[0]), pieces.Length == 2 ? DecodeQueryPart(pieces[1]) : string.Empty);
        }).ToArray();
    }

    private static string DecodeQueryPart(string value)
    {
        try { return Uri.UnescapeDataString(value.Replace('+', ' ')); }
        catch (UriFormatException) { return value; }
    }

    private static string FormatHeaders(IEnumerable<KeyValuePair<string, string>> headers) => string.Join(Environment.NewLine,
        headers.OrderBy(item => item.Key, StringComparer.OrdinalIgnoreCase)
            .Select(item => $"{item.Key}: {item.Value}"));

    private static string FormatCookies(IReadOnlyDictionary<string, string> headers)
    {
        if (!headers.TryGetValue("Cookie", out var value) || string.IsNullOrWhiteSpace(value)) return string.Empty;
        return string.Join(Environment.NewLine, value.Split(';', StringSplitOptions.RemoveEmptyEntries).Select(cookie =>
        {
            var pieces = cookie.Trim().Split('=', 2);
            return pieces[0] + " = " + (pieces.Length == 2 ? pieces[1] : string.Empty);
        }));
    }

    private static async Task<byte[]> ReadHeadersAsync(Stream stream, CancellationToken cancellationToken)
    {
        using var buffer = new MemoryStream();
        var matched = 0;
        byte[] marker = [13, 10, 13, 10];
        while (buffer.Length < MaximumHeaderBytes)
        {
            var value = new byte[1];
            if (await stream.ReadAsync(value, cancellationToken) == 0) break;
            buffer.WriteByte(value[0]);
            matched = value[0] == marker[matched] ? matched + 1 : value[0] == marker[0] ? 1 : 0;
            if (matched == marker.Length) return buffer.ToArray()[..^4];
        }
        if (buffer.Length >= MaximumHeaderBytes) throw new InvalidDataException("请求头超过 64 KB 限制。");
        return buffer.ToArray();
    }

    private static async Task<byte[]> ReadExactAsync(Stream stream, int length, CancellationToken cancellationToken)
    {
        var buffer = new byte[length];
        var offset = 0;
        while (offset < length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(offset, length - offset), cancellationToken);
            if (read == 0) throw new EndOfStreamException("请求正文提前结束。");
            offset += read;
        }
        return buffer;
    }

    private static async Task<byte[]> ReadBoundedAsync(Stream stream, int maximumBytes, CancellationToken cancellationToken)
    {
        using var output = new MemoryStream();
        var buffer = new byte[16 * 1024];
        int read;
        while ((read = await stream.ReadAsync(buffer, cancellationToken)) > 0)
        {
            if (output.Length + read > maximumBytes) throw new InvalidDataException("响应正文超过工作区允许的大小。");
            output.Write(buffer, 0, read);
        }
        return output.ToArray();
    }

    public ValueTask DisposeAsync()
    {
        _listener?.Stop();
        _httpClient.Dispose();
        _certificateAuthority?.Dispose();
        _connectionSlots.Dispose();
        return ValueTask.CompletedTask;
    }
}
