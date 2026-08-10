using System.Net;

namespace NetMind.Core;

/// <summary>静默抓包结算出的一条事务：元数据 + 请求/响应原始正文。</summary>
public sealed record SilentCapturedTransaction(TrafficRecord Traffic, byte[] RequestBody, byte[] ResponseBody);

/// <summary>
/// 底层静默抓包引擎：WinDivert 被动嗅探 TCP 报文，按四元组重组双向字节流，
/// 配对 HTTP/1.x 请求与响应；TLS 流记录隧道元数据，命中 SSLKEYLOGFILE 密钥时解密出明文再配对。
/// 单循环串行处理，无并发共享。
/// </summary>
public sealed class SilentCaptureEngine
{
    private sealed class FlowState
    {
        public required string Key;
        public IPEndPoint? ClientEndpoint;
        public IPEndPoint? ServerEndpoint;
        public SilentTcpReassembler ToServer = new();
        public SilentTcpReassembler ToClient = new();
        public SilentHttpMessageParser Requests = new(isRequest: true);
        public SilentHttpMessageParser Responses = new(isRequest: false);
        public Queue<(SilentHttpMessage Message, DateTimeOffset At)> PendingRequests = [];
        public bool Classified;
        public bool DirectionKnown;
        public bool IsTls;
        public bool TlsRecorded;
        public SilentTlsSession? Tls;
        public SilentHttp2Connection? Http2;
        public string? Sni;
        public DateTimeOffset FirstSeen;
        public DateTimeOffset LastActivity;
        public bool ClientClosed;
        public bool ServerClosed;
        public bool Reset;
        public string ProcessLabel = "未知";
    }

    /// <summary>QUIC（UDP 443）连接状态：与 TCP 流表分开管理。</summary>
    private sealed class QuicFlow
    {
        public required string Key;
        public required SilentQuicConnection Quic;
        public IPEndPoint? ClientEndpoint;
        public IPEndPoint? ServerEndpoint;
        public bool DirectionKnown;
        public bool TunnelRecorded;
        public DateTimeOffset FirstSeen = DateTimeOffset.UtcNow;
        public DateTimeOffset LastActivity;
        public string ProcessLabel = "未知";
        public SilentHttp3Connection? Http3;
    }

    private readonly string _filter;
    private readonly Func<SilentCapturedTransaction, Task> _recordAsync;
    private readonly SilentTlsKeyLog? _keyLog;
    private readonly Dictionary<string, FlowState> _flows = new(StringComparer.Ordinal);
    private readonly Dictionary<string, QuicFlow> _quicFlows = new(StringComparer.Ordinal);
    private long _transactions;
    // 诊断计数器：分层定位“驱动收包→解析→路由→落库”链路断点。
    private long _packetsReceived;
    private long _packetsTooShort;
    private long _recvFailures;
    private long _tcpPackets;
    private long _udpPackets;
    private long _notParsed;
    private long _handle;
    private string? _openError;

    /// <summary>已结算事务总数（诊断用）。</summary>
    public long TransactionCount => Interlocked.Read(ref _transactions);

    /// <summary>运行期分层计数摘要（排障用）：收包/解析/路由/落库各层报文数。</summary>
    public string GetDiagnostics() =>
        $"handle=0x{Interlocked.Read(ref _handle):X}, openError={_openError}, " +
        $"recv={Interlocked.Read(ref _packetsReceived)}, short={Interlocked.Read(ref _packetsTooShort)}, " +
        $"recvFail={Interlocked.Read(ref _recvFailures)}, lastRecvError={WinDivert.LastRecvError}, " +
        $"tcp={Interlocked.Read(ref _tcpPackets)}, udp={Interlocked.Read(ref _udpPackets)}, " +
        $"flows={_flows.Count}, quicFlows={_quicFlows.Count}, transactions={Interlocked.Read(ref _transactions)}, " +
        $"notParsed={Interlocked.Read(ref _notParsed)}";

    /// <param name="filter">WinDivert 过滤表达式，默认捕获全部 TCP。</param>
    /// <param name="recordAsync">事务结算回调（由调用方持久化）。</param>
    /// <param name="keyLog">SSLKEYLOGFILE 密钥日志（为 null 时 TLS 只记隧道不解密）。</param>
    public SilentCaptureEngine(string filter, Func<SilentCapturedTransaction, Task> recordAsync, SilentTlsKeyLog? keyLog = null)
    {
        _filter = string.IsNullOrWhiteSpace(filter) ? "tcp" : filter;
        _recordAsync = recordAsync;
        _keyLog = keyLog;
    }

    /// <summary>注入单个合成报文走完整路由结算链路（冒烟测试用；生产路径经由 RunAsync）。</summary>
    public Task InjectPacketAsync(SilentTcpPacket packet, bool outbound) => RoutePacketAsync(packet, outbound);

    /// <summary>注入合成 UDP 报文（QUIC 冒烟测试用）。</summary>
    public Task InjectUdpPacketAsync(SilentUdpPacket packet, bool outbound) => RouteUdpPacketAsync(packet, outbound);

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        IntPtr handle;
        try
        {
            handle = WinDivert.Open(_filter);
        }
        catch (Exception exception)
        {
            _openError = exception.Message;
            throw;
        }
        Interlocked.Exchange(ref _handle, handle.ToInt64());
        var closed = 0;
        using var registration = cancellationToken.Register(() =>
        {
            if (Interlocked.Exchange(ref closed, 1) == 0) WinDivert.Close(handle);
        });
        try
        {
            var buffer = new byte[64 * 1024];
            var lastEvictionTicks = Environment.TickCount64;
            while (!cancellationToken.IsCancellationRequested)
            {
                // 阻塞接收放到后台线程，保证 RunAsync 在打开句柄后立即让出，可被取消与就绪判定。
                var (received, address, read) = await Task.Run(() =>
                {
                    var success = WinDivert.Recv(handle, buffer, out var packetAddress, out var packetLength);
                    return (success, packetAddress, packetLength);
                }, CancellationToken.None);
                if (!received || read < 40)
                {
                    if (received) Interlocked.Increment(ref _packetsTooShort);
                    else
                    {
                        Interlocked.Increment(ref _recvFailures);
                        // 接收持续失败时避免空转风暴；正常停止路径由取消令牌退出循环。
                        await Task.Delay(10, CancellationToken.None);
                    }
                    continue;
                }
                Interlocked.Increment(ref _packetsReceived);
                var ipv6 = (address.LayerEventFlags & WinDivertAddress.FlagIpv6) != 0;
                var outbound = (address.LayerEventFlags & WinDivertAddress.FlagOutbound) != 0;
                if (!SilentPacketParser.TryParseTcpPacket(buffer.AsSpan(0, read), ipv6, out var packet))
                {
                    if (SilentPacketParser.TryParseUdpPacket(buffer.AsSpan(0, read), ipv6, out var udpPacket))
                    {
                        Interlocked.Increment(ref _udpPackets);
                        await RouteUdpPacketAsync(udpPacket, outbound);
                    }
                    else Interlocked.Increment(ref _notParsed);
                    continue;
                }
                Interlocked.Increment(ref _tcpPackets);
                await RoutePacketAsync(packet, outbound);
                var nowTicks = Environment.TickCount64;
                if (nowTicks - lastEvictionTicks > 5000)
                {
                    await EvictIdleFlowsAsync();
                    lastEvictionTicks = nowTicks;
                }
            }
        }
        catch (OperationCanceledException)
        {
            // 正常停止：落到 finally 结算全部流。
        }
        finally
        {
            foreach (var flow in _flows.Values.ToArray()) await FinalizeFlowAsync(flow);
            _flows.Clear();
            foreach (var quicFlow in _quicFlows.Values.ToArray()) await FinalizeQuicFlowAsync(quicFlow);
            _quicFlows.Clear();
            if (Interlocked.Exchange(ref closed, 1) == 0) WinDivert.Close(handle);
        }
    }

    private async Task RoutePacketAsync(SilentTcpPacket packet, bool outbound)
    {
        var sourceEndpoint = new IPEndPoint(packet.SourceAddress, packet.SourcePort);
        var destinationEndpoint = new IPEndPoint(packet.DestinationAddress, packet.DestinationPort);
        var key = FlowKey(sourceEndpoint, destinationEndpoint);
        if (!_flows.TryGetValue(key, out var flow))
        {
            if (_flows.Count >= NetMindDefaults.SilentMaximumFlows) await EvictOldestFlowAsync();
            flow = new FlowState
            {
                Key = key,
                FirstSeen = DateTimeOffset.UtcNow,
                ProcessLabel = ResolveProcessLabel(sourceEndpoint, destinationEndpoint)
            };
            _flows[key] = flow;
        }
        flow.LastActivity = DateTimeOffset.UtcNow;
        // 客户端方向判定：纯 SYN 最权威；其次用地址结构 Outbound 位（本机发出方为客户端）；
        // 中途捕获且两者都不可用时，以首个报文方向为客户端方向。
        if (packet.Syn && !packet.Ack)
        {
            AssignDirection(flow, sourceEndpoint, destinationEndpoint);
            flow.DirectionKnown = true;
        }
        else if (!flow.DirectionKnown)
        {
            AssignDirection(flow, outbound ? sourceEndpoint : destinationEndpoint,
                outbound ? destinationEndpoint : sourceEndpoint);
            flow.DirectionKnown = true;
        }
        var clientDirection = Matches(flow.ClientEndpoint, sourceEndpoint);

        var reassembler = clientDirection ? flow.ToServer : flow.ToClient;
        if (packet.Syn) reassembler.Initialize(packet.Sequence);
        if (packet.Payload.Length > 0 && !reassembler.Broken)
        {
            var contiguous = reassembler.Append(packet.Sequence, packet.Payload);
            if (contiguous.Length > 0) await FeedStreamAsync(flow, clientDirection, contiguous);
        }
        if (packet.Rst)
        {
            flow.Reset = true;
            await FinalizeFlowAsync(flow);
            _flows.Remove(key);
            return;
        }
        if (packet.Fin)
        {
            if (clientDirection) flow.ClientClosed = true;
            else flow.ServerClosed = true;
            // 客户端 FIN 结束请求流，服务端 FIN 结束响应流（含“读到关闭为止”正文的结算）。
            if (clientDirection) flow.Requests.Close();
            else flow.Responses.Close();
            await DrainResponsesAsync(flow);
            if (flow.ClientClosed && flow.ServerClosed)
            {
                await FinalizeFlowAsync(flow);
                _flows.Remove(key);
            }
        }
    }

    private async Task RouteUdpPacketAsync(SilentUdpPacket packet, bool outbound)
    {
        // 仅处理 QUIC 常见端口，避免捕获全部 UDP 带来的噪音
        if (packet.SourcePort != 443 && packet.DestinationPort != 443) return;
        var sourceEndpoint = new IPEndPoint(packet.SourceAddress, packet.SourcePort);
        var destinationEndpoint = new IPEndPoint(packet.DestinationAddress, packet.DestinationPort);
        var key = FlowKey(sourceEndpoint, destinationEndpoint);
        if (!_quicFlows.TryGetValue(key, out var flow))
        {
            if (_quicFlows.Count >= NetMindDefaults.SilentMaximumFlows / 4) await EvictOldestQuicFlowAsync();
            flow = new QuicFlow
            {
                Key = key,
                Quic = new SilentQuicConnection(_keyLog),
                ProcessLabel = ResolveProcessLabel(sourceEndpoint, destinationEndpoint)
            };
            _quicFlows[key] = flow;
        }
        flow.LastActivity = DateTimeOffset.UtcNow;
        if (!flow.DirectionKnown)
        {
            // QUIC 无 SYN：以首个报文方向（结合 Outbound 位）认定客户端
            flow.ClientEndpoint = outbound ? sourceEndpoint : destinationEndpoint;
            flow.ServerEndpoint = outbound ? destinationEndpoint : sourceEndpoint;
            flow.DirectionKnown = true;
        }
        var clientDirection = Matches(flow.ClientEndpoint, sourceEndpoint);
        var streams = flow.Quic.Feed(clientDirection, packet.Payload);
        // Initial 解密出 ClientHello 即落隧道记录（与 TLS 同策略，QUIC 连接长驻复用）
        if (!flow.TunnelRecorded && flow.Quic.Sni is not null)
        {
            flow.TunnelRecorded = true;
            var target = flow.Quic.Sni;
            var traffic = new TrafficRecord(
                Guid.NewGuid(), flow.FirstSeen, "CONNECT", target, 200, 0, 0,
                flow.ProcessLabel, NetMindDefaults.ProtocolSilentQuic,
                $"QUIC 隧道 {target}",
                flow.Quic.Alpn == "h3"
                    ? "QUIC/HTTP3 隧道：正文按流重组中。"
                    : "QUIC 隧道：仅记录握手元数据与目标主机。",
                "https://" + target + "/");
            await _recordAsync(new SilentCapturedTransaction(traffic, [], []));
            Interlocked.Increment(ref _transactions);
        }
        // M4：ALPN 为 h3 的流数据喂入 HTTP/3 连接解码器，重组为事务落库
        if (streams.Count > 0 && flow.Quic.Alpn == "h3")
        {
            flow.Http3 ??= new SilentHttp3Connection();
            foreach (var stream in streams) flow.Http3.Feed(stream);
            await DrainHttp3Async(flow);
        }
    }

    private async Task DrainHttp3Async(QuicFlow flow)
    {
        if (flow.Http3 is null) return;
        while (flow.Http3.Completed.TryDequeue(out var exchange))
        {
            await _recordAsync(BuildHttp3Transaction(flow, exchange));
            Interlocked.Increment(ref _transactions);
        }
    }

    private SilentCapturedTransaction BuildHttp3Transaction(QuicFlow flow, SilentHttp3Exchange exchange)
    {
        var method = FindHeader(exchange.RequestHeaders, ":method") ?? "GET";
        var target = FindHeader(exchange.RequestHeaders, ":path") ?? "/";
        var authority = FindHeader(exchange.RequestHeaders, ":authority")
                        ?? flow.Quic.Sni ?? flow.ServerEndpoint?.ToString() ?? string.Empty;
        var statusCode = int.TryParse(FindHeader(exchange.ResponseHeaders, ":status"), out var code) ? code : 0;
        // QUIC 恒为 https（h3 强制 TLS）
        var url = "https://" + authority + (target.StartsWith('/') ? target : "/" + target);
        var queryIndex = url.IndexOf('?');
        var pathPart = queryIndex < 0 ? url : url[..queryIndex];
        var queryPart = queryIndex < 0 ? string.Empty : url[(queryIndex + 1)..];
        var uriPath = pathPart;
        try { uriPath = new Uri(pathPart).AbsolutePath; } catch (UriFormatException) { /* 非绝对 URL 保留原路径 */ }
        var statusText = FindHeader(exchange.ResponseHeaders, ":status") ?? "0";
        // 落库正文按 Content-Encoding 解压，避免 gzip/br 压缩字节被当文本展示。
        var responseBody = ProtocolParsers.DecompressHttpBody(
            FindHeader(exchange.ResponseHeaders, "content-encoding"), exchange.ResponseBody);
        var traffic = new TrafficRecord(
            Guid.NewGuid(), exchange.RequestAt, method, uriPath, statusCode,
            (int)Math.Max(0, (DateTimeOffset.UtcNow - exchange.RequestAt).TotalMilliseconds),
            exchange.RequestBody.Length + responseBody.Length,
            flow.ProcessLabel, NetMindDefaults.ProtocolSilentHttp3,
            $"{method} {target}", $"HTTP/3 {statusText}",
            url, FormatQuery(queryPart), FormatHeaders(exchange.RequestHeaders), FormatCookies(exchange.RequestHeaders),
            FormatHeaders(exchange.ResponseHeaders));
        return new SilentCapturedTransaction(traffic, exchange.RequestBody, responseBody);
    }

    private async Task EvictOldestQuicFlowAsync()
    {
        var oldest = _quicFlows.Values.MinBy(item => item.LastActivity);
        if (oldest is null) return;
        await FinalizeQuicFlowAsync(oldest);
        _quicFlows.Remove(oldest.Key);
    }

    /// <summary>QUIC 流淘汰/停止时兜底：结算未关闭的 HTTP/3 交换后丢弃。</summary>
    private async Task FinalizeQuicFlowAsync(QuicFlow flow)
    {
        flow.Http3?.FlushPending();
        await DrainHttp3Async(flow);
    }

    private static void AssignDirection(FlowState flow, IPEndPoint source, IPEndPoint destination)
    {
        flow.ClientEndpoint = source;
        flow.ServerEndpoint = destination;
    }

    private static bool Matches(IPEndPoint? endpoint, IPEndPoint candidate) =>
        endpoint is not null && endpoint.Port == candidate.Port && endpoint.Address.Equals(candidate.Address);

    private static string FlowKey(IPEndPoint left, IPEndPoint right)
    {
        var first = $"{left.Address}:{left.Port}";
        var second = $"{right.Address}:{right.Port}";
        return string.CompareOrdinal(first, second) <= 0 ? $"{first}|{second}" : $"{second}|{first}";
    }

    private async Task FeedStreamAsync(FlowState flow, bool clientDirection, byte[] data)
    {
        if (!flow.Classified && clientDirection)
        {
            if (SilentPacketParser.LooksLikeTlsClientHello(data))
            {
                flow.Classified = true;
                flow.IsTls = true;
                flow.Sni = SilentPacketParser.TryParseTlsServerName(data);
                if (_keyLog is not null) flow.Tls = new SilentTlsSession(_keyLog);
                // 识别到 ClientHello 立即落库隧道记录：浏览器 TLS 连接长驻复用（keep-alive/HTTP2 连接池），
                // 若等流结算才记录，活跃浏览期间用户几乎看不到任何条目。
                await RecordTlsTunnelAsync(flow);
            }
            else flow.Classified = true;
        }
        if (flow.IsTls)
        {
            if (flow.Tls is null) return;
            // 解密器消费记录层字节；解密失败/缺密钥时保持隧道模式，绝不中断抓包。
            var plain = clientDirection ? flow.Tls.FeedClient(data) : flow.Tls.FeedServer(data);
            if (flow.Tls.Broken) { flow.Tls = null; return; }
            if (plain.Length == 0) return;
            if (flow.Tls.Alpn == "h2")
            {
                // HTTP/2：解密明文按方向馈入连接解码器，按流重组为事务
                flow.Http2 ??= new SilentHttp2Connection();
                if (clientDirection) flow.Http2.FeedClient(plain); else flow.Http2.FeedServer(plain);
                await DrainHttp2Async(flow);
                return;
            }
            data = plain; // http/1.1（或无 ALPN 的 TLS 1.2）明文落到下方 h1 配对
        }

        if (clientDirection)
        {
            flow.Requests.Feed(data);
            while (flow.Requests.Completed.TryDequeue(out var request))
                flow.PendingRequests.Enqueue((request, DateTimeOffset.UtcNow));
        }
        else
        {
            flow.Responses.Feed(data);
            await DrainResponsesAsync(flow);
        }
    }

    private async Task DrainResponsesAsync(FlowState flow)
    {
        while (flow.Responses.Completed.TryDequeue(out var response))
        {
            if (!flow.PendingRequests.TryDequeue(out var pending)) continue;
            var (request, requestAt) = pending;
            await _recordAsync(BuildTransaction(flow, request, requestAt, response));
            Interlocked.Increment(ref _transactions);
        }
    }

    private async Task DrainHttp2Async(FlowState flow)
    {
        if (flow.Http2 is null) return;
        while (flow.Http2.Completed.TryDequeue(out var exchange))
        {
            await _recordAsync(BuildHttp2Transaction(flow, exchange));
            Interlocked.Increment(ref _transactions);
        }
    }

    private async Task FinalizeFlowAsync(FlowState flow)
    {
        flow.Requests.Close();
        flow.Responses.Close();
        await DrainResponsesAsync(flow);
        flow.PendingRequests.Clear();
        // HTTP/2 连接长驻，流结束时兜底结算未收到 END_STREAM 的进行中交换
        flow.Http2?.FlushPending();
        await DrainHttp2Async(flow);
        // 识别阶段已即时落库的隧道不再重复；仅兜底“未及识别就结束”的边界情况。
        await RecordTlsTunnelAsync(flow);
    }

    private async Task RecordTlsTunnelAsync(FlowState flow)
    {
        if (!flow.IsTls || flow.TlsRecorded) return;
        flow.TlsRecorded = true;
        var target = string.IsNullOrWhiteSpace(flow.Sni)
            ? flow.ServerEndpoint?.ToString() ?? "未知主机"
            : flow.Sni!;
        var traffic = new TrafficRecord(
            Guid.NewGuid(), flow.FirstSeen, "CONNECT", target, 200, 0, 0,
            flow.ProcessLabel, NetMindDefaults.ProtocolSilentTlsTunnel,
            $"TLS 隧道 {target}", "TLS 正文保持加密。仅记录握手元数据与目标主机。",
            "https://" + target + "/");
        await _recordAsync(new SilentCapturedTransaction(traffic, [], []));
        Interlocked.Increment(ref _transactions);
    }

    private SilentCapturedTransaction BuildTransaction(FlowState flow, SilentHttpMessage request,
        DateTimeOffset requestAt, SilentHttpMessage response)
    {
        var requestParts = request.StartLine.Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
        var method = requestParts.ElementAtOrDefault(0) ?? "GET";
        var target = requestParts.ElementAtOrDefault(1) ?? "/";
        var responseParts = response.StartLine.Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
        var statusCode = int.TryParse(responseParts.ElementAtOrDefault(1), out var code) ? code : 0;

        var host = request.Headers.TryGetValue("Host", out var hostValue) && !string.IsNullOrWhiteSpace(hostValue)
            ? hostValue.Trim()
            : flow.Sni ?? flow.ServerEndpoint?.ToString() ?? string.Empty;
        // TLS 解密出的明文按 https 重建 URL；无 Host 头时回退 SNI。
        var scheme = flow.IsTls ? "https" : "http";
        string url;
        if (target.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || target.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            url = target;
        else
            url = scheme + "://" + host + (target.StartsWith('/') ? target : "/" + target);
        var queryIndex = url.IndexOf('?');
        var pathPart = queryIndex < 0 ? url : url[..queryIndex];
        var queryPart = queryIndex < 0 ? string.Empty : url[(queryIndex + 1)..];
        var uriPath = pathPart;
        try { uriPath = new Uri(pathPart).AbsolutePath; } catch (UriFormatException) { /* 非绝对 URL 保留原路径 */ }

        var latency = (int)Math.Max(0, (DateTimeOffset.UtcNow - requestAt).TotalMilliseconds);
        // 落库正文按 Content-Encoding 解压，避免 gzip/br 压缩字节被当文本展示。
        var responseBody = ProtocolParsers.DecompressHttpBody(FindHeader(response.Headers), response.Body);
        var traffic = new TrafficRecord(
            Guid.NewGuid(), requestAt, method, uriPath, statusCode, latency,
            request.Body.Length + responseBody.Length,
            flow.ProcessLabel, flow.IsTls ? "HTTPS/1.1（已解密）" : "HTTP/1.1",
            $"{method} {target}", response.StartLine,
            url, FormatQuery(queryPart), request.HeaderText, FormatCookies(request), response.HeaderText);
        return new SilentCapturedTransaction(traffic, request.Body, responseBody);
    }

    private SilentCapturedTransaction BuildHttp2Transaction(FlowState flow, SilentHttp2Exchange exchange)
    {
        var method = FindHeader(exchange.RequestHeaders, ":method") ?? "GET";
        var target = FindHeader(exchange.RequestHeaders, ":path") ?? "/";
        var authority = FindHeader(exchange.RequestHeaders, ":authority")
                        ?? FindHeader(exchange.RequestHeaders, "host")
                        ?? flow.Sni ?? flow.ServerEndpoint?.ToString() ?? string.Empty;
        var statusCode = int.TryParse(FindHeader(exchange.ResponseHeaders, ":status"), out var code) ? code : 0;
        var scheme = flow.IsTls ? "https" : "http";
        var url = scheme + "://" + authority + (target.StartsWith('/') ? target : "/" + target);
        var queryIndex = url.IndexOf('?');
        var pathPart = queryIndex < 0 ? url : url[..queryIndex];
        var queryPart = queryIndex < 0 ? string.Empty : url[(queryIndex + 1)..];
        var uriPath = pathPart;
        try { uriPath = new Uri(pathPart).AbsolutePath; } catch (UriFormatException) { /* 非绝对 URL 保留原路径 */ }
        var statusText = FindHeader(exchange.ResponseHeaders, ":status") ?? "0";
        // 落库正文按 Content-Encoding 解压，避免 gzip/br 压缩字节被当文本展示。
        var responseBody = ProtocolParsers.DecompressHttpBody(
            FindHeader(exchange.ResponseHeaders, "content-encoding"), exchange.ResponseBody);
        var traffic = new TrafficRecord(
            Guid.NewGuid(), exchange.RequestAt, method, uriPath, statusCode,
            (int)Math.Max(0, (DateTimeOffset.UtcNow - exchange.RequestAt).TotalMilliseconds),
            exchange.RequestBody.Length + responseBody.Length,
            flow.ProcessLabel, NetMindDefaults.ProtocolSilentHttp2,
            $"{method} {target}", $"HTTP/2 {statusText}",
            url, FormatQuery(queryPart), FormatHeaders(exchange.RequestHeaders), FormatCookies(exchange.RequestHeaders),
            FormatHeaders(exchange.ResponseHeaders));
        return new SilentCapturedTransaction(traffic, exchange.RequestBody, responseBody);
    }

    private static string? FindHeader(List<(string Name, string Value)> headers, string name)
    {
        foreach (var (headerName, value) in headers)
            if (string.Equals(headerName, name, StringComparison.OrdinalIgnoreCase)) return value;
        return null;
    }

    /// <summary>HTTP/1.x 头部字典大小写不敏感查找（解析器构造时不保证比较器）。</summary>
    private static string? FindHeader(IReadOnlyDictionary<string, string> headers)
    {
        foreach (var (headerName, value) in headers)
            if (string.Equals(headerName, "content-encoding", StringComparison.OrdinalIgnoreCase)) return value;
        return null;
    }

    private static string FormatHeaders(List<(string Name, string Value)> headers)
    {
        return string.Join(Environment.NewLine, headers
            .Where(header => !header.Name.StartsWith(':'))
            .Select(header => $"{header.Name}: {header.Value}"));
    }

    private static string FormatCookies(List<(string Name, string Value)> headers)
    {
        var value = FindHeader(headers, "cookie");
        if (string.IsNullOrWhiteSpace(value)) return string.Empty;
        return string.Join(Environment.NewLine, value.Split(';', StringSplitOptions.RemoveEmptyEntries).Select(cookie =>
        {
            var pieces = cookie.Trim().Split('=', 2);
            return pieces[0] + " = " + (pieces.Length == 2 ? pieces[1] : string.Empty);
        }));
    }

    private static string ResolveProcessLabel(IPEndPoint source, IPEndPoint destination)
    {
        var identity = WindowsTcpProcessResolver.Resolve(source, destination)
                       ?? WindowsTcpProcessResolver.Resolve(destination, source);
        return identity?.DisplayName ?? "未知";
    }

    private async Task EvictIdleFlowsAsync()
    {
        var cutoff = DateTimeOffset.UtcNow.AddSeconds(-NetMindDefaults.SilentFlowIdleTimeoutSeconds);
        foreach (var flow in _flows.Values.Where(item => item.LastActivity < cutoff).ToArray())
        {
            await FinalizeFlowAsync(flow);
            _flows.Remove(flow.Key);
        }
        foreach (var quicFlow in _quicFlows.Values.Where(item => item.LastActivity < cutoff).ToArray())
        {
            await FinalizeQuicFlowAsync(quicFlow);
            _quicFlows.Remove(quicFlow.Key);
        }
    }

    private async Task EvictOldestFlowAsync()
    {
        var oldest = _flows.Values.MinBy(item => item.LastActivity);
        if (oldest is null) return;
        await FinalizeFlowAsync(oldest);
        _flows.Remove(oldest.Key);
    }

    private static string FormatQuery(string query)
    {
        if (string.IsNullOrWhiteSpace(query)) return string.Empty;
        return string.Join(Environment.NewLine, query.Split('&', StringSplitOptions.RemoveEmptyEntries).Select(part =>
        {
            var pieces = part.Split('=', 2);
            return $"{Decode(pieces[0])} = {(pieces.Length == 2 ? Decode(pieces[1]) : string.Empty)}";
        }));
    }

    private static string Decode(string value)
    {
        try { return Uri.UnescapeDataString(value.Replace('+', ' ')); }
        catch (UriFormatException) { return value; }
    }

    private static string FormatCookies(SilentHttpMessage request)
    {
        if (!request.Headers.TryGetValue("Cookie", out var value) || string.IsNullOrWhiteSpace(value)) return string.Empty;
        return string.Join(Environment.NewLine, value.Split(';', StringSplitOptions.RemoveEmptyEntries).Select(cookie =>
        {
            var pieces = cookie.Trim().Split('=', 2);
            return pieces[0] + " = " + (pieces.Length == 2 ? pieces[1] : string.Empty);
        }));
    }
}
