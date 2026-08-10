namespace NetMind.Core;

/// <summary>HTTP/2 解码出的一次完整交换：按流 ID 配对的请求/响应伪首部与正文。</summary>
public sealed class SilentHttp2Exchange
{
    public int StreamId;
    public DateTimeOffset RequestAt = DateTimeOffset.UtcNow;
    public List<(string Name, string Value)> RequestHeaders = [];
    public List<(string Name, string Value)> ResponseHeaders = [];
    public byte[] RequestBody = [];
    public byte[] ResponseBody = [];
    public bool RequestEnded;
    public bool ResponseEnded;
    /// <summary>RST_STREAM 中止：首部/正文可能不完整。</summary>
    public bool Reset;
}

/// <summary>
/// HTTP/2 连接解码器（RFC 7540/9113 帧层）：解析 9 字节帧头，按流重组 HEADERS/CONTINUATION/DATA，
/// END_STREAM 或 RST_STREAM 时产出配对交换。每方向独立 HPACK 上下文与帧缓冲；
/// 仅解码不编码，任何协议违例标记 <see cref="Broken"/> 后停止解码（抓包本身不受影响）。
/// </summary>
public sealed class SilentHttp2Connection
{
    private const int FrameData = 0;
    private const int FrameHeaders = 1;
    private const int FramePriority = 2;
    private const int FrameRstStream = 3;
    private const int FrameSettings = 4;
    private const int FramePushPromise = 5;
    private const int FramePing = 6;
    private const int FrameGoaway = 7;
    private const int FrameWindowUpdate = 8;
    private const int FrameContinuation = 9;

    private const int FlagEndStream = 0x1;
    private const int FlagEndHeaders = 0x4;
    private const int FlagPadded = 0x8;
    private const int FlagPriority = 0x20;
    private const int FlagAck = 0x1;

    // 客户端连接前言（魔法字节），仅客户端方向首个分片可能出现
    private static readonly byte[] ClientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"u8.ToArray();

    /// <summary>单方向解码状态：帧缓冲 + HPACK 上下文 + 未完成的头块分片。</summary>
    private sealed class DirectionState
    {
        public readonly MemoryStream Buffer = new();
        public int BufferedBytes;
        public readonly SilentHpackDecoder Hpack = new();
        public bool PrefaceChecked;
        public int PendingStreamId;                    // 0 = 无等待 CONTINUATION 的头块
        public int PendingFlags;
        public readonly MemoryStream PendingFragment = new();
    }

    /// <summary>流内解码状态：请求/响应首部与正文缓冲。</summary>
    private sealed class StreamState
    {
        public readonly SilentHttp2Exchange Exchange = new();
        public readonly MemoryStream RequestBody = new();
        public readonly MemoryStream ResponseBody = new();
        public bool RequestHeadersSeen;
        public bool ResponseHeadersSeen;
    }

    private readonly DirectionState _client = new();
    private readonly DirectionState _server = new();
    private readonly Dictionary<int, StreamState> _streams = new();

    /// <summary>已结算的完整交换（按结算顺序）。</summary>
    public Queue<SilentHttp2Exchange> Completed { get; } = new();

    /// <summary>出现过协议违例：该连接解码停用（调用方保留隧道记录即可）。</summary>
    public bool Broken { get; private set; }

    public void FeedClient(byte[] data) => Feed(_client, clientDirection: true, data);

    public void FeedServer(byte[] data) => Feed(_server, clientDirection: false, data);

    /// <summary>流结束/淘汰时兜底：产出所有尚未结算但已有首部的交换。</summary>
    public void FlushPending()
    {
        if (Broken) return;
        foreach (var stream in _streams.Values.ToArray()) Emit(stream, settled: false);
        _streams.Clear();
    }

    private void Feed(DirectionState direction, bool clientDirection, byte[] data)
    {
        if (Broken || data.Length == 0) return;
        direction.Buffer.Write(data);
        direction.BufferedBytes += data.Length;
        if (!direction.PrefaceChecked)
        {
            direction.PrefaceChecked = true;
            if (clientDirection) TryConsumePreface(direction); // 前言可能与后续帧同块到达，剥离后继续解析
        }
        ParseFrames(direction, clientDirection);
    }

    private static bool TryConsumePreface(DirectionState direction)
    {
        var buffer = direction.Buffer.GetBuffer().AsSpan(0, direction.BufferedBytes);
        if (buffer.Length < ClientPreface.Length || !buffer[..ClientPreface.Length].SequenceEqual(ClientPreface))
            return false;
        var remaining = buffer[ClientPreface.Length..].ToArray();
        direction.Buffer.SetLength(0);
        direction.Buffer.Write(remaining);
        direction.BufferedBytes = remaining.Length;
        return true;
    }

    private void ParseFrames(DirectionState direction, bool clientDirection)
    {
        var buffer = direction.Buffer.GetBuffer().AsSpan(0, direction.BufferedBytes);
        var offset = 0;
        while (buffer.Length - offset >= 9)
        {
            var header = buffer.Slice(offset, 9);
            var length = (header[0] << 16) | (header[1] << 8) | header[2];
            var type = header[3];
            var flags = header[4];
            var streamId = ((header[5] & 0x7f) << 24) | (header[6] << 16) | (header[7] << 8) | header[8];
            if (length > NetMindDefaults.SilentMaximumBodyBytes) { Broken = true; break; }
            if (buffer.Length - offset < 9 + length) break; // 帧未收全，等下一块
            var payload = buffer.Slice(offset + 9, length);
            offset += 9 + length;
            if (!HandleFrame(direction, clientDirection, type, flags, streamId, payload)) { Broken = true; break; }
        }
        if (offset > 0)
        {
            var remaining = buffer[offset..].ToArray();
            direction.Buffer.SetLength(0);
            direction.Buffer.Write(remaining);
            direction.BufferedBytes = remaining.Length;
        }
    }

    private bool HandleFrame(DirectionState direction, bool clientDirection, int type, int flags, int streamId, ReadOnlySpan<byte> payload)
    {
        // 头块分片期间只允许 CONTINUATION（RFC 9113 6.10）
        if (direction.PendingStreamId != 0 && type != FrameContinuation) return false;
        switch (type)
        {
            case FrameHeaders:
            {
                if (streamId == 0) return false;
                var fragment = payload;
                if ((flags & FlagPadded) != 0)
                {
                    if (fragment.IsEmpty) return false;
                    var padLength = fragment[0];
                    if (padLength >= fragment.Length) return false;
                    fragment = fragment[1..^padLength];
                }
                if ((flags & FlagPriority) != 0)
                {
                    if (fragment.Length < 5) return false;
                    fragment = fragment[5..]; // 流依赖 4 字节 + 权重 1 字节，解码无需
                }
                return BeginHeaderBlock(direction, clientDirection, flags, streamId, fragment);
            }
            case FrameContinuation:
            {
                if (streamId != direction.PendingStreamId) return false;
                if (direction.PendingFragment.Length + payload.Length > NetMindDefaults.SilentMaximumHeaderBytes) return false;
                direction.PendingFragment.Write(payload);
                if ((flags & FlagEndHeaders) != 0)
                {
                    // END_STREAM 可能携带在 HEADERS 或末尾 CONTINUATION 上，两者合并
                    direction.PendingFlags |= flags & FlagEndStream;
                    return FinishHeaderBlock(direction, clientDirection);
                }
                return true;
            }
            case FrameData:
            {
                if (streamId == 0) return false;
                var body = payload;
                if ((flags & FlagPadded) != 0)
                {
                    if (body.IsEmpty) return false;
                    var padLength = body[0];
                    if (padLength >= body.Length) return false;
                    body = body[1..^padLength];
                }
                return HandleData(clientDirection, streamId, flags, body);
            }
            case FrameRstStream:
            {
                if (streamId == 0 || payload.Length != 4) return false;
                if (_streams.TryGetValue(streamId, out var stream))
                {
                    stream.Exchange.Reset = true;
                    Emit(stream, settled: true);
                    _streams.Remove(streamId);
                }
                return true;
            }
            case FrameGoaway:
            {
                // 连接关闭在即：结算全部进行中的交换
                foreach (var stream in _streams.Values.ToArray()) Emit(stream, settled: true);
                _streams.Clear();
                return true;
            }
            default:
                // SETTINGS/PING/WINDOW_UPDATE/PRIORITY/PUSH_PROMISE 等对事务解码无影响；
                // 偶数流（服务端推送）不参与配对，忽略。
                return true;
        }
    }

    private bool BeginHeaderBlock(DirectionState direction, bool clientDirection, int flags, int streamId, ReadOnlySpan<byte> fragment)
    {
        if ((flags & FlagEndHeaders) != 0)
            return ApplyHeaderBlock(direction, clientDirection, flags, streamId, fragment);
        direction.PendingStreamId = streamId;
        direction.PendingFlags = flags;
        direction.PendingFragment.SetLength(0);
        direction.PendingFragment.Write(fragment);
        return true;
    }

    private bool FinishHeaderBlock(DirectionState direction, bool clientDirection)
    {
        var streamId = direction.PendingStreamId;
        var flags = direction.PendingFlags;
        var fragment = direction.PendingFragment.ToArray();
        direction.PendingStreamId = 0;
        direction.PendingFlags = 0;
        direction.PendingFragment.SetLength(0);
        return ApplyHeaderBlock(direction, clientDirection, flags, streamId, fragment);
    }

    private bool ApplyHeaderBlock(DirectionState direction, bool clientDirection, int flags, int streamId, ReadOnlySpan<byte> fragment)
    {
        var headers = direction.Hpack.Decode(fragment);
        if (headers is null) return false;
        // 服务端推送的偶数流不参与配对
        if ((streamId & 1) == 0) return true;
        if (_streams.Count >= 512)
        {
            // 并发流异常堆积：结算最旧的流，避免无界增长
            var oldest = _streams.OrderBy(item => item.Key).First();
            Emit(oldest.Value, settled: false);
            _streams.Remove(oldest.Key);
        }
        if (!_streams.TryGetValue(streamId, out var stream))
        {
            stream = new StreamState { Exchange = { StreamId = streamId } };
            _streams[streamId] = stream;
        }
        var exchange = stream.Exchange;
        if (clientDirection)
        {
            if (!stream.RequestHeadersSeen)
            {
                exchange.RequestAt = DateTimeOffset.UtcNow;
                stream.RequestHeadersSeen = true;
            }
            exchange.RequestHeaders.AddRange(headers); // 首个 HEADERS 为请求首部，后续为 trailer
            if ((flags & FlagEndStream) != 0) exchange.RequestEnded = true;
        }
        else
        {
            stream.ResponseHeadersSeen = true;
            exchange.ResponseHeaders.AddRange(headers);
            if ((flags & FlagEndStream) != 0) exchange.ResponseEnded = true;
        }
        TryComplete(streamId, stream);
        return true;
    }

    private bool HandleData(bool clientDirection, int streamId, int flags, ReadOnlySpan<byte> body)
    {
        if (!_streams.TryGetValue(streamId, out var stream)) return true; // HEADERS 缺失时的 DATA：跳过不判错
        var target = clientDirection ? stream.RequestBody : stream.ResponseBody;
        if (target.Length + body.Length <= NetMindDefaults.SilentMaximumBodyBytes) target.Write(body);
        // 超限部分静默丢弃（与 h1 正文上限策略一致）
        if ((flags & FlagEndStream) != 0)
        {
            if (clientDirection) stream.Exchange.RequestEnded = true;
            else stream.Exchange.ResponseEnded = true;
        }
        TryComplete(streamId, stream);
        return true;
    }

    /// <summary>双向均结束时结算：正常路径要求双方 END_STREAM；RST 立即结算。</summary>
    private void TryComplete(int streamId, StreamState stream)
    {
        var exchange = stream.Exchange;
        if (!exchange.Reset && (!exchange.RequestEnded || !exchange.ResponseEnded)) return;
        Emit(stream, settled: true);
        _streams.Remove(streamId);
    }

    private void Emit(StreamState stream, bool settled)
    {
        var exchange = stream.Exchange;
        if (exchange.RequestHeaders.Count == 0 && exchange.ResponseHeaders.Count == 0) return;
        exchange.RequestBody = stream.RequestBody.ToArray();
        exchange.ResponseBody = stream.ResponseBody.ToArray();
        if (!settled) { /* 兜底结算：结束标志保持现状，调用方按不完整事务展示 */ }
        Completed.Enqueue(exchange);
    }
}
