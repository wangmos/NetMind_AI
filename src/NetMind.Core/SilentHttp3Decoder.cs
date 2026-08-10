namespace NetMind.Core;

/// <summary>HTTP/3 一个已结算的请求/响应交换（按 QUIC 双向流配对）。</summary>
public sealed class SilentHttp3Exchange
{
    public long StreamId;
    public DateTimeOffset RequestAt = DateTimeOffset.UtcNow;
    public List<(string Name, string Value)> RequestHeaders = [];
    public List<(string Name, string Value)> ResponseHeaders = [];
    public byte[] RequestBody = [];
    public byte[] ResponseBody = [];
    public bool RequestEnded;
    public bool ResponseEnded;
}

/// <summary>
/// HTTP/3（RFC 9114）连接解码器：消费 QUIC 重组出的流数据。
/// 单向流按类型路由（编码器流喂给对应方向的 QPACK 解码器，控制/解码器流丢弃）；
/// 双向流按帧解析（HEADERS/DATA），QPACK 解出头字段后按流配对为交换。
/// 被动捕获缺编码器流前段时动态引用可能解不出：该头块放弃但不影响后续流量。
/// </summary>
public sealed class SilentHttp3Connection
{
    private const long FrameData = 0x00;
    private const long FrameHeaders = 0x01;
    private const long StreamTypeEncoder = 0x02;
    private const int MaximumOpenStreams = 512;

    private sealed class DirectionState
    {
        public byte[] Pending = [];  // 未拼成完整帧的残余字节
        public bool HeadersDone;     // 首个 HEADERS 帧已解出（后续 HEADERS 视为 trailer 忽略）
    }

    private sealed class StreamState
    {
        public required SilentHttp3Exchange Exchange;
        public readonly DirectionState Client = new();
        public readonly DirectionState Server = new();
    }

    private sealed class UniStreamState
    {
        public long Type = -1;       // 未读全类型 varint 前为 -1
        public byte[] Pending = [];
    }

    private readonly SilentQpackDecoder _clientQpack = new(); // 解客户端产出的字段段（请求）
    private readonly SilentQpackDecoder _serverQpack = new(); // 解服务端产出的字段段（响应）
    private readonly Dictionary<long, StreamState> _streams = new();
    private readonly Dictionary<long, UniStreamState> _uniStreams = new();

    /// <summary>已结算的交换队列（引擎消费落库）。</summary>
    public Queue<SilentHttp3Exchange> Completed { get; } = new();

    /// <summary>帧层出现不可恢复错误：调用方停止喂入。</summary>
    public bool Broken { get; private set; }

    /// <summary>喂入一条 QUIC 流重组数据；按流 ID 低位区分单向/双向。</summary>
    public void Feed(SilentQuicStreamData data)
    {
        if (Broken) return;
        try
        {
            if ((data.StreamId & 0x02) != 0) FeedUnidirectional(data);
            else FeedBidirectional(data);
        }
        catch (Exception exception) when (exception is InvalidDataException or IndexOutOfRangeException or ArgumentOutOfRangeException)
        {
            Broken = true;
        }
    }

    /// <summary>连接结束时兜底结算所有有头部的进行中交换。</summary>
    public void FlushPending()
    {
        foreach (var state in _streams.Values)
            if (state.Exchange.RequestHeaders.Count > 0 || state.Exchange.ResponseHeaders.Count > 0)
                Completed.Enqueue(state.Exchange);
        _streams.Clear();
    }

    // ── 单向流：编码器流喂 QPACK，其余丢弃 ──────────────────────

    private void FeedUnidirectional(SilentQuicStreamData data)
    {
        if (!_uniStreams.TryGetValue(data.StreamId, out var state))
        {
            state = new UniStreamState();
            _uniStreams[data.StreamId] = state;
        }
        state.Pending = Concat(state.Pending, data.Data);
        if (state.Type < 0)
        {
            var position = 0;
            if (!TryReadVarint(state.Pending, ref position, out var type)) { if (data.Fin) _uniStreams.Remove(data.StreamId); return; }
            state.Type = type;
            state.Pending = state.Pending[position..];
        }
        if (state.Type == StreamTypeEncoder)
        {
            // 客户端编码器流更新解请求用的动态表；服务端同理
            var qpack = data.ClientDirection ? _clientQpack : _serverQpack;
            if (state.Pending.Length > 0) qpack.FeedEncoderStream(state.Pending);
        }
        state.Pending = [];
        if (data.Fin) _uniStreams.Remove(data.StreamId);
    }

    // ── 双向流：帧解析 + 交换配对 ───────────────────────────────

    private void FeedBidirectional(SilentQuicStreamData data)
    {
        if (!_streams.TryGetValue(data.StreamId, out var state))
        {
            if (_streams.Count >= MaximumOpenStreams) SettleOldest();
            state = new StreamState { Exchange = new SilentHttp3Exchange { StreamId = data.StreamId } };
            _streams[data.StreamId] = state;
        }
        var direction = data.ClientDirection ? state.Client : state.Server;
        var qpack = data.ClientDirection ? _clientQpack : _serverQpack;
        direction.Pending = Concat(direction.Pending, data.Data);

        var position = 0;
        while (TryReadFrame(direction.Pending, ref position, out var frameType, out var payload))
        {
            if (frameType == FrameData)
            {
                AppendBody(state, data.ClientDirection, payload);
            }
            else if (frameType == FrameHeaders && !direction.HeadersDone)
            {
                var headers = qpack.DecodeFieldSection(payload);
                if (headers is not null)
                {
                    if (data.ClientDirection) state.Exchange.RequestHeaders = headers;
                    else state.Exchange.ResponseHeaders = headers;
                }
                // QPACK Broken 时仅放弃该头块；帧层继续
                direction.HeadersDone = true;
            }
            // 其余帧类型（SETTINGS 残留/尾部 HEADERS/未知）按跳过处理
        }
        if (position > 0) direction.Pending = direction.Pending[position..];

        if (data.Fin)
        {
            if (data.ClientDirection) state.Exchange.RequestEnded = true;
            else state.Exchange.ResponseEnded = true;
        }
        if (state.Exchange.RequestEnded && state.Exchange.ResponseEnded) Settle(data.StreamId, state);
    }

    private void AppendBody(StreamState state, bool clientDirection, byte[] payload)
    {
        if (clientDirection)
        {
            if (state.Exchange.RequestBody.Length + payload.Length <= NetMindDefaults.SilentMaximumBodyBytes)
                state.Exchange.RequestBody = Concat(state.Exchange.RequestBody, payload);
        }
        else
        {
            if (state.Exchange.ResponseBody.Length + payload.Length <= NetMindDefaults.SilentMaximumBodyBytes)
                state.Exchange.ResponseBody = Concat(state.Exchange.ResponseBody, payload);
        }
    }

    private void Settle(long streamId, StreamState state)
    {
        _streams.Remove(streamId);
        if (state.Exchange.RequestHeaders.Count > 0 || state.Exchange.ResponseHeaders.Count > 0)
            Completed.Enqueue(state.Exchange);
    }

    private void SettleOldest()
    {
        // 字典保持插入序（未重排的 Dictionary 枚举序 = 插入序）：结算最早打开的流
        foreach (var (streamId, state) in _streams)
        {
            Settle(streamId, state);
            return;
        }
    }

    // ── 帧与 varint 读取（不完整返回 false，位置不回退由调用方裁剪）──

    private static bool TryReadFrame(byte[] buffer, ref int position, out long frameType, out byte[] payload)
    {
        frameType = 0;
        payload = [];
        var start = position;
        if (!TryReadVarint(buffer, ref position, out frameType)) { position = start; return false; }
        if (!TryReadVarint(buffer, ref position, out var length)) { position = start; return false; }
        if (length > NetMindDefaults.SilentMaximumHeaderBytes && frameType == FrameHeaders) throw new InvalidDataException("HEADERS 帧超限");
        if (position + length > buffer.Length) { position = start; return false; }
        payload = buffer.AsSpan(position, (int)length).ToArray();
        position += (int)length;
        return true;
    }

    private static bool TryReadVarint(byte[] buffer, ref int position, out long value)
    {
        value = 0;
        if (position >= buffer.Length) return false;
        var first = buffer[position];
        var length = 1 << (first >> 6);
        if (position + length > buffer.Length) return false;
        value = first & 0x3f;
        position += 1;
        for (var i = 1; i < length; i++) value = (value << 8) | buffer[position++];
        return true;
    }

    private static byte[] Concat(byte[] first, ReadOnlySpan<byte> second)
    {
        if (second.IsEmpty) return first;
        var joined = new byte[first.Length + second.Length];
        first.CopyTo(joined, 0);
        second.CopyTo(joined.AsSpan(first.Length));
        return joined;
    }
}
