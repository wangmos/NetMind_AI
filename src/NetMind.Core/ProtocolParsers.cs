using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;

namespace NetMind.Core;

public sealed record Http2Frame(int Length, byte Type, byte Flags, int StreamId, byte[] Payload);
public sealed record WebSocketFrame(bool Final, byte Opcode, bool Masked, byte[] Payload);
public sealed record ReassembledWebSocketMessage(bool IsText, byte[] Payload, bool IsControl);
public sealed record ServerSentEvent(string Event, string Data, string? Id, int? RetryMilliseconds);
public sealed record GrpcEnvelope(bool Compressed, byte[] Message);
public sealed record DnsQuestion(string Name, ushort Type, ushort Class);
public sealed record DnsMessage(ushort Id, bool IsResponse, ushort ResponseCode, IReadOnlyList<DnsQuestion> Questions);
public sealed record ProtobufField(int Number, int WireType, ulong? NumericValue, byte[] Data);

public static class ProtocolParsers
{
    private const int MaximumFrameBytes = 16 * 1024 * 1024;

    // 重组后的单条 WebSocket 消息与 gRPC 解压结果的统一上限，防止分片拼接或压缩载荷造成内存放大。
    private const int MaximumReassembledMessageBytes = 16 * 1024 * 1024;

    // WebSocket 操作码：延续帧、文本帧、二进制帧；操作码不小于控制帧下限的均为控制帧（ping/pong/close）。
    private const byte WebSocketOpcodeContinuation = 0;
    private const byte WebSocketOpcodeText = 1;
    private const byte WebSocketOpcodeBinary = 2;
    private const byte WebSocketOpcodeControlFloor = 8;

    // gRPC gzip 解压时的分块读取缓冲，配合上限检查逐块拒绝超限载荷。
    private const int GzipReadBufferBytes = 8192;

    public static IReadOnlyList<Http2Frame> ParseHttp2Frames(ReadOnlySpan<byte> input)
    {
        var frames = new List<Http2Frame>();
        var offset = 0;
        while (offset < input.Length)
        {
            if (input.Length - offset < 9) throw new InvalidDataException("HTTP/2 帧头不完整。");
            var length = (input[offset] << 16) | (input[offset + 1] << 8) | input[offset + 2];
            if (length > MaximumFrameBytes) throw new InvalidDataException("HTTP/2 帧超过 16 MB 限制。");
            if (input.Length - offset - 9 < length) throw new InvalidDataException("HTTP/2 帧载荷不完整。");
            var type = input[offset + 3];
            var flags = input[offset + 4];
            var streamId = BinaryPrimitives.ReadInt32BigEndian(input.Slice(offset + 5, 4)) & 0x7fffffff;
            frames.Add(new Http2Frame(length, type, flags, streamId, input.Slice(offset + 9, length).ToArray()));
            offset += 9 + length;
        }
        return frames;
    }

    public static IReadOnlyList<WebSocketFrame> ParseWebSocketFrames(ReadOnlySpan<byte> input)
    {
        var frames = new List<WebSocketFrame>();
        var offset = 0;
        while (offset < input.Length)
        {
            if (input.Length - offset < 2) throw new InvalidDataException("WebSocket 帧头不完整。");
            var first = input[offset++];
            var second = input[offset++];
            var final = (first & 0x80) != 0;
            var reserved = first & 0x70;
            var opcode = (byte)(first & 0x0f);
            var masked = (second & 0x80) != 0;
            ulong length = (uint)(second & 0x7f);
            if (reserved != 0) throw new InvalidDataException("WebSocket RSV 位未获批准扩展使用。");
            if (length == 126)
            {
                if (input.Length - offset < 2) throw new InvalidDataException("WebSocket 扩展长度不完整。");
                length = BinaryPrimitives.ReadUInt16BigEndian(input.Slice(offset, 2));
                offset += 2;
            }
            else if (length == 127)
            {
                if (input.Length - offset < 8) throw new InvalidDataException("WebSocket 扩展长度不完整。");
                length = BinaryPrimitives.ReadUInt64BigEndian(input.Slice(offset, 8));
                offset += 8;
            }
            if (length > MaximumFrameBytes) throw new InvalidDataException("WebSocket 帧超过 16 MB 限制。");
            if (opcode >= 8 && (!final || length > 125)) throw new InvalidDataException("WebSocket 控制帧格式无效。");

            ReadOnlySpan<byte> mask = default;
            if (masked)
            {
                if (input.Length - offset < 4) throw new InvalidDataException("WebSocket 掩码不完整。");
                mask = input.Slice(offset, 4);
                offset += 4;
            }
            if ((ulong)(input.Length - offset) < length) throw new InvalidDataException("WebSocket 帧载荷不完整。");
            var payload = input.Slice(offset, (int)length).ToArray();
            if (masked)
                for (var index = 0; index < payload.Length; index++) payload[index] ^= mask[index % 4];
            frames.Add(new WebSocketFrame(final, opcode, masked, payload));
            offset += (int)length;
        }
        return frames;
    }

    public static IReadOnlyList<ReassembledWebSocketMessage> ReassembleWebSocketMessages(IReadOnlyList<WebSocketFrame> frames)
    {
        var messages = new List<ReassembledWebSocketMessage>();
        MemoryStream? pending = null;
        var pendingIsText = false;
        try
        {
            foreach (var frame in frames)
            {
                if (frame.Opcode >= WebSocketOpcodeControlFloor)
                {
                    // 控制帧允许在分片之间穿插，单独保留且不打断当前数据帧重组。
                    messages.Add(new ReassembledWebSocketMessage(IsText: false, frame.Payload, IsControl: true));
                    continue;
                }

                if (frame.Opcode == WebSocketOpcodeContinuation)
                {
                    if (pending is null) throw new InvalidDataException("WebSocket 延续帧缺少起始数据帧。");
                    AppendWithLimit(pending, frame.Payload);
                    if (frame.Final)
                    {
                        messages.Add(new ReassembledWebSocketMessage(pendingIsText, pending.ToArray(), IsControl: false));
                        pending.Dispose();
                        pending = null;
                    }
                    continue;
                }

                if (frame.Opcode != WebSocketOpcodeText && frame.Opcode != WebSocketOpcodeBinary)
                    throw new InvalidDataException($"不支持的 WebSocket 数据帧操作码：{frame.Opcode}。");
                if (pending is not null) throw new InvalidDataException("WebSocket 分片序列无效：上一条消息未完成即出现新的数据帧。");
                if (frame.Final)
                {
                    messages.Add(new ReassembledWebSocketMessage(frame.Opcode == WebSocketOpcodeText, frame.Payload, IsControl: false));
                    continue;
                }
                pending = new MemoryStream();
                pendingIsText = frame.Opcode == WebSocketOpcodeText;
                AppendWithLimit(pending, frame.Payload);
            }

            if (pending is not null) throw new InvalidDataException("WebSocket 消息未完成：输入以未设 FIN 的数据帧结尾。");
            return messages;
        }
        finally
        {
            pending?.Dispose();
        }
    }

    private static void AppendWithLimit(MemoryStream target, byte[] payload)
    {
        if (target.Length + payload.Length > MaximumReassembledMessageBytes)
            throw new InvalidDataException("WebSocket 重组消息超过 16 MB 限制。");
        target.Write(payload, 0, payload.Length);
    }

    public static IReadOnlyList<ServerSentEvent> ParseServerSentEvents(ReadOnlySpan<byte> input)
    {
        var text = new UTF8Encoding(false, true).GetString(input);
        var events = new List<ServerSentEvent>();
        var data = new List<string>();
        var eventName = "message";
        string? id = null;
        int? retry = null;
        foreach (var line in text.Replace("\r\n", "\n", StringComparison.Ordinal).Replace('\r', '\n').Split('\n'))
        {
            if (line.Length == 0)
            {
                if (data.Count > 0 || eventName != "message" || id is not null)
                    events.Add(new ServerSentEvent(eventName, string.Join("\n", data), id, retry));
                data.Clear();
                eventName = "message";
                id = null;
                retry = null;
                continue;
            }
            if (line[0] == ':') continue;
            var separator = line.IndexOf(':');
            var field = separator < 0 ? line : line[..separator];
            var value = separator < 0 ? string.Empty : line[(separator + 1)..].TrimStart(' ');
            switch (field)
            {
                case "event": eventName = value; break;
                case "data": data.Add(value); break;
                case "id" when !value.Contains('\0'): id = value; break;
                case "retry" when int.TryParse(value, out var parsed) && parsed >= 0: retry = parsed; break;
            }
        }
        if (data.Count > 0 || eventName != "message" || id is not null)
            events.Add(new ServerSentEvent(eventName, string.Join("\n", data), id, retry));
        return events;
    }

    public static IReadOnlyList<GrpcEnvelope> ParseGrpcEnvelopes(ReadOnlySpan<byte> input)
    {
        var envelopes = new List<GrpcEnvelope>();
        var offset = 0;
        while (offset < input.Length)
        {
            if (input.Length - offset < 5) throw new InvalidDataException("gRPC envelope 头不完整。");
            var compressedFlag = input[offset];
            if (compressedFlag > 1) throw new InvalidDataException("gRPC 压缩标志无效。");
            var length = BinaryPrimitives.ReadUInt32BigEndian(input.Slice(offset + 1, 4));
            if (length > MaximumFrameBytes) throw new InvalidDataException("gRPC 消息超过 16 MB 限制。");
            offset += 5;
            if ((uint)(input.Length - offset) < length) throw new InvalidDataException("gRPC 消息载荷不完整。");
            envelopes.Add(new GrpcEnvelope(compressedFlag == 1, input.Slice(offset, (int)length).ToArray()));
            offset += (int)length;
        }
        return envelopes;
    }

    // 仅供证据检查展示调用：对标记压缩的 gRPC 消息体做有界 gzip 解压，不改变既有 envelope 解析。
    public static byte[] DecompressGrpcMessage(GrpcEnvelope envelope)
    {
        if (!envelope.Compressed) return envelope.Message;
        using var output = new MemoryStream();
        try
        {
            using var input = new MemoryStream(envelope.Message);
            using var gzip = new GZipStream(input, CompressionMode.Decompress);
            var buffer = new byte[GzipReadBufferBytes];
            int read;
            while ((read = gzip.Read(buffer, 0, buffer.Length)) > 0)
            {
                output.Write(buffer, 0, read);
                if (output.Length > MaximumReassembledMessageBytes)
                    throw new InvalidDataException("gRPC 解压消息超过 16 MB 限制。");
            }
        }
        catch (InvalidDataException exception) when (exception.Message.StartsWith("gRPC", StringComparison.Ordinal) is false)
        {
            throw new InvalidDataException("gRPC gzip 载荷解压失败。");
        }
        return output.ToArray();
    }

    /// <summary>
    /// 按 Content-Encoding 解压 HTTP 正文（gzip/deflate/br，可逗号组合）供分析与展示；
    /// 编码未知、正文为空或解压失败/超限时原样返回，绝不影响原始字节回写。
    /// </summary>
    public static byte[] DecompressHttpBody(string? contentEncoding, byte[] body)
    {
        if (body.Length == 0 || string.IsNullOrWhiteSpace(contentEncoding)) return body;
        var codings = contentEncoding.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (codings.Length == 0) return body;
        try
        {
            var current = body;
            // Content-Encoding 按应用顺序列出，解压需反向进行（先解最后一次压缩）。
            for (var index = codings.Length - 1; index >= 0; index--)
            {
                var coding = codings[index].ToLowerInvariant();
                // .NET 解压流容错强（不校验 gzip 魔数）：先预检魔数，避免把非压缩字节误解成乱码文本。
                if ((coding == "gzip" || coding == "x-gzip") && (current.Length < 2 || current[0] != 0x1F || current[1] != 0x8B))
                    throw new InvalidDataException("正文缺少 gzip 魔数。");
                using var output = new MemoryStream();
                using (var input = new MemoryStream(current, false))
                {
                    Stream stream = coding switch
                    {
                        "gzip" or "x-gzip" => new GZipStream(input, CompressionMode.Decompress),
                        "deflate" => new DeflateStream(input, CompressionMode.Decompress),
                        "br" => new BrotliStream(input, CompressionMode.Decompress),
                        "identity" => input,
                        _ => throw new InvalidDataException("未知压缩编码：" + codings[index])
                    };
                    var buffer = new byte[GzipReadBufferBytes];
                    int read;
                    while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        output.Write(buffer, 0, read);
                        if (output.Length > NetMindDefaults.MaximumDecompressedBodyBytes)
                            throw new InvalidDataException("解压正文超过上限。");
                    }
                }
                current = output.ToArray();
            }
            return current;
        }
        catch (Exception exception) when (exception is InvalidDataException or IOException or NotSupportedException)
        {
            // 解压失败保留原始压缩字节：展示层依旧能看到原始证据，不阻塞结算。
            return body;
        }
    }

    public static DnsMessage ParseDnsMessage(ReadOnlySpan<byte> input)
    {
        if (input.Length < 12) throw new InvalidDataException("DNS 消息头不完整。");
        var id = BinaryPrimitives.ReadUInt16BigEndian(input);
        var flags = BinaryPrimitives.ReadUInt16BigEndian(input.Slice(2, 2));
        var questionCount = BinaryPrimitives.ReadUInt16BigEndian(input.Slice(4, 2));
        if (questionCount > 256) throw new InvalidDataException("DNS 问题数量超过限制。");
        var offset = 12;
        var questions = new List<DnsQuestion>(questionCount);
        for (var index = 0; index < questionCount; index++)
        {
            var name = ReadDnsName(input, ref offset);
            if (input.Length - offset < 4) throw new InvalidDataException("DNS 问题字段不完整。");
            var type = BinaryPrimitives.ReadUInt16BigEndian(input.Slice(offset, 2));
            var @class = BinaryPrimitives.ReadUInt16BigEndian(input.Slice(offset + 2, 2));
            offset += 4;
            questions.Add(new DnsQuestion(name, type, @class));
        }
        return new DnsMessage(id, (flags & 0x8000) != 0, (ushort)(flags & 0x000f), questions);
    }

    public static IReadOnlyList<ProtobufField> ParseProtobufFields(ReadOnlySpan<byte> input)
    {
        var fields = new List<ProtobufField>();
        var offset = 0;
        while (offset < input.Length)
        {
            var key = ReadVarint(input, ref offset);
            var number = (int)(key >> 3);
            var wireType = (int)(key & 0x07);
            if (number <= 0) throw new InvalidDataException("Protobuf 字段编号无效。");
            switch (wireType)
            {
                case 0:
                    fields.Add(new ProtobufField(number, wireType, ReadVarint(input, ref offset), []));
                    break;
                case 1:
                    EnsureRemaining(input, offset, 8, "Protobuf 64 位字段不完整。");
                    fields.Add(new ProtobufField(number, wireType, BinaryPrimitives.ReadUInt64LittleEndian(input.Slice(offset, 8)), input.Slice(offset, 8).ToArray()));
                    offset += 8;
                    break;
                case 2:
                    var length = ReadVarint(input, ref offset);
                    if (length > MaximumFrameBytes || length > int.MaxValue) throw new InvalidDataException("Protobuf 长度字段超过限制。");
                    EnsureRemaining(input, offset, (int)length, "Protobuf 长度字段不完整。");
                    fields.Add(new ProtobufField(number, wireType, null, input.Slice(offset, (int)length).ToArray()));
                    offset += (int)length;
                    break;
                case 5:
                    EnsureRemaining(input, offset, 4, "Protobuf 32 位字段不完整。");
                    fields.Add(new ProtobufField(number, wireType, BinaryPrimitives.ReadUInt32LittleEndian(input.Slice(offset, 4)), input.Slice(offset, 4).ToArray()));
                    offset += 4;
                    break;
                default:
                    throw new InvalidDataException($"不支持的 Protobuf wire type：{wireType}。");
            }
        }
        return fields;
    }

    private static string ReadDnsName(ReadOnlySpan<byte> input, ref int offset)
    {
        var labels = new List<string>();
        var cursor = offset;
        var jumped = false;
        var jumps = 0;
        while (true)
        {
            if (cursor >= input.Length) throw new InvalidDataException("DNS 名称超出消息边界。");
            var length = input[cursor++];
            if (length == 0)
            {
                if (!jumped) offset = cursor;
                break;
            }
            if ((length & 0xc0) == 0xc0)
            {
                if (cursor >= input.Length) throw new InvalidDataException("DNS 压缩指针不完整。");
                var pointer = ((length & 0x3f) << 8) | input[cursor++];
                if (pointer >= input.Length || ++jumps > 16) throw new InvalidDataException("DNS 压缩指针无效或形成循环。");
                if (!jumped) offset = cursor;
                cursor = pointer;
                jumped = true;
                continue;
            }
            if ((length & 0xc0) != 0 || length > 63 || input.Length - cursor < length)
                throw new InvalidDataException("DNS 标签格式无效。");
            labels.Add(Encoding.ASCII.GetString(input.Slice(cursor, length)));
            cursor += length;
            if (!jumped) offset = cursor;
        }
        return string.Join('.', labels);
    }

    private static ulong ReadVarint(ReadOnlySpan<byte> input, ref int offset)
    {
        ulong value = 0;
        for (var shift = 0; shift < 70; shift += 7)
        {
            if (offset >= input.Length) throw new InvalidDataException("Protobuf varint 不完整。");
            var current = input[offset++];
            if (shift == 63 && current > 1) throw new InvalidDataException("Protobuf varint 溢出。");
            value |= (ulong)(current & 0x7f) << shift;
            if ((current & 0x80) == 0) return value;
        }
        throw new InvalidDataException("Protobuf varint 超过 10 字节。");
    }

    private static void EnsureRemaining(ReadOnlySpan<byte> input, int offset, int required, string message)
    {
        if (required < 0 || input.Length - offset < required) throw new InvalidDataException(message);
    }
}
