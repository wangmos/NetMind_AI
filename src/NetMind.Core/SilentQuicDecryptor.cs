using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace NetMind.Core;

/// <summary>QUIC STREAM 帧重组出的一段新连续数据（M4 的 HTTP/3 解码输入）。</summary>
public sealed record SilentQuicStreamData(bool ClientDirection, long StreamId, byte[] Data, bool Fin);

/// <summary>
/// QUIC v1/v2 连接解码器（RFC 9000/9001）：
/// Initial 包用 RFC 9001 §5.2 由 DCID 派生的固定密钥解密，提取 ClientHello（SNI/ALPN）；
/// 1-RTT 短包头用 SSLKEYLOGFILE 的流量机密按 "quic key/iv/hp" 标签派生密钥解密（AES-128-GCM），
/// 重组 STREAM 帧供 HTTP/3 使用。无法解密（缺密钥/中途捕获未知 CID 长度）时安静跳过，绝不抛出。
/// </summary>
public sealed class SilentQuicConnection
{
    private const uint Version1 = 0x00000001;
    private const uint Version2 = 0x6b3343cf;

    // RFC 9001 §5.2 / RFC 9369 §3.3.1 初始盐
    private static readonly byte[] SaltV1 = Convert.FromHexString("38762cf7f55934b34d179ae6a4c80cadccbb7f0a");
    private static readonly byte[] SaltV2 = Convert.FromHexString("0dede3def700a6db81bd0c272266e958");

    private sealed class KeyPhase
    {
        public byte[] Key = [];
        public byte[] Iv = [];
        public byte[] Hp = [];
        public ulong LargestPacketNumber; // RFC 9000 A.3 完整序号还原参照
        public bool Ready => Key.Length > 0;
    }

    private sealed class DirectionKeys
    {
        public readonly KeyPhase Initial = new();
        public readonly KeyPhase Application = new();
    }

    /// <summary>CRYPTO/STREAM 通用偏移重组器：单流单方向，乱序超限即弃。</summary>
    private sealed class OffsetReassembler
    {
        private readonly List<(long Offset, byte[] Data)> _pending = [];
        private long _expected;
        private int _buffered;

        public bool Broken { get; private set; }
        public bool FinSeen { get; private set; }

        public void MarkFin() => FinSeen = true;

        /// <summary>喂入一段带偏移的数据，返回新产生的连续字节（可能为空）。</summary>
        public byte[] Append(long offset, ReadOnlySpan<byte> data)
        {
            if (Broken || data.IsEmpty) return [];
            var end = offset + data.Length;
            if (end <= _expected) return []; // 完全重传
            if (offset < _expected)
            {
                var skip = (int)(_expected - offset);
                _expected = end;
                return data[skip..].ToArray();
            }
            if (offset == _expected)
            {
                _expected = end;
                return data.ToArray();
            }
            _buffered += data.Length;
            if (_buffered > NetMindDefaults.SilentMaximumReassemblyBufferBytes) { Broken = true; _pending.Clear(); return []; }
            var copy = data.ToArray();
            var index = _pending.FindIndex(item => item.Offset >= offset);
            _pending.Insert(index < 0 ? _pending.Count : index, (offset, copy));
            return Drain();
        }

        private byte[] Drain()
        {
            using var output = new MemoryStream();
            while (_pending.Count > 0 && _pending[0].Offset <= _expected)
            {
                var (offset, data) = _pending[0];
                _pending.RemoveAt(0);
                _buffered -= data.Length;
                var end = offset + data.Length;
                if (end <= _expected) continue;
                var skip = (int)Math.Max(0, _expected - offset);
                output.Write(data, skip, data.Length - skip);
                _expected = end;
            }
            return output.Length == 0 ? [] : output.ToArray();
        }
    }

    private sealed class StreamState
    {
        public readonly OffsetReassembler Data = new();
    }

    private readonly SilentTlsKeyLog? _keyLog;
    private readonly DirectionKeys _clientKeys = new();
    private readonly DirectionKeys _serverKeys = new();
    private readonly OffsetReassembler _clientCrypto = new();
    private readonly OffsetReassembler _serverCrypto = new();
    private readonly Dictionary<long, StreamState> _clientStreams = new();
    private readonly Dictionary<long, StreamState> _serverStreams = new();

    private readonly MemoryStream _clientCryptoBuffer = new();
    private string? _clientRandomKey;
    private bool _clientHelloParsed;

    private int _serverCidLength = -1; // 服务端 CID 长度：客户端 Initial 的 DCID 给出
    private int _clientCidLength = -1; // 客户端 CID 长度：服务端首个长包头 SCID 给出
    private uint _version;

    public SilentQuicConnection(SilentTlsKeyLog? keyLog) => _keyLog = keyLog;

    /// <summary>从 ClientHello 提取的 SNI 主机名。</summary>
    public string? Sni { get; private set; }

    /// <summary>协商的 ALPN（http/3 时进入 M4 解码）。</summary>
    public string? Alpn { get; private set; }

    /// <summary>版本不支持或解析彻底失败：调用方只记隧道。</summary>
    public bool Broken { get; private set; }

    /// <summary>喂入一个 UDP 报文；返回本次新重组出的 STREAM 数据（供 HTTP/3 解码）。</summary>
    public List<SilentQuicStreamData> Feed(bool clientDirection, ReadOnlySpan<byte> datagram)
    {
        var streams = new List<SilentQuicStreamData>();
        if (Broken || datagram.IsEmpty) return streams;
        try
        {
            var offset = 0;
            while (offset < datagram.Length)
            {
                var rest = datagram[offset..];
                if (rest.Length < 5) break;
                if ((rest[0] & 0x80) != 0)
                {
                    if (!ProcessLongHeader(clientDirection, rest, out var consumed, streams)) break;
                    offset += consumed;
                }
                else
                {
                    if (!ProcessShortHeader(clientDirection, rest, streams)) break;
                    offset = datagram.Length; // 短包头合并包无法可靠定界，一次一个
                }
            }
        }
        catch (Exception exception) when (exception is CryptographicException or InvalidDataException or IndexOutOfRangeException or ArgumentOutOfRangeException or ArgumentNullException or ArgumentException)
        {
            Broken = true;
        }
        return streams;
    }

    // ── 长包头（Initial/Handshake/0-RTT）──────────────────────────

    private bool ProcessLongHeader(bool clientDirection, ReadOnlySpan<byte> packet, out int consumed, List<SilentQuicStreamData> streams)
    {
        consumed = 0;
        var version = BinaryPrimitives.ReadUInt32BigEndian(packet[1..]);
        if (_version == 0)
        {
            if (version != Version1 && version != Version2) { Broken = true; return false; }
            _version = version;
        }
        else if (version != _version) return false;
        var offset = 5;
        if (offset >= packet.Length) return false;
        var dcidLength = packet[offset]; offset += 1;
        if (dcidLength > 20 || offset + dcidLength > packet.Length) return false;
        var dcid = packet.Slice(offset, dcidLength); offset += dcidLength;
        if (offset >= packet.Length) return false;
        var scidLength = packet[offset]; offset += 1;
        if (scidLength > 20 || offset + scidLength > packet.Length) return false;
        offset += scidLength;

        var packetType = (packet[0] >> 4) & 0x3;
        if (clientDirection)
        {
            // 客户端 Initial 的 DCID 是服务端 CID 的兜底估计；SCID 即客户端自己的 CID
            if (_serverCidLength < 0) _serverCidLength = dcidLength;
            if (packetType == 0 && _clientCidLength < 0) _clientCidLength = scidLength;
            if (packetType == 0 && !_clientKeys.Initial.Ready) SetupInitialKeys(dcid);
        }
        else
        {
            // 服务端长包头的 SCID 是权威值：客户端 1-RTT 包以它为 DCID
            _serverCidLength = scidLength;
            if (_clientCidLength < 0) _clientCidLength = dcidLength;
        }

        if (packetType == 0)
        {
            // 注意：不能写 offset += ReadVarint(ref offset)，复合赋值会先读旧值再调用，
            // 抵消 ReadVarint 内部的推进；必须分两步
            var tokenLength = (int)ReadVarint(packet, ref offset);
            if (tokenLength < 0 || offset + tokenLength > packet.Length) return false;
            offset += tokenLength;
        }
        var payloadLength = (int)ReadVarint(packet, ref offset);
        if (payloadLength < 0 || offset + payloadLength > packet.Length) return false;
        consumed = offset + payloadLength;

        var keys = clientDirection ? _clientKeys : _serverKeys;
        var pnOffset = offset;
        // 解密：优先 Initial 密钥（握手初期），失败回退应用密钥（握手后期 ACK 混发）
        if (keys.Initial.Ready && TryDecryptPacket(packet, pnOffset, keys.Initial, out var frames1))
            return ProcessFrames(clientDirection, frames1, streams);
        if (keys.Application.Ready && TryDecryptPacket(packet, pnOffset, keys.Application, out var frames2))
            return ProcessFrames(clientDirection, frames2, streams);
        return true; // 无密钥：安静跳过该包
    }

    private void SetupInitialKeys(ReadOnlySpan<byte> dcid)
    {
        var salt = _version == Version2 ? SaltV2 : SaltV1;
        var initialSecret = HKDF.Extract(HashAlgorithmName.SHA256, ikm: dcid.ToArray(), salt: salt);
        SetupDirectionKeys(_clientKeys.Initial, HKDF.Expand(HashAlgorithmName.SHA256, initialSecret, 32, "client in"u8.ToArray()));
        SetupDirectionKeys(_serverKeys.Initial, HKDF.Expand(HashAlgorithmName.SHA256, initialSecret, 32, "server in"u8.ToArray()));
    }

    private void SetupDirectionKeys(KeyPhase phase, byte[] secret)
    {
        phase.Key = SilentTlsSession.HkdfExpandLabel(secret, "quic key", 16, HashAlgorithmName.SHA256);
        phase.Iv = SilentTlsSession.HkdfExpandLabel(secret, "quic iv", 12, HashAlgorithmName.SHA256);
        phase.Hp = SilentTlsSession.HkdfExpandLabel(secret, "quic hp", 16, HashAlgorithmName.SHA256);
    }

    /// <summary>命中密钥日志时建立 1-RTT 应用密钥（标签 quic key/iv/hp，AES-128-GCM 套件）。</summary>
    private void EnsureApplicationKeys()
    {
        if (_keyLog is null || _clientKeys.Application.Ready || _clientRandomKey is null) return;
        _keyLog.Refresh();
        var entry = _keyLog.Find(_clientRandomKey);
        if (entry?.ClientTrafficSecret is null || entry.ServerTrafficSecret is null) return;
        SetupDirectionKeys(_clientKeys.Application, Convert.FromHexString(entry.ClientTrafficSecret));
        SetupDirectionKeys(_serverKeys.Application, Convert.FromHexString(entry.ServerTrafficSecret));
    }

    // ── 短包头（1-RTT）────────────────────────────────────────────

    private bool ProcessShortHeader(bool clientDirection, ReadOnlySpan<byte> packet, List<SilentQuicStreamData> streams)
    {
        var cidLength = clientDirection ? _serverCidLength : _clientCidLength;
        if (cidLength < 0) return false; // 中途捕获：未知对端 CID 长度，无法定界包头
        var keys = clientDirection ? _clientKeys : _serverKeys;
        EnsureApplicationKeys();
        if (!keys.Application.Ready) return false;
        var pnOffset = 1 + cidLength;
        if (packet.Length < pnOffset + 4 + 16) return false;
        if (!TryDecryptPacket(packet, pnOffset, keys.Application, out var frames)) return false;
        return ProcessFrames(clientDirection, frames, streams);
    }

    // ── 解密公共路径：解除头部保护 → 还原序号 → AEAD ──────────────

    private bool TryDecryptPacket(ReadOnlySpan<byte> packet, int pnOffset, KeyPhase phase, out ReadOnlySpan<byte> frames)
    {
        frames = default;
        if (!phase.Ready || packet.Length < pnOffset + 4 + 16) return false; // 采样需 pn 偏移后 16 字节
        var header = packet[..pnOffset].ToArray();
        var sample = packet.Slice(pnOffset + 4, 16).ToArray();
        var mask = new byte[16];
        using (var ecb = Aes.Create())
        {
            ecb.Mode = CipherMode.ECB;
            ecb.Padding = PaddingMode.None;
            // ECB 模式 IV 必须传 null：空数组会触发 ArgumentNullException
            using var encryptor = ecb.CreateEncryptor(phase.Hp, null);
            encryptor.TransformBlock(sample, 0, 16, mask, 0);
        }
        header[0] = (byte)(header[0] ^ (mask[0] & ((packet[0] & 0x80) != 0 ? 0x0f : 0x1f)));
        var pnLength = (header[0] & 0x03) + 1;
        if (packet.Length < pnOffset + pnLength + 16) return false;
        for (var i = 0; i < pnLength; i++) header = AppendPnByte(header, (byte)(packet[pnOffset + i] ^ mask[1 + i]));
        var truncated = 0L;
        for (var i = 0; i < pnLength; i++) truncated = (truncated << 8) | header[pnOffset + i];
        var packetNumber = ExpandPacketNumber(phase.LargestPacketNumber, truncated, pnLength);

        var nonce = (byte[])phase.Iv.Clone();
        var pnBytes = new byte[12];
        BinaryPrimitives.WriteUInt64BigEndian(pnBytes.AsSpan(4), (ulong)packetNumber);
        for (var i = 0; i < 12; i++) nonce[i] ^= pnBytes[i];
        var ciphertext = packet[(pnOffset + pnLength)..];
        var tag = ciphertext[^16..];
        var body = ciphertext[..^16];
        var plain = new byte[body.Length];
        try
        {
            using var gcm = new AesGcm(phase.Key, 16);
            gcm.Decrypt(nonce, body, tag, plain, header);
        }
        catch (CryptographicException) { return false; }
        if (packetNumber > (long)phase.LargestPacketNumber) phase.LargestPacketNumber = (ulong)packetNumber;
        frames = plain;
        return true;
    }

    private static byte[] AppendPnByte(byte[] header, byte value)
    {
        var grown = new byte[header.Length + 1];
        header.CopyTo(grown, 0);
        grown[^1] = value;
        return grown;
    }

    /// <summary>RFC 9000 附录 A.3：按已知最大序号还原截断序号的完整值。</summary>
    private static long ExpandPacketNumber(ulong largest, long truncated, int pnLength)
    {
        var expected = (long)largest + 1;
        var window = 1L << (pnLength * 8);
        var half = window / 2;
        var candidate = (expected & ~(window - 1)) | truncated;
        if (candidate <= expected - half && candidate + window < (1L << 62)) return candidate + window;
        if (candidate > expected + half && candidate >= window) return candidate - window;
        return candidate;
    }

    // ── 帧解析 ────────────────────────────────────────────────

    private bool ProcessFrames(bool clientDirection, ReadOnlySpan<byte> frames, List<SilentQuicStreamData> streams)
    {
        var offset = 0;
        while (offset < frames.Length)
        {
            var type = frames[offset];
            switch (type)
            {
                case 0x00: offset += 1; break;                                        // PADDING
                case 0x01: offset += 1; break;                                        // PING
                case 0x02: case 0x03: SkipAck(frames, ref offset); break;             // ACK / ACK_ECN
                case 0x06:                                                            // CRYPTO
                {
                    offset += 1;
                    var frameOffset = (long)ReadVarint(frames, ref offset);
                    var length = (int)ReadVarint(frames, ref offset);
                    if (length < 0 || offset + length > frames.Length) return false;
                    var chunk = frames.Slice(offset, length);
                    offset += length;
                    var reassembler = clientDirection ? _clientCrypto : _serverCrypto;
                    var fresh = reassembler.Append(frameOffset, chunk);
                    if (clientDirection && fresh.Length > 0) OnClientCrypto(fresh);
                    break;
                }
                case 0x07:                                                            // NEW_TOKEN
                {
                    offset += 1;
                    var tokenLength = (int)ReadVarint(frames, ref offset);
                    if (tokenLength < 0 || offset + tokenLength > frames.Length) return false;
                    offset += tokenLength;
                    break;
                }
                case 0x08: case 0x09: case 0x0A: case 0x0B:
                case 0x0C: case 0x0D: case 0x0E: case 0x0F:                           // STREAM
                {
                    offset += 1;
                    var streamId = (long)ReadVarint(frames, ref offset);
                    var streamOffset = (type & 0x04) != 0 ? (long)ReadVarint(frames, ref offset) : 0L;
                    var fin = (type & 0x01) != 0;
                    int length;
                    if ((type & 0x02) != 0) length = (int)ReadVarint(frames, ref offset);
                    else length = frames.Length - offset;
                    if (length < 0 || offset + length > frames.Length) return false;
                    var chunk = frames.Slice(offset, length);
                    offset += length;
                    // 单向流（0x2/0x3 位标识的服务端推送流）同样重组，交由上层识别
                    var table = clientDirection ? _clientStreams : _serverStreams;
                    if (!table.TryGetValue(streamId, out var stream)) { stream = new StreamState(); table[streamId] = stream; }
                    if (fin) stream.Data.MarkFin();
                    var fresh = stream.Data.Append(streamOffset, chunk);
                    if (fresh.Length > 0 || (fin && stream.Data.FinSeen))
                        streams.Add(new SilentQuicStreamData(clientDirection, streamId, fresh, fin));
                    break;
                }
                case 0x04: offset += 1 + VarintSize(frames, ref offset); break;       // MAX_DATA
                case 0x05: offset += 1 + VarintSize(frames, ref offset) + VarintSize(frames, ref offset); break; // MAX_STREAM_DATA
                case 0x12: case 0x13: offset += 1 + VarintSize(frames, ref offset); break; // MAX_STREAMS
                case 0x10: offset += 1 + VarintSize(frames, ref offset); break;       // STREAMS_BLOCKED
                case 0x14: case 0x15:                                                 // NEW_CONNECTION_ID
                    offset += 1 + VarintSize(frames, ref offset) + VarintSize(frames, ref offset) + 32;
                    break;
                case 0x16: case 0x17: offset += 1 + VarintSize(frames, ref offset); break; // RETIRE_CONNECTION_ID
                case 0x18: case 0x19: offset += 1 + 8; break;                         // PATH_CHALLENGE / PATH_RESPONSE
                case 0x1C:                                                            // CONNECTION_CLOSE（传输层）
                {
                    offset += 1;
                    ReadVarint(frames, ref offset);                                   // 错误码
                    ReadVarint(frames, ref offset);                                   // 触发帧类型
                    var reasonLength = (int)ReadVarint(frames, ref offset);
                    if (reasonLength < 0 || offset + reasonLength > frames.Length) return false;
                    offset += reasonLength;
                    break;
                }
                case 0x1D:                                                            // CONNECTION_CLOSE（应用层）
                {
                    offset += 1;
                    ReadVarint(frames, ref offset);                                   // 错误码
                    var reasonLength = (int)ReadVarint(frames, ref offset);
                    if (reasonLength < 0 || offset + reasonLength > frames.Length) return false;
                    offset += reasonLength;
                    break;
                }
                case 0x1E: offset += 1; break;                                        // HANDSHAKE_DONE
                default: return true; // 未知帧：放弃本包剩余帧（不判连接损坏）
            }
            if (offset < 0 || offset > frames.Length) return false;
        }
        return true;
    }

    private void OnClientCrypto(byte[] fresh)
    {
        if (_clientHelloParsed) return;
        _clientCryptoBuffer.Write(fresh);
        var accumulated = _clientCryptoBuffer.GetBuffer().AsSpan(0, (int)_clientCryptoBuffer.Length);
        // CRYPTO 流首部：握手消息类型 1（ClientHello）+ 24 位长度；未收全时等待后续分块
        if (accumulated.Length < 4 || accumulated[0] != 0x01) return;
        var messageLength = (accumulated[1] << 16) | (accumulated[2] << 8) | accumulated[3];
        if (accumulated.Length < 4 + messageLength) return;
        var body = accumulated[..(4 + messageLength)].ToArray();
        if (!SilentTlsSession.TryParseClientHello(body, out var random, out var alpn)) return;
        _clientHelloParsed = true;
        _clientRandomKey = Convert.ToHexString(random).ToLowerInvariant();
        if (alpn is not null) Alpn = alpn;
        Sni = TryParseSniFromClientHello(body);
        EnsureApplicationKeys();
    }

    private static string? TryParseSniFromClientHello(byte[] body)
    {
        // body 为握手消息（含 4 字节头）；SilentPacketParser 需要 TLS 记录形态，故此处直接遍历扩展
        var helloLength = (body[1] << 16) | (body[2] << 8) | body[3];
        var hello = body.AsSpan(4, Math.Min(helloLength, body.Length - 4));
        if (hello.Length < 35) return null;
        var offset = 34;
        offset += 1 + hello[offset];                                   // 会话 ID
        if (offset + 2 > hello.Length) return null;
        offset += 2 + BinaryPrimitives.ReadUInt16BigEndian(hello[offset..]); // 密码套件
        if (offset + 1 > hello.Length) return null;
        offset += 1 + hello[offset];                                   // 压缩方法
        if (offset + 2 > hello.Length) return null;
        var extensionsLength = BinaryPrimitives.ReadUInt16BigEndian(hello[offset..]);
        offset += 2;
        var end = offset + Math.Min(extensionsLength, hello.Length - offset);
        while (offset + 4 <= end)
        {
            var type = BinaryPrimitives.ReadUInt16BigEndian(hello[offset..]);
            var length = BinaryPrimitives.ReadUInt16BigEndian(hello[(offset + 2)..]);
            offset += 4;
            if (offset + length > hello.Length) break;
            if (type == 0 && length > 5)
            {
                var list = hello.Slice(offset, length);
                if (list[2] == 0)
                {
                    var nameLength = BinaryPrimitives.ReadUInt16BigEndian(list[3..]);
                    if (nameLength > 0 && 5 + nameLength <= list.Length)
                        return Encoding.ASCII.GetString(list.Slice(5, nameLength));
                }
            }
            offset += length;
        }
        return null;
    }

    // ── varint 与跳帧辅助 ────────────────────────────────────────

    private static long ReadVarint(ReadOnlySpan<byte> buffer, ref int offset)
    {
        if (offset >= buffer.Length) throw new InvalidDataException("varint 截断");
        var first = buffer[offset++];
        var length = 1 << (first >> 6);
        var value = (long)(first & 0x3f);
        if (offset + length - 1 > buffer.Length) throw new InvalidDataException("varint 截断");
        for (var i = 1; i < length; i++) value = (value << 8) | buffer[offset++];
        return value;
    }

    /// <summary>读取并丢弃一个 varint，返回其编码字节数。</summary>
    private static int VarintSize(ReadOnlySpan<byte> buffer, ref int offset)
    {
        var before = offset;
        ReadVarint(buffer, ref offset);
        return offset - before;
    }

    private static void SkipAck(ReadOnlySpan<byte> frames, ref int offset)
    {
        offset += 1;
        ReadVarint(frames, ref offset);                                // 最大确认包号
        ReadVarint(frames, ref offset);                                // ACK 延迟
        var rangeCount = (int)ReadVarint(frames, ref offset);
        ReadVarint(frames, ref offset);                                // 首个 ACK 块长
        for (var i = 0; i < rangeCount; i++)
        {
            ReadVarint(frames, ref offset);                            // 间隔
            ReadVarint(frames, ref offset);                            // 块长
        }
    }
}
