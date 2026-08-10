using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace NetMind.Core;

/// <summary>
/// 浏览器 SSLKEYLOGFILE（NSS Key Log 格式）中的一条密钥材料：
/// 以 ClientHello 随机数为键，TLS 1.2 为主密钥，TLS 1.3 为各方向流量密钥。
/// </summary>
public sealed class SilentTlsKeyLogEntry
{
    public string? MasterSecret;
    public string? ClientHandshakeSecret;
    public string? ServerHandshakeSecret;
    public string? ClientTrafficSecret;
    public string? ServerTrafficSecret;

    /// <summary>具备解密 TLS 1.3 应用数据的最小条件。</summary>
    public bool HasTls13 => ClientTrafficSecret is not null && ServerTrafficSecret is not null;
}

/// <summary>
/// 增量解析工作区中的 sslkeylog 文本文件：浏览器边连接边追加，采集后台按偏移续读，
/// 按 ClientHello 随机数索引密钥。行格式错误静默跳过，绝不抛出。
/// </summary>
public sealed class SilentTlsKeyLog
{
    private readonly string _path;
    private readonly Dictionary<string, SilentTlsKeyLogEntry> _entries = new(StringComparer.OrdinalIgnoreCase);
    private long _offset;

    public SilentTlsKeyLog(string path) => _path = path;

    public int Count => _entries.Count;

    public SilentTlsKeyLogEntry? Find(string clientRandomHex) =>
        _entries.TryGetValue(clientRandomHex, out var entry) ? entry : null;

    /// <summary>续读文件新增内容并解析；文件不存在或被占用时安静返回。</summary>
    public void Refresh()
    {
        try
        {
            if (!File.Exists(_path)) return;
            using var stream = new FileStream(_path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            if (stream.Length < _offset) _offset = 0; // 文件被重建（新会话）则从头读
            if (stream.Length == _offset) return;
            stream.Seek(_offset, SeekOrigin.Begin);
            var remaining = (int)(stream.Length - _offset);
            var bytes = new byte[remaining];
            var read = stream.Read(bytes, 0, remaining);
            // 密钥日志行为纯 ASCII；只消费到最后一个完整行，残行留给下次读取
            var text = Encoding.ASCII.GetString(bytes, 0, read);
            var lastNewline = text.LastIndexOf('\n');
            if (lastNewline < 0) return;
            foreach (var line in text[..(lastNewline + 1)].Split('\n', StringSplitOptions.RemoveEmptyEntries))
                ParseLine(line.TrimEnd('\r'));
            _offset += lastNewline + 1;
        }
        catch { /* 密钥日志不可读只影响解密可见性，不中断抓包 */ }
    }

    private void ParseLine(string line)
    {
        var parts = line.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length != 3 || parts[1].Length != 64) return;
        if (!_entries.TryGetValue(parts[1], out var entry))
        {
            entry = new SilentTlsKeyLogEntry();
            _entries[parts[1]] = entry;
        }
        switch (parts[0])
        {
            case "CLIENT_RANDOM": entry.MasterSecret = parts[2]; break;
            case "CLIENT_HANDSHAKE_TRAFFIC_SECRET": entry.ClientHandshakeSecret = parts[2]; break;
            case "SERVER_HANDSHAKE_TRAFFIC_SECRET": entry.ServerHandshakeSecret = parts[2]; break;
            case "CLIENT_TRAFFIC_SECRET_0": entry.ClientTrafficSecret = parts[2]; break;
            case "SERVER_TRAFFIC_SECRET_0": entry.ServerTrafficSecret = parts[2]; break;
        }
    }
}

/// <summary>TLS 记录层使用的 AEAD 算法（与密码套件一一对应，仅支持主流 AEAD 套件）。</summary>
public enum SilentTlsAead { Aes128Gcm, Aes256Gcm, ChaCha20Poly1305 }

/// <summary>单方向解密上下文：记录缓冲、序号、握手/应用两套 AEAD 密钥与阶段标志。</summary>
internal sealed class SilentTlsDirection
{
    public readonly MemoryStream Buffer = new();
    public ulong Sequence;
    public SilentTlsAead Aead;
    public byte[] HandshakeKey = [];
    public byte[] HandshakeIv = [];
    public byte[] ApplicationKey = [];
    public byte[] ApplicationIv = [];
    public bool HandshakeReady;   // 握手密钥已就位（TLS 1.3）
    public bool ApplicationReady; // 应用密钥已就位
    public bool CcsSeen;          // TLS 1.2：已见 ChangeCipherSpec
}

/// <summary>
/// 单条 TLS 连接的记录层解密器：解析 ClientHello/ServerHello 定位版本与套件，
/// 用 SSLKEYLOGFILE 密钥解密 TLS 1.3 握手与应用记录、TLS 1.2 GCM/ChaCha20 应用记录，
/// 输出解密后的应用字节与协商出的 ALPN。无法解密（缺密钥/不支持套件）时保持隧道模式，绝不抛出。
/// </summary>
public sealed class SilentTlsSession
{
    private readonly SilentTlsDirection _client = new();
    private readonly SilentTlsDirection _server = new();
    private readonly SilentTlsKeyLog _keyLog;

    private bool _clientHelloDone;
    private byte[] _clientRandom = [];
    private byte[] _serverRandom = [];
    private SilentTlsKeyLogEntry? _keys;
    private bool _serverHelloDone;
    private bool _isTls13;
    private int _suite = -1;
    private bool _broken;

    /// <summary>解密彻底不可用（解析失败或套件不支持）：调用方退回隧道模式。</summary>
    public bool Broken => _broken;

    /// <summary>协商出的 ALPN（http/1.1、h2…）；未知时为 null。</summary>
    public string? Alpn { get; private set; }

    /// <summary>密钥日志中命中了对应 ClientHello 的材料（解密前提）。</summary>
    public bool HasKeys => _keys is not null && (_keys.HasTls13 || _keys.MasterSecret is not null);

    public SilentTlsSession(SilentTlsKeyLog keyLog) => _keyLog = keyLog;

    /// <summary>喂入客户端方向字节，返回解密得到的应用数据（无则为空）。</summary>
    public byte[] FeedClient(byte[] data) => _broken || data.Length == 0 ? [] : Feed(_client, data, isClient: true);

    /// <summary>喂入服务端方向字节，返回解密得到的应用数据（无则为空）。</summary>
    public byte[] FeedServer(byte[] data) => _broken || data.Length == 0 ? [] : Feed(_server, data, isClient: false);

    private byte[] Feed(SilentTlsDirection direction, byte[] data, bool isClient)
    {
        try
        {
            direction.Buffer.Write(data, 0, data.Length);
            return isClient ? PumpClient() : PumpServer();
        }
        catch { _broken = true; return []; }
    }

    // ── 双向泵：单遍读取记录，先定位 Hello，再对同一批记录续走解密 ──

    private byte[] PumpClient()
    {
        var records = TakeRecordsFull(_client);
        var index = 0;
        if (!_clientHelloDone)
        {
            for (; index < records.Count; index++)
            {
                var (type, _, body) = records[index];
                if (type != 22) continue;
                if (!TryParseClientHello(body, out var random, out var alpn)) { _broken = true; return []; }
                _clientRandom = random;
                if (alpn is not null) Alpn = alpn; // 服务端选择优先，此处仅先行占位
                _clientHelloDone = true;
                EnsureKeys();
                index++;
                break;
            }
            if (!_clientHelloDone) return [];
        }
        // ClientHello 之后：Finished（加密握手）与应用数据（请求明文）
        return DrainRecords(_client, records, index);
    }

    private byte[] PumpServer()
    {
        var records = TakeRecordsFull(_server);
        var index = 0;
        if (!_serverHelloDone)
        {
            for (; index < records.Count; index++)
            {
                var (type, _, body) = records[index];
                if (type == 20) { _server.CcsSeen = true; continue; } // TLS 1.2 中 ChangeCipherSpec 可能混在 ServerHello 前到达
                if (type != 22 || !TryParseServerHello(body, out var version, out var suite, out var alpn, out var serverRandom)) continue;
                _isTls13 = version >= 0x0304;
                _suite = suite;
                _serverRandom = serverRandom;
                if (alpn is not null) Alpn = alpn;
                _serverHelloDone = true;
                if (_isTls13) SetupTls13Keys();
                index++;
                break;
            }
            if (!_serverHelloDone) return [];
        }
        return DrainRecords(_server, records, index);
    }

    private byte[] DrainRecords(SilentTlsDirection direction, List<(byte Type, ushort Version, byte[] Body)> records, int index)
    {
        using var application = new MemoryStream();
        for (; index < records.Count; index++)
        {
            var (type, version, body) = records[index];
            if (_isTls13)
            {
                if (type == 22)
                {
                    // 加密握手记录（加密扩展/证书/Finished）：内容仅用于提取 ALPN 覆盖。
                    if (!direction.HandshakeReady) continue;
                    var inner = DecryptAuto(direction, type, body);
                    if (inner is null) { _broken = true; return []; }
                    var (contentType, payload) = StripTls13Padding(inner);
                    if (contentType == 22 && Alpn is null) Alpn = TryParseAlpnFromEncryptedExtensions(payload);
                    continue;
                }
                if (type != 23 || !direction.ApplicationReady) continue;
                var plain = DecryptAuto(direction, type, body);
                if (plain is null) { _broken = true; return []; }
                var (recordType, data) = StripTls13Padding(plain);
                if (recordType == 23) application.Write(data, 0, data.Length);
                // 22 = 握手后消息（NewSessionTicket 等），无分析价值，跳过
            }
            else
            {
                if (_suite < 0 || _keys?.MasterSecret is null) return [];
                if (!direction.ApplicationReady && !TrySetupTls12Keys()) return [];
                if (type == 20) { direction.CcsSeen = true; continue; }
                if (type == 22) continue; // 明文握手（证书等）不需要
                if (type != 23 || !direction.CcsSeen) continue;
                var plain = DecryptTls12(direction, type, version, body);
                if (plain is null) { _broken = true; return []; }
                application.Write(plain, 0, plain.Length);
            }
        }
        return application.Length == 0 ? [] : application.ToArray();
    }

    // ── 密钥建立 ──────────────────────────────────────────────

    /// <summary>密钥行可能晚于 ClientHello 写入日志：未命中时增量重读并重查。</summary>
    private void EnsureKeys()
    {
        if (_keys is not null || _clientRandom.Length == 0) return;
        _keyLog.Refresh();
        _keys = _keyLog.Find(Convert.ToHexString(_clientRandom));
    }

    private void SetupTls13Keys()
    {
        EnsureKeys();
        if (_keys is null || !_keys.HasTls13 || _suite < 0) return;
        var aead = SuiteToAead(_suite, tls13: true);
        if (aead is null) return;
        var hash = _suite == 0x1302 ? HashAlgorithmName.SHA384 : HashAlgorithmName.SHA256;
        var keyLength = aead == SilentTlsAead.Aes128Gcm ? 16 : 32; // AES-256 与 ChaCha20 均为 32
        // 握手机密缺失时只跳过加密握手记录，应用数据仍可解密（正常浏览器两者都会写）
        if (_keys.ServerHandshakeSecret is not null && _keys.ClientHandshakeSecret is not null)
        {
            SetupHandshakeKeys(_server, _keys.ServerHandshakeSecret, aead.Value, hash, keyLength);
            SetupHandshakeKeys(_client, _keys.ClientHandshakeSecret, aead.Value, hash, keyLength);
        }
        SetupApplicationKeys(_server, _keys.ServerTrafficSecret!, aead.Value, hash, keyLength);
        SetupApplicationKeys(_client, _keys.ClientTrafficSecret!, aead.Value, hash, keyLength);
    }

    private static void SetupHandshakeKeys(SilentTlsDirection direction, string secretHex,
        SilentTlsAead aead, HashAlgorithmName hash, int keyLength)
    {
        var secret = Convert.FromHexString(secretHex);
        direction.Aead = aead;
        direction.HandshakeKey = HkdfExpandLabel(secret, "tls13 key", keyLength, hash);
        direction.HandshakeIv = HkdfExpandLabel(secret, "tls13 iv", 12, hash);
        direction.HandshakeReady = true;
    }

    private static void SetupApplicationKeys(SilentTlsDirection direction, string secretHex,
        SilentTlsAead aead, HashAlgorithmName hash, int keyLength)
    {
        var secret = Convert.FromHexString(secretHex);
        direction.Aead = aead;
        direction.ApplicationKey = HkdfExpandLabel(secret, "tls13 key", keyLength, hash);
        direction.ApplicationIv = HkdfExpandLabel(secret, "tls13 iv", 12, hash);
        direction.ApplicationReady = true;
    }

    private bool TrySetupTls12Keys()
    {
        EnsureKeys();
        var aead = SuiteToAead(_suite, tls13: false);
        if (aead is null || _keys?.MasterSecret is null || _clientRandom.Length == 0 || _serverRandom.Length == 0) return false;
        // key expansion：server_random 在前（服务端生成的块方向相反）
        var seed = new byte[64];
        _serverRandom.CopyTo(seed, 0);
        _clientRandom.CopyTo(seed, 32);
        var master = Convert.FromHexString(_keys.MasterSecret);
        var hash = _suite is 0xC02C or 0xC030 ? HashAlgorithmName.SHA384 : HashAlgorithmName.SHA256;
        var keyLength = aead == SilentTlsAead.Aes128Gcm ? 16 : 32;
        var block = Tls12Prf(master, "key expansion", seed, keyLength * 2 + 8, hash);
        SetupTls12Direction(_client, block, 0, keyLength, aead.Value);
        SetupTls12Direction(_server, block, keyLength, keyLength, aead.Value);
        _server.ApplicationReady = true;
        _client.ApplicationReady = true;
        return true;
    }

    private static void SetupTls12Direction(SilentTlsDirection direction, byte[] block, int keyOffset, int keyLength, SilentTlsAead aead)
    {
        direction.Aead = aead;
        direction.ApplicationKey = block.AsSpan(keyOffset, keyLength).ToArray();
        direction.ApplicationIv = block.AsSpan(keyLength * 2, 4).ToArray(); // GCM 隐式 4 字节盐；ChaCha20 套件不使用
    }

    private static SilentTlsAead? SuiteToAead(int suite, bool tls13) => tls13 ? suite switch
    {
        0x1301 => SilentTlsAead.Aes128Gcm,
        0x1302 => SilentTlsAead.Aes256Gcm,
        0x1303 => SilentTlsAead.ChaCha20Poly1305,
        _ => null
    } : suite switch
    {
        0xC02B or 0xC02F => SilentTlsAead.Aes128Gcm,
        0xC02C or 0xC030 => SilentTlsAead.Aes256Gcm,
        0xCCA8 or 0xCCA9 => SilentTlsAead.ChaCha20Poly1305,
        _ => null
    };

    // ── 记录读取与解密 ────────────────────────────────────────

    private static List<(byte Type, ushort Version, byte[] Body)> TakeRecordsFull(SilentTlsDirection direction)
    {
        var result = new List<(byte, ushort, byte[])>();
        var data = direction.Buffer.ToArray();
        var offset = 0;
        while (offset + 5 <= data.Length)
        {
            var length = BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(offset + 3));
            if (length > 16384 + 256) { direction.Buffer.SetLength(0); break; } // 非法长度：放弃缓冲
            if (offset + 5 + length > data.Length) break;
            result.Add((data[offset], BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(offset + 1)),
                data.AsSpan(offset + 5, length).ToArray()));
            offset += 5 + length;
        }
        if (offset > 0)
        {
            var remaining = data.AsSpan(offset).ToArray();
            direction.Buffer.SetLength(0);
            direction.Buffer.Write(remaining, 0, remaining.Length);
        }
        return result;
    }

    /// <summary>TLS 1.3 解密：先试应用密钥，失败回退回握手密钥（记录到达顺序即相位，AEAD 认证失败可安全判别）。</summary>
    private byte[]? DecryptAuto(SilentTlsDirection direction, byte type, byte[] body)
    {
        var plain = Decrypt(direction, type, body, direction.ApplicationKey, direction.ApplicationIv);
        if (plain is null && direction.HandshakeReady)
            plain = Decrypt(direction, type, body, direction.HandshakeKey, direction.HandshakeIv);
        return plain;
    }

    private byte[]? Decrypt(SilentTlsDirection direction, byte type, byte[] body, byte[] key, byte[] iv)
    {
        if (key.Length == 0 || iv.Length == 0 || body.Length < 16) return null;
        var nonce = (byte[])iv.Clone();
        var sequenceBytes = new byte[12];
        BinaryPrimitives.WriteUInt64BigEndian(sequenceBytes.AsSpan(4), direction.Sequence);
        for (var i = 0; i < 12; i++) nonce[i] ^= sequenceBytes[i];
        // 序号仅在解密成功后递增：DecryptAuto 先试应用密钥再回退回握手密钥，两者共用同一序号
        var header = new byte[5] { type, 0x03, 0x03, (byte)(body.Length >> 8), (byte)body.Length };
        try
        {
            var plain = DecryptAead(direction.Aead, key, nonce, header, body);
            direction.Sequence++;
            return plain;
        }
        catch (CryptographicException) { return null; }
    }

    private byte[]? DecryptTls12(SilentTlsDirection direction, byte type, ushort version, byte[] body)
    {
        if (direction.Aead == SilentTlsAead.ChaCha20Poly1305)
        {
            if (body.Length < 16 || direction.ApplicationIv.Length != 4) return null;
            var nonce = new byte[12];
            direction.ApplicationIv.CopyTo(nonce, 0);
            BinaryPrimitives.WriteUInt64BigEndian(nonce.AsSpan(4), direction.Sequence);
            direction.Sequence++;
            var header = BuildTls12Aad(direction.Sequence - 1, type, version, body.Length - 16);
            try { return DecryptAead(direction.Aead, direction.ApplicationKey, nonce, header, body); }
            catch (CryptographicException) { return null; }
        }
        // GCM：记录前 8 字节为显式随机数，与 4 字节隐式盐拼成 12 字节 nonce
        if (body.Length < 24) return null;
        var gcmNonce = new byte[12];
        direction.ApplicationIv.CopyTo(gcmNonce, 0);
        body.AsSpan(0, 8).CopyTo(gcmNonce.AsSpan(4));
        var gcmHeader = BuildTls12Aad(direction.Sequence, type, version, body.Length - 8 - 16);
        direction.Sequence++;
        try { return DecryptAead(direction.Aead, direction.ApplicationKey, gcmNonce, gcmHeader, body.AsSpan(8).ToArray()); }
        catch (CryptographicException) { return null; }
    }

    private static byte[] BuildTls12Aad(ulong sequence, byte type, ushort version, int plainLength)
    {
        var aad = new byte[13];
        BinaryPrimitives.WriteUInt64BigEndian(aad, sequence);
        aad[8] = type;
        BinaryPrimitives.WriteUInt16BigEndian(aad.AsSpan(9), version);
        BinaryPrimitives.WriteUInt16BigEndian(aad.AsSpan(11), (ushort)plainLength);
        return aad;
    }

    private static byte[] DecryptAead(SilentTlsAead aead, byte[] key, byte[] nonce, byte[] aad, byte[] ciphertextWithTag)
    {
        var plain = new byte[ciphertextWithTag.Length - 16];
        switch (aead)
        {
            case SilentTlsAead.Aes128Gcm:
            case SilentTlsAead.Aes256Gcm:
                using (var gcm = new AesGcm(key, 16)) gcm.Decrypt(nonce, ciphertextWithTag.AsSpan(0, ciphertextWithTag.Length - 16),
                    ciphertextWithTag.AsSpan(ciphertextWithTag.Length - 16), plain, aad);
                break;
            default:
                using (var chacha = new ChaCha20Poly1305(key)) chacha.Decrypt(nonce, ciphertextWithTag.AsSpan(0, ciphertextWithTag.Length - 16),
                    ciphertextWithTag.AsSpan(ciphertextWithTag.Length - 16), plain, aad);
                break;
        }
        return plain;
    }

    /// <summary>TLS 1.3 内层明文：返回（真实内容类型，去零填充后的内容）；全零返回 (0, 空)。</summary>
    private static (byte ContentType, byte[] Data) StripTls13Padding(byte[] inner)
    {
        for (var i = inner.Length - 1; i >= 0; i--)
        {
            if (inner[i] != 0)
                return (inner[i], inner.AsSpan(0, i).ToArray());
        }
        return (0, []);
    }

    // ── 握手解析 ─────────────────────────────────────────────

    internal static bool TryParseClientHello(byte[] body, out byte[] random, out string? alpn)
    {
        random = [];
        alpn = null;
        if (body.Length < 4 || body[0] != 0x01) return false;
        var helloLength = (body[1] << 16) | (body[2] << 8) | body[3];
        var hello = body.AsSpan(4, Math.Min(helloLength, body.Length - 4));
        if (hello.Length < 34) return false;
        random = hello.Slice(2, 32).ToArray();
        var offset = 34;
        if (offset >= hello.Length) return true;
        var sessionIdLength = hello[offset]; offset += 1 + sessionIdLength;
        if (offset + 2 > hello.Length) return true;
        offset += 2 + BinaryPrimitives.ReadUInt16BigEndian(hello[offset..]);
        if (offset + 1 > hello.Length) return true;
        offset += 1 + hello[offset];
        if (offset + 2 > hello.Length) return true;
        var extensionsLength = BinaryPrimitives.ReadUInt16BigEndian(hello[offset..]);
        offset += 2;
        var end = offset + Math.Min(extensionsLength, hello.Length - offset);
        alpn = WalkExtensionsForAlpn(hello, offset, end);
        return true;
    }

    private static bool TryParseServerHello(byte[] body, out int version, out int suite, out string? alpn, out byte[] serverRandom)
    {
        version = 0;
        suite = -1;
        alpn = null;
        serverRandom = [];
        if (body.Length < 4 || body[0] != 0x02) return false;
        var helloLength = (body[1] << 16) | (body[2] << 8) | body[3];
        var hello = body.AsSpan(4, Math.Min(helloLength, body.Length - 4));
        if (hello.Length < 35) return false;
        version = (hello[0] << 8) | hello[1];
        serverRandom = hello.Slice(2, 32).ToArray();
        var offset = 34;
        var sessionIdLength = hello[offset]; offset += 1 + sessionIdLength;
        if (offset + 3 > hello.Length) return false;
        suite = BinaryPrimitives.ReadUInt16BigEndian(hello[offset..]);
        offset += 3; // 套件(2) + 压缩方法(1)
        if (offset + 2 > hello.Length) return true;
        var extensionsLength = BinaryPrimitives.ReadUInt16BigEndian(hello[offset..]);
        offset += 2;
        var end = offset + Math.Min(extensionsLength, hello.Length - offset);
        while (offset + 4 <= end)
        {
            var type = BinaryPrimitives.ReadUInt16BigEndian(hello[offset..]);
            var length = BinaryPrimitives.ReadUInt16BigEndian(hello[(offset + 2)..]);
            offset += 4;
            if (offset + length > hello.Length) break;
            if (type == 43 && length >= 2) version = BinaryPrimitives.ReadUInt16BigEndian(hello[offset..]); // supported_version
            offset += length;
        }
        return true;
    }

    private static string? TryParseAlpnFromEncryptedExtensions(byte[] inner)
    {
        // 加密扩展消息可能拼接多条握手消息；只找 EncryptedExtensions(type=8)
        var offset = 0;
        while (offset + 4 <= inner.Length)
        {
            var type = inner[offset];
            var length = (inner[offset + 1] << 16) | (inner[offset + 2] << 8) | inner[offset + 3];
            offset += 4;
            if (offset + length > inner.Length) break;
            if (type == 8 && length >= 2)
            {
                var body = inner.AsSpan(offset, length);
                var extensionsLength = BinaryPrimitives.ReadUInt16BigEndian(body);
                return WalkExtensionsForAlpn(body, 2, 2 + Math.Min(extensionsLength, body.Length - 2));
            }
            offset += length;
        }
        return null;
    }

    private static string? WalkExtensionsForAlpn(ReadOnlySpan<byte> buffer, int offset, int end)
    {
        while (offset + 4 <= end)
        {
            var type = BinaryPrimitives.ReadUInt16BigEndian(buffer[offset..]);
            var length = BinaryPrimitives.ReadUInt16BigEndian(buffer[(offset + 2)..]);
            offset += 4;
            if (offset + length > buffer.Length) break;
            if (type == 16 && length >= 4)
            {
                // ALPN 扩展负载：[协议列表总长 2 字节][协议名长 1 字节][协议名]，取首个协议
                var list = buffer.Slice(offset, length);
                var nameLength = list[2];
                if (nameLength > 0 && 3 + nameLength <= list.Length)
                    return Encoding.ASCII.GetString(list.Slice(3, nameLength));
            }
            offset += length;
        }
        return null;
    }

    // ── 密码学原语 ───────────────────────────────────────────

    /// <summary>TLS 1.3 HkdfExpandLabel（RFC 8446 §7.1）。</summary>
    public static byte[] HkdfExpandLabel(byte[] secret, string label, int length, HashAlgorithmName hash)
    {
        var fullLabel = "tls13 " + label;
        var info = new byte[2 + 1 + fullLabel.Length + 1];
        BinaryPrimitives.WriteUInt16BigEndian(info, (ushort)length);
        info[2] = (byte)fullLabel.Length;
        Encoding.ASCII.GetBytes(fullLabel, info.AsSpan(3));
        info[^1] = 0; // 空 context
        return HKDF.Expand(hash, secret, length, info);
    }

    /// <summary>TLS 1.2 PRF（P_hash 迭代，SHA-256/384）。</summary>
    public static byte[] Tls12Prf(byte[] secret, string label, byte[] seed, int length, HashAlgorithmName hash)
    {
        var labelBytes = Encoding.ASCII.GetBytes(label);
        var labeledSeed = new byte[labelBytes.Length + seed.Length];
        labelBytes.CopyTo(labeledSeed, 0);
        seed.CopyTo(labeledSeed, labelBytes.Length);
        var output = new byte[length];
        var produced = 0;
        var a = labeledSeed;
        while (produced < length)
        {
            a = ComputeHmac(hash, secret, a);
            var joined = new byte[a.Length + labeledSeed.Length];
            a.CopyTo(joined, 0);
            labeledSeed.CopyTo(joined, a.Length);
            var block = ComputeHmac(hash, secret, joined);
            var take = Math.Min(block.Length, length - produced);
            block.AsSpan(0, take).CopyTo(output.AsSpan(produced));
            produced += take;
        }
        return output;
    }

    private static byte[] ComputeHmac(HashAlgorithmName hash, byte[] key, byte[] data) =>
        hash == HashAlgorithmName.SHA384 ? HMACSHA384.HashData(key, data) : HMACSHA256.HashData(key, data);
}
