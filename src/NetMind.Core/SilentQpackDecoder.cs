using System.Text;

namespace NetMind.Core;

/// <summary>
/// QPACK（RFC 9204）解码器：静态表 + 由单向编码器流指令维护的动态表。
/// 被动捕获下编码器流可能中途才开始见到，动态引用落在已逐出/未见范围时标记 <see cref="Broken"/>，
/// 调用方放弃该方向头解码但继续抓包。任何错误绝不抛出。
/// </summary>
public sealed class SilentQpackDecoder
{
    // RFC 9204 附录 A 静态表（0 基索引，共 99 项）
    private static readonly (string Name, string Value)[] StaticTable =
    [
        (":authority", ""),
        (":path", "/"),
        ("age", "0"),
        ("content-disposition", ""),
        ("content-length", "0"),
        ("cookie", ""),
        ("date", ""),
        ("etag", ""),
        ("if-modified-since", ""),
        ("if-none-match", ""),
        ("last-modified", ""),
        ("link", ""),
        ("location", ""),
        ("referer", ""),
        ("set-cookie", ""),
        (":method", "CONNECT"),
        (":method", "DELETE"),
        (":method", "GET"),
        (":method", "HEAD"),
        (":method", "OPTIONS"),
        (":method", "POST"),
        (":method", "PUT"),
        (":scheme", "http"),
        (":scheme", "https"),
        (":status", "103"),
        (":status", "200"),
        (":status", "304"),
        (":status", "404"),
        (":status", "503"),
        ("accept", "*/*"),
        ("accept", "application/dns-message"),
        ("accept-encoding", "gzip, deflate, br"),
        ("accept-ranges", "bytes"),
        ("access-control-allow-headers", "cache-control"),
        ("access-control-allow-headers", "content-type"),
        ("access-control-allow-origin", "*"),
        ("cache-control", "max-age=0"),
        ("cache-control", "max-age=2592000"),
        ("cache-control", "max-age=604800"),
        ("cache-control", "no-cache"),
        ("cache-control", "no-store"),
        ("cache-control", "public, max-age=31536000"),
        ("content-encoding", "br"),
        ("content-encoding", "gzip"),
        ("content-type", "application/dns-message"),
        ("content-type", "application/javascript"),
        ("content-type", "application/json"),
        ("content-type", "application/x-www-form-urlencoded"),
        ("content-type", "image/gif"),
        ("content-type", "image/jpeg"),
        ("content-type", "image/png"),
        ("content-type", "text/css"),
        ("content-type", "text/html; charset=utf-8"),
        ("content-type", "text/plain"),
        ("content-type", "text/plain;charset=utf-8"),
        ("range", "bytes=0-"),
        ("strict-transport-security", "max-age=31536000"),
        ("strict-transport-security", "max-age=31536000; includesubdomains"),
        ("strict-transport-security", "max-age=31536000; includesubdomains; preload"),
        ("vary", "accept-encoding"),
        ("vary", "origin"),
        ("x-content-type-options", "nosniff"),
        ("x-xss-protection", "1; mode=block"),
        (":status", "100"),
        (":status", "204"),
        (":status", "206"),
        (":status", "302"),
        (":status", "400"),
        (":status", "403"),
        (":status", "421"),
        (":status", "425"),
        (":status", "500"),
        ("accept-language", ""),
        ("access-control-allow-credentials", "FALSE"),
        ("access-control-allow-credentials", "TRUE"),
        ("access-control-allow-headers", "*"),
        ("access-control-allow-methods", "get"),
        ("access-control-allow-methods", "get, post, options"),
        ("access-control-allow-methods", "options"),
        ("access-control-expose-headers", "content-length"),
        ("access-control-request-headers", "content-type"),
        ("access-control-request-method", "get"),
        ("access-control-request-method", "post"),
        ("alt-svc", "clear"),
        ("authorization", ""),
        ("content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'"),
        ("early-data", "1"),
        ("expect-ct", ""),
        ("forwarded", ""),
        ("if-range", ""),
        ("origin", ""),
        ("purpose", "prefetch"),
        ("server", ""),
        ("timing-allow-origin", "*"),
        ("upgrade-insecure-requests", "1"),
        ("user-agent", ""),
        ("x-forwarded-for", ""),
        ("x-frame-options", "deny"),
        ("x-frame-options", "sameorigin")
    ];

    private readonly List<(string Name, string Value)> _dynamicTable = []; // 表头 = 最早插入（最小绝对索引）
    private byte[] _encoderPending = [];                                    // 编码器流未解析残余
    private int _capacity;
    private int _size;
    private int _totalInserts;                                              // 插入总数（含已逐出）
    private int _oldestAbsoluteIndex;                                       // 表中现存最早条目的绝对索引

    /// <summary>出现过不可恢复的格式错误：该方向 QPACK 上下文停用。</summary>
    public bool Broken { get; private set; }

    /// <summary>喂入该方向单向编码器流的新字节（RFC 9204 §4.3 指令）。</summary>
    public void FeedEncoderStream(ReadOnlySpan<byte> data)
    {
        if (Broken || data.IsEmpty) return;
        try
        {
            _encoderPending = Concat(_encoderPending, data);
            var position = 0;
            while (position < _encoderPending.Length)
            {
                var snapshot = position;
                if (!TryParseInstruction(_encoderPending, ref position)) { position = snapshot; break; } // 指令未收全：等待后续分块
            }
            if (position > 0) _encoderPending = _encoderPending[position..];
        }
        catch (Exception exception) when (exception is InvalidDataException or IndexOutOfRangeException or ArgumentOutOfRangeException)
        {
            Broken = true;
        }
    }

    /// <summary>解码一个字段段（HEADERS 帧负载）；任何错误返回 null 并置 <see cref="Broken"/>。</summary>
    public List<(string Name, string Value)>? DecodeFieldSection(ReadOnlySpan<byte> block)
    {
        if (Broken) return null;
        try
        {
            var position = 0;
            // 字段段前缀（§4.5.1）：Required Insert Count（8 位前缀）+ Sign 位 + Delta Base（7 位前缀）
            var encodedInsertCount = SilentHpackDecoder.DecodeInteger(block, ref position, 8);
            var sign = (block[position] & 0x80) != 0;
            var deltaBase = SilentHpackDecoder.DecodeInteger(block, ref position, 7);
            var requiredInsertCount = DecodeRequiredInsertCount(encodedInsertCount);
            var baseIndex = requiredInsertCount == 0 ? 0
                : sign ? requiredInsertCount - deltaBase - 1
                : requiredInsertCount + deltaBase;
            if (baseIndex < 0) throw new InvalidDataException("QPACK Base 为负");

            var result = new List<(string, string)>();
            while (position < block.Length)
            {
                var first = block[position];
                if ((first & 0x80) != 0)
                {
                    // 索引字段行（§4.5.2）：1 T + 6 位索引
                    var index = SilentHpackDecoder.DecodeInteger(block, ref position, 6);
                    result.Add((first & 0x40) != 0 ? LookupStatic(index) : LookupDynamic(baseIndex - index - 1));
                }
                else if ((first & 0xF0) == 0x10)
                {
                    // Base 后索引字段行（§4.5.3）：0001 + 4 位索引
                    var index = SilentHpackDecoder.DecodeInteger(block, ref position, 4);
                    result.Add(LookupDynamic(requiredInsertCount + index));
                }
                else if ((first & 0xC0) == 0x40)
                {
                    // 名字引用字面字段行（§4.5.4）：01 N T + 4 位名字索引 + 值串
                    var index = SilentHpackDecoder.DecodeInteger(block, ref position, 4);
                    var name = (first & 0x10) != 0 ? LookupStatic(index).Name : LookupDynamic(baseIndex - index - 1).Name;
                    result.Add((name, SilentHpackDecoder.DecodePrefixedString(block, ref position, 7)));
                }
                else if ((first & 0xF0) == 0x00)
                {
                    // Base 后名字引用字面字段行（§4.5.5）：0000 N + 3 位索引 + 值串
                    var index = SilentHpackDecoder.DecodeInteger(block, ref position, 3);
                    var name = LookupDynamic(requiredInsertCount + index).Name;
                    result.Add((name, SilentHpackDecoder.DecodePrefixedString(block, ref position, 7)));
                }
                else if ((first & 0xE0) == 0x20)
                {
                    // 全字面字段行（§4.5.6）：001 N H + 3 位名字长 + 名字 + 值串
                    var name = SilentHpackDecoder.DecodePrefixedString(block, ref position, 3);
                    var value = SilentHpackDecoder.DecodePrefixedString(block, ref position, 7);
                    result.Add((name, value));
                }
                else throw new InvalidDataException("QPACK 字段行模式未知");
            }
            return result;
        }
        catch (Exception exception) when (exception is InvalidDataException or IndexOutOfRangeException or ArgumentOutOfRangeException)
        {
            Broken = true;
            return null;
        }
    }

    /// <summary>RFC 9204 §4.5.1.1 官方解码算法：模 2*MaxEntries 还原 Required Insert Count。</summary>
    private int DecodeRequiredInsertCount(int encoded)
    {
        if (encoded == 0) return 0;
        var maxEntries = _capacity / 32;
        var fullRange = 2 * maxEntries;
        if (fullRange == 0 || encoded > fullRange) throw new InvalidDataException("QPACK Required Insert Count 非法");
        var maxValue = _totalInserts + maxEntries;
        var maxWrapped = maxValue / fullRange * fullRange;
        var required = maxWrapped + encoded - 1;
        if (required > maxValue)
        {
            if (required <= fullRange) throw new InvalidDataException("QPACK Required Insert Count 非法");
            required -= fullRange;
        }
        if (required == 0) throw new InvalidDataException("QPACK Required Insert Count 非法");
        return required;
    }

    /// <summary>解析一条编码器流指令；剩余字节不足以构成完整指令时返回 false（位置不动）。</summary>
    private bool TryParseInstruction(byte[] buffer, ref int position)
    {
        var first = buffer[position];
        if ((first & 0x80) != 0)
        {
            // 名字引用插入（§4.3.2）：1 T + 6 位名字索引 + 值串
            if (!TryDecodeInteger(buffer, ref position, 6, out var index)) return false;
            var name = (first & 0x40) != 0 ? LookupStatic(index).Name : LookupDynamic(_totalInserts - index - 1).Name;
            if (!TryDecodeString(buffer, ref position, 7, out var value)) return false;
            Insert(name, value);
            return true;
        }
        if ((first & 0xC0) == 0x40)
        {
            // 全字面插入（§4.3.3）：01 H + 5 位名字长 + 名字 + 值串
            position += 1;
            var name = SilentHpackDecoder.DecodePrefixedString(buffer, ref position, 5);
            var value = SilentHpackDecoder.DecodePrefixedString(buffer, ref position, 7);
            Insert(name, value);
            return true;
        }
        if ((first & 0xE0) == 0x20)
        {
            // 动态表容量设置（§4.3.1）：001 + 5 位前缀
            if (!TryDecodeInteger(buffer, ref position, 5, out var capacity)) return false;
            _capacity = capacity;
            Evict();
            return true;
        }
        if ((first & 0xE0) == 0x00)
        {
            // 复制（§4.3.4）：000 + 5 位相对索引
            if (!TryDecodeInteger(buffer, ref position, 5, out var index)) return false;
            var entry = LookupDynamic(_totalInserts - index - 1);
            Insert(entry.Name, entry.Value);
            return true;
        }
        throw new InvalidDataException("QPACK 编码器指令未知");
    }

    private (string Name, string Value) LookupStatic(int index)
    {
        if (index < 0 || index >= StaticTable.Length) throw new InvalidDataException("QPACK 静态表索引越界");
        return StaticTable[index];
    }

    private (string Name, string Value) LookupDynamic(int absoluteIndex)
    {
        if (absoluteIndex < _oldestAbsoluteIndex || absoluteIndex >= _totalInserts)
            throw new InvalidDataException("QPACK 动态表索引越界（被动捕获缺失）");
        return _dynamicTable[absoluteIndex - _oldestAbsoluteIndex];
    }

    private void Insert(string name, string value)
    {
        _totalInserts++;
        _dynamicTable.Add((name, value));
        _size += name.Length + value.Length + 32; // RFC 9204 §3.2.1：条目大小 = 名长 + 值长 + 32
        Evict();
    }

    private void Evict()
    {
        while (_dynamicTable.Count > 0 && _size > _capacity)
        {
            var (name, value) = _dynamicTable[0];
            _dynamicTable.RemoveAt(0);
            _size -= name.Length + value.Length + 32;
            _oldestAbsoluteIndex++;
        }
    }

    // ── 边界安全的解码辅助（截断返回 false，格式错误抛出）──────────────

    private static bool TryDecodeInteger(byte[] buffer, ref int position, int prefixBits, out int value)
    {
        value = 0;
        if (position >= buffer.Length) return false;
        var mask = (1 << prefixBits) - 1;
        value = buffer[position] & mask;
        position++;
        if (value < mask) return true;
        var shift = 0;
        while (true)
        {
            if (position >= buffer.Length) return false;
            if (shift > 28) throw new InvalidDataException("整数编码过长");
            var part = buffer[position];
            position++;
            value += (part & 0x7f) << shift;
            shift += 7;
            if ((part & 0x80) == 0) return true;
        }
    }

    private static bool TryDecodeString(byte[] buffer, ref int position, int prefixBits, out string value)
    {
        value = string.Empty;
        if (position >= buffer.Length) return false;
        var start = position;
        var huffman = (buffer[position] & (1 << prefixBits)) != 0;
        if (!TryDecodeInteger(buffer, ref position, prefixBits, out var length)) { position = start; return false; }
        if (position + length > buffer.Length) { position = start; return false; }
        var slice = buffer.AsSpan(position, length);
        position += length;
        value = huffman ? SilentHpackDecoder.DecodeHuffman(slice) : Encoding.Latin1.GetString(slice);
        return true;
    }

    private static byte[] Concat(byte[] first, ReadOnlySpan<byte> second)
    {
        if (first.Length == 0) return second.ToArray();
        var joined = new byte[first.Length + second.Length];
        first.CopyTo(joined, 0);
        second.CopyTo(joined.AsSpan(first.Length));
        return joined;
    }
}
