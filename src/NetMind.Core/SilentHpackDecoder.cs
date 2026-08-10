using System.Buffers.Binary;
using System.Text;

namespace NetMind.Core;

/// <summary>
/// HPACK（RFC 7541）解码器：静态表 + 动态表 + Huffman 解码，仅解码不编码。
/// 每个 HTTP/2 方向独立一个实例；任何格式错误标记 <see cref="Broken"/> 后该方向解码永久停用。
/// </summary>
public sealed class SilentHpackDecoder
{
    private sealed class HuffmanNode
    {
        public HuffmanNode? Zero;
        public HuffmanNode? One;
        public int Symbol = -1;
    }

    // RFC 7541 附录 A 静态表（索引 1-61）
    private static readonly (string Name, string Value)[] StaticTable =
    [
        ("", ""),                                                     // 0 占位：HPACK 索引从 1 开始
        (":authority", ""),
        (":method", "GET"),
        (":method", "POST"),
        (":path", "/"),
        (":path", "/index.html"),
        (":scheme", "http"),
        (":scheme", "https"),
        (":status", "200"),
        (":status", "204"),
        (":status", "206"),
        (":status", "304"),
        (":status", "400"),
        (":status", "404"),
        (":status", "500"),
        ("accept-charset", ""),
        ("accept-encoding", "gzip, deflate"),
        ("accept-language", ""),
        ("accept-ranges", ""),
        ("accept", ""),
        ("access-control-allow-origin", ""),
        ("age", ""),
        ("allow", ""),
        ("authorization", ""),
        ("cache-control", ""),
        ("content-disposition", ""),
        ("content-encoding", ""),
        ("content-language", ""),
        ("content-length", ""),
        ("content-location", ""),
        ("content-range", ""),
        ("content-type", ""),
        ("cookie", ""),
        ("date", ""),
        ("etag", ""),
        ("expect", ""),
        ("expires", ""),
        ("from", ""),
        ("host", ""),
        ("if-match", ""),
        ("if-modified-since", ""),
        ("if-none-match", ""),
        ("if-range", ""),
        ("if-unmodified-since", ""),
        ("last-modified", ""),
        ("link", ""),
        ("location", ""),
        ("max-forwards", ""),
        ("proxy-authenticate", ""),
        ("proxy-authorization", ""),
        ("range", ""),
        ("referer", ""),
        ("refresh", ""),
        ("retry-after", ""),
        ("server", ""),
        ("set-cookie", ""),
        ("strict-transport-security", ""),
        ("transfer-encoding", ""),
        ("user-agent", ""),
        ("vary", ""),
        ("via", ""),
        ("www-authenticate", "")
    ];

    // RFC 7541 附录 B Huffman 码表：下标为符号值（0-255，256 为 EOS），LSB 对齐码值 + 位长
    private static readonly (uint Code, int Length)[] HuffmanTable =
    [
        (0x1ff8, 13), (0x7fffd8, 23), (0xfffffe2, 28), (0xfffffe3, 28), (0xfffffe4, 28), (0xfffffe5, 28),
        (0xfffffe6, 28), (0xfffffe7, 28), (0xfffffe8, 28), (0xfffea, 24), (0x3ffffffc, 30), (0xfffffe9, 28),
        (0xfffffea, 28), (0x3ffffffd, 30), (0xfffffeb, 28), (0xfffffec, 28), (0xfffffed, 28), (0xfffffee, 28),
        (0xfffffef, 28), (0xffffff0, 28), (0xffffff1, 28), (0xffffff2, 28), (0x3ffffffe, 30), (0xffffff3, 28),
        (0xffffff4, 28), (0xffffff5, 28), (0xffffff6, 28), (0xffffff7, 28), (0xffffff8, 28), (0xffffff9, 28),
        (0xffffffa, 28), (0xffffffb, 28), (0x14, 6), (0x3f8, 10), (0x3f9, 10), (0xffa, 12),
        (0x1ff9, 13), (0x15, 6), (0xf8, 8), (0x7fa, 11), (0x3fa, 10), (0x3fb, 10),
        (0xf9, 8), (0x7fb, 11), (0xfa, 8), (0x16, 6), (0x17, 6), (0x18, 6),
        (0x0, 5), (0x1, 5), (0x2, 5), (0x19, 6), (0x1a, 6), (0x1b, 6),
        (0x1c, 6), (0x1d, 6), (0x1e, 6), (0x1f, 6), (0x5c, 7), (0xfb, 8),
        (0x7ffc, 15), (0x20, 6), (0xffb, 12), (0x3fc, 10), (0x1ffa, 13), (0x21, 6),
        (0x5d, 7), (0x5e, 7), (0x5f, 7), (0x60, 7), (0x61, 7), (0x62, 7),
        (0x63, 7), (0x64, 7), (0x65, 7), (0x66, 7), (0x67, 7), (0x68, 7),
        (0x69, 7), (0x6a, 7), (0x6b, 7), (0x6c, 7), (0x6d, 7), (0x6e, 7),
        (0x6f, 7), (0x70, 7), (0x71, 7), (0x72, 7), (0xfc, 8), (0x73, 7),
        (0xfd, 8), (0x1ffb, 13), (0x7fff0, 19), (0x1ffc, 13), (0x3ffc, 14), (0x22, 6),
        (0x7ffd, 15), (0x3, 5), (0x23, 6), (0x4, 5), (0x24, 6), (0x5, 5),
        (0x25, 6), (0x26, 6), (0x27, 6), (0x6, 5), (0x74, 7), (0x75, 7),
        (0x28, 6), (0x29, 6), (0x2a, 6), (0x7, 5), (0x2b, 6), (0x76, 7),
        (0x2c, 6), (0x8, 5), (0x9, 5), (0x2d, 6), (0x77, 7), (0x78, 7),
        (0x79, 7), (0x7a, 7), (0x7b, 7), (0x7ffe, 15), (0x7fc, 11), (0x3ffd, 14),
        (0x1ffd, 13), (0xffffffc, 28), (0xfffe6, 20), (0x3fffd2, 22), (0xfffe7, 20), (0xfffe8, 20),
        (0x3fffd3, 22), (0x3fffd4, 22), (0x3fffd5, 22), (0x7fffd9, 23), (0x3fffd6, 22), (0x7fffda, 23),
        (0x7fffdb, 23), (0x7fffdc, 23), (0x7fffdd, 23), (0x7fffde, 23), (0xffffeb, 24), (0x7fffdf, 23),
        (0xffffec, 24), (0xffffed, 24), (0x3fffd7, 22), (0x7fffe0, 23), (0xffffee, 24), (0x7fffe1, 23),
        (0x7fffe2, 23), (0x7fffe3, 23), (0x7fffe4, 23), (0x1fffdc, 21), (0x3fffd8, 22), (0x7fffe5, 23),
        (0x3fffd9, 22), (0x7fffe6, 23), (0x7fffe7, 23), (0xffffef, 24), (0x3fffda, 22), (0x1fffdd, 21),
        (0xfffe9, 20), (0x3fffdb, 22), (0x3fffdc, 22), (0x7fffe8, 23), (0x7fffe9, 23), (0x1fffde, 21),
        (0x7fffea, 23), (0x3fffdd, 22), (0x3fffde, 22), (0xfffff0, 24), (0x1fffdf, 21), (0x3fffdf, 22),
        (0x7fffeb, 23), (0x7fffec, 23), (0x1fffe0, 21), (0x1fffe1, 21), (0x3fffe0, 22), (0x1fffe2, 21),
        (0x7fffed, 23), (0x3fffe1, 22), (0x7fffee, 23), (0x7fffef, 23), (0xfffea, 20), (0x3fffe2, 22),
        (0x3fffe3, 22), (0x3fffe4, 22), (0x7ffff0, 23), (0x3fffe5, 22), (0x3fffe6, 22), (0x7ffff1, 23),
        (0x3ffffe0, 26), (0x3ffffe1, 26), (0xfffeb, 20), (0x7fff1, 19), (0x3fffe7, 22), (0x7ffff2, 23),
        (0x3fffe8, 22), (0x1ffffec, 25), (0x3ffffe2, 26), (0x3ffffe3, 26), (0x3ffffe4, 26), (0x7ffffde, 27),
        (0x7ffffdf, 27), (0x3ffffe5, 26), (0xfffff1, 24), (0x1ffffed, 25), (0x7fff2, 19), (0x1fffe3, 21),
        (0x3ffffe6, 26), (0x7ffffe0, 27), (0x7ffffe1, 27), (0x3ffffe7, 26), (0x7ffffe2, 27), (0xfffff2, 24),
        (0x1fffe4, 21), (0x1fffe5, 21), (0x3ffffe8, 26), (0x3ffffe9, 26), (0xffffffd, 28), (0x7ffffe3, 27),
        (0x7ffffe4, 27), (0x7ffffe5, 27), (0xfffec, 20), (0xfffff3, 24), (0xfffed, 20), (0x1fffe6, 21),
        (0x3fffe9, 22), (0x1fffe7, 21), (0x1fffe8, 21), (0x7ffff3, 23), (0x3fffea, 22), (0x3fffeb, 22),
        (0x1ffffee, 25), (0x1ffffef, 25), (0xfffff4, 24), (0xfffff5, 24), (0x3ffffea, 26), (0x7ffff4, 23),
        (0x3ffffeb, 26), (0x7ffffe6, 27), (0x3ffffec, 26), (0x3ffffed, 26), (0x7ffffe7, 27), (0x7ffffe8, 27),
        (0x7ffffe9, 27), (0x7ffffea, 27), (0x7ffffeb, 27), (0xffffffe, 28), (0x7ffffec, 27), (0x7ffffed, 27),
        (0x7ffffee, 27), (0x7ffffef, 27), (0x7fffff0, 27), (0x3ffffee, 26), (0x3fffffff, 30)                // 256 = EOS
    ];

    private static readonly HuffmanNode HuffmanRoot = BuildHuffmanTree();

    private readonly List<(string Name, string Value)> _dynamicTable = []; // 最新条目在索引 0
    private int _dynamicTableSize;
    private int _maxDynamicTableSize = 4096;

    /// <summary>出现过任何格式错误：该方向 HPACK 上下文不可恢复。</summary>
    public bool Broken { get; private set; }

    /// <summary>解码一个头块，返回首部列表（含伪首部）；任何错误返回 null 并置 <see cref="Broken"/>。</summary>
    public List<(string Name, string Value)>? Decode(ReadOnlySpan<byte> block)
    {
        if (Broken) return null;
        var result = new List<(string, string)>();
        try
        {
            var position = 0;
            while (position < block.Length)
            {
                var first = block[position];
                if ((first & 0x80) != 0)
                {
                    // 索引首部字段：1xxxxxxx
                    var index = DecodeInteger(block, ref position, 7);
                    result.Add(Lookup(index));
                }
                else if ((first & 0x40) != 0)
                {
                    // 字面首部 + 增量索引：01xxxxxx
                    var index = DecodeInteger(block, ref position, 6);
                    var name = index == 0 ? DecodeString(block, ref position) : Lookup(index).Name;
                    var value = DecodeString(block, ref position);
                    AddDynamic(name, value);
                    result.Add((name, value));
                }
                else if ((first & 0x20) != 0)
                {
                    // 动态表大小更新：001xxxxx
                    var size = DecodeInteger(block, ref position, 5);
                    if (size > 4096) throw new InvalidDataException("动态表大小超出协议上限");
                    _maxDynamicTableSize = size;
                    Evict();
                }
                else
                {
                    // 字面首部不索引（0000xxxx）/ 永不索引（0001xxxx）：解码方式一致
                    var index = DecodeInteger(block, ref position, 4);
                    var name = index == 0 ? DecodeString(block, ref position) : Lookup(index).Name;
                    var value = DecodeString(block, ref position);
                    result.Add((name, value));
                }
            }
            return result;
        }
        catch (Exception exception) when (exception is InvalidDataException or IndexOutOfRangeException or ArgumentOutOfRangeException)
        {
            Broken = true;
            return null;
        }
    }

    /// <summary>HPACK 索引查找：1-61 静态表，62 起动态表（最新条目索引最小）。</summary>
    private (string Name, string Value) Lookup(int index)
    {
        if (index <= 0) throw new InvalidDataException("HPACK 索引为 0");
        if (index < StaticTable.Length) return StaticTable[index];
        var dynamicIndex = index - StaticTable.Length;
        if (dynamicIndex >= _dynamicTable.Count) throw new InvalidDataException("HPACK 索引越界");
        return _dynamicTable[dynamicIndex];
    }

    /// <summary>N 位前缀整数解码（RFC 7541 5.1）：前缀全 1 时续读 7 位分组字节。QPACK 同样复用。</summary>
    internal static int DecodeInteger(ReadOnlySpan<byte> block, ref int position, int prefixBits)
    {
        var mask = (1 << prefixBits) - 1;
        var value = block[position] & mask;
        position++;
        if (value < mask) return value;
        var shift = 0;
        while (true)
        {
            if (position >= block.Length) throw new InvalidDataException("整数编码被截断");
            if (shift > 28) throw new InvalidDataException("整数编码过长");
            var part = block[position];
            position++;
            value += (part & 0x7f) << shift;
            shift += 7;
            if ((part & 0x80) == 0) return value;
        }
    }

    /// <summary>字符串字面解码：H 位选择 Huffman 或原文，长度为 7 位前缀整数。</summary>
    private static string DecodeString(ReadOnlySpan<byte> block, ref int position) =>
        DecodePrefixedString(block, ref position, 7);

    /// <summary>
    /// 带 H 位的字符串字面解码（通用前缀宽度）：H 位位于第 prefixBits 位，长度用 prefixBits 位前缀整数。
    /// HPACK 值串（7 位）、QPACK 值串（7 位）与 QPACK 名字串（3/5 位）共用。
    /// </summary>
    internal static string DecodePrefixedString(ReadOnlySpan<byte> block, ref int position, int prefixBits)
    {
        var huffman = (block[position] & (1 << prefixBits)) != 0;
        var length = DecodeInteger(block, ref position, prefixBits);
        if (length < 0 || position + length > block.Length) throw new InvalidDataException("字符串长度越界");
        var slice = block.Slice(position, length);
        position += length;
        return huffman ? DecodeHuffman(slice) : Encoding.Latin1.GetString(slice);
    }

    /// <summary>Huffman 解码：按位走树；结尾只允许不足 8 位的全 1 填充（EOS 前缀）。</summary>
    internal static string DecodeHuffman(ReadOnlySpan<byte> data)
    {
        var output = new StringBuilder(data.Length * 2);
        var node = HuffmanRoot;
        var trailingBits = 0;
        var trailingAllOnes = true;
        foreach (var item in data)
        {
            for (var bitIndex = 7; bitIndex >= 0; bitIndex--)
            {
                var bit = (item >> bitIndex) & 1;
                trailingBits++;
                if (bit == 0) trailingAllOnes = false;
                node = bit == 0 ? node.Zero : node.One;
                if (node is null) throw new InvalidDataException("Huffman 码字无效");
                if (node.Symbol >= 0)
                {
                    if (node.Symbol == 256) throw new InvalidDataException("Huffman 流中出现 EOS 符号");
                    output.Append((char)node.Symbol);
                    node = HuffmanRoot;
                    trailingBits = 0;
                    trailingAllOnes = true;
                }
            }
        }
        if (trailingBits >= 8 || !trailingAllOnes) throw new InvalidDataException("Huffman 填充无效");
        return output.ToString();
    }

    private static HuffmanNode BuildHuffmanTree()
    {
        var root = new HuffmanNode();
        for (var symbol = 0; symbol < HuffmanTable.Length; symbol++)
        {
            var (code, length) = HuffmanTable[symbol];
            var node = root;
            for (var bitIndex = length - 1; bitIndex >= 0; bitIndex--)
            {
                var bit = (code >> bitIndex) & 1;
                var next = bit == 0 ? node.Zero : node.One;
                if (next is null)
                {
                    next = new HuffmanNode();
                    if (bit == 0) node.Zero = next; else node.One = next;
                }
                node = next;
            }
            node.Symbol = symbol;
        }
        return root;
    }

    private void AddDynamic(string name, string value)
    {
        // RFC 7541 4.1：条目大小 = 名字长度 + 值长度 + 32
        _dynamicTable.Insert(0, (name, value));
        _dynamicTableSize += name.Length + value.Length + 32;
        Evict();
    }

    private void Evict()
    {
        while (_dynamicTable.Count > 0 && _dynamicTableSize > _maxDynamicTableSize)
        {
            var (name, value) = _dynamicTable[^1];
            _dynamicTable.RemoveAt(_dynamicTable.Count - 1);
            _dynamicTableSize -= name.Length + value.Length + 32;
        }
    }
}
