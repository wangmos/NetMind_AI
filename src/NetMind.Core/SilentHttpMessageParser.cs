using System.Text;

namespace NetMind.Core;

/// <summary>从重组字节流中解析出的一条完整 HTTP/1.x 消息。</summary>
public sealed record SilentHttpMessage(
    string StartLine,
    string HeaderText,
    IReadOnlyDictionary<string, string> Headers,
    byte[] Body,
    bool BodyTruncated);

/// <summary>
/// HTTP/1.x 消息增量解析器（纯逻辑）：在重组后的字节流上切分消息，
/// 支持 Content-Length、chunked 与连接关闭截止三种正文语义；头部与正文均有硬上限。
/// 起始行非法时标记 <see cref="NotHttp"/>，调用方按非 HTTP 流处理。
/// </summary>
public sealed class SilentHttpMessageParser
{
    private static readonly byte[] HeaderTerminator = [13, 10, 13, 10];
    private static readonly byte[] Crlf = [13, 10];

    private enum BodyMode { None, ContentLength, Chunked, UntilClose }

    private sealed class MessageBuilder
    {
        public required string StartLine;
        public required string HeaderText;
        public required Dictionary<string, string> Headers;
        public BodyMode Mode;
        public long RemainingContentLength;
        public bool BodyTruncated;
        public readonly MemoryStream Body = new();
    }

    private readonly bool _isRequest;
    private readonly List<byte> _buffer = [];
    private MessageBuilder? _current;

    public SilentHttpMessageParser(bool isRequest)
    {
        _isRequest = isRequest;
    }

    /// <summary>起始行不是合法 HTTP/1.x（或头部超限）时为真。</summary>
    public bool NotHttp { get; private set; }

    /// <summary>已解析完成的消息队列（按流序）。</summary>
    public Queue<SilentHttpMessage> Completed { get; } = new();

    /// <summary>尚未消费的缓冲字节数（供外部做内存护栏）。</summary>
    public int BufferedBytes => _buffer.Count;

    public void Feed(ReadOnlySpan<byte> data)
    {
        if (NotHttp) return;
        foreach (var value in data) _buffer.Add(value);
        while (!NotHttp && TryAdvance(streamClosed: false)) { }
    }

    /// <summary>连接关闭结算：完成“读到关闭为止”的正文，其余未完整消息按截断完成。</summary>
    public void Close()
    {
        if (NotHttp) return;
        while (TryAdvance(streamClosed: true)) { }
        if (_current is null) return;
        _current.BodyTruncated = _current.Mode is BodyMode.ContentLength && _current.RemainingContentLength > 0
            || _current.BodyTruncated;
        Complete(_current);
        _current = null;
    }

    private bool TryAdvance(bool streamClosed)
    {
        if (_current is null) return TryReadHeaders();
        return _current.Mode switch
        {
            BodyMode.ContentLength => TryReadContentLengthBody(streamClosed),
            BodyMode.Chunked => TryReadChunkedBody(streamClosed),
            BodyMode.UntilClose => TryReadUntilCloseBody(streamClosed),
            _ => false
        };
    }

    private bool TryReadHeaders()
    {
        var span = CollectionsMarshalSpan();
        var index = IndexOf(span, HeaderTerminator);
        if (index < 0)
        {
            if (_buffer.Count > NetMindDefaults.SilentMaximumHeaderBytes) NotHttp = true;
            return false;
        }
        var headerText = Encoding.Latin1.GetString(span[..index]);
        var lines = headerText.Split("\r\n", StringSplitOptions.RemoveEmptyEntries);
        if (lines.Length == 0 || !IsValidStartLine(lines[0]))
        {
            NotHttp = true;
            return false;
        }
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var formatted = new List<string>();
        foreach (var line in lines.Skip(1))
        {
            var separator = line.IndexOf(':');
            if (separator <= 0) continue;
            var name = line[..separator].Trim();
            var value = line[(separator + 1)..].Trim();
            headers.TryAdd(name, value);
            formatted.Add($"{name}: {value}");
        }
        _buffer.RemoveRange(0, index + HeaderTerminator.Length);

        var builder = new MessageBuilder
        {
            StartLine = lines[0],
            HeaderText = string.Join(Environment.NewLine, formatted),
            Headers = headers
        };
        builder.Mode = ResolveBodyMode(builder, out builder.RemainingContentLength);
        if (builder.Mode == BodyMode.None && builder.RemainingContentLength == 0)
        {
            Complete(builder);
            return true;
        }
        if (builder.Mode == BodyMode.ContentLength && builder.RemainingContentLength == 0)
        {
            Complete(builder);
            return true;
        }
        _current = builder;
        return true;
    }

    private BodyMode ResolveBodyMode(MessageBuilder builder, out long contentLength)
    {
        contentLength = 0;
        if (builder.Headers.TryGetValue("Content-Length", out var lengthText) &&
            long.TryParse(lengthText.Trim(), out contentLength) && contentLength >= 0)
            return BodyMode.ContentLength;
        if (builder.Headers.TryGetValue("Transfer-Encoding", out var encoding) &&
            encoding.Contains("chunked", StringComparison.OrdinalIgnoreCase))
            return BodyMode.Chunked;
        if (_isRequest) return BodyMode.None;
        var statusCode = ParseStatusCode(builder.StartLine);
        if (statusCode is 204 or 304 || statusCode is >= 100 and < 200) return BodyMode.None;
        return BodyMode.UntilClose;
    }

    private bool TryReadContentLengthBody(bool streamClosed)
    {
        var builder = _current!;
        while (builder.RemainingContentLength > 0)
        {
            if (_buffer.Count == 0)
            {
                if (streamClosed) { builder.BodyTruncated = true; Complete(builder); _current = null; return true; }
                return false;
            }
            var take = (int)Math.Min(_buffer.Count, builder.RemainingContentLength);
            if (builder.Body.Length < NetMindDefaults.SilentMaximumBodyBytes)
            {
                var keep = (int)Math.Min(take, NetMindDefaults.SilentMaximumBodyBytes - builder.Body.Length);
                builder.Body.Write(CollectionsMarshalSpan()[..keep]);
                if (keep < take) builder.BodyTruncated = true;
            }
            else
            {
                builder.BodyTruncated = true;
            }
            _buffer.RemoveRange(0, take);
            builder.RemainingContentLength -= take;
        }
        Complete(builder);
        _current = null;
        return true;
    }

    private bool TryReadChunkedBody(bool streamClosed)
    {
        var builder = _current!;
        while (true)
        {
            var span = CollectionsMarshalSpan();
            var lineEnd = IndexOf(span, Crlf);
            if (lineEnd < 0)
            {
                if (_buffer.Count > NetMindDefaults.SilentMaximumHeaderBytes) { NotHttp = true; return false; }
                if (streamClosed) { builder.BodyTruncated = true; Complete(builder); _current = null; return true; }
                return false;
            }
            var sizeText = Encoding.ASCII.GetString(span[..lineEnd]).Split(';', 2)[0].Trim();
            if (!long.TryParse(sizeText, System.Globalization.NumberStyles.HexNumber, null, out var chunkSize) || chunkSize < 0)
            {
                NotHttp = true;
                return false;
            }
            if (chunkSize == 0)
            {
                // 终结块：跳过 0\r\n 之后直到 trailer 段的空行
                var trailerStart = lineEnd + Crlf.Length;
                var trailerEnd = IndexOf(span[trailerStart..], HeaderTerminator);
                var singleTerminator = IndexOf(span[trailerStart..], Crlf);
                if (trailerEnd < 0 && singleTerminator != 0)
                {
                    if (streamClosed) { Complete(builder); _current = null; return true; }
                    return false;
                }
                var consumed = trailerEnd >= 0
                    ? trailerStart + trailerEnd + HeaderTerminator.Length
                    : trailerStart + Crlf.Length;
                _buffer.RemoveRange(0, consumed);
                Complete(builder);
                _current = null;
                return true;
            }
            var required = lineEnd + Crlf.Length + chunkSize + Crlf.Length;
            if (_buffer.Count < required)
            {
                if (streamClosed) { builder.BodyTruncated = true; Complete(builder); _current = null; return true; }
                return false;
            }
            var chunkStart = lineEnd + Crlf.Length;
            if (builder.Body.Length < NetMindDefaults.SilentMaximumBodyBytes)
            {
                var keep = (int)Math.Min(chunkSize, NetMindDefaults.SilentMaximumBodyBytes - builder.Body.Length);
                builder.Body.Write(span.Slice(chunkStart, (int)keep));
                if (keep < chunkSize) builder.BodyTruncated = true;
            }
            else
            {
                builder.BodyTruncated = true;
            }
            _buffer.RemoveRange(0, (int)required);
        }
    }

    private bool TryReadUntilCloseBody(bool streamClosed)
    {
        if (!streamClosed) return false;
        var builder = _current!;
        var keep = Math.Min(_buffer.Count, NetMindDefaults.SilentMaximumBodyBytes - (int)builder.Body.Length);
        if (keep > 0) builder.Body.Write(CollectionsMarshalSpan()[..(int)keep]);
        if (_buffer.Count > keep) builder.BodyTruncated = true;
        _buffer.Clear();
        Complete(builder);
        _current = null;
        return true;
    }

    private void Complete(MessageBuilder builder)
    {
        Completed.Enqueue(new SilentHttpMessage(builder.StartLine, builder.HeaderText, builder.Headers,
            builder.Body.ToArray(), builder.BodyTruncated));
    }

    private bool IsValidStartLine(string line)
    {
        var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (_isRequest)
        {
            return parts.Length == 3 && parts[2] is "HTTP/1.0" or "HTTP/1.1" &&
                   parts[0].Length <= 16 && parts[0].All(character => char.IsAsciiLetterUpper(character));
        }
        return parts.Length >= 2 && parts[0] is "HTTP/1.0" or "HTTP/1.1" &&
               parts[1].Length == 3 && parts[1].All(char.IsAsciiDigit);
    }

    private static int ParseStatusCode(string startLine)
    {
        var parts = startLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        return parts.Length >= 2 && int.TryParse(parts[1], out var code) ? code : 0;
    }

    private ReadOnlySpan<byte> CollectionsMarshalSpan() =>
        System.Runtime.InteropServices.CollectionsMarshal.AsSpan(_buffer);

    private static int IndexOf(ReadOnlySpan<byte> source, ReadOnlySpan<byte> pattern)
    {
        var index = source.IndexOf(pattern);
        return index;
    }
}
