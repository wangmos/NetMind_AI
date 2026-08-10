using System.Text;

namespace NetMind.Core;

public static class TrafficCopyFormatter
{
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    public static string BuildRawEvidence(TrafficRecord traffic, string requestBody, string responseBody)
    {
        var builder = new StringBuilder();
        AppendSection(builder, "事务", $"{traffic.Method} {traffic.Endpoint}\n状态：{traffic.StatusCode}\n协议：{traffic.Protocol}\n进程：{traffic.Process}\n时间：{traffic.Timestamp.ToLocalTime():yyyy-MM-dd HH:mm:ss.fff}\n延迟：{traffic.LatencyMs} 毫秒\n大小：{traffic.SizeBytes} 字节");
        AppendSection(builder, "完整 URL", EmptyFallback(traffic.Url, "历史记录未保存完整 URL"));
        AppendSection(builder, "查询参数", EmptyFallback(traffic.QueryParameters, "无查询参数"));
        AppendSection(builder, "Cookie", EmptyFallback(traffic.Cookies, "无 Cookie"));
        AppendSection(builder, "请求头", EmptyFallback(traffic.RequestHeaders, "无请求头"));
        AppendSection(builder, "请求正文", EmptyFallback(requestBody, "（空正文）"));
        AppendSection(builder, "响应头", EmptyFallback(traffic.ResponseHeaders, "无响应头"));
        AppendSection(builder, "响应正文", EmptyFallback(responseBody, "（空正文）"));
        return builder.ToString().TrimEnd();
    }

    public static string BuildPowerShellCurl(TrafficRecord traffic, ReadOnlySpan<byte> requestBody)
    {
        if (traffic.Method.Equals("CONNECT", StringComparison.OrdinalIgnoreCase) ||
            traffic.Protocol.Contains("隧道", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("HTTPS CONNECT 是加密隧道，无法生成可重放的 cURL 请求。");
        if (!Uri.TryCreate(traffic.Url, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https"))
            throw new InvalidOperationException("当前记录没有可用于重放的完整 HTTP URL。");

        var builder = new StringBuilder("curl.exe --request ")
            .Append(QuotePowerShell(traffic.Method))
            .Append(" --url ")
            .Append(QuotePowerShell(uri.AbsoluteUri));
        foreach (var header in ParseHeaderLines(traffic.RequestHeaders))
        {
            if (header.Name.Equals("Host", StringComparison.OrdinalIgnoreCase) ||
                header.Name.Equals("Content-Length", StringComparison.OrdinalIgnoreCase) ||
                header.Name.Equals("Connection", StringComparison.OrdinalIgnoreCase) ||
                header.Name.Equals("Proxy-Connection", StringComparison.OrdinalIgnoreCase)) continue;
            builder.Append(" `\n  --header ").Append(QuotePowerShell(header.Name + ": " + header.Value));
        }
        if (!requestBody.IsEmpty)
        {
            string body;
            try { body = StrictUtf8.GetString(requestBody); }
            catch (DecoderFallbackException)
            {
                throw new InvalidOperationException("请求正文包含二进制数据，无法安全生成文本 cURL 命令。");
            }
            if (body.IndexOf('\0') >= 0)
                throw new InvalidOperationException("请求正文包含二进制数据，无法安全生成文本 cURL 命令。");
            builder.Append(" `\n  --data-binary ").Append(QuotePowerShell(body));
        }
        return builder.ToString();
    }

    private static IEnumerable<(string Name, string Value)> ParseHeaderLines(string value)
    {
        foreach (var line in value.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
        {
            var separator = line.IndexOf(':');
            if (separator <= 0) continue;
            yield return (line[..separator].Trim(), line[(separator + 1)..].Trim());
        }
    }

    private static string QuotePowerShell(string value) => "'" + value.Replace("'", "''", StringComparison.Ordinal) + "'";

    private static string EmptyFallback(string value, string fallback) => string.IsNullOrWhiteSpace(value) ? fallback : value;

    private static void AppendSection(StringBuilder builder, string title, string content)
    {
        if (builder.Length > 0) builder.AppendLine().AppendLine();
        builder.Append("【").Append(title).AppendLine("】").Append(content);
    }
}
