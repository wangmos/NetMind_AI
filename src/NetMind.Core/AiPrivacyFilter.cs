using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Encodings.Web;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace NetMind.Core;

public sealed record AiTrafficContext(
    string Method,
    string Endpoint,
    int StatusCode,
    int LatencyMilliseconds,
    string Protocol,
    string Process,
    string Url,
    string QueryParameters,
    string RequestHeaders,
    string Cookies,
    string ResponseHeaders,
    string RequestSummary,
    string ResponseSummary);

public static class AiPrivacyFilter
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    public static AiTrafficContext CreateContext(TrafficRecord traffic) => new(
        traffic.Method,
        WorkspaceStore.RedactUrl(traffic.Endpoint),
        traffic.StatusCode,
        traffic.LatencyMs,
        traffic.Protocol,
        traffic.Process,
        WorkspaceStore.RedactUrl(traffic.Url),
        RedactNamedLines(traffic.QueryParameters, '='),
        RedactHeaders(traffic.RequestHeaders),
        RedactCookies(traffic.Cookies),
        RedactHeaders(traffic.ResponseHeaders),
        WorkspaceStore.Redact(traffic.RequestSummary),
        WorkspaceStore.Redact(traffic.ResponseSummary));

    public static string BuildJson(IEnumerable<TrafficRecord> traffic, int maximumTransactions = 50)
    {
        maximumTransactions = Math.Clamp(maximumTransactions, 1, NetMindDefaults.AiMaximumEvidenceTransactions);
        return JsonSerializer.Serialize(traffic.Take(maximumTransactions).Select(CreateContext), JsonOptions);
    }

    /// <summary>
    /// 面向脚本沙箱的脱敏 fixture 事务条数上限，字段名与 <see cref="RedactedScriptTransaction"/> 一致。
    /// </summary>
    public const int ScriptFixtureMaximumTransactions = 30;

    /// <summary>
    /// 面向脚本沙箱的脱敏流量投影；所有字段都复用与 AI 上下文相同的脱敏逻辑，绝不携带原始敏感值。
    /// </summary>
    public sealed record RedactedScriptTransaction(
        [property: JsonPropertyName("method")] string Method,
        [property: JsonPropertyName("url")] string Url,
        [property: JsonPropertyName("host")] string Host,
        [property: JsonPropertyName("endpoint")] string Endpoint,
        [property: JsonPropertyName("status")] int Status,
        [property: JsonPropertyName("latency_ms")] int LatencyMs,
        [property: JsonPropertyName("size_bytes")] long SizeBytes,
        [property: JsonPropertyName("protocol")] string Protocol,
        [property: JsonPropertyName("process")] string Process,
        [property: JsonPropertyName("request_summary")] string RequestSummary,
        [property: JsonPropertyName("response_summary")] string ResponseSummary);

    private static readonly Regex SensitiveNamedValuePattern = new(
        "(?i)(^|[\\s,;\"'])([^\\s,;\"':=]*(?:token|key|secret|auth|session|cookie|password)[^\\s,;\"':=]*)([:=])([^,;\\s\"']+)",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    public static RedactedScriptTransaction CreateScriptTransaction(TrafficRecord traffic)
    {
        var context = CreateContext(traffic);
        return new RedactedScriptTransaction(
            traffic.Method,
            context.Url,
            ResolveScriptHost(traffic),
            context.Endpoint,
            traffic.StatusCode,
            traffic.LatencyMs,
            traffic.SizeBytes,
            traffic.Protocol,
            traffic.Process,
            RedactScriptSummary(traffic.RequestSummary),
            RedactScriptSummary(traffic.ResponseSummary));
    }

    /// <summary>
    /// 脚本 fixture 专用的摘要脱敏：在通用正则脱敏之外，对“敏感名: 多词值”形式（如 Authorization: Bearer xxx）整段替换，
    /// 堵住冒号后带空格时通用正则只命中前半段导致的泄漏。
    /// </summary>
    private static string RedactScriptSummary(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return string.Empty;
        return string.Join(Environment.NewLine, value.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries).Select(line =>
        {
            var separator = line.IndexOf(':');
            if (separator <= 0) return SensitiveNamedValuePattern.Replace(WorkspaceStore.Redact(line), "$1$2$3" + NetMindDefaults.RedactedPlaceholder);
            var name = line[..separator].Trim();
            if (!IsSensitiveHeader(name)) return SensitiveNamedValuePattern.Replace(WorkspaceStore.Redact(line), "$1$2$3" + NetMindDefaults.RedactedPlaceholder);
            return name + ": " + NetMindDefaults.RedactedPlaceholder;
        }));
    }

    public static string BuildScriptFixture(IEnumerable<TrafficRecord> traffic) =>
        JsonSerializer.Serialize(new { transactions = traffic.Take(ScriptFixtureMaximumTransactions).Select(CreateScriptTransaction) }, JsonOptions);

    private static string ResolveScriptHost(TrafficRecord traffic)
    {
        if (Uri.TryCreate(traffic.Url, UriKind.Absolute, out var uri) && !string.IsNullOrWhiteSpace(uri.Host))
            return uri.IsDefaultPort ? uri.Host : uri.Authority;
        if (traffic.Method.Equals("CONNECT", StringComparison.OrdinalIgnoreCase) &&
            Uri.TryCreate("https://" + traffic.Endpoint, UriKind.Absolute, out uri) && !string.IsNullOrWhiteSpace(uri.Host))
            return uri.IsDefaultPort ? uri.Host : uri.Authority;
        return string.Empty;
    }

    public static string RedactText(string text) => WorkspaceStore.Redact(text);

    /// <summary>
    /// 外部导出文本专用脱敏：有效 JSON 按属性名递归脱敏；普通文本处理 URL 查询值、Header/Cookie 行与
    /// token/key/secret/auth/session/cookie/password 等命名值。只改变导出副本，不修改本地会话原文。
    /// </summary>
    public static string RedactExportText(string text)
    {
        if (string.IsNullOrEmpty(text)) return string.Empty;
        try
        {
            var node = JsonNode.Parse(text);
            if (node is not null)
                return RedactJsonNode(node, null)!.ToJsonString(new JsonSerializerOptions(JsonOptions) { WriteIndented = true });
        }
        catch (JsonException) { /* 非 JSON 按普通文本处理 */ }

        return string.Join('\n', text.Replace("\r\n", "\n", StringComparison.Ordinal).Replace('\r', '\n')
            .Split('\n').Select(RedactExportLine));
    }

    private static JsonNode? RedactJsonNode(JsonNode? node, string? propertyName)
    {
        if (node is null) return null;
        if (!string.IsNullOrWhiteSpace(propertyName) && IsSensitiveName(propertyName))
            return JsonValue.Create(NetMindDefaults.RedactedPlaceholder);
        if (node is JsonObject sourceObject)
        {
            var result = new JsonObject();
            foreach (var property in sourceObject)
                result[property.Key] = RedactJsonNode(property.Value, property.Key);
            return result;
        }
        if (node is JsonArray sourceArray)
        {
            var result = new JsonArray();
            foreach (var item in sourceArray) result.Add(RedactJsonNode(item, propertyName));
            return result;
        }
        if (node is JsonValue value && value.TryGetValue<string>(out var textValue))
            return JsonValue.Create(RedactExportLine(textValue));
        return node.DeepClone();
    }

    private static string RedactExportLine(string line)
    {
        var redacted = WorkspaceStore.RedactUrl(line);
        var separator = redacted.IndexOfAny([':', '=']);
        if (separator > 0)
        {
            var name = redacted[..separator].Trim().Trim('"', '\'', '-', '*', '#', ' ', '\t');
            if (IsSensitiveHeader(name) || IsSensitiveName(name))
                return redacted[..(separator + 1)] + " " + NetMindDefaults.RedactedPlaceholder;
        }
        redacted = WorkspaceStore.Redact(redacted);
        return SensitiveNamedValuePattern.Replace(redacted, "$1$2$3" + NetMindDefaults.RedactedPlaceholder);
    }

    private static string RedactHeaders(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return string.Empty;
        return string.Join(Environment.NewLine, value.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries).Select(line =>
        {
            var separator = line.IndexOf(':');
            if (separator <= 0) return WorkspaceStore.Redact(line);
            var name = line[..separator].Trim();
            return name + ": " + (IsSensitiveHeader(name) ? NetMindDefaults.RedactedPlaceholder : WorkspaceStore.Redact(line[(separator + 1)..].Trim()));
        }));
    }

    private static string RedactCookies(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return string.Empty;
        return string.Join(Environment.NewLine, value.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries).Select(line =>
        {
            var separator = line.IndexOf('=');
            return (separator <= 0 ? line.Trim() : line[..separator].Trim()) + " = " + NetMindDefaults.RedactedPlaceholder;
        }));
    }

    private static string RedactNamedLines(string value, char separatorCharacter)
    {
        if (string.IsNullOrWhiteSpace(value)) return string.Empty;
        return string.Join(Environment.NewLine, value.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries).Select(line =>
        {
            var separator = line.IndexOf(separatorCharacter);
            if (separator <= 0) return WorkspaceStore.Redact(line);
            var name = line[..separator].Trim();
            var content = line[(separator + 1)..].Trim();
            return name + " = " + (IsSensitiveName(name) ? NetMindDefaults.RedactedPlaceholder : WorkspaceStore.Redact(content));
        }));
    }

    private static bool IsSensitiveHeader(string name) => name.Equals("Authorization", StringComparison.OrdinalIgnoreCase) ||
        name.Equals("Proxy-Authorization", StringComparison.OrdinalIgnoreCase) ||
        name.Equals("Cookie", StringComparison.OrdinalIgnoreCase) ||
        name.Equals("Set-Cookie", StringComparison.OrdinalIgnoreCase) || IsSensitiveName(name);

    private static bool IsSensitiveName(string name) => new[] { "token", "key", "secret", "auth", "session", "cookie", "password" }
        .Any(part => name.Contains(part, StringComparison.OrdinalIgnoreCase));
}
