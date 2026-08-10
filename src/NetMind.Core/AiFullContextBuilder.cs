using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace NetMind.Core;

/// <summary>
/// 单条事务进入 AI 上下文的完整原始投影：URL、查询参数、请求头、Cookie、响应头原样保留，
/// 请求与响应正文以文本形式完整携带（二进制正文只保留有界十六进制预览）。不做任何脱敏。
/// </summary>
public sealed record AiFullTransactionContext(
    string Method,
    string Url,
    string Endpoint,
    int StatusCode,
    int LatencyMilliseconds,
    long SizeBytes,
    string Protocol,
    string Process,
    string CaptureMode,
    string QueryParameters,
    string RequestHeaders,
    string Cookies,
    string ResponseHeaders,
    string RequestBody,
    bool RequestBodyTruncated,
    string ResponseBody,
    bool ResponseBodyTruncated);

/// <summary>
/// AI 完整上下文构建器：把已持久化事务连同 Blob 正文组装为发送给模型的原始 JSON。
/// 面向测试账号数据场景，完整数据直接发送，不经 <see cref="AiPrivacyFilter"/> 脱敏。
/// 正文只保留与参数溯源相关的文本类内容（HTML/纯文本/JS/JSON/XML 等），
/// 图片、CSS、字体、音视频等无关资源按 Content-Type 直接省略，不读 Blob 也不进入上下文。
/// </summary>
public static class AiFullContextBuilder
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    /// <summary>
    /// 构建完整上下文 JSON。事务条数超过宽松安全上限时拒绝（不静默裁剪）；
    /// 单个正文超过 <see cref="NetMindDefaults.AiMaximumBodyBytesPerTransaction"/> 时截断并显式标记；
    /// 图片/CSS 等非分析相关正文按 Content-Type 省略；
    /// 总体积超过 <see cref="NetMindDefaults.AiMaximumFullContextBytes"/> 时拒绝。
    /// </summary>
    public static async Task<string> BuildJsonAsync(
        IReadOnlyList<StoredTrafficRecord> records,
        Func<string, CancellationToken, Task<StoredBlobContent>> readBlobAsync,
        CancellationToken cancellationToken = default)
    {
        if (records.Count == 0) throw new InvalidOperationException("没有可发送给模型的流量证据。");
        if (records.Count > NetMindDefaults.AiMaximumEvidenceTransactions)
            throw new InvalidOperationException("AI 分析范围超过上限，请减少所选事务。");

        var transactions = new List<AiFullTransactionContext>(records.Count);
        foreach (var record in records)
        {
            cancellationToken.ThrowIfCancellationRequested();
            transactions.Add(await BuildTransactionAsync(record, readBlobAsync, cancellationToken));
        }

        var json = JsonSerializer.Serialize(new { transactions }, JsonOptions);
        if (Encoding.UTF8.GetByteCount(json) > NetMindDefaults.AiMaximumFullContextBytes)
            throw new InvalidOperationException(
                $"完整上下文超过 {NetMindDefaults.AiMaximumFullContextBytes / 1024 / 1024} MB 上限，请减少所选事务。");
        return json;
    }

    /// <summary>
    /// 构建单条事务的完整原始投影：对话式分析中 tool_call 按序号取数的最小单元，
    /// 与批量路径共用同一套正文过滤、二进制预览与截断规则。
    /// </summary>
    public static async Task<AiFullTransactionContext> BuildTransactionAsync(
        StoredTrafficRecord record,
        Func<string, CancellationToken, Task<StoredBlobContent>> readBlobAsync,
        CancellationToken cancellationToken = default)
    {
        var traffic = record.Traffic;
        var (requestBody, requestTruncated) = await ReadBodyAsync(record.RequestBlobHash,
            ExtractContentType(traffic.RequestHeaders), readBlobAsync, cancellationToken);
        var (responseBody, responseTruncated) = await ReadBodyAsync(record.ResponseBlobHash,
            ExtractContentType(traffic.ResponseHeaders), readBlobAsync, cancellationToken);
        return new AiFullTransactionContext(
            traffic.Method,
            traffic.Url,
            traffic.Endpoint,
            traffic.StatusCode,
            traffic.LatencyMs,
            traffic.SizeBytes,
            traffic.Protocol,
            traffic.Process,
            record.CaptureMode,
            traffic.QueryParameters,
            traffic.RequestHeaders,
            traffic.Cookies,
            traffic.ResponseHeaders,
            requestBody,
            requestTruncated,
            responseBody,
            responseTruncated);
    }

    /// <summary>构建多条事务的 JSON（不做 16 MB 总体积拒绝；正文读取上限由调用方决定，
    /// 总体积再由会话引擎的单轮取数预算承担）。</summary>
    public static async Task<string> BuildTransactionsJsonAsync(
        IReadOnlyList<StoredTrafficRecord> records,
        Func<string, CancellationToken, Task<StoredBlobContent>> readBlobAsync,
        CancellationToken cancellationToken = default)
    {
        var transactions = new List<AiFullTransactionContext>(records.Count);
        foreach (var record in records)
        {
            cancellationToken.ThrowIfCancellationRequested();
            transactions.Add(await BuildTransactionAsync(record, readBlobAsync, cancellationToken));
        }
        return JsonSerializer.Serialize(new { transactions }, JsonOptions);
    }

    private static async Task<(string Body, bool Truncated)> ReadBodyAsync(
        string blobHash,
        string? contentType,
        Func<string, CancellationToken, Task<StoredBlobContent>> readBlobAsync,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(blobHash)) return (string.Empty, false);
        // 图片、CSS、字体、音视频等与参数溯源无关的资源：不读 Blob，直接标记省略，避免无关数据挤占模型上下文。
        if (!IsAiRelevantContentType(contentType))
            return ($"[正文已省略：{contentType} 属图片/CSS 等非分析相关资源，不喂给模型]", false);
        StoredBlobContent blob;
        try
        {
            blob = await readBlobAsync(blobHash, cancellationToken);
        }
        catch (FileNotFoundException)
        {
            return ("[正文缺失：内容寻址存储中不存在该哈希]", false);
        }
        var truncated = blob.Truncated;
        if (blob.Content.Length == 0) return (string.Empty, truncated);
        if (LooksLikeBinary(blob.Content))
        {
            var preview = Convert.ToHexString(blob.Content[..Math.Min(blob.Content.Length, NetMindDefaults.BlobHexPreviewBytes)]).ToLowerInvariant();
            return ($"[二进制正文 {blob.OriginalLength:N0} 字节，十六进制预览] {preview}", true);
        }
        var text = Encoding.UTF8.GetString(blob.Content);
        if (truncated) text += $"\n[正文已按本次读取上限截断；保留 {blob.Content.Length:N0} 字节，原始大小 {blob.OriginalLength:N0} 字节]";
        return (text, truncated);
    }

    /// <summary>从请求/响应头文本中提取 Content-Type（不存在时返回 null）。</summary>
    private static string? ExtractContentType(string headers)
    {
        foreach (var line in headers.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
        {
            var separator = line.IndexOf(':');
            if (separator <= 0) continue;
            if (!line[..separator].Trim().Equals("Content-Type", StringComparison.OrdinalIgnoreCase)) continue;
            var value = line[(separator + 1)..].Trim();
            if (value.Length > 0) return value;
        }
        return null;
    }

    /// <summary>
    /// 判定正文是否与 AI 分析相关：只放行 HTML、纯文本、JS、JSON、XML 与表单类文本内容；
    /// 图片、CSS、字体、音视频、wasm 与各类二进制容器一律排除。
    /// Content-Type 缺失时不在此拒绝，交给二进制启发式判定兜底。
    /// </summary>
    private static bool IsAiRelevantContentType(string? contentType)
    {
        if (string.IsNullOrWhiteSpace(contentType)) return true;
        var mediaType = contentType.Split(';')[0].Trim().ToLowerInvariant();
        if (mediaType.StartsWith("text/", StringComparison.Ordinal)) return mediaType != "text/css";
        return mediaType switch
        {
            "application/json" or "application/javascript" or "application/x-javascript" or "application/ecmascript"
                or "application/xml" or "application/x-www-form-urlencoded" or "multipart/form-data" => true,
            _ => mediaType.EndsWith("+json", StringComparison.Ordinal) || mediaType.EndsWith("+xml", StringComparison.Ordinal)
        };
    }

    /// <summary>按 NUL 字节与 UTF-8 严格解码启发式判定二进制正文。</summary>
    private static bool LooksLikeBinary(byte[] content)
    {
        var probe = content.AsSpan(0, Math.Min(content.Length, 8 * 1024));
        if (probe.Contains((byte)0)) return true;
        try
        {
            var strict = new UTF8Encoding(false, true);
            strict.GetString(content.AsSpan(0, Math.Min(content.Length, 64 * 1024)));
            return false;
        }
        catch (DecoderFallbackException)
        {
            return true;
        }
    }
}
