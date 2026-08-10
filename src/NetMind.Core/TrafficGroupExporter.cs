using System.IO.Compression;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace NetMind.Core;

public sealed record TrafficGroupExportResult(
    string Format,
    int ExportedTransactions,
    int MissingTransactions,
    long RequestBodyBytes,
    long ResponseBodyBytes,
    long OutputBytes);

/// <summary>
/// 将记录组导出为可移植的完整归档或 HAR 1.2。ZIP 保留原始元数据与内容寻址正文，
/// 并内置一份 HAR；独立 HAR 对文本正文写原文、对二进制正文写 Base64，不截断正文。
/// </summary>
public static class TrafficGroupExporter
{
    private const string PackageFormat = "netmind-traffic-group";
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    public static async Task<TrafficGroupExportResult> ExportZipAsync(
        string workspacePath,
        TrafficGroup group,
        string outputPath,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(group);
        var destination = PrepareDestination(outputPath);
        var temporaryPath = destination + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            using var archive = new TrafficArchive(workspacePath);
            var snapshot = CreateSnapshot(archive, group);
            var blobLengths = GetBlobLengths(archive, snapshot.Records);
            var requestBytes = snapshot.Records.Sum(record => blobLengths[record.RequestBlobHash]);
            var responseBytes = snapshot.Records.Sum(record => blobLengths[record.ResponseBlobHash]);

            await using (var output = new FileStream(temporaryPath, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                             128 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan))
            using (var zip = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: true, Encoding.UTF8))
            {
                var exportedAt = DateTimeOffset.UtcNow;
                await WriteJsonEntryAsync(zip, "manifest.json", new
                {
                    format = PackageFormat,
                    schemaVersion = 1,
                    exportedAt,
                    application = new { name = "NetMind AI", version = "0.8.0" },
                    group = new
                    {
                        group.Id,
                        group.Name,
                        group.Description,
                        group.CreatedAt,
                        group.UpdatedAt,
                        transactionIds = group.TrafficIds
                    },
                    exportedTransactions = snapshot.Records.Count,
                    missingTransactionIds = snapshot.MissingIds,
                    requestBodyBytes = requestBytes,
                    responseBodyBytes = responseBytes,
                    files = new
                    {
                        transactions = "transactions.json",
                        har = "traffic-group.har",
                        blobs = "blobs/<sha256-prefix>/<sha256>.bin"
                    }
                }, cancellationToken);

                var transactionIndex = snapshot.Records.Select(record => new
                {
                    record.Traffic,
                    record.SessionId,
                    record.CaptureMode,
                    requestBody = new
                    {
                        sha256 = record.RequestBlobHash,
                        length = blobLengths[record.RequestBlobHash],
                        path = BlobEntryPath(record.RequestBlobHash)
                    },
                    responseBody = new
                    {
                        sha256 = record.ResponseBlobHash,
                        length = blobLengths[record.ResponseBlobHash],
                        path = BlobEntryPath(record.ResponseBlobHash)
                    }
                }).ToArray();
                await WriteJsonEntryAsync(zip, "transactions.json", transactionIndex, cancellationToken);

                var harEntry = zip.CreateEntry("traffic-group.har", CompressionLevel.Optimal);
                await using (var harStream = harEntry.Open())
                    await WriteHarDocumentAsync(harStream, archive, group, snapshot.Records, cancellationToken);

                foreach (var hash in blobLengths.Keys.Order(StringComparer.Ordinal))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var entry = zip.CreateEntry(BlobEntryPath(hash), CompressionLevel.Optimal);
                    await using var target = entry.Open();
                    await using var source = archive.OpenBlobRead(hash);
                    await source.CopyToAsync(target, 128 * 1024, cancellationToken);
                }

                var readme = zip.CreateEntry("README.txt", CompressionLevel.Optimal);
                await using (var stream = readme.Open())
                {
                    var text = "NetMind AI 记录组完整归档\r\n\r\n" +
                               "manifest.json       导出清单、记录组信息与缺失事务列表\r\n" +
                               "transactions.json   全部事务元数据与正文 SHA-256 引用\r\n" +
                               "traffic-group.har   可导入其他 HTTP/HAR 分析工具的 HAR 1.2\r\n" +
                               "blobs/               未截断的原始请求/响应正文字节，按 SHA-256 去重\r\n\r\n" +
                               "该归档是本地所有者原始导出，可能包含 Header、Cookie、令牌和正文敏感数据。\r\n";
                    await stream.WriteAsync(Encoding.UTF8.GetBytes(text), cancellationToken);
                }
            }

            File.Move(temporaryPath, destination, overwrite: true);
            return new TrafficGroupExportResult("zip", snapshot.Records.Count, snapshot.MissingIds.Length,
                requestBytes, responseBytes, new FileInfo(destination).Length);
        }
        finally
        {
            if (File.Exists(temporaryPath)) File.Delete(temporaryPath);
        }
    }

    public static async Task<TrafficGroupExportResult> ExportHarAsync(
        string workspacePath,
        TrafficGroup group,
        string outputPath,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(group);
        var destination = PrepareDestination(outputPath);
        var temporaryPath = destination + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            using var archive = new TrafficArchive(workspacePath);
            var snapshot = CreateSnapshot(archive, group);
            var blobLengths = GetBlobLengths(archive, snapshot.Records);
            var requestBytes = snapshot.Records.Sum(record => blobLengths[record.RequestBlobHash]);
            var responseBytes = snapshot.Records.Sum(record => blobLengths[record.ResponseBlobHash]);
            await using (var output = new FileStream(temporaryPath, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                             128 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan))
                await WriteHarDocumentAsync(output, archive, group, snapshot.Records, cancellationToken);
            File.Move(temporaryPath, destination, overwrite: true);
            return new TrafficGroupExportResult("har", snapshot.Records.Count, snapshot.MissingIds.Length,
                requestBytes, responseBytes, new FileInfo(destination).Length);
        }
        finally
        {
            if (File.Exists(temporaryPath)) File.Delete(temporaryPath);
        }
    }

    private static ExportSnapshot CreateSnapshot(TrafficArchive archive, TrafficGroup group)
    {
        if (group.Id == Guid.Empty) throw new InvalidDataException("记录组缺少有效标识。");
        if (group.TrafficIds.Count > 1000) throw new InvalidDataException("单个记录组最多导出 1,000 条事务。");
        var records = archive.GetTrafficByIds(group.TrafficIds)
            .OrderBy(record => record.Traffic.Timestamp)
            .ThenBy(record => record.Traffic.Id)
            .ToArray();
        var found = records.Select(record => record.Traffic.Id).ToHashSet();
        var missing = group.TrafficIds.Where(id => !found.Contains(id)).Distinct().ToArray();
        return new ExportSnapshot(records, missing);
    }

    private static Dictionary<string, long> GetBlobLengths(TrafficArchive archive, IReadOnlyList<StoredTrafficRecord> records)
    {
        var result = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
        foreach (var hash in records.SelectMany(record => new[] { record.RequestBlobHash, record.ResponseBlobHash })
                     .Distinct(StringComparer.OrdinalIgnoreCase))
        {
            using var stream = archive.OpenBlobRead(hash);
            result[hash] = stream.Length;
        }
        return result;
    }

    private static async Task WriteHarDocumentAsync(
        Stream output,
        TrafficArchive archive,
        TrafficGroup group,
        IReadOnlyList<StoredTrafficRecord> records,
        CancellationToken cancellationToken)
    {
        using var writer = new Utf8JsonWriter(output, new JsonWriterOptions { Indented = true });
        writer.WriteStartObject();
        writer.WritePropertyName("log");
        writer.WriteStartObject();
        writer.WriteString("version", "1.2");
        writer.WritePropertyName("creator");
        writer.WriteStartObject();
        writer.WriteString("name", "NetMind AI");
        writer.WriteString("version", "0.8.0");
        writer.WriteEndObject();
        writer.WritePropertyName("comment");
        writer.WriteStringValue($"NetMind 记录组：{group.Name}（{group.Id:N}）");
        writer.WritePropertyName("entries");
        writer.WriteStartArray();

        foreach (var record in records)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var requestBody = await ReadCompleteBlobAsync(archive, record.RequestBlobHash, cancellationToken);
            var responseBody = await ReadCompleteBlobAsync(archive, record.ResponseBlobHash, cancellationToken);
            WriteHarEntry(writer, record, requestBody, responseBody);
        }

        writer.WriteEndArray();
        writer.WriteEndObject();
        writer.WriteEndObject();
        await writer.FlushAsync(cancellationToken);
    }

    private static void WriteHarEntry(Utf8JsonWriter writer, StoredTrafficRecord stored, byte[] requestBody, byte[] responseBody)
    {
        var traffic = stored.Traffic;
        var requestHeaders = ParseHeaders(traffic.RequestHeaders);
        var responseHeaders = ParseHeaders(traffic.ResponseHeaders);
        var requestMime = HeaderValue(requestHeaders, "Content-Type") ?? string.Empty;
        var responseMime = HeaderValue(responseHeaders, "Content-Type") ?? string.Empty;
        var url = string.IsNullOrWhiteSpace(traffic.Url) ? traffic.Endpoint : traffic.Url;
        var httpVersion = NormalizeHttpVersion(traffic.Protocol);

        writer.WriteStartObject();
        writer.WriteString("startedDateTime", traffic.Timestamp.ToString("O"));
        writer.WriteNumber("time", Math.Max(0, traffic.LatencyMs));

        writer.WritePropertyName("request");
        writer.WriteStartObject();
        writer.WriteString("method", traffic.Method);
        writer.WriteString("url", url);
        writer.WriteString("httpVersion", httpVersion);
        WriteNameValueArray(writer, "cookies", ParseRequestCookies(traffic.Cookies, requestHeaders));
        WriteNameValueArray(writer, "headers", requestHeaders);
        WriteNameValueArray(writer, "queryString", ParseQuery(url));
        if (requestBody.Length > 0)
        {
            writer.WritePropertyName("postData");
            writer.WriteStartObject();
            writer.WriteString("mimeType", requestMime);
            WriteBodyText(writer, requestBody, requestMime, requestBodyEncodingProperty: "_encoding");
            writer.WriteEndObject();
        }
        writer.WriteNumber("headersSize", HeaderSize(traffic.RequestHeaders));
        writer.WriteNumber("bodySize", requestBody.LongLength);
        writer.WriteEndObject();

        writer.WritePropertyName("response");
        writer.WriteStartObject();
        writer.WriteNumber("status", traffic.StatusCode);
        writer.WriteString("statusText", ParseStatusText(traffic.ResponseHeaders));
        writer.WriteString("httpVersion", httpVersion);
        WriteNameValueArray(writer, "cookies", ParseResponseCookies(responseHeaders));
        WriteNameValueArray(writer, "headers", responseHeaders);
        writer.WritePropertyName("content");
        writer.WriteStartObject();
        writer.WriteNumber("size", responseBody.LongLength);
        writer.WriteString("mimeType", responseMime);
        if (responseBody.Length > 0) WriteBodyText(writer, responseBody, responseMime, requestBodyEncodingProperty: "encoding");
        writer.WriteEndObject();
        writer.WriteString("redirectURL", HeaderValue(responseHeaders, "Location") ?? string.Empty);
        writer.WriteNumber("headersSize", HeaderSize(traffic.ResponseHeaders));
        writer.WriteNumber("bodySize", responseBody.LongLength);
        writer.WriteEndObject();

        writer.WritePropertyName("cache");
        writer.WriteStartObject();
        writer.WriteEndObject();
        writer.WritePropertyName("timings");
        writer.WriteStartObject();
        writer.WriteNumber("blocked", -1);
        writer.WriteNumber("dns", -1);
        writer.WriteNumber("connect", -1);
        writer.WriteNumber("send", 0);
        writer.WriteNumber("wait", Math.Max(0, traffic.LatencyMs));
        writer.WriteNumber("receive", 0);
        writer.WriteNumber("ssl", -1);
        writer.WriteEndObject();

        writer.WritePropertyName("_netmind");
        writer.WriteStartObject();
        writer.WriteString("transactionId", traffic.Id);
        writer.WriteString("sessionId", stored.SessionId);
        writer.WriteString("captureMode", stored.CaptureMode);
        writer.WriteString("process", traffic.Process);
        writer.WriteString("protocol", traffic.Protocol);
        writer.WriteString("requestSummary", traffic.RequestSummary);
        writer.WriteString("responseSummary", traffic.ResponseSummary);
        writer.WriteString("requestBodySha256", stored.RequestBlobHash);
        writer.WriteString("responseBodySha256", stored.ResponseBlobHash);
        writer.WriteEndObject();
        writer.WriteEndObject();
    }

    private static void WriteBodyText(Utf8JsonWriter writer, byte[] body, string mimeType, string requestBodyEncodingProperty)
    {
        if (TryDecodeText(body, mimeType, out var text))
        {
            writer.WriteString("text", text);
            return;
        }
        writer.WriteBase64String("text", body);
        writer.WriteString(requestBodyEncodingProperty, "base64");
    }

    private static bool TryDecodeText(byte[] body, string mimeType, out string text)
    {
        text = string.Empty;
        var normalized = mimeType.Split(';', 2)[0].Trim();
        var declaredText = normalized.StartsWith("text/", StringComparison.OrdinalIgnoreCase) ||
                           normalized.Contains("json", StringComparison.OrdinalIgnoreCase) ||
                           normalized.Contains("xml", StringComparison.OrdinalIgnoreCase) ||
                           normalized.Contains("javascript", StringComparison.OrdinalIgnoreCase) ||
                           normalized.Contains("x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase) ||
                           normalized.Contains("graphql", StringComparison.OrdinalIgnoreCase);
        if (!declaredText && body.Any(value => value == 0)) return false;
        try
        {
            text = StrictUtf8.GetString(body);
            if (declaredText) return true;
            var controls = text.Count(character => char.IsControl(character) && character is not ('\r' or '\n' or '\t'));
            return controls <= Math.Max(1, text.Length / 100);
        }
        catch (DecoderFallbackException)
        {
            text = string.Empty;
            return false;
        }
    }

    private static async Task<byte[]> ReadCompleteBlobAsync(TrafficArchive archive, string hash, CancellationToken cancellationToken)
    {
        await using var stream = archive.OpenBlobRead(hash);
        if (stream.Length > int.MaxValue) throw new InvalidDataException("单个正文超过 2 GB，无法写入 HAR JSON；请使用 ZIP 完整归档。");
        var bytes = new byte[(int)stream.Length];
        if (bytes.Length > 0) await stream.ReadExactlyAsync(bytes, cancellationToken);
        return bytes;
    }

    private static List<NameValue> ParseHeaders(string raw)
    {
        var result = new List<NameValue>();
        foreach (var line in raw.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n'))
        {
            var separator = line.IndexOf(':');
            if (separator <= 0) continue;
            var name = line[..separator].Trim();
            if (name.Length == 0) continue;
            result.Add(new NameValue(name, line[(separator + 1)..].Trim()));
        }
        return result;
    }

    private static List<NameValue> ParseQuery(string url)
    {
        var result = new List<NameValue>();
        var question = url.IndexOf('?');
        if (question < 0) return result;
        var fragment = url.IndexOf('#', question + 1);
        var query = fragment < 0 ? url[(question + 1)..] : url[(question + 1)..fragment];
        foreach (var pair in query.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var separator = pair.IndexOf('=');
            var name = separator < 0 ? pair : pair[..separator];
            var value = separator < 0 ? string.Empty : pair[(separator + 1)..];
            result.Add(new NameValue(DecodeFormValue(name), DecodeFormValue(value)));
        }
        return result;
    }

    private static List<NameValue> ParseRequestCookies(string formattedCookies, IReadOnlyList<NameValue> headers)
    {
        var result = ParseFormattedCookies(formattedCookies);
        if (result.Count > 0) return result;
        foreach (var header in headers.Where(header => header.Name.Equals("Cookie", StringComparison.OrdinalIgnoreCase)))
            result.AddRange(ParseCookieHeader(header.Value));
        return result;
    }

    private static List<NameValue> ParseResponseCookies(IReadOnlyList<NameValue> headers)
    {
        var result = new List<NameValue>();
        foreach (var header in headers.Where(header => header.Name.Equals("Set-Cookie", StringComparison.OrdinalIgnoreCase)))
        {
            var first = header.Value.Split(';', 2)[0];
            var separator = first.IndexOf('=');
            if (separator > 0) result.Add(new NameValue(first[..separator].Trim(), first[(separator + 1)..].Trim()));
        }
        return result;
    }

    private static List<NameValue> ParseFormattedCookies(string raw)
    {
        var result = new List<NameValue>();
        foreach (var line in raw.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var separator = line.IndexOf('=');
            if (separator > 0) result.Add(new NameValue(line[..separator].Trim(), line[(separator + 1)..].Trim()));
        }
        return result;
    }

    private static IEnumerable<NameValue> ParseCookieHeader(string value)
    {
        foreach (var part in value.Split(';', StringSplitOptions.RemoveEmptyEntries))
        {
            var separator = part.IndexOf('=');
            if (separator > 0) yield return new NameValue(part[..separator].Trim(), part[(separator + 1)..].Trim());
        }
    }

    private static string DecodeFormValue(string value)
    {
        try { return Uri.UnescapeDataString(value.Replace('+', ' ')); }
        catch (UriFormatException) { return value; }
    }

    private static string? HeaderValue(IReadOnlyList<NameValue> headers, string name) =>
        headers.FirstOrDefault(header => header.Name.Equals(name, StringComparison.OrdinalIgnoreCase))?.Value;

    private static int HeaderSize(string headers) => string.IsNullOrEmpty(headers) ? 0 : Encoding.UTF8.GetByteCount(headers);

    private static string ParseStatusText(string responseHeaders)
    {
        var first = responseHeaders.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n').FirstOrDefault() ?? string.Empty;
        if (!first.StartsWith("HTTP/", StringComparison.OrdinalIgnoreCase)) return string.Empty;
        var parts = first.Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
        return parts.Length >= 3 ? parts[2] : string.Empty;
    }

    private static string NormalizeHttpVersion(string protocol)
    {
        if (protocol.Contains("HTTP/3", StringComparison.OrdinalIgnoreCase)) return "HTTP/3";
        if (protocol.Contains("HTTP/2", StringComparison.OrdinalIgnoreCase)) return "HTTP/2";
        if (protocol.Contains("HTTP/1.0", StringComparison.OrdinalIgnoreCase)) return "HTTP/1.0";
        return "HTTP/1.1";
    }

    private static void WriteNameValueArray(Utf8JsonWriter writer, string propertyName, IEnumerable<NameValue> values)
    {
        writer.WritePropertyName(propertyName);
        writer.WriteStartArray();
        foreach (var value in values)
        {
            writer.WriteStartObject();
            writer.WriteString("name", value.Name);
            writer.WriteString("value", value.Value);
            writer.WriteEndObject();
        }
        writer.WriteEndArray();
    }

    private static async Task WriteJsonEntryAsync<T>(ZipArchive zip, string path, T value, CancellationToken cancellationToken)
    {
        var entry = zip.CreateEntry(path, CompressionLevel.Optimal);
        await using var stream = entry.Open();
        await JsonSerializer.SerializeAsync(stream, value, JsonOptions, cancellationToken);
    }

    private static string BlobEntryPath(string hash) => $"blobs/{hash[..2].ToLowerInvariant()}/{hash.ToLowerInvariant()}.bin";

    private static string PrepareDestination(string outputPath)
    {
        if (string.IsNullOrWhiteSpace(outputPath)) throw new ArgumentException("导出路径不能为空。", nameof(outputPath));
        var destination = Path.GetFullPath(outputPath);
        var directory = Path.GetDirectoryName(destination) ?? throw new InvalidOperationException("无法确定导出目录。");
        Directory.CreateDirectory(directory);
        return destination;
    }

    private sealed record ExportSnapshot(IReadOnlyList<StoredTrafficRecord> Records, Guid[] MissingIds);
    private sealed record NameValue(string Name, string Value);
}
