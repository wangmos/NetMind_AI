using System.Text;
using System.Text.Json;

namespace NetMind.Core;

/// <summary>一条按事件名过滤后的审计日志条目。<see cref="PayloadJson"/> 是已脱敏的原始 JSON 文本。</summary>
public sealed record AuditLogEntry(DateTimeOffset Timestamp, string EventName, string PayloadJson);

/// <summary>
/// 只读审计日志尾读：找出最近 N 条指定事件名的记录。
///
/// 审计日志是唯一记录"采集期间脚本真实产出了什么"的地方——工作台进程和实际执行钩子的
/// CoreHost/SandboxHost 是不同进程，脚本的观察结论（<c>hooks.finding</c>）只经由
/// <see cref="WorkspaceStore.AppendAuditAsync"/> 落到这个文件，不会出现在工作台内存里。
/// 文件是追加写的纯文本，没有索引；这里用固定大小的环形缓冲顺序扫一遍，只保留命中的最后
/// N 条，不会因为文件几 MB 大就把全部内容都留在内存里。
/// </summary>
public static class AuditLogReader
{
    public static async Task<IReadOnlyList<AuditLogEntry>> ReadRecentAsync(string workspacePath, string eventName,
        int maxCount, CancellationToken cancellationToken = default)
    {
        var path = Path.Combine(workspacePath, NetMindDefaults.LogsDirectoryName, NetMindDefaults.AuditLogFileName);
        if (!File.Exists(path)) return [];
        maxCount = Math.Max(1, maxCount);
        var buffer = new Queue<AuditLogEntry>(maxCount + 1);
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite,
            64 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        using var reader = new StreamReader(stream, Encoding.UTF8);
        string? line;
        while ((line = await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false)) is not null)
        {
            if (line.Length == 0) continue;
            var entry = TryParseEntry(line, eventName);
            if (entry is null) continue;
            buffer.Enqueue(entry);
            if (buffer.Count > maxCount) buffer.Dequeue();
        }
        return buffer.ToArray();
    }

    /// <summary>损坏的单行（写入过程中崩溃截断等）直接跳过，不能让一行坏数据挡住整份日志的读取。</summary>
    private static AuditLogEntry? TryParseEntry(string line, string eventName)
    {
        try
        {
            using var document = JsonDocument.Parse(line);
            var root = document.RootElement;
            if (!root.TryGetProperty("eventName", out var eventNameElement) ||
                !string.Equals(eventNameElement.GetString(), eventName, StringComparison.Ordinal))
                return null;
            var timestamp = root.TryGetProperty("timestamp", out var timestampElement) &&
                             timestampElement.TryGetDateTimeOffset(out var parsed)
                ? parsed
                : DateTimeOffset.MinValue;
            if (!root.TryGetProperty("payload", out var payloadElement) || payloadElement.ValueKind != JsonValueKind.String)
                return null;
            var payloadJson = payloadElement.GetString();
            return string.IsNullOrEmpty(payloadJson) ? null : new AuditLogEntry(timestamp, eventName, payloadJson);
        }
        catch (JsonException) { return null; }
    }
}
