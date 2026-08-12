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
///
/// 文件是追加写的纯文本，没有索引，而"最近 N 条"天然在文件末尾——所以<b>从文件尾往前按块读</b>，
/// 凑够 N 条就停，不做全量扫描。审计日志每条事务都会追加一行（<c>traffic.recorded</c>），
/// 长期高强度采集能攒到几百 MB；顺读一遍意味着用户每次打开脚本页都要把整个文件过一遍，
/// 而真正要的往往只是末尾那几十条。倒着读让代价只与 N 相关，与文件总大小无关。
/// </summary>
public static class AuditLogReader
{
    /// <summary>倒读块大小。一条审计行通常几百字节，64 KB 足以在一两块内凑齐常见的 N。</summary>
    private const int ChunkBytes = 64 * 1024;

    /// <summary>
    /// 跨块累积的半行上限。正常审计行远小于此；超过说明文件被写坏成了一整块没有换行的数据，
    /// 这时放弃继续往前找，而不是无限扩张缓冲把内存吃光。
    /// </summary>
    private const int MaximumCarryBytes = 8 * 1024 * 1024;

    /// <summary>返回最近 <paramref name="maxCount"/> 条命中条目，按时间升序（最旧的在前）。</summary>
    public static async Task<IReadOnlyList<AuditLogEntry>> ReadRecentAsync(string workspacePath, string eventName,
        int maxCount, CancellationToken cancellationToken = default)
    {
        var path = Path.Combine(workspacePath, NetMindDefaults.LogsDirectoryName, NetMindDefaults.AuditLogFileName);
        if (!File.Exists(path)) return [];
        maxCount = Math.Max(1, maxCount);

        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite,
            ChunkBytes, FileOptions.Asynchronous);
        var position = stream.Length;
        var newestFirst = new List<AuditLogEntry>(maxCount);
        // 块首那段不完整的行：它的前半截在更靠前的块里，留到下一轮拼上再解析。
        // 只解析"完整行"这一点也保证了 UTF-8 多字节字符不会被块边界劈开——按字节切块必然会切中
        // 中文这类多字节序列，只有等整行凑齐再解码才不会出现乱码。
        var carry = Array.Empty<byte>();
        while (position > 0 && newestFirst.Count < maxCount)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var take = (int)Math.Min(ChunkBytes, position);
            position -= take;
            stream.Seek(position, SeekOrigin.Begin);
            var buffer = new byte[take + carry.Length];
            await stream.ReadExactlyAsync(buffer.AsMemory(0, take), cancellationToken).ConfigureAwait(false);
            carry.CopyTo(buffer, take);

            // 自块尾向前切行：每遇到一个换行，它后面到上一个切点之间就是一整行。
            var lineEnd = buffer.Length;
            var reachedLimit = false;
            for (var index = buffer.Length - 1; index >= 0; index--)
            {
                if (buffer[index] != (byte)'\n') continue;
                var entry = TryParseEntry(buffer, index + 1, lineEnd - index - 1, eventName);
                lineEnd = index;
                if (entry is null) continue;
                newestFirst.Add(entry);
                if (newestFirst.Count >= maxCount) { reachedLimit = true; break; }
            }
            if (reachedLimit) break;

            if (position == 0)
            {
                // 已经到文件头：剩下的这段不是半行，而是第一行本身。
                var entry = TryParseEntry(buffer, 0, lineEnd, eventName);
                if (entry is not null) newestFirst.Add(entry);
                break;
            }
            if (lineEnd > MaximumCarryBytes) break; // 单行大到不像正常日志：停止回溯，返回已经拿到的
            carry = buffer[..lineEnd];
        }

        newestFirst.Reverse(); // 倒读得到的是最新在前；调用方约定按时间升序
        return newestFirst;
    }

    /// <summary>解析一整行的字节。行尾可能带 <c>\r</c>（写入用的是 Environment.NewLine），由 Trim 吃掉。</summary>
    private static AuditLogEntry? TryParseEntry(byte[] buffer, int offset, int count, string eventName)
    {
        if (count <= 0) return null;
        var line = Encoding.UTF8.GetString(buffer, offset, count).Trim();
        return line.Length == 0 ? null : TryParseEntry(line, eventName);
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
