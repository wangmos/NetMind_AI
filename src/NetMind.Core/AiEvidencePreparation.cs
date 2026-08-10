using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace NetMind.Core;

/// <summary>本地确定性证据预整理结果。只建立索引和候选关系，不替代模型对原始证据的判断。</summary>
public sealed record AiPreparedEvidence(
    int TransactionCount,
    IReadOnlyList<AiEndpointGroup> EndpointGroups,
    IReadOnlyList<AiEvidenceAnomaly> Anomalies,
    IReadOnlyList<AiEvidenceRelation> Relations);

public sealed record AiEndpointGroup(
    string Key,
    string Method,
    string Host,
    string NormalizedEndpoint,
    int RequestCount,
    int ErrorCount,
    int MedianLatencyMs,
    int P95LatencyMs,
    IReadOnlyList<int> RepresentativeOrdinals,
    IReadOnlyList<int> Ordinals);

public sealed record AiEvidenceAnomaly(string Kind, int Ordinal, string Description);

public sealed record AiEvidenceRelation(
    int FromOrdinal,
    int ToOrdinal,
    int Score,
    IReadOnlyList<string> Reasons);

public sealed record AiTransactionComparison(
    IReadOnlyList<int> Ordinals,
    IReadOnlyList<string> EndpointKeys,
    IReadOnlyDictionary<int, int> StatusDistribution,
    int MinimumLatencyMs,
    int MedianLatencyMs,
    int MaximumLatencyMs,
    IReadOnlyList<AiComparedField> Fields,
    string Note);

public sealed record AiComparedField(string Location, string Name, string Classification, int PresentCount, int DistinctCount);

/// <summary>
/// AI 证据编排的本地规则层：稳定序号、端点归一化、代表样本、异常检测和事务关联评分。
/// 规则输出均为“候选”，最终结论仍需通过 get_transactions / Hook / 证据文件核对。
/// </summary>
public static partial class AiEvidencePreparationEngine
{
    private const int MaximumRelationLookAhead = 25;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public static AiPreparedEvidence Prepare(IReadOnlyList<TrafficRecord> pool)
    {
        if (pool.Count == 0) return new AiPreparedEvidence(0, [], [], []);
        var indexed = pool.Select((record, index) => new IndexedTraffic(index + 1, record, EndpointKey(record))).ToArray();
        var groups = indexed
            .GroupBy(item => item.EndpointKey, StringComparer.OrdinalIgnoreCase)
            .Select(CreateGroup)
            .OrderByDescending(group => group.ErrorCount)
            .ThenByDescending(group => group.RequestCount)
            .ThenBy(group => group.Key, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        return new AiPreparedEvidence(pool.Count, groups, DetectAnomalies(indexed), DetectRelations(indexed));
    }

    public static IReadOnlyList<AiEvidenceRelation> GetRelated(IReadOnlyList<TrafficRecord> pool, int ordinal, int limit = 12)
        => GetRelated(Prepare(pool), ordinal, limit);

    /// <summary>从已准备的不可变证据快照读取关联项，避免一次 AI 会话内重复扫描全部事务。</summary>
    public static IReadOnlyList<AiEvidenceRelation> GetRelated(AiPreparedEvidence prepared, int ordinal, int limit = 12)
    {
        if (ordinal < 1 || ordinal > prepared.TransactionCount) return [];
        return prepared.Relations
            .Where(relation => relation.FromOrdinal == ordinal || relation.ToOrdinal == ordinal)
            .OrderByDescending(relation => relation.Score)
            .ThenBy(relation => Math.Abs(relation.ToOrdinal - relation.FromOrdinal))
            .Take(Math.Clamp(limit, 1, 50))
            .ToArray();
    }

    public static AiTransactionComparison Compare(IReadOnlyList<TrafficRecord> pool, IEnumerable<int> requestedOrdinals)
    {
        var ordinals = requestedOrdinals.Where(ordinal => ordinal >= 1 && ordinal <= pool.Count)
            .Distinct().Take(NetMindDefaults.AiToolMaximumOrdinalsPerFetch).Order().ToArray();
        var selected = ordinals.Select(ordinal => pool[ordinal - 1]).ToArray();
        if (selected.Length == 0)
            return new AiTransactionComparison([], [], new Dictionary<int, int>(), 0, 0, 0, [], "没有有效事务序号。");

        var fields = selected.Select(record => ExtractComparableFields(record)).ToArray();
        var fieldNames = fields.SelectMany(map => map.Keys).Distinct(FieldKeyComparer.Instance);
        var compared = fieldNames.Select(key =>
        {
            var values = fields.Where(map => map.ContainsKey(key)).Select(map => map[key]).ToArray();
            return new AiComparedField(key.Location, key.Name, ClassifyValues(values), values.Length,
                values.Distinct(StringComparer.Ordinal).Count());
        }).OrderBy(field => field.Location, StringComparer.Ordinal)
          .ThenBy(field => field.Name, StringComparer.OrdinalIgnoreCase).ToArray();
        var latencies = selected.Select(record => record.LatencyMs).Order().ToArray();
        return new AiTransactionComparison(
            ordinals,
            selected.Select(EndpointKey).Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
            selected.GroupBy(record => record.StatusCode).OrderBy(group => group.Key).ToDictionary(group => group.Key, group => group.Count()),
            latencies[0], Median(latencies), latencies[^1], compared,
            "本地比较覆盖 URL 查询参数、请求头和 Cookie；请求/响应正文结构需再用 get_transactions 核对。");
    }

    public static string ToJson(object value) => JsonSerializer.Serialize(value, JsonOptions);

    /// <summary>首轮使用的有界证据地图：高价值端点、异常与关联候选，不包含原始敏感值。</summary>
    public static string BuildCompactManifest(IReadOnlyList<TrafficRecord> pool)
        => BuildCompactManifest(Prepare(pool));

    /// <summary>从已准备的证据快照生成首轮紧凑清单。</summary>
    public static string BuildCompactManifest(AiPreparedEvidence prepared)
    {
        if (prepared.TransactionCount == 0) return "事务 0 条";
        var groups = prepared.EndpointGroups.Take(10)
            .Select(group => $"{group.Key} ×{group.RequestCount} 错误{group.ErrorCount} P95={group.P95LatencyMs}ms 代表[{string.Join(',', group.RepresentativeOrdinals.Select(value => "#" + value))}]");
        var anomalies = prepared.Anomalies.Take(8).Select(item => $"#{item.Ordinal} {item.Kind}：{item.Description}");
        var relations = prepared.Relations.Take(8)
            .Select(item => $"#{item.FromOrdinal}→#{item.ToOrdinal}({item.Score}) {string.Join('、', item.Reasons)}");
        return "端点组：\n- " + string.Join("\n- ", groups) +
               (prepared.Anomalies.Count > 0 ? "\n异常候选：\n- " + string.Join("\n- ", anomalies) : string.Empty) +
               (prepared.Relations.Count > 0 ? "\n关联候选：\n- " + string.Join("\n- ", relations) : string.Empty);
    }

    private static AiEndpointGroup CreateGroup(IGrouping<string, IndexedTraffic> group)
    {
        var rows = group.OrderBy(item => item.Ordinal).ToArray();
        var latencies = rows.Select(item => item.Record.LatencyMs).Order().ToArray();
        var first = rows[0].Record;
        var representatives = new List<int>();
        AddRepresentative(representatives, rows.FirstOrDefault(item => item.Record.StatusCode < 400)?.Ordinal);
        AddRepresentative(representatives, rows.LastOrDefault(item => item.Record.StatusCode < 400)?.Ordinal);
        AddRepresentative(representatives, rows.FirstOrDefault(item => item.Record.StatusCode >= 400)?.Ordinal);
        AddRepresentative(representatives, rows.MaxBy(item => item.Record.LatencyMs)?.Ordinal);
        return new AiEndpointGroup(group.Key, first.Method.ToUpperInvariant(), Host(first), EndpointNormalizer.Normalize(first.Endpoint),
            rows.Length, rows.Count(item => item.Record.StatusCode >= 400), Median(latencies), Percentile(latencies, 0.95),
            representatives, rows.Select(item => item.Ordinal).ToArray());
    }

    private static IReadOnlyList<AiEvidenceAnomaly> DetectAnomalies(IReadOnlyList<IndexedTraffic> rows)
    {
        var medians = rows.GroupBy(item => item.EndpointKey, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => Median(group.Select(item => item.Record.LatencyMs).Order().ToArray()), StringComparer.OrdinalIgnoreCase);
        var anomalies = new List<AiEvidenceAnomaly>();
        for (var index = 0; index < rows.Count; index++)
        {
            var row = rows[index];
            if (row.Record.StatusCode >= 400)
                anomalies.Add(new AiEvidenceAnomaly("HTTP错误", row.Ordinal, $"{row.Record.StatusCode} {row.Record.Method} {row.Record.Endpoint}"));
            var median = medians[row.EndpointKey];
            if (row.Record.LatencyMs >= 1000 && row.Record.LatencyMs >= Math.Max(1, median) * 3)
                anomalies.Add(new AiEvidenceAnomaly("慢请求", row.Ordinal, $"{row.Record.LatencyMs}ms，端点中位数 {median}ms"));
            if (row.Record.SizeBytes >= 2L * 1024 * 1024)
                anomalies.Add(new AiEvidenceAnomaly("大响应", row.Ordinal, $"{row.Record.SizeBytes / 1024d / 1024d:F1}MB"));
            if (index > 0)
            {
                var previous = rows[index - 1];
                if (row.EndpointKey.Equals(previous.EndpointKey, StringComparison.OrdinalIgnoreCase) &&
                    row.Record.Timestamp - previous.Record.Timestamp <= TimeSpan.FromSeconds(2))
                    anomalies.Add(new AiEvidenceAnomaly("快速重复", row.Ordinal, $"与 #{previous.Ordinal} 同端点，间隔 {(row.Record.Timestamp - previous.Record.Timestamp).TotalMilliseconds:F0}ms"));
            }
        }
        return anomalies.OrderBy(item => item.Ordinal).ThenBy(item => item.Kind, StringComparer.Ordinal).Take(200).ToArray();
    }

    private static IReadOnlyList<AiEvidenceRelation> DetectRelations(IReadOnlyList<IndexedTraffic> rows)
    {
        var relations = new List<AiEvidenceRelation>();
        for (var left = 0; left < rows.Count; left++)
        {
            for (var right = left + 1; right < rows.Count && right <= left + MaximumRelationLookAhead; right++)
            {
                var elapsed = rows[right].Record.Timestamp - rows[left].Record.Timestamp;
                if (elapsed > TimeSpan.FromSeconds(15)) break;
                var score = 0;
                var reasons = new List<string>();
                if (Host(rows[left].Record).Equals(Host(rows[right].Record), StringComparison.OrdinalIgnoreCase))
                {
                    score += 10;
                    reasons.Add("同主机");
                }
                if (rows[left].EndpointKey.Equals(rows[right].EndpointKey, StringComparison.OrdinalIgnoreCase))
                {
                    score += 20;
                    reasons.Add("同端点");
                }
                if (rows[left].Record.Process.Equals(rows[right].Record.Process, StringComparison.OrdinalIgnoreCase)) score += 5;
                if (elapsed <= TimeSpan.FromSeconds(2))
                {
                    score += 15;
                    reasons.Add($"相隔{elapsed.TotalMilliseconds:F0}ms");
                }
                else if (elapsed <= TimeSpan.FromSeconds(5))
                {
                    score += 8;
                    reasons.Add($"相隔{elapsed.TotalSeconds:F1}s");
                }
                // Accept/Accept-Encoding/Accept-Language/Host/Referer 等浏览器稳定头在同一站点大量重复，
                // 不能证明事务之间存在依赖。关联候选只保留端点与时序信号，字段差异交给 Compare 单独展示。
                if (score >= 35)
                    relations.Add(new AiEvidenceRelation(rows[left].Ordinal, rows[right].Ordinal, Math.Min(100, score), reasons));
            }
        }
        return relations.OrderByDescending(item => item.Score)
            .ThenBy(item => item.FromOrdinal).ThenBy(item => item.ToOrdinal).Take(300).ToArray();
    }

    private static Dictionary<FieldKey, string> ExtractComparableFields(TrafficRecord record)
    {
        var result = new Dictionary<FieldKey, string>(FieldKeyComparer.Instance);
        AddKeyValueLines(result, "查询", record.QueryParameters, '=');
        AddKeyValueLines(result, "请求头", record.RequestHeaders, ':');
        AddCookieFields(result, record.Cookies);
        return result;
    }

    private static void AddKeyValueLines(Dictionary<FieldKey, string> target, string location, string source, char separator)
    {
        foreach (var line in source.Split(['\r', '\n', '&'], StringSplitOptions.RemoveEmptyEntries))
        {
            var split = line.IndexOf(separator);
            if (split <= 0 || split >= line.Length - 1) continue;
            var name = line[..split].Trim();
            var value = line[(split + 1)..].Trim();
            if (name.Length == 0 || value.Length == 0) continue;
            target[new FieldKey(location, name)] = value;
        }
    }

    private static void AddCookieFields(Dictionary<FieldKey, string> target, string source)
    {
        foreach (var part in source.Split([';', '\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
        {
            var split = part.IndexOf('=');
            if (split <= 0 || split >= part.Length - 1) continue;
            target[new FieldKey("Cookie", part[..split].Trim())] = part[(split + 1)..].Trim();
        }
    }

    private static string ClassifyValues(IReadOnlyList<string> values)
    {
        var distinct = values.Distinct(StringComparer.Ordinal).ToArray();
        if (distinct.Length <= 1) return "固定值";
        if (distinct.All(value => Guid.TryParse(value, out _))) return "UUID候选";
        if (distinct.All(value => long.TryParse(value, out _)))
        {
            var numbers = distinct.Select(long.Parse).Order().ToArray();
            if (numbers.All(value => value is >= 946684800 and <= 4102444800000)) return "时间戳/序号候选";
            return "数值变化";
        }
        if (distinct.All(value => value.Length >= 16 && OpaqueValue().IsMatch(value))) return "高熵/编码值候选";
        return "变化值";
    }

    private static string EndpointKey(TrafficRecord record) => $"{record.Method.ToUpperInvariant()} {Host(record)}{EndpointNormalizer.Normalize(record.Endpoint)}";
    private static string Host(TrafficRecord record) => Uri.TryCreate(record.Url, UriKind.Absolute, out var uri) ? uri.Host : string.Empty;
    private static int Median(IReadOnlyList<int> sorted) => sorted.Count == 0 ? 0 : sorted[(sorted.Count - 1) / 2];
    private static int Percentile(IReadOnlyList<int> sorted, double percentile) => sorted.Count == 0 ? 0 : sorted[Math.Max(0, (int)Math.Ceiling(sorted.Count * percentile) - 1)];

    private static void AddRepresentative(List<int> target, int? ordinal)
    {
        if (ordinal is > 0 && !target.Contains(ordinal.Value)) target.Add(ordinal.Value);
    }

    private sealed record IndexedTraffic(int Ordinal, TrafficRecord Record, string EndpointKey);
    private sealed record FieldKey(string Location, string Name);

    private sealed class FieldKeyComparer : IEqualityComparer<FieldKey>
    {
        public static readonly FieldKeyComparer Instance = new();
        public bool Equals(FieldKey? x, FieldKey? y) => x is not null && y is not null &&
            x.Location.Equals(y.Location, StringComparison.OrdinalIgnoreCase) && x.Name.Equals(y.Name, StringComparison.OrdinalIgnoreCase);
        public int GetHashCode(FieldKey obj) => HashCode.Combine(obj.Location.ToUpperInvariant(), obj.Name.ToUpperInvariant());
    }

    [GeneratedRegex("^[A-Za-z0-9+/=_-]+$", RegexOptions.CultureInvariant)]
    private static partial Regex OpaqueValue();
}
