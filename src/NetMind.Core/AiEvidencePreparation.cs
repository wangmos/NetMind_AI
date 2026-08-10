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

/// <summary>异常候选。字段名缩写，见 <see cref="AiJsonFieldLegend.Anomaly"/>。</summary>
public sealed record AiEvidenceAnomaly(
    [property: JsonPropertyName("k")] string Kind,
    [property: JsonPropertyName("o")] int Ordinal,
    [property: JsonPropertyName("d")] string Description);

/// <summary>
/// 端点组的有界摘要：只带代表序号与序号范围，不逐一列出组内全部序号。
/// 字段名缩写，见 <see cref="AiJsonFieldLegend.EndpointGroup"/>。
/// </summary>
public sealed record AiEndpointGroupDigest(
    [property: JsonPropertyName("k")] string Key,
    [property: JsonPropertyName("n")] int RequestCount,
    [property: JsonPropertyName("err")] int ErrorCount,
    [property: JsonPropertyName("p50")] int MedianLatencyMs,
    [property: JsonPropertyName("p95")] int P95LatencyMs,
    [property: JsonPropertyName("rep")] IReadOnlyList<int> RepresentativeOrdinals,
    [property: JsonPropertyName("cnt")] int OrdinalCount,
    [property: JsonPropertyName("rng")] string OrdinalRange);

/// <summary>发给模型的证据地图投影；省略数量显式给出，不静默截断。</summary>
public sealed record AiEvidenceOverviewProjection(
    int TransactionCount,
    IReadOnlyList<AiEndpointGroupDigest> EndpointGroups,
    int OmittedEndpointGroups,
    IReadOnlyList<AiEvidenceAnomaly> Anomalies,
    int OmittedAnomalies,
    IReadOnlyList<AiEvidenceRelation> Relations,
    int OmittedRelations,
    string Note);

/// <summary>关联候选。单次可返回数十条，字段名缩写，见 <see cref="AiJsonFieldLegend.Relation"/>。</summary>
public sealed record AiEvidenceRelation(
    [property: JsonPropertyName("f")] int FromOrdinal,
    [property: JsonPropertyName("t")] int ToOrdinal,
    [property: JsonPropertyName("s")] int Score,
    [property: JsonPropertyName("r")] IReadOnlyList<string> Reasons);

public sealed record AiTransactionComparison(
    IReadOnlyList<int> Ordinals,
    IReadOnlyList<string> EndpointKeys,
    IReadOnlyDictionary<int, int> StatusDistribution,
    int MinimumLatencyMs,
    int MedianLatencyMs,
    int MaximumLatencyMs,
    IReadOnlyList<AiComparedField> Fields,
    string Note);

/// <summary>比较结果的单个字段。一次比较可产出上百条，字段名缩写，见 <see cref="AiJsonFieldLegend.ComparedField"/>。</summary>
public sealed record AiComparedField(
    [property: JsonPropertyName("l")] string Location,
    [property: JsonPropertyName("n")] string Name,
    [property: JsonPropertyName("c")] string Classification,
    [property: JsonPropertyName("p")] int PresentCount,
    [property: JsonPropertyName("d")] int DistinctCount);

/// <summary>
/// 发给模型的 JSON 字段缩写图例。
///
/// 只压缩会重复出现的元素（事务、关联、异常、端点组、比较字段）——它们在单次工具结果里
/// 出现几十上百次，长字段名按次计费；容器层的单例字段（总数、省略数、说明）保持可读全名，
/// 压了省不下几个字节，却平白增加模型的理解成本。
///
/// 图例随工具说明发送，每次请求只有一份；改动上面任何 JsonPropertyName 都必须同步这里，
/// 否则模型会拿着过期的对照表解析结果。<c>--ai-orchestration-only</c> 有一致性断言兜底。
/// </summary>
public static class AiJsonFieldLegend
{
    public const string Transaction =
        "事务字段：m=方法 u=URL ep=端点 st=状态码 ms=延迟毫秒 sz=字节数 pr=协议 ps=进程 cm=采集模式 " +
        "qs=查询参数 rqh=请求头 ck=Cookie rsh=响应头 rqb=请求正文 rqt=请求正文是否截断 rsb=响应正文 rst=响应正文是否截断。";

    public const string EndpointGroup =
        "端点组字段：k=端点键 n=请求数 err=错误数 p50=延迟中位数 p95=延迟P95 rep=代表序号 cnt=组内条数 rng=序号范围。";

    public const string Anomaly = "异常字段：k=类型 o=序号 d=说明。";

    public const string Relation = "关联字段：f=起始序号 t=目标序号 s=分数 r=依据。";

    public const string ComparedField = "比较字段：l=位置 n=字段名 c=分类 p=出现次数 d=不同取值数。";
}

/// <summary>
/// AI 证据编排的本地规则层：稳定序号、端点归一化、代表样本、异常检测和事务关联评分。
/// 规则输出均为“候选”，最终结论仍需通过 get_transactions / Hook / 证据文件核对。
/// </summary>
public static partial class AiEvidencePreparationEngine
{
    private const int MaximumRelationLookAhead = 25;
    // 面向模型的 JSON 一律不缩进：缩进只服务人眼，却按字节数实打实计费。
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = false,
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

    /// <summary>
    /// 计算与指定 #序号 相关的事务候选。
    /// 必须就地计算，不能去过滤 <see cref="AiPreparedEvidence.Relations"/>：那份全局清单按分数取前 300 条，
    /// 池子一大，绝大多数序号根本不在其中，过滤的结果会是空数组——工具看起来「没有关联」，实则从未被计算。
    /// 这里只扫描该序号前后各 <see cref="MaximumRelationLookAhead"/> 条的时间邻域，代价恒定且结果完整。
    /// </summary>
    public static IReadOnlyList<AiEvidenceRelation> GetRelated(IReadOnlyList<TrafficRecord> pool, int ordinal, int limit = 12)
    {
        if (ordinal < 1 || ordinal > pool.Count) return [];
        var indexed = pool.Select((record, index) => new IndexedTraffic(index + 1, record, EndpointKey(record))).ToArray();
        var center = indexed[ordinal - 1];
        var relations = new List<AiEvidenceRelation>();
        var from = Math.Max(0, ordinal - 1 - MaximumRelationLookAhead);
        var to = Math.Min(indexed.Length - 1, ordinal - 1 + MaximumRelationLookAhead);
        for (var index = from; index <= to; index++)
        {
            if (index == ordinal - 1) continue;
            // 先后关系按序号顺序摆放，保持“序号越大时间越晚”的语义，模型据此判断依赖方向。
            var (left, right) = index < ordinal - 1 ? (indexed[index], center) : (center, indexed[index]);
            if (TryScore(left, right, out var relation)) relations.Add(relation);
        }
        return relations
            .OrderByDescending(relation => relation.Score)
            .ThenBy(relation => Math.Abs(relation.ToOrdinal - relation.FromOrdinal))
            .Take(Math.Clamp(limit, 1, 50))
            .ToArray();
    }

    /// <summary>沿用已准备快照的重载：仍需要池本身才能就地计算，保留签名以兼容既有调用点。</summary>
    public static IReadOnlyList<AiEvidenceRelation> GetRelated(IReadOnlyList<TrafficRecord> pool,
        AiPreparedEvidence prepared, int ordinal, int limit = 12) => GetRelated(pool, ordinal, limit);

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

    /// <summary>
    /// get_evidence_overview 的有界投影。直接序列化 <see cref="AiPreparedEvidence"/> 会把每个端点组的
    /// 全部 Ordinals（可达上千个整数）、200 条异常和 300 条关联一次性塞进模型——实测 1,000 条池子达 91 KB，
    /// 占满单轮取数预算的 71%。这里改为：端点组只带代表序号与范围，异常/关联按上限截断，
    /// 并显式写出省略条数，模型据此知道还能用 search_transactions / get_related_transactions 继续挖。
    /// </summary>
    public static string BuildOverviewJson(AiPreparedEvidence prepared)
    {
        var groups = prepared.EndpointGroups.Take(NetMindDefaults.AiOverviewMaximumEndpointGroups)
            .Select(group => new AiEndpointGroupDigest(
                group.Key, group.RequestCount, group.ErrorCount, group.MedianLatencyMs, group.P95LatencyMs,
                group.RepresentativeOrdinals,
                group.Ordinals.Count,
                group.Ordinals.Count == 0 ? string.Empty : $"#{group.Ordinals[0]}–#{group.Ordinals[^1]}"))
            .ToArray();
        return ToJson(new AiEvidenceOverviewProjection(
            prepared.TransactionCount,
            groups,
            Math.Max(0, prepared.EndpointGroups.Count - groups.Length),
            prepared.Anomalies.Take(NetMindDefaults.AiOverviewMaximumAnomalies).ToArray(),
            Math.Max(0, prepared.Anomalies.Count - NetMindDefaults.AiOverviewMaximumAnomalies),
            prepared.Relations.Take(NetMindDefaults.AiOverviewMaximumRelations).ToArray(),
            Math.Max(0, prepared.Relations.Count - NetMindDefaults.AiOverviewMaximumRelations),
            "端点组只列代表序号与序号范围；需要组内某条事务时用 compare_transactions 或 get_transactions 按序号取。" +
            "关联候选是全局最强的若干条，针对具体事务请调用 get_related_transactions（它会就地计算该序号的完整邻域）。"));
    }

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
                if (rows[right].Record.Timestamp - rows[left].Record.Timestamp > TimeSpan.FromSeconds(15)) break;
                if (TryScore(rows[left], rows[right], out var relation)) relations.Add(relation);
            }
        }
        // 全局清单只用于首轮地图的“最强关联”预览，按分数截断；单个序号的关联一律走 GetRelated 就地计算。
        return relations.OrderByDescending(item => item.Score)
            .ThenBy(item => item.FromOrdinal).ThenBy(item => item.ToOrdinal).Take(300).ToArray();
    }

    /// <summary>
    /// 关联评分的唯一规则实现，全局地图与单序号查询共用，避免两条路径给出不一致的分数。
    /// Accept/Accept-Encoding/Accept-Language/Host/Referer 等浏览器稳定头在同一站点大量重复，
    /// 不能证明事务之间存在依赖。关联候选只保留端点与时序信号，字段差异交给 Compare 单独展示。
    /// </summary>
    private static bool TryScore(IndexedTraffic left, IndexedTraffic right, out AiEvidenceRelation relation)
    {
        relation = null!;
        var elapsed = right.Record.Timestamp - left.Record.Timestamp;
        if (elapsed > TimeSpan.FromSeconds(15)) return false;
        var score = 0;
        var reasons = new List<string>();
        if (Host(left.Record).Equals(Host(right.Record), StringComparison.OrdinalIgnoreCase))
        {
            score += 10;
            reasons.Add("同主机");
        }
        if (left.EndpointKey.Equals(right.EndpointKey, StringComparison.OrdinalIgnoreCase))
        {
            score += 20;
            reasons.Add("同端点");
        }
        if (left.Record.Process.Equals(right.Record.Process, StringComparison.OrdinalIgnoreCase)) score += 5;
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
        if (score < 35) return false;
        relation = new AiEvidenceRelation(left.Ordinal, right.Ordinal, Math.Min(100, score), reasons);
        return true;
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
