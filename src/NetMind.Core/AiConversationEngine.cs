using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace NetMind.Core;

/// <summary>
/// 证据池取数接口：由工作台实现，封装所选事务范围（勾选/记录组/当前高亮）与 Blob 读取路径。
/// 序号是池内从 1 起的索引，与首轮摘要清单一致。
/// </summary>
public interface AiEvidenceProvider
{
    /// <summary>证据池事务（按采集时间升序）。</summary>
    IReadOnlyList<TrafficRecord> Pool { get; }

    /// <summary>证据池对应的不可变本地索引；同一会话只构建一次。</summary>
    AiPreparedEvidence PreparedEvidence { get; }

    /// <summary>按序号取完整事务上下文（JSON 文本），序号从 1 起。</summary>
    Task<string> GetTransactionsAsync(int[] ordinals, CancellationToken cancellationToken);

    /// <summary>在池内 URL/头/正文做大小写不敏感子串匹配，返回命中序号与位置摘要文本。</summary>
    Task<string> SearchAsync(string keyword, CancellationToken cancellationToken);

    /// <summary>检索采集浏览器页内 Hook 事件（M3 接通；未接通时返回空结果文本）。</summary>
    Task<string> GetHooksAsync(string? type, int limit, CancellationToken cancellationToken);

    /// <summary>当前会话可按需读取的证据文件名；只暴露清单，不在首轮上传正文。</summary>
    IReadOnlyList<string> EvidenceFileNames { get; }

    /// <summary>按文件名读取用户显式添加的证据文件；空数组表示读取全部。</summary>
    Task<string> GetEvidenceFilesAsync(string[] names, CancellationToken cancellationToken);

    /// <summary>按事务序号读取请求或响应正文的有界片段；keyword 非空时返回命中附近上下文。</summary>
    Task<string> GetTransactionBodyExcerptAsync(
        int ordinal, string direction, string? keyword, int maximumCharacters, CancellationToken cancellationToken);
}

/// <summary>单轮对话产出：助手最终文本、取数统计与累计令牌。</summary>
public sealed record AiTurnOutcome(
    string AssistantText,
    int ToolFetchCount,
    int InputTokens,
    int OutputTokens,
    long DurationMilliseconds,
    string FinishReason,
    bool IterationCapReached);

/// <summary>首轮证据清单的结构化行；文本提示与 WPF 表格共用，避免 UI 再用正则猜测模型输入格式。</summary>
public sealed record AiEvidenceSummaryRow(
    int Ordinal,
    string Time,
    string Method,
    string Host,
    string Endpoint,
    int StatusCode,
    int LatencyMilliseconds,
    long SizeBytes,
    string ContentType);

/// <summary>
/// 对话式分析引擎：摘要先行 + tool_call 按需取数。
/// 每轮先从持久历史构建不含旧工具原文的模型历史；模型返回 tool_calls 时，结果只追加到当前轮临时历史。
/// 收尾后仅持久化用户问题、最终回答和轻量工具摘要。后续追问不会重发此前工具原文，必要时按序号重新取证。
/// 迭代上限 <see cref="NetMindDefaults.AiToolLoopMaximumIterations"/> 次，
/// 单轮取数预算 <see cref="NetMindDefaults.AiToolFetchBudgetBytesPerTurn"/>。
/// </summary>
public sealed class AiConversationEngine(AiGatewayClient gateway)
{
    private static readonly JsonSerializerOptions ToolJsonOptions = new() { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };

    /// <summary>八个只读工具：本地证据地图、关联/比较、事务概览、正文片段、搜索、页内 Hook 与证据文件。</summary>
    public static IReadOnlyList<AiToolSchema> BuildToolSchemas() =>
    [
        new("get_evidence_overview", "获取本地规则预整理的完整证据地图：归一化端点组、代表序号、错误/慢请求/重复请求候选，以及事务关联候选。该结果用于规划取证，不能替代原始事务。",
            JsonDocument.Parse("""{"type":"object","properties":{},"additionalProperties":false}""").RootElement.Clone()),
        new("get_related_transactions", "获取与指定 #序号 相关的事务候选。只使用同端点与时间邻近等结构信号，不把同站点普遍相同的请求头当作关联；必须再取原始事务确认因果关系。",
            JsonDocument.Parse("""{"type":"object","properties":{"ordinal":{"type":"integer","description":"中心事务的 #序号（从 1 起）"},"limit":{"type":"integer","description":"最多返回的关联候选，默认 12"}},"required":["ordinal"],"additionalProperties":false}""").RootElement.Clone()),
        new("compare_transactions", "本地比较一组事务的端点、状态、延迟、查询参数、请求头和 Cookie 字段，标记固定值、变化值、UUID、时间戳或高熵候选。正文结构仍需 get_transactions 核对。",
            JsonDocument.Parse("""{"type":"object","properties":{"ordinals":{"type":"array","items":{"type":"integer"},"description":"要比较的 #序号列表，建议选择同一端点的成功/失败/异常样本"}},"required":["ordinals"],"additionalProperties":false}""").RootElement.Clone()),
        new("get_transactions", "按序号获取事务元数据、请求头、响应头及有界正文预览。ordinals 为证据池摘要中的 #序号数组（从 1 起），单次最多 " + NetMindDefaults.AiToolMaximumOrdinalsPerFetch + " 个；长正文请用 get_transaction_body_excerpt 按关键词读取片段。",
            JsonDocument.Parse("""{"type":"object","properties":{"ordinals":{"type":"array","items":{"type":"integer"},"description":"要获取完整数据的事务序号列表（从 1 起）"}},"required":["ordinals"],"additionalProperties":false}""").RootElement.Clone()),
        new("get_transaction_body_excerpt", "读取单条事务请求或响应正文的有界片段。优先提供 keyword 返回命中附近上下文，避免把整个大型 HTML/JS/JSON 放入模型。",
            JsonDocument.Parse("""{"type":"object","properties":{"ordinal":{"type":"integer","description":"事务 #序号（从 1 起）"},"direction":{"type":"string","enum":["request","response"],"description":"读取请求或响应正文"},"keyword":{"type":"string","description":"可选；返回首次命中附近上下文"},"max_characters":{"type":"integer","minimum":512,"maximum":24000,"description":"最多返回字符数，默认 6000"}},"required":["ordinal","direction"],"additionalProperties":false}""").RootElement.Clone()),
        new("search_transactions", "在证据池全部事务的 URL、请求头、响应头、Cookie 与正文中做大小写不敏感关键字搜索，返回命中的序号与位置摘要。",
            JsonDocument.Parse("""{"type":"object","properties":{"keyword":{"type":"string","description":"要搜索的关键字"}},"required":["keyword"],"additionalProperties":false}""").RootElement.Clone()),
        new("get_page_hooks", "检索采集浏览器页内 Hook 捕获的事件（XHR/fetch 调用、加密函数调用、Base64 编解码、存储写入），用于定位加密参数的实际入参。",
            JsonDocument.Parse("""{"type":"object","properties":{"type":{"type":"string","description":"事件类型过滤：xhr、fetch、crypto、encode、storage，不传返回全部"},"limit":{"type":"integer","description":"最多返回条数，默认 50"}},"additionalProperties":false}""").RootElement.Clone()),
        new("get_evidence_files", "按文件名读取用户为当前分析添加的 JS、HAR、接口文档、日志或其他文本证据。首轮消息会列出可用文件名；只读取与任务相关的文件。",
            JsonDocument.Parse("""{"type":"object","properties":{"names":{"type":"array","items":{"type":"string"},"description":"要读取的证据文件名；不传或空数组时读取全部"}},"additionalProperties":false}""").RootElement.Clone())
    ];

    /// <summary>
    /// 构建证据池摘要：每条事务一行 "#序号 时间 方法 主机 路径 查询键 状态 延迟 大小 类型"，
    /// 序号从 1 起与池内索引一致；超过上限时截断并标注。
    /// </summary>
    public static string BuildEvidenceSummary(IReadOnlyList<TrafficRecord> pool)
    {
        var builder = new StringBuilder();
        var rows = BuildEvidenceSummaryRows(pool);
        foreach (var row in rows)
        {
            builder.Append('#').Append(row.Ordinal)
                .Append(' ').Append(row.Time)
                .Append(' ').Append(row.Method)
                .Append(' ').Append(row.Host)
                .Append(' ').Append(row.Endpoint)
                .Append(' ').Append(row.StatusCode)
                .Append(' ').Append(row.LatencyMilliseconds).Append("ms")
                .Append(' ').Append(row.SizeBytes).Append("B")
                .Append(' ').Append(TrimSummaryValue(row.ContentType, 72))
                .Append('\n');
        }
        if (pool.Count > rows.Count) builder.Append($"…… 其余 {pool.Count - rows.Count} 条摘要已省略，可用 search_transactions 定位 ……\n");
        return builder.ToString().TrimEnd();
    }

    public static IReadOnlyList<AiEvidenceSummaryRow> BuildEvidenceSummaryRows(IReadOnlyList<TrafficRecord> pool)
    {
        var limit = Math.Min(pool.Count, NetMindDefaults.AiConversationSummaryMaximumLines);
        var rows = new List<AiEvidenceSummaryRow>(limit);
        for (var index = 0; index < limit; index++)
        {
            var record = pool[index];
            var host = Uri.TryCreate(record.Url, UriKind.Absolute, out var uri) ? uri.Host : record.Endpoint;
            var path = Uri.TryCreate(record.Url, UriKind.Absolute, out var pathUri) ? pathUri.AbsolutePath : record.Endpoint;
            var queryKeys = Uri.TryCreate(record.Url, UriKind.Absolute, out var queryUri)
                ? ExtractQueryKeys(queryUri.Query)
                : string.Empty;
            if (queryKeys.Length > 0) path += " ?{" + queryKeys + "}";
            rows.Add(new AiEvidenceSummaryRow(
                index + 1,
                record.Timestamp.ToLocalTime().ToString("HH:mm:ss.fff"),
                record.Method,
                host,
                path,
                record.StatusCode,
                record.LatencyMs,
                record.SizeBytes,
                ExtractHeaderValue(record.ResponseHeaders, "Content-Type") ?? "未知"));
        }
        return rows;
    }

    /// <summary>构建低成本确定性概况，帮助模型先确定证据范围，避免逐条试探式取数。</summary>
    public static string BuildEvidenceOverview(IReadOnlyList<TrafficRecord> pool)
    {
        if (pool.Count == 0) return "事务 0 条";
        var totalBytes = pool.Sum(record => Math.Max(0, record.SizeBytes));
        var errors = pool.Count(record => record.StatusCode >= 400);
        var hosts = pool.Select(record => Uri.TryCreate(record.Url, UriKind.Absolute, out var uri) ? uri.Host : record.Endpoint)
            .Where(host => !string.IsNullOrWhiteSpace(host)).Distinct(StringComparer.OrdinalIgnoreCase).Count();
        var endpoints = pool.Select(record =>
        {
            var host = Uri.TryCreate(record.Url, UriKind.Absolute, out var uri) ? uri.Host : string.Empty;
            var path = Uri.TryCreate(record.Url, UriKind.Absolute, out var pathUri) ? pathUri.AbsolutePath : record.Endpoint;
            return $"{record.Method.ToUpperInvariant()} {host}{path}";
        }).Distinct(StringComparer.OrdinalIgnoreCase).Count();
        var slowest = pool.Select((record, index) => (record, ordinal: index + 1))
            .OrderByDescending(item => item.record.LatencyMs).Take(3)
            .Select(item => $"#{item.ordinal}={item.record.LatencyMs}ms");
        return $"时间 {pool[0].Timestamp.ToLocalTime():HH:mm:ss.fff}–{pool[^1].Timestamp.ToLocalTime():HH:mm:ss.fff}；" +
               $"主机 {hosts}；端点 {endpoints}；错误 {errors}；响应总量 {FormatBytes(totalBytes)}；最慢 {string.Join("、", slowest)}";
    }

    private static string ExtractQueryKeys(string query)
    {
        if (string.IsNullOrWhiteSpace(query)) return string.Empty;
        var keys = query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(part => part.Split('=', 2)[0])
            .Where(key => key.Length > 0)
            .Select(DecodeQueryKey)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(8)
            .Select(key => TrimSummaryValue(key, 32));
        return string.Join(',', keys);
    }

    private static string DecodeQueryKey(string key)
    {
        try { return Uri.UnescapeDataString(key); }
        catch (UriFormatException) { return key; }
    }

    private static string TrimSummaryValue(string value, int maximum) =>
        value.Length <= maximum ? value : value[..maximum] + "…";

    private static string FormatBytes(long bytes) => bytes switch
    {
        >= 1024L * 1024L => $"{bytes / 1024d / 1024d:F1}MB",
        >= 1024L => $"{bytes / 1024d:F1}KB",
        _ => $"{bytes}B"
    };

    private static string? ExtractHeaderValue(string headers, string name)
    {
        foreach (var line in headers.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
        {
            var separator = line.IndexOf(':');
            if (separator <= 0) continue;
            if (!line[..separator].Trim().Equals(name, StringComparison.OrdinalIgnoreCase)) continue;
            var value = line[(separator + 1)..].Trim();
            return value.Length > 0 ? value : null;
        }
        return null;
    }

    /// <summary>组装首轮用户消息：确定性概况 + 证据池摘要 + 文件清单 + 分析要求。</summary>
    public static string BuildFirstUserMessage(AiEvidenceProvider provider, AiPromptTemplate template, string? userRequirement = null) =>
        BuildFirstUserMessage(provider.Pool, template, userRequirement, provider.EvidenceFileNames, provider.PreparedEvidence);

    public static string BuildFirstUserMessage(IReadOnlyList<TrafficRecord> pool, AiPromptTemplate template,
        string? userRequirement = null, IReadOnlyList<string>? evidenceFileNames = null,
        AiPreparedEvidence? preparedEvidence = null)
    {
        var summary = BuildEvidenceSummary(pool);
        var builder = new StringBuilder();
        builder.Append($"以下是本次分析的证据池摘要（共 {pool.Count} 条事务，按采集时间升序，#序号 与工作台列表一致）。\n\n");
        builder.Append("证据池概况：").Append(BuildEvidenceOverview(pool)).Append("\n\n本地证据地图（规则候选，结论仍需取原始事务验证）：\n")
            .Append(AiEvidencePreparationEngine.BuildCompactManifest(preparedEvidence ?? AiEvidencePreparationEngine.Prepare(pool))).Append("\n\n事务摘要：\n");
        builder.Append(summary);
        if (evidenceFileNames is { Count: > 0 })
            builder.Append("\n\n可用证据文件：").AppendJoin("、", evidenceFileNames.Select(name => $"《{name}》"))
                .Append("。需要正文时调用 get_evidence_files。文件不是网络事务，引用时使用文件名。 ");
        builder.Append("\n\n分析要求：").Append(template.AnalysisRequirement);
        if (!string.IsNullOrWhiteSpace(userRequirement))
            builder.Append("\n\n用户针对本次分析的补充要求：").Append(userRequirement.Trim());
        builder.Append("\n\n执行要求：摘要不含查询值、头、Cookie 和正文。先规划少量代表序号，用 get_transactions 读取概览；大型正文先搜索，再用正文片段工具读取命中附近内容。完成取证后给最终结论，并用 [#序号] 引用关键证据。工具原文只在本轮临时可用。");
        return builder.ToString();
    }

    /// <summary>
    /// 执行一轮对话：追加用户消息、与网关交互并执行工具取数回环，全部新消息写入
    /// <paramref name="history"/> 并经 <paramref name="store"/> 持久化。
    /// </summary>
    public async Task<AiTurnOutcome> RunTurnAsync(
        AiGatewaySettings settings, string? apiKey,
        AiEvidenceProvider provider,
        List<AiChatMessage> history, string userText,
        AiConversationStore? store, Guid conversationId,
        AiStreamCallbacks? callbacks = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(userText)) throw new InvalidOperationException("提问内容不能为空。");
        if (userText.Length > NetMindDefaults.AiMaximumPromptCharacters)
            throw new InvalidOperationException($"提问不得超过 {NetMindDefaults.AiMaximumPromptCharacters} 个字符。");

        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        await AppendAsync(history, new AiChatMessage("user", userText.Trim()), store, conversationId, cancellationToken);
        FoldHistoryIfNeeded(history);

        var tools = BuildToolSchemas();
        var toolFetchCount = 0;
        var inputTokens = 0;
        var outputTokens = 0;
        var iterationCapReached = false;
        var finishReason = string.Empty;
        var assistantText = string.Empty;
        // 预算属于整个用户回合，而不是单次 tool-loop 迭代；放在循环外防止模型通过多轮取数成倍放大上下文。
        var budgetUsed = 0;
        var toolTraces = new List<AiToolTrace>();
        // 工具协议只存在于本轮临时历史。持久历史只保存最终结论，避免追问重复上传原始证据。
        var workingHistory = CreateGatewayHistory(history);

        for (var iteration = 0; ; iteration++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            // 带 tools 调用不计入迭代预算；收尾调用不带 tools，模型只能基于已有数据作答。
            var result = await gateway.AnalyzeConversationAsync(settings, apiKey, workingHistory, tools, callbacks, cancellationToken);
            inputTokens += result.InputTokens;
            outputTokens += result.OutputTokens;
            finishReason = result.FinishReason;

            if (result.ToolCalls.Count == 0)
            {
                assistantText = result.Text;
                // 收尾助手消息携带本轮耗时与令牌统计，仅供界面展示，网关投影不会发给模型。
                await AppendAsync(history, new AiChatMessage("assistant", result.Text,
                    ElapsedMilliseconds: stopwatch.ElapsedMilliseconds, InputTokens: inputTokens, OutputTokens: outputTokens,
                    ToolTraces: toolTraces.Count == 0 ? null : toolTraces.ToArray()),
                    store, conversationId, cancellationToken);
                break;
            }
            if (iteration >= NetMindDefaults.AiToolLoopMaximumIterations)
            {
                // 达到取数迭代上限仍要求取数：不再执行工具，追加系统提示后做一次无工具收尾调用。
                iterationCapReached = true;
                workingHistory.Add(new AiChatMessage("user", "[系统]取数迭代已达上限，请直接基于已取回的数据给出结论，不要再调用工具。"));
                var final = await gateway.AnalyzeConversationAsync(settings, apiKey, workingHistory, [], callbacks, cancellationToken);
                inputTokens += final.InputTokens;
                outputTokens += final.OutputTokens;
                finishReason = final.FinishReason;
                assistantText = final.Text;
                await AppendAsync(history, new AiChatMessage("assistant", final.Text,
                    ElapsedMilliseconds: stopwatch.ElapsedMilliseconds, InputTokens: inputTokens, OutputTokens: outputTokens,
                    ToolTraces: toolTraces.Count == 0 ? null : toolTraces.ToArray()),
                    store, conversationId, cancellationToken);
                break;
            }

            workingHistory.Add(new AiChatMessage("assistant", result.Text.Length > 0 ? result.Text : null, result.ToolCalls));
            // 单轮取数预算：全部 tool 结果跨迭代累计，超限后仍为每个 tool_call 返回明确结果，保持协议闭合。
            foreach (var call in result.ToolCalls)
            {
                cancellationToken.ThrowIfCancellationRequested();
                callbacks?.OnToolFetch?.Invoke(call.Name, call.ArgumentsJson);
                string output;
                var truncated = false;
                if (budgetUsed >= NetMindDefaults.AiToolFetchBudgetBytesPerTurn)
                {
                    output = $"[本轮取数预算 {NetMindDefaults.AiToolFetchBudgetBytesPerTurn / 1024} KB 已用尽，本次工具调用未执行；请基于已取回的数据作答]";
                    truncated = true;
                }
                else
                {
                    output = await ExecuteToolAsync(provider, call, cancellationToken);
                    var outputBytes = Encoding.UTF8.GetByteCount(output);
                    var remaining = NetMindDefaults.AiToolFetchBudgetBytesPerTurn - budgetUsed;
                    if (outputBytes > remaining)
                    {
                        output = TruncateToBytes(output, remaining) +
                                  $"\n[本轮取数预算 {NetMindDefaults.AiToolFetchBudgetBytesPerTurn / 1024} KB 已用尽，本条结果被截断]";
                        budgetUsed = NetMindDefaults.AiToolFetchBudgetBytesPerTurn;
                        truncated = true;
                    }
                    else
                    {
                        budgetUsed += outputBytes;
                    }
                }
                toolFetchCount++;
                toolTraces.Add(AiEvidenceLedger.CreateTrace(call.Name, call.ArgumentsJson, output, truncated));
                workingHistory.Add(new AiChatMessage("tool", output, ToolCallId: call.Id, Name: call.Name));
            }
        }

        stopwatch.Stop();
        return new AiTurnOutcome(assistantText, toolFetchCount, inputTokens, outputTokens,
            stopwatch.ElapsedMilliseconds, finishReason, iterationCapReached);
    }

    /// <summary>执行单个工具调用；参数或执行异常时返回中文错误文本而非抛出，保证回环不中断。</summary>
    private static async Task<string> ExecuteToolAsync(AiEvidenceProvider provider, AiToolCall call, CancellationToken cancellationToken)
    {
        try
        {
            JsonElement arguments;
            try
            {
                using var document = JsonDocument.Parse(call.ArgumentsJson);
                arguments = document.RootElement.Clone();
            }
            catch (JsonException)
            {
                return $"工具 {call.Name} 的参数不是有效 JSON：{call.ArgumentsJson}";
            }
            switch (call.Name)
            {
                case "get_evidence_overview":
                    return AiEvidencePreparationEngine.ToJson(provider.PreparedEvidence);
                case "get_related_transactions":
                    var centerOrdinal = arguments.TryGetProperty("ordinal", out var centerElement) && centerElement.TryGetInt32(out var parsedOrdinal)
                        ? parsedOrdinal : 0;
                    if (centerOrdinal < 1 || centerOrdinal > provider.Pool.Count)
                        return $"未提供有效中心序号（有效范围 #1 到 #{provider.Pool.Count}）。";
                    var relatedLimit = arguments.TryGetProperty("limit", out var relatedLimitElement) && relatedLimitElement.TryGetInt32(out var parsedRelatedLimit)
                        ? Math.Clamp(parsedRelatedLimit, 1, 50) : 12;
                    return AiEvidencePreparationEngine.ToJson(AiEvidencePreparationEngine.GetRelated(provider.PreparedEvidence, centerOrdinal, relatedLimit));
                case "compare_transactions":
                    var compareOrdinals = arguments.TryGetProperty("ordinals", out var compareArray) && compareArray.ValueKind == JsonValueKind.Array
                        ? compareArray.EnumerateArray()
                            .Where(element => element.ValueKind == JsonValueKind.Number && element.TryGetInt32(out _))
                            .Select(element => element.GetInt32()).ToArray()
                        : [];
                    if (compareOrdinals.Length < 2) return "至少提供两个有效事务序号才能比较。";
                    return AiEvidencePreparationEngine.ToJson(AiEvidencePreparationEngine.Compare(provider.Pool, compareOrdinals));
                case "get_transactions":
                    var ordinals = arguments.TryGetProperty("ordinals", out var ordinalArray) && ordinalArray.ValueKind == JsonValueKind.Array
                        ? ordinalArray.EnumerateArray()
                            .Where(element => element.ValueKind == JsonValueKind.Number && element.TryGetInt32(out _))
                            .Select(element => element.GetInt32())
                            .Where(ordinal => ordinal >= 1 && ordinal <= provider.Pool.Count)
                            .Distinct()
                            .Take(NetMindDefaults.AiToolMaximumOrdinalsPerFetch)
                            .ToArray()
                        : [];
                    if (ordinals.Length == 0) return "未提供有效的事务序号（序号从 1 起，且必须在证据池范围内）。";
                    return await provider.GetTransactionsAsync(ordinals, cancellationToken);
                case "get_transaction_body_excerpt":
                    var bodyOrdinal = arguments.TryGetProperty("ordinal", out var bodyOrdinalElement) && bodyOrdinalElement.TryGetInt32(out var parsedBodyOrdinal)
                        ? parsedBodyOrdinal : 0;
                    if (bodyOrdinal < 1 || bodyOrdinal > provider.Pool.Count)
                        return $"未提供有效事务序号（有效范围 #1 到 #{provider.Pool.Count}）。";
                    var direction = arguments.TryGetProperty("direction", out var directionElement) && directionElement.ValueKind == JsonValueKind.String
                        ? directionElement.GetString()?.Trim().ToLowerInvariant() : null;
                    if (direction is not ("request" or "response")) return "direction 必须是 request 或 response。";
                    var bodyKeyword = arguments.TryGetProperty("keyword", out var bodyKeywordElement) && bodyKeywordElement.ValueKind == JsonValueKind.String
                        ? bodyKeywordElement.GetString()?.Trim() : null;
                    var maximumCharacters = arguments.TryGetProperty("max_characters", out var maximumCharactersElement) && maximumCharactersElement.TryGetInt32(out var parsedMaximumCharacters)
                        ? Math.Clamp(parsedMaximumCharacters, 512, NetMindDefaults.AiToolBodyExcerptMaximumCharacters)
                        : NetMindDefaults.AiToolBodyExcerptDefaultCharacters;
                    return await provider.GetTransactionBodyExcerptAsync(
                        bodyOrdinal, direction!, bodyKeyword, maximumCharacters, cancellationToken);
                case "search_transactions":
                    var keyword = arguments.TryGetProperty("keyword", out var keywordElement) && keywordElement.ValueKind == JsonValueKind.String
                        ? keywordElement.GetString()?.Trim() : null;
                    if (string.IsNullOrWhiteSpace(keyword)) return "未提供搜索关键字。";
                    return await provider.SearchAsync(keyword, cancellationToken);
                case "get_page_hooks":
                    var type = arguments.TryGetProperty("type", out var typeElement) && typeElement.ValueKind == JsonValueKind.String
                        ? typeElement.GetString() : null;
                    var limit = arguments.TryGetProperty("limit", out var limitElement) && limitElement.TryGetInt32(out var parsedLimit)
                        ? Math.Clamp(parsedLimit, 1, 200) : 50;
                    return await provider.GetHooksAsync(type, limit, cancellationToken);
                case "get_evidence_files":
                    var names = arguments.TryGetProperty("names", out var namesElement) && namesElement.ValueKind == JsonValueKind.Array
                        ? namesElement.EnumerateArray()
                            .Where(element => element.ValueKind == JsonValueKind.String)
                            .Select(element => element.GetString()?.Trim())
                            .Where(name => !string.IsNullOrWhiteSpace(name))
                            .Select(name => name!)
                            .Distinct(StringComparer.OrdinalIgnoreCase)
                            .Take(20)
                            .ToArray()
                        : [];
                    if (provider.EvidenceFileNames.Count == 0) return "[当前会话没有添加证据文件]";
                    return await provider.GetEvidenceFilesAsync(names, cancellationToken);
                default:
                    return $"未知工具：{call.Name}";
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception)
        {
            return $"工具 {call.Name} 执行失败：{exception.Message}";
        }
    }

    /// <summary>
    /// 会话体积保护：消息 JSON 累计超过上限时，把最早的 tool 结果替换为折叠占位，
    /// 保留最近的取数结果与全部结构，会话不断。
    /// </summary>
    public static void FoldHistoryIfNeeded(List<AiChatMessage> history)
    {
        var totalBytes = EstimateHistoryBytes(history);
        if (totalBytes <= NetMindDefaults.AiConversationMaximumHistoryBytes) return;
        for (var index = 0; index < history.Count && totalBytes > NetMindDefaults.AiConversationMaximumHistoryBytes; index++)
        {
            var message = history[index];
            if (message.Role != "tool" || message.Content is null || message.Content == NetMindDefaults.AiToolResultFoldedPlaceholder) continue;
            var savedBytes = Encoding.UTF8.GetByteCount(message.Content) - Encoding.UTF8.GetByteCount(NetMindDefaults.AiToolResultFoldedPlaceholder);
            history[index] = message with { Content = NetMindDefaults.AiToolResultFoldedPlaceholder };
            totalBytes -= Math.Max(0, savedBytes);
        }
    }

    /// <summary>估算消息历史序列化后的字节数（与实际请求负载同量级）。</summary>
    public static long EstimateHistoryBytes(IReadOnlyList<AiChatMessage> history) =>
        history.Sum(message => Encoding.UTF8.GetByteCount(AiChatMessageJson.Serialize(message)));

    /// <summary>
    /// 构建发给模型的长期历史：旧工具调用及其原文全部移除，只保留用户问题和收尾回答。
    /// 当前轮工具协议由 <see cref="RunTurnAsync"/> 的临时工作历史维护。
    /// </summary>
    public static List<AiChatMessage> CreateGatewayHistory(IReadOnlyList<AiChatMessage> history)
    {
        var result = new List<AiChatMessage>(history.Count);
        foreach (var message in history)
        {
            if (message.Role == "tool") continue;
            if (message.Role == "assistant" && message.ToolCalls is { Count: > 0 }) continue;
            if (message.Role == "user" && message.Content?.StartsWith("[系统]", StringComparison.Ordinal) == true) continue;
            result.Add(message.ToolTraces is null ? message : message with { ToolTraces = null });
        }
        var ledger = AiEvidenceLedger.BuildCompact(history);
        if (ledger.Length > 0)
        {
            var systemIndex = result.FindIndex(message => message.Role == "system");
            if (systemIndex >= 0)
            {
                var system = result[systemIndex];
                result[systemIndex] = system with { Content = string.Join("\n\n", new[] { system.Content, ledger }.Where(value => !string.IsNullOrWhiteSpace(value))) };
            }
            else
            {
                result.Insert(0, new AiChatMessage("system", ledger));
            }
        }
        return result;
    }

    private static string TruncateToBytes(string value, int maximumBytes)
    {
        if (maximumBytes <= 0 || value.Length == 0) return string.Empty;
        if (Encoding.UTF8.GetByteCount(value) <= maximumBytes) return value;
        // 二分查找最大可保留字符数（UTF-8 每字符至少 1 字节，右界取 maximumBytes）。
        var low = 0;
        var high = Math.Min(value.Length, maximumBytes);
        while (low < high)
        {
            var mid = (low + high + 1) / 2;
            if (Encoding.UTF8.GetByteCount(value.AsSpan(0, mid)) <= maximumBytes) low = mid;
            else high = mid - 1;
        }
        return value[..low];
    }

    private static async Task AppendAsync(List<AiChatMessage> history, AiChatMessage message,
        AiConversationStore? store, Guid conversationId, CancellationToken cancellationToken)
    {
        history.Add(message);
        if (store is not null && conversationId != Guid.Empty)
            await store.AppendMessageAsync(conversationId, message, cancellationToken);
    }
}
