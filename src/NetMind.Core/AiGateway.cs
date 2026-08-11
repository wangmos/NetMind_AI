using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace NetMind.Core;

public sealed record AiGatewaySettings(
    string Endpoint = "https://api.deepseek.com",
    string Model = "deepseek-v4-flash",
    string ApiStyle = "chat_completions",
    string ReasoningEffort = "high",
    int MaxOutputTokens = 8192,
    int TimeoutSeconds = NetMindDefaults.AiDefaultRequestTimeoutSeconds,
    int MaximumResponseBytes = NetMindDefaults.AiMaximumResponseBytes)
{
    public AiGatewaySettings Validate()
    {
        if (!Uri.TryCreate(Endpoint, UriKind.Absolute, out var endpoint))
            throw new InvalidOperationException("模型网关地址必须是绝对 URL。");
        if (endpoint.Scheme != Uri.UriSchemeHttps && !(endpoint.Scheme == Uri.UriSchemeHttp && IPAddress.TryParse(endpoint.Host, out var address) && IPAddress.IsLoopback(address)) &&
            !(endpoint.Scheme == Uri.UriSchemeHttp && endpoint.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase)))
            throw new InvalidOperationException("模型网关必须使用 HTTPS；仅本机回环地址允许使用 HTTP。");
        if (string.IsNullOrWhiteSpace(Model) || Model.Length > NetMindDefaults.AiModelNameMaximumCharacters)
            throw new InvalidOperationException("模型名称不能为空，且不得超过 128 个字符。");
        var effort = ReasoningEffort.Trim().ToLowerInvariant();
        if (effort is not ("none" or "low" or "medium" or "high" or "xhigh" or "max"))
            throw new InvalidOperationException("推理强度必须是 none、low、medium、high、xhigh 或 max。");
        if (MaxOutputTokens is < NetMindDefaults.AiMinimumOutputTokens or > NetMindDefaults.AiMaximumOutputTokens)
            throw new InvalidOperationException("输出令牌上限必须在 256–65,536 之间。");
        if (TimeoutSeconds is < NetMindDefaults.AiMinimumRequestTimeoutSeconds or > NetMindDefaults.AiMaximumRequestTimeoutSeconds)
            throw new InvalidOperationException("请求超时必须在 10–600 秒之间。");
        if (MaximumResponseBytes is < NetMindDefaults.AiMinimumResponseBytes or > NetMindDefaults.AiConfigurableMaximumResponseBytes)
            throw new InvalidOperationException("响应上限必须在 8–128 MB 之间。");
        return this with
        {
            Endpoint = endpoint.AbsoluteUri,
            Model = Model.Trim(),
            ApiStyle = NormalizeApiStyle(ApiStyle),
            ReasoningEffort = effort,
            MaxOutputTokens = MaxOutputTokens
        };
    }

    private static string NormalizeApiStyle(string value) => value.Trim().ToLowerInvariant() switch
    {
        "responses" => "responses",
        "chat_completions" or "chat" or "chat/completions" => "chat_completions",
        _ => throw new InvalidOperationException("接口类型必须是 responses 或 chat_completions。")
    };
}

public sealed record AiAnalysisResult(
    string ResponseId,
    string Model,
    string Text,
    int InputTokens,
    int OutputTokens,
    string FinishReason,
    long DurationMilliseconds);

public sealed class AiGatewayException(string message, HttpStatusCode? statusCode = null) : Exception(message)
{
    public HttpStatusCode? StatusCode { get; } = statusCode;
    /// <summary>网关原始响应 JSON：提取不到文本结果时保留，供界面以 JSON 树展示便于排查。</summary>
    public string? RawResponseJson { get; init; }
}

/// <summary>
/// 对话式模型网关客户端：流式（SSE）请求 + function calling。
/// 每轮发送完整消息历史与工具声明，累积文本/推理增量与 tool_calls 分片后返回 <see cref="AiTurnResult"/>；
/// 网关不支持流式而返回单 JSON 时自动按非流式结构兜底解析。
/// </summary>
public sealed class AiGatewayClient(HttpClient? httpClient = null) : IDisposable
{
    // 单次响应字节上限已改为按次请求配置（AiGatewaySettings.MaximumResponseBytes），不再使用类级常量。
    // 已接收字节进度上报的节流步长：每累计 128 KB 回调一次，避免高频行增量频繁触发界面刷新。
    private const long ResponseBytesReportStride = 128 * 1024;
    // 中文提问与证据保持原样序列化，避免 \u 转义增加模型令牌消耗。
    private static readonly JsonSerializerOptions PayloadJsonOptions = new() { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };
    private readonly HttpClient _httpClient = httpClient ?? new HttpClient { Timeout = System.Threading.Timeout.InfiniteTimeSpan };
    private readonly bool _ownsClient = httpClient is null;

    /// <summary>
    /// 发送完整消息历史与工具声明执行一轮对话。流式返回时经 <paramref name="callbacks"/> 实时上送增量；
    /// 模型要求调用工具时结果放在 <see cref="AiTurnResult.ToolCalls"/>，由会话引擎执行后追加 tool 消息再次调用。
    /// </summary>
    /// <param name="enableReasoning">
    /// 是否启用模型的扩展思考。取证分析需要它；一次性代码生成不需要——
    /// 思考令牌会占掉输出预算的绝大部分（实测生成 30 行脚本花掉 13,000 输出令牌），
    /// 而且思考内容对这类任务没有任何用处。
    /// </param>
    public async Task<AiTurnResult> AnalyzeConversationAsync(AiGatewaySettings settings, string? apiKey,
        IReadOnlyList<AiChatMessage> messages, IReadOnlyList<AiToolSchema> tools,
        AiStreamCallbacks? callbacks = null, CancellationToken cancellationToken = default,
        bool enableReasoning = true)
    {
        settings = settings.Validate();
        if (messages.Count == 0) throw new InvalidOperationException("没有可发送的对话消息。");
        var requestUri = ResolveRequestUri(settings.Endpoint, settings.ApiStyle);
        if (!IsLoopback(requestUri) && string.IsNullOrWhiteSpace(apiKey))
            throw new InvalidOperationException("远程模型网关需要 API 密钥。");

        var payload = settings.ApiStyle == "chat_completions"
            ? BuildChatCompletionsPayload(settings, messages, tools, enableReasoning)
            : BuildResponsesPayload(settings, messages, tools, enableReasoning);
        using var request = new HttpRequestMessage(HttpMethod.Post, requestUri)
        {
            Content = new StringContent(payload, Encoding.UTF8, "application/json")
        };
        if (!string.IsNullOrWhiteSpace(apiKey)) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", apiKey.Trim());
        request.Headers.UserAgent.ParseAdd("NetMind-AI/1.0");

        var stopwatch = Stopwatch.StartNew();
        // 超时按本次请求配置生效（外部传入的 HttpClient 可能自带默认超时，统一用取消令牌叠加约束）。
        using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutSource.CancelAfter(TimeSpan.FromSeconds(settings.TimeoutSeconds));
        try
        {
            using var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeoutSource.Token);
            if (!response.IsSuccessStatusCode)
            {
                                var errorBytes = await ReadBoundedAsync(await response.Content.ReadAsStreamAsync(timeoutSource.Token), timeoutSource.Token, settings.MaximumResponseBytes, callbacks?.OnResponseBytes);
                stopwatch.Stop();
                using var errorDocument = ParseResponse(errorBytes);
                throw new AiGatewayException(ReadError(errorDocument.RootElement, response.StatusCode), response.StatusCode)
                {
                    RawResponseJson = TruncateForDisplay(Encoding.UTF8.GetString(errorBytes))
                };
            }
            var contentType = response.Content.Headers.ContentType?.MediaType ?? string.Empty;
            await using var responseStream = await response.Content.ReadAsStreamAsync(timeoutSource.Token);
            if (contentType.Contains("text/event-stream", StringComparison.OrdinalIgnoreCase))
                return await ReadSseAsync(responseStream, settings, callbacks, stopwatch, timeoutSource.Token);
            // 非流式兜底：部分网关忽略 stream=true 直接返回单 JSON。
                        var bodyBytes = await ReadBoundedAsync(responseStream, timeoutSource.Token, settings.MaximumResponseBytes, callbacks?.OnResponseBytes);
            stopwatch.Stop();
            using var document = ParseResponse(bodyBytes);
            var fallback = settings.ApiStyle == "chat_completions"
                ? ParseChatCompletion(document.RootElement)
                : ParseResponses(document.RootElement);
            if (fallback.Text.Length == 0 && fallback.ToolCalls.Count == 0)
                throw new AiGatewayException("模型网关返回成功，但没有可显示的文本结果。", response.StatusCode)
                {
                    RawResponseJson = TruncateForDisplay(Encoding.UTF8.GetString(bodyBytes))
                };
            return fallback with { DurationMilliseconds = stopwatch.ElapsedMilliseconds };
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            stopwatch.Stop();
            throw new AiGatewayException($"模型网关请求超时（{settings.TimeoutSeconds} 秒），可在 AI 分析页调大请求超时后重试。");
        }
    }

    private static string TruncateForDisplay(string value) => value.Length <= 60_000 ? value : value[..60_000] + "…";

    private static string BuildChatCompletionsPayload(AiGatewaySettings settings, IReadOnlyList<AiChatMessage> messages,
        IReadOnlyList<AiToolSchema> tools, bool enableReasoning)
    {
        var payload = new Dictionary<string, object?>
        {
            ["model"] = settings.Model,
            ["stream"] = true,
            ["max_tokens"] = settings.MaxOutputTokens,
            ["messages"] = messages.Select(SerializeChatMessage).ToArray(),
            ["stream_options"] = new { include_usage = true }
        };
        if (tools.Count > 0)
        {
            payload["tools"] = tools.Select(tool => new
            {
                type = "function",
                function = new { name = tool.Name, description = tool.Description, parameters = tool.Parameters }
            }).ToArray();
            payload["tool_choice"] = "auto";
        }
        if (settings.Model.StartsWith("deepseek-", StringComparison.OrdinalIgnoreCase))
        {
            // DeepSeek 官方文档：thinking 与 function calling 不可同时使用；携带 tools 时不启用 thinking，reasoning_effort 保留。
            // 调用方显式关闭思考时两个字段都不下发——否则「无工具」这一条会把一次性代码生成也带进思考模式。
            if (enableReasoning)
            {
                if (tools.Count == 0) payload["thinking"] = new { type = "enabled" };
                payload["reasoning_effort"] = settings.ReasoningEffort is "max" or "xhigh" ? "max" : "high";
            }
        }
        return JsonSerializer.Serialize(payload, PayloadJsonOptions);
    }

    private static Dictionary<string, object?> SerializeChatMessage(AiChatMessage message)
    {
        var result = new Dictionary<string, object?> { ["role"] = message.Role };
        if (message.Content is not null) result["content"] = message.Content;
        if (message.ToolCalls is { Count: > 0 })
            result["tool_calls"] = message.ToolCalls.Select(call => new
            {
                id = call.Id,
                type = "function",
                function = new { name = call.Name, arguments = call.ArgumentsJson }
            }).ToArray();
        if (message.ToolCallId is not null) result["tool_call_id"] = message.ToolCallId;
        if (message.Name is not null) result["name"] = message.Name;
        return result;
    }

    private static string BuildResponsesPayload(AiGatewaySettings settings, IReadOnlyList<AiChatMessage> messages,
        IReadOnlyList<AiToolSchema> tools, bool enableReasoning)
    {
        var input = new List<object>();
        foreach (var message in messages)
        {
            switch (message.Role)
            {
                case "system":
                case "user":
                    input.Add(new { role = message.Role, content = new[] { new { type = "input_text", text = message.Content ?? string.Empty } } });
                    break;
                case "assistant":
                    if (!string.IsNullOrEmpty(message.Content))
                        input.Add(new { role = "assistant", content = new[] { new { type = "output_text", text = message.Content } } });
                    if (message.ToolCalls is { Count: > 0 })
                        foreach (var call in message.ToolCalls)
                            input.Add(new { type = "function_call", call_id = call.Id, name = call.Name, arguments = call.ArgumentsJson });
                    break;
                case "tool":
                    input.Add(new { type = "function_call_output", call_id = message.ToolCallId, output = message.Content ?? string.Empty });
                    break;
            }
        }
        var payload = new Dictionary<string, object?>
        {
            ["model"] = settings.Model,
            ["store"] = false,
            ["stream"] = true,
            ["max_output_tokens"] = settings.MaxOutputTokens,
            ["reasoning"] = new { effort = enableReasoning ? settings.ReasoningEffort : "minimal" },
            ["text"] = new { verbosity = "medium" },
            ["input"] = input.ToArray()
        };
        if (tools.Count > 0)
        {
            payload["tools"] = tools.Select(tool => new
            {
                type = "function",
                name = tool.Name,
                description = tool.Description,
                parameters = tool.Parameters
            }).ToArray();
            payload["tool_choice"] = "auto";
        }
        return JsonSerializer.Serialize(payload, PayloadJsonOptions);
    }

    // ── SSE 流式解析 ─────────────────────────────────────────────────────────

    private sealed class SseAccumulator
    {
        public string ResponseId = string.Empty;
        public string Model = string.Empty;
        public readonly StringBuilder Text = new();
        public readonly StringBuilder Reasoning = new();
        public string FinishReason = string.Empty;
        public int InputTokens;
        public int OutputTokens;
        public readonly List<AiToolCallBuilder> ToolCalls = [];

        public AiTurnResult ToResult(long durationMilliseconds) => new(
            ResponseId, Model, Text.ToString().Trim(), Reasoning.ToString(),
            ToolCalls.Select(builder => builder.ToToolCall()).Where(call => call.Name.Length > 0).ToArray(),
            InputTokens, OutputTokens, FinishReason, durationMilliseconds);
    }

    /// <summary>chat_completions 的 tool_calls 按 index 分片到达：同一调用的 id/name/arguments 需跨多个增量拼接。</summary>
    private sealed class AiToolCallBuilder
    {
        public string Id = string.Empty;
        public readonly StringBuilder Name = new();
        public readonly StringBuilder Arguments = new();

        public AiToolCallBuilder AppendCompleted(string name, string arguments)
        {
            Name.Append(name);
            Arguments.Append(arguments);
            return this;
        }

        public AiToolCall ToToolCall() => new(
            string.IsNullOrEmpty(Id) ? "call-" + Guid.NewGuid().ToString("N") : Id,
            Name.ToString(), Arguments.ToString());
    }

    private static async Task<AiTurnResult> ReadSseAsync(Stream stream, AiGatewaySettings settings,
        AiStreamCallbacks? callbacks, Stopwatch stopwatch, CancellationToken cancellationToken)
    {
        var accumulator = new SseAccumulator();
        long bytesRead = 0;
        var lastReported = 0L;
        using var reader = new StreamReader(stream, Encoding.UTF8);
        while (await reader.ReadLineAsync(cancellationToken) is { } line)
        {
            // 响应上限定义为 UTF-8 字节数；按 UTF-16 字符数统计会对中文等多字节内容严重低估。
            bytesRead += Encoding.UTF8.GetByteCount(line) + 1; // 加上被 ReadLineAsync 去掉的换行符
            if (bytesRead > settings.MaximumResponseBytes) throw new AiGatewayException($"模型网关响应超过 {settings.MaximumResponseBytes / 1024 / 1024} MB 安全限制（可在 AI 配置页调大响应上限）。");
            // 实时上送已接收字节数，供界面对照响应上限展示当前容量。
            if (callbacks?.OnResponseBytes is { } reportBytes && bytesRead - lastReported >= ResponseBytesReportStride)
            {
                lastReported = bytesRead;
                reportBytes(bytesRead);
            }
            if (!line.StartsWith("data:", StringComparison.Ordinal)) continue;
            var data = line[5..].TrimStart();
            if (data.Length == 0 || data == "[DONE]") continue;
            JsonElement root;
            try
            {
                using var document = JsonDocument.Parse(data);
                root = document.RootElement.Clone();
            }
            catch (JsonException)
            {
                continue; // 单条增量 JSON 无效时跳过，不中断整轮流式。
            }
            if (root.TryGetProperty("error", out var error) && error.ValueKind == JsonValueKind.Object)
                throw new AiGatewayException(ReadError(root, HttpStatusCode.OK)) { RawResponseJson = TruncateForDisplay(data) };
            if (settings.ApiStyle == "chat_completions") ApplyChatChunk(root, accumulator, callbacks);
            else ApplyResponsesEvent(root, accumulator, callbacks);
        }
        callbacks?.OnResponseBytes?.Invoke(bytesRead);
        stopwatch.Stop();
        var result = accumulator.ToResult(stopwatch.ElapsedMilliseconds);
        if (result.FinishReason == "length" && result.Text.Length > 0)
            result = result with { Text = result.Text + "\n\n[模型达到输出上限，结果可能未完整结束。]" };
        return result;
    }

    private static void ApplyChatChunk(JsonElement root, SseAccumulator accumulator, AiStreamCallbacks? callbacks)
    {
        var responseId = ReadString(root, "id");
        if (responseId.Length > 0) accumulator.ResponseId = responseId;
        var model = ReadString(root, "model");
        if (model.Length > 0) accumulator.Model = model;
        if (root.TryGetProperty("usage", out var usage))
        {
            accumulator.InputTokens = ReadInt32(usage, "prompt_tokens");
            accumulator.OutputTokens = ReadInt32(usage, "completion_tokens");
        }
        if (!root.TryGetProperty("choices", out var choices) || choices.ValueKind != JsonValueKind.Array) return;
        foreach (var choice in choices.EnumerateArray())
        {
            var finishReason = ReadString(choice, "finish_reason");
            if (finishReason.Length > 0) accumulator.FinishReason = finishReason;
            if (!choice.TryGetProperty("delta", out var delta) || delta.ValueKind != JsonValueKind.Object) continue;
            var textDelta = ReadString(delta, "content");
            if (textDelta.Length > 0)
            {
                accumulator.Text.Append(textDelta);
                callbacks?.OnTextDelta?.Invoke(textDelta);
            }
            var reasoningDelta = ReadString(delta, "reasoning_content");
            if (reasoningDelta.Length > 0)
            {
                accumulator.Reasoning.Append(reasoningDelta);
                callbacks?.OnReasoningDelta?.Invoke(reasoningDelta);
            }
            if (!delta.TryGetProperty("tool_calls", out var toolCalls) || toolCalls.ValueKind != JsonValueKind.Array) continue;
            foreach (var item in toolCalls.EnumerateArray())
            {
                var index = item.TryGetProperty("index", out var indexElement) && indexElement.TryGetInt32(out var parsed) ? parsed : 0;
                while (accumulator.ToolCalls.Count <= index) accumulator.ToolCalls.Add(new AiToolCallBuilder());
                var builder = accumulator.ToolCalls[index];
                var callId = ReadString(item, "id");
                if (callId.Length > 0) builder.Id = callId;
                if (item.TryGetProperty("function", out var function))
                {
                    var name = ReadString(function, "name");
                    if (name.Length > 0) builder.Name.Append(name);
                    builder.Arguments.Append(ReadString(function, "arguments"));
                }
            }
        }
    }

    private static void ApplyResponsesEvent(JsonElement root, SseAccumulator accumulator, AiStreamCallbacks? callbacks)
    {
        var eventType = ReadString(root, "type");
        switch (eventType)
        {
            case "response.created":
                if (root.TryGetProperty("response", out var created))
                {
                    accumulator.ResponseId = ReadString(created, "id");
                    accumulator.Model = ReadString(created, "model");
                }
                break;
            case "response.output_text.delta":
                var textDelta = ReadString(root, "delta");
                if (textDelta.Length > 0)
                {
                    accumulator.Text.Append(textDelta);
                    callbacks?.OnTextDelta?.Invoke(textDelta);
                }
                break;
            case "response.output_item.done":
                // function_call 项完成时携带完整 call_id/name/arguments，直接取最终值，不依赖增量拼接。
                if (root.TryGetProperty("item", out var item) && ReadString(item, "type") == "function_call")
                {
                    accumulator.ToolCalls.Add(new AiToolCallBuilder
                    {
                        Id = ReadString(item, "call_id", ReadString(item, "id", "call-" + Guid.NewGuid().ToString("N")))
                    }.AppendCompleted(ReadString(item, "name"), ReadString(item, "arguments")));
                }
                break;
            case "response.completed":
                if (!root.TryGetProperty("response", out var completed)) break;
                accumulator.FinishReason = ReadString(completed, "status");
                if (completed.TryGetProperty("usage", out var usage))
                {
                    accumulator.InputTokens = ReadInt32(usage, "input_tokens");
                    accumulator.OutputTokens = ReadInt32(usage, "output_tokens");
                }
                break;
        }
    }

    // ── 非流式兜底解析 ───────────────────────────────────────────────────────

    private static AiTurnResult ParseChatCompletion(JsonElement root)
    {
        var text = new StringBuilder();
        var reasoning = new StringBuilder();
        var calls = new List<AiToolCall>();
        var finishReason = string.Empty;
        if (root.TryGetProperty("choices", out var choices) && choices.ValueKind == JsonValueKind.Array)
        {
            foreach (var choice in choices.EnumerateArray())
            {
                var choiceFinish = ReadString(choice, "finish_reason");
                if (choiceFinish.Length > 0) finishReason = choiceFinish;
                if (!choice.TryGetProperty("message", out var message) || message.ValueKind != JsonValueKind.Object) continue;
                // 部分网关（推理模型）正文放在 reasoning_content，或 content 为 null；逐字段兜底避免漏提。
                var content = ReadString(message, "content");
                if (content.Length > 0) text.Append(content);
                var reasoningContent = ReadString(message, "reasoning_content");
                if (reasoningContent.Length > 0) reasoning.Append(reasoningContent);
                if (message.TryGetProperty("tool_calls", out var toolCalls) && toolCalls.ValueKind == JsonValueKind.Array)
                {
                    foreach (var call in toolCalls.EnumerateArray())
                    {
                        if (!call.TryGetProperty("function", out var function)) continue;
                        calls.Add(new AiToolCall(
                            ReadString(call, "id", "call-" + Guid.NewGuid().ToString("N")),
                            ReadString(function, "name"),
                            ReadString(function, "arguments")));
                    }
                }
            }
        }
        var usage = root.TryGetProperty("usage", out var usageElement) ? usageElement : default;
        return new AiTurnResult(
            ReadString(root, "id"), ReadString(root, "model"), text.ToString().Trim(), reasoning.ToString(),
            calls, ReadInt32(usage, "prompt_tokens"), ReadInt32(usage, "completion_tokens"), finishReason, 0);
    }

    private static AiTurnResult ParseResponses(JsonElement root)
    {
        var text = new List<string>();
        var calls = new List<AiToolCall>();
        if (root.TryGetProperty("output", out var output) && output.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in output.EnumerateArray())
            {
                var itemType = ReadString(item, "type");
                if (itemType == "function_call")
                {
                    calls.Add(new AiToolCall(
                        ReadString(item, "call_id", ReadString(item, "id", "call-" + Guid.NewGuid().ToString("N"))),
                        ReadString(item, "name"), ReadString(item, "arguments")));
                    continue;
                }
                if (!item.TryGetProperty("content", out var content) || content.ValueKind != JsonValueKind.Array) continue;
                foreach (var part in content.EnumerateArray())
                {
                    var partType = ReadString(part, "type");
                    if (partType is not ("output_text" or "summary_text" or "text")) continue;
                    var partText = ReadString(part, "text");
                    if (partText.Length > 0) text.Add(partText);
                }
            }
        }
        var directText = ReadString(root, "output_text");
        if (directText.Length > 0) text.Add(directText);
        var usage = root.TryGetProperty("usage", out var usageElement) ? usageElement : default;
        return new AiTurnResult(
            ReadString(root, "id"), ReadString(root, "model"),
            string.Join(Environment.NewLine, text.Where(part => !string.IsNullOrWhiteSpace(part))).Trim(),
            string.Empty, calls,
            ReadInt32(usage, "input_tokens"), ReadInt32(usage, "output_tokens"),
            ReadString(root, "status"), 0);
    }

    private static Uri ResolveRequestUri(string endpoint, string apiStyle)
    {
        var uri = new Uri(endpoint, UriKind.Absolute);
        var suffix = apiStyle == "chat_completions" ? "/chat/completions" : "/responses";
        if (uri.AbsolutePath.TrimEnd('/').EndsWith(suffix, StringComparison.OrdinalIgnoreCase)) return uri;
        return new Uri(uri.AbsoluteUri.TrimEnd('/') + suffix, UriKind.Absolute);
    }

    private static bool IsLoopback(Uri uri) => uri.IsLoopback || uri.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase);

    private static async Task<byte[]> ReadBoundedAsync(Stream stream, CancellationToken cancellationToken, int maximumResponseBytes, Action<long>? onResponseBytes = null)
    {
        using var output = new MemoryStream();
        var buffer = new byte[16 * 1024];
        var lastReported = 0L;
        while (true)
        {
            var read = await stream.ReadAsync(buffer, cancellationToken);
            if (read == 0)
            {
                onResponseBytes?.Invoke(output.Length);
                return output.ToArray();
            }
            if (output.Length + read > maximumResponseBytes) throw new AiGatewayException($"模型网关响应超过 {maximumResponseBytes / 1024 / 1024} MB 安全限制（可在 AI 配置页调大响应上限）。");
            await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
            if (onResponseBytes is not null && output.Length - lastReported >= ResponseBytesReportStride)
            {
                lastReported = output.Length;
                onResponseBytes(output.Length);
            }
        }
    }

    private static JsonDocument ParseResponse(byte[] bytes)
    {
        try { return JsonDocument.Parse(bytes); }
        catch (JsonException) { throw new AiGatewayException("模型网关返回了无效 JSON。"); }
    }

    private static string ReadError(JsonElement root, HttpStatusCode statusCode)
    {
        var message = root.TryGetProperty("error", out var error) && error.ValueKind == JsonValueKind.Object &&
                      error.TryGetProperty("message", out var detail) && detail.ValueKind == JsonValueKind.String
            ? detail.GetString()
            : null;
        message = string.IsNullOrWhiteSpace(message) ? $"模型网关返回 HTTP {(int)statusCode}。" : message;
        return message!.Length > 1000 ? message[..1000] + "…" : message;
    }

    private static string ReadString(JsonElement element, string name, string fallback = "") =>
        element.ValueKind == JsonValueKind.Object && element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString() ?? fallback
            : fallback;

    private static int ReadInt32(JsonElement element, string name) =>
        element.ValueKind == JsonValueKind.Object && element.TryGetProperty(name, out var value) && value.TryGetInt32(out var result) ? result : 0;

    public void Dispose()
    {
        if (_ownsClient) _httpClient.Dispose();
    }
}
