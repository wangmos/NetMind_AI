using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace NetMind.Core;

/// <summary>
/// AI 对话中的一条消息（system/user/assistant/tool 四种角色），
/// 助手消息可携带 tool_calls，tool 消息以 ToolCallId 关联对应的调用。
/// 会话历史以该结构逐条持久化；网关请求由手工投影构造，末尾的界面展示统计字段不会发给模型。
/// </summary>
public sealed record AiChatMessage(
    string Role,
    string? Content,
    IReadOnlyList<AiToolCall>? ToolCalls = null,
    string? ToolCallId = null,
    string? Name = null,
    /// <summary>本轮从提问到该回复完成的累计耗时（毫秒），仅收尾助手消息携带，供界面展示。</summary>
    long? ElapsedMilliseconds = null,
    /// <summary>本轮累计输入令牌（含取数回环的多次调用），仅收尾助手消息携带。</summary>
    int? InputTokens = null,
    /// <summary>本轮累计输出令牌，仅收尾助手消息携带。</summary>
    int? OutputTokens = null,
    /// <summary>本轮工具调用的轻量审计信息；不包含工具原文，也不会投影给模型。</summary>
    IReadOnlyList<AiToolTrace>? ToolTraces = null,
    /// <summary>消息写入会话文件的时间；旧会话没有该字段时保持为空。</summary>
    DateTimeOffset? CreatedAt = null);

/// <summary>模型发起的一次工具调用：Id 用于关联 tool 角色回传结果，ArgumentsJson 是工具参数的原始 JSON。</summary>
public sealed record AiToolCall(string Id, string Name, string ArgumentsJson);

/// <summary>工具调用的持久化摘要。原始结果只存在于当前模型回环，后续追问按需重新取证。</summary>
public sealed record AiToolTrace(
    string Name,
    string ArgumentsJson,
    int ResultCharacters,
    int ResultBytes,
    bool Truncated,
    /// <summary>实际送入当前模型回环的工具结果 SHA-256；只用于完整性核对，不包含结果原文。</summary>
    string ResultSha256 = "",
    /// <summary>由工具名和参数生成的稳定引用；追问可据此判断是否需要重新取证。</summary>
    string EvidenceReference = "");

/// <summary>工具声明（名称、描述、参数 JSON Schema），序列化进网关请求的 tools 字段。</summary>
public sealed record AiToolSchema(string Name, string Description, JsonElement Parameters);

/// <summary>单轮网关结果：文本、工具调用列表、令牌用量、停止原因与耗时。</summary>
public sealed record AiTurnResult(
    string ResponseId,
    string Model,
    string Text,
    string ReasoningText,
    IReadOnlyList<AiToolCall> ToolCalls,
    int InputTokens,
    int OutputTokens,
    string FinishReason,
    long DurationMilliseconds);

/// <summary>对话轮的流式回调：界面实时消费文本/推理增量与取数进度；回调在请求线程触发，界面侧自行调度 UI 线程。</summary>
public sealed class AiStreamCallbacks
{
    public Action<string>? OnTextDelta { get; init; }
    public Action<string>? OnReasoningDelta { get; init; }
    /// <summary>模型返回的一个 tool_call 即将执行取数（工具名、参数 JSON）。</summary>
    public Action<string, string>? OnToolFetch { get; init; }
    /// <summary>网关响应已接收的累计字节数（含 SSE 全部行与非流式正文），供界面实时对照响应上限。</summary>
    public Action<long>? OnResponseBytes { get; init; }
}

/// <summary>会话消息的 JSONL 序列化约定：中文不转义、空字段省略，保证文件可读且体积紧凑。</summary>
public static class AiChatMessageJson
{
    public static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public static string Serialize(AiChatMessage message) => JsonSerializer.Serialize(message, Options);

    public static AiChatMessage? Deserialize(string line) => JsonSerializer.Deserialize<AiChatMessage>(line, Options);
}
