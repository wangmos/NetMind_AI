using System.Globalization;
using System.Text;

namespace NetMind.Core;

/// <summary>
/// AI 多轮会话的 Markdown 导出。包含系统提示、全部用户/助手消息、工具调用参数与轻量取数记录；
/// 本地原始工具结果按会话安全策略不重复长期保存，导出内容统一生成脱敏副本。
/// </summary>
public static class AiConversationExportFormatter
{
    public static string BuildMarkdown(AiConversation conversation, bool systemPromptRecovered = false)
    {
        using var writer = new StringWriter(CultureInfo.InvariantCulture);
        WriteMarkdownAsync(writer, conversation, systemPromptRecovered).GetAwaiter().GetResult();
        return writer.ToString();
    }

    public static async Task WriteMarkdownAsync(TextWriter writer, AiConversation conversation,
        bool systemPromptRecovered = false, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(conversation);
        var header = conversation.Header;
        var messages = conversation.Messages;
        var turns = AiConversationStore.CountTurns(messages);
        var finalReplies = messages.Where(message => message.Role == "assistant" && message.ToolCalls is null &&
                                                     !string.IsNullOrWhiteSpace(message.Content)).ToArray();
        var totalInputTokens = finalReplies.Sum(message => (long)(message.InputTokens ?? 0));
        var totalOutputTokens = finalReplies.Sum(message => (long)(message.OutputTokens ?? 0));
        var totalElapsedMilliseconds = finalReplies.Sum(message => message.ElapsedMilliseconds ?? 0);

        await WriteAsync(writer, "# NetMind AI 完整对话记录\n\n", cancellationToken);
        await WriteAsync(writer, $"- 会话开始：{header.CreatedAt.ToLocalTime():yyyy-MM-dd HH:mm:ss zzz}\n", cancellationToken);
        await WriteAsync(writer, $"- 导出时间：{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss zzz}\n", cancellationToken);
        await WriteAsync(writer, $"- 模型：`{Inline(header.Model)}`\n", cancellationToken);
        await WriteAsync(writer, $"- 模板：`{Inline(header.TemplateId)}`\n", cancellationToken);
        await WriteAsync(writer, $"- 分析范围：{Inline(header.ScopeName)}\n", cancellationToken);
        await WriteAsync(writer, $"- 证据事务：{header.TransactionIds.Count:N0} 条\n", cancellationToken);
        await WriteAsync(writer, $"- 对话轮数：{turns:N0} 轮\n", cancellationToken);
        await WriteAsync(writer, $"- 累计模型用量：输入 {totalInputTokens:N0} / 输出 {totalOutputTokens:N0} 令牌\n", cancellationToken);
        await WriteAsync(writer, $"- 累计耗时：{FormatDuration(totalElapsedMilliseconds)}\n\n", cancellationToken);
        await WriteAsync(writer,
            "> 导出包含完整系统提示、每轮提问、AI 回复、工具调用参数和取数规模。敏感字段已自动脱敏；" +
            "工具返回原文遵循会话安全策略，不在对话记录中重复长期保存。\n" +
            (systemPromptRecovered ? "> 此旧会话未保存原始系统提示，本次按当前同名模板补全。\n" : string.Empty) + "\n---\n\n",
            cancellationToken);

        var turn = 0;
        foreach (var message in messages)
        {
            cancellationToken.ThrowIfCancellationRequested();
            switch (message.Role)
            {
                case "system":
                    await WriteAsync(writer, "## 系统提示词\n\n", cancellationToken);
                    await WriteCodeBlockAsync(writer, AiPrivacyFilter.RedactExportText(message.Content ?? string.Empty), "text", cancellationToken);
                    break;
                case "user" when message.Content?.StartsWith("[系统]", StringComparison.Ordinal) == true:
                    await WriteAsync(writer, $"## 系统流程提示{MessageTime(message)}\n\n", cancellationToken);
                    await WriteCodeBlockAsync(writer, AiPrivacyFilter.RedactExportText(message.Content), "text", cancellationToken);
                    break;
                case "user":
                    turn++;
                    await WriteAsync(writer, $"## 第 {turn} 轮 · 用户{MessageTime(message)}\n\n", cancellationToken);
                    await WriteCodeBlockAsync(writer, AiPrivacyFilter.RedactExportText(message.Content ?? string.Empty), "text", cancellationToken);
                    break;
                case "assistant":
                    if (message.ToolCalls is { Count: > 0 })
                    {
                        await WriteAsync(writer, $"## 第 {Math.Max(1, turn)} 轮 · 工具调用{MessageTime(message)}\n\n", cancellationToken);
                        foreach (var call in message.ToolCalls)
                        {
                            await WriteAsync(writer, $"### `{Inline(call.Name)}`\n\n- 调用 ID：`{Inline(call.Id)}`\n\n", cancellationToken);
                            await WriteCodeBlockAsync(writer, AiPrivacyFilter.RedactExportText(call.ArgumentsJson), "json", cancellationToken);
                        }
                    }
                    if (!string.IsNullOrWhiteSpace(message.Content))
                    {
                        await WriteAsync(writer, $"## 第 {Math.Max(1, turn)} 轮 · AI 回复{MessageTime(message)}\n\n", cancellationToken);
                        await WriteAsync(writer, AiPrivacyFilter.RedactExportText(message.Content!).TrimEnd() + "\n\n", cancellationToken);
                    }
                    if (message.ToolTraces is { Count: > 0 })
                    {
                        await WriteAsync(writer, "### 本轮取数流程\n\n", cancellationToken);
                        for (var index = 0; index < message.ToolTraces.Count; index++)
                        {
                            var trace = message.ToolTraces[index];
                            await WriteAsync(writer, $"#### {index + 1}. `{Inline(trace.Name)}`\n\n", cancellationToken);
                            await WriteCodeBlockAsync(writer, AiPrivacyFilter.RedactExportText(trace.ArgumentsJson), "json", cancellationToken);
                            await WriteAsync(writer,
                                $"- 结果规模：{trace.ResultCharacters:N0} 字符 / {FormatBytes(trace.ResultBytes)}" +
                                (trace.Truncated ? "（已截断）" : string.Empty) + "\n" +
                                (string.IsNullOrWhiteSpace(trace.EvidenceReference) ? string.Empty : $"- 证据引用：`{Inline(trace.EvidenceReference)}`\n") +
                                (string.IsNullOrWhiteSpace(trace.ResultSha256) ? string.Empty : $"- 结果 SHA-256：`{Inline(trace.ResultSha256)}`\n") +
                                "\n", cancellationToken);
                        }
                    }
                    if (message.ElapsedMilliseconds.HasValue || message.InputTokens.HasValue || message.OutputTokens.HasValue)
                        await WriteAsync(writer,
                            $"_本轮统计：耗时 {FormatDuration(message.ElapsedMilliseconds ?? 0)}；输入 {message.InputTokens ?? 0:N0} / 输出 {message.OutputTokens ?? 0:N0} 令牌。_\n\n",
                            cancellationToken);
                    break;
                case "tool":
                    await WriteAsync(writer,
                        $"## 第 {Math.Max(1, turn)} 轮 · 工具结果 `{Inline(message.Name ?? "unknown")}`{MessageTime(message)}\n\n" +
                        (string.IsNullOrWhiteSpace(message.ToolCallId) ? string.Empty : $"- 调用 ID：`{Inline(message.ToolCallId)}`\n\n"),
                        cancellationToken);
                    await WriteCodeBlockAsync(writer, AiPrivacyFilter.RedactExportText(message.Content ?? string.Empty), "text", cancellationToken);
                    break;
            }
        }
    }

    private static async Task WriteCodeBlockAsync(TextWriter writer, string content, string language,
        CancellationToken cancellationToken)
    {
        var fence = new string('`', Math.Max(3, LongestBacktickRun(content) + 1));
        await WriteAsync(writer, $"{fence}{language}\n{content.TrimEnd()}\n{fence}\n\n", cancellationToken);
    }

    private static Task WriteAsync(TextWriter writer, string value, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return writer.WriteAsync(value.AsMemory(), cancellationToken);
    }

    private static string MessageTime(AiChatMessage message) => message.CreatedAt is { } timestamp
        ? $" · {timestamp.ToLocalTime():yyyy-MM-dd HH:mm:ss}"
        : string.Empty;

    private static string Inline(string value) => value.Replace('`', '′').Replace('\r', ' ').Replace('\n', ' ').Trim();

    private static string FormatDuration(long milliseconds) => milliseconds < 1000
        ? $"{Math.Max(0, milliseconds):N0} ms"
        : TimeSpan.FromMilliseconds(milliseconds) is var duration && duration.TotalMinutes < 1
            ? $"{duration.TotalSeconds:0.0} 秒"
            : $"{(int)duration.TotalMinutes:N0} 分 {duration.Seconds:N0} 秒";

    private static string FormatBytes(int bytes) => bytes < 1024 ? $"{bytes:N0} B" : $"{bytes / 1024d:0.0} KB";

    private static int LongestBacktickRun(string value)
    {
        var longest = 0;
        var current = 0;
        foreach (var character in value)
        {
            if (character == '`') longest = Math.Max(longest, ++current);
            else current = 0;
        }
        return longest;
    }
}
