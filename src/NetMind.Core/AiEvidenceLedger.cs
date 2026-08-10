using System.Security.Cryptography;
using System.Text;

namespace NetMind.Core;

/// <summary>
/// 跨轮证据账本。它只携带工具调用的稳定引用、结果大小与摘要哈希，绝不携带工具结果原文。
/// 这让追问能够判断“上一轮查过什么”，同时强制模型在需要细节时重新调用只读工具取证。
/// </summary>
public static class AiEvidenceLedger
{
    private const int MaximumEntries = 200;
    private const int MaximumCharacters = 16 * 1024;

    public static AiToolTrace CreateTrace(string name, string argumentsJson, string result, bool truncated)
    {
        var resultBytes = Encoding.UTF8.GetBytes(result);
        return new AiToolTrace(
            name,
            argumentsJson,
            result.Length,
            resultBytes.Length,
            truncated,
            Convert.ToHexString(SHA256.HashData(resultBytes)).ToLowerInvariant(),
            BuildReference(name, argumentsJson));
    }

    public static string BuildReference(string name, string argumentsJson)
    {
        var bytes = Encoding.UTF8.GetBytes(name.Trim() + "\n" + argumentsJson.Trim());
        return name.Trim() + "@" + Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant()[..12];
    }

    public static string BuildCompact(IReadOnlyList<AiChatMessage> history)
    {
        var entries = new List<string>();
        var turn = 0;
        foreach (var message in history)
        {
            if (message.Role == "user" && message.Content?.StartsWith("[系统]", StringComparison.Ordinal) != true)
            {
                turn++;
                continue;
            }
            if (message.Role != "assistant" || message.ToolTraces is not { Count: > 0 }) continue;

            var citations = ExtractCitations(message.Content);
            foreach (var trace in message.ToolTraces)
            {
                if (entries.Count >= MaximumEntries) break;
                var reference = string.IsNullOrWhiteSpace(trace.EvidenceReference)
                    ? BuildReference(trace.Name, trace.ArgumentsJson)
                    : trace.EvidenceReference;
                var hash = string.IsNullOrWhiteSpace(trace.ResultSha256) ? "legacy-unknown" : trace.ResultSha256;
                entries.Add($"- turn={Math.Max(1, turn)} tool={trace.Name} ref={reference} bytes={trace.ResultBytes} " +
                            $"sha256={hash} truncated={(trace.Truncated ? "yes" : "no")}" +
                            (citations.Length == 0 ? string.Empty : $" citations={citations}"));
            }
            if (entries.Count >= MaximumEntries) break;
        }

        if (entries.Count == 0) return string.Empty;
        const string header = "[evidence-ledger]\n以下是历史轮次的证据校验账本，不含工具结果原文。需要核对字段或正文时必须重新调用只读工具，不得根据哈希猜测内容。\n";
        var builder = new StringBuilder(header);
        foreach (var entry in entries)
        {
            if (builder.Length + entry.Length + 1 > MaximumCharacters)
            {
                builder.Append("- more=omitted\n");
                break;
            }
            builder.AppendLine(entry);
        }
        return builder.ToString().TrimEnd();
    }

    private static string ExtractCitations(string? content)
    {
        if (string.IsNullOrWhiteSpace(content)) return string.Empty;
        var citations = new SortedSet<int>();
        for (var index = 0; index < content.Length - 3; index++)
        {
            if (content[index] != '[' || content[index + 1] != '#') continue;
            var cursor = index + 2;
            var value = 0;
            var hasDigit = false;
            while (cursor < content.Length && char.IsAsciiDigit(content[cursor]))
            {
                hasDigit = true;
                value = Math.Min(1_000_000, value * 10 + content[cursor] - '0');
                cursor++;
            }
            if (hasDigit && cursor < content.Length && content[cursor] == ']' && value > 0) citations.Add(value);
        }
        return string.Join(',', citations.Select(value => "#" + value));
    }
}
