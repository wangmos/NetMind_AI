using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace NetMind.Core;

/// <summary>会话元数据（JSONL 首行）：标识、创建时间、模板、模型、证据池事务与范围名。</summary>
public sealed record AiConversationHeader(
    Guid Id,
    DateTimeOffset CreatedAt,
    string TemplateId,
    string Model,
    string ScopeName,
    IReadOnlyList<Guid> TransactionIds);

/// <summary>会话列表行：标题 = 模板 + 时间 + 轮数。</summary>
public sealed record AiConversationSummary(
    Guid Id,
    DateTimeOffset CreatedAt,
    string TemplateId,
    string Model,
    string ScopeName,
    int TurnCount);

/// <summary>完整会话：元数据 + 全部消息（含 tool 调用与结果），用于跨重启恢复“每一轮对话”。</summary>
public sealed record AiConversation(AiConversationHeader Header, IReadOnlyList<AiChatMessage> Messages);

/// <summary>
/// 工作区 ai-conversations/ 目录下的会话存储：每会话一个 JSONL 文件，
/// 首行元数据，其后逐条追加消息；跨重启可列表/读取/删除。
/// </summary>
public sealed class AiConversationStore
{
    /// <summary>默认单文件读取上限：默认响应上限 32 MB + 16 MB 历史消息余量；调用方可按配置的响应上限放宽。</summary>
    private const int DefaultMaximumFileBytes = NetMindDefaults.AiMaximumResponseBytes + 16 * 1024 * 1024;
    private const string SystemNoticePrefix = "[系统]";
    private readonly string _root;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    private readonly int _maximumFileBytes;

    public AiConversationStore(string workspacePath, int maximumFileBytes = DefaultMaximumFileBytes)
    {
        _maximumFileBytes = maximumFileBytes;
        var workspaceRoot = Path.GetFullPath(workspacePath);
        _root = Path.GetFullPath(Path.Combine(workspaceRoot, NetMindDefaults.AiConversationsDirectoryName));
        if (!_root.StartsWith(workspaceRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("AI 会话目录不在当前工作区内。");
        Directory.CreateDirectory(_root);
    }

    public async Task CreateAsync(AiConversationHeader header, CancellationToken cancellationToken = default)
    {
        if (header.Id == Guid.Empty || header.CreatedAt == default) throw new InvalidDataException("会话标识或时间无效。");
        if (header.Model.Trim().Length is < 1 or > NetMindDefaults.AiModelNameMaximumCharacters) throw new InvalidDataException("会话中的模型名称无效。");
        if (header.ScopeName.Length > 120) throw new InvalidDataException("会话范围名过长。");
        if (header.TransactionIds.Count > NetMindDefaults.AiMaximumEvidenceTransactions || header.TransactionIds.Any(id => id == Guid.Empty))
            throw new InvalidDataException("会话引用的事务列表无效。");
        var path = ConversationFile(header.Id);
        if (File.Exists(path)) throw new IOException("相同标识的 AI 会话已经存在。");
        var line = JsonSerializer.Serialize(new { kind = "header", header }, JsonOptions);
        await File.WriteAllTextAsync(path, line + "\n", new UTF8Encoding(false), cancellationToken);
    }

    /// <summary>追加一条消息到会话文件（UTF-8 无 BOM 单行）；文件不存在时视为会话已被删除。</summary>
    public async Task AppendMessageAsync(Guid id, AiChatMessage message, CancellationToken cancellationToken = default)
    {
        var path = ConversationFile(id);
        if (!File.Exists(path)) return;
        var storedMessage = message.CreatedAt.HasValue ? message : message with { CreatedAt = DateTimeOffset.UtcNow };
        var line = JsonSerializer.Serialize(new { kind = "message", message = storedMessage }, JsonOptions);
        await File.AppendAllTextAsync(path, line + "\n", new UTF8Encoding(false), cancellationToken);
    }

    public async Task<IReadOnlyList<AiConversationSummary>> GetRecentAsync(int limit = 50, CancellationToken cancellationToken = default)
    {
        limit = Math.Clamp(limit, 1, 200);
        return await Task.Run<IReadOnlyList<AiConversationSummary>>(() =>
        {
            var summaries = new List<AiConversationSummary>();
            foreach (var path in Directory.EnumerateFiles(_root, "*.jsonl", SearchOption.TopDirectoryOnly))
            {
                cancellationToken.ThrowIfCancellationRequested();
                var name = Path.GetFileNameWithoutExtension(path);
                if (!Guid.TryParseExact(name, "N", out _) || new FileInfo(path).Length > _maximumFileBytes) continue;
                try
                {
                    var conversation = ReadConversation(path);
                    if (conversation is null) continue;
                    summaries.Add(new AiConversationSummary(
                        conversation.Header.Id, conversation.Header.CreatedAt, conversation.Header.TemplateId,
                        conversation.Header.Model, conversation.Header.ScopeName, CountTurns(conversation.Messages)));
                }
                catch (IOException) { }
                catch (InvalidDataException) { }
            }
            return summaries.OrderByDescending(item => item.CreatedAt).Take(limit).ToArray();
        }, cancellationToken);
    }

    public async Task<AiConversation?> LoadAsync(Guid id, CancellationToken cancellationToken = default)
    {
        var path = ConversationFile(id);
        return await Task.Run(() =>
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!File.Exists(path)) return null;
            if (new FileInfo(path).Length > _maximumFileBytes) throw new InvalidDataException("AI 会话文件超过安全限制。");
            var conversation = ReadConversation(path);
            cancellationToken.ThrowIfCancellationRequested();
            if (conversation is null || conversation.Header.Id != id) throw new InvalidDataException("AI 会话文件无效。");
            return conversation;
        }, cancellationToken);
    }

    public bool Delete(Guid id)
    {
        var path = ConversationFile(id);
        if (!File.Exists(path)) return false;
        File.Delete(path);
        return true;
    }

    /// <summary>轮数 = 非系统提示的用户消息条数（首轮摘要提问与每次追问各计一轮）。</summary>
    public static int CountTurns(IReadOnlyList<AiChatMessage> messages) =>
        messages.Count(message => message.Role == "user" && !(message.Content?.StartsWith(SystemNoticePrefix, StringComparison.Ordinal) ?? false));

    private static AiConversation? ReadConversation(string path)
    {
        AiConversationHeader? header = null;
        var messages = new List<AiChatMessage>();
        foreach (var rawLine in File.ReadLines(path, Encoding.UTF8))
        {
            var line = rawLine.Trim();
            if (line.Length == 0) continue;
            JsonElement envelope;
            try
            {
                using var document = JsonDocument.Parse(line);
                envelope = document.RootElement.Clone();
            }
            catch (JsonException)
            {
                continue; // 单行损坏跳过，不阻断整个会话恢复。
            }
            var kind = envelope.TryGetProperty("kind", out var kindElement) && kindElement.ValueKind == JsonValueKind.String
                ? kindElement.GetString() : null;
            if (kind == "header" && envelope.TryGetProperty("header", out var headerElement))
            {
                header = JsonSerializer.Deserialize<AiConversationHeader>(headerElement.GetRawText(), JsonOptions);
            }
            else if (kind == "message" && envelope.TryGetProperty("message", out var messageElement))
            {
                var message = JsonSerializer.Deserialize<AiChatMessage>(messageElement.GetRawText(), JsonOptions);
                if (message is not null && !string.IsNullOrEmpty(message.Role)) messages.Add(message);
            }
        }
        return header is null ? null : new AiConversation(header, messages);
    }

    private string ConversationFile(Guid id)
    {
        if (id == Guid.Empty) throw new ArgumentException("AI 会话标识不能为空。", nameof(id));
        var path = Path.GetFullPath(Path.Combine(_root, id.ToString("N") + ".jsonl"));
        if (!path.StartsWith(_root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("AI 会话路径越过了当前工作区。");
        return path;
    }
}
