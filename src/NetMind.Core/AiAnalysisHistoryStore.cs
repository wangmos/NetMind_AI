using System.Text.Encodings.Web;
using System.Text.Json;

namespace NetMind.Core;

public sealed record AiAnalysisHistoryMetadata(
    Guid Id,
    DateTimeOffset CreatedAt,
    string EndpointHost,
    string Model,
    string ApiStyle,
    string ReasoningEffort,
    int MaxOutputTokens,
    string ScopeName,
    IReadOnlyList<Guid> TransactionIds,
    string ResponseId,
    int InputTokens,
    int OutputTokens,
    string FinishReason,
    long DurationMilliseconds);

public sealed record AiAnalysisHistoryEntry(
    AiAnalysisHistoryMetadata Metadata,
    string EvidenceJson,
    string ResultMarkdown);

public sealed class AiAnalysisHistoryStore
{
    private const int MaximumEvidenceBytes = NetMindDefaults.AiMaximumFullContextBytes;
    private const int MaximumResultBytes = 2 * 1024 * 1024;
    private readonly string _root;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    public AiAnalysisHistoryStore(string workspacePath)
    {
        var workspaceRoot = Path.GetFullPath(workspacePath);
        _root = Path.GetFullPath(Path.Combine(workspaceRoot, NetMindDefaults.AiHistoryDirectoryName));
        if (!_root.StartsWith(workspaceRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("AI 历史目录不在当前工作区内。");
        Directory.CreateDirectory(_root);
    }

    public async Task SaveAsync(AiAnalysisHistoryEntry entry, CancellationToken cancellationToken = default)
    {
        Validate(entry.Metadata);
        ValidateTextSize(entry.EvidenceJson, MaximumEvidenceBytes, "完整证据快照");
        ValidateTextSize(entry.ResultMarkdown, MaximumResultBytes, "模型分析结果");
        if (string.IsNullOrWhiteSpace(entry.EvidenceJson)) throw new InvalidDataException("完整证据快照不能为空。");
        if (string.IsNullOrWhiteSpace(entry.ResultMarkdown)) throw new InvalidDataException("模型分析结果不能为空。");

        var destination = EntryDirectory(entry.Metadata.Id);
        if (Directory.Exists(destination)) throw new IOException("相同标识的 AI 分析历史已经存在。");
        var temporary = Path.Combine(_root, ".tmp-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(temporary);
        try
        {
            await File.WriteAllTextAsync(Path.Combine(temporary, "metadata.json"), JsonSerializer.Serialize(entry.Metadata, JsonOptions), cancellationToken);
            await File.WriteAllTextAsync(Path.Combine(temporary, "evidence.json"), entry.EvidenceJson, cancellationToken);
            await File.WriteAllTextAsync(Path.Combine(temporary, "result.md"), entry.ResultMarkdown, cancellationToken);
            Directory.Move(temporary, destination);
        }
        finally
        {
            if (Directory.Exists(temporary)) Directory.Delete(temporary, recursive: true);
        }
    }

    public async Task<IReadOnlyList<AiAnalysisHistoryMetadata>> GetRecentAsync(int limit = 100,
        CancellationToken cancellationToken = default)
    {
        limit = Math.Clamp(limit, 1, 500);
        var metadata = new List<AiAnalysisHistoryMetadata>();
        foreach (var directory in Directory.EnumerateDirectories(_root, "*", SearchOption.TopDirectoryOnly))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var name = Path.GetFileName(directory);
            if (!Guid.TryParseExact(name, "N", out _)) continue;
            var path = Path.Combine(directory, "metadata.json");
            if (!File.Exists(path) || new FileInfo(path).Length > 256 * 1024) continue;
            try
            {
                await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite,
                    16 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
                var item = await JsonSerializer.DeserializeAsync<AiAnalysisHistoryMetadata>(stream, JsonOptions, cancellationToken);
                if (item is null) continue;
                Validate(item);
                metadata.Add(item);
            }
            catch (JsonException) { }
            catch (InvalidDataException) { }
        }
        return metadata.OrderByDescending(item => item.CreatedAt).Take(limit).ToArray();
    }

    public async Task<AiAnalysisHistoryEntry?> LoadAsync(Guid id, CancellationToken cancellationToken = default)
    {
        var directory = EntryDirectory(id);
        if (!Directory.Exists(directory)) return null;
        var metadataPath = Path.Combine(directory, "metadata.json");
        var evidencePath = Path.Combine(directory, "evidence.json");
        var resultPath = Path.Combine(directory, "result.md");
        if (!File.Exists(metadataPath) || !File.Exists(evidencePath) || !File.Exists(resultPath))
            throw new InvalidDataException("AI 分析历史文件不完整。");
        EnsureBoundedFile(evidencePath, MaximumEvidenceBytes, "完整证据快照");
        EnsureBoundedFile(resultPath, MaximumResultBytes, "模型分析结果");
        await using var stream = new FileStream(metadataPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite,
            16 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        var metadata = await JsonSerializer.DeserializeAsync<AiAnalysisHistoryMetadata>(stream, JsonOptions, cancellationToken)
                       ?? throw new InvalidDataException("AI 分析历史元数据无效。");
        Validate(metadata);
        if (metadata.Id != id) throw new InvalidDataException("AI 分析历史标识不匹配。");
        var evidence = await File.ReadAllTextAsync(evidencePath, cancellationToken);
        var result = await File.ReadAllTextAsync(resultPath, cancellationToken);
        return new AiAnalysisHistoryEntry(metadata, evidence, result);
    }

    public bool Delete(Guid id)
    {
        var directory = EntryDirectory(id);
        if (!Directory.Exists(directory)) return false;
        Directory.Delete(directory, recursive: true);
        return true;
    }

    private string EntryDirectory(Guid id)
    {
        if (id == Guid.Empty) throw new ArgumentException("AI 分析历史标识不能为空。", nameof(id));
        var directory = Path.GetFullPath(Path.Combine(_root, id.ToString("N")));
        if (!directory.StartsWith(_root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("AI 分析历史路径越过了当前工作区。");
        return directory;
    }

    private static void Validate(AiAnalysisHistoryMetadata metadata)
    {
        if (metadata.Id == Guid.Empty || metadata.CreatedAt == default) throw new InvalidDataException("AI 分析历史标识或时间无效。");
        if (metadata.Model.Trim().Length is < 1 or > NetMindDefaults.AiModelNameMaximumCharacters) throw new InvalidDataException("AI 分析历史中的模型名称无效。");
        if (metadata.EndpointHost.Length > 255 || metadata.ScopeName.Length > 120) throw new InvalidDataException("AI 分析历史文本字段过长。");
        if (metadata.TransactionIds.Count is < 1 or > NetMindDefaults.AiMaximumEvidenceTransactions || metadata.TransactionIds.Any(id => id == Guid.Empty))
            throw new InvalidDataException($"AI 分析历史必须引用 1–{NetMindDefaults.AiMaximumEvidenceTransactions} 条有效事务。");
        if (metadata.MaxOutputTokens is < NetMindDefaults.AiMinimumOutputTokens or > NetMindDefaults.AiMaximumOutputTokens || metadata.InputTokens < 0 || metadata.OutputTokens < 0 || metadata.DurationMilliseconds < 0)
            throw new InvalidDataException("AI 分析历史中的计量信息无效。");
    }

    private static void ValidateTextSize(string content, int maximumBytes, string name)
    {
        if (System.Text.Encoding.UTF8.GetByteCount(content) > maximumBytes)
            throw new InvalidDataException($"{name}超过 {maximumBytes / 1024:N0} KB 安全限制。");
    }

    private static void EnsureBoundedFile(string path, int maximumBytes, string name)
    {
        if (new FileInfo(path).Length > maximumBytes) throw new InvalidDataException($"{name}文件超过安全限制。");
    }
}

public static class AiAnalysisExportFormatter
{
    public static string BuildMarkdown(AiAnalysisHistoryEntry entry)
    {
        var metadata = entry.Metadata;
        var model = OneLine(metadata.Model);
        var scope = OneLine(metadata.ScopeName);
        return $"# NetMind AI 分析结果\n\n" +
               $"- 时间：{metadata.CreatedAt.ToLocalTime():yyyy-MM-dd HH:mm:ss}\n" +
               $"- 模型：`{model.Replace("`", "\\`", StringComparison.Ordinal)}`\n" +
               $"- 范围：{scope}\n" +
               $"- 事务数：{metadata.TransactionIds.Count}\n" +
               $"- 输入 / 输出令牌：{metadata.InputTokens:N0} / {metadata.OutputTokens:N0}\n\n" +
               "---\n\n" + entry.ResultMarkdown;
    }

    private static string OneLine(string value) => value.Replace('\r', ' ').Replace('\n', ' ').Trim();
}
