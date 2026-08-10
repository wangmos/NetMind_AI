using System.Text.Encodings.Web;
using System.Text.Json;

namespace NetMind.Core;

public sealed record TrafficGroup(
    Guid Id,
    string Name,
    string Description,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt,
    IReadOnlyList<Guid> TrafficIds);

public sealed class TrafficGroupStore
{
    private readonly string _directory;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    public TrafficGroupStore(string workspacePath)
    {
        var root = Path.GetFullPath(workspacePath);
        _directory = Path.GetFullPath(Path.Combine(root, "traffic-groups"));
        if (!_directory.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("记录组目录不在当前工作区内。");
        Directory.CreateDirectory(_directory);
    }

    public async Task SaveAsync(TrafficGroup group, CancellationToken cancellationToken = default)
    {
        var normalized = Validate(group);
        var path = GroupPath(normalized.Id);
        var temporaryPath = path + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            await File.WriteAllTextAsync(temporaryPath, JsonSerializer.Serialize(normalized, JsonOptions), cancellationToken);
            File.Move(temporaryPath, path, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporaryPath)) File.Delete(temporaryPath);
        }
    }

    public async Task<IReadOnlyList<TrafficGroup>> GetAllAsync(CancellationToken cancellationToken = default)
    {
        var groups = new List<TrafficGroup>();
        foreach (var path in Directory.EnumerateFiles(_directory, "*.json", SearchOption.TopDirectoryOnly))
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite,
                    16 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
                var group = await JsonSerializer.DeserializeAsync<TrafficGroup>(stream, JsonOptions, cancellationToken);
                if (group is not null) groups.Add(Validate(group));
            }
            // 单个记录组损坏不阻断其余记录组，但**跳过是静默的**：损坏项会直接从界面消失，
            // 用户可能误以为数据已丢失。让损坏可见需要把跳过计数带回界面，属于独立改动。
            catch (JsonException) { }
            catch (InvalidDataException) { }
        }
        return groups.OrderByDescending(group => group.UpdatedAt).ToArray();
    }

    public bool Delete(Guid id)
    {
        var path = GroupPath(id);
        if (!File.Exists(path)) return false;
        File.Delete(path);
        return true;
    }

    private string GroupPath(Guid id) => Path.Combine(_directory, id.ToString("N") + ".json");

    private static TrafficGroup Validate(TrafficGroup group)
    {
        if (group.Id == Guid.Empty) throw new InvalidDataException("记录组缺少有效标识。");
        var name = group.Name.Trim();
        if (name.Length is < 1 or > 80) throw new InvalidDataException("记录组名称必须为 1–80 个字符。");
        var description = group.Description.Trim();
        if (description.Length > 500) throw new InvalidDataException("记录组说明不得超过 500 个字符。");
        if (group.CreatedAt == default || group.UpdatedAt == default || group.UpdatedAt < group.CreatedAt)
            throw new InvalidDataException("记录组时间信息无效。");
        var ids = group.TrafficIds.Where(id => id != Guid.Empty).Distinct().Take(1001).ToArray();
        if (ids.Length > 1000) throw new InvalidDataException("单个记录组最多保存 1,000 条事务。");
        return group with { Name = name, Description = description, TrafficIds = ids };
    }
}
