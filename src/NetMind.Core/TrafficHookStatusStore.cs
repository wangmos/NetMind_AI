using System.Text;
using System.Text.Json;

namespace NetMind.Core;

/// <summary>采集后台发布给工作台的脚本 Hook 运行状态；只包含计数与错误摘要。</summary>
public sealed record TrafficHookRuntimeStatus(
    DateTimeOffset UpdatedAtUtc,
    int HostProcessId,
    ScriptHookMetricsSnapshot Metrics);

public static class TrafficHookStatusStore
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web) { WriteIndented = true };

    public static string GetPath(string workspacePath) =>
        Path.Combine(TrafficHookConfigStore.GetScriptsDirectory(workspacePath), NetMindDefaults.HookStatusFileName);

    public static async Task SaveAsync(string workspacePath, ScriptHookMetricsSnapshot metrics,
        CancellationToken cancellationToken = default)
    {
        var path = GetPath(workspacePath);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var temporaryPath = path + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            var status = new TrafficHookRuntimeStatus(DateTimeOffset.UtcNow, Environment.ProcessId, metrics);
            await File.WriteAllTextAsync(temporaryPath, JsonSerializer.Serialize(status, JsonOptions),
                new UTF8Encoding(false), cancellationToken);
            File.Move(temporaryPath, path, overwrite: true);
        }
        finally
        {
            try { if (File.Exists(temporaryPath)) File.Delete(temporaryPath); } catch { }
        }
    }

    public static async Task<TrafficHookRuntimeStatus?> LoadAsync(string workspacePath,
        CancellationToken cancellationToken = default)
    {
        var path = GetPath(workspacePath);
        if (!File.Exists(path)) return null;
        try
        {
            await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 16 * 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            return await JsonSerializer.DeserializeAsync<TrafficHookRuntimeStatus>(stream, JsonOptions, cancellationToken);
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("脚本 Hook 运行状态文件损坏。", exception);
        }
    }
}
