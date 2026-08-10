using System.Text.Json;

namespace NetMind.Core;

public sealed class AiGatewaySettingsStore(string path)
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web) { WriteIndented = true };
    public string Path { get; } = System.IO.Path.GetFullPath(path);

    public async Task<AiGatewaySettings> LoadAsync(CancellationToken cancellationToken = default)
    {
        if (!File.Exists(Path)) return new AiGatewaySettings();
        try
        {
            await using var stream = new FileStream(Path, FileMode.Open, FileAccess.Read, FileShare.Read, 16 * 1024, FileOptions.Asynchronous);
            return (await JsonSerializer.DeserializeAsync<AiGatewaySettings>(stream, JsonOptions, cancellationToken) ?? new AiGatewaySettings()).Validate();
        }
        catch (JsonException exception) { throw new InvalidDataException("AI 网关设置文件格式无效。", exception); }
    }

    public async Task SaveAsync(AiGatewaySettings settings, CancellationToken cancellationToken = default)
    {
        settings = settings.Validate();
        var directory = System.IO.Path.GetDirectoryName(Path) ?? throw new InvalidOperationException("AI 设置路径无效。");
        Directory.CreateDirectory(directory);
        var temporaryPath = Path + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            await File.WriteAllTextAsync(temporaryPath, JsonSerializer.Serialize(settings, JsonOptions), cancellationToken);
            File.Move(temporaryPath, Path, overwrite: true);
        }
        finally { if (File.Exists(temporaryPath)) File.Delete(temporaryPath); }
    }
}
