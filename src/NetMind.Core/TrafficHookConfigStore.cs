using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace NetMind.Core;

/// <summary>
/// 钩子逐项开关（对应工作区 hook-config.json 的 hooks 节点）。
/// 序列化/反序列化采用 camelCase（<see cref="JsonSerializerDefaults.Web"/>），
/// 与采集后台读取方的契约完全一致；缺失字段按默认值（关闭）处理。
/// </summary>
public sealed record TrafficHookSwitches(
    bool BeforeSend = false,
    bool AfterSend = false,
    bool BeforeWrite = false,
    bool AfterDeliver = false)
{
    /// <summary>已勾选的钩子点数量（0–4）；仅工作台展示用，不参与配置序列化。</summary>
    [JsonIgnore]
    public int EnabledCount => (BeforeSend ? 1 : 0) + (AfterSend ? 1 : 0) + (BeforeWrite ? 1 : 0) + (AfterDeliver ? 1 : 0);
}

/// <summary>
/// 工作区钩子配置（scripts/hook-config.json 的 camelCase 契约）。
/// enabled 默认关闭；scriptPath 相对工作区 scripts 目录解析（采集后台契约），也接受绝对路径。
/// </summary>
public sealed record TrafficHookConfiguration(
    bool Enabled = false,
    string? ScriptPath = null,
    TrafficHookSwitches? Hooks = null);

/// <summary>
/// 工作区钩子配置与钩子脚本的读写辅助：路径定位、容错加载与原子写（tmp + File.Move）。
/// 供工作台读写；采集后台按相同契约只读，两端字段名必须保持一致。
/// </summary>
public static class TrafficHookConfigStore
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web) { WriteIndented = true };

    /// <summary>工作区内钩子脚本所在目录（工作区根下的 scripts 目录）。</summary>
    public static string GetScriptsDirectory(string workspacePath) =>
        Path.Combine(workspacePath, NetMindDefaults.ScriptsDirectoryName);

    /// <summary>钩子配置文件完整路径（工作区 scripts/hook-config.json）。</summary>
    public static string GetConfigPath(string workspacePath) =>
        Path.Combine(GetScriptsDirectory(workspacePath), NetMindDefaults.HookConfigFileName);

    /// <summary>工作台默认钩子脚本完整路径（工作区 scripts/hook-script.py）。</summary>
    public static string GetDefaultScriptPath(string workspacePath) =>
        Path.Combine(GetScriptsDirectory(workspacePath), NetMindDefaults.HookScriptFileName);

    /// <summary>
    /// 按采集后台相同的解析规则把配置中的 scriptPath 还原为完整路径：
    /// 绝对路径原样返回，相对路径基于工作区 scripts 目录拼接。
    /// </summary>
    public static string ResolveScriptPath(string workspacePath, string scriptPath) =>
        Path.IsPathRooted(scriptPath) ? scriptPath : Path.Combine(GetScriptsDirectory(workspacePath), scriptPath);

    /// <summary>
    /// 加载钩子配置：文件缺失返回 null（工作台按默认模板处理）；
    /// 文件损坏抛出带中文说明的 <see cref="InvalidDataException"/>。
    /// </summary>
    public static async Task<TrafficHookConfiguration?> LoadAsync(string workspacePath, CancellationToken cancellationToken = default)
    {
        var configPath = GetConfigPath(workspacePath);
        if (!File.Exists(configPath)) return null;
        try
        {
            await using var stream = new FileStream(configPath, FileMode.Open, FileAccess.Read, FileShare.Read, 16 * 1024, FileOptions.Asynchronous);
            return await JsonSerializer.DeserializeAsync<TrafficHookConfiguration>(stream, JsonOptions, cancellationToken) ?? new TrafficHookConfiguration();
        }
        catch (JsonException exception) { throw new InvalidDataException("钩子配置文件损坏，已按未配置处理。", exception); }
    }

    /// <summary>原子写钩子配置到工作区 scripts/hook-config.json（tmp + File.Move）。</summary>
    public static async Task SaveConfigAsync(string workspacePath, TrafficHookConfiguration configuration, CancellationToken cancellationToken = default)
    {
        Directory.CreateDirectory(GetScriptsDirectory(workspacePath));
        var configPath = GetConfigPath(workspacePath);
        var temporaryPath = configPath + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            await File.WriteAllTextAsync(temporaryPath, JsonSerializer.Serialize(configuration, JsonOptions), new UTF8Encoding(false), cancellationToken);
            File.Move(temporaryPath, configPath, overwrite: true);
        }
        finally { if (File.Exists(temporaryPath)) File.Delete(temporaryPath); }
    }

    /// <summary>原子写钩子脚本到工作区 scripts/hook-script.py（tmp + File.Move，UTF-8 无 BOM）。</summary>
    public static Task SaveScriptAsync(string workspacePath, string scriptText, CancellationToken cancellationToken = default)
        => SaveScriptToPathAsync(GetDefaultScriptPath(workspacePath), scriptText, cancellationToken);

    /// <summary>原子写钩子脚本到指定完整路径（tmp + File.Move，UTF-8 无 BOM）；非默认脚本路径场景写回原路径用。</summary>
    public static async Task SaveScriptToPathAsync(string scriptFilePath, string scriptText, CancellationToken cancellationToken = default)
    {
        var directory = Path.GetDirectoryName(Path.GetFullPath(scriptFilePath));
        if (!string.IsNullOrEmpty(directory)) Directory.CreateDirectory(directory);
        var temporaryPath = scriptFilePath + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            await File.WriteAllTextAsync(temporaryPath, scriptText, new UTF8Encoding(false), cancellationToken);
            File.Move(temporaryPath, scriptFilePath, overwrite: true);
        }
        finally { if (File.Exists(temporaryPath)) File.Delete(temporaryPath); }
    }
}
