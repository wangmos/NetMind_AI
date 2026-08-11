using System.Text;
using System.Text.Json;

namespace NetMind.Core;

/// <summary>脚本用途。决定工作台上「运行」按钮做什么，以及编辑器补全给哪一套词表。</summary>
public enum ScriptPurpose
{
    /// <summary>钩子脚本：定义 on_before_send 等函数，采集期间由隔离的钩子工作进程执行。</summary>
    Hook,

    /// <summary>验证脚本：从 netmind 读取 fixture，在沙箱里对流量快照跑一次并以退出码表达结论。</summary>
    Fixture
}

/// <summary>脚本库中的一个脚本。</summary>
/// <param name="FileName">工作区 scripts 目录下的文件名（含 .py 后缀），同时是脚本的唯一标识。</param>
/// <param name="FullPath">完整路径。</param>
/// <param name="Purpose">用途。</param>
/// <param name="UpdatedAt">最后写入时间。</param>
/// <param name="SizeBytes">文件字节数。</param>
public sealed record ScriptLibraryItem(string FileName, string FullPath, ScriptPurpose Purpose, DateTimeOffset UpdatedAt, long SizeBytes);

/// <summary>
/// 工作区脚本库。
///
/// 设计取舍：<b>目录即真相</b>——库的内容就是工作区 scripts 目录下的 *.py，直接枚举得到。
/// 只有「用途」这一位信息无法从文件本身可靠推断，才落在 sidecar（script-library.json）里；
/// sidecar 中指向已删除文件的条目在列举时自然被忽略，因此不会出现清单与磁盘不一致的幽灵条目，
/// 用户在资源管理器里直接增删 .py 也能被正确反映。
/// </summary>
public static class ScriptLibraryStore
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web) { WriteIndented = true };

    /// <summary>sidecar 文档：仅保存文件名到用途的映射。</summary>
    private sealed record LibraryDocument(int Version, Dictionary<string, string> Purposes);

    private const int DocumentVersion = 1;
    private const string DocumentFileName = "script-library.json";
    private const string PurposeHook = "hook";
    private const string PurposeFixture = "fixture";

    /// <summary>脚本文件名最大长度（含 .py 后缀）。</summary>
    public const int MaximumFileNameLength = 64;

    /// <summary>sidecar 文档路径。</summary>
    public static string GetDocumentPath(string workspacePath) =>
        Path.Combine(TrafficHookConfigStore.GetScriptsDirectory(workspacePath), DocumentFileName);

    /// <summary>
    /// 列出工作区脚本库。目录不存在或不可读时返回空列表——脚本库缺失不是错误，
    /// 只意味着这个工作区还没写过脚本。
    /// </summary>
    public static IReadOnlyList<ScriptLibraryItem> List(string workspacePath)
    {
        var directory = TrafficHookConfigStore.GetScriptsDirectory(workspacePath);
        if (!Directory.Exists(directory)) return [];
        var purposes = ReadPurposes(workspacePath);
        var items = new List<ScriptLibraryItem>();
        foreach (var path in EnumerateScriptFiles(directory))
        {
            var fileName = Path.GetFileName(path);
            FileInfo info;
            try { info = new FileInfo(path); }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException) { continue; }
            var purpose = purposes.TryGetValue(fileName, out var recorded)
                ? ParsePurpose(recorded)
                : InferPurpose(ReadTextOrEmpty(path));
            items.Add(new ScriptLibraryItem(fileName, path, purpose,
                new DateTimeOffset(info.LastWriteTimeUtc, TimeSpan.Zero), info.Length));
        }
        return [.. items.OrderBy(item => item.FileName, StringComparer.OrdinalIgnoreCase)];
    }

    private static IEnumerable<string> EnumerateScriptFiles(string directory)
    {
        try { return Directory.EnumerateFiles(directory, "*.py", SearchOption.TopDirectoryOnly).ToArray(); }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException) { return []; }
    }

    private static string ReadTextOrEmpty(string path)
    {
        try { return File.ReadAllText(path); }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException) { return string.Empty; }
    }

    /// <summary>
    /// 从脚本内容推断用途。只在 sidecar 里没有记录时使用（例如用户直接往目录里丢了个 .py）。
    /// 钩子函数名优先：一个既定义了钩子函数又 import 了 fixture 的脚本，钩子语义更强。
    /// </summary>
    public static ScriptPurpose InferPurpose(string scriptText)
    {
        if (string.IsNullOrEmpty(scriptText)) return ScriptPurpose.Hook;
        foreach (var name in new[]
                 {
                     HookEventNames.FunctionBeforeSend, HookEventNames.FunctionAfterSend,
                     HookEventNames.FunctionBeforeWrite, HookEventNames.FunctionAfterDeliver
                 })
        {
            if (scriptText.Contains("def " + name, StringComparison.Ordinal)) return ScriptPurpose.Hook;
        }
        return scriptText.Contains("import fixture", StringComparison.Ordinal) ||
               scriptText.Contains("fixture.transactions", StringComparison.Ordinal)
            ? ScriptPurpose.Fixture
            : ScriptPurpose.Hook;
    }

    /// <summary>
    /// 校验并规范化脚本文件名：补 .py 后缀、拒绝路径分隔符与非法字符。
    /// 文件名来自用户输入且会拼进工作区路径，这里是唯一的路径穿越防线，失败一律抛中文说明。
    /// </summary>
    public static string NormalizeFileName(string? name)
    {
        var trimmed = (name ?? string.Empty).Trim();
        if (trimmed.Length == 0) throw new ArgumentException("脚本名不能为空。", nameof(name));
        if (trimmed.EndsWith(".py", StringComparison.OrdinalIgnoreCase)) trimmed = trimmed[..^3];
        trimmed = trimmed.Trim();
        if (trimmed.Length == 0) throw new ArgumentException("脚本名不能只有扩展名。", nameof(name));
        if (trimmed is "." or "..") throw new ArgumentException("脚本名不能是 . 或 ..", nameof(name));
        if (trimmed.Contains('/', StringComparison.Ordinal) || trimmed.Contains('\\', StringComparison.Ordinal))
            throw new ArgumentException("脚本名不能包含路径分隔符，脚本只能位于工作区 scripts 目录下。", nameof(name));
        foreach (var invalid in Path.GetInvalidFileNameChars())
        {
            if (trimmed.Contains(invalid, StringComparison.Ordinal))
                throw new ArgumentException("脚本名包含文件系统不允许的字符。", nameof(name));
        }
        var fileName = trimmed + ".py";
        if (fileName.Length > MaximumFileNameLength)
            throw new ArgumentException($"脚本名过长，含 .py 后缀不能超过 {MaximumFileNameLength} 个字符。", nameof(name));
        return fileName;
    }

    /// <summary>在已有脚本名基础上生成一个不冲突的文件名（追加 -2、-3…）。</summary>
    public static string CreateUniqueFileName(string workspacePath, string baseName)
    {
        var fileName = NormalizeFileName(baseName);
        var directory = TrafficHookConfigStore.GetScriptsDirectory(workspacePath);
        if (!File.Exists(Path.Combine(directory, fileName))) return fileName;
        var stem = fileName[..^3];
        for (var index = 2; index < 1000; index++)
        {
            var candidate = NormalizeFileName(stem + "-" + index.ToString(System.Globalization.CultureInfo.InvariantCulture));
            if (!File.Exists(Path.Combine(directory, candidate))) return candidate;
        }
        throw new InvalidOperationException("同名脚本过多，请换一个脚本名。");
    }

    /// <summary>新建脚本并写入初始内容；文件已存在时拒绝覆盖。</summary>
    public static async Task<ScriptLibraryItem> CreateAsync(string workspacePath, string name, ScriptPurpose purpose,
        string initialText, CancellationToken cancellationToken = default)
    {
        var fileName = NormalizeFileName(name);
        var directory = TrafficHookConfigStore.GetScriptsDirectory(workspacePath);
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, fileName);
        if (File.Exists(path)) throw new InvalidOperationException($"脚本 {fileName} 已存在，请换一个名字。");
        await TrafficHookConfigStore.SaveScriptToPathAsync(path, initialText, cancellationToken).ConfigureAwait(false);
        await SetPurposeAsync(workspacePath, fileName, purpose, cancellationToken).ConfigureAwait(false);
        var info = new FileInfo(path);
        return new ScriptLibraryItem(fileName, path, purpose, new DateTimeOffset(info.LastWriteTimeUtc, TimeSpan.Zero), info.Length);
    }

    /// <summary>重命名脚本文件，并把 sidecar 中的用途一并迁移。返回新文件名。</summary>
    public static async Task<string> RenameAsync(string workspacePath, string fileName, string newName,
        CancellationToken cancellationToken = default)
    {
        var source = NormalizeFileName(fileName);
        var target = NormalizeFileName(newName);
        if (string.Equals(source, target, StringComparison.Ordinal)) return target;
        var directory = TrafficHookConfigStore.GetScriptsDirectory(workspacePath);
        var sourcePath = Path.Combine(directory, source);
        var targetPath = Path.Combine(directory, target);
        if (!File.Exists(sourcePath)) throw new FileNotFoundException($"脚本 {source} 不存在。", sourcePath);
        // 仅大小写不同的重命名在 Windows 上目标「已存在」，但那就是同一个文件，应放行。
        if (File.Exists(targetPath) && !string.Equals(source, target, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException($"脚本 {target} 已存在，请换一个名字。");
        File.Move(sourcePath, targetPath, overwrite: false);
        var purposes = ReadPurposes(workspacePath);
        if (purposes.Remove(source, out var recorded)) purposes[target] = recorded;
        await WritePurposesAsync(workspacePath, purposes, cancellationToken).ConfigureAwait(false);
        return target;
    }

    /// <summary>删除脚本文件并清理 sidecar 条目。</summary>
    public static async Task DeleteAsync(string workspacePath, string fileName, CancellationToken cancellationToken = default)
    {
        var name = NormalizeFileName(fileName);
        var path = Path.Combine(TrafficHookConfigStore.GetScriptsDirectory(workspacePath), name);
        if (File.Exists(path)) File.Delete(path);
        var purposes = ReadPurposes(workspacePath);
        if (purposes.Remove(name)) await WritePurposesAsync(workspacePath, purposes, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>记录脚本用途。</summary>
    public static async Task SetPurposeAsync(string workspacePath, string fileName, ScriptPurpose purpose,
        CancellationToken cancellationToken = default)
    {
        var name = NormalizeFileName(fileName);
        var purposes = ReadPurposes(workspacePath);
        var value = purpose == ScriptPurpose.Fixture ? PurposeFixture : PurposeHook;
        if (purposes.TryGetValue(name, out var existing) && string.Equals(existing, value, StringComparison.Ordinal)) return;
        purposes[name] = value;
        await WritePurposesAsync(workspacePath, purposes, cancellationToken).ConfigureAwait(false);
    }

    private static ScriptPurpose ParsePurpose(string value) =>
        string.Equals(value, PurposeFixture, StringComparison.OrdinalIgnoreCase) ? ScriptPurpose.Fixture : ScriptPurpose.Hook;

    /// <summary>读取 sidecar；缺失或损坏都按「没有记录」处理，用途会退回内容推断，不影响脚本本身。</summary>
    private static Dictionary<string, string> ReadPurposes(string workspacePath)
    {
        var path = GetDocumentPath(workspacePath);
        if (!File.Exists(path)) return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            var document = JsonSerializer.Deserialize<LibraryDocument>(File.ReadAllText(path), JsonOptions);
            return document?.Purposes is null
                ? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                : new Dictionary<string, string>(document.Purposes, StringComparer.OrdinalIgnoreCase);
        }
        catch (Exception exception) when (exception is JsonException or IOException or UnauthorizedAccessException)
        {
            return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        }
    }

    /// <summary>原子写 sidecar（tmp + File.Move），与工作区其他 JSON 写入保持同一套语义。</summary>
    private static async Task WritePurposesAsync(string workspacePath, Dictionary<string, string> purposes,
        CancellationToken cancellationToken)
    {
        var directory = TrafficHookConfigStore.GetScriptsDirectory(workspacePath);
        Directory.CreateDirectory(directory);
        var path = GetDocumentPath(workspacePath);
        var temporaryPath = path + ".tmp-" + Guid.NewGuid().ToString("N");
        var document = new LibraryDocument(DocumentVersion,
            purposes.ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal));
        try
        {
            await File.WriteAllTextAsync(temporaryPath, JsonSerializer.Serialize(document, JsonOptions),
                new UTF8Encoding(false), cancellationToken).ConfigureAwait(false);
            File.Move(temporaryPath, path, overwrite: true);
        }
        finally { if (File.Exists(temporaryPath)) File.Delete(temporaryPath); }
    }
}
