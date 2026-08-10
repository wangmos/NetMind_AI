using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace NetMind.Core;

public sealed record WorkspaceDescriptor(string Id, string Path, WorkspaceManifest Manifest);

public sealed partial class WorkspaceCatalog
{
    private readonly string _root;
    private readonly string _selectionPath;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    public WorkspaceCatalog(string rootPath)
    {
        _root = Path.GetFullPath(rootPath);
        Directory.CreateDirectory(_root);
        _selectionPath = Path.Combine(_root, "current-workspace.json");
    }

    public async Task<IReadOnlyList<WorkspaceDescriptor>> GetAllAsync(CancellationToken cancellationToken = default)
    {
        var workspaces = new List<WorkspaceDescriptor>();
        foreach (var directory in Directory.EnumerateDirectories(_root, "*", SearchOption.TopDirectoryOnly))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var id = Path.GetFileName(directory);
            if (!ValidId().IsMatch(id)) continue;
            var manifestPath = Path.Combine(directory, NetMindDefaults.WorkspaceManifestFileName);
            if (!File.Exists(manifestPath)) continue;
            try
            {
                await using var stream = new FileStream(manifestPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite,
                    16 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
                var manifest = await JsonSerializer.DeserializeAsync<WorkspaceManifest>(stream, JsonOptions, cancellationToken);
                if (manifest is not null && !string.IsNullOrWhiteSpace(manifest.Name))
                    workspaces.Add(new WorkspaceDescriptor(id, Path.GetFullPath(directory), manifest));
            }
            // 单个工作区清单损坏不阻断其余工作区，但**跳过是静默的**：损坏项会直接从界面消失，
            // 用户可能误以为数据已丢失。让损坏可见需要把跳过计数带回界面，属于独立改动。
            catch (JsonException) { }
        }
        return workspaces.OrderByDescending(item => item.Manifest.LastOpenedAt).ThenBy(item => item.Manifest.Name).ToArray();
    }

    public async Task<WorkspaceDescriptor> CreateAsync(string name, CancellationToken cancellationToken = default)
    {
        name = ValidateName(name);
        var id = "ws-" + DateTimeOffset.UtcNow.ToString("yyyyMMdd-HHmmss") + "-" + Guid.NewGuid().ToString("N")[..6];
        var path = ResolvePath(id);
        var store = new WorkspaceStore(path);
        await store.InitializeAsync(name, cancellationToken);
        var manifest = await ReadManifestAsync(path, cancellationToken);
        return new WorkspaceDescriptor(id, path, manifest);
    }

    public async Task<WorkspaceDescriptor> RenameAsync(WorkspaceDescriptor workspace, string name,
        CancellationToken cancellationToken = default)
    {
        name = ValidateName(name);
        var path = ResolvePath(workspace.Id);
        var manifest = await ReadManifestAsync(path, cancellationToken);
        var updated = manifest with { Name = name, LastOpenedAt = DateTimeOffset.UtcNow };
        await WriteManifestAtomicAsync(path, updated, cancellationToken);
        return new WorkspaceDescriptor(workspace.Id, path, updated);
    }

    public async Task<WorkspaceDescriptor?> GetCurrentAsync(CancellationToken cancellationToken = default)
    {
        if (!File.Exists(_selectionPath)) return null;
        try
        {
            await using var stream = new FileStream(_selectionPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite,
                4096, FileOptions.Asynchronous | FileOptions.SequentialScan);
            var selection = await JsonSerializer.DeserializeAsync<WorkspaceSelection>(stream, JsonOptions, cancellationToken);
            if (selection is null || !ValidId().IsMatch(selection.Id)) return null;
            var path = ResolvePath(selection.Id);
            if (!File.Exists(Path.Combine(path, NetMindDefaults.WorkspaceManifestFileName))) return null;
            return new WorkspaceDescriptor(selection.Id, path, await ReadManifestAsync(path, cancellationToken));
        }
        catch (JsonException) { return null; }
    }

    public async Task SetCurrentAsync(WorkspaceDescriptor workspace, CancellationToken cancellationToken = default)
    {
        var path = ResolvePath(workspace.Id);
        var manifest = await ReadManifestAsync(path, cancellationToken);
        var updated = manifest with { LastOpenedAt = DateTimeOffset.UtcNow };
        await WriteManifestAtomicAsync(path, updated, cancellationToken);
        var temporaryPath = _selectionPath + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            await File.WriteAllTextAsync(temporaryPath, JsonSerializer.Serialize(new WorkspaceSelection(workspace.Id), JsonOptions), cancellationToken);
            File.Move(temporaryPath, _selectionPath, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporaryPath)) File.Delete(temporaryPath);
        }
    }

    public async Task<WorkspaceDescriptor> ImportLegacyAsync(string id, string name, CancellationToken cancellationToken = default)
    {
        if (!ValidId().IsMatch(id)) throw new InvalidOperationException("旧工作区标识无效。");
        var path = ResolvePath(id);
        var store = new WorkspaceStore(path);
        if (!File.Exists(Path.Combine(path, NetMindDefaults.WorkspaceManifestFileName))) await store.InitializeAsync(ValidateName(name), cancellationToken);
        return new WorkspaceDescriptor(id, path, await ReadManifestAsync(path, cancellationToken));
    }

    private string ResolvePath(string id)
    {
        if (!ValidId().IsMatch(id)) throw new InvalidOperationException("工作区标识无效。");
        var path = Path.GetFullPath(Path.Combine(_root, id));
        if (!path.StartsWith(_root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("工作区路径越过了工作区根目录。");
        return path;
    }

    private static async Task<WorkspaceManifest> ReadManifestAsync(string path, CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(Path.Combine(path, NetMindDefaults.WorkspaceManifestFileName), FileMode.Open, FileAccess.Read,
            FileShare.ReadWrite, 16 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        return await JsonSerializer.DeserializeAsync<WorkspaceManifest>(stream, JsonOptions, cancellationToken)
               ?? throw new InvalidDataException("工作区清单内容无效。");
    }

    private static async Task WriteManifestAtomicAsync(string path, WorkspaceManifest manifest, CancellationToken cancellationToken)
    {
        var manifestPath = Path.Combine(path, NetMindDefaults.WorkspaceManifestFileName);
        var temporaryPath = manifestPath + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            await File.WriteAllTextAsync(temporaryPath, JsonSerializer.Serialize(manifest, JsonOptions), cancellationToken);
            File.Move(temporaryPath, manifestPath, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporaryPath)) File.Delete(temporaryPath);
        }
    }

    private static string ValidateName(string name)
    {
        name = name.Trim();
        if (name.Length is < 1 or > 60) throw new InvalidOperationException("工作区名称必须为 1–60 个字符。");
        if (name.Any(character => char.IsControl(character))) throw new InvalidOperationException("工作区名称不能包含控制字符。");
        return name;
    }

    [GeneratedRegex("^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$", RegexOptions.CultureInvariant)]
    private static partial Regex ValidId();

    private sealed record WorkspaceSelection(string Id);
}
