using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace NetMind.Core;

public sealed record StoredBlobContent(byte[] Content, long OriginalLength, bool Truncated);

public sealed partial class WorkspaceStore
{
    private readonly JsonSerializerOptions _jsonOptions = new(JsonSerializerDefaults.Web) { WriteIndented = true };

    public WorkspaceStore(string rootPath)
    {
        RootPath = Path.GetFullPath(rootPath);
        Directory.CreateDirectory(RootPath);
        Directory.CreateDirectory(Path.Combine(RootPath, NetMindDefaults.BlobsDirectoryName));
        Directory.CreateDirectory(Path.Combine(RootPath, NetMindDefaults.LogsDirectoryName));
    }

    public string RootPath { get; }

    public async Task InitializeAsync(string name, CancellationToken cancellationToken = default)
    {
        var path = Path.Combine(RootPath, NetMindDefaults.WorkspaceManifestFileName);
        var manifest = new WorkspaceManifest(name, 1, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow);
        await File.WriteAllTextAsync(path, JsonSerializer.Serialize(manifest, _jsonOptions), cancellationToken);
        await AppendAuditAsync("workspace.initialized", new { name }, cancellationToken);
    }

    public async Task<string> StoreBlobAsync(ReadOnlyMemory<byte> content, CancellationToken cancellationToken = default)
    {
        var hash = Convert.ToHexString(SHA256.HashData(content.Span)).ToLowerInvariant();
        var directory = Path.Combine(RootPath, NetMindDefaults.BlobsDirectoryName, hash[..2]);
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, hash);
        if (!File.Exists(path))
        {
            await File.WriteAllBytesAsync(path, content.ToArray(), cancellationToken);
        }
        return hash;
    }

    public async Task<StoredBlobContent> ReadBlobAsync(string hash, int maximumBytes = NetMindDefaults.BlobPreviewDefaultBytes,
        CancellationToken cancellationToken = default)
    {
        maximumBytes = Math.Clamp(maximumBytes, 1024, NetMindDefaults.BlobPreviewMaximumBytes);
        var path = ResolveBlobPath(hash, requireExists: true);

        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite,
            64 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        var originalLength = stream.Length;
        var length = (int)Math.Min(originalLength, maximumBytes);
        var content = new byte[length];
        await stream.ReadExactlyAsync(content, cancellationToken);
        return new StoredBlobContent(content, originalLength, originalLength > length);
    }

    /// <summary>
    /// 打开完整正文的只读流。与预览 API 不同，该方法不截断数据，供记录组归档、HAR 导出等
    /// 本地所有者操作流式复制原始字节；调用方负责释放返回的流。
    /// </summary>
    public Stream OpenBlobRead(string hash)
    {
        var path = ResolveBlobPath(hash, requireExists: true);
        return new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite,
            64 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
    }

    public async Task AppendAuditAsync(string eventName, object payload, CancellationToken cancellationToken = default)
    {
        var entry = JsonSerializer.Serialize(new
        {
            timestamp = DateTimeOffset.UtcNow,
            eventName,
            payload = Redact(JsonSerializer.Serialize(payload))
        });
        await File.AppendAllTextAsync(Path.Combine(RootPath, NetMindDefaults.LogsDirectoryName, NetMindDefaults.AuditLogFileName), entry + Environment.NewLine, cancellationToken);
    }

    /// <summary>删除单个正文 Blob；哈希非法或文件不存在时返回 false。用于记录定向删除后的孤儿正文清理。</summary>
    public Task<bool> TryDeleteBlobAsync(string hash, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        string path;
        try { path = ResolveBlobPath(hash, requireExists: false); }
        catch (ArgumentException) { return Task.FromResult(false); }
        if (!File.Exists(path)) return Task.FromResult(false);
        File.Delete(path);
        return Task.FromResult(true);
    }

    private string ResolveBlobPath(string hash, bool requireExists)
    {
        ArgumentNullException.ThrowIfNull(hash);
        if (hash.Length != NetMindDefaults.Sha256HexLength || hash.Any(character => !Uri.IsHexDigit(character)))
            throw new ArgumentException("正文哈希必须是 64 位十六进制 SHA-256。", nameof(hash));
        var normalizedHash = hash.ToLowerInvariant();
        var blobRoot = Path.GetFullPath(Path.Combine(RootPath, NetMindDefaults.BlobsDirectoryName));
        var path = Path.GetFullPath(Path.Combine(blobRoot, normalizedHash[..2], normalizedHash));
        if (!path.StartsWith(blobRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("正文路径不在当前工作区 Blob 目录内。");
        if (requireExists && !File.Exists(path)) throw new FileNotFoundException("内容寻址存储中不存在该正文。", path);
        return path;
    }

    public Task ClearBlobsAsync(CancellationToken cancellationToken = default)
    {
        var blobRoot = Path.GetFullPath(Path.Combine(RootPath, NetMindDefaults.BlobsDirectoryName));
        if (!blobRoot.StartsWith(RootPath + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Blob 目录不在当前工作区内，已拒绝清理。");
        if (!Directory.Exists(blobRoot)) return Task.CompletedTask;
        foreach (var file in Directory.EnumerateFiles(blobRoot, "*", SearchOption.AllDirectories))
        {
            cancellationToken.ThrowIfCancellationRequested();
            File.Delete(file);
        }
        foreach (var directory in Directory.EnumerateDirectories(blobRoot, "*", SearchOption.AllDirectories)
                     .OrderByDescending(path => path.Length))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!Directory.EnumerateFileSystemEntries(directory).Any()) Directory.Delete(directory);
        }
        return Task.CompletedTask;
    }

    /// <summary>
    /// 删除未被 SQLite 事务引用的合法内容寻址 Blob；非 64 位十六进制文件不擅自删除，避免误伤用户放入的文件。
    /// </summary>
    public Task<(int Files, long Bytes)> CleanupOrphanBlobsAsync(IReadOnlySet<string> referencedHashes,
        CancellationToken cancellationToken = default)
    {
        var blobRoot = Path.GetFullPath(Path.Combine(RootPath, NetMindDefaults.BlobsDirectoryName));
        if (!blobRoot.StartsWith(RootPath + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Blob 目录不在当前工作区内，已拒绝清理。");
        if (!Directory.Exists(blobRoot)) return Task.FromResult((0, 0L));
        var files = 0;
        long bytes = 0;
        foreach (var path in Directory.EnumerateFiles(blobRoot, "*", SearchOption.AllDirectories))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var name = Path.GetFileName(path);
            if (name.Length != NetMindDefaults.Sha256HexLength || name.Any(character => !Uri.IsHexDigit(character)) ||
                referencedHashes.Contains(name)) continue;
            long length;
            try { length = new FileInfo(path).Length; }
            catch (FileNotFoundException) { continue; }
            File.Delete(path);
            files++;
            bytes += length;
        }
        foreach (var directory in Directory.EnumerateDirectories(blobRoot, "*", SearchOption.AllDirectories)
                     .OrderByDescending(path => path.Length))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!Directory.EnumerateFileSystemEntries(directory).Any()) Directory.Delete(directory);
        }
        return Task.FromResult((files, bytes));
    }

    public static string Redact(string value) => SecretPattern().Replace(value, "$1=" + NetMindDefaults.RedactedPlaceholder);

    public static string RedactUrl(string value) => SensitiveQueryPattern().Replace(value, "$1" + NetMindDefaults.RedactedPlaceholder);

    [GeneratedRegex("(?i)(authorization|token|api[_-]?key|secret)\\s*[:=]\\s*(?:\\[[^\\]\\r\\n]*\\]|[^,;\\s\\\"]+)")]
    private static partial Regex SecretPattern();

    [GeneratedRegex("(?i)([?&][^?&=]*(?:token|key|secret|auth|session|cookie|password)[^?&=]*=)[^&#]*")]
    private static partial Regex SensitiveQueryPattern();
}
