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

    /// <summary>
    /// 按 SHA-256 内容寻址写入正文 Blob，返回哈希。
    /// 写入必须原子：先写同目录唯一临时文件再重命名。直接写目标路径的话，
    /// 中途崩溃会留下一个「文件名是正确哈希、内容却被截断」的 Blob，
    /// 而后续的存在性检查永远命中，这份损坏证据再也不会被修复。
    /// </summary>
    public async Task<string> StoreBlobAsync(ReadOnlyMemory<byte> content, CancellationToken cancellationToken = default)
    {
        var hash = Convert.ToHexString(SHA256.HashData(content.Span)).ToLowerInvariant();
        var directory = Path.Combine(RootPath, NetMindDefaults.BlobsDirectoryName, hash[..2]);
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, hash);
        if (File.Exists(path)) return hash;

        // 临时文件名带随机后缀：并发采集连接可能同时落盘不同正文，不能共用固定临时名。
        var temporaryPath = Path.Combine(directory, $"{hash}.{Guid.NewGuid():N}.tmp");
        try
        {
            await using (var stream = new FileStream(temporaryPath, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                             64 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan))
            {
                await stream.WriteAsync(content, cancellationToken);
            }

            try
            {
                File.Move(temporaryPath, path, overwrite: false);
            }
            catch (IOException) when (File.Exists(path))
            {
                // 另一个并发写者已经落盘同一哈希。内容寻址保证两者逐字节相同，丢弃本次临时文件即可。
            }
        }
        finally
        {
            if (File.Exists(temporaryPath)) File.Delete(temporaryPath);
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
    /// 例外是 <see cref="StoreBlobAsync"/> 留下的 <c>&lt;哈希&gt;.&lt;随机&gt;.tmp</c> 残留：
    /// 进程在重命名前崩溃才会产生，永远不会被引用，一并回收。
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
            if (!IsAbandonedBlobTemporary(name) &&
                (name.Length != NetMindDefaults.Sha256HexLength || name.Any(character => !Uri.IsHexDigit(character)) ||
                 referencedHashes.Contains(name))) continue;
            long length;
            try { length = new FileInfo(path).Length; }
            catch (FileNotFoundException) { continue; }
            try { File.Delete(path); }
            catch (IOException) { continue; }   // 另一进程正在写这个临时文件，本轮跳过
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

    /// <summary>
    /// 判断是否为 <see cref="StoreBlobAsync"/> 的遗留临时文件：
    /// 严格匹配 <c>&lt;64 位哈希&gt;.&lt;32 位 Guid&gt;.tmp</c>，避免误删用户放入 blobs 目录的其他文件。
    /// </summary>
    private static bool IsAbandonedBlobTemporary(string name)
    {
        if (!name.EndsWith(".tmp", StringComparison.Ordinal)) return false;
        var parts = name.Split('.');
        return parts.Length == 3
               && parts[0].Length == NetMindDefaults.Sha256HexLength
               && parts[0].All(Uri.IsHexDigit)
               && parts[1].Length == 32
               && parts[1].All(Uri.IsHexDigit);
    }

    public static string Redact(string value) => SecretPattern().Replace(value, "$1=" + NetMindDefaults.RedactedPlaceholder);

    public static string RedactUrl(string value) => SensitiveQueryPattern().Replace(value, "$1" + NetMindDefaults.RedactedPlaceholder);

    [GeneratedRegex("(?i)(authorization|token|api[_-]?key|secret)\\s*[:=]\\s*(?:\\[[^\\]\\r\\n]*\\]|[^,;\\s\\\"]+)")]
    private static partial Regex SecretPattern();

    [GeneratedRegex("(?i)([?&][^?&=]*(?:token|key|secret|auth|session|cookie|password)[^?&=]*=)[^&#]*")]
    private static partial Regex SensitiveQueryPattern();
}
