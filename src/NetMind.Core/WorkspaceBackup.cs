using System.IO.Compression;
using System.Text.Json;

namespace NetMind.Core;

public sealed record WorkspaceBackupResult(string Path, int FileCount, long UncompressedBytes);

public static class WorkspaceBackup
{
    private const string Format = "netmind.workspace-backup";
    private const int Version = 1;
    private const int MaximumEntries = 200_000;
    private const long MaximumUncompressedBytes = 256L * 1024 * 1024 * 1024;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web) { WriteIndented = true };

    public static async Task<WorkspaceBackupResult> ExportAsync(string workspacePath, string outputPath,
        CancellationToken cancellationToken = default)
    {
        var root = System.IO.Path.GetFullPath(workspacePath).TrimEnd(System.IO.Path.DirectorySeparatorChar, System.IO.Path.AltDirectorySeparatorChar);
        var output = System.IO.Path.GetFullPath(outputPath);
        if (output.StartsWith(root + System.IO.Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("工作区备份不能保存到被备份的工作区内部。");
        if (!File.Exists(System.IO.Path.Combine(root, NetMindDefaults.WorkspaceManifestFileName)))
            throw new InvalidDataException("当前目录不是有效的 NetMind 工作区。");
        var outputDirectory = System.IO.Path.GetDirectoryName(output) ?? throw new InvalidOperationException("备份输出路径无效。");
        Directory.CreateDirectory(outputDirectory);

        var databasePath = System.IO.Path.Combine(root, NetMindDefaults.MetadataDatabaseFileName);
        if (File.Exists(databasePath))
        {
            using var metadata = new SqliteMetadataStore(databasePath);
            metadata.Checkpoint();
        }
        var files = WorkspaceDataMaintenance.EnumerateFilesSafely(root)
            .Where(path => ShouldInclude(path, databasePath))
            .Select(path => new FileInfo(path))
            .ToArray();
        var totalBytes = files.Sum(file => file.Length);
        var temporary = output + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            await using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None,
                             128 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan))
            {
                using (var archive = new ZipArchive(stream, ZipArchiveMode.Create, leaveOpen: true))
                {
                    var backupManifest = archive.CreateEntry(NetMindDefaults.WorkspaceBackupManifestFileName, CompressionLevel.Optimal);
                    await using (var manifestStream = backupManifest.Open())
                    {
                        await JsonSerializer.SerializeAsync(manifestStream,
                            new BackupManifest(Format, Version, DateTimeOffset.UtcNow, files.Length, totalBytes), JsonOptions, cancellationToken);
                    }
                    foreach (var file in files)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        var relative = System.IO.Path.GetRelativePath(root, file.FullName).Replace('\\', '/');
                        var entry = archive.CreateEntry("workspace/" + relative, CompressionLevel.Optimal);
                        entry.LastWriteTime = new DateTimeOffset(file.LastWriteTimeUtc, TimeSpan.Zero);
                        await using var source = new FileStream(file.FullName, FileMode.Open, FileAccess.Read,
                            FileShare.ReadWrite | FileShare.Delete, 128 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
                        await using var target = entry.Open();
                        await source.CopyToAsync(target, 128 * 1024, cancellationToken);
                    }
                }
                await stream.FlushAsync(cancellationToken);
            }
            File.Move(temporary, output, overwrite: true);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
        await new WorkspaceStore(root).AppendAuditAsync("workspace.backup.exported",
            new { fileCount = files.Length, uncompressedBytes = totalBytes }, cancellationToken);
        return new WorkspaceBackupResult(output, files.Length, totalBytes);
    }

    public static async Task<WorkspaceDescriptor> ImportAsync(string backupPath, string workspaceRoot,
        CancellationToken cancellationToken = default)
    {
        var input = System.IO.Path.GetFullPath(backupPath);
        if (!File.Exists(input)) throw new FileNotFoundException("工作区备份文件不存在。", input);
        var root = System.IO.Path.GetFullPath(workspaceRoot).TrimEnd(System.IO.Path.DirectorySeparatorChar, System.IO.Path.AltDirectorySeparatorChar);
        Directory.CreateDirectory(root);
        var temporary = System.IO.Path.Combine(root, ".import-" + Guid.NewGuid().ToString("N"));
        var targetId = "ws-" + DateTimeOffset.UtcNow.ToString("yyyyMMdd-HHmmss") + "-" + Guid.NewGuid().ToString("N")[..6];
        var target = System.IO.Path.Combine(root, targetId);
        Directory.CreateDirectory(temporary);
        try
        {
            using var archive = ZipFile.OpenRead(input);
            var manifestEntry = archive.GetEntry(NetMindDefaults.WorkspaceBackupManifestFileName)
                                ?? throw new InvalidDataException("备份缺少格式清单。");
            BackupManifest manifest;
            await using (var stream = manifestEntry.Open())
                manifest = await JsonSerializer.DeserializeAsync<BackupManifest>(stream, JsonOptions, cancellationToken)
                           ?? throw new InvalidDataException("备份格式清单无效。");
            if (manifest.Format != Format || manifest.Version != Version)
                throw new InvalidDataException("不是受支持的 NetMind 工作区备份格式。");

            var workspaceEntries = archive.Entries.Where(entry => entry.FullName.StartsWith("workspace/", StringComparison.Ordinal)).ToArray();
            if (workspaceEntries.Length == 0 || workspaceEntries.Length > MaximumEntries)
                throw new InvalidDataException("备份文件条目数量无效或超过安全上限。");
            long totalBytes = 0;
            var extracted = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var entry in workspaceEntries)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (entry.FullName.EndsWith("/", StringComparison.Ordinal)) continue;
                totalBytes = checked(totalBytes + entry.Length);
                if (totalBytes > MaximumUncompressedBytes)
                    throw new InvalidDataException("备份解压后容量超过 256 GB 安全上限。");
                var relative = entry.FullName["workspace/".Length..].Replace('/', System.IO.Path.DirectorySeparatorChar)
                    .Replace('\\', System.IO.Path.DirectorySeparatorChar);
                if (relative.Length == 0 || System.IO.Path.IsPathRooted(relative)) throw new InvalidDataException("备份包含非法绝对路径。");
                var destination = System.IO.Path.GetFullPath(System.IO.Path.Combine(temporary, relative));
                if (!destination.StartsWith(temporary + System.IO.Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException("备份包含越界路径，已拒绝导入。");
                if (!extracted.Add(destination)) throw new InvalidDataException("备份包含重复文件路径。");
                Directory.CreateDirectory(System.IO.Path.GetDirectoryName(destination)!);
                await using var source = entry.Open();
                await using var output = new FileStream(destination, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                    128 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
                await source.CopyToAsync(output, 128 * 1024, cancellationToken);
            }

            var workspaceManifestPath = System.IO.Path.Combine(temporary, NetMindDefaults.WorkspaceManifestFileName);
            if (!File.Exists(workspaceManifestPath)) throw new InvalidDataException("备份中缺少 workspace.json。 ");
            var workspaceManifest = JsonSerializer.Deserialize<WorkspaceManifest>(await File.ReadAllTextAsync(workspaceManifestPath, cancellationToken), JsonOptions)
                                    ?? throw new InvalidDataException("备份中的 workspace.json 无效。");
            var importedName = workspaceManifest.Name.EndsWith("（导入）", StringComparison.Ordinal)
                ? workspaceManifest.Name
                : workspaceManifest.Name.Length <= 56 ? workspaceManifest.Name + "（导入）" : workspaceManifest.Name[..56] + "（导入）";
            workspaceManifest = workspaceManifest with { Name = importedName, LastOpenedAt = DateTimeOffset.UtcNow };
            await File.WriteAllTextAsync(workspaceManifestPath, JsonSerializer.Serialize(workspaceManifest, JsonOptions), cancellationToken);
            Directory.Move(temporary, target);
            await new WorkspaceStore(target).AppendAuditAsync("workspace.backup.imported",
                new { sourceFormat = Format, manifest.Version, importedBytes = totalBytes }, cancellationToken);
            return new WorkspaceDescriptor(targetId, target, workspaceManifest);
        }
        catch
        {
            if (Directory.Exists(target)) Directory.Delete(target, recursive: true);
            throw;
        }
        finally
        {
            if (Directory.Exists(temporary)) Directory.Delete(temporary, recursive: true);
        }
    }

    private static bool ShouldInclude(string path, string databasePath)
    {
        var fileName = System.IO.Path.GetFileName(path);
        if (fileName.Contains(".tmp-", StringComparison.OrdinalIgnoreCase)) return false;
        if (path.Equals(databasePath + "-wal", StringComparison.OrdinalIgnoreCase) ||
            path.Equals(databasePath + "-shm", StringComparison.OrdinalIgnoreCase)) return false;
        return true;
    }

    private sealed record BackupManifest(string Format, int Version, DateTimeOffset CreatedAt, int FileCount, long UncompressedBytes);
}
