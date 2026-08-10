using System.Text.Json;

namespace NetMind.Core;

public sealed record WorkspaceDataPolicy(int RetentionDays = 0, long MaximumWorkspaceBytes = 0)
{
    public WorkspaceDataPolicy Validate()
    {
        if (RetentionDays is < 0 or > 3650) throw new InvalidOperationException("数据保留天数必须为 0–3650；0 表示永久保留。");
        if (MaximumWorkspaceBytes < 0 || MaximumWorkspaceBytes > 1024L * 1024 * 1024 * 1024)
            throw new InvalidOperationException("工作区容量上限必须为 0–1 TB；0 表示不限制。");
        if (MaximumWorkspaceBytes is > 0 and < 256L * 1024 * 1024)
            throw new InvalidOperationException("启用容量上限时不得低于 256 MB。");
        return this;
    }
}

public sealed class WorkspaceDataPolicyStore(string workspacePath)
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web) { WriteIndented = true };
    public string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetFullPath(workspacePath), NetMindDefaults.WorkspaceDataPolicyFileName);

    public async Task<WorkspaceDataPolicy> LoadAsync(CancellationToken cancellationToken = default)
    {
        if (!File.Exists(Path)) return new WorkspaceDataPolicy();
        try
        {
            await using var stream = new FileStream(Path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite,
                16 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
            return (await JsonSerializer.DeserializeAsync<WorkspaceDataPolicy>(stream, JsonOptions, cancellationToken) ??
                    new WorkspaceDataPolicy()).Validate();
        }
        catch (JsonException exception) { throw new InvalidDataException("工作区数据策略文件格式无效。", exception); }
    }

    public async Task SaveAsync(WorkspaceDataPolicy policy, CancellationToken cancellationToken = default)
    {
        policy = policy.Validate();
        var temporary = Path + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            await File.WriteAllTextAsync(temporary, JsonSerializer.Serialize(policy, JsonOptions), cancellationToken);
            File.Move(temporary, Path, overwrite: true);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
}

public sealed record WorkspaceStatistics(
    long TotalBytes,
    long BlobBytes,
    long MetadataBytes,
    long AiBytes,
    long LogBytes,
    long OtherBytes,
    int FileCount,
    int BlobFileCount,
    long TrafficCount,
    long PageHookCount);

public sealed record WorkspaceMaintenanceResult(
    WorkspaceStatistics Before,
    WorkspaceStatistics After,
    long DeletedTransactions,
    long DeletedPageHooks,
    long DeletedSessions,
    int DeletedOrphanBlobs,
    long ReclaimedBytes,
    bool CapacitySatisfied);

/// <summary>当前工作区的数据统计、保留期限、容量上限、孤儿 Blob 清理与 SQLite 压缩。</summary>
public static class WorkspaceDataMaintenance
{
    private const int DeleteBatchSize = 500;

    public static WorkspaceStatistics GetStatistics(string workspacePath)
    {
        var root = System.IO.Path.GetFullPath(workspacePath);
        using var metadata = new SqliteMetadataStore(System.IO.Path.Combine(root, NetMindDefaults.MetadataDatabaseFileName));
        return CollectStatistics(root, metadata.GetTrafficCount(), metadata.GetPageHookCount());
    }

    public static async Task<WorkspaceMaintenanceResult> RunAsync(string workspacePath, WorkspaceDataPolicy policy,
        CancellationToken cancellationToken = default)
    {
        policy = policy.Validate();
        var root = System.IO.Path.GetFullPath(workspacePath);
        var workspace = new WorkspaceStore(root);
        using var metadata = new SqliteMetadataStore(System.IO.Path.Combine(root, NetMindDefaults.MetadataDatabaseFileName));
        var before = CollectStatistics(root, metadata.GetTrafficCount(), metadata.GetPageHookCount());
        long deletedTransactions = 0;
        long deletedHooks = 0;
        long deletedSessions = 0;
        var deletedOrphans = 0;

        if (policy.RetentionDays > 0)
        {
            var cutoff = DateTimeOffset.UtcNow.AddDays(-policy.RetentionDays);
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var ids = metadata.GetTrafficIdsOlderThan(cutoff, DeleteBatchSize);
                if (ids.Count == 0) break;
                deletedTransactions += metadata.DeleteTraffic(ids);
            }
            deletedHooks += metadata.DeletePageHooksOlderThan(cutoff);
            deletedSessions += metadata.DeleteUnusedCompletedSessionsOlderThan(cutoff);
        }

        var orphanResult = await workspace.CleanupOrphanBlobsAsync(metadata.GetReferencedBlobHashes(), cancellationToken);
        deletedOrphans += orphanResult.Files;
        metadata.CheckpointAndVacuum();
        var after = CollectStatistics(root, metadata.GetTrafficCount(), metadata.GetPageHookCount());

        if (policy.MaximumWorkspaceBytes > 0)
        {
            while (after.TotalBytes > policy.MaximumWorkspaceBytes)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var ids = metadata.GetOldestTrafficIds(DeleteBatchSize);
                if (ids.Count == 0) break;
                deletedTransactions += metadata.DeleteTraffic(ids);
                orphanResult = await workspace.CleanupOrphanBlobsAsync(metadata.GetReferencedBlobHashes(), cancellationToken);
                deletedOrphans += orphanResult.Files;
                metadata.CheckpointAndVacuum();
                after = CollectStatistics(root, metadata.GetTrafficCount(), metadata.GetPageHookCount());
            }
        }

        after = CollectStatistics(root, metadata.GetTrafficCount(), metadata.GetPageHookCount());
        var capacitySatisfied = policy.MaximumWorkspaceBytes == 0 || after.TotalBytes <= policy.MaximumWorkspaceBytes;
        var reclaimed = Math.Max(0, before.TotalBytes - after.TotalBytes);
        await workspace.AppendAuditAsync("workspace.maintenance.completed", new
        {
            policy.RetentionDays,
            policy.MaximumWorkspaceBytes,
            deletedTransactions,
            deletedHooks,
            deletedSessions,
            deletedOrphans,
            reclaimedBytes = reclaimed,
            capacitySatisfied
        }, cancellationToken);
        return new WorkspaceMaintenanceResult(before, after, deletedTransactions, deletedHooks, deletedSessions,
            deletedOrphans, reclaimed, capacitySatisfied);
    }

    internal static IEnumerable<string> EnumerateFilesSafely(string rootPath)
    {
        var root = System.IO.Path.GetFullPath(rootPath);
        var pending = new Stack<string>();
        pending.Push(root);
        while (pending.Count > 0)
        {
            var directory = pending.Pop();
            IEnumerable<string> files;
            IEnumerable<string> directories;
            try
            {
                files = Directory.EnumerateFiles(directory).ToArray();
                directories = Directory.EnumerateDirectories(directory).ToArray();
            }
            catch (DirectoryNotFoundException) { continue; }
            foreach (var file in files) yield return file;
            foreach (var child in directories)
            {
                FileAttributes attributes;
                try { attributes = File.GetAttributes(child); }
                catch (FileNotFoundException) { continue; }
                if ((attributes & FileAttributes.ReparsePoint) == 0) pending.Push(child);
            }
        }
    }

    private static WorkspaceStatistics CollectStatistics(string root, long trafficCount, long pageHookCount)
    {
        long total = 0, blobs = 0, metadata = 0, ai = 0, logs = 0;
        var fileCount = 0;
        var blobFiles = 0;
        var blobRoot = System.IO.Path.Combine(root, NetMindDefaults.BlobsDirectoryName) + System.IO.Path.DirectorySeparatorChar;
        var aiHistoryRoot = System.IO.Path.Combine(root, NetMindDefaults.AiHistoryDirectoryName) + System.IO.Path.DirectorySeparatorChar;
        var aiConversationRoot = System.IO.Path.Combine(root, NetMindDefaults.AiConversationsDirectoryName) + System.IO.Path.DirectorySeparatorChar;
        var logsRoot = System.IO.Path.Combine(root, NetMindDefaults.LogsDirectoryName) + System.IO.Path.DirectorySeparatorChar;
        foreach (var path in EnumerateFilesSafely(root))
        {
            long length;
            try { length = new FileInfo(path).Length; }
            catch (FileNotFoundException) { continue; }
            var full = System.IO.Path.GetFullPath(path);
            total += length;
            fileCount++;
            if (full.StartsWith(blobRoot, StringComparison.OrdinalIgnoreCase)) { blobs += length; blobFiles++; }
            else if (System.IO.Path.GetFileName(full).StartsWith(NetMindDefaults.MetadataDatabaseFileName, StringComparison.OrdinalIgnoreCase)) metadata += length;
            else if (full.StartsWith(aiHistoryRoot, StringComparison.OrdinalIgnoreCase) ||
                     full.StartsWith(aiConversationRoot, StringComparison.OrdinalIgnoreCase)) ai += length;
            else if (full.StartsWith(logsRoot, StringComparison.OrdinalIgnoreCase)) logs += length;
        }
        return new WorkspaceStatistics(total, blobs, metadata, ai, logs,
            Math.Max(0, total - blobs - metadata - ai - logs), fileCount, blobFiles, trafficCount, pageHookCount);
    }
}
