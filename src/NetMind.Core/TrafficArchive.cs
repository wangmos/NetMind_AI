namespace NetMind.Core;

public sealed class TrafficArchive : IDisposable
{
    private readonly WorkspaceStore _workspace;
    private readonly SqliteMetadataStore _metadata;

    public TrafficArchive(string workspacePath)
    {
        _workspace = new WorkspaceStore(workspacePath);
        _metadata = new SqliteMetadataStore(Path.Combine(_workspace.RootPath, NetMindDefaults.MetadataDatabaseFileName));
    }

    public string WorkspacePath => _workspace.RootPath;

    public Task InitializeAsync(string name, CancellationToken cancellationToken = default) =>
        _workspace.InitializeAsync(name, cancellationToken);

    public Task StartSessionAsync(CaptureSessionRecord session, CancellationToken cancellationToken = default)
    {
        _metadata.SaveSession(session);
        return _workspace.AppendAuditAsync("capture.started", new { session.Id, session.Mode, session.Target }, cancellationToken);
    }

    public Task CompleteSessionAsync(CaptureSessionRecord session, CancellationToken cancellationToken = default)
    {
        _metadata.SaveSession(session);
        return _workspace.AppendAuditAsync("capture.completed", new { session.Id, session.State }, cancellationToken);
    }

    public async Task<StoredTrafficRecord> RecordAsync(Guid sessionId, TrafficRecord traffic, ReadOnlyMemory<byte> requestBody,
        ReadOnlyMemory<byte> responseBody, CancellationToken cancellationToken = default)
    {
        var requestHash = await _workspace.StoreBlobAsync(requestBody, cancellationToken);
        var responseHash = await _workspace.StoreBlobAsync(responseBody, cancellationToken);
        var stored = new StoredTrafficRecord(traffic, sessionId, requestHash, responseHash);
        _metadata.SaveTraffic(stored);
        await _workspace.AppendAuditAsync("traffic.recorded", new
        {
            traffic.Id,
            sessionId,
            traffic.Method,
            traffic.Endpoint,
            traffic.StatusCode,
            requestHash,
            responseHash
        }, cancellationToken);
        return stored;
    }

    public Task UpdateTrafficAsync(StoredTrafficRecord stored, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _metadata.SaveTraffic(stored);
        return _workspace.AppendAuditAsync("traffic.updated", new
        {
            stored.Traffic.Id,
            stored.Traffic.SizeBytes,
            stored.Traffic.RequestSummary,
            stored.Traffic.ResponseSummary
        }, cancellationToken);
    }

    public IReadOnlyList<StoredTrafficRecord> GetRecentTraffic(int limit = NetMindDefaults.DefaultTrafficWindowCount) => _metadata.GetRecentTraffic(limit);
    public long GetLatestTrafficCursor() => _metadata.GetLatestTrafficCursor();
    public IReadOnlyList<StoredTrafficChange> GetTrafficChangesAfter(long cursor, int limit = 2000) =>
        _metadata.GetTrafficChangesAfter(cursor, limit);

    /// <summary>页内 Hook 事件批量入库（采集浏览器注入脚本上报），并按批追加一条计数汇总审计。</summary>
    public async Task RecordPageHooksAsync(IReadOnlyList<PageHookEvent> events, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (events.Count == 0) return;
        _metadata.SavePageHooks(events);
        await _workspace.AppendAuditAsync(NetMindDefaults.AuditEventPageHookReceived, new { count = events.Count }, cancellationToken);
    }

    public IReadOnlyList<PageHookEvent> GetPageHooks(string? type = null, int limit = 200) => _metadata.GetPageHooks(type, limit);
    public IReadOnlyList<PageHookEvent> GetPageHooksBySessions(IEnumerable<Guid> sessionIds, string? type = null, int limit = 200) =>
        _metadata.GetPageHooksBySessions(sessionIds, type, limit);
    public IReadOnlyList<StoredTrafficRecord> GetTrafficByIds(IEnumerable<Guid> ids) => _metadata.GetTrafficByIds(ids);
    public long GetTrafficCount() => _metadata.GetTrafficCount();
    public IReadOnlyList<CaptureSessionSummary> GetRecentSessions(int limit = NetMindDefaults.DefaultSessionWindowCount) => _metadata.GetRecentSessions(limit);
    public Task<StoredBlobContent> ReadBlobAsync(string hash, int maximumBytes = NetMindDefaults.BlobPreviewDefaultBytes,
        CancellationToken cancellationToken = default) => _workspace.ReadBlobAsync(hash, maximumBytes, cancellationToken);
    public Stream OpenBlobRead(string hash) => _workspace.OpenBlobRead(hash);

    public async Task<long> ClearAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var count = _metadata.ClearCaptureData();
        var deletedPageHooks = _metadata.ClearPageHooks();
        await _workspace.ClearBlobsAsync(cancellationToken);
        await _workspace.AppendAuditAsync("workspace.capture-data-cleared", new { deletedTransactions = count, deletedPageHooks }, cancellationToken);
        return count;
    }

    /// <summary>
    /// 定向删除指定事务：先删事务行，再仅删除已无任何事务引用的正文 Blob
    /// （内容寻址正文可能被多条事务共享，不得误删），并追加审计日志。
    /// </summary>
    public async Task<long> DeleteTrafficAsync(IReadOnlyCollection<Guid> ids, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var targets = _metadata.GetTrafficByIds(ids);
        if (targets.Count == 0) return 0;
        var candidateHashes = targets
            .SelectMany(record => new[] { record.RequestBlobHash, record.ResponseBlobHash })
            .Where(hash => !string.IsNullOrWhiteSpace(hash))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var deleted = _metadata.DeleteTraffic(targets.Select(record => record.Traffic.Id).ToArray());
        var referenced = _metadata.GetReferencedBlobHashes();
        var deletedBlobs = 0;
        foreach (var hash in candidateHashes)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!referenced.Contains(hash) && await _workspace.TryDeleteBlobAsync(hash, cancellationToken)) deletedBlobs++;
        }
        await _workspace.AppendAuditAsync("workspace.traffic-deleted", new { deletedTransactions = deleted, deletedBlobs }, cancellationToken);
        return deleted;
    }
    public void Dispose() => _metadata.Dispose();
}
