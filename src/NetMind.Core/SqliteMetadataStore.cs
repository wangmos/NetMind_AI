using System.Runtime.InteropServices;
using System.Text;

namespace NetMind.Core;

public sealed record CaptureSessionRecord(
    Guid Id,
    DateTimeOffset StartedAt,
    DateTimeOffset? EndedAt,
    string Mode,
    string Target,
    string State);

public sealed record CaptureSessionSummary(
    CaptureSessionRecord Session,
    long TransactionCount);

public sealed record StoredTrafficRecord(
    TrafficRecord Traffic,
    Guid SessionId,
    string RequestBlobHash,
    string ResponseBlobHash,
    string CaptureMode = "未知");

/// <summary>SQLite 写入游标及其对应事务；游标只用于工作台增量刷新，不作为业务标识持久化。</summary>
public sealed record StoredTrafficChange(long Cursor, StoredTrafficRecord Stored);

/// <summary>
/// 使用 Windows 自带 winsqlite3.dll 保存有界元数据。请求和响应正文只保存 SHA-256 引用。
/// </summary>
public sealed class SqliteMetadataStore : IDisposable
{
    private const int SqliteOk = 0;
    private const int SqliteRow = 100;
    private const int SqliteDone = 101;
    private const int OpenReadWrite = 0x00000002;
    private const int OpenCreate = 0x00000004;
    private const int OpenFullMutex = 0x00010000;
    // 架构版本：1 = traffic_transactions 五个扩展列；2 = page_hooks 目标 URL 与调用栈；
    // 3 = 为会话内 Hook 检索与时间序列查询补充组合索引。
    private const int SchemaVersion = 3;
    private readonly object _gate = new();
    private IntPtr _database;

    public SqliteMetadataStore(string databasePath)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("当前 SQLite 实现需要 Windows winsqlite3.dll。");

        var fullPath = Path.GetFullPath(databasePath);
        Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);
        var result = Native.sqlite3_open_v2(Utf8(fullPath), out _database, OpenReadWrite | OpenCreate | OpenFullMutex, IntPtr.Zero);
        if (result != SqliteOk) throw CreateException("无法打开工作区数据库", result);
        Execute($"PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout={NetMindDefaults.SqliteBusyTimeoutMilliseconds};");
        InitializeSchema();
        EnsureTrafficMetadataColumns();
    }

    public void SaveSession(CaptureSessionRecord session)
    {
        Execute($"""
            INSERT INTO capture_sessions(id, started_at, ended_at, mode, target, state)
            VALUES('{Esc(session.Id.ToString())}', '{Esc(session.StartedAt.ToString("O"))}', {Sql(session.EndedAt?.ToString("O"))}, '{Esc(session.Mode)}', '{Esc(session.Target)}', '{Esc(session.State)}')
            ON CONFLICT(id) DO UPDATE SET
                ended_at=excluded.ended_at,
                mode=excluded.mode,
                target=excluded.target,
                state=excluded.state;
            """);
    }

    public void SaveTraffic(StoredTrafficRecord stored)
    {
        var item = stored.Traffic;
        Execute($"""
            INSERT OR REPLACE INTO traffic_transactions(
                id, session_id, captured_at, method, endpoint, status_code, latency_ms,
                size_bytes, process_name, protocol, request_blob_hash, response_blob_hash,
                request_summary, response_summary, request_url, query_parameters,
                request_headers, cookies, response_headers)
            VALUES(
                '{Esc(item.Id.ToString())}', '{Esc(stored.SessionId.ToString())}', '{Esc(item.Timestamp.ToString("O"))}',
                '{Esc(item.Method)}', '{Esc(item.Endpoint)}', {item.StatusCode}, {item.LatencyMs},
                {item.SizeBytes}, '{Esc(item.Process)}', '{Esc(item.Protocol)}',
                '{Esc(stored.RequestBlobHash)}', '{Esc(stored.ResponseBlobHash)}',
                '{Esc(item.RequestSummary)}', '{Esc(item.ResponseSummary)}', '{Esc(item.Url)}',
                '{Esc(item.QueryParameters)}', '{Esc(item.RequestHeaders)}', '{Esc(item.Cookies)}',
                '{Esc(item.ResponseHeaders)}');
            """);
    }

    public IReadOnlyList<StoredTrafficRecord> GetRecentTraffic(int limit = NetMindDefaults.DefaultTrafficWindowCount)
    {
        limit = Math.Clamp(limit, 1, 2000);
        const string columns = "t.id,t.session_id,t.captured_at,t.method,t.endpoint,t.status_code,t.latency_ms,t.size_bytes,t.process_name,t.protocol,t.request_blob_hash,t.response_blob_hash,t.request_summary,t.response_summary,COALESCE(s.mode,'未知'),t.request_url,t.query_parameters,t.request_headers,t.cookies,t.response_headers";
        lock (_gate)
        {
            EnsureOpen();
            var result = Native.sqlite3_prepare_v2(_database, Utf8($"SELECT {columns} FROM traffic_transactions t LEFT JOIN capture_sessions s ON s.id=t.session_id ORDER BY t.captured_at DESC LIMIT {limit};"), -1, out var statement, IntPtr.Zero);
            if (result != SqliteOk) throw CreateException("无法读取流量元数据", result);
            try
            {
                var rows = new List<StoredTrafficRecord>();
                while ((result = Native.sqlite3_step(statement)) == SqliteRow)
                {
                    var traffic = new TrafficRecord(
                        Guid.Parse(Text(statement, 0)),
                        DateTimeOffset.Parse(Text(statement, 2)),
                        Text(statement, 3),
                        Text(statement, 4),
                        Native.sqlite3_column_int(statement, 5),
                        Native.sqlite3_column_int(statement, 6),
                        Native.sqlite3_column_int64(statement, 7),
                        Text(statement, 8),
                        Text(statement, 9),
                        Text(statement, 12),
                        Text(statement, 13),
                        Text(statement, 15),
                        Text(statement, 16),
                        Text(statement, 17),
                        Text(statement, 18),
                        Text(statement, 19));
                    rows.Add(new StoredTrafficRecord(traffic, Guid.Parse(Text(statement, 1)), Text(statement, 10), Text(statement, 11), Text(statement, 14)));
                }
                if (result != SqliteDone) throw CreateException("读取流量元数据时发生错误", result);
                return rows;
            }
            finally
            {
                Native.sqlite3_finalize(statement);
            }
        }
    }

    /// <summary>返回当前事务表最新写入游标。INSERT OR REPLACE 的完成态更新也会获得新游标。</summary>
    public long GetLatestTrafficCursor()
    {
        lock (_gate)
        {
            EnsureOpen();
            var result = Native.sqlite3_prepare_v2(_database, Utf8("SELECT COALESCE(MAX(rowid), 0) FROM traffic_transactions;"), -1, out var statement, IntPtr.Zero);
            if (result != SqliteOk) throw CreateException("无法读取流量刷新游标", result);
            try
            {
                return Native.sqlite3_step(statement) == SqliteRow ? Native.sqlite3_column_int64(statement, 0) : 0;
            }
            finally { Native.sqlite3_finalize(statement); }
        }
    }

    /// <summary>读取给定 SQLite 写入游标之后的新增或更新事务，按实际写入顺序返回。</summary>
    public IReadOnlyList<StoredTrafficChange> GetTrafficChangesAfter(long cursor, int limit = 2000)
    {
        cursor = Math.Max(0, cursor);
        limit = Math.Clamp(limit, 1, 2000);
        const string columns = "t.id,t.session_id,t.captured_at,t.method,t.endpoint,t.status_code,t.latency_ms,t.size_bytes,t.process_name,t.protocol,t.request_blob_hash,t.response_blob_hash,t.request_summary,t.response_summary,COALESCE(s.mode,'未知'),t.request_url,t.query_parameters,t.request_headers,t.cookies,t.response_headers";
        lock (_gate)
        {
            EnsureOpen();
            var sql = $"SELECT t.rowid,{columns} FROM traffic_transactions t LEFT JOIN capture_sessions s ON s.id=t.session_id WHERE t.rowid>{cursor} ORDER BY t.rowid ASC LIMIT {limit};";
            var result = Native.sqlite3_prepare_v2(_database, Utf8(sql), -1, out var statement, IntPtr.Zero);
            if (result != SqliteOk) throw CreateException("无法增量读取流量元数据", result);
            try
            {
                var rows = new List<StoredTrafficChange>();
                while ((result = Native.sqlite3_step(statement)) == SqliteRow)
                {
                    var traffic = new TrafficRecord(
                        Guid.Parse(Text(statement, 1)), DateTimeOffset.Parse(Text(statement, 3)), Text(statement, 4),
                        Text(statement, 5), Native.sqlite3_column_int(statement, 6), Native.sqlite3_column_int(statement, 7),
                        Native.sqlite3_column_int64(statement, 8), Text(statement, 9), Text(statement, 10), Text(statement, 13),
                        Text(statement, 14), Text(statement, 16), Text(statement, 17), Text(statement, 18), Text(statement, 19), Text(statement, 20));
                    var stored = new StoredTrafficRecord(traffic, Guid.Parse(Text(statement, 2)), Text(statement, 11), Text(statement, 12), Text(statement, 15));
                    rows.Add(new StoredTrafficChange(Native.sqlite3_column_int64(statement, 0), stored));
                }
                if (result != SqliteDone) throw CreateException("增量读取流量元数据时发生错误", result);
                return rows;
            }
            finally { Native.sqlite3_finalize(statement); }
        }
    }

    public IReadOnlyList<StoredTrafficRecord> GetTrafficByIds(IEnumerable<Guid> ids)
    {
        var snapshot = ids.Where(id => id != Guid.Empty).Distinct().Take(1001).ToArray();
        if (snapshot.Length > 1000) throw new InvalidOperationException("单次最多读取 1,000 条记录组事务。");
        if (snapshot.Length == 0) return [];
        const string columns = "t.id,t.session_id,t.captured_at,t.method,t.endpoint,t.status_code,t.latency_ms,t.size_bytes,t.process_name,t.protocol,t.request_blob_hash,t.response_blob_hash,t.request_summary,t.response_summary,COALESCE(s.mode,'未知'),t.request_url,t.query_parameters,t.request_headers,t.cookies,t.response_headers";
        var idList = string.Join(',', snapshot.Select(id => $"'{Esc(id.ToString())}'"));
        lock (_gate)
        {
            EnsureOpen();
            var result = Native.sqlite3_prepare_v2(_database, Utf8($"SELECT {columns} FROM traffic_transactions t LEFT JOIN capture_sessions s ON s.id=t.session_id WHERE t.id IN ({idList}) ORDER BY t.captured_at ASC;"), -1, out var statement, IntPtr.Zero);
            if (result != SqliteOk) throw CreateException("无法读取记录组事务", result);
            try
            {
                var rows = new List<StoredTrafficRecord>();
                while ((result = Native.sqlite3_step(statement)) == SqliteRow)
                {
                    var traffic = new TrafficRecord(
                        Guid.Parse(Text(statement, 0)), DateTimeOffset.Parse(Text(statement, 2)), Text(statement, 3),
                        Text(statement, 4), Native.sqlite3_column_int(statement, 5), Native.sqlite3_column_int(statement, 6),
                        Native.sqlite3_column_int64(statement, 7), Text(statement, 8), Text(statement, 9), Text(statement, 12),
                        Text(statement, 13), Text(statement, 15), Text(statement, 16), Text(statement, 17), Text(statement, 18), Text(statement, 19));
                    rows.Add(new StoredTrafficRecord(traffic, Guid.Parse(Text(statement, 1)), Text(statement, 10), Text(statement, 11), Text(statement, 14)));
                }
                if (result != SqliteDone) throw CreateException("读取记录组事务时发生错误", result);
                return rows;
            }
            finally { Native.sqlite3_finalize(statement); }
        }
    }

    public long GetTrafficCount()
    {
        lock (_gate)
        {
            EnsureOpen();
            var result = Native.sqlite3_prepare_v2(_database, Utf8("SELECT COUNT(*) FROM traffic_transactions;"), -1, out var statement, IntPtr.Zero);
            if (result != SqliteOk) throw CreateException("无法读取流量数量", result);
            try
            {
                return Native.sqlite3_step(statement) == SqliteRow ? Native.sqlite3_column_int64(statement, 0) : 0;
            }
            finally
            {
                Native.sqlite3_finalize(statement);
            }
        }
    }

    public long GetPageHookCount() => Scalar("SELECT COUNT(*) FROM page_hooks;");

    public IReadOnlyList<CaptureSessionSummary> GetRecentSessions(int limit = NetMindDefaults.DefaultSessionWindowCount)
    {
        limit = Math.Clamp(limit, 1, 500);
        lock (_gate)
        {
            EnsureOpen();
            var sql = $"SELECT s.id,s.started_at,s.ended_at,s.mode,s.target,s.state,COUNT(t.id) FROM capture_sessions s LEFT JOIN traffic_transactions t ON t.session_id=s.id GROUP BY s.id,s.started_at,s.ended_at,s.mode,s.target,s.state ORDER BY s.started_at DESC LIMIT {limit};";
            var result = Native.sqlite3_prepare_v2(_database, Utf8(sql), -1, out var statement, IntPtr.Zero);
            if (result != SqliteOk) throw CreateException("无法读取捕获会话", result);
            try
            {
                var sessions = new List<CaptureSessionSummary>();
                while ((result = Native.sqlite3_step(statement)) == SqliteRow)
                {
                    var endedAtText = Text(statement, 2);
                    var session = new CaptureSessionRecord(
                        Guid.Parse(Text(statement, 0)),
                        DateTimeOffset.Parse(Text(statement, 1)),
                        string.IsNullOrWhiteSpace(endedAtText) ? null : DateTimeOffset.Parse(endedAtText),
                        Text(statement, 3),
                        Text(statement, 4),
                        Text(statement, 5));
                    sessions.Add(new CaptureSessionSummary(session, Native.sqlite3_column_int64(statement, 6)));
                }
                if (result != SqliteDone) throw CreateException("读取捕获会话时发生错误", result);
                return sessions;
            }
            finally { Native.sqlite3_finalize(statement); }
        }
    }

    public long ClearCaptureData()
    {
        var count = GetTrafficCount();
        // 保留“运行中”的会话行：采集中清空时采集进程仍持有该会话并继续写入事务，
        // 会话行被删会导致事务外键失败；会话结束时采集进程会把它更新为已完成。
        Execute($"BEGIN IMMEDIATE; DELETE FROM traffic_transactions; DELETE FROM capture_sessions WHERE state <> '{Esc(NetMindDefaults.SessionStateRunning)}'; COMMIT;");
        return count;
    }

    /// <summary>
    /// 按事务 ID 定向删除流量事务（工作台勾选删除），返回实际删除条数；
    /// 正文 Blob 的引用清理由调用方结合 <see cref="GetReferencedBlobHashes"/> 处理。
    /// </summary>
    public long DeleteTraffic(IReadOnlyCollection<Guid> ids)
    {
        var snapshot = ids.Where(id => id != Guid.Empty).Distinct().Take(1001).ToArray();
        if (snapshot.Length > 1000) throw new InvalidOperationException("单次最多删除 1,000 条流量记录。");
        if (snapshot.Length == 0) return 0;
        var idList = string.Join(",", snapshot.Select(id => $"'{Esc(id.ToString())}'"));
        var existing = Scalar($"SELECT COUNT(*) FROM traffic_transactions WHERE id IN ({idList});");
        Execute($"BEGIN IMMEDIATE; DELETE FROM traffic_transactions WHERE id IN ({idList}); COMMIT;");
        return existing;
    }

    /// <summary>按采集时间升序读取早于截止时间的事务 ID，供保留策略分批删除。</summary>
    public IReadOnlyList<Guid> GetTrafficIdsOlderThan(DateTimeOffset cutoff, int limit = 500) =>
        GetTrafficIds($"WHERE julianday(captured_at) < julianday('{Esc(cutoff.UtcDateTime.ToString("O"))}')", limit);

    /// <summary>按采集时间升序读取最旧事务 ID，供工作区容量上限治理。</summary>
    public IReadOnlyList<Guid> GetOldestTrafficIds(int limit = 500) => GetTrafficIds(string.Empty, limit);

    private IReadOnlyList<Guid> GetTrafficIds(string whereClause, int limit)
    {
        limit = Math.Clamp(limit, 1, 1000);
        lock (_gate)
        {
            EnsureOpen();
            var sql = $"SELECT id FROM traffic_transactions {whereClause} ORDER BY captured_at ASC, id ASC LIMIT {limit};";
            var result = Native.sqlite3_prepare_v2(_database, Utf8(sql), -1, out var statement, IntPtr.Zero);
            if (result != SqliteOk) throw CreateException("无法读取最旧事务", result);
            try
            {
                var ids = new List<Guid>();
                while ((result = Native.sqlite3_step(statement)) == SqliteRow)
                    if (Guid.TryParse(Text(statement, 0), out var id)) ids.Add(id);
                if (result != SqliteDone) throw CreateException("读取最旧事务时发生错误", result);
                return ids;
            }
            finally { Native.sqlite3_finalize(statement); }
        }
    }

    /// <summary>当前仍被任意事务引用的正文哈希集合（请求与响应正文，空哈希除外）。</summary>
    public IReadOnlySet<string> GetReferencedBlobHashes()
    {
        lock (_gate)
        {
            EnsureOpen();
            var result = Native.sqlite3_prepare_v2(_database, Utf8("""
                SELECT DISTINCT hash FROM (
                    SELECT request_blob_hash AS hash FROM traffic_transactions
                    UNION ALL
                    SELECT response_blob_hash AS hash FROM traffic_transactions
                ) WHERE hash <> '';
                """), -1, out var statement, IntPtr.Zero);
            if (result != SqliteOk) throw CreateException("无法读取正文引用哈希", result);
            try
            {
                var hashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                while ((result = Native.sqlite3_step(statement)) == SqliteRow) hashes.Add(Text(statement, 0));
                if (result != SqliteDone) throw CreateException("读取正文引用哈希时发生错误", result);
                return hashes;
            }
            finally { Native.sqlite3_finalize(statement); }
        }
    }

    // ── 页内 Hook 事件（采集浏览器注入脚本上报） ─────────────────────────────

    /// <summary>
    /// 批量写入页内 Hook 事件，并在同一事务内淘汰超过总量上限的最旧记录；
    /// 单批入库条数受 <see cref="NetMindDefaults.PageHookMaximumEventsPerBatch"/> 限制；
    /// maximumRows 仅供定向测试注入小阈值。
    /// </summary>
    public void SavePageHooks(IReadOnlyList<PageHookEvent> events, int maximumRows = NetMindDefaults.PageHookMaximumRows)
    {
        if (events.Count == 0) return;
        var builder = new StringBuilder("BEGIN IMMEDIATE;");
        foreach (var item in events.Take(NetMindDefaults.PageHookMaximumEventsPerBatch))
        {
            builder.Append("INSERT INTO page_hooks(session_id,ts,type,fn,page_url,args_json,target_url,stack) VALUES(")
                .Append('\'').Append(Esc(item.SessionId.ToString())).Append("',")
                .Append('\'').Append(Esc(item.Timestamp.ToString("O"))).Append("',")
                .Append('\'').Append(Esc(item.Type)).Append("',")
                .Append('\'').Append(Esc(item.Function)).Append("',")
                .Append('\'').Append(Esc(item.PageUrl)).Append("',")
                .Append('\'').Append(Esc(item.ArgsJson)).Append("',")
                .Append('\'').Append(Esc(item.TargetUrl)).Append("',")
                .Append('\'').Append(Esc(item.Stack)).Append("');");
        }
        builder.Append($"DELETE FROM page_hooks WHERE id NOT IN (SELECT id FROM page_hooks ORDER BY id DESC LIMIT {maximumRows});");
        builder.Append("COMMIT;");
        Execute(builder.ToString());
    }

    /// <summary>按类型过滤读取页内 Hook 事件（最新在前）；type 为空返回全部。</summary>
    public IReadOnlyList<PageHookEvent> GetPageHooks(string? type, int limit = 200)
    {
        limit = Math.Clamp(limit, 1, 1000);
        var filter = string.IsNullOrWhiteSpace(type) ? string.Empty : $" WHERE type='{Esc(type)}'";
        lock (_gate)
        {
            EnsureOpen();
            var result = Native.sqlite3_prepare_v2(_database, Utf8($"SELECT id,session_id,ts,type,fn,page_url,args_json,target_url,stack FROM page_hooks{filter} ORDER BY id DESC LIMIT {limit};"), -1, out var statement, IntPtr.Zero);
            if (result != SqliteOk) throw CreateException("无法读取页内 Hook 事件", result);
            try
            {
                var rows = new List<PageHookEvent>();
                while ((result = Native.sqlite3_step(statement)) == SqliteRow)
                {
                    rows.Add(new PageHookEvent(
                        Native.sqlite3_column_int64(statement, 0),
                        Guid.TryParse(Text(statement, 1), out var sessionId) ? sessionId : Guid.Empty,
                        DateTimeOffset.Parse(Text(statement, 2)),
                        Text(statement, 3),
                        Text(statement, 4),
                        Text(statement, 5),
                        Text(statement, 6),
                        Text(statement, 7),
                        Text(statement, 8)));
                }
                if (result != SqliteDone) throw CreateException("读取页内 Hook 事件时发生错误", result);
                return rows;
            }
            finally { Native.sqlite3_finalize(statement); }
        }
    }

    /// <summary>
    /// 只读取指定捕获会话的 Hook 事件，避免 AI 证据池混入其他会话的页内调用。
    /// 会话 ID 去重且限制为 1,000 个，空集合直接返回空结果。
    /// </summary>
    public IReadOnlyList<PageHookEvent> GetPageHooksBySessions(IEnumerable<Guid> sessionIds, string? type = null, int limit = 200)
    {
        var sessions = sessionIds.Where(id => id != Guid.Empty).Distinct().Take(1001).ToArray();
        if (sessions.Length > 1000) throw new InvalidOperationException("单次最多检索 1,000 个捕获会话的 Hook 事件。");
        if (sessions.Length == 0) return [];
        limit = Math.Clamp(limit, 1, 1000);
        var sessionList = string.Join(',', sessions.Select(id => $"'{Esc(id.ToString())}'"));
        var typeFilter = string.IsNullOrWhiteSpace(type) ? string.Empty : $" AND type='{Esc(type)}'";
        lock (_gate)
        {
            EnsureOpen();
            var sql = $"SELECT id,session_id,ts,type,fn,page_url,args_json,target_url,stack FROM page_hooks WHERE session_id IN ({sessionList}){typeFilter} ORDER BY id DESC LIMIT {limit};";
            var result = Native.sqlite3_prepare_v2(_database, Utf8(sql), -1, out var statement, IntPtr.Zero);
            if (result != SqliteOk) throw CreateException("无法读取指定会话的页内 Hook 事件", result);
            try
            {
                var rows = new List<PageHookEvent>();
                while ((result = Native.sqlite3_step(statement)) == SqliteRow)
                {
                    rows.Add(new PageHookEvent(
                        Native.sqlite3_column_int64(statement, 0),
                        Guid.TryParse(Text(statement, 1), out var sessionId) ? sessionId : Guid.Empty,
                        DateTimeOffset.Parse(Text(statement, 2)),
                        Text(statement, 3), Text(statement, 4), Text(statement, 5), Text(statement, 6),
                        Text(statement, 7), Text(statement, 8)));
                }
                if (result != SqliteDone) throw CreateException("读取指定会话的页内 Hook 事件时发生错误", result);
                return rows;
            }
            finally { Native.sqlite3_finalize(statement); }
        }
    }

    /// <summary>清空全部页内 Hook 事件（随“清空记录”联动），返回删除条数。</summary>
    public long ClearPageHooks()
    {
        var count = Scalar("SELECT COUNT(*) FROM page_hooks;");
        Execute("DELETE FROM page_hooks;");
        return count;
    }

    /// <summary>删除早于截止时间的页内 Hook 事件，并返回实际删除条数。</summary>
    public long DeletePageHooksOlderThan(DateTimeOffset cutoff)
    {
        var condition = $"julianday(ts) < julianday('{Esc(cutoff.UtcDateTime.ToString("O"))}')";
        var count = Scalar($"SELECT COUNT(*) FROM page_hooks WHERE {condition};");
        if (count > 0) Execute($"DELETE FROM page_hooks WHERE {condition};");
        return count;
    }

    /// <summary>删除没有事务引用且已结束的旧捕获会话。</summary>
    public long DeleteUnusedCompletedSessionsOlderThan(DateTimeOffset cutoff)
    {
        var condition = $"state <> '{Esc(NetMindDefaults.SessionStateRunning)}' " +
                        $"AND julianday(COALESCE(ended_at, started_at)) < julianday('{Esc(cutoff.UtcDateTime.ToString("O"))}') " +
                        "AND NOT EXISTS (SELECT 1 FROM traffic_transactions t WHERE t.session_id = capture_sessions.id)";
        var count = Scalar($"SELECT COUNT(*) FROM capture_sessions WHERE {condition};");
        if (count > 0) Execute($"DELETE FROM capture_sessions WHERE {condition};");
        return count;
    }

    /// <summary>截断 WAL 并压缩 SQLite 主文件；只应在采集停止且无并发写入时调用。</summary>
    public void CheckpointAndVacuum() => Execute("PRAGMA wal_checkpoint(TRUNCATE); VACUUM;");

    /// <summary>把 WAL 内容合并进主数据库并截断 WAL，供一致性工作区备份使用。</summary>
    public void Checkpoint() => Execute("PRAGMA wal_checkpoint(TRUNCATE);");

    private long Scalar(string sql)
    {
        lock (_gate)
        {
            EnsureOpen();
            var result = Native.sqlite3_prepare_v2(_database, Utf8(sql), -1, out var statement, IntPtr.Zero);
            if (result != SqliteOk) throw CreateException("无法执行统计查询", result);
            try
            {
                return Native.sqlite3_step(statement) == SqliteRow ? Native.sqlite3_column_int64(statement, 0) : 0;
            }
            finally { Native.sqlite3_finalize(statement); }
        }
    }

    private void InitializeSchema()
    {
        Execute("""
            CREATE TABLE IF NOT EXISTS capture_sessions(
                id TEXT PRIMARY KEY,
                started_at TEXT NOT NULL,
                ended_at TEXT NULL,
                mode TEXT NOT NULL,
                target TEXT NOT NULL,
                state TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS traffic_transactions(
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                captured_at TEXT NOT NULL,
                method TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                status_code INTEGER NOT NULL,
                latency_ms INTEGER NOT NULL,
                size_bytes INTEGER NOT NULL,
                process_name TEXT NOT NULL,
                protocol TEXT NOT NULL,
                request_blob_hash TEXT NOT NULL,
                response_blob_hash TEXT NOT NULL,
                request_summary TEXT NOT NULL,
                response_summary TEXT NOT NULL,
                FOREIGN KEY(session_id) REFERENCES capture_sessions(id)
            );
            CREATE INDEX IF NOT EXISTS ix_traffic_captured_at ON traffic_transactions(captured_at DESC);
            CREATE INDEX IF NOT EXISTS ix_traffic_session ON traffic_transactions(session_id);
            CREATE INDEX IF NOT EXISTS ix_traffic_session_time ON traffic_transactions(session_id, captured_at DESC);
            CREATE INDEX IF NOT EXISTS ix_traffic_endpoint ON traffic_transactions(endpoint);
            CREATE INDEX IF NOT EXISTS ix_traffic_method_endpoint ON traffic_transactions(method, endpoint);
            CREATE INDEX IF NOT EXISTS ix_traffic_status_time ON traffic_transactions(status_code, captured_at DESC);
            CREATE TABLE IF NOT EXISTS page_hooks(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                ts TEXT NOT NULL,
                type TEXT NOT NULL,
                fn TEXT NOT NULL,
                page_url TEXT NOT NULL,
                args_json TEXT NOT NULL,
                target_url TEXT NOT NULL DEFAULT '',
                stack TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS ix_page_hooks_type ON page_hooks(type);
            CREATE INDEX IF NOT EXISTS ix_page_hooks_session_id ON page_hooks(session_id, id DESC);
            CREATE INDEX IF NOT EXISTS ix_page_hooks_type_id ON page_hooks(type, id DESC);
            """);
    }

    private void EnsureTrafficMetadataColumns()
    {
        // user_version 已达目标时跳过逐列探测；旧库首次打开仍会执行探测/补齐并提升版本号。
        if (ReadSchemaVersion() >= SchemaVersion) return;
        EnsureColumn("traffic_transactions", "request_url", "TEXT NOT NULL DEFAULT ''");
        EnsureColumn("traffic_transactions", "query_parameters", "TEXT NOT NULL DEFAULT ''");
        EnsureColumn("traffic_transactions", "request_headers", "TEXT NOT NULL DEFAULT ''");
        EnsureColumn("traffic_transactions", "cookies", "TEXT NOT NULL DEFAULT ''");
        EnsureColumn("traffic_transactions", "response_headers", "TEXT NOT NULL DEFAULT ''");
        EnsureColumn("page_hooks", "target_url", "TEXT NOT NULL DEFAULT ''");
        EnsureColumn("page_hooks", "stack", "TEXT NOT NULL DEFAULT ''");
        Execute($"PRAGMA user_version={SchemaVersion};");
    }

    private int ReadSchemaVersion()
    {
        lock (_gate)
        {
            EnsureOpen();
            var result = Native.sqlite3_prepare_v2(_database, Utf8("PRAGMA user_version;"), -1, out var statement, IntPtr.Zero);
            if (result != SqliteOk) throw CreateException("无法读取数据库架构版本", result);
            try
            {
                return Native.sqlite3_step(statement) == SqliteRow ? Native.sqlite3_column_int(statement, 0) : 0;
            }
            finally { Native.sqlite3_finalize(statement); }
        }
    }

    private void EnsureColumn(string table, string column, string definition)
    {
        lock (_gate)
        {
            EnsureOpen();
            var result = Native.sqlite3_prepare_v2(_database, Utf8($"PRAGMA table_info({table});"), -1, out var statement, IntPtr.Zero);
            if (result != SqliteOk) throw CreateException($"无法检查字段 {column}", result);
            try
            {
                while ((result = Native.sqlite3_step(statement)) == SqliteRow)
                    if (Text(statement, 1).Equals(column, StringComparison.OrdinalIgnoreCase)) return;
                if (result != SqliteDone) throw CreateException($"检查字段 {column} 时发生错误", result);
            }
            finally { Native.sqlite3_finalize(statement); }
            Execute($"ALTER TABLE {table} ADD COLUMN {column} {definition};");
        }
    }

    private void Execute(string sql)
    {
        lock (_gate)
        {
            EnsureOpen();
            var result = Native.sqlite3_exec(_database, Utf8(sql), IntPtr.Zero, IntPtr.Zero, out var errorPointer);
            if (result == SqliteOk) return;
            var detail = errorPointer == IntPtr.Zero ? null : Marshal.PtrToStringUTF8(errorPointer);
            if (errorPointer != IntPtr.Zero) Native.sqlite3_free(errorPointer);
            throw CreateException(detail ?? "SQLite 操作失败", result);
        }
    }

    private InvalidOperationException CreateException(string message, int result)
    {
        var nativeMessage = _database == IntPtr.Zero ? null : Marshal.PtrToStringUTF8(Native.sqlite3_errmsg(_database));
        return new InvalidOperationException($"{message}（SQLite {result}：{nativeMessage ?? "未知错误"}）");
    }

    private static string Text(IntPtr statement, int column)
    {
        var pointer = Native.sqlite3_column_text(statement, column);
        return pointer == IntPtr.Zero ? string.Empty : Marshal.PtrToStringUTF8(pointer) ?? string.Empty;
    }

    private static string Esc(string value) => value.Replace("'", "''", StringComparison.Ordinal);
    private static string Sql(string? value) => value is null ? "NULL" : $"'{Esc(value)}'";
    private static byte[] Utf8(string value) => Encoding.UTF8.GetBytes(value + '\0');

    private void EnsureOpen()
    {
        if (_database == IntPtr.Zero) throw new ObjectDisposedException(nameof(SqliteMetadataStore));
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_database == IntPtr.Zero) return;
            Native.sqlite3_close_v2(_database);
            _database = IntPtr.Zero;
        }
        GC.SuppressFinalize(this);
    }

    private static class Native
    {
        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int sqlite3_open_v2(byte[] filename, out IntPtr database, int flags, IntPtr vfs);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int sqlite3_close_v2(IntPtr database);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int sqlite3_exec(IntPtr database, byte[] sql, IntPtr callback, IntPtr argument, out IntPtr errorMessage);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int sqlite3_prepare_v2(IntPtr database, byte[] sql, int bytes, out IntPtr statement, IntPtr tail);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int sqlite3_step(IntPtr statement);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int sqlite3_finalize(IntPtr statement);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int sqlite3_column_int(IntPtr statement, int column);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern long sqlite3_column_int64(IntPtr statement, int column);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr sqlite3_column_text(IntPtr statement, int column);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr sqlite3_errmsg(IntPtr database);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern void sqlite3_free(IntPtr pointer);
    }
}
