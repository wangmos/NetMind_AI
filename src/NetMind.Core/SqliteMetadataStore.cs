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
    /// <summary>sqlite3_bind_text 的 SQLITE_TRANSIENT 析构器：要求 SQLite 在调用返回前复制缓冲区。</summary>
    private static readonly IntPtr SqliteTransient = new(-1);
    private readonly object _gate = new();
    /// <summary>热路径写语句的预编译缓存（SQL 文本恒定，条目数固定为下面三条常量）。</summary>
    private readonly Dictionary<string, IntPtr> _statements = new(StringComparer.Ordinal);
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

    private const string SaveSessionSql = """
        INSERT INTO capture_sessions(id, started_at, ended_at, mode, target, state)
        VALUES(?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            ended_at=excluded.ended_at,
            mode=excluded.mode,
            target=excluded.target,
            state=excluded.state;
        """;

    private const string SaveTrafficSql = """
        INSERT OR REPLACE INTO traffic_transactions(
            id, session_id, captured_at, method, endpoint, status_code, latency_ms,
            size_bytes, process_name, protocol, request_blob_hash, response_blob_hash,
            request_summary, response_summary, request_url, query_parameters,
            request_headers, cookies, response_headers)
        VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """;

    public void SaveSession(CaptureSessionRecord session) =>
        WriteCached(SaveSessionSql, "无法保存捕获会话",
            session.Id, session.StartedAt, session.EndedAt?.ToString("O"), session.Mode, session.Target, session.State);

    /// <summary>
    /// 写入一条事务元数据。URL、Header、Cookie 等字段直接来自被抓取的网络流量，
    /// 完全由被访问站点控制，因此全部经参数绑定写入，绝不进入 SQL 文本。
    /// </summary>
    public void SaveTraffic(StoredTrafficRecord stored)
    {
        var item = stored.Traffic;
        WriteCached(SaveTrafficSql, "无法保存流量元数据",
            item.Id, stored.SessionId, item.Timestamp,
            item.Method, item.Endpoint, item.StatusCode, item.LatencyMs,
            item.SizeBytes, item.Process, item.Protocol,
            stored.RequestBlobHash, stored.ResponseBlobHash,
            item.RequestSummary, item.ResponseSummary, item.Url,
            item.QueryParameters, item.RequestHeaders, item.Cookies,
            item.ResponseHeaders);
    }

    /// <summary>
    /// 读取最近的事务窗口。<paramref name="sessionId"/> 非空时只返回该捕获会话的事务：
    /// 工作台据此让每次「开始采集」从空列表起步，也让下钻历史会话时窗口不被其他会话占满。
    /// </summary>
    public IReadOnlyList<StoredTrafficRecord> GetRecentTraffic(int limit = NetMindDefaults.DefaultTrafficWindowCount,
        Guid? sessionId = null)
    {
        limit = Math.Clamp(limit, 1, 2000);
        const string columns = "t.id,t.session_id,t.captured_at,t.method,t.endpoint,t.status_code,t.latency_ms,t.size_bytes,t.process_name,t.protocol,t.request_blob_hash,t.response_blob_hash,t.request_summary,t.response_summary,COALESCE(s.mode,'未知'),t.request_url,t.query_parameters,t.request_headers,t.cookies,t.response_headers";
        var scope = sessionId.HasValue ? " WHERE t.session_id=?" : string.Empty;
        Parameter[] parameters = sessionId.HasValue ? [sessionId.Value, limit] : [limit];
        lock (_gate)
        {
            EnsureOpen();
            var statement = Prepare(
                $"SELECT {columns} FROM traffic_transactions t LEFT JOIN capture_sessions s ON s.id=t.session_id{scope} ORDER BY t.captured_at DESC LIMIT ?;",
                "无法读取流量元数据", parameters);
            try
            {
                int result;
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
            var statement = Prepare("SELECT COALESCE(MAX(rowid), 0) FROM traffic_transactions;", "无法读取流量刷新游标");
            try
            {
                return Native.sqlite3_step(statement) == SqliteRow ? Native.sqlite3_column_int64(statement, 0) : 0;
            }
            finally { Native.sqlite3_finalize(statement); }
        }
    }

    /// <summary>
    /// 读取给定 SQLite 写入游标之后的新增或更新事务，按实际写入顺序返回。
    /// <paramref name="sessionId"/> 非空时只返回该捕获会话的变更，与 <see cref="GetRecentTraffic"/> 的限定一致。
    /// </summary>
    public IReadOnlyList<StoredTrafficChange> GetTrafficChangesAfter(long cursor, int limit = 2000, Guid? sessionId = null)
    {
        cursor = Math.Max(0, cursor);
        limit = Math.Clamp(limit, 1, 2000);
        const string columns = "t.id,t.session_id,t.captured_at,t.method,t.endpoint,t.status_code,t.latency_ms,t.size_bytes,t.process_name,t.protocol,t.request_blob_hash,t.response_blob_hash,t.request_summary,t.response_summary,COALESCE(s.mode,'未知'),t.request_url,t.query_parameters,t.request_headers,t.cookies,t.response_headers";
        var scope = sessionId.HasValue ? " AND t.session_id=?" : string.Empty;
        Parameter[] parameters = sessionId.HasValue ? [cursor, sessionId.Value, limit] : [cursor, limit];
        lock (_gate)
        {
            EnsureOpen();
            var sql = $"SELECT t.rowid,{columns} FROM traffic_transactions t LEFT JOIN capture_sessions s ON s.id=t.session_id WHERE t.rowid>?{scope} ORDER BY t.rowid ASC LIMIT ?;";
            var statement = Prepare(sql, "无法增量读取流量元数据", parameters);
            try
            {
                int result;
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
        var parameters = Array.ConvertAll(snapshot, id => (Parameter)id);
        lock (_gate)
        {
            EnsureOpen();
            var statement = Prepare(
                $"SELECT {columns} FROM traffic_transactions t LEFT JOIN capture_sessions s ON s.id=t.session_id WHERE t.id IN ({Placeholders(snapshot.Length)}) ORDER BY t.captured_at ASC;",
                "无法读取记录组事务", parameters);
            try
            {
                int result;
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

    /// <summary><paramref name="sessionId"/> 非空时只统计该捕获会话的事务数。</summary>
    public long GetTrafficCount(Guid? sessionId = null) => sessionId.HasValue
        ? Scalar("SELECT COUNT(*) FROM traffic_transactions WHERE session_id=?;", sessionId.Value)
        : Scalar("SELECT COUNT(*) FROM traffic_transactions;");

    public long GetPageHookCount() => Scalar("SELECT COUNT(*) FROM page_hooks;");

    public IReadOnlyList<CaptureSessionSummary> GetRecentSessions(int limit = NetMindDefaults.DefaultSessionWindowCount)
    {
        limit = Math.Clamp(limit, 1, 500);
        lock (_gate)
        {
            EnsureOpen();
            const string sql = "SELECT s.id,s.started_at,s.ended_at,s.mode,s.target,s.state,COUNT(t.id) FROM capture_sessions s LEFT JOIN traffic_transactions t ON t.session_id=s.id GROUP BY s.id,s.started_at,s.ended_at,s.mode,s.target,s.state ORDER BY s.started_at DESC LIMIT ?;";
            var statement = Prepare(sql, "无法读取捕获会话", limit);
            try
            {
                int result;
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
        InTransaction(() =>
        {
            Execute("DELETE FROM traffic_transactions;");
            // 保留“运行中”的会话行：采集中清空时采集进程仍持有该会话并继续写入事务，
            // 会话行被删会导致事务外键失败；会话结束时采集进程会把它更新为已完成。
            Write("DELETE FROM capture_sessions WHERE state <> ?;", "无法清理已结束的捕获会话",
                NetMindDefaults.SessionStateRunning);
        });
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
        var parameters = Array.ConvertAll(snapshot, id => (Parameter)id);
        var placeholders = Placeholders(snapshot.Length);
        long existing;
        lock (_gate)
        {
            existing = Scalar($"SELECT COUNT(*) FROM traffic_transactions WHERE id IN ({placeholders});", parameters);
            InTransaction(() => Write($"DELETE FROM traffic_transactions WHERE id IN ({placeholders});",
                "无法删除流量记录", parameters));
        }
        return existing;
    }

    /// <summary>按采集时间升序读取早于截止时间的事务 ID，供保留策略分批删除。</summary>
    public IReadOnlyList<Guid> GetTrafficIdsOlderThan(DateTimeOffset cutoff, int limit = 500) =>
        GetTrafficIds("WHERE julianday(captured_at) < julianday(?)", limit, cutoff);

    /// <summary>按采集时间升序读取最旧事务 ID，供工作区容量上限治理。</summary>
    public IReadOnlyList<Guid> GetOldestTrafficIds(int limit = 500) => GetTrafficIds(string.Empty, limit);

    private IReadOnlyList<Guid> GetTrafficIds(string whereClause, int limit, params ReadOnlySpan<Parameter> filters)
    {
        limit = Math.Clamp(limit, 1, 1000);
        // 过滤参数（若有）在 SQL 中先于 LIMIT 出现，绑定顺序必须一致。
        var parameters = new Parameter[filters.Length + 1];
        filters.CopyTo(parameters);
        parameters[^1] = limit;
        lock (_gate)
        {
            EnsureOpen();
            var sql = $"SELECT id FROM traffic_transactions {whereClause} ORDER BY captured_at ASC, id ASC LIMIT ?;";
            var statement = Prepare(sql, "无法读取最旧事务", parameters);
            try
            {
                int result;
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
            var statement = Prepare("""
                SELECT DISTINCT hash FROM (
                    SELECT request_blob_hash AS hash FROM traffic_transactions
                    UNION ALL
                    SELECT response_blob_hash AS hash FROM traffic_transactions
                ) WHERE hash <> '';
                """, "无法读取正文引用哈希");
            try
            {
                int result;
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
        InTransaction(() =>
        {
            foreach (var item in events.Take(NetMindDefaults.PageHookMaximumEventsPerBatch))
            {
                WriteCached(SavePageHookSql, "无法写入页内 Hook 事件",
                    item.SessionId, item.Timestamp, item.Type, item.Function,
                    item.PageUrl, item.ArgsJson, item.TargetUrl, item.Stack);
            }
            Write("DELETE FROM page_hooks WHERE id NOT IN (SELECT id FROM page_hooks ORDER BY id DESC LIMIT ?);",
                "无法淘汰超量页内 Hook 事件", maximumRows);
        });
    }

    private const string SavePageHookSql =
        "INSERT INTO page_hooks(session_id,ts,type,fn,page_url,args_json,target_url,stack) VALUES(?, ?, ?, ?, ?, ?, ?, ?);";

    /// <summary>按类型过滤读取页内 Hook 事件（最新在前）；type 为空返回全部。</summary>
    public IReadOnlyList<PageHookEvent> GetPageHooks(string? type, int limit = 200)
    {
        limit = Math.Clamp(limit, 1, 1000);
        var hasType = !string.IsNullOrWhiteSpace(type);
        var filter = hasType ? " WHERE type=?" : string.Empty;
        Parameter[] parameters = hasType ? [type, limit] : [limit];
        lock (_gate)
        {
            EnsureOpen();
            var statement = Prepare(
                $"SELECT id,session_id,ts,type,fn,page_url,args_json,target_url,stack FROM page_hooks{filter} ORDER BY id DESC LIMIT ?;",
                "无法读取页内 Hook 事件", parameters);
            try
            {
                int result;
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
        var hasType = !string.IsNullOrWhiteSpace(type);
        var typeFilter = hasType ? " AND type=?" : string.Empty;
        // 绑定顺序与 SQL 中 `?` 的出现顺序一致：会话 ID 集合、可选类型、LIMIT。
        var parameters = new List<Parameter>(sessions.Length + 2);
        parameters.AddRange(sessions.Select(id => (Parameter)id));
        if (hasType) parameters.Add(type);
        parameters.Add(limit);
        lock (_gate)
        {
            EnsureOpen();
            var sql = $"SELECT id,session_id,ts,type,fn,page_url,args_json,target_url,stack FROM page_hooks WHERE session_id IN ({Placeholders(sessions.Length)}){typeFilter} ORDER BY id DESC LIMIT ?;";
            var statement = Prepare(sql, "无法读取指定会话的页内 Hook 事件", CollectionsMarshal.AsSpan(parameters));
            try
            {
                int result;
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
        const string condition = "julianday(ts) < julianday(?)";
        var utcCutoff = new DateTimeOffset(cutoff.UtcDateTime, TimeSpan.Zero);
        lock (_gate)
        {
            var count = Scalar($"SELECT COUNT(*) FROM page_hooks WHERE {condition};", utcCutoff);
            if (count > 0) Write($"DELETE FROM page_hooks WHERE {condition};", "无法删除到期页内 Hook 事件", utcCutoff);
            return count;
        }
    }

    /// <summary>删除没有事务引用且已结束的旧捕获会话。</summary>
    public long DeleteUnusedCompletedSessionsOlderThan(DateTimeOffset cutoff)
    {
        const string condition =
            "state <> ? " +
            "AND julianday(COALESCE(ended_at, started_at)) < julianday(?) " +
            "AND NOT EXISTS (SELECT 1 FROM traffic_transactions t WHERE t.session_id = capture_sessions.id)";
        var utcCutoff = new DateTimeOffset(cutoff.UtcDateTime, TimeSpan.Zero);
        lock (_gate)
        {
            var count = Scalar($"SELECT COUNT(*) FROM capture_sessions WHERE {condition};",
                NetMindDefaults.SessionStateRunning, utcCutoff);
            if (count > 0)
                Write($"DELETE FROM capture_sessions WHERE {condition};", "无法删除无引用的旧捕获会话",
                    NetMindDefaults.SessionStateRunning, utcCutoff);
            return count;
        }
    }

    /// <summary>截断 WAL 并压缩 SQLite 主文件；只应在采集停止且无并发写入时调用。</summary>
    public void CheckpointAndVacuum() => Execute("PRAGMA wal_checkpoint(TRUNCATE); VACUUM;");

    /// <summary>把 WAL 内容合并进主数据库并截断 WAL，供一致性工作区备份使用。</summary>
    public void Checkpoint() => Execute("PRAGMA wal_checkpoint(TRUNCATE);");

    private long Scalar(string sql, params ReadOnlySpan<Parameter> parameters)
    {
        lock (_gate)
        {
            EnsureOpen();
            var statement = Prepare(sql, "无法执行统计查询", parameters);
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
            var statement = Prepare("PRAGMA user_version;", "无法读取数据库架构版本");
            try
            {
                return Native.sqlite3_step(statement) == SqliteRow ? Native.sqlite3_column_int(statement, 0) : 0;
            }
            finally { Native.sqlite3_finalize(statement); }
        }
    }

    /// <summary>
    /// 表名与列名是 SQL 标识符，无法用参数绑定，只能拼进语句文本。
    /// 因此这里强制它们只能是 ASCII 标识符字面量——本类的全部调用点都传编译期常量，
    /// 该检查用于把这个前提固化下来，防止后续有人把外部数据接到这条路径上。
    /// </summary>
    private static string Identifier(string value)
    {
        foreach (var character in value)
            if (!char.IsAsciiLetterOrDigit(character) && character != '_')
                throw new ArgumentException($"SQL 标识符只允许 ASCII 字母、数字和下划线：{value}", nameof(value));
        return value.Length == 0 ? throw new ArgumentException("SQL 标识符不能为空。", nameof(value)) : value;
    }

    private void EnsureColumn(string table, string column, string definition)
    {
        table = Identifier(table);
        column = Identifier(column);
        lock (_gate)
        {
            EnsureOpen();
            var statement = Prepare($"PRAGMA table_info({table});", $"无法检查字段 {column}");
            try
            {
                int result;
                while ((result = Native.sqlite3_step(statement)) == SqliteRow)
                    if (Text(statement, 1).Equals(column, StringComparison.OrdinalIgnoreCase)) return;
                if (result != SqliteDone) throw CreateException($"检查字段 {column} 时发生错误", result);
            }
            finally { Native.sqlite3_finalize(statement); }
            Execute($"ALTER TABLE {table} ADD COLUMN {column} {definition};");
        }
    }

    /// <summary>
    /// 绑定到预编译语句的参数值。只有文本、整数和 NULL 三种存储类；文本按显式字节长度绑定，
    /// 因此可以原样携带 NUL、单引号等任何字节，无需也不允许再做 SQL 文本转义。
    /// Guid 与 DateTimeOffset 的文本形式在此统一（分别为 <c>ToString()</c> 与 ISO 8601 <c>"O"</c>），
    /// 避免各调用点各写各的格式。
    /// </summary>
    private readonly struct Parameter
    {
        private readonly byte[]? _text;
        private readonly long _number;
        private readonly bool _isNumber;

        private Parameter(byte[]? text, long number, bool isNumber)
        {
            _text = text;
            _number = number;
            _isNumber = isNumber;
        }

        public void Bind(IntPtr statement, int index)
        {
            var result = _isNumber
                ? Native.sqlite3_bind_int64(statement, index, _number)
                : _text is null
                    ? Native.sqlite3_bind_null(statement, index)
                    : Native.sqlite3_bind_text(statement, index, _text, _text.Length, SqliteTransient);
            if (result != SqliteOk)
                throw new InvalidOperationException($"无法绑定第 {index} 个查询参数（SQLite {result}）。");
        }

        public static implicit operator Parameter(string? value) =>
            new(value is null ? null : Encoding.UTF8.GetBytes(value), 0, isNumber: false);
        public static implicit operator Parameter(long value) => new(null, value, isNumber: true);
        public static implicit operator Parameter(int value) => new(null, value, isNumber: true);
        public static implicit operator Parameter(Guid value) => value.ToString();
        public static implicit operator Parameter(DateTimeOffset value) => value.ToString("O");
    }

    /// <summary>生成 <paramref name="count"/> 个 <c>?</c> 占位符，供 IN 子句按参数绑定标识集合。</summary>
    private static string Placeholders(int count) => string.Join(',', Enumerable.Repeat("?", count));

    /// <summary>
    /// 预编译并绑定参数，返回语句句柄；调用方负责在 finally 中 finalize。
    /// 用于返回结果集的查询，语句用完即弃。
    /// </summary>
    private IntPtr Prepare(string sql, string failureMessage, params ReadOnlySpan<Parameter> parameters)
    {
        var result = Native.sqlite3_prepare_v2(_database, Utf8(sql), -1, out var statement, IntPtr.Zero);
        if (result != SqliteOk) throw CreateException(failureMessage, result);
        try
        {
            for (var i = 0; i < parameters.Length; i++) parameters[i].Bind(statement, i + 1);
        }
        catch
        {
            Native.sqlite3_finalize(statement);
            throw;
        }
        return statement;
    }

    /// <summary>执行一条带参数的写语句，语句用完即弃。适用于低频的删除与治理操作。</summary>
    private void Write(string sql, string failureMessage, params ReadOnlySpan<Parameter> parameters)
    {
        lock (_gate)
        {
            EnsureOpen();
            var statement = Prepare(sql, failureMessage, parameters);
            try
            {
                var result = Native.sqlite3_step(statement);
                if (result != SqliteDone) throw CreateException(failureMessage, result);
            }
            finally { Native.sqlite3_finalize(statement); }
        }
    }

    /// <summary>
    /// 用缓存的预编译语句执行一条写语句。只允许传入 SQL 文本恒定的热路径写入
    /// （事务入库、会话 upsert、Hook 批量插入），缓存因此有固定上界。
    /// </summary>
    private void WriteCached(string sql, string failureMessage, params ReadOnlySpan<Parameter> parameters)
    {
        lock (_gate)
        {
            EnsureOpen();
            var statement = GetCachedStatement(sql);
            try
            {
                for (var i = 0; i < parameters.Length; i++) parameters[i].Bind(statement, i + 1);
                var result = Native.sqlite3_step(statement);
                if (result != SqliteDone) throw CreateException(failureMessage, result);
            }
            finally
            {
                // reset 释放语句持有的锁与游标，clear_bindings 避免上一轮的值残留到下一轮。
                Native.sqlite3_reset(statement);
                Native.sqlite3_clear_bindings(statement);
            }
        }
    }

    /// <summary>取得（并缓存）预编译语句；调用方必须持有 <see cref="_gate"/>。</summary>
    private IntPtr GetCachedStatement(string sql)
    {
        if (_statements.TryGetValue(sql, out var cached)) return cached;
        var result = Native.sqlite3_prepare_v2(_database, Utf8(sql), -1, out var statement, IntPtr.Zero);
        if (result != SqliteOk) throw CreateException("无法预编译语句", result);
        _statements[sql] = statement;
        return statement;
    }

    /// <summary>在 BEGIN IMMEDIATE / COMMIT 之间执行 <paramref name="body"/>，异常时回滚。</summary>
    private void InTransaction(Action body)
    {
        // _gate 是可重入的：整段事务必须在同一把锁内完成，否则其他线程可能在
        // BEGIN 与 COMMIT 之间插入语句，破坏原本单条 exec 提供的原子性。
        lock (_gate)
        {
            EnsureOpen();
            Execute("BEGIN IMMEDIATE;");
            try
            {
                body();
            }
            catch
            {
                try { Execute("ROLLBACK;"); }
                catch { /* 回滚失败时保留原始异常，避免掩盖真正的错误 */ }
                throw;
            }
            Execute("COMMIT;");
        }
    }

    /// <summary>
    /// 执行不带参数的 DDL、PRAGMA 与事务控制语句。
    /// 严禁把任何外部数据拼进 <paramref name="sql"/>——带值的语句一律走 <see cref="Write"/>／
    /// <see cref="WriteCached"/>／<see cref="Prepare"/> 的参数绑定路径。
    /// </summary>
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

    /// <summary>
    /// 按列的实际字节长度读取文本。不能用 <c>Marshal.PtrToStringUTF8</c>：它在首个 NUL 处截断，
    /// 而抓包证据（URL、Header、Cookie、正文摘要）可能合法地携带 NUL 等控制字符。
    /// 必须先取指针再取长度，这是 SQLite 文档要求的调用顺序。
    /// </summary>
    private static string Text(IntPtr statement, int column)
    {
        var pointer = Native.sqlite3_column_text(statement, column);
        if (pointer == IntPtr.Zero) return string.Empty;
        var length = Native.sqlite3_column_bytes(statement, column);
        if (length <= 0) return string.Empty;
        var buffer = new byte[length];
        Marshal.Copy(pointer, buffer, 0, length);
        return Encoding.UTF8.GetString(buffer);
    }

    /// <summary>
    /// 仅用于 SQL 文本与文件名的 NUL 结尾 UTF-8 编码。参数值一律经 <see cref="Parameter"/> 绑定，
    /// 绝不拼进 SQL 文本，因此这里的输入永远是本仓库自己生成的常量或占位符串。
    /// </summary>
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
            // 必须先 finalize 全部缓存语句：仍有未释放语句时 sqlite3_close_v2 只会把连接标记为
            // 僵尸连接并延迟关闭，数据库文件与 WAL 不会立即释放。
            foreach (var statement in _statements.Values) Native.sqlite3_finalize(statement);
            _statements.Clear();
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
        internal static extern int sqlite3_reset(IntPtr statement);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int sqlite3_clear_bindings(IntPtr statement);

        // 第 4 参数是字节数而非字符数，传入 -1 会让 SQLite 在首个 NUL 处截断；本仓库一律传显式长度。
        // 第 5 参数为析构器：SQLITE_TRANSIENT((void*)-1) 要求 SQLite 在返回前自行复制缓冲区，
        // 因为托管 byte[] 只在本次 P/Invoke 期间被固定。
        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int sqlite3_bind_text(IntPtr statement, int index, byte[] value, int bytes, IntPtr destructor);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int sqlite3_bind_int64(IntPtr statement, int index, long value);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int sqlite3_bind_null(IntPtr statement, int index);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int sqlite3_column_int(IntPtr statement, int column);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern long sqlite3_column_int64(IntPtr statement, int column);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr sqlite3_column_text(IntPtr statement, int column);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int sqlite3_column_bytes(IntPtr statement, int column);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr sqlite3_errmsg(IntPtr database);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern void sqlite3_free(IntPtr pointer);
    }
}
