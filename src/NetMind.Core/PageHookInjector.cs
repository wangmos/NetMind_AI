using System.Net;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;

namespace NetMind.Core;

/// <summary>页内 Hook 事件：采集浏览器注入脚本捕获的一次页面调用（XHR/fetch/加密/编码/存储）。</summary>
public sealed record PageHookEvent(
    long Id,
    Guid SessionId,
    DateTimeOffset Timestamp,
    string Type,
    string Function,
    string PageUrl,
    string ArgsJson,
    string TargetUrl = "",
    string Stack = "");

/// <summary>持续页内 Hook 挂载的一次状态快照。</summary>
public sealed record PageHookMonitorStatus(
    bool BrowserReachable,
    int ActiveTargetCount,
    int InjectedTargetCount,
    int NewlyInjectedCount,
    int FailedTargetCount,
    int WorkerTargetCount = 0,
    int InjectedWorkerTargetCount = 0,
    string WorkerMonitorError = "");

/// <summary>
/// 注入采集浏览器的页内 Hook 脚本：包裹 XHR/fetch/加密/编码/存储五类调用，
/// 每次调用记录 {ts, type, fn, url?, args(截断 8 KB), stack(首帧)}，
/// 500 ms 批量 POST 到本机接收端点（loopback 在代理绕过名单内，直连不经过代理）。
/// </summary>
public static class PageHookScript
{
    private const string HookPortPlaceholder = "__NETMIND_HOOK_PORT__";
    private const string HookTokenPlaceholder = "__NETMIND_HOOK_TOKEN__";

    /// <summary>生成绑定接收端口的完整脚本；脚本内只使用单引号，避免与 C# 字符串转义冲突。</summary>
    public static string Build(int hookPort, string? hookToken = null) => Script
        .Replace(HookPortPlaceholder, hookPort.ToString(), StringComparison.Ordinal)
        .Replace(HookTokenPlaceholder,
            string.IsNullOrWhiteSpace(hookToken) ? string.Empty : Uri.EscapeDataString(hookToken.Trim()) + "/",
            StringComparison.Ordinal);

    private const string Script = """
        (function () {
          var NEXT_ENDPOINT = 'http://127.0.0.1:__NETMIND_HOOK_PORT__/hooks/__NETMIND_HOOK_TOKEN__';
          var ROOT = typeof globalThis !== 'undefined' ? globalThis : self;
          var CONTEXT = (typeof Window !== 'undefined' && ROOT instanceof Window) ? 'page' :
                        ((typeof ServiceWorkerGlobalScope !== 'undefined' && ROOT instanceof ServiceWorkerGlobalScope) ? 'service_worker' : 'worker');
          var existingControl = ROOT.__netmindPageHookControl;
          if (existingControl && typeof existingControl.updateEndpoint === 'function') {
            existingControl.updateEndpoint(NEXT_ENDPOINT);
            return;
          }
          if (ROOT.__netmindPageHookInstalled) return;
          ROOT.__netmindPageHookInstalled = true;
          var ENDPOINT = NEXT_ENDPOINT;
          var pending = [];
          var MAX_PENDING = 1000;
          var MAX_BATCH = 6;

          function toText(value) {
            if (typeof value === 'string') return value;
            if (value === undefined || value === null) return '';
            try { return JSON.stringify(value); } catch (e) { return String(value); }
          }

          function truncate(value) {
            var text = toText(value);
            if (text.length > 8192) text = text.slice(0, 8192);
            return text;
          }

          function binaryPreview(value) {
            try {
              var bytes = null;
              if (value instanceof ArrayBuffer) bytes = new Uint8Array(value);
              else if (ArrayBuffer.isView(value)) bytes = new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
              if (!bytes) return { dataBytes: toText(value).length, dataHex: '', dataTruncated: false };
              var limit = Math.min(bytes.byteLength, 512);
              var parts = [];
              for (var i = 0; i < limit; i++) parts.push(bytes[i].toString(16).padStart(2, '0'));
              return { dataBytes: bytes.byteLength, dataHex: parts.join(''), dataTruncated: bytes.byteLength > limit };
            } catch (e) { return { dataBytes: 0, dataHex: '', dataTruncated: false }; }
          }

          function firstFrame() {
            try {
              var lines = (new Error()).stack.split('\n');
              for (var i = 1; i < lines.length; i++) {
                var line = lines[i] || '';
                if (line.indexOf('firstFrame') < 0 && line.indexOf('recordHook') < 0) return line.trim().slice(0, 512);
              }
            } catch (e) { }
            return '';
          }

          function recordHook(type, fn, url, args) {
            try {
              if (pending.length >= MAX_PENDING) pending.shift();
              pending.push({
                ts: Date.now(),
                type: type,
                fn: fn,
                url: url || '',
                pageUrl: ROOT.location && ROOT.location.href ? ROOT.location.href : '',
                args: truncate(args),
                stack: firstFrame()
              });
              if (pending.length >= 48) flush();
            } catch (e) { }
          }

          function flush() {
            if (pending.length === 0) return;
            while (pending.length > 0) {
              var batch = pending.splice(0, MAX_BATCH);
              try {
                // text/plain + no-cors 避免 application/json 触发跨源预检；接收端仍按 JSON 解析正文。
                fetch(ENDPOINT, {
                  method: 'POST',
                  mode: 'no-cors',
                  headers: { 'Content-Type': 'text/plain' },
                  body: JSON.stringify(batch)
                }).catch(function () { });
              } catch (e) { }
            }
          }
          setInterval(flush, 500);

          // ① XMLHttpRequest.open/send
          if (typeof ROOT.XMLHttpRequest === 'function' && ROOT.XMLHttpRequest.prototype) {
            var xhrOpen = ROOT.XMLHttpRequest.prototype.open;
            var xhrSend = ROOT.XMLHttpRequest.prototype.send;
            var xhrSetRequestHeader = ROOT.XMLHttpRequest.prototype.setRequestHeader;
            ROOT.XMLHttpRequest.prototype.open = function (method, url) {
              try { this.__netmindHook = { method: String(method || ''), url: String(url || ''), headers: {} }; } catch (e) { }
              return xhrOpen.apply(this, arguments);
            };
            ROOT.XMLHttpRequest.prototype.setRequestHeader = function (name, value) {
              try {
                var meta = this.__netmindHook || (this.__netmindHook = { method: '', url: '', headers: {} });
                meta.headers[String(name || '')] = String(value || '');
              } catch (e) { }
              return xhrSetRequestHeader.apply(this, arguments);
            };
            ROOT.XMLHttpRequest.prototype.send = function (body) {
              var meta = this.__netmindHook || { method: '', url: '', headers: {} };
              recordHook('xhr', 'XMLHttpRequest.send', meta.url, { method: meta.method, headers: meta.headers || {}, body: body === undefined ? '' : toText(body) });
              return xhrSend.apply(this, arguments);
            };
          }

          // ② fetch（跳过上报自身，避免递归记录）
          var nativeFetch = ROOT.fetch;
          if (typeof nativeFetch === 'function') {
            ROOT.fetch = function (input, init) {
              try {
                var url = typeof input === 'string' ? input : (input && input.url) || '';
                if (String(url).indexOf(ENDPOINT) !== 0)
                  recordHook('fetch', 'fetch', String(url), {
                    method: (init && init.method) || (input && input.method) || 'GET',
                    headers: (init && init.headers) || (input && input.headers) || {},
                    body: init && init.body !== undefined ? init.body : ''
                  });
              } catch (e) { }
              return nativeFetch.apply(ROOT, arguments);
            };
          }

          // ③ crypto.subtle 加密/解密/摘要/签名/验签
          if (ROOT.crypto && ROOT.crypto.subtle) {
            var subtle = ROOT.crypto.subtle;
            ['encrypt', 'decrypt', 'digest', 'sign', 'verify'].forEach(function (name) {
              var original = subtle[name];
              if (typeof original !== 'function') return;
              subtle[name] = function () {
                try {
                  var algorithm = arguments[0];
                  var algoName = algorithm && algorithm.name ? algorithm.name : toText(algorithm);
                  var dataIndex = name === 'digest' ? 1 : (name === 'verify' ? 3 : 2);
                  var data = arguments[dataIndex];
                  var preview = binaryPreview(data);
                  recordHook('crypto', 'crypto.subtle.' + name, '', {
                    algorithm: algoName,
                    dataBytes: preview.dataBytes,
                    dataHex: preview.dataHex,
                    dataTruncated: preview.dataTruncated
                  });
                } catch (e) { }
                return original.apply(subtle, arguments);
              };
            });
          }

          // ④ Base64 编解码
          var nativeBtoa = ROOT.btoa;
          if (typeof nativeBtoa === 'function') {
            ROOT.btoa = function (input) { recordHook('encode', 'btoa', '', input); return nativeBtoa.apply(ROOT, arguments); };
          }
          var nativeAtob = ROOT.atob;
          if (typeof nativeAtob === 'function') {
            ROOT.atob = function (input) { recordHook('encode', 'atob', '', input); return nativeAtob.apply(ROOT, arguments); };
          }

          // ⑤ localStorage/sessionStorage.setItem（Storage 是 WebIDL 对象，应包裹原型方法而不是给实例赋值）
          if (ROOT.Storage && ROOT.Storage.prototype && typeof ROOT.Storage.prototype.setItem === 'function') {
            var nativeStorageSetItem = ROOT.Storage.prototype.setItem;
            ROOT.Storage.prototype.setItem = function (key, value) {
              var label = 'storage.setItem';
              try { label = this === ROOT.localStorage ? 'localStorage.setItem' : (this === ROOT.sessionStorage ? 'sessionStorage.setItem' : label); } catch (e) { }
              recordHook('storage', label, '', { key: toText(key), value: toText(value) });
              return nativeStorageSetItem.apply(this, arguments);
            };
          }

          // 安装握手：即使页面尚未调用 XHR/加密函数，也立即产生一条可见事件，
          // 用于区分“页面没有触发目标 API”和“注入成功但上报通道已断”。
          // 停止/重新开始采集时接收端口和令牌会轮换；保留已包装函数，只热更新上报地址，
          // 避免重复包装产生双份事件，也避免已打开标签页继续向失效端口发送。
          ROOT.__netmindPageHookControl = {
            version: 3,
            updateEndpoint: function (nextEndpoint) {
              var changed = ENDPOINT !== nextEndpoint;
              ENDPOINT = nextEndpoint;
              recordHook('lifecycle', 'hook.installed', '', { version: 3, context: CONTEXT, reattached: true, endpointChanged: changed });
              flush();
            }
          };
          recordHook('lifecycle', 'hook.installed', '', { version: 3, context: CONTEXT });
          flush();
        })();
        """;
}

/// <summary>
/// 页内 Hook 注入器：轮询浏览器调试端口的 /json/list。page/webview 目标通过
/// Page.addScriptToEvaluateOnNewDocument + Runtime.evaluate 挂载；worker/shared_worker/service_worker
/// 目标不支持 Page 域，直接通过 Runtime.evaluate 挂载并在目标重建后重新发现。
/// 浏览器级 /json/version WebSocket 不支持 Page 域，不能用作页面脚本注入目标。
/// </summary>
public static class PageHookInjector
{
    private static readonly JsonSerializerOptions CdpJsonOptions = new()
    {
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    public static Task<bool> InjectAsync(int debuggingPort, int hookPort, TimeSpan timeout,
        CancellationToken cancellationToken = default) =>
        InjectAsync(debuggingPort, hookPort, string.Empty, timeout, cancellationToken, null);

    /// <summary>尝试注入；至少一个页面目标明确返回成功才返回 true，协议 error 不再误报为已注入。</summary>
    public static async Task<bool> InjectAsync(int debuggingPort, int hookPort, string hookToken, TimeSpan timeout,
        CancellationToken cancellationToken = default, BrowserEnvironmentProfile? environmentProfile = null)
    {
        if (debuggingPort <= 0 || hookPort <= 0) return false;
        var targets = await TryGetHookTargetsAsync(debuggingPort, timeout, cancellationToken);
        if (targets.Count == 0) return false;
        var source = PageHookScript.Build(hookPort, hookToken);
        var injected = false;
        foreach (var target in targets.Take(16))
        {
            if (await InjectTargetAsync(target, source, environmentProfile, cancellationToken)) injected = true;
        }
        return injected;
    }

    /// <summary>
    /// 持续发现采集浏览器中新出现的页面与 Worker target，并仅对尚未成功挂载的 target 注入。
    /// 页面内导航由 addScript 自然覆盖；标签页关闭后从集合移除，避免长会话状态无限增长。
    /// </summary>
    public static async Task MonitorAsync(int debuggingPort, int hookPort, string hookToken,
        Func<PageHookMonitorStatus, Task>? onStatus = null, TimeSpan? pollInterval = null,
        CancellationToken cancellationToken = default, BrowserEnvironmentProfile? environmentProfile = null)
    {
        if (debuggingPort <= 0 || hookPort <= 0) return;
        var source = PageHookScript.Build(hookPort, hookToken);
        var connections = new Dictionary<string, TargetConnection>(StringComparer.Ordinal);
        var reportedInjectedTargets = new HashSet<string>(StringComparer.Ordinal);
        BrowserWorkerConnection? workerConnection = null;
        var interval = pollInterval.GetValueOrDefault(TimeSpan.FromSeconds(1));
        if (interval < TimeSpan.FromMilliseconds(250)) interval = TimeSpan.FromMilliseconds(250);

        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                if (workerConnection is null || workerConnection.RunTask.IsCompleted)
                {
                    if (workerConnection is not null) await workerConnection.DisposeAsync();
                    workerConnection = new BrowserWorkerConnection(debuggingPort, source, cancellationToken);
                }
                var discovered = await TryGetHookTargetsAsync(debuggingPort, TimeSpan.FromSeconds(2), cancellationToken);
                var activeTargets = discovered.Take(64).ToDictionary(target => target.WebSocketUrl, StringComparer.Ordinal);
                foreach (var stale in connections.Keys.Where(target => !activeTargets.ContainsKey(target)).ToArray())
                {
                    await connections[stale].DisposeAsync();
                    connections.Remove(stale);
                    reportedInjectedTargets.Remove(stale);
                }
                foreach (var (targetUrl, target) in activeTargets)
                {
                    if (connections.TryGetValue(targetUrl, out var existing) && !existing.RunTask.IsCompleted) continue;
                    if (existing is not null) await existing.DisposeAsync();
                    connections[targetUrl] = new TargetConnection(target, source, environmentProfile, cancellationToken);
                }
                var injectedTargets = connections
                    .Where(pair => activeTargets.ContainsKey(pair.Key) && pair.Value.Injected)
                    .Select(pair => pair.Key)
                    .ToHashSet(StringComparer.Ordinal);
                reportedInjectedTargets.RemoveWhere(target => !injectedTargets.Contains(target));
                var newlyInjected = injectedTargets.Count(target => reportedInjectedTargets.Add(target)) +
                                    workerConnection.ConsumeNewlyInjectedCount() +
                                    connections.Values.Sum(connection => connection.ConsumeNewlyInjectedWorkerCount());
                var workerTargets = workerConnection.ActiveTargetCount +
                                    connections.Values.Sum(connection => connection.ActiveWorkerCount);
                var injectedWorkers = workerConnection.InjectedTargetCount +
                                      connections.Values.Sum(connection => connection.InjectedWorkerCount);
                var activeCount = activeTargets.Count + workerTargets;
                var injectedCount = injectedTargets.Count + injectedWorkers;
                var failed = activeCount - injectedCount;
                var workerErrors = connections.Values.Select(connection => connection.WorkerError)
                    .Where(error => !string.IsNullOrWhiteSpace(error)).Take(2).ToList();
                if (!string.IsNullOrWhiteSpace(workerConnection.LastError)) workerErrors.Insert(0, workerConnection.LastError);
                if (onStatus is not null)
                    await onStatus(new PageHookMonitorStatus(activeTargets.Count > 0 || workerConnection.BrowserReachable,
                        activeCount, injectedCount, newlyInjected, failed, workerTargets, injectedWorkers,
                        string.Join(" | ", workerErrors)));
                await Task.Delay(interval, cancellationToken);
            }
        }
        finally
        {
            foreach (var connection in connections.Values) await connection.DisposeAsync();
            if (workerConnection is not null) await workerConnection.DisposeAsync();
        }
    }

    /// <summary>
    /// 持有一个页面目标的 CDP WebSocket。Page.addScriptToEvaluateOnNewDocument 的注册与调试会话同寿命；
    /// 若注入后立即断开，同一标签页导航时可能只留下 about:blank 的安装握手而丢失真实页面调用。
    /// </summary>
    private sealed class TargetConnection : IAsyncDisposable
    {
        private readonly CancellationTokenSource _cancellation;
        private int _injected;
        private int _activeWorkerCount;
        private int _injectedWorkerCount;
        private int _newlyInjectedWorkerCount;
        private string _workerError = string.Empty;

        public TargetConnection(HookTarget target, string source, BrowserEnvironmentProfile? environmentProfile,
            CancellationToken ownerCancellation)
        {
            _cancellation = CancellationTokenSource.CreateLinkedTokenSource(ownerCancellation);
            RunTask = MaintainTargetAsync(target, source, environmentProfile, _cancellation.Token);
        }

        public bool Injected => Volatile.Read(ref _injected) != 0;
        public int ActiveWorkerCount => Volatile.Read(ref _activeWorkerCount);
        public int InjectedWorkerCount => Volatile.Read(ref _injectedWorkerCount);
        public string WorkerError => Volatile.Read(ref _workerError);
        public Task RunTask { get; }
        public int ConsumeNewlyInjectedWorkerCount() => Interlocked.Exchange(ref _newlyInjectedWorkerCount, 0);

        public async ValueTask DisposeAsync()
        {
            _cancellation.Cancel();
            try { await RunTask.WaitAsync(TimeSpan.FromSeconds(1)); } catch { /* 目标关闭或取消是正常收尾 */ }
            _cancellation.Dispose();
        }

        private async Task MaintainTargetAsync(HookTarget target, string source,
            BrowserEnvironmentProfile? environmentProfile, CancellationToken cancellationToken)
        {
            try
            {
                using var socket = new ClientWebSocket();
                await socket.ConnectAsync(new Uri(target.WebSocketUrl), cancellationToken);
                var commandId = 0;
                if (!target.IsWorker)
                {
                    var profile = (environmentProfile ?? new BrowserEnvironmentProfile()).Validate();
                    if (profile.Enabled)
                        commandId = await ApplyEnvironmentProfileAsync(socket, profile, commandId, cancellationToken);
                    var enablePage = JsonSerializer.Serialize(new { id = ++commandId, method = "Page.enable" }, CdpJsonOptions);
                    await SendTextAsync(socket, enablePage, cancellationToken);
                    if (!await ReadSuccessfulResponseAsync(socket, commandId, cancellationToken)) return;
                    var addScript = JsonSerializer.Serialize(new
                    {
                        id = ++commandId,
                        method = "Page.addScriptToEvaluateOnNewDocument",
                        @params = new { source }
                    }, CdpJsonOptions);
                    await SendTextAsync(socket, addScript, cancellationToken);
                    if (!await ReadSuccessfulResponseAsync(socket, commandId, cancellationToken)) return;
                }
                else
                {
                    var enableRuntime = JsonSerializer.Serialize(new { id = ++commandId, method = "Runtime.enable" }, CdpJsonOptions);
                    await SendTextAsync(socket, enableRuntime, cancellationToken);
                    if (!await ReadSuccessfulResponseAsync(socket, commandId, cancellationToken)) return;
                }

                var evaluate = JsonSerializer.Serialize(new
                {
                    id = ++commandId,
                    method = "Runtime.evaluate",
                    @params = new { expression = source, returnByValue = false }
                }, CdpJsonOptions);
                await SendTextAsync(socket, evaluate, cancellationToken);
                if (!await ReadSuccessfulResponseAsync(socket, commandId, cancellationToken)) return;
                Volatile.Write(ref _injected, 1);

                // Dedicated/Shared Worker 是页面的直接子目标。从页面会话自动挂载，能避免浏览器级手工 attach
                // 在 Worker URL 尚未就绪时产生永不返回的 Runtime 命令。
                if (!target.IsWorker)
                {
                    var autoAttach = JsonSerializer.Serialize(new
                    {
                        id = ++commandId,
                        method = "Target.setAutoAttach",
                        @params = new
                        {
                            autoAttach = true,
                            waitForDebuggerOnStart = true,
                            flatten = true,
                            filter = new object[]
                            {
                                new { type = "worker", exclude = false },
                                new { type = "shared_worker", exclude = false },
                                new { exclude = true }
                            }
                        }
                    }, CdpJsonOptions);
                    await SendTextAsync(socket, autoAttach, cancellationToken);
                    if (!await ReadSuccessfulResponseAsync(socket, commandId, cancellationToken))
                    {
                        // 旧版 Chromium 不支持 TargetFilter 时回退到全部直接子目标。
                        var fallbackAttach = JsonSerializer.Serialize(new
                        {
                            id = ++commandId,
                            method = "Target.setAutoAttach",
                            @params = new { autoAttach = true, waitForDebuggerOnStart = true, flatten = true }
                        }, CdpJsonOptions);
                        await SendTextAsync(socket, fallbackAttach, cancellationToken);
                        _ = await ReadSuccessfulResponseAsync(socket, commandId, cancellationToken);
                    }
                }

                var activeWorkers = new HashSet<string>(StringComparer.Ordinal);
                var injectedWorkers = new HashSet<string>(StringComparer.Ordinal);
                var pendingEnables = new Dictionary<int, string>();
                var pendingEvaluations = new Dictionary<int, string>();
                while (socket.State == WebSocketState.Open && !cancellationToken.IsCancellationRequested)
                {
                    var payload = await ReceiveTextAsync(socket, cancellationToken);
                    if (payload is null) return;
                    using var document = JsonDocument.Parse(payload);
                    var root = document.RootElement;

                    if (root.TryGetProperty("id", out var responseIdElement) && responseIdElement.TryGetInt32(out var responseId))
                    {
                        if (pendingEnables.Remove(responseId, out var enabledSession))
                        {
                            if (!root.TryGetProperty("error", out _) && activeWorkers.Contains(enabledSession))
                            {
                                var evaluationId = ++commandId;
                                pendingEvaluations[evaluationId] = enabledSession;
                                var workerEvaluate = JsonSerializer.Serialize(new
                                {
                                    id = evaluationId,
                                    method = "Runtime.evaluate",
                                    @params = new { expression = source, returnByValue = false },
                                    sessionId = enabledSession
                                }, CdpJsonOptions);
                                await SendTextAsync(socket, workerEvaluate, cancellationToken);
                            }
                            else if (root.TryGetProperty("error", out _))
                                Volatile.Write(ref _workerError, "Worker Runtime.enable 失败：" + root.GetRawText());
                        }
                        if (pendingEvaluations.Remove(responseId, out var evaluatedSession))
                        {
                            var succeeded = !root.TryGetProperty("error", out _) &&
                                            !(root.TryGetProperty("result", out var result) && result.ValueKind == JsonValueKind.Object &&
                                              result.TryGetProperty("exceptionDetails", out _));
                            if (succeeded && activeWorkers.Contains(evaluatedSession) && injectedWorkers.Add(evaluatedSession))
                            {
                                Interlocked.Increment(ref _newlyInjectedWorkerCount);
                                Volatile.Write(ref _injectedWorkerCount, injectedWorkers.Count);
                            }
                            else if (!succeeded)
                                Volatile.Write(ref _workerError, "Worker Runtime.evaluate 失败：" + root.GetRawText());
                        }
                        continue;
                    }

                    if (!root.TryGetProperty("method", out var methodElement) || methodElement.ValueKind != JsonValueKind.String ||
                        !root.TryGetProperty("params", out var parameters) || parameters.ValueKind != JsonValueKind.Object)
                        continue;
                    var method = methodElement.GetString();
                    if (method == "Target.attachedToTarget" &&
                        parameters.TryGetProperty("sessionId", out var sessionElement) && sessionElement.ValueKind == JsonValueKind.String &&
                        parameters.TryGetProperty("targetInfo", out var targetInfo) && targetInfo.ValueKind == JsonValueKind.Object)
                    {
                        var sessionId = sessionElement.GetString()!;
                        var targetType = targetInfo.TryGetProperty("type", out var typeElement) ? typeElement.GetString() : null;
                        if (targetType is not ("worker" or "shared_worker"))
                        {
                            var resumeOther = JsonSerializer.Serialize(new
                            {
                                id = ++commandId,
                                method = "Runtime.runIfWaitingForDebugger",
                                sessionId
                            }, CdpJsonOptions);
                            await SendTextAsync(socket, resumeOther, cancellationToken);
                            var detachOther = JsonSerializer.Serialize(new
                            {
                                id = ++commandId,
                                method = "Target.detachFromTarget",
                                @params = new { sessionId }
                            }, CdpJsonOptions);
                            await SendTextAsync(socket, detachOther, cancellationToken);
                            continue;
                        }
                        if (activeWorkers.Add(sessionId)) Volatile.Write(ref _activeWorkerCount, activeWorkers.Count);
                        var resume = JsonSerializer.Serialize(new
                        {
                            id = ++commandId,
                            method = "Runtime.runIfWaitingForDebugger",
                            sessionId
                        }, CdpJsonOptions);
                        await SendTextAsync(socket, resume, cancellationToken);
                        var enableId = ++commandId;
                        pendingEnables[enableId] = sessionId;
                        var enable = JsonSerializer.Serialize(new { id = enableId, method = "Runtime.enable", sessionId }, CdpJsonOptions);
                        await SendTextAsync(socket, enable, cancellationToken);
                        continue;
                    }
                    if (method == "Target.detachedFromTarget" &&
                        parameters.TryGetProperty("sessionId", out var detachedElement) && detachedElement.ValueKind == JsonValueKind.String)
                    {
                        var sessionId = detachedElement.GetString()!;
                        activeWorkers.Remove(sessionId);
                        injectedWorkers.Remove(sessionId);
                        foreach (var pending in pendingEnables.Where(pair => pair.Value == sessionId).Select(pair => pair.Key).ToArray())
                            pendingEnables.Remove(pending);
                        foreach (var pending in pendingEvaluations.Where(pair => pair.Value == sessionId).Select(pair => pair.Key).ToArray())
                            pendingEvaluations.Remove(pending);
                        Volatile.Write(ref _activeWorkerCount, activeWorkers.Count);
                        Volatile.Write(ref _injectedWorkerCount, injectedWorkers.Count);
                    }
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
            catch (Exception exception)
            {
                // 标签页关闭、浏览器重启或调试连接瞬断：MonitorAsync 下一轮创建新连接。
                Volatile.Write(ref _workerError, exception.GetType().Name + "：" + exception.Message);
            }
            finally
            {
                Volatile.Write(ref _activeWorkerCount, 0);
                Volatile.Write(ref _injectedWorkerCount, 0);
            }
        }
    }

    private static async Task<bool> InjectTargetAsync(HookTarget target, string source, BrowserEnvironmentProfile? environmentProfile,
        CancellationToken cancellationToken)
    {
        try
        {
            using var socket = new ClientWebSocket();
            await socket.ConnectAsync(new Uri(target.WebSocketUrl), cancellationToken);
            var commandId = 0;
            if (!target.IsWorker)
            {
                var profile = (environmentProfile ?? new BrowserEnvironmentProfile()).Validate();
                if (profile.Enabled)
                    commandId = await ApplyEnvironmentProfileAsync(socket, profile, commandId, cancellationToken);
                var enablePage = JsonSerializer.Serialize(new { id = ++commandId, method = "Page.enable" }, CdpJsonOptions);
                await socket.SendAsync(Encoding.UTF8.GetBytes(enablePage), WebSocketMessageType.Text, true, cancellationToken);
                if (!await ReadSuccessfulResponseAsync(socket, commandId, cancellationToken)) return false;
                var addScript = JsonSerializer.Serialize(new
                {
                    id = ++commandId,
                    method = "Page.addScriptToEvaluateOnNewDocument",
                    @params = new { source }
                }, CdpJsonOptions);
                await socket.SendAsync(Encoding.UTF8.GetBytes(addScript), WebSocketMessageType.Text, true, cancellationToken);
                if (!await ReadSuccessfulResponseAsync(socket, commandId, cancellationToken)) return false;
            }
            else
            {
                var enableRuntime = JsonSerializer.Serialize(new { id = ++commandId, method = "Runtime.enable" }, CdpJsonOptions);
                await socket.SendAsync(Encoding.UTF8.GetBytes(enableRuntime), WebSocketMessageType.Text, true, cancellationToken);
                if (!await ReadSuccessfulResponseAsync(socket, commandId, cancellationToken)) return false;
            }

            // addScript 只覆盖后续文档；对注入时已打开的页面立即执行一次，脚本内安装标记保证幂等。
            var evaluate = JsonSerializer.Serialize(new
            {
                id = ++commandId,
                method = "Runtime.evaluate",
                @params = new { expression = source, returnByValue = false }
            }, CdpJsonOptions);
            await socket.SendAsync(Encoding.UTF8.GetBytes(evaluate), WebSocketMessageType.Text, true, cancellationToken);
            return await ReadSuccessfulResponseAsync(socket, commandId, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch
        {
            // 标签页可能在发现后立即关闭；下一轮会继续发现和重试。
            return false;
        }
    }

    /// <summary>
    /// 在页面脚本执行前应用 CDP Emulation。实验性命令失败时继续挂载 Hook，避免浏览器版本差异破坏采集主链路。
    /// UA 覆盖同时携带 userAgentMetadata，确保 Sec-CH-UA-* 与 navigator.userAgentData 不和 UA 字符串冲突。
    /// </summary>
    private static async Task<int> ApplyEnvironmentProfileAsync(ClientWebSocket socket, BrowserEnvironmentProfile profile,
        int commandId, CancellationToken cancellationToken)
    {
        var commands = new List<(string Method, object Parameters)>
        {
            ("Emulation.setDeviceMetricsOverride", new
            {
                width = profile.ScreenWidth,
                height = profile.ScreenHeight,
                deviceScaleFactor = profile.DeviceScaleFactor,
                mobile = false,
                screenWidth = profile.ScreenWidth,
                screenHeight = profile.ScreenHeight
            }),
            ("Emulation.setTimezoneOverride", new { timezoneId = profile.TimezoneId }),
            ("Emulation.setLocaleOverride", new { locale = profile.Locale }),
            ("Emulation.setHardwareConcurrencyOverride", new { hardwareConcurrency = profile.HardwareConcurrency })
        };
        if (profile.UserAgent.Length > 0)
        {
            var version = ExtractChromiumVersion(profile.UserAgent);
            var major = version.Split('.', 2)[0];
            var brand = profile.UserAgent.Contains("Edg/", StringComparison.OrdinalIgnoreCase) ? "Microsoft Edge" : "Google Chrome";
            commands.Add(("Emulation.setUserAgentOverride", new
            {
                userAgent = profile.UserAgent,
                acceptLanguage = profile.AcceptLanguage,
                platform = profile.Platform,
                userAgentMetadata = new
                {
                    brands = new[]
                    {
                        new { brand = "Not_A Brand", version = "99" },
                        new { brand = "Chromium", version = major },
                        new { brand, version = major }
                    },
                    fullVersionList = new[]
                    {
                        new { brand = "Not_A Brand", version = "99.0.0.0" },
                        new { brand = "Chromium", version },
                        new { brand, version }
                    },
                    fullVersion = version,
                    platform = profile.CdpPlatformName,
                    platformVersion = profile.CdpPlatformName == "Windows" ? "10.0.0" : profile.CdpPlatformName == "macOS" ? "14.0.0" : "6.0.0",
                    architecture = "x86",
                    model = string.Empty,
                    mobile = false,
                    bitness = "64",
                    wow64 = false
                }
            }));
        }

        foreach (var (method, parameters) in commands)
        {
            var id = ++commandId;
            var payload = JsonSerializer.Serialize(new { id, method, @params = parameters }, CdpJsonOptions);
            await socket.SendAsync(Encoding.UTF8.GetBytes(payload), WebSocketMessageType.Text, true, cancellationToken);
            _ = await ReadSuccessfulResponseAsync(socket, id, cancellationToken); // best effort：旧 Chromium 可能不支持实验性命令。
        }
        return commandId;
    }

    private static string ExtractChromiumVersion(string userAgent)
    {
        foreach (var marker in new[] { "Edg/", "Chrome/", "Chromium/" })
        {
            var index = userAgent.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
            if (index < 0) continue;
            var start = index + marker.Length;
            var end = start;
            while (end < userAgent.Length && (char.IsDigit(userAgent[end]) || userAgent[end] == '.')) end++;
            var value = userAgent[start..end].Trim('.');
            if (value.Length > 0) return value.Split('.', StringSplitOptions.RemoveEmptyEntries) switch
            {
                [var a] => a + ".0.0.0",
                [var a, var b] => a + "." + b + ".0.0",
                [var a, var b, var c] => a + "." + b + "." + c + ".0",
                [var a, var b, var c, var d, ..] => a + "." + b + "." + c + "." + d,
                _ => "129.0.0.0"
            };
        }
        return "129.0.0.0";
    }

    private static async Task<bool> ReadSuccessfulResponseAsync(ClientWebSocket socket, int commandId,
        CancellationToken cancellationToken)
    {
        var buffer = new byte[8 * 1024];
        using var message = new MemoryStream();
        while (message.Length <= 256 * 1024)
        {
            var received = await socket.ReceiveAsync(new ArraySegment<byte>(buffer), cancellationToken);
            if (received.MessageType == WebSocketMessageType.Close) return false;
            await message.WriteAsync(buffer.AsMemory(0, received.Count), cancellationToken);
            if (!received.EndOfMessage) continue;
            try
            {
                using var document = JsonDocument.Parse(message.ToArray());
                var root = document.RootElement;
                if (root.TryGetProperty("id", out var id) && id.TryGetInt32(out var value) && value == commandId)
                    return !root.TryGetProperty("error", out _) &&
                           !(root.TryGetProperty("result", out var result) &&
                             result.ValueKind == JsonValueKind.Object && result.TryGetProperty("exceptionDetails", out _));
            }
            catch (JsonException) { return false; }
            message.SetLength(0); // 跳过在命令应答前到达的 CDP 事件帧。
            message.Position = 0;
        }
        return false;
    }

    /// <summary>
    /// 浏览器级扁平 CDP 会话。Dedicated Worker 通常不会出现在 /json/list，必须结合
    /// Target.setAutoAttach 与 Target.setDiscoverTargets 主动发现并接管；执行上下文创建后通过 Runtime.evaluate 挂载。
    /// </summary>
    private sealed class BrowserWorkerConnection : IAsyncDisposable
    {
        private readonly CancellationTokenSource _cancellation;
        private int _browserReachable;
        private int _activeTargetCount;
        private int _injectedTargetCount;
        private int _newlyInjectedCount;
        private string _lastError = string.Empty;

        public BrowserWorkerConnection(int debuggingPort, string source, CancellationToken ownerCancellation)
        {
            _cancellation = CancellationTokenSource.CreateLinkedTokenSource(ownerCancellation);
            RunTask = MaintainAsync(debuggingPort, source, _cancellation.Token);
        }

        public bool BrowserReachable => Volatile.Read(ref _browserReachable) != 0;
        public int ActiveTargetCount => Volatile.Read(ref _activeTargetCount);
        public int InjectedTargetCount => Volatile.Read(ref _injectedTargetCount);
        public string LastError => Volatile.Read(ref _lastError);
        public Task RunTask { get; }
        public int ConsumeNewlyInjectedCount() => Interlocked.Exchange(ref _newlyInjectedCount, 0);

        public async ValueTask DisposeAsync()
        {
            _cancellation.Cancel();
            try { await RunTask.WaitAsync(TimeSpan.FromSeconds(1)); } catch { /* 浏览器关闭或取消是正常收尾 */ }
            _cancellation.Dispose();
        }

        private async Task MaintainAsync(int debuggingPort, string source, CancellationToken cancellationToken)
        {
            try
            {
                var browserSocketUrl = await TryGetBrowserWebSocketUrlAsync(debuggingPort, TimeSpan.FromSeconds(2), cancellationToken);
                if (string.IsNullOrWhiteSpace(browserSocketUrl)) return;
                using var socket = new ClientWebSocket();
                await socket.ConnectAsync(new Uri(browserSocketUrl), cancellationToken);
                Volatile.Write(ref _browserReachable, 1);
                var commandId = 0;
                var autoAttachCommandId = ++commandId;
                var autoAttach = JsonSerializer.Serialize(new
                {
                    id = autoAttachCommandId,
                    method = "Target.setAutoAttach",
                    @params = new
                    {
                        autoAttach = true,
                        // Worker 在等待调试器时尚未创建默认执行上下文，Runtime.evaluate 会悬而不返；
                        // 先让上下文启动，再立即挂载。持续/重复调用可完整捕获，启动首条调用由网络流量兜底。
                        waitForDebuggerOnStart = false,
                        flatten = true,
                        filter = new object[]
                        {
                            new { type = "service_worker", exclude = false },
                            new { exclude = true }
                        }
                    }
                }, CdpJsonOptions);
                await SendTextAsync(socket, autoAttach, cancellationToken);
                var discover = JsonSerializer.Serialize(new
                {
                    id = ++commandId,
                    method = "Target.setDiscoverTargets",
                    @params = new { discover = true }
                }, CdpJsonOptions);
                await SendTextAsync(socket, discover, cancellationToken);

                var active = new HashSet<string>(StringComparer.Ordinal);
                var injected = new HashSet<string>(StringComparer.Ordinal);
                var awaitingExecutionContext = new HashSet<string>(StringComparer.Ordinal);
                var pendingRuntimeEnables = new Dictionary<int, string>();
                var pendingEvaluations = new Dictionary<int, string>();
                var pendingAttaches = new Dictionary<int, string>();
                var targetToSession = new Dictionary<string, string>(StringComparer.Ordinal);
                var targetUrls = new Dictionary<string, string>(StringComparer.Ordinal);
                var fallbackSent = false;

                while (socket.State == WebSocketState.Open && !cancellationToken.IsCancellationRequested)
                {
                    var payload = await ReceiveTextAsync(socket, cancellationToken);
                    if (payload is null) return;
                    using var document = JsonDocument.Parse(payload);
                    var root = document.RootElement;

                    if (root.TryGetProperty("id", out var responseIdElement) && responseIdElement.TryGetInt32(out var responseId))
                    {
                        if (responseId == autoAttachCommandId && root.TryGetProperty("error", out _) && !fallbackSent)
                        {
                            // 旧 Chromium 不支持 TargetFilter 时仅保留 discover + 显式 attach，避免接管普通页面目标。
                            fallbackSent = true;
                        }
                        if (pendingEvaluations.Remove(responseId, out var evaluatedSession))
                        {
                            var succeeded = !root.TryGetProperty("error", out _) &&
                                            !(root.TryGetProperty("result", out var result) &&
                                              result.ValueKind == JsonValueKind.Object && result.TryGetProperty("exceptionDetails", out _));
                            if (succeeded && active.Contains(evaluatedSession) && injected.Add(evaluatedSession))
                            {
                                Volatile.Write(ref _lastError, string.Empty);
                                Interlocked.Increment(ref _newlyInjectedCount);
                                PublishCounts(active.Count, injected.Count);
                            }
                            else if (!succeeded)
                            {
                                var detail = root.GetRawText();
                                if (detail.Length > 1000) detail = detail[..1000];
                                Volatile.Write(ref _lastError, "Worker Runtime.evaluate 失败：" + detail);
                            }
                        }
                        if (pendingRuntimeEnables.Remove(responseId, out var enabledSession))
                        {
                            if (!root.TryGetProperty("error", out _) && active.Contains(enabledSession) &&
                                !pendingEvaluations.ContainsValue(enabledSession) && !injected.Contains(enabledSession))
                            {
                                awaitingExecutionContext.Remove(enabledSession);
                                commandId = await BeginWorkerInjectionAsync(socket, source, enabledSession, commandId,
                                    pendingEvaluations, cancellationToken);
                            }
                            else if (root.TryGetProperty("error", out _))
                            {
                                awaitingExecutionContext.Remove(enabledSession);
                                var detail = root.GetRawText();
                                if (detail.Length > 1000) detail = detail[..1000];
                                Volatile.Write(ref _lastError, "Worker Runtime.enable 失败：" + detail);
                            }
                            // ServiceWorker 可能在命令往返期间轮换/合并 CDP 会话；已分离的旧会话属于正常竞态。
                        }
                        if (pendingAttaches.Remove(responseId, out var attachedTargetId) &&
                            !root.TryGetProperty("error", out _) &&
                            root.TryGetProperty("result", out var attachResult) && attachResult.ValueKind == JsonValueKind.Object &&
                            attachResult.TryGetProperty("sessionId", out var attachedSessionElement) && attachedSessionElement.ValueKind == JsonValueKind.String)
                        {
                            var attachedSession = attachedSessionElement.GetString()!;
                            if (targetToSession.TryGetValue(attachedTargetId, out var existingSession))
                            {
                                if (!string.Equals(existingSession, attachedSession, StringComparison.Ordinal))
                                    commandId = await ResumeAndDetachAsync(socket, attachedSession, commandId, cancellationToken);
                            }
                            else
                            {
                                targetToSession[attachedTargetId] = attachedSession;
                                if (active.Add(attachedSession)) PublishCounts(active.Count, injected.Count);
                                if (targetUrls.TryGetValue(attachedTargetId, out var attachedUrl) &&
                                    IsAllowedWorkerUrl(attachedUrl) && awaitingExecutionContext.Add(attachedSession))
                                {
                                    commandId = await StartWorkerRuntimeAsync(socket, attachedSession, commandId,
                                        pendingRuntimeEnables, cancellationToken);
                                }
                            }
                        }
                        continue;
                    }

                    if (!root.TryGetProperty("method", out var methodElement) || methodElement.ValueKind != JsonValueKind.String)
                        continue;
                    var method = methodElement.GetString();
                    if (!root.TryGetProperty("params", out var parameters) || parameters.ValueKind != JsonValueKind.Object)
                        continue;

                    if (method == "Target.attachedToTarget" &&
                        parameters.TryGetProperty("sessionId", out var sessionElement) && sessionElement.ValueKind == JsonValueKind.String &&
                        parameters.TryGetProperty("targetInfo", out var targetInfo) && targetInfo.ValueKind == JsonValueKind.Object)
                    {
                        var sessionId = sessionElement.GetString()!;
                        var targetType = targetInfo.TryGetProperty("type", out var typeElement) ? typeElement.GetString() : null;
                        var targetUrl = targetInfo.TryGetProperty("url", out var urlElement) ? urlElement.GetString() : null;
                        var targetId = targetInfo.TryGetProperty("targetId", out var targetIdElement) ? targetIdElement.GetString() : null;
                        if (string.IsNullOrWhiteSpace(targetUrl) && !string.IsNullOrWhiteSpace(targetId) &&
                            targetUrls.TryGetValue(targetId, out var knownUrl)) targetUrl = knownUrl;
                        if (!IsSupportedWorkerType(targetType) || (!string.IsNullOrWhiteSpace(targetUrl) && !IsAllowedWorkerUrl(targetUrl)))
                        {
                            commandId = await ResumeAndDetachAsync(socket, sessionId, commandId, cancellationToken);
                            continue;
                        }

                        if (!string.IsNullOrWhiteSpace(targetId)) targetToSession[targetId] = sessionId;
                        if (active.Add(sessionId)) PublishCounts(active.Count, injected.Count);
                        if (IsAllowedWorkerUrl(targetUrl) && awaitingExecutionContext.Add(sessionId))
                        {
                            commandId = await StartWorkerRuntimeAsync(socket, sessionId, commandId,
                                pendingRuntimeEnables, cancellationToken);
                        }
                        continue;
                    }

                    if (method == "Runtime.executionContextCreated" &&
                        root.TryGetProperty("sessionId", out var contextSessionElement) && contextSessionElement.ValueKind == JsonValueKind.String)
                    {
                        var sessionId = contextSessionElement.GetString()!;
                        if (active.Contains(sessionId) && awaitingExecutionContext.Remove(sessionId) &&
                            !pendingEvaluations.ContainsValue(sessionId) && !injected.Contains(sessionId))
                            commandId = await BeginWorkerInjectionAsync(socket, source, sessionId, commandId,
                                pendingEvaluations, cancellationToken);
                        continue;
                    }

                    if (method == "Target.targetInfoChanged" &&
                        parameters.TryGetProperty("targetInfo", out var changedInfo) && changedInfo.ValueKind == JsonValueKind.Object)
                    {
                        var targetType = changedInfo.TryGetProperty("type", out var typeElement) ? typeElement.GetString() : null;
                        var targetUrl = changedInfo.TryGetProperty("url", out var urlElement) ? urlElement.GetString() : null;
                        var targetId = changedInfo.TryGetProperty("targetId", out var targetIdElement) ? targetIdElement.GetString() : null;
                        if (IsSupportedWorkerType(targetType) && !string.IsNullOrWhiteSpace(targetId))
                        {
                            if (!string.IsNullOrWhiteSpace(targetUrl)) targetUrls[targetId] = targetUrl;
                            if (IsAllowedWorkerUrl(targetUrl))
                            {
                                if (targetToSession.TryGetValue(targetId, out var sessionId) && active.Contains(sessionId))
                                {
                                    if (awaitingExecutionContext.Add(sessionId) &&
                                        !pendingRuntimeEnables.ContainsValue(sessionId) &&
                                        !pendingEvaluations.ContainsValue(sessionId) && !injected.Contains(sessionId))
                                    {
                                        commandId = await StartWorkerRuntimeAsync(socket, sessionId, commandId,
                                            pendingRuntimeEnables, cancellationToken);
                                    }
                                }
                                else if (!pendingAttaches.ContainsValue(targetId))
                                {
                                    var attachId = ++commandId;
                                    pendingAttaches[attachId] = targetId;
                                    var attach = JsonSerializer.Serialize(new
                                    {
                                        id = attachId,
                                        method = "Target.attachToTarget",
                                        @params = new { targetId, flatten = true }
                                    }, CdpJsonOptions);
                                    await SendTextAsync(socket, attach, cancellationToken);
                                }
                            }
                        }
                        continue;
                    }

                    if (method == "Target.targetCreated" &&
                        parameters.TryGetProperty("targetInfo", out var createdInfo) && createdInfo.ValueKind == JsonValueKind.Object)
                    {
                        var targetType = createdInfo.TryGetProperty("type", out var typeElement) ? typeElement.GetString() : null;
                        var targetUrl = createdInfo.TryGetProperty("url", out var urlElement) ? urlElement.GetString() : null;
                        var targetId = createdInfo.TryGetProperty("targetId", out var targetIdElement) ? targetIdElement.GetString() : null;
                        if (IsSupportedWorkerType(targetType) && !string.IsNullOrWhiteSpace(targetId) && !string.IsNullOrWhiteSpace(targetUrl))
                            targetUrls[targetId] = targetUrl;
                        if (IsSupportedWorkerType(targetType) && IsAllowedWorkerUrl(targetUrl) &&
                            !string.IsNullOrWhiteSpace(targetId) && !targetToSession.ContainsKey(targetId) &&
                            !pendingAttaches.ContainsValue(targetId))
                        {
                            var attachId = ++commandId;
                            pendingAttaches[attachId] = targetId;
                            var attach = JsonSerializer.Serialize(new
                            {
                                id = attachId,
                                method = "Target.attachToTarget",
                                @params = new { targetId, flatten = true }
                            }, CdpJsonOptions);
                            await SendTextAsync(socket, attach, cancellationToken);
                        }
                        continue;
                    }

                    if (method == "Target.targetDestroyed" &&
                        parameters.TryGetProperty("targetId", out var destroyedElement) && destroyedElement.ValueKind == JsonValueKind.String)
                    {
                        var targetId = destroyedElement.GetString()!;
                        targetUrls.Remove(targetId);
                        if (targetToSession.Remove(targetId, out var sessionId))
                        {
                            active.Remove(sessionId);
                            injected.Remove(sessionId);
                            awaitingExecutionContext.Remove(sessionId);
                            foreach (var pending in pendingRuntimeEnables.Where(pair => pair.Value == sessionId).Select(pair => pair.Key).ToArray())
                                pendingRuntimeEnables.Remove(pending);
                            PublishCounts(active.Count, injected.Count);
                        }
                        continue;
                    }

                    if (method == "Target.detachedFromTarget" &&
                        parameters.TryGetProperty("sessionId", out var detachedElement) && detachedElement.ValueKind == JsonValueKind.String)
                    {
                        var sessionId = detachedElement.GetString()!;
                        active.Remove(sessionId);
                        injected.Remove(sessionId);
                        awaitingExecutionContext.Remove(sessionId);
                        foreach (var pending in pendingRuntimeEnables.Where(pair => pair.Value == sessionId).Select(pair => pair.Key).ToArray())
                            pendingRuntimeEnables.Remove(pending);
                        foreach (var target in targetToSession.Where(pair => pair.Value == sessionId).Select(pair => pair.Key).ToArray())
                            targetToSession.Remove(target);
                        foreach (var pending in pendingEvaluations.Where(pair => pair.Value == sessionId).Select(pair => pair.Key).ToArray())
                            pendingEvaluations.Remove(pending);
                        PublishCounts(active.Count, injected.Count);
                    }
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
            catch (Exception exception)
            {
                // 浏览器重启、调试端口瞬断或目标协议差异：外层 Monitor 下一轮重建连接。
                Volatile.Write(ref _lastError, exception.GetType().Name + "：" + exception.Message);
            }
            finally
            {
                Volatile.Write(ref _browserReachable, 0);
                PublishCounts(0, 0);
            }
        }

        private void PublishCounts(int active, int injected)
        {
            Volatile.Write(ref _activeTargetCount, active);
            Volatile.Write(ref _injectedTargetCount, injected);
        }

        // Dedicated/Shared Worker 由所属页面会话挂载；浏览器级连接只负责没有稳定父页面会话的 ServiceWorker。
        private static bool IsSupportedWorkerType(string? type) => type is "service_worker";

        private static bool IsAllowedWorkerUrl(string? value)
        {
            if (string.IsNullOrWhiteSpace(value)) return false;
            if (!Uri.TryCreate(value, UriKind.Absolute, out var uri)) return true;
            return uri.Scheme is "http" or "https" or "blob" or "data" or "file";
        }

        private static async Task<int> StartWorkerRuntimeAsync(ClientWebSocket socket, string sessionId, int commandId,
            Dictionary<int, string> pendingRuntimeEnables, CancellationToken cancellationToken)
        {
            // 部分 Chromium 版本即使 auto-attach 声明 waitForDebuggerOnStart=false，
            // 新建 Dedicated Worker 仍会短暂处于等待调试器状态；先显式放行，Runtime.enable 才会返回执行上下文。
            var resume = JsonSerializer.Serialize(new
            {
                id = ++commandId,
                method = "Runtime.runIfWaitingForDebugger",
                sessionId
            }, CdpJsonOptions);
            await SendTextAsync(socket, resume, cancellationToken);
            var enableId = ++commandId;
            pendingRuntimeEnables[enableId] = sessionId;
            var enable = JsonSerializer.Serialize(new
            {
                id = enableId,
                method = "Runtime.enable",
                sessionId
            }, CdpJsonOptions);
            await SendTextAsync(socket, enable, cancellationToken);
            return commandId;
        }

        private async Task<int> BeginWorkerInjectionAsync(ClientWebSocket socket, string source, string sessionId,
            int commandId, Dictionary<int, string> pendingEvaluations,
            CancellationToken cancellationToken)
        {
            var evaluationId = ++commandId;
            pendingEvaluations[evaluationId] = sessionId;
            var evaluate = JsonSerializer.Serialize(new
            {
                id = evaluationId,
                method = "Runtime.evaluate",
                @params = new { expression = source, returnByValue = false },
                sessionId
            }, CdpJsonOptions);
            await SendTextAsync(socket, evaluate, cancellationToken);
            return commandId;
        }

        private static async Task<int> ResumeAndDetachAsync(ClientWebSocket socket, string sessionId, int commandId,
            CancellationToken cancellationToken)
        {
            var resume = JsonSerializer.Serialize(new
            {
                id = ++commandId,
                method = "Runtime.runIfWaitingForDebugger",
                sessionId
            }, CdpJsonOptions);
            await SendTextAsync(socket, resume, cancellationToken);
            var detach = JsonSerializer.Serialize(new
            {
                id = ++commandId,
                method = "Target.detachFromTarget",
                @params = new { sessionId }
            }, CdpJsonOptions);
            await SendTextAsync(socket, detach, cancellationToken);
            return commandId;
        }
    }

    private static async Task<string?> TryGetBrowserWebSocketUrlAsync(int debuggingPort, TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(2) };
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var json = await http.GetStringAsync($"http://{NetMindDefaults.LoopbackAddress}:{debuggingPort}/json/version", cancellationToken);
                using var document = JsonDocument.Parse(json);
                if (document.RootElement.TryGetProperty("webSocketDebuggerUrl", out var value) && value.ValueKind == JsonValueKind.String)
                    return value.GetString();
            }
            catch (Exception exception) when (exception is not OperationCanceledException || !cancellationToken.IsCancellationRequested) { }
            await Task.Delay(200, cancellationToken);
        }
        return null;
    }

    private static async Task SendTextAsync(ClientWebSocket socket, string payload, CancellationToken cancellationToken) =>
        await socket.SendAsync(Encoding.UTF8.GetBytes(payload), WebSocketMessageType.Text, true, cancellationToken);

    private static async Task<byte[]?> ReceiveTextAsync(ClientWebSocket socket, CancellationToken cancellationToken)
    {
        var buffer = new byte[16 * 1024];
        using var message = new MemoryStream();
        while (message.Length <= 1024 * 1024)
        {
            var received = await socket.ReceiveAsync(new ArraySegment<byte>(buffer), cancellationToken);
            if (received.MessageType == WebSocketMessageType.Close) return null;
            if (received.MessageType != WebSocketMessageType.Text) continue;
            await message.WriteAsync(buffer.AsMemory(0, received.Count), cancellationToken);
            if (received.EndOfMessage) return message.ToArray();
        }
        throw new InvalidDataException("浏览器 CDP 消息超过 1 MB 安全上限。");
    }

    private static async Task<IReadOnlyList<HookTarget>> TryGetHookTargetsAsync(int debuggingPort, TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(2) };
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var json = await http.GetStringAsync($"http://{NetMindDefaults.LoopbackAddress}:{debuggingPort}/json/list", cancellationToken);
                using var document = JsonDocument.Parse(json);
                if (document.RootElement.ValueKind == JsonValueKind.Array)
                {
                    var targets = document.RootElement.EnumerateArray()
                        .Where(target => target.ValueKind == JsonValueKind.Object &&
                                         target.TryGetProperty("type", out var type) &&
                                         type.ValueKind == JsonValueKind.String &&
                                         type.GetString() is "page" or "webview")
                        .Select(target =>
                        {
                            var type = target.GetProperty("type").GetString()!;
                            var url = target.TryGetProperty("webSocketDebuggerUrl", out var socketUrl) && socketUrl.ValueKind == JsonValueKind.String
                                ? socketUrl.GetString() : null;
                            return string.IsNullOrWhiteSpace(url) ? null : new HookTarget(url, type);
                        })
                        .Where(target => target is not null)
                        .Select(target => target!)
                        .DistinctBy(target => target.WebSocketUrl, StringComparer.Ordinal)
                        .ToArray();
                    if (targets.Length > 0) return targets;
                }
            }
            catch (Exception exception) when (exception is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
            {
                // 浏览器未就绪或瞬时错误（含 HttpClient 自身超时的 TaskCanceled）：继续轮询。
            }
            await Task.Delay(250, cancellationToken);
        }
        return [];
    }

    internal static bool IsSupportedTargetType(string? type) =>
        type is "page" or "webview" or "worker" or "shared_worker" or "service_worker";

    private sealed record HookTarget(string WebSocketUrl, string Type)
    {
        public bool IsWorker => Type is "worker" or "shared_worker" or "service_worker";
    }
}

/// <summary>
/// 页内 Hook 上报接收器：仅监听 127.0.0.1 的 HttpListener，POST /hooks 接收 JSON 数组批次，
/// 逐条规范化（args 单条 8 KB 截断）后经回调入库；接收失败只记 stderr，不影响代理。
/// </summary>
public sealed class PageHookReceiver : IAsyncDisposable
{
    private readonly HttpListener _listener;
    private readonly Func<IReadOnlyList<PageHookEvent>, Task> _onBatch;
    private readonly CancellationTokenSource _cancellation = new();
    private Task? _runTask;

    public PageHookReceiver(int port, Guid sessionId, Func<IReadOnlyList<PageHookEvent>, Task> onBatch, string? hookToken = null)
    {
        SessionId = sessionId;
        _onBatch = onBatch;
        var token = string.IsNullOrWhiteSpace(hookToken) ? string.Empty : hookToken.Trim();
        if (token.Any(character => !char.IsAsciiLetterOrDigit(character) && character is not '-' and not '_'))
            throw new ArgumentException("页内 Hook 令牌格式无效。", nameof(hookToken));
        _listener = new HttpListener();
        _listener.Prefixes.Add($"http://{NetMindDefaults.LoopbackAddress}:{port}/hooks/{(token.Length == 0 ? string.Empty : token + "/")}");
    }

    public Guid SessionId { get; }
    public string Endpoint => _listener.Prefixes.First();

    public void Start()
    {
        _listener.Start();
        _runTask = Task.Run(AcceptLoopAsync);
    }

    private async Task AcceptLoopAsync()
    {
        while (!_cancellation.IsCancellationRequested)
        {
            HttpListenerContext context;
            try
            {
                context = await _listener.GetContextAsync();
            }
            catch (Exception)
            {
                if (_cancellation.IsCancellationRequested) return;
                await Task.Delay(200);
                continue;
            }
            // 单消费者顺序落库，天然形成背压；避免每个 HTTP 批次 Task.Run 导致无界并发与停机时悬空写库。
            await HandleAsync(context);
        }
    }

    private async Task HandleAsync(HttpListenerContext context)
    {
        try
        {
            AddCorsHeaders(context.Response);
            if (string.Equals(context.Request.HttpMethod, "OPTIONS", StringComparison.OrdinalIgnoreCase))
            {
                context.Response.StatusCode = 204;
                context.Response.Close();
                return;
            }
            if (!string.Equals(context.Request.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase) ||
                context.Request.ContentLength64 > NetMindDefaults.PageHookMaximumRequestBodyBytes)
            {
                context.Response.StatusCode = 400;
                context.Response.Close();
                return;
            }
            var body = await ReadBoundedBodyAsync(context.Request.InputStream, _cancellation.Token);
            var events = ParseBatch(body, SessionId);
            if (events.Count > 0) await _onBatch(events);
            context.Response.StatusCode = 204;
            context.Response.Close();
        }
        catch
        {
            try { context.Response.StatusCode = 400; context.Response.Close(); } catch { /* 连接已断 */ }
        }
    }

    private static void AddCorsHeaders(HttpListenerResponse response)
    {
        response.Headers["Access-Control-Allow-Origin"] = "*";
        response.Headers["Access-Control-Allow-Methods"] = "POST, OPTIONS";
        response.Headers["Access-Control-Allow-Headers"] = "Content-Type";
        response.Headers["Access-Control-Allow-Private-Network"] = "true";
    }

    private static async Task<string> ReadBoundedBodyAsync(Stream input, CancellationToken cancellationToken)
    {
        using var output = new MemoryStream();
        var buffer = new byte[16 * 1024];
        while (true)
        {
            var read = await input.ReadAsync(buffer, cancellationToken);
            if (read == 0) break;
            if (output.Length + read > NetMindDefaults.PageHookMaximumRequestBodyBytes)
                throw new InvalidDataException("页内 Hook 上报正文超过大小上限。");
            await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
        }
        return Encoding.UTF8.GetString(output.GetBuffer(), 0, checked((int)output.Length));
    }

    /// <summary>
    /// 解析上报批次 JSON（对象数组），逐条规范化：字段缺失取空串、args 按 UTF-8 8 KB 截断、
    /// 剔除 NUL 控制符（防截断 SQL 文本）；单批最多取 <see cref="NetMindDefaults.PageHookMaximumEventsPerBatch"/> 条。
    /// </summary>
    public static IReadOnlyList<PageHookEvent> ParseBatch(string json, Guid sessionId)
    {
        using var document = JsonDocument.Parse(json);
        if (document.RootElement.ValueKind != JsonValueKind.Array) return [];
        var events = new List<PageHookEvent>();
        foreach (var element in document.RootElement.EnumerateArray())
        {
            if (events.Count >= NetMindDefaults.PageHookMaximumEventsPerBatch) break;
            if (element.ValueKind != JsonValueKind.Object) continue;
            var timestamp = element.TryGetProperty("ts", out var ts) && ts.ValueKind == JsonValueKind.Number && ts.TryGetInt64(out var millis)
                ? DateTimeOffset.FromUnixTimeMilliseconds(millis)
                : DateTimeOffset.UtcNow;
            events.Add(new PageHookEvent(
                0,
                sessionId,
                timestamp,
                Sanitize(StringProperty(element, "type")),
                Sanitize(StringProperty(element, "fn")),
                Sanitize(StringProperty(element, "pageUrl")),
                TruncateArgs(Sanitize(StringProperty(element, "args"))),
                TruncateText(Sanitize(StringProperty(element, "url")), 4096),
                TruncateText(Sanitize(StringProperty(element, "stack")), 2048)));
        }
        return events;
    }

    private static string StringProperty(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() ?? string.Empty : string.Empty;

    private static string Sanitize(string value) => value.Replace("\0", string.Empty, StringComparison.Ordinal);

    private static string TruncateText(string value, int maximumChars) =>
        value.Length <= maximumChars ? value : value[..maximumChars];

    /// <summary>args 按 UTF-8 字节截断到单条上限；截断点回退到合法字符边界。</summary>
    private static string TruncateArgs(string value)
    {
        if (Encoding.UTF8.GetByteCount(value) <= NetMindDefaults.PageHookMaximumArgsBytes) return value;
        var low = 0;
        var high = Math.Min(value.Length, NetMindDefaults.PageHookMaximumArgsBytes);
        while (low < high)
        {
            var mid = (low + high + 1) / 2;
            if (Encoding.UTF8.GetByteCount(value.AsSpan(0, mid)) <= NetMindDefaults.PageHookMaximumArgsBytes) low = mid;
            else high = mid - 1;
        }
        return value[..low];
    }

    public async ValueTask DisposeAsync()
    {
        _cancellation.Cancel();
        try { _listener.Stop(); } catch { /* 已停止 */ }
        if (_runTask is not null)
        {
            try { await _runTask.WaitAsync(TimeSpan.FromSeconds(2)); } catch { /* 收尾不阻塞 */ }
        }
        _listener.Close();
        _cancellation.Dispose();
    }
}
