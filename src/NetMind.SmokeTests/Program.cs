using System.Text;
using System.Buffers.Binary;
using System.Diagnostics;
using System.IO.Compression;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.RegularExpressions;
using NetMind.Core;

// ── 冒烟测试注册表与运行器 ────────────────────────────────────────────────
// 原实现是 24 个 if 分支加一段内联的“全量”流程，且 Require 直接抛异常：
// 首个失败就中止整轮，CI 上一次只能看到一个问题，也没有耗时与结果汇总。
// 这里改为注册表驱动：逐个套件独立执行、失败继续、末尾统一汇总，退出码为失败套件数。
// 仍然不引入任何第三方测试框架，保持离线可构建。
var suites = new SmokeSuite[]
{
    new("核心存储、脱敏、演示数据与沙箱策略", "core-only", VerifyCoreStorageAndSandboxAsync),
    new("协议解析（HTTP/2、WebSocket、SSE、gRPC、DNS、Protobuf）", "protocol-only", Sync(VerifyProtocolParsers)),
    new("确定性端点聚类与字段传播", "analysis-only", Sync(VerifyTrafficAnalysis)),
    new("静默抓包报文解析、TCP 重组与 TLS 识别", "silent-only", async () =>
    {
        await VerifySilentCapture();
        VerifyCaptureBrowserPlan(Path.Combine(Path.GetTempPath(), "netmind-smoke-browser-" + Guid.NewGuid().ToString("N")));
    }),
    new("HTTP 转发、HTTPS 隧道与采集浏览器启动计划", "proxy-only", async () =>
    {
        var root = Path.Combine(Path.GetTempPath(), "netmind-proxy-test-" + Guid.NewGuid().ToString("N"));
        try
        {
            await new WorkspaceStore(root).InitializeAsync("代理定向测试工作区");
            await VerifyProxyAsync(root);
            VerifyCaptureBrowserPlan(root);
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, recursive: true); }
    }),
    new("站点可控证据参数绑定往返（引号/NUL/注入片段/中文/emoji）", "hostile-only", VerifyHostileEvidenceRoundTripAsync),
    new("采集会话范围限定（每次开始采集从空列表起步）", "scope-only", VerifyCaptureSessionScopeAsync),
    new("并发审计追加（一条不丢、一行不坏）", "audit-only", VerifyConcurrentAuditAppendAsync),
    new("AI 证据编排（折叠无损、地图有界、关联就地计算）", "ai-orchestration-only", Sync(VerifyAiEvidenceOrchestration)),
    new("AI 对话式网关、取数回环、会话持久化与提示词目录", "ai-only", async () =>
    {
        await VerifyAiGatewayAsync();
        await VerifyAiFullContextAsync();
        await VerifyAiPromptCatalogAsync();
    }),
    new("AI 分析历史持久化、隔离、恢复与删除", "ai-history-only", VerifyAiAnalysisHistoryAsync),
    new("清空记录", "clear-only", VerifyClearCaptureDataAsync),
    new("勾选删除", "delete-only", VerifyDeleteTrafficAsync),
    new("流量增量刷新游标", "refresh-only", VerifyIncrementalTrafficCursorAsync),
    new("证据复制与 cURL 格式化", "copy-only", Sync(VerifyTrafficCopyFormatting)),
    new("流量搜索布尔表达式与选择范围", "filter-only", Sync(() =>
    {
        VerifyTrafficFilterExpression();
        VerifyTrafficSelectionScope();
    })),
    new("JSON 展示树解码、降级与复制隔离", "json-only", Sync(VerifyJsonPreview)),
    new("记录组持久化、导出与历史事务恢复", "group-only", VerifyTrafficGroupsAsync),
    new("工作区新建、切换、重命名与数据隔离", "workspace-only", VerifyWorkspaceCatalogAsync),
    new("工作区保留策略、容量治理、备份与安全导入", "workspace-data-only", VerifyWorkspaceDataManagementAsync),
    new("工作台设置存储", "settings-only", VerifyWorkbenchSettingsAsync),
    new("系统代理快照序列化与哨兵原子读写", "sysproxy-only", VerifySystemProxySentinelAsync),
    new("脚本钩子策略、信封契约、队列、配置与页内 Hook", "hooks-only", async () =>
    {
        await VerifyHooksAsync();
        await VerifyPageHooksAsync();
    }),
    new("工作区脚本库（命名校验、用途推断、重命名/删除一致性、补全词表同源）", "script-library-only", VerifyScriptLibraryAsync),
    new("审计日志尾读（按事件名过滤、最近 N 条排序、损坏行容错）", "audit-reader-only", VerifyAuditLogReaderAsync),
    new("编辑器文本变换（注释切换、整理格式、折叠区域、AI 代写提示词）", "script-text-only", Sync(VerifyScriptTextTools)),
    new("钩子信封正文预览按需下发", "hook-payload-only", VerifyHookBodyPreviewGateAsync),
    new("代理钩子挂载点端到端触发（顺序、txnId、正文、单点开关）", "mountpoint-only", VerifyProxyHookMountPointsAsync),
    new("拦截规则正则匹配（URL/方法/主机/路径/头/正文/状态码）与 fail-open", "intercept-only", VerifyHookInterceptRulesAsync),
    new("示例脚本端到端：百度搜索关键字固定为 888（真实 worker + 真实代理）", "baidu-intercept-only", VerifyBaiduSearchInterceptAsync),
    new("采集链路一键自检", "capture-health-only", VerifyCaptureHealthAsync),
    new("HTTPS CONNECT、TLS 解密、正文持久化与 AI 脱敏", "tls-only", VerifyTlsInspectionAsync),
    new("Windows Job Object 沙箱资源限制与真实 Python", "sandbox-only", VerifyWindowsSandboxAsync),
    // 需要真实 Chromium，只能显式指定，不进默认全量运行。
    new("真实 Chromium 页内 Hook 注入、上报与入库", "page-hook-live", VerifyLivePageHookBrowserAsync, InDefaultRun: false)
};

if (args.Contains("--list", StringComparer.OrdinalIgnoreCase))
{
    Console.WriteLine("可用冒烟套件（不带参数时运行标注“默认”的全部套件）：");
    foreach (var item in suites)
        Console.WriteLine($"  --{item.Tag,-24} {(item.InDefaultRun ? "默认" : "可选")}  {item.Name}");
    return 0;
}

// 未知开关必须报错：静默回退到默认全量会让人误以为定向验证已经跑过。
var unknown = args.Where(argument => argument.StartsWith("--", StringComparison.Ordinal))
    .Where(argument => !argument.Equals("--list", StringComparison.OrdinalIgnoreCase))
    .Where(argument => !suites.Any(item => argument.Equals("--" + item.Tag, StringComparison.OrdinalIgnoreCase)))
    .ToArray();
if (unknown.Length > 0)
{
    Console.Error.WriteLine($"未知参数：{string.Join(' ', unknown)}。用 --list 查看全部套件。");
    return 2;
}

var requested = suites.Where(item => args.Contains("--" + item.Tag, StringComparer.OrdinalIgnoreCase)).ToArray();
var selected = requested.Length > 0 ? requested : suites.Where(item => item.InDefaultRun).ToArray();
Console.WriteLine($"NetMind 冒烟测试 · {(requested.Length > 0 ? "定向" : "默认全量")} {selected.Length} 个套件\n");

var failedSuites = new List<(string Name, Exception Error)>();
var wallClock = Stopwatch.StartNew();
foreach (var item in selected)
{
    var timer = Stopwatch.StartNew();
    try
    {
        await item.Run();
        timer.Stop();
        Console.WriteLine($"  [通过] {item.Name}  ({item.Tag}, {timer.ElapsedMilliseconds:N0} ms)");
    }
    catch (Exception exception)
    {
        // 关键：单个套件失败不得中止整轮，否则一次只能暴露一个问题。
        timer.Stop();
        failedSuites.Add((item.Name, exception));
        Console.WriteLine($"  [失败] {item.Name}  ({item.Tag}, {timer.ElapsedMilliseconds:N0} ms)");
        Console.WriteLine($"         {exception.GetType().Name}：{exception.Message}");
    }
}
wallClock.Stop();

Console.WriteLine($"\n{selected.Length - failedSuites.Count} 通过 / {failedSuites.Count} 失败 · 合计 {wallClock.Elapsed.TotalSeconds:F1} 秒");
if (failedSuites.Count == 0)
{
    Console.WriteLine(requested.Length > 0 ? "定向冒烟测试通过。" : "全部核心冒烟测试通过。");
    return 0;
}
Console.WriteLine("\n失败详情：");
foreach (var (name, error) in failedSuites)
{
    Console.WriteLine($"── {name}");
    Console.WriteLine(error.ToString());
}
// 退出码为失败套件数（上限 100，避开 shell 退出码的 8 位语义）。
return Math.Min(100, failedSuites.Count);

/// <summary>把同步验证函数包装成注册表要求的异步签名。</summary>
static Func<Task> Sync(Action body) => () => { body(); return Task.CompletedTask; };

/// <summary>核心存储、脱敏、演示数据与 Python 静态策略；其余能力各自独立成套件。</summary>
static async Task VerifyCoreStorageAndSandboxAsync()
{
    var testRoot = Path.Combine(Path.GetTempPath(), "netmind-smoke-" + Guid.NewGuid().ToString("N"));
    try
    {
        var store = new WorkspaceStore(testRoot);
        await store.InitializeAsync("冒烟测试工作区");

        var content = Encoding.UTF8.GetBytes("deterministic payload");
        var firstHash = await store.StoreBlobAsync(content);
        var secondHash = await store.StoreBlobAsync(content);
        Require(firstHash == secondHash, "相同内容必须生成相同哈希");
        Require(File.Exists(Path.Combine(testRoot, NetMindDefaults.BlobsDirectoryName, firstHash[..2], firstHash)), "Blob 文件必须按哈希持久化");

        var redacted = WorkspaceStore.Redact("token=super-secret authorization=Bearer-value");
        Require(!redacted.Contains("super-secret", StringComparison.Ordinal), "令牌必须脱敏");
        Require(!redacted.Contains("Bearer-value", StringComparison.Ordinal), "授权信息必须脱敏");

        // 回归：以下两类写法此前完全绕过脱敏通道，而它们恰恰是最常见的形态。
        foreach (var (input, secret) in new[]
                 {
                     // Bearer/Basic：旧正则把方案名当成值遮掉，真正的凭据留在明文里。
                     ("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.LEAKED", "LEAKED"),
                     ("authorization: Basic QWxhZGRpbjpMRUFLRUQ=", "QWxhZGRpbjpMRUFLRUQ="),
                     // JSON 属性名带引号，旧正则要求键后紧跟 : 或 =，整条不命中；而审计载荷本身就是 JSON。
                     ("""{"token":"tok_live_LEAKED"}""", "tok_live_LEAKED"),
                     ("""{"api_key": "ak_LEAKED"}""", "ak_LEAKED"),
                     ("""{"secret" : "s3cr3t_LEAKED"}""", "s3cr3t_LEAKED")
                 })
        {
            var result = WorkspaceStore.Redact(input);
            Require(!result.Contains(secret, StringComparison.Ordinal), $"脱敏必须覆盖该写法：{input}");
            Require(result.Contains(NetMindDefaults.RedactedPlaceholder, StringComparison.Ordinal),
                $"脱敏后必须留下占位符：{input}");
        }

        // 不得过度脱敏：只替换凭据本身，键名、鉴权方案与相邻字段必须原样保留。
        Require(WorkspaceStore.Redact("token=abc&page=2&size=50").Contains("page=2&size=50", StringComparison.Ordinal),
            "脱敏不得吞掉凭据之后的查询参数");
        Require(WorkspaceStore.Redact("https://api.test/api_keys/list").Contains("api_keys/list", StringComparison.Ordinal),
            "路径中出现 api_key 字样但无键值形态时不得脱敏");
        Require(WorkspaceStore.Redact("Authorization: Bearer XYZ").Contains("Bearer", StringComparison.Ordinal),
            "鉴权方案本身是有价值的证据，必须保留");
        // JSON 载荷脱敏后必须仍是合法 JSON，否则审计与导出会带出结构损坏的内容。
        using (JsonDocument.Parse(WorkspaceStore.Redact("""{"token":"tok_live_LEAKED","userId":1001}"""))) { }
        // 幂等：重复脱敏不得反复吞掉占位符。
        var onceRedacted = WorkspaceStore.Redact("Authorization: Bearer eyJLEAKED");
        Require(onceRedacted == WorkspaceStore.Redact(onceRedacted), "重复脱敏必须幂等");

        var traffic = DemoData.CreateTraffic();
        Require(traffic.Count >= 10, "演示流量必须覆盖主要协议场景");
        Require(DemoData.CreateFinding(traffic.First(t => t.StatusCode >= 400)).Evidence.Count >= 3, "异常发现必须包含完整证据链");

        using (var archive = new TrafficArchive(testRoot))
        {
            var sessionId = Guid.NewGuid();
            await archive.StartSessionAsync(new CaptureSessionRecord(sessionId, DateTimeOffset.UtcNow, null, NetMindDefaults.SourceSimulated, "全部进程", NetMindDefaults.SessionStateRunning));
            var item = traffic[0];
            var stored = await archive.RecordAsync(sessionId, item, Encoding.UTF8.GetBytes(item.RequestSummary), Encoding.UTF8.GetBytes(item.ResponseSummary));
            Require(stored.RequestBlobHash.Length == NetMindDefaults.Sha256HexLength, "正文哈希必须为 SHA-256");
            Require(archive.GetTrafficCount() == 1, "SQLite 必须保存事务元数据");
            var restored = archive.GetRecentTraffic(10).Single();
            Require(restored.Traffic.Endpoint == item.Endpoint, "SQLite 查询必须还原端点");
            Require(restored.RequestBlobHash == stored.RequestBlobHash, "SQLite 只能保存正文哈希引用");
            await archive.CompleteSessionAsync(new CaptureSessionRecord(sessionId, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow, NetMindDefaults.SourceSimulated, "全部进程", NetMindDefaults.SessionStateCompleted));
        }

        var rejected = PythonSandboxPolicy.Validate("import os\nopen('secret.txt')");
        Require(rejected.Count == 2, "Python 静态策略必须拒绝文件和系统模块能力");
        var accepted = PythonSandboxPolicy.Validate("from netmind import fixture\nprint(len(fixture.transactions))");
        Require(accepted.Count == 0, "Python 静态策略必须允许只读样例分析");
        var missingRuntime = await new PythonSandboxRunner().RunAsync(new SandboxJob(
            "from netmind import fixture\nprint(len(fixture.transactions))",
            JsonSerializer.SerializeToElement(new { transactions = Array.Empty<object>() }),
            PythonPath: Path.Combine(testRoot, "不存在的-python.exe")));
        Require(missingRuntime.State == "运行时不可用", "缺少 Python 时必须返回结构化中文状态");
    }
    finally
    {
        if (Directory.Exists(testRoot)) Directory.Delete(testRoot, recursive: true);
    }
}


static async Task VerifyCaptureHealthAsync()
{
    static int PickPort()
    {
        var probe = new TcpListener(IPAddress.Loopback, 0);
        probe.Start();
        var port = ((IPEndPoint)probe.LocalEndpoint).Port;
        probe.Stop();
        return port;
    }

    var root = Path.Combine(Path.GetTempPath(), "netmind-health-test-" + Guid.NewGuid().ToString("N"));
    TcpListener? proxy = null;
    TcpListener? hook = null;
    HttpListener? cdp = null;
    try
    {
        await new WorkspaceStore(root).InitializeAsync("采集自检测试工作区");
        using (var archive = new TrafficArchive(root))
        {
            var sessionId = Guid.NewGuid();
            await archive.StartSessionAsync(new CaptureSessionRecord(sessionId, DateTimeOffset.UtcNow, null,
                NetMindDefaults.SourceRealProxy, "all", NetMindDefaults.SessionStateRunning));
            var traffic = DemoData.CreateTraffic()[0] with { Timestamp = DateTimeOffset.UtcNow };
            await archive.RecordAsync(sessionId, traffic, Encoding.UTF8.GetBytes("request"), Encoding.UTF8.GetBytes("response"));
            await archive.RecordPageHooksAsync([
                new PageHookEvent(0, sessionId, DateTimeOffset.UtcNow, "lifecycle", "hook.installed", traffic.Url,
                    "{\"version\":3,\"context\":\"worker\"}")
            ]);
        }

        proxy = new TcpListener(IPAddress.Loopback, 0);
        proxy.Start();
        var proxyPort = ((IPEndPoint)proxy.LocalEndpoint).Port;
        hook = new TcpListener(IPAddress.Loopback, 0);
        hook.Start();
        var hookPort = ((IPEndPoint)hook.LocalEndpoint).Port;
        var cdpPort = PickPort();
        cdp = new HttpListener();
        cdp.Prefixes.Add($"http://127.0.0.1:{cdpPort}/");
        cdp.Start();
        var cdpReply = Task.Run(async () =>
        {
            var context = await cdp.GetContextAsync();
            var bytes = Encoding.UTF8.GetBytes($"{{\"webSocketDebuggerUrl\":\"ws://127.0.0.1:{cdpPort}/devtools/browser/test\"}}");
            context.Response.ContentType = "application/json";
            context.Response.ContentLength64 = bytes.Length;
            await context.Response.OutputStream.WriteAsync(bytes);
            context.Response.Close();
        });

        var healthy = await CaptureHealthChecker.RunAsync(new CaptureHealthContext(root, true, false, true,
            proxyPort, hookPort, true, cdpPort, false,
            new PageHookMonitorStatus(true, 2, 2, 2, 0, 1, 1), DateTimeOffset.UtcNow));
        await cdpReply;
        Require(healthy.OverallLevel == CaptureHealthLevel.Passed &&
                healthy.Items.Any(item => item.Name == "代理监听" && item.Level == CaptureHealthLevel.Passed) &&
                healthy.Items.Any(item => item.Name == "页面与 Worker Hook" && item.Summary.Contains("Worker 1/1", StringComparison.Ordinal)) &&
                healthy.Items.Any(item => item.Name == "流量入库" && item.Level == CaptureHealthLevel.Passed) &&
                healthy.Items.Any(item => item.Name == "Hook 入库" && item.Level == CaptureHealthLevel.Passed),
            "采集自检必须汇总代理、CDP、Worker Hook 与实际入库证据");
        Require(healthy.ToPlainText().Contains("采集自检", StringComparison.Ordinal) &&
                healthy.ToPlainText().Contains("页面与 Worker Hook", StringComparison.Ordinal),
            "采集自检报告必须可完整复制为纯文本");

        proxy.Stop();
        hook.Stop();
        cdp.Close();
        proxy = null;
        hook = null;
        cdp = null;
        var broken = await CaptureHealthChecker.RunAsync(new CaptureHealthContext(root, true, false, false,
            proxyPort, hookPort, true, cdpPort, false, null, null));
        Require(broken.OverallLevel == CaptureHealthLevel.Failed &&
                broken.Items.Count(item => item.Level == CaptureHealthLevel.Failed) >= 4,
            "后台退出、代理/Hook/CDP 不可达时，自检必须明确判定失败");
    }
    finally
    {
        proxy?.Stop();
        hook?.Stop();
        cdp?.Close();
        if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
    }
}

static async Task VerifyWindowsSandboxAsync()
{
    var runner = new PythonSandboxRunner();
    var fixture = JsonSerializer.SerializeToElement(new { value = 42 });
    var accepted = await runner.RunAsync(new SandboxJob(
        "from netmind import fixture\nprint(f'fixture={fixture.value}')",
        fixture,
        TimeoutMilliseconds: 3000,
        MaximumMemoryBytes: 128L * 1024 * 1024));
    Require(accepted.Succeeded && accepted.StandardOutput.Contains("fixture=42", StringComparison.Ordinal),
        "真实 Python 必须在 Windows 沙箱中读取只读样例并成功返回");
    Require(accepted.Enforcement.Contains("Windows Job Object", StringComparison.Ordinal) &&
            accepted.Enforcement.Contains("最多 1 个进程", StringComparison.Ordinal),
        "沙箱结果必须明确报告 Windows 强制资源边界");

    var timed = await runner.RunAsync(new SandboxJob(
        "while True:\n    pass",
        fixture,
        TimeoutMilliseconds: 350,
        MaximumMemoryBytes: 128L * 1024 * 1024));
    Require(!timed.Succeeded && timed.DurationMilliseconds < 5000,
        "无限循环必须由 CPU 或墙钟限制快速终止");

    var memoryLimited = await runner.RunAsync(new SandboxJob(
        "blocks = []\nwhile True:\n    blocks.append(bytearray(8 * 1024 * 1024))",
        fixture,
        TimeoutMilliseconds: 5000,
        MaximumMemoryBytes: 64L * 1024 * 1024));
    Require(!memoryLimited.Succeeded && memoryLimited.Enforcement.Contains("内存 64 MB", StringComparison.Ordinal),
        "Python 内存分配必须受到 Job Object 进程内存上限约束");
}

static async Task VerifyTlsInspectionAsync()
{
    var root = Path.Combine(Path.GetTempPath(), "netmind-tls-test-" + Guid.NewGuid().ToString("N"));
    WorkspaceCertificateAuthority? authority = null;
    try
    {
        await new WorkspaceStore(root).InitializeAsync("TLS 解密定向测试工作区");
        authority = new WorkspaceCertificateAuthority(root);
        var enabled = authority.EnableAndTrust();
        Require(authority.IsEnabledAndTrusted() && !string.IsNullOrWhiteSpace(enabled.Thumbprint), "工作区 CA 必须可由当前用户明确启用和信任");
        authority.DisableAndRemoveTrust();
        Require(!authority.IsEnabledAndTrusted(), "停用 TLS 解密必须撤销当前用户根信任");
        var probeCertificate = authority.GetServerCertificate("localhost");
        Require(probeCertificate.HasPrivateKey, "动态站点证书必须包含私钥");
        var policyStore = new TlsInspectionPolicyStore(root);
        var normalizedPolicy = policyStore.SaveFromText("*.Pinned.Example, login.example.com; login.example.com");
        Require(normalizedPolicy.BypassHosts.SequenceEqual(["*.pinned.example", "login.example.com"]), "HTTPS 直通规则必须规范化、去重并稳定排序");
        Require(TlsInspectionPolicyStore.ShouldBypass(normalizedPolicy, "api.pinned.example") &&
                !TlsInspectionPolicyStore.ShouldBypass(normalizedPolicy, "pinned.example") &&
                TlsInspectionPolicyStore.ShouldBypass(normalizedPolicy, "LOGIN.EXAMPLE.COM"),
            "HTTPS 直通规则必须支持精确域名和子域名通配符");

        using var upstreamCertificate = CreateTestServerCertificate("localhost");
        var upstreamListener = new TcpListener(IPAddress.Loopback, 0);
        upstreamListener.Start();
        var upstreamEndpoint = (IPEndPoint)upstreamListener.LocalEndpoint;
        var upstreamTask = Task.Run(async () =>
        {
            using var accepted = await upstreamListener.AcceptTcpClientAsync();
            using var tls = new SslStream(accepted.GetStream(), false);
            await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
            {
                ServerCertificate = upstreamCertificate,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                ApplicationProtocols = [SslApplicationProtocol.Http11]
            });
            for (var index = 0; index < 2; index++)
            {
                var request = await ReadTestHeadersAsync(tls);
                var requestBody = await ReadTestBodyAsync(tls, request);
                if (index == 0)
                {
                    Require(request.StartsWith("GET /secure?token=secret-value HTTP/1.1", StringComparison.Ordinal), "上游必须收到解密后的第一个 HTTPS 请求");
                    Require(requestBody.Length == 0, "HTTPS GET 不应产生请求正文");
                }
                else
                {
                    Require(request.StartsWith("POST /submit HTTP/1.1", StringComparison.Ordinal), "上游必须收到复用 TLS 连接后的第二个 HTTPS 请求");
                    Require(Encoding.UTF8.GetString(requestBody) == "hello world", "代理必须解码 chunked 请求正文后完整转发");
                }

                var body = Encoding.UTF8.GetBytes(index == 0 ? "{\"secure\":true}" : "{\"stored\":true}");
                var connection = index == 0 ? "keep-alive" : "close";
                await tls.WriteAsync(Encoding.ASCII.GetBytes($"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nSet-Cookie: server-session=raw-server-cookie\r\nSet-Cookie: preference=dark\r\nContent-Length: {body.Length}\r\nConnection: {connection}\r\n\r\n"));
                await tls.WriteAsync(body);
                await tls.FlushAsync();
            }
        });

        using var archive = new TrafficArchive(root);
        using var handler = new HttpClientHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None,
            UseCookies = false,
            UseProxy = false,
            ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
        };
        await using var proxy = new ExplicitHttpProxy(new ProxyOptions(IPAddress.Loopback, 0,
            EnableTlsInspection: true, WorkspacePath: root), archive, handler);
        using var cancellation = new CancellationTokenSource();
        var proxyTask = proxy.RunAsync(cancellation.Token);
        while (proxy.LocalEndpoint is null) await Task.Delay(10);

        using var client = new TcpClient();
        await client.ConnectAsync(proxy.LocalEndpoint.Address, proxy.LocalEndpoint.Port);
        using var stream = client.GetStream();
        await stream.WriteAsync(Encoding.ASCII.GetBytes($"CONNECT localhost:{upstreamEndpoint.Port} HTTP/1.1\r\nHost: localhost:{upstreamEndpoint.Port}\r\n\r\n"));
        var connectResponse = await ReadTestHeadersAsync(stream);
        Require(connectResponse.StartsWith("HTTP/1.1 200", StringComparison.Ordinal), "TLS 解密代理必须接受 CONNECT");
        using var clientTls = new SslStream(stream, false, (_, certificate, _, _) => certificate is not null);
        try
        {
            await clientTls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = "localhost",
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                ApplicationProtocols = [SslApplicationProtocol.Http11],
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck
            });
        }
        catch (Exception exception)
        {
            var diagnostic = archive.GetRecentTraffic(5).FirstOrDefault();
            var detail = diagnostic is null
                ? "无"
                : Encoding.UTF8.GetString((await archive.ReadBlobAsync(diagnostic.ResponseBlobHash)).Content);
            throw new InvalidOperationException($"客户端 TLS 握手失败；代理记录：{detail}", exception);
        }
        await clientTls.WriteAsync(Encoding.ASCII.GetBytes($"GET /secure?token=secret-value HTTP/1.1\r\nHost: localhost:{upstreamEndpoint.Port}\r\nCookie: session=raw-client-cookie\r\nConnection: keep-alive\r\n\r\n"));
        await clientTls.FlushAsync();
        var firstResponse = await ReadTestResponseAsync(clientTls);
        Require(firstResponse.Headers.Contains("Connection: keep-alive", StringComparison.OrdinalIgnoreCase) &&
                firstResponse.Headers.Contains("Set-Cookie: server-session=raw-server-cookie", StringComparison.OrdinalIgnoreCase) &&
                firstResponse.Headers.Contains("Set-Cookie: preference=dark", StringComparison.OrdinalIgnoreCase) &&
                Encoding.UTF8.GetString(firstResponse.Body) == "{\"secure\":true}",
            "客户端必须收到可复用连接的第一个 HTTPS 响应");

        await clientTls.WriteAsync(Encoding.ASCII.GetBytes($"POST /submit HTTP/1.1\r\nHost: localhost:{upstreamEndpoint.Port}\r\nTransfer-Encoding: chunked\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n6\r\nhello \r\n5\r\nworld\r\n0\r\nX-Test-Trailer: ok\r\n\r\n"));
        await clientTls.FlushAsync();
        var secondResponse = await ReadTestResponseAsync(clientTls);
        Require(secondResponse.Headers.Contains("Connection: close", StringComparison.OrdinalIgnoreCase) &&
                Encoding.UTF8.GetString(secondResponse.Body) == "{\"stored\":true}",
            "同一 TLS 连接必须完成第二个 chunked HTTPS 请求并按客户端语义关闭");
        await upstreamTask;

        using (var invalidClient = new TcpClient())
        {
            await invalidClient.ConnectAsync(proxy.LocalEndpoint.Address, proxy.LocalEndpoint.Port);
            using var invalidStream = invalidClient.GetStream();
            await invalidStream.WriteAsync(Encoding.ASCII.GetBytes($"CONNECT localhost:{upstreamEndpoint.Port} HTTP/1.1\r\nHost: localhost:{upstreamEndpoint.Port}\r\n\r\n"));
            Require((await ReadTestHeadersAsync(invalidStream)).StartsWith("HTTP/1.1 200", StringComparison.Ordinal),
                "无效请求测试必须先建立 TLS 解密隧道");
            using var invalidTls = new SslStream(invalidStream, false, (_, certificate, _, _) => certificate is not null);
            await invalidTls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = "localhost",
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                ApplicationProtocols = [SslApplicationProtocol.Http11],
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck
            });
            await invalidTls.WriteAsync(Encoding.ASCII.GetBytes($"POST /invalid HTTP/1.1\r\nHost: localhost:{upstreamEndpoint.Port}\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"));
            await invalidTls.FlushAsync();
            var invalidResponse = await ReadTestResponseAsync(invalidTls);
            Require(invalidResponse.Headers.StartsWith("HTTP/1.1 400", StringComparison.Ordinal),
                "冲突的 HTTPS 正文边界必须返回 TLS 内的 400 响应");
        }

        var deadline = DateTimeOffset.UtcNow.AddSeconds(3);
        while (archive.GetTrafficCount() < 3 && DateTimeOffset.UtcNow < deadline) await Task.Delay(20);
        var captured = archive.GetRecentTraffic(5).Where(item => item.Traffic.Protocol.StartsWith("HTTPS 解密", StringComparison.Ordinal)).ToArray();
        Require(captured.Count(item => item.Traffic.Protocol.StartsWith("HTTPS 解密 ·", StringComparison.Ordinal)) == 2,
            "同一 TLS 连接中的两个请求必须分别持久化");
        Require(captured.Any(item => item.Traffic.Protocol == "HTTPS 解密失败" && item.Traffic.StatusCode == 400),
            "TLS 内部无效 HTTP 请求必须作为失败证据持久化");
        var stored = captured.Single(item => item.Traffic.Method == "GET");
        var submitted = captured.Single(item => item.Traffic.Method == "POST");
        Require(stored.Traffic.Method == "GET" && stored.Traffic.Url.Contains("secret-value", StringComparison.Ordinal), "本地证据必须保留原始 HTTPS URL");
        Require(stored.Traffic.Cookies.Contains("raw-client-cookie", StringComparison.Ordinal), "本地证据必须保留 HTTPS Cookie");
        var responseBody = await archive.ReadBlobAsync(stored.ResponseBlobHash);
        Require(Encoding.UTF8.GetString(responseBody.Content) == "{\"secure\":true}", "HTTPS 响应正文必须写入内容寻址存储");
        var submittedBody = await archive.ReadBlobAsync(submitted.RequestBlobHash);
        Require(Encoding.UTF8.GetString(submittedBody.Content) == "hello world", "解码后的 chunked HTTPS 请求正文必须写入内容寻址存储");
        var redacted = AiPrivacyFilter.BuildJson([stored.Traffic], 1);
        Require(!redacted.Contains("secret-value", StringComparison.Ordinal) && !redacted.Contains("raw-client-cookie", StringComparison.Ordinal), "脱敏过滤器必须遮蔽 HTTPS 敏感字段");

        Require(new ProxyOptions(IPAddress.Loopback, 0).MaximumConcurrentConnections >= 128,
            "并发连接上限必须足以容纳系统代理场景下的长连接数量");
        var handshakeTasks = Enumerable.Range(0, 16).Select(async index =>
        {
            var host = $"concurrent-{index}.test";
            using var handshakeClient = new TcpClient();
            await handshakeClient.ConnectAsync(proxy.LocalEndpoint.Address, proxy.LocalEndpoint.Port);
            using var handshakeStream = handshakeClient.GetStream();
            await handshakeStream.WriteAsync(Encoding.ASCII.GetBytes($"CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n"));
            var handshakeResponse = await ReadTestHeadersAsync(handshakeStream);
            if (!handshakeResponse.StartsWith("HTTP/1.1 200", StringComparison.Ordinal))
                throw new InvalidOperationException($"{host} 未建立 CONNECT 隧道：{handshakeResponse.Split('\r')[0]}");
            using var handshakeTls = new SslStream(handshakeStream, false, (_, certificate, _, _) => certificate is not null);
            await handshakeTls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = host,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                ApplicationProtocols = [SslApplicationProtocol.Http11],
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck
            });
        }).ToArray();
        Require(await Task.WhenAll(handshakeTasks).WaitAsync(TimeSpan.FromSeconds(30)).ContinueWith(task => task.IsCompletedSuccessfully),
            "16 个并发 TLS 握手必须全部限时完成，不得被长连接占用名额或证书签发串行化拖垮");

        cancellation.Cancel();
        await proxyTask;
        upstreamListener.Stop();

        policyStore.SaveFromText("localhost");
        var bypassListener = new TcpListener(IPAddress.Loopback, 0);
        bypassListener.Start();
        var bypassEndpoint = (IPEndPoint)bypassListener.LocalEndpoint;
        var bypassUpstreamTask = Task.Run(async () =>
        {
            using var accepted = await bypassListener.AcceptTcpClientAsync();
            using var tls = new SslStream(accepted.GetStream(), false);
            await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
            {
                ServerCertificate = upstreamCertificate,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                ApplicationProtocols = [SslApplicationProtocol.Http11]
            });
            var request = await ReadTestHeadersAsync(tls);
            Require(request.StartsWith("GET /pinned?token=must-remain-encrypted HTTP/1.1", StringComparison.Ordinal),
                "直通域名必须把 TLS 字节原样转发到上游");
            var body = Encoding.UTF8.GetBytes("{\"bypass\":true}");
            await tls.WriteAsync(Encoding.ASCII.GetBytes($"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {body.Length}\r\nConnection: close\r\n\r\n"));
            await tls.WriteAsync(body);
            await tls.FlushAsync();
        });

        await using var bypassProxy = new ExplicitHttpProxy(new ProxyOptions(IPAddress.Loopback, 0,
            EnableTlsInspection: true, WorkspacePath: root), archive);
        using var bypassCancellation = new CancellationTokenSource();
        var bypassProxyTask = bypassProxy.RunAsync(bypassCancellation.Token);
        while (bypassProxy.LocalEndpoint is null) await Task.Delay(10);
        using (var bypassClient = new TcpClient())
        {
            await bypassClient.ConnectAsync(bypassProxy.LocalEndpoint.Address, bypassProxy.LocalEndpoint.Port);
            using var bypassStream = bypassClient.GetStream();
            await bypassStream.WriteAsync(Encoding.ASCII.GetBytes($"CONNECT localhost:{bypassEndpoint.Port} HTTP/1.1\r\nHost: localhost:{bypassEndpoint.Port}\r\n\r\n"));
            Require((await ReadTestHeadersAsync(bypassStream)).StartsWith("HTTP/1.1 200", StringComparison.Ordinal),
                "直通域名必须建立 CONNECT 隧道");
            using var bypassTls = new SslStream(bypassStream, false, (_, certificate, _, _) => certificate is not null);
            await bypassTls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = "localhost",
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                ApplicationProtocols = [SslApplicationProtocol.Http11],
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck
            });
            await bypassTls.WriteAsync(Encoding.ASCII.GetBytes($"GET /pinned?token=must-remain-encrypted HTTP/1.1\r\nHost: localhost:{bypassEndpoint.Port}\r\nConnection: close\r\n\r\n"));
            await bypassTls.FlushAsync();
            var bypassResponse = await ReadTestResponseAsync(bypassTls);
            Require(Encoding.UTF8.GetString(bypassResponse.Body) == "{\"bypass\":true}", "直通隧道必须返回真实上游响应");
        }
        await bypassUpstreamTask;
        bypassCancellation.Cancel();
        await bypassProxyTask;
        bypassListener.Stop();
        var bypassRecord = archive.GetRecentTraffic(10).First(item => item.Traffic.Protocol == NetMindDefaults.ProtocolHttpsTunnel);
        var bypassRequestBlob = await archive.ReadBlobAsync(bypassRecord.RequestBlobHash);
        var bypassResponseBlob = await archive.ReadBlobAsync(bypassRecord.ResponseBlobHash);
        Require(!bypassRecord.Traffic.Url.Contains("must-remain-encrypted", StringComparison.Ordinal) &&
                bypassRequestBlob.Content.Length == 0 && bypassResponseBlob.Content.Length == 0,
            "直通域名只能记录 CONNECT 元数据，不得持久化加密请求路径或正文");
    }
    finally
    {
        authority?.DeleteAuthorityForTesting();
        authority?.Dispose();
        if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
    }
}

static X509Certificate2 CreateTestServerCertificate(string host)
{
    using var rsa = RSA.Create(2048);
    var request = new CertificateRequest($"CN={host}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    var san = new SubjectAlternativeNameBuilder();
    san.AddDnsName(host);
    request.CertificateExtensions.Add(san.Build());
    request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
    request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
    using var created = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(1));
    return X509CertificateLoader.LoadPkcs12(created.Export(X509ContentType.Pfx), (string?)null, X509KeyStorageFlags.Exportable);
}

static async Task<string> ReadTestHeadersAsync(Stream stream)
{
    using var output = new MemoryStream();
    var marker = new byte[] { 13, 10, 13, 10 };
    var matched = 0;
    while (output.Length < 64 * 1024)
    {
        var buffer = new byte[1];
        if (await stream.ReadAsync(buffer) == 0) break;
        output.WriteByte(buffer[0]);
        matched = buffer[0] == marker[matched] ? matched + 1 : buffer[0] == marker[0] ? 1 : 0;
        if (matched == marker.Length) return Encoding.Latin1.GetString(output.ToArray());
    }
    throw new InvalidDataException("测试连接未返回完整头部。");
}

static async Task<byte[]> ReadTestBodyAsync(Stream stream, string headers)
{
    var contentLengthLine = headers.Split("\r\n", StringSplitOptions.RemoveEmptyEntries)
        .FirstOrDefault(line => line.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase));
    if (contentLengthLine is null) return [];
    Require(int.TryParse(contentLengthLine[(contentLengthLine.IndexOf(':') + 1)..].Trim(), out var length) && length >= 0,
        "测试上游收到的 Content-Length 必须有效");
    var body = new byte[length];
    var offset = 0;
    while (offset < length)
    {
        var read = await stream.ReadAsync(body.AsMemory(offset));
        if (read == 0) throw new EndOfStreamException("测试请求正文提前结束。");
        offset += read;
    }
    return body;
}

static async Task<(string Headers, byte[] Body)> ReadTestResponseAsync(Stream stream)
{
    var headers = await ReadTestHeadersAsync(stream);
    return (headers, await ReadTestBodyAsync(stream, headers));
}

static async Task VerifyWorkbenchSettingsAsync()
{
    var settingsRoot = Path.Combine(Path.GetTempPath(), "netmind-settings-test-" + Guid.NewGuid().ToString("N"));
    try
    {
        var defaults = new WorkbenchSettings();
        Require(defaults.ListenPort == NetMindDefaults.ListenPort &&
                defaults.RefreshIntervalMilliseconds == NetMindDefaults.DefaultRefreshIntervalMilliseconds &&
                defaults.TrafficWindowCount == NetMindDefaults.DefaultTrafficWindowCount &&
                defaults.SessionWindowCount == NetMindDefaults.DefaultSessionWindowCount &&
                defaults.AiEvidenceMaximumTransactions == NetMindDefaults.DefaultAiEvidenceMaximumTransactions,
            "工作台设置默认值必须全部引用集中常量");

        var settingsPath = Path.Combine(settingsRoot, "settings.json");
        var store = new WorkbenchSettingsStore(settingsPath);
        Require((await store.LoadAsync()).Equals(defaults), "设置文件缺失时必须返回默认实例");

        var workspaceRoot = Path.Combine(settingsRoot, "workspaces");
        var custom = new WorkbenchSettings(ListenPort: 8899, SystemProxyAutomation: true, WorkspaceRootPath: workspaceRoot);
        await store.SaveAsync(custom);
        Require(!Directory.EnumerateFiles(settingsRoot).Any(file => file.Contains(".tmp-", StringComparison.Ordinal)), "原子写不得残留临时文件");
        Require((await store.LoadAsync()).Equals(custom), "设置保存后必须可完整往返读取");
        // V3 起这些条数由用户配置，必须持久化；此前是系统托管、写入时丢弃。
        var compactJson = await File.ReadAllTextAsync(settingsPath);
        Require(compactJson.Contains("refreshIntervalMilliseconds", StringComparison.OrdinalIgnoreCase) &&
                compactJson.Contains("trafficWindowCount", StringComparison.OrdinalIgnoreCase) &&
                compactJson.Contains("sessionWindowCount", StringComparison.OrdinalIgnoreCase) &&
                compactJson.Contains("pageHookWindowCount", StringComparison.OrdinalIgnoreCase) &&
                compactJson.Contains("aiEvidenceMaximumTransactions", StringComparison.OrdinalIgnoreCase),
            "V3 设置文件必须持久化用户可配置的刷新间隔与各列表/证据条数");

        var tuned = new WorkbenchSettings(RefreshIntervalMilliseconds: 800, TrafficWindowCount: 300,
            SessionWindowCount: 60, AiEvidenceMaximumTransactions: 50, PageHookWindowCount: 120,
            WorkspaceRootPath: workspaceRoot);
        await store.SaveAsync(tuned);
        var reloaded = await store.LoadAsync();
        Require(reloaded.RefreshIntervalMilliseconds == 800 && reloaded.TrafficWindowCount == 300 &&
                reloaded.SessionWindowCount == 60 && reloaded.AiEvidenceMaximumTransactions == 50 &&
                reloaded.PageHookWindowCount == 120,
            "用户配置的条数与刷新间隔必须原样往返，不得被回填为默认值");

        // 旧版 V2 文件没有这些字段，读取时按记录默认值补齐而不是报错。
        var legacyPath = Path.Combine(settingsRoot, "legacy-v2.json");
        await File.WriteAllTextAsync(legacyPath,
            """{"schemaVersion":2,"listenPort":8877,"systemProxyAutomation":false,"enableTrafficHooks":false,"useSilentCapture":false,"browserEnvironment":null,"workspaceRootPath":null}""");
        var legacy = await new WorkbenchSettingsStore(legacyPath).LoadAsync();
        Require(legacy.TrafficWindowCount == NetMindDefaults.DefaultTrafficWindowCount &&
                legacy.PageHookWindowCount == NetMindDefaults.DefaultPageHookWindowCount &&
                legacy.AiEvidenceMaximumTransactions == NetMindDefaults.DefaultAiEvidenceMaximumTransactions,
            "V2 旧设置文件必须能加载，缺失的新字段按默认值补齐");

        Require(!defaults.UseSilentCapture, "静默抓包开关默认必须关闭（走回环代理模式）");
        await store.SaveAsync(custom with { UseSilentCapture = true });
        Require((await store.LoadAsync()).UseSilentCapture, "静默抓包开关必须可经设置文件往返持久化");

        var browserProfile = new BrowserEnvironmentProfile(true,
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
            ScreenWidth: 2560, ScreenHeight: 1440, DeviceScaleFactor: 1.25, HardwareConcurrency: 8);
        await store.SaveAsync(custom with { BrowserEnvironment = browserProfile });
        var browserSettings = await store.LoadAsync();
        Require(browserSettings.BrowserEnvironment == browserProfile && browserSettings.BrowserEnvironment.Summary.Contains("2560×1440", StringComparison.Ordinal),
            "浏览器测试画像必须可经设置文件完整往返");

        foreach (var invalid in new[]
        {
            new WorkbenchSettings(ListenPort: 80),
            new WorkbenchSettings(ListenPort: 70000),
            new WorkbenchSettings(WorkspaceRootPath: Path.GetPathRoot(settingsRoot)),
            // 条数越界必须显式报错，不能静默夹取——否则用户填了 5000 却按 2000 跑，会以为设置没生效。
            new WorkbenchSettings(TrafficWindowCount: NetMindDefaults.MinimumTrafficWindowCount - 1),
            new WorkbenchSettings(TrafficWindowCount: NetMindDefaults.MaximumTrafficWindowCount + 1),
            new WorkbenchSettings(SessionWindowCount: NetMindDefaults.MaximumSessionWindowCount + 1),
            new WorkbenchSettings(PageHookWindowCount: NetMindDefaults.MinimumPageHookWindowCount - 1),
            new WorkbenchSettings(AiEvidenceMaximumTransactions: 0),
            new WorkbenchSettings(AiEvidenceMaximumTransactions: NetMindDefaults.AiMaximumEvidenceTransactions + 1),
            new WorkbenchSettings(RefreshIntervalMilliseconds: NetMindDefaults.MinimumRefreshIntervalMilliseconds - 1)
        })
        {
            var rejected = false;
            try { invalid.Validate(); }
            catch (InvalidOperationException exception) { rejected = exception.Message.Length > 0; }
            Require(rejected, "越界设置值必须被拒绝并给出中文错误消息");
        }

        await File.WriteAllTextAsync(settingsPath, "{ 损坏的 JSON");
        var corruptRejected = false;
        try { await store.LoadAsync(); }
        catch (InvalidDataException exception) { corruptRejected = exception.Message.Contains("工作台设置文件格式无效", StringComparison.Ordinal); }
        Require(corruptRejected, "损坏的设置文件必须抛出中文 InvalidDataException");
    }
    finally
    {
        if (Directory.Exists(settingsRoot)) Directory.Delete(settingsRoot, recursive: true);
    }
}

static async Task VerifySystemProxySentinelAsync()
{
    // 纯逻辑验证：只测快照 JSON 往返、哨兵文件原子读写、注册表值映射与回读校验谓词，
    // 严禁调用 Apply/Restore 触碰真实系统代理。
    var sentinelRoot = Path.Combine(Path.GetTempPath(), "netmind-sysproxy-test-" + Guid.NewGuid().ToString("N"));
    try
    {
        var snapshot = new SystemProxySnapshot(11, "proxy.example.test:8080", NetMindDefaults.SystemProxyLocalBypass);
        Require(SystemProxySnapshot.FromJson(snapshot.ToJson()) == snapshot, "系统代理快照必须支持 JSON 序列化往返");
        var emptySnapshot = new SystemProxySnapshot(1, null, null);
        Require(SystemProxySnapshot.FromJson(emptySnapshot.ToJson()) == emptySnapshot, "无代理服务器/绕过列表的快照必须可空值往返");
        var invalidRejected = false;
        try { SystemProxySnapshot.FromJson("{ 损坏的 JSON"); }
        catch (InvalidDataException exception) { invalidRejected = exception.Message.Contains("系统代理快照文件格式无效", StringComparison.Ordinal); }
        Require(invalidRejected, "损坏的快照必须抛出中文 InvalidDataException");

        // 注册表值 ↔ 快照映射：启用代理时 flags 含显式代理位，且快照往返还原逐字段一致。
        var baseline = SystemProxyAutomation.SnapshotFromRegistryValues(1, "127.0.0.1:3067", NetMindDefaults.SystemProxyLocalBypass);
        Require((baseline.Flags & SystemProxyAutomation.ProxyTypeProxy) != 0, "ProxyEnable=1 的快照必须含显式代理标志位");
        var (restoredEnable, restoredServer, restoredBypass) = SystemProxyAutomation.RestoreTargetsFromSnapshot(baseline);
        Require(restoredEnable == 1 && restoredServer == "127.0.0.1:3067" && restoredBypass == NetMindDefaults.SystemProxyLocalBypass,
            "快照到注册表的还原映射必须逐字段往返一致");

        // 直连快照：还原时 ProxyEnable=0，且快照中原值缺失的 ProxyServer/ProxyOverride 保持“值不存在”语义（不得被写成空串）。
        var direct = SystemProxyAutomation.SnapshotFromRegistryValues(0, null, null);
        Require((direct.Flags & SystemProxyAutomation.ProxyTypeProxy) == 0, "ProxyEnable=0 的快照不得含显式代理标志位");
        var (directEnable, directServer, directBypass) = SystemProxyAutomation.RestoreTargetsFromSnapshot(direct);
        Require(directEnable == 0 && directServer is null && directBypass is null,
            "直连快照还原时必须保留空值语义，是否清空 ProxyServer 以快照原值为准");

        // 接管目标映射：启用代理、地址原样、空绕过列表按“值不存在”处理。
        var (applyEnable, applyServer, applyBypass) = SystemProxyAutomation.ApplyTargets("127.0.0.1:8877", null);
        Require(applyEnable == 1 && applyServer == "127.0.0.1:8877" && applyBypass is null, "接管目标映射必须启用代理并保留空绕过列表语义");

        // 注册表回读校验谓词：目标一致即通过，错值（如被截断成单字符）必须判不一致。
        Require(SystemProxyAutomation.RegistryValuesMatch(1, "127.0.0.1:8877", NetMindDefaults.SystemProxyLocalBypass, 1, "127.0.0.1:8877", NetMindDefaults.SystemProxyLocalBypass),
            "注册表回读与目标完全一致时校验必须通过");
        Require(!SystemProxyAutomation.RegistryValuesMatch(1, "1", NetMindDefaults.SystemProxyLocalBypass, 1, "127.0.0.1:8877", NetMindDefaults.SystemProxyLocalBypass),
            "代理地址被写错（如截断成单字符）时回读校验必须判不一致");
        Require(!SystemProxyAutomation.RegistryValuesMatch(0, "127.0.0.1:8877", null, 1, "127.0.0.1:8877", null),
            "ProxyEnable 与目标不一致时回读校验必须判不一致");
        Require(SystemProxyAutomation.RegistryValuesMatch(0, null, null, 0, null, null),
            "直连且无附加值时回读校验必须通过");

        var sentinelPath = Path.Combine(sentinelRoot, NetMindDefaults.SystemProxySentinelFileName);
        Require(await SystemProxySentinel.TryReadAsync(sentinelPath) is null, "哨兵文件缺失时必须返回空");
        await SystemProxySentinel.WriteAsync(sentinelPath, snapshot);
        Require(!Directory.EnumerateFiles(sentinelRoot).Any(file => file.Contains(".tmp-", StringComparison.Ordinal)), "哨兵原子写不得残留临时文件");
        Require(await SystemProxySentinel.TryReadAsync(sentinelPath) == snapshot, "哨兵文件必须可完整往返读取");

        await File.WriteAllTextAsync(sentinelPath, "{ 损坏的 JSON");
        Require(await SystemProxySentinel.TryReadAsync(sentinelPath) is null, "损坏的哨兵文件必须按缺失处理");

        SystemProxySentinel.Delete(sentinelPath);
        Require(!File.Exists(sentinelPath), "还原后哨兵文件必须删除");
        SystemProxySentinel.Delete(sentinelPath); // 重复删除不得抛异常
    }
    finally
    {
        if (Directory.Exists(sentinelRoot)) Directory.Delete(sentinelRoot, recursive: true);
    }
}

static async Task VerifyAiAnalysisHistoryAsync()
{
    var root = Path.Combine(Path.GetTempPath(), "netmind-ai-history-test-" + Guid.NewGuid().ToString("N"));
    var otherRoot = root + "-other";
    try
    {
        await new WorkspaceStore(root).InitializeAsync("AI 历史测试工作区");
        await new WorkspaceStore(otherRoot).InitializeAsync("隔离工作区");
        var transactionIds = new[] { Guid.NewGuid(), Guid.NewGuid() };
        var metadata = new AiAnalysisHistoryMetadata(
            Guid.NewGuid(), DateTimeOffset.UtcNow, "api.example.test", "test-model", "chat_completions", "high", 4096,
            "记录组：登录链路", transactionIds, "response-test", 321, 654, "stop", 1200);
        var entry = new AiAnalysisHistoryEntry(metadata, "[{\"cookies\":\"[REDACTED]\"}]", "# 结论\n\n仅基于脱敏证据。");
        var store = new AiAnalysisHistoryStore(root);
        await store.SaveAsync(entry);

        var summary = (await store.GetRecentAsync()).Single();
        Require(summary.Id == metadata.Id && summary.TransactionIds.SequenceEqual(transactionIds), "AI 历史索引必须保留精确事务引用");
        var restored = await store.LoadAsync(metadata.Id);
        Require(restored is not null && restored.EvidenceJson.Contains("[REDACTED]") && restored.ResultMarkdown == entry.ResultMarkdown, "AI 历史必须恢复证据快照和 Markdown 结果");
        var exported = AiAnalysisExportFormatter.BuildMarkdown(restored!);
        Require(exported.StartsWith("# NetMind AI 分析结果", StringComparison.Ordinal) && exported.Contains("历史结果", StringComparison.Ordinal) == false && exported.Contains("# 结论", StringComparison.Ordinal), "Markdown 导出必须包含元数据标题和原始分析结果");
        Require((await new AiAnalysisHistoryStore(otherRoot).GetRecentAsync()).Count == 0, "AI 历史必须按工作区隔离");

        var invalidRejected = false;
        try
        {
            await store.SaveAsync(entry with
            {
                Metadata = metadata with { Id = Guid.NewGuid(), TransactionIds = Enumerable.Range(0, NetMindDefaults.AiMaximumEvidenceTransactions + 1).Select(_ => Guid.NewGuid()).ToArray() }
            });
        }
        catch (InvalidDataException) { invalidRejected = true; }
        Require(invalidRejected, $"AI 历史必须拒绝超过 {NetMindDefaults.AiMaximumEvidenceTransactions} 条的事务引用");
        Require(store.Delete(metadata.Id) && await store.LoadAsync(metadata.Id) is null, "删除 AI 历史必须移除完整条目目录");
    }
    finally
    {
        if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        if (Directory.Exists(otherRoot)) Directory.Delete(otherRoot, recursive: true);
    }
}

static async Task VerifyWorkspaceCatalogAsync()
{
    var root = Path.Combine(Path.GetTempPath(), "netmind-workspace-test-" + Guid.NewGuid().ToString("N"));
    try
    {
        var catalog = new WorkspaceCatalog(root);
        var first = await catalog.CreateAsync("项目甲");
        var second = await catalog.CreateAsync("项目乙");
        Require(first.Id != second.Id && Directory.Exists(first.Path) && Directory.Exists(second.Path), "不同工作区必须使用独立目录");
        await catalog.SetCurrentAsync(second);
        Require((await catalog.GetCurrentAsync())?.Id == second.Id, "当前工作区选择必须持久化");

        var renamed = await catalog.RenameAsync(second, "项目乙-复测");
        Require(renamed.Manifest.Name == "项目乙-复测" && renamed.Path == second.Path, "重命名不得迁移或重建工作区目录");
        await catalog.SetCurrentAsync(renamed);
        Require((await catalog.GetAllAsync()).Count == 2, "工作区目录索引必须发现全部有效工作区");

        using (var firstArchive = new TrafficArchive(first.Path))
        {
            var session = new CaptureSessionRecord(Guid.NewGuid(), DateTimeOffset.UtcNow, null, NetMindDefaults.SourceRealProxy, "项目甲", NetMindDefaults.SessionStateRunning);
            await firstArchive.StartSessionAsync(session);
            var item = new TrafficRecord(Guid.NewGuid(), DateTimeOffset.UtcNow, "GET", "/only-first", 200, 1, 0, "test.exe · 1", "HTTP/1.1", "", "");
            await firstArchive.RecordAsync(session.Id, item, Array.Empty<byte>(), Array.Empty<byte>());
        }
        using var firstRead = new TrafficArchive(first.Path);
        using var secondRead = new TrafficArchive(second.Path);
        Require(firstRead.GetTrafficCount() == 1 && secondRead.GetTrafficCount() == 0, "流量数据库必须按工作区完全隔离");

        var invalidRejected = false;
        try { await catalog.CreateAsync(" "); }
        catch (InvalidOperationException) { invalidRejected = true; }
        Require(invalidRejected, "工作区必须拒绝空名称");
    }
    finally
    {
        if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
    }
}

static async Task VerifyWorkspaceDataManagementAsync()
{
    var root = Path.Combine(Path.GetTempPath(), "netmind-data-test-" + Guid.NewGuid().ToString("N"));
    var importRoot = Path.Combine(Path.GetTempPath(), "netmind-data-import-" + Guid.NewGuid().ToString("N"));
    var backupPath = Path.Combine(Path.GetTempPath(), "netmind-data-backup-" + Guid.NewGuid().ToString("N") + ".zip");
    var maliciousPath = Path.Combine(Path.GetTempPath(), "netmind-data-malicious-" + Guid.NewGuid().ToString("N") + ".zip");
    try
    {
        await new WorkspaceStore(root).InitializeAsync("数据治理项目");
        var sessionId = Guid.NewGuid();
        using (var archive = new TrafficArchive(root))
        {
            await archive.StartSessionAsync(new CaptureSessionRecord(sessionId, DateTimeOffset.UtcNow.AddDays(-80),
                DateTimeOffset.UtcNow, NetMindDefaults.SourceRealProxy, "all", NetMindDefaults.SessionStateCompleted));
            foreach (var (timestamp, endpoint, payload) in new[]
                     {
                         (DateTimeOffset.UtcNow.AddDays(-70), "/old-a", "old-a"),
                         (DateTimeOffset.UtcNow.AddDays(-60), "/old-b", "old-b"),
                         (DateTimeOffset.UtcNow, "/current", "current")
                     })
            {
                var traffic = new TrafficRecord(Guid.NewGuid(), timestamp, "POST", endpoint, 200, 5, payload.Length,
                    "test.exe · 1", "HTTP/1.1", payload, payload, "https://example.test" + endpoint);
                await archive.RecordAsync(sessionId, traffic, Encoding.UTF8.GetBytes(payload), Encoding.UTF8.GetBytes(payload));
            }
            await archive.RecordPageHooksAsync([
                new PageHookEvent(0, sessionId, DateTimeOffset.UtcNow.AddDays(-70), "fetch", "old", "https://example.test", "[]"),
                new PageHookEvent(0, sessionId, DateTimeOffset.UtcNow, "fetch", "current", "https://example.test", "[]")
            ]);
        }
        var orphanHash = await new WorkspaceStore(root).StoreBlobAsync(Encoding.UTF8.GetBytes("unreferenced-orphan"));
        var orphanPath = Path.Combine(root, NetMindDefaults.BlobsDirectoryName, orphanHash[..2], orphanHash);
        Require(File.Exists(orphanPath), "测试前必须建立未引用 Blob");

        var policyStore = new WorkspaceDataPolicyStore(root);
        await policyStore.SaveAsync(new WorkspaceDataPolicy(30, 0));
        Require((await policyStore.LoadAsync()).RetentionDays == 30, "工作区数据策略必须原子保存并可回读");
        var before = WorkspaceDataMaintenance.GetStatistics(root);
        Require(before.TrafficCount == 3 && before.PageHookCount == 2 && before.BlobFileCount >= 4,
            "整理前统计必须包含事务、Hook 与正文 Blob");
        var maintenance = await WorkspaceDataMaintenance.RunAsync(root, await policyStore.LoadAsync());
        Require(maintenance.DeletedTransactions == 2 && maintenance.DeletedPageHooks == 1 &&
                maintenance.After.TrafficCount == 1 && maintenance.After.PageHookCount == 1,
            "30 天保留策略必须只删除截止时间前的事务与 Hook");
        Require(!File.Exists(orphanPath) && maintenance.DeletedOrphanBlobs >= 1,
            "整理必须删除 SQLite 未引用的合法内容寻址 Blob");

        var conversationDirectory = Path.Combine(root, NetMindDefaults.AiConversationsDirectoryName);
        Directory.CreateDirectory(conversationDirectory);
        await File.WriteAllTextAsync(Path.Combine(conversationDirectory, "unicode-evidence.txt"), "中文证据往返");
        var exported = await WorkspaceBackup.ExportAsync(root, backupPath);
        Require(exported.FileCount > 0 && File.Exists(backupPath), "工作区备份必须生成原子 ZIP 文件");
        using (var zip = ZipFile.OpenRead(backupPath))
        {
            Require(zip.GetEntry(NetMindDefaults.WorkspaceBackupManifestFileName) is not null &&
                    zip.GetEntry("workspace/metadata.db") is not null &&
                    zip.GetEntry("workspace/ai-conversations/unicode-evidence.txt") is not null,
                "备份必须包含格式清单、SQLite、正文与 AI 会话文件");
        }
        var imported = await WorkspaceBackup.ImportAsync(backupPath, importRoot);
        Require(imported.Manifest.Name.EndsWith("（导入）", StringComparison.Ordinal) && Directory.Exists(imported.Path),
            "导入必须创建独立的新工作区且不覆盖当前项目");
        using (var importedArchive = new TrafficArchive(imported.Path))
            Require(importedArchive.GetTrafficCount() == 1 && importedArchive.GetPageHooks(limit: 10).Count == 1,
                "备份导入后 SQLite 事务与 Hook 必须完整可读");
        Require(await File.ReadAllTextAsync(Path.Combine(imported.Path, NetMindDefaults.AiConversationsDirectoryName, "unicode-evidence.txt")) == "中文证据往返",
            "备份导入必须逐字节恢复 Unicode 会话证据");

        await using (var file = new FileStream(maliciousPath, FileMode.CreateNew, FileAccess.ReadWrite))
        using (var zip = new ZipArchive(file, ZipArchiveMode.Create))
        {
            await using (var manifest = new StreamWriter(zip.CreateEntry(NetMindDefaults.WorkspaceBackupManifestFileName).Open(), Encoding.UTF8, leaveOpen: false))
                await manifest.WriteAsync("{\"format\":\"netmind.workspace-backup\",\"version\":1}");
            await using (var workspaceManifest = new StreamWriter(zip.CreateEntry("workspace/workspace.json").Open(), Encoding.UTF8, leaveOpen: false))
                await workspaceManifest.WriteAsync(JsonSerializer.Serialize(new WorkspaceManifest("恶意备份", 1, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow)));
            await using var traversal = new StreamWriter(zip.CreateEntry("workspace/../../escape.txt").Open(), Encoding.UTF8, leaveOpen: false);
            await traversal.WriteAsync("escape");
        }
        var traversalRejected = false;
        try { await WorkspaceBackup.ImportAsync(maliciousPath, importRoot); }
        catch (InvalidDataException) { traversalRejected = true; }
        Require(traversalRejected && !File.Exists(Path.Combine(Path.GetDirectoryName(importRoot)!, "escape.txt")),
            "工作区备份导入必须拒绝 ZIP 路径穿越且不得在根目录外落盘");
    }
    finally
    {
        if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        if (Directory.Exists(importRoot)) Directory.Delete(importRoot, recursive: true);
        if (File.Exists(backupPath)) File.Delete(backupPath);
        if (File.Exists(maliciousPath)) File.Delete(maliciousPath);
    }
}

static async Task VerifyTrafficGroupsAsync()
{
    var root = Path.Combine(Path.GetTempPath(), "netmind-group-test-" + Guid.NewGuid().ToString("N"));
    try
    {
        await new WorkspaceStore(root).InitializeAsync("记录组定向测试工作区");
        using var archive = new TrafficArchive(root);
        var session = new CaptureSessionRecord(Guid.NewGuid(), DateTimeOffset.UtcNow, null, NetMindDefaults.SourceRealProxy, "定向测试", NetMindDefaults.SessionStateRunning);
        await archive.StartSessionAsync(session);
        var traffic = new[]
        {
            new TrafficRecord(Guid.NewGuid(), DateTimeOffset.UtcNow.AddSeconds(1), "POST", "/group/1?token=owner-secret", 201,
                12, 48, "test.exe · 1", "HTTP/1.1", "json request", "json response",
                "http://example.test/group/1?token=owner-secret&name=%E6%B5%8B%E8%AF%95", "token = owner-secret\nname = 测试",
                "Content-Type: application/json; charset=utf-8\nAuthorization: Bearer owner-secret\nCookie: session=owner-cookie",
                "session = owner-cookie", "Content-Type: application/json; charset=utf-8\nSet-Cookie: result=accepted; Path=/"),
            new TrafficRecord(Guid.NewGuid(), DateTimeOffset.UtcNow.AddSeconds(2), "GET", "/group/2", 200,
                8, 5, "test.exe · 1", "HTTP/2（静默）", "binary request", "binary response",
                "https://example.test/group/2", string.Empty, "Accept: application/octet-stream", string.Empty,
                "Content-Type: application/octet-stream"),
            new TrafficRecord(Guid.NewGuid(), DateTimeOffset.UtcNow.AddSeconds(3), "GET", "/group/3", 204,
                4, 20, "test.exe · 1", "HTTP/1.1", "text request", "text response",
                "http://example.test/group/3", string.Empty, "Accept: text/plain", string.Empty,
                "Content-Type: text/plain; charset=utf-8")
        };
        var requestBodies = new[]
        {
            Encoding.UTF8.GetBytes("{\"account\":\"owner\",\"password\":\"secret\"}"),
            Array.Empty<byte>(),
            Encoding.UTF8.GetBytes("request-3")
        };
        var responseBodies = new[]
        {
            Encoding.UTF8.GetBytes("{\"ok\":true,\"message\":\"完整响应\"}"),
            new byte[] { 0, 1, 2, 3, 254, 255 },
            Encoding.UTF8.GetBytes("response-3")
        };
        for (var index = 0; index < traffic.Length; index++)
            await archive.RecordAsync(session.Id, traffic[index], requestBodies[index], responseBodies[index]);

        var now = DateTimeOffset.UtcNow;
        var group = new TrafficGroup(Guid.NewGuid(), "登录链路", "用于复现登录请求", now, now, traffic.Take(2).Select(item => item.Id).ToArray());
        var store = new TrafficGroupStore(root);
        await store.SaveAsync(group);
        var restoredGroup = (await store.GetAllAsync()).Single();
        Require(restoredGroup.Name == "登录链路" && restoredGroup.TrafficIds.Count == 2, "记录组必须完整持久化名称、说明和事务引用");
        var restoredTraffic = archive.GetTrafficByIds(restoredGroup.TrafficIds);
        Require(restoredTraffic.Count == 2 && restoredTraffic.All(item => restoredGroup.TrafficIds.Contains(item.Traffic.Id)), "记录组必须按事务 ID 精确恢复历史记录");

        var updated = restoredGroup with { UpdatedAt = DateTimeOffset.UtcNow.AddSeconds(1), TrafficIds = traffic.Select(item => item.Id).ToArray() };
        await store.SaveAsync(updated);
        Require((await store.GetAllAsync()).Single().TrafficIds.Count == 3, "记录组成员更新必须持久化");

        var exportGroup = updated with { TrafficIds = updated.TrafficIds.Append(Guid.NewGuid()).ToArray() };
        var zipPath = Path.Combine(root, "export", "登录链路.zip");
        var zipResult = await TrafficGroupExporter.ExportZipAsync(root, exportGroup, zipPath);
        Require(zipResult.ExportedTransactions == 3 && zipResult.MissingTransactions == 1 && File.Exists(zipPath),
            "ZIP 导出必须包含全部可用事务并明确报告缺失引用");
        using (var zip = ZipFile.OpenRead(zipPath))
        {
            Require(zip.GetEntry("manifest.json") is not null && zip.GetEntry("transactions.json") is not null &&
                    zip.GetEntry("traffic-group.har") is not null && zip.GetEntry("README.txt") is not null,
                "完整记录组包必须包含清单、事务索引、HAR 与说明");
            var manifestEntry = zip.GetEntry("manifest.json")!;
            using (var manifestStream = manifestEntry.Open())
            using (var manifest = await JsonDocument.ParseAsync(manifestStream))
                Require(manifest.RootElement.GetProperty("format").GetString() == "netmind-traffic-group" &&
                        manifest.RootElement.GetProperty("missingTransactionIds").GetArrayLength() == 1,
                    "ZIP 清单必须声明格式并列出缺失事务 ID");

            var transactionEntry = zip.GetEntry("transactions.json")!;
            using (var reader = new StreamReader(transactionEntry.Open(), Encoding.UTF8))
            {
                var transactionJson = await reader.ReadToEndAsync();
                Require(transactionJson.Contains("Bearer owner-secret", StringComparison.Ordinal) &&
                        transactionJson.Contains("requestBody", StringComparison.Ordinal),
                    "本地所有者完整包不得丢失原始 Header 或正文引用");
            }

            var firstStored = archive.GetTrafficByIds([traffic[0].Id]).Single();
            var requestBlobPath = $"blobs/{firstStored.RequestBlobHash[..2]}/{firstStored.RequestBlobHash}.bin";
            var requestBlobEntry = zip.GetEntry(requestBlobPath);
            Require(requestBlobEntry is not null, "完整记录组包必须按 SHA-256 保存原始正文 Blob");
            using (var body = new MemoryStream())
            {
                await using var source = requestBlobEntry!.Open();
                await source.CopyToAsync(body);
                Require(body.ToArray().SequenceEqual(requestBodies[0]), "ZIP 中请求正文必须逐字节完整，不得截断或改写");
            }

            await using var embeddedHarStream = zip.GetEntry("traffic-group.har")!.Open();
            using var embeddedHar = await JsonDocument.ParseAsync(embeddedHarStream);
            Require(embeddedHar.RootElement.GetProperty("log").GetProperty("version").GetString() == "1.2" &&
                    embeddedHar.RootElement.GetProperty("log").GetProperty("entries").GetArrayLength() == 3,
                "ZIP 内置 HAR 必须是包含全组事务的 HAR 1.2");
        }

        var harPath = Path.Combine(root, "export", "登录链路.har");
        var harResult = await TrafficGroupExporter.ExportHarAsync(root, updated, harPath);
        Require(harResult.ExportedTransactions == 3 && harResult.MissingTransactions == 0, "独立 HAR 导出数量必须准确");
        await using (var harStream = File.OpenRead(harPath))
        using (var har = await JsonDocument.ParseAsync(harStream))
        {
            var entries = har.RootElement.GetProperty("log").GetProperty("entries");
            Require(entries[0].GetProperty("request").GetProperty("queryString")[1].GetProperty("value").GetString() == "测试",
                "HAR 查询参数必须按标准 name/value 结构解码保存");
            var binaryContent = entries[1].GetProperty("response").GetProperty("content");
            Require(binaryContent.GetProperty("encoding").GetString() == "base64" &&
                    Convert.FromBase64String(binaryContent.GetProperty("text").GetString()!).SequenceEqual(responseBodies[1]),
                "HAR 二进制响应必须以 Base64 完整保存");
            Require(entries[0].GetProperty("_netmind").GetProperty("requestBodySha256").GetString()?.Length == 64,
                "HAR 必须保留 NetMind 事务与正文哈希溯源信息");
        }

        Require(store.Delete(group.Id) && (await store.GetAllAsync()).Count == 0, "删除记录组不得残留分组文件");

        var invalidRejected = false;
        try { await store.SaveAsync(group with { Id = Guid.NewGuid(), Name = " " }); }
        catch (InvalidDataException) { invalidRejected = true; }
        Require(invalidRejected, "记录组必须拒绝空名称");
    }
    finally
    {
        if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
    }
}

static void VerifyCaptureBrowserPlan(string testRoot)
{
    var profilePath = Path.Combine(testRoot, "浏览器配置");
    var keyLogPath = Path.Combine(testRoot, NetMindDefaults.SilentKeyLogRelativePath);
    var plan = CaptureBrowser.BuildPlan("测试浏览器", Path.Combine(testRoot, "browser.exe"), profilePath,
        new IPEndPoint(IPAddress.Loopback, NetMindDefaults.ListenPort), keyLogPath: keyLogPath);
    Require(plan.ProfilePath == Path.GetFullPath(profilePath), "采集浏览器必须使用独立配置目录");
    Require(plan.Arguments.Contains($"--proxy-server=http={NetMindDefaults.DefaultListenEndpoint};https={NetMindDefaults.DefaultListenEndpoint}"), "采集浏览器必须同时设置 HTTP 与 HTTPS 代理");
    Require(plan.Arguments.Contains("--disable-quic"), "采集浏览器必须关闭 QUIC 以确保 HTTPS 进入代理隧道");
    Require(plan.Arguments.Contains("--disable-http-cache"), "采集浏览器必须禁用 HTTP 磁盘缓存，否则缓存命中的静态资源不走网络无法捕获");
    Require(plan.Arguments.Contains("--proxy-bypass-list=127.0.0.1;localhost;[::1]"),
        "采集浏览器必须让页内 Hook 回环上报绕过流量代理");
    Require(plan.Environment.TryGetValue(NetMindDefaults.SslKeyLogFileEnvironmentVariable, out var envKeyLog)
        && envKeyLog == Path.GetFullPath(keyLogPath),
        "采集浏览器必须注入指向工作区约定路径的 SSLKEYLOGFILE 环境变量");

    var environmentProfile = new BrowserEnvironmentProfile(true,
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
        ScreenWidth: 2560, ScreenHeight: 1440, DeviceScaleFactor: 1.25, HardwareConcurrency: 8);
    var profiled = CaptureBrowser.BuildPlan("测试浏览器", Path.Combine(testRoot, "browser.exe"), profilePath,
        new IPEndPoint(IPAddress.Loopback, NetMindDefaults.ListenPort), remoteDebuggingPort: 9222,
        environmentProfile: environmentProfile);
    Require(profiled.Arguments.Contains("--window-size=2560,1440") &&
            profiled.Arguments.Contains("--force-device-scale-factor=1.25") &&
            profiled.Arguments.Contains("--force-webrtc-ip-handling-policy=disable_non_proxied_udp") &&
            profiled.Arguments.Any(argument => argument.StartsWith("--user-agent=Mozilla/5.0", StringComparison.Ordinal)),
        "采集浏览器测试画像必须映射为一致的 Chromium 启动参数");

    var silent = CaptureBrowser.BuildPlan("测试浏览器", Path.Combine(testRoot, "browser.exe"), profilePath,
        new IPEndPoint(IPAddress.Loopback, NetMindDefaults.ListenPort), useProxy: false);
    Require(silent.Arguments.All(argument => !argument.StartsWith("--proxy-server=", StringComparison.Ordinal)),
        "静默抓包浏览器不得连接不存在的显式代理端口");
}

static void Require(bool condition, string message)
{
    if (!condition) throw new InvalidOperationException(message);
}

/// <summary>
/// 编辑器文本变换：注释切换、整理格式、折叠区域识别，以及 AI 代写提示词与回复解析。
///
/// 这些函数直接改用户写了一半的脚本，改坏就是数据损坏，所以断言重点是
/// 「不该动的一个字符都别动」——尤其是三引号字符串内部与行首之后的空白。
/// </summary>
static void VerifyScriptTextTools()
{
    // ── 注释切换 ──
    var block = "def probe(event):\n    url = event.get('url')\n    return None";
    var commented = ScriptTextTools.ToggleComment(block, 1, 2);
    Require(commented == "def probe(event):\n    # url = event.get('url')\n    # return None",
        "注释符必须插在这批行的最小缩进处，而不是行首，否则 Python 缩进结构会被破坏：\n" + commented);
    Require(ScriptTextTools.ToggleComment(commented, 1, 2) == block, "再切换一次必须精确还原原文");

    var mixedIndent = "if a:\n        deep = 1\n    shallow = 2";
    var mixed = ScriptTextTools.ToggleComment(mixedIndent, 1, 2);
    Require(mixed == "if a:\n    #     deep = 1\n    # shallow = 2",
        "缩进不一致时注释符必须统一插在最小缩进列，保持相对缩进不变：\n" + mixed);
    Require(ScriptTextTools.ToggleComment(mixed, 1, 2) == mixedIndent, "不同缩进的整体取消注释必须还原原文");

    var withBlank = "a = 1\n\nb = 2";
    Require(ScriptTextTools.ToggleComment(withBlank, 0, 2) == "# a = 1\n\n# b = 2", "空行不得被加上注释符");

    var partial = "# already\nnot_yet = 1";
    Require(ScriptTextTools.ToggleComment(partial, 0, 1) == "# # already\n# not_yet = 1",
        "只要有一行未注释就整体注释（与主流编辑器一致），而不是逐行反转");
    Require(ScriptTextTools.ToggleComment("#no space", 0, 0) == "no space", "取消注释只吃掉一个紧跟的空格");
    Require(ScriptTextTools.ToggleComment("    #   对齐注释", 0, 0) == "    #   对齐注释".Replace("#   ", "  ", StringComparison.Ordinal),
        "取消注释不得吞掉用于对齐的多余空格");

    // ── 整理格式：只做不改变语义的事 ──
    Require(ScriptTextTools.Format("\tx = 1") == "    x = 1", "行首制表符必须展开为 4 空格");
    Require(ScriptTextTools.Format("x = 1   ") == "x = 1", "行尾空白必须去掉");
    Require(ScriptTextTools.Format("a = 1\n\n\n\n\nb = 2") == "a = 1\n\n\nb = 2", "连续空行必须压到最多两行");
    Require(ScriptTextTools.Format("\n\n\na = 1\n\n\n") == "a = 1", "首尾空行必须清掉，结尾不留多余换行");
    Require(ScriptTextTools.Format("s = 'a\tb'") == "s = 'a\tb'", "行首之后的制表符属于数据，绝不能改");
    Require(ScriptTextTools.Format("x = 1 + 1") == "x = 1 + 1", "整理格式不得重排运算符空格");

    const string docstring = "def f():\n    \"\"\"说明   \n\ttab 开头   \n\n\n\n    仍在字符串里   \n    \"\"\"\n    return 1";
    Require(ScriptTextTools.Format(docstring) == docstring,
        "三引号字符串内部是数据，行尾空白/制表符/连续空行一律不得改动：\n" + ScriptTextTools.Format(docstring));
    Require(ScriptTextTools.Format(ScriptTextTools.Format(docstring)) == ScriptTextTools.Format(docstring),
        "整理格式必须幂等");

    // ── 折叠区域 ──
    const string foldable = "import json\n\ndef outer(event):\n    if event:\n        value = 1\n        return value\n    return None\n\nx = 2";
    var regions = ScriptTextTools.FindFoldRegions(foldable);
    Require(regions.Any(region => region.Header == 2 && region.End == 6),
        "def 区域必须覆盖到最后一行缩进体（不含其后的空行与顶层语句）");
    Require(regions.Any(region => region.Header == 3 && region.End == 5), "嵌套 if 也应识别为可折叠区域");
    Require(ScriptTextTools.FindFoldRegions("def f():\n    return 1").Count == 0,
        "只有一行体的区域不值得折叠，必须不返回");
    Require(ScriptTextTools.FindFoldRegions("# def fake():\n    x = 1").Count == 0, "注释掉的行不得识别为折叠头");
    var innermost = ScriptTextTools.FindFoldRegionAt(foldable, 4);
    Require(innermost is { Header: 3 }, "定位折叠区域必须取包含该行的最内层区域");

    // 折叠还原必须无损：把区域体摘掉再拼回去要与原文逐字节一致。
    foreach (var region in regions)
    {
        var lines = foldable.Split('\n');
        var hidden = string.Join('\n', lines.Skip(region.Header + 1).Take(region.End - region.Header));
        var restored = string.Join('\n', lines.Take(region.Header + 1).Append(hidden).Concat(lines.Skip(region.End + 1)));
        Require(restored == foldable, $"折叠区域 [{region.Header},{region.End}] 还原后与原文不一致");
    }

    // ── AI 代写：提示词与回复解析 ──
    var hookPrompt = HookScriptApi.BuildAuthoringSystemPrompt(ScriptPurpose.Hook);
    foreach (var required in new[]
             {
                 HookEventNames.FunctionBeforeSend, HookEventNames.RequestBeforeSend, "INTERCEPT",
                 "subprocess", "open()", NetMindDefaults.HookBodyPreviewFieldName,
                 NetMindDefaults.HookEventTimeoutMilliseconds.ToString(System.Globalization.CultureInfo.InvariantCulture)
             })
        Require(hookPrompt.Contains(required, StringComparison.Ordinal), $"钩子代写提示词缺少关键约束 {required}");
    foreach (var field in HookScriptApi.EventFields)
        Require(hookPrompt.Contains(field.Name, StringComparison.Ordinal),
            $"钩子代写提示词必须列出信封字段 {field.Name}，否则模型会臆造字段名");

    var fixturePrompt = HookScriptApi.BuildAuthoringSystemPrompt(ScriptPurpose.Fixture);
    Require(fixturePrompt.Contains("fixture.transactions", StringComparison.Ordinal), "验证脚本提示词必须说明输入来源");
    Require(!fixturePrompt.Contains("INTERCEPT", StringComparison.Ordinal), "验证脚本提示词不应混入钩子专属的拦截契约");
    foreach (var field in HookScriptApi.FixtureFields)
        Require(fixturePrompt.Contains(field.Name, StringComparison.Ordinal), $"验证脚本提示词必须列出事务字段 {field.Name}");

    Require(HookScriptApi.ExtractPythonCode("说明文字\n```python\ndef f():\n    return 1\n```\n收尾") == "def f():\n    return 1",
        "必须能从模型回复里取出 ```python 围栏内的代码");
    Require(HookScriptApi.ExtractPythonCode("```\nx = 1\n```") == "x = 1", "无语言标注的围栏同样要能取出");
    Require(HookScriptApi.ExtractPythonCode("x = 1") == "x = 1", "没有围栏时按纯代码处理");
    Require(HookScriptApi.ExtractPythonCode("   ").Length == 0, "空回复必须得到空字符串而不是异常");
}

/// <summary>
/// 审计日志尾读（<c>AuditLogReader</c>）：真实抓包时脚本的观察结论只经这条路径落盘，
/// 工作台脚本页的「返回数据」列表靠它读回真实结果，读错就等于用户永远看不到脚本到底拦没拦到。
/// </summary>
static async Task VerifyAuditLogReaderAsync()
{
    var root = Path.Combine(Path.GetTempPath(), "netmind-auditreader-" + Guid.NewGuid().ToString("N"));
    try
    {
        var store = new WorkspaceStore(root);
        await store.InitializeAsync("审计尾读定向测试工作区");

        Require((await AuditLogReader.ReadRecentAsync(root, NetMindDefaults.AuditEventHooksFinding, 50)).Count == 0,
            "空日志必须返回空列表，而不是抛异常");

        // 写 3 条目标事件，中间穿插 2 条其他事件——必须按事件名精确过滤，不能把无关审计也算进来。
        for (var index = 0; index < 3; index++)
        {
            await store.AppendAuditAsync("traffic.recorded", new { note = "噪声事件 " + index });
            await store.AppendAuditAsync(NetMindDefaults.AuditEventHooksFinding, new
            {
                @event = "response.before_write",
                txnId = $"txn-{index}",
                hookName = "on_before_write",
                data = new { kind = "probe", ordinal = index },
                truncated = false
            });
        }

        var recent = await AuditLogReader.ReadRecentAsync(root, NetMindDefaults.AuditEventHooksFinding, 50);
        Require(recent.Count == 3, $"必须只命中 3 条 hooks.finding，实际 {recent.Count}（噪声事件必须被过滤掉）");
        Require(recent.All(entry => entry.EventName == NetMindDefaults.AuditEventHooksFinding),
            "返回条目的事件名必须与查询条件一致");
        Require(recent[0].PayloadJson.Contains("txn-0", StringComparison.Ordinal) &&
                recent[^1].PayloadJson.Contains("txn-2", StringComparison.Ordinal),
            "必须按文件中的先后顺序返回（旧的在前、新的在后），调用方按此假设把最新一条插到列表顶部");
        Require(recent.All(entry => entry.PayloadJson.Contains("\"kind\":\"probe\"", StringComparison.Ordinal)),
            "payload 必须是可解析的原始 JSON 文本，字段完整");

        // 容量上限：只保留最近 N 条，且必须是真正最近的那几条（不是文件里随便哪 N 条）。
        var capped = await AuditLogReader.ReadRecentAsync(root, NetMindDefaults.AuditEventHooksFinding, 2);
        Require(capped.Count == 2, "容量上限必须生效");
        Require(capped[0].PayloadJson.Contains("txn-1", StringComparison.Ordinal) &&
                capped[^1].PayloadJson.Contains("txn-2", StringComparison.Ordinal),
            "容量受限时必须保留最新的那几条，而不是文件里最早出现的几条");

        // 手工在文件末尾追加一行损坏数据：单行损坏不能让其余审计条目读不出来。
        var auditPath = Path.Combine(root, "logs", "audit.jsonl");
        await File.AppendAllTextAsync(auditPath, "{ 这不是合法 JSON\n", new UTF8Encoding(false));
        await store.AppendAuditAsync(NetMindDefaults.AuditEventHooksFinding, new
        {
            @event = "response.before_write", txnId = "txn-after-corruption", hookName = "on_before_write",
            data = new { kind = "probe" }, truncated = false
        });
        var afterCorruption = await AuditLogReader.ReadRecentAsync(root, NetMindDefaults.AuditEventHooksFinding, 50);
        Require(afterCorruption.Count == 4, "损坏行必须被跳过，其余包括损坏行之后写入的条目都必须能读到");
        Require(afterCorruption[^1].PayloadJson.Contains("txn-after-corruption", StringComparison.Ordinal),
            "损坏行之后的条目必须能正常读到，不能被前面的坏行拖累整体失败");
    }
    finally
    {
        if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
    }
}

/// <summary>
/// 钩子信封的正文预览按需下发。
///
/// 实测一次 100 个资源的页面加载，带预览要往单线程 Python worker 推约 18.5 MB NDJSON，
/// 而多数观察脚本只用 bodySize/bodySha256。这里断言判定规则本身，防止有人"顺手"改回全量下发。
/// </summary>
static async Task VerifyHookBodyPreviewGateAsync()
{
    var root = Path.Combine(Path.GetTempPath(), "netmind-preview-" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(root);
    try
    {
        async Task<bool> WantsAsync(string script)
        {
            var path = Path.Combine(root, "s-" + Guid.NewGuid().ToString("N") + ".py");
            await File.WriteAllTextAsync(path, script, new UTF8Encoding(false));
            return ScriptHookEngine.ScriptWantsBodyPreview(path);
        }

        Require(!await WantsAsync("def on_before_send(event):\n    return {'size': event.get('bodySize')}"),
            "只用 bodySize 的观察脚本不应触发正文预览下发");
        Require(!await WantsAsync("def on_before_write(event):\n    return {'h': event.get('bodySha256')}"),
            "只用 bodySha256 的脚本不应触发正文预览下发");
        Require(await WantsAsync("def on_before_write(event):\n    return {'b': event.get('bodyPreviewBase64')}"),
            "脚本读取 bodyPreviewBase64 时必须下发正文预览");
        Require(await WantsAsync("WANT_BODY = True\ndef on_before_send(event):\n    key = 'body' + 'Preview' + 'Base64'\n    return None"),
            "键名拼接时文本扫不到字段名，显式声明 WANT_BODY 必须生效");
        Require(ScriptHookEngine.ScriptWantsBodyPreview(Path.Combine(root, "不存在.py")),
            "读不到脚本时必须按需要正文处理——宁可多带也不能让脚本拿到空正文");

        // 默认模板不碰正文预览：新用户开箱即是省流量的那条路径。
        var templatePath = Path.Combine(root, "default.py");
        await File.WriteAllTextAsync(templatePath,
            "def on_before_send(event):\n    return {'kind': 'x', 'bodySize': event.get('bodySize')}\n", new UTF8Encoding(false));
        Require(!ScriptHookEngine.ScriptWantsBodyPreview(templatePath), "默认观察模板不应触发正文预览下发");
    }
    finally
    {
        if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
    }
}

/// <summary>
/// 工作区脚本库：命名校验（唯一的路径穿越防线）、用途推断与 sidecar 往返、
/// 重命名/删除的目录一致性，以及编辑器补全词表与运行时契约的一致性。
///
/// 脚本名来自用户输入且会拼进工作区 scripts 路径，所以命名校验被当作安全断言写在这里。
/// </summary>
static async Task VerifyScriptLibraryAsync()
{
    var root = Path.Combine(Path.GetTempPath(), "netmind-scriptlib-" + Guid.NewGuid().ToString("N"));
    try
    {
        await new WorkspaceStore(root).InitializeAsync("脚本库定向测试工作区");
        Require(ScriptLibraryStore.List(root).Count == 0, "新工作区的脚本库必须是空的");

        // ── 命名校验：路径穿越、非法字符、空名与超长名一律拒绝 ──
        foreach (var hostile in new[]
                 {
                     "../escape", @"..\escape", "sub/child", @"sub\child", "", "   ", ".", "..", ".py",
                     "bad:name", "bad*name", "bad?name", "bad\"name", "bad|name", new string('x', 100)
                 })
        {
            var rejected = false;
            try { ScriptLibraryStore.NormalizeFileName(hostile); }
            catch (ArgumentException) { rejected = true; }
            Require(rejected, $"脚本名 {hostile.Replace('\\', '/')} 必须被拒绝，否则可写出 scripts 目录之外");
        }
        Require(ScriptLibraryStore.NormalizeFileName("probe") == "probe.py", "缺少后缀的脚本名必须补齐 .py");
        Require(ScriptLibraryStore.NormalizeFileName(" probe.PY ") == "probe.py", "脚本名必须去空白并统一 .py 后缀");
        Require(ScriptLibraryStore.NormalizeFileName("接口探针") == "接口探针.py", "中文脚本名必须可用");

        // ── 用途推断：钩子函数名优先于 fixture 导入 ──
        Require(ScriptLibraryStore.InferPurpose("def on_before_send(event):\n    return None") == ScriptPurpose.Hook,
            "定义钩子函数的脚本必须推断为钩子脚本");
        Require(ScriptLibraryStore.InferPurpose("from netmind import fixture\nprint(len(fixture.transactions))") == ScriptPurpose.Fixture,
            "导入 fixture 的脚本必须推断为验证脚本");
        Require(ScriptLibraryStore.InferPurpose("from netmind import fixture\ndef on_before_write(event):\n    return None") == ScriptPurpose.Hook,
            "同时具备两种特征时，钩子语义更强，必须推断为钩子脚本");

        // ── 新建、列举与 sidecar 往返 ──
        var hook = await ScriptLibraryStore.CreateAsync(root, "hook-script", ScriptPurpose.Hook, "def on_before_send(event):\n    return None\n");
        var check = await ScriptLibraryStore.CreateAsync(root, "check", ScriptPurpose.Fixture, "from netmind import fixture\n");
        Require(hook.FileName == "hook-script.py" && check.FileName == "check.py", "新建脚本必须落在 scripts 目录且带 .py 后缀");
        var listed = ScriptLibraryStore.List(root);
        Require(listed.Count == 2, $"脚本库应有 2 个脚本，实际 {listed.Count}");
        Require(listed.Single(item => item.FileName == "check.py").Purpose == ScriptPurpose.Fixture,
            "sidecar 记录的用途必须能读回来，而不是每次都退回内容推断");
        Require(listed.All(item => File.Exists(item.FullPath)), "列出的脚本必须都真实存在");

        // 重名新建必须拒绝；CreateUniqueFileName 负责给出不冲突的名字。
        var duplicated = false;
        try { await ScriptLibraryStore.CreateAsync(root, "check", ScriptPurpose.Fixture, "x = 1\n"); }
        catch (InvalidOperationException) { duplicated = true; }
        Require(duplicated, "同名脚本必须拒绝创建，不能静默覆盖已有内容");
        Require(ScriptLibraryStore.CreateUniqueFileName(root, "check") == "check-2.py", "唯一命名必须在冲突时追加序号");

        // 目录即真相：sidecar 里残留的条目不能变成幽灵脚本。
        File.Delete(check.FullPath);
        Require(ScriptLibraryStore.List(root).All(item => item.FileName != "check.py"),
            "文件被外部删除后不得继续出现在脚本库中");
        await ScriptLibraryStore.CreateAsync(root, "check", ScriptPurpose.Fixture, "from netmind import fixture\n");

        // 用户直接丢进目录的脚本必须被接纳，并按内容推断用途。
        await File.WriteAllTextAsync(Path.Combine(TrafficHookConfigStore.GetScriptsDirectory(root), "dropped.py"),
            "from netmind import fixture\n", new UTF8Encoding(false));
        var dropped = ScriptLibraryStore.List(root).Single(item => item.FileName == "dropped.py");
        Require(dropped.Purpose == ScriptPurpose.Fixture, "外部放入的脚本必须按内容推断用途");

        // hook-config.json 与 hook-status.json 不是脚本，不能出现在库里。
        await TrafficHookConfigStore.SaveConfigAsync(root, new TrafficHookConfiguration(true, "hook-script.py",
            new TrafficHookSwitches(BeforeSend: true)));
        Require(ScriptLibraryStore.List(root).All(item => item.FileName.EndsWith(".py", StringComparison.Ordinal)),
            "脚本库只能包含 *.py，配置与状态文件不得混入");

        // ── 重命名：文件与 sidecar 用途一起迁移 ──
        var renamed = await ScriptLibraryStore.RenameAsync(root, "check.py", "回归校验");
        Require(renamed == "回归校验.py", "重命名必须返回规范化后的文件名");
        var afterRename = ScriptLibraryStore.List(root);
        Require(afterRename.All(item => item.FileName != "check.py"), "重命名后旧文件名必须消失");
        Require(afterRename.Single(item => item.FileName == renamed).Purpose == ScriptPurpose.Fixture,
            "重命名必须把 sidecar 中的用途一并迁移，否则用途会被内容推断悄悄改掉");
        var collided = false;
        try { await ScriptLibraryStore.RenameAsync(root, renamed, "hook-script"); }
        catch (InvalidOperationException) { collided = true; }
        Require(collided, "重命名到已存在的脚本名必须拒绝，不能覆盖另一个脚本");

        // ── 删除：文件与 sidecar 条目一起清掉 ──
        await ScriptLibraryStore.DeleteAsync(root, renamed);
        Require(ScriptLibraryStore.List(root).All(item => item.FileName != renamed), "删除后脚本必须从库中消失");
        var document = await File.ReadAllTextAsync(ScriptLibraryStore.GetDocumentPath(root));
        Require(!document.Contains(renamed, StringComparison.Ordinal), "删除脚本必须一并清掉 sidecar 中的用途条目");

        // sidecar 损坏时退回内容推断，不能让整个脚本库不可用。
        await File.WriteAllTextAsync(ScriptLibraryStore.GetDocumentPath(root), "{ 这不是 JSON", new UTF8Encoding(false));
        var resilient = ScriptLibraryStore.List(root);
        Require(resilient.Count >= 2, "sidecar 损坏时脚本库仍必须可列举");
        Require(resilient.Single(item => item.FileName == "hook-script.py").Purpose == ScriptPurpose.Hook,
            "sidecar 损坏时必须退回内容推断而不是报错");

        // ── 补全词表与运行时契约同源 ──
        Require(HookScriptApi.FixtureFields.Count > 0, "验证脚本补全必须给出 fixture 事务字段");
        Require(HookScriptApi.FixtureFields.All(symbol => symbol.Detail != "（尚未补充说明）"),
            "fixture 字段补全说明有遗漏：新增字段后必须在 HookScriptApi 补上中文说明");
        var fixtureNames = HookScriptApi.FixtureFields.Select(symbol => symbol.Name).ToHashSet(StringComparer.Ordinal);
        foreach (var required in new[] { "method", "url", "host", "endpoint", "status", "latency_ms", "size_bytes", "protocol", "process" })
            Require(fixtureNames.Contains(required), $"fixture 字段补全缺少 {required}");
        var sample = AiPrivacyFilter.CreateScriptTransaction(DemoData.CreateTraffic()[0]);
        var serialized = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(
            JsonSerializer.Serialize(sample, new JsonSerializerOptions(JsonSerializerDefaults.Web)))!;
        Require(serialized.Keys.All(fixtureNames.Contains) && fixtureNames.All(serialized.ContainsKey),
            "fixture 补全词表必须与真实序列化字段完全一致，否则照提示写会取不到值");
        Require(HookScriptApi.HookVocabulary.Any(symbol => symbol.Name == "INTERCEPT"),
            "钩子词表必须包含 INTERCEPT，它是拦截改写的唯一声明入口");
        foreach (var function in HookScriptApi.HookFunctions)
            Require(HookScriptApi.HookVocabulary.Any(symbol => symbol.Name == function.Name),
                $"钩子词表必须包含挂载点函数 {function.Name}");
    }
    finally
    {
        if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
    }
}

/// <summary>
/// 拦截规则匹配与 fail-open 边界。
///
/// 规则由脚本声明、在宿主进程内匹配，代理热路径上每个请求都会跑一遍，
/// 因此这里既要验证「能按 URL/方法/主机/路径/头/正文/状态码 精确命中」，
/// 也要验证「病态正则炸不掉热路径」和「拿不到裁决时一定放行」。
/// </summary>
static async Task VerifyHookInterceptRulesAsync()
{
    static HookTransactionSnapshot Snapshot(string method, string url, string body, int? status = null,
        IReadOnlyDictionary<string, string>? headers = null)
    {
        var uri = new Uri(url);
        return new HookTransactionSnapshot(Guid.NewGuid(), Guid.NewGuid(), method, url, uri.Host, uri.PathAndQuery,
            headers ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { ["X-Sign"] = "a1b2c3d4e5f60718" },
            Encoding.UTF8.GetBytes(body)) { StatusCode = status };
    }

    var login = Snapshot("POST", "https://api.test.local/v2/user/login?lang=zh", "{\"password\":\"p\",\"sign\":\"abc\"}");
    var listing = Snapshot("GET", "https://cdn.test.local/assets/app.js", "console.log(1)");

    // 每个可匹配位置都要能单独命中，也要能正确地不命中。
    (string Name, string? Url, string? Method, string? Host, string? Endpoint, string? Body, string? Status,
        Dictionary<string, string>? Headers, bool ShouldMatch)[] cases =
    {
        ("URL 正则", @"/v\d+/user/login", null, null, null, null, null, null, true),
        ("URL 不命中", @"/v\d+/order", null, null, null, null, null, null, false),
        ("方法", null, "^POST$", null, null, null, null, null, true),
        ("方法不命中", null, "^GET$", null, null, null, null, null, false),
        ("主机", null, null, @"^api\.", null, null, null, null, true),
        ("主机不命中", null, null, @"^cdn\.", null, null, null, null, false),
        ("路径", null, null, null, @"^/v2/user/", null, null, null, true),
        ("正文", null, null, null, null, @"""password""\s*:", null, null, true),
        ("正文不命中", null, null, null, null, @"""token""\s*:", null, null, false),
        ("请求头值", null, null, null, null, null, null, new() { ["X-Sign"] = "^[0-9a-f]{16}$" }, true),
        ("请求头值不命中", null, null, null, null, null, null, new() { ["X-Sign"] = "^\\d+$" }, false),
        ("请求头缺失", null, null, null, null, null, null, new() { ["X-Absent"] = "" }, false),
        ("请求头仅要求存在", null, null, null, null, null, null, new() { ["X-Sign"] = "" }, true),
        // 多条件之间是 AND：任一不满足即整体不命中。
        ("多条件全中", @"/user/login", "^POST$", @"api\.test", null, @"password", null, null, true),
        ("多条件其一不中", @"/user/login", "^GET$", @"api\.test", null, @"password", null, null, false),
    };
    foreach (var item in cases)
    {
        var rule = HookInterceptRule.TryCreate(HookEventNames.RequestBeforeSend, item.Url, item.Method, item.Host,
            item.Endpoint, item.Body, item.Status, item.Headers);
        Require(rule is not null, $"规则「{item.Name}」必须能编译");
        Require(rule!.Matches(HookEventNames.RequestBeforeSend, login) == item.ShouldMatch,
            $"规则「{item.Name}」的匹配结果不符合预期");
    }

    // 状态码只在响应侧有意义。
    var responseRule = HookInterceptRule.TryCreate(HookEventNames.ResponseBeforeWrite, null, null, null, null, null, @"^4\d\d$", null);
    Require(responseRule is not null, "响应侧状态码规则必须能编译");
    Require(responseRule!.Matches(HookEventNames.ResponseBeforeWrite, Snapshot("GET", "https://a.test/x", "", 404)),
        "状态码正则必须能命中 4xx");
    Require(!responseRule.Matches(HookEventNames.ResponseBeforeWrite, Snapshot("GET", "https://a.test/x", "", 200)),
        "状态码正则不得命中 2xx");

    // 事件名不匹配、挂载点不可改写、模式非法：整条规则作废而不是部分生效。
    Require(!responseRule.Matches(HookEventNames.RequestBeforeSend, login), "规则不得跨挂载点命中");
    Require(HookInterceptRule.TryCreate(HookEventNames.RequestAfterSend, null, null, null, null, null, null, null) is null,
        "只有发送前与回写前两个点可改写，其余点声明必须被拒绝");
    Require(HookInterceptRule.TryCreate(HookEventNames.RequestBeforeSend, "([unclosed", null, null, null, null, null, null) is null,
        "非法正则必须让整条规则作废");

    // 病态正则不得拖垮热路径：线性引擎保证不回溯，退回普通引擎时也有匹配超时兜底。
    var pathological = HookInterceptRule.TryCreate(HookEventNames.RequestBeforeSend, null, null, null, null,
        "(a+)+$", null, null);
    Require(pathological is not null, "病态模式仍应能编译（由线性引擎或超时兜底保证安全）");
    var evil = Snapshot("POST", "https://api.test.local/x", new string('a', 5000) + "!");
    var timer = Stopwatch.StartNew();
    pathological!.Matches(HookEventNames.RequestBeforeSend, evil);
    timer.Stop();
    Require(timer.ElapsedMilliseconds < 1000,
        $"病态正则匹配必须在毫秒级内收敛，实测 {timer.ElapsedMilliseconds} ms（回溯爆炸会拖死代理）");

    // 编辑器补全词表必须与运行时契约同步：字段名反射自 HookEventEnvelope，说明是人工维护的，
    // 漏写说明就等于提示里出现一个「不知道是什么」的字段，这里直接测挂。
    Require(HookScriptApi.EventFields.Count > 0, "事件字段词表不得为空");
    Require(HookScriptApi.EventFields.All(field => !field.Detail.Contains("尚未补充说明", StringComparison.Ordinal)),
        "新增信封字段后必须补上中文说明：" +
        string.Join("、", HookScriptApi.EventFields.Where(f => f.Detail.Contains("尚未补充说明", StringComparison.Ordinal)).Select(f => f.Name)));
    foreach (var expected in new[] { "url", "method", "headers", "bodyPreviewBase64", "statusCode", "txnId" })
        Require(HookScriptApi.EventFields.Any(field => field.Name == expected),
            $"事件字段词表必须包含 {expected}（它直接来自信封契约）");
    // 钩子函数词表必须与实际派发用的函数名一致，否则补全出来的函数永远不会被调用。
    foreach (var function in new[]
             {
                 HookEventNames.FunctionBeforeSend, HookEventNames.FunctionAfterSend,
                 HookEventNames.FunctionBeforeWrite, HookEventNames.FunctionAfterDeliver
             })
        Require(HookScriptApi.HookFunctions.Any(symbol => symbol.Name == function),
            $"钩子函数词表必须包含 {function}");
    // INTERCEPT 只能声明可改写的两个挂载点，补全里也不能出现别的。
    Require(HookScriptApi.InterceptEvents.All(symbol => HookInterceptRule.IsMutable(symbol.Name)),
        "拦截事件补全项必须都是可改写的挂载点");
    // 规则字段补全必须覆盖匹配器实际支持的每个位置。
    foreach (var field in new[] { "url", "method", "host", "endpoint", "body", "status", "headers" })
        Require(HookScriptApi.InterceptRuleFields.Any(symbol => symbol.Name == field),
            $"拦截规则补全必须包含匹配位置 {field}");

    // 未声明规则、引擎未运行时必须不拦截且立即放行——纯观察脚本不付任何代价。
    var testRoot = Path.Combine(Path.GetTempPath(), "netmind-intercept-test-" + Guid.NewGuid().ToString("N"));
    try
    {
        Directory.CreateDirectory(testRoot);
        await using var engine = new ScriptHookEngine("dummy-host.exe", null,
            Path.Combine(testRoot, "hook.py"), Path.Combine(testRoot, "data"),
            [HookEventNames.RequestBeforeSend]);
        Require(engine.InterceptRuleCount == 0, "未上报规则时拦截规则数必须为 0");
        Require(!engine.ShouldIntercept(HookEventNames.RequestBeforeSend, login), "未声明规则时不得拦截任何请求");
        Require(!engine.ShouldIntercept(HookEventNames.RequestAfterSend, login), "不可改写的挂载点永远不得拦截");
        // 工作进程未启动：必须立刻返回放行，而不是等满超时。
        var failOpenTimer = Stopwatch.StartNew();
        var verdict = await engine.InterceptAsync(HookEventNames.RequestBeforeSend, login);
        failOpenTimer.Stop();
        Require(verdict is null, "工作进程不可用时必须放行（fail-open）");
        Require(failOpenTimer.ElapsedMilliseconds < NetMindDefaults.HookInterceptTimeoutMilliseconds / 2,
            $"工作进程不可用时必须立刻放行，不能空等超时，实测 {failOpenTimer.ElapsedMilliseconds} ms");
    }
    finally
    {
        if (Directory.Exists(testRoot)) Directory.Delete(testRoot, recursive: true);
    }
}

/// <summary>
/// 代理挂载点端到端触发验证。
///
/// 此前只有引擎层（策略、信封契约、队列背压）和 worker 端到端被覆盖，
/// 唯一给代理传钩子引擎的测试传的是 hookEngine:null；四个挂载点里有三个
/// 在整个测试集中从未被断言过——也就是说「代理是否真的在这四个位置按序触发、
/// 信封字段是否正确」一直没有验证。脚本的读取/修改能力要建在这四个点上，
/// 先把地基测出来。
///
/// 刻意不启动工作进程：直接读引擎待投递队列，断言才不会连带依赖本机是否装了 Python。
/// </summary>
static async Task VerifyProxyHookMountPointsAsync()
{
    var workspaceRoot = Path.Combine(Path.GetTempPath(), "netmind-mountpoint-test-" + Guid.NewGuid().ToString("N"));
    var upstream = new TcpListener(IPAddress.Loopback, 0);
    upstream.Start();
    var upstreamEndpoint = (IPEndPoint)upstream.LocalEndpoint;
    try
    {
        await new WorkspaceStore(workspaceRoot).InitializeAsync("挂载点测试工作区");
        var requestBodyBytes = Encoding.UTF8.GetBytes("{\"probe\":\"请求正文\"}");
        var upstreamTask = Task.Run(async () =>
        {
            using var client = await upstream.AcceptTcpClientAsync();
            using var stream = client.GetStream();
            await ReadUntilHeadersAsync(stream);
            // 必须把请求正文读干净：只读头就回包，转发端写正文时会失败，整条请求被记成 502。
            await ReadExactAsync(stream, new byte[requestBodyBytes.Length], CancellationToken.None);
            var body = Encoding.UTF8.GetBytes("{\"ok\":true,\"marker\":\"上游响应正文\"}");
            await stream.WriteAsync(Encoding.ASCII.GetBytes(
                $"HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {body.Length}\r\nConnection: close\r\n\r\n"));
            await stream.WriteAsync(body);
        });

        // 引擎只构造不启动：Emit 仍会正常入队，但不依赖 SandboxHost 与 Python。
        await using var engine = new ScriptHookEngine("dummy-host.exe", null,
            Path.Combine(workspaceRoot, "hook.py"), Path.Combine(workspaceRoot, "data"),
            [HookEventNames.RequestBeforeSend, HookEventNames.RequestAfterSend,
             HookEventNames.ResponseBeforeWrite, HookEventNames.ResponseAfterDeliver]);

        using var archive = new TrafficArchive(workspaceRoot);
        await using var proxy = new ExplicitHttpProxy(new ProxyOptions(IPAddress.Loopback, 0), archive, hookEngine: engine);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var proxyTask = proxy.RunAsync(cancellation.Token);
        while (proxy.LocalEndpoint is null) await Task.Delay(10, cancellation.Token);

        using (var client = new TcpClient())
        {
            await client.ConnectAsync(proxy.LocalEndpoint.Address, proxy.LocalEndpoint.Port, cancellation.Token);
            using var stream = client.GetStream();
            var bodyBytes = requestBodyBytes;
            await stream.WriteAsync(Encoding.ASCII.GetBytes(
                $"POST http://127.0.0.1:{upstreamEndpoint.Port}/v1/probe?a=1 HTTP/1.1\r\nHost: 127.0.0.1:{upstreamEndpoint.Port}\r\n" +
                $"X-Probe: 探针\r\nContent-Type: application/json\r\nContent-Length: {bodyBytes.Length}\r\nConnection: close\r\n\r\n"), cancellation.Token);
            await stream.WriteAsync(bodyBytes, cancellation.Token);
            using var response = new MemoryStream();
            await stream.CopyToAsync(response, cancellation.Token);
            var responseText = Encoding.UTF8.GetString(response.ToArray());
            Require(responseText.Contains("201", StringComparison.Ordinal),
                "挂载点测试的请求本身必须成功完成，实际响应：" + (responseText.Length == 0 ? "(空)" : responseText[..Math.Min(400, responseText.Length)]));
        }

        await upstreamTask;
        cancellation.Cancel();
        try { await proxyTask; } catch (OperationCanceledException) { }
        upstream.Stop();

        var fired = new List<HookEventEnvelope>();
        while (engine.TryDequeuePendingForTest(out var envelope)) fired.Add(envelope);

        Require(fired.Count == 4, $"四个挂载点必须各触发一次，实际触发 {fired.Count} 次：" +
                                  string.Join("、", fired.Select(item => item.Event)));
        Require(fired.Select(item => item.Event).SequenceEqual(new[]
            {
                HookEventNames.RequestBeforeSend, HookEventNames.RequestAfterSend,
                HookEventNames.ResponseBeforeWrite, HookEventNames.ResponseAfterDeliver
            }),
            "挂载点触发顺序必须是 发送前 → 发送后 → 回写前 → 交付后，实际：" +
            string.Join(" → ", fired.Select(item => item.Event)));

        // 同一事务的四个点必须共用同一 txnId，否则脚本无法把请求与响应关联起来。
        Require(fired.Select(item => item.TxnId).Distinct().Count() == 1, "同一事务的四个挂载点必须共用同一 txnId");
        Require(fired.All(item => item.Method == "POST" && item.Url.Contains("/v1/probe", StringComparison.Ordinal)),
            "每个挂载点的信封都必须带上本次事务的方法与 URL");
        Require(fired.All(item => item.HookName == HookEventNames.FunctionBeforeSend ||
                                  item.HookName == HookEventNames.FunctionAfterSend ||
                                  item.HookName == HookEventNames.FunctionBeforeWrite ||
                                  item.HookName == HookEventNames.FunctionAfterDeliver),
            "每个挂载点都必须映射到对应的脚本函数名");

        // 状态码只有在上游响应之后才可知：发送前必须为空，其余三点必须是真实状态码。
        Require(fired[0].StatusCode is null, "请求发送前的挂载点不得携带状态码");
        Require(fired.Skip(1).All(item => item.StatusCode == 201), "发送后的三个挂载点必须携带上游真实状态码");

        // 请求侧挂载点带请求正文，响应侧带响应正文——这是脚本能读到正确数据的前提。
        // 正文预览是在泵线程序列化前才补齐的（且按脚本是否需要决定带不带），
        // 所以这里必须断言「实际下发的那一份」，而不是刚入队时的信封。
        static string Decode(HookEventEnvelope envelope, bool includeBodyPreview)
        {
            var delivered = ScriptHookEngine.MaterializeForDelivery(envelope, includeBodyPreview);
            return delivered.BodyPreviewBase64 is null
                ? string.Empty
                : Encoding.UTF8.GetString(Convert.FromBase64String(delivered.BodyPreviewBase64));
        }
        Require(Decode(fired[0], true).Contains("请求正文", StringComparison.Ordinal) &&
                Decode(fired[1], true).Contains("请求正文", StringComparison.Ordinal),
            "请求侧两个挂载点必须携带请求正文");
        Require(Decode(fired[2], true).Contains("上游响应正文", StringComparison.Ordinal) &&
                Decode(fired[3], true).Contains("上游响应正文", StringComparison.Ordinal),
            "响应侧两个挂载点必须携带响应正文");
        // 脚本不需要正文时一律不下发，但大小与哈希必须仍然可用，否则观察脚本会失去判据。
        Require(fired.All(item => Decode(item, false).Length == 0),
            "脚本不使用正文预览时，观察事件不得携带正文");
        Require(fired.All(item => ScriptHookEngine.MaterializeForDelivery(item, false) is
                { BodySha256.Length: 64, BodySize: > 0 }),
            "不下发正文预览时，bodySize 与 bodySha256 必须照常补齐");
        Require(fired[0].Headers is not null && fired[0].Headers!.Keys.Any(name => name.Equals("X-Probe", StringComparison.OrdinalIgnoreCase)),
            "请求挂载点必须携带请求头");

        // 未勾选的挂载点不得触发：单点开关在引擎侧判断，这是「只观察我关心的点」的基础。
        await using var singleEngine = new ScriptHookEngine("dummy-host.exe", null,
            Path.Combine(workspaceRoot, "hook.py"), Path.Combine(workspaceRoot, "data"),
            [HookEventNames.ResponseBeforeWrite]);
        var snapshot = new HookTransactionSnapshot(Guid.NewGuid(), Guid.NewGuid(), "GET", "http://x.test/", "x.test", "/", null, []);
        foreach (var name in new[]
                 {
                     HookEventNames.RequestBeforeSend, HookEventNames.RequestAfterSend,
                     HookEventNames.ResponseBeforeWrite, HookEventNames.ResponseAfterDeliver
                 })
            singleEngine.Emit(name, snapshot, 200);
        var single = new List<HookEventEnvelope>();
        while (singleEngine.TryDequeuePendingForTest(out var envelope)) single.Add(envelope);
        Require(single.Count == 1 && single[0].Event == HookEventNames.ResponseBeforeWrite,
            "只勾选一个挂载点时，其余挂载点不得入队");
    }
    finally
    {
        try { upstream.Stop(); } catch (SocketException) { }
        if (Directory.Exists(workspaceRoot)) Directory.Delete(workspaceRoot, recursive: true);
    }
}

/// <summary>
/// 示例脚本 docs/samples/hook-baidu-search-888.py 的端到端验证：
/// 真实 SandboxHost hook-worker + 真实 Python + 真实代理，断言上游实际收到的字节里
/// 搜索关键字已被固定为 888。
///
/// 之所以要走完整链路而不是只测 <see cref="HookInterceptRule"/>：规则匹配、worker 上报、
/// 代理阻塞裁决、改写回写请求行——这四段里任何一段断了，用户看到的都是「脚本没生效」，
/// 而单测规则匹配对这四段中的三段一无所知。
///
/// 断言用的脚本直接读仓库里那一份，不在测试里另抄一份：抄一份就会漂移，
/// 漂移之后这个套件验证的就不再是用户真正拿到的脚本。
/// </summary>
static async Task VerifyBaiduSearchInterceptAsync()
{
    // 与既有钩子端到端子断言一致：本机没有 Python 时跳过，不计失败。
    var probe = await new PythonSandboxRunner().RunAsync(new SandboxJob(
        "print('python-ok')", JsonSerializer.SerializeToElement(new { }), TimeoutMilliseconds: 10000));
    if (!probe.Succeeded && probe.State == "运行时不可用")
    {
        Console.WriteLine("百度搜索拦截端到端断言跳过（未找到 Python）。");
        return;
    }

    var sandboxHostPath = ResolveSandboxHostForTest();
    Require(sandboxHostPath is not null, "端到端断言必须能找到同批构建的 NetMind.SandboxHost 可执行文件");

    var samplePath = ResolveRepositoryFileForTest(Path.Combine("docs", "samples", "hook-baidu-search-888.py"));
    Require(samplePath is not null, "必须能定位仓库中的示例脚本 docs/samples/hook-baidu-search-888.py");
    var scriptText = await File.ReadAllTextAsync(samplePath!);
    Require(PythonSandboxPolicy.Validate(scriptText).Count == 0,
        "示例脚本必须通过静态能力策略，否则用户保存时就会被拒：" +
        string.Join("、", PythonSandboxPolicy.Validate(scriptText)));

    var workspaceRoot = Path.Combine(Path.GetTempPath(), "netmind-baidu-intercept-" + Guid.NewGuid().ToString("N"));
    var upstream = new TcpListener(IPAddress.Loopback, 0);
    upstream.Start();
    var upstreamPort = ((IPEndPoint)upstream.LocalEndpoint).Port;
    try
    {
        await new WorkspaceStore(workspaceRoot).InitializeAsync("百度拦截测试工作区");
        var scriptsDirectory = Path.Combine(workspaceRoot, NetMindDefaults.ScriptsDirectoryName);
        Directory.CreateDirectory(scriptsDirectory);
        var scriptPath = Path.Combine(scriptsDirectory, "hook-baidu-search-888.py");
        await File.WriteAllTextAsync(scriptPath, scriptText, new UTF8Encoding(false));

        // 上游只记录收到的请求行：这是「实际上线的字节」，也是唯一有说服力的断言对象。
        var receivedRequestLines = new List<string>();
        var upstreamTask = Task.Run(async () =>
        {
            for (var index = 0; index < 2; index++)
            {
                using var client = await upstream.AcceptTcpClientAsync();
                using var stream = client.GetStream();
                var headerText = await ReadHeaderTextAsync(stream);
                lock (receivedRequestLines)
                    receivedRequestLines.Add(headerText.Split("\r\n", StringSplitOptions.None)[0]);
                var body = Encoding.UTF8.GetBytes("{\"ok\":true}");
                await stream.WriteAsync(Encoding.ASCII.GetBytes(
                    $"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {body.Length}\r\nConnection: close\r\n\r\n"));
                await stream.WriteAsync(body);
            }
        });

        await using var engine = new ScriptHookEngine(sandboxHostPath!, null, scriptPath,
            Path.Combine(scriptsDirectory, NetMindDefaults.HookDataDirectoryName),
            [HookEventNames.RequestBeforeSend]);
        Require(await engine.StartAsync(), "钩子工作进程必须能按示例脚本启动");

        // 规则随 ready 一次性上报；上报完成前不得开始断言，否则测的是「还没生效」的时刻。
        var ruleTimer = Stopwatch.StartNew();
        while (engine.InterceptRuleCount == 0 && ruleTimer.Elapsed < TimeSpan.FromSeconds(20))
            await Task.Delay(50);
        Require(engine.InterceptRuleCount == 1,
            $"示例脚本必须上报 1 条 INTERCEPT 规则，实际 {engine.InterceptRuleCount} 条");

        using var archive = new TrafficArchive(workspaceRoot);
        await using var proxy = new ExplicitHttpProxy(new ProxyOptions(IPAddress.Loopback, 0), archive, hookEngine: engine);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var proxyTask = proxy.RunAsync(cancellation.Token);
        while (proxy.LocalEndpoint is null) await Task.Delay(10, cancellation.Token);

        static async Task SendAsync(ExplicitHttpProxy proxy, string target, CancellationToken cancellationToken)
        {
            using var client = new TcpClient();
            await client.ConnectAsync(proxy.LocalEndpoint!.Address, proxy.LocalEndpoint.Port, cancellationToken);
            using var stream = client.GetStream();
            await stream.WriteAsync(Encoding.ASCII.GetBytes(
                $"GET {target} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"), cancellationToken);
            using var sink = new MemoryStream();
            await stream.CopyToAsync(sink, cancellationToken);
        }

        // ① 命中：百度网页搜索形态 /s?wd=…，关键字必须被固定为 888。
        await SendAsync(proxy, $"http://127.0.0.1:{upstreamPort}/s?wd=%E5%8E%9F%E5%A7%8B%E5%85%B3%E9%94%AE%E8%AF%8D&rsv_spt=1", cancellation.Token);
        // ② 不命中：同样带 wd，但不是搜索端点，必须原样透传。
        await SendAsync(proxy, $"http://127.0.0.1:{upstreamPort}/nosearch?wd=%E5%8E%9F%E5%A7%8B%E5%85%B3%E9%94%AE%E8%AF%8D", cancellation.Token);

        await upstreamTask;
        cancellation.Cancel();
        try { await proxyTask; } catch (OperationCanceledException) { }

        Require(receivedRequestLines.Count == 2, $"上游必须收到 2 个请求，实际 {receivedRequestLines.Count} 个");
        var intercepted = receivedRequestLines[0];
        Require(intercepted.Contains("wd=888", StringComparison.Ordinal),
            "命中的搜索请求必须以 wd=888 发往上游，实际请求行：" + intercepted);
        Require(!intercepted.Contains("%E5%8E%9F%E5%A7%8B", StringComparison.OrdinalIgnoreCase),
            "原始搜索关键字不得残留在发往上游的请求行里：" + intercepted);
        // 只改关键字，不得顺手吞掉同一查询串里的其他参数。
        Require(intercepted.Contains("rsv_spt=1", StringComparison.Ordinal),
            "改写必须保留查询串中的其他参数，实际请求行：" + intercepted);

        var untouched = receivedRequestLines[1];
        Require(untouched.Contains("%E5%8E%9F%E5%A7%8B", StringComparison.OrdinalIgnoreCase),
            "未命中规则的请求必须原样透传，实际请求行：" + untouched);
    }
    finally
    {
        try { upstream.Stop(); } catch (SocketException) { }
        if (Directory.Exists(workspaceRoot)) Directory.Delete(workspaceRoot, recursive: true);
    }
}

/// <summary>读取并返回完整请求头文本（含结尾 CRLFCRLF 之前的内容），供断言实际上线的请求行。</summary>
static async Task<string> ReadHeaderTextAsync(Stream stream)
{
    var buffer = new List<byte>(1024);
    var single = new byte[1];
    while (await stream.ReadAsync(single) > 0)
    {
        buffer.Add(single[0]);
        if (buffer.Count >= 4 && buffer[^4] == 13 && buffer[^3] == 10 && buffer[^2] == 13 && buffer[^1] == 10)
            return Encoding.UTF8.GetString(buffer.ToArray(), 0, buffer.Count - 4);
    }
    throw new EndOfStreamException("上游测试请求头未完整到达。");
}

/// <summary>
/// 从测试输出目录回溯到仓库根，定位随仓库交付的文件。
/// 与 <c>ResolveSandboxHostForTest</c> 用同一套相对布局假设：bin/&lt;cfg&gt;/net10.0 上溯四层即 src。
/// </summary>
static string? ResolveRepositoryFileForTest(string relativePath)
{
    var repositoryRoot = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", ".."));
    var candidate = Path.Combine(repositoryRoot, relativePath);
    return File.Exists(candidate) ? candidate : null;
}

/// <summary>
/// 审计写入方本身是并发的：CoreHost 代理每条事务写一次 traffic.recorded，多个连接同时结算，
/// 工作台还会就同一工作区写用户操作审计。并发追加必须一条不丢、一行不坏。
/// 回归背景：原实现用 File.AppendAllTextAsync（FileShare.Read），实测 8 路并发 1,200 条只落盘 508 条。
/// </summary>
static async Task VerifyConcurrentAuditAppendAsync()
{
    const int workers = 8;
    const int perWorker = 150;
    var testRoot = Path.Combine(Path.GetTempPath(), "netmind-audit-test-" + Guid.NewGuid().ToString("N"));
    try
    {
        var store = new WorkspaceStore(testRoot);
        await store.InitializeAsync("并发审计测试工作区");

        var failures = 0;
        await Task.WhenAll(Enumerable.Range(0, workers).Select(worker => Task.Run(async () =>
        {
            // 各处代码都是就地 new WorkspaceStore(path)，这里照此模拟，确保串行化不依赖共享实例。
            var local = new WorkspaceStore(testRoot);
            for (var index = 0; index < perWorker; index++)
            {
                try { await local.AppendAuditAsync("concurrent.probe", new { worker, index, note = "token=abc123secret" }); }
                catch (IOException) { Interlocked.Increment(ref failures); }
            }
        })));

        Require(failures == 0, $"并发审计写入不得抛 IOException，实际 {failures} 次");

        var logPath = Path.Combine(testRoot, NetMindDefaults.LogsDirectoryName, NetMindDefaults.AuditLogFileName);
        var lines = await File.ReadAllLinesAsync(logPath);
        var probes = lines.Count(line => line.Contains("\"eventName\":\"concurrent.probe\"", StringComparison.Ordinal));
        Require(probes == workers * perWorker,
            $"并发写入的审计条目一条都不能丢：应有 {workers * perWorker} 条，实际 {probes} 条");
        Require(lines.All(line => line.Length == 0 || (line.StartsWith('{') && line.EndsWith('}'))),
            "并发追加不得写出结构损坏的审计行");
        foreach (var line in lines.Where(line => line.Length > 0))
        {
            using var document = JsonDocument.Parse(line);
            Require(document.RootElement.TryGetProperty("eventName", out _), "每条审计都必须带 eventName");
        }
        // 串行化不得绕开脱敏通道：载荷里的 token=值 必须已被替换。
        var joined = string.Join('\n', lines);
        Require(!joined.Contains("abc123secret", StringComparison.Ordinal), "审计载荷中的令牌必须已脱敏");
        Require(joined.Contains(NetMindDefaults.RedactedPlaceholder, StringComparison.Ordinal), "审计仍必须经过脱敏通道");
    }
    finally
    {
        if (Directory.Exists(testRoot)) Directory.Delete(testRoot, recursive: true);
    }
}

/// <summary>
/// AI 首轮摘要与证据地图的省 token 编排必须是无损的：
/// 静态资源折叠后每个 #序号 仍要出现，证据地图的省略数量必须如实报出，
/// 单序号关联查询不得因全局清单截断而返回空。
/// </summary>
static void VerifyAiEvidenceOrchestration()
{
    static IReadOnlyList<TrafficRecord> BuildPool(int count)
    {
        string[] hosts = ["api.test.local", "cdn.test.local", "www.test.local"];
        // 一半是静态资源（会被折叠），一半是接口/文档（保持逐条明细）。
        string[] types = ["application/json; charset=utf-8", "image/png", "text/css; charset=utf-8",
                          "application/javascript", "text/html; charset=utf-8", "font/woff2"];
        var start = new DateTimeOffset(2026, 8, 11, 10, 0, 0, TimeSpan.Zero);
        var pool = new List<TrafficRecord>(count);
        for (var i = 0; i < count; i++)
        {
            // 主机、路径、方法同用 i%3：相隔 3 条的事务端点键完全一致，即使池子只有 12 条也存在真实的同端点关联，
            // 关联评分才可能越过阈值——否则断言测的是构造数据而不是被测逻辑。
            var bucket = i % 3;
            pool.Add(new TrafficRecord(Guid.NewGuid(), start.AddMilliseconds(i * 300), bucket == 0 ? "POST" : "GET",
                $"/v2/item/{bucket}", i % 37 == 0 ? 500 : 200, 40 + i % 150, 4096 + i * 11, "msedge.exe", "HTTP/1.1",
                "请求摘要", "响应摘要", $"https://{hosts[bucket]}/v2/item/{bucket}?id={i}",
                $"id={i}", "Accept: */*", $"sid=s{i}", $"Content-Type: {types[i % types.Length]}"));
        }
        return pool;
    }

    // 展开 "#3-#5,#9" 形式的序号区间，用于核对折叠行没有丢序号。
    static IEnumerable<int> ExpandOrdinals(string text)
    {
        foreach (Match match in Regex.Matches(text, @"#(\d+)(?:-#(\d+))?"))
        {
            var from = int.Parse(match.Groups[1].Value);
            var to = match.Groups[2].Success ? int.Parse(match.Groups[2].Value) : from;
            for (var value = from; value <= to; value++) yield return value;
        }
    }

    foreach (var size in new[] { 12, 200, 1000 })
    {
        var pool = BuildPool(size);
        var summary = AiConversationEngine.BuildEvidenceSummary(pool);
        var present = ExpandOrdinals(summary).ToHashSet();
        var missing = Enumerable.Range(1, size).Where(ordinal => !present.Contains(ordinal)).ToArray();
        Require(missing.Length == 0,
            $"证据池 {size} 条：首轮摘要必须覆盖全部 #序号，缺失 {missing.Length} 个（首个 #{missing.FirstOrDefault()}）");
        Require(Encoding.UTF8.GetByteCount(summary) <= NetMindDefaults.AiConversationSummaryMaximumBytes,
            $"证据池 {size} 条：首轮摘要不得超过字节兜底上限");

        var prepared = AiEvidencePreparationEngine.Prepare(pool);
        var overview = AiEvidencePreparationEngine.BuildOverviewJson(prepared);
        Require(!overview.Contains("\n  ", StringComparison.Ordinal), "发给模型的证据地图不得缩进");
        Require(Encoding.UTF8.GetByteCount(overview) <= 32 * 1024,
            $"证据池 {size} 条：证据地图必须有界，实测 {Encoding.UTF8.GetByteCount(overview)} 字节");
        using var document = JsonDocument.Parse(overview);
        var omittedRelations = document.RootElement.GetProperty("omittedRelations").GetInt32();
        var relationCount = document.RootElement.GetProperty("relations").GetArrayLength();
        Require(relationCount <= NetMindDefaults.AiOverviewMaximumRelations, "证据地图关联候选必须受上限约束");
        Require(relationCount + omittedRelations == prepared.Relations.Count,
            "证据地图必须如实报出省略的关联条数，不得静默截断");
        Require(document.RootElement.GetProperty("transactionCount").GetInt32() == size,
            "证据地图必须报出真实事务总数");

        // 全局关联清单按分数取前 300 条；单序号查询必须就地计算，不能因此返回空。
        var middle = size / 2;
        var related = AiEvidencePreparationEngine.GetRelated(pool, middle, 12);
        Require(related.Count > 0, $"证据池 {size} 条：#{middle} 的关联查询不得为空（回归：曾因过滤全局截断清单而恒空）");
        Require(related.All(relation => relation.FromOrdinal == middle || relation.ToOrdinal == middle),
            "关联结果必须都与被查询序号相关");
        Require(related.All(relation => relation.FromOrdinal < relation.ToOrdinal),
            "关联方向必须与时序一致（序号小的在前）");
    }

    // 字段缩写图例必须与实际序列化出来的字段名一致，否则模型拿着过期对照表解析结果。
    {
        var pool = BuildPool(24);
        var prepared = AiEvidencePreparationEngine.Prepare(pool);

        static IEnumerable<string> KeysOf(JsonElement element) =>
            element.ValueKind == JsonValueKind.Object
                ? element.EnumerateObject().Select(property => property.Name)
                : element.ValueKind == JsonValueKind.Array && element.GetArrayLength() > 0
                    ? KeysOf(element[0])
                    : [];

        static void RequireLegendCovers(string legend, IEnumerable<string> keys, string what)
        {
            foreach (var key in keys)
                Require(Regex.IsMatch(legend, $@"(?:^|[ ：])({Regex.Escape(key)})="),
                    $"{what} 的字段 “{key}” 未出现在缩写图例中；改字段名必须同步 AiJsonFieldLegend");
        }

        using var overviewDocument = JsonDocument.Parse(AiEvidencePreparationEngine.BuildOverviewJson(prepared));
        RequireLegendCovers(AiJsonFieldLegend.EndpointGroup,
            KeysOf(overviewDocument.RootElement.GetProperty("endpointGroups")), "端点组");
        RequireLegendCovers(AiJsonFieldLegend.Anomaly,
            KeysOf(overviewDocument.RootElement.GetProperty("anomalies")), "异常候选");
        RequireLegendCovers(AiJsonFieldLegend.Relation,
            KeysOf(overviewDocument.RootElement.GetProperty("relations")), "关联候选");
        // 容器层字段刻意保留可读全名：单例压缩省不了字节，只会增加理解成本。
        Require(overviewDocument.RootElement.TryGetProperty("transactionCount", out _) &&
                overviewDocument.RootElement.TryGetProperty("omittedRelations", out _),
            "证据地图的容器层字段必须保持可读全名");

        using var compareDocument = JsonDocument.Parse(
            AiEvidencePreparationEngine.ToJson(AiEvidencePreparationEngine.Compare(pool, [1, 2, 3, 4])));
        RequireLegendCovers(AiJsonFieldLegend.ComparedField,
            KeysOf(compareDocument.RootElement.GetProperty("fields")), "比较字段");

        using var relatedDocument = JsonDocument.Parse(
            AiEvidencePreparationEngine.ToJson(AiEvidencePreparationEngine.GetRelated(pool, 12, 8)));
        RequireLegendCovers(AiJsonFieldLegend.Relation, KeysOf(relatedDocument.RootElement), "单序号关联");

        // 全部图例都必须随工具说明一起发出去，否则缩写就是无法解码的。
        var toolText = string.Join('\n', AiConversationEngine.BuildToolSchemas().Select(tool => tool.Description));
        foreach (var legend in new[]
                 {
                     AiJsonFieldLegend.Transaction, AiJsonFieldLegend.EndpointGroup,
                     AiJsonFieldLegend.Anomaly, AiJsonFieldLegend.Relation, AiJsonFieldLegend.ComparedField
                 })
            Require(toolText.Contains(legend, StringComparison.Ordinal), "每份字段缩写图例都必须出现在工具说明中");
    }

    // 静态资源折叠必须真的省下体积，且明确标注折叠事实。
    var assetHeavy = BuildPool(300);
    var assetSummary = AiConversationEngine.BuildEvidenceSummary(assetHeavy);
    Require(assetSummary.Contains("[静态资源]", StringComparison.Ordinal), "静态资源应折叠为聚合行");
    Require(assetSummary.Contains("已按主机+类型折叠", StringComparison.Ordinal), "折叠必须对模型明确说明");
    Require(!assetSummary.Contains("charset=", StringComparison.OrdinalIgnoreCase), "摘要不应携带 Content-Type 参数");
}

/// <summary>
/// 每次「开始采集」都必须从空列表起步：流量读取按捕获会话限定后，
/// 只应返回本次会话的事务，历史会话既不进窗口也不计入本次计数，但仍完整留在库里。
/// </summary>
static async Task VerifyCaptureSessionScopeAsync()
{
    var testRoot = Path.Combine(Path.GetTempPath(), "netmind-scope-test-" + Guid.NewGuid().ToString("N"));
    try
    {
        using var archive = new TrafficArchive(testRoot);
        await archive.InitializeAsync("会话范围测试工作区");
        var traffic = DemoData.CreateTraffic();

        var oldSession = Guid.NewGuid();
        await archive.StartSessionAsync(new CaptureSessionRecord(oldSession, DateTimeOffset.UtcNow.AddMinutes(-10), null,
            NetMindDefaults.SourceSimulated, "上一次采集", NetMindDefaults.SessionStateRunning));
        for (var i = 0; i < 3; i++)
            await archive.RecordAsync(oldSession, traffic[i] with { Id = Guid.NewGuid() }, "req"u8.ToArray(), "res"u8.ToArray());

        var cursorBeforeNewSession = archive.GetLatestTrafficCursor();
        var newSession = Guid.NewGuid();
        await archive.StartSessionAsync(new CaptureSessionRecord(newSession, DateTimeOffset.UtcNow, null,
            NetMindDefaults.SourceSimulated, "本次采集", NetMindDefaults.SessionStateRunning));

        // 新会话尚未产生事务：限定读取必须是空列表，而不限定时仍能看到历史。
        Require(archive.GetTrafficCount(newSession) == 0, "新会话开始时本次会话事务数必须为 0");
        Require(archive.GetRecentTraffic(500, newSession).Count == 0, "新会话开始时列表必须为空，不得加载历史记录");
        Require(archive.GetTrafficCount() == 3 && archive.GetRecentTraffic(500).Count == 3,
            "限定视图不得删除或隐藏历史事务，不限定读取仍应返回全部");

        for (var i = 0; i < 2; i++)
            await archive.RecordAsync(newSession, traffic[i] with { Id = Guid.NewGuid() }, "req2"u8.ToArray(), "res2"u8.ToArray());

        Require(archive.GetTrafficCount(newSession) == 2, "本次会话计数只统计本次会话的事务");
        var scoped = archive.GetRecentTraffic(500, newSession);
        Require(scoped.Count == 2 && scoped.All(item => item.SessionId == newSession), "限定读取只能返回本次会话的事务");
        Require(archive.GetTrafficCount() == 5, "限定读取不得影响全局计数");

        // 增量游标同样要受会话限定：否则采集期间旧会话的完成态更新会漏进本次列表。
        var changes = archive.GetTrafficChangesAfter(cursorBeforeNewSession, sessionId: newSession);
        Require(changes.Count == 2 && changes.All(change => change.Stored.SessionId == newSession),
            "增量读取必须只返回本次会话的变更");
        Require(archive.GetTrafficChangesAfter(0, sessionId: oldSession).Count == 3,
            "限定到历史会话时必须能完整读回该会话的事务");
        Require(archive.GetTrafficChangesAfter(0).Count == 5, "不限定时增量读取仍应覆盖全部会话");
    }
    finally
    {
        if (Directory.Exists(testRoot)) Directory.Delete(testRoot, recursive: true);
    }
}

/// <summary>
/// 被抓取的流量完全由被访问站点控制。URL、Header、Cookie 与查询参数中的单引号、NUL、
/// SQL 注入片段、中文与 4 字节 emoji 都必须作为数据逐字符往返，既不能改变数据库结构，
/// 也不能在写入或读取时被截断。Blob 落盘必须原子，不留临时文件。
/// </summary>
static async Task VerifyHostileEvidenceRoundTripAsync()
{
    const string hostileUrl = "https://evil.test/a'b\"c--d/\u0000/中文/\U0001F510?x=1";
    const string hostileHeaders = "X-Odd: v'1\u0000v2\nX-中文: 值\U0001F510";
    const string hostileCookies = "sid=a'b\u0000c; 名字=值'; emoji=\U0001F510";
    const string hostileQuery = "q=' OR 1=1 --&名=值\u0000&e=\U0001F510";
    const string hostileTarget = "全部进程'; DROP TABLE capture_sessions; --";

    var testRoot = Path.Combine(Path.GetTempPath(), "netmind-hostile-test-" + Guid.NewGuid().ToString("N"));
    try
    {
        using var archive = new TrafficArchive(testRoot);
        await archive.InitializeAsync("恶意证据往返测试工作区");
        var sessionId = Guid.NewGuid();
        await archive.StartSessionAsync(new CaptureSessionRecord(sessionId, DateTimeOffset.UtcNow, null,
            NetMindDefaults.SourceSimulated, hostileTarget, NetMindDefaults.SessionStateRunning));

        var item = DemoData.CreateTraffic()[0] with
        {
            Id = Guid.NewGuid(),
            Url = hostileUrl,
            RequestHeaders = hostileHeaders,
            ResponseHeaders = hostileHeaders,
            Cookies = hostileCookies,
            QueryParameters = hostileQuery,
            RequestSummary = "摘要'; DELETE FROM traffic_transactions; --",
        };
        await archive.RecordAsync(sessionId, item, "请求\u0000正文"u8.ToArray(), "响应正文"u8.ToArray());

        Require(archive.GetTrafficCount() == 1, "注入片段必须作为数据写入，不得改变事务表内容");

        var restored = archive.GetRecentTraffic(10).Single().Traffic;
        Require(restored.Url == hostileUrl, "URL 中的单引号、NUL、中文与 emoji 必须逐字符往返");
        Require(restored.RequestHeaders == hostileHeaders, "请求头必须逐字符往返");
        Require(restored.ResponseHeaders == hostileHeaders, "响应头必须逐字符往返");
        Require(restored.Cookies == hostileCookies, "Cookie 必须逐字符往返");
        Require(restored.QueryParameters == hostileQuery, "查询参数必须逐字符往返");
        Require(restored.RequestSummary == item.RequestSummary, "摘要中的注入片段必须原样保留");
        Require(restored.Url.Contains('\u0000') && restored.Cookies.Contains('\u0000'),
            "NUL 必须作为数据保留，而不是截断 SQL 文本或读取结果");

        // 记录组精确查询与增量游标走不同 SQL，必须给出同样完整的证据。
        var byId = archive.GetTrafficByIds([item.Id]).Single().Traffic;
        Require(byId.Url == hostileUrl && byId.Cookies == hostileCookies, "按 ID 精确查询必须返回同样完整的证据");
        var changes = archive.GetTrafficChangesAfter(0);
        Require(changes.Count == 1 && changes[0].Stored.Traffic.Url == hostileUrl,
            "增量读取必须返回同样完整的证据");

        // 会话表的 target 同样承载外部可控文本。
        var session = archive.GetRecentSessions(10).Single().Session;
        Require(session.Target == hostileTarget, "会话目标中的注入片段必须原样保存为数据");

        // 正文 Blob 必须原子落盘：目录内只应有内容寻址文件，不留 .tmp 残留。
        var blobRoot = Path.Combine(testRoot, NetMindDefaults.BlobsDirectoryName);
        var residue = Directory.EnumerateFiles(blobRoot, "*.tmp", SearchOption.AllDirectories).ToArray();
        Require(residue.Length == 0, "Blob 写入完成后不得留下临时文件");
        var blob = await archive.ReadBlobAsync(archive.GetRecentTraffic(1).Single().RequestBlobHash);
        Require(blob.Content.AsSpan().SequenceEqual("请求\u0000正文"u8), "正文 Blob 必须逐字节往返，含 NUL");
    }
    finally
    {
        if (Directory.Exists(testRoot)) Directory.Delete(testRoot, recursive: true);
    }
}

static async Task VerifyIncrementalTrafficCursorAsync()
{
    var testRoot = Path.Combine(Path.GetTempPath(), "netmind-refresh-test-" + Guid.NewGuid().ToString("N"));
    try
    {
        using var archive = new TrafficArchive(testRoot);
        await archive.InitializeAsync("增量刷新测试工作区");
        var sessionId = Guid.NewGuid();
        await archive.StartSessionAsync(new CaptureSessionRecord(sessionId, DateTimeOffset.UtcNow, null,
            NetMindDefaults.SourceSimulated, "全部进程", NetMindDefaults.SessionStateRunning));
        var first = DemoData.CreateTraffic()[0];
        var stored = await archive.RecordAsync(sessionId, first, "request"u8.ToArray(), "response"u8.ToArray());
        var firstCursor = archive.GetLatestTrafficCursor();
        var initialChanges = archive.GetTrafficChangesAfter(0);
        Require(firstCursor > 0 && initialChanges.Count == 1 && initialChanges[0].Cursor == firstCursor &&
                initialChanges[0].Stored.Traffic.Id == first.Id,
            "首次增量读取必须返回新事务及其 SQLite 写入游标");

        var completed = stored with { Traffic = stored.Traffic with { StatusCode = 201, ResponseSummary = "完成态" } };
        await archive.UpdateTrafficAsync(completed);
        var updateChanges = archive.GetTrafficChangesAfter(firstCursor);
        Require(archive.GetTrafficCount() == 1 && updateChanges.Count == 1 &&
                updateChanges[0].Cursor > firstCursor && updateChanges[0].Stored.Traffic.StatusCode == 201,
            "同一事务完成态更新必须产生新游标且不得增加事务总数");
        Require(archive.GetTrafficChangesAfter(updateChanges[0].Cursor).Count == 0,
            "游标追平后空闲轮询不得重复读取最近窗口");
    }
    finally
    {
        if (Directory.Exists(testRoot)) Directory.Delete(testRoot, recursive: true);
    }
}

static async Task VerifyDeleteTrafficAsync()
{
    var testRoot = Path.Combine(Path.GetTempPath(), "netmind-delete-test-" + Guid.NewGuid().ToString("N"));
    try
    {
        using var archive = new TrafficArchive(testRoot);
        await archive.InitializeAsync("勾选删除测试工作区");
        var auditPath = Path.Combine(testRoot, NetMindDefaults.LogsDirectoryName, NetMindDefaults.AuditLogFileName);
        var auditLengthBefore = new FileInfo(auditPath).Length;

        var sessionId = Guid.NewGuid();
        await archive.StartSessionAsync(new CaptureSessionRecord(
            sessionId, DateTimeOffset.UtcNow, null, NetMindDefaults.SourceRealProxy, "定向测试", NetMindDefaults.SessionStateCompleted));
        // A、B 正文完全相同（内容寻址下共享同一 Blob），C 与 A 共享请求正文、响应正文独有。
        var trafficA = new TrafficRecord(
            Guid.NewGuid(), DateTimeOffset.UtcNow, "POST", "/api/delete-a", 200, 8, 16,
            "NetMind.SmokeTests", "HTTP/1.1", "测试请求A", "测试响应A");
        var trafficB = new TrafficRecord(
            Guid.NewGuid(), DateTimeOffset.UtcNow, "POST", "/api/delete-b", 200, 8, 16,
            "NetMind.SmokeTests", "HTTP/1.1", "测试请求B", "测试响应B");
        var trafficC = new TrafficRecord(
            Guid.NewGuid(), DateTimeOffset.UtcNow, "GET", "/api/keep-c", 200, 5, 12,
            "NetMind.SmokeTests", "HTTP/1.1", "测试请求C", "测试响应C");
        await archive.RecordAsync(sessionId, trafficA, Encoding.UTF8.GetBytes("shared-request"), Encoding.UTF8.GetBytes("shared-response"));
        await archive.RecordAsync(sessionId, trafficB, Encoding.UTF8.GetBytes("shared-request"), Encoding.UTF8.GetBytes("shared-response"));
        await archive.RecordAsync(sessionId, trafficC, Encoding.UTF8.GetBytes("shared-request"), Encoding.UTF8.GetBytes("unique-response"));
        Require(archive.GetTrafficCount() == 3, "删除前应存在三条流量事务");

        Require(await archive.DeleteTrafficAsync([]) == 0, "空 ID 集合删除必须返回 0");
        var deleted = await archive.DeleteTrafficAsync([trafficA.Id, trafficB.Id]);

        Require(deleted == 2, "定向删除应返回实际删除条数");
        Require(archive.GetTrafficCount() == 1, "定向删除后仅应保留未勾选事务");
        Require(archive.GetTrafficByIds([trafficC.Id]).Count == 1, "未勾选事务必须保留可读");
        Require(archive.GetTrafficByIds([trafficA.Id, trafficB.Id]).Count == 0, "已删除事务不得再可读");
        var remainingBlobs = Directory.EnumerateFiles(Path.Combine(testRoot, NetMindDefaults.BlobsDirectoryName), "*", SearchOption.AllDirectories).Count();
        Require(remainingBlobs == 2, "共享请求正文（C 仍引用）与 C 独有响应正文必须保留，其余孤儿 Blob 必须删除，实际 " + remainingBlobs);
        Require(new FileInfo(auditPath).Length > auditLengthBefore, "定向删除必须追加审计日志");
        Require((await File.ReadAllTextAsync(auditPath)).Contains("workspace.traffic-deleted", StringComparison.Ordinal),
            "审计日志必须记录定向删除事件");
    }
    finally
    {
        if (Directory.Exists(testRoot)) Directory.Delete(testRoot, recursive: true);
    }
}

static async Task VerifyClearCaptureDataAsync()
{
    var testRoot = Path.Combine(Path.GetTempPath(), "netmind-clear-test-" + Guid.NewGuid().ToString("N"));
    try
    {
        using var archive = new TrafficArchive(testRoot);
        await archive.InitializeAsync("清空记录测试工作区");
        var workspacePath = Path.Combine(testRoot, NetMindDefaults.WorkspaceManifestFileName);
        var auditPath = Path.Combine(testRoot, NetMindDefaults.LogsDirectoryName, NetMindDefaults.AuditLogFileName);
        var workspaceBefore = await File.ReadAllTextAsync(workspacePath);
        var auditLengthBefore = new FileInfo(auditPath).Length;

        var sessionId = Guid.NewGuid();
        await archive.StartSessionAsync(new CaptureSessionRecord(
            sessionId, DateTimeOffset.UtcNow, null, NetMindDefaults.SourceRealProxy, "定向测试", NetMindDefaults.SessionStateCompleted));
        var traffic = new TrafficRecord(
            Guid.NewGuid(), DateTimeOffset.UtcNow, "POST", "/api/clear-test", 200, 8, 16,
            "NetMind.SmokeTests", "HTTP/1.1", "测试请求", "测试响应");
        await archive.RecordAsync(sessionId, traffic, Encoding.UTF8.GetBytes("request"), Encoding.UTF8.GetBytes("response"));

        Require(archive.GetTrafficCount() == 1, "清空前应存在一条流量事务");
        Require(archive.GetRecentSessions().Count == 1, "清空前应存在一个捕获会话");
        Require(Directory.EnumerateFiles(Path.Combine(testRoot, NetMindDefaults.BlobsDirectoryName), "*", SearchOption.AllDirectories).Any(),
            "清空前应存在正文 Blob");

        var deleted = await archive.ClearAsync();

        Require(deleted == 1, "清空操作应返回已删除的流量事务数");
        Require(archive.GetTrafficCount() == 0, "清空后不应保留流量事务");
        Require(archive.GetRecentSessions().Count == 0, "清空后不应保留捕获会话");
        Require(!Directory.EnumerateFiles(Path.Combine(testRoot, NetMindDefaults.BlobsDirectoryName), "*", SearchOption.AllDirectories).Any(),
            "清空后不应保留正文 Blob");
        Require(await File.ReadAllTextAsync(workspacePath) == workspaceBefore, "清空记录不得修改工作区配置");
        Require(new FileInfo(auditPath).Length > auditLengthBefore, "清空记录必须保留并追加审计日志");
        Require((await File.ReadAllTextAsync(auditPath)).Contains("workspace.capture-data-cleared", StringComparison.Ordinal),
            "审计日志必须记录清空事件");

        // 采集进行中清空的回归：第二个归档连接模拟采集进程，清空必须成功且不影响后续新记录写入。
        using var writer = new TrafficArchive(testRoot);
        var liveSession = Guid.NewGuid();
        await writer.StartSessionAsync(new CaptureSessionRecord(
            liveSession, DateTimeOffset.UtcNow, null, NetMindDefaults.SourceRealProxy, "定向测试", NetMindDefaults.SessionStateRunning));
        var liveTraffic = new TrafficRecord(
            Guid.NewGuid(), DateTimeOffset.UtcNow, "GET", "/api/live-during-clear", 200, 3, 8,
            "NetMind.SmokeTests", "HTTP/1.1", "采集进行中", "新记录");
        await writer.RecordAsync(liveSession, liveTraffic, Encoding.UTF8.GetBytes("live-request"), Encoding.UTF8.GetBytes("live-response"));
        var deletedDuringCapture = await archive.ClearAsync();
        Require(deletedDuringCapture == 1, "采集进行中清空必须成功删除已写入事务");
        // 运行中会话行必须保留（事务外键引用会话），采集进程用原会话继续写入不得失败。
        await writer.RecordAsync(liveSession, new TrafficRecord(
            Guid.NewGuid(), DateTimeOffset.UtcNow, "GET", "/api/after-clear", 200, 3, 8,
            "NetMind.SmokeTests", "HTTP/1.1", "清空后", "继续写入"),
            Encoding.UTF8.GetBytes("after-request"), Encoding.UTF8.GetBytes("after-response"));
        Require(archive.GetTrafficCount() == 1, "清空后采集进程用原会话写入的新事务必须可读");
        Require(archive.GetRecentSessions().Any(session => session.Session.Id == liveSession),
            "运行中的采集会话不得被清空操作删除");
    }
    finally
    {
        if (Directory.Exists(testRoot)) Directory.Delete(testRoot, recursive: true);
    }
}

static void VerifyTrafficSelectionScope()
{
    var visibleFirst = Guid.NewGuid();
    var hiddenBetween = Guid.NewGuid();
    var visibleMiddle = Guid.NewGuid();
    var visibleLast = Guid.NewGuid();
    var visible = new[] { visibleFirst, visibleMiddle, visibleLast };
    var range = TrafficSelectionScope.ResolveVisibleRange(visible, visibleFirst, visibleLast);
    Require(range.SequenceEqual(visible) && !range.Contains(hiddenBetween),
        "Shift 范围只能包含当前显示顺序中的行，不能把底层隐藏行算入");
    Require(TrafficSelectionScope.ResolveVisibleRange(visible, hiddenBetween, visibleLast).SequenceEqual([visibleLast]),
        "锚点被筛掉时 Shift 范围必须退化为当前目标行");

    IReadOnlySet<Guid> checkedIds = new HashSet<Guid> { visibleFirst, hiddenBetween, visibleLast };
    var currentChecked = TrafficSelectionScope.IntersectVisibleChecked(visible, checkedIds);
    Require(currentChecked.SequenceEqual([visibleFirst, visibleLast]) && !currentChecked.Contains(hiddenBetween),
        "保存记录组和 AI 证据必须使用当前可见行与勾选集合的交集");
}

static void VerifyTrafficFilterExpression()
{
    const string text = "GET https://api.bigmodel.cn/api/auth/login 200 HTTPS 解密 · chrome.exe";
    Require(TrafficFilterExpression.Compile("")(text), "空查询必须命中所有记录");
    Require(TrafficFilterExpression.Compile("login")(text) && !TrafficFilterExpression.Compile("wechat")(text),
        "不含运算符的查询必须保持原子串搜索语义");
    Require(TrafficFilterExpression.Compile("a=1&b=2")("GET /x?a=1&b=2"), "单个 & 属于 URL 内容，不得当作运算符");
    Require(TrafficFilterExpression.Compile("login && chrome")(text) && !TrafficFilterExpression.Compile("login && wechat")(text),
        "&& 必须要求两个关键词同时命中");
    Require(TrafficFilterExpression.Compile("wechat || login")(text) && !TrafficFilterExpression.Compile("wechat || css")(text),
        "|| 任一关键词命中即通过");
    Require(!TrafficFilterExpression.Compile("!login")(text) && TrafficFilterExpression.Compile("!wechat")(text),
        "! 必须排除命中关键词的记录");
    Require(TrafficFilterExpression.Compile("(wechat || login) && chrome")(text) &&
            !TrafficFilterExpression.Compile("(wechat || css) && chrome")(text),
        "() 分组必须改变运算符组合语义");
    Require(TrafficFilterExpression.Compile("chrome || wechat && css")(text),
        "&& 优先级必须高于 ||（等价 chrome || (wechat && css)");
    Require(TrafficFilterExpression.Compile("\"HTTPS 解密\" && login")(text), "双引号必须支持包含空格的关键词");
    var broken = TrafficFilterExpression.Compile("(login && chrome");
    Require(!broken(text), "括号不配对的表达式必须回退为整串子串匹配而不是抛异常");
    Require(TrafficFilterExpression.Compile("&&")("任意 && 文本") && !TrafficFilterExpression.Compile("&&")(text),
        "孤立运算符必须回退为整串子串匹配");
}

static void VerifyTrafficCopyFormatting()
{
    var traffic = new TrafficRecord(
        Guid.NewGuid(), DateTimeOffset.UtcNow, "POST", "/api/items?token=owner-secret", 201, 23, 19,
        "copy-test.exe · 42", "HTTP/1.1", "请求摘要", "响应摘要",
        "http://localhost/api/items?token=owner-secret", "token = owner-secret",
        "Host: localhost\nAuthorization: Bearer owner-secret\nCookie: session=owner-cookie\nContent-Type: application/json\nContent-Length: 19\nConnection: keep-alive\nX-Note: O'Brien",
        "session = owner-cookie", "Content-Type: application/json");
    var requestBody = Encoding.UTF8.GetBytes("{\"name\":\"O'Brien\"}");
    var curl = TrafficCopyFormatter.BuildPowerShellCurl(traffic, requestBody);
    Require(curl.Contains("curl.exe --request 'POST'", StringComparison.Ordinal), "cURL 必须包含 HTTP 方法");
    Require(curl.Contains("owner-secret", StringComparison.Ordinal) && curl.Contains("owner-cookie", StringComparison.Ordinal),
        "原始 cURL 必须保留工作区所有者需要的原始凭据");
    Require(curl.Contains("O''Brien", StringComparison.Ordinal), "PowerShell cURL 必须正确转义单引号");
    Require(!curl.Contains("Content-Length", StringComparison.OrdinalIgnoreCase) &&
            !curl.Contains("Connection: keep-alive", StringComparison.OrdinalIgnoreCase) &&
            !curl.Contains("--header 'Host:", StringComparison.OrdinalIgnoreCase),
        "cURL 不得复制由客户端重新计算的连接级请求头");

    var rawEvidence = TrafficCopyFormatter.BuildRawEvidence(traffic, Encoding.UTF8.GetString(requestBody), "{\"ok\":true}");
    Require(rawEvidence.Contains("【完整 URL】", StringComparison.Ordinal) &&
            rawEvidence.Contains("owner-secret", StringComparison.Ordinal) &&
            rawEvidence.Contains("owner-cookie", StringComparison.Ordinal),
        "完整原始证据必须包含所有可复制区块和本地原值");
    var redacted = AiPrivacyFilter.BuildJson([traffic], 1);
    Require(!redacted.Contains("owner-secret", StringComparison.Ordinal) && !redacted.Contains("owner-cookie", StringComparison.Ordinal),
        "脱敏副本不得包含原始令牌或 Cookie");

    var connectRejected = false;
    try { TrafficCopyFormatter.BuildPowerShellCurl(traffic with { Method = "CONNECT", Protocol = NetMindDefaults.ProtocolHttpsTunnel }, []); }
    catch (InvalidOperationException) { connectRejected = true; }
    Require(connectRejected, "HTTPS CONNECT 不得生成伪造的 cURL 重放命令");

    var binaryRejected = false;
    try { TrafficCopyFormatter.BuildPowerShellCurl(traffic, new byte[] { 0xff, 0xfe, 0x00 }); }
    catch (InvalidOperationException) { binaryRejected = true; }
    Require(binaryRejected, "二进制请求正文不得生成损坏的文本 cURL 命令");
}

static void VerifyJsonPreview()
{
    // 解码断言：\uXXXX 必须在展示层解码为中文，且扁平文本不得重新转义。
    var escapedJson = Encoding.UTF8.GetBytes("{\"k\":\"\\u4E8E\\u6587\"}");
    Require(JsonPreviewTreeBuilder.TryBuild(escapedJson, truncated: false, out var root, out var buildReason) &&
            buildReason is null && root is not null,
        "有效 JSON 必须成功构建预览树且不返回降级原因");
    var member = root!.Children.Single();
    Require(member.Key == "k" && member.Kind == JsonTreeNodeKind.String && member.DisplayText == "于文",
        "预览树字符串值必须把 \\uXXXX 转义解码为中文");
    var flatText = JsonPreviewText.Build(escapedJson);
    Require(flatText.Contains("于文", StringComparison.Ordinal) && !flatText.Contains("\\u4E8E", StringComparison.Ordinal),
        "JSON 扁平文本必须输出解码后的中文，不得重新转义为 \\uXXXX");

    // 降级断言：截断、超限与无效 JSON 都必须拒绝建树并给出中文原因。
    Require(!JsonPreviewTreeBuilder.TryBuild(escapedJson, truncated: true, out var truncatedRoot, out var truncatedReason) &&
            truncatedRoot is null && !string.IsNullOrWhiteSpace(truncatedReason),
        "截断正文不得构建 JSON 树，必须给出中文降级原因");
    var oversizedJson = Encoding.UTF8.GetBytes("{\"data\":\"" + new string('a', NetMindDefaults.JsonTreeMaximumBytes) + "\"}");
    Require(!JsonPreviewTreeBuilder.TryBuild(oversizedJson, truncated: false, out _, out var oversizedReason) &&
            !string.IsNullOrWhiteSpace(oversizedReason),
        $"超过 {NetMindDefaults.JsonTreeMaximumBytes} 字节的 JSON 必须降级且说明原因");
    Require(!JsonPreviewTreeBuilder.TryBuild(Encoding.UTF8.GetBytes("{\"a\":"), truncated: false, out _, out var invalidReason) &&
            !string.IsNullOrWhiteSpace(invalidReason),
        "无效 JSON 必须拒绝建树并给出中文原因");

    // 边界断言：507 个元素只物化 500 个子项加 1 个中文省略提示节点。
    var manyItemsJson = Encoding.UTF8.GetBytes("[" + string.Join(",", Enumerable.Range(0, NetMindDefaults.JsonTreeMaximumChildrenPerNode + 7)) + "]");
    Require(JsonPreviewTreeBuilder.TryBuild(manyItemsJson, truncated: false, out var arrayRoot, out _),
        "含 507 个元素的数组必须成功建树");
    Require(arrayRoot!.IsContainer && arrayRoot.ChildrenCount == NetMindDefaults.JsonTreeMaximumChildrenPerNode + 7,
        "容器 ChildrenCount 必须是真实子项总数");
    var materialized = arrayRoot.Children;
    Require(materialized.Count == NetMindDefaults.JsonTreeMaximumChildrenPerNode + 1,
        "超限容器只能物化前 500 个子项并追加 1 个省略提示节点");
    Require(materialized.Take(NetMindDefaults.JsonTreeMaximumChildrenPerNode).All(node => !node.IsEllipsis),
        "正常物化的子项不得被标记为省略提示");
    var ellipsis = materialized[^1];
    Require(ellipsis.IsEllipsis && !ellipsis.IsContainer &&
            ellipsis.DisplayText.Contains("其余 7 项已省略", StringComparison.Ordinal),
        "省略提示节点必须标记 IsEllipsis 并使用中文文案");

    // 边界断言：超长字符串值展示必须截断并附带中文省略标记。
    var longValue = new string('长', NetMindDefaults.JsonPreviewMaximumValueCharacters + 100);
    var longValueJson = Encoding.UTF8.GetBytes("{\"note\":\"" + longValue + "\"}");
    Require(JsonPreviewTreeBuilder.TryBuild(longValueJson, truncated: false, out var longRoot, out _),
        "超长字符串值必须成功建树");
    var longNode = longRoot!.Children.Single();
    Require(longNode.DisplayText.Length < longValue.Length &&
            longNode.DisplayText.StartsWith(longValue[..NetMindDefaults.JsonPreviewMaximumValueCharacters], StringComparison.Ordinal) &&
            longNode.DisplayText.Contains($"共 {longValue.Length:N0} 字符，已截断", StringComparison.Ordinal),
        "超长字符串值展示必须截断并附带中文省略标记");

    // 内嵌 JSON 断言：字符串字段本身是 JSON 时必须展开为子树，长值逐字段截断，不得吞掉长字段之后的兄弟字段。
    var embeddedLong = new string('x', NetMindDefaults.JsonPreviewMaximumValueCharacters + 500);
    var embeddedJson = Encoding.UTF8.GetBytes(
        "{\"responseBody\":\"{\\\"a\\\":333,\\\"b\\\":\\\"" + embeddedLong + "\\\",\\\"c\\\":2222}\",\"after\":1}");
    Require(JsonPreviewTreeBuilder.TryBuild(embeddedJson, truncated: false, out var embeddedRoot, out _),
        "含内嵌 JSON 字符串字段的 JSON 必须成功建树");
    var bodyNode = embeddedRoot!.Children.Single(node => node.Key == "responseBody");
    Require(bodyNode.IsContainer && bodyNode.ChildrenCount == 3 &&
            bodyNode.DisplayText.Contains("字符串内嵌 JSON", StringComparison.Ordinal),
        "内嵌 JSON 字符串必须展开为容器子树并标注来源");
    var embeddedLongNode = bodyNode.Children.Single(node => node.Key == "b");
    Require(embeddedLongNode.DisplayText.Length < embeddedLong.Length &&
            embeddedLongNode.DisplayText.Contains("已截断", StringComparison.Ordinal),
        "内嵌 JSON 内的长值必须逐字段截断而不是整串截断");
    Require(bodyNode.Children.Any(node => node.Key == "c"),
        "内嵌 JSON 长字段之后的兄弟字段不得被吞掉");
    Require(embeddedRoot.Children.Any(node => node.Key == "after"),
        "内嵌 JSON 字段的外层兄弟字段不得受影响");

    // 复制/展示隔离回归锁：原始复制路径直通 \uXXXX 字面量，展示层不得改写输入字节。
    var rawBodyText = "{\"k\":\"\\u4E8E\\u6587\"}";
    var copyTraffic = new TrafficRecord(
        Guid.NewGuid(), DateTimeOffset.UtcNow, "POST", "/api/json-preview", 200, 12, rawBodyText.Length,
        "NetMind.SmokeTests", "HTTP/1.1", "请求摘要", "响应摘要");
    var rawEvidence = TrafficCopyFormatter.BuildRawEvidence(copyTraffic, rawBodyText, rawBodyText);
    Require(rawEvidence.Contains("\\u4E8E", StringComparison.Ordinal) && !rawEvidence.Contains("于文", StringComparison.Ordinal),
        "原始证据复制必须直通原始字节文本，不得被展示层解码污染");
    var displayInput = Encoding.UTF8.GetBytes(rawBodyText);
    var displayInputBefore = (byte[])displayInput.Clone();
    Require(JsonPreviewTreeBuilder.TryBuild(displayInput, truncated: false, out _, out _) && JsonPreviewText.Build(displayInput).Contains("于文", StringComparison.Ordinal),
        "隔离回归样例必须可建树并输出解码文本");
    Require(displayInput.SequenceEqual(displayInputBefore),
        "JSON 展示层不得改写输入字节数组");
}

static async Task VerifyAiGatewayAsync()
{
    // ── 网关层：SSE 流式 + tool_calls 分片拼接 ─────────────────────────
    var capturedRequests = new List<string>();
    // SSE 数据行由序列化器生成，避免手工多层转义；arguments 分片到达，需网关按 index 拼接。
    string SseLine(object chunk) => "data: " + JsonSerializer.Serialize(chunk);
    var toolCallSse = string.Join("\n\n",
        SseLine(new { id = "resp-1", model = "deepseek-v4-flash", choices = new object[] { new { index = 0, delta = new { role = "assistant", tool_calls = new object[] { new { index = 0, id = "call-abc", type = "function", function = new { name = "get_tra" } } } } } } }),
        SseLine(new { id = "resp-1", choices = new object[] { new { index = 0, delta = new { tool_calls = new object[] { new { index = 0, function = new { name = "nsactions", arguments = @"{""ord" } } } } } } }),
        SseLine(new { id = "resp-1", choices = new object[] { new { index = 0, delta = new { tool_calls = new object[] { new { index = 0, function = new { arguments = @"inals"":[1]}" } } } }, finish_reason = "tool_calls" } } }),
        SseLine(new { id = "resp-1", choices = Array.Empty<object>(), usage = new { prompt_tokens = 100, completion_tokens = 10 } }),
        "data: [DONE]") + "\n\n";
    var listener = await StartFakeAiSseGatewayAsync(capturedRequests, requestIndex => toolCallSse, expectedRequests: 1);
    var endpoint = (IPEndPoint)listener.LocalEndpoint;
    var settings = new AiGatewaySettings($"http://127.0.0.1:{endpoint.Port}", "deepseek-v4-flash", "chat_completions", "high", 900);
    using (var gateway = new AiGatewayClient())
    {
        var turn = await gateway.AnalyzeConversationAsync(settings, "test-api-key",
            [new AiChatMessage("system", "系统提示"), new AiChatMessage("user", "首轮提问")],
            AiConversationEngine.BuildToolSchemas());
        Require(turn.ToolCalls.Count == 1 && turn.ToolCalls[0].Id == "call-abc" &&
                turn.ToolCalls[0].Name == "get_transactions" && turn.ToolCalls[0].ArgumentsJson == "{\"ordinals\":[1]}",
            "AI 网关必须把跨分片的 tool_calls 按 index 拼接还原");
        Require(turn.InputTokens == 100 && turn.OutputTokens == 10, "AI 网关必须从流式 usage 还原令牌用量");
        Require(turn.FinishReason == "tool_calls", "AI 网关必须还原流式停止原因");
    }
    listener.Stop();
    var firstRequest = capturedRequests.Single();
    Require(firstRequest.StartsWith("POST /chat/completions HTTP/1.1", StringComparison.Ordinal) &&
            firstRequest.Contains("Authorization: Bearer test-api-key", StringComparison.OrdinalIgnoreCase),
        "对话式请求必须调用 /chat/completions 并使用 Bearer 密钥认证");
    Require(firstRequest.Contains("\"stream\":true", StringComparison.Ordinal) &&
            firstRequest.Contains("\"tool_choice\":\"auto\"", StringComparison.Ordinal) &&
            firstRequest.Contains("\"include_usage\":true", StringComparison.Ordinal),
        "对话式请求必须启用流式、工具自动选择与 usage 上报");
    Require(firstRequest.Contains("\"name\":\"get_transactions\"", StringComparison.Ordinal) &&
            firstRequest.Contains("\"name\":\"get_transaction_body_excerpt\"", StringComparison.Ordinal) &&
            firstRequest.Contains("\"name\":\"get_evidence_files\"", StringComparison.Ordinal),
        "对话式请求必须携带事务概览、正文片段与证据文件工具声明");
    Require(!firstRequest.Contains("\"thinking\"", StringComparison.Ordinal) &&
            firstRequest.Contains("\"reasoning_effort\":\"high\"", StringComparison.Ordinal),
        "DeepSeek 携带 tools 时不得启用 thinking，但保留 reasoning_effort");

    // ── 引擎层：取数回环 + 单轮预算截断 + JSONL 持久化往返 ───────────────
    var conversationRoot = Path.Combine(Path.GetTempPath(), "netmind-ai-conversation-test-" + Guid.NewGuid().ToString("N"));
    try
    {
        var pool = new[]
        {
            new TrafficRecord(Guid.NewGuid(), DateTimeOffset.UtcNow.AddMinutes(-2), "GET", "/login", 200, 12, 512,
                "browser.exe · 99", "HTTP/1.1", "登录页", "登录成功",
                "http://example.test/login", string.Empty, "Host: example.test", string.Empty, "Content-Type: application/json"),
            new TrafficRecord(Guid.NewGuid(), DateTimeOffset.UtcNow.AddMinutes(-1), "POST", "/api/data", 200, 30, 2048,
                "browser.exe · 99", "HTTP/1.1", "sign=owner-secret", "响应含令牌",
                "http://example.test/api/data?sign=owner-secret", "sign = owner-secret", "Host: example.test", string.Empty, "Content-Type: application/json")
        };
        var provider = new FakeAiEvidenceProvider(pool);
        var store = new AiConversationStore(conversationRoot);
        var conversationId = Guid.NewGuid();
        await store.CreateAsync(new AiConversationHeader(conversationId, DateTimeOffset.UtcNow, AiPromptTemplate.DefaultTemplateId,
            "deepseek-v4-flash", "定向测试", pool.Select(item => item.Id).ToArray()));

        var finalSse = string.Join("\n\n",
            SseLine(new { id = "resp-2", model = "deepseek-v4-flash", choices = new object[] { new { index = 0, delta = new { content = "分析结论：sign 参数来自登录响应。" } } } }),
            SseLine(new { id = "resp-2", choices = new object[] { new { index = 0, delta = new { }, finish_reason = "stop" } }, usage = new { prompt_tokens = 200, completion_tokens = 20 } }),
            "data: [DONE]") + "\n\n";
        var loopRequests = new List<string>();
        var loopListener = await StartFakeAiSseGatewayAsync(loopRequests,
            requestIndex => requestIndex == 0 ? toolCallSse : finalSse, expectedRequests: 2);
        var loopSettings = new AiGatewaySettings($"http://127.0.0.1:{((IPEndPoint)loopListener.LocalEndpoint).Port}", "deepseek-v4-flash", "chat_completions", "high", 900);
        using (var gateway = new AiGatewayClient())
        {
            var engine = new AiConversationEngine(gateway);
            var history = new List<AiChatMessage> { new("system", AiPromptTemplate.Get(null).SystemPrompt) };
            var fetchedTools = new List<string>();
            var streamedText = new StringBuilder();
            var firstUserMessage = AiConversationEngine.BuildFirstUserMessage(pool, AiPromptTemplate.Get(null));
            Require(firstUserMessage.Contains("证据池概况", StringComparison.Ordinal) &&
                    firstUserMessage.Contains("最慢", StringComparison.Ordinal) &&
                    !AiConversationEngine.BuildEvidenceSummary(pool).Contains("owner-secret", StringComparison.Ordinal),
                "首轮应提供确定性证据概况，摘要只列查询键而不内联查询值");
            var outcome = await engine.RunTurnAsync(loopSettings, "test-api-key", provider, history, firstUserMessage,
                store, conversationId, new AiStreamCallbacks
                {
                    OnToolFetch = (name, _) => fetchedTools.Add(name),
                    OnTextDelta = delta => streamedText.Append(delta)
                });
            Require(outcome.AssistantText.Contains("sign 参数来自登录响应", StringComparison.Ordinal),
                "会话引擎必须执行取数回环并产出最终文本");
            Require(outcome.ToolFetchCount == 1 && fetchedTools.Single() == "get_transactions",
                "会话引擎必须执行模型要求的取数并回报取数进度");
            Require(streamedText.ToString().Contains("分析结论", StringComparison.Ordinal),
                "流式增量必须实时回调给界面");
            Require(outcome.InputTokens == 300 && outcome.OutputTokens == 30, "会话引擎必须累计多轮令牌用量");
            var savedTrace = history[2].ToolTraces?.SingleOrDefault();
            Require(history.Count == 3 && history[1].Role == "user" && history[2].Role == "assistant" &&
                    history[2].ToolCalls is null && savedTrace is not null &&
                    savedTrace.Name == "get_transactions" && savedTrace.ResultSha256.Length == 64 &&
                    savedTrace.EvidenceReference.StartsWith("get_transactions@", StringComparison.Ordinal),
                "持久会话只应追加 user→最终 assistant，并在最终消息保存轻量工具摘要");
            Require(!string.Join('\n', history.Select(AiChatMessageJson.Serialize)).Contains("owner-secret", StringComparison.Ordinal),
                "工具原始结果不得进入长期会话历史");
        }
        loopListener.Stop();
        Require(loopRequests.Count == 2, "取数回环必须在追加 tool 结果后再次调用网关");
        Require(loopRequests[1].Contains("\"tool_call_id\":\"call-abc\"", StringComparison.Ordinal) &&
                loopRequests[1].Contains("owner-secret", StringComparison.Ordinal),
            "当前用户回合的收尾请求必须携带临时 tool 结果与已取回数据");

        var restored = await store.LoadAsync(conversationId);
        Require(restored is not null && restored.Header.Id == conversationId &&
                restored.Header.TemplateId == AiPromptTemplate.DefaultTemplateId &&
                restored.Messages.Count == 2 && AiConversationStore.CountTurns(restored.Messages) == 1,
            "会话 JSONL 必须恢复用户问题、最终回答、轻量工具摘要与轮数，且不落盘工具原文");
        Require(restored!.Messages[0].Role == "user" && restored.Messages[0].Content!.Contains("证据池摘要", StringComparison.Ordinal),
            "恢复的首条消息必须是含证据池摘要的首轮提问");
        Require(restored.Messages[1].ToolTraces is { Count: 1 } &&
                !string.Join('\n', restored.Messages.Select(AiChatMessageJson.Serialize)).Contains("owner-secret", StringComparison.Ordinal),
            "跨重启恢复必须保留工具审计摘要但不能包含工具原文");
        var restoredTrace = restored.Messages[1].ToolTraces!.Single();
        Require(restored.Messages.All(message => message.CreatedAt.HasValue),
            "新写入的会话消息必须带时间，完整导出才能还原对话顺序");

        var exportConversation = restored with
        {
            Messages = [new AiChatMessage("system", "系统提示：只基于证据回答。", CreatedAt: DateTimeOffset.UtcNow), .. restored.Messages]
        };
        var conversationMarkdown = AiConversationExportFormatter.BuildMarkdown(exportConversation);
        Require(conversationMarkdown.StartsWith("# NetMind AI 完整对话记录", StringComparison.Ordinal) &&
                conversationMarkdown.Contains("## 系统提示词", StringComparison.Ordinal) &&
                conversationMarkdown.Contains("第 1 轮 · 用户", StringComparison.Ordinal) &&
                conversationMarkdown.Contains("第 1 轮 · AI 回复", StringComparison.Ordinal) &&
                conversationMarkdown.Contains("get_transactions", StringComparison.Ordinal) &&
                conversationMarkdown.Contains(restoredTrace.EvidenceReference, StringComparison.Ordinal) &&
                conversationMarkdown.Contains(restoredTrace.ResultSha256, StringComparison.Ordinal) &&
                conversationMarkdown.Contains("输入 300 / 输出 30", StringComparison.Ordinal),
            "完整对话导出必须包含系统提示、全部角色、取数流程与每轮统计");

        var privacyConversation = new AiConversation(exportConversation.Header,
        [
            new AiChatMessage("system", "system"),
            new AiChatMessage("user", "{\"guest_token\":\"owner-token\",\"normal\":\"kept\"}"),
            new AiChatMessage("assistant", "Authorization: Bearer owner-secret\nhttps://example.test/?session=owner-session"),
            new AiChatMessage("tool", "{\"cookie\":\"owner-cookie\",\"value\":42}", ToolCallId: "call-1", Name: "get_transactions")
        ]);
        var privacyMarkdown = AiConversationExportFormatter.BuildMarkdown(privacyConversation);
        Require(!privacyMarkdown.Contains("owner-token", StringComparison.Ordinal) &&
                !privacyMarkdown.Contains("owner-secret", StringComparison.Ordinal) &&
                !privacyMarkdown.Contains("owner-session", StringComparison.Ordinal) &&
                !privacyMarkdown.Contains("owner-cookie", StringComparison.Ordinal) &&
                privacyMarkdown.Contains("kept", StringComparison.Ordinal) &&
                privacyMarkdown.Contains(NetMindDefaults.RedactedPlaceholder, StringComparison.Ordinal),
            "完整对话导出必须递归脱敏 JSON、Header 与 URL，同时保留普通内容");
        var summaries = await store.GetRecentAsync();
        Require(summaries.Count == 1 && summaries[0].TurnCount == 1 && summaries[0].Id == conversationId,
            "会话列表必须返回标题所需的模板、时间与轮数");

        // 追问载荷不得重新发送首轮工具原文；模型如需原证据应再次调用只读工具。
        var followUpRequests = new List<string>();
        var followUpListener = await StartFakeAiSseGatewayAsync(followUpRequests, _ => finalSse, expectedRequests: 1);
        var followUpSettings = new AiGatewaySettings($"http://127.0.0.1:{((IPEndPoint)followUpListener.LocalEndpoint).Port}", "deepseek-v4-flash", "chat_completions", "high", 900);
        using (var followUpGateway = new AiGatewayClient())
        {
            var followUpEngine = new AiConversationEngine(followUpGateway);
            List<AiChatMessage> followUpHistory = [new("system", AiPromptTemplate.Get(null).SystemPrompt), .. restored.Messages];
            await followUpEngine.RunTurnAsync(followUpSettings, "test-api-key", provider, followUpHistory,
                "继续解释签名参数", null, Guid.Empty);
        }
        followUpListener.Stop();
        Require(followUpRequests.Count == 1 &&
                !followUpRequests[0].Contains("owner-secret", StringComparison.Ordinal) &&
                !followUpRequests[0].Contains("tool_call_id", StringComparison.Ordinal) &&
                followUpRequests[0].Contains("evidence-ledger", StringComparison.Ordinal) &&
                followUpRequests[0].Contains(restored.Messages[1].ToolTraces![0].EvidenceReference, StringComparison.Ordinal) &&
                followUpRequests[0].Contains(restored.Messages[1].ToolTraces![0].ResultSha256, StringComparison.Ordinal),
            "追问请求不得重发上一轮工具原文或旧工具协议消息，但应携带轻量证据校验账本");

        // 单轮取数预算截断：provider 返回超过当前预算的结果时必须截断并只保留轻量摘要。
        provider.NextFetchResult = new string('数', NetMindDefaults.AiToolFetchBudgetBytesPerTurn);
        var budgetRequests = new List<string>();
        var budgetListener = await StartFakeAiSseGatewayAsync(budgetRequests,
            requestIndex => requestIndex == 0 ? toolCallSse : finalSse, expectedRequests: 2);
        var budgetSettings = new AiGatewaySettings($"http://127.0.0.1:{((IPEndPoint)budgetListener.LocalEndpoint).Port}", "deepseek-v4-flash", "chat_completions", "high", 900);
        using var budgetGateway = new AiGatewayClient();
        var budgetEngine = new AiConversationEngine(budgetGateway);
        var budgetHistory = new List<AiChatMessage> { new("system", "s") };
        await budgetEngine.RunTurnAsync(budgetSettings, "test-api-key", provider, budgetHistory, "分析", null, Guid.Empty);
        budgetListener.Stop();
        var budgetTrace = budgetHistory.Single(message => message.Role == "assistant" && message.ToolTraces is { Count: > 0 }).ToolTraces!.Single();
        Require(budgetTrace.ResultBytes <= NetMindDefaults.AiToolFetchBudgetBytesPerTurn + 1024 && budgetTrace.Truncated &&
                budgetHistory.All(message => message.Role != "tool"),
            "单轮取数超过预算必须截断，且持久历史只记录截断状态而不保留工具原文");

        // 迭代上限：网关始终返回 tool_calls 时引擎必须收尾而不是无限取数。
        var capRequests = new List<string>();
        var capListener = await StartFakeAiSseGatewayAsync(capRequests, _ => toolCallSse, expectedRequests: NetMindDefaults.AiToolLoopMaximumIterations + 2);
        var capSettings = new AiGatewaySettings($"http://127.0.0.1:{((IPEndPoint)capListener.LocalEndpoint).Port}", "deepseek-v4-flash", "chat_completions", "high", 900);
        using var capGateway = new AiGatewayClient();
        var capEngine = new AiConversationEngine(capGateway);
        var capHistory = new List<AiChatMessage> { new("system", "s") };
        var capOutcome = await capEngine.RunTurnAsync(capSettings, "test-api-key", provider, capHistory, "分析", null, Guid.Empty);
        capListener.Stop();
        Require(capOutcome.IterationCapReached && capRequests.Count == NetMindDefaults.AiToolLoopMaximumIterations + 2,
            "取数迭代达到上限后必须提示模型用已有数据收尾，不得无限取数");
        Require(capHistory.All(message => message.Role != "tool" && message.ToolCalls is null) &&
                capHistory.Last().Role == "assistant",
            "达到迭代上限后必须以最终助手消息收尾，临时工具协议不得进入持久历史");

        // 会话体积保护：超过 14 MB 时折叠最早的 tool 结果（单字节字符使字节数与字符数一致）。
        var bigHistory = new List<AiChatMessage>
        {
            new("user", "提问"),
            new("tool", new string('a', 8 * 1024 * 1024), ToolCallId: "call-1", Name: "get_transactions"),
            new("tool", new string('b', 7 * 1024 * 1024), ToolCallId: "call-2", Name: "get_transactions")
        };
        AiConversationEngine.FoldHistoryIfNeeded(bigHistory);
        Require(bigHistory[1].Content == NetMindDefaults.AiToolResultFoldedPlaceholder,
            "超过会话体积上限时必须折叠最早的取数结果");
        Require(bigHistory[2].Content!.StartsWith("b", StringComparison.Ordinal),
            "折叠保护必须保留最近的取数结果");
        var legacyProtocolHistory = new List<AiChatMessage>
        {
            new("system", "系统"),
            new("user", "旧提问"),
            new("assistant", null, [new AiToolCall("old-call", "get_transactions", "{\"ordinals\":[1]}")]),
            new("tool", "owner-secret-old-result", ToolCallId: "old-call", Name: "get_transactions"),
            new("assistant", "旧结论")
        };
        var gatewayHistory = AiConversationEngine.CreateGatewayHistory(legacyProtocolHistory);
        Require(gatewayHistory.Count == 3 && gatewayHistory.All(message => message.Role != "tool" && message.ToolCalls is null) &&
                !string.Join('\n', gatewayHistory.Select(AiChatMessageJson.Serialize)).Contains("owner-secret-old-result", StringComparison.Ordinal),
            "加载旧会话后，发给模型的长期历史也必须剔除旧工具协议与原文");

        // 摘要构建与序号映射。
        var summary = AiConversationEngine.BuildEvidenceSummary(pool);
        Require(summary.StartsWith("#1 ", StringComparison.Ordinal) && summary.Contains("/api/data", StringComparison.Ordinal) &&
                summary.Contains("application/json", StringComparison.Ordinal),
            "证据池摘要必须按 #序号 时间 方法 主机 路径 状态 大小 类型 输出");
        Require(store.Delete(conversationId) && await store.LoadAsync(conversationId) is null,
            "会话必须可删除且删除后不可读");
    }
    finally { if (Directory.Exists(conversationRoot)) Directory.Delete(conversationRoot, recursive: true); }

    // ── 模板清单完整性 ─────────────────────────────────────────
    Require(AiPromptTemplate.All.Length == 5 && AiPromptTemplate.All.All(template => template.SystemPrompt.Length > 100 && template.AnalysisRequirement.Length > 0),
        "必须内置五套分析模板且系统提示与分析要求非空");
    Require(AiPromptTemplate.Get(null).Id == AiPromptTemplate.DefaultTemplateId && AiPromptTemplate.Get("不存在").Id == AiPromptTemplate.DefaultTemplateId,
        "模板选择缺失或无效时必须回退默认的自动识别模板");

    // ── 设置持久化与安全边界（既有定向回归）─────────────────────────
    var settingsRoot = Path.Combine(Path.GetTempPath(), "netmind-ai-settings-test-" + Guid.NewGuid().ToString("N"));
    try
    {
        var settingsPath = Path.Combine(settingsRoot, "ai-settings.json");
        var store = new AiGatewaySettingsStore(settingsPath);
        await store.SaveAsync(settings);
        var restored = await store.LoadAsync();
        Require(restored.Model == settings.Model && restored.ApiStyle == "chat_completions", "AI 网关设置必须可持久化还原");
        Require(!(await File.ReadAllTextAsync(settingsPath)).Contains("test-api-key", StringComparison.Ordinal),
            "AI 设置文件不得保存 API 密钥");
    }
    finally { if (Directory.Exists(settingsRoot)) Directory.Delete(settingsRoot, recursive: true); }

    var insecureRejected = false;
    try { new AiGatewaySettings("http://example.com", "deepseek-v4-flash", "chat_completions", "high").Validate(); }
    catch (InvalidOperationException) { insecureRejected = true; }
    Require(insecureRejected, "远程模型网关不得使用明文 HTTP");
}

/// <summary>假 SSE 网关：按序接受请求并回写脚本化响应，请求全文（头+体）供断言。</summary>
static async Task<TcpListener> StartFakeAiSseGatewayAsync(List<string> capturedRequests, Func<int, string> responseForRequest, int expectedRequests)
{
    var listener = new TcpListener(IPAddress.Loopback, 0);
    listener.Start();
    _ = Task.Run(async () =>
    {
        for (var index = 0; index < expectedRequests; index++)
        {
            using var client = await listener.AcceptTcpClientAsync();
            await using var stream = client.GetStream();
            var headerBytes = await ReadUntilHeadersBytesAsync(stream, CancellationToken.None);
            var headerText = Encoding.Latin1.GetString(headerBytes);
            var contentLengthLine = headerText.Split("\r\n", StringSplitOptions.RemoveEmptyEntries)
                .First(line => line.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase));
            var contentLength = int.Parse(contentLengthLine.Split(':', 2)[1].Trim());
            var body = new byte[contentLength];
            await ReadExactAsync(stream, body, CancellationToken.None);
            capturedRequests.Add(headerText + Encoding.UTF8.GetString(body));
            var sseBody = Encoding.UTF8.GetBytes(responseForRequest(index));
            var responseHeader = Encoding.ASCII.GetBytes($"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {sseBody.Length}\r\nConnection: close\r\n\r\n");
            await stream.WriteAsync(responseHeader);
            await stream.WriteAsync(sseBody);
        }
    });
    return listener;
}

static async Task VerifyAiPromptCatalogAsync()
{
    var root = Path.Combine(Path.GetTempPath(), "netmind-ai-prompts-test-" + Guid.NewGuid().ToString("N"));
    try
    {
        var missing = await new AiPromptCatalogStore(root).LoadAsync();
        Require(missing.Templates.Count == AiPromptTemplate.All.Length &&
                missing.QuickFollowUps.SequenceEqual(AiPromptCatalog.DefaultQuickFollowUps),
            "提示词目录文件缺失时必须回退内置默认");

        var store = new AiPromptCatalogStore(root);
        var customId = AiPromptCatalogStore.NewCustomTemplateId();
        var custom = new AiPromptTemplate(customId, "自定义模板", "自定义系统提示", "自定义分析要求");
        var edited = AiPromptTemplate.Get("api-reverse") with { DisplayName = "API 逆向（已改）" };
        var templates = AiPromptTemplate.All.Select(template => template.Id == "api-reverse" ? edited : template).Append(custom).ToArray();
        await store.SaveAsync(new AiPromptCatalog(templates, ["追问一", "追问二"]));

        var reloaded = await new AiPromptCatalogStore(root).LoadAsync();
        Require(reloaded.Templates.Any(template => template.Id == customId && template.DisplayName == "自定义模板"),
            "保存后必须能读回新增的自定义模板");
        Require(reloaded.Templates.Count(template => template.Id == "api-reverse") == 1 &&
                reloaded.Templates.Single(template => template.Id == "api-reverse").DisplayName == "API 逆向（已改）",
            "同 Id 内置模板必须以文件覆写为准且不重复");
        Require(reloaded.QuickFollowUps.SequenceEqual(new[] { "追问一", "追问二" }),
            "快捷追问必须按保存顺序读回");

        await File.WriteAllTextAsync(Path.Combine(root, AiPromptCatalogStore.CatalogFileName), "{损坏的 JSON");
        var corrupted = await new AiPromptCatalogStore(root).LoadAsync();
        Require(corrupted.Templates.Count == AiPromptTemplate.All.Length,
            "目录文件损坏时必须回退内置默认而不是抛异常");
    }
    finally
    {
        try { if (Directory.Exists(root)) Directory.Delete(root, recursive: true); } catch { /* 清理失败不阻断测试 */ }
    }
}

static async Task VerifyAiFullContextAsync()
{
    var traffic = new TrafficRecord(
        Guid.NewGuid(), DateTimeOffset.UtcNow, "GET", "/account?token=owner-secret", 200, 18, 0,
        "browser.exe · 99", "HTTP/1.1", "请求摘要", "响应摘要",
        "http://example.test/account?token=owner-secret", "token = owner-secret",
        "Authorization: Bearer owner-secret\nCookie: session=owner-cookie", "session = owner-cookie", "HTTP/1.1 200");
    var bodies = new Dictionary<string, byte[]>
    {
        ["req-hash"] = Encoding.UTF8.GetBytes("请求正文含凭据 owner-secret 与脚本 <script>fetch('/api')</script>"),
        ["resp-hash"] = [0x00, 0x01, 0x02]
    };
    Task<StoredBlobContent> Read(string hash, CancellationToken token) =>
        Task.FromResult(new StoredBlobContent(bodies[hash], bodies[hash].Length, false));

    var json = await AiFullContextBuilder.BuildJsonAsync(
        [new StoredTrafficRecord(traffic, Guid.NewGuid(), "req-hash", "resp-hash", "定向测试")], Read);
    Require(json.Contains("owner-secret", StringComparison.Ordinal) &&
            json.Contains("session=owner-cookie", StringComparison.Ordinal) &&
            json.Contains("请求正文含凭据 owner-secret 与脚本", StringComparison.Ordinal),
        "完整上下文必须原样保留 URL、请求头、Cookie 与文本正文");
    Require(json.Contains("[二进制正文", StringComparison.Ordinal), "二进制正文必须降级为有界十六进制预览");
    Require(!json.Contains("[REDACTED]", StringComparison.Ordinal), "完整上下文不得包含脱敏占位符");

    // AI 正文只保留 html/文本/js 等分析相关内容：图片/CSS 按 Content-Type 省略且不读 Blob。
    var resourceReaderCalls = new List<string>();
    var imageTraffic = traffic with { Url = "http://example.test/assets/logo.png", ResponseHeaders = "Content-Type: image/png" };
    var cssTraffic = traffic with { Url = "http://example.test/assets/site.css", ResponseHeaders = "Content-Type: text/css; charset=utf-8" };
    var jsTraffic = traffic with { Url = "http://example.test/assets/app.js", ResponseHeaders = "Content-Type: application/javascript" };
    var resourceJson = await AiFullContextBuilder.BuildJsonAsync(
        [new StoredTrafficRecord(imageTraffic, Guid.NewGuid(), string.Empty, "res-img", "定向测试"),
         new StoredTrafficRecord(cssTraffic, Guid.NewGuid(), string.Empty, "res-css", "定向测试"),
         new StoredTrafficRecord(jsTraffic, Guid.NewGuid(), string.Empty, "res-js", "定向测试")],
        (hash, token) =>
        {
            resourceReaderCalls.Add(hash);
            if (hash != "res-js") throw new InvalidOperationException("非分析相关正文不得触发 Blob 读取");
            var body = Encoding.UTF8.GetBytes("var marker = 'js-body-marker';");
            return Task.FromResult(new StoredBlobContent(body, body.Length, false));
        });
    Require(!resourceReaderCalls.Contains("res-img", StringComparer.Ordinal) &&
            !resourceReaderCalls.Contains("res-css", StringComparer.Ordinal),
        "图片与 CSS 正文不得触发 Blob 读取");
    Require(resourceJson.Contains("[正文已省略", StringComparison.Ordinal) &&
            resourceJson.Contains("js-body-marker", StringComparison.Ordinal),
        "AI 上下文必须省略图片/CSS 等无关正文并保留 html/文本/js");

    var missingJson = await AiFullContextBuilder.BuildJsonAsync(
        [new StoredTrafficRecord(traffic, Guid.NewGuid(), "missing-hash", string.Empty, "定向测试")],
        (hash, token) => throw new FileNotFoundException("内容寻址存储中不存在该正文。", hash));
    Require(missingJson.Contains("[正文缺失", StringComparison.Ordinal), "缺失正文必须显式标记而不是静默忽略");

    var overLimitRejected = false;
    try
    {
        var many = Enumerable.Range(0, NetMindDefaults.AiMaximumEvidenceTransactions + 1)
            .Select(_ => new StoredTrafficRecord(traffic, Guid.NewGuid(), string.Empty, string.Empty, "定向测试")).ToArray();
        await AiFullContextBuilder.BuildJsonAsync(many, Read);
    }
    catch (InvalidOperationException) { overLimitRejected = true; }
    Require(overLimitRejected, "超过事务上限的完整上下文必须被拒绝而不是静默裁剪");
}

static async Task VerifySilentCapture()
{
    // ── IPv4 + TCP 报文解析 ─────────────────────────────────────────
    var payload = Encoding.ASCII.GetBytes("GET /api?x=1 HTTP/1.1\r\nHost: t\r\n\r\n");
    var packet = BuildIpv4TcpPacket(0x7F000001u, 0xC0A80164u, 55001, 80, 1000, payload, flags: 0x18);
    Require(SilentPacketParser.TryParseTcpPacket(packet, ipv6: false, out var parsed), "合法 IPv4 TCP 报文必须可解析");
    Require(parsed.SourceAddress.ToString() == "127.0.0.1" && parsed.DestinationAddress.ToString() == "192.168.1.100" &&
            parsed.SourcePort == 55001 && parsed.DestinationPort == 80 && parsed.Sequence == 1000 &&
            parsed.Payload.AsSpan().SequenceEqual(payload), "TCP 五元组、序号与负载必须原样还原");
    var udpPacket = BuildIpv4TcpPacket(0x7F000001u, 0xC0A80164u, 55001, 53, 1000, payload, flags: 0x18, protocol: 17);
    Require(!SilentPacketParser.TryParseTcpPacket(udpPacket, ipv6: false, out _), "非 TCP 报文必须被拒绝");

    // ── TCP 字节流重组：乱序、重叠、重传 ─────────────────────────────
    var reassembler = new SilentTcpReassembler();
    reassembler.Initialize(1000);
    Require(Encoding.ASCII.GetString(reassembler.Append(1001, "Hello"u8)) == "Hello", "顺序段必须立即输出");
    Require(reassembler.Append(1011, "World"u8).Length == 0, "未来段必须先缓冲而不是输出");
    Require(Encoding.ASCII.GetString(reassembler.Append(1006, ", abc "u8)) == ", abc orld",
        "空洞补齐后必须链式输出后续缓冲，且重叠段只输出未覆盖部分");
    Require(reassembler.Append(1001, "Hello"u8).Length == 0, "完全覆盖的重传段必须丢弃");
    var overflow = new SilentTcpReassembler(64 * 1024);
    overflow.Initialize(0);
    overflow.Append(1000, new byte[65 * 1024]); // 未来段超过缓冲上限
    Require(overflow.Broken, "乱序缓冲超限必须标记流断裂");
    var midStream = new SilentTcpReassembler();
    Require(Encoding.ASCII.GetString(midStream.Append(5000, "FirstByte"u8)) == "FirstByte",
        "中途捕获（未见 SYN）时首段必须完整输出，不得像 SYN 那样额外消耗序号位");

    // ── HTTP/1.x 请求解析：Content-Length 与 keep-alive ───────────────
    var requests = new SilentHttpMessageParser(isRequest: true);
    requests.Feed(Encoding.ASCII.GetBytes("POST /api?x=1 HTTP/1.1\r\nHost: t\r\nContent-Length: 5\r\n\r\nhelloGET /next HTTP/1.1\r\nHost: t\r\n\r\n"));
    Require(requests.Completed.Count == 2, "keep-alive 请求必须连续切分");
    var firstRequest = requests.Completed.Dequeue();
    Require(firstRequest.StartLine == "POST /api?x=1 HTTP/1.1" && Encoding.ASCII.GetString(firstRequest.Body) == "hello" &&
            !firstRequest.BodyTruncated, "请求正文必须按 Content-Length 完整切分");
    var junk = new SilentHttpMessageParser(isRequest: true);
    junk.Feed("BINARY\x00\x01\r\n\r\n"u8);
    Require(junk.NotHttp, "非 HTTP 起始行必须被识别为非 HTTP 流");

    // ── HTTP/1.x 响应解析：Content-Length、chunked 与关闭截止 ───────────
    var responses = new SilentHttpMessageParser(isRequest: false);
    responses.Feed(Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"));
    responses.Feed(Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nabcde\r\n0\r\n\r\n"));
    responses.Feed(Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\ntail-body"));
    Require(responses.Completed.Count == 2, "未关闭的连接截止正文必须等待结算");
    Require(Encoding.ASCII.GetString(responses.Completed.Dequeue().Body) == "ok", "Content-Length 响应正文必须完整");
    Require(Encoding.ASCII.GetString(responses.Completed.Dequeue().Body) == "abcde", "chunked 响应正文必须解码");
    responses.Close();
    var closeBody = responses.Completed.Dequeue();
    Require(Encoding.ASCII.GetString(closeBody.Body) == "tail-body" && !closeBody.BodyTruncated,
        "连接关闭截止的正文必须在结算时完整输出");

    // ── TLS ClientHello 识别与 SNI 提取 ──────────────────────────────
    var clientHello = BuildTlsClientHello("api.test", new byte[32]);
    Require(SilentPacketParser.LooksLikeTlsClientHello(clientHello), "TLS ClientHello 必须被识别");
    Require(SilentPacketParser.TryParseTlsServerName(clientHello) == "api.test", "SNI 主机名必须从 ClientHello 提取");
    Require(SilentPacketParser.TryParseTlsServerName(payload) is null, "非 TLS 负载不得误判出 SNI");

    // ── 引擎级：TLS 隧道识别即落库，不依赖长驻连接结算，且流结束不重复 ─────
    var engineRecords = new List<SilentCapturedTransaction>();
    var engine = new SilentCaptureEngine("tcp", transaction =>
    {
        engineRecords.Add(transaction);
        return Task.CompletedTask;
    });
    var clientAddress = new IPAddress([127, 0, 0, 1]);
    var serverAddress = new IPAddress([203, 0, 113, 9]);
    await engine.InjectPacketAsync(new SilentTcpPacket(clientAddress, 55001, serverAddress, 443,
        5000, Syn: true, Ack: false, Fin: false, Rst: false, []), outbound: true);
    await engine.InjectPacketAsync(new SilentTcpPacket(clientAddress, 55001, serverAddress, 443,
        5001, Syn: false, Ack: true, Fin: false, Rst: false, clientHello), outbound: true);
    Require(engineRecords.Count == 1, "TLS 隧道必须在识别到 ClientHello 时立即落库，而不是等待连接关闭");
    Require(engineRecords[0].Traffic.Endpoint == "api.test" && engineRecords[0].Traffic.Method == "CONNECT",
        "隧道记录必须携带 SNI 主机");
    await engine.InjectPacketAsync(new SilentTcpPacket(clientAddress, 55001, serverAddress, 443,
        5001 + (uint)clientHello.Length, Syn: false, Ack: true, Fin: true, Rst: false, []), outbound: true);
    await engine.InjectPacketAsync(new SilentTcpPacket(serverAddress, 443, clientAddress, 55001,
        8000, Syn: false, Ack: true, Fin: true, Rst: false, []), outbound: false);
    Require(engineRecords.Count == 1, "流结束结算不得重复落库隧道记录");

    // ── M1：SSLKEYLOGFILE 命中后 TLS 1.3 记录层解密（会话级往返）────────────
    var tlsClientRandom = new byte[32];
    for (var i = 0; i < tlsClientRandom.Length; i++) tlsClientRandom[i] = (byte)(i + 1);
    var clientTrafficSecret = new byte[32];
    var serverTrafficSecret = new byte[32];
    for (var i = 0; i < 32; i++) { clientTrafficSecret[i] = (byte)(0xA0 + i % 16); serverTrafficSecret[i] = (byte)(0x50 + i % 16); }
    var tlsClientRandomHex = Convert.ToHexString(tlsClientRandom).ToLowerInvariant();
    var keyLogPath = Path.Combine(Path.GetTempPath(), "netmind-smoke-keylog-" + Guid.NewGuid().ToString("N") + ".txt");
    File.WriteAllText(keyLogPath,
        $"CLIENT_TRAFFIC_SECRET_0 {tlsClientRandomHex} {Convert.ToHexString(clientTrafficSecret).ToLowerInvariant()}\n" +
        $"SERVER_TRAFFIC_SECRET_0 {tlsClientRandomHex} {Convert.ToHexString(serverTrafficSecret).ToLowerInvariant()}\n");
    try
    {
        var tlsKeyLog = new SilentTlsKeyLog(keyLogPath);
        var tlsSession = new SilentTlsSession(tlsKeyLog);
        tlsSession.FeedClient(BuildTlsClientHello("api.test", tlsClientRandom));
        Require(tlsSession.HasKeys, "密钥日志必须按 ClientHello 随机数命中");
        // ServerHello 与加密应用记录同一块到达（验证单遍续走），解密后应直接得到响应明文
        var responsePlain = Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        var serverPlain = tlsSession.FeedServer(ConcatBytes(BuildTls13ServerHello(), BuildTls13AppRecord(responsePlain, serverTrafficSecret)));
        Require(Encoding.ASCII.GetString(serverPlain).StartsWith("HTTP/1.1 200 OK"), "TLS 1.3 服务端应用记录必须解密出响应明文");
        var requestPlain = Encoding.ASCII.GetBytes("GET /hello HTTP/1.1\r\nHost: api.test\r\n\r\n");
        var clientPlain = tlsSession.FeedClient(BuildTls13AppRecord(requestPlain, clientTrafficSecret));
        Require(Encoding.ASCII.GetString(clientPlain).StartsWith("GET /hello"), "TLS 1.3 客户端应用记录必须解密出请求明文");
        Require(!tlsSession.Broken, "合法握手不得误判为解密失败");

        // 引擎级：命中密钥的 TLS 流除隧道记录外，还必须落库解密后的 HTTP 事务
        var decryptRecords = new List<SilentCapturedTransaction>();
        var decryptEngine = new SilentCaptureEngine("tcp", transaction =>
        {
            decryptRecords.Add(transaction);
            return Task.CompletedTask;
        }, new SilentTlsKeyLog(keyLogPath));
        await decryptEngine.InjectPacketAsync(new SilentTcpPacket(clientAddress, 55002, serverAddress, 443,
            9000, Syn: true, Ack: false, Fin: false, Rst: false, []), outbound: true);
        var decryptClientHello = BuildTlsClientHello("api.test", tlsClientRandom);
        await decryptEngine.InjectPacketAsync(new SilentTcpPacket(clientAddress, 55002, serverAddress, 443,
            9001, Syn: false, Ack: true, Fin: false, Rst: false, decryptClientHello), outbound: true);
        // 真实时序：ServerHello 先到（触发密钥建立），客户端再发加密请求，最后服务端响应
        var decryptServerHello = BuildTls13ServerHello();
        await decryptEngine.InjectPacketAsync(new SilentTcpPacket(serverAddress, 443, clientAddress, 55002,
            7000, Syn: false, Ack: true, Fin: false, Rst: false, decryptServerHello), outbound: false);
        var encryptedRequest = BuildTls13AppRecord(requestPlain, clientTrafficSecret);
        await decryptEngine.InjectPacketAsync(new SilentTcpPacket(clientAddress, 55002, serverAddress, 443,
            9001 + (uint)decryptClientHello.Length, Syn: false, Ack: true, Fin: false, Rst: false, encryptedRequest), outbound: true);
        var encryptedResponse = BuildTls13AppRecord(responsePlain, serverTrafficSecret);
        await decryptEngine.InjectPacketAsync(new SilentTcpPacket(serverAddress, 443, clientAddress, 55002,
            7000 + (uint)decryptServerHello.Length, Syn: false, Ack: true, Fin: false, Rst: false, encryptedResponse), outbound: false);
        Require(decryptRecords.Count == 2, "命中密钥的 TLS 流必须同时落库隧道记录与解密事务");
        var decryptedTransaction = decryptRecords.Single(record => record.Traffic.Method == "GET");
        Require(decryptedTransaction.Traffic.Endpoint == "/hello" && decryptedTransaction.Traffic.StatusCode == 200,
            "解密事务必须携带请求路径与状态码");
        Require(decryptedTransaction.Traffic.Protocol.Contains("已解密") && decryptedTransaction.Traffic.Url.StartsWith("https://api.test"),
            "解密事务必须标记 HTTPS 协议并按 SNI 重建 URL");
        Require(Encoding.ASCII.GetString(decryptedTransaction.ResponseBody) == "ok", "解密事务正文必须完整");

        // 无密钥的 TLS 流保持隧道模式：同一引擎换随机数（密钥日志不命中）不得产出解密事务
        var noKeyRandom = new byte[32];
        noKeyRandom[0] = 0xFF;
        var tunnelOnlyRecords = new List<SilentCapturedTransaction>();
        var tunnelEngine = new SilentCaptureEngine("tcp", transaction =>
        {
            tunnelOnlyRecords.Add(transaction);
            return Task.CompletedTask;
        }, new SilentTlsKeyLog(keyLogPath));
        await tunnelEngine.InjectPacketAsync(new SilentTcpPacket(clientAddress, 55003, serverAddress, 443,
            9500, Syn: true, Ack: false, Fin: false, Rst: false, []), outbound: true);
        await tunnelEngine.InjectPacketAsync(new SilentTcpPacket(clientAddress, 55003, serverAddress, 443,
            9501, Syn: false, Ack: true, Fin: false, Rst: false, BuildTlsClientHello("locked.test", noKeyRandom)), outbound: true);
        await tunnelEngine.InjectPacketAsync(new SilentTcpPacket(clientAddress, 55003, serverAddress, 443,
            9901, Syn: false, Ack: true, Fin: true, Rst: false, []), outbound: true);
        await tunnelEngine.InjectPacketAsync(new SilentTcpPacket(serverAddress, 443, clientAddress, 55003,
            7500, Syn: false, Ack: true, Fin: true, Rst: false, []), outbound: false);
        Require(tunnelOnlyRecords.Count == 1 && tunnelOnlyRecords[0].Traffic.Method == "CONNECT",
            "未命中密钥的 TLS 流必须保持隧道模式，不得产出解密事务");

        // ── M2：HPACK 解码（静态表、Huffman、动态表、多字节整数、错误容限）────────
        var hpack = new SilentHpackDecoder();
        var indexedHeaders = hpack.Decode([0x82, 0x86, 0x84]);
        Require(indexedHeaders is { Count: 3 } && indexedHeaders[0] == (":method", "GET")
            && indexedHeaders[1] == (":scheme", "http") && indexedHeaders[2] == (":path", "/"),
            "HPACK 静态表索引首部必须可解码");
        var authorityBlock = ConcatBytes([0x41, 0x8c], [0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff]);
        var authorityHeaders = hpack.Decode(authorityBlock);
        Require(authorityHeaders is { Count: 1 } && authorityHeaders[0] == (":authority", "www.example.com"),
            "HPACK Huffman 编码字符串必须可解码（RFC 7541 C.4.1 固件）");
        var cacheBlock = ConcatBytes([0x58, 0x86], [0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf]);
        var cacheHeaders = hpack.Decode(cacheBlock);
        Require(cacheHeaders is { Count: 1 } && cacheHeaders[0] == ("cache-control", "no-cache"),
            "HPACK 索引名 + Huffman 值混合编码必须可解码（RFC 7541 C.4.2 固件）");
        var literalBlock = ConcatBytes(
            ConcatBytes([0x40, 10], Encoding.ASCII.GetBytes("custom-key")),
            ConcatBytes([12], Encoding.ASCII.GetBytes("custom-value")));
        hpack.Decode(literalBlock);
        var dynamicReference = hpack.Decode([0xBE]); // 索引 62 = 动态表最新条目
        Require(dynamicReference is { Count: 1 } && dynamicReference[0] == ("custom-key", "custom-value"),
            "HPACK 动态表增量索引与回引必须正确");
        var longValue = new string('b', 130);
        var longBlock = ConcatBytes([0x00, 1, (byte)'x', 0x7f, 0x03], Encoding.ASCII.GetBytes(longValue));
        var longHeaders = hpack.Decode(longBlock);
        Require(longHeaders is { Count: 1 } && longHeaders[0].Value == longValue,
            "HPACK 字符串长度超出 7 位前缀时必须按续字节解码");
        var brokenHpack = new SilentHpackDecoder();
        Require(brokenHpack.Decode([0xBE]) is null && brokenHpack.Broken,
            "非法 HPACK 索引必须标记损坏而不是抛出异常");

        // ── M2：引擎级 HTTP/2 解密重组（TLS 1.3 + ALPN h2，多流复用）──────────
        var h2Records = new List<SilentCapturedTransaction>();
        var h2Engine = new SilentCaptureEngine("tcp", transaction =>
        {
            h2Records.Add(transaction);
            return Task.CompletedTask;
        }, new SilentTlsKeyLog(keyLogPath));
        await h2Engine.InjectPacketAsync(new SilentTcpPacket(clientAddress, 55004, serverAddress, 443,
            9000, Syn: true, Ack: false, Fin: false, Rst: false, []), outbound: true);
        var h2ClientHello = BuildTlsClientHello("api.test", tlsClientRandom, "h2");
        await h2Engine.InjectPacketAsync(new SilentTcpPacket(clientAddress, 55004, serverAddress, 443,
            9001, Syn: false, Ack: true, Fin: false, Rst: false, h2ClientHello), outbound: true);
        var h2ServerHello = BuildTls13ServerHello();
        await h2Engine.InjectPacketAsync(new SilentTcpPacket(serverAddress, 443, clientAddress, 55004,
            7000, Syn: false, Ack: true, Fin: false, Rst: false, h2ServerHello), outbound: false);

        // 客户端：连接前言 + SETTINGS + 流 1 头块（HEADERS 不带 END_HEADERS，CONTINUATION 续接，验证续帧）
        var clientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"u8.ToArray();
        var requestBlockFirst = new byte[] { 0x82, 0x87 }; // :method GET、:scheme https（静态表索引）
        var huffmanAuthority = new byte[] { 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff };
        var requestBlockRest = ConcatBytes(
            ConcatBytes([0x04], EncodeH2String("/h2")),                              // :path /h2（引用索引 4 的字面值）
            ConcatBytes([0x41, 0x8c], huffmanAuthority));                            // :authority www.example.com（Huffman）
        var clientFirstFrames = ConcatBytes(
            ConcatBytes(clientPreface, BuildH2Frame(4, 0, 0, [])),                    // SETTINGS
            ConcatBytes(BuildH2Frame(1, 0, 1, requestBlockFirst),                     // HEADERS（未结束头块）
                BuildH2Frame(9, 0x5, 1, requestBlockRest)));                          // CONTINUATION END_HEADERS|END_STREAM
        var encryptedClientFirst = BuildTls13AppRecord(clientFirstFrames, clientTrafficSecret);
        await h2Engine.InjectPacketAsync(new SilentTcpPacket(clientAddress, 55004, serverAddress, 443,
            9001 + (uint)h2ClientHello.Length, Syn: false, Ack: true, Fin: false, Rst: false, encryptedClientFirst), outbound: true);

        // 服务端：SETTINGS + 流 1 响应（:status 200 + content-type）+ DATA END_STREAM
        var responseHeaders = ConcatBytes([0x88], BuildH2LiteralHeader("content-type", "text/plain"));
        var serverFirstFrames = ConcatBytes(
            ConcatBytes(BuildH2Frame(4, 0, 0, []), BuildH2Frame(1, 0x4, 1, responseHeaders)),
            BuildH2Frame(0, 0x1, 1, "hello-h2"u8.ToArray()));
        await h2Engine.InjectPacketAsync(new SilentTcpPacket(serverAddress, 443, clientAddress, 55004,
            7000 + (uint)h2ServerHello.Length, Syn: false, Ack: true, Fin: false, Rst: false,
            BuildTls13AppRecord(serverFirstFrames, serverTrafficSecret)), outbound: false);

        // 流 3 复用：带正文的 POST，响应 201（验证按流配对而非按到达顺序）
        var postHeaders = ConcatBytes(
            ConcatBytes([0x83], ConcatBytes([0x04], EncodeH2String("/submit"))),     // :method POST、:path /submit
            ConcatBytes([0x01], EncodeH2String("api.test")));                        // :authority api.test
        var clientSecondFrames = ConcatBytes(BuildH2Frame(1, 0x5, 3, postHeaders), BuildH2Frame(0, 0x1, 3, "ping"u8.ToArray()));
        await h2Engine.InjectPacketAsync(new SilentTcpPacket(clientAddress, 55004, serverAddress, 443,
            9001 + (uint)h2ClientHello.Length + (uint)encryptedClientFirst.Length, Syn: false, Ack: true, Fin: false, Rst: false,
            BuildTls13AppRecord(clientSecondFrames, clientTrafficSecret, sequence: 1)), outbound: true);
        var statusHeaders = ConcatBytes([0x08], EncodeH2String("201"));              // :status 字面值（201 不在静态表）
        var serverSecondFrames = ConcatBytes(BuildH2Frame(1, 0x4, 3, statusHeaders), BuildH2Frame(0, 0x1, 3, "pong"u8.ToArray()));
        await h2Engine.InjectPacketAsync(new SilentTcpPacket(serverAddress, 443, clientAddress, 55004,
            7000 + (uint)h2ServerHello.Length + (uint)BuildTls13AppRecord(serverFirstFrames, serverTrafficSecret).Length,
            Syn: false, Ack: true, Fin: false, Rst: false,
            BuildTls13AppRecord(serverSecondFrames, serverTrafficSecret, sequence: 1)), outbound: false);

        Require(h2Records.Count == 3, "HTTP/2 连接必须落库隧道与两条复用流事务");
        var getTransaction = h2Records.Single(record => record.Traffic.Method == "GET");
        Require(getTransaction.Traffic.Endpoint == "/h2" && getTransaction.Traffic.StatusCode == 200,
            "HTTP/2 事务必须携带伪首部映射出的路径与状态码");
        Require(getTransaction.Traffic.Protocol == NetMindDefaults.ProtocolSilentHttp2
            && getTransaction.Traffic.Url == "https://www.example.com/h2",
            "HTTP/2 事务必须标记协议并按 :authority 重建 URL");
        Require(Encoding.ASCII.GetString(getTransaction.ResponseBody) == "hello-h2", "HTTP/2 响应正文必须按 DATA 帧重组");
        var postTransaction = h2Records.Single(record => record.Traffic.Method == "POST");
        Require(postTransaction.Traffic.Endpoint == "/submit" && postTransaction.Traffic.StatusCode == 201,
            "复用流事务必须按流 ID 配对");
        Require(Encoding.ASCII.GetString(postTransaction.RequestBody) == "ping"
            && Encoding.ASCII.GetString(postTransaction.ResponseBody) == "pong",
            "HTTP/2 请求/响应正文必须完整重组");

        // ── M3：QUIC Initial 解密（无需密钥）提取 SNI/ALPN ─────────────
        // QUIC CRYPTO 流只含握手消息：去掉 TLS 记录头 5 字节
        var chQuic = BuildTlsClientHello("quic.test", new byte[32], "h3")[5..];
        var quicDcid = new byte[] { 0x83, 0x94, 0xa5, 0xc6, 0xd7, 0xe8, 0xf9, 0x0a };
        var quicScid = new byte[] { 0x11, 0x22, 0x33, 0x44 };
        var quicInitialSecret = HKDF.Extract(HashAlgorithmName.SHA256, ikm: quicDcid,
            salt: Convert.FromHexString("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"));
        var quicClientInitial = BuildQuicInitialPacket(quicDcid, quicScid,
            ConcatBytes([0x06, 0x00], ConcatBytes([0x40, (byte)chQuic.Length], chQuic)),
            HKDF.Expand(HashAlgorithmName.SHA256, quicInitialSecret, 32, "client in"u8.ToArray()));
        var quicSession = new SilentQuicConnection(null);
        quicSession.Feed(clientDirection: true, quicClientInitial);
        Require(quicSession.Sni == "quic.test" && quicSession.Alpn == "h3" && !quicSession.Broken,
            "QUIC Initial 必须无需密钥即可解密出 ClientHello 的 SNI 与 ALPN");

        // ── M4：QPACK 静态字段段 + 编码器流驱动的动态表 ──────────────
        var qpack = new SilentQpackDecoder();
        // 静态引用：:method GET(17)→D1 / :scheme https(23)→D7 / :status 200(25)→D9 + :authority 名字引用字面（0101 0000→静态 0）
        var qpackStaticSection = new byte[] { 0x00, 0x00, 0xD1, 0xD7, 0xD9, 0x50, 0x07, 0x68, 0x33, 0x2E, 0x74, 0x65, 0x73, 0x74 };
        var qpackStaticHeaders = qpack.DecodeFieldSection(qpackStaticSection);
        Require(qpackStaticHeaders is not null && qpackStaticHeaders.Count == 4
            && qpackStaticHeaders[0] == (":method", "GET")
            && qpackStaticHeaders[1] == (":scheme", "https")
            && qpackStaticHeaders[2] == (":status", "200")
            && qpackStaticHeaders[3] == (":authority", "h3.test"),
            "QPACK 静态表引用与名字引用字面字段行必须正确解码");
        // 编码器流：容量 220（0x3FBD）+ 静态 0（:authority）引用插入值 "www.example.com"
        qpack.FeedEncoderStream(Convert.FromHexString("3fbd01c00f"));
        qpack.FeedEncoderStream(Encoding.ASCII.GetBytes("www.example.com"));
        // RIC 编码：TotalInserts=1，MaxEntries=220/32=6 → (1 mod 12)+1=2；动态索引 0 = Base-0-1
        var qpackDynamicHeaders = qpack.DecodeFieldSection(new byte[] { 0x02, 0x00, 0x80 });
        Require(qpackDynamicHeaders is not null && qpackDynamicHeaders.Count == 1
            && qpackDynamicHeaders[0] == (":authority", "www.example.com"),
            "QPACK 编码器流插入的动态条目必须可被字段段引用");

        // ── M3：引擎级 QUIC 隧道 + 1-RTT 流解密（命中密钥日志）──────────
        var quicClientRandom = new byte[32];
        for (var i = 0; i < 32; i++) quicClientRandom[i] = (byte)(0x30 + i % 16);
        var quicClientRandomHex = Convert.ToHexString(quicClientRandom).ToLowerInvariant();
        File.AppendAllText(keyLogPath,
            $"CLIENT_TRAFFIC_SECRET_0 {quicClientRandomHex} {Convert.ToHexString(clientTrafficSecret).ToLowerInvariant()}\n" +
            $"SERVER_TRAFFIC_SECRET_0 {quicClientRandomHex} {Convert.ToHexString(serverTrafficSecret).ToLowerInvariant()}\n");
        var chQuicKeyed = BuildTlsClientHello("quic.test", quicClientRandom, "h3")[5..];
        var quicClientInitialKeyed = BuildQuicInitialPacket(quicDcid, quicScid,
            ConcatBytes([0x06, 0x00], ConcatBytes([0x40, (byte)chQuicKeyed.Length], chQuicKeyed)),
            HKDF.Expand(HashAlgorithmName.SHA256, quicInitialSecret, 32, "client in"u8.ToArray()));
        var quicRecords = new List<SilentCapturedTransaction>();
        var quicEngine = new SilentCaptureEngine("tcp", transaction =>
        {
            quicRecords.Add(transaction);
            return Task.CompletedTask;
        }, new SilentTlsKeyLog(keyLogPath));
        var quicClientEndpoint = new IPEndPoint(new IPAddress([127, 0, 0, 1]), 51888);
        var quicServerEndpoint = new IPEndPoint(new IPAddress([203, 0, 113, 9]), 443);
        await quicEngine.InjectUdpPacketAsync(new SilentUdpPacket(
            quicClientEndpoint.Address, (ushort)quicClientEndpoint.Port, quicServerEndpoint.Address, (ushort)quicServerEndpoint.Port,
            quicClientInitialKeyed), outbound: true);
        Require(quicRecords.Count == 1 && quicRecords[0].Traffic.Method == "CONNECT"
            && quicRecords[0].Traffic.Endpoint == "quic.test",
            "QUIC 隧道必须在 Initial 解密出 ClientHello 时立即落库");

        // 服务端 Initial（ACK 帧）：真实握手必有，让解码器从 SCID 学到客户端 CID 长度
        var quicServerCid = new byte[] { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x02 };
        var quicServerInitialFrames = new byte[64];
        quicServerInitialFrames[0] = 0x02;                            // ACK：最大包号/延迟/区间数/首块长均为 0
        var quicServerInitial = BuildQuicInitialPacket(quicScid, quicServerCid, quicServerInitialFrames,
            HKDF.Expand(HashAlgorithmName.SHA256, quicInitialSecret, 32, "server in"u8.ToArray()));
        await quicEngine.InjectUdpPacketAsync(new SilentUdpPacket(
            quicServerEndpoint.Address, (ushort)quicServerEndpoint.Port, quicClientEndpoint.Address, (ushort)quicClientEndpoint.Port,
            quicServerInitial), outbound: false);

        // ── M4：引擎级 HTTP/3 事务重组（客户端动态 QPACK + 服务端静态 QPACK）──
        // 客户端编码器流（单向流 2，类型 0x02）：类型 varint 后直接是指令，无长度前缀
        var h3EncoderStream = ConcatBytes([0x02],
            ConcatBytes(Convert.FromHexString("3fbd01c007"), Encoding.ASCII.GetBytes("h3.test")));
        var h3EncoderPacket = BuildQuicShortPacket(quicDcid, 0,
            ConcatBytes([0x0A, 0x02, (byte)h3EncoderStream.Length], h3EncoderStream),
            clientTrafficSecret, clientTrafficSecret);
        await quicEngine.InjectUdpPacketAsync(new SilentUdpPacket(
            quicClientEndpoint.Address, (ushort)quicClientEndpoint.Port, quicServerEndpoint.Address, (ushort)quicServerEndpoint.Port,
            h3EncoderPacket), outbound: true);

        // 请求流（双向流 0）：HEADERS 帧负载 = 前缀(RIC=2,Base=2) + 动态索引引用
        var h3RequestSection = new byte[] { 0x02, 0x00, 0x80 };
        var h3RequestStream = ConcatBytes([0x01, (byte)h3RequestSection.Length], h3RequestSection);
        var h3RequestPacket = BuildQuicShortPacket(quicDcid, 1,
            ConcatBytes([0x0B, 0x00, (byte)h3RequestStream.Length], h3RequestStream),
            clientTrafficSecret, clientTrafficSecret);
        await quicEngine.InjectUdpPacketAsync(new SilentUdpPacket(
            quicClientEndpoint.Address, (ushort)quicClientEndpoint.Port, quicServerEndpoint.Address, (ushort)quicServerEndpoint.Port,
            h3RequestPacket), outbound: true);

        // 响应流：HEADERS 帧（静态 :status 200）+ DATA 帧，FIN 结束
        var h3ResponseSection = new byte[] { 0x00, 0x00, 0xD9 };
        var h3ResponseStream = ConcatBytes([0x01, 0x03], ConcatBytes(h3ResponseSection, [0x00, 0x05]));
        h3ResponseStream = ConcatBytes(h3ResponseStream, Encoding.ASCII.GetBytes("h3-ok"));
        var h3ResponsePacket = BuildQuicShortPacket(quicScid, 0,
            ConcatBytes([0x0B, 0x00, (byte)h3ResponseStream.Length], h3ResponseStream),
            serverTrafficSecret, serverTrafficSecret);
        await quicEngine.InjectUdpPacketAsync(new SilentUdpPacket(
            quicServerEndpoint.Address, (ushort)quicServerEndpoint.Port, quicClientEndpoint.Address, (ushort)quicClientEndpoint.Port,
            h3ResponsePacket), outbound: false);

        Require(quicRecords.Count == 2, "QUIC 1-RTT 解密后必须重组出 HTTP/3 事务落库");
        var h3Transaction = quicRecords.Single(record => record.Traffic.Method == "GET");
        Require(h3Transaction.Traffic.Protocol == NetMindDefaults.ProtocolSilentHttp3
            && h3Transaction.Traffic.StatusCode == 200,
            "HTTP/3 事务必须携带解密协议标记与响应状态码");
        Require(h3Transaction.Traffic.Url == "https://h3.test/",
            "HTTP/3 事务 URL 必须用 QPACK 解出的 :authority 重建");
        Require(Encoding.ASCII.GetString(h3Transaction.ResponseBody) == "h3-ok",
            "HTTP/3 响应正文必须完整重组");
    }
    finally { try { File.Delete(keyLogPath); } catch { /* 临时密钥日志清理失败不影响结果 */ } }

    static byte[] BuildIpv4TcpPacket(uint source, uint destination, ushort sourcePort, ushort destinationPort,
        uint sequence, byte[] payload, byte flags, byte protocol = 6)
    {
        var totalLength = 20 + 20 + payload.Length;
        var packet = new byte[totalLength];
        packet[0] = 0x45;
        packet[2] = (byte)(totalLength >> 8);
        packet[3] = (byte)totalLength;
        packet[8] = 64;
        packet[9] = protocol;
        WriteUInt32BigEndian(packet.AsSpan(12), source);
        WriteUInt32BigEndian(packet.AsSpan(16), destination);
        packet[20] = (byte)(sourcePort >> 8);
        packet[21] = (byte)sourcePort;
        packet[22] = (byte)(destinationPort >> 8);
        packet[23] = (byte)destinationPort;
        WriteUInt32BigEndian(packet.AsSpan(24), sequence);
        packet[32] = 0x50; // 数据偏移 5
        packet[33] = flags;
        payload.CopyTo(packet.AsSpan(40));
        return packet;
    }

    static byte[] BuildTlsClientHello(string host, byte[] random, string? alpn = null)
    {
        var name = Encoding.ASCII.GetBytes(host);
        using var hello = new MemoryStream();
        hello.WriteByte(0x03); hello.WriteByte(0x03);               // 版本
        hello.Write(random);                                          // 随机数（32 字节）
        hello.WriteByte(0);                                          // 会话 ID 长度
        hello.WriteByte(0); hello.WriteByte(2); hello.WriteByte(0); hello.WriteByte(0x2F); // 密码套件
        hello.WriteByte(1); hello.WriteByte(0);                      // 压缩方法
        var extensions = new MemoryStream();
        var list = new MemoryStream();
        list.WriteByte(0);
        list.WriteByte((byte)(name.Length >> 8)); list.WriteByte((byte)name.Length);
        list.Write(name);
        var listBytes = list.ToArray();
        extensions.WriteByte(0); extensions.WriteByte(0);            // server_name
        extensions.WriteByte((byte)((listBytes.Length + 2) >> 8));
        extensions.WriteByte((byte)(listBytes.Length + 2));
        extensions.WriteByte((byte)(listBytes.Length >> 8));
        extensions.WriteByte((byte)listBytes.Length);
        extensions.Write(listBytes);
        if (alpn is not null)
        {
            var alpnName = Encoding.ASCII.GetBytes(alpn);
            var alpnList = new MemoryStream();
            alpnList.WriteByte(0);                                    // 协议列表总长（uint16 高字节）
            alpnList.WriteByte((byte)(1 + alpnName.Length));          // 协议列表总长（低字节）
            alpnList.WriteByte((byte)alpnName.Length);
            alpnList.Write(alpnName);
            var alpnBytes = alpnList.ToArray();
            extensions.WriteByte(0); extensions.WriteByte(16);        // application_layer_protocol_negotiation
            extensions.WriteByte((byte)(alpnBytes.Length >> 8));
            extensions.WriteByte((byte)alpnBytes.Length);
            extensions.Write(alpnBytes);
        }
        var extensionBytes = extensions.ToArray();
        hello.WriteByte((byte)(extensionBytes.Length >> 8));
        hello.WriteByte((byte)extensionBytes.Length);
        hello.Write(extensionBytes);
        var helloBytes = hello.ToArray();
        using var output = new MemoryStream();
        output.WriteByte(0x16); output.WriteByte(0x03); output.WriteByte(0x01);
        var recordLength = helloBytes.Length + 4;
        output.WriteByte((byte)(recordLength >> 8)); output.WriteByte((byte)recordLength);
        output.WriteByte(0x01);
        output.WriteByte((byte)(helloBytes.Length >> 16));
        output.WriteByte((byte)(helloBytes.Length >> 8));
        output.WriteByte((byte)helloBytes.Length);
        output.Write(helloBytes);
        return output.ToArray();
    }

    static byte[] BuildTls13ServerHello()
    {
        using var hello = new MemoryStream();
        hello.WriteByte(0x03); hello.WriteByte(0x03);               // 兼容版本
        hello.Write(new byte[32]);                                   // 服务端随机数
        hello.WriteByte(0);                                          // 会话 ID 长度
        hello.WriteByte(0x13); hello.WriteByte(0x01);               // TLS_AES_128_GCM_SHA256
        hello.WriteByte(0);                                          // 压缩方法
        hello.WriteByte(0); hello.WriteByte(6);                      // 扩展总长
        hello.WriteByte(0); hello.WriteByte(43);                     // supported_version
        hello.WriteByte(0); hello.WriteByte(2);
        hello.WriteByte(0x03); hello.WriteByte(0x04);               // TLS 1.3
        var helloBytes = hello.ToArray();
        using var output = new MemoryStream();
        output.WriteByte(0x16); output.WriteByte(0x03); output.WriteByte(0x03);
        var recordLength = helloBytes.Length + 4;
        output.WriteByte((byte)(recordLength >> 8)); output.WriteByte((byte)recordLength);
        output.WriteByte(0x02);
        output.WriteByte((byte)(helloBytes.Length >> 16));
        output.WriteByte((byte)(helloBytes.Length >> 8));
        output.WriteByte((byte)helloBytes.Length);
        output.Write(helloBytes);
        return output.ToArray();
    }

    static byte[] BuildTls13AppRecord(byte[] plaintext, byte[] trafficSecret, ulong sequence = 0)
    {
        // nonce = IV XOR 零填充序号；与 SilentTlsSession 的密钥派生/nonce 构造互为镜像
        var key = SilentTlsSession.HkdfExpandLabel(trafficSecret, "tls13 key", 16, HashAlgorithmName.SHA256);
        var iv = SilentTlsSession.HkdfExpandLabel(trafficSecret, "tls13 iv", 12, HashAlgorithmName.SHA256);
        var sequenceBytes = new byte[12];
        BinaryPrimitives.WriteUInt64BigEndian(sequenceBytes.AsSpan(4), sequence);
        var nonce = (byte[])iv.Clone();
        for (var i = 0; i < 12; i++) nonce[i] ^= sequenceBytes[i];
        var inner = new byte[plaintext.Length + 1];
        plaintext.CopyTo(inner, 0);
        inner[^1] = 23;                                              // 内层内容类型：应用数据
        var cipher = new byte[inner.Length];
        var tag = new byte[16];
        var header = new byte[] { 23, 0x03, 0x03, (byte)((inner.Length + 16) >> 8), (byte)(inner.Length + 16) };
        using var gcm = new AesGcm(key, 16);
        gcm.Encrypt(nonce, inner, cipher, tag, header);
        var record = new byte[5 + cipher.Length + tag.Length];
        header.CopyTo(record, 0);
        cipher.CopyTo(record, 5);
        tag.CopyTo(record, 5 + cipher.Length);
        return record;
    }

    static byte[] ConcatBytes(byte[] first, byte[] second)
    {
        var joined = new byte[first.Length + second.Length];
        first.CopyTo(joined, 0);
        second.CopyTo(joined, first.Length);
        return joined;
    }

    static byte[] BuildH2Frame(int type, int flags, int streamId, byte[] payload)
    {
        var frame = new byte[9 + payload.Length];
        frame[0] = (byte)(payload.Length >> 16);
        frame[1] = (byte)(payload.Length >> 8);
        frame[2] = (byte)payload.Length;
        frame[3] = (byte)type;
        frame[4] = (byte)flags;
        frame[5] = (byte)(streamId >> 24);
        frame[6] = (byte)(streamId >> 16);
        frame[7] = (byte)(streamId >> 8);
        frame[8] = (byte)streamId;
        payload.CopyTo(frame, 9);
        return frame;
    }

    /// <summary>HPACK 字面首部（不索引、新名字），测试用最小编码器。</summary>
    static byte[] BuildH2LiteralHeader(string name, string value) =>
        ConcatBytes(ConcatBytes([0x00], EncodeH2String(name)), EncodeH2String(value));

    /// <summary>HPACK 原文字符串（长度前缀 + ASCII，无 Huffman），测试用最小编码器。</summary>
    static byte[] EncodeH2String(string text)
    {
        var bytes = Encoding.ASCII.GetBytes(text);
        var output = new byte[1 + bytes.Length];
        output[0] = (byte)bytes.Length;
        bytes.CopyTo(output, 1);
        return output;
    }

    /// <summary>构造一个带头部保护的 QUIC Initial 长包头包（RFC 9001 §5.2 初始密钥，pn=0）。</summary>
    static byte[] BuildQuicInitialPacket(byte[] dcid, byte[] scid, byte[] frames, byte[] initialSecret)
    {
        var key = SilentTlsSession.HkdfExpandLabel(initialSecret, "quic key", 16, HashAlgorithmName.SHA256);
        var iv = SilentTlsSession.HkdfExpandLabel(initialSecret, "quic iv", 12, HashAlgorithmName.SHA256);
        var hp = SilentTlsSession.HkdfExpandLabel(initialSecret, "quic hp", 16, HashAlgorithmName.SHA256);
        using var header = new MemoryStream();
        header.WriteByte(0xC0);                                          // 长包头 Initial，pn 长度 1
        header.WriteByte(0); header.WriteByte(0); header.WriteByte(0); header.WriteByte(1); // 版本 1
        header.WriteByte((byte)dcid.Length); header.Write(dcid);
        header.WriteByte((byte)scid.Length); header.Write(scid);
        header.WriteByte(0);                                             // 令牌长度 0
        var payloadLength = frames.Length + 1 + 16;                        // 负载长度（pn + 密文 + tag）
        if (payloadLength < 64) header.WriteByte((byte)payloadLength);   // varint：<64 单字节
        else { header.WriteByte((byte)(0x40 | (payloadLength >> 8))); header.WriteByte((byte)payloadLength); }
        var pnOffset = (int)header.Length;
        header.WriteByte(0);                                             // 包号 0
        var headerBytes = header.ToArray();
        var cipher = new byte[frames.Length];
        var tag = new byte[16];
        using (var gcm = new AesGcm(key, 16)) gcm.Encrypt(iv, frames, cipher, tag, headerBytes);
        var packet = ConcatBytes(headerBytes, ConcatBytes(cipher, tag));
        return ApplyQuicHeaderProtection(packet, pnOffset, hp, longHeader: true);
    }

    /// <summary>构造一个带头部保护的 QUIC 1-RTT 短包头包（应用密钥，pn 单字节）。</summary>
    static byte[] BuildQuicShortPacket(byte[] dcid, int packetNumber, byte[] frames, byte[] trafficSecret, byte[] hpSecret)
    {
        var key = SilentTlsSession.HkdfExpandLabel(trafficSecret, "quic key", 16, HashAlgorithmName.SHA256);
        var iv = SilentTlsSession.HkdfExpandLabel(trafficSecret, "quic iv", 12, HashAlgorithmName.SHA256);
        var hp = SilentTlsSession.HkdfExpandLabel(hpSecret, "quic hp", 16, HashAlgorithmName.SHA256);
        var pnOffset = 1 + dcid.Length;
        var header = new byte[pnOffset + 1];
        header[0] = 0x40;                                                // 短包头：固定位，pn 长度 1
        dcid.CopyTo(header, 1);
        // 包头必须携带真实包号（随后被头部保护掩码）：占位 0 会让解码器还原出错误包号，
        // nonce 失配导致 AEAD 校验失败、整包被静默丢弃
        header[pnOffset] = (byte)(packetNumber & 0xff);
        var nonce = (byte[])iv.Clone();
        var pnBytes = new byte[12];
        BinaryPrimitives.WriteUInt64BigEndian(pnBytes.AsSpan(4), (ulong)packetNumber);
        for (var i = 0; i < 12; i++) nonce[i] ^= pnBytes[i];
        var cipher = new byte[frames.Length];
        var tag = new byte[16];
        using (var gcm = new AesGcm(key, 16)) gcm.Encrypt(nonce, frames, cipher, tag, header);
        var packet = ConcatBytes(header, ConcatBytes(cipher, tag));
        return ApplyQuicHeaderProtection(packet, pnOffset, hp, longHeader: false);
    }

    /// <summary>QUIC 头部保护（RFC 9001 §5.4）：AES-ECB(hp) 采样掩码异或首字节与包号字节。</summary>
    static byte[] ApplyQuicHeaderProtection(byte[] packet, int pnOffset, byte[] hp, bool longHeader)
    {
        var sample = new byte[16];
        Array.Copy(packet, pnOffset + 4, sample, 0, 16);
        var mask = new byte[16];
        using (var ecb = Aes.Create())
        {
            ecb.Mode = CipherMode.ECB;
            ecb.Padding = PaddingMode.None;
            using var encryptor = ecb.CreateEncryptor(hp, null);
            encryptor.TransformBlock(sample, 0, 16, mask, 0);
        }
        packet[0] ^= (byte)(mask[0] & (longHeader ? 0x0f : 0x1f));
        packet[pnOffset] ^= mask[1];
        return packet;
    }

    static void WriteUInt32BigEndian(Span<byte> target, uint value)
    {
        target[0] = (byte)(value >> 24);
        target[1] = (byte)(value >> 16);
        target[2] = (byte)(value >> 8);
        target[3] = (byte)value;
    }
}

static void VerifyProtocolParsers()
{
    byte[] http2 = [0, 0, 3, 0, 1, 0, 0, 0, 1, 1, 2, 3];
    var http2Frames = ProtocolParsers.ParseHttp2Frames(http2);
    Require(http2Frames.Count == 1 && http2Frames[0].StreamId == 1 && http2Frames[0].Payload.SequenceEqual(new byte[] { 1, 2, 3 }), "HTTP/2 帧解析失败");

    byte[] websocket = [0x81, 0x82, 1, 2, 3, 4, (byte)('H' ^ 1), (byte)('i' ^ 2)];
    var webSocketFrames = ProtocolParsers.ParseWebSocketFrames(websocket);
    Require(webSocketFrames.Count == 1 && webSocketFrames[0].Masked && Encoding.UTF8.GetString(webSocketFrames[0].Payload) == "Hi", "WebSocket 掩码解析失败");

    var events = ProtocolParsers.ParseServerSentEvents(Encoding.UTF8.GetBytes("id: 42\nevent: update\ndata: first\ndata: second\nretry: 1000\n\n"));
    Require(events.Count == 1 && events[0].Event == "update" && events[0].Data == "first\nsecond" && events[0].RetryMilliseconds == 1000, "SSE 事件解析失败");

    byte[] grpc = [0, 0, 0, 0, 2, 8, 1];
    var envelopes = ProtocolParsers.ParseGrpcEnvelopes(grpc);
    Require(envelopes.Count == 1 && !envelopes[0].Compressed && envelopes[0].Message.SequenceEqual(new byte[] { 8, 1 }), "gRPC envelope 解析失败");

    byte[] dns = [0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 3, (byte)'a', (byte)'p', (byte)'i', 7, (byte)'n', (byte)'e', (byte)'t', (byte)'m', (byte)'i', (byte)'n', (byte)'d', 5, (byte)'l', (byte)'o', (byte)'c', (byte)'a', (byte)'l', 0, 0, 1, 0, 1];
    var dnsMessage = ProtocolParsers.ParseDnsMessage(dns);
    Require(dnsMessage.Id == 0x1234 && dnsMessage.Questions.Single().Name == "api.netmind.local" && dnsMessage.Questions[0].Type == 1, "DNS 问题解析失败");

    byte[] protobuf = [0x08, 0x96, 0x01, 0x12, 0x02, (byte)'o', (byte)'k', 0x1d, 0x78, 0x56, 0x34, 0x12];
    var fields = ProtocolParsers.ParseProtobufFields(protobuf);
    Require(fields.Count == 3 && fields[0].Number == 1 && fields[0].NumericValue == 150 && Encoding.ASCII.GetString(fields[1].Data) == "ok" && fields[2].NumericValue == 0x12345678, "Protobuf wire 字段解析失败");

    var rejected = false;
    try { ProtocolParsers.ParseWebSocketFrames(new byte[] { 0x09, 0x7e, 0, 126 }); }
    catch (InvalidDataException) { rejected = true; }
    Require(rejected, "无效 WebSocket 控制帧必须被拒绝");

    var reassembled = ProtocolParsers.ReassembleWebSocketMessages(new[]
    {
        new WebSocketFrame(false, 1, false, Encoding.UTF8.GetBytes("Hel")),
        new WebSocketFrame(true, 9, false, Array.Empty<byte>()),
        new WebSocketFrame(false, 0, false, Encoding.UTF8.GetBytes("lo")),
        new WebSocketFrame(true, 0, false, Encoding.UTF8.GetBytes("!")),
    });
    Require(reassembled.Count == 2 && reassembled[0].IsControl && reassembled[0].Payload.Length == 0,
        "穿插的控制帧必须单独保留且不打断数据帧重组");
    Require(reassembled[1].IsText && !reassembled[1].IsControl &&
            Encoding.UTF8.GetString(reassembled[1].Payload) == "Hello!",
        "分片 WebSocket 帧必须按 FIN 位重组为完整消息");

    var incompleteRejected = false;
    try { ProtocolParsers.ReassembleWebSocketMessages(new[] { new WebSocketFrame(false, 1, false, new byte[] { 1 }) }); }
    catch (InvalidDataException) { incompleteRejected = true; }
    Require(incompleteRejected, "未完成的 WebSocket 分片消息不得被解释为有效证据");

    var orphanRejected = false;
    try { ProtocolParsers.ReassembleWebSocketMessages(new[] { new WebSocketFrame(true, 0, false, new byte[] { 1 }) }); }
    catch (InvalidDataException) { orphanRejected = true; }
    Require(orphanRejected, "缺少起始数据帧的延续帧必须被拒绝");

    using var gzipBuffer = new MemoryStream();
    using (var gzipWriter = new GZipStream(gzipBuffer, CompressionMode.Compress, leaveOpen: true))
        gzipWriter.Write(Encoding.UTF8.GetBytes("grpc-ok"));
    var decompressed = ProtocolParsers.DecompressGrpcMessage(new GrpcEnvelope(true, gzipBuffer.ToArray()));
    Require(Encoding.UTF8.GetString(decompressed) == "grpc-ok", "压缩 gRPC 消息必须可经 gzip 解压展示");
    Require(ProtocolParsers.DecompressGrpcMessage(new GrpcEnvelope(false, new byte[] { 8, 1 })).SequenceEqual(new byte[] { 8, 1 }),
        "未压缩 gRPC 消息必须原样返回");

    // ── HTTP 正文按 Content-Encoding 解压（乱码修复）──────────────────
    using var httpGzipBuffer = new MemoryStream();
    using (var gzipWriter = new GZipStream(httpGzipBuffer, CompressionMode.Compress, leaveOpen: true))
        gzipWriter.Write(Encoding.UTF8.GetBytes("<html>ok</html>"));
    Require(Encoding.UTF8.GetString(ProtocolParsers.DecompressHttpBody("gzip", httpGzipBuffer.ToArray())) == "<html>ok</html>",
        "gzip 响应正文必须解压后落库");

    using var httpBrotliBuffer = new MemoryStream();
    using (var brotliWriter = new BrotliStream(httpBrotliBuffer, CompressionMode.Compress, leaveOpen: true))
        brotliWriter.Write(Encoding.UTF8.GetBytes("br-ok"));
    Require(Encoding.UTF8.GetString(ProtocolParsers.DecompressHttpBody("br", httpBrotliBuffer.ToArray())) == "br-ok",
        "brotli 响应正文必须解压后落库");

    using var httpDeflateBuffer = new MemoryStream();
    using (var deflateWriter = new DeflateStream(httpDeflateBuffer, CompressionMode.Compress, leaveOpen: true))
        deflateWriter.Write(Encoding.UTF8.GetBytes("deflate-ok"));
    Require(Encoding.UTF8.GetString(ProtocolParsers.DecompressHttpBody("deflate", httpDeflateBuffer.ToArray())) == "deflate-ok",
        "deflate 响应正文必须解压后落库");

    var plainBody = Encoding.UTF8.GetBytes("plain");
    Require(ProtocolParsers.DecompressHttpBody(null, plainBody).SequenceEqual(plainBody), "无 Content-Encoding 时正文必须原样返回");
    var notGzip = Encoding.UTF8.GetBytes("Hello, 未压缩的正文");
    Require(ProtocolParsers.DecompressHttpBody("gzip", notGzip).SequenceEqual(notGzip), "缺少 gzip 魔数的正文必须原样返回而非被误解");
    byte[] corruptStream = [0x1F, 0x8B, 0x08, 0x00, 0, 0, 0, 0, 0, 0, 0xFF, 0xC0, 0xFF];
    Require(ProtocolParsers.DecompressHttpBody("gzip", corruptStream).SequenceEqual(corruptStream), "损坏的压缩正文必须回退为原始字节而非抛异常");
    Require(ProtocolParsers.DecompressHttpBody("zstd", plainBody).SequenceEqual(plainBody), "未知压缩编码必须原样返回");
}

static void VerifyTrafficAnalysis()
{
    Require(EndpointNormalizer.Normalize("/api/users/123?b=2&a=1") == "/api/users/{id}?a={value}&b={value}", "数字端点规范化失败");
    Require(EndpointNormalizer.Normalize("https://api.local/orders/550e8400-e29b-41d4-a716-446655440000") == "/orders/{id}", "GUID 端点规范化失败");

    var now = DateTimeOffset.UtcNow;
    var first = new TrafficRecord(Guid.NewGuid(), now, "GET", "/api/users/123", 200, 40, 20, "client.exe · 1", "HTTP/2", "请求一", "响应一");
    var second = new TrafficRecord(Guid.NewGuid(), now.AddSeconds(1), "GET", "/api/users/456", 500, 240, 30, "client.exe · 1", "HTTP/2", "请求二", "响应二");
    var snapshot = TrafficAnalysisEngine.Analyze(new[] { first, second });
    var cluster = snapshot.Clusters.Single();
    Require(cluster.RequestCount == 2 && cluster.ErrorCount == 1 && cluster.ErrorRate == 50 && cluster.P95LatencyMilliseconds == 240, "端点聚类指标失败");

    var propagation = FieldPropagationAnalyzer.Analyze(new[]
    {
        new ObservedField(first.Id, "请求头", "Authorization", "Bearer real-secret", 12),
        new ObservedField(second.Id, "请求头", "Authorization", "Bearer real-secret", 18)
    }).Single();
    Require(propagation.Placeholder.StartsWith("[敏感信息 #", StringComparison.Ordinal) && !propagation.Placeholder.Contains("real-secret", StringComparison.Ordinal), "字段传播必须使用稳定脱敏占位符");
    Require(FieldPropagationAnalyzer.Placeholder("Bearer real-secret") == propagation.Placeholder, "敏感占位符必须稳定");

    var evidencePool = new[]
    {
        new TrafficRecord(Guid.NewGuid(), now, "POST", "/api/login", 200, 120, 420, "browser.exe · 1", "HTTP/2", "请求", "响应",
            "https://api.test/api/login", string.Empty, "Content-Type: application/json", string.Empty, "Content-Type: application/json"),
        new TrafficRecord(Guid.NewGuid(), now.AddSeconds(1), "GET", "/api/users/123", 200, 80, 800, "browser.exe · 1", "HTTP/2", "请求", "响应",
            "https://api.test/api/users/123?id=123", "id = 123", "Authorization: Bearer shared-token", "sid=shared-cookie", "Content-Type: application/json"),
        new TrafficRecord(Guid.NewGuid(), now.AddSeconds(2), "GET", "/api/users/456", 500, 1500, 900, "browser.exe · 1", "HTTP/2", "请求", "响应",
            "https://api.test/api/users/456?id=456", "id = 456", "Authorization: Bearer shared-token", "sid=shared-cookie", "Content-Type: application/json")
    };
    var prepared = AiEvidencePreparationEngine.Prepare(evidencePool);
    var usersGroup = prepared.EndpointGroups.Single(group => group.NormalizedEndpoint == "/api/users/{id}");
    Require(usersGroup.RequestCount == 2 && usersGroup.ErrorCount == 1 && usersGroup.RepresentativeOrdinals.Contains(2) && usersGroup.RepresentativeOrdinals.Contains(3),
        "AI 证据预整理必须聚合同端点并选择成功/失败代表样本");
    Require(prepared.Anomalies.Any(item => item.Ordinal == 3 && item.Kind == "HTTP错误") &&
            prepared.Anomalies.Any(item => item.Ordinal == 3 && item.Kind == "慢请求"),
        "AI 证据预整理必须标出错误与端点内慢请求候选");
    Require(prepared.Relations.Any(item => item.FromOrdinal == 2 && item.ToOrdinal == 3 && item.Score >= 35 &&
                                   item.Reasons.All(reason => !reason.StartsWith("共享字段", StringComparison.Ordinal))),
        "AI 证据预整理只应按同端点与时序生成关联候选");
    Require(!prepared.Relations.Any(item => item.FromOrdinal == 1 && item.ToOrdinal == 2),
        "同主机且稳定请求头相同不得单独构成关联候选");
    var comparison = AiEvidencePreparationEngine.Compare(evidencePool, [2, 3]);
    Require(comparison.StatusDistribution.Count == 2 && comparison.Fields.Any(field => field.Name == "Authorization" && field.Classification == "固定值"),
        "AI 样本比较必须输出状态分布和稳定字段分类");
    Require(AiEvidencePreparationEngine.BuildCompactManifest(evidencePool).Contains("代表[#2,#3]", StringComparison.Ordinal),
        "首轮证据地图必须携带代表事务序号");
}

static async Task VerifyProxyAsync(string workspacePath)
{
    var upstream = new TcpListener(IPAddress.Loopback, 0);
    upstream.Start();
    var upstreamEndpoint = (IPEndPoint)upstream.LocalEndpoint;
    var upstreamTask = Task.Run(async () =>
    {
        using var client = await upstream.AcceptTcpClientAsync();
        using var stream = client.GetStream();
        await ReadUntilHeadersAsync(stream);
        var body = Encoding.UTF8.GetBytes("代理链路正常");
        var header = Encoding.ASCII.GetBytes($"HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {body.Length}\r\nConnection: close\r\n\r\n");
        await stream.WriteAsync(header);
        await stream.WriteAsync(body);
    });

    using var archive = new TrafficArchive(workspacePath);
    await using var proxy = new ExplicitHttpProxy(new ProxyOptions(IPAddress.Loopback, 0), archive);
    using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
    var proxyTask = proxy.RunAsync(cancellation.Token);
    while (proxy.LocalEndpoint is null) await Task.Delay(10, cancellation.Token);
    var initialTrafficCount = archive.GetTrafficCount();

    using (var client = new TcpClient())
    {
        await client.ConnectAsync(proxy.LocalEndpoint.Address, proxy.LocalEndpoint.Port, cancellation.Token);
        using var stream = client.GetStream();
        var request = Encoding.ASCII.GetBytes($"GET http://127.0.0.1:{upstreamEndpoint.Port}/health HTTP/1.1\r\nHost: 127.0.0.1:{upstreamEndpoint.Port}\r\nConnection: close\r\n\r\n");
        await stream.WriteAsync(request, cancellation.Token);
        using var response = new MemoryStream();
        await stream.CopyToAsync(response, cancellation.Token);
        var responseText = Encoding.UTF8.GetString(response.ToArray());
        Require(responseText.Contains("200 OK", StringComparison.Ordinal), "显式代理必须转发上游状态");
        Require(responseText.Contains("代理链路正常", StringComparison.Ordinal), "显式代理必须转发上游正文");
    }

    await upstreamTask;
    var deadline = DateTimeOffset.UtcNow.AddSeconds(2);
    while (archive.GetTrafficCount() < initialTrafficCount + 1 && DateTimeOffset.UtcNow < deadline) await Task.Delay(20);
    var httpRecord = archive.GetRecentTraffic(1)[0].Traffic;
    Require(httpRecord.Endpoint == "/health", "代理捕获必须持久化规范化端点");
    Require(httpRecord.Process.Contains("NetMind.SmokeTests", StringComparison.OrdinalIgnoreCase), "代理捕获必须关联真实客户端进程和 PID");

    // ── 乱码修复 E2E：上游返回 gzip 正文时，回写客户端保持原样，落库正文必须已解压 ─────
    var gzipUpstream = new TcpListener(IPAddress.Loopback, 0);
    gzipUpstream.Start();
    var gzipEndpoint = (IPEndPoint)gzipUpstream.LocalEndpoint;
    var gzipPayload = Encoding.UTF8.GetBytes("<html>压缩页面</html>");
    using var gzipBuffer = new MemoryStream();
    using (var gzipWriter = new GZipStream(gzipBuffer, CompressionMode.Compress, leaveOpen: true))
        gzipWriter.Write(gzipPayload);
    var gzipBody = gzipBuffer.ToArray();
    var gzipUpstreamTask = Task.Run(async () =>
    {
        using var gzipClient = await gzipUpstream.AcceptTcpClientAsync(cancellation.Token);
        using var gzipStream = gzipClient.GetStream();
        await ReadUntilHeadersAsync(gzipStream);
        var header = Encoding.ASCII.GetBytes($"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Encoding: gzip\r\nContent-Length: {gzipBody.Length}\r\nConnection: close\r\n\r\n");
        await gzipStream.WriteAsync(header, cancellation.Token);
        await gzipStream.WriteAsync(gzipBody, 0, gzipBody.Length, cancellation.Token);
    }, cancellation.Token);

    var countBeforeGzip = archive.GetTrafficCount();
    using (var gzipClient = new TcpClient())
    {
        await gzipClient.ConnectAsync(proxy.LocalEndpoint.Address, proxy.LocalEndpoint.Port, cancellation.Token);
        using var stream = gzipClient.GetStream();
        var request = Encoding.ASCII.GetBytes($"GET http://127.0.0.1:{gzipEndpoint.Port}/compressed HTTP/1.1\r\nHost: 127.0.0.1:{gzipEndpoint.Port}\r\nConnection: close\r\n\r\n");
        await stream.WriteAsync(request, cancellation.Token);
        using var response = new MemoryStream();
        await stream.CopyToAsync(response, cancellation.Token);
        var raw = response.ToArray();
        var bodyStart = Encoding.Latin1.GetString(raw).IndexOf("\r\n\r\n", StringComparison.Ordinal) + 4;
        Require(bodyStart > 3 && raw.Skip(bodyStart).SequenceEqual(gzipBody), "代理回写客户端的压缩字节必须保持原样");
    }

    await gzipUpstreamTask;
    gzipUpstream.Stop();
    var gzipDeadline = DateTimeOffset.UtcNow.AddSeconds(2);
    while (archive.GetTrafficCount() < countBeforeGzip + 1 && DateTimeOffset.UtcNow < gzipDeadline) await Task.Delay(20, cancellation.Token);
    var gzipRecord = archive.GetRecentTraffic(1)[0];
    Require(gzipRecord.Traffic.Endpoint == "/compressed", "gzip 事务必须落库");
    var storedGzipBody = await archive.ReadBlobAsync(gzipRecord.ResponseBlobHash);
    Require(Encoding.UTF8.GetString(storedGzipBody.Content) == "<html>压缩页面</html>", "落库正文必须按 Content-Encoding 解压而不是保存压缩字节");

    var unavailableUpstream = new TcpListener(IPAddress.Loopback, 0);
    unavailableUpstream.Start();
    var unavailablePort = ((IPEndPoint)unavailableUpstream.LocalEndpoint).Port;
    unavailableUpstream.Stop();
    var countBeforeFailure = archive.GetTrafficCount();
    using (var failedClient = new TcpClient())
    {
        await failedClient.ConnectAsync(proxy.LocalEndpoint.Address, proxy.LocalEndpoint.Port, cancellation.Token);
        using var stream = failedClient.GetStream();
        var request = Encoding.ASCII.GetBytes(
            $"GET http://127.0.0.1:{unavailablePort}/unreachable?token=owner-secret HTTP/1.1\r\n" +
            $"Host: 127.0.0.1:{unavailablePort}\r\nCookie: session_id=owner-cookie\r\nConnection: close\r\n\r\n");
        await stream.WriteAsync(request, cancellation.Token);
        using var response = new MemoryStream();
        await stream.CopyToAsync(response, cancellation.Token);
        Require(Encoding.UTF8.GetString(response.ToArray()).Contains("502", StringComparison.Ordinal),
            "上游连接失败时代理必须向客户端返回 502");
    }
    var failureDeadline = DateTimeOffset.UtcNow.AddSeconds(2);
    while (archive.GetTrafficCount() < countBeforeFailure + 1 && DateTimeOffset.UtcNow < failureDeadline)
        await Task.Delay(20, cancellation.Token);
    var failureRecord = archive.GetRecentTraffic(1)[0].Traffic;
    Require(failureRecord.StatusCode == 502 && failureRecord.Endpoint.StartsWith("/unreachable", StringComparison.Ordinal),
        "上游连接失败必须持久化为可检查的 502 事务");
    Require(failureRecord.Url.Contains("owner-secret", StringComparison.Ordinal) &&
            failureRecord.Cookies.Contains("owner-cookie", StringComparison.Ordinal),
        "本地失败事务必须保留原始请求元数据");
    var redactedFailure = AiPrivacyFilter.BuildJson([failureRecord], 1);
    Require(!redactedFailure.Contains("owner-secret", StringComparison.Ordinal) &&
            !redactedFailure.Contains("owner-cookie", StringComparison.Ordinal),
        "脱敏过滤器必须遮蔽失败事务的敏感字段");

    var tunnelUpstream = new TcpListener(IPAddress.Loopback, 0);
    tunnelUpstream.Start();
    var tunnelEndpoint = (IPEndPoint)tunnelUpstream.LocalEndpoint;
    var tunnelUpstreamTask = Task.Run(async () =>
    {
        using var client = await tunnelUpstream.AcceptTcpClientAsync(cancellation.Token);
        using var stream = client.GetStream();
        var request = new byte[4];
        await ReadExactAsync(stream, request, cancellation.Token);
        Require(Encoding.ASCII.GetString(request) == "PING", "HTTPS 隧道必须把客户端字节转发到上游");
        await stream.WriteAsync(Encoding.ASCII.GetBytes("PONG"), cancellation.Token);
    }, cancellation.Token);

    using (var connectClient = new TcpClient())
    {
        await connectClient.ConnectAsync(proxy.LocalEndpoint.Address, proxy.LocalEndpoint.Port, cancellation.Token);
        using var stream = connectClient.GetStream();
        var authority = $"127.0.0.1:{tunnelEndpoint.Port}";
        await stream.WriteAsync(Encoding.ASCII.GetBytes($"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n"), cancellation.Token);
        var connectResponse = Encoding.ASCII.GetString(await ReadUntilHeadersBytesAsync(stream, cancellation.Token));
        Require(connectResponse.Contains("200 Connection Established", StringComparison.Ordinal), "HTTPS CONNECT 必须建立加密透传隧道");
        await stream.WriteAsync(Encoding.ASCII.GetBytes("PING"), cancellation.Token);
        var tunnelResponse = new byte[4];
        await ReadExactAsync(stream, tunnelResponse, cancellation.Token);
        Require(Encoding.ASCII.GetString(tunnelResponse) == "PONG", "HTTPS 隧道必须把上游字节返回客户端");
    }

    await tunnelUpstreamTask;
    tunnelUpstream.Stop();
    var tunnelDeadline = DateTimeOffset.UtcNow.AddSeconds(2);
    StoredTrafficRecord? tunnelRecord = null;
    while (DateTimeOffset.UtcNow < tunnelDeadline)
    {
        tunnelRecord = archive.GetRecentTraffic(10).FirstOrDefault(item => item.Traffic.Method == "CONNECT" && item.Traffic.SizeBytes == 4);
        if (tunnelRecord is not null) break;
        await Task.Delay(20, cancellation.Token);
    }
    Require(tunnelRecord is not null, "HTTPS 隧道必须持久化连接元数据和下行字节数");
    Require(tunnelRecord!.Traffic.Protocol == NetMindDefaults.ProtocolHttpsTunnel, "HTTPS 隧道记录必须明确正文未解密");
    Require(tunnelRecord.Traffic.Process.Contains("NetMind.SmokeTests", StringComparison.OrdinalIgnoreCase), "HTTPS 隧道必须关联真实客户端进程");
    var tunnelEvidence = DemoData.CreateFinding(tunnelRecord.Traffic).Evidence;
    Require(tunnelEvidence.Any(item => item.Title == "加密隧道" && item.Value.Contains("未进行内容推断", StringComparison.Ordinal)),
        "HTTPS 隧道证据不得伪装成已解析的 TLS 正文");

    cancellation.Cancel();
    await proxyTask;
    upstream.Stop();
}

static async Task ReadExactAsync(Stream stream, Memory<byte> buffer, CancellationToken cancellationToken)
{
    var offset = 0;
    while (offset < buffer.Length)
    {
        var read = await stream.ReadAsync(buffer[offset..], cancellationToken);
        if (read == 0) throw new EndOfStreamException("测试流提前结束。");
        offset += read;
    }
}

static async Task<byte[]> ReadUntilHeadersBytesAsync(Stream stream, CancellationToken cancellationToken)
{
    using var output = new MemoryStream();
    byte[] marker = [13, 10, 13, 10];
    var matched = 0;
    var buffer = new byte[1];
    while (await stream.ReadAsync(buffer, cancellationToken) > 0)
    {
        output.WriteByte(buffer[0]);
        matched = buffer[0] == marker[matched] ? matched + 1 : buffer[0] == marker[0] ? 1 : 0;
        if (matched == marker.Length) return output.ToArray();
    }
    throw new EndOfStreamException("代理响应头未完整到达。");
}

static async Task ReadUntilHeadersAsync(Stream stream)
{
    byte[] marker = [13, 10, 13, 10];
    var matched = 0;
    var buffer = new byte[1];
    while (await stream.ReadAsync(buffer) > 0)
    {
        matched = buffer[0] == marker[matched] ? matched + 1 : buffer[0] == marker[0] ? 1 : 0;
        if (matched == marker.Length) return;
    }
    throw new EndOfStreamException("上游测试请求头未完整到达。");
}

static async Task VerifyHooksAsync()
{
    // 策略分支回归：钩子脚本沿用脚本验证页的静态策略，行为不得漂移。
    var openViolations = PythonSandboxPolicy.Validate("data = open('secret.txt').read()");
    Require(openViolations.Any(item => item.Contains("open()", StringComparison.Ordinal)),
        "含 open() 的钩子脚本必须仍被静态策略拒绝");
    var importViolations = PythonSandboxPolicy.Validate("import os");
    Require(importViolations.Any(item => item.Contains("禁止导入模块：os", StringComparison.Ordinal)),
        "钩子脚本导入 os 必须被拒绝");
    var execViolations = PythonSandboxPolicy.Validate("exec('print(1)')");
    Require(execViolations.Any(item => item.Contains("exec()", StringComparison.Ordinal)),
        "钩子脚本调用 exec() 必须被拒绝");
    Require(PythonSandboxPolicy.Validate("def on_before_send(event):\n    return {'url': event.get('url')}\n").Count == 0,
        "纯逻辑钩子脚本必须通过静态策略");

    VerifyHookEnvelopeContract();
    VerifyHookEventQueue();
    VerifyHookEngineEmitBackpressure();
    await VerifyHookConfigStoreAsync();
    await VerifyHookSettingsSwitchAsync();
    await VerifyProxyWithoutHooksAsync();
    await VerifyHookWorkerEndToEndAsync();
}

static void VerifyHookEngineEmitBackpressure()
{
    // 未启动的引擎即可验证关键路径背压：队列满时 Emit 整体跳过信封（含哈希），不入队也不抛出。
    using var engineHolder = new ScriptHookEngineDisposer();
    var engine = new ScriptHookEngine("NetMind.SandboxHost.exe", null, "hook-script.py", "data",
        new[] { HookEventNames.RequestBeforeSend });
    engineHolder.Engine = engine;
    var snapshot = new HookTransactionSnapshot(Guid.NewGuid(), Guid.NewGuid(), "GET",
        "http://example.test/backpressure", "example.test", "/backpressure", null, new byte[16]);
    for (var index = 0; index < NetMindDefaults.HookEventQueueCapacity; index++)
        engine.Emit(HookEventNames.RequestBeforeSend, snapshot);
    Require(engine.QueuedEventCount == NetMindDefaults.HookEventQueueCapacity,
        "投递达到队列容量前不得丢弃");
    engine.Emit(HookEventNames.RequestBeforeSend, snapshot);
    Require(engine.QueuedEventCount == NetMindDefaults.HookEventQueueCapacity && engine.DroppedEventCount == 1,
        "队列已满时 Emit 必须整体跳过信封、不入队、不抛出，并纳入背压丢弃统计");
    var metrics = engine.GetMetricsSnapshot();
    Require(metrics.State == "starting" && metrics.QueuedEvents == NetMindDefaults.HookEventQueueCapacity &&
            metrics.DroppedEvents == 1 && metrics.ProcessedEvents == 0,
        "脚本 Hook 运行快照必须在未启动状态下准确报告队列、丢弃与处理计数");
    Require(engine.DrainFindings().Count == 0, "未启动工作进程时观察结论取回必须为空");
}

static void VerifyHookEnvelopeContract()
{
    var envelope = new HookEventEnvelope(
        HookEventNames.RequestBeforeSend, Guid.NewGuid().ToString(), Guid.NewGuid().ToString(),
        HookEventNames.FunctionBeforeSend, "POST", "http://api.example.test/items?id=1",
        "api.example.test", "/items?id=1", 201,
        new Dictionary<string, string> { ["Content-Type"] = "application/json" },
        Convert.ToBase64String(Encoding.UTF8.GetBytes("预览正文")), true, "0f", 4096);
    var json = JsonSerializer.Serialize(envelope, HookEventEnvelope.JsonOptions);
    using var document = JsonDocument.Parse(json);
    var expectedFields = new[]
    {
        "schema", "event", "txnId", "sessionId", "hookName", "method", "url", "host", "endpoint",
        "statusCode", "headers", "bodyPreviewBase64", "bodyTruncated", "bodySha256", "bodySize"
    };
    foreach (var field in expectedFields)
        Require(document.RootElement.TryGetProperty(field, out _), $"钩子事件信封必须包含 camelCase 字段 {field}");
    Require(document.RootElement.EnumerateObject().Count() == expectedFields.Length,
        "钩子事件信封不得包含契约之外的字段");
    Require(document.RootElement.GetProperty("schema").GetInt32() == NetMindDefaults.HookEventSchemaVersion,
        "信封 schema 版本必须等于集中常量");
    Require(document.RootElement.GetProperty("statusCode").GetInt32() == 201 &&
            document.RootElement.GetProperty("bodyTruncated").GetBoolean() &&
            document.RootElement.GetProperty("bodySize").GetInt64() == 4096,
        "信封数值与布尔字段必须按 camelCase 契约序列化");

    var beforeSend = new HookEventEnvelope(HookEventNames.RequestBeforeSend, "txn", "session",
        HookEventNames.FunctionBeforeSend, "GET", "http://example.test/", "example.test", "/",
        null, null, null, false, null, 0);
    var roundTripped = JsonSerializer.Deserialize<HookEventEnvelope>(
        JsonSerializer.Serialize(beforeSend, HookEventEnvelope.JsonOptions), HookEventEnvelope.JsonOptions);
    Require(roundTripped == beforeSend, "信封必须支持 JSON 往返（请求发送前状态码可为空）");
}

static HookEventEnvelope MakeHookEnvelope(string endpoint) => new(
    HookEventNames.RequestBeforeSend, "txn", "session", HookEventNames.FunctionBeforeSend,
    "GET", "http://example.test" + endpoint, "example.test", endpoint, null, null, null, false, null, 0);

static void VerifyHookEventQueue()
{
    var countLimited = new HookEventQueue(2, 64L * 1024 * 1024);
    Require(countLimited.TryEnqueue(MakeHookEnvelope("/q/1")) &&
            countLimited.TryEnqueue(MakeHookEnvelope("/q/2")) &&
            countLimited.TryEnqueue(MakeHookEnvelope("/q/3")),
        "超容量入队不得抛出");
    Require(countLimited.DroppedCount == 1 && countLimited.Count == 2,
        "超容量入队必须丢弃最旧事件并递增丢弃计数");
    Require(countLimited.TryDequeue(out var oldestSurvivor) && oldestSurvivor!.Endpoint == "/q/2",
        "超容量丢弃后后续仍可出队最旧存活事件");

    var longEndpoint = "/" + new string('x', 200);
    var singleBytes = MakeHookEnvelope(longEndpoint).EstimateBytes();
    var byteLimited = new HookEventQueue(NetMindDefaults.HookEventQueueCapacity, 2 * singleBytes);
    Require(byteLimited.TryEnqueue(MakeHookEnvelope(longEndpoint)) &&
            byteLimited.TryEnqueue(MakeHookEnvelope(longEndpoint)),
        "字节限额内的入队必须成功");
    Require(byteLimited.TryEnqueue(MakeHookEnvelope(longEndpoint)), "超字节限额入队不得抛出");
    Require(byteLimited.DroppedCount == 1 && byteLimited.Count == 2,
        "超字节限额必须丢弃最旧事件并递增丢弃计数");
    while (byteLimited.TryDequeue(out _)) { }
    Require(byteLimited.Count == 0 && byteLimited.CurrentBytes == 0, "全部出队后条数与字节记账必须归零");
    Require(!byteLimited.TryEnqueue(null), "空信封入队必须被安全拒绝");

    var concurrent = new HookEventQueue(64, 64L * 1024 * 1024);
    Parallel.For(0, 2048, index => concurrent.TryEnqueue(MakeHookEnvelope("/parallel/" + index)));
    Require(concurrent.Count <= concurrent.Capacity && concurrent.CurrentBytes <= 64L * 1024 * 1024,
        "多写入线程并发投递时，队列条数与字节账面不得突破硬限制");
    while (concurrent.TryDequeue(out _)) { }
    Require(concurrent.Count == 0 && concurrent.CurrentBytes == 0,
        "并发投递队列全部出队后记账必须归零");
}

static async Task VerifyHookConfigStoreAsync()
{
    var workspaceRoot = Path.Combine(Path.GetTempPath(), "netmind-hooks-config-test-" + Guid.NewGuid().ToString("N"));
    try
    {
        Require(!new TrafficHookConfiguration().Enabled && new TrafficHookSwitches().EnabledCount == 0,
            "钩子配置与逐项开关默认必须关闭");
        Require(await TrafficHookConfigStore.LoadAsync(workspaceRoot) is null,
            "钩子配置缺失时必须按未配置处理");

        var configuration = new TrafficHookConfiguration(true, NetMindDefaults.HookScriptFileName,
            new TrafficHookSwitches(BeforeSend: true, BeforeWrite: true));
        await TrafficHookConfigStore.SaveConfigAsync(workspaceRoot, configuration);
        Require(!Directory.EnumerateFiles(TrafficHookConfigStore.GetScriptsDirectory(workspaceRoot))
                .Any(file => file.Contains(".tmp-", StringComparison.Ordinal)),
            "钩子配置原子写不得残留临时文件");
        var restored = await TrafficHookConfigStore.LoadAsync(workspaceRoot);
        Require(restored is not null && restored.Equals(configuration) && restored.Hooks!.EnabledCount == 2,
            "钩子配置必须可完整往返读取");
        Require(TrafficHookConfigStore.ResolveScriptPath(workspaceRoot, NetMindDefaults.HookScriptFileName) ==
                TrafficHookConfigStore.GetDefaultScriptPath(workspaceRoot) &&
                TrafficHookConfigStore.ResolveScriptPath(workspaceRoot, @"C:\abs\hook.py") == @"C:\abs\hook.py",
            "scriptPath 必须按采集后台契约解析相对与绝对路径");

        var runtimeMetrics = new ScriptHookMetricsSnapshot("running", 2, 1, 10, 9, 0, 3, 0, 1,
            DateTimeOffset.UtcNow, HookEventNames.RequestBeforeSend, null, null);
        await TrafficHookStatusStore.SaveAsync(workspaceRoot, runtimeMetrics);
        var runtime = await TrafficHookStatusStore.LoadAsync(workspaceRoot);
        Require(runtime is not null && runtime.Metrics == runtimeMetrics && runtime.HostProcessId == Environment.ProcessId,
            "采集后台发布的脚本 Hook 运行指标必须可由工作台原子读取并完整往返");
        Require(!Directory.EnumerateFiles(TrafficHookConfigStore.GetScriptsDirectory(workspaceRoot))
                .Any(file => file.Contains(".tmp-", StringComparison.Ordinal)),
            "脚本 Hook 状态原子写不得残留临时文件");

        await File.WriteAllTextAsync(TrafficHookConfigStore.GetConfigPath(workspaceRoot), "{ 损坏的 JSON");
        var corruptRejected = false;
        try { await TrafficHookConfigStore.LoadAsync(workspaceRoot); }
        catch (InvalidDataException exception) { corruptRejected = exception.Message.Contains("钩子配置文件损坏", StringComparison.Ordinal); }
        Require(corruptRejected, "损坏的钩子配置必须抛出中文 InvalidDataException");
    }
    finally
    {
        if (Directory.Exists(workspaceRoot)) Directory.Delete(workspaceRoot, recursive: true);
    }
}

static async Task VerifyHookSettingsSwitchAsync()
{
    var settingsRoot = Path.Combine(Path.GetTempPath(), "netmind-hooks-settings-test-" + Guid.NewGuid().ToString("N"));
    try
    {
        Require(!new WorkbenchSettings().EnableTrafficHooks, "钩子总开关默认必须关闭");
        var store = new WorkbenchSettingsStore(Path.Combine(settingsRoot, "settings.json"));
        await store.SaveAsync(new WorkbenchSettings() with { EnableTrafficHooks = true });
        Require((await store.LoadAsync()).EnableTrafficHooks, "钩子总开关必须随设置文件完整往返");
    }
    finally
    {
        if (Directory.Exists(settingsRoot)) Directory.Delete(settingsRoot, recursive: true);
    }
}

static async Task VerifyProxyWithoutHooksAsync()
{
    // 开关关闭等价于 hookEngine=null：代理必须按既有链路正常完成请求。
    var workspaceRoot = Path.Combine(Path.GetTempPath(), "netmind-hooks-proxy-test-" + Guid.NewGuid().ToString("N"));
    try
    {
        await new WorkspaceStore(workspaceRoot).InitializeAsync("钩子关闭代理测试工作区");
        var upstream = new TcpListener(IPAddress.Loopback, 0);
        upstream.Start();
        var upstreamEndpoint = (IPEndPoint)upstream.LocalEndpoint;
        var upstreamTask = Task.Run(async () =>
        {
            using var client = await upstream.AcceptTcpClientAsync();
            using var stream = client.GetStream();
            await ReadUntilHeadersAsync(stream);
            var body = Encoding.UTF8.GetBytes("钩子关闭链路正常");
            await stream.WriteAsync(Encoding.ASCII.GetBytes($"HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {body.Length}\r\nConnection: close\r\n\r\n"));
            await stream.WriteAsync(body);
        });

        using var archive = new TrafficArchive(workspaceRoot);
        await using var proxy = new ExplicitHttpProxy(new ProxyOptions(IPAddress.Loopback, 0), archive, hookEngine: null);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var proxyTask = proxy.RunAsync(cancellation.Token);
        while (proxy.LocalEndpoint is null) await Task.Delay(10, cancellation.Token);

        using (var client = new TcpClient())
        {
            await client.ConnectAsync(proxy.LocalEndpoint.Address, proxy.LocalEndpoint.Port, cancellation.Token);
            using var stream = client.GetStream();
            await stream.WriteAsync(Encoding.ASCII.GetBytes(
                $"GET http://127.0.0.1:{upstreamEndpoint.Port}/no-hooks HTTP/1.1\r\nHost: 127.0.0.1:{upstreamEndpoint.Port}\r\nConnection: close\r\n\r\n"), cancellation.Token);
            using var response = new MemoryStream();
            await stream.CopyToAsync(response, cancellation.Token);
            var responseText = Encoding.UTF8.GetString(response.ToArray());
            Require(responseText.Contains("200 OK", StringComparison.Ordinal) &&
                    responseText.Contains("钩子关闭链路正常", StringComparison.Ordinal),
                "钩子关闭（hookEngine=null）时代理请求必须正常完成");
        }

        await upstreamTask;
        cancellation.Cancel();
        await proxyTask;
        upstream.Stop();
    }
    finally
    {
        if (Directory.Exists(workspaceRoot)) Directory.Delete(workspaceRoot, recursive: true);
    }
}

static string? ResolveSandboxHostForTest()
{
    foreach (var configuration in new[] { "Release", "Debug" })
    {
        var candidate = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory,
            "..", "..", "..", "..", "NetMind.SandboxHost", "bin", configuration, "net10.0", "NetMind.SandboxHost.exe"));
        if (File.Exists(candidate)) return candidate;
    }
    return null;
}

static async Task<JsonElement?> ReadHookWorkerMessageAsync(Process worker, string expectedType, TimeSpan timeout)
{
    var deadline = DateTimeOffset.UtcNow + timeout;
    while (DateTimeOffset.UtcNow < deadline)
    {
        string? line;
        try { line = await worker.StandardOutput.ReadLineAsync().WaitAsync(deadline - DateTimeOffset.UtcNow); }
        catch (TimeoutException) { return null; }
        if (line is null) return null;
        try
        {
            using var document = JsonDocument.Parse(line);
            if (document.RootElement.ValueKind == JsonValueKind.Object &&
                document.RootElement.TryGetProperty("type", out var type) &&
                type.GetString() == expectedType)
                return document.RootElement.Clone();
        }
        catch (JsonException) { /* 非协议输出直接忽略。 */ }
    }
    return null;
}

static async Task VerifyHookWorkerEndToEndAsync()
{
    // 可选端到端子断言：需要本机 Python 可发现；否则跳过不视为失败。
    var probe = await new PythonSandboxRunner().RunAsync(new SandboxJob(
        "print('python-ok')", JsonSerializer.SerializeToElement(new { }), TimeoutMilliseconds: 10000));
    if (!probe.Succeeded && probe.State == "运行时不可用")
    {
        Console.WriteLine("钩子工作进程端到端子断言跳过（未找到 Python）。");
        return;
    }

    var sandboxHostPath = ResolveSandboxHostForTest();
    Require(sandboxHostPath is not null, "钩子端到端断言必须能找到同批构建的 NetMind.SandboxHost 可执行文件");

    var hookRoot = Path.Combine(Path.GetTempPath(), "netmind-hooks-e2e-" + Guid.NewGuid().ToString("N"));
    Process? worker = null;
    try
    {
        Directory.CreateDirectory(hookRoot);
        var dataDirectory = Path.Combine(hookRoot, "data");
        var scriptPath = Path.Combine(hookRoot, NetMindDefaults.HookScriptFileName);
        // store 由宿主直接注入脚本命名空间，无需也不得 import 宿主模块。
        await File.WriteAllTextAsync(scriptPath, """
            def on_before_send(event):
                store.save('last-url.txt', event.get('url') or '')
                return {'method': event.get('method'), 'url': event.get('url')}
            """, new UTF8Encoding(false));

        var startInfo = new ProcessStartInfo(sandboxHostPath!)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
            StandardInputEncoding = new UTF8Encoding(false)
        };
        startInfo.ArgumentList.Add("hook-worker");
        startInfo.ArgumentList.Add(scriptPath);
        startInfo.ArgumentList.Add(dataDirectory);
        worker = new Process { StartInfo = startInfo };
        Require(worker.Start(), "钩子沙箱宿主必须可启动");

        Require(await ReadHookWorkerMessageAsync(worker, HookWorkerMessageTypes.Ready, TimeSpan.FromSeconds(30)) is not null,
            "钩子工作进程必须上报 ready");

        var envelope = new HookEventEnvelope(HookEventNames.RequestBeforeSend, Guid.NewGuid().ToString(), Guid.NewGuid().ToString(),
            HookEventNames.FunctionBeforeSend, "GET", "http://127.0.0.1:1/hook-e2e?probe=1", "127.0.0.1", "/hook-e2e?probe=1",
            null, null, null, false, null, 0);
        await worker.StandardInput.WriteLineAsync(JsonSerializer.Serialize(envelope, HookEventEnvelope.JsonOptions));
        await worker.StandardInput.FlushAsync();

        var finding = await ReadHookWorkerMessageAsync(worker, HookWorkerMessageTypes.Finding, TimeSpan.FromSeconds(30));
        Require(finding is not null &&
                finding.Value.GetProperty("event").GetString() == HookEventNames.RequestBeforeSend &&
                finding.Value.GetProperty("data").GetProperty("method").GetString() == "GET",
            "钩子工作进程必须把事件分发到 on_before_send 并回传 finding");
        Require(await ReadHookWorkerMessageAsync(worker, HookWorkerMessageTypes.Processed, TimeSpan.FromSeconds(15)) is not null,
            "钩子工作进程必须为已执行事件回传 processed，供运行指标与试跑完成判定");
        var storedPath = Path.Combine(dataDirectory, "last-url.txt");
        Require(File.Exists(storedPath) && await File.ReadAllTextAsync(storedPath) == "http://127.0.0.1:1/hook-e2e?probe=1",
            "钩子经 store.save 的持久化必须落在数据目录（工作进程 cwd）");

        // 心跳回环：驱动对 heartbeat 行必须回 heartbeat-ack（F5 回归）。
        await worker.StandardInput.WriteLineAsync(JsonSerializer.Serialize(new { type = HookWorkerMessageTypes.Heartbeat }, HookEventEnvelope.JsonOptions));
        await worker.StandardInput.FlushAsync();
        Require(await ReadHookWorkerMessageAsync(worker, HookWorkerMessageTypes.HeartbeatAck, TimeSpan.FromSeconds(15)) is not null,
            "钩子驱动必须对心跳行回 heartbeat-ack");

        // 未定义钩子的事件明确回 processed/missing-handler，且不得阻塞回环。
        var undefinedHookEnvelope = new HookEventEnvelope(HookEventNames.ResponseAfterDeliver, Guid.NewGuid().ToString(), Guid.NewGuid().ToString(),
            HookEventNames.FunctionAfterDeliver, "GET", "http://127.0.0.1:1/hook-e2e?probe=2", "127.0.0.1", "/hook-e2e?probe=2",
            200, null, null, false, null, 0);
        await worker.StandardInput.WriteLineAsync(JsonSerializer.Serialize(undefinedHookEnvelope, HookEventEnvelope.JsonOptions));
        await worker.StandardInput.FlushAsync();
        var undefinedProcessed = await ReadHookWorkerMessageAsync(worker, HookWorkerMessageTypes.Processed, TimeSpan.FromSeconds(15));
        Require(undefinedProcessed is not null && undefinedProcessed.Value.GetProperty("outcome").GetString() == "missing-handler",
            "未定义的钩子函数必须被明确统计为 missing-handler，不能表现成无响应");
        await worker.StandardInput.WriteLineAsync(JsonSerializer.Serialize(new { type = HookWorkerMessageTypes.Heartbeat }, HookEventEnvelope.JsonOptions));
        await worker.StandardInput.FlushAsync();
        var ackAfterUndefined = await ReadHookWorkerMessageAsync(worker, HookWorkerMessageTypes.HeartbeatAck, TimeSpan.FromSeconds(15));
        Require(ackAfterUndefined is not null, "未定义钩子事件后驱动必须仍然存活并应答心跳");

        await worker.StandardInput.WriteLineAsync(JsonSerializer.Serialize(new { type = HookWorkerMessageTypes.Shutdown }, HookEventEnvelope.JsonOptions));
        await worker.StandardInput.FlushAsync();
        try
        {
            await worker.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(15));
            Require(worker.ExitCode == 0, "shutdown 指令必须让钩子工作进程优雅退出（退出码 0）");
        }
        catch (TimeoutException)
        {
            Require(false, "钩子工作进程未在限时内优雅退出");
        }
    }
    finally
    {
        if (worker is not null)
        {
            try { if (!worker.HasExited) worker.Kill(entireProcessTree: true); } catch { /* 进程可能刚好退出。 */ }
            worker.Dispose();
        }
        if (Directory.Exists(hookRoot)) Directory.Delete(hookRoot, recursive: true);
    }

    await VerifyHookShimIsolationAsync(sandboxHostPath!);
}

static async Task VerifyHookShimIsolationAsync(string sandboxHostPath)
{
    // F1 策略绕过回归：`from netmind_hooks import os` 类脚本不得获得宿主能力；
    // 宿主模块已不存在，应体现为 worker 端加载失败（ImportError → error 消息 + 退出码 3）而非放行。
    var isolationRoot = Path.Combine(Path.GetTempPath(), "netmind-hooks-isolation-" + Guid.NewGuid().ToString("N"));
    Process? worker = null;
    try
    {
        Directory.CreateDirectory(isolationRoot);
        var scriptPath = Path.Combine(isolationRoot, "hook-bypass-script.py");
        await File.WriteAllTextAsync(scriptPath, "from netmind_hooks import os\n\ndef on_before_send(event):\n    return {'bypass': True}", new UTF8Encoding(false));

        var startInfo = new ProcessStartInfo(sandboxHostPath)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
            StandardInputEncoding = new UTF8Encoding(false)
        };
        startInfo.ArgumentList.Add("hook-worker");
        startInfo.ArgumentList.Add(scriptPath);
        startInfo.ArgumentList.Add(Path.Combine(isolationRoot, "data"));
        worker = new Process { StartInfo = startInfo };
        Require(worker.Start(), "钩子沙箱宿主必须可启动（隔离回归）");

        var errorMessage = await ReadHookWorkerMessageAsync(worker, HookWorkerMessageTypes.Error, TimeSpan.FromSeconds(30));
        Require(errorMessage is not null &&
                errorMessage.Value.TryGetProperty("message", out var message) &&
                message.GetString()!.Contains("钩子脚本加载失败", StringComparison.Ordinal),
            "试图从宿主模块导入 os 的钩子脚本必须在 worker 端加载失败，而非获得宿主能力");
        Require(await ReadHookWorkerMessageAsync(worker, HookWorkerMessageTypes.Ready, TimeSpan.FromSeconds(5)) is null,
            "绕过脚本不得进入 ready 状态");
        try
        {
            await worker.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(15));
            Require(worker.ExitCode == 3, "绕过脚本必须以脚本加载失败退出码 3 结束");
        }
        catch (TimeoutException)
        {
            Require(false, "绕过脚本的钩子工作进程未在限时内退出");
        }
    }
    finally
    {
        if (worker is not null)
        {
            try { if (!worker.HasExited) worker.Kill(entireProcessTree: true); } catch { /* 进程可能刚好退出。 */ }
            worker.Dispose();
        }
        if (Directory.Exists(isolationRoot)) Directory.Delete(isolationRoot, recursive: true);
    }
}

/// <summary>
/// 页内 Hook 定向验证：脚本五类包裹目标完整；ParseBatch 字段映射/单条截断/单批上限；
/// 接收端点 HTTP 回环入库；超限淘汰最旧；注入器对不可达端口限时降级不抛。
/// </summary>
static async Task VerifyPageHooksAsync()
{
    // ① 注入脚本必须覆盖五类包裹目标，且端口占位符正确替换。
    var script = PageHookScript.Build(4321);
    foreach (var marker in new[] { "XMLHttpRequest.prototype.open", "XMLHttpRequest.prototype.send", "ROOT.fetch", "crypto", "btoa", "atob", "setItem", "hook.installed", "service_worker" })
        Require(script.Contains(marker, StringComparison.Ordinal), $"页内 Hook 脚本必须包裹 {marker}");

    // 存储读取与安装快照：只钩 setItem 会漏掉“上次会话写入、本次只读取”的令牌，
    // 那是参数溯源里最常见的盲区。以下断言锁住这条链路的三个要点。
    Require(script.Contains("Storage.prototype.getItem", StringComparison.Ordinal),
        "页内 Hook 脚本必须包裹 Storage.prototype.getItem，否则采集前写入的值只会被静默读走");
    Require(script.Contains("storage.snapshot", StringComparison.Ordinal),
        "页内 Hook 脚本必须在安装时对现有存储做一份快照");
    Require(script.Contains("nativeStorageGetItem.call(store, key)", StringComparison.Ordinal),
        "快照必须走原生 getItem：经包装版本读取会自造一批读取事件并把所有键标记为已见");
    Require(script.Contains("seenReads", StringComparison.Ordinal) &&
            script.Contains("Object.create(null)", StringComparison.Ordinal),
        "读取事件必须按键去重，且去重表不能用普通对象（页面可控的 __proto__ 会污染判断）");
    Require(script.Contains("http://127.0.0.1:4321/hooks", StringComparison.Ordinal), "脚本必须把接收端口替换进上报端点");
    Require(!script.Contains("__NETMIND_HOOK_PORT__", StringComparison.Ordinal), "脚本不得残留端口占位符");
    Require(PageHookInjector.IsSupportedTargetType("page") && PageHookInjector.IsSupportedTargetType("worker") &&
            PageHookInjector.IsSupportedTargetType("shared_worker") && PageHookInjector.IsSupportedTargetType("service_worker") &&
            !PageHookInjector.IsSupportedTargetType("browser"),
        "Hook 目标分类必须覆盖页面与三类 Worker，且不得把浏览器级目标误当作脚本上下文");

    // ② ParseBatch：字段映射、ts 毫秒转时间、args UTF-8 单条截断、NUL 剔除、单批上限。
    var sessionId = Guid.NewGuid();
    var longArgs = new string('汉', 9000); // 每字 3 字节，超限触发二分截断
    var batchJson = JsonSerializer.Serialize(new object[]
    {
        new { ts = 1700000000000L, type = "xhr", fn = "XMLHttpRequest.send", url = "http://a.test/api", pageUrl = "http://a.test/", args = "{\"method\":\"POST\"}", stack = "at f (app.js:1)" },
        new { ts = 1700000000100L, type = "encode", fn = "btoa", pageUrl = "http://a.test/", args = longArgs },
        new { type = "fetch", fn = "fetch\u0000.clean" }
    });
    var parsed = PageHookReceiver.ParseBatch(batchJson, sessionId);
    Require(parsed.Count == 3, "ParseBatch 必须解析出全部三条对象事件");
    Require(parsed[0].Timestamp == DateTimeOffset.FromUnixTimeMilliseconds(1700000000000), "ts 毫秒必须映射为 DateTimeOffset");
    Require(parsed[0].Type == "xhr" && parsed[0].Function == "XMLHttpRequest.send" && parsed[0].PageUrl == "http://a.test/", "事件字段映射必须正确");
    Require(Encoding.UTF8.GetByteCount(parsed[1].ArgsJson) <= NetMindDefaults.PageHookMaximumArgsBytes, "超长 args 必须按 UTF-8 字节截断到单条上限");
    Require(parsed[0].TargetUrl == "http://a.test/api" && parsed[0].Stack.Contains("app.js", StringComparison.Ordinal), "页内 Hook 必须保留调用目标 URL 与脚本位置");
    Require(!parsed[2].Function.Contains('\0'), "args/fn 中的 NUL 必须剔除");
    Require(parsed.All(item => item.SessionId == sessionId), "解析结果必须携带接收会话标识");
    var overBatch = Enumerable.Range(0, NetMindDefaults.PageHookMaximumEventsPerBatch + 50)
        .Select(index => (object)new { ts = 1L, type = "xhr", fn = $"fn{index}" }).ToArray();
    Require(PageHookReceiver.ParseBatch(JsonSerializer.Serialize(overBatch), sessionId).Count == NetMindDefaults.PageHookMaximumEventsPerBatch,
        "单批事件数必须截断到上限");
    Require(PageHookReceiver.ParseBatch("{}", sessionId).Count == 0, "非数组上报必须解析为空");

    // ③ 接收端点回环 + TrafficArchive 入库与回读。
    var hookRoot = Path.Combine(Path.GetTempPath(), "netmind-pagehook-test-" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(hookRoot);
    try
    {
        using var archive = new TrafficArchive(hookRoot);
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var hookPort = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        var batches = new List<IReadOnlyList<PageHookEvent>>();
        await using var receiver = new PageHookReceiver(hookPort, sessionId, events =>
        {
            lock (batches) batches.Add(events);
            return archive.RecordPageHooksAsync(events);
        });
        receiver.Start();
        using (var http = new HttpClient())
        {
            var response = await http.PostAsync($"http://127.0.0.1:{hookPort}/hooks",
                new StringContent(batchJson, Encoding.UTF8, "application/json"));
            Require((int)response.StatusCode == 204, "接收端点必须回 204");
            var getResponse = await http.GetAsync($"http://127.0.0.1:{hookPort}/hooks");
            Require((int)getResponse.StatusCode == 400, "非 POST 请求必须回 400");
        }
        var deadline = DateTime.UtcNow.AddSeconds(5);
        while (DateTime.UtcNow < deadline)
        {
            lock (batches) { if (batches.Count > 0) break; }
            await Task.Delay(50);
        }
        lock (batches) Require(batches.Count == 1 && batches[0].Count == 3, "接收器必须把上报批次回调入库");
        var stored = archive.GetPageHooks();
        Require(stored.Count == 3, "页内 Hook 必须可从工作区回读");
        Require(stored.Any(item => item.Function == "XMLHttpRequest.send"), "回读必须包含上报事件");
        Require(Encoding.UTF8.GetByteCount(stored.Single(item => item.Function == "btoa").ArgsJson) <= NetMindDefaults.PageHookMaximumArgsBytes,
            "入库后的 args 必须保持截断上限");
        Require(archive.GetPageHooks("encode").Count == 1 && archive.GetPageHooks("encode")[0].Function == "btoa", "按类型过滤必须生效");
        var otherSessionId = Guid.NewGuid();
        await archive.RecordPageHooksAsync([
            new PageHookEvent(0, otherSessionId, DateTimeOffset.UtcNow, "fetch", "other-session", "https://other.test", "[]")
        ]);
        var scopedHooks = archive.GetPageHooksBySessions([sessionId]);
        Require(scopedHooks.Count == 3 && scopedHooks.All(item => item.SessionId == sessionId) &&
                scopedHooks.All(item => item.Function != "other-session"),
            "按证据会话读取 Hook 时不得混入其他捕获会话");

        // ④ 超限淘汰：注入小阈值验证保留最新、删除最旧。
        var metadataPath = Path.Combine(hookRoot, NetMindDefaults.MetadataDatabaseFileName);
        using (var metadata = new SqliteMetadataStore(metadataPath))
        {
            var oldHooks = Enumerable.Range(0, 5)
                .Select(index => new PageHookEvent(0, sessionId, DateTimeOffset.UtcNow.AddMinutes(-index), "xhr", $"old-{index}", "", "")).ToList();
            metadata.SavePageHooks(oldHooks, maximumRows: 5);
            metadata.SavePageHooks(Enumerable.Range(0, 3)
                .Select(index => new PageHookEvent(0, sessionId, DateTimeOffset.UtcNow, "xhr", $"new-{index}", "", "")).ToList(), maximumRows: 5);
            var remaining = metadata.GetPageHooks(null, 100);
            Require(remaining.Count == 5, "超限后必须淘汰到保留上限");
            Require(remaining.Any(item => item.Function == "new-0") &&
                    remaining.All(item => item.Function is not ("old-0" or "old-1" or "old-2")),
                "淘汰必须删除最旧记录、保留最新");
        }
    }
    finally
    {
        if (Directory.Exists(hookRoot)) Directory.Delete(hookRoot, recursive: true);
    }

    // ⑤ 注入器降级：不可达调试端口必须限时返回 false 且不抛出。
    var listener2 = new TcpListener(IPAddress.Loopback, 0);
    listener2.Start();
    var deadPort = ((IPEndPoint)listener2.LocalEndpoint).Port;
    listener2.Stop();
    var stopwatch = System.Diagnostics.Stopwatch.StartNew();
    var injected = await PageHookInjector.InjectAsync(deadPort, 9, TimeSpan.FromSeconds(2));
    stopwatch.Stop();
    Require(!injected, "不可达调试端口必须返回注入失败");
    Require(stopwatch.Elapsed < TimeSpan.FromSeconds(10), "注入失败必须在限时内返回");
}

/// <summary>
/// 使用本机已安装 Chromium 做真实端到端验证。浏览器连接一个故意不存在的代理，
/// 只有回环 Hook 地址正确绕过代理时，安装握手才能到达接收器并落库。
/// </summary>
static async Task VerifyLivePageHookBrowserAsync()
{
    static int PickPort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        try
        {
            listener.Start();
            return ((IPEndPoint)listener.LocalEndpoint).Port;
        }
        finally { listener.Stop(); }
    }

    var root = Path.Combine(Path.GetTempPath(), "netmind-pagehook-live-" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(root);
    Process? browser = null;
    HttpListener? pageServer = null;
    CancellationTokenSource? monitorCancellation = null;
    Task? monitorTask = null;
    try
    {
        var hookPort = PickPort();
        var debuggingPort = PickPort();
        var unavailableProxyPort = PickPort();
        var pagePort = PickPort();
        var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(24)).ToLowerInvariant();
        var sessionId = Guid.NewGuid();
        using var archive = new TrafficArchive(root);
        await using var receiver = new PageHookReceiver(hookPort, sessionId,
            events => archive.RecordPageHooksAsync(events), token);
        receiver.Start();
        const string marker = "netmind-after-navigation";
        var stageOneHtml = "<script>var timer=setInterval(function(){if(window.__netmindPageHookInstalled){clearInterval(timer);location.href='/stage-two';}},50);</script>";
        var workerMarker = marker + "-worker";
        var serviceWorkerMarker = marker + "-service-worker";
        var stageTwoHtml = $"<script>window.__netmindWorker=new Worker('/worker.js');" +
                           $"if('serviceWorker' in navigator){{navigator.serviceWorker.register('/service-worker.js').then(function(reg){{setInterval(function(){{var w=reg.active||reg.waiting||reg.installing;if(w)w.postMessage('probe');}},250);}});}}" +
                           $"setTimeout(function(){{fetch('https://example.com/{marker}').catch(function(){{}});}},50);setInterval(function(){{btoa('{marker}');}},200);</script>";
        var workerScript = $"setInterval(function(){{btoa('{workerMarker}');fetch('https://example.com/{workerMarker}').catch(function(){{}});}},200);";
        var serviceWorkerScript = $"self.addEventListener('install',function(){{self.skipWaiting();}});self.addEventListener('activate',function(e){{e.waitUntil(self.clients.claim());}});self.addEventListener('message',function(){{btoa('{serviceWorkerMarker}');fetch('https://example.com/{serviceWorkerMarker}').catch(function(){{}});}});";
        var workerScriptRequestCount = 0;
        var serviceWorkerScriptRequestCount = 0;
        pageServer = new HttpListener();
        pageServer.Prefixes.Add($"http://127.0.0.1:{pagePort}/");
        pageServer.Start();
        _ = Task.Run(async () =>
        {
            try
            {
                while (pageServer.IsListening)
                {
                    var context = await pageServer.GetContextAsync();
                    var requestPath = context.Request.Url?.AbsolutePath;
                    var workerRequest = requestPath == "/worker.js";
                    var serviceWorkerRequest = requestPath == "/service-worker.js";
                    if (workerRequest) Interlocked.Increment(ref workerScriptRequestCount);
                    if (serviceWorkerRequest) Interlocked.Increment(ref serviceWorkerScriptRequestCount);
                    var content = workerRequest ? workerScript : serviceWorkerRequest ? serviceWorkerScript : requestPath == "/stage-two" ? stageTwoHtml : stageOneHtml;
                    var body = Encoding.UTF8.GetBytes(content);
                    context.Response.ContentType = workerRequest || serviceWorkerRequest ? "application/javascript; charset=utf-8" : "text/html; charset=utf-8";
                    context.Response.ContentLength64 = body.Length;
                    await context.Response.OutputStream.WriteAsync(body);
                    context.Response.Close();
                }
            }
            catch (Exception) when (!pageServer.IsListening) { }
        });

        var plan = CaptureBrowser.CreatePlan(Path.Combine(root, "browser-profile"),
            new IPEndPoint(IPAddress.Loopback, unavailableProxyPort), remoteDebuggingPort: debuggingPort,
            startUrl: $"http://127.0.0.1:{pagePort}/stage-one",
            useProxy: true) ?? throw new InvalidOperationException("未找到可用于 Hook 端到端验证的 Chromium 浏览器。");
        var startInfo = new ProcessStartInfo(plan.ExecutablePath)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardError = true
        };
        startInfo.ArgumentList.Add("--headless=new");
        startInfo.ArgumentList.Add("--disable-gpu");
        foreach (var argument in plan.Arguments) startInfo.ArgumentList.Add(argument);
        foreach (var (name, value) in plan.Environment) startInfo.Environment[name] = value;
        browser = Process.Start(startInfo) ?? throw new InvalidOperationException("真实 Chromium 测试进程未能启动。");

        monitorCancellation = new CancellationTokenSource();
        var injected = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        PageHookMonitorStatus? latestHookStatus = null;
        monitorTask = PageHookInjector.MonitorAsync(debuggingPort, hookPort, token, status =>
        {
            latestHookStatus = status;
            var pageTargets = status.ActiveTargetCount - status.WorkerTargetCount;
            var injectedPages = status.InjectedTargetCount - status.InjectedWorkerTargetCount;
            if (pageTargets > 0 && injectedPages == pageTargets)
                injected.TrySetResult();
            return Task.CompletedTask;
        }, TimeSpan.FromMilliseconds(250), monitorCancellation.Token);
        try { await injected.Task.WaitAsync(TimeSpan.FromSeconds(12)); }
        catch (TimeoutException)
        {
            throw new TimeoutException($"页面挂载超时；最后状态：active={latestHookStatus?.ActiveTargetCount ?? 0}, " +
                                       $"injected={latestHookStatus?.InjectedTargetCount ?? 0}, workers={latestHookStatus?.WorkerTargetCount ?? 0}, " +
                                       $"injectedWorkers={latestHookStatus?.InjectedWorkerTargetCount ?? 0}, failed={latestHookStatus?.FailedTargetCount ?? 0}");
        }

        // 首屏在检测到当前文档补注入后自行导航，避免第二个 CDP 客户端干扰被测会话。
        // addScript 的注册若随注入连接释放，stage-two 将没有安装握手，也捕获不到 API 调用。

        var deadline = DateTime.UtcNow.AddSeconds(10);
        IReadOnlyList<PageHookEvent> stored = [];
        while (DateTime.UtcNow < deadline)
        {
            stored = archive.GetPageHooks();
            if (stored.Count(item => item.Type == "lifecycle" && item.Function == "hook.installed") >= 2 &&
                stored.Any(item => item.Type == "encode" && item.Function == "btoa" &&
                                  item.ArgsJson.Contains("netmind-after-navigation", StringComparison.Ordinal)) &&
                stored.Any(item => item.Type == "fetch" &&
                                  item.TargetUrl.Contains("netmind-after-navigation", StringComparison.Ordinal)) &&
                stored.Any(item => item.Type == "lifecycle" && item.ArgsJson.Contains("\"context\":\"worker\"", StringComparison.Ordinal)) &&
                stored.Any(item => item.Type == "encode" && item.ArgsJson.Contains(workerMarker, StringComparison.Ordinal)) &&
                stored.Any(item => item.Type == "fetch" && item.TargetUrl.Contains(workerMarker, StringComparison.Ordinal)) &&
                stored.Any(item => item.Type == "lifecycle" && item.ArgsJson.Contains("\"context\":\"service_worker\"", StringComparison.Ordinal)) &&
                stored.Any(item => item.Type == "encode" && item.ArgsJson.Contains(serviceWorkerMarker, StringComparison.Ordinal)) &&
                stored.Any(item => item.Type == "fetch" && item.TargetUrl.Contains(serviceWorkerMarker, StringComparison.Ordinal))) break;
            await Task.Delay(100);
        }
        Console.WriteLine($"导航后 Hook 诊断：总数={stored.Count}，安装={stored.Count(item => item.Function == "hook.installed")}，" +
                          $"btoa={stored.Count(item => item.Function == "btoa")}，fetch={stored.Count(item => item.Type == "fetch")}");
        Console.WriteLine($"  monitor active={latestHookStatus?.ActiveTargetCount ?? 0}, injected={latestHookStatus?.InjectedTargetCount ?? 0}, " +
                          $"workers={latestHookStatus?.WorkerTargetCount ?? 0}, injectedWorkers={latestHookStatus?.InjectedWorkerTargetCount ?? 0}, " +
                          $"workerError={latestHookStatus?.WorkerMonitorError}");
        foreach (var lifecycle in stored.Where(item => item.Function == "hook.installed"))
            Console.WriteLine($"  install page={lifecycle.PageUrl} args={lifecycle.ArgsJson}");
        Console.WriteLine($"  worker-marker encode={stored.Count(item => item.ArgsJson.Contains(workerMarker, StringComparison.Ordinal))}，" +
                          $"fetch={stored.Count(item => item.TargetUrl.Contains(workerMarker, StringComparison.Ordinal))}，worker.js requests={workerScriptRequestCount}");
        Console.WriteLine($"  service-worker-marker encode={stored.Count(item => item.ArgsJson.Contains(serviceWorkerMarker, StringComparison.Ordinal))}，" +
                          $"fetch={stored.Count(item => item.TargetUrl.Contains(serviceWorkerMarker, StringComparison.Ordinal))}，service-worker.js requests={serviceWorkerScriptRequestCount}");
        Require(stored.Count(item => item.Type == "lifecycle" && item.Function == "hook.installed") >= 2,
            "Hook 必须覆盖初始文档与同标签页导航后的新文档");
        Require(stored.Any(item => item.Type == "encode" && item.Function == "btoa" &&
                                  item.ArgsJson.Contains("netmind-after-navigation", StringComparison.Ordinal)),
            "导航后的页面编码调用必须实际写入 SQLite");
        Require(stored.Any(item => item.Type == "fetch" &&
                                  item.TargetUrl.Contains("netmind-after-navigation", StringComparison.Ordinal)),
            "导航后的页面 fetch 调用必须实际写入 SQLite");
        Require(stored.Any(item => item.Type == "lifecycle" && item.Function == "hook.installed" &&
                                  item.ArgsJson.Contains("\"context\":\"worker\"", StringComparison.Ordinal)),
            "Dedicated Worker 必须通过 Runtime.evaluate 完成安装握手");
        Require(stored.Any(item => item.Type == "encode" && item.Function == "btoa" &&
                                  item.ArgsJson.Contains(workerMarker, StringComparison.Ordinal)) &&
                stored.Any(item => item.Type == "fetch" && item.TargetUrl.Contains(workerMarker, StringComparison.Ordinal)),
            "Dedicated Worker 内的编码与 fetch 调用必须实际写入 SQLite");
        Require(stored.Any(item => item.Type == "lifecycle" && item.Function == "hook.installed" &&
                                  item.ArgsJson.Contains("\"context\":\"service_worker\"", StringComparison.Ordinal)),
            "ServiceWorker 必须通过浏览器级 CDP 会话完成安装握手");
        Require(stored.Any(item => item.Type == "encode" && item.Function == "btoa" &&
                                  item.ArgsJson.Contains(serviceWorkerMarker, StringComparison.Ordinal)) &&
                stored.Any(item => item.Type == "fetch" && item.TargetUrl.Contains(serviceWorkerMarker, StringComparison.Ordinal)),
            "ServiceWorker 内的编码与 fetch 调用必须实际写入 SQLite");

        // 模拟用户停止后重新开始采集：新会话会轮换 Hook 端口与令牌，但浏览器标签页保持不变。
        monitorCancellation.Cancel();
        if (monitorTask is not null)
            try { await monitorTask; } catch (OperationCanceledException) { }
        monitorCancellation.Dispose();
        monitorCancellation = null;
        monitorTask = null;

        var restartedHookPort = PickPort();
        var restartedToken = Convert.ToHexString(RandomNumberGenerator.GetBytes(24)).ToLowerInvariant();
        var restartedSessionId = Guid.NewGuid();
        await using var restartedReceiver = new PageHookReceiver(restartedHookPort, restartedSessionId,
            events => archive.RecordPageHooksAsync(events), restartedToken);
        restartedReceiver.Start();
        monitorCancellation = new CancellationTokenSource();
        var reattached = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        monitorTask = PageHookInjector.MonitorAsync(debuggingPort, restartedHookPort, restartedToken, status =>
        {
            if (status.ActiveTargetCount > 0 && status.InjectedTargetCount == status.ActiveTargetCount)
                reattached.TrySetResult();
            return Task.CompletedTask;
        }, TimeSpan.FromMilliseconds(250), monitorCancellation.Token);
        await reattached.Task.WaitAsync(TimeSpan.FromSeconds(8));
        var restartedDeadline = DateTime.UtcNow.AddSeconds(5);
        IReadOnlyList<PageHookEvent> restartedEvents = [];
        while (DateTime.UtcNow < restartedDeadline)
        {
            restartedEvents = archive.GetPageHooksBySessions([restartedSessionId]);
            if (restartedEvents.Any(item => item.Function == "hook.installed") &&
                restartedEvents.Any(item => item.Function == "btoa" &&
                                            item.ArgsJson.Contains(marker, StringComparison.Ordinal))) break;
            await Task.Delay(100);
        }
        Require(restartedEvents.Any(item => item.Function == "hook.installed"),
            "采集重启后已打开页面必须切换到新的 Hook 接收端点");
        Require(restartedEvents.Any(item => item.Function == "btoa" &&
                                            item.ArgsJson.Contains(marker, StringComparison.Ordinal)),
            "采集重启后已打开页面的调用必须进入新会话");
    }
    finally
    {
        pageServer?.Close();
        if (monitorCancellation is not null)
        {
            monitorCancellation.Cancel();
            if (monitorTask is not null)
                try { await monitorTask; } catch (OperationCanceledException) { }
            monitorCancellation.Dispose();
        }
        if (browser is not null)
        {
            try { if (!browser.HasExited) browser.Kill(entireProcessTree: true); } catch { /* 测试浏览器可能已退出 */ }
            browser.Dispose();
        }
        if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
    }
}

/// <summary>
/// 一个冒烟套件：名称、定向开关标签、执行体，以及是否进入默认全量运行。
/// 需要外部依赖（真实浏览器等）的套件设 InDefaultRun=false，只能显式指定。
/// </summary>
sealed record SmokeSuite(string Name, string Tag, Func<Task> Run, bool InDefaultRun = true);

/// <summary>冒烟测试用引擎释放器：无论断言成败都优雅关停引擎。</summary>
sealed class ScriptHookEngineDisposer : IDisposable
{
    public ScriptHookEngine? Engine;
    public void Dispose() => Engine?.DisposeAsync().AsTask().GetAwaiter().GetResult();
}

/// <summary>冒烟用证据提供者：取数/搜索返回脚本化文本并记录调用；超大结果用于预算截断测试。</summary>
sealed class FakeAiEvidenceProvider(IReadOnlyList<TrafficRecord> pool) : AiEvidenceProvider
{
    private readonly Lazy<AiPreparedEvidence> _preparedEvidence = new(() => AiEvidencePreparationEngine.Prepare(pool));
    public string? NextFetchResult { get; set; }
    public IReadOnlyList<TrafficRecord> Pool { get; } = pool;
    public AiPreparedEvidence PreparedEvidence => _preparedEvidence.Value;
    public IReadOnlyList<string> EvidenceFileNames { get; } = [];
    public List<int[]> FetchCalls { get; } = [];

    public Task<string> GetTransactionsAsync(int[] ordinals, CancellationToken cancellationToken)
    {
        FetchCalls.Add(ordinals);
        return Task.FromResult(NextFetchResult ?? "{\"transactions\":[{\"url\":\"http://example.test/api/data?sign=owner-secret\"}]}");
    }

    public Task<string> SearchAsync(string keyword, CancellationToken cancellationToken) =>
        Task.FromResult($"[{{\"序号\":2,\"位置\":\"URL\",\"关键字\":\"{keyword}\"}}]");

    public Task<string> GetHooksAsync(string? type, int limit, CancellationToken cancellationToken) =>
        Task.FromResult("[]");

    public Task<string> GetEvidenceFilesAsync(string[] names, CancellationToken cancellationToken) =>
        Task.FromResult("{\"证据文件\":[]}");

    public Task<string> GetTransactionBodyExcerptAsync(
        int ordinal, string direction, string? keyword, int maximumCharacters, CancellationToken cancellationToken) =>
        Task.FromResult($"{{\"ordinal\":{ordinal},\"direction\":\"{direction}\",\"excerpt\":\"fake excerpt\"}}");
}
