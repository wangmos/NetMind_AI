using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;

namespace NetMind.Core;

public enum CaptureHealthLevel
{
    Passed,
    Information,
    Warning,
    Failed
}

public sealed record CaptureHealthItem(string Name, CaptureHealthLevel Level, string Summary, string Detail = "");

public sealed record CaptureHealthContext(
    string WorkspacePath,
    bool Capturing,
    bool SilentCapture,
    bool CaptureHostAlive,
    int ProxyPort,
    int HookReceiverPort,
    bool BrowserAlive,
    int BrowserDebuggingPort,
    bool TlsInspectionEnabled,
    PageHookMonitorStatus? PageHookStatus,
    DateTimeOffset? PageHookStatusAt);

public sealed record CaptureHealthReport(DateTimeOffset CheckedAt, CaptureHealthLevel OverallLevel,
    IReadOnlyList<CaptureHealthItem> Items)
{
    public string ToPlainText()
    {
        var builder = new StringBuilder();
        builder.AppendLine($"采集自检 · {CheckedAt.ToLocalTime():yyyy-MM-dd HH:mm:ss}");
        builder.AppendLine($"结论：{LevelText(OverallLevel)}");
        builder.AppendLine();
        foreach (var item in Items)
        {
            builder.Append('[').Append(LevelText(item.Level)).Append("] ").Append(item.Name).Append("：").AppendLine(item.Summary);
            if (!string.IsNullOrWhiteSpace(item.Detail)) builder.Append("    ").AppendLine(item.Detail);
        }
        return builder.ToString().TrimEnd();
    }

    private static string LevelText(CaptureHealthLevel level) => level switch
    {
        CaptureHealthLevel.Passed => "通过",
        CaptureHealthLevel.Information => "信息",
        CaptureHealthLevel.Warning => "注意",
        _ => "失败"
    };
}

/// <summary>
/// 采集链路只读自检：核对宿主进程、回环监听、Hook 接收器、浏览器 CDP、页面/Worker 挂载、
/// TLS 信任与最近入库证据。自检不会创建流量、修改代理或变更证书。
/// </summary>
public static class CaptureHealthChecker
{
    public static async Task<CaptureHealthReport> RunAsync(CaptureHealthContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(context.WorkspacePath);
        var checkedAt = DateTimeOffset.UtcNow;
        var items = new List<CaptureHealthItem>();

        if (!context.Capturing)
        {
            items.Add(new CaptureHealthItem("采集宿主", CaptureHealthLevel.Information, "当前未开始采集",
                "开始采集后可进一步核对监听端口、Hook 接收端与实时入库。"));
        }
        else if (!context.CaptureHostAlive)
        {
            items.Add(new CaptureHealthItem("采集宿主", CaptureHealthLevel.Failed, "界面处于采集中，但后台进程已退出"));
        }
        else
        {
            items.Add(new CaptureHealthItem("采集宿主", CaptureHealthLevel.Passed,
                context.SilentCapture ? "WinDivert 静默采集后台正在运行" : "代理采集后台正在运行"));
        }

        if (context.Capturing && !context.SilentCapture)
        {
            var proxyReachable = await CanConnectLoopbackAsync(context.ProxyPort, cancellationToken);
            items.Add(new CaptureHealthItem("代理监听", proxyReachable ? CaptureHealthLevel.Passed : CaptureHealthLevel.Failed,
                proxyReachable ? $"127.0.0.1:{context.ProxyPort} 可连接" : $"127.0.0.1:{context.ProxyPort} 不可连接",
                proxyReachable ? "" : "检查监听端口占用、CoreHost 启动状态与采集方式设置。"));
        }
        else if (context.SilentCapture)
        {
            items.Add(new CaptureHealthItem("代理监听", CaptureHealthLevel.Information, "静默采集不使用显式代理端口"));
        }

        if (context.Capturing)
        {
            var receiverReachable = await CanConnectLoopbackAsync(context.HookReceiverPort, cancellationToken);
            items.Add(new CaptureHealthItem("Hook 接收端", receiverReachable ? CaptureHealthLevel.Passed : CaptureHealthLevel.Failed,
                receiverReachable ? $"127.0.0.1:{context.HookReceiverPort} 可连接" : "本次会话的 Hook 接收端不可连接",
                receiverReachable ? "" : "页内调用将无法上报；网络流量采集仍可独立工作。"));
        }

        if (!context.BrowserAlive)
        {
            items.Add(new CaptureHealthItem("采集浏览器", CaptureHealthLevel.Information, "未打开采集浏览器",
                "手动代理流量仍可采集；页内 Hook 需要从“打开采集浏览器”启动浏览器。"));
        }
        else
        {
            var cdpReachable = await CanReadCdpVersionAsync(context.BrowserDebuggingPort, cancellationToken);
            items.Add(new CaptureHealthItem("浏览器 CDP", cdpReachable ? CaptureHealthLevel.Passed : CaptureHealthLevel.Failed,
                cdpReachable ? $"调试端口 {context.BrowserDebuggingPort} 可用" : $"调试端口 {context.BrowserDebuggingPort} 不可用"));
            AppendPageHookStatus(items, context, checkedAt, cdpReachable);
        }

        AppendTlsStatus(items, context);
        AppendWorkspaceEvidence(items, context, checkedAt);

        var overall = items.Any(item => item.Level == CaptureHealthLevel.Failed)
            ? CaptureHealthLevel.Failed
            : items.Any(item => item.Level == CaptureHealthLevel.Warning)
                ? CaptureHealthLevel.Warning
                : CaptureHealthLevel.Passed;
        return new CaptureHealthReport(checkedAt, overall, items);
    }

    private static void AppendPageHookStatus(List<CaptureHealthItem> items, CaptureHealthContext context,
        DateTimeOffset checkedAt, bool cdpReachable)
    {
        if (!cdpReachable) return;
        var status = context.PageHookStatus;
        if (status is null || context.PageHookStatusAt is null || checkedAt - context.PageHookStatusAt > TimeSpan.FromSeconds(5))
        {
            items.Add(new CaptureHealthItem("页面与 Worker Hook", CaptureHealthLevel.Warning, "尚未收到新鲜的挂载状态",
                "确认已开始采集，并等待浏览器页面完成加载。"));
            return;
        }
        if (status.ActiveTargetCount == 0)
        {
            items.Add(new CaptureHealthItem("页面与 Worker Hook", CaptureHealthLevel.Warning, "浏览器可达，但尚未发现可挂载目标"));
            return;
        }
        var level = status.InjectedTargetCount == status.ActiveTargetCount
            ? CaptureHealthLevel.Passed
            : status.InjectedTargetCount > 0 ? CaptureHealthLevel.Warning : CaptureHealthLevel.Failed;
        var summary = $"目标 {status.InjectedTargetCount}/{status.ActiveTargetCount} 已挂载";
        if (status.WorkerTargetCount > 0)
            summary += $" · Worker {status.InjectedWorkerTargetCount}/{status.WorkerTargetCount}";
        items.Add(new CaptureHealthItem("页面与 Worker Hook", level, summary, status.WorkerMonitorError));
    }

    private static void AppendTlsStatus(List<CaptureHealthItem> items, CaptureHealthContext context)
    {
        if (!context.TlsInspectionEnabled)
        {
            items.Add(new CaptureHealthItem("HTTPS 正文", CaptureHealthLevel.Information, "TLS 解密未启用",
                "仍会记录 CONNECT/隧道元数据；需要请求与响应正文时再启用工作区 CA。"));
            return;
        }
        try
        {
            using var authority = new WorkspaceCertificateAuthority(context.WorkspacePath);
            var trusted = authority.IsEnabledAndTrusted();
            items.Add(new CaptureHealthItem("HTTPS 正文", trusted ? CaptureHealthLevel.Passed : CaptureHealthLevel.Failed,
                trusted ? "工作区 CA 已启用并受当前用户信任" : "界面标记已启用，但工作区 CA 不受信任"));
        }
        catch (Exception exception)
        {
            items.Add(new CaptureHealthItem("HTTPS 正文", CaptureHealthLevel.Failed, "无法核对工作区 CA", exception.Message));
        }
    }

    private static void AppendWorkspaceEvidence(List<CaptureHealthItem> items, CaptureHealthContext context,
        DateTimeOffset checkedAt)
    {
        try
        {
            using var archive = new TrafficArchive(context.WorkspacePath);
            var traffic = archive.GetRecentTraffic(1).FirstOrDefault();
            var hook = archive.GetPageHooks(limit: 1).FirstOrDefault();
            if (traffic is null)
            {
                items.Add(new CaptureHealthItem("流量入库", context.Capturing ? CaptureHealthLevel.Warning : CaptureHealthLevel.Information,
                    "当前工作区还没有流量记录"));
            }
            else
            {
                var age = checkedAt - traffic.Traffic.Timestamp;
                items.Add(new CaptureHealthItem("流量入库",
                    context.Capturing && age > TimeSpan.FromMinutes(5) ? CaptureHealthLevel.Warning : CaptureHealthLevel.Passed,
                    $"最近事务：{FormatAge(age)} · {traffic.Traffic.Method} {traffic.Traffic.Endpoint}"));
            }
            if (hook is null)
            {
                items.Add(new CaptureHealthItem("Hook 入库", context.BrowserAlive ? CaptureHealthLevel.Warning : CaptureHealthLevel.Information,
                    "当前工作区还没有页内 Hook 事件"));
            }
            else
            {
                var age = checkedAt - hook.Timestamp;
                items.Add(new CaptureHealthItem("Hook 入库",
                    context.BrowserAlive && age > TimeSpan.FromMinutes(5) ? CaptureHealthLevel.Warning : CaptureHealthLevel.Passed,
                    $"最近事件：{FormatAge(age)} · {hook.Function}"));
            }
        }
        catch (Exception exception)
        {
            items.Add(new CaptureHealthItem("工作区数据库", CaptureHealthLevel.Failed, "无法读取采集证据", exception.Message));
        }
    }

    private static async Task<bool> CanConnectLoopbackAsync(int port, CancellationToken cancellationToken)
    {
        if (port is < 1 or > 65535) return false;
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(1.5));
            using var client = new TcpClient(AddressFamily.InterNetwork);
            await client.ConnectAsync(IPAddress.Loopback, port, timeout.Token);
            return client.Connected;
        }
        catch (Exception exception) when (exception is SocketException or OperationCanceledException) { return false; }
    }

    private static async Task<bool> CanReadCdpVersionAsync(int port, CancellationToken cancellationToken)
    {
        if (port is < 1 or > 65535) return false;
        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(2) };
            var json = await http.GetStringAsync($"http://{NetMindDefaults.LoopbackAddress}:{port}/json/version", cancellationToken);
            using var document = JsonDocument.Parse(json);
            return document.RootElement.TryGetProperty("webSocketDebuggerUrl", out var socket) &&
                   socket.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(socket.GetString());
        }
        catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException or JsonException) { return false; }
    }

    private static string FormatAge(TimeSpan age)
    {
        if (age < TimeSpan.Zero) age = TimeSpan.Zero;
        if (age < TimeSpan.FromSeconds(60)) return $"{Math.Max(0, (int)age.TotalSeconds)} 秒前";
        if (age < TimeSpan.FromHours(1)) return $"{(int)age.TotalMinutes} 分钟前";
        if (age < TimeSpan.FromDays(1)) return $"{(int)age.TotalHours} 小时前";
        return $"{(int)age.TotalDays} 天前";
    }
}
