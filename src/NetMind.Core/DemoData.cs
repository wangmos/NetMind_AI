namespace NetMind.Core;

public static class DemoData
{
    private static readonly string[] Processes = ["chrome.exe · 12844", "NetMind.Api.exe · 7840", "Code.exe · 9128"];

    public static IReadOnlyList<TrafficRecord> CreateTraffic()
    {
        var now = DateTimeOffset.Now;
        return
        [
            Row(now, 0, "POST", "/api/v2/auth/refresh", 200, 126, 2480, 0, "HTTP/2", "refresh_token=[敏感信息 #01]", "令牌轮换成功，expires_in=3600"),
            Row(now, 2, "GET", "/api/v2/projects?limit=20", 200, 84, 12640, 0, "HTTP/2", "分页查询 limit=20", "返回 18 个项目"),
            Row(now, 5, "POST", "/v1/chat/completions", 200, 842, 18420, 1, "SSE", "model=netmind-reasoner · stream=true", "流式返回 64 个事件"),
            Row(now, 8, "GET", "/api/v2/users/me", 200, 92, 3210, 0, "HTTP/2", "Authorization=[敏感信息 #02]", "用户资料与 7 项权限"),
            Row(now, 12, "POST", "/api/v2/files/upload", 413, 268, 940, 2, "HTTP/1.1", "multipart/form-data · 12.4 MB", "payload_too_large"),
            Row(now, 17, "GET", "/api/v2/analytics/summary", 500, 1240, 1120, 1, "HTTP/2", "range=24h&group=service", "upstream_timeout"),
            Row(now, 21, "OPTIONS", "/api/v2/integrations", 204, 31, 0, 0, "HTTP/2", "CORS 预检", "无响应体"),
            Row(now, 25, "PATCH", "/api/v2/projects/nm-2048", 200, 174, 2680, 0, "HTTP/2", "更新采集策略", "version=42"),
            Row(now, 32, "GET", "/ws/events?workspace=alpha", 101, 48, 0, 0, "WebSocket", "Upgrade: websocket", "协议升级成功"),
            Row(now, 39, "POST", "/grpc.TraceService/Stream", 200, 316, 7480, 1, "gRPC", "4 个 Protobuf envelope", "4 个 Protobuf envelope"),
            Row(now, 44, "GET", "/api/v2/health", 200, 18, 264, 1, "HTTP/1.1", "健康检查", "status=healthy"),
            Row(now, 51, "DELETE", "/api/v2/sessions/expired", 403, 76, 780, 0, "HTTP/2", "清理过期会话", "缺少 sessions:write 权限")
        ];
    }

    public static FindingRecord CreateFinding(TrafficRecord traffic)
    {
        var failing = traffic.StatusCode >= 400;
        var title = failing ? "检测到异常响应链路" : "认证字段在请求链中稳定传播";
        var summary = failing
            ? $"{traffic.Endpoint} 返回 {traffic.StatusCode}。确定性解析器已定位请求与响应证据，建议核对上游限制与权限策略。"
            : "Authorization 字段经过占位符脱敏后，在 3 个相关端点中保持一致；当前没有发现令牌泄漏。";

        return new FindingRecord(
            Guid.NewGuid(),
            title,
            summary,
            failing ? FindingSeverity.High : FindingSeverity.Medium,
            failing ? 94 : 88,
            [
                new EvidenceRecord("入口请求", $"{traffic.Method} {traffic.Endpoint}", traffic.Protocol, 0, traffic.RequestSummary),
                BuildProtocolEvidence(traffic),
                new EvidenceRecord("响应结论", $"状态 {traffic.StatusCode} · {traffic.LatencyMs} ms", "流量存储", 384, traffic.ResponseSummary)
            ]);
    }

    private static EvidenceRecord BuildProtocolEvidence(TrafficRecord traffic)
    {
        if (traffic.Protocol == "HTTPS 隧道（加密）")
            return new EvidenceRecord("加密隧道", "已记录 CONNECT 目标、建连耗时和双向字节数", "代理连接元数据", 0, "TLS 正文保持加密，未进行内容推断");

        var (description, value) = traffic.Protocol switch
        {
            "HTTP/2" => ("已解析 9 字节帧头、标志与流标识", "帧边界和流编号有效"),
            "WebSocket" => ("已解析 FIN、操作码、长度与掩码", "升级连接中的帧结构有效"),
            "SSE" => ("已按空行边界解析流式事件字段", "事件序列与 data 字段有效"),
            "gRPC" => ("已解析压缩标志和 5 字节 envelope 头", "消息长度与载荷边界有效"),
            "DNS" => ("已解析消息头、名称标签与问题字段", "查询名称和类型有效"),
            _ => ("已完成请求行、响应状态与正文边界解析", "HTTP/1.1 消息结构有效")
        };
        return new EvidenceRecord("协议解析", description, $"{traffic.Protocol} 确定性解析器", 128, value);
    }

    public static TrafficRecord CreateLiveRecord(int index)
    {
        var samples = new[]
        {
            ("GET", "/api/v2/runs/active", 200, 72),
            ("POST", "/api/v2/events/batch", 202, 116),
            ("GET", "/api/v2/metrics/live", 200, 44),
            ("POST", "/v1/embeddings", 200, 238),
            ("GET", "/api/v2/policies/effective", 304, 35)
        };
        var sample = samples[index % samples.Length];
        return Row(DateTimeOffset.Now, 0, sample.Item1, sample.Item2, sample.Item3, sample.Item4, 640 + index * 73, index, "HTTP/2", "实时采集请求", "结构化响应已持久化");
    }

    private static TrafficRecord Row(DateTimeOffset now, int secondsAgo, string method, string endpoint, int status,
        int latency, long size, int processIndex, string protocol, string request, string response) =>
        new(Guid.NewGuid(), now.AddSeconds(-secondsAgo), method, endpoint, status, latency, size,
            Processes[processIndex % Processes.Length], protocol, request, response);
}
