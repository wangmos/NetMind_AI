namespace NetMind.Core;

/// <summary>
/// NetMind AI 全局默认值与哨兵常量集中定义。
/// 其中的哨兵词、目录布局文件名与哈希格式是既有工作区持久化的兼容契约，只允许引用，不允许改值；
/// 安全与协议边界常量同样不得放宽。
/// </summary>
public static class NetMindDefaults
{
    // ── 网络默认 ──────────────────────────────────────────────────────────────

    /// <summary>默认监听端口。</summary>
    public const int ListenPort = 8877;

    /// <summary>默认监听回环地址（安全默认值：代理无鉴权，只允许 Loopback，绝不提供 0.0.0.0）。</summary>
    public const string LoopbackAddress = "127.0.0.1";

    /// <summary>默认监听端点，例如 127.0.0.1:8877（供展示与缺省参数使用）。</summary>
    public static readonly string DefaultListenEndpoint = $"{LoopbackAddress}:{ListenPort}";

    /// <summary>CoreHost 就绪输出的机器可读前缀（工作台据此判定捕获后台已监听）。</summary>
    public const string CoreHostReadyMarker = "监听地址：";

    /// <summary>
    /// CoreHost 本次采集会话标识的机器可读前缀。工作台据此把流量视图限定在本次采集，
    /// 使每次「开始采集」都从空列表起步，而不是先加载历史事务。
    /// </summary>
    public const string CoreHostSessionMarker = "会话标识：";

    // ── 哨兵字符串 ────────────────────────────────────────────────────────────

    /// <summary>HTTPS 加密隧道事务的协议标记（正文未解密）。</summary>
    public const string ProtocolHttpsTunnel = "HTTPS 隧道（加密）";

    /// <summary>来源标签：真实代理捕获。</summary>
    public const string SourceRealProxy = "真实代理";

    /// <summary>来源标签：模拟采集。</summary>
    public const string SourceSimulated = "模拟";

    /// <summary>来源标签：演示数据。</summary>
    public const string SourceDemo = "演示";

    /// <summary>来源标签：未知。</summary>
    public const string SourceUnknown = "未知";

    /// <summary>沙箱结果：脚本验证通过（退出码 0）。</summary>
    public const string SandboxVerificationPassed = "验证通过";

    /// <summary>沙箱结果：脚本验证失败（退出码非 0）。</summary>
    public const string SandboxVerificationFailed = "验证失败";

    /// <summary>通用脱敏占位符。</summary>
    public const string RedactedPlaceholder = "[REDACTED]";

    /// <summary>稳定字段传播脱敏占位符前缀，完整形如 [敏感信息 #a1b2c3d4]。</summary>
    public const string SensitivePlaceholderPrefix = "[敏感信息 #";

    /// <summary>自定义采集浏览器可执行文件的环境变量名。</summary>
    public const string BrowserEnvironmentVariable = "NETMIND_BROWSER";

    /// <summary>会话状态词：进行中。</summary>
    public const string SessionStateRunning = "运行中";

    /// <summary>会话状态词：正常结束。</summary>
    public const string SessionStateCompleted = "已完成";

    /// <summary>会话模式词：模拟采集。</summary>
    public const string SessionModeSimulation = "模拟采集";

    /// <summary>会话模式词：HTTP 显式代理（不解密 HTTPS）。</summary>
    public const string SessionModeExplicitProxy = "HTTP 显式代理";

    /// <summary>会话模式词：HTTP/HTTPS 解密代理（TLS 正文抓取）。</summary>
    public const string SessionModeDecryptProxy = "HTTP/HTTPS 解密代理";

    /// <summary>会话模式词：底层静默抓包（WinDivert 透明捕获，不依赖代理配置）。</summary>
    public const string SessionModeSilentCapture = "底层静默抓包";

    /// <summary>来源标签：静默抓包。</summary>
    public const string SourceSilentCapture = "静默抓包";

    /// <summary>静默抓包中 TLS 加密隧道的协议标记（正文未解密）。</summary>
    public const string ProtocolSilentTlsTunnel = "TLS 隧道（加密）";

    /// <summary>静默抓包中解密后重组出的 HTTP/2 事务的协议标记。</summary>
    public const string ProtocolSilentHttp2 = "HTTP/2（已解密）";

    /// <summary>静默抓包中 QUIC（UDP 443）隧道与流的协议标记。</summary>
    public const string ProtocolSilentQuic = "QUIC（已解密）";

    /// <summary>静默抓包中解密后重组出的 HTTP/3 事务的协议标记。</summary>
    public const string ProtocolSilentHttp3 = "HTTP/3（已解密）";

    /// <summary>静默抓包默认过滤表达式：全部 TCP + QUIC 常用端口（443）的 UDP。</summary>
    /// <remarks>WinDivert 2.2 过滤语言只支持字段比较（如 udp.DstPort == 443），
    /// 不存在 dstport/srcport/port 等原语：写错时 WinDivertOpen 返回无效句柄（Win32 错误 87）。</remarks>
    public const string SilentDefaultFilter = "tcp or (udp and (udp.DstPort == 443 or udp.SrcPort == 443))";

    // ── 存储布局（工作区目录契约，改值将导致既有 metadata.db/blobs/audit.jsonl 不可读） ──

    /// <summary>SQLite 元数据数据库文件名。</summary>
    public const string MetadataDatabaseFileName = "metadata.db";

    /// <summary>内容寻址正文目录名。</summary>
    public const string BlobsDirectoryName = "blobs";

    /// <summary>日志目录名。</summary>
    public const string LogsDirectoryName = "logs";

    /// <summary>审计日志文件名。</summary>
    public const string AuditLogFileName = "audit.jsonl";

    /// <summary>工作区清单文件名。</summary>
    public const string WorkspaceManifestFileName = "workspace.json";

    /// <summary>当前工作区的数据保留与容量策略文件名。</summary>
    public const string WorkspaceDataPolicyFileName = "data-policy.json";

    /// <summary>工作区备份 ZIP 的格式清单文件名。</summary>
    public const string WorkspaceBackupManifestFileName = "netmind-backup.json";

    /// <summary>AI 分析历史目录名。</summary>
    public const string AiHistoryDirectoryName = "ai-history";

    /// <summary>脚本沙箱只读样例文件名。</summary>
    public const string SandboxFixtureFileName = "fixture.json";

    /// <summary>SHA-256 十六进制哈希长度。</summary>
    public const int Sha256HexLength = 64;

    // ── 安全与协议边界（不得放宽） ────────────────────────────────────────────

    /// <summary>代理单条事务 HTTP 头部上限（64 KB）。</summary>
    public const int ProxyMaximumHeaderBytes = 64 * 1024;

    /// <summary>代理监听 TCP backlog。</summary>
    public const int ProxyListenBacklog = 128;

    /// <summary>脚本沙箱脚本体积上限（128 KB）。</summary>
    public const int SandboxMaximumScriptBytes = 128 * 1024;

    /// <summary>模型网关单次响应上限默认值（32 MB）：可在 AI 配置页下拉调整（8–128 MB）。</summary>
    public const int AiMaximumResponseBytes = 32 * 1024 * 1024;

    /// <summary>模型网关单次响应上限可配置下限（8 MB）。</summary>
    public const int AiMinimumResponseBytes = 8 * 1024 * 1024;

    /// <summary>模型网关单次响应上限可配置上限（128 MB）。</summary>
    public const int AiConfigurableMaximumResponseBytes = 128 * 1024 * 1024;

    /// <summary>模型名称最大字符数。</summary>
    public const int AiModelNameMaximumCharacters = 128;

    /// <summary>AI 输出令牌下限。</summary>
    public const int AiMinimumOutputTokens = 256;

    /// <summary>AI 输出令牌上限（64k）。</summary>
    public const int AiMaximumOutputTokens = 65_536;

    /// <summary>单次 AI 分析证据事务条数的宽松安全上限（原 30 已取消；真正的边界是完整上下文总体积上限，此值仅防结构性滥用）。</summary>
    public const int AiMaximumEvidenceTransactions = 1000;

    /// <summary>AI 完整上下文单条事务正文读取上限（8 MB），超过截断并显式标记；
    /// 放宽到 8 MB 让未压缩的大 JS 源文件与大型 JSON 响应完整进入会话，支撑参数溯源中的 JS 计算还原。</summary>
    public const int AiMaximumBodyBytesPerTransaction = 8 * 1024 * 1024;

    /// <summary>AI 完整上下文总体积上限（16 MB），超过拒绝请求而非静默裁剪。</summary>
    public const int AiMaximumFullContextBytes = 16 * 1024 * 1024;

    /// <summary>用户自定义 AI 提问的最大字符数。</summary>
    public const int AiMaximumPromptCharacters = 8000;

    /// <summary>AI 模型请求默认超时（秒）。</summary>
    public const int AiDefaultRequestTimeoutSeconds = 90;

    /// <summary>AI 模型请求超时下限（秒）。</summary>
    public const int AiMinimumRequestTimeoutSeconds = 10;

    /// <summary>AI 模型请求超时上限（秒）：大输出与深度推理耗时较长，预留 10 分钟。</summary>
    public const int AiMaximumRequestTimeoutSeconds = 600;

    /// <summary>单次 AI 分析可追加的附加文件数量上限。</summary>
    public const int AiMaximumAttachedFiles = 10;

    // ── AI 对话式分析（摘要先行 + tool_call 按需取数） ────────────────────────

    /// <summary>AI 对话会话目录名（与旧单轮历史 ai-history 独立，旧历史仅保留读取）。</summary>
    public const string AiConversationsDirectoryName = "ai-conversations";

    /// <summary>会话首轮发送给模型的证据池摘要行数上限。</summary>
    public const int AiConversationSummaryMaximumLines = 1000;

    /// <summary>
    /// 首轮事务摘要的字节兜底上限（64 KB）。首轮消息会在本轮每次取数迭代和之后每一轮追问中重发，
    /// 是整个会话最贵的固定成本；行数上限管不住单行长度，这里按实际体积再兜一道，超限显式标注省略条数。
    /// </summary>
    public const int AiConversationSummaryMaximumBytes = 64 * 1024;

    /// <summary>
    /// 摘要中静态资源（图片/CSS/字体/音视频）折叠为聚合行的触发条数。
    /// 这些正文本来就被 <c>AiFullContextBuilder</c> 判定为非分析相关、从不发给模型，
    /// 却按完整行占据首轮摘要；折叠后仍逐一列出全部 #序号，不丢证据。
    /// </summary>
    public const int AiSummaryStaticAssetFoldThreshold = 3;

    /// <summary>get_evidence_overview 单次返回的端点组、异常与关联候选条数上限；超出部分显式标注省略数量。</summary>
    public const int AiOverviewMaximumEndpointGroups = 24;
    public const int AiOverviewMaximumAnomalies = 40;
    public const int AiOverviewMaximumRelations = 40;

    /// <summary>get_transactions 单次只取少量代表事务；更多样本应分批规划，避免一次塞入大量重复头与正文。</summary>
    public const int AiToolMaximumOrdinalsPerFetch = 8;

    /// <summary>单轮全部工具结果预算（128 KB）；超限截断。原始结果仅存在当前轮，不进入长期历史。</summary>
    public const int AiToolFetchBudgetBytesPerTurn = 128 * 1024;

    /// <summary>get_transactions 中单个请求/响应正文的预览上限（24 KB）；大型正文改用关键词片段工具。</summary>
    public const int AiToolMaximumBodyBytesPerTransaction = 24 * 1024;

    /// <summary>正文片段工具默认与最大返回字符数。</summary>
    public const int AiToolBodyExcerptDefaultCharacters = 6000;
    public const int AiToolBodyExcerptMaximumCharacters = 24000;

    /// <summary>单轮工具取数回环的执行上限；超出后用已有证据收尾，防累计输入令牌指数式增长。</summary>
    public const int AiToolLoopMaximumIterations = 4;

    /// <summary>会话消息 JSON 累计体积上限（16 MB 网关上限之下留余量），超限折叠最早的取数结果。</summary>
    public const int AiConversationMaximumHistoryBytes = 14 * 1024 * 1024;

    /// <summary>会话体积保护折叠早期取数结果后的占位文本。</summary>
    public const string AiToolResultFoldedPlaceholder = "[早期取数结果已折叠]";

    /// <summary>AI 附加文件单文件大小上限（1 MB），超限文件拒绝加入。</summary>
    public const int AiMaximumAttachedFileBytes = 1_048_576;

    /// <summary>SQLite busy_timeout（毫秒）。</summary>
    public const int SqliteBusyTimeoutMilliseconds = 5000;

    // ── 页内 JS Hook（采集浏览器注入 + loopback 上报） ────────────────────

    /// <summary>页内 Hook 事件单条参数上限（8 KB），超限入库前截断。</summary>
    public const int PageHookMaximumArgsBytes = 8 * 1024;

    /// <summary>page_hooks 表总条数上限，超限删除最旧。</summary>
    public const int PageHookMaximumRows = 20000;

    /// <summary>页内 Hook 单批上报的入库条数上限，防单次 POST 病理性爆量。</summary>
    public const int PageHookMaximumEventsPerBatch = 500;

    /// <summary>页内 Hook 上报接收请求体上限（4 MB），超限拒绝。</summary>
    public const int PageHookMaximumRequestBodyBytes = 4 * 1024 * 1024;

    /// <summary>审计事件名：页内 Hook 注入成功。</summary>
    public const string AuditEventPageHookInjected = "hooks.page-injected";

    /// <summary>审计事件名：页内 Hook 事件接收（计数汇总，不逐条审计）。</summary>
    public const string AuditEventPageHookReceived = "hooks.page-received";

    /// <summary>工作区 TLS 解密叶子证书缓存容量。</summary>
    public const int CertificateCacheCapacity = 256;

    /// <summary>TCP 连接进程解析缓存容量。</summary>
    public const int ProcessResolverCacheCapacity = 4096;

    /// <summary>TCP 连接进程解析缓存存活时间（秒）。</summary>
    public const int ProcessResolverCacheTtlSeconds = 2;

    /// <summary>解压后的 HTTP 正文上限：防止压缩炸弹在结算阶段放大内存。</summary>
    public const int MaximumDecompressedBodyBytes = 16 * 1024 * 1024;

    /// <summary>正文 Blob 预览默认读取上限（256 KB）。</summary>
    public const int BlobPreviewDefaultBytes = 256 * 1024;

    /// <summary>正文 Blob 预览读取上限（4 MB）。</summary>
    public const int BlobPreviewMaximumBytes = 4 * 1024 * 1024;

    // ── 底层静默抓包（WinDivert 透明捕获） ────────────────────────────────

    /// <summary>WinDivert 用户态库文件名。</summary>
    public const string WinDivertLibraryFileName = "WinDivert.dll";

    /// <summary>WinDivert 内核驱动文件名（随库同目录部署，或由已安装的驱动服务加载）。</summary>
    public const string WinDivertDriverFileName = "WinDivert64.sys";

    /// <summary>静默抓包就绪信号文件名（位于 %LocalAppData%\NetMind；提升权限后无法重定向 stdout，改用文件信号）。</summary>
    public const string SilentReadyFileName = "silent-ready.json";

    /// <summary>静默抓包停止信号文件名（工作台写入后采集后台优雅停止）。</summary>
    public const string SilentStopFileName = "silent-stop.signal";

    /// <summary>静默抓包并发 TCP 流表上限，超限淘汰最旧流。</summary>
    public const int SilentMaximumFlows = 4096;

    /// <summary>静默抓包流空闲超时（秒），超限结算并淘汰。</summary>
    public const int SilentFlowIdleTimeoutSeconds = 120;

    /// <summary>静默抓包单方向乱序缓冲上限（1 MB），超限标记该流正文断裂。</summary>
    public const int SilentMaximumReassemblyBufferBytes = 1024 * 1024;

    /// <summary>静默抓包 HTTP 头部上限（64 KB）。</summary>
    public const int SilentMaximumHeaderBytes = 64 * 1024;

    /// <summary>静默抓包单条事务正文上限（4 MB），超限截断并标记。</summary>
    public const int SilentMaximumBodyBytes = 4 * 1024 * 1024;

    /// <summary>静默抓包停止信号轮询间隔（毫秒）。</summary>
    public const int SilentStopPollIntervalMilliseconds = 500;

    /// <summary>SSLKEYLOGFILE 密钥日志相对工作区的路径：采集浏览器写入、采集后台读取，两端必须一致。</summary>
    public const string SilentKeyLogRelativePath = "keys/sslkeylog.txt";

    /// <summary>Chromium/Firefox 会话密钥导出环境变量名（NSS Key Log 格式）。</summary>
    public const string SslKeyLogFileEnvironmentVariable = "SSLKEYLOGFILE";

    /// <summary>审计事件名：静默抓包启动失败。</summary>
    public const string AuditEventSilentCaptureFailed = "silent-capture.start-failed";

    // ── JSON 与正文预览展示边界 ───────────────────────────────────────────────

    /// <summary>JSON 树视图可建树的正文大小上限（512 KB），超过则降级为着色扁平文本，不建树。</summary>
    public const int JsonTreeMaximumBytes = 512 * 1024;

    /// <summary>AI 输入数据（完整上下文）建树上限：节点惰性物化且字符串值截断展示，可放宽到上下文体积上限 16 MB。</summary>
    public const int JsonTreeMaximumBytesForAiContext = 16 * 1024 * 1024;

    /// <summary>单个 JSON 容器节点的子项实例化上限，超出只物化前 N 项并追加“其余 N 项已省略”提示节点。</summary>
    public const int JsonTreeMaximumChildrenPerNode = 500;

    /// <summary>JSON 树默认展开深度，防止大 JSON 首屏全量展开。</summary>
    public const int JsonTreeDefaultExpandDepth = 2;

    /// <summary>按正文 Blob SHA-256 缓存已解析 JSON 树的容量。</summary>
    public const int JsonParseCacheCapacity = 4;

    /// <summary>JSON 单值展示字符截断上限，超出截断并追加中文省略标记。</summary>
    public const int JsonPreviewMaximumValueCharacters = 2048;

    /// <summary>字符串值尝试按内嵌 JSON 展开解析的长度上限，超过直接按普通文本截断展示，避免超长字符串解析浪费。</summary>
    public const int JsonPreviewEmbeddedJsonMaximumCharacters = 8 * 1024 * 1024;

    /// <summary>内嵌 JSON 字符串展开的最大嵌套深度（含顶层），超过后按普通字符串截断展示，防病理嵌套。</summary>
    public const int JsonPreviewMaximumEmbeddedJsonDepth = 6;

    /// <summary>二进制正文十六进制预览的字节上限。</summary>
    public const int BlobHexPreviewBytes = 512;

    // ── 工作台运行默认值 ──────────────────────────────────────────────────────

    /// <summary>流量列表默认刷新间隔（毫秒）。</summary>
    public const int DefaultRefreshIntervalMilliseconds = 1500;

    /// <summary>流量列表默认窗口条数。</summary>
    public const int DefaultTrafficWindowCount = 200;

    /// <summary>采集浏览器优雅关闭等待时间（毫秒），超时后强制结束进程树。</summary>
    public const int CaptureBrowserCloseTimeoutMilliseconds = 3000;

    /// <summary>会话列表默认窗口条数。</summary>
    public const int DefaultSessionWindowCount = 100;

    /// <summary>
    /// AI 证据池的系统上限。首轮只发摘要，正文由工具按需批量读取，因此 200 条不会直接放大正文上下文；
    /// 单轮取数预算与会话历史折叠继续承担成本保护。
    /// </summary>
    public const int DefaultAiEvidenceMaximumTransactions = 200;

    /// <summary>AI 证据链自动补全的候选扫描条数：窗口内候选不足时，从最近持久化事务中补齐同主机上游证据。</summary>
    public const int AiEvidenceCompletionScanLimit = 2000;

    // ── 系统代理自动化（无感抓包） ────────────────────────────────────────────

    /// <summary>系统代理接管哨兵文件名，保存在与 settings.json 相同的 %LocalAppData%\NetMind 目录。</summary>
    public const string SystemProxySentinelFileName = "system-proxy-sentinel.json";

    /// <summary>接管系统代理时的默认绕过列表：内网/本机地址直连，不经代理。</summary>
    public const string SystemProxyLocalBypass = "<local>";

    /// <summary>审计事件名：系统代理已接管。</summary>
    public const string AuditEventSystemProxyApplied = "system-proxy.applied";

    /// <summary>审计事件名：系统代理已还原。</summary>
    public const string AuditEventSystemProxyRestored = "system-proxy.restored";

    /// <summary>审计事件名：系统代理还原失败。</summary>
    public const string AuditEventSystemProxyRestoreFailed = "system-proxy.restore-failed";

    /// <summary>Win32 系统代理事实来源注册表子键（HKCU 根下）。</summary>
    public const string SystemProxyRegistrySubKey = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

    /// <summary>系统代理启用开关注册表值名（DWORD，1 启用 / 0 禁用）。</summary>
    public const string SystemProxyRegistryEnableValueName = "ProxyEnable";

    /// <summary>系统代理地址注册表值名（REG_SZ，如 127.0.0.1:8877）。</summary>
    public const string SystemProxyRegistryServerValueName = "ProxyServer";

    /// <summary>系统代理绕过列表注册表值名（REG_SZ，如 &lt;local&gt;）。</summary>
    public const string SystemProxyRegistryOverrideValueName = "ProxyOverride";

    /// <summary>审计事件名：工作台设置已更新。</summary>
    public const string AuditEventSettingsUpdated = "settings.updated";

    // ── 脚本钩子系统（请求关键路径钩子的长驻 Python 工作进程） ────────────────

    /// <summary>工作区内用户钩子脚本目录名。</summary>
    public const string ScriptsDirectoryName = "scripts";

    /// <summary>钩子工作进程的键值数据目录名（脚本经 store 接口的持久化落盘处）。</summary>
    public const string HookDataDirectoryName = "data";

    /// <summary>钩子系统配置文件名。</summary>
    public const string HookConfigFileName = "hook-config.json";

    /// <summary>采集后台写入、工作台只读的脚本 Hook 运行状态文件名。</summary>
    public const string HookStatusFileName = "hook-status.json";

    /// <summary>工作台保存钩子脚本的默认文件名（落在工作区 scripts 目录，配置中 scriptPath 引用该相对文件名）。</summary>
    public const string HookScriptFileName = "hook-script.py";

    /// <summary>审计事件名：工作台保存钩子配置。</summary>
    public const string AuditEventHooksConfigSaved = "hooks.config-saved";

    /// <summary>钩子事件信封协议版本号。</summary>
    public const int HookEventSchemaVersion = 1;

    /// <summary>钩子信封序列化后每封固定开销的保守上界（字节）：JSON 字段名、引号、逗号等结构性开销，供队列字节记账避免系统性低估。</summary>
    public const int HookEnvelopeFixedOverheadBytes = 512;

    /// <summary>钩子事件入队队列的条数容量。</summary>
    public const int HookEventQueueCapacity = 1024;

    /// <summary>钩子事件入队队列的累计字节上限（64 MB），超限丢弃最旧事件。</summary>
    public const long HookEventQueueMaximumBytes = 64L * 1024 * 1024;

    /// <summary>投递给钩子工作进程的正文预览字节上限（256 KB），超过则截断并标记。</summary>
    public const int HookBodyPreviewBytes = 256 * 1024;

    /// <summary>钩子工作进程处理单个事件的看门狗超时（毫秒），超时记错并继续下一事件。</summary>
    public const int HookEventTimeoutMilliseconds = 200;

    /// <summary>钩子工作进程心跳上报间隔（毫秒）。</summary>
    public const int HookHeartbeatIntervalMilliseconds = 5000;

    /// <summary>优雅关停时清队 flush 的总时限（毫秒），超时放弃剩余事件直接发 shutdown。</summary>
    public const int HookShutdownFlushTimeoutMilliseconds = 5000;

    /// <summary>优雅关停时清队 flush 的事件条数上限，超限放弃剩余事件直接发 shutdown。</summary>
    public const int HookShutdownFlushMaximumEvents = 128;

    /// <summary>优雅关停收尾时等待单个工作线程任务退出的时限（毫秒），压缩整体关停耗时。</summary>
    public const int HookShutdownJoinTimeoutMilliseconds = 1000;

    /// <summary>连续丢失的心跳次数达到该值即判定钩子工作进程失联。</summary>
    public const int HookHeartbeatMaximumMisses = 3;

    /// <summary>钩子工作进程崩溃重启计数的滑动窗口（秒）。</summary>
    public const int HookRestartWindowSeconds = 60;

    /// <summary>重启滑动窗口内允许的最大重启次数，超过即停用钩子。</summary>
    public const int HookRestartMaximumPerWindow = 3;

    /// <summary>钩子数据目录单文件字节上限（1 MB），超限抛中文 ValueError。</summary>
    public const long HookDataSingleFileBytes = 1024L * 1024;

    /// <summary>钩子数据目录全部文件累计字节上限（64 MB），超限抛中文 ValueError。</summary>
    public const long HookDataTotalBytes = 64L * 1024 * 1024;

    /// <summary>钩子工作进程单条 finding/error 输出的字节上限（4 KB），超限截断。</summary>
    public const int HookFindingMaximumBytes = 4 * 1024;

    /// <summary>钩子工作进程（长驻 Python）的作业对象内存上限（256 MB）。</summary>
    public const long HookWorkerMaximumMemoryBytes = 256L * 1024 * 1024;

    /// <summary>审计事件名：钩子系统已启用。</summary>
    public const string AuditEventHooksEnabled = "hooks.enabled";

    /// <summary>审计事件名：钩子工作进程已启动。</summary>
    public const string AuditEventHooksStarted = "hooks.started";

    /// <summary>审计事件名：钩子工作进程崩溃。</summary>
    public const string AuditEventHooksCrashed = "hooks.crashed";

    /// <summary>审计事件名：钩子系统已停用。</summary>
    public const string AuditEventHooksDisabled = "hooks.disabled";

    /// <summary>审计事件名：钩子脚本产出的一条观察结论（finding）经采集后台落盘审计。</summary>
    public const string AuditEventHooksFinding = "hooks.finding";

    /// <summary>采集后台周期消费钩子观察结论（finding）并写入审计的间隔（毫秒）。</summary>
    public const int HookFindingDrainIntervalMilliseconds = 2000;

    /// <summary>采集后台刷新脚本 Hook 运行状态文件的间隔。</summary>
    public const int HookStatusPublishIntervalMilliseconds = 1000;

    /// <summary>单次周期消费写入审计的 finding 条数上限，防止异常爆量时单批审计过大。</summary>
    public const int HookFindingDrainBatchMaximum = 128;

    // ── 宿主布局（工作台设置目录与沙箱宿主相对布局） ─────────────────────────

    /// <summary>
    /// 审计日志写入锁的等待上限。串行化只覆盖一次「打开-追加-关闭」，正常情况是亚毫秒级；
    /// 取 5 秒是给磁盘卡顿和跨进程排队留余量，超时宁可显式抛错也不静默丢审计。
    /// </summary>
    public const int AuditAppendLockTimeoutMilliseconds = 5000;

    /// <summary>工作台用户设置目录名（%LocalAppData% 下，settings.json、哨兵与工作区根所在目录）。</summary>
    public const string SettingsDirectoryName = "NetMind";

    /// <summary>工作台设置文件名（位于设置目录内）。</summary>
    public const string WorkbenchSettingsFileName = "settings.json";

    /// <summary>脚本沙箱宿主相对布局目录名（生产布局为可执行文件同级 SandboxHost 目录）。</summary>
    public const string SandboxHostDirectoryName = "SandboxHost";

    /// <summary>脚本沙箱宿主可执行文件名。</summary>
    public const string SandboxHostExecutableName = "NetMind.SandboxHost.exe";

    /// <summary>脚本沙箱宿主程序集文件名（经 dotnet 命令运行时使用）。</summary>
    public const string SandboxHostAssemblyName = "NetMind.SandboxHost.dll";

    /// <summary>dotnet 命令名（宿主仅有程序集时的启动命令）。</summary>
    public const string DotnetCommandName = "dotnet";
}
