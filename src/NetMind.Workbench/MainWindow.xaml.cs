using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using Microsoft.Win32;
using NetMind.Core;
using static NetMind.Core.NetMindDefaults;

namespace NetMind.Workbench;

public partial class MainWindow : Window, INotifyPropertyChanged
{
    private static readonly Brush Accent = new SolidColorBrush(Color.FromRgb(121, 184, 179));
    private static readonly Brush Green = new SolidColorBrush(Color.FromRgb(130, 184, 155));
    private static readonly Brush Amber = new SolidColorBrush(Color.FromRgb(199, 170, 114));
    private static readonly Brush Red = new SolidColorBrush(Color.FromRgb(216, 134, 143));
    private static readonly Brush Muted = new SolidColorBrush(Color.FromRgb(135, 152, 164));
    private static readonly Brush PythonKeyword = new SolidColorBrush(Color.FromRgb(126, 169, 196));
    private static readonly Brush PythonString = new SolidColorBrush(Color.FromRgb(196, 173, 120));
    private static readonly Brush PythonComment = new SolidColorBrush(Color.FromRgb(105, 154, 135));
    private static readonly Brush PythonNumber = new SolidColorBrush(Color.FromRgb(169, 154, 196));
    private static readonly Brush PythonBuiltin = new SolidColorBrush(Color.FromRgb(121, 184, 179));
    private static readonly Regex PythonKeywordPattern = new(@"\b(?:False|None|True|and|as|assert|async|await|break|class|continue|def|del|elif|else|except|finally|for|from|global|if|import|in|is|lambda|nonlocal|not|or|pass|raise|return|try|while|with|yield)\b", RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex PythonBuiltinPattern = new(@"\b(?:print|len|range|enumerate|zip|min|max|sum|sorted|list|dict|set|tuple|str|int|float|bool|bytes|bytearray)\b", RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex PythonNumberPattern = new(@"(?<![\w.])(?:0[xX][0-9a-fA-F]+|0[bB][01]+|0[oO][0-7]+|\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)\b", RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex PythonStringPattern = new(@"(?:[rRuUbBfF]{0,2})(?:'(?:\\.|[^'\\\r\n])*'|""(?:\\.|[^""\\\r\n])*"")", RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex PythonCommentPattern = new(@"(?m)#.*$", RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private const string OutputTruncatedNotice = "（输出超限已截断）";
    private const string ScriptGuideTextContent =
        "① 输入：脚本首行写 from netmind import fixture，fixture.transactions 是当前流量表中最近 30 条已脱敏事务。\n" +
        "② 每条事务字段：method、url、host、endpoint、status、latency_ms、size_bytes、protocol、process、request_summary、response_summary。\n" +
        "③ 输出：用 print() 写入 stdout；退出码 0 = 验证通过，非 0（含 assert 失败）= 验证失败。\n" +
        "④ 禁止项：导入 os / sys / subprocess / socket / ctypes / pathlib / shutil / winreg / multiprocessing / http / urllib；\n" +
        "    调用 open()、exec()、eval()、compile()、__import__()、input()、breakpoint()。\n" +
        "⑤ 资源限制：脚本 ≤ 128 KB · 默认超时 5 秒 · 内存 256 MB · stdout/stderr 各 256 KB · 单进程、无网络、无第三方包。";
    private const string DefaultGuidedScript =
        "# NetMind 脚本验证引导示例\n" +
        "# 输入：from netmind import fixture；fixture.transactions 为最近 30 条已脱敏流量\n" +
        "# 每条事务字段：method url host endpoint status latency_ms size_bytes protocol process request_summary response_summary\n" +
        "# 输出：print() 写入结果；退出码 0 = 验证通过，非 0 = 验证失败（assert 失败也算非 0）\n\n" +
        "from netmind import fixture\n\n" +
        "total = len(fixture.transactions)\n" +
        "# 校验：至少应有一条事务\n" +
        "assert total > 0, '流量表中没有任何事务，无法验证'\n\n" +
        "successful = [item for item in fixture.transactions if item.status < 400]\n" +
        "print(f'共 {total} 条事务，其中 {len(successful)} 条状态小于 400')\n" +
        "print('验证通过：fixture 可正常读取')";
    private const string DefaultHookScriptTemplate =
        "# NetMind API 逆向观察模板\n" +
        "#\n" +
        "# 【默认拒绝转发】定义了下面这些函数不代表它们会被调用：必须先在 OBSERVE（不阻塞）或\n" +
        "# INTERCEPT（阻塞，仅限发送前/回写前两点）里声明匹配规则，宿主才会把命中的事件转发过来；\n" +
        "# 没声明的挂载点、没命中的流量一律不转发，函数体永远不会执行——不报错，只是安静地没反应。\n" +
        "# 这份模板要观察全部端点，所以 OBSERVE 没写 url/host 条件：只写 {'event': 'x'} 表示要这个\n" +
        "# 挂载点的全部流量。只想看某个接口时，照 INTERCEPT 例子的样子给 OBSERVE 也加一条 url 正则。\n" +
        "OBSERVE = [\n" +
        "    {'event': 'request.before_send'},\n" +
        "    {'event': 'response.before_write'},\n" +
        "]\n" +
        "#\n" +
        "# 仅首次发现端点或响应异常时返回 finding；返回 None 不写审计，避免每个请求都产生噪声。\n" +
        "# event 为 dict，字段：event、txnId、sessionId、hookName、method、url、host、endpoint、\n" +
        "#   statusCode、headers、bodyPreviewBase64、bodyTruncated、bodySha256、bodySize。\n" +
        "# 正文预览（bodyPreviewBase64）默认不下发：脚本里出现这个字段名，或写一行 WANT_BODY = True，\n" +
        "#   宿主才会带上。只用 bodySize / bodySha256 时不必声明，可省掉绝大部分事件数据量。\n" +
        "# store 为宿主注入的键值存储（落盘在工作区 scripts/data 目录，直接使用，无需导入）：\n" +
        "#   store.save('名称', 文本或对象) 写入 · store.load('名称') 读取（不存在返回 None）\n" +
        "#   store.list() 列出全部键 · store.delete('名称') 删除\n" +
        "# 编辑器：Ctrl+J 智能提示 · Ctrl+/ 切换注释 · Ctrl+[ 折叠当前块 · 右键有整理格式与折叠命令。\n" +
        "#\n" +
        "# 【拦截改写】要修改数据并向下传播，取消下面 INTERCEPT 的注释：只有命中规则的请求才阻塞\n" +
        "# 等待裁决，其余流量仍按 OBSERVE 只读转发或完全不转发。规则条件全是正则\n" +
        "# （url/method/host/endpoint/body/status/headers），条件之间是 AND。\n" +
        "# 命中时钩子函数的返回值即改写内容，返回 None 原样放行；超时或异常一律放行，不会卡住浏览器。\n" +
        "#\n" +
        "# INTERCEPT = [\n" +
        "#     {'event': 'request.before_send', 'url': r'/v\\d+/user/login', 'method': r'^POST$'},\n" +
        "# ]\n" +
        "#\n" +
        "# def on_before_send(event):\n" +
        "#     # 删掉签名头并替换正文，验证服务端是否真的校验\n" +
        "#     return {\n" +
        "#         'headers': {'X-Sign': None, 'X-Debug': '1'},\n" +
        "#         'body': '{\"password\":\"changed\"}',\n" +
        "#         'finding': {'kind': 'probe.sign-removed'},\n" +
        "#     }\n\n" +
        "def _header_names(event):\n" +
        "    headers = event.get('headers') or {}\n" +
        "    return sorted([str(name) for name in headers.keys()])\n\n" +
        "def on_before_send(event):\n" +
        "    # 维护跨请求的 API 端点清单，只在首次出现时形成结论。\n" +
        "    key = str(event.get('method') or '') + ' ' + str(event.get('endpoint') or '')\n" +
        "    known = store.load('api-endpoints.txt') or ''\n" +
        "    if ('\\n' + key + '\\n') in ('\\n' + known):\n" +
        "        return None\n" +
        "    store.save('api-endpoints.txt', known + key + '\\n')\n" +
        "    return {\n" +
        "        'kind': 'api.endpoint.discovered', 'method': event.get('method'),\n" +
        "        'url': event.get('url'), 'headerNames': _header_names(event),\n" +
        "        'bodySize': event.get('bodySize'), 'bodySha256': event.get('bodySha256')\n" +
        "    }\n\n" +
        "# 未在 OBSERVE/INTERCEPT 中声明的挂载点：定义了也不会被调用，留空占位。\n" +
        "# 想要它触发，在上面 OBSERVE 里加一条 {'event': 'request.after_send'} 即可。\n" +
        "def on_after_send(event):\n" +
        "    return None\n\n" +
        "def on_before_write(event):\n" +
        "    # 仅把错误响应升级为 finding；txnId 可与流量事务精确关联。\n" +
        "    status = event.get('statusCode') or 0\n" +
        "    if status < 400:\n" +
        "        return None\n" +
        "    return {\n" +
        "        'kind': 'api.response.error', 'status': status, 'url': event.get('url'),\n" +
        "        'bodySize': event.get('bodySize'), 'bodySha256': event.get('bodySha256')\n" +
        "    }\n\n" +
        "# 同上：未在 OBSERVE 中声明 response.after_deliver，这个函数当前不会被调用。\n" +
        "def on_after_deliver(event):\n" +
        "    return None";
    private sealed record ScriptSample(string Title, string Script);
    private static readonly ScriptSample[] ScriptSamples =
    [
        new("按端点统计请求次数（去重计数）",
            "# 示例一：按 endpoint 统计请求次数并去重计数\n" +
            "# 用途：观察哪些接口被调用最多，适合做接口热点分析\n\n" +
            "from netmind import fixture\n\n" +
            "counts = {}\n" +
            "for item in fixture.transactions:\n" +
            "    counts[item.endpoint] = counts.get(item.endpoint, 0) + 1\n\n" +
            "print(f'共出现 {len(counts)} 个不同端点')\n" +
            "for endpoint, count in sorted(counts.items(), key=lambda pair: pair[1], reverse=True):\n" +
            "    print(f'{count:>3} 次 · {endpoint}')"),
        new("计算成功率与错误率",
            "# 示例二：基于 status 计算成功率与错误率\n" +
            "# 约定：状态码小于 400 视为成功，4xx/5xx 视为错误\n\n" +
            "from netmind import fixture\n\n" +
            "total = len(fixture.transactions)\n" +
            "assert total > 0, '流量表中没有任何事务'\n\n" +
            "failed = [item for item in fixture.transactions if item.status >= 400]\n" +
            "success_rate = (total - len(failed)) / total * 100\n" +
            "print(f'事务总数：{total}')\n" +
            "print(f'成功：{total - len(failed)} 条 · 错误：{len(failed)} 条')\n" +
            "print(f'成功率：{success_rate:.1f}%')"),
        new("筛选错误事务并断言无 5xx",
            "# 示例三：过滤出错误事务；assert 失败时脚本以非 0 退出码结束，结果为“验证失败”\n" +
            "# 用途：把“不允许出现 5xx”写成可重复执行的回归规则\n\n" +
            "from netmind import fixture\n\n" +
            "errors = [item for item in fixture.transactions if item.status >= 400]\n" +
            "print(f'发现 {len(errors)} 条错误事务：')\n" +
            "for item in errors:\n" +
            "    print(f'  {item.method} {item.endpoint} -> {item.status}')\n\n" +
            "server_errors = [item for item in errors if item.status >= 500]\n" +
            "assert not server_errors, f'出现 {len(server_errors)} 条 5xx 服务端错误'\n" +
            "print('验证通过：没有 5xx 服务端错误')"),
        new("汇总所有 host 与访问方法",
            "# 示例四：字段提取汇总，列出所有 host 及其使用的 HTTP 方法\n" +
            "# 用途：梳理当前流量覆盖的服务与域名\n\n" +
            "from netmind import fixture\n\n" +
            "hosts = {}\n" +
            "for item in fixture.transactions:\n" +
            "    name = item.host if item.host else '(未知主机)'\n" +
            "    methods = hosts.setdefault(name, set())\n" +
            "    methods.add(item.method)\n\n" +
            "print(f'共访问 {len(hosts)} 个主机：')\n" +
            "for name in sorted(hosts):\n" +
            "    print(f'  {name} · {\"、\".join(sorted(hosts[name]))}')"),
        new("断言校验：响应大小不超过阈值",
            "# 示例五：断言校验演示。断言失败 → 退出码非 0 → 结果区显示“验证失败”\n" +
            "# 用途：把“单条响应不得超过 1 MB”写成自动规则\n\n" +
            "from netmind import fixture\n\n" +
            "MAX_SIZE_BYTES = 1024 * 1024  # 阈值 1 MB\n\n" +
            "oversized = [item for item in fixture.transactions if item.size_bytes > MAX_SIZE_BYTES]\n" +
            "for item in oversized:\n" +
            "    print(f'超限：{item.endpoint} · {item.size_bytes} 字节')\n\n" +
            "assert not oversized, f'有 {len(oversized)} 条响应超过大小阈值'\n" +
            "print(f'验证通过：{len(fixture.transactions)} 条响应均未超过阈值')"),
        new("生成文本报告",
            "# 示例六：生成文本报告，用 print 格式化输出汇总结果\n" +
            "# 用途：一键产出可读的流量质量报告\n\n" +
            "from netmind import fixture\n\n" +
            "total = len(fixture.transactions)\n" +
            "if total == 0:\n" +
            "    print('流量表中没有任何事务。')\n" +
            "    raise SystemExit(0)\n\n" +
            "latencies = [item.latency_ms for item in fixture.transactions]\n" +
            "sizes = [item.size_bytes for item in fixture.transactions]\n" +
            "failed = sum(1 for item in fixture.transactions if item.status >= 400)\n\n" +
            "print('=' * 40)\n" +
            "print('NetMind 流量报告')\n" +
            "print('=' * 40)\n" +
            "print(f'事务总数：{total}')\n" +
            "print(f'错误事务：{failed} 条（{failed / total * 100:.1f}%）')\n" +
            "print(f'延迟：平均 {sum(latencies) // total} 毫秒 · 最大 {max(latencies)} 毫秒')\n" +
            "print(f'响应总大小：{sum(sizes)} 字节')")
    ];
    private readonly DispatcherTimer _captureTimer = new() { Interval = TimeSpan.FromMilliseconds(DefaultRefreshIntervalMilliseconds) };
    private readonly DispatcherTimer _scriptHighlightTimer = new() { Interval = TimeSpan.FromMilliseconds(250) };
    private static readonly string DefaultWorkspaceRoot = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), SettingsDirectoryName, "workspaces");
    private string _workspaceRoot = DefaultWorkspaceRoot;
    private string _workspacePath;
    private WorkspaceDescriptor? _currentWorkspace;
    private readonly string _aiSettingsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), SettingsDirectoryName, "ai-settings.json");
    private readonly string _settingsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), SettingsDirectoryName, WorkbenchSettingsFileName);
    private readonly string _systemProxySentinelPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), SettingsDirectoryName, SystemProxySentinelFileName);
    private WorkbenchSettings _settings = new();
    private Task _settingsLoadTask = Task.CompletedTask;
    private Process? _coreHostProcess;
    private Process? _captureBrowserProcess;
    private int _hookReceivePort;
    private string _hookReceiveToken = string.Empty;
    private int _captureBrowserDebuggingPort;
    private CancellationTokenSource? _pageHookMonitorCancellation;
    private Task? _pageHookMonitorTask;
    private PageHookMonitorStatus? _lastPageHookStatus;
    private DateTimeOffset? _lastPageHookStatusAt;
    private CancellationTokenSource? _aiCancellation;
    private bool _capturing;
    private bool _silentCaptureActive;
    private bool _refreshing;
    private bool _refreshPaused;
    private bool _closing;
    private bool _showingDemoData = true;
    private bool _tlsInspectionEnabled;
    private bool _hasLoadedStoredTraffic;
    private long _trafficRefreshCursor;
    private long _capturedCount;
    private TrafficRow? _selectedTraffic;
    private Guid? _preferredTrafficId;
    private bool _updatingTrafficRows;
    private readonly Dictionary<Guid, StoredTrafficRecord> _storedTraffic = [];
    private readonly HashSet<Guid> _aiSelectedTrafficIds = [];
    // Shift 范围勾选锚点：记录最近一次普通点击的行 id，范围勾选时按 id 解析索引，避免行刷新后索引漂移。
    private Guid? _aiCheckAnchorId;
    private DataGrid? _aiCheckAnchorGrid;
    // 表头全选框程序化同步守卫：防止设置 IsChecked 触发 Checked/Unchecked 事件回环。
    private bool _syncingAiSelectAll;
    // 资源类型“全部”与各类型复选框双向同步守卫，避免程序化赋值触发重复筛选。
    private bool _syncingResourceTypeFilters;
    private static readonly IReadOnlySet<string> DefaultVisibleResourceTypes =
        new HashSet<string>(["接口数据", "脚本", "文档", "其他"], StringComparer.Ordinal);
    // 静默抓包按进程过滤：非 null 时采集后台仅落库该进程产生的事务（“按进程采集”入口设置，停止后清空）。
    private string? _silentProcessFilter;
    // 内容搜索定位高亮：记录目标行，防止后续手动切行后错误应用。
    private (Guid RowId, string Keyword, string Location)? _pendingContentHighlight;
    // AI 分析用时计数：运行期间每秒刷新状态栏。
    private DispatcherTimer? _aiElapsedTimer;
    private DateTime _aiRunStartedAt;
    private string _aiRunStatusBase = string.Empty;
    // 当前回合生效的网关响应上限（字节）：0 表示未在运行，回复期间随用时一起动态展示。
    private int _aiRunResponseLimitBytes;
    // 当前回合已接收的网关响应累计字节：网关回调在请求线程写入，状态栏每秒读取渲染。
    private long _aiTurnResponseBytes;
    private readonly ObservableCollection<AiAttachedFile> _aiAttachedFiles = [];
    // AI 对话式会话状态：当前打开会话的元数据、完整消息历史（含 system 提示）与证据池取数 provider。
    private AiConversationHeader? _openConversationHeader;
    private List<AiChatMessage> _openConversationHistory = [];
    private WorkbenchAiEvidenceProvider? _openEvidenceProvider;
    // 只渲染最近若干轮，完整历史仍保留在内存和磁盘；避免长会话反复创建大量 Markdown/代码控件。
    private const int AiTurnRenderPageSize = 12;
    private int _aiVisibleTurnLimit = AiTurnRenderPageSize;
    private bool _loadingAiConversations;
    private bool _aiTurnRunning;
    // 会话累计统计（跨轮）：取数次数与输入/输出令牌。
    private int _aiTurnFetchCount;
    private int _aiTurnInputTokens;
    private int _aiTurnOutputTokens;
    // 流式渲染：网关文本增量累积进缓冲，300 ms 节流重渲染当前轮的助手回复块。
    private readonly StringBuilder _aiStreamBuffer = new();
    private DispatcherTimer? _aiStreamRenderTimer;
    private TextBox? _aiStreamingTextBox;
    // AI 页配置自动持久化：输入后防抖落盘，避免每次按键都写文件；初始为 true 以抑制 XAML 初始化阶段的变更事件。
    private DispatcherTimer? _aiConfigAutoSaveTimer;
    private bool _loadingAiSettings = true;
    // 追加文件对话框目录记忆：首次打开默认定位系统下载目录，之后沿用上次选择位置。
    private string? _lastAttachedFileDirectory;
    private TrafficGroup? _activeTrafficGroup;
    private readonly HashSet<Guid> _activeTrafficGroupIds = [];
    private TrafficRecord[]? _groupAiEvidence;
    private string? _groupAiName;
    private AiAnalysisHistoryEntry? _currentAiHistoryEntry;
    private string _currentAiMarkdown = string.Empty;
    private bool _loadingAiHistory;
    /// <summary>加载设置回填界面时为真，防止复选框同步赋值触发即时持久化回写。</summary>
    private bool _applyingWorkbenchSettings;
    private Guid? _sessionFilterId;
    /// <summary>本次采集的捕获会话标识（由 CoreHost 就绪输出/信号文件带回）；未知时为 null，退化为不限定视图。</summary>
    private Guid? _liveCaptureSessionId;
    /// <summary>上一次刷新实际生效的会话范围；与 <see cref="_sessionFilterId"/> 不一致时必须整窗重读并重置游标。</summary>
    private Guid? _trafficScopeSessionId;
    private long _pendingRefreshCount;
    private int _copyFeedbackVersion;
    private bool _highlightingScript;
    /// <summary>补全时已键入的前缀长度；提交前要先删掉它，否则会出现 meth+method 这类重复。</summary>
    private int _scriptCompletionPrefixLength;
    private RichTextBox? _pendingHighlightEditor;
    /// <summary>脚本库中当前编辑的脚本；脚本库为空时为 null。</summary>
    private ScriptRow? _currentScript;
    /// <summary>当前脚本最后一次落盘的内容，用于判断是否真的有未保存改动。</summary>
    private string _loadedScriptText = string.Empty;
    private bool _scriptDirty;
    private bool _suppressScriptListChange;
    private bool _suppressScriptPurposeChange;
    /// <summary>hook-config.json 中 scriptPath 的原值；指向 scripts 目录外的自定义路径也原样保留。</summary>
    private string? _activeHookScriptPath;
    /// <summary>采集钩子脚本在脚本库中的文件名；scriptPath 指向 scripts 目录之外时为 null。</summary>
    private string? _activeHookScriptFileName;
    private CancellationTokenSource? _evidenceLoadCts;
    /// <summary>选中行到真正读盘之间的等待。快速连点时中途路过的行不该各读一次正文。</summary>
    private const int EvidenceLoadDebounceMilliseconds = 120;

    /// <summary>停止采集时系统代理还原结果，决定状态栏提示文案。</summary>
    private enum SystemProxyRestoreOutcome { NotTaken, Restored, Failed }
    private readonly Dictionary<string, JsonTreeNode> _jsonTreeCache = [];
    private readonly LinkedList<string> _jsonTreeCacheOrder = [];

    public ObservableCollection<ScriptRow> Scripts { get; } = [];
    /// <summary>钩子脚本试跑期间返回的结论，累积保留供用户回看，而不是每次运行就覆盖上一次的预览。</summary>
    public ObservableCollection<ScriptFindingRow> ScriptFindings { get; } = [];
    /// <summary>累积上限：够看清脚本行为，又不至于让列表无限增长拖慢界面。</summary>
    private const int ScriptFindingsCapacity = 300;
    public ObservableCollection<TrafficRow> TrafficRows { get; } = [];
    public ObservableCollection<TrafficRow> FilteredTrafficRows { get; } = [];
    public ObservableCollection<SessionRow> Sessions { get; } = [];
    public ObservableCollection<TrafficGroupRow> TrafficGroups { get; } = [];
    public ObservableCollection<TrafficRow> GroupTrafficRows { get; } = [];
    public ObservableCollection<WorkspaceRow> Workspaces { get; } = [];
    public ObservableCollection<AiHistoryRow> AiHistoryRows { get; } = [];
    /// <summary>AI 页左侧会话列表：标题 = 模板 + 时间 + 轮数 + 范围。</summary>
    public ObservableCollection<AiConversationRow> AiConversationRows { get; } = [];
    /// <summary>实时概览右列：按请求数排序的端点聚类健康度行。</summary>
    public ObservableCollection<OverviewClusterRow> OverviewClusterRows { get; } = [];

    /// <summary>实时概览端点聚类行：展示确定性分析的每端点指标，点击可下钻到流量探索。</summary>
    public sealed record OverviewClusterRow(int Ordinal, string Method, string Endpoint, int Requests, string ErrorRate, string P95)
    {
        public static OverviewClusterRow From(EndpointCluster cluster, int ordinal) =>
            new(ordinal, cluster.Method, cluster.NormalizedEndpoint, cluster.RequestCount,
                cluster.ErrorRate.ToString("0.0") + "%", cluster.P95LatencyMilliseconds + " 毫秒");
    }

    public TrafficRow? SelectedTraffic
    {
        get => _selectedTraffic;
        set
        {
            if (ReferenceEquals(_selectedTraffic, value)) return;
            _selectedTraffic = value;
            OnPropertyChanged();
            UpdateInspector(value?.Source);
        }
    }

    public MainWindow()
    {
        _workspacePath = Path.Combine(_workspaceRoot, "northstar-lab");
        InitializeComponent();
        DataContext = this;
        WorkspacePathText.Text = _workspacePath;
        _captureTimer.Tick += async (_, _) => await RefreshStoredTrafficAsync();
        _scriptHighlightTimer.Tick += (_, _) =>
        {
            _scriptHighlightTimer.Stop();
            var editor = _pendingHighlightEditor;
            _pendingHighlightEditor = null;
            if (editor is not null) ApplyPythonSyntaxHighlighting(editor);
        };
        // 工作区载入前先摆一份默认钩子脚本模板；LoadScriptWorkspaceAsync 会用真实脚本库覆盖它。
        ApplyScriptPurposeCombo(ScriptPurpose.Hook);
        SetScriptText(DefaultHookScriptTemplate);
        ApplyPythonSyntaxHighlighting();
        UpdateScriptHeader();
        InitializeAboutPage();
        // 分析模板与快捷追问：先用内置默认填充，工作区载入后改读可编辑目录（ai-prompts.json）。
        ApplyAiCatalog(AiPromptCatalog.BuiltIn, AiPromptTemplate.DefaultTemplateId);
        AiQuickFollowUpPanel.IsEnabled = false;
        ShowAiEmptyHint();
        _settingsLoadTask = LoadWorkbenchSettingsAsync();
        Loaded += async (_, _) =>
        {
            await _settingsLoadTask;
            await InitializeWorkspaceAsync();
        };
        Closing += async (_, eventArgs) =>
        {
            _aiCancellation?.Cancel();
            StopPageHookMonitor();
            if (_closing || !_capturing) return;
            eventArgs.Cancel = true;
            _closing = true;
            await StopCoreHostAsync();
            Close();
        };
        var demoTraffic = DemoData.CreateTraffic();
        ReplaceTraffic(demoTraffic, demoTraffic.Count);
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));

    private void 导航_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button selected) SelectPage(selected);
    }

    private void SelectPage(Button selected)
    {
        var buttons = new[] { OverviewNav, TrafficNav, GroupNav, AiNav, SandboxNav, WorkspaceNav, SettingsNav, AboutNav };
        var index = Array.IndexOf(buttons, selected);
        if (index < 0) return;
        foreach (var button in buttons) button.Tag = null;
        selected.Tag = "选中";
        MainTabs.SelectedIndex = index;
    }

    /// <summary>版本号取自程序集（与 Directory.Build.props 的 &lt;Version&gt; 同源），不在这里手写第二份。</summary>
    private void InitializeAboutPage()
    {
        var version = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version;
        if (AboutVersionText is not null)
            AboutVersionText.Text = version is null ? "版本未知" : $"v{version.Major}.{version.Minor}.{version.Build}";
        if (AboutCopyrightText is not null)
            AboutCopyrightText.Text = $"Copyright © {DateTime.Now.Year} varlar";
    }

    /// <summary>关于页仓库链接：用系统默认浏览器打开，不在应用内嵌 WebView（项目约定不发起远程内容渲染）。</summary>
    private void 关于仓库链接_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            Process.Start(new ProcessStartInfo("https://github.com/wangmos/NetMind_AI") { UseShellExecute = true });
        }
        catch { /* 打开默认浏览器失败不影响关于页其余信息的可读性 */ }
    }

    private async void 主页面_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!IsLoaded || MainTabs.SelectedItem is not TabItem tab) return;
        PageTitle.Text = tab.Header?.ToString() ?? "NetMind AI";
        PageSubtitle.Text = MainTabs.SelectedIndex switch
        {
            0 => "查看真实代理状态与最近流量证据",
            1 => "按端点、进程、协议与状态筛选已捕获事务",
            2 => "选择项目并管理其中的证据记录组",
            3 => "基于证据生成可审计的分析建议",
            4 => "在受限 Python 沙箱中验证规则",
            5 => "管理当前项目的 HTTPS 边界与捕获会话",
            6 => "偏好与运行参数设置",
            _ => "项目简介与版本信息"
        };
        if (MainTabs.SelectedIndex == 4) await RefreshScriptHookRuntimeStatusAsync();
    }

    private async void 切换采集_Click(object sender, RoutedEventArgs e)
    {
        CaptureButton.IsEnabled = false;
        try
        {
            if (_capturing) await StopCoreHostAsync();
            else
            {
                _silentProcessFilter = null; // 常规开始采集面向全部进程；进程过滤仅“按进程采集”入口一次性生效
                await StartCoreHostAsync();
            }
        }
        finally { CaptureButton.IsEnabled = true; }
    }

    private async void 打开浏览器_Click(object sender, RoutedEventArgs e)
    {
        BrowserButton.IsEnabled = false;
        try
        {
            if (IsProcessAlive(_captureBrowserProcess))
            {
                if (_capturing && _captureBrowserDebuggingPort > 0 && _pageHookMonitorCancellation is null)
                    StartPageHookMonitor(_captureBrowserDebuggingPort);
                MessageBox.Show(this, "采集浏览器已在运行，无需重复打开。\n\n如需重新启动，请先点击“关闭采集浏览器”。", "采集浏览器已在运行", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }
            DisposeCaptureBrowserHandle();
            if (!_capturing) await StartCoreHostAsync();
            if (!_capturing) return;
            var workspaceId = _currentWorkspace?.Id ?? "northstar-lab";
            var profilePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "NetMind", "browser-profiles", workspaceId);
            // 密钥日志与工作区约定同路径：浏览器写入、采集后台增量读取，实现 HTTPS 解密
            var keyLogPath = Path.Combine(_workspacePath, SilentKeyLogRelativePath);
            // 页内 Hook 注入通道：为浏览器选一个本机空闲调试端口，启动后再经 CDP 注入脚本。
            var debuggingPort = PickFreeLoopbackPort();
            var plan = CaptureBrowser.CreatePlan(profilePath, new IPEndPoint(IPAddress.Loopback, _settings.ListenPort), keyLogPath,
                remoteDebuggingPort: debuggingPort, environmentProfile: _settings.BrowserEnvironment,
                useProxy: !_silentCaptureActive);
            if (plan is null)
            {
                MessageBox.Show(this, $"未找到 Microsoft Edge 或 Google Chrome。\n\n也可以设置 {BrowserEnvironmentVariable} 指向 Chromium 浏览器可执行文件。", "无法打开采集浏览器", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            Directory.CreateDirectory(plan.ProfilePath);
            try { Directory.CreateDirectory(Path.GetDirectoryName(keyLogPath)!); } catch { /* 密钥目录不可建时退化为隧道模式，浏览器仍可正常采集 */ }
            var startInfo = new ProcessStartInfo(plan.ExecutablePath) { UseShellExecute = false };
            foreach (var argument in plan.Arguments) startInfo.ArgumentList.Add(argument);
            foreach (var (name, value) in plan.Environment) startInfo.Environment[name] = value;
            var browserProcess = Process.Start(startInfo) ?? throw new InvalidOperationException("浏览器进程未能启动。");
            _captureBrowserDebuggingPort = debuggingPort;
            TrackCaptureBrowserProcess(browserProcess);
            StartPageHookMonitor(debuggingPort);
            CaptureState.Text = "采集浏览器已连接 · 页内 Hook 持续挂载中";
            CaptureState.Foreground = Accent;
        }
        catch (Exception exception)
        {
            MessageBox.Show(this, $"打开采集浏览器失败：\n\n{exception.Message}", "无法打开采集浏览器", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally { BrowserButton.IsEnabled = true; }
    }

    private async void 关闭浏览器_Click(object sender, RoutedEventArgs e)
    {
        CloseBrowserButton.IsEnabled = false;
        try
        {
            var process = _captureBrowserProcess;
            if (!IsProcessAlive(process))
            {
                DisposeCaptureBrowserHandle();
                MessageBox.Show(this, "没有正在运行的采集浏览器。", "关闭采集浏览器", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }
            // 优先尝试优雅关闭窗口；失败或超时后再强制结束整个进程树（Chromium 会派生子进程）。
            var browser = process!;
            try { browser.CloseMainWindow(); }
            catch (InvalidOperationException) { /* 进程可能在关闭瞬间已退出 */ }
            if (!await Task.Run(() => browser.WaitForExit(CaptureBrowserCloseTimeoutMilliseconds)))
            {
                try
                {
                    browser.Kill(entireProcessTree: true);
                    await Task.Run(() => browser.WaitForExit(CaptureBrowserCloseTimeoutMilliseconds));
                }
                catch (InvalidOperationException) { /* 进程已在强制结束前退出 */ }
            }
            var stillRunning = IsProcessAlive(process);
            DisposeCaptureBrowserHandle();
            RefreshCaptureStateWithoutBrowser();
            MessageBox.Show(this, stillRunning ? "采集浏览器进程拒绝退出，请手动关闭浏览器窗口。" : "采集浏览器已关闭。", "关闭采集浏览器", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception exception)
        {
            DisposeCaptureBrowserHandle();
            MessageBox.Show(this, $"关闭采集浏览器失败：\n\n{exception.Message}", "无法关闭采集浏览器", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally { CloseBrowserButton.IsEnabled = true; }
    }

    private void TrackCaptureBrowserProcess(Process browserProcess)
    {
        _captureBrowserProcess = browserProcess;
        browserProcess.EnableRaisingEvents = true;
        browserProcess.Exited += (_, _) => Dispatcher.BeginInvoke(() =>
        {
            if (!ReferenceEquals(_captureBrowserProcess, browserProcess)) return;
            DisposeCaptureBrowserHandle();
            RefreshCaptureStateWithoutBrowser();
        });
    }

    private static bool IsProcessAlive(Process? process)
    {
        if (process is null) return false;
        try { return !process.HasExited; }
        catch (InvalidOperationException) { return false; }
        catch (SystemException) { return false; }
    }

    private void DisposeCaptureBrowserHandle()
    {
        StopPageHookMonitor();
        _captureBrowserDebuggingPort = 0;
        var process = _captureBrowserProcess;
        _captureBrowserProcess = null;
        try { process?.Dispose(); }
        catch (Exception) { /* 句柄释放失败不影响后续生命周期判断 */ }
    }

    private void RefreshCaptureStateWithoutBrowser()
    {
        if (!_capturing) return;
        CaptureState.Text = _tlsInspectionEnabled ? "HTTPS 正文抓取中" : "真实代理监听中";
        CaptureState.Foreground = Accent;
    }

    private async Task StartCoreHostAsync()
    {
        var coreHostExecutable = Path.Combine(AppContext.BaseDirectory, "CoreHost", "NetMind.CoreHost.exe");
        var coreHostAssembly = Path.Combine(AppContext.BaseDirectory, "CoreHost", "NetMind.CoreHost.dll");
        if (!File.Exists(coreHostExecutable) && !File.Exists(coreHostAssembly))
        {
            MessageBox.Show(this, "未找到流量捕获后台，请先重新构建工作台项目。", "无法开始采集", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        // 上一次采集的会话标识不得沿用：拿不到新会话时应退化为不限定，而不是筛到旧会话（列表会恒为空）。
        _liveCaptureSessionId = null;
        // 页内 Hook 在代理/静默两种模式下都需要独立回环接收端口；令牌只在本次采集生命周期有效。
        _hookReceivePort = PickFreeLoopbackPort();
        _hookReceiveToken = Convert.ToHexString(RandomNumberGenerator.GetBytes(24)).ToLowerInvariant();
        if (_settings.UseSilentCapture)
        {
            // 采集模式开关：底层静默抓包走独立的提升权限启动路径（信号文件就绪协议）。
            await StartSilentCaptureAsync(coreHostExecutable);
            return;
        }
        var ready = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var errors = new StringBuilder();
        var startInfo = new ProcessStartInfo(File.Exists(coreHostExecutable) ? coreHostExecutable : "dotnet")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
            StandardInputEncoding = Encoding.UTF8
        };
        if (!File.Exists(coreHostExecutable)) startInfo.ArgumentList.Add(coreHostAssembly);
        // 监听地址固定本机回环（代理无鉴权，绝不对外监听），仅端口可配置。
        var listenEndpoint = $"{LoopbackAddress}:{_settings.ListenPort}";
        // 页内 Hook 接收端口：随本次采集会话选定，传给 CoreHost 起仅监听回环的接收端点。
        foreach (var argument in new[] { "proxy", "--listen", listenEndpoint, "--workspace", _workspacePath,
                     "--hook-port", _hookReceivePort.ToString(), "--hook-token", _hookReceiveToken })
            startInfo.ArgumentList.Add(argument);
        if (_tlsInspectionEnabled) startInfo.ArgumentList.Add("--tls-inspect");
        var process = new Process { StartInfo = startInfo, EnableRaisingEvents = true };
        process.OutputDataReceived += (_, eventArgs) =>
        {
            // CoreHost 的“监听地址：”行是稳定的机器可读就绪标记，据此解析实际端点，
            // 改端口后就绪探测仍成立，也避免后台控制台编码影响中文文本匹配。
            var line = eventArgs.Data;
            if (line is null) return;
            // 会话标识行先于就绪行到达（CoreHost 保证输出顺序），据此把列表限定到本次采集。
            var sessionIndex = line.IndexOf(CoreHostSessionMarker, StringComparison.Ordinal);
            if (sessionIndex >= 0)
            {
                if (Guid.TryParse(line[(sessionIndex + CoreHostSessionMarker.Length)..].Trim(), out var liveSession))
                    _liveCaptureSessionId = liveSession;
                return;
            }
            var markerIndex = line.IndexOf(CoreHostReadyMarker, StringComparison.Ordinal);
            if (markerIndex < 0) return;
            var endpoint = line[(markerIndex + CoreHostReadyMarker.Length)..].Trim();
            if (endpoint.Length > 0 && (endpoint == listenEndpoint || line.Contains(listenEndpoint, StringComparison.Ordinal))) ready.TrySetResult();
        };
        process.ErrorDataReceived += (_, eventArgs) => { if (!string.IsNullOrWhiteSpace(eventArgs.Data)) errors.AppendLine(eventArgs.Data); };
        process.Exited += (_, _) => ready.TrySetException(new InvalidOperationException(errors.Length > 0 ? errors.ToString().Trim() : "捕获后台意外退出。"));
        try
        {
            if (!process.Start()) throw new InvalidOperationException("无法启动捕获后台进程。");
            _coreHostProcess = process;
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();
            await ready.Task.WaitAsync(TimeSpan.FromSeconds(8));
            _capturing = true;
            ResumeLiveTrafficView();
            SettingsListenPortBox.IsEnabled = false;
            _showingDemoData = false;
            CaptureButton.Content = "停止采集";
            CaptureButton.Background = Red;
            CaptureState.Text = _tlsInspectionEnabled ? "HTTPS 正文抓取中" : "真实代理监听中";
            CaptureState.Foreground = Accent;
            if (IsProcessAlive(_captureBrowserProcess) && _captureBrowserDebuggingPort > 0)
                StartPageHookMonitor(_captureBrowserDebuggingPort);
            await TryTakeOverSystemProxyAsync();
            _captureTimer.Start();
            UpdateModeText();
            await RefreshStoredTrafficAsync();
        }
        catch (Exception exception)
        {
            if (!process.HasExited) process.Kill(entireProcessTree: true);
            process.Dispose();
            _coreHostProcess = null;
            MessageBox.Show(this, $"捕获后台启动失败：\n\n{exception.Message}", "无法开始采集", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    /// <summary>选取一个本机回环空闲端口（短暂绑定 0 端口后释放，窗口期极短可接受）。</summary>
    private static int PickFreeLoopbackPort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        try
        {
            listener.Start();
            return ((IPEndPoint)listener.LocalEndpoint).Port;
        }
        finally
        {
            listener.Stop();
        }
    }

    /// <summary>启动页内 Hook 持续挂载：现有页面立即注入，后续新标签页由监视器自动发现并注入。</summary>
    private void StartPageHookMonitor(int debuggingPort)
    {
        StopPageHookMonitor();
        if (debuggingPort <= 0 || _hookReceivePort <= 0 || string.IsNullOrWhiteSpace(_hookReceiveToken)) return;
        var cancellation = new CancellationTokenSource();
        _pageHookMonitorCancellation = cancellation;
        PageHookAttachStatusText.Text = "正在发现浏览器页面…";
        PageHookAttachStatusText.Foreground = Amber;
        _pageHookMonitorTask = Task.Run(async () =>
        {
            try
            {
                await PageHookInjector.MonitorAsync(debuggingPort, _hookReceivePort, _hookReceiveToken, async status =>
                {
                    if (!ReferenceEquals(_pageHookMonitorCancellation, cancellation)) return;
                    _lastPageHookStatus = status;
                    _lastPageHookStatusAt = DateTimeOffset.UtcNow;
                    await Dispatcher.InvokeAsync(() =>
                    {
                        if (!ReferenceEquals(_pageHookMonitorCancellation, cancellation)) return;
                        PageHookAttachStatusText.Text = status.BrowserReachable
                            ? $"已挂载 {status.InjectedTargetCount}/{status.ActiveTargetCount} 个目标" +
                              (status.WorkerTargetCount > 0
                                  ? $" · Worker {status.InjectedWorkerTargetCount}/{status.WorkerTargetCount}"
                                  : string.Empty) +
                              (status.FailedTargetCount > 0 ? $" · {status.FailedTargetCount} 个待重试" : string.Empty)
                            : "等待浏览器页面…";
                        PageHookAttachStatusText.Foreground = status.BrowserReachable && status.InjectedTargetCount > 0 ? Green : Amber;
                    });
                    if (status.NewlyInjectedCount > 0)
                        await new WorkspaceStore(_workspacePath).AppendAuditAsync(AuditEventPageHookInjected,
                            new { debuggingPort, hookPort = _hookReceivePort, newlyInjected = status.NewlyInjectedCount, activeTargets = status.ActiveTargetCount });
                }, cancellationToken: cancellation.Token, environmentProfile: _settings.BrowserEnvironment);
            }
            catch (OperationCanceledException) when (cancellation.IsCancellationRequested) { }
            catch (Exception exception)
            {
                if (!ReferenceEquals(_pageHookMonitorCancellation, cancellation)) return;
                await Dispatcher.InvokeAsync(() =>
                {
                    PageHookAttachStatusText.Text = "页内 Hook 挂载失败 · 抓包不受影响";
                    PageHookAttachStatusText.ToolTip = exception.Message;
                    PageHookAttachStatusText.Foreground = Red;
                });
            }
        });
    }

    private void StopPageHookMonitor()
    {
        var cancellation = _pageHookMonitorCancellation;
        var task = _pageHookMonitorTask;
        _pageHookMonitorCancellation = null;
        _pageHookMonitorTask = null;
        _lastPageHookStatus = null;
        _lastPageHookStatusAt = null;
        if (cancellation is null) return;
        cancellation.Cancel();
        _ = (task ?? Task.CompletedTask).ContinueWith(_ => cancellation.Dispose(), TaskScheduler.Default);
        if (PageHookAttachStatusText is not null)
        {
            PageHookAttachStatusText.Text = "浏览器尚未挂载";
            PageHookAttachStatusText.ToolTip = null;
            PageHookAttachStatusText.Foreground = Amber;
        }
    }

    /// <summary>
    /// 底层静默抓包：以提升权限（UAC runas）启动 CoreHost silent。提升后无法重定向 stdout，
    /// 改为轮询采集后台写入的就绪信号文件（silent-ready.json）判定就绪/失败；
    /// 用户取消 UAC 时 Process.Start 抛 Win32Exception，按取消处理并提示。
    /// </summary>
    private async Task StartSilentCaptureAsync(string coreHostExecutable)
    {
        if (!File.Exists(coreHostExecutable))
        {
            MessageBox.Show(this, "静默抓包需要以提升权限方式启动 NetMind.CoreHost.exe，未找到该可执行文件。\n\n请重新构建工作台项目后重试。", "无法开始静默抓包", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        var signalDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), SettingsDirectoryName);
        var readyPath = Path.Combine(signalDirectory, SilentReadyFileName);
        try { File.Delete(readyPath); } catch { /* 旧就绪信号删除失败不阻断启动，后台写时覆盖 */ }
        // 隐藏控制台窗口：ShellExecute 会将 WindowStyle 映射为 nShowCmd，runas 提升后同样生效；
        // 停止与就绪均走信号文件，黑框无任何交互价值。
        var startInfo = new ProcessStartInfo(coreHostExecutable) { UseShellExecute = true, Verb = "runas", WindowStyle = ProcessWindowStyle.Hidden };
        foreach (var argument in new[] { "silent", "--workspace", _workspacePath,
                     "--hook-port", _hookReceivePort.ToString(), "--hook-token", _hookReceiveToken })
            startInfo.ArgumentList.Add(argument);
        if (_silentProcessFilter is not null)
        {
            startInfo.ArgumentList.Add("--process-name");
            startInfo.ArgumentList.Add(_silentProcessFilter);
        }
        Process process;
        try { process = Process.Start(startInfo) ?? throw new InvalidOperationException("无法启动提升权限的采集后台。"); }
        catch (Win32Exception exception)
        {
            // UAC 提示被取消或提升失败：保持就绪状态，不进入采集中。
            CaptureState.Text = "静默抓包未启动 · 管理员权限提示已取消";
            CaptureState.Foreground = Amber;
            MessageBox.Show(this, $"无法以提升权限启动静默抓包：\n\n{exception.Message}", "无法开始静默抓包", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        _coreHostProcess = process;
        try
        {
            // 轮询就绪信号文件直到读到 ready/failed 或超时；后台进程提前退出（驱动加载失败等）也立即报错。
            var deadline = Environment.TickCount64 + 15000;
            while (true)
            {
                if (File.Exists(readyPath))
                {
                    using var document = JsonDocument.Parse(await File.ReadAllTextAsync(readyPath));
                    var state = document.RootElement.TryGetProperty("state", out var stateProperty) ? stateProperty.GetString() : null;
                    var error = document.RootElement.TryGetProperty("error", out var errorProperty) ? errorProperty.GetString() : null;
                    // 会话标识用于把列表限定到本次采集；旧版信号文件没有该字段时退化为不限定。
                    if (document.RootElement.TryGetProperty("sessionId", out var sessionProperty) &&
                        Guid.TryParse(sessionProperty.GetString(), out var liveSession) && liveSession != Guid.Empty)
                        _liveCaptureSessionId = liveSession;
                    if (state == "ready") break;
                    throw new InvalidOperationException(string.IsNullOrWhiteSpace(error) ? "静默抓包后台启动失败。" : error!);
                }
                if (process.HasExited) throw new InvalidOperationException("静默抓包后台意外退出（可能是驱动文件缺失或权限不足）。");
                if (Environment.TickCount64 > deadline) throw new TimeoutException("等待静默抓包就绪信号超时。");
                await Task.Delay(300);
            }
            _silentCaptureActive = true;
            _capturing = true;
            ResumeLiveTrafficView();
            SettingsListenPortBox.IsEnabled = false;
            _showingDemoData = false;
            CaptureButton.Content = "停止采集";
            CaptureButton.Background = Red;
            CaptureState.Text = "底层静默抓包中 · WinDivert 透明捕获";
            CaptureState.Foreground = Accent;
            if (IsProcessAlive(_captureBrowserProcess) && _captureBrowserDebuggingPort > 0)
                StartPageHookMonitor(_captureBrowserDebuggingPort);
            _captureTimer.Start();
            UpdateModeText();
            await RefreshStoredTrafficAsync();
        }
        catch (Exception exception)
        {
            try { if (!process.HasExited) process.Kill(entireProcessTree: true); } catch { /* 进程可能已退出 */ }
            process.Dispose();
            _coreHostProcess = null;
            MessageBox.Show(this, $"静默抓包启动失败：\n\n{exception.Message}", "无法开始静默抓包", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private async Task StopCoreHostAsync()
    {
        _captureTimer.Stop();
        StopPageHookMonitor();
        _hookReceivePort = 0;
        _hookReceiveToken = string.Empty;
        // 静默抓包未接管系统代理；仅代理模式需要还原，避免静默模式下误报。
        var proxyOutcome = _silentCaptureActive ? default : await RestoreSystemProxyIfTakenAsync();
        var wasSilent = _silentCaptureActive;
        var stopSignalPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), SettingsDirectoryName, SilentStopFileName);
        var process = _coreHostProcess;
        _coreHostProcess = null;
        if (process is not null)
        {
            try
            {
                if (!process.HasExited)
                {
                    if (wasSilent)
                    {
                        // 提升权限进程无法使用 stdin：以停止信号文件通信，后台完成会话结算后自行退出；超时仍强杀。
                        try { File.WriteAllText(stopSignalPath, DateTimeOffset.UtcNow.ToString("O")); }
                        catch { /* 信号文件写入失败退化为超时强杀路径 */ }
                        await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10));
                    }
                    else
                    {
                        await process.StandardInput.WriteLineAsync("停止");
                        await process.StandardInput.FlushAsync();
                        // 停止窗口放宽到 8 秒：采集后台需在其内完成钩子引擎优雅关停
                        // （限时清队 flush 后发 shutdown，各任务等待已压缩到秒级）；超时仍强杀进程树。
                        await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(8));
                    }
                }
            }
            catch { if (!process.HasExited) process.Kill(entireProcessTree: true); }
            finally { process.Dispose(); }
        }
        _capturing = false;
        _silentCaptureActive = false;
        _silentProcessFilter = null;
        SettingsListenPortBox.IsEnabled = true;
        CaptureButton.Content = "开始采集";
        CaptureButton.SetResourceReference(BackgroundProperty, "AccentBrush");
        switch (proxyOutcome)
        {
            case SystemProxyRestoreOutcome.Restored:
                CaptureState.Text = "采集器就绪 · 系统代理已还原";
                CaptureState.Foreground = Green;
                break;
            case SystemProxyRestoreOutcome.Failed:
                CaptureState.Text = "采集已停止 · 系统代理还原失败，请手工还原";
                CaptureState.Foreground = Red;
                break;
            default:
                CaptureState.Text = wasSilent ? "静默抓包已停止 · 采集器就绪" : "采集器就绪";
                CaptureState.Foreground = Green;
                break;
        }
        UpdateModeText();
        await ApplySavedWorkspacePolicyAfterStopAsync();
        await RefreshStoredTrafficAsync(force: true);
    }

    /// <summary>
    /// 无感抓包：功能开启时把系统代理接管到回环监听端口。
    /// 先读取接管前快照并原子写入哨兵文件，再应用新代理；哨兵删除条件收窄为仅 Apply 之前/失败时，
    /// Apply 成功后的审计失败仅降级提示，绝不删除哨兵（否则系统代理不可还原）。
    /// </summary>
    private async Task TryTakeOverSystemProxyAsync()
    {
        if (!_settings.SystemProxyAutomation)
        {
            // 开关关闭早退不再静默：状态栏明确提示未接管原因，避免“勾选后未保存/未生效”的困惑。
            CaptureState.Text += " · 无感抓包未开启（不接管系统代理）";
            return;
        }
        if (File.Exists(_systemProxySentinelPath)) return; // 已接管（重入场景），避免把被接管的设置误存为原始快照
        var targetServer = $"{LoopbackAddress}:{_settings.ListenPort}";
        SystemProxySnapshot original;
        try
        {
            original = SystemProxyAutomation.Read();
            await SystemProxySentinel.WriteAsync(_systemProxySentinelPath, original);
        }
        catch (Exception exception)
        {
            // Apply 之前失败：哨兵至多刚写入，删除以保持“无哨兵 = 未接管”语义。
            SystemProxySentinel.Delete(_systemProxySentinelPath);
            ShowTakeOverFailure(exception.Message, targetServer);
            return;
        }
        // 接管前若检测到其他已启用的系统代理（如其他代理工具），仅告知不阻断：停止采集时会按快照还原。
        if (SystemProxyAutomation.HasExplicitProxy(original)
            && original.Server is not null
            && !string.Equals(original.Server, targetServer, StringComparison.OrdinalIgnoreCase))
        {
            CaptureState.Text += $" · 检测到已有系统代理（{original.Server}），接管后将在停止采集时自动还原";
        }
        try
        {
            SystemProxyAutomation.Apply(targetServer, SystemProxyLocalBypass);
        }
        catch (Exception exception)
        {
            // Apply 失败：接管未生效，删除哨兵回退为手工代理模式。
            SystemProxySentinel.Delete(_systemProxySentinelPath);
            ShowTakeOverFailure(exception.Message, targetServer);
            return;
        }
        // Apply 已成功：接管事实成立，审计与接管成败解耦——审计失败仅降级提示，哨兵必须保留供停止时还原。
        try
        {
            await new WorkspaceStore(_workspacePath).AppendAuditAsync(AuditEventSystemProxyApplied, new
            {
                server = targetServer,
                bypass = SystemProxyLocalBypass,
                originalFlags = original.Flags,
                originalServer = original.Server,
                originalBypass = original.Bypass
            });
            CaptureState.Text += " · 系统代理已接管";
        }
        catch (Exception auditException)
        {
            CaptureState.Text += " · 系统代理已接管（审计写入失败）";
            CaptureState.Foreground = Amber;
            MessageBox.Show(this, $"系统代理已成功接管，但接管审计写入失败，不影响采集与停止时的自动还原：\n\n{auditException.Message}", "审计写入失败", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    /// <summary>接管失败统一提示：采集继续以手工代理模式运行，不阻塞采集。</summary>
    private void ShowTakeOverFailure(string reason, string targetServer)
    {
        CaptureState.Text += " · 系统代理接管失败（手工代理模式）";
        CaptureState.Foreground = Amber;
        MessageBox.Show(this, $"自动接管系统代理失败，采集继续以手工代理模式运行：\n\n{reason}\n\n如需继续采集系统流量，可手动把 Windows 系统代理指向 {targetServer}。", "系统代理接管失败", MessageBoxButton.OK, MessageBoxImage.Warning);
    }

    /// <summary>
    /// 无感抓包：若存在接管哨兵则按快照还原系统代理并删除哨兵；
    /// 还原失败保留哨兵供下次启动检测，并记录审计与手工还原指引。
    /// </summary>
    private async Task<SystemProxyRestoreOutcome> RestoreSystemProxyIfTakenAsync()
    {
        var snapshot = await SystemProxySentinel.TryReadAsync(_systemProxySentinelPath);
        if (snapshot is null) return SystemProxyRestoreOutcome.NotTaken;
        try
        {
            SystemProxyAutomation.Restore(snapshot);
            SystemProxySentinel.Delete(_systemProxySentinelPath);
            await new WorkspaceStore(_workspacePath).AppendAuditAsync(AuditEventSystemProxyRestored, new
            {
                source = "会话停止",
                restoredFlags = snapshot.Flags,
                restoredServer = snapshot.Server,
                restoredBypass = snapshot.Bypass
            });
            return SystemProxyRestoreOutcome.Restored;
        }
        catch (Exception exception)
        {
            try { await new WorkspaceStore(_workspacePath).AppendAuditAsync(AuditEventSystemProxyRestoreFailed, new { source = "会话停止", error = exception.Message }); }
            catch { /* 审计写入失败不阻断还原失败提示 */ }
            MessageBox.Show(this, $"系统代理还原失败：\n\n{exception.Message}\n\n手工还原指引：打开 Windows 设置 → 网络和 Internet → 代理，关闭“使用代理服务器”，或删除指向 {LoopbackAddress}:{_settings.ListenPort} 的代理配置。", "系统代理还原失败", MessageBoxButton.OK, MessageBoxImage.Error);
            return SystemProxyRestoreOutcome.Failed;
        }
    }

    /// <summary>
    /// 应用启动时检测异常退出遗留的接管哨兵；用户确认后还原系统代理并删除哨兵。
    /// </summary>
    private async Task DetectLeftoverSystemProxyTakeoverAsync()
    {
        var snapshot = await SystemProxySentinel.TryReadAsync(_systemProxySentinelPath);
        if (snapshot is null) return;
        var answer = MessageBox.Show(this,
            "检测到上次异常退出时系统代理已被 NetMind 接管。\n\n是否立即还原为接管前的系统代理设置？\n（选择“否”将保留现状，之后可在 Windows 代理设置中手工还原）",
            "系统代理接管残留", MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (answer != MessageBoxResult.Yes) return;
        try
        {
            SystemProxyAutomation.Restore(snapshot);
            SystemProxySentinel.Delete(_systemProxySentinelPath);
            await new WorkspaceStore(_workspacePath).AppendAuditAsync(AuditEventSystemProxyRestored, new
            {
                source = "启动残留检测",
                restoredFlags = snapshot.Flags,
                restoredServer = snapshot.Server,
                restoredBypass = snapshot.Bypass
            });
            if (!_capturing)
            {
                CaptureState.Text = "采集器就绪 · 系统代理已还原";
                CaptureState.Foreground = Green;
            }
        }
        catch (Exception exception)
        {
            try { await new WorkspaceStore(_workspacePath).AppendAuditAsync(AuditEventSystemProxyRestoreFailed, new { source = "启动残留检测", error = exception.Message }); }
            catch { /* 审计写入失败不阻断还原失败提示 */ }
            MessageBox.Show(this, $"系统代理还原失败：\n\n{exception.Message}\n\n手工还原指引：打开 Windows 设置 → 网络和 Internet → 代理，关闭“使用代理服务器”，或删除指向 {LoopbackAddress}:{_settings.ListenPort} 的代理配置。", "系统代理还原失败", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private async Task InitializeWorkspaceAsync()
    {
        try
        {
            var catalog = new WorkspaceCatalog(_workspaceRoot);
            var current = await catalog.GetCurrentAsync();
            if (current is null)
            {
                current = await catalog.ImportLegacyAsync("northstar-lab", "北辰实验室");
                await catalog.SetCurrentAsync(current);
            }
            else if (current.Id == "northstar-lab" && current.Manifest.Name.Equals("Northstar Lab", StringComparison.OrdinalIgnoreCase))
            {
                current = await catalog.RenameAsync(current, "北辰实验室");
                await catalog.SetCurrentAsync(current);
            }
            await LoadAiSettingsAsync();
            await ActivateWorkspaceAsync(current, persistSelection: false);
            await DetectLeftoverSystemProxyTakeoverAsync();
        }
        catch (Exception exception)
        {
            CaptureState.Text = "工作区初始化受限";
            CaptureState.ToolTip = exception.Message;
        }
    }

    private async Task ActivateWorkspaceAsync(WorkspaceDescriptor workspace, bool persistSelection = true)
    {
        if (_capturing) throw new InvalidOperationException("请先停止采集，再切换工作区。");
        if (_aiCancellation is not null) throw new InvalidOperationException("请先取消正在运行的 AI 分析，再切换工作区。");
        var catalog = new WorkspaceCatalog(_workspaceRoot);
        if (persistSelection) await catalog.SetCurrentAsync(workspace);

        _currentWorkspace = workspace;
        _workspacePath = workspace.Path;
        WorkspaceTitleText.Text = workspace.Manifest.Name;
        SidebarWorkspaceNameText.Text = workspace.Manifest.Name;
        WorkspaceNameBox.Text = workspace.Manifest.Name;
        WorkspacePathText.Text = workspace.Path;
        WorkspaceActionStatusText.Text = "当前工作区已载入";
        WorkspaceActionStatusText.Foreground = Green;
        RefreshTlsInspectionState();

        _refreshPaused = false;
        _pendingRefreshCount = 0;
        _hasLoadedStoredTraffic = false;
        _trafficRefreshCursor = 0;
        _showingDemoData = false;
        _preferredTrafficId = null;
        _sessionFilterId = null;
        // 会话标识属于旧工作区，跨工作区复用会把新工作区筛成空列表。
        _liveCaptureSessionId = null;
        _trafficScopeSessionId = null;
        _aiSelectedTrafficIds.Clear();
        ClearGroupAiScope();
        _currentAiHistoryEntry = null;
        _currentAiMarkdown = string.Empty;
        AiHistoryRows.Clear();
        AiLegacyHistoryList.SelectedItem = null;
        CopyAiResultButton.IsEnabled = ExportAiResultButton.IsEnabled = DeleteAiHistoryButton.IsEnabled = false;
        AiConversationRows.Clear();
        _openConversationHeader = null;
        _openConversationHistory = [];
        _openEvidenceProvider = null;
        _aiVisibleTurnLimit = AiTurnRenderPageSize;
        DeleteAiConversationButton.IsEnabled = false;
        ExportAiConversationButton.IsEnabled = false;
        AiQuickFollowUpPanel.IsEnabled = false;
        SessionFilterBadge.Visibility = Visibility.Collapsed;
        TrafficSearch.Clear();
        SourceFilter.SelectedIndex = 0;
        StatusFilter.SelectedIndex = 0;
        ResetResourceTypeFilters();
        Sessions.Clear();
        SessionCountText.Text = "暂无捕获会话";
        ReplaceTraffic([], 0, new Dictionary<Guid, StoredTrafficRecord>());
        ClearTrafficGroupEditor();
        // 工作区切换：取消未完成的证据加载并清空 JSON 树缓存，禁止旧工作区对象跨工作区复用。
        _evidenceLoadCts?.Cancel();
        _evidenceLoadCts?.Dispose();
        _evidenceLoadCts = null;
        ClearJsonTreeCache();

        using (var archive = new TrafficArchive(_workspacePath)) { }
        await RefreshStoredTrafficAsync(force: true);
        await LoadTrafficGroupsAsync();
        await LoadAiPromptCatalogAsync();
        ShowAiEmptyHint();
        await LoadAiConversationsAsync();
        await LoadAiHistoryAsync();
        await LoadScriptWorkspaceAsync();
        await RefreshWorkspaceDataStatusAsync();
        await ReloadWorkspaceCatalogAsync(workspace.Id);
        await new WorkspaceStore(_workspacePath).AppendAuditAsync("workspace.opened", new { workspace.Id });
    }

    private async Task ReloadWorkspaceCatalogAsync(string? selectedId = null)
    {
        var catalog = new WorkspaceCatalog(_workspaceRoot);
        var descriptors = await catalog.GetAllAsync();
        Workspaces.Clear();
        foreach (var descriptor in descriptors) Workspaces.Add(new WorkspaceRow(descriptor));
        WorkspaceCountText.Text = $"{Workspaces.Count:N0} 个工作区";
        selectedId ??= _currentWorkspace?.Id;
        WorkspaceCombo.SelectedItem = selectedId is null ? Workspaces.FirstOrDefault() : Workspaces.FirstOrDefault(row => row.Source.Id == selectedId);
    }

    private async Task RefreshWorkspaceDataStatusAsync()
    {
        try
        {
            var policyTask = new WorkspaceDataPolicyStore(_workspacePath).LoadAsync();
            var statisticsTask = Task.Run(() => WorkspaceDataMaintenance.GetStatistics(_workspacePath));
            var policy = await policyTask;
            var statistics = await statisticsTask;
            SelectComboByTag(WorkspaceRetentionCombo, policy.RetentionDays.ToString());
            var capacityGb = policy.MaximumWorkspaceBytes == 0 ? 0 : policy.MaximumWorkspaceBytes / (1024L * 1024 * 1024);
            SelectComboByTag(WorkspaceCapacityCombo, capacityGb.ToString());
            WorkspaceDataStatusText.Text = $"占用 {FormatStorageBytes(statistics.TotalBytes)} · 正文 {FormatStorageBytes(statistics.BlobBytes)} · " +
                                           $"SQLite {FormatStorageBytes(statistics.MetadataBytes)} · AI {FormatStorageBytes(statistics.AiBytes)} · " +
                                           $"事务 {statistics.TrafficCount:N0} · Hook {statistics.PageHookCount:N0}";
            WorkspaceDataStatusText.Foreground = Muted;
        }
        catch (Exception exception)
        {
            WorkspaceDataStatusText.Text = "工作区容量读取失败：" + exception.Message;
            WorkspaceDataStatusText.Foreground = Red;
        }
    }

    private WorkspaceDataPolicy ReadWorkspaceDataPolicyFromUi()
    {
        var retentionText = (WorkspaceRetentionCombo.SelectedItem as ComboBoxItem)?.Tag?.ToString() ?? "0";
        var capacityText = (WorkspaceCapacityCombo.SelectedItem as ComboBoxItem)?.Tag?.ToString() ?? "0";
        if (!int.TryParse(retentionText, out var retentionDays) || !long.TryParse(capacityText, out var capacityGb))
            throw new InvalidOperationException("工作区数据策略选项无效。");
        return new WorkspaceDataPolicy(retentionDays, checked(capacityGb * 1024L * 1024 * 1024)).Validate();
    }

    private async void 保存数据策略_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var policy = ReadWorkspaceDataPolicyFromUi();
            if (policy.RetentionDays > 0 || policy.MaximumWorkspaceBytes > 0)
            {
                var answer = MessageBox.Show(this,
                    "保存后，每次停止采集会自动应用该项目的数据策略：删除超出期限或容量上限的最旧流量及其无引用正文。\n\n" +
                    "AI 会话、记录组定义和配置不会自动删除。是否继续？",
                    "确认数据保留策略", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);
                if (answer != MessageBoxResult.Yes) return;
            }
            await new WorkspaceDataPolicyStore(_workspacePath).SaveAsync(policy);
            await new WorkspaceStore(_workspacePath).AppendAuditAsync("workspace.data-policy.updated",
                new { policy.RetentionDays, policy.MaximumWorkspaceBytes });
            WorkspaceDataStatusText.Text = policy.RetentionDays == 0 && policy.MaximumWorkspaceBytes == 0
                ? "数据策略已保存：永久保留，不限制容量"
                : "数据策略已保存；将在停止采集或点击“立即整理”时应用";
            WorkspaceDataStatusText.Foreground = Green;
        }
        catch (Exception exception)
        {
            WorkspaceDataStatusText.Text = "保存数据策略失败：" + exception.Message;
            WorkspaceDataStatusText.Foreground = Red;
        }
    }

    private async void 立即整理工作区_Click(object sender, RoutedEventArgs e)
    {
        if (_capturing || _aiCancellation is not null)
        {
            WorkspaceDataStatusText.Text = "请先停止采集并结束 AI 分析，再整理工作区";
            WorkspaceDataStatusText.Foreground = Amber;
            return;
        }
        var answer = MessageBox.Show(this,
            "将立即应用当前界面中的保留期限和容量上限，并清理无引用正文、压缩 SQLite。\n\n" +
            "超出策略的原始流量无法恢复，建议先备份工作区。是否继续？",
            "确认整理工作区", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);
        if (answer != MessageBoxResult.Yes) return;
        try
        {
            var policy = ReadWorkspaceDataPolicyFromUi();
            WorkspaceDataStatusText.Text = "正在整理工作区…";
            WorkspaceDataStatusText.Foreground = Amber;
            var result = await Task.Run(async () => await WorkspaceDataMaintenance.RunAsync(_workspacePath, policy));
            await RefreshStoredTrafficAsync(force: true);
            await LoadTrafficGroupsAsync();
            await RefreshWorkspaceDataStatusAsync();
            WorkspaceDataStatusText.Text += $" · 本次删除 {result.DeletedTransactions:N0} 条事务 / {result.DeletedPageHooks:N0} 条 Hook，回收 {FormatStorageBytes(result.ReclaimedBytes)}" +
                                            (result.CapacitySatisfied ? string.Empty : " · 非流量文件仍使容量高于上限");
            WorkspaceDataStatusText.Foreground = result.CapacitySatisfied ? Green : Amber;
        }
        catch (Exception exception)
        {
            WorkspaceDataStatusText.Text = "整理工作区失败：" + exception.Message;
            WorkspaceDataStatusText.Foreground = Red;
        }
    }

    private async void 备份工作区_Click(object sender, RoutedEventArgs e)
    {
        if (_capturing || _aiCancellation is not null)
        {
            WorkspaceDataStatusText.Text = "请先停止采集并结束 AI 分析，再创建一致性备份";
            WorkspaceDataStatusText.Foreground = Amber;
            return;
        }
        var safeName = string.Join("_", (_currentWorkspace?.Manifest.Name ?? "NetMind-Workspace")
            .Split(Path.GetInvalidFileNameChars(), StringSplitOptions.RemoveEmptyEntries));
        var dialog = new SaveFileDialog
        {
            Title = "备份完整工作区（包含原始敏感证据）",
            Filter = "NetMind 工作区备份 (*.zip)|*.zip",
            DefaultExt = ".zip",
            AddExtension = true,
            FileName = safeName + "-backup-" + DateTimeOffset.Now.ToString("yyyyMMdd-HHmmss") + ".zip"
        };
        if (dialog.ShowDialog(this) != true) return;
        try
        {
            WorkspaceDataStatusText.Text = "正在创建完整工作区备份…";
            WorkspaceDataStatusText.Foreground = Amber;
            var result = await Task.Run(async () => await WorkspaceBackup.ExportAsync(_workspacePath, dialog.FileName));
            WorkspaceDataStatusText.Text = $"备份完成：{result.FileCount:N0} 个文件 · {FormatStorageBytes(result.UncompressedBytes)}";
            WorkspaceDataStatusText.Foreground = Green;
        }
        catch (Exception exception)
        {
            WorkspaceDataStatusText.Text = "备份失败：" + exception.Message;
            WorkspaceDataStatusText.Foreground = Red;
        }
    }

    private async void 导入工作区备份_Click(object sender, RoutedEventArgs e)
    {
        if (_capturing || _aiCancellation is not null)
        {
            WorkspaceDataStatusText.Text = "请先停止采集并结束 AI 分析，再导入备份";
            WorkspaceDataStatusText.Foreground = Amber;
            return;
        }
        var dialog = new OpenFileDialog { Title = "导入 NetMind 工作区备份", Filter = "NetMind 工作区备份 (*.zip)|*.zip" };
        if (dialog.ShowDialog(this) != true) return;
        try
        {
            WorkspaceDataStatusText.Text = "正在校验并导入备份…";
            WorkspaceDataStatusText.Foreground = Amber;
            var imported = await Task.Run(async () => await WorkspaceBackup.ImportAsync(dialog.FileName, _workspaceRoot));
            await ActivateWorkspaceAsync(imported);
            WorkspaceActionStatusText.Text = "备份已导入为新的独立工作区";
            WorkspaceActionStatusText.Foreground = Green;
        }
        catch (Exception exception)
        {
            WorkspaceDataStatusText.Text = "导入备份失败：" + exception.Message;
            WorkspaceDataStatusText.Foreground = Red;
        }
    }

    private async Task ApplySavedWorkspacePolicyAfterStopAsync()
    {
        try
        {
            var policy = await new WorkspaceDataPolicyStore(_workspacePath).LoadAsync();
            if (policy.RetentionDays == 0 && policy.MaximumWorkspaceBytes == 0) return;
            WorkspaceDataStatusText.Text = "采集已停止，正在应用数据保留策略…";
            WorkspaceDataStatusText.Foreground = Amber;
            var result = await Task.Run(async () => await WorkspaceDataMaintenance.RunAsync(_workspacePath, policy));
            await LoadTrafficGroupsAsync();
            await RefreshWorkspaceDataStatusAsync();
            if (!result.CapacitySatisfied)
            {
                WorkspaceDataStatusText.Text += " · 非流量文件仍使容量高于上限";
                WorkspaceDataStatusText.Foreground = Amber;
            }
        }
        catch (Exception exception)
        {
            WorkspaceDataStatusText.Text = "自动数据整理失败：" + exception.Message;
            WorkspaceDataStatusText.Foreground = Red;
        }
    }

    private async void 更改工作区目录_Click(object sender, RoutedEventArgs e)
    {
        if (_capturing)
        {
            WorkspaceActionStatusText.Text = "请先停止采集，再更改存储目录";
            WorkspaceActionStatusText.Foreground = Amber;
            return;
        }
        if (_aiCancellation is not null)
        {
            WorkspaceActionStatusText.Text = "请先取消正在运行的 AI 分析";
            WorkspaceActionStatusText.Foreground = Amber;
            return;
        }

        var dialog = new Microsoft.Win32.OpenFolderDialog
        {
            Title = "选择 NetMind 工作区存储目录",
            InitialDirectory = Directory.Exists(_workspaceRoot) ? _workspaceRoot : DefaultWorkspaceRoot,
            Multiselect = false
        };
        if (dialog.ShowDialog(this) != true) return;

        string selectedRoot;
        try
        {
            selectedRoot = (_settings with { WorkspaceRootPath = dialog.FolderName }).Validate().WorkspaceRootPath!;
        }
        catch (Exception exception)
        {
            WorkspaceActionStatusText.Text = "目录无效：" + exception.Message;
            WorkspaceActionStatusText.Foreground = Red;
            return;
        }
        if (selectedRoot.Equals(_workspaceRoot, StringComparison.OrdinalIgnoreCase))
        {
            WorkspaceActionStatusText.Text = "当前已使用这个存储目录";
            WorkspaceActionStatusText.Foreground = Muted;
            return;
        }

        try
        {
            Directory.CreateDirectory(selectedRoot);
            var catalog = new WorkspaceCatalog(selectedRoot);
            var target = await catalog.GetCurrentAsync();
            if (target is null)
            {
                target = (await catalog.GetAllAsync()).FirstOrDefault();
                if (target is null) target = await catalog.CreateAsync("默认项目");
            }

            var previousRoot = _workspaceRoot;
            _workspaceRoot = selectedRoot;
            try { await ActivateWorkspaceAsync(target); }
            catch
            {
                _workspaceRoot = previousRoot;
                throw;
            }

            _settings = (_settings with { WorkspaceRootPath = selectedRoot }).Validate();
            await new WorkbenchSettingsStore(_settingsPath).SaveAsync(_settings);
            WorkspaceRootPathBox.Text = selectedRoot;
            WorkspaceActionStatusText.Text = "存储目录已切换；旧目录数据保持原样";
            WorkspaceActionStatusText.Foreground = Green;
        }
        catch (Exception exception)
        {
            WorkspaceRootPathBox.Text = _workspaceRoot;
            WorkspaceActionStatusText.Text = "切换目录失败：" + exception.Message;
            WorkspaceActionStatusText.Foreground = Red;
        }
    }

    private async void 切换工作区_Click(object sender, RoutedEventArgs e)
    {
        if (WorkspaceCombo.SelectedItem is not WorkspaceRow selected)
        {
            WorkspaceActionStatusText.Text = "请先选择要切换的工作区";
            WorkspaceActionStatusText.Foreground = Amber;
            return;
        }
        if (_currentWorkspace?.Id == selected.Source.Id)
        {
            WorkspaceActionStatusText.Text = "当前已经是该工作区";
            WorkspaceActionStatusText.Foreground = Muted;
            return;
        }
        try { await ActivateWorkspaceAsync(selected.Source); }
        catch (Exception exception)
        {
            WorkspaceActionStatusText.Text = "切换失败：" + exception.Message;
            WorkspaceActionStatusText.Foreground = Red;
        }
    }

    private async void 新建工作区_Click(object sender, RoutedEventArgs e)
    {
        if (_capturing)
        {
            WorkspaceActionStatusText.Text = "请先停止采集，再新建并切换工作区";
            WorkspaceActionStatusText.Foreground = Amber;
            return;
        }
        try
        {
            var catalog = new WorkspaceCatalog(_workspaceRoot);
            var workspace = await catalog.CreateAsync(WorkspaceNameBox.Text);
            await ActivateWorkspaceAsync(workspace);
            WorkspaceActionStatusText.Text = "新工作区已创建并切换";
            WorkspaceActionStatusText.Foreground = Green;
        }
        catch (Exception exception)
        {
            WorkspaceActionStatusText.Text = "新建失败：" + exception.Message;
            WorkspaceActionStatusText.Foreground = Red;
        }
    }

    private async void 重命名工作区_Click(object sender, RoutedEventArgs e)
    {
        if (_currentWorkspace is null) return;
        try
        {
            var catalog = new WorkspaceCatalog(_workspaceRoot);
            var renamed = await catalog.RenameAsync(_currentWorkspace, WorkspaceNameBox.Text);
            _currentWorkspace = renamed;
            await catalog.SetCurrentAsync(renamed);
            WorkspaceTitleText.Text = SidebarWorkspaceNameText.Text = renamed.Manifest.Name;
            await ReloadWorkspaceCatalogAsync(renamed.Id);
            await new WorkspaceStore(_workspacePath).AppendAuditAsync("workspace.renamed", new { renamed.Id, renamed.Manifest.Name });
            WorkspaceActionStatusText.Text = "当前工作区已重命名";
            WorkspaceActionStatusText.Foreground = Green;
        }
        catch (Exception exception)
        {
            WorkspaceActionStatusText.Text = "重命名失败：" + exception.Message;
            WorkspaceActionStatusText.Foreground = Red;
        }
    }

    private void RefreshTlsInspectionState()
    {
        try
        {
            using var authority = new WorkspaceCertificateAuthority(_workspacePath);
            var policyStore = new TlsInspectionPolicyStore(_workspacePath);
            var policy = policyStore.Load();
            _tlsInspectionEnabled = authority.IsEnabledAndTrusted();
            TlsInspectionStatusText.Text = _tlsInspectionEnabled
                ? $"HTTPS 正文抓取已启用 · {policy.BypassHosts.Count} 条域名加密直通"
                : $"HTTPS 正文抓取已关闭 · 已配置 {policy.BypassHosts.Count} 条直通规则";
            TlsInspectionStatusText.Foreground = _tlsInspectionEnabled ? Green : Muted;
            EnableTlsInspectionButton.IsEnabled = !_tlsInspectionEnabled;
            DisableTlsInspectionButton.IsEnabled = _tlsInspectionEnabled;
            TlsBypassHostsBox.Text = TlsInspectionPolicyStore.ToEditingText(policy);
        }
        catch (Exception exception)
        {
            _tlsInspectionEnabled = false;
            TlsInspectionStatusText.Text = "HTTPS 解密状态读取失败";
            TlsInspectionStatusText.ToolTip = exception.Message;
            TlsInspectionStatusText.Foreground = Red;
        }
    }

    private async void 保存HTTPS直通规则_Click(object sender, RoutedEventArgs e)
    {
        if (_capturing)
        {
            MessageBox.Show(this, "请先停止采集，再修改 HTTPS 加密直通域名。", "采集正在运行", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        try
        {
            var policy = new TlsInspectionPolicyStore(_workspacePath).SaveFromText(TlsBypassHostsBox.Text);
            await new WorkspaceStore(_workspacePath).AppendAuditAsync("tls-inspection.bypass-policy.updated", new { ruleCount = policy.BypassHosts.Count });
            RefreshTlsInspectionState();
            TlsInspectionStatusText.ToolTip = policy.BypassHosts.Count == 0
                ? "没有配置加密直通域名。"
                : "匹配的域名保持端到端加密，只记录 CONNECT 元数据。修改将在下次开始采集时生效。";
        }
        catch (Exception exception)
        {
            TlsInspectionStatusText.Text = "保存 HTTPS 直通规则失败";
            TlsInspectionStatusText.ToolTip = exception.Message;
            TlsInspectionStatusText.Foreground = Red;
        }
    }

    private async void 启用HTTPS解密_Click(object sender, RoutedEventArgs e)
    {
        if (_capturing)
        {
            MessageBox.Show(this, "请先停止采集，再启用 HTTPS 正文抓取。", "采集正在运行", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        var answer = MessageBox.Show(this,
            "启用后将生成工作区独立 CA，并把公钥证书加入当前 Windows 用户的受信任根证书。\n\n使用该工作区代理的 HTTP/1.1 HTTPS 流量将被解密并保存 URL、Header、Cookie 和正文。证书固定应用可能拒绝连接，停用时可撤销信任。\n\n是否继续？",
            "确认启用 HTTPS 正文抓取", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);
        if (answer != MessageBoxResult.Yes) return;
        EnableTlsInspectionButton.IsEnabled = false;
        try
        {
            using var authority = new WorkspaceCertificateAuthority(_workspacePath);
            var state = await Task.Run(authority.EnableAndTrust);
            await new WorkspaceStore(_workspacePath).AppendAuditAsync("tls-inspection.enabled", new { thumbprint = state.Thumbprint, scope = "CurrentUser" });
            RefreshTlsInspectionState();
            TlsInspectionStatusText.ToolTip = "CA 公钥：" + authority.PublicCertificatePath;
        }
        catch (Exception exception)
        {
            TlsInspectionStatusText.Text = "启用 HTTPS 正文抓取失败";
            TlsInspectionStatusText.ToolTip = exception.Message;
            TlsInspectionStatusText.Foreground = Red;
            EnableTlsInspectionButton.IsEnabled = true;
        }
    }

    private async void 停用HTTPS解密_Click(object sender, RoutedEventArgs e)
    {
        if (_capturing)
        {
            MessageBox.Show(this, "请先停止采集，再停用 HTTPS 正文抓取。", "采集正在运行", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        var answer = MessageBox.Show(this, "确认停用 HTTPS 正文抓取，并从当前用户受信任根证书中移除该工作区 CA？", "确认停用 HTTPS 解密", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);
        if (answer != MessageBoxResult.Yes) return;
        DisableTlsInspectionButton.IsEnabled = false;
        try
        {
            using var authority = new WorkspaceCertificateAuthority(_workspacePath);
            await Task.Run(authority.DisableAndRemoveTrust);
            await new WorkspaceStore(_workspacePath).AppendAuditAsync("tls-inspection.disabled", new { scope = "CurrentUser" });
            RefreshTlsInspectionState();
        }
        catch (Exception exception)
        {
            TlsInspectionStatusText.Text = "停用 HTTPS 正文抓取失败";
            TlsInspectionStatusText.ToolTip = exception.Message;
            TlsInspectionStatusText.Foreground = Red;
            DisableTlsInspectionButton.IsEnabled = true;
        }
    }

    private async Task RefreshStoredTrafficAsync(bool force = false)
    {
        if (_refreshing || !File.Exists(Path.Combine(_workspacePath, MetadataDatabaseFileName))) return;
        _refreshing = true;
        try
        {
            // 会话范围决定读取哪一批事务：采集期间限定为本次会话，下钻历史会话时限定为该会话，
            // 清除筛选后为 null（全部历史）。范围一旦变化就必须整窗重读并重置游标。
            var scope = _sessionFilterId;
            var scopeChanged = scope != _trafficScopeSessionId;
            if (_refreshPaused && !force && !scopeChanged)
            {
                var pausedCount = await Task.Run(() =>
                {
                    using var archive = new TrafficArchive(_workspacePath);
                    return archive.GetTrafficCount(scope);
                });
                _pendingRefreshCount = Math.Max(0, pausedCount - _capturedCount);
                UpdateRefreshPauseUi();
                return;
            }
            var reload = force || scopeChanged;
            var result = await Task.Run(() =>
            {
                using var archive = new TrafficArchive(_workspacePath);
                var count = archive.GetTrafficCount(scope);
                var sessions = archive.GetRecentSessions(_settings.SessionWindowCount);
                var latestCursor = archive.GetLatestTrafficCursor();
                if (reload || !_hasLoadedStoredTraffic || latestCursor < _trafficRefreshCursor || count < _capturedCount)
                    return (Count: count, Rows: archive.GetRecentTraffic(_settings.TrafficWindowCount, scope),
                        Changes: (IReadOnlyList<StoredTrafficChange>)[], Sessions: sessions, Cursor: latestCursor, Full: true);

                var changes = archive.GetTrafficChangesAfter(_trafficRefreshCursor, sessionId: scope);
                if (count > _capturedCount && changes.Count == 0)
                    return (Count: count, Rows: archive.GetRecentTraffic(_settings.TrafficWindowCount, scope),
                        Changes: (IReadOnlyList<StoredTrafficChange>)[], Sessions: sessions, Cursor: latestCursor, Full: true);
                // 一次轮询积压超过单批上限时直接读取最新窗口，避免漏过游标中间段。
                if (changes.Count == 2000 && changes[^1].Cursor < latestCursor)
                    return (Count: count, Rows: archive.GetRecentTraffic(_settings.TrafficWindowCount, scope),
                        Changes: (IReadOnlyList<StoredTrafficChange>)[], Sessions: sessions, Cursor: latestCursor, Full: true);
                return (Count: count, Rows: (IReadOnlyList<StoredTrafficRecord>)[], Changes: changes,
                    Sessions: sessions, Cursor: latestCursor, Full: false);
            });
            _trafficScopeSessionId = scope;
            if (result.Full && (result.Rows.Count > 0 || _capturing))
            {
                _showingDemoData = false;
                ReplaceTraffic(result.Rows.Select(item => item.Traffic), result.Count,
                    result.Rows.ToDictionary(item => item.Traffic.Id), preserveSelection: _hasLoadedStoredTraffic);
                _hasLoadedStoredTraffic = true;
            }
            else if (!result.Full && result.Changes.Count > 0)
            {
                _showingDemoData = false;
                var recent = _storedTraffic.Values.ToDictionary(item => item.Traffic.Id);
                foreach (var change in result.Changes) recent[change.Stored.Traffic.Id] = change.Stored;
                var window = recent.Values.OrderByDescending(item => item.Traffic.Timestamp)
                    .Take(_settings.TrafficWindowCount).ToArray();
                ReplaceTraffic(window.Select(item => item.Traffic), result.Count,
                    window.ToDictionary(item => item.Traffic.Id), preserveSelection: true);
                _hasLoadedStoredTraffic = true;
            }
            else if (!result.Full)
            {
                _capturedCount = result.Count;
                RequestMetric.Text = _capturedCount.ToString("N0");
                UpdateModeText();
            }
            _trafficRefreshCursor = result.Cursor;
            if (Sessions.Count != result.Sessions.Count ||
                Sessions.Where((row, index) => !row.Matches(result.Sessions[index])).Any())
            {
                Sessions.Clear();
                foreach (var session in result.Sessions) Sessions.Add(new SessionRow(session));
            }
            SessionCountText.Text = $"最近 {Sessions.Count} 次会话";
            _pendingRefreshCount = 0;
            UpdateRefreshPauseUi();
            // Hook 页处于可见状态时随采集定时器自动刷新，避免已入库但界面长期显示 0 条。
            if (ExploreSubTabs?.SelectedIndex == 1) await RefreshPageHooksAsync();
            if (MainTabs?.SelectedIndex == 4) await RefreshScriptHookRuntimeStatusAsync();
        }
        catch (Exception exception)
        {
            // 有界诊断：异步写一条审计，不阻塞 UI；诊断写入本身静默兜底，绝不抛出或递归。
            var workspacePath = _workspacePath;
            var errorType = exception.GetType().Name;
            var errorMessage = exception.Message.Length > 500 ? exception.Message[..500] : exception.Message;
            _ = Task.Run(async () =>
            {
                try
                {
                    await new WorkspaceStore(workspacePath).AppendAuditAsync("traffic-refresh-failed",
                        new { error = errorType, message = errorMessage });
                }
                catch { /* 诊断写入失败时保持静默 */ }
            });
        }
        finally { _refreshing = false; }
    }

    private async void 暂停刷新_Click(object sender, RoutedEventArgs e)
    {
        _refreshPaused = !_refreshPaused;
        _pendingRefreshCount = 0;
        UpdateRefreshPauseUi();
        if (_refreshPaused) return;
        RefreshPauseStatus.Text = "正在同步…";
        RefreshPauseStatus.Foreground = Accent;
        await RefreshStoredTrafficAsync(force: true);
    }

    private void UpdateRefreshPauseUi()
    {
        if (PauseRefreshButton is null || RefreshPauseStatus is null) return;
        PauseRefreshButton.Content = _refreshPaused ? "继续刷新" : "暂停刷新";
        RefreshPauseStatus.Text = _refreshPaused
            ? _pendingRefreshCount > 0 ? $"列表已固定 · 新增 {_pendingRefreshCount:N0} 条" : "列表已固定 · 采集仍在继续"
            : "实时刷新";
        RefreshPauseStatus.Foreground = _refreshPaused ? Muted : Green;
    }

    /// <summary>
    /// 新采集始终回到实时列表。暂停刷新与会话范围只属于上一次查看状态，若跨采集保留，
    /// 后端会持续入库但列表可能固定或被旧会话筛成 0 条，造成“代理没有流量”的假象。
    /// 搜索、资源类型等用户主动配置仍保留。
    /// </summary>
    private void ResumeLiveTrafficView()
    {
        _refreshPaused = false;
        _pendingRefreshCount = 0;
        // 每次开始采集都从空列表起步：把视图限定到本次捕获会话，而不是先加载历史事务。
        // 拿不到会话标识（旧版 CoreHost 或信号缺字段）时退化为不限定，行为与改动前一致。
        _sessionFilterId = _liveCaptureSessionId;
        if (SessionFilterBadge is not null)
        {
            if (_liveCaptureSessionId is null) SessionFilterBadge.Visibility = Visibility.Collapsed;
            else
            {
                SessionFilterText.Text = "本次采集 · 只显示本次会话的记录";
                SessionFilterBadge.Visibility = Visibility.Visible;
            }
        }
        UpdateRefreshPauseUi();
        ApplyFilter(selectFallback: false);
    }

    private void ReplaceTraffic(IEnumerable<TrafficRecord> source, long count,
        IReadOnlyDictionary<Guid, StoredTrafficRecord>? storedTraffic = null, bool preserveSelection = false)
    {
        var selectedId = preserveSelection ? _preferredTrafficId ?? _selectedTraffic?.Source.Id : null;
        _updatingTrafficRows = true;
        try
        {
            var existingRows = TrafficRows.ToDictionary(row => row.Source.Id);
            _storedTraffic.Clear();
            if (storedTraffic is not null)
                foreach (var item in storedTraffic) _storedTraffic[item.Key] = item.Value;
            // 列表统一按采集时间升序（最新在最下），与 AI 证据池 #序号 顺序一致。
            var rows = source.OrderBy(item => item.Timestamp).Select(item =>
            {
                var dataSource = _storedTraffic.TryGetValue(item.Id, out var stored) ? SourceLabel(stored.CaptureMode) : SourceDemo;
                var row = existingRows.TryGetValue(item.Id, out var existing) && existing.Source == item &&
                       existing.DataSource == dataSource && existing.SessionId == stored?.SessionId
                    ? existing
                    : new TrafficRow(item, dataSource, stored?.SessionId);
                row.IsAiSelected = _aiSelectedTrafficIds.Contains(item.Id);
                return row;
            }).ToArray();
            var rowsChanged = TrafficRows.Count != rows.Length ||
                              TrafficRows.Where((row, index) => !ReferenceEquals(row, rows[index])).Any();
            ReconcileCollection(TrafficRows, rows);
            _aiSelectedTrafficIds.IntersectWith(rows.Select(row => row.Source.Id));
            _capturedCount = count;
            if (!rowsChanged)
            {
                // 空闲轮询不再重建筛选集合、聚类表和证据区；数据库读取仍在后台，UI 保持零布局抖动。
                RequestMetric.Text = _capturedCount.ToString("N0");
                UpdateModeText();
                return;
            }
            RenumberTrafficRows();
            ApplyFilter(selectFallback: false);
            UpdateAnalysis(rows.Select(item => item.Source));

            var selected = selectedId.HasValue
                ? TrafficRows.FirstOrDefault(row => row.Source.Id == selectedId.Value)
                : preserveSelection ? null : TrafficRows.FirstOrDefault();
            SelectedTraffic = selected;
            _preferredTrafficId = selected?.Source.Id;
            SetTrafficGridCurrent(OverviewGrid, selected);
            SetTrafficGridCurrent(TrafficGrid, selected is not null && FilteredTrafficRows.Contains(selected) ? selected : null);
            UpdateAiSelectionUi();
            UpdateModeText();
        }
        finally { _updatingTrafficRows = false; }
    }

    private void 搜索_TextChanged(object sender, TextChangedEventArgs e) => ApplyFilter();
    private void 筛选_Changed(object sender, SelectionChangedEventArgs e) => ApplyFilter();

    private void 排除关键字_Changed(object sender, TextChangedEventArgs e) => ApplyFilter();

    /// <summary>排除关键字解析：逗号/分号分隔，命中任一关键字的记录从列表隐藏（仅显示层，不落删除）。</summary>
    private static string[] ParseExcludeKeywords(string? text) =>
        (text ?? string.Empty).Split([',', '，', ';', '；'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    private static bool IsExcludedRow(TrafficRow row, string[] excludes)
    {
        var url = row.Source.Url ?? string.Empty;
        var host = row.Host;
        return excludes.Any(keyword => url.Contains(keyword, StringComparison.OrdinalIgnoreCase) ||
                                       host.Contains(keyword, StringComparison.OrdinalIgnoreCase));
    }

    private void 流量列表_右键按下(object sender, MouseButtonEventArgs e)
    {
        if (sender is not DataGrid grid || e.OriginalSource is not DependencyObject source) return;
        TrafficRow? clickedRow = null;
        for (var current = source; current is not null; current = VisualTreeHelper.GetParent(current))
        {
            if (current is DataGridCell { DataContext: TrafficRow cellRow })
            {
                clickedRow = cellRow;
                break;
            }
            if (current is DataGridRow { Item: TrafficRow row })
            {
                clickedRow = row;
                break;
            }
        }
        if (clickedRow is null) return;

        // 右键已选行时保留 Ctrl/Shift 多选；右键未选行时才切换为单选。
        if (!grid.SelectedItems.Contains(clickedRow))
        {
            grid.UnselectAll();
            grid.SelectedItem = clickedRow;
        }
        if (grid.Columns.Count > 0) grid.CurrentCell = new DataGridCellInfo(clickedRow, grid.Columns[0]);
        grid.Focus();
    }

    /// <summary>把指定行设为当前行（首列）；已有多选不被程序化定位破坏。</summary>
    private static void SetTrafficGridCurrent(DataGrid grid, TrafficRow? row)
    {
        if (row is null || grid.Columns.Count == 0)
        {
            grid.CurrentCell = default;
            return;
        }
        grid.CurrentCell = new DataGridCellInfo(row, grid.Columns[0]);
        if (grid.SelectedItems.Count == 0) grid.SelectedItem = row;
    }

    private static TrafficRow[] GetSelectedTrafficRows(DataGrid grid) =>
        grid.SelectedItems.OfType<TrafficRow>().DistinctBy(row => row.Source.Id).ToArray();

    /// <summary>DataGrid.Items 是用户眼前的排序/筛选结果，所有“当前显示”批量操作以它为唯一范围。</summary>
    private static TrafficRow[] GetDisplayedTrafficRows(DataGrid grid) =>
        grid.Items.OfType<TrafficRow>().DistinctBy(row => row.Source.Id).ToArray();

    private TrafficRow[] GetCurrentVisibleCheckedTrafficRows()
    {
        var visible = GetDisplayedTrafficRows(TrafficGrid);
        var ids = TrafficSelectionScope.IntersectVisibleChecked(
            visible.Select(row => row.Source.Id), _aiSelectedTrafficIds).ToHashSet();
        return visible.Where(row => ids.Contains(row.Source.Id)).ToArray();
    }

    private static T? FindAncestor<T>(DependencyObject source) where T : DependencyObject
    {
        for (DependencyObject? current = source; current is not null; current = GetAnyParent(current))
            if (current is T match) return match;
        return null;
    }

    private static void SelectSingleTrafficRow(DataGrid grid, TrafficRow row)
    {
        grid.UnselectAll();
        grid.SelectedItem = row;
        if (grid.Columns.Count > 0) grid.CurrentCell = new DataGridCellInfo(row, grid.Columns[0]);
        grid.Focus();
    }

    private void 流量菜单_Opened(object sender, RoutedEventArgs e)
    {
        if (sender is not ContextMenu menu || menu.PlacementTarget is not DataGrid grid) return;
        var row = grid.CurrentItem as TrafficRow;
        var selectedRows = GetSelectedTrafficRows(grid);
        if (selectedRows.Length == 0 && row is not null) selectedRows = [row];
        var persistedSelectedRows = selectedRows.Where(candidate => candidate.SessionId is not null)
            .DistinctBy(candidate => candidate.Source.Id).ToArray();
        foreach (var item in EnumerateMenuItems(menu.Items))
        {
            item.DataContext = row;
            item.CommandParameter = selectedRows;
        }

        var filterMenu = FindMenuItem(menu.Items, "选择过滤");
        if (filterMenu is not null)
        {
            filterMenu.IsEnabled = row is not null;
            foreach (var item in filterMenu.Items.OfType<MenuItem>())
            {
                item.DataContext = row;
                var category = item.Tag?.ToString() ?? string.Empty;
                var value = row is null ? string.Empty : category switch
                {
                    "主机" => row.Host,
                    "类型" => row.ResourceKind,
                    "协议" => row.Protocol,
                    "方法" => row.Method,
                    _ => string.Empty
                };
                item.Header = string.IsNullOrWhiteSpace(value) ? category : $"{category}：{value}";
                item.ToolTip = string.IsNullOrWhiteSpace(value) ? null : value;
                item.IsEnabled = row is not null && !(category == "主机" && row.Host == "—");
            }
        }

        var clearItem = FindMenuItem(menu.Items, "清除过滤");
        if (clearItem is not null)
        {
            clearItem.DataContext = grid;
            clearItem.IsEnabled = HasActiveTrafficFilter();
        }

        var excludeItem = FindMenuItem(menu.Items, "排除域名");
        if (excludeItem is not null)
        {
            excludeItem.DataContext = row;
            var host = row?.Host;
            var usable = row is not null && !string.IsNullOrWhiteSpace(host) && host != "—";
            excludeItem.IsEnabled = usable;
            // 动态头直接展示将排除的域名（去端口），所见即所得
            excludeItem.Header = usable ? $"排除域名：{host!.Split(':')[0]}" : "排除本记录域名";
        }

        var hasRow = row is not null;
        foreach (var tag in new[] { "复制菜单", "复制URL", "复制Curl", "复制原始证据", "复制脱敏证据" })
            if (FindMenuItem(menu.Items, tag) is { } item) item.IsEnabled = hasRow;

        if (FindMenuItem(menu.Items, "切换AI证据") is { } aiItem)
        {
            aiItem.IsEnabled = selectedRows.Length > 0;
            aiItem.Header = selectedRows.Length > 1
                ? $"将所选 {selectedRows.Length:N0} 条事务加入 AI 证据"
                : "将所选事务加入 AI 证据";
        }
        if (FindMenuItem(menu.Items, "打开AI分析") is { } openAiItem)
        {
            openAiItem.IsEnabled = selectedRows.Length > 0;
            openAiItem.Header = selectedRows.Length > 1
                ? $"使用所选 {selectedRows.Length:N0} 条事务打开 AI 分析"
                : "使用所选事务打开 AI 分析";
        }
        if (FindMenuItem(menu.Items, "保存勾选到记录组") is { } saveCheckedItem)
        {
            var checkedRows = ReferenceEquals(grid, TrafficGrid) ? GetCurrentVisibleCheckedTrafficRows() : [];
            var persistedChecked = checkedRows.Count(candidate => candidate.SessionId is not null);
            saveCheckedItem.IsEnabled = persistedChecked > 0;
            saveCheckedItem.Header = persistedChecked > 0
                ? $"保存当前可见已勾选 {persistedChecked:N0} 条到记录组"
                : "保存勾选到记录组";
        }

        if (FindMenuItem(menu.Items, "记录组菜单") is { } groupMenu) groupMenu.IsEnabled = persistedSelectedRows.Length > 0;
        if (FindMenuItem(menu.Items, "新建记录组") is { } createGroupItem)
        {
            createGroupItem.IsEnabled = persistedSelectedRows.Length > 0;
            createGroupItem.Header = persistedSelectedRows.Length > 1
                ? $"用所选 {persistedSelectedRows.Length:N0} 条事务新建记录组"
                : "以此事务新建记录组";
        }
        if (FindMenuItem(menu.Items, "加入当前记录组") is { } appendGroupItem)
        {
            var appendableCount = persistedSelectedRows.Count(candidate => !_activeTrafficGroupIds.Contains(candidate.Source.Id));
            var canAppend = _activeTrafficGroup is not null && appendableCount > 0;
            appendGroupItem.IsEnabled = canAppend;
            appendGroupItem.Header = _activeTrafficGroup is null
                ? "加入当前记录组（未选择记录组）"
                : appendableCount == 0
                    ? $"已在《{_activeTrafficGroup.Name}》中"
                    : persistedSelectedRows.Length > 1
                        ? $"将 {appendableCount:N0} 条事务加入《{_activeTrafficGroup.Name}》"
                        : $"加入《{_activeTrafficGroup.Name}》";
        }
        if (FindMenuItem(menu.Items, "删除选择") is { } deleteSelectionItem)
        {
            deleteSelectionItem.DataContext = grid;
            deleteSelectionItem.IsEnabled = persistedSelectedRows.Length > 0;
            deleteSelectionItem.Header = persistedSelectedRows.Length > 0
                ? $"删除所选 {persistedSelectedRows.Length:N0} 条事务…"
                : "删除所选事务…";
        }
        if (FindMenuItem(menu.Items, "删除全部") is { } deleteAllItem)
        {
            deleteAllItem.DataContext = grid;
            // 范围是 DataGrid.Items，即用户眼前的过滤结果；演示数据没有 SessionId，不可删除。
            var displayedPersisted = GetDisplayedTrafficRows(grid).Count(candidate => candidate.SessionId is not null);
            deleteAllItem.IsEnabled = displayedPersisted > 0;
            deleteAllItem.Header = displayedPersisted > 0
                ? (HasActiveTrafficFilter() ? $"删除当前列表全部 {displayedPersisted:N0} 条（已过滤）…" : $"删除全部 {displayedPersisted:N0} 条…")
                : "删除全部…";
        }
    }

    private static MenuItem? FindMenuItem(ItemCollection items, string tag) =>
        EnumerateMenuItems(items).FirstOrDefault(item => Equals(item.Tag, tag));

    private static IEnumerable<MenuItem> EnumerateMenuItems(ItemCollection items)
    {
        foreach (var item in items.OfType<MenuItem>())
        {
            yield return item;
            foreach (var child in EnumerateMenuItems(item.Items)) yield return child;
        }
    }

    private void 复制事务URL_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not MenuItem { DataContext: TrafficRow row }) return;
        var value = string.IsNullOrWhiteSpace(row.Source.Url) ? row.Source.Endpoint : row.Source.Url;
        CopyText(value, "已复制完整 URL。", sensitive: true);
    }

    private void 右键复制Curl_Click(object sender, RoutedEventArgs e)
    {
        if (!UseContextTraffic(sender)) return;
        复制Curl_Click(sender, e);
    }

    private void 右键复制完整证据_Click(object sender, RoutedEventArgs e)
    {
        if (!UseContextTraffic(sender)) return;
        复制完整证据_Click(sender, e);
    }

    private void 右键复制脱敏副本_Click(object sender, RoutedEventArgs e)
    {
        if (!UseContextTraffic(sender)) return;
        复制脱敏副本_Click(sender, e);
    }

    private bool UseContextTraffic(object sender)
    {
        if (sender is not MenuItem { DataContext: TrafficRow row }) return false;
        SelectedTraffic = TrafficRows.FirstOrDefault(candidate => candidate.Source.Id == row.Source.Id) ?? row;
        return true;
    }

    private void 切换右键AI证据_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not MenuItem item) return;
        var rows = GetMenuTrafficRows(item);
        if (rows.Length == 0) return;
        var mainIds = TrafficRows.Select(candidate => candidate.Source.Id).ToHashSet();
        if (rows.All(candidate => mainIds.Contains(candidate.Source.Id)))
        {
            ClearGroupAiScope();
            _updatingTrafficRows = true;
            try
            {
                foreach (var row in rows)
                {
                    _aiSelectedTrafficIds.Add(row.Source.Id);
                    foreach (var candidate in TrafficRows.Where(candidate => candidate.Source.Id == row.Source.Id)) candidate.IsAiSelected = true;
                    foreach (var candidate in GroupTrafficRows.Where(candidate => candidate.Source.Id == row.Source.Id)) candidate.IsAiSelected = true;
                }
            }
            finally { _updatingTrafficRows = false; }
        }
        else
        {
            _groupAiEvidence = rows.Select(candidate => candidate.Source).DistinctBy(record => record.Id)
                .OrderBy(record => record.Timestamp).ToArray();
            _groupAiName = "右键所选事务";
        }
        UpdateAiSelectionUi();
    }

    private void 右键打开AI分析_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not MenuItem item) return;
        var rows = GetMenuTrafficRows(item);
        if (rows.Length == 0) return;
        var ids = rows.Select(candidate => candidate.Source.Id).ToHashSet();
        var allInMainList = ids.All(id => TrafficRows.Any(candidate => candidate.Source.Id == id));
        _updatingTrafficRows = true;
        try
        {
            _aiSelectedTrafficIds.Clear();
            foreach (var candidate in TrafficRows)
            {
                candidate.IsAiSelected = allInMainList && ids.Contains(candidate.Source.Id);
                if (candidate.IsAiSelected) _aiSelectedTrafficIds.Add(candidate.Source.Id);
            }
        }
        finally { _updatingTrafficRows = false; }
        if (allInMainList)
        {
            ClearGroupAiScope();
        }
        else
        {
            _groupAiEvidence = rows.Select(candidate => candidate.Source).DistinctBy(record => record.Id)
                .OrderBy(record => record.Timestamp).ToArray();
            _groupAiName = "右键所选事务";
        }
        SelectedTraffic = rows[0];
        UpdateAiSelectionUi();
        SelectPage(AiNav);
    }

    private async void 保存勾选到记录组_Click(object sender, RoutedEventArgs e) =>
        await SaveVisibleCheckedTrafficGroupAsync();

    private async void 右键新建记录组_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not MenuItem item) return;
        var ids = GetMenuTrafficRows(item).Where(row => row.SessionId is not null)
            .Select(row => row.Source.Id).Distinct().ToArray();
        if (ids.Length == 0) return;
        if (ids.Length > 1000)
        {
            MessageBox.Show(this, "单个记录组最多保存 1,000 条事务，请缩小选择范围。", "选择过多", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        await CreateTrafficGroupAsync(ids);
    }

    private async void 右键加入当前记录组_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not MenuItem item || _activeTrafficGroup is null) return;
        var ids = GetMenuTrafficRows(item).Where(row => row.SessionId is not null)
            .Select(row => row.Source.Id).Distinct().Where(id => !_activeTrafficGroupIds.Contains(id)).ToArray();
        if (ids.Length == 0) return;
        if (_activeTrafficGroupIds.Count + ids.Length > 1000)
        {
            MessageBox.Show(this, "加入后将超过单个记录组 1,000 条事务的上限，请缩小选择范围。", "无法加入记录组", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        var previousIds = _activeTrafficGroupIds.ToArray();
        try
        {
            _activeTrafficGroupIds.UnionWith(ids);
            var updated = _activeTrafficGroup with
            {
                UpdatedAt = DateTimeOffset.UtcNow,
                TrafficIds = _activeTrafficGroupIds.ToArray()
            };
            await new TrafficGroupStore(_workspacePath).SaveAsync(updated);
            _activeTrafficGroup = updated;
            await new WorkspaceStore(_workspacePath).AppendAuditAsync("traffic-group.appended", new
            {
                updated.Id,
                added = ids.Length,
                transactionCount = updated.TrafficIds.Count
            });
            await LoadTrafficGroupsAsync(updated.Id);
            TrafficGroupStatusText.Text = $"已将 {ids.Length:N0} 条事务加入《{updated.Name}》";
            TrafficGroupStatusText.Foreground = Green;
        }
        catch (Exception exception)
        {
            _activeTrafficGroupIds.Clear();
            _activeTrafficGroupIds.UnionWith(previousIds);
            MessageBox.Show(this, "加入记录组失败：\n\n" + exception.Message, "无法更新记录组", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private static TrafficRow[] GetMenuTrafficRows(MenuItem item)
    {
        var rows = (item.CommandParameter as IEnumerable<TrafficRow>)?.DistinctBy(row => row.Source.Id).ToArray() ?? [];
        if (rows.Length == 0 && item.DataContext is TrafficRow row) rows = [row];
        return rows;
    }

    private async void 右键删除选择_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not MenuItem { DataContext: DataGrid grid }) return;
        var targets = GetSelectedTrafficRows(grid).Where(row => row.SessionId is not null).ToArray();
        if (targets.Length == 0) return;
        var answer = MessageBox.Show(this,
            $"将删除当前选择中的 {targets.Length:N0} 条流量事务。\n\n无其他事务引用的正文 Blob 会一并删除；记录组中的引用会保留为“已清理”。此操作无法撤销，是否继续？",
            "确认删除所选事务", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);
        if (answer != MessageBoxResult.Yes) return;
        try
        {
            var deleted = await DeleteTrafficRowsAsync(targets);
            MessageBox.Show(this, $"已删除 {deleted:N0} 条流量事务。", "删除完成", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception exception)
        {
            MessageBox.Show(this, "删除所选事务失败：\n\n" + exception.Message, "无法删除事务", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    /// <summary>
    /// 「删除全部」：删除当前列表（DataGrid.Items，即用户眼前的过滤结果）中的所有事务。
    /// 与「清空记录」不同——后者清掉整个工作区的事务、会话与正文，这里只删列表内可见的部分。
    /// </summary>
    private async void 右键删除全部_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not MenuItem { DataContext: DataGrid grid }) return;
        var targets = GetDisplayedTrafficRows(grid).Where(row => row.SessionId is not null).ToArray();
        if (targets.Length == 0) return;
        var filtered = HasActiveTrafficFilter();
        var answer = MessageBox.Show(this,
            $"将删除当前列表中的 {targets.Length:N0} 条流量事务" + (filtered ? "（当前有过滤条件，只删除过滤后可见的记录）" : "") + "。\n\n" +
            "无其他事务引用的正文 Blob 会一并删除；记录组中的引用会保留为“已清理”。此操作无法撤销，是否继续？",
            "确认删除全部", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);
        if (answer != MessageBoxResult.Yes) return;
        try
        {
            var deleted = await DeleteTrafficRowsAsync(targets);
            MessageBox.Show(this, $"已删除 {deleted:N0} 条流量事务。", "删除完成", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception exception)
        {
            MessageBox.Show(this, "删除全部失败：\n\n" + exception.Message, "无法删除事务", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private async Task<long> DeleteTrafficRowsAsync(IEnumerable<TrafficRow> rows)
    {
        var targets = rows.Where(row => row.SessionId is not null).DistinctBy(row => row.Source.Id).ToArray();
        if (targets.Length == 0) return 0;
        var ids = targets.Select(row => row.Source.Id).ToHashSet();
        using var archive = new TrafficArchive(_workspacePath);
        // 分批删除：单次 DeleteTrafficAsync 上限 1,000 条，而「删除全部」的范围是整个列表窗口。
        var deleted = await archive.DeleteTrafficBatchedAsync(ids.ToArray());
        if (deleted == 0) return 0;
        foreach (var id in ids)
        {
            _storedTraffic.Remove(id);
            _aiSelectedTrafficIds.Remove(id);
        }
        ReconcileCollection(TrafficRows, TrafficRows.Where(row => !ids.Contains(row.Source.Id)).ToArray());
        ReconcileCollection(GroupTrafficRows, GroupTrafficRows.Where(row => !ids.Contains(row.Source.Id)).ToArray());
        _capturedCount = Math.Max(0, _capturedCount - deleted);
        // SQLite rowid 在删除当前最大行后允许复用；下一轮强制重建游标，避免新事务恰好复用旧游标而漏刷。
        _trafficRefreshCursor = 0;
        if (SelectedTraffic is not null && ids.Contains(SelectedTraffic.Source.Id)) SelectedTraffic = null;
        RenumberTrafficRows();
        ClearGroupAiScope();
        ApplyFilter(selectFallback: true);
        UpdateAiSelectionUi();
        UpdateAiEvidencePreview();
        return deleted;
    }

    /// <summary>右键“排除域名”：把当前记录域名追加进排除关键字并立即刷新筛选。</summary>
    private void 排除域名_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not MenuItem { DataContext: TrafficRow row } || ExcludeKeywordBox is null) return;
        var host = row.Host;
        if (string.IsNullOrWhiteSpace(host) || host == "—") return;
        var domain = host.Split(':')[0];
        if (!ParseExcludeKeywords(ExcludeKeywordBox.Text).Contains(domain, StringComparer.OrdinalIgnoreCase))
        {
            var existing = ExcludeKeywordBox.Text.Trim().TrimEnd([',', '，', ';', '；']).TrimEnd();
            ExcludeKeywordBox.Text = existing.Length == 0 ? domain : existing + ", " + domain;
        }
        ApplyFilter(); // TextChanged 已触发过一次，这里确保关键字未变时也刷新
    }

    private void 按记录过滤_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not MenuItem { DataContext: TrafficRow row } item) return;
        var category = item.Tag?.ToString();
        _updatingTrafficRows = true;
        try
        {
            ResetSessionScopeForQuickFilter();
            SourceFilter.SelectedIndex = 0;
            StatusFilter.SelectedIndex = 0;
            ResetResourceTypeFilters();
            TrafficSearch.Clear();
            switch (category)
            {
                case "主机": TrafficSearch.Text = row.Host; break;
                case "类型": SelectOnlyResourceType(row.ResourceKind); break;
                case "协议": TrafficSearch.Text = row.Protocol; break;
                case "方法": TrafficSearch.Text = row.Method; break;
                default: return;
            }
        }
        finally { _updatingTrafficRows = false; }

        _preferredTrafficId = row.Source.Id;
        SelectPage(TrafficNav);
        ApplyFilter(selectFallback: false);
        var selected = FilteredTrafficRows.FirstOrDefault(candidate => candidate.Source.Id == row.Source.Id);
        if (selected is null) return;
        SelectedTraffic = selected;
        SetTrafficGridCurrent(TrafficGrid, selected);
        TrafficGrid.ScrollIntoView(selected);
    }

    private async void 清除右键过滤_Click(object sender, RoutedEventArgs e)
    {
        var sourceGrid = (sender as MenuItem)?.DataContext as DataGrid;
        _updatingTrafficRows = true;
        try
        {
            ResetSessionScopeForQuickFilter();
            SourceFilter.SelectedIndex = 0;
            StatusFilter.SelectedIndex = 0;
            ResetResourceTypeFilters();
            TrafficSearch.Clear();
        }
        finally { _updatingTrafficRows = false; }
        await RefreshStoredTrafficAsync();
        ApplyFilter();
        if (ReferenceEquals(sourceGrid, TrafficGrid)) SelectPage(TrafficNav);
    }

    /// <summary>
    /// 快速过滤要清掉可能把当前记录排除在外的旧条件。但采集进行中时会话范围必须保留为本次采集：
    /// 被右键的记录本来就属于本次会话，清掉它反而会把全部历史事务重新拉回列表。
    /// </summary>
    private void ResetSessionScopeForQuickFilter()
    {
        _sessionFilterId = _capturing ? _liveCaptureSessionId : null;
        if (SessionFilterBadge is null) return;
        SessionFilterBadge.Visibility = _sessionFilterId is null ? Visibility.Collapsed : Visibility.Visible;
    }

    private bool HasActiveTrafficFilter() =>
        _sessionFilterId is not null ||
        !string.IsNullOrWhiteSpace(TrafficSearch.Text) ||
        SourceFilter.SelectedIndex > 0 ||
        StatusFilter.SelectedIndex > 0 ||
        !AreDefaultResourceTypesEnabled();

    private CheckBox[] ResourceTypeCheckBoxes =>
        [ResourceApiBox, ResourceImageBox, ResourceScriptBox, ResourceStyleBox, ResourceFontBox,
            ResourceMediaBox, ResourceDocumentBox, ResourceConnectBox, ResourceOtherBox];

    private HashSet<string> GetEnabledResourceTypes() => ResourceTypeCheckBoxes
        .Where(box => box.IsChecked == true && box.Tag is string)
        .Select(box => (string)box.Tag)
        .ToHashSet(StringComparer.Ordinal);

    private bool AreDefaultResourceTypesEnabled() => ResourceTypeCheckBoxes.All(box =>
        box.Tag is string resourceType && box.IsChecked.GetValueOrDefault() == DefaultVisibleResourceTypes.Contains(resourceType));

    private void ResetResourceTypeFilters()
    {
        _syncingResourceTypeFilters = true;
        try
        {
            foreach (var box in ResourceTypeCheckBoxes)
                box.IsChecked = box.Tag is string resourceType && DefaultVisibleResourceTypes.Contains(resourceType);
            UpdateResourceTypeAllState();
        }
        finally { _syncingResourceTypeFilters = false; }
    }

    private void SelectOnlyResourceType(string resourceType)
    {
        _syncingResourceTypeFilters = true;
        try
        {
            foreach (var box in ResourceTypeCheckBoxes)
                box.IsChecked = string.Equals(box.Tag?.ToString(), resourceType, StringComparison.Ordinal);
            UpdateResourceTypeAllState();
        }
        finally { _syncingResourceTypeFilters = false; }
    }

    private void UpdateResourceTypeAllState()
    {
        var selectedCount = ResourceTypeCheckBoxes.Count(box => box.IsChecked == true);
        ResourceTypeAllBox.IsChecked = selectedCount == 0 ? false
            : selectedCount == ResourceTypeCheckBoxes.Length ? true : null;
    }

    /// <summary>
    /// 勾选「全部」→ 全选，逻辑不变。取消勾选「全部」→ 退回默认可见类型，而不是清空整张表
    /// （清空后列表看起来像是坏了，用户还得自己记住原来选的是哪几类）。
    /// 正常点击路径已被 <see cref="资源类型全选_按下"/> 接管；这里只处理键盘/自动化等
    /// 不经过鼠标按下事件的路径，同一条规则兜底。
    /// </summary>
    private void 资源类型全选_Changed(object sender, RoutedEventArgs e)
    {
        if (!IsLoaded || _updatingTrafficRows || _syncingResourceTypeFilters ||
            sender is not CheckBox { IsChecked: bool selected }) return;
        if (selected)
        {
            _syncingResourceTypeFilters = true;
            try { foreach (var box in ResourceTypeCheckBoxes) box.IsChecked = true; }
            finally { _syncingResourceTypeFilters = false; }
        }
        else
        {
            ResetResourceTypeFilters();
        }
        ApplyFilter();
    }

    /// <summary>
    /// WPF 三态复选框默认点击循环是 未选 → 全选 → 部分（不确定）→ 未选，这里改写两段：
    /// 从「部分选择」点击 → 直接全选（而不是继续走到「未选」）；
    /// 从「全选」点击 → 直接退回默认可见类型（而不是先滑进「部分选择」的中间态再等下一次点击）。
    /// 「未选」状态下点击维持默认框架行为（未选 → 全选），与「勾选全部」入口一致。
    /// </summary>
    private void 资源类型全选_按下(object sender, MouseButtonEventArgs e)
    {
        if (sender is not CheckBox box || _syncingResourceTypeFilters) return;
        if (box.IsChecked is null)
        {
            e.Handled = true;
            _syncingResourceTypeFilters = true;
            try
            {
                foreach (var item in ResourceTypeCheckBoxes) item.IsChecked = true;
                ResourceTypeAllBox.IsChecked = true;
            }
            finally { _syncingResourceTypeFilters = false; }
            ApplyFilter();
        }
        else if (box.IsChecked == true)
        {
            e.Handled = true;
            ResetResourceTypeFilters();
            ApplyFilter();
        }
    }

    private void 资源类型筛选_Changed(object sender, RoutedEventArgs e)
    {
        if (!IsLoaded || _updatingTrafficRows || _syncingResourceTypeFilters) return;
        _syncingResourceTypeFilters = true;
        try { UpdateResourceTypeAllState(); }
        finally { _syncingResourceTypeFilters = false; }
        ApplyFilter();
    }

    private void ClearTrafficEvidencePanel(string title)
    {
        TrafficEvidenceTitle.Text = title;
        TrafficEvidenceMeta.Text = string.Empty;
        TrafficUrlText.Text = string.Empty;
        ClearKeyValueText(TrafficQueryText);
        ClearKeyValueText(TrafficCookieText);
        ClearKeyValueText(TrafficRequestHeadersText);
        ClearKeyValueText(TrafficResponseHeadersText);
        TrafficRequestBody.Text = TrafficResponseBody.Text = string.Empty;
        ResetEvidenceJsonViews();
        SetResponsePreviewMessage("请选择一条流量记录");
    }

    private void ApplyFilter(bool selectFallback = true)
    {
        if (FilteredTrafficRows is null || TrafficSearch is null || SourceFilter is null || StatusFilter is null || ResourceTypeAllBox is null || TrafficCountText is null) return;
        var query = TrafficSearch.Text.Trim();
        var searchMatch = TrafficFilterExpression.Compile(query);
        var source = (SourceFilter.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "全部来源";
        var status = (StatusFilter.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "全部状态";
        var enabledResourceTypes = GetEnabledResourceTypes();
        var excludes = ParseExcludeKeywords(ExcludeKeywordBox?.Text);
        var filteredRows = TrafficRows.Where(row =>
                (query.Length == 0 || searchMatch(row.SearchText)) &&
                (excludes.Length == 0 || !IsExcludedRow(row, excludes)) &&
                (source == "全部来源" || row.DataSource == source) &&
                enabledResourceTypes.Contains(row.ResourceKind) &&
                (_sessionFilterId is null || row.SessionId == _sessionFilterId) &&
                (status == "全部状态" || status == "成功" && row.Source.StatusCode < 400 || status == "异常" && row.Source.StatusCode >= 400))
            .ToArray();
        ReconcileCollection(FilteredTrafficRows, filteredRows);
        var hiddenTypeCount = ResourceTypeCheckBoxes.Length - enabledResourceTypes.Count;
        TrafficCountText.Text = $"显示 {FilteredTrafficRows.Count} 条 · 共 {_capturedCount:N0} 条" +
                                (hiddenTypeCount > 0 ? $" · 隐藏 {hiddenTypeCount} 类" : string.Empty);
        if (TrafficGrid is not null && (TrafficGrid.CurrentItem is not TrafficRow selected || !FilteredTrafficRows.Contains(selected)))
        {
            var next = _preferredTrafficId.HasValue
                ? FilteredTrafficRows.FirstOrDefault(row => row.Source.Id == _preferredTrafficId.Value)
                : null;
            if (next is null && selectFallback && !_updatingTrafficRows) next = FilteredTrafficRows.FirstOrDefault();
            SetTrafficGridCurrent(TrafficGrid, next);
            SelectedTraffic = next;
            if (next is null)
            {
                ClearTrafficEvidencePanel(DescribeEmptyTrafficList(query, source, status, excludes, enabledResourceTypes));
            }
        }
    }

    /// <summary>
    /// 列表为空时说清楚是被哪一层挡掉的。
    /// "什么都没有" 有好几种完全不同的原因（还没采到 / 被会话范围限定 / 被筛选条件挡掉），
    /// 只显示一句"没有符合条件的流量记录"会让人怀疑是采集坏了。
    /// </summary>
    private string DescribeEmptyTrafficList(string query, string source, string status, string[] excludes,
        IReadOnlyCollection<string> enabledResourceTypes)
    {
        if (TrafficRows.Count == 0)
        {
            if (_sessionFilterId is not null)
                return _capturing
                    ? "本次采集会话还没有产生流量记录。\n\n列表只显示本次会话，历史记录已隐藏；把目标应用的代理指向监听地址后即会出现。"
                    : "本次采集会话没有记录。\n\n点上方会话徽标旁的清除按钮可查看全部历史记录。";
            return _capturing ? "尚未采集到流量记录。" : "当前工作区还没有流量记录。";
        }
        var total = TrafficRows.Count;
        // 最常见也最容易让人误以为"采集坏了"的一种：目标站点是 HTTPS，但没启用解密，
        // 于是抓到的全是 CONNECT 隧道；而"连接"这一类默认不显示，列表就成了 0 条。
        // 这种情况下正文看不到、钩子也拦不到，必须把该做什么直接说出来。
        var tunnelCount = TrafficRows.Count(row => row.ResourceKind == TrafficRow.ResourceKindConnect);
        if (tunnelCount == total && !enabledResourceTypes.Contains(TrafficRow.ResourceKindConnect))
        {
            return $"已加载 {total} 条，全部是 HTTPS 加密隧道（CONNECT），而「连接」类型默认不显示。\n\n" +
                   "未启用 HTTPS 解密时，HTTPS 请求只留下连接元数据：看不到 URL 与正文，请求钩子也无法拦截（加密隧道不可钩）。\n\n" +
                   "要抓到真实请求：在「项目与数据」页启用 HTTPS 解密并信任工作区 CA，然后重新开始采集。\n" +
                   "只想看连接记录：在上方资源类型里勾选「连接」。";
        }

        // 逐个条件试掉：找出单独放开哪一个就能出现记录，直接点名它。
        var reasons = new List<string>();
        if (_sessionFilterId is not null && TrafficRows.Count(row => row.SessionId == _sessionFilterId) == 0)
            reasons.Add($"会话范围（本次采集 0 条，工作区共 {total} 条）");
        if (query.Length > 0 && TrafficRows.Count(row => TrafficFilterExpression.Compile(query)(row.SearchText)) == 0)
            reasons.Add($"搜索关键字「{query}」");
        if (excludes.Length > 0 && TrafficRows.All(row => IsExcludedRow(row, excludes)))
            reasons.Add($"排除关键字「{string.Join('、', excludes)}」");
        if (source != "全部来源" && TrafficRows.Count(row => row.DataSource == source) == 0)
            reasons.Add($"来源筛选「{source}」");
        if (status != "全部状态" && TrafficRows.Count(row =>
                status == "成功" ? row.Source.StatusCode < 400 : row.Source.StatusCode >= 400) == 0)
            reasons.Add($"状态筛选「{status}」");
        if (TrafficRows.Count(row => enabledResourceTypes.Contains(row.ResourceKind)) == 0)
        {
            var kinds = TrafficRows.Select(row => row.ResourceKind).Distinct()
                .Where(kind => !enabledResourceTypes.Contains(kind)).Order(StringComparer.Ordinal);
            reasons.Add($"资源类型勾选（这些记录都属于未勾选的「{string.Join("、", kinds)}」）");
        }
        return reasons.Count == 0
            ? $"当前筛选条件组合后没有匹配记录（列表共 {total} 条）。"
            : $"已加载 {total} 条，但被以下条件全部挡掉：\n\n• {string.Join("\n• ", reasons)}";
    }

    /// <summary>按当前列表顺序重新编序号（升序排列下即时间顺序），供序号列与 AI 取数对照。</summary>
    private void RenumberTrafficRows()
    {
        for (var index = 0; index < TrafficRows.Count; index++) TrafficRows[index].Ordinal = index + 1;
    }

    private static void ReconcileCollection<T>(ObservableCollection<T> collection, IReadOnlyList<T> desired)
        where T : class
    {
        // 先删除已滑出窗口的对象。实时列表达到窗口上限后通常是“头部淘汰 + 尾部追加”；
        // 若直接逐项向后查找并 Move，每次刷新都会退化为 O(n²)。先做集合差可让常见路径保持 O(n)。
        var desiredSet = new HashSet<T>(desired, ReferenceEqualityComparer.Instance);
        for (var index = collection.Count - 1; index >= 0; index--)
            if (!desiredSet.Contains(collection[index])) collection.RemoveAt(index);

        for (var index = 0; index < desired.Count; index++)
        {
            if (index < collection.Count && ReferenceEquals(collection[index], desired[index])) continue;
            var existingIndex = -1;
            for (var candidate = index + 1; candidate < collection.Count; candidate++)
            {
                if (!ReferenceEquals(collection[candidate], desired[index])) continue;
                existingIndex = candidate;
                break;
            }
            if (existingIndex >= 0) collection.Move(existingIndex, index);
            else collection.Insert(index, desired[index]);
        }
        while (collection.Count > desired.Count) collection.RemoveAt(collection.Count - 1);
    }

    private async void 会话_DoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (SessionGrid.SelectedItem is not SessionRow session) return;
        _sessionFilterId = session.SessionId;
        SessionFilterText.Text = $"会话：{session.StartedAt} · {session.Mode}";
        SessionFilterBadge.Visibility = Visibility.Visible;
        SourceFilter.SelectedIndex = 0;
        StatusFilter.SelectedIndex = 0;
        ResetResourceTypeFilters();
        TrafficSearch.Clear();
        SelectPage(TrafficNav);
        // 会话范围现在也决定从 SQLite 读取哪一批事务，必须重新取数而不是只过滤内存中的行，
        // 否则下钻较早的会话时最近窗口里可能一条都没有。
        await RefreshStoredTrafficAsync();
        ApplyFilter();
    }

    private async void 清除会话筛选_Click(object sender, RoutedEventArgs e)
    {
        _sessionFilterId = null;
        SessionFilterBadge.Visibility = Visibility.Collapsed;
        await RefreshStoredTrafficAsync();
        ApplyFilter();
    }

    private async void 流量选择_Changed(object sender, SelectionChangedEventArgs e)
    {
        // 单元格选择模式下 SelectedItem 不再随行点击更新：改从 CurrentItem 取当前单元格所属行；
        // 同行不重复刷新的守卫在 SelectTrafficRowAsync 内统一处理（键盘导航也走这条路）。
        if (sender is not DataGrid grid || grid.CurrentItem is not TrafficRow row) return;
        await SelectTrafficRowAsync(grid, row);
    }

    /// <summary>流量行选中联动：同一条记录不重复刷新证据；探索表额外加载证据详情。</summary>
    private async Task SelectTrafficRowAsync(DataGrid grid, TrafficRow row)
    {
        if (ReferenceEquals(row, SelectedTraffic)) return;
        if (!_updatingTrafficRows) _preferredTrafficId = row.Source.Id;
        SelectedTraffic = row;
        UpdateAiEvidencePreview();
        if (ReferenceEquals(grid, TrafficGrid)) await UpdateTrafficEvidenceAsync(row.Source);
    }

    private async void 流量列表_左键按下(object sender, MouseButtonEventArgs e)
    {
        if (sender is not DataGrid grid || e.OriginalSource is not DependencyObject source) return;
        // Ctrl/Shift 交给 DataGrid 的 Extended/FullRow 范围选择逻辑。
        if (Keyboard.Modifiers is not ModifierKeys.None) return;
        for (var current = source; current is not null; current = VisualTreeHelper.GetParent(current))
        {
            // AI 勾选框保持独立的勾选与 Shift 范围勾选语义。
            if (current is CheckBox) return;
            if (current is DataGridCell { DataContext: TrafficRow row })
            {
                SelectSingleTrafficRow(grid, row);
                await SelectTrafficRowAsync(grid, row);
                return;
            }
            if (current is DataGridRow { Item: TrafficRow rowItem })
            {
                SelectSingleTrafficRow(grid, rowItem);
                await SelectTrafficRowAsync(grid, rowItem);
                return;
            }
        }
    }

    private void AI记录选择_Changed(object sender, RoutedEventArgs e)
    {
        if (_updatingTrafficRows || sender is not CheckBox { DataContext: TrafficRow row } checkBox) return;
        ClearGroupAiScope();
        row.IsAiSelected = checkBox.IsChecked == true;
        if (row.IsAiSelected) _aiSelectedTrafficIds.Add(row.Source.Id);
        else _aiSelectedTrafficIds.Remove(row.Source.Id);
        UpdateAiSelectionUi();
    }

    /// <summary>表头全选：概览页作用于全量列表，流量记录页作用于当前筛选结果。</summary>
    private void AI全选_Changed(object sender, RoutedEventArgs e)
    {
        if (_syncingAiSelectAll || _updatingTrafficRows || sender is not CheckBox checkBox) return;
        var scope = ReferenceEquals(checkBox, OverviewAiSelectAll) ? TrafficRows : FilteredTrafficRows;
        var target = checkBox.IsChecked == true;
        ClearGroupAiScope();
        foreach (var row in scope)
        {
            row.IsAiSelected = target;
            if (target) _aiSelectedTrafficIds.Add(row.Source.Id);
            else _aiSelectedTrafficIds.Remove(row.Source.Id);
        }
        UpdateAiSelectionUi();
    }

    /// <summary>Shift+点击范围勾选：严格按当前 DataGrid 实际显示顺序取范围，底层被筛掉的行不参与。</summary>
    private void AI勾选_按下(object sender, MouseButtonEventArgs e)
    {
        if (sender is not CheckBox { DataContext: TrafficRow row } checkBox || FindAncestor<DataGrid>(checkBox) is not { } grid) return;
        if ((Keyboard.Modifiers & ModifierKeys.Shift) != ModifierKeys.Shift)
        {
            _aiCheckAnchorId = row.Source.Id;
            _aiCheckAnchorGrid = grid;
            return;
        }
        var visibleRows = GetDisplayedTrafficRows(grid);
        var visibleIds = visibleRows.Select(candidate => candidate.Source.Id).ToArray();
        var anchor = ReferenceEquals(_aiCheckAnchorGrid, grid) ? _aiCheckAnchorId : null;
        var rangeIds = TrafficSelectionScope.ResolveVisibleRange(visibleIds, anchor, row.Source.Id).ToHashSet();
        if (rangeIds.Count == 0) return;
        e.Handled = true; // 范围勾选由此处理：屏蔽勾选框自身单击，避免与绑定二次打架
        ClearGroupAiScope();
        _updatingTrafficRows = true;
        try
        {
            foreach (var rangeRow in visibleRows.Where(candidate => rangeIds.Contains(candidate.Source.Id)))
            {
                rangeRow.IsAiSelected = true;
                _aiSelectedTrafficIds.Add(rangeRow.Source.Id);
            }
        }
        finally { _updatingTrafficRows = false; }
        if (!anchor.HasValue || !visibleIds.Contains(anchor.Value))
        {
            _aiCheckAnchorId = row.Source.Id;
            _aiCheckAnchorGrid = grid;
        }
        UpdateAiSelectionUi();
    }

    /// <summary>
    /// 预览与实际发送共用同一证据来源；统一按采集时间升序输出（最早在前、最新在最后），
    /// 与实际请求发生顺序一致，避免模型把列表展示顺序误判为执行顺序。
    /// </summary>
    private TrafficRecord[] GetAiEvidence()
    {
        if (_groupAiEvidence is { Length: > 0 }) return _groupAiEvidence.OrderBy(item => item.Timestamp).ToArray();
        var selected = GetCurrentVisibleCheckedTrafficRows().Select(row => row.Source).OrderBy(item => item.Timestamp).ToArray();
        if (selected.Length > 0) return selected;
        return SelectedTraffic is null ? [] : ExpandRelatedEvidence(SelectedTraffic.Source);
    }

    /// <summary>
    /// 仅分析当前高亮事务时，自动补全同主机更早时间的相关事务：参数取值通常来自登录、取 token、
    /// JS 装载等上游响应，缺少这些上下文模型无法溯源参数来源；补全条数等于设置中的“AI 证据事务上限”，
    /// 候选优先当前列表窗口，不足时扩展到最近持久化事务补齐；总体积仍由完整上下文 16 MB 上限兜底。
    /// </summary>
    private TrafficRecord[] ExpandRelatedEvidence(TrafficRecord target)
    {
        if (!Uri.TryCreate(target.Url, UriKind.Absolute, out var targetUri)) return [target];
        var capacity = _settings.AiEvidenceMaximumTransactions;
        if (capacity <= 1) return [target];
        var related = FilterRelatedEvidence(_storedTraffic.Values.Select(stored => stored.Traffic), target, targetUri, capacity - 1);
        if (related.Length < capacity - 1)
        {
            // 窗口内同主机上游事务不足以填满设置条数时，从最近持久化事务中补齐。
            try
            {
                using var archive = new TrafficArchive(_workspacePath);
                related = FilterRelatedEvidence(
                    archive.GetRecentTraffic(NetMindDefaults.AiEvidenceCompletionScanLimit).Select(item => item.Traffic),
                    target, targetUri, capacity - 1);
            }
            catch { /* 工作区不可读时退回窗口候选，不阻断分析 */ }
        }
        var chain = related.Append(target).OrderBy(item => item.Timestamp).ToArray();
        return chain.Length > 1 ? chain : [target];
    }

    private static TrafficRecord[] FilterRelatedEvidence(IEnumerable<TrafficRecord> pool, TrafficRecord target, Uri targetUri, int take) =>
        pool.Where(item => item.Id != target.Id && item.Timestamp <= target.Timestamp &&
                           Uri.TryCreate(item.Url, UriKind.Absolute, out var itemUri) &&
                           string.Equals(itemUri.Host, targetUri.Host, StringComparison.OrdinalIgnoreCase))
            .DistinctBy(item => item.Id)
            .OrderByDescending(item => item.Timestamp)
            .Take(take)
            .ToArray();

    private void UpdateAiSelectionUi()
    {
        if (AiSelectionCountText is null) return;
        SyncAiSelectAllBoxes();
        if (_groupAiEvidence is { Length: > 0 })
        {
            AiSelectionCountText.Text = $"AI 记录组 {_groupAiEvidence.Length} 条";
            AiSelectionCountText.Foreground = _groupAiEvidence.Length > _settings.AiEvidenceMaximumTransactions ? Red : Accent;
            UpdateAiEvidencePreview();
            return;
        }
        var count = GetCurrentVisibleCheckedTrafficRows().Length;
        AiSelectionCountText.Text = $"AI 已选 {count} 条";
        AiSelectionCountText.Foreground = count > _settings.AiEvidenceMaximumTransactions ? Red : count > 0 ? Accent : Muted;
        UpdateAiEvidencePreview();
    }

    /// <summary>同步表头全选框三态：全选=Checked、部分=Indeterminate、无=Unchecked；带守卫防事件回环。</summary>
    private void SyncAiSelectAllBoxes()
    {
        _syncingAiSelectAll = true;
        try
        {
            SetSelectAllState(OverviewAiSelectAll, TrafficRows);
            SetSelectAllState(TrafficAiSelectAll, FilteredTrafficRows);
        }
        finally { _syncingAiSelectAll = false; }
    }

    private static void SetSelectAllState(CheckBox? box, IReadOnlyCollection<TrafficRow> scope)
    {
        if (box is null) return;
        var total = scope.Count;
        var selected = scope.Count(row => row.IsAiSelected);
        box.IsChecked = total > 0 && selected == total ? true : selected > 0 ? null : false;
    }

    /// <summary>对话式分析不再有“发送上下文预览”：范围文案只陈述本次会话将使用的证据池来源与条数。</summary>
    private void UpdateAiEvidencePreview()
    {
        if (AiEvidenceScopeText is null) return;
        var evidence = GetAiEvidence();
        if (evidence.Length > _settings.AiEvidenceMaximumTransactions)
        {
            AiEvidenceScopeText.Text = $"已勾选 {evidence.Length} 条，超过单次分析上限 {_settings.AiEvidenceMaximumTransactions} 条";
            AiEvidenceScopeText.Foreground = Red;
            return;
        }
        AiEvidenceScopeText.Text = _groupAiEvidence is { Length: > 0 }
            ? $"仅分析记录组“{_groupAiName}”中的 {evidence.Length} 条可用事务"
            : GetCurrentVisibleCheckedTrafficRows().Length > 0
                ? $"仅分析明确勾选的 {evidence.Length} 条事务"
                : evidence.Length == 1
                    ? "未勾选记录：仅分析当前高亮事务"
                    : evidence.Length == 0
                        ? "尚未选择分析事务"
                        : $"未勾选记录：分析当前高亮事务，已自动补全 {evidence.Length - 1} 条同主机更早事务供参数溯源";
        AiEvidenceScopeText.Foreground = evidence.Length > 0 ? Amber : Muted;
    }

    // ==================== 页内 Hook 面板（流量探索子页） ====================

    private IReadOnlyList<PageHookEvent> _pageHookEvents = [];

    private async void 采集自检_Click(object sender, RoutedEventArgs e)
    {
        CaptureHealthCheckButton.IsEnabled = false;
        PageHookStatusText.Text = "正在核对采集链路…";
        try
        {
            var report = await CaptureHealthChecker.RunAsync(new CaptureHealthContext(
                _workspacePath,
                _capturing,
                _silentCaptureActive,
                IsProcessAlive(_coreHostProcess),
                _settings.ListenPort,
                _hookReceivePort,
                IsProcessAlive(_captureBrowserProcess),
                _captureBrowserDebuggingPort,
                _tlsInspectionEnabled,
                _lastPageHookStatus,
                _lastPageHookStatusAt));
            var failed = report.Items.Count(item => item.Level == CaptureHealthLevel.Failed);
            var warnings = report.Items.Count(item => item.Level == CaptureHealthLevel.Warning);
            PageHookStatusText.Text = failed > 0 ? $"自检发现 {failed} 项失败" : warnings > 0 ? $"自检有 {warnings} 项需注意" : "采集链路自检通过";
            PageHookStatusText.Foreground = failed > 0 ? Red : warnings > 0 ? Amber : Green;
            await new WorkspaceStore(_workspacePath).AppendAuditAsync("capture.health.checked",
                new { overall = report.OverallLevel.ToString(), failed, warnings, checkedAt = report.CheckedAt });
            new CaptureHealthWindow(report) { Owner = this }.ShowDialog();
        }
        catch (Exception exception)
        {
            PageHookStatusText.Text = "采集自检失败";
            PageHookStatusText.Foreground = Red;
            MessageBox.Show(this, $"无法完成采集自检：\n\n{exception.Message}", "采集自检", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally { CaptureHealthCheckButton.IsEnabled = true; }
    }

    /// <summary>页内 Hook 面板列表行：摘要展示字段 + 原始事件（双击详情用）。</summary>
    private sealed class PageHookRow
    {
        public required string Time { get; init; }
        public required string Type { get; init; }
        public required string Function { get; init; }
        /// <summary>调用目标的主机名；crypto/encode/storage 等非网络调用没有目标 URL，留空。</summary>
        public required string Host { get; init; }
        /// <summary>调用目标的路径与查询串。</summary>
        public required string Path { get; init; }
        public required string ArgsSummary { get; init; }
        public required PageHookEvent Event { get; init; }

        // 空值显示为"—"而不是空白：空白单元格和"这一列压根不存在"在视觉上没有区别，
        // 用户第一反应是列丢了，而不是"这条事件没有 URL"。
        public string HostDisplay => Host.Length == 0 ? "—" : Host;
        public string PathDisplay => Path.Length == 0 ? "—" : Path;

        public static (string Host, string Path) SplitTargetUrl(string targetUrl)
        {
            if (string.IsNullOrEmpty(targetUrl)) return (string.Empty, string.Empty);
            return Uri.TryCreate(targetUrl, UriKind.Absolute, out var uri)
                ? (uri.IsDefaultPort ? uri.Host : uri.Authority, uri.PathAndQuery)
                : (string.Empty, targetUrl); // 非绝对 URL（相对路径等）原样放进「路径」列，主机留空好过瞎猜
        }
    }

    private async void 探索子页_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        // 切到页内 Hook 子页时懒加载最新事件，不扰动流量列表刷新链路。
        if (PageHookList is null) return; // XAML 初始化阶段控件尚未全部创建
        if (ExploreSubTabs.SelectedIndex == 1) await RefreshPageHooksAsync();
    }

    private async void 页内Hook刷新_Click(object sender, RoutedEventArgs e) => await RefreshPageHooksAsync();

    private void 页内Hook筛选_Changed(object sender, RoutedEventArgs e)
    {
        // XAML 加载期 SelectedIndex="0" 会先于其余控件创建触发本回调，空守卫防启动崩溃。
        if (PageHookList is null) return;
        ApplyPageHookFilter();
    }

    /// <summary>从工作区元数据重新加载页内 Hook 事件（最多 500 条、最新在前）并应用当前过滤。</summary>
    private async Task RefreshPageHooksAsync()
    {
        if (_closing) return;
        try
        {
            var type = (PageHookTypeFilter.SelectedItem as ComboBoxItem)?.Tag as string;
            // 与流量列表同一套会话范围：开始采集后只显示本次会话的页内 Hook，
            // 否则新一轮采集会带出上一轮的调用记录。历史事件不删除，清除会话筛选即可看到全部。
            var scope = _sessionFilterId;
            var limit = _settings.PageHookWindowCount;
            _pageHookEvents = await Task.Run(() =>
            {
                using var archive = new TrafficArchive(_workspacePath);
                return scope is null
                    ? archive.GetPageHooks(type, limit)
                    : archive.GetPageHooksBySessions([scope.Value], type, limit);
            });
            ApplyPageHookFilter();
        }
        catch (Exception exception)
        {
            PageHookStatusText.Text = "加载失败：" + exception.Message;
            PageHookStatusText.Foreground = Red;
        }
    }

    /// <summary>关键字本地过滤（函数名/页面 URL/参数）并渲染列表；无事件时显示空态说明。</summary>
    private void ApplyPageHookFilter()
    {
        // 这个方法随采集定时器每 1.5 秒被调一次。旧实现无条件重建 ItemsSource：
        // 页面没有新 Hook 事件时也整表重排，还会把用户当前选中的那一行清掉。
        // 与流量表同一套约定——内容没变就什么都不做。
        var keyword = PageHookSearch.Text?.Trim() ?? string.Empty;
        IEnumerable<PageHookEvent> matches = _pageHookEvents;
        if (keyword.Length > 0)
        {
            matches = matches.Where(hook =>
                hook.Function.Contains(keyword, StringComparison.OrdinalIgnoreCase) ||
                hook.PageUrl.Contains(keyword, StringComparison.OrdinalIgnoreCase) ||
                hook.TargetUrl.Contains(keyword, StringComparison.OrdinalIgnoreCase) ||
                hook.Stack.Contains(keyword, StringComparison.OrdinalIgnoreCase) ||
                hook.ArgsJson.Contains(keyword, StringComparison.OrdinalIgnoreCase));
        }
        var rows = matches.Select(hook =>
        {
            var (host, path) = PageHookRow.SplitTargetUrl(hook.TargetUrl);
            return new PageHookRow
            {
                Time = hook.Timestamp.LocalDateTime.ToString("HH:mm:ss.fff"),
                Type = hook.Type,
                Function = hook.Function,
                Host = host,
                Path = path,
                ArgsSummary = string.IsNullOrEmpty(hook.ArgsJson) ? "（空）" : hook.ArgsJson.Replace('\n', ' '),
                Event = hook
            };
        }).ToArray();
        // 事件按数据库 rowid 比对：每次轮询都是新对象，但同一条事件的 Id 稳定。
        if (PageHookList.ItemsSource is PageHookRow[] current && current.Length == rows.Length &&
            !current.Where((row, index) => row.Event.Id != rows[index].Event.Id).Any())
            return;
        var selectedId = (PageHookList.SelectedItem as PageHookRow)?.Event.Id;
        PageHookList.ItemsSource = rows;
        if (selectedId.HasValue)
            PageHookList.SelectedItem = rows.FirstOrDefault(row => row.Event.Id == selectedId.Value);
        PageHookEmptyHint.Visibility = rows.Length == 0 ? Visibility.Visible : Visibility.Collapsed;
        PageHookStatusText.Text = $"共 {rows.Length} 条";
        PageHookStatusText.Foreground = Muted;
    }

    /// <summary>列表与详情现在左右并排（不再是需要双击才展开的折叠区），选中即预览更顺手；双击保留兼容。</summary>
    private void 页内Hook_选择变化(object sender, SelectionChangedEventArgs e) => RenderPageHookDetail();

    private void 页内Hook_双击(object sender, MouseButtonEventArgs e) => RenderPageHookDetail();

    private void RenderPageHookDetail()
    {
        if (PageHookList.SelectedItem is not PageHookRow row) return;
        var hook = row.Event;
        var builder = new StringBuilder();
        builder.Append("时间：").Append(hook.Timestamp.LocalDateTime.ToString("yyyy-MM-dd HH:mm:ss.fff")).Append('\n');
        builder.Append("类型：").Append(hook.Type).Append('\n');
        builder.Append("函数：").Append(hook.Function).Append('\n');
        if (!string.IsNullOrEmpty(hook.PageUrl)) builder.Append("页面 URL：").Append(hook.PageUrl).Append('\n');
        if (!string.IsNullOrEmpty(hook.TargetUrl)) builder.Append("调用 URL：").Append(hook.TargetUrl).Append('\n');
        if (!string.IsNullOrEmpty(hook.Stack)) builder.Append("调用位置：").Append(hook.Stack).Append('\n');
        builder.Append("参数：").Append('\n').Append(FormatPageHookArgs(hook.ArgsJson));
        PageHookDetailTitle.Text = $"{hook.Type} · {hook.Function} · {hook.Timestamp.LocalDateTime:HH:mm:ss.fff}";
        RenderKeyValueText(PageHookDetailBox, builder.ToString());
    }

    /// <summary>详情参数美化：JSON 对象/数组时缩进逐行展开（配合键值分色），否则原文展示。</summary>
    private static string FormatPageHookArgs(string argsJson)
    {
        if (string.IsNullOrWhiteSpace(argsJson)) return "（空）";
        try
        {
            using var document = JsonDocument.Parse(argsJson);
            return JsonSerializer.Serialize(document.RootElement,
                new JsonSerializerOptions { WriteIndented = true, Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping });
        }
        catch { return argsJson; }
    }

    /// <summary>
    /// 证据池的工作台实现：序号是池内从 1 起的索引，与首轮摘要一致；取数复用
    /// AiFullContextBuilder 的单事务投影（正文过滤/二进制预览/截断规则）。证据文件拥有独立工具，
    /// 模型可先看文件清单，再明确选择要读取的文件，不再和第一次事务取数隐式耦合。
    /// </summary>
    private sealed class WorkbenchAiEvidenceProvider(MainWindow owner, IReadOnlyList<TrafficRecord> pool) : AiEvidenceProvider
    {
        private readonly Lazy<AiPreparedEvidence> _preparedEvidence = new(
            () => AiEvidencePreparationEngine.Prepare(pool), LazyThreadSafetyMode.ExecutionAndPublication);

        public IReadOnlyList<TrafficRecord> Pool { get; } = pool;
        public AiPreparedEvidence PreparedEvidence => _preparedEvidence.Value;
        public IReadOnlyList<string> EvidenceFileNames => owner._aiAttachedFiles.Select(file => file.Name).ToArray();

        public async Task<string> GetTransactionsAsync(int[] ordinals, CancellationToken cancellationToken)
        {
            var inlineBodies = new Dictionary<string, byte[]>(StringComparer.Ordinal);
            var records = new List<StoredTrafficRecord>();
            foreach (var ordinal in ordinals.Distinct())
            {
                if (ordinal < 1 || ordinal > Pool.Count) continue;
                records.Add(owner.ResolveAiEvidenceRecord(Pool[ordinal - 1], inlineBodies));
            }
            if (records.Count == 0) return $"[请求的序号均无效，有效范围 #1 到 #{Pool.Count}]";
            return await AiFullContextBuilder.BuildTransactionsJsonAsync(records,
                (hash, token) => inlineBodies.TryGetValue(hash, out var body)
                    ? Task.FromResult(new StoredBlobContent(body, body.Length, false))
                    : owner.ReadAiBlobAsync(hash, token, NetMindDefaults.AiToolMaximumBodyBytesPerTransaction),
                cancellationToken);
        }

        public async Task<string> SearchAsync(string keyword, CancellationToken cancellationToken)
        {
            if (string.IsNullOrWhiteSpace(keyword)) return "[搜索关键字为空]";
            var builder = new StringBuilder();
            var totalHits = 0;
            for (var index = 0; index < Pool.Count; index++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var record = Pool[index];
                var locations = new List<string>();
                foreach (var (content, label) in new[]
                {
                    (record.Url, "URL"), (record.QueryParameters, "查询参数"), (record.Cookies, "Cookie"),
                    (record.RequestHeaders, "请求头"), (record.ResponseHeaders, "响应头")
                })
                {
                    if (!string.IsNullOrEmpty(content) && content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                        locations.Add(label);
                }
                // 正文只读有界上限内的持久化正文，控制搜索成本。
                if (owner._storedTraffic.TryGetValue(record.Id, out var stored))
                {
                    foreach (var (hash, label) in new[] { (stored.RequestBlobHash, "请求正文"), (stored.ResponseBlobHash, "响应正文") })
                    {
                        if (string.IsNullOrEmpty(hash)) continue;
                        try
                        {
                            var blob = await owner.ReadAiBlobAsync(hash, cancellationToken);
                            var bodyText = Encoding.UTF8.GetString(blob.Content);
                            var matchIndex = bodyText.IndexOf(keyword, StringComparison.OrdinalIgnoreCase);
                            if (matchIndex >= 0)
                                locations.Add($"{label}（{BuildSearchSnippet(bodyText, matchIndex, keyword.Length)}）");
                        }
                        catch { /* 单条正文读取失败不阻断整体搜索 */ }
                    }
                }
                if (locations.Count > 0)
                {
                    totalHits += locations.Count;
                    builder.Append('#').Append(index + 1).Append(' ').Append(record.Method).Append(' ')
                        .Append(record.Endpoint).Append(" 命中：").AppendJoin("、", locations).Append('\n');
                }
                if (totalHits >= 50)
                {
                    builder.Append("…… 命中数已达上限，其余省略 ……\n");
                    break;
                }
            }
            return builder.Length == 0 ? $"[关键字“{keyword}”在证据池中未命中]" : builder.ToString().TrimEnd();
        }

        public async Task<string> GetHooksAsync(string? type, int limit, CancellationToken cancellationToken)
        {
            var sessionIds = Pool
                .Select(record => owner._storedTraffic.TryGetValue(record.Id, out var stored) ? stored.SessionId : Guid.Empty)
                .Where(id => id != Guid.Empty)
                .Distinct()
                .ToArray();
            if (sessionIds.Length == 0)
                return "[当前证据池没有可关联的持久化捕获会话，未读取其他会话的 Hook 事件]";
            IReadOnlyList<PageHookEvent> events;
            try
            {
                events = await Task.Run(() =>
                {
                    using var archive = new TrafficArchive(owner._workspacePath);
                    return archive.GetPageHooksBySessions(sessionIds, string.IsNullOrWhiteSpace(type) ? null : type,
                        Math.Clamp(limit, 1, 1000));
                }, cancellationToken);
            }
            catch (OperationCanceledException) { throw; }
            catch { return "[页内 Hook 事件读取失败]"; }
            if (events.Count == 0) return "[暂无页内 Hook 事件：采集浏览器未注入脚本或页面尚未触发被包裹的调用]";
            var builder = new StringBuilder();
            foreach (var hook in events)
            {
                builder.Append('[').Append(hook.Timestamp.LocalDateTime.ToString("HH:mm:ss.fff")).Append("] ")
                    .Append(hook.Type).Append(' ').Append(hook.Function);
                if (!string.IsNullOrEmpty(hook.PageUrl)) builder.Append(" 页面：").Append(hook.PageUrl);
                if (!string.IsNullOrEmpty(hook.TargetUrl)) builder.Append(" 调用URL：").Append(hook.TargetUrl);
                if (!string.IsNullOrEmpty(hook.Stack)) builder.Append(" 调用位置：").Append(hook.Stack);
                builder.Append(" 参数：").Append(string.IsNullOrEmpty(hook.ArgsJson) ? "（空）" : hook.ArgsJson).Append('\n');
            }
            return builder.ToString().TrimEnd();
        }

        public Task<string> GetEvidenceFilesAsync(string[] names, CancellationToken cancellationToken) =>
            owner.BuildAiEvidenceFilesJsonAsync(names, cancellationToken);

        public async Task<string> GetTransactionBodyExcerptAsync(
            int ordinal, string direction, string? keyword, int maximumCharacters, CancellationToken cancellationToken)
        {
            if (ordinal < 1 || ordinal > Pool.Count) return $"[无效序号：有效范围 #1 到 #{Pool.Count}]";
            maximumCharacters = Math.Clamp(maximumCharacters, 512, NetMindDefaults.AiToolBodyExcerptMaximumCharacters);
            var inlineBodies = new Dictionary<string, byte[]>(StringComparer.Ordinal);
            var stored = owner.ResolveAiEvidenceRecord(Pool[ordinal - 1], inlineBodies);
            var blobHash = direction == "request" ? stored.RequestBlobHash : stored.ResponseBlobHash;
            if (string.IsNullOrWhiteSpace(blobHash)) return $"[#{ordinal} 的{(direction == "request" ? "请求" : "响应")}正文为空]";

            StoredBlobContent blob;
            if (inlineBodies.TryGetValue(blobHash, out var inline))
                blob = new StoredBlobContent(inline, inline.Length, false);
            else
                blob = await owner.ReadAiBlobAsync(blobHash, cancellationToken);

            if (blob.Content.AsSpan(0, Math.Min(blob.Content.Length, 8192)).Contains((byte)0))
                return $"[#{ordinal} 的{(direction == "request" ? "请求" : "响应")}正文是二进制数据，不适合文本片段检索]";
            var body = Encoding.UTF8.GetString(blob.Content);
            var matchIndex = string.IsNullOrWhiteSpace(keyword)
                ? -1
                : body.IndexOf(keyword, StringComparison.OrdinalIgnoreCase);
            var start = matchIndex < 0 ? 0 : Math.Max(0, matchIndex - maximumCharacters / 3);
            var length = Math.Min(maximumCharacters, Math.Max(0, body.Length - start));
            var excerpt = length == 0 ? string.Empty : body.Substring(start, length);
            return JsonSerializer.Serialize(new
            {
                ordinal,
                direction,
                keyword = string.IsNullOrWhiteSpace(keyword) ? null : keyword,
                keywordFound = matchIndex >= 0,
                excerptStartCharacter = start,
                excerptEndCharacter = start + length,
                decodedCharactersRead = body.Length,
                originalBytes = blob.OriginalLength,
                sourceReadTruncated = blob.Truncated,
                excerptTruncated = start > 0 || start + length < body.Length || blob.Truncated,
                excerpt
            }, new JsonSerializerOptions
            {
                WriteIndented = true,
                Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
            });
        }

        private static string BuildSearchSnippet(string text, int matchIndex, int keywordLength)
        {
            const int maximumCharacters = 240;
            var start = Math.Max(0, matchIndex - 80);
            var end = Math.Min(text.Length, Math.Max(matchIndex + keywordLength + 80, start + maximumCharacters));
            if (end - start > maximumCharacters) end = start + maximumCharacters;
            var snippet = text[start..end].Replace('\r', ' ').Replace('\n', ' ').Trim();
            return (start > 0 ? "…" : string.Empty) + snippet + (end < text.Length ? "…" : string.Empty);
        }
    }

    /// <summary>证据池记录转为存储事务：未持久化事务（演示数据）降级为内联正文 Blob。</summary>
    private StoredTrafficRecord ResolveAiEvidenceRecord(TrafficRecord record, Dictionary<string, byte[]> inlineBodies)
    {
        if (_storedTraffic.TryGetValue(record.Id, out var stored)) return stored;
        var requestKey = "inline-request-" + record.Id.ToString("N");
        var responseKey = "inline-response-" + record.Id.ToString("N");
        inlineBodies[requestKey] = Encoding.UTF8.GetBytes(record.RequestSummary);
        inlineBodies[responseKey] = Encoding.UTF8.GetBytes(record.ResponseSummary);
        return new StoredTrafficRecord(record, Guid.Empty, requestKey, responseKey, SourceDemo);
    }

    /// <summary>读取 AI 取数用的正文 Blob；事务概览使用更小上限，关键词片段在本地有界读取后再裁剪。</summary>
    private Task<StoredBlobContent> ReadAiBlobAsync(
        string hash, CancellationToken cancellationToken, int maximumBytes = AiMaximumBodyBytesPerTransaction) =>
        new WorkspaceStore(_workspacePath).ReadBlobAsync(hash, maximumBytes, cancellationToken);

    private void Ai结果_菜单打开(object sender, RoutedEventArgs e)
    {
        // FlowDocumentScrollViewer 内置编辑菜单是浅色系统样式，与深色主题不一致，拦截后弹出自定义深色菜单。
        e.Handled = true;
        if (TryFindResource("AiResultContextMenu") is not ContextMenu menu || AiLegacyViewer is null) return;
        menu.PlacementTarget = AiLegacyViewer;
        menu.Placement = PlacementMode.MousePoint;
        menu.IsOpen = true;
    }

    private void 复制结果选择_Click(object sender, RoutedEventArgs e) => ApplicationCommands.Copy.Execute(null, AiLegacyViewer);

    private void 全选结果_Click(object sender, RoutedEventArgs e)
    {
        if (AiLegacyViewer is not null) ApplicationCommands.SelectAll.Execute(null, AiLegacyViewer);
    }

    private void 复制全部结果_Click(object sender, RoutedEventArgs e)
    {
        if (!string.IsNullOrEmpty(_currentAiMarkdown)) Clipboard.SetText(_currentAiMarkdown);
    }

    /// <summary>读取模型明确选择的证据文件；文件名在当前清单内匹配，避免模型构造任意本地路径。</summary>
    private async Task<string> BuildAiEvidenceFilesJsonAsync(string[] names, CancellationToken cancellationToken)
    {
        var requested = names.Length == 0
            ? _aiAttachedFiles.ToArray()
            : _aiAttachedFiles.Where(file => names.Contains(file.Name, StringComparer.OrdinalIgnoreCase)).ToArray();
        if (requested.Length == 0) return "[请求的证据文件不在当前会话清单中]";
        var files = new List<Dictionary<string, object?>>(requested.Length);
        foreach (var file in requested)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var bytes = await File.ReadAllBytesAsync(file.FullPath, cancellationToken);
                var probeLength = Math.Min(bytes.Length, 4096);
                var isBinary = Array.IndexOf(bytes, (byte)0, 0, probeLength) >= 0;
                files.Add(new Dictionary<string, object?>
                {
                    ["文件名"] = file.Name,
                    ["大小"] = file.SizeBytes,
                    ["内容"] = isBinary ? "（二进制文件，无法作为文本发送，已省略正文）" : Encoding.UTF8.GetString(bytes),
                });
            }
            catch (Exception exception)
            {
                files.Add(new Dictionary<string, object?> { ["文件名"] = file.Name, ["读取失败"] = exception.Message });
            }
        }
        return JsonSerializer.Serialize(new Dictionary<string, object?> { ["证据文件"] = files }, new JsonSerializerOptions(JsonSerializerDefaults.Web)
        {
            WriteIndented = true,
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        });
    }

    private sealed record AiAttachedFile(string FullPath, string Name, long SizeBytes)
    {
        public string Display => $"{Name} · {SizeBytes:N0} 字节 · {FullPath}";
    }

    private void 添加AI附加文件_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Multiselect = true,
            Title = "选择当前 AI 会话要使用的证据文件",
            Filter = "常用证据|*.js;*.mjs;*.json;*.har;*.txt;*.log;*.md;*.html;*.xml;*.yaml;*.yml;*.csv|所有文件|*.*"
        };
        // 目录优先级：记忆的上次位置 → 系统下载目录 → 当前目录。
        var initialDirectory = _lastAttachedFileDirectory;
        if (initialDirectory is null || !Directory.Exists(initialDirectory))
        {
            initialDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
            if (!Directory.Exists(initialDirectory)) initialDirectory = Environment.CurrentDirectory;
        }
        dialog.InitialDirectory = initialDirectory;
        if (dialog.ShowDialog(this) != true) return;
        if (dialog.FileNames.Length > 0) _lastAttachedFileDirectory = Path.GetDirectoryName(dialog.FileNames[0]);
        foreach (var path in dialog.FileNames)
        {
            if (_aiAttachedFiles.Count >= AiMaximumAttachedFiles)
            {
                AiAttachedFilesSummary.Text = $"最多追加 {AiMaximumAttachedFiles} 个文件，其余已跳过";
                break;
            }
            if (_aiAttachedFiles.Any(item => string.Equals(item.FullPath, path, StringComparison.OrdinalIgnoreCase))) continue;
            var info = new FileInfo(path);
            if (!info.Exists) continue;
            if (info.Length > AiMaximumAttachedFileBytes)
            {
                AiAttachedFilesSummary.Text = $"已跳过 {info.Name}：超过单文件 {AiMaximumAttachedFileBytes / 1024} KB 上限";
                continue;
            }
            _aiAttachedFiles.Add(new AiAttachedFile(path, info.Name, info.Length));
        }
        RefreshAiAttachedFilesUi();
        UpdateAiEvidencePreview();
    }

    private void 移除AI附加文件_Click(object sender, RoutedEventArgs e)
    {
        foreach (var selected in GetSelectedAttachedFiles()) _aiAttachedFiles.Remove(selected);
        RefreshAiAttachedFilesUi();
        UpdateAiEvidencePreview();
    }

    private IEnumerable<AiAttachedFile> GetSelectedAttachedFiles() =>
        AiAttachedFilesList.SelectedItems.OfType<AiAttachedFile>().ToList();

    private void RefreshAiAttachedFilesUi()
    {
        if (AiAttachedFilesList.ItemsSource != _aiAttachedFiles) AiAttachedFilesList.ItemsSource = _aiAttachedFiles;
        AiAttachedFilesList.Visibility = _aiAttachedFiles.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
        RemoveAiAttachedFileButton.Visibility = _aiAttachedFiles.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
        if (_aiAttachedFiles.Count > 0)
        {
            AiAttachedFilesSummary.Text = $"{_aiAttachedFiles.Count} 个证据文件 · 模型按需读取";
            AiAttachedFilesSummary.Visibility = Visibility.Visible;
        }
        else if (AiAttachedFilesSummary.Text.StartsWith("已跳过", StringComparison.Ordinal))
        {
            AiAttachedFilesSummary.Visibility = Visibility.Visible;
        }
        else if (string.IsNullOrEmpty(AiAttachedFilesSummary.Text) || !AiAttachedFilesSummary.Text.StartsWith("已跳过", StringComparison.Ordinal))
        {
            AiAttachedFilesSummary.Text = string.Empty;
            AiAttachedFilesSummary.Visibility = Visibility.Collapsed;
        }
    }

    private void ClearGroupAiScope()
    {
        _groupAiEvidence = null;
        _groupAiName = null;
    }

    private async Task UpdateTrafficEvidenceAsync(TrafficRecord traffic)
    {
        if (TrafficEvidenceTitle is null) return;
        // 先取消上一次未完成的证据加载，与既有 SelectedTraffic 事务 ID 比对构成快速切换的双重防护。
        _evidenceLoadCts?.Cancel();
        _evidenceLoadCts?.Dispose();
        var evidenceLoad = new CancellationTokenSource();
        _evidenceLoadCts = evidenceLoad;
        var token = evidenceLoad.Token;
        // 三个 JSON 树视图与切换按钮统一重置，避免上一条事务的残留。
        ResetEvidenceJsonViews();
        TrafficEvidenceTitle.Text = $"{traffic.Method} {traffic.Endpoint}";
        var source = _storedTraffic.TryGetValue(traffic.Id, out var sourceRecord) ? SourceLabel(sourceRecord.CaptureMode) : SourceDemo;
        TrafficEvidenceMeta.Text = $"来源：{source} · {traffic.Protocol} · 状态 {traffic.StatusCode} · {traffic.Process}";
        // 原“事务与采集信息”底部区块已按需求移除，相关字段同步清理。
        TrafficUrlText.Text = string.IsNullOrWhiteSpace(traffic.Url) ? "历史记录未保存完整 URL" : traffic.Url;
        RenderKeyValueText(TrafficQueryText, string.IsNullOrWhiteSpace(traffic.QueryParameters) ? "无查询参数" : traffic.QueryParameters);
        RenderKeyValueText(TrafficCookieText, string.IsNullOrWhiteSpace(traffic.Cookies) ? "无 Cookie，或历史记录未保存 Cookie 元数据" : traffic.Cookies);
        RenderKeyValueText(TrafficRequestHeadersText, string.IsNullOrWhiteSpace(traffic.RequestHeaders) ? "历史记录未保存请求头" : traffic.RequestHeaders);
        RenderKeyValueText(TrafficResponseHeadersText, string.IsNullOrWhiteSpace(traffic.ResponseHeaders) ? "历史记录未保存响应头" : traffic.ResponseHeaders);
        // 内容搜索定位的同步项（URL/参数/Cookie/头）在此处即可高亮；正文项在异步加载完成后重试。
        TryApplyPendingHighlight();
        SetResponsePreviewMessage("正在准备响应预览…");
        if (traffic.Protocol == ProtocolHttpsTunnel || traffic.Method == "CONNECT")
        {
            TrafficRequestBody.Text = "TLS 正文保持加密。仅记录 CONNECT 目标和连接元数据。";
            TrafficResponseBody.Text = traffic.ResponseSummary;
            SetResponsePreviewMessage("TLS 正文保持加密，无法生成响应预览。");
            return;
        }
        if (!_storedTraffic.TryGetValue(traffic.Id, out var stored))
        {
            TrafficRequestBody.Text = traffic.RequestSummary;
            TrafficResponseBody.Text = traffic.ResponseSummary;
            SetResponsePreviewMessage("演示或历史记录没有可读取的原始响应正文。");
            return;
        }

        TrafficRequestBody.Text = "正在读取内容寻址存储…";
        TrafficResponseBody.Text = "正在读取内容寻址存储…";
        try
        {
            // 快速连点/按住方向键连翻时，先等一小会儿再真正读盘。
            // 上一次的令牌在方法开头已被取消，所以中途路过的行只花一次取消，不会去读它的正文。
            await Task.Delay(EvidenceLoadDebounceMilliseconds, token);
            var workspace = new WorkspaceStore(_workspacePath);
            var requestTask = workspace.ReadBlobAsync(stored.RequestBlobHash, cancellationToken: token);
            var responseTask = workspace.ReadBlobAsync(stored.ResponseBlobHash, BlobPreviewMaximumBytes, token);
            await Task.WhenAll(requestTask, responseTask);
            if (token.IsCancellationRequested || SelectedTraffic?.Source.Id != traffic.Id) return;
            var requestBlob = await requestTask;
            var responseBlob = await responseTask;
            // 正文可能有数 MB，格式化（含二进制判定与十六进制预览）不能占着界面线程做。
            var requestText = await Task.Run(() => FormatBlob(requestBlob), token);
            var responseText = await Task.Run(() => FormatBlob(responseBlob), token);
            if (token.IsCancellationRequested || SelectedTraffic?.Source.Id != traffic.Id) return;
            TrafficRequestBody.Text = requestText;
            TrafficResponseBody.Text = responseText;
            // JSON 树构建与响应预览（图片解码/HTML 取文本）都是重活，降到后台优先级排队；
            // 期间用户又点了别的行，令牌一取消它们就不会执行，界面不会被上一条的渲染拖住。
            await Dispatcher.InvokeAsync(() =>
            {
                if (token.IsCancellationRequested || SelectedTraffic?.Source.Id != traffic.Id) return;
                TryShowBodyJsonTree(traffic.RequestHeaders, requestBlob, stored.RequestBlobHash, TrafficRequestJsonTree, TrafficRequestBody, 请求正文视图切换);
                TryShowBodyJsonTree(traffic.ResponseHeaders, responseBlob, stored.ResponseBlobHash, TrafficResponseJsonTree, TrafficResponseBody, 响应正文视图切换);
                UpdateResponsePreview(traffic, responseBlob, stored.ResponseBlobHash);
                // 正文加载完成后重试内容搜索定位的待高亮关键字（若当前为树视图会自动切回原始正文）。
                TryApplyPendingHighlight();
            }, DispatcherPriority.Background);
        }
        catch (OperationCanceledException)
        {
            // 用户已经切到别的记录：这一条的证据不必再渲染。
        }
        catch (Exception exception)
        {
            if (token.IsCancellationRequested || SelectedTraffic?.Source.Id != traffic.Id) return;
            TrafficRequestBody.Text = "读取请求正文失败：" + exception.Message;
            TrafficResponseBody.Text = "读取响应正文失败：" + exception.Message;
            SetResponsePreviewMessage("生成响应预览失败：" + exception.Message);
        }
    }

    private void UpdateResponsePreview(TrafficRecord traffic, StoredBlobContent blob, string blobHash)
    {
        TrafficResponseImage.Source = null;
        TrafficResponseImage.Visibility = Visibility.Collapsed;
        TrafficResponsePreviewText.Visibility = Visibility.Visible;
        JsonTreeViewRenderer.Clear(TrafficResponsePreviewJsonTree);
        TrafficResponsePreviewJsonTree.Visibility = Visibility.Collapsed;
        if (blob.Content.Length == 0)
        {
            TrafficResponsePreviewStatus.Text = "空响应";
            TrafficResponsePreviewText.Text = "（响应正文为空）";
            return;
        }

        var mediaType = ResolveResponseMediaType(traffic);
        if (mediaType is "image/png" or "image/jpeg" or "image/jpg" or "image/gif" or "image/bmp" or "image/x-icon" or "image/vnd.microsoft.icon")
        {
            if (blob.Truncated)
            {
                SetResponsePreviewMessage($"图片超过 4 MB 预览上限（原始大小 {blob.OriginalLength:N0} 字节）。");
                return;
            }
            try
            {
                using var stream = new MemoryStream(blob.Content, writable: false);
                var image = new BitmapImage();
                image.BeginInit();
                image.CacheOption = BitmapCacheOption.OnLoad;
                image.CreateOptions = BitmapCreateOptions.PreservePixelFormat;
                image.StreamSource = stream;
                image.EndInit();
                image.Freeze();
                TrafficResponseImage.Source = image;
                TrafficResponseImage.Visibility = Visibility.Visible;
                TrafficResponsePreviewText.Visibility = Visibility.Collapsed;
                TrafficResponsePreviewStatus.Text = $"{mediaType} · {image.PixelWidth} × {image.PixelHeight} · {blob.Content.Length:N0} 字节";
                return;
            }
            catch (Exception exception) when (exception is not OutOfMemoryException)
            {
                SetResponsePreviewMessage("图片数据无法解码：" + exception.Message);
                return;
            }
        }

        var text = Encoding.UTF8.GetString(blob.Content);
        if (mediaType == "application/json" || mediaType.EndsWith("+json", StringComparison.Ordinal))
        {
            var root = GetOrBuildJsonTree(blobHash, blob);
            if (root is not null)
            {
                JsonTreeViewRenderer.Render(TrafficResponsePreviewJsonTree, root);
                if (TrafficResponsePreviewJsonTree.Items.Count > 0)
                {
                    TrafficResponsePreviewJsonTree.Visibility = Visibility.Visible;
                    TrafficResponsePreviewText.Visibility = Visibility.Collapsed;
                    TrafficResponsePreviewStatus.Text = $"JSON · {blob.OriginalLength:N0} 字节";
                    return;
                }
            }
            // 建树失败（截断/超限）时降级为解码后的缩进扁平文本；无效 JSON 会在解析时抛出并落入既有中文文案。
            try
            {
                text = JsonPreviewText.Build(blob.Content);
                TrafficResponsePreviewStatus.Text = $"JSON · {blob.OriginalLength:N0} 字节";
                TrafficResponsePreviewText.Text = LimitPreviewText(text, blob);
                return;
            }
            catch (JsonException)
            {
                SetResponsePreviewMessage("响应声明为 JSON，但正文格式无效。原始正文仍可在下方查看。");
                return;
            }
        }

        if (mediaType == "text/html")
        {
            text = Regex.Replace(text, @"(?is)<(script|style)\b[^>]*>.*?</\1>", " ");
            text = WebUtility.HtmlDecode(Regex.Replace(text, @"(?s)<[^>]+>", " "));
            text = Regex.Replace(text, @"[ \t\f\v]+", " ");
            text = Regex.Replace(text, @"(?:\r?\n\s*){3,}", Environment.NewLine + Environment.NewLine).Trim();
            TrafficResponsePreviewStatus.Text = $"HTML 安全文本 · {blob.OriginalLength:N0} 字节";
            TrafficResponsePreviewText.Text = LimitPreviewText(text, blob);
            return;
        }

        if (mediaType.StartsWith("text/", StringComparison.Ordinal) || mediaType.Contains("xml", StringComparison.Ordinal) ||
            mediaType.Contains("javascript", StringComparison.Ordinal) || mediaType == "image/svg+xml" ||
            mediaType == "application/x-www-form-urlencoded")
        {
            TrafficResponsePreviewStatus.Text = $"{(string.IsNullOrWhiteSpace(mediaType) ? "文本" : mediaType)} · {blob.OriginalLength:N0} 字节";
            TrafficResponsePreviewText.Text = LimitPreviewText(text, blob);
            return;
        }

        SetResponsePreviewMessage(string.IsNullOrWhiteSpace(mediaType)
            ? "无法识别响应类型，暂无可视化预览。"
            : $"{mediaType} 暂无安全可视化预览，原始正文仍可在下方查看。");
    }

    private static string ResolveResponseMediaType(TrafficRecord traffic)
    {
        foreach (var line in traffic.ResponseHeaders.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
        {
            var separator = line.IndexOf(':');
            if (separator > 0 && line[..separator].Trim().Equals("Content-Type", StringComparison.OrdinalIgnoreCase))
                return line[(separator + 1)..].Split(';', 2)[0].Trim().ToLowerInvariant();
        }
        var summaryType = traffic.ResponseSummary.Split('·', 2)[0].Trim().ToLowerInvariant();
        return summaryType.Contains('/') ? summaryType : string.Empty;
    }

    private static string LimitPreviewText(string text, StoredBlobContent blob)
    {
        const int maximumCharacters = BlobPreviewDefaultBytes;
        var limited = text.Length > maximumCharacters ? text[..maximumCharacters] : text;
        return blob.Truncated || text.Length > maximumCharacters
            ? limited + $"\n\n[预览已截断，原始正文 {blob.OriginalLength:N0} 字节]"
            : limited;
    }

    private void SetResponsePreviewMessage(string message)
    {
        if (TrafficResponseImage is null || TrafficResponsePreviewText is null) return;
        TrafficResponseImage.Source = null;
        TrafficResponseImage.Visibility = Visibility.Collapsed;
        JsonTreeViewRenderer.Clear(TrafficResponsePreviewJsonTree);
        TrafficResponsePreviewJsonTree.Visibility = Visibility.Collapsed;
        TrafficResponsePreviewText.Visibility = Visibility.Visible;
        TrafficResponsePreviewText.Text = message;
        TrafficResponsePreviewStatus.Text = "预览状态";
    }

    private void 请求正文视图切换_Click(object sender, RoutedEventArgs e) =>
        ToggleBodyJsonView(TrafficRequestJsonTree, TrafficRequestBody, 请求正文视图切换);

    private void 响应正文视图切换_Click(object sender, RoutedEventArgs e) =>
        ToggleBodyJsonView(TrafficResponseJsonTree, TrafficResponseBody, 响应正文视图切换);

    /// <summary>在树视图与原始正文之间切换显示；显示树时按钮文字为“原始正文”，显示文本时为“树视图”。</summary>
    private static void ToggleBodyJsonView(TreeView jsonTree, TextBox bodyText, Button toggleButton)
    {
        var showTree = jsonTree.Visibility != Visibility.Visible;
        jsonTree.Visibility = showTree ? Visibility.Visible : Visibility.Collapsed;
        bodyText.Visibility = showTree ? Visibility.Collapsed : Visibility.Visible;
        toggleButton.Content = showTree ? "原始正文" : "树视图";
    }

    /// <summary>切换事务时统一重置三个 JSON 树视图与正文切换按钮（默认树视图优先，按钮复位为“原始正文”）。</summary>
    private void ResetEvidenceJsonViews()
    {
        JsonTreeViewRenderer.Clear(TrafficRequestJsonTree);
        JsonTreeViewRenderer.Clear(TrafficResponseJsonTree);
        JsonTreeViewRenderer.Clear(TrafficResponsePreviewJsonTree);
        TrafficRequestJsonTree.Visibility = Visibility.Collapsed;
        TrafficResponseJsonTree.Visibility = Visibility.Collapsed;
        TrafficResponsePreviewJsonTree.Visibility = Visibility.Collapsed;
        TrafficRequestBody.Visibility = Visibility.Visible;
        TrafficResponseBody.Visibility = Visibility.Visible;
        请求正文视图切换.Visibility = Visibility.Collapsed;
        响应正文视图切换.Visibility = Visibility.Collapsed;
        请求正文视图切换.Content = "原始正文";
        响应正文视图切换.Content = "原始正文";
    }

    /// <summary>JSON 树右键菜单：对菜单挂靠的 TreeView 递归展开全部节点。</summary>
    private void JSON树展开全部_Click(object sender, RoutedEventArgs e) => SetJsonTreeExpanded(sender, expand: true);

    /// <summary>JSON 树右键菜单：对菜单挂靠的 TreeView 递归折叠全部节点。</summary>
    private void JSON树折叠全部_Click(object sender, RoutedEventArgs e) => SetJsonTreeExpanded(sender, expand: false);

    private static void SetJsonTreeExpanded(object sender, bool expand)
    {
        if (sender is not MenuItem { Parent: ContextMenu menu } || menu.PlacementTarget is not TreeView tree) return;
        // 树为 ItemsSource 模式：Items 内是数据节点而非 TreeViewItem，必须经 ItemContainerGenerator 取容器；
        // 展开全部时逐层先置 IsExpanded 再下钻，WPF 会同步生成直接子容器，惰性 Children 也随之物化。
        SetJsonTreeGeneratorExpanded(tree.ItemContainerGenerator, expand);
    }

    private static void SetJsonTreeGeneratorExpanded(ItemContainerGenerator generator, bool expand)
    {
        for (var index = 0; index < generator.Items.Count; index++)
        {
            if (generator.ContainerFromIndex(index) is not TreeViewItem item) continue;
            item.IsExpanded = expand;
            if (!expand)
            {
                SetJsonTreeGeneratorExpanded(item.ItemContainerGenerator, expand: false);
                continue;
            }
            // 置 IsExpanded 不会同步生成子容器（惰性布局才生成），直接递归只能展开第一层；
            // 先强制同步布局使直接子容器物化，再下钻，才能递归展开全部层级。
            item.UpdateLayout();
            SetJsonTreeGeneratorExpanded(item.ItemContainerGenerator, expand: true);
        }
    }

    /// <summary>
    /// 全局滚轮转发：Markdown 查看器/证据文本框/表格等内层可滚控件在自身内容滚不动时仍会吞掉滚轮事件，
    /// 导致聊天区等外层滚动区必须拖动滚动条。在隧道阶段检查光标下最内层 ScrollViewer 的可滚余量，
    /// 已到边界则向上转发给第一个仍可滚动的外层；内层尚有余量时不干预，保持其原生滚动。
    /// </summary>
    private void 窗口_滚轮转发(object sender, MouseWheelEventArgs e)
    {
        if (e.Handled) return;
        var source = e.OriginalSource as DependencyObject ?? e.Source as DependencyObject;
        if (source is null) return;
        var inner = FindScrollViewer(source);
        if (inner is null) return;
        if (CanScrollVertically(inner, e.Delta)) return;
        for (var parent = GetAnyParent(inner); parent is not null; parent = GetAnyParent(parent))
        {
            if (parent is ScrollViewer outer && CanScrollVertically(outer, e.Delta))
            {
                // 每格 120 增量折算约 56 像素，与各滚动区原生手感接近。
                outer.ScrollToVerticalOffset(outer.VerticalOffset - e.Delta / 120.0 * 56);
                e.Handled = true;
                return;
            }
        }
    }

    private static bool CanScrollVertically(ScrollViewer viewer, int delta)
        => viewer.ScrollableHeight > 0 && (delta > 0 ? viewer.VerticalOffset > 0 : viewer.VerticalOffset < viewer.ScrollableHeight);

    /// <summary>
    /// 向上取父级：Visual/Visual3D 走视觉树；命中 Run/Paragraph 等流文档内联元素时它们是 ContentElement 而非 Visual，
    /// VisualTreeHelper.GetParent 会直接抛 InvalidOperationException 导致滚动即崩溃，必须改走逻辑树。
    /// </summary>
    private static DependencyObject? GetAnyParent(DependencyObject node)
    {
        if (node is Visual) return VisualTreeHelper.GetParent(node);
        if (node is ContentElement content)
            return ContentOperations.GetParent(content) ?? LogicalTreeHelper.GetParent(node);
        return LogicalTreeHelper.GetParent(node);
    }

    private static ScrollViewer? FindScrollViewer(DependencyObject source)
    {
        for (var current = source; current is not null; current = GetAnyParent(current))
            if (current is ScrollViewer viewer) return viewer;
        return null;
    }

    /// <summary>请求/响应正文的 JSON 树展示尝试：建树成功则显示树并隐藏原始正文 TextBox；失败保持既有文本与隐藏按钮。</summary>
    private void TryShowBodyJsonTree(string headers, StoredBlobContent blob, string blobHash, TreeView jsonTree, TextBox bodyText, Button toggleButton)
    {
        toggleButton.Visibility = Visibility.Collapsed;
        if (!LooksLikeJsonBody(headers, blob)) return;
        var root = GetOrBuildJsonTree(blobHash, blob);
        if (root is null) return;
        JsonTreeViewRenderer.Render(jsonTree, root);
        if (jsonTree.Items.Count == 0) return;
        jsonTree.Visibility = Visibility.Visible;
        bodyText.Visibility = Visibility.Collapsed;
        toggleButton.Content = "原始正文";
        toggleButton.Visibility = Visibility.Visible;
    }

    /// <summary>判定正文是否疑似 JSON：Content-Type 含 json；无该头时看首个非空白字节是否为 { 或 [。</summary>
    private static bool LooksLikeJsonBody(string headers, StoredBlobContent blob)
    {
        if (TryGetHeaderValue(headers, "Content-Type", out var contentType))
            return contentType.Contains("json", StringComparison.OrdinalIgnoreCase);
        foreach (var value in blob.Content)
        {
            if (value is 0x09 or 0x0A or 0x0D or 0x20) continue;
            return value is (byte)'{' or (byte)'[';
        }
        return false;
    }

    /// <summary>从原始头文本中按名称读取头值（大小写不敏感）；不存在时返回 false。</summary>
    private static bool TryGetHeaderValue(string headers, string headerName, out string headerValue)
    {
        headerValue = string.Empty;
        foreach (var line in headers.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
        {
            var separator = line.IndexOf(':');
            if (separator <= 0 || !line[..separator].Trim().Equals(headerName, StringComparison.OrdinalIgnoreCase)) continue;
            headerValue = line[(separator + 1)..].Trim();
            return true;
        }
        return false;
    }

    /// <summary>按 Blob SHA-256 查询或构建 JSON 树缓存（容量 JsonParseCacheCapacity，LRU 逐出；节点自持数据无需 Dispose）。</summary>
    private JsonTreeNode? GetOrBuildJsonTree(string blobHash, StoredBlobContent blob)
    {
        if (_jsonTreeCache.TryGetValue(blobHash, out var cached))
        {
            _jsonTreeCacheOrder.Remove(blobHash);
            _jsonTreeCacheOrder.AddFirst(blobHash);
            return cached;
        }
        if (!JsonPreviewTreeBuilder.TryBuild(blob.Content, blob.Truncated, out var root, out _) || root is null) return null;
        _jsonTreeCache[blobHash] = root;
        _jsonTreeCacheOrder.AddFirst(blobHash);
        while (_jsonTreeCache.Count > JsonParseCacheCapacity && _jsonTreeCacheOrder.Last is { } evicted)
        {
            _jsonTreeCache.Remove(evicted.Value);
            _jsonTreeCacheOrder.RemoveLast();
        }
        return root;
    }

    /// <summary>清空 JSON 树缓存（工作区切换时调用，避免旧工作区解析结果跨工作区复用）。</summary>
    private void ClearJsonTreeCache()
    {
        _jsonTreeCache.Clear();
        _jsonTreeCacheOrder.Clear();
    }

    private static string FormatBlob(StoredBlobContent blob)
    {
        if (blob.Content.Length == 0) return "（空正文）";
        var controlBytes = blob.Content.Count(value => value < 0x09 || value is > 0x0D and < 0x20);
        string text;
        if (controlBytes > blob.Content.Length / 20)
        {
            var preview = Convert.ToHexString(blob.Content.AsSpan(0, Math.Min(blob.Content.Length, BlobHexPreviewBytes))).ToLowerInvariant();
            text = "二进制正文（十六进制预览）\n" + string.Join(' ', Enumerable.Range(0, (preview.Length + 1) / 2).Select(index => preview.Substring(index * 2, Math.Min(2, preview.Length - index * 2))));
        }
        else text = Encoding.UTF8.GetString(blob.Content);
        return blob.Truncated ? text + $"\n\n[正文共 {blob.OriginalLength:N0} 字节，当前仅显示前 {blob.Content.Length:N0} 字节]" : text;
    }

    private async Task<CopyEvidence> ReadEvidenceForCopyAsync(TrafficRecord traffic, int maximumBytes = BlobPreviewDefaultBytes)
    {
        if (traffic.Method == "CONNECT" || traffic.Protocol == ProtocolHttpsTunnel)
            return new CopyEvidence([], "TLS 正文保持加密。仅记录 CONNECT 目标和连接元数据。", traffic.ResponseSummary, false);
        if (!_storedTraffic.TryGetValue(traffic.Id, out var stored))
        {
            var requestBytes = Encoding.UTF8.GetBytes(traffic.RequestSummary);
            return new CopyEvidence(requestBytes, traffic.RequestSummary, traffic.ResponseSummary, false);
        }

        var workspace = new WorkspaceStore(_workspacePath);
        var requestTask = workspace.ReadBlobAsync(stored.RequestBlobHash, maximumBytes);
        var responseTask = workspace.ReadBlobAsync(stored.ResponseBlobHash, maximumBytes);
        await Task.WhenAll(requestTask, responseTask);
        var request = await requestTask;
        var response = await responseTask;
        return new CopyEvidence(request.Content, FormatBlob(request), FormatBlob(response), request.Truncated);
    }

    private async void 复制完整证据_Click(object sender, RoutedEventArgs e)
    {
        if (SelectedTraffic is not TrafficRow selected)
        {
            ShowCopyStatus("请先选择一条流量记录。", success: false);
            return;
        }
        try
        {
            var traffic = selected.Source;
            var evidence = await ReadEvidenceForCopyAsync(traffic);
            if (SelectedTraffic?.Source.Id != traffic.Id) return;
            CopyText(TrafficCopyFormatter.BuildRawEvidence(traffic, evidence.RequestText, evidence.ResponseText),
                "已复制完整原始证据；粘贴或分享前请检查敏感信息。", sensitive: true);
        }
        catch (Exception exception) { ShowCopyStatus("复制失败：" + exception.Message, success: false); }
    }

    private void 复制脱敏副本_Click(object sender, RoutedEventArgs e)
    {
        if (SelectedTraffic is not TrafficRow selected)
        {
            ShowCopyStatus("请先选择一条流量记录。", success: false);
            return;
        }
        try
        {
            CopyText(AiPrivacyFilter.BuildJson([selected.Source], 1), "已复制脱敏 JSON，可用于外部分享。", sensitive: false);
        }
        catch (Exception exception) { ShowCopyStatus("复制失败：" + exception.Message, success: false); }
    }

    private async void 复制Curl_Click(object sender, RoutedEventArgs e)
    {
        if (SelectedTraffic is not TrafficRow selected)
        {
            ShowCopyStatus("请先选择一条 HTTP 流量记录。", success: false);
            return;
        }
        try
        {
            var traffic = selected.Source;
            var evidence = await ReadEvidenceForCopyAsync(traffic, BlobPreviewMaximumBytes);
            if (SelectedTraffic?.Source.Id != traffic.Id) return;
            if (evidence.RequestTruncated)
                throw new InvalidOperationException("请求正文超过 4 MB，为避免生成不完整命令，已拒绝复制 cURL。");
            CopyText(TrafficCopyFormatter.BuildPowerShellCurl(traffic, evidence.RequestBytes),
                "已复制原始 PowerShell cURL；命令可能包含凭据。", sensitive: true);
        }
        catch (Exception exception) { ShowCopyStatus(exception.Message, success: false); }
    }

    private void CopyText(string content, string message, bool sensitive)
    {
        Clipboard.SetDataObject(content, copy: true);
        ShowCopyStatus(message, success: true, sensitive: sensitive);
    }

    private async void ShowCopyStatus(string message, bool success, bool sensitive = false)
    {
        if (CopyStatusText is null) return;
        var version = ++_copyFeedbackVersion;
        CopyStatusText.Foreground = success ? sensitive ? Amber : Green : Red;
        CopyStatusText.Text = message;
        await Task.Delay(TimeSpan.FromSeconds(4));
        if (version == _copyFeedbackVersion) CopyStatusText.Text = string.Empty;
    }

    private sealed record CopyEvidence(byte[] RequestBytes, string RequestText, string ResponseText, bool RequestTruncated);

    /// <summary>
    /// 选中流量记录后更新结论卡片与 AI 证据预览；
    /// 概览页原证据检查器已由流量探索的本地原始证据面板承担，此处不再维护重复区块。
    /// </summary>
    private void UpdateInspector(TrafficRecord? traffic)
    {
        if (traffic is null)
        {
            UpdateAiEvidencePreview();
            return;
        }
        // 结论卡片只陈述确定性事实，不虚构“发现/置信度”；分析结论由运行 AI 分析产出。
        var failing = traffic.StatusCode >= 400;
        FindingTitle.Text = failing
            ? $"异常响应：{traffic.Method} {traffic.Endpoint} 返回 {traffic.StatusCode}"
            : $"事务证据就绪：{traffic.Method} {traffic.Endpoint}";
        var credentialNote = traffic.RequestHeaders.Contains("Authorization:", StringComparison.OrdinalIgnoreCase) || traffic.Cookies.Length > 0
            ? "检测到 Authorization/Cookie 凭据字段，将以完整原始数据进入 AI 上下文。"
            : "未检测到认证类请求头。";
        FindingSummary.Text = $"主机 {TrafficRow.ResolveHost(traffic)} · {traffic.Protocol} · 状态 {traffic.StatusCode} · 延迟 {traffic.LatencyMs} 毫秒 · 响应 {traffic.SizeBytes:N0} 字节。{credentialNote}";
        FindingConfidence.Text = "以上仅为确定性事实摘要；分析结论请运行右侧 AI 分析生成。";
        UpdateAiEvidencePreview();
    }

    private async Task LoadAiSettingsAsync()
    {
        _loadingAiSettings = true;
        try
        {
            var settings = await new AiGatewaySettingsStore(_aiSettingsPath).LoadAsync();
            AiEndpointBox.Text = settings.Endpoint.TrimEnd('/');
            AiModelBox.Text = settings.Model;
            SelectMaxTokensCombo(settings.MaxOutputTokens);
            SelectResponseBytesCombo(settings.MaximumResponseBytes);
            AiTimeoutBox.Text = settings.TimeoutSeconds.ToString();
            SelectComboByTag(AiApiStyleCombo, settings.ApiStyle);
            SelectComboByTag(AiEffortCombo, settings.ReasoningEffort);
            AiLegacyViewer.Document = MarkdownFlowDocumentRenderer.Render("选择左侧模板并点击 **开始新会话**：首轮只发送证据池摘要，模型需要完整数据时按序号取数；每轮对话都会保留在会话中，可随时追问。");
            UpdateAiCredentialStatus();
        }
        catch (Exception exception)
        {
            AiCredentialStatus.Text = "配置读取失败：" + exception.Message;
            AiCredentialStatus.Foreground = Red;
        }
        finally { _loadingAiSettings = false; }
    }

    private async Task LoadWorkbenchSettingsAsync()
    {
        try
        {
            _settings = await new WorkbenchSettingsStore(_settingsPath).LoadAsync();
        }
        catch (Exception)
        {
            // 设置缺失或格式无效时保留安全默认值，界面仍可正常使用。
            _settings = new WorkbenchSettings();
        }
        _workspaceRoot = _settings.WorkspaceRootPath ?? DefaultWorkspaceRoot;
        ApplyWorkbenchSettings();
        // 证据文件属于当前分析草稿，不跨重启自动恢复，避免把上一次任务的材料误带入新会话。
        RefreshAiAttachedFilesUi();
    }

    private void ApplyWorkbenchSettings()
    {
        _applyingWorkbenchSettings = true;
        try
        {
            SettingsListenPortBox.Text = _settings.ListenPort.ToString();
            SettingsTrafficWindowBox.Text = _settings.TrafficWindowCount.ToString();
            SettingsSessionWindowBox.Text = _settings.SessionWindowCount.ToString();
            SettingsPageHookWindowBox.Text = _settings.PageHookWindowCount.ToString();
            SettingsAiEvidenceBox.Text = _settings.AiEvidenceMaximumTransactions.ToString();
            SettingsRefreshIntervalBox.Text = _settings.RefreshIntervalMilliseconds.ToString();
            SettingsSystemProxyBox.IsChecked = _settings.SystemProxyAutomation;
            SettingsSilentCaptureBox.IsChecked = _settings.UseSilentCapture;
            TopSilentBox.IsChecked = _settings.UseSilentCapture;
            TopSystemProxyBox.IsChecked = _settings.SystemProxyAutomation;
            SettingsCaptureModeCombo.SelectedIndex = CaptureModeIndex(_settings);
            TopCaptureModeCombo.SelectedIndex = CaptureModeIndex(_settings);
            ApplyBrowserEnvironmentToUi(_settings.BrowserEnvironment ?? new BrowserEnvironmentProfile());
            WorkspaceRootPathBox.Text = _workspaceRoot;
            _captureTimer.Interval = TimeSpan.FromMilliseconds(_settings.RefreshIntervalMilliseconds);
            SettingsListenPortBox.IsEnabled = !_capturing;
        }
        finally { _applyingWorkbenchSettings = false; }
        UpdateModeText();
        UpdateAiSelectionUi();
        UpdateAiEvidencePreview();
    }

    private WorkbenchSettings ReadWorkbenchSettingsFromUi()
    {
        if (!int.TryParse(SettingsListenPortBox.Text.Trim(), out var listenPort))
            throw new InvalidOperationException("监听端口必须是整数。");
        // 条数与间隔的范围校验在 WorkbenchSettings.Validate() 内统一完成，越界抛中文异常而非静默夹取。
        return new WorkbenchSettings(listenPort,
            ReadCountBox(SettingsRefreshIntervalBox, "列表刷新间隔"),
            ReadCountBox(SettingsTrafficWindowBox, "流量列表条数"),
            ReadCountBox(SettingsSessionWindowBox, "会话列表条数"),
            ReadCountBox(SettingsAiEvidenceBox, "AI 证据条数上限"),
            ReadCountBox(SettingsPageHookWindowBox, "页内 Hook 列表条数"),
            // EnableTrafficHooks 已无界面开关：钩子的唯一启用来源是工作区 hook-config.json。
            // 这里原样透传旧值而不是写死 false，保证旧设置文件往返不被静默清掉。
            SettingsSystemProxyBox.IsChecked == true, _settings.EnableTrafficHooks,
            SettingsSilentCaptureBox.IsChecked == true, null, ReadBrowserEnvironmentFromUi(), _workspaceRoot).Validate();
    }

    private static int ReadCountBox(TextBox box, string label) =>
        int.TryParse(box.Text.Trim(), out var value) ? value : throw new InvalidOperationException($"{label}必须是整数。");

    private BrowserEnvironmentProfile ReadBrowserEnvironmentFromUi()
    {
        if (!int.TryParse(SettingsBrowserWidthBox.Text.Trim(), out var width) ||
            !int.TryParse(SettingsBrowserHeightBox.Text.Trim(), out var height))
            throw new InvalidOperationException("浏览器画像分辨率必须是整数。");
        if (!double.TryParse(SettingsBrowserDprBox.Text.Trim(), System.Globalization.NumberStyles.Float,
                System.Globalization.CultureInfo.InvariantCulture, out var dpr) &&
            !double.TryParse(SettingsBrowserDprBox.Text.Trim(), out dpr))
            throw new InvalidOperationException("浏览器画像设备像素比必须是数字。");
        if (!int.TryParse(SettingsBrowserCpuBox.Text.Trim(), out var cores))
            throw new InvalidOperationException("浏览器画像 CPU 核心数必须是整数。");
        return new BrowserEnvironmentProfile(
            SettingsBrowserProfileEnabledBox.IsChecked == true,
            SettingsBrowserUserAgentBox.Text,
            SelectedTag(SettingsBrowserPlatformCombo, "Win32"),
            width, height, dpr, cores,
            SettingsBrowserTimezoneBox.Text,
            SettingsBrowserLocaleBox.Text,
            SettingsBrowserLanguageBox.Text,
            SelectedTag(SettingsBrowserWebRtcCombo, "disable_non_proxied_udp")).Validate();
    }

    private void ApplyBrowserEnvironmentToUi(BrowserEnvironmentProfile profile)
    {
        profile = profile.Validate();
        SettingsBrowserProfileEnabledBox.IsChecked = profile.Enabled;
        SettingsBrowserUserAgentBox.Text = profile.UserAgent;
        SelectComboByTag(SettingsBrowserPlatformCombo, profile.Platform);
        SettingsBrowserWidthBox.Text = profile.ScreenWidth.ToString();
        SettingsBrowserHeightBox.Text = profile.ScreenHeight.ToString();
        SettingsBrowserDprBox.Text = profile.DeviceScaleFactor.ToString("0.##", System.Globalization.CultureInfo.InvariantCulture);
        SettingsBrowserCpuBox.Text = profile.HardwareConcurrency.ToString();
        SettingsBrowserTimezoneBox.Text = profile.TimezoneId;
        SettingsBrowserLocaleBox.Text = profile.Locale;
        SettingsBrowserLanguageBox.Text = profile.AcceptLanguage;
        SelectComboByTag(SettingsBrowserWebRtcCombo, profile.WebRtcPolicy);
        BrowserProfileSummaryText.Text = profile.Summary;
    }

    private void 生成浏览器画像_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var baseline = _settings.BrowserEnvironment ?? new BrowserEnvironmentProfile();
            baseline = baseline with
            {
                Platform = SelectedTag(SettingsBrowserPlatformCombo, baseline.Platform),
                TimezoneId = string.IsNullOrWhiteSpace(SettingsBrowserTimezoneBox.Text) ? baseline.TimezoneId : SettingsBrowserTimezoneBox.Text.Trim(),
                Locale = string.IsNullOrWhiteSpace(SettingsBrowserLocaleBox.Text) ? baseline.Locale : SettingsBrowserLocaleBox.Text.Trim(),
                AcceptLanguage = string.IsNullOrWhiteSpace(SettingsBrowserLanguageBox.Text) ? baseline.AcceptLanguage : SettingsBrowserLanguageBox.Text.Trim(),
                WebRtcPolicy = SelectedTag(SettingsBrowserWebRtcCombo, baseline.WebRtcPolicy)
            };
            ApplyBrowserEnvironmentToUi(CaptureBrowser.CreateCoherentProfile(baseline));
            SettingsStatusText.Text = "已生成与本机 Chromium 版本一致的画像；点击“保存设置”后生效";
            SettingsStatusText.Foreground = Green;
        }
        catch (Exception exception)
        {
            SettingsStatusText.Text = "生成画像失败：" + exception.Message;
            SettingsStatusText.Foreground = Red;
        }
    }

    private static int CaptureModeIndex(WorkbenchSettings settings)
        => settings.UseSilentCapture ? 2 : settings.SystemProxyAutomation ? 1 : 0;

    private static (bool SystemProxy, bool SilentCapture) CaptureModeFlags(ComboBox combo)
        => combo.SelectedIndex switch
        {
            1 => (true, false),
            2 => (false, true),
            _ => (false, false)
        };

    private async void 采集模式_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (_applyingWorkbenchSettings || sender is not ComboBox combo) return;
        var (systemProxy, silentCapture) = CaptureModeFlags(combo);
        if (_settings.SystemProxyAutomation == systemProxy && _settings.UseSilentCapture == silentCapture) return;

        var updated = _settings with { SystemProxyAutomation = systemProxy, UseSilentCapture = silentCapture };
        try
        {
            await new WorkbenchSettingsStore(_settingsPath).SaveAsync(updated);
            await new WorkspaceStore(_workspacePath).AppendAuditAsync(AuditEventSettingsUpdated, new
            {
                source = "采集方式",
                mode = combo.SelectedIndex switch { 1 => "auto_proxy", 2 => "windivert", _ => "manual_proxy" },
                updated.SystemProxyAutomation,
                updated.UseSilentCapture
            });
            _settings = updated;
            SyncModeSwitchBoxes();
            ModeSwitchStatusText.Text = combo.SelectedIndex switch { 1 => "自动接管代理", 2 => "需管理员权限", _ => "手动配置代理" };
            ModeSwitchStatusText.Foreground = Green;
            SettingsStatusText.Text = "采集方式已保存，下次开始采集生效";
            SettingsStatusText.Foreground = Green;
        }
        catch (Exception exception)
        {
            SyncModeSwitchBoxes();
            ModeSwitchStatusText.Text = "保存失败";
            ModeSwitchStatusText.Foreground = Red;
            SettingsStatusText.Text = "保存失败：" + exception.Message;
            SettingsStatusText.Foreground = Red;
        }
    }

    private async void 保存设置_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            if (_capturing && int.TryParse(SettingsListenPortBox.Text.Trim(), out var enteredPort) && enteredPort != _settings.ListenPort)
            {
                SettingsStatusText.Text = "采集中无法修改监听端口，请先停止采集";
                SettingsStatusText.Foreground = Amber;
                return;
            }
            var settings = ReadWorkbenchSettingsFromUi();
            await new WorkbenchSettingsStore(_settingsPath).SaveAsync(settings);
            await new WorkspaceStore(_workspacePath).AppendAuditAsync(AuditEventSettingsUpdated, new
            {
                settings.ListenPort,
                settings.SystemProxyAutomation,
                settings.EnableTrafficHooks,
                settings.UseSilentCapture,
                browserEnvironmentEnabled = settings.BrowserEnvironment?.Enabled == true,
                browserEnvironmentSummary = settings.BrowserEnvironment?.Summary,
                settings.RefreshIntervalMilliseconds,
                settings.TrafficWindowCount,
                settings.SessionWindowCount,
                settings.PageHookWindowCount,
                settings.AiEvidenceMaximumTransactions
            });
            _settings = settings;
            // 刷新间隔按用户配置生效，不再回落到默认常量。
            _captureTimer.Interval = TimeSpan.FromMilliseconds(settings.RefreshIntervalMilliseconds);
            SettingsListenPortBox.IsEnabled = !_capturing;
            BrowserProfileSummaryText.Text = settings.BrowserEnvironment?.Summary ?? "使用浏览器原生环境";
            SettingsStatusText.Text = "设置已保存，监听端口和浏览器画像将在下次开始采集时生效";
            SettingsStatusText.Foreground = Green;
            SettingsCountsStatusText.Text =
                $"当前生效：流量 {settings.TrafficWindowCount} 条 · AI 证据上限 {settings.AiEvidenceMaximumTransactions} 条 · " +
                $"页内 Hook {settings.PageHookWindowCount} 条 · 会话 {settings.SessionWindowCount} 条 · 刷新 {settings.RefreshIntervalMilliseconds} 毫秒";
            SettingsCountsStatusText.Foreground = Green;
            UpdateModeText();
            UpdateAiSelectionUi();
            UpdateAiEvidencePreview();
            UpdateHookStatusLine();
            // 条数改变会影响每轮读取范围，立即整窗重读一次，让新配置所见即所得。
            await RefreshStoredTrafficAsync(force: true);
        }
        catch (Exception exception)
        {
            SettingsStatusText.Text = "保存失败：" + exception.Message;
            SettingsStatusText.Foreground = Red;
        }
    }

    /// <summary>
    /// 无感抓包开关即时生效：勾选/取消时立即以当前已生效设置的其他字段合并构造新设置，
    /// 经既有设置存储原子写入并记录 settings.updated 审计，不依赖“保存设置”按钮，
    /// 也不受其他输入框校验状态影响；写入失败时回滚复选框并中文提示。
    /// </summary>
    private async void 无感抓包开关_Changed(object sender, RoutedEventArgs e)
    {
        if (_applyingWorkbenchSettings) return; // 加载设置同步复选框时不回写
        var enabled = SettingsSystemProxyBox.IsChecked == true;
        if (_settings.SystemProxyAutomation == enabled) return;
        var updated = _settings with { SystemProxyAutomation = enabled };
        try
        {
            await new WorkbenchSettingsStore(_settingsPath).SaveAsync(updated);
            await new WorkspaceStore(_workspacePath).AppendAuditAsync(AuditEventSettingsUpdated, new
            {
                source = "无感抓包开关",
                updated.ListenPort,
                updated.RefreshIntervalMilliseconds,
                updated.TrafficWindowCount,
                updated.SessionWindowCount,
                updated.AiEvidenceMaximumTransactions,
                updated.SystemProxyAutomation,
                updated.EnableTrafficHooks
            });
            _settings = updated;
            SyncModeSwitchBoxes();
            SettingsStatusText.Text = enabled
                ? "已保存，启动采集时自动接管系统代理，停止时自动还原"
                : "已保存，启动采集时不再自动接管系统代理";
            SettingsStatusText.Foreground = Green;
        }
        catch (Exception exception)
        {
            // 写入失败：全部开关回滚到实际已持久化的状态，避免界面与磁盘不一致。
            SyncModeSwitchBoxes();
            SettingsStatusText.Text = "保存失败：" + exception.Message;
            SettingsStatusText.Foreground = Red;
        }
    }

    /// <summary>
    /// 静默抓包开关即时生效：与无感抓包开关同一范式——勾选/取消时立即合并当前已持久化设置原子写入并记审计，
    /// 不依赖“保存设置”按钮；写入失败时回滚复选框并中文提示。
    /// </summary>
    private async void 静默抓包开关_Changed(object sender, RoutedEventArgs e)
    {
        if (_applyingWorkbenchSettings) return; // 加载设置同步复选框时不回写
        var enabled = SettingsSilentCaptureBox.IsChecked == true;
        if (_settings.UseSilentCapture == enabled) return;
        var updated = _settings with { UseSilentCapture = enabled };
        try
        {
            await new WorkbenchSettingsStore(_settingsPath).SaveAsync(updated);
            await new WorkspaceStore(_workspacePath).AppendAuditAsync(AuditEventSettingsUpdated, new
            {
                source = "静默抓包开关",
                updated.ListenPort,
                updated.RefreshIntervalMilliseconds,
                updated.TrafficWindowCount,
                updated.SessionWindowCount,
                updated.AiEvidenceMaximumTransactions,
                updated.SystemProxyAutomation,
                updated.EnableTrafficHooks,
                updated.UseSilentCapture
            });
            _settings = updated;
            SyncModeSwitchBoxes();
            SettingsStatusText.Text = enabled
                ? "已保存，下次开始采集将使用底层静默抓包（WinDivert，需管理员权限与驱动）"
                : "已保存，下次开始采集将使用回环代理模式";
            SettingsStatusText.Foreground = Green;
        }
        catch (Exception exception)
        {
            SyncModeSwitchBoxes();
            SettingsStatusText.Text = "保存失败：" + exception.Message;
            SettingsStatusText.Foreground = Red;
        }
    }

    /// <summary>
    /// 顶部栏静默抓包开关：与设置页同一语义——勾选/取消立即持久化并记审计，下次开始采集生效；
    /// 写入成功后顶部与设置页四处复选框统一同步，失败时一并回滚。
    /// </summary>
    private async void 顶部静默开关_Changed(object sender, RoutedEventArgs e)
    {
        if (_applyingWorkbenchSettings) return;
        var enabled = TopSilentBox.IsChecked == true;
        if (_settings.UseSilentCapture == enabled) return;
        var updated = _settings with { UseSilentCapture = enabled };
        try
        {
            await new WorkbenchSettingsStore(_settingsPath).SaveAsync(updated);
            await new WorkspaceStore(_workspacePath).AppendAuditAsync(AuditEventSettingsUpdated, new
            {
                source = "顶部静默抓包开关",
                updated.ListenPort,
                updated.RefreshIntervalMilliseconds,
                updated.TrafficWindowCount,
                updated.SessionWindowCount,
                updated.AiEvidenceMaximumTransactions,
                updated.SystemProxyAutomation,
                updated.EnableTrafficHooks,
                updated.UseSilentCapture
            });
            _settings = updated;
            SyncModeSwitchBoxes();
            ModeSwitchStatusText.Text = enabled ? "静默抓包已开启 · 下次开始采集生效" : "已切回回环代理模式 · 下次开始采集生效";
            ModeSwitchStatusText.Foreground = Green;
        }
        catch (Exception exception)
        {
            SyncModeSwitchBoxes();
            ModeSwitchStatusText.Text = "保存失败：" + exception.Message;
            ModeSwitchStatusText.Foreground = Red;
        }
    }

    /// <summary>
    /// 顶部栏无感抓包开关：与设置页同一语义——勾选/取消立即持久化并记审计，启动采集时接管系统代理；
    /// 写入成功后四处复选框统一同步，失败时一并回滚。
    /// </summary>
    private async void 顶部无感开关_Changed(object sender, RoutedEventArgs e)
    {
        if (_applyingWorkbenchSettings) return;
        var enabled = TopSystemProxyBox.IsChecked == true;
        if (_settings.SystemProxyAutomation == enabled) return;
        var updated = _settings with { SystemProxyAutomation = enabled };
        try
        {
            await new WorkbenchSettingsStore(_settingsPath).SaveAsync(updated);
            await new WorkspaceStore(_workspacePath).AppendAuditAsync(AuditEventSettingsUpdated, new
            {
                source = "顶部无感抓包开关",
                updated.ListenPort,
                updated.RefreshIntervalMilliseconds,
                updated.TrafficWindowCount,
                updated.SessionWindowCount,
                updated.AiEvidenceMaximumTransactions,
                updated.SystemProxyAutomation,
                updated.EnableTrafficHooks
            });
            _settings = updated;
            SyncModeSwitchBoxes();
            ModeSwitchStatusText.Text = enabled ? "无感抓包已开启 · 启动采集时接管系统代理" : "无感抓包已关闭 · 不再接管系统代理";
            ModeSwitchStatusText.Foreground = Green;
        }
        catch (Exception exception)
        {
            SyncModeSwitchBoxes();
            ModeSwitchStatusText.Text = "保存失败：" + exception.Message;
            ModeSwitchStatusText.Foreground = Red;
        }
    }

    /// <summary>把顶部栏与设置页共四个模式复选框统一同步为已持久化设置；加载守卫内批量赋值避免互相触发。</summary>
    private void SyncModeSwitchBoxes()
    {
        _applyingWorkbenchSettings = true;
        try
        {
            TopSilentBox.IsChecked = _settings.UseSilentCapture;
            TopSystemProxyBox.IsChecked = _settings.SystemProxyAutomation;
            SettingsSilentCaptureBox.IsChecked = _settings.UseSilentCapture;
            SettingsSystemProxyBox.IsChecked = _settings.SystemProxyAutomation;
            SettingsCaptureModeCombo.SelectedIndex = CaptureModeIndex(_settings);
            TopCaptureModeCombo.SelectedIndex = CaptureModeIndex(_settings);
            CaptureModeHelpText.Text = CaptureModeIndex(_settings) switch
            {
                1 => "自动系统代理：开始采集时接管 Windows 系统代理，停止或退出时还原；适合浏览器和大多数桌面应用。",
                2 => "WinDivert 静默抓包：透明捕获进程 TCP 流量，支持按进程采集；需要管理员权限和 WinDivert 驱动。",
                _ => "手动代理：由你自行把目标应用代理指向监听端口；行为最可控，不修改系统代理。"
            };
        }
        finally { _applyingWorkbenchSettings = false; }
    }

    private async Task LoadAiHistoryAsync(Guid? selectedId = null, string? justRunElapsed = null)
    {
        _loadingAiHistory = true;
        try
        {
            var history = await new AiAnalysisHistoryStore(_workspacePath).GetRecentAsync(100);
            AiHistoryRows.Clear();
            foreach (var item in history) AiHistoryRows.Add(new AiHistoryRow(item));
            var selected = selectedId.HasValue
                ? AiHistoryRows.FirstOrDefault(row => row.Source.Id == selectedId.Value)
                : AiHistoryRows.FirstOrDefault();
            AiLegacyHistoryList.SelectedItem = selected;
            if (selected is null)
            {
                _currentAiHistoryEntry = null;
                _currentAiMarkdown = string.Empty;
                CopyAiResultButton.IsEnabled = ExportAiResultButton.IsEnabled = DeleteAiHistoryButton.IsEnabled = false;
                AiRunStatus.Text = "当前工作区暂无 AI 分析历史" + (justRunElapsed is null ? string.Empty : $" · 本次用时 {justRunElapsed}");
                AiRunStatus.Foreground = Muted;
                AiLegacyViewer.Document = MarkdownFlowDocumentRenderer.Render("旧版一次性分析的历史记录仍可在此查看；新分析请使用上方“开始新会话”。 ");
            }
        }
        catch (Exception exception)
        {
            AiRunStatus.Text = "AI 历史读取失败" + (justRunElapsed is null ? string.Empty : $" · 本次用时 {justRunElapsed}");
            AiRunStatus.ToolTip = exception.Message;
            AiRunStatus.Foreground = Red;
        }
        finally { _loadingAiHistory = false; }

        if (AiLegacyHistoryList.SelectedItem is AiHistoryRow row) await DisplayAiHistoryAsync(row, justRunElapsed);
    }

    private async void AI历史选择_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (_loadingAiHistory || AiLegacyHistoryList.SelectedItem is not AiHistoryRow row) return;
        await DisplayAiHistoryAsync(row);
    }

    private async Task DisplayAiHistoryAsync(AiHistoryRow row, string? justRunElapsed = null)
    {
        var workspacePath = _workspacePath;
        try
        {
            var entry = await new AiAnalysisHistoryStore(workspacePath).LoadAsync(row.Source.Id);
            if (entry is null) throw new FileNotFoundException("所选 AI 分析历史已不存在。");
            if (!string.Equals(workspacePath, _workspacePath, StringComparison.OrdinalIgnoreCase) ||
                AiLegacyHistoryList.SelectedItem is not AiHistoryRow selected || selected.Source.Id != row.Source.Id) return;
            _currentAiHistoryEntry = entry;
            _currentAiMarkdown = entry.ResultMarkdown;
            AiLegacyViewer.Document = MarkdownFlowDocumentRenderer.Render(entry.ResultMarkdown);
            SwitchToLegacyView();
            AiRunStatus.Text = $"历史 · {entry.Metadata.Model} · {entry.Metadata.CreatedAt.ToLocalTime():MM-dd HH:mm} · {entry.Metadata.TransactionIds.Count} 条 · 输入 {entry.Metadata.InputTokens:N0} / 输出 {entry.Metadata.OutputTokens:N0}" +
                               (justRunElapsed is null ? string.Empty : $" · 本次用时 {justRunElapsed}");
            AiRunStatus.ToolTip = $"范围：{entry.Metadata.ScopeName}\n响应：{entry.Metadata.ResponseId}";
            AiRunStatus.Foreground = entry.Metadata.FinishReason == "length" ? Amber : Green;
            CopyAiResultButton.IsEnabled = ExportAiResultButton.IsEnabled = DeleteAiHistoryButton.IsEnabled = true;
        }
        catch (Exception exception)
        {
            _currentAiHistoryEntry = null;
            _currentAiMarkdown = string.Empty;
            CopyAiResultButton.IsEnabled = ExportAiResultButton.IsEnabled = DeleteAiHistoryButton.IsEnabled = false;
            AiRunStatus.Text = "历史结果读取失败";
            AiRunStatus.ToolTip = exception.Message;
            AiRunStatus.Foreground = Red;
        }
    }

    private async void 复制AI结果_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(_currentAiMarkdown)) return;
        Exception? lastError = null;
        for (var attempt = 0; attempt < 5; attempt++)
        {
            try
            {
                Clipboard.SetDataObject(_currentAiMarkdown, copy: true);
                AiRunStatus.Text = "已复制当前 Markdown 分析结果";
                AiRunStatus.ToolTip = null;
                AiRunStatus.Foreground = Green;
                return;
            }
            catch (Exception exception)
            {
                lastError = exception;
                await Task.Delay(80);
            }
        }
        AiRunStatus.Text = "复制失败：剪贴板正被其他程序占用";
        AiRunStatus.ToolTip = lastError?.Message;
        AiRunStatus.Foreground = Red;
    }

    private async void 导出AI结果_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(_currentAiMarkdown)) return;
        var metadata = _currentAiHistoryEntry?.Metadata;
        var dialog = new SaveFileDialog
        {
            Title = "导出 AI 分析结果",
            Filter = "Markdown 文件 (*.md)|*.md",
            DefaultExt = ".md",
            AddExtension = true,
            FileName = $"NetMind-AI-{(metadata?.CreatedAt ?? DateTimeOffset.UtcNow).ToLocalTime():yyyyMMdd-HHmmss}.md"
        };
        if (dialog.ShowDialog(this) != true) return;
        try
        {
            var markdown = _currentAiHistoryEntry is null
                ? "# NetMind AI 分析结果\n\n" + _currentAiMarkdown
                : AiAnalysisExportFormatter.BuildMarkdown(_currentAiHistoryEntry);
            await File.WriteAllTextAsync(dialog.FileName, markdown, new UTF8Encoding(false));
            if (metadata is not null)
                await new WorkspaceStore(_workspacePath).AppendAuditAsync("ai.analysis-exported", new { metadata.Id, format = "markdown" });
            AiRunStatus.Text = "Markdown 分析结果已导出";
            AiRunStatus.ToolTip = dialog.FileName;
            AiRunStatus.Foreground = Green;
        }
        catch (Exception exception)
        {
            AiRunStatus.Text = "导出失败";
            AiRunStatus.ToolTip = exception.Message;
            AiRunStatus.Foreground = Red;
        }
    }

    private async void 删除AI历史_Click(object sender, RoutedEventArgs e)
    {
        if (_currentAiHistoryEntry is not { } entry) return;
        var answer = MessageBox.Show(this, $"确认删除 {entry.Metadata.CreatedAt.ToLocalTime():yyyy-MM-dd HH:mm} 的 AI 分析历史？\n\n只删除分析结果与脱敏证据快照，不会删除原始流量。", "确认删除 AI 历史", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);
        if (answer != MessageBoxResult.Yes) return;
        try
        {
            new AiAnalysisHistoryStore(_workspacePath).Delete(entry.Metadata.Id);
            await new WorkspaceStore(_workspacePath).AppendAuditAsync("ai.analysis-deleted", new { entry.Metadata.Id });
            _currentAiHistoryEntry = null;
            _currentAiMarkdown = string.Empty;
            await LoadAiHistoryAsync();
        }
        catch (Exception exception)
        {
            AiRunStatus.Text = "删除历史失败";
            AiRunStatus.ToolTip = exception.Message;
            AiRunStatus.Foreground = Red;
        }
    }

    private AiGatewaySettings ReadAiSettingsFromUi()
    {
        if (!int.TryParse((AiMaxTokensBox.SelectedItem as ComboBoxItem)?.Content?.ToString(), out var maximumOutputTokens))
            throw new InvalidOperationException("请选择输出令牌上限。");
        if (!int.TryParse(((AiResponseLimitBox.SelectedItem ?? AiResponseLimitBox.Items[2]) as ComboBoxItem)?.Content?.ToString()?.Replace(" MB", string.Empty), out var responseLimitMb))
            throw new InvalidOperationException("请选择响应上限。");
        if (AiTimeoutBox.Text is null || !int.TryParse(AiTimeoutBox.Text.Trim(), out var timeoutSeconds))
            throw new InvalidOperationException("请求超时必须是整数秒。");
        return new AiGatewaySettings(
            AiEndpointBox.Text.Trim(),
            AiModelBox.Text.Trim(),
            SelectedTag(AiApiStyleCombo, "chat_completions"),
            SelectedTag(AiEffortCombo, "high"),
            maximumOutputTokens,
            timeoutSeconds,
            responseLimitMb * 1024 * 1024).Validate();
    }

    /// <summary>响应上限下拉回填：精确匹配预设 MB 值，历史值不在预设内时回落默认 32 MB。</summary>
    private void SelectResponseBytesCombo(int bytes)
    {
        var megabytes = bytes / 1024 / 1024;
        for (var i = 0; i < AiResponseLimitBox.Items.Count; i++)
        {
            if (!int.TryParse((AiResponseLimitBox.Items[i] as ComboBoxItem)?.Content?.ToString()?.Replace(" MB", string.Empty), out var preset)) continue;
            if (preset == megabytes)
            {
                AiResponseLimitBox.SelectedIndex = i;
                return;
            }
        }
        AiResponseLimitBox.SelectedIndex = 2;
    }

    /// <summary>会话文件读取上限跟随配置的响应上限：从持久化配置取值（不依赖 UI 当前输入），再预留 32 MB 历史余量。</summary>
    private async Task<AiConversationStore> CreateAiConversationStoreAsync()
    {
        int responseLimitBytes;
        try { responseLimitBytes = (await new AiGatewaySettingsStore(_aiSettingsPath).LoadAsync()).MaximumResponseBytes; }
        catch { responseLimitBytes = NetMindDefaults.AiMaximumResponseBytes; }
        return new AiConversationStore(_workspacePath, responseLimitBytes + 32 * 1024 * 1024);
    }

    /// <summary>输出上限仅保留预设下拉：选中与已保存值一致的预设；历史自定义值就近选不小于它的预设，超出则选最大。</summary>
    private void SelectMaxTokensCombo(int value)
    {
        var bestIndex = -1;
        var bestValue = int.MaxValue;
        for (var i = 0; i < AiMaxTokensBox.Items.Count; i++)
        {
            if (!int.TryParse((AiMaxTokensBox.Items[i] as ComboBoxItem)?.Content?.ToString(), out var preset)) continue;
            if (preset == value)
            {
                bestIndex = i;
                break;
            }
            if (preset > value && preset < bestValue)
            {
                bestIndex = i;
                bestValue = preset;
            }
        }
        AiMaxTokensBox.SelectedIndex = bestIndex >= 0 ? bestIndex : AiMaxTokensBox.Items.Count - 1;
    }

    private async void 保存AI配置_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var settings = ReadAiSettingsFromUi();
            await new AiGatewaySettingsStore(_aiSettingsPath).SaveAsync(settings);
            if (!string.IsNullOrWhiteSpace(AiApiKeyBox.Password))
            {
                WindowsCredentialStore.SaveApiKey(AiApiKeyBox.Password);
                AiApiKeyBox.Clear();
            }
            await new WorkspaceStore(_workspacePath).AppendAuditAsync("ai.gateway-configured", new
            {
                endpointHost = new Uri(settings.Endpoint).Host,
                settings.Model,
                settings.ApiStyle,
                settings.ReasoningEffort
            });
            UpdateAiCredentialStatus("配置已保存");
        }
        catch (Exception exception)
        {
            AiCredentialStatus.Text = "保存失败：" + exception.Message;
            AiCredentialStatus.Foreground = Red;
        }
    }

    /// <summary>AI 页配置项（网关地址/模型/接口类型/推理强度/输出上限/超时）变更后防抖自动持久化；API 密钥仍需显式保存。</summary>
    private void AI配置输入_Changed(object sender, RoutedEventArgs e)
    {
        if (_loadingAiSettings) return;
        _aiConfigAutoSaveTimer ??= new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(700) };
        _aiConfigAutoSaveTimer.Stop();
        _aiConfigAutoSaveTimer.Tick -= AI配置自动保存_Tick;
        _aiConfigAutoSaveTimer.Tick += AI配置自动保存_Tick;
        _aiConfigAutoSaveTimer.Start();
    }

    private async void AI配置自动保存_Tick(object? sender, EventArgs e)
    {
        _aiConfigAutoSaveTimer?.Stop();
        try
        {
            var settings = ReadAiSettingsFromUi();
            await new AiGatewaySettingsStore(_aiSettingsPath).SaveAsync(settings);
            UpdateAiCredentialStatus($"配置已自动保存 {DateTime.Now:HH:mm:ss}");
        }
        catch
        {
            // 输入暂不合法（如超时正在编辑中）时跳过本次，等待下一次合法输入后自动落盘。
        }
    }

    private void 清除AI密钥_Click(object sender, RoutedEventArgs e)
    {
        var answer = MessageBox.Show(this, "确认删除 Windows 凭据管理器中保存的模型网关密钥？", "确认清除密钥",
            MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);
        if (answer != MessageBoxResult.Yes) return;
        try
        {
            WindowsCredentialStore.DeleteApiKey();
            AiApiKeyBox.Clear();
            UpdateAiCredentialStatus("已清除保存的密钥");
        }
        catch (Exception exception)
        {
            AiCredentialStatus.Text = "清除失败：" + exception.Message;
            AiCredentialStatus.Foreground = Red;
        }
    }

    private async void 开始新会话_Click(object sender, RoutedEventArgs e)
    {
        var requirement = AiPromptBox.Text?.Trim() ?? string.Empty;
        AiPromptBox.Clear();
        await StartAiConversationAsync(requirement.Length == 0 ? null : requirement);
    }

    /// <summary>以当前证据池开始新会话：创建 JSONL 会话文件，发送首轮（摘要先行，tool_call 按需取数）。</summary>
    private async Task StartAiConversationAsync(string? userRequirement)
    {
        if (_aiTurnRunning) return;
        var evidence = GetAiEvidence();
        if (evidence.Length == 0)
        {
            AiRunStatus.Text = "请先高亮或勾选要分析的流量记录";
            AiRunStatus.Foreground = Red;
            return;
        }
        if (evidence.Length > _settings.AiEvidenceMaximumTransactions)
        {
            AiRunStatus.Text = $"已选择 {evidence.Length} 条，单次最多分析 {_settings.AiEvidenceMaximumTransactions} 条";
            AiRunStatus.Foreground = Red;
            return;
        }
        AiGatewaySettings settings;
        try
        {
            settings = ReadAiSettingsFromUi();
        }
        catch (Exception exception)
        {
            AiRunStatus.Text = "AI 配置不合法：" + exception.Message;
            AiRunStatus.Foreground = Red;
            return;
        }
        var template = ResolveAiTemplate((AiTemplateCombo.SelectedItem as ComboBoxItem)?.Tag?.ToString());
        var enteredKey = AiApiKeyBox.Password;
        var apiKey = string.IsNullOrWhiteSpace(enteredKey) ? WindowsCredentialStore.ReadApiKey() : enteredKey;
        var scopeName = _groupAiEvidence is { Length: > 0 }
            ? $"记录组：{_groupAiName}"
            : _aiSelectedTrafficIds.Count > 0 ? $"明确勾选 {_aiSelectedTrafficIds.Count} 条" : "当前高亮事务";
        var header = new AiConversationHeader(Guid.NewGuid(), DateTimeOffset.UtcNow, template.Id, settings.Model, scopeName, evidence.Select(item => item.Id).ToArray());
        AiConversationStore? conversationStore = null;
        try
        {
            conversationStore = await CreateAiConversationStoreAsync();
            await conversationStore.CreateAsync(header);
            await conversationStore.AppendMessageAsync(header.Id,
                new AiChatMessage("system", template.SystemPrompt, CreatedAt: DateTimeOffset.UtcNow));
        }
        catch (Exception exception)
        {
            try { conversationStore?.Delete(header.Id); } catch { /* 创建失败清理不覆盖原始错误 */ }
            AiRunStatus.Text = "创建会话失败：" + exception.Message;
            AiRunStatus.Foreground = Red;
            return;
        }
        _openConversationHeader = header;
        _openConversationHistory = [new AiChatMessage("system", template.SystemPrompt)];
        _openEvidenceProvider = new WorkbenchAiEvidenceProvider(this, evidence);
        _aiVisibleTurnLimit = AiTurnRenderPageSize;
        ResetAiTurnStatistics();
        SwitchToConversationView();
        AiTurnsPanel.Children.Clear();
        AiConversationTitle.Text = $"{template.DisplayName} · {header.CreatedAt.ToLocalTime():MM-dd HH:mm} · {scopeName}";
        DeleteAiConversationButton.IsEnabled = true;
        ExportAiConversationButton.IsEnabled = true;
        AiQuickFollowUpPanel.IsEnabled = true;
        try
        {
            await new WorkspaceStore(_workspacePath).AppendAuditAsync("ai.conversation-started", new
            {
                conversationId = header.Id,
                header.TemplateId,
                header.Model,
                transactionCount = evidence.Length
            });
        }
        catch { /* 审计失败不阻断会话 */ }
        await ExecuteAiTurnAsync(settings, apiKey, AiConversationEngine.BuildFirstUserMessage(_openEvidenceProvider, template, userRequirement));
        await LoadAiConversationsAsync(header.Id);
    }

    private async void 发送AI追问_Click(object sender, RoutedEventArgs e)
    {
        var text = AiPromptBox.Text?.Trim() ?? string.Empty;
        if (text.Length == 0) return;
        AiPromptBox.Clear();
        if (_openConversationHeader is null)
        {
            await StartAiConversationAsync(text);
            return;
        }
        await SendAiFollowUpAsync(text);
    }

    private void AI追问_回车(object sender, KeyEventArgs e)
    {
        if (e.Key != Key.Enter || (Keyboard.Modifiers & ModifierKeys.Control) == 0) return;
        e.Handled = true;
        发送AI追问_Click(sender, e);
    }

    private async void 快捷追问_Click(object sender, RoutedEventArgs e)
    {
        if (_openConversationHeader is null || _aiTurnRunning) return;
        if (sender is not FrameworkElement { Tag: string text } || text.Length == 0) return;
        await SendAiFollowUpAsync(text);
    }

    /// <summary>已打开会话时发送追问：只重发会话历史，不重发原始数据。</summary>
    private async Task SendAiFollowUpAsync(string userText)
    {
        if (_aiTurnRunning || _openConversationHeader is null || _openEvidenceProvider is null) return;
        AiGatewaySettings settings;
        try
        {
            settings = ReadAiSettingsFromUi();
        }
        catch (Exception exception)
        {
            AiRunStatus.Text = "AI 配置不合法：" + exception.Message;
            AiRunStatus.Foreground = Red;
            return;
        }
        var enteredKey = AiApiKeyBox.Password;
        var apiKey = string.IsNullOrWhiteSpace(enteredKey) ? WindowsCredentialStore.ReadApiKey() : enteredKey;
        SwitchToConversationView();
        await ExecuteAiTurnAsync(settings, apiKey, userText);
    }

    /// <summary>首轮/追问共享路径：引擎取数回环 + 流式渲染；完成后整体重渲染轮次面板并刷新状态栏、审计与会话列表。</summary>
    private async Task ExecuteAiTurnAsync(AiGatewaySettings settings, string? apiKey, string userText)
    {
        if (_aiTurnRunning || _openConversationHeader is null || _openEvidenceProvider is null) return;
        var header = _openConversationHeader;
        var workspacePath = _workspacePath;
        _aiTurnRunning = true;
        _aiCancellation?.Dispose();
        _aiCancellation = new CancellationTokenSource();
        var token = _aiCancellation.Token;
        StartAiElapsedTimer();
        RunAiButton.IsEnabled = false;
        SendAiFollowUpButton.IsEnabled = false;
        ExportAiConversationButton.IsEnabled = false;
        AiQuickFollowUpPanel.IsEnabled = false;
        CancelAiButton.IsEnabled = true;
        _aiRunResponseLimitBytes = settings.MaximumResponseBytes;
        _aiTurnResponseBytes = 0;
        SetAiRunningStatus($"正在调用 {settings.Model}…");
        AiRunStatus.Foreground = Accent;
        BeginAiStreamingRender();
        AiConversationStore? store = null;
        var turnHistoryStart = _openConversationHistory.Count;
        try
        {
            store = await CreateAiConversationStoreAsync();
            using var gateway = new AiGatewayClient();
            var engine = new AiConversationEngine(gateway);
            var callbacks = new AiStreamCallbacks
            {
                OnTextDelta = delta =>
                {
                    if (!Dispatcher.CheckAccess())
                    {
                        Dispatcher.BeginInvoke(() => AppendAiStreamDelta(delta));
                        return;
                    }
                    AppendAiStreamDelta(delta);
                },
                OnToolFetch = (name, _) => Dispatcher.BeginInvoke(() => SetAiRunningStatus($"正在取数：{name}")),
                // 在请求线程触发，只原子写入累计字节；状态栏每秒读取渲染，避免高频调度 UI 线程。
                OnResponseBytes = bytes => Interlocked.Exchange(ref _aiTurnResponseBytes, bytes)
            };
            var outcome = await engine.RunTurnAsync(settings, apiKey, _openEvidenceProvider, _openConversationHistory, userText, store, header.Id, callbacks, token);
            EndAiStreamingRender();
            _aiTurnFetchCount += outcome.ToolFetchCount;
            _aiTurnInputTokens += outcome.InputTokens;
            _aiTurnOutputTokens += outcome.OutputTokens;
            RenderAiConversation(_openConversationHistory);
            var turns = AiConversationStore.CountTurns(_openConversationHistory);
            var elapsed = FormatElapsed(DateTime.Now - _aiRunStartedAt);
            var truncated = outcome.FinishReason == "length";
            AiRunStatus.Text = $"{turns} 轮 · 取数 {_aiTurnFetchCount} 次 · 累计模型用量：输入 {_aiTurnInputTokens:N0} / 输出 {_aiTurnOutputTokens:N0} 令牌 · 用时 {elapsed}" +
                               (truncated ? " · 已达输出上限" : string.Empty) +
                               (outcome.IterationCapReached ? " · 取数迭代已达上限" : string.Empty);
            AiRunStatus.ToolTip = null;
            AiRunStatus.Foreground = truncated || outcome.IterationCapReached ? Amber : Green;
            try
            {
                await new WorkspaceStore(workspacePath).AppendAuditAsync("ai.turn-completed", new
                {
                    conversationId = header.Id,
                    turns,
                    outcome.ToolFetchCount,
                    outcome.InputTokens,
                    outcome.OutputTokens,
                    outcome.FinishReason,
                    outcome.DurationMilliseconds
                });
            }
            catch { /* 审计失败不阻断会话 */ }
        }
        catch (OperationCanceledException)
        {
            var partialText = _aiStreamBuffer.ToString();
            EndAiStreamingRender();
            await CompleteInterruptedAiTurnAsync(store, header.Id, turnHistoryStart, partialText, "本轮已取消，未完成的工具调用已关闭。", CancellationToken.None);
            AiRunStatus.Text = $"本轮已取消 · 用时 {FormatElapsed(DateTime.Now - _aiRunStartedAt)}";
            AiRunStatus.ToolTip = null;
            AiRunStatus.Foreground = Muted;
            RenderAiConversation(_openConversationHistory);
        }
        catch (Exception exception)
        {
            var partialText = _aiStreamBuffer.ToString();
            EndAiStreamingRender();
            await CompleteInterruptedAiTurnAsync(store, header.Id, turnHistoryStart, partialText, "本轮模型调用失败，可直接重新追问。", CancellationToken.None);
            AiRunStatus.Text = "模型分析失败";
            AiRunStatus.ToolTip = exception.Message;
            AiRunStatus.Foreground = Red;
            RenderAiConversation(_openConversationHistory);
            AppendAiNoticeBlock("模型分析失败：" + exception.Message);
            if (turnHistoryStart > 1 && string.IsNullOrWhiteSpace(AiPromptBox.Text))
            {
                AiPromptBox.Text = userText;
                AiPromptBox.CaretIndex = AiPromptBox.Text.Length;
            }
        }
        finally
        {
            StopAiElapsedTimer();
            _aiRunResponseLimitBytes = 0;
            _aiTurnRunning = false;
            RunAiButton.IsEnabled = true;
            SendAiFollowUpButton.IsEnabled = true;
            ExportAiConversationButton.IsEnabled = _openConversationHeader is not null;
            AiQuickFollowUpPanel.IsEnabled = _openConversationHeader is not null;
            CancelAiButton.IsEnabled = false;
            _aiCancellation?.Dispose();
            _aiCancellation = null;
        }
    }

    /// <summary>
    /// 取消或异常时把已经持久化但尚未返回结果的 tool_call 补成明确的 tool 结果，
    /// 再保存流式阶段已经收到的部分答复。这样下一次追问仍是合法的工具调用协议序列，
    /// 会话列表也不会出现只有提问、没有终态的“孤儿轮次”。
    /// </summary>
    private async Task CompleteInterruptedAiTurnAsync(AiConversationStore? store, Guid conversationId,
        int turnHistoryStart, string partialText, string terminalMessage, CancellationToken cancellationToken)
    {
        var turnMessages = _openConversationHistory.Skip(Math.Clamp(turnHistoryStart, 0, _openConversationHistory.Count)).ToArray();
        if (turnMessages.LastOrDefault() is { Role: "assistant", ToolCalls: null, Content: not null }) return;

        var completedToolCalls = turnMessages
            .Where(message => message.Role == "tool" && !string.IsNullOrWhiteSpace(message.ToolCallId))
            .Select(message => message.ToolCallId!)
            .ToHashSet(StringComparer.Ordinal);
        var pendingToolCalls = turnMessages
            .Where(message => message.Role == "assistant" && message.ToolCalls is { Count: > 0 })
            .SelectMany(message => message.ToolCalls!)
            .Where(call => !completedToolCalls.Contains(call.Id))
            .GroupBy(call => call.Id, StringComparer.Ordinal)
            .Select(group => group.First())
            .ToArray();

        foreach (var call in pendingToolCalls)
        {
            var toolMessage = new AiChatMessage("tool", "[本轮被中断，工具调用未执行]", ToolCallId: call.Id, Name: call.Name);
            _openConversationHistory.Add(toolMessage);
            if (store is not null)
                try { await store.AppendMessageAsync(conversationId, toolMessage, cancellationToken); }
                catch { /* 终态补偿写入失败不覆盖原始取消/异常状态 */ }
        }

        var content = string.IsNullOrWhiteSpace(partialText)
            ? $"[{terminalMessage}]"
            : partialText.TrimEnd() + $"\n\n[{terminalMessage}]";
        var assistantMessage = new AiChatMessage("assistant", content,
            ElapsedMilliseconds: Math.Max(0, (long)(DateTime.Now - _aiRunStartedAt).TotalMilliseconds));
        _openConversationHistory.Add(assistantMessage);
        if (store is not null)
            try { await store.AppendMessageAsync(conversationId, assistantMessage, cancellationToken); }
            catch { /* 同上 */ }
    }

    private void AppendAiStreamDelta(string delta)
    {
        _aiStreamBuffer.Append(delta);
        _aiStreamRenderTimer?.Start();
    }

    private void ResetAiTurnStatistics()
    {
        _aiTurnFetchCount = 0;
        _aiTurnInputTokens = 0;
        _aiTurnOutputTokens = 0;
    }

    // —— 会话轮次面板渲染：每轮 = 提问 + 取数记录（默认折叠）+ 助手回复 ——

    /// <summary>内容区显示会话轮次面板，隐藏旧版一次性结果查看器。</summary>
    private void SwitchToConversationView()
    {
        AiTurnsScroll.Visibility = Visibility.Visible;
        AiLegacyViewer.Visibility = Visibility.Collapsed;
    }

    private void SwitchToLegacyView()
    {
        AiTurnsScroll.Visibility = Visibility.Collapsed;
        AiLegacyViewer.Visibility = Visibility.Visible;
    }

    /// <summary>无会话时的引导文案。</summary>
    private void ShowAiEmptyHint()
    {
        AiTurnsPanel.Children.Clear();
        AiTurnsPanel.Children.Add(new TextBlock
        {
            Text = "当前没有打开的会话：选择左侧会话可恢复全部轮次并继续追问；或选择顶部模板后点击“开始新会话”，以当前证据池开始分析。",
            TextWrapping = TextWrapping.Wrap,
            Foreground = Muted,
        });
        SwitchToConversationView();
        AiConversationTitle.Text = "会话区";
    }

    /// <summary>
    /// 按消息历史整体渲染轮次面板：user 消息开新轮；assistant 携带的 tool_calls
    /// 与后续 tool 结果按 ToolCallId 配对生成取数清单；system 提示不渲染，[系统] 提示渲染为小提示。
    /// </summary>
    private void RenderAiConversation(IReadOnlyList<AiChatMessage> history, bool forceTail = false)
    {
        var followTail = forceTail || IsAiTurnsPinnedToBottom();
        var previousOffset = AiTurnsScroll.VerticalOffset;
        var totalTurns = history.Count(message =>
            message.Role == "user" && message.Content?.StartsWith("[系统]", StringComparison.Ordinal) != true);
        var hiddenTurns = Math.Max(0, totalTurns - _aiVisibleTurnLimit);
        var toolResults = history
            .Where(message => message.Role == "tool" && !string.IsNullOrWhiteSpace(message.ToolCallId))
            .GroupBy(message => message.ToolCallId!, StringComparer.Ordinal)
            .ToDictionary(group => group.Key, group => group.Last(), StringComparer.Ordinal);
        AiTurnsPanel.Children.Clear();
        if (hiddenTurns > 0)
        {
            var revealCount = Math.Min(AiTurnRenderPageSize, hiddenTurns);
            var revealButton = new Button
            {
                Content = $"显示更早的 {revealCount} 轮（另有 {hiddenTurns} 轮未渲染）",
                HorizontalAlignment = HorizontalAlignment.Center,
                Padding = new Thickness(14, 5, 14, 5),
                Margin = new Thickness(0, 0, 0, 10),
                ToolTip = "只影响界面渲染；完整对话仍会参与导出，长期历史仍由轻量上下文策略管理。"
            };
            revealButton.Click += (_, _) =>
            {
                _aiVisibleTurnLimit = Math.Min(totalTurns, _aiVisibleTurnLimit + AiTurnRenderPageSize);
                RenderAiConversation(history);
                Dispatcher.BeginInvoke(DispatcherPriority.Loaded, AiTurnsScroll.ScrollToHome);
            };
            AiTurnsPanel.Children.Add(revealButton);
        }
        var turn = 0;
        var renderCurrentTurn = hiddenTurns == 0;
        for (var index = 0; index < history.Count; index++)
        {
            var message = history[index];
            switch (message.Role)
            {
                case "system":
                    continue;
                case "user":
                    if (message.Content is not null && message.Content.StartsWith("[系统]", StringComparison.Ordinal))
                    {
                        if (renderCurrentTurn) AppendAiNoticeBlock(message.Content);
                        break;
                    }
                    turn++;
                    renderCurrentTurn = turn > hiddenTurns;
                    if (!renderCurrentTurn) break;
                    AppendAiUserBlock(turn, message);
                    var fetches = new List<(string Name, string Arguments, int ResultChars, int ResultBytes, bool Truncated)>();
                    for (var ahead = index + 1; ahead < history.Count && history[ahead].Role != "user"; ahead++)
                    {
                        if (history[ahead].Role != "assistant") continue;
                        if (history[ahead].ToolCalls is { Count: > 0 } calls)
                        {
                            foreach (var call in calls)
                            {
                                toolResults.TryGetValue(call.Id, out var result);
                                var resultText = result?.Content ?? string.Empty;
                                fetches.Add((call.Name, call.ArgumentsJson, resultText.Length,
                                    Encoding.UTF8.GetByteCount(resultText),
                                    resultText.Contains("预算", StringComparison.Ordinal) || resultText == NetMindDefaults.AiToolResultFoldedPlaceholder));
                            }
                        }
                        if (history[ahead].ToolTraces is { Count: > 0 } traces)
                            fetches.AddRange(traces.Select(trace =>
                                (trace.Name, trace.ArgumentsJson, trace.ResultCharacters, trace.ResultBytes, trace.Truncated)));
                    }
                    if (fetches.Count > 0) AppendAiFetchBlock(fetches);
                    break;
                case "assistant" when !string.IsNullOrWhiteSpace(message.Content):
                    if (renderCurrentTurn) AppendAiAssistantBlock(message);
                    break;
                default:
                    // tool 结果已并入取数清单，不单独渲染。
                    break;
            }
        }
        RestoreAiTurnsScroll(followTail, previousOffset);
    }

    // —— 会话气泡：用户提问与助手回复各为可折叠气泡，取数/JSON 默认折叠，收尾回复底部附用时与令牌统计 ——

    private static readonly Brush UserBubbleBrush = new SolidColorBrush(Color.FromRgb(20, 52, 64));
    // 气泡正文亮色：代码构建的 TextBlock 从窗口继承前景色会在 Expander 内容链路上丢失（渲染为黑字），必须显式赋值。
    private static readonly Brush BubbleTextBrush = new SolidColorBrush(Color.FromRgb(206, 217, 223));
    private static readonly Brush AssistantBubbleBrush = new SolidColorBrush(Color.FromRgb(23, 37, 52));
    private static readonly Brush BubbleBorderBrush = new SolidColorBrush(Color.FromRgb(36, 56, 74));

    private void AppendAiUserBlock(int turn, AiChatMessage message)
    {
        var text = message.Content ?? string.Empty;
        var firstLine = text.Split('\n')[0].Trim();
        var summary = firstLine.Length > 60 ? firstLine[..60] + "…" : firstLine;
        var panel = new StackPanel();
        panel.Children.Add(new TextBlock
        {
            Text = $"提问 · 第 {turn} 轮",
            FontSize = 12,
            FontWeight = FontWeights.SemiBold,
            Foreground = Accent,
            Margin = new Thickness(0, 0, 0, 4),
        });
        // 首轮表格直接使用会话证据池的结构化行；不再从整段提示词正则反解析。
        // 旧会话无法恢复证据池时才使用兼容解析，二者都失败才回退纯文本。
        if (turn != 1 || (!TryAppendStructuredEvidenceListBlocks(panel, text) && !TryAppendEvidenceListBlocks(panel, text)))
            panel.Children.Add(new TextBlock { Text = text, TextWrapping = TextWrapping.Wrap, Foreground = BubbleTextBrush });
        var bubble = new Border
        {
            Background = UserBubbleBrush,
            BorderBrush = BubbleBorderBrush,
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(8),
            Padding = new Thickness(12, 8, 12, 8),
            Margin = new Thickness(0, 6, 0, 6),
            Child = panel
        };
        // Border 无 Foreground 属性，用 TextElement 附加属性向后代继承亮色前景。
        TextElement.SetForeground(bubble, BubbleTextBrush);
        AiTurnsPanel.Children.Add(new Expander
        {
            Header = new TextBlock { Text = $"我的提问（第 {turn} 轮）：{summary}", FontSize = 12, Foreground = Accent },
            Content = bubble,
            IsExpanded = true,
            Margin = new Thickness(0, 4, 0, 8),
        });
    }

    // v2：#序号 时间 方法 主机 路径/查询键 状态 延迟ms 大小B 内容类型；端点允许包含查询键前的空格。
    private static readonly Regex EvidenceListLinePattern = new(@"^#(\d+)\s+(\d{2}:\d{2}:\d{2}\.\d{3})\s+(\S+)\s+(\S+)\s+(.+?)\s+(\d{3})\s+(\d+)ms\s+(\d+)B(?:\s+(.*))?$", RegexOptions.Compiled | RegexOptions.CultureInvariant);
    // 兼容已保存的 v1 会话：#序号 时间 方法 主机 路径 状态 大小B 内容类型。
    private static readonly Regex LegacyEvidenceListLinePattern = new(@"^#(\d+)\s+(\d{2}:\d{2}:\d{2}\.\d{3})\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d{3})\s+(\d+)B(?:\s+(.*))?$", RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private sealed record EvidenceListRow(string Ordinal, string Time, string Method, string Host, string Endpoint, string Status, string Latency, string Size, string ContentType);

    /// <summary>使用会话证据池直接创建首轮清单，提示词格式变化不会再导致表格失效。</summary>
    private bool TryAppendStructuredEvidenceListBlocks(StackPanel panel, string text)
    {
        if (_openEvidenceProvider is not { Pool.Count: > 0 } provider) return false;
        var summaryRows = AiConversationEngine.BuildEvidenceSummaryRows(provider.Pool);
        if (summaryRows.Count == 0) return false;
        var rows = summaryRows.Select(row => new EvidenceListRow(
            row.Ordinal.ToString(), row.Time, row.Method, row.Host, row.Endpoint,
            row.StatusCode.ToString(), row.LatencyMilliseconds + " ms",
            row.SizeBytes >= 1024 ? $"{row.SizeBytes / 1024d:0.0} KB" : row.SizeBytes + " B",
            row.ContentType)).ToArray();

        const string marker = "事务摘要：";
        var markerIndex = text.IndexOf(marker, StringComparison.Ordinal);
        if (markerIndex < 0) return false;
        var summaryStart = text.IndexOf('\n', markerIndex + marker.Length);
        summaryStart = summaryStart < 0 ? markerIndex + marker.Length : summaryStart + 1;
        var tailCandidates = new[] { "\n\n可用证据文件：", "\n\n分析要求：" }
            .Select(candidate => text.IndexOf(candidate, summaryStart, StringComparison.Ordinal))
            .Where(index => index >= 0)
            .ToArray();
        var summaryEnd = tailCandidates.Length == 0 ? text.Length : tailCandidates.Min();
        var leading = text[..summaryStart].Trim();
        var trailing = summaryEnd < text.Length ? text[summaryEnd..].Trim() : string.Empty;
        if (leading.Length > 0)
            panel.Children.Add(new TextBlock { Text = leading, TextWrapping = TextWrapping.Wrap, Foreground = BubbleTextBrush, Margin = new Thickness(0, 0, 0, 6) });
        panel.Children.Add(CreateEvidenceListGrid(rows));
        if (trailing.Length > 0)
            panel.Children.Add(new TextBlock { Text = trailing, TextWrapping = TextWrapping.Wrap, Foreground = BubbleTextBrush, Margin = new Thickness(0, 6, 0, 0) });
        return true;
    }

    /// <summary>把首轮消息中连续的“#序号”证据行渲染为紧凑表格，前后说明文字保持纯文本；无证据行返回 false。</summary>
    private static bool TryAppendEvidenceListBlocks(StackPanel panel, string text)
    {
        var lines = text.Split('\n');
        var firstEvidence = -1;
        var lastEvidence = -1;
        var rows = new List<EvidenceListRow>();
        for (var index = 0; index < lines.Length; index++)
        {
            var line = lines[index].TrimEnd('\r');
            var match = EvidenceListLinePattern.Match(line);
            var legacy = false;
            if (!match.Success)
            {
                match = LegacyEvidenceListLinePattern.Match(line);
                legacy = match.Success;
            }
            if (!match.Success) continue;
            if (firstEvidence < 0) firstEvidence = index;
            lastEvidence = index;
            var bytesGroup = legacy ? 7 : 8;
            var typeGroup = legacy ? 8 : 9;
            var bytes = long.TryParse(match.Groups[bytesGroup].Value, out var parsed) ? parsed : 0;
            rows.Add(new EvidenceListRow(match.Groups[1].Value, match.Groups[2].Value, match.Groups[3].Value,
                match.Groups[4].Value, match.Groups[5].Value, match.Groups[6].Value,
                legacy ? "—" : match.Groups[7].Value + " ms",
                bytes >= 1024 ? $"{bytes / 1024d:0.0} KB" : bytes + " B",
                match.Groups[typeGroup].Success && match.Groups[typeGroup].Value.Trim().Length > 0 ? match.Groups[typeGroup].Value.Trim() : "—"));
        }
        if (rows.Count == 0) return false;
        var leading = string.Join("\n", lines[..firstEvidence]).Trim();
        var trailing = string.Join("\n", lines[(lastEvidence + 1)..]).Trim();
        if (leading.Length > 0)
            panel.Children.Add(new TextBlock { Text = leading, TextWrapping = TextWrapping.Wrap, Foreground = BubbleTextBrush, Margin = new Thickness(0, 0, 0, 6) });
        panel.Children.Add(CreateEvidenceListGrid(rows));
        if (trailing.Length > 0)
            panel.Children.Add(new TextBlock { Text = trailing, TextWrapping = TextWrapping.Wrap, Foreground = BubbleTextBrush, Margin = new Thickness(0, 6, 0, 0) });
        return true;
    }

    /// <summary>证据清单紧凑表格：深色透明底，与用户气泡背景融合；自身限高内滚动。</summary>
    private static DataGrid CreateEvidenceListGrid(IReadOnlyList<EvidenceListRow> rows)
    {
        var grid = new DataGrid
        {
            AutoGenerateColumns = false,
            IsReadOnly = true,
            CanUserAddRows = false,
            HeadersVisibility = DataGridHeadersVisibility.Column,
            FontSize = 11,
            RowHeight = 22,
            MaxHeight = 260,
            Margin = new Thickness(0, 2, 0, 2),
            Background = Brushes.Transparent,
            Foreground = new SolidColorBrush(Color.FromRgb(197, 210, 217)),
            BorderBrush = BubbleBorderBrush,
            GridLinesVisibility = DataGridGridLinesVisibility.Horizontal,
            HorizontalGridLinesBrush = new SolidColorBrush(Color.FromArgb(0x26, 0xFF, 0xFF, 0xFF)),
            RowBackground = Brushes.Transparent,
            AlternatingRowBackground = new SolidColorBrush(Color.FromArgb(0x14, 0xFF, 0xFF, 0xFF)),
            ItemsSource = rows,
            SelectionMode = DataGridSelectionMode.Single,
        };
        grid.ColumnHeaderStyle = new Style(typeof(DataGridColumnHeader))
        {
            Setters =
            {
                new Setter(Control.BackgroundProperty, new SolidColorBrush(Color.FromRgb(19, 31, 44))),
                new Setter(Control.ForegroundProperty, Muted),
                new Setter(Control.PaddingProperty, new Thickness(6, 3, 6, 3)),
                new Setter(Control.BorderBrushProperty, new SolidColorBrush(Color.FromArgb(0x26, 0xFF, 0xFF, 0xFF))),
                new Setter(Control.BorderThicknessProperty, new Thickness(0, 0, 1, 1)),
            }
        };
        DataGridTextColumn Column(string header, string binding, double width, bool center = false)
        {
            var column = new DataGridTextColumn
            {
                Header = header,
                Binding = new Binding(binding),
                Width = width,
                IsReadOnly = true,
                // 隐式 DataGridRow 样式的 Foreground 会盖过表格级 Foreground，逐列显式亮色保证气泡深色底上可读
                ElementStyle = new Style(typeof(TextBlock))
                {
                    Setters =
                    {
                        new Setter(TextBlock.ForegroundProperty, new SolidColorBrush(Color.FromRgb(206, 217, 223))),
                        new Setter(TextBlock.VerticalAlignmentProperty, VerticalAlignment.Center),
                        new Setter(TextBlock.HorizontalAlignmentProperty, center ? HorizontalAlignment.Stretch : HorizontalAlignment.Left),
                        new Setter(TextBlock.TextAlignmentProperty, center ? TextAlignment.Center : TextAlignment.Left),
                        new Setter(TextBlock.TextTrimmingProperty, TextTrimming.CharacterEllipsis),
                    }
                }
            };
            // 不要给普通列写入 HeaderStyle=null：这会覆盖 DataGrid.ColumnHeaderStyle，
            // 使表头退回系统白色默认样式。仅序号列创建继承深色表头的居中样式。
            if (center)
            {
                column.HeaderStyle = new Style(typeof(DataGridColumnHeader), grid.ColumnHeaderStyle)
                {
                    Setters =
                    {
                        new Setter(Control.HorizontalContentAlignmentProperty, HorizontalAlignment.Center),
                    }
                };
            }
            return column;
        }
        grid.Columns.Add(Column("#", nameof(EvidenceListRow.Ordinal), 32, center: true));
        grid.Columns.Add(Column("时间", nameof(EvidenceListRow.Time), 76));
        grid.Columns.Add(Column("方法", nameof(EvidenceListRow.Method), 48));
        grid.Columns.Add(Column("主机", nameof(EvidenceListRow.Host), 120));
        grid.Columns.Add(Column("端点", nameof(EvidenceListRow.Endpoint), 170));
        grid.Columns.Add(Column("状态", nameof(EvidenceListRow.Status), 42));
        grid.Columns.Add(Column("延迟", nameof(EvidenceListRow.Latency), 56));
        grid.Columns.Add(Column("大小", nameof(EvidenceListRow.Size), 56));
        grid.Columns.Add(Column("类型", nameof(EvidenceListRow.ContentType), 110));
        return grid;
    }

    private void AppendAiFetchBlock(IReadOnlyList<(string Name, string Arguments, int ResultChars, int ResultBytes, bool Truncated)> fetches)
    {
        var panel = new StackPanel();
        foreach (var (name, arguments, resultChars, resultBytes, truncated) in fetches)
        {
            var detail = arguments.Length > 160 ? arguments[..160] + "…" : arguments;
            panel.Children.Add(new TextBlock
            {
                Text = $"· {name} {detail} → 取回 {resultChars:N0} 字符 / {FormatByteCount(resultBytes)}" +
                       (truncated ? "（已截断）" : string.Empty),
                TextWrapping = TextWrapping.Wrap,
                FontSize = 12,
                Foreground = Muted,
                Margin = new Thickness(12, 2, 0, 0),
            });
        }
        AiTurnsPanel.Children.Add(new Expander
        {
            Header = new TextBlock { Text = $"取数记录（{fetches.Count} 次，含 JSON 参数，点击展开）", FontSize = 12, Foreground = Accent },
            Content = panel,
            IsExpanded = false,
            Margin = new Thickness(0, 0, 0, 8),
        });
    }

    private void AppendAiAssistantBlock(AiChatMessage message)
    {
        var content = new StackPanel();
        content.Children.Add(CreateMarkdownViewer(message.Content ?? string.Empty));
        var stats = FormatAiMessageStats(message);
        if (stats.Length > 0)
        {
            content.Children.Add(new TextBlock
            {
                Text = stats,
                FontSize = 11,
                Foreground = Muted,
                HorizontalAlignment = HorizontalAlignment.Right,
                Margin = new Thickness(0, 6, 0, 0),
            });
        }
        var bubble = new Border
        {
            Background = AssistantBubbleBrush,
            BorderBrush = BubbleBorderBrush,
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(8),
            Padding = new Thickness(12, 10, 12, 10),
            Margin = new Thickness(0, 6, 0, 6),
            Child = content
        };
        AiTurnsPanel.Children.Add(new Expander
        {
            Header = new TextBlock { Text = "助手回复（点击折叠/展开）", FontSize = 12, Foreground = Accent },
            Content = bubble,
            IsExpanded = true,
            Margin = new Thickness(0, 0, 0, 10),
        });
    }

    /// <summary>收尾助手消息携带的本轮统计：用时 · 输入/输出令牌；旧会话无统计时返回空串。</summary>
    private static string FormatAiMessageStats(AiChatMessage message)
    {
        var parts = new List<string>(3);
        if (message.ElapsedMilliseconds.HasValue)
            parts.Add($"用时 {FormatElapsed(TimeSpan.FromMilliseconds(message.ElapsedMilliseconds.Value))}");
        if (message.InputTokens.HasValue || message.OutputTokens.HasValue)
            parts.Add($"本轮累计输入 {(message.InputTokens ?? 0):N0} / 输出 {(message.OutputTokens ?? 0):N0} 令牌");
        if (message.ToolTraces is { Count: > 0 }) parts.Add("工具原文已释放，追问不会重复发送");
        return string.Join(" · ", parts);
    }

    private static string FormatByteCount(int bytes) => bytes switch
    {
        >= 1024 * 1024 => $"{bytes / 1024d / 1024d:0.0} MB",
        >= 1024 => $"{bytes / 1024d:0.0} KB",
        _ => $"{bytes} B"
    };

    private static string FormatStorageBytes(long bytes) => bytes switch
    {
        >= 1024L * 1024 * 1024 * 1024 => $"{bytes / 1024d / 1024d / 1024d / 1024d:0.00} TB",
        >= 1024L * 1024 * 1024 => $"{bytes / 1024d / 1024d / 1024d:0.00} GB",
        >= 1024L * 1024 => $"{bytes / 1024d / 1024d:0.0} MB",
        >= 1024L => $"{bytes / 1024d:0.0} KB",
        _ => $"{bytes:N0} B"
    };

    private FlowDocumentScrollViewer CreateMarkdownViewer(string markdown)
    {
        var viewer = new FlowDocumentScrollViewer
        {
            Document = MarkdownFlowDocumentRenderer.Render(markdown),
            // 会话区只有最外层 AiTurnsScroll 负责纵向滚动；回复内再放一个可滚查看器会吞掉滚轮。
            VerticalScrollBarVisibility = ScrollBarVisibility.Disabled,
            IsToolBarVisible = false,
            IsSelectionEnabled = true,
            Background = Brushes.Transparent,
        };
        viewer.PreviewMouseWheel += Ai只读内容_滚轮转发;
        return viewer;
    }

    private TextBox CreateStreamingTextBox()
    {
        var textBox = new TextBox
        {
            Text = "正在请求模型…",
            IsReadOnly = true,
            AcceptsReturn = true,
            TextWrapping = TextWrapping.Wrap,
            VerticalScrollBarVisibility = ScrollBarVisibility.Disabled,
            HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled,
            Background = Brushes.Transparent,
            Foreground = BubbleTextBrush,
            BorderThickness = new Thickness(0),
            Padding = new Thickness(0),
        };
        textBox.PreviewMouseWheel += Ai只读内容_滚轮转发;
        return textBox;
    }

    /// <summary>
    /// Markdown/流式只读控件为了允许选择文本仍需参与命中测试，但它们自己的纵向滚动已禁用；
    /// 明确把滚轮交给会话外层，避免鼠标位于回复正文时形成滚动死区。
    /// </summary>
    private void Ai只读内容_滚轮转发(object sender, MouseWheelEventArgs e)
    {
        if (e.Handled || !CanScrollVertically(AiTurnsScroll, e.Delta)) return;
        AiTurnsScroll.ScrollToVerticalOffset(AiTurnsScroll.VerticalOffset - e.Delta / 120.0 * 56);
        e.Handled = true;
    }

    private bool IsAiTurnsPinnedToBottom() =>
        AiTurnsScroll.ScrollableHeight <= 0 || AiTurnsScroll.ScrollableHeight - AiTurnsScroll.VerticalOffset <= 80;

    private void RestoreAiTurnsScroll(bool followTail, double previousOffset)
    {
        // 动态子控件要到布局阶段后才会更新 ScrollableHeight；Loaded 优先级恢复可避免在旧高度上被夹断。
        Dispatcher.BeginInvoke(DispatcherPriority.Loaded, () =>
        {
            if (followTail) AiTurnsScroll.ScrollToEnd();
            else AiTurnsScroll.ScrollToVerticalOffset(previousOffset);
        });
    }

    private void AppendAiNoticeBlock(string text)
    {
        AiTurnsPanel.Children.Add(new TextBlock
        {
            Text = text,
            TextWrapping = TextWrapping.Wrap,
            FontSize = 12,
            Foreground = Amber,
            Margin = new Thickness(0, 0, 0, 10),
        });
    }

    // —— 流式渲染：网关文本增量累积进缓冲，300 ms 节流重渲染当前轮的助手占位块 ——

    private void BeginAiStreamingRender()
    {
        _aiStreamBuffer.Clear();
        var followTail = IsAiTurnsPinnedToBottom();
        var previousOffset = AiTurnsScroll.VerticalOffset;
        var textBox = CreateStreamingTextBox();
        _aiStreamingTextBox = textBox;
        AiTurnsPanel.Children.Add(new Border
        {
            Background = AssistantBubbleBrush,
            BorderBrush = BubbleBorderBrush,
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(8),
            Padding = new Thickness(12, 10, 12, 10),
            Margin = new Thickness(0, 6, 0, 10),
            Child = textBox,
        });
        _aiStreamRenderTimer ??= new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(300) };
        _aiStreamRenderTimer.Stop();
        _aiStreamRenderTimer.Tick -= Ai流式渲染_Tick;
        _aiStreamRenderTimer.Tick += Ai流式渲染_Tick;
        RestoreAiTurnsScroll(followTail, previousOffset);
    }

    private void Ai流式渲染_Tick(object? sender, EventArgs e)
    {
        _aiStreamRenderTimer?.Stop();
        if (_aiStreamingTextBox is null || _aiStreamBuffer.Length == 0) return;
        var followTail = IsAiTurnsPinnedToBottom();
        var previousOffset = AiTurnsScroll.VerticalOffset;
        // 流式阶段只更新纯文本；完整 Markdown 在本轮结束后渲染一次，避免随输出增长反复重建整棵 FlowDocument。
        _aiStreamingTextBox.Text = _aiStreamBuffer.ToString();
        RestoreAiTurnsScroll(followTail, previousOffset);
    }

    private void EndAiStreamingRender()
    {
        _aiStreamRenderTimer?.Stop();
        _aiStreamingTextBox = null;
        _aiStreamBuffer.Clear();
    }

    // —— 会话列表：加载/选择恢复/删除 ——

    private async Task LoadAiConversationsAsync(Guid? selectedId = null)
    {
        _loadingAiConversations = true;
        try
        {
            var summaries = await (await CreateAiConversationStoreAsync()).GetRecentAsync(50);
            AiConversationRows.Clear();
            foreach (var summary in summaries) AiConversationRows.Add(new AiConversationRow(summary, ResolveAiTemplate(summary.TemplateId).DisplayName));
            AiConversationList.SelectedItem = selectedId.HasValue
                ? AiConversationRows.FirstOrDefault(row => row.Source.Id == selectedId.Value)
                : null;
        }
        catch (Exception exception)
        {
            AiRunStatus.Text = "AI 会话列表读取失败";
            AiRunStatus.ToolTip = exception.Message;
            AiRunStatus.Foreground = Red;
        }
        finally { _loadingAiConversations = false; }
    }

    private async void AI会话选择_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (_loadingAiConversations) return;
        UpdateDeleteConversationButton();
        if (_aiTurnRunning)
        {
            // 运行中不允许切换会话：回滚视觉选中，避免点击被吞后选中态与实际会话不一致导致后续点击无响应。
            AiConversationList.SelectedItem = AiConversationRows.FirstOrDefault(row => row.Source.Id == _openConversationHeader?.Id);
            SetAiRunningStatus("AI 分析运行中，完成后再切换会话");
            AiRunStatus.Foreground = Amber;
            return;
        }
        // 多选仅服务批量删除；恰好单选时才恢复会话，避免多选过程中反复重载。
        if (AiConversationList.SelectedItems.Count != 1) return;
        if (AiConversationList.SelectedItem is not AiConversationRow row) return;
        await RestoreAiConversationAsync(row);
    }

    /// <summary>点击已选中项不会再触发 SelectionChanged；对当前已打开会话强制重新恢复，保证点击总能还原轮次。</summary>
    private async void AI会话列表_点击(object sender, MouseButtonEventArgs e)
    {
        if (_loadingAiConversations || _aiTurnRunning) return;
        if (AiConversationList.SelectedItems.Count != 1) return; // 多选状态下的点击交给批量删除，不触发恢复
        if (AiConversationList.SelectedItem is not AiConversationRow row) return;
        if (_openConversationHeader?.Id == row.Source.Id) await RestoreAiConversationAsync(row);
    }

    /// <summary>删除按钮随选中会话数联动：多选时标题带计数，未选中时置灰。</summary>
    private void UpdateDeleteConversationButton()
    {
        if (DeleteAiConversationButton is null || AiConversationList is null) return;
        var count = AiConversationList.SelectedItems.Count;
        DeleteAiConversationButton.IsEnabled = count > 0 && !_aiTurnRunning;
        DeleteAiConversationButton.Content = count > 1 ? $"删除会话（{count}）" : "删除会话";
    }

    private async Task RestoreAiConversationAsync(AiConversationRow row)
    {
        var workspacePath = _workspacePath;
        try
        {
            var conversation = await (await CreateAiConversationStoreAsync()).LoadAsync(row.Source.Id);
            if (conversation is null) return;
            if (!string.Equals(workspacePath, _workspacePath, StringComparison.OrdinalIgnoreCase) ||
                AiConversationList.SelectedItem is not AiConversationRow selected || selected.Source.Id != row.Source.Id) return;
            OpenAiConversation(conversation);
        }
        catch (Exception exception)
        {
            AiRunStatus.Text = "会话恢复失败";
            AiRunStatus.ToolTip = exception.Message;
            AiRunStatus.Foreground = Red;
        }
    }

    /// <summary>恢复打开会话：模板系统提示 + 落盘消息重建历史，尽力解析证据池，渲染全部轮次。</summary>
    private void OpenAiConversation(AiConversation conversation)
    {
        var header = conversation.Header;
        var template = ResolveAiTemplate(header.TemplateId);
        _openConversationHeader = header;
        var hasPersistedSystemPrompt = conversation.Messages.Any(message => message.Role == "system");
        _openConversationHistory = hasPersistedSystemPrompt
            ? [.. conversation.Messages]
            : [new AiChatMessage("system", template.SystemPrompt), .. conversation.Messages];
        AiConversationEngine.FoldHistoryIfNeeded(_openConversationHistory);
        _openEvidenceProvider = new WorkbenchAiEvidenceProvider(this, ResolveConversationPool(header.TransactionIds));
        _aiVisibleTurnLimit = AiTurnRenderPageSize;
        ResetAiTurnStatistics();
        SwitchToConversationView();
        AiConversationTitle.Text = $"{template.DisplayName} · {header.CreatedAt.ToLocalTime():MM-dd HH:mm} · {header.ScopeName}";
        RenderAiConversation(_openConversationHistory, forceTail: true);
        AiRunStatus.Text = $"已恢复 {AiConversationStore.CountTurns(_openConversationHistory)} 轮对话，可继续追问";
        AiRunStatus.ToolTip = null;
        AiRunStatus.Foreground = Green;
        DeleteAiConversationButton.IsEnabled = true;
        ExportAiConversationButton.IsEnabled = true;
        AiQuickFollowUpPanel.IsEnabled = true;
    }

    /// <summary>按会话元数据尽力解析证据池：优先内存持久化表，其次工作区最近事务；缺失记录跳过。</summary>
    private TrafficRecord[] ResolveConversationPool(IReadOnlyList<Guid> transactionIds)
    {
        var pool = new List<TrafficRecord>();
        var remaining = new List<Guid>();
        foreach (var id in transactionIds)
        {
            if (_storedTraffic.TryGetValue(id, out var stored)) pool.Add(stored.Traffic);
            else remaining.Add(id);
        }
        if (remaining.Count > 0)
        {
            try
            {
                using var archive = new TrafficArchive(_workspacePath);
                var byId = archive.GetRecentTraffic(NetMindDefaults.AiEvidenceCompletionScanLimit * 4)
                    .GroupBy(item => item.Traffic.Id)
                    .ToDictionary(group => group.Key, group => group.First().Traffic);
                foreach (var id in remaining)
                    if (byId.TryGetValue(id, out var traffic)) pool.Add(traffic);
            }
            catch { /* 工作区不可读时退回已解析的部分池 */ }
        }
        return pool.OrderBy(item => item.Timestamp).ToArray();
    }

    private async void 删除AI会话_Click(object sender, RoutedEventArgs e)
    {
        if (_aiTurnRunning) return;
        var targets = AiConversationList.SelectedItems.OfType<AiConversationRow>().ToArray();
        if (targets.Length == 0) return;
        var prompt = targets.Length == 1
            ? $"确认删除会话“{targets[0].DisplayName}”？"
            : $"确认删除选中的 {targets.Length} 个会话？";
        var answer = MessageBox.Show(this, prompt + "\n\n只删除会话记录，不会删除原始流量。", "确认删除 AI 会话", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);
        if (answer != MessageBoxResult.Yes) return;
        try
        {
            var store = await CreateAiConversationStoreAsync();
            foreach (var row in targets)
            {
                store.Delete(row.Source.Id);
                if (_openConversationHeader?.Id == row.Source.Id) CloseOpenConversation();
            }
            await new WorkspaceStore(_workspacePath).AppendAuditAsync("ai.conversation-deleted", new { conversationIds = targets.Select(item => item.Source.Id).ToArray() });
            await LoadAiConversationsAsync();
        }
        catch (Exception exception)
        {
            AiRunStatus.Text = "删除会话失败";
            AiRunStatus.ToolTip = exception.Message;
            AiRunStatus.Foreground = Red;
        }
    }

    private async void 导出AI完整会话_Click(object sender, RoutedEventArgs e)
    {
        if (_aiTurnRunning || _openConversationHeader is not { } openHeader) return;
        var dialog = new SaveFileDialog
        {
            Title = "导出 AI 完整对话",
            Filter = "Markdown 文件 (*.md)|*.md",
            DefaultExt = ".md",
            AddExtension = true,
            FileName = $"NetMind-AI-Conversation-{openHeader.CreatedAt.ToLocalTime():yyyyMMdd-HHmmss}.md"
        };
        if (dialog.ShowDialog(this) != true) return;
        ExportAiConversationButton.IsEnabled = false;
        try
        {
            var conversation = await (await CreateAiConversationStoreAsync()).LoadAsync(openHeader.Id)
                ?? throw new InvalidDataException("AI 会话记录不存在或已被删除。");
            var recoveredSystemPrompt = !conversation.Messages.Any(message => message.Role == "system");
            if (recoveredSystemPrompt)
            {
                var template = ResolveAiTemplate(conversation.Header.TemplateId);
                conversation = conversation with
                {
                    Messages = [new AiChatMessage("system", template.SystemPrompt), .. conversation.Messages]
                };
            }
            await using var stream = new FileStream(dialog.FileName, FileMode.Create, FileAccess.Write, FileShare.None,
                64 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
            await using var writer = new StreamWriter(stream, new UTF8Encoding(false));
            await AiConversationExportFormatter.WriteMarkdownAsync(writer, conversation, recoveredSystemPrompt);
            await new WorkspaceStore(_workspacePath).AppendAuditAsync("ai.conversation-exported", new
            {
                conversationId = openHeader.Id,
                turns = AiConversationStore.CountTurns(conversation.Messages),
                format = "markdown",
                redacted = true
            });
            AiRunStatus.Text = "完整对话已导出（敏感字段已脱敏）";
            AiRunStatus.ToolTip = dialog.FileName;
            AiRunStatus.Foreground = Green;
        }
        catch (Exception exception)
        {
            AiRunStatus.Text = "完整对话导出失败";
            AiRunStatus.ToolTip = exception.Message;
            AiRunStatus.Foreground = Red;
        }
        finally
        {
            ExportAiConversationButton.IsEnabled = _openConversationHeader is not null && !_aiTurnRunning;
        }
    }

    /// <summary>按进程采集：选定进程后启动静默抓包，后台仅落库该进程产生的事务。</summary>
    private async void 按进程采集_Click(object sender, RoutedEventArgs e)
    {
        if (_capturing)
        {
            MessageBox.Show(this, "采集进行中：请先停止当前采集，再按进程重新开始。", "按进程采集", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        if (!_settings.UseSilentCapture)
        {
            MessageBox.Show(this, "按进程抓取依赖底层静默抓包的事务进程归属解析：请先在顶部开启“静默抓包”后再试。", "按进程采集", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        var picker = new ProcessPickerWindow { Owner = this };
        if (picker.ShowDialog() != true || picker.SelectedProcess is not (var name, var pid, _)) return;
        _silentProcessFilter = name;
        await StartCoreHostAsync();
        if (_capturing)
        {
            CaptureState.Text = $"底层静默抓包中 · 仅抓取进程 {name}（PID {pid}）";
            CaptureState.Foreground = Accent;
        }
    }

    private void CloseOpenConversation()
    {
        _openConversationHeader = null;
        _openConversationHistory = [];
        _openEvidenceProvider = null;
        _aiVisibleTurnLimit = AiTurnRenderPageSize;
        ResetAiTurnStatistics();
        AiTurnsPanel.Children.Clear();
        AiConversationTitle.Text = "会话区";
        DeleteAiConversationButton.IsEnabled = false;
        ExportAiConversationButton.IsEnabled = false;
        AiQuickFollowUpPanel.IsEnabled = false;
        ShowAiEmptyHint();
    }

    // —— 提示词目录：模板与快捷追问可编辑，持久化到工作区 ai-prompts.json ——

    /// <summary>当前工作区的提示词目录；未载入时为内置默认。</summary>
    private AiPromptCatalog _aiCatalog = AiPromptCatalog.BuiltIn;

    /// <summary>按 Id 解析模板：优先当前目录（含自定义与覆写），未命中退回内置。</summary>
    private AiPromptTemplate ResolveAiTemplate(string? id) =>
        _aiCatalog.Templates.FirstOrDefault(template => string.Equals(template.Id, id, StringComparison.OrdinalIgnoreCase)) ?? AiPromptTemplate.Get(id);

    private void ApplyAiCatalog(AiPromptCatalog catalog, string? preferTemplateId)
    {
        _aiCatalog = catalog;
        RebuildAiTemplateCombo(preferTemplateId);
        RebuildQuickFollowUpButtons();
    }

    private void RebuildAiTemplateCombo(string? preferTemplateId)
    {
        var previous = preferTemplateId ?? (AiTemplateCombo.SelectedItem as ComboBoxItem)?.Tag?.ToString();
        AiTemplateCombo.Items.Clear();
        var selectedIndex = 0;
        foreach (var template in _aiCatalog.Templates)
        {
            AiTemplateCombo.Items.Add(new ComboBoxItem { Content = template.DisplayName, Tag = template.Id });
            if (string.Equals(template.Id, previous, StringComparison.OrdinalIgnoreCase)) selectedIndex = AiTemplateCombo.Items.Count - 1;
        }
        AiTemplateCombo.SelectedIndex = selectedIndex;
    }

    /// <summary>快捷追问按钮由目录动态生成；按钮 Tag 携带文本，复用既有快捷追问_Click 发送链路。</summary>
    private void RebuildQuickFollowUpButtons()
    {
        if (AiQuickFollowUpPanel is null) return;
        AiQuickFollowUpPanel.Children.Clear();
        var style = FindResource("SecondaryButton") as Style;
        var items = _aiCatalog.QuickFollowUps;
        for (var index = 0; index < items.Count; index++)
        {
            var button = new Button
            {
                Content = items[index],
                Tag = items[index],
                Style = style,
                Padding = new Thickness(11, 5, 11, 5),
                Margin = new Thickness(0, 0, index == items.Count - 1 ? 0 : 8, 6),
                ToolTip = "作为追问发送给当前会话"
            };
            button.Click += 快捷追问_Click;
            AiQuickFollowUpPanel.Children.Add(button);
        }
    }

    private async Task LoadAiPromptCatalogAsync()
    {
        try
        {
            var catalog = await new AiPromptCatalogStore(_workspacePath).LoadAsync();
            ApplyAiCatalog(catalog, (AiTemplateCombo.SelectedItem as ComboBoxItem)?.Tag?.ToString());
        }
        catch
        {
            // 目录不可读时退回内置默认，不阻断 AI 页初始化。
            ApplyAiCatalog(AiPromptCatalog.BuiltIn, AiPromptTemplate.DefaultTemplateId);
        }
    }

    private async void 管理提示词_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new AiPromptManagerWindow(_aiCatalog) { Owner = this };
        if (dialog.ShowDialog() != true) return;
        try
        {
            await new AiPromptCatalogStore(_workspacePath).SaveAsync(dialog.Catalog);
            ApplyAiCatalog(dialog.Catalog, null);
            await new WorkspaceStore(_workspacePath).AppendAuditAsync("ai.prompt-catalog-saved", new
            {
                templates = dialog.Catalog.Templates.Count,
                quickFollowUps = dialog.Catalog.QuickFollowUps.Count
            });
            AiRunStatus.Text = "提示词目录已保存";
            AiRunStatus.ToolTip = null;
            AiRunStatus.Foreground = Green;
        }
        catch (Exception exception)
        {
            MessageBox.Show(this, "提示词目录保存失败：\n\n" + exception.Message, "保存失败", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    // —— AI 分析用时计数：运行期间每秒在状态栏追加“已用时 X 分 X 秒” ——

    private void StartAiElapsedTimer()
    {
        _aiRunStartedAt = DateTime.Now;
        _aiElapsedTimer ??= new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _aiElapsedTimer.Tick -= Ai用时刷新_Tick;
        _aiElapsedTimer.Tick += Ai用时刷新_Tick;
        _aiElapsedTimer.Start();
    }

    private void StopAiElapsedTimer() => _aiElapsedTimer?.Stop();

    private void Ai用时刷新_Tick(object? sender, EventArgs e) => RefreshAiElapsedText();

    private void SetAiRunningStatus(string baseText)
    {
        _aiRunStatusBase = baseText;
        RefreshAiElapsedText();
    }

    private void RefreshAiElapsedText()
    {
        if (AiRunStatus is null) return;
        // 回复期间动态展示“已接收 / 响应上限”：用户需要知道当前容量与距上限的远近，上限本身不再单独展示；
        // 接近上限（≥90%）时状态转为警示色。
        var usageText = string.Empty;
        if (_aiRunResponseLimitBytes > 0)
        {
            var receivedBytes = Interlocked.Read(ref _aiTurnResponseBytes);
            usageText = $" · 已接收 {receivedBytes / 1048576.0:0.##} / {_aiRunResponseLimitBytes / 1048576.0:0} MB";
            AiRunStatus.Foreground = receivedBytes >= _aiRunResponseLimitBytes * 0.9 ? Amber : Accent;
        }
        AiRunStatus.Text = $"{_aiRunStatusBase}{usageText} · 已用时 {FormatElapsed(DateTime.Now - _aiRunStartedAt)}";
    }

    private static string FormatElapsed(TimeSpan elapsed) =>
        elapsed.TotalMinutes >= 1 ? $"{(int)elapsed.TotalMinutes} 分 {elapsed.Seconds:D2} 秒" : $"{elapsed.Seconds} 秒";

    // —— 键值分色渲染：键名用强调色，值用正文色，方便区分请求/响应中的键值信息 ——

    private static void ClearKeyValueText(RichTextBox box) => box.Document.Blocks.Clear();

    /// <summary>将“键: 值 / 键 = 值”格式文本键值分色渲染；无法识别分隔符的行按普通文本处理。</summary>
    private static void RenderKeyValueText(RichTextBox box, string text)
    {
        box.Document.Blocks.Clear();
        var paragraph = new Paragraph { Margin = new Thickness(0) };
        foreach (var rawLine in text.Split('\n'))
        {
            var line = rawLine.TrimEnd('\r');
            var colon = line.IndexOf(':');
            var equals = line.IndexOf('=');
            var separator = colon >= 0 && (equals < 0 || colon < equals) ? colon : equals;
            if (separator > 0)
            {
                paragraph.Inlines.Add(new Run(line[..(separator + 1)]) { Foreground = Accent });
                paragraph.Inlines.Add(new Run(line[(separator + 1)..]));
            }
            else
            {
                paragraph.Inlines.Add(new Run(line));
            }
            paragraph.Inlines.Add(new LineBreak());
        }
        box.Document.Blocks.Add(paragraph);
    }

    // —— 内容搜索关键字高亮：命中后选中该区间，用选区颜色高亮显示 ——

    private static bool TryHighlight(TextBox box, string keyword)
    {
        var index = box.Text.IndexOf(keyword, StringComparison.OrdinalIgnoreCase);
        if (index < 0) return false;
        box.Select(index, keyword.Length);
        box.Focus();
        return true;
    }

    /// <summary>在富文本框中选中并高亮关键字；命中需完整落在单个文本段内（键/值各自为独立段）。</summary>
    private static bool TryHighlight(RichTextBox box, string keyword)
    {
        foreach (var block in box.Document.Blocks)
        {
            if (block is not Paragraph paragraph) continue;
            foreach (var inline in paragraph.Inlines)
            {
                if (inline is not Run run) continue;
                var index = run.Text.IndexOf(keyword, StringComparison.OrdinalIgnoreCase);
                if (index < 0) continue;
                var start = run.ContentStart.GetPositionAtOffset(index + 1, LogicalDirection.Forward);
                var end = start?.GetPositionAtOffset(keyword.Length, LogicalDirection.Forward);
                if (start is null || end is null) continue;
                box.Selection.Select(start, end);
                box.Focus();
                return true;
            }
        }
        return false;
    }

    /// <summary>正文高亮：若当前为 JSON 树视图，先切回原始正文再选中关键字。</summary>
    private static bool TryHighlightBody(TextBox bodyText, TreeView jsonTree, Button toggleButton, string keyword)
    {
        if (bodyText.Visibility != Visibility.Visible && jsonTree.Visibility == Visibility.Visible)
            ToggleBodyJsonView(jsonTree, bodyText, toggleButton);
        return bodyText.Visibility == Visibility.Visible && TryHighlight(bodyText, keyword);
    }

    /// <summary>应用内容搜索定位的待高亮关键字；目标行已变化则丢弃，避免误高亮。</summary>
    private void TryApplyPendingHighlight()
    {
        if (_pendingContentHighlight is not (var rowId, var keyword, var location)) return;
        if (SelectedTraffic?.Source.Id != rowId)
        {
            _pendingContentHighlight = null;
            return;
        }
        var applied = location switch
        {
            "URL" => TryHighlight(TrafficUrlText, keyword),
            "查询参数" => TryHighlight(TrafficQueryText, keyword),
            "Cookie" => TryHighlight(TrafficCookieText, keyword),
            "请求头" => TryHighlight(TrafficRequestHeadersText, keyword),
            "响应头" => TryHighlight(TrafficResponseHeadersText, keyword),
            "请求正文" => TryHighlightBody(TrafficRequestBody, TrafficRequestJsonTree, 请求正文视图切换, keyword),
            "响应正文" => TryHighlightBody(TrafficResponseBody, TrafficResponseJsonTree, 响应正文视图切换, keyword),
            _ => false,
        };
        if (!applied) return;
        _pendingContentHighlight = null;
    }

    // —— 流量内容关键字搜索：覆盖 URL/头/参数/Cookie/正文，结果列表选中后定位主列表并高亮 ——

    private const int ContentSearchMaximumRows = 500;
    private const int ContentSearchBodyMaximumBytes = 1_048_576;
    private const int ContentSearchMaximumHits = 300;

    private sealed record ContentSearchHit(TrafficRow Row, string Keyword, string Location, string Title, string Snippet);

    private async void 内容搜索_Click(object sender, RoutedEventArgs e) => await RunContentSearchAsync();

    private async void 内容搜索_回车(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter) await RunContentSearchAsync();
    }

    private void 内容搜索结果关闭_Click(object sender, RoutedEventArgs e)
    {
        ContentSearchResultsPanel.Visibility = Visibility.Collapsed;
        ContentSearchCloseButton.Visibility = Visibility.Collapsed;
        ContentSearchResults.ItemsSource = null;
        ContentSearchStatus.Text = string.Empty;
    }

    private async Task RunContentSearchAsync()
    {
        var keyword = ContentSearchBox.Text?.Trim() ?? string.Empty;
        if (keyword.Length == 0)
        {
            ContentSearchStatus.Text = "请输入要搜索的关键字";
            return;
        }
        var rows = FilteredTrafficRows.Take(ContentSearchMaximumRows).ToArray();
        if (rows.Length == 0)
        {
            ContentSearchStatus.Text = "当前筛选没有可搜索的记录";
            return;
        }
        ContentSearchStatus.Text = $"正在搜索 {rows.Length} 条记录…";
        var storedSnapshot = _storedTraffic.ToArray();
        var workspacePath = _workspacePath;
        List<ContentSearchHit> hits;
        try
        {
            hits = await Task.Run(() => SearchTrafficContent(rows, keyword, storedSnapshot, workspacePath));
        }
        catch (Exception exception)
        {
            ContentSearchStatus.Text = "内容搜索失败：" + exception.Message;
            return;
        }
        ContentSearchResults.ItemsSource = hits;
        var hasHits = hits.Count > 0;
        ContentSearchResultsPanel.Visibility = hasHits ? Visibility.Visible : Visibility.Collapsed;
        ContentSearchCloseButton.Visibility = hasHits ? Visibility.Visible : Visibility.Collapsed;
        ContentSearchStatus.Text = $"命中 {hits.Count} 处（范围 {rows.Length} 条：URL、请求/响应头、查询参数、Cookie 与正文）";
    }

    private static List<ContentSearchHit> SearchTrafficContent(
        TrafficRow[] rows, string keyword, KeyValuePair<Guid, StoredTrafficRecord>[] stored, string workspacePath)
    {
        var hits = new List<ContentSearchHit>();
        var storedMap = new Dictionary<Guid, StoredTrafficRecord>(stored.Length);
        foreach (var pair in stored) storedMap[pair.Key] = pair.Value;
        foreach (var row in rows)
        {
            var traffic = row.Source;
            SearchField(row, keyword, traffic.Url, "URL", hits);
            SearchField(row, keyword, traffic.QueryParameters, "查询参数", hits);
            SearchField(row, keyword, traffic.Cookies, "Cookie", hits);
            SearchField(row, keyword, traffic.RequestHeaders, "请求头", hits);
            SearchField(row, keyword, traffic.ResponseHeaders, "响应头", hits);
            if (storedMap.TryGetValue(traffic.Id, out var record))
            {
                var workspace = new WorkspaceStore(workspacePath);
                SearchBlob(hits, row, keyword, workspace, record.RequestBlobHash, "请求正文");
                SearchBlob(hits, row, keyword, workspace, record.ResponseBlobHash, "响应正文");
            }
            if (hits.Count >= ContentSearchMaximumHits) break;
        }
        return hits;
    }

    private static void SearchField(TrafficRow row, string keyword, string? content, string location, List<ContentSearchHit> hits)
    {
        if (string.IsNullOrEmpty(content)) return;
        var index = content.IndexOf(keyword, StringComparison.OrdinalIgnoreCase);
        if (index < 0) return;
        hits.Add(new ContentSearchHit(row, keyword, location,
            $"{location} · {row.Method} {row.Host}{row.Endpoint}", BuildSearchSnippet(content, index, keyword)));
    }

    private static void SearchBlob(
        List<ContentSearchHit> hits, TrafficRow row, string keyword, WorkspaceStore workspace, string blobHash, string location)
    {
        if (string.IsNullOrEmpty(blobHash)) return;
        try
        {
            var blob = workspace.ReadBlobAsync(blobHash, ContentSearchBodyMaximumBytes).GetAwaiter().GetResult();
            var text = Encoding.UTF8.GetString(blob.Content);
            var index = text.IndexOf(keyword, StringComparison.OrdinalIgnoreCase);
            if (index < 0) return;
            hits.Add(new ContentSearchHit(row, keyword, location,
                $"{location} · {row.Method} {row.Host}{row.Endpoint}", BuildSearchSnippet(text, index, keyword)));
        }
        catch
        {
            // 单条正文读取失败（截断/损坏）不阻断整体搜索。
        }
    }

    private static string BuildSearchSnippet(string content, int index, string keyword)
    {
        var start = Math.Max(0, index - 26);
        var end = Math.Min(content.Length, index + keyword.Length + 34);
        var snippet = content[start..end].Replace('\n', ' ').Replace('\r', ' ').Replace('\t', ' ');
        return (start > 0 ? "…" : string.Empty) + snippet + (end < content.Length ? "…" : string.Empty);
    }

    private void 内容搜索结果_选中(object sender, SelectionChangedEventArgs e)
    {
        if (ContentSearchResults.SelectedItem is not ContentSearchHit hit) return;
        SelectedTraffic = hit.Row;
        TrafficGrid.ScrollIntoView(hit.Row);
        _pendingContentHighlight = (hit.Row.Source.Id, hit.Keyword, hit.Location);
        // 同步项（URL/参数/Cookie/头）立即高亮；正文在异步加载完成后由 UpdateTrafficEvidenceAsync 重试。
        TryApplyPendingHighlight();
    }

    private void 取消AI分析_Click(object sender, RoutedEventArgs e)
    {
        CancelAiButton.IsEnabled = false;
        AiRunStatus.Text = "正在取消…";
        _aiCancellation?.Cancel();
    }

    private void UpdateAiCredentialStatus(string? prefix = null)
    {
        var fromEnvironment = !string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("NETMIND_AI_API_KEY"));
        var hasKey = WindowsCredentialStore.HasApiKey();
        var detail = fromEnvironment ? "已读取环境变量密钥" : hasKey ? "密钥已安全保存到 Windows 凭据管理器" : "尚未保存 API 密钥";
        AiCredentialStatus.Text = string.IsNullOrWhiteSpace(prefix) ? detail : prefix + " · " + detail;
        AiCredentialStatus.Foreground = hasKey ? Green : Muted;
        // 已保存密钥且未输入新值时，用叠加占位提示告知用户无需重复填写。
        if (AiApiKeyPlaceholder is not null)
            AiApiKeyPlaceholder.Visibility = AiApiKeyBox.Password.Length == 0 && (hasKey || fromEnvironment)
                ? Visibility.Visible
                : Visibility.Collapsed;
    }

    /// <summary>密钥输入框变化时同步占位提示可见性；密钥本身仍需显式保存才写入凭据管理器。</summary>
    private void AI密钥输入_Changed(object sender, RoutedEventArgs e) => UpdateAiCredentialStatus();

    private static string SelectedTag(ComboBox comboBox, string fallback) =>
        (comboBox.SelectedItem as ComboBoxItem)?.Tag?.ToString() ?? fallback;

    private static void SelectComboByTag(ComboBox comboBox, string value)
    {
        foreach (var item in comboBox.Items.OfType<ComboBoxItem>())
        {
            if (!string.Equals(item.Tag?.ToString(), value, StringComparison.OrdinalIgnoreCase)) continue;
            comboBox.SelectedItem = item;
            return;
        }
    }

    private async Task LoadTrafficGroupsAsync(Guid? selectedId = null)
    {
        try
        {
            selectedId ??= _activeTrafficGroup?.Id;
            var groups = await new TrafficGroupStore(_workspacePath).GetAllAsync();
            TrafficGroups.Clear();
            // 记录组按创建时间升序（最新在最下），序号列随之递增。
            var groupOrdinal = 0;
            foreach (var group in groups.OrderBy(item => item.CreatedAt))
            {
                var row = new TrafficGroupRow(group) { Ordinal = ++groupOrdinal };
                TrafficGroups.Add(row);
            }
            TrafficGroupCountText.Text = $"{TrafficGroups.Count:N0} 个";
            TrafficGroupList.SelectedItem = selectedId.HasValue
                ? TrafficGroups.FirstOrDefault(row => row.Source.Id == selectedId.Value)
                : TrafficGroups.FirstOrDefault();
            if (TrafficGroups.Count == 0) ClearTrafficGroupEditor();
        }
        catch (Exception exception)
        {
            TrafficGroupStatusText.Text = "读取记录组失败：" + exception.Message;
            TrafficGroupStatusText.Foreground = Red;
        }
    }

    private Guid[] GetPersistedTrafficSelection()
    {
        return GetCurrentVisibleCheckedTrafficRows()
            .Where(row => _storedTraffic.ContainsKey(row.Source.Id))
            .Select(row => row.Source.Id).Distinct().ToArray();
    }

    private async Task SaveVisibleCheckedTrafficGroupAsync()
    {
        var ids = GetPersistedTrafficSelection();
        if (ids.Length == 0)
        {
            MessageBox.Show(this, "当前流量记录界面没有可保存的已勾选事务。\n\n被类型、搜索或域名过滤隐藏的勾选不会写入记录组；演示数据也不会写入。", "没有可保存的勾选记录", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        if (ids.Length > 1000)
        {
            MessageBox.Show(this, "当前可见已勾选事务超过记录组 1,000 条上限，请缩小筛选或勾选范围。", "选择过多", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        await CreateTrafficGroupAsync(ids);
    }

    private async void 保存选择为记录组_Click(object sender, RoutedEventArgs e) =>
        await SaveVisibleCheckedTrafficGroupAsync();

    private async void 新建记录组_Click(object sender, RoutedEventArgs e) => await CreateTrafficGroupAsync([]);

    private async Task CreateTrafficGroupAsync(IReadOnlyList<Guid> ids)
    {
        try
        {
            var now = DateTimeOffset.UtcNow;
            var group = new TrafficGroup(Guid.NewGuid(), $"记录组 {now.ToLocalTime():yyyy-MM-dd HH:mm}", string.Empty,
                now, now, ids.Distinct().ToArray());
            await new TrafficGroupStore(_workspacePath).SaveAsync(group);
            await new WorkspaceStore(_workspacePath).AppendAuditAsync("traffic-group.created", new
            {
                group.Id,
                transactionCount = group.TrafficIds.Count
            });
            await LoadTrafficGroupsAsync(group.Id);
            SelectPage(GroupNav);
        }
        catch (Exception exception)
        {
            MessageBox.Show(this, "创建记录组失败：\n\n" + exception.Message, "无法创建记录组", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private async void 记录组选择_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (TrafficGroupList.SelectedItem is not TrafficGroupRow row)
        {
            ClearTrafficGroupEditor();
            return;
        }
        _activeTrafficGroup = row.Source;
        _activeTrafficGroupIds.Clear();
        _activeTrafficGroupIds.UnionWith(row.Source.TrafficIds);
        TrafficGroupNameBox.Text = row.Source.Name;
        TrafficGroupDescriptionBox.Text = row.Source.Description;
        SetTrafficGroupEditorEnabled(true);
        TrafficGroupStatusText.Text = "正在恢复记录组事务…";
        TrafficGroupStatusText.Foreground = Accent;
        GroupTrafficRows.Clear();
        try
        {
            var stored = await Task.Run(() =>
            {
                using var archive = new TrafficArchive(_workspacePath);
                return archive.GetTrafficByIds(row.Source.TrafficIds);
            });
            if (_activeTrafficGroup?.Id != row.Source.Id) return;
            var groupOrdinal = 0;
            foreach (var item in stored.OrderBy(storedItem => storedItem.Traffic.Timestamp))
            {
                // 记录组可能包含已滑出“最近流量窗口”的事务；保留其存储元数据，供右键复制正文/cURL 与 AI 取证复用。
                _storedTraffic[item.Traffic.Id] = item;
                var trafficRow = new TrafficRow(item.Traffic, SourceLabel(item.CaptureMode), item.SessionId) { Ordinal = ++groupOrdinal };
                GroupTrafficRows.Add(trafficRow);
            }
            var missing = row.Source.TrafficIds.Count - stored.Count;
            TrafficGroupStatusText.Text = missing > 0
                ? $"已恢复 {stored.Count:N0} 条 · {missing:N0} 条原始事务已被清理或不存在"
                : $"已恢复全部 {stored.Count:N0} 条事务";
            TrafficGroupStatusText.Foreground = missing > 0 ? Amber : Green;
            AnalyzeTrafficGroupButton.IsEnabled = stored.Count > 0;
            RemoveTrafficGroupItemsButton.IsEnabled = stored.Count > 0;
        }
        catch (Exception exception)
        {
            TrafficGroupStatusText.Text = "恢复记录组失败：" + exception.Message;
            TrafficGroupStatusText.Foreground = Red;
        }
    }

    private async void 保存记录组_Click(object sender, RoutedEventArgs e)
    {
        if (_activeTrafficGroup is null) return;
        try
        {
            var updated = _activeTrafficGroup with
            {
                Name = TrafficGroupNameBox.Text,
                Description = TrafficGroupDescriptionBox.Text,
                UpdatedAt = DateTimeOffset.UtcNow,
                TrafficIds = _activeTrafficGroupIds.ToArray()
            };
            await new TrafficGroupStore(_workspacePath).SaveAsync(updated);
            _activeTrafficGroup = updated;
            await new WorkspaceStore(_workspacePath).AppendAuditAsync("traffic-group.updated", new
            {
                updated.Id,
                transactionCount = updated.TrafficIds.Count
            });
            await LoadTrafficGroupsAsync(updated.Id);
            TrafficGroupStatusText.Text = "记录组信息已保存";
            TrafficGroupStatusText.Foreground = Green;
        }
        catch (Exception exception)
        {
            TrafficGroupStatusText.Text = "保存失败：" + exception.Message;
            TrafficGroupStatusText.Foreground = Red;
        }
    }

    private async void 追加记录到组_Click(object sender, RoutedEventArgs e)
    {
        if (_activeTrafficGroup is null) return;
        var ids = GetPersistedTrafficSelection();
        if (ids.Length == 0)
        {
            TrafficGroupStatusText.Text = "当前没有已持久化的勾选或高亮记录可追加";
            TrafficGroupStatusText.Foreground = Amber;
            return;
        }
        var before = _activeTrafficGroupIds.Count;
        _activeTrafficGroupIds.UnionWith(ids);
        if (_activeTrafficGroupIds.Count > 1000)
        {
            _activeTrafficGroupIds.Clear();
            _activeTrafficGroupIds.UnionWith(_activeTrafficGroup.TrafficIds);
            TrafficGroupStatusText.Text = "单个记录组最多保存 1,000 条事务";
            TrafficGroupStatusText.Foreground = Red;
            return;
        }
        await SaveTrafficGroupMembersAsync($"已追加 {_activeTrafficGroupIds.Count - before:N0} 条新事务");
    }

    private async void 移除组内记录_Click(object sender, RoutedEventArgs e)
    {
        if (_activeTrafficGroup is null) return;
        var selected = GetSelectedTrafficRows(TrafficGroupGrid).Select(row => row.Source.Id).ToArray();
        if (selected.Length == 0)
        {
            TrafficGroupStatusText.Text = "请先在下方表格中选择要移除的事务";
            TrafficGroupStatusText.Foreground = Amber;
            return;
        }
        foreach (var id in selected) _activeTrafficGroupIds.Remove(id);
        await SaveTrafficGroupMembersAsync($"已从记录组移除 {selected.Length:N0} 条事务");
    }

    private async Task SaveTrafficGroupMembersAsync(string successMessage)
    {
        if (_activeTrafficGroup is null) return;
        try
        {
            var updated = _activeTrafficGroup with { UpdatedAt = DateTimeOffset.UtcNow, TrafficIds = _activeTrafficGroupIds.ToArray() };
            await new TrafficGroupStore(_workspacePath).SaveAsync(updated);
            _activeTrafficGroup = updated;
            await new WorkspaceStore(_workspacePath).AppendAuditAsync("traffic-group.members-updated", new
            {
                updated.Id,
                transactionCount = updated.TrafficIds.Count
            });
            await LoadTrafficGroupsAsync(updated.Id);
            TrafficGroupStatusText.Text = successMessage;
            TrafficGroupStatusText.Foreground = Green;
        }
        catch (Exception exception)
        {
            TrafficGroupStatusText.Text = "更新记录组失败：" + exception.Message;
            TrafficGroupStatusText.Foreground = Red;
        }
    }

    private void 分析记录组_Click(object sender, RoutedEventArgs e)
    {
        if (_activeTrafficGroup is null) return;
        var explicitlySelected = GetSelectedTrafficRows(TrafficGroupGrid).Select(row => row.Source).ToArray();
        var evidence = explicitlySelected.Length > 1
            ? explicitlySelected
            : GroupTrafficRows.Select(row => row.Source).ToArray();
        if (evidence.Length == 0)
        {
            TrafficGroupStatusText.Text = "该记录组没有可恢复的事务";
            TrafficGroupStatusText.Foreground = Red;
            return;
        }
        if (evidence.Length > _settings.AiEvidenceMaximumTransactions)
        {
            TrafficGroupStatusText.Text = $"全组 {evidence.Length} 条超出上限 {_settings.AiEvidenceMaximumTransactions}：请在下方表格中用 Ctrl/Shift 多选不超过上限的事务后再分析";
            TrafficGroupStatusText.Foreground = Red;
            return;
        }
        _groupAiEvidence = evidence;
        _groupAiName = _activeTrafficGroup.Name;
        _aiSelectedTrafficIds.Clear();
        _updatingTrafficRows = true;
        try { foreach (var row in TrafficRows) row.IsAiSelected = false; }
        finally { _updatingTrafficRows = false; }
        UpdateAiSelectionUi();
        SelectPage(AiNav);
        AiRunStatus.Text = $"已载入记录组“{_groupAiName}” · {evidence.Length} 条，等待运行分析";
        AiRunStatus.Foreground = Accent;
    }

    private async void 导出记录组_Click(object sender, RoutedEventArgs e)
    {
        if (_activeTrafficGroup is null) return;
        var group = _activeTrafficGroup;
        var safeName = string.Concat(group.Name.Select(character =>
            Path.GetInvalidFileNameChars().Contains(character) ? '_' : character)).Trim();
        if (string.IsNullOrWhiteSpace(safeName)) safeName = "记录组-" + group.Id.ToString("N")[..8];
        var dialog = new SaveFileDialog
        {
            Title = "导出记录组完整数据",
            Filter = "NetMind 完整记录组包 (*.zip)|*.zip|HTTP Archive 1.2 (*.har)|*.har",
            FilterIndex = 1,
            AddExtension = true,
            DefaultExt = ".zip",
            FileName = $"{safeName}-{DateTimeOffset.Now:yyyyMMdd-HHmmss}.zip"
        };
        if (dialog.ShowDialog(this) != true) return;

        ExportTrafficGroupButton.IsEnabled = false;
        TrafficGroupStatusText.Text = "正在导出完整事务元数据与原始正文…";
        TrafficGroupStatusText.Foreground = Accent;
        try
        {
            var exportHar = dialog.FilterIndex == 2;
            var outputPath = Path.ChangeExtension(dialog.FileName, exportHar ? ".har" : ".zip");
            var result = exportHar
                ? await TrafficGroupExporter.ExportHarAsync(_workspacePath, group, outputPath)
                : await TrafficGroupExporter.ExportZipAsync(_workspacePath, group, outputPath);
            await new WorkspaceStore(_workspacePath).AppendAuditAsync("traffic-group.exported", new
            {
                group.Id,
                result.Format,
                result.ExportedTransactions,
                result.MissingTransactions,
                result.RequestBodyBytes,
                result.ResponseBodyBytes,
                result.OutputBytes,
                fileName = Path.GetFileName(outputPath)
            });
            TrafficGroupStatusText.Text = result.MissingTransactions == 0
                ? $"已导出 {result.ExportedTransactions:N0} 条完整事务 · {result.OutputBytes / 1024d / 1024d:0.0} MB"
                : $"已导出 {result.ExportedTransactions:N0} 条 · {result.MissingTransactions:N0} 条原始事务缺失（已写入清单）";
            TrafficGroupStatusText.Foreground = result.MissingTransactions == 0 ? Green : Amber;
        }
        catch (Exception exception)
        {
            TrafficGroupStatusText.Text = "导出记录组失败：" + exception.Message;
            TrafficGroupStatusText.Foreground = Red;
            MessageBox.Show(this, "导出记录组失败：\n\n" + exception.Message, "无法导出记录组", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            ExportTrafficGroupButton.IsEnabled = _activeTrafficGroup is not null;
        }
    }

    private async void 删除记录组_Click(object sender, RoutedEventArgs e)
    {
        if (_activeTrafficGroup is null) return;
        var group = _activeTrafficGroup;
        var answer = MessageBox.Show(this, $"确认删除记录组“{group.Name}”？\n\n只删除分组，不会删除原始流量事务。", "确认删除记录组", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);
        if (answer != MessageBoxResult.Yes) return;
        try
        {
            new TrafficGroupStore(_workspacePath).Delete(group.Id);
            if (_groupAiName == group.Name) ClearGroupAiScope();
            await new WorkspaceStore(_workspacePath).AppendAuditAsync("traffic-group.deleted", new { group.Id, transactionCount = group.TrafficIds.Count });
            _activeTrafficGroup = null;
            _activeTrafficGroupIds.Clear();
            await LoadTrafficGroupsAsync();
        }
        catch (Exception exception)
        {
            TrafficGroupStatusText.Text = "删除记录组失败：" + exception.Message;
            TrafficGroupStatusText.Foreground = Red;
        }
    }

    private void ClearTrafficGroupEditor()
    {
        _activeTrafficGroup = null;
        _activeTrafficGroupIds.Clear();
        GroupTrafficRows.Clear();
        TrafficGroupNameBox.Text = TrafficGroupDescriptionBox.Text = string.Empty;
        SetTrafficGroupEditorEnabled(false);
        TrafficGroupStatusText.Text = "请选择或新建一个记录组";
        TrafficGroupStatusText.Foreground = Muted;
    }

    private void SetTrafficGroupEditorEnabled(bool enabled)
    {
        TrafficGroupNameBox.IsEnabled = enabled;
        TrafficGroupDescriptionBox.IsEnabled = enabled;
        SaveTrafficGroupButton.IsEnabled = enabled;
        AppendTrafficGroupButton.IsEnabled = enabled;
        ExportTrafficGroupButton.IsEnabled = enabled;
        DeleteTrafficGroupButton.IsEnabled = enabled;
        AnalyzeTrafficGroupButton.IsEnabled = enabled && GroupTrafficRows.Count > 0;
        RemoveTrafficGroupItemsButton.IsEnabled = enabled && GroupTrafficRows.Count > 0;
    }

    private void UpdateAnalysis(IEnumerable<TrafficRecord> traffic)
    {
        var snapshot = TrafficAnalysisEngine.Analyze(traffic);
        RequestMetric.Text = _capturedCount.ToString("N0");
        ErrorMetric.Text = snapshot.ErrorRate.ToString("0.0") + "%";
        LatencyMetric.Text = snapshot.P95LatencyMilliseconds + " 毫秒";
        ClusterMetric.Text = snapshot.Clusters.Count.ToString();
        // 概览右列同步端点聚类明细：按请求数降序取前 40，让指标卡背后的分析结果可见可下钻；序号列从 1 起递增。
        OverviewClusterRows.Clear();
        var clusterOrdinal = 0;
        foreach (var cluster in snapshot.Clusters.OrderByDescending(item => item.RequestCount).Take(40))
            OverviewClusterRows.Add(OverviewClusterRow.From(cluster, ++clusterOrdinal));
    }

    /// <summary>概览端点聚类下钻：把规范化端点填入流量探索搜索框并切页，复用既有搜索筛选链路。</summary>
    private void 端点聚类选择_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (!IsLoaded || OverviewClusterGrid.CurrentItem is not OverviewClusterRow row) return;
        if (TrafficSearch.Text == row.Endpoint) { SelectPage(TrafficNav); return; }
        TrafficSearch.Text = row.Endpoint;
        SelectPage(TrafficNav);
    }

    private void UpdateModeText()
    {
        if (OverviewMode is null) return;
        var hasRealTraffic = _storedTraffic.Values.Any(item => SourceLabel(item.CaptureMode) is SourceRealProxy or SourceSilentCapture);
        var listenEndpoint = $"{LoopbackAddress}:{_settings.ListenPort}";
        OverviewMode.Text = _showingDemoData
            ? "演示数据 · 点击“开始采集”切换为真实 HTTP/HTTPS 代理"
            : _capturing ? _silentCaptureActive
                ? "底层静默抓包中 · WinDivert 透明捕获全部进程 TCP"
                : _tlsInspectionEnabled
                ? $"真实 HTTP/HTTPS 代理采集中 · HTTPS HTTP/1.1 正文解密已启用 · {listenEndpoint}"
                : $"真实 HTTP/HTTPS 代理采集中 · {listenEndpoint}"
            : hasRealTraffic ? "本地捕获记录 · 包含真实代理与明确标记的模拟数据" : "本地模拟记录 · 尚未捕获真实代理事务";
    }

    private static string SourceLabel(string mode) => mode.Contains("代理", StringComparison.OrdinalIgnoreCase)
        ? SourceRealProxy
        : mode.Contains("静默", StringComparison.OrdinalIgnoreCase) ? SourceSilentCapture
        : mode.Contains("模拟", StringComparison.OrdinalIgnoreCase) ? SourceSimulated : SourceUnknown;

    private void 脚本编辑器_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (_highlightingScript || ScriptEditor is null) return;
        RequestScriptHighlight(ScriptEditor);
        MarkScriptDirty();
        UpdateScriptCompletion(auto: true);
    }

    // ==================== 脚本编辑器智能提示 ====================
    // 词表全部来自 NetMind.Core 的 HookScriptApi，与运行时契约同源：
    // event 信封字段与 fixture 事务字段都是反射出来的，契约一改提示立刻跟着改，
    // 不会出现「照提示写、运行时取不到值」。

    /// <summary>判断补全上下文时向光标前回看的字符数；够覆盖跨行的 INTERCEPT 规则和 return 字典。</summary>
    private const int ScriptCompletionLookBehind = 600;

    /// <summary>自动弹出所需的最短标识符前缀；太短会在正常打字时频繁跳出无关列表。</summary>
    private const int ScriptCompletionMinimumPrefix = 2;

    /// <summary>取光标前一段文本（含换行），用于判断补全上下文。</summary>
    private static string GetTextBeforeCaret(RichTextBox editor, int maximumCharacters)
    {
        var caret = editor.CaretPosition;
        var start = caret.GetPositionAtOffset(-maximumCharacters, LogicalDirection.Backward) ?? caret.DocumentStart;
        return new TextRange(start, caret).Text;
    }

    private static string LastLineOf(string text)
    {
        var index = text.LastIndexOfAny(['\n', '\r']);
        return index < 0 ? text : text[(index + 1)..];
    }

    /// <summary>光标是否落在 # 注释里。字符串里的 # 不算注释，所以要跟着引号状态走。</summary>
    private static bool IsInsideComment(string lineBeforeCaret)
    {
        var single = false;
        var quoted = false;
        foreach (var character in lineBeforeCaret)
        {
            if (character == '\'' && !quoted) single = !single;
            else if (character == '"' && !single) quoted = !quoted;
            else if (character == '#' && !single && !quoted) return true;
        }
        return false;
    }

    /// <summary>字典字面量所属的语义位置——决定光标在里面敲引号时该补哪一套字段。</summary>
    private enum HookRuleContext { None, Observe, Intercept, Mutation }

    /// <summary>
    /// 判断光标是否在一个未闭合的字典字面量里，并区分它属于 OBSERVE 规则、INTERCEPT 规则，
    /// 还是钩子函数的返回值（改写字典）。只在回看窗口内做括号配对，不真的解析 Python——
    /// 编辑器提示够用，且不会因为语法未写完就失效。
    /// </summary>
    private static HookRuleContext ResolveRuleContext(string before)
    {
        var depth = 0;
        var openIndex = -1;
        for (var index = before.Length - 1; index >= 0; index--)
        {
            var character = before[index];
            if (character == '}') depth++;
            else if (character == '{')
            {
                if (depth == 0) { openIndex = index; break; }
                depth--;
            }
        }
        if (openIndex < 0) return HookRuleContext.None;
        var head = before[..openIndex];
        // 谁离这个左花括号最近，就按谁解释：OBSERVE 规则表、INTERCEPT 规则表，还是函数返回值。
        var observeIndex = head.LastIndexOf("OBSERVE", StringComparison.Ordinal);
        var interceptIndex = head.LastIndexOf("INTERCEPT", StringComparison.Ordinal);
        var returnIndex = head.LastIndexOf("return", StringComparison.Ordinal);
        var nearest = Math.Max(observeIndex, Math.Max(interceptIndex, returnIndex));
        if (nearest < 0) return HookRuleContext.None; // 三个关键字都找不到，宁可不补全也不要猜错
        if (nearest == returnIndex) return HookRuleContext.Mutation;
        return nearest == observeIndex ? HookRuleContext.Observe : HookRuleContext.Intercept;
    }

    /// <summary>
    /// 按光标前的文本判定该补什么。明确的触发形态（event.get('、store.、字典字段…）优先，
    /// 其次才是按标识符前缀的模糊补全；自动触发时要求至少 2 个字符，手动唤出则一律给候选。
    /// </summary>
    private static (IReadOnlyList<HookScriptApi.Symbol> Items, string Prefix)? ResolveScriptCompletion(
        string before, ScriptPurpose purpose, bool auto)
    {
        var line = LastLineOf(before);
        if (auto && IsInsideComment(line)) return null;
        return purpose == ScriptPurpose.Fixture
            ? ResolveFixtureCompletion(before, line, auto)
            : ResolveHookCompletion(before, line, auto);
    }

    private static (IReadOnlyList<HookScriptApi.Symbol> Items, string Prefix)? ResolveHookCompletion(
        string before, string line, bool auto)
    {
        // event.get('xxx  /  event['xxx
        var eventMatch = ScriptEventFieldPattern().Match(line);
        if (eventMatch.Success) return (HookScriptApi.EventFields, eventMatch.Groups["p"].Value);
        // store.xxx
        var storeMatch = ScriptStoreMemberPattern().Match(line);
        if (storeMatch.Success) return (HookScriptApi.StoreMembers, storeMatch.Groups["p"].Value);
        // OBSERVE/INTERCEPT 规则里的 'event': 'xxx——按最近声明的是哪一个给出对应的挂载点候选
        // （OBSERVE 四个都能选，INTERCEPT 只有两个可改写的）。
        var eventNameMatch = ScriptRuleEventPattern().Match(line);
        if (eventNameMatch.Success)
        {
            var eventContext = ResolveRuleContext(before);
            return (eventContext == HookRuleContext.Observe ? HookScriptApi.ObserveEvents : HookScriptApi.InterceptEvents,
                eventNameMatch.Groups["p"].Value);
        }
        // 字典字面量里敲引号：按上下文补 OBSERVE 规则字段、INTERCEPT 规则字段，还是改写字段。
        var quoted = ScriptQuotedPrefixPattern().Match(line);
        if (quoted.Success)
        {
            var context = ResolveRuleContext(before);
            var fields = context switch
            {
                HookRuleContext.Observe => HookScriptApi.ObserveRuleFields,
                HookRuleContext.Intercept => HookScriptApi.InterceptRuleFields,
                HookRuleContext.Mutation => HookScriptApi.MutationFields,
                _ => (IReadOnlyList<HookScriptApi.Symbol>?)null
            };
            if (fields is not null) return (fields, quoted.Groups["p"].Value);
        }
        return ResolveVocabularyCompletion(line, HookScriptApi.HookVocabulary, auto);
    }

    private static (IReadOnlyList<HookScriptApi.Symbol> Items, string Prefix)? ResolveFixtureCompletion(
        string before, string line, bool auto)
    {
        _ = before;
        var memberMatch = ScriptMemberPattern().Match(line);
        if (memberMatch.Success)
        {
            var prefix = memberMatch.Groups["p"].Value;
            return memberMatch.Groups["base"].Value is "fixture"
                ? (HookScriptApi.FixtureVocabulary.Where(symbol => symbol.Name is "transactions").ToArray(), prefix)
                : (HookScriptApi.FixtureFields, prefix);
        }
        return ResolveVocabularyCompletion(line, HookScriptApi.FixtureVocabulary, auto);
    }

    private static (IReadOnlyList<HookScriptApi.Symbol> Items, string Prefix)? ResolveVocabularyCompletion(
        string line, IReadOnlyList<HookScriptApi.Symbol> vocabulary, bool auto)
    {
        var word = ScriptWordPrefixPattern().Match(line);
        if (word.Success)
        {
            var prefix = word.Groups["p"].Value;
            if (!auto || prefix.Length >= ScriptCompletionMinimumPrefix) return (vocabulary, prefix);
            return null;
        }
        // 手动唤出且光标不在标识符上：把整份词表摆出来，让用户直接挑。
        return auto ? null : (vocabulary, string.Empty);
    }

    private ScriptPurpose CurrentScriptPurpose =>
        _currentScript?.Purpose ?? (ScriptPurposeCombo?.SelectedIndex == 1 ? ScriptPurpose.Fixture : ScriptPurpose.Hook);

    private void UpdateScriptCompletion(bool auto)
    {
        if (ScriptEditor is null || ScriptCompletionPopup is null || ScriptCompletionList is null) return;
        var resolved = ResolveScriptCompletion(
            GetTextBeforeCaret(ScriptEditor, ScriptCompletionLookBehind), CurrentScriptPurpose, auto);
        if (resolved is null)
        {
            ScriptCompletionPopup.IsOpen = false;
            return;
        }
        var (items, prefix) = resolved.Value;
        var filtered = items.Where(symbol => symbol.Name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)).ToArray();
        // 只剩一个候选且已经完整键入，再弹就是纯干扰。
        if (filtered.Length == 0 ||
            (auto && filtered.Length == 1 && filtered[0].Name.Equals(prefix, StringComparison.OrdinalIgnoreCase)))
        {
            ScriptCompletionPopup.IsOpen = false;
            return;
        }
        _scriptCompletionPrefixLength = prefix.Length;
        ScriptCompletionList.ItemsSource = filtered;
        ScriptCompletionList.SelectedIndex = 0;
        var caretRect = ScriptEditor.CaretPosition.GetCharacterRect(LogicalDirection.Forward);
        ScriptCompletionPopup.HorizontalOffset = caretRect.Left;
        ScriptCompletionPopup.VerticalOffset = caretRect.Bottom + 2;
        ScriptCompletionPopup.IsOpen = true;
    }

    private void 脚本编辑器_按键(object sender, KeyEventArgs e)
    {
        if (ScriptCompletionPopup is null || ScriptCompletionList is null) return;
        // Alt 组合键到达时 Key 是 System，真实按键在 SystemKey。
        var key = e.Key == Key.System ? e.SystemKey : e.Key;
        // 手动唤出提供三个组合键：中文输入法把 Ctrl+空格 用作中英文切换，那个组合根本到不了应用，
        // 所以 Ctrl+J 才是这里真正可靠的入口，Alt+/ 作为习惯 VS 的用户的备选。
        var control = (Keyboard.Modifiers & ModifierKeys.Control) == ModifierKeys.Control;
        var alt = (Keyboard.Modifiers & ModifierKeys.Alt) == ModifierKeys.Alt;
        var shift = (Keyboard.Modifiers & ModifierKeys.Shift) == ModifierKeys.Shift;
        if ((control && key is Key.J or Key.Space) || (alt && key is Key.Oem2 or Key.Divide))
        {
            UpdateScriptCompletion(auto: false);
            e.Handled = true;
            return;
        }
        if (control && key == Key.S)
        {
            ScriptCompletionPopup.IsOpen = false;
            保存脚本_Click(sender, e);
            e.Handled = true;
            return;
        }
        // Ctrl+/ 切换注释。斜杠在主键盘区是 Oem2、小键盘是 Divide，两个都收。
        if (control && !shift && key is Key.Oem2 or Key.Divide)
        {
            ToggleSelectedLinesComment();
            e.Handled = true;
            return;
        }
        if (control && key is Key.OemOpenBrackets)
        {
            if (shift) CollapseAllFolds(); else FoldAtCaret();
            e.Handled = true;
            return;
        }
        if (control && shift && key is Key.OemCloseBrackets)
        {
            ExpandAllFolds();
            e.Handled = true;
            return;
        }
        if (!ScriptCompletionPopup.IsOpen) return;
        switch (key)
        {
            case Key.Escape:
                ScriptCompletionPopup.IsOpen = false;
                e.Handled = true;
                break;
            case Key.Down:
                ScriptCompletionList.SelectedIndex = Math.Min(ScriptCompletionList.SelectedIndex + 1, ScriptCompletionList.Items.Count - 1);
                ScriptCompletionList.ScrollIntoView(ScriptCompletionList.SelectedItem);
                e.Handled = true;
                break;
            case Key.Up:
                ScriptCompletionList.SelectedIndex = Math.Max(ScriptCompletionList.SelectedIndex - 1, 0);
                ScriptCompletionList.ScrollIntoView(ScriptCompletionList.SelectedItem);
                e.Handled = true;
                break;
            case Key.Enter:
            case Key.Tab:
                CommitScriptCompletion();
                e.Handled = true;
                break;
            case Key.Left:
            case Key.Right:
            case Key.Home:
            case Key.End:
                // 光标离开了刚才那个词，候选已经失效。
                ScriptCompletionPopup.IsOpen = false;
                break;
        }
    }

    private void 脚本补全_点击(object sender, MouseButtonEventArgs e)
    {
        CommitScriptCompletion();
        ScriptEditor?.Focus();
    }

    private void 脚本编辑器_失焦(object sender, KeyboardFocusChangedEventArgs e)
    {
        if (ScriptCompletionPopup is null) return;
        // 点补全列表时焦点可能短暂落进弹层，那不算离开编辑器，否则会在 MouseUp 前就把列表关掉。
        if (e.NewFocus is DependencyObject target && ScriptCompletionPopup.Child is DependencyObject popupRoot &&
            IsVisualDescendant(target, popupRoot)) return;
        ScriptCompletionPopup.IsOpen = false;
    }

    // ==================== 编辑器：注释切换 / 整理格式 / 代码折叠 ====================
    //
    // 折叠模型：把被折叠的行从文档里摘掉，原地留一个占位段落，隐藏文本挂在 _folds 上。
    // GetEditorText 遍历 Blocks 时遇到占位段落就还原隐藏文本，因此「折叠状态下保存」
    // 拿到的仍是完整脚本——这是这套实现唯一不能出错的地方。
    // 用户若直接删掉占位段落，等于删掉整个折叠块，语义合理，不需要额外兜底。

    private sealed class FoldedRegion
    {
        public required Paragraph Placeholder { get; init; }
        public required string HiddenText { get; init; }
    }

    private readonly List<FoldedRegion> _folds = [];

    /// <summary>光标所在行在整篇文本中的行号（0 起）。</summary>
    private static int GetCaretLineIndex(RichTextBox editor)
    {
        var caret = editor.CaretPosition;
        var text = new TextRange(editor.Document.ContentStart, caret).Text;
        return text.Count(character => character == '\n');
    }

    /// <summary>
    /// 切换选中行的注释。
    ///
    /// 只改动涉及的那几个段落，不重建整篇文档——整体替换会让滚动条跳回顶部、
    /// 丢掉撤销粒度，也会把着色重来一遍。改完只对这几行重新着色。
    /// </summary>
    private void ToggleSelectedLinesComment()
    {
        if (ScriptEditor is null) return;
        var paragraphs = ScriptEditor.Document.Blocks.OfType<Paragraph>().ToArray();
        if (paragraphs.Length == 0) return;
        var selection = ScriptEditor.Selection;
        var startLine = new TextRange(ScriptEditor.Document.ContentStart, selection.Start).Text.Count(c => c == '\n');
        var endLine = new TextRange(ScriptEditor.Document.ContentStart, selection.End).Text.Count(c => c == '\n');
        startLine = Math.Clamp(startLine, 0, paragraphs.Length - 1);
        endLine = Math.Clamp(endLine, startLine, paragraphs.Length - 1);

        // 折叠占位段落不是真代码，落在选区里就先展开，避免把占位文字也注释掉。
        if (_folds.Count > 0 &&
            paragraphs[startLine..(endLine + 1)].Any(item => _folds.Any(fold => ReferenceEquals(fold.Placeholder, item))))
        {
            ExpandAllFolds();
            paragraphs = ScriptEditor.Document.Blocks.OfType<Paragraph>().ToArray();
            endLine = Math.Clamp(endLine, startLine, paragraphs.Length - 1);
        }

        var target = paragraphs[startLine..(endLine + 1)];
        var original = string.Join('\n', target.Select(ParagraphText));
        var toggled = ScriptTextTools.ToggleComment(original, 0, target.Length - 1);
        if (string.Equals(toggled, original, StringComparison.Ordinal)) return;
        var lines = toggled.Split('\n');
        if (lines.Length != target.Length) return; // 行数必须一一对应，否则宁可不动

        _highlightingScript = true;
        try
        {
            for (var index = 0; index < target.Length; index++)
                new TextRange(target[index].ContentStart, target[index].ContentEnd).Text = lines[index];
        }
        finally { _highlightingScript = false; }
        foreach (var paragraph in target) HighlightParagraph(paragraph);
        MarkScriptDirty();
    }

    private static string ParagraphText(Paragraph paragraph) =>
        new TextRange(paragraph.ContentStart, paragraph.ContentEnd).Text;

    private void 切换注释_Click(object sender, RoutedEventArgs e) => ToggleSelectedLinesComment();

    private void 唤出补全_Click(object sender, RoutedEventArgs e)
    {
        ScriptEditor?.Focus();
        UpdateScriptCompletion(auto: false);
    }

    private void 整理格式_Click(object sender, RoutedEventArgs e)
    {
        if (ScriptEditor is null) return;
        var line = GetCaretLineIndex(ScriptEditor);
        var text = GetScriptText();
        var formatted = ScriptTextTools.Format(text);
        if (string.Equals(formatted, text, StringComparison.Ordinal))
        {
            UpdateHookStatusLine("格式已经是整理过的，没有需要改动的地方。");
            return;
        }
        ReplaceScriptTextPreservingLine(formatted, line);
        UpdateHookStatusLine("已整理格式：行首制表符转空格、去行尾空白、压缩连续空行；三引号字符串内部未改动。");
    }

    /// <summary>整体替换编辑器内容并把光标放回指定行；折叠状态一并作废（文本已经变了）。</summary>
    private void ReplaceScriptTextPreservingLine(string text, int line)
    {
        _folds.Clear();
        SetScriptText(text);
        ApplyPythonSyntaxHighlighting();
        MarkScriptDirty();
        var target = ScriptEditor.Document.ContentStart;
        for (var index = 0; index < line; index++)
            target = target.GetLineStartPosition(1) ?? target;
        ScriptEditor.CaretPosition = target;
        ScriptEditor.Focus();
    }

    private void 折叠当前_Click(object sender, RoutedEventArgs e) => FoldAtCaret();

    private void 折叠全部_Click(object sender, RoutedEventArgs e) => CollapseAllFolds();

    private void 展开全部_Click(object sender, RoutedEventArgs e) => ExpandAllFolds();

    /// <summary>单击占位段落即展开——折叠后最自然的还原动作就是点它一下。</summary>
    private void 脚本编辑器_鼠标按下(object sender, MouseButtonEventArgs e)
    {
        if (_folds.Count == 0 || ScriptEditor is null) return;
        var position = ScriptEditor.GetPositionFromPoint(e.GetPosition(ScriptEditor), snapToText: false);
        if (position?.Paragraph is not { } paragraph) return;
        var fold = _folds.FirstOrDefault(item => ReferenceEquals(item.Placeholder, paragraph));
        if (fold is null) return;
        ExpandFold(fold);
        e.Handled = true;
    }

    private void FoldAtCaret()
    {
        if (ScriptEditor is null) return;
        var region = ScriptTextTools.FindFoldRegionAt(GetScriptText(), GetCaretLineIndex(ScriptEditor));
        if (region is null)
        {
            UpdateHookStatusLine("光标所在位置没有可折叠的代码块（需要以冒号结尾的行加至少一行缩进体）。");
            return;
        }
        ApplyFolds([region.Value]);
    }

    private void CollapseAllFolds()
    {
        if (ScriptEditor is null) return;
        var regions = ScriptTextTools.FindFoldRegions(GetScriptText());
        // 只折最外层：嵌套区域会互相包含，逐层折叠没有意义也不好还原。
        var outermost = regions.Where(region => !regions.Any(other =>
            !other.Equals(region) && other.Header < region.Header && other.End >= region.End)).ToArray();
        if (outermost.Length == 0)
        {
            UpdateHookStatusLine("当前脚本没有可折叠的代码块。");
            return;
        }
        ApplyFolds(outermost);
    }

    /// <summary>
    /// 按区域重建文档：先取全文，再按「保留行 / 折叠占位」逐段写回。
    /// 一次性重建比在文档上做增量删除简单得多，也不会留下悬空的 TextPointer。
    /// </summary>
    private void ApplyFolds(IReadOnlyList<ScriptTextTools.FoldRegion> regions)
    {
        var lines = GetScriptText().Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');
        var ordered = regions.OrderBy(region => region.Header).ToArray();
        var document = ScriptEditor.Document;
        _highlightingScript = true;
        try
        {
            _folds.Clear();
            document.Blocks.Clear();
            var index = 0;
            var next = 0;
            while (index < lines.Length)
            {
                if (next < ordered.Length && index == ordered[next].Header)
                {
                    var region = ordered[next++];
                    document.Blocks.Add(NewLineParagraph(lines[region.Header]));
                    var hidden = string.Join('\n', lines.Skip(region.Header + 1).Take(region.End - region.Header));
                    var placeholder = NewLineParagraph(
                        new string(' ', LeadingSpaces(lines[region.Header]) + ScriptTextTools.IndentSpaces) +
                        $"⋯ 已折叠 {region.HiddenLineCount} 行（单击展开）");
                    placeholder.Foreground = Muted;
                    document.Blocks.Add(placeholder);
                    _folds.Add(new FoldedRegion { Placeholder = placeholder, HiddenText = hidden });
                    index = region.End + 1;
                    continue;
                }
                document.Blocks.Add(NewLineParagraph(lines[index]));
                index++;
            }
        }
        finally { _highlightingScript = false; }
        ApplyPythonSyntaxHighlighting();
        UpdateHookStatusLine($"已折叠 {_folds.Count} 个代码块；单击折叠行或按 Ctrl+Shift+] 展开全部。保存与运行读取的始终是完整脚本。");
    }

    private void ExpandAllFolds()
    {
        if (_folds.Count == 0) return;
        foreach (var fold in _folds.ToArray()) ExpandFold(fold);
        UpdateHookStatusLine("已展开全部折叠块。");
    }

    private void ExpandFold(FoldedRegion fold)
    {
        var document = ScriptEditor.Document;
        _highlightingScript = true;
        try
        {
            _folds.Remove(fold);
            Block anchor = fold.Placeholder;
            foreach (var line in fold.HiddenText.Split('\n'))
            {
                var paragraph = NewLineParagraph(line);
                document.Blocks.InsertAfter(anchor, paragraph);
                anchor = paragraph;
            }
            document.Blocks.Remove(fold.Placeholder);
        }
        finally { _highlightingScript = false; }
        ApplyPythonSyntaxHighlighting();
    }

    private static Paragraph NewLineParagraph(string text) =>
        new(new Run(text)) { Margin = new Thickness(0) };

    private static int LeadingSpaces(string line) => line.Length - line.TrimStart().Length;

    // ==================== 让 AI 写脚本 ====================

    /// <summary>
    /// 当前脚本代写会话的消息历史（含系统提示词）。保留它是为了支持追问式修改——
    /// 第一次生成的往往不满意，用户需要接着说「再加个 xxx」而不是每次从零描述一遍。
    /// 只在内存里，不落盘、不进 AI 分析历史：这是脚本编辑器的辅助功能，不是取证会话。
    /// </summary>
    private List<AiChatMessage>? _scriptAiMessages;
    private ScriptPurpose? _scriptAiPurpose;

    private void AI写脚本_按键(object sender, KeyEventArgs e)
    {
        if (e.Key != Key.Enter) return;
        e.Handled = true;
        AI写脚本_Click(sender, e);
    }

    /// <summary>切换脚本或改变用途时旧对话的上下文就不再适用（面向的是另一个文件/另一套契约），清空重开。</summary>
    private void ResetScriptAiConversation()
    {
        _scriptAiMessages = null;
        _scriptAiPurpose = null;
        if (AiScriptTurnText is not null) AiScriptTurnText.Text = string.Empty;
    }

    private void 清空脚本AI对话_Click(object sender, RoutedEventArgs e)
    {
        ResetScriptAiConversation();
        WriteRunOutput("已清空对话，下一次生成会重新开始。", Muted, "对话已清空");
    }

    /// <summary>
    /// 把需求发给模型，回复里的代码块写进编辑器；同一个脚本、同一种用途下的后续追问
    /// 会带着此前的对话历史一起发送，模型因此知道「上一版写的是什么、你现在想改什么」。
    /// 不带工具调用，也不进 AI 分析会话历史：这是脚本编辑器内的辅助功能。
    /// </summary>
    private async void AI写脚本_Click(object sender, RoutedEventArgs e)
    {
        if (AiWriteScriptButton is null || AiScriptRequestBox is null) return;
        var request = AiScriptRequestBox.Text?.Trim() ?? string.Empty;
        if (request.Length == 0)
        {
            UpdateHookStatusLine("请先描述你要的脚本，例如「拦截登录请求并删掉签名头」。", isError: true);
            return;
        }
        AiWriteScriptButton.IsEnabled = false;
        var purpose = CurrentScriptPurpose;
        try
        {
            // 用途变了（钩子 ⇄ 验证）说明这是另一套契约，旧对话继续发送只会误导模型。
            if (_scriptAiMessages is null || _scriptAiPurpose != purpose)
            {
                _scriptAiMessages = [new("system", HookScriptApi.BuildAuthoringSystemPrompt(purpose))];
                _scriptAiPurpose = purpose;
            }
            var isFollowUp = _scriptAiMessages.Count > 1;

            var settings = await new AiGatewaySettingsStore(_aiSettingsPath).LoadAsync();
            var enteredKey = AiApiKeyBox.Password;
            var apiKey = string.IsNullOrWhiteSpace(enteredKey) ? WindowsCredentialStore.ReadApiKey() : enteredKey;
            WriteRunOutput(
                $"正在请求模型{(isFollowUp ? "按你的追问修改" : "生成")}{(purpose == ScriptPurpose.Hook ? "钩子" : "验证")}脚本…",
                Accent, "生成中");

            // 每一轮都带上编辑器当前内容：用户可能在两轮之间手动改过，模型必须以实际文件为准，
            // 而不是自己上一轮回复的记忆（两者一旦分叉，继续对着记忆改只会越改越错）。
            var current = GetScriptText();
            var userPrompt = new StringBuilder(request);
            if (!string.IsNullOrWhiteSpace(current))
            {
                userPrompt.Append("\n\n当前编辑器里的脚本如下，请在它基础上按需求修改：\n```python\n")
                          .Append(current.Length > 6000 ? current[..6000] + "\n# …（已截断）" : current)
                          .Append("\n```");
            }
            _scriptAiMessages.Add(new AiChatMessage("user", userPrompt.ToString()));

            using var gateway = new AiGatewayClient();
            // 关掉扩展思考：这是代码生成，思考令牌会吃掉绝大部分输出预算却毫无用处
            // （开着时生成 30 行脚本花了 13,000 输出令牌）。
            var result = await gateway.AnalyzeConversationAsync(settings, apiKey, _scriptAiMessages, [],
                enableReasoning: false);
            var code = HookScriptApi.ExtractPythonCode(result.Text);
            if (code.Length == 0) throw new InvalidDataException("模型没有返回可用的 Python 代码块。");
            // 助手回复原样存进历史（不是改写后的 code 变量）：模型下一轮看到的必须是它自己真实说过的话。
            _scriptAiMessages.Add(new AiChatMessage("assistant", result.Text));

            // 静态策略先过一遍：与其让用户点了运行才看到「策略拒绝」，不如当场说清楚。
            var violations = PythonSandboxPolicy.Validate(code);
            SetScriptText(code);
            ApplyPythonSyntaxHighlighting();
            _folds.Clear();
            MarkScriptDirty();
            AiScriptRequestBox.Clear();
            var turnIndex = (_scriptAiMessages.Count - 1) / 2; // 每轮 user+assistant 两条
            if (AiScriptTurnText is not null)
                AiScriptTurnText.Text = $"第 {turnIndex} 轮 · 不满意可以继续在上面描述怎么改";
            var summary = $"已生成并写入编辑器（{code.Split('\n').Length} 行）。检查无误后按 Ctrl+S 保存。\n" +
                          $"输入 {result.InputTokens} 令牌 · 输出 {result.OutputTokens} 令牌";
            // 输出令牌远大于代码量时，多半是模型仍在思考。把思考文本长度摆出来，免得只能靠猜。
            if (result.ReasoningText.Length > 0)
                summary += $"（其中思考 {result.ReasoningText.Length} 字符，本次请求已要求关闭思考）";
            if (violations.Count > 0)
                WriteRunOutput(summary + "\n\n注意：生成的脚本未通过静态策略，运行前需要修改：\n" +
                    string.Join("\n", violations.Select(item => "• " + item)), Amber, "需修改");
            else
                WriteRunOutput(summary, Green, "已生成");
        }
        catch (Exception exception)
        {
            // 失败的这一轮不该留在历史里干扰下一次重试：撤掉刚才追加的 user 消息（assistant 消息在失败时还没加入）。
            if (_scriptAiMessages is { Count: > 0 } && _scriptAiMessages[^1].Role == "user")
                _scriptAiMessages.RemoveAt(_scriptAiMessages.Count - 1);
            WriteRunOutput("AI 生成脚本失败\n\n" + exception.Message, Red, "生成失败");
        }
        finally
        {
            AiWriteScriptButton.IsEnabled = true;
        }
    }

    private static bool IsVisualDescendant(DependencyObject candidate, DependencyObject ancestor)
    {
        for (var current = candidate; current is not null; current = VisualTreeHelper.GetParent(current))
        {
            if (ReferenceEquals(current, ancestor)) return true;
        }
        return false;
    }

    /// <summary>把选中项插入编辑器：先删掉已经键入的前缀，避免出现 "meth" + "method" 这种重复。</summary>
    private void CommitScriptCompletion()
    {
        if (ScriptEditor is null || ScriptCompletionPopup is null ||
            ScriptCompletionList?.SelectedItem is not HookScriptApi.Symbol symbol) return;
        ScriptCompletionPopup.IsOpen = false;
        var caret = ScriptEditor.CaretPosition;
        if (_scriptCompletionPrefixLength > 0)
        {
            var start = caret.GetPositionAtOffset(-_scriptCompletionPrefixLength, LogicalDirection.Backward);
            if (start is not null) new TextRange(start, caret).Text = string.Empty;
        }
        // 插入文本可能含换行（钩子函数骨架）；RichTextBox 会自行拆段，无需额外处理。
        ScriptEditor.CaretPosition.InsertTextInRun(symbol.Insert);
        ScriptEditor.CaretPosition = ScriptEditor.CaretPosition.GetPositionAtOffset(symbol.Insert.Length) ?? ScriptEditor.CaretPosition;
        RequestScriptHighlight(ScriptEditor);
    }

    [GeneratedRegex(@"event(?:\.get\(|\[)\s*['""](?<p>[A-Za-z0-9_]*)$", RegexOptions.CultureInvariant)]
    private static partial Regex ScriptEventFieldPattern();

    [GeneratedRegex(@"\bstore\.(?<p>[A-Za-z0-9_]*)$", RegexOptions.CultureInvariant)]
    private static partial Regex ScriptStoreMemberPattern();

    [GeneratedRegex(@"['""]event['""]\s*:\s*['""](?<p>[A-Za-z0-9_.]*)$", RegexOptions.CultureInvariant)]
    private static partial Regex ScriptRuleEventPattern();

    [GeneratedRegex(@"['""](?<p>[A-Za-z0-9_]*)$", RegexOptions.CultureInvariant)]
    private static partial Regex ScriptQuotedPrefixPattern();

    [GeneratedRegex(@"\b(?<base>[A-Za-z_][A-Za-z0-9_]*)\.(?<p>[A-Za-z0-9_]*)$", RegexOptions.CultureInvariant)]
    private static partial Regex ScriptMemberPattern();

    [GeneratedRegex(@"(?<![\w.'""])(?<p>[A-Za-z_][A-Za-z0-9_]*)$", RegexOptions.CultureInvariant)]
    private static partial Regex ScriptWordPrefixPattern();

    private void RequestScriptHighlight(RichTextBox editor)
    {
        _pendingHighlightEditor = editor;
        _scriptHighlightTimer.Stop();
        _scriptHighlightTimer.Start();
    }

    private void SetScriptText(string text) => SetEditorText(ScriptEditor, text);

    private void SetEditorText(RichTextBox editor, string text)
    {
        _highlightingScript = true;
        try
        {
            _folds.Clear(); // 整体替换内容后旧的折叠占位段落已不存在
            var range = new TextRange(editor.Document.ContentStart, editor.Document.ContentEnd);
            range.Text = text.Replace("\r\n", "\n", StringComparison.Ordinal);
        }
        finally
        {
            _highlightingScript = false;
        }
    }

    /// <summary>
    /// 取编辑器中的完整脚本。存在折叠时逐段还原：占位段落输出它藏起来的原文，
    /// 因此「折叠着保存/运行」拿到的与展开时完全一致——折叠只是视图状态。
    /// </summary>
    private string GetScriptText()
    {
        if (_folds.Count == 0) return GetEditorText(ScriptEditor);
        var builder = new StringBuilder();
        foreach (var block in ScriptEditor.Document.Blocks)
        {
            if (block is not Paragraph paragraph) continue;
            var fold = _folds.FirstOrDefault(item => ReferenceEquals(item.Placeholder, paragraph));
            builder.Append(fold?.HiddenText ?? new TextRange(paragraph.ContentStart, paragraph.ContentEnd).Text).Append('\n');
        }
        return builder.ToString().TrimEnd('\r', '\n');
    }

    private static string GetEditorText(RichTextBox editor) => new TextRange(editor.Document.ContentStart, editor.Document.ContentEnd)
        .Text.TrimEnd('\r', '\n');

    private void ApplyPythonSyntaxHighlighting() => ApplyPythonSyntaxHighlighting(ScriptEditor);

    private void ApplyPythonSyntaxHighlighting(RichTextBox editor)
    {
        if (_highlightingScript || editor is null) return;
        _highlightingScript = true;
        try { HighlightRange(editor.Document.ContentStart, editor.Document.ContentEnd); }
        finally { _highlightingScript = false; }
    }

    /// <summary>只给一个段落重新着色。改动局限在几行时不必整篇重来（整篇重来会让滚动位置和撤销栈受牵连）。</summary>
    private void HighlightParagraph(Paragraph paragraph)
    {
        if (_highlightingScript) return;
        _highlightingScript = true;
        try { HighlightRange(paragraph.ContentStart, paragraph.ContentEnd); }
        finally { _highlightingScript = false; }
    }

    private void HighlightRange(TextPointer start, TextPointer end)
    {
        var range = new TextRange(start, end);
        var text = range.Text;
        range.ApplyPropertyValue(TextElement.ForegroundProperty, FindResource("TextBrush"));
        range.ApplyPropertyValue(TextElement.FontWeightProperty, FontWeights.Normal);
        ApplyPythonMatches(start, end, text, PythonKeywordPattern, PythonKeyword, FontWeights.SemiBold);
        ApplyPythonMatches(start, end, text, PythonBuiltinPattern, PythonBuiltin, FontWeights.SemiBold);
        ApplyPythonMatches(start, end, text, PythonNumberPattern, PythonNumber, FontWeights.Normal);
        ApplyPythonMatches(start, end, text, PythonStringPattern, PythonString, FontWeights.Normal);
        ApplyPythonMatches(start, end, text, PythonCommentPattern, PythonComment, FontWeights.Normal);
    }

    private static void ApplyPythonMatches(TextPointer start, TextPointer end, string text, Regex pattern,
        Brush foreground, FontWeight weight)
    {
        var matches = pattern.Matches(text).Cast<Match>()
            .Where(match => match.Length > 0)
            .ToArray();
        if (matches.Length == 0) return;
        var pointers = GetTextPointersAtCharacterOffsets(start, end,
            matches.SelectMany(match => new[] { match.Index, match.Index + match.Length }));
        foreach (var match in matches)
        {
            if (!pointers.TryGetValue(match.Index, out var matchStart) ||
                !pointers.TryGetValue(match.Index + match.Length, out var matchEnd) ||
                matchStart.CompareTo(matchEnd) >= 0) continue;
            var range = new TextRange(matchStart, matchEnd);
            range.ApplyPropertyValue(TextElement.ForegroundProperty, foreground);
            range.ApplyPropertyValue(TextElement.FontWeightProperty, weight);
        }
    }

    /// <summary>
    /// 单次顺序扫描把全部字符偏移映射到 TextPointer。旧实现为每个正则命中都从文档开头重扫，
    /// 代码越长、命中越多越接近 O(n²)；这里每类 token 只遍历文档一次。
    /// </summary>
    private static IReadOnlyDictionary<int, TextPointer> GetTextPointersAtCharacterOffsets(
        TextPointer start, TextPointer end, IEnumerable<int> targetOffsets)
    {
        var targets = targetOffsets.Where(offset => offset >= 0).Distinct().Order().ToArray();
        var result = new Dictionary<int, TextPointer>(targets.Length);
        if (targets.Length == 0) return result;
        var navigator = start;
        var consumed = 0;
        var targetIndex = 0;
        while (targetIndex < targets.Length && targets[targetIndex] == 0)
            result[targets[targetIndex++]] = navigator;

        while (targetIndex < targets.Length && navigator.CompareTo(end) < 0)
        {
            var next = navigator.GetNextContextPosition(LogicalDirection.Forward);
            if (next is null) break;
            var segment = new TextRange(navigator, next).Text;
            if (segment.Length > 0)
            {
                while (targetIndex < targets.Length && targets[targetIndex] <= consumed + segment.Length)
                {
                    var target = targets[targetIndex++];
                    result[target] = navigator.GetPointerContext(LogicalDirection.Forward) == TextPointerContext.Text
                        ? navigator.GetPositionAtOffset(target - consumed, LogicalDirection.Forward) ?? next
                        : next;
                }
                consumed += segment.Length;
            }
            navigator = next;
        }
        while (targetIndex < targets.Length) result[targets[targetIndex++]] = end;
        return result;
    }

    // ==================== 脚本页 ====================
    // 这一页只有一个编辑器：左侧脚本库决定编辑哪个文件，顶部「保存」是唯一的写入口，
    // 顶部「运行」按脚本用途分派（钩子脚本隔离试跑 / 验证脚本沙箱执行）。

    /// <summary>新建验证脚本时的默认文件名。</summary>
    private const string DefaultFixtureScriptFileName = "check.py";

    private const string HookScriptGuideTextContent =
        "① 挂载点：定义 on_before_send / on_after_send / on_before_write / on_after_deliver，采集期间由隔离工作进程调用。\n" +
        "② 默认拒绝转发：定义了函数不代表会被调用，必须声明 OBSERVE 或 INTERCEPT 且命中，宿主才会转发事件；\n" +
        "    未声明的挂载点、未命中的流量，函数体永远不执行——不报错，只是安静地没反应。\n" +
        "③ 观察：OBSERVE = [{'event': ..., 'url': r'...'}]，四个挂载点都可声明，不阻塞，规则形状与 INTERCEPT 相同\n" +
        "    （url/method/host/endpoint/body/status/headers 全是正则，条件之间是 AND）。不写任何条件等于要这个挂载点的全部流量。\n" +
        "④ 拦截改写：模块级写 INTERCEPT = [{'event': ..., 'url': r'...'}]，只能声明在 request.before_send 与\n" +
        "    response.before_write 两点，命中规则的请求才阻塞等待裁决；命中时返回\n" +
        "    {'url'/'method'/'status'/'headers'/'body'/'finding'} 即改写并向下传播，返回 None 原样放行，\n" +
        "    裁决超时、脚本异常或改写超限一律放行。OBSERVE 与 INTERCEPT 相互独立，可以同时用，也可以只用一个。\n" +
        "⑤ 入参：event 是 dict，字段有 event、txnId、sessionId、hookName、method、url、host、endpoint、statusCode、\n" +
        "    headers、bodyPreviewBase64、bodyTruncated、bodySha256、bodySize、schema。\n" +
        "    正文预览默认不下发（省掉绝大部分事件数据量）：脚本里出现 bodyPreviewBase64 或写 WANT_BODY = True 才带上。\n" +
        "⑥ 存储：store.save('名称', 值) / store.load('名称') / store.list() / store.delete('名称')，落盘在工作区 scripts/data。\n" +
        "⑦ 结论：返回 None 不写审计；返回 dict 形成一条 hooks.finding，可用 txnId 精确关联流量事务。";

    private static readonly ScriptSample[] HookScriptSamples =
    [
        new("记录首次出现的 API 端点（只观察）",
            "# 钩子示例一：跨请求维护端点清单，只在首次出现时形成结论。\n" +
            "# 只观察不改写，代理不会等待脚本，采集吞吐不受影响。\n" +
            "# OBSERVE 没写 url/host 条件：故意要这个挂载点的全部流量，用来梳理站点访问了哪些接口；\n" +
            "# 只想看某个域名/接口时，照下面注释的样子加一条正则即可收窄范围。\n\n" +
            "OBSERVE = [\n" +
            "    {'event': 'request.before_send'},\n" +
            "    # {'event': 'request.before_send', 'host': r'api\\.example\\.com$'},\n" +
            "]\n\n" +
            "def on_before_send(event):\n" +
            "    key = str(event.get('method') or '') + ' ' + str(event.get('endpoint') or '')\n" +
            "    known = store.load('api-endpoints.txt') or ''\n" +
            "    if ('\\n' + key + '\\n') in ('\\n' + known):\n" +
            "        return None\n" +
            "    store.save('api-endpoints.txt', known + key + '\\n')\n" +
            "    return {'kind': 'api.endpoint.discovered', 'method': event.get('method'), 'url': event.get('url')}"),
        new("把错误响应升级为结论（只观察）",
            "# 钩子示例二：只把 4xx/5xx 响应记成结论，正常响应直接返回 None。\n" +
            "# txnId 与流量事务一一对应，可在流量探索里回溯到原始证据。\n" +
            "# 下面按挂载点全量转发、在函数体内判断状态码；也可以直接用 OBSERVE 的 status 正则\n" +
            "# 在宿主侧先收窄，见注释——两种写法效果一样，后者能省掉不需要的事件序列化开销。\n\n" +
            "OBSERVE = [\n" +
            "    {'event': 'response.before_write'},\n" +
            "    # {'event': 'response.before_write', 'status': r'^[45]\\d\\d$'},\n" +
            "]\n\n" +
            "def on_before_write(event):\n" +
            "    status = event.get('statusCode') or 0\n" +
            "    if status < 400:\n" +
            "        return None\n" +
            "    return {\n" +
            "        'kind': 'api.response.error', 'status': status, 'url': event.get('url'),\n" +
            "        'bodySize': event.get('bodySize'), 'bodySha256': event.get('bodySha256')\n" +
            "    }"),
        new("拦截改写：删掉签名头再发出去",
            "# 钩子示例三：验证服务端是否真的校验签名头。\n" +
            "# 只有命中 INTERCEPT 规则的请求才阻塞等待裁决，其余流量仍是即发即忘。\n" +
            "# 规则条件全是正则，条件之间是 AND。\n\n" +
            "INTERCEPT = [\n" +
            "    {'event': 'request.before_send', 'url': r'/v\\d+/', 'method': r'^(POST|PUT)$'},\n" +
            "]\n\n" +
            "def on_before_send(event):\n" +
            "    headers = event.get('headers') or {}\n" +
            "    names = [name for name in headers if name.lower() in ('x-sign', 'x-signature')]\n" +
            "    if not names:\n" +
            "        return None\n" +
            "    # 值为 None 表示删除该头；宿主会按实际长度重算 Content-Length。\n" +
            "    return {\n" +
            "        'headers': {name: None for name in names},\n" +
            "        'finding': {'kind': 'probe.sign-removed', 'removed': names},\n" +
            "    }"),
        new("拦截改写：替换响应正文与状态码",
            "# 钩子示例四：把某个接口的响应换成构造数据，观察前端如何处理。\n" +
            "# 落库记录的是实际上线的字节，改写前的原始内容一并保留，证据链不会因为改写而失真。\n\n" +
            "INTERCEPT = [\n" +
            "    {'event': 'response.before_write', 'endpoint': r'/user/profile', 'status': r'^200$'},\n" +
            "]\n\n" +
            "def on_before_write(event):\n" +
            "    return {\n" +
            "        'status': 200,\n" +
            "        'headers': {'Content-Type': 'application/json; charset=utf-8'},\n" +
            "        'body': '{\"role\":\"admin\",\"vip\":true}',\n" +
            "        'finding': {'kind': 'probe.response-replaced', 'url': event.get('url')},\n" +
            "    }"),
        new("按响应头匹配并落盘取证",
            "# 钩子示例五：按响应头正则匹配（值为空串表示只要求该头存在），把命中的 URL 落盘。\n\n" +
            "INTERCEPT = [\n" +
            "    {'event': 'response.before_write', 'headers': {'Set-Cookie': r'HttpOnly'}},\n" +
            "]\n\n" +
            "def on_before_write(event):\n" +
            "    seen = store.load('httponly-cookies.txt') or ''\n" +
            "    store.save('httponly-cookies.txt', seen + str(event.get('url')) + '\\n')\n" +
            "    # 返回 None：不改写，只留下一条可回溯的记录。\n" +
            "    return None")
    ];

    private void 脚本指南_Click(object sender, RoutedEventArgs e)
    {
        if (ScriptGuidePanel.Visibility == Visibility.Visible)
        {
            ScriptGuidePanel.Visibility = Visibility.Collapsed;
            return;
        }
        var hook = CurrentScriptPurpose == ScriptPurpose.Hook;
        ScriptGuideTitle.Text = hook ? "脚本指南 · 钩子 API 速查" : "脚本指南 · 验证 API 速查";
        ScriptGuideText.Text = hook ? HookScriptGuideTextContent : ScriptGuideTextContent;
        ScriptGuidePanel.Visibility = Visibility.Visible;
    }

    /// <summary>
    /// 在按钮下方弹出菜单。每次都重建并重新挂上：旧实现在菜单已存在时直接 return，
    /// 用户点开菜单又点别处关掉后按钮就再也没反应了。
    /// </summary>
    private void ShowDropDownMenu(Button anchor, IEnumerable<MenuItem> items)
    {
        var menu = new ContextMenu
        {
            Style = (Style)FindResource("TrafficContextMenuStyle"),
            PlacementTarget = anchor,
            Placement = System.Windows.Controls.Primitives.PlacementMode.Bottom
        };
        foreach (var item in items) menu.Items.Add(item);
        anchor.ContextMenu = menu;
        menu.IsOpen = true;
    }

    private MenuItem CreateDropDownItem(string header, object tag, RoutedEventHandler handler)
    {
        var item = new MenuItem { Header = header, Style = (Style)FindResource("TrafficMenuItemStyle"), Tag = tag };
        item.Click += handler;
        return item;
    }

    private void 插入示例_Click(object sender, RoutedEventArgs e)
    {
        var samples = CurrentScriptPurpose == ScriptPurpose.Hook ? HookScriptSamples : ScriptSamples;
        ShowDropDownMenu(InsertSampleButton, samples.Select(sample => CreateDropDownItem(sample.Title, sample, 示例项_Click)));
    }

    private void 示例项_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.Tag is not ScriptSample sample) return;
        SetScriptText(sample.Script);
        ApplyPythonSyntaxHighlighting();
        MarkScriptDirty();
        WriteRunOutput($"已插入示例：{sample.Title}\n\n点击「保存」写入脚本文件，或直接点「{RunScriptButton.Content}」执行。", Muted, "已插入示例");
    }

    // ── 脚本库 ────────────────────────────────────────────────────────────────

    /// <summary>读取当前工作区的钩子配置与脚本库并回填界面；空工作区先落一份默认钩子脚本。</summary>
    private async Task LoadScriptWorkspaceAsync()
    {
        var workspacePath = _workspacePath;
        TrafficHookConfiguration? configuration = null;
        string? loadError = null;
        try { configuration = await TrafficHookConfigStore.LoadAsync(workspacePath); }
        catch (Exception exception) { loadError = exception.Message; }
        var configured = configuration is not null;
        configuration ??= new TrafficHookConfiguration(ScriptPath: HookScriptFileName,
            Hooks: new TrafficHookSwitches(BeforeSend: true, BeforeWrite: true));

        try
        {
            // 空脚本库对新用户等于「没有入口」，所以先给一份可直接改的默认钩子脚本。
            if (ScriptLibraryStore.List(workspacePath).Count == 0)
                await ScriptLibraryStore.CreateAsync(workspacePath, HookScriptFileName, ScriptPurpose.Hook, DefaultHookScriptTemplate);
        }
        catch (Exception exception) { loadError ??= "默认钩子脚本创建失败：" + exception.Message; }

        // 工作区可能在加载期间被切换，禁止旧工作区内容回填新界面。
        if (!string.Equals(workspacePath, _workspacePath, StringComparison.OrdinalIgnoreCase) || HookEnabledBox is null) return;

        HookEnabledBox.IsChecked = configuration.Enabled;
        var switches = configuration.Hooks ?? new TrafficHookSwitches();
        HookBeforeSendBox.IsChecked = switches.BeforeSend;
        HookAfterSendBox.IsChecked = switches.AfterSend;
        HookBeforeWriteBox.IsChecked = switches.BeforeWrite;
        HookAfterDeliverBox.IsChecked = switches.AfterDeliver;
        _activeHookScriptPath = string.IsNullOrWhiteSpace(configuration.ScriptPath) ? null : configuration.ScriptPath;
        _activeHookScriptFileName = ResolveActiveHookFileName(workspacePath, _activeHookScriptPath);
        RefreshScriptLibrary(_activeHookScriptFileName);
        UpdateHookStatusLine(loadError ?? (configured
            ? null
            : "当前工作区尚无钩子配置；改完点顶部「保存」即可写入，下次启动采集生效。"), isError: loadError is not null);
        if (loadError is null) await RefreshScriptHookRuntimeStatusAsync();
        await LoadRealHookFindingsAsync();
    }

    /// <summary>
    /// 把配置里的 scriptPath 还原为脚本库中的文件名。指向 scripts 目录之外的绝对路径无法在库里管理，
    /// 这时返回 null——但原始 scriptPath 会保留在 <see cref="_activeHookScriptPath"/> 里，保存时原样写回。
    /// </summary>
    private static string? ResolveActiveHookFileName(string workspacePath, string? scriptPath)
    {
        if (string.IsNullOrWhiteSpace(scriptPath)) return null;
        try
        {
            var full = Path.GetFullPath(TrafficHookConfigStore.ResolveScriptPath(workspacePath, scriptPath));
            var directory = Path.GetFullPath(TrafficHookConfigStore.GetScriptsDirectory(workspacePath));
            return string.Equals(Path.GetDirectoryName(full), directory, StringComparison.OrdinalIgnoreCase)
                ? Path.GetFileName(full)
                : null;
        }
        catch (Exception exception) when (exception is ArgumentException or PathTooLongException or NotSupportedException)
        {
            return null;
        }
    }

    /// <summary>重新枚举工作区 scripts 目录并回填列表；随后把 <paramref name="selectFileName"/> 载入编辑器。</summary>
    private void RefreshScriptLibrary(string? selectFileName)
    {
        if (ScriptList is null) return;
        IReadOnlyList<ScriptLibraryItem> items;
        try { items = ScriptLibraryStore.List(_workspacePath); }
        catch (Exception exception)
        {
            UpdateHookStatusLine("脚本库读取失败：" + exception.Message, isError: true);
            return;
        }
        _suppressScriptListChange = true;
        Scripts.Clear();
        foreach (var item in items)
        {
            Scripts.Add(new ScriptRow(item)
            {
                IsActiveHook = _activeHookScriptFileName is not null &&
                               string.Equals(item.FileName, _activeHookScriptFileName, StringComparison.OrdinalIgnoreCase)
            });
        }
        ScriptLibraryCountText.Text = Scripts.Count == 0 ? "空" : $"{Scripts.Count} 个";
        ActiveHookScriptText.Text = _activeHookScriptPath ?? "尚未指定";
        var target = Scripts.FirstOrDefault(row => string.Equals(row.FileName, selectFileName, StringComparison.OrdinalIgnoreCase))
                     ?? Scripts.FirstOrDefault(row => row.IsActiveHook)
                     ?? Scripts.FirstOrDefault();
        ScriptList.SelectedItem = target;
        _suppressScriptListChange = false;
        if (target is null)
        {
            _currentScript = null;
            UpdateScriptHeader();
            return;
        }
        LoadScriptIntoEditor(target);
    }

    private void LoadScriptIntoEditor(ScriptRow row)
    {
        string text;
        try { text = File.ReadAllText(row.FullPath); }
        catch (Exception exception)
        {
            UpdateHookStatusLine($"脚本 {row.FileName} 读取失败：{exception.Message}", isError: true);
            return;
        }
        _currentScript = row;
        _loadedScriptText = text;
        SetScriptText(text);
        ApplyPythonSyntaxHighlighting();
        ApplyScriptPurposeCombo(row.Purpose);
        _scriptDirty = false;
        ResetScriptAiConversation(); // 换了文件，旧对话谈的是另一个脚本，继续带着发只会误导模型
        UpdateScriptHeader();
    }

    private void 脚本列表_选择变化(object sender, SelectionChangedEventArgs e)
    {
        if (_suppressScriptListChange || ScriptList.SelectedItem is not ScriptRow row || ReferenceEquals(row, _currentScript)) return;
        if (_scriptDirty && _currentScript is not null && !ConfirmDiscardScriptChanges(_currentScript))
        {
            _suppressScriptListChange = true;
            ScriptList.SelectedItem = _currentScript;
            _suppressScriptListChange = false;
            return;
        }
        LoadScriptIntoEditor(row);
    }

    private bool ConfirmDiscardScriptChanges(ScriptRow row) =>
        MessageBox.Show(this, $"脚本 {row.FileName} 有未保存的修改，切换后会丢失。\n\n仍要切换吗？",
            "未保存的修改", MessageBoxButton.OKCancel, MessageBoxImage.Warning) == MessageBoxResult.OK;

    private void ApplyScriptPurposeCombo(ScriptPurpose purpose)
    {
        if (ScriptPurposeCombo is null) return;
        _suppressScriptPurposeChange = true;
        ScriptPurposeCombo.SelectedIndex = purpose == ScriptPurpose.Fixture ? 1 : 0;
        _suppressScriptPurposeChange = false;
    }

    private void 脚本用途_变化(object sender, SelectionChangedEventArgs e)
    {
        if (_suppressScriptPurposeChange) return;
        var purpose = ScriptPurposeCombo.SelectedIndex == 1 ? ScriptPurpose.Fixture : ScriptPurpose.Hook;
        // 用途和脚本内容一起在「保存」时落盘，保持这一页只有一个写入口。
        _currentScript?.SetPurpose(purpose);
        MarkScriptDirty();
        UpdateScriptHeader();
    }

    private void MarkScriptDirty()
    {
        if (_scriptDirty) return;
        _scriptDirty = true;
        UpdateScriptHeader();
    }

    private void UpdateScriptHeader()
    {
        if (CurrentScriptNameText is null) return;
        CurrentScriptNameText.Text = _currentScript?.FileName ?? "尚未选择脚本";
        ScriptDirtyText.Text = _scriptDirty ? "● 未保存" : string.Empty;
        var hook = CurrentScriptPurpose == ScriptPurpose.Hook;
        RunScriptButton.Content = hook ? "试跑钩子" : "运行验证";
        if (ScriptEditorHintText is not null)
        {
            ScriptEditorHintText.Text =
                "Ctrl+S 保存 · Ctrl+J 智能提示（Ctrl+空格 常被中文输入法拦截，Alt+/ 亦可）· Ctrl+/ 切换注释 · Ctrl+[ 折叠当前块 · 右键有整理格式与折叠命令。\n" +
                (hook
                    ? "输入 event.get('、store.、字典字段或任意标识符前两个字母会自动弹出补全；Enter/Tab 插入，Esc 关闭。"
                    : "输入 fixture. 或事务字段前两个字母会自动弹出补全；Enter/Tab 插入，Esc 关闭。");
        }
    }

    private void 新建脚本_Click(object sender, RoutedEventArgs e) =>
        ShowDropDownMenu(NewScriptButton,
        [
            CreateDropDownItem("新建钩子脚本（采集期间执行）", ScriptPurpose.Hook, 新建脚本项_Click),
            CreateDropDownItem("新建验证脚本（对流量快照跑一次）", ScriptPurpose.Fixture, 新建脚本项_Click)
        ]);

    private async void 新建脚本项_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.Tag is not ScriptPurpose purpose) return;
        if (_scriptDirty && _currentScript is not null && !ConfirmDiscardScriptChanges(_currentScript)) return;
        try
        {
            var requested = ScriptNameBox.Text;
            var baseName = string.IsNullOrWhiteSpace(requested)
                ? (purpose == ScriptPurpose.Hook ? HookScriptFileName : DefaultFixtureScriptFileName)
                : requested;
            var fileName = ScriptLibraryStore.CreateUniqueFileName(_workspacePath, baseName);
            var template = purpose == ScriptPurpose.Hook ? DefaultHookScriptTemplate : DefaultGuidedScript;
            await ScriptLibraryStore.CreateAsync(_workspacePath, fileName, purpose, template);
            ScriptNameBox.Clear();
            RefreshScriptLibrary(fileName);
            UpdateHookStatusLine($"已新建 {fileName}。");
        }
        catch (Exception exception)
        {
            UpdateHookStatusLine("新建脚本失败：" + exception.Message, isError: true);
        }
    }

    private async void 重命名脚本_Click(object sender, RoutedEventArgs e)
    {
        var row = _currentScript;
        if (row is null)
        {
            UpdateHookStatusLine("请先在脚本库中选择要重命名的脚本。", isError: true);
            return;
        }
        try
        {
            var target = await ScriptLibraryStore.RenameAsync(_workspacePath, row.FileName, ScriptNameBox.Text);
            var notice = $"已重命名为 {target}。";
            if (row.IsActiveHook)
            {
                // 采集钩子的 scriptPath 必须跟着改，否则配置会指向一个已经不存在的文件。
                _activeHookScriptFileName = target;
                _activeHookScriptPath = target;
                await SaveHookConfigurationAsync();
                notice += "采集钩子配置已同步更新。";
            }
            ScriptNameBox.Clear();
            RefreshScriptLibrary(target);
            UpdateHookStatusLine(notice);
        }
        catch (Exception exception)
        {
            UpdateHookStatusLine("重命名失败：" + exception.Message, isError: true);
        }
    }

    private async void 删除脚本_Click(object sender, RoutedEventArgs e)
    {
        var row = _currentScript;
        if (row is null)
        {
            UpdateHookStatusLine("请先在脚本库中选择要删除的脚本。", isError: true);
            return;
        }
        if (row.IsActiveHook)
        {
            UpdateHookStatusLine("该脚本是当前采集钩子，请先把其他脚本设为采集钩子再删除。", isError: true);
            return;
        }
        if (MessageBox.Show(this, $"确定删除脚本 {row.FileName} 吗？\n\n文件会从工作区 scripts 目录中移除，无法撤销。",
                "删除脚本", MessageBoxButton.OKCancel, MessageBoxImage.Warning) != MessageBoxResult.OK) return;
        try
        {
            await ScriptLibraryStore.DeleteAsync(_workspacePath, row.FileName);
            _currentScript = null;
            _scriptDirty = false;
            RefreshScriptLibrary(null);
            UpdateHookStatusLine($"已删除 {row.FileName}。");
        }
        catch (Exception exception)
        {
            UpdateHookStatusLine("删除失败：" + exception.Message, isError: true);
        }
    }

    private async void 刷新脚本库_Click(object sender, RoutedEventArgs e)
    {
        if (_scriptDirty && _currentScript is not null && !ConfirmDiscardScriptChanges(_currentScript)) return;
        _scriptDirty = false;
        await LoadScriptWorkspaceAsync();
    }

    private void 设为采集钩子_Click(object sender, RoutedEventArgs e)
    {
        var row = _currentScript;
        if (row is null)
        {
            UpdateHookStatusLine("请先在脚本库中选择要用作采集钩子的脚本。", isError: true);
            return;
        }
        if (CurrentScriptPurpose != ScriptPurpose.Hook)
        {
            UpdateHookStatusLine("只有钩子脚本能作为采集钩子；请先把上方「用途」改为「钩子脚本」。", isError: true);
            return;
        }
        _activeHookScriptFileName = row.FileName;
        _activeHookScriptPath = row.FileName;
        foreach (var item in Scripts)
            item.IsActiveHook = string.Equals(item.FileName, row.FileName, StringComparison.OrdinalIgnoreCase);
        ActiveHookScriptText.Text = row.FileName;
        UpdateHookStatusLine($"已选定 {row.FileName} 为采集钩子，点击顶部「保存」写入工作区。");
    }

    // ── 保存 ──────────────────────────────────────────────────────────────────

    /// <summary>把编辑器内容与右侧钩子配置一并写入当前工作区：这一页唯一的写入口。</summary>
    private async void 保存脚本_Click(object sender, RoutedEventArgs e)
    {
        SaveScriptButton.IsEnabled = false;
        try
        {
            var purpose = CurrentScriptPurpose;
            var scriptText = GetScriptText();
            if (string.IsNullOrWhiteSpace(scriptText)) throw new InvalidOperationException("脚本内容不能为空。");
            string fileName;
            if (_currentScript is null)
            {
                fileName = ScriptLibraryStore.CreateUniqueFileName(_workspacePath,
                    purpose == ScriptPurpose.Hook ? HookScriptFileName : DefaultFixtureScriptFileName);
                await ScriptLibraryStore.CreateAsync(_workspacePath, fileName, purpose, scriptText);
            }
            else
            {
                fileName = _currentScript.FileName;
                await TrafficHookConfigStore.SaveScriptToPathAsync(_currentScript.FullPath, scriptText);
                await ScriptLibraryStore.SetPurposeAsync(_workspacePath, fileName, purpose);
            }
            var configurationNotice = await SaveHookConfigurationAsync();
            _loadedScriptText = scriptText;
            _scriptDirty = false;
            RefreshScriptLibrary(fileName);
            UpdateHookStatusLine($"已保存 {fileName}。{configurationNotice}");
        }
        catch (Exception exception)
        {
            UpdateHookStatusLine("保存失败：" + exception.Message, isError: true);
        }
        finally
        {
            SaveScriptButton.IsEnabled = true;
        }
    }

    /// <summary>写 hook-config.json 并留审计；启用状态下的必要条件在这里集中校验。</summary>
    private async Task<string> SaveHookConfigurationAsync()
    {
        var switches = new TrafficHookSwitches(HookBeforeSendBox.IsChecked == true, HookAfterSendBox.IsChecked == true,
            HookBeforeWriteBox.IsChecked == true, HookAfterDeliverBox.IsChecked == true);
        var enabled = HookEnabledBox.IsChecked == true;
        if (enabled && string.IsNullOrWhiteSpace(_activeHookScriptPath))
            throw new InvalidOperationException("启用请求钩子前，需要先用「设为采集钩子」指定采集期间执行的脚本。");
        if (enabled && switches.EnabledCount == 0)
            throw new InvalidOperationException("启用请求钩子时至少需要勾选一个挂载点。");
        var configuration = new TrafficHookConfiguration(enabled, _activeHookScriptPath, switches);
        await TrafficHookConfigStore.SaveConfigAsync(_workspacePath, configuration);
        await new WorkspaceStore(_workspacePath).AppendAuditAsync(AuditEventHooksConfigSaved, new
        {
            enabled = configuration.Enabled,
            scriptPath = configuration.ScriptPath,
            hooks = new
            {
                beforeSend = switches.BeforeSend,
                afterSend = switches.AfterSend,
                beforeWrite = switches.BeforeWrite,
                afterDeliver = switches.AfterDeliver
            }
        });
        return enabled ? "采集钩子配置已保存，下次启动采集生效。" : "采集钩子配置已保存（未启用）。";
    }

    // ── 运行 ──────────────────────────────────────────────────────────────────

    private async void 运行脚本_Click(object sender, RoutedEventArgs e)
    {
        RunScriptButton.IsEnabled = false;
        try
        {
            if (CurrentScriptPurpose == ScriptPurpose.Hook) await RunHookDryRunAsync();
            else await RunFixtureValidationAsync();
        }
        finally
        {
            RunScriptButton.IsEnabled = true;
        }
    }

    private void WriteRunOutput(string text, Brush foreground, string state)
    {
        SandboxOutput.Foreground = foreground;
        SandboxOutput.Text = text;
        ScriptRunStateText.Text = state;
    }

    /// <summary>验证脚本：把当前流量表投影成脱敏 fixture，交给隔离沙箱执行一次。</summary>
    private async Task RunFixtureValidationAsync()
    {
        WriteRunOutput("正在执行静态策略检查与隔离验证…", Accent, "运行中");
        var jobPath = Path.Combine(Path.GetTempPath(), "netmind-job-" + Guid.NewGuid().ToString("N") + ".json");
        try
        {
            var hostExecutable = Path.Combine(AppContext.BaseDirectory, SandboxHostDirectoryName, SandboxHostExecutableName);
            var hostAssembly = Path.Combine(AppContext.BaseDirectory, SandboxHostDirectoryName, SandboxHostAssemblyName);
            if (!File.Exists(hostExecutable) && !File.Exists(hostAssembly))
                throw new FileNotFoundException("独立脚本沙箱后台不可用，请重新构建工作台项目。", hostExecutable);
            var transactions = TrafficRows.Select(item => item.Source).ToArray();
            var fixtureJson = AiPrivacyFilter.BuildScriptFixture(transactions);
            var job = new SandboxJob(GetScriptText(), JsonSerializer.SerializeToElement(fixtureJson, new JsonSerializerOptions(JsonSerializerDefaults.Web)));
            await File.WriteAllTextAsync(jobPath, JsonSerializer.Serialize(job, new JsonSerializerOptions(JsonSerializerDefaults.Web)), new UTF8Encoding(false));
            var startInfo = new ProcessStartInfo(File.Exists(hostExecutable) ? hostExecutable : DotnetCommandName)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8
            };
            if (!File.Exists(hostExecutable)) startInfo.ArgumentList.Add(hostAssembly);
            foreach (var argument in new[] { "run", jobPath }) startInfo.ArgumentList.Add(argument);
            using var process = new Process { StartInfo = startInfo };
            if (!process.Start()) throw new InvalidOperationException("无法启动独立脚本沙箱后台。");
            var standardOutput = process.StandardOutput.ReadToEndAsync();
            var standardError = process.StandardError.ReadToEndAsync();
            await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(12));
            var json = await standardOutput;
            var error = await standardError;
            var result = JsonSerializer.Deserialize<SandboxResult>(json.Trim(), new JsonSerializerOptions(JsonSerializerDefaults.Web));
            if (result is null) throw new InvalidDataException(string.IsNullOrWhiteSpace(error) ? "脚本沙箱返回了无效结果。" : error.Trim());
            // 流量表为空是常见状态（刚开始采集），fixture 会是 0 条；先说清楚，免得脚本里的 assert 失败显得莫名其妙。
            var fixtureNotice = transactions.Length == 0
                ? "当前流量表为空，fixture.transactions 是 0 条。\n\n"
                : $"输入：{Math.Min(transactions.Length, AiPrivacyFilter.ScriptFixtureMaximumTransactions)} 条已脱敏事务。\n\n";
            if (result.PolicyViolations.Count > 0)
            {
                WriteRunOutput("策略拒绝\n\n" + string.Join("\n", result.PolicyViolations.Select(item => "• " + item)), Red, "策略拒绝");
                return;
            }
            var detail = string.IsNullOrWhiteSpace(result.StandardError) ? result.StandardOutput : result.StandardError;
            var truncatedNotice = result.OutputTruncated ? "\n\n" + OutputTruncatedNotice : string.Empty;
            WriteRunOutput(
                $"{fixtureNotice}{result.State}\n\n耗时 {result.DurationMilliseconds} 毫秒 · 退出码 {result.ExitCode}\n隔离：{result.Enforcement}\n\n" +
                $"{(string.IsNullOrWhiteSpace(detail) ? "结果对象符合验证规则。" : detail.Trim())}{truncatedNotice}",
                result.Succeeded ? Green : Red, result.State);
        }
        catch (Exception exception)
        {
            WriteRunOutput("沙箱执行失败\n\n" + exception.Message, Red, "执行失败");
        }
        finally
        {
            try { if (File.Exists(jobPath)) File.Delete(jobPath); } catch { /* 临时作业文件删除失败不影响结果展示。 */ }
        }
    }

    /// <summary>
    /// 钩子脚本：在临时数据目录里启动隔离工作进程，用一条事务快照走一遍已勾选的挂载点。
    /// 不修改钩子配置，也不碰正式数据。缺流量、未勾挂载点都不再是错误——试跑本来就应该随时能跑。
    /// </summary>
    private async Task RunHookDryRunAsync()
    {
        var temporaryRoot = Path.Combine(Path.GetTempPath(), "netmind-hook-dryrun-" + Guid.NewGuid().ToString("N"));
        ScriptHookEngine? engine = null;
        try
        {
            var script = GetScriptText();
            if (string.IsNullOrWhiteSpace(script)) throw new InvalidOperationException("脚本内容不能为空。");
            var violations = PythonSandboxPolicy.Validate(script);
            if (violations.Count > 0) throw new InvalidOperationException("静态策略拒绝：" + string.Join("；", violations));

            var notices = new List<string>();
            var traffic = SelectedTraffic?.Source ?? TrafficRows.LastOrDefault()?.Source;
            if (traffic is null)
            {
                traffic = CreateDryRunSampleTraffic();
                notices.Add("当前没有流量，已用内置示例事务试跑。");
            }

            var enabledEvents = new List<string>();
            if (HookBeforeSendBox.IsChecked == true) enabledEvents.Add(HookEventNames.RequestBeforeSend);
            if (HookAfterSendBox.IsChecked == true) enabledEvents.Add(HookEventNames.RequestAfterSend);
            if (HookBeforeWriteBox.IsChecked == true) enabledEvents.Add(HookEventNames.ResponseBeforeWrite);
            if (HookAfterDeliverBox.IsChecked == true) enabledEvents.Add(HookEventNames.ResponseAfterDeliver);
            if (enabledEvents.Count == 0)
            {
                enabledEvents.AddRange([HookEventNames.RequestBeforeSend, HookEventNames.RequestAfterSend,
                    HookEventNames.ResponseBeforeWrite, HookEventNames.ResponseAfterDeliver]);
                notices.Add("右侧未勾选挂载点，本次按四个挂载点全开试跑（不改动配置）。");
            }

            var hostExecutable = Path.Combine(AppContext.BaseDirectory, SandboxHostDirectoryName, SandboxHostExecutableName);
            var hostAssembly = Path.Combine(AppContext.BaseDirectory, SandboxHostDirectoryName, SandboxHostAssemblyName);
            if (!File.Exists(hostExecutable) && !File.Exists(hostAssembly))
                throw new FileNotFoundException("独立脚本沙箱后台不可用，请重新构建工作台项目。", hostExecutable);
            WriteRunOutput("正在隔离试跑当前脚本…", Accent, "试跑中");
            Directory.CreateDirectory(temporaryRoot);
            var scriptPath = Path.Combine(temporaryRoot, HookScriptFileName);
            await File.WriteAllTextAsync(scriptPath, script, new UTF8Encoding(false));
            engine = new ScriptHookEngine(File.Exists(hostExecutable) ? hostExecutable : DotnetCommandName,
                File.Exists(hostExecutable) ? null : hostAssembly, scriptPath, Path.Combine(temporaryRoot, HookDataDirectoryName), enabledEvents);
            if (!await engine.StartAsync())
            {
                var failed = engine.GetMetricsSnapshot();
                throw new InvalidOperationException(failed.DisabledReason ?? failed.LastError ?? "钩子工作进程未能启动。");
            }

            var body = Encoding.UTF8.GetBytes(traffic.RequestSummary ?? string.Empty);
            var snapshot = new HookTransactionSnapshot(traffic.Id, Guid.Empty, traffic.Method, traffic.Url,
                TrafficRow.ResolveHost(traffic), traffic.Endpoint, null, body);
            foreach (var hookEvent in enabledEvents)
                engine.Emit(hookEvent, snapshot, hookEvent.StartsWith("response.", StringComparison.Ordinal) ? traffic.StatusCode : null);

            // 默认拒绝转发下，勾选的挂载点里可能有一部分（甚至全部）根本没被送去给脚本——
            // 那部分永远等不到 worker 的 processed 回执。用 Emit 后立刻可读的 NotObservedEvents
            // 算出真正指望它被处理的条数，只等这些，而不是傻等全部挂载点直到 5 秒超时。
            var notObserved = (int)engine.GetMetricsSnapshot().NotObservedEvents;
            var expectedProcessed = Math.Max(0, enabledEvents.Count - notObserved);
            var deadline = DateTimeOffset.UtcNow.AddSeconds(5);
            while (engine.ProcessedEventCount < expectedProcessed && DateTimeOffset.UtcNow < deadline)
                await Task.Delay(50);
            var metrics = engine.GetMetricsSnapshot();
            var findings = engine.DrainFindings();
            AppendScriptFindings(findings);
            var builder = new StringBuilder();
            foreach (var notice in notices) builder.Append(notice).Append('\n');
            if (notices.Count > 0) builder.Append('\n');
            builder.Append($"试跑事务：{traffic.Method} {traffic.Url}\n")
                   .Append($"挂载点：{string.Join('、', enabledEvents)}\n\n")
                   .Append($"投递 {metrics.DeliveredEvents}/{expectedProcessed} · 处理 {metrics.ProcessedEvents} · ")
                   .Append($"结论 {metrics.Findings} · 错误 {metrics.WorkerErrors}");
            if (notObserved > 0)
                builder.Append($" · 未转发 {notObserved}");
            var failedRun = metrics.WorkerErrors > 0 || metrics.ProcessedEvents < expectedProcessed;
            if (metrics.ProcessedEvents < expectedProcessed) builder.Append("\n\n等待处理完成超时，请检查脚本是否阻塞。");
            if (!string.IsNullOrWhiteSpace(metrics.LastError)) builder.Append("\n\n最近错误：").Append(metrics.LastError);
            if (notObserved == enabledEvents.Count)
            {
                // 一条都没转发：多半是压根没写 OBSERVE/INTERCEPT，或者写了但条件没命中这条试跑事务。
                builder.Append("\n\n未转发任何事件：勾选的挂载点没有被 OBSERVE 或 INTERCEPT 规则命中，")
                       .Append("函数完全没有被调用（这不是错误，是默认拒绝转发生效）。\n")
                       .Append("检查脚本里是否声明了 OBSERVE（想只观察）或 INTERCEPT（想修改流量），")
                       .Append("以及规则的 url/host 等条件是否会命中试跑用的这条事务：")
                       .Append(traffic.Url);
            }
            else if (notObserved > 0)
            {
                builder.Append($"\n\n{notObserved} 个挂载点没有被 OBSERVE/INTERCEPT 规则命中，函数未被调用（默认拒绝转发）。");
            }
            if (findings.Count > 0)
                builder.Append($"\n\n本次新增 {findings.Count} 条结论，已加入下方「返回数据」列表（点击查看完整内容）。");
            else if (metrics.WorkerErrors == 0 && notObserved < enabledEvents.Count)
                builder.Append("\n\n脚本返回 None，因此没有生成结论。");
            WriteRunOutput(builder.ToString(),
                notObserved == enabledEvents.Count ? Amber : failedRun ? Red : Green,
                notObserved == enabledEvents.Count ? "未转发" : failedRun ? "试跑异常" : "试跑完成");
        }
        catch (Exception exception)
        {
            WriteRunOutput("隔离试跑失败\n\n" + exception.Message, Red, "试跑失败");
        }
        finally
        {
            if (engine is not null) await engine.DisposeAsync();
            try { if (Directory.Exists(temporaryRoot)) Directory.Delete(temporaryRoot, recursive: true); } catch { /* 临时目录清理失败不影响结果展示。 */ }
        }
    }

    /// <summary>把本次试跑产出的结论前插进列表（最新在上），并裁掉超出容量的旧条目。</summary>
    private void AppendScriptFindings(IReadOnlyList<HookFinding> findings)
    {
        if (findings.Count == 0) return;
        var scriptName = _currentScript?.FileName ?? "（未命名脚本）";
        for (var index = findings.Count - 1; index >= 0; index--)
        {
            var finding = findings[index];
            var json = JsonSerializer.Serialize(finding.Data, new JsonSerializerOptions
                { WriteIndented = true, Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping });
            ScriptFindings.Insert(0, new ScriptFindingRow
            {
                Time = finding.ReceivedAtUtc.ToLocalTime().ToString("HH:mm:ss"),
                Source = "试跑",
                Event = finding.Event,
                Script = scriptName,
                Summary = json.Length > 90 ? json.Replace('\n', ' ')[..90] + "…" : json.Replace('\n', ' '),
                FullJson = json
            });
        }
        while (ScriptFindings.Count > ScriptFindingsCapacity) ScriptFindings.RemoveAt(ScriptFindings.Count - 1);
        UpdateScriptFindingsCount();
    }

    /// <summary>
    /// 真实采集时脚本产出的结论走的是另一条路：CoreHost（不是工作台进程）每 2 秒把队列里的
    /// finding 落到工作区审计日志（<c>hooks.finding</c>），工作台之前从不读这份日志——
    /// 「运行结果」列表此前只在点「运行」做工作台内试跑时才有内容，真实抓包命中了什么，
    /// 界面上根本看不到。这里把审计日志最近的记录读回来，接入同一个列表。
    /// </summary>
    private async Task LoadRealHookFindingsAsync()
    {
        var workspacePath = _workspacePath;
        IReadOnlyList<AuditLogEntry> entries;
        try
        {
            entries = await AuditLogReader.ReadRecentAsync(workspacePath, NetMindDefaults.AuditEventHooksFinding,
                ScriptFindingsCapacity);
        }
        catch (Exception exception)
        {
            UpdateHookStatusLine("读取实时抓包结论失败：" + exception.Message, isError: true);
            return;
        }
        if (!string.Equals(workspacePath, _workspacePath, StringComparison.OrdinalIgnoreCase)) return; // 读取期间切换了工作区

        for (var index = ScriptFindings.Count - 1; index >= 0; index--)
            if (ScriptFindings[index].Source == "实时抓包") ScriptFindings.RemoveAt(index);

        foreach (var entry in entries)
        {
            string? eventName = null, txnId = null;
            JsonElement data = default;
            try
            {
                using var document = JsonDocument.Parse(entry.PayloadJson);
                var root = document.RootElement;
                eventName = root.TryGetProperty("event", out var eventElement) ? eventElement.GetString() : null;
                txnId = root.TryGetProperty("txnId", out var txnElement) ? txnElement.GetString() : null;
                if (root.TryGetProperty("data", out var dataElement)) data = dataElement.Clone();
            }
            catch (JsonException) { continue; } // 单条损坏跳过，不影响其余条目显示

            var json = data.ValueKind == JsonValueKind.Undefined
                ? "{}"
                : JsonSerializer.Serialize(data, new JsonSerializerOptions
                    { WriteIndented = true, Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping });
            ScriptFindings.Insert(0, new ScriptFindingRow
            {
                Time = entry.Timestamp.ToLocalTime().ToString("MM-dd HH:mm:ss"),
                Source = "实时抓包",
                Event = eventName ?? "（未知挂载点）",
                Script = txnId is null ? "实时抓包" : $"事务 {txnId}",
                Summary = json.Length > 90 ? json.Replace('\n', ' ')[..90] + "…" : json.Replace('\n', ' '),
                FullJson = json
            });
        }
        while (ScriptFindings.Count > ScriptFindingsCapacity) ScriptFindings.RemoveAt(ScriptFindings.Count - 1);
        UpdateScriptFindingsCount();
    }

    private async void 刷新脚本结果_Click(object sender, RoutedEventArgs e) => await LoadRealHookFindingsAsync();

    /// <summary>
    /// 观察型脚本可能对每个响应都产出一条结论（比如 <c>on_before_write</c> 没有按 URL 过滤时），
    /// 列表会越攒越多；没有搜索框根本找不到某个特定 URL 的那一条。用 WPF 默认视图的 Filter
    /// 而不是另建一个过滤后的集合——新结论插入时会自动重新套用当前过滤条件，不需要手动刷新。
    /// </summary>
    private void 脚本结果搜索_Changed(object sender, TextChangedEventArgs e)
    {
        if (ScriptFindingsSearchBox is null) return;
        var view = CollectionViewSource.GetDefaultView(ScriptFindings);
        var keyword = ScriptFindingsSearchBox.Text.Trim();
        view.Filter = keyword.Length == 0
            ? null
            : item => item is ScriptFindingRow row &&
                      (row.Event.Contains(keyword, StringComparison.OrdinalIgnoreCase) ||
                       row.Script.Contains(keyword, StringComparison.OrdinalIgnoreCase) ||
                       row.Source.Contains(keyword, StringComparison.OrdinalIgnoreCase) ||
                       row.FullJson.Contains(keyword, StringComparison.OrdinalIgnoreCase));
        UpdateScriptFindingsCount();
    }

    private void UpdateScriptFindingsCount()
    {
        if (ScriptFindingsCountText is null) return;
        var view = CollectionViewSource.GetDefaultView(ScriptFindings);
        var visible = view.Cast<object>().Count();
        ScriptFindingsCountText.Text = ScriptFindings.Count == 0 ? "空"
            : visible == ScriptFindings.Count ? $"{ScriptFindings.Count} 条"
            : $"{visible} / {ScriptFindings.Count} 条";
    }

    private void 脚本结果_选择变化(object sender, SelectionChangedEventArgs e)
    {
        if (ScriptFindingsList?.SelectedItem is not ScriptFindingRow row) return;
        WriteRunOutput($"[{row.Source}] {row.Script} · {row.Event} · {row.Time}\n\n{row.FullJson}", Green, "查看结论");
    }

    private void 清空脚本结果列表_Click(object sender, RoutedEventArgs e)
    {
        ScriptFindings.Clear();
        if (ScriptFindingsSearchBox is not null) ScriptFindingsSearchBox.Clear(); // 否则清空后再刷新会立刻被旧关键字重新过滤掉
        UpdateScriptFindingsCount();
    }

    /// <summary>流量表为空时的兜底试跑事务：让「运行」在任何时刻都能给出结果，而不是报「没有可用快照」。</summary>
    private static TrafficRecord CreateDryRunSampleTraffic() => new(
        Guid.NewGuid(), DateTimeOffset.Now, "POST", "/v1/user/login", 200, 42, 128,
        "netmind-dryrun", "HTTP/1.1",
        "{\"username\":\"demo\",\"password\":\"demo\"}",
        "{\"token\":\"demo-token\",\"expiresIn\":3600}",
        Url: "https://api.example.com/v1/user/login");

    private void 钩子勾选_Changed(object sender, RoutedEventArgs e)
    {
        MarkScriptDirty();
        UpdateHookStatusLine();
    }

    /// <summary>读取采集后台原子发布的脚本 Hook 指标；状态文件仅含计数和脱敏错误摘要。</summary>
    private async Task RefreshScriptHookRuntimeStatusAsync()
    {
        if (HookStatusText is null) return;
        var workspacePath = _workspacePath;
        try
        {
            var status = await TrafficHookStatusStore.LoadAsync(workspacePath);
            if (!string.Equals(workspacePath, _workspacePath, StringComparison.OrdinalIgnoreCase) || status is null) return;
            var metrics = status.Metrics;
            var fresh = DateTimeOffset.UtcNow - status.UpdatedAtUtc < TimeSpan.FromSeconds(5);
            var state = metrics.State switch
            {
                "running" when fresh => "运行中",
                "starting" when fresh => "正在启动",
                "disabled" => "已停用",
                "stopping" => "已停止",
                _ => fresh ? metrics.State : "状态已过期"
            };
            var detail = $"运行状态：{state} · 已投递 {metrics.DeliveredEvents:N0} · 已处理 {metrics.ProcessedEvents:N0} · " +
                         $"结论 {metrics.Findings:N0} · 队列 {metrics.QueuedEvents:N0} · 丢弃 {metrics.DroppedEvents:N0} · " +
                         $"错误 {metrics.WorkerErrors:N0} · 重启 {metrics.Restarts:N0}";
            if (!string.IsNullOrWhiteSpace(metrics.LastEvent)) detail += $"\n最近处理：{metrics.LastEvent}";
            if (!string.IsNullOrWhiteSpace(metrics.LastError)) detail += $"\n最近错误：{metrics.LastError}";
            else if (!string.IsNullOrWhiteSpace(metrics.DisabledReason)) detail += $"\n原因：{metrics.DisabledReason}";
            var isError = HookEnabledBox.IsChecked == true && _capturing && metrics.State == "disabled";
            UpdateHookStatusLine(detail, isError);
        }
        catch (Exception exception)
        {
            UpdateHookStatusLine("运行状态读取失败：" + exception.Message, isError: true);
        }
    }

    /// <summary>刷新钩子状态行：启用状态、已勾选挂载点数、当前采集钩子脚本。</summary>
    private void UpdateHookStatusLine(string? notice = null, bool isError = false)
    {
        if (HookStatusText is null || HookEnabledBox is null) return;
        var enabled = HookEnabledBox.IsChecked == true;
        var hookCount = new TrafficHookSwitches(HookBeforeSendBox.IsChecked == true, HookAfterSendBox.IsChecked == true,
            HookBeforeWriteBox.IsChecked == true, HookAfterDeliverBox.IsChecked == true).EnabledCount;
        var configured = !string.IsNullOrWhiteSpace(_activeHookScriptPath);
        var summary = $"{(enabled ? "已启用" : "未启用")} · 挂载点 {hookCount}/4 · " +
                      (configured ? "钩子脚本 " + _activeHookScriptPath : "尚未指定钩子脚本");
        // 加密隧道不可钩：没开 HTTPS 解密时，HTTPS 站点的请求在代理眼里只是 CONNECT，
        // 钩子一次都不会触发。这一条不说清楚，用户只会以为是脚本写错了。
        if (enabled && !_tlsInspectionEnabled)
            summary += "\n未启用 HTTPS 解密：HTTPS 流量是加密隧道，钩子无法触发，只有明文 HTTP 会被钩到。";
        HookStatusText.Text = notice is null ? summary : summary + "\n" + notice;
        HookStatusText.Foreground = isError ? Red
            : enabled && !_tlsInspectionEnabled ? Amber
            : enabled && hookCount > 0 && configured ? Green : Muted;
        // 设置页只读回显同一份事实，避免用户在设置页找不到钩子状态而以为没有这项功能。
        if (SettingsHookSummaryText is not null)
        {
            SettingsHookSummaryText.Text = "当前工作区：" + summary;
            SettingsHookSummaryText.Foreground = enabled && hookCount > 0 && configured ? Green : Muted;
        }
    }

    /// <summary>设置页的钩子入口：跳到脚本页，那里才是钩子的唯一配置处。</summary>
    private void 前往脚本页配置钩子_Click(object sender, RoutedEventArgs e) => SelectPage(SandboxNav);
}

public sealed class TrafficRow(TrafficRecord source, string dataSource = SourceDemo, Guid? sessionId = null) : INotifyPropertyChanged
{
    private bool _isAiSelected;
    public TrafficRecord Source { get; } = source;
    public string Time => Source.Timestamp.ToLocalTime().ToString("HH:mm:ss");
    public string Method => Source.Method;
    public string Host => ResolveHost(Source);
    public string Endpoint => Source.Endpoint;
    public string ResourceKind => ResolveResourceKind(Source);
    // 类型徽章短文本：与 TrafficResourceIconTemplate 的色块背景组合，比符号图形辨识度更高。
    public string ResourceIcon => ResourceKind switch
    {
        "图片" => "图",
        "接口数据" => "API",
        "脚本" => "JS",
        "样式" => "CSS",
        "字体" => "字",
        "媒体" => "媒",
        "连接" => "连",
        "文档" => "文",
        _ => "其"
    };
    public string ResourceType => $"资源类型：{ResourceKind}";
    public string Status => Source.StatusCode.ToString();
    public string Latency => Source.LatencyMs + " 毫秒";
    public string Protocol => Source.Protocol;
    public string Process => Source.Process;
    public string DataSource { get; } = dataSource;
    public Guid? SessionId { get; } = sessionId;
    private int _ordinal;
    /// <summary>列表左侧序号（随采集时间升序递增），与 AI 证据池 #序号 语义一致。</summary>
    public int Ordinal
    {
        get => _ordinal;
        set
        {
            if (_ordinal == value) return;
            _ordinal = value;
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Ordinal)));
        }
    }
    public string Size => Source.SizeBytes >= 1024 ? $"{Source.SizeBytes / 1024d:0.0} KB" : Source.SizeBytes + " B";
    public string SearchText => $"{Method} {Host} {Endpoint} {Status} {Protocol} {Process}";
    public bool IsAiSelected
    {
        get => _isAiSelected;
        set
        {
            if (_isAiSelected == value) return;
            _isAiSelected = value;
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsAiSelected)));
        }
    }
    public event PropertyChangedEventHandler? PropertyChanged;

    internal static string ResolveHost(TrafficRecord traffic)
    {
        if (Uri.TryCreate(traffic.Url, UriKind.Absolute, out var uri) && !string.IsNullOrWhiteSpace(uri.Host))
            return uri.IsDefaultPort ? uri.Host : uri.Authority;
        if (traffic.Method.Equals("CONNECT", StringComparison.OrdinalIgnoreCase) &&
            Uri.TryCreate("https://" + traffic.Endpoint, UriKind.Absolute, out uri))
            return uri.IsDefaultPort ? uri.Host : uri.Authority;
        return "—";
    }

    /// <summary>未解密 HTTPS（CONNECT 隧道）的资源分类名。分类映射只有这一处，别处一律引用它。</summary>
    public const string ResourceKindConnect = "连接";

    private static string ResolveResourceKind(TrafficRecord traffic)
    {
        if (traffic.Method.Equals("CONNECT", StringComparison.OrdinalIgnoreCase)) return ResourceKindConnect;
        var contentType = traffic.ResponseHeaders.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries)
            .Select(line => line.Split(':', 2))
            .Where(parts => parts.Length == 2 && parts[0].Trim().Equals("Content-Type", StringComparison.OrdinalIgnoreCase))
            .Select(parts => parts[1].Split(';', 2)[0].Trim().ToLowerInvariant())
            .FirstOrDefault() ?? string.Empty;
        var path = traffic.Endpoint.Split(['?', '#'], 2)[0].ToLowerInvariant();

        if (contentType.StartsWith("image/", StringComparison.Ordinal) || HasExtension(path, ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".bmp")) return "图片";
        if (contentType.Contains("json", StringComparison.Ordinal) || contentType.Contains("graphql", StringComparison.Ordinal) || HasExtension(path, ".json")) return "接口数据";
        if (contentType.Contains("javascript", StringComparison.Ordinal) || HasExtension(path, ".js", ".mjs", ".wasm")) return "脚本";
        if (contentType.Equals("text/css", StringComparison.Ordinal) || HasExtension(path, ".css")) return "样式";
        if (contentType.StartsWith("font/", StringComparison.Ordinal) || HasExtension(path, ".woff", ".woff2", ".ttf", ".otf", ".eot")) return "字体";
        if (contentType.StartsWith("audio/", StringComparison.Ordinal) || contentType.StartsWith("video/", StringComparison.Ordinal) || HasExtension(path, ".mp3", ".mp4", ".webm", ".wav", ".m3u8")) return "媒体";
        if (contentType.Contains("html", StringComparison.Ordinal) || contentType.Contains("xml", StringComparison.Ordinal) || contentType.StartsWith("text/", StringComparison.Ordinal) || HasExtension(path, ".html", ".htm", ".xml", ".txt", ".pdf")) return "文档";
        return "其他";
    }

    private static bool HasExtension(string path, params string[] extensions) =>
        extensions.Any(extension => path.EndsWith(extension, StringComparison.OrdinalIgnoreCase));
}

public sealed class TrafficGroupRow(TrafficGroup source)
{
    public TrafficGroup Source { get; } = source;
    public int Ordinal { get; init; }
    public string Name => Source.Name;
    public string NumberedName => $"#{Ordinal} {Source.Name}";
    public string Detail => $"{Source.TrafficIds.Count:N0} 条事务 · {Source.UpdatedAt.ToLocalTime():MM-dd HH:mm}";
}

public sealed class WorkspaceRow(WorkspaceDescriptor source)
{
    public WorkspaceDescriptor Source { get; } = source;
    public string DisplayName => $"{Source.Manifest.Name}  ·  {Source.Manifest.LastOpenedAt.ToLocalTime():MM-dd HH:mm}";
    public override string ToString() => DisplayName;
}

public sealed class AiHistoryRow(AiAnalysisHistoryMetadata source)
{
    public AiAnalysisHistoryMetadata Source { get; } = source;
    public string DisplayName => $"{Source.CreatedAt.ToLocalTime():MM-dd HH:mm} · {Source.Model} · {Source.TransactionIds.Count} 条 · {Source.ScopeName}";
    public override string ToString() => DisplayName;
}

public sealed class AiConversationRow(AiConversationSummary source, string templateDisplayName)
{
    public AiConversationSummary Source { get; } = source;
    public string DisplayName => $"{templateDisplayName} · {Source.CreatedAt.ToLocalTime():MM-dd HH:mm} · {Source.TurnCount} 轮 · {Source.ScopeName}";
    public override string ToString() => DisplayName;
}

public sealed class SessionRow(CaptureSessionSummary summary)
{
    public Guid SessionId => summary.Session.Id;
    public string StartedAt => summary.Session.StartedAt.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");
    public string Mode => summary.Session.Mode;
    public string Target => summary.Session.Target;
    public string State => summary.Session.State;
    public string TransactionCount => summary.TransactionCount.ToString("N0");
    public bool Matches(CaptureSessionSummary candidate) => summary == candidate;
    public string Duration
    {
        get
        {
            var duration = (summary.Session.EndedAt ?? DateTimeOffset.UtcNow) - summary.Session.StartedAt;
            return duration.TotalHours >= 1 ? $"{duration.TotalHours:0.0} 小时" : duration.TotalMinutes >= 1 ? $"{duration.TotalMinutes:0.0} 分钟" : $"{Math.Max(0, duration.TotalSeconds):0} 秒";
        }
    }
}

/// <summary>脚本库列表行。用途与「是否采集钩子」会在界面上原地变化，所以需要变更通知。</summary>
public sealed class ScriptRow(ScriptLibraryItem item) : INotifyPropertyChanged
{
    private ScriptPurpose _purpose = item.Purpose;
    private bool _isActiveHook;

    public string FileName { get; } = item.FileName;
    public string FullPath { get; } = item.FullPath;
    public ScriptPurpose Purpose => _purpose;

    public bool IsActiveHook
    {
        get => _isActiveHook;
        set
        {
            if (_isActiveHook == value) return;
            _isActiveHook = value;
            OnPropertyChanged(nameof(IsActiveHook));
            OnPropertyChanged(nameof(StateText));
        }
    }

    public string StateText => _isActiveHook ? "采集启用" : string.Empty;
    public string PurposeText => _purpose == ScriptPurpose.Fixture ? "验证脚本" : "钩子脚本";
    public string Detail => $"{PurposeText} · {item.UpdatedAt.ToLocalTime():MM-dd HH:mm} · {FormatSize(item.SizeBytes)}";

    public void SetPurpose(ScriptPurpose purpose)
    {
        if (_purpose == purpose) return;
        _purpose = purpose;
        OnPropertyChanged(nameof(Purpose));
        OnPropertyChanged(nameof(PurposeText));
        OnPropertyChanged(nameof(Detail));
    }

    private static string FormatSize(long bytes) =>
        bytes >= 1024 ? $"{bytes / 1024.0:0.#} KB" : $"{bytes} B";

    public event PropertyChangedEventHandler? PropertyChanged;

    private void OnPropertyChanged(string propertyName) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}

/// <summary>钩子脚本试跑返回的一条结论，用于「运行结果」下方的可回看列表。</summary>
public sealed class ScriptFindingRow
{
    public required string Time { get; init; }
    /// <summary>"试跑"（工作台内点「运行」产出）或 "实时抓包"（真实采集时由 CoreHost 经审计日志落盘）。</summary>
    public required string Source { get; init; }
    public required string Event { get; init; }
    public required string Script { get; init; }
    public required string Summary { get; init; }
    public required string FullJson { get; init; }
}
