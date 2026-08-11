using System.Reflection;
using System.Text.Json;

namespace NetMind.Core;

/// <summary>
/// 钩子脚本可见的 API 词表。
///
/// 编辑器补全、示例模板与文档共用这一份：<c>event</c> 字典的字段名直接反射
/// <see cref="HookEventEnvelope"/> 得到，序列化命名策略也取自同一份 <see cref="HookEventEnvelope.JsonOptions"/>，
/// 因此契约一改，提示立刻跟着改，不会出现「照着提示写、运行时取不到值」的情况。
/// 说明文字是人工维护的，但 <c>--intercept-only</c> 会断言每个反射出的字段都有说明，漏写即测挂。
/// </summary>
public static class HookScriptApi
{
    /// <summary>一个可补全的符号。<paramref name="Insert"/> 是实际插入编辑器的文本。</summary>
    /// <param name="Name">显示名。</param>
    /// <param name="Insert">插入文本；与显示名不同时用于补上引号、括号等。</param>
    /// <param name="Detail">中文说明，补全列表右侧展示。</param>
    public sealed record Symbol(string Name, string Insert, string Detail);

    /// <summary>事件字段说明。键必须覆盖 <see cref="HookEventEnvelope"/> 的全部序列化字段。</summary>
    private static readonly Dictionary<string, string> EventFieldDetails = new(StringComparer.Ordinal)
    {
        ["event"] = "挂载点事件名，如 request.before_send",
        ["txnId"] = "事务标识；同一事务的四个挂载点共用，用它关联请求与响应",
        ["sessionId"] = "捕获会话标识",
        ["hookName"] = "本次触发对应的钩子函数名",
        ["method"] = "HTTP 方法",
        ["url"] = "完整请求 URL",
        ["host"] = "主机名",
        ["endpoint"] = "路径与查询串",
        ["statusCode"] = "响应状态码；请求发送前为 None",
        ["headers"] = "请求或响应头字典",
        ["bodyPreviewBase64"] = "正文预览（Base64）；超过预览上限时被截断",
        ["bodyTruncated"] = "正文预览是否被截断",
        ["bodySha256"] = "完整正文的 SHA-256",
        ["bodySize"] = "完整正文字节数",
        ["schema"] = "信封协议版本号"
    };

    /// <summary>
    /// <c>event</c> 字典可用字段。名称来自反射，不是手写常量——契约新增字段时提示自动出现。
    /// </summary>
    public static IReadOnlyList<Symbol> EventFields { get; } = BuildEventFields();

    private static Symbol[] BuildEventFields()
    {
        var naming = HookEventEnvelope.JsonOptions.PropertyNamingPolicy ?? JsonNamingPolicy.CamelCase;
        return [.. typeof(HookEventEnvelope)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Where(property => property.GetIndexParameters().Length == 0)
            // Snapshot 是宿主内部携带的引用，不会序列化进信封，脚本自然也看不到。
            .Where(property => property.GetCustomAttribute<System.Text.Json.Serialization.JsonIgnoreAttribute>() is null)
            .Select(property => naming.ConvertName(property.Name))
            .Distinct(StringComparer.Ordinal)
            .OrderBy(name => name, StringComparer.Ordinal)
            .Select(name => new Symbol(name, $"'{name}'",
                EventFieldDetails.TryGetValue(name, out var detail) ? detail : "（尚未补充说明）"))];
    }

    /// <summary>宿主注入脚本命名空间的 store 对象成员。</summary>
    public static IReadOnlyList<Symbol> StoreMembers { get; } =
    [
        new("save", "save('', )", "写入键值：store.save('名称', 文本或对象)"),
        new("load", "load('')", "读取键值，不存在返回 None"),
        new("list", "list()", "列出全部键"),
        new("delete", "delete('')", "删除指定键")
    ];

    /// <summary>
    /// 四个挂载点对应的钩子函数。插入文本是完整签名骨架。
    /// 默认拒绝转发：定义了函数不代表会被调用，必须在 OBSERVE（非阻塞）或 INTERCEPT（阻塞、
    /// 仅限两个可改写挂载点）中声明匹配规则，宿主才会把命中的事件转发过来。
    /// </summary>
    public static IReadOnlyList<Symbol> HookFunctions { get; } =
    [
        new(HookEventNames.FunctionBeforeSend, $"def {HookEventNames.FunctionBeforeSend}(event):\n    return None\n",
            "请求发往上游之前触发；需在 OBSERVE 或 INTERCEPT 中声明匹配规则才会被调用，INTERCEPT 命中时可拦截改写"),
        new(HookEventNames.FunctionAfterSend, $"def {HookEventNames.FunctionAfterSend}(event):\n    return None\n",
            "请求已发往上游之后触发；只能通过 OBSERVE 声明（此挂载点不支持 INTERCEPT）"),
        new(HookEventNames.FunctionBeforeWrite, $"def {HookEventNames.FunctionBeforeWrite}(event):\n    return None\n",
            "响应写回浏览器之前触发；需在 OBSERVE 或 INTERCEPT 中声明匹配规则才会被调用，INTERCEPT 命中时可拦截改写"),
        new(HookEventNames.FunctionAfterDeliver, $"def {HookEventNames.FunctionAfterDeliver}(event):\n    return None\n",
            "响应已交付浏览器之后触发；只能通过 OBSERVE 声明（此挂载点不支持 INTERCEPT）")
    ];

    /// <summary>规则可用字段（OBSERVE 与 INTERCEPT 共用同一套形状）；全部是正则，条件之间是 AND。</summary>
    private static IReadOnlyList<Symbol> BuildRuleFields(string eventDetail) =>
    [
        new("event", "'event': ''", eventDetail),
        new("url", "'url': r''", "URL 正则"),
        new("method", "'method': r''", "HTTP 方法正则"),
        new("host", "'host': r''", "主机名正则"),
        new("endpoint", "'endpoint': r''", "路径与查询串正则"),
        new("body", "'body': r''", "正文正则；只匹配前 64 KB"),
        new("status", "'status': r''", "状态码正则；仅响应侧有意义"),
        new("headers", "'headers': {'': r''}", "{头名: 值正则}；值为空串表示只要求该头存在")
    ];

    /// <summary>INTERCEPT 规则可用字段。</summary>
    public static IReadOnlyList<Symbol> InterceptRuleFields { get; } =
        BuildRuleFields($"挂载点，只能是 {HookEventNames.RequestBeforeSend} 或 {HookEventNames.ResponseBeforeWrite}");

    /// <summary>OBSERVE 规则可用字段；四个挂载点都能声明，字段形状与 INTERCEPT 一致。</summary>
    public static IReadOnlyList<Symbol> ObserveRuleFields { get; } =
        BuildRuleFields("挂载点，四个均可，见 on_before_send / on_after_send / on_before_write / on_after_deliver");

    /// <summary>拦截命中时钩子函数返回值可用字段；返回 None 表示原样放行。</summary>
    public static IReadOnlyList<Symbol> MutationFields { get; } =
    [
        new("url", "'url': ''", "改写请求 URL；仅请求侧，只接受 http(s) 绝对地址"),
        new("method", "'method': ''", "改写 HTTP 方法；仅请求侧"),
        new("status", "'status': 200", "改写响应状态码；仅响应侧"),
        new("headers", "'headers': {'': ''}", "覆盖或新增头；值为 None 表示删除该头"),
        new("body", "'body': ''", "改写正文；Content-Length 由宿主按实际长度重算"),
        new("finding", "'finding': {}", "顺带产出的观察结论，写入审计日志")
    ];

    /// <summary>挂载点事件名，供 INTERCEPT 的 event 字段补全；只有两个可改写挂载点。</summary>
    public static IReadOnlyList<Symbol> InterceptEvents { get; } =
    [
        new(HookEventNames.RequestBeforeSend, $"'{HookEventNames.RequestBeforeSend}'", "请求发往上游之前；可改写"),
        new(HookEventNames.ResponseBeforeWrite, $"'{HookEventNames.ResponseBeforeWrite}'", "响应写回浏览器之前；可改写")
    ];

    /// <summary>挂载点事件名，供 OBSERVE 的 event 字段补全；四个挂载点都可以声明观察。</summary>
    public static IReadOnlyList<Symbol> ObserveEvents { get; } =
    [
        new(HookEventNames.RequestBeforeSend, $"'{HookEventNames.RequestBeforeSend}'", "请求发往上游之前；只观察不改写"),
        new(HookEventNames.RequestAfterSend, $"'{HookEventNames.RequestAfterSend}'", "请求已发往上游之后"),
        new(HookEventNames.ResponseBeforeWrite, $"'{HookEventNames.ResponseBeforeWrite}'", "响应写回浏览器之前；只观察不改写"),
        new(HookEventNames.ResponseAfterDeliver, $"'{HookEventNames.ResponseAfterDeliver}'", "响应已交付浏览器之后")
    ];

    /// <summary>钩子脚本可见的全部符号，供按词前缀的模糊补全使用。</summary>
    public static IReadOnlyList<Symbol> HookVocabulary { get; } =
    [
        .. HookFunctions,
        new("OBSERVE", "OBSERVE = [\n    {'event': '', 'url': r''},\n]\n", "模块级观察规则声明；未命中的挂载点/流量不会被转发，这是默认行为"),
        new("INTERCEPT", "INTERCEPT = [\n    {'event': '', 'url': r''},\n]\n", "模块级拦截规则声明；只有命中的流量才阻塞等待裁决"),
        new("event", "event", "钩子函数入参，字段见 event.get('…')"),
        new("store", "store", "宿主注入的键值存储，落盘在工作区 scripts/data")
    ];

    // ── 验证脚本（沙箱 fixture）词表 ─────────────────────────────────────────────

    /// <summary>验证脚本事务字段说明。键必须覆盖 fixture 事务的全部序列化字段。</summary>
    private static readonly Dictionary<string, string> FixtureFieldDetails = new(StringComparer.Ordinal)
    {
        ["method"] = "HTTP 方法",
        ["url"] = "完整请求 URL（已脱敏）",
        ["host"] = "主机名",
        ["endpoint"] = "路径与查询串",
        ["status"] = "响应状态码",
        ["latency_ms"] = "耗时（毫秒）",
        ["size_bytes"] = "响应字节数",
        ["protocol"] = "协议",
        ["process"] = "发起请求的进程名",
        ["request_summary"] = "请求摘要（已脱敏）",
        ["response_summary"] = "响应摘要（已脱敏）"
    };

    /// <summary>
    /// <c>fixture.transactions</c> 中每条事务的字段。名称同样来自反射
    /// （<see cref="AiPrivacyFilter.RedactedScriptTransaction"/> 上的 JsonPropertyName），不是手抄的常量。
    /// </summary>
    public static IReadOnlyList<Symbol> FixtureFields { get; } = BuildFixtureFields();

    private static Symbol[] BuildFixtureFields() =>
        [.. typeof(AiPrivacyFilter.RedactedScriptTransaction)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Where(property => property.GetIndexParameters().Length == 0)
            .Select(property => property
                .GetCustomAttribute<System.Text.Json.Serialization.JsonPropertyNameAttribute>()?.Name ?? property.Name)
            .Distinct(StringComparer.Ordinal)
            .OrderBy(name => name, StringComparer.Ordinal)
            .Select(name => new Symbol(name, name,
                FixtureFieldDetails.TryGetValue(name, out var detail) ? detail : "（尚未补充说明）"))];

    /// <summary>验证脚本可见的全部符号，供按词前缀的模糊补全使用。</summary>
    public static IReadOnlyList<Symbol> FixtureVocabulary { get; } =
    [
        new("fixture", "from netmind import fixture\n", "沙箱注入的输入对象；脚本首行导入"),
        new("transactions", "fixture.transactions", $"最近 {AiPrivacyFilter.ScriptFixtureMaximumTransactions} 条已脱敏事务的列表"),
        .. FixtureFields
    ];

    // ── AI 代写脚本的系统提示词 ────────────────────────────────────────────────

    /// <summary>
    /// 生成让模型代写脚本的系统提示词。
    ///
    /// 字段清单直接由上面那些反射来的词表拼出，不另抄一份：模型看到的契约与编辑器补全、
    /// 与运行时是同一个来源，避免出现「AI 写得很像、跑起来取不到值」。
    /// </summary>
    public static string BuildAuthoringSystemPrompt(ScriptPurpose purpose)
    {
        var builder = new System.Text.StringBuilder();
        builder.AppendLine("你是 NetMind AI 工作台的 Python 脚本助手。用户描述需求，你直接产出可运行的脚本。");
        builder.AppendLine();
        builder.AppendLine("输出要求（严格遵守）：");
        builder.AppendLine("- 直接输出一个 ```python 代码块，块外不要有任何文字。");
        builder.AppendLine("- 不要输出思考过程、方案对比、注意事项、使用说明或任何前后缀，一个字都不要。");
        builder.AppendLine("- 需要解释的内容一律写成代码里的中文注释，注释要能让人看懂为什么这么写。");
        builder.AppendLine("- 不要臆造 API：只能使用下面列出的字段与函数。");
        builder.AppendLine();
        builder.AppendLine("运行环境（沙箱强制，违反会被静态策略直接拒绝，不会启动 Python）：");
        builder.AppendLine("- 禁止导入：os、sys、subprocess、socket、ctypes、pathlib、shutil、winreg、multiprocessing、http、urllib。");
        builder.AppendLine("- 禁止调用：open()、exec()、eval()、compile()、__import__()、input()、breakpoint()。");
        builder.AppendLine("  注意静态策略按文本匹配，注释和字符串里出现这些调用同样会被拒。");
        builder.AppendLine("- 可用纯逻辑标准库：json、math、re、datetime、collections、itertools、functools、statistics。");
        builder.AppendLine("- 无网络、无文件系统、无第三方包。");
        builder.AppendLine();

        if (purpose == ScriptPurpose.Fixture)
        {
            builder.AppendLine("脚本类型：验证脚本。顶层顺序执行一次，用 print() 输出结论，用 assert 表达规则；");
            builder.AppendLine("退出码 0 为验证通过，非 0（含 assert 失败）为验证失败。");
            builder.AppendLine();
            builder.AppendLine("输入：");
            builder.AppendLine("```python");
            builder.AppendLine("from netmind import fixture");
            builder.AppendLine($"# fixture.transactions：最近 {AiPrivacyFilter.ScriptFixtureMaximumTransactions} 条已脱敏事务，按点号访问字段");
            builder.AppendLine("```");
            builder.AppendLine();
            builder.AppendLine("每条事务的字段：");
            AppendSymbols(builder, FixtureFields);
            builder.AppendLine();
            builder.AppendLine("注意：字段值已脱敏，令牌、密钥、Cookie 原值不会出现，不要基于它们做判断。");
            builder.AppendLine("流量表可能为空（刚开始采集），需要断言非空时请给出清晰的中文失败原因。");
            return builder.ToString();
        }

        builder.AppendLine("脚本类型：钩子脚本。采集期间由隔离工作进程按挂载点调用，定义下面这些函数（只定义需要的）：");
        AppendSymbols(builder, HookFunctions);
        builder.AppendLine();
        builder.AppendLine("入参 event 是 dict，用 event.get('字段') 读取：");
        AppendSymbols(builder, EventFields);
        builder.AppendLine();
        builder.AppendLine("=== 默认拒绝转发：这是最容易写错的地方，必须严格遵守 ===");
        builder.AppendLine("定义了钩子函数不代表它会被调用。没有 OBSERVE 也没有 INTERCEPT 声明匹配到的挂载点，");
        builder.AppendLine("宿主根本不会把事件转发过来，函数体永远不会执行——不会报错，只是安静地什么都不发生。");
        builder.AppendLine("按用户的需求选择声明哪一种，两者可以同时使用，但不要在同一个挂载点上重复声明同一条件");
        builder.AppendLine("（会导致同一个事件触发两次函数调用）：");
        builder.AppendLine();
        builder.AppendLine("① 只想观察/记录特定流量、不修改任何内容 → 用 OBSERVE。四个挂载点都可以声明，非阻塞：");
        builder.AppendLine("```python");
        builder.AppendLine("OBSERVE = [");
        builder.AppendLine("    {'event': 'response.before_write', 'url': r'/api/target'},");
        builder.AppendLine("]");
        builder.AppendLine("```");
        AppendSymbols(builder, ObserveRuleFields);
        builder.AppendLine("规则一定要按用户描述的目标收窄（写 url/host/endpoint 等条件）：不写任何条件、只写");
        builder.AppendLine("{'event': '...'} 等于要求转发这个挂载点的全部流量，几乎总不是用户真正想要的，会制造大量噪声。");
        builder.AppendLine();
        builder.AppendLine("② 需要修改请求/响应内容 → 用 INTERCEPT。只能声明在两个可改写挂载点上，命中的请求会阻塞");
        builder.AppendLine("等待脚本裁决，其余流量仍是即发即忘：");
        AppendSymbols(builder, InterceptRuleFields);
        builder.AppendLine($"event 只能是 {HookEventNames.RequestBeforeSend} 或 {HookEventNames.ResponseBeforeWrite}，其余挂载点不可改写。");
        builder.AppendLine("命中时钩子函数的返回值即改写内容：");
        AppendSymbols(builder, MutationFields);
        builder.AppendLine("返回 None 表示原样放行。裁决超时、脚本异常或改写超限一律按原样放行，不会阻塞浏览器。");
        builder.AppendLine();
        builder.AppendLine($"正文预览默认不下发：脚本文本里出现 {NetMindDefaults.HookBodyPreviewFieldName}");
        builder.AppendLine($"（或写一行 {NetMindDefaults.HookWantBodyDeclaration} = True）时宿主才会带上，只用 bodySize/bodySha256 时不必声明。");
        builder.AppendLine();
        builder.AppendLine("宿主注入的 store 对象（直接用，不能也不需要 import）：");
        AppendSymbols(builder, StoreMembers);
        builder.AppendLine("store 落盘在工作区 scripts/data；单文件上限 1 MB，目录总量 64 MB。");
        builder.AppendLine();
        builder.AppendLine("=== 返回值含义看触发路径，不是看函数名：这是第二容易写错的地方 ===");
        builder.AppendLine("被 OBSERVE 触发时：返回 None 表示什么都不做（不写审计）；返回 dict 本身就是一条观察结论，直接写入审计日志。");
        builder.AppendLine("被 INTERCEPT 触发时：返回值只按上面 MutationFields 列出的字段解析，其余字段一律忽略、不会自动变成结论——");
        builder.AppendLine("想同时留一条结论必须嵌套在 finding 键下，例如：");
        builder.AppendLine("  return {'finding': {'kind': '...'}}  # 只想记录不改写：headers/body/status/url/method 都不要给");
        builder.AppendLine("千万不要把业务字段直接摊平在顶层 return（尤其字段名恰好撞上 url/status 等改写字段名时），");
        builder.AppendLine("会被当成改写指令静默处理掉，结论也不会被记录，且没有任何报错提示。只想观察不改写时优先用");
        builder.AppendLine("OBSERVE 而不是 INTERCEPT，能从根上避免这个混淆。结论上限 4 KB，请只在确有发现时返回，否则每个请求都会产生噪声。");
        builder.AppendLine();
        builder.AppendLine("性能约束：单个事件有 200 毫秒看门狗，工作进程是单线程串行处理。");
        builder.AppendLine("不要写正则回溯爆炸、长循环或大对象拼接，超时会被跳过并记为错误。");
        return builder.ToString();
    }

    private static void AppendSymbols(System.Text.StringBuilder builder, IReadOnlyList<Symbol> symbols)
    {
        foreach (var symbol in symbols) builder.Append("- ").Append(symbol.Name).Append("：").AppendLine(symbol.Detail);
    }

    /// <summary>从模型回复里取出 Python 代码：优先取 ```python 围栏，其次任意围栏，最后按纯代码处理。</summary>
    public static string ExtractPythonCode(string reply)
    {
        if (string.IsNullOrWhiteSpace(reply)) return string.Empty;
        var text = reply.Replace("\r\n", "\n", StringComparison.Ordinal);
        var start = text.IndexOf("```python", StringComparison.OrdinalIgnoreCase);
        var skip = 9;
        if (start < 0)
        {
            start = text.IndexOf("```", StringComparison.Ordinal);
            skip = 3;
        }
        if (start < 0) return text.Trim();
        var bodyStart = start + skip;
        var newline = text.IndexOf('\n', bodyStart);
        if (newline < 0) return text.Trim();
        var end = text.IndexOf("```", newline, StringComparison.Ordinal);
        return (end < 0 ? text[(newline + 1)..] : text[(newline + 1)..end]).Trim();
    }
}
