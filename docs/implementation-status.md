# Implementation status

## 2026-08-11 钩子默认拒绝转发：OBSERVE 显式声明取代"勾选即转发全部"

- **用户报告的症状**：脚本页「返回数据」列表"一大堆根本无法查找"。排查发现真实原因不是列表本身，而是观察路径的转发语义——`INTERCEPT` 只决定"要不要阻塞等裁决"，从不决定"要不要转发"；`ScriptHookEngine.Emit()` 此前对某挂载点只要在 `hook-config.json` 里勾选，就无条件转发该点**全部**流量，脚本只能自己在函数体内按 URL 过滤。用户当时激活的脚本 `on_before_write` 没做这个过滤，于是采集到的每一条 HTTP 响应都被处理、`store.save` 一次：工作区 `scripts/data` 下堆了 65 个文件，真正对应目标接口的只有 4 个。更严重的是：命中 `INTERCEPT` 规则的 URL 还会被**双重处理**——一次经阻塞的 intercept 消息，一次经无条件的 observe 消息，同一个事件调用两次函数。
- **修法是把过滤的责任从"脚本作者自己记得写 if"搬到宿主强制**：新增脚本模块级 `OBSERVE` 声明（规则形状与 `INTERCEPT` 完全一致——url/method/host/endpoint/body/status/headers 全是正则，条件之间 AND），`ScriptHookEngine.Emit()` 改为默认拒绝转发：挂载点已勾选、但没有 `OBSERVE`/`INTERCEPT` 规则命中的事件，一条都不会送到脚本，函数体不会执行，也不报错。`INTERCEPT` 与 `OBSERVE` 是两条独立路径，互不依赖，同一挂载点只声明一种就不会再有双重调用。
- `HookInterceptRule` 与新增的 `HookObserveRule` 共用同一份正则子句实现（抽出 `HookRuleClauses`）：两者的匹配逻辑必须永远同步，写两份迟早会在某次改动里悄悄分叉。`HookObserveRule` 唯一的区别是事件名校验允许全部四个挂载点（`INTERCEPT` 只认两个可改写的）。
- 新增 `ScriptHookEngine.NotObservedEventCount`：挂载点已启用但未命中 OBSERVE 规则而被就地丢弃的计数，与队列背压丢弃（`DroppedEvents`，原因是队列满）分开统计——前者通常意味着脚本忘了声明 OBSERVE，后者意味着流量太大。工作台「试跑」用它算出真正指望被处理的事件数，不会再对着永远不会来的 `processed` 回执傻等 5 秒超时。
- SandboxHost 的 Python 驱动模板同步：`INTERCEPT`/`OBSERVE` 的解析抽成一个函数复用，`ready` 消息新增 `observe` 字段；宿主侧过滤，worker 端不做转发判断（一贯的设计：单线程 worker 不背匹配逻辑）。
- 影响面排查：工作区里另外两份脚本（`hook-ip.py`、`hook-script.py`）与随包示例 `docs/samples/hook-baidu-search-888.py` 全部只用 `INTERCEPT`，天然兼容新语义、无需改动；默认钩子模板与两个"只观察"类的插入示例补了 `OBSERVE` 声明。AI 代写系统提示词新增"默认拒绝转发"专节，教模型按需求选择 `OBSERVE`/`INTERCEPT`，避免生成的脚本重犯同一个错误。编辑器补全按最近声明的是 `OBSERVE` 还是 `INTERCEPT` 给出对应的挂载点候选（前者四个，后者两个）。
- 定向验证：新增 `--observe-only`（四挂载点声明、AND 组合、词表与 AI 提示词同源）；`--mountpoint-only` 补充默认拒绝转发的正面/反面断言（未声明不转发、声明但不命中不转发、两种情况都计入 `NotObservedEventCount`）；`--hooks-only`/`--intercept-only`/`--baidu-intercept-only` 均通过。默认全量 34 个套件通过，Release 构建 0 警告 0 错误。

## 2026-08-11 设置页孤儿钩子开关清理与百度搜索拦截示例

- **设置页那个「请求钩子」开关是个死控件**：`SettingsHooksBox` 连同它的标题与整块 `Border` 都是 `Visibility="Collapsed"`，用户在设置页根本看不到它。而 CoreHost 早在之前的重构里就改成只认工作区 `hook-config.json`（`TryCreateHookEngineAsync` 注释：「旧版全局 EnableTrafficHooks 字段仅保留配置兼容，不再形成第二道无语义差异的门控」）——也就是说这个开关既看不见，也早就不起作用了。
- 真正有害的不是控件本身，而是**没跟着改的文案**：脚本页 `HookEnabledBox` 的 ToolTip 仍写着「还需在设置页开启『请求钩子』总开关，两者同时满足才会拉起钩子工作进程」。用户照着去设置页找，找不到，于是合理地得出「挂载不了脚本」的结论。挂载链路其实一直是通的。
- 处理：删掉死控件与那段陈述第二道门控的说明，设置页改为**可见的只读入口**——一行「当前工作区：已启用 · 挂载点 N/4 · 钩子脚本 X」状态回显加一个「去脚本页配置」按钮。状态由 `UpdateHookStatusLine` 一处产出，脚本页与设置页共用同一份事实，不会出现两处各说各话。
- `EnableTrafficHooks` 字段在 `WorkbenchSettings` 中保留（旧设置文件 JSON 兼容），但界面不再读写；`ReadWorkbenchSettingsFromUi` 原样透传 `_settings.EnableTrafficHooks` 而不是写死 `false`，否则用户旧文件里的 `true` 会在下次保存时被静默清掉。
- 新增示例脚本 `docs/samples/hook-baidu-search-888.py`：用模块级 `INTERCEPT` 命中百度网页搜索（`method ^GET$` + `endpoint ^/s\?` + `url [?&](wd|word)=`），在 `on_before_send` 里把关键字参数固定为 `888`，其余查询参数逐项原样保留；关键字已经是 888 时返回 `None` 不改写。刻意不加 `host` 条件，好处是同一份脚本对 `www.baidu.com`、`m.baidu.com` 与本地回环测试都成立，脚本头部注明了想收窄时该加哪一条。
- 新增定向套件 `--baidu-intercept-only`：**真实** SandboxHost `hook-worker` + **真实** Python + **真实** `ExplicitHttpProxy` + 本地上游，断言上游实际收到的请求行是 `GET /s?wd=888&rsv_spt=1`。只测 `HookInterceptRule` 是不够的——规则匹配、worker 上报、代理阻塞裁决、改写回写请求行这四段里断任何一段，用户看到的都是「脚本没生效」，而单测规则匹配对其中三段一无所知。套件直接读仓库里那一份示例脚本，不另抄副本，抄一份就会漂移。
- 套件同时断言：未命中的 `/nosearch?wd=…` 原样透传、改写不得吞掉同查询串里的其他参数、示例脚本能通过 `PythonSandboxPolicy` 静态策略（否则用户保存时就会被拒）。本机无 Python 时跳过不计失败，与既有钩子端到端子断言一致。
- 反向验证过套件确实会红：把示例里的 `FIXED_KEYWORD` 改成 `777`，套件失败并打印实际请求行 `GET /s?wd=777&rsv_spt=1`——证明断言跑的是真实链路而不是恒真。
- 定向验证：`--baidu-intercept-only`（新增）、`--intercept-only`、`--hooks-only`、`--mountpoint-only`、`--settings-only`、`--script-library-only` 全部通过。

## 2026-08-11 钩子信封瘦身、编辑器折叠/注释/格式化与 AI 代写脚本

- **开启钩子后界面发涩，先量再改**：写了个基准跑一次典型页面加载（100 个资源、正文合计 7.7 MB、四个挂载点）。Base64 本身只有 13 毫秒，不是问题；真正的开销是**信封 JSON 序列化后要往单线程 Python 工作进程推 36.9 MB**，宿主侧序列化 189 毫秒，还伴随大量大对象堆分配——LOH 回收会暂停包括界面线程在内的所有线程。
- 修法是把正文预览改成**按需下发**：观察事件默认只送 `bodySize` 与 `bodySha256`，脚本文本里出现 `bodyPreviewBase64`（或写 `WANT_BODY = True`）才带上正文。同一场景实测降到 **0.18 MB / 17 毫秒**（数据量 −99.5%、耗时 −91%）。拦截命中的事件不受此约束，一律带全正文——脚本声明规则就是冲着改它来的。读不到脚本时按"需要"处理，宁可多带也不能让脚本拿到空正文。
- 顺带把预览与 SHA-256 一起挪到泵线程惰性计算并在快照内缓存。此前 `response.before_write` 的 Base64 发生在把响应字节写回浏览器**之前**，等于把编码时间直接加进浏览器等待；而响应侧两个挂载点共用同一份正文，却各编码了一次。SHA-256 早就是惰性缓存的，Base64 被漏掉了。
- 页内 Hook 列表此前每 1.5 秒无条件重建 `ItemsSource`：没有新事件也整表重排，还会把用户选中的行清掉。改为按数据库 rowid 比对，内容没变直接返回，变了也保留原选中行。
- 新增 `ScriptTextTools`（放在 Core 以便冒烟覆盖——这些函数直接改用户写了一半的脚本，改坏就是数据损坏）：
  - **Ctrl+/ 切换注释**：多行整体切换，注释符插在这批行的最小缩进处而非行首，相对缩进不变；空行不动；取消注释只吃掉一个紧跟的空格，不破坏对齐注释。
  - **整理格式**：只做不改变语义的事——行首制表符转 4 空格、去行尾空白、连续空行压到两行、结尾一个换行。开发中被自己的测试抓到一个真 bug：打开三引号的那一行也被 TrimEnd 了，而引号之后已经是字符串数据，去空白等于改值；现在打开三引号的行与整个字符串内部一个字符都不动。
  - **折叠区域**按缩进识别，体少于两行的区域不返回（占位行本身也占一行，折了不省高度）。
- **代码折叠**用占位段落模型：被折的行从文档摘出来存在 `_folds`，`GetScriptText` 遍历 Blocks 时遇到占位段落还原隐藏文本，因此折叠状态下保存/运行拿到的仍是完整脚本——这是这套实现唯一不能出错的地方。折叠只是视图状态，任何整体替换内容的操作都会清空它。
- **右键菜单**补齐撤销/重做/剪切/复制/粘贴/全选之外的切换注释、整理格式、智能提示、折叠当前块/全部、展开全部，并标注快捷键。
- **让 AI 写脚本**：编辑器下方输入需求即可。系统提示词由 `HookScriptApi.BuildAuthoringSystemPrompt` 生成，字段清单直接取自与编辑器补全、与运行时同一份反射词表，模型看到的契约不会漂移；同时写入静态策略禁止清单与 200 毫秒看门狗约束。生成结果先过一遍 `PythonSandboxPolicy`，命中禁止项当场提示需要修改，而不是等点了运行才报"策略拒绝"。一次性调用，不带工具，不写入 AI 分析会话历史。
- 定向验证：新增 `--script-text-only`（注释切换往返、整理格式幂等与三引号保真、折叠区域还原逐字节一致、代写提示词必须列出全部反射字段、代码块提取）与 `--hook-payload-only`（预览下发判定规则）。

## 2026-08-11 脚本页重做、多脚本管理与按进程采集崩溃修复

- **按进程采集必崩**：`ProcessPickerWindow` 用 `Width = width ?? double.NaN` 给 DataGrid 列设宽，而 `DataGridLength` 对 NaN 与无穷大都抛「不应允许无限值」。这条路径**从写下那天起就没成功过**——不是偶发，是每次点击都在窗口构造函数里抛。列宽改用 `DataGridLength`（`Auto` / 固定值 / `1*`），不再借用 `FrameworkElement.Width` 那套「NaN 表示自动」的约定。定位靠的是上一轮加的全局异常兜底写出的 `workbench-crash.log`：完整栈直接指到行号，没有它只能看到工作台弹一个框。
- **脚本页有两个输入框**：`ScriptEditor`（页面下方的大编辑器，跑 fixture 验证）和 `HookScriptEditor`（折叠面板里的钩子脚本）。真正在采集期间执行的是折叠起来的那个，页面上最显眼的那个反而只是一次性验证——入口指向完全反了。智能提示只挂在钩子编辑器上，用户在大编辑器里怎么敲都不会弹。现在合并为**一个编辑器**，脚本的「用途」（钩子脚本 / 验证脚本）决定「运行」做什么，页面改为「脚本库 / 编辑器 / 采集钩子与运行结果」三栏。
- **多脚本管理**（此前记为未完成项）：新增 `ScriptLibraryStore`。设计上**目录即真相**——库的内容就是工作区 `scripts/*.py`，直接枚举得到；只有「用途」这一位无法从内容可靠推断的信息落在 sidecar `script-library.json` 里。这样外部增删 `.py` 能被正确反映，也不会出现清单有、磁盘没有的幽灵条目。sidecar 损坏时退回内容推断，脚本库不会因此不可用。
- 脚本名来自用户输入且会拼进工作区路径，`NormalizeFileName` 是唯一的路径穿越防线：补 `.py`、拒绝路径分隔符 / `.` / `..` / 文件系统非法字符 / 超长名。`--script-library-only` 用 15 个敌意名字（含 `../escape`、`sub\child`、`bad:name`）断言全部被拒。
- **智能提示不触发**的首要原因是快捷键：`Ctrl+空格` 是 Windows 中文输入法的中英文切换键，**这个组合根本到不了应用**。改为 `Ctrl+J` 为主、`Alt+/` 备选，三个都监听。同时把自动触发从「只认几个固定形态」放宽到「任意标识符前两个字母」，并抑制注释内弹出；字典字面量里按上下文区分 INTERCEPT 规则字段与改写字段（跨行有效，回看 600 字符做括号配对）。补全弹层改为 `StaysOpen` + 焦点祖先判断，避免点击列表时先被失焦逻辑关掉。
- 验证脚本也有了补全：`fixture` 事务字段反射自 `AiPrivacyFilter.RedactedScriptTransaction` 的 `JsonPropertyName`，与钩子 `event` 字段同样是反射得来，不是手抄常量。测试断言词表与真实序列化字段**双向完全一致**，照提示写不会取不到值。
- **消除前置条件报错**：试跑此前在「没有流量」和「未勾选挂载点」两种常见状态下直接抛异常——而每次开始采集列表都是空的，等于刚开始采集时按钮必然报错。现在无流量用内置示例事务、未勾挂载点按四点全开试跑，并在结果里说明；运行结果统一落到右侧「运行结果」面板，不再散在状态行。
- 顺带修掉「插入示例」按钮的假死：旧实现在 `ContextMenu` 已存在时直接 return，而菜单只在点中菜单项时才被清空——用户点开菜单后点别处关掉，按钮就再也没反应了。下拉菜单改为每次重建。
- 保存路径收敛为一个：顶部「保存」同时写脚本文件、用途与 `hook-config.json`。启用钩子的必要条件（已指定采集钩子脚本、至少一个挂载点）在保存前集中校验，不再写出一份启动时才失败的配置；重命名采集钩子脚本时 `scriptPath` 同步更新，删除它之前要求先改指向。
- 定向验证：`--script-library-only`（新增）、`--hooks-only`、`--intercept-only` 通过；Workbench 与 Core Release 构建 0 警告 0 错误。

## 2026-08-11 钩子拦截改写、挂载点测试补齐与脚本智能提示

- 补齐代理钩子四个挂载点的端到端触发测试（`--mountpoint-only`）。此前引擎层测得很扎实，但唯一给 `ExplicitHttpProxy` 传钩子引擎的测试传的是 `hookEngine:null`，`RequestAfterSend` / `ResponseBeforeWrite` / `ResponseAfterDeliver` 在整个测试集中从未被断言——四个挂载点是否真的按序触发一直是未经验证的假设。测试结果：实现本来就是正确的，未发现缺陷。断言覆盖触发顺序、四点共用同一 `txnId`、请求侧带请求正文而响应侧带响应正文、状态码在发送前为空、未勾选的点不入队；刻意不启动工作进程（直接读引擎待投递队列），避免断言连带依赖本机是否装了 Python。
- 钩子从只读观察扩展为可阻塞拦截：脚本用模块级 `INTERCEPT` 声明规则，worker 在 `ready` 时一次性上报，此后每个请求的匹配都在宿主进程内完成。不下推给 Python 判断是关键——worker 是单线程的，若所有请求都问一遍，一个页面的上百个资源会全部串行排队。未声明规则的纯观察脚本不付任何代价。
- 规则条件全是正则，覆盖 `url` / `method` / `host` / `endpoint` / `body` / `status` 与 `headers`（`{头名: 值正则}`），条件之间是 AND。正则优先用 .NET 线性引擎（`NonBacktracking`）编译，脚本里写出病态回溯模式也炸不掉代理热路径；用到反向引用/环视时退回普通引擎并强制 50 毫秒匹配超时。任一模式非法则整条规则作废，不做部分生效。正文匹配只取前 64 KB。
- 可改写的只有 `request.before_send` 与 `response.before_write` 两个点。脚本返回 dict 即为改写内容（`url`/`method`/`status`/`headers`/`body`，头值为 `None` 表示删除），返回 `None` 原样放行，可另带 `finding`。`Content-Length` 按改写后正文重算，改写 URL 只接受 http(s) 绝对地址。明文与 TLS 解密两条路径语义完全一致。
- 一律 fail-open：裁决超时（2 秒）、工作进程崩溃、协议错误、改写正文超 1 MB 均按原样放行；worker 在缺 handler、队列满、超时、异常每一条分支都必须回一条 `pass`/`mutate`，否则宿主只能空等满自己的超时。落库记录实际上线的字节，同时保留改写前的 URL 与正文并标注 `Mutated`。
- 期间修掉一个本次引入的真实回归：重构响应写出时把多值头按名合并成逗号串，`Set-Cookie` 会被并成一条、浏览器解出的 Cookie 数量出错；`--tls-only` 抓到。响应头改为以「行」为单位贯穿拦截与写出，按名合并的字典只用于快照与落库。
- 脚本编辑器新增钩子 API 智能提示：`Ctrl+空格` 手动唤出，输入 `event.get('`、`event[`、`store.` 或在 `INTERCEPT` 规则内自动弹出，Enter/Tab 插入、Esc 关闭。词表集中在 `HookScriptApi`，`event` 字段名由反射 `HookEventEnvelope` 得到、命名策略取自同一份 `JsonOptions`，契约一改提示立刻跟着改；`--intercept-only` 断言每个反射出的字段都有中文说明、钩子函数名与实际派发一致、拦截事件补全项都是可改写挂载点。
- 定向验证：`--intercept-only` 覆盖 15 组匹配用例（各位置命中/不命中、多条件 AND、状态码仅响应侧有效、非法正则整条作废、不可改写挂载点被拒）、病态正则 `(a+)+$` 对 5,000 个字符必须毫秒级收敛、未声明规则不拦截、工作进程不可用时立刻 fail-open 而非空等；全量 28 个套件通过。

## 2026-08-11 稳定版 .NET 10 与可验证发布

- 全部项目保持 `net10.0` / `net10.0-windows`，新增 `global.json` 锁定官方稳定 SDK 10.0.302、`latestPatch` 且 `allowPrerelease=false`，避免当前机器的 10.0.400-preview 或后续预览 SDK混入发布。CI 环境启用确定性构建并把警告视为错误。
- 新增 Windows GitHub Actions：固定安装 10.0.302，执行 restore、Release build、完整核心冒烟、自包含 win-x64 发布及发布清单验证。
- 发布脚本先校验语义版本，继续生成自包含 Workbench/CoreHost/SandboxHost、逐文件 SHA-256 清单、ZIP 与归档 SHA-256。新增 `verify-release.ps1` 重算每个文件大小和哈希，并拒绝缺失宿主、未登记文件、PDB/DBG 以及宿主落在错误目录。
- 官方当前信息：.NET 10 为 LTS，官方 10.0 渠道最新 SDK 为 10.0.302；本次使用官方发布元数据中的 SHA-512 校验隔离下载的 SDK 后再进行最终验证。
- 最终落地验证：稳定 SDK 10.0.302 的 Release 与 `CI=true` 警告即错误构建均为 0 警告/0 错误；完整核心冒烟、真实 Chromium 页面/Dedicated Worker/Service Worker Hook 注入和 SQLite 入库通过；自包含 0.8.0 包的 8 个清单文件均完成大小与 SHA-256 复核，归档哈希随包写入同目录 `.zip.sha256` 文件。
- 正式安全扫描尚未计为通过：扫描器读取 Visual Studio 锁定的 `.vs/...vsidx` 时被拒绝访问并按规范停止，没有自动删除 IDE 数据或用其他检查冒充扫描结果。关闭占用该目录的 Visual Studio、清理或排除 `.vs` 后需要重新执行。

## 2026-08-11 AI 长会话、增量刷新与脚本 Hook 可观测性

- AI 多轮对话继续采用确定性证据池和只读工具，不引入向量模型、向量库或 RAG。每轮工具结果只存在于当前取数回环；长期会话新增轻量 `evidence-ledger`，仅记录工具名、参数稳定引用、结果字节数、SHA-256、截断状态及回复中的 `[#序号]` 引用。追问能判断上一轮查过什么，需要字段细节时必须重新调用工具，不会再次上传上一轮大段工具原文。
- 完整会话导出同步包含证据引用与结果 SHA-256，便于核对取证流程；仍不长期保存工具原文，导出参数继续经过敏感信息脱敏。
- AI 会话界面改为窗口化渲染：默认仅创建最近 12 轮的气泡、Markdown、代码块与证据控件，更早轮次按 12 轮分批展开；磁盘历史、模型长期历史和完整导出不受显示窗口影响，避免长会话每次追问都重建全部动态控件。
- 流量定时刷新改为 SQLite `rowid` 写入游标增量同步：空闲轮询只读总数、会话和游标后的变更，`INSERT OR REPLACE` 的事务完成态更新同样产生新游标；检测到删除、游标回退或单次积压超过 2,000 条时才安全回退最近窗口全量读取。
- 脚本 Hook 协议新增 `processed` 回执，未定义处理函数明确标记 `missing-handler`，不再表现为无响应。引擎提供已投递、已处理、排队、丢弃、结论、错误、重启与最近事件/脱敏错误摘要；CoreHost 每秒原子发布 `scripts/hook-status.json`，普通代理和提权静默采集均可由工作台读取。
- 请求钩子区新增“试跑当前脚本”：对当前事务快照和已勾选挂载点启动真实隔离工作进程，脚本与 `store` 使用独立临时目录，完成后删除，不改正式脚本、配置和数据。界面显示投递/处理/结论/错误及最多四条结论预览。
- 定向验证：`--ai-only` 覆盖账本哈希/稳定引用、追问不重发工具原文及完整导出；`--refresh-only` 覆盖新增事务、完成态更新与游标追平空轮询；`--hooks-only` 覆盖 processed/missing-handler、运行指标和状态文件原子往返；Workbench Release 构建 0 警告 0 错误。

## 2026-08-11 工作区数据治理与完整备份

- “项目与数据”按工作区显示总占用、正文、SQLite、AI 文件、事务与 Hook 数量；数据策略属于当前项目而非全局设置，默认“永久保留 + 不限制容量”，不会在升级后暗中删除既有证据。
- 可保存 7/30/90/180/365 天保留期限与 1/5/10/25/50/100 GB 容量上限。启用策略时明确二次确认；每次停止采集后应用已保存策略，按最旧事务分批删除，并同步清理到期 Hook、无事务的旧会话与不再被 SQLite 引用的 SHA-256 Blob。AI 会话、记录组定义和配置不会被容量策略自动删除；非流量文件导致仍超限时明确提示，绝不伪报完成。
- “立即整理”可手动应用当前界面策略、清理孤儿 Blob、执行 WAL checkpoint 与 `VACUUM`；采集或 AI 运行中拒绝整理。操作记录删除量、回收字节和容量是否满足的脱敏审计汇总。
- “备份工作区”以同目录临时文件原子生成 ZIP，覆盖原始流量、正文 Blob、AI 会话/历史、记录组、脚本、配置与审计；备份前 checkpoint SQLite，跳过 WAL/SHM、临时文件和目录联接。备份不能写入被备份工作区内部。
- “导入备份”始终创建新的 `ws-*` 工作区，不覆盖现有项目；校验格式版本、条目数、总解压容量、重复路径与路径越界，采用逐条流式解压并拒绝 ZIP Slip。导入成功后切换到独立的“（导入）”项目。
- 定向验证：`--workspace-data-only` 覆盖策略原子往返、到期事务/Hook、孤儿 Blob、备份结构、SQLite/Hook/Unicode AI 文件恢复及恶意 `workspace/../../escape.txt` 拒绝；Workbench Release 构建 0 警告 0 错误。

## 2026-08-10 Worker Hook 与采集自检

- 页内 Hook 脚本改为基于 `globalThis`，同一份脚本可运行于页面、Dedicated Worker 与 Shared Worker；安装握手携带 `page` / `worker` / `service_worker` 上下文。Dedicated/Shared Worker 由所属页面 CDP 会话通过 `Target.setAutoAttach` 接管，ServiceWorker 由浏览器级 discover/attach 路径负责，避免 Worker 尚无 URL 时过早执行 Runtime 命令而永久挂起。
- Hook 状态按页面与 Worker 分项统计，界面显示已挂载目标和 Worker 比例；扩展程序等非 HTTP(S)/blob/data/file ServiceWorker 不注入，也不污染错误状态。
- “流量探索 / 页内 Hook”新增“采集自检”：只读核对采集宿主、代理监听、Hook 接收端、浏览器 CDP、页面/Worker 挂载、工作区 CA 信任，以及最近流量/Hook 入库时间；结果逐项显示通过/信息/注意/失败，可复制完整报告并写入不含正文的审计汇总。
- 定向验证：真实 Chromium 经过页面导航后，页面与 Dedicated Worker 安装握手、Worker 内 `btoa`/`fetch` 均实际进入 SQLite；`--page-hook-live`、`--hooks-only`、`--capture-health-only` 通过，Workbench Release 构建 0 警告 0 错误。

## 2026-08-10 记录组完整导出

- “项目与数据 / 记录组”新增“导出记录组”按钮：保存对话框可选择完整 `.zip` 归档或独立 HAR 1.2。ZIP 包含 `manifest.json`、`transactions.json`、`traffic-group.har`、说明文件及按 SHA-256 去重的未截断请求/响应正文 Blob；缺失/已清理事务以原 GUID 写入清单，不伪造替代数据。
- HAR 1.2 按采集时间升序写出请求方法、URL、查询参数、Header、Cookie、状态、时序与完整正文；UTF-8 文本保留原文，二进制使用 Base64，`_netmind` 扩展保留事务/会话 ID、采集模式、进程、协议及正文哈希，便于其他分析工具导入后继续溯源。
- 完整导出通过同目录临时文件原子提交，失败时清理临时文件；ZIP 正文采用流式复制，避免把整个记录组载入内存。导出操作写入脱敏审计汇总，不在审计中记录正文。
- 定向验证：Release Core/SmokeTests 与 Workbench 编译 0 警告 0 错误；`--group-only` 覆盖 ZIP 文件结构、缺失事务清单、Header 原样保留、Blob 逐字节一致、内置/独立 HAR 1.2、中文查询参数与二进制 Base64 往返，EXIT=0。

## 2026-08-10 功能增量（第四批）

- AI 分层取证：首轮改为确定性概况 + 查询键级事务摘要 + 证据文件名清单；工具扩展为 `get_transactions`、`search_transactions`、`get_page_hooks`、`get_evidence_files`，系统提示要求先确定范围、批量取证、区分事实/推断并以 `[#序号]` 引用，完整原始事务仍按当前测试账号场景不脱敏发送。
- 内置提示词 v2：统一证据等级、置信度、依赖链核对、复现边界和证据缺口格式；自动识别/API 逆向/安全审计/JS 加密/性能分析五套模板只保留领域差异。工作区中精确匹配旧默认值的模板自动升级，用户手工编辑过的覆盖不被替换。
- “追加文件”重构为“添加证据文件”：文件正文不再暗中附在第一次事务取数中，模型只能通过独立工具按清单读取；空状态不再常驻“未追加文件”，文件路径取消跨重启恢复，避免旧任务材料误入新会话。
- 滚轮联动滚动：窗口级 `PreviewMouseWheel` 隧道转发（`窗口_滚轮转发`）——Markdown 查看器/证据文本框/表格等内层可滚控件在自身内容滚不动时仍吞掉滚轮事件，导致聊天区等外层滚动区必须拖滚动条；现在光标下最内层 ScrollViewer 已到边界时自动转发给第一个仍可滚动的外层，内层有余量时不干预保持原生手感，所有滚动区统一生效。
- JSON 树展开/折叠真正修复：树为 ItemsSource 模式，`tree.Items` 内是数据节点而非 TreeViewItem，旧实现 `item is TreeViewItem` 永不命中；改经 `ItemContainerGenerator` 逐层取容器递归置 `IsExpanded`（展开时 WPF 同步生成直接子容器，惰性 Children 随之物化）。
- “事务与采集信息”底部区块按需求移除（XAML 块与 `TrafficRelatedText` 字段引用同步清理）。
- 排除关键字输入框宽度 380 → 760（拉长一倍）。
- “分析整个记录组”不再误认残留选中：单元格选择模式下点击任意单元格会留下 1 格选中，旧逻辑把它当成显式选择只分析 1 条；现改为显式选中 ≥ 2 条才按选中范围分析，否则分析全组；超限文案提示 Ctrl/Shift 多选单元格。
- 首轮证据清单表格文字颜色：隐式 DataGridRow 样式的 Foreground 会盖过表格级设置，改为逐列 ElementStyle 显式亮色（#E6EEF5）+ 单行截断，气泡深色底上清晰可读。
- 滚轮转发崩溃修复（回归）：鼠标悬停聊天区 Markdown 气泡文字上滚动即崩，事件日志堆栈为 `VisualTreeHelper.GetParent` 抛 `InvalidOperationException`（'Run'/'Paragraph' 不是 Visual）——流文档内联元素是 ContentElement；上溯统一改经 `GetAnyParent`：Visual 走视觉树，其余走逻辑树，转发行为不变。
- AI 回复期间动态展示网关响应容量：回合开始时记录本次请求生效的 `MaximumResponseBytes`，运行状态栏每秒刷新时带上“响应上限 X MB”（贯穿“正在调用/正在取数”各阶段），回合结束清除；显示的是本次请求实际生效值，运行中改配置不影响在途请求。
- 定向验证：Debug+Release 全量构建 0 警告 0 错误，冒烟全量通过（EXIT=0），工作台 Release 启动 14 秒存活验证通过。

## 2026-08-10 功能增量（第三批）

- 流量列表改单元格选择：概览/探索两个流量表 `SelectionUnit="FullRow"` → `Cell`，移除 `SelectedItem` 双向绑定；选择事件改从 `CurrentItem` 取行并防同行重复触发证据重载，右键按下改设光标下单元格为当前/选中单元格（非单元格区域退化首列），程序化选中统一走 `SetTrafficGridCurrent`。
- 勾选框表头修复：全局 `DataGridColumnHeader` ContentTemplate 原为 `TextBlock Text={Binding}`，把 CheckBox 表头字符串化成控件类型名；改为 ContentPresenter + 局部隐式 TextBlock 单行样式（文本表头仍单行省略，控件表头原样渲染）。
- JSON 树右键展开/折叠修复：`JsonTreeContextMenu` 补 `x:shared="False"`，多棵树共用单实例导致 `PlacementTarget` 不指向被右键的 TreeView。
- 响应上限配置化：`AiGatewaySettings` 新增 `MaximumResponseBytes`（默认 32 MB，校验 8–128 MB）；AI 配置页新增“响应上限”下拉（8/16/32/64/128 MB，默认 32），防抖自动保存，加载时精确匹配预设否则回落 32；网关 SSE/非流式两处读取改按次配置限流，超限文案提示可调大；会话文件读取上限改为构造参数（默认 48 MB）并随配置响应上限 + 32 MB 余量联动。
- 流量表列宽重构：“端点”改名 Path 固定 500 像素，其余列全部改为内容宽度（Auto），消除星宽列吸收拖拽导致的“右列不跟随”；概览/探索/记录组三表统一。
- 单元格点击联动加固：新增 `流量列表_左键按下`（PreviewMouseLeftButtonDown）显式定位单元格并立即调用 `SelectTrafficRowAsync` 证据联动（同一条记录不重复刷新），不再依赖 SelectionChanged 时序；勾选框列与 Ctrl/Shift 组合键不拦截保留原语义；键盘导航仍走 SelectionChanged 兼容路径。
- 单元格选择覆盖扩大：记录组表格改 `SelectionUnit="Cell"`（多选移除/分析改从 `SelectedCells` 去重取行），概览端点聚类表同步改单元格选择（下钻改读 `CurrentItem`）；会话列表保持整行多选以服务批量删除。
- 定向验证：Debug+Release 全量构建 0 警告 0 错误，冒烟全量通过（EXIT=0），工作台 Release 启动 14 秒存活验证通过。

## 2026-08-10 功能增量（第二批）

- 网关响应上限放宽：`AiMaximumResponseBytes` 自 2 MB 放宽到 32 MB（与会话文件读取上限对齐），错误文案改为动态插值；此前放开的 8 MB 是取数预算/正文上限，两者是不同常量。
- 流量列表紧凑化：列宽整体收窄（序号 40/图标 46/AI 34/时间 58/方法 52/主机 108/状态 40/延迟 54/大小 52/协议 62/进程 86/来源 48，端点列 * 填充剩余宽度）。
- AI 勾选增强：两个流量表 AI 列表头新增三态全选框（概览页作用全量、记录页作用筛选结果，`SyncAiSelectAllBoxes` 防事件回环）；单元格勾选框支持 Shift+点击范围勾选（锚点按行 id 记录，`AI勾选_按下` 拦截自行处理）。
- 证据区两栏并行：原请求/响应 TabControl 改为左右两栏 DockPanel 常显（列比 1.05*/1.45*），相关数据改为底部限高区块；内容搜索高亮不再需要切 Tab（移除 `TrafficEvidenceTabs` 引用）。
- JSON 树右键菜单：请求/响应/响应预览三个树统一挂 `JsonTreeContextMenu`（展开全部/折叠全部，递归 TreeViewItem；资源定义在 MainWindow 窗口资源，处理函数在本窗口代码后台）。
- AI 会话批量删除：`AiConversationList` 改 `SelectionMode="Extended"`（Ctrl/Shift 多选），删除按钮随选中数联动（多选时标题带计数），批量循环删除并在命中当前打开会话时关闭；恰好单选时才触发会话恢复。
- 首轮证据清单表格化：`AppendAiUserBlock` 对首轮用户消息解析 `#序号 时间 方法 主机 路径 状态 大小B 类型` 行（类型可含空格取剩余全部）渲染为深色紧凑 DataGrid，前后说明文字保持纯文本；解析失败回退纯文本。
- 提示词管理保存按钮修复：`saveTemplateButton` 未设 `DockPanel.SetDock` 默认 Left+垂直拉伸占满整列，显式 `Dock.Bottom` + 右对齐恢复正常尺寸。
- 排除关键字：流量探索工具栏新增排除关键字输入框（逗号/分号分隔，命中 URL/主机的记录从列表隐藏，仅显示层不删数据），默认预置 microsoft.com、edge.microsoft.com、googleusercontent.com、substrate.office.com、edge-consumer-static.azureedge.net；流量列表右键新增“排除域名：xxx”菜单项（动态头展示目标域名，去端口后追加进关键字）。
- 按进程采集：顶部新增“按进程采集”按钮，弹出 `ProcessPickerWindow`（进程名/PID/可执行路径列表，关键字过滤+刷新，双击即选定）；启动静默抓包时经 `--process-name` 传给 CoreHost，`RunSilentAsync` 按“进程名（PID”前缀过滤仅落库该进程事务，会话目标记为“进程：xxx”；需静默抓包模式，常规开始采集仍面向全部进程。
- 会话筛选徽章“清除”小按钮 hover 修复：自绘 `BadgeClearButton` 模板接管 hover/pressed 态（白色半透明底），消除系统默认浅蓝高亮在深色底上的割裂感。
- 定向验证：Debug+Release 全量构建 0 警告 0 错误，冒烟全量通过，工作台 Release 启动 14 秒存活验证通过。

## 2026-08-10 界面打磨增量

- 列表序号列与时间升序：概览端点聚类（健康度）、实时概览流量表、流量探索流量表、记录组四处列表统一加序号列并按采集时间升序（最新在最下），与 AI 证据池 #序号 顺序一致；`TrafficRow.Ordinal` 在列表变更后经 `RenumberTrafficRows` 动态重编号；提示词（系统提示与首轮用户消息）显式说明“#序号 随时间递增”。
- 放开会话取数限制：`AiToolFetchBudgetBytesPerTurn`（单轮取数预算）与 `AiMaximumBodyBytesPerTransaction`（单事务正文上限）自 1 MB 放宽到 8 MB；14 MB 历史折叠与 16 MB 完整上下文上限仍作兜底。
- 提示词目录可编辑：新增 `AiPromptCatalogStore`（工作区 `ai-prompts.json`，临时文件+原子替换写入，缺失/损坏回退内置默认，文件未覆盖的内置模板自动补回）；新增 `AiPromptManagerWindow` 管理窗口（查看/编辑内置模板、恢复内置默认、新增自定义模板可删除、快捷追问增删改与上下移排序），确认后整批保存并审计 `ai.prompt-catalog-saved`；AI 页模板下拉经 `ResolveAiTemplate` 优先目录解析。
- 修复 AI 会话列表点击无法恢复选中会话：点击已选中项不触发 SelectionChanged → 补 MouseLeftButtonUp 强制恢复；运行中点击被吞导致选中态失同步 → 运行中回滚选中项并提示。
- AI 聊天区气泡化：用户/助手消息以 Expander+Border 气泡呈现（可折叠/展开），取数记录默认折叠（JSON 参数默认折叠），收尾助手消息底部显示“用时 · 输入/输出令牌”（`AiChatMessage` 新增三个可选统计字段，随 JSONL 持久化，网关手工投影不会发给模型）。
- Markdown 渲染加固：单独 `\r` 归一化为换行、表格分隔行宽松识别（`|--|` 变体）、有序列表识别中文顿号（1、）、兼容 `~~~` 代码围栏；富文本查看器统一由 `CreateMarkdownViewer` 生成。
- 流量列表类型图标改为文字徽章：`TrafficResourceIconTemplate` 由低饱和符号图形改为色块背景 + 深色粗体短文本（图/API/JS/CSS/字/媒/连/文/其），列宽 30→46，整行着色保留作辅助。
- 定向验证（Release）：`--ai-only` 新增提示词目录往返断言（缺失回退/自定义模板读回/同 Id 内置覆写且不重复/快捷追问顺序/损坏回退）；全量构建 0 警告 0 错误，`--ai-only` EXIT=0，工作台启动 14 秒存活验证通过。

## 2026-08-09 当前源码增量

- 缓存资源选取功能已整体移除（用户验证后认为实用价值不足）：删除 `BrowserCacheReader`（Core 的 Chromium blockfile 解析器）、`CacheResourcePickerWindow` 选取窗口、AI 页“从缓存选取”按钮与导出追加逻辑、`--cache-only` 冒烟夹具与临时验证工程；追加文件对话框与附加文件清单不受影响。
- 追加文件对话框默认定位系统下载目录：目录优先级为上次选择位置（会话内记忆）→ 下载目录 → 当前目录。

- 采集中允许清空记录：清空按钮不再拦截运行中的采集（确认框提示新记录会继续写入）；`ClearCaptureData` 保留“运行中”会话行（事务外键引用会话，采集进程持原会话继续写入不失败，会话结束时自动更新为已完成），新增冒烟回归：采集中清空成功且原会话后续写入可读。
- 流量搜索支持布尔表达式：新增 `TrafficFilterExpression` 引擎，搜索框支持 &&（且）、||（或）、!（非）与 () 分组，双引号包裹含空格关键词；单词仍为大小写不敏感子串匹配，不含运算符时行为与原来完全一致，解析失败回退整串子串匹配绝不抛异常；优先级 ! > && > ||。单个 &/| 属于 URL 内容不当作运算符。
- AI 正文按内容类型过滤：`AiFullContextBuilder` 只保留 HTML/纯文本/JS/JSON/XML 与表单类文本正文，图片、CSS、字体、音视频、wasm 与二进制容器按 Content-Type 直接省略（不读 Blob，标记“[正文已省略]”）；Content-Type 缺失时仍由二进制启发式兜底。
- 取消 AI 证据 30 条硬上限：`AiMaximumEvidenceTransactions` 30→1000（仅防结构性滥用，真正边界是完整上下文 16 MB 总体积上限），设置页“AI 证据事务上限”范围同步改为 5–1000（默认仍 30），证据自动补全容量不再被 30 钳制。

- M1 AI 分析重构为对话式多轮取数（旧一次性全量发送链路已移除）：网关层 `AiGateway.AnalyzeConversationAsync` 支持 chat_completions/responses 双接口 SSE 流式 + function calling（tool_calls 增量按 index 拼接；DeepSeek 带 tools 时不启用 thinking）；会话引擎 `AiConversationEngine` 首轮只发证据池摘要（#序号 时间 方法 主机 路径 状态 大小 类型，上限 1000 行），模型经三个工具按需取数（get_transactions≤60 序号、search_transactions、get_page_hooks），单轮取数预算 1 MB、迭代上限 8 次；追问不重发原始数据，只携带完整会话历史；消息 JSON 累计超 14 MB 时把最早 tool 结果折叠为占位符会话不断；会话以 JSONL 持久化到工作区 `ai-conversations/`（元数据首行 + 逐条消息），跨重启恢复不丢记忆。AI 页改造为会话列表 + 轮次面板（用户提问/默认折叠的取数记录/Markdown 回复，流式 300 ms 节流重渲染）+ 追问输入区；审计 ai.conversation-started / ai.turn-completed。
- M2 提示词模板与快捷追问：`AiPromptTemplates` 内置 5 套（自动识别/API 逆向/安全审计/JS 加密逆向/性能分析，保留“只根据证据回答、证据不足明确说明、按时间升序为准”约束），新建会话时下拉选定并写入会话元数据；输入区上方 4 个快捷追问按钮（生成 Python 复现代码/详解加密签名流程/分析潜在安全风险/列出全部 API 参数与响应结构），仅在已打开会话时可用。
- M3 页内 JS Hook（采集浏览器注入）：采集浏览器启动计划新增可选 `--remote-debugging-port`（仅回环）；工作台选空闲调试端口启动浏览器后，`PageHookInjector` 轮询 CDP `/json/version` 经 `Page.addScriptToEvaluateOnNewDocument` 注入 Hook 脚本（包裹 XHR.open/send、fetch、crypto.subtle 五方法、btoa/atob、storage.setItem，记录 ts/类型/函数/参数截断 8 KB/堆栈首帧，500 ms 批量 keepalive POST 到回环接收端口）；CoreHost proxy 新增 `--hook-port`，`PageHookReceiver` 仅监听 127.0.0.1 接收 JSON 批次（单批 500 条、请求体 4 MB、NUL 剔除、UTF-8 二分截断）写入新表 page_hooks（AUTOINCREMENT，超 20000 条同事务淘汰最旧，清空记录联动清空）；流量探索页新增“页内 Hook”子标签（类型/关键字过滤、双击键值分色详情、未注入时空态说明）；AI 工具 get_page_hooks 接通，参数溯源可直接看到加密函数实参；注入/接收失败均静默降级不影响抓包；审计 hooks.page-injected / hooks.page-received（按批计数）。
- 定向验证（Release）：`--ai-only` 重写为假网关 SSE（含 tool_calls 增量分片）回环、迭代上限、单轮预算截断、JSONL 往返、14 MB 折叠断言；`--hooks-only` 追加页内 Hook 断言（脚本五类包裹目标、ParseBatch 字段映射/截断/单批上限、接收端点 HTTP 回环入库、超限淘汰、注入器不可达端口限时降级不抛）；均 EXIT=0。CDP 真机注入为手工验证项。

- AI 参数溯源增强：完整上下文数据链路不变（URL/Header/Cookie/请求与响应正文不脱敏发送），但系统提示与默认提问重写为参数溯源导向——逐一判定每个请求参数（查询串/请求体/关键请求头/Cookie）的取值来源（更早响应字段、Set-Cookie、JS 计算还是静态字面量）并输出溯源表，对 JS 计算的参数要求结合证据中的 JS 源代码还原输入项与算法，证据不足时明确指出缺哪条事务；默认输出令牌 4096→8192，单条事务正文读取上限 512 KB→1 MB（让压缩后常见的完整 JS 源文件进入上下文，总体积 16 MB 上限与 30 条硬上限不变）。
- AI 证据自动补全：未勾选记录仅高亮单条事务时，`GetAiEvidence` 自动从已落库事务中补全同主机更早时间的事务（受证据条数上限约束），让模型能看到参数取值的上游来源（登录/取 token/JS 装载等响应）；概览范围文案同步显示补全条数，勾选与记录组场景不受影响。
- 自定义提问改为追加语义：内置参数溯源提问始终发送，用户自定义提问以“用户针对本次分析的补充要求”追加在其后（不再替换内置要求），字符上限只约束自定义部分；AI 页标签与提示文案同步更新。
- 修复开启抓包后验证码/二维码/图片零星加载失败：根因是显式代理并发名额按连接生命周期持有且上限仅 32，视频流/长轮询/多站点浏览的长连接耗尽名额后新 CONNECT 排队，浏览器握手预算耗尽主动断开（落库表现为 CONNECT 495 IOException 爆发，取证会话中 open.weixin.qq.com 在列）。修复：`ProxyOptions.MaximumConcurrentConnections` 32→256；`WorkspaceCertificateAuthority` 叶子证书签发由全局锁改为按主机锁并行（实测 RSA-2048 签发约 75 ms/张），CA 证书改内存缓存消除每次签发的证书库 I/O，叶子缓存超限按最旧淘汰；495 失败记录的响应摘要改为携带异常类型与消息便于后续诊断。冒烟新增断言：默认并发上限不得低于 128，且 16 个并发 TLS 握手必须全部限时完成。已知独立限制：上游 HttpClient 30 秒超时会把长轮询连接记为 502（如 telegram apiws），与本次故障无关，暂未改动。
- 实时概览页右列新增端点聚类明细表（按请求数降序前 40，展示方法/端点/请求数/错误率/P95），点击行自动把端点填入流量探索搜索框并切页下钻，复用既有筛选链路。
- 静默抓包与无感抓包开关上移至主窗口顶部栏（开始采集按钮旁）：勾选/取消立即持久化并记审计，与设置页四个复选框经 `SyncModeSwitchBoxes` 双向同步，保存失败自动回滚并显示红色原因，状态文字提示“下次开始采集生效”。
- 修正 AI 页结论卡片描述文字：原“发现/置信度”式文案虚构确定性结论（如“认证字段稳定传播”“未发现令牌泄漏”），改为只陈述可验证事实——标题按状态码区分“异常响应”与“事务证据就绪”，摘要列主机/协议/状态/延迟/字节数并如实提示是否检测到 Authorization/Cookie，尾注说明分析结论需运行 AI 分析产出；卡片各行之间增加浅色分隔线提升可读性。
- 支持勾选多条记录并删除：流量列表“清空记录”旁新增“删除勾选”按钮，删除 AI 列已勾选事务；Core 新增 `SqliteMetadataStore.DeleteTraffic`（单次上限 1000 条）、`GetReferencedBlobHashes` 与 `WorkspaceStore.TryDeleteBlobAsync`，`TrafficArchive.DeleteTrafficAsync` 先删事务行再仅删除已无任何事务引用的孤儿正文 Blob（内容寻址正文可能被多条事务共享，不得误删）并追加 `workspace.traffic-deleted` 审计事件；工作台同步清理内存态、记录组范围与 AI 证据预览。
- AI 输入数据侧显示提交数据字符数：发送上下文预览标题在构建完成后追加“· N 字符”，加载中与失败时回退基础标题。
- 全部列表类数据表格统一浅色横向分隔线（`GridLinesVisibility=Horizontal` + `#26FFFFFF`）：最近流量、端点聚类健康度、捕获会话、记录组明细（流量探索列表原有）。
- 修复表格单元格长文本折行：根因是 App.xaml 全局 TextBlock 隐式样式 `TextWrapping=Wrap`，列宽不足时端点等长字段折行撑高行；新增共享样式 `SingleLineCellText`（NoWrap + CharacterEllipsis + 垂直居中）并应用到全部 DataGridTextColumn，主机/端点列保留完整值 ToolTip。
- 流量探索顶部按钮合并为左侧列表上方同一行（AI 选择组 + 刷新/清空/删除组），消除窄窗口下左右两组错位重叠。
- 流量记录列表（实时概览最近流量与流量探索）新增“进程”列，显示流量所属进程名。
- AI 证据链自动补全补齐到设置中的证据数量：补全条数等于“AI 证据事务上限”，候选优先当前列表窗口，窗口内同主机上游事务不足时扩展到最近 2000 条持久化事务（`AiEvidenceCompletionScanLimit`）继续补齐，工作区不可读时退回窗口候选不阻断分析。
- AI 证据按实际请求顺序传递：`GetAiEvidence` 在记录组/勾选/自动补全三种来源上统一按采集时间升序输出（最早在前、最新在最后），与实际执行顺序一致；系统提示追加“证据按实际发生时间升序提供，梳理流程必须以该顺序为准”，避免模型把展示顺序误判为执行顺序。
- AI 输出令牌上限改为可编辑下拉框：预设 4096/8192/16384/32768/65536，支持直接输入自定义整数，范围 256–65,536（`AiMaximumOutputTokens` 由 16,384 提高到 65,536），校验文案同步更新，已保存配置加载时回填；`--settings-only` 复跑 EXIT=0。
- 参数溯源提示词改为按需聚焦：系统提示与默认提问不再要求逐一覆盖被分析请求的全部参数——有自定义需求时只追溯实现该需求涉及的参数，未给出需求时默认聚焦能得到最终页面（证据中最后一条事务呈现的页面）的相关参数；追加语义不变（内置提问始终发送），“参数溯源表”等冒烟标记词保留，`--ai-only` EXIT=0。
- AI 请求超时做成可配置设置：原先硬编码 90 秒，现 `AiGatewaySettings` 新增 `TimeoutSeconds`（默认 90，范围 10–600 秒）随配置持久化，AI 分析页新增“请求超时（秒）”输入框；超时改为按次请求的链接取消令牌生效（自建 HttpClient 改无限超时避免双重截断），超时报中文错误并提示调大超时；`--settings-only` EXIT=0。
- 修复“模型网关返回成功但没有可显示文本”的排查盲区：结果提取增强——Chat Completions 合并所有 choices 并在 content 为空时兜底 `reasoning_content`，Responses 兼容 `output_text/summary_text/text` 三种 part 类型；仍提取不到时 `AiGatewayException` 携带原始响应 JSON，界面在结果区下方以 JSON 树展示（默认全折叠）便于核对网关实际返回结构。
- AI 输入数据预览改 JSON 树展示：发送上下文预览优先按 JSON 树呈现且默认全部折叠（`JsonTreeViewRenderer` 新增可指定展开深度的重载，0 即全折叠），构建失败回退纯文本；占位/降级文案统一走 `ShowAiContextPreviewText` 避免残留旧数据。
- 分析结果右键菜单适配深色主题：拦截 `FlowDocumentScrollViewer` 内置浅色编辑菜单（ContextMenuOpening 置 Handled），改为复用流量列表深色菜单样式的自定义菜单（复制所选/全选/复制全部结果）。
- 证据文本与 JSON 树字体调大：请求/响应各证据文本框 11→13，AI 输入数据预览 10.5→12.5，JSON 树样式 11→13，长时间阅读更舒适。
- 定向验证（Release）：`--ai-only` 新增系统提示必须包含参数溯源与 JS 计算还原要求的断言，`--proxy-only` 新增并发上限与 16 并发 TLS 握手断言；新增 `--filter-only` 布尔表达式定向测试与 `--delete-only` 勾选删除定向测试（共享正文 Blob 被其他事务引用时必须保留、孤儿 Blob 必须删除、审计必须追加），`--clear-only` 新增采集中清空回归，`--ai-only` 新增图片/CSS 正文省略且不读 Blob 断言，`--settings-only` 新增上限放宽到 200 的合法性断言，均 EXIT=0；Workbench 编译通过（输出目录复制被运行中的工作台进程锁定，重启程序后自动更新）。
- 修复输出上限下拉选中后数值不可见：根因是自定义 ComboBox 模板无编辑区且显示层被遮挡，重构模板将显示区与下拉按钮分离；按用户要求最终取消自定义输入，输出上限只保留 4096/8192/16384/32768/65536 预设下拉（默认 65536），历史自定义值加载时就近选不小于它的预设。
- 点击“运行 AI 分析”后输入数据保持 JSON 树全折叠：与预览共用 `ShowAiContextPreviewJson`，不再展开为纯文本；运行期间状态栏每秒追加“已用时 X 分 XX 秒”，完成/取消状态附带总用时。
- 流量探索新增内容关键字搜索：在当前筛选结果（最多 500 条）的 URL、请求/响应头、查询参数、Cookie 与正文（Blob 读取上限 1 MB）中大小写不敏感搜索，命中结果以列表展示（位置+摘要）；选中结果项自动在主流量列表选中该记录、切换到命中所在页签并选中高亮关键字，正文若处于 JSON 树视图自动切回原始正文再高亮；搜索在后台线程执行不阻塞 UI。
- 应用程序图标：生成 NetMind 主题图标并打包多尺寸 ICO（packaging/make-app-icon.ps1，256/64/48/32/16），同时嵌入 exe 资源与窗口标题栏图标。
- AI 分析页新增追加文件：可多选追加最多 10 个文件（单个 ≤1 MB，超限/超数拒绝并提示），随流量证据在同一次请求发送；上下文 JSON 追加“用户追加文件”顶层节点（文件名+内容，二进制文件标记省略），预览与实际发送同一构建链路。
- 请求/响应键值信息颜色区分：查询参数、Cookie、请求头、响应头四个区块改为只读富文本渲染，键名（含分隔符）用强调色、值用正文色；正文 JSON 仍由彩色树视图承担，深色右键复制菜单保持一致。
- 定向验证（Release）：Workbench 与 SmokeTests 构建 0 警告 0 错误，`--ai-only`、`--settings-only` 均 EXIT=0，工作台启动级验证无异常。
- AI 页配置输入后立即持久化：网关地址/模型/接口类型/推理强度/输出上限/超时六个配置项变更后防抖 700 毫秒自动落盘并在凭据状态栏提示“配置已自动保存”，输入暂不合法（如超时编辑中）时跳过本次；API 密钥仍需显式点保存写入凭据管理器；加载配置与 XAML 初始化阶段的变更事件被抑制避免回写默认值。
- AI 输入数据可导出为文本文件：发送上下文预览标题栏新增“导出输入数据”按钮（有实际输入数据时可用），把当前发送给模型的完整 JSON 另存为 txt/json；同时输入数据降级为纯文本展示时对超过 30 万字符的内容截断显示避免 TextBox 卡顿，导出仍为完整内容。
- 修复追加文件与用时三个反馈：① 追加/移除文件后立即重建输入数据预览（原来预览不刷新，看不到“用户追加文件”节点）；② 附加文件清单随工作台设置持久化（`WorkbenchSettings.AiAttachedFilePaths`），重启后自动恢复，文件已不存在或超限的条目自动丢弃，设置页保存不再覆盖清单；③ 分析完成后加载历史会把状态栏改写为“历史 · …”导致用时丢失，现历史状态末尾追加“本次用时 X 分 XX 秒”；④ 已保存密钥时密钥输入框叠加占位提示“已设置密钥 · 留空即沿用已保存密钥”，输入新值即隐藏。`--settings-only` EXIT=0。
- 修复追加大文件后输入数据降级为展开且不可折叠的扁平文本：根因是建树上限 `JsonTreeMaximumBytes` 为 512 KB，追加文件后完整上下文超限即降级到纯文本 TextBox；`JsonPreviewTreeBuilder.TryBuild` 新增可指定字节上限的重载，普通正文仍按 512 KB，AI 输入数据显式放宽到新常量 `JsonTreeMaximumBytesForAiContext`（16 MB，与上下文体积上限对齐），节点惰性物化且字符串值截断展示，首屏成本不变。`--json-only` EXIT=0。

## 2026-08-08 当前源码增量

- 证据图谱功能已整体删除：Core 图谱类型与存储、工作台图谱页面及对应冒烟断言均已移除；端点规范化、聚类与字段传播等确定性分析保留。
- AI 分析改为发送完整原始数据：上下文由 `AiFullContextBuilder` 构建（元数据、Header、Cookie、查询参数与请求/响应正文），二进制正文转有界十六进制预览，单次上下文上限提升到 16 MB，中文不再转义为 `\uXXXX`；`AiPrivacyFilter` 仅保留给对外分享的脱敏副本与审计通道，模型上下文不再脱敏（分析对象为测试账号数据）。
- AI 页新增自定义提问输入框（有字符上限，超限拒绝），随完整证据一并发送给模型；为空时使用默认分析请求。预览与实际发送调用同一上下文构建方法，未持久化的演示事务以内联哈希哨兵把摘要文本作为正文进入上下文。
- AI 历史 `evidence.json` 改为保存实际发送的完整证据快照（上限 16 MB），文案同步改为“完整证据快照”。
- 已实现底层静默抓包（WinDivert 被动嗅探，不拦截不改包）：Core 新增报文解析（IPv4/IPv6 扩展头）、回绕安全的 TCP 双向重组、HTTP/1.x 增量配对（Content-Length / chunked / 读到关闭为止）与 TLS ClientHello/SNI 识别；`SilentCaptureEngine` 按四元组维护有界流表，空闲淘汰与停机结算，进程关联复用 Windows TCP 所有者表。
- CoreHost 新增 `silent` 动词：管理员与 WinDivert 驱动检测（缺失/被阻止给中文指引与非零退出码）、提升权限后以 `%LocalAppData%\NetMind\silent-ready.json` / `silent-stop.signal` 信号文件协议与工作台通信，优雅停机后结算会话并清理信号文件；启动失败写 `silent-capture.start-failed` 审计事件。
- 工作台设置页新增“采集模式”开关（默认关闭，勾选即保存并记审计）：开启后开始采集以 UAC 提升权限启动 CoreHost silent，轮询就绪信号文件判定启动结果，停止时写停止信号并等待优雅退出；静默模式不接管系统代理，概览与来源标签适配“静默抓包”。
- 定向验证（Debug）：`--ai-only`（完整数据必须出现、自定义提问随请求发送、超长拒绝）、`--settings-only`（静默开关默认关闭与往返持久化）、`--silent-only`（乱序/重叠重组、三种正文语义、keep-alive 配对、SNI 解析与非 HTTP 判定）均已通过；全量 Release 构建与完整冒烟留待最终落地执行。
- 静默抓包落地缺陷修复：`WinDivertRecv` P/Invoke 参数顺序与 windivert.h 对齐（pRecvLen 在 pAddr 前），消除首个报文到达即栈踩踏崩溃；不再将 stdin EOF 误判为退出请求；CoreHost 新增全局异常陷阱（未处理异常堆栈落 `%LocalAppData%\NetMind\silent-crash.log`）；TLS 隧道记录改为识别到 ClientHello 即落库（浏览器长驻连接不再导致活跃浏览期间无条目），结算阶段防重复；新增引擎级“识别即落库/不重复”冒烟断言，管理员提升环境实测真实 HTTPS 连接在运行期即可见隧道记录。
- 静默抓包启动不再弹出控制台黑框：UAC runas 提升改用 ShellExecute + `WindowStyle=Hidden`，就绪与停止均走信号文件，黑框无交互价值。
- 静默抓包全链路解密（M1–M4）：SSLKEYLOGFILE（NSS Key Log）增量解析 + TLS 1.2/1.3 记录层解密，h1 明文复用现有配对；HTTP/2 HPACK 解码与帧重组为事务（多流复用、END_STREAM 兜底结算）；QUIC v1/v2 捕获（UDP 443），Initial 无密钥解密提取 SNI/ALPN，1-RTT 用流量机密派生 `quic key/iv/hp` 解密并重组 STREAM 帧；QPACK（RFC 9204 静态表 + 单向编码器流维护的动态表，分块指令快照回退）与 HTTP/3 帧层重组为事务；缺密钥/解码损坏一律退回隧道模式不中断抓包。`--silent-only` 定向冒烟覆盖全部里程碑断言。
- 采集浏览器启动计划新增环境变量契约：注入指向工作区 `keys/sslkeylog.txt` 的 `SSLKEYLOGFILE`（仅浏览器进程生效），采集后台增量读取同一文件解密该浏览器的 HTTPS/HTTP2 正文。
- 静默抓包“采集正常但零落库”缺陷修复（实测复现定位）：① 默认过滤表达式使用了 WinDivert 2.2 不存在的 `dstport/srcport` 原语，`WinDivertOpen` 失败返回 INVALID_HANDLE_VALUE(-1)，而句柄校验只判 `IntPtr.Zero` 放行 -1，之后每次 `Recv` 报错误 6 空转，改为字段比较语法 `tcp or (udp and (udp.DstPort == 443 or udp.SrcPort == 443))` 并补 -1 判定；② `WINDIVERT_ADDRESS` 位域 IPv6 位误用 bit21（实为 IPChecksum 校验和标志），导致带校验和标志的入站包被误判 IPv6 解析丢弃，改为官方 bit20；③ CoreHost 引擎主循环异常不再被吞掉，落崩溃日志与 `silent-capture.start-failed` 审计，停机后写 `silent-last-run.json` 运行摘要（结算条数 + 收包/解析/落库分层计数），杜绝静默断采。管理员提升环境实测：真实 HTTPS 请求落库 2 条事务，UDP 443 报文解析计数归位，`--silent-only` 冒烟 EXIT=0。
- 响应正文乱码修复（实测取证定位：落库 blob 头部为 gzip 魔数 1F 8B）：新增 `ProtocolParsers.DecompressHttpBody` 按 Content-Encoding 解压 gzip/deflate/br（含逗号组合，反向解压），带 16 MB 解压炸弹上限与 gzip 魔数预检，失败/未知编码原样返回；代理模式（明文转发与 TLS 检查两条路径，回写浏览器的字节保持原样、仅落库/分析正文解压）与静默抓包（HTTP/1.1、HTTP/2、HTTP/3 三个结算入口）全部接入，落库大小与摘要同步为解压后字节。定向断言覆盖 gzip/br/deflate/无编码/缺魔数/损坏流/未知编码，代理 E2E 断言上游 gzip 响应回写原样且落库正文已解压（`--protocol-only`、`--silent-only`、`--proxy-only` 均 EXIT=0）。
- 静态资源抓不到根因取证与修复：用户站点（wenshushu.cn）主页唯一外部 JS 装载器 `/ag/gls` 响应头为 `Cache-Control: public, max-age=604800`（实测 Age 已 17 万秒），缓存命中时浏览器不发任何网络请求，任何抓包模式均无法看到；采集浏览器启动计划新增 `--disable-http-cache` 与 `--disable-cache`（未知开关会被 Chromium 忽略，双写兼容新旧版本），确保采集浏览器内 JS/CSS/图片等静态资源全部走网络被捕获；冒烟断言已覆盖。旧会话中已按压缩字节落库的历史记录不受影响，新记录自动解压。

## 2026-08-07 当前源码增量

- 已迁移为可运行的全中文 WPF 工作台，包含实时概览、流量探索、记录组、证据图谱、AI 分析、脚本验证和工作区页面；使用保留模式渲染、原生窗口标题栏及虚拟化流量表格，移除 WinForms 逐控件重绘和缩放快照。
- 已新增独立 `NetMind.CoreHost`，支持 HTTP/1.1 显式代理、模拟采集和工作区状态命令；所有操作错误均使用中文消息和非零退出码。
- 已实现 Windows `winsqlite3.dll` 元数据仓库、捕获会话、事务查询、WAL 模式、SHA-256 正文寻址、审计日志与稳定脱敏。
- 工作台采集按钮会启动/停止独立 CoreHost，并从 SQLite 自动刷新捕获记录。
- 工作台可使用独立用户数据目录一键启动 Edge/Chrome 采集浏览器，同时注入 HTTP/HTTPS 代理参数并关闭 QUIC，不修改系统全局代理。
- 已新增独立 `NetMind.SandboxHost`：静态能力拒绝、随机暂存目录、Python `-X utf8 -I -B -S` 隔离参数、环境最小化、5 秒超时、256 KB 输出限制和结构化中文结果；工作台“安全运行”已连接该后台。
- Python 子进程已加入独立 Windows Job Object，强制最多 1 个活动进程、64 MB–1 GB 可配置进程内存、CPU 时间、墙钟超时与 kill-on-close；工作台显示本次真实隔离边界。定向测试已验证正常样例、无限循环终止和 64 MB 内存上限。
- SandboxHost 已自动发现本机 Python 3.14，并以 `-X utf8 -I -B -S` 完成真实脱敏样例执行；中文输出、退出码和超时终止均已验证。
- 已实现 HTTP/2、WebSocket、SSE、gRPC envelope、DNS 和 Protobuf wire 确定性解析器，包含帧上限、边界检查、掩码还原、DNS 指针循环限制和 varint 溢出保护；协议证据已接入工作台证据检查器。
- 已实现端点规范化与聚类指标、稳定敏感字段传播占位符、动态证据图谱、版本化保存和补丁引用校验；图谱页面由当前流量实时生成，不再使用固定节点。
- 工作台已明确区分演示数据、真实代理采集中和本地真实捕获记录；证据检查器使用 WPF 数据绑定原子更新，不再依赖冻结重绘或截图覆盖。
- 流量探索已接入内容寻址正文读取：真实事务根据 SHA-256 引用读取请求/响应 Blob；本地所有者视图展示原始内容，AI 工具取数按当前测试要求使用完整原始证据，用户主动导出/分享时可另行复制脱敏副本。二进制内容使用有界十六进制预览，超大正文明确标记截断。未解密的 HTTPS CONNECT 只显示加密隧道说明。
- 元数据查询已关联捕获会话模式，流量列表和正文检查器逐条显示“真实代理 / 模拟 / 演示”来源，避免把测试事务误报为真实抓取。
- 流量探索支持按来源、状态和资源类型组合筛选；类型图标、整行前景色与筛选共享同一分类，覆盖图片、接口数据、脚本、样式、字体、媒体、文档、连接和其他，选中行维持高对比文本。工作区页面展示捕获会话的模式、目标、状态、持续时间和事务数量。
- 捕获会话支持双击下钻到流量探索，并使用可清除的会话筛选标签隔离该次采集的事务。
- HTTP 与已解密的 HTTPS/HTTP 1.1 请求在本地工作区持久化原始 URL、查询参数、请求头、Cookie、正文和响应头；本地流量检查器按独立区块展示。AI 对话采用摘要先行、模型按需调用 `get_transactions` 取完整原始证据的方式，便于临时测试账号的协议逆向。
- 流量探索提供带中文二次确认的“清空记录”，清除事务、捕获会话和正文 Blob，保留工作区配置与脱敏审计日志；采集中禁止执行。
- 已实现持久化记录组：只接受已写入当前工作区的事务引用，支持创建空组、从 AI 勾选/当前高亮创建、重命名、说明、追加、移除与删除；历史组按事务 ID 从 SQLite 精确恢复，原事务被清理时明确显示缺失数量。可将全组或表中显式选择的最多 30 条可用事务作为唯一 AI 范围。
- 工作区不再是固定路径状态页：工作区目录索引保存当前选择，界面支持新建、切换和重命名；流量数据库、正文 Blob、记录组和审计日志按工作区隔离。切换时会原子清除旧页面状态并重新载入目标工作区，采集或 AI 分析运行中拒绝切换。
- AI 配置区的 TextBox、PasswordBox 与 ComboBox 已统一最小高度和垂直对齐；运行时 UI Automation 像素检查为文本框 37 像素、下拉框 38 像素（受 DPI 像素取整影响），视觉外框等高。
- AI 成功结果已按工作区持久化为有界历史条目：小型元数据、脱敏证据 JSON 与 Markdown 结果分文件保存并通过临时目录原子提交；历史保留精确事务 ID、范围、模型、响应 ID、耗时和令牌计量。界面支持最近 100 条恢复、Markdown 原文复制、`.md` 导出与带确认删除；剪贴板占用会有限重试并显示错误，不再导致工作台退出。
- 采集定时刷新按事务 ID 增量对齐列表，复用未变化的行对象并保持用户当前选择；新增事务不会再强制选中最新一行，也不会通过全量清空列表造成选择闪烁。
- 本地证据区块和 AI 脱敏上下文均改为可选择文本；提供完整原始证据、脱敏 JSON、PowerShell cURL 三种复制方式，并用中文状态明确敏感边界。CONNECT、二进制正文和超过 4 MB 的请求正文不会生成误导性的 cURL。
- 流量探索支持暂停/继续显示刷新；暂停仅固定界面列表，后台代理继续采集，界面显示积压数量，恢复时增量同步且不改变用户选择。
- 流量探索表已将“主机/域名”和“端点”拆为独立紧凑列，长值省略显示并保留完整悬停提示；左右布局为证据区分配更多宽度。原始证据改为“请求 / 响应 / 相关数据”三标签结构，复制操作、异步 Blob 读取、可选文本和主题滚动条保持不变。
- 响应标签页已在底部加入安全可视化预览：支持 PNG/JPEG/GIF/BMP/ICO 图片、格式化 JSON、HTML 安全文本及常见文本类型；预览不执行 HTML/脚本、不加载远程资源，图片读取限制为 4 MB。
- WPF 工作台使用统一深色滚动条、保留模式渲染和虚拟化列表；窗口移动与缩放不再执行截图、GDI 拉伸或逐控件同步刷新。
- 实时概览与流量探索表已统一为资源图标、AI 选择、时间、方法、主机/域名、端点、状态、延迟、大小、协议和来源列，并共享类型行色；固定连续列布局已验证缩窄列宽时后续列同步左移。
- 实时概览与流量探索均已加入全主题右键菜单：右键行先切换当前选择，“选择过滤”动态显示该记录的主机、类型、协议和方法，可一键应用或清除全部过滤。定向交互验证主机 `cn.bing.com` 能导航到流量探索并精确筛为 1 条。
- Windows x64 自包含便携发布脚本已兼容 Windows PowerShell 5.1，能清理宿主残留、生成逐文件清单、ZIP 与 SHA-256。0.8.0 包已从 ZIP 独立解压验证：6 个清单文件哈希一致，CoreHost 模拟事务与状态读取通过，SandboxHost 使用真实 Python 和 Job Object 通过，工作台能从包内启动并正确启停包内 CoreHost；目标机无需预装 .NET。
- 证据图谱列表和关系检查器均具备主题滚动能力；脚本验证页改用顶部对齐的 Python 富文本编辑器，18px 固定行高，并对关键字、内置函数、数字、字符串和注释进行本地语法着色。
- 显式代理已通过 Windows TCP 所有者表关联真实客户端进程名与 PID；关联失败时显示“未知进程”，不会伪造来源。
- HTTP 上游连接失败、读取失败和转发超时会持久化为真实 502 事务；本地证据和 AI 按需取数均可保留原始 URL、请求头、Cookie 与请求正文，失败请求不会再从列表中丢失。
- AI 分析页已接入真实模型网关，支持 DeepSeek Chat Completions 和 OpenAI Responses；DeepSeek V4 Flash 为当前默认。密钥保存于 Windows 凭据管理器，普通设置 JSON 与审计日志只记录端点主机、模型、接口类型、令牌用量和响应 ID。
- 模型请求由用户显式触发，首轮只发送事务摘要，完整原始事务由工具按序号取数；保留远程 HTTPS 限制、`store: false`（Responses）、取消、可配置超时/响应上限、输出令牌上限和截断状态提示。
- 流量表支持逐条 AI 勾选、当前筛选批量选择与清除；有勾选时模型严格只分析勾选集合，无勾选时只分析当前高亮事务，超过 30 条明确拒绝。实际发送的完整脱敏集合会在 AI 页预览。
- 模型输出使用 WPF `FlowDocument` 按 Markdown 渲染，支持多级标题、粗体、斜体、行内代码、列表、引用、代码块、分隔线和表格；结果仍可鼠标选择复制。AI 输出令牌上限可在 256–16,384 范围配置并持久化。
- HTTPS `CONNECT` 默认支持真实双向加密隧道转发；另已实现默认关闭的工作区 CA、当前用户根信任启用/撤销、动态站点证书缓存和 HTTPS/HTTP 1.1 解密转发。同一 TLS 隧道可顺序处理最多 1000 个 keep-alive 请求，支持 `Content-Length` 与有界 `chunked` 正文，剥离逐跳头并拒绝冲突正文边界。解密记录会持久化原始 URL、Header、Cookie 与请求/响应正文，TLS 内部格式错误也会保存为失败证据；AI 可按需取得这些完整证据，不绕过证书固定。
- 已实现脚本钩子系统（默认关闭，不改写流量）：代理关键路径四个观察点（请求发送前/发送后、响应写回前/交付后）投递只读 camelCase 事件信封（schema 版本 1），双限有界队列（1024 条 / 64 MB）丢弃最旧并计数；SandboxHost 新增 `hook-worker` 动词拉起受 Windows Job Object 监管的长驻 Python 工作进程，宿主把 `store` 对象直接注入脚本运行命名空间（不存在可 import 的宿主模块，提供 store.save/load/list/delete 受控持久化，cwd 锁定工作区 scripts/data，单文件 1 MB、总量 64 MB，文件名校验拒绝穿越，临时文件名唯一后缀且配额与写入同锁）；200 毫秒看门狗超时置废弃标记继续（单工作线程串行，至多一个钩子触碰 store），心跳 heartbeat-ack 回环探活与滑动窗口熔断重启，优雅关停限时清队再发 shutdown。工作区 `scripts/hook-config.json` 是唯一启用入口；旧设置字段只为兼容保留。Python 缺失、配置损坏或工作进程崩溃均静默降级直通，加密隧道不可钩；脚本返回 `None` 不写 finding，返回对象才形成 `hooks.finding` 审计事件。
- 已实现无感抓包（默认关闭）：设置页开关开启后，开始采集自动把系统代理接管为回环监听地址（`<local>` 绕过），停止时按接管前快照还原；原始设置先写入 %LocalAppData%\NetMind 哨兵文件，异常退出后下次启动可据此恢复；接管/还原/还原失败写入审计日志（system-proxy.applied/restored/restore-failed）。UWP 回环隔离与 WinHTTP 不读 WinINET 代理的已知限制已在安装文档说明。
- Release 全量构建、SQLite/Blob/脱敏测试、HTTP 代理端到端转发测试和界面后台启动/停止测试均已通过。

## 当前仓库已验证能力

- 解决方案与独立进程骨架、工作区清单、SQLite 元数据、内容寻址 Blob、审计日志和稳定脱敏。
- CoreHost 捕获会话持久化、HTTP/1.1 显式代理端到端转发、HTTPS `CONNECT` 双向加密隧道、可选 HTTPS/HTTP 1.1 解密和模拟数据提供器。
- HTTP 与 HTTPS 隧道事务的 Windows 客户端进程/PID 关联，以及无法关联时的明确降级状态。
- 采集浏览器启动计划包含独立配置目录、HTTP/HTTPS 分协议代理、回环目标捕获和 QUIC 禁用参数。
- HTTP/2 帧、WebSocket 帧、SSE、gRPC envelope、DNS 问题和 Protobuf wire 字段的有界确定性解析。
- 确定性字段传播与端点聚类。
- SandboxHost 随机暂存目录、Python 隔离参数、敏感环境清理、静态策略、输出上限、超时和真实 Python 样例执行。
- WPF 工作台的全中文界面、深色高对比度配色、主题滚动条、中文证据检查器，以及虚拟化流量列表。
- 工作区 CA 与 `--tls-inspect` 已实现并通过本地 TLS 上游定向测试；测试覆盖同一 TLS 连接连续 GET、chunked POST、原始证据持久化、AI 脱敏和无效边界的 TLS 内 400 响应。功能默认关闭且必须由用户在工作区界面明确启用。
- 工作区 HTTPS 策略支持原子保存最多 200 条精确域名或子域名通配符；CONNECT 在启动时加载策略，匹配域名走原始加密隧道。定向测试验证真实 TLS 上游可访问且敏感路径和正文不进入本地证据。
- 钩子系统定向验证（`--hooks-only`）：脚本静态策略分支回归（open()/exec()/import os 拒绝）、信封 camelCase 序列化契约逐字段对照与 schema 版本、队列超容量/超字节丢弃计数与后续出队、钩子配置默认关闭/往返一致/损坏中文异常/无 tmp 残留、设置总开关默认与往返、hookEngine=null 时代理直通完成请求；本机 Python 可发现时追加 hook-worker 端到端子断言（ready/finding/store 落盘/shutdown 优雅退出），否则跳过不视为失败。
- 系统代理快照 JSON 往返与哨兵文件原子读写定向验证（`--sysproxy-only`，不触碰真实系统代理）。
- 输入数据内嵌 JSON 逐字段截断：响应正文等字段以整串字符串携带 JSON 时，原展示把整串当一个值截断（2048 字符），长字段之后的兄弟字段被整体吞掉；`JsonPreviewTreeBuilder` 现在对字符串值尝试解析为内嵌 JSON，成功则展开为容器子树（标注“字符串内嵌 JSON”），其中长值仍按 `JsonPreviewMaximumValueCharacters` 逐字段截断；新增解析长度上限 8 MB 与最大嵌套深度 6 防病理数据，非法 JSON/纯文本回退原截断逻辑；`--json-only` 新增断言：展开后兄弟字段保留且长值逐字段截断。
- 修复 AI 输入数据预览 JSON 树水平滚动条要拖到最底才可见：根因是 `AiContextJsonTree` 位于外层无限高滚动容器中且自身未限高，树被撑到全部内容高度，树内 ScrollViewer 的水平滚动条绘制在整棵树的底部（几千像素之下）；补上 `MaxHeight="480"`（与 `AiRawResponseTree`/`TrafficResponseJsonTree` 同一限界模式），水平/垂直滚动改由树内 ScrollViewer 接管，水平滚动条即刻出现在可视区底部。

## Release blockers / external integration work

- WinDivert 驱动文件（WinDivert.dll / WinDivert64.sys）的生产签名与自动部署；ETW process lifecycle tracker, and transparent redirect recovery.（静默抓包捕获链路已实现并默认关闭，见 2026-08-08 增量）
- HTTP/2 ALPN/HPACK 解密转发（代理转发路径；静默抓包路径的 HTTP/2/HTTP/3 key-log 解密已实现）、WebSocket 压缩/分片续帧、gRPC 压缩和 Protobuf descriptors。
- Windows AppContainer 或受限令牌、只读输入 ACL 与更严格的结果 schema 校验。
- Multi-provider cost routing, repeatable model evaluation suites, and human approval policy for future side effects.

The release blockers are deliberately not presented as implemented capabilities.
