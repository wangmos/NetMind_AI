# 安装与运行

> 脚本 Hook 运行期间，采集后台会在当前工作区 `scripts/hook-status.json` 原子发布轻量指标。工作台“脚本”页右侧的“采集钩子”卡片可查看投递、处理、丢弃、错误与重启数，并可用“试跑钩子”在临时数据目录做无副作用验证。

## 系统要求

- Windows 10 1903 或更高版本，推荐 Windows 11。
- 开发构建需要稳定版 .NET 10 SDK 10.0.302（仓库 `global.json` 已锁定且禁止预览 SDK）；直接运行发布包时可使用自包含版本，无需预装运行时。
- 执行 Python 验证脚本与可选的请求钩子系统都需要 Python 3；未安装时其余功能仍可使用，脚本页会显示明确的“运行时不可用”状态，钩子系统则保持关闭且不影响采集。
- 推荐显示分辨率 1440 × 900 或更高。WPF 工作台最小窗口尺寸为 1120 × 700。

## 从源码运行

在项目根目录打开 PowerShell：

```powershell
dotnet restore NetMind.slnx
dotnet run --project src/NetMind.Workbench/NetMind.Workbench.csproj
```

首次启动会导入或创建默认本地工作区：

```text
%LOCALAPPDATA%\NetMind\workspaces\northstar-lab
```

工作区中包含 `workspace.json`、`metadata.db`、`traffic-groups`、`ai-history`、`logs/audit.jsonl` 与按 SHA-256 分目录存储的 `blobs`。程序不会在首次启动时安装证书或开启 HTTPS 检查。

## 使用工作区与记录组

“工作区”是项目级数据容器，不只是状态页面。打开“工作区”页，在名称框输入项目名称后可新建工作区；也可从下拉列表选择历史工作区后点击“切换”，或重命名当前工作区。各工作区的流量、正文、捕获会话、记录组和审计日志彼此独立。采集正在运行或 AI 正在分析时不能切换工作区。

在“流量探索”中勾选相关事务后点击“保存为记录组”；没有勾选时使用当前高亮的已持久化事务。打开“记录组”页可以修改名称和说明、追加当前选择、移除表中选中项或删除分组。删除分组不会删除原始流量。点击“分析整个记录组”时，如果表格中有明确选择则只分析这些记录，否则分析全组；单次遵守当前 AI 证据事务上限。清空流量会保留记录组定义，但其事务会明确显示为已清理或不存在。

“导出记录组”支持两种格式：完整 ZIP 包同时保存事务元数据、未截断原始请求/响应正文、缺失事务清单和一份 HAR；独立 HAR 1.2 可直接导入支持 HTTP Archive 的其他分析工具。文本正文保存为原文，二进制正文使用 Base64。两种导出均属于本地所有者原始数据，可能包含 Header、Cookie、令牌和业务正文，请按敏感证据文件保管。

“项目与数据”的工作区卡片会显示容量分类。每个项目拥有独立的数据策略：默认永久保留且不限制容量；也可选择保留天数和容量上限。保存非默认策略时会二次确认，并在停止采集后自动按最旧事务应用；“立即整理”可手工执行相同策略、清理无引用正文并压缩 SQLite。容量策略不会自动删除 AI 会话、记录组定义或配置，因此这些文件本身超出上限时会显示“仍高于上限”，不会继续扩大删除范围。

“备份工作区”导出项目级完整 ZIP，包含原始流量、Blob、AI 会话/历史、记录组、脚本、配置和审计，可能含 Cookie、令牌与业务正文。备份要求先停止采集和 AI 分析；“导入备份”会先校验格式与路径安全，再创建新的独立“（导入）”工作区，绝不覆盖当前项目。若只需要把记录组交给其他流量工具，应优先使用较小的记录组 ZIP/HAR，而不是完整工作区备份。

每次成功的模型分析会自动保存到当前工作区。在“AI 分析”右侧历史下拉框中可重新打开最近 100 条结果；“复制结果”复制 Markdown 原文，“导出 MD”生成带模型、范围和令牌计量的 Markdown 文件，“删除历史”只删除该分析结果与脱敏证据快照，不删除原始流量事务。

对话式 AI 会话可在会话列表标题栏点击“导出完整对话”：导出文件包含系统提示、全部轮次的用户提问与 AI 回复、工具调用参数、取数规模、消息时间、耗时和令牌计量。导出副本自动脱敏；工具返回原文按会话安全策略不重复长期保存。旧会话未保存系统提示时，会按当前同名模板补全并在文件中明确标注。

## 使用 HTTP/HTTPS 代理采集

在工作台右上角点击“开始采集”，后台会监听（默认端口 8877，可在“设置”页修改，监听地址固定为本机回环）：

```text
127.0.0.1:8877
```

将需要观察的应用或浏览器的 HTTP 与 HTTPS 代理都设置为该地址即可。停止采集时工作台会通知 CoreHost 完成会话收尾。默认情况下，HTTPS `CONNECT` 建立真实加密隧道，只记录目标主机、建连耗时及双向字节数。

如需查看 HTTPS URL、Header、Cookie 和正文，先停止采集，进入“工作区”页，在“HTTPS 解密与安全边界”中点击“启用 HTTPS 正文抓取”并确认。程序会为当前工作区生成独立 CA，只把公钥加入当前 Windows 用户的受信任根证书；随后重新开始采集即可解密经该显式代理传输的 HTTPS/HTTP 1.1 流量。使用完毕后点击“停用并撤销 CA 信任”。该功能不会修改系统全局代理，不支持 HTTP/2、HTTP/3，也不会绕过应用的证书固定；此类应用可能拒绝连接。

证书固定或不希望解密的站点，可在同一区域的“加密直通域名”输入框配置，使用逗号分隔，例如 `login.example.com, *.bank.example`。保存后下次开始采集时生效；精确规则匹配单一主机，`*.` 规则匹配其子域名。匹配连接仍通过真实 CONNECT 隧道转发，但不会保存路径、Header、Cookie 或正文。

也可以点击顶部“打开采集浏览器”。工作台会先启动采集后台，再使用 `%LOCALAPPDATA%\NetMind\browser-profile` 独立配置目录打开 Microsoft Edge 或 Google Chrome，并仅通过启动参数为该浏览器设置代理。该操作不会改写 Windows 全局代理；浏览器会关闭 QUIC，使 HTTPS 请求进入可记录的 `CONNECT` 隧道。如果浏览器安装在非标准位置，可设置 `NETMIND_BROWSER` 指向 Chromium 浏览器可执行文件。

采集浏览器同时开启仅限回环的 CDP 通道，用于把页内 Hook 挂载到页面、Dedicated/Shared Worker 与符合范围的 ServiceWorker。打开“流量探索 / 页内 Hook”可查看挂载比例和事件；点击“采集自检”会只读核对采集后台、代理端口、Hook 接收端、浏览器 CDP、页面/Worker 挂载、TLS 信任及最近入库证据。报告可完整复制，自检不会修改系统代理、证书或采集数据。

默认情况下，工作台、HTTPS 解密与采集浏览器都不会修改 Windows 系统代理。若希望免逐个配置客户端，可在“设置”页勾选“无感抓包”：开启后，开始采集会自动把系统代理接管为当前回环监听地址（默认绕过列表为 `<local>`，内网与本机地址直连），停止采集时按接管前的快照自动还原。接管前的原始设置会先写入哨兵文件 `%LOCALAPPDATA%\NetMind\system-proxy-sentinel.json`，进程异常退出后下次启动可据此恢复；接管、还原与还原失败均写入审计日志（`system-proxy.applied` / `system-proxy.restored` / `system-proxy.restore-failed`）。已知限制：UWP/商店应用受回环网络隔离约束，默认不经过系统代理；直接使用 WinHTTP 的程序不读取 WinINET 系统代理设置，也不会被接管。

工作台会明确显示当前数据来源：

- “演示数据”：尚未开始真实采集，列表内容用于展示界面和分析流程。
- “真实 HTTP/HTTPS 代理采集中”：CoreHost 正在监听，需要目标应用实际使用该代理。
- “本地真实捕获记录”：展示 SQLite 中已经持久化的真实代理事务。

在“流量探索”中，URL、参数、Cookie、Header 和正文均可直接框选并按 `Ctrl+C` 复制。右侧快捷按钮可复制完整原始证据、脱敏 JSON 或 PowerShell cURL；原始复制可能包含登录态和令牌，只应粘贴到可信位置。查看高频流量时可点击“暂停刷新”固定当前列表，后台采集不会停止，继续刷新后会一次同步暂停期间新增的记录。

如果点击“开始采集”后列表仍为空，请先运行“流量探索 / 页内 Hook / 采集自检”，再按失败项检查。手动代理模式仍要求目标应用把 HTTP 和 HTTPS 请求发送到当前监听地址（默认端口 8877，可在“设置”页修改）；仅打开代理但不配置客户端，不会产生捕获记录。未启用正文抓取时，HTTPS 记录会标记为“HTTPS 隧道（加密）”；启用后，成功解密的记录会标记为“HTTPS 解密 · HTTP/1.1”。

也可以独立运行后台：

```powershell
dotnet run --project src/NetMind.CoreHost/NetMind.CoreHost.csproj -- `
  proxy --listen 127.0.0.1:8877
```

已在工作区界面创建并信任 CA 后，也可用 `--tls-inspect` 启动 HTTPS/HTTP 1.1 解密：

```powershell
dotnet run --project src/NetMind.CoreHost/NetMind.CoreHost.csproj -- `
  proxy --listen 127.0.0.1:8877 --tls-inspect
```

生成模拟事务并查看工作区状态：

```powershell
dotnet run --project src/NetMind.CoreHost/NetMind.CoreHost.csproj -- simulate --count 12
dotnet run --project src/NetMind.CoreHost/NetMind.CoreHost.csproj -- status
```

## 构建 Release 版本

```powershell
dotnet build NetMind.slnx --configuration Release
```

可执行文件位于：

```text
src\NetMind.Workbench\bin\Release\net10.0-windows\NetMind.Workbench.exe
```

## 配置 AI 模型分析

打开“AI 分析”页面，填写模型网关地址、模型、接口类型和推理强度。当前默认配置为：

```text
模型网关：https://api.deepseek.com
模型：deepseek-v4-flash
接口类型：Chat Completions
推理强度：高
```

在密钥框中输入 API Key 后点击“保存配置”。密钥会写入当前 Windows 用户的凭据管理器，目标名称为 `NetMind AI / 模型网关`；`%LOCALAPPDATA%\NetMind\ai-settings.json` 只保存非敏感设置。也可以使用 `NETMIND_AI_API_KEY` 环境变量临时提供密钥。

在“流量探索”表格的 AI 列逐条勾选要分析的事务，也可以先筛选再点击“选择当前筛选”。存在勾选时使用勾选集合；没有勾选时以当前高亮事务为目标，并按配置补全同主机的更早事务。点击“开始新会话”后才会发起网络请求：首轮发送证据池概况和按时间排序的 #序号摘要，模型再通过工具批量读取相关完整原始 URL、Header、Cookie、查询值和请求/响应正文。分析对象应为用户自有测试账号；审计日志和主动对外分享副本仍使用脱敏路径。可在输入区添加 JS、HAR、接口文档或日志作为当前会话证据，首轮只发送文件名，正文由模型按需读取且不会跨重启自动恢复。分析期间可取消，完成后界面显示 Markdown、耗时和输入/输出令牌数；输出上限可配置为 256–65,536。

## 启用 Python 验证脚本与请求钩子

安装 Python 3 后，NetMind 会自动搜索当前用户和系统的常见 Python 安装目录，不要求重新登录或刷新 PATH。也可以显式设置：

```powershell
$env:NETMIND_PYTHON = "C:\Python312\python.exe"
```

工作台只会把脚本和脱敏样例暂存到随机临时目录，通过独立 SandboxHost 使用 `-X utf8 -I -B -S` 参数执行。系统模块、网络、文件打开、动态执行等能力会在启动前被静态策略拒绝；执行时间和输出大小均有上限。

可选的“请求钩子”复用同一套 Python 发现与 SandboxHost 隔离宿主（`hook-worker` 动词拉起长驻工作进程）：未安装 Python 时钩子保持关闭，采集不受影响；已安装时在脚本页右侧“采集钩子”卡片指定脚本、勾选挂载点并启用，再点顶部“保存”即可，详见 `docs/scripting.md` 的请求钩子章节。

## 生成自包含发布包

推荐运行仓库提供的兼容 Windows PowerShell 5.1 的发布脚本。它会同时发布工作台、流量捕获后台和脚本沙箱后台，生成文件清单、逐文件 SHA-256、ZIP 与 ZIP 校验文件：

```powershell
.\packaging\publish-win-x64.ps1 -Version 0.8.0
```

输出位于 `artifacts\NetMind-AI-0.8.0-win-x64.zip`。解压后应保持 `CoreHost` 与 `SandboxHost` 子目录不变，直接双击 `NetMind.Workbench.exe` 即可运行，无需预装 .NET。

仅调试工作台发布参数时可以使用：

```powershell
dotnet publish src/NetMind.Workbench/NetMind.Workbench.csproj `
  --configuration Release `
  --runtime win-x64 `
  --self-contained true `
  -p:PublishSingleFile=true `
  --output artifacts/win-x64
```

该手工命令不会单独整理两个后台宿主，不应作为正式便携包交付方式。

## 常见问题

- 界面字体异常：确认系统已安装“微软雅黑 UI”字体。
- 工作区无法创建：检查当前用户是否可以写入 `%LOCALAPPDATA%`。
- 构建提示正在使用预览 SDK：项目目标框架仍是 .NET 10；正式环境建议安装当前受支持的稳定版 .NET 10 SDK。
