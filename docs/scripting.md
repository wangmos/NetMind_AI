# 脚本开发文档

NetMind AI 的"脚本"页面允许在受限本地沙箱中运行 Python 脚本。脚本无法访问网络与任意文件。

脚本分两种用途，共用同一个编辑器，由页面上的"用途"下拉框决定"运行"按钮做什么：

| 用途 | 形态 | 执行时机 | 输入 |
| --- | --- | --- | --- |
| **钩子脚本** | 定义 `on_before_send` 等挂载点函数 | 采集期间由隔离工作进程持续调用 | 本地所有者视图的原始事件 |
| **验证脚本** | 顶层顺序执行，用 `assert` 与退出码表达结论 | 点击"运行验证"时在沙箱中跑一次 | 当前流量表的脱敏 fixture |

钩子脚本详见[请求钩子](#请求钩子可选扩展)章节，验证脚本详见下文 fixture 契约。

## 脚本库

脚本保存在**当前工作区的 `scripts` 目录**，一个工作区可以有任意多个脚本，页面左侧的"脚本库"负责新建、重命名、删除与切换。

- **目录即真相**：脚本库列出的就是 `scripts/*.py`。直接往目录里放一个 `.py` 文件，它就会出现在库中；在资源管理器里删掉，它就消失。不存在"清单里有、磁盘上没有"的幽灵条目。
- **用途**记录在 `scripts/script-library.json`（sidecar）里，因为这一位信息无法从文件内容可靠推断。sidecar 缺失或损坏时退回按内容推断（有挂载点函数即钩子脚本，导入 fixture 即验证脚本），脚本库本身不会因此不可用。
- **脚本名**由 `ScriptLibraryStore.NormalizeFileName` 校验：自动补 `.py`，拒绝路径分隔符、`.`/`..`、文件系统非法字符与超长名。脚本名来自用户输入且会拼进工作区路径，这是唯一的路径穿越防线，`--script-library-only` 对它有专门断言。
- **采集钩子**：`scripts/hook-config.json` 的 `scriptPath` 指向采集期间实际执行的那一个脚本，在页面右侧用"设为采集钩子"指定，列表中带"采集启用"标记。重命名该脚本时配置会同步更新，删除它之前必须先改指向别的脚本。

页面上只有一个写入口：顶部的**保存**同时写脚本文件、用途和右侧的钩子配置。编辑器标题栏的"● 未保存"标记内容与配置的改动，切换脚本前会提示。

## 编辑器智能提示

编辑器内置钩子与 fixture 两套 API 补全，词表来自 `NetMind.Core.HookScriptApi`，与运行时契约同源——`event` 字段反射自 `HookEventEnvelope`，fixture 事务字段反射自 `AiPrivacyFilter.RedactedScriptTransaction`，契约一改提示立刻跟着改。

- **手动唤出**：`Ctrl+J`（推荐）、`Alt+/`、`Ctrl+空格`。
  中文输入法把 `Ctrl+空格` 用作中英文切换，那个组合通常到不了应用，所以 `Ctrl+J` 才是可靠入口。
- **自动弹出**：输入 `event.get('`、`event[`、`store.`、字典字面量里的引号（按上下文补 INTERCEPT 规则字段或改写字段）、`fixture.`，或任意标识符的前两个字母。注释内不弹。
- **操作**：`Enter` / `Tab` 插入，`↑` / `↓` 选择，`Esc` 关闭。插入前会先删掉已键入的前缀。

## netmind 模块与 fixture 契约

沙箱在执行前会在脚本同目录生成 `netmind.py` 模块，脚本通过以下方式取得输入：

```python
from netmind import fixture

for item in fixture.transactions:
    print(item.method, item.endpoint, item.status)
```

- `fixture` 是一个属性字典对象，支持点号访问字段。
- `fixture.transactions` 是一个列表，包含当前流量表中**最近 30 条真实事务**（含 4xx/5xx，便于错误率分析），每条事务均为已脱敏投影。
- 条数上限由 `AiPrivacyFilter.ScriptFixtureMaximumTransactions` 具名常量控制。

## 输入 JSON 字段级结构

工作台传给沙箱的作业 JSON 中，`fixture` 字段结构如下（字段名即脚本中的属性名）：

```json
{
  "transactions": [
    {
      "method": "GET",
      "url": "https://api.example.com/v1/orders?page=1&token=[REDACTED]",
      "host": "api.example.com",
      "endpoint": "/v1/orders",
      "status": 200,
      "latency_ms": 138,
      "size_bytes": 4096,
      "protocol": "HTTP/1.1",
      "process": "msedge.exe",
      "request_summary": "Accept: application/json",
      "response_summary": "application/json; charset=utf-8"
    }
  ]
}
```

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `method` | 字符串 | HTTP 方法，例如 `GET`、`POST`、`CONNECT` |
| `url` | 字符串 | 完整 URL，敏感查询参数已替换为 `[REDACTED]` |
| `host` | 字符串 | 主机名（含非默认端口），无法解析时为空字符串 |
| `endpoint` | 字符串 | 路径端点，敏感查询参数已脱敏 |
| `status` | 整数 | HTTP 状态码；`CONNECT` 等无状态码事务为 0 |
| `latency_ms` | 整数 | 请求耗时（毫秒） |
| `size_bytes` | 整数 | 响应大小（字节） |
| `protocol` | 字符串 | 协议名，例如 `HTTP/1.1`、`HTTPS CONNECT` |
| `process` | 字符串 | 发起请求的进程名 |
| `request_summary` | 字符串 | 请求摘要（已脱敏） |
| `response_summary` | 字符串 | 响应摘要（已脱敏） |

**脱敏契约**：fixture 中的每一个字符串字段都复用与 AI 分析相同的 `AiPrivacyFilter` 脱敏逻辑（见 `AiPrivacyFilter.CreateScriptTransaction`）。Authorization、Cookie 值、令牌、密钥、会话、密码类参数的原值不会进入 fixture。

## 输出契约

- 脚本通过 `print()` 把结论写入 stdout，结果显示在右侧"运行结果"区。
- **退出码 0** → 状态"验证通过"；**退出码非 0** → 状态"验证失败"。
- `assert` 断言失败会以非 0 退出码结束脚本，因此可以直接把规则写成断言。
- stdout 或 stderr 超过输出上限时，工作台会在结果末尾追加"（输出超限已截断）"。

## 可用标准库 vs 禁止清单

沙箱以 `-X utf8 -I -B -S` 隔离模式运行 Python，无法使用任何第三方包，但可以使用 `json`、`math`、`re`、`datetime`、`collections`、`itertools`、`functools`、`statistics` 等纯逻辑标准库。

静态策略在执行前检查脚本，命中即拒绝（不会启动 Python）：

| 禁止导入 | 禁止调用 |
| --- | --- |
| `os` | `open()` |
| `sys` | `exec()` |
| `subprocess` | `eval()` |
| `socket` | `compile()` |
| `ctypes` | `__import__()` |
| `pathlib` | `input()` |
| `shutil` | `breakpoint()` |
| `winreg` | |
| `multiprocessing` | |
| `http` | |
| `urllib` | |

注意：静态策略按文本匹配，注释或字符串中出现被禁调用（如 `open()`）仍会命中；被禁导入仅在以 `from` / `import` 开头的行触发。

## 资源限制

| 项目 | 限制 |
| --- | --- |
| 脚本大小 | ≤ 128 KB（UTF-8 字节数） |
| 默认超时 | 5000 毫秒（CPU/墙钟，超时后整进程树被终止） |
| 内存 | 默认 256 MB（Windows Job Object 强制） |
| 输出 | stdout / stderr 各 256 KB，超出部分丢弃并标记截断 |
| 进程数 | 最多 1 个（Job Object kill-on-close，宿主退出自动终止） |
| 网络与文件 | 不可用；临时工作目录在运行结束后删除 |

## NETMIND_PYTHON 运行时发现

沙箱按以下顺序查找 Python：

1. 作业中显式指定的 Python 路径；
2. 环境变量 `NETMIND_PYTHON`（例如 `C:\Python312\python.exe`）；
3. `%LocalAppData%\Programs\Python\Python*\python.exe`（按版本号倒序）；
4. `Program Files` / `Program Files (x86)` 下的 `Python*\python.exe`；
5. 系统 `PATH` 中的 `python.exe`。

找不到运行时，结果为"运行时不可用"，请安装 Python 3 或设置 `NETMIND_PYTHON`。

## 错误状态词对照

| 状态词 | 含义 |
| --- | --- |
| 验证通过 | 脚本退出码为 0 |
| 验证失败 | 脚本退出码非 0（含 assert 失败、未捕获异常） |
| 策略拒绝 | 静态策略检查命中禁止项，未启动 Python |
| 执行超时 | 超过超时限制，进程已被终止 |
| 运行时不可用 | 未找到可启动的 Python |
| 隔离初始化失败 | Windows Job Object 创建或进程加入失败 |

## 示例

### 断言规则：不允许出现 5xx

```python
from netmind import fixture

server_errors = [item for item in fixture.transactions if item.status >= 500]
assert not server_errors, f'出现 {len(server_errors)} 条 5xx 服务端错误'
print(f'验证通过：{len(fixture.transactions)} 条事务均无 5xx')
```

### 错误率报告

```python
from netmind import fixture

total = len(fixture.transactions)
assert total > 0, '流量表中没有任何事务'
failed = sum(1 for item in fixture.transactions if item.status >= 400)
print(f'事务总数：{total} · 错误率：{failed / total * 100:.1f}%')
```

更多示例可通过脚本页的"插入示例"按钮一键写入编辑器。

## 请求钩子（可选扩展）

请求钩子在代理关键路径的四个观察点上，把只读事件信封异步投递给一个长驻的隔离 Python 工作进程。钩子系统**默认关闭**，语义上只做观察、提取与受控持久化，**不改写任何流量字节**；任何故障（Python 缺失、脚本错误、工作进程崩溃）都静默降级为直通，代理采集不受影响。

### 四个钩子点

| 事件名 | 触发时机 | 用户函数 | 状态码 |
| --- | --- | --- | --- |
| `request.before_send` | 请求即将发往后端之前 | `on_before_send(event)` | 不可得，为 `null` |
| `request.after_send` | 请求已发往后端之后 | `on_after_send(event)` | 已补齐 |
| `response.before_write` | 响应即将写回客户端之前 | `on_before_write(event)` | 已补齐 |
| `response.after_deliver` | 响应已交付客户端之后 | `on_after_deliver(event)` | 已补齐 |

钩子只覆盖 HTTP 与已解密的 HTTPS/HTTP 1.1 请求。未解密的加密 `CONNECT` 隧道字节不可见，因此**隧道流量不可钩**，这与"加密隧道不得被解释为正文"的整体安全原则一致。

### 事件信封字段

每个事件以一行 NDJSON（camelCase）投递，`txnId` 与捕获持久化的事务记录同一标识，便于关联：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `schema` | 整数 | 信封协议版本，当前固定为 1 |
| `event` | 字符串 | 事件名，见上表 |
| `txnId` | 字符串 | 事务标识（GUID） |
| `sessionId` | 字符串 | 捕获会话标识（GUID） |
| `hookName` | 字符串 | 对应的用户函数名 |
| `method` | 字符串 | HTTP 方法 |
| `url` | 字符串 | 完整 URL（本地所有者视图，未脱敏） |
| `host` | 字符串 | 主机名 |
| `endpoint` | 字符串 | 路径与查询 |
| `statusCode` | 整数/空 | 响应状态码；发送前钩子为空 |
| `headers` | 对象/空 | 请求或响应头键值 |
| `bodyPreviewBase64` | 字符串/空 | 正文预览（Base64，最多 256 KB） |
| `bodyTruncated` | 布尔 | 正文预览是否被截断 |
| `bodySha256` | 字符串/空 | 完整正文 SHA-256（十六进制小写） |
| `bodySize` | 整数 | 完整正文字节数 |

钩子函数返回值会作为 `finding`（观察结论）回传采集后台，由后台周期性以 `hooks.finding` 审计事件落盘（payload 含 event/txnId/hookName/data/truncated，与其他审计事件走同一脱敏通道），工作台可在工作区审计日志中查看；单条结论上限 4 KB，超限截断。事件信封属于工作区本地所有者视图：原始观察只送达本机隔离工作进程，任何跨边界（AI 上下文、导出）的使用仍必须先经 `AiPrivacyFilter` 脱敏。

### store 键值存储

宿主把 `store` 对象直接注入脚本运行命名空间，脚本直接使用即可（不存在可 `import` 的宿主模块，`from netmind_hooks import ...` 会以导入失败被拒），用于受控持久化观察结论：

```python
def on_before_write(event):
    if event.get('statusCode', 0) >= 500:
        store.save('server-errors.txt', event.get('url') + '\n')
```

- 接口：`store.save(name, data)`、`store.load(name)`、`store.list()`、`store.delete(name)`。非字符串数据按 JSON 序列化保存。
- 目录：工作进程的工作目录锁定为工作区 `scripts/data`，文件即键，直接落在该目录。
- 文件名规则：只允许字母、数字、下划线、连字符与点；拒绝空名、绝对路径和上级目录穿越。
- 大小上限：单文件 1 MB，目录总量 64 MB；超限抛中文 `ValueError`，由看门狗记为错误后继续。

### 拦截改写（INTERCEPT）

默认情况下钩子只观察、不改写：事件即发即忘，代理不等待脚本。要让脚本**读取并修改数据、再向下传播**，
需要在脚本模块级声明 `INTERCEPT`。只有被规则命中的请求才会阻塞等待裁决，其余流量仍是即发即忘——
工作进程是单线程的，若所有请求都阻塞，一个页面的上百个资源会全部串行排队。

```python
INTERCEPT = [
    # 条件全是正则，可同时约束 URL、方法、主机、路径、头、正文与状态码；给出的条件之间是 AND。
    {'event': 'request.before_send', 'url': r'/v\d+/user/login', 'method': r'^POST$'},
    {'event': 'response.before_write', 'status': r'^4\d\d$', 'headers': {'Content-Type': r'json'}},
]

def on_before_send(event):
    # 拦截命中时，返回值就是改写内容；返回 None 表示原样放行。
    body = event.get('bodyPreviewBase64')
    return {
        'url': 'https://api.test.local/v2/user/login?debug=1',  # 可选，仅请求侧
        'method': 'POST',                                        # 可选，仅请求侧
        'headers': {'X-Debug': '1', 'X-Sign': None},             # None 表示删除该头
        'body': '{"password":"changed"}',
        'finding': {'note': '已替换签名参数用于验证服务端是否校验'},  # 可选，顺带产出结论
    }

def on_before_write(event):
    return {'status': 200, 'body': '{"ok":true}'}   # 响应侧可改状态码
```

- **可改写的挂载点只有两个**：`request.before_send`（发往上游前）与 `response.before_write`（回写浏览器前）。
  另外两个点的数据已经离开，声明它们会被忽略。
- **匹配位置**：`url`、`method`、`host`、`endpoint`、`body`、`status`，以及 `headers`（`{头名: 值正则}`，
  值为空串表示只要求该头存在）。正文匹配只取前 64 KB——这条判断在每个请求上都要跑。
- **正则安全**：模式优先用 .NET 线性引擎（`NonBacktracking`）编译，病态回溯模式也炸不掉代理热路径；
  用到反向引用/环视时退回普通引擎并强制 50 毫秒匹配超时，超时按不命中处理。
  任一模式非法则**整条规则作废**（不做部分生效，否则脚本会以为自己限定了范围，实际却在拦截别的流量）。
- **一律 fail-open**：裁决超时（2 秒）、工作进程崩溃、协议错误、改写正文超过 1 MB，
  一律按原样放行。拦截失败绝不能把浏览器挂住。
- **证据语义**：落库记录的是**实际上线的字节**（即改写后的），同时保留改写前的 URL 与正文，
  并标注该事务被脚本改写过——否则证据链会把脚本的改动说成客户端的原始意图。
- `Content-Length` 始终按改写后的实际正文长度重算。改写 URL 只接受 http(s) 绝对地址，非法值忽略。

### 失败语义

- 单个事件处理有 200 毫秒看门狗；工作进程内固定单个工作线程串行处理事件，超时后当前执行被置废弃标记（其后续输出丢弃），工作线程继续处理下一事件，任意时刻至多一个钩子函数触碰 store。
- 钩子函数抛异常时输出 `error` 消息并继续；脚本加载失败按退出码 3 处理。
- 事件队列双限额：1024 条且累计 64 MB，超限丢弃最旧事件并计数展示。
- 心跳每 5 秒探活：采集后台发送 `heartbeat`，工作进程回 `heartbeat-ack`；失联判定只看写端-读端回环（ack 或 stdout 活动），与是否命中已定义钩子无关，连续 3 次无应答才判定失联；工作进程崩溃按滑动窗口（60 秒内最多 3 次）熔断重启，超限后停用钩子。
- 优雅关停时先限时清队（超时放弃剩余事件）再发 `shutdown`，丢弃情况并入停机生命周期审计。
- 上述任何环节失败时代理关键路径保持直通，采集不中断；生命周期事件写入审计日志（`hooks.enabled` / `hooks.started` / `hooks.crashed` / `hooks.disabled` / `hooks.config-saved`），观察结论写入 `hooks.finding`。

### 开启方式

钩子只使用一个启用入口：在脚本页右侧"采集钩子"卡片中，用"设为采集钩子"指定脚本、勾选挂载点、勾选"启用请求钩子"，然后点顶部"保存"。配置写入工作区 `scripts/hook-config.json`（camelCase 契约：`enabled` / `scriptPath` / `hooks`），新工作区首次进入时自动生成 `scripts/hook-script.py` 作为默认钩子脚本。

启用时的必要条件在保存前集中校验：未指定采集钩子脚本、或一个挂载点都没勾，都会被拒绝并给出中文说明，而不是写出一份启动时才失败的配置。

页面上的"试跑钩子"在临时目录里拉起一个隔离工作进程走一遍挂载点，不改动配置也不碰正式数据。它不要求先有流量：流量表为空时用内置示例事务，未勾选挂载点时按四个全开试跑并在结果里说明。

采集后台（CoreHost `proxy` 命令）启动时读取当前工作区配置，启用且至少选择一个挂载点时才经 SandboxHost 的 `hook-worker` 动词拉起长驻工作进程；配置缺失、损坏、脚本缺失或 Python 不可用时均按关闭处理并给出中文提示。旧设置文件中的 `enableTrafficHooks` 字段仅为兼容保留，不再参与门控。

### 与验证脚本的关系

- 钩子脚本沿用同一套静态策略：`open()`、`exec()`、`import os` 等同样被拒绝，保存与启动前都会校验；宿主能力（os/json/re 等）只存在于注入用的私有执行命名空间，脚本无法经 `import` 取得。
- 两者共用相同的 Python 发现顺序（`NETMIND_PYTHON` 等）与 SandboxHost 隔离宿主；钩子工作进程同样受 Windows Job Object 约束（单进程、256 MB 内存、宿主退出自动终止）。
- 区别：验证脚本是用户手动触发的一次性执行，输入为脱敏样例；请求钩子是随采集长驻的观察（未命中 INTERCEPT 规则时不阻塞代理），输入为本地所有者视图的原始事件，产出结论以 `hooks.finding` 审计事件落盘，可在工作区审计日志中查看。

