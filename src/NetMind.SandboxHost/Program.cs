using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Text.Json;
using NetMind.Core;

Console.OutputEncoding = Encoding.UTF8;
Console.InputEncoding = Encoding.UTF8;
try
{
    if (args.Length >= 1 && args[0].Equals("hook-worker", StringComparison.OrdinalIgnoreCase))
        return await RunHookWorkerAsync(args);

    if (args.Length != 2 || !args[0].Equals("run", StringComparison.OrdinalIgnoreCase))
    {
        Console.Error.WriteLine("用法：NetMind.SandboxHost run <作业 JSON 路径>");
        Console.Error.WriteLine("　　　NetMind.SandboxHost hook-worker <脚本路径> <数据目录>");
        return 2;
    }

    var jobPath = Path.GetFullPath(args[1]);
    if (!File.Exists(jobPath))
    {
        Console.Error.WriteLine("作业文件不存在。");
        return 2;
    }

    if (new FileInfo(jobPath).Length > 2 * 1024 * 1024)
    {
        Console.Error.WriteLine("作业 JSON 文件超过 2 MB 上限。");
        return 2;
    }

    var job = JsonSerializer.Deserialize<SandboxJob>(await File.ReadAllTextAsync(jobPath), new JsonSerializerOptions(JsonSerializerDefaults.Web))
        ?? throw new InvalidDataException("作业 JSON 不是有效对象。");
    var result = await new PythonSandboxRunner().RunAsync(job);
    Console.WriteLine(JsonSerializer.Serialize(result, new JsonSerializerOptions(JsonSerializerDefaults.Web)));
    return result.Succeeded ? 0 : 3;
}
catch (Exception exception)
{
    Console.Error.WriteLine($"沙箱执行失败：{exception.Message}");
    return 1;
}

// ── hook-worker：长驻 Python 钩子工作进程（NDJSON in / NDJSON out） ────────────

/// <summary>
/// 钩子工作进程动词：静态策略校验用户脚本后，启动受作业对象监管的长驻 Python 进程，
/// 把本进程 stdin 的 NDJSON 信封逐行转发给 Python 驱动，并把其 stdout NDJSON 原样回传。
/// </summary>
static async Task<int> RunHookWorkerAsync(string[] args)
{
    if (args.Length != 3)
    {
        EmitMessage(new { type = HookWorkerMessageTypes.Error, message = "用法：NetMind.SandboxHost hook-worker <脚本路径> <数据目录>" });
        return 2;
    }

    string scriptPath;
    try
    {
        scriptPath = Path.GetFullPath(args[1]);
    }
    catch (Exception exception)
    {
        EmitMessage(new { type = HookWorkerMessageTypes.Error, message = $"钩子脚本路径无效：{exception.Message}" });
        return 2;
    }
    if (!File.Exists(scriptPath))
    {
        EmitMessage(new { type = HookWorkerMessageTypes.Error, message = "钩子脚本不存在。" });
        return 2;
    }

    string dataDirectory;
    try
    {
        dataDirectory = Path.GetFullPath(args[2]);
    }
    catch (Exception exception)
    {
        EmitMessage(new { type = HookWorkerMessageTypes.Error, message = $"钩子数据目录路径无效：{exception.Message}" });
        return 2;
    }

    string script;
    try
    {
        script = await File.ReadAllTextAsync(scriptPath);
    }
    catch (Exception exception)
    {
        EmitMessage(new { type = HookWorkerMessageTypes.Error, message = $"钩子脚本读取失败：{exception.Message}" });
        return 2;
    }

    // 用户钩子脚本沿用脚本验证页的静态策略；宿主生成的 shim 与驱动模块不受该策略约束。
    var violations = PythonSandboxPolicy.Validate(script);
    if (violations.Count > 0)
    {
        EmitMessage(new { type = HookWorkerMessageTypes.Error, message = "钩子脚本未通过静态策略校验：" + string.Join("；", violations) });
        return 3;
    }

    try
    {
        Directory.CreateDirectory(dataDirectory);
    }
    catch (Exception exception)
    {
        EmitMessage(new { type = HookWorkerMessageTypes.Error, message = $"钩子数据目录创建失败：{exception.Message}" });
        return 2;
    }

    var workingDirectory = Path.Combine(Path.GetTempPath(), "netmind-hooks-" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(workingDirectory);
    try
    {
        var userScriptPath = Path.Combine(workingDirectory, "hook_user_script.py");
        var driverPath = Path.Combine(workingDirectory, "hook_driver.py");
        var noBom = new UTF8Encoding(false);
        await File.WriteAllTextAsync(userScriptPath, script, noBom);
        // shim 源码随驱动内联下发，由驱动 exec 在私有命名空间内取得 store；
        // 不写 netmind_hooks 模块、不把任何宿主目录加入 sys.path，用户脚本无法 import 宿主能力。
        await File.WriteAllTextAsync(driverPath, BuildHookDriverModule(BuildHookShimSource(), userScriptPath), noBom);

        var python = PythonSandboxRunner.ResolvePythonPath(null);
        var startInfo = new ProcessStartInfo(python)
        {
            WorkingDirectory = dataDirectory, // cwd 锁定数据目录，store 文件即相对落盘于此。
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
            // 输入侧必须用无 BOM 的 UTF-8：否则 StreamWriter 会在流首写入 BOM，被 Python 端拼进首行信封导致 JSON 解析失败。
            StandardInputEncoding = new UTF8Encoding(false)
        };
        startInfo.ArgumentList.Add("-X");
        startInfo.ArgumentList.Add("utf8");
        startInfo.ArgumentList.Add("-I");
        startInfo.ArgumentList.Add("-B");
        startInfo.ArgumentList.Add("-S");
        startInfo.ArgumentList.Add("-c");
        startInfo.ArgumentList.Add("import sys,runpy;sys.path.insert(0,sys.argv[1]);runpy.run_path(sys.argv[2],run_name='__main__')");
        startInfo.ArgumentList.Add(workingDirectory);
        startInfo.ArgumentList.Add(driverPath);
        PythonSandboxRunner.MinimizeEnvironment(startInfo.Environment);

        Process process;
        try
        {
            process = new Process { StartInfo = startInfo };
            if (!process.Start())
            {
                EmitMessage(new { type = HookWorkerMessageTypes.Error, message = "无法启动钩子工作进程的 Python 运行时。" });
                return 3;
            }
        }
        catch (Exception exception) when (exception is Win32Exception or FileNotFoundException)
        {
            EmitMessage(new { type = HookWorkerMessageTypes.Error, message = "未找到 Python。请安装 Python 3，或通过 NETMIND_PYTHON 指定 python.exe。" });
            return 3;
        }

        using (process)
        {
            // 长驻模式作业对象：内存上限 + 单进程 + 宿主退出即终止，不设累计 CPU 时限。
            WindowsJobObject jobObject;
            try
            {
                jobObject = WindowsJobObject.CreateResident(NetMindDefaults.HookWorkerMaximumMemoryBytes);
                jobObject.Assign(process);
            }
            catch (Exception exception) when (exception is Win32Exception or PlatformNotSupportedException or InvalidOperationException)
            {
                try { if (!process.HasExited) process.Kill(entireProcessTree: true); } catch { }
                EmitMessage(new { type = HookWorkerMessageTypes.Error, message = $"钩子工作进程隔离初始化失败：{exception.Message}" });
                return 4;
            }

            using (jobObject)
            {
                var inputTask = ForwardStandardInputAsync(process);
                var outputTask = ForwardStandardOutputAsync(process);
                var errorTask = ForwardStandardErrorAsync(process);
                await process.WaitForExitAsync();
                try { await Task.WhenAll(outputTask, errorTask); } catch { /* 输出转发失败不影响退出码。 */ }
                _ = inputTask; // 输入转发随宿主 stdin 关闭自然结束，不阻塞退出。
                return process.ExitCode;
            }
        }
    }
    finally
    {
        try { Directory.Delete(workingDirectory, recursive: true); } catch { /* 系统稍后会清理临时目录。 */ }
    }
}

/// <summary>把宿主 stdin 的 NDJSON 行逐行转发给 Python 工作进程；stdin 关闭即关闭对端输入（触发优雅退出）。</summary>
static async Task ForwardStandardInputAsync(Process process)
{
    // 不依赖 Console.In（宿主控制台代码页可能非 UTF-8），直接以 UTF-8 包装标准输入字节流。
    using var hostInput = new StreamReader(Console.OpenStandardInput(), Encoding.UTF8, detectEncodingFromByteOrderMarks: false);
    try
    {
        string? line;
        while ((line = await hostInput.ReadLineAsync()) is not null)
        {
            await process.StandardInput.WriteLineAsync(line);
            await process.StandardInput.FlushAsync();
        }
    }
    catch { /* 工作进程先行退出时写端断开属正常情形。 */ }
    finally
    {
        try { process.StandardInput.Close(); } catch { /* 对端输入可能已关闭。 */ }
    }
}

/// <summary>把 Python 工作进程的 stdout NDJSON 行原样回传给宿主 stdout。</summary>
static async Task ForwardStandardOutputAsync(Process process)
{
    try
    {
        string? line;
        while ((line = await process.StandardOutput.ReadLineAsync()) is not null)
            Console.WriteLine(line);
    }
    catch { /* 输出读取中断不影响主流程。 */ }
}

/// <summary>把 Python 工作进程的 stderr 逐行收敛为 error NDJSON（截断防爆量），绝不原样透传大对象。</summary>
static async Task ForwardStandardErrorAsync(Process process)
{
    try
    {
        string? line;
        while ((line = await process.StandardError.ReadLineAsync()) is not null)
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            EmitMessage(new { type = HookWorkerMessageTypes.Error, source = "python", message = TruncateToMaximumBytes(line) });
        }
    }
    catch { /* 错误流读取中断不影响主流程。 */ }
}

/// <summary>按既有 JSON 约定（camelCase）输出一行 NDJSON 消息。</summary>
static void EmitMessage(object payload)
    => Console.WriteLine(JsonSerializer.Serialize(payload, new JsonSerializerOptions(JsonSerializerDefaults.Web)));

/// <summary>按 UTF-8 字节上限截断文本（单条 finding/error 不超过 <see cref="NetMindDefaults.HookFindingMaximumBytes"/>）。</summary>
static string TruncateToMaximumBytes(string text)
{
    var bytes = Encoding.UTF8.GetBytes(text);
    if (bytes.Length <= NetMindDefaults.HookFindingMaximumBytes) return text;
    return Encoding.UTF8.GetString(bytes.AsSpan(0, NetMindDefaults.HookFindingMaximumBytes));
}

/// <summary>
/// 生成宿主 shim 源码：向用户脚本提供 store.save/load/list/delete 键值存储，
/// cwd 锁定数据目录；文件名校验拒绝路径穿越；单文件与总量配额检查与写入同锁（无 TOCTOU）。
/// 该源码只由驱动在私有命名空间内 exec，不作为可 import 的模块落盘。
/// </summary>
static string BuildHookShimSource() => GetHookStoreModuleTemplate()
    .Replace("__SINGLE_FILE_BYTES__", NetMindDefaults.HookDataSingleFileBytes.ToString(CultureInfo.InvariantCulture))
    .Replace("__TOTAL_BYTES__", NetMindDefaults.HookDataTotalBytes.ToString(CultureInfo.InvariantCulture));

/// <summary>
/// 生成钩子驱动模块：exec shim 源码取得 store 并经 init_globals 注入用户脚本命名空间（用户脚本不可也无需 import 宿主模块），
/// 逐行读 stdin NDJSON 信封，心跳行回 ack，按事件名分发用户钩子（未定义即跳过），
/// 单个工作线程串行执行保证任意时刻至多一个 handler 触碰 store；
/// stdout 输出 ready/finding/error NDJSON；shutdown 行或 stdin 关闭优雅退出。
/// </summary>
static string BuildHookDriverModule(string shimSource, string userScriptPath) => GetHookDriverModuleTemplate()
    .Replace("__SHIM_SOURCE__", JsonSerializer.Serialize(shimSource))
    .Replace("__USER_SCRIPT__", JsonSerializer.Serialize(userScriptPath))
    .Replace("__TIMEOUT_SECONDS__", (NetMindDefaults.HookEventTimeoutMilliseconds / 1000.0).ToString(CultureInfo.InvariantCulture))
    .Replace("__TIMEOUT_MS__", NetMindDefaults.HookEventTimeoutMilliseconds.ToString(CultureInfo.InvariantCulture))
    .Replace("__FINDING_MAXIMUM_BYTES__", NetMindDefaults.HookFindingMaximumBytes.ToString(CultureInfo.InvariantCulture));

// ── 宿主生成的 Python 模板（不受用户脚本静态策略约束，占位符由上方常量注入） ──

/// <summary>宿主 shim 源码模板（由驱动在私有命名空间内 exec，占位符由常量注入）。</summary>
static string GetHookStoreModuleTemplate() => """"
    # NetMind 钩子工作进程宿主 shim（宿主生成）：提供绑定数据目录的键值存储。
    # 该源码由驱动在私有命名空间内 exec 取得 store，不作为可 import 的模块暴露；
    # os/json/re/uuid/threading 仅供 shim 内部使用，用户脚本仅获得注入的 store 对象。
    import json
    import os
    import re
    import threading
    import uuid

    _SINGLE_FILE_BYTES = __SINGLE_FILE_BYTES__
    _TOTAL_BYTES = __TOTAL_BYTES__
    _NAME_PATTERN = re.compile(r'^[A-Za-z0-9_\-\.]+$')
    _STORE_LOCK = threading.Lock()


    def _validate_name(name):
        if not isinstance(name, str) or not name:
            raise ValueError('数据文件名不能为空。')
        if not _NAME_PATTERN.fullmatch(name):
            raise ValueError('数据文件名只允许字母、数字、下划线、连字符与点。')
        if '..' in name or os.path.isabs(name):
            raise ValueError('数据文件名不允许包含上级目录或绝对路径。')
        return name


    def _directory_usage_bytes():
        total = 0
        for entry in os.scandir('.'):
            if entry.is_file():
                total += entry.stat().st_size
        return total


    class _Store:
        # 键值存储：文件即键，进程工作目录（数据目录）即存储根。

        def save(self, name, data):
            name = _validate_name(name)
            text = data if isinstance(data, str) else json.dumps(data, ensure_ascii=False)
            payload = text.encode('utf-8')
            if len(payload) > _SINGLE_FILE_BYTES:
                raise ValueError('单个数据文件超过 1 MB 上限。')
            with _STORE_LOCK:
                # 配额检查与写入同锁完成，消除 TOCTOU；临时文件名带唯一后缀，避免同名覆盖。
                existing = os.path.getsize(name) if os.path.exists(name) else 0
                if _directory_usage_bytes() - existing + len(payload) > _TOTAL_BYTES:
                    raise ValueError('数据目录总量超过 64 MB 上限。')
                temporary = name + '.tmp.' + uuid.uuid4().hex
                try:
                    with open(temporary, 'w', encoding='utf-8', newline='') as target:
                        target.write(text)
                    os.replace(temporary, name)
                finally:
                    if os.path.exists(temporary):
                        os.remove(temporary)
            return len(payload)

        def load(self, name):
            name = _validate_name(name)
            if not os.path.exists(name):
                return None
            with open(name, 'r', encoding='utf-8') as source:
                return source.read()

        def list(self):
            return sorted(entry.name for entry in os.scandir('.')
                          if entry.is_file() and _NAME_PATTERN.fullmatch(entry.name))

        def delete(self, name):
            name = _validate_name(name)
            if os.path.exists(name):
                os.remove(name)
                return True
            return False


    store = _Store()
    """";

/// <summary>钩子驱动模块模板（占位符由常量注入）。</summary>
static string GetHookDriverModuleTemplate() => """"
    # NetMind 钩子工作进程驱动（宿主生成）：stdin 逐行读 NDJSON 信封，分发用户钩子，stdout 输出 NDJSON。
    import json
    import queue
    import sys
    import threading

    _EVENT_HOOKS = {
        'request.before_send': 'on_before_send',
        'request.after_send': 'on_after_send',
        'response.before_write': 'on_before_write',
        'response.after_deliver': 'on_after_deliver',
    }
    _EVENT_TIMEOUT_SECONDS = __TIMEOUT_SECONDS__
    _FINDING_MAXIMUM_BYTES = __FINDING_MAXIMUM_BYTES__


    def _emit(payload):
        sys.stdout.write(json.dumps(payload, ensure_ascii=False))
        sys.stdout.write('\n')
        sys.stdout.flush()


    def _truncate(value):
        text = json.dumps(value, ensure_ascii=False)
        encoded = text.encode('utf-8')
        if len(encoded) <= _FINDING_MAXIMUM_BYTES:
            return value, False
        return encoded[:_FINDING_MAXIMUM_BYTES].decode('utf-8', 'ignore'), True


    # shim 在私有命名空间内 exec：import 全部收进该命名空间，宿主模块不进 sys.modules，
    # 用户脚本拿到的只有注入的 store，无法 import 到 os/json/re 等宿主能力。
    _shim_ns = {}
    exec(__SHIM_SOURCE__, _shim_ns)
    _store = _shim_ns['store']

    try:
        with open(__USER_SCRIPT__, 'r', encoding='utf-8') as _source_file:
            _user_source = _source_file.read()
        _user_globals = {'__name__': 'netmind_hooks_user', 'store': _store}
        exec(compile(_user_source, __USER_SCRIPT__, 'exec'), _user_globals)
    except Exception as exception:
        _emit({'type': 'error', 'message': '钩子脚本加载失败：' + str(exception)})
        sys.exit(3)

    # 脚本用模块级 INTERCEPT 声明要拦截哪些请求，随 ready 一次性上报给宿主。
    # 之后每个请求的匹配都在宿主进程内完成：若下推到这里判断，等于所有流量都被
    # 单线程 worker 串行化，页面会直接卡死。未声明即纯观察，不阻塞任何请求。
    _intercept_rules = []
    try:
        for _rule in (_user_globals.get('INTERCEPT') or [])[:64]:
            if not isinstance(_rule, dict):
                continue
            _event = _rule.get('event')
            if not isinstance(_event, str):
                continue
            _entry = {'event': _event}
            # 条件全是正则，可同时约束 URL、方法、主机、路径、正文与状态码；给出的条件之间是 AND。
            for _field in ('url', 'method', 'host', 'endpoint', 'body', 'status'):
                if isinstance(_rule.get(_field), str):
                    _entry[_field] = _rule[_field]
            # headers: {头名: 值正则}；值为空串表示只要求该头存在。
            if isinstance(_rule.get('headers'), dict):
                _entry['headers'] = {str(_n): ('' if _v is None else str(_v))
                                     for _n, _v in list(_rule['headers'].items())[:64]}
            _intercept_rules.append(_entry)
    except Exception as exception:
        _emit({'type': 'error', 'message': 'INTERCEPT 声明无法解析：' + str(exception)})
        _intercept_rules = []

    _emit({'type': 'ready', 'intercept': _intercept_rules})


    # 单个工作线程 + 可丢弃任务槽：任意时刻至多一个 handler 触碰 store；
    # 超时后给当前执行置废弃标记并继续下一事件，迟到结果丢弃、不再产生新事件处理。
    _WRITE_LOCK = threading.Lock()
    _WORK_QUEUE = queue.Queue(maxsize=1024)


    def _safe_emit(payload):
        with _WRITE_LOCK:
            _emit(payload)


    def _worker():
        while True:
            item = _WORK_QUEUE.get()
            if item is None:
                return
            handler, envelope, state = item
            try:
                result = ('ok', handler(envelope))
            except Exception as exception:
                result = ('error', str(exception))
            state['done'].set()
            if state['obsolete']:
                continue  # 已超时废弃：串行队列保证其后无并发 handler，仅丢弃其输出
            context = {'event': envelope.get('event'), 'txnId': envelope.get('txnId'),
                       'hookName': envelope.get('hookName')}
            status, payload = result

            # 拦截模式：宿主正阻塞等待裁决，任何分支都必须回一条 pass/mutate，否则代理只能等满超时。
            _correlation = state.get('intercept')
            if _correlation is not None:
                if status != 'ok' or not isinstance(payload, dict):
                    if status != 'ok':
                        _safe_emit({'type': 'error', **context, 'message': ('钩子执行异常：' + str(payload))[:_FINDING_MAXIMUM_BYTES]})
                    _safe_emit({'type': 'pass', 'correlationId': _correlation})
                    _safe_emit({'type': 'processed', **context, 'outcome': 'pass'})
                    continue
                _reply = {'type': 'mutate', 'correlationId': _correlation}
                for _key, _wire in (('url', 'url'), ('method', 'method'), ('body', 'body')):
                    if isinstance(payload.get(_key), str):
                        _reply[_wire] = payload[_key]
                if isinstance(payload.get('status'), int):
                    _reply['statusCode'] = payload['status']
                if isinstance(payload.get('headers'), dict):
                    _reply['headers'] = {str(_n): (None if _v is None else str(_v))
                                         for _n, _v in list(payload['headers'].items())[:64]}
                if len(_reply) == 2:  # 只有 type 与 correlationId：没给出任何改写字段
                    _safe_emit({'type': 'pass', 'correlationId': _correlation})
                    _safe_emit({'type': 'processed', **context, 'outcome': 'pass'})
                    continue
                _safe_emit(_reply)
                # 拦截同样可以顺带产出结论：改写事实本身往往就是分析结果。
                if payload.get('finding') is not None:
                    _data, _truncated = _truncate(payload['finding'])
                    _safe_emit({'type': 'finding', **context, 'data': _data, 'truncated': _truncated})
                _safe_emit({'type': 'processed', **context, 'outcome': 'mutate'})
                continue

            if status == 'ok':
                if payload is None:
                    _safe_emit({'type': 'processed', **context, 'outcome': 'none'})
                    continue  # None 表示本次没有高价值结论，不生成空 finding 污染审计日志。
                data, truncated = _truncate(payload)
                _safe_emit({'type': 'finding', **context, 'data': data, 'truncated': truncated})
                _safe_emit({'type': 'processed', **context, 'outcome': 'finding'})
            else:
                message = ('钩子执行异常：' + str(payload))[:_FINDING_MAXIMUM_BYTES]
                _safe_emit({'type': 'error', **context, 'message': message})
                _safe_emit({'type': 'processed', **context, 'outcome': 'error'})


    _worker_thread = threading.Thread(target=_worker, daemon=True)
    _worker_thread.start()


    for _line in sys.stdin:
        _line = _line.strip()
        if not _line:
            continue
        try:
            _message = json.loads(_line)
        except Exception:
            _safe_emit({'type': 'error', 'message': '信封 JSON 无效。'})
            continue
        if not isinstance(_message, dict):
            _safe_emit({'type': 'error', 'message': '信封 JSON 不是对象。'})
            continue
        _type = _message.get('type')
        if _type == 'shutdown':
            break
        if _type == 'heartbeat':
            _safe_emit({'type': 'heartbeat-ack'})
            continue
        # 拦截：宿主正阻塞等待，信封裹在 envelope 里，且每条分支都必须回一条 pass/mutate。
        _correlation = None
        if _type == 'intercept':
            _correlation = _message.get('correlationId')
            _message = _message.get('envelope') or {}
        _event = _message.get('event')
        _hook = _EVENT_HOOKS.get(_event)
        _handler = _user_globals.get(_hook) if _hook else None
        if not callable(_handler):
            if _correlation is not None:
                _safe_emit({'type': 'pass', 'correlationId': _correlation})
            _safe_emit({'type': 'processed', 'event': _event, 'txnId': _message.get('txnId'),
                        'hookName': _hook, 'outcome': 'missing-handler'})
            continue
        _context = {'event': _event, 'txnId': _message.get('txnId'), 'hookName': _hook}
        _state = {'obsolete': False, 'done': threading.Event(), 'intercept': _correlation}
        try:
            _WORK_QUEUE.put_nowait((_handler, _message, _state))
        except queue.Full:
            if _correlation is not None:
                _safe_emit({'type': 'pass', 'correlationId': _correlation})
            _safe_emit({'type': 'error', **_context, 'message': '钩子处理积压，已跳过该事件。'})
            _safe_emit({'type': 'processed', **_context, 'outcome': 'queue-full'})
            continue
        if _state['done'].wait(_EVENT_TIMEOUT_SECONDS):
            continue  # 工作线程已在限时内完成并自行输出
        _state['obsolete'] = True
        if _state['done'].is_set():
            if _correlation is not None:
                _safe_emit({'type': 'pass', 'correlationId': _correlation})
            _safe_emit({'type': 'processed', **_context, 'outcome': 'timeout-boundary'})
            continue  # 刚好在临界完成：工作线程看到废弃标记后会丢弃输出，不再重复报错
        # 超时也要立刻回执：否则宿主只能等满自己的拦截超时，白白拖慢这一个请求。
        if _correlation is not None:
            _safe_emit({'type': 'pass', 'correlationId': _correlation})
        _safe_emit({'type': 'error', **_context, 'message': '钩子处理超时（__TIMEOUT_MS__ 毫秒），已跳过该事件。'})
        _safe_emit({'type': 'processed', **_context, 'outcome': 'timeout'})

    _WORK_QUEUE.put(None)
    """";
