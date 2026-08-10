using System.Diagnostics;
using System.ComponentModel;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace NetMind.Core;

public sealed record SandboxJob(
    string Script,
    JsonElement Fixture,
    int TimeoutMilliseconds = 5000,
    int MaximumOutputBytes = 256 * 1024,
    string? PythonPath = null,
    long MaximumMemoryBytes = 256L * 1024 * 1024);

public sealed record SandboxResult(
    bool Succeeded,
    string State,
    string StandardOutput,
    string StandardError,
    int? ExitCode,
    long DurationMilliseconds,
    IReadOnlyList<string> PolicyViolations,
    bool OutputTruncated = false,
    string Enforcement = "未启动隔离进程");

public static class PythonSandboxPolicy
{
    private const int MaximumScriptBytes = NetMindDefaults.SandboxMaximumScriptBytes;
    private static readonly Regex ForbiddenImport = new(
        @"(?im)^\s*(?:from|import)\s+(os|sys|subprocess|socket|ctypes|pathlib|shutil|winreg|multiprocessing|http|urllib)\b",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex ForbiddenCall = new(
        @"(?m)\b(open|exec|eval|compile|__import__|input|breakpoint)\s*\(",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    public static IReadOnlyList<string> Validate(string script)
    {
        var violations = new List<string>();
        if (string.IsNullOrWhiteSpace(script)) violations.Add("脚本不能为空。");
        if (Encoding.UTF8.GetByteCount(script) > MaximumScriptBytes) violations.Add("脚本超过 128 KB 限制。");
        foreach (Match match in ForbiddenImport.Matches(script))
            violations.Add($"禁止导入模块：{match.Groups[1].Value}");
        foreach (Match match in ForbiddenCall.Matches(script))
            violations.Add($"禁止调用能力：{match.Groups[1].Value}()");
        return violations.Distinct(StringComparer.Ordinal).ToArray();
    }
}

public sealed class PythonSandboxRunner
{
    public async Task<SandboxResult> RunAsync(SandboxJob job, CancellationToken cancellationToken = default)
    {
        var violations = PythonSandboxPolicy.Validate(job.Script);
        if (violations.Count > 0)
            return Validate(new SandboxResult(false, "策略拒绝", string.Empty, string.Empty, null, 0, violations));

        var timeout = Math.Clamp(job.TimeoutMilliseconds, 100, 30_000);
        var outputLimit = Math.Clamp(job.MaximumOutputBytes, 1024, 1024 * 1024);
        var memoryLimit = Math.Clamp(job.MaximumMemoryBytes, 64L * 1024 * 1024, 1024L * 1024 * 1024);
        var enforcement = $"Windows Job Object · 最多 1 个进程 · 内存 {memoryLimit / 1024 / 1024} MB · CPU/墙钟 {timeout} 毫秒 · 宿主退出自动终止";
        var workingDirectory = Path.Combine(Path.GetTempPath(), "netmind-sandbox-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(workingDirectory);
        try
        {
            var scriptPath = Path.Combine(workingDirectory, "approved_script.py");
            var fixturePath = Path.Combine(workingDirectory, NetMindDefaults.SandboxFixtureFileName);
            var modulePath = Path.Combine(workingDirectory, "netmind.py");
            await File.WriteAllTextAsync(scriptPath, job.Script, new UTF8Encoding(false), cancellationToken);
            await File.WriteAllTextAsync(fixturePath, job.Fixture.GetRawText(), new UTF8Encoding(false), cancellationToken);
            await File.WriteAllTextAsync(modulePath, BuildFixtureModule(), new UTF8Encoding(false), cancellationToken);

            var python = ResolvePythonPath(job.PythonPath);
            var startInfo = new ProcessStartInfo(python)
            {
                WorkingDirectory = workingDirectory,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8
            };
            startInfo.ArgumentList.Add("-X");
            startInfo.ArgumentList.Add("utf8");
            startInfo.ArgumentList.Add("-I");
            startInfo.ArgumentList.Add("-B");
            startInfo.ArgumentList.Add("-S");
            startInfo.ArgumentList.Add("-c");
            startInfo.ArgumentList.Add("import sys,runpy;sys.path.insert(0,sys.argv[1]);runpy.run_path(sys.argv[2],run_name='__main__')");
            startInfo.ArgumentList.Add(workingDirectory);
            startInfo.ArgumentList.Add(scriptPath);
            MinimizeEnvironment(startInfo.Environment);

            using var process = new Process { StartInfo = startInfo };
            WindowsJobObject jobObject;
            try
            {
                jobObject = WindowsJobObject.Create(TimeSpan.FromMilliseconds(timeout), memoryLimit);
            }
            catch (Exception exception) when (exception is Win32Exception or PlatformNotSupportedException)
            {
                return Validate(new SandboxResult(false, "隔离初始化失败", string.Empty, exception.Message, null, 0, [], Enforcement: enforcement));
            }
            using (jobObject)
            {
            var stopwatch = Stopwatch.StartNew();
            try
            {
                if (!process.Start())
                    return Validate(new SandboxResult(false, "运行时不可用", string.Empty, "无法启动 Python 运行时。", null, 0, [], Enforcement: enforcement));
            }
            catch (Exception exception) when (exception is System.ComponentModel.Win32Exception or FileNotFoundException)
            {
                return Validate(new SandboxResult(false, "运行时不可用", string.Empty,
                    "未找到 Python。请安装 Python 3，或通过 NETMIND_PYTHON 指定 python.exe。", null, 0, [], Enforcement: enforcement));
            }
            try
            {
                jobObject.Assign(process);
            }
            catch (Exception exception) when (exception is Win32Exception or InvalidOperationException)
            {
                try { if (!process.HasExited) process.Kill(entireProcessTree: true); } catch { }
                await process.WaitForExitAsync(CancellationToken.None);
                stopwatch.Stop();
                return Validate(new SandboxResult(false, "隔离初始化失败", string.Empty, exception.Message, process.ExitCode,
                    stopwatch.ElapsedMilliseconds, [], Enforcement: enforcement));
            }

            using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutSource.CancelAfter(timeout);
            var stdoutTask = ReadBoundedAsync(process.StandardOutput, outputLimit, timeoutSource.Token);
            var stderrTask = ReadBoundedAsync(process.StandardError, outputLimit, timeoutSource.Token);
            try
            {
                await process.WaitForExitAsync(timeoutSource.Token);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                if (!process.HasExited) process.Kill(entireProcessTree: true);
                await process.WaitForExitAsync(CancellationToken.None);
                stopwatch.Stop();
                var timedOutOutput = await SafeReadAsync(stdoutTask);
                var timedOutError = await SafeReadAsync(stderrTask);
                return Validate(new SandboxResult(false, "执行超时", timedOutOutput.Text, timedOutError.Text, process.ExitCode,
                    stopwatch.ElapsedMilliseconds, [], timedOutOutput.Truncated || timedOutError.Truncated, enforcement));
            }

            stopwatch.Stop();
            var stdout = await stdoutTask;
            var stderr = await stderrTask;
            return Validate(new SandboxResult(process.ExitCode == 0, process.ExitCode == 0 ? NetMindDefaults.SandboxVerificationPassed : NetMindDefaults.SandboxVerificationFailed,
                stdout.Text, stderr.Text, process.ExitCode, stopwatch.ElapsedMilliseconds, [], stdout.Truncated || stderr.Truncated, enforcement));
            }
        }
        finally
        {
            try { Directory.Delete(workingDirectory, recursive: true); } catch { /* 系统稍后会清理临时目录。 */ }
        }
    }

    private static string BuildFixtureModule() => """
        import json
        class _AttrDict(dict):
            __getattr__ = dict.__getitem__

        def _convert(value):
            if isinstance(value, dict):
                return _AttrDict({key: _convert(item) for key, item in value.items()})
            if isinstance(value, list):
                return [_convert(item) for item in value]
            return value

        with open('fixture.json', 'r', encoding='utf-8') as source:
            fixture = _convert(json.load(source))
        """;

    /// <summary>
    /// 精简子进程环境变量：只保留系统必需项并强制 UTF-8/隔离相关开关。
    /// 供脚本验证与钩子工作进程共用的环境收敛范式。
    /// </summary>
    public static void MinimizeEnvironment(IDictionary<string, string?> environment)
    {
        var allowed = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        foreach (var name in new[] { "SystemRoot", "WINDIR", "TEMP", "TMP" })
            if (environment.TryGetValue(name, out var value)) allowed[name] = value;
        environment.Clear();
        foreach (var item in allowed) environment[item.Key] = item.Value;
        environment["PYTHONNOUSERSITE"] = "1";
        environment["PYTHONDONTWRITEBYTECODE"] = "1";
        environment["PYTHONUTF8"] = "1";
        environment["PYTHONIOENCODING"] = "utf-8";
    }

    /// <summary>
    /// 解析 Python 可执行文件路径：优先显式配置，其次 NETMIND_PYTHON 环境变量，
    /// 再按常见安装目录探测，均未命中时回退到 PATH 中的 python.exe。
    /// 供脚本验证与钩子工作进程共用。
    /// </summary>
    public static string ResolvePythonPath(string? configuredPath)
    {
        if (!string.IsNullOrWhiteSpace(configuredPath)) return configuredPath;
        var environmentPath = Environment.GetEnvironmentVariable("NETMIND_PYTHON");
        if (!string.IsNullOrWhiteSpace(environmentPath)) return environmentPath;

        var candidates = new List<string>();
        var localPrograms = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "Python");
        if (Directory.Exists(localPrograms))
        {
            candidates.AddRange(Directory.EnumerateDirectories(localPrograms, "Python*")
                .OrderByDescending(path => path, StringComparer.OrdinalIgnoreCase)
                .Select(path => Path.Combine(path, "python.exe")));
        }
        foreach (var programFiles in new[]
                 {
                     Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                     Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86)
                 })
        {
            if (string.IsNullOrWhiteSpace(programFiles) || !Directory.Exists(programFiles)) continue;
            candidates.AddRange(Directory.EnumerateDirectories(programFiles, "Python*")
                .OrderByDescending(path => path, StringComparer.OrdinalIgnoreCase)
                .Select(path => Path.Combine(path, "python.exe")));
        }
        return candidates.FirstOrDefault(File.Exists) ?? "python.exe";
    }

    private static async Task<(string Text, bool Truncated)> ReadBoundedAsync(StreamReader reader, int maximumBytes, CancellationToken cancellationToken)
    {
        var output = new StringBuilder();
        var buffer = new char[4096];
        var bytes = 0;
        var truncated = false;
        int read;
        while ((read = await reader.ReadAsync(buffer.AsMemory(), cancellationToken)) > 0)
        {
            var chunk = new string(buffer, 0, read);
            var chunkBytes = Encoding.UTF8.GetByteCount(chunk);
            if (bytes + chunkBytes <= maximumBytes) output.Append(chunk);
            else truncated = true;
            bytes += chunkBytes;
        }
        return (output.ToString(), truncated);
    }

    private static SandboxResult Validate(SandboxResult result)
    {
        if (result.State.Length > 64) throw new InvalidDataException("沙箱结果的状态字段超过 64 个字符。");
        if (result.Enforcement.Length > 256) throw new InvalidDataException("沙箱结果的隔离说明字段超过 256 个字符。");
        return result;
    }

    private static async Task<(string Text, bool Truncated)> SafeReadAsync(Task<(string Text, bool Truncated)> task)
    {
        try { return await task; } catch (OperationCanceledException) { return (string.Empty, false); }
    }
}
