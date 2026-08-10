using System.Globalization;
using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;

namespace NetMind.Core;

public sealed record CaptureBrowserPlan(string BrowserName, string ExecutablePath, string ProfilePath,
    IReadOnlyList<string> Arguments, IReadOnlyDictionary<string, string> Environment);

public static class CaptureBrowser
{
    /// <summary>按已安装 Chromium 真实版本生成内部一致的桌面测试画像，不随机拼接浏览器版本。</summary>
    public static BrowserEnvironmentProfile CreateCoherentProfile(BrowserEnvironmentProfile? baseline = null)
    {
        var profile = (baseline ?? new BrowserEnvironmentProfile()).Validate();
        var browser = FindInstalledBrowser();
        var version = browser is null ? "129.0.0.0" : NormalizeVersion(FileVersionInfo.GetVersionInfo(browser.Value.Path).FileVersion);
        var chromeToken = "Chrome/" + version;
        var platformToken = profile.Platform switch
        {
            "MacIntel" => "Macintosh; Intel Mac OS X 14_0",
            "Linux x86_64" => "X11; Linux x86_64",
            _ => "Windows NT 10.0; Win64; x64"
        };
        var edgeToken = browser?.Name.Contains("Edge", StringComparison.OrdinalIgnoreCase) == true ? " Edg/" + version : string.Empty;
        var presets = new (int Width, int Height, double Dpr, int Cores)[]
        {
            (1920, 1080, 1.0, 8), (1920, 1080, 1.25, 8), (2560, 1440, 1.25, 8),
            (2560, 1440, 1.5, 12), (1366, 768, 1.0, 4), (3840, 2160, 1.5, 16)
        };
        var preset = presets[RandomNumberGenerator.GetInt32(presets.Length)];
        return (profile with
        {
            Enabled = true,
            UserAgent = $"Mozilla/5.0 ({platformToken}) AppleWebKit/537.36 (KHTML, like Gecko) {chromeToken} Safari/537.36{edgeToken}",
            ScreenWidth = preset.Width,
            ScreenHeight = preset.Height,
            DeviceScaleFactor = preset.Dpr,
            HardwareConcurrency = preset.Cores
        }).Validate();
    }

    public static CaptureBrowserPlan? CreatePlan(string profilePath, IPEndPoint proxyEndpoint, string? keyLogPath = null,
        string startUrl = "about:blank", int remoteDebuggingPort = 0, BrowserEnvironmentProfile? environmentProfile = null,
        bool useProxy = true)
    {
        var browser = FindInstalledBrowser();
        return browser is null ? null : BuildPlan(browser.Value.Name, browser.Value.Path, profilePath, proxyEndpoint,
            startUrl, keyLogPath, remoteDebuggingPort, environmentProfile, useProxy);
    }

    public static CaptureBrowserPlan BuildPlan(string browserName, string executablePath, string profilePath,
        IPEndPoint proxyEndpoint, string startUrl = "about:blank", string? keyLogPath = null, int remoteDebuggingPort = 0,
        BrowserEnvironmentProfile? environmentProfile = null, bool useProxy = true)
    {
        if (string.IsNullOrWhiteSpace(browserName)) throw new ArgumentException("浏览器名称不能为空。", nameof(browserName));
        if (string.IsNullOrWhiteSpace(executablePath)) throw new ArgumentException("浏览器路径不能为空。", nameof(executablePath));
        if (string.IsNullOrWhiteSpace(profilePath)) throw new ArgumentException("浏览器配置目录不能为空。", nameof(profilePath));
        if (!Uri.TryCreate(startUrl, UriKind.Absolute, out _)) throw new ArgumentException("浏览器起始地址无效。", nameof(startUrl));

        var fullProfilePath = Path.GetFullPath(profilePath);
        var proxy = proxyEndpoint.ToString();
        var arguments = new List<string>
        {
            $"--user-data-dir={fullProfilePath}",
            "--disable-quic",
            // 禁用 HTTP 磁盘缓存：缓存命中的资源不发网络请求，任何抓包模式都看不到；
            // 采集浏览器全部走网络，确保 JS/CSS/图片等静态资源可被捕获（未知开关会被 Chromium 忽略，双写兼容新旧版本）。
            "--disable-http-cache",
            "--disable-cache",
            "--no-first-run",
            "--no-default-browser-check",
            "--new-window",
        };
        if (useProxy)
        {
            arguments.Add($"--proxy-server=http={proxy};https={proxy}");
            // 页内 Hook 上报端点位于本机回环。必须直连，否则上报会再次进入采集代理，
            // 在浏览器私有网络访问策略下表现为“CDP 已注入，但一条 Hook 数据也收不到”。
            arguments.Add("--proxy-bypass-list=127.0.0.1;localhost;[::1]");
        }
        // 页内 Hook 注入通道：仅监听回环的调试端口，供 PageHookInjector 经 CDP 注入脚本；不传（≤ 0）时不开启。
        if (remoteDebuggingPort > 0)
        {
            arguments.Add($"--remote-debugging-port={remoteDebuggingPort}");
            arguments.Add("--remote-debugging-address=127.0.0.1");
        }
        var browserEnvironment = (environmentProfile ?? new BrowserEnvironmentProfile()).Validate();
        if (browserEnvironment.Enabled)
        {
            arguments.Add($"--window-size={browserEnvironment.ScreenWidth},{browserEnvironment.ScreenHeight}");
            arguments.Add("--force-device-scale-factor=" + browserEnvironment.DeviceScaleFactor.ToString("0.##", CultureInfo.InvariantCulture));
            var primaryLanguage = browserEnvironment.AcceptLanguage.Split(',', 2)[0].Split(';', 2)[0].Trim();
            if (primaryLanguage.Length > 0) arguments.Add("--lang=" + primaryLanguage);
            if (browserEnvironment.WebRtcPolicy != "default")
                arguments.Add("--force-webrtc-ip-handling-policy=" + browserEnvironment.WebRtcPolicy);
            // 启动参数覆盖第一次导航；CDP 会在每个新 target 上再次设置 UA + Client Hints，保持两层一致。
            if (browserEnvironment.UserAgent.Length > 0) arguments.Add("--user-agent=" + browserEnvironment.UserAgent);
        }
        arguments.Add(startUrl);
        // 浏览器经 SSLKEYLOGFILE 写出会话密钥，采集后台增量读取同一文件解密；
        // 两端路径由工作区相对路径约定锁死，缺一端则退化为隧道模式。
        var environment = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (!string.IsNullOrWhiteSpace(keyLogPath))
            environment[NetMindDefaults.SslKeyLogFileEnvironmentVariable] = Path.GetFullPath(keyLogPath);
        return new CaptureBrowserPlan(browserName, Path.GetFullPath(executablePath), fullProfilePath, arguments, environment);
    }

    private static (string Name, string Path)? FindInstalledBrowser()
    {
        var configured = Environment.GetEnvironmentVariable(NetMindDefaults.BrowserEnvironmentVariable);
        if (!string.IsNullOrWhiteSpace(configured) && File.Exists(configured)) return ("自定义浏览器", configured);

        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        (string Name, string Path)[] candidates =
        [
            ("Microsoft Edge", Path.Combine(programFilesX86, "Microsoft", "Edge", "Application", "msedge.exe")),
            ("Microsoft Edge", Path.Combine(programFiles, "Microsoft", "Edge", "Application", "msedge.exe")),
            ("Google Chrome", Path.Combine(programFiles, "Google", "Chrome", "Application", "chrome.exe")),
            ("Google Chrome", Path.Combine(programFilesX86, "Google", "Chrome", "Application", "chrome.exe")),
            ("Google Chrome", Path.Combine(localAppData, "Google", "Chrome", "Application", "chrome.exe"))
        ];
        return candidates.FirstOrDefault(candidate => File.Exists(candidate.Path)) is var match && !string.IsNullOrEmpty(match.Path)
            ? match
            : null;
    }

    private static string NormalizeVersion(string? value)
    {
        var parts = (value ?? string.Empty).Split(['.', ' ', '-'], StringSplitOptions.RemoveEmptyEntries)
            .Where(part => part.All(char.IsDigit)).Take(4).ToList();
        while (parts.Count < 4) parts.Add("0");
        return parts.Count > 0 && parts[0] != "0" ? string.Join('.', parts) : "129.0.0.0";
    }
}
