using System.Text.RegularExpressions;

namespace NetMind.Core;

/// <summary>
/// 采集浏览器的可复现测试画像。只包含 Chromium/CDP 能可靠覆盖的高价值字段；
/// WebGL、Canvas、字体等无法保持全栈一致的字段不伪造，避免产生“看似生效”的错误配置。
/// </summary>
public sealed partial record BrowserEnvironmentProfile(
    bool Enabled = false,
    string UserAgent = "",
    string Platform = "Win32",
    int ScreenWidth = 1920,
    int ScreenHeight = 1080,
    double DeviceScaleFactor = 1.0,
    int HardwareConcurrency = 8,
    string TimezoneId = "Asia/Shanghai",
    string Locale = "zh_CN",
    string AcceptLanguage = "zh-CN,zh;q=0.9,en;q=0.8",
    string WebRtcPolicy = "disable_non_proxied_udp")
{
    public BrowserEnvironmentProfile Validate()
    {
        if (UserAgent.Length > 1024) throw new InvalidOperationException("User-Agent 不得超过 1024 个字符。");
        if (Platform is not ("Win32" or "Linux x86_64" or "MacIntel"))
            throw new InvalidOperationException("浏览器平台必须是 Win32、Linux x86_64 或 MacIntel。");
        if (ScreenWidth is < 800 or > 7680 || ScreenHeight is < 600 or > 4320)
            throw new InvalidOperationException("浏览器画像分辨率范围为 800×600 到 7680×4320。");
        if (DeviceScaleFactor is < 0.75 or > 4.0)
            throw new InvalidOperationException("浏览器画像设备像素比范围为 0.75–4.0。");
        if (HardwareConcurrency is < 1 or > 64)
            throw new InvalidOperationException("浏览器画像 CPU 核心数范围为 1–64。");
        if (TimezoneId.Length is < 1 or > 128 || !SafeIcuValue().IsMatch(TimezoneId))
            throw new InvalidOperationException("浏览器画像时区格式无效。");
        if (Locale.Length is < 2 or > 32 || !SafeIcuValue().IsMatch(Locale))
            throw new InvalidOperationException("浏览器画像区域格式无效。");
        if (AcceptLanguage.Length is < 2 or > 256 || AcceptLanguage.Contains('\r') || AcceptLanguage.Contains('\n'))
            throw new InvalidOperationException("浏览器画像语言列表格式无效。");
        if (WebRtcPolicy is not ("default" or "default_public_interface_only" or "disable_non_proxied_udp"))
            throw new InvalidOperationException("浏览器画像 WebRTC 策略无效。");
        return this with
        {
            UserAgent = UserAgent.Trim(),
            TimezoneId = TimezoneId.Trim(),
            Locale = Locale.Trim(),
            AcceptLanguage = AcceptLanguage.Trim()
        };
    }

    public string Summary => Enabled
        ? $"{Platform} · {ScreenWidth}×{ScreenHeight} @{DeviceScaleFactor:0.##}x · {HardwareConcurrency} 核 · {TimezoneId} · {AcceptLanguage.Split(',')[0]}"
        : "使用浏览器原生环境";

    public string CdpPlatformName => Platform switch
    {
        "MacIntel" => "macOS",
        "Linux x86_64" => "Linux",
        _ => "Windows"
    };

    [GeneratedRegex("^[A-Za-z0-9_+./-]+$", RegexOptions.CultureInvariant)]
    private static partial Regex SafeIcuValue();
}
