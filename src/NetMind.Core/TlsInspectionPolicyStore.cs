using System.Net;
using System.Text.Json;

namespace NetMind.Core;

public sealed record TlsInspectionPolicy(IReadOnlyList<string> BypassHosts)
{
    public static TlsInspectionPolicy Empty { get; } = new(Array.Empty<string>());
}

public sealed class TlsInspectionPolicyStore
{
    private const int MaximumRules = 200;
    private readonly string _directory;
    private readonly string _path;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web) { WriteIndented = true };

    public TlsInspectionPolicyStore(string workspacePath)
    {
        var root = Path.GetFullPath(workspacePath);
        _directory = Path.GetFullPath(Path.Combine(root, "tls"));
        if (!_directory.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("HTTPS 策略目录不在当前工作区内。");
        _path = Path.Combine(_directory, "policy.json");
    }

    public TlsInspectionPolicy Load()
    {
        if (!File.Exists(_path)) return TlsInspectionPolicy.Empty;
        try
        {
            var policy = JsonSerializer.Deserialize<TlsInspectionPolicy>(File.ReadAllText(_path), JsonOptions);
            return policy is null ? TlsInspectionPolicy.Empty : Normalize(policy.BypassHosts);
        }
        catch (JsonException)
        {
            return TlsInspectionPolicy.Empty;
        }
    }

    public TlsInspectionPolicy SaveFromText(string? value)
    {
        var rules = (value ?? string.Empty).Split([',', ';', '\r', '\n', '\t', ' '], StringSplitOptions.RemoveEmptyEntries);
        return Save(new TlsInspectionPolicy(rules));
    }

    public TlsInspectionPolicy Save(TlsInspectionPolicy policy)
    {
        var normalized = Normalize(policy.BypassHosts);
        Directory.CreateDirectory(_directory);
        var temporary = _path + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            File.WriteAllText(temporary, JsonSerializer.Serialize(normalized, JsonOptions));
            File.Move(temporary, _path, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporary)) File.Delete(temporary);
        }
        return normalized;
    }

    public static bool ShouldBypass(TlsInspectionPolicy policy, string host)
    {
        var normalizedHost = host.Trim().TrimEnd('.').ToLowerInvariant();
        foreach (var rule in policy.BypassHosts)
        {
            if (rule.StartsWith("*.", StringComparison.Ordinal))
            {
                var suffix = rule[1..];
                if (normalizedHost.EndsWith(suffix, StringComparison.Ordinal) && normalizedHost.Length > suffix.Length)
                    return true;
            }
            else if (normalizedHost.Equals(rule, StringComparison.Ordinal))
            {
                return true;
            }
        }
        return false;
    }

    public static string ToEditingText(TlsInspectionPolicy policy) => string.Join(", ", policy.BypassHosts);

    private static TlsInspectionPolicy Normalize(IEnumerable<string>? input)
    {
        var normalized = (input ?? Array.Empty<string>())
            .Select(NormalizeRule)
            .Where(rule => rule.Length > 0)
            .Distinct(StringComparer.Ordinal)
            .OrderBy(rule => rule, StringComparer.Ordinal)
            .ToArray();
        if (normalized.Length > MaximumRules) throw new InvalidDataException($"HTTPS 直通规则最多允许 {MaximumRules} 条。");
        return new TlsInspectionPolicy(normalized);
    }

    private static string NormalizeRule(string? value)
    {
        var rule = (value ?? string.Empty).Trim().TrimEnd('.').ToLowerInvariant();
        if (rule.Length == 0) return string.Empty;
        var host = rule.StartsWith("*.", StringComparison.Ordinal) ? rule[2..] : rule;
        if (host.Length is < 1 or > 253 || host.Any(char.IsControl) || host.Contains('/') || host.Contains(':') && !IPAddress.TryParse(host, out _))
            throw new InvalidDataException($"HTTPS 直通域名无效：{value}");
        if (!IPAddress.TryParse(host, out _) && host.Split('.').Any(label => label.Length is < 1 or > 63 || label.StartsWith('-') || label.EndsWith('-') || label.Any(character => !char.IsLetterOrDigit(character) && character != '-')))
            throw new InvalidDataException($"HTTPS 直通域名无效：{value}");
        if (rule.StartsWith("*.", StringComparison.Ordinal) && IPAddress.TryParse(host, out _))
            throw new InvalidDataException("IP 地址不能使用通配符直通规则。");
        return rule.StartsWith("*.", StringComparison.Ordinal) ? "*." + host : host;
    }
}
