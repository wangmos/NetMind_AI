using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace NetMind.Core;

public sealed record EndpointCluster(
    string Method,
    string NormalizedEndpoint,
    string Protocol,
    int RequestCount,
    int ErrorCount,
    double ErrorRate,
    int AverageLatencyMilliseconds,
    int P95LatencyMilliseconds,
    IReadOnlyList<string> Processes);

public sealed record ObservedField(Guid TrafficId, string Location, string Name, string Value, int Offset);

public sealed record FieldPropagationFinding(
    string Name,
    string Placeholder,
    int Confidence,
    IReadOnlyList<ObservedFieldEvidence> Evidence);

public sealed record ObservedFieldEvidence(Guid TrafficId, string Location, int Offset);

public sealed record TrafficAnalysisSnapshot(
    DateTimeOffset GeneratedAt,
    int TransactionCount,
    double ErrorRate,
    int P95LatencyMilliseconds,
    IReadOnlyList<EndpointCluster> Clusters);

public static partial class EndpointNormalizer
{
    public static string Normalize(string endpoint)
    {
        if (string.IsNullOrWhiteSpace(endpoint)) return "/";
        var pathAndQuery = Uri.TryCreate(endpoint, UriKind.Absolute, out var absolute) ? absolute.PathAndQuery : endpoint;
        var queryIndex = pathAndQuery.IndexOf('?');
        var path = queryIndex >= 0 ? pathAndQuery[..queryIndex] : pathAndQuery;
        var query = queryIndex >= 0 ? pathAndQuery[(queryIndex + 1)..] : string.Empty;
        var normalizedSegments = path.Split('/', StringSplitOptions.RemoveEmptyEntries)
            .Select(segment => IsIdentifier(segment) ? "{id}" : segment.ToLowerInvariant());
        var normalizedPath = "/" + string.Join('/', normalizedSegments);
        if (string.IsNullOrWhiteSpace(query)) return normalizedPath;
        var keys = query.Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(part => part.Split('=', 2)[0].Trim().ToLowerInvariant())
            .Where(key => key.Length > 0)
            .Distinct(StringComparer.Ordinal)
            .OrderBy(key => key, StringComparer.Ordinal)
            .Select(key => key + "={value}");
        var normalizedQuery = string.Join('&', keys);
        return normalizedQuery.Length == 0 ? normalizedPath : normalizedPath + "?" + normalizedQuery;
    }

    private static bool IsIdentifier(string segment) =>
        Guid.TryParse(segment, out _) ||
        long.TryParse(segment, out _) ||
        HexIdentifier().IsMatch(segment) ||
        OpaqueIdentifier().IsMatch(segment);

    [GeneratedRegex("^[a-fA-F0-9]{8,}$", RegexOptions.CultureInvariant)]
    private static partial Regex HexIdentifier();

    [GeneratedRegex("^[A-Za-z0-9_-]{20,}$", RegexOptions.CultureInvariant)]
    private static partial Regex OpaqueIdentifier();
}

public static class FieldPropagationAnalyzer
{
    public static IReadOnlyList<FieldPropagationFinding> Analyze(IEnumerable<ObservedField> observations)
    {
        return observations
            .Where(item => !string.IsNullOrWhiteSpace(item.Name) && !string.IsNullOrWhiteSpace(item.Value))
            .GroupBy(item => (Name: item.Name.ToLowerInvariant(), item.Value))
            .Where(group => group.Select(item => item.TrafficId).Distinct().Count() >= 2)
            .Select(group =>
            {
                var evidence = group.OrderBy(item => item.TrafficId).ThenBy(item => item.Offset)
                    .Select(item => new ObservedFieldEvidence(item.TrafficId, item.Location, item.Offset)).ToArray();
                var transactions = evidence.Select(item => item.TrafficId).Distinct().Count();
                var locations = evidence.Select(item => item.Location).Distinct(StringComparer.OrdinalIgnoreCase).Count();
                var confidence = Math.Min(99, 65 + transactions * 8 + locations * 5);
                return new FieldPropagationFinding(group.Key.Name, Placeholder(group.Key.Value), confidence, evidence);
            })
            .OrderByDescending(item => item.Confidence)
            .ThenBy(item => item.Name, StringComparer.Ordinal)
            .ToArray();
    }

    public static string Placeholder(string sensitiveValue)
    {
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(sensitiveValue))).ToLowerInvariant();
        return $"{NetMindDefaults.SensitivePlaceholderPrefix}{hash[..8]}]";
    }
}

public static class TrafficAnalysisEngine
{
    public static TrafficAnalysisSnapshot Analyze(IEnumerable<TrafficRecord> source)
    {
        var traffic = source.OrderBy(item => item.Timestamp).ToArray();
        var clusters = traffic
            .GroupBy(item => (item.Method, Endpoint: EndpointNormalizer.Normalize(item.Endpoint), item.Protocol))
            .Select(group =>
            {
                var latencies = group.Select(item => item.LatencyMs).Order().ToArray();
                var errors = group.Count(item => item.StatusCode >= 400);
                return new EndpointCluster(
                    group.Key.Method,
                    group.Key.Endpoint,
                    group.Key.Protocol,
                    group.Count(),
                    errors,
                    group.Any() ? errors * 100d / group.Count() : 0,
                    latencies.Length == 0 ? 0 : (int)Math.Round(latencies.Average()),
                    Percentile95(latencies),
                    group.Select(item => item.Process).Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.OrdinalIgnoreCase).ToArray());
            })
            .OrderByDescending(item => item.RequestCount)
            .ThenBy(item => item.NormalizedEndpoint, StringComparer.Ordinal)
            .ToArray();
        var allLatencies = traffic.Select(item => item.LatencyMs).Order().ToArray();
        var errorCount = traffic.Count(item => item.StatusCode >= 400);
        return new TrafficAnalysisSnapshot(
            DateTimeOffset.UtcNow,
            traffic.Length,
            traffic.Length == 0 ? 0 : errorCount * 100d / traffic.Length,
            Percentile95(allLatencies),
            clusters);
    }

    private static int Percentile95(IReadOnlyList<int> sorted)
    {
        if (sorted.Count == 0) return 0;
        var index = Math.Max(0, (int)Math.Ceiling(sorted.Count * 0.95) - 1);
        return sorted[index];
    }
}
