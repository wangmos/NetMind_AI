namespace NetMind.Core;

public enum FindingSeverity
{
    Info,
    Low,
    Medium,
    High
}

public sealed record TrafficRecord(
    Guid Id,
    DateTimeOffset Timestamp,
    string Method,
    string Endpoint,
    int StatusCode,
    int LatencyMs,
    long SizeBytes,
    string Process,
    string Protocol,
    string RequestSummary,
    string ResponseSummary,
    string Url = "",
    string QueryParameters = "",
    string RequestHeaders = "",
    string Cookies = "",
    string ResponseHeaders = "");

public sealed record EvidenceRecord(
    string Title,
    string Description,
    string Source,
    int Offset,
    string Value);

public sealed record FindingRecord(
    Guid Id,
    string Title,
    string Summary,
    FindingSeverity Severity,
    int Confidence,
    IReadOnlyList<EvidenceRecord> Evidence);

public sealed record WorkspaceManifest(
    string Name,
    int SchemaVersion,
    DateTimeOffset CreatedAt,
    DateTimeOffset LastOpenedAt);
