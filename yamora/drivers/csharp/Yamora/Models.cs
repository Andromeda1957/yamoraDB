using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace Yamora;

public sealed class ClientOptions
{
    // Numeric canonical IPv4, explicit port, no prefix, query, fragment or userinfo.
    public required string Endpoint { get; init; }
    public string ReadToken { get; init; } = "";
    public string WriteToken { get; init; } = "";
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(5);
    public int MaxRequestBytes { get; init; } = Client.RequestLimit;
    public int MaxResponseBytes { get; init; } = Client.ResponseLimit;
    // Empty uses system roots; supplied roots replace system trust, for this client only.
    public IReadOnlyList<X509Certificate2> TrustedRoots { get; init; } = [];
    public X509Certificate2? ClientCertificate { get; init; }
    // Explicit local chain material for mTLS; never fetched from certificate AIA URLs.
    public IReadOnlyList<X509Certificate2> ClientIntermediates { get; init; } = [];
}

// ETag/revision strings in this API are unquoted lowercase hexadecimal.
public sealed record WriteOptions(string? ETag = null, bool CreateOnly = false, string? RequestId = null);
public sealed record Document(byte[] Source, string ETag, string Revision);
public sealed record Mutation(string ETag, string Revision);
public sealed record JsonResult(JsonElement Value, string Revision);
public sealed record NamesPage(IReadOnlyList<string> Names, string? NextAfter, string Revision);

// Messages deliberately exclude credentials, request/response bodies and URLs.
public class YamoraException : Exception
{
    public bool OutcomeMayBeCommitted { get; }
    internal YamoraException(string message, bool uncertain = false) : base("yamora: " + message)
        => OutcomeMayBeCommitted = uncertain;
}

public sealed class HttpError : YamoraException
{
    public HttpStatusCode StatusCode { get; }
    internal HttpError(HttpStatusCode status, bool write) : base($"HTTP {(int)status}", write && (int)status >= 500)
        => StatusCode = status;
}

public sealed class SchemaPolicyReplicationError : YamoraException
{
    public HttpStatusCode StatusCode => HttpStatusCode.Conflict;
    internal SchemaPolicyReplicationError() : base("schema_policy_replication_unsupported") { }
}

public sealed class TransportError : YamoraException
{
    internal TransportError(bool write) : base("transport failed or deadline expired", write) { }
}

public sealed class RequestCanceled : OperationCanceledException
{
    public bool OutcomeMayBeCommitted { get; }
    internal RequestCanceled(bool write, CancellationToken token)
        : base("yamora: request canceled", token) => OutcomeMayBeCommitted = write;
}
