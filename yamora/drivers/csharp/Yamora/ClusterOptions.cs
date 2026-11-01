using System.Security.Cryptography.X509Certificates;

namespace Yamora;

public sealed record ClusterSeed(string Endpoint, int Node);

public sealed class ClusterOptions
{
    public required IReadOnlyList<ClusterSeed> Seeds { get; init; }
    public required string ClusterId { get; init; }
    public int Voters { get; init; } = 3;
    public string ReadToken { get; init; } = "";
    public string WriteToken { get; init; } = "";
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(5);
    public TimeSpan AttemptTimeout { get; init; } = TimeSpan.FromSeconds(1);
    public int MaxRequestBytes { get; init; } = Client.RequestLimit;
    public int MaxResponseBytes { get; init; } = Client.ResponseLimit;
    public IReadOnlyList<X509Certificate2> TrustedRoots { get; init; } = [];
    public X509Certificate2? ClientCertificate { get; init; }
    public IReadOnlyList<X509Certificate2> ClientIntermediates { get; init; } = [];

    internal ClientOptions Transport(string endpoint) => new()
    {
        Endpoint = endpoint,
        ReadToken = ReadToken,
        WriteToken = WriteToken,
        Timeout = Timeout,
        MaxRequestBytes = MaxRequestBytes,
        MaxResponseBytes = MaxResponseBytes,
        TrustedRoots = TrustedRoots,
        ClientCertificate = ClientCertificate,
        ClientIntermediates = ClientIntermediates,
    };
}

/// <summary>Immutable replay inputs. Body returns a defensive copy. Contains no credentials.</summary>
public sealed class ClusterWrite
{
    private readonly byte[]? payload;
    public string Method { get; }
    public string Path { get; }
    public byte[]? Body => payload?.ToArray();
    public string? ContentType { get; }
    public WriteOptions Conditions { get; }
    public string RequestId => Conditions.RequestId!;
    public int OperationCount { get; }
    public string ClusterId { get; }
    public int Voters { get; }
    internal byte[]? Payload => payload;
    internal int Maximum { get; }
    internal string? ResponseMedia { get; }
    internal int[] Statuses { get; }
    internal ClusterWrite(HttpMethod method, string path, byte[]? body, string? media, WriteOptions conditions,
        int count, string clusterId, int voters, int maximum, string? responseMedia, int[] statuses)
    {
        Method = method.Method; Path = path; payload = body?.ToArray(); ContentType = media;
        Conditions = conditions; OperationCount = count; ClusterId = clusterId; Voters = voters;
        Maximum = maximum; ResponseMedia = responseMedia; Statuses = statuses.ToArray();
    }
    public override string ToString() => "Yamora.ClusterWrite (immutable recovery inputs)";
}

public sealed class UncertainWriteException : YamoraException
{
    public ClusterWrite Recovery { get; }
    public string RequestId => Recovery.RequestId;
    public string FailureKind { get; }
    internal UncertainWriteException(ClusterWrite recovery, Exception reason)
        : base("write outcome uncertain; recover the original immutable request", true)
    { Recovery = recovery; FailureKind = reason.GetType().Name; }
}

// Recovery returns the original wire receipt, including HTTP status and revision.
// DELETE has an empty body. Arrays are independent of stored recovery inputs.
public sealed record ClusterReceipt(int StatusCode, byte[] Body, string Revision, string? ETag);
