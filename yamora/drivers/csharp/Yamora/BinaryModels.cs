using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Yamora;

public sealed class BinaryClientOptions
{
    public required string Endpoint { get; init; }
    public required string ServerName { get; init; }
    // Explicit roots only: system stores and opaque validation callbacks cannot
    // be frozen. These certificates and the mTLS private key are cloned at construction.
    public required X509Certificate2[] TrustedRoots { get; init; }
    public X509Certificate2? ClientCertificate { get; init; }
    public X509Certificate2[] ClientIntermediates { get; init; } = [];
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(5);
    public int MaxFrameBytes { get; init; } = 65536;
    public int MaxConcurrentCalls { get; init; } = 4;
}

public enum BinaryMethod { Get = 1, Head = 2, Put = 3, Delete = 4 }
public enum BinaryFailure { Protocol, Transport, Deadline, Canceled, Status }

public class BinaryException : YamoraException
{
    public BinaryFailure Kind { get; }
    public int StatusCode { get; }
    internal BinaryException(BinaryFailure kind, int status = 0, bool uncertain = false)
        : base($"binary {kind}" + (status == 0 ? "" : $" {status}"), uncertain)
    { Kind = kind; StatusCode = status; }
    internal static BinaryException Protocol() => new(BinaryFailure.Protocol);
}

public sealed class BinaryUncertainException : BinaryException
{
    public BinaryEnvelope Recovery { get; }
    internal BinaryUncertainException(BinaryEnvelope envelope, BinaryException error)
        : base(error.Kind, error.StatusCode, true) => Recovery = envelope;
}

// No credentials, public mutable backing memory, caller objects, or serialization hooks.
public sealed class BinaryEnvelope
{
    public BinaryMethod Method { get; }
    public string Collection { get; }
    public string Document { get; }
    public string? IfMatch { get; }
    public string? IfNoneMatch { get; }
    public string? RequestId { get; }
    private readonly byte[] source;
    public byte[] Source => (byte[])source.Clone();
    internal byte[] OwnedSource => source;
    internal string Target => $"/v1/collections/{Collection}/documents/{Document}";
    internal bool Mutation => Method is BinaryMethod.Put or BinaryMethod.Delete;
    internal BinaryEnvelope(BinaryMethod method, string collection, string document, byte[] source,
        string? ifMatch, string? ifNoneMatch, string? requestId, BinaryCall call)
    {
        Validation.Require(method is >= BinaryMethod.Get and <= BinaryMethod.Delete, "invalid binary method");
        Validation.Id(collection); Validation.Id(document);
        BinaryWire.AsciiInput(ifMatch, 0, 31); BinaryWire.AsciiInput(ifNoneMatch, 0, 31);
        Validation.Require(source.Length <= BinaryClient.DocumentLimit && (method == BinaryMethod.Put || source.Length == 0), "invalid binary source length");
        if (requestId is null && method is BinaryMethod.Put or BinaryMethod.Delete)
        {
            do { requestId = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16)); } while (requestId.All(c => c == '0'));
        }
        Validation.Require(requestId is null || Validation.Hex(requestId, 32) && requestId.Any(c => c != '0'), "invalid binary request ID");
        Method = method; Collection = collection; Document = document;
        IfMatch = ifMatch; IfNoneMatch = ifNoneMatch; RequestId = requestId;
        this.source = new byte[source.Length];
        for (var offset = 0; offset < source.Length; offset += 4096)
        {
            call.Check();
            source.AsSpan(offset, Math.Min(4096, source.Length - offset)).CopyTo(this.source.AsSpan(offset));
        }
        if (method == BinaryMethod.Put) BinaryReply.Utf8(this.source, call);
        call.Check();
    }
    public override string ToString() => "BinaryEnvelope[redacted]";
}

public sealed class BinaryResponse
{
    public int StatusCode { get; }
    public string Revision { get; }
    public string? ETag { get; }
    public string? RequestId { get; }
    public string? Collection { get; }
    public string? Document { get; }
    public int RepresentationLength { get; }
    private readonly byte[] body;
    public byte[] Body => (byte[])body.Clone();
    internal BinaryResponse(BinaryReply.Metadata meta, byte[] body)
    {
        StatusCode = meta.Status; Revision = meta.Revision; ETag = meta.ETag;
        RequestId = meta.RequestId; Collection = meta.Collection; Document = meta.Document;
        RepresentationLength = meta.RepresentationLength; this.body = body;
    }
    public override string ToString() => "BinaryResponse[redacted]";
}
