using System.Security.Cryptography;

namespace Yamora;

/// <summary>Owned exact schema-2 request. Credentials are deliberately excluded.</summary>
public sealed class BinaryOperation
{
    public string Method { get; }
    public string Target { get; }
    public string ContentType { get; }
    public string? IfMatch { get; }
    public string? IfNoneMatch { get; }
    public string RequestId { get; }
    private readonly byte[] source;
    public byte[] Source => (byte[])source.Clone();
    internal byte[] OwnedSource => source;
    internal bool Mutation => Method == "PATCH" || Target == "/v1/transactions";
    internal byte Wire => Method == "GET" ? (byte)1 : Method == "POST" ? (byte)5 : (byte)6;
    internal BinaryOperation(string method, string target, string contentType, byte[] source,
        string? match, string? none, string? requestId, BinaryCall call)
    {
        BinaryWire.AsciiInput(target, 1, 511); BinaryWire.AsciiInput(contentType, 0, 95);
        BinaryWire.AsciiInput(match, 0, 31); BinaryWire.AsciiInput(none, 0, 31);
        static bool Named(string value, string prefix) => value.StartsWith(prefix, StringComparison.Ordinal) && Validation.IsId(value[prefix.Length..]);
        var parts = target.Split('/');
        bool document = parts.Length == 6 && parts[0] == "" && parts[1] == "v1" && parts[2] == "collections" && parts[4] == "documents" && Validation.IsId(parts[3]) && Validation.IsId(parts[5]);
        bool query = Named(target, "/v1/query/") || Named(target, "/v1/aggregate/") || Named(target, "/v1/search/");
        bool changes = target == "/v1/changes" || target.StartsWith("/v1/changes?", StringComparison.Ordinal) || target.StartsWith("/v1/changes/stream?", StringComparison.Ordinal);
        Validation.Require(source.Length <= BinaryClient.DocumentLimit && (method == "GET" && changes || method == "POST" && (query || target == "/v1/transactions") || method == "PATCH" && document), "invalid binary operation");
        var media = contentType.Split(';', 2)[0].ToLowerInvariant();
        Validation.Require(method == "GET" ? source.Length == 0 && contentType.Length == 0 : media is "application/json" or "application/yaml" or "text/yaml", "invalid binary operation media");
        if (requestId is null) do { requestId = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16)); } while (requestId.All(c => c == '0'));
        Validation.Require(Validation.Hex(requestId, 32) && requestId.Any(c => c != '0'), "invalid binary operation ID");
        Method = method; Target = target; ContentType = contentType; IfMatch = match; IfNoneMatch = none; RequestId = requestId;
        this.source = new byte[source.Length];
        for (int offset = 0; offset < source.Length; offset += 4096) { call.Check(); source.AsSpan(offset, Math.Min(4096, source.Length - offset)).CopyTo(this.source.AsSpan(offset)); }
        call.Check();
    }
    public override string ToString() => "BinaryOperation[redacted]";
}

public sealed class BinaryUnsupportedPeerException : BinaryException
{
    internal BinaryUnsupportedPeerException() : base(BinaryFailure.Protocol) { }
}

public sealed class BinaryOperationException : BinaryException
{
    /// <summary>Non-null only for an uncertain dispatched mutation.</summary>
    public BinaryOperation? Recovery { get; }
    public BinaryResponse? Response { get; }
    public string LastAfter { get; }
    internal BinaryOperationException(BinaryException error, BinaryOperation? recovery, BinaryResponse? response, string after)
        : base(error.Kind, error.StatusCode, recovery is not null) { Recovery = recovery; Response = response; LastAfter = after; }
}

public sealed record BinaryFeedResult(BinaryResponse Response, string LastAfter);
