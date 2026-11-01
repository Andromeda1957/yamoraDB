using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Yamora;

/// <summary>Bounded single-endpoint HTTP/1.1 client; no routing or automatic replay.</summary>
public partial class Client : IDisposable
{
    private static readonly System.Diagnostics.ActivitySource diagnostics = new("Yamora");
    public const int DocumentLimit = 16 * 1024 * 1024;
    public const int RequestLimit = 64 * 1024 * 1024;
    public const int ResponseLimit = 64 * 1024 * 1024;
    private readonly Uri endpoint;
    private readonly IPEndPoint address;
    private readonly string readToken, writeToken;
    private readonly TimeSpan timeout;
    private readonly int requestMaximum, responseMaximum;
    private readonly X509Certificate2[] roots;
    private readonly X509Certificate2? clientCertificate;
    private readonly X509Certificate2[] clientIntermediates;
    private SslStreamCertificateContext? clientContext;
    private bool disposed;
    internal bool RequireContentLength { get; set; }

    public Client(ClientOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        Validation.Require(options.Endpoint is { Length: <= 64 }, "invalid endpoint length");
        // System.Uri and IPAddress accept short, octal, hex and normalized hosts.
        // Validate original spelling before either parser can normalize it.
        var match = Regex.Match(options.Endpoint ?? "", @"\A(http|https)://([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):([0-9]{1,5})/?\z", RegexOptions.CultureInvariant);
        Validation.Require(match.Success, "numeric IPv4 endpoint with explicit port required");
        var host = match.Groups[2].Value;
        Validation.Require(IPAddress.TryParse(host, out var ip) && ip.AddressFamily == AddressFamily.InterNetwork
            && ip.ToString() == host, "canonical IPv4 required");
        var octets = ip!.GetAddressBytes();
        Validation.Require(octets[0] == 127 || octets[0] == 10 || octets[0] == 172 && octets[1] is >= 16 and <= 31
            || octets[0] == 192 && octets[1] == 168, "loopback or RFC1918 required");
        var portText = match.Groups[3].Value;
        Validation.Require(int.TryParse(portText, out var port) && port is >= 1 and <= 65535
            && port.ToString(System.Globalization.CultureInfo.InvariantCulture) == portText, "invalid port");
        endpoint = new Uri(options.Endpoint!, UriKind.Absolute);
        address = new IPEndPoint(ip, port);
        Validation.Token(options.ReadToken);
        Validation.Token(options.WriteToken);
        Validation.Require(options.Timeout > TimeSpan.Zero && options.Timeout <= TimeSpan.FromSeconds(30), "timeout must be positive and at most 30 seconds");
        Validation.Require(options.MaxRequestBytes is > 0 and <= RequestLimit
            && options.MaxResponseBytes is > 0 and <= ResponseLimit, "invalid byte limits");
        ArgumentNullException.ThrowIfNull(options.TrustedRoots);
        ArgumentNullException.ThrowIfNull(options.ClientIntermediates);
        Validation.Require(options.TrustedRoots.Count <= 64, "too many trust roots");
        Validation.Require(options.ClientIntermediates.Count <= 64, "too many client intermediates");
        Validation.Require(options.ClientIntermediates.Count == 0 || options.ClientCertificate is not null, "client intermediates require an mTLS identity");
        Validation.Require(endpoint.Scheme == "https" || options.TrustedRoots.Count == 0 && options.ClientCertificate is null, "certificates require HTTPS");
        Validation.Require(options.ClientCertificate is null || options.ClientCertificate.HasPrivateKey, "mTLS certificate needs a private key");
        roots = [];
        clientIntermediates = [];
        var ownedRoots = new List<X509Certificate2>();
        var ownedIntermediates = new List<X509Certificate2>();
        try
        {
            foreach (var root in options.TrustedRoots) ownedRoots.Add(X509CertificateLoader.LoadCertificate(root.RawData));
            roots = ownedRoots.ToArray();
            if (options.ClientCertificate is not null)
            {
                var pfx = options.ClientCertificate.Export(X509ContentType.Pkcs12);
                try { clientCertificate = X509CertificateLoader.LoadPkcs12(pfx, null, X509KeyStorageFlags.EphemeralKeySet); }
                finally { CryptographicOperations.ZeroMemory(pfx); }
                foreach (var certificate in options.ClientIntermediates)
                    ownedIntermediates.Add(X509CertificateLoader.LoadCertificate(certificate.RawData));
                clientIntermediates = ownedIntermediates.ToArray();
                // ClientCertificates makes SslStream build a local chain with
                // offline:false, outside the peer-validation chain policy.
                // Prebuild it offline so client AIA/OCSP cannot bypass our I/O
                // policy or deadlines. All supplied certs have owned lifetimes.
                clientContext = SslStreamCertificateContext.Create(clientCertificate,
                    new X509Certificate2Collection(clientIntermediates), offline: true);
            }
        }
        catch
        {
            foreach (var root in ownedRoots) root.Dispose();
            foreach (var certificate in ownedIntermediates) certificate.Dispose();
            clientCertificate?.Dispose();
            throw;
        }
        readToken = options.ReadToken;
        writeToken = options.WriteToken;
        timeout = options.Timeout;
        requestMaximum = options.MaxRequestBytes;
        responseMaximum = options.MaxResponseBytes;
    }

    private SocketsHttpHandler Handler()
    {
        var attempts = 0;
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseProxy = false,
            UseCookies = false,
            AutomaticDecompression = DecompressionMethods.None,
            Credentials = null,
            PreAuthenticate = false,
            MaxResponseHeadersLength = 16,
            MaxResponseDrainSize = 0,
            ConnectTimeout = timeout,
            PooledConnectionLifetime = TimeSpan.Zero,
            ActivityHeadersPropagator = null,
            // A new handler per call plus this guard also denies HttpClient's
            // internal retry paths, even if the runtime changes its retry policy.
            ConnectCallback = async (_, token) =>
            {
                if (Interlocked.Increment(ref attempts) != 1) throw new IOException("yamora: replay denied");
                var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
                try
                {
                    await socket.ConnectAsync(address, token).ConfigureAwait(false);
                    return new NetworkStream(socket, ownsSocket: true);
                }
                catch { socket.Dispose(); throw; }
            },
        };
        if (endpoint.Scheme == "https")
        {
            // No validation callback or insecure-mode escape hatch. SslStream
            // checks IP SAN, chain, validity and server-auth EKU.
            var policy = new X509ChainPolicy
            {
                RevocationMode = X509RevocationMode.NoCheck,
                DisableCertificateDownloads = true,
            };
            policy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.1"));
            if (roots.Length > 0)
            {
                policy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                policy.CustomTrustStore.AddRange(roots);
            }
            handler.SslOptions = new SslClientAuthenticationOptions
            {
                EnabledSslProtocols = SslProtocols.Tls13,
                AllowRenegotiation = false,
                AllowTlsResume = false,
                CertificateChainPolicy = policy,
                ClientCertificateContext = clientContext,
            };
        }
        return handler;
    }

    internal sealed record Response(byte[] Body, string Revision, string? ETag, int Status);

    private protected virtual async Task<Response> SendAsync(HttpMethod method, string path, byte[]? body, string? media, string? responseMedia,
        bool write, WriteOptions? conditions, int maximum, string? expectedRevision, CancellationToken ct, params int[] statuses)
    {
        return await ExchangeAsync(method, path, body, media, responseMedia, write, conditions, maximum,
            expectedRevision, Current, Current.Token, () => Current.Uncertain = write, statuses).ConfigureAwait(false);
    }

    internal async Task<Response> ExchangeAsync(HttpMethod method, string path, byte[]? body, string? media, string? responseMedia,
        bool write, WriteOptions? conditions, int maximum, string? expectedRevision, Operation owner, CancellationToken token,
        Action? onDispatch, params int[] statuses)
    {
        token.ThrowIfCancellationRequested();
        Validation.Revision(expectedRevision);
        Validation.Require(body is null || body.Length <= requestMaximum, "request exceeds byte limit");
        var http = new HttpClient(Handler()) { Timeout = System.Threading.Timeout.InfiniteTimeSpan };
        owner.Retain(http);
        using var request = new HttpRequestMessage(method, new Uri(endpoint, path))
        {
            Version = HttpVersion.Version11,
            VersionPolicy = HttpVersionPolicy.RequestVersionExact,
        };
        request.Headers.ConnectionClose = true;
        request.Headers.Accept.ParseAdd("application/json, application/yaml");
        var credential = write ? writeToken : readToken;
        if (path != "/healthz" && credential.Length > 0) request.Headers.TryAddWithoutValidation("Authorization", "Bearer " + credential);
        if (conditions?.ETag is not null) request.Headers.IfMatch.Add(new EntityTagHeaderValue('"' + conditions.ETag + '"'));
        if (conditions?.CreateOnly == true) request.Headers.IfNoneMatch.Add(EntityTagHeaderValue.Any);
        if (conditions?.RequestId is not null) request.Headers.Add("X-Yamora-Request-Id", conditions.RequestId);
        if (body is not null)
        {
            request.Content = new ByteArrayContent(body);
            request.Content.Headers.ContentType = new MediaTypeHeaderValue(media!);
        }
        try
        {
            onDispatch?.Invoke();
            using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, token).ConfigureAwait(false);
            var accepted = statuses.Contains((int)response.StatusCode);
            if (!accepted && !RequireContentLength) throw new HttpError(response.StatusCode, write);
            ValidateHeaders(response, write);
            var revision = Header(response.Headers, "X-YamlDB-Revision");
            if (!Validation.Hex(revision, 16) || expectedRevision is not null && revision != expectedRevision)
                throw new YamoraException("invalid or changed revision", write);
            if (response.Content.Headers.NonValidated.Contains("Content-Encoding"))
                throw new YamoraException("unexpected content encoding", write);
            var length = Framing(response, write);
            if (RequireContentLength && length is null) throw new YamoraException("cluster requires explicit content length", write);
            if (accepted && responseMedia is not null && !ValidMedia(response.Content.Headers.ContentType, responseMedia))
                throw new YamoraException("unexpected response media type", write);
            var cap = Math.Min(accepted ? maximum : 4096, responseMaximum);
            if (length > cap) throw new YamoraException("response exceeds byte limit", write);
            using var output = new MemoryStream();
            await using var stream = await response.Content.ReadAsStreamAsync(token).ConfigureAwait(false);
            var buffer = new byte[8192];
            while (true)
            {
                var count = await stream.ReadAsync(buffer.AsMemory(0, (int)Math.Min(buffer.Length, cap + 1L - output.Length)), token).ConfigureAwait(false);
                if (count == 0) break;
                if (output.Length + count > cap) throw new YamoraException("response exceeds byte limit", write);
                output.Write(buffer, 0, count);
            }
            if (length is not null && length != output.Length) throw new YamoraException("truncated response", write);
            if (response.TrailingHeaders.Any()) throw new YamoraException("unexpected response trailers", write);
            token.ThrowIfCancellationRequested();
            if (!accepted) throw new HttpError(response.StatusCode, write);
            return new Response(output.ToArray(), revision!, Header(response.Headers, "ETag"), (int)response.StatusCode);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (FormatException) { throw new YamoraException("malformed response metadata", write); }
        catch (Exception e) when (e is HttpRequestException or IOException or AuthenticationException)
        { throw new TransportError(write); }
    }

    private static string? Header(HttpResponseHeaders headers, string name)
        => headers.TryGetValues(name, out var values) && values.Count() == 1 ? values.Single() : null;

    private static long? Framing(HttpResponseMessage response, bool write)
    {
        // Parsed header properties can hide invalid raw fields. HttpClient
        // removes the chunk framing, but does not decode other transfer codings.
        var hasTransfer = response.Headers.NonValidated.TryGetValues("Transfer-Encoding", out var transfer);
        var hasLength = response.Content.Headers.NonValidated.TryGetValues("Content-Length", out var lengths);
        if (hasTransfer && (hasLength || transfer.Count != 1 || !string.Equals(transfer.First().Trim(' ', '\t'), "chunked", StringComparison.OrdinalIgnoreCase)))
            throw new YamoraException("invalid or conflicting transfer framing", write);
        if (!hasLength) return null;
        if (lengths.Count != 1) throw new YamoraException("duplicate content length", write);
        var text = lengths.First().Trim(' ', '\t');
        if (text.Length == 0 || !text.All(c => c is >= '0' and <= '9')
            || !long.TryParse(text, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var length))
            throw new YamoraException("invalid content length", write);
        return length;
    }

    private static bool ValidMedia(MediaTypeHeaderValue? actual, string expected)
        => actual is not null && (string.Equals(actual.MediaType, expected, StringComparison.OrdinalIgnoreCase)
            || expected == "application/yaml" && string.Equals(actual.MediaType, "text/yaml", StringComparison.OrdinalIgnoreCase))
            && (actual.CharSet is null || string.Equals(actual.CharSet.Trim('"'), "utf-8", StringComparison.OrdinalIgnoreCase));

    private byte[] Encode(JsonElement value)
    {
        Validation.Json(value);
        Validation.Require(value.GetRawText().Length <= requestMaximum, "JSON request exceeds byte limit");
        using var output = new BoundedOutput(requestMaximum);
        using (var writer = new Utf8JsonWriter(output)) value.WriteTo(writer);
        return output.ToArray();
    }

    private sealed class BoundedOutput(int maximum) : MemoryStream
    {
        public override void Write(byte[] buffer, int offset, int count)
        { Validation.Require(Length + count <= maximum, "JSON request exceeds byte limit"); base.Write(buffer, offset, count); }
        public override void Write(ReadOnlySpan<byte> buffer)
        { Validation.Require(Length + buffer.Length <= maximum, "JSON request exceeds byte limit"); base.Write(buffer); }
    }

    private async Task<JsonResult> JsonAsync(HttpMethod method, string path, JsonElement? value, bool write,
        WriteOptions? conditions, string? revision, CancellationToken ct, params int[] statuses)
    {
        var response = await SendAsync(method, path, value is null ? null : Encode(value.Value), "application/json", "application/json", write,
            conditions, ResponseLimit, revision, ct, statuses.Length == 0 ? [200] : statuses).ConfigureAwait(false);
        using var decoding = diagnostics.StartActivity("Yamora.PublicDecode");
        try
        {
            Validation.Utf8.GetCharCount(response.Body);
            using var json = JsonDocument.Parse(response.Body, new JsonDocumentOptions { MaxDepth = 64 });
            Validation.Object(json.RootElement);
            Validation.Json(json.RootElement);
            var requiresRevision = path.StartsWith("/v1/query/", StringComparison.Ordinal)
                || path.StartsWith("/v1/aggregate/", StringComparison.Ordinal) || path.StartsWith("/v1/search/", StringComparison.Ordinal)
                || path == "/v1/transactions";
            if (requiresRevision && !json.RootElement.TryGetProperty("revision", out _))
                throw new YamoraException("missing body revision", write);
            // Job publication revisions can precede the observed database head.
            if (!path.StartsWith("/v1/index-builds", StringComparison.Ordinal) && json.RootElement.TryGetProperty("revision", out var bodyRevision)
                && (bodyRevision.ValueKind != JsonValueKind.String || bodyRevision.GetString() != response.Revision))
                throw new YamoraException("body/header revision mismatch", write);
            return new JsonResult(json.RootElement.Clone(), response.Revision);
        }
        catch (Exception e) when (e is JsonException or ArgumentException or InvalidOperationException)
        { throw new YamoraException("invalid UTF-8 JSON object response", write); }
    }

    private async Task<Document> GetCoreAsync(string collection, string document, string? revision = null, CancellationToken ct = default)
    {
        var response = await SendAsync(HttpMethod.Get, Validation.DocumentPath(collection, document), null, null, "application/yaml",
            false, null, DocumentLimit, revision, ct, 200).ConfigureAwait(false);
        var etag = response.ETag;
        if (etag is null || etag.Length != 18 || etag[0] != '"' || etag[^1] != '"' || !Validation.Hex(etag[1..^1], 16))
            throw new YamoraException("invalid document ETag");
        return new Document(response.Body, etag[1..^1], response.Revision);
    }

    private async Task<Mutation> PutCoreAsync(string collection, string document, ReadOnlyMemory<byte> source,
        WriteOptions? options = null, CancellationToken ct = default)
    {
        options ??= new();
        var path = Validation.DocumentPath(collection, document);
        Validation.Write(options, true);
        Validation.Yaml(source.Span);
        var response = await SendAsync(HttpMethod.Put, path, source.ToArray(), "application/yaml", "application/json", true, options,
            DocumentLimit, null, ct, 200, 201).ConfigureAwait(false);
        // PUT sends YAML but returns JSON.
        return ParseMutation(response);
    }

    private static Mutation MutationResult(JsonElement value, string revision)
    {
        if (!value.TryGetProperty("status", out var status) || status.ValueKind != JsonValueKind.String || status.GetString() != "stored"
            || !value.TryGetProperty("etag", out var etag) || etag.ValueKind != JsonValueKind.String || !Validation.Hex(etag.GetString(), 16)
            || !value.TryGetProperty("revision", out var rev) || rev.ValueKind != JsonValueKind.String || rev.GetString() != revision)
            throw new YamoraException("invalid mutation receipt", true);
        return new Mutation(etag.GetString()!, revision);
    }

    private static Mutation ParseMutation(Response response)
    {
        using var decoding = diagnostics.StartActivity("Yamora.PublicDecode");
        try
        {
            Validation.Utf8.GetCharCount(response.Body);
            using var json = JsonDocument.Parse(response.Body, new JsonDocumentOptions { MaxDepth = 64 });
            Validation.Object(json.RootElement);
            Validation.Json(json.RootElement);
            return MutationResult(json.RootElement, response.Revision);
        }
        catch (Exception e) when (e is JsonException or ArgumentException or InvalidOperationException)
        { throw new YamoraException("invalid mutation receipt", true); }
    }

    private async Task<string> DeleteCoreAsync(string collection, string document, WriteOptions? options = null, CancellationToken ct = default)
    {
        options ??= new();
        Validation.Write(options, false);
        var response = await SendAsync(HttpMethod.Delete, Validation.DocumentPath(collection, document), null, null, null, true,
            options, 0, null, ct, 204).ConfigureAwait(false);
        return response.Revision;
    }

    public void Dispose()
    {
        lock (lifetime)
        {
            if (disposed) return;
            disposed = true;
            if (activeCalls != 0) return;
        }
        ReleaseResources();
    }

    private protected virtual void ReleaseResources()
    {
        foreach (var root in roots) root.Dispose();
        // SslStreamCertificateContext has no public Dispose. Dispose the public
        // chain certs it created and release our reference; runtime-owned native
        // SafeHandles are finalized with the context. Never dispose in-flight.
        if (clientContext is not null)
            foreach (var certificate in clientContext.IntermediateCertificates) certificate.Dispose();
        clientContext = null;
        foreach (var certificate in clientIntermediates) certificate.Dispose();
        clientCertificate?.Dispose();
    }
}
