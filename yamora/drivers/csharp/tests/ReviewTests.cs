using System.Diagnostics;
using System.IO.Compression;
using System.Text;
using Yamora;

namespace DriverTests;

static partial class Program
{
    static async Task OfflineClientCertificate()
    {
        // A different issuer from the server's roots, never added to an OS store.
        // AIA must not open this HTTP listener, even while choosing a client cert.
        await using var aia = new Server(async s =>
        {
            await Task.Delay(3000);
            await Server.Bytes(s, "HTTP/1.1 503 Stalled\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        });
        using var serverIssuer = new Certificates();
        using var clientIssuer = new Certificates();
        using var serverCert = serverIssuer.Issue();
        using var identity = clientIssuer.Issue(client: true, issuerUrl: aia.Endpoint + "/issuer.der");
        await using var server = new Server(s => Server.Bytes(s, Server.Response("{}")), serverCert, clientRoot: clientIssuer.Root);
        var watch = Stopwatch.StartNew();
        using var client = new Client(new ClientOptions
        {
            Endpoint = server.Endpoint, TrustedRoots = [serverIssuer.Root], ClientCertificate = identity,
            Timeout = TimeSpan.FromMilliseconds(500),
        });
        Exception? failure = null;
        try { await client.HealthAsync(); }
        catch (YamoraException e) { failure = e; }
        watch.Stop();
        Check(aia.Connections == 0 && watch.Elapsed < TimeSpan.FromSeconds(2),
            $"client chain fetched AIA: connections={aia.Connections}, elapsed={watch.Elapsed.TotalMilliseconds:F0}ms");
        Check(failure is null, "offline mTLS failed: " + failure?.GetType().Name);
        Console.WriteLine($"  offline mTLS: {watch.Elapsed.TotalMilliseconds:F0}ms; AIA connections={aia.Connections}");
    }

    static async Task RawResponseFraming()
    {
        const string yaml = "# exact source\r\nn: 1\r\n";
        var payload = Encoding.UTF8.GetBytes(yaml);
        using var compressed = new MemoryStream();
        using (var gzip = new GZipStream(compressed, CompressionLevel.Fastest, leaveOpen: true)) gzip.Write(payload);
        var gzipBytes = compressed.ToArray();
        var failures = new List<string>();

        async Task Reject(string label, string framing, byte[] body, bool chunked = false)
        {
            await using var server = new Server(async s =>
            {
                await Server.Bytes(s, "HTTP/1.1 200 OK\r\nContent-Type: application/yaml\r\nETag: \"fedcba9876543210\"\r\nX-YamlDB-Revision: 0123456789abcdef\r\nConnection: close\r\n" + framing + "\r\n");
                if (chunked) await Server.Bytes(s, body.Length.ToString("x", System.Globalization.CultureInfo.InvariantCulture) + "\r\n");
                await s.WriteAsync(body);
                if (chunked) await Server.Bytes(s, "\r\n0\r\n\r\n");
            });
            using var client = New(server.Endpoint);
            try
            {
                var document = await client.GetAsync("examples", "one");
                failures.Add(label + $" returned {document.Source.Length} bytes");
            }
            catch (YamoraException) { }
        }

        await Reject("gzip transfer coding", "Transfer-Encoding: gzip, chunked\r\n", gzipBytes, chunked: true);
        await Reject("compress transfer coding", "Transfer-Encoding: compress, chunked\r\n", payload, chunked: true);
        await Reject("duplicate chunked", "Transfer-Encoding: chunked, chunked\r\n", payload, chunked: true);
        await Reject("empty transfer coding", "Transfer-Encoding:\r\n", payload);
        await Reject("conflicting framing", "Transfer-Encoding: chunked\r\nContent-Length: " + payload.Length + "\r\n", payload, chunked: true);
        foreach (var length in new[] { "invalid", "+" + payload.Length, "-1", "1.0", "9223372036854775808", payload.Length + ", " + payload.Length })
            await Reject("Content-Length=" + length, "Content-Length: " + length + "\r\n", payload);
        await Reject("duplicate Content-Length", $"Content-Length: {payload.Length}\r\nContent-Length: {payload.Length}\r\n", payload);
        await Reject("invalid raw content encoding", "Content-Encoding: ;\r\nContent-Length: " + payload.Length + "\r\n", payload);
        Check(failures.Count == 0, string.Join("; ", failures));
        foreach (var framing in new[] { "", "Content-Length: " + payload.Length + "\r\n", "Transfer-Encoding: CHUNKED\r\n" })
        {
            var chunked = framing.StartsWith("Transfer-Encoding", StringComparison.Ordinal);
            await using var server = new Server(async s =>
            {
                await Server.Bytes(s, "HTTP/1.1 200 OK\r\nContent-Type: application/yaml\r\nETag: \"fedcba9876543210\"\r\nX-YamlDB-Revision: 0123456789abcdef\r\nConnection: close\r\n" + framing + "\r\n");
                if (chunked) await Server.Bytes(s, payload.Length.ToString("x", System.Globalization.CultureInfo.InvariantCulture) + "\r\n");
                await s.WriteAsync(payload);
                if (chunked) await Server.Bytes(s, "\r\n0\r\n\r\n");
            });
            using var client = New(server.Endpoint);
            Check((await client.GetAsync("examples", "one")).Source.SequenceEqual(payload), "allowed framing changed YAML bytes");
        }
    }

    static async Task ExplicitClientIntermediates()
    {
        using var serverIssuer = new Certificates();
        using var clientIssuer = new Certificates();
        using var intermediate = clientIssuer.Intermediate();
        using var serverCert = serverIssuer.Issue();
        using var identity = clientIssuer.Issue(client: true, issuer: intermediate);
        await using var server = new Server(s => Server.Bytes(s, Server.Response("{}")), serverCert, clientRoot: clientIssuer.Root);
        using var client = new Client(new ClientOptions
        {
            Endpoint = server.Endpoint, TrustedRoots = [serverIssuer.Root], ClientCertificate = identity,
            ClientIntermediates = [intermediate], Timeout = TimeSpan.FromSeconds(1),
        });
        // Input lifetimes cannot affect the owned leaf, chain or context.
        identity.Dispose();
        intermediate.Dispose();
        await client.HealthAsync();
        await client.HealthAsync();
    }

    static async Task MalformedTransactionReceipts()
    {
        var failures = new List<string>();
        foreach (var count in new[] { "\"1\"", "null", "true", "false", "{}", "[]", "1.5", "1e400", "-1", "0", "9223372036854775807" })
        {
            var body = "{\"status\":\"committed\",\"operations\":" + count + ",\"revision\":\"0123456789abcdef\"}";
            await using var server = new Server(s => Server.Bytes(s, Server.Response(body)));
            using var client = New(server.Endpoint);
            try
            {
                await client.TransactionAsync(J("{\"operations\":[{\"collection\":\"examples\",\"document\":\"one\",\"put\":\"n: 1\\n\"}]}"));
                failures.Add(count + " accepted");
            }
            catch (YamoraException e) { if (!e.OutcomeMayBeCommitted) failures.Add(count + " lost uncertainty"); }
            catch (Exception e) { failures.Add(count + " threw " + e.GetType().Name); }
        }
        Check(failures.Count == 0, string.Join("; ", failures));
    }
}
