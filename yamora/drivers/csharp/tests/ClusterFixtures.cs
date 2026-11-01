using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Yamora;

namespace DriverTests;

sealed record WireRequest(string Headers, byte[] Body)
{
    public string Method => Headers.Split(' ')[0];
    public string Path => Headers.Split(' ')[1];
    public string? Header(string name) => Headers.Split("\r\n").FirstOrDefault(line => line.StartsWith(name + ": ", StringComparison.OrdinalIgnoreCase))?[(name.Length + 2)..];
}

// Concurrent real TLS peers; every connection/task is owned and drained.
sealed class ClusterPeer : IAsyncDisposable
{
    private readonly TcpListener listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource stop = new(TimeSpan.FromSeconds(45));
    private readonly ConcurrentBag<Task> connections = [];
    private readonly Task accept;
    public ConcurrentQueue<WireRequest> Requests { get; } = [];
    public string Endpoint { get; }
    public ClusterPeer(X509Certificate2 certificate, Func<WireRequest, Stream, CancellationToken, Task> reply,
        SslProtocols protocols = SslProtocols.Tls13)
    {
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        if (port == 8000) throw new Exception("owner port allocated");
        Endpoint = $"https://127.0.0.1:{port}";
        accept = Task.Run(async () =>
        {
            try
            {
                while (!stop.IsCancellationRequested)
                {
                    var client = await listener.AcceptTcpClientAsync(stop.Token);
                    connections.Add(Task.Run(async () =>
                    {
                        using (client)
                        await using (var stream = new SslStream(client.GetStream()))
                        {
                            try
                            {
                                await stream.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                                { ServerCertificate = certificate, EnabledSslProtocols = protocols }, stop.Token);
                                var (headers, body) = await Server.ReadRequest(stream, stop.Token);
                                var request = new WireRequest(headers, body);
                                Requests.Enqueue(request);
                                await reply(request, stream, stop.Token);
                            }
                            catch (Exception e) when (e is IOException or AuthenticationException or OperationCanceledException or ObjectDisposedException) { }
                        }
                    }));
                }
            }
            catch (Exception e) when (e is OperationCanceledException or ObjectDisposedException or SocketException) { }
        });
    }
    public async ValueTask DisposeAsync()
    {
        stop.Cancel(); listener.Stop(); await accept;
        await Task.WhenAll(connections);
        stop.Dispose();
    }
}

static partial class Program
{
    const string ClusterId = "1234567890abcdef1234567890abcdef";
    const string Revision = "0123456789abcdef";
    const string Tag = "fedcba9876543210";
    const string Stored = "{\"status\":\"stored\",\"collection\":\"examples\",\"document\":\"one\",\"etag\":\"fedcba9876543210\",\"revision\":\"0123456789abcdef\"}";
    static readonly string Feed = JsonSerializer.Serialize(new
    {
        checkpoint = "v1." + ClusterId + ".0000000000000001",
        next_after = "v1." + ClusterId + ".0000000000000001",
        oldest_after = "v1." + ClusterId + ".0000000000000000",
        transactions = Array.Empty<object>(),
        has_more = false
    });
    static string Status(int node = 1) => JsonSerializer.Serialize(new { node, leader = node, voters = 3, term = 1, role = "leader" });
    static string Reply(string body, int status = 200, string extra = "", string media = "application/json")
        => $"HTTP/1.1 {status} Test\r\nConnection: close\r\nX-YamlDB-Revision: {Revision}\r\nContent-Type: {media}\r\n{extra}Content-Length: {Encoding.UTF8.GetByteCount(body)}\r\n\r\n{body}";
    static ClusterOptions Options(IReadOnlyList<ClusterSeed> seeds, Certificates ca, TimeSpan? timeout = null, TimeSpan? attempt = null) => new()
    {
        Seeds = seeds,
        ClusterId = ClusterId,
        TrustedRoots = [ca.Root],
        ReadToken = Native.ReadToken,
        WriteToken = Native.WriteToken,
        Timeout = timeout ?? TimeSpan.FromSeconds(2),
        AttemptTimeout = attempt ?? TimeSpan.FromMilliseconds(300),
    };
    static ClusterClient Cluster(string endpoint, Certificates ca, TimeSpan? timeout = null)
        => new(Options([new(endpoint, 1)], ca, timeout));
    static bool Discovery(WireRequest request, out string body)
    {
        body = request.Path == "/v1/cluster/status" ? Status() : Feed;
        return request.Path is "/v1/cluster/status" or "/v1/changes";
    }
    static Task Respond(WireRequest request, Stream stream, string reply)
        => Server.Bytes(stream, Discovery(request, out var body) ? Reply(body) : reply);
}
