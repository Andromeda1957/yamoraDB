using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace DriverTests;

sealed record BinaryRequest(int Method, Dictionary<int, byte[]> Fields, byte[] Source)
{
    public string? Id => Fields.TryGetValue(8, out var value) ? Convert.ToHexStringLower(value) : null;
}

// Independent wire fixture: no production framing, TLV or hashing helpers.
static class BinaryFixtureWire
{
    public static byte[] Num(ulong value, int width)
    {
        var bytes = new byte[width]; for (var i = width - 1; i >= 0; i--) { bytes[i] = (byte)value; value >>= 8; } return bytes;
    }
    public static byte[] Frame(int type, byte[]? payload = null, uint stream = 1)
    {
        payload ??= []; var result = new byte[16 + payload.Length];
        "YMBF"u8.CopyTo(result); result[4] = 1; result[5] = (byte)type;
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(8), stream);
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(12), (uint)payload.Length); payload.CopyTo(result, 16); return result;
    }
    public static async Task<(int Type, byte[] Payload)> Read(Stream stream, CancellationToken ct)
    {
        var header = new byte[16]; await stream.ReadExactlyAsync(header, ct);
        if (!header.AsSpan(0, 4).SequenceEqual("YMBF"u8) || header[4] != 1 || header[6] != 0 || header[7] != 0) throw new Exception("client frame invalid");
        var size = BinaryPrimitives.ReadUInt32BigEndian(header.AsSpan(12));
        if (size > 65536) throw new Exception("client frame over cap");
        var payload = new byte[(int)size]; await stream.ReadExactlyAsync(payload, ct);
        return (header[5], payload);
    }
    public static byte[] Tlv(IEnumerable<KeyValuePair<int, byte[]>> fields)
    {
        var entries = fields.ToArray(); using var output = new MemoryStream();
        output.Write(Num(1, 2)); output.Write(Num((ulong)entries.Length, 2));
        foreach (var (id, value) in entries) { output.Write(Num((ulong)id, 2)); output.Write(Num((ulong)value.Length, 2)); output.Write(value); }
        return output.ToArray();
    }
    public static Dictionary<int, byte[]> Fields(byte[] bytes)
    {
        var fields = new Dictionary<int, byte[]>(); var count = BinaryPrimitives.ReadUInt16BigEndian(bytes.AsSpan(2)); var offset = 4;
        for (var i = 0; i < count; i++)
        {
            var id = BinaryPrimitives.ReadUInt16BigEndian(bytes.AsSpan(offset)); var size = BinaryPrimitives.ReadUInt16BigEndian(bytes.AsSpan(offset + 2));
            fields.Add(id, bytes.AsSpan(offset + 4, size).ToArray()); offset += size + 4;
        }
        if (offset != bytes.Length) throw new Exception("client metadata trailer"); return fields;
    }
    public static string Hash(byte[] bytes)
    {
        ulong n = 1469598103934665603; foreach (var b in bytes) n = unchecked((n ^ b) * 1099511628211); return n.ToString("x16");
    }
    public static SortedDictionary<int, byte[]> Metadata(BinaryRequest request, byte[] body, int? status = null, string? etag = null)
    {
        var target = Encoding.ASCII.GetString(request.Fields[2]).Split('/');
        var tag = etag ?? Hash(request.Method == 3 ? request.Source : body);
        var fields = new SortedDictionary<int, byte[]>
        {
            [1] = Num((ulong)(status ?? (request.Method == 3 ? 201 : request.Method == 4 ? 204 : 200)), 2),
            [2] = Encoding.ASCII.GetBytes(request.Method is 1 or 2 ? "application/yaml" : "application/json"),
            [3] = Num((ulong)body.Length, 8), [4] = Num((ulong)body.Length, 8), [5] = "0123456789abcdef"u8.ToArray(),
            [6] = Encoding.ASCII.GetBytes('"' + tag + '"'), [7] = Encoding.ASCII.GetBytes(target[3]), [8] = Encoding.ASCII.GetBytes(target[5]),
        };
        if (request.Fields.TryGetValue(8, out var id)) fields[12] = id;
        return fields;
    }
    public static byte[] Receipt(BinaryRequest request, string? etag = null)
    {
        var target = Encoding.ASCII.GetString(request.Fields[2]).Split('/');
        return JsonSerializer.SerializeToUtf8Bytes(new { status = "stored", collection = target[3], document = target[5], etag = etag ?? Hash(request.Source), revision = "0123456789abcdef" });
    }
    public static async Task Reply(Stream stream, BinaryRequest request, CancellationToken ct, byte[]? source = null,
        Action<SortedDictionary<int, byte[]>>? change = null, byte[]? overrideBody = null, bool end = true, int? status = null)
    {
        var body = overrideBody ?? (request.Method == 3 ? Receipt(request) : request.Method is 2 or 4 ? [] : source ?? "n: 1\n"u8.ToArray());
        var meta = Metadata(request, body, status); change?.Invoke(meta);
        await stream.WriteAsync(Frame(3, Tlv(meta)), ct);
        for (var offset = 0; offset < body.Length; offset += 4096)
            await stream.WriteAsync(Frame(4, body.AsSpan(offset, Math.Min(4096, body.Length - offset)).ToArray()), ct);
        if (end) await stream.WriteAsync(Frame(5), ct);
    }
}

sealed class BinaryServer : IAsyncDisposable
{
    private readonly TcpListener listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource stop = new(TimeSpan.FromSeconds(30));
    private readonly ConcurrentBag<TcpClient> sockets = [];
    private readonly List<Task> workers = [];
    private readonly Task accept;
    private readonly SslStreamCertificateContext context;
    private readonly ConcurrentQueue<Exception> failures = [];
    public readonly ConcurrentQueue<BinaryRequest> Requests = [];
    public string Endpoint { get; }
    public int Connections;
    public int Frames;
    public BinaryServer(X509Certificate2 certificate, Func<Stream, BinaryRequest, CancellationToken, Task> reply,
        SslProtocols protocols = SslProtocols.Tls13, string? alpn = "yamora-binary/1",
        Func<Stream, CancellationToken, Task>? hello = null, ushort schema = 1, ushort minimum = 1)
    {
        context = SslStreamCertificateContext.Create(certificate, null, offline: true);
        listener.Start(); var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        if (port == 8000) throw new Exception("owner port allocated");
        Endpoint = $"https://127.0.0.1:{port}";
        accept = Task.Run(async () =>
        {
            try
            {
                while (true)
                {
                    var socket = await listener.AcceptTcpClientAsync(stop.Token); sockets.Add(socket); Interlocked.Increment(ref Connections);
                    workers.Add(Serve(socket));
                }
            }
            catch (Exception e) when (e is OperationCanceledException or ObjectDisposedException or SocketException) { }
        });
        async Task Serve(TcpClient socket)
        {
            using (socket)
            using (var stream = new SslStream(socket.GetStream()))
            {
                try
                {
                    await stream.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                    {
                        ServerCertificateContext = context, EnabledSslProtocols = protocols,
                        ApplicationProtocols = alpn is null ? null : [new SslApplicationProtocol(alpn)],
                        AllowTlsResume = false,
                    }, stop.Token);
                    var first = await BinaryFixtureWire.Read(stream, stop.Token);
                    if (first.Type != 1) throw new Exception("client HELLO missing");
                    if (hello is not null) { await hello(stream, stop.Token); return; }
                    await stream.WriteAsync(BinaryFixtureWire.Frame(1, [0, (byte)minimum, 0, (byte)schema, 0, 0, 16, 0, 0, 0, 0, 1], 0), stop.Token);
                    var request = await BinaryFixtureWire.Read(stream, stop.Token);
                    if (request.Type != 2) throw new Exception("client REQUEST missing");
                    if (BinaryPrimitives.ReadUInt16BigEndian(request.Payload) != schema) throw new Exception("client metadata schema");
                    var fields = BinaryFixtureWire.Fields(request.Payload); using var output = new MemoryStream();
                    while (true)
                    {
                        var frame = await BinaryFixtureWire.Read(stream, stop.Token); Interlocked.Increment(ref Frames);
                        if (frame.Type == 5) break;
                        if (frame.Type != 4 || frame.Payload.Length is < 1 or > 4096 || output.Length + frame.Payload.Length > 16777216) throw new Exception("invalid client DATA");
                        output.Write(frame.Payload);
                    }
                    var captured = new BinaryRequest(fields[1][0], fields, output.ToArray()); Requests.Enqueue(captured);
                    await reply(stream, captured, stop.Token);
                }
                catch (Exception e) when (e is IOException or AuthenticationException or OperationCanceledException or ObjectDisposedException) { }
                catch (Exception e) { failures.Enqueue(e); }
            }
        }
    }
    public async Task WaitRequests(int count)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        while (Requests.Count < count) await Task.Delay(5, deadline.Token);
    }
    public async ValueTask DisposeAsync()
    {
        stop.Cancel(); listener.Stop(); foreach (var socket in sockets) socket.Dispose();
        await accept; await Task.WhenAll(workers); stop.Dispose();
        foreach (var certificate in context.IntermediateCertificates) certificate.Dispose();
        if (!failures.IsEmpty) throw new AggregateException(failures);
    }
}
