using System.Net;
using System.Security.Authentication;
using System.Text;
using System.Text.Json;
using Yamora;

namespace DriverTests;

static partial class Program
{
    static JsonElement J(string json) { using var doc = JsonDocument.Parse(json); return doc.RootElement.Clone(); }
    static void Check(bool condition, string message = "assertion failed") { if (!condition) throw new Exception(message); }
    static async Task<T> Throws<T>(Func<Task> action) where T : Exception
    {
        try { await action(); }
        catch (T error) { return error; }
        throw new Exception("expected " + typeof(T).Name);
    }
    static void Invalid(Action action)
    {
        try { action(); }
        catch (ArgumentException) { return; }
        throw new Exception("expected ArgumentException");
    }
    static Client New(string endpoint, int maxResponse = Client.ResponseLimit, TimeSpan? timeout = null)
        => new(new ClientOptions
        {
            Endpoint = endpoint,
            ReadToken = Native.ReadToken,
            WriteToken = Native.WriteToken,
            MaxResponseBytes = maxResponse,
            Timeout = timeout ?? TimeSpan.FromSeconds(3)
        });

    static async Task ReplicationSourceGuard()
    {
        foreach (var value in new[] { "false", "null", "\"false\"", "\"true\"", "0", "1", "[]", "{}", "true", "absent", "nested" })
        {
            var field = value == "absent" ? "" : value == "nested"
                ? ",\"nested\":{\"replication_policy_free\":false}" : ",\"replication_policy_free\":" + value;
            var body = "{\"revision\":\"0123456789abcdef\"" + field + "}";
            await using var server = new Server(s => Server.Bytes(s, Server.Response(body)));
            using var client = New(server.Endpoint);
            if (value is "true" or "absent" or "nested")
                Check((await client.RequireReplicationSourceAsync()).Value.GetRawText() == body, "readiness changed");
            else
            {
                var error = await Throws<YamoraException>(() => client.RequireReplicationSourceAsync());
                Check(!error.OutcomeMayBeCommitted && (error is SchemaPolicyReplicationError) == (value == "false"), "wrong guard error");
                if (error is SchemaPolicyReplicationError policy) Check(policy.StatusCode == HttpStatusCode.Conflict);
            }
            Check(server.LastRequest.StartsWith("GET /readyz ", StringComparison.Ordinal), "guard dispatched mutation");
        }
    }

    static Task Endpoints()
    {
        foreach (var host in new[] { "127.0.0.1", "127.255.255.254", "10.0.0.1", "172.16.0.1", "172.31.255.254", "192.168.0.1" })
            using (New($"http://{host}:1234")) { }
        foreach (var endpoint in new[] { "http://localhost:1", "http://127.1:1", "http://2130706433:1", "http://0x7f000001:1",
            "http://0177.0.0.1:1", "http://127.000.0.1:1", "http://[::1]:1", "http://[::ffff:127.0.0.1]:1", "http://8.8.8.8:1",
            "http://0.0.0.0:1", "http://169.254.169.254:1", "http://172.15.0.1:1", "http://172.32.0.1:1", "http://192.169.1.1:1",
            "http://127.0.0.1", "http://127.0.0.1:0", "http://127.0.0.1:65536", "http://127.0.0.1:01", "http://127.0.0.1:-1",
            "http://u:p@127.0.0.1:1", "http://127.0.0.1:1?x", "http://127.0.0.1:1#", "http://127.0.0.1:1/v1", "http://127.0.0.1:1/../",
            "http://127.0.0.1:1\\evil", "http://127.0.0.1:1\n", "http://127.0.0.1:1/%2f", "ftp://127.0.0.1:1" })
            Invalid(() => New(endpoint).Dispose());
        Invalid(() => new Client(new ClientOptions { Endpoint = "http://127.0.0.1:1", Timeout = TimeSpan.FromSeconds(31) }));
        Invalid(() => new Client(new ClientOptions { Endpoint = "http://127.0.0.1:1", Timeout = TimeSpan.Zero }));
        return Task.CompletedTask;
    }

    static Task Tokens()
    {
        foreach (var token in new[] { new string('a', 31), new string('a', 513), new string('a', 31) + " ", new string('a', 31) + "\r\nX: y",
            new string('a', 31) + "é", new string('a', 31) + "\0", new string('a', 31) + "\u007f" })
        {
            Invalid(() => new Client(new ClientOptions { Endpoint = "http://127.0.0.1:1", ReadToken = token }));
            Invalid(() => new Client(new ClientOptions { Endpoint = "http://127.0.0.1:1", WriteToken = token }));
        }
        using var empty = new Client(new ClientOptions { Endpoint = "http://127.0.0.1:1" });
        using var ascii = new Client(new ClientOptions { Endpoint = "http://127.0.0.1:1", ReadToken = new string('!', 32), WriteToken = new string('~', 512) });
        return Task.CompletedTask;
    }

    static async Task Inputs()
    {
        using var client = New("http://127.0.0.1:1");
        foreach (var id in new[] { "", "..", "a/b", "a%2fb", "A", "a?x", "a#x", "a\\b", "a\n", "é", new string('a', 129) })
        {
            await Throws<ArgumentException>(() => client.GetAsync(id, "one"));
            await Throws<ArgumentException>(() => client.DeleteAsync("examples", id));
        }
        await Throws<ArgumentException>(() => client.PutAsync("examples", "one", Array.Empty<byte>()));
        await Throws<ArgumentException>(() => client.PutAsync("examples", "one", new byte[] { 0xff }));
        await Throws<ArgumentException>(() => client.PutAsync("examples", "one", new byte[Client.DocumentLimit + 1]));
        await Throws<ArgumentException>(() => client.PutAsync("examples", "one", "n: 1\n"u8.ToArray(), new("0123456789abcdef", true)));
        await Throws<ArgumentException>(() => client.DeleteAsync("examples", "one", new(CreateOnly: true)));
        await Throws<ArgumentException>(() => client.DeleteAsync("examples", "one", new("\"0123456789abcdef\"")));
        foreach (var requestId in new[] { "", new string('0', 32), new string('A', 32), "../../" })
            await Throws<ArgumentException>(() => client.PutAsync("examples", "one", "n: 1\n"u8.ToArray(), new(RequestId: requestId)));
        await Throws<ArgumentException>(() => client.QueryAsync("examples", J("{\"after\":\"one\"}")));
        await Throws<ArgumentException>(() => client.QueryAsync("examples", J("{\"limit\":0}")));
        await Throws<ArgumentException>(() => client.QueryAsync("examples", J("{\"x\":1,\"x\":2}")));
        await Throws<ArgumentException>(() => client.QueryAsync("examples", J("{\"x\":\"\\ud800\"}")));
        await Throws<ArgumentException>(() => client.TransactionAsync(J("{\"operations\":[{\"collection\":\"examples\",\"document\":\"one\",\"put\":\"n: 1\\n\",\"delete\":true}]}")));
        await Throws<ArgumentException>(() => client.IndexBuildAsync("../other"));
        await Throws<ArgumentException>(() => client.ChangesAsync("v1.bad"));
        using var bounded = new Client(new ClientOptions { Endpoint = "http://127.0.0.1:1", MaxRequestBytes = 32 });
        await Throws<ArgumentException>(() => bounded.PutAsync("examples", "one", Encoding.UTF8.GetBytes("n: " + new string('x', 33))));
        await Throws<ArgumentException>(() => bounded.QueryAsync("examples", J("{\"filter\":{\"a\":\"" + new string('x', 40) + "\"}}")));
        await Throws<ArgumentException>(() => bounded.QueryAsync("examples", J("{\"x\":\"éééééé\"}")));
    }

    static async Task ExactYaml()
    {
        const string source = "# exact é\r\nn: 9223372036854775807 # retained\r\ntext: 'yes'\r\n";
        await using var server = new Server(s => Server.Bytes(s, Server.Response(source, "ETag: \"fedcba9876543210\"\r\n", "application/yaml; charset=utf-8")));
        using var client = New(server.Endpoint);
        var document = await client.GetAsync("examples", "one", "0123456789abcdef");
        Check(document.Source.SequenceEqual(Encoding.UTF8.GetBytes(source)) && document.ETag == "fedcba9876543210");
        Check(server.LastRequest.Contains("Authorization: Bearer " + Native.ReadToken, StringComparison.Ordinal));
        Check(server.LastRequest.StartsWith("GET /v1/collections/examples/documents/one HTTP/1.1\r\n", StringComparison.Ordinal));
        Check(server.LastRequest.Contains("Connection: close", StringComparison.OrdinalIgnoreCase));
    }

    static async Task PutConditions()
    {
        await using var server = new Server(s => Server.Bytes(s, Server.Response("{\"status\":\"stored\",\"etag\":\"fedcba9876543210\",\"revision\":\"0123456789abcdef\"}")));
        using var client = New(server.Endpoint);
        var source = Encoding.UTF8.GetBytes("# exact é\r\nn: 1\r\n");
        var receipt = await client.PutAsync("examples", "one", source, new(CreateOnly: true, RequestId: new string('1', 32)));
        Check(receipt.ETag == "fedcba9876543210" && server.LastBody.SequenceEqual(source));
        Check(server.LastRequest.Contains("If-None-Match: *", StringComparison.OrdinalIgnoreCase));
        Check(server.LastRequest.Contains("Authorization: Bearer " + Native.WriteToken, StringComparison.Ordinal));
        Check(server.LastRequest.Contains("X-Yamora-Request-Id: " + new string('1', 32), StringComparison.Ordinal));
        await client.PutAsync("examples", "one", source, new("fedcba9876543210"));
        Check(server.LastRequest.Contains("If-Match: \"fedcba9876543210\"", StringComparison.OrdinalIgnoreCase));
    }

    static async Task Redirect()
    {
        await using var target = new Server(s => Server.Bytes(s, Server.Response("{}")));
        await using var server = new Server(s => Server.Bytes(s, $"HTTP/1.1 307 Temporary Redirect\r\nLocation: {target.Endpoint}/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"));
        using var client = New(server.Endpoint);
        var error = await Throws<HttpError>(() => client.PutAsync("examples", "one", "n: 1\n"u8.ToArray()));
        Check(error.StatusCode == HttpStatusCode.TemporaryRedirect && target.Connections == 0 && server.Connections == 1);
        Check(!error.Message.Contains(Native.WriteToken, StringComparison.Ordinal));
    }

    static async Task SizeAndFraming()
    {
        var cases = new[] {
            Server.Response("{}", "Content-Encoding: gzip\r\n"),
            Server.Response("{}", media: "text/html"),
            Server.Response("{}", media: "application/json; charset=iso-8859-1"),
            Server.Response("{}").Replace("Content-Length: 2", "Content-Length: 99999999", StringComparison.Ordinal),
            Server.Response("{}").Replace("Content-Length: 2", "Content-Length: 9", StringComparison.Ordinal),
            "HTTP/1.1 200 OK\r\nX-YamlDB-Revision: 0123456789abcdef\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n20\r\n" + new string('x', 32) + "\r\n0\r\n\r\n",
            "HTTP/1.1 200 OK\r\nX-YamlDB-Revision: 0123456789abcdef\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\n{}",
            Server.Response("{}").Replace("0123456789abcdef", "not-a-revision", StringComparison.Ordinal),
            Server.Response("{\"revision\":\"fedcba9876543210\"}"),
            Server.Response("{\"x\":1,\"x\":2}"),
            Server.Response("{\"x\":\"\\ud800\"}"),
        };
        foreach (var response in cases)
        {
            await using var server = new Server(s => Server.Bytes(s, response));
            using var client = New(server.Endpoint, maxResponse: response.Contains("20\r\n", StringComparison.Ordinal) ? 16 : 1024);
            await Throws<YamoraException>(() => client.HealthAsync());
        }
        // Exact cap succeeds; neither Content-Length nor EOF is itself an error.
        await using var exact = new Server(s => Server.Bytes(s, Server.Response("{}")));
        using var exactClient = New(exact.Endpoint, maxResponse: 2);
        await exactClient.HealthAsync();
    }

    static async Task InvalidMetadata()
    {
        var responses = new[] {
            Server.Response("n: 1\n", "ETag: W/\"fedcba9876543210\"\r\n", "application/yaml"),
            Server.Response("n: 1\n", "ETag: \"FEDCBA9876543210\"\r\n", "application/yaml"),
            Server.Response("n: 1\n", "X-YamlDB-Revision: fedcba9876543210\r\nETag: \"fedcba9876543210\"\r\n", "application/yaml"),
            Server.Response("n: 1\n", "ETag: \"fedcba9876543210\"\r\n", "application/json"),
            Server.Response("n: 1\n", "X-Large: " + new string('a', 17000) + "\r\nETag: \"fedcba9876543210\"\r\n", "application/yaml"),
        };
        foreach (var response in responses)
        {
            await using var server = new Server(s => Server.Bytes(s, response));
            using var client = New(server.Endpoint);
            await Throws<YamoraException>(() => client.GetAsync("examples", "one"));
        }
        await using var invalidUtf8 = new Server(async s =>
        {
            await Server.Bytes(s, "HTTP/1.1 200 OK\r\nX-YamlDB-Revision: 0123456789abcdef\r\nContent-Type: application/json\r\nContent-Length: 9\r\nConnection: close\r\n\r\n");
            await s.WriteAsync(new byte[] { (byte)'{', (byte)'"', (byte)'x', (byte)'"', (byte)':', (byte)'"', 0xff, (byte)'"', (byte)'}' });
        });
        using var badUtf8 = New(invalidUtf8.Endpoint);
        await Throws<YamoraException>(() => badUtf8.HealthAsync());
        await using var errorBody = new Server(s => Server.Bytes(s, "HTTP/1.1 500 Failed\r\nContent-Length: 32\r\nConnection: close\r\n\r\n" + Native.WriteToken));
        using var errorClient = New(errorBody.Endpoint);
        var error = await Throws<HttpError>(() => errorClient.PutAsync("examples", "one", "n: 1\n"u8.ToArray()));
        Check(error.OutcomeMayBeCommitted && !error.ToString().Contains(Native.WriteToken, StringComparison.Ordinal));
    }

    static async Task ResponseBounds()
    {
        var body = "{\"text\":\"" + new string('x', 64) + "\"}";
        var responses = new[] {
            Server.Response(body),
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-YamlDB-Revision: 0123456789abcdef\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n"
                + Encoding.UTF8.GetByteCount(body).ToString("x", System.Globalization.CultureInfo.InvariantCulture) + "\r\n" + body + "\r\n0\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-YamlDB-Revision: 0123456789abcdef\r\nConnection: close\r\n\r\n" + body,
        };
        foreach (var response in responses)
        {
            await using var server = new Server(s => Server.Bytes(s, response));
            using var client = New(server.Endpoint, maxResponse: 16);
            await Throws<YamoraException>(() => client.HealthAsync());
        }
    }

    static async Task DeadlineAndCancellation()
    {
        await using var server = new Server(async s => { await Task.Delay(250); await Server.Bytes(s, Server.Response("{}")); });
        using var client = New(server.Endpoint, timeout: TimeSpan.FromMilliseconds(50));
        await Throws<TransportError>(() => client.HealthAsync());
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await Throws<OperationCanceledException>(() => client.HealthAsync(cancellation.Token));
        using var inFlight = new CancellationTokenSource(50);
        using var slower = New(server.Endpoint);
        var error = await Throws<RequestCanceled>(() => slower.PutAsync("examples", "one", "n: 1\n"u8.ToArray(), ct: inFlight.Token));
        Check(error.OutcomeMayBeCommitted);
        await using var slowBody = new Server(async s =>
        {
            await Server.Bytes(s, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-YamlDB-Revision: 0123456789abcdef\r\nContent-Length: 2\r\n\r\n{");
            await Task.Delay(250);
            await Server.Bytes(s, "}");
        });
        using var boundedBody = New(slowBody.Endpoint, timeout: TimeSpan.FromMilliseconds(50));
        await Throws<TransportError>(() => boundedBody.HealthAsync());
    }

    static async Task NoReplay()
    {
        await using var server = new Server(_ => Task.CompletedTask); // request consumed, ACK lost
        using var client = New(server.Endpoint);
        var error = await Throws<TransportError>(() => client.PutAsync("examples", "one", "n: 1\n"u8.ToArray()));
        Check(error.OutcomeMayBeCommitted && server.Connections == 1, "mutation replayed after lost acknowledgement");
        Check(!error.ToString().Contains(Native.WriteToken, StringComparison.Ordinal));
    }

    static async Task NoProxy()
    {
        await using var proxy = new Server(s => Server.Bytes(s, "HTTP/1.1 500 Proxy\r\nContent-Length: 0\r\n\r\n"));
        await using var server = new Server(s => Server.Bytes(s, Server.Response("{}")));
        var names = new[] { "HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy" };
        var saved = names.Select(Environment.GetEnvironmentVariable).ToArray();
        try
        {
            foreach (var name in names) Environment.SetEnvironmentVariable(name, name.Contains("NO_PROXY", StringComparison.OrdinalIgnoreCase) ? "" : proxy.Endpoint);
            using var client = New(server.Endpoint);
            await client.HealthAsync();
            Check(proxy.Connections == 0 && server.Connections == 1);
            Check(!server.LastRequest.Contains("Authorization:", StringComparison.OrdinalIgnoreCase), "health leaked a credential");
        }
        finally { for (var i = 0; i < names.Length; i++) Environment.SetEnvironmentVariable(names[i], saved[i]); }
    }

    static async Task Tls()
    {
        using var certs = new Certificates();
        using var good = certs.Issue();
        await using var server = new Server(s => Server.Bytes(s, Server.Response("{}")), good);
        using (var trusted = new Client(new ClientOptions { Endpoint = server.Endpoint, TrustedRoots = [certs.Root] }))
            await trusted.HealthAsync();
        Check(server.Negotiated == SslProtocols.Tls13);
        using (var untrusted = New(server.Endpoint)) await Throws<TransportError>(() => untrusted.HealthAsync());
        foreach (var certificate in new[] { certs.Issue("127.0.0.2"), certs.Issue(expired: true), certs.Issue(client: true) })
        {
            using (certificate)
            {
                await using var invalid = new Server(s => Server.Bytes(s, Server.Response("{}")), certificate);
                using var client = new Client(new ClientOptions { Endpoint = invalid.Endpoint, TrustedRoots = [certs.Root] });
                await Throws<TransportError>(() => client.HealthAsync());
            }
        }
        await using var old = new Server(s => Server.Bytes(s, Server.Response("{}")), good, SslProtocols.Tls12);
        using var modernOnly = new Client(new ClientOptions { Endpoint = old.Endpoint, TrustedRoots = [certs.Root] });
        await Throws<TransportError>(() => modernOnly.HealthAsync());
    }

    static async Task QueryNumbers()
    {
        const string response = "{\"documents\":[{\"id\":\"one\",\"value\":{\"n\":9223372036854775807}}],\"matched\":1,\"next_after\":null,\"revision\":\"0123456789abcdef\"}";
        await using var server = new Server(s => Server.Bytes(s, Server.Response(response)));
        using var client = New(server.Endpoint);
        var result = await client.QueryAsync("examples", J("{\"sort\":{\"n\":-1,\"name\":1},\"filter\":{\"text\":\"a\\u0085b\"}}"));
        Check(result.Value.GetProperty("documents")[0].GetProperty("value").GetProperty("n").GetInt64() == long.MaxValue);
        var sent = Encoding.UTF8.GetString(server.LastBody);
        Check(sent.Contains("\"sort\":{\"n\":-1,\"name\":1}", StringComparison.Ordinal) && !sent.Contains('\u0085'));
        Check(server.LastRequest.Contains(Native.ReadToken, StringComparison.Ordinal) && !server.LastRequest.Contains(Native.WriteToken, StringComparison.Ordinal));
    }

    static async Task NativeCrud(string binary, bool tls)
    {
        using var certs = new Certificates();
        using var identity = certs.Issue(client: true);
        await using var native = await Native.Start(binary, certificates: tls ? certs : null);
        using var client = native.Client(tls ? [certs.Root] : [], tls ? identity : null);
        var ready = await client.ReadyAsync();
        Check(ready.Value.GetProperty("storage").GetString() == "native-disk-v2");
        await client.HealthAsync();
        await client.StatsAsync();
        Check((await client.MetricsAsync()).Contains("yamldb_uptime_seconds", StringComparison.Ordinal));
        const string yaml = "# original é\r\nname: Alpha\r\nn: 1 # unchanged comment\r\n";
        var created = await client.PutAsync("examples", "one", Encoding.UTF8.GetBytes(yaml), new(CreateOnly: true));
        var document = await client.GetAsync("examples", "one", created.Revision);
        Check(document.Source.SequenceEqual(Encoding.UTF8.GetBytes(yaml)) && document.ETag == created.ETag);
        Check((await Throws<HttpError>(() => client.PutAsync("examples", "one", document.Source, new(CreateOnly: true)))).StatusCode == HttpStatusCode.PreconditionFailed);
        var updated = await client.PatchAsync("examples", "one", J("{\"$inc\":{\"n\":1}}"), new(document.ETag));
        Check(Encoding.UTF8.GetString((await client.GetAsync("examples", "one")).Source) == yaml.Replace("n: 1", "n: 2", StringComparison.Ordinal));
        Check((await Throws<HttpError>(() => client.DeleteAsync("examples", "one", new(document.ETag)))).StatusCode == HttpStatusCode.PreconditionFailed);
        Check((await Throws<HttpError>(() => client.PutAsync("examples", "one", document.Source, new(document.ETag)))).StatusCode == HttpStatusCode.PreconditionFailed);
        var replaced = await client.PutAsync("examples", "one", "name: Omega\nn: 9223372036854775807\n"u8.ToArray(), new(updated.ETag));
        var query = await client.QueryAsync("examples", J("{\"filter\":{\"name\":\"Omega\"},\"explain\":true}"));
        Check(query.Value.GetProperty("documents")[0].GetProperty("value").GetProperty("n").GetInt64() == long.MaxValue);
        await client.GetAsync("examples", "one", replaced.Revision);
        var names = await client.DocumentsAsync("examples");
        Check(names.Names.SequenceEqual(new[] { "one" }));
        Check((await client.CollectionsAsync()).Names.Contains("examples"));
        await client.DeleteAsync("examples", "one", new(replaced.ETag));
        Check((await Throws<HttpError>(() => client.GetAsync("examples", "one"))).StatusCode == HttpStatusCode.NotFound);
        if (tls)
        {
            using var noIdentity = native.Client([certs.Root]);
            await Throws<TransportError>(() => noIdentity.HealthAsync());
            using var noTrust = native.Client(cert: identity);
            await Throws<TransportError>(() => noTrust.HealthAsync());
        }
        using var anonymous = new Client(new ClientOptions
        {
            Endpoint = native.Endpoint,
            TrustedRoots = tls ? [certs.Root] : [],
            ClientCertificate = tls ? identity : null
        });
        Check((await Throws<HttpError>(() => anonymous.ReadyAsync())).StatusCode == HttpStatusCode.Unauthorized);
        using var readOnly = new Client(new ClientOptions
        {
            Endpoint = native.Endpoint,
            ReadToken = Native.ReadToken,
            WriteToken = Native.ReadToken,
            TrustedRoots = tls ? [certs.Root] : [],
            ClientCertificate = tls ? identity : null
        });
        Check((await Throws<HttpError>(() => readOnly.PutAsync("examples", "denied", "n: 1\n"u8.ToArray()))).StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden);
    }

    static async Task NativeOperations(string binary)
    {
        await using var native = await Native.Start(binary);
        using var client = native.Client();
        await client.PutAsync("examples", "one", "# rollback guide\r\nname: Alpha\r\nn: 1\r\n"u8.ToArray());
        await client.PutAsync("examples", "two", "name: Beta\nn: 2\n"u8.ToArray());
        var catalog = await client.IndexesAsync();
        await client.SetIndexesAsync(J("{\"indexes\":[{\"collection\":\"examples\",\"name\":\"by-name\",\"fields\":[\"name\"],\"unique\":true}]}"), catalog.Revision);
        Check((await Throws<HttpError>(() => client.SetIndexesAsync(J("{\"indexes\":[]}"), catalog.Revision))).StatusCode == HttpStatusCode.PreconditionFailed);
        var checkpoint = await client.ChangesAsync();
        var token = checkpoint.Value.GetProperty("next_after").GetString()!;
        var tx = await client.TransactionAsync(J("{\"operations\":[{\"collection\":\"examples\",\"document\":\"two\",\"patch\":{\"$inc\":{\"n\":1}}},{\"collection\":\"examples\",\"document\":\"three\",\"put\":\"name: Gamma\\nn: 4\\n\",\"create_only\":true}]}"));
        Check(tx.Value.GetProperty("operations").GetInt32() == 2);
        var first = await client.DocumentsAsync("examples", 1);
        var second = await client.DocumentsAsync("examples", 1, first.NextAfter, first.Revision);
        Check(first.NextAfter == "one" && second.Names.SequenceEqual(new[] { "three" }) && second.NextAfter == "three");
        var beforeFailure = await client.GetAsync("examples", "one");
        Check((await Throws<HttpError>(() => client.TransactionAsync(J("{\"operations\":[{\"collection\":\"examples\",\"document\":\"one\",\"patch\":{\"$inc\":{\"n\":100}}},{\"collection\":\"examples\",\"document\":\"duplicate\",\"put\":\"name: Alpha\\nn: 0\\n\"}]}")))).StatusCode == HttpStatusCode.Conflict);
        Check((await client.GetAsync("examples", "one")).Source.SequenceEqual(beforeFailure.Source), "failed transaction partially published");
        var changes = await client.ChangesAsync(token);
        Check(changes.Value.GetProperty("transactions").GetArrayLength() == 1, "failed transaction entered the feed");
        await client.PutAsync("aux", "one", "n: 1\n"u8.ToArray());
        await Throws<YamoraException>(() => client.DocumentsAsync("examples", 1, first.NextAfter, first.Revision));
        Check((await Throws<HttpError>(() => client.QueryAsync("examples", JsonSerializer.SerializeToElement(new { revision = first.Revision })))).StatusCode == HttpStatusCode.PreconditionFailed);
        var aggregate = await client.AggregateAsync("examples", J("{\"pipeline\":[{\"$group\":{\"_id\":null,\"total\":{\"$sum\":\"$n\"}}}]}"));
        Check(aggregate.Value.GetProperty("documents")[0].GetProperty("total").GetInt64() == 8);
        var job = await client.StartIndexBuildAsync(J("{\"indexes\":[{\"collection\":\"examples\",\"name\":\"words\",\"fields\":[\"$source\"],\"type\":\"text\"}]}"));
        var id = job.Value.GetProperty("id").GetString()!;
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        do
        {
            await Task.Delay(20, deadline.Token);
            job = await client.IndexBuildAsync(id, deadline.Token);
        } while (job.Value.GetProperty("status").GetString() == "running");
        Check(job.Value.GetProperty("status").GetString() == "succeeded");
        await client.IndexBuildAsync();
        var search = await client.SearchAsync("examples", J("{\"index\":\"words\",\"text\":\"rollback\"}"));
        Check(search.Value.GetProperty("documents").GetArrayLength() == 1);
        await Throws<HttpError>(() => client.CancelIndexBuildAsync(id));
        await Throws<HttpError>(() => client.LeaderAsync()); // standalone does not advertise a leader
        await Throws<HttpError>(() => client.ClusterStatusAsync());
        await using var replica = await Native.Start(binary, replica: true);
        using var target = replica.Client();
        await target.ReplicationStatusAsync();
        var begun = await target.BeginReplicationAsync(J("{\"revision\":\"0123456789abcdef\",\"collections\":[\"examples\"]}"));
        var session = begun.Value.GetProperty("session").GetString();
        await target.AbortReplicationAsync(JsonSerializer.SerializeToElement(new { session }));
    }

    static async Task NativeReplication(string binary)
    {
        await using var sourceDaemon = await Native.Start(binary);
        await using var replicaDaemon = await Native.Start(binary, replica: true);
        using var source = sourceDaemon.Client();
        using var target = replicaDaemon.Client();
        const string yaml = "# explicit replicated source\r\nn: 9007199254740993\r\n";
        await source.PutAsync("examples", "one", Encoding.UTF8.GetBytes(yaml));
        var checkpoint = await source.ChangesAsync();
        var after = checkpoint.Value.GetProperty("checkpoint").GetString()!;
        var begun = await target.BeginReplicationAsync(JsonSerializer.SerializeToElement(new
        {
            revision = checkpoint.Revision,
            collections = new[] { "examples" },
            full = true,
            revision_scheme = "xor-fnv-v2",
            source_after = after,
        }));
        var session = begun.Value.GetProperty("session").GetString();
        await target.ApplyReplicationAsync(JsonSerializer.SerializeToElement(new
        {
            session,
            operations = new[] { new { collection = "examples", document = "one", put = yaml } },
        }));
        await target.CommitReplicationAsync(JsonSerializer.SerializeToElement(new { session, revision = checkpoint.Revision }));
        Check((await target.GetAsync("examples", "one", checkpoint.Revision)).Source.SequenceEqual(Encoding.UTF8.GetBytes(yaml)));
        var position = await target.ReplicationStatusAsync();
        Check(position.Value.GetProperty("after").GetString() == after);
        await source.PatchAsync("examples", "one", J("{\"$inc\":{\"n\":1}}"));
        var changes = await source.ChangesAsync(after);
        var frame = changes.Value.GetProperty("transactions")[0];
        var beginArgs = JsonSerializer.SerializeToElement(new
        {
            after,
            token = frame.GetProperty("token").GetString(),
            previous_revision = frame.GetProperty("previous_revision").GetString(),
            revision = frame.GetProperty("revision").GetString(),
            operations = frame.GetProperty("operations").GetArrayLength(),
        });
        var follow = await target.BeginFollowAsync(beginArgs);
        session = follow.Value.GetProperty("session").GetString();
        await target.AbortFollowAsync(JsonSerializer.SerializeToElement(new { session }));
        follow = await target.BeginFollowAsync(beginArgs);
        session = follow.Value.GetProperty("session").GetString();
        await target.ApplyFollowAsync(JsonSerializer.SerializeToElement(new { session, operations = frame.GetProperty("operations") }));
        await target.CommitFollowAsync(JsonSerializer.SerializeToElement(new { session }));
        var expected = yaml.Replace("9007199254740993", "9007199254740994", StringComparison.Ordinal);
        Check((await target.GetAsync("examples", "one", changes.Revision)).Source.SequenceEqual(Encoding.UTF8.GetBytes(expected)));
        var finalPosition = await target.ReplicationStatusAsync();
        Check(finalPosition.Value.GetProperty("after").GetString() == frame.GetProperty("token").GetString());
    }

    static async Task NativeLarge(string binary)
    {
        await using var native = await Native.Start(binary);
        using var client = native.Client();
        var source = Encoding.UTF8.GetBytes("# exact large UTF-8\r\nn: 9223372036854775807\r\ntext: " + new string('é', 600_000) + "\r\n");
        var stored = await client.PutAsync("examples", "large", source);
        var document = await client.GetAsync("examples", "large", stored.Revision);
        Check(document.Source.SequenceEqual(source), "large source was truncated or rewritten");
        var query = await client.QueryAsync("examples", J("{\"projection\":[\"n\"],\"limit\":1}"));
        Check(query.Value.GetProperty("documents")[0].GetProperty("value").GetProperty("n").GetInt64() == long.MaxValue);
    }

    public static async Task<int> Main(string[] args)
    {
        if (Environment.GetEnvironmentVariable("TMPDIR") is not { } scratch || !Directory.Exists(scratch))
            throw new Exception("set TMPDIR to an owned disk-backed test directory");
        var tests = new List<(string Name, Func<Task> Run)> {
            ("replication-source", ReplicationSourceGuard),
            ("endpoint-validation", Endpoints), ("token-validation", Tokens), ("path-and-body-validation", Inputs),
            ("exact-yaml", ExactYaml), ("put-conditions", PutConditions), ("redirect-rejection", Redirect),
            ("size-and-framing", SizeAndFraming), ("response-bounds", ResponseBounds), ("invalid-metadata", InvalidMetadata), ("deadlines-cancellation", DeadlineAndCancellation),
            ("no-mutation-replay", NoReplay), ("no-env-proxy", NoProxy), ("verified-tls13", Tls), ("query-numbers", QueryNumbers),
            ("offline-client-certificate", OfflineClientCertificate), ("raw-response-framing", RawResponseFraming),
            ("malformed-transaction-receipts", MalformedTransactionReceipts), ("explicit-client-intermediates", ExplicitClientIntermediates),
        };
        tests.AddRange(new (string Name, Func<Task> Run)[] {
            ("binary-operation-peer", BinaryOperationPeer), ("binary-operation-count", BinaryOperationCount),
            ("binary-operations", BinaryOperations), ("binary-operation-feeds", BinaryOperationFeeds),
            ("binary-configuration", BinaryConfiguration), ("binary-tls-trust", BinaryTlsTrust),
            ("binary-utf8-boundaries", BinaryUtf8Boundaries),
            ("binary-hostile-receipts", BinaryHostileReceipts), ("binary-hostile-frames", BinaryHostileFrames),
            ("binary-concurrent-ownership", BinaryConcurrentOwnership), ("binary-decode-deadlines", BinaryDecodeDeadlines),
            ("cluster-public-decode-lifetime", ClusterPublicDecodeLifetime),
            ("cluster-error-framing", ClusterErrorFraming),
            ("cluster-configuration", ClusterConfiguration), ("cluster-identity", ClusterIdentity),
            ("cluster-trust-redirects", ClusterTrustAndRedirects), ("cluster-receipts", ClusterReceipts),
            ("cluster-framing", ClusterFraming), ("cluster-immutable-recovery", ClusterImmutableRecovery),
            ("cluster-certainty-budgets", ClusterCertaintyAndBudgets), ("cluster-concurrent-lifetime", ClusterConcurrentLifetime),
        });
        var binary = Environment.GetEnvironmentVariable("YAMORA_TEST_BINARY");
        if (binary is null || !Path.IsPathFullyQualified(binary) || !File.Exists(binary))
        {
            Console.Error.WriteLine("YAMORA_TEST_BINARY must name an existing absolute native daemon; acceptance never skips");
            return 1;
        }
        var binaryHash = System.Security.Cryptography.SHA256.HashData(await File.ReadAllBytesAsync(binary!));
        if (binary is not null)
        {
            tests.Add(("package-artifact", () => PackageArtifact(binary)));
            tests.Add(("package-lifecycle", PackageLifecycle));
            tests.Add(("binary-native-crud", () => BinaryNativeCrud(binary)));
            tests.Add(("binary-native-large", () => BinaryNativeLarge(binary)));
            tests.Add(("binary-native-lost-receipts", () => BinaryNativeLostReceipts(binary)));
            tests.Add(("binary-native-owned-identity", () => BinaryNativeOwnedIdentity(binary)));
            tests.Add(("binary-native-offline-identity", () => BinaryNativeOfflineIdentity(binary)));
            tests.Add(("binary-native-offline-identity-oracle", () => BinaryNativeOfflineIdentityOracle(binary)));
            tests.Add(("cluster-native-fixture-guards", () => NativeFixtureGuards(binary)));
            tests.Add(("cluster-native-replica-set", () => NativeReplicaSet(binary)));
            tests.Add(("cluster-native-receipt-recovery", () => NativeReceiptRecovery(binary)));
            tests.Add(("native-http-crud", () => NativeCrud(binary, false)));
            tests.Add(("native-mtls-crud", () => NativeCrud(binary, true)));
            tests.Add(("native-json-operations", () => NativeOperations(binary)));
            tests.Add(("native-explicit-replication", () => NativeReplication(binary)));
            tests.Add(("native-large-yaml", () => NativeLarge(binary)));
        }

        var selected = tests.Where(t => args.Length == 0 || args.Contains(t.Name, StringComparer.Ordinal)).ToArray();
        Check(selected.Length > 0, "unknown test selector");
        var failed = 0;
        foreach (var test in selected)
        {
            try { await test.Run(); Console.WriteLine("PASS " + test.Name); }
            catch (Exception e) { failed++; Console.WriteLine("FAIL " + test.Name + ": " + e); }
        }
        Console.WriteLine($"{selected.Length - failed}/{selected.Length} checks passed; native enabled: {binary is not null}");
        var finalBinaryHash = System.Security.Cryptography.SHA256.HashData(await File.ReadAllBytesAsync(binary!));
        Check(binaryHash.SequenceEqual(finalBinaryHash), "native daemon changed during qualification");
        return failed == 0 ? 0 : 1;
    }
}
