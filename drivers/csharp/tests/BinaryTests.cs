using System.Diagnostics;
using System.Net;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Yamora;

namespace DriverTests;

static partial class Program
{
    static BinaryClient Binary(string endpoint, X509Certificate2 root, TimeSpan? timeout = null, int capacity = 4,
        X509Certificate2? identity = null, int frame = 65536, string name = "127.0.0.1")
        => new(new BinaryClientOptions { Endpoint = endpoint, ServerName = name, TrustedRoots = [root],
            Timeout = timeout ?? TimeSpan.FromSeconds(5), MaxConcurrentCalls = capacity, ClientCertificate = identity, MaxFrameBytes = frame });
    static async Task BinaryConfiguration()
    {
        using var ca = new Certificates();
        foreach (var endpoint in new[] { "http://127.0.0.1:1", "https://localhost:1", "https://127.1:1", "https://0177.0.0.1:1", "https://127.0.0.1:01",
            "https://8.8.8.8:1", "https://169.254.169.254:1", "https://127.0.0.1:1/", "https://127.0.0.1:1?x", "https://127.0.0.1:0", "https://u:p@127.0.0.1:1" })
            Invalid(() => Binary(endpoint, ca.Root));
        foreach (var name in new[] { "", "foo/bar", "foo.", "foo\n", "https://foo", "127.1", "[::1]", "*.test" })
            Invalid(() => Binary("https://127.0.0.1:1", ca.Root, name: name));
        foreach (var capacity in new[] { 0, 5 }) Invalid(() => Binary("https://127.0.0.1:1", ca.Root, capacity: capacity));
        foreach (var cap in new[] { 4095, 65537 }) Invalid(() => Binary("https://127.0.0.1:1", ca.Root, frame: cap));
        Invalid(() => new BinaryClient(new BinaryClientOptions { Endpoint = "https://127.0.0.1:1", ServerName = "127.0.0.1", TrustedRoots = [] }));
        using var db = Binary("https://127.0.0.1:1", ca.Root);
        foreach (var name in new[] { "", "..", "A", "a/b", "é", new string('a', 129) }) await Throws<ArgumentException>(() => db.GetAsync(name, "one"));
        foreach (var token in new[] { "", "a b", "a\r\n", "é", new string('a', 513) }) await Throws<ArgumentException>(() => db.GetAsync("allowed", "one", token));
        foreach (var id in new[] { "", new string('0', 32), new string('A', 32), "bad" }) await Throws<ArgumentException>(() => db.PutAsync("allowed", "one", [], requestId: id));
        await Throws<ArgumentException>(() => db.PutAsync("allowed", "one", new byte[BinaryClient.DocumentLimit + 1]));
        Check((await Throws<BinaryException>(() => db.PutAsync("allowed", "one", [0xff]))).Kind == BinaryFailure.Protocol);
        await Throws<ArgumentException>(() => db.CallAsync(BinaryMethod.Get, "allowed", "one", [1]));
        await Throws<ArgumentException>(() => db.PutAsync("allowed", "one", [], ifMatch: new string('x', 32)));
    }

    static async Task BinaryNativeCrud(string binary)
    {
        await using var native = await BinaryNative.Start(binary); using var db = native.Client(); using var http = native.Http();
        var cases = new[] { "# exact é\r\nname: café\r\nn: 01 # unchanged\r\n", "# Unicode\nname: 雪😀\nvalue: |\n  source\n  retained\n", "quoted: '1'\nfloat: 1.00\n# trailing comment\n",
            "#" + new string('x', 4094) + "é" + new string('x', 5000) + "\r\nn: 1\r\n",
            "#" + new string('x', 4092) + "😀" + new string('x', 5000) + "\r\nn: 1\r\n" };
        for (var i = 0; i < cases.Length; i++)
        {
            var name = "doc" + i; var source = Encoding.UTF8.GetBytes(cases[i]);
            var stored = await db.PutAsync("allowed", name, source, Native.WriteToken, ifNoneMatch: "*");
            Check(stored.StatusCode == 201 && stored.ETag == BinaryFixtureWire.Hash(source));
            var read = await db.GetAsync("allowed", name, Native.ReadToken);
            Check(read.Body.SequenceEqual(source) && read.ETag == stored.ETag && read.RequestId is null, "native byte identity");
            var copy = read.Body; copy[0] ^= 1; Check(read.Body.SequenceEqual(source), "response exposed backing source");
            Check((await http.GetAsync("allowed", name)).Source.SequenceEqual(source), "binary to HTTP exact source");
            var head = await db.HeadAsync("allowed", name, Native.ReadToken);
            Check(head.StatusCode == 200 && head.Body.Length == 0 && head.RepresentationLength == source.Length && head.ETag == read.ETag);
            Check((await Throws<BinaryException>(() => db.PutAsync("allowed", name, source, Native.WriteToken, ifNoneMatch: "*"))).StatusCode == 412);
            Check((await Throws<BinaryException>(() => db.PutAsync("allowed", name, source, Native.WriteToken, ifMatch: "\"0000000000000000\""))).StatusCode == 412);
            var update = await db.PutAsync("allowed", name, source, Native.WriteToken, ifMatch: '"' + stored.ETag + '"'); Check(update.StatusCode == 200);
            await http.PutAsync("allowed", name, "n: 2\n# HTTP source\r\n"u8.ToArray());
            Check((await db.GetAsync("allowed", name, Native.ReadToken)).Body.SequenceEqual("n: 2\n# HTTP source\r\n"u8.ToArray()), "HTTP to binary source");
            Check((await db.DeleteAsync("allowed", name, Native.WriteToken)).StatusCode == 204);
            Check((await Throws<BinaryException>(() => db.GetAsync("allowed", name, Native.ReadToken))).StatusCode == 404);
        }
        foreach (var credential in new string?[] { null, "wrong" }) Check((await Throws<BinaryException>(() => db.GetAsync("allowed", "one", credential))).StatusCode == 401);
        Check((await Throws<BinaryException>(() => db.PutAsync("allowed", "denied", "n: 1\n"u8.ToArray(), Native.ReadToken))).StatusCode is 401 or 403);
        await db.PutAsync("allowed", "scoped", "n: 1\n"u8.ToArray(), BinaryNative.ScopedToken);
        Check((await Throws<BinaryException>(() => db.PutAsync("private", "scoped", "n: 1\n"u8.ToArray(), BinaryNative.ScopedToken))).StatusCode == 403);
        Check((await Throws<BinaryException>(() => db.GetAsync("private", "scoped", BinaryNative.ScopedToken))).StatusCode == 403);
        Check((await Throws<BinaryException>(() => db.HeadAsync("private", "scoped", BinaryNative.ScopedToken))).StatusCode == 403);
        using var noIdentity = native.Client(identity: false); Check((await Throws<BinaryException>(() => noIdentity.GetAsync("allowed", "scoped", Native.ReadToken))).Kind == BinaryFailure.Transport);
    }
    static async Task BinaryNativeLarge(string binary)
    {
        await using (var native = await BinaryNative.Start(binary))
        {
            using var db = native.Client(cap: 4096); using var http = native.Http();
            var source = Enumerable.Repeat((byte)'x', BinaryClient.DocumentLimit).ToArray();
            var prefix = "# exact é CRLF\r\nvalue: 01\r\n# "u8; prefix.CopyTo(source); source[^2] = 13; source[^1] = 10;
            var stored = await db.PutAsync("allowed", "large", source, Native.WriteToken, ifNoneMatch: "*");
            Check(stored.StatusCode == 201 && stored.ETag == BinaryFixtureWire.Hash(source));
            Check((await db.GetAsync("allowed", "large", Native.ReadToken)).Body.SequenceEqual(source), "16MiB over 4KiB identity");
            Check((await http.GetAsync("allowed", "large")).Source.SequenceEqual(source), "large HTTP interoperability");
            Check((await db.HeadAsync("allowed", "large", Native.ReadToken)).RepresentationLength == source.Length);
        }
        await using (var legacy = await BinaryNative.Start(binary, legacy: true))
        {
            using var db = legacy.Client(); using var http = legacy.Http();
            var source = Encoding.ASCII.GetBytes("value: 1\n# " + new string('x', 256 * 1024));
            Check((await Throws<BinaryException>(() => db.PutAsync("allowed", "legacy", source, Native.WriteToken))).StatusCode == 413);
            Check((await Throws<HttpError>(() => http.GetAsync("allowed", "legacy"))).StatusCode == HttpStatusCode.NotFound, "legacy source published despite rejection");
            await db.PutAsync("allowed", "legacy", "n: 1\n"u8.ToArray(), Native.WriteToken);
        }
    }
    static async Task BinaryNativeLostReceipts(string binary)
    {
        await using var native = await BinaryNative.Start(binary); using var http = native.Http();
        using var certificate = native.Ca.Issue();
        foreach (var mode in new[] { "lost", "partial", "cancel" })
        {
            var committed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously); var forwarded = 0;
            await using var proxy = new BinaryServer(certificate, async (stream, request, ct) =>
            {
                var reply = await native.Forward(request, ct); var number = Interlocked.Increment(ref forwarded);
                if (number == 1)
                {
                    committed.TrySetResult();
                    if (mode == "lost") return;
                    if (mode == "partial") { await stream.WriteAsync(reply.AsMemory(0, reply.Length - 16), ct); return; }
                    await release.Task.WaitAsync(ct); return;
                }
                await stream.WriteAsync(reply, ct);
            });
            using var db = Binary(proxy.Endpoint, native.Ca.Root); using var cancel = new CancellationTokenSource();
            var source = Encoding.UTF8.GetBytes("# committed before " + mode + " é\r\nn: 01\r\n"); var original = (byte[])source.Clone();
            var id = Guid.NewGuid().ToString("N");
            var operation = db.PutAsync("allowed", mode, source, Native.WriteToken, requestId: id, ct: cancel.Token);
            await committed.Task.WaitAsync(TimeSpan.FromSeconds(15));
            Array.Fill(source, (byte)'x'); if (mode == "cancel") { cancel.Cancel(); release.TrySetResult(); }
            var error = await Throws<BinaryUncertainException>(() => operation);
            Check(error.OutcomeMayBeCommitted && error.Recovery.RequestId == id && error.Recovery.Source.SequenceEqual(original), "lost receipt did not retain original envelope");
            var exposed = error.Recovery.Source; Array.Fill(exposed, (byte)'y');
            Check(error.Recovery.Source.SequenceEqual(original) && !error.ToString().Contains(Native.WriteToken, StringComparison.Ordinal), "mutable/leaking recovery");
            await Task.Delay(40); Check(proxy.Requests.Count == 1 && proxy.Connections == 1 && forwarded == 1, "automatic replay occurred");
            using (var preCanceled = new CancellationTokenSource())
            {
                preCanceled.Cancel();
                var again = await Throws<BinaryUncertainException>(() => db.ReplayAsync(error.Recovery, Native.WriteToken, preCanceled.Token));
                Check(ReferenceEquals(again.Recovery, error.Recovery) && again.Kind == BinaryFailure.Canceled && proxy.Requests.Count == 1, "pre-canceled replay lost original uncertainty");
            }
            // Independent authenticated native HTTP observation before the only retry.
            Check((await http.GetAsync("allowed", mode)).Source.SequenceEqual(original), "exact committed source must be independently observed before retry");
            var replayed = await db.ReplayAsync(error.Recovery, Native.WriteToken);
            Check(replayed.StatusCode == 200 && proxy.Requests.Count == 2 && proxy.Connections == 2 && forwarded == 2, "explicit replay observability");
            var requests = proxy.Requests.ToArray();
            Check(requests.All(r => r.Id == id && r.Source.SequenceEqual(original)), "replay changed original operation");
            Check((await http.GetAsync("allowed", mode)).Source.SequenceEqual(original));
        }
    }

    static async Task BinaryTlsTrust()
    {
        using var ca = new Certificates(); using var good = ca.Issue();
        await using (var server = new BinaryServer(good, (s, r, ct) => BinaryFixtureWire.Reply(s, r, ct)))
        {
            var roots = new[] { X509CertificateLoader.LoadCertificate(ca.Root.RawData) };
            using var db = new BinaryClient(new BinaryClientOptions { Endpoint = server.Endpoint, ServerName = "127.0.0.1", TrustedRoots = roots });
            roots[0].Dispose(); roots[0] = good;
            Check((await db.GetAsync("allowed", "one", "a")).Body.SequenceEqual("n: 1\n"u8.ToArray()));
            Check(server.Requests.Single().Fields[5].SequenceEqual("Bearer a"u8.ToArray()), "bearer was not per call");
            await db.GetAsync("allowed", "one"); Check(!server.Requests.Last().Fields.ContainsKey(5), "bearer retained across calls");
        }
        foreach (var certificate in new[] { ca.Issue("127.0.0.2"), ca.Issue(expired: true), ca.Issue(client: true) })
        {
            using (certificate)
            await using (var server = new BinaryServer(certificate, (s, r, ct) => BinaryFixtureWire.Reply(s, r, ct)))
            using (var db = Binary(server.Endpoint, ca.Root))
            {
                Check((await Throws<BinaryException>(() => db.GetAsync("allowed", "one"))).Kind == BinaryFailure.Transport);
                Check(server.Requests.IsEmpty, "untrusted request dispatched");
            }
        }
        using var other = new Certificates();
        await using (var server = new BinaryServer(good, (s, r, ct) => BinaryFixtureWire.Reply(s, r, ct)))
        using (var db = Binary(server.Endpoint, other.Root))
        { await Throws<BinaryException>(() => db.GetAsync("allowed", "one")); Check(server.Requests.IsEmpty); }
        foreach (var config in new[] { (SslProtocols.Tls12, (string?)"yamora-binary/1"), (SslProtocols.Tls13, (string?)null), (SslProtocols.Tls13, (string?)"http/1.1") })
        {
            await using var server = new BinaryServer(good, (s, r, ct) => BinaryFixtureWire.Reply(s, r, ct), config.Item1, config.Item2);
            using var db = Binary(server.Endpoint, ca.Root); await Throws<BinaryException>(() => db.GetAsync("allowed", "one"));
            Check(server.Requests.IsEmpty, "TLS/ALPN failure dispatched a request");
        }
        // The certificate's DNS name is identity only, never a routing lookup.
        using var named = ca.Issue(peerName: "frozen.invalid");
        await using (var server = new BinaryServer(named, (s, r, ct) => BinaryFixtureWire.Reply(s, r, ct)))
        using (var db = Binary(server.Endpoint, ca.Root, name: "frozen.invalid"))
            await db.GetAsync("allowed", "one");
        // Missing AIA issuers must fail offline without contacting their HTTP URL.
        await using var observer = new Server(s => Server.Bytes(s, Server.Response("")));
        using var intermediate = ca.Intermediate(); using var aia = ca.Issue(issuer: intermediate, issuerUrl: observer.Endpoint + "/issuer");
        await using (var server = new BinaryServer(aia, (s, r, ct) => BinaryFixtureWire.Reply(s, r, ct)))
        using (var db = Binary(server.Endpoint, ca.Root)) { await Throws<BinaryException>(() => db.GetAsync("allowed", "one")); Check(server.Requests.IsEmpty); }
        Check(observer.Connections == 0, "server AIA fetched over network");
    }
}
