using System.Collections.Concurrent;
using System.Diagnostics;
using System.Security.Authentication;
using System.Text;
using System.Text.Json;
using Yamora;

namespace DriverTests;

static partial class Program
{
    static Task ClusterConfiguration()
    {
        using var ca = new Certificates();
        foreach (var endpoint in new[] { "http://127.0.0.1:1", "https://localhost:1", "https://127.1:1", "https://8.8.8.8:1", "https://127.0.0.1:01" })
            Invalid(() => Cluster(endpoint, ca));
        foreach (var voters in new[] { 0, 1, 2, 4, 10 })
            Invalid(() => new ClusterClient(new ClusterOptions { Seeds = [new("https://127.0.0.1:1", 1)], ClusterId = ClusterId, Voters = voters }));
        foreach (var id in new[] { "", new string('0', 32), new string('A', 32) })
            Invalid(() => new ClusterClient(new ClusterOptions { Seeds = [new("https://127.0.0.1:1", 1)], ClusterId = id }));
        Invalid(() => new ClusterClient(Options([], ca)));
        Invalid(() => new ClusterClient(Options([new("https://127.0.0.1:1", 0)], ca)));
        Invalid(() => new ClusterClient(Options([new("https://127.0.0.1:1", 4)], ca)));
        Invalid(() => new ClusterClient(Options([new("https://127.0.0.1:1", 1), new("https://127.0.0.1:1/", 2)], ca)));
        return Task.CompletedTask;
    }

    static async Task ClusterIdentity()
    {
        using var ca = new Certificates(); using var cert = ca.Issue();
        foreach (var status in new[] { Status(2), Status().Replace("\"voters\":3", "\"voters\":5"), Status().Replace("\"term\":1", "\"term\":0"),
            Status().Replace("\"node\":1", "\"node\":1.0"), Status().Replace("\"term\":1", "\"term\":1e0"), Status().Replace("\"node\":1", "\"node\":1,\"node\":1"),
            Status().Replace("\"term\":1", "\"term\":18446744073709551616"), Status().Replace("leader\"}", "follower\"}") })
        {
            await using var peer = new ClusterPeer(cert, (r, s, _) => Server.Bytes(s, Reply(r.Path == "/v1/cluster/status" ? status : Feed)));
            using var client = Cluster(peer.Endpoint, ca, TimeSpan.FromMilliseconds(120));
            await Throws<YamoraException>(() => client.GetAsync("examples", "one"));
            Check(peer.Requests.All(r => r.Path is "/v1/cluster/status" or "/v1/changes"), "unbound node received user request");
        }
        foreach (var feed in new[] { Feed.Replace(ClusterId, new string('f', 32)), Feed.Replace("false", "true"),
            Feed.Replace("\"transactions\":[]", "\"transactions\":[{}]"), Feed.Replace("0000000000000001\",\"oldest", "0000000000000002\",\"oldest") })
        {
            await using var peer = new ClusterPeer(cert, (r, s, _) => Server.Bytes(s, Reply(r.Path == "/v1/cluster/status" ? Status() : feed)));
            using var client = Cluster(peer.Endpoint, ca, TimeSpan.FromMilliseconds(120));
            await Throws<YamoraException>(() => client.PutAsync("examples", "one", "n: 1\n"u8.ToArray()));
            Check(peer.Requests.All(r => r.Method == "GET"), "wrong feed received mutation");
        }
        var changed = false;
        await using var cached = new ClusterPeer(cert, (r, s, _) => Server.Bytes(s, r.Path == "/v1/cluster/status" ? Reply(Status(changed ? 2 : 1))
            : r.Path == "/v1/changes" ? Reply(Feed) : Reply("n: 1\n", extra: $"ETag: \"{Tag}\"\r\n", media: "application/yaml")));
        using var routed = Cluster(cached.Endpoint, ca, TimeSpan.FromMilliseconds(180));
        await routed.GetAsync("examples", "one"); changed = true;
        await Throws<YamoraException>(() => routed.GetAsync("examples", "one"));
        Check(cached.Requests.Count(r => r.Path.Contains("/documents/", StringComparison.Ordinal)) == 1, "cached route was not rebound");
    }

    static async Task ClusterTrustAndRedirects()
    {
        using var ca = new Certificates(); using var other = new Certificates();
        foreach (var kind in new[] { "unknown", "san", "expired", "eku", "tls12" })
        {
            using var certificate = kind == "unknown" ? other.Issue() : ca.Issue(ip: kind == "san" ? "127.0.0.2" : "127.0.0.1", client: kind == "eku", expired: kind == "expired");
            await using var peer = new ClusterPeer(certificate, (r, s, _) => Respond(r, s, Reply(Stored, extra: $"ETag: \"{Tag}\"\r\n")),
                kind == "tls12" ? SslProtocols.Tls12 : SslProtocols.Tls13);
            using var client = Cluster(peer.Endpoint, ca, TimeSpan.FromMilliseconds(150));
            var error = await Throws<YamoraException>(() => client.PutAsync("examples", "one", "n: 1\n"u8.ToArray()));
            Check(!error.OutcomeMayBeCommitted && peer.Requests.IsEmpty, kind + " received credentials");
        }
        using var cert = ca.Issue();
        await using var destination = new ClusterPeer(cert, (r, s, _) => Server.Bytes(s, Reply("{}")));
        await using var peerRedirect = new ClusterPeer(cert, (r, s, _) => Respond(r, s, Reply("", 307, $"Location: {destination.Endpoint}/steal\r\n")));
        using var redirect = Cluster(peerRedirect.Endpoint, ca);
        var uncertainty = await Throws<UncertainWriteException>(() => redirect.PutAsync("examples", "one", "n: 1\n"u8.ToArray()));
        Check(uncertainty.RequestId.Length == 32 && destination.Requests.IsEmpty);
        await using var hinted = new ClusterPeer(cert, (r, s, _) => Server.Bytes(s,
            r.Path == "/v1/cluster/status" ? Reply(Status()[..^1] + ",\"leader_address\":\"" + destination.Endpoint + "\"}")
            : r.Path == "/v1/changes" ? Reply(Feed) : Reply(Stored, extra: $"ETag: \"{Tag}\"\r\n")));
        using var hintedClient = Cluster(hinted.Endpoint, ca);
        await hintedClient.PutAsync("examples", "one", "n: 1\n"u8.ToArray());
        Check(destination.Requests.IsEmpty, "leader hint selected a credential destination");
    }

    static async Task ClusterReceipts()
    {
        using var ca = new Certificates(); using var cert = ca.Issue();
        var replies = new[] { Reply(Stored.Replace("stored", "failed")), Reply(Stored.Replace("examples", "other")),
            Reply(Stored.Replace("\"one\"", "\"two\"")), Reply(Stored.Replace(Revision, new string('0',16))),
            Reply(Stored.Replace("\"etag\":", "\"etag\":\"0000000000000000\",\"etag\":")), Reply(Stored),
            Reply(Stored,extra:$"ETag: \"{Revision}\"\r\n"), Reply(Stored,202,$"ETag: \"{Tag}\"\r\n"),
            Reply(Stored,extra:$"ETag: \"{Tag}\"\r\nETag: \"{Tag}\"\r\n"), Reply(Stored,extra:$"ETag: \"{Tag}\"\r\nX-YamlDB-Revision: {Revision}\r\n"),
            Reply(Stored,extra:$"ETag: \"{Tag}\"\r\nCache-Control: no-store\r\nCache-Control: public\r\n"), Reply("{bad"),
            Reply(Stored,extra:$"ETag: \"{Tag}\"\r\nContent-Length: {Encoding.UTF8.GetByteCount(Stored)}\r\n"),
            Reply(Stored,extra:$"ETag: \"{Tag}\"\r\nContent-Encoding: gzip\r\n"),
            Reply(Stored,extra:$"ETag: \"{Tag}\"\r\nContent-Type: application/json\r\n"),
            Reply(Stored,201,$"ETag: \"{Tag}\"\r\n"), // If-Match requires 200.
        };
        foreach (var reply in replies)
        {
            await using var peer = new ClusterPeer(cert, (r, s, _) => Respond(r, s, reply));
            using var client = Cluster(peer.Endpoint, ca);
            var error = await Throws<UncertainWriteException>(() => client.PutAsync("examples", "one", "n: 1\n"u8.ToArray(), new(Tag)));
            Check(error.OutcomeMayBeCommitted && error.Recovery.Conditions.ETag == Tag);
        }
        await using var create = new ClusterPeer(cert, (r, s, _) => Respond(r, s, Reply(Stored, extra: $"ETag: \"{Tag}\"\r\n")));
        using var createClient = Cluster(create.Endpoint, ca);
        await Throws<UncertainWriteException>(() => createClient.PutAsync("examples", "one", "n: 1\n"u8.ToArray(), new(CreateOnly: true)));
        foreach (var count in new[] { "0", "2", "1.0", "1e0", "true", "\"1\"", "-1", "18446744073709551616" })
        {
            var receipt = "{\"status\":\"committed\",\"operations\":" + count + ",\"revision\":\"" + Revision + "\"}";
            await using var peer = new ClusterPeer(cert, (r, s, _) => Respond(r, s, Reply(receipt)));
            using var client = Cluster(peer.Endpoint, ca);
            await Throws<UncertainWriteException>(() => client.TransactionAsync(J("{\"operations\":[{\"collection\":\"examples\",\"document\":\"one\",\"put\":\"n: 1\\n\"}]}")));
            await Throws<UncertainWriteException>(() => client.SetIndexesAsync(J("{\"indexes\":[]}")));
        }
        await using var diagnostic = new ClusterPeer(cert, (r, s, _) => Respond(r, s, Reply(Stored, extra: $"ETag: \"{Tag}\"\r\nCache-Control: no-store\r\nCache-Control: no-store\r\n")));
        using var good = Cluster(diagnostic.Endpoint, ca);
        Check((await good.PutAsync("examples", "one", "n: 1\n"u8.ToArray())).ETag == Tag);
    }

    static async Task ClusterFraming()
    {
        using var ca = new Certificates(); using var cert = ca.Issue();
        foreach (var framing in new[] { "", "Transfer-Encoding: chunked\r\n", "Transfer-Encoding: gzip, chunked\r\n", "Transfer-Encoding: chunked\r\nContent-Length: 2\r\n" })
        {
            var reply = $"HTTP/1.1 200 OK\r\nConnection: close\r\nX-YamlDB-Revision: {Revision}\r\nContent-Type: application/json\r\nETag: \"{Tag}\"\r\n{framing}\r\n";
            reply += framing.StartsWith("Transfer-Encoding", StringComparison.Ordinal) ? Encoding.UTF8.GetByteCount(Stored).ToString("x") + "\r\n" + Stored + "\r\n0\r\n\r\n" : Stored;
            await using var peer = new ClusterPeer(cert, (r, s, _) => Respond(r, s, reply));
            using var client = Cluster(peer.Endpoint, ca);
            await Throws<UncertainWriteException>(() => client.PutAsync("examples", "one", "n: 1\n"u8.ToArray()));
        }
    }

    static async Task ClusterImmutableRecovery()
    {
        using var ca = new Certificates(); using var cert = ca.Issue();
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var discovery = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var bad = true;
        await using var peer = new ClusterPeer(cert, async (r, s, ct) =>
        {
            if (r.Path == "/v1/cluster/status") { discovery.TrySetResult(); await release.Task.WaitAsync(ct); }
            await Respond(r, s, bad ? Reply("{bad") : Reply(Stored, extra: $"ETag: \"{Tag}\"\r\n"));
        });
        using var client = Cluster(peer.Endpoint, ca);
        var source = Encoding.UTF8.GetBytes("# exact é\r\nn: 9007199254740993\r\n"); var expected = source.ToArray();
        var task = client.PutAsync("examples", "one", source, new(RequestId: new string('a', 32)));
        await discovery.Task.WaitAsync(TimeSpan.FromSeconds(2)); Array.Fill(source, (byte)'x'); release.SetResult();
        var error = await Throws<UncertainWriteException>(() => task);
        Check(error.Recovery.Body!.SequenceEqual(expected) && error.RequestId == new string('a', 32));
        var tamper = error.Recovery.Body!; Array.Fill(tamper, (byte)'z');
        using (var cancellation = new CancellationTokenSource())
        {
            cancellation.Cancel();
            var canceled = await Throws<UncertainWriteException>(() => client.RecoverAsync(error.Recovery, cancellation.Token));
            Check(canceled.RequestId == error.RequestId && canceled.FailureKind == nameof(RequestCanceled));
        }
        bad = false; var recovered = await client.RecoverAsync(error.Recovery);
        Check(recovered.StatusCode == 200 && recovered.ETag == '"' + Tag + '"');
        var writes = peer.Requests.Where(r => r.Method == "PUT").ToArray();
        Check(writes.Length == 2 && writes.All(r => r.Body.SequenceEqual(expected) && r.Header("X-Yamora-Request-Id") == error.RequestId));

        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var txSeen = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var txPeer = new ClusterPeer(cert, async (r, s, ct) =>
        {
            if (r.Path == "/v1/cluster/status") { txSeen.TrySetResult(); await gate.Task.WaitAsync(ct); }
            await Respond(r, s, Reply("{\"status\":\"committed\",\"operations\":1,\"revision\":\"" + Revision + "\"}"));
        });
        using var txClient = Cluster(txPeer.Endpoint, ca);
        using var json = JsonDocument.Parse("{\"operations\":[{\"collection\":\"examples\",\"document\":\"one\",\"patch\":{\"$inc\":{\"n\":9007199254740993}}}]}");
        var tx = txClient.TransactionAsync(json.RootElement);
        await txSeen.Task.WaitAsync(TimeSpan.FromSeconds(2)); json.Dispose(); gate.SetResult();
        await tx;
        Check(Encoding.UTF8.GetString(txPeer.Requests.Single(r => r.Method == "POST").Body).Contains("9007199254740993", StringComparison.Ordinal));
    }

    static async Task ClusterCertaintyAndBudgets()
    {
        using var ca = new Certificates(); using var cert = ca.Issue();
        foreach (var status in new[] { 400, 401, 403, 404, 409, 412, 413, 415, 422, 429 })
        {
            await using var peer = new ClusterPeer(cert, (r, s, _) => Respond(r, s, Reply("", status)));
            using var client = Cluster(peer.Endpoint, ca);
            var error = await Throws<HttpError>(() => client.PutAsync("examples", "one", "n: 1\n"u8.ToArray()));
            Check(!error.OutcomeMayBeCommitted);
        }
        foreach (var status in new[] { 202, 301, 307, 408, 500, 502, 504 })
        {
            await using var peer = new ClusterPeer(cert, (r, s, _) => Respond(r, s, Reply("", status)));
            using var client = Cluster(peer.Endpoint, ca);
            await Throws<UncertainWriteException>(() => client.PutAsync("examples", "one", "n: 1\n"u8.ToArray()));
        }
        // Count mutations independently of the discovery callbacks.
        var mutations = 0;
        await using var later = new ClusterPeer(cert, (r, s, _) => Discovery(r, out var body) ? Server.Bytes(s, Reply(body)) :
            Server.Bytes(s, Reply("", Interlocked.Increment(ref mutations) == 1 ? 503 : 412)));
        using var retryClient = Cluster(later.Endpoint, ca);
        var uncertain = await Throws<UncertainWriteException>(() => retryClient.PutAsync("examples", "one", "n: 1\n"u8.ToArray()));
        Check(mutations == 2 && later.Requests.Where(r => r.Method == "PUT").Select(r => r.Header("X-Yamora-Request-Id")).Distinct().Count() == 1);
        await Throws<UncertainWriteException>(() => retryClient.RecoverAsync(uncertain.Recovery));
        await using var stall = new ClusterPeer(cert, async (_, _, ct) => await Task.Delay(3000, ct));
        await using var good = new ClusterPeer(cert, (r, s, _) => Respond(r, s, Reply("n: 1\n", extra: $"ETag: \"{Tag}\"\r\n", media: "application/yaml")));
        using var fair = new ClusterClient(Options([new(stall.Endpoint, 2), new(good.Endpoint, 1)], ca, TimeSpan.FromMilliseconds(700), TimeSpan.FromSeconds(2)));
        Check((await fair.GetAsync("examples", "one")).Source.SequenceEqual("n: 1\n"u8.ToArray()), "first seed starved later seed");
        using var shortClient = Cluster(stall.Endpoint, ca, TimeSpan.FromMilliseconds(120));
        var watch = Stopwatch.StartNew();
        await Throws<YamoraException>(() => shortClient.GetAsync("examples", "one"));
        Check(watch.Elapsed < TimeSpan.FromSeconds(1));
        Check(stall.Requests.Count < 32);
        using var unsupported = Cluster(good.Endpoint, ca);
        var before = good.Requests.Count;
        Check((int)(await Throws<HttpError>(() => unsupported.StartIndexBuildAsync(J("{\"indexes\":[]}")))).StatusCode == 405);
        Check((int)(await Throws<HttpError>(() => unsupported.BeginReplicationAsync(J("{}")))).StatusCode == 405);
        Check(before == good.Requests.Count, "unsupported operation performed discovery");
    }

    static async Task ClusterConcurrentLifetime()
    {
        using var ca = new Certificates(); using var cert = ca.Issue();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var arrivals = new ConcurrentDictionary<string, byte>();
        await using var peer = new ClusterPeer(cert, async (r, s, ct) =>
        {
            if (Discovery(r, out var body)) { await Server.Bytes(s, Reply(body)); return; }
            // Either call may reach the server first. Cancellation must wait
            // for BOTH immutable requests, not just the survivor's arrival.
            arrivals.TryAdd(r.Header("X-Yamora-Request-Id") ?? throw new Exception("missing request ID"), 0);
            if (arrivals.Count == 2) entered.TrySetResult();
            await release.Task.WaitAsync(ct);
            await Server.Bytes(s, Reply(Stored, extra: $"ETag: \"{Tag}\"\r\n"));
        });
        using var client = Cluster(peer.Endpoint, ca);
        using var cancel = new CancellationTokenSource();
        var canceled = client.PutAsync("examples", "one", "n: 1\n"u8.ToArray(), ct: cancel.Token);
        var survivor = client.PutAsync("examples", "one", "n: 1\n"u8.ToArray());
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(2)); cancel.Cancel(); client.Dispose();
        await Throws<UncertainWriteException>(() => canceled);
        release.TrySetResult(); Check((await survivor).ETag == Tag, "another call disposed/canceled certificate or handler");
        await Throws<ObjectDisposedException>(() => client.HealthAsync());
        Check(peer.Requests.Where(r => r.Method == "PUT").Select(r => r.Header("X-Yamora-Request-Id")).Distinct().Count() == 2);

        var discovered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var resume = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var bound = new ClusterPeer(cert, async (r, s, ct) =>
        {
            if (r.Path == "/v1/cluster/status") { discovered.TrySetResult(); await resume.Task.WaitAsync(ct); }
            await Respond(r, s, Reply(Stored, extra: $"ETag: \"{Tag}\"\r\n"));
        });
        using var disposing = Cluster(bound.Endpoint, ca);
        var call = disposing.PutAsync("examples", "one", "n: 1\n"u8.ToArray());
        await discovered.Task.WaitAsync(TimeSpan.FromSeconds(2));
        disposing.Dispose(); resume.TrySetResult();
        Check((await call).ETag == Tag, "Dispose released trust material before the owning discovery and dispatch finished");
    }
    static async Task ClusterPublicDecodeLifetime()
    {
        using var ca = new Certificates(); using var cert = ca.Issue();
        await using var peer = new ClusterPeer(cert, (r, s, _) => Respond(r, s, Reply(Stored, extra: $"ETag: \"{Tag}\"\r\n")));
        foreach (var cancelAtDecode in new[] { true, false })
        {
            using var cancellation = new CancellationTokenSource();
            var observed = 0;
            using var listener = new ActivityListener
            {
                ShouldListenTo = source => source.Name == "Yamora",
                Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllData,
                ActivityStopped = activity =>
                {
                    if (activity.OperationName != "Yamora.PublicDecode") return;
                    Interlocked.Increment(ref observed);
                    if (cancelAtDecode) cancellation.Cancel();
                    else Thread.Sleep(1100); // An actual synchronous tracing consumer holds public decode.
                },
            };
            ActivitySource.AddActivityListener(listener);
            using var client = Cluster(peer.Endpoint, ca, TimeSpan.FromSeconds(1));
            var error = await Throws<UncertainWriteException>(() => client.PutAsync("examples", "one", "n: 1\n"u8.ToArray(), ct: cancellation.Token));
            Check(observed == 1 && error.Recovery.Body!.SequenceEqual("n: 1\n"u8.ToArray()));
            Check(error.FailureKind == (cancelAtDecode ? nameof(RequestCanceled) : nameof(TransportError)));
        }
        using var canceled = new CancellationTokenSource();
        var rejection = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var unavailable = new ClusterPeer(cert, async (r, s, _) =>
        {
            await Respond(r, s, Reply("", 503));
            if (r.Method == "PUT") rejection.TrySetResult();
        });
        using var retry = Cluster(unavailable.Endpoint, ca);
        var pending = retry.PutAsync("examples", "one", "n: 1\n"u8.ToArray(), ct: canceled.Token);
        await rejection.Task.WaitAsync(TimeSpan.FromSeconds(2));
        await Task.Delay(5); canceled.Cancel();
        await Throws<UncertainWriteException>(() => pending);
        Check(unavailable.Requests.Count(r => r.Method == "PUT") == 1, "cancellation did not interrupt backoff");
    }

    static async Task ClusterErrorFraming()
    {
        using var ca = new Certificates(); using var cert = ca.Issue();
        foreach (var reply in new[] {
            Reply("x",400).Replace("Content-Length: 1", "Content-Length: 2"),
            Reply("",412,extra:"Content-Length: 0\r\n"),
            Reply("",400,extra:$"X-YamlDB-Revision: {Revision}\r\n"),
        })
        {
            await using var peer = new ClusterPeer(cert, (r, s, _) => Respond(r, s, reply));
            using var client = Cluster(peer.Endpoint, ca);
            await Throws<UncertainWriteException>(() => client.PutAsync("examples", "one", "n: 1\n"u8.ToArray()));
        }
    }

}
