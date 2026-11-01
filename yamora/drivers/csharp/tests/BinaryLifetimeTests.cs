using System.Diagnostics;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using Yamora;

namespace DriverTests;

static partial class Program
{
    static async Task BinaryConcurrentOwnership()
    {
        using var ca = new Certificates(); using var certificate = ca.Issue();
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var server = new BinaryServer(certificate, async (s, r, ct) =>
        {
            await release.Task.WaitAsync(ct); await BinaryFixtureWire.Reply(s, r, ct);
        });
        using var db = Binary(server.Endpoint, ca.Root, timeout: TimeSpan.FromSeconds(15));
        var sources = Enumerable.Range(0, 4).Select(i => Encoding.UTF8.GetBytes($"# owned {i} é\r\nn: {i}\r\n")).ToArray();
        var originals = sources.Select(b => (byte[])b.Clone()).ToArray();
        using var canceled = new CancellationTokenSource();
        var active = sources.Select((b, i) => db.PutAsync("allowed", "doc" + i, b, Native.WriteToken, ct: i == 0 ? canceled.Token : default)).ToArray();
        await server.WaitRequests(4);
        foreach (var b in sources) Array.Fill(b, (byte)'x');
        // An invalid queued buffer becomes valid before admission: a speculative
        // clone/validation in a waiter would fail or later send the wrong source.
        var queued = new byte[] { 0xff, 0xff, 0xff, 0xff, 0xff };
        var waiter = db.PutAsync("allowed", "queued", queued, Native.WriteToken);
        using var stopped = new CancellationTokenSource();
        var cancelWaiter = db.PutAsync("allowed", "canceled", "n: 1\n"u8.ToArray(), Native.WriteToken, ct: stopped.Token);
        await Task.Delay(50);
        Check(!waiter.IsCompleted && server.Connections == 4 && server.Requests.Count == 4, "admission permitted a fifth frozen call");
        stopped.Cancel();
        var queuedError = await Throws<BinaryException>(() => cancelWaiter);
        Check(queuedError.Kind == BinaryFailure.Canceled && !queuedError.OutcomeMayBeCommitted, "queued cancellation dispatched");
        "n: 9\n"u8.CopyTo(queued);
        canceled.Cancel();
        var uncertain = await Throws<BinaryUncertainException>(() => active[0]);
        Check(uncertain.Kind == BinaryFailure.Canceled && uncertain.Recovery.Source.SequenceEqual(originals[0]));
        await server.WaitRequests(5);
        db.Dispose();
        await Throws<ObjectDisposedException>(() => db.GetAsync("allowed", "new"));
        release.TrySetResult();
        await Task.WhenAll(active.Skip(1)).WaitAsync(TimeSpan.FromSeconds(20)); await waiter.WaitAsync(TimeSpan.FromSeconds(20));
        Check(server.Requests.Count == 5 && server.Connections == 5, "cancellation affected another call or replayed");
        foreach (var request in server.Requests.Where(r => Encoding.ASCII.GetString(r.Fields[2]).Split('/')[^1].StartsWith("doc", StringComparison.Ordinal)))
        {
            var index = int.Parse(Encoding.ASCII.GetString(request.Fields[2])[^1..]);
            Check(request.Source.SequenceEqual(originals[index]), "admitted input was not owned");
        }
        Check(server.Requests.Last().Source.SequenceEqual("n: 9\n"u8.ToArray()), "waiter held an extra source copy");
    }
    static async Task BinaryDecodeDeadlines()
    {
        using var ca = new Certificates(); using var certificate = ca.Issue();
        foreach (var stage in new[] { "Yamora.BinaryDecode", "Yamora.BinaryHash", "Yamora.BinaryReturn" })
        foreach (var cancel in new[] { true, false })
        {
            using var cts = new CancellationTokenSource(); var observed = 0;
            using var listener = new ActivityListener
            {
                ShouldListenTo = s => s.Name == "Yamora.Binary",
                Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllData,
                ActivityStopped = a =>
                {
                    if (a.OperationName != stage || Interlocked.Increment(ref observed) != 1) return;
                    if (cancel) cts.Cancel(); else Thread.Sleep(700);
                },
            };
            ActivitySource.AddActivityListener(listener);
            await using var server = new BinaryServer(certificate, (s, r, ct) => BinaryFixtureWire.Reply(s, r, ct));
            using var db = Binary(server.Endpoint, ca.Root, timeout: TimeSpan.FromMilliseconds(500));
            var error = await BinaryRejected(() => db.PutAsync("allowed", "one", "# decode é\r\nn: 1\r\n"u8.ToArray(), Native.WriteToken, ct: cts.Token), server, "guard-" + stage);
            Check(observed == 1 && server.Requests.Count == 1 && server.Connections == 1
                && error.Kind == (cancel ? BinaryFailure.Canceled : BinaryFailure.Deadline), "decode/hash/final deadline guard failed: " + stage);
        }
        // Stalled TCP/TLS and fragmented response progress must not reset budget.
        await using (var server = new BinaryServer(certificate, async (s, r, ct) =>
        {
            var frame = BinaryFixtureWire.Frame(3, BinaryFixtureWire.Tlv(BinaryFixtureWire.Metadata(r, BinaryFixtureWire.Receipt(r))));
            foreach (var b in frame) { await s.WriteAsync(new byte[] { b }, ct); await Task.Delay(40, ct); }
        }))
        using (var db = Binary(server.Endpoint, ca.Root, timeout: TimeSpan.FromMilliseconds(250)))
        {
            var elapsed = Stopwatch.StartNew();
            Check((await Throws<BinaryUncertainException>(() => db.PutAsync("allowed", "one", "n: 1\n"u8.ToArray()))).Kind == BinaryFailure.Deadline);
            Check(server.Requests.Count == 1 && elapsed.Elapsed < TimeSpan.FromSeconds(3), "fragment deadline reset");
        }
    }
    static async Task BinaryNativeOwnedIdentity(string binary)
    {
        await using var native = await BinaryNative.Start(binary);
        var root = X509CertificateLoader.LoadCertificate(native.Ca.Root.RawData);
        var pfx = native.Identity.Export(X509ContentType.Pkcs12);
        using var identity = X509CertificateLoader.LoadPkcs12(pfx, null, X509KeyStorageFlags.EphemeralKeySet);
        System.Security.Cryptography.CryptographicOperations.ZeroMemory(pfx);
        using var db = Binary(native.Endpoint, root, identity: identity);
        root.Dispose(); identity.Dispose();
        // The binary API accepts only exact byte[] sources, never JsonElement,
        // converters, streams, MemoryManager or caller-owned TLS option objects.
        var calls = Enumerable.Range(0, 4).Select(i => db.PutAsync("allowed", "owned" + i, "n: 1\n"u8.ToArray(), Native.WriteToken)).ToArray();
        var replies = await Task.WhenAll(calls); Check(replies.All(r => r.StatusCode == 201), "disposed caller identity affected calls");
    }
    static async Task BinaryNativeOfflineIdentity(string binary)
        => await BinaryNativeOfflineIdentityCheck(binary, mtls: true);

    const string MissingIntermediateAccepted = "REGRESSION missing-client-intermediate: TLS accepted GET 200 with exact seeded source";
    static async Task BinaryNativeOfflineIdentityCheck(string binary, bool mtls)
    {
        await using var native = await BinaryNative.Start(binary, mtls: mtls);
        var source = "# seeded before missing-intermediate check\r\nn: 1\r\n"u8.ToArray();
        using (var valid = native.Client())
        {
            Check((await valid.PutAsync("allowed", "one", source, Native.WriteToken)).StatusCode == 201, "offline identity seed was not created");
            Check((await valid.GetAsync("allowed", "one", Native.ReadToken)).Body.SequenceEqual(source), "offline identity seed was not independently read");
        }
        await using var observer = new Server(s => Server.Bytes(s, Server.Response("")));
        using var intermediate = native.Ca.Intermediate();
        using var leaf = native.Ca.Issue(client: true, issuer: intermediate, issuerUrl: observer.Endpoint + "/issuer");
        using (var missing = Binary(native.Endpoint, native.Ca.Root, identity: leaf))
        {
            BinaryException? failure = null;
            BinaryResponse? accepted = null;
            try { accepted = await missing.GetAsync("allowed", "one", Native.ReadToken); }
            catch (BinaryException error) { failure = error; }
            if (accepted is not null)
            {
                Check(accepted.StatusCode == 200 && accepted.Body.SequenceEqual(source), "TLS gate mutant did not serve the exact seeded target");
                throw new Exception(MissingIntermediateAccepted);
            }
            Check(failure is { Kind: BinaryFailure.Transport, StatusCode: 0 }, "missing client intermediate did not reject with Transport/status=0");
        }
        using var db = new BinaryClient(new BinaryClientOptions
        {
            Endpoint = native.Endpoint, ServerName = "127.0.0.1", TrustedRoots = [native.Ca.Root],
            ClientCertificate = leaf, ClientIntermediates = [intermediate, native.Ca.Root],
        });
        leaf.Dispose(); intermediate.Dispose();
        Check((await db.PutAsync("allowed", "offline", "n: 1\n"u8.ToArray(), Native.WriteToken)).StatusCode == 201);
        Check(observer.Connections == 0, "mTLS AIA fetched over network");
    }

    static async Task BinaryNativeOfflineIdentityOracle(string binary)
    {
        var rejected = false;
        try
        {
            // Deliberately remove the native mTLS admission gate. The seeded
            // GET must now complete, exposing the precise missing rejection.
            await BinaryNativeOfflineIdentityCheck(binary, mtls: false);
        }
        catch (Exception error) when (error.GetType() == typeof(Exception) && error.Message == MissingIntermediateAccepted)
        {
            rejected = true;
            Console.WriteLine("  RED missing-intermediate TLS gate: GET 200 and exact seeded source triggered the intended assertion");
        }
        // No status error, deadline, signal, sanitizer or fixture failure can
        // count as this behavioral red; native disposal runs before the catch.
        Check(rejected, "missing-intermediate oracle accepted the permissive TLS gate");
        await BinaryNativeOfflineIdentityCheck(binary, mtls: true);
        Console.WriteLine("  GREEN restored TLS gate: Transport/status=0; explicit owned chain succeeds; AIA connections=0");
    }
}
