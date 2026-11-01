using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net.Security;
using System.Security.Authentication;
using System.Net.Sockets;
using Yamora;

namespace DriverTests;

sealed class NativeProbeFailure(string message) : Exception(message);

// Reading starts at the complete native request send, independently of gateway
// reply delivery. Completion means the full HTTP frame, not EOF or a later Read.
sealed class NativeExchange : IAsyncDisposable
{
    private readonly TcpClient socket;
    private readonly SslStream stream;
    private readonly CancellationTokenSource stop;
    private readonly Task<byte[]> response;
    private long fullResponseAt;
    public long SentAt { get; }
    public long FullResponseAt => Interlocked.Read(ref fullResponseAt);
    public NativeExchange(TcpClient socket, SslStream stream, CancellationToken ct)
    {
        this.socket = socket; this.stream = stream;
        stop = CancellationTokenSource.CreateLinkedTokenSource(ct);
        SentAt = Stopwatch.GetTimestamp();
        response = Receive(stop.Token);
    }
    public Task<byte[]> Read(CancellationToken ct) => response.WaitAsync(ct);
    private async Task<byte[]> Receive(CancellationToken ct)
    {
        // Native replies have one Content-Length. Do not wait for connection
        // close: a fully buffered frame must finish its measured interval now.
        using var output = new MemoryStream();
        var one = new byte[1];
        var tail = 0;
        while (tail != 0x0d0a0d0a)
        {
            await stream.ReadExactlyAsync(one, ct);
            output.WriteByte(one[0]);
            tail = (tail << 8) | one[0];
            if (output.Length > 65536) throw new IOException("native response headers too large");
        }
        var headers = System.Text.Encoding.ASCII.GetString(output.ToArray()).Split("\r\n");
        var lengths = headers.Where(line => line.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase)).ToArray();
        if (lengths.Length != 1 || headers.Any(line => line.StartsWith("Transfer-Encoding:", StringComparison.OrdinalIgnoreCase))
            || !int.TryParse(lengths[0].Split(':', 2)[1].Trim(), System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture, out var length) || length > 16 * 1024 * 1024)
            throw new IOException("native qualification requires bounded Content-Length framing");
        var body = new byte[length];
        await stream.ReadExactlyAsync(body, ct);
        Interlocked.Exchange(ref fullResponseAt, Stopwatch.GetTimestamp());
        output.Write(body);
        return output.ToArray();
    }
    public async ValueTask DisposeAsync()
    {
        stop.Cancel();
        await stream.DisposeAsync(); socket.Dispose();
        try { await response; } catch (Exception error) when (error is IOException or OperationCanceledException or ObjectDisposedException) { }
        stop.Dispose();
    }
}

static partial class Program
{
    private sealed record LostReplyResult(Mutation Recovered, byte[] OriginalWire, string RequestId, int OldLeader);

    private static async Task<LostReplyResult> LostReply(NativeCluster cluster, byte[] expected, bool injectEarlyRetry = false)
    {
        var leader = await cluster.Leader();
        var verification = new TaskCompletionSource<(byte[] Wire, string Id)>(TaskCreationOptions.RunContinuationsAsynchronously);
        var observations = new ConcurrentQueue<(int Member, WireRequest Request, long ArrivedAt)>();
        var retryNativeSends = new ConcurrentQueue<long>();
        var peers = new List<ClusterPeer>();
        var guard = new object();
        var arrivals = 0; var earlyRetries = 0; var nativeSends = 0;
        long verifiedAt = 0;
        try
        {
            for (var i = 0; i < cluster.Seeds.Length; i++)
            {
                var member = i;
                peers.Add(new ClusterPeer(cluster.ServerCertificate, async (request, stream, ct) =>
                {
                    var mutation = request.Method is "PUT" or "PATCH" or "DELETE"
                        || request.Method == "POST" && request.Path == "/v1/transactions";
                    if (!mutation)
                    {
                        try { await stream.WriteAsync(await cluster.Forward(member, request, ct), ct); }
                        catch (Exception error) when (error is SocketException or IOException or AuthenticationException)
                        { await Server.Bytes(stream, Reply("", 503)); }
                        return;
                    }
                    bool first; bool early;
                    lock (guard)
                    {
                        first = arrivals++ == 0;
                        early = !first && verifiedAt == 0;
                        if (early) earlyRetries++;
                    }
                    observations.Enqueue((member, request, Stopwatch.GetTimestamp()));
                    if (early)
                    {
                        // An early retry is observable and rejected at EVERY
                        // configured seed. It cannot modify the source under test.
                        await Server.Bytes(stream, Reply("", 503));
                        return;
                    }
                    if (!first)
                    {
                        try
                        {
                            await using var retry = await cluster.Send(member, request, ct);
                            Interlocked.Increment(ref nativeSends);
                            retryNativeSends.Enqueue(retry.SentAt);
                            await stream.WriteAsync(await retry.Read(ct), ct);
                        }
                        catch (Exception error) when (error is SocketException or IOException or AuthenticationException)
                        { await Server.Bytes(stream, Reply("", 503)); }
                        return;
                    }
                    try
                    {
                        Check(member == leader, "initial mutation missed the selected native leader");
                        await using var original = await cluster.Send(member, request, ct);
                        Interlocked.Increment(ref nativeSends);
                        var wire = await original.Read(ct);
                        var value = WireJson(wire);
                        Check(value.GetProperty("status").GetString() == "stored");
                        if (injectEarlyRetry)
                            await cluster.ForwardTo(peers[(member + 1) % peers.Count].Endpoint, request, ct);
                        using var direct = cluster.Direct(member);
                        Check((await direct.GetAsync("examples", "one")).Source.SequenceEqual(expected),
                            "exact source was not committed before retry admission");
                        lock (guard)
                        {
                            verifiedAt = Stopwatch.GetTimestamp();
                            if (earlyRetries != 0)
                                throw new NativeProbeFailure($"early retry rejected: arrivals={arrivals}, early={earlyRetries}, native_sends_before_assert={nativeSends}");
                        }
                        // The exact source assertion and retry-admission marker
                        // both precede crash and loss of the original reply.
                        await cluster.StopNode(leader, crash: true);
                        verification.TrySetResult((wire, request.Header("X-Yamora-Request-Id")!));
                    }
                    catch (Exception error) { verification.TrySetException(error); }
                }));
            }
            // No direct native seed is exposed to this routed client.
            var order = new[] { leader }.Concat(Enumerable.Range(0, peers.Count).Where(i => i != leader));
            var seeds = order.Select(i => new ClusterSeed(peers[i].Endpoint, i + 1)).ToArray();
            using var cancellation = new CancellationTokenSource();
            using var routed = cluster.Client(seeds);
            var pending = routed.PatchAsync("examples", "one", J("{\"$inc\":{\"n\":1}}"), ct: cancellation.Token);
            try
            {
                var original = await verification.Task.WaitAsync(TimeSpan.FromSeconds(15));
                var recovered = await pending;
                Check(earlyRetries == 0 && observations.Count >= 2 && nativeSends >= 2,
                    "lost reply did not produce an observed native replay");
                Check(observations.All(item => item.Request.Header("X-Yamora-Request-Id") == original.Id
                    && item.Request.Body.SequenceEqual(observations.First().Request.Body)));
                Check(retryNativeSends.All(sent => sent > verifiedAt), "native retry preceded exact source verification");
                Check(observations.Select(item => item.Member).Distinct().Count() >= 2, "failover did not cross observed seed gateways");
                Console.WriteLine($"  lost reply: gateways={peers.Count}, mutation_arrivals={arrivals}, early_retries={earlyRetries}, native_sends={nativeSends}; exact source verified before every native retry");
                return new(recovered, original.Wire, original.Id, leader);
            }
            finally
            {
                cancellation.Cancel();
                try { await pending; } catch { }
            }
        }
        finally
        {
            var failures = new List<Exception>();
            foreach (var peer in peers)
                try { await peer.DisposeAsync(); } catch (Exception error) { failures.Add(error); }
            if (failures.Count > 0) throw new AggregateException(failures);
        }
    }

    private enum NativeSchedule { Concurrent, Serialized, EarlyCompleted }

    private static async Task<Mutation[]> NativeOverlap(NativeCluster cluster, string[] ids,
        NativeSchedule schedule = NativeSchedule.Concurrent)
    {
        var leader = await cluster.Leader();
        var arrivals = new ConcurrentQueue<WireRequest>();
        var sends = new ConcurrentQueue<NativeExchange>();
        var responses = new ConcurrentQueue<byte[]>();
        var allPrepared = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var allRead = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var firstCompleted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseReplies = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var serial = new SemaphoreSlim(1);
        var pending = 0; var prepared = 0; var arrived = 0;
        async Task BeforeFinalByte(CancellationToken ct)
        {
            // Prepare all real mTLS sockets before releasing the last request
            // bytes together. There is no response-read gate, including here.
            if (Interlocked.Increment(ref prepared) == ids.Length) allPrepared.TrySetResult();
            await allPrepared.Task.WaitAsync(ct);
        }
        await using var gateway = new ClusterPeer(cluster.ServerCertificate, async (request, stream, ct) =>
        {
            if (request.Method != "PATCH")
            {
                await stream.WriteAsync(await cluster.Forward(leader, request, ct), ct);
                return;
            }
            var ordinal = Interlocked.Increment(ref arrived);
            arrivals.Enqueue(request);
            Interlocked.Increment(ref pending);
            if (schedule == NativeSchedule.Serialized) await serial.WaitAsync(ct);
            var serialReleased = false;
            try
            {
                // Negative control: buffer the first fully received native
                // receipt before admitting any other complete native request.
                if (schedule == NativeSchedule.EarlyCompleted && ordinal != 1)
                    await firstCompleted.Task.WaitAsync(ct);
                await using var exchange = await cluster.Send(leader, request, ct,
                    schedule == NativeSchedule.Concurrent ? BeforeFinalByte : null);
                sends.Enqueue(exchange);
                // Receive is already running. Read only obtains its immutable
                // framed bytes; neither this await nor reply delivery sets time.
                var wire = await exchange.Read(ct);
                responses.Enqueue(wire);
                if (ordinal == 1) firstCompleted.TrySetResult();
                if (responses.Count == ids.Length) allRead.TrySetResult();
                if (schedule == NativeSchedule.Serialized) { serial.Release(); serialReleased = true; }
                // This holds client receipts ONLY, after native frame timing.
                await releaseReplies.Task.WaitAsync(ct);
                await stream.WriteAsync(wire, ct);
            }
            finally
            {
                if (schedule == NativeSchedule.Serialized && !serialReleased) serial.Release();
                Interlocked.Decrement(ref pending);
            }
        });
        using var client = cluster.Client([new(gateway.Endpoint, leader + 1)]);
        using var cancellation = new CancellationTokenSource();
        var calls = ids.Select(id => client.PatchAsync("examples", "one", J("{\"$inc\":{\"n\":1}}"), new(RequestId: id), cancellation.Token)).ToArray();
        try
        {
            await allRead.Task.WaitAsync(TimeSpan.FromSeconds(12));
            Check(arrivals.Count == ids.Length && sends.Count == ids.Length && responses.Count == ids.Length
                && pending == ids.Length && calls.All(call => !call.IsCompleted));
            Check(arrivals.Select(request => request.Header("X-Yamora-Request-Id")).Order().SequenceEqual(ids.Order()));
            Check(arrivals.All(request => request.Body.SequenceEqual(arrivals.First().Body)));
            Check(responses.All(wire => System.Text.Encoding.ASCII.GetString(wire).StartsWith("HTTP/1.1 200 ", StringComparison.Ordinal)
                && WireJson(wire).GetProperty("status").GetString() == "stored"), "native overlap requires successful committed receipts");
            Check(sends.All(exchange => exchange.FullResponseAt >= exchange.SentAt));
            var lastSend = sends.Max(exchange => exchange.SentAt);
            var firstResponse = sends.Min(exchange => exchange.FullResponseAt);
            var completedBeforeLastSend = sends.Count(exchange => exchange.FullResponseAt <= lastSend);
            if (lastSend >= firstResponse)
                throw new NativeProbeFailure($"native intervals rejected {schedule}: client_arrivals={arrivals.Count}, sent={sends.Count}, full_native_responses={responses.Count}, completed_before_last_send={completedBeforeLastSend}, distinct_ids={ids.Distinct().Count()}");
            Console.WriteLine($"  native intervals: sent={sends.Count}, full_native_responses={responses.Count}, distinct_ids={ids.Distinct().Count()}, last_send={lastSend}, first_complete_frame={firstResponse}, overlap_us={(firstResponse - lastSend) * 1000000.0 / Stopwatch.Frequency:F1}");
            if (ids.Distinct().Count() == 1) Check(responses.All(response => response.SequenceEqual(responses.First())),
                "same-ID wire receipts differ: " + string.Join(" | ", responses.Select(System.Text.Encoding.UTF8.GetString)));
            releaseReplies.SetResult();
            return await Task.WhenAll(calls);
        }
        finally
        {
            releaseReplies.TrySetResult();
            cancellation.Cancel();
            try { await Task.WhenAll(calls); } catch { }
        }
    }
    private static async Task NativeFixtureGuards(string binary)
    {
        await using var cluster = await NativeCluster.Start(binary);
        using var client = cluster.Client();
        await client.PutAsync("examples", "one", "# guard\r\nn: 0\r\n"u8.ToArray());
        var early = await Throws<NativeProbeFailure>(() => LostReply(cluster, "# guard\r\nn: 1\r\n"u8.ToArray(), injectEarlyRetry: true));
        Check(early.Message.Contains("early=1", StringComparison.Ordinal)
            && early.Message.Contains("native_sends_before_assert=1", StringComparison.Ordinal));
        Console.WriteLine("  guard injection rejected: " + early.Message);
        foreach (var sameId in new[] { false, true })
        {
            var count = sameId ? 6 : 4;
            var id = Guid.NewGuid().ToString("N");
            var ids = Enumerable.Range(0, count).Select(_ => sameId ? id : Guid.NewGuid().ToString("N")).ToArray();
            foreach (var schedule in new[] { NativeSchedule.EarlyCompleted, NativeSchedule.Serialized })
            {
                var rejected = await Throws<NativeProbeFailure>(() => NativeOverlap(cluster, ids, schedule));
                Check(rejected.Message.Contains($"client_arrivals={count}, sent={count}, full_native_responses={count}", StringComparison.Ordinal)
                    && rejected.Message.Contains($"distinct_ids={(sameId ? 1 : count)}", StringComparison.Ordinal));
                Console.WriteLine("  guard injection rejected: " + rejected.Message);
            }
        }
    }

}
