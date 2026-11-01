using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Yamora;

namespace DriverTests;

static partial class Program
{
    internal const string ClusterIdentityValue = ClusterId;
    static JsonElement WireJson(byte[] wire)
    {
        var text = Encoding.UTF8.GetString(wire); return J(text[(text.IndexOf("\r\n\r\n", StringComparison.Ordinal) + 4)..]);
    }
    static async Task NativeReplicaSet(string binary)
    {
        await using var cluster = await NativeCluster.Start(binary);
        using var client = cluster.Client();
        const string source = "# authored café\r\nname: 'Alpha'\r\nn: 0 # retain\r\nwide: 9223372036854775807\r\n";
        var yaml = Encoding.UTF8.GetBytes(source);
        var original = await client.PutAsync("examples", "one", yaml, new(CreateOnly: true, RequestId: new string('1', 32)));
        Check((await client.GetAsync("examples", "one")).Source.SequenceEqual(yaml));
        Check((await client.QueryAsync("examples", J("{}"))).Value.GetProperty("documents")[0].GetProperty("value").GetProperty("wide").GetInt64() == long.MaxValue);
        var rejected = await Throws<HttpError>(() => client.PatchAsync("examples", "one", J("{\"$inc\":{\"n\":1}}"), new(new string('0', 16))));
        Check((int)rejected.StatusCode == 412 && !rejected.OutcomeMayBeCommitted);
        var leader = await cluster.Leader();
        using (var noIdentity = cluster.Direct(leader, false)) await Throws<YamoraException>(() => noIdentity.ClusterStatusAsync());
        var expected = Encoding.UTF8.GetBytes(source.Replace("n: 0", "n: 1", StringComparison.Ordinal));
        var loss = await LostReply(cluster, expected);
        var recovered = loss.Recovered;
        var id = loss.RequestId;
        var saved = WireJson(loss.OriginalWire);
        Check(recovered.Revision == saved.GetProperty("revision").GetString() && recovered.ETag == saved.GetProperty("etag").GetString());
        Check(id.Length == 32 && id.Any(c => c != '0'));
        Check(await client.PatchAsync("examples", "one", J("{\"$inc\":{\"n\":1}}"), new(RequestId: id)) == recovered);
        Check((await client.GetAsync("examples", "one")).Source.SequenceEqual(expected));
        await cluster.StartNode(loss.OldLeader);
        var overlapping = await NativeOverlap(cluster, Enumerable.Repeat(new string('2', 32), 6).ToArray());
        Check(overlapping.All(receipt => receipt == overlapping[0]));
        var distinctIds = Enumerable.Range(3, 4).Select(i => i.ToString("x").PadLeft(32, '0')).ToArray();
        var independent = await NativeOverlap(cluster, distinctIds);
        Check(independent.Select(receipt => receipt.Revision).Distinct().Count() == 4);
        expected = Encoding.UTF8.GetBytes(source.Replace("n: 0", "n: 6", StringComparison.Ordinal));
        Check((await client.GetAsync("examples", "one")).Source.SequenceEqual(expected));
        var transaction = J("{\"operations\":[{\"collection\":\"examples\",\"document\":\"tx\",\"put\":\"# tx\\r\\nn: 9007199254740993\\r\\n\",\"create_only\":true}]}");
        var tx = await client.TransactionAsync(transaction, new string('7', 32));
        var catalog = J("{\"indexes\":[{\"collection\":\"examples\",\"name\":\"n\",\"fields\":[\"n\"]}]}");
        var indexes = await client.SetIndexesAsync(catalog, requestId: new string('8', 32));
        var deleted = await client.DeleteAsync("examples", "tx", new(RequestId: new string('9', 32)));
        await client.PutAsync("examples", "tx", "n: 10\n"u8.ToArray());
        var current = await cluster.Leader();
        using var quorumClient = cluster.Client();
        await quorumClient.GetAsync("examples", "one");
        for (var i = 0; i < 3; i++) if (i != current) await cluster.StopNode(i);
        var watch = Stopwatch.StartNew();
        using var quorumDeadline = new CancellationTokenSource(TimeSpan.FromMilliseconds(350));
        var quorum = await Throws<RequestCanceled>(() => quorumClient.PutAsync("examples", "quorum", "n: 99\n"u8.ToArray(),
            new(CreateOnly: true, RequestId: new string('a', 32)), quorumDeadline.Token));
        Check(watch.Elapsed < TimeSpan.FromSeconds(2) && !quorum.OutcomeMayBeCommitted, "quorum-bound discovery dispatched a mutation");
        await cluster.StopNode(current); for (var i = 0; i < 3; i++) await cluster.StartNode(i); await cluster.Leader();
        using var restarted = cluster.Client();
        Check((await restarted.GetAsync("examples", "one")).Source.SequenceEqual(expected));
        Check(await restarted.PutAsync("examples", "one", yaml, new(CreateOnly: true, RequestId: new string('1', 32))) == original);
        Check(await restarted.PatchAsync("examples", "one", J("{\"$inc\":{\"n\":1}}"), new(RequestId: id)) == recovered);
        Check(await restarted.PatchAsync("examples", "one", J("{\"$inc\":{\"n\":1}}"), new(RequestId: new string('2', 32))) == overlapping[0]);
        Check((await restarted.TransactionAsync(transaction, new string('7', 32))).Value.GetRawText() == tx.Value.GetRawText());
        Check((await restarted.SetIndexesAsync(catalog, requestId: new string('8', 32))).Value.GetRawText() == indexes.Value.GetRawText());
        Check(await restarted.DeleteAsync("examples", "tx", new(RequestId: new string('9', 32))) == deleted);
        Check((await restarted.GetAsync("examples", "tx")).Source.SequenceEqual("n: 10\n"u8.ToArray()));
        Check((await restarted.GetAsync("examples", "one")).Source.SequenceEqual(expected));
        await restarted.PutAsync("examples", "quorum", "n: 99\n"u8.ToArray(), new(CreateOnly: true, RequestId: new string('a', 32)));
    }

    static async Task NativeReceiptRecovery(string binary)
    {
        await using var cluster = await NativeCluster.Start(binary);
        var leader = await cluster.Leader();
        var corrupt = true; var requests = new ConcurrentQueue<WireRequest>(); byte[]? saved = null;
        await using var gateway = new ClusterPeer(cluster.ServerCertificate, async (r, s, ct) =>
        {
            var response = await cluster.Forward(leader, r, ct);
            if (r.Method is "PUT" or "PATCH" or "DELETE" || r.Method == "POST" && r.Path == "/v1/transactions")
            {
                requests.Enqueue(r); saved ??= response;
                if (corrupt) { await Server.Bytes(s, Reply("{bad")); return; }
            }
            await s.WriteAsync(response, ct);
        });
        using var client = cluster.Client([new(gateway.Endpoint, leader + 1)]);
        foreach (var kind in new[] { "put", "transaction", "catalog" })
        {
            requests.Clear(); saved = null; corrupt = true;
            Task Run() => kind switch
            {
                "put" => client.PutAsync("examples", "one", "# exact é\r\nn: 9007199254740993\r\n"u8.ToArray(), new(CreateOnly: true)),
                "transaction" => client.TransactionAsync(J("{\"operations\":[{\"collection\":\"examples\",\"document\":\"tx\",\"put\":\"n: 7\\n\",\"create_only\":true}]}")),
                _ => client.SetIndexesAsync(J("{\"indexes\":[]}")),
            };
            var error = await Throws<UncertainWriteException>(Run);
            Check(requests.Count == 1 && error.RequestId == requests.Single().Header("X-Yamora-Request-Id"));
            corrupt = false; var recovered = await client.RecoverAsync(error.Recovery);
            Check(recovered.Body.SequenceEqual(Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(saved!)[(Encoding.UTF8.GetString(saved!).IndexOf("\r\n\r\n", StringComparison.Ordinal) + 4)..])));
            Check(requests.Count == 2 && requests.All(r => r.Body.SequenceEqual(requests.First().Body) && r.Header("X-Yamora-Request-Id") == error.RequestId));
        }
        Check((await client.GetAsync("examples", "one")).Source.SequenceEqual("# exact é\r\nn: 9007199254740993\r\n"u8.ToArray()));
    }
}
