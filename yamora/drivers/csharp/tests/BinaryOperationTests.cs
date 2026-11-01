using System.Text;
using System.Text.Json;
using Yamora;

namespace DriverTests;

static partial class Program
{
    static async Task OperationReply(Stream stream, BinaryRequest request, CancellationToken ct, byte[] body,
        int mode = 0, bool end = true, Action<SortedDictionary<int, byte[]>>? change = null, int schema = 2)
    {
        var metadata = new SortedDictionary<int, byte[]> {
            [1] = BinaryFixtureWire.Num(200, 2),
            [2] = Encoding.ASCII.GetBytes(mode == 1 ? "application/x-ndjson" : "application/json"),
            [3] = BinaryFixtureWire.Num(mode == 1 ? 0 : (ulong)body.Length, 8),
            [4] = BinaryFixtureWire.Num(mode == 1 ? 0 : (ulong)body.Length, 8),
            [5] = "0123456789abcdef"u8.ToArray(), [12] = request.Fields[8], [13] = [(byte)mode],
        };
        change?.Invoke(metadata);
        var raw = BinaryFixtureWire.Tlv(metadata); raw[1] = (byte)schema;
        await stream.WriteAsync(BinaryFixtureWire.Frame(3, raw), ct);
        if (body.Length > 0) await stream.WriteAsync(BinaryFixtureWire.Frame(4, body), ct);
        if (end) await stream.WriteAsync(BinaryFixtureWire.Frame(5), ct);
    }
    static async Task BinaryOperationPeer()
    {
        using var ca = new Certificates(); using var cert = ca.Issue();
        await using var peer = new BinaryServer(cert, (s, r, ct) => OperationReply(s, r, ct, "{\"revision\":\"0123456789abcdef\",\"rows\":[]}"u8.ToArray()), schema: 2, minimum: 2);
        using var db = Binary(peer.Endpoint, ca.Root);
        try { Check((await db.OperationAsync("POST", "/v1/query/config", "application/json", "{}"u8.ToArray())).StatusCode == 200); }
        catch (BinaryException error) { throw new Exception("schema2-only peer rejected", error); }
    }
    static async Task BinaryOperationCount()
    {
        using var ca = new Certificates(); using var cert = ca.Issue();
        byte[] source = "{\"operations\":[{\"collection\":\"config\",\"document\":\"one\",\"put\":\"n: 1\\n\"}]}"u8.ToArray();
        await using var peer = new BinaryServer(cert, (s, r, ct) => OperationReply(s, r, ct, "{\"status\":\"committed\",\"operations\":2,\"revision\":\"0123456789abcdef\"}"u8.ToArray()), schema: 2);
        using var db = Binary(peer.Endpoint, ca.Root);
        var error = await Throws<BinaryOperationException>(() => db.OperationAsync("POST", "/v1/transactions", "application/json", source));
        Check(error.Kind == BinaryFailure.Protocol && error.Recovery is not null && error.Recovery.Source.SequenceEqual(source) && peer.Requests.Count == 1, "transaction count uncertainty lost");
    }
    static async Task BinaryOperations()
    {
        using var ca = new Certificates(); using var cert = ca.Issue();
        string mapping = "{\"deep\":" + string.Concat(Enumerable.Repeat("{\"n\":", 63)) + "{}" + new string('}', 64);
        foreach (string value in new[] { "{\"value\":" + new string('[', 64) + "0" + new string(']', 64) + "}", mapping, "{\"edge\":[" + mapping + "]}" }) {
            byte[] edge = Encoding.UTF8.GetBytes("{\"revision\":\"0123456789abcdef\",\"documents\":[" + value + "]}");
            await using var peer = new BinaryServer(cert, (s, r, ct) => OperationReply(s, r, ct, edge), schema: 2);
            using var db = Binary(peer.Endpoint, ca.Root);
            byte[]? actual = null;
            try { actual = (await db.OperationAsync("POST", "/v1/query/config", "application/json", "{}"u8.ToArray())).Body; }
            catch (BinaryException error) { Check(false, "native domain edge response was rejected: " + error.Kind); }
            Check(actual is not null && actual.SequenceEqual(edge), "deep response bytes changed");
        }
        foreach (string value in new[] { new string('[', 80) + "0" + new string(']', 80), "1,\"v\":2", "\"invalid\"" }) {
            byte[] invalid = Encoding.UTF8.GetBytes("{\"revision\":\"0123456789abcdef\",\"v\":" + value + "}");
            if (value == "\"invalid\"") invalid[^3] = 255;
            await using var peer = new BinaryServer(cert, (s, r, ct) => OperationReply(s, r, ct, invalid), schema: 2);
            using var db = Binary(peer.Endpoint, ca.Root);
            var error = await Throws<BinaryOperationException>(() => db.OperationAsync("POST", "/v1/query/config", "application/json", "{}"u8.ToArray()));
            Check(error.Kind == BinaryFailure.Protocol, "response JSON guard changed");
        }
        byte[] domain = Encoding.UTF8.GetBytes("{\"operations\":[{}],\"v\":" + new string('[', 64) + "0" + new string(']', 64) + "}");
        byte[] domainReceipt = "{\"status\":\"committed\",\"operations\":1,\"revision\":\"0123456789abcdef\"}"u8.ToArray();
        await using (var peer = new BinaryServer(cert, (s, r, ct) => OperationReply(s, r, ct, domainReceipt), schema: 2)) {
            using var db = Binary(peer.Endpoint, ca.Root);
            var error = await Throws<BinaryOperationException>(() => db.OperationAsync("POST", "/v1/transactions", "application/json", domain));
            Check(error.Kind == BinaryFailure.Protocol && error.Recovery is not null, "transaction domain depth changed");
        }
        var spec = "{\"filter\":{\"n\":9007199254740993}}"u8.ToArray();
        var body = "{\"revision\":\"0123456789abcdef\",\"rows\":[{\"n\":9007199254740993}]}"u8.ToArray();
        await using (var peer = new BinaryServer(cert, (s, r, ct) => OperationReply(s, r, ct, body), schema: 2)) {
            using var db = Binary(peer.Endpoint, ca.Root);
            var result = await db.OperationAsync("POST", "/v1/query/config", "application/json", spec);
            Check(result.Body.SequenceEqual(body), "operation changed numeric bytes");
            Check(peer.Requests.Single().Source.SequenceEqual(spec) && peer.Requests.Single().Method == 5, "operation raw specification");
        }
        var receipt = "{\"status\":\"stored\",\"collection\":\"config\",\"document\":\"one\",\"etag\":\"1111111111111111\",\"revision\":\"0123456789abcdef\"}"u8.ToArray();
        await using (var peer = new BinaryServer(cert, (s, r, ct) => OperationReply(s, r, ct, receipt, change: fields => {
            fields[6] = "\"1111111111111111\""u8.ToArray(); fields[7] = "config"u8.ToArray(); fields[8] = "one"u8.ToArray();
        }), schema: 2)) {
            using var db = Binary(peer.Endpoint, ca.Root);
            Check((await db.OperationAsync("PATCH", "/v1/collections/config/documents/one", "application/json", "{\"$inc\":{\"n\":1}}"u8.ToArray())).Body.SequenceEqual(receipt), "PATCH receipt source hash");
        }
        await using (var peer = new BinaryServer(cert, (_, _, _) => throw new Exception("unsupported peer dispatch"))) {
            using var db = Binary(peer.Endpoint, ca.Root);
            await Throws<BinaryUnsupportedPeerException>(() => db.OperationAsync("POST", "/v1/query/config", "application/json", spec));
            Check(peer.Requests.IsEmpty, "unsupported peer received REQUEST");
        }
        var tx = "{\"status\":\"committed\",\"operations\":1,\"revision\":\"0123456789abcdef\"}"u8.ToArray();
        var txSpec = "{\"operations\":[{\"collection\":\"config\",\"document\":\"one\",\"put\":\"n: 9007199254740993\\n\"}]}"u8.ToArray();
        foreach (var fault in new[] { "id", "mode", "schema" }) {
            await using var peer = new BinaryServer(cert, (s, r, ct) => OperationReply(s, r, ct, tx, schema: fault == "schema" ? 1 : 2, change: fields => {
                if (fault == "id") fields[12] = Enumerable.Repeat((byte)4, 16).ToArray();
                if (fault == "mode") fields[13] = [2];
            }), schema: 2);
            using var db = Binary(peer.Endpoint, ca.Root);
            var source = (byte[])txSpec.Clone(); var expected = (byte[])source.Clone();
            var error = await Throws<BinaryOperationException>(() => db.OperationAsync("POST", "/v1/transactions", "application/json", source, ifNoneMatch: "", requestId: new string('a', 32)));
            Check(error.Kind == BinaryFailure.Protocol && error.OutcomeMayBeCommitted && error.Recovery is not null && peer.Requests.Count == 1, "operation correlation accepted: " + fault);
            source[0] ^= 1; var owned = error.Recovery!; var copy = owned.Source; copy[0] ^= 1;
            Check(owned.Source.SequenceEqual(expected) && owned.Method == "POST" && owned.Target == "/v1/transactions" && owned.ContentType == "application/json" && owned.IfNoneMatch == "" && owned.RequestId == new string('a', 32), "operation envelope ownership");
        }
    }
    static async Task BinaryOperationFeeds()
    {
        using var ca = new Certificates(); using var cert = ca.Issue();
        var prefix = "v1." + new string('a', 32) + ".";
        var a = prefix + "0000000000000001"; var b = prefix + "0000000000000002"; var c = prefix + "0000000000000003";
        var page = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new {
            checkpoint = c, next_after = b, oldest_after = a, revision = "0123456789abcdef", has_more = true,
            transactions = new[] { new { token = b, revision = "0123456789abcdef", previous_revision = "1111111111111111", resnapshot_required = false,
                operations = new[] { new { collection = "config", document = "one", put = "n: 9007199254740993\n" } } } },
        }) + "\n");
        var terminal = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new { terminal = true, status = 503, after = b, detail = new { error = "unavailable" } }) + "\n");
        foreach (bool complete in new[] { true, false }) {
            var suffix = complete ? terminal : "{\"partial\":"u8.ToArray();
            await using var peer = new BinaryServer(cert, (s, r, ct) => OperationReply(s, r, ct, page.Concat(suffix).ToArray(), mode: 1, end: complete), schema: 2);
            using var db = Binary(peer.Endpoint, ca.Root); var pages = new List<byte[]>();
            ValueTask Consume(byte[] raw, CancellationToken ct) { pages.Add(raw); return ValueTask.CompletedTask; }
            if (complete) {
                BinaryFeedResult result;
                try { result = await db.FeedAsync("/v1/changes/stream?after=" + a, Consume); }
                catch (BinaryOperationException error) { throw new Exception("feed used checkpoint instead of next_after", error); }
                Check(result.LastAfter == b && pages.Count == 2 && pages[1].SequenceEqual(terminal), "feed used checkpoint instead of next_after");
            } else {
                var error = await Throws<BinaryOperationException>(() => db.FeedAsync("/v1/changes/stream?after=" + a, Consume));
                Check(error.LastAfter == b && error.Recovery is null && error.Response is not null && pages.Count == 1, "partial page advanced cursor");
            }
            Check(pages[0].SequenceEqual(page), "feed changed raw page");
        }
        await using (var peer = new BinaryServer(cert, (s, r, ct) => OperationReply(s, r, ct, page.Concat(terminal).ToArray(), mode: 1), schema: 2)) {
            using var db = Binary(peer.Endpoint, ca.Root); using var cancel = new CancellationTokenSource(); var count = 0;
            var error = await Throws<BinaryOperationException>(() => db.FeedAsync("/v1/changes/stream?after=" + a, (raw, ct) => {
                count++; cancel.Cancel(); return ValueTask.CompletedTask;
            }, ct: cancel.Token));
            Check(error.Kind == BinaryFailure.Canceled && error.LastAfter == b && count == 1, "feed cancellation lost completed page");
        }
    }
}
