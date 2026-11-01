using System.Buffers.Binary;
using System.Text;
using Yamora;

namespace DriverTests;

static partial class Program
{
    static async Task<BinaryUncertainException> BinaryRejected(Func<Task> action, BinaryServer server, string label)
    {
        try { await action(); }
        catch (BinaryUncertainException error)
        {
            Check(server.Requests.Count == 1 && server.Connections == 1, "hostile fixture dispatch missing: " + label); return error;
        }
        catch (BinaryException)
        {
            Check(server.Requests.Count == 1 && server.Connections == 1, "hostile fixture dispatch missing: " + label);
            throw new Exception("REGRESSION typed-uncertainty-" + label + ": lost original envelope after exactly one dispatch");
        }
        Check(server.Requests.Count == 1 && server.Connections == 1, "hostile fixture dispatch missing: " + label);
        throw new Exception("REGRESSION " + label + ": accepted invalid reply after exactly one dispatch");
    }
    static async Task BinaryHostileReceipts()
    {
        using var ca = new Certificates(); using var cert = ca.Issue();
        var faults = new Dictionary<string, Action<SortedDictionary<int, byte[]>>>
        {
            ["missing-id"] = f => f.Remove(12), ["wrong-id"] = f => f[12] = Enumerable.Repeat((byte)3, 16).ToArray(),
            ["zero-id"] = f => f[12] = new byte[16], ["short-id"] = f => f[12] = new byte[15],
            ["wrong-collection"] = f => f[7] = "other"u8.ToArray(), ["wrong-document"] = f => f[8] = "other"u8.ToArray(),
            ["revision-body-disagrees"] = f => f[5] = "fedcba9876543210"u8.ToArray(),
            ["etag-body-disagrees"] = f => f[6] = "\"fedcba9876543210\""u8.ToArray(),
            ["quoted-revision"] = f => f[5] = "\"0123456789abcdef\""u8.ToArray(),
            ["uppercase-etag"] = f => f[6] = "\"FEDCBA9876543210\""u8.ToArray(),
            ["missing-status"] = f => f.Remove(1), ["wrong-status-width"] = f => f[1] = [201],
            ["wrong-length-width"] = f => f[3] = [0], ["wrong-media"] = f => f[2] = "text/plain"u8.ToArray(),
            ["wrong-charset"] = f => f[2] = "application/json; charset=latin1"u8.ToArray(),
            ["body-too-large"] = f => { f[3] = BinaryFixtureWire.Num(16777217, 8); f[4] = f[3]; },
            ["ack-too-large"] = f => { f[3] = BinaryFixtureWire.Num(4097, 8); f[4] = f[3]; },
            ["length-disagreement"] = f => f[4] = BinaryFixtureWire.Num(1, 8),
            ["unknown-field"] = f => f[13] = [], ["unexpected-auth"] = f => f[10] = [1],
            ["unexpected-allow"] = f => f[9] = [1], ["unexpected-retry"] = f => f[11] = [0, 0, 0, 1],
            ["bad-name"] = f => f[7] = "a/b"u8.ToArray(), ["control-media"] = f => f[2] = "application/json\r\n"u8.ToArray(),
        };
        foreach (var (name, fault) in faults)
        {
            await using var server = new BinaryServer(cert, (s, r, ct) => BinaryFixtureWire.Reply(s, r, ct, change: fault));
            using var db = Binary(server.Endpoint, ca.Root);
            var error = await BinaryRejected(() => db.PutAsync("allowed", "one", "# é\r\nn: 01\r\n"u8.ToArray(), Native.WriteToken), server, name);
            Check(error.Kind == BinaryFailure.Protocol && server.Requests.Count == 1 && server.Connections == 1, "hostile receipt accepted: " + name);
        }
        foreach (var condition in new[] { "create", "match" })
        {
            await using var server = new BinaryServer(cert, (s, r, ct) => BinaryFixtureWire.Reply(s, r, ct, status: condition == "create" ? 200 : 201));
            using var db = Binary(server.Endpoint, ca.Root);
            await BinaryRejected(() => db.PutAsync("allowed", "one", "n: 1\n"u8.ToArray(), Native.WriteToken,
                ifMatch: condition == "match" ? "\"0123456789abcdef\"" : null, ifNoneMatch: condition == "create" ? "*" : null), server, "put-status-" + condition);
            Check(server.Requests.Count == 1, "wrong PUT success status accepted: " + condition);
        }
        var invalidJson = new[]
        {
            "[]", "{}", "{\"status\":\"stored\",\"status\":\"stored\"}", "{\"status\":1}",
            "{\"n\":1.0}", "{\"n\":1e0}", "{\"n\":18446744073709551616}", "{\"s\":\"\\ud800\"}",
            "{\"n\":" + new string('[', 33) + "1" + new string(']', 33) + "}",
            "{\"n\":[" + string.Join(',', Enumerable.Repeat("0", 1025)) + "]}",
        }.Select(Encoding.UTF8.GetBytes).Append(new byte[] { 0xff }).ToArray();
        foreach (var bytes in invalidJson)
        {
            await using var server = new BinaryServer(cert, (s, r, ct) => BinaryFixtureWire.Reply(s, r, ct, overrideBody: bytes));
            using var db = Binary(server.Endpoint, ca.Root);
            Check((await Throws<BinaryUncertainException>(() => db.PutAsync("allowed", "one", "n: 1\n"u8.ToArray()))).Kind == BinaryFailure.Protocol);
            Check(server.Requests.Count == 1);
        }
        // Fully self-consistent TLV + receipt still lies about the frozen source.
        await using (var server = new BinaryServer(cert, (s, r, ct) => BinaryFixtureWire.Reply(s, r, ct,
            overrideBody: BinaryFixtureWire.Receipt(r, "fedcba9876543210"), change: f => f[6] = "\"fedcba9876543210\""u8.ToArray())))
        using (var db = Binary(server.Endpoint, ca.Root))
        {
            await BinaryRejected(() => db.PutAsync("allowed", "one", "# frozen é\r\nn: 01\r\n"u8.ToArray()), server, "source-hash-lie");
            Check(server.Requests.Count == 1, "source hash lie accepted");
        }
        foreach (var fault in new[] { "hash", "utf8", "head-body", "head-tag", "unexpected-id", "missing-read-id" })
        {
            await using var server = new BinaryServer(cert, (s, r, ct) => BinaryFixtureWire.Reply(s, r, ct,
                source: fault == "utf8" ? [0xff] : null,
                overrideBody: fault == "head-body" ? "n: 1\n"u8.ToArray() : null,
                change: f =>
                {
                    if (fault == "hash") f[6] = "\"fedcba9876543210\""u8.ToArray();
                    if (fault == "head-tag") f.Remove(6);
                    if (fault == "unexpected-id") f[12] = Enumerable.Repeat((byte)4, 16).ToArray();
                    if (fault == "missing-read-id") f.Remove(12);
                }));
            using var db = Binary(server.Endpoint, ca.Root);
            Check((await Throws<BinaryException>(() => db.CallAsync(fault.StartsWith("head", StringComparison.Ordinal) ? BinaryMethod.Head : BinaryMethod.Get,
                "allowed", "one", requestId: fault == "missing-read-id" ? new string('1', 32) : null))).Kind == BinaryFailure.Protocol, "hostile read accepted: " + fault);
        }
    }
    static async Task BinaryHostileFrames()
    {
        using var ca = new Certificates(); using var cert = ca.Issue();
        foreach (var fault in new[] { "magic", "version", "flags", "stream", "even-stream", "oversize", "zero-data", "error", "goaway", "hello", "request", "pong", "end", "header-eof", "payload-eof", "no-end", "excess-data", "repeat-response", "tlv-duplicate", "tlv-order", "tlv-trailer", "tlv-schema" })
        {
            await using var server = new BinaryServer(cert, async (s, r, ct) =>
            {
                if (fault == "no-end") { await BinaryFixtureWire.Reply(s, r, ct, end: false); return; }
                if (fault == "excess-data")
                {
                    await BinaryFixtureWire.Reply(s, r, ct, end: false);
                    await s.WriteAsync(BinaryFixtureWire.Frame(4, [1]), ct); await s.WriteAsync(BinaryFixtureWire.Frame(5), ct); return;
                }
                var meta = BinaryFixtureWire.Tlv(BinaryFixtureWire.Metadata(r, BinaryFixtureWire.Receipt(r)));
                if (fault.StartsWith("tlv-", StringComparison.Ordinal))
                {
                    var fields = BinaryFixtureWire.Metadata(r, BinaryFixtureWire.Receipt(r)).ToList();
                    // Duplicate an identical optional field; removing only the
                    // uniqueness check must leave every semantic field valid.
                    if (fault == "tlv-duplicate")
                    {
                        fields.Add(fields[^1]); meta = BinaryFixtureWire.Tlv(fields);
                    }
                    // Reorder two complete fields without changing their IDs,
                    // values, widths or presence. Only wire order is invalid.
                    if (fault == "tlv-order")
                    {
                        (fields[6], fields[7]) = (fields[7], fields[6]); meta = BinaryFixtureWire.Tlv(fields);
                    }
                    if (fault == "tlv-trailer") meta = [.. meta, 0];
                    if (fault == "tlv-schema") meta[1] = 2;
                    await s.WriteAsync(BinaryFixtureWire.Frame(3, meta), ct);
                    await s.WriteAsync(BinaryFixtureWire.Frame(4, BinaryFixtureWire.Receipt(r)), ct);
                    await s.WriteAsync(BinaryFixtureWire.Frame(5), ct); return;
                }
                var bytes = fault switch
                {
                    "zero-data" => BinaryFixtureWire.Frame(4), "error" => BinaryFixtureWire.Frame(7, [0, 0, 0, 1]),
                    "goaway" => BinaryFixtureWire.Frame(10, stream: 0), "hello" => BinaryFixtureWire.Frame(1, new byte[12], 0),
                    "request" => BinaryFixtureWire.Frame(2, [1]), "pong" => BinaryFixtureWire.Frame(9, new byte[8], 0),
                    "end" => BinaryFixtureWire.Frame(5), _ => BinaryFixtureWire.Frame(3, meta),
                };
                if (fault == "magic") bytes[0] = 0;
                if (fault == "version") bytes[4] = 2;
                if (fault == "flags") bytes[7] = 1;
                if (fault == "stream") bytes[11] = 3;
                if (fault == "even-stream") bytes[11] = 2;
                if (fault == "oversize") BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(12), uint.MaxValue);
                if (fault == "header-eof") bytes = bytes[..5];
                if (fault == "payload-eof") bytes = bytes[..17];
                await s.WriteAsync(bytes, ct);
                if (fault == "repeat-response") await s.WriteAsync(bytes, ct);
                // Header guards are tested against an otherwise complete valid
                // receipt, never EOF masking removal of that single guard.
                if (fault is "magic" or "version" or "flags" or "stream" or "even-stream")
                {
                    await s.WriteAsync(BinaryFixtureWire.Frame(4, BinaryFixtureWire.Receipt(r)), ct);
                    await s.WriteAsync(BinaryFixtureWire.Frame(5), ct);
                }
            });
            using var db = Binary(server.Endpoint, ca.Root);
            var error = await BinaryRejected(() => db.PutAsync("allowed", "one", "n: 1\n"u8.ToArray(), Native.WriteToken), server, "frame-" + fault);
            Check(error.Kind == (fault is "header-eof" or "payload-eof" or "no-end" ? BinaryFailure.Transport : BinaryFailure.Protocol), "wrong framing rejection: " + fault);
        }
        foreach (var fault in new[] { "min", "max", "frame-small", "frame-large", "streams-zero", "streams-large", "duplicate" })
        {
            await using var server = new BinaryServer(cert, (_, _, _) => Task.CompletedTask, hello: async (s, ct) =>
            {
                byte[] bytes = [0, 1, 0, 1, 0, 0, 16, 0, 0, 0, 0, 1];
                if (fault == "min") bytes[1] = 0;
                if (fault == "max") bytes[3] = 0;
                if (fault == "frame-small") bytes[6] = 15;
                if (fault == "frame-large") bytes[4] = 1;
                if (fault == "streams-zero") bytes[11] = 0;
                if (fault == "streams-large") bytes[11] = 129;
                await s.WriteAsync(BinaryFixtureWire.Frame(1, bytes, 0), ct);
                if (fault == "duplicate") await s.WriteAsync(BinaryFixtureWire.Frame(1, bytes, 0), ct);
            });
            using var db = Binary(server.Endpoint, ca.Root);
            await Throws<BinaryException>(() => db.GetAsync("allowed", "one"));
            Check(server.Requests.Count == 0);
        }
        // Coalesced frames, byte fragmentation, a bounded correlated PING, and
        // UTF-8 split across DATA boundaries all remain valid.
        var source = Encoding.UTF8.GetBytes("# 雪😀\r\nn: 1\r\n");
        await using (var server = new BinaryServer(cert, async (s, r, ct) =>
        {
            await s.WriteAsync(BinaryFixtureWire.Frame(8, new byte[8], 0), ct);
            if ((await BinaryFixtureWire.Read(s, ct)).Type != 9) throw new Exception("PING not echoed");
            var response = BinaryFixtureWire.Frame(3, BinaryFixtureWire.Tlv(BinaryFixtureWire.Metadata(r, source)));
            foreach (var b in response) await s.WriteAsync(new byte[] { b }, ct);
            foreach (var b in source) await s.WriteAsync(BinaryFixtureWire.Frame(4, [b]), ct);
            await s.WriteAsync(BinaryFixtureWire.Frame(5), ct);
        }))
        using (var db = Binary(server.Endpoint, ca.Root)) Check((await db.GetAsync("allowed", "one")).Body.SequenceEqual(source));
    }
}
