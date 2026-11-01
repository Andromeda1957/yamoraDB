using System.Buffers.Binary;
using System.Text;
using System.Text.Json;

namespace Yamora;

internal static class BinaryOperationsCodec
{
    private static void Require(bool value) { if (!value) throw BinaryException.Protocol(); }
    internal static int Negotiate(BinaryWire.Frame hello, int local)
    {
        Require(hello.Type == BinaryWire.Hello && hello.Payload.Length == 12);
        var bytes = hello.Payload.AsSpan();
        var minimum = BinaryPrimitives.ReadUInt16BigEndian(bytes); var maximum = BinaryPrimitives.ReadUInt16BigEndian(bytes[2..]);
        var cap = BinaryPrimitives.ReadUInt32BigEndian(bytes[4..]); var streams = BinaryPrimitives.ReadUInt32BigEndian(bytes[8..]);
        Require(minimum >= 1 && maximum >= minimum && cap is >= 4096 and <= 1048576 && streams is >= 1 and <= 128);
        if (minimum > 2 || maximum < 2) throw new BinaryUnsupportedPeerException();
        return Math.Min(local, (int)cap);
    }
    internal static byte[] Request(BinaryOperation operation, string? bearer, int timeout)
    {
        static byte[] Number(ulong value, int n) { var bytes = new byte[n]; for (int i = n - 1; i >= 0; --i) { bytes[i] = (byte)value; value >>= 8; } return bytes; }
        var fields = new List<(int Id, byte[] Bytes)> {
            (1, [operation.Wire]), (2, Encoding.ASCII.GetBytes(operation.Target)), (3, Encoding.ASCII.GetBytes(operation.ContentType)),
            (4, Number((ulong)operation.OwnedSource.Length, 8)) };
        if (bearer is not null) fields.Add((5, Encoding.ASCII.GetBytes("Bearer " + bearer)));
        if (operation.IfMatch is not null) fields.Add((6, Encoding.ASCII.GetBytes(operation.IfMatch)));
        if (operation.IfNoneMatch is not null) fields.Add((7, Encoding.ASCII.GetBytes(operation.IfNoneMatch)));
        fields.Add((8, Convert.FromHexString(operation.RequestId))); fields.Add((9, Number((ulong)timeout, 4)));
        var result = new byte[4 + fields.Sum(field => field.Bytes.Length + 4)]; Require(result.Length <= 2048);
        BinaryPrimitives.WriteUInt16BigEndian(result, 2); BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(2), (ushort)fields.Count);
        int offset = 4;
        foreach (var (id, bytes) in fields) {
            BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(offset), (ushort)id); BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(offset + 2), (ushort)bytes.Length);
            bytes.CopyTo(result, offset + 4); offset += bytes.Length + 4;
        }
        return result;
    }
    internal static void Correlate(BinaryReply.Metadata meta, BinaryOperation operation, bool feed)
    {
        Require(meta.RequestId == operation.RequestId && meta.BodyLength == meta.RepresentationLength);
        Require(meta.Status >= 400 ? !meta.Streaming && meta.BodyLength <= 4096 : meta.Status == 200 && feed == meta.Streaming);
        Require(meta.Media.Split(';', 2)[0].Equals(meta.Streaming ? "application/x-ndjson" : "application/json", StringComparison.OrdinalIgnoreCase));
        Require(!operation.Mutation || meta.BodyLength <= 4096);
        if (operation.Method == "PATCH") { var parts = operation.Target.Split('/'); Require((meta.Collection is null || meta.Collection == parts[3]) && (meta.Document is null || meta.Document == parts[5])); }
        else Require(meta.Collection is null && meta.Document is null && meta.ETag is null);
    }
    private static void Walk(JsonElement value, ref int budget, BinaryCall call)
    {
        call.Check(); Require(--budget >= 0);
        if (value.ValueKind == JsonValueKind.Object) {
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var field in value.EnumerateObject()) { Require(seen.Add(field.Name)); Validation.Utf8.GetByteCount(field.Name); Walk(field.Value, ref budget, call); }
        } else if (value.ValueKind == JsonValueKind.Array) foreach (var item in value.EnumerateArray()) Walk(item, ref budget, call);
        else if (value.ValueKind == JsonValueKind.String) Validation.Utf8.GetByteCount(value.GetString()!);
        // Numbers remain raw JSON tokens; no conversion to floating point.
    }
    private static JsonDocument Json(byte[] raw, BinaryCall call, int maxDepth = 64)
    {
        BinaryReply.Utf8(raw, call);
        var document = JsonDocument.Parse(raw, new JsonDocumentOptions { MaxDepth = maxDepth });
        try { int nodes = 262144; Walk(document.RootElement, ref nodes, call); Require(document.RootElement.ValueKind == JsonValueKind.Object); return document; }
        catch { document.Dispose(); throw; }
    }
    private static string Text(JsonElement value, string name) => value.GetProperty(name).GetString() ?? throw BinaryException.Protocol();
    private static bool Token(string value) => value.Length == 52 && value.StartsWith("v1.", StringComparison.Ordinal) && value[35] == '.' && Validation.Hex(value[3..35], 32) && Validation.Hex(value[36..], 16);
    internal static string After(string target)
    {
        int query = target.IndexOf('?'); if (query < 0) return "";
        foreach (string pair in target[(query + 1)..].Split('&')) if (pair.StartsWith("after=", StringComparison.Ordinal)) return pair[6..]; return "";
    }
    internal static void Validate(BinaryReply.Metadata meta, byte[] raw, BinaryOperation operation, BinaryCall call)
    {
        try {
            // Native depth64 values gain query/facet envelope containers.
            using var json = Json(raw, call, 80); var p = json.RootElement;
            if (meta.Status >= 400) { var code = Text(p, "error"); Require(p.EnumerateObject().Count() == 1 && code.Length is > 0 and <= 128 && code.All(c => c is >= 'a' and <= 'z' or >= '0' and <= '9' or '_')); return; }
            Require(Text(p, "revision") == meta.Revision);
            if (operation.Method == "PATCH") { var parts = operation.Target.Split('/'); Require(p.EnumerateObject().Count() == 5 && Text(p, "status") == "stored" && Text(p, "collection") == parts[3] && Text(p, "document") == parts[5] && Validation.Hex(Text(p, "etag"), 16) && Text(p, "etag") == meta.ETag); }
            else if (operation.Mutation) {
                int count = p.GetProperty("operations").GetInt32();
                Require(p.EnumerateObject().Count() == 3 && Text(p, "status") == "committed" && count is >= 1 and <= 128);
                if (operation.ContentType.Split(';', 2)[0].Equals("application/json", StringComparison.OrdinalIgnoreCase)) {
                    using var specification = Json(operation.OwnedSource, call);
                    Require(specification.RootElement.GetProperty("operations").GetArrayLength() == count);
                }
            }
            else if (operation.Target.StartsWith("/v1/changes", StringComparison.Ordinal)) _ = Page(p, After(operation.Target));
            call.Check();
        } catch (Exception error) when (error is JsonException or InvalidOperationException or ArgumentException or KeyNotFoundException or OverflowException) { throw BinaryException.Protocol(); }
    }
    internal static (string After, bool Terminal) Page(byte[] raw, string after, BinaryCall call)
    {
        try { using var json = Json(raw, call, 80); return Page(json.RootElement, after); }
        catch (Exception error) when (error is JsonException or InvalidOperationException or ArgumentException or KeyNotFoundException or OverflowException) { throw BinaryException.Protocol(); }
    }
    private static (string After, bool Terminal) Page(JsonElement p, string after)
    {
        if (p.TryGetProperty("terminal", out var terminal)) {
            Require(p.EnumerateObject().Count() == 4 && terminal.ValueKind == JsonValueKind.True && p.GetProperty("status").GetInt32() is >= 400 and <= 599 && Text(p, "after") == after && p.GetProperty("detail").ValueKind == JsonValueKind.Object); return (after, true);
        }
        var next = Text(p, "next_after"); var tip = Text(p, "checkpoint"); var oldest = Text(p, "oldest_after");
        Require(Token(next) && Token(tip) && Token(oldest) && Validation.Hex(Text(p, "revision"), 16));
        Require(next[..36] == tip[..36] && oldest[..36] == tip[..36] && string.CompareOrdinal(oldest, next) <= 0 && string.CompareOrdinal(next, tip) <= 0 && p.GetProperty("has_more").GetBoolean() == (string.CompareOrdinal(next, tip) < 0));
        Require(after == "" || Token(after) && after[..36] == next[..36] && string.CompareOrdinal(after, next) <= 0);
        var transactions = p.GetProperty("transactions"); Require(transactions.ValueKind == JsonValueKind.Array && transactions.GetArrayLength() <= 100 && (after != "" || transactions.GetArrayLength() == 0));
        var previous = after; var revision = "";
        foreach (var tx in transactions.EnumerateArray()) {
            var cursor = Text(tx, "token"); var current = Text(tx, "revision"); var before = Text(tx, "previous_revision");
            Require(Token(cursor) && cursor[..36] == tip[..36] && string.CompareOrdinal(cursor, previous) > 0 && string.CompareOrdinal(cursor, tip) <= 0 && Validation.Hex(current, 16) && Validation.Hex(before, 16) && (revision == "" || revision == before));
            var operations = tx.GetProperty("operations"); Require(operations.ValueKind == JsonValueKind.Array && operations.GetArrayLength() <= 256 && (!tx.GetProperty("resnapshot_required").GetBoolean() || operations.GetArrayLength() == 0));
            var seen = new HashSet<string>(StringComparer.Ordinal); int sourceBytes = 0;
            foreach (var op in operations.EnumerateArray()) {
                var collection = Text(op, "collection"); Require(Validation.IsId(collection));
                bool hasDocument = op.TryGetProperty("document", out var document); var id = hasDocument ? document.GetString() : ""; Require(seen.Add(collection + "/" + id));
                if (!hasDocument) Require(op.EnumerateObject().Count() == 2 && op.GetProperty("create_collection").ValueKind == JsonValueKind.True);
                else { Require(Validation.IsId(id) && op.EnumerateObject().Count() == 3); bool put = op.TryGetProperty("put", out var source); bool deleted = op.TryGetProperty("delete", out var erased); Require(put != deleted);
                    if (put) { int bytes = Validation.Utf8.GetByteCount(source.GetString()!); Require(bytes > 0 && bytes <= BinaryClient.DocumentLimit - sourceBytes); sourceBytes += bytes; }
                    else Require(erased.ValueKind == JsonValueKind.True);
                }
            }
            previous = cursor; revision = current;
        }
        Require(transactions.GetArrayLength() == 0 ? !p.GetProperty("has_more").GetBoolean() && (after == "" || after == next) : previous == next);
        return (next, false);
    }
}
