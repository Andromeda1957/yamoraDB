using System.Buffers.Binary;
using System.Text;
using System.Text.Json;
using System.Net.Http.Headers;

namespace Yamora;

internal static class BinaryReply
{
    internal sealed record Metadata(int Status, string Media, int BodyLength, int RepresentationLength,
        string Revision, string? ETag, string? Collection, string? Document, string? RequestId, bool Streaming = false);
    internal static Metadata Parse(byte[] payload, BinaryEnvelope envelope)
        => ParseCore(payload, envelope, null, false);
    internal static Metadata ParseOperation(byte[] payload, BinaryOperation operation, bool feed)
        => ParseCore(payload, null, operation, feed);
    private static Metadata ParseCore(byte[] payload, BinaryEnvelope? envelope, BinaryOperation? operation, bool feed)
    {
        var schema = operation is null ? 1 : 2;
        if (payload.Length is < 4 or > 2048 || BinaryPrimitives.ReadUInt16BigEndian(payload) != schema) throw BinaryException.Protocol();
        var count = BinaryPrimitives.ReadUInt16BigEndian(payload.AsSpan(2));
        if (count < 5 || count > (schema == 2 ? 13 : 12)) throw BinaryException.Protocol();
        var fields = new byte[14][]; var previous = 0; var offset = 4;
        for (var i = 0; i < count; i++)
        {
            if (payload.Length - offset < 4) throw BinaryException.Protocol();
            var id = BinaryPrimitives.ReadUInt16BigEndian(payload.AsSpan(offset));
            var size = BinaryPrimitives.ReadUInt16BigEndian(payload.AsSpan(offset + 2)); offset += 4;
            if (id <= previous || id > (schema == 2 ? 13 : 12) || size > payload.Length - offset) throw BinaryException.Protocol();
            fields[id] = payload.AsSpan(offset, size).ToArray(); offset += size; previous = id;
        }
        if (offset != payload.Length) throw BinaryException.Protocol();
        for (var id = 1; id <= 5; id++) if (fields[id] is null) throw BinaryException.Protocol();
        var status = (int)Integer(fields[1], 2); var media = Text(fields[2], 1, 95);
        var body = Integer(fields[3], 8); var representation = Integer(fields[4], 8);
        var revision = Text(fields[5], 16, 16);
        if (status is < 200 or > 599 || !Validation.Hex(revision, 16) || body > BinaryClient.DocumentLimit || representation > BinaryClient.DocumentLimit
            || body != 0 && body != representation || status == 204 && (body != 0 || representation != 0) || status == 304 && body != 0) throw BinaryException.Protocol();
        string? etag = null;
        if (fields[6] is { } tag)
        {
            var text = Text(tag, 18, 18);
            if (text[0] != '"' || text[^1] != '"' || !Validation.Hex(text[1..^1], 16)) throw BinaryException.Protocol();
            etag = text[1..^1];
        }
        var collection = Name(fields[7]); var document = Name(fields[8]);
        if (fields[9] is { } allow && (Integer(allow, 1) < 1 || Integer(allow, 1) > (schema == 2 ? 63UL : 15UL) || status != 405)
            || fields[10] is { } auth && (Integer(auth, 1) != 1 || status != 401)
            || status == 401 && fields[10] is null || status == 405 && fields[9] is null
            || fields[11] is { } retry && (Integer(retry, 4) > uint.MaxValue || status is not (429 or 503))) throw BinaryException.Protocol();
        string? requestId = null;
        if (fields[12] is { } request)
        {
            if (request.Length != 16 || request.All(b => b == 0)) throw BinaryException.Protocol();
            requestId = Convert.ToHexStringLower(request);
        }
        if (operation is not null)
        {
            if (fields[13] is not { } mode) throw BinaryException.Protocol();
            var streaming = Integer(mode, 1);
            var metadata = new Metadata(status, media, (int)body, (int)representation, revision, etag, collection, document, requestId, streaming == 1);
            if (streaming > 1 || streaming == 1 && (status != 200 || body != 0 || representation != 0)) throw BinaryException.Protocol();
            BinaryOperationsCodec.Correlate(metadata, operation, feed);
            return metadata;
        }
        if (envelope is null) throw BinaryException.Protocol();
        if (requestId != envelope.RequestId || collection is not null && collection != envelope.Collection || document is not null && document != envelope.Document
            || (envelope.Method == BinaryMethod.Head ? body != 0 : body != representation)
            || status == 204 && etag is not null
            || (envelope.Mutation || status >= 400) && representation > 4096) throw BinaryException.Protocol();
        if (status < 400 && !(envelope.Method switch
        {
            BinaryMethod.Get or BinaryMethod.Head => status == 200,
            BinaryMethod.Put => envelope.IfNoneMatch == "*" ? status == 201 : envelope.IfMatch is not null ? status == 200 : status is 200 or 201,
            BinaryMethod.Delete => status == 204,
            _ => false,
        })) throw BinaryException.Protocol();
        if (!MediaTypeHeaderValue.TryParse(media, out var parsed) || parsed.CharSet is not null && !parsed.CharSet.Trim('"').Equals("utf-8", StringComparison.OrdinalIgnoreCase)) throw BinaryException.Protocol();
        var yaml = status == 200 && envelope.Method is BinaryMethod.Get or BinaryMethod.Head;
        if (yaml ? !(parsed.MediaType?.Equals("application/yaml", StringComparison.OrdinalIgnoreCase) == true || parsed.MediaType?.Equals("text/yaml", StringComparison.OrdinalIgnoreCase) == true)
            || etag is null || collection != envelope.Collection || document != envelope.Document
            : parsed.MediaType?.Equals("application/json", StringComparison.OrdinalIgnoreCase) != true) throw BinaryException.Protocol();
        return new Metadata(status, media, (int)body, (int)representation, revision, etag, collection, document, requestId);
    }
    private static ulong Integer(byte[] bytes, int width)
    {
        if (bytes.Length != width) throw BinaryException.Protocol();
        ulong number = 0; foreach (var b in bytes) number = number << 8 | b; return number;
    }
    private static string Text(byte[] bytes, int min, int max)
    {
        if (bytes.Length < min || bytes.Length > max || bytes.Any(b => b is < 32 or > 126)) throw BinaryException.Protocol();
        return Encoding.ASCII.GetString(bytes);
    }
    private static string? Name(byte[]? bytes)
    {
        if (bytes is null) return null;
        var name = Text(bytes, 1, 128); if (!Validation.IsId(name)) throw BinaryException.Protocol(); return name;
    }
    internal static void Utf8(byte[] bytes, BinaryCall call)
    {
        // Stateful decoder preserves multibyte characters across the cooperative chunks.
        var decoder = Validation.Utf8.GetDecoder();
        // A scalar pending from the previous chunk can add two UTF-16 code
        // units to this chunk's otherwise all-ASCII output.
        var characters = new char[4098];
        try
        {
            for (var offset = 0; offset < bytes.Length; offset += 4096)
            {
                call.Check(); var length = Math.Min(4096, bytes.Length - offset);
                decoder.Convert(bytes.AsSpan(offset, length), characters, offset + length == bytes.Length,
                    out var consumed, out _, out var complete);
                if (consumed != length || !complete) throw BinaryException.Protocol();
            }
        }
        catch (DecoderFallbackException) { throw BinaryException.Protocol(); }
        call.Check();
    }
    internal static string Hash(byte[] bytes, BinaryCall call)
    {
        using var activity = BinaryClient.Diagnostics.StartActivity("Yamora.BinaryHash");
        // This is the native engine's seed, deliberately not the standard FNV-1a seed.
        ulong value = 1469598103934665603;
        for (var offset = 0; offset < bytes.Length; offset += 4096)
        {
            call.Check(); var end = Math.Min(offset + 4096, bytes.Length);
            for (var i = offset; i < end; i++) value = unchecked((value ^ bytes[i]) * 1099511628211);
        }
        call.Check(); return value.ToString("x16", System.Globalization.CultureInfo.InvariantCulture);
    }
    internal static void Validate(Metadata meta, byte[] body, BinaryEnvelope envelope, BinaryCall call)
    {
        using var activity = BinaryClient.Diagnostics.StartActivity("Yamora.BinaryDecode");
        call.Check();
        if (meta.Status == 200 && envelope.Method == BinaryMethod.Get)
        {
            Utf8(body, call);
            if (Hash(body, call) != meta.ETag) throw BinaryException.Protocol();
            return;
        }
        if (envelope.Method == BinaryMethod.Head || meta.Status == 204) return;
        Utf8(body, call);
        try
        {
            using var json = JsonDocument.Parse(body, new JsonDocumentOptions { MaxDepth = 32 });
            var budget = 1024; Walk(json.RootElement, 0, ref budget, call);
            var value = json.RootElement;
            if (value.ValueKind != JsonValueKind.Object) throw BinaryException.Protocol();
            static string? Str(JsonElement obj, string name) => obj.TryGetProperty(name, out var p) && p.ValueKind == JsonValueKind.String ? p.GetString() : null;
            var keys = value.EnumerateObject().Count();
            if (meta.Status >= 400)
            {
                var error = Str(value, "error");
                if (keys != 1 || error is null || error.Length is < 1 or > 128 || !error.All(c => c is >= 'a' and <= 'z' or >= '0' and <= '9' or '_')) throw BinaryException.Protocol();
            }
            else if (envelope.Method != BinaryMethod.Put || keys != 5 || Str(value, "status") != "stored"
                || Str(value, "collection") != envelope.Collection || Str(value, "document") != envelope.Document
                || Str(value, "revision") != meta.Revision || meta.ETag is null || Str(value, "etag") != meta.ETag
                || Hash(envelope.OwnedSource, call) != meta.ETag) throw BinaryException.Protocol();
        }
        catch (Exception e) when (e is JsonException or InvalidOperationException or ArgumentException) { throw BinaryException.Protocol(); }
        call.Check();
    }
    private static void Walk(JsonElement value, int depth, ref int budget, BinaryCall call)
    {
        call.Check(); if (depth > 32 || --budget < 0) throw BinaryException.Protocol();
        switch (value.ValueKind)
        {
            case JsonValueKind.Object:
                var seen = new HashSet<string>(StringComparer.Ordinal);
                foreach (var field in value.EnumerateObject())
                {
                    if (!seen.Add(field.Name)) throw BinaryException.Protocol();
                    Validation.Utf8.GetByteCount(field.Name); Walk(field.Value, depth + 1, ref budget, call);
                }
                break;
            case JsonValueKind.Array:
                foreach (var element in value.EnumerateArray()) Walk(element, depth + 1, ref budget, call);
                break;
            case JsonValueKind.String: Validation.Utf8.GetByteCount(value.GetString()!); break;
            case JsonValueKind.Number:
                if (!value.TryGetInt64(out _) && !value.TryGetUInt64(out _)) throw BinaryException.Protocol();
                break;
            case JsonValueKind.True or JsonValueKind.False or JsonValueKind.Null: break;
            default: throw BinaryException.Protocol();
        }
    }
}
