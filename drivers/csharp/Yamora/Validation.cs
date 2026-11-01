using System.Text;
using System.Text.Json;

namespace Yamora;

internal static class Validation
{
    internal static readonly UTF8Encoding Utf8 = new(false, true);
    internal static void Require([System.Diagnostics.CodeAnalysis.DoesNotReturnIf(false)] bool condition, string message)
    {
        if (!condition) throw new ArgumentException("yamora: " + message);
    }
    internal static bool Hex(string? value, int length) => value is not null && value.Length == length
        && value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');
    internal static bool IsId(string? value) => value is not null && value.Length is >= 1 and <= 128
        && value.All(c => c is >= 'a' and <= 'z' or >= '0' and <= '9' or '-');
    internal static string Id(string value)
    {
        Require(IsId(value), "invalid identifier");
        return value;
    }
    internal static string? Revision(string? value)
    {
        Require(value is null || Hex(value, 16), "invalid revision or ETag");
        return value;
    }
    internal static void Token(string value) => Require(value is not null && (value.Length == 0
        || value.Length is >= 32 and <= 512 && value.All(c => c is >= '!' and <= '~')), "invalid credential");
    internal static string Job(string value)
    {
        Require(Hex(value, 32), "invalid index job ID");
        return value;
    }
    internal static string ChangeToken(string value)
    {
        Require(value is not null && value.Length == 52 && value.StartsWith("v1.", StringComparison.Ordinal)
            && value[35] == '.' && Hex(value[3..35], 32) && Hex(value[36..], 16), "invalid change token");
        return value;
    }
    internal static void Write(WriteOptions options, bool createAllowed)
    {
        Revision(options.ETag);
        Require(!options.CreateOnly || createAllowed && options.ETag is null, "conflicting write conditions");
        Require(options.RequestId is null || Hex(options.RequestId, 32) && options.RequestId.Any(c => c != '0'), "invalid request ID");
    }
    internal static void Yaml(ReadOnlySpan<byte> source)
    {
        Require(source.Length is > 0 and <= Client.DocumentLimit, "invalid YAML size");
        try { Utf8.GetCharCount(source); }
        catch (DecoderFallbackException) { throw new ArgumentException("yamora: invalid UTF-8 source"); }
    }
    internal static string DocumentPath(string collection, string document)
        => $"/v1/collections/{Id(collection)}/documents/{Id(document)}";

    internal static void Json(JsonElement value)
    {
        try
        {
            var budget = 100_000;
            Walk(value, 0, ref budget);
        }
        catch (Exception e) when (e is InvalidOperationException or EncoderFallbackException)
        { throw new ArgumentException("yamora: invalid JSON Unicode or value"); }
    }
    private static void Walk(JsonElement value, int depth, ref int budget)
    {
        Require(depth <= 64 && --budget >= 0, "JSON nesting or item limit exceeded");
        switch (value.ValueKind)
        {
            case JsonValueKind.Object:
                var seen = new HashSet<string>(StringComparer.Ordinal);
                foreach (var prop in value.EnumerateObject())
                {
                    Require(seen.Add(prop.Name), "duplicate JSON key");
                    Utf8.GetByteCount(prop.Name);
                    Walk(prop.Value, depth + 1, ref budget);
                }
                break;
            case JsonValueKind.Array:
                foreach (var item in value.EnumerateArray()) Walk(item, depth + 1, ref budget);
                break;
            case JsonValueKind.String:
                Utf8.GetByteCount(value.GetString()!);
                break;
            case JsonValueKind.Number:
            case JsonValueKind.True:
            case JsonValueKind.False:
            case JsonValueKind.Null:
                break;
            default: throw new ArgumentException("yamora: invalid JSON value");
        }
    }
    internal static void Object(JsonElement value)
        => Require(value.ValueKind == JsonValueKind.Object, "JSON object required");
}
