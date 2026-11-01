using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace HttpReplica;

sealed class InvalidInput : Exception { }

// Input and artifact boundaries only; HTTP and retry policy belong to the SDK.
sealed class Protocol(string root)
{
    internal const int LineLimit = 16384, FileLimit = 131072;
    internal static readonly UTF8Encoding Utf8 = new(false, true);
    internal static void Need(bool valid) { if (!valid) throw new InvalidInput(); }
    internal static void Keys(JsonElement value, params string[] keys)
    {
        Need(value.ValueKind == JsonValueKind.Object);
        Need(value.EnumerateObject().Select(p => p.Name).Order().SequenceEqual(keys.Order()));
    }
    internal static bool Match(string value, string pattern) => Regex.IsMatch(value, "\\A(?:" + pattern + ")\\z", RegexOptions.CultureInvariant);
    internal static string Text(JsonElement value)
    { Need(value.ValueKind == JsonValueKind.String); return value.GetString()!; }
    internal static string? NullableText(JsonElement value) => value.ValueKind == JsonValueKind.Null ? null : Text(value);
    internal static int Integer(JsonElement value)
    { Need(value.ValueKind == JsonValueKind.Number && Match(value.GetRawText(), "[0-9]+") && value.TryGetInt32(out _)); return value.GetInt32(); }
    internal static JsonDocument Json(byte[] bytes)
    {
        Utf8.GetCharCount(bytes);
        var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 12 });
        try { CheckJson(document.RootElement); return document; }
        catch { document.Dispose(); throw; }
    }
    private static void CheckJson(JsonElement value)
    {
        if (value.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in value.EnumerateObject()) { Need(names.Add(property.Name)); CheckJson(property.Value); }
        }
        else if (value.ValueKind == JsonValueKind.Array) { foreach (var item in value.EnumerateArray()) CheckJson(item); }
        else if (value.ValueKind == JsonValueKind.Number) { Need(value.TryGetDouble(out var number) && double.IsFinite(number)); }
    }
    internal static void NoLinks(string path, bool directory)
    {
        Need(Path.IsPathFullyQualified(path) && Path.GetFullPath(path) == path && !path.Contains('\0'));
        var parts = path.Split(Path.DirectorySeparatorChar);
        Need(parts.Skip(1).All(p => p.Length > 0 && p != "." && p != ".."));
        var current = Path.GetPathRoot(path)!;
        foreach (var part in parts.Skip(1))
        {
            current = Path.Combine(current, part);
            Need(new FileInfo(current).LinkTarget is null && new DirectoryInfo(current).LinkTarget is null);
        }
        var attributes = File.GetAttributes(path);
        Need(!attributes.HasFlag(FileAttributes.ReparsePoint) && attributes.HasFlag(FileAttributes.Directory) == directory);
        if (!directory)
        {
            // File.GetAttributes also accepts Unix FIFOs/devices. The session
            // root is runner owned; reject nonregular Unix files before open.
            Need(!attributes.HasFlag(FileAttributes.Device));
            if (OperatingSystem.IsLinux()) Need(UnixRegular(path));
        }
    }
    // statx avoids opening a FIFO while validating a Linux fixture path.
    [System.Runtime.InteropServices.DllImport("libc", SetLastError = true)]
    private static extern int statx(int dirfd, string path, int flags, uint mask, byte[] buffer);
    private static bool UnixRegular(string path)
    {
        var buffer = new byte[256];
        return statx(-100, path, 0x100, 2, buffer) == 0 && (BitConverter.ToUInt16(buffer, 28) & 0xf000) == 0x8000;
    }
    internal byte[] Read(string relative, int limit = FileLimit)
    {
        var path = root + "/" + relative; NoLinks(path, false);
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        Need(stream.Length <= limit);
        using var output = new MemoryStream();
        var buffer = new byte[4096];
        while (output.Length <= limit)
        {
            var count = stream.Read(buffer, 0, (int)Math.Min(buffer.Length, limit + 1L - output.Length));
            if (count == 0) break;
            output.Write(buffer, 0, count);
        }
        Need(output.Length <= limit); return output.ToArray();
    }
    internal string Write(int seq, string name, byte[] bytes)
    {
        Need(bytes.Length <= FileLimit);
        var dir = $"call-{seq:D6}"; NoLinks(root + "/" + dir, true);
        var relative = dir + "/" + name + ".bin";
        using var stream = new FileStream(root + "/" + relative, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        stream.Write(bytes); return relative;
    }
    internal static byte[] Line(Stream input)
    {
        using var line = new MemoryStream();
        while (line.Length < LineLimit)
        {
            var b = input.ReadByte(); Need(b >= 0 && b != 13); line.WriteByte((byte)b);
            if (b == 10) return line.ToArray();
        }
        throw new InvalidInput();
    }
}
