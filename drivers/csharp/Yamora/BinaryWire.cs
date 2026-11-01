using System.Buffers.Binary;
using System.Text;

namespace Yamora;

internal static class BinaryWire
{
    internal const byte Hello = 1, Request = 2, Response = 3, Data = 4, End = 5,
        Cancel = 6, Error = 7, Ping = 8, Pong = 9, GoAway = 10;
    internal sealed record Frame(byte Type, uint Stream, byte[] Payload);
    internal static void AsciiInput(string? value, int minimum, int maximum)
        => Validation.Require(value is null || value.Length >= minimum && value.Length <= maximum && value.All(c => c is >= ' ' and <= '~'), "invalid binary text");
    internal static void Bearer(string? value)
        => Validation.Require(value is null || value.Length is > 0 and <= 512 && value.All(c => c is >= '!' and <= '~'), "invalid binary bearer");

    private static void Shape(byte type, uint stream, uint size, int cap)
    {
        if (size > cap || cap is < 4096 or > 65536 || type is < Hello or > GoAway) throw BinaryException.Protocol();
        var control = type is Hello or Ping or Pong or GoAway;
        if (control ? stream != 0 : stream != 1) throw BinaryException.Protocol();
        if (!(type switch
        {
            Hello => size == 12,
            Request or Response => size is > 0 and <= 2048,
            Data => size > 0,
            End or Cancel or GoAway => size == 0,
            Error => size == 4,
            Ping or Pong => size == 8,
            _ => false,
        })) throw BinaryException.Protocol();
    }
    internal static async Task<Frame> Read(Stream stream, int cap, BinaryCall call)
    {
        var header = new byte[16];
        await Exact(stream, header, call).ConfigureAwait(false);
        if (!header.AsSpan(0, 4).SequenceEqual("YMBF"u8) || header[4] != 1 || header[6] != 0 || header[7] != 0) throw BinaryException.Protocol();
        var type = header[5]; var id = BinaryPrimitives.ReadUInt32BigEndian(header.AsSpan(8));
        var size = BinaryPrimitives.ReadUInt32BigEndian(header.AsSpan(12));
        // Reject the advertised length and direction before any payload allocation.
        Shape(type, id, size, cap);
        if (type is Request or Cancel or Pong) throw BinaryException.Protocol();
        var payload = new byte[(int)size];
        await Exact(stream, payload, call).ConfigureAwait(false);
        if (type == Error && BinaryPrimitives.ReadUInt32BigEndian(payload) == 0) throw BinaryException.Protocol();
        return new Frame(type, id, payload);
    }
    private static async Task Exact(Stream stream, Memory<byte> bytes, BinaryCall call)
    {
        while (bytes.Length > 0)
        {
            call.Check();
            var count = await stream.ReadAsync(bytes, call.Token).ConfigureAwait(false);
            call.Check();
            if (count == 0) throw new BinaryException(BinaryFailure.Transport);
            bytes = bytes[count..];
        }
    }
    internal static async Task Write(Stream stream, byte type, uint id, ReadOnlyMemory<byte> payload, int cap, BinaryCall call)
    {
        call.Check(); Shape(type, id, (uint)payload.Length, cap);
        var header = new byte[16]; "YMBF"u8.CopyTo(header); header[4] = 1; header[5] = type;
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(8), id);
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(12), (uint)payload.Length);
        await stream.WriteAsync(header, call.Token).ConfigureAwait(false);
        if (!payload.IsEmpty) await stream.WriteAsync(payload, call.Token).ConfigureAwait(false);
        call.Check();
    }
    internal static byte[] HelloPayload(int cap)
    {
        var payload = new byte[12];
        BinaryPrimitives.WriteUInt16BigEndian(payload, 1); BinaryPrimitives.WriteUInt16BigEndian(payload.AsSpan(2), 1);
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(4), (uint)cap); BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(8), 1);
        return payload;
    }
    internal static int Negotiate(Frame hello, int cap)
    {
        if (hello.Type != Hello) throw BinaryException.Protocol();
        var bytes = hello.Payload.AsSpan();
        var minimum = BinaryPrimitives.ReadUInt16BigEndian(bytes); var maximum = BinaryPrimitives.ReadUInt16BigEndian(bytes[2..]);
        var peerCap = BinaryPrimitives.ReadUInt32BigEndian(bytes[4..]); var streams = BinaryPrimitives.ReadUInt32BigEndian(bytes[8..]);
        if (minimum != 1 || maximum < minimum || peerCap is < 4096 or > 1048576 || streams is < 1 or > 128) throw BinaryException.Protocol();
        return Math.Min(cap, (int)peerCap);
    }
    internal static byte[] RequestMetadata(BinaryEnvelope envelope, string? bearer, int timeoutMs)
    {
        // Fields are assembled locally, strictly increasing; all values are bounded.
        var fields = new List<(int Id, byte[] Bytes)>
        {
            (1, [(byte)envelope.Method]), (2, Encoding.ASCII.GetBytes(envelope.Target)),
            (3, Encoding.ASCII.GetBytes(envelope.Method == BinaryMethod.Put ? "application/yaml" : "")),
            (4, Integer((ulong)envelope.OwnedSource.Length, 8)),
        };
        if (bearer is not null) fields.Add((5, Encoding.ASCII.GetBytes("Bearer " + bearer)));
        if (envelope.IfMatch is not null) fields.Add((6, Encoding.ASCII.GetBytes(envelope.IfMatch)));
        if (envelope.IfNoneMatch is not null) fields.Add((7, Encoding.ASCII.GetBytes(envelope.IfNoneMatch)));
        if (envelope.RequestId is not null) fields.Add((8, Convert.FromHexString(envelope.RequestId)));
        fields.Add((9, Integer((ulong)timeoutMs, 4)));
        var output = new byte[4 + fields.Sum(f => 4 + f.Bytes.Length)];
        if (output.Length > 2048) throw BinaryException.Protocol();
        BinaryPrimitives.WriteUInt16BigEndian(output, 1); BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(2), (ushort)fields.Count);
        var offset = 4;
        foreach (var (id, bytes) in fields)
        {
            BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(offset), (ushort)id);
            BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(offset + 2), (ushort)bytes.Length);
            bytes.CopyTo(output, offset + 4); offset += bytes.Length + 4;
        }
        return output;
    }
    private static byte[] Integer(ulong value, int width)
    {
        var bytes = new byte[width];
        for (var i = width - 1; i >= 0; i--) { bytes[i] = (byte)value; value >>= 8; }
        return bytes;
    }
}
