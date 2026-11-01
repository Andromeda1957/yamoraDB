using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;

namespace Yamora;

public sealed partial class BinaryClient
{
    public async Task<BinaryResponse> OperationAsync(string method, string target, string contentType, byte[] specification,
        string? bearer = null, string? ifMatch = null, string? ifNoneMatch = null, string? requestId = null, CancellationToken ct = default)
        => (await RunOperation(method, target, contentType, specification, bearer, ifMatch, ifNoneMatch, requestId, null, ct).ConfigureAwait(false)).Response;

    /// <summary>Deliver one complete validated owned NDJSON page, including LF. Callback completion applies backpressure.</summary>
    public Task<BinaryFeedResult> FeedAsync(string target, Func<byte[], CancellationToken, ValueTask> consume,
        string? bearer = null, string? requestId = null, string? ifMatch = null, string? ifNoneMatch = null, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(consume);
        return RunOperation("GET", target, "", [], bearer, ifMatch, ifNoneMatch, requestId, consume, ct);
    }
    private async Task<BinaryFeedResult> RunOperation(string method, string target, string contentType, byte[] source, string? bearer,
        string? match, string? none, string? id, Func<byte[], CancellationToken, ValueTask>? consume, CancellationToken ct)
    {
        using var call = new BinaryCall(timeout, ct);
        bool entered = false, admitted = false, dispatched = false;
        BinaryOperation? operation = null; BinaryResponse? observed = null; string after = BinaryOperationsCodec.After(target);
        try {
            EnterCall(); entered = true; call.Check(); await slots.WaitAsync(call.Token).ConfigureAwait(false); admitted = true; call.Check();
            BinaryWire.Bearer(bearer); operation = new BinaryOperation(method, target, contentType, source, match, none, id, call);
            Validation.Require((consume is not null) == target.StartsWith("/v1/changes/stream?", StringComparison.Ordinal), "invalid binary feed target");
            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            using var registration = call.Token.UnsafeRegister(static state => ((Socket)state!).Dispose(), socket);
            await socket.ConnectAsync(tls.Address, call.Token).ConfigureAwait(false); call.Check();
            using var stream = new SslStream(new NetworkStream(socket, ownsSocket: false), leaveInnerStreamOpen: false);
            await stream.AuthenticateAsClientAsync(tls.Options(), call.Token).ConfigureAwait(false); call.Check();
            if (stream.SslProtocol != SslProtocols.Tls13 || stream.NegotiatedApplicationProtocol != new SslApplicationProtocol("yamora-binary/1")) throw BinaryException.Protocol();
            var hello = BinaryWire.HelloPayload(frameCap); hello[3] = 2;
            await BinaryWire.Write(stream, BinaryWire.Hello, 0, hello, frameCap, call).ConfigureAwait(false);
            var peer = await BinaryWire.Read(stream, frameCap, call).ConfigureAwait(false);
            int cap = BinaryOperationsCodec.Negotiate(peer, frameCap);
            var metadata = BinaryOperationsCodec.Request(operation, bearer, call.RemainingMilliseconds); call.Check(); dispatched = true;
            await BinaryWire.Write(stream, BinaryWire.Request, 1, metadata, cap, call).ConfigureAwait(false);
            for (int offset = 0; offset < operation.OwnedSource.Length; offset += cap)
                await BinaryWire.Write(stream, BinaryWire.Data, 1, operation.OwnedSource.AsMemory(offset, Math.Min(cap, operation.OwnedSource.Length - offset)), cap, call).ConfigureAwait(false);
            await BinaryWire.Write(stream, BinaryWire.End, 1, ReadOnlyMemory<byte>.Empty, cap, call).ConfigureAwait(false);
            int pings = 0;
            async Task<BinaryWire.Frame> Receive() {
                while (true) { var frame = await BinaryWire.Read(stream, cap, call).ConfigureAwait(false);
                    if (frame.Type != BinaryWire.Ping) return frame;
                    if (++pings > 4) throw BinaryException.Protocol();
                    await BinaryWire.Write(stream, BinaryWire.Pong, 0, frame.Payload, cap, call).ConfigureAwait(false);
                }
            }
            var response = await Receive().ConfigureAwait(false); if (response.Type != BinaryWire.Response) throw BinaryException.Protocol();
            var meta = BinaryReply.ParseOperation(response.Payload, operation, consume is not null); call.Check();
            if (meta.Streaming) {
                observed = new BinaryResponse(meta, []); using var page = new MemoryStream(); int total = 0; bool terminal = false, started = false;
                while (true) { var frame = await Receive().ConfigureAwait(false);
                    if (frame.Type == BinaryWire.End) { if (!started || page.Length != 0) throw BinaryException.Protocol(); break; }
                    if (frame.Type != BinaryWire.Data || terminal || frame.Payload.Length > DocumentLimit - total) throw BinaryException.Protocol(); total += frame.Payload.Length;
                    foreach (byte value in frame.Payload) {
                        if (terminal) throw BinaryException.Protocol(); page.WriteByte(value);
                        if (value == '\n') { var raw = page.ToArray(); page.SetLength(0); var parsed = BinaryOperationsCodec.Page(raw, after, call);
                            call.Check(); await consume!(raw, call.Token).ConfigureAwait(false); after = parsed.After; terminal = parsed.Terminal; started = true; call.Check(); }
                    }
                }
                call.Check(); return new BinaryFeedResult(observed, after);
            }
            var body = new byte[meta.BodyLength]; int position = 0;
            while (true) { var frame = await Receive().ConfigureAwait(false);
                if (frame.Type == BinaryWire.End) { if (position != body.Length) throw BinaryException.Protocol(); break; }
                if (frame.Type != BinaryWire.Data || frame.Payload.Length > body.Length - position) throw BinaryException.Protocol();
                frame.Payload.CopyTo(body, position); position += frame.Payload.Length;
            }
            BinaryOperationsCodec.Validate(meta, body, operation, call); call.Check(); observed = new BinaryResponse(meta, body);
            if (meta.Status >= 400) throw new BinaryException(BinaryFailure.Status, meta.Status);
            return new BinaryFeedResult(observed, after);
        } catch (BinaryUnsupportedPeerException) { throw; }
        catch (Exception error) when (error is BinaryException or IOException or SocketException or AuthenticationException or OperationCanceledException || error is ObjectDisposedException && entered) {
            BinaryException safe;
            try { call.Check(); safe = error as BinaryException ?? new BinaryException(BinaryFailure.Transport); } catch (BinaryException stopped) { safe = stopped; }
            bool uncertain = dispatched && operation is { Mutation: true } && (safe.Kind != BinaryFailure.Status || safe.StatusCode == 408 || safe.StatusCode >= 500);
            throw new BinaryOperationException(safe, uncertain ? operation : null, observed, after);
        } finally { if (admitted) slots.Release(); if (entered && LeaveCall()) { tls.Dispose(); slots.Dispose(); } }
    }
}
