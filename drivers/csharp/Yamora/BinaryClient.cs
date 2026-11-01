using System.Diagnostics;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;

namespace Yamora;

internal sealed class BinaryCall : IDisposable
{
    private readonly long start = Stopwatch.GetTimestamp();
    private readonly TimeSpan timeout;
    private readonly CancellationToken caller;
    private readonly CancellationTokenSource deadline;
    internal CancellationToken Token => deadline.Token;
    internal BinaryCall(TimeSpan timeout, CancellationToken caller)
    {
        this.timeout = timeout; this.caller = caller;
        deadline = CancellationTokenSource.CreateLinkedTokenSource(caller); deadline.CancelAfter(timeout);
    }
    internal void Check()
    {
        if (caller.IsCancellationRequested) throw new BinaryException(BinaryFailure.Canceled);
        if (Stopwatch.GetElapsedTime(start) >= timeout || Token.IsCancellationRequested) throw new BinaryException(BinaryFailure.Deadline);
    }
    internal int RemainingMilliseconds
    {
        get { Check(); return Math.Clamp((int)Math.Ceiling((timeout - Stopwatch.GetElapsedTime(start)).TotalMilliseconds), 1, 30000); }
    }
    public void Dispose() => deadline.Dispose();
}

/// <summary>One verified TLS 1.3 binary connection per operation; no automatic replay.</summary>
public sealed partial class BinaryClient : IDisposable
{
    public const int DocumentLimit = 16 * 1024 * 1024;
    internal static readonly ActivitySource Diagnostics = new("Yamora.Binary");
    private readonly BinaryTls tls;
    private readonly TimeSpan timeout;
    private readonly int frameCap;
    private readonly SemaphoreSlim slots;
    private readonly object lifetime = new();
    private bool disposed;
    private int calls;
    private void EnterCall()
    {
        lock (lifetime) { ObjectDisposedException.ThrowIf(disposed, this); calls++; }
    }
    private bool LeaveCall()
    {
        lock (lifetime) { return --calls == 0 && disposed; }
    }
    public BinaryClient(BinaryClientOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        Validation.Require(options.Timeout > TimeSpan.Zero && options.Timeout <= TimeSpan.FromSeconds(30), "invalid binary timeout");
        Validation.Require(options.MaxFrameBytes is >= 4096 and <= 65536 && options.MaxConcurrentCalls is >= 1 and <= 4, "invalid binary capacity");
        timeout = options.Timeout; frameCap = options.MaxFrameBytes; slots = new(options.MaxConcurrentCalls);
        tls = new BinaryTls(options);
    }
    public Task<BinaryResponse> GetAsync(string collection, string document, string? bearer = null, CancellationToken ct = default)
        => CallAsync(BinaryMethod.Get, collection, document, null, bearer, ct: ct);
    public Task<BinaryResponse> HeadAsync(string collection, string document, string? bearer = null, CancellationToken ct = default)
        => CallAsync(BinaryMethod.Head, collection, document, null, bearer, ct: ct);
    public Task<BinaryResponse> PutAsync(string collection, string document, byte[] source, string? bearer = null,
        string? ifMatch = null, string? ifNoneMatch = null, string? requestId = null, CancellationToken ct = default)
        => CallAsync(BinaryMethod.Put, collection, document, source, bearer, ifMatch, ifNoneMatch, requestId, ct);
    public Task<BinaryResponse> DeleteAsync(string collection, string document, string? bearer = null,
        string? ifMatch = null, string? requestId = null, CancellationToken ct = default)
        => CallAsync(BinaryMethod.Delete, collection, document, null, bearer, ifMatch, null, requestId, ct);

    // Conditions are exact wire values (including quotes, '*' and present empty values).
    // Waiters hold caller references, but never a second source copy. Leave queued
    // sources unchanged until admitted; admitted calls own their immutable snapshot.
    public Task<BinaryResponse> CallAsync(BinaryMethod method, string collection, string document, byte[]? source = null,
        string? bearer = null, string? ifMatch = null, string? ifNoneMatch = null, string? requestId = null, CancellationToken ct = default)
        => Run(method, collection, document, source, bearer, ifMatch, ifNoneMatch, requestId, null, ct);
    public Task<BinaryResponse> ReplayAsync(BinaryEnvelope original, string? bearer = null, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(original);
        Validation.Require(original.Mutation, "binary replay requires mutation envelope");
        return Run(original.Method, original.Collection, original.Document, null, bearer, null, null, null, original, ct);
    }
    private async Task<BinaryResponse> Run(BinaryMethod method, string collection, string document, byte[]? source,
        string? bearer, string? ifMatch, string? ifNoneMatch, string? requestId, BinaryEnvelope? replay, CancellationToken ct)
    {
        using var call = new BinaryCall(timeout, ct);
        bool entered = false, admitted = false, dispatched = false;
        BinaryEnvelope? envelope = replay;
        try
        {
            EnterCall(); entered = true;
            call.Check(); await slots.WaitAsync(call.Token).ConfigureAwait(false); admitted = true; call.Check();
            BinaryWire.Bearer(bearer);
            envelope ??= new BinaryEnvelope(method, collection, document, source ?? [], ifMatch, ifNoneMatch, requestId, call);
            using (Diagnostics.StartActivity("Yamora.BinaryFreeze")) { call.Check(); }
            call.Check();
            BinaryResponse result;
            {
                using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
                // Cancellation owns exactly this socket. Registration.Dispose joins any
                // executing callback before admission or certificate lifetimes are released.
                using var registration = call.Token.UnsafeRegister(static state => ((Socket)state!).Dispose(), socket);
                await socket.ConnectAsync(tls.Address, call.Token).ConfigureAwait(false); call.Check();
                using var stream = new SslStream(new NetworkStream(socket, ownsSocket: false), leaveInnerStreamOpen: false);
                await stream.AuthenticateAsClientAsync(tls.Options(), call.Token).ConfigureAwait(false); call.Check();
                if (stream.SslProtocol != SslProtocols.Tls13 || stream.NegotiatedApplicationProtocol != new SslApplicationProtocol("yamora-binary/1")) throw BinaryException.Protocol();
                await BinaryWire.Write(stream, BinaryWire.Hello, 0, BinaryWire.HelloPayload(frameCap), frameCap, call).ConfigureAwait(false);
                var cap = BinaryWire.Negotiate(await BinaryWire.Read(stream, frameCap, call).ConfigureAwait(false), frameCap);
                var metadata = BinaryWire.RequestMetadata(envelope, bearer, call.RemainingMilliseconds);
                call.Check(); dispatched = true;
                await BinaryWire.Write(stream, BinaryWire.Request, 1, metadata, cap, call).ConfigureAwait(false);
                for (var offset = 0; offset < envelope.OwnedSource.Length; offset += cap)
                    await BinaryWire.Write(stream, BinaryWire.Data, 1, envelope.OwnedSource.AsMemory(offset, Math.Min(cap, envelope.OwnedSource.Length - offset)), cap, call).ConfigureAwait(false);
                await BinaryWire.Write(stream, BinaryWire.End, 1, ReadOnlyMemory<byte>.Empty, cap, call).ConfigureAwait(false);
                int pings = 0;
                async Task<BinaryWire.Frame> Receive()
                {
                    while (true)
                    {
                        var frame = await BinaryWire.Read(stream, cap, call).ConfigureAwait(false);
                        if (frame.Type != BinaryWire.Ping) return frame;
                        if (++pings > 4) throw BinaryException.Protocol();
                        await BinaryWire.Write(stream, BinaryWire.Pong, 0, frame.Payload, cap, call).ConfigureAwait(false);
                    }
                }
                var response = await Receive().ConfigureAwait(false);
                if (response.Type != BinaryWire.Response) throw BinaryException.Protocol();
                var meta = BinaryReply.Parse(response.Payload, envelope); call.Check();
                var body = new byte[meta.BodyLength]; var position = 0;
                while (true)
                {
                    var next = await Receive().ConfigureAwait(false);
                    if (next.Type == BinaryWire.End)
                    {
                        if (position != body.Length) throw BinaryException.Protocol();
                        break;
                    }
                    if (next.Type != BinaryWire.Data || next.Payload.Length > body.Length - position) throw BinaryException.Protocol();
                    next.Payload.CopyTo(body, position); position += next.Payload.Length;
                }
                BinaryReply.Validate(meta, body, envelope, call); call.Check();
                if (meta.Status >= 400) throw new BinaryException(BinaryFailure.Status, meta.Status);
                result = new BinaryResponse(meta, body);
            }
            using (Diagnostics.StartActivity("Yamora.BinaryReturn")) { call.Check(); }
            call.Check(); return result;
        }
        catch (Exception error) when ((error is BinaryException or IOException or SocketException or AuthenticationException or OperationCanceledException
            || error is ObjectDisposedException && (entered || replay is not null) || error is ArgumentException && replay is not null))
        {
            BinaryException safe;
            try { call.Check(); safe = error as BinaryException ?? new BinaryException(BinaryFailure.Transport); }
            catch (BinaryException stopped) { safe = stopped; }
            if (envelope is { Mutation: true } && (replay is not null || dispatched
                && (safe.Kind != BinaryFailure.Status || safe.StatusCode >= 500 || safe.StatusCode == 408))) throw new BinaryUncertainException(envelope, safe);
            throw safe;
        }
        finally
        {
            if (admitted) slots.Release();
            bool release = false;
            if (entered) release = LeaveCall();
            if (release) { tls.Dispose(); slots.Dispose(); }
        }
    }
    public void Dispose()
    {
        lock (lifetime) { if (disposed) return; disposed = true; if (calls != 0) return; }
        tls.Dispose(); slots.Dispose();
    }
}
