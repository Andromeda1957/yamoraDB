using System.Diagnostics;

namespace Yamora;

public partial class Client
{
    private readonly object lifetime = new();
    private int activeCalls;
    private readonly AsyncLocal<Operation?> operation = new();
    private protected Operation Current => operation.Value ?? throw new InvalidOperationException("no owning operation");

    internal sealed class Operation : IDisposable
    {
        private readonly List<IDisposable> resources = [];
        internal void Retain(IDisposable resource) => resources.Add(resource);
        private readonly long started = Stopwatch.GetTimestamp();
        private readonly TimeSpan timeout;
        private readonly CancellationToken caller;
        private readonly CancellationTokenSource deadline;
        internal CancellationToken Token => deadline.Token;
        internal ClusterWrite? Recovery;
        internal bool Uncertain;
        internal int Attempts;
        internal Operation(TimeSpan timeout, CancellationToken caller)
        {
            this.timeout = timeout;
            this.caller = caller;
            deadline = CancellationTokenSource.CreateLinkedTokenSource(caller);
            deadline.CancelAfter(timeout);
        }
        internal TimeSpan Remaining => timeout - Stopwatch.GetElapsedTime(started);
        internal void Check()
        {
            if (caller.IsCancellationRequested) throw new RequestCanceled(Uncertain, caller);
            if (Remaining <= TimeSpan.Zero || Token.IsCancellationRequested) throw new TransportError(Uncertain);
        }
        public void Dispose()
        {
            foreach (var resource in resources.AsEnumerable().Reverse()) resource.Dispose();
            deadline.Dispose();
        }
    }

    // AsyncLocal flows only into this call's async descendants. Concurrent calls
    // never share cancellation registrations, dispatch state or recovery inputs.
    private protected async Task<T> RunAsync<T>(Func<Task<T>> action, CancellationToken ct, ClusterWrite? recovery = null)
    {
        lock (lifetime)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            activeCalls++;
        }
        var call = new Operation(timeout, ct) { Recovery = recovery, Uncertain = recovery is not null };
        operation.Value = call;
        try
        {
            call.Check();
            var result = await action().ConfigureAwait(false);
            call.Check();
            return result;
        }
        catch (Exception error) when (call.Uncertain && call.Recovery is not null && error is not UncertainWriteException)
        { throw new UncertainWriteException(call.Recovery, error); }
        catch (OperationCanceledException)
        {
            call.Check();
            throw new TransportError(false);
        }
        finally
        {
            operation.Value = null;
            call.Dispose();
            bool release;
            lock (lifetime) release = --activeCalls == 0 && disposed;
            if (release) ReleaseResources();
        }
    }

    private static void ValidateHeaders(HttpResponseMessage response, bool write)
    {
        foreach (var header in response.Headers.NonValidated.Concat(response.Content.Headers.NonValidated))
        {
            // Native diagnostic replies emit this identical value twice.
            // No other duplicated identity, media or framing field is allowed.
            if (header.Key.Equals("Cache-Control", StringComparison.OrdinalIgnoreCase))
            {
                if (header.Value.Count > 1 && !header.Value.All(v => v.Trim(' ', '\t') == "no-store"))
                    throw new YamoraException("conflicting cache policy", write);
            }
            else if (header.Value.Count != 1 && new[] { "ETag", "X-YamlDB-Revision", "Content-Type", "Content-Length", "Transfer-Encoding", "Content-Encoding" }
                .Contains(header.Key, StringComparer.OrdinalIgnoreCase))
                throw new YamoraException("duplicate response metadata", write);
        }
        // Trailers can replace identity after the header checks; they are never
        // accepted by this bounded HTTP/1.1 protocol.
    }
}
