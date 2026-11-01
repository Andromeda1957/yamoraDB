using System.Net;
using System.Security.Cryptography;
using System.Text.Json;

namespace Yamora;

/// <summary>Bounded replica-set routing over explicitly trusted HTTPS seeds.</summary>
public sealed class ClusterClient : Client
{
    private readonly Client[] clients;
    private readonly ClusterSeed[] seeds;
    private readonly string clusterId;
    private readonly int voters, requestMaximum;
    private readonly TimeSpan attemptTimeout;
    private readonly object routing = new();
    private sealed record Route(int Index);
    private Route? cached;
    private int cursor;
    private long generation;

    private static ClientOptions First(ClusterOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        Validation.Require(options.Seeds is { Count: >= 1 and <= 9 }, "1..9 trusted seeds required");
        Validation.Require(Validation.Hex(options.ClusterId, 32) && options.ClusterId.Any(c => c != '0'), "invalid cluster ID");
        Validation.Require(options.Voters is 3 or 5 or 7 or 9, "invalid voter count");
        Validation.Require(options.AttemptTimeout > TimeSpan.Zero && options.AttemptTimeout <= TimeSpan.FromSeconds(30), "invalid attempt timeout");
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var seed in options.Seeds)
        {
            Validation.Require(seed is not null && seed.Node >= 1 && seed.Node <= options.Voters, "invalid seed node binding");
            Validation.Require(seed.Endpoint is not null && seed.Endpoint.StartsWith("https://", StringComparison.Ordinal), "cluster seeds require HTTPS");
            Validation.Require(seen.Add(seed.Endpoint.TrimEnd('/')), "duplicate seed");
        }
        return options.Transport(options.Seeds[0].Endpoint);
    }

    public ClusterClient(ClusterOptions options) : base(First(options))
    {
        seeds = options.Seeds.ToArray();
        clusterId = options.ClusterId; voters = options.Voters;
        requestMaximum = options.MaxRequestBytes; attemptTimeout = options.AttemptTimeout;
        var owned = new List<Client> { this };
        try
        {
            foreach (var seed in seeds.Skip(1)) owned.Add(new Client(options.Transport(seed.Endpoint)));
            clients = owned.ToArray();
            foreach (var client in clients) client.RequireContentLength = true;
        }
        catch
        {
            foreach (var client in owned.Skip(1)) client.Dispose();
            base.ReleaseResources();
            throw;
        }
    }

    private protected override void ReleaseResources()
    {
        foreach (var client in clients.Skip(1)) client.Dispose();
        base.ReleaseResources();
    }

    public Task<ClusterReceipt> RecoverAsync(ClusterWrite recovery, CancellationToken ct = default)
        => RunAsync(async () =>
        {
            ArgumentNullException.ThrowIfNull(recovery);
            Validation.Require(recovery.ClusterId == clusterId && recovery.Voters == voters, "recovery cluster binding mismatch");
            Current.Recovery = recovery;
            Current.Uncertain = true; // Earlier ambiguity survives even failed discovery/rejection.
            var response = await SendAsync(new HttpMethod(recovery.Method), recovery.Path, recovery.Payload, recovery.ContentType,
                recovery.ResponseMedia, true, recovery.Conditions, recovery.Maximum, null, ct, recovery.Statuses).ConfigureAwait(false);
            return new ClusterReceipt(response.Status, response.Body, response.Revision, response.ETag);
        }, ct, recovery);

    private protected override async Task<Response> SendAsync(HttpMethod method, string path, byte[]? body, string? media,
        string? responseMedia, bool write, WriteOptions? conditions, int maximum, string? expectedRevision,
        CancellationToken ct, params int[] statuses)
    {
        var call = Current;
        Validation.Revision(expectedRevision);
        Validation.Require(body is null || body.Length <= requestMaximum, "request exceeds byte limit");
        if (path.StartsWith("/v1/index-builds", StringComparison.Ordinal) || path.StartsWith("/v1/replication/", StringComparison.Ordinal))
            throw new HttpError(HttpStatusCode.MethodNotAllowed, false);
        if (write)
        {
            var document = path.StartsWith("/v1/collections/", StringComparison.Ordinal) && method.Method is "PUT" or "PATCH" or "DELETE";
            if (!document && !(method == HttpMethod.Post && path == "/v1/transactions") && !(method == HttpMethod.Put && path == "/v1/indexes"))
                throw new HttpError(HttpStatusCode.MethodNotAllowed, false);
            if (call.Recovery is null)
            {
                var id = conditions?.RequestId;
                if (id is null)
                    do { id = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16)); } while (id.All(c => c == '0'));
                conditions = (conditions ?? new()) with { RequestId = id };
                var count = 1;
                if (path == "/v1/transactions")
                {
                    using var json = JsonDocument.Parse(body!);
                    count = json.RootElement.GetProperty("operations").GetArrayLength();
                }
                call.Recovery = new ClusterWrite(method, path, body, media, conditions, count, clusterId, voters, maximum, responseMedia, statuses);
            }
            var frozen = call.Recovery;
            body = frozen.Payload; conditions = frozen.Conditions;
        }
        Exception last = new HttpError(HttpStatusCode.ServiceUnavailable, false);
        var delay = 25;
        while (call.Attempts < 32)
        {
            call.Check();
            var route = await DiscoverAsync(call).ConfigureAwait(false);
            if (route is not null && call.Attempts < 32)
            {
                call.Check(); call.Attempts++;
                var prior = call.Uncertain;
                try
                {
                    using var attempt = Budget(call, seeds.Length > 1 ? 2 : 1);
                    var result = await clients[route.Index].ExchangeAsync(method, path, body, media, responseMedia, write, conditions,
                        maximum, expectedRevision, call, attempt.Token, () => { if (write) call.Uncertain = true; }, statuses).ConfigureAwait(false);
                    if (write) Receipt(call.Recovery!, result);
                    call.Check();
                    return result;
                }
                catch (Exception error) when (error is YamoraException or OperationCanceledException)
                {
                    if (error is HttpError http && (int)http.StatusCode is >= 400 and < 500 && http.StatusCode != HttpStatusCode.RequestTimeout)
                        call.Uncertain = prior;
                    call.Check();
                    if (error is not TransportError && error is not OperationCanceledException
                        && !(error is HttpError unavailable && unavailable.StatusCode == HttpStatusCode.ServiceUnavailable)) throw;
                    last = error;
                    lock (routing)
                    {
                        if (ReferenceEquals(cached, route)) { cached = null; generation++; cursor = (route.Index + 1) % seeds.Length; }
                    }
                }
            }
            call.Check();
            await Task.Delay(TimeSpan.FromMilliseconds(Math.Max(1, Math.Min(delay, call.Remaining.TotalMilliseconds))), call.Token).ConfigureAwait(false);
            delay = Math.Min(500, delay * 2);
        }
        call.Check();
        throw last;
    }

    private CancellationTokenSource Budget(Operation call, int shares)
    {
        call.Check();
        var budget = CancellationTokenSource.CreateLinkedTokenSource(call.Token);
        budget.CancelAfter(TimeSpan.FromTicks(Math.Max(1, Math.Min(attemptTimeout.Ticks, call.Remaining.Ticks / shares))));
        return budget;
    }

    private async Task<Route?> DiscoverAsync(Operation call)
    {
        int start; long observed;
        lock (routing) { start = cached?.Index ?? cursor; observed = generation; }
        for (var offset = 0; offset < seeds.Length && call.Attempts < 32; offset++)
        {
            call.Check();
            var index = (start + offset) % seeds.Length;
            try
            {
                call.Attempts++;
                using var statusBudget = Budget(call, seeds.Length - offset + 2);
                var status = Json(await clients[index].ExchangeAsync(HttpMethod.Get, "/v1/cluster/status", null, null, "application/json",
                    false, null, 4096, null, call, statusBudget.Token, null, 200).ConfigureAwait(false));
                if (!Integer(status, "node", out var node) || node != (ulong)seeds[index].Node
                    || !Integer(status, "leader", out var leader) || leader != node
                    || !Integer(status, "voters", out var count) || count != (ulong)voters
                    || !Integer(status, "term", out var term) || term == 0 || !Text(status, "role", out var role) || role != "leader") continue;
                if (call.Attempts >= 32) break;
                call.Attempts++;
                using var feedBudget = Budget(call, seeds.Length - offset + 1);
                var feed = Json(await clients[index].ExchangeAsync(HttpMethod.Get, "/v1/changes", null, null, "application/json",
                    false, null, 4096, null, call, feedBudget.Token, null, 200).ConfigureAwait(false));
                if (!new[] { "checkpoint", "next_after", "oldest_after" }.All(key => Text(feed, key, out var value) && FeedToken(value))
                    || feed.GetProperty("checkpoint").GetString() != feed.GetProperty("next_after").GetString()
                    || !feed.TryGetProperty("transactions", out var frames) || frames.ValueKind != JsonValueKind.Array || frames.GetArrayLength() != 0
                    || !feed.TryGetProperty("has_more", out var more) || more.ValueKind != JsonValueKind.False) continue;
                call.Check();
                var route = new Route(index);
                lock (routing)
                {
                    if (observed == generation) { cached = route; generation++; cursor = (index + 1) % seeds.Length; }
                }
                return route;
            }
            catch (Exception error) when (error is YamoraException or OperationCanceledException)
            {
                call.Check();
                if (error is HttpError denied && denied.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden) throw;
            }
        }
        lock (routing) { if (observed == generation) cursor = (start + 1) % seeds.Length; }
        return null;
    }

    private bool FeedToken(string? value) => value is { Length: 52 } && value.StartsWith("v1.", StringComparison.Ordinal)
        && value[35] == '.' && value[3..35] == clusterId && Validation.Hex(value[36..], 16);

    private static void Protocol(bool valid)
    { if (!valid) throw new YamoraException("invalid cluster identity or mutation receipt", true); }
    private static bool Text(JsonElement value, string name, out string? text)
    {
        text = null;
        if (!value.TryGetProperty(name, out var property) || property.ValueKind != JsonValueKind.String) return false;
        text = property.GetString(); return true;
    }
    private static bool Integer(JsonElement value, string name, out ulong number)
    {
        number = 0;
        return value.TryGetProperty(name, out var property) && property.ValueKind == JsonValueKind.Number
            && property.GetRawText().All(c => c is >= '0' and <= '9') && property.TryGetUInt64(out number);
    }
    private static JsonElement Json(Response response)
    {
        try
        {
            Validation.Utf8.GetCharCount(response.Body);
            using var document = JsonDocument.Parse(response.Body, new JsonDocumentOptions { MaxDepth = 64 });
            Validation.Object(document.RootElement); Validation.Json(document.RootElement);
            return document.RootElement.Clone();
        }
        catch (Exception error) when (error is ArgumentException or InvalidOperationException or JsonException)
        { throw new YamoraException("invalid cluster JSON"); }
    }
    private static void Receipt(ClusterWrite write, Response response)
    {
        if (write.Method == "DELETE")
        {
            Protocol(response.Status == 204 && response.Body.Length == 0
            && (response.ETag is null || response.ETag == '"' + response.Revision + '"')); return;
        }
        var value = Json(response);
        Protocol(Text(value, "revision", out var revision) && revision == response.Revision);
        if (write.Path.StartsWith("/v1/collections/", StringComparison.Ordinal))
        {
            var parts = write.Path.Split('/');
            Protocol(response.Status == 200 || write.Method == "PUT" && response.Status == 201);
            if (write.Method == "PUT" && write.Conditions.CreateOnly) Protocol(response.Status == 201);
            if (write.Method == "PUT" && write.Conditions.ETag is not null) Protocol(response.Status == 200);
            Protocol(Text(value, "status", out var status) && status == "stored"
                && Text(value, "collection", out var collection) && collection == parts[3]
                && Text(value, "document", out var document) && document == parts[5]
                && Text(value, "etag", out var etag) && Validation.Hex(etag, 16)
                && response.ETag == '"' + etag + '"');
        }
        else
            Protocol(response.Status == 200 && Text(value, "status", out var status) && status == "committed"
                && Integer(value, "operations", out var count) && count == (ulong)write.OperationCount
                && (response.ETag is null || response.ETag == '"' + response.Revision + '"'));
    }
}
