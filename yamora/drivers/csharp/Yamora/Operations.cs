using System.Text.Json;

namespace Yamora;

public partial class Client
{
    private Task<JsonResult> HealthCoreAsync(CancellationToken ct = default) => JsonAsync(HttpMethod.Get, "/healthz", null, false, null, null, ct);
    private Task<JsonResult> ReadyCoreAsync(CancellationToken ct = default) => JsonAsync(HttpMethod.Get, "/readyz", null, false, null, null, ct);
    private Task<JsonResult> StatsCoreAsync(CancellationToken ct = default) => JsonAsync(HttpMethod.Get, "/v1/stats", null, false, null, null, ct);
    private Task<JsonResult> LeaderCoreAsync(CancellationToken ct = default) => JsonAsync(HttpMethod.Get, "/v1/cluster/leader", null, false, null, null, ct);
    private Task<JsonResult> ClusterStatusCoreAsync(CancellationToken ct = default) => JsonAsync(HttpMethod.Get, "/v1/cluster/status", null, false, null, null, ct);

    private async Task<string> MetricsCoreAsync(CancellationToken ct = default)
    {
        var response = await SendAsync(HttpMethod.Get, "/metrics", null, null, "text/plain", false, null, DocumentLimit, null, ct, 200).ConfigureAwait(false);
        try { return Validation.Utf8.GetString(response.Body); }
        catch (System.Text.DecoderFallbackException) { throw new YamoraException("invalid metrics UTF-8"); }
    }

    private async Task<NamesPage> CollectionsCoreAsync(string? revision = null, CancellationToken ct = default)
    {
        var result = await JsonAsync(HttpMethod.Get, "/v1/collections", null, false, null, revision, ct).ConfigureAwait(false);
        return new NamesPage(Names(result.Value, "collections", 65536, ""), null, result.Revision);
    }

    // Explicit bounded pages: pin the first revision on subsequent calls.
    private async Task<NamesPage> DocumentsCoreAsync(string collection, int limit = 1000, string? after = null,
        string? revision = null, CancellationToken ct = default)
    {
        Validation.Id(collection);
        Validation.Require(limit is >= 1 and <= 1000, "invalid page limit");
        if (after is not null) { Validation.Id(after); Validation.Require(revision is not null, "cursor requires revision"); }
        var path = $"/v1/collections/{collection}/documents?limit={limit}" + (after is null ? "" : "&after=" + after);
        var result = await JsonAsync(HttpMethod.Get, path, null, false, null, revision, ct).ConfigureAwait(false);
        var names = Names(result.Value, "documents", limit, after ?? "");
        if (!StringField(result.Value, "collection", out var actual) || actual != collection)
            throw new YamoraException("invalid document collection");
        var next = Cursor(result.Value);
        if (next is not null && (names.Length == 0 || next != names[^1])) throw new YamoraException("non-progressing document page");
        return new NamesPage(names, next, result.Revision);
    }

    private async Task<Mutation> PatchCoreAsync(string collection, string document, JsonElement operations,
        WriteOptions? options = null, CancellationToken ct = default)
    {
        options ??= new();
        Validation.Write(options, false);
        Validation.Object(operations);
        Validation.Require(operations.EnumerateObject().Any(), "empty patch");
        var result = await JsonAsync(HttpMethod.Patch, Validation.DocumentPath(collection, document), operations, true, options, null, ct).ConfigureAwait(false);
        return MutationResult(result.Value, result.Revision);
    }

    // JsonElement retains numeric tokens and insertion order (compound sort).
    // The server owns query/operator semantics; this layer validates the envelope.
    private async Task<JsonResult> QueryCoreAsync(string collection, JsonElement spec, CancellationToken ct = default)
    {
        Validation.Object(spec);
        var revision = QueryArguments(spec);
        var result = await JsonAsync(HttpMethod.Post, "/v1/query/" + Validation.Id(collection), spec, false, null, revision, ct).ConfigureAwait(false);
        Rows(result.Value, 1000);
        var next = Cursor(result.Value);
        if (!result.Value.TryGetProperty("matched", out var count) || count.ValueKind != JsonValueKind.Null
            && (count.ValueKind != JsonValueKind.Number || !count.TryGetUInt64(out var matched) || matched < (ulong)result.Value.GetProperty("documents").GetArrayLength()))
            throw new YamoraException("invalid query count");
        if (count.ValueKind == JsonValueKind.Null && (!spec.TryGetProperty("include_count", out var include) || include.ValueKind != JsonValueKind.False
            || spec.TryGetProperty("count_only", out var countOnly) && countOnly.ValueKind == JsonValueKind.True))
            throw new YamoraException("missing query count");
        if (next is not null && result.Value.GetProperty("documents").GetArrayLength() == 0)
            throw new YamoraException("empty query continuation");
        return result;
    }

    private Task<JsonResult> AggregateCoreAsync(string collection, JsonElement spec, CancellationToken ct = default)
    {
        Validation.Object(spec);
        Validation.Require(spec.TryGetProperty("pipeline", out var pipeline) && pipeline.ValueKind == JsonValueKind.Array
            && pipeline.GetArrayLength() is >= 1 and <= 32, "invalid aggregation pipeline");
        return JsonAsync(HttpMethod.Post, "/v1/aggregate/" + Validation.Id(collection), spec, false, null, RevisionOption(spec), ct);
    }

    private Task<JsonResult> SearchCoreAsync(string collection, JsonElement spec, CancellationToken ct = default)
    {
        Validation.Object(spec);
        Validation.Require(StringField(spec, "index", out var index) && Validation.IsId(index)
            && StringField(spec, "text", out var text) && Validation.Utf8.GetByteCount(text!) is >= 1 and <= 8192, "invalid search");
        return JsonAsync(HttpMethod.Post, "/v1/search/" + Validation.Id(collection), spec, false, null, QueryArguments(spec), ct);
    }

    private Task<JsonResult> IndexesCoreAsync(CancellationToken ct = default) => JsonAsync(HttpMethod.Get, "/v1/indexes", null, false, null, null, ct);

    private Task<JsonResult> SetIndexesCoreAsync(JsonElement catalog, string? revision = null, string? requestId = null, CancellationToken ct = default)
    {
        IndexArguments(catalog);
        var options = new WriteOptions(revision, RequestId: requestId);
        Validation.Write(options, false);
        return JsonAsync(HttpMethod.Put, "/v1/indexes", catalog, true, options, null, ct);
    }
    private Task<JsonResult> StartIndexBuildCoreAsync(JsonElement catalog, string? revision = null, CancellationToken ct = default)
    {
        IndexArguments(catalog);
        var options = new WriteOptions(revision);
        Validation.Write(options, false);
        return JsonAsync(HttpMethod.Post, "/v1/index-builds", catalog, true, options, null, ct, 202);
    }
    private Task<JsonResult> IndexBuildCoreAsync(string? jobId = null, CancellationToken ct = default)
        => JsonAsync(HttpMethod.Get, "/v1/index-builds" + (jobId is null ? "" : "/" + Validation.Job(jobId)), null, false, null, null, ct);
    private Task<JsonResult> CancelIndexBuildCoreAsync(string jobId, CancellationToken ct = default)
        => JsonAsync(HttpMethod.Delete, "/v1/index-builds/" + Validation.Job(jobId), null, true, null, null, ct, 202);

    private async Task<JsonResult> TransactionCoreAsync(JsonElement transaction, string? requestId = null, CancellationToken ct = default)
    {
        Validation.Object(transaction);
        RevisionOption(transaction);
        Validation.Require(transaction.TryGetProperty("operations", out var operations), "operations required");
        TransactionArguments(operations);
        var options = new WriteOptions(RequestId: requestId);
        Validation.Write(options, false);
        var result = await JsonAsync(HttpMethod.Post, "/v1/transactions", transaction, true, options, null, ct).ConfigureAwait(false);
        if (!StringField(result.Value, "status", out var status) || status != "committed"
            || !result.Value.TryGetProperty("operations", out var n) || n.ValueKind != JsonValueKind.Number
            || !n.TryGetInt32(out var count) || count != operations.GetArrayLength())
            throw new YamoraException("invalid transaction receipt", true);
        return result;
    }

    private Task<JsonResult> ChangesCoreAsync(string? after = null, int limit = 100, CancellationToken ct = default)
    {
        Validation.Require(limit is >= 1 and <= 100, "invalid change page limit");
        var path = "/v1/changes" + (after is null ? "" : $"?after={Validation.ChangeToken(after)}&limit={limit}");
        return JsonAsync(HttpMethod.Get, path, null, false, null, null, ct);
    }
    private Task<JsonResult> ReplicationStatusCoreAsync(CancellationToken ct = default)
        => JsonAsync(HttpMethod.Get, "/v1/replication/status", null, false, null, null, ct);

    // Low-level explicit replication steps. No automatic bootstrap/follow/retry;
    // the caller must preserve staging, revision and checkpoint ownership.
    private Task<JsonResult> BeginReplicationCoreAsync(JsonElement value, CancellationToken ct = default)
        => ReplicationAsync("begin", value, ct);
    private Task<JsonResult> ApplyReplicationCoreAsync(JsonElement value, CancellationToken ct = default)
        => ReplicationAsync("apply", value, ct);
    private Task<JsonResult> CommitReplicationCoreAsync(JsonElement value, CancellationToken ct = default)
        => ReplicationAsync("commit", value, ct);
    private Task<JsonResult> AbortReplicationCoreAsync(JsonElement value, CancellationToken ct = default)
        => ReplicationAsync("abort", value, ct);
    private Task<JsonResult> BeginFollowCoreAsync(JsonElement value, CancellationToken ct = default)
        => ReplicationAsync("follow/begin", value, ct);
    private Task<JsonResult> ApplyFollowCoreAsync(JsonElement value, CancellationToken ct = default)
        => ReplicationAsync("follow/apply", value, ct);
    private Task<JsonResult> CommitFollowCoreAsync(JsonElement value, CancellationToken ct = default)
        => ReplicationAsync("follow/commit", value, ct);
    private Task<JsonResult> AbortFollowCoreAsync(JsonElement value, CancellationToken ct = default)
        => ReplicationAsync("follow/abort", value, ct);

    private Task<JsonResult> ReplicationAsync(string step, JsonElement value, CancellationToken ct)
    {
        Validation.Object(value);
        return JsonAsync(HttpMethod.Post, "/v1/replication/" + step, value, true, null, null, ct);
    }

    private static string? RevisionOption(JsonElement spec)
    {
        if (!spec.TryGetProperty("revision", out var revision)) return null;
        Validation.Require(revision.ValueKind == JsonValueKind.String, "invalid revision");
        return Validation.Revision(revision.GetString());
    }
    private static string? QueryArguments(JsonElement spec)
    {
        var revision = RevisionOption(spec);
        if (spec.TryGetProperty("limit", out var limit))
            Validation.Require(limit.ValueKind == JsonValueKind.Number && limit.TryGetInt32(out var count) && count is >= 1 and <= 1000, "invalid query limit");
        if (spec.TryGetProperty("after", out var after))
            Validation.Require(after.ValueKind == JsonValueKind.String && Validation.IsId(after.GetString()) && revision is not null
                && (!spec.TryGetProperty("count_only", out var countOnly) || countOnly.ValueKind != JsonValueKind.True), "invalid cursor or missing pinned revision");
        return revision;
    }
    private static void IndexArguments(JsonElement catalog)
    {
        Validation.Object(catalog);
        Validation.Require(catalog.TryGetProperty("indexes", out var indexes) && indexes.ValueKind == JsonValueKind.Array
            && indexes.GetArrayLength() <= 64, "invalid index catalog");
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var index in indexes.EnumerateArray())
        {
            Validation.Object(index);
            Validation.Require(StringField(index, "collection", out var collection) && Validation.IsId(collection)
                && StringField(index, "name", out var name) && Validation.IsId(name), "invalid index identity");
            Validation.Require(seen.Add(index.GetProperty("collection").GetString() + "/" + index.GetProperty("name").GetString()), "duplicate index");
            Validation.Require(index.TryGetProperty("fields", out var fields) && fields.ValueKind == JsonValueKind.Array
                && fields.GetArrayLength() is >= 1 and <= 8, "invalid index fields");
            var paths = new HashSet<string>(StringComparer.Ordinal);
            foreach (var field in fields.EnumerateArray())
                Validation.Require(field.ValueKind == JsonValueKind.String && !string.IsNullOrEmpty(field.GetString()) && paths.Add(field.GetString()!), "invalid index field");
        }
    }
    private static void TransactionArguments(JsonElement operations)
    {
        Validation.Require(operations.ValueKind == JsonValueKind.Array && operations.GetArrayLength() is >= 1 and <= 128, "invalid transaction operations");
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var op in operations.EnumerateArray())
        {
            Validation.Object(op);
            Validation.Require(StringField(op, "collection", out var collection) && Validation.IsId(collection)
                && StringField(op, "document", out var document) && Validation.IsId(document), "invalid operation identity");
            Validation.Require(seen.Add(op.GetProperty("collection").GetString() + "/" + op.GetProperty("document").GetString()), "duplicate operation target");
            var put = op.TryGetProperty("put", out var source);
            var patch = op.TryGetProperty("patch", out var patchValue);
            var delete = op.TryGetProperty("delete", out var deleteValue);
            Validation.Require((put ? 1 : 0) + (patch ? 1 : 0) + (delete ? 1 : 0) == 1
                && (!delete || deleteValue.ValueKind == JsonValueKind.True), "operation requires exactly one mutation");
            if (put)
            {
                Validation.Require(source.ValueKind == JsonValueKind.String, "put source must be a YAML string");
                Validation.Yaml(Validation.Utf8.GetBytes(source.GetString()!));
            }
            if (patch) { Validation.Object(patchValue); Validation.Require(patchValue.EnumerateObject().Any(), "empty patch"); }
            var etag = op.TryGetProperty("etag", out var tag);
            if (etag) Validation.Require(tag.ValueKind == JsonValueKind.String && Validation.Hex(tag.GetString(), 16), "invalid operation ETag");
            if (op.TryGetProperty("create_only", out var create))
                Validation.Require(create.ValueKind == JsonValueKind.False || create.ValueKind == JsonValueKind.True && put && !etag, "invalid create-only operation");
        }
    }
    private static bool StringField(JsonElement value, string name, out string? result)
    {
        result = null;
        if (value.ValueKind != JsonValueKind.Object || !value.TryGetProperty(name, out var field) || field.ValueKind != JsonValueKind.String) return false;
        result = field.GetString();
        return true;
    }
    private static string[] Names(JsonElement value, string key, int maximum, string after)
    {
        if (!value.TryGetProperty(key, out var items) || items.ValueKind != JsonValueKind.Array || items.GetArrayLength() > maximum)
            throw new YamoraException("invalid name index");
        var names = new List<string>();
        foreach (var item in items.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.String || !Validation.IsId(item.GetString()) || string.CompareOrdinal(after, item.GetString()) >= 0)
                throw new YamoraException("invalid or unordered name index");
            names.Add(after = item.GetString()!);
        }
        return names.ToArray();
    }
    private static string? Cursor(JsonElement value)
    {
        if (!value.TryGetProperty("next_after", out var next) || next.ValueKind != JsonValueKind.Null
            && (next.ValueKind != JsonValueKind.String || !Validation.IsId(next.GetString())))
            throw new YamoraException("invalid continuation cursor");
        return next.ValueKind == JsonValueKind.Null ? null : next.GetString();
    }
    private static void Rows(JsonElement value, int maximum)
    {
        if (!value.TryGetProperty("documents", out var rows) || rows.ValueKind != JsonValueKind.Array || rows.GetArrayLength() > maximum)
            throw new YamoraException("invalid result documents");
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var row in rows.EnumerateArray())
            if (!StringField(row, "id", out var id) || !Validation.IsId(id) || !seen.Add(id!) || !row.TryGetProperty("value", out _))
                throw new YamoraException("invalid result row");
    }
}
