using System.Text.Json;

namespace Yamora;

public partial class Client
{
    public Task<JsonResult> HealthAsync(CancellationToken ct = default)
        => RunAsync(() => HealthCoreAsync(ct), ct);

    public Task<JsonResult> ReadyAsync(CancellationToken ct = default)
        => RunAsync(() => ReadyCoreAsync(ct), ct);

    /// <summary>Advisory source preflight before application-owned stages; native admission remains authoritative.</summary>
    public Task<JsonResult> RequireReplicationSourceAsync(CancellationToken ct = default)
        => RunAsync(async () =>
        {
            var ready = await ReadyCoreAsync(ct).ConfigureAwait(false);
            if (ready.Value.TryGetProperty("replication_policy_free", out var allowed))
            {
                if (allowed.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
                    throw new YamoraException("invalid replication source capability");
                if (allowed.ValueKind == JsonValueKind.False) throw new SchemaPolicyReplicationError();
            }
            return ready;
        }, ct);

    public Task<JsonResult> StatsAsync(CancellationToken ct = default)
        => RunAsync(() => StatsCoreAsync(ct), ct);

    public Task<JsonResult> LeaderAsync(CancellationToken ct = default)
        => RunAsync(() => LeaderCoreAsync(ct), ct);

    public Task<JsonResult> ClusterStatusAsync(CancellationToken ct = default)
        => RunAsync(() => ClusterStatusCoreAsync(ct), ct);

    public Task<string> MetricsAsync(CancellationToken ct = default)
        => RunAsync(() => MetricsCoreAsync(ct), ct);

    public Task<NamesPage> CollectionsAsync(string? revision = null, CancellationToken ct = default)
        => RunAsync(() => CollectionsCoreAsync(revision, ct), ct);

    public Task<NamesPage> DocumentsAsync(string collection, int limit = 1000, string? after = null,
        string? revision = null, CancellationToken ct = default)
        => RunAsync(() => DocumentsCoreAsync(collection, limit, after, revision, ct), ct);

    public Task<Mutation> PatchAsync(string collection, string document, JsonElement operations,
        WriteOptions? options = null, CancellationToken ct = default)
        => RunAsync(() => PatchCoreAsync(collection, document, operations.Clone(), options, ct), ct);

    public Task<JsonResult> QueryAsync(string collection, JsonElement spec, CancellationToken ct = default)
        => RunAsync(() => QueryCoreAsync(collection, spec.Clone(), ct), ct);

    public Task<JsonResult> AggregateAsync(string collection, JsonElement spec, CancellationToken ct = default)
        => RunAsync(() => AggregateCoreAsync(collection, spec.Clone(), ct), ct);

    public Task<JsonResult> SearchAsync(string collection, JsonElement spec, CancellationToken ct = default)
        => RunAsync(() => SearchCoreAsync(collection, spec.Clone(), ct), ct);

    public Task<JsonResult> IndexesAsync(CancellationToken ct = default)
        => RunAsync(() => IndexesCoreAsync(ct), ct);

    public Task<JsonResult> SetIndexesAsync(JsonElement catalog, string? revision = null, string? requestId = null, CancellationToken ct = default)
        => RunAsync(() => SetIndexesCoreAsync(catalog.Clone(), revision, requestId, ct), ct);

    public Task<JsonResult> StartIndexBuildAsync(JsonElement catalog, string? revision = null, CancellationToken ct = default)
        => RunAsync(() => StartIndexBuildCoreAsync(catalog.Clone(), revision, ct), ct);

    public Task<JsonResult> IndexBuildAsync(string? jobId = null, CancellationToken ct = default)
        => RunAsync(() => IndexBuildCoreAsync(jobId, ct), ct);

    public Task<JsonResult> CancelIndexBuildAsync(string jobId, CancellationToken ct = default)
        => RunAsync(() => CancelIndexBuildCoreAsync(jobId, ct), ct);

    public Task<JsonResult> TransactionAsync(JsonElement transaction, string? requestId = null, CancellationToken ct = default)
        => RunAsync(() => TransactionCoreAsync(transaction.Clone(), requestId, ct), ct);

    public Task<JsonResult> ChangesAsync(string? after = null, int limit = 100, CancellationToken ct = default)
        => RunAsync(() => ChangesCoreAsync(after, limit, ct), ct);

    public Task<JsonResult> ReplicationStatusAsync(CancellationToken ct = default)
        => RunAsync(() => ReplicationStatusCoreAsync(ct), ct);

    public Task<JsonResult> BeginReplicationAsync(JsonElement value, CancellationToken ct = default)
        => RunAsync(() => BeginReplicationCoreAsync(value.Clone(), ct), ct);

    public Task<JsonResult> ApplyReplicationAsync(JsonElement value, CancellationToken ct = default)
        => RunAsync(() => ApplyReplicationCoreAsync(value.Clone(), ct), ct);

    public Task<JsonResult> CommitReplicationAsync(JsonElement value, CancellationToken ct = default)
        => RunAsync(() => CommitReplicationCoreAsync(value.Clone(), ct), ct);

    public Task<JsonResult> AbortReplicationAsync(JsonElement value, CancellationToken ct = default)
        => RunAsync(() => AbortReplicationCoreAsync(value.Clone(), ct), ct);

    public Task<JsonResult> BeginFollowAsync(JsonElement value, CancellationToken ct = default)
        => RunAsync(() => BeginFollowCoreAsync(value.Clone(), ct), ct);

    public Task<JsonResult> ApplyFollowAsync(JsonElement value, CancellationToken ct = default)
        => RunAsync(() => ApplyFollowCoreAsync(value.Clone(), ct), ct);

    public Task<JsonResult> CommitFollowAsync(JsonElement value, CancellationToken ct = default)
        => RunAsync(() => CommitFollowCoreAsync(value.Clone(), ct), ct);

    public Task<JsonResult> AbortFollowAsync(JsonElement value, CancellationToken ct = default)
        => RunAsync(() => AbortFollowCoreAsync(value.Clone(), ct), ct);

    public Task<Document> GetAsync(string collection, string document, string? revision = null, CancellationToken ct = default)
        => RunAsync(() => GetCoreAsync(collection, document, revision, ct), ct);

    public Task<Mutation> PutAsync(string collection, string document, ReadOnlyMemory<byte> source,
        WriteOptions? options = null, CancellationToken ct = default)
        => RunAsync(() => PutCoreAsync(collection, document, source, options, ct), ct);

    public Task<string> DeleteAsync(string collection, string document, WriteOptions? options = null, CancellationToken ct = default)
        => RunAsync(() => DeleteCoreAsync(collection, document, options, ct), ct);
}
