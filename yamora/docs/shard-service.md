# Authenticated shard service

The native service routes explicit shard keys, runs bounded scatter/gather and
aggregation, and resumes whole-partition migration through authenticated peers.
It uses the [native sharding contract](sharding.md), exact authored YAML, and the
existing native storage and replicated application interfaces.

The parent daemon loads private configuration through `yd_shard_service_load`,
starts its listener after cluster startup, and frees the service before closing
the cluster. Configuration paths are absolute. The file must pass the existing
private-file ownership, mode and symlink checks.
Enable it with `--shard-config-file PATH` alongside `--cluster-config-file PATH`.
It cannot be combined with `--replica` or the one-shot cluster backup/restore
options. Shutdown drains and joins public HTTP workers before freeing the shard
service and its backend views.

```yaml
version: 1
local_name: alpha.internal
local_group: alpha
control_group: control
listen: {address: '10.0.0.11', port: 7444}
peer_tls:
  cert_file: /run/yamora/alpha.pem
  key_file: /run/yamora/alpha.key
  ca_file: /run/yamora/ca.pem
peers:
  - {group: alpha, name: alpha.internal, address: '10.0.0.11', port: 7444}
  - {group: control, name: control.internal, address: '10.0.0.10', port: 7444}
request_timeout_ms: 5000
```

Unknown fields, missing required fields, duplicate identities, unregistered
groups and nonnumeric or public addresses fail closed. IPv4 loopback and RFC1918
addresses, IPv6 loopback and unique-local addresses are accepted. Each group can
have multiple independently named replica endpoints. No caller supplies an
endpoint or redirect. The local registry endpoint must match the listener.
Timeouts are 100–30,000 ms in operator configuration. Peer TLS requires a trusted
client certificate, the registered certificate identity, TLS 1.3 and the separate
`yamora-shard/1` ALPN. Optional `crl_file` uses the existing TLS revocation
profile. Raft and binary-client ALPNs cannot authenticate a shard RPC.

Every public and destination operation requires the original bearer credential.
The mandatory authorization callback independently authenticates it and checks
the collection's read, write or administrator grant before state, document,
snapshot or receipt access. A peer certificate alone grants no public identity.
Credentials remain transient TLS input or bounded in-memory scan state;
commands, durable receipts, responses and logs contain no credential. Ordinary
scan continuations bind the credential, shard and complete control state.
Restart, eviction or changed placement invalidates an ordinary continuation.
Migration scans instead use the durable logical freeze identity and local
partition fence, which survive replica layout changes and logical restore.

Public GET state is `/v1/sharding?collection=COLLECTION`; a collection without
a placement returns 404 `shard_placement_missing`. POST operations under
`/v1/sharding/` are `install`, `migrate`, `step`, `route`, `gather`,
`aggregate` and `changes`. One control group can hold up to 64 sharded
collections; installation refuses a shard name that another collection already
uses (409 `conflict`).

Route requires placement ID, epoch, operation, explicit key and document ID;
mutations also require a stable mutation ID, and writes carry exact source.
For a compound placement (`key_version: 2`) `key` is a JSON array with one
string, integer or boolean per field, in field order, for example
`"key": ["acme", 42]`; a scalar, a wrong count, null, a float or a container
returns 400 (`invalid_key` or `unsupported_key`). Gather takes global
offset/limit, optional field sort and descending flag, and bounded row/byte
budgets. Any shard error fails the whole query without partial rows.

Aggregation returns the native pipeline's JSON array. Its `$lookup` stages may
name the collection itself or another sharded collection of the same control
group, with the targeting, bounds and consistency described in
[sharding](sharding.md#cross-shard-lookup). Optional integer fields are
`max_rows` and `max_bytes` (input), `max_foreign_rows` and `max_foreign_bytes`
(all relations), `max_matches` (foreign documents per input row, default and
maximum 1,024) and `max_time_ms` (default 10,000, at most 30,000). With
`"explain": true` the reply is `{"results", "input", "global_snapshot":
false, "lookups": [{"from", "mode", "shards", "ranges", "rows", "bytes"}]}`
where `mode` is `input`, `targeted` or `scatter`. A caller without read access
to any `from` collection receives 403 before any data group is contacted.
Exceeded bounds return 413 `budget_exceeded` and an expired deadline 504
`deadline_exceeded`, always without partial results.

`changes` reads the cluster-wide change feed of a version-2 placement and
requires the collection's administrator grant (the daemon's write token). The
body has `collection`, `placement_id`, `epoch`, optional `after` (a `ysf1.`
token), `limit` (1–1,024, default 128) and `max_bytes` (up to 1 MiB, default
512 KiB). The reply is `{"changes": [{"shard", "sequence", "epoch",
"operation": "write" | "delete", "id", "key" (canonical key hex), "source"
(writes only)}], "next_after", "has_more", "epoch", "shards"}`. Without `after`
it returns a checkpoint token and no changes. Status codes: 400 for a malformed
token or a version-1 placement (`unsupported_metadata`), 403 without the
administrator grant, 409 for a token of another placement or layout, beyond a
shard's tail or with a mismatched hash, 410 `expired` when retention has
passed the position, 413 when one record exceeds `max_bytes`, and 503 while a
migrated partition is published but not yet activated. Token format, ordering,
retention and migration behavior are specified in
[sharding](sharding.md#cluster-wide-change-feed).

The Python `YamoraClient` in [client.py](../client.py) wraps these routes:
`shard_state`, `shard_install`, `shard_route` (a list key for compound
placements), `shard_gather`, `shard_aggregate` (including `explain` and the
lookup bounds), `shard_migrate`, `shard_step`, `shard_changes` and
`iter_shard_changes`. Reads use the read token; install, mutations, migration
and the change feed use the write token. The iterator yields pages, re-reads the
state when a migration advances the epoch and raises every other 409, 410 or
403. The other SDKs do not yet expose sharded routes.

Every ordinary scan continuation obtains a fresh local quorum proof before
looking up its saved view. Followers return unavailable so the registered replica
search can reach the leader. A valid leader without the saved cursor still
returns stale placement and requires a query restart. The original captured
generation remains pinned for stable pages across later writes.

The native integration callback executes internal `YSHARD` commands using
`yd_shard_service_prepare`. It must atomically commit the returned transaction,
the original replicated receipt and the applied checkpoint. Internal mutation
responses are at most 88 bytes; public reads are not logged mutations. Hidden
records must pass `yd_shard_service_key` and `yd_shard_service_validate` during
snapshot and restore admission. The read callback must supply a fresh
majority-confirmed immutable view. The service does not establish Raft quorum or
replace application receipt validation.

Within a managed heavy task environment, run the native fixtures:

```sh
python3 -m unittest -v yamora.tests.test_sharding_runtime yamora.tests.test_shard_service
SHARD_SERVICE_SANITIZED=1 ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
  UBSAN_OPTIONS=halt_on_error=1 python3 -m unittest -v yamora.tests.test_shard_service
```

The service fixture runs three real mutual-TLS listeners and native roots with
immutable-view and prepared-transaction callbacks. It exercises exact sources,
per-destination grants, original retries, pagination, aggregation and restart at
every migration phase, compound-key routing and refusal, targeted, scattered
and self `$lookup` with every bound and foreign-collection denial, and the
change feed through restart, token tampering and a migration with a restart
around every step. Runtime fixtures also terminate processes after durable
RPC effects and control publication. These callbacks are local native adapters:
they do not prove Raft replication, independent-host load distribution, partition
availability, latency or failover limits. The separate
`tests/test_session2_sharding.py` fixture uses nine actual Raft-backed daemons
for control and two data groups, public scatter/gather and aggregation, all
three group leader failures, receipt replay and partition migration. It is a
single-host sanitizer fixture. The separate
[ThinkPad/Precision qualification](session2-qualification.md#two-host-route)
passed 288 exact documents across both hosts, multi-page sorting/pagination,
aggregation, router/shard leader loss, majority-loss rejection, receipt replay
and migration through source-leader failure. All nine affected native methods
also pass, including forced nonfirst shard leaders and proof-denied held pages.
The two-host report publishes measured latency/recovery and its colocated-voter
limits; it establishes no production availability or sub-second guarantee.
