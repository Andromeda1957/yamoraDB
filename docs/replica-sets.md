# Experimental replica sets

The daemon can now run the native Raft document controller with
`--cluster-config-file PATH`. This is an experimental Raft profile,
not a production high-availability guarantee. Verified snapshot capture,
authenticated installation and peer catch-up from persisted checkpoints are
implemented. Background checkpoints and physical journal compaction are opt-in
and disabled by default. Application-data reclamation, archive/generation and
receipt retention and sustained operational fault testing
remain required. Retained entries and retry receipts have no expiry policy;
restarting verifies the complete retained journal. Do not use this profile as
the sole copy of data.

Storage remains Yamora's native C engine. System OpenSSL supplies TLS and
cryptography. Authored YAML and its Git history remain independent of generated
cluster storage. No existing YAML or standalone database is converted in place.

## Configuration

Create separate, empty, pre-existing document and journal directories for each
node. A stopped node must retain **both** roots together. The daemon exclusively
locks its document directory before opening either engine. The journal also has
its native writer lock. Aliases of the two roots are rejected.

The configuration is one strict YAML document, at most 64 KiB, stored in a
private regular file. Symlinks, public permissions, group writes and executable
permissions are rejected; use `0600`, `0640` or systemd's `0440` profile. Unknown
fields, duplicate keys and unsafe YAML features are errors. File paths must be
absolute. For node 1, for example:

```yaml
cluster: "01020304000000000000000000000000"
node: 1
journal_dir: /srv/yamora/node1/journal
peer_tls:
  cert_file: /etc/yamora/node1.pem
  key_file: /etc/yamora/node1.key
  ca_file: /etc/yamora/cluster-ca.pem
peers:
  - {id: 1, name: node1.example, address: 10.20.0.11, port: 9765}
  - {id: 2, name: node2.example, address: 10.20.0.12, port: 9765}
  - {id: 3, name: node3.example, address: 10.20.0.13, port: 9765}
timing:
  heartbeat_ms: 50
  election_min_ms: 600
  election_max_ms: 1100
  rpc_ms: 250
journal_cache_bytes: 1048576
command_bytes: 67108864
request_timeout_ms: 5000
checkpoints:
  entries: 0
  interval_ms: 10000
  timeout_ms: 1000
compaction:
  minimum_bytes: 0
  minimum_saved_bytes: 1048576
  interval_ms: 60000
  attempts: 3
```

Use a random nonzero 16-byte cluster identity encoded as 32 lowercase hex digits,
quoted so YAML preserves the string type. All nodes must use the same identity,
complete authenticated peer catalog with 3, 5, 7 or 9 identity slots. IDs are
exactly 1 through that count. Change only the local `node`, journal path and
certificate paths. The optional `initial_voters: [1, 2, 3]` selects at least
three bootstrap voters; omitted means every catalog slot initially votes.
Other slots start as learners and cannot campaign or grant votes. All nodes
must retain the same bootstrap setting across restart. Changing this setting
after a node has participated is refused. The catalog, endpoints and certificate
names remain immutable; increasing the identity catalog is unsupported.

## Online voter changes

The native acceptance suite exercises durable configuration recovery and five
mutually authenticated processes on one host. These are crash-fault tests, with
authenticated participants running the protocol; they do not establish Byzantine
fault tolerance, independent-host qualification or a failover-time guarantee.

The runtime reconfiguration operation changes the voting subset of the existing
catalog. At least three voters must remain. A new voter first catches up through
the leader's complete durable log (including snapshot transfer when needed).
It then enters a durable joint configuration requiring a majority of the old
voters **and** a majority of the new voters for elections, log commitment and
fresh read confirmation. A learner's successful replication never counts toward
the old quorum. Only one transition can be in flight.

Once the joint configuration commits, the leader appends its final stable
configuration. Each node uses that configuration as soon as the entry is
durable, and its commitment requires the new majority. This follows
[Raft's joint-consensus protocol](https://raft.github.io/raft.pdf), section 6:
joint commitment precedes final creation, and both phases use the latest durable
configuration. Delaying activation until final commitment can strand elections
when the current leader is removed. A removed current leader continues
replicating final without a self vote until it commits, then steps down. A leader
elected after a crash resumes finalization. Read proofs bind their configuration
and cannot cross a configuration change, even in the same leader term. A
removed leader steps down when it learns the final commitment. An isolated
former leader cannot obtain the quorum needed for a committed write or fresh
read: every old majority intersects the durable joint majority, whose members
require the new majority too. New elections also require an up-to-date log.

If the leader fails after old voters persist joint but before other participants
receive it, a candidate may retransmit that exact durable joint entry. A recipient
accepts it only as an exact extension of its stable pre-joint prefix. This repair
does not advance commitment, establish a leader, reset election timers, produce
a read acknowledgement, or let a learner campaign or vote before it persists
joint. Once delivered, ordinary elections still require both majorities. A
newly promoted candidate with the newest suffix can also repair an old voter
that missed joint. Delayed repair cannot depose a peer already using joint or a
same-term elected leader. Wire header byte 12 distinguishes this exchange from
leader replication; mixed versions that lack this extension are unsupported.
Peers holding a pending final entry also forward it through this exchange.
This includes removed followers, which remain unable to campaign or vote: if
only removed identities received final before the leader failed, forwarding
lets an eligible successor learn final and obtain the new quorum. The recipient
requires the exact joint prefix and matching retired identities; forwarding
still grants no commitment or leader contact.
Repair also catches up missing retained entries before the configuration, one
bounded entry per exchange, without overwriting a conflicting suffix. If the
needed prefix was compacted, a separately marked snapshot session can install
the source's already committed image and checkpoint configuration. Its marker
is bound through every transfer phase, and reception keeps the leader identity
empty. Ordinary replication resumes after an eligible successor wins election.

Replacement means promoting a distinct, preprovisioned identity slot and
removing the old slot through this protocol. Removed slots are durably retired
and cannot rejoin or have their IDs reused. Keep their directories recoverable;
removal does not erase data. An unused slot is required for each later
replacement. Deploying a different certificate or empty journal under an old
identity is not a supported replacement procedure.

The operation returns success only after final commitment. A timeout can leave
catch-up pending or an uncertain, resumable joint transition; inspect status
and retry the same target. A different target is rejected while joint. Busy
write traffic can defer admission until the leader has no uncommitted tail.
No availability or failover-time guarantee follows from these local fixtures.

Configuration has its own versioned journal record, selected in the same native
transaction as log/commit metadata. Configured journals explicitly require that
record and refuse recovery if it is omitted. Checkpoints preserve the exact
configuration at their application boundary. Authenticated snapshot sessions
carry and correlate that configuration through every phase; installing the
application and selecting its membership is one durable journal transition.
An offer conflicting with the locally committed topology at the same boundary
is rejected, even when its application archive identity matches. The topology
is carried by the authenticated transfer envelope and independent journal record;
the application-only archive hash does not by itself identify a configuration.
Journal copying preserves and verifies this record as well as the complete
configuration suffix. The immutable identity catalog size continues to bind
storage and snapshot identity; it never substitutes for the live voter quorum.

The optional `checkpoints` map enables one background capture/checkpoint worker
when `entries` is positive. Omit it or use `entries: 0` to keep the default
disabled behavior. `entries` is required when the map is present and accepts
0..1,000,000,000; it measures committed entries since this node's persisted base,
including election no-ops. Only the current leader meeting that threshold attempts
work. `interval_ms` defaults to 10,000 and accepts 100..3,600,000; a new interval
starts after each attempt completes. `timeout_ms` defaults to 1,000 and accepts
100..30,000, bounding quorum/admission rather than complete image/graph work.
Positive entries require a command/payload budget of at least 256 bytes.

Every publication obtains fresh quorum, validates/archives the exact immutable
application and rechecks leadership. A peer missing the retained prefix catches
up through authenticated snapshot installation before ordinary suffix appends.
Configuration is loaded at startup; changing this policy requires restart.
Checkpointing removes logical journal prefix keys but preserves all archives,
application generations, retry receipts and historical physical pages. It does
not itself reclaim disk space or qualify the profile for production high availability.

The optional `compaction` map enables one physical journal compactor on each
configured member when `minimum_bytes` is positive. Omission or zero keeps it
disabled. Physical journal replacement supports legacy unfenced journals;
fresh retaining journals reject enabling this worker because their native open
fence forbids that export path. Application compaction has its own worker and
retention protocol. That key is required when the map is present; the YAML size bounds
are 0..1 PiB for `minimum_bytes`, and 1 byte..1 PiB for `minimum_saved_bytes`
(default 1 MiB). `interval_ms` defaults to 60,000 and accepts 100..3,600,000;
`attempts` defaults to 3 and accepts 1..16. Types, unknown fields and bounds
are checked before native storage creation, including when disabled.

An interval starts after the preceding operation completes. Below the source
threshold it skips without staging; a verified copy must save the requested
bytes before selection. Capture/copy/catch-up run outside the Raft mutex; the
final guarded journal switch is serialized and durable. Stale selection retries
are bounded by `attempts`; exhausting them waits another interval. The configured
`journal_cache_bytes` is preserved. Followers and minority members may reclaim
identical local state without a quorum; this grants no new read/write authority.
If interrupted publication or retirement leaves the selected native file
hardlinked to staged work, retaining startup refuses and preserves every file.
It does not adopt those aliases or reconstruct cleanup authority after restart.

Failure or incomplete retirement/cleanup disables the worker until restart,
preserving uncertain or unverified artifacts. A diagnostic candidate may remain
fenced; the worker never sweeps crash leftovers or deletes unknown files. A
selection durability failure fences participation until reopen. Cleanup failure
after a durable selection can leave the member healthy with compaction disabled.
Shutdown cancels and joins owned maintenance before closing the runtime. Slow
syscalls can delay shutdown until their operation completes.

Administrative status adds local `compaction` enabled/running state, saturating
`attempted`, `succeeded`, `skipped`, `stale` and `failed` counters, and
`source_bytes`, `candidate_bytes` and `last_result` from the last finished
operation. Result codes are -1 failed, 0 skipped, 1 succeeded, 2 stale, 3
cancelled and 4 incomplete; before any attempt the numeric fields are zero.
Counters reset at restart. Clock/wait failure also increments `failed` and
disables scheduling without starting an attempt. These observations are not
disk-usage measurements or readiness proofs. Physical compaction removes
obsolete journal pages only; retained logical entries, application pages,
archives, generations and retry receipts require separate retention work.

Every endpoint is a distinct literal loopback or private address: IPv4 RFC 1918
or 127/8, IPv6 ULA or `::1`. DNS resolution, public/link-local addresses,
unspecified/multicast addresses and IPv4-mapped IPv6 are rejected. Names are
distinct lowercase DNS names with exact certificate DNS SANs; wildcards, IP
identities and Common Name fallback are rejected. Each peer certificate needs
both server and client authentication usage. Peer connections require TLS 1.3,
mutual certificate verification and the separate `yamora-raft/1` ALPN protocol.
HTTP clients cannot use the peer port.

An optional absolute `peer_tls.crl_file` path enables the bounded local
[CRL profile](tls-revocation.md) for inbound and outbound peer verification.
Supply complete current issuer coverage; invalid configuration refuses startup.
Public HTTP revocation is configured separately with `--tls-crl-file` and
`--tls-client-ca-file`. SIGHUP validates each profile's replacement independently.

Timing and memory fields are optional, with the defaults shown. Heartbeats are
50–1,000 ms; election minimum is at least five heartbeats; maximum exceeds minimum
by at least one heartbeat and is at most 30 seconds. RPC timeout is positive and
at most half the election minimum. Journal cache is 32 KiB–1 GiB; command-buffer
budget is 1 byte–64 MiB; request deadline is 100–30,000 ms. Document cache uses the
ordinary `--cache-bytes` option, separately from journal and transport budgets.
These are resource bounds, not measured latency or capacity guarantees.
All voters must use the same command budget; retain it when restarting existing
journals. It limits the complete encoded consensus command, including the
request and receipt envelope. A larger request returns 413 before journal append,
and a smaller subsequent write can still proceed. Lowering this budget for an
existing journal is unsupported because retained entries must remain transferable.

Start each node with a verified HTTP TLS certificate and distinct administrative
read/write credentials, for example:

```sh
yamora --data-dir /srv/yamora/node1/data \
  --cluster-config-file /etc/yamora/node1.yaml \
  --bind-address 10.20.0.11 --port 8765 \
  --auth-token-file /etc/yamora/read.token \
  --write-auth-token-file /etc/yamora/write.token \
  --tls-cert-file /etc/yamora/http-node1.pem \
  --tls-key-file /etc/yamora/http-node1.key
```

HTTP mTLS and collection access policies remain available. Certificate identity
does not grant an API role. SIGHUP independently validates/reloads HTTP and peer
TLS profiles; a failed reload retains that profile's previous context. Topology
and access policies load only at startup. SIGTERM drains HTTP workers, closes
application/peer workers, then releases roots and listeners.

Initialization/import flags, offline compaction and `--validate-only` cannot be
combined with cluster configuration. `--replica` is accepted for a read-only
destination, including before its first bootstrap. Cluster documents use format 6;
standalone opens, old writers, standalone validation and compaction refuse them.
Never compact one root independently or restore only one member of a root pair.
The local one-shot `--cluster-backup-to PATH` operation starts the configured
node, waits up to 30 seconds for fresh leader quorum, captures a paired backup
and exits. Other voters must be running. Use an existing empty private output
directory. Offline `--cluster-restore-from PATH` verifies the bundle and restores
into two existing empty roots before ordinary startup. Stop the original node
identity first. Neither option can be combined with shard configuration; backups
and restoration cannot be requested together. See [paired backup/restore](cluster-backup.md)
for identity, topology, corruption and recovery constraints.

## HTTP requests and failure behavior

Only the current leader serves document reads and writes. Reads (including
queries, aggregations, search, indexes, listings and paged change feeds) require
fresh successful contact with a majority and application through the proven
commit position before capturing their immutable view. An isolated former leader
returns 503. Followers return 503 rather than serving potentially stale data.
`/readyz` uses the same proof; `/healthz` reports process health only.

Document PUT/PATCH/DELETE, atomic transactions and synchronous index-catalog PUT
run through consensus. Each write **requires** `X-Yamora-Request-Id`: a client
generated nonzero 16-byte ID encoded as exactly 32 lowercase hex digits. Missing,
duplicate or malformed headers return 400. Retain the ID and exact method, path,
body and preconditions until the operation is resolved. Generate a new ID for
each new logical operation. Successful replies wait for majority commitment and
atomic durable application of effects, receipt and applied position.

A timeout/disconnect/503 can leave a write outcome uncertain. Retry the same ID
and exact request against the discovered leader; a committed retry returns its
original status, body and ETag without repeating effects. Reusing an ID for
different request bytes returns 409. Receipts currently have no expiry. Ordinary
validation errors remain local rejections and are not durable retry receipts.

Authenticated `GET /v1/cluster/leader` returns only `node`, `leader`, `term` and
`role`. Collection-scoped principals may use it. Administrative read credentials
can also use `GET /v1/cluster/status`, which adds `voters`, `last`, `committed`,
`applied`, `failed` and a `checkpoints` object with `enabled`, `running`,
`succeeded`, `failed` and `last_index`. Checkpoint attempt counters are local to
this process and reset on restart; `last_index` is the persisted boundary observed
after its most recent successful policy publication, or zero before one.
These responses are advisory, include `Cache-Control:
no-store`, and establish no read proof. A reported leader can already be stale.
Clients should try an explicitly configured trusted list of HTTP seeds and retry
discovery after failure; the server sends no redirect URL. Credentials must never
be forwarded to an endpoint supplied by an untrusted redirect.

Authorization runs before cluster routing and does not expand collection grants.
Administrative write and read credentials keep their distinct roles. Status and
metrics describe local operational state; they are not document read barriers.

Replica bootstrap/follow routes stage hidden destination state and publish it
atomically through consensus. Published destinations reject ordinary writes.
Online index-build jobs replicate admission, terminal outcomes and exact catalog
publication; see [index jobs](replicated-index-jobs.md).
Synchronous indexes, paged feeds and continuous HTTP change streams are available
on the quorum-serving leader. Every stream page, including an empty heartbeat,
obtains a fresh majority-confirmed owned application view; a session cannot keep
serving from its initial proof after quorum loss. Failure before admission returns
503; failure after headers emits terminal 503 `cluster_unavailable`. An already
rendered committed page may finish delivery after leadership changes. Resume
explicitly on a trusted current leader using the consumer's durable token; the
server's last-sent position is not a consumer acknowledgment. See the version-1
[publication/resume contract](replicated-publication.md) and
[stream bounds](change-streams.md). Feed tokens share the cluster identity and survive
leader changes; elections append empty no-op frames, so checkpoints can advance
without changing documents. Peer replication is continuous independently of the
HTTP feed interface. Python and Go cluster drivers implement the retry contract
below. Direct HTTP clients can also use it.

## Python cluster driver

Use `YamoraClusterClient` for replica sets. The ordinary `YamoraClient` retains
its standalone behavior and does not acquire automatic write retries.

```python
import secrets
import ssl
from yamora import YamoraClusterClient, YamoraUncertainWriteError

tls = ssl.create_default_context(cafile="/etc/yamora/http-ca.pem")
tls.minimum_version = ssl.TLSVersion.TLSv1_3
client = YamoraClusterClient(
    seeds=[("10.20.0.11", 8765), ("10.20.0.12", 8765), ("10.20.0.13", 8765)],
    tls_context=tls,
    auth_token_file="/etc/yamora/read.token",
    write_auth_token_file="/etc/yamora/write.token",
    timeout=5,
    retry_timeout=30,
)
request_id = secrets.token_hex(16)
try:
    client.patch("manifests", "counter", {"$inc": {"count": 1}}, request_id=request_id)
except YamoraUncertainWriteError as error:
    # Retain error.request_id and the exact operation/preconditions for recovery.
    # Reissuing the same primitive with those bytes recovers its durable receipt.
    raise
```

Seeds are 1–9 distinct numeric IPv4 loopback/RFC 1918 host/port pairs, validated
before networking. Verified TLS 1.3 and hostname/IP verification are mandatory.
The driver sends credentials only to these explicit endpoints. It never follows
HTTP redirects or accepts advertised URLs. Discovery validates the minimal
leader response and treats it as advisory: stale leaders that reject operations
cause discovery to advance to other seeds. Each discovery attempt gets a share
of the remaining time so a slow first seed cannot consume the whole budget.

`timeout` bounds each attempt (default 1.5 seconds, maximum 30). `retry_timeout`
bounds retry admission (default/max 30 seconds); at most 32 routing attempts
occur, with backoff increasing from 50 milliseconds to one second between
attempts. This leaves time for an elected leader to establish quorum/application.
Socket deadlines use the remaining budget, and a joined watchdog shuts
down a separately owned raw socket on expiry, including when response bytes keep
arriving. TCP setup and TLS handshake share the same remaining setup budget;
expired results are rejected. With multiple seeds, dispatched requests get at
most half the remaining retry budget to reserve time for failover. Each logical
call owns its immutable request bytes,
preconditions and request ID. The client supports concurrent calls.

PUT, PATCH, DELETE, `transaction` and `set_indexes` accept an explicit
`request_id`. If omitted, the cluster driver creates a new nonzero random ID
once per logical write. Transport failures and HTTP 503 trigger bounded discovery
and replay with the same ID/body/preconditions. Exhaustion raises
`YamoraUncertainWriteError` with its `request_id`. A subsequent authentication
failure after a lost response also retains that ID. Unexpected success statuses,
redirects, 5xx failures and HTTP 408 retain the ID even on the first attempt;
only initial 4xx rejections other than 408 retain their ordinary status. Declared-short replies are treated as
transport failures; malformed successful write JSON, media types or revisions
retain the write ID in an uncertainty error. Error messages omit response bodies
and credentials. Reads also rediscover after transport failures or 503.

For recovery across process restarts, persist the ID **before** sending, together
with the exact primitive request and preconditions. A new operation needs a new
ID. For catalog workflows requiring durable manual recovery, use `set_indexes`
with known definitions/revision: `create_index`/`drop_index` are convenience
read/modify/write helpers, and invoking one again can recompute its request.
Continuous HTTP feeds acquire a fresh majority-confirmed page on every heartbeat;
see [publication and resume](replicated-publication.md) for reconnect semantics.

## Go cluster driver

The [standard-library Go driver](../drivers/go/README.md) accepts explicit
`Config.Seeds` with verified `TLSConfig` and bounded `RetryTimeout`. It uses
trusted-seed discovery, fair probe deadlines and the same exact-request retry
contract. `WithRequestID(ctx, id)` assigns a caller-persisted identity to one
primitive write; otherwise the cluster driver generates one. An
`UncertainWriteError` retains `RequestID`, including when a successful receipt
is malformed or a later authentication failure follows a lost reply. Caller
context cancellation covers TCP setup, TLS handshake and response delivery.
Standalone clients keep their prior retry policy. See the driver README for
configuration and manual recovery examples.

## Verification

Real three-process HTTPS tests exercise majority writes, byte-exact CRLF/comment
preservation, transactions, concurrent increments, a 3 MiB document, leader kill
and restart, original-response retries, shared feed history, isolated leader
rejection, follower rejection, scoped authorization, invalid/repeated request
IDs and configuration/mode/lock rejection. These extend the native controller,
application crash-boundary, peer-identity and journal recovery tests described
in [consensus.md](consensus.md). They do not establish production availability,
online maintenance, sharding, or MongoDB parity.
