# Native binary document listener

The daemon supports an opt-in TLS binary listener for native standalone stores
and replica sets. It serves document GET, HEAD, PUT and DELETE using the same
authorization, source validation, conditional writes and native execution path
as HTTP. Successful GET returns the exact stored YAML bytes. Negotiated protocol
2 additionally serves bounded query/aggregate/search, PATCH, atomic transactions
and paged/continuous change feeds under the additive [schema-2 contract](binary-messages.md#additive-operations-schema-2).
[Go](../drivers/go/README.md), [Python](python-binary.md),
[Node.js](../drivers/node/README.md), [Java](../drivers/java/README.md),
[Ruby](../drivers/ruby/README.md), [Rust](../drivers/rust/README.md),
[C++](../drivers/cpp/README.md), [PHP](../drivers/php/README.md) and
[C#](../drivers/csharp/README.md) clients support these binary document calls.
Binary cluster discovery/recovery and full transport conformance remain open.

## Enable the listener

Add `--binary-port PORT` to an existing native TLS daemon invocation. Zero asks
the operating system for an available port. For example, after initializing a
native data directory and provisioning private token and certificate files:

```sh
yamora --data-dir /srv/yamora/data --port 7400 --binary-port 7401 \
  --auth-token-file /run/yamora/read-token \
  --write-auth-token-file /run/yamora/write-token \
  --tls-cert-file /run/yamora/server.pem --tls-key-file /run/yamora/server.key
```

The option is absent by default. It requires a native disk or cluster backend
and TLS; initialization, validation, import, offline compaction and legacy
snapshot backends reject it. The existing bind-address policy applies to both
listeners. Startup reports readiness only after both requested listeners start:

```text
yamora listening on 127.0.0.1:7400 ...
binary listening on 127.0.0.1:7401
```

The binary listener requires TLS 1.3 and ALPN exactly `yamora-binary/1`.
HTTP and Raft retain separate profiles. `--tls-client-ca-file` enables mutual
TLS, and the configured CRL policy applies. A client certificate authenticates
the channel. Each request selects its bearer credential or an explicitly
mapped [certificate principal](certificate-identity.md); a supplied bearer
never falls back to certificate roles.
SIGHUP reloads the independent contexts. A failed reload retains each last
valid context; established connections retain their original context.

## Operation and receipt contract

Use the [frame contract](binary-transport.md) and strict
[document metadata schema](binary-messages.md). One connection advertises four
active streams, reduced to the peer's limit when smaller. Requests target exactly
`/v1/collections/<collection>/documents/<document>` with no query string.
GET, HEAD and DELETE carry no input body. PUT carries exact UTF-8 YAML in DATA
frames followed by END. Metadata and the declared body length must match before
execution. HEAD carries zero response DATA while retaining representation
length and ETag. DELETE 204 carries no DATA.

Administrative credentials and collection-scoped roles follow HTTP semantics.
Missing/incorrect credentials, denied collections, disabled writes, replica
write rejection, source limits and conditional preconditions retain their
native status semantics. Typed admission rejections drain the exact declared
body without allocating it, then return their response after END. The immutable
storage profile is checked before allocation: older stores retain their
256 KiB document limit; large-document stores allow up to 16 MiB.

Replica-set mutations require a nonzero 16-byte request ID. Both transports
project the same method, target, conditions, source bytes and ID into the native
write operation. An explicit retry over either transport can recover the
original durable status, body, ETag and revision even after later writes,
failover or restart. Reusing the ID with a different operation returns 409.
Reads still require confirmed leader quorum; the binary listener provides no
local-disk fallback. Standalone writes acquire no new deduplication guarantee.

Success requires a complete response followed by END. Cancellation, EOF,
ERROR, timeout or a partial response cannot prove a mutation failed. Neither
listener nor reference wire client automatically replays mutations. Cancelled
queued work never dispatches. An already executing call may commit; its
completion is suppressed for the cancelled stream and remains owned until it
actually returns. A request ID in a response must match the request exactly.

Streams have independent upload assembly, request/queue deadlines, response
positions and send deadlines. Ready replies rotate after each complete frame;
metadata and END yield too. Cancellation terminates only its selected stream.
An expired complete request receives ERROR on that stream, retaining any
executing callback until return. Malformed protocol, an expired incomplete
upload, or failed/expired pending TLS output can still close the connection and
affect all its streams. A slow socket shares TCP/TLS backpressure across its
streams; fairness cannot bypass an unfinished immutable TLS write.

ERROR currently carries the generic nonzero code `1`. A complete request's
deadline/queue expiry terminates its stream independently; malformed framing,
metadata, exhausted global capacity and expired input use bounded closing drain.
Callers must not infer a storage outcome or retry policy from
that code. It differs from a typed native RESPONSE status.

## Capacity and lifecycle

The [session module](binary-sessions.md) owns eight connections, one I/O thread,
two dispatch workers and four admitted jobs, including assembly, queued work,
executing calls, retained replies and detached work. At most two jobs wait for
dispatch. Application input and response reservations total at most 128 MiB.
Only uploads greater than 2 MiB reserve their full declared size in the shared
64 MiB HTTP/binary upload ledger; credit returns exactly once when the owned
job is freed, including cancellation and disconnect.

Local frames are at most 64 KiB; peers must accept at least 4 KiB. A 16 MiB
document spans multiple frames. Each direction retains one frame and its
ticket, with a 4 KiB control reserve and a 16 KiB coalesced input tail.
Backpressure retains the same frame and unread bytes. These are transport
buffer bounds; native caches, parsers, OpenSSL and thread overhead remain
additional memory costs.

Request timeouts are absolute and capped at 30 seconds. Upload and response
phases also respect `--io-timeout-ms`; queue wait is at most one second.
Connection idle, lifetime, request-count and drain limits are documented by the
session module. Worker dispatch receives the remaining request budget, further
capped by the configured cluster timeout. Admission uses cached immutable
profile/advisory revision metadata without acquiring backend locks. Native
responses preserve their own committed receipt revisions.

Shutdown stops admission, closes the binary runtime and joins its I/O and
dispatch threads before freeing storage, cluster or TLS owners. A blocked
filesystem call can outlive a network deadline and delay that join; it retains
its slot and reservations until it returns.

## Integration checks

Build the daemon and the real native-call fault variant with the normal
Makefile targets. The fault target is `build/yamora-binary-runtime-faults` with
the default `BUILD_DIR`. With an existing task-owned disk scratch directory,
run from the repository root:

```sh
make all build/yamora-binary-runtime-faults
TMPDIR=/var/tmp/andromeda-work/yamora-binary-storage \
  YAMLDB_BUILD_DIR="$PWD/yamora/build" \
  python3 -m unittest yamora.tests.test_binary_runtime yamora.tests.test_binary_cluster \
    yamora.tests.test_binary_multiplex -v
```

The suites require actual daemons and verified TLS. They cover byte-exact CRUD,
HTTP interoperability, permissions/mTLS, large and legacy profiles, fragmented
frames, persistent deadlines, shared upload accounting, TLS reload, capacity,
native cancellation/commit barriers, cross-transport receipts, failover, quorum
loss and full restart. Multiplex checks use one verified TLS connection for
interleaved uploads and reads, two blocked actual native calls, queued/running
cancellation, isolated queue expiry, bounded stream admission, slow-reader
fairness and shutdown ownership. The production binary contains no test gates.
`make test` and `make sanitizer-test` build the fault variant and discover these
suites. Sanitizer runs must keep fatal ASan/UBSan options enabled.

Qualification remains Linux-only. Schema 2 produces continuous feeds one native
page at a time, acquiring the next page after complete delivery of the previous
page. Query/aggregate/search responses remain bounded materialized pages from
the existing native API. Document GET instead captures an immutable source
checkpoint, validates its outer and nested checksums, raw UTF-8 and typed value
before publishing metadata, then reads at most 32 KiB per producer pull. The
typed validator uses bounded reads and comparisons rather than decoding a
second full document. HEAD performs the same validation and returns its exact
length, hash and captured revision without a body. Cluster reads capture a
confirmed application view before adopting the source checkpoint; a concurrent
write cannot replace that source or turn captured absence into a later document.
Binary envelopes/finite results and total feed bytes are limited to 16 MiB;
native large-profile HTTP request envelopes can reach 64 MiB. Existing SDKs
retain schema-1 CRUD and provide schema-2 finite operations and bounded page
feeds, with one stream per operation-owned connection. The shared conformance
profiles cover binary documents, HTTP replica receipts and binary operations;
installed-consumer qualification remains separate from native runtime tests.
