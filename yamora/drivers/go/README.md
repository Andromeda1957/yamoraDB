# YamoraDB Go driver

This module uses only the Go standard library. It speaks the existing HTTP API
and offers an additive TLS binary source-CRUD client.
The C daemon requires no Go runtime or additional library. Go 1.23 or newer is
required; CI pins Go 1.27.3.

The module path is
`github.com/Andromeda1957/yamldb/yamora/drivers/go`. This branch has no published
driver release. An application can use a local checkout while evaluating it:

```sh
go mod edit -require=github.com/Andromeda1957/yamldb/yamora/drivers/go@v0.0.0
go mod edit -replace=github.com/Andromeda1957/yamldb/yamora/drivers/go=/absolute/path/to/yamora/drivers/go
```

Provide private read/write credentials from the application's secret store:

```go
import (
    "context"
    "net/netip"

    yamora "github.com/Andromeda1957/yamldb/yamora/drivers/go"
)

client, err := yamora.New(yamora.Config{
    Address: netip.MustParseAddrPort("127.0.0.1:8765"),
    ReadToken: readToken,
    WriteToken: writeToken,
})
if err != nil { return err }
defer client.Close()

ctx := context.Background()
stored, err := client.Put(ctx, "services", "api",
    []byte("# production\nreplicas: 3\n"), yamora.WriteOptions{CreateOnly: true})
if err != nil { return err }
document, err := client.Get(ctx, "services", "api", stored.Revision)
// document.Source contains exact original YAML; document.ETag guards later edits.
```

`Get`, `Put`, `Patch`, and `Delete` retain raw YAML and support ETag conditions.
`Collections` and callback-based `Documents` support revision checks and bounded
pagination. A concurrent source revision aborts a document scan; previously
visited callbacks cannot be undone.

`Query` supports filters, projections, compound sort, count, explanation, and
revision-pinned cursors. Use `Sort`, a sequence of `SortField`, for ordered sort
priority. Row values remain `json.RawMessage`, preserving signed 64-bit integer
tokens; decode into typed structures or use a decoder with `UseNumber`.
`Indexes`, `SetIndexes`, `CreateIndex`, `DropIndex`, and `Transaction` expose the
native catalog and atomic batch APIs. Catalog convenience edits use a revision
precondition so they cannot silently overwrite another catalog writer.

For [online catalog replacement](../../docs/online-indexes.md), use
`StartIndexBuild(ctx, definitions, revision)`, then `WaitIndexBuild(ctx, job.ID)`
and check `Status == "succeeded"`. `IndexBuild` reads progress and
`CancelIndexBuild` requests cancellation. Cancelling a local wait leaves the
remote job running. A job's successful revision describes its own publication,
even when later writes advance the database. Submissions are never retried.

`Aggregate(ctx, collection, pipeline, revision)` streams native disk input into
group, bucket, count, and facet reducers. Reduced objects remain
`json.RawMessage`; `DocumentsExamined` reports source scan work. The optional
revision is `""` when unpinned. Use `Sort` inside `$sort` to preserve compound
priority. See the [supported stages and capacity limits](../../docs/aggregation.md).

`Health`, `Ready`, `Stats`, and `Metrics` expose service observations.
`Changes` obtains a native checkpoint or a bounded page of complete commits.
`FollowChanges` drains available commits, optionally polling continuously, and
returns the last successfully handled token. Commit consumer effects and that
token together in the consumer's own storage. Reset markers return
`ErrResnapshotRequired` without advancing past the boundary.

`Search(ctx, collection, Search{Index: "words", Text: "rollback deploy"})` merges
native text postings. Create a text index with `Index{Type: "text", Fields:
[]string{"$source"}, ...}` to include YAML comments, or select value paths.
Results use ascending IDs; scores count matched distinct terms. See
[full-text search](../../docs/full-text-search.md) for Unicode semantics and
the format-4-or-newer requirement. Catalog convenience edits retain text types.

`StreamChanges(ctx, after, StreamOptions{}, visit)` continuously receives complete
commits over a bounded chunked NDJSON session. Zero options select 30 seconds,
1-second heartbeats and 100 commits per page. The return token advances only
after `visit` succeeds; reset markers return `ErrResnapshotRequired` before the
callback. Persist effects and token together and reconnect explicitly from that
durable position. Context cancellation interrupts reads, including slow partial
pages. See [continuous change sessions](../../docs/change-streams.md).

For native replicas using format 3 or newer:

```go
_, err := destination.ReplicateFrom(ctx, source)
if err != nil { return err }
_, err = destination.FollowReplication(ctx, source,
    yamora.FollowOptions{Continuous: true}, nil)
```

`ReplicateFrom` streams a stable source into invisible staging, checking both
revision and source checkpoint before publication. `ReplicateChangesFrom`
catches up once; `FollowReplication` can continue polling. Each transfer uses
bounded apply requests. The destination stores data and upstream progress
atomically. After a lost commit response, start a new call: the driver reads
that durable position before transferring another change. Expired/foreign
tokens and reset markers require explicit bootstrap. The Go bootstrap helper
requires a native source and destination with change-feed support; Python retains the legacy
backend compatibility copy path.

`StreamReplication(ctx, source, StreamOptions{}, visit)` applies one continuous
session from the destination's stored position. Its optional visitor runs after
each replica commit. A visitor error returns the already committed position and
count; it cannot undo that publication. Each new call resumes from the server,
including after an uncertain commit acknowledgement. Session expiry is a normal
return; reset markers and expired history require explicit bootstrap.

Every request accepts cancellation and has a configurable timeout, defaulting
to five seconds. The driver restricts connections to numeric IPv4 loopback or
RFC1918 addresses, ignores proxy environment variables, rejects redirects,
bounds payloads, and does not retry standalone writes. A transport error during mutation
can have an uncertain outcome; use the durable replica position or read and
reconcile document state before sending another mutation. The daemon's current
protected-network transport requirements still apply. Set `Config.TLSConfig`
to use [verified TLS 1.3/mTLS](../../docs/tls.md); insecure verification and older
explicit protocol settings are rejected. The daemon uses system OpenSSL while
the driver continues to use only Go's standard library.

For the experimental [native replica-set profile](../../docs/replica-sets.md),
configure `Seeds` instead of `Address`, with a verified `TLSConfig`:

```go
client, err := yamora.New(yamora.Config{
    Seeds: []netip.AddrPort{
        netip.MustParseAddrPort("10.20.0.11:8765"),
        netip.MustParseAddrPort("10.20.0.12:8765"),
        netip.MustParseAddrPort("10.20.0.13:8765"),
    },
    TLSConfig: verifiedTLS,
    ReadToken: readToken,
    WriteToken: writeToken,
    Timeout: 5 * time.Second,
    RetryTimeout: 30 * time.Second,
})
if err != nil { return err }
defer client.Close()

// Persist this nonzero 32-digit lowercase hex ID and the exact operation first.
ctx, err := yamora.WithRequestID(context.Background(), persistedRequestID)
if err != nil { return err }
_, err = client.Patch(ctx, "manifests", "counter",
    map[string]any{"$inc": map[string]any{"count": 1}}, "")
var uncertain *yamora.UncertainWriteError
if errors.As(err, &uncertain) {
    // Retain uncertain.RequestID and recover the same request/preconditions.
    return err
}
```

There must be 1–9 distinct numeric private IPv4 seeds. Only those configured
endpoints receive credentials; discovery never follows redirects or advertised
URLs. Each discovery probe gets a share of the remaining context deadline.
The server still proves quorum for every document read/write. A stale leader's
503 triggers discovery of other seeds. `RetryTimeout` defaults to 30 seconds and
cannot exceed 30; `Timeout` retains its normal five-second default and 30-second
maximum. The caller's context can end either budget sooner, including during TCP,
TLS or a slowly arriving response. With multiple seeds, each dispatched request
gets at most half the remaining retry budget, reserving time for rediscovery. At most 32 routing attempts occur, with
backoff increasing from 50 milliseconds to one second between attempts. This
avoids exhausting retries while an elected leader waits for quorum/application.

The cluster client creates one random request ID per logical write when none
was assigned by `WithRequestID`. PUT, PATCH, DELETE, transactions and complete
catalog replacements retry transport failures or 503 with their original owned
bytes, ID and preconditions. Exhaustion, malformed successful receipts, or an
authentication failure after a possibly committed attempt return
`UncertainWriteError`, retaining the ID. Unexpected success statuses, redirects,
5xx errors and HTTP 408 also retain the ID because they cannot prove rejection.
Initial 4xx errors other than 408 retain `HTTPError`; a later rejection after a
possibly committed attempt still retains the uncertain write ID. Reads also rediscover after transport failures or 503.

A new logical write needs a new ID/context. For recovery across application
restarts, persist the ID and exact primitive request **before** sending. Retry
`SetIndexes` with known definitions and revision; `CreateIndex`/`DropIndex` are
read/modify/write helpers and a fresh invocation can compute a different request.
`WithRequestID` also forwards an explicit ID through a standalone client without
enabling automatic retries or standalone deduplication. The initial cluster
profile rejects bulk replica transfer, online index jobs and continuous HTTP
feeds; paged `Changes` remains supported. Driver calls are safe concurrently.

From the repository root, with `TMPDIR` set to an owned disk-backed test root:

```sh
make -C yamora go-test
```

This runs race checks and integration against the actual native daemon on
OS-allocated ports. In the module directory, `go test ./...` requires
`YAMORA_TEST_BINARY` to name an absolute native daemon path: binary fixtures
fail when it is missing. CI requires integration tests. Linux execution is verified;
macOS and Windows driver compilation is checked separately from daemon support.
The HTTP client remains separate from binary source CRUD. Binary SDK parity,
shared transport conformance, binary cluster routing, and sharding remain open.

## TLS binary source CRUD

`NewBinary(BinaryConfig)` speaks the frozen [native binary listener](../../docs/binary-runtime.md)
on a separately configured numeric loopback/RFC1918 IPv4 endpoint. This additive
API provides `Get(ctx, collection, document, revision)`,
`Head(ctx, collection, document, revision)`,
`Put(ctx, collection, document, source, WriteOptions)`, and
`Delete(ctx, collection, document, etag)`. It reuses `Document`, `Mutation`,
`WriteOptions`, `HTTPError`, and `WithRequestID`. HEAD returns `BinaryHead`
with representation `Length`, unquoted `ETag`, and `Revision`; it transfers no
YAML DATA. DELETE accepts only a terminal 204 with an empty body.

```go
binary, err := yamora.NewBinary(yamora.BinaryConfig{
    Address: netip.MustParseAddrPort("10.20.0.11:7401"),
    TLSConfig: staticTLS, // optional client certificate and ServerName; RootCAs nil
    RootCAPEM: rootCertificatePEM, // required, copied and freshly parsed
    ReadToken: readToken,
    WriteToken: writeToken,
    Timeout: 5 * time.Second,
    MaxFrameBytes: 4096,
    MaxConcurrentCalls: 4,
})
if err != nil { return err }
stored, err := binary.Put(ctx, "services", "api", exactYAML,
    yamora.WriteOptions{CreateOnly: true})
if err != nil { return err }
head, err := binary.Head(ctx, "services", "api", stored.Revision)
```

Every call owns a new connection with verified TLS 1.3 and mandatory ALPN
`yamora-binary/1`. The endpoint is never resolved through DNS. ServerName may
select a certificate identity; it does not change the connection destination.
There are no proxies, redirects, discovery, connection pools, or automatic
replays. There is no `Close` method because calls release their own sockets and
join cancellation callbacks before returning. The default five-second timeout
(maximum 30 seconds) and caller context form one monotonic deadline covering
admission, input freezing, TCP, TLS, HELLO, all fragments, response validation,
and END. Cancellation closes only the current call's socket. It cannot roll
back work already executing on the daemon.

`NewBinary` requires `BinaryConfig.RootCAPEM`: 1..32 certificate PEM blocks,
at most 64 KiB total. It copies those bytes and parses new certificate objects
into a private root pool. Empty/malformed bundles, PEM headers, other block
types, leading/trailing garbage and excess certificates/bytes are rejected.
There is no system or global fallback-root lookup. `TLSConfig.RootCAs` must be
nil, even when `RootCAPEM` is present: `CertPool.Clone` can retain caller-owned
certificate objects and blocking constraint callbacks, so opaque pools cannot
provide frozen trust or bounded callback lifetimes.

The supported `TLSConfig` still supplies static `ServerName` and one optional
client certificate/private key. Certificate DER and supported standard-library
private keys are copied. TLS callbacks, custom clocks/randomness, key logging,
external signers and session caches are rejected. Provision PEM roots and mTLS
identity explicitly; certificate rotation requires a new client. Bearer
credentials remain mandatory per request when the daemon requires them; mTLS
alone does not grant storage permission. Binary credential syntax follows the
wire contract: empty means omitted, otherwise 1..512 printable non-space ASCII
bytes. Keep credentials in the application's secret store.

`MaxFrameBytes` is 4096..65536 (default 65536), and negotiated frames never
reduce the 16 MiB document ceiling. Legacy stores still reject documents above
256 KiB. `MaxConcurrentCalls` is 1..4 (default four); waiting calls observe their
original deadline and allocate no owned upload copy until admitted. Each admitted
call retains at most one source copy and one bounded response body, plus one
frame (64 KiB maximum), metadata (2048 bytes maximum), and TLS/runtime overhead.
Acknowledgements and error representations are limited to 4096 bytes. At most
16 PING/GOAWAY controls are handled per call. The native daemon independently
limits sessions/tickets; other clients can still exhaust its capacity.

GET preserves original UTF-8 YAML bytes, including CRLF, comments, Unicode and
integer scalar spelling. The driver validates strict frame types, flags,
stream IDs, metadata field ordering/widths, lengths and method/status/body
correlation. PUT additionally requires five distinct JSON receipt fields and
agreement of collection, document, ETag and revision with the request and binary
metadata. Request IDs must be echoed exactly whenever sent, including errors.
A complete RESPONSE/DATA/END sequence and semantic validation are required for
success. Remote bodies and credentials never appear in returned errors.

Every mutation freezes the source, preconditions and a nonzero 128-bit request
ID before network I/O. `WithRequestID` supplies a persisted lowercase hex ID;
otherwise the client generates one using `crypto/rand`. An ambiguous dispatched
mutation returns `*BinaryUncertainWriteError` with `RequestID` and `Envelope()`.
The envelope retains method, collection, document, `WriteOptions`, and a
copy-returning `Source()` without credentials. Its default formatted output
redacts source. Persist that sensitive source explicitly if crash recovery is
needed. Validated terminal 4xx rejections (except HTTP-equivalent 408) retain
`HTTPError`; transport failures, generic ERROR, malformed/partial receipts,
timeouts, and 5xx responses retain typed uncertainty. The server's current
ERROR code 1 is generic and proves no storage outcome or retry policy.

Use `errors.Is` with `ErrBinaryProtocol` or `ErrBinaryTransport` to classify
binary exchange failures, including causes wrapped by `BinaryUncertainWriteError`.
Deadlines and cancellation retain `context.DeadlineExceeded` and `context.Canceled`;
validated status rejections retain `*HTTPError`. Classification needs no error-text
parsing and does not change whether a dispatched mutation may have committed.

An ID on a standalone daemon **does not provide deduplication**. Reconcile its
state before deciding how to recover. A native replica set can recognize the
same ID and exact primitive request across binary/HTTP. A caller may explicitly
persist the operation and use the existing HTTP cluster client with
`WithRequestID` against its separately trusted, configured seeds; never substitute
a new ID, changed source, or changed preconditions. Binary error/response metadata
cannot add credential destinations or prove quorum. This binary client implements
no recovery bridge, cluster discovery, retry/failover helper, or cross-transport
recovery guarantee. Such recovery is not qualified by this slice; three-node
lost-receipt failover/recovery remains a separate gate. PATCH, query, catalog,
transaction and feed operations continue to use the HTTP API.

Run the binary tests with a required, prebuilt native daemon; a missing path
fails instead of skipping. The daemon is not modified or rebuilt by these tests,
and its SHA-256 is checked before and after each native fixture. For example,
from the Go module directory, with TMPDIR set to the active task's owned
disk-backed scratch root:

```sh
YAMORA_TEST_BINARY=/absolute/path/to/immutable/asan/yamora \
  GOMAXPROCS=2 GOFLAGS=-p=2 go test -race ./... -count=1
GOMAXPROCS=2 GOFLAGS=-p=2 go vet ./...
```

The native binary fixtures enforce fatal ASan/UBSan options and cleanly join
owned daemons. Qualification includes native mTLS/roles, exact-source HTTP
interoperability, ETag guards, HEAD/204, 16 MiB over 4 KiB frames, the legacy cap,
native ticket exhaustion, and actual committed receipts lost at three boundaries.
Independent literal wire goldens and verified hostile TLS peers cover malformed
frames/metadata, contradictory receipts, cancellation and a single total deadline.
Root regressions cover post-construction CA validity/public-key and PEM-byte
mutation, opaque constraint rejection, and bounded callback/call teardown.
Linux execution is qualified here; other platform runtime qualification and
broad binary SDK/shared conformance remain open.

## Local v0.1.0 artifacts

The local packaging version is **0.1.0**, independent of Python’s existing
0.3.0 project. No registry release or new module path is implied.

```sh
python3 yamora/drivers/go/build_package.py --output /absolute/private/go-artifacts
```

The stdlib-only builder emits `yamora-go-0.1.0.tar.gz` and a canonical module
zip, `.mod`, `.info` and version list under `proxy/`. Its explicit
`package-files.txt` includes all twelve public runtime source files, go.mod,
README, VERSION, the exact MIT LICENSE and `examples/crud_tls/main.go`. It
excludes repository-dependent tests and conformance adapters. Output must be
empty and outside the source directory.

A private application can require this module at `v0.1.0`, set GOPROXY to
`file:///absolute/private/go-artifacts/proxy`, use a private module cache and
GOSUMDB=off, and build without a checkout `replace`. The extracted source
archive builds offline with `go build ./examples/crud_tls`.

The example accepts `--port`, `--ca`, optional paired `--cert`/`--key`,
`--read-token-file` and `--write-token-file`. It uses verified TLS 1.3, creates
`packaged/go-example`, reads exact CRLF/Unicode YAML, performs an ETag update,
checks stale rejection and deletes. Endpoint and test identity can be changed
with `--host`, `--collection` and `--document`. Use a disposable standalone
native store. It prints no credentials/source and never retries uncertain
mutations; reconcile a failed run before reusing its document identity.

Focused acceptance: `python3 -m unittest yamora.drivers.go.tests.test_package -v`.
Supply `YAMORA_PACKAGE_GO` (or Go on PATH) and `YAMORA_TEST_BINARY` pointing
to the immutable fatal-ASAN/UBSAN daemon. Missing prerequisites fail. Tests
consume the actual module through the private file proxy and independently
compile the source archive, require stdlib-only dependencies and execute the
public example with real native mTLS. Wrong trust must reject after valid
controls. The supplied daemon digest remains unchanged and owned resources
are cleaned. Private tools/caches belong in task scratch; managed provisioning
and tests share one invocation when the task container overlay is ephemeral.

These local Linux artifact/example checks leave both shared conformance profile
runs against installed artifacts with SDK checkout excluded to parent-owned
adapter wiring. They do not establish a published package or broad SDK gate.

## Replication source preflight

`source.RequireReplicationSource(ctx)` returns readiness or the sentinel
`ErrSchemaPolicyReplicationUnsupported` (test with `errors.Is`). An advertised
non-boolean fails; absent fields support older policy-free servers. Bootstrap,
follow and stream helpers preflight automatically, including checks before
commit and each incoming frame. This advisory read does not replace the native
outgoing and receiver guards during concurrent policy changes.

### Raw binary operations and page feeds

`BinaryClient.Operation(ctx, method, target, contentType, spec, conditions)` adds
negotiated schema 2 for query/aggregate/search POST, atomic transaction POST,
document PATCH and paged changes GET. `spec` and the returned `Body` are owned
raw bytes; numeric spellings are preserved. Conditions use exact `If-Match` and
`If-None-Match` keys, retaining absent versus present-empty values. Read-only
POST uses the configured read credential; transactions and PATCH use the write
credential. Existing `Get`, `Head`, `Put` and `Delete` retain schema 1.

`Feed(ctx, target, consume)` calls `consume` synchronously for each complete
validated native NDJSON page including LF. The callback owns those bytes.
Persist page effects and its `next_after` together; `checkpoint` is the tip,
not the delivered cursor. The result's `ResumeAfter` records the last accepted
callback. Return an error or cancel the context to stop. Terminal records stay
raw and observable; a normal END completes the feed. Interrupted pages are
never exposed. One absolute deadline includes admission, TLS, callbacks and
decoding; no progress refreshes it.

Both finite responses and total feed DATA are bounded to 16 MiB; acknowledgement
and error bodies are at most 4 KiB. A protocol-1 peer returns
`ErrBinaryUnsupported` before REQUEST, with no HTTP fallback. Mutation ambiguity
retains exact method, target, content type, conditions, source and request ID in
`BinaryUncertainWriteError.Envelope()`. Neither cancellation nor EOF proves
rollback. No automatic replay occurs. These raw APIs do not claim decoded
numeric-value support or the HTTP large-profile 64 MiB envelope.

The separate version-3 adapter builds with `go build ./conformance/operations`.
