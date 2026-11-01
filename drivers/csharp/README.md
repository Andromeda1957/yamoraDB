# Yamora C# HTTP, binary TLS and bounded replica-set clients

## Local NuGet package and runnable CRUD example

`Yamora` 0.1.0 packages the existing `net10.0` library with its README,
MIT license copied verbatim from `yamora/LICENSE`, and runnable example source.
There are no external NuGet/runtime dependencies. Package metadata establishes
a local distribution foundation, without registry publication or a stable API
version promise. Qualification remains Linux x86_64, .NET SDK 10.0.402 and
runtime 10.0.13; a target framework alone does not qualify other operating systems.

From this directory with an existing owned disk-backed `TMPDIR`:

```sh
dotnet pack Yamora/Yamora.csproj -c Release --configfile NuGet.Config \
  --artifacts-path "$TMPDIR/csharp-package-build" --output "$TMPDIR/local-feed"
dotnet restore examples/Crud/Crud.csproj --source "$TMPDIR/local-feed" \
  --packages "$TMPDIR/consumer-nuget" -p:NuGetAudit=false
dotnet build examples/Crud/Crud.csproj -c Release --no-restore
```

The example references the NuGet package, rather than the source project.
For an existing native HTTPS listener, set `YAMORA_PORT`,
`YAMORA_CA_FILE`, `YAMORA_READ_TOKEN` and `YAMORA_WRITE_TOKEN` using
your secret store. The host defaults to 127.0.0.1; `YAMORA_HOST` may be a
canonical private IPv4. Set both `YAMORA_CLIENT_CERT_FILE` and
`YAMORA_CLIENT_KEY_FILE` to PEM files for mTLS. From this directory:

```sh
dotnet examples/Crud/bin/Release/net10.0/Crud.dll
```

The example creates `package-demo/csharp`, verifies exact UTF-8/CRLF YAML
bytes after create and conditional update, deletes conditionally, verifies 404,
and prints `CRUD_OK`. Set `YAMORA_COLLECTION` and `YAMORA_DOCUMENT`
to select another fresh target. An existing target fails create-only.
No uncertain mutation is automatically repeated.

The normal console runner registers `package-artifact` and `package-lifecycle`.
From this directory:

```sh
dotnet build tests/Tests.csproj -c Release --configfile NuGet.Config \
  --artifacts-path "$TMPDIR/csharp-checks" -m:1
dotnet run --project tests/Tests.csproj -c Release --no-build \
  --artifacts-path "$TMPDIR/csharp-checks" -- package-artifact
```

The same mandatory `TMPDIR` and `YAMORA_TEST_BINARY` requirements apply.
This check packs a scratch source
copy, inspects package members and dependency metadata, extracts the packaged
example into a separate consumer, restores exclusively from a fresh local feed,
compiles it, and runs against disposable native mTLS with synthetic credentials.

Package checks also require Python 3 and the repository's existing Python process
and workspace owner. Foundation orchestration supplies `PYTHONPATH` pointing to
the repository and `YAMORA_PACKAGE_TASK_ROOT=/var/tmp/andromeda-work/<task>`.
The wrapper launch is `python3 tests/package_process.py <dotnet-host> <test-assembly>`;
only this wrapper supplies the private `YAMORA_PACKAGE_WORKSPACE` for the inner
fixture. The anchor must be an existing owned, non-symlink, disk-backed task root
directly under `/var/tmp/andromeda-work`, match `ANDROMEDA_TASK` when supplied, and
contain the validated `TMPDIR`. The shared owner verifies the complete process
group before deleting the allocation, including when a tool's `Kill(true)` fails.
An uncertain stop retains the allocation and `.yamora-sdk-retained-*` marker
directly under that anchor, outside disposable ancestors. The lifecycle controls
compile the actual fixture with bounded kill and verifier faults. These test-only
source and owner settings must be excluded from artifact conformance consumers.

A .NET 10 library using only `HttpClient`, `System.Text.Json`, sockets and system
TLS. No external NuGet dependencies, external database or YAML parser. Native C storage is
unchanged. `Client` retains its standalone asynchronous API; `ClusterClient` adds
explicit replica-set routing and immutable mutation recovery. This slice does
not complete the enterprise roadmap.

Reference the `Yamora/Yamora.csproj` project from your application. From the
repository root, build and run the dependency-free console checks:

```sh
dotnet build drivers/csharp/tests/Tests.csproj -c Release --configfile drivers/csharp/NuGet.Config
dotnet run --project drivers/csharp/tests/Tests.csproj -c Release --no-build
```

Set `TMPDIR` to an owned disk-backed test directory and `YAMORA_TEST_BINARY`
to an existing absolute native daemon executable before running checks. A
missing daemon fails the normal runner, including when selecting named checks. The runner never builds or changes that binary. It initializes fresh
roots and token files under `TMPDIR`, starts its own daemons on ephemeral loopback
ports, verifies graceful shutdown/sanitizer diagnostics and deletes the roots on
exit. The runner also verifies that the supplied daemon bytes remain unchanged.
Pass check names after `--` to select individual console checks.
The console entry point and checks live in `tests/DriverTests.cs` and
`tests/ReviewTests.cs`, `tests/ClusterTests.cs`, `tests/ClusterNativeTests.cs` and
the `tests/Binary*.cs` files.
All are registered in `Program.Main` and included through the normal project
source glob. Run `Tests.dll` or `dotnet run`; `dotnet test` alone does not execute
this console harness. The existing shared `csharp-test` Make target invokes it.

```csharp
using System.Text;
using System.Text.Json;
using Yamora;

using var db = new Client(new ClientOptions {
    Endpoint = "https://127.0.0.1:9090",
    ReadToken = readCredential,       // supplied by your secret store
    WriteToken = writeCredential,
    TrustedRoots = [issuerCertificate],
    ClientCertificate = clientIdentityWithPrivateKey,  // for mTLS
    ClientIntermediates = [intermediateCertificate],  // if the identity needs one
});
using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(3));

byte[] yaml = Encoding.UTF8.GetBytes("# kept exactly\r\nname: Ada\r\n");
var stored = await db.PutAsync("people", "ada", yaml,
    new WriteOptions(CreateOnly: true), deadline.Token);
var document = await db.GetAsync("people", "ada", stored.Revision, deadline.Token);
// document.Source has exactly the original bytes, including CRLF and comments.

using var patch = JsonDocument.Parse("""{"$set":{"name":"Ada Lovelace"}}""");
var updated = await db.PatchAsync("people", "ada", patch.RootElement,
    new WriteOptions(document.ETag), deadline.Token);

using var query = JsonDocument.Parse("""{"filter":{"name":"Ada Lovelace"},"limit":10}""");
var result = await db.QueryAsync("people", query.RootElement, deadline.Token);
// JsonElement retains integer tokens; use GetInt64(), not a double conversion.
await db.DeleteAsync("people", "ada", new WriteOptions(updated.ETag), deadline.Token);
```

ETags and revisions passed to this API are **unquoted** 16-character lowercase
hexadecimal strings. `WriteOptions` quotes ETags in `If-Match`; `CreateOnly`
sends `If-None-Match: *`. The two conditions cannot be combined. A stale condition
returns `HttpError` with `StatusCode == HttpStatusCode.PreconditionFailed`.
PUT sends the exact provided UTF-8 bytes, snapshots the input buffer, and never
parses/reserializes YAML. PATCH semantics and source preservation belong to the
daemon. Raw GET also permits byte-exact legacy source outside the typed profile.

The API exposes these cohesive HTTP groups:

| Methods | Behavior |
| --- | --- |
| `HealthAsync`, `ReadyAsync`, `StatsAsync`, `MetricsAsync` | Metadata and metrics |
| `CollectionsAsync`, `DocumentsAsync` | Sorted names and bounded document pages |
| `GetAsync`, `PutAsync`, `PatchAsync`, `DeleteAsync` | Raw YAML and conditional mutations |
| `QueryAsync`, `AggregateAsync`, `SearchAsync` | Read-token JSON operations |
| `IndexesAsync`, `SetIndexesAsync` | Read/replace the entire index catalog, optionally guarded by snapshot revision |
| `StartIndexBuildAsync`, `IndexBuildAsync`, `CancelIndexBuildAsync` | Explicit online catalog job steps |
| `TransactionAsync` | Atomic JSON operation envelope, optional stable request ID |
| `ChangesAsync`, `ReplicationStatusAsync` | Explicit durable feed pages and replica position |
| `BeginReplicationAsync`, `ApplyReplicationAsync`, `CommitReplicationAsync`, `AbortReplicationAsync` | Low-level staging calls |
| `BeginFollowAsync`, `ApplyFollowAsync`, `CommitFollowAsync`, `AbortFollowAsync` | Low-level incremental replication calls |
| `LeaderAsync`, `ClusterStatusAsync` | Advisory metadata only, with daemon authorization |

JSON calls take `JsonElement` envelopes matching the HTTP protocol. For example,
aggregation takes `{"pipeline":[...]}`, indexes take `{"indexes":[...]}`, and a
transaction takes `{"operations":[...]}` with an optional `revision`. Input
object order is retained for compound sort maps. Duplicate keys and invalid
Unicode reject locally. The daemon validates field paths, operators and semantic
limits; JSON results intentionally retain the daemon's object shape. This is not
a complete typed validator for every response envelope. Do not infer successful
replication or job publication merely from receiving a JSON object; inspect its
status, session and checkpoint fields.

For consistent paging, pass the first page's `Revision` on every subsequent
`DocumentsAsync` call and pass its `NextAfter` as `after`. The client requires a
revision with a cursor and rejects changed revisions and non-progressing name
pages. Query/search envelopes likewise require `revision` with `after`. The
client performs no implicit page loop. Prior results cannot be undone if a later
page observes a concurrent write.

Endpoint spelling is checked **before** .NET URI/IP normalization: only canonical
numeric IPv4 loopback or RFC1918, explicit port 1–65535, `http` or `https`, and an
optional final slash. DNS names, shortened/octal/hex IPs, public/link-local IPs,
IPv6, userinfo, URL prefixes, query strings, fragments, escaping and backslashes
reject. Document/collection path IDs are 1–128 lowercase ASCII letters, digits
or hyphens. Credentials are empty or 32–512 ASCII bytes from `!` through `~`;
health never sends a credential. Other reads/query POSTs use only the read
credential; mutations use only the write credential.

Every call uses HTTP/1.1 and a fresh connection/handler, with redirects, proxies,
cookies, default credentials and decompression disabled. A per-operation connect
guard rejects a second connection attempt, including automatic runtime replay.
For standalone `Client`, no status, leader hint, connection error or dropped
acknowledgement triggers a driver retry. No global .NET switches or certificate stores are changed by the
library. Concurrent calls are independent. Dispose rejects new calls immediately, then
releases owned trust material after existing calls finish. HTTP handlers and
cancellation registrations survive public decoding and its final return guard. Supplied certificates are cloned; mTLS private keys must be
exportable for that owned clone. Supply the mTLS chain through `ClientIntermediates`
(at most 64 certificates); the client prebuilds its owned certificate context
offline. Client-certificate selection therefore cannot fetch AIA issuers outside
the request deadline. This follows the runtime's [offline certificate context
contract](https://learn.microsoft.com/en-us/dotnet/api/system.net.security.sslstreamcertificatecontext.create?view=net-10.0).

HTTPS requires TLS 1.3 and normal peer verification, including numeric IP SAN,
validity, chain and server-auth EKU. Supplied trust roots replace system roots for
this client only; no callback can bypass verification. Certificate downloads,
renegotiation and TLS resumption are disabled. Revocation checks are not provided;
certificate-to-role mapping and trust rotation are later roadmap work. Unsupported
TLS 1.3/mTLS platforms fail closed; there is no TLS 1.2 fallback. Plain HTTP is an
explicit local/private option, not a fallback after HTTPS failure.

Requests and responses cap at 64 MiB each, YAML sources at 16 MiB, response
headers at 16 KiB, JSON depth at 64 and JSON value count at 100,000. Configurable
byte caps may only lower those limits. Default operation deadline is five seconds,
configurable up to 30 seconds, including connect/TLS/headers/body, public JSON
decoding/validation and a final monotonic clock check; cancellation can shorten
it. Synchronous decoding is cooperative at that return guard. The optional
`Yamora` ActivitySource emits `Yamora.PublicDecode` without bodies, URLs or
credentials; synchronous tracing consumers remain within the operation deadline. Bounds also apply to chunked or unknown-length bodies. Truncation,
unexpected encodings/media, malformed JSON and invalid revisions fail closed.
Raw response framing permits absent `Transfer-Encoding` or sole `chunked`, and
an absent or unique valid decimal `Content-Length`; transfer encoding and content
length cannot coexist. Invalid raw fields reject even if .NET's parsed property
would treat them as absent. Malformed committed transaction counts retain
`OutcomeMayBeCommitted` instead of leaking a JSON type exception.
Older daemons can enforce smaller limits than the driver. Large JSON inputs can
temporarily require both source and escaped output buffers; no streaming-memory
or pagination-consistency guarantee beyond the documented bounded calls is made.

`TransportError.OutcomeMayBeCommitted` (or `RequestCanceled`'s same property)
marks an uncertain mutation. A malformed mutation receipt or server 5xx also
marks uncertainty. Errors omit remote bodies, credentials and URLs. An error is
not proof of rollback. Reconcile the served state and durability condition before
submitting another write. For standalone `Client`, explicit nonzero 32-lowercase-hex `RequestId` values
can be sent for supported mutations; it never generates IDs or replays requests. Index catalog/job and replication operations can
have profile-specific restrictions; the daemon's rejection remains authoritative.

## Replica sets

```csharp
using var db = new ClusterClient(new ClusterOptions {
    Seeds = [new("https://10.0.0.11:9090", 1),
             new("https://10.0.0.12:9090", 2),
             new("https://10.0.0.13:9090", 3)],
    ClusterId = "1234567890abcdef1234567890abcdef", Voters = 3,
    TrustedRoots = [issuerCertificate], ClientCertificate = clientIdentityWithPrivateKey,
    ReadToken = readCredential, WriteToken = writeCredential,
    Timeout = TimeSpan.FromSeconds(5), AttemptTimeout = TimeSpan.FromSeconds(1),
});
try {
    await db.PutAsync("people", "ada", yaml, new(CreateOnly: true), deadline.Token);
} catch (UncertainWriteException error) {
    // Retain these original inputs for explicit recovery.
    // Recover only this original request; do not construct a new mutation ID.
    ClusterReceipt original = await db.RecoverAsync(error.Recovery, recoveryCancellation);
}
```

Seeds are 1–9 distinct canonical private/loopback IPv4 HTTPS endpoints, each
bound to an expected node ID in `1..Voters`. Voters must be odd, 3–9; cluster
identity is nonzero 32-character lowercase hex. Lists, roots, client identity
and intermediates are copied. Cached routes only prioritize discovery: **every
operation** rechecks strict `/v1/cluster/status` integer node/leader/voters/term
and role, followed by an empty `/v1/changes` checkpoint whose three feed tokens
carry the configured cluster identity. Fair budgets reserve time for later seeds
and mutation dispatch. There are at most 32 exchanges, with cancellable bounded
backoff, all under the one public operation deadline. No redirect or leader
address hint ever supplies a credential destination. Quorum-bound discovery
can reject before any mutation is dispatched.

**Trust boundary:** the native status API does not attest a cluster UUID. The
client binds authenticated TLS endpoints to their configured node IDs and checks
the feed identity, relying on trusted seed operators and TLS issuers. This is
not cryptographic UUID attestation and does not prevent a trusted server from
lying or rebinding between discovery and dispatch. TLS identity, node binding
and feed binding must all be administered together. Revocation remains outside
this stage.

Document PUT/PATCH/DELETE, transactions and synchronous index catalog PUT are
supported. Online index job and replication orchestration methods reject with
405 before I/O. Changes are explicit finite pages; no continuous feed is
implemented. All inherited async signatures and `CancellationToken` arguments
remain available. All JSON inputs are cloned and serialized, operation counts
and conditions frozen, and supplied or generated nonzero 32hex request IDs fixed
before the first await. Raw YAML and numeric tokens remain exact. Every replay
uses the same method, path, payload, conditions and ID.

A dispatched transport/TLS/framing failure, invalid semantic receipt, cancellation,
deadline, redirect, unexpected success, HTTP 408 or 5xx yields typed recoverable
uncertainty. Transport failures and 503 may retry within the remaining budget;
malformed receipts stop for explicit recovery. An initial definitive 4xx rejection
(except 408) is certain. Prior dispatched uncertainty survives later rejection,
failed discovery and pre-canceled recovery. `UncertainWriteException.Recovery`
holds immutable, credential-free original inputs; its `Body` returns a copy.
Recovery uses the receiving client's configured credentials and requires matching
cluster ID and voter count. Store recovery inputs as sensitive application data
if their payload is private. The library does not provide a persistence format.

Receipt validation stays inside the recovery boundary: expected HTTP status
(including create-only PUT 201 and If-Match PUT 200), stored/committed status,
document/collection identity, exact integer count, revision agreement and ETag
agreement. Replays may legitimately return original revisions and receipts after
the database advances; they are never rewritten to the current head.

Cluster framing requires one explicit decimal `Content-Length`; chunked and
close-delimited replies reject. Standalone framing remains as described above.
Both profiles reject identity/framing duplicates and response trailers. The only
repeated cache value accepted is identical `Cache-Control: no-store`, needed for
native diagnostics; conflicting repeated cache policies reject.

The normal runner covers hostile real HTTPS, input disposal and recovery,
tracing-held decoding cancellation/deadline checks, concurrent disposal/cancellation,
and real three-node mTLS failover. Native tests assert exact committed source
before a lost-reply retry, hold six identical-ID requests at dispatch and reply
barriers, exercise distinct IDs, lose quorum, restart all nodes, and replay
original receipts without rewriting YAML. Native stderr is checked for
ASAN/UBSan diagnostics. Only Linux x86_64, .NET SDK 10.0.402/runtime 10.0.13 has
been qualified here; Windows/macOS, shared cross-driver
conformance, high-level continuous replication and packaging guarantees remain
open. Parent `yamora-binary-storage` owns combined review, integration, shared
runner/toolchain wiring and immediate child cleanup.

## Binary document transport

`BinaryClient` is a separate .NET 10 standard-library client for the native TLS
binary listener. HTTP `Client` and `ClusterClient` retain their existing API and
serve their existing HTTP operations. Binary document calls
support GET, HEAD, PUT and DELETE only, on one explicitly configured destination.

```csharp
using var binary = new BinaryClient(new BinaryClientOptions {
    Endpoint = "https://10.0.0.11:7401", // canonical private IPv4, explicit port
    ServerName = "node1.internal",      // trusted certificate identity; no DNS routing
    TrustedRoots = [issuerCertificate],
    ClientCertificate = clientIdentityWithPrivateKey, // when the listener uses mTLS
    ClientIntermediates = [intermediateCertificate],
    Timeout = TimeSpan.FromSeconds(5),
    MaxFrameBytes = 4096,
    MaxConcurrentCalls = 4,
});
byte[] authored = Encoding.UTF8.GetBytes("# exact source é\r\nn: 01\r\n");
BinaryResponse stored = await binary.PutAsync("config", "one", authored,
    writeCredential, ifNoneMatch: "*", ct: deadline.Token);
BinaryResponse read = await binary.GetAsync("config", "one", readCredential, deadline.Token);
BinaryResponse head = await binary.HeadAsync("config", "one", readCredential, deadline.Token);
await binary.DeleteAsync("config", "one", writeCredential,
    ifMatch: '"' + stored.ETag + '"', ct: deadline.Token);
```

Unlike HTTP `WriteOptions`, binary condition arguments are **exact wire values**:
quote an If-Match ETag, use `"*"` for create-only If-None-Match, and use `null` for
absence. Present empty values and combinations pass to native validators through
`CallAsync`. Results expose unquoted lowercase ETag/revision strings, status,
request ID, optional names, representation length and a copied `Body`. HEAD has
no body and preserves the representation length. DELETE requires 204 and no body
or ETag. PUT requires 201 for create-only, 200 for If-Match, or 200/201 for an
unconditional write, with an exact stored receipt and matching identity, revision
and ETag. GET and frozen PUT bytes are hashed with the native engine's specific
64-bit source hash, including comments, CRLF and unsigned UTF-8 octets.

Every call opens exactly one verified TLS 1.3 connection, negotiates ALPN
`yamora-binary/1`, exchanges HELLO and uses stream 1. No reconnect, automatic
retry, proxy, redirect, address hint, DNS destination lookup or TLS fallback is
provided. ServerName is a canonical IPv4 identity or lowercase DNS identity used
only for certificate verification and SNI. Explicit nonempty root certificates
are required; system/opaque trust, validation callbacks and insecure options are
not exposed. Roots, exportable mTLS keys and intermediates are copied at client
construction and retained through admitted calls and disposal. Peer validation
and client chain construction disable AIA/CRL/network downloads. Revocation is
not provided. Disposing caller certificates or replacing their array entries
after construction cannot change the client's identity or trust.

Credentials are supplied per call (`null` omits them), never cached in the client
or recovery envelope. Mutations generate or accept a nonzero 32-lowercase-hex
request ID. Responses must match its exact presence and value. EOF, ERROR 1,
GOAWAY, cancellation, deadline, incomplete END, malformed framing or an invalid
semantic receipt after dispatch raises `BinaryUncertainException`. Its immutable
`Recovery` retains the original method, target names, conditions, source and ID;
`Source` returns a copy. Error messages omit credentials, remote bodies and URLs.
Typed 4xx rejections except 408 are definitive on an initial call; 408/5xx retain
uncertainty. An earlier uncertain envelope remains uncertain on a failed replay.

Retain the envelope as sensitive application data. Independently establish the
exact stored source and required durability before choosing a retry. Explicit
`ReplayAsync(originalEnvelope, newPerCallCredential, cancellation)` is the only
replay API; it sends that original immutable operation once. Standalone stores
gain no deduplication guarantee. Binary cluster discovery, failover orchestration
and cluster replay qualification remain open.

The single monotonic deadline starts at entry and covers admission, input copy,
TCP/TLS, every fragment, decoding, hashing and the final guard after socket and
cancellation-registration cleanup. Cancellation closes only its operation's
socket and joins its callback. At most four calls are admitted per client
(configurable down to one); queued callers hold references without speculative
source copies. Keep source arrays unchanged while they are being copied. Public
inputs are exact byte arrays and immutable strings, not converters, streams,
JsonDocument/JsonElement or mutable TLS option objects. Disposing the client
rejects new calls and defers owned certificate release until existing calls end.

Frame payloads negotiate between 4 KiB and the client's 64 KiB ceiling without
reducing the 16 MiB document limit. Headers and TLVs validate sizes before
allocating payloads. Receipts and errors are capped at 4096 bytes, strict UTF-8
JSON at depth 32 and 1024 nodes, with unique decoded keys and integer number
tokens. UTF-8 validation and source hashing check cancellation/deadlines every
4096 input bytes; JSON checks on each node. Multibyte UTF-8 may span arbitrary
frame and validation chunk boundaries without normalization.

The normal console runner registers all `binary-*` checks, requires the actual
native daemon even for named selections, and verifies its hash stays unchanged.
It covers native HTTP interoperability, mTLS and offline client intermediates,
scoped roles, preconditions, HEAD/DELETE, exact 16 MiB documents over 4 KiB frames,
legacy 256 KiB rejection, concurrent ownership/admission/disposal, cancellation,
deadlines, correctly framed hostile replies and UTF-8 chunk boundaries. Lost and
partial committed receipts are independently read over HTTP before explicit
repetition, with every possible retry observed by the forwarding fixture.
Fixture processes are stopped and joined before scratch deletion on all exits.

The separate behavioral mutation command uses private copies and restores each
guard before its green run; compiler, infrastructure, signal, timeout and fatal
sanitizer failures cannot certify a red:

```sh
python3 drivers/csharp/tests/prove_binary_guards.py \
  --dotnet /absolute/path/to/dotnet --binary /absolute/path/to/yamora
```

Set task-owned disk-backed `TMPDIR` as for the normal console runner. Binary
qualification is Linux x86_64 with .NET SDK 10.0.402/runtime 10.0.13 only. Broader
platform support, shared conformance, discovery and enterprise parity stay open.

## Additive binary operations and page feeds

`BinaryClient.OperationAsync(method, target, contentType, specification, bearer,
ifMatch, ifNoneMatch, requestId, ct)` returns `BinaryResponse`.
`FeedAsync(target, consume, bearer, requestId, ifMatch, ifNoneMatch, ct)` returns
`BinaryFeedResult` with `Response` and `LastAfter`. Its asynchronous callback
receives owned page bytes and a cancellation token; completion supplies
backpressure. `BinaryOperationException` exposes `Response`, `LastAfter` and an
immutable `Recovery` only for an uncertain mutation.
`BinaryUnsupportedPeerException` is a distinct pre-dispatch protocol exception.
Envelope source accessors copy. Build the V3 adapter from
`operations-conformance/Operations.csproj`, assembly `Operations`.

The additive API negotiates metadata schema 2 before sending REQUEST. A peer
that only supports schema 1 raises a typed unsupported-peer exception before
operation dispatch. Existing document CRUD continues to use schema 1 exactly.
There is no automatic retry, HTTP fallback, discovery or transaction replay.

Finite requests accept GET `/v1/changes`, POST query/aggregate/search endpoints
and `/v1/transactions`, and PATCH document endpoints. Supply the exact raw JSON
or YAML specification and media type. Specifications, finite replies and total
feed DATA each have a separate 16 MiB bound, even when the native large profile
allows 64 MiB HTTP envelopes. Mutation receipts and finite errors are bounded
to 4 KiB. JSON is validated without converting number tokens to floating point;
returned body bytes retain their original numeric spellings.

A feed callback receives one complete validated raw NDJSON page including LF.
Callback completion applies backpressure before another page is delivered.
Retain bytes by copying where the callback uses a borrowed view. Complete
transactions stay within a page. The exposed last-complete cursor advances to
`next_after` only after callback success; `checkpoint` may be ahead. Partial or
invalid lines never reach the callback. Native terminal records are delivered
as validated pages, followed by normal END. EOF, ERROR, cancellation and deadline
expiry remain failures with the last completed cursor. One absolute deadline
covers admission, copying, TLS, upload, parsing and callbacks; heartbeats do not
extend it. This is page-at-a-time change-feed delivery. Finite query results and
document sources are still buffered.

PATCH and transaction POST are mutations; query POST is read-only. A mutation
without a complete validated receipt and END after attempted dispatch has an
uncertain outcome, including timeout, cancellation, malformed replies, 408 and
5xx. Its exception owns the original method, target, content type, raw
specification, conditions and Request-ID, excluding credentials. A PATCH ETag
identifies the stored document, never the patch specification. Transaction
receipts validate committed operation count and revision. JSON transaction counts
also match the original specification; raw YAML retains native grammar validation
and the bounded receipt contract without an SDK YAML parser. Reconciliation and
any same-ID retry remain explicit application decisions.

## Replication source preflight

Before application-owned replica staging, call
`await source.RequireReplicationSourceAsync(ct)`. It returns readiness or throws
`SchemaPolicyReplicationError` with status `Conflict` and
`OutcomeMayBeCommitted == false`. Advertised non-booleans fail validation; absent
fields support older policy-free servers. Recheck before publication or applying
each source frame. This advisory read never opens a destination stage; native
outgoing and receiver admission remains authoritative.
