# Yamora Java HTTP, HTTPS replica-set and binary document drivers

This SDK uses Java 17 or newer and only the JDK. It adds no runtime dependency
to an application or to the native daemon. Sources compile directly with
`javac`; no Maven or Gradle setup is needed. A JDK-only local JAR build is
available below; there is no published artifact or version compatibility
guarantee yet.

The finite HTTP foundation also has a separate binary TLS document CRUD API.
Binary cluster discovery/recovery and shared all-driver conformance remain open.
HTTPS replica-set routing has focused native three-node qualification below. The parent storage task owns the shared roadmap;
this contribution does not complete or cross off that stage.

## Use

Compile `src/io/yamora/*.java` into your application's classes directory, or
include those sources in its normal JDK build. For example, from this SDK
directory, with an existing application-owned `classes` output directory:

```sh
javac --release 17 -d classes src/io/yamora/*.java
```

Supply credentials from the application's secret store. An empty token means
no credential; a null token is invalid. A null TLS configuration selects HTTP
on a protected network. Only numeric IPv4 loopback or RFC1918 addresses are
accepted, matching the Go driver's endpoint policy. Hostnames, URLs, IPv6,
ambiguous numeric forms, public and link-local addresses are rejected.

```java
import io.yamora.YamoraClient;
import io.yamora.YamoraClient.WriteOptions;
import java.nio.charset.StandardCharsets;

var client = new YamoraClient("127.0.0.1", 8765, readToken, writeToken, null);
byte[] authored = "# keep this comment\r\nname: Alpha\r\nn: 9007199254740993\r\n"
        .getBytes(StandardCharsets.UTF_8);
var stored = client.put("examples", "one", authored,
        new WriteOptions(null, true, null));
var document = client.get("examples", "one", stored.revision());
// document.source() is a defensive copy of the exact authored bytes.
client.patch("examples", "one", "{\"$inc\":{\"n\":1}}",
        new WriteOptions(document.etag(), false, null));
```

`WriteOptions(etag, createOnly, requestId)` takes an **unquoted** 16-character
lowercase hex document ETag, or null for no condition. Create-only is valid
only for PUT and cannot accompany an ETag. The optional request ID is nonzero
32-character lowercase hex; it is forwarded unchanged, without enabling
replay or promising standalone deduplication. Use null for absent revisions,
cursors, IDs and ETags; empty strings are rejected.

The client has immutable configuration and no per-client process, executor,
pool or close obligation. Concurrent calls have independent connections and
bounded buffers. Applications must bound their own concurrent call count.

## Local distribution and runnable example

`VERSION` identifies the experimental SDK package as **0.1.0**, independently
of daemon/storage/wire versions. There is no stable cross-version compatibility
promise, registry publication or expanded v1/v2 qualification. Only Linux is
qualified. The build targets Java 17 bytecode; existing SDK qualification
covers Linux JDK 17 and 21, and package acceptance uses Temurin 17.0.21.

From the repository root with an owned disk-backed `TMPDIR`, JDK 17+ tools
`javac` and `jar` on PATH, and normal POSIX shell utilities:

```sh
sh drivers/java/build.sh "$TMPDIR/artifacts"
mkdir "$TMPDIR/consumer"
javac --release 17 -cp "$TMPDIR/artifacts/yamora-java-0.1.0.jar" -d "$TMPDIR/consumer" drivers/java/examples/Crud.java
java -cp "$TMPDIR/consumer:$TMPDIR/artifacts/yamora-java-0.1.0.jar" Crud
```

The fresh output directory receives `yamora-java-0.1.0.jar` and
`yamora-java-0.1.0-sources.jar`; existing artifacts are never overwritten.
The binary JAR contains all compiled SDK classes, manifest implementation
version, automatic module name `io.yamora.driver` and `META-INF/LICENSE`.
The source JAR includes original sources, README, `examples/Crud.java` and
the exact MIT notice copied from parent `yamora/LICENSE`. Neither artifact
contains tests, conformance adapters, credentials or external dependencies.
Build scratch is removed on success/failure; no Maven/Gradle installation,
network, signing or upload is involved.

Use a **disposable** native database. Supply `YAMORA_PORT`,
`YAMORA_READ_TOKEN`, `YAMORA_WRITE_TOKEN` and `YAMORA_CA_FILE` through your
application environment. `YAMORA_HOST` defaults to `127.0.0.1`. Optional
mTLS uses `YAMORA_IDENTITY_FILE` (PKCS12) and `YAMORA_IDENTITY_PASSWORD`.
The example creates document `java-package-crud` in collection `examples` with create-only, checks
authored bytes, PATCHes under an ETag, verifies comments/CRLF/UTF-8/int64
spelling, deletes under the new ETag and verifies 404. Failure or uncertainty
stops without replay; a newly created document may remain for reconciliation.

`tests/test_packaging.py` is discovered by the existing Java Python runner.
It builds and checks actual JAR inventories, Java 17 class format, license
and manifest; extracts the packaged example; compiles an external consumer
with only the binary JAR on its SDK classpath and an empty source path; then
runs that consumer and the example against a synthetic native mTLS fixture.
Supply `YAMORA_TEST_BINARY`, owned `TMPDIR` and `YAMORA_PACKAGE_SOURCE_ROOT`
pointing to the managed repository for the shared fixture imports. Parent
runner integration must pass this source root and expose/probe `jar` from
the same pinned JDK as javac.

Every top-level SDK class must appear in the JAR, including public binary
codecs, cancellation, receipts, errors and the HTTP, HTTPS replica and binary
transport implementations. The external consumer loads every top-level class
and verifies its code source is the built JAR. Ambient JVM classpaths/options
are cleared. Removing one implementation from each transport in disposable
JARs must fail that consumer, followed by a restored pass. Both unchanged
`conformance/Adapter.java` and `conformance/HttpReplicaAdapter.java` compile
alongside the external consumer with an empty source path and only the JAR
as the SDK dependency.

Full artifact conformance remains a **parent gate**: run both existing
`binary-document-standalone` and `http-replica-receipt` profiles using the
compiled adapters with only their classes and the binary JAR on the classpath.
SDK checkout sources must be absent from classpath and source path. The parent
runner must launch these artifact-backed adapters for both profiles. The CRUD
example and adapter compilation do not qualify either complete profile;
both profiles are required before closing the broad gate.

Installed artifact manifests supply the binary JAR as role `package` and the
shipped source JAR as role `sources`. The parent qualifies `examples/Crud.java`
from that verified source archive against the binary JAR and independently
checks native commit history and the deleted document. Missing example inputs
fail qualification; the runner never substitutes an example from the checkout.

The focused launcher below provisions only existing checksum-pinned Node,
JDK and test compiler into private scratch, probes npm/jar, copies the supplied
immutable daemon into scratch, checks its expected SHA256 before/after and
runs only the two packaging tests. It shares the established environment,
source-copying, workspace retention and process supervision:

```sh
python3 drivers/java/tests/test_packaging.py --acceptance --binary /absolute/path/to/native/yamora --sha256 EXPECTED_SHA256
```

Invoke through the repository's managed task environment. Provisioning
downloads pinned development tools; artifact building and npm consumer
installation are local. Private tools, artifacts, native roots and credentials
are cleaned after verified process shutdown. Use `--suite node` or `--suite java`
to rerun only a failed package check. No broad SDK suites are run.

## Implemented API

Every method throws `YamoraException` for transport, protocol or HTTP failures.
Invalid local arguments throw `IllegalArgumentException`. JSON methods return
`JsonReply(status, revision, json, value)`: the finite response text and a parsed,
immutable object. The SDK checks UTF-8, JSON syntax/budgets, media type, HTTP
status, revision header, and any body revision against that header. Online
index job body revisions describe the job's earlier publication and are not
required to equal the current response header. The raw APIs leave endpoint
semantics and supported operators to the daemon; they do not present unvalidated
fields as typed query/feed/job receipts.

| Methods | Behavior |
| --- | --- |
| `health()`, `ready()`, `stats()`, `metrics()` | Service observations; metrics returns UTF-8 text. Health works without authentication. |
| `collections(expectedRevision)` | Sorted, distinct collection IDs and optional revision check. |
| `documentPage(collection, limit, after, expectedRevision)` | One ID page, limit 1–1,000. A non-null cursor requires a revision. IDs and continuation are checked; use the returned revision on every subsequent page/read. |
| `get(collection, document, expectedRevision)` | Exact UTF-8 YAML bytes, unquoted ETag, snapshot revision. |
| `put(collection, document, byte[], options)` | Raw YAML create/replace; validates stored receipt, uses write credential. No YAML parser or source rewriting. |
| `patch(collection, document, operatorsJson, options)` | Nonempty JSON operator object; validates stored receipt. |
| `delete(collection, document, options)` | Conditional delete; returns deletion revision. |
| `query(collection, specificationJson)` | JSON query envelope, including filters, ordered sort, projection, count, explain, revision and cursor. |
| `aggregate(collection, specificationJson)` | JSON envelope containing `pipeline` and optional revision. |
| `search(collection, specificationJson)` | JSON text-search envelope; read credential. |
| `indexes()`, `setIndexes(catalogJson, expectedRevision, requestId)` | Reads/replaces the complete catalog. Catalog is an object with an `indexes` array. Replacement uses a database-revision If-Match, not a document ETag. |
| `startIndexBuild(catalogJson, expectedRevision)`, `indexBuild(jobId)`, `cancelIndexBuild(jobId)` | Finite online job calls; null ID reads latest status. Start/cancel return 202. Local interruption does not cancel a remote job. |
| `transaction(envelopeJson, requestId)` | Atomic transaction envelope with 1–128 operations and optional revision. Validates operation identities, modes, source limits, preconditions, duplicate targets and committed operation count. |
| `changes(after, limit)` | Null `after` obtains a checkpoint; otherwise one finite page, limit 1–100. Tokens must match the current native token grammar. Application owns validation/handling of frames and durable consumer progress. |
| `replicationStatus()` | Durable replica observations. |
| `replication(operation, envelopeJson)` | Low-level `BEGIN`, `APPLY`, `COMMIT`, `ABORT`, `FOLLOW_BEGIN`, `FOLLOW_APPLY`, `FOLLOW_COMMIT`, `FOLLOW_ABORT` requests. Application owns session lifecycle, revision calculation, frame validation and recovery. No automatic bootstrap/follow algorithm. |
| `clusterLeader()`, `clusterStatus()` | Advisory metadata from the selected endpoint. Metadata is never a quorum proof. |

Query/aggregation/search POSTs use the read token. Document/index/transaction
and replication mutations use the write token. The driver validates path IDs
as 1–128 lowercase ASCII letters, digits or hyphens before building a request.
It rejects writes to the reserved system collection. JSON envelopes cannot
select arbitrary HTTP paths or headers. Unsupported operator semantics and
server-side collection access grants are enforced by the native daemon.

Example query, with explicit compound sort priority preserved in authored JSON:

```java
var page = client.query("examples",
        "{\"sort\":{\"n\":-1,\"name\":1},\"limit\":10,\"explain\":true}");
// page.json() retains the exact numeric response text.
// Parsed numeric fields are Json.NumberValue, never Double.
```

`Json.parse` and `Json.stringify` are available for constructing/reading
envelopes. Maps retain insertion order, including sort priority. Number tokens
retain all digits and exponent spelling; choose explicit `longValueExact()`,
`bigIntegerExact()` or `decimal()` conversion as appropriate. Serialization
accepts integral JDK types, `BigInteger`, `BigDecimal`, `NumberValue`, booleans,
strings, null, lists and string-keyed maps. Float/Double, duplicate object keys,
non-JSON numbers and invalid Unicode are rejected. NEL and Unicode line
separators are escaped before passing JSON to the daemon's YAML parser.

## HTTPS replica sets

Use the same methods through the common request boundary:

```java
import io.yamora.ClusterConfig;
import io.yamora.ClusterConfig.Seed;
import io.yamora.Tls;
import java.time.Duration;
import java.util.List;

var config = new ClusterConfig(List.of(new Seed("10.20.0.11", 8765),
        new Seed("10.20.0.12", 8765), new Seed("10.20.0.13", 8765)), tls,
        Duration.ofSeconds(20), Duration.ofSeconds(3),
        YamoraClient.MAX_REQUEST_BYTES, YamoraClient.MAX_RESPONSE_BYTES);
var cluster = YamoraClient.replicaSet(config, readToken, writeToken);
cluster.patch("examples", "one", "{\"$inc\":{\"n\":1}}", WriteOptions.NONE);
```

The shorter `ClusterConfig(seeds, tls)` constructor uses a 30-second overall
budget, a five-second attempt cap, and protocol byte ceilings. Configuration
copies 1–9 distinct numeric private IPv4 seed pairs and requires verified TLS.
It cannot accept a separate standalone address or server-advertised endpoint.
Discovery reads only these seeds using the read token, accepts exactly the
native `node`, `leader`, `term`, `role` schema, and selects a seed only when
it reports itself as leader with a positive unsigned-64-bit term. Node numbers
never become addresses. Unknown fields (including URLs), redirects, malformed
metadata and oversized discovery bodies cannot enlarge the trust set.

The atomic leader cache is safe for concurrent calls. Discovery, dispatch and
backoff share one monotonic deadline; each attempt uses the smaller of its
configured cap and a share of remaining time. Discovery reserves a dispatch
share, and dispatch reserves another discovery opportunity when multiple seeds
exist. At most 32 rounds run, with backoff from 50 milliseconds to one second.
Thread interruption cancels discovery, dispatch or backoff. No call consults a
proxy or follows a redirect. Discovery responses are capped at 512 bytes and
also respect the application's lower response limit.

PUT, PATCH, DELETE, transactions and complete index-catalog replacement all
receive one nonzero request ID before discovery. The already serialized body,
ID and preconditions remain identical across retries. Transport failures,
acknowledgements lost before a status line, and HTTP 503 trigger rediscovery.
A malformed/truncated response after a status, unexpected success status, or
other failure such as HTTP 500 returns an error with `outcomeUncertain()` and
`requestId()`. Receipt validation occurs inside this boundary, including the
stored document identity/ETag and committed transaction/catalog operation count.
Definitive HTTP validation/conflict/authentication errors retain `Kind.HTTP`
and their status; a rejection following an earlier ambiguous dispatch remains
uncertain with the original ID. Discovery/deadline exhaustion on a mutation
also returns the ID, conservatively, even if dispatch was never established.

Persist that ID **and the original exact arguments**, then reconcile by repeating
the same operation using `WriteOptions.requestId`, `transaction`'s request ID,
or `setIndexes`'s request ID. Never use the ID for another body or precondition.
For recovery across application crashes, supply an application-persisted ID
before the call: generated IDs are available on exceptions, not durably stored
by the SDK. Exactly-once replay depends on the native replica set's durable
request receipts and quorum; the SDK provides neither local durable recovery
nor a rollback guarantee. Read data/revision checks still belong to the native
quorum protocol; discovery is advisory.

Online index-build and replication mutations return typed HTTP 405 in cluster
mode. Native replica sets also reject their related read endpoints. Finite
changes/query/aggregation/search and document/catalog reads use the same routed
request boundary. Standalone constructors retain one-attempt behavior and never
acquire automatic mutation replay.

## TLS and failure behavior

```java
import io.yamora.Tls;
import java.nio.file.Path;

var tls = Tls.trustPem(Path.of("ca.pem"), Path.of("client.p12"), keyPassword);
var secure = new YamoraClient("10.20.0.11", 8765, readToken, writeToken, tls);
// For server-authenticated TLS only, pass null identity and null password.
// Tls.systemTrust() uses the configured JDK trust store.
```

TLS uses JSSE with TLS 1.3 only, the provider's enabled cipher suites, mandatory
certificate/IP verification and HTTP/1.1 ALPN. `Tls` is constructed from JDK
trust managers and optional PKCS12 client keys; there is no insecure/custom
verifier or arbitrary SSLContext injection API. Client certificates do not
replace bearer authorization. Certificate paths and passwords are trusted
application configuration; the caller owns their custody and password cleanup.

Each endpoint attempt opens exactly one channel-backed JDK socket, writes one
HTTP/1.1 request and closes it. This explicit exchange avoids Java pooled HTTP clients'
transparent idempotent retries without modifying global JVM retry settings.
There is no redirect following, proxy lookup (including JVM `ProxySelector`),
environment proxy, cookie handling, authentication challenge replay,
compression or hidden retries. Standalone calls make one attempt; replica-set
retries are explicit and bounded as described above.

The default absolute exchange deadline is five seconds, configurable from
1 millisecond through 30 seconds. It covers connect, TLS handshake, writes,
headers, response body and peer close. Thread interruption closes the
channel-backed I/O. Local envelope parsing/encoding happens before that network
deadline and has separate size/depth/node budgets. No per-call cancellation
token or async API is provided.

Only the daemon's finite, Content-Length-framed HTTP/1.1 profile is accepted.
Truncated bodies, extra bytes, transfer encoding, compression, folded headers,
missing revisions and unexpected success statuses fail closed. Duplicate headers
are rejected except identical `Cache-Control: no-store` directives, which the
native cluster metadata endpoint currently emits twice. Framing and revision
headers must remain unique. Header
input is capped at 16 KiB and 64 fields. The transport requires peer close,
as the current daemon protocol specifies; this also rejects trailing bytes.

Raw sources are limited to 16 MiB. JSON request ceilings are 2 MiB for
query/search/aggregate/catalog/job and replication control, 64 MiB for patch,
transactions and replication apply. JSON responses are at most 64 MiB, with
16 MiB caps on document/mutation/job/replication/metrics responses. Server
profiles may impose smaller limits. The extended constructor can lower request
and response byte limits. JSON values have depth 64, 100,000 total nodes
(including keys), and 1,024 characters per number token. Large semantic results
may therefore require smaller pages even if they fit the byte limit. Buffers
and decoded values are bounded per call; this foundation does not stream bodies.

`YamoraException.kind()` distinguishes HTTP, transport and malformed-protocol
failures; `status()` is zero if no HTTP status was available. Remote error
bodies are never included in exceptions. `outcomeUncertain()` is true when a
mutation was sent and acknowledgement was lost/invalid, or an unexpected
redirect, 408 or 5xx arrived. A 5xx can follow publication. Reconcile served
state and preconditions before explicitly resubmitting; this driver cannot
promise rollback or crash durability. Transport failures before sending the
request (for example certificate verification failure) are marked definite.


## Separate binary document API

`BinaryClient` document methods implement GET, HEAD, PUT and DELETE on the committed
v1 binary metadata/framing profile. Existing HTTP and HTTPS cluster APIs retain
their own contracts. Every binary call opens one owned TLS 1.3 connection with
mandatory `yamora-binary/1` ALPN. The route is a canonical private/loopback
numeric IPv4 address; `serverName` is the explicit certificate identity and
optional DNS SNI name. It is never resolved to choose a route. There is no
proxy lookup, redirect, reconnect, automatic replay or network certificate-chain
fetch. PKIX validates the supplied chain directly against copied DER/PEM anchors,
with network revocation disabled. Supply the entire server intermediate chain.

```java
import io.yamora.BinaryClient;
import io.yamora.BinaryConfig;
import io.yamora.BinaryCancellation;
import io.yamora.BinaryUncertainException;
import java.time.Duration;

var config = new BinaryConfig("127.0.0.1", binaryPort, "database.internal",
        trustDerOrPemBytes, clientPkcs12Bytes, clientPassword,
        Duration.ofSeconds(10), 2, 4096);
var binary = new BinaryClient(config);
var cancel = new BinaryCancellation();
try {
    var receipt = binary.put("examples", "one", authored, writeToken,
            null, "*", null, cancel);
    var result = binary.get("examples", "one", readToken);
    // result.body() is a copy of the exact authored YAML bytes.
} catch (BinaryUncertainException uncertain) {
    var original = uncertain.envelope();
    // Retain securely for explicit reconciliation: original request ID, method,
    // target, source bytes and conditions. No bearer is retained in the envelope.
}
```

Trust input is 1..65,536 bytes with at most 16 certificates. Optional static
PKCS12 identity is at most 131,072 bytes (16 entries, eight certificates per key
chain); pass both identity and password as null for server-only TLS. Inputs
are copied before fresh internal certificate/key parsing. There is no public
SSLContext, TrustManager or KeyManager injection point. Callers may erase their
original configuration bytes/password once construction returns. TLS verification
and bearer roles are both mandatory for protected operations; mTLS does not
replace per-request authorization. A null binary bearer omits the credential;
otherwise it is 1..512 non-space printable ASCII characters.

Each client admits 1..4 calls. Queued calls allocate no source snapshot or
socket. After admission and before I/O the driver freezes source, target,
conditions and a nonzero 32-character lowercase hexadecimal request ID (random
when null). Keep caller source unchanged until the call returns; the driver
then owns any uncertain envelope. Conditions are exact wire values, including
quoted ETags and present empty values, and native storage validates them.
`call(Method, ..., cancellation)` also exposes conditions on reads. A
`BinaryCancellation` is one-way; thread interruption also cancels. One absolute
monotonic deadline (up to 30 seconds) includes admission, copying, TCP, TLS,
HELLO, upload, response fragments, receipt decoding and END. Each admitted I/O
call owns one watchdog and socket; all exit paths close and join before releasing
admission. There is no client executor, timer registry or close obligation.

Frames negotiate 4..64 KiB effective payloads, metadata is at most 2,048 bytes,
and source is at most 16 MiB regardless of frame size. Acknowledgements and
errors, including HEAD error representations, are at most 4,096 bytes. Header
and TLV checks precede advertised-size allocations. Response status, method,
wire/representation lengths, revision, ETag, collection/document, echoed ID,
strict bounded JSON receipt semantics and terminal END must all agree. Successful
GET verifies the received raw source against its ETag; successful PUT verifies
the JSON/TLV ETag against the admitted immutable input. Both use the native
source hash (seed 1469598103934665603, multiplier 1099511628211, unsigned
bytes, arithmetic modulo 2^64), with deadline/cancellation checks every 4 KiB
and after hashing. A mismatch is PROTOCOL, with typed uncertainty for dispatched
PUT and its original owned envelope. A HEAD body is empty while its representation length remains available; DELETE 204
has both lengths zero. Response byte accessors copy and receipts are immutable.

`BinaryException` distinguishes STATUS, PROTOCOL, TRANSPORT, TIMEOUT and CANCELLED.
Every dispatched mutation without a verified terminal receipt throws the typed
`BinaryUncertainException`, including closing ERROR code 1, GOAWAY, partial
receipt, malformed semantic response, EOF, timeout/cancellation, 408 and 5xx.
The owned `BinaryEnvelope` excludes credentials and redacts `toString`; source
access returns a copy. Pre-dispatch failures and validated 4xx rejections have
no uncertain envelope. IDs **do not deduplicate standalone writes**. This API
provides no binary cluster discovery or recovery helper and never resends.

Binary qualification uses literal independent frame/TLV vectors, verified hostile
TLS peers, admission and deadline/cancellation probes, descriptor/watchdog checks,
and required real native mTLS/HTTP interoperation. It checks exact CRLF/Unicode/
comments, conditions/roles, HEAD and DELETE, exact 16 MiB documents over 4 KiB
frames and the legacy 256 KiB profile. A verified TLS proxy truncates a real
committed receipt; HTTP confirms the known source before any explicit repetition.
The native executable is read-only and its digest is checked after qualification.

An additional explicit behavioral mutation gate compiles five private mutants
(request identity, receipt semantics, uncertainty and both source-hash guards)
and requires the exact assertion failure followed by the same restored test passing. Compiler errors,
signals, sanitizer diagnostics and infrastructure failures never count as reds:

```sh
python3 drivers/java/tests/prove_binary_guards.py
```

Supply task-owned disk `TMPDIR` for both commands. Qualification is Linux native
with JDK 17 and 21; macOS/Windows native execution and broader binary conformance
remain unverified.

## Verification and remaining stages

From the repository root:

```sh
sh drivers/java/tests/run.sh /absolute/path/to/native/yamora
```

The script honors the caller's `TMPDIR`, falling back to the repository's
disk-backed scratch root only when none is supplied. It creates a unique
`yamora-java-check-*` directory beneath that root and contains compiler, JVM,
native subprocess and certificate temporary files within that allocation.
The caller's root and existing files are preserved; the unique allocation is
removed on success or failure. It compiles with
`--release 17 -Xlint:all -Werror`, runs standalone and HTTPS cluster fault tests,
plus binary wire/TLS contracts and required native standalone, binary CRUD and
three-node HTTPS replica-set tests. Missing/non-executable native configuration fails;
there is no native skip mode. JVMs use two processors, bounded heaps and private
temp/compiler output; fatal ASan/UBSan options apply to native children. No daemon is built. Tests own ephemeral loopback listeners, native
roots, credentials and certificates, and stop/remove their allocations on
success or failure. TLS test fixtures require the `openssl` executable for disposable certificates;
native tests additionally require Linux/POSIX file permissions; neither is a runtime SDK
dependency. Build output is removed by the runner.

The focused scratch-ownership checks use only Python's standard library and
substitute the JDK launchers, without running the driver suites. With an owned
disk-backed `TMPDIR` supplied, run:

```sh
python3 drivers/java/tests/test_runner.py
```

Local verification covers the parent-built ASAN native daemon: exact comments,
CRLF and UTF-8, large sources, stale ETags/revisions, authentication, query
64-bit numbers, transactions, paging, full-text catalog/search, online jobs,
finite changes, staged full replication and TLS/mTLS. Hostile-peer checks
cover bad endpoints/tokens/paths, redirect rejection, framing/size failures,
no mutation replay, proxy bypass, deadlines for reads and blocked writes, and
interruption. Actual TLS probes reject an untrusted chain, a wrong IP SAN,
missing client identity and a TLS-1.2-only server.

Remaining stages include binary cluster discovery/recovery, multiplexed streaming, shared conformance,
typed semantic query/feed/job validation, continuous change streams,
bootstrap/follow orchestration, durable application retry recovery,
stable version guarantees, and real macOS/Windows daemon integration.
The cluster suite verifies actual native leader loss after a committed but lost
PATCH acknowledgement, exact-once receipt replay for PATCH, transactions, catalog
replacement and DELETE, concurrent increments, exact YAML and int64 query values,
and loss of read quorum under mTLS. HTTPS peers exercise all five mutation paths
across lost acknowledgements, bad success/500 receipts, trusted routing rejection,
byte caps, shared deadlines, cancellation, and concurrent generated IDs. Binary
cluster discovery/recovery and cross-driver shared conformance remain open. No native storage code is changed.

## Additive binary operations and page feeds

`BinaryClient.operation(method, target, contentType, specification, bearer,
ifMatch, ifNoneMatch, requestId, cancellation)` returns `BinaryResponse`.
`feed(target, bearer, requestId, cancellation, pageConsumer)` returns
`FeedResult(response, lastAfter)`; the overload also accepts both conditions.
`BinaryOperationException` exposes `response()`, `lastAfter()` and an immutable
`envelope()` only when `uncertain()` is true. `BinaryUnsupportedPeerException`
is a distinct pre-dispatch protocol exception. Byte-array accessors copy.
The V3 adapter entry point is `conformance/OperationsAdapter.java`.

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

Before application-owned replica staging, call `source.requireReplicationSource()`.
It returns readiness or throws `YamoraException` with kind
`SCHEMA_POLICY_REPLICATION_UNSUPPORTED`, status 409 and a definite outcome.
Advertised non-booleans are protocol errors; absent fields support older
policy-free servers. Recheck before publication or applying each source frame.
This advisory read never opens a destination stage; native outgoing and receiver
admission remains authoritative.
