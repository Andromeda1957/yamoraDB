# YamoraDB Node.js HTTP driver foundation

An ESM driver using Node standard libraries only, with TypeScript declarations.
Requires Node.js 22.23.1 or later; verified here on Linux with Node 22.23.1
(the repository CI runtime) and Node 26.11.1. There are no runtime dependencies,
YAML parser, install scripts, or build step. The package is private and has no
published release or compatibility guarantee yet.
Import `Client` from the local package's `index.js` during source evaluation,
or install the local tarball described below.

```js
import { Client, YamoraError } from './index.js';
import { readFile } from 'node:fs/promises';

const client = new Client({
  host: '127.0.0.1', port: 8765,
  readToken: process.env.YAMORA_READ_TOKEN,
  writeToken: process.env.YAMORA_WRITE_TOKEN,
  tls: { ca: await readFile('/private/ca.pem') },
});
const source = Buffer.from('# authored exactly\r\nname: API\r\nreplicas: 2\r\n');
const stored = await client.put('services', 'api', source, { createOnly: true });
const document = await client.get('services', 'api', { revision: stored.revision });
// document.source is a Buffer of the exact authored bytes.
await client.patch('services', 'api', { $inc: { replicas: 1 } }, { etag: document.etag });
```

Load tokens from your application's secret store; tokens must be 32–512
printable ASCII bytes, excluding spaces. Omit a token only for endpoints that
the server allows without it. Query, aggregate, search and observations use the
read token; mutations use only the write token. Credentials and remote error
bodies are excluded from error messages and enumerable client properties.

Endpoints accept canonical numeric IPv4 loopback or RFC1918 addresses only,
with an integer port 1–65535. Hostnames, URLs, public/metadata addresses, IPv6,
path injection and arbitrary request headers are rejected. IDs are 1–128
lowercase ASCII letters, digits and hyphens. Storage remains entirely native
and is unchanged by this driver.

`tls` accepts only PEM `ca`, `cert`, and `key` strings or Buffers; `cert` and
`key` must be paired for mTLS. Certificates must contain the endpoint's IP SAN.
Without `ca`, Node's default trust store applies. TLS always verifies trust and
IP identity and negotiates only TLS 1.3 with HTTP/1.1. Verification callbacks,
custom agents, protocol downgrades and insecure flags are rejected. Caller PEM
buffers are copied. Omitting `tls` selects HTTP, suitable for loopback or an
otherwise protected network. See the [Node TLS documentation](https://nodejs.org/api/tls.html).

Every request owns a fresh connection, ignores proxy environment variables,
rejects every redirect, and requests identity encoding. Standalone `Client`
has no automatic retry or reconnect. `timeoutMs` defaults to 5000 and accepts 1–30000 milliseconds. It
bounds connection, TLS, response headers and the entire body, including slow
trickles. Every API accepts an optional `signal: AbortSignal`; aborting before
dispatch sends nothing. Iterator requests each receive their own deadline.
Connections close on success, failure, cancellation and early rejection;
there is no persistent pool to close. See [Node HTTP requests](https://nodejs.org/api/http.html#httprequestoptions-callback).

The default hard limits are 16 MiB per YAML document and 64 MiB per request or
response, with 16 KiB response headers. `maxDocumentBytes`, `maxRequestBytes`
and `maxResponseBytes` may reduce those limits. Structured inputs and outputs
also have depth 64 and 100,000 visited-value limits. UTF-8, well-formed Unicode,
finite numbers and plain JSON trees are required for structured calls. Inputs
reject cycles, sparse arrays, accessors and `toJSON` hooks. YAML writes accept
nonempty UTF-8 strings, Buffers or Uint8Arrays and never parse or normalize the
source. The daemon validates YAML semantics and source-preserving patch rules.
Compressed, oversized, truncated and malformed structured responses fail closed.
Older native formats and legacy servers may enforce smaller server limits.

Structured integers outside JavaScript's safe range are returned as `bigint`
when the JSON token is an integer literal. Send signed 64-bit `bigint` values
for exact integer predicates or operations. Unsafe integer `number` inputs are
rejected because they have already lost precision. Finite fractional and
exponent-form numbers follow JavaScript's IEEE 754 behavior. JSON envelopes
escape NEL and Unicode line/paragraph separators so the daemon's YAML parser
does not fold string data. Use raw YAML when source spelling matters.

## Local package and runnable example

`@yamora/node` remains **private**, version **0.1.0**. This experimental local
distribution has no registry release or cross-version compatibility promise.
The SDK package version is independent of daemon/storage/wire versions;
packaging does not expand v1/v2 conformance qualification. Only Linux is
qualified; macOS, Windows, browsers and CommonJS remain unverified.

From this package directory, with an owned disk-backed `TMPDIR` and npm from
the selected Node installation:

```sh
npm pack --offline --ignore-scripts --pack-destination "$TMPDIR"
mkdir "$TMPDIR/consumer"
cd "$TMPDIR/consumer"
npm install --offline --ignore-scripts --no-audit --no-fund --package-lock=false "$TMPDIR/yamora-node-0.1.0.tgz"
```

ESM consumers import from `@yamora/node`. The tarball includes the public
entry point, declarations, every required `lib` module, README, runnable
example and exact MIT notice from parent `yamora/LICENSE`. Tests, conformance
adapters, credentials and toolchains are excluded. There are no runtime
dependencies or lifecycle scripts.
All public clients (`Client`, `ClusterClient`, `BinaryClient`), their errors,
declarations and standalone HTTP, HTTPS replica and binary TLS implementations
are included; packaging does not select just the example's HTTP transport.

Use a **disposable** native database. Supply `YAMORA_PORT`,
`YAMORA_READ_TOKEN`, `YAMORA_WRITE_TOKEN` and `YAMORA_CA_FILE` through your
application environment. `YAMORA_HOST` defaults to `127.0.0.1`; optional
mTLS uses paired `YAMORA_CERT_FILE` and `YAMORA_KEY_FILE` paths. Run:

```sh
node node_modules/@yamora/node/examples/crud.mjs
```

The example creates document `node-package-crud` in collection `examples` with create-only, checks
exact UTF-8/CRLF/comment/int64 source bytes, PATCHes with the ETag, verifies
the exact changed bytes, deletes with the new ETag and verifies 404. It
stops on failure/uncertainty without replay; a newly created document may
remain for explicit reconciliation.

`node --test tests/package.test.js` packs and installs offline into an
isolated consumer, checks the artifact inventory and public exports, and
compiles a consumer against installed declarations. Supply the test compiler
and `NODE_TYPE_ROOTS` from the shared runner. With `YAMORA_TEST_BINARY`, it
also executes the installed example against synthetic native mTLS. The
ordinary JavaScript test glob discovers it. The sibling Java README documents
the focused managed two-package launcher. Parent runner integration must
expose/probe npm from the pinned Node prefix alongside node/tsc.

Artifact consumers clear ambient Node module/loader options and verify the
resolved package entry and declarations are inside the installation. Temporarily
removing each of the HTTP, replica and binary transport modules must make the
same consumer fail, followed by a restored pass. Both unchanged adapters,
`conformance/adapter.mjs` and `conformance/http_replica.mjs`, are copied into the
external consumer. A consumer-root bridge re-exports `@yamora/node` for their
relative entry-point imports; empty-input startup checks prove linking only.

Full artifact conformance remains a **parent gate**: run both existing
`binary-document-standalone` and `http-replica-receipt` profiles through these
artifact-backed adapter copies, with SDK checkout paths excluded from resolution.
The parent runner must launch these artifact-backed adapters for both profiles.
CRUD examples and adapter startup checks do not qualify either complete profile;
both profiles are required before closing the broad gate.

## Implemented APIs

All methods return promises except `documents`, which is an async generator.
Names in request/result objects follow the HTTP protocol; method options use
camelCase. `etag` and `revision` arguments are unquoted 16-character lowercase
hex strings; the driver adds HTTP quotes where required. Every successful
response must have a valid revision header. Structured body revisions, when
present, must agree, except an online job's historical publication revision.
Catalog mutation receipts must also have `status: "committed"` and numeric
`operations: 1`; this applies to standalone and cluster clients alike.

| API | Behavior |
| --- | --- |
| `health(options)`, `ready(options)`, `stats(options)` | JSON metadata objects, preserving large integer tokens |
| `metrics(options)` | UTF-8 Prometheus text |
| `collections({revision, signal})` | Sorted collection IDs plus observed revision |
| `documentPage(collection, {limit, after, revision, signal})` | One sorted ID page; limit 1–1000; continuation requires revision |
| `documents(collection, {limit, revision, signal})` | Iterate IDs with first-page revision pinned and forward-progress checks |
| `get(collection, document, {revision, signal})` | Exact source Buffer, unquoted ETag, revision |
| `put(collection, document, source, {createOnly, etag, requestId, signal})` | Raw YAML create/replace; create-only and ETag cannot combine |
| `patch(collection, document, operators, {etag, requestId, signal})` | JSON `$set`, `$unset`, `$inc`, `$push`, `$pull`; server validates paths/operators |
| `delete(collection, document, {etag, requestId, signal})` | Delete with optional ETag; returns commit revision |
| `query(collection, spec, {signal})` | Filter, sort, projection, limit, pinned continuation, count, explanation and `include_count` |
| `count(collection, filter, {revision, signal})` | Complete match count without rows |
| `aggregate(collection, pipeline, {revision, signal})` | Native 1–32 stage pipeline; server validates stage semantics |
| `search(collection, spec, {signal})` | Text index, text, optional mode/filter/limit/after/revision; ascending IDs and term scores |
| `indexes({signal})` | Complete catalog with revision |
| `setIndexes(definitions, {revision, requestId, signal})` | Replace complete catalog with optional snapshot guard |
| `createIndex(definition, {signal})`, `dropIndex(collection, name, {signal})` | Read catalog then write under its revision; conflict returns 412 |
| `startIndexBuild(definitions, {revision, signal})` | Submit complete online catalog; returns job after HTTP 202 |
| `indexBuild(id, {signal})` | Observe a job; omit ID for latest/idle state |
| `cancelIndexBuild(id, {signal})` | Explicit remote cancellation request; completed jobs reject cancellation |
| `transaction(operations, {revision, requestId, signal})` | 1–128 distinct targets; exactly one raw `put`, JSON `patch`, or `delete: true` each |
| `changes({after, limit, signal})` | Checkpoint when no token; otherwise one validated page of complete commits, limit 1–100 |

Query/search specifications use the documented protocol's snake_case fields,
including `count_only`, `include_count`, and `revision`. Compound sort priority
uses JavaScript property enumeration order; integer-like keys enumerate first.
Use a single sort field if that ordering cannot express your desired priority.
After a 412, restart a scan/query from the beginning. Already yielded IDs cannot
be undone when a later page detects a concurrent write.

Transaction operations use `collection`, `document`, optional `etag`, and one
of `put`, `patch`, or `delete`; `create_only` applies only to `put`. Atomicity,
uniqueness and source-preserving patch semantics are enforced by the daemon.
Online jobs are observed explicitly; aborting a local request does not cancel
the remote job. No unbounded polling helper is provided.

`changes` validates token identity, ordering, revision continuity and complete
operations. A `resnapshot_required` frame is returned explicitly: take a new
consistent snapshot before applying later frames. HTTP 409 means a foreign or
future position; 410 means expired history. Persist consumer effects and the
handled token together in the consumer's own durable store. This API never
advances durable consumer progress on the caller's behalf.

`YamoraError.status` carries HTTP failures, including 401, 403, 409, 410 and
412. `code` distinguishes `HTTP_ERROR`, `TIMEOUT`, `ABORT_ERR`,
`RESPONSE_LIMIT`, `TRUNCATED_RESPONSE`, `PROTOCOL_ERROR`, and sanitized Node
transport/TLS error codes. `uncertain: true` means a dispatched mutation may
have committed, including a lost or malformed acknowledgement. Read and
reconcile state/preconditions before submitting another mutation. An explicit
`requestId` forwards a nonzero 32-character lowercase hexadecimal ID; this
does not enable standalone deduplication, discovery, failover, or retries.

## HTTPS replica sets

`ClusterClient` extends `Client` with the same methods and lossless JSON codec.
Its configuration requires `tls` and 1–9 distinct explicit `{host, port}` seeds;
standalone `host` and `port` options are rejected. All seeds must be trusted to
receive the configured tokens and client certificate. Seed arrays, endpoint
objects and PEM buffers are copied at construction.

```js
import { ClusterClient, UncertainWriteError } from './index.js';

const cluster = new ClusterClient({
  seeds: [
    { host: '10.0.0.11', port: 8765 },
    { host: '10.0.0.12', port: 8765 },
    { host: '10.0.0.13', port: 8765 },
  ],
  tls: { ca: await readFile('/private/ca.pem') },
  readToken: process.env.YAMORA_READ_TOKEN,
  writeToken: process.env.YAMORA_WRITE_TOKEN,
  timeoutMs: 20000,
});
// Prefer an ID persisted with the exact primitive arguments before dispatch.
const requestId = '123456789abcdef0123456789abcdef01';
try {
  await cluster.patch('services', 'api', { $inc: { replicas: 1n } }, { requestId });
} catch (error) {
  if (error instanceof UncertainWriteError) {
    // Persist error.requestId and reconcile/recover this exact request.
    // Never change its bytes or preconditions, or generate a fresh ID.
    throw error;
  }
  throw error;
}
```

Discovery accepts only a bounded `/v1/cluster/leader` JSON reply identifying
the responding seed itself as leader. IDs are not seed-array indexes. Follower
hints and advertised URLs are never routing destinations. Verified IP identity,
TLS 1.3, optional mTLS, private numeric endpoints, independent tokens, no proxies
and no redirects apply to discovery and dispatch alike. The native server still
establishes quorum for document operations; cached discovery is advisory. Late
concurrent discovery/failures cannot overwrite or invalidate newer cached routes.

One total deadline covers discovery, dispatch, response bodies and exponential
backoff: `min(timeoutMs, retryTimeoutMs)`, where `retryTimeoutMs` defaults to
30000 and accepts 1–30000 milliseconds. Later seeds and failover get a share of
the remaining time when an endpoint stalls. Each operation permits at most 32
total endpoint requests, including discovery. Catalog convenience methods share
one deadline and attempt count across their catalog read and guarded write.
Iterator pages each get their own budget. `signal` cancels discovery, dispatch
and backoff; cancellation after dispatch can leave a mutation uncertain.

CRUD mutations, PATCH, transactions and complete catalog replacement generate
a nonzero request ID when omitted. Automatic retries on transport failure or
HTTP 503 preserve that ID, the once-serialized body bytes and preconditions.
Retries do not serialize mutable caller objects again. Every typed mutation
receipt is validated before leaving this identity boundary. Truncation,
malformed/wrong receipts, unexpected success statuses, HTTP 500, response caps,
timeouts and cancellation after dispatch retain the ID in `UncertainWriteError`.
Its `cause` retains the sanitized underlying `YamoraError`. A validation error
before dispatch or a definitive 4xx response (except 408) remains definitive;
a prior ambiguous dispatch takes precedence over a later conflict/auth error.

Persist exact primitive requests for recovery. For catalog recovery, prefer
`setIndexes` with the complete persisted catalog and revision over the
read/modify/write convenience methods. Native durable receipts are bounded by
server retention: recovery must follow that contract, rather than assume
permanent deduplication. Online catalog build start/cancel are unsupported in
replica sets and fail locally with 405. No continuous-feed or binary transport
API is added here.

## Verification and remaining stages

From the repository root, set an owned disk-backed scratch root and use the
already built daemon; tests do not rebuild it. The full test glob also includes
package acceptance: expose npm/tsc and the shared runner's `NODE_TYPE_ROOTS`,
or use the focused pinned launcher documented in the Java README:

```sh
mkdir -p /var/tmp/andromeda-work/yamora-node-driver
export TMPDIR=/var/tmp/andromeda-work/yamora-node-driver
export YAMORA_TEST_BINARY=/absolute/path/to/built/yamora
node --test drivers/node/tests/*.test.js
```

Without `YAMORA_TEST_BINARY`, only the native integration cases skip. TLS tests
require system OpenSSL to create ephemeral test certificates. Native tests
initialize private roots, launch their own daemon on OS-allocated loopback
ports, and stop it and remove their files on teardown. HTTP/TLS fixtures cover
malformed endpoints/tokens, exact YAML, conditions, redirects, no replay,
proxy isolation, deadlines, cancellation, truncation/size/framing failures and
actual trust/IP/mTLS/protocol-version failures. Native cases cover CRUD,
transactions, query pagination, int64, aggregation, search, catalogs, online
jobs, large sources and paged changes. These are focused foundation tests.

For declaration checking, supply a TypeScript compiler and Node 22 type
definitions as development tooling, then typecheck this package's tsconfig.
The compile-only fixture `tests/types.test.ts` is included by `tsconfig.json`;
the runtime command selects only `tests/*.test.js` and does not execute it.
Neither the compiler nor Node type definitions are required to execute the SDK.
The package artifact test requires them to check installed declarations;
the other runtime suites do not.
The parent must register the added JavaScript test files with the repository's
shared CI gate registry during integration; this child intentionally changes
only its SDK subtree and unique history entry. The local command above runs
all suites directly, including native cases when configured. The three-node
mTLS case drops a committed PATCH acknowledgement, kills that leader, recovers
the original receipt and checks one resulting increment; it also exercises
same-ID PUT/transaction/catalog/delete recovery, int64 queries, source bytes,
concurrent increments, representative APIs and isolated-quorum rejection.

The parent `yamora-binary-storage` task owns the enterprise roadmap. This child
does not complete its Node driver conformance checkbox. Still pending:

- Enterprise binary/streaming transport and version negotiation.
- The shared, versioned all-driver conformance suite against standalone and
  replica-set daemons, including shared numeric and uncertain-write contracts.
- Continuous NDJSON feeds, automatic feed following, bulk bootstrap and
  incremental replica orchestration; replication/session endpoints are not
  exposed by this foundation.
- Stable version guarantees, CommonJS/browser bindings, and execution on
  macOS and Windows. Only the stated Linux/Node versions were run here.
- Parent canonical combined review and shared test wiring remain separate gates;
  this worker does not run inherited-master broad readiness/review.

## Binary TLS document client

`BinaryClient` is a separate opt-in GET, HEAD, PUT and DELETE client. Existing
`Client` and `ClusterClient` continue to use HTTP. It uses only Node standard
library modules, requires TLS 1.3 and ALPN `yamora-binary/1`, and opens one
verified connection per call.

```js
import { BinaryClient, BinaryUncertainWriteError } from '@yamora/node';
import { readFileSync } from 'node:fs';

const client = new BinaryClient({
  host: '10.0.0.5', port: 7401, servername: 'database.internal',
  tls: { ca: readFileSync('/run/yamora/ca.pem') },
  maxConcurrentCalls: 4, maxFrameBytes: 4096, timeoutMs: 5000,
});
const result = await client.put('config', 'service', '# exact\r\nvalue: 01\r\n', {
  token: process.env.YAMORA_WRITE_TOKEN,
  ifNoneMatch: '*',
  requestId: '112233445566778899aabbccddeeff00',
});
const metadata = await client.head('config', 'service', {
  token: process.env.YAMORA_READ_TOKEN,
});
```

`tls.ca` must contain explicit PEM trust certificates; `tls.cert` and `tls.key`
optionally supply a paired static mTLS identity. All material is bounded using
intrinsic view sizes and copied into dedicated unpooled storage. A fresh TLS
context parses the owned bytes on each call. The numeric private IPv4 endpoint is never resolved through DNS. `servername` supplies the
certificate identity and DNS SNI; a numeric identity must equal the endpoint.
Verification callbacks, TLS context objects, proxies and redirects are not
options. No certificate chain is fetched over the network.

Each call accepts a per-request bearer `token`, `signal`, optional `timeoutMs`,
opaque `ifMatch`/`ifNoneMatch` conditions (quoted ETags are passed unchanged),
and a nonzero 32 lowercase hexadecimal `requestId`. An ID is generated when
omitted and echoed on every result. The single absolute monotonic deadline
includes admission, connection, handshake, HELLO, all fragments and strict
response decode through END. Admission is limited to 1..4 active calls; callers
waiting for capacity retain their input reference and do not copy source bytes.
Changeable inputs are snapshotted immediately after admission, before I/O.
Public byte views use captured native getters and native bounded copies; shadowed
properties and conversion hooks cannot alter their actual size or backing.
Shared backing and proxies are rejected. Source, trust, metadata, queued frames
and envelope copies use dedicated buffers, isolated from caller-visible slabs.

Sources are UTF-8 strings or nonshared `Uint8Array` bytes, preserved exactly up
to 16 MiB independently of the 4 KiB..64 KiB frame limit. HEAD returns
`representationLength`, ETag and revision without a source. DELETE requires a
complete 204 response. Acknowledgements and errors are limited to 4 KiB;
metadata is limited to 2 KiB. GET source bytes and PUT source/receipt ETags must
match the native raw-byte FNV hash (seed 1469598103934665603, multiplier
1099511628211, modulo 2^64), with budget checks at each 4 KiB chunk. Successful
PUT with `ifNoneMatch: '*'` must be 201; a present `ifMatch` requires 200. Typed
complete 4xx rejections other than 408 are certain. Truncation, malformed responses, cancellation, timeout, ERROR, GOAWAY,
and transport failures after dispatch of PUT/DELETE produce
`BinaryUncertainWriteError`. A complete 5xx/408 mutation response also remains
uncertain.

The error retains its original `requestId` and frozen `envelope` with method,
target, conditions and source length. `envelope.source` returns a fresh copy of
the privately owned original bytes; JSON and inspection omit source and bearer
credentials. Its source getter retains only the source owner, separate from the
request credential owner. Inspect actual state before explicitly resubmitting
anything.
No mutation is automatically replayed. Standalone request IDs provide no
deduplication guarantee. Binary cluster routing, durable receipt recovery,
other HTTP methods and broader transport/platform conformance remain open.
Qualification here is Linux x86-64 with Node 22.23.1 and the installed Node.

The existing `tests/*.test.js` glob discovers binary codec, TLS peer, invariant,
behavioral mutant and mandatory native acceptance suites. Set `TMPDIR` to an
owned disk-backed task scratch root. Native binary tests require the real
sanitizer executable in `YAMORA_BINARY_NATIVE` (or `YAMORA_TEST_BINARY`), pointing to the parent's
read-only integrated ASan artifact; missing executables fail rather than skip. Full
HTTP/cluster acceptance also uses `YAMORA_TEST_BINARY`. Test-owned daemons
retain fatal ASan/UBSan checks and executable digest verification. The partial
receipt case verifies committed source over HTTP before explicit resubmission.

## Replication source preflight

Before application-owned replica staging, call
`await source.requireReplicationSource(options)`. It returns readiness or throws
`YamoraError` with code `SCHEMA_POLICY_REPLICATION_UNSUPPORTED`, status 409 and
`uncertain === false`. Advertised non-booleans are protocol errors; absent fields
support older policy-free servers. Recheck before publication or applying each
source frame. This advisory read never opens a destination stage; native
outgoing and receiver admission remains authoritative.

### Raw binary operations and page feeds

`BinaryClient.operation(method, target, contentType, source, options)` adds
negotiated schema 2 for query/aggregate/search POST, transaction POST, document
PATCH and paged changes GET. It returns owned raw JSON `body` bytes, preserving
numeric spellings. Existing `get`, `head`, `put` and `delete` remain schema 1.
Credentials remain explicit through `options.token`; supply read credentials for
queries/feeds and write credentials for PATCH/transactions.

`feed(target, onPage, options)` invokes a synchronous `onPage(raw, metadata)`
callback for each complete validated NDJSON page including LF. The callback owns
its bytes and must finish before returning; asynchronous callback work is not
awaited. Persist effects and page `next_after` together; `checkpoint` is the tip.
`resumeAfter` records the last completed callback. Native terminal records remain
observable. Normal END resolves; cancellation, deadline, malformed data and EOF
reject while preserving already delivered pages. One deadline covers admission,
TLS, decoding and callbacks; heartbeats never refresh it.

Finite bodies and total feed DATA are bounded to 16 MiB; acknowledgement/error
bodies stay within 4 KiB. A protocol-1 peer fails with `BINARY_UNSUPPORTED` before
REQUEST. No HTTP fallback or automatic replay occurs. Uncertain PATCH/transaction
errors retain exact method, target, `contentType`, source, conditions and request
ID. Cancellation and EOF never establish rollback. These raw APIs do not claim
decoded numeric-value support or the HTTP 64 MiB large-profile envelope.

The separate version-3 adapter is `conformance/operations.mjs`.
