# Yamora Rust HTTP, replica-set and binary document driver

This synchronous `yamora` 0.1.0 crate provides the current YamoraDB HTTP/1.1
operations without third-party Rust crates. It uses Rust's standard library and
system `libssl`/`libcrypto` for TLS. It does not change native storage.

This is an HTTP foundation stage, **not completed enterprise driver conformance**.
Verified HTTPS replica-set discovery, bounded retries and semantic mutation receipt
recovery are implemented. Separate TLS binary document CRUD is implemented below.
Shared all-driver conformance, stream
consumers, registry publication and cross-platform qualification remain pending.
The parent enterprise roadmap owns those stages.

## Local source package and CRUD example

`yamora` remains version **0.1.0**, edition 2024, with a declared Rust 1.85
minimum. Package acceptance is qualified on Linux x86_64 with Rust/Cargo 1.95
and system OpenSSL 3.5.5. The declared minimum is not an independently tested
toolchain here. macOS, Windows, other architectures and enterprise-wide
conformance remain unqualified. This package does not alter HTTP v1, binary
`yamora-binary/1`, or the existing v1/v2 conformance profiles.

Create a local distributable source archive, without contacting a registry:

```bash
cargo package --offline --locked
```

The result is `target/package/yamora-0.1.0.crate` (under `CARGO_TARGET_DIR`
when set). Unpack it and use the extracted directory as a Cargo path dependency:

```toml
[dependencies]
yamora = { path = "../yamora-0.1.0", version = "=0.1.0" }
```

The crate is marked `publish = false`. It includes the existing MIT `LICENSE`,
README, library sources, examples and test support; the separate parent-dependent
conformance workspace is excluded. There are no Rust crate dependencies.
System OpenSSL development/linker files remain required; no OpenSSL library,
native daemon or certificate material is bundled. Pin the exact package version
and retain `Cargo.lock`; this foundation makes no future API compatibility promise.

`examples/crud.rs` creates document `package-crud` in collection `examples`,
verifies exact UTF-8 YAML bytes (comments, CRLF and quoted text), conditionally
replaces it, verifies the replacement, then conditionally deletes it. Supply
`YAMORA_HOST` (numeric
private/loopback IPv4), `YAMORA_PORT`, `YAMORA_READ_TOKEN`, `YAMORA_WRITE_TOKEN`,
`YAMORA_CA_FILE`, `YAMORA_CLIENT_CERT` and `YAMORA_CLIENT_KEY` from your trusted
configuration. The server certificate needs the host's IP SAN. Use a disposable
database; an existing document fails create-only, and an uncertain write needs
application reconciliation before repetition.

```bash
cargo run --offline --locked --example crud
```

Package acceptance requires Python 3.12+, the `openssl` CLI, an existing
TLS-capable daemon in `YAMORA_TEST_BINARY`, and a task-owned disk-backed
`TMPDIR` below `/var/tmp/andromeda-work/`. It creates a `.crate`, checks its
contents and license, relocates the extracted package, verifies Cargo metadata
resolves the dependency only from that artifact, and builds an independent
consumer. It compiles and links `Client`, `ClusterClient` and `BinaryClient`
and runs the packaged example against disposable native mTLS data.
It also checks denied write authority and independently verifies deletion.
The daemon is copied into scratch and hash-checked before/after; it is never built.
Native launches use the shared qualification harness's pre-admitted process owner
and retaining workspace. An interrupted constructor or unverified shutdown retains
the database and keys; verified shutdown removes them. Allocation is beside the
caller's disposable workspace under the validated canonical task scratch root,
derived from `TMPDIR` and checked against `ANDROMEDA_TASK` when supplied. This
preserves uncertain state even when a Rust/Python subprocess exit is reduced to
an ordinary failed status and its caller removes its own allocation.
The registered package test
also exercises these boundaries with real daemon handles alongside its normal CRUD
acceptance. Qualification requires the repository's `tools.ci.yamora_driver_ci`
and `yamora.conformance` Python fixture closure on `PYTHONPATH`; this is test
tooling, not a crate runtime dependency. For a copied SDK, the language runner
must supply that private fixture closure (as shared conformance already does).
Missing fixture imports are setup failures; these checks never skip.
Consumer Cargo metadata and compilation still exclude the SDK checkout.
The existing `cargo test --all-targets` runner includes this test automatically:

```bash
cargo test --offline --locked --test package -- --nocapture
```

This bounded smoke does **not** close the shared artifact-conformance gate.
The parent must run both `binary-document-standalone` and
`http-replica-receipt` against the extracted package. Stage the existing
binary adapter source (`conformance/src/main.rs`) and HTTP replica adapter
source (`conformance/src/bin/http_replica.rs`) in a separate scratch consumer.
Give that consumer its own workspace and an exact `yamora` 0.1.0 path
dependency on the extracted artifact; do not copy the source adapter manifest
with its `path = ".."` dependency. Build both adapter binaries offline with a
fresh Cargo home/target directory, verify their dependency manifest in Cargo
metadata is the extracted artifact, and pass their launch paths to the parent
shared profile runner. No SDK checkout may appear in consumer resolution.
The package includes all three public clients and both existing transports;
the conformance adapter workspace and shared fixture/runner remain parent inputs.

Build requirements are Rust 1.85 or newer and linkable OpenSSL 1.1.1 or newer
with TLS 1.3 support. Earlier SDK qualification used Linux x86_64 with Rust
1.95 and OpenSSL 3.6.5; local package qualification above uses OpenSSL 3.5.5.
Other OpenSSL versions, macOS and Windows remain unqualified. Native
integration tests additionally need the `openssl` CLI, Unix `kill`, and an
already-built TLS-capable Yamora daemon. The delayed-connect regression also
requires the system C compiler/linker used by Cargo and Linux `LD_PRELOAD`; its
test-only interposer delays actual TCP completion while leaving TLS intact. No daemon build or network downloads
are part of this crate's tests.

Use a Cargo path dependency pointing to this directory. A minimal operation is:

```rust,no_run
use yamora::{Client, Config, Condition, WriteOptions};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = Config::new("127.0.0.1:8765");
    config.read_token = Some(std::env::var("YAMORA_READ_TOKEN")?);
    config.write_token = Some(std::env::var("YAMORA_WRITE_TOKEN")?);
    let client = Client::new(config)?;
    let authored = b"# keep this comment\r\nname: 'first'\r\nn: 1\r\n";
    client.put("examples", "one", authored, WriteOptions {
        condition: Condition::CreateOnly, request_id: None,
    })?;
    let original = client.get("examples", "one", None)?;
    assert_eq!(original.source, authored);
    client.patch("examples", "one", br#"{"$inc":{"n":1}}"#, WriteOptions {
        condition: Condition::IfMatch(&original.etag), request_id: None,
    })?;
    let query = client.query("examples", br#"{"filter":{"n":2},"limit":10}"#)?;
    // query.body is exact JSON bytes; choose a parser in the calling application.
    assert_eq!(query.status, 200);
    Ok(())
}
```

The same example is available as `examples/raw.rs`. It uses an explicitly
configured endpoint and optional verified TLS settings from environment variables.
Run it against your own disposable collection: it creates document `one` in
collection `examples`.

## Configuration and transport contract

`Config::new(endpoint)` defaults to a five-second network deadline and a 64 MiB
response ceiling. `endpoint` must be a canonical numeric IPv4 `address:port`,
with port 1–65535 and a loopback (`127/8`) or RFC1918 address. URLs, hostnames,
credentials in endpoints, public/link-local/unspecified IPs, IPv6, URL paths,
queries and fragments are rejected. No DNS resolution is performed.

`read_token` and `write_token` are optional `String` values. Supplied tokens
must be 32–512 ASCII bytes in `!` through `~`, with no spaces or controls.
Mutations require an explicit write token and never fall back to the read token.
Query, aggregation and search POSTs use the read token. The server still enforces
authorization, including collection grants. Health does not require a token on
the server. Load credentials from the application's secret source. Configuration
and client types do not implement `Debug`; errors omit bodies and credentials.

Set `timeout` to a nonzero `Duration` up to 30 seconds. One absolute deadline
covers connect, TLS handshake and all network I/O, including trickling peers.
The standalone client has no async API or cancellation handle. Replica-set calls
have the cancellation token described below. Trusted local PEM file
loading and bounded JSON validation also take time; this is not a wall-clock
guarantee on filesystem or CPU work.

Each call uses a fresh connection and `Connection: close`. The implementation
does not consult proxy environment variables, follow redirects, reconnect,
negotiate compression, or replay any request. It accepts only bounded HTTP/1.1
responses with a single Content-Length; transfer/content encoding, folded fields,
duplicate fields, invalid framing and truncated bodies fail closed. The sole duplicate
exception is repeated `Cache-Control: no-store` (directive case and surrounding
OWS ignored), which native cluster metadata currently emits twice. Conflicting
cache directives and all framing/identity field duplicates still fail closed. Response
headers are at most 16 KiB and 64 fields; request headers are constructed solely
from validated values and fixed route templates.

`TlsOptions` requires an explicit PEM `ca_file`. An optional `ClientIdentity`
contains a PEM certificate chain and matching unencrypted private key. Encrypted
keys fail without prompting. Set `server_name: None` to verify the endpoint's
IP SAN; an explicit ASCII DNS `server_name` verifies a DNS SAN and sends SNI
without changing the numeric connection target. There is no verification bypass.
TLS minimum and maximum are both 1.3; ALPN advertises only HTTP/1.1. Certificate
CN fallback is disabled. Trust/identity files are loaded at construction for
validation and again into a fresh context on each call; protect them as trusted
local configuration. A CA/client pair is required by servers configured for mTLS;
the client identity does not replace bearer authorization.

The private unsafe module `src/tls.rs` owns every OpenSSL pointer. Memory BIOs
carry bounded records between OpenSSL and Rust socket I/O; no handwritten crypto,
raw socket BIO, global signal changes, verification callbacks, or unsafe
Send/Sync declarations are used. A shared `Client` uses only immutable Rust
configuration; each request owns its TLS objects until they are freed.

## Implemented APIs

All methods return `Result<Response>` unless indicated. A `Response` exposes
`status: u16`, exact `body: Vec<u8>`, validated 16-lowercase-hex `revision`,
optional HTTP `etag`, and `content_type`. Structured responses require JSON
content type, UTF-8, object syntax, depth at most 80 and at most 1,000,000 values.
Numbers are never converted. **Response envelope schemas, duplicate JSON keys,
body/header revision agreement, counts and cursors are not interpreted** in this
stage. Use a caller-selected JSON decoder, reject ambiguous keys and validate
these semantic fields before making application-level consistency decisions.

| Methods | HTTP operation and arguments |
| --- | --- |
| `health`, `ready`, `stats`, `metrics` | GET health/readiness/statistics; metrics returns UTF-8 text |
| `collections` | GET collection catalog as raw JSON |
| `documents_page(collection, limit, after, expected_revision)` | GET one ID page, limit 1–1000; continuation requires a pinned revision; compares response revision |
| `get(collection, document, expected_revision)` | GET `Document { source, etag, revision }`; exact raw YAML and validated, unquoted ETag; optional pinned revision |
| `put(collection, document, source, options)` | PUT exact nonempty UTF-8 YAML; accepts 200/201 |
| `patch(collection, document, operations, options)` | PATCH raw JSON operator object; accepts 200 |
| `delete(collection, document, options)` | DELETE; requires 204 and an empty body |
| `query`, `aggregate`, `search` `(collection, spec)` | POST a complete raw JSON request object with read credential |
| `transaction(spec, request_id)` | POST complete transaction envelope, including optional body revision |
| `indexes`, `set_indexes(catalog, expected_revision, request_id)` | GET / PUT the entire catalog; conditional snapshot revision on PUT |
| `start_index_build(catalog, expected_revision)` | POST catalog; accepts 202 |
| `index_builds`, `index_build(job)`, `cancel_index_build(job)` | GET current job / exact job, DELETE cancellation; 32-lowercase-hex job ID |
| `changes(after, limit)` | GET checkpoint when `after` is absent, otherwise one complete feed page; limit 1–100; token `v1.<32 hex>.<16 hex>` |
| `replication_status` | GET durable replica progress |
| `replication(phase, spec)`, `follow_replication(phase, spec)` | POST low-level replication/follow envelopes; `ReplicationPhase::{Begin, Apply, Commit, Abort}` |
| `cluster_leader`, `cluster_status` | GET advisory cluster metadata; no automatic endpoint changes or leader routing |

Collection/document identifiers are 1–128 lowercase ASCII letters, digits or
hyphens. There is no arbitrary path/header request escape hatch. Reserved
collections and JSON envelope semantics are enforced by the daemon.

`WriteOptions` holds `Condition::{Any, IfMatch(unquoted_etag), CreateOnly}` and
an optional caller-supplied, nonzero 32-lowercase-hex `request_id`. The enum
prevents conflicting conditions; create-only is supported only by PUT. PATCH
and DELETE use document ETags. Catalog conditions use snapshot revisions.
The driver quotes validators exactly once and never generates request IDs.

Raw JSON arguments are `&[u8]` containing a complete UTF-8 JSON **object**.
The driver validates syntax and bounds and transmits those bytes unchanged.
No serializer, query builder or field coercion is supplied. Use escaped `\u0085`
for NEL in JSON requests; a literal NEL is rejected because the daemon's YAML
parser gives it line-break semantics. Query pagination belongs in the complete
JSON envelope (`after` with `revision`); the application checks returned cursors
and snapshot identity. Aggregation uses `{"pipeline":[...]}`; catalogs use
`{"indexes":[...]}`; transactions use `{"operations":[...],"revision":"..."}`.
Replication calls are primitives: the caller owns session lifetime, atomic
commit grouping, source verification, progress persistence and abort on failure.

Limits are 16 MiB for raw documents, 2 MiB for query/search/aggregation, catalog,
job submission, replication begin/commit/abort, and 64 MiB for PATCH,
transactions and replication apply. Responses are bounded by
`Config::max_response_bytes` (1 byte–64 MiB), additionally capped at 16 MiB
for document reads, PUT receipts, metrics and cancellation; DELETE allows zero.
The daemon can impose stricter per-format, principal and admission limits.

`ErrorKind` distinguishes local invalid input/protocol, HTTP status, timeout,
TLS and I/O kinds. No error includes the remote body. After a mutation starts
sending, transport/protocol errors, 408 and 5xx conservatively set
`may_have_committed`; ordinary 4xx rejection leaves it false. A false flag is
not an application-wide rollback or crash-durability guarantee. After uncertainty,
reconcile with reads and preconditions; do not blindly submit another mutation.
Use `ClusterClient` for the explicit replica-set recovery policy below. The
standalone client continues to send exactly once.

## Replica sets

`ClusterClient` exposes the same named raw operations as `Client`, plus immutable
prepared mutations. Existing standalone method signatures, raw JSON/YAML bytes and
single-dispatch behavior are preserved. Cluster operations return
`Result<T, ClusterError>`; construction and preparation return `Result<T, Error>`.

```rust,no_run
use yamora::{ClusterClient, ClusterConfig, ClusterError, ClusterSeed, Condition,
             TlsOptions, WriteOptions};
use std::{path::PathBuf, time::Duration};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let tls = TlsOptions {
        ca_file: PathBuf::from("/trusted/cluster-ca.pem"),
        identity: None, // supply ClientIdentity when the daemon requires mTLS
        server_name: Some("documents.internal".into()),
    };
    let seeds = vec![
        ClusterSeed::new("10.0.0.11:8765", 1, tls.clone()),
        ClusterSeed::new("10.0.0.12:8765", 2, tls.clone()),
        ClusterSeed::new("10.0.0.13:8765", 3, tls),
    ];
    let mut config = ClusterConfig::new(seeds, 3);
    config.read_token = Some(std::env::var("YAMORA_READ_TOKEN")?);
    config.write_token = Some(std::env::var("YAMORA_WRITE_TOKEN")?);
    config.timeout = Duration::from_secs(20);
    let client = ClusterClient::new(config)?;
    let prepared = client.prepare_put("examples", "one", b"# authored\r\nn: 0\r\n",
        WriteOptions { condition: Condition::CreateOnly, request_id: None })?;
    // Persist these recovery inputs in the application's own durable job record.
    // body(), method(), path(), condition(), request_id() expose the exact envelope.
    match client.execute(&prepared) {
        Ok(receipt) => assert_eq!(receipt.status, 201),
        Err(ClusterError::Uncertain(error)) => {
            assert_eq!(error.mutation, prepared);
            assert_eq!(error.request_id(), prepared.request_id());
            // After restoring availability, execute this same envelope. Never
            // change its bytes/preconditions or generate a replacement identity.
            let _original_receipt = client.execute(&error.mutation)?;
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}
```

`ClusterConfig::new(seeds, voters)` accepts 1–9 trusted seeds with distinct
canonical private/loopback IPv4 endpoints and distinct expected node IDs. The
configured electorate is 3, 5, 7 or 9; node IDs must be within it. Each seed
requires `TlsOptions`, optionally with its own verification name/client identity.
Defaults are a 30-second logical deadline, a three-second per-attempt ceiling and
a 64 MiB response ceiling. Both timeouts must be 1 ms–30 seconds. Credentials and
response ceilings have the standalone limits.

**Trust boundary:** the caller supplies a dedicated CA/SAN policy and expected
node/voter bindings for these endpoints. Discovery reads `/v1/cluster/status`
only from those verified HTTPS seeds, validates the responding node against its
configured binding, validates the voter count, exact positive u64 term, leader
role/identity, failure flag and log-position relationships. A node number is
never interpreted as an array index or address. Unknown routing fields, duplicate
JSON keys (including escaped equivalents), fractional/overflowing integers and
malformed metadata cannot establish a route. Server hints, redirects and proxy
environment variables never extend the trust set or route credentials.

The existing HTTP protocol exposes **no cluster UUID** in either cluster status
or leader metadata. This SDK does not attest a UUID, infer one from a revision or
invent an absent field. Dedicated CA/SAN configuration is the caller's cluster
trust boundary; node/voter checks validate only the identities actually supplied
by that protocol. A server holding trusted credentials can make false metadata
claims, so sharing that trust policy with unrelated clusters is unsafe.

One logical network deadline covers discovery, every dispatch, fair per-attempt
budgets and exponential backoff (25 ms initially, capped at 500 ms). At most 32
network attempts, including discovery, are made. Discovery reserves time for each
remaining seed and a dispatch; a cached leader cannot consume the entire budget
when alternatives exist. Route publication/invalidation compares generations so
stale concurrent calls cannot replace or erase newer routing. Trusted local PEM
loading and bounded input/JSON processing are synchronous CPU/filesystem work;
this is not a hard wall-clock guarantee for a stalled local filesystem.

`CancellationToken::new()` creates a one-way token; `client.cancellable(&token)`
returns a handle sharing the route cache with cancellation scoped to that token.
`cancel()` is checked before discovery/dispatch, during socket I/O (20 ms polling)
and backoff (10 ms polling), and after receipt validation. On Linux, a single
owned nonblocking TCP socket remains alive across connect polling slices; polling
does not restart the connection or cap it at 20 ms. Cancellable connect is
currently qualified only on Linux; other platforms reject that path explicitly.
The SDK starts no background threads, and each call releases its socket/TLS objects before returning.
Cancelled reads and undispatched writes are `ClusterError::Failure`; dispatched
ambiguous mutations remain `ClusterError::Uncertain`.

`prepare_put`, `prepare_patch`, `prepare_delete`, `prepare_transaction` and
`prepare_set_indexes` own the exact body, operation, preconditions and nonzero
32-lowercase-hex ID. A supplied ID is retained; an absent ID is generated once
from the OS CSPRNG (`/dev/urandom` on the currently qualified Unix platform).
`PreparedMutation` is cloneable but its fields cannot be mutated. Named mutation
methods also freeze their envelope before the first connection. Retries send
identical bytes, preconditions and ID. Prepared objects contain no credential;
diagnostic formatting omits source and response bodies.

All fallible mutation receipt checks run **inside recovery**, including the raw
transaction and entire-catalog APIs. Document receipts require `stored`, exact
collection/document identities, valid body ETag matching the HTTP ETag, and
body/header revision agreement. PUT status must also agree with the frozen
precondition: create-only requires 201, If-Match requires 200, and unconditional
PUT accepts either. Transaction/catalog receipts require `committed`,
the exact operation count (catalog replacement is one), and matching revision.
DELETE requires 204, no body and a valid revision. Any supplied response ETag must
be valid. Unexpected success statuses, malformed/truncated/oversize responses,
semantic receipt errors, 408, redirects and 5xx after dispatch retain the
original envelope in `ClusterError::Uncertain(Box<UncertainWriteError>)`.
Ordinary 4xx rejection is definitive until a prior dispatch in the same call was
uncertain; that uncertainty survives a later rejection, discovery failure,
deadline or cancellation. Failure before dispatch does not imply a commit.
Transport failures and 503 can retry within the same budget; malformed receipts
return uncertainty immediately for explicit recovery.

Safe retry depends on the native replica set's durable same-ID receipt ledger.
Native acceptance tests verify that a lost committed reply, subsequent election,
concurrent calls and full restart preserve the original receipt and apply an
increment once. These are protocol-scoped guarantees, not cross-cluster ID
attestation or unlimited receipt retention guarantees. Keep recovery within the
server's supported identity/receipt lifetime.

Cluster writes support document PUT/PATCH/DELETE, transactions and catalog PUT.
Index-build and low-level replication writes fail locally with a definitive 405.
Raw transaction input is additionally checked for 1–128 unique document identities,
exactly one mutation mode and valid preconditions. Cluster JSON semantic decoding
is bounded to depth 80 and 65,536 values, retains numeric lexemes without floating
point and rejects duplicate keys; raw standalone decoding remains syntax-only.
Raw query/read envelopes remain caller-owned consistency contracts beyond these
cluster routing and mutation receipt checks.

## Verification

From this directory, point scratch and the build target at the active task root:

```sh
export TMPDIR=/var/tmp/andromeda-work/yamora-rust-cluster
export CARGO_TARGET_DIR="$TMPDIR/target"
mkdir -p "$TMPDIR"
cargo fmt --check
cargo clippy --offline --locked --all-targets -- -D warnings
cargo test --offline --locked --lib --test http --test cluster
cargo build --offline --locked --example raw
export YAMORA_TEST_BINARY=/absolute/path/to/existing/yamora
cargo test --offline --locked --all-targets -- --test-threads=1
```

Native tests fail with an actionable message if the binary or task scratch is
missing. They never silently skip, rebuild the daemon or use the owner server.
They initialize their own native stores, use ephemeral loopback ports, issue
their own test certificates, shut down only their own children, inspect daemon
logs for ASAN/UBSAN failures, and remove their unique data/cert directories on
normal success or panic. Cargo output remains task-owned and must be removed
with the task's normal scratch cleanup. Test ports explicitly reject 8000.
The example executable is found beside the test build, or can be selected with
`YAMORA_RUST_EXAMPLE=/absolute/path/to/raw`.

The tests cover invalid inputs, exact YAML and JSON bytes, conditional errors,
full and incremental replica publication, metadata/query/search/aggregation,
transactions, jobs/feed calls, redirects, hostile/truncated/oversized responses,
no proxy use, standalone no-replay, cluster same-ID recovery after lost
acknowledgements, node/voter trust binding, concurrent routing, cancellation,
deadlines, verified TLS/mTLS,
unknown CAs, wrong DNS/IP SANs, mismatched client keys, missing client certificates
and TLS 1.2 rejection. The cluster-native target runs real three-node TLS stores,
leader failover, committed malformed receipts for each mutation family, quorum
loss and full restart with exact original YAML and durable receipt comparisons.
Separate native same-ID and distinct-ID tests hold four complete SDK mutation
requests at a bounded HTTPS gateway gate before release; inflight/arrival/timeout
counters must be exactly `0 4 4 0` after drain. A serialized-dispatch mutant
produces `0 1 4 4` and fails both tests, preventing thread creation alone from
being presented as proof of overlapping dispatch.

Remaining stages: binary cluster discovery, streaming protocol and shared conformance; stronger
typed response/envelope validation; cancellable async calls; validated pagination
iterators and consistent exports; continuous NDJSON and replication consumers;
registry publication/version guarantees and macOS/Windows integration. Full
binary/shared cross-driver conformance remains explicitly open. Shared
CI/gate registration belongs to parent integration (outside this subtree).


## Binary document CRUD

`BinaryClient` is independent of `Client` and `ClusterClient`. It implements only
GET, HEAD, PUT and DELETE on one configured canonical loopback/RFC1918 IPv4
endpoint. HTTP retains every existing API. There is no binary discovery, DNS
routing, proxy, redirect, reconnect or automatic replay. Linux x86_64 is the
qualified platform; broad transport/platform conformance remains OPEN.

```rust,no_run
use yamora::{BinaryClient, BinaryConfig, BinaryTlsConfig, BinaryOptions};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let tls = BinaryTlsConfig {
        root_pem: std::fs::read("/trusted/ca.pem")?,
        server_name: "documents.internal".into(),
        identity: None, // BinaryIdentity owns PEM certificate chain/private key bytes
    };
    let client = BinaryClient::new(BinaryConfig::new("10.0.0.11:7401".into(), tls))?;
    let token = std::env::var("YAMORA_WRITE_TOKEN")?;
    let result = client.put("examples", "one", b"# exact\r\nvalue: 01\r\n",
        BinaryOptions { bearer: Some(&token), if_none_match: Some("*"), ..Default::default() });
    match result {
        Ok(receipt) => assert_eq!(receipt.status, 201),
        Err(error) if error.may_have_committed() => {
            let original = error.envelope().unwrap();
            // Retain source(), method(), collection(), document(), conditions and
            // request_id(). First independently inspect storage and availability.
            // Only explicitly, with credentials supplied again:
            let _explicit_result = client.replay(original, Some(&token), None);
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}
```

Configuration transfers owned static PEM bytes into the client; no caller paths,
OpenSSL contexts, opaque trust pools, verification callbacks, session caches or
insecure mode are accepted. Root and client certificate bundles each permit
1–32 certificate blocks within 64 KiB. Keys must be matching, unencrypted PEM
(PKCS#8, RSA or EC) within 64 KiB. Each operation creates and frees its own
OpenSSL context, SSL, memory BIOs and socket. TLS 1.3 and selected ALPN exactly
`yamora-binary/1` are mandatory. The frozen expected DNS/IP SAN is independent
of the numeric route. A client certificate does not grant bearer permissions.
Credentials exist only in `BinaryOptions` for that call; envelopes and errors
omit them and diagnostic formatting redacts source bytes.

`BinaryOptions` accepts optional `if_match` and `if_none_match` strings, including
present empty conditions, and optional `[u8; 16]` request identity. Conditions
pass unchanged to native validators. Zero IDs are rejected. Mutations generate a
nonzero cryptographically random ID when absent. Responses require the exact
presence and value of the request ID; unsolicited, missing and unequal IDs fail.

The client admits at most four calls (configurable 1–4). Waiters retain borrowed
input; copying begins only after admission. Rust borrowing prohibits safe caller
mutation during the call. The original immutable upload, preconditions and ID
survive every ambiguous dispatched mutation failure, including malformed semantic
receipts, generic ERROR1, GOAWAY, EOF, missing END, deadline and cancellation.
`BinaryEnvelope` clones share immutable private storage with no mutable accessor.
Explicit `replay` repeats that envelope with a new per-call credential/deadline.
Standalone request IDs provide correlation, **no deduplication guarantee**.
Native cluster same-ID behavior does not imply binary discovery or qualification.

One monotonic deadline starts at call entry and covers admission, source copy,
TCP/TLS, negotiation, every fragment, decoding, native source hash and final
guard. The default is five seconds, configurable to a nonzero duration up to
30 seconds. `BinaryOptions::cancellation` borrows a `CancellationToken`; socket
I/O polls that token in bounded slices. TCP connect polls the same owned socket
without restarting SYNs. There are no callbacks or background workers to outlive
a call. Input copy, UTF-8 and hash work check the guard every 4 KiB; JSON is
bounded to 4 KiB with strict UTF-8, duplicate rejection and depth/node limits.
OpenSSL verification calls and scheduler delays cannot be preempted mid-call.

Frames negotiate 4–64 KiB locally while documents remain independently capped at
16 MiB. Headers, frame shapes, ordered unique TLVs, HELLO caps and method/status
budgets are validated before allocation. Success needs exact declared DATA plus
END. PUT create-only requires 201, If-Match requires 200; unconditional accepts
200/201. Receipt identity, revision and ETag must agree with metadata. Successful
GET and frozen PUT source are hashed with native unsigned-octet modulo-2^64
arithmetic (seed `1469598103934665603`, multiplier `1099511628211`). HEAD carries
no DATA but retains representation length; DELETE requires empty 204.
`BinaryResponse::body()` exposes only an immutable slice.

Additional qualification commands from the repository root, with the existing
native binary and task scratch environment from Verification above:

```sh
cargo test --manifest-path yamora/drivers/rust/Cargo.toml --offline --locked --test binary --test binary_admission -j2 -- --test-threads=1
python3 yamora/drivers/rust/tests/prove_binary_guards.py
```

`cargo test --all-targets` includes both registered integration targets. Any
parent runner enumerating test targets must include `--test binary --test
binary_admission`. The mutant runner builds precise broken guards in disposable
scratch and requires the exact behavioral assertion and observed dispatch;
compiler errors, signals, timeouts, fixture failures and sanitizer diagnostics
cannot prove a red. Native tests use the actual immutable daemon, fatal
ASan/UBSan, mTLS, HTTP storage observation before explicit repetition, exact
CRLF/Unicode/comments, 16 MiB/4 KiB fragments and the legacy 256 KiB profile.

## Replication source preflight

Before application-owned replica staging, call `source.require_replication_source()`.
It returns readiness or an error with kind
`ErrorKind::SchemaPolicyReplicationUnsupported` and `may_have_committed == false`.
Advertised non-booleans fail validation; absent fields support older policy-free
servers. Recheck before publication or applying each source frame. This advisory
read never opens a destination stage; native outgoing and receiver admission
remains authoritative.

## Additive binary operations (schema 2)

`BinaryClient::operation(method, target, content_type, source, options)` accepts
`BinaryOperationMethod::{Get, Post, Patch}` for native changes pages,
query/aggregate/search, PATCH and atomic transactions. It negotiates protocol 2;
the existing document methods continue to use schema 1. Supply raw YAML or JSON
specification bytes and their explicit content type. Results expose immutable
raw `body()` bytes and actual `metadata`, including the echoed request ID.
Numbers are validated as original decimal lexemes and never converted to floats.
Bodies and complete-feed bytes are bounded to 16 MiB; JSON validation permits
80 levels and 65,536 values, rejecting duplicate keys.

`client.feed(target, options, |page| { consume(page.bytes()); true })` delivers
one complete validated NDJSON page at a time. The callback must finish before
another page is read; returning false cancels the call. `BinaryFeedResult`
contains response metadata, the last delivered cursor and an optional native
terminal status. Normal END is required for success. A native terminal record
is delivered intact before END. An incomplete/invalid later page never reaches
the callback. Errors retain validated metadata and `last_after`, preserving the
completed prefix without asserting complete delivery. Callbacks can retain
copies deliberately; the SDK does not collect the feed.

One absolute timeout covers admission, TLS, request, validation, callbacks and
END. Cancellation closes this operation's socket. A dispatched PATCH or
transaction without a validated receipt returns `BinaryOperationError` with
`may_have_committed()` and an immutable original `envelope()`: method, target,
content type, exact source, conditions and ID. Query POST is read-only. There is
no automatic replay, reconnect, rollback claim or HTTP fallback.

The version-3 adapter is `conformance/src/bin/operations.rs`; build it with
`cargo build --locked --manifest-path yamora/drivers/rust/conformance/Cargo.toml --bin operations`.
