# Yamora C++17 HTTP, replica-set and binary document driver

C++17 on Linux with the standard library, POSIX sockets and system OpenSSL
1.1.1 or newer. No database engine, HTTP, YAML or JSON runtime is required.
The standalone `Client` retains its raw HTTP API; additive `ClusterClient`
provides the static replica-set profile described below. This is not completed
enterprise roadmap driver conformance. Native storage is unchanged. Separate
`BinaryClient` supports verified TLS document CRUD, finite operations and bounded page feeds. Shared all-driver conformance,
binary cluster discovery and cross-platform qualification remain OPEN.

## Build and use

Build this directory with CMake and link `yamora::cpp`; its public header is
`<yamora/client.hpp>`. The library is static by default; `BUILD_SHARED_LIBS`
selects a shared library. A C++17 compiler and system OpenSSL development files
must already be installed. Python 3.12+ and the `openssl` CLI are test-only
requirements; `BUILD_TESTING=OFF` removes them.

From the repository root:

```bash
mkdir -p /var/tmp/andromeda-work/yamora-cpp-driver
TMPDIR=/var/tmp/andromeda-work/yamora-cpp-driver cmake \
  -S yamora/drivers/cpp -B /var/tmp/andromeda-work/yamora-cpp-driver/build \
  -DCMAKE_BUILD_TYPE=Debug
TMPDIR=/var/tmp/andromeda-work/yamora-cpp-driver cmake \
  --build /var/tmp/andromeda-work/yamora-cpp-driver/build -j2
```

An application can use CMake `add_subdirectory` for this SDK and
`target_link_libraries(your_application PRIVATE yamora::cpp)`.

### Local distributable package

Version **0.1.0** supports local installation and a CPack TGZ artifact. Only
Linux x86_64/C++17 is qualified; macOS, Windows and other architectures remain
unqualified. Package acceptance uses Clang 21.1.8, CMake/CPack 4.2.3 and system OpenSSL
3.5.5. OpenSSL 1.1.1 remains the declared dependency minimum, not an independently
tested configuration here. This changes no HTTP v1, binary `yamora-binary/1`,
or v1/v2 conformance semantics.

Use task-owned scratch for these build and install directories:

```bash
cmake -S . -B "$TMPDIR/cpp-build" -DBUILD_TESTING=OFF -DCMAKE_BUILD_TYPE=Release
cmake --build "$TMPDIR/cpp-build" -j1
cmake --install "$TMPDIR/cpp-build" --prefix "$TMPDIR/cpp-install"
cpack --config "$TMPDIR/cpp-build/CPackConfig.cmake" -G TGZ -B "$TMPDIR/packages"
```

Unpack the archive into a local prefix. An independent consumer uses:

```cmake
find_package(yamora_cpp 0.1.0 EXACT CONFIG REQUIRED)
target_link_libraries(your_application PRIVATE yamora::cpp)
```

Configure with `-DCMAKE_PREFIX_PATH=/absolute/extracted/prefix`. The exported
target carries C++17, public include paths, `OpenSSL::SSL`, `OpenSSL::Crypto`
and `Threads::Threads`; consumers still need those system development libraries.
Both public headers, the built library, relocatable CMake config/version files,
the exact existing MIT `LICENSE`, README and example sources are included.
OpenSSL, the native daemon and test credentials are not bundled. No registry
publication, signing or upload is performed. Version selection is exact for
this foundation; a pre-1.0 package does not promise a stable C++ ABI. Rebuild
for the consumer's compiler, standard library, architecture and build flags.
`BUILD_SHARED_LIBS=ON` selects a shared artifact subject to those same limits.
Keep GNUInstallDirs destinations relative to preserve relocation; absolute
custom install destinations are outside this qualification.

The installed `share/yamora_cpp/examples/crud.cpp` uses public APIs to create,
read, conditionally replace, verify and delete document `package-crud` in
collection `examples`.
It checks byte-exact comments, Unicode, CRLF and quoted text. Set `YAMORA_HOST`
(numeric private/loopback IPv4), `YAMORA_PORT`, `YAMORA_READ_TOKEN`,
`YAMORA_WRITE_TOKEN`, `YAMORA_CA_FILE`, `YAMORA_CLIENT_CERT` and
`YAMORA_CLIENT_KEY` from trusted configuration; the server needs the host's
IP SAN. Use disposable data. Create-only protects an existing document, and
uncertain mutation failures require reconciliation before repetition.

```bash
cmake -S "$TMPDIR/cpp-install/share/yamora_cpp/examples" -B "$TMPDIR/cpp-example" \
  -DCMAKE_PREFIX_PATH="$TMPDIR/cpp-install"
cmake --build "$TMPDIR/cpp-example" -j1
"$TMPDIR/cpp-example/yamora_crud"
```

With `BUILD_TESTING=ON`, existing CTest registration includes
`cpp_package_smoke`. It requires Python 3.12+, the `openssl` CLI,
`YAMORA_TEST_BINARY` naming an existing TLS-capable daemon, and task-owned
disk-backed `TMPDIR`. It builds a TGZ from the enclosing build, extracts and
relocates it, compiles independent consumers linking `Client`, `ClusterClient`
and `BinaryClient`, checks their imported library/headers resolve within that
artifact and their compiler commands exclude the checkout/producer build,
rejects an incompatible requested package version, and runs the installed CRUD example
against disposable native mTLS data. It checks denied write authority and
independently verifies deletion. The producer's actual compiler, flags and
toolchain settings are reused. The daemon is copied and hash-checked; no
daemon build or full SDK suite is part of this focused check.

```bash
ctest --test-dir "$TMPDIR/cpp-build" -R '^cpp_package_smoke$' --output-on-failure
```

This bounded smoke does **not** close shared artifact conformance. The parent
must run both `binary-document-standalone` and `http-replica-receipt` against
the installed/extracted package. Stage `conformance/main.cpp` and
`conformance/http_replica.cpp` in a separate scratch consumer project that
uses `find_package(yamora_cpp 0.1.0 EXACT CONFIG REQUIRED)` and links only
`yamora::cpp`. Do not reuse the source conformance CMake file's
`add_subdirectory(.. sdk)`. Pin `yamora_cpp_DIR` to the extracted config
directory, disable user/system package registries, and exclude SDK checkout
paths from package/module searches and compiler include/library inputs.
Verify the imported target's library and public include paths are inside the
artifact. For a shared package, put its library directory first in the consumer
loader path. Then give the two adapter launch paths to the parent shared profile
runner. The package exposes all existing public clients/transports; the
adapter sources and shared fixture/runner remain separate parent inputs.

```cpp
#include <yamora/client.hpp>

void example(const std::string& read_token, const std::string& write_token) {
    yamora::Config config;
    config.read_token = read_token;
    config.write_token = write_token;
    // Set config.tls to a yamora::TLS trust bundle and optional client
    // certificate/key before creating the client when using HTTPS.
    yamora::Client db(config);
    yamora::WriteOptions create;
    create.create_only = true;
    db.put("examples", "one", "# authored YAML\r\nn: 1 # retained\r\n", create);
    auto document = db.get("examples", "one");
    yamora::WriteOptions replace;
    replace.etag = document.etag;
    db.patch("examples", "one", R"({"$inc":{"n":1}})", replace);
    yamora::CallOptions query;
    query.collection = "examples";
    auto page = db.call(yamora::Operation::query, R"({"limit":10})", query);
    // page.body is raw JSON; use an application-selected decoder if needed.
}
```

## Connection and errors

`Client(Config)` copies configuration. Copies of a client share an immutable
configuration and OpenSSL context; concurrent calls use separate connections.
Calls are synchronous. String views must remain valid until the call returns;
responses own their strings.

| Configuration | Contract |
| --- | --- |
| `host` | Numeric IPv4: loopback 127/8 or RFC1918 10/8, 172.16/12, 192.168/16; default 127.0.0.1 |
| `port` | Integer 1–65535; default 8765 |
| `read_token`, `write_token` | Empty or 32–512 ASCII bytes in range 33–126, matching Go validation; never loaded from a file or logged by this driver |
| `timeout` | One absolute monotonic deadline for connect, TLS, writes, headers and body; 1–30000 ms, default 5000 |
| `tls` | Null selects HTTP; otherwise a copied TLS configuration enables verified TLS 1.3 exclusively |
| `document_limit` | 1–16 MiB, default 16 MiB |
| `request_limit` | 1–64 MiB, default 64 MiB; operation ceilings below also apply |
| `response_limit` | 1–64 MiB, default 64 MiB; operation ceilings below also apply |

`TLS.ca_file` is an explicit PEM trust bundle; empty uses OpenSSL system trust
paths, including its standard trust-path environment overrides.
`certificate_file` and `private_key_file` are either both empty or a matching
PEM client certificate chain/key. Encrypted keys fail without prompting.
The peer certificate must validate for the configured **numeric IP**, including
its IP SAN. There is no hostname override or insecure mode. HTTP/1.1 ALPN is
advertised. Every call opens a new socket/TLS connection. No environment proxy
or DNS is consulted. Redirects reject; TLS early data and automatic retries or
reconnections are absent. The Linux socket BIO uses `MSG_NOSIGNAL` without
changing application signal handlers.

`yamora::Error` exposes `kind()` (`invalid_argument`, `transport`, `protocol`,
`http`), `status()` (HTTP status or zero), and `uncertain()`. Messages omit
credentials, remote bodies and redirect locations. A mutation attempted on the
wire has an uncertain result after transport/protocol failures, HTTP 408, 5xx,
or an unexpected non-error status. Invalid arguments or failed connections
before submission have `uncertain() == false`. Standard C++ allocation
exceptions can propagate too: reconcile served state after any exception during
a mutation before submitting again. A 500 can follow publication; an error
does not establish rollback or durability.

Mutation `request_id` options accept optional **nonzero 32-character lowercase
hex** identities. They are sent unchanged, never generated or replayed. Keep
exact request bytes and identity for application-managed replica-set retries.
`Client` performs no discovery, retry or replica-set binding. Its cluster
metadata calls remain raw advisory reads; use `ClusterClient` for routing and recovery.

## Exact YAML and preconditions

Collection/document IDs are 1–128 lowercase ASCII letters, digits and hyphens.
URLs, percent escapes, separators, whitespace, uppercase, NUL and traversal
reject before connection. Revision/ETag arguments are unquoted **16-character
lowercase hex** strings. YAML input is nonempty, bounded UTF-8; NUL and ASCII C0
controls other than tab/CR/LF reject. The daemon validates its YAML semantic profile. The
driver never parses or reserializes YAML, and raw GET returns legacy source
bytes without a new UTF-8 requirement.

| Method | Behavior |
| --- | --- |
| `get(collection, document, revision="")` | Exact `Document.source`, unquoted `etag`, snapshot `revision`; optional revision must match the response header |
| `put(collection, document, source, WriteOptions={})` | Raw YAML; 201 create/200 replace; `create_only` sends `If-None-Match: *`; `etag` sends quoted `If-Match`; combining both rejects |
| `patch(collection, document, json, WriteOptions={})` | Raw JSON operator map, e.g. `{"$inc":{"n":1}}`; optional ETag; `create_only` rejects |
| `erase(collection, document, WriteOptions={})` | DELETE; optional ETag; 204/empty body; `create_only` rejects |
| `documents(collection, limit=1000, after="", revision="")` | Raw JSON ID page; limit 1–1000, exclusive validated ID cursor, optional response revision check |

Mutations return `Response`: integer `status`, raw JSON `body`, validated header
`revision`, and unquoted `etag` if a header supplies one. PUT/PATCH receipt
fields inside JSON are not extracted; parse the receipt or use GET for the
content ETag. DELETE returns an empty body.

## Raw JSON operations

`call(Operation, json="", CallOptions={})` constructs only the routes below.
GET/DELETE operations reject bodies; POST/PUT require nonempty bounded UTF-8.
**Standalone `Client` does not parse JSON syntax, nesting, field types, semantic
schemas or body/header revision equality.** The daemon validates
requests. Callers must decode and validate response schemas before acting on
them. Literal U+0085 in request JSON rejects because LibYAML interprets it as a
line break; use JSON escape `\u0085`. Complete request/response bytes preserve
64-bit integer, decimal/exponent and escape tokens without floating-point
conversion. The driver does not validate feed order, advance cursors, loop
pages, compute replication revisions, or implicitly apply replicas.

`CallOptions.collection` is required only for query/aggregate/search. `job_id`
applies only to index-build reads/cancellation (32 lowercase hex; required for
cancellation). `after` and `limit` apply only to changes (limit 1–100, default
100; token `v1.<32 lowercase hex>.<16 lowercase hex>`). Without `after`, changes
reads the checkpoint and limit has no effect. Unexpected options reject.
`revision` sends a quoted database If-Match for catalog mutations; on reads it
checks the response header. Other mutations put their conditions inside JSON
and reject `CallOptions.revision`. `request_id` applies only to mutations.

| Operation | HTTP method/path | Credential and body |
| --- | --- | --- |
| `health`, `ready`, `stats`, `metrics` | GET `/healthz`, `/readyz`, `/v1/stats`, `/metrics` | Read; health also works unauthenticated |
| `collections` | GET `/v1/collections` | Read |
| `indexes`, `set_indexes` | GET/PUT `/v1/indexes` | Read/write; PUT `{"indexes":[...]}` replaces the whole catalog |
| `start_index_build` | POST `/v1/index-builds` | Write; `{"indexes":[...]}`; optional revision condition; 202 |
| `index_build` | GET `/v1/index-builds[/<job_id>]` | Read |
| `cancel_index_build` | DELETE `/v1/index-builds/<job_id>` | Write; 202, remote cancellation request |
| `query` | POST `/v1/query/<collection>` | Read; filter/sort/projection/limit/after/revision/count/explain JSON object |
| `aggregate` | POST `/v1/aggregate/<collection>` | Read; `{"pipeline":[...],"revision":"optional hex"}` |
| `search` | POST `/v1/search/<collection>` | Read; `{"index":"words","text":"term",...}` |
| `transaction` | POST `/v1/transactions` | Write; `{"operations":[...],"revision":"optional hex"}` |
| `changes` | GET `/v1/changes[?after=TOKEN&limit=N]` | Read; checkpoint or complete-commit page |
| `replication_status` | GET `/v1/replication/status` | Read; destination position |
| `replication_begin` | POST `/v1/replication/begin` | Write; revision, collections, optional full/revision_scheme/source_after |
| `replication_apply` | POST `/v1/replication/apply` | Write; session and operations |
| `replication_commit`, `replication_abort` | POST `/v1/replication/commit`, `/v1/replication/abort` | Write; session; optional documented commit revision |
| `follow_begin` | POST `/v1/replication/follow/begin` | Write; after, token, previous_revision, revision, integer operations count |
| `follow_apply` | POST `/v1/replication/follow/apply` | Write; session and operations |
| `follow_commit`, `follow_abort` | POST `/v1/replication/follow/commit`, `/v1/replication/follow/abort` | Write; session |
| `cluster_leader`, `cluster_status` | GET `/v1/cluster/leader`, `/v1/cluster/status` | Read; daemon profile/access policy applies, no routing/retry |

Expected status is 200 except index start/cancel (202), document PUT (200/201)
and document DELETE (204). Response media must be JSON, YAML for raw GET, or
text/plain for metrics. Every success needs a well-formed snapshot revision
header. Raw GET requires a strong content ETag. Callers must check the revision
on every export page/document and discard an export on any mismatch.

## Limits and tests

| Boundary | Client ceiling |
| --- | --- |
| Raw PUT input | 16 MiB and configured document/request limit |
| PATCH, transactions, replication/follow apply input | 64 MiB and configured request limit |
| Other structured input | 2 MiB and configured request limit |
| Response headers | 16 KiB, at most 64 unique fields; duplicates/folding/controls reject |
| Raw GET and document mutation responses | 16 MiB and configured document/response limit; DELETE 0 |
| Metrics | 16 MiB and configured response limit |
| Other operation responses | 64 MiB and configured response limit |

HTTP/1.1 with decimal Content-Length is required. Missing/overflowing lengths,
truncation, transfer/content encodings, upgrades, wrong media and wrong revisions
reject. There is no decompression. Error bodies are not consumed. Each call
needs memory proportional to its bounded response. Daemon profiles and
individual operations may impose smaller ceilings and return HTTP errors.

CMake builds a probe against the public API; CTest runs it. The suite covers bad endpoints,
tokens, paths and inputs; exact wire/source bytes; credentials and proxy bypass;
redirects/no replay; framing, truncation and size bounds; absolute slow-peer
deadlines; actual CA/IP/TLS-version/mTLS failures; native CRUD/ETags,
query/aggregation/search, catalog jobs, transactions, pagination and durable
feeds; full replica bootstrap, incremental follow/abort and native mTLS.
Fixtures own data, ephemeral loopback ports, certificates and cleanup under
the supplied task TMPDIR. Missing native binaries fail instead of skipping;
tests never rebuild the daemon or silently substitute mocks.

Set `YAMORA_TEST_BINARY` to an existing compatible read/execute-only daemon.
Then, from the repository root:

```bash
TMPDIR=/var/tmp/andromeda-work/yamora-cpp-driver ctest \
  --test-dir /var/tmp/andromeda-work/yamora-cpp-driver/build --output-on-failure
```

Shared CI/Makefile registration belongs to parent integration. This subtree
provides its CTest entry without changing shared build files.

Remaining stages: enterprise binary transport, shared cross-driver conformance,
full typed result schemas, continuous streams/backpressure/consumer progress,
packaging/compatibility guarantees, macOS/Windows and broader daemon
qualification. Linux HTTP and static replica-set evidence does not establish
these capabilities. Parent integration owns shared runner/registry wiring;
this slice does not close enterprise conformance.


## Static replica sets

`ClusterClient` shares the standalone document and raw JSON method shapes:
`get`, `put`, `patch`, `erase`, `documents`, and `call(Operation, json, options)`.
Query counting uses `Operation::query` with `{"count_only":true}` (`matched` in
the raw response). Paging, aggregation, search, synchronous catalog replacement,
transactions, and finite changes use the same existing HTTP profile.
Online index jobs and replication operations are outside this client's cluster
profile. They raise `invalid_argument` before discovery or dispatch, even when
the daemon supports those routes. The SDK exposes no continuous-feed API.

```cpp
void cluster_example(const std::shared_ptr<const yamora::TLS>& tls,
                     const std::string& read_token, const std::string& write_token) {
    yamora::ClusterConfig config;
    config.seeds = {{"127.0.0.1", 18761, 1}, {"127.0.0.1", 18762, 2},
                    {"127.0.0.1", 18763, 3}};
    config.cluster_id = "0123456789abcdef0123456789abcdef";
    config.voters = 3;
    config.tls = tls;
    config.read_token = read_token;
    config.write_token = write_token;
    yamora::ClusterClient db(config);
    auto mutation = db.prepare_put("examples", "one", "# exact\r\nn: 1\r\n",
                                   {"", true, ""});
    try {
        db.execute(mutation);
    } catch (const yamora::UncertainWriteError& error) {
        // Preserve this envelope for later recovery. An immediate recovery is
        // shown here only to demonstrate the API; it can also fail uncertainly.
        db.execute(error.mutation());
    }
}
```

The caller supplies 1–9 distinct private IPv4 HTTPS endpoints and distinct
expected node IDs in 1..voters; voters is 3, 5, 7 or 9. TLS is mandatory, with
IP verification and optional client credentials exactly as for `Client`.
`cluster_id` is the expected nonzero 32-lowercase-hex durable feed identity.
Credentials, TLS options, seeds and limits are copied on construction. The
configuration's timeout and byte limits have the standalone ranges; an
additional `attempt_timeout` (default 1000 ms, 1–30000 ms) caps each exchange.
The default absolute operation timeout is 5000 ms.

**Caller trust boundary:** native status has no cryptographic UUID attestation.
The caller must bind the configured CA/IP/seed policy to the intended cluster
and authorize sending credentials to every configured seed. Status plus the
feed checkpoint detects accidental misbinding; it does not authenticate an
otherwise trusted malicious server's claimed cluster identity. Administrative
read credentials are required for `/v1/cluster/status`. Remote leader hints,
URLs and redirects never add destinations or receive credentials.

Every operation revalidates status (`node`, self leader, odd voter count, uint64
term/positions, role and failure flag), then a fresh `/v1/changes` checkpoint
bound to `cluster_id`. A cached route only prioritizes that check. Discovery
reserves time for remaining seeds, binding and dispatch. At most 32 exchanges
(including discovery) occur; transport/attempt timeouts and 503 retry with
bounded exponential backoff (25–500 ms). Other HTTP errors and malformed
responses return immediately. Error bodies and redirect locations are omitted.

An optional final `RequestOptions` argument accepts a shared `Cancellation`
and a timeout that can shorten the configured operation deadline. One absolute
monotonic deadline spans input validation, all discovery/retries, backoff,
connect/TLS/I/O, JSON decoding, receipt validation and the final return guard.
Cancellation is cooperative with at most 10 ms socket/backoff polling, plus
bounded CPU/allocation work. It never closes a descriptor from another thread.
Each concurrent call owns its socket and TLS state until RAII destruction;
connect polling preserves one in-flight socket. Reusing a cancellation object
intentionally cancels all operations using that object.

Mutations snapshot method, path, body, preconditions, operation count and a
supplied or cryptographically generated nonzero 32-hex request ID **before any
I/O**. Retries use exactly those bytes. Caller-owned buffers must be valid and
must not be mutated concurrently during the initial snapshot; after discovery
begins, the operation no longer reads those buffers. `prepare_put`,
`prepare_patch`, `prepare_erase` and `prepare_call` (transactions/catalog only)
create an immutable `PreparedMutation` without I/O. `execute` reuses it; it
rejects an envelope bound to another configured cluster ID. Accessors expose
owned ID, method, path, body, unquoted ETag, create-only flag and operation count;
no credential is retained in the envelope. Use the same envelope for recovery,
including its original conditions, even if the database has advanced.

`UncertainWriteError` derives from `Error` and retains that envelope. Its
`kind()`/`status()` identify the failure; `uncertain()` is true. An ambiguous
dispatched result includes transport, framing, semantic receipt, cancellation,
deadline, allocation failure, redirect, unexpected status, 408 and 5xx. The
recovery exception and envelope are allocated before dispatch so an allocation
failure cannot silently lose a generated ID. Initial definitive 4xx rejection
(except 408) is certain. Earlier uncertainty survives later rejections,
including a subsequent `execute` of the same envelope. A valid replay receipt
establishes success even when its revision predates current database state.

PUT/PATCH receipts require exact collection/document, `stored`, body/header
revision agreement and matching strong header/body ETag. PUT create-only must
return 201, If-Match 200, unconditional 200 or 201; PATCH returns 200. Transaction
and catalog receipts require 200, `committed`, exact integer operation count and
matching revision (and matching snapshot ETag if present). DELETE requires
204/empty body. Receipt validation remains inside the recovery boundary.

JSON validation rejects duplicate decoded keys, invalid UTF-8/escapes,
malformed number tokens, nesting beyond 64 and more than 262144 values. Metadata
exchanges are capped at 4096 response bytes. Routing/receipt integer fields
require actual unsigned integer tokens within uint64, never booleans,
decimals or exponent notation. General result values remain raw JSON: numeric
bytes, escapes and authored YAML are never reserialized. General JSON results
receive syntax/object and optional body/header revision validation; full result
schemas and feed consumer ordering remain application responsibilities.
Identical repeated `Cache-Control: no-store` is the sole cluster header duplicate
exception for native diagnostics; conflicting policy, identity and framing
duplicates reject. Standalone duplicate handling is unchanged.

The CMake/CTest entry runs both `cpp_http_contract` and `cpp_cluster_contract`.
The latter requires the real immutable daemon and verifies hostile HTTPS,
mutable inputs, decoding/cancellation/deadline/allocation failures, route
rebinding, concurrency isolation, three-node mTLS election/failover, a dropped
COMMITTED reply with source checked before retry, overlapping native send and
complete framed-response intervals for same-ID and distinct-ID calls, quorum
loss and full restart with exact YAML and original receipts. Native responses
are read immediately; serialized exchanges and early completed replies held at
the gateway must fail the overlap guard. Test-only
link wrapping injects failures at the real JSON decoder boundary; it is absent
from the library. Missing daemon fails; fixtures own and clean their processes,
certificates and ephemeral ports and check that the daemon hash is unchanged.

## TLS binary source CRUD

Include `<yamora/binary.hpp>` and link the same `yamora::cpp` target. HTTP and
`ClusterClient` retain their public interfaces. The binary API serves GET,
HEAD, PUT and DELETE; use HTTP for all other operations.

```cpp
#include <yamora/binary.hpp>

void binary_example(const std::string& ca_pem, const std::string& client_pem,
                    const std::string& key_pem, const std::string& read_token,
                    const std::string& write_token) {
    yamora::BinaryConfig config;
    config.host = "127.0.0.1";
    config.port = 7401;
    config.server_identity = "127.0.0.1";
    config.ca_pem = ca_pem;
    config.client_certificate_pem = client_pem;
    config.client_private_key_pem = key_pem;
    yamora::BinaryClient db(config);
    yamora::BinaryOptions create;
    create.if_none_match = "*";
    auto stored = db.put("config", "item", "# retained\r\nn: 01\r\n",
                         write_token, create);
    auto document = db.get("config", "item", read_token);
    auto head = db.head("config", "item", read_token);
    yamora::BinaryOptions condition;
    condition.if_match = "\"" + document.etag + "\"";
    db.erase("config", "item", write_token, condition);
}
```

`BinaryConfig.host` must be canonical numeric loopback/RFC1918 IPv4; port is
1–65535. `server_identity` is an explicit certificate SAN IP or DNS identity,
frozen at construction; DNS identities never affect the numeric socket route.
TLS 1.3 and ALPN `yamora-binary/1` are mandatory. Explicit `ca_pem` accepts
1–32 certificate PEM blocks within 64 KiB. Optional client certificate chain
(up to eight certificates within 64 KiB) and matching unencrypted private key
(within 64 KiB) must be supplied together. Construction parses fresh private
OpenSSL objects. Later caller PEM/identity changes or file replacement cannot
change trust. There are no caller callbacks, SSL contexts, opaque key/trust
objects, system trust fallback, proxy settings, redirects, session resumption,
early data, DNS routing, connection reuse or automatic replay.

Bearer credentials are per-call printable ASCII (1–512 non-space bytes); empty
omits authentication. They are never retained in recovery envelopes or errors.
`BinaryOptions` preserves optional `if_match` and `if_none_match` verbatim,
including present empty strings, for native validation. Conditions are printable
ASCII up to 31 bytes; quoted ETags use the wire spelling shown above. Supplied
IDs must be nonzero 32-character lowercase hex. Mutations generate a random
nonzero ID if absent; reads may omit the ID. Response ID presence and bytes
must match exactly. Standalone IDs grant no deduplication guarantee.

`BinaryResponse` owns its body, metadata and unquoted ETag. HEAD has an empty
body and the source size in `representation_length`. Successful GET verifies
the exact raw source against the native ETag; PUT verifies its frozen input
against the TLV and strict five-field JSON stored receipt, including target,
revision and ETag. The native hash uses unsigned octets modulo 2^64, seed
1469598103934665603 and multiplier 1099511628211. Create-only PUT requires 201,
If-Match requires 200, and unconditional PUT permits 200/201. DELETE requires
204 with empty wire and representation bodies. JSON receipts reject invalid
UTF-8, duplicate fields, incorrect types, excessive depth/nodes and trailing
content. Advertised bounds are checked before body allocation: 16 MiB source,
4096-byte receipts/errors, 2048-byte metadata. Frames negotiate 4–64 KiB;
smaller frames do not shrink document capacity. END and exact byte counts are
required before a receipt can succeed.

Conditional GET and HEAD also accept 304 when `if_none_match` is exactly `*`
or the returned quoted ETag. Absent, empty, unquoted, weak or mismatched
conditions reject a 304. Its wire body is empty, with a complete END; the
advertised representation length is retained, including for HEAD. Revision,
ETag, target identity, Request-ID and media validation still apply. A 304 has
no source bytes to hash or JSON receipt to decode.

Copies of `BinaryClient` share admission: `max_concurrent_calls` is 1–4,
default 4. Waiters hold borrowed caller input without an extra source copy.
Input views, options and bearer bytes must remain alive and synchronized until
return; applications must not race mutations with the copying step. The driver
freezes input only after admission. Each operation owns its socket. `timeout`
is 1–30000 milliseconds, default 5000, and `RequestOptions.timeout` can shorten
it. One steady-clock deadline covers admission, copying, validation, connect,
TLS, all frames, decoding, hashing and the final return guard. Cooperative CPU
checks occur in bounded chunks. Existing `Cancellation` is one-way and polled
at most every five milliseconds during network/admission waits; there are no
callbacks or background cancellation workers.

`BinaryUncertainWriteError` preserves an immutable `BinaryEnvelope` after any
dispatched mutation without a trustworthy complete receipt: EOF, partial reply,
ERROR 1, GOAWAY, malformed metadata/receipt, cancellation, deadline, native 408
or 5xx. Its `kind()` and `status()` identify the redacted failure. Envelope
copies share const private data; `source()` and `options()` return defensive
copies. `execute(envelope, bearer, request)` is the only replay API and requires
an explicit application decision. Independently establish the exact stored
source and reconcile the outcome before repetition. An explicit standalone
create-only repetition may return 412. A complete validated native 4xx other
than 408 raises ordinary `Error` with `kind() == ErrorKind::http`. No error
message includes credentials, source or remote JSON text.

The CTest `cpp_binary_contract` requires `YAMORA_TEST_BINARY` to name an existing
native daemon and fails if absent. It never rebuilds that executable. It checks
mTLS/TLS failures, exact CRLF/Unicode/comments, binary/HTTP interoperability,
16 MiB over 4 KiB frames, legacy 256 KiB rejection, permissions/preconditions,
HEAD/delete, native concurrent calls, shared admission, caller ownership,
cancellation/deadlines, hostile framing/TLV/IDs/JSON/source hashes and real
committed lost/partial receipts. The recovery fixture observes every possible
binary retry and independently verifies exact source via HTTP before explicit
repetition. `cpp_binary_mutants` proves focused failures after dispatch for
GET/PUT source identity, Request-ID presence, create status, final deadline and
cancellation guard, admission before input copying, and conditional 304 status
and exact ETag correlation, then restores and passes
the same tests. Compiler/infrastructure/sanitizer/signal/timeout failures do not
count as mutation proof. Fixture sockets, threads and daemon processes are
closed and joined before their scratch is deleted, including failure paths.

CTest supplies `cpp_binary_mutants` with generated settings from its enclosing
CMake build. The runner preserves the actual compiler, global/configuration
C++ flags, build configuration, generator, linker flags and supported toolchain
settings; the caller's `CXX` environment cannot override them. It verifies the
child's actual CMake cache before building and uses its generated target path
for the selected configuration. Direct invocation requires `--settings` with
that generated JSON file; there is no fallback compiler or stripped-flags mode.

For GCC and Clang qualification, configure separate task-scratch CMake builds
with the chosen `CMAKE_CXX_COMPILER` and
`CMAKE_CXX_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer`.
Set fatal `ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:abort_on_error=1` and
`UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1`, then run CTest with the
immutable native daemon, disk-backed task `TMPDIR`, and `-j2` for builds.
The existing HTTP and replica-set CTests remain mandatory. These checks
qualify Linux C++17/system OpenSSL only; broad protocol/platform conformance
and binary cluster discovery remain OPEN.

The uncertainty exception and its message are constructed before dispatch.
After-dispatch handlers update only kind/status scalars and throw a nothrow
copy sharing the owned snapshot/message. The focused allocation regression
holds `operator new` failure from receipt decoding through SDK propagation and
caller catch, covering generated/supplied IDs and both allocation and preowned
protocol-error paths. Reintroducing message construction in those handlers
loses the envelope and fails the exact assertion after confirmed dispatch.
This verifies that trace on the qualified toolchains; exception ABI emergency
storage, OS exhaustion and process survival under arbitrary OOM remain outside
this guarantee. Envelope accessors make defensive copies after recovery from
the injected allocation failure.

## Additive binary operations and page feeds

`BinaryClient::operation(method, target, content_type, specification, bearer,
options, request)` returns `BinaryResponse`. `feed(target, consume, bearer,
options, request)` returns `BinaryFeedResult { response, last_after }`. The
callback takes a borrowed `std::string_view` valid only for that callback.
`BinaryOperationError` exposes `response()`, `last_after()` and optional owned
`envelope()` when `uncertain()` is true. Copying the exception shares its
preallocated state without allocating. `BinaryUnsupportedPeerError` is a
distinct pre-dispatch protocol error. Envelope accessors return copies.
The separately built V3 adapter target is `yamora_operations_conformance` in
`conformance/CMakeLists.txt`.

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

Before application-owned replica staging, call `source.require_replication_source()`.
It returns readiness or throws `yamora::Error` with kind
`schema_policy_replication_unsupported`, status 409 and `uncertain() == false`.
Advertised non-booleans are protocol errors; absent fields support older
policy-free servers. Recheck before publication or applying each source frame.
This advisory read never opens a destination stage; native outgoing and receiver
admission remains authoritative.
