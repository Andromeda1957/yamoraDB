# Python binary client

`yamora.binary_client` provides the separate public `BinaryClient`,
`BinaryConfig`, `BinaryEnvelope`, `BinaryResponse`, `BinaryError`,
`BinaryStatusError` and `BinaryUncertainWriteError` APIs. It uses only Python's
standard library and system OpenSSL. Existing HTTP and cluster clients retain
their APIs. Document GET, HEAD, PUT and DELETE keep exact schema-1 semantics.
The additive raw operation and page-feed APIs negotiate protocol 2 explicitly.
Each call owns one stream and one fresh connection.

```python illustrative
from pathlib import Path
from yamora.binary_client import BinaryClient, BinaryConfig

config = BinaryConfig(
    host="127.0.0.1",
    port=7401,
    server_name="yamora.internal",  # Must match a certificate SAN.
    ca_pem=Path("ca.pem").read_bytes(),
    client_cert_pem=Path("client.pem").read_bytes(),  # Optional pair for mTLS.
    client_key_pem=Path("client.key").read_bytes(),
    timeout=10,
    concurrency=2,
    max_frame=4096,
)
with BinaryClient(config) as client:
    stored = client.put(
        "config", "service", b"# exact\r\nvalue: 01\r\n", token=write_token, if_none_match="*"
    )
    source = client.get("config", "service", token=read_token).body
    metadata = client.head("config", "service", token=read_token)
    removed = client.delete("config", "service", token=write_token, if_match=stored.etag)
```

Every convenience method returns an immutable `BinaryResponse`. `body` is
exact bytes; `body_length` is wire DATA length and `representation_length` is
the corresponding native representation length. HEAD has an empty body and
retains the representation length. Successful DELETE is 204 with both lengths
zero. Responses expose revision, quoted ETag, collection/document identity,
optional request ID, Allow mask, Bearer challenge and retry-after delta.
Complete 400–499 native rejections raise `BinaryStatusError` with `.status`
and `.response`. No response automatically causes a retry or delay.

The general `request(method, collection, document, *, source=b"", token=None,
if_match=None, if_none_match=None, request_id=None, timeout=None, cancel=None)`
accepts only those four methods. Names use `[a-z0-9-]{1,128}`. Conditions,
including empty present values, pass unchanged to native validators. PUT takes
bytes, bytearray or a contiguous memoryview, up to 16 MiB, and always uses
`application/yaml`. It never parses, re-emits or normalizes YAML. The native
safe YAML parser and immutable storage profile decide whether to admit it.
Other methods accept no source body. Bearer tokens are per call, 1–512
non-space printable ASCII characters, and never become envelope fields.

## Raw operations and complete change pages

`operation(method, target, *, source=b"", content_type="", token=None,
if_match=None, if_none_match=None, request_id=None, timeout=None, cancel=None)`
accepts POST query/aggregate/search routes and `/v1/transactions`, document
PATCH, and finite GET `/v1/changes` with native `after` and `limit` parameters.
It accepts no other routes or methods. POST/PATCH accept raw JSON or YAML
specification bytes up to 16 MiB. Read-only POSTs use the caller's read token;
PATCH and transactions require the write credential/grants enforced by native
admission. No credential is selected or replayed implicitly.

```python illustrative
query = client.operation(
    "POST",
    "/v1/query/config",
    source=b'{"limit":1}',
    content_type="application/json",
    token=read_token,
)
raw_json = query.body
patched = client.operation(
    "PATCH",
    "/v1/collections/config/documents/service",
    source=b'{"$inc":{"value":1}}',
    content_type="application/json",
    token=write_token,
    if_match=metadata.etag,
)
```

The immutable `BinaryOperationResponse` owns raw response bytes. The SDK never
rounds, re-emits or normalizes numeric tokens. Applications may decode these
bytes with a decoder appropriate for their numeric domain. Query continuation
specifications pass unchanged, including their pinned revision and `after`.
Finite JSON responses are limited to 16 MiB. Acknowledgements/errors are limited
to 4 KiB. Strict UTF-8 JSON validation rejects duplicate decoded keys, non-finite
constants, unpaired surrogates, excessive nesting and excessive node counts.
Transaction counts must be integers; JSON requests also correlate the count
with the original operation list. PATCH receipts identify the resulting source
ETag, rather than the patch specification's hash.

`feed(target, on_page, *, token=None, if_match=None, if_none_match=None,
request_id=None, timeout=None, cancel=None)` accepts only GET
`/v1/changes/stream?after=...`, with native limit, duration and heartbeat options.
It synchronously passes one immutable, complete, validated raw NDJSON page,
including its LF, to the callback. Native terminal records also reach the
callback. No incomplete page is exposed. The driver retains one page assembly
and one frame, with a 16 MiB total wire limit, and never accumulates a whole feed.
Normal END returns metadata and `.last_after`; a native terminal record remains
observable in the callback and does not become a fabricated transport error.
The initial response revision describes admission; later pages can have newer
revisions.

An interrupted feed raises `BinaryOperationError` with `.response` when validated
metadata exists and `.last_after` for the last accepted complete page. A callback
that returns normally commits its delivered cursor; returning `False` commits
that cursor and stops with `kind="cancelled"`. A callback exception leaves the
prior cursor and raises `kind="local"`. Deadline/cancellation after a completed
callback retains the newly delivered cursor. Callbacks must bound their own
execution: Python cannot preempt user code. Reentering the same client directly
from its callback fails immediately; `close()` inside a callback marks the client
closed and returns so the owning feed can release its own socket.

Protocol 2 requires response mode field 13 and exact schema/request-ID correlation.
A protocol-1-only peer is rejected before REQUEST, with no HTTP fallback. All
operation calls have an owned request ID. Dispatched PATCH/transaction failures,
including 408 or 5xx, missing END, wrong IDs, deadline and cancellation, raise
`BinaryUncertainWriteError` with the exact `BinaryOperationEnvelope`. Its raw
specification bytes, method, target, content type and conditions remain available
for explicit recovery; credentials are absent. Read-only POSTs never acquire
mutation uncertainty merely because their method is POST.

## Trust and endpoint ownership

The host must be numeric IPv4 in RFC 1918 space or 127/8. An explicit
`server_name` selects the certificate identity without DNS discovery. A DNS
name sends SNI and verifies the matching DNS SAN. An IP literal verifies its
IP SAN without sending SNI; IP literals remain supported. A mismatched DNS
name or IP SAN fails verification before REQUEST. Every
call requires certificate verification, TLS 1.3 and ALPN exactly
`yamora-binary/1`. There is no plaintext, hostname-verification bypass, caller
SSLContext, trust callback, HTTP proxy or redirect option. Proxy environment
variables are ignored; connections go directly to the configured numeric
endpoint. A mismatched HTTP listener fails ALPN negotiation before REQUEST.

Configuration copies bounded PEM CA bytes, with an independent 1 MiB limit for
each CA, client certificate and client key input. Configuration validates the
material eagerly and keeps bytes, never an opaque mutable SSLContext. Each
call freshly parses those owned bytes into its own context, without system
roots or network chain fetching. Replacing/mutating original input buffers
does not change admitted configuration. Optional client identity requires
both certificate and unencrypted key; there is no interactive password prompt.
TLS client authentication still requires the applicable per-request bearer.

The implementation requires Python 3.10+ and TLS 1.3/ALPN support. This slice
was qualified on Linux with Python 3.12.13 and system OpenSSL 3.5.7.
For mTLS, CPython's filename-only certificate loader reads short-lived anonymous
Linux descriptors via `/proc/self/fd`; descriptors close immediately after
the fresh context parses the owned material. No persistent key files are
created by the driver. Windows/macOS qualification and alternate identity
loading remain open.

## Admission, deadlines and connection lifetime

Configuration accepts concurrency 1–4 (default 1), frame payloads 4–64 KiB
(default 64 KiB), and finite timeouts greater than zero through 30 seconds
(default 10 seconds). A call may override its timeout and pass a
`threading.Event` as `cancel`. Its single monotonic deadline starts before
admission and covers connect, TLS, HELLO, every upload/response fragment,
metadata, receipt validation, source hashing and complete END. The transmitted
native timeout is the remaining budget, capped at 30,000 ms. Progress does not
renew it.

Waiting callers retain their own source reference. They do not own a copied
16 MiB envelope, SSLContext or socket while waiting. After admission, the
driver freezes exact source bytes, target, conditions and request ID before
I/O. Mutating a buffer before admission can change what is admitted; do not
concurrently modify a buffer during its admission copy. After that copy,
caller mutations cannot change the operation or an uncertainty envelope.

Each caller owns and closes its socket in `finally`. Nonblocking I/O checks
cancellation at most every 50 ms while waiting; bounded local copies and
OpenSSL parsing are checked before and after. Source hashing checks at each
64 KiB chunk. Cancellation closes the connection without proving rollback.
There are no client background threads, connection pool, retry loop or detached
network jobs. `close(timeout=1.0)` rejects/wakes waiters, cancels active calls
and waits up to its bounded timeout for the owning callers to release their
sockets. An expired close raises `BinaryError(kind="timeout")` while each
remaining caller retains its own connection until its cleanup executes.

Client-owned per-call application memory is bounded by admitted input/output
source size, one negotiated frame, bounded metadata/receipt buffers, and
temporary immutable conversions. GET can temporarily retain both an assembly
buffer and the immutable result; PUT owns one frozen source copy. Caller
buffers, Python/OpenSSL overhead and OS socket buffers are additional. The
driver does not preallocate advertised response sizes or copy sources for
waiting callers.

## Mutation uncertainty and explicit recovery

PUT and DELETE always have a nonzero lowercase 32-hex request ID, generated
before I/O unless the caller supplies one. Reads may supply one too. Every
response ID must match the request exactly, including presence. A mutation
becomes conservatively dispatched immediately before the first REQUEST send:
even that send may partially succeed.

After dispatch, EOF, timeout, cancellation, client close, local exceptions, malformed/partial
metadata or receipt, wrong ID, unexpected method/status, incorrect source
identity, GOAWAY or session ERROR raises `BinaryUncertainWriteError`. Complete
5xx mutation replies also remain conservatively uncertain. The error has
`.request_id` and `.envelope`, an immutable owned snapshot of method, target,
source bytes, conditions, content type and that original ID. Envelope/error
representations redact source and credentials; source remains explicitly
accessible for application recovery. No bearer token is retained there.

Generic closing ERROR code 1 proves no operation outcome. A complete END is
necessary for success, followed by length, source FNV identity, ETag, target
and mutation JSON receipt/revision correlation. Mutation receipt bytes must
strictly decode as UTF-8 before JSON parsing; matching UTF-16/32 receipts are
protocol failures with the original request ID and recovery envelope. These
checks establish the received contract, not an independent quorum or durability
proof.

Do not blindly replay an uncertain mutation. Inspect authoritative state and
the deployment's recovery contract explicitly. Standalone request IDs provide
correlation, **not deduplication**. Replica-set servers have their documented
durable receipt semantics, but automatic cluster discovery, failover/recovery
and broader SDK conformance remain **OPEN** in this client. This slice makes
no topology or full protocol-parity claim.

## Focused acceptance

The codecs in `../binary_wire.py` and `../binary_reply.py` are independent of
the server/reference test codecs. The suites include literal network/TLV
goldens, independent hostile TLS peers, bounded allocation/acknowledgement
probes, deadline/cancellation/admission and caller-thread lifetime checks.

Inside an active managed task environment, explicitly set `YAMORA_TEST_BINARY`
to the supplied immutable native executable, then run from the repository root:

```sh
python3 -m unittest yamora.tests.test_binary_client \
  yamora.tests.test_binary_client_native yamora.tests.test_binary_client_mutants \
  yamora.tests.test_binary_operations -v
```

The native suite fails if configuration/executable is missing, checks its
SHA-256 before/after without overwriting it, and forces fatal ASan/UBSan
settings on every daemon invocation. It initializes disposable native stores
and verifies mTLS plus HTTP interoperability, read/write/scoped permissions,
conditions, HEAD/204, 16 MiB over 4 KiB frames and the legacy 256 KiB profile.
The partial-receipt oracle forwards one actual native mutation, independently
observes the known committed source over HTTP before truncating its receipt,
verifies the original uncertainty envelope and absence of replay, then makes
explicit recovery reads. Reusing the standalone create-only ID returns 412.
No fault variant is needed for that oracle. Existing HTTP fixtures using
`YAMLDB_BUILD_DIR` are not used to choose this executable.

Three exact behavioral mutants remove request-ID correlation, widen the
acknowledgement bound or accept EOF as END. Each must produce one named
assertion failure with no errors, then pass restored. The peer must first
confirm the complete expected request, and the client must produce the exact
expected mutant response or acknowledgement status/body before that named
failure can qualify. Unexpected exceptions propagate as test errors. Restored
guards must report protocol uncertainty after confirmed dispatch; a transport
failure cannot stand in for a restored green. Real TLS identity failures,
pre-dispatch transport faults and unexpected statuses/response metadata are
negative controls. The red oracle also rejects compiler, infrastructure,
signal and sanitizer diagnostics. UTF-16/32 receipt acceptance and the old
oracle's acceptance of TLS/transport failures were observed red against
`49f95d215` before their fixes. DNS-name and IP-SAN positive/negative peers
verify SNI presence and absence directly. The connect
readiness and dispatched local-failure envelope regressions additionally have
observed ordinary reds before their fixes. Client threading qualification
exercises actual caller cancellation,
admission and bounded joins; no new native threaded module is introduced.
Shared test/build discovery registration, combined qualification, independent
review and feature-branch integration belong to the parent.
