# Yamora Ruby driver foundation

## Local gem and runnable CRUD example

The local distribution is `yamora` 0.1.0. This is foundation packaging,
without a stable-version promise or registry publication. It contains the full
HTTP, replica-set and binary client source, this README, the existing MIT
license and the example; tests and conformance adapters are excluded. The gem
declares only the libraries the driver already requires. Ruby >=4.0 and JSON
>=2.18.0 are requirements; the qualified combination remains Linux x86_64,
Ruby 4.0.9, JSON 2.18.0 and OpenSSL 3.5.5. Other combinations are unqualified.

RubyGems build/install also needs Ruby's standard zlib extension. A minimal
build image must provide zlib development headers when compiling Ruby; this is
a packaging-tool prerequisite, rather than an added SDK library dependency.

From this driver directory, with an existing owned disk-backed `TMPDIR`:

```sh
gem build yamora.gemspec --output "$TMPDIR/yamora-0.1.0.gem"
gem install --local "$TMPDIR/yamora-0.1.0.gem" --no-document \
  --install-dir "$TMPDIR/consumer-gems"
export GEM_HOME="$TMPDIR/consumer-gems"
export GEM_PATH="$GEM_HOME:$(ruby -rrubygems -e 'puts Gem.default_dir')"
ruby -ryamora -e 'puts Gem.loaded_specs.fetch("yamora").version'
```

Configure an existing native HTTPS listener and a disposable document. Set
`YAMORA_PORT`, `YAMORA_CA_FILE`, `YAMORA_READ_TOKEN` and
`YAMORA_WRITE_TOKEN` in the environment using your secret store. The host
defaults to 127.0.0.1; `YAMORA_HOST` can name another canonical private IPv4.
For mTLS, also set both `YAMORA_CLIENT_CERT_FILE` and
`YAMORA_CLIENT_KEY_FILE` to PEM files. Run:

```sh
ruby "$GEM_HOME/gems/yamora-0.1.0/examples/crud.rb"
```

The example creates `package-demo/ruby`, checks byte-exact reads of
commented UTF-8/CRLF YAML before and after a conditional update, then deletes
conditionally and verifies 404. It prints `CRUD_OK`. Override
`YAMORA_COLLECTION` and `YAMORA_DOCUMENT` to choose a fresh target.
An existing target fails the create-only precondition. It never retries an
uncertain write automatically.

The normal [tests/run.rb](tests/run.rb) discovery includes
[tests/test_package.rb](tests/test_package.rb).
For this package-only check, with `YAMORA_TEST_BINARY` pointing to an existing
native daemon and repository-owned disk-backed scratch, run from this directory:

```sh
ruby tests/run.rb --name /test_installed_gem_and_native_mtls_example/
```

This builds the gem in scratch, installs it locally, checks that all public
client families load from the installed artifact, and executes its packaged
example against a fresh native mTLS daemon with synthetic credentials.

Dependency-free standalone HTTP/1.1 client using Ruby's Net::HTTP, JSON and
OpenSSL libraries. It preserves authored YAML as bytes and never parses or
serializes YAML locally. Native storage is unchanged. This is a bounded stage
of the parent-maintained enterprise roadmap, not completion of the Ruby driver
conformance milestone.

Verified on Linux with Ruby 4.0.9, bundled JSON 2.18.0, and OpenSSL 3.5.5 against
the native ASAN daemon. The driver requires TLS 1.3 support for HTTPS and JSON
with `allow_duplicate_key: false`. Older JSON implementations that silently
ignore this option are rejected at load time. Other Ruby/runtime/platform
combinations remain unqualified; no packages need installing on the tested
runtime. Tests use minitest when provided by the Ruby distribution.

## TLS binary document CRUD

`Yamora::BinaryClient` is a separate, additive client for GET, HEAD, PUT and
DELETE against an explicitly enabled native binary listener. HTTP and cluster
clients retain their existing APIs. Other calls continue to use HTTP. Binary
cluster discovery, broad transport conformance and other platforms remain open.

```ruby
config = Yamora::BinaryConfig.new(
  host: '127.0.0.1', port: 7401, server_name: 'database.internal',
  ca_pem: trusted_ca_pem,
  certificate_pem: client_certificate_chain_pem, # omit both for server TLS
  private_key_pem: client_private_key_pem,
  timeout: 10, concurrency: 4, max_frame: 4096
)
binary = Yamora::BinaryClient.new(config)
created = binary.put('people', 'ada', source,
                     token: write_credential, if_none_match: '*')
document = binary.get('people', 'ada', token: read_credential)
raise 'source changed' unless document.body.b == source.b
head = binary.head('people', 'ada', token: read_credential)
binary.delete('people', 'ada', token: write_credential, if_match: head.etag)
binary.close
```

Config owns bounded PEM **contents**, endpoint strings and server identity.
It accepts no filenames, opaque trust stores, SSLContext, verification switches,
custom callbacks, proxy, redirect, DNS routing or TLS downgrade options. Explicit
CA anchors replace system trust. Each call creates a fresh verified TLS 1.3
connection with mandatory `yamora-binary/1` ALPN. The destination must be a
canonical loopback/RFC1918 IPv4 address. `server_name` is an explicit exact DNS
SAN or IPv4 SAN identity used for SNI/verification, never routing. Common names
and wildcard SAN substitution are unsupported. Optional mTLS identity is owned
PEM bytes with an unencrypted key; loading never prompts for passwords.

Each method accepts `token:`, `if_match:`, `if_none_match:`, `request_id:`,
`timeout:` (seconds, at most 30), and `cancel:`. Conditions are opaque printable
wire values, including quotes and empty present values, passed to native
validation. Unlike HTTP's unquoted ETag convenience, binary `etag` is the
**quoted** wire value and can be passed directly as `if_match:`. Bearers are
supplied per call and never retained in config or recovery envelopes. Reads
omit the request ID by default; mutations generate a nonzero 16-byte ID unless
a 32-character lowercase hex ID is supplied. Response ID presence and value
must match exactly, including for native errors.

`BinaryResponse` exposes frozen `body` bytes plus `status`, `content_type`,
`body_length`, `representation_length`, `revision`, `etag`, `collection`,
`document`, `request_id`, `allow`, `authenticate` and `retry_after_seconds`.
HEAD has no DATA and retains its representation length. DELETE returns 204
with both lengths zero. Source bytes preserve UTF-8, CRLF, Unicode and comments;
no YAML parsing or conversion occurs in the SDK. Successful GET and PUT verify
the native source hash with Yamora's seed `1469598103934665603`. PUT also checks
conditional status and exact JSON receipt identity/revision/ETag agreement.
Frames/TLVs, lengths, UTF-8, JSON duplicates, nesting, node counts and numbers
are bounded and checked. A complete validated END is required for success.
Documents can reach 16 MiB over negotiated 4–64 KiB frames; receipts/errors are
bounded to 4096 bytes. The native store's immutable profile can impose a lower
limit, including 256 KiB for legacy stores.

The synchronous client supports concurrent threads and ordinary fibers without
an installed Fiber scheduler. Scheduler-managed calls are rejected explicitly.
At most 1–4 calls are admitted per client; waiters retain caller references
without copying source or allocating connections. Input is captured only after
admission. One monotonic deadline includes admission, copying/validation,
TCP/TLS, every fragment, decode, hashing and the final success check. Hashing
checks the budget every 4096 bytes. `BinaryCancellation.new`, followed by
`cancel` from another thread, sets a polled signal; only the call owner closes
its socket. There are no cancellation callbacks, background timers or thread
exception injection. Cancellation/closed/deadline checks occur between CPU
chunks and within 20 ms I/O/admission waits; OS scheduling and bounded native
OpenSSL/string operations can add latency. `close(timeout: 1)` cancels pending
calls and waits for admitted owners to release their sockets. A close timeout
reports outstanding owners, which can be joined by a later close.

Complete valid 4xx rejections other than 408 raise `BinaryStatusError` with
`status` and `response`. `BinaryError` carries a redacted `kind` for local,
transport, TLS, framing, deadline and cancellation failures. Once REQUEST may
have left the socket, ambiguous mutation outcomes raise
`BinaryUncertainWriteError` with the original immutable, credential-free
`envelope` and `request_id`. This includes EOF, partial receipts, session ERROR
(including code 1), GOAWAY, cancellation/deadline, malformed semantic receipts,
408 and 5xx. No binary call automatically reconnects or retries.

Recovery belongs to the application: independently establish the exact stored
source after a lost/partial receipt **before** explicitly repeating the original
operation using `binary.replay(error.envelope, token: fresh_credential)`.
The envelope freezes method, target, conditions, source, content type and ID;
its inspect output redacts source. Keep sensitive source under application
custody. A standalone store gains **no deduplication guarantee** from an ID;
explicit repetition can return 412 or have another effect. The SDK makes no
cluster routing, quorum or replay-safety inference.

Binary qualification uses the required actual native ASan/UBSan daemon and
correctly framed hostile TLS peers. `tests/run.rb` discovers every
`test_binary*.rb` alongside the full existing HTTP/cluster suites. Missing
native executables fail. Native fixture processes and TLS threads are stopped
and joined before scratch deletion, including on failures. The mutation oracle
requires exact behavioral assertion failures with confirmed REQUEST/END
dispatch, rejects infrastructure/sanitizer/signal/timeout failures as proof,
and verifies restored behavior. Run the private SDK runner from the repository
root with your existing task-owned scratch root and immutable daemon:

```sh
PYTHONDONTWRITEBYTECODE=1 TMPDIR="$TASK_SCRATCH" \
  python3 tools/ci/yamora_driver_tests.py --suite ruby \
  --scratch-root "$TASK_SCRATCH" --binary "$YAMORA_TEST_BINARY" --jobs 2
```

## Use

From the repository root:

```ruby
$LOAD_PATH.unshift('yamora/drivers/ruby/lib')
require 'yamora'

# Load credentials using the application's existing secret custody mechanism.
client = Yamora::Client.new(
  host: '127.0.0.1', port: 8765,
  read_token: read_credential, write_token: write_credential,
  timeout: 5
)

source = "# authored source\r\nname: 'Ada'  # retain this comment\r\nactive: true\r\n"
receipt = client.put('people', 'ada', source, create_only: true)
document = client.get('people', 'ada')
raise 'source changed' unless document.source.b == source.b
client.patch('people', 'ada', { '$set' => { 'active' => false } }, etag: document.etag)

page = client.query('people', {
  'filter' => { 'active' => true },
  'sort' => { 'name' => 1 }, 'limit' => 20
})
```

Strings are interpreted as UTF-8 bytes without transcoding. Raw PUT rejects
empty, invalid UTF-8 and oversized source; GET returns exact UTF-8 source,
unquoted content ETag, and database revision in a `Yamora::Document`.
ETags/revisions supplied by callers are 16 lowercase hex characters without
quotes. The driver quotes HTTP conditions. PATCH sends JSON operators; the
server owns source-preserving edits and semantic validation.

Verified HTTPS and optional client identity use PEM **contents**:

```ruby
tls = Yamora::TLS.new(
  ca_pem: trusted_ca_pem,
  certificate_pem: client_certificate_chain_pem,
  private_key_pem: client_private_key_pem
)
secure = Yamora::Client.new(
  host: '127.0.0.1', port: 8765, tls: tls,
  read_token: read_credential, write_token: write_credential
)
```

Omit both client identity arguments for server-authenticated TLS. Omit
`ca_pem` to use system trust. A supplied CA bundle replaces system trust for
that client. TLS always requires verified certificates and an exact four-byte
IPv4 SAN match; DNS SANs and common names never substitute for that IP SAN.
TLS 1.3 is both the minimum and maximum. Expired/untrusted/wrong-IP
certificates and missing/untrusted mTLS identity fail. Keys must be unencrypted
PEM; encrypted keys fail immediately without a password prompt. No insecure
verification mode, custom TLS callbacks or server-name override is offered.

## Implemented API

All structured arguments use string-keyed Hashes, Arrays, UTF-8 Strings, finite
Floats, Integers, booleans and nil. Compound sort priority follows Hash
insertion order. JSON numbers retain Ruby integer precision, including signed
64-bit values; this client permits integers from -2^63 through 2^64-1 and the
server enforces each field's range. JSON input has depth, node and byte budgets;
custom serialization hooks are not called. Duplicate response keys, malformed
UTF-8/JSON, invalid revisions, malformed receipts and unsafe cursors fail closed.
NEL (U+0085), line separator (U+2028), and paragraph separator (U+2029) are
escaped in JSON requests so the daemon retains their values rather than
interpreting them as YAML line breaks. This also preserves raw YAML strings
inside transaction envelopes.

JSON response numbers decode to Ruby Integer or Float. Any parsed Float that
overflows to positive or negative infinity, including deeply nested document
values or metadata, raises `ProtocolError`. The native engine can retain finite
numbers outside Ruby Float's range; use raw `get` for their exact YAML source.
The driver never silently returns Infinity for those numbers.

Structured methods return string-keyed Hashes. `revision` is validated against
`X-YamlDB-Revision`; metadata/list/catalog responses receive that header revision
when their body omits it. An online job's `revision` is its own publication
revision (empty before success), which may precede the current response head.

| Method | Contract |
| --- | --- |
| `health`, `ready`, `stats` | JSON metadata; health is the unauthenticated daemon route |
| `metrics` | UTF-8 Prometheus text |
| `collections(revision: nil)` | Sorted IDs and validated header revision |
| `document_page(collection, limit: 1000, after: nil, revision: nil)` | Bounded sorted ID page, `next_after`, revision; continuing requires the initial revision |
| `each_document(collection, revision: nil, limit: 1000)` | Yield IDs or return Enumerator; pin revision across pages; stop on callback exception |
| `get(collection, document, revision: nil)` | `Document(source:, etag:, revision:)` with exact source |
| `put(collection, document, source, etag: nil, create_only: false)` | Raw YAML create/replace; `If-Match` or `If-None-Match: *`, never both; stored receipt |
| `patch(collection, document, operators, etag: nil)` | JSON field operators and optional content ETag; stored receipt |
| `delete(collection, document, etag: nil)` | Conditional delete; return commit revision |
| `query(collection, spec = {})` | Filter, ordered sort, projection, limit, revision/after, count_only, explain, include_count |
| `count(collection, filter = {}, revision: nil)` | Return complete integer match count |
| `aggregate(collection, pipeline, revision: nil)` | 1–32 stages, reduced objects and examination count |
| `search(collection, index:, text:, mode: 'all', filter: {}, limit: 100, after: nil, revision: nil)` | Text-index matches in ID order, scores, statistics and pinned continuation |
| `indexes` | Read complete index catalog and revision |
| `set_indexes(definitions, revision: nil)` | Replace **entire** scalar/unique/text catalog; optional database revision condition |
| `start_index_build(definitions, revision: nil)` | Submit complete replacement catalog once; return online job |
| `index_build(id = nil)` | Read job by 32-hex ID, or current/idle job |
| `cancel_index_build(id)` | Explicit remote cancellation request; return job; no automatic polling |
| `transaction(operations, revision: nil)` | 1–128 unique targets, exactly one raw `put`, operator `patch`, or `delete: true`; per-operation ETag/create-only and optional database revision |
| `changes(after: nil, limit: 100)` | One complete validated feed page; absent token obtains checkpoint only; no implicit consumer progress |
| `replication_status` | Read replica's durable `after` token and revision; no replica mutation |

Transactions retain raw YAML strings inside the JSON envelope. Index definitions
use `collection`, `name`, `fields`, optional `unique`, and optional `type: text`.
`set_indexes`/`start_index_build` replace the whole catalog; use its last-read
revision to avoid overwriting concurrent edits. There is no catalog-edit retry.

To continue a query/search, repeat its filter, sort and other options, passing
`next_after` and the first page's `revision`. HTTP 412 or a detected changed
revision invalidates the traversal. Previously yielded document IDs or consumer
effects cannot be undone by this client. Feed pages expose complete frames;
persist each frame's token atomically with the consumer's effects. A
`resnapshot_required` frame requires an explicit new consistent snapshot.

## Transport and errors

- Only canonical numeric IPv4 loopback and RFC1918 endpoints with ports
  1–65535 are accepted. URLs, DNS names, IPv6, shorthand/octal IPv4, public,
  wildcard and link-local addresses are rejected before networking. Identifiers
  follow `[a-z0-9-]{1,128}`; paths and conditions are constructed internally.
- Optional tokens are 32–512 printable ASCII bytes (0x21–0x7e). Read operations,
  including query/aggregate/search POSTs, use the read credential. Mutations use
  only the write credential. The client never loads token files or logs tokens.
- `Net::HTTP.new` receives an explicit nil proxy; no environment proxy discovery
  occurs. All redirects are returned as errors without following their Location.
- Every call owns a fresh connection with `Connection: close`, retries set to
  zero, and compression disabled. The finite-response APIs require a single
  Content-Length and reject transfer encoding, upgrades, content encoding,
  folded/duplicate headers (except identical native `Cache-Control: no-store`
  repetitions), truncated bodies and oversize output.
- Response headers are bounded before line allocation to 16 KiB and 64 fields,
  including informational responses. This uses a private Net::HTTP subclass
  and connection-local BufferedIO extension; no global Net classes change.
  That seam must be requalified when upgrading the Ruby HTTP implementation.
- Defaults: 16 MiB raw documents; 2 MiB structured requests, with 64 MiB for
  PATCH/transactions; 64 MiB responses. `max_response_bytes:` can lower the
  response cap. Earlier daemon profiles impose their own smaller limits.
- `timeout:` defaults to five seconds, must be positive and at most 30 seconds,
  and bounds the **whole** network request, including handshake and slow-drip
  headers/body, in addition to open/read/write socket timeouts. Request
  validation/JSON encoding occurs before that network deadline. Connections
  close on all exits, including a stalled TLS handshake before the HTTP socket
  is assigned; cleanup does not depend on garbage collection. Immutable
  configuration can be shared across threads.

Invalid local arguments raise `ArgumentError`. Remote statuses raise
`Yamora::HTTPError` with integer `status` (including 401/403/404/409/410/412).
Transport errors raise `TransportError`; malformed responses raise
`ProtocolError`, `LimitError` or `RevisionError`. These inherit `Yamora::Error`.
Remote response bodies and underlying exception causes are not exposed in
errors. Inspecting client/TLS objects redacts credentials and key material.

`error.uncertain?` is conservative for mutations: true for transport/receipt
failures, redirects, HTTP 408 and server errors. A failed acknowledgement does
not prove rollback; the native daemon can publish before an I/O failure. Read
served state and reconcile preconditions/recovery before submitting another
mutation. **Standalone calls do not retry mutations automatically.** Definitive
4xx errors other than 408 retain their status and are not marked uncertain.

## Tests

From the repository root, set `YAMORA_TEST_BINARY` to an absolute path to an
already-built native daemon. The suite executes it read-only, initializes only
disposable roots, and never builds or edits the daemon:

```bash
ruby yamora/drivers/ruby/tests/run.rb
```

The caller must export `TMPDIR` as an existing, owned, disk-backed descendant
of `/var/tmp/andromeda-work`. The base itself, paths resolving outside it,
missing directories, files and memory-backed roots are rejected. Each test
creates a unique private child below that caller root and removes the child
on success or failure, preserving the root and any existing files. No task slug
or fallback temporary directory is embedded in the fixture. Shared gates
provide both `TMPDIR` and `YAMORA_TEST_BINARY`.

The environment variables are inherited by the command. The full runner requires
an executable daemon and fails immediately if it is absent. Individual standalone
files can still be run without a daemon; their native cases explicitly skip. The suite owns and stops its child daemons, uses generated test
certificates and ephemeral loopback ports, and cleans each unique allocation on
success/failure. It never uses the owner's server or data. Tests cover raw CRLF
and Unicode YAML, source-preserving patches, ETags and atomic conditional
failures, integer precision, pagination, query/search/aggregate/index/transaction
and feed contracts, mTLS and real TLS trust/hostname/expiry/version failures,
proxy/retry defaults, redirects, truncation, bounds and slow-drip deadlines.
Regression cases include every Unicode separator through native query, patch
and transaction calls, nested numeric overflow from real native values, and
stalled TLS deadlines with descriptor counts and peer closure checked while
garbage collection is disabled.

## Replica sets

`ClusterClient` inherits the finite standalone API. Configure trusted numeric
private HTTPS seeds, their expected node IDs, the nonzero 32-hex cluster ID and
an odd voter count (3, 5, 7 or 9):

```ruby
cluster = Yamora::ClusterClient.new(
  seeds: [{ host: '10.20.0.11', port: 8765, node: 1 },
          { host: '10.20.0.12', port: 8765, node: 2 },
          { host: '10.20.0.13', port: 8765, node: 3 }],
  cluster_id: '01020304000000000000000000000000', voters: 3,
  tls: tls, read_token: read_token, write_token: write_token,
  timeout: 10, attempt_timeout: 1
)
request_id = SecureRandom.hex(16) # Persist with the exact request before sending.
receipt = cluster.put('manifests', 'a', "# authored\r\ncount: 0\r\n",
                      create_only: true, request_id: request_id)
```

The expected node and voter count are checked against authenticated status.
The change-feed checkpoint binds the candidate to the configured cluster ID.
This profile **requires an administrative read credential** for status and the
checkpoint; scoped-principal discovery is not implemented. Neither follower
hints nor redirect URLs supply destinations. Configured gateways must preserve
these bindings. Credentials go only to configured seeds after verified TLS 1.3;
HTTP mTLS is available through the same immutable `TLS` object.

`put`, `patch`, `delete`, `transaction` and `set_indexes` accept `request_id:`.
Omitting it generates a nonzero 32-character lowercase hex identity. All request
bytes, identifiers and preconditions are copied before discovery; retries keep
those bytes and the same ID. Reusing an ID with different bytes is a conflict.
Online index jobs remain unsupported (405 before dispatch). No replica restore,
follow or continuous-feed operation is added by this profile.

Public calls, including response decoding and semantic validation, discovery,
attempts and backoff share one monotonic deadline (default five
seconds, maximum 30), with at most 32 discovery/dispatch exchanges. Each attempt
has its own cap (`attempt_timeout:`, default one second), and stalled seeds get
only a share of remaining time. A stalled cached leader leaves time to discover
another seed. A cached route only prioritizes discovery: each operation rechecks
node, voter and cluster binding before dispatch. Routing state uses a mutex and
route generations; concurrent or
late failures cannot erase a newer route. Each operation owns its connections.

`UncertainWriteError < Yamora::Error` carries `request_id`, `status`, `reason`
(the sanitized exception class name) and `uncertain? == true`. It has no cause,
remote body, TLS key or credential details. This includes malformed/truncated
receipts, wrong success status, operation count, document identity, revision or
ETag, HTTP 408/server errors/redirects, and cancellation/deadline after dispatch.
Definitive 4xx rejection is certain unless an earlier attempt was uncertain.
Before any dispatch, unavailability/cancellation is certain. Dispatched HTTP
rejections also expose their request ID for bookkeeping.

Recover by retrying the **same primitive operation, exact arguments, conditions
and `error.request_id`**. Retain supplied IDs as well. Retrying an index catalog
requires the original complete catalog and revision, not a newly fetched catalog.
The driver never changes an ID to make a failed write succeed. Catalog and raw
YAML receipts are validated inside the identity recovery boundary.

For a shorter deadline or cooperative cancellation, use a request scope:

```ruby
cancellation = Yamora::Cancellation.new
patch_id = SecureRandom.hex(16) # A new logical operation needs a new ID.
cluster.with_request(timeout: 0.5, cancellation: cancellation) do |client|
  client.patch('manifests', 'a', { '$inc' => { 'count' => 1 } }, request_id: patch_id)
end
# Another thread can call cancellation.cancel! while the scope runs.
```

Nested calls share the outer deadline and attempt budget. Every public result
passes a final deadline/cancellation check after decoding and semantic validation.
Mutation recovery identity stays available through that final check, including
when a valid receipt arrives before decoding exceeds the operation lifetime.

A cancellation token is permanent once cancelled and can cancel multiple scopes.
It closes only the operation's own connection, including an unpublished TLS
handshake socket, and never injects an exception into a caller's thread. Manual
fibers sharing a thread therefore retain separate cancellation contexts. Socket
registrations are removed on every exit; cancellation owns no background thread.
Established I/O is interrupted by closing the TLS connection with close_notify;
TCP connection setup is bounded by its attempt timeout. Cancellation during
CPU decoding/validation is cooperative: it rejects the result at the final
public return check. Use this token instead of killing threads when a recovery
ID is needed. Scheduler-specific runtime qualification remains open.

`each_document` remains a sequence of individually guarded page calls unless
enclosed in one request scope; already yielded effects cannot be undone.

The HTTPS fixtures exercise trust, framing, exact-request snapshots, semantic
receipts, definitive/uncertain outcomes, cancellation and bounded fair failover.
Native acceptance starts three private mTLS daemons, loses a committed reply and
leader, holds six dispatched same-ID mutations and their native replies at
bounded gateway barriers, checks deduplication, quorum loss, restart and original
receipts/source preservation. A separate native gateway corrupts committed raw,
transaction and catalog receipts and checks same-ID recovery. The daemon is
executed read-only; all data, keys, processes and ports are disposable.

## Remaining stages

The enterprise binary/streaming transport and shared all-driver conformance
suite are pending. This SDK does not yet implement continuous NDJSON feeds,
replica bootstrap/follow orchestration, consistent export/restore, package
publication/version guarantees, or macOS/Windows qualification. Administrative
cluster diagnostics are used internally for discovery. Cluster discovery needs
an administrative read token. Full binary/shared cross-driver conformance remains
open; this cluster implementation does not complete that roadmap milestone.

## Replication source preflight

Before application-owned replica staging, call `source.require_replication_source`.
It returns readiness or raises `Yamora::SchemaPolicyReplicationError` with
status 409 and `uncertain? == false`. Advertised non-booleans raise
`Yamora::ProtocolError`; absent fields support older policy-free servers. Recheck
before publication or applying each source frame. This advisory read never
opens a destination stage; native outgoing and receiver admission remains
authoritative.

### Raw binary operations and page feeds

`BinaryClient#operation(method, target, content_type, source, **options)` adds
negotiated schema 2 for query/aggregate/search POST, transaction POST, document
PATCH and paged changes GET. Its immutable response contains the exact owned
raw JSON body; numeric spellings are preserved. Existing source CRUD remains
schema 1. Credentials remain explicit per-call `token:` values: use read
credentials for queries/feeds, write credentials for PATCH/transactions.

`feed(target, **options) { |raw_page, metadata| ... }` synchronously yields one
complete validated immutable NDJSON page including LF. Persist page effects and
`next_after` together; `checkpoint` is the tip. `resume_after` records delivered
progress on normal completion. Native terminal records remain raw and observable.
Cancel the public `BinaryCancellation` to stop. Incomplete pages never reach the
block; completed pages survive a later failure. One absolute deadline includes
admission, TLS, decoding and the block; heartbeats never refresh it.

Finite bodies and total feed DATA are bounded to 16 MiB, acknowledgements/errors
to 4 KiB. Protocol-1 peers raise a typed `:unsupported` error before REQUEST.
There is no HTTP fallback or automatic replay. Uncertain mutation errors own a
`BinaryOperationEnvelope` retaining exact method, target, content type, source,
conditions and request ID. Cancellation and EOF never prove rollback. These raw
APIs do not claim decoded numeric-value support or HTTP's 64 MiB large envelope.

The separate version-3 adapter is `conformance/operations.rb`.
