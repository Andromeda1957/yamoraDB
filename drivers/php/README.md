# Yamora PHP HTTP/TLS, replica sets and binary document CRUD

## Local Composer package and runnable CRUD example

The local package is **yamora/driver** 0.1.0. Its classmap includes all source
files, including classes sharing files and transitive HTTP, replica-set and
binary dependencies. The archive includes source, README, MIT license copied
verbatim from `yamora/LICENSE`, Composer metadata and the example. Tests,
conformance adapters, vendor files and lockfiles are excluded. No third-party
SDK runtime dependencies are added.

The full package requires Linux, 64-bit PHP >=8.2, JSON, filter, PCRE, OpenSSL
with TLS 1.3 and POSIX support. Only Linux x86_64 with PHP 8.5.12 is qualified.
The minimum requirement is not a qualification of every PHP release. This local
foundation does not establish stable-version compatibility or registry availability.

Composer is a build/test tool only. The private test PHP configured with
`--disable-all` also needs `--enable-phar --with-iconv` to run Composer;
these are not SDK runtime requirements. Set `COMPOSER_PHAR` to a verified
official Composer PHAR. Acceptance uses Composer 2.8.12 from
`https://getcomposer.org/download/2.8.12/composer.phar`, verified before execution
with SHA-256 `f446ea719708bb85fcbf4ef18def5d0515f1f9b4d703f6d820c9c1656e10a2f2`.
From this directory, using existing owned disk-backed
`TMPDIR` and a fresh consumer directory:

```sh
php "$COMPOSER_PHAR" --no-plugins --no-scripts archive \
  --format=tar --dir="$TMPDIR" --file=yamora-driver
mkdir "$TMPDIR/php-consumer"
php -r '
$archive = new PharData($argv[1]);
$metadata = json_decode($archive["composer.json"]->getContent(), true, flags: JSON_THROW_ON_ERROR);
$metadata["dist"] = ["type" => "tar", "url" => "file://" . $argv[1]];
file_put_contents($argv[2] . "/composer.json", json_encode([
    "name" => "yamora/local-consumer",
    "require" => ["yamora/driver" => "0.1.0"],
    "repositories" => [
        ["type" => "package", "package" => $metadata],
        ["packagist.org" => false]
    ],
    "config" => ["allow-plugins" => false]
], JSON_THROW_ON_ERROR));
' "$TMPDIR/yamora-driver.tar" "$TMPDIR/php-consumer"
COMPOSER_DISABLE_NETWORK=1 php "$COMPOSER_PHAR" --no-plugins --no-scripts \
  --working-dir="$TMPDIR/php-consumer" install --no-dev --no-interaction
```

For an existing native HTTPS listener, set `YAMORA_PORT`,
`YAMORA_CA_FILE`, `YAMORA_READ_TOKEN` and `YAMORA_WRITE_TOKEN` using
your secret store. The host defaults to 127.0.0.1; `YAMORA_HOST` accepts a
canonical private IPv4. Set both `YAMORA_CLIENT_CERT_FILE` and
`YAMORA_CLIENT_KEY_FILE` to PEM files when mTLS is required. Run:

```sh
php "$TMPDIR/php-consumer/vendor/yamora/driver/examples/crud.php"
```

This creates `package-demo/php`, compares exact commented UTF-8/CRLF source
after create and conditional update, deletes conditionally, verifies 404, and
prints `CRUD_OK`. Override `YAMORA_COLLECTION` and `YAMORA_DOCUMENT`
for a fresh target. Existing targets fail create-only; uncertain writes are
never automatically repeated.

The existing Python runner registers `Contract.test_packaged_artifact` and the
two `PackageLifecycle` shutdown controls. With the same scratch and existing
native binary requirements as the normal runner, plus `COMPOSER_PHAR`, run from
this directory:

```sh
python3 tests/test_driver.py --binary "$YAMORA_TEST_BINARY" Contract.test_packaged_artifact
```

The check uses real Composer archive/install with networking, plugins and
scripts disabled, verifies the complete package contents and installed class
origins, and runs the installed example against fresh native mTLS with synthetic
credentials. It never substitutes a handwritten autoloader.

Package tests additionally use the repository's existing Python process and
workspace owner. Foundation orchestration supplies `PYTHONPATH` pointing to the
repository and `YAMORA_PACKAGE_TASK_ROOT=/var/tmp/andromeda-work/<task>`.
The anchor must be an existing owned, non-symlink, disk-backed task root directly
under `/var/tmp/andromeda-work`, match `ANDROMEDA_TASK` when supplied, and contain
the validated `TMPDIR`. An uncertain group shutdown retains the allocation and
its `.yamora-sdk-retained-*` marker directly under that anchor, outside temporary
test ancestors. Cleanup follows verified group shutdown. Composer's consumer
version is explicit, disabling its Git version probes. These are test-only
requirements; artifact conformance consumers must exclude the foundation source
`PYTHONPATH` and package-owner environment settings.

Requires 64-bit PHP 8.2 or newer with standard JSON, filter, PCRE and stream support.
HTTPS additionally requires the standard OpenSSL extension with TLS 1.3 support.
No third-party Composer packages, curl, YAML extension or runtime libraries are
required. The driver sends YAML as bytes and leaves semantic validation to the
native daemon.

This is a bounded stage of the enterprise roadmap, with separate HTTP, replica-set and binary document clients. It has been
tested on Linux with PHP 8.5 and the native format-5 daemon over HTTP and mutual
TLS. It does not qualify the full driver roadmap: shared
all-driver conformance, continuous change streams,
high-level replication, packaging/version guarantees, and other platforms remain
open. There are no fallback or insecure placeholder implementations.

## TLS binary document client

`src/BinaryClient.php` adds GET, HEAD, PUT and DELETE against the native
binary listener. HTTP and `ClusterClient` keep their existing public APIs and
provide the other operations. Binary cluster discovery, shared conformance,
registry publication and cross-platform qualification remain **OPEN**.

```php
require_once 'drivers/php/src/BinaryClient.php';

$binary = new Yamora\BinaryClient(new Yamora\BinaryConfig(
    host: '10.0.0.11', port: 7401, serverName: '10.0.0.11',
    caPem: $trustedCaPem, privateDirectory: $ownedPrivateDirectory,
    clientCertPem: $clientCertificatePem, clientKeyPem: $unencryptedClientKeyPem,
    timeout: 10, maxFrame: 4096,
));
$saved = $binary->put('people', 'ada', "# authored\r\nname: Ada\r\n",
    token: $writeCredential, ifNoneMatch: '*');
$document = $binary->get('people', 'ada', token: $readCredential);
$head = $binary->head('people', 'ada', token: $readCredential);
$binary->delete('people', 'ada', token: $writeCredential,
    ifMatch: '"' . $document->metadata['etag'] . '"');
$binary->close();
```

`BinaryResponse` exposes readonly `metadata` (scalar values only) and `body`
(the exact owned bytes). HEAD has an empty body and the unsuppressed
`representationLength`. Metadata includes `status`, `revision`, unquoted `etag`,
`collection`, `document` and nullable `requestId`. PUT bodies are native JSON
receipts; they are validated before return. The raw `request` method accepts
only the four document methods. All calls accept named `token`, `ifMatch`,
`ifNoneMatch`, `requestId`, `timeout` and `cancellation` options. Binary conditions
are exact printable wire strings, including empty present values; unlike the
HTTP convenience API, an ETag condition includes its quotation marks. Invalid
conditions are rejected by the native daemon. Tokens are per-call, absent or
1–512 non-space printable ASCII bytes; no credential is stored in the client
or recovery envelope. GET/HEAD 304 requires `ifNoneMatch: '*'` or the exact
quoted response ETag, complete metadata, no DATA, and a terminal END.

Every operation makes one fresh TLS 1.3 connection with mandatory ALPN
`yamora-binary/1`, verified explicit CA trust and an exact typed SAN.
The destination remains canonical private IPv4 (loopback or RFC1918).
`serverName` selects a certificate identity independently: a private IPv4
identity requires an iPAddress SAN; an explicit ASCII DNS name requires a
matching dNSName SAN and is sent as TLS SNI. DNS names are at most 253 bytes,
with labels of 1–63 bytes, and comparisons ignore ASCII case. They never
resolve or select a network destination. CN fallback, wildcards, trailing
dots, IDNA, numeric DNS SANs in place of IP SANs, opaque contexts, custom verification,
system-root fallback and insecure settings are unsupported. There is no proxy,
redirect, connection reuse, reconnect or automatic binary retry.

Trust and optional client identity are PEM **bytes**, frozen with PHP string
value semantics at configuration construction. No caller certificate path is
retained. CA bundles are bounded at 1 MiB/128 CA certificates; the client
certificate chain and unencrypted matching key are each bounded at 1 MiB.
The key must be exactly one inline unencrypted PEM block with matching labels
and canonical base64; file URIs, concatenated blocks and surrounding opaque
text are rejected before OpenSSL can interpret the string as a path.
PHP's TLS loader takes paths, so each operation creates a random mode-0700
directory under the explicit canonical, current-user-owned `privateDirectory`.
That parent must already exist and must not be group/world writable. Files
are created exclusively, set to 0600 before credential bytes are written, and
removed with their directory on every success/failure before admission is
released. Cleanup failure fails the call. No global umask, SSL configuration
or trust store is changed. This facility requires Linux, 64-bit PHP 8.2+,
standard POSIX/OpenSSL support and a private local filesystem; other operating
systems are not qualified. Supply the credential
directory through application provisioning and remove its empty parent under
the application's normal lifecycle.

One synchronous owner is admitted per client. Fibers and reentrant calls fail
before source freezing or socket creation; rejected callers hold no additional
source copy or queued connection. Independent clients/processes are isolated.
PHP strings, envelopes and results have value semantics; readonly fields expose
no mutable backing buffer or caller conversion/serialization hooks. A monotonic
deadline starts at method admission and covers input freezing, UTF-8 checks,
credential files, TCP/TLS, all fragments, strict decoding, source hashing,
cleanup and the final return guard. The default is 10 seconds, maximum 30.
`CancellationToken` is cooperative, including during bounded CPU scans and
10 ms socket waits; native PHP/OpenSSL primitives cannot be preempted. There
are no background cancellation callbacks to join. Cancel the owning call before
`close`; calling `close` reentrantly is unsupported.

HELLO/TLV/frame validation precedes advertised-length allocations. Negotiated
DATA frames are 4–64 KiB, sources at most 16 MiB, and acknowledgements/errors
at most 4096 bytes. Complete DATA and END are required. JSON must be UTF-8,
duplicate-free (including escaped keys), bounded to 64 nesting levels and
100,000 values; receipt identity fields must have exact string types. PUT
status must match create-only/If-Match semantics, body identity/revision/ETag
must match metadata, and successful GET and PUT source hashes must match the
native ETag. Hashing uses bounded integer pairs and the native
1469598103934665603 offset basis, without float overflow.

Mutations always have a supplied or generated nonzero 32-hex request ID.
Responses must have exactly the request's ID presence and value. A dispatched
EOF, partial response, ERROR (including code 1), GOAWAY without completion,
cancellation, timeout or malformed receipt raises `BinaryUncertainException`.
It retains readonly `envelope`, `requestId`, sanitized `reason` and optional
`status`, with no credential or raw exception attached. Complete native 4xx
rejections (except 408) raise `BinaryStatusException`; 408/5xx mutations remain
uncertain. Reads use the existing protocol/transport/deadline/cancel errors.

Reconcile exact stored source and preconditions independently before choosing
to repeat an uncertain mutation. `execute($envelope, token: ...)` explicitly
submits that immutable operation once. `recover($uncertain, token: ...)` does
the same while preserving the original uncertainty if the repetition fails,
even before dispatch or on a later rejection. Method, target, source,
conditions and ID remain unchanged; only the new deadline and per-call bearer
are supplied anew. Standalone stores gain **no deduplication guarantee** from
an ID. The driver makes no rollback, exactly-once or safe-replay promise.

The existing `tests/test_driver.py --binary ...` command below discovers the
required `BinaryContract` alongside the full HTTP and cluster suites. Missing
native daemon input fails, never skips. Binary checks cover real ASan/UBSan
native mTLS CRUD/roles, exact CRLF/Unicode/comments, HTTP interoperability,
16 MiB over 4 KiB frames, legacy 256 KiB rejection, TLS/ALPN and hostile framed
receipts, immutable trust/source ownership, admission/cancellation/deadlines,
and independently observed committed source before explicit lost-reply
repetition. Precise mutants require a named behavioral assertion and confirmed
wire dispatch; crashes, infrastructure errors and timeouts do not count as red.

```php
<?php
declare(strict_types=1);
require_once 'drivers/php/src/Client.php';

use Yamora\Client;
use Yamora\TlsOptions;

$db = new Client(
    host: '127.0.0.1',
    port: 8765,
    readToken: $readCredential,
    writeToken: $writeCredential,
    timeout: 5.0,
    tls: new TlsOptions(caFile: $trustedCaPath),
);

$yaml = "# authored source\r\nname: Ada\r\nvisits: 1\r\n";
$stored = $db->put('people', 'ada', $yaml, createOnly: true);
$doc = $db->get('people', 'ada', $stored->revision);
assert($doc->source === $yaml);
$updated = $db->patch('people', 'ada', ['$inc' => ['visits' => 1]], $doc->etag);
$page = $db->query('people', ['filter' => ['visits' => ['$gte' => 2]], 'limit' => 20]);
$db->delete('people', 'ada', $updated->etag);
```

For mutual TLS, pass `certificateFile` and `privateKeyFile` together to
`TlsOptions`. Client keys must be unencrypted PEM; encrypted keys fail without
prompting for a passphrase, including when a controlling terminal is present.
Without `caFile`, OpenSSL uses its normal trust store. Certificate chain and
endpoint IP identity verification are mandatory. Before sending HTTP, the driver
checks the captured, chain-verified leaf for a matching four-byte **iPAddress SAN**.
CN fallback, numeric DNS names and DNS wildcards do not satisfy this check. The
bounded DER reader checks typed SAN fields; it does not infer identity from
OpenSSL's human-readable SAN display string. The transport uses
the runtime's [TLS 1.3 method](https://www.php.net/manual/en/function.stream-socket-enable-crypto.php)
and fixed [verified SSL context options](https://www.php.net/manual/en/context.ssl.php).
It rejects older protocols and never falls back to plaintext. Omitting `tls`
explicitly selects HTTP; use TLS for private cross-host traffic.

The host must be a canonical numeric IPv4 address in `127/8`, `10/8`,
`172.16/12`, or `192.168/16`, and the port must be 1–65535. URLs, hostnames,
IPv6, public addresses, wildcard binds and metadata/link-local targets are
rejected. Tokens are empty for an unauthenticated role or 32–512 non-space
printable ASCII bytes. Supply credentials through the application's secret
store; the driver never reads proxy environment variables.

| API | Behavior |
| --- | --- |
| `health`, `ready`, `stats`, `metrics` | Bounded metadata/metrics reads |
| `get` | `Document` with exact `source`, unquoted `etag`, and `revision` |
| `put`, `patch`, `delete` | Raw YAML or structured operators; explicit preconditions |
| `collections`, `documentPage`, `documents` | Sorted IDs; pages expose revision and exclusive cursor; iterator pins its first revision |
| `query`, `count` | Structured predicates, sorting, projection and revision-bound pages |
| `aggregate`, `search` | Native pipeline and full-text endpoints |
| `transaction` | 1–128 operations with optional snapshot revision; atomic native validation |
| `indexes`, `setIndexes` | Read/replace the entire catalog, optionally guarded by snapshot revision |
| `startIndexBuild`, `indexBuild`, `cancelIndexBuild` | Submit, inspect or explicitly cancel a native online catalog job |
| `changes` | Single bounded native change page or initial checkpoint; no automatic follow/reconnect |

JSON results are `stdClass` objects with ordered properties; JSON lists remain
PHP arrays. Use associative arrays for maps, lists for arrays, and `(object) []`
for an empty JSON map. Signed 64-bit integers remain PHP integers. Values
outside PHP's integer range are returned as strings, rather than rounded floats.
Floating-point results exceeding PHP's finite range are rejected, including
nested fields; JSON exponent overflow must not silently become infinity.
The engine's signed 64-bit value profile is the supported numeric contract.
Invalid UTF-8, non-finite floats, cycles, custom serializers, excessive nesting
and excessive node counts are rejected before encoding. Literal Unicode NEL is
escaped in JSON so the native YAML parser cannot treat it as a line break.

ETags and revisions are **unquoted** 16-digit lowercase hexadecimal strings in
PHP arguments. `createOnly: true` sends `If-None-Match: *` and cannot be combined
with an ETag. Index replacement uses a database revision for `If-Match`.
`after` in document/query/search pages requires an explicit revision; a changed
snapshot fails instead of silently mixing pages. Stop using partial results if
an iterator later fails.

Every primitive call opens one socket, submits one request and closes it. There
are no redirects, connection reuse, proxy lookup, compression negotiation or
automatic mutation replay. Optional `requestId` arguments on document mutations,
transactions and catalog replacement forward a nonzero 32-digit lowercase hex
identity exactly once; they do not add cluster routing or retry semantics.
Read-only JSON POSTs use the read token, and mutations use the write token.

The monotonic whole-network-request deadline covers connection, TLS handshake,
all writes, headers and body together; the default is 5 seconds, capped at 30.
Progress cannot refresh that deadline. JSON input validation/encoding happens
before network I/O and has separate byte, node and depth limits. Raw sources
are capped at 16 MiB. Structured requests are capped at 2 MiB, or 64 MiB for
PATCH/transactions. Responses have a hard 64 MiB ceiling, additionally reducible
with `maxResponseBytes`; raw documents and metrics have a 16 MiB ceiling.
Response headers are limited to 16 KiB/64 fields. This nonstreaming stage requires
an unambiguous `Content-Length`, and rejects duplicate/folded headers (except identical `Cache-Control: no-store` diagnostics), truncated
framing, transfer encodings and content encodings. Success additionally requires
EOF after exactly the declared bytes under the same request deadline. A split
trailer fails regardless of packet boundaries; a server that keeps the response
connection open expires the deadline.

`HttpException::$status` retains HTTP status (including 412 conflicts and 3xx
redirect refusals). `ProtocolException`, `TransportException` and
`DeadlineException` distinguish malformed responses, I/O/TLS failures and time
limits. Error messages omit remote bodies and credentials. A failed mutation can
already be committed, including a timeout, lost reply or malformed success
receipt. Reconcile served state and preconditions before explicitly submitting
another mutation. The driver never promises rollback on error.

From the repository root, set `caller_scratch` to an existing owned disk-backed
directory below `/var/tmp/andromeda-work` and `native_binary` to an existing native
daemon executable:

```bash
TMPDIR="$caller_scratch" python3 drivers/php/tests/test_driver.py --binary "$native_binary"
```

`YAMORA_TEST_BINARY` can supply the binary instead of `--binary`; no implicit
binary path exists. Missing input fails with an actionable error. The Linux
runner accepts an existing caller `TMPDIR` beneath the scratch base, rejecting
the shared base itself, symlinks, missing directories and memory-backed mounts.
Every run allocates a unique child for its disposable state and cleans it on
success or failure. The caller's root remains owned by the caller.

The runner uses only Python's standard library, the local PHP executable and
the system `openssl` command. It never builds or alters the supplied daemon.
All fixture services bind ephemeral IPv4 loopback ports and are stopped by the
runner. Temporary databases, certificates and logs are owned under `TMPDIR` and
removed on success or failure. No shared application database is accessed.
Individual `Contract.test_*` names can be passed after the runner arguments.

Coverage includes exact CRLF/comments/Unicode and large-source round trips,
stale/create-only conditions, read/write auth separation, numeric/query results,
transaction atomicity, paging/revisions, native indexes/search/aggregation/change
pages, redirects/replay refusal, invalid endpoint/token/path inputs, oversized and
truncated framing, slow headers/bodies/blocked writes/handshakes, and real trusted,
untrusted, wrong-IP, CN-only, misleading numeric DNS, TLS 1.2 and mutual-TLS
connections, noninteractive encrypted-key rejection, and split response trailers.
The PHP process runs with
its ini disabled to verify this installed runtime needs no curl configuration.
Other PHP builds may require enabling their standard OpenSSL extension explicitly
when adapting the test invocation.

## Bounded replica sets

Load `src/ClusterClient.php` to use the same synchronous API through
`ClusterClient`. `Client` remains final, with its standalone one-attempt behavior.
The internal execution adapter shares its validation and once-only JSON encoding;
no user serializer, transport plugin, Composer package, or extra runtime library
is needed.

```php
require_once 'drivers/php/src/ClusterClient.php';
$db = new Yamora\ClusterClient(
    seeds: [
        ['host' => '10.0.0.11', 'port' => 8765, 'node' => 1],
        ['host' => '10.0.0.12', 'port' => 8765, 'node' => 2],
        ['host' => '10.0.0.13', 'port' => 8765, 'node' => 3],
    ],
    clusterId: $expectedFeedIdentity, // nonzero 32 lowercase hex digits
    voters: 3,
    tls: new Yamora\TlsOptions($caPath, $certificatePath, $privateKeyPath),
    readToken: $readCredential,
    writeToken: $writeCredential,
    timeout: 10,
    attemptTimeout: 2,
);
$cancel = new Yamora\CancellationToken();
try {
    $result = $db->patch('people', 'ada', ['$inc' => ['visits' => 1]],
        cancellation: $cancel, timeout: 5);
} catch (Yamora\UncertainWriteException $uncertain) {
    // Reuse the original method/path/body/conditions/count and request ID.
    $result = $db->recover($uncertain, timeout: 5);
}
```

Configuration requires 1–9 distinct private IPv4 HTTPS endpoints, distinct
expected node IDs in `1..voters`, and 3/5/7/9 voters. TLS chain, TLS 1.3, exact
IP SAN and optional mTLS checks precede HTTP credentials. Discovery reads the
strict bounded `/v1/cluster/status` and initial `/v1/changes` checkpoint: node,
leader, voter count, positive integer term, nonfailed state, applied/committed/log
ordering and all three feed identities must agree. Additive diagnostic objects,
including `application_compaction`, are tolerated and never used as destinations. The initial feed must be
empty with equal checkpoint and next cursor. A cached route only prioritizes
these checks; every operation revalidates them. Redirects, peer hints and
addresses in response bodies never choose a credential destination.

The native status API **does not attest a cluster UUID**. Feed identity is a
server assertion over TLS, not independent cryptographic UUID attestation. The
operator must provision the correct trusted CA, endpoint IP SANs, expected node
IDs and feed identity. A malicious server trusted for those configured endpoints
can lie about its metadata. This slice makes no stronger identity claim.

Each operation has one monotonic deadline from entry through input validation,
encoding, fair discovery budgets, transport, retries, cooperative backoff,
response decoding, semantic validation and the final return check. Named
`timeout` and `cancellation` apply to every primitive operation. There are at
most 32 exchanges, including discovery, with exponential backoff capped at
500 ms and cancellation polling during socket waits/backoff. PHP decoding and
other native primitives are synchronous: cancellation/deadline are checked
around them and during the duplicate-property scan, so a cancelled or expired
operation cannot return success after decoding. They cannot preempt an individual
native PHP/OpenSSL call. Calls from fibers and reentrant use of the same client
are rejected before dispatch; independent processes/clients are isolated. This
slice does not promise asynchronous scheduler or thread support. The `documents`
iterator pins revisions and applies these bounds to each page.

Mutations freeze their method, path, encoded bytes, preconditions, operation
count and supplied or generated nonzero 32-hex request ID **before discovery**.
Mutable arrays and nested `stdClass` values are encoded once. Automatic retry
sends exactly those bytes and that ID. For preparation without I/O:

```php
$prepared = $db->prepareMutation('patch', [
    'collection' => 'people', 'document' => 'ada',
    'operations' => ['$inc' => ['visits' => 1]],
]);
$result = $db->execute($prepared);
```

`PreparedMutation` exposes readonly scalar fields and readonly header/status
arrays; it contains no credentials. After an uncertain dispatch, use
`recover($exception)` to preserve that uncertainty across further rejection,
cancellation or timeout. `execute($prepared)` starts a new execution without
previous dispatch history. Never repurpose a request ID for different inputs.
An initially definitive HTTP rejection (4xx except 408) remains `HttpException`.
A dispatched transport/TLS/framing error, malformed/contradictory receipt,
timeout/cancellation, redirect, unexpected success, 408 or 5xx yields
`UncertainWriteException` if recovery cannot finish. It exposes `requestId`,
`mutation`, sanitized cause class `reason`, and optional HTTP `status`; an earlier
uncertain dispatch survives a later definitive rejection. A successful native
replay returns the **original receipt**, even after the database advances.

Receipt validation stays inside this recovery boundary. It checks stored versus
committed status, exact collection/document, integer operation count, body/header
revision, ETag agreement, DELETE 204, and PUT create-only 201/If-Match 200.
Every cluster JSON response, including reads, passes the bounded parser under
the same operation deadline before standalone API decoding. It rejects duplicate
properties (including escaped equivalent names and nested duplicates), depth above
64 and more than 100,000 JSON values. Raw YAML and metrics retain their byte API. Metadata counters
used for routing must fit a nonnegative PHP integer; larger native unsigned
counters fail closed. Raw YAML remains byte exact; signed 64-bit document
integers and JSON zero-fraction tokens keep the standalone profile.

Supported cluster mutations are document PUT/PATCH/DELETE, transactions and
**synchronous** index catalog replacement. Online index jobs, replication
orchestration and continuous feeds return 405 before dispatch. They are not
emulated. Binary transport, shared cross-driver conformance, other operating
systems/architectures, packaging/version stability and the remaining enterprise
roadmap are still open.

The normal `tests/test_driver.py --binary ...` runner discovers all cluster tests;
the parent's existing shared PHP SDK command already invokes that runner, so no
shared wiring change is required. Tests require the supplied daemon and never
skip native acceptance. They cover hostile real HTTPS metadata/framing/receipts,
input snapshots, recovery, cancellation/deadlines through decoding, fair and
bounded discovery, fiber rejection, and a real three-node mTLS replica set with
lost COMMITTED reply, exact source verification before retry, measured native
same-ID/distinct-ID overlap, quorum loss and full restart/original receipts.
The six actual native TLS sockets rendezvous before dispatch, then each reads
immediately. Completion is timestamped when Content-Length bytes arrive, before
EOF; the last send must precede the first full response, including the four
same-ID and two distinct-ID groups. Both groups have negative controls for
serialized native exchanges and early complete frames with EOF held open. Neither
buffered replies nor overlapping PHP calls alone can satisfy the overlap gate.

## Replication source preflight

Before application-owned replica staging, call `$source->requireReplicationSource()`.
It returns readiness or throws `Yamora\SchemaPolicyReplicationException` with
status 409. Advertised non-booleans throw `ProtocolException`; absent fields
support older policy-free servers. Recheck before publication or applying each
source frame. This advisory read never opens a destination stage; native
outgoing and receiver admission remains authoritative.

## Additive binary operations (schema 2)

`Yamora\BinaryOperationClient` uses the existing `BinaryConfig` for verified
TLS 1.3, a bounded synchronous owner and operation cancellation. Its
`operation($method, $target, $source, $contentType, ...)` returns a
`BinaryResponse` with exact raw bytes and actual scalar metadata. It supports
native query/aggregate/search POST, PATCH, transaction POST and changes GET.
`BinaryClient` document CRUD stays on schema 1. Operation specifications are
raw YAML or JSON; validation never rewrites numeric spellings or source bytes.

`feed($target, $onPage, ...)` calls `$onPage(BinaryChangePage $page): bool`
with complete validated NDJSON pages including their LF. Return true to continue
or false to cancel. The callback runs before another page is read. The result
contains actual response metadata, `lastAfter` and an optional native terminal
status. Native terminal records reach the callback unchanged before END.
Partial, invalid or regressing pages never reach it. A failed feed retains
validated metadata and the last completed cursor on `BinaryOperationException`.
Callers choose any retained copies; the client holds at most one page.

All calls share one absolute timeout through admission, TLS, parsing, callbacks
and END. Request/result/total feed bytes are limited to 16 MiB. Strict JSON
validation bounds depth to 80 and values to 65,536, rejects duplicate properties,
and retains number lexemes without PHP float conversion. Response mode, request
ID, status, cursor and native mutation receipts are checked before exposure.
Once a PATCH or transaction may have dispatched, an ambiguous failure raises
`BinaryOperationUncertainException` containing the original immutable envelope
(method, target, content type, exact source, conditions and ID). Query POST is
read-only. No call retries or falls back to HTTP automatically.

The separate version-3 adapter entry point is `conformance/operations.php`.
