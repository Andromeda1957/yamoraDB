# Binary CRUD metadata, schema 1

`src/transport/binary_message.h` freezes the pure REQUEST/RESPONSE metadata
contract. The codec owns fixed-size decoded structs and performs no allocation,
I/O, authentication, authorization, dispatch, or body conversion. Its success
proves only metadata validity, never permission, durability, or a write outcome.
Listener/session integration and SDK adoption belong to subsequent parent work.

Schema 1 below remains exact. The opt-in additive schema 2 is described at the
end of this document and requires explicit HELLO protocol-2 negotiation.

Metadata is one complete frame payload, at most 2,048 bytes. The prefix is
`u16 schema=1, u16 field_count`, followed by `u16 id, u16 length, value` for
each field. All integers are unsigned big endian; no C structs are transmitted.
IDs must be strictly increasing and unique. Missing required fields, unknown
IDs, wrong widths, unsupported versions, truncation and trailing bytes fail.
There is no incremental metadata decode: assemble the frame first using the
existing framing parser, then decode before its borrowed payload is reused.

All text is printable ASCII (0x20..0x7e), without a wire NUL terminator. Names
are the existing `snapshot.c` profile `[a-z0-9-]{1,128}`. This deliberately
keeps native names and header metadata distinct from Unicode YAML DATA.

## Request

| ID | Field | Type and rules |
| --- | --- | --- |
| 1 | method | Required u8: GET=1, HEAD=2, PUT=3, DELETE=4 |
| 2 | target | Required text, at most 1,024 bytes; exactly `/v1/collections/<name>/documents/<name>` |
| 3 | content_type | Required text, at most 95 bytes; empty for GET/HEAD/DELETE; YAML for PUT |
| 4 | body_length | Required u64, 0..16,777,216; zero for GET/HEAD/DELETE |
| 5 | authorization | Optional text, at most 519 bytes; exact `Bearer ` plus 1..512 bytes from 0x21..0x7e |
| 6 | if_match | Optional opaque text, 0..31 bytes |
| 7 | if_none_match | Optional opaque text, 0..31 bytes |
| 8 | request_id | Optional nonzero 16-byte value |
| 9 | timeout_ms | Optional u32, 1..30,000; absent means 30,000 |

There are no query strings, percent decoding, alternative path spellings or
collection-only routes. `yamldb-system` remains syntactically valid: the codec
does not replace the storage/API reserved-collection rule. PUT's base media
type is case-insensitive `application/yaml` or `text/yaml`, optionally followed
immediately by `;` and printable parameters, matching the daemon check. Empty
PUT bodies are metadata-valid; the existing document validator rejects them.
Conditions, including empty values and both fields together, pass unchanged to
existing validators. The codec imposes no credential minimum beyond nonempty
token syntax, no cluster-mode request-ID requirement and no storage-profile
capacity choice; those are application responsibilities.

## Response

| ID | Field | Type and rules |
| --- | --- | --- |
| 1 | status | Required u16, 200..599 |
| 2 | content_type | Required nonempty text, at most 95 bytes |
| 3 | body_length | Required u64: DATA bytes on the wire |
| 4 | representation_length | Required u64: corresponding unsuppressed body length |
| 5 | revision | Required exactly 16 lowercase hexadecimal ASCII bytes, unquoted |
| 6 | etag | Optional exactly 18 bytes: quoted 16 lowercase hexadecimal digits |
| 7 | collection | Optional native name, at most 128 bytes |
| 8 | document | Optional native name, at most 128 bytes |
| 9 | allow | Optional nonzero u8 mask: GET=1, HEAD=2, PUT=4, DELETE=8; no other bits |
| 10 | authenticate | Optional u8, exactly 1 meaning Bearer |
| 11 | retry_after_seconds | Optional u32 delta seconds, including zero |
| 12 | request_id | Optional nonzero 16-byte value |

Both lengths are at most 16 MiB. Wire length is zero or equals representation
length; this schema has no compression or partial representation. Status 204
requires both lengths zero; status 304 requires wire length zero. A zero wire
length and positive representation length can describe HEAD or 304; correlating
HEAD and all other request-specific expectations is the runtime's duty. The
codec does not infer a request method from a response.

The native disk API emits `ETag: "0123456789abcdef"` as a header line, while
its JSON receipt uses `"etag":"0123456789abcdef"`. Field 6 preserves the
quoted header **value**, without the `ETag: ` prefix or CRLF. Revision remains
unquoted; collection/document fields contain the actual native names. Allow,
challenge and retry fields describe their corresponding HTTP header values;
their correlation with a particular status is left to the response bridge.

## Ownership and integration

The optional-field `present` masks use bit `1 << (id-1)`; required fields have
no presence bits. Unknown presence bits fail encoding. Unflagged optional
members are ignored when encoding. Decoding clears unflagged members except
for the default timeout. All strings have an additional owned NUL byte.

The size functions validate and report exact encoded size. Encoders require
non-NULL output/length pointers and sufficient capacity, write no output on
failure, and leave output tail and length unchanged on failure. The length
object must not overlap the source struct or output capacity. Struct/output
overlap is supported using bounded local storage. Decoders accept overlapping
input/output, copy all metadata, and clear every output byte on failure; that
clear also overwrites overlapping input. Other input is unchanged. Pointers
must cover their declared accessible extents. Calls have no shared mutable
state; shared immutable inputs with separate outputs are safe concurrently.

Raw YAML DATA remains byte-exact source, split at arbitrary byte offsets;
metadata carries its length, not an alternative source encoding. JSON receipt
DATA remains unchanged. `YMV1` persisted native values are not public input.
Runtime code still checks actual DATA length, safe YAML/profile validation,
credentials/grants, cluster request IDs, deadlines, and receipt semantics.
Neither decode success nor response metadata establishes an authoritative
outcome, replay safety, rollback, quorum proof or adoption/full API parity.

## Conformance vectors and focused gate

Independent literal request/response bytes live in
`tests/binary_message_harness.c`, together with field, capacity, alias,
fragmentation and malformed-input cases. The Python discovery wrapper
`tests/test_binary_message.py` compiles the codec with that harness directly,
without daemon, YAML, storage or TLS linkage, then runs normal and fatal
ASan/UBSan builds plus an unsuppressed TSan parallel-call build when its
runtime can initialize. An unavailable TSan runtime is reported explicitly.
The parent owns shared build registration and runtime qualification.

With `TMPDIR` set to the active task's disk-backed scratch directory, run
`python3 -m unittest discover -s yamora/tests -p test_binary_message.py -v`
from the repository root. `CC` selects a direct host compiler (default `gcc`).
The sanitizer-policy test independently demonstrates fatal signed overflow
even with recovery requested, and fatal address instrumentation. TSan uses no
suppression list; only a separate empty-program probe may report a recognized
runtime initialization limitation. A failure of the parallel codec harness
always fails the test.

## Additive operations, schema 2

HELLO advertises message protocols 1..2 under the unchanged version-1 framing
envelope and `yamora-binary/1` ALPN. Select the highest common protocol. A peer
offering only 1 retains schema-1 CRUD. On protocol 2 each request independently
chooses schema 1 or 2, and its response mirrors that schema. Schema 1 gains no
methods, fields, streaming meaning, statuses or target spellings.

Schema-2 requests retain fields 1..9 and add method POST=5 and PATCH=6. Document
targets retain GET/HEAD/PUT/DELETE and additionally accept PATCH. POST accepts
exactly `/v1/query/<name>`, `/v1/aggregate/<name>`, `/v1/search/<name>` and
`/v1/transactions`. GET additionally accepts `/v1/changes`, its native paged
query parameters, and `/v1/changes/stream?after=...` with native limit, duration
and heartbeat parameters. No percent decoding or general endpoint tunnel is
introduced. Native API validators still validate specifications and cursors.
POST/PATCH accept YAML or JSON; document PUT retains raw YAML only. Application
bytes pass unchanged to the native API, preserving numeric spellings and YAML
sources. Aggregate foreign collections and every transaction operation receive
the same full-body authorization checks as HTTP before backend execution.

Schema-2 responses retain fields 1..12 and require field 13, a one-byte mode:
0 is finite, 1 is a page stream. Unknown values, widths and missing mode fail.
Allow adds POST=16 and PATCH=32 only in schema 2. Mode 0 retains exact fixed
length checks. Mode 1 requires status 200 and both fixed lengths zero; DATA
instead contains newline-delimited native change pages followed by END. The
initial response revision describes admission, not every later page. No other
operation currently produces mode 1.

Binary request envelopes and finite responses are each limited to 16 MiB,
independently of the native large profile's 64 MiB request envelope. GET/HEAD
documents also retain their storage profile limits. Acknowledgements and errors
remain at most 4 KiB; the atomic transaction receipt is the native count-only
`status/operations/revision` receipt. Oversized native query results return 413
before RESPONSE. An excessive declared request is rejected before dispatch;
transport metadata violations terminate the stream/connection, without a write.

The 128 MiB transport application ledger accounts separately for native output
allocation: query/aggregate/search/change-page/feed jobs reserve 64 MiB plus one
byte before dispatch, since the native page API can allocate that buffer even
for an empty result. Input ownership is additional. A live feed keeps this
reservation between pulls; consequently only one such page job can be admitted
at once under the current ledger. Capacity exhaustion follows the existing
bounded protocol rejection; it performs no backend dispatch. This ledger covers
owned request/output allocations. Native query heaps, decoded documents,
reducers, disk caches and TLS buffers have separate bounds; 128 MiB is not a
claim about total process memory.

A feed retains at most one complete page and transfers at most 16 MiB including
all page LFs, heartbeats and terminal records. Its ordinary-page budget reserves
4 KiB for one terminal record. Cursor `next_after` advances only when the complete
prior page has left TLS; `checkpoint` is never a substitute. Transactions remain
whole within a page. A later native failure or byte limit emits the existing
`{"terminal":true,"status":...,"after":...,"detail":...}` shape with the last
complete cursor, then END. Initial token/size errors return a finite error before
streaming starts. Normal duration completion sends END; cancellation may send
END without proving full delivery. EOF, ERROR or deadline expiry can interrupt
a page; retain only the last complete validated page cursor.

The one monotonic request deadline includes upload, queue, initial read and all
later pulls/delivery. Producer duration is capped by the remaining request budget
minus 100 ms reserved for terminal delivery; heartbeats also wake at duration
expiry. A shorter requested duration remains its own bound. This permits normal
END for the default duration without extending the request deadline. Scheduling
or delivery that exhausts the absolute deadline still yields ERROR/EOF. Per-page
send budgets are capped by that deadline. Idle
heartbeats schedule future finite worker pulls without sleeping on a worker or
holding an application view. Pulls yield to other jobs and complete-page delivery
applies backpressure before acquiring another page. Cancelled queued pulls never
dispatch; executing pulls retain sole ownership until they return. Producer
cleanup is exact-once, including disconnect and shutdown.

Replica-set PATCH and transaction mutations require the same nonzero request ID
and exact retry bytes as HTTP. Their original durable receipt revision survives
later writes and cross-transport same-ID replay. Query POST is read-only;
transaction POST is a mutation. A cancelled, timed-out or incomplete mutation
can have committed. There is no automatic replay, rollback assertion or HTTP
fallback. Standalone mutations retain their existing deduplication semantics.

All nine public SDKs retain schema-1 document CRUD and provide negotiated
schema-2 finite operations and bounded change-feed clients. Their installed
consumer qualification is separate from native wire-fixture coverage; see the
[driver contracts](drivers.md) and [shared conformance profiles](../conformance/README.md).
