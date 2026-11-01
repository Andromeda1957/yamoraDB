# Native binary framing foundation, version 1

`src/transport/binary_frame.[ch]` implements a byte-stream codec and local
connection admission state in C17, without allocation, sockets, TLS calls, or
third-party dependencies. This document describes the framing layer. The
opt-in [native daemon listener](binary-runtime.md) combines it with typed
document metadata, dedicated TLS and an owned session runtime. HTTP and the
native storage format remain available; public SDK binary adoption is open.

## Wire header

Every frame is a 16-byte header followed by exactly `length` payload bytes.
All multibyte wire integers are unsigned **big endian**, independent of the
existing storage codecs' little-endian formats. Never transmit a C struct.

| Byte offset | Width | Meaning |
| --- | --- | --- |
| 0 | 4 | ASCII `YMBF` |
| 4 | 1 | Envelope version, exactly `1` |
| 5 | 1 | Frame type, table below |
| 6 | 2 | Reserved flags, exactly zero |
| 8 | 4 | Stream ID |
| 12 | 4 | Payload length, excluding the header |

Example: an END on stream 1 is
`59 4d 42 46 01 05 00 00 00 00 00 01 00 00 00 00`.
There is no compression, implicit terminator, padding, checksum, resynchronizing
scan, or permissive unknown-frame handling. TLS supplies channel integrity when
the parent wires the listener. Reject malformed headers before copying payload
bytes. A frame may cross any socket/TLS-record boundary; several frames may
arrive in one read.

| Type | Value | Stream | Payload and boundary |
| --- | --- | --- | --- |
| HELLO | 1 | 0 | Exactly 12 bytes of capabilities, once per direction |
| REQUEST | 2 | Odd, nonzero | Nonempty opaque application metadata; opens a stream, client only |
| RESPONSE | 3 | Active | Nonempty opaque application metadata; server only, once, after request END or CANCEL |
| DATA | 4 | Active | Nonempty application body bytes, concatenated in order for that direction |
| END | 5 | Active | Empty; ends only the sender's message half |
| CANCEL | 6 | Active or historical | Empty; client only, ends its request half and asks the server to stop |
| ERROR | 7 | Active | Exactly one nonzero u32 application error code; server only, terminates its response half |
| PING | 8 | 0 | Exactly 8 opaque bytes; upper layer bounds and correlates probes |
| PONG | 9 | 0 | Exactly 8 opaque bytes; upper layer echoes/correlates PING |
| GOAWAY | 10 | 0 | Empty; once per direction, admission enters drain mode |

REQUEST/RESPONSE metadata has no endpoint, authorization, content-type,
conditional-write, or status schema in this slice. It is bounded opaque data,
separate from DATA body bytes. The parent must define and validate that schema
before dispatch or SDK adoption, preserving HTTP behavior and permissions.
Framing success never authenticates a peer or authorizes a storage operation.
The ERROR code is application-defined; it carries no private error string and
does not itself establish a transaction outcome.

## Negotiation and limits

Each endpoint sends one HELLO and receives one HELLO before any other type.
Either endpoint can send first. The 12-byte payload is:

| Offset | Width | Capability |
| --- | --- | --- |
| 0 | 2 | Minimum supported message version |
| 2 | 2 | Maximum supported message version |
| 4 | 4 | Maximum frame payload bytes |
| 8 | 4 | Maximum concurrent streams |

The native listener advertises message protocols `[1,2]` and selects the highest
common version. Legacy callers offering `[1,1]` select 1. Protocol 2 also accepts
schema-1 CRUD, returning the exact schema-1 response. Schema 2 requires a selected
protocol of 2; it cannot be sent to a protocol-1 peer. The framing envelope and
ALPN stay version 1. Pure framing callers default to advertising `[1,1]` unless
they explicitly initialize `max_protocol=2`. An unknown envelope version fails.
The local HELLO must exactly advertise initialized local caps, even when it is
sent after the peer HELLO. Duplicate HELLO, incompatible ranges, zero caps,
and peer caps outside implementation bounds are errors.

Effective frame and stream caps are the minima of the local and remote caps,
symmetrically used for send and receive. Frame payload caps range from 12 bytes
through 1 MiB; stream caps range from 1 through 128. HELLO does not alter local
queue budgets or cumulative message limits. Initialize each message limit from
16 MiB through 64 MiB, separately enforced on request DATA and response DATA.
One 16 MiB document therefore spans many DATA frames even if the peer advertises
a 4 KiB frame cap. Smaller negotiated frames never shrink document capacity.
An empty body consists of zero DATA frames and END. Metadata bytes are bounded
per frame, separately from the cumulative DATA limit.

The application still applies its own document/request profile from `value.h`:
ordinary document limits, opt-in 16 MiB documents and 64 MiB request envelopes
remain independent of framing. A transport message limit is a ceiling, not
permission to exceed the selected storage profile.

## Stream lifetime and half-closes

The client chooses odd IDs in strictly increasing order on this ordered
connection. ID 0 is connection control, even IDs are invalid, and there are no
server-created streams. Gaps are allowed; reuse, decreasing IDs, and wrapping
from `UINT32_MAX` to 1 are invalid. Open a new connection after exhaustion.
The implementation compares IDs without incrementing or wrapping them.

REQUEST opens the request half. Only client DATA can follow until client END
or CANCEL. Request END keeps the stream slot active while the server prepares
its response. RESPONSE then allows server DATA until server END. DATA byte
counters and END state are independent for the two halves. A stream slot
retires only when both halves have ended; held queue tickets may outlive it.
Concurrent streams may interleave frames, but a direction cannot interleave two
messages on the same stream. Repeated END/RESPONSE or DATA on a closed half is
invalid. Caller serialization preserves frame order.

Server ERROR may precede RESPONSE and request END. It closes only the response
half. Already-sent client DATA is still bounded and admitted for draining until
the client sends END/CANCEL; the application must discard it after the error,
without invoking a new write. The `errored` stream field identifies that state.
A client observing an early error should stop producing data and send CANCEL.

CANCEL ends the request half, sets `cancelled`, and keeps the slot until the
server terminates via END or ERROR. A cancellation acknowledgement can be END
without RESPONSE. A response already in flight may still produce RESPONSE and
DATA after cancellation; drain those bytes under the usual budgets. Repeating
CANCEL on an active cancelled stream is invalid. A late CANCEL for an odd ID at
or below the highest admitted ID is a no-op when no slot exists, handling the
race with a terminal response. This includes skipped historical IDs and never
creates a stream or changes a newer request. A future unknown ID is invalid.

Cancellation, admission, END, ERROR, EOF, timeout, or send failure **cannot prove
whether a write committed**. There is no automatic write replay, rollback,
exactly-once promise, reconnect replay, or idempotency token in this layer.
Runtime/SDK code must surface an uncertain outcome when the application's
durable acknowledgement is unavailable. Only a future application contract
can define retry safety and terminal write status.

Either GOAWAY stops admission of new requests on this connection; existing
streams and connection controls may finish. There is no accepted-ID watermark
or safe-retry promise. A request in flight across GOAWAY can lose its connection
and has the same uncertain-write rule. Graceful draining and its deadline are
runtime responsibilities, not inferred from local queue release.

## Memory ownership and backpressure

`yd_binary_parser_init` takes caller-owned storage at least `max_frame` bytes
long. The parser holds only a fixed header plus that buffer; it never allocates
from a peer length. Feed nonoverlapping input into `yd_binary_parser_feed`.
Each call consumes at most one frame and reports exactly how many input bytes
it consumed. Feed the unconsumed tail again for coalesced frames. MORE leaves
the output frame unchanged. FRAME returns borrowed bytes valid only until the
next feed; copy or process them before feeding again. Errors are sticky and
`yd_binary_parser_finish` distinguishes a clean boundary from truncated EOF.
A clean EOF is not proof that outstanding streams or writes finished.

After peer HELLO, reinitialize the parser at that frame boundary with the
effective `connection.max_frame`, retaining the same buffer. Do this before
feeding any coalesced tail. Never reinitialize midway through a frame or
discard unconsumed input. Admission independently checks the negotiated cap.

`yd_binary_connection_init` creates a fixed table of at most 128 slots, with
no per-request allocation. `yd_binary_admit` takes a complete validated frame,
local RECEIVE/SEND direction, and an output ticket. It validates state and
reserves wire bytes (16-byte header plus payload) atomically. On **every**
rejection the connection and output ticket remain byte-for-byte unchanged.
BACKPRESSURE can be retried with the identical frame after capacity releases;
INVALID/LIMIT require closing the connection. Header codec errors also close
the connection. The layer never dispatches or sends anything by itself.

REQUEST, RESPONSE, DATA share the data budget; HELLO, END, CANCEL, ERROR, PING,
PONG, GOAWAY use a separate control reserve so a full data queue alone does not
prevent termination. RECEIVE and SEND have separate counters. Each data budget
must fit one maximum local frame plus header and may not exceed 64 MiB; each
direction's control reserve is 28 bytes through 64 KiB. Control reserve can
also fill and applies backpressure. Admission charges metadata as well as DATA,
so many small requests cannot bypass retained/queued byte accounting.

Retain the received frame and stop feeding its parser on backpressure; bound
any coalesced unread tail in the caller's input buffer. Do not consume and lose
a rejected frame. Release an RX ticket only after its payload is discarded,
processed, or transferred into a separately bounded application buffer. Moving
bytes into an unbounded accumulator is not release. Release a TX ticket after
its queued frame has actually left the local queue (or is discarded on close),
not when its application operation commits. These budgets are local queue
accounting, not peer-advertised flow-control windows or durability acks.

Use each live ticket exactly once with the connection that issued it.
`yd_binary_release` zeros a successful ticket and rejects its second release or
use with another connection. Tickets are caller-owned, must not be copied,
forged, overwritten while live, or used after connection destruction. Do not
move/reinitialize a connection with live tickets. Serialize admission, release,
and frame queueing per connection; the API is not internally synchronized.

Admit SEND once before queueing the complete frame. Encode and enqueue bytes
in the same order as admissions. On socket/TLS failure close the connection;
never undo admission or replay an admitted request onto a new connection.
Parser storage, socket buffers, application accumulators, session count,
timeouts, ping rate, worker queues, and global budgets need additional runtime
bounds. The fixed per-connection state does not bound the number of connections.

## Parent integration and validation

The parent owns daemon/TLS dispatch, build and CI registration, and SDK adoption.
Add `src/transport/binary_frame.c` to the native build and register
`tests/binary_transport_harness.c` through `tests/run_binary_transport.sh`.
The discovered `tests/test_binary_transport.py` wrapper executes the entire
runner, so the existing Yamora unittest gate exercises this slice and fails on
compile or runtime errors. No shared Makefile/CI registry or daemon file is
changed by this slice. Before enabling a listener, define application metadata and error
codes, authenticate and authorize requests, select an explicit TLS/ALPN or
separate-listener routing contract that preserves HTTP and Raft, apply deadlines
and global/session budgets, and exercise real TLS dispatch and client
conformance. Those are remaining transport work, not completed features here.

Run the focused harness from the repository root with an existing task-owned
scratch directory, for example:

```sh
TMPDIR=/var/tmp/andromeda-work/yamora-binary-transport bash tests/run_binary_transport.sh
```

The script builds serially, uses unique disposable children under TMPDIR, and
cleans them on success/failure. It runs the standalone codec/state suite, then
ASan/UBSan, then an integration harness against the parent's existing native
pack/unpack implementation (`-lyaml -pthread -lm` are existing storage harness
requirements, not codec dependencies). Tests cover every two-part split and
one-byte feeds, coalescing, truncation, corrupt fields, a deterministic hostile
corpus, atomic admission rejection, invalid directions, version minima,
bounded streams, no ID reuse/wrap, independent halves/budgets, cancellation and
early-error races, and an exact 16 MiB body over negotiated 4 KiB frames.

## Exact YAML bytes

DATA for a raw-YAML body is the original source byte sequence split at arbitrary
byte offsets and concatenated without modification. Splits may occur within
UTF-8 characters, CRLF, quoted scalars, escapes, or comments. Preserve byte
length, whitespace, comments, key ordering, numeric spelling, quotes, BOMs if
accepted by the application, and trailing newlines. Never use `strlen`, JSON
conversion, a re-emitted `YDValue`, normalization, or `YMV1` as a substitute for
the raw source. Empty raw YAML remains an empty byte sequence. The framing codec
does not validate UTF-8/YAML or execute tags/aliases; the assembled body must
pass the existing safe parser and document profile before storage. Arbitrary
binary DATA accepted by framing is not automatically a valid stored document.

The storage integration test performs native pack/unpack followed by fragmented
DATA transport for three real synthetic YAML inputs, comparing exact source
bytes (CRLF/comments, numeric spellings, Unicode, block and quoted scalars).
It also validates the exact 16 MiB reassembled YAML document against the native
large-document pack/unpack profile.
Neither the binary framing nor any later runtime deployment should rewrite the
Git-backed YAML sources or existing HTTP API payloads.
