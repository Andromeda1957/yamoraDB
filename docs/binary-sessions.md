# Owned binary session runtime

`src/transport/binary_session.h` exposes an IPv4 TLS listener with one I/O
thread and two dispatch workers. It consumes the existing binary TLS profile,
frame state machine and typed metadata codec. This module owns connections,
request snapshots, dispatch, response framing and shutdown. The parent owns
daemon wiring, backend operations, authentication policy, the shared HTTP upload
ledger and integration acceptance. The [native listener](binary-runtime.md)
documents daemon qualification; this module contract does not imply broader
binary APIs or multiplexed public SDKs.

## Callback and lifecycle contract

`yd_binary_runtime_start(options, error, error_length)` copies
`YDBinaryRuntimeOptions`, binds the requested `struct in_addr` and port, and
starts the three threads. Port zero asks the OS to allocate a port;
`yd_binary_runtime_port` returns it. `yd_binary_runtime_healthy` reports whether
the I/O loop remains operational. Startup failure unwinds descriptors and every
successfully started thread. An error buffer, when supplied with nonzero size,
is cleared first and receives a bounded diagnostic on failure.

Aborted connections and Linux transient accept/network errors consume a
bounded accept batch and leave the runtime healthy. Exhausted retry batches
and temporary descriptor/memory pressure defer further accepts for 50 ms,
including listener polling, while existing sessions continue. An unusable
listener still stops the runtime and fails health explicitly.

Options require a dedicated binary `tls`, `admit`, `execute`, `reserve_upload`
and `release_upload`. `io_timeout_ms` is 1 through 30000. `max_body` zero means
16 MiB; a nonzero value must be at most 16 MiB. The runtime borrows `tls` and
`context` until close returns. Callbacks must support concurrent calls.

`admit(context, request, rejection)` runs on the I/O thread after bounded
metadata decoding and the module body-cap check, before request-body allocation
or shared upload reservation. It must be nonblocking and perform no backend
I/O or wait for locks held across backend work. True accepts and leaves the
initially zeroed rejection empty. False transfers one valid `YDBinaryReply`
with status 400 through 599 and at most 4 KiB of error body. Parent admission
authenticates and checks the actual immutable disk profile before reservation.

A valid typed rejection drains exactly the declared body without allocating
it, then sends the rejection after exact END. Its absolute upload deadline
still applies. A body mismatch, invalid metadata, module cap or exhausted
capacity produces a bounded ERROR and a closing drain; it never dispatches.
Missing authentication therefore need not allocate an attacker-sized body or
lose the parent's typed 401 response.

`execute(context, request, body, length, remaining_ms)` runs only on the two
workers, after all declared DATA and exact END. Request metadata and body are
owned immutable snapshots, borrowed by the callback for that invocation only.
Workers receive no SSL or session pointers. `remaining_ms` is a monotonic
snapshot of the remaining absolute request budget immediately before callback
entry, not a fresh timeout. Parent further caps it to the configured backend
or cluster budget. Expired queued work never starts backend execution.

`YDBinaryReply.message` contains typed response metadata and `.body` transfers
one malloc/free-compatible owner to the runtime. NULL is required when wire
body length is zero. A buffered reply's allocation covers the declared length.
An alternative finite GET producer owns `next` and `close` callbacks and a
first chunk. Its metadata declares the complete body length before transmission.
The dispatch worker requests the next chunk only after TLS has delivered the
previous one. Every chunk has a separate malloc/free-compatible owner, and its
size cannot exceed the remaining declared length. Early END, WAIT, overflow or
invalid ownership fails the stream. Delivery of the exact final byte queues END
without an extra producer pull. Cancellation and disconnect retain a running
callback until it returns; `close` then releases its source exactly once.
GET/HEAD representations are at most 16 MiB; acknowledgements and errors are
at most 4 KiB. GET/HEAD conservatively reserve 16 MiB plus one byte before
backend execution. The daemon's document path validates and pins a source
without allocating its whole body; admission keeps its full reservation.
HEAD returns NULL body,
zero wire body length and the original representation length. The runtime
validates the reply before any response metadata reaches the wire, echoes the
owned request ID and replaces invalid or oversized callback results with a
bounded 500 response. For non-HEAD responses other than 304, wire and
representation lengths must match. The metadata codec validates the remaining
typed fields, including ETag, collection/document, Allow, Bearer and RetryAfter.
HTTP Vary and no-store handling belongs to the parent adapter.

The reservation callbacks bridge the shared HTTP large-upload ledger. They are
required, nonblocking and thread-safe. Only uploads strictly greater than
2 MiB call `reserve_upload`, for their entire declared size. Each success has
one `release_upload` at actual job free, including allocation failure,
assembly disconnect, queued cancellation, completed response and detached
execution. Module defaults do not replace the parent's shared 64 MiB ledger.

`yd_binary_runtime_close` is called by the external lifecycle owner, never a
callback. It stops admission, joins the I/O thread after connections detach,
joins both dispatch workers, then releases all remaining jobs and runtime
state. Borrowed TLS and backend context remain usable until return. A running
filesystem or backend callback may block this join. Accessors must be
serialized against destruction; NULL close is harmless.

## Fixed ownership and capacity

| Resource | Bound and lifetime |
| --- | --- |
| Connections | Eight, including incomplete TLS handshakes |
| Dispatch | Two workers, at most two waiting jobs |
| Admitted jobs | Four total across assembly, waiting, executing, retained response and detached execution |
| Body and response reservations | 128 MiB globally, charged before module body allocation or callback dispatch |
| Request DATA | At most 16 MiB, further limited by `max_body` and parent admission |
| Frames | Local maximum 64 KiB; peer maximum must be at least 4 KiB; negotiated maximum bounds transmission |
| Active streams | Four per connection, reduced to the peer's negotiated limit; four admitted jobs remain the global bound |
| Per-session transport | One receive frame, one transmit frame and their owned tickets; 4 KiB control wire budget; 16 KiB coalesced tail |

The body/response ledger excludes fixed session structures and OpenSSL's own
connection state and retry copy. Request metadata is fixed-size and stored by
value. A complete receive frame remains in place with its ticket under
BACKPRESSURE; its coalesced tail is preserved. A transmit ticket is admitted
once and retained until the frame is sent or discarded. Bounded iteration
prevents one ready connection from monopolizing the I/O loop.

While a retained complete frame or tail prevents another SSL read, the reactor
omits unnecessary read readiness. A wholly blocked descriptor is omitted from
polling so unread bytes or a hangup cannot spin the loop. Worker wakeups and
the at-most-50-ms deadline checks continue; pending TLS writes retain priority
and poll their required read or write direction until the immutable retry
resolves.

Cancellation before dispatch prevents execution. Cancellation after dispatch
detaches the running job and suppresses its completion on that stream. It does
not interrupt backend execution, release its slot or return upload credit
early. Disconnect and draining shutdown have the same retention rule. A
generation token and job identity prevent a stale completion from reaching a
reused session. Cancellation END retains its job owner until sent; other active
streams continue. The detached job still counts globally until its callback returns.
No automatic replay, rollback or certain outcome for an interrupted write is
promised.

Each job owns its reply position and response-send deadline. The I/O owner
selects ready replies in round-robin order after each complete metadata, DATA
or END frame. One connection still retains only one immutable transmit frame.
Backpressure on that TLS write therefore affects the whole socket, while other
connections and HTTP remain independently serviced. A complete request that
expires can send stream ERROR without terminating its siblings. An incomplete
upload expiry, protocol failure or expired pending TLS write still closes the
connection. Control frames retain their separate bounded reserve and priority.

## Deadlines and TLS retries

All clocks are `CLOCK_MONOTONIC`; there are no wall-clock timeout decisions.
The reactor polls for at most 50 ms and performs deadline checks each turn.
The TLS step functions have no polling or sleeping; the reactor owns readiness.

| Phase | Absolute deadline |
| --- | --- |
| TLS handshake | Accepted time plus I/O budget |
| HELLO | TLS handshake completion plus I/O budget |
| Frame assembly | First observed frame byte plus I/O budget |
| Request | First observed REQUEST frame byte plus typed request timeout |
| Upload, including rejected body drain | Earlier of request deadline and REQUEST arrival plus I/O budget |
| Waiting after END | Earlier of request deadline and END plus one second |
| Entire response send | Earlier of request deadline and first response-send preparation plus I/O budget |
| Idle with no job | Last application activity plus five seconds |
| Connection lifetime | Sixty seconds or 128 admitted requests, then GOAWAY and at most two seconds of drain |
| Peer GOAWAY or fatal protocol drain | At most two seconds |

HELLO establishes the initial application-idle baseline. Admitted application
frames and response progress refresh it; raw reads and explicit PING/PONG or
other control writes do not. A peer cannot extend idle lifetime with control
traffic. The active request budget replaces the idle read budget while a job is owned.
New requests and send phases receive their own explicit deadlines; a previous
HELLO/write deadline is never latched onto later requests. PING permits four
per second with a burst of four.

The I/O thread serializes all SSL calls. An unfinished SSL write retains the
same pointer, length and immutable bytes through WANT_READ or WANT_WRITE. No
SSL read interleaves until that retry resolves, and polling follows the
requested direction. A positive short write advances only by its reported
progress and resumes the exact remaining bytes. Already decrypted SSL bytes
are consumed without requiring a new socket-readability event. Session close
frees TLS state and then its owned descriptor; no worker closes either.

## Focused qualification

From the repository root, use the owner-assigned disk scratch root as TMPDIR:

```sh
python3 agent/task_environment.py run --task TASK --workload heavy -- \
  python3 -m unittest yamora.tests.test_binary_session -v
```

The Python stdlib client verifies a real TCP TLS server certificate and binary
ALPN. Independent frame/TLV vectors exercise the module and controlled native
callbacks. A small fixed-path filesystem callback verifies byte-exact
PUT/GET/HEAD persistence. Callback barriers prove cancellation, detached slot
and ledger retention, two-worker/two-queue limits, and shutdown waiting for
actual backend return. Slow readers retain all four response slots until send
expiry. Link wrappers force immutable SSL retry, positive short writes,
receive/send BACKPRESSURE, body-allocation failure and partial startup failures
at allocation, socket, pipe and each thread creation. Startup tests compare
descriptor counts and created/joined thread counts. Ticket balance is asserted
at teardown. A monotonic-only test clock offset advances exact production
deadline constants without modifying certificate wall-clock checks.

Three separately compiled behavioral mutants must fail their targeted tests:
a fifth job slot, early upload-credit return during executing cancellation,
and accepting oversized acknowledgement/error replies. Each must produce one
normal unittest failure containing the exact named invariant assertion for the
selected test. Compile/setup errors, unrelated or additional failures, native
signals/assertion aborts, sanitizer diagnostics and infrastructure failures
cannot count as a successful red guard. Oracle self-tests reject an actual
compiled dispatch-abort mutant and representative sanitizer/signal/error
results. The earlier loose oracle established only a failing subprocess, not
this stronger invariant-only requirement.

Red-first review cases cover transient accept survival, a retained second
REQUEST's read interest, control traffic incorrectly refreshing application
idle, and the old oracle accepting an actual harness abort. Additional probes
check bounded accept storms/resource pressure, fatal listener errors, an
unread socket's bounded poll count, worker wakeup under RX backpressure,
opposite-direction TLS write WANT_READ, retained-frame deadline/shutdown,
unsolicited PONG, and application responses legitimately refreshing idle.
Earlier red-first cases cover malformed successful GET length correlation and
accidental idle expiry of an active request.

Fatal AddressSanitizer/UndefinedBehaviorSanitizer qualification:

```sh
TMPDIR=/var/tmp/andromeda-work/yamora-binary-sessions \
  ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:abort_on_error=1 \
  UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
  BINARY_SESSION_SANITIZER=address,undefined \
  python3 -m unittest yamora.tests.test_binary_session -v
```

Unsuppressed ThreadSanitizer qualification uses the owner's existing fully
instrumented OpenSSL static libraries and headers read-only:

```sh
TMPDIR=/var/tmp/andromeda-work/yamora-binary-sessions \
  TSAN_OPTIONS=halt_on_error=1:exitcode=66 \
  BINARY_SESSION_SANITIZER=thread \
  BINARY_SESSION_OPENSSL=/var/tmp/andromeda-work/yamora-binary-storage/openssl-tsan-verification/openssl-3.6.5 \
  python3 -m unittest yamora.tests.test_binary_session -v
```

Qualification is Linux-only (`accept4`, `pipe2`, `/proc/self/fd`, pthreads and
OpenSSL), with C17 warnings treated as errors. Tests cover this owned module
and test callbacks. Actual daemon routing, production authentication,
cluster semantics, public clients and broader platform qualification remain
the parent's independent integration responsibility.
