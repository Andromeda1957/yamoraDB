# Audit helper integration contract, version 1

The native `yamora-audit-helper`, protected anchor and C client implement this
contract using the [native sink](audit-trail.md). The managed
[privilege fixture](../../docs/runbooks/yamora-audit-qualification.md) exercises
the original synthetic prerequisite, native protocol/storage and actual HTTPS
and binary daemon dispatch under different real UIDs. The daemon adapter uses
explicit native outcomes and receipt ownership; the sink alone cannot infer
database outcomes or establish compliance.

## Custody and configuration

The daemon and helper run under different nonzero Linux UIDs, with no retained
capabilities or saved privileged UID and with no-new-privileges enabled. The
trusted UID-switching parent belongs only to the managed fixture. The helper owns its
32-byte HMAC key, nonsecret 16-byte key label, native audit directory and a
separate anchor directory. All ancestors must prevent daemon replacement of
the helper's directories. Helper roots are 0700 and regular files 0600 with
one link. Constructors, opens and anchor publication reject symlinks, unexpected
owners, modes, links and namespace changes. Advisory locking supplies exclusion,
not this access-control boundary.

Only the helper reads the key or receives native sink ownership. The daemon
never receives key bytes, helper file descriptors or writable audit files.
The anchor comes from the helper's independently protected storage. Reading a
segment's newest valid MAC is not a source of anchor authority.

The paired daemon options are `--audit-socket`, an absolute local Unix
socket path, and `--audit-helper-uid`, the exact expected helper UID. Their
presence selects mandatory auditing for that daemon's data and
administrative operations; there is no best-effort mode or fallback to local
logging. The `yamora-audit-helper` executable takes the required options
`--key-file`, `--key-id` (32 lowercase hexadecimal characters, nonzero and
nonsecret), `--audit-dir`, `--anchor-dir`, `--socket`, `--daemon-uid`,
`--mode` (`create` or `resume`), `--segment-records`, `--segments`,
`--max-bytes` and `--pending` from operator-controlled startup configuration.
Every path is absolute. Limits obey `yd_audit_limits_valid`; no coercion or
implicit expansion is allowed. The helper's
UID must differ from that daemon UID. No HTTP request can set these values.
The pair is mandatory together. Audited startup refuses cluster and offline
maintenance/import/init modes that do not use this dispatcher.

Each process validates its own custody and the other's UID before the daemon
opens database storage or public listeners. Initial creation is an explicit operator-selected
mode and requires empty sink and anchor roots. Resume requires existing key,
label, limits and protected anchor; missing or contradictory state never
silently creates a new stream. A socket path is not itself authentication.
Both client and server validate the kernel `SO_PEERCRED` UID against their
configured peer. The daemon also pins its established helper incarnation.

## Fixed local exchange

Use Linux `AF_UNIX` / `SOCK_SEQPACKET`, one complete 512-byte packet per message.
The helper admits at most eight connections and at most the configured pending
intent count, never exceeding `YD_AUDIT_MAX_PENDING`. Packets use explicit
unsigned little-endian integers, not serialized C structures. Reject truncation,
extra bytes, unknown kinds, nonzero reserved bytes and invalid lengths.

| Offset | Bytes | Field |
| --- | ---: | --- |
| 0 | 8 | ASCII `YDAUIP01` |
| 8 | 4 | Version, exactly 1 |
| 12 | 4 | Kind: HELLO=1, BEGIN=2, FINISH=3, reply=4 |
| 16 | 8 | Nonzero request ID, strictly increasing on this connection |
| 24 | 4 | Meaningful payload length, at most 480 |
| 28 | 4 | Reserved zero |
| 32 | 480 | Kind-specific payload, then zero padding |

HELLO has an empty payload. A successful reply identifies a random nonzero
16-byte helper incarnation. BEGIN carries only the fields of `YDAuditEvent`:
wall milliseconds (8), transport (4), authentication (4), operation (4), actor
length (4), and 128 actor bytes with zero padding; meaningful length is 152.
A [runtime access](runtime-access.md) management event adds subject length (4)
and 128 subject bytes with zero padding, for a meaningful length of 284; every
other BEGIN keeps 152, so a helper that predates management events rejects
them. No token, verifier, certificate fingerprint, raw claim, URL,
collection/document name, query, YAML, patch, body or sensitive field value is
permitted.

FINISH carries a helper-issued opaque 16-byte intent handle, wall milliseconds
(8), elapsed microseconds (8), outcome (4), status (4), HAS_REVISION (4), and
16 revision bytes; meaningful length is 60. The remaining packet is zero.
The native ticket and its creating-process identity stay inside the helper.
The handle binds exactly one pending ticket, helper incarnation and connection;
another connection, a restarted helper, duplicate use or an invented handle
cannot finish it. A native finish refusal preserves the ticket according to
the sink contract; uncertainty consumes it and poisons dispatch.

Reply payload is 52 bytes: result (4), echoed request kind (4), helper
incarnation (16), intent handle (16, zero except a successful BEGIN), native
intent sequence (8, zero without a successful BEGIN), and reserved zero (4).
Results are ACK=0, REFUSED=1, BUSY=2, LIMIT=3, UNCERTAIN=4, ERROR=5. Native
negative results never become ACK. The handle is process-local protocol state,
not a bearer credential or a reusable write receipt. The reply does not grant
the daemon anchor publication or recovery authority.

Every exchange is bounded by the smaller of the original operation deadline
and 2,000 milliseconds. Failure or timeout grants no dispatch permission.
Unknown peers are denied before application parsing. At most one bounded packet
may be drained without interpretation to avoid discarding a denial through an
unread-request connection reset. A slow peer cannot monopolize the helper.
Never log supplied packets or secret material as diagnostics.

## Admission and outcome order

The standalone daemon copies security identity and constructs events at the
shared dispatch boundary. Unsupported cluster and maintenance modes refuse
audited startup; they do not inherit an audit claim. Internal or detached work
within the supported profile retains its original admitted operation.

1. Authenticate exactly one credential using existing terminal bearer/certificate
   selection and map it to current local authority. Copy the mapped local name
   and authentication category into owned job state. Never retain a principal
   pointer or connection identity beyond its documented lifetime.
2. Authorize the entire operation, including transaction members, lookup inputs
   and receipt replay. Construct a bounded event with a native operation enum.
   Rejections use ACCESS_REJECT and do not acquire data authority.
3. Request BEGIN. The helper calls `yd_audit_begin`, then durably publishes the
   returned head in its protected anchor. Only ACK after both publications
   permits database dispatch, receipt lookup/replay, background-job submission
   or the first private response/stream bytes.
4. Execute the admitted operation. A detached job owns its handle until its
   terminal outcome; a reused session cannot inherit it. A stream remains
   outstanding for its entire admitted lifetime. When capacity is exhausted,
   reject a new operation before dispatch; never evict an outstanding intent.
5. Request FINISH with an explicit outcome. The helper calls `yd_audit_finish`,
   durably publishes its returned head, and acknowledges only then. A completed
   response may be sent after ACK. Stream completion is recorded after the
   actual terminal result; an interrupted or unprovable result is UNKNOWN.

| Outcome | Required evidence |
| --- | --- |
| NOT_DISPATCHED | The admitted operation provably never entered its operation handler. |
| RETURNED_SUCCESS | The handler established its operation's success, including an actual durable commit when required. |
| RETURNED_FAILURE | The handler established failure without an unknown commit outcome. |
| UNKNOWN | Crash, cancellation, lost acknowledgement or another uncertainty prevents either conclusion. |

HTTP status alone cannot establish an outcome. Zero status means no response;
otherwise it is 100..599. A committed write whose audit finish fails cannot be
reported as an uncommitted write: return an uncertain-write failure and preserve
its original write ID for authenticated retry. Audit failure never rolls back
an already committed database operation. The liveness-only health endpoint may
remain available without exposing data or granting operation authority.

Startup owns an anchored intent before opening native storage. Its success
completion follows worker and HTTP/binary listener construction. Binary data
admission stays closed until that completion is acknowledged; a construction
failure records failure instead. A failed completion closes listeners and joins
their users without rewriting uncertainty as a second outcome. Shutdown follows
worker and detached-job cleanup. SIGHUP TLS replacement is audited separately.

Receipt replay authenticates and obtains a fresh BEGIN before reading the
stored result. A detached index job retains its original intent after its
submitting connection closes and finishes only at the native terminal outcome.
Audit unavailability refuses new dispatch with 503. A FINISH failure after
dispatch returns a fixed uncertainty response and never silently retries.

## Anchor publication and restart

The helper publishes exactly 128 bytes in `anchor-v1.yda`, explicitly encoded
from the exact `YDAuditHead` returned by the sink. Integers are little endian.
Reject another size, zero identifier/MAC, zero ordinal/sequence, nonzero reserved
bytes or an unsupported version; never serialize a native C structure.

| Offset | Bytes | Field |
| --- | ---: | --- |
| 0 | 8 | ASCII `YDAUAN01` |
| 8 | 4 | Version, exactly 1 |
| 12 | 4 | Length, exactly 128 |
| 16 | 16 | Nonsecret key label |
| 32 | 16 | Stream ID |
| 48 | 16 | Segment ID |
| 64 | 8 | Segment ordinal |
| 72 | 8 | Global sequence |
| 80 | 32 | Exact frame MAC |
| 112 | 16 | Reserved zero |

The protected anchor directory contains only that final file in a resumable
state. Publication uses a random, noncolliding `anchor-next-<32 hex>.tmp` name;
leftover temporary or unknown files refuse restart and remain preserved.
Use a new private file with O_EXCL, complete write and file sync, atomic rename,
directory sync and exact reread/binding validation before acknowledgement.
Sync newly created ancestor entries before the initial acknowledgement.

Only complete exact-anchor rescan success grants an owner.
Normal `yd_audit_resume_at` refuses pending intents, torn tails, unanchored valid tails,
rollback prefixes and incomplete rotations. These refusals remain failures;
no code may truncate, promote an observed head or silently select an older
anchor. A read-only verified prefix is diagnostic evidence, not restart power.

On an ordinary peer disconnect while the helper is still healthy, the helper
finishes its owned live tickets as UNKNOWN and anchors those outcomes. On restart,
`yd_audit_recover_at` acquires independent exclusive ownership and rescans a
complete history ending at the exact protected anchor. Pending intents are its
only additional admissible state. Normal BEGIN, FINISH and rotation remain
blocked while recovery is pending. `yd_audit_recovery_next` appends at most one
UNKNOWN outcome using the intent's authenticated actor/authentication/operation;
it exposes no adoptable ticket and cannot manufacture success, revision or status.
The helper publishes each resulting head before taking the next recovery step
and opens its listener only after reconciliation completes. An interrupted
reconciliation can resume from the last exactly published anchor; a tail ahead
of that anchor still refuses. No history is truncated or promoted by observation.

The C client constructor, like native sink constructors, requires cancellation
already disabled through adoption by its caller. BEGIN/FINISH serialize with an
absolute monotonic deadline that includes mutex acquisition and is capped at two
seconds from call entry. Close masks cancellation through disposal. Foreign PID
operations refuse before inspecting inherited mutable state. Unauthenticated
connections must send HELLO within two seconds. Authenticated sessions remain
open across idle periods and detached work; each packet is handled without a
blocking partial-message read. The connection and pending-intent limits bound
trusted-daemon resource consumption.

Any post-mutation audit or anchor error is sticky uncertainty for the helper
incarnation. Stop new admission, preserve every artifact and pending outcome,
and require independently authorized investigation. Rotation uses the existing
quiescent native API and must publish the successor's exact anchor before
resuming. There is no automatic retention deletion. Filling the immutable
physical capacity denies new dispatch; it never authorizes log removal.

## Required integration proof

Before advertising daemon auditing, exercise actual HTTPS, binary and replica
daemons with successful controls before denial cases. Verify identity before
receipt replay, detached/session reuse, stream and replication coverage, full
capacity, malformed IPC, helper loss, lost replies, each audit/anchor publication
fault and anchored restart. Preserve exact authored YAML and native storage.
Run normal and fatal sanitizer native gates and controls that remove each
guard, then restore the passing implementation. The current managed fixture
alone supplies none of those daemon results.

This boundary protects against the configured unprivileged daemon UID. It does
not protect against the helper UID, its trusted launcher, host administration,
offline rollback of both protected volumes, or an attacker controlling the
kernel. Local durable anchors and authenticated records do not establish
remote immutable delivery, production retention, encryption at rest or any
compliance framework.
