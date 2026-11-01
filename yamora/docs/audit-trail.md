# Native audit storage and helper

`security/audit.h` supplies a bounded storage owner and
`security/audit_codec.h` its versioned codec. The separately installed native
`yamora-audit-helper` owns this sink, its private key and protected external
anchor. Its [IPC/client contract](audit-helper.md) defines distinct-UID peer
authentication, intent acknowledgement only after anchor publication, bounded
delivery and restart reconciliation. The standalone daemon's opt-in mandatory
audit dispatcher calls this helper before native dispatch and after explicit
terminal outcomes, including receipt replay and detached index jobs. Unsupported
cluster and maintenance profiles refuse startup. This supplies local protected
delivery and finite retention, without a compliance or remote immutability claim.

The caller supplies an external 32-byte secret key, a nonsecret 16-byte key label,
and immutable capacity limits. OpenSSL `EVP_MAC` HMAC with SHA256 authenticates
each fixed frame and its predecessor. The key label is not derived from the key.
The sink supplies no key discovery or key rotation. Its helper supplies local
transport, custody and bounded segment rotation, with no unprotected disk-head
fallback. Neither component deletes retained segments automatically.

## API and ownership

`yd_audit_create_at(directory, config, &owner, &head)` requires an empty, private
0700 directory owned by the effective user. It acquires an independent root OFD
using nonblocking exclusive `flock`, then creates a 0600 segment with O_EXCL.
Regular files must have one link and the expected owner. The caller may close
its borrowed directory descriptor after the call. No owned descriptor escapes.

All three constructors (`create_at`, `resume_at` and `recover_at`) require pthread cancellation
already disabled through adoption of every returned nonnull owner. Normal
creation returns OK and a synchronized GENESIS head. Any failure after the first
mutating **attempt** returns UNCERTAIN, a zero head, and a nonnull poisoned owner.
This includes an O_EXCL call that creates a file but returns -1, leaving no known
file descriptor. The owner still retains independent root exclusion until close.
The caller must adopt and close this owner even though creation failed. Earlier
failures return null and leave no new audit artifact. No failure removes files.

`yd_audit_begin(owner, event, &ticket, &head)` durably appends INTENT before
returning its process-local ticket. `yd_audit_finish(owner, &ticket, completion,
&head)` matches that exact outstanding intent and copies its saved actor,
authentication, transport and operation. It consumes the ticket on success or
uncertainty; invalid input refuses without consuming it. The caller describes
the outcome explicitly. HTTP status alone does not establish operation success,
and this storage layer does not authenticate an actor or infer database commit.

Tickets can transfer between workers in the creating process, with exclusive
use per ticket. Outstanding tickets keep no independent owner reference. The
caller must keep the owner alive and join all users before `yd_audit_close`.
Returned heads must be persisted in an independently protected anchor. The
native helper performs this step before acknowledgement. A head returned by the same untrusted files is not such an
anchor. Audit-file sync and external anchor persistence are separate operations;
the API provides no cross-system atomic transaction.

`yd_audit_rotate(owner, &head)` requires zero outstanding intents and reserves
the old SEAL and new CONTINUE before mutation. It precomputes entropy and both
encoded frames, syncs and rereads the seal, creates the exact named successor
with O_EXCL, syncs and rereads its header, syncs the directory, and validates all
bindings before publishing the successor head. A failed rotation leaves all
artifacts in place and becomes sticky UNCERTAIN after any mutating attempt.
There is no implicit rotation, retry, truncation, unlink, deletion or rewind.

`yd_audit_state` copies mutable state under the same owner mutex. Its OK return
means the copy succeeded; consult `state.health`. Health never recovers from
UNCERTAIN. Acknowledged head and capacity caches advance only after final sync,
exact reread and binding checks. Failed publication leaves their old values;
those caches are not a promise about the bytes of a poisoned owner.

All owner methods check the immutable creator PID before accessing an inherited
mutex, mutable state, or descriptor. A child cannot append, finish, rotate,
inspect mutable state, or dispose its parent's owner. Foreign close is a no-op;
forked processes must exit/exec to release their inherited descriptor copies.
Fork does not transfer writer authority. Each method masks deferred cancellation
before its mutex through publication, caller-output updates and unlock. A pending
cancel can be delivered on restoration, so caller cleanup must handle the
published ticket/state and the whole enclosing operation. Verification similarly
masks cancellation through private-handle cleanup. Asynchronous cancellation,
callback exits and nonlocal exits are unsupported. There are no user/backend
callbacks. Caller-owned key/config/event/output buffers must be disjoint and
stable for their call. Original key storage belongs to the caller; private key
copies are cleansed with OpenSSL on disposal.

## Results and failure policy

Every public operation preserves incoming errno. Output owners, heads, tickets
and state are cleared on refusal where applicable, except that `finish` retains
its input ticket for invalid input. Verification may return an authenticated
prefix report on failure, which grants no writer authority.

| Result | Meaning |
| --- | --- |
| OK (1) | Requested publication or exact anchored verification succeeded. |
| REFUSED (0) | Contract/input/anchor/immutable-limit mismatch. |
| BUSY (-1) | Independent exclusion or outstanding-intent limit/quiescence. |
| LIMIT (-2) | Record, byte, segment or sequence budget cannot be reserved. |
| UNCERTAIN (-3) | Mutating attempt or observed binding/I/O failure prevents safe continuation. |
| CORRUPT (-4) | Invalid framing, MAC, namespace or authenticated protocol history. |
| INCOMPLETE (-5) | Partial frame, outstanding intent, empty successor or unmatched final seal. |
| ERROR (-6) | Allocation/provider/entropy or prewrite infrastructure failure. |

Begin/rotation encoding, provider or entropy failure before mutation remains
retryable ERROR when bindings are intact. Finish failure after accepting a valid
ticket is conservatively UNCERTAIN and consumes it, including a provider failure
before its first write. Invalid completion input merely refuses. A namespace
binding failure poisons the live owner even if detected before its next write.
After uncertainty the caller retains exclusion, stops dispatch through this
owner, and closes only after joining users. Externally authorized investigation
is required; no API promotes observed disk history into authority.

Owner bookkeeping and frame buffers are allocated/prepared before mutation.
Both rotation frames and their entropy are ready before writing the seal.
OpenSSL provider internals can allocate during prewrite MAC processing; the API
does not promise allocator-free cryptography. No provider work follows the first
write within an append or rotation publication.

## Version 1 frame

Every frame is exactly 1024 bytes. Integer fields are unsigned little endian;
there is no native structure serialization. Kinds are GENESIS=1, INTENT=2,
FINISH=3, SEAL=4 and CONTINUE=5. Only flags bit 0 (HAS_REVISION) exists.

| Offset | Bytes | Field |
| --- | ---: | --- |
| 0 | 8 | ASCII `YDAUDR01` |
| 8 | 4 | Version, exactly 1 |
| 12 | 4 | Kind |
| 16 | 4 | Frame length, exactly 1024 |
| 20 | 4 | Flags |
| 24 | 16 | External nonsecret key label |
| 40 | 16 | Stream ID |
| 56 | 16 | Segment ID |
| 72 | 8 | Segment ordinal |
| 80 | 8 | Global sequence |
| 88 | 8 | Referenced INTENT sequence (FINISH only) |
| 96 | 32 | Previous frame MAC |
| 128 | 8 | Informational wall milliseconds; zero means unknown |
| 136 | 8 | Elapsed microseconds (FINISH only) |
| 144 | 4 | Transport |
| 148 | 4 | Authentication category |
| 152 | 4 | Operation |
| 156 | 4 | Outcome (FINISH only) |
| 160 | 4 | Status (FINISH only) |
| 164 | 4 | Actor length |
| 168 | 128 | Actor and zero padding |
| 296 | 16 | Lowercase hex revision iff HAS_REVISION; otherwise zero |
| 312 | 8 | Successor ordinal (SEAL only) |
| 320 | 16 | Successor ID (SEAL only) |
| 336 | 8 | Segment record limit (GENESIS/CONTINUE only) |
| 344 | 8 | Segment count limit (GENESIS/CONTINUE only) |
| 352 | 8 | Total physical byte limit (GENESIS/CONTINUE only) |
| 360 | 4 | Outstanding intent limit (GENESIS/CONTINUE only) |
| 364 | 4 | Subject length (access-management INTENT/FINISH only) |
| 368 | 128 | Subject and zero padding |
| 496 | 496 | Reserved, exactly zero |
| 992 | 32 | Own MAC |

MAC input is exactly 23 domain bytes (22 ASCII bytes
`YAMORA-AUDIT-RECORD-V1` followed by one NUL), followed by frame bytes 0..991.
The private key is exactly 32 bytes. EVP_MAC fetch, init, update, final and exact
32-byte output are all checked; verification uses constant-time MAC comparison.
There is no fallback algorithm. GENESIS is segment/sequence 1 with zero previous
MAC. Other frames require a nonzero previous MAC and the exact next global
sequence. Stream and segment IDs come from checked OpenSSL randomness. IDs and
key label are nonzero; segment IDs cannot repeat within a stream.

GENESIS, CONTINUE and SEAL contain no event, completion, timestamp, revision or
intent fields. INTENT contains no completion fields. FINISH must reference one
currently outstanding INTENT and repeat its exact event identity. Duplicate,
unmatched or contradictory FINISH records are corrupt even with valid MACs.
Headers persist exact immutable limits. A new segment requires the preceding
SEAL's exact ordinal and ID, with zero outstanding intents. No records follow a
SEAL in its file. Only the initial file can contain GENESIS.

Transport values are NONE=0, HTTP=1, BINARY=2, CLI=3, INTERNAL=4; event transport
cannot be NONE. Authentication values are UNKNOWN=0, ADMIN_READ=1,
ADMIN_WRITE=2, STATIC=3, CERTIFICATE=4, OIDC=5, LOCAL=6, AWS=7, LDAP=8 and
KERBEROS=9. STATIC, CERTIFICATE, OIDC, AWS, LDAP and KERBEROS carry a nonempty
actor. That actor is a mapped local
principal of 1..128 lowercase ASCII letters, digits, `_` or `-`; it is never a
credential, raw claim, token, key fingerprint or query/document content.

Operation values are NONE=0, READ_DOCUMENT=1, LIST=2, QUERY=3, AGGREGATE=4,
SEARCH=5, WRITE_DOCUMENT=6, TRANSACTION=7, INDEX_ADMIN=8,
REPLICATION_ADMIN=9, STREAM=10, TLS_RELOAD=11, STARTUP=12, SHUTDOWN=13,
ACCESS_REJECT=14, and the [runtime access](runtime-access.md) management
operations ACCESS_ROLE_PUT=15, ACCESS_ROLE_DELETE=16, ACCESS_PRINCIPAL_PUT=17,
ACCESS_PRINCIPAL_ROTATE=18 and ACCESS_PRINCIPAL_DELETE=19. Exactly those five
carry a subject: the managed role or principal name, 1..128 bytes of the same
character profile as the actor. Every other record has zero subject bytes. The
subject is never a credential, verifier or request body. Verifiers and helpers
that predate these values reject such records and packets as invalid; they never
skip them. Event operation cannot be NONE. Outcomes are NONE=0,
NOT_DISPATCHED=1, RETURNED_SUCCESS=2, RETURNED_FAILURE=3, UNKNOWN=4; FINISH
requires a nonzero outcome. Status is zero for no response, otherwise 100..599.
Wall milliseconds are zero or at most 253402300799999. Sequence/MAC order is
authoritative; wall time is not.

## Bounds, recovery and protection limits

Limits are 4..8192 records per segment, 1..16 segments, 4096..128 MiB total
physical bytes, and 1..64 pending intents, additionally at most
`floor((segment_records - 2) / 2)`. With R existing current-segment records and N
pending intents, admitting another INTENT requires room for `1 + (N+1) + 1`
additional records: itself, every promised FINISH, and the eventual SEAL. The
same reservation applies to total bytes and nonwrapping sequence space. FINISH
never needs rotation. Rotation requires two total records and a successor slot.
All headers, seals and incomplete physical bytes count toward physical budgets.

Segment names are exactly
`audit-<16 lowercase hex ordinal>-<32 lowercase hex ID>.yda`. The complete
private namespace must contain only those files. Each operation checks root
identity, mode, ownership and change times; names, inode identities, link counts,
sizes and change times must match. Appends sync/reread exactly their encoded
frame and recheck all bindings before acknowledging. Root OFD exclusion protects
cooperating owners; it is not a filesystem access-control boundary against a
process that can ignore locks or compromise the effective user.

`yd_audit_verify_at` takes independent nonblocking shared root exclusion and
rescans the bounded complete namespace, full MAC chain and semantic history.
It requires the externally protected anchor; reports can identify an intact
prefix but never produce an owner. `yd_audit_resume_at` takes a fresh independent
exclusive exclusion and repeats the scan. It succeeds only for the exact final
anchor, exact original limits and a complete quiescent final segment. Pending
intent, torn write, final seal without successor, empty successor, valid tail
ahead of the anchor and valid rollback prefix all refuse resumption. No
reconstruction, truncation or anchor rewrite occurs. A complete rotation whose
new head was never externally anchored likewise requires investigation.

`yd_audit_recover_at` is a separate restricted constructor. It repeats the full
exclusive scan and requires the exact protected final anchor and original
limits. Its only additional allowance is authenticated outstanding intents in
an otherwise complete history. It cannot repair a torn frame, an unanchored
tail or a rollback. `yd_audit_recovery_next` appends one FINISH with the saved
event identity and explicit UNKNOWN outcome, zero response status/time and no
revision. It creates no ticket and infers no database result. The caller must
publish each resulting head before another recovery step or dispatch. Begin,
normal finish and rotation refuse while reconciliation remains pending. A crash
after an unanchored recovery append requires investigation on restart; the
helper never silently adopts that tail.

The MAC detects tampering without the key. The independently protected anchor
detects rollback only to the extent it was durably persisted. This API cannot
detect deletion back to an older valid prefix when the external anchor was also
rolled back or never advanced, and cannot distinguish an attacker holding the
key from an authorized writer. It provides no global single-writer guarantee
across cloned roots, remote delivery, retention deletion or restart authority.

## Explicit qualification

The unregistered runner is `python3 -m unittest discover -s yamora/tests -p
test_security_audit.py -v`, through the current managed execution route and an
allocated native-test slot. It defaults to fatal ASAN+UBSAN including leak checks.
`YD_AUDIT_SANITIZER=thread` requires an existing, instrumented
`YD_AUDIT_OPENSSL` tree with include and libcrypto.a; no system-OpenSSL TSAN claim
or report suppression is supported. No dependency installation/build is done.

The harness includes an independent Python HMAC/full-frame vector, mutation of
every frame byte and authenticated invalid fields; exact-anchor and valid-MAC
semantic forgeries; reservations and budget refusal; partial writes, each
publication sync/binding failure and uncertain create acknowledgement; independent
process OFD probes; held-mutex fork rejection of all five owner APIs; real-I/O
pending cancellation, publication/getter/trylock checks; provider/entropy failures
and key-copy cleansing; and concurrent intent/finish histories. Compilable
refusal/mutation controls must exit normally at their named behavioral assertion
before the restored implementation passes. Compiler errors, sanitizers, timeouts
and signals are infrastructure/failures, never accepted behavioral reds. The
task's qualification receipt records actual execution; this document describes
the executable gate and does not claim an unrun PASS.
