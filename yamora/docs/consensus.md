# Native consensus implementation

The Raft core, bounded peer RPC, election scheduler, worker runtime, atomic
document application and fresh-majority read barriers are connected to the
daemon through an [experimental static replica-set profile](replica-sets.md).
Verified snapshots, authenticated installation and peer catch-up from persisted
checkpoints and opt-in background checkpoint policy are implemented; physical
reclamation, membership changes and sustained
operational testing remain required before claiming production high availability.

The algorithm follows the [original Raft paper](https://raft.github.io/raft.pdf),
particularly its state transitions, election restriction and current-term
commit rule. Implementation stages are:

1. Persistent term, vote and contiguous command log, with deterministic election,
   append, restart, partition, reordering and durability-failure tests.
2. Authenticated bounded peer transport, independent election/heartbeat scheduling
   and static replica-set configuration.
3. Serialized committed-command application, atomically stored applied positions,
   quorum-confirmed reads, uncertain-response recovery and client leader discovery.
4. Snapshot transfer, log reclamation, membership changes and sustained fault/load
   verification before claiming operational high availability.

The core uses a separate native paged journal root, with Yamora's own checksummed
records, copy-on-write trees, filesystem synchronization and superblocks. It
does not introduce another storage engine. Journal identity includes the cluster,
node and fixed voter count; mismatched configuration is rejected. Calls must be
serialized by the integrating event loop. No timer, network or application code
runs inside the deterministic state machine.

Initial voters are numbered 1 through the configured odd count, 3–9. A node
persists its new term and vote before sending/granting votes, and persists log
entries before acknowledging them. Duplicate votes cannot form a majority.
Leaders append a current-term no-op after election. They advance commitment only
using distinct voter matches on a current-term entry; followers cannot overwrite
their committed prefix. Delayed append responses must match the current request
context before changing replication progress. Higher terms cause a durable
step-down, including when carried by delayed responses.

Persistent commit positions survive restart. Runtime persistence failures fence
the core until close/reopen, including failures where local publication is
uncertain. Application progress will belong in the document transaction itself;
a journal position alone is not proof that document effects were applied.

Entries are loaded individually with a bounded command size. Replacing an
uncommitted suffix moves the logical tail and overwrites its first conflicting
entry atomically; unreachable older tail records remain for later reclamation.
Native page retention and the separate-root compaction constraints still apply.
This journal does not expose a document API or a public cluster endpoint.

The journal namespace is private to this root: `NUL YRM` stores metadata;
`NUL YRE` plus a big-endian 64-bit index stores an entry record offset; and
`NUL YRT` plus the same index stores its term. Initial metadata uses the `YDRMETA1`
64-byte little-endian encoding, including reserved zero fields; snapshot and
application-generation extensions are described below. Each `YDRLOG01`
entry has a 40-byte header followed by an opaque command, with the native outer
record checksum. Commands are bounded at 64 MiB minus that header. Recovery
streams the live keys and checks continuity, term ordering and record checksums
without retaining the entire log in memory. Checkpoints can remove logical
prefix keys; old physical pages remain until separate compaction. Startup work
includes the live journal suffix and verification of its selected archive.

The sanitizer harness covers election and distinct-voter rules, an isolated old
leader, partition repair, restart after suffix truncation, reordered and duplicate
RPC responses, current-term commitment, immutable committed prefixes, both fsync
failure positions and all six native publication kill boundaries. Three fixed
randomized schedules deliver, duplicate and reorder messages across five nodes,
restart them, compare every observed committed prefix, and require convergence
after reconnection. Additional cases exercise the maximum command, malformed
messages, same-term payload collisions, missing log/term keys, checksummed invalid
records and damaged record checksums. These bounded tests establish development
evidence; operational failover and application consistency remain unverified.

## Authenticated peer RPC

`rpc.c` provides one request/response exchange on an already accepted or connected
descriptor. It does not open a listener, select destinations, schedule elections,
retry failed calls or expose a daemon route. The integrating owner must bound
connection concurrency, connect time, and serialize core access in its dispatch
callback. The callback must complete native durability before returning a reply.
An append acknowledgement confirms local journal persistence, not quorum commitment
or application to the document database. Lost replies remain uncertain outcomes.

This profile requires system OpenSSL 3, TLS 1.3, a dedicated mutual-trust CA and
the mandatory ALPN name `yamora-raft/1`. HTTP credentials and HTTP ALPN do not
grant peer access. Each configured voter has a distinct lowercase DNS name,
matched against its certificate's DNS subjectAltName. Wildcards and subject CN
fallback are disabled. Issued peer certificates need both clientAuth and serverAuth;
the cluster CA must not issue overlapping node names to unrelated identities.
The outbound handshake verifies the configured destination name; inbound frames
bind their sender ID to the configured name after trust verification and before
command allocation. The shared TLS loader owns copies of its file paths and
retains its existing atomic context replacement behavior.

Frames use a 128-byte `YDRPC001` header with explicit little-endian integers;
they never serialize a native C struct. Byte 8 selects vote, vote reply, append
or append reply (1–4), or the snapshot phases below; bytes 9 and 10 identify sender and destination, byte 11
is the message flag, and bytes 16–31 hold the cluster identity. Eight-byte fields
at 32 and 40 hold term and RPC context. Offsets 48–72 hold message-specific log
positions, 80 holds payload size, 88 holds entry kind, and 96/104 hold entry
index/term. Other bytes are reserved zero for messages 1–4. An append entry carries opaque
payload bytes after the header. Vote replies echo the request term at 48;
append replies echo the request RPC at 40. Reply endpoint and request context
must match. This internal protocol remains under development.

Snapshot begin/begun, chunk/chunked and finish/finished use kinds 5–10. Their
header shares the cluster/endpoints, with leader/current term at 32, request ID
at 40, base index/term at 48/56, image-byte offset at 64, payload length at 72,
manifest SHA-256 at 80–111 and transfer session at 112–127. Bytes 12–15 remain
zero. Begin carries exactly 256 manifest bytes and no session or offset; a
receiver assigns a nonzero random 16-byte session. Each chunk carries 1 byte to
1 MiB, with checked signed-file offset arithmetic. Finish has no payload and
names the completed image end. The transfer layer must still validate the
manifest/hash, image size, sequential chunk progress and durable installation.

Replies carry no payload. Flag bit 0 accepts protocol progress; bit 1 separately
confirms application installation. A chunk reply can never set bit 1. A begin
reply can report an already installed prefix without allocating a session;
an accepted ongoing begin returns its session and received offset. Finish can
report pending installation separately from its final result. Negative replies
carry zero progress and may report a newer current term. Every reply binds the
phase, endpoints, cluster, request ID and exact archive boundary/hash. Accepted
replies retain the request's leader term; chunk/finish replies also bind the
session and valid progress. These checks grant no quorum or matched-log credit.

The existing mutual-TLS RPC layer authenticates sender identity and validates
these headers before reserving bounded payload bytes. Snapshot buffers share
its service-wide admission budget and absolute I/O deadline. Ordinary core
runtimes reject snapshot phases; the recovered controller registers the receiver
described below. Outbound transfer and automatic retention remain pending. Synthetic
transport fixtures acknowledge only byte progress and change no Raft state.
Fifteen RPC cases pass ASAN/UBSAN and instrumented OpenSSL TSAN, including all
legacy cases, canonical single-bit mutations, phase/session/term correlation,
full-sized chunks, authentication before allocation, budget rejection and
partial-payload release. Flag/correlation bypasses fail their assertions.

Header validation checks type, endpoint, cluster, reserved fields, log shape and
the native command bound before allocation. Received commands share an atomic
service-wide byte budget, at most 64 MiB; saturation rejects a new command while
zero-payload control requests remain admissible. The budget counts transport
command buffers, separately from TLS, page cache and core persistence buffers.
One absolute timeout (1–30,000 ms) covers handshake, header, payload and response;
partial frames release their reservation without dispatch. A slow storage callback
can outlast this timeout, so its completion remains uncertain to the caller.
The library logs no certificates, credentials or command payloads.

Native sanitizer tests exercise real TCP mutual TLS, both native endpoints,
wrong server names, missing/foreign/expired/inappropriate certificates, node-ID
impersonation, wildcard/CN denial, absent or HTTP ALPN, malformed/foreign frames,
budget exhaustion, slow headers and partial payloads. A 3 MiB command containing
NUL and non-UTF-8 bytes is read back exactly from the native journal.

## Bounded incoming transfer sessions

The private `consensus/snapshot_receive.h` module stages one incoming session
under an owned trusted archive directory. Its integrating caller must authenticate
the configured peer first. A valid begin binds the decoded manifest, trusted
cluster/voters, exact offered index/term and manifest SHA-256 before invoking
leader-contact hooks. The module assigns a random nonzero session; repeated
begins for the same offer return that session and received offset. Its directory
descriptor remains pinned after the caller closes or renames the original path.

Chunks must match the exact peer, leader term, archive boundary/hash and session.
They cannot skip bytes, straddle the received prefix or exceed the declared image
end. A fully repeated earlier chunk reports current progress without feeding the
verifier twice. Invalid sessions, manifests, premature finish requests and bad
offsets do not renew leader contact. Valid contacts use the controller's scheduler
and require the exact current leader term; received bytes grant no matched-log or
quorum credit. Memory remains bounded by per-request transport chunks and the
archive verifier rather than complete images.

Finish requires every image byte, complete physical verification and durable
archive publication. It hands off one session-bound installation job and replies
with pending progress. Duplicate finish requests do not create another job. The
integrating owner queues this job outside the receiver call, validates the native
graph, selects the live generation in a background operation, and completes the
job on every outcome. An uncertain archive publication creates no job and retains
any completed artifact for retry. No native graph or application is selected by
the receiver itself.

Job completion consumes only its exact outstanding session and offer. Reporting
success still requires a serialized controller confirmation of the current
leader/term and the applied durable committed prefix. Final replies recheck that
confirmation, including already committed begin requests; commit metadata alone
cannot acknowledge an unapplied application. A higher-term begin can renew the
new authority while old work remains pending, but receives no new job until the
old one finishes. Stale completion cannot acknowledge a superseded session.
False or unconfirmed completion requires a new session, preserving archives.
The module serializes its state and callbacks internally; its owner joins all
callers/jobs before close. Callbacks cannot reenter the receiver.

Ten native cases cover exact YAML/receipt restoration with a 2 MiB source,
renamed/pinned directories, resumed offsets and repeated chunks, invalid offers
and sessions without timer contact, corrupt image retry, one outstanding job,
false/unconfirmed completion, committed-but-unapplied state, higher terms,
concurrent begins, receiver restart and uncertain publication after a complete
archive exists. ASAN/UBSAN and instrumented cryptography TSAN cover these paths.
Bypassing physical publication, session binding, application confirmation or
duplicate-chunk handling fails the corresponding assertions. The module is
linked into the daemon. Its live controller integration is described next;
outbound catch-up is connected through the runtime described below. Automatic
checkpoint/retention policy remains disabled by default.

`consensus/cluster_receive.c` owns the live integration. After recovery and
application-worker construction, the controller registers one authenticated
runtime callback. The runtime releases its lock before invoking that callback,
preserving the controller-to-runtime lock order. The receiver/store is lazy;
ordinary startup creates neither an archive directory nor an additional thread.
A valid first manifest opens the directory through the pinned owned journal.
The background installer starts when the first completed archive needs a job.
Queue/thread-creation failure rejects the finish, completes that job as failed
and keeps its published archive for a new-session retry.

The job runs the existing durable candidate construction, graph validation,
generation selection and constant-time pointer publication outside receiver
serialization. Pending finish polls can renew authenticated leader contact while
that work proceeds; they cannot acknowledge installation. Confirmation inspects
the active application under controller ownership and requires its applied
position through the committed boundary in the exact follower leader/term.
`yd_raft_cluster_snapshot_job` gives background work a separate policy. Its
timeout bounds initial admission and a fresh final wait for prepared writes;
the receiver uses 30 seconds for each. Image verification/copy does not expire
merely because it exceeds that budget. At progress boundaries, it checks the
exact current follower leader/term and still-advancing boundary under controller
ownership, and stops on shutdown or superseding authority/committed progress.
The final publication repeats those checks. Native graph and prefix scans remain
complete operations and may finish before cancellation is observed. The existing
bounded `yd_raft_cluster_snapshot_install` API retains its original shared
admission/I/O deadline for controlled synchronous callers.

Shutdown first marks the controller unavailable and wakes its application waiters,
then stops/joins the installer while runtime callbacks remain alive. The incoming
object remains allocated until runtime shutdown joins every inbound callback;
only then are the receiver, synchronization state and application freed. External
callers still join before controller close, and returned owned views/captures
retain their independent lifetimes.

Real mutual-TLS cases hold an installer pending beyond the election timeout while
finish polls retain follower authority without changing the application, then
install and reopen the selected generation. A new begin after restart can confirm
the already applied prefix without retransmission. Other cases reject corrupt
images before jobs, retry retained archives after worker-creation failure, join
a held job on shutdown and require a fresh session after restart. A paused
application worker proves that committed journal metadata cannot acknowledge an
unapplied prefix; release permits the already installed response. Removing live
dispatch or the applied-position guard fails these behavioral checks. The source
side in these receiver-specific tests uses a trusted test client. Separate live
outbound tests below verify actual runtime scheduling and installed progress;
automatic checkpointing is opt-in and physical reclamation remains disabled.

Three additional actual mutual-TLS cases inject image I/O beyond a short
admission budget while finish polls renew authority, change the leader term
during that I/O and require cancellation before candidate-directory creation,
and stop the controller during image work before retrying after restart. The
elapsed-I/O regression fails with the earlier shared deadline and passes with the
background policy. Removing its progress authority guard creates an unwanted
candidate and fails the corresponding assertion. ASAN/UBSAN, instrumented TLS
TSAN and all 22 legacy generation/installation cases pass.

## Election and heartbeat scheduling

`member.c` integrates the deterministic core with an injected monotonic clock and
a bounded asynchronous emission callback. It does not create threads or open
sockets. The caller serializes ticks, inbound dispatch, proposals and completed
RPCs, and supplies an independently randomized nonzero seed at process startup.
The scheduler randomizes each election deadline and retries votes while a
campaign remains current. Current-term leader traffic and granted votes reset
election timeouts; stale requests do not. A newly elected leader sends its
durable no-op, and new proposals trigger replication on the next tick.

Each peer has one outstanding request until completion or its deadline. This
preserves the core's current RPC context while a slow response is still live;
otherwise new heartbeats could repeatedly invalidate responses before they
arrive. Delayed responses remain subject to the core's term/context checks.
Rejected emissions free their command allocation; accepted emissions transfer
ownership to the caller's bounded queue, which must eventually free it even
when shutting down or dropping a request. The emitter must not block or reenter
the core. Transport admission remains a separate runtime responsibility.

Heartbeat intervals are 50–1,000 ms. Election minima must be at least five
heartbeats; maxima must exceed minima by at least one heartbeat and remain
within 30 seconds. RPC deadlines are positive and at most half the election
minimum. Bounds are checked before addition; clock reversal and deadline
overflow are rejected. These limits support tuning, not a measured failover
latency guarantee. Sanitizer simulations verify stable leadership, majority
election during partition, repair after reconnection, in-flight context retention,
timeout retry, stale-traffic rejection and configuration/clock bounds. Database
application and daemon integration are described below; operational
qualification remains pending.

## Live peer runtime

`runtime.c` connects the core, scheduler and peer RPC with one outbound worker per
remote voter, four inbound workers and a timer thread. One mutex serializes core
and scheduler access; network I/O runs outside it. The runtime seeds election
jitter from system OpenSSL randomness. Its static programmatic configuration
binds every voter to a distinct literal private or loopback endpoint and an exact
certificate name. IPv4 RFC 1918/loopback and IPv6 ULA/loopback are accepted;
DNS resolution, public/link-local/multicast/unspecified targets, duplicate
endpoints and a listener that differs from the local configuration are rejected.
The caller supplies and owns an already listening descriptor and the TLS profile.
It must retain both until stopping the runtime has joined every worker.

Outbound requests share a command-buffer budget of at most 64 MiB, separately
from the incoming RPC budget. Each peer has at most one queued or active request;
queue rejection releases the prepared log allocation. Connect, handshake and RPC
I/O consume the same deadline. Owned network threads block SIGPIPE locally,
without changing the hosting application's signal policy. Persistence failures
stop participation. Shutdown drains or frees every owned packet and joins all
threads before closing the journal; bounded I/O deadlines limit this drain.
Storage synchronization can still outlast a network deadline.

The runtime's proposal API acknowledges only local journal acceptance. Its entry
API returns committed entries for the application worker; document access goes
through the cluster controller and daemon described below. Startup still
verifies the complete journal; recovered controller runtimes support snapshot
catch-up from persisted archives. Background checkpointing is opt-in; physical
reclamation remains disabled.
Three-process sanitizer tests use real TCP and independent native journals. They
verify majority election after SIGKILL, durable log catch-up on restart, refusal
to expose an isolated leader's uncommitted entry, repair of that tail after a new
majority commits, graceful shutdown, and invalid endpoint/listener rejection.
The same three cases pass with both Yamora and OpenSSL 3.6.5 instrumented by
ThreadSanitizer, without suppressions. The instrumented crypto build requires
the harness's slower 2-second RPC / 5–8-second election profile; its ordinary
250-ms RPC / 600–1,100-ms election profile passes under AddressSanitizer and
UndefinedBehaviorSanitizer. These are test profiles, not failover latency claims.
A partial-instrumentation run against the system OpenSSL reports an ASN.1 cache
race similar to the [upstream report](https://github.com/python/cpython/issues/150191);
the fully instrumented run gives visibility into the library's synchronization.

## Atomic document application

`application.c` supplies serialized preparation and committed-command application
for document PUT/PATCH/DELETE, transactions and synchronous index catalogs. It
uses the existing native API validators and source patcher. Preparation holds an
exclusive native transaction long enough to calculate the expected response,
then aborts that unpublished candidate. The resulting bounded opaque command
contains the exact request, its SHA-256 digest, base applied position/revision,
and expected successful response. Followers repeat validation and require an
identical response before publication; allocation failures or divergence stop
application instead of recording a different outcome. The integrating leader
must serialize one proposal through application and verify its captured term
before proposing it. This module alone does not establish leadership or quorum.

A committed entry publishes document/index effects, a durable request receipt,
and the applied index/term in the same native transaction. Receipts use nonzero
16-byte client request IDs and exact request digests. Reusing an ID for different
bytes is rejected. Retrying a committed increment or delete returns the original
response without applying it again, including after restart or at a later log
position. No-op and duplicate entries advance application without changing user
data. Replaying the latest exact entry is also safe; mismatched, noncontiguous,
or malformed committed entries fence the application object until recovery.
Receipts are currently retained indefinitely; request and journal reclamation
need a coordinated retention contract before this profile is operational.

Cluster document roots use dedicated native format 6 (`YAMDIS06`). Only empty
roots can be initialized; existing format 3–5 roots and authored YAML are never
converted in place. Ordinary read/write opens reject the cluster profile, and
both superblock slots become format 6 during initial checkpoint publication, so
older format-5 writers cannot silently reopen a stale standalone generation.
The journal remains a separate format-5 root. The private document namespaces
are `NUL YRA` for the 96-byte `YDAPLY01` checkpoint and `NUL YRR` plus request ID
for `YDRCPT01` receipts. Checkpoints bind cluster identity, applied index/term,
source revision and a SHA-256 digest of the last applied journal entry. Startup
requires the checkpoint and generation to agree.

Every applied entry produces one native change-feed frame, including empty
frames for no-ops and duplicates. The cluster identity seeds the feed identity;
identically applied replicas therefore produce the same tokens and history.
Index-catalog publication retains its existing resnapshot marker behavior.
Writes through ordinary APIs cannot publish a cluster feed without its explicit
identity. This establishes token consistency in application tests; serving
cluster reads and streams still requires daemon integration and quorum checks.

Sanitizer tests cover three independently applied document roots, byte-exact
CRLF/comments, transactions, unique indexes, duplicate increments, delete/recreate
retries, shared feed responses, restart and standalone-writer rejection. All six
publication kill boundaries and both fsync failures exercise a non-idempotent
increment, checking that its effects, receipt and applied position recover
together. An intentionally split-publication test build must fail those recovery
checks. Malformed and divergent command tests verify failure without publication.
A 3 MiB source round trip and checksummed corrupt checkpoint/receipt cases also
pass. Online index jobs, bulk restores and pull-replica mutation routes are outside
this application profile until they can participate in consensus.

## Fresh-majority read barriers

`read.c` tracks a monotonic sequence for each accepted outbound queue request.
A read captures the current leader term and sequence boundary. Successful append
responses count only when their matching request was queued after that boundary,
with the same term, cluster, sender/destination, RPC context and matched position.
Each voter counts once. Delayed replies to older requests and duplicated replies
cannot validate a new read. The core also requires a committed entry from the
current term, which establishes that the leader knows the complete committed
prefix. This follows the read precautions in section 8 of the
[Raft paper](https://raft.github.io/raft.pdf).

`yd_raft_runtime_barrier` waits within a monotonic 1–30,000-ms deadline for this
proof, returning a term and committed index. Term changes, lost majority, stop,
sequence exhaustion or deadline expiry cannot produce a successful proof. It
does not append a log entry for each read and uses no clock lease. The caller
must still wait for atomic document application through the returned index
before taking a query view. A proof is specific to that read invocation and must
not be cached for future reads. Slow storage calls may outlast an I/O deadline;
expiry after such calls rejects the result.

Prepared writes can use `yd_raft_runtime_propose_at`, which atomically checks
the captured leader term and exact log base before appending. It rejects
intervening appends and leadership changes. Local acceptance still does not
acknowledge a database write; quorum commitment and durable application are
required first.

Three- and five-voter sanitizer tests deliver old replies after invocation,
duplicate votes, malformed contexts and fresh replies without current-term
commitment, then verify valid proofs and term-change rejection. A disposable
build that allows older heartbeat responses fails both scenarios; the restored
implementation passes. Live three-process tests verify an isolated old leader
cannot pass a fresh read, a replacement leader can, and stale term/base proposals
publish nothing. Normal ASAN/UBSAN and fully instrumented OpenSSL TSAN profiles
pass. The daemon uses these barriers for each cluster document read and write.

## Live document controller

`cluster.c` owns the peer runtime and atomic application worker. Journal and
document roots must be distinct pre-existing directories; alias roots are
rejected before initialization. Startup verifies the document checkpoint against
the committed journal entry and refuses a document database that is ahead of,
or inconsistent with, its journal before creating any peer worker. The private
runtime recovery callback runs once with the already-open journal exclusively
owned, before constructing the member or starting outbound, inbound or timer
threads. The controller checks the applied position against commitment and
replays the latest exact entry to verify its term and digest. The same core stays
owned through worker creation; failed recovery releases it without participation.
Checkpointed journals require the archive-bound recovery checks described below.
Committed entries are applied in order by
one worker. Runtime waits wake on commitment, and application progress wakes
waiting clients. Application invariant or durability failures fence peer
participation and client operations until recovery.

Eight native startup cases cover an application ahead of commitment, a different
valid history at the same index, a term mismatch, matching/lagging/empty roots,
exclusive ownership during recovery and partial worker-creation failures. The
three mismatched-root cases each reproduced seven premature peer threads before
the check moved; they now start zero workers. ASAN/UBSAN and fully instrumented
OpenSSL TSAN exercise cleanup and subsequent journal reopen.

Document writes serialize preparation and use one monotonic 1–30,000-ms budget
across queue admission, fresh quorum confirmation, catch-up and application.
Before preparing another command the controller waits for the preceding log
tail to apply. It then appends with the captured term and exact applied base.
A successful response comes from the durable request receipt after commitment
and application. Local journal acceptance never becomes a successful document
response. A timeout after acceptance is uncertain: clients must retry the same
request ID and exact bytes. Reads obtain a fresh majority proof and wait for
application through its index before taking an immutable query view. Raw local
views and status are not substitutes for that read procedure.

Read waiters trigger immediate leader probes instead of always waiting for the
normal heartbeat interval. Outstanding RPC contexts and deadlines remain intact;
a probe cannot replace an in-flight request. Per-peer queues and shared byte
budgets retain their existing bounds. Shutdown joins the application worker,
then all runtime workers before closing either root. Integrating servers must
first join their external request callers; the listener and TLS remain borrowed.

Five live three-process tests cover 20 increments from four concurrent native
clients, exact source replication, leader SIGKILL after committing an increment
but before its reply, retry on the replacement without a second increment,
restart/catch-up, denial of reads and new writes to an isolated former leader,
aliased roots, an application ahead of its journal, and corrupt retry receipts.
All five pass under ASAN/UBSAN and with both Yamora and OpenSSL instrumented by
ThreadSanitizer. Omitting the application-to-peer fence in a disposable build
fails the corruption test; the restored implementation passes. Four deterministic
scheduler tests also verify immediate probes while preserving live contexts.
The concurrent test uses a 30-second outer harness response window for a batch
of 20 separately bounded requests; this is not a production latency benchmark.
The daemon now exposes the controller with strict private configuration,
authenticated leader/status discovery and mandatory durable write IDs. See
[replica-sets.md](replica-sets.md) for its initial restrictions and HTTP tests.
Python and Go driver discovery and exact-ID retries are connected to this
profile. Snapshot artifacts and verification are available below; operational
peer installation remains a subsequent stage.

## Immutable checkpoint streaming foundation

`yd_disk_checkpoint_open` captures one complete native generation under the root
mutex and owns a duplicate file descriptor plus one canonical superblock. Capture
returns unavailable while any transaction is unfinished, including staging or
optimistic preparations: their private reservations can lie below a later
committed end and flush afterward. Retry capture at a transaction boundary. New
writes can proceed normally after a handle is captured. Reads use caller-provided
buffers of at most 1 MiB, with no per-read allocation or writer lock. Both exported
superblocks describe the captured generation rather
than the live file's changing publication slots. The remaining immutable file
prefix ends at the captured view's `end`; later appends are excluded.

Handles support concurrent reads and can outlive the source disk object. Their
descriptor retains its file lock until checkpoint close; callers must join all
readers before closing a checkpoint. This relies on the append-only CoW page
policy. Future reclamation must preserve captured file generations and existing
immutable views. The primitive supports native formats 3–6 and rejects older
format 2 rather than changing it.

The image includes the entire native root: exact YAML, indexes, change history,
applied position and durable retry receipts in format 6. It also includes
unreachable historical pages. This is a physical export primitive, with no
journal trimming or automatic peer installation yet. The artifact layer below
binds its contents to an application position. Operational snapshots still need
verified staging, durable publication and Raft snapshot-installation rules before
any committed prefix can be discarded.

Six native cases verify bounds and empty roots, source-handle lifetime/locks,
concurrent publications with 3 MiB records, complete consensus application
restoration, late private-page reservations, and truncated-source rejection.
The staging interleaving fails before the transaction-boundary guard.
The restoration test advances both live superblocks after capture; a disposable implementation using those live
headers fails instead of opening the intended checkpoint.


## Bound snapshot artifacts

`consensus/snapshot.c` builds a sealed artifact from an application checkpoint.
Capture is serialized with the application's owner so cluster identity, applied
index/term, last-entry digest and native root describe the same publication.
The handle retains no live application pointer. SHA-256 sealing runs outside that
serialization lock, using a 1 MiB buffer and an optional progress/cancellation
callback. A cancelled hash can retry; no manifest or stream is available until
sealing succeeds. Sealed manifests and image chunks can be read concurrently.

The fixed 256-byte `YDRSNAP1` manifest records the cluster identity, static voter
count, native format 6 view, applied index/term, last-entry digest and whole-image
SHA-256. Integers use explicit little-endian encoding, reserved bytes are zero,
and CRC32C protects the complete manifest prefix. Decoding requires the trusted
runtime's expected cluster identity and voter count, valid root/size bounds, and
an applied index consistent with native generation. It accepts the initial empty
application at index/term zero. This does not add membership changes.

The receiver verifier accepts contiguous chunks starting at byte zero, each at
most 1 MiB. It checks both normalized superblocks against the manifest and hashes
every image byte. Gaps, duplicate offsets, excess bytes, altered headers,
truncation and content-digest mismatches permanently reject that verification
state. Finish is single-use, and the caller frees the state on every outcome.
The primitive neither writes staging files nor modifies Raft state. Installation
must still validate the native application, prove the appropriate committed
prefix, durably publish staging, and reconcile journal progress before serving.
No artifact alone authorizes journal trimming or a peer state replacement.

Five native cases cover exact restoration after later live publications, retained
write receipts, malformed manifests and wrong identities, partial/corrupt streams,
a 3 MiB source with cancellation/resealing, empty application state, active
transaction rejection and fenced applications. A disposable digest-check bypass
must fail the corrupt-body assertion.

## Durable snapshot archives

`consensus/snapshot_store.c` stages a received manifest and image in an existing
trusted directory. The directory must belong to the process uid and deny writes
to group and other users. It is held by descriptor; final path components are
opened without following symlinks. Stages create unpredictable exclusive private
temporary files and own their directory descriptors independently of the store.
Only contiguous chunks of at most 1 MiB pass through the snapshot verifier before
being written. A failed feed or finish fences the stage.

An archive consists of the 256-byte manifest followed immediately by its native
image. Its name is the lowercase SHA-256 of the complete manifest followed by
`.snapshot`; image offsets in the API remain relative to the native image.
Finish verifies the whole stream, sets owner-read-only mode, and syncs file data
before publishing with a no-overwrite hard link. It removes its temporary name
and syncs the directory before returning the archive id. Concurrent identical
publishers converge on one file. A pre-existing name must pass complete
verification and a data sync; a malformed, corrupt or conflicting file remains
untouched and causes failure. Errors after publication can be uncertain; a new
stage with the exact same manifest and image resolves retries.

Opening an archive checks private regular-file ownership/mode, exact length,
manifest name/identity, both superblocks and every image byte. Verification uses
a 1 MiB buffer and supports cancellation. Successful handles own their file
descriptors and support concurrent bounded reads after the store is closed.
Callers must preserve archived files as immutable and join readers before close.
Stage close attempts to remove only its own temporary name. Process-crash
leftovers stay unpublished and are never removed by another stage or retry.
This layer provides no archive deletion or retention policy.

The archive layer does not select a snapshot or expose a daemon installation
endpoint. An archived image requires complete native application validation and
the document/journal coordination described below before use. Archive publication
does not permit log trimming, change membership, or replace a peer's live root.
The physical image continues to include unreachable historical pages.

Seven native cases cover exact YAML/application/receipt restoration, short and
corrupt streams, partial writes, idempotent and concurrent publication, corrupt
existing-file preservation, private paths and symlink/FIFO rejection, sync/link/
unlink failures, and process exits around publication boundaries. Those process
tests verify retry behavior, not physical power-loss durability. Removing the
file-sync guard or existing-image digest verification from disposable builds
must fail the corresponding assertions.

## Staged application validation

`yd_raft_application_validate` checks an opened staged application against the
trusted snapshot's complete native view, cluster, applied index/term and last
entry digest. Its owner serializes calls, as with application preparation and
apply. Every tree key must be strictly ordered and reachable through normal
lookup with the same value. The validator rejects unknown namespaces, malformed
metadata keys, retained feed frames outside their declared range, mismatched
frame counts and more receipts than applied entries. It checks the stored
application checkpoint and every receipt, including receipts never looked up by
a client. Live receipt lookup shares the same bounded decoder and validates a
stored reply before classifying a request id as reused.

The existing native validator then checks collection/document counts and source
fingerprints, document parsing, scalar/unique/text index coverage and references,
and retained change history. Validation writes nothing and uses the native page
cache and bounded per-record/parser allocations rather than loading the dataset
into memory. It may scan the full dataset; it is intended for a staged root,
before the controller selects it. Metadata mismatch or any other failure must
prevent selection. It does not prove that a prefix was committed or grant
permission to replace the live document root or discard journal entries.

The private `yd_raft_application_validate_at` variant scans a trusted immutable
captured native view without accessing or recapturing the live application. Its
caller pins the disk/view lifetime and takes expected metadata from that same
owned capture. The scan may overlap later application writes and uses the
captured position for every receipt, namespace and feed check. It validates the
logical graph; separate sealed-image verification must bind the complete physical
image, including its end and historical bytes. The ordinary staged-application
wrapper retains its exact current metadata/view check before sharing this scan.

Two native cases retain indexed source/receipt state through twenty later
publications and validate it during concurrent writes, reject altered expected
identity/position and publish no validation writes. All nine validation cases
pass ASAN/UBSAN and fully instrumented cryptography TSAN. Both new cases fail
with the view bridge disconnected; recapturing the current view in a disposable
build also fails the historical assertion. Selected-root startup, retained/local
checkpoint suffixes and damaged-candidate rejection pass after this refactor.

Seven native cases exercise empty and populated roots, index catalogs and noops,
all expected metadata fields, fourteen receipt mutations, unknown key types,
stray feed frames, excess receipts, document/collection/index/history damage,
and a 3 MiB source with a 32 KiB page cache. Malformed fixtures retain an otherwise
openable application checkpoint, so ordinary open is not their acceptance gate.
The damaged-reply regression fails against the previous live lookup behavior;
disposable namespace-check and native-validation bypasses also fail their tests.

## Owned outgoing capture archives

The private `consensus/capture_internal.h` factory borrows an immutable image and
its same pinned source disk, plus trusted controller-origin metadata. It seals
the image, checks the trusted cluster/voter configuration and position, and runs
the complete captured-view graph/receipt validation while later writes may
proceed. It then streams chunks of at most 1 MiB through the durable archive
store and reopens the published archive with full physical verification. Its
caller must already have made the archive directory's parent names durable.

The returned opaque handle owns an immutable archive descriptor and no source
application/controller pointer. It can stream after both the source and borrowed
directory are closed. Its origin check returns a base only for the exact stored
cluster, voter configuration, node and leader term; the integrating controller
must obtain that origin from a quorum-confirmed serialized capture and prove
fresh leadership again before any local checkpoint. The factory does not prove
consensus authority, trim a journal or select an application.

Cancellation uses phase-local progress counters for sealing, graph validation,
archive copy and archive verification. Cancelling after publication retains the
complete private archive and permits an identical retry. Native cases cover
source/controller-independent reads, exact restored YAML/receipts, bounds and
foreign origins, concurrent later writes, both early and post-publication
cancellation, idempotent archives and a physically sealed but invalid native
graph. The six cases pass ASAN/UBSAN and fully instrumented cryptography TSAN.
Disconnecting construction or removing graph validation/archive cancellation
from disposable builds fails behavioral assertions. The module is linked into
the daemon.

The private controller `yd_raft_cluster_capture` obtains a new majority read
proof, waits through its applied boundary, and rechecks the same leader term
before capturing the image under the application lock. It pins that generation
and its disk together while sealing, validation and archive publication proceed
outside the lock. A progress callback can issue an ordinary write during sealing;
the returned artifact retains the earlier captured state. Admission is bounded
by the supplied timeout; artifact work uses cancellation rather than a fixed
wall-clock cutoff. Callers join active operations before closing the controller.
An already returned capture has no such controller lifetime dependency.

`yd_raft_cluster_checkpoint` is a controlled private publication bridge. It
obtains another fresh majority proof, checks the capture's exact cluster, voter
configuration, node and leader term, and rejects a boundary beyond that proof.
The runtime rechecks leadership and term under its own lock immediately before
the native prefix transaction. This operation retains the complete suffix and
selected application identity; it does not switch generations. An uncertain
native sync fences the runtime and controller for restart recovery. Prefix work
remains serialized and may exceed the admission timeout. No HTTP endpoint or
default policy invokes this bridge; explicit checkpoint settings can enable it.

Real mutual-TLS controller cases cover a concurrent sealing-time write, restart
from an older archive plus the retained suffix, durable retry receipts, minority
and follower rejection, a higher-term contact immediately before the runtime's
publication guard, both native journal sync failures, cancellation/retry and
complete archive streaming after controller close. The tests also require that
cancellation and superseded authority leave a healthy application usable.

## Fresh snapshot candidate roots

`yd_raft_snapshot_restore` extracts a verified archive into an existing empty
trusted directory. It checks the expected cluster/voters and cache bounds before
creating files, requires the current uid and denies writes by other users, and
holds an exclusive directory lock. Every subsequent open, validation and
publication uses the pinned directory descriptor. Renaming the destination path
therefore cannot redirect a later application open into another directory.
Descriptor-based native opens use an independent directory scan when checking
emptiness, even if the caller previously exhausted its own scan position.

`yd_raft_snapshot_restore_at` accepts an already pinned candidate directory and
duplicates that file description. It shares the caller's exclusive directory
lock and never closes the caller's descriptor or reopens a pathname. The caller
controls its remaining descriptor/lock lifetime, including after cancellation;
independent file descriptions still exclude competing restorers. The pathname
wrapper uses this same implementation. Descriptor tests cover replacement before
the call, an exhausted directory scan, caller-lock lifetime on success and
cancellation, wrong identity/cache, unsafe permissions, competing ownership,
regular-file descriptors and repeated restoration into a completed root. Each
new case fails with the descriptor bridge disconnected. The nine restore cases
pass ASAN/UBSAN and fully instrumented cryptography TSAN.

The restorer writes and syncs the complete manifest under the normal
`.yamora-initializing` fence before creating the candidate's native file. It
copies chunks of at most 1 MiB, syncs the file and directory, then reads the
copied file back through the complete snapshot verifier. This checks historical
pages as well as live records; a valid native graph alone cannot establish byte
identity for dead pages. Progress counts copy plus readback bytes and permits
cancellation in either phase. Native application validation then performs its
complete serialized scan with bounded per-record allocations.

Only after both checks succeed does the restorer link the durable manifest as
`.yamora-snapshot`, sync the directory, remove the initialization fence and sync
the directory again. Replica-set startup checks that fence before opening an
application, creating a journal or starting peer workers. Standalone startup
retains its existing fence check. Failure preserves candidate files for diagnosis;
retry extraction into another empty root. An error on the final sync can leave
a complete candidate, but does not grant authority to select it.

Restoration constructs a candidate. The authenticated controller receiver
supplies the live switch, coordinated selection/recovery and Raft snapshot-base
checks described below; automatic retention remains disabled.
Neither a completed candidate nor its manifest permits discarding a log prefix.

Six native cases cover exact application/receipt restoration, eight process-exit
boundaries, file and directory sync/link/unlink failures, short writes and altered
dead-page bytes, directory renames and overlapping attempts, cancellation,
foreign identities, symlinks, permissions and occupied roots. A hash-valid image
with unknown application metadata must retain its initialization fence. Separate
daemon tests reject empty, populated and symlink fences without creating a
journal. The exhausted-directory-scan and daemon-startup regressions fail before
their repairs; readback-digest, pinned-open and native-validation bypasses fail
the corresponding assertions.

## Durable Raft snapshot boundaries

The serialized core's `yd_raft_checkpoint` accepts a committed snapshot boundary
only after its owner has durably archived and validated the corresponding
application image. The archive identity is the 32-byte SHA-256 of the manifest;
the core treats it as an opaque binding and does not open or validate archives.
The boundary index and term must match the local committed log, move forward,
and carry a nonzero archive identity. Repeating the exact boundary is idempotent;
changing its identity, using an uncommitted index or regressing is rejected.

One native transaction removes entry/term keys through that index and persists
the boundary with the existing term, vote, last and commit positions. The suffix
is retained, including uncommitted entries, and later conflict repair and ordinary
journal mutations preserve the boundary. Sync failures fence the live core.
Reopen sees a complete old or new logical prefix and metadata, never a mixed
publication. Historical physical pages remain in the append-only journal file;
this does not reclaim disk space or add a compaction policy.

Journals without a snapshot keep the 64-byte `YDRMETA1` metadata record. The
first local checkpoint atomically introduces the 112-byte `YDRMETA2` record, adding the
base index/term and manifest digest; the underlying native journal stays format
5. Recovery accepts these versions, rejects malformed boundaries or
retained prefix keys, and verifies a contiguous suffix with nondecreasing terms
starting at the stored boundary term. Older core builds cannot open checkpointed
metadata. No ordinary journal is upgraded before a snapshot operation is requested.

Elections and previous-entry checks use the boundary term when all earlier
entries have been removed. Missing compacted entries return unavailable rather
than fencing the core. Requests below a follower's boundary reject normally;
when a leader's next position is below its own boundary,
`yd_raft_snapshot_required` reports that the peer needs snapshot installation.
The member scheduler suspends ordinary appends for that peer while the runtime
schedules snapshot transfer on its existing peer worker, continuing other peers.
Observing this condition grants no matched position or quorum acknowledgement.

The private core `yd_raft_snapshot_request` now allocates one unique outbound
operation token for a lagging static peer and copies the persisted checkpoint
identity. A new operation supersedes older snapshot and append contexts for that
peer. Transport must authenticate and correlate the complete phase, base and
session exchange before calling `yd_raft_snapshot_reply` on final completion;
received bytes, pending installation and unverified archives grant no progress.
Only the exact current operation's installed acknowledgement moves matched to
its offered boundary and resumes ordinary appends. A newer local checkpoint
does not enlarge an older operation's acknowledgement. Failed final operations
clear their context; duplicate, stale-term, unsolicited and wrong-token replies
cannot advance it. Higher authenticated terms still cause durable stepdown,
including replies from superseded operations. This in-memory progress bridge
does not change commit or establish fresh read/quorum proof. It performs no
image I/O; the recovered controller's runtime workers schedule it as described
below.

The scheduler's private `yd_raft_member_snapshot_begin`/`done` pair now owns that
operation until explicit final completion or a role/term change. Its lifetime
does not expire at an ordinary RPC deadline: replacing tokens while a large
image is still being transferred would prevent any completion from matching.
An existing live append blocks admission until it finishes or expires; other
peers keep their ordinary heartbeat/append schedule. The caller must reserve a
bounded worker before beginning and must finish failed/cancelled jobs as well as
successful ones. A NULL reply ends a failed operation, never reports intermediate
progress. Delayed completions cannot release newer jobs; higher authenticated
rejection terms still cause durable stepdown. Four deterministic scheduler cases
verify these rules, clock bounds and immediate suffix scheduling after success.

The private `consensus/snapshot_send.c` operation now drives begin, resumable
chunks and pending finish polls from a borrowed verified archive. Its complete
manifest must match the persisted request's cluster, voters, index, term and
archive digest before network admission. Each reply passes canonical wire and
phase/peer/token/base/session correlation; accepted offsets cannot exceed the
image. A lost transport reply ends the attempt, allowing a new operation to
resume the receiver's existing offset. Only a confirmed full-image installed
reply reports installation; correlated rejection/higher terms return without it.

Caller hooks authenticate each bounded RPC, check current leader authority,
reserve/release payload bytes and pace cancellable pending polls. Each chunk is
allocated only after reservation and released after exchange on success or
failure. No payload allocation/reservation remains during installation polling.
The operation grants no core progress itself. Eight native cases cover exact
2 MiB YAML and receipt restoration,
resume after a lost chunk reply, higher-term rejection, cancellation, malformed
phase identities/offsets, archive mismatch, budget failures and failed-job retry.

Seven native cases verify retained suffix replication, unchanged commit until
an ordinary append acknowledgement, rejected inputs and token exhaustion,
superseded operations, delayed appends, advancing checkpoints, durable term
adoption and fencing at both native sync failures. The tests fail against an
unconnected bridge and when disposable builds remove operation correlation,
offered-boundary binding, old-append invalidation or stale-token term adoption.

The daemon calls checkpoint only when explicitly configured. The ordinary
runtime entry point rejects a checkpointed journal without a recovery callback;
the document controller uses the verified archive recovery described below.
A native runtime regression proves the ordinary caller cannot bypass recovery.
Physical reclamation still requires a separate policy and sustained fault/load
qualification. Six native
cases check immediate restart before later writes, suffix preservation, elections
with an empty suffix, lagging-peer scheduling, invalid boundaries, conflict repair
and a second checkpoint, malformed metadata and missing suffix records, both sync
failures and all six SIGKILL publication boundaries. Omitting checkpoint metadata,
boundary-term lookup or the lagging-peer scheduler check from disposable builds
must fail the corresponding runtime assertions.

## Archive-bound startup recovery

`consensus/recovery.c` checks a checkpointed journal's selected immutable archive
before its controller starts any peer worker. The core holds an owned descriptor
for its journal directory and opens its native file through that same pinned
directory. Recovery opens the existing `.yamora-snapshots` child relative to it,
without following a symlink or creating a directory. Renaming or replacing the
original journal pathname cannot redirect archive selection. Archive directories
retain their owned-directory and permission checks.

The metadata's archive hash selects exactly one manifest; recovery verifies the
complete artifact, trusted cluster and voter count, and its boundary index/term.
An application before that boundary or beyond the journal's committed position
rejects. If the application is exactly at the boundary, its sealed canonical
image must match every manifest byte, including the complete physical image
digest. This covers unreachable historical bytes as well as live data. The native
application graph and all receipts/indexes/feed state must also validate. If the
application has advanced beyond the boundary, its latest applied entry must match
the retained committed journal's term/digest, followed by complete native graph
validation at its current view.

This check publishes no application or journal writes. Artifact verification and
current-image sealing can be cancelled; the native graph pass is serialized and
not cancellable. Memory is bounded by the page cache, per-record parsing and
bounded image chunks; startup work grows with physical archive size and live
state. The checkpoint caller must have durably archived and fully validated the
snapshot before binding its manifest hash in the journal. Archive integrity is
not a substitute for that prior validation or for a coordinated remote install.

There is no HTTP checkpoint endpoint or physical garbage collection. Explicit
checkpoint settings enable automatic archive creation and logical journal-prefix
removal; they remain disabled by default. Authenticated peer installation uses
the receiver above; durable generation resolution at startup is described below.
Native test utilities can also prepare offline fixture checkpoints and selected
generations. Startup without an enabled policy does not create an archive
directory for an uncheckpointed journal. A candidate marker alone cannot replace
the archive selected by durable journal metadata.

Adversarial startup cases reject missing, corrupted, symlinked or untrusted
archives, mismatched boundaries, lagging applications, altered historical image
bytes, divergent suffixes and damaged native receipts before worker creation.
Pinned-directory recovery and cancellation preserve both native stores. Removing
image identity, boundary binding or suffix graph validation in disposable builds
must fail their runtime assertions. Three actual mutual-TLS members restart from
checkpointed journals, elect, write, survive a lost increment reply and retry it
once after failover; the test retains exact YAML and durable receipts.

## Incoming snapshot journal transitions

The isolated `consensus/install.h` interface implements the journal portion of
[Raft's snapshot rules, §7 and Figure 13](https://raft.github.io/raft.pdf).
It is not a peer RPC or a live application installer. Its caller must first
durably archive and validate a candidate and coordinate application selection
across a crash before publishing the new journal boundary. The private controller
installer now performs that coordination for the authenticated incoming receiver.
No HTTP endpoint exposes the isolated journal transition.

`yd_raft_snapshot_contact` validates the trusted cluster/member and bounded
offer metadata, durably adopts a higher leader term and steps down on current
leader contact. Same-term contact preserves the existing vote. Stale terms and
already committed positions report no install needed. A verifiable committed
boundary-term conflict or regression below the committed term fences the core
without trimming its journal. A different physical archive hash at an already
committed position is harmless contact: nodes can have independent valid images.

`yd_raft_member_snapshot_contact` also updates the election scheduler. Only a
valid offer from the exact current-term leader resets the follower's randomized
deadline, including contact for an already committed boundary. Stale or malformed
offers cannot postpone an election. Observing a term or role change clears stale
outbound scheduler state. The private runtime bridge serializes this contact,
wakes read/proposal waiters after stepdown, and stops participation on a fenced
core. Its caller must authenticate the configured peer before using it; the
incoming receiver invokes it only after verified peer RPC authentication.

Native scheduler cases cover current, installed, stale, malformed and conflicting
offers. Actual mutual-TLS runtime cases verify stepdown, sustained current contact,
election after stale traffic, restart without a selected boundary, and fencing on
committed-history conflict. ASAN/UBSAN and fully instrumented TLS TSAN pass.
Disposable builds that omit the runtime bridge or timeout reset, or permit stale
traffic to reset the deadline, fail their behavioral assertions. Contact alone
does not transfer or install an application or acknowledge replication progress.

`yd_raft_snapshot_install` rechecks the exact current term, follower role, leader
and committed progress after staging. It rejects a superseded offer. A boundary
newer than commitment retains the suffix only when its local index and term
match; otherwise the local tail is replaced. The new boundary, archive identity,
commit position, tail and removed keys publish in one native transaction, with
term/vote preserved. Retry of the identical selected base performs no writes;
changing that selected archive at the same position rejects. This transition
shares checkpoint publication with local retention and still leaves physical
historical pages for later reclamation. It scans logical journal keys while
serialized; it does not yet provide bounded background retention work.

Nine native cases cover retained/replaced/beyond-tail snapshots, successive
boundaries, elections and appends after restart, malformed/stale offers, three
committed conflicts, intervening leadership or commitment, same-term votes,
higher-term contact sync failures, and both sync failures plus six SIGKILL
publication boundaries for both retained and replaced suffixes. ASAN/UBSAN and
TSAN pass; disposable builds bypassing suffix-term matching, term or leader
revalidation, or committed-prefix checking fail their runtime assertions. Core
fixtures use opaque archive identities and do not claim application installation.

### Durable application generation identity

An incoming installation now publishes the application's generation identity in
the same native transaction as its snapshot boundary, commit position and suffix.
`YDRMETA3` is exactly 144 bytes: the preceding 112 bytes retain the snapshot
encoding, and bytes 112–143 contain the nonzero SHA-256 manifest hash of the
selected application generation. `yd_raft_application_generation` copies this
identity; all zeros in an older record mean the original document root. Local
checkpoints, elections, term changes and ordinary appends preserve the selected
generation independently of any newer local snapshot archive hash. A later
remote installation atomically replaces it. An idempotent boundary retry does
not change generation selection.

Recovery rejects zero identities in version 3, truncated or version/size-mismatched
records, unknown versions, invalid reserved fields and inconsistent boundaries.
Both sync failures and six SIGKILL boundaries for retained and replaced suffixes
must recover either the entire old journal with its original selection or the
entire new journal with its new selection. Tests also preserve selection through
elections, local checkpoints and successive remote installations. Deliberately
dropping persisted selection, clearing it during a local checkpoint, or accepting
zero version-3 identities fails runtime assertions. These core fixtures do not
resolve application directories; the controller does so before peer startup as
described below. Incoming installation uses the authenticated peer receiver;
there is no HTTP installation endpoint.

### Serialized runtime publication

The private `yd_raft_runtime_snapshot_install` bridge publishes only an advancing
boundary under the owned runtime lock. The integrating controller must first
durably archive and validate its candidate, hold its application lock and exclude
in-flight prepared writes. Immediately after the atomic journal decision, a
non-failing callback moves the prepared application into the controller's live
slot before runtime observers can see the new boundary. The callback must not
allocate, block or reenter the runtime. Rejected, superseded or already committed
offers never invoke it. The runtime then renews the follower deadline using a
fresh clock reading, including after slow journal-prefix work.

The separate `published` output records ownership transfer even if a subsequent
clock/scheduler failure stops participation and makes the call return false.
Sync failure fences the runtime without transferring the live application;
durable candidates must remain available for recovery of an uncertain journal
decision. A return value alone is not a peer installation acknowledgement.
The private controller installer below uses this bridge. Its incoming worker
supplies incoming peer integration; runtime workers supply outbound catch-up.

Actual mutual-TLS runtime tests cover fresh contact, rejected peer/term changes,
successive installations, duplicate rejection, both sync failures, post-decision
clock failure and an installation exceeding the election timeout. ASAN/UBSAN and
fully instrumented TLS TSAN pass. Removing publication, its callback or the fresh
deadline renewal from disposable builds fails the corresponding assertions.

### Resolving a selected generation before participation

The controller pins the document directory and opens its journal before opening
an application. Its recovery callback resolves the durable application identity
while that exact journal remains exclusively owned and before any member or peer
worker exists. An original version-1/2 journal opens the original document root.
A selected identity opens only
`.yamora-generations/<64 lowercase manifest-hash digits>/` beneath the pinned
document directory. A missing or invalid selected generation rejects startup;
the original root is never a fallback.

The parent and child directories must be owned by this uid, must not be writable
by other users and must not be symlinks. The completed `.yamora-snapshot` manifest
and native data file must be private regular files with a single link. Recovery
rejects an initialization fence, malformed or truncated markers, an identity hash
mismatch, a foreign cluster/voter manifest and a generation origin inconsistent
with the journal boundary. It opens selected data without creating a file or
initializing an empty native genesis image. Existing application state must be
at least as recent as its generation origin, then pass the complete archive,
position/digest and native validation described above. Initial creation remains
available only for the original empty root.

The generation identity remains independent of later local checkpoint archive
identities, so restart can reopen the same application after its journal advances
to another verified boundary. Resolution follows the pinned directory even if its
pathname is renamed and replaced. Cancelled verification publishes neither
application nor journal writes. The controller retains the document-root lifecycle
lock through worker shutdown. The ordinary path constructor acquires its own
exclusive directory lock before opening the journal. The daemon uses
`yd_raft_cluster_start_at` with a duplicate of its already locked directory's file
description; it retains its own descriptor through HTTP and peer shutdown. Startup
therefore follows the exact owned root even after pathname replacement, without
a second independent lock attempt or an unlocked reopen. Successful close and
failed startup preserve the daemon's caller-owned lock until that caller closes
its descriptor. Native callers reject another root owner before journal/peer
startup and release their own lock on close. No old generation or original file
is deleted.

Native cases cover exact YAML in selected roots and retained suffixes, independent
local checkpoint archives, missing/corrupted original roots, directory and file
symlinks, permissions, hard links, missing or malformed markers/data, altered
historical bytes, native genesis images, pinned-path replacement and cancellation.
ASAN/UBSAN and fully instrumented TLS TSAN check startup and cleanup. Disposable
builds that bypass manifest identity, directory trust or selection fail runtime
assertions. An actual three-node HTTPS case prepares a generation offline, starts
it as a voter, forces its election after a newer write and verifies exact YAML,
feed reads and the original durable retry receipt. The offline helper is test
infrastructure, not a daemon install endpoint or an online transfer protocol.

### Private live generation installation

The private controller installer consumes a completed archive already stored
beneath its owned journal directory. It requires prior authenticated leader
contact from a configured non-self voter and an exact current follower term/leader
with a boundary newer than commitment. It opens archives through the runtime's
pinned journal descriptor,
checks their full image and exact offered boundary, and stages beneath the
pinned document directory. No storage path supplied by a peer is followed.

A fresh copy uses a private random `.incoming-<nonce>/` sibling. The restorer
retains its initialization fence on failure, leaving the final generation name
available for a fresh retry. After copy, an existing-only candidate open checks
the completed private manifest/files, exact physical image, application position
and full native graph, then syncs its native file. Only a completed candidate
receives its manifest-hash name through Linux `renameat2(RENAME_NOREPLACE)`;
the child, generation parent and document root are synced before journal
selection. Existing completed candidates must pass the same verification and
can be reused after a publication-admission timeout. Partial copies and old roots
are preserved; no cleanup or reclamation runs automatically.

Staging permits ordinary application progress. At final publication the controller
waits for any active write preparation/proposal/receipt flow, rechecks leadership,
commitment and its deadline, then serializes the journal decision with a constant
time live-generation pointer transfer. No new term/leader contact is synthesized
by installation. A superseding contact during staging rejects the old offer.
Sync uncertainty fences the runtime/controller and retains every recovery input.
The deadline bounds admission and I/O progress. Native graph validation polls
cancellation between bounded units; the final journal-prefix decision remains
serialized and indivisible.

The application worker pins its generation across journal waits and entry lookup.
After a switch it discards the old cursor, even if the old entry is now compacted,
instead of fencing the replacement. Owned read views independently retain the old
application until their final close. Their historical reads may finish after
installation and controller shutdown; fresh captures still require a quorum.

Native tests exercise live replacement and restart, both pinned-root pathname
replacements, paused old workers and file-lock lifetime, active-write admission,
retry after a fenced failed copy, damaged or advanced candidates, superseding
leadership before/during staging, both journal sync failures and SIGKILL immediately
before/after the journal decision. The latter reopens the exact old or new durable
generation even when the live pointer callback never ran. These process tests
do not simulate physical power loss. A real mutual-TLS three-process test retains
a quorum-confirmed old view through replacement/shutdown, restarts the selected
image, retries an increment once and resumes replication. ASAN/UBSAN and fully
instrumented TLS TSAN pass. Disposable builds removing worker retention, cursor
checking, write admission, image identity or runtime publication fail their
behavioral assertions. The authenticated receiver now connects incoming transfer
and confirmed installation replies to this interface. The core acknowledgement
bridge and outbound transfer scheduling are implemented. Background checkpointing
is opt-in; physical reclamation remains absent. This private function is not an HTTP RPC.

## Runtime snapshot catch-up

After a recovered controller registers its receiver, the existing outbound peer
workers also service peers whose next position is below the persisted checkpoint.
The timer reserves a free worker before admitting one scheduler operation, then
opens the exact archive beneath the owned journal directory and verifies its
physical digest outside the runtime lock. It creates no missing directory and
does not capture mutable application state. An unavailable/corrupt bound archive
stops source participation; a superseding term/role or shutdown cancels the job.
Bare runtimes without a recovered controller remain outside this integration.

Each TCP connect, mutual-TLS handshake and peer phase has a separate configured
RPC deadline. The overall operation can continue beyond that deadline while its
leader/term remains current and the peer responds. Chunks are at most 1 MiB and
fit the configured outbound payload budget, with reservation before allocation
and release after every exchange. Pending installation polls hold no payload
reservation, wait one heartbeat interval and wake for shutdown/authority changes.
Archive physical verification retains its independently bounded 1 MiB work buffer.
Snapshot transfer requires a payload budget of at least the 256-byte manifest.

Only a correlated final installed acknowledgement reaches scheduler/core matched
progress. No snapshot phase issues or observes a read-proof sequence. Once the
installed boundary is acknowledged, ordinary appends resume the retained suffix;
their normal current-term majority and fresh-read rules still apply. Failed or
uncertain transport operations release their context and retry after a heartbeat
interval, beginning again at the receiver's verified resumable offset. Shutdown
joins active/queued jobs before closing the owned journal and borrowed TLS state.
Published archives and previous application generations remain preserved.

Five actual mutual-TLS cases cover pending installation beyond election timeouts,
minority read/write rejection despite snapshot contacts, retained suffix and
receipt recovery after restart, a lost chunk reply under a 1 KiB budget, source
shutdown during pending installation, superseding terms while an archive is held,
and a damaged source archive without selecting the target image. ASAN/UBSAN and
fully instrumented TLS TSAN verify these paths. Removing authority cancellation,
source archive fencing or installed-progress delivery fails targeted behavior.
Daemon checkpointing can opt into the worker below. Physical reclamation and
production fault qualification remain separate requirements.

## Opt-in controller checkpoint worker

The C controller can now enable `yd_raft_cluster_checkpoints` once after recovery.
It remains disabled unless explicitly requested through the optional daemon
`checkpoints` settings or the C API. One owned worker polls a committed-entry delta from the persisted snapshot
base. Only a healthy leader meeting that threshold attempts work. It calls the
existing fresh-quorum capture and checkpoint bridges, with current leader/term
checks during image progress and the final serialized publication guard. An
observed committed position or an archived image never supplies quorum authority.

The policy accepts 1..1,000,000,000 entries, a 100..3,600,000 ms interval between
attempts, and a 100..30,000 ms quorum/admission timeout. It requires an outbound
budget large enough for a snapshot manifest. One attempt completes before the
next interval starts; followers and leaders below the threshold create no
archives or attempts. Quorum, leadership or admission failure retries later.
Failed thread creation leaves the policy disabled and permits another enable;
an already enabled policy cannot be replaced through this API.

Controller status copies enabled/running state and process-local succeeded/failed
attempt counters. `last_index` is the persisted boundary observed after the
latest successful policy publication. Counters reset on restart. These are
observations, not readiness or read proofs. The module never calls the controller
while holding its own status mutex. Close marks the controller stopping, cancels
and joins owned capture/checkpoint work before destroying its runtime or source
application. Complete graph scans and native prefix publication remain serialized
and can outlast the admission timeout; cancellation is observed at progress
boundaries. All archives, generations and old physical journal pages remain.

Six actual mutual-TLS cases cover disabled defaults, the committed threshold and
retained-suffix catch-up, invalid/duplicate enable and worker-creation retry,
minority failure without an archive followed by quorum recovery, cancellation
during owned capture, and fencing/restart at each of the two journal sync faults.
Daemon configuration validates the optional map before storage creation, rejects
unknown/invalid fields and enables the worker after recovered controller startup.
Administrative cluster status copies its local counters; minimal leader discovery
is unchanged. Actual HTTPS cases verify omitted/zero defaults without archives,
invalid settings before native files are created, and automatic snapshot catch-up
of an offline peer. That peer restarts from its selected generation, becomes leader
and returns the original increment receipt without repeating its effect.
Physical reclamation remains separate.

Three additional native mutual-TLS fault cases combine four concurrent writers,
lost-success leader SIGKILL and majority failover during held capture, after
checkpoint publication, and during pending incoming installation. Every original
write ID and body is retried through the new leader before a complete cluster
restart, checking exact YAML and one effect per durable receipt. The pending old
leader's image must cancel before candidate creation after new-majority writes.
These are bounded fault schedules, not sustained load or production HA
qualification; ordinary append catch-up can legitimately repair a peer in these
schedules. Actual daemon selected-generation recovery is checked separately.

## Application-copy foundation

`consensus/application_copy.c` captures a logical immutable reader together with
cluster identity, applied position and entry digest under application ownership.
Copying runs outside that owner and survives source writes, close and directory
rename. Complete source validation precedes candidate creation. The destination
must be an empty private directory; every created candidate keeps its durable
initialization fence on success and failure. Closing it preserves diagnostic files.

The copy streams reachable primary records, exact YAML/model bytes, retry
receipts, applied metadata, index catalog and secondary/unique/text keys. Change
frames reference historical document records that may no longer be primary:
those records are copied too, with only embedded physical offsets relocated.
Tokens, revisions, headers, source bytes and receipt responses remain exact.
A temporary offset map lives in the candidate's native tree and is removed
before commit. Caches, dirty-page buffers and per-record allocations are bounded;
there is no dataset-sized in-memory map. Private staging pages add overhead, so
this foundation does not claim optimal dense packing or a live space budget.

An independent reader then validates the complete graph, compares every logical
key and referenced record against the captured source, and reads back the active
superblock. Exact primary/catalog bytes and identical index keys, together with
both full graph checks, bind each posting to its correct relocated primary.
Capture and returned image own their file locks; a separately pinned reader may
outlive both. The image exposes only a read-only handle. Serialize image methods,
including observations and close; independently owned disk pins can read in
parallel. A serialized currentness check requires the original source inode,
complete view and exact applied metadata. Matching bytes on another inode fail;
this check supplies no quorum or publication authority.
An owned duplicate source descriptor keeps that inode and its file lock alive
until image close, even after application/capture close, preventing inode reuse
from passing the identity check. It retains no application object.

Incremental catch-up accepts only monotonic captures of the same inode/cluster.
It validates source and prior candidate, prunes absent keys, reuses byte-identical
records, seeds historical record relocation from matching prior frames, and
copies new references through the native-tree map. Independent full graph,
key/record and superblock readback precedes updating the image's capture metadata.
An unchanged generation is verified without writes. Corrupt/cancelled source
validation preserves the prior image, as does cancellation while verifying an
unchanged generation. A candidate integrity failure or failed mutation attempt
permanently fences it. Other owned readers retain their previous views.
Catch-up appends private changes without reclaiming earlier candidate pages;
future operation budgets must bound this growth. The guarded controller bridge
below supplies live selection; old-generation deletion, pin admission/backpressure
and retention remain unimplemented.

Progress cancels between copied/compared keys and nested graph validation units
as described below. Individual bounded records, tree traversals and syscalls are
indivisible. Callbacks can hold the candidate writer mutex and must not call
runtime/cluster methods. Seven native cases pass
ASAN/UBSan and fully instrumented crypto TSAN, covering exact history and receipts,
source writes in each phase, source-close lifetime, all six sync failures, corrupt
source/candidate rejection, genesis, 3 MiB YAML and a multi-page relocation map.
Four more cases cover catch-up across feed/primary/index pruning, retry receipts
after reopen, stale/foreign captures, concurrent writes in every phase, unchanged
3 MiB record reuse, source-close lifetime, cancellation, sync faults and legal
checksummed receipt changes and header corruption. All eleven cases pass both profiles;
five copy and ten catch-up guard removals fail behaviorally. The foundation's
23 application, graph-validation, snapshot and pinned-read regressions pass.
This is groundwork for application-page
reclamation, without production qualification or a public maintenance endpoint.

### Compact application archive binding

`consensus/application_archive.c` binds a private compact image to an owned
physical checkpoint and the existing sealed `YDRSNAP1` archive format. The
manifest records the compact image's actual root/end together with its exact
applied index, term and entry digest. Checkpoint/snapshot descriptors survive
later catch-up and all original owner closes. Serialize image methods; owned
immutable checkpoints and archive readers may read concurrently.

The shared artifact path seals the full physical image, validates its logical
graph, stages/publishes it without overwrite, then independently reopens and
verifies the complete archive. Transfer buffers stay at or below 1 MiB. Trusted
cluster/voter configuration is supplied separately; malformed native contents
are rejected even when their file checksum is valid. Cancellation or failure
clears the output identity and preserves the image and any published archive.
An existing corrupt artifact is preserved and exact retries reject it.

This returns an archive, never a quorum-authorized capture. A compact image has
a different physical identity from the original application; passing it through
ordinary journal checkpoint publication would break restart's physical binding.
Live generation selection uses the separate guarded controller bridge below;
reclamation remains unimplemented.
Genesis artifacts are valid, but cannot be selected by the existing installer.
Graph validation polls cancellation at the boundaries described below; individual
bounded records and syscalls remain indivisible.

Nine archive cases pass ASAN/UBSan and fully instrumented crypto TSAN, covering
exact YAML/history/index/receipt restore, later writes, owned checkpoint lifetime,
concurrent 3 MiB archive reads after directory rename, every artifact cancellation
phase, sync failures, permissions/identity/genesis boundaries, fenced images,
post-seal changes, checksum corruption and invalid native graphs. Twenty existing
snapshot/capture/restore regressions pass after sharing artifact publication.
All four guard removals fail behaviorally: full graph validation, complete image
hash verification, checkpoint/position shape binding, and withholding the output
identity until verified reopen. Strengthened ownership/cancellation cases pass
both sanitizer profiles after host I/O stalls exceeded the initial test timeout;
each case retains a bounded three-minute deadline.

### Native local application-selection decision

The private `yd_raft_application_select` core primitive compares the expected
prior selected-generation hash and accepts only an existing committed boundary
with the exact term and a nonzero archive identity. In one native journal
transaction it changes both snapshot and application identities and removes
prefix keys, preserving term, vote, commit, retained/uncommitted suffix and
volatile role/peer/RPC state. Same-index rebinding is permitted because compact
physical bytes can differ at the same logical boundary. Exact repeated decisions
are write-free only when the prior-generation guard still matches. Subsequent
ordinary journal checkpoints preserve the selected application identity.

This serialized primitive opens no artifacts and supplies no quorum proof or
leader contact. Its trusted integrating caller must durably prepare and validate
the equivalent application generation, exclude application writes, check its
exact original source view and transfer the live pointer immediately after a
successful decision. A persistence failure fences the core; candidate artifacts
must remain available for restart. Follower maintenance does not grant read or
write authority. The integrating runtime/controller bridge is described below;
this private journal primitive alone supplies no maintenance policy.

Five native cases pass ASAN/UBSan and ThreadSanitizer. They cover stale/invalid,
uncommitted and fenced decisions, same-index rebinding, future checkpoints,
suffix/peer preservation, follower/election behavior, both sync failures and six
SIGKILL boundaries recovering only complete old/new decisions. Five guard
removals fail behaviorally (prior identity, committed bound, term, application
identity publication, suffix preservation); seventeen checkpoint/install
regressions, the sanitizer daemon build and static analysis also pass.

### Guarded local controller publication

`yd_raft_cluster_application_capture` owns a logical capture under application
serialization without a quorum proof. `yd_raft_cluster_application_select`
consumes no image ownership: its caller exclusively owns the image and must
keep the controller alive until return. It pins the original generation, makes
a compact archive, and restores/verifies a separate generation through the same
durable named-directory path as remote installation. This work runs outside the
application lock; ordinary writes can proceed. Local and remote preparations
share one admission slot. No files are deleted on success or failure.

Final admission waits for prepared/in-flight writes and requires the exact
original generation, source inode/view and applied metadata. Runtime serialization
then compares that generation's journal-selected identity and atomically binds
the new snapshot/application identities. Its non-failing callback moves the live
pointer immediately after durable success, while both owners remain serialized.
Recovery and every prepared generation retain their selected identity, allowing
later recompaction before or after restart. Old owned views retain the previous
application until their last release, including across controller shutdown.

The explicit `published` result records live ownership transfer. Stale sources
and cancelled work reject without a journal decision. Persistence uncertainty
fences participation without transferring the pointer; all archive/generation
data remains available to recovery. Healthy followers and isolated members may
compact their already committed state, but gain no leadership, quorum proof,
read/write permission or renewed election deadline.

The timeout bounds initial/final admission, not artifact I/O. Progress callbacks
run outside owner locks and must not reenter image methods or selection. Graph
validation now polls between units as described below. The final journal prefix
scan remains indivisible; after final admission the durable decision cannot be
cancelled. Join calls before closing
the image/controller. This is a private integration bridge, with no automatic
application worker, public maintenance endpoint, reclamation/retention policy,
pin/space budget or sustained-load qualification.

Thirteen actual TLS replica-set cases pass ASAN/UBSan and fully instrumented TLS
TSAN: every-member switching, exact source/receipt recovery, ordinary checkpointing
after selection, old views through shutdown, repeated selection before/after
restart, writes in artifact/prepared phases, in-flight write exclusion, cancellation,
both journal sync failures, runtime fencing and minority denial. Six guard removals
fail behaviorally (final source, write exclusion, pointer transfer, recovered/live
identity and runtime stopping). Ten existing remote installation/transfer/view
regressions and one selected-generation HTTPS daemon case pass. Static analysis,
the sanitizer daemon build and a scoped independent static review also pass.

### Explicit obsolete application retirement

The private `yd_raft_cluster_application_select_outcome` bridge exposes typed
outcomes for maintenance callers; existing boolean selectors remain wrappers.
It distinguishes invalid arguments, unavailable controllers, occupied admission,
stale images, explicit cancellation, admission timeout, artifact preparation
failure and an unconfirmed runtime decision. Successful selection is separate
from physical retirement. Outputs clear before validation, and only successful
durable publication may return the optional retirement ticket below.

Cancellation identifies a callback rejection before the indivisible decision;
it does not authorize deletion of prepared files. An uncertain decision requires
preserving every artifact even when `published` is false. Busy/stale/timeout
results may permit later admission with a current image, while preparation errors
must not be treated as ordinary churn. No result grants cleanup authority or
enables an automatic worker. Callers still exclusively own images and tickets
and join operations before closing their controller.

`yd_raft_cluster_application_select_retaining` optionally returns an exclusively
owned retirement ticket for the exact previous application. Only successful
durable publication grants a ticket; stale, cancelled or uncertain decisions
grant none. The original selector remains a preserving wrapper. Preparing the
ticket acquires independent descriptors without inheriting the native ownership
lock. Final serialized admission seals native metadata after pending writes
drain, including physical tails left by rejected preparations.

`yd_raft_cluster_application_retire` requires the matching live controller,
cluster/root identity and a healthy different selected generation. It reserves
the shared selection slot while leaving new-generation writes free to proceed.
It returns 0 while old controller views/workers or native pins, checkpoints and
copy-source captures retain ownership. Closing those references allows the
independent native descriptor to acquire the exclusive file lock. Callers retry
busy tickets; calls must join before ticket/controller close.

Cleanup uses descriptor-relative, no-follow operations, exact inode/metadata
checks and bounded directory inspection. The original application contributes
only `.yamora-disk`; a named generation contributes its native and verified
manifest files. Each file is claimed individually into private random
`.retiring-application-*` custody, verified after the no-replace rename, then
removed only under the documented cooperative exclusion inside pinned custody.
Unknown/replaced objects are restored without overwriting another actor or
preserved for recovery. No directory shell is intentionally renamed or removed:
mkdir followed by open cannot prove directory birth, even for an empty private
same-user replacement. Exact identity proves location, not shell disposability.

Both claim namespaces and each deletion are synced. Partial errors return -1
and retain the same ticket's precise retry state. Durable completion returns 1
and closes removed file descriptors so disk blocks become reclaimable. It leaves
empty custody and named-generation shells in place. Completed live tickets can
prove those exact empty shells to the retained-admission API before and after
inventory. The [one-shot owner](application-compaction.md) holds a fixed bounded
registry; no prefix, age or reopened shell grants an exemption. Closing a ticket
performs no deletion and can outlive the controller. Crash/restart loses the
live proof: unknown leftovers block maintenance and remain recoverable.

The retirement suite checks native pages and manifests, held-reader types,
every remaining file-unlink/sync boundary, custody birth swaps, replacements,
rejected-write tails, concurrent writes, uncertain decisions, descriptor release
and crash/restart preservation. Directory unlink requests are rejected by the
asynchronous test fixture. The sanitizer profiles include fatal ASAN/UBSan and
fully instrumented TLS ThreadSanitizer. Automatic scheduling, global pin/space
budgets, archive/crash retention and receipt expiry remain separate work.

## Cooperative application validation

`disk_validation.h` defines an operation-local cancellation state used by the
cancellable variants of native, change-feed and consensus application validation.
The original functions remain complete, non-cancellable wrappers. Every graph
key/receipt, collection, document, index entry, retained history frame and frame
operation polls before processing. A rejected callback sets sticky `cancelled`;
the scan returns false, frees its cursors/records and performs no writes. Retry
with fresh state; its `cancelled` field is scan-owned output. Observe external
atomic stop flags through the callback. Cancellation proves neither validity nor
corruption.

Copy/catch-up, archive capture, restore, candidate preparation and selected-root
recovery propagate their existing callbacks into these nested scans. Logical
captures keep their pinned view and never recapture a later application. Copy
validation repeats SOURCE 0 for the source, SOURCE 1 for prior-image validation,
and VERIFY 0 for the resulting graph. Snapshot callbacks repeat their surrounding
physical byte counters; `done == total` alone does not mean an operation finished.
Callbacks must not reenter the operation or take owner/runtime locks. Individual
bounded records (including YAML parsing/index expansion), tree traversals and
syscalls remain indivisible; this provides cooperative cancellation, not a strict
wall-clock shutdown deadline.

Cancelling before catch-up mutation preserves a healthy prior image, including
validation and comparison of an unchanged generation. Integrity failures still
fence candidates; any failed mutation attempt fences the image even on
cancellation. Separately pinned old readers and created artifacts survive; failed
restore retains its initialization fence and cannot become selectable.

Focused tests cover all six scan phases at three cancellation boundaries through
serialized, pinned and native validators, sticky cancellation without further
callbacks, unchanged/changed image comparisons, empty archive preservation,
restore fences, and read-only retry of candidate/selected recovery both at and
beyond a snapshot. See `test_raft_application_validate.py`,
`test_raft_application_copy.py`, `test_raft_capture.py`,
`test_raft_snapshot_restore.py` and `test_raft_selection.py` in `yamora/tests/`.


## Background journal-copy foundation

The private `consensus/journal_copy.c` layer captures exact durable core metadata
and an owned immutable native reader under core serialization. Copying then runs
without the source core or its lock and can outlive source close. It scans and
validates every retained entry/term pair and the canonical metadata, streams only
that logical suffix into an existing empty private destination, then compares
the result against the source using a fresh independent read cache. It also
reads back the selected native superblock. Exact command bytes, term/vote/commit,
uncommitted suffix, checkpoint archive and selected application generation survive;
unreachable tail keys and old physical pages are excluded from the new copy.

The captured reader, private candidate writer and independent readback handle
each have a bounded cache; transactions buffer bounded private pages and
individual records retain the existing command-size limit.
Readback comparison can hold one source and one destination record at a time.
Progress can cancel between records in source validation, copying and readback.
The candidate owns its pinned directory and native file lock, even after pathname
replacement. Source validation precedes file creation. Any created native file
keeps its durable `.yamora-initializing` fence on success and failure. Core startup
rejects that fence before opening or creating journal data.
Closing a candidate preserves its files and fence for diagnosis.

The returned candidate is read-only. A serialized current-source observation
checks its original inode, complete native view and exact metadata; this is no
quorum or publication proof. Source writes make the candidate stale. There is
no maintenance policy, live file switch or physical deletion in this layer;
those remain necessary to turn this copy foundation into online reclamation.

Nine native cases cover three metadata encodings, empty/checkpoint-only journals,
selected generations, committed/uncommitted suffixes, dead tail removal, a 3 MiB
binary command with threaded source writes, source-close and directory-rename
lifetime, strict destination checks, cancellation in all three phases, each of
six candidate sync faults, checksummed metadata/command damage, header readback
and identical state on a different inode. ASAN/UBSan and ThreadSanitizer pass.
Removing metadata, command-byte, header, inode or startup-fence checks makes its
targeted case fail. This is development evidence, not production qualification.

Private runtime capture and current-source bridges serialize those short local
operations under the runtime mutex. A successful capture owns no runtime pointer;
validation/copying and its progress callbacks run after releasing that mutex.
Stopping runtimes reject capture and current-source observations. These operations
do not contact peers, renew election timers or issue/observe read-proof sequences.
Three actual mutual-TLS cases hold a follower copy while its journal receives new
commits, reject fresh quorum proof despite a current minority-leader candidate,
and complete a held copy after runtime shutdown before releasing file ownership.
A postpublication clock-failure case also rejects capture on a stopped runtime
whose underlying core has not failed. ASAN/UBSan and fully instrumented TLS
ThreadSanitizer pass; bypassing the stopping guard must fail that last check.

`yd_raft_journal_catch_up` can now advance a private candidate from a newer owned
capture of the same source inode. It validates source state before any candidate
write, removes keys superseded by a newer checkpoint or shortened tail, and
compares records and scalar values so unchanged data retains its original offsets.
The candidate's private writer publishes one transaction; an independent reader
then compares the complete result and reads back its native header before the
candidate origin advances. Older captures and different source inodes reject
without changing a valid candidate. An identical capture verifies without another
publication. No operation contacts peers or changes the source.

Callers must join borrowed candidate readers before catch-up and reacquire that
borrowed handle afterward. Independently owned pins retain their original view.
Failed/cancelled candidate updates or incomplete readback disable further use of
that candidate while preserving its files and initialization fence. A failure
during the preliminary source scan leaves the earlier candidate intact. Catch-up
appends CoW pages; it does not shrink the candidate or delete old pages. Live
selection still needs a final serialized source check and a durable recoverable
file transition, followed by a separate reclamation lifecycle.

Five additional cases cover bounded delta writes beside an unchanged 3 MiB
record, checkpoint advancement, conflicting pending entries, shortened tails,
selected-generation metadata, writes during all three phases, foreign/older
capture rejection, both publication sync faults and cancellation. All fourteen
copy/catch-up cases pass ASAN/UBSan and ThreadSanitizer. Guard removals check delta
reuse, inode/age binding, failed-candidate exclusion and superseded-key pruning.
The three actual TLS lifetime/replication/minority cases still pass both sanitizer
profiles. These tests do not enable automatic compaction or establish a sustained
throughput guarantee.

## Prepared journal publication links

The private `consensus/journal_publish.c` preparation step pins the journal root,
checks its existing native file against the candidate's source inode, and creates
durable hardlinks for that file beneath `.yamora-journals/old-*` and for the
verified candidate at a fresh `.prepared-journal-*` root name. It synchronizes
the retained directory/root before linking, the retained link before proceeding,
and the prepared root link before returning. Source and candidate must share a
filesystem. The selected `.yamora-disk` name and core remain unchanged.

The operation runs outside core serialization and owns only pinned directory
descriptors. It reserves a borrowed candidate until publication close; catch-up
and duplicate preparation reject during that reservation. Close releases the
reservation and descriptors while preserving all files and links. Old hardlinks
can follow source writes until selection succeeds; preparation is not an
immutable backup. A source update makes the prepared state stale.

The serialized observation checks the exact source generation/metadata, root
directory, retained directory/link, candidate/fence and prepared link identities.
A different directory aliasing the same source inode cannot pass this root check.
Five native cases cover these bindings, writes during all four preparation syncs,
each sync failure followed by retry, pinned-root rename, strict private roots and
replaced prepared/retained links, retained directories and candidate fences.
ASAN/UBSan and fully instrumented crypto ThreadSanitizer pass. Removing source,
root, reservation or final preparation-sync guards fails the targeted checks.
Preparation itself performs no selector rename or ownership transfer.

The private final publisher rechecks all bindings under core serialization, then
atomically renames the prepared link over the standard native filename and syncs
the pinned root directory. Once the selected inode is observed, it transfers the
candidate's writer into the same core and closes the former writer. Logical
metadata, role and peer progress remain unchanged; owned historical readers keep
their old generations alive. The candidate becomes unavailable for further use.
A stale preparation rejects without mutation or fencing. An uncertain rename or
failed final sync fences participation until reopen. Its separate `published`
output records ownership transfer even on failure, including a rename that took
effect but reported an error; callers must not infer durable success from it.

Four added native cases cover unchanged core/peer state, historical-reader
lifetime, new writes/reopen, stale rejection followed by catch-up, final sync and
both uncertain-rename outcomes, and process kills at four switch boundaries.
All nine preparation/selection cases pass ASAN/UBSan and crypto-instrumented
ThreadSanitizer. Removing source, ownership, final-sync or fencing guards makes
the targeted checks fail. Process-kill recovery is not a hardware power-loss
qualification. All old and candidate links/files are preserved.

Private runtime wrappers now pin the journal root under its mutex, prepare links
after releasing it, and serialize only the final selector. They retain no borrowed
core/root pointer, reject stopped runtimes, stop participation and wake waiters on
durability fencing, and change neither election deadlines nor quorum proof.
Callers keep the runtime/image alive through preparation and close the publication
before its image. The complete copy/catch-up/prepare work stays outside the mutex.

Six actual mutual-TLS cases switch every member before new commits and failover,
reject source writes after preparation then catch up/retry, fence a final-sync
failure while retaining selected ownership across reopen, reject fresh proof in a
minority despite successful selection, reject both preparation and selection on a
stopped runtime with a healthy underlying core, and commit twenty writes while a
preparation sync is held. ASAN/UBSan and fully instrumented TLS ThreadSanitizer
pass. Removing either runtime stop guard fails the targeted check.

An explicit private retirement operation now removes only the publication's
verified old-file hardlink and its candidate-directory native link, outside core
serialization. A successful final selection/root sync is mandatory; `published`
alone grants no retirement authority. It checks the still-selected inode and all
remaining obsolete names before mutation, then syncs the retained and candidate
directories after their respective unlinks. It preserves the selected native
filename, initialization fence, directories, unknown files and all uncertain
artifacts. Missing obsolete names permit retry after interrupted cleanup. Cleanup
errors do not fence the selected core or undo its durable decision.

Owned historical readers/captures remain usable after the last old-file link is
removed; storage becomes reclaimable when their last descriptor closes. The
native fixture verifies a smaller selected file, zero links on the old reader,
one selected-file link and unchanged historical command bytes. Fifteen native
cases pass both sanitizers, including uncertain-selection rejection, replaced
paths, all six unlink/sync fault outcomes with live writes between retries,
writes during both cleanup syncs and five process-kill/restart boundaries.
Removing durable-selection, obsolete-inode, selected-inode or final cleanup-sync
guards fails the targeted checks. Actual TLS cases retire every member before
new commits/failover, retain uncertain artifacts, and commit twenty writes while
a retirement sync is held; both sanitizer profiles pass. Crash leftovers remain
preserved for diagnosis; there is no directory sweep, archive/generation removal
or automatic maintenance policy yet.

Unattempted preparations can now cancel outside serialization after source
writes make them stale. Cancellation verifies the still-selected source inode,
candidate/fence and both owned links, then unlinks the prepared root name and
extra retained source link, syncing each directory. It preserves the active
journal and the candidate's original fenced file. Publication close releases the
reservation so that candidate can catch up and prepare again. Missing obsolete
names allow an exact retry after partial cleanup. A sticky attempted-selection
flag rejects cancellation after any rename attempt, including one that reported
failure without selecting the candidate; uncertain artifacts remain untouched.

Nineteen native cases pass ASAN/UBSan and crypto-instrumented ThreadSanitizer,
including stale publication rejection/cancel/catch-up/reselection, all attempted
selection outcomes, six cancellation unlink/sync faults with intervening writes,
replaced source/fence/link identities and five cancellation kill/restart
boundaries. Removing attempted-selection, source, obsolete-inode or cleanup-sync
guards fails targeted checks. Four actual TLS cases cover stale/held preparation
retry, uncertain-selection rejection and twenty commits during held cancellation
sync followed by catch-up, retirement and restart; both sanitizer profiles pass.
This closes the temporary-link lifecycle for a bounded retry. The opt-in
[application worker](application-compaction.md#automatic-worker) now schedules
bounded operations; crash-leftover sweeping remains unimplemented.

## Bounded local journal compaction

The private `consensus/journal_compact.c` operation now assembles owned capture,
verified copy, catch-up, prepared selection, retirement and generated-directory
cleanup. It pins a private `.yamora-compactions` container under the runtime's
exact journal root, then performs directory creation/sync and artifact work
outside the runtime mutex. Only final selection uses runtime serialization.
Positive source-size and minimum-savings thresholds avoid unnecessary selection;
cache bounds are 32 KiB..1 GiB and selection attempts are 1..16. Source/candidate
sizes are captured native high-water marks. Catch-up uses newer owned captures;
every stale unattempted preparation cancels its own links before retry. The
operation stops at the selection-attempt limit and removes its verified unused
candidate. It preserves unverified artifacts and all attempted/uncertain outcomes.

Reports distinguish skipped, completed, stale, cancelled, failed and incomplete
work. `published` still records writer ownership even on failure; `retired`
records successful obsolete-link retirement. Completed also requires cleanup of
the generated candidate directory and its parent sync. Cleanup validates the
known child-directory/native/fence identities and rejects unknown files. There
is no sweep of other directories or crash leftovers. Errors after durable
selection preserve the active writer, and retirement/cleanup errors do not fence
otherwise healthy participation. The caller keeps the runtime alive and joins
the complete operation before runtime destruction.

Thirteen actual mutual-TLS cases pass ASAN/UBSan and fully instrumented TLS
ThreadSanitizer. They cover every-member reclamation/new writes/failover, invalid
options and both size thresholds, writes after preparation, bounded stale retries,
cancellation before/after preparation and after durable selection, selected
ownership at selection/retirement sync failures, a failure on the second attempt,
unknown files and replaced staging directories, untrusted staging paths, shutdown,
a runtime fence during progress, and cancellation inside the unverified copy.
The last case retains its fenced candidate while the active journal keeps writing.
Five guard removals fail targeted checks; six existing runtime selection cases
also pass. Each attempt resets its result so a later failure cannot inherit a
previous stale outcome. Progress uses an atomic stop observation before/after
callbacks: it never takes the runtime mutex while a private native writer mutex
is held. Callbacks report/cancel only and must not reenter database methods.

This private one-shot operation grants no quorum or election authority. The
opt-in controller below supplies scheduling, with no public maintenance endpoint.
Crash-leftover sweeping, archive/generation retention and sustained production
load qualification remain separate work.

## Opt-in owned journal compactor

`yd_raft_cluster_compactions` enables one worker after recovered startup; it is
disabled by default. The daemon's strict optional `compaction` map is validated
before storage creation. Positive source/savings thresholds, a 100..3,600,000 ms
interval and 1..16 selection attempts bound work; the replacement preserves the
configured journal cache. This is physical local journal maintenance on any
healthy member, independent of leader/quorum availability. It does not authorize
reads, proposals, elections or checkpoint publication.

The worker borrows the runtime and owns its cancellation flag, thread, monotonic
condition variable and status. Every attempt calls the verified one-shot operation
outside the status mutex. Progress only observes the worker's atomic stop flag;
it never calls runtime/cluster/storage methods or takes a status lock under a
native writer mutex. The controller marks stopping, shuts down incoming work,
then cancels/joins the compactor and checkpointer before runtime destruction.
Native syscalls are indivisible and may outlast a requested shutdown.

Skipped/stale work waits another interval, with no overlapping attempt. Failed
or incomplete work disables scheduling until restart and retains diagnostics;
independent runtime cancellation also disables it. Constructor/thread failure
leaves no worker and permits enable retry; duplicate enable is rejected. Status
reports saturating process-local attempt/outcome counters and last-report sizes
and result, not a quorum proof or disk-usage total. An own shutdown cancellation
does not increment failed; incomplete work after selection remains a failure.

Six actual mutual-TLS controller cases pass ASAN/UBSan and fully instrumented
TLS TSAN: every-member reclamation with exact-source/receipt/failover/restart
preservation, invalid/duplicate enable and thread-creation retry, minority safety,
continued writes during a held copy followed by shutdown cancellation, uncertain
selection sync and incomplete retirement with scheduling disabled. The six cases
fail behaviorally with the worker absent. Actual HTTPS daemon cases cover omitted
and zero defaults, strict invalid fields before native files, configured work on
every member with a minimum journal cache, and receipt recovery after failover.
Application pages, logical retention, archives/generations and crash leftovers
remain separate requirements.

## Owned cluster read views

`yd_raft_cluster_view` obtains a fresh majority confirmation, waits for application
through that position and captures a native view while the controller still
serializes application access. The owned handle pins a reference-counted
application generation together with the exact immutable native view. Queries
must use `yd_raft_view_disk` with `yd_raft_view_value`, then close the view after
all reads finish. Reusing a handle reads its captured state; a fresh read requires
a new quorum-confirmed capture. Followers and isolated leaders cannot capture a
new view.

The handle retains no cluster or runtime pointer. Its reads may finish after
cluster shutdown; the last owner/view release closes the application and releases
its native file lock. The controller stops and joins application and peer workers
before dropping its generation reference. A view's readers must join before
closing that handle, and external cluster calls must join before cluster close.

Three actual mutual-TLS cases preserve exact captured YAML across later writes
and cluster close, reject fresh follower/minority captures, and concurrently read
and release eight handles after shutdown. Reopening the application in the same
process proves that the final reader released file ownership. ASAN/UBSAN and fully
instrumented OpenSSL TSAN pass. Bypassing reference retention, quorum confirmation
or the captured view in disposable builds must fail these checks.

`yd_disk_api_read_at` materializes stateless document, collection, catalog, query,
aggregation, search and finite feed responses against an explicit captured native
view. It creates no API workers or mutable replication/index-job state and rejects
mutations, replication, index jobs and continuous streams. The ordinary standalone
API uses the same dispatcher with its current view. A caller must retain its disk
or owned application view for the complete materialization call.

`yd_raft_cluster_query` acquires a fresh confirmed owned view, builds the complete
response at that root and releases the view before returning the owned response
bytes. Its timeout covers quorum confirmation and application acquisition; native
query limits govern execution after capture. The daemon routes all cluster data
reads through this interface and never caches the initial application disk or
starts an independent disk API worker for a cluster. Health, statistics, metrics
and readiness metadata copy native values under controller ownership. Local
operational statistics do not assert quorum; readiness still requires a fresh
confirmation. The cluster reports zero continuous-stream capacity because that
operation remains unsupported in this profile. The compatibility borrowed disk
accessor remains for isolated native fixtures, with no daemon caller.

Three native ASAN/UBSAN and TSAN cases compare exact historical responses across
all supported read families after source/catalog changes, reject stateful calls
without publishing writes and read concurrently during current writes. HTTPS
checks cover native metadata on every member, gzip source fidelity, indexed
queries, aggregation, full-text search, catalog/list/feed reads and minority
rejection. Live application replacement uses the guarded installation and local
publication paths above; owned readers retain their captured generations.
