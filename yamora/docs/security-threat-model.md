# Security boundaries and qualification

This model covers the Session 3 modules and their adoption by the native
standalone daemon and storage engine. The supported boundaries are local
document/field authorization, pinned HTTPS enterprise identity adapters,
bounded profile-5 encrypted storage and a distinct-UID protected audit helper.
Each profile refuses unsupported combinations. External credential qualification
is excluded by the owner's instruction to skip credentials; local fixtures do
not establish live provider interoperability.

## Assets and adversaries

Protect exact authored YAML, hidden document paths, local role assignments,
administrative authority, access credentials, envelope keys and plaintext,
database receipts, and the audit key, chain and independently protected head.
Content fingerprints are sensitive whenever their source includes unreadable
fields. Availability and bounded resource use apply to every untrusted parser,
transport, recovery scan and provider call.

Consider unauthenticated network clients, valid principals with insufficient
grants, forged or stale identity-provider messages, a hostile provider response,
corrupt or substituted encrypted artifacts, stolen data files without keys,
and a compromised daemon UID attempting to forge or roll back audit history.
Root, kernel, helper-UID compromise and malicious authorized key custodians are
outside the distinct-UID audit protection. Authentication alone grants no local
role, administrative privilege or permission to select a key provider endpoint.

## Credential selection and provider transport

Explicit bearer selection is terminal. Static bearer, certificate and OIDC
authority must never be unioned. A mapped principal narrows local collection
grants; external claims do not create roles. Authenticate before durable receipt
lookup, including cached replies and detached-job attachment. Established
connection context belongs to its selected immutable policy generation.

Identity transport uses operator-pinned origins, numeric addresses and trust
roots, bounded deadlines and response sizes, with no redirect or discovery-led
SSRF expansion. OIDC discovery must agree with the configured issuer and pinned
endpoints. Access tokens and ID tokens have distinct verification profiles;
ID tokens require the expected nonce and do not become access tokens. Check
signature, key selection, issuer, audience, client/subject mapping, time and
scope before adopting authority. Introspection failure is a denial or temporary
unavailability, never an offline-success fallback. Revocation acknowledgement
does not imply that every independently cached bearer has become invalid.

AWS IAM authentication forwards the fixed signed GetCallerIdentity request,
binding the configured server identifier in signed headers. It must not act as
an arbitrary signed-request proxy. LDAP uses authenticated LDAPS and an exact
configured DN, with no search-filter construction from attacker input. Kerberos
delegates ticket and replay validation to the system GSSAPI provider and pins
the service identity; malformed, expired, wrong-service and replayed contexts
must fail. Provider-library presence is not a successful enterprise login.

Sockets must be close-on-exec and nonblocking. Cleanup must survive deferred
cancellation, peer close/SIGPIPE and clock failures. Raw tokens, passwords,
tickets, keys and provider response bodies must never enter diagnostic output.
Native fixtures exercise local protocol behavior; actual Google, AWS,
directory and realm qualification requires credentials and remains unclaimed.

## Field and document authority

Masks only narrow collection grants. Validate all query dependencies before
execution, including predicates, sorts, projection, count and explain. A
nonmatching filter must not hide an unauthorized dependency. Exact document
selectors cannot authorize scans, enumeration, counts or sibling mutation.
Patch authorization checks every referenced path and operator before dispatch;
transaction authorization checks every member before any publication.

Whole-source reads, replacements, deletes, aggregation, search, export, change
feeds, incoming replication and restore require the corresponding complete
document or collection authority. Foreign lookups require both source and
foreign collection grants. Global administration remains separately authorized.
Redaction must not parse and rewrite authored YAML as a substitute for denying
an unauthorized whole-source read.

Native revisions and ETags are unkeyed fingerprints of complete sources. A safe
boundary removes internal top-level JSON metadata, HTTP fingerprint headers
and binary metadata from masked replies, including denials and replayed
receipts. Preserve nested user properties and authorized source bytes. Capture
the response classification during authentication and carry it through reply
encoding; never reauthenticate at send time or use process-global mutable
request state. Before authentication, malformed requests and anonymous endpoints
must use safe headers whenever the policy contains masked principals.

Removing metadata does not remove precondition oracles. Deny masked global
revision pins, revision-dependent pagination, source-hash If-Match, transaction
ETag and creation/existence preconditions until a separately qualified private
cursor/conditional protocol exists. A failed response filter must discard the
original body and fail closed, including after binary fallback construction.
The daemon applies these rules to HTTPS and binary response construction,
including early denials, cached replies and binary fallback paths.

## Encrypted artifacts and key lifecycle

Use system AES-256-GCM with a fresh random data key and nonce for each envelope.
Authenticate the versioned header, key label and wrapped data key. Bind the
provider wrapping context to the header and key label. The reader supplies the
expected store ID, object ID, generation and kind from trusted storage state;
copying those values out of the untrusted envelope defeats substitution
protection. A valid tag alone is not freshness or rollback evidence.

Rotation decrypts under the old provider and reseals under the new provider
with a strictly greater trusted generation and fresh key/nonce. It does not
reuse a GCM nonce with changed associated data. Historical wrapped-key versions
remain needed for retained backups. Missing keys, wrong contexts, wrong kinds,
wrong generations, truncation, provider errors and authentication failures must
not publish plaintext or silently fall back to an unencrypted format. Preserve
the last recoverable artifact if publication is uncertain.

The local key ring, AWS KMS and Vault Transit adapters share the envelope
contract. Provider transport callbacks must provide authenticated TLS,
operator-selected endpoints, authentication, deadline and bounded responses;
the callback interface alone supplies none of those guarantees. Hold the
documented cancellation-disabled state through adopting outputs and cleanse
temporary plaintext/data keys on all ordinary failure paths. A pending cancel
must not bypass cleanup during wrap, unwrap or rotation.

The encrypted profile keeps the entire bounded native image in a locked,
nondumpable anonymous file. Named publication stages, selected storage and
physical backups contain ciphertext. Native publication precedes receipt/view
release only after ciphertext sync, rename, directory sync and final binding
checks. Writer failure fences further writes and retains uncertain artifacts.
Pins keep memory, provider lifetime and root exclusion through their last close.
The allocation, including historical and aborted work, is at most 64 MiB;
every commit rewrites the full image. This profile is Linux standalone format 5.
Schema format 7, Raft format 6, retention, generic physical export/compaction
and unsupported maintenance modes refuse instead of creating plaintext.
Logical exports remain authorized reads whose receiving clients own their files.

The operator supplies the exact trusted store/object/generation/kind from
independent state and retains each backup's identity and keys. The daemon never
derives expected generation from ciphertext or rewrites that configuration.
Its default config loader supports a local keyring; KMS/Vault require a qualified
caller-owned transport through the library API and refuse in that daemon loader.
Native caches, caller inputs and decoded temporary buffers remain application
memory; deployment owns their swap/core policy. Neither this profile nor its
status endpoint provides an external monotonic rollback service.

## Audit delivery and recovery

The daemon UID must be unable to read the helper key or write, replace, chmod,
unlink or roll back its anchor or protected ancestors. Authenticate Linux peer
credentials before parsing application packets. Require exact canonical frames,
request IDs and helper incarnation; bind opaque handles to the originating
connection and reject duplicates, invention and cross-session reuse.

The helper acknowledges INTENT only after sink sync, external anchor publication
and identity rechecks. Dispatch requires that acknowledgement. Record explicit
NOT_DISPATCHED, RETURNED_SUCCESS, RETURNED_FAILURE or UNKNOWN; an HTTP status
does not prove a database commit. If finish publication fails after dispatch,
report uncertainty and preserve the durable database receipt. Do not retry an
operation merely because its audit acknowledgement was lost.

Startup success is recorded after worker/listener construction and before
binary data admission opens. Failed construction cannot leave a success record.
The helper remains unavailable to new dispatch on an unacknowledged completion;
cleanup joins runtime users before releasing storage. Detached jobs retain their
original copied identity and audit intent through actual terminal completion.

Disconnect reconciles outstanding helper tickets as UNKNOWN. Restart accepts
only the exact independently protected final anchor. Restricted recovery appends
and anchors one UNKNOWN at a time, never reconstructing tickets or success.
Torn frames, unanchored tails, stale anchors, dirty anchor namespaces and
substituted final inodes refuse restart or poison the owner. Same-byte inode
replacement is still substitution. Forked handles confer no writer authority.

Bounds cover packet size, connections, pending intents, records, segments,
bytes, sequence space and original caller deadlines, including mutex waits.
Segment rotation is quiescent. Capacity exhaustion stops new audited dispatch;
no automatic deletion, silent drop, overwrite or unprotected fallback is
permitted. Persistent authenticated connections may idle without losing their
live operation. Operators must provide a qualified retention/archive procedure
before exhausting finite capacity; this helper claims no remote immutable
retention or compliance framework.

## Combined runtime acceptance

Qualify successful operations before denials using the actual HTTPS, binary
and replica runtimes. Exercise receipt replay, queued/detached jobs, session
reuse, policy/certificate/provider/key rotation, malformed input and provider
failure. Verify that denied requests leave the database unchanged, safe replies
contain no fingerprints of hidden fields, and no secret/source content reaches
audit frames or process output. Key-loss/rotation/restore checks must use
independently reopened artifacts and trusted identity, not only in-process
round trips.

Use real helper and daemon-side processes with different UIDs, actual DAC
attacks and crash/restart reconciliation. Normal and fatal sanitizer builds
must pass. Behavioral controls must deliberately remove each essential guard,
fail at its named security assertion, then pass with the restored guard;
compiler errors, signals, timeouts and sanitizer failures are not valid reds.
Independent review findings remain open until their fixes and controls pass.

Executable coverage is split between `test_access_identity_daemon.py`,
`test_field_runtime.py`, `test_encryption_daemon.py`, `test_envelope_storage.py`
and the fixed managed `test_audit_privilege_boundary.py` launcher. The last suite
uses actual helper and daemon UIDs and independently verifies HMAC frames and
the protected anchor. It covers HTTP/binary source round trips, schema receipt
replay, a deliberately held detached index job, encrypted publication failure,
healthy-writer helper loss, startup failure and finite segment exhaustion.
Guard controls remove BEGIN admission, binary startup admission, identity expiry,
private response metadata and helper peer/custody/deadline checks. A behavioral
failure at the named assertion is required before a restored pass counts.

No combined encrypted schema/Raft/retention profile, live cloud/directory/realm
login, daemon remote-KMS transport, remote immutable audit archive, unlimited
retention or compliance framework is claimed. Refusing an unsupported profile
is part of the acceptance boundary, not interoperability evidence.
