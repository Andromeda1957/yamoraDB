# Authenticated storage envelopes

`src/security/envelope.h` is the version 1 native storage adoption contract.
It preserves arbitrary input bytes, including comments, scalar spelling,
whitespace and UTF-8 in authored YAML. It does not parse or rewrite YAML.

Each envelope encrypts one bounded unit with a fresh 256-bit data encryption
key (DEK), AES-256-GCM, a fresh 96-bit nonce and a 128-bit authentication tag.
OpenSSL supplies the AEAD implementation, `RAND_priv_bytes` for DEKs,
`RAND_bytes` for nonces and `OPENSSL_cleanse` for sensitive owned buffers.
The selected provider wraps each DEK under an independently retained key
encryption key (KEK). No plaintext DEK is serialized into the envelope.

The envelope/provider module is adopted by the bounded native-image profile
below and the daemon's explicit encrypted-storage selector. It never converts
an existing plaintext directory in place. Existing-store migration, consensus
journals and schema/retention profiles are outside this profile and refuse
encryption-mode startup.

## Bounded native-image profile

`src/security/storage_image.h` supplies the opt-in standalone API. It uses the
actual `disk.c` constructor, publication and pinned-view lifetime hooks; there
is no alternate document engine. Native and HTTPS daemon fixtures exercise
these hooks in normal and fatal ASan/UBSan builds.

| Entry point | Required behavior |
| --- | --- |
| `yd_storage_image_open_at` | Authenticate an exact trusted identity, load into locked anonymous storage, then open native profile 5; create only in an actually empty private root. |
| `yd_storage_image_disk` | Borrow the actual native engine; documents, indexes, hidden opaque records, change log and replica staging retain native transaction semantics. |
| `yd_storage_image_identity` | Return the current acknowledged encrypted publication identity; never infer it by trusting a ciphertext header. |
| `yd_storage_image_backup_at` | Copy the exact last committed ciphertext into a new empty private directory and return its trusted identity after file/directory durability and delivered-file validation. |
| `yd_storage_image_restore_at` | Authenticate and native-open a backup with its saved exact identity, then copy ciphertext into an empty destination. |
| `yd_storage_image_rotate` | Reencrypt the committed native image with a fresh DEK/nonce and higher encrypted generation, preserving native bytes. |
| `yd_storage_image_close` | Release the writer; native pins retain locked memory, namespace custody and borrowed provider lifetime through their actual last close. |

The profile accepts a page-aligned full native allocation limit from 8192 bytes
through 64 MiB. That limit includes CoW history and aborted work, not only live
documents. A small limit can reject a document much smaller than the ordinary
16 MiB native document limit. It also bounds a full-image rewrite on **every**
successful native commit; this is a finite profile, not a scalable encrypted
page cache or space-reclamation implementation. Allocation exhaustion refuses
the operation; there is no switch to plaintext or an unlimited profile.

Only Linux with working `memfd_create`, `mlock2(flags=0)`, `MADV_DONTDUMP` and
fixed-size file seals is supported. The complete configured anonymous file is
mapped and locked before native data enters it. Admission failure leaves no
named plaintext or weaker fallback. Locked-memory limits must accommodate the
whole configured extent and simultaneous restores/pins; the library does not
raise limits. The anonymous file mapping cannot be swapped while locked and is
excluded from core dumps. Other process allocations, including native caches,
caller source and temporary decoded envelope buffers, remain application memory
whose swap/core policy belongs to deployment. Process memory compromise is
outside this at-rest boundary. `mlock2` avoids sanitizer runtimes that silently
replace ordinary `mlock` with a success-returning no-op; the fixture independently
checks the exact anonymous mapping's kernel `Locked` size and `lo`/`dd` flags
in `/proc/self/smaps`. See [Linux memory locking](https://man7.org/linux/man-pages/man2/mlock.2.html)
and [LLVM's interceptor implementation](https://github.com/llvm/llvm-project/blob/main/compiler-rt/lib/sanitizer_common/sanitizer_common_interceptors.inc).

The root must already be private, caller-owned mode 0700. An independent root
descriptor holds an exclusive namespace flock. The only selected file is
`.yamora-disk`, containing an envelope with kind `YD_STORAGE_IMAGE_KIND`, rather
than plaintext native headers. Old native openers refuse those bytes. Publication
creates a private random `.yamora-sealed-<32 lowercase hex>` ciphertext stage,
completes and syncs it, verifies its bytes/binding, renames it over the selected
ciphertext, syncs the directory and verifies the final delivered bytes and
custody. Only then may native publish its view, receipt and waiter notification.
All sensitive native file writes, including private staging and rejected-write
tails, remain in the anonymous mapping. They never use named plaintext files.

Aggregation [disk spill](aggregation.md#disk-spill) is allowed with this
profile because it writes no plaintext: each request's unnamed spill file is
sealed block by block with AES-256-GCM under a random key held only in memory,
independent of the store's data and key-encryption keys. Configure the spill
directory outside the encrypted root.

A failed publication fences further native writes even when the old in-memory
view remains readable. After a failed rename/directory sync, the selected name
may contain either generation; preserve artifacts and resolve the uncertainty
using the independently saved expected identities and available backups.
Unfinished ciphertext stages are retained, never adopted or automatically
deleted. At most three old stage artifacts are admitted before another attempt;
capacity exhaustion refuses startup/publication rather than silently discarding
uncertain evidence. Unknown names, links, nonprivate objects and unsupported
namespace state refuse. Backups never overwrite an existing destination.

The encrypted generation is independent of native superblock generation:
fresh creation uses encrypted generation 1; each successful native commit and
rotation advances it once. Restart requires the **exact saved trusted identity**
from the controller or operator, including generation. Keep the identity of each
retained backup. A generation written beside ciphertext by the same daemon is
not an independent rollback anchor. This API neither invents one nor accepts
the envelope's own claimed generation as expected state. Restoring an old backup
must deliberately reconcile any external monotonic anchor.

Schema profile 7, retention enrollment/fences and cluster profile 6 refuse;
their persistent policy/Raft request-ID receipt semantics are not qualified by
an opaque-record preservation fixture. Generic native physical checkpoints,
compaction/copy and physical-root recovery exports refuse image handles so
they cannot create plaintext artifacts. The profile's ciphertext backup is its
checkpoint/recovery path. Logical client exports are still application reads;
clients control any files they write. Daemon startup must reject unsupported
maintenance/backup modes before creating their artifacts.

The private `storage_image_native.h` hook carries exact authenticated plaintext
length independently of anonymous-file capacity. Native header ends must be
validated against that authenticated length. Native descendants retain the
image context, and foreign-PID/cancellation/lifetime checks remain in force.
Every public operation requires cancellation already disabled through output
adoption and cleanup. Callbacks return normally without changing that state.

`src/security/storage_config.h` supplies the daemon adapter:
`yd_storage_config_open(path, data_dir, error, length)`, `disk`, `identity` and
`close`. The daemon selector is `--encrypted-storage-file PATH`.
`GET /v1/encryption/status` returns the nonsecret acknowledged identity
to the configured administrator. The config lives **outside** the data root
and is a current-UID, single-link, regular mode-0600 file of at most 16 KiB.
The operator trusts its parent path. Final symlinks, changed file identity,
unknown/duplicate fields, coercions and incomplete keyrings refuse.

All version-1 JSON fields are required: `version` (1), `mode` (`"create"` or
`"open"`), `store_id` (32 lowercase hex digits), `object_id` (64 lowercase hex
digits), `generation` (positive integer), `maximum_bytes`, `cache_bytes`,
`key_id` and `provider`. Numbers use ordinary integer spelling, without a
fraction or exponent. The loader never rewrites operator configuration or
derives the expected generation from the data file. The active local key id
must exist in the retained ring before opening a data directory.

The local provider is `{ "type": "local", "keys": [...] }`, with 1..16 exact
`{ "id": "immutable-id", "key_hex": "64 lowercase hex digits" }` entries.
Use independently generated, retained 32-byte KEKs; those quoted hex words are
schema placeholders. Keys are owned copies, and the JSON input, decoded arena
and temporary key entries are cleansed. Closing the config releases its writer;
provider cleanup is deferred until actual last native-pin/image release.

The optional `open_with_http` constructor accepts a caller-owned trusted
transport meeting `key_provider.h`. Only then can config select
`{ "type": "aws-kms", "key_arn": "full immutable ARN" }`, with matching
top-level `key_id`, or `{ "type": "vault-transit", "mount": "transit",
"name": "immutable-name", "write_version": 1 }`, with `key_id` equal to name.
The default daemon loader has no remote transport and refuses these modes
before native mutation. No credentials, token acquisition, automatic retry or
provider fallback are implemented by this config layer.

## Storage API

The caller supplies an immutable `YDKeyProvider` and a
`YDEnvelopeIdentity` containing a nonzero 16-byte store id, nonzero 32-byte
object id, positive 64-bit generation and positive 32-bit object kind. Identity
bytes are opaque: use stable native ids or collision-resistant hashes of
canonical storage identities, not unvalidated filesystem paths. Kinds separate
pages, manifests, journals and other storage purposes.

| Function | Contract |
| --- | --- |
| `yd_envelope_seal` | Encrypt exact bytes using a named KEK. |
| `yd_envelope_open` | Authenticate the exact externally expected identity and generation before releasing plaintext. |
| `yd_envelope_rotate` | Authenticate/decrypt, then seal under the new provider/key with a fresh DEK/nonce and strictly higher generation. |
| `yd_envelope_free` | Cleanse and free successful output using its exact returned length. |

Maximum plaintext is 64 MiB per envelope; a larger artifact must be split into
independently identified, ordered units under an authenticated manifest. Wire
overhead is 128 fixed bytes, up to 255 key-id bytes, up to 8192 wrapped-key bytes
and a 16-byte tag. All functions reset output pointer/length on failure. They
return `OK` (1), `INVALID` (0, rejected artifact/key) or `ERROR` (-1, caller,
resource, crypto or provider failure). Both failure results deny access; do not
fall back to plaintext, a different key or an earlier artifact.

The expected identity MUST come from trusted storage state independently of
the envelope. Reading its header to create an expected identity defeats the
relocation and generation checks. A ciphertext copied to another store,
object, kind or expected generation is rejected. Metadata and wrapped keys
are authenticated too; no plaintext escapes before the GCM final check.

Encryption cannot distinguish an entire valid old store and its old manifest
from a deliberate recovery. Detecting rollback of all daemon-controlled state
requires an independently protected monotonic checkpoint/anchor. This codec
does not create one or claim that a generation stored beside ciphertext is
such an anchor. The storage caller must define the trusted generation source
and its crash recovery protocol.

Inputs/outputs must be disjoint. Providers are immutable, do not cache DEKs and
may be shared by readers when their transport context is thread-safe. Exclude
provider destruction from concurrent calls. Caller-owned source YAML, keyring
entries and returned plaintext remain the caller's responsibility; cleanse
those buffers and prevent core dumps/swap exposure according to deployment
policy. Process memory compromise is outside at-rest protection.

Cancellation is an explicit adoption boundary: `seal`, `open`, `rotate` and
direct provider `wrap`/`unwrap` require pthread cancellation already disabled
on entry. Enabled callers receive `ERROR` with cleared outputs before secret
ownership. Keep cancellation disabled through adopting outputs and registering
their cleanup, or until cleansing/freeing them; callbacks must preserve that
state. Only then restore the caller's prior state. The library never enables
cancellation. Asynchronous cancellation is unsupported. Constructors and free
functions do not invoke user code or cancellation points. This protects private
stack keys, request/response buffers and decrypted rotation buffers while a
bounded provider network call blocks. A pending cancellation is delivered only
after the caller deliberately reenables it outside that ownership boundary.

## Canonical wire version 1

Integers use big endian byte order. Parsers bound every length before indexing
or allocation; trailing bytes, truncation, noncanonical reserved bytes,
unknown versions, algorithms and provider types all reject.

| Offset | Bytes | Value |
| --- | --- | --- |
| 0 | 8 | `YDENVP1` followed by NUL |
| 8 | 2 | Format version 1 |
| 10 | 2 | Algorithm 1: AES-256-GCM / nonce 12 / tag 16 |
| 12 | 2 | Provider 1 local, 2 AWS KMS, 3 Vault Transit |
| 14 | 6 | Reserved zero |
| 20 | 4 | Plaintext/ciphertext length |
| 24 | 8 | Expected generation |
| 32 | 4 | Object kind |
| 36 | 2 | Key-id length |
| 38 | 2 | Wrapped-DEK length |
| 40 | 16 | Store identity |
| 56 | 32 | Object identity |
| 88 | 12 | Data nonce |
| 100 | 28 | Reserved zero |
| 128 | variable | Key id, then wrapped DEK, then ciphertext, then tag |

Payload AAD is the complete fixed header, key id and wrapped DEK. The provider
wrapping context is SHA-256 of the fixed header with bytes 38–39 set to zero,
followed by the key id. This removes the unknown wrapped length during sealing
while binding the provider to format, algorithm, identity, generation, length,
key id and data nonce. The final payload tag authenticates the actual wrapped
length and bytes. These digests are metadata, not plaintext or secret material;
they may be visible in provider audit logs. Do not put document contents,
credentials or human identifiers into context metadata.

## Key providers

`key_provider.h` freezes the wrap/unwrap and trusted HTTP transport interface.
Every provider clears output on failure. The local provider copies up to 16
unique versioned KEKs into memory and wraps DEKs with AES-256-GCM using a
fresh nonce and the metadata digest as AAD. Its wrapped form is 12 nonce
bytes, 32 ciphertext bytes and 16 tag bytes. Provision local 32-byte KEKs with
an approved CSPRNG, keep the keyring outside the encrypted data directory and
back it up separately with restricted access. The module deliberately performs
no key-file discovery, environment inspection or automatic key creation.

The AWS KMS protocol adapter uses the documented symmetric `Encrypt` and
`Decrypt` operations. It pins a full key ARN, denies mutable aliases, sends
`EncryptionAlgorithm: SYMMETRIC_DEFAULT` and the exact metadata digest in
`EncryptionContext["yamora-envelope-v1"]`, then requires the returned `KeyId`
and algorithm to match. Standard canonical base64 and exact 32-byte decrypted
DEKs are required. Historical KMS-managed backing-key versions stay within
the opaque KMS ciphertext; deleting/disabling a KMS key can make its envelopes
unreadable.

The Vault Transit adapter pins a mount, key name and positive write version.
It uses `/v1/<mount>/encrypt/<name>` with `plaintext`, `associated_data` and
explicit `key_version`, then `/decrypt/<name>` with `ciphertext` and the same
associated data. Configure a non-derived, non-convergent `aes256-gcm96` key.
It validates the `vault:vN:` ciphertext prefix, canonical positive version,
bounded base64, and matching encryption response `key_version`. Decryption
accepts historical embedded versions; Vault's minimum-decryption-version and
key retention policy determine whether those remain usable. Key/mount names
are single bounded ASCII identifiers, so metadata cannot inject paths.

Both remote adapters have a required `YDKeyHTTP` callback. This is an explicit
trusted integration boundary: supply a supported SDK/HTTP transport that pins
the configured endpoint, performs AWS SigV4 or Vault token authentication,
verifies TLS trust and hostname, rejects redirects, caps reads and enforces a
whole-call deadline. The adapter supplies a fixed POST path, target and bounded
JSON body and requires status 200 plus a strict bounded JSON response. It never
discovers endpoints, obtains credentials, retries, follows redirects, parses
provider error text into diagnostics or substitutes a provider. Transport
credentials must never be placed in the envelope or logged with request bodies.
The callback and its context are borrowed for the provider's lifetime.

This callback contract does not constitute an included cloud authentication or
network client. Production adoption must supply and qualify that transport.
The checked-in fixture transport is test-only and accepts loopback with a
generated CA. External credentials were skipped by owner request; neither
real AWS KMS nor a real Vault deployment has been qualified by this work.

## Rotation, backup and recovery

1. Back up the current encrypted artifacts, authenticated identity/generation
   manifest and all KEKs needed by every retained generation. Keep keys and data
   in separately protected custody. Verify an isolated restore first.
2. Add/provision the new KEK version while retaining the old one. Construct a
   new immutable provider rather than changing existing readers' key mappings.
3. Call `yd_envelope_rotate` with the old trusted identity and a greater
   generation. It authenticates first and creates a fresh DEK and data nonce.
   It decrypts/reseals instead of changing AAD under a reused GCM key/nonce.
4. Publish the complete new artifact and trusted generation atomically using
   storage's durable commit protocol. On failure the original borrowed bytes
   are unchanged. An interrupted unpublished candidate has no authority.
5. Reopen using only the new expected generation and verify exact plaintext.
   Retain old KEKs until active objects, replicas, journals, snapshots and
   retained backups no longer reference them. Do not delete keys as a test.

An isolated recovery uses the backup's authenticated original identity and
generation, plus the original KEK/provider access. Missing keys fail closed;
recreating a different key under the same id does not recover data. Restoring
the original key does. Recovery to another storage identity requires opening
under the authenticated original identity and sealing a new envelope; copying
raw ciphertext to a new identity is rejected. An operator-approved recovery
must also reconcile any independently protected rollback checkpoint.

## Evidence and limits

`test_envelope_storage.py` exercises actual native commits, indexes, opaque
records, pins through writer close, concurrent writers, encrypted restart,
generation checks, backup/restore, rotation, custody and publication failures.
`test_encryption_daemon.py` exercises the actual HTTPS selector, exact source
round trips, status, restart and rejection of unsupported profiles/configuration.
`test_audit_privilege_boundary.py` combines encrypted native publication with
the distinct-UID helper, including uncertain publication and helper loss before
dispatch. These finite-profile tests do not qualify schema, Raft or retention
storage or a remote key transport in the daemon.

Run `python3 -m unittest yamora.tests.test_envelope` in the managed task runtime.
Its default native builds use fatal ASan/UBSan and leak detection; set
`ENVELOPE_SANITIZER=none` for normal compiler verification. It exercises exact
authored YAML bytes, distinct fresh envelopes, missing/wrong/restored keys,
generation-advancing rotation, rejected old-generation replay, failed rotation
preservation, every wire byte's tampering, every truncation, size/configuration
bounds, output clearing and crypto failures. Temporary guard mutants must fail
before the restored implementation passes; intentional mutant assertion exits
disable only leak detection because they bypass harness teardown.

Independent Python `cryptography` AESGCM loopback TLS services validate real
native adapter calls and enforce context binding. Tests cover successful
wrap/unwrap/rotation, untrusted TLS, permission/availability/redirect failures,
oversized/malformed/duplicate JSON, algorithm/key/version mismatch, invalid
base64 and wrong/short plaintext DEKs. Fixtures are synthetic protocol models,
not provider interoperability or provider authentication evidence.
Real pthread controls verify enabled callers reject, pending cancellation in
TLS provider callbacks remains masked through output cleanup, and cancellation
is observed after explicit reenable. Removing cancellation guards must fail
the same native contract check before its restored pass.

At-rest encryption does not hide artifact size, header identities, key ids or
access patterns, prevent deletion, enforce authorization, protect plaintext
temporary exports/backups, or establish immutable audit delivery/compliance.
Combine it with storage integrity/recovery, identity policy, protected audit
delivery and operational key custody at integration.

Protocol and primitive references: [OpenSSL EVP authenticated encryption](https://docs.openssl.org/3.5/man3/EVP_EncryptInit/),
[AWS KMS Encrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Encrypt.html),
[AWS KMS Decrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html),
[Vault Transit HTTP API](https://developer.hashicorp.com/vault/api-docs/secret/transit).
