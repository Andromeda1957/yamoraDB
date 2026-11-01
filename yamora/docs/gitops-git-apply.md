# Signed local Git publication

This optional GitOps slice publishes one reviewed Git-target tree as one SSH-signed
commit to one configured local publication ref. The database daemon and storage
engine acquire no dependencies. Existing DB apply and plan-v1 APIs remain unchanged.
Git apply consumes the pinned export; it makes no database requests and does not
attest to the live database revision or advance the common baseline.

## Dependencies and scope

Require system Git with SSH signing and interactive ref transactions, plus
`ssh-keygen` from `openssh-client`. Actual synthetic managed fixtures must prove
both capabilities. Missing tools/setup/cleanup failures are infrastructure failures,
never behavioral reds or skips. No host installs, agent/key discovery, external DB,
push, fetch, rebase, force, checkout, or index updates belong to this implementation.
Signing fixtures create ephemeral Ed25519 keys only in owned task scratch.

Accept an ordinary non-bare repository with a real .git directory, files ref storage,
no commondir, linked worktrees, object alternates or symlinked metadata/input paths.
Repository metadata is operator-trusted; concurrent replacement of its internals is
outside the boundary. Revalidate repository path/device/inodes and metadata before
object writes and while the ref transaction is prepared. The target is an existing
direct loose ref matching `refs/yamora-gitops/targets/[A-Za-z0-9][A-Za-z0-9_-]{0,63}`.
Reject a HEAD target, symbolic refs, packed-only targets, and unsupported storage.

## API

```python
prepare_git(repo, plan, *, expected_plan_id, target_ref, expected_old_commit,
            operation_id, commit_metadata, signer_policy, limits=None) -> PreparedGit
stage_git(repo, prepared, *, artifacts, expected_intent_id,
          signer_config, limits=None) -> StagedGit
publish_git(repo, staged, *, artifacts, expected_intent_id,
            expected_staged_id, limits=None) -> GitResult
recover_git(repo, staged, *, artifacts, expected_intent_id,
            expected_staged_id, limits=None) -> GitObservation
GitArtifacts(root)
```

prepare_git makes no writes. It freezes and independently rederives the complete
v1 or lifecycle v2 plan and rejects any document or collection conflict, including
conflicts outside Git targets. Its new
intent ID binds every field below. Caller-supplied expected IDs must come from
review, not be copied blindly from untrusted input. Stage persists before returning;
publish accepts only the exact persisted staged artifact. Recovery is read-only.
Dataclasses expose canonical to_dict/from_dict validation; no opaque metadata.

Prepared format `yamora-gitops-prepared-git-v1` has exactly format, intent_id,
plan_id, operation_id, plan, repository, target_ref, expected_old_commit,
commit_metadata and signer_policy. intent_id is SHA256 of canonical JSON excluding
intent_id, using the existing canonical serializer. operation_id is nonzero
lowercase 32-hex, a correlation ID rather than a durable deduplication key.
repository binds absolute path, repo/.git/objects device and inode identities,
and object format. OLD is a full lowercase commit OID of that format; its tree must
equal plan.current_tree. A different commit with the same tree fails OLD CAS.

commit_metadata contains author and committer (each name,email), timestamp,
timezone and message. Names are nonempty UTF-8 <=128 bytes; email is nonempty ASCII
<=254 bytes. Identities reject controls, angle brackets and email whitespace.
timestamp is an exact integer Unix second in 0..4102444800; timezone is +0000.
Message is UTF-8 <=16KiB with no NUL or CR. Generated trailers bind intent ID,
plan ID, operation ID, export SHA256 and source DB revision in a fixed order.
No apply-time clock or identity environment defaults enter the commit.

signer_policy has backend=ssh-ed25519-v1, principal, public_key and fingerprint.
principal is a literal ASCII identity without whitespace, wildcards or commas.
public_key is one comment-free canonical OpenSSH Ed25519 public record; fingerprint
must equal SHA256 of its SSH public blob. signer_config has only private_key_file,
a trusted operator-selected absolute regular file, no symlink components, owned by
the current UID and protected mode 0400 or 0600. Its path and bytes never enter
artifacts. Hold a validated file descriptor through helper teardown; an internally
constructed /proc/ADAPTER_PID/fd/FD path pins it without copying the private key.
An isolated allowed-signers file contains only the policy principal/public key
with namespace git. A valid signature must verify against this exact policy.
Encrypted/noninteractive-unusable keys fail; there is no unsigned fallback.

Staged format `yamora-gitops-staged-git-v1` has exactly format, staged_id,
prepared, tree_oid, commit_oid, commit_source_b64, objects and artifact_store.
artifact_store has exactly path, device, inode, intent_device and intent_inode.
Its identity is bound by staged_id and checked against the explicitly selected
store; artifact data never selects a path to open. Copies into another store or
replacement intent directory cannot discard a fence while retaining the staged ID.
Each object has
exactly type (blob/tree), oid, source_b64 and sha256; objects sort by type/OID and
are unique. The signed raw commit is saved verbatim, <=64KiB, signature <=16KiB.
staged_id hashes canonical JSON excluding staged_id. Validate canonical base64,
raw Git object hashes/types, exact expected tree, single OLD parent, metadata,
message and signature before CAS. Git SHA-1 uses gpgsig; SHA-256 uses the exact
gpgsig-sha256 header, validated according to pinned object format. Sources are never
parsed/reserialized as YAML.
Only target=git entries change: add requires absence; update/delete requires exact
original blob OID/presence/length/SHA256/bytes. All other tree records/subtrees,
including existing empty trees, remain intact; deletion removes only the document
entry, so deleting a collection's last document leaves its prefix as an empty tree.
A v2 collection decision with target=git also changes the prefix tree itself.
Creating it requires the prefix to be absent and records the resulting tree, empty
when the collection has no documents. Removing it requires the exact reviewed
prefix tree OID, which holds only the reviewed document blobs, and removes only
that entry without per-document edits; ancestors and siblings keep their records.
Each collection decision counts as one of the 128 Git changes, and its document
deletions count as none, so a collection of any size is one change. Generated objects form a bounded complete bundle for restoring those same
bytes/OIDs without signing again; original parent/baseline objects must remain local.
An empty intent has null commit/tree fields and an empty object list. It bypasses
signer/key/tool access, mutating Git commands and the attempt marker, and returns
no_git_operations with receipt=null and explicit pending_db.

## Artifact durability and one-shot fence

GitArtifacts requires an existing current-UID private 0700 directory outside the
repository. Pin its directory identity and use descriptor-relative no-follow
operations. Its layout is ROOT/INTENT/{intent.json,staged.json,publish.lock,
attempt.json,receipt.json}; filenames/intent are validated, never supplied by a plan.
Sources/artifacts are private data. Stage creates the INTENT directory mode0700,
fsyncs the new directory and ROOT, and creates publish.lock mode0600 before its
parent-directory barrier. Canonical JSON files are <=256MiB; raw generated objects
total <=64MiB. All JSON is strict with exact field sets and bounded reads.

Intent, staged and receipt files use exclusive owned temporary files, complete write, file fsync,
no-overwrite atomic installation, directory fsync, and identity revalidation.
Existing bytes must match exactly and be fsynced again before use; never replace.
There is no automatic cleanup of artifacts after uncertainty. Ephemeral workspace
cleanup occurs only after all owned groups have verified stop; signing-child stop
uncertainty preserves its workspace too. Temporary files may be removed only when
their exact ownership is proven. Published Git objects are never pruned by cleanup.

Hold an exclusive nonblocking flock on publish.lock throughout publication.
Refuse redispatch whenever attempt.json or receipt.json exists, including malformed
records or prior uncertain fsync/ack/status. Exclusively create attempt.json by name
before writing its contents. Retain even
an empty/partial marker on failure; its presence is a positive fence. Complete and
fsync its contents and containing directory before any commit command bytes can be
sent. A failure before admission cannot authorize commit. Failure while persisting
that fence cannot authorize sending commit. Receipt persistence failure remains uncertain and the fence remains.
These barriers rely on filesystem fsync semantics; they do not create a transaction
across Git/artifact filesystems, a DB/Git transaction, or a new power-loss guarantee.

## Fixed Git commands and environment

The writer has a private typed allowlist; do not widen GitReader's read-only runner.
Permit only the existing reader command shapes and the following exact additions
(OID/TREE/OLD/REF are validated typed operands):
```text
rev-parse --show-object-format
symbolic-ref --quiet HEAD
symbolic-ref --quiet REF
show-ref --verify --hash REF
cat-file commit OID
cat-file tree OID
hash-object -w -t blob --stdin
hash-object -w -t tree --stdin
hash-object -w -t commit --stdin
mktree -z
commit-tree TREE -p OLD -S
verify-commit --raw OID
update-ref --stdin -z
```
No caller-supplied argv/executable/config name is accepted. Messages, objects and
NUL-framed mktree records use bounded stdin. Tree/object writes use only generated,
validated records; raw restoration validates the entire staged bundle first.
Git and ssh-keygen resolve through os.defpath, with absolute fixed executables.
Direct ssh-keygen key generation is test-only and uses fixed Ed25519 parameters,
empty passphrase, no stdin/TTY, and a fresh owned destination.

Each Git argv prefixes --no-pager --no-replace-objects and fixed -c values:
core.hooksPath=/dev/null, core.fsmonitor=false, protocol.allow=never,
maintenance.auto=false, gc.auto=0, core.logAllRefUpdates=false, i18n.commitEncoding=UTF-8,
gpg.format=ssh, gpg.ssh.program=SYSTEM_SSH_KEYGEN,
gpg.ssh.defaultKeyCommand=, gpg.ssh.allowedSignersFile=OWNED_POLICY_FILE,
gpg.ssh.revocationFile=OWNED_EMPTY_FILE. Signing alone adds
user.signingKey=PINNED_PRIVATE_FD_PATH. Apply hooks/signing overrides to every
writer launch; never trust repository signing programs, defaults or trust files.

Construct a closed environment: PATH=os.defpath, LC_ALL=C, LANG=C, TZ=UTC,
HOME/XDG_CONFIG_HOME/TMPDIR in the owned private workspace,
GIT_CONFIG_NOSYSTEM=1, GIT_CONFIG_SYSTEM=/dev/null,
GIT_CONFIG_GLOBAL=/dev/null, GIT_TERMINAL_PROMPT=0, GIT_OPTIONAL_LOCKS=0,
GIT_NO_REPLACE_OBJECTS=1, GIT_NO_LAZY_FETCH=1, GIT_ATTR_NOSYSTEM=1.
Only commit-tree receives explicit validated GIT_AUTHOR_NAME/EMAIL/DATE and
GIT_COMMITTER_NAME/EMAIL/DATE. No inherited Git overrides, agent sockets, askpass,
display/TTY, SSH commands, credential settings or identity defaults survive.

## Prepared-lock CAS and cancellation

Use the documented [Git update-ref protocol](https://git-scm.com/docs/git-update-ref).
One interactive process, with NUL termination, receives:
```text
start\0
option no-deref\0
update REF\0NEW\0OLD\0
prepare\0
```
Require exact start: ok and prepare: ok acknowledgments. Git now owns REF.lock.
While it is held, revalidate roots/metadata/loose-ref identity, require
symbolic-ref --quiet REF to report a direct ref, show-ref to return OLD, and all
required commit/tree/source objects and the public signature to match the staged
artifact. Revalidate the artifact store and fsync durable attempt.json. Only then
may any bytes of commit\0 be written. A stale OLD or symbolic-ref substitution
aborts before commit. No-op input never opens this transaction.

Before commit can be sent, cancellation closes/aborts the transaction and verifies
group stop; no publication is claimed. Git documents abort on EOF before commit.
After commit may be sent, any failure/cancellation is uncertain. Success requires
the exact commit: ok acknowledgment, exit0, and verified whole-group teardown,
then durable receipt.json. The receipt records both artifact IDs, REF/OLD/NEW,
exact operation count, commit acknowledgment and verified stop. It acknowledges
that transition; it does not claim the ref cannot subsequently move.

Recovery never starts signing, object writing, a ref transaction, or a retry.
With a matching durable receipt it reports publication_recorded and the current
observation separately. Without one, exact NEW plus available verified objects
establishes publication_observed. Every other state, including OLD after ABA,
missing/unreadable refs or objects, remains publication_unresolved. If publication
holds the intent lock, report publication_in_progress. No current-byte comparison
proves a historical attempt was never applied.

## Bounds, process ownership and acceptance

Default logical budget60s, maximum300; each command gets min(5s by default,
remaining), maximum30s. Existing source bounds apply (1000 documents by default,
up to 50000 with `--max-documents`), capped here at 128 Git changes, 16MiB/source,
64MiB combined sources and 100000 tree entries. A prepared intent carries the whole
plan, so these byte caps keep it inside the 256MiB envelope; a collection tree
removal is one change at any document count.
Check bounded CPU phases before/after; do not claim preemption within serializers.
Bound every pipe while running: stderr8KiB, commit64KiB, small acknowledgments4KiB,
tree listings64MiB and blobs by declared checked size. Pump stdin/stdout/stderr
without deadlock, including the interactive transaction. No protocol logs or argv
printing expose source/key configuration.

Writer launches require the main thread for scoped SIGTERM handler ownership.
Writer and helper handles reject foreign PID/thread ownership before process
control. Admission stays pending from before process construction through handle
handoff, registration and verified teardown. Pending admission preserves the
workspace and signing descriptor before the key context unwinds; disable implicit
workspace finalization before launch. Missing handles and interrupted/idempotent
cleanup never establish verified stop or authorize redispatch. Dispatch checks each
registered helper's closed/admitted state independently of retention callbacks;
equal bookkeeping counts alone cannot establish safety. Clear admission
only after verified teardown. Keep the leader unreaped until group stop to prevent
PGID reuse.
Each launch starts a new session/group; protect constructor/handle publication
and teardown from repeated SIGINT/SIGTERM. A shared invocation can own both the
prepared transaction group and bounded read/verifier groups. On success, error,
or cancellation, stop/reap the leader and all in-group descendants with TERM5s
then KILL5s and verify no live members before deleting workspace. If ownership or
stop cannot be verified, retain workspace/artifacts and fail infrastructure.
Do not kill other tasks or adopt a PID merely from an artifact. A ref lock may be
removed only after verified group stop and exact saved inode ownership; foreign
or unidentified lock files remain protected.

Required behavioral gates cover exact source/tree fidelity; all three-way conflicts;
full identity/guard/envelope tampering; real concurrent OLD CAS and same-tree
different-parent controls; symbolic substitution while preparing; hook/config/path
injection; real expected-key signature and wrong-key/signature rejection; empty and
mixed plans; durable no-overwrite and new-directory fsync order; interruptions at
each artifact/prepare/commit/receipt boundary; real lost-ack publication and ABA;
restoration of saved objects without re-signing; pipeline flood/deadline/constructor
interrupt and descendant teardown. Targeted wrong-behavior mutants must yield named
normal assertion failures and restored greens; setup/compiler/timeouts/cleanup
failures never count as behavioral reds.

## CLI and implementation ownership

New commands live in git_cli, dispatched before the unchanged legacy CLI parser:
prepare-git, stage-git, apply-git and recover-git. Each takes --repo and --artifacts.
Prepare additionally takes --plan-file, --expected-plan-id, --target-ref,
--expected-old-commit, --operation-id, --commit-metadata-file and --signer-policy-file.
Stage takes --expected-intent-id and requires --signer-config-file for nonempty
Git work only; empty work never reads a signer configuration file. Apply/recover take
--expected-intent-id and --expected-staged-id. Files in the artifact directory are
the concrete review surface. Print canonical bounded JSON; exits0 success/no-op,
1 rejection,3 unresolved publication,75 infrastructure. No DB flags/client creation.

Exclusive implementation paths: gitops/git_apply.py, git_writer.py, signing.py,
git_artifacts.py, git_cli.py; tests/test_git_apply.py, test_git_signing.py,
test_git_process.py, test_git_artifacts.py; bounded __init__.py/__main__.py exports
and dispatch; this document and gitops.md pointer; one unique structured history.
The parent owns runtime activation, security exceptions, shared CI/build wiring,
and broader roadmap accounting. The child only uses its synthetic test repositories,
identities, artifacts and keys; source/owner repository refs and signing assets are
never test targets.
