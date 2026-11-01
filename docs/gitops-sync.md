# Explicit bidirectional Git synchronization

The synchronizer composes the existing [byte-exact planner](gitops.md),
[atomic DB apply](gitops-apply.md), and [signed local Git publication](gitops-git-apply.md)
into a bounded, restartable operation. It preserves disjoint Git and DB edits,
rejects divergent edits and prohibited directions, and records a new common
baseline only after verifying the actual source maps on both sides.

This is an explicit operator workflow over a dedicated local ref. It does not
schedule background work, push, fetch, rewrite history, update HEAD/index/checkout,
or merge YAML. Executing the commands requires authority for the selected DB,
repository, publication ref and signing key. Implementation/test authorization
does not grant authority over an owner's repositories or production database.

## Ownership and conflict decisions

Every sorted plan mapping requires one explicit ownership record:

```json
[{"collection":"people","prefix":"data/people","upstream":"both","downstream":"both"}]
```

Supported pairs are `git` → `db`, `db` → `git`, and `both` → `both`. The first
permits only Git-authored changes to flow into the DB; DB-only divergence rejects
the entire intent. The second reverses that rule. The third accepts independent
changes on either side. Different mappings may have different pairs. Ownership
never chooses a winner for a three-way conflict. Add/add, update/delete, and
formatting-only conflicts reject before artifacts or effects. Resolve the authored
sources deliberately, capture a fresh export, and review a fresh plan. No command
silently discards either source.

Decisions and diffs remain exact presence/absence and byte states in the existing
plan, including canonical base64 and SHA-256. Comments, whitespace, CRLF, quotes,
Unicode and empty Git blobs are never parsed/reserialized. Native DB validation
still applies: an invalid/empty proposed YAML put rejects the whole DB transaction.
Mapping direction is a reviewed operation policy, not a new daemon RBAC
mechanism; existing credentials authorize reads and writes.

## Collection creation and deletion

A plan built with `collection_lifecycle=True` (CLI `--collection-lifecycle`) is a
`yamora-gitops-plan-v2`. It also decides each mapped collection's presence, so the
synchronizer can create and delete whole collections in either direction. The
default remains the unchanged v1 plan, which never creates or drops collection
metadata: there, emptying a Git directory deletes its documents and leaves an
empty DB collection.

Presence is exact on both sides and empty differs from absent. In Git a collection
is present when its mapping prefix is a tree in the selected commit, including an
empty tree. In the DB it is present when the complete export lists it, including
with no documents. The three-way decision uses the same rule as documents:

- Removing the prefix tree from Git, with the DB unchanged since the baseline,
  freezes one native purging drop,
  `{"collection":C,"drop_collection":true,"purge":true}`, in a transaction that
  carries the reviewed DB revision. The daemon deletes every document and then
  the collection in one storage commit, at any collection size.
- Dropping the collection in the DB, with Git unchanged since the baseline,
  publishes a signed commit that removes exactly the prefix tree, as one tree
  entry at any collection size, and keeps every sibling and ancestor tree.
- Creating a collection on one side creates it on the other: an empty Git tree
  becomes a native `create_collection`, a new empty DB collection becomes an
  empty Git tree, and document puts create collections implicitly.
- Removing a collection conflicts with any document change on the other side since
  the baseline: an added, updated or conflicting document there rejects the whole
  plan with a collection conflict. Removal never discards the other side's edits.

Every collection guarantee is the document one. Ownership applies per mapping:
a `git` → `db` mapping rejects a DB-side drop and `db` → `git` rejects a Git-side
removal. The purge deletes exactly the reviewed documents: the native daemon
refuses a purge without the transaction revision and rejects it with 412 after
any write since review, so a document written after review stays in place. The
live export check normally rejects that drift before any dispatch. The purge is
all-or-nothing across crashes: a kill before publication leaves every document,
and after it none. The DB attempt fence, the
same-ID cluster recovery, and the Git-ref check before every initial or recovery
dispatch apply to drops unchanged. Git publication requires the exact reviewed
prefix tree OID before removing it, and requires its absence before creating it.
That tree can hold only the reviewed document blobs, because planning refuses any
other entry under a mapping prefix.
Checkpoints record the resulting collection list, and verification also compares
the published Git prefix trees with it. A lifecycle drop needs the native disk
engine. The legacy snapshot backend rejects collection operations with 400 and
publishes nothing.

Ordinary Git checkouts cannot record an empty directory. Deleting the last file of
a collection directory in a checkout and committing therefore removes the prefix
tree, and a lifecycle plan reads that as removing the collection. The reviewed
plan shows the decision before any effect. A DB-side delete of the last
document keeps the collection and publishes an empty tree. To keep an empty
collection that was edited through a checkout, use a v1 plan or restore the tree.

`plan_from_checkpoint` keeps the completed sync's plan format by default. Passing
`collection_lifecycle=True` (CLI `--collection-lifecycle`) after a v1 sync also
requires the checkpoint's DB collections to match its Git prefix trees. A v1
checkpoint can disagree because v1 kept an empty DB collection whose Git directory
was removed; the call then rejects with a collection presence error. Resolve
it deliberately: drop the empty DB collection, or build a lifecycle plan from the
checkpoint commit with `build_plan`, which publishes the empty tree, then sync it.

## Durable operation and phases

`prepare_sync` returns immutable `PreparedSync` data. Its `sync_id` hashes the
canonical intent, which contains the complete prepared Git and DB operations,
explicit ownership, caller-selected nonzero 32-hex `database_id` and `operation_id`.
The DB request ID and Git operation ID are distinct deterministic 32-hex prefixes
of SHA-256 over domain, operation ID, database ID, plan ID, repository identity and
target ref. Reopening an intent never generates a new ID or request body.
`database_id` is an operator assertion identifying the configured deployment; the
native protocol does not attest to a cryptographic deployment identity. Maintain
its custody with the endpoint/TLS/credential configuration. Use a fresh operation
ID for a newly reviewed operation, retaining an existing one for recovery.

All inputs are frozen and independently rederived from local Git/export data.
Review and retain the expected sync and staged IDs independently of artifact
contents. Hashes bind content; they do not authenticate an untrusted reviewer.

The explicit sequence is:

1. Prepare read-only, checking every mapping, both reviewed operations and the
   exact existing direct target ref. No signing key is accessed.
2. Stage the immutable intent and lock, then the signed Git bundle. Persist the
   coordinator staged record with the exact artifact-directory identities. A
   restart reuses an existing saved signed bundle; it does not require the private
   key or sign again. Staging does not dispatch DB writes or publish refs.
3. Under the coordinator's exclusive nonblocking lock, recheck the selected ref
   before initial DB dispatch. Exclusively persist and fsync a positive DB attempt
   fence before calling the existing guarded transaction. Persist the validated
   committed result before continuing. An empty DB phase uses no attempt fence.
4. Verify the complete revision-consistent live DB export against the frozen
   expected result, including collection metadata. Only then publish the staged
   Git commit with the existing exact-parent CAS. Mixed plans keep current Git
   edits and add only the DB-target changes to that tree.
5. Verify the exact current direct ref and its mapped Git source map against a
   fresh complete DB export. Persist an immutable common-baseline checkpoint.

An existing DB receipt is validated and reused on restart. Every unattempted
phase may resume; an attempted effect is never blindly repeated. Stage files,
fences and receipts reuse the private, descriptor-relative, no-follow,
no-overwrite/fsync `GitArtifacts` implementation. Artifacts must be in an existing
current-UID private `0700` directory disjoint from the repository; files are
private `0600`. Directory identity binds staged state so copying artifacts to a
replacement root does not discard a fence. No automatic artifact cleanup occurs.

The artifact layout uses three independent intent directories under that root:

- `SYNC_ID`: coordinator `intent.json`, `staged.json`, `publish.lock`, DB
  `attempt.json` and DB `receipt.json`.
- Prepared Git intent ID: the existing signed Git artifacts, publication fence,
  lock and receipt.
- SHA-256 of canonical `["yamora-gitops-sync-checkpoint-v1", SYNC_ID]`: immutable
  completion `receipt.json` containing checkpoint ID, sync/staged/database IDs,
  common baseline commit, ownership and the complete verified export.

A checkpoint addresses a verified common source baseline, not historical
transaction atomicity. `plan_from_checkpoint` verifies its frozen intent,
receipt and exact common source state before building the next three-way plan.
The caller explicitly selects the next current commit; the synchronizer never
moves the dedicated ref to ingest an author's branch on their behalf.

## Recovery and partial results

`observe-sync` is read-only. It reports recorded/unattempted/unresolved DB state,
existing Git recovery observations and any saved checkpoint. It never clears a
fence, writes a receipt, dispatches a transaction, signs or republishes a ref.

If a DB attempt exists without a durable valid result, normal apply refuses even
when current bytes equal the intended result. Standalone receipt recovery cannot
prove deduplication and remains unresolved. For an actual replica client only,
`apply-sync --recover-db` explicitly replays the original request bytes/ID through
the existing durable receipt protocol. Replay can first-commit if the original
fenced attempt never reached the server. Recovery therefore checks the exact OLD
Git ref before dispatch too; a moved or unreadable ref retains the unresolved
fence because the protocol has no receipt-only operation. A malformed/partial DB fence refuses even
that route. A failed barrier never authorizes a send. Definitive native rejections
also retain the conservative fence; correct the cause and deliberately prepare a
new reviewed operation rather than replacing or deleting recovery records.

If Git has an attempt fence, resume uses only existing read-only `recover_git`.
An exact verified NEW commit may establish observed publication after a lost ack.
A recorded receipt also requires the current ref to equal NEW before completing
synchronization. OLD after ABA, missing/unreadable objects, symbolic refs, other
commits and ambiguous effects remain unresolved; recovery never republishes.

Any intervening authored DB/ref edit is preserved. Drift stops completion and
leaves all already committed phases intact. No rollback or compensating overwrite
runs. An operator can inspect the original plan and durable receipts and prepare
a new reconciliation from the known baseline; a partial operation is never
misrepresented as a new common baseline.

## Python and CLI

```python
prepare_sync(repo, plan, *, expected_plan_id, database_id, operation_id,
             ownership, target_ref, expected_old_commit, commit_metadata,
             signer_policy, limits=None) -> PreparedSync
stage_sync(repo, prepared, *, artifacts, expected_sync_id,
           signer_config=None, limits=None) -> dict
run_sync(client, repo, *, artifacts, expected_sync_id, expected_staged_id,
         database_id, recover_db=False, limits=None) -> dict
observe_sync(repo, *, artifacts, expected_sync_id, expected_staged_id,
             limits=None) -> dict
plan_from_checkpoint(repo, current, export, *, artifacts, expected_sync_id,
                     expected_staged_id, expected_checkpoint_id,
                     limits=None, collection_lifecycle=None) -> dict
```

Public exports live in `yamora.gitops`. All CLI commands use
`python3 -m yamora.gitops COMMAND --repo REPOSITORY`:

| Command | Required additional arguments |
| --- | --- |
| `prepare-sync` | `--plan-file`, `--expected-plan-id`, `--database-id`, `--operation-id`, `--ownership-file`, `--target-ref`, `--expected-old-commit`, `--commit-metadata-file`, `--signer-policy-file` |
| `stage-sync` | `--artifacts`, `--expected-sync-id`, `--prepared-file`; `--signer-config-file` only for new nonempty Git staging |
| `apply-sync` | `--artifacts`, `--expected-sync-id`, `--expected-staged-id`, `--database-id`, `--write-auth-token-file`; optional explicit `--recover-db` |
| `observe-sync` | `--artifacts`, `--expected-sync-id`, `--expected-staged-id` |
| `plan-sync` | `--artifacts`, `--expected-sync-id`, `--expected-staged-id`, `--expected-checkpoint-id`, `--current`; optional `--export-file` and `--collection-lifecycle`/`--no-collection-lifecycle` |

`apply-sync` and live `plan-sync` accept the existing `--host`, `--port`,
`--auth-token-file`, `--seed`, `--tls-ca`, `--tls-cert` and `--tls-key` options.
Private numeric endpoints, TLS verification, credential-file confinement,
collection authorization and existing DB/replica limits remain unchanged.
Outputs are canonical JSON on stdout. Redirect outputs using an operator-owned
private artifact procedure; output contains full authored data. Exit codes are
0 success/observation, 1 rejected/incomplete, 2 a next plan with document or
collection conflicts,
3 unresolved effects, and 75 Git infrastructure failure. Usage errors remain
argparse exit 2. Retain all persisted phases after every nonzero apply result.

## Bounds and limits

A plan holds at most 1,000 mapped documents and 64 MiB of combined source bytes
by default. Every sync command accepts `--max-documents` (up to 50,000) and
`--max-bytes` (up to 64 MiB, the Git publication maximum); pass the same values to
every phase of one sync, because each phase revalidates the frozen plan. Other
bounds are 128 Git changes, 128 DB operations and 16 MiB per source. A collection
create, drop or tree removal counts as one change or operation whatever the
collection holds: its document deletions are part of that one purge or tree
removal. Removing a collection therefore adds no bound beyond the plan limits that
any sync of that mapping already needs, while ordinary document changes keep the
128-change and 128-operation bounds. Planning reads every mapped blob of a commit
through two Git processes, so its cost grows with bytes rather than process
launches. There is
one DB transaction and at most one signed commit per operation; no hidden batching.
Canonical sync envelopes and output are capped at 256 MiB. Existing helper process
budgets, sanitized environments, signing custody and verified teardown apply.
`--deadline` defaults to 60 seconds, maximum 300; bounded helpers share the
remaining phase budget. Each CLI database request may wait up to 30 seconds of
it, so a purge that takes seconds to commit is not reported as uncertain.
Synchronous JSON/byte processing is checked around
bounded operations, not preempted mid-instruction. A live export reads each
document with its own request, and against a replica set each read also passes a
linearizable read barrier: a three-node test cluster on a loaded host managed about
14 reads a second. Size `--deadline` for the mapped document count.

There is no Git+DB distributed transaction, watcher guarantee, automatic conflict
winner, history retention API or cross-machine artifact replication. A crash can
leave the DB committed and Git pending. Filesystem durability relies on the
existing fsync semantics. A verified checkpoint proves the observed common state;
concurrent edits can occur immediately afterwards. Native revisions/ETags retain
their content-fingerprint collision and ABA limits. Source-map verification uses
exact bytes but cannot create a simultaneous cross-resource snapshot or prove a
standalone uncertain transaction was never committed.

Focused suites are `yamora.gitops.tests.test_sync`,
`yamora.gitops.tests.test_collection_lifecycle` and
`yamora.gitops.tests.test_sync_native`. The last requires an externally supplied
immutable actual daemon in `YAMORA_TEST_BINARY` and optionally its expected SHA-256
in `YAMORA_TEST_BINARY_SHA256`; it never builds one. Synthetic repositories,
Ed25519 keys, credentials and native roots remain isolated in task scratch.
