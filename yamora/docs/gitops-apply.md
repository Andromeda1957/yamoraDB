# Bounded database apply

This stage takes a reviewed `yamora-gitops-plan-v1` or lifecycle
`yamora-gitops-plan-v2` and applies only entries and collection decisions whose
`target` is `db`, through **one native atomic transaction**. Git targets
remain pending and are reported by path, then collection prefix. This is one direction of synchronization;
it does not publish Git changes or claim bidirectional completion.

Planning, exporting and preparing are read-only. The implementation never changes
Git blobs, index, checkout, refs, commits or signatures, and never fetches or
pushes. The Git reader accepts only locally available committed objects in a
non-bare repository with an ordinary `.git` directory. Symlinked input paths,
worktree indirection, unsafe selectors, executable blobs, nested document paths
and overlapping mappings are rejected. Dirty checkout files are not input.

## Review and trust boundary

A plan is **data, not authentication**. A trusted operator must review the complete
plan, obtain its `plan_id` independently from that review, explicitly supply
`expected_plan_id`, and select the intended database and write credential. Merely
copying an untrusted plan's ID into a command does not establish approval. A plan
can be legitimately regenerated with a different ID; SHA-256 detects alteration
relative to the reviewed ID, not authorship. Signed plans and signed Git
publication are later stages.

Every apply requires a caller-provided, nonzero, lowercase 32-hex `request_id`.
Use a fresh random ID for each new intent. Keep the same ID only for recovery of
the same frozen operation against the **same cluster**. IDs are not derived from
plans and must not be reused across databases or clusters. The envelope carries
no authenticated cluster identity; the trusted operator owns endpoint selection
and recovery custody.

The write token is separate from the read token. Apply refuses clients without
an explicit write credential; the daemon still authorizes the transaction.
Credentials never enter the plan or recovery envelope. Envelopes contain exact
source data and should be protected like exports.

## Validation and atomicity

`prepare_db` validates the complete format, exact field sets, types, sorted
identities, mappings and paths, summaries, presence conditions, canonical base64,
source lengths and SHA-256, document ETags, export hash, baseline commit/tree,
current tree and blob OIDs. It independently rebuilds the plan from local Git
blobs and the reconstructed pinned export and compares all fields. Any unresolved
conflict rejects the whole operation, including a conflict outside DB targets.

For a nonempty DB batch, before initial dispatch, `apply_prepared_db` captures a
fresh **complete** export for the exact mapped scope and checks its canonical hash.
This binds revision,
revision scheme, collection membership, document IDs, ETags and source bytes.
An omitted document or absent-versus-empty collection cannot be accepted as an
empty export. The same transaction then carries the global revision and every
update/delete ETag or create-only guard, closing the preflight/write race.

There are at most **128 DB operations**, with at most 16 MiB per source and an
actual **64 MiB encoded JSON request ceiling**. JSON escaping and transaction
metadata count toward that ceiling. Source/planning limits may be lower. An
oversized operation rejects before any database request; batches are never
chunked. Native transaction validation rejects invalid, empty or non-UTF-8 YAML
before publication, without publishing earlier operations from that transaction.
The Python preparation boundary also rejects empty/non-UTF-8 puts. Valid source
bytes, including CRLF, comments and Unicode, are preserved without reserialization
of YAML.

The `Limits.deadline` budget (default 60 seconds, maximum 300) covers input
validation, Git reads, live export, dispatch and receipt decoding/return within
one invocation. Each Git process and client request receives only remaining time.
The existing internal `_request(..., _timeout=...)` hook is used; parent client
files are unchanged. CPU decoding/encoding is bounded by input limits and checked
afterwards; it is not preempted mid-call. A separate explicit recovery invocation
has its own deadline.

No DB targets yields a local `status: no_db_operations`, zero database requests,
and `receipt: null`, even if the database is unavailable or has advanced. Local
identity, type, write-credential and deadline checks still apply. This result
does not attest to the live database revision or fabricate a committed receipt.
Success with DB targets yields
`status: db_committed` and a receipt whose status is exactly `committed`, operation
count is an exact integer equal to the batch count, and revision agrees with the
response header. This layer validates the raw receipt itself.

## Python API and recovery

```python
from yamora.gitops import (
    ApplyUncertainError,
    PreparedDB,
    apply_db,
    apply_prepared_db,
    prepare_db,
)

# Read-only: validates local Git and freezes bytes/conditions/revision/ID.
prepared = prepare_db(repo, plan, expected_plan_id=reviewed_id, request_id=write_id)
# Persist prepared.to_dict() securely before dispatch for process-loss recovery.
try:
    result = apply_prepared_db(client, prepared, expected_plan_id=reviewed_id)
except ApplyUncertainError as error:
    # error.prepared is immutable; error.request_id, error.plan_id and
    # error.operation retain the exact request identity and encoded bytes.
    recovery_envelope = error.prepared.to_dict()
```

`apply_db(client, repo, plan, expected_plan_id=..., request_id=..., limits=...)`
combines preparation and initial dispatch under one deadline. It never retries
on its own. The configured `YamoraClusterClient` may perform its existing bounded
transport retries using the same ID and frozen bytes.

After ambiguity, use `apply_prepared_db(cluster_client, prepared,
expected_plan_id=reviewed_id, recover=True)` explicitly. This requires an actual
configured `YamoraClusterClient`. It skips live DB preflight deliberately: another
write may have advanced the database, while the durable deduplication receipt
still belongs to the original operation. Do not replan, alter conditions, generate
a new ID, or substitute current revision/ETags during recovery. Restoring with
`PreparedDB.from_dict(repo, envelope, expected_plan_id=...)` validates and rederives
the saved plan and verifies exact operation bytes; it does not read the live DB.
Retain the referenced local Git objects for recovery from a serialized envelope.

Transport errors, malformed/ambiguous receipts, exhausted deadlines and
cancellation after dispatch raise `ApplyUncertainError`, retaining the frozen
operation even when it may already have committed. A definitive HTTP 4xx rejection
other than 408 remains a client error. Pre-dispatch failures are ordinary errors.
An uncatchable process kill cannot produce an exception: save the envelope first.

A standalone daemon has **no durable request deduplication guarantee**. There is
no automatic replay, `recover=True` is refused, and reapplying is not claimed to
be idempotent. Preserve the uncertainty and reconcile the outcome operationally.
Neither a stale precondition nor matching current bytes proves an intent was
already applied.

## CLI

Existing `plan` and `export` commands retain their format and exit behavior.
`prepare-db` performs no database I/O. Protect files produced by shell redirection:

```sh
umask 077
python3 -m yamora.gitops prepare-db --repo /srv/config-repo \
  --plan-file reviewed-plan.json --expected-plan-id "$REVIEWED_ID" \
  --request-id "$WRITE_ID" > prepared.json
python3 -m yamora.gitops apply-db --repo /srv/config-repo \
  --prepared-file prepared.json --expected-plan-id "$REVIEWED_ID" \
  --auth-token-file /run/secrets/yamora-read \
  --write-auth-token-file /run/secrets/yamora-write \
  --host 127.0.0.1 --port 8765
```

Alternatively initial `apply-db` accepts `--plan-file` with `--request-id`.
For cluster recovery, use the original `--prepared-file`, add `--recover`, and
specify trusted `--seed IPV4:PORT` endpoints (repeat per seed), `--tls-ca`, and
when required `--tls-cert` plus `--tls-key`. These TLS/seed options also work for
initial apply and read commands. Seed discovery cannot introduce new endpoints.

Exit codes: 0 success/no DB operations, 1 rejected/error, 2 read-only plan has
conflicts, 3 uncertain apply. Exit 3 writes a JSON object containing `status:
uncertain` and `prepared` to stdout; retain that nested envelope securely. Stderr
contains only a generic uncertainty message. `prepare-db` before apply remains
the process-loss recovery path.

## Explicit limits

Collection metadata is part of the pinned export. Puts can create a missing
collection natively. A v1 plan has no collection create/drop operation: deleting
the last document leaves an empty collection, and an absent Git directory does
not authorize dropping database collection metadata. A reviewed
`yamora-gitops-plan-v2` (see [collection lifecycle](gitops-sync.md#collection-creation-and-deletion))
freezes one `{"collection":C,"drop_collection":true,"purge":true}` in place of
the deletes of every document of C, which the daemon applies in one storage commit
under the batch's reviewed `revision`, or `{"collection":C,"create_collection":true}`
for an empty Git tree. Each counts as one of the 128 operations and the receipt's
`operations`, whatever the collection holds.
Deleted/missing collections, incomplete exports and drift reject initial preflight.

Native ETags and global revisions are 64-bit FNV-derived **content fingerprints**,
not monotonic transaction versions or cryptographic authentication. ABA changes
that restore all bytes/metadata, and fingerprint collisions, are not detected by
native CAS. Exact SHA-256 export comparison strengthens initial preflight but
cannot eliminate a subsequent fingerprint collision or ABA race. Durable cluster
request IDs resolve receipt recovery; they do not make content revisions
monotonic. Concurrent collection/index/policy evolution beyond the exported
metadata retains the native protocol's limits.

## Focused verification

The existing `yamora.gitops.tests.test_gitops` unittest entry also selects the
standalone apply and three-node mTLS suites through `load_tests`. It requires
`YAMORA_TEST_BINARY` and fails when the daemon is missing; it never rebuilds it.
Run with task-owned disk scratch and fatal sanitizer settings:

```sh
ASAN_OPTIONS=abort_on_error=1:detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1 \
  python3 -m unittest yamora.gitops.tests.test_gitops
```

The acceptance tests own temporary Git repositories, native roots, credentials,
certificates, daemons, gateway threads and sockets. They verify native atomic
create/update/delete and exact sources, stale global/ETag/absence guards,
metadata drift, tampering, conflicts, malformed YAML without partial writes,
128/129 operations, actual encoded byte limits, frozen mutable inputs, deadlines,
receipt validation and standalone non-replay. The three-node mTLS tests record
every POST at all seed gateways, including gated rejections, with its seed,
verification state and arrival time. Qualification rejects any second mutation
request arriving before exact source verification completes, including when a
slow verification allows a transport timeout and retry. A negative control holds
verification and forces arrivals at all three gates to prove that qualification
fails. Both lost and correctly framed malformed receipt tests advance the
database, crash/restart the leader, and explicitly recover the original receipt
with unchanged bytes/ID and no duplicate log entry.
