# Read-only GitOps planning

This first GitOps slice compares a previous common Git commit, an explicitly
selected current Git tree, and a revision-consistent Yamora export. It produces
a reviewable JSON plan. [Guarded atomic database apply](gitops-apply.md) is a
separate stage. Optional [signed local Git publication](gitops-git-apply.md) handles the other
reviewed direction through a dedicated ref. The [explicit synchronizer](gitops-sync.md) composes both directions with per-mapping
ownership, fail-closed conflicts and durable recovery. Automatic conflict resolution
and background scheduling remain outside its scope.

The planner uses Python's standard library and the installed Git executable. It
does not parse or serialize YAML. Comments, quoting, whitespace, CRLF, final
newlines, and even empty source blobs remain exact bytes. Missing documents
have `present: false`; empty blobs have `present: true`, `bytes: 0`. A proposed
empty or otherwise invalid YAML blob still needs native validation before a
database apply; planning does not certify a document is writable.

## CLI

Run from the repository root. A mapping owns a complete flat directory of
`document-id.yaml` files, for example `people=data/people`. Repeat `--map` for
additional collections. Use the commit that last represented the common Git/DB
state as the explicit baseline; the tool cannot establish that historical fact.

```sh
python3 -m yamora.gitops plan --repo /path/to/content-repo \
  --baseline FULL_BASELINE_COMMIT_OID --current HEAD \
  --map people=data/people --host 127.0.0.1 --port 8765 \
  --auth-token-file /path/to/private-read-token
```

Only GET requests are issued. The client accepts numeric loopback or RFC1918
IPv4 addresses and performs no redirects. Add `--tls-ca /path/to/ca.pem` for
verified TLS 1.3. This slice uses the existing administrative read credential
because complete collection enumeration is needed to prove absence. It takes no
write credential. The connected client must reach a valid native read endpoint;
the planner does not add replica-set leader discovery.

For an offline pin, capture an export with the same mapping, retain it through
your own artifact procedure, and supply `--export-file /path/to/export.json` to
`plan` instead of connecting to Yamora:

```sh
python3 -m yamora.gitops export --map people=data/people \
  --host 127.0.0.1 --port 8765 --auth-token-file /path/to/private-read-token
python3 -m yamora.gitops plan --repo /path/to/content-repo \
  --baseline FULL_BASELINE_COMMIT_OID --current FULL_CURRENT_TREE_OID \
  --map people=data/people --export-file /path/to/export.json
```

Both commands emit JSON to stdout and never open an output file. Exit codes are
0 for a valid export or conflict-free plan, 2 for a valid plan with document or
collection conflicts,
and 1 for invalid, incomplete, unsafe, stale, or over-budget input. Argument
usage errors use argparse's exit code 2 with no JSON output. A read failure
emits no plan. Output contains the full sources and should be handled with the
same access controls as the original documents.

## Three-way decisions

Equality means exact byte equality, with absence as a separate state. For each
document, `baseline`, `git`, and `db` represent the three input states.

| Condition | Status | Proposed target |
| --- | --- | --- |
| All three equal | `unchanged` | `none` |
| Git and DB equal, different from baseline | `converged` | `none` |
| Git changed, DB equals baseline | `add`, `update`, or `delete` | `db` |
| DB changed, Git equals baseline | `add`, `update`, or `delete` | `git` |
| Both changed differently | `conflict` | `none` |

Add/add divergence, delete/update divergence, and formatting-only divergence
all produce conflicts. No merge algorithm chooses a winner. Renames are
reported as deletion/addition. In the default v1 plan, collections are mapping
scope, not apply actions; empty collections and absent collections remain distinct
export metadata.

`collection_lifecycle=True` (CLI `plan --collection-lifecycle`) also decides each
mapped collection's presence with the same table. Git presence is the mapping
prefix tree, including an empty tree; DB presence is the export's `collections`
list, including an empty collection. Removing a collection whose other side
changed any of its documents since the baseline is a collection `conflict`.
[Explicit synchronization](gitops-sync.md#collection-creation-and-deletion)
describes how each decision is applied.

## Python interface and machine contracts

Import `Mapping`, `Limits`, `Export`, `PlanError`, `capture_export`, and
`build_plan` from `yamora.gitops`. The signatures are:

```python
capture_export(client, mappings, limits=None) -> Export
Export.from_dict(value, limits=None) -> Export
export.to_dict() -> dict
build_plan(repo, baseline, current, export, mappings, limits=None, *,
           collection_lifecycle=False) -> dict
```

`client` can be `yamora.client.YamlDBClient` or a preconfigured
`yamora.cluster_client.YamoraClusterClient`. Cluster discovery, endpoint attempts
and retry backoff share each request's remaining export budget, capped by the
client's retry limit. The complete capture retains `Limits.deadline`.
`export` may be an `Export` or its JSON dictionary; exports are revalidated
before planning.

An export has exactly these top-level fields:

```json
{"format":"yamora-gitops-export-v1","revision":"0123456789abcdef","revision_scheme":"xor-fnv-v2","scope":["people"],"collections":["people"],"documents":[]}
```

`scope` is the complete sorted set of mapped collections whose existence was
checked. `collections` is its sorted subset present in Yamora, including empty
collections. Each document has `collection`, `document`, a bare 16-character
lowercase hex `etag`, and canonical `source_b64`. All mapped documents must be
included. Duplicate keys/documents, missing scope, invalid identifiers, and
ETag/source mismatches reject. ETags use the existing source-byte FNV algorithm;
they are consistency tokens, not authentication. Offline exports are trusted
input pins; their claims of complete enumeration cannot be proven offline.

Live capture pins `/readyz`, checks the revision header on every collection
listing, every paginated document listing, and every raw document GET, then
checks readiness again. Any revision mismatch, malformed cursor, non-progressing
page, invalid ETag, read failure, or deadline invalidates the complete capture.
Capture requests identity bytes and never decompresses or rewrites YAML.

Plans have `format: yamora-gitops-plan-v1`, `read_only: true`, `plan_id`,
`preconditions`, `summary`, and sorted `entries`. Each entry has `collection`,
`document`, exact mapped `path`, `status`, `target`, three source states and
per-document `preconditions`. Present source states contain `bytes`, `sha256`,
and canonical `source_b64`. Entries sort by collection then document; summaries
count each status. No timestamp, checkout location, or moving ref name enters
the plan. `plan_id` is SHA-256 of canonical JSON without `plan_id`: UTF-8,
sorted keys, compact separators, ASCII escapes, no terminal newline.

A lifecycle plan has `format: yamora-gitops-plan-v2` and every v1 field, plus
`collections` and `collection_summary`. `collections` holds one decision per
sorted mapping with `collection`, `prefix`, `status` (`add`, `delete`,
`conflict`, `unchanged` or `converged`), `target`, `baseline: {present}`,
`git: {present, tree_oid}` and `db: {present}`. `tree_oid` is the selected prefix
tree's OID, or null when absent. `collection_summary` counts each status. A v1
plan carrying either field, or a v2 plan missing one, is rejected.

Global preconditions pin `baseline_commit`, `baseline_tree`, `current_tree`, DB
`revision`, `revision_scheme`, `export_sha256`, `scope`, `collections`, and exact
`mappings`. `export_sha256` hashes canonical `export.to_dict()`. Per-document
preconditions pin the selected Git `blob_oid` or absence, plus DB `etag`,
`present`, and `create_only`. Absent DB entries require create-only semantics.

A later apply must validate plan identity/signature and sources, reject
unresolved conflicts, compare the selected Git tree, and use the global DB
revision together with document ETags/create-only guards in an atomic native
transaction. FNV revisions/ETags alone do not authenticate content or prevent
ABA histories. Recheck scope, collection metadata, authorization and native
document validity; a plan is no authorization to mutate. This planner implements
none of apply, authentication of offline pins, or distributed atomic Git/DB
publication.

## Bounds and Git isolation

Defaults: 1,000 documents, 16 MiB per source, 64 MiB combined plan source
bytes, 100,000 entries in each full Git tree listing, five seconds per Git
command, and 60 seconds per capture/planning Git phase. `--max-documents`,
`--max-bytes`, and `--deadline` can lower or raise the defaults up to the
validated hard ceilings in `Limits`. Mappings are limited to 256. Captures cap
JSON response metadata at 1 MiB and use document listing pages of at most 1,000.
Unrelated Git tree entries still count against the listing budget. Listing and
stderr streams are capped while the process runs; blob sizes are checked before
reading. Sources are retained in memory only within these bounded budgets.

Git inputs are non-bare repositories with a real `.git` directory. Symlinked
input paths and linked-worktree `.git` indirection are rejected. Selectors are
`HEAD`, full lowercase SHA-1/SHA-256 object IDs, or simple `refs/heads/...` and
`refs/tags/...` names. Revision expressions, abbreviated OIDs, options, and
`ref:path` syntax reject. Baselines must resolve to commits; current input may
resolve to a commit or tree. Refs resolve once to immutable OIDs.

Prefixes contain plain relative directory components, cannot overlap, and map
one collection each. IDs follow the native lowercase letter/digit/hyphen rules;
the system collection is reserved. Mapped entries must be non-executable
regular `.yaml` blobs with no nested directories. Symlinks, submodules, path
traversal, unsupported extensions and invalid mapping ancestors reject.
Unmapped repository content is not imported.

Only `rev-parse`, `ls-tree`, and `cat-file` are invoked, with fixed argv, no
shell, sanitized environment, no repository hooks, no filesystem
monitor, no replacement refs, no lazy fetch, denied transport protocols, and
disabled automatic maintenance. No checkout, index mutation, fetch, diff,
filter, external merge tool, commit, or network command is issued. Required
objects must already exist locally. Repository metadata and offline pins must
be provided by a trusted operator; this is not a sandbox for malicious Git
implementations or concurrent replacement of repository internals.

The runner is private and additionally allowlists the exact internal read
command shapes. One sized `ls-tree` listing checks every document count and byte
limit before any blob is read; one `cat-file --batch` then reads every mapped
blob, and its only stdin is the listed object IDs, one per line. Its output must
match the listed IDs, types and sizes exactly. A snapshot therefore uses two Git
processes at any collection size. Ctrl-C is deferred through constructor return until the child
handle is owned. Error/interrupt cleanup kills and reaps that child and closes
its pipes while deferring repeated Ctrl-C. A stop that cannot be verified fails
with a retain-scratch error; never clean that workspace until ownership is
resolved. Tests inject a real SIGINT during constructor handoff and an interrupt
during pipe reads, and check that the PID is reaped before fixture cleanup.

## Focused verification and parent wiring

The integration parent owns shared Makefile and CI registration. Register
`yamora.gitops.tests.test_gitops` with the focused Yamora native gate, passing
the freshly built daemon in `YAMORA_TEST_BINARY`. The native test requires it
and fails if missing; it never silently skips. A standalone focused invocation
uses only the existing daemon target (build parallelism at most two):

```sh
mkdir -p /var/tmp/andromeda-work/yamora-gitops-sync
export TMPDIR=/var/tmp/andromeda-work/yamora-gitops-sync
export PYTHONDONTWRITEBYTECODE=1
make -j2 BUILD_DIR="$TMPDIR/build" "$TMPDIR/build/yamora"
YAMORA_TEST_BINARY="$TMPDIR/build/yamora" python3 -m unittest yamora.gitops.tests.test_gitops -v
```

Tests create disposable Git repositories and a native disk root, exercise the
full three-way byte-state matrix, exact CRLF/comment preservation, deterministic
CAS metadata, conflict exit codes, hostile selectors/mappings, symlink/submodule
rejection, Git environment isolation, revision drift on paginated reads, and
resource limits. Native verification performs no mutation of owner data.
