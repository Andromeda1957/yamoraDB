# Native branches and retained commits

Branches and commit reads use immutable copy-on-write roots inside the native
`.yamora-disk` file. They retain authored document bytes, including YAML comments,
line endings and numeric spelling. A branch is an isolated document/index/schema
snapshot. Writing it does not change main's documents. It does not create another
database file, directory of YAML documents, or sidecar database.

## Explicit capability profile

Profile 8 has magic `YAMDIS08` and a required-capability envelope `YDCAPS01` at
byte 128: little-endian version 1 at byte 136 and mask at byte 140. Supported bits
are cluster 1, schema 2 and retained roots 4. The mask must be nonzero and exact;
unknown bits, unsupported versions, differing physical header requirements and
damaged capability pairs fail closed. Schema also retains its protocol-1 marker
at byte 112. Existing formats 5, 6 and 7 keep their existing interpretation and
constructors. Their constructors refuse profile 8.

`yd_disk_open_capabilities[_at]` explicitly creates or reopens the required
profile. It never converts an existing database. Standalone roots and native
files must have the same owned private namespace and file binding requirements
as the schema profile. Cluster roots retain their consensus namespace. Schema
constructors require cancellation disabled through ownership adoption.
`yd_disk_initialize_capabilities` imports an existing YAML source into a separate
empty destination, preserves source bytes, validates the complete candidate, and
removes its durable initialization marker only after success. Cluster roots are
initialized by the consensus application constructor instead.

The daemon selects this profile explicitly with `--native-capabilities MASK`.
Standalone masks are 2 (schema), 4 (history), or 6 (both); the option is used
for initialization and every subsequent open. For example:

```sh
yamora --data-dir /srv/yamora/review --native-capabilities 6 --init-disk --validate-only
yamora --data-dir /srv/yamora/review --native-capabilities 6 --port 7400 \
  --auth-token-file /run/yamora/read --write-auth-token-file /run/yamora/write
```

Cluster configuration instead supplies `native_capabilities: 1`, `3`, `5`, or
`7`, including the cluster bit. Every voter must select the same mask. Omitting
the field preserves the legacy format-6 application. Startup, checkpoint
selection, incoming snapshot admission and recovery compare exact masks before
publication. Format-8 snapshots use `YDRSNAP2`, with the exact mask at manifest
byte 26; the legacy `YDRSNAP1` reserved bytes retain their old meaning. A new
profile requires a new empty destination; changing the option cannot upgrade or
downgrade an existing native root.

## API contract

The transport authenticates and authorizes before any access or receipt lookup.
Branch creation, deletion and merge require database-wide write permission.
Branch transactions authorize every collection in the nested transaction. Commit
reads authorize the underlying route and all query foreign lookups before
resolving its storage root. A selector never grants access.

| Request | Body or condition | Result |
| --- | --- | --- |
| `GET /v1/branches` | none | Retained count, oldest/latest tokens and named heads |
| `PUT /v1/branches/work` | `{"from":"main"}` | Create from a named branch or retained commit |
| `DELETE /v1/branches/work` | `If-Match: "c1.…"` | Delete that exact named head |
| `POST /v1/branches/work/transactions` | `{"head":"c1.…","transaction":{"operations":[…]}}` | Atomic native transaction on the exact branch head |
| `POST /v1/branches/work/merge` | `{"head":"c1.…","main":"c1.…"}` | Atomic three-way document merge into the exact main head |
| `/v1/at/<selector>/v1/<finite-route>` | The ordinary read/query specification | Read one resolved immutable root |

The nested transaction uses the ordinary native transaction syntax and limits.
Its optional revision is the branch dataset revision. A successful mutation
returns `status`, `branch`, `commit`, `operations` and `revision`; the branch
transaction revision describes its branch dataset. Merge returns the resulting
main commit. Commit tokens contain `c1.`, the persisted 32-hex database identity,
a dot, and a 16-hex logical sequence: exactly 52 characters. `If-Match` quotes
that token; `X-Yamora-Commit` and JSON fields carry the unquoted value. Document
ETags retain their ordinary document grammar.

Standalone mutations require a nonzero 16-byte request ID. The durable receipt
binds the exact method, target, request bytes and conditional fields. An exact
same-ID retry returns the original status, body and revision after restart,
without another publication. Reusing an ID for different inputs returns 409.
Consensus mutations use the application's existing committed exact-request
receipt and apply position; branch effects and that receipt publish together.
An interrupted transport never establishes a mutation outcome: retain the exact
envelope and retry its ID. Authorization is checked again for the retry.

## Merge and availability

Each branch pins its head and a known common base with main. A fork from another
branch inherits its common base, so its unmerged parent changes participate in
the merge. Merge compares exact source bytes or document absence against that
base. Different changes to the same document return 409 with no publication;
identical changes are compatible. Main's independent changes survive. The whole
replacement batch passes current main policy and index admission before any
publication. A policy or index rejection returns 409; a work limit returns 413.
A successful merge advances that branch's known common base to its
merged head. It does not reset or rewrite the branch's source tree.

In a cluster, applying an election NOOP also publishes main's application
checkpoint and retained commit, even when document bytes and dataset revision
are unchanged. A rejected merge publishes no merge effect; a later election may
independently advance main's commit token.

The catalog holds 128 commits and at most 32 named branches including main.
Main publications add a retained commit; a branch write also adds its isolated
commit. The oldest unpinned commit is evicted when the bounded catalog fills.
Branch heads and common bases stay pinned until their names advance or are
deleted. A commit fork whose required common base has expired is unavailable.
Sequence numbers identify publications rather than wall-clock timestamps or the
dataset's XOR revision. Dataset revisions can repeat; commit sequences do not.

Malformed selectors return 400, unknown names or future commits 404, foreign
database identities or missing required capability 409, evicted commits 410,
and invalid/unreadable catalog state 503. Commit reads resolve against one
captured view. Later branch changes, deletion or eviction do not change an
already owned pin or its catalog. Reopening the native file recovers the same
published catalog and roots. History before this profile's genesis is not
invented or inferred from unreachable pages.

Merge scans at most 65,536 source keys, charges at most 64 MiB of compared source
bytes and applies at most 128 changed documents. Exceeding a bound rejects the
entire merge. Finite temporal routes include source/list/catalog/statistics and
query/aggregate/search reads. They exclude feed, replication, job and mutation
operations. Private branch snapshots discard inherited main feed and legacy
follow checkpoints, which do not describe their changed dataset. Main keeps its
feed and publishes a reset marker for an isolated branch change.

## Preservation and recovery

Every retained root excludes the branch catalog key, preventing recursive
catalog retention. Native compaction and application-image copying relocate all
retained roots, indexes, change-frame references and durable receipts. A private
native-tree relocation map shares unchanged source records across copied roots;
it is never published. Copy validates the source and completed destination.
Failures preserve the source and the destination's diagnostic initialization
state. Physical native checkpoints already include retained and unreachable
pages and preserve the required capability header.

A standalone profile-8 writer reclaims space without stopping, through
[online compaction](disk-engine.md#space-backup-and-recovery). It physically
relocates every retained branch and history root and keeps branch heads,
commit tokens and receipts exact. History validation runs on the candidate
before the switch, and the capability header is unchanged.

For an offline standalone copy, close writers and use the same explicit mask
with `--validate-only --compact-to NEWROOT`, where `NEWROOT` is a different
existing empty owned 0700 directory. Validate and reopen the result with that
same mask. This preserves retained roots and exact receipts while leaving the
original source available. Legacy logical document dumps cannot preserve the
retained graph. Schema-only logical recovery uses its separate sealed stream;
it deliberately rejects a history or cluster capability.

The bounded catalog controls logical availability. It does not change Session1
file/journal retention admission, promise immediate physical reclamation, or
grant deletion authority. Legacy logical follow/export protocols cannot carry
the retained-root graph and refuse history-capable roots. Replica branch state
uses the consensus command, snapshot and recovery contracts with exact capability
and cluster identity. A retained branch root is a source/query snapshot; it is
not an independent consensus checkpoint or a fresh-quorum proof.
