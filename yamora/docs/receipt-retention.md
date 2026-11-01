# Native retry receipt retention

This opt-in native contract extends the unlimited legacy replica receipts. It
does not expire ordinary standalone document requests or schema-policy receipts.
Physical page reclamation, retained archives and historical readers have their
own storage budgets; limiting reachable receipts alone does not bound disk use.

## Identity and expiry

An activated application requires `YDRaftWrite.receipt_epoch` together with the
original nonzero ID, method, target, exact body and preconditions. Persist that
whole identity before dispatch. Epoch zero selects the existing legacy contract
only while retention is disabled. Activation is one-way and expires all legacy
IDs. Never assign an uncertain operation a new epoch to retry it.

This policy applies to public mutation receipts in `\0YRR`, including replica
staging requests. The Raft-only `PUBLISH`, `FAIL` and `YSHARD` operations instead
require epoch zero and retain permanent receipts in `\0YRI`. They remain usable
at public capacity and during pruning; their receipts do not consume the public
count or byte limits. Activation and epoch advancement never expire them.

There is one live epoch. Explicit replicated advancement closes the preceding
epoch immediately. Requests below the current epoch return 410
`request_expired`: the historical outcome is unknown, not proof the mutation
failed. Missing epochs return 400 `request_epoch_required`; future epochs return
409 `request_epoch_invalid`. These checks precede effects and receipt lookup.
Unactivated applications reject a nonzero epoch rather than ignoring it.

## Native integration interface

`yd_raft_application_retention_status` observes serialized local state. It gives
no fresh-read or quorum authority. `maximum_count` is 1..65536 and
`maximum_bytes` is 128..1073741824, inclusive. Bytes count complete encoded
receipt payloads. `prune_limit` is 1..256 records per committed maintenance
command. Capacity rejects a new receipt before publishing effects; existing
matching live receipts remain replayable even at capacity.

`yd_raft_application_retention_prepare(app, expected_epoch, policy, proposal, ...)`
uses the ordinary preparation convention: -1 unavailable, 0 a local reply, 1 a
prepared command. A non-NULL policy activates with expected epoch zero; an exact
activation retry is local success only at epoch one with the identical policy.
A NULL policy advances exactly the expected epoch. Retrying an advance while
the application is exactly one epoch ahead returns local success; older requests
expire. An advance during pruning returns a conflict.

`yd_raft_application_retention_prune_prepare(app, expected_epoch, proposal, ...)`
prepares one bounded removal batch. It requires the exact current epoch and is
local success if already drained. It never advances the epoch. New mutations
wait while expired receipts remain; reads continue. Activation examines no more
than `maximum_count + 1` existing receipts and refuses an oversized legacy set.

The owner submits `proposal.command/size` through the existing term/base-checked
Raft path and waits for application through the returned log index. Control
commands create no mutation receipt: success is the applied position followed by
serialized status. Preparation itself never publishes. Responses lost after
advancement must be retried with the original expected epoch; pruning is a
separate idempotent operation.

## HTTPS and Python

`GET /v1/cluster/receipt-retention` returns the eight state fields `enabled`,
`epoch`, `count`, `bytes`, `maximum_count`, `maximum_bytes`, `prune_limit` and
`pruning`, after a leader/quorum check. Both GET and POST require the configured
administrative write bearer. Read tokens and collection-scoped principals cannot
inspect or change the retry boundary.

POST requires `application/json` and at most 512 body bytes. Activation has exactly
these fields (in any order):

```json
{"operation":"activate","expected_epoch":0,"maximum_count":4096,"maximum_bytes":16777216,"prune_limit":64}
```

Advancement and pruning have exactly `operation` (`advance` or `prune`) and
nonzero `expected_epoch`. Names and operations use literal ASCII strings; numbers use
canonical unsigned decimal integers. Duplicate/unknown fields, escaped strings,
coerced values and trailing input are rejected. Control requests do not carry a
mutation ID, epoch header or document precondition.

Every replicated mutation after activation carries the original
`X-Yamora-Receipt-Epoch` header as a nonzero canonical decimal uint64, together
with `X-Yamora-Request-Id`. Duplicate/malformed epoch headers are rejected. A
standalone server explicitly refuses an epoch header. The current binary wire
protocol has no epoch field: its legacy mutation requests return
`request_epoch_required` after activation, without effects.

`YamoraClusterClient` offers `receipt_retention_status`,
`receipt_retention_activate`, `receipt_retention_advance` and
`receipt_retention_prune`. Its `put`, `patch`, `delete`, `set_indexes` and
`transaction` methods accept an explicit `receipt_epoch` keyword. Existing
callers retain legacy behavior while retention is disabled. For example:

```python
client.patch(
    "counters",
    "value",
    {"$inc": {"n": 1}},
    request_id=saved_id,
    receipt_epoch=saved_epoch,
)
```

An uncertain write exposes both `request_id` and `receipt_epoch` on
`YamoraUncertainWriteError`; preserve them with the original operation bytes and
preconditions for recovery. `YamoraRequestExpiredError` is a terminal 410 even
after an earlier transport failure. It carries the same identity and reports an
unknown historical outcome. The client never fetches a new epoch or rewrites an
uncertain operation's epoch automatically. Choosing a new epoch means submitting
a deliberate new operation after reconciling the old outcome.

## Persistence boundary

Activated roots publish the `YDAPLY02` application checkpoint. Older application
executables require `YDAPLY01` and refuse the activated root. Unknown checkpoint
versions and malformed state also refuse. Standalone open remains prohibited
for these format-6 replica roots. Effects, receipts, epoch state and applied
position publish atomically; maintenance also preserves generation = applied
index + 2. Epoch-bearing request/command/receipt codecs are versioned.

The current checkpoint carries policy, epoch and remaining public count/bytes.
Full validation checks public receipt epochs against live versus pruning state
and requires epoch zero for internal receipts. Copy and catch-up preserve job,
replica staging and shard records, including exact source and permanent internal
receipts. Archives and snapshot restore preserve this
metadata with exact source, feed and index data. Closed-epoch duplicate commands
cannot execute again even after their receipts have been removed.

Normal crash recovery preserves the durable epoch. Restoring an older backup is
a historical rollback and needs a new retry incarnation or an independently
retained monotonic boundary; an old backup cannot establish later expiry state.

## Standalone schema policy receipts

Profile-7 schema policy publications use their existing `\0YSP` / `YDSPRC01`
receipt format. These IDs are permanent: the replicated epoch API does not apply
to them. This executable admits at most 4096 receipts and 4 MiB of encoded receipt
payloads. Either inclusive ceiling rejects a new publication with 413. The
exclusive transaction checks count and minimum space before staging policy
changes, then checks the exact encoded size before inserting the receipt.
Each census reads at most 4096 fixed-size records and includes private receipts
inserted earlier in the same native transaction.

Current administrative authorization and an existing ID's exact digest/reply are
checked before capacity. Matching retries replay their original bytes at capacity;
changed requests conflict. No receipt is pruned, expired or replaced. Existing
stores above a ceiling remain readable and replayable, but cannot admit new
policy IDs. Validation, compaction and preservation copies retain every old ID,
including an oversized legacy set. Older executables retain the same on-disk
retry semantics but do not enforce this new local admission ceiling.

## Standalone physical maintenance

Writable standalone native profiles 5 and 7 use one finite storage owner through
initialization, requests and replacement generations. At one third of its extent
ceiling (at least 64 KiB), further reserved growth requests maintenance. The
daemon closes listeners, drains and joins HTTP, binary, raw-view, waiter and index
workers, then retains its original exclusive root lock through native rollover.
Successful rollover preserves the exact retained feed, indexes, policy receipts
and source, removes the exact old inode, and restarts fresh engines on the same
allocated HTTP/binary ports. Busy or low-yield attempts require more subsequent
growth before retrying; no maintenance loop runs on an unchanged small store.
The same in-process index-job object survives maintenance: a running worker is
cancelled and joined, and the latest terminal ID, status, counters and publication
revision remain observable until an explicit new submission supersedes it. A
normal process restart retains the existing idle-job behavior.

Maintenance has a finite native work/deadline budget. A failed operation stops
serving and preserves its diagnostic `.yamora-rollover-*` stage; subsequent
startup refuses that stage. No stage is silently adopted or deleted. Retained
change history is never discarded to create space: a ceiling too small for the
live retained graph eventually refuses writes. This finite admission behavior is
distinct from the explicit replicated receipt expiry policy above.

## Focused qualification

The actual count-3 schema-fault daemon and its complete production object closure
passed these suites with fatal ASan/UBSan, leak detection and verified TLS:

```bash
python3 -m unittest -v yamora.tests.test_schema_receipt_capacity yamora.tests.test_standalone_rollover
```

All seven cases passed: authenticated HTTP capacity and permanent replay; native
inclusive count/encoded-byte capacity across restart; preservation of an oversized
legacy receipt set; private-transaction receipt accounting; actual stage-fsync
failure with fail-stop and restart preservation; profile-5 churn; and profile-7
churn with exact policy receipt preservation. Native count/byte insertion and
before-effects preflight mutants failed before their restored passes. Three
separate daemon mutants also failed at the intended checks: disabled capacity
accepted publication four (200 instead of 413), disabled job handoff lost the
latest exact ID after adoption (404 instead of 200), and disabled rollover
completed no retirements where two were required.

The two restored TLS workloads each retained eight live disjoint document IDs
alongside one hot document, completed two rollovers under a 6 MiB extent ceiling,
and checked queries, indexes, exact job terminal records, binary reconnects,
allocated ports, counters, source bytes and retained feed equality after restart.

| Profile | Hot + disjoint writes | Elapsed s | Writes/s | p50 / p95 / p99 ms | Observed peak RSS KiB | Observed peak native bytes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 5 | 256 + 22 = 278 | 12.569 | 22.12 | 25.77 / 48.18 / 143.76 | 133812 | 2236416 |
| 7 | 249 + 21 = 270 | 9.914 | 27.23 | 20.19 / 39.78 / 98.51 | 140892 | 2228224 |

These are one synthetic fatal-sanitizer workload's observations, with another
admitted suite active, not production throughput claims. Elapsed time includes
churn, query/job checks, feed comparison and process restart; writes/s divides
successful PUTs by that whole interval. Latencies measure PUT calls including TLS
connection setup. RSS and current-plus-staged native file lengths were sampled
every 5 ms; native bytes exclude directory metadata and other filesystem costs.
