# Bounded fault qualification

`yamora.tests.test_raft_fault_history` adds development evidence for the
experimental static three-voter replica set. It uses the real native daemon,
verified HTTPS, mutual TLS between voters, separate native data/journal roots,
and synthetic exact YAML. It does not establish production qualification,
availability targets, crash safety under power loss, or general transaction
linearizability. The [replica-set contract](replica-sets.md) remains authoritative.

## Request-history oracle

`yamora/tests/raft_fault_history.py` accepts immutable `Call` records with
monotonic invocation/completion times, operation, outcome, exact mutation bytes,
request ID, exact read source, and successful status/body/ETag receipts.
`check_history(calls)` returns a deterministic `Checked(order, explored)` witness
or raises `HistoryViolation`. Inputs are limited to 128 calls and 100,000 search
states; exhaustion fails qualification instead of accepting a partial check.

The intentionally small model starts with the fixture's counter at zero and
supports a nonzero integer `$inc` on that document, reads, changed-request 409s,
and unavailable reads. It checks every successful intermediate read against the
exact source bytes, including comments and CRLF. It searches for an order that
respects real-time intervals, permits each logical ID's increment once, and
preserves acknowledged effects across subsequent successful reads. Concurrent
calls may appear in either legal order. A successful retry must return the same
status, body and ETag as every earlier successful attempt for that ID. A 409
requires different request bytes and an applied original; it has no effect.

Timeouts, EOFs and mutation 503s are **uncertain**, not proven failures. Attempts
with the same ID and exact bytes form one logical write, from first invocation
through first successful response. An unresolved write may take effect zero or
one times after invocation, even after its timeout. Successful reads and later
retries constrain that choice. A read 503 exposes no state. The oracle does not
infer non-application from a disconnect or require an uncertain request to have
completed inside the failed attempt's interval.

Every new logical operation uses a separate nonzero ID. Setup PUT is outside
the counter history; only increments and observations after its acknowledged
zero state enter the model. Method, document path and absence of preconditions
are fixed by this test driver; this is not an oracle for arbitrary API traffic.
Proxy-observed successful receipts are compared against later retries by the
scenario, while the client-visible history correctly records the lost reply as
uncertain. The proxy's independently observed HTTP 200 also requires the
cumulative exact source to be visible before any retry, both after leader loss
and before/after full process restart. Client-only uncertainty would otherwise
permit a stale read followed by application during the retry interval.
Whole-snapshot revision headers are not replay receipts.

## Actual failure schedules

| Test | Failure and observations |
| --- | --- |
| `test_seeded_lost_replies_and_repeated_leader_loss` | Three rounds with seed `0x59414D4F5241`: forward a real HTTPS increment, consume its successful upstream reply, SIGKILL that leader, and close the client's TLS connection without an HTTP reply. Elect a survivor, read before retry, retry identical bytes/ID and compare the retained receipt, reject changed bytes with 409, read again, restart the former leader, and wait for its applied prefix to catch up. |
| `test_lost_reply_then_full_process_restart_retains_receipt` | Seed `0x52455354415254`: lose a successful reply, read its effect, wait for all three applied prefixes, SIGKILL all three processes, reopen the same hermetic roots, read again, and retry the same ID with the original receipt and one effect. |
| `test_quorum_loss_uncertainty_and_concurrent_same_id_retries` | Seed `0x51554F52554D`: acknowledge a write, SIGKILL both followers, require an uncertain mutation and a 503 document read from the remaining process, restore quorum, observe and resolve the same ID, then use two simultaneous HTTPS clients to retry the earlier acknowledged ID without another effect. |

The duplicate retries pass through an owned HTTPS proxy. Two bounded rendezvous
points wait for both actual requests before dispatch and both upstream replies
before delivering either response. The scenario also requires strict overlap of
the two intervals recorded around the real client calls: the later invocation
must precede the earlier completion. An initial thread barrier alone would not
prove overlap; invocation timestamps are never manufactured or edited. Both
proxy rendezvous expire after three seconds and abort together on error.

Each test checks its complete history, rather than only a final count, and
rejects a deliberately corrupted copy of an actual intermediate observation.
Separate unit controls reject a multiply-applied retry, a stale intermediate
read even when the final count is correct, changed receipts, changed request
bytes, and exact-source corruption. Valid controls include overlapping writes,
an unapplied uncertain request, and a request applied after timeout.

The workload IDs, increments and fault points are seeded and fixed. Native
election randomness, certificate keys, OS scheduling and ephemeral ports remain
nondeterministic; these tests do not claim a reproducible thread schedule. A
scenario has a 90-second admission budget, socket calls at most four seconds,
existing fixture startup/convergence waits at most 20 seconds, and bounded
process/proxy cleanup. A fixture wait already in flight may finish after the
admission budget; exceeding the budget fails the next scenario action. There is
no unbounded retry loop or soak. Only processes created by the fixture are
signalled; no system network configuration is changed.

## Focused execution and discovery

Build a native daemon into a task-owned directory with at most two build jobs,
or supply an existing verified immutable daemon through `YAMLDB_BUILD_DIR`.
These tests never build or overwrite that executable. From the repository root,
after creating your owned disk-backed scratch root, run:

```sh
TMPDIR=/var/tmp/andromeda-work/yamora-fault-qualification \
PYTHONPYCACHEPREFIX=/var/tmp/andromeda-work/yamora-fault-qualification/pycache \
YAMLDB_BUILD_DIR=/var/tmp/andromeda-work/yamora-fault-qualification/daemon \
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1 \
python3 -m unittest -v yamora.tests.test_raft_fault_history
```

The daemon must already exist at `$YAMLDB_BUILD_DIR/yamora`; a missing binary
fails instead of silently skipping real tests. The class checks its digest
before and after the run. OpenSSL CLI/system TLS and Python's existing standard
library fixtures suffice; no SQLite, external database, owner data or network
service is used. All sockets bind loopback ephemeral ports, with port 8000
explicitly excluded. Temporary certificates, credentials, roots and logs follow
`TMPDIR` and are automatically removed on success/failure. The invoking task
owns cleanup of its bytecode cache and scratch root.

The existing `yamora/Makefile` `test_*.py` discovery finds the new module.
The parent integrating these tests owns shared CI/registry wiring; select
`yamora.tests.test_raft_fault_history` in any explicit native module list and
provide the built daemon and owned `TMPDIR`. The helper is not a separate test
module. The pure oracle subset can run without a daemon with:

```sh
python3 -m unittest yamora.tests.test_raft_fault_history.FaultHistoryCheckerTests
```

## Remaining qualification limits

- Process stops simulate missing peers, not asymmetric network partitions.
  Half-open links, majority/minority partitions with all processes alive,
  overlapping partitions and partition healing still need separate evidence.
- No slow disk, full disk, fsync failure, torn write, controller-cache power
  loss or filesystem corruption is injected here. Existing native storage
  fault harnesses are different evidence, not covered by these HTTPS runs.
- No explicit peer packet drop, duplication, delay or reorder is injected;
  normal TLS/TCP delivery and process loss are the only transport conditions.
- Three fixed voters, one small document, a few operations and two concurrent
  retry clients do not cover membership changes, shard routing, arbitrary
  transactions/queries, large documents, snapshot/receipt retention, sustained
  saturation, resource bounds or long-duration endurance.
- Losing a reply is injected after the native upstream success is consumed.
  Arbitrary kill positions between journal append, quorum, application,
  receipt publication and socket send remain outside this black-box schedule.
- Whole-process restart follows confirmed three-node application; it does not
  test simultaneous loss before replication or actual power failure. Catch-up
  positions are synchronization evidence; exact-source reads in this suite
  use the current quorum-serving leader, not follower-local storage inspection.

These exclusions remain release-readiness work. A passing bounded run is not a
reason to mark the entire enterprise roadmap or sustained operational
qualification complete.
