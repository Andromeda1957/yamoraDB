# Session 2 distributed fault qualification

The Session 2 qualification harness extends the [bounded counter oracle](fault-qualification.md)
with native instrumentation, independent per-seed histories and real mutual-TLS
peer fault relays. The qualification module requires an instrumented native
daemon. The helper controls passing independently do not establish that the
three-daemon workloads passed, and a local run does not establish independent-host
availability or a production latency guarantee.

## Native boundary contract

Build the qualification candidate with `YD_RAFT_SESSION2_TEST_HOOKS` and link
`src/consensus/session2_hooks.c`. Ordinary builds use the header's inline no-ops
and have no hook environment, file, timing or linkage dependency. The Makefile's
`yamora-session2` target enables the hooks; ordinary `all` builds remain separate.

The native caller supplies its voter ID and original 16-byte request ID to
`yd_session2_mutation_enter`, before waiting on write serialization; it calls
`yd_session2_mutation_exit` on every return. An admission failure returns
`allowed=false`. Disk-delay hooks belong at actual journal persistence and
maintenance begin/end hooks surround actual maintenance work.

Each node receives `YAMORA_SESSION2_TRACE` naming a precreated owned, regular,
single-link `0600` trace file and `YAMORA_SESSION2_CONTROL` naming an owned
`0700` directory. Final symlinks are refused. Control files are bounded owned,
single-link `0600` regular files:

| File | Meaning |
| --- | --- |
| `overlap-id` | Exactly 32 lowercase hexadecimal characters; hold matching native calls until two have entered, for at most three seconds. Both calls retain overlap evidence even when one exits first. |
| `disk-delay-ms` | Decimal delay from 1 to 250 milliseconds, optionally followed by a newline; applied by the real persistence caller. Missing/invalid delay files produce no delay. |
| `index-hold` | Exactly 32 lowercase hexadecimal characters; hold the matching index worker at its first scan step for at most three seconds, with an `index_hold` trace. |

Trace lines have `version:1`, `event`, `node` and `monotonic_ns`. Mutation events
add `request_id` and unique `call`; `gate_pass` adds `request_id` and `active>=2`;
`gate_timeout` is explicit. `disk_delay` adds `delay_ms`. Maintenance events add
`kind` (`journal_compaction`, `application_compaction` or `checkpoint`) and
`cycle`. The helper bounds active calls at 256 and writes one bounded JSON line
per event using `O_APPEND`. Trace/control failures cannot manufacture a pass.

`session2_evidence.py` requires complete, strictly overlapping native call
intervals for the same ID and node plus native gate evidence. Overlapping HTTP
or proxy intervals alone fail. Maintenance also needs overlapping native work
and mutation intervals on the same node. Trace parsing permits at most 8 MiB,
20,000 lines and 2 KiB per line; missing, malformed and exhausted evidence fail.

## Network faults and histories

`session2_faults.py` creates six directed routes for three voters. Each relay
authenticates the expected source SAN with the destination's synthetic test
certificate, opens a verified upstream mutual-TLS connection with the source's
synthetic certificate, and forwards the exact original native RPC frame and
payload. Fixture keys are generated only for synthetic test identities. Every
native request and reply retains the original source/destination IDs; native
packet validation still runs. This test controller terminates TLS on both
authenticated legs so it can fault a completed native reply separately from a
TLS handshake. It is not a production proxy.

Each route can reject new/existing traffic, delay requests or replies, or drop a
reply after consuming the target's actual response. A shared bounded reorder
controller holds the first completed reply until another has been delivered;
the scenario checks the observed delivery order. It never rearranges bytes
inside a TLS/TCP stream. Policy snapshots apply to admitted calls; healing
restores all subsequent connections. Frames are limited to 1 MiB, each route to
eight concurrent calls, sockets to three seconds, and reorder waits to two
seconds. Owned sockets, server threads and fixture processes are joined on
success and failure. No system network configuration or foreign process changes.

`test_session2_qualification.py` runs three separately seeded clusters, each
with its own roots, exact-source observations and history. Each seed runs 12
paced fault cycles spanning at least 45 seconds by default, with a 240-second
action budget, at most four seconds per client call, and the fixture's bounded
startup/convergence waits. `YAMORA_SESSION2_MIN_SECONDS` permits 30–120 seconds.
The complete per-seed history stays within the oracle's 128-call/100,000-state
limit; an exhausted check fails.

The schedule includes live minority/former-leader isolation, two-voter majority
progress, one-way partitions and healing, lost/delayed/reordered processed peer
replies, repeated leader SIGKILL, full process restart, a 40 ms native persistence
delay, and enabled concurrent checkpoint capture/publication. Checkpoints prune
the logical prefix; these histories do not qualify physical journal replacement
or reclamation. Each seed independently loses
at least one successful HTTP mutation acknowledgement. An HTTPS proxy retains
the original native status/body/ETag; after leader loss, the new leader must
return the exact cumulative YAML before any retry. The successful retry must
retain that original receipt. Every uncertain ID needs this independent witness;
an unexpected uncertain submission fails the scenario rather than escaping it.
The same seed also requires actual native same-ID overlap and maintenance/disk
evidence. Changed-byte retries must return conflict without another effect.

Every complete history runs through the independent original oracle. A corrupted
copy of an actual intermediate source must fail as a negative control. Reports
include the seed, daemon digest, elapsed duration, calls/outcomes, p50/p95/max
observed call latency, oracle states, peer-event count and explicit host count.

## Qualified native behavior

The retained strict-Clang, fatal-ASan/UBSan qualification includes the actual
native daemon and its production source dependencies. Helper tests alone do not
establish these results. The three sustained histories each passed the original
consistency oracle, exact-source/receipt checks, native overlap and checkpoint
evidence, and a corrupted-source negative control:

| Independent seed history | Duration | Calls | Successful outcomes | Uncertain writes | Unavailable reads | p50 / p95 / maximum call latency (ms) |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| A | 45.083655 s | 59 | 43 | 2 | 2 | 92.236 / 262.489 / 2502.282 |
| B | 45.069944 s | 59 | 43 | 2 | 2 | 91.564 / 270.744 / 2502.338 |
| C | 45.059821 s | 59 | 43 | 2 | 2 | 91.324 / 284.874 / 2502.153 |

Each history also contains 12 rejected changed-byte retries. The two uncertain
writes have independent exact-source witnesses before retry; they are not
counted as successful acknowledgements. These are three single-host,
three-daemon histories. They qualify concurrent checkpoint capture/publication
and logical prefix pruning, not physical journal replacement or reclamation.
Latency includes the deliberately injected faults and delays. The
[combined native report][final-native-proof] records these observations without an
availability SLO.

The final [combined native run][final-native-proof] exercised 131 methods on
Precision: 130 passed, with one synthetic-CA error under Python 3.14 strict TLS.
The CA now declares critical certificate/revocation signing usage; the exact
mutual-TLS control case passes after that repair, including rejection of peer
identities and arbitrary child commands. Production source and Makefile remained
identical across the combined run and focused repair. The table above records
that run's three independently checked histories.

The subsequent native continuation repair adds a fresh local quorum proof before
looking up a saved scan. Both new regressions failed first: nonfirst shard leaders
returned 409 on the second page, and held pages bypassed proof loss. All nine
affected native service/sharding methods then passed under fatal ASan/UBSan in
353.516 seconds. The original captured generation remains pinned, genuine stale
cursors remain rejected, and authorization still precedes proof/cache access.
This nine-line guard is the only native source change since the combined run;
all other native source and the Makefile retain that run's implementation.
[Continuation and bridge proof][continuation-proof]

The following additional checks passed with actual native state assertions.
Each listed regression first failed against the unfixed behavior and passed
again after restoring the fix:

| Boundary | Qualified result and proof |
| --- | --- |
| Checkpoint/read quorum race | A checkpoint invalidates the old membership proof; renewal requires fresh acknowledgements under the original absolute deadline. Both unfixed cases and separate stale-acknowledgement/deadline-extension controls failed before restored passes. [Proof][barrier-proof] |
| Marked joint membership | Five real HTTPS/mTLS peers replace and remove voters, install a committed joint checkpoint through an eligible nonleader candidate, retain the learner's lack of authority, and recover membership, exact source and receipts across restart. Old admission gates fail at marked installation; restored gates pass. [Proof][membership-proof] |
| Paired backup | All 13 native cases pass, together with public mTLS CLI backup into an empty private destination, restore into clean document/journal roots and rejoin under the original identity with the original receipt. The public CLI capture regression failed before the cancellation wrapper and passed after it. A five-identity replacement/removal backup also restores clean paired roots and proves committed/applied positions plus voter/retired state while every peer is stopped, before rejoin/source/receipt/fresh-write checks. No-op restore and omitted membership metadata both fail before peers can repair state. [Isolated restore proof][isolated-backup-proof]. [Contract](cluster-backup.md), [combined proof][native-report], [CLI proof][cli-proof] |
| Backup/application drain | A paused fetch is genuinely pruned while backup drains the application. The old guard produces a 503 fresh read; the restored guard passes exact source, receipt retry, fresh writes, unfenced state and full restart. [Proof][membership-proof] |
| Membership cancellation | Cancellation at real runtime and controller timed waits formerly wedged status or fresh reads. Both restored cases pass status, lost/fresh quorum barriers, proposal, exact source, original receipt retry, fresh write and clean close. [Proof][cancellation-proof] |
| Public/private HTTP methods | Administrative forged `YSHARD` and `FAIL` return 200 before the gate; `PUBLISH` reaches the private resolver with 409. All three regressions pass after the public allowlist: denied calls return 405 without log changes, the held index job stays running, genuine internal publication and documented CRUD/query methods succeed. [Proof][http-proof] |

The [nine-daemon fixture](shard-service.md) also passes public routing,
scatter/gather, exact global order and pagination, native aggregation, all three
group leader failures, original receipt replay and partition migration. It runs
control and two data groups on one physical host; it does not establish
independent-host load distribution. [Native integration proof][routing-proof]

[Analytics qualification](explain.md) includes six native sanitizer methods and
31 joined-query/disk-aggregation methods, including the million-document
streaming reducer, typed missing/null behavior, all-foreign authorization,
caller-pinned views, cancellation and shared work bounds. The denied second
foreign relation, wrong native totals and eight focused native mutations have
observed RED/restored-GREEN controls. The preserved 1,000-row multiply/group/sort
measurements report 711,736 retained state bytes, 383,923 work units and
0.077054/0.146250 seconds for feeding/finalization, excluding compilation and
process startup. State is not process RSS, and these local measurements are not
independent-host throughput or a latency guarantee. [Analytics proof][analytics-proof]

## Execution

The parent builds one exact instrumented candidate and supplies its immutable
directory through `YAMLDB_BUILD_DIR`; this test module never builds or overwrites
the daemon. The binary digest must stay unchanged during the run. Use the normal
managed task supervisor, with task-owned disk scratch, fatal ASan/UBSan and the
shared two-heavy-job limit. From the task worktree, helper controls run with:

```sh
python3 agent/task_environment.py run --task yamora-session2-qualification -- python3 -m unittest -v yamora.tests.test_session2_faults yamora.tests.test_session2_stdio_mux
```

For real workloads, launch `yamora.tests.test_session2_qualification` through the
same supervisor with the candidate directory and sanitizer settings set inside
the worker. A missing daemon, absent native instrumentation, missing gate/delay
or maintenance evidence fails; these requirements are never skipped. Existing
`test_*.py` discovery finds the modules; the parent owns explicit native CI/module
registry selection and the shared instrumented build.

`tests/run_session2.py` builds normal and instrumented candidates with Clang,
strict warnings and fatal ASan/UBSan in managed scratch, then runs either its
explicit acceptance modules or the modules supplied as arguments. Its three
sustained seeds each run for at least 45 seconds by default and report the
instrumented executable SHA-256 alongside independent history-oracle results.

## Independent-host shard qualification

`tests/session2_two_host.py` runs one bounded worker per managed container.
The parent supplies one clean committed source identity and a private synthetic
TLS fixture to both workers, builds and records each executable's SHA-256, and
connects their stdio using strict host-authenticated SSH. The existing opaque
Mux retains end-to-end native mTLS; SSH keys and host networking stay outside
the containers. Native children receive closed stdin and have explicit bounded
ownership and teardown, including partial startup and Mux failures.

The ThinkPad side owns the control and alpha groups; Precision owns beta.
Each group has three local Raft voters. The scenario checks 288 exact authored
documents, multi-page gather, global ordering/offset/limit, native aggregation,
work on both physical hosts, router and group leader loss, whole-query rejection
on beta quorum loss, recovery, and alpha-to-beta migration. The parent must
observe both worker exits and cleanup receipts with zero running native children.
Two physical failure domains do not provide a three-host quorum or survival
after losing a host containing an entire group's voters. Published request and
recovery bounds describe this deployment, including the SSH bridge's overhead.

## Two-host route

Read-only SSH inspection confirmed the existing Precision host at
`andromeda-worker` is a Precision Tower 3431, x86-64, six cores, about 15.8 GB RAM
and 129 GB free SSD at inspection. Capacity inspection does not establish a
Session 2 execution result or authorize restarting another task's retained work.

The Session 2 managed source/toolchain probes and canonical source/Git access
passed on Precision with SELinux Enforcing. Named-worker shared labels apply
only to the canonical task source and exact common Git directory; primary
read-only source and generic system/dependency mounts retain their existing
options. The [completed physical-host run][two-host-proof] passed with three
groups, nine native voters and 288 exact authored CRLF documents. Both hosts
independently built strict-Clang fatal-ASan/UBSan candidates from the same clean
commit. Both worker readiness events, cleanup receipts for six/three children
with zero running, unforced supervisor exits with status zero and launcher exit
zero were observed.

Before migration, alpha on ThinkPad held 141 documents and advanced its applied
position by 141; beta on Precision held 147 and advanced by 148, including a
later authored version. The 32-query window recorded 2,046/718 native CPU ticks
on alpha/beta; these include concurrent Raft work. Reported CPU affinity was
eight/six. Exact global ordering, pagination, all-row source equality and native
aggregation (41,328) passed. Original beta receipt replay preserved the later
source. Alpha-to-beta migration survived frozen-source leader loss, traversed
phases 1, 2, 2, 2, 3, 4, 0, activated epoch two and converged after full rejoin.

| Observation | Measured result |
| --- | --- |
| 32 queries, up to four callers: min / median / p95 / maximum | 3,079.186 / 6,027.196 / 6,857.636 / 6,886.088 ms |
| Router process and control leader recovery | 3,900.726 ms; 14 attempts |
| Beta shard leader recovery | 3,017.063 ms; two attempts |
| Beta lost majority | Whole query rejected without partial rows in 5,600.730 ms |
| Restored beta majority | 1,999.294 ms; one attempt |
| Frozen migration-source leader recovery | 5,448.314 ms; four attempts |

Latency includes native TLS, queueing and the opaque SSH bridge. Requests retain
their 20-second bound and recovery observations their 30-second bound. Each
group's three voters remain on one physical host: losing that host removes the
group's quorum. These measurements qualify bounded cross-host work and recovery;
they do not establish a three-host quorum, horizontal throughput scaling,
whole-host survival, sub-second failover or a production availability SLO.

All 35 helper/Mux controls also pass after observed timeout-setter races were
confined to the already closing channel. An unrelated channel must still deliver
exact bytes; malformed frames, stdio failures, deadlines and byte budgets retain
their existing failure checks. Diagnostics publish only bounded categories,
helper coordinates and allowlisted native HTTP status fields, never fixture
credentials or raw response/log contents. [Proof][continuation-proof]

`session2_stdio_mux.py` supports a separately assigned and committed Session 2
managed worker on Precision without host networking or mounting SSH keys. The
parent host starts strict-host-key SSH, launches each managed supervisor, and
connects their inherited stdin/stdout with owned pipes. Each managed container
runs native child processes and one mux endpoint in the same network namespace.
The transport remains opaque: original native mTLS runs end to end across SSH.
Only fixed named loopback endpoints are reachable; port 8000 is refused.

```sh
python3 -m yamora.tests.session2_stdio_mux --side 0 --target node1=21001 --listen node2=21002 --seconds 300
python3 -m yamora.tests.session2_stdio_mux --side 1 --target node2=21003 --listen node1=21004 --seconds 300
```

The port numbers illustrate matching names, not allocated test ports. The parent
must reserve real task ports and align source/candidate identities before launch.
Stdout contains only binary frames; diagnostics and results use stderr. A parent
wrapper can import `Mux`, start its native children, configure targets/listeners,
and call `serve()`. A standalone mux process cannot reach another container's
loopback. Frames are at most 16 KiB, channels at most 32, outbound bytes at most
64 MiB by default, total lifetime at most 600 seconds, connect/write waits two
seconds, and owned worker shutdown three seconds. Nonblocking stdio enforces the
deadline even when SSH stops reading. Malformed, truncated, unassigned, duplicate
or exhausted frames fail closed.

The ThinkPad/Precision deployment represents two physical failure domains.
It cannot establish three-host quorum fault isolation. A third host,
power-loss faults, real full-disk/fsync failure, sustained saturation, large data,
arbitrary transactions, independent-host membership changes and saturated shard
throughput remain outside this bounded workload's evidence. Neither these bounds
nor the passing two-host run supports a sub-second failover claim or an
availability SLO.

[native-report]: ../../docs/site_history/changelog/entries/2026-10/20261026T103457740416-0500-record-native-session2-replication-and-fault-qualification.md
[barrier-proof]: ../../docs/site_history/changelog/entries/2026-10/20261026T093545588779-0500-prove-checkpoint-racing-read-barriers-renew-bounded-quorum-p.md
[membership-proof]: ../../docs/site_history/changelog/entries/2026-10/20261026T102754796959-0500-qualify-backup-drain-racing-a-pruned-application-fetch.md
[cli-proof]: ../../docs/site_history/changelog/entries/2026-10/20261026T095213075143-0500-protect-fenced-backup-capture-and-document-integrated-sessio.md
[cancellation-proof]: ../../docs/site_history/changelog/entries/2026-10/20261026T104615383712-0500-verify-native-membership-cancellation-releases-runtime-and-c.md
[http-proof]: ../../docs/site_history/changelog/entries/2026-10/20261026T105630653597-0500-reject-private-replicated-verbs-at-the-native-http-boundary.md
[routing-proof]: ../../docs/site_history/changelog/entries/2026-10/20261026T093156449362-0500-wire-replicated-publication-backup-and-sharding-into-the-nat.md
[analytics-proof]: ../../docs/site_history/changelog/entries/2026-10/20261026T090343955504-0500-qualify-session-2-native-analytics-and-cumulative-filter-bud.md

[final-native-proof]: ../../docs/site_history/changelog/entries/2026-10/20261026T132443566721-0500-record-full-frozen-session-2-native-acceptance-and-isolated-.md
[isolated-backup-proof]: ../../docs/site_history/changelog/entries/2026-10/20261026T130936926524-0500-prove-restored-topology-before-backup-peers-rejoin.md
[continuation-proof]: ../../docs/site_history/changelog/entries/2026-10/20261026T155321882426-0500-qualify-shard-continuations-and-isolate-bridge-channel-close.md
[two-host-proof]: ../../docs/site_history/changelog/entries/2026-10/20261026T160620335831-0500-qualify-session-2-routing-across-two-physical-hosts.md
