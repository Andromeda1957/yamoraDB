# Native document conformance profiles

This test component runs public SDK adapters against an existing immutable native
TLS daemon. The initial profile is `binary-document-standalone`: 22 cases, one
stream, document GET/HEAD/PUT/DELETE. It does not qualify cluster discovery,
durable retry receipts, 304, queries, numeric decoding, pagination or feeds.

The integrated Linux x86_64 run passed all 198 driver/case combinations on
October 25, 2026: 22 each for Python, Go, Node.js, Java, Ruby, Rust, C++, PHP and
C#. It used the shared private-toolchain runner with the supplied fatal
ASan/UBSan daemon. The daemon digest was unchanged and both nested workspaces
and retention guards were removed after verified shutdown. Tool versions came
from the shared [pinned manifest](../../tools/ci/yamora_driver_ci/toolchains.json).
This result qualifies only the standalone profile described here.

The adapter interface is frozen in [ADAPTER_V1.md](ADAPTER_V1.md). Versioned raw
fixtures and the complete case set live in [v1/manifest.json](v1/manifest.json).
Each case ID is bound to its versioned method, source/seed, conditions,
credentials, status, fault, cancellation and direct/relay mode. Alternate
manifests cannot retain the profile name while weakening those scenarios.
The runner supplies only primitive call inputs to adapters. It compares public
API observations separately from actual native wire responses and independent
HTTPS storage observations. Go/Node numeric success statuses and raw receipts
are deliberately absent from their public observations. Static exposure rules
in `contract.py` reject fabricated fields.

With an existing task-owned disk-backed `TMPDIR` and an explicit executable:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m yamora.conformance.runner \
  --binary "$YAMORA_TEST_BINARY" --driver python
```

Add `--sha256` to require an expected daemon digest. The executable is checked
before and after execution and never built or overwritten. Omitting `--driver`
requires all nine adapters. Missing adapter prefixes, executables, tools, cases,
observations or verified process shutdown fail; there are no skips or automatic
subset selection. Parent-owned build/toolchain wiring supplies other launch
prefixes using `--adapters-file` (JSON driver-to-argv mapping).

The shared runner embeds `execute(..., environment=private_environment)` in the
same process. `Native` copies this environment, retaining private homes, tools
and Python imports; only native scratch and fatal sanitizer settings are added.
No global environment mutation is needed. Keep cleanup exceptions in process:
`ProcessGroupCleanupError` must reach any enclosing shared workspace so its
retention guard protects an interrupted launch. A subprocess exit code cannot
carry that exception to an outer workspace.
Adapter executable preflight uses the copied environment's PATH, with no ambient
fallback when a PATH is supplied. The unchanged certificate recipe runs in a
private helper process with the same environment, including OpenSSL configuration
overrides. Existing process-group supervision bounds that helper to 30 seconds;
the recipe retains its 15-second per-command limit. No shared fixture or process
global is patched.
Python's default launch uses `-P` so the caller's checkout cannot shadow the
private PYTHONPATH. With no explicit environment, an absent PYTHONPATH defaults
to the source root containing this core; supplied private import paths are kept.

The ordinary native daemon is sufficient. One bounded relay thread per operation
forwards real TLS binary traffic without executing database logic. It records a
complete native response and checks HTTPS state before withholding/truncating
delivery or changing its request-ID echo. The pre-cancel case requires zero
binary connections. A direct-native GET separately exercises SDK-to-daemon TLS.
Mutation uncertainty retains original ID/conditions/source and forbids automatic
replay. Explicit standalone create-only ID reuse returns 412; this is no claim
of cluster receipt recovery, rollback or interruption of native filesystem work.
The relay keeps observing queued connections and additional REQUEST frames on
the established TLS connection during faults. Only the first operation reaches
the daemon. After adapter exit, a 100 ms quiet period and thread join precede the
no-replay assertion; observation has byte/frame/connection and time limits.

The call deadline is 1500 ms for held responses, with a 500 ms return allowance;
normal calls use 5000 ms. Startup is excluded from adapter call timing. A 20 s
outer process watchdog is always a failure. Relay frames are at most 64 KiB,
bodies at most 128 KiB, and exchanges at most 64 frames per direction. Adapter
JSON/stderr are each capped at 16 KiB, native logs have explicit bounds, and
control/relay threads have bounded joins. Sources include a 69,308-byte fixture
using 4 KiB frames; this profile makes no maximum-document-capacity claim.

Process groups, shutdown verification and retained-workspace guards reuse the
existing shared SDK runner. Disposable allocations are removed after verified
shutdown, including ordinary failures. No installer or package dependency is
introduced. Fatal ASan/UBSan settings apply to daemon initialization and serving.

Focused acceptance (native tests require `YAMORA_TEST_BINARY`, never skip):

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest \
  yamora.tests.test_conformance_contract yamora.tests.test_conformance_native \
  yamora.tests.test_conformance_lifecycle yamora.tests.test_conformance_environment \
  yamora.tests.test_conformance_relay -v
```

The tests run the Python profile and independently qualify byte/ETag/status
corruption, request-ID correlation and terminal-END SDK mutants in isolated
source copies. Each requires a confirmed native exchange, one named behavioral
assertion failure, the exact mutant result, and restored green. A wrong TLS
identity and an actual stalled child are negative controls. Compiler, process,
signal and sanitizer failures cannot qualify as mutant reds.
Lifecycle tests also interrupt actual process construction, require retained
nested workspaces while the daemon remains live, and independently verify
daemon/relay teardown on fixture failures. Only the test's owned children are
stopped before removing those deliberate retained allocations.

For the parent's private source copy, retain `conformance/`, the root
`yamora/*.py` Python import closure, and the existing fixture modules
`yamora.tests.test_binary_client`, `yamora.tests.binary_runtime_support` and
`yamora.tests.test_binary_client_mutants` (the latter for mutant qualification).
The existing `tools.ci.yamora_driver_ci` module/package and toolchain manifest
remain part of the shared runner closure. This child changes none of those
existing helpers, other SDKs, native sources or shared CI/build wiring.
The root production import closure includes `yamora/client.py`,
`yamora/cluster_client.py` and `yamora/http_transport.py`, because the unchanged
package initializer imports HTTP clients. `yamora.tests` is a namespace package
at this base. A bounded import-only child verifies this private closure while
preloading byte-matching shared tools modules and preserving their workspace
and launch-guard objects.

## HTTP replica receipt profile, version 2

The separate `http-replica-receipt` profile exercises public HTTP cluster clients
for Python, Go, Node, Java, Ruby, Rust, C++, PHP and C#. Its contract is
[ADAPTER_HTTP_REPLICA_V2.md](ADAPTER_HTTP_REPLICA_V2.md); the fixed 15 scenarios
and exact CRLF/comment-bearing sources are in
[v2/http-replica-receipt/manifest.json](v2/http-replica-receipt/manifest.json).
The integrated Linux x86_64 run passed all 135 driver/case combinations on
October 25, 2026: 15 each for all nine drivers, using the shared pinned private
toolchains and supplied fatal ASan/UBSan daemon. The executable digest remained
`af72e70c9e2b01c77a0f2b85fb2ee00f7ef2d389c1bcd714d2a203962bf83a78`.
The complete run exited successfully; its nested workspace and retention guards
were removed after verified shutdown. This qualifies the fixed receipt profile,
including its failover, restart, quorum-loss and native-overlap cases. General
query, streaming, numeric and platform conformance remains open.

Use the shared private-toolchain runner from the repository root:

```sh
python3 tools/ci/yamora_driver_tests.py --binary "$YAMORA_TEST_BINARY" \
  --scratch-root "$TMPDIR" --provision --conformance-only \
  --conformance-profile http-replica-receipt
```

Repeat `--conformance-profile binary-document-standalone` to select both without
reprovisioning tools or recopying SDK sources. The default remains version 1.
The supplied executable is pinned before any toolchain/build activity; both
cores receive that same digest and preserve cleanup exceptions during integrity
checks. No daemon is built by this command.

Each case owns three native mTLS members and instruments every configured seed.
All mutation arrivals are recorded before retry gating. Recovery forwarding waits
for the first complete native receipt, independent exact-source/ETag/revision
observation and a witnessed distinct-ID advancement. Replays must retain the
actual SDK-emitted method, target, bytes, conditions and request identity, return
the original native receipt, and leave the newer source unchanged. API exposure
is validated independently and unavailable fields remain null.

The profile covers automatic and explicit recovery, generated IDs, five changed
operation conflicts, leader death, same-root cluster restart and quorum loss.
Its overlap case uses two SDK processes and two distinct native TLS sockets;
request/response timestamps must establish native overlap. Both original SDK
successes and the single increment are required before later advancement and
explicit replay. Holding client replies alone cannot establish this evidence.

Adapters retain actual SDK exceptions/recovery objects in bounded JSONL sessions.
Python/Go/Node/Java/Ruby reissue frozen primitives using the exception's ID;
Rust/C++/PHP/C# use their public recovery envelopes. This profile does not imply
uniform serialized recovery objects or persistence across adapter-process
restart. It does not qualify general numeric/query/stream/platform behavior.
Implementation and qualification checkpoints are tracked in the
[enterprise roadmap](../../docs/plans/yamora-enterprise-roadmap.md).

## Binary operations and page feeds, version 3

The opt-in `binary-operations-standalone` profile exercises schema-2 finite
query/aggregate/search, PATCH, atomic transactions, paged changes and complete
NDJSON feed pages. Its [adapter contract](ADAPTER_BINARY_OPERATIONS_V3.md) and
[22 fixed cases](v3/binary-operations-standalone/manifest.json) preserve the older
profiles. Scenario specifications and expected effects are code-owned; alternate
manifests cannot remove, reorder or weaken a case.

The relay records the actual native exchange before forwarding or interrupting
delivery. Independent HTTPS observations check query results, raw sources,
atomic rejection and absence of a second mutation. Cases cover scoped lookup
and transaction grants, stale pagination, pre-cancellation, absolute deadlines,
original uncertainty envelopes and retention of complete feed pages after an
interrupted tail. The raw-byte API preserves numeric spellings without claiming
decoded numeric-type parity. It makes no discovery or automatic-retry claim.

The SDK helper supports all nine drivers, including Python. Omitting `--suite`
selects all nine; repeat it to choose an explicit subset. The direct core CLI
still requires explicit driver names and adapter prefixes. For example:

```sh
python3 tools/ci/yamora_driver_tests.py --binary "$YAMORA_TEST_BINARY" \
  --scratch-root "$TMPDIR" --provision --conformance-only \
  --conformance-profile binary-operations-standalone
```

This invocation qualifies source consumers. To build packages and qualify
operation adapters against their independent installations, select all three
profiles explicitly:

```sh
python3 tools/ci/yamora_driver_tests.py --binary "$YAMORA_TEST_BINARY" \
  --scratch-root "$TMPDIR" --provision --conformance-only \
  --build-sdk-artifacts \
  --conformance-profile binary-document-standalone \
  --conformance-profile http-replica-receipt \
  --conformance-profile binary-operations-standalone
```

Both existing installed-artifact profiles remain mandatory. The optional third
profile adds 22 operation cases per selected SDK using unchanged copied adapters,
the SDK-independent artifact core and the installed package's runtime. Package
origin checks, private dependency resolution and public-example acceptance still
apply. Omitting either mandatory profile refuses before package work. Python's
operation adapter loads the public client from its verified installed wheel;
the copied fixture core supplies no SDK source fallback.

Installed operation qualification also runs four separate depth acceptance calls
while those same installed consumers remain available: a depth64 array query, a
depth64 mapping aggregate, its terminal facet and an indexed deep mapping search.
Native HTTP admission, exact stored bytes, HTTP 200 results, expected values and
response depths must all pass before an SDK is invoked. Binary responses and SDK
raw bytes must match those native results. This sidecar reports a separate
`yamora-depth-acceptance/1` result under `depth`; it does not add or rename any of
the 22 versioned operation cases. Current native and SDK qualification remains
subject to the recorded verification below.
Operation response readers use a separate depth budget of 80 to include native
domain values and their envelopes. Ordinary JSON defaults and transaction
specification correlation retain their depth budget of 64; byte, node, UTF-8
and duplicate-key checks still apply.
Current verification is recorded in the [Session 4 plan](../../docs/plans/yamora-session-4-developer.md).
