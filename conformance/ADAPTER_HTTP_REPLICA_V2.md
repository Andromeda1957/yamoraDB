# Frozen HTTP replica receipt adapter contract, version 2

Protocol freeze: `http-replica-receipt`, independent of the binary standalone
version 1 profile. All nine SDKs are required for a complete qualification.
This file fixes the adapter interface before runner/adapter implementation.

## Launch and configuration

Launch an existing public-SDK adapter argv prefix, without a shell, followed by:

```text
--config ABS_SESSION_ROOT/config.json --root ABS_SESSION_ROOT
```

The runner creates a private disk-backed session root and every input/output
directory. All JSON file names below are relative to that root, regular files
with no symlink component or traversal. Configuration itself must be exactly
`ROOT/config.json`. No arbitrary metadata, executable, URL or operation file
paths are accepted. The exact config object is:

```json
{
  "schema": "yamora-http-replica-config/2",
  "cluster_id": "01020304000000000000000000000000",
  "voters": 3,
  "seeds": [
    {"host": "127.0.0.1", "port": 19001, "node": 1},
    {"host": "127.0.0.1", "port": 19002, "node": 2},
    {"host": "127.0.0.1", "port": 19003, "node": 3}
  ],
  "tls": {"ca_file": "ca.pem", "cert_file": "client.pem", "key_file": "client.key"},
  "tokens": {"read_file": "read.token", "write_file": "write.token"},
  "timeout_ms": 15000,
  "attempt_timeout_ms": 3000
}
```

`config.json` and each PEM/key file are nonempty and at most 16384 bytes;
each token file is nonempty and at most 512 bytes. These configuration bounds
are separate from the 131072-byte source/output file bound.

Seeds are three distinct loopback proxy ports (1..65535 except owner port 8000),
bound one-to-one to nodes 1..3; their list order is routing priority, not identity.
Cluster identity is nonzero 32 lowercase hexadecimal digits. TLS is verified
TLS 1.3 with fixture CA, client identity and exact `IP:127.0.0.1` server SAN.
Do not use the binary v1 DNS-name override. Only configured seeds receive SDK
credentials. The runner observes all seeds, including discovery, cached routes
and retries. Credentials are synthetic files, never values in JSON/argv/logs.
Map the fixed logical budget to public SDK configuration; where a separate
attempt budget exists, set 3000 ms. No private API or timeout reset is allowed.

## Bounded persistent JSONL session

Each stdin command and stdout observation is one UTF-8 JSON object plus one LF,
at most 16384 bytes including LF. Literal CR bytes anywhere in the frame reject;
escaped `\r` inside JSON strings is permitted. JSON number tokens must be
integers; floating tokens such as `1.0`, duplicate keys, nonfinite numbers,
unknown keys, wrong types and nesting deeper than 12 reject. Stdout has no banners.
Stderr is at most 16384 bytes for the whole session, with no source, credentials
or peer error text. Exit nonzero for invalid input or infrastructure failure;
handled public SDK errors produce observations and keep the session alive.

Sequence starts at 1 and increases by one, maximum 64 commands. One command is
outstanding per process; use two processes for the overlap case. At most 16
recovery handles are retained. A command has a 25-second outer watchdog; an
adapter-process timeout is infrastructure failure, never a behavioral red.
The 15-second SDK call budget starts immediately before public API invocation,
after configuration, client construction and command parsing. Closing stdin
without `close` is an incomplete session. `close` disposes the SDK and helpers,
emits its observation, then exits 0. The runner owns all processes and cleanup.

Exact `call` command (all shown keys required):

```json
{"schema":"yamora-http-replica-command/2","seq":1,"action":"call","method":"PUT","collection":"manifests","document":"counter","source_file":"input/value-a.bin","request_id":"11111111111111111111111111111111","if_match":null,"if_none_match":"*"}
```

Methods are GET/PUT/PATCH/DELETE. Collection/document are `[a-z0-9-]{1,128}`;
mutations reject collection `yamldb-system`. IDs are nonzero 32 lowercase hex;
null requests SDK generation for mutations. GET requires ID and both conditions
null. `if_match` is null or a quoted 16-lowercase-hex ETag; `if_none_match` is
null or `*`, only on PUT, and cannot coexist with `if_match`. No empty/combined
or arbitrary condition values are in this profile. `source_file` is null for
GET/DELETE; otherwise exactly `input/[a-z0-9-]{1,64}.bin`, nonempty and at most
131072 bytes. PUT preserves raw UTF-8 YAML bytes. PATCH file contains exactly
the JSON value `{"$inc":{"n":1}}`; whitespace is permitted, duplicate keys
are not. Typed SDKs own encoding; record their first actual outgoing bytes and
require identical bytes on every retry. Do not claim input JSON whitespace
preservation. Adapters never parse YAML, implement HTTP or retry themselves.

Exact recovery and close commands:

```json
{"schema":"yamora-http-replica-command/2","seq":2,"action":"recover","handle":"h1"}
{"schema":"yamora-http-replica-command/2","seq":3,"action":"close"}
```

Handles are `h1`..`h16`, assigned in order on uncertain `call` results and retained
until close, including after successful recovery. Recover rejects unknown
handles. Adapters retain the real exception/recovery object. For the five
ID-only SDKs, retain the original immutable primitive arguments before dispatch,
take the recovery ID from the actual SDK error, and reissue that primitive via
the public SDK. Report `caller-reissue`; never fabricate an SDK envelope.
For the four envelope SDKs use the actual SDK recovery object and report
`sdk-envelope`. Each recovery is one public recovery/execute/primitive call;
the SDK may internally discover and retry. Never recover through direct HTTP.

## Observation

All keys are required; unavailable fields are null. Output files go only in the
runner-created `call-NNNNNN` directory for this command's six-digit sequence.

```json
{
  "schema": "yamora-http-replica-observation/2",
  "seq": 1,
  "action": "call",
  "outcome": "uncertain",
  "error_kind": "transport",
  "elapsed_ns": 15000000000,
  "api": {"status": null, "body_file": null, "etag": null, "revision": null, "receipt": null},
  "sdk_request_id": "11111111111111111111111111111111",
  "envelope": null,
  "recovery_mode": "caller-reissue",
  "recovery_handle": "h1"
}
```

Outcomes: success/status/uncertain/deadline/cancelled/protocol/transport/closed.
`error_kind` is null on success/closed; otherwise the corresponding typed
status/deadline/cancelled/protocol/transport category. It may be null for
uncertain when the SDK exposes no typed cause. Do not classify by error text.
`api.status` is only an actually exposed HTTP status, including an SDK error's
status; never infer it from a successful method. `api.body_file` is
`call-NNNNNN/body.bin`: raw SDK response/source bytes, or Java's original JSON
text encoded as UTF-8, never reconstructed JSON. Exposed empty bodies have
empty files. Each file is at most 131072 bytes. `api.receipt` is only the SDK's
returned receipt fields. ETags preserve API spelling. `sdk_request_id` is only
the ID exposed by uncertainty, not an input copy or a response echo.

Uncertain calls require SDK ID and handle/mode. Other `call` outcomes have all
four recovery fields null. Recover observations always retain the requested
handle/mode; SDK ID/envelope are present only if that recovery itself returns
uncertainty. Close has outcome closed, elapsed 0, and every API/recovery/error
field null. No observation contains native evidence or pass assertions.

An actual SDK-owned envelope has exactly these keys:

```json
{"method":"PUT","path":"/v1/collections/manifests/documents/counter","if_match":null,"if_none_match":"*","request_id":"11111111111111111111111111111111","body_file":"call-000001/envelope.bin"}
```

Read fields only from the exception-owned prepared mutation, converting its
public ETag/create-only representation to equivalent quoted HTTP conditions.
Write the owned body to the fixed file. DELETE's body file is empty except C#,
whose public recovery Body is null and must be reported null. Credentials and
opaque serialization are absent. No public import API for serialized prepared
objects is claimed. Full daemon restart retains adapter sessions.

## Frozen public API exposure

PUT/PATCH receipts have five fields: `status` (text `stored`), `collection`,
`document`, `etag` (unquoted hex), `revision`. Go exposes only status/etag/revision;
C# ordinary mutations only ETag/revision, without a receipt object. Raw response
SDKs report receipt null; the runner parses their body independently.

| SDK | Public cluster and recovery APIs | Successful PUT/PATCH; DELETE; GET |
| --- | --- | --- |
| Python | YamoraClusterClient; reissue primitive with error.request_id | receipt; no return fields; source bytes only |
| Go | New(Config.Seeds), WithRequestID; reissue using UncertainWriteError.RequestID | three-field receipt; no return fields; source/etag/revision |
| Node | ClusterClient, requestId; reissue using UncertainWriteError.requestId | five-field receipt; revision; source/etag/revision |
| Java | YamoraClient.replicaSet, WriteOptions; reissue using YamoraException.requestId() | status/original JSON text/revision/five-field receipt; revision; source/etag/revision |
| Ruby | Yamora::ClusterClient, request_id; reissue using UncertainWriteError.request_id | five-field receipt; revision; source/etag/revision |
| Rust | ClusterClient; execute(ClusterError::Uncertain.mutation) | status/body/quoted etag/revision; same; source/unquoted etag/revision |
| C++ | ClusterClient; execute(UncertainWriteError.mutation()) | status/body/unquoted etag/revision; same; source/unquoted etag/revision |
| PHP | ClusterClient; recover(UncertainWriteException) | five-field receipt; revision; source/unquoted etag/revision |
| C# | ClusterClient; RecoverAsync(UncertainWriteException.Recovery) | ordinary etag/revision; revision; source/unquoted etag/revision |

For receipt APIs, also report `api.etag`/`api.revision` from the returned receipt.
Java's etag comes from its receipt, not a claimed header. C# RecoverAsync alone
returns status/raw body/quoted etag/revision, receipt null, for all mutations.
Java protocol errors retain a received HTTP status when exposed by
`YamoraException.status()`; status zero is reported as null. This includes a
received 200 rejected for invalid document metadata. Other error fields remain null.
All other receipt/API ETags above are unquoted. HTTP success exposes no request
ID echo. HTTP numeric success status/raw mutation body are absent for
Python/Go/Node/Ruby/PHP and ordinary C#. Python/Go/Node/Java/Ruby have no public
HTTP prepared envelope/recovery method. PHP forbids reentrant/Fiber concurrency;
two processes avoid making a shared-instance concurrency claim.

Python/Go/Node/Java expose no expected cluster-ID, voter-count or seed-node
configuration. Rust exposes voter count and seed nodes, but no expected
cluster-ID setter. Validate all config fields; use the public bindings that
exist, without claiming that local validation authenticates a cluster UUID.
Ruby/C++/PHP/C# expose expected cluster-ID, voters and seed nodes and must use
those public bindings. The runner retains native identity/source evidence
separately from each SDK's verified discovery. Rust's HTTP Document GET ETag
is unquoted, while mutation Response ETags are quoted.

## Fixed scenarios and independent witnesses

Versioned manifest and code-owned case requirements bind all 15 scenarios,
including source/seed/conditions/fault/advance/topology/recovery/collision/overlap.
A retained ID cannot replace a mutation with a GET. Fixture bytes are exactly
`# receipt\r\nn: 0 # keep\r\n`, the same with 1, and the same with 9.

| Case | Required behavior |
| --- | --- |
| R01 | Create-only PUT A, lost committed reply, advance C, automatic recovery of original 201 |
| R02 | Seed B, matching PUT A, lost reply, advance C, original 200 despite stale condition |
| R03 | Seed A, matching PATCH to B, lost reply, advance C, no second increment |
| R04 | Seed A, matching DELETE, lost reply, recreate C, original 204 without deleting C |
| R05 | Explicit-ID matching PATCH, exhaust delivery on all seeds, advance C, public manual recovery |
| R06 | R05 with SDK-generated ID retained by uncertainty and every dispatch |
| R07 | Committed create-only PUT A ID reused for PUT with appended `# changed\r\n`: 409 |
| R08 | Same committed PUT ID reused at document counter-other: 409 |
| R09 | Committed unconditional PUT ID reused for DELETE (body removed): 409 |
| R10 | Seed B, matching PUT A ID reused with If-Match removed: 409 |
| R11 | Committed create-only PUT ID reused with If-None-Match removed: 409 |
| R12 | Committed matching PATCH, lost reply, advance C, leader kill and new leader, original receipt |
| R13 | Committed matching PATCH uncertainty, advance C, full three-member paired-root restart, manual recovery |
| R14 | Committed matching PATCH uncertainty, advance C, isolate receipt-holding leader; recovery cannot succeed without quorum, then restore/recover |
| R15 | Two processes dispatch same fresh matching PATCH ID with native overlap; B once, identical receipts; advance C and replay original |

Before ANY automatic or explicit retry is forwarded: capture the first complete
native successful reply; independently GET and prove exact committed source,
ETag and receipt revision (DELETE proves absence); advance with a different ID
to C and prove a different revision. Gate all SDK mutation admissions at all
seeds until these witnesses exist. Setup and advancement writes are witnessed
too. For R15 both intentional initial dispatches are admitted together; any
subsequent retry is gated until the same witnesses exist. Discovery responses
are genuine native responses, never fabricated leader/cluster metadata.

Every retry preserves original ID/method/target/bytes/conditions. Compare original
native status/body/ETag/revision exactly, separately from fields exposed by each
SDK and from independent current-source observations. C remains unchanged after
recovery/rejection. R07..R11 then replay the original operation through the SDK
and recover its unchanged receipt. Harness HTTP is only setup, observation or
forwarding an actual SDK request, never an independently initiated recovery.

R15 requires distinct native TLS sockets, immediate response reads, completed
Content-Length framing before EOF, and strict
`max(native_request_sent_ns) < min(native_complete_response_ns)`.
Holding SDK replies or starting threads does not prove overlap. Missing evidence
fails qualification. Reuse native fixture recipes, existing toolchain installers,
process supervision and retained-workspace guards; introduce no cleanup stack.

Compiler/setup/TLS/sanitizer/process-watchdog/cleanup failures are infrastructure
failures and cannot count as behavioral reds. An SDK-returned deadline is an API
observation. No skips, automatic weakening, extra review rounds, numeric/stream/
platform/retention/enterprise-parity claims follow from this profile.
