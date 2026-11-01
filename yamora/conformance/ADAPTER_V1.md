# Frozen binary document adapter contract, version 1

The runner owns expected results, daemon/relay lifecycle and all assertions.
Adapters call their public SDK once and report observations, without parsing YAML,
implementing wire framing, replaying operations or receiving expected results.
Linux standalone binary document profile only; no 304 or cluster recovery.

## Invocation

The parent supplies an argv prefix for each driver (no shell), followed by:

```
--host 127.0.0.1 --port PORT --server-name localhost
--ca-file ABS --cert-file ABS --key-file ABS
--method GET|HEAD|PUT|DELETE --collection NAME --document NAME
--source-file ABS --request-id NONZERO_32_LOWER_HEX
--timeout-ms INTEGER --max-frame-bytes 4096
--cancel-mode none|pre|external --output-dir ABS
```

Optional flags: `--token-file ABS`, `--if-match VALUE`, `--if-none-match VALUE`.
Absence differs from an empty present condition. Conditions are literal header
values, including ETag quotes. Adapt those to public SDK options, retaining the
same wire meaning. Source is a raw file, empty except for PUT. Credentials are
synthetic files only; never put their contents in argv, JSON or logs. TLS files
are fresh synthetic PEMs with a trusted fixture CA and server SAN `DNS:localhost`.
The TCP host stays `127.0.0.1`; TLS verification and SNI use DNS `localhost` for
both native and relay connections. Never replace this with an IP server name.
Paths and output directory are already allocated by runner.
Timeout starts immediately before the public SDK call, after process startup and
client construction. Configuration uses one call slot and the requested frame cap.

`pre` cancels the SDK token before calling. For `external`, start a bounded
control reader before the call; `C\n` on stdin cancels the SDK token. PHP alone
uses SIGUSR1 mapped to its public cancellation token (runner's static registry
selects this). Join control helpers before exit. Closing stdin stops the reader.
No signal/thread exception injection, process termination or fresh timeout budget
may substitute for SDK cancellation. Other modes have stdin closed.

## Observation

Write exactly one JSON object plus newline to stdout, at most 16 KiB. Diagnostics
go to stderr, at most 16 KiB, without secrets/source/peer error text. Exit 0 means
an observation was produced, including a handled SDK exception. Unexpected
exceptions, missing files, malformed control or unavailable tools exit nonzero.
No banners, pass claims, expected statuses or success-shaped fallback objects.

All keys below are required; unavailable fields are JSON null:

```json
{
  "schema": "yamora-observation/1",
  "outcome": "success",
  "error_kind": null,
  "elapsed_ns": 123,
  "api": {
    "status": null,
    "body_file": null,
    "etag": null,
    "revision": null,
    "representation_length": null,
    "request_id": null,
    "receipt": null
  },
  "envelope": null
}
```

Outcome is `success`, `status`, `deadline`, `cancelled`, `protocol`, `transport`,
or `uncertain`. Error kind is null on success; otherwise one of `status`,
`deadline`, `cancelled`, `protocol`, `transport`. Map typed SDK errors, not text.
`uncertain` requires the SDK's uncertainty type/flag plus original envelope:

```json
{
  "method": "PUT", "collection": "config", "document": "one",
  "if_match": null, "if_none_match": "*",
  "request_id": "0102030405060708090a0b0c0d0e0f10",
  "source_file": "envelope.bin"
}
```

Write exposed raw response bytes to `output-dir/body.bin`, reported as `body.bin`;
write exception-owned source to `output-dir/envelope.bin`. These are the only
permitted output paths. An exposed empty body is an empty file, not null.
Elapsed nanoseconds cover the API invocation through return/exception, excluding
serialization and process startup. ETags retain the public API's quoted/unquoted
spelling; revisions and IDs use lowercase hex. The static runner registry owns
exposure capabilities, quote spelling and cancellation transport for each SDK.

`api.status` is the actual numeric status when exposed; it is null for Go/Node
successful calls. `api.receipt` contains only fields actually returned by the
public SDK: subset of `status`, `collection`, `document`, `etag`, `revision`.
Go returns status/etag/revision; Node returns all five. Raw-response SDKs report
receipt null: runner independently parses their body file. Never reconstruct a
raw receipt from fields, infer a numeric status, copy request data into response
fields, or fabricate an ID echo. Reads/DELETE have receipt null. On exceptions
report exposed response/status only; absent fields stay null. The envelope comes
from the exception, never from the adapter's input arguments.

## Parent launch locations

Core supplies Python: `python3 -P -m yamora.conformance.python_adapter`.
Other workers place adapters under `yamora/drivers/`, in each language's
conformance subdirectory, and return their exact build/run argv prefixes. The parent builds/copies them with
its existing private toolchain runner and passes a JSON object mapping driver
names to nonempty argv arrays through `--adapters-file ABS`. Python defaults to
the interpreter running the runner. Default selection requires all nine drivers;
`--driver python` explicitly qualifies Python alone. No implicit subset or skips.

Worker A: Go, Node, Java, Ruby. Worker B: Rust, C++, PHP, C#.
Neither worker edits this contract, core, shared runner, Makefile or CI.
