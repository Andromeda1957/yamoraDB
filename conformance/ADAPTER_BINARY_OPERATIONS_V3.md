# Binary operation adapter contract, version 3

This additive profile exercises the schema-2 native operation and page-feed
APIs. It preserves the separate version-1 document and version-2 HTTP replica
contracts. It does not qualify discovery, automatic retry, row-at-a-time query
production or an unimplemented language. All nine public clients support this
profile, including Python. The direct core runner requires an explicit driver
selection and adapter prefixes; the SDK helper defaults to all nine drivers.

Adapters invoke public SDK APIs and expose their actual results. They must not
implement wire framing, parse YAML, retry operations, infer response fields from
inputs or receive expected results. Raw owned specification and response bytes
preserve numeric spellings without claiming decoded numeric-type support.

## Invocation

The runner appends these argument pairs to the language's adapter argv prefix:

```
--host 127.0.0.1 --port PORT --server-name localhost
--ca-file ABS --cert-file ABS --key-file ABS
--method GET|POST|PATCH --target TARGET --content-type TYPE
--source-file ABS --request-id NONZERO_32_LOWER_HEX
--timeout-ms INTEGER --max-frame-bytes 4096
--cancel-mode none|pre|external --feed true|false --output-dir ABS
```

Optional pairs are `--token-file ABS`, `--if-match VALUE` and
`--if-none-match VALUE`. Absent and empty conditions differ. The content type
and source are empty for GET. POST/PATCH receive raw YAML or JSON specification
bytes. Targets are exactly those permitted by
[native schema 2](../../docs/binary-messages.md#additive-operations-schema-2).
`feed=true` selects only GET `/v1/changes/stream?...`; every other request uses
the finite operation API. Feed specifications use the native query parameters.

Use one admitted call, the supplied timeout and frame bound, verified TLS 1.3,
the supplied synthetic trust/client PEMs, DNS identity `localhost` and numeric
TCP host `127.0.0.1`. Port 8000 is forbidden. Read credentials only from the
synthetic token file; never emit them or pass their contents in argv.

Cancellation and timing follow [version 1](ADAPTER_V1.md#invocation): `pre`
cancels before API entry; external `C\n` cancels the public token, with PHP's
existing SIGUSR1 mapping. Start timing immediately before the SDK call and stop
after return/exception. Join owned control helpers and close sockets before exit.

## Observation

Emit the exact version-1 observation keys and API keys, with schema changed to
`yamora-operation-observation/3`. Retain its outcome/error-kind vocabulary,
16-KiB stdout/stderr bounds, typed error mapping and no-secret diagnostics.
Unavailable public fields remain null. Actual public raw response bytes are
written exclusively to `output-dir/body.bin`, including exposed empty bodies.
Report that relative filename. Never reconstruct a receipt or raw response.

For a feed, the public callback/iterator delivers complete validated NDJSON
pages, including terminal records, without rounding numbers or rewriting raw
bytes. Write those completed pages, including their LF, incrementally to
`body.bin`; do not retain a whole feed in adapter memory. Keep any completed
prefix on a later failure. An incomplete or unvalidated page must never reach
the adapter. The runner independently checks each native cursor, source and
terminal record. Normal END completes the call; an interrupted feed does not
establish complete delivery. Native terminal records remain observable as such.
Use metadata only when the public API exposes it, including on partial failure.

On mutation uncertainty, report the SDK exception's original owned envelope:

```json
{
  "method": "PATCH",
  "target": "/v1/collections/config/documents/one",
  "content_type": "application/json",
  "if_match": null,
  "if_none_match": null,
  "request_id": "0102030405060708090a0b0c0d0e0f10",
  "source_file": "envelope.bin"
}
```

Write exception-owned bytes to that file. Do not copy the adapter input into a
replacement envelope. Query/aggregate/search POST is read-only; transaction POST
and PATCH are mutations. Once dispatch may have begun, cancellation, malformed
response or absent validated receipt leaves those mutation outcomes uncertain.
Do not replay automatically or fall back to HTTP.

Place adapters beside each language's existing conformance adapters, with a
distinct operations entry point. Return exact build/run argv to the parent.
Existing version-1/2 entry points and their observable API exposure stay intact.
