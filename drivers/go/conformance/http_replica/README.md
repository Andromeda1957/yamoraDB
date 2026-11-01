# Public HTTP replica adapters

This package implements the frozen `http-replica-receipt` v2 adapter interface.
The parent integration supplies the shared protocol document. This README
records local entry points and control-test limits. The v1 binary adapter
remains independent.

Build this Go entry point from the Go module directory with
`go build -o ABS_OWNED_SCRATCH/http-replica ./conformance/http_replica`.
The Python entry point is
`python3 -P -m yamora.conformance.python_http_replica_adapter`, with an explicit
`PYTHONPATH` naming the checkout being tested. Each prefix takes
`--config ABS_SESSION_ROOT/config.json --root ABS_SESSION_ROOT`.

Both sessions use public SDK cluster configuration and keep the SDK retries
enabled. Recovering a handle reissues the immutable saved primitive using the
actual retained uncertainty exception's ID. Neither SDK exposes an HTTP prepared
envelope. DELETE returns no receipt metadata in either SDK; those observation
fields stay null. Python GET exposes only source bytes. Go GET exposes source,
ETag and revision. Success never implies an exposed HTTP status or request ID.

Logical calls use a 15-second public SDK budget and a 3-second attempt timeout.
A separate 25-second command watchdog is infrastructure supervision, excluded
from API timing. Lines are limited to 16 KiB, source/body files to 128 KiB,
sessions to 64 commands and retained uncertainty handles to 16. Config and
PEM/key files are capped at 16 KiB; token files at 512 bytes. JSON accepts
integer number tokens only, and JSONL frames reject literal CR bytes.

The file guards use Linux descriptor-relative opens, without following symlink
components. Python additionally uses `/proc/self/fd` to load verified local
certificate descriptors. No other platform qualification is claimed. Both
adapters validate the frozen cluster ID, voters, node bindings and three numeric
loopback seeds. The public SDK configurations accept seeds and verified TLS;
the parent native fixture independently proves the cluster/node bindings.

Focused controls run with an owned disk-backed `TMPDIR`:

- `python3 -m unittest yamora.tests.test_conformance_http_python_adapter`
  from the repository root;
- `go test ./conformance/http_replica/...` from the Go module directory.

Tests use synthetic peers for input, output, error and session controls only.
They do not qualify native receipts, restart safety, overlap, or mutation
deduplication. The parent's independent native fixture owns all 15 qualification
cases, native wire receipts and source-before-retry evidence. PATCH controls
compare the first actual SDK-emitted body, not input JSON whitespace.
