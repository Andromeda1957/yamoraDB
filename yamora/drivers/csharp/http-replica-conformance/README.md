# PHP and C# HTTP replica receipt adapters

These persistent JSONL adapters implement the frozen HTTP replica receipt
protocol, version 2. The parent integrates its shared contract and runner. They are separate from
the binary version 1 adapters. PHP uses public `ClusterClient` preparation,
execution and `recover(exception)`; C# uses public asynchronous primitives and
`RecoverAsync(exception.Recovery)`. All discovery and automatic retry belong to
the SDK. The process retains actual SDK recovery objects until `close`.

Build with the installed mise .NET SDK, without installing packages. For this
task the scratch root is `/var/tmp/andromeda-work/yamora-http-adapters-php-csharp`.
Set `TMPDIR` to that root and allocate CLI home and artifacts beneath it:

```sh
export TMPDIR=/var/tmp/andromeda-work/yamora-http-adapters-php-csharp
export DOTNET_CLI_HOME="$TMPDIR/dotnet-home"
export DOTNET_CLI_TELEMETRY_OPTOUT=1
export DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
export DOTNET_GENERATE_ASPNET_CERTIFICATE=false
dotnet_root=$(mise where dotnet)
"$dotnet_root/dotnet" build yamora/drivers/csharp/http-replica-conformance/HttpReplica.csproj \
  --artifacts-path "$TMPDIR/build" --nologo --verbosity quiet
```

Launch argv prefixes, followed by `--config ROOT/config.json --root ROOT`:

```text
php -n yamora/drivers/php/conformance/http_replica.php
DOTNET_ROOT/dotnet SCRATCH/build/bin/HttpReplica/debug/HttpReplica.dll
```

The runner creates the private root, all fixed input files and `call-NNNNNN`
directories. Input EOF without `close` fails. There are no background helpers.
SDK calls have the fixed 15-second logical budget and 3-second attempt budget;
the external runner owns the separate 25-second process watchdog. Elapsed time
covers the public SDK invocation, excluding startup, parsing and output writes.
PHP is synchronous; the SDK rejects Fiber or reentrant use. Use separate
processes for concurrent callers.

Unavailable fields stay null. PHP exposes parsed mutation receipts and DELETE
revision. Ordinary C# mutations expose only ETag/revision; C# recovery alone
exposes status, original raw response bytes, quoted ETag and revision. C# DELETE
recovery envelopes have null body; PHP exposes an empty prepared body file.
Neither adapter reports a request ID on success. Uncertainty IDs and envelopes
come only from actual SDK exceptions. Recovery retains the requested handle
after success and subsequent uncertainty. Once 16 handles are retained, further
mutations are rejected before dispatch; GET, recovery and close still work.

Both adapters reject malformed/duplicate/deep JSON, invalid conditions,
untrusted seed bindings, oversized files and symlink components. Files use fixed
slots under the runner root and exclusive output creation. C# uses Linux
`statx` to reject nonregular input files before opening them, so a FIFO cannot
block validation. Diagnostics are fixed text; SDK/peer exception messages,
credentials and source content are never printed.

JSONL permits LF framing and rejects raw CR. Config and each PEM/key file are
bounded at 16 KiB; token files at 512 bytes; source/output files at 128 KiB.

PHP's warning handler respects suppressed severities so the public SDK can
classify TLS/socket failures and retry. Unsuppressed adapter/file warnings
remain fatal. Focused controls retain a real uncertain mutation through rejected
TLS on all seeds, then recover in the same process; a reset during a bounded
write also proves SDK retry with the original ID/bytes and retained recovery.

Run the focused controls from the repository root after building:

```sh
export YAMORA_HTTP_REPLICA_TEST_LANGUAGE=both
export YAMORA_HTTP_REPLICA_PHP_ADAPTER="$PWD/yamora/drivers/php/conformance/http_replica.php"
export YAMORA_HTTP_REPLICA_CSHARP_DLL="$TMPDIR/build/bin/HttpReplica/debug/HttpReplica.dll"
export PATH="$dotnet_root:$PATH"
PYTHONDONTWRITEBYTECODE=1 python3 \
  yamora/drivers/csharp/http-replica-conformance/tests/test_http_replica.py
```

Private foundations set `YAMORA_HTTP_REPLICA_TEST_LANGUAGE=php` or `csharp` and
supply only that language's artifact variable and runtime on `PATH`. The C# DLL
may be a Release build anywhere; the PHP adapter may be in a private SDK copy.
The test file and `peers.py` can also be copied together without repository path
assumptions. Selected runtimes or artifacts missing from the environment fail
the suite, with no skips. C# runs all 15 shared controls; PHP also runs the three
warning controls. `TMPDIR` must be an existing absolute owned writable directory,
without symlink components or write permission for others. Each suite creates
and cleans a unique child allocation, including on setup failure.

The tests create synthetic TLS 1.3 peers and credentials in unique task scratch
allocations and clean their children, sockets and files on every path. They
cover public SDK uncertainty, unchanged recovery IDs/bytes/conditions, honest
field exposure, protocol/path/file/output bounds, credential redaction, EOF,
close and interruption. Fake peers do not qualify native receipt durability,
leader failover, quorum behavior, daemon restart or overlap. The parent owns
the independent 15-by-9 native qualification and reserved review round.

The optional `tests/prove_guards.py` driver temporarily changes only the two
adapters to suppress SDK uncertainty IDs, replace retained recovery with a new
primitive, or invent success status. It requires explicit behavioral assertion
failures in both CLIs, restores sources in `finally`, rebuilds, and verifies
the same controls green. Compiler, setup and watchdog failures fail the proof.
