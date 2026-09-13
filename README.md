# YamlDB

A small native C document store for bounded collections of human-readable YAML.
Documents live in ordinary files, retain their original comments and formatting,
and are served over HTTP from an in-memory snapshot. A Python client and optional
administration tools are included.

YamlDB is read-only by default. A separate write credential enables durable
single-document `PUT` and `DELETE` operations with optimistic preconditions.
It runs independently of any web framework or relational database.

## Build and try it

The daemon requires Linux, a C17 compiler, Make, and POSIX threads. It uses only
libc and pthreads: no YAML parser, database, compression library, or Python
runtime is required by the daemon. Python tools require Python 3.10 or later;
validation and the CLI additionally require PyYAML.

From a fresh checkout:

```sh
git clone https://github.com/Andromeda1957/yamldb.git
cd yamldb
make
python3 -m venv .venv
. .venv/bin/activate
python -m pip install '.[admin]'
yamldbctl validate --data-dir examples/data
./build/yamldb --data-dir examples/data --port 8765
```

In a second terminal, from the same checkout:

```sh
. .venv/bin/activate
yamldbctl health
yamldbctl ready
yamldbctl collections
yamldbctl list notes
yamldbctl get notes welcome
yamldbctl stats
```

The example server binds `127.0.0.1`, permits local reads without a token, and
disables writes. Stop it with Ctrl-C. The repository contains only synthetic
example documents and test fixtures; no Classic Chess YAML data is included.

## Python client

The client itself uses only the Python standard library. `pip install .` installs
it without the optional administration dependencies; use `.[admin]` for the CLI.

```python
from yamldb import YamlDBClient

client = YamlDBClient(port=8765)
print(client.collections())
print(client.get("notes", "welcome").decode("utf-8"))
```

The Python installation contains the client, CLI, and example schema. Build the
C daemon separately with Make. Distribution is through this GitHub repository.

## Data and schemas

```text
data/
  notes/
    welcome.yaml
    second.yaml
```

Collection names and document IDs use 1–128 lowercase ASCII letters, digits,
and hyphens. Each document is a nonempty UTF-8 `.yaml` file of at most 256 KiB.
The daemon preserves bytes; it does not parse YAML or enforce field schemas.

The optional validator checks a schema registry before local publication:

```sh
yamldbctl validate --data-dir examples/data
yamldbctl validate --data-dir /path/to/data --schema /path/to/collections.yaml
```

The default registry, [`yamldb/schemas/collections.yaml`](yamldb/schemas/collections.yaml),
describes the generic `notes` examples. Each document has `schema_version: 1`,
a registered `kind`, and an `id` matching its filename. Schemas define required
and optional fields, an optional `exactly_one` group, and top-level `integer`,
`string`, `mapping`, and `sequence` types; a `?` suffix permits null. Unknown
fields, duplicate mapping keys, and YAML aliases are rejected. Nested field
semantics and cross-document references belong to your application.

Snapshot validation requires the registry and directory to contain the same
collections, each with at least one document. The daemon also supports empty
collections, including those left after a network deletion.

To try local import, copy the sample collection to your own data directory and
run this while its daemon is stopped:

```sh
cp -r examples/data my-data
yamldbctl import notes second --input examples/second.yaml --data-dir my-data
./build/yamldb --data-dir my-data --port 8765
```

Local imports validate first, write through a same-directory temporary file,
and use `fsync` and atomic rename. Use one local publisher at a time. A running
daemon keeps its existing snapshot until restarted; do not mix local imports
with live network writers.

## Authentication and network writes

Set `--auth-token-file` for authenticated reads and a distinct
`--write-auth-token-file` to enable writes. Tokens must be 32–512 printable ASCII
bytes in regular, non-symlink files with private permissions. For example,
generate credentials outside the checkout:

```sh
install -d -m 700 "$HOME/.config/yamldb"
python - <<'PY'
import os
import secrets
from pathlib import Path

for name in ("read.token", "write.token"):
    path = Path.home() / ".config" / "yamldb" / name
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write(secrets.token_urlsafe(48) + "\n")
PY
./build/yamldb --data-dir my-data --port 8765 \
  --auth-token-file "$HOME/.config/yamldb/read.token" \
  --write-auth-token-file "$HOME/.config/yamldb/write.token"
```

With that server running, reads use the read token; writes use the write token:

```sh
yamldbctl --auth-token-file "$HOME/.config/yamldb/read.token" get notes welcome
yamldbctl --write-auth-token-file "$HOME/.config/yamldb/write.token" \
  put notes second --input examples/second.yaml
```

Use `--create-only` to reject an existing document, or `--etag` with the unquoted
ETag from a previous HTTP response to prevent a stale update or deletion.
Network writes validate byte limits and encoding, but do **not** apply the
Python schema registry. Validate application data before sending it.

Only `/healthz` is unauthenticated when read authentication is configured.
The daemon accepts loopback or an exact RFC1918 IPv4 bind address; private LAN
binding requires read authentication. The client similarly accepts only numeric
loopback or RFC1918 IPv4 targets. There is no built-in TLS: use a trusted private
network or an authenticated encrypted transport, and do not expose the daemon
directly to the public internet.

## Behavior and limits

- Sorted collection/document indexes and cursor paging.
- Cached native gzip representations for compressible documents.
- Content ETags and a revision identifying the current snapshot.
- Atomic single-document writes and snapshot swaps, with restart recovery.
- Bounded worker concurrency, queue backpressure, and request deadlines.
- JSON readiness/statistics and Prometheus metrics.
- At most 256 collections, 50,000 total documents, and 256 MiB of combined
  raw/compressed snapshot storage.

There are no field queries, secondary indexes, multi-document transactions,
replication, or automatic reload of filesystem edits. See [PROTOCOL.md](PROTOCOL.md)
for endpoints, status codes, and detailed limits.

## Tests

With the administration dependencies installed and Clang available:

```sh
mkdir -p /var/tmp/yamldb-tests
TMPDIR=/var/tmp/yamldb-tests make test
TMPDIR=/var/tmp/yamldb-tests make sanitizer-test
make clean all
```

Tests start isolated loopback daemons on automatically allocated ports and use
synthetic temporary data. They cover HTTP parsing, authentication, filesystem
boundaries, compression, paging, CRUD durability, concurrency, and CLI behavior.
CI runs the normal suite and AddressSanitizer/UndefinedBehaviorSanitizer suite.

## License

MIT. See [LICENSE](LICENSE). The optional Python administration tools depend on
PyYAML, which is installed separately under its own MIT license.
