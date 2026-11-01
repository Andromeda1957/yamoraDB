# YamoraDB

YamoraDB is a native document database written in C17, with binary disk storage,
a YAML interface, and source-preserving document updates. This repository was
previously named YamlDB; its existing URL and history are retained.

This is a public source extract of YamoraDB. It includes the database engine,
Python client and administration tools, language drivers, documentation, examples,
tests, and fuzzing harnesses. Application data, application schemas, credentials,
and build outputs are excluded.

## Features

- Durable binary storage with a bounded page cache and exact YAML retrieval.
- Typed document queries, projections, sorting, pagination, and explain.
- Field, compound, unique, multikey, partial, and TTL indexes.
- Source-preserving updates and atomic transactions.
- Aggregation, full-text search, geospatial queries, and vector search.
- TLS 1.3/mTLS, access roles, backups, change feeds, and read replication.
- Experimental Raft replica sets and authenticated shard routing.
- Python, Go, Node.js, Java, Ruby, Rust, C++, PHP, and C# drivers.

See the [full documentation](yamora/README.md),
[protocol](yamora/PROTOCOL.md), [operations guide](yamora/docs/operations.md),
and [driver guide](yamora/docs/drivers.md). Experimental cluster features have
qualification limits described in their documentation.

## Build

Linux is the verified build target. Install a C17 compiler, Make, pkg-config,
LibYAML 0.2.5 or newer, and OpenSSL 3 or newer, including development headers.

```sh
git clone https://github.com/Andromeda1957/yamldb.git
cd yamldb
make
```

The daemon is `yamora/build/yamora`; `yamora/build/yamldb` is a compatibility
executable. For installation:

```sh
make install PREFIX="$HOME/.local"
```

## Python client

Python 3.10 or newer is required. The client uses the standard library;
optional administration dependencies are available with the `admin` extra.

```sh
python3 -m pip install '.[admin]'
```

```python
from yamora import YamoraClient

client = YamoraClient(host="127.0.0.1", port=8765)
print(client.collections())
```

See [synthetic examples](yamora/examples) and the
[Python TLS example](yamora/drivers/python/examples/crud_tls.py) for writable
and authenticated setups. The `yamldb` compatibility package is also included.

## Development

Native and Python tests and fuzzing sources are included under `yamora/`.
Advanced cross-language conformance and release orchestration retain references
to tooling in the original development monorepo. No test suite was run for this
source publication.

## License

[MIT](LICENSE), copyright 2026 Christian Walls. Generated Unicode tables retain
their [Unicode license notice](UNICODE-LICENSE.txt).
