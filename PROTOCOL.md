# YamlDB protocol version 2

## Storage layout

The configured data root contains one directory per collection and one `.yaml`
file per document. Collection and document IDs are 1–128 lowercase ASCII
letters, digits, and hyphens. Empty collections are valid.

The server opens every path relative to a pre-opened data-root descriptor,
rejects symlinks, accepts only bounded UTF-8 text, and never accepts a path
separator in an ID. The exact `.yamldb-PID-NANOSECOND-COUNTER` namespace is
reserved for atomic writes; interrupted temporary files are never visible and
are ignored during restart recovery.

The C service preserves YAML bytes and comments exactly. The optional Python validator checks collection schemas, filename/ID identity,
duplicate keys, and aliases before local publication. Application-specific
cross-document relationships remain the responsibility of the caller. Network
writes enforce byte, encoding, and storage limits; they do not parse YAML or
apply the Python schemas.

## HTTP endpoints

`GET /healthz`

: Returns unauthenticated liveness and protocol version.

`GET /readyz`

: Returns authenticated readiness, revision, snapshot counts, and whether
  network writes are enabled.

`GET /metrics`

: Returns authenticated Prometheus metrics, including write and conflict
  counters.

`GET /v1/stats`

: Returns authenticated snapshot, worker, queue, request, response,
  authentication, overload, write, byte, and uptime statistics.

`GET /v1/collections`

: Returns every sorted collection ID.

`GET /v1/collections/{collection}/documents`

: Returns every sorted document ID in the collection.

`GET /v1/collections/{collection}/documents?limit=N&after=ID`

: Returns at most 1–1,000 sorted IDs after the exclusive cursor plus
  `next_after`, or `null` on the final page. Parameters are optional,
  order-independent, and may not repeat.

`GET /v1/collections/{collection}/documents/{document}`

: Returns exact document bytes as `application/yaml; charset=utf-8` and a
  content ETag. A cached native-C gzip representation is selected when the
  client accepts gzip and compression materially reduces the response.

`PUT /v1/collections/{collection}/documents/{document}`

: When writes are enabled, atomically creates or replaces one non-empty YAML
  representation and publishes a new complete in-memory revision.
  `Content-Type` must be `application/yaml` or `text/yaml`.
  `If-None-Match: *` is create-only; `If-Match: "ETAG"` is guarded replace.

`DELETE /v1/collections/{collection}/documents/{document}`

: When writes are enabled, durably deletes one document and publishes a new
  revision. `If-Match: "ETAG"` guards against stale deletion. Collections may
  become empty.

All responses close the connection. Invalid paths or queries return `400`,
failed authentication `401`, missing documents `404`, disabled/unsupported
methods `405`, interrupted requests `408`, stale preconditions `412`, oversized
bodies `413`, invalid content types `415`, oversized headers `431`, and a full
work queue `503` with `Retry-After`.

## Authentication and network boundary

When `--auth-token-file` is configured, every endpoint except `/healthz`
requires its read bearer token. Writes are disabled unless
`--write-auth-token-file` supplies a distinct write bearer token. Token files
must be non-symlink regular files containing 32–512 printable ASCII bytes with
private permissions. Comparisons are length-aware and constant-time; tokens are
never logged.

The daemon binds IPv4 loopback by default. `--bind-address` can select one exact
numeric RFC1918 address for a trusted application LAN, but LAN mode requires a
read token. Wildcard, public, hostname, URL, link-local/metadata, and IPv6
targets are rejected. Expose application-approved documents through your own API; direct public
YamlDB exposure is unsupported.

## Limits and durability

- One request per connection; 8 KiB request headers; at most 64 headers; one
  absolute configurable I/O deadline.
- Fixed 1–64 workers and 1–4,096 queued connections; defaults are 8 and 128.
- At most 256 collections, 50,000 documents per collection and snapshot,
  256 KiB per document, and 256 MiB combined raw/compressed snapshot bytes.
- Read/delete bodies, transfer encoding, protocol upgrade, folded or duplicate
  security-sensitive headers, absolute request targets, and fragments fail
  closed. Only the documented paging query is accepted.
- YAML must be UTF-8 text without NUL or disallowed control bytes.
- Each write uses a private same-directory file, `fsync`, atomic `rename`, and
  directory `fsync`; readers see the complete old or complete new snapshot.
- Gzip/DEFLATE, storage, indexes, HTTP parsing, and concurrency are implemented
  in the C service without a database, YAML-parser, compression-library,
  Python, or wrapper dependency.

Field queries, multi-document transactions, a journal/checkpoint engine,
replication, TLS, and public exposure are not claimed by protocol version 2.
Coordinated schema/graph updates still use the validated release publisher.
