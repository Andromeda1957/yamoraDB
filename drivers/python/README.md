# Python packaging

Python keeps the canonical `yamora` 0.3.0 project, imports and optional
administration extra. The local builder stages original files privately;
no driver implementation is duplicated in this directory.

See [Python packaging](../../docs/python-packaging.md) for wheel/sdist builds,
the shipped public TLS CRUD example and isolated-consumer acceptance.

## Replication source preflight

`source.require_replication_source()` reads readiness and returns its metadata.
It raises `yamora.client.SchemaPolicyReplicationError` (status 409) when
`replication_policy_free` is false, and `YamoraClientError` for an advertised
non-boolean. An absent field supports older policy-free servers. The high-level
bootstrap, follow and stream APIs guard sources automatically and recheck before
publication. Readiness is advisory; native outgoing and receiver admission
remains authoritative during concurrent policy changes.
