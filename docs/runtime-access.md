# Runtime access management

`--runtime-access` lets the write administrative credential create, list,
change and delete token principals and their collection roles on a running
native daemon. A change applies to the next request without a restart, and it
survives restart, crash and replica-set failover. These principals sit beside
the immutable [policy file](access-control.md). They use the same
authorization boundary, the same collection grants and the same optional
[field permissions](field-permissions.md).

The option is off by default. Without it, `/v1/access` is an unknown route, any
stored runtime state is ignored, and the policy file behaves exactly as before.

## Enabling

Add `--runtime-access` to a serving native disk daemon, either standalone or a
replica-set member. The option requires `--auth-token-file` and
`--write-auth-token-file`. Startup rejects it with `--validate-only`,
`--replica`, `--shard-config-file`, `--init-binary` or a legacy snapshot
backend. `--access-policy-file` is optional. TLS, the binary listener,
[encrypted storage](encryption-at-rest.md) and standalone
[audit delivery](audit-helper.md) work with it.

At startup the daemon loads the stored state and refuses to start when the
state is invalid, or when a runtime name or token collides with the policy file
or an administrative token. A replica-set member that cannot yet read its
application starts with no runtime principals and loads them as soon as it can.

## API

Every management request sends `Authorization: Bearer <write administrative
token>` over HTTP or HTTPS. The binary transport has no access route: like
any other target outside its document and operation routes, a `/v1/access`
request is a protocol error that ends the binary session unserved. Every
response carries `Cache-Control: no-store`.

| Request | Body | Success |
| --- | --- | --- |
| `GET` or `HEAD /v1/access` | none | 200, the listing below |
| `PUT /v1/access/roles/{role}` | `{"read": [...], "write": [...]}` | 201 created, 200 updated |
| `DELETE /v1/access/roles/{role}` | none | 200 deleted |
| `PUT /v1/access/principals/{principal}` | `{"roles": [...], "token": "..."}`, or `"generate_token": true`, optional `"field_permissions": [...]` | 201 created, 200 updated |
| `POST /v1/access/principals/{principal}/rotate` | `{"token": "..."}` or `{"generate_token": true}`, optional `"overlap_seconds": N` | 200 rotated |
| `DELETE /v1/access/principals/{principal}` | none | 200 deleted |

A change answers
`{"status": "created", "kind": "role", "name": "...", "version": N}`.
`version` counts committed changes. An overlapping rotation adds
`previous_expires_at`. A generated token appears once, as `token`, in the
successful create or rotate response, and is never retrievable again.

The listing returns `runtime_access`, `version`, `roles` and `principals`. Each
role has `name`, `source` (`file` or `runtime`), `read` and `write`. Each
principal has `name`, `source`, `roles`, `credential` (`token`, `certificate`
or `external`), `field_permissions` (a boolean) and, during an overlap,
`previous_expires_at`. It never contains a token or verifier.

The Python client exposes `access()`, `put_role()`, `delete_role()`,
`put_principal()`, `rotate_principal()` and `delete_principal()`. The other
language drivers do not have these methods yet; they can call the HTTP API
directly.

### Roles

A role names exact collections in `read` and `write`. Both arrays are
required, together hold at least one grant, and each holds at most 64 distinct
collection names. `yamldb-system` cannot be granted. Replacing a role changes
every principal that holds it at the next request. A role still held by a
principal cannot be deleted (`409 role_in_use`).

### Principals

`roles` lists 1 to 64 distinct runtime roles. Runtime principals cannot hold
policy-file roles. A new principal needs `token` or `"generate_token": true`.
A supplied token uses the existing profile of 32 to 512 printable ASCII bytes
without spaces. A generated token is `yrt_` followed by 43 base64url characters
from 32 bytes of OpenSSL randomness. Replacing an existing principal changes
its roles and field permissions and keeps its credential. Leaving out
`field_permissions` removes the masks. Repeating the current token is accepted;
a different token answers `409 principal_exists`, so use rotation.

`field_permissions` uses the version 4 rule schema from the policy file:
document selectors and field read/write masks, bounded the same way. As for a
policy-file principal, a masked principal reads through projected queries;
an exact-source `GET` needs a whole-document read grant.

### Rotation

Rotation replaces the principal's token. With `overlap_seconds` 0, the default,
the old token stops working at the commit. With 1 to 86,400 seconds, the old
token keeps working until `previous_expires_at`, in Unix seconds by the
daemon's wall clock. A replica set checks expiry against each serving node's
clock. Only one previous token is kept: a second rotation replaces it. A
rotation to the current token, or to the token still in its overlap, answers
`409 token_conflict`.

## Authority

Only the write administrative credential, sent over HTTP or HTTPS, can use
`/v1/access`. A missing or unknown bearer gets `401` with the existing
`unauthorized` body and `WWW-Authenticate: Bearer`. The read administrative
credential, policy-file principals and runtime principals get `403` with the
existing `forbidden` body. Restricted principals never read `yamldb-system`
or the change feed, so they never see the stored state.

Policy-file roles and principals appear in the listing with `source: file` and
are read-only: every change to one answers `409 static_policy_read_only`. A
runtime role or principal cannot take a policy-file name. No runtime token may
equal an administrative token, a policy-file token or another runtime token,
including a token still in its overlap (`409 token_conflict`). A policy file
edited later so that it collides with stored runtime state stops the daemon at
startup.

## Credentials

The daemon never stores, replicates or logs a token. Before a change leaves the
request handler it turns the token into a verifier: SHA-256 over the
NUL-terminated domain `yamora-runtime-access-token-v1` followed by the token,
computed with OpenSSL. This is acceptable because tokens are 32 to 512 bytes of
high entropy; it is not a password hash, so never use a low-entropy token.
Authentication compares verifiers in constant time and checks every runtime
principal without stopping early.

Tokens do not appear in diagnostics, audit records, the change feed, replicated
commands, the stored document or error bodies. The request body, the parsed
request tree, the command and the reply buffer are cleared before they are
freed. The read administrative credential can read the stored verifiers, as it
can read every document. A verifier does not authenticate.

Runtime principals authenticate only with bearer tokens. Certificate pins and
OIDC or identity-provider mappings stay policy-file features.

## Persistence

The state is one JSON document, `yamldb-system/access-control`, in format
`yamora-runtime-access-v1`. It holds the version, the roles, and for each
principal its roles, field rules, verifier and any overlapping previous
verifier with its expiry. Each change is one native transaction on that
document: the daemon validates the whole change against the current state,
writes the new state and commits it, or changes nothing. A standalone daemon
answers after the commit is durable. If the final commit fails, it answers
`500 access_durability_failed_restart_required`; restart the daemon and read
the listing to learn the outcome.

Because the state is an ordinary native document, it shares the journal's
crash recovery, snapshots, compaction, [encrypted storage](encryption-at-rest.md)
and [replica-set backups](cluster-backup.md). With encryption at rest the
verifiers, names and grants are stored only as ciphertext. The tests cover
restart, a crash at each commit boundary, encrypted storage and leader
failover. Snapshot installation, compaction and backup restore carry the
document like any other, but have no runtime-access test of their own.
Restoring from a YAML export has not been verified to carry runtime access
state; after such a restore, check the listing and re-create principals if
needed.

## Revocation

The daemon re-checks runtime credentials on every request; it does not tear
sessions down. After a delete or rotation commits, every later request that
presents the old token is rejected with `401`, including requests on an
existing binary session. Requests already executing finish under the
credential they were admitted with.

Each node holds a snapshot of the state. The committing node refreshes it
before answering. Every HTTP request, and every binary request a worker
handles, that presents a runtime or unknown bearer token first brings the
snapshot up to the node's applied state; that costs one comparison when nothing
changed. A background thread also refreshes it about every 250 ms. The binary
transport's early check on its network thread never reads storage and uses the
snapshot as it stands. It can reject a just-created principal on another node
until that node refreshes, but it cannot admit a revoked one, because the worker
check that follows rejects it.

## Replica sets

A change is a replicated write through the leader, like any other write. It
requires `X-Yamora-Request-Id`, and retries use the durable receipt: the same
request ID with the same body returns the original answer and changes nothing.
A different body with a used ID answers `409 request_id_reused`. The daemon
builds each replicated command afresh, so a retry that generates a token, or a
retry of a rotation with an overlap (whose expiry is computed per attempt),
differs from the first attempt and answers `409 request_id_reused`; read the
listing to learn whether the first attempt committed. Receipts never store
tokens. Supply your own token, and rotate without an overlap, when retries must
replay the original answer.

Followers apply the change from the replicated log and enforce the same state
once they have applied it; until then they enforce the state they have applied.
Before trusting a runtime principal, the leader proves its leadership with the
same barrier it uses for reads, which adds that barrier's round trip to such
requests. A follower cannot change or list the state: listing answers
`503 cluster_unavailable` and changes are refused. The state survives leader
failover, because the new leader already has every committed change.

Runtime access cannot be combined with standalone `--replica` read-only copies
or the shard service. Standalone
[incremental replication](incremental-replication.md) never transfers
`yamldb-system`, so a replica copy holds no runtime state.

## Audit

Each management request emits one audit event through the existing dispatch.
Its authentication category is `ADMIN_WRITE`, it has no actor, and it carries
the operation and the role or principal name as its subject:
`ACCESS_ROLE_PUT`, `ACCESS_ROLE_DELETE`, `ACCESS_PRINCIPAL_PUT`,
`ACCESS_PRINCIPAL_ROTATE` or `ACCESS_PRINCIPAL_DELETE`. Listings audit as
`LIST`. Rejected requests audit as `ACCESS_REJECT` without a subject. Requests
by runtime principals audit as `STATIC` authentication with the principal name
as actor. Audit delivery, as before, is available to standalone daemons only.
The [record](audit-trail.md) and [helper packet](audit-helper.md) layouts
describe the subject field.

## Limits

| Limit | Value |
| --- | --- |
| Runtime roles | 64, in addition to the policy file's |
| Runtime principals | 64, in addition to the policy file's |
| Collections per `read` or `write` array | 64 |
| Roles per principal | 64 |
| Names | 1 to 128 lowercase ASCII letters, digits and `-` |
| Request body | 64 KiB; JSON only; exact keys |
| Stored state | 192 KiB |
| Rotation overlap | 0 to 86,400 seconds |
| Version | 2^53 − 1 |

Malformed JSON, unknown or missing keys, duplicate keys, grants or roles,
invalid names, unknown roles and out-of-range values fail validation before
any change, with a stable error code. A change that would exceed a count limit
answers `413` (`access_role_limit`, `access_principal_limit`,
`access_state_limit` or `access_version_limit`).

## Rollback and older binaries

Older binaries fail closed. They reject the `--runtime-access` option at
startup. If started without it on a store that holds runtime state, they ignore
`yamldb-system/access-control`, so every runtime principal gets `401`. Their
audit verifiers and helpers reject the new management records and packets as
invalid rather than skipping them, so keep the audit helper and verifier at
least as new as the daemon. A rolled-back daemon keeps the stored state
untouched; re-enabling the option on a current binary restores it.

To remove runtime access, delete the runtime principals and roles, then drop
the option.

## Compatibility claims

These routes and their behavior are Yamora's own. They are not MongoDB user,
role or authentication commands, and no MongoDB driver or tool compatibility is
claimed or tested.
