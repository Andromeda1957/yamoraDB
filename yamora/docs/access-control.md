# Native collection access roles

`--access-policy-file /absolute/path/access.yaml` adds named collection roles
to a native disk daemon. Existing read and write administrative credentials
retain their respective database-wide capabilities. The read administrative
credential is required with a policy; writes still require the write credential.
Legacy snapshot backends reject policies.

The policy uses safe native YAML and references separate private credential
files. Keep token values outside this file and outside Git:

```yaml
version: 1
roles:
  platform-reader:
    read: [services, manifests]
    write: []
  manifest-editor:
    read: []
    write: [manifests]
principals:
  deployment-agent:
    token_file: /run/credentials/yamora/deployment-agent
    roles: [platform-reader, manifest-editor]
```

Grants are additive, exact collection names. Read and write are independent:
a write grant alone does not permit reads. There are no wildcards, inherited
administrative rights, or grants to `yamldb-system`. Each role must contain both
arrays and at least one grant. Each token principal needs a unique token, distinct
from both administrative tokens, and at least one defined role. Duplicate keys,
grants or role references, unknown options and unsafe YAML fail startup before
the listener opens.

Use the principal credential in the existing Python `auth_token_file` and
`write_auth_token_file` settings, or Go `Config.ReadToken` and `Config.WriteToken`.
A principal with both capabilities can use the same credential for both client
settings; the daemon's administrative tokens remain distinct. Verified TLS/mTLS
applies before authorization. A trusted client certificate grants no rights by
itself. A strict version 2 policy can instead map one or two complete DER-leaf
SHA-256 pins to a named principal, requiring explicit client-CA verification.
Omit Authorization to select that identity; a supplied bearer is always
authoritative and cannot fall back to certificate roles. See
[certificate principals](certificate-identity.md) for the schema, startup
requirements, renewal overlap and restart-based rotation.

A strict version 3 policy adds locally pinned RS256 access tokens on HTTP.
Issuer, resource audience, scope and exact subject/client mappings are explicit;
existing local roles still decide grants. Static-token matches remain terminal,
and binary authentication retains its static/certificate profile. See
[offline access tokens](oidc.md) for configuration, bounds, failures and rotation.

Version 4 adds optional per-principal document selectors and field read/write
masks, retaining the existing credential selectors and optional offline OIDC
configuration. See [field permissions](field-permissions.md) for configuration,
whole-source restrictions and private response metadata. The separate
`--identity-provider-file` enables pinned online identity providers over HTTP
TLS 1.3 and maps verified identities to these same local principals. It cannot
coexist with offline OIDC; see [identity providers](identity-providers.md).

## Authorization boundary

| Operation | Restricted principal requirement |
| --- | --- |
| Raw GET/HEAD and document listing within one collection | Read grant for that collection |
| Query, aggregation and full-text search POST | Read grant for that collection |
| Document PUT, PATCH and DELETE | Write grant for that collection |
| Atomic transaction, including `create_collection` and `drop_collection` operations | Write grants for every operation's collection; field-masked principals cannot create or drop collections, and cannot purge because a purge requires a transaction revision |
| Collection enumeration, readiness/counts, statistics and metrics | Administrative credential |
| Index catalog and online index jobs | Administrative credential |
| Change feeds/streams, replica status, bootstrap and transfer | Administrative credential |
| `/healthz` | Existing unauthenticated liveness contract |

Unrecognized routes are denied. Global routes are denied as a whole rather than
returning partially filtered snapshots, feeds or catalogs. Mixed transactions
are rejected before any operation is applied. Scoped queries execute against
one authorized collection. An aggregation lookup additionally requires read
access to its foreign collection even when local input is empty or filtered out.

Unknown or absent credentials return 401. Known restricted credentials without
the needed grant return 403 and a generic `forbidden` body before looking up
the object. Malformed requests can fail transport validation first. Daemon-wide
read-only and replica restrictions still apply. Collection-only responses retain
their ordinary global revision headers. Field-masked replies suppress full-source
fingerprints; anonymous and malformed replies do so whenever the policy contains
masked principals. These roles do not supply quotas or arbitrary row predicates.

Large document writes check authentication and the target collection grant
before body admission. Large transactions require an authenticated principal
with some write grant before allocation, then authorize every collection in
the complete parsed body before storage preparation. Existing admission budgets
and transport deadlines apply. Collection grants cannot open global streams.

## Configuration and rotation

The policy is at most 128 KiB, with at most 64 roles, 64 principals, 64 collection
names per read/write array and 64 role references per principal. Names use the
existing 1–128-character lowercase ASCII identifier profile. Token-file paths
must be absolute and at most 4,096 bytes.

Policy and token files must be regular files, with no final symlink, owner
execute, group write/execute or other-user permissions. Mode 0600 is recommended;
the systemd credential profile 0440 is accepted. Tokens use the existing
32–512 printable ASCII byte profile and optional trailing newline within the
file-size bound. Bounded descriptor reads reject FIFO/device, truncated,
oversized and insecure files. Keep parent directories under trusted operator
control. Token contents never enter diagnostics or the YAML policy tree;
policy-owned tokens are cleared before free.

The policy file and its credentials are immutable for the running daemon. A
controlled restart revokes or replaces its grants; SIGHUP continues to reload
only TLS contexts. Keep the policy option in service configuration during
rollback: older binaries reject it.

The opt-in `--runtime-access` option adds token principals and their roles
beside this file, managed through an authenticated API without a restart and
stored in the native journal. File entries stay read-only through that API, and
names and tokens cannot collide between the two. See
[runtime access management](runtime-access.md) for the API, persistence,
revocation, replication, rollback and limits.

Mandatory [audit delivery](audit-helper.md) and opt-in
[encrypted storage](encryption-at-rest.md) have separate explicit startup
configuration and supported-profile limits.
