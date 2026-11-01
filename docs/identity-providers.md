# Native identity-provider adapters

[identity.h](../src/security/identity.h) defines a bounded native integration
boundary for OIDC discovery, online token state and revocation, AWS IAM, LDAPS
and system Kerberos. These functions authenticate identity; the caller maps an
exact provider identity to its own principal and grants before dispatch and
before receipt replay. They never infer grants from email addresses, LDAP
groups, AWS account membership or an authenticated Kerberos realm.

The adapters are separately callable. [access_identity.h](../src/security/access_identity.h)
adds the immutable runtime provider-file boundary selected by the daemon's
`--identity-provider-file PATH`. Startup requires a native disk, access policy
and inbound TLS; binary remains static bearer/certificate. Existing
[offline access tokens](oidc.md) retain their separate profile.

## Runtime provider file and credential selection

`yd_access_identity_load(path, offline_oidc_configured, error, capacity)` loads a
private JSON regular file of at most 64 KiB using the existing private-file
reader. Symlinks, public access, executable files and group writes reject;
systemd's private 0440 credential files remain supported. It accepts version 1,
up to eight endpoint pins and 64 exact mappings. Unknown/duplicate fields,
duplicate origins/mapping tuples, absent providers and unsupported versions
reject. Every endpoint uses an explicit port, numeric transport IP, absolute CA
path and a 1–10,000 ms deadline. Configuration remains immutable until free.

```json
{
  "version": 1,
  "endpoints": [
    {"origin":"https://identity.example:443","address":"192.0.2.10",
     "ca_file":"/etc/yamora/idp-ca.pem","timeout_ms":2000},
    {"origin":"ldaps://directory.example:636","address":"192.0.2.11",
     "ca_file":"/etc/yamora/ldap-ca.pem","timeout_ms":2000}
  ],
  "oidc": {"issuer":"https://identity.example:443","audience":"yamora",
           "scope":"read","client_id":"yamora-introspection",
           "client_secret_file":"/run/credentials/yamora/idp-secret"},
  "aws": {"url":"https://identity.example:443/","server_id":"yamora-production"},
  "ldap": {"origin":"ldaps://directory.example:636"},
  "kerberos": {"principal":"yamora/server.example@EXAMPLE",
               "keytab":"/run/credentials/yamora/service-keytab"},
  "mappings": [
    {"category":"oidc","subject":"stable-subject","client_id":"client",
     "local_name":"reader"},
    {"category":"aws","subject":"arn:aws:iam::123456789012:user/service",
     "local_name":"reader"},
    {"category":"ldap","subject":"uid=alice,dc=example","local_name":"reader"},
    {"category":"kerberos","subject":"alice@EXAMPLE","local_name":"reader"}
  ]
}
```

Provider sections are optional; at least one must exist, and each mapping must
refer to a configured category. Use a separately pinned real STS origin for
AWS; the shared illustrative origin above is suitable only for a controlled
gateway/fixture. Local names are 1–128 ASCII letters, digits, `_`, `.` or `-`,
excluding `yamldb-system`. Multiple exact identities may map to one local name.
The local name must independently exist in the daemon's access policy. This
file contains no roles, collection grants or administrative capability.

The loader rejects coexistence with an offline OIDC policy. Online OIDC startup
retrieves pinned discovery and JWKS, requires introspection and revocation
endpoints, and constructs the strict access-token verifier. Each Bearer request
requires its RS256 signature/profile/scope/time check, then fresh authenticated
introspection. Subject, client ID and expiry must agree exactly. Provider
unavailability never falls back to offline JWT success. Keys are immutable for
the runtime owner's lifetime; replacement requires constructing a fully checked
new owner. `yd_access_identity_revoke` is an explicit operator action, separate
from authentication, against the discovered revocation endpoint.

The daemon checks its administrative credential and recognized static
bearer credentials first. Such selection is terminal, including when grants
deny the request. An explicit Authorization header selects exactly one runtime
scheme; rejection never falls back to mTLS, another provider or offline OIDC.
The runtime accepts these narrow schemes over trusted inbound HTTP TLS 1.3:

| Scheme | Self-contained credential | Verified mapping key |
| --- | --- | --- |
| `Bearer` | RS256 access JWT, at most 4,096 bytes | exact subject and client ID |
| `Yamora-IAM` | standard padded base64 of strict JSON with exactly `authorization`, `date`, `session_token` | exact authenticated ARN |
| `Basic` | standard padded base64 of UTF-8 `DN:password`; first colon separates fields | exact configured DN |
| `Negotiate` | standard padded base64 of a raw Kerberos GSS initial token, at most 4,096 decoded bytes | exact authenticated principal |

No proof may supply an endpoint, CA, address, server audience or channel binding.
Base64 must be canonical with padding; whitespace and alternate encodings
reject. LDAP DNs containing a colon cannot use this Basic profile. Negotiate is
a direct raw Kerberos profile: browser SPNEGO/NTLM negotiation is unsupported.
The module caps a complete Authorization value at 6,144 bytes; an integrating
daemon's existing parser may enforce its stricter 4,096-byte credential limit
and 8,192-byte total header limit. Larger tickets/proofs must reject.

`yd_access_identity_authenticate` returns 0, 401, 403 or 503 and clears outputs
on rejection. Success copies a local name, an authentication category, and an
optional raw Kerberos AP-REP; it supplies no policy handle or grants. The daemon
looks up that name in its immutable access policy and applies ordinary grants
before body reservation, dispatch and receipt replay. OIDC output also carries
the cryptographically verified expiry matching the authenticated introspection
response. Since the explicit `now` snapshot precedes provider I/O, the daemon
must reread trusted wall time immediately before data dispatch/replay and
require it to be earlier than that expiry; time failure rejects. The original
absolute monotonic request deadline still applies across provider I/O. Online
OIDC must refresh after header preflight/body/audit waits; a Kerberos proof and
its AP-REP stay cached for the single request to avoid replaying a one-use GSS
initial token. It must return a produced
AP-REP in `WWW-Authenticate: Negotiate base64(reply)` on the final response,
including when subsequent local authorization denies the operation. Concurrent
authentication is supported; Kerberos credential use is serialized. Destruction
must exclude active calls, and deferred cancellation follows the leaf contract.

Eight actual HTTPS daemon tests pass in normal and fatal ASan/UBSan builds.
They cover online revocation/provider failure, final expiry after delayed
introspection, delayed request bodies, terminal mixed-case static/admin
selection, IAM mapping, exact-DN LDAP grants and binary exclusion, and same-TLS
Kerberos exporter binding with mutual replies on success and local denial.
These controlled local providers qualify the implemented protocol profiles;
they do not establish live Google, AWS, directory or realm interoperability.

## Trusted TLS channel binding

`yd_connection_channel_binding(connection, out[32])` is serialized with the
connection's I/O/close. It accepts only a healthy completed inbound HTTP TLS 1.3
profile on the matching descriptor. Plaintext, outbound, binary, peer/shard,
failed, incomplete and closed connections reject and clear all output bytes.
The accessor copies [RFC 9266](https://www.rfc-editor.org/rfc/rfc9266.html)
`tls-exporter` data: 32 bytes from the exact `EXPORTER-Channel-Binding` label and
empty context. See [OpenSSL's exporter API](https://docs.openssl.org/3.0/man3/SSL_export_keying_material/).

The runtime Negotiate profile requires these exact 32 bytes directly as GSS
`application_data` on both peers. They come from the same established connection
carrying the credential. The daemon copies native evidence while receiving a
request; a wire header or TLS-terminating proxy cannot supply it. This runtime
profile does not use `tls-server-end-point` or an HTTP request-supplied hash.

## Outbound trust and failure behavior

Every network operation receives immutable operator-owned endpoint entries:

```c
YDIdentityEndpoint endpoints[] = {
    {"https://identity.example:443", "192.0.2.10", "/etc/yamora/idp-ca.pem", 2000},
    {"ldaps://directory.example:636", "192.0.2.11", "/etc/yamora/ldap-ca.pem", 2000}
};
YDIdentityNetwork network = {endpoints, 2};
```

These are illustrative reserved addresses. Configure actual numeric IPv4/IPv6
addresses and an exact origin; hostnames in origins are ASCII DNS names or
IPv4 literals. Numeric addresses avoid an unbounded resolver operation. An
operator must resolve/update these pins through its trusted configuration
lifecycle. URLs from discovery must match an allowlisted origin exactly.
Cross-origin JWKS/introspection/revocation require separate explicit entries.
No HTTP proxy, cookies, redirects, ambient resolver or default trust store is
consulted. A request token cannot choose a URL, address, CA file or TLS policy.

OpenSSL verifies the chain against the specified PEM trust store and verifies
the origin hostname/IP. TLS 1.3 is mandatory. Nonblocking connect, handshake,
write and read share one monotonic deadline (1–10,000 ms per exchange). There
are at most eight endpoints, 8 KiB of HTTP headers and 64 KiB of response body.
The deliberate HTTP/1.1 profile requires Content-Length, rejects duplicate
headers, folding and Transfer-Encoding, and does not follow redirects. A
provider using chunked responses needs a compatible configured gateway or a
separately qualified transport extension; it must never be accepted by treating
ambiguous framing as success.

Sockets are created atomically with NONBLOCK and CLOEXEC. A dedicated
non-owning OpenSSL socket BIO uses `send(MSG_NOSIGNAL)`, so peer closure cannot
raise SIGPIPE and no process signal disposition is changed. Failed monotonic
clock reads reject at handshake completion and after every successful read or
write, including already buffered TLS data.

Public blocking calls disable deferred POSIX cancellation through complete local
cleanup, restore the caller's state and test pending cancellation at the return
boundary. Callers that already disabled cancellation retain that state. A
constructor cleanup handler releases a newly created Kerberos owner if pending
cancellation arrives before caller adoption. Asynchronous cancellation and
nonlocal exits (including abandoning a call from a signal handler) are outside
the API contract.

`VALID` means the requested protocol check succeeded. Authenticated credential
denials return `INVALID`. Invalid configuration, malformed upstream responses,
TLS/network failures and unsupported protocol shapes return `ERROR`. Both
reject authentication. Identity output is zero on every rejecting result.
No credentials, response bodies or supplied identifiers are logged by these
modules. Temporary request/response buffers are cleansed before return.

## Discovery, introspection and revocation

`yd_identity_discover` retrieves the configured issuer's
`/.well-known/openid-configuration`, requires an exact `issuer`, and validates
every returned identity URL against the endpoint allowlist. Optional online
endpoints remain empty if omitted; callers must refuse a configured online mode
when its endpoint is absent. Discovery is configuration-time work, never driven
by an untrusted JWT issuer or key ID. See [OIDC Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html).

`yd_identity_jwks` retrieves the pinned key URI. Feed its bounded result through
the strict verifier constructor before publishing a replacement key set. The
constructor still rejects unsupported keys, duplicate key IDs and private key
material. Key selection never initiates network work. The caller owns immutable
replacement, restart/reload policy and retirement after outstanding lifetimes.

`yd_identity_introspect` sends an authenticated form-encoded POST using
`client_secret_basic`. Client ID and secret are individually form encoded
before Basic encoding. Token input is independently form encoded. The response
must have boolean `active: true`, exact issuer and audience, `Bearer` token
type, a bounded nonempty subject and client ID, required scope and integral
`iat`/`exp` (at most one hour). Expiry, future issue/not-before, wrong claims or
`active: false` reject. No result is cached, so the next call observes a local
provider's revocation state. This is a deliberately strict
[RFC 7662](https://www.rfc-editor.org/rfc/rfc7662.html) profile: optional fields
in that RFC become requirements here so the caller can bind identity and
authorization. An unavailable provider cannot fall back to offline success.

`yd_identity_revoke` is a separate explicitly requested client/operator action
using the same authenticated form POST and `access_token` hint. It implements
the [RFC 7009](https://www.rfc-editor.org/rfc/rfc7009.html) success semantics:
HTTP 200 does not establish that the token existed or that every resource
server has already observed revocation. It does not change local grants.

## Google-shaped OIDC ID tokens

`yd_oidc_new_id` and `yd_oidc_verify_id` form an explicit ID-token profile.
They reuse bounded RS256 verification, exact issuer/audience binding, curated
JWKS, time limits and strict JSON parsing. They require `typ: JWT`, a matching
expected nonce and an audience-bound authorized party (`azp` when supplied;
otherwise a scalar audience). ID tokens do not need access-token `jti`,
`client_id` or scope. Output contains the stable `sub`, the client ID and expiry;
its access-scope flag stays false. An ID-profile object cannot be passed to the
access-token entrypoint, or vice versa. A caller must consume its expected
nonce once; nonce storage and a browser authorization flow are not supplied by
this leaf verifier.

Google mode should pin `https://accounts.google.com` and its actual configured
client audience. The local tests use Google's documented claim shape with an
ephemeral local signing key. They do not qualify a real Google account,
credential acquisition, browser login, provider revocation or Google's live key
rotation. See [Google's ID-token validation guidance](https://developers.google.com/identity/openid-connect/openid-connect#validatinganidtoken).

## AWS IAM

`yd_identity_aws` sends only a fixed POST `/` with
`Action=GetCallerIdentity&Version=2011-06-15` to a pinned STS endpoint. The caller
presents an AWS4-HMAC-SHA256 Authorization header, X-Amz-Date and session token.
Signed headers must be exactly `host;x-amz-date;x-amz-security-token;x-yamora-server-id`.
The adapter supplies the configured server ID; changing the audience invalidates
the signature at STS. A timestamp older than 60 seconds or more than five seconds
in the future rejects before network work. STS validates the signature and AWS
credential state; the adapter never holds an AWS secret access key.

Only bounded successful GetCallerIdentity XML with one ARN and matching
12-digit account is accepted. Entities, DTDs, duplicate fields and unsupported
ARN partitions reject. This initial profile accepts `arn:aws:iam` and
`arn:aws:sts`; other partitions need explicit qualification. Local policy maps
the exact returned ARN, never merely the account. Server ID is an audience
binding, not a one-use challenge: a signed request remains replayable within
the short timestamp window. Use confidential TLS and do not log it. These
semantics follow [GetCallerIdentity](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html)
and [SigV4 request signing](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html).

## LDAP and Kerberos

`yd_identity_ldap` uses a fresh verified LDAPS connection for one LDAPv3 simple
bind against an exact DN. DN and password must be nonempty and bounded; an empty
password never becomes an unauthenticated successful bind. No search/filter is
constructed. Definite-length BER, message ID, bind response type and result code
are checked; referrals, SASL, response controls, indefinite lengths and unknown
extensions reject. No group/search authorization or StartTLS downgrade is
implemented. See [RFC 4511](https://www.rfc-editor.org/rfc/rfc4511.html) and
[RFC 4513](https://www.rfc-editor.org/rfc/rfc4513.html).

Kerberos uses the optional fixed system library `libgssapi_krb5.so.2`, loaded
locally with `dlopen`. It is an explicit dependency for this mode, reconciled
with the roadmap's native dependency constraint; it adds no dependency to the
storage engine or offline OIDC mode. There is no handwritten Kerberos crypto
or vendored Kerberos implementation. A missing library, symbol, explicit
principal or keytab fails closed. Installations using this mode must provide
an up-to-date system MIT-compatible GSSAPI implementation with
`gss_acquire_cred_from` and channel-binding support.

The acceptor acquires credentials from the explicit keytab, then requires the
authenticated context's target name to equal the explicitly imported principal
using system GSS name comparison. Other service principals in the same keytab
cannot authenticate to this adapter. No ambient default acceptor credentials
are used. A configured principal absent from the keytab denies at acceptance.
This avoids a missing-principal allocation leak in the qualified system MIT
name-specific credential-acquisition path without suppressing sanitizer checks.
It accepts only raw Kerberos GSS
tokens, requires complete mutual authentication, replay/integrity flags,
positive remaining lifetime and verified TLS channel bindings, and rejects
SPNEGO/NTLM, anonymous identity and delegated credentials. The caller provides
the established TLS channel-binding bytes and returns the produced AP-REP to
the client before granting service. Do not substitute client-supplied binding
bytes. Keep system replay caching enabled; an explicit
`KRB5RCACHETYPE=none` is refused. Keytab and replay-cache permissions and
rotation belong to deployment policy. Use an exact returned principal-to-role
mapping. See [MIT's GSSAPI documentation](https://web.mit.edu/kerberos/krb5-latest/doc/appdev/gssapi.html).

## Local qualification and limits

Run the leaf suite in the managed task environment:

```sh
python3 -m unittest yamora.tests.test_identity_providers -v
```

It compiles the native harness with fatal ASan/UBSan, creates ephemeral TLS/RSA
keys in owned scratch, starts isolated HTTPS and LDAPS services, checks SigV4
independently using the Python standard library, and issues real local Kerberos
service tickets using system MIT encryption/encoding, keytab and ccache APIs.
GSS initiation and acceptance use the real system libraries; no external KDC
or production realm is contacted. Fixtures and processes are removed on success
and failure. Missing native crypto/GSS capabilities fail the suite.

Positive controls precede issuer/audience/scope/time/revocation denials,
untrusted TLS, unallowlisted endpoints, oversize/malformed responses, LDAP
password/protocol failures, and Kerberos replay/channel-binding/keytab failures.
Independent guard-removal builds prove selected negative tests fail after
successful compilation and pass with the original source restored.

The runtime boundary suite is `yamora.tests.test_access_identity`; it uses the
real private-file reader and local protocols, with fatal native sanitizers and
independent online-state/mapping/TLS guard controls. Actual daemon integration
has a separate gate, supplied an already built native executable:

```sh
YAMORA_TEST_BINARY="$build/yamora" python3 -m unittest yamora.tests.test_access_identity_daemon -v
```

That suite never builds or substitutes a daemon. Missing executable or protocol
capabilities fail rather than skip. It exercises local HTTPS provider identity,
ordinary local grants, explicit terminal credentials, binary exclusion,
revocation/expiry across delayed body/provider I/O, and same-connection Kerberos
exporter bindings with mutual replies on allowed and denied operations. A source
handoff or leaf-only pass is insufficient evidence that daemon wiring works.

External credentials and real-provider qualification were explicitly waived by
the owner. Local protocol evidence does not establish real Google/AWS account
interoperability, an enterprise directory/realm deployment, browser login,
SDK token acquisition or daemon dispatch integration. No compliance claim is
made.
