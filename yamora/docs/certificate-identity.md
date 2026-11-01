# Certificate principals

Native HTTP and binary requests can authenticate through an explicitly mapped,
verified client certificate under a version 2 collection policy. Existing bearer
entry points and version 1 policies keep their contracts. Mapping a certificate
does not grant database administration or Raft peer identity.

## Trust boundary

`yd_connection_client_identity` in `src/transport/tls.h` returns a copied
`YDTLSClientIdentity`: `verified` and the 32-byte SHA-256 of the entire DER-encoded
client leaf certificate. It requires a completed, healthy, inbound native HTTP
or binary TLS 1.3 connection, a context constructed for that public profile with
client verification enabled, both `SSL_VERIFY_PEER` and
`SSL_VERIFY_FAIL_IF_NO_PEER_CERT`, a present certificate, and `X509_V_OK`.
Binary connections also require their completed handshake and
`yamora-binary/1` ALPN. Certificate issuer trust, purpose, expiry, and configured
CRL validation remain the existing TLS handshake's responsibility.

Results are `YD_TLS_CLIENT_VERIFIED`, `YD_TLS_CLIENT_NONE` for plaintext or a
server-only context, and `YD_TLS_CLIENT_ERROR` for invalid arguments, failed or
incomplete TLS, shutdown, extraction failure, outbound TLS, or a Raft context.
Every result other than VERIFIED clears the entire output. An empty/closed
connection has no identity. A digest is public evidence, not a bearer secret:
accepting a digest supplied by a request, proxy header, SDK, or untrusted caller
would bypass proof of certificate-key possession.

The private `ContextProfile` tags in `tls.c` are immutable static objects
associated with the exact `SSL_CTX` through its application-data slot, which the
TLS module owns. An `SSL` retains that context across profile reload and profile
destruction. Tags never point into `YDTLS`, and identity extraction does not read
the reloadable owner. One thread must own/serialize a connection's identity
extraction, I/O, and close; reload may run concurrently. Profile destruction
still follows the existing begin/reload exclusion contract. Evidence contains
no borrowed pointers and survives connection close, but represents only the
established handshake's verification snapshot. Trust/CRL reload does not
reauthenticate an established connection.

## Explicit policy mapping

Version 2 retains the exact root fields `version`, `roles`, and `principals`.
Each principal has `roles` and exactly one credential field: `token_file` or
`tls_client_sha256`. For example, this illustrative pin must be replaced by the
actual trusted client's full DER leaf digest:

```yaml
version: 2
roles:
  reader:
    read: [orders]
    write: []
principals:
  reporting-client:
    roles: [reader]
    tls_client_sha256:
      - "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
```

A certificate list contains one or two distinct, globally unique fingerprints.
Each scalar must be exactly 64 lowercase hexadecimal characters inside literal
single or double quotes. Plain, numeric, escaped, prefixed, colon-separated,
block, uppercase, and malformed forms are rejected. The native parser's source
spans enforce the spelling as well as the decoded value. Duplicate pins within
or across principals, both credential fields, unknown fields, duplicate roles,
missing roles, or unknown roles reject the entire policy. Limits remain 128 KiB,
64 roles, 64 principals, and 64 read/write collection names per role; at most 128
certificate pins result. Private policy/token file checks remain unchanged,
including rejection of symlinks and public access. Version 1 stays token-only.

`yd_access_has_certificate_principals` reports whether startup must enforce
certificate prerequisites. `yd_access_identify_certificate` maps trusted native
evidence to one opaque `const YDAccessPrincipal *`, or NULL when unmapped.
`yd_access_principal_name` returns its configured name. Neither CN/SAN, issuer,
public key, nor a successful handshake alone creates a principal or grants.
Same-key renewal creates a different full-certificate digest and requires an
explicit new pin. No certificate principal can acquire administrative bypass,
reserved collection access, or global endpoint privileges. Restricted leader
discovery retains its existing allowance.

`yd_access_principal_request` returns 0/401/403 using the same grant evaluator as
the existing bearer `yd_access_request` wrapper. `yd_access_principal_writer`
and `yd_access_writer` share the same early write-grant check. Full transactions
require every operation's write grant; aggregation requires its foreign lookup
collection's read grant even with empty input or an eliminating filter. No API
unions bearer and certificate roles or tries another credential after denial.
NULL or another live policy's handles return 401/false/NULL without dereference.

Handles and names borrow the immutable loaded policy. Concurrent readers may
share them while that policy remains alive. They must not outlive
`yd_access_free`; pointer membership checks cannot make stale handles safe.
Policy-file edits do not mutate existing objects. A future policy replacement
must retain the old object until all admitted work using it completes, or
re-resolve copied evidence under the new policy according to an explicit
admission contract. There is no policy hot-reload mechanism in this primitive.

## Daemon credential selection

The identity primitive declarations live in `src/transport/tls.h` and
`src/security/access.h`, with implementations and private types in the
corresponding `.c` files. `YDConnection` layout, existing constructors,
bearer APIs, and source callers remain compatible. Primitive tests live in
`tests/certificate_identity_harness.c` and `tests/test_certificate_identity.py`;
daemon enforcement is covered separately below.

Startup rejects a certificate policy without a server certificate/key and an
explicit client CA, before opening storage or listeners. The existing policy
requirement for an administrative read token remains. Failed TLS never reaches
API authorization. Raft peer SAN checks remain independent.

| Request | Authentication |
| --- | --- |
| Authorization present | Bearer exclusively, including invalid or insufficient credentials |
| Authorization absent; certificate policy configured | Verified full-leaf pin mapped to one restricted principal |
| Trusted but unmapped certificate under that policy | 401 |
| Mapped principal without the operation's grants | 403 |

A valid bearer retains its existing capabilities even on a trusted, unmapped
certificate connection. Roles are never combined, and denial never falls back
to another credential. Without any certificate principals in the policy,
existing bearer and authentication-disabled behavior remains unchanged;
configuring a client CA alone does not enable certificate authentication.
Writes remain disabled without the administrative write credential. `/healthz`
keeps its liveness exception after a successful required TLS handshake.

HTTP attaches evidence after request parsing, before body admission. Binary I/O
copies the verified connection identity into each owned job before admission;
workers receive that copy rather than an `SSL *` or a borrowed session identity.
The additive `yd_binary_runtime_start_with_identity` requires both identity-aware
callbacks; the original start/options/callback API remains available. The same
grant checks govern admission and execution. Full transaction and foreign-lookup
authorization precedes storage preparation.

For rotation, load a policy mapping both old and new leaves to the same
principal, switch clients, then load a policy removing the old pin. Existing
loaded objects keep their previous mapping until restart; SIGHUP reloads only
TLS contexts. Trust/CRL reload affects new handshakes; invalid replacements
preserve the previous context. Established binary sessions retain their
authenticated handshake snapshot within existing session limits. Mapping
removal revokes certificate authentication after restart; transport revocation
requires the CA/CRL trust policy. Neither mechanism promises immediate revocation
of already established sessions.

## Verification

Run from the repository root using an existing task-specific disk scratch root:

```sh
TMPDIR=/var/tmp/andromeda-work/yamora-certificate-identity \
CC=/usr/bin/clang CERTIFICATE_IDENTITY_SANITIZER=address,undefined \
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:abort_on_error=1 \
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
python3 -m unittest yamora.tests.test_certificate_identity -v
```

The suite performs real native HTTP/binary TLS handshakes against independently
verified Python TLS clients, checks full-DER digest equality and explicit role
mapping, rejects actual invalid/revoked clients, and covers strict policy,
two-pin rotation, shared bearer grants, foreign handles, and concurrent reads.
Fault controls operate only in the harness and start from otherwise valid
connections. A deterministic gate overlaps extraction with release of the old
profile-owned context reference, then verifies identity and I/O after profile
destruction. Thread qualification uses `CERTIFICATE_IDENTITY_SANITIZER=thread`,
`TSAN_OPTIONS=halt_on_error=1:exitcode=66`, and
`CERTIFICATE_IDENTITY_OPENSSL` pointing at existing fully TSan-instrumented
OpenSSL headers and static libraries; it must not use uninstrumented OpenSSL or
sanitizer suppressions. No dependency build or installation is part of the test.

The source-override variables `CERTIFICATE_IDENTITY_TLS_SOURCE` and
`CERTIFICATE_IDENTITY_ACCESS_SOURCE` permit isolated negative-control copies.
Removing verification-result, Raft-exclusion, collection-grant, quote-profile,
or global-uniqueness guards, or substituting a public-key digest, produces
assertion failures after successful compilation with valid native fixtures.
The unmodified suite must then pass again under fatal ASan/UBSan.

The primitive harness is separate from actual-daemon enforcement tests in
`tests/test_certificate_access.py`. Those exercise both public listeners and a
three-node mTLS cluster: exact leaf mapping, credential precedence, collection
and global denials, transactions/lookups, large-upload admission, restart-based
mapping rotation, witnessed TLS/CRL replacement, and independent peer SAN checks.
Bearer-fallback, grant-bypass and compatibility-guard-removal mutants fail their
targeted assertions under fatal ASan/UBSan; the restored tests pass. These are
bounded native certificate-policy checks, not enterprise identity-provider or
full platform qualification.

The test-only `certificate_access_faults.c` callback gate is linked into the
existing `yamora-binary-runtime-faults` target. It pauses before execution
consumes identity evidence. With seven other sessions occupied, the tests
disconnect a writer, require a new reader or unmapped client to reuse its slot,
and verify both clients retain their own permissions. Borrowing the reused
session's evidence instead of the job copy fails the exact writer-result
assertion in both cases; the restored implementation passes. All 17 daemon
enforcement tests pass under fatal ASan/UBSan, including the three-node cases.

Build both daemon targets before running the enforcement suite:

```sh
make -C yamora all build/yamora-binary-runtime-faults
TMPDIR=/var/tmp/andromeda-work/yamora-certificate-identity \
YAMLDB_BUILD_DIR="$PWD/yamora/build" \
python3 -m unittest yamora.tests.test_certificate_access -v
```
