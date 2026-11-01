# Native TLS certificate revocation

This first security/governance slice adds opt-in, local CRL checking with system
OpenSSL 3. Storage and YAML handling are unchanged. Revocation remains disabled
until an operator supplies a CRL through the daemon CLI or peer configuration.

For public HTTP mTLS, add `--tls-crl-file /service/pki/current-crls.pem` alongside
`--tls-cert-file`, `--tls-key-file` and `--tls-client-ca-file`. A CRL without
client CA trust or TLS identity, an empty path, or a missing option argument is
rejected. For Raft, add optional `peer_tls.crl_file` to the existing strict
replica-set configuration. It must be an absolute string path, at most 4096
characters, without control characters; nulls and other types are rejected.
The file must also meet the platform path and CRL safety bounds below.
Omitting `peer_tls.crl_file` preserves the existing peer profile.

## Constructor contract

```c
YDTLSOptions options = {.crl_file = "/service/pki/current-crls.pem"};
YDTLS *http = yd_tls_new_with_options(cert, key, client_ca, &options, error, length);
YDTLS *peer = yd_tls_peer_new_with_options(cert, key, peer_ca, &options, error, length);
```

The new constructors take the existing certificate, key and CA arguments,
followed by `const YDTLSOptions *`, error buffer and buffer length. Paths are
copied. `NULL` options or a `NULL` `crl_file` disables revocation; an empty string
is an error. Supplying a CRL requires an explicit CA bundle. The peer profile
continues to require CA trust even without a CRL. The original `yd_tls_new()`
and `yd_tls_peer_new()` constructors are wrappers with `NULL` options, retaining
their existing behavior and signatures.

HTTP mTLS verifies inbound client certificates. A peer context verifies both
inbound peer clients and outbound peer servers. The existing TLS 1.3, peer SAN
hostname checks, `yamora-raft/1` ALPN and certificate purposes remain in force.
An inbound peer caller must still call `yd_connection_peer_name()` for its
configured peer identity before consuming Raft bytes. Revocation grants no API
roles and changes no bearer authentication or identity-to-role mapping.

## Approved CRL snapshots and bounds

The file contains one to 64 PEM `X509 CRL` blocks, with only whitespace between
blocks. `YD_TLS_CRL_MAX_BYTES` is 1 MiB, and `YD_TLS_CRL_MAX_COUNT` is 64. DER,
other PEM types, empty files, extra text, malformed trailing blocks and duplicate
issuer snapshots are rejected. This slice supports complete direct CRLs;
delta, indirect, partitioned/scoped CRLs, critical extensions and
`removeFromCRL` entries are rejected.

A syntactically valid CRL or a signature by an arbitrary key is insufficient:

- The issuer must be a CA in this context's explicit CA bundle, with permitted
  CRL signing usage, a matching authority key identifier when supplied, and a
  currently trusted certificate chain under OpenSSL authentication level 2.
- The CRL signature must verify against that issuer. A foreign issuer and an
  impostor using the trusted issuer's name with another key are rejected.
- `lastUpdate` must be valid and no later than now; `nextUpdate` must be present,
  valid and later than now. Expired or future snapshots are rejected.
- Every CA in the configured bundle needs a CRL signed by that CA, including
  roots. Every coverage match checks the CRL authority key identifier, including
  issuer/serial constraints when present; a signature by a reused CA key alone
  cannot cover a renewed CA with a different identifier. Include intermediate
  issuer certificates and their CRLs for chains using intermediates. An
  incomplete configured bundle cannot be published.
- The CRL must be a regular file owned by root or the effective service user,
  without group/other write permission. Symlinks in the file or any ancestor
  path component, parent traversal, FIFOs and directories are rejected. Reads
  use bounded descriptor-based, nonblocking file access.

OpenSSL's [CRL verification flags](https://docs.openssl.org/3.0/man3/X509_VERIFY_PARAM_set_flags/)
check the full presented chain on every new handshake, including CRL freshness.
A peer supplying an unconfigured intermediate cannot bypass a missing issuer
CRL. Sessions, tickets and early data remain disabled. Neither HTTP nor Raft
application bytes are processed by the accepting side after verification fails.

Operators supply their CA's approved current snapshot through the local file.
There is no CRL network fetch, OCSP, persistent CRL-number high-water mark or
rollback detector in this slice. An older, still-valid full CRL signed by a
trusted issuer can be loaded; distribution must prevent rollback and replace
the snapshot before expiry. Trust anchors and CRL paths remain operator policy.

## Reload behavior

Replace the configured files atomically, then call the existing
`yd_tls_reload(context, error, length)`. It rereads certificate, key, CA and CRL
from the retained paths and builds a fully verified replacement before swapping
contexts under the existing mutex. A missing, unsafe, malformed, untrusted,
expired or incomplete replacement returns `false` and keeps the prior context.
There is no revocation-disabled fallback. Initial construction returns `NULL`
for the same errors, without returning a partially configured context.

New handshakes use the published snapshot. Existing connections retain their
previous OpenSSL context and finish under normal I/O deadlines. Reload does
not terminate established sessions. Keeping a previous context after a failed
reload does not extend CRL validity: once that snapshot expires, new handshakes
fail even without another reload. Each context reload is atomic individually;
HTTP and peer contexts do not form one cross-context transaction.

## Daemon integration and remaining parent hooks

The daemon wiring is implemented in this slice. The parent retains Makefile,
shared CI registration, roadmap, memory and final combined review:

1. Separate optional CRL paths are retained for the HTTP client-CA profile and
   the Raft peer profile. Missing/invalid HTTP CRL options are rejected before
   accepting requests. Peer config and CRL errors reject before opening cluster
   storage. There is no constructor fallback after revocation failure.
2. The daemon HTTP construction site calls
   `yd_tls_new_with_options(cert, key, client_ca, &options, error, length)`;
   peer construction calls `yd_tls_peer_new_with_options(...)`. Each profile
   supplies its own `YDTLSOptions`. The peer object enforces the option in
   both inbound and outbound connections.
3. SIGHUP calls `yd_tls_reload()` for HTTP and peer contexts on the existing
   reload path. Failures are reported generically and retain the objects. No new
   reload API or shared library source registration is needed.
4. `yamora/tests/test_tls_revocation.py` is discoverable by the existing
   `test_*.py` unittest command. It compiles its own small harness and `tls.c`
   serially using system `cc`, pthreads and OpenSSL. No Makefile change is
   required; the parent owns any shared CI inventory adjustments.
   `yamora/tests/test_tls_revocation_daemon.py` adds real daemon HTTP mTLS,
   SIGHUP and strict public/peer config tests. It uses `YAMLDB_BUILD_DIR` when
   supplied, otherwise builds the daemon serially in its owned fixture scratch
   with `make -j2`; it changes no shared build definition.

## Focused verification

From the repository root, with an owned disk-backed `TMPDIR` already created:

```sh
python3 -m unittest yamora.tests.test_tls_revocation -v
python3 -m unittest yamora.tests.test_tls_revocation_daemon -v
```

The suite creates synthetic authorities, leaves and signed CRLs, then connects
real TLS 1.3 peers over socket pairs. It checks successful HTTP/peer payloads,
revoked clients and servers rejecting before application bytes, intermediate
revocation, hostile files and bundles, constructor compatibility, initial/reload
failures, successful snapshot rotation, active expiry and retained established
sessions. Generated keys, binaries and fixtures remain in unique temporary
directories under the supplied scratch root and are removed on either outcome.
