# TLS and mutual TLS

The daemon uses the system OpenSSL 3 library for TLS 1.3. Storage, indexes,
transactions and recovery remain native C17. Python and Go TLS clients use their
standard libraries. Build the daemon with OpenSSL development headers and its
`openssl` pkg-config module; the operating system owns library security updates.

Enable encrypted transport explicitly:

```sh
yamora --data-dir /path/to/runtime --port 8765 \
  --auth-token-file /path/to/read.token \
  --write-auth-token-file /path/to/write.token \
  --tls-cert-file /path/to/server-chain.pem \
  --tls-key-file /path/to/server.key
```

Certificate files contain a PEM leaf followed by optional intermediates. The
leaf must be currently valid and match the PEM private key. The key must be a
non-symlink regular file with no group/other permissions or owner execute bit
(normally mode 0600). Certificates and CA files must also be non-symlink regular
files without group/other write permission. Each file is limited to 1 MiB;
server chains allow at most 16 intermediates. Encrypted keys that require a
password cannot prompt the daemon; use service-managed unencrypted key material
protected by filesystem permissions. Never put private keys or bearer tokens
in Git or command arguments.

Add `--tls-client-ca-file /path/to/client-ca-bundle.pem` to require mutual TLS.
This bundle supplies the explicit client trust anchors (at most 64 certificates),
without automatically adding system roots. OpenSSL verifies the client's chain,
certificate lifetime and client-authentication purpose; missing, expired or
untrusted client certificates fail the handshake. Verification depth is eight
intermediates and the received certificate-list limit is 64 KiB.

Add `--tls-crl-file /path/to/client-revocations.pem` with the client CA option
to enforce locally supplied, signed certificate revocation lists. The bounded
bundle must provide a current complete direct CRL for every configured CA;
invalid or incomplete state refuses startup or replacement. New handshakes
check the chain's revocation state. See [revocation](tls-revocation.md) for the
file profile, issuer coverage, expiry and existing-session limits.

Mutual TLS authenticates the transport. API requests use their configured
bearer credentials or explicitly mapped [certificate principals](certificate-identity.md).
Even bearer-free liveness requires the TLS handshake
on a TLS listener. Certificate subjects and SANs do not assign collection or field roles.
This stage adds no OIDC, cloud IAM, network CRL/OCSP service,
or encryption at rest. Existing numeric loopback/RFC1918 bind restrictions and
private-network firewall requirements continue to apply.

## Protocol and resource bounds

Only TLS 1.3 is enabled. ALPN selects `http/1.1`; a client offering only an
unsupported protocol is rejected. Clients without ALPN can still use HTTP/1.1.
This transport adds no HTTP/2, gRPC, or binary wire protocol. The plaintext
listener remains the default when TLS files are omitted; a TLS listener accepts
no plaintext fallback.

Each handshake has the configured `--io-timeout-ms` deadline. A stalled TLS
client occupies one bounded worker until that deadline. Header/body reads share
an absolute request deadline after the handshake. Response headers/body share an
absolute write deadline. Nonblocking I/O handles both TLS read/write retry
directions and buffered plaintext without polling indefinitely. When the queue
is full, TLS connections close before an expensive handshake; plaintext retains
its bounded HTTP 503 response. Session resumption/tickets and early data are
disabled, so new connections validate the current client trust policy.

## Certificate rotation

Replace the configured certificate/key/CA/CRL files, then send SIGHUP to the daemon
you manage. Paths are retained; no network certificate issuer or ACME client is
built into the service. The reload builds and verifies a replacement context
before publishing it. A malformed certificate/CA, mismatched key, expired leaf,
or unavailable/insecure file rejects the reload and retains the previous
context. The daemon logs a generic rejection without key or certificate contents.

New handshakes use the published context. Established connections retain their
previous context until they finish, within their normal I/O limits. A reload
does not revoke an already established connection. Monitor rejection logs and
certificate expiry; retaining a context does not extend its certificate's life.
The surrounding website's read-only loopback service does not enable TLS
automatically through this feature.

## Python

```python
import ssl
from yamora import YamoraClient

context = ssl.create_default_context(cafile="/path/to/server-ca.pem")
context.minimum_version = ssl.TLSVersion.TLSv1_3
context.load_cert_chain("/path/to/client.pem", "/path/to/client.key")  # for mTLS
db = YamoraClient(
    host="127.0.0.1", port=8765, tls_context=context, auth_token_file="/path/to/read.token"
)
source = db.get("services", "api")
```

The server certificate must contain the numeric connection address in its IP
subject alternative names. The client rejects contexts with disabled certificate
or hostname verification, or a minimum protocol below TLS 1.3. Treat the supplied
context and its trust material as immutable while the client is in use.

## Go

Supply `Config.TLSConfig` with trusted server roots and, for mTLS, a client key
pair. The driver clones the configuration, fixes TLS 1.3 and HTTP/1.1, and rejects
`InsecureSkipVerify` or an explicitly older protocol. Default system roots are
used when `RootCAs` is nil. Numeric endpoint restrictions still apply; `ServerName`
can select a verified DNS certificate identity while dialing that numeric address.
Certificate/key objects should remain immutable while in use. Calls retain
cancellation, response limits, separate bearer credentials and no write retries.

## Administration CLI

`yamoractl --tls` uses system server trust. `--tls-ca-file PATH` supplies explicit
server roots and implies TLS. Pair `--tls-cert-file PATH --tls-key-file PATH`
for mutual TLS; these flags also imply TLS. All ordinary read, write, export and
backup commands use the same verified client. The `replicate` command accepts
separate `--source-tls`, `--source-tls-ca-file`, `--source-tls-cert-file`, and
`--source-tls-key-file` options for its upstream connection. No insecure
verification flag or interactive key-password prompt is provided.

The implementation follows OpenSSL's [protocol version controls](https://docs.openssl.org/3.6/man3/SSL_CTX_set_min_proto_version/),
[peer verification flags](https://docs.openssl.org/3.6/man3/SSL_CTX_set_verify/),
[nonblocking error contract](https://docs.openssl.org/3.6/man3/SSL_get_error/), and
[ALPN callback contract](https://docs.openssl.org/3.6/man3/SSL_CTX_set_alpn_select_cb/).
