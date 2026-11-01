#ifndef YAMORA_SECURITY_IDENTITY_H
#define YAMORA_SECURITY_IDENTITY_H
#include "oidc.h"
#include <stddef.h>
#include <stdint.h>

#define YD_IDENTITY_URL_MAX 1024U
#define YD_IDENTITY_RESPONSE_MAX 65536U
#define YD_IDENTITY_GSS_TOKEN_MAX 16384U
typedef enum {
    YD_IDENTITY_ERROR = -1, YD_IDENTITY_INVALID = 0, YD_IDENTITY_VALID = 1
} YDIdentityResult;
/* Operator configuration only: exact origin (https:// or ldaps://host:port),
 * numeric IP (no DNS), PEM trust store, 1..10000ms total deadline per exchange.
 * No ambient proxy, DNS, redirects, cookies, client-controlled URL or trust.
 * Caller keeps configuration immutable for the duration of each call. */
typedef struct {
    const char *origin, *address, *ca_file;
    unsigned timeout_ms;
} YDIdentityEndpoint;
typedef struct {
    const YDIdentityEndpoint *endpoints;
    size_t count; /* 1..8 */
} YDIdentityNetwork;
/* Public blocking calls defer POSIX thread cancellation through cleanup and
 * restore/deliver pending deferred cancellation at the return boundary. Caller
 * cancellation already disabled remains disabled. Asynchronous cancellation,
 * longjmp/nonlocal exits and signal handlers that abandon the call are excluded.
 * Socket I/O uses atomic CLOEXEC/NONBLOCK and per-send MSG_NOSIGNAL, without
 * changing process signal disposition. */
typedef struct {
    char issuer[513], jwks_uri[YD_IDENTITY_URL_MAX + 1];
    char introspection_endpoint[YD_IDENTITY_URL_MAX + 1];
    char revocation_endpoint[YD_IDENTITY_URL_MAX + 1];
} YDIdentityDiscovery;
/* Every non-VALID result clears output. Strings are bounded NUL-terminated.
 * ERROR is unavailable/malformed upstream or local failure; INVALID is a
 * provider-authenticated credential denial. Both deny authentication. */
YDIdentityResult yd_identity_discover(const YDIdentityNetwork *, const char *issuer,
    YDIdentityDiscovery *out);
YDIdentityResult yd_identity_jwks(const YDIdentityNetwork *, const char *jwks_uri,
    unsigned char *out, size_t capacity, size_t *length);
YDIdentityResult yd_identity_introspect(const YDIdentityNetwork *, const char *url,
    const char *client_id, const char *client_secret, const char *token,
    const char *issuer, const char *audience, const char *required_scope,
    int64_t now, YDOIDCIdentity *out);
/* Revocation is a separate operator/client operation; never automatic during
 * verification. RFC7009 success does not prove the token previously existed. */
YDIdentityResult yd_identity_revoke(const YDIdentityNetwork *, const char *url,
    const char *client_id, const char *client_secret, const char *token);
typedef struct { char arn[513], account[13]; } YDIdentityAWS;
/* Fixed STS GetCallerIdentity POST; authorization must sign exactly host,
 * x-amz-date, x-amz-security-token and x-yamora-server-id. Timestamp <=60s old,
 * <=5s future; exact server ID is an audience binding, not a one-use nonce.
 * The accepted ARN must still map to a local grant. No AWS credentials stored. */
YDIdentityResult yd_identity_aws(const YDIdentityNetwork *, const char *sts_url,
    const char *server_id, const char *authorization, const char *amz_date,
    const char *session_token, int64_t now, YDIdentityAWS *out);
/* LDAPv3 exact-DN simple bind on verified LDAPS. Rejects anonymous/empty-password
 * binds, referrals and controls. No search/filter interpolation or group grants. */
YDIdentityResult yd_identity_ldap(const YDIdentityNetwork *, const char *ldaps_origin,
    const char *dn, const char *password);
typedef struct YDIdentityKerberos YDIdentityKerberos;
/* Optional system libgssapi_krb5.so.2 backend, explicit acceptor principal and
 * keytab via gss_acquire_cred_from, never ambient default acceptor credentials;
 * accepted context target must equal the explicitly imported principal.
 * Caller provides trusted established TLS application binding bytes; the
 * access_identity.h runtime profile mandates RFC9266 tls-exporter.
 * Raw Kerberos GSS tokens only; no SPNEGO/NTLM, delegation or anonymous identity.
 * System replay cache must remain enabled. Exclude concurrent accept/free. */
YDIdentityKerberos *yd_identity_kerberos_new(const char *principal, const char *keytab);
YDIdentityResult yd_identity_kerberos_accept(YDIdentityKerberos *,
    const unsigned char *token, size_t length,
    const unsigned char *channel_binding, size_t binding_length,
    char *principal, size_t principal_capacity,
    unsigned char *reply, size_t reply_capacity, size_t *reply_length);
void yd_identity_kerberos_free(YDIdentityKerberos *);
#endif
