#ifndef YAMORA_SECURITY_ACCESS_IDENTITY_H
#define YAMORA_SECURITY_ACCESS_IDENTITY_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#define YD_ACCESS_IDENTITY_AUTHORIZATION_MAX 6144U
#define YD_ACCESS_IDENTITY_REPLY_MAX 4096U
#define YD_ACCESS_IDENTITY_BINDING_SIZE 32U
typedef struct YDAccessIdentity YDAccessIdentity;
typedef enum {
    YD_ACCESS_IDENTITY_NONE, YD_ACCESS_IDENTITY_OIDC, YD_ACCESS_IDENTITY_AWS,
    YD_ACCESS_IDENTITY_LDAP, YD_ACCESS_IDENTITY_KERBEROS
} YDAccessIdentityCategory;
typedef struct {
    char local_name[129];
    YDAccessIdentityCategory category;
    int64_t expires_at; /* Verified matching OIDC expiry; zero for other modes. */
    unsigned char reply[YD_ACCESS_IDENTITY_REPLY_MAX];
    size_t reply_length;
} YDAccessIdentityVerified;
/* Private bounded regular JSON file, operator only. Immutable configuration;
 * constructor performs pinned discovery/JWKS loading and acquires explicit
 * Kerberos keytab credentials. Refuses coexistence with offline OIDC policy.
 * Lifetime may span concurrent authentications; exclude concurrent free. */
YDAccessIdentity *yd_access_identity_load(const char *path, bool offline_oidc_configured,
    char *error, size_t error_capacity);
void yd_access_identity_free(YDAccessIdentity *);
/* Caller checks admin and recognized static bearer credentials FIRST, then
 * selects this boundary exclusively. Never fall back to certificates/offline
 * verification/another scheme following rejection. TLS evidence comes only
 * from established healthy inbound HTTP TLS1.3, never request headers.
 * Negotiate requires exactly 32 RFC9266 tls-exporter bytes (label
 * EXPORTER-Channel-Binding, empty context) from THIS connection; pass directly
 * as GSS application_data. Client uses identical bytes. No proxy termination.
 * Return HTTP status 0/401/403/503: authentication, rejection, unmapped identity,
 * unavailable/malformed provider. Output clears on all rejection paths.
 * Successful output supplies no grants: caller must lookup local_name in its
 * immutable access policy, then apply normal grants before dispatch/replay.
 * OIDC verification uses the explicit trusted now snapshot. Immediately before
 * data dispatch/replay, caller rereads trusted wall time and requires it to be
 * less than the returned verified expires_at; time failure rejects. Also honor
 * the request's original absolute monotonic deadline across provider I/O.
 * Return a nonempty GSS reply as WWW-Authenticate: Negotiate base64(reply)
 * on the final HTTP response, including when subsequent local policy denies.
 * Public calls defer deferred cancellation through cleanup; async cancellation
 * and nonlocal exits are excluded, as for identity.h. */
int yd_access_identity_authenticate(YDAccessIdentity *, const char *authorization,
    bool trusted_inbound_tls, const unsigned char *binding, size_t binding_length,
    int64_t now, YDAccessIdentityVerified *out);
/* Separate explicit operator action, never an implicit authentication side
 * effect. Returns 0/503; requires configured RFC7009 endpoint. */
int yd_access_identity_revoke(YDAccessIdentity *, const char *token);
#endif
