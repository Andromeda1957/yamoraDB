#ifndef YAMORA_SECURITY_OIDC_H
#define YAMORA_SECURITY_OIDC_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#define YD_OIDC_JWT_MAX_BYTES 4096U
#define YD_OIDC_JWKS_MAX_BYTES 65536U
#define YD_OIDC_IDENTITY_MAX_BYTES 255U
typedef struct YDOIDC YDOIDC;
typedef struct {
    const char *issuer, *audience, *required_scope;
    unsigned clock_skew_seconds, max_token_lifetime_seconds;
} YDOIDCOptions;
typedef struct {
    char subject[YD_OIDC_IDENTITY_MAX_BYTES + 1];
    char client_id[YD_OIDC_IDENTITY_MAX_BYTES + 1];
    int64_t expires_at;
    bool required_scope_present;
} YDOIDCIdentity;
typedef enum {
    YD_OIDC_ERROR = -1, YD_OIDC_INVALID = 0, YD_OIDC_VALID = 1
} YDOIDCResult;
/* Immutable owned copies, public RSA keys, RS256 only; no file/network access.
 * Options: HTTPS issuer <=512 bytes, audience <=256, scope word <=128;
 * skew 0..120 seconds, lifetime 60..3600. Configuration errors return NULL.
 * All strings are NUL-terminated. Diagnostics never contain supplied input.
 * JWKS input is borrowed only during this call. */
YDOIDC *yd_oidc_new(const YDOIDCOptions *options,
    const unsigned char *jwks, size_t jwks_length, char *error, size_t error_length);
/* Explicit OIDC ID-token profile, including Google-shaped tokens. Separate
 * object and entrypoint: never accepted by yd_oidc_verify access-token calls.
 * Exact HTTPS issuer, audience/azp, RS256, iat/exp and required nonce bind the
 * identity. No access-token jti/client_id/scope requirements; no grants implied.
 * Curate provider JWKS into the documented public-key profile before loading. */
YDOIDC *yd_oidc_new_id(const YDOIDCOptions *options,
    const unsigned char *jwks, size_t jwks_length, char *error, size_t error_length);
YDOIDCResult yd_oidc_verify_id(const YDOIDC *oidc, const char *jwt, size_t jwt_length,
    const char *expected_nonce, int64_t now_seconds, YDOIDCIdentity *out);
/* Caller supplies trusted Unix wall-clock seconds, 0..253402300799.
 * VALID authenticates claims/signature, NOT grants: parent checks scope flag
 * and maps exact issuer/subject/client to its own policy. No replay detection.
 * Malformed/invalid credentials return INVALID. Invalid arguments/time and
 * local allocation/provider/setup failures return ERROR. Both fail closed.
 * Every non-VALID result clears ALL output bytes. Inputs/output are disjoint.
 * Concurrent readers are supported; caller excludes destruction. */
YDOIDCResult yd_oidc_verify(const YDOIDC *oidc, const char *jwt, size_t jwt_length,
    int64_t now_seconds, YDOIDCIdentity *out);
/* NULL-safe. Exclude concurrent verification/free. */
void yd_oidc_free(YDOIDC *oidc);
#endif
