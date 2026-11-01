#ifndef YAMORA_SECURITY_ACCESS_H
#define YAMORA_SECURITY_ACCESS_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
typedef struct YDAccess YDAccess;
typedef struct YDAccessPrincipal YDAccessPrincipal;
/* Immutable policy; token bytes are loaded separately from private files.
 * v1 is unchanged. v2 adds roles + exactly one of token_file or
 * tls_client_sha256: 1..2 globally unique, quoted lowercase 64-hex DER pins.
 * v3 adds one pinned offline RS256 issuer and exact subject/client mappings.
 * v4 permits optional per-principal field_permissions (an array of native field
 * policy rules). Masks only narrow existing collection grants. Optional oidc
 * retains the exact v3 profile; legacy versions do not accept field masks. */
YDAccess *yd_access_load(const char *path, char *error, size_t length);
void yd_access_free(YDAccess *access);
bool yd_access_secure_equal(const char *left, size_t left_length, const char *right, size_t right_length);
char *yd_access_read_token(const char *path, size_t *token_length, char *error, size_t error_length);
/* Bounded private regular file, no symlinks, group writes, execution or public
 * access. Allows the systemd 0440 credential profile. Caller owns the buffer. */
char *yd_access_read_private(const char *path, size_t maximum, size_t *length);
bool yd_access_conflicts(const YDAccess *access, const char *token, size_t length);
/* Restricted credentials deny global endpoints except minimal authenticated
 * cluster leader discovery. Aggregation compiles its entire pipeline and
 * requires read grants on source and lookup collection before disk dispatch,
 * independently of empty input or filters. Schema-policy GET/HEAD require the
 * target collection's read grant; every policy mutation is denied to scoped
 * principals, even collection writers. The daemon's separately configured
 * administrative credential is checked before dispatch/replay, never inferred
 * from these grants. Status is 0/401/403. */
int yd_access_request(const YDAccess *access, const char *authorization, const char *method,
                       const char *target, const unsigned char *body, size_t length);
/* Authentication plus some write grant, before allocating a large body. */
bool yd_access_writer(const YDAccess *access, const char *authorization);
/* Static-token lookup only; recognized credentials remain terminal even when
 * their grants deny an operation. No JWT parsing or certificate fallback. */
const YDAccessPrincipal *yd_access_identify_token(const YDAccess *access,
                                                const char *token, size_t length);
/* Use only after an external adapter has verified and exactly mapped identity.
 * This grants no authority beyond the named immutable local policy principal. */
const YDAccessPrincipal *yd_access_identify_local(const YDAccess *access, const char *name);
bool yd_access_has_oidc(const YDAccess *access);
/* Offline verification and exact local identity mapping. 0/401/403/503;
 * clears *out except on success. Caller supplies current wall-clock seconds
 * and enforces HTTP/TLS prerequisites. Never unions external claim grants. */
int yd_access_authenticate_oidc(const YDAccess *access, const char *jwt, size_t length,
                              int64_t now_seconds, const YDAccessPrincipal **out);
/* The caller must enforce public mTLS prerequisites before serving a policy
 * containing certificate principals. No TLS configuration or credential
 * selection is performed here; bearer wrappers never try certificates. */
bool yd_access_has_certificate_principals(const YDAccess *access);
/* Trusted, verified inbound client evidence only, never wire-supplied hashes.
 * Returns NULL for absent/unmapped evidence. Handles/names borrow the immutable
 * policy and expire at yd_access_free; never free or retain them beyond it.
 * No certificate principal has administrative rights. */
const YDAccessPrincipal *yd_access_identify_certificate(const YDAccess *access,
                                                       const unsigned char leaf_sha256[32]);
const char *yd_access_principal_name(const YDAccess *access, const YDAccessPrincipal *principal);
/* Response context must be captured during credential selection and retained
 * through execution/replay. Before authentication, any configured mask requires
 * safe headers, including parse errors and anonymous health replies. */
bool yd_access_has_field_principals(const YDAccess *access);
bool yd_access_principal_masked(const YDAccess *access, const YDAccessPrincipal *principal);
/* Call before conditional HTTP/binary dispatch. Masked principals reject both
 * source-fingerprint and creation/existence preconditions. 0/401/403. */
int yd_access_principal_preconditions(const YDAccess *access,
                                    const YDAccessPrincipal *principal,
                                    bool has_if_match, bool has_if_none_match);
/* Same grants and full transaction/foreign-lookup checks as bearer wrappers.
 * NULL/foreign-policy handles return 401/false without dereferencing them.
 * Callers select exactly one credential; these functions never union grants. */
int yd_access_principal_request(const YDAccess *access, const YDAccessPrincipal *principal,
                                const char *method, const char *target,
                                const unsigned char *body, size_t length);
bool yd_access_principal_writer(const YDAccess *access, const YDAccessPrincipal *principal);

/* Runtime principals (opt-in, --runtime-access). The static policy owns one
 * registry of immutable snapshots compiled from the replicated access
 * document. Token lookup tries static credentials first, then compares a
 * domain-separated SHA-256 verifier with every runtime principal in constant
 * time. The authenticating thread pins the snapshot it used; handles from it
 * stay valid on that thread until its next runtime authentication or unpin.
 * Never pass a runtime handle to another thread: re-authenticate there.
 * Runtime principals never have certificate, OIDC or identity-provider
 * mappings and never gain administrative rights. */
struct YDAccessState;
YDAccess *yd_access_new_empty(void);
bool yd_access_runtime_enable(YDAccess *access);
bool yd_access_runtime_enabled(const YDAccess *access);
bool yd_access_runtime_verifier(const char *token, size_t length, unsigned char out[32]);
/* Compiles and atomically replaces the published runtime snapshot. Fails
 * closed (keeping the previous snapshot) on names or credentials that collide
 * with the static policy or on field rules that do not compile. */
bool yd_access_runtime_publish(YDAccess *access, const struct YDAccessState *state,
    char *error, size_t length);
bool yd_access_principal_runtime(const YDAccess *access, const YDAccessPrincipal *principal);
void yd_access_runtime_unpin(const YDAccess *access);
bool yd_access_static_name(const YDAccess *access, const char *name, bool role);
bool yd_access_static_token_matches(const YDAccess *access, const unsigned char verifier[32]);
#endif
