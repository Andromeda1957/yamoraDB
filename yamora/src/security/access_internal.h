#ifndef YAMORA_SECURITY_ACCESS_INTERNAL_H
#define YAMORA_SECURITY_ACCESS_INTERNAL_H
/* Private to the security layer: policy object layout shared by the static
 * loader (access.c) and the runtime administration glue (access_admin.c).
 * Never include from transport, storage or consensus code. */
#include "access.h"
#include "field_policy.h"
#include "oidc.h"

#define YD_ACCESS_ROLE_LIMIT 64U
#define YD_ACCESS_PRINCIPAL_LIMIT 64U
#define YD_ACCESS_GRANT_LIMIT 64U
typedef struct {
    char name[129], read[YD_ACCESS_GRANT_LIMIT][129], write[YD_ACCESS_GRANT_LIMIT][129];
    size_t reads, writes;
} YDAccessRole;
struct YDAccessPrincipal {
    char name[129];
    char *token;
    size_t length;
    uint64_t roles;
    unsigned char certificates[2][32];
    size_t certificate_count;
    char oidc_subject[256], oidc_client[256];
    YDFieldPolicy *fields;
    /* Runtime principals only: domain-separated SHA-256 verifiers. */
    unsigned char verifier[32], previous[32];
    int64_t previous_expires_at;
    bool runtime;
};
typedef struct YDAccessRuntime YDAccessRuntime;
struct YDAccess {
    YDAccessRole roles[YD_ACCESS_ROLE_LIMIT];
    struct YDAccessPrincipal principals[YD_ACCESS_PRINCIPAL_LIMIT];
    size_t role_count, principal_count;
    YDOIDC *oidc;
    /* Static policy: optional runtime registry (owned). */
    YDAccessRuntime *runtime;
    /* Runtime snapshot: immutable after publication, owned by its registry. */
    YDAccessRuntime *parent;
    size_t references;
    struct YDAccess *next;
};
#endif
