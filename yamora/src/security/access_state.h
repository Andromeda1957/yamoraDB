#ifndef YAMORA_SECURITY_ACCESS_STATE_H
#define YAMORA_SECURITY_ACCESS_STATE_H
#include "../value.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Runtime access state: one canonical JSON document, yamldb-system/
 * access-control, written only through the commands below. It stores names,
 * collection grants, optional field rules and SHA-256 token verifiers; it never
 * stores token bytes. Restricted principals can never read the reserved
 * collection. The administrative credentials can, so verifiers are treated as
 * sensitive but not as credentials. Pure functions: no I/O, clock or locks. */
#define YD_ACCESS_STATE_COLLECTION "yamldb-system"
#define YD_ACCESS_STATE_DOCUMENT "access-control"
#define YD_ACCESS_STATE_FORMAT "yamora-runtime-access-v1"
#define YD_ACCESS_STATE_ROLES 64U
#define YD_ACCESS_STATE_PRINCIPALS 64U
#define YD_ACCESS_STATE_GRANTS 64U
#define YD_ACCESS_STATE_BYTES (192U * 1024U)
#define YD_ACCESS_COMMAND_BYTES (64U * 1024U)
#define YD_ACCESS_OVERLAP_LIMIT 86400
/* Private replicated verb: never accepted from a public transport method. */
#define YD_ACCESS_COMMAND_METHOD "YACCESS"

typedef struct {
    char name[129];
    char read[YD_ACCESS_STATE_GRANTS][129], write[YD_ACCESS_STATE_GRANTS][129];
    size_t reads, writes;
} YDAccessStateRole;
typedef struct {
    char name[129];
    char roles[YD_ACCESS_STATE_ROLES][129];
    size_t role_count;
    unsigned char verifier[32], previous[32];
    int64_t previous_expires_at; /* 0: no previous verifier. */
    YDValue *fields;             /* Owned rule array or NULL. */
} YDAccessStatePrincipal;
typedef struct YDAccessState {
    uint64_t version;
    YDAccessStateRole roles[YD_ACCESS_STATE_ROLES];
    YDAccessStatePrincipal principals[YD_ACCESS_STATE_PRINCIPALS];
    size_t role_count, principal_count;
} YDAccessState;

typedef enum {
    YD_ACCESS_OP_NONE, YD_ACCESS_ROLE_PUT, YD_ACCESS_ROLE_DELETE,
    YD_ACCESS_PRINCIPAL_PUT, YD_ACCESS_PRINCIPAL_ROTATE, YD_ACCESS_PRINCIPAL_DELETE
} YDAccessOperation;

/* Exact mutation targets: PUT/DELETE /v1/access/roles/NAME, PUT/DELETE
 * /v1/access/principals/NAME and POST /v1/access/principals/NAME/rotate. NAME
 * uses the native name profile. Returns NONE for anything else. */
YDAccessOperation yd_access_state_target(const char *method, const char *target,
    char name[129]);

YDAccessState *yd_access_state_new(void);
/* Clears verifiers before release. NULL is a no-op. */
void yd_access_state_free(YDAccessState *state);
/* Strict canonical document parse: exact keys, limits, unique names and
 * verifiers, existing role references. Never returns a partial state. */
YDAccessState *yd_access_state_parse(const unsigned char *body, size_t length);
/* Canonical name-sorted JSON; NULL on allocation failure or over the bound. */
char *yd_access_state_encode(const YDAccessState *state, size_t *length);

typedef struct {
    int status;       /* 200/201 on success; 4xx on rejection. */
    const char *code; /* Static status word or error code. */
} YDAccessResult;
/* Deterministic read-modify-write of one internal command. The state changes
 * only on success. Commands carry verifiers and absolute expiry times, never
 * token bytes or wall-clock reads. */
YDAccessResult yd_access_state_apply(YDAccessState *state, YDAccessOperation operation,
    const char *name, const unsigned char *command, size_t length);
bool yd_access_state_verifier_hex(const char *text, unsigned char out[32]);
void yd_access_state_hex(const unsigned char bytes[32], char text[65]);
/* Field rules are compiled by the security layer; this profile check bounds
 * shape only (an array of at most 64 maps). */
bool yd_access_state_fields_shape(const YDValue *fields);
const YDAccessStateRole *yd_access_state_role(const YDAccessState *state, const char *name);
const YDAccessStatePrincipal *yd_access_state_principal(const YDAccessState *state,
    const char *name);

#endif
