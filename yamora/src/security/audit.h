#ifndef YAMORA_SECURITY_AUDIT_H
#define YAMORA_SECURITY_AUDIT_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define YD_AUDIT_VERSION 1U
#define YD_AUDIT_RECORD_BYTES 1024U
#define YD_AUDIT_MAX_PENDING 64U
#define YD_AUDIT_MAX_SEGMENTS 16U
#define YD_AUDIT_MAX_RECORDS 8192U
#define YD_AUDIT_MAX_BYTES (128ULL * 1024ULL * 1024ULL)

typedef enum {
    YD_AUDIT_OK = 1, YD_AUDIT_REFUSED = 0, YD_AUDIT_BUSY = -1,
    YD_AUDIT_LIMIT = -2, YD_AUDIT_UNCERTAIN = -3,
    YD_AUDIT_CORRUPT = -4, YD_AUDIT_INCOMPLETE = -5,
    YD_AUDIT_ERROR = -6
} YDAuditResult;
typedef enum {
    YD_AUDIT_TRANSPORT_NONE, YD_AUDIT_HTTP, YD_AUDIT_BINARY,
    YD_AUDIT_CLI, YD_AUDIT_INTERNAL
} YDAuditTransport;
typedef enum {
    YD_AUDIT_AUTH_UNKNOWN, YD_AUDIT_ADMIN_READ, YD_AUDIT_ADMIN_WRITE,
    YD_AUDIT_STATIC, YD_AUDIT_CERTIFICATE, YD_AUDIT_OIDC, YD_AUDIT_LOCAL,
    YD_AUDIT_AWS, YD_AUDIT_LDAP, YD_AUDIT_KERBEROS
} YDAuditAuthentication;
typedef enum {
    YD_AUDIT_OPERATION_NONE, YD_AUDIT_READ_DOCUMENT, YD_AUDIT_LIST,
    YD_AUDIT_QUERY, YD_AUDIT_AGGREGATE, YD_AUDIT_SEARCH,
    YD_AUDIT_WRITE_DOCUMENT, YD_AUDIT_TRANSACTION, YD_AUDIT_INDEX_ADMIN,
    YD_AUDIT_REPLICATION_ADMIN, YD_AUDIT_STREAM, YD_AUDIT_TLS_RELOAD,
    YD_AUDIT_STARTUP, YD_AUDIT_SHUTDOWN, YD_AUDIT_ACCESS_REJECT,
    /* Runtime access management (--runtime-access). Each carries a subject;
     * verifiers that predate them reject these records and packets. */
    YD_AUDIT_ACCESS_ROLE_PUT, YD_AUDIT_ACCESS_ROLE_DELETE,
    YD_AUDIT_ACCESS_PRINCIPAL_PUT, YD_AUDIT_ACCESS_PRINCIPAL_ROTATE,
    YD_AUDIT_ACCESS_PRINCIPAL_DELETE
} YDAuditOperation;
#define YD_AUDIT_OPERATION_LAST YD_AUDIT_ACCESS_PRINCIPAL_DELETE
/* Exactly the operations that require a subject. */
#define YD_AUDIT_SUBJECT_OPERATION(op) \
    ((op) >= YD_AUDIT_ACCESS_ROLE_PUT && (op) <= YD_AUDIT_ACCESS_PRINCIPAL_DELETE)
typedef enum {
    YD_AUDIT_OUTCOME_NONE, YD_AUDIT_NOT_DISPATCHED,
    YD_AUDIT_RETURNED_SUCCESS, YD_AUDIT_RETURNED_FAILURE, YD_AUDIT_UNKNOWN
} YDAuditOutcome;
typedef struct {
    uint64_t segment_records, segments, bytes;
    uint32_t pending;
} YDAuditLimits;
typedef struct {
    const unsigned char *key; /* Borrowed exactly 32 bytes; never a pathname. */
    size_t key_length;
    unsigned char key_id[16]; /* Caller-supplied NONSECRET label, not a key hash. */
    YDAuditLimits limits;
} YDAuditConfig;
typedef struct {
    uint32_t version;
    unsigned char key_id[16], stream_id[16], segment_id[16];
    uint64_t segment, sequence;
    unsigned char mac[32];
} YDAuditHead;
typedef struct {
    uint64_t wall_ms; /* 0 means unknown; informational, not ordering authority. */
    uint32_t transport, authentication, operation;
    char actor[129]; /* Local mapped principal only; no credential/claim bytes. */
    /* Managed role or principal name for access-management operations only;
     * empty for every other operation. Never a credential or verifier. */
    char subject[129];
} YDAuditEvent;
typedef struct {
    uint64_t wall_ms, elapsed_us;
    uint32_t outcome, status; /* Status 0 means no response; otherwise 100..599. */
    bool has_revision;
    char revision[17];
} YDAuditCompletion;
typedef struct {
    unsigned char owner[16]; /* Process-local incarnation, not authorization. */
    uint64_t intent_sequence;
} YDAuditTicket;
typedef struct {
    YDAuditResult health;
    YDAuditHead acknowledged;
    uint64_t physical_bytes, segment_records, segments;
    uint32_t pending;
} YDAuditState;
typedef struct {
    YDAuditResult result;
    YDAuditHead prefix; /* Verified prefix only, never an acknowledged writer. */
    uint64_t verified_records, physical_bytes, segments;
    uint32_t pending;
    bool exact_anchor;
} YDAuditReport;
typedef struct YDAudit YDAudit;

/* INACTIVE storage API: no authentication, database, delivery or cut authority.
 * All inputs/outputs must be disjoint. Config/key/event inputs are borrowed only
 * during the call. Copies of the external key are cleansed on disposal.
 * Constructors require cancellation ALREADY DISABLED through adoption of every
 * non-NULL owner, including UNCERTAIN. All owner operations reject foreign PID
 * before inherited synchronization, state or descriptor access. No callbacks.
 * Methods mask deferred cancellation before their mutex through publication and
 * unlock. Caller owns whole-operation cleanup and joins operations before close;
 * asynchronous cancellation/nonlocal exits are unsupported. Tickets may transfer
 * between joined workers in the creator process, with exclusive use per ticket.
 * No descriptors escape and no API unlocks/converts the owned OFD exclusion. */
/* Private empty trusted directory; independent root OFD, O_EXCL segment create.
 * OK returns usable *out plus synchronized head. A mutating ATTEMPT that fails
 * returns UNCERTAIN with a poisoned NON-NULL *out and zero head: caller MUST
 * adopt/close it. This includes unknown O_EXCL acknowledgement with fd == -1.
 * Other failures clear both outputs. No automatic truncate/unlink/repair. */
YDAuditResult yd_audit_create_at(int directory, const YDAuditConfig *, YDAudit **out,
    YDAuditHead *head);
/* Independent shared exclusion, bounded complete namespace/semantic rescan.
 * Report may expose a verified prefix on error; it grants no writable owner.
 * Non-NULL protected anchor required. Never obtains it from these same files. */
YDAuditResult yd_audit_verify_at(int directory, const YDAuditConfig *,
    const YDAuditHead *expected_anchor, YDAuditReport *out);
/* Independent exclusive exclusion and fresh rescan. Exact final anchored head,
 * exact original limits, no pending intent, partial tail or incomplete rotation.
 * Even a valid tail ahead of the anchor refuses; no authority from observation.
 * Does not persist an external anchor or provide cross-system atomicity. */
YDAuditResult yd_audit_resume_at(int directory, const YDAuditConfig *,
    const YDAuditHead *expected_anchor, YDAudit **out);
/* Restricted recovery owner: requires a COMPLETE history ending at the exact
 * independently protected anchor. Pending intents alone may remain. No normal
 * begin/finish/rotation is admitted until every pending intent has been appended
 * as UNKNOWN by recovery_next. Never adopts a caller-supplied ticket or repairs
 * an unanchored/torn tail. Constructor cancellation contract is unchanged. */
YDAuditResult yd_audit_recover_at(int directory, const YDAuditConfig *,
    const YDAuditHead *expected_anchor, YDAudit **out);
/* Appends at most one UNKNOWN finish, preserving the authenticated intent's
 * event and using zero status/times/revision. changed=false means none remain.
 * The caller MUST publish each returned head in protected storage before the
 * next call or dispatch. Failed publication requires closing the owner. */
YDAuditResult yd_audit_recovery_next(YDAudit *, bool *changed, YDAuditHead *head);
YDAuditResult yd_audit_begin(YDAudit *, const YDAuditEvent *, YDAuditTicket *out,
    YDAuditHead *head);
/* Exact outstanding intent; copies its saved actor/auth/transport/operation.
 * Consumes the ticket only on success or uncertainty. Invalid input refuses
 * without consumption. An uncertain ticket can never finish again. */
YDAuditResult yd_audit_finish(YDAudit *, YDAuditTicket *, const YDAuditCompletion *,
    YDAuditHead *head);
/* No pending intents; pre-reserves seal + successor header. Both files and the
 * directory are synced/rebound before active-head publication. No auto retry. */
YDAuditResult yd_audit_rotate(YDAudit *, YDAuditHead *head);
/* OK means the state was copied, not that health is OK. */
YDAuditResult yd_audit_state(YDAudit *, YDAuditState *out);
/* Joined disposal, including poisoned factories. Foreign PID is a no-op. */
void yd_audit_close(YDAudit *);
#endif
