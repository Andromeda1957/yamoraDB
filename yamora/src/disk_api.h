#ifndef YAMORA_DISK_API_H
#define YAMORA_DISK_API_H
#include "disk_query.h"
#include <pthread.h>
struct YDDiskReplicaPending;
struct YDDiskIndexJobs;
typedef struct {
    YDDisk *disk;
    bool replica;
    struct YDDiskIndexJobs *index_jobs;
    pthread_mutex_t stage_lock;
    YDDiskTxn *stage;
    YDValue *stage_spec;
    struct YDDiskReplicaPending *follow;
    char session[48];
    uint64_t deadline, serial;
    bool preparing;
    YDDiskTxn *prepared;
} YDDiskAPI;
/* Internal evidence, never inferred from an HTTP status or exposed as wire
 * authority. UNKNOWN includes uncommitted preparation and uncertain durability. */
typedef enum {
    YD_DISK_OUTCOME_UNKNOWN = 0,
    YD_DISK_OUTCOME_NOT_DISPATCHED,
    YD_DISK_OUTCOME_RETURNED_SUCCESS,
    YD_DISK_OUTCOME_RETURNED_FAILURE
} YDDiskOutcome;
/* Called exactly once by an adopted standalone index worker at its actual
 * terminal decision, outside native/jobs locks and with cancellation disabled.
 * receipt is non-NULL only after an actual successful publication. It is
 * borrowed for this call. The callback releases its owned context and returns
 * whether terminal audit delivery is certain. It may read status, but must not
 * destroy the API/disk or submit/join its own worker. */
typedef bool (*YDDiskJobTerminal)(void *context, YDDiskOutcome outcome,
                                 const YDDiskView *receipt);
typedef struct {
    int status;
    char *body;
    size_t length;
    char revision[17], headers[512];
    /* Internal complete-page progress for continuous feed transport. */
    char resume_after[53];
    bool has_more;
    const char *content_type;
    YDDiskOutcome outcome;
    bool has_receipt;
    YDDiskView receipt;
} YDDiskReply;
bool yd_disk_api_init(YDDiskAPI *api, YDDisk *disk, bool replica);
void yd_disk_api_destroy(YDDiskAPI *api);
YDDiskReply yd_disk_error_reply(int status, const char *code);
void yd_disk_reply_free(YDDiskReply *reply);
YDDiskReply yd_disk_api_request(YDDiskAPI *api, const char *method, const char *target,
                                const unsigned char *body, size_t length, const char *if_match,
                                const char *if_none_match, bool gzip);
/* Additive standalone dispatch. The transport authenticates/authorizes before
 * this call, including replay. Policy mutations require a nonzero 16-byte ID
 * and a configured ADMIN credential; the old wrapper supplies NULL and cannot
 * perform them. No wire-controlled flag or scoped write grant confers ADMIN. */
YDDiskReply yd_disk_api_request_with_id(YDDiskAPI *api, const char *method, const char *target,
                                const unsigned char *body, size_t length, const char *if_match,
                                const char *if_none_match, bool gzip,
                                const unsigned char request_id[16]);
/* Only exact POST /v1/index-builds can adopt terminal/context. With a callback,
 * transferred is required; it is set false before validation, then true only
 * after successful worker creation, even if allocating its 202 reply fails.
 * Before transfer the enclosing dispatch owns context; afterwards the worker
 * does, independently of the reply/client lifetime. Completion can race return:
 * pass a heap-owned lease, never a caller stack frame. Other calls never invoke
 * terminal. A false callback yields job status unknown/error audit_uncertain,
 * retaining a committed receipt/revision rather than claiming rollback. */
YDDiskReply yd_disk_api_request_with_job(YDDiskAPI *api, const char *method, const char *target,
                                const unsigned char *body, size_t length, const char *if_match,
                                const char *if_none_match, bool gzip,
                                const unsigned char request_id[16],
                                YDDiskJobTerminal terminal, void *context, bool *transferred);
/* Stateless document/query/catalog/feed reads at a caller-owned immutable view.
 * Caller retains the disk/application for the entire call. Rejects mutations,
 * replication, index jobs and continuous streams; creates no API worker/state. */
YDDiskReply yd_disk_api_read_at(YDDisk *disk, const YDDiskView *view, const char *method,
                                const char *target, const unsigned char *body, size_t length,
                                const char *if_match, const char *if_none_match, bool gzip);
/* Internal serialized consensus preparation. Supported document/transaction/
 * catalog writes run the ordinary validators but leave publication to the
 * caller. A successful result owns an exclusive transaction, which must be
 * committed or aborted; no document changes are visible before that decision. */
YDDiskReply yd_disk_api_prepare(YDDisk *disk, const char *method, const char *target,
                                const unsigned char *body, size_t length, const char *if_match,
                                const char *if_none_match, YDDiskTxn **prepared);
/* Shared native transaction validation/application, without publication. */
YDDiskReply yd_disk_api_apply_transaction(YDDiskTxn *, const YDValue *, YDPolicyWork *);
#endif
