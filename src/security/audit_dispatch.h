#ifndef YAMORA_SECURITY_AUDIT_DISPATCH_H
#define YAMORA_SECURITY_AUDIT_DISPATCH_H
#include "audit_client.h"
#include "../disk_api.h"
typedef struct YDAuditDispatcher YDAuditDispatcher;
typedef struct YDAuditedOperation YDAuditedOperation;
/* Owns the one authenticated helper session and at most 64 outstanding local
 * operations. Callers keep cancellation disabled through operation adoption,
 * transfer and terminal completion. Close only after every worker/job joins.
 * An unacknowledged finish stops new dispatch; retained leases remain owned
 * until shutdown, when disconnect/restart reconciliation records UNKNOWN. */
YDAuditDispatcher *yd_audit_dispatcher_new(const char *socket, uid_t helper,
    uint64_t deadline);
YDAuditedOperation *yd_audit_dispatch_begin(YDAuditDispatcher *,
    const YDAuditEvent *, uint64_t deadline);
/* Consumes caller use of the operation on every result. Only explicit native
 * evidence may report success/failure or a publication receipt. False never
 * means rollback. A transferred job owns this pointer until its terminal call. */
bool yd_audit_dispatch_finish(YDAuditedOperation *, YDAuditOutcome outcome,
    unsigned status, const YDDiskView *actual_receipt);
bool yd_audit_dispatch_job_terminal(void *, YDDiskOutcome, const YDDiskView *);
void yd_audit_dispatcher_close(YDAuditDispatcher *);
#endif
