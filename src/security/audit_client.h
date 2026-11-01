#ifndef YAMORA_AUDIT_CLIENT_H
#define YAMORA_AUDIT_CLIENT_H
#include "audit.h"
#include <sys/types.h>
typedef struct YDAuditClient YDAuditClient;
typedef struct {
    unsigned char owner[16], handle[16];
    uint64_t sequence;
} YDAuditLease;
/* Monotonic milliseconds; zero is local clock failure. All deadlines are
 * absolute values in this clock. Each exchange also has a 2s upper bound.
 * Constructor requires cancellation ALREADY DISABLED through caller adoption,
 * just like the native sink constructors; it refuses otherwise.
 * Process must have distinct nonzero real/effective/saved UID from helper,
 * no capabilities and no-new-privileges. Constructor authenticates SO_PEERCRED
 * and HELLO before returning. NULL never permits database/listener startup. */
uint64_t yd_audit_clock_ms(void);
YDAuditClient *yd_audit_client_open(const char *absolute_socket, uid_t helper_uid,
    uint64_t deadline_ms);
/* Serializes exchanges. Event identity must be copied from locally mapped
 * authentication BEFORE this call. ACK permits one dispatch only. A timeout,
 * failed I/O or contradictory reply poisons the connection; never reconnect or
 * retry an admitted operation under a newly invented handle. Deadline expiry
 * after sending, including a late ACK, is UNCERTAIN and grants no dispatch.
 * Methods mask cancellation through publication of caller outputs. A pending
 * cancellation may arrive on restoration before return: install enclosing
 * operation cleanup BEFORE begin, or keep cancellation disabled through lease
 * adoption. Cleanup must finish the retained lease as NOT_DISPATCHED/UNKNOWN
 * using actual dispatch evidence. Never close a shared client for one job. */
YDAuditResult yd_audit_client_begin(YDAuditClient *, const YDAuditEvent *,
    uint64_t deadline_ms, YDAuditLease *out);
/* Report handler evidence, not a status-derived outcome. Finish failures after
 * dispatch mean uncertain audit/operation acknowledgement, never rollback.
 * Only this exact client can finish its leases, including detached jobs. */
YDAuditResult yd_audit_client_finish(YDAuditClient *, YDAuditLease *,
    const YDAuditCompletion *, uint64_t deadline_ms);
/* Caller excludes concurrent users. Disconnect lets healthy helper append
 * UNKNOWN for any remaining owned tickets. Foreign-PID close is a no-op. */
void yd_audit_client_close(YDAuditClient *);
/* Validate own OS custody; does not change credentials/capabilities. */
bool yd_audit_unprivileged_process(uid_t peer_uid);
#endif
