#ifndef YAMORA_INDEX_TTL_RUNTIME_H
#define YAMORA_INDEX_TTL_RUNTIME_H
#include "consensus/cluster.h"
#include "disk_api.h"
#include "security/audit_dispatch.h"

/* One background expirer per serving writer. Exactly one backend is set:
 * a writable standalone API (optionally audited) or a replica-set member that
 * expires only while it is leader. Followers, replicas and read-only roots
 * never start one. Deletes use the ordinary durable write path with each
 * examined version's ETag, so they replicate, appear in change feeds and can
 * never remove a newer version. The clock is this process's wall clock. */
#define YD_TTL_INTERVAL_DEFAULT 60U
#define YD_TTL_INTERVAL_LIMIT 86400U
typedef struct {
    YDDiskAPI *api;
    YDAuditDispatcher *audit;
    YDRaftCluster *cluster;
    unsigned interval_seconds; /* 1..86400 */
    unsigned timeout_ms;       /* Cluster write and quorum deadline. */
} YDTTLConfig;
typedef struct YDTTLMonitor YDTTLMonitor;

YDTTLMonitor *yd_ttl_monitor_start(const YDTTLConfig *config);
/* Wakes and joins the expirer; status remains readable until free. */
void yd_ttl_monitor_stop(YDTTLMonitor *monitor);
void yd_ttl_monitor_free(YDTTLMonitor *monitor);
/* Aggregate counters only, never collection or document names. NULL monitor
 * reports an inactive expirer. Caller frees; NULL on allocation failure. */
char *yd_ttl_monitor_status(YDTTLMonitor *monitor, unsigned interval_seconds, size_t *size);
#endif
