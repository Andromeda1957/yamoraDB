#ifndef YAMORA_DISK_REPLICA_H
#define YAMORA_DISK_REPLICA_H
#include "disk_api.h"
#include "disk_log.h"

typedef struct {
    char after[YD_LOG_TOKEN_SIZE];
    uint64_t revision;
} YDDiskReplicaPosition;
/* 1 initialized, 0 absent, -1 corrupt or diverged from the published root. */
int yd_disk_replica_position(YDDisk *disk, const YDDiskView *view, YDDiskReplicaPosition *position,
                             char *error, size_t length);
bool yd_disk_replica_checkpoint(YDDiskTxn *txn, const char *after, char *error, size_t length);
bool yd_disk_replica_token(const char *text);
/* Legacy replication has no receipt-aware policy protocol. Fail closed on
 * catalog presence (including empty/off catalogs), any raw YSP key, or read
 * failure. Check a captured source before export and destination before reset.
 * The transaction variant checks the actual private root before publication;
 * neither helper mutates state or treats profile 7 alone as policy presence. */
bool yd_disk_replica_policy_free(YDDisk *disk, const YDDiskView *view,
                                  char *error, size_t length);
bool yd_disk_replica_policy_free_tx(YDDiskTxn *txn, char *error, size_t length);
typedef enum {
    YD_REPLICA_POLICY_ERROR = -1, YD_REPLICA_POLICY_PRESENT = 0, YD_REPLICA_POLICY_FREE = 1
} YDDiskReplicaPolicyState;
/* Typed counterparts preserve error (503) versus unsupported state (409).
 * Presence deliberately does not decode metadata or transfer any bytes. */
YDDiskReplicaPolicyState yd_disk_replica_policy_state(YDDisk *disk, const YDDiskView *view,
                                                       char *error, size_t length);
YDDiskReplicaPolicyState yd_disk_replica_policy_state_tx(YDDiskTxn *txn,
                                                          char *error, size_t length);
YDDiskReply yd_disk_replica_status(YDDiskAPI *api);
/* Called with stage_lock held, after lease expiry has been checked. */
YDDiskReply yd_disk_replica_follow(YDDiskAPI *api, const char *target, const YDValue *spec);
void yd_disk_replica_abort(YDDiskAPI *api);
#endif
