#ifndef YAMORA_CONSENSUS_BACKUP_H
#define YAMORA_CONSENSUS_BACKUP_H
#include "snapshot.h"

typedef struct YDRaftBackup YDRaftBackup;
/* PRIVATE controller bridge. Caller holds application AND core serialization,
 * excludes prepared/in-flight writes and snapshot installation, and drains the
 * application through core commitment first. No quorum proof is created here.
 * Short capture pins logical journal/application roots and required archives;
 * hashing, complete validation and copying happen only in write(), outside the
 * owner locks. No borrowed core/application pointer escapes. configuration is
 * the persisted CHECKPOINT membership word (r->configuration_base), not masks
 * after replaying suffix transitions; zero denotes the legacy fixed catalog.
 * The controller must obtain a fresh majority before invoking this factory.
 * A fenced journal requires caller-disabled cancellation through capture and
 * returned-handle adoption; the public cluster bridge owns this. */
YDRaftBackup *yd_raft_backup_capture(YDRaft *raft, YDRaftApplication *application,
    uint32_t configuration, size_t cache, char *error, size_t length);
/* Exclusively owned capture, reusable for separate destinations; close after
 * joining writers. Owns every pin and survives controller/runtime shutdown.
 * destination must already exist, be empty, private, and owned by this uid.
 * Durable manifest is published LAST. Failure preserves fenced partial work;
 * retry in a fresh empty directory. No live journal/application modification.
 * Buffers are <=1 MiB plus one bounded native journal record. Progress may
 * cancel between records/chunks and must return normally, without reentry. */
bool yd_raft_backup_write(YDRaftBackup *backup, const char *destination,
    YDRaftSnapshotProgress progress, void *context, char *error, size_t length);
void yd_raft_backup_close(YDRaftBackup *backup);
/* Offline restore into TWO distinct existing empty private roots. Expected
 * cluster/node/catalog identity is mandatory; no identity rewrite or node clone.
 * Verifies manifest, hashes, native journal and complete application/receipts
 * before removing either durable initialization fence. Both roots retain a
 * shared pairing marker, checked by verify_pair(). Failure preserves partial
 * roots fenced; use fresh roots to retry. No overwriting or automatic deletion.
 * A restored node retains its original persisted membership/removal state; the
 * ordinary runtime must still enforce quorum/topology admission. This API never
 * authorizes starting a restored node beside the original live node. */
bool yd_raft_backup_restore(const char *source, const char *documents,
    const char *journal, const unsigned char cluster[16], unsigned node,
    unsigned voters, size_t cache, YDRaftSnapshotProgress progress,
    void *context, char *error, size_t length);
/* Startup guard for restored roots: absent on BOTH accepts legacy roots;
 * one missing, invalid, or unequal marker rejects. Markers bind the original
 * bundle and identities, not subsequent generations. Never creates files. */
bool yd_raft_backup_verify_pair(int documents, int journal,
    const unsigned char cluster[16], unsigned node, unsigned voters,
    char *error, size_t length);
#endif
