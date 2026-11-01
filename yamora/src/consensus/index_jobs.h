#ifndef YAMORA_CONSENSUS_INDEX_JOBS_H
#define YAMORA_CONSENSUS_INDEX_JOBS_H
#include "../disk_api.h"
#include "../disk_index_build.h"

/* Durable records live in the ordinary native consensus root; no thread or
 * staging pointer is a job's authority. Callers supply serialization, owned
 * disk lifetime, Raft commitment and fresh-majority reads. */
bool yd_raft_index_job_handles(const char *target);
YDDiskReply yd_raft_index_job_read(YDDisk *disk, const YDDiskView *view,
                                   const char *target);
/* POST root admits id=request ID; DELETE /id commits cancellation. PUBLISH
 * and FAIL /id are INTERNAL commands and must never pass the remote parser.
 * FAIL body is one fixed public error code. Successful mutations return an
 * UNCOMMITTED exclusive native transaction for application receipt/checkpoint.
 * PUBLISH deterministically rebuilds when no cached leader transaction exists. */
YDDiskReply yd_raft_index_job_prepare(YDDisk *disk, const unsigned char id[16],
    const char *method, const char *target, const unsigned char *body, size_t size,
    const char *match, const char *none, YDDiskTxn **prepared);
/* 1 running job, 0 none/terminal, -1 corrupt/unavailable. Explicit owned view. */
int yd_raft_index_job_pending(YDDisk *disk, const YDDiskView *view,
    unsigned char id[16], char *error, size_t length);
/* Scan/catch up off the writer lock. admission(true) precedes writer locking;
 * admission(false) releases it on retry/failure. On SUCCESS caller owns the
 * returned writer-locked transaction AND its successful admission until it
 * commits/aborts ON THE BUILD THREAD and then calls admission(false). A locked
 * transaction must never be consumed by another apply thread. It must check term/barrier
 * under that admission and propose only at prepared->base generation. */
YDDiskReply yd_raft_index_job_build(YDDisk *disk, const unsigned char id[16],
    YDIndexProgress progress, void *context, YDIndexAdmission admission,
    void *admission_context, YDDiskTxn **prepared, char *error, size_t length);
/* Complete record framing/identity validation for snapshot graph walkers.
 * Recognizes keys "\\0YRJ"+id (20 bytes), and latest pointer "\\0YRJ" (4).
 * The latter references the same full job record. No side effects. */
bool yd_raft_index_job_validate_record(const unsigned char *key, size_t key_size,
    const unsigned char *record, size_t size, const unsigned char cluster[16],
    uint64_t generation);
#endif
