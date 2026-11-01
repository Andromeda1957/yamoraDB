#ifndef YAMORA_DISK_COMPACT_H
#define YAMORA_DISK_COMPACT_H
#include "disk.h"
#include <pthread.h>
#include <stdatomic.h>

/* Online space reclamation for a private standalone native writer (formats 5,
 * 7 and 8 without the cluster capability). Reads and writes continue while a
 * private candidate file in ROOT/.yamora-compact-<hex>/ receives a physical,
 * memoized copy of every reachable tree page and record (exact bytes, keys,
 * revisions, counters, change feed, retained branch roots). Writers pause only
 * to copy the final bounded delta; the candidate is committed at the SAME
 * generation and atomically exchanged with ROOT/.yamora-disk. ROOT/.yamora-disk
 * is authoritative after any crash; yd_disk_compact_recover removes leftovers.
 * Views captured before the exchange keep reading the superseded file during a
 * grace period (and while their cursors stay open), then fail closed (ESTALE). */
#define YD_COMPACT_STAGE_PREFIX ".yamora-compact-"
typedef struct {
    bool automatic;          /* background policy enabled */
    uint64_t min_bytes;      /* automatic: physical file at least this large */
    unsigned growth_percent; /* automatic: file >= baseline * percent / 100 */
    unsigned interval_ms;    /* automatic policy check interval */
    unsigned drain_ms;       /* bounded wait for in-flight transactions */
    unsigned pause_ms;       /* bounded final copy while writers wait */
    unsigned rounds;         /* catch-up rounds before the final pause */
    uint64_t final_items;    /* converge once a round copies at most this many */
    uint64_t grace_ms;       /* superseded file kept for captured views */
    size_t cache_bytes;      /* each of candidate, map and source pin caches */
} YDCompactPolicy;
YDCompactPolicy yd_compact_policy_defaults(void);
typedef enum {
    YD_COMPACT_IDLE, YD_COMPACT_RUNNING, YD_COMPACT_SUCCEEDED, YD_COMPACT_FAILED,
    YD_COMPACT_CANCELLED, YD_COMPACT_BUSY
} YDCompactState;
typedef struct {
    YDCompactState state;
    char phase[24];
    bool automatic;
    uint64_t runs, succeeded, failed, cancelled, busy;
    uint64_t rounds, pages, records, bytes_copied, pause_attempts, pause_ms;
    uint64_t size_before, size_after, reclaimed_bytes, total_reclaimed_bytes;
    uint64_t generation, started_unix, finished_unix;
    size_t retired_files;
    char error[160];
} YDCompactStatus;
const char *yd_compact_state_name(YDCompactState);
/* Shared by a run and its observers; lock guards status. */
typedef struct {
    atomic_bool cancel;
    pthread_mutex_t lock;
    YDCompactStatus status;
} YDCompactControl;
bool yd_compact_control_init(YDCompactControl *);
void yd_compact_control_destroy(YDCompactControl *);
/* Synchronous run on the caller thread (pthread cancellation disabled inside).
 * root is the directory holding disk's .yamora-disk. 1 compacted, 0 busy
 * (transactions never drained; nothing changed), -1 refused, failed or
 * cancelled (stage removed; the original file stays authoritative). */
int yd_disk_compact_online(YDDisk *disk, int root, const YDCompactPolicy *,
    YDCompactControl *, char *error, size_t length);
/* Startup recovery before opening ROOT writable: removes crash-leftover stages
 * that contain only this module's private files. Unexpected content, foreign
 * ownership, an in-use stage or an invalid root native file refuse (-1) and
 * preserve everything. Otherwise returns the number of stages removed. */
int yd_disk_compact_recover(int root, char *error, size_t length);

/* Background owner: policy checks, operator requests, retired-file collection.
 * The disk must outlive yd_compactor_free. */
typedef struct YDCompactor YDCompactor;
YDCompactor *yd_compactor_new(YDDisk *, const char *root, const YDCompactPolicy *,
    char *error, size_t length);
/* 1 started, 0 already running, -1 unsupported for this handle. */
int yd_compactor_start(YDCompactor *, char *error, size_t length);
/* True when a running compaction was asked to stop. */
bool yd_compactor_cancel(YDCompactor *);
void yd_compactor_status(YDCompactor *, YDCompactStatus *out);
bool yd_compactor_supported(YDCompactor *);
/* Physical size of the handle's current native file (0 when unknown). */
uint64_t yd_disk_file_bytes(YDDisk *);
/* Re-checks support after an in-place format upgrade of the served handle. */
void yd_compactor_refresh(YDCompactor *);
/* Cancels a run, joins the worker and retires superseded files. */
void yd_compactor_free(YDCompactor *);

/* In-place format upgrade: formats 2, 3 and 4 become format 5 by rewriting
 * both superblocks after the complete root validates under the old and the new
 * format rules. Tree pages and records are byte-identical, so the upgrade is a
 * two-step header publication: either slot alone opens the same root, and a
 * crash between the steps resumes on the next run. 6, 7, 8 and fenced, schema
 * or invalid input are never modified. */
typedef struct {
    uint32_t from, to;
    uint64_t generation;
    bool upgraded, resumed;
} YDDiskUpgradeInfo;
/* Offline; the caller owns root exclusively. 1 upgraded, 0 already current,
 * -1 refused (file unchanged) or failed. */
int yd_disk_upgrade_root(int root, size_t cache_bytes, YDStorageBudget *,
    YDDiskUpgradeInfo *, char *error, size_t length);
/* Online for a private standalone 3/4 writer. 1 upgraded, 0 already current,
 * -2 busy (transactions did not drain), -1 refused or failed. */
int yd_disk_upgrade_live(YDDisk *, unsigned drain_ms, YDDiskUpgradeInfo *,
    char *error, size_t length);
#endif
