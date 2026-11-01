#ifndef YAMORA_DISK_HISTORY_H
#define YAMORA_DISK_HISTORY_H
#include "disk.h"
#include "disk_validation.h"

#define YD_HISTORY_COMMITS 128U
#define YD_HISTORY_BRANCHES 32U
#define YD_HISTORY_TOKEN 53U
typedef struct { uint64_t sequence, parent; YDDiskView view; uint64_t base; } YDHistoryCommit;
typedef struct { char name[129]; uint64_t head, base; } YDHistoryBranch;
typedef struct {
    unsigned char identity[16];
    uint64_t last;
    size_t count, branches;
    YDHistoryCommit commits[YD_HISTORY_COMMITS];
    YDHistoryBranch names[YD_HISTORY_BRANCHES];
} YDHistory;
/* Catalog is bounded and owns no handles. 1 present, 0 absent, -1 invalid. */
int yd_disk_history_load(YDDisk *, const YDDiskView *, YDHistory *, char *, size_t);
int yd_disk_history_tx_load(YDDiskTxn *, YDHistory *, char *, size_t);
bool yd_disk_history_start(YDDiskTxn *, char *, size_t);
int yd_disk_history_select(YDHistory *, const char *, YDHistoryCommit **);
bool yd_disk_history_store(YDDiskTxn *, const YDHistory *, char *, size_t);
/* Exact catalog record bytes for h (caller frees); NULL on bounds/allocation. */
unsigned char *yd_disk_history_encode(const YDHistory *, size_t *size);
/* Decode and shape-check the catalog record at offset against view: 1 or -1. */
int yd_disk_history_decode_at(YDDisk *, const YDDiskView *, uint64_t offset,
    YDHistory *, char *, size_t);
void yd_disk_history_token(const YDHistory *, uint64_t, char[YD_HISTORY_TOKEN]);
/* HTTP status: 200 resolved, 400 malformed, 404 unknown/future, 409 foreign or
 * unsupported, 410 evicted, 503 corrupt/unavailable. Uses only captured view. */
int yd_disk_history_resolve(YDDisk *, const YDDiskView *, const char *,
    YDDiskView *, char[YD_HISTORY_TOKEN], char *, size_t);
YDHistoryCommit *yd_disk_history_commit(YDHistory *, uint64_t);
YDHistoryBranch *yd_disk_history_branch(YDHistory *, const char *);
bool yd_disk_history_add(YDHistory *, const YDDiskView *, uint64_t,
    uint64_t *, char *, size_t);
/* Publication hook, serialized after log preparation, before durable header. */
bool yd_disk_history_publish(YDDiskTxn *, const YDDiskView *, char *, size_t);
bool yd_disk_history_validate(YDDisk *, const YDDiskView *, YDDiskValidation *, char *, size_t);

/* Copy callbacks relocate/compare CLEAN roots; catalog itself is handled here.
 * Callback must preserve exact source bytes and metadata and return an owned
 * destination root in the same transaction/file. No catalog recursion. */
typedef bool (*YDHistoryCopyRoot)(void *, const YDDiskView *, YDDiskView *, char *, size_t);
typedef bool (*YDHistorySameRoot)(void *, const YDDiskView *, const YDDiskView *, char *, size_t);
bool yd_disk_history_copy(YDDisk *, const YDDiskView *, YDDiskTxn *,
    YDHistoryCopyRoot, void *, char *, size_t);
bool yd_disk_history_same(YDDisk *, const YDDiskView *, YDDisk *, const YDDiskView *,
    YDHistorySameRoot, void *, char *, size_t);
/* Physical native-tree relocation for clean snapshots. Bounded tree cursors
 * and an on-disk private relocation map; no dataset-sized memory. */
bool yd_disk_history_root_copy(YDDisk *,const YDDiskView *,YDDiskTxn *,YDDiskView *,char *,size_t);
bool yd_disk_history_root_copy_mapped(YDDisk *,const YDDiskView *,YDDiskTxn *,YDDiskView *,
    YDDiskView *private_record_map,YDDiskValidation *,char *,size_t);
bool yd_disk_history_root_same(YDDisk *,const YDDiskView *,YDDisk *,const YDDiskView *,char *,size_t);
bool yd_disk_history_root_same_checked(YDDisk *,const YDDiskView *,YDDisk *,const YDDiskView *,
    YDDiskValidation *,char *,size_t);
#endif
