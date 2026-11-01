#ifndef YAMORA_INDEX_TTL_H
#define YAMORA_INDEX_TTL_H
#include "disk_documents.h"

/* TTL indexes are ordinary single-field native indexes whose definition also
 * carries expire_after_seconds (0..2147483647). A document expires once
 * time(field) + expire_after_seconds <= now, where now is the expiring
 * writer's wall clock in whole UTC seconds. Only these values have a time:
 *   - integer or finite float epoch seconds in -62167219200..253402300799
 *     (0000-01-01T00:00:00Z..9999-12-31T23:59:59Z; a fraction rounds up to
 *     the next whole second);
 *   - "YYYY-MM-DD" (midnight UTC);
 *   - "YYYY-MM-DDTHH:MM:SS[.fraction]Z" or the same ending in "+00:00", with an
 *     uppercase T, 1..9 fraction digits (rounded up) and no leap second.
 * Missing fields, arrays, maps, other strings, offsets other than +00:00 and
 * every other type never expire. */
#define YD_TTL_EXPIRE_LIMIT INT64_C(2147483647)
#define YD_TTL_TIME_LIMIT INT64_C(253402300799)
#define YD_TTL_BATCH_LIMIT 128U

/* 1 with seconds when the value has a TTL time, otherwise 0. */
int yd_ttl_time(const YDValue *value, int64_t *seconds);

typedef struct {
    char collection[YAMLDB_NAME_LIMIT + 1], id[YAMLDB_NAME_LIMIT + 1];
    uint64_t hash; /* Source hash of the examined version: its ETag. */
} YDTTLCandidate;

/* Resumable position across collection calls and passes. Zero-initialize. A
 * missing or changed catalog entry restarts at the first TTL index. */
typedef struct {
    char collection[YAMLDB_NAME_LIMIT + 1], name[YAMLDB_NAME_LIMIT + 1];
    unsigned range; /* 0 numeric values, 1 string values. */
    unsigned char key[YD_DISK_KEY_LIMIT];
    size_t key_size; /* 0 starts the range; otherwise resume after key. */
} YDTTLCursor;

/* Collect at most capacity (<= 128) distinct due documents from one immutable
 * view, examining at most budget index entries. Returns 1 when it stopped on
 * capacity or budget (more may remain), 0 when it reached the end of every TTL
 * index (the cursor wraps to the start), -1 on error. examined is incremented
 * by the entries read. The caller deletes candidates only with their ETag. */
int yd_ttl_collect(YDDisk *disk, const YDDiskView *view, int64_t now, YDTTLCursor *cursor,
                   YDTTLCandidate *candidates, size_t capacity, size_t *count, size_t budget,
                   uint64_t *examined, char *error, size_t length);
/* True when the view's catalog has at least one TTL index. -1 on error. */
int yd_ttl_present(YDDisk *disk, const YDDiskView *view, char *error, size_t length);
/* Exact {"operations":[{collection,document,delete:true,etag}]} request body;
 * NULL on allocation failure. Caller frees. */
char *yd_ttl_transaction(const YDTTLCandidate *candidates, size_t count, size_t *size);
#endif
