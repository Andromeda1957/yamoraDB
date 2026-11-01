#ifndef YAMORA_DISK_AGGREGATE_H
#define YAMORA_DISK_AGGREGATE_H
#include "disk_documents.h"
#include "aggregate.h"
/* Uses the caller's exact immutable disk/view for both collections. HTTP
 * callers must pass yd_access_request first (generic admin access remains in
 * the daemon); this internal reader has no principal and grants no authority. */
char *yd_disk_aggregate(YDDisk *disk, const YDDiskView *view, const char *collection,
                        const YDValue *spec, size_t *size, char *error, size_t length);
char *yd_disk_aggregate_controlled(YDDisk *disk, const YDDiskView *view, const char *collection,
    const YDValue *spec, const YDQueryControl *control, size_t *size, char *error, size_t length);
#endif
