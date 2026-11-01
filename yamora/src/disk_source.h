#ifndef YAMORA_DISK_SOURCE_H
#define YAMORA_DISK_SOURCE_H
#include "disk.h"

#define YD_DISK_SOURCE_CHUNK 32768U
typedef struct YDDiskSource YDDiskSource;
typedef struct {
    size_t length;
    uint64_t hash;
    YDDiskView view;
} YDDiskSourceInfo;
/* Capture and verify an exact native YAML representation without materializing
 * its source or decoded value. Owns the checkpoint/retention lease through
 * close and survives later publications or source-handle close. Both nested
 * and outer CRCs, metadata, lengths, source UTF-8 and the existing encoded-value
 * acceptance profile are checked before success. Key identity uses bounded
 * node-count metadata pages with exact rereads on hash collisions.
 * 1 found, 0 absent, -1 invalid/unavailable/deadline. deadline_ms is absolute
 * CLOCK_MONOTONIC; all I/O uses buffers of at most 32 KiB.
 * Caller disables pthread cancellation through capture and handle adoption. */
int yd_disk_source_open(YDDisk *disk, const char *collection, const char *document,
    uint64_t deadline_ms, YDDiskSource **out, char *error, size_t length);
/* Read exactly a caller-owned captured view of this native incarnation. The
 * checkpoint retains the immutable file after the caller releases its view. */
int yd_disk_source_open_at(YDDisk *disk, const YDDiskView *view,
    const char *collection, const char *document, uint64_t deadline_ms,
    YDDiskSource **out, char *error, size_t length);
bool yd_disk_source_info(const YDDiskSource *, YDDiskSourceInfo *);
/* Exact bounded range, no implicit cursor. Failure clears a valid buffer. */
bool yd_disk_source_read(const YDDiskSource *, size_t offset, void *buffer,
    size_t size, char *error, size_t length);
void yd_disk_source_close(YDDiskSource *);
#endif
