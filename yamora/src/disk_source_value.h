#ifndef YAMORA_DISK_SOURCE_VALUE_H
#define YAMORA_DISK_SOURCE_VALUE_H

#include "disk.h"

/* Validate the existing YMV1 acceptance profile without materializing a tree.
 * The caller owns the immutable checkpoint throughout this synchronous call.
 * Reads are <=32768 bytes; individual allocations are <=65536 bytes. Keys
 * retain bounded offset/hash metadata only, with exact rereads on collisions.
 * The absolute CLOCK_MONOTONIC deadline applies to reads and bounded work. */
bool yd_disk_source_value_validate(YDDiskCheckpoint *checkpoint, uint64_t encoded_offset,
    size_t encoded_length, size_t source_length, bool large, uint64_t monotonic_deadline,
    char *error, size_t error_length);

#endif
