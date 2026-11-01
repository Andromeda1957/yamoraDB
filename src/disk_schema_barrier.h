#ifndef YAMORA_DISK_SCHEMA_BARRIER_H
#define YAMORA_DISK_SCHEMA_BARRIER_H
#include "disk.h"

#define YD_SCHEMA_BARRIER_OFFSET 112U
#define YD_SCHEMA_BARRIER_SIZE 16U
#define YD_SCHEMA_BARRIER_VERSION 1U
#define YD_SCHEMA_BARRIER_PROTOCOL 1U
#define YD_SCHEMA_BARRIER_MARKER ".yamora-schema-preparing"

typedef enum {
    YD_SCHEMA_BARRIER_OK,
    YD_SCHEMA_BARRIER_INVALID,
    YD_SCHEMA_BARRIER_UNSUPPORTED,
    YD_SCHEMA_BARRIER_BUSY,
    YD_SCHEMA_BARRIER_LIMIT,
    YD_SCHEMA_BARRIER_IO
} YDSchemaBarrierResult;
typedef struct {
    bool valid[2];
    YDDiskView views[2];
    unsigned char retention[48];
    uint32_t version, required_protocol;
} YDSchemaBarrierPair;
typedef struct {
    uint64_t physical_bytes;
    YDSchemaBarrierPair pair;
} YDSchemaBarrierPrepared;

/* Pure, fixed-size inspection of TWO completely read physical pages. A failed
 * or incomplete read MUST refuse before calling this function. Never selects a
 * root or manufactures a view. Feature-free legacy pairs preserve per-slot
 * validity/fallback; any extension evidence requires two valid compatible
 * profile-5 or profile-7 headers. Recognizes retention-only, schema-only and
 * both. Raw profile-7 magic is evidence even with a damaged CRC or marker.
 * Success conveys recognition only: ordinary constructors refuse schema;
 * explicit schema constructors require operational profile 7, protocol 1.
 * out is zeroed on failure; arguments must not overlap.
 * Immutable inputs may be inspected concurrently with independent outputs. */
YDSchemaBarrierResult yd_disk_schema_inspect(
    const unsigned char pages[2][YD_DISK_PAGE], uint64_t physical_bytes,
    YDSchemaBarrierPair *out, char *error, size_t error_size);

/* Private OFFLINE candidate, never activation/publication or copy authority for
 * retention origins. Borrow distinct trusted directory descriptors; source
 * contains an unfenced profile-5 native file with TWO valid physical headers.
 * Destination is empty, owned by euid, mode 0700. Owned regular files are 0600,
 * single-link; all opens are relative and no-follow. Source/native EX locks and
 * namespace identity checks exclude cooperative producers through verification.
 * Caller already disabled pthread cancellation through cleanup. No descriptor,
 * YDDisk, callback or ownership authority escapes; borrowed descriptors survive.
 *
 * maximum_bytes bounds the entire physical extent, including unreachable bytes
 * and an unaligned tail. Shared remaining_work is never refilled/refunded:
 * before each I/O request charge requested bytes; before copying/comparing/CRC
 * charge processed bytes; before each metadata/directory operation charge one.
 * Includes failed attempts and finalization: reserve each close BEFORE acquiring
 * its descriptor, so budget exhaustion cannot prevent cleanup. Fixed inspection
 * reserves four processing units per header byte (scan/CRC/decode/copy upper
 * bound). Caller serializes counter access. Fixed buffers, no extent-
 * sized allocation. No retries/resume/adoption of existing candidate files.
 *
 * O_EXCL invalid marker and native file remain on success AND failure. Both
 * schema markers are durable in invalid headers before any legacy prefix is
 * installed. Exact full-extent reread, file/directory fsync, rebinding and
 * verified close precede OK. out is zeroed on failure; partial files are NEVER
 * removed. Caller owns their subsequent preservation, not automatic cleanup. */
YDSchemaBarrierResult yd_disk_schema_prepare_at(
    int source_directory, int candidate_directory, uint64_t maximum_bytes,
    uint64_t *remaining_work, YDSchemaBarrierPrepared *out,
    char *error, size_t error_size);
#endif
