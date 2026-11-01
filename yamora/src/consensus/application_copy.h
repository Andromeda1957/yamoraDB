#ifndef YAMORA_CONSENSUS_APPLICATION_COPY_H
#define YAMORA_CONSENSUS_APPLICATION_COPY_H
#include "application.h"
typedef struct YDRaftApplicationCapture YDRaftApplicationCapture;
/* Serialize image methods, including observations and close. Separately owned
 * immutable disk pins may be read concurrently and survive image close. */
typedef struct YDRaftApplicationImage YDRaftApplicationImage;
typedef struct {
    YDRaftCheckpoint checkpoint;
    YDDiskView source;
} YDRaftApplicationCopyInfo;
typedef enum {
    YD_RAFT_APPLICATION_SOURCE = 1,
    YD_RAFT_APPLICATION_COPY,
    YD_RAFT_APPLICATION_VERIFY
} YDRaftApplicationCopyPhase;
/* Per-key copy/comparison and nested native validation boundaries; total=0
 * means the key count is unknown. Validation repeats phase counters (SOURCE 0
 * for source, SOURCE 1 for the prior image, VERIFY 0 for the new graph).
 * Individual bounded records, tree traversals and syscalls are indivisible.
 * Copy progress may hold the private writer mutex. Integrating callbacks must
 * not call runtime/cluster methods, reenter the candidate or retain arguments. */
typedef bool (*YDRaftApplicationCopyProgress)(void *context, YDRaftApplicationCopyPhase phase,
                                              uint64_t done, uint64_t total);
/* Serialized with application calls. Owns one logical reader and exact metadata;
 * no application pointer escapes. Capture survives later writes and source close.
 * Join copy calls before closing the capture. Cache is 32 KiB..1 GiB.
 * Preserves caller cancellation state and disposes the completed capture
 * if pending deferred cancellation is delivered during ownership adoption. */
YDRaftApplicationCapture *yd_raft_application_capture(YDRaftApplication *application, size_t cache,
                                                      char *error, size_t length);
YDRaftApplicationCopyInfo yd_raft_application_capture_info(const YDRaftApplicationCapture *capture);
void yd_raft_application_capture_close(YDRaftApplicationCapture *capture);
/* Outside the application owner lock. Destination is a borrowed, empty, private
 * existing directory. Copies every reachable document, receipt, catalog/index
 * and retained change frame, relocating all record references with a temporary
 * native-tree map rather than an in-memory dataset. Source validation precedes
 * candidate creation; every created candidate retains its initialization fence
 * on success and failure. Owns directory/file locks and a read-only view. Keeps
 * a duplicate source descriptor through image close to prevent inode reuse;
 * its original file lock survives application/capture close too.
 * No source mutation, live selection, deletion, quorum or retention authority. */
YDRaftApplicationImage *yd_raft_application_copy(const YDRaftApplicationCapture *capture,
                                                 int directory, size_t cache,
                                                 YDRaftApplicationCopyProgress progress,
                                                 void *context, char *error, size_t length);
/* Same copy, with one immutable absolute destination file-extent cap installed
 * before header creation. Includes temporary relocation-map pages and all later
 * catch-up work. Finite limits are 8192..INT64_MAX; UNLIMITED is explicit.
 * Optional usage is output on success/failure, including abandoned reservations.
 * A failed copy still retains its initialization fence if creation began. */
YDRaftApplicationImage *yd_raft_application_copy_limited(const YDRaftApplicationCapture *capture,
    int directory, size_t cache, uint64_t limit, YDDiskAllocation *usage,
    YDRaftApplicationCopyProgress progress, void *context, char *error, size_t length);
/* Serialized like all image calls. Available even after a failed catch-up;
 * failure does not refund reservations. NULL returns zero. */
YDDiskAllocation yd_raft_application_image_allocation(const YDRaftApplicationImage *image);
YDRaftApplicationCopyInfo yd_raft_application_image_info(const YDRaftApplicationImage *image);
/* Borrowed read-only handle, valid through image close; grants no quorum proof. */
YDDisk *yd_raft_application_image_disk(const YDRaftApplicationImage *image);
/* Filesystem provenance only, serialized with image calls. While a successful
 * image is alive, prove the supplied directory/native/fence descriptors match
 * its exact directory, O_EXCL-created native file and retained O_EXCL fence.
 * Does not grant directory birth or selection/disposal authority. */
bool yd_raft_application_image_created_files(const YDRaftApplicationImage *image,
    int directory, int native, int fence);
/* Owned physical checkpoint of this private image, bound to its exact applied
 * metadata. Serialize with image calls; survives later catch-up/image close.
 * No archive, journal or selection authority. Output is zero on failure.
 * Preserves caller cancellation state; pending deferred cancellation closes
 * the completed checkpoint before ownership can escape. */
YDDiskCheckpoint *yd_raft_application_image_checkpoint(YDRaftApplicationImage *image,
    YDRaftCheckpoint *position, char *error, size_t length);
/* Serialized with application calls. Exact original inode, complete view and
 * applied metadata must still match. No quorum or publication authority. */
bool yd_raft_application_image_current(const YDRaftApplicationImage *image,
                                       YDRaftApplication *application);
/* Outside application ownership, on one exclusively owned private image. Only
 * monotonically later captures of the same inode/cluster are accepted. Reuse
 * unchanged records and retain old owned readers. A failed mutation attempt or
 * integrity failure permanently fences this image; files remain for diagnosis.
 * Invalid source or cancellation before mutation leaves the prior image usable,
 * including validation/comparison of an unchanged generation. */
bool yd_raft_application_catch_up(YDRaftApplicationImage *image,
                                  const YDRaftApplicationCapture *capture,
                                  YDRaftApplicationCopyProgress progress, void *context,
                                  char *error, size_t length);
void yd_raft_application_image_close(YDRaftApplicationImage *image);
#endif
