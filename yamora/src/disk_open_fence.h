#ifndef YAMORA_DISK_OPEN_FENCE_H
#define YAMORA_DISK_OPEN_FENCE_H
#include "disk.h"
#include <sys/stat.h>

#define YD_DISK_OPEN_FENCE_VERSION 1U
#define YD_DISK_OPEN_FENCE_PROTOCOL 1U
#define YD_DISK_OPEN_FENCE_OFFSET 64U
#define YD_DISK_OPEN_FENCE_SIZE 48U
#define YD_DISK_OPEN_SESSION_FILE ".yamora-retention-session"

typedef struct YDDiskOpening YDDiskOpening;
typedef struct {
    uint32_t version, producer_protocol;
    unsigned char incarnation[32]; /* SHA256 of all 256 exact birth bytes. */
} YDDiskOpenFence;
typedef struct {
    struct stat directory, native;
    YDDiskView selected;
    unsigned valid_slots;
    bool created_here, installed_here;
    YDDiskOpenFence fence;
} YDDiskOpeningInfo;
typedef enum {
    YD_DISK_OPEN_OWNER = 1,
    YD_DISK_OPEN_PRESERVE = 2
} YDDiskOpenMode;
/* Provider keeps context alive throughout construction. retain returns an owned
 * lease and its ORIGINAL session identity, never a fresh pathname adoption.
 * It clears *lease on failure. validate proves the real provider's exclusive
 * OFD WR lock, same exact session/root/native bindings and preserving service
 * policy. No operation exports, unlocks or converts its descriptor. Native's
 * independent GETLK check supplements this ownership proof. Native calls retain
 * exactly once per admitted origin using context. Its opaque lease may differ
 * from context: descendants never call retain/validate and never duplicate a
 * provider descriptor. release receives that same lease at actual last close,
 * outside native/lineage locks, with cancellation disabled and namespace still
 * excluded. release may run under an owned exclusive cut: it must not enter
 * shared gate admission or wait for the caller/other descendants. No cut authority. */
typedef struct {
    bool (*retain)(void *context, void **lease, struct stat *original_session,
        char *error, size_t length);
    bool (*validate)(void *lease, const YDDiskOpeningInfo *opening,
        const struct stat *original_session, char *error, size_t length);
    void (*release)(void *lease);
} YDDiskServiceOwnerOps;
typedef struct {
    YDDiskOpenFence expected;
    YDDiskOpenMode mode;
    YDDiskServiceOwnerOps owner_ops;
    void *owner_context;
} YDDiskOpenAdmission;
typedef bool (*YDDiskOpenGuard)(void *context, YDDiskOpening *opening,
    YDDiskOpenAdmission *admission, char *error, size_t length);
typedef bool (*YDDiskOpeningPrepare)(YDDisk *borrowed, int directory,
    void *context, char *error, size_t length);

/* Constructor lifetime: caller disables pthread cancellation BEFORE guarded_at
 * and keeps it disabled through adoption of any returned handle into its own
 * cleanup/lifetime mechanism. Guarded_at checks this before owned I/O, rejects
 * enabled callers and leaves state/type unchanged for compliant callers.
 * ALL callbacks (guard, prepare, owner operations) return normally: no
 * pthread_exit, longjmp, exceptions across C, or cancellation-state changes.
 * No automatic unwind is provided for violating this cooperative contract;
 * stack opening pointers and borrowed objects must never escape their callback.
 * Caller establishes its cleanup before reenabling cancellation after adoption. */
/* Guard-only, same PID/thread/lifetime, no recursive preparation. No ownership
 * transfer, close, native mutation, transaction, recovery or export is allowed.
 * Actual fresh generation-1 independent creation facts are retained. Supported
 * metadata preparation: gate+birth, install outside prepare, then ACTIVE.
 * Detected operation/preparation failures permanently refuse this opening,
 * preserving all bytes. Nonreturning callbacks have no automatic unwind. */
bool yd_disk_opening_prepare(YDDiskOpening *, YDDiskOpeningPrepare, void *context,
    char *error, size_t length);
/* Existing fenced profile-5 constructor only, before recovery/adoption. One
 * callback may update retention metadata while the original directory, native
 * identity/extent and exact physical pair remain unchanged. No native writes,
 * exports, transactions or recovery. Failure invalidates this opening forever.
 * Caller-disabled cancellation and ordinary constructor callback rules apply. */
bool yd_disk_opening_resume_prepare(YDDiskOpening *, YDDiskOpeningPrepare, void *,
    char *error, size_t length);
/* Exact live resume callback, PID/thread/opening/disk only; no I/O or locks.
 * Metadata capture uses this in addition to its gate/cut/birth requirements. */
bool yd_disk_opening_resume_active(const YDDiskOpening *, const YDDisk *);
bool yd_disk_opening_info(const YDDiskOpening *, YDDiskOpeningInfo *out);
/* Borrowed directory for metadata only; never close, retain or retarget it. */
int yd_disk_opening_directory(const YDDiskOpening *);
/* Fresh successful first prepare required; exact birth digest is caller-proven.
 * Both generation-1 slots are written, fsynced, reread and rebound. Installation
 * cannot be retried or reconstructed by reopening. Existing objects preserved. */
bool yd_disk_opening_install_fence(YDDiskOpening *, const unsigned char birth_sha256[32],
    char *error, size_t length);
/* Additive private profile-5 writer constructor. NULL guard preserves legacy
 * unfenced behavior only. Fenced opens need exact supported identity and OWNER
 * or preserving native exclusion. Fresh installation requires two successful
 * prepare calls in the order documented above and OWNER admission. All fenced
 * constructors own an independent root namespace EX flock until actual last
 * descendant close. Ordinary pins/nested pins, physical-root readers, lineage
 * sources and private snapshot readers share a checked native holder with the
 * immutable creator PID, fence and original inode. Producer pins retain their
 * existing shared gate admissions; observational snapshots never enter shared
 * admission or retain the provider. Holder references prove lifetime only.
 * Fenced resource constructors/binding require cancellation disabled through
 * caller adoption, as above. Close internally masks cancellation through all
 * descriptor/reference cleanup, then restores the caller state. Join operations
 * before close; asynchronous cancellation and nonreturning callbacks unsupported.
 * Fenced operations (including cached reads) reject a foreign PID before locks,
 * reference changes, I/O or provider callbacks. Foreign close is a no-op, with
 * no synchronization destruction: fork children must exit without using these
 * inherited resources. Checkpoint/copy/independent-path exports still refuse;
 * no runtime enrollment, CLEAN, fingerprint or retirement is enabled. */
YDDisk *yd_disk_open_guarded_at(int directory, bool initialize, size_t cache_bytes,
    uint64_t allocation_limit, YDDiskOpenGuard, void *context, char *error, size_t length);
YDDisk *yd_disk_open_guarded_budgeted_at(int directory, bool initialize, size_t cache_bytes,
    uint64_t allocation_limit, YDStorageBudget *, YDDiskOpenGuard, void *context,
    char *error, size_t length);
bool yd_disk_open_fence_info(const YDDisk *, YDDiskOpenFence *out);
/* Internal operation barrier: pending constructor use poisons the opening;
 * unqualified checkpoint/copy exports still refuse for fenced origins. */
bool yd_disk_open_fence_operation(YDDisk *, bool exporting);
#endif
