#ifndef YAMORA_CONSENSUS_APPLICATION_ADMISSION_H
#define YAMORA_CONSENSUS_APPLICATION_ADMISSION_H
#include "snapshot.h"
#include <sys/types.h>
/* Maintenance admissions only, never a filesystem quota or deletion authority.
 * Every cap is finite; ordinary writes/checkpoints/transfers are independent.
 * Extents include abandoned pages. Reservations are not refunded on failure. */
#define YD_RAFT_APPLICATION_SHELLS 64u
typedef struct {
    uint64_t image_bytes, archive_bytes, restore_bytes;
    uint64_t maximum_work_bytes, maximum_retained_bytes;
    uint64_t minimum_free_bytes, minimum_saved_bytes;
} YDRaftApplicationLimits;
typedef struct {
    dev_t device;
    uint64_t retained_bytes, available_bytes, allocation_unit;
} YDRaftApplicationVolume;
typedef struct {
    YDRaftApplicationVolume documents, archives;
    uint64_t files;
    uint64_t source_bytes, replacement_bytes;
    bool complete;
} YDRaftApplicationSpace;
typedef enum {
    YD_RAFT_APPLICATION_ADMIT = 1,
    YD_RAFT_APPLICATION_ADMIT_INVALID,
    YD_RAFT_APPLICATION_ADMIT_UNKNOWN,
    YD_RAFT_APPLICATION_ADMIT_WORK,
    YD_RAFT_APPLICATION_ADMIT_RETAINED,
    YD_RAFT_APPLICATION_ADMIT_FREE,
    YD_RAFT_APPLICATION_ADMIT_SAVINGS
} YDRaftApplicationAdmission;
typedef struct {
    YDRaftApplicationAdmission result;
    uint64_t retained_bytes, reserved_bytes, peak_bytes;
} YDRaftApplicationReservation;
bool yd_raft_application_limits_valid(YDRaftApplicationLimits limits);
/* Read-only, descriptor-relative, bounded inventory of private production roots.
 * Documents contain only native/root marker and complete named generations;
 * archives contain only immutable manifest-bound snapshots. Unknown, incomplete,
 * linked or unstable objects reject admission and remain untouched. At most
 * 4096 entries total; no dataset/graph read or recursive unknown traversal.
 * workspace is -1 or the exact exclusively owned staging directory below the
 * archive root; it is excluded here and charged by its full image reservation.
 * source is the live native descriptor: exactly one counted native must match
 * its inode and sampled metadata. replacement is NULL before preparation, or
 * the completed archive/generation's 64-character lowercase manifest hash.
 * Roots must be different owned directories. Caller keeps all descriptors alive.
 * This is an observation: independent filesystem users can change free space. */
bool yd_raft_application_space(int documents, int archives, int workspace, int source,
    const char *replacement,
    const unsigned char cluster[16], unsigned voters, YDRaftApplicationSpace *space,
    char *error, size_t length);
/* Same inventory with an optional exact, EMPTY retained custody directory.
 * Integrating caller proves both directories through its live workspace owner
 * before and after inventory. No prefix exemption or restart reconstruction.
 * Custody is observed empty/stable and must differ from every other root. */
bool yd_raft_application_space_with_custody(int documents, int archives,
    int workspace, int custody, int source, const char *replacement,
    const unsigned char cluster[16], unsigned voters, YDRaftApplicationSpace *space,
    char *error, size_t length);
/* Additional live-proven EMPTY document-root/generation shells from completed
 * retirements. At most SHELLS distinct descriptors, all observed exactly once;
 * caller proves capabilities before and after inventory. No name exemptions. */
bool yd_raft_application_space_with_shells(int documents, int archives,
    int workspace, int custody, const int *shells, size_t shell_count, int source,
    const char *replacement, const unsigned char cluster[16], unsigned voters,
    YDRaftApplicationSpace *space, char *error, size_t length);
/* Fixed-slot variant. Exact live-created slot descriptors may be empty or hold
 * one complete native/manifest pair; identity comes from the marker, never the
 * slot's basename. retirement_custody is -1 or the owner's exact EMPTY reusable
 * document-root custody. Unknown siblings reject and remain fully preserved.
 * Caller proves the slots owner immediately before and after this inventory. */
bool yd_raft_application_space_with_slots(int documents, int archives,
    int workspace, int workspace_custody, const int *slots, size_t slot_count,
    int retirement_custody, int source, const char *replacement,
    const unsigned char cluster[16], unsigned voters, YDRaftApplicationSpace *space,
    char *error, size_t length);
/* Incoming native admission uses the same complete document inventory, without
 * granting exemptions for an independently owned compactor's archive workspace.
 * Archive bytes/failures stay charged by the separate ingress reservation.
 * Caller validates the live slot ledger before and after. No mutation. */
bool yd_raft_application_documents_with_slots(int documents, const int *slots, size_t slot_count,
    int retirement_custody, int source, const unsigned char cluster[16], unsigned voters,
    YDRaftApplicationSpace *space, char *error, size_t length);
/* Preserving incoming service after restart. Observe complete fixed slots,
 * complete hash generations and empty retirement shells without adopting them.
 * Unknown, partial, linked or changed objects still refuse new work. This is
 * accounting only: it returns no slot, custody or retirement capability. */
bool yd_raft_application_documents_preserving(int documents, int source,
    const unsigned char cluster[16], unsigned voters, YDRaftApplicationSpace *space,
    char *error, size_t length);
/* Same document inventory when a serialized noncreating runtime lookup found
 * no archive directory. archive_volume samples its trusted journal filesystem;
 * no workspace or replacement can exist in this state. Creates nothing. */
bool yd_raft_application_space_empty_archives(int documents, int source,
    YDRaftApplicationVolume archive_volume, const unsigned char cluster[16], unsigned voters,
    YDRaftApplicationSpace *space, char *error, size_t length);
/* Simultaneously reserves image (archive filesystem), archive and restored
 * native+manifest (document filesystem), even when artifacts might be reused.
 * Existing files remain charged until actually removed, including the source.
 * Same-device reservations share one available-space check. No speculative
 * retirement credit, and no refund for failed work. */
/* Computes a conservative plan, not a reservation token. The integrating owner
 * serializes its maintenance attempts through reconciliation/retirement. File
 * contents/allocation are charged; filesystem directory/inode metadata and
 * unrelated producers require a later shared space policy. */
YDRaftApplicationReservation yd_raft_application_reserve(YDRaftApplicationSpace space,
    YDRaftApplicationLimits limits);
/* Final serialized decision: recheck the original native descriptor after
 * prepared writes drain. Savings include the retained archive AND new native
 * and marker; private scratch is temporary and never counted as reclaimed.
 * Inventory must have counted the exact source inode once. replacement_bytes
 * comes from the actual inventoried archive/native/marker, including allocation
 * above rounded extents. Estimates alone cannot authorize final savings. */
YDRaftApplicationAdmission yd_raft_application_savings(int source, uint64_t image_end,
    YDRaftApplicationSpace space, YDRaftApplicationLimits limits,
    uint64_t *source_bytes, uint64_t *saved_bytes);
#endif
