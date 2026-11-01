#ifndef YAMORA_CONSENSUS_APPLICATION_REFERENCE_H
#define YAMORA_CONSENSUS_APPLICATION_REFERENCE_H
#include "raft_internal.h"
#include "snapshot.h"
#include <sys/stat.h>

typedef struct YDRaftApplicationReference YDRaftApplicationReference;
typedef enum {
    YD_RAFT_APPLICATION_REFERENCE_OK = 1,
    YD_RAFT_APPLICATION_REFERENCE_BUSY = 0,
    YD_RAFT_APPLICATION_REFERENCE_INVALID = -1,
    YD_RAFT_APPLICATION_REFERENCE_IO = -2
} YDRaftApplicationReferenceResult;
typedef struct {
    bool named;
    unsigned layout;
    unsigned char application[32];
    YDRaftApplied origin;
    struct stat root, parent, directory, native, manifest;
} YDRaftApplicationReferenceInfo;
/* Linux cooperative exclusion: independent O_RDONLY native OFD, F_OFD_SETLK
 * F_RDLCK at byte 0, length 1. This is deliberately separate from native flock
 * ownership: a live EX-flocked writer can coexist with these references.
 * Every ticketed retirement takes F_WRLCK on that range through its independent
 * O_RDWR native OFD BEFORE custody/namespace mutation, retained across partial
 * failures. Neither acquisition nor lock availability grants cleanup authority.
 *
 * metadata supplies a decoded journal edge: trusted cluster/voters, application
 * generation A, snapshot boundary B. A and B may differ. Zero A names the
 * original document root. Nonzero A requires exact completed manifest/hash,
 * cluster/voters and origin <= B, matching term/hash at equal index. No graph,
 * native-root, suffix, checkpoint image or current-application validation.
 * No filesystem writes, directory creation, blocking locks or callbacks.
 * Outputs clear on failure; no input ownership transfers. Missing/untrusted,
 * substituted or initializing objects are INVALID; lock contention is BUSY.
 */
YDRaftApplicationReferenceResult yd_raft_application_reference_open(int document_root,
    const YDRaftMeta *metadata, YDRaftApplicationReference **out, char *error, size_t length);
/* Clone retains the acquired inode/OFD without reopening or adopting names.
 * Closing other clones/caller directories/controllers does not release it.
 * Never unlock a duplicated OFD; close only owned descriptors. */
YDRaftApplicationReferenceResult yd_raft_application_reference_clone(
    const YDRaftApplicationReference *, YDRaftApplicationReference **out, char *error, size_t length);
bool yd_raft_application_reference_info(const YDRaftApplicationReference *, YDRaftApplicationReferenceInfo *);
/* Recheck ORIGINAL names/inodes/trust, immutable manifest and initializing
 * absence. Native extent may advance through normal writes. No adoption.
 * This is cooperative lifetime protection, not atomic namespace exclusion.
 * Immutable operations may overlap; join users before close. */
bool yd_raft_application_reference_validate(const YDRaftApplicationReference *);
/* Owned duplicate of the exact pinned generation directory after validation.
 * Native OFD protection remains owned by the reference; keep it alive through
 * adopting the application writer. No pathname fallback or cleanup authority. */
int yd_raft_application_reference_directory(const YDRaftApplicationReference *);
void yd_raft_application_reference_close(YDRaftApplicationReference *);
#endif
