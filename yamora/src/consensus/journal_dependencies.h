#ifndef YAMORA_CONSENSUS_JOURNAL_DEPENDENCIES_H
#define YAMORA_CONSENSUS_JOURNAL_DEPENDENCIES_H
#include "raft_internal.h"
#include "snapshot_store_internal.h"
#include "../disk_internal.h"

typedef struct YDRaftJournalDependencies YDRaftJournalDependencies;
typedef enum {
    YD_RAFT_DEPENDENCY_INVALID_HEADER,
    YD_RAFT_DEPENDENCY_EMPTY,
    YD_RAFT_DEPENDENCY_KNOWN,
    YD_RAFT_DEPENDENCY_UNKNOWN
} YDRaftJournalDependencyState;
typedef struct {
    YDRaftJournalDependencyState state;
    YDDiskView view;
    /* Only KNOWN has metadata. snapshot.archive and application are distinct
     * typed edges: archive beneath the journal root, generation beneath the
     * document root (zero application means the original document root). */
    YDRaftMeta metadata;
    /* OK also means no archive edge for EMPTY/META1. UNKNOWN/invalid headers
     * have INVALID; a missing store cannot satisfy a known archive edge. */
    YDRaftArchiveResult archive_pin;
} YDRaftJournalDependency;
typedef struct {
    YDDiskRecoveryInfo physical;
    YDRaftJournalDependency slots[2];
    bool metadata_complete, archive_pins_complete;
} YDRaftJournalDependencyInfo;

/* Pure classification of one explicit saved native view. found is the native
 * key lookup result (-1/0/1); bytes/size are the bounded record for found == 1.
 * Absent metadata requires bytes == NULL and size == 0. Trusted identity supplies
 * cluster/node/voters only. Invalid inputs, unsupported profiles or malformed
 * metadata yield UNKNOWN with zero metadata. No header/graph/suffix validation,
 * I/O, allocation, locks or archive acquisition. A known snapshot edge remains
 * unpinned (INVALID); no-edge KNOWN and EMPTY return archive_pin == OK.
 * Logical saved views are not physical slots or current recovery decisions. */
YDRaftJournalDependency yd_raft_journal_dependency_decode(const YDDiskView *view,
    int found, const unsigned char *bytes, size_t size, const YDRaftMeta *identity);

/* ALWAYS consumes roots, including bad arguments/allocation failure. Identity
 * supplies trusted cluster/node/voters only. store is borrowed for this call,
 * nullable when unavailable; resulting archive references own their lifetimes.
 * Reads both saved physical views, at most 144 metadata bytes each. No suffix,
 * full graph/image/generation validation, fallback, writes or callbacks.
 * Malformed/unreadable metadata and absent/busy archives produce an owned
 * PARTIAL observation, not NULL; inspect completeness and individual states.
 * Complete means only this physical pair, NOT a runtime-wide census or cleanup
 * authority. Captures, images, retained/prepared files and name changes require
 * separate coherent coverage before any retention decision. */
YDRaftJournalDependencies *yd_raft_journal_dependencies_take_roots(
    YDDiskRecoveryRoots *roots, const YDRaftMeta *identity,
    const YDRaftSnapshotStore *store, char *error, size_t length);
/* Copies immutable results; clears output on invalid input. Calls may overlap;
 * join them before close. Saved edges/pins survive source/store/runtime close. */
bool yd_raft_journal_dependencies_info(const YDRaftJournalDependencies *dependencies,
    YDRaftJournalDependencyInfo *out);
void yd_raft_journal_dependencies_close(YDRaftJournalDependencies *dependencies);
#endif
