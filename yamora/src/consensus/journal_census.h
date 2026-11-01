#ifndef YAMORA_CONSENSUS_JOURNAL_CENSUS_H
#define YAMORA_CONSENSUS_JOURNAL_CENSUS_H
#include "journal_dependencies.h"
#include "journal_namespace.h"
#include "journal_scope.h"

#define YD_RAFT_CENSUS_SOURCES 32U
#define YD_RAFT_CENSUS_ROOTS 64U
#define YD_RAFT_CENSUS_CACHE (1024U * 1024U)
typedef struct YDRaftJournalCensus YDRaftJournalCensus;
typedef bool (*YDRaftJournalCensusProgress)(void *context);
enum {
    YD_RAFT_CENSUS_ARGUMENT = 1U,
    YD_RAFT_CENSUS_NATIVE = 2U,
    YD_RAFT_CENSUS_SCOPE = 4U,
    YD_RAFT_CENSUS_NAMESPACE = 8U,
    YD_RAFT_CENSUS_UNOWNED = 16U,
    YD_RAFT_CENSUS_LIMIT = 32U,
    YD_RAFT_CENSUS_IO = 64U,
    YD_RAFT_CENSUS_BUSY = 128U,
    YD_RAFT_CENSUS_METADATA = 256U,
    YD_RAFT_CENSUS_ARCHIVE = 512U,
    YD_RAFT_CENSUS_CHANGED = 1024U,
    YD_RAFT_CENSUS_CANCELLED = 2048U
};
typedef struct {
    bool coverage_complete, metadata_complete, archive_pins_complete;
    unsigned reasons, native_reasons, scope_reasons, namespace_reasons;
    /* Native counters bracket its original physical capture. Final validation
     * rechecks that original revision after ALL metadata/archive I/O. Scope
     * counts are two diagnostic endpoints, never an exclusion/atomic sample. */
    uint64_t native_revision, native_revision_after, native_active, native_active_after;
    uint64_t scope_revision, scope_revision_after, scope_active, scope_active_after;
    size_t scope_count, scope_count_after;
    bool native_validated, scope_validated, namespace_validated;
    size_t source_count, root_count, producer_count, binding_count, namespace_entries;
    size_t cache_reserved; /* Includes every retained/temporary native reader. */
    struct stat root;
    YDRaftMeta identity; /* Only copied cluster/node/voters are trusted inputs. */
} YDRaftJournalCensusInfo;
typedef struct {
    uint64_t native_id; /* Zero for an independent diagnostic/current OFD. */
    dev_t device;
    ino_t inode;
    bool independent, writer_alive, physical_known, physical_final;
    YDDiskObserveResult observation;
    YDDiskRecoveryInfo physical;
} YDRaftJournalCensusSource;
typedef struct {
    size_t source_index;
    unsigned physical_slots; /* Bit i means actual physical header slot i. */
    uint64_t producers; /* Bit i associates copied producer entry i. */
    YDRaftJournalDependency dependency;
} YDRaftJournalCensusRoot;
typedef struct {
    YDRaftJournalNamespaceKind kind;
    size_t depth, candidate_index;
    char path[YD_RAFT_NAMESPACE_DEPTH][YD_RAFT_NAMESPACE_COMPONENT];
    char component[YD_RAFT_NAMESPACE_COMPONENT];
    struct stat parent_identity, file_identity;
    uint32_t sources; /* All matching OFD source indices, never inode merged. */
    bool registered; /* Exact kind/parent/name/inode, not name-shape inference. */
} YDRaftJournalCensusBinding;

/* Borrow all inputs only through this call; store/progress may be NULL. Missing
 * scopes/identity, busy/changed/unknown/budget/fault/cancel yield owned PARTIAL
 * information, never complete emptiness. NULL means token allocation failed.
 * Root and snapshots retain independent capabilities; result survives all
 * callers/producers/runtime/store closing. No input ownership transfers.
 * Call outside backend/controller locks. All I/O and callbacks are outside
 * observation mutexes. No recovery, fallback, application pin or disposal.
 * Registration/native snapshots NEVER become producers. Global bounds are
 * 32 OFDs, 64 unique FULL views per-source in total, 1024 namespace entries,
 * 1 MiB aggregate native reader caches (32 KiB reserved per source).
 * Partial tokens never authorize dropping undiscovered roots or names. */
YDRaftJournalCensus *yd_raft_journal_census_observe(int root, YDDiskLineage *native,
    YDRaftJournalScope *scope, const YDRaftMeta *identity,
    const YDRaftSnapshotStore *store, YDRaftJournalCensusProgress progress,
    void *context, char *error, size_t length);
/* Immutable copies only; invalid calls clear an available output and fail.
 * No descriptors, native readers or archive handles escape. Accessors may
 * overlap; join all users before close. A result is never refreshed/adopted. */
bool yd_raft_journal_census_info(const YDRaftJournalCensus *, YDRaftJournalCensusInfo *);
bool yd_raft_journal_census_source(const YDRaftJournalCensus *, size_t, YDRaftJournalCensusSource *);
bool yd_raft_journal_census_root(const YDRaftJournalCensus *, size_t, YDRaftJournalCensusRoot *);
bool yd_raft_journal_census_producer(const YDRaftJournalCensus *, size_t, YDDiskLineageEntry *);
bool yd_raft_journal_census_binding(const YDRaftJournalCensus *, size_t, YDRaftJournalCensusBinding *);
bool yd_raft_journal_census_registration(const YDRaftJournalCensus *, size_t, YDRaftJournalBindingInfo *);
void yd_raft_journal_census_close(YDRaftJournalCensus *);
#endif
