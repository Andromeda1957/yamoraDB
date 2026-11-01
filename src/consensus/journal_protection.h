#ifndef YAMORA_CONSENSUS_JOURNAL_PROTECTION_H
#define YAMORA_CONSENSUS_JOURNAL_PROTECTION_H
#include "application_reference.h"
#include "journal_census.h"

typedef struct YDRaftJournalProtection YDRaftJournalProtection;
enum {
    YD_RAFT_PROTECTION_ARGUMENT = 1U,
    YD_RAFT_PROTECTION_CENSUS = 2U,
    YD_RAFT_PROTECTION_APPLICATION = 4U,
    YD_RAFT_PROTECTION_BUSY = 8U,
    YD_RAFT_PROTECTION_IO = 16U,
    YD_RAFT_PROTECTION_CHANGED = 32U,
    YD_RAFT_PROTECTION_CANCELLED = 64U
};
typedef struct {
    YDRaftJournalCensusInfo census;
    struct stat document_root;
    bool application_pins_complete;
    unsigned reasons;
    size_t required, pinned;
} YDRaftJournalProtectionInfo;
typedef struct {
    bool required, attempted, binding_validated;
    YDRaftApplicationReferenceResult result;
    YDRaftApplicationReferenceInfo application;
} YDRaftJournalApplicationEdge;
/* ALWAYS consumes census, including NULL, bad arguments and allocation failure.
 * Owns the immutable census plus at most 64 independent application references
 * (five FDs each), one per KNOWN root. Validate EACH root's (A,B) relationship,
 * even when A repeats. EMPTY/invalid-header roots add no application reference.
 * Unknown metadata, incomplete census, bad document-root binding, missing/busy
 * reference, fault/change/cancellation return owned PARTIAL information.
 * Only outer-token allocation failure returns NULL. Existing pins remain held
 * in a partial result until close. Inputs/progress are borrowed only in call.
 *
 * document_root is an explicitly trusted caller binding, distinct from journal
 * root; a census cannot authenticate their application-level relationship.
 * Call outside backend/controller locks. All callbacks run before final name
 * checks. Result survives input, store, runtime and controller close.
 *
 * Completeness refers ONLY to roots in the consumed immutable census. This does
 * not continuously pin every producer, refresh/revalidate the census revision,
 * exclude new dependencies, reconstruct provenance, validate recovery/images,
 * or authorize retention/deletion. A later retirement decision still needs an
 * atomic producer barrier and durable provenance. Linux local-filesystem OFD
 * and flock semantics are required; no process-lock fallback exists.
 */
YDRaftJournalProtection *yd_raft_journal_protection_take(YDRaftJournalCensus *census,
    int document_root, YDRaftJournalCensusProgress progress, void *context,
    char *error, size_t length);
/* Immutable copies only, clear outputs on invalid calls. No handles/FDs escape.
 * Accessors may overlap; join users before close. Close never deletes. */
bool yd_raft_journal_protection_info(const YDRaftJournalProtection *, YDRaftJournalProtectionInfo *);
bool yd_raft_journal_protection_root(const YDRaftJournalProtection *, size_t,
    YDRaftJournalCensusRoot *, YDRaftJournalApplicationEdge *);
void yd_raft_journal_protection_close(YDRaftJournalProtection *);
#endif
