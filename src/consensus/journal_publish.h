#ifndef YAMORA_CONSENSUS_JOURNAL_PUBLISH_H
#define YAMORA_CONSENSUS_JOURNAL_PUBLISH_H
#include "journal_copy.h"
#define YD_RAFT_JOURNAL_RETAINED ".yamora-journals"
typedef struct YDRaftJournalPublication YDRaftJournalPublication;
/* Outside core serialization, prepare durable hardlinks for the old journal in
 * a private retained directory and the verified candidate at a fresh root name.
 * The standard native file remains unchanged. Owns pinned root/retained directory
 * descriptors; no core/runtime pointer. Borrows image until publication close:
 * do not catch up/close it meanwhile. Failure preserves all created link names.
 * Old links may follow later source writes until a guarded selection succeeds;
 * this is preparation, not an immutable backup or authority to publish. */
YDRaftJournalPublication *yd_raft_journal_prepare(YDRaftJournalImage *image, int journal_directory,
                                                  char *error, size_t length);
/* Serialized exact source/root/candidate/retained-link observation only. A
 * subsequent publisher must recheck immediately before its atomic file switch.
 * No quorum/read proof, file mutation, ownership transfer or core fencing. */
bool yd_raft_journal_prepared_current(const YDRaftJournalPublication *publication,
                                      const YDRaft *raft);
/* Serialized final exact-source check, one same-directory selector rename and
 * root-directory sync. On observed selection, transfers the candidate writer
 * into this same core without changing logical metadata/role/peer progress.
 * published records ownership transfer even when a later sync/error fences the
 * core and returns false; it does not prove durable success. Rename uncertainty
 * also fences. A stale/invalid preparation rejects before filesystem mutation.
 * Preserves old-file hardlinks and all candidate files; no physical deletion. */
bool yd_raft_journal_publish(YDRaftJournalPublication *publication, YDRaft *raft, bool *published,
                             char *error, size_t length);
/* Outside core serialization, retire only this publication's old-file hardlink
 * and candidate-directory native link after a durably successful selection.
 * Verify selected/retained/candidate identities before mutation; preserve the
 * selected native filename, initialization fence, directories and unknown files.
 * Owned historical readers survive unlink until their last descriptor closes.
 * Retry resolves partial cleanup; cleanup errors never fence the selected core.
 * Caller serializes operations on this publication/image and keeps both alive.
 * Uncertain/failed selection grants no retirement authority. */
bool yd_raft_journal_retire(YDRaftJournalPublication *publication, char *error, size_t length);
/* Outside serialization, cancel an unattempted preparation, including one made
 * stale by later source writes. Verify the still-selected source and both owned
 * links, remove only the prepared root link and retained extra source link, and
 * sync both directories. Preserve the candidate's original fenced file for
 * catch-up/retry after publication close. No attempted/uncertain selection may
 * cancel. Cleanup failures preserve selected state and allow an exact retry. */
bool yd_raft_journal_cancel(YDRaftJournalPublication *publication, char *error, size_t length);
/* Releases descriptors and the image's preparation reservation, preserving all
 * files/links. The borrowed image remains owned by its caller. */
void yd_raft_journal_publication_close(YDRaftJournalPublication *publication);
#endif
