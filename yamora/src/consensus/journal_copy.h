#ifndef YAMORA_CONSENSUS_JOURNAL_COPY_H
#define YAMORA_CONSENSUS_JOURNAL_COPY_H
#include "raft.h"
#include "../disk.h"
typedef struct YDRaftJournalCapture YDRaftJournalCapture;
typedef struct YDRaftJournalImage YDRaftJournalImage;
typedef enum {
    YD_RAFT_JOURNAL_SOURCE,
    YD_RAFT_JOURNAL_COPY,
    YD_RAFT_JOURNAL_VERIFY
} YDRaftJournalPhase;
typedef bool (*YDRaftJournalProgress)(void *context, YDRaftJournalPhase phase, uint64_t done,
                                      uint64_t total);
/* Short serialized capture of exact durable metadata and an owned logical
 * native reader. Subsequent source writes and close are independent. No core
 * pointer escapes. Join copy calls before closing this capture. */
YDRaftJournalCapture *yd_raft_journal_capture(YDRaft *raft, size_t cache, char *error,
                                              size_t length);
void yd_raft_journal_capture_close(YDRaftJournalCapture *capture);
/* Physical high-water mark of this owned capture; zero for NULL. */
uint64_t yd_raft_journal_capture_bytes(const YDRaftJournalCapture *capture);
/* Background copy into a borrowed, existing, empty private directory. Owns a
 * directory descriptor and file lock on success. Streams retained records and terms,
 * preserving exact metadata (including uncommitted suffix/selected generation).
 * Fully verifies source and copy; progress may cancel between bounded records.
 * Source validation precedes file creation. Any created native candidate keeps
 * its durable initialization fence on success AND failure. Never starts
 * a core, changes the source, switches a live file or removes any old state.
 * A future serialized publisher must catch up/recheck before selecting a copy. */
YDRaftJournalImage *yd_raft_journal_copy(const YDRaftJournalCapture *capture, int directory,
                                         size_t cache, YDRaftJournalProgress progress,
                                         void *context, char *error, size_t length);
/* Borrowed read-only candidate handle, valid until image close. */
YDDisk *yd_raft_journal_image_disk(const YDRaftJournalImage *image);
/* Exclusive candidate maintenance from a newer capture of the same source
 * inode. Join borrowed readers/copy calls first; reacquire the borrowed disk
 * afterward. Prunes superseded keys, writes only changed records, verifies exact
 * readback and advances the candidate origin only on success. An uncertain or
 * cancelled write attempt disables the candidate while preserving its fence and
 * files. No source mutation, selection, quorum proof or physical deletion. */
bool yd_raft_journal_catch_up(YDRaftJournalImage *image, const YDRaftJournalCapture *capture,
                              YDRaftJournalProgress progress, void *context, char *error,
                              size_t length);
/* Serialized observation of the exact source inode/generation/metadata only;
 * grants no quorum authority or permission to publish a stale image. */
bool yd_raft_journal_image_current(const YDRaftJournalImage *image, const YDRaft *raft);
void yd_raft_journal_image_close(YDRaftJournalImage *image);
#endif
