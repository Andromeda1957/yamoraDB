#ifndef YAMORA_CONSENSUS_JOURNAL_COPY_INTERNAL_H
#define YAMORA_CONSENSUS_JOURNAL_COPY_INTERNAL_H
#include "journal_copy.h"
#include "raft_internal.h"
#include <sys/types.h>
typedef struct {
    dev_t device;
    ino_t inode;
    YDDiskView view;
    YDRaftMeta meta;
} YDRaftJournalOrigin;
struct YDRaftJournalImage {
    YDRaftJournalOrigin origin;
    YDRaftJournalScope *scope;
    YDRaftJournalBinding *workspace, *fence;
    YDDisk *disk, *writer;
    size_t cache;
    bool failed, prepared, published, disposed;
    int directory;
};
#endif
