#ifndef YAMORA_CONSENSUS_JOURNAL_NAMESPACE_H
#define YAMORA_CONSENSUS_JOURNAL_NAMESPACE_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>

#define YD_RAFT_NAMESPACE_ENTRIES 1024U
#define YD_RAFT_NAMESPACE_FILES 32U
#define YD_RAFT_NAMESPACE_BINDINGS 64U
#define YD_RAFT_NAMESPACE_DEPTH 3U
#define YD_RAFT_NAMESPACE_COMPONENT 64U
#define YD_RAFT_NAMESPACE_CANDIDATES 32U

typedef struct YDRaftJournalNamespace YDRaftJournalNamespace;
typedef enum {
    YD_RAFT_NAMESPACE_CURRENT,
    YD_RAFT_NAMESPACE_PREPARED_CANDIDATE,
    YD_RAFT_NAMESPACE_RETAINED_CANDIDATE,
    YD_RAFT_NAMESPACE_STAGING_CANDIDATE,
    YD_RAFT_NAMESPACE_STAGING_FENCE,
    YD_RAFT_NAMESPACE_RETENTION_CONTROL,
    YD_RAFT_NAMESPACE_RETENTION_BIRTH,
    YD_RAFT_NAMESPACE_RETENTION_SESSION
} YDRaftJournalNamespaceKind;
typedef enum {
    YD_RAFT_NAMESPACE_UNKNOWN = 1U << 0,
    YD_RAFT_NAMESPACE_SYMLINK = 1U << 1,
    YD_RAFT_NAMESPACE_UNTRUSTED = 1U << 2,
    YD_RAFT_NAMESPACE_IO = 1U << 3,
    YD_RAFT_NAMESPACE_CHANGED = 1U << 4,
    YD_RAFT_NAMESPACE_ENTRY_LIMIT = 1U << 5,
    YD_RAFT_NAMESPACE_FILE_LIMIT = 1U << 6,
    YD_RAFT_NAMESPACE_BINDING_LIMIT = 1U << 7,
    YD_RAFT_NAMESPACE_MISSING_CURRENT = 1U << 8,
    YD_RAFT_NAMESPACE_INVALID_FENCE = 1U << 9,
    YD_RAFT_NAMESPACE_INVALID_ARGUMENT = 1U << 10
} YDRaftJournalNamespaceReason;
typedef struct {
    bool complete;
    uint32_t reasons;
    size_t entries, file_count, binding_count, directory_count;
    /* Comparisons exclude atime: directory enumeration may update it. */
    struct stat root;
} YDRaftJournalNamespaceInfo;
typedef struct {
    YDRaftJournalNamespaceKind kind;
    /* All regular files, including fences, share the 32-inode budget. Aliases
     * retain separate bindings with the same source_index. Fences are NOT
     * journal sources and must not be handed to native root readers. Retention
     * metadata consumes these budgets without becoming a native source. */
    size_t source_index;
    size_t depth;
    /* SIZE_MAX for paths below journal root; otherwise first supplied candidate
     * index. Extra paths are relative to that directory capability. */
    size_t candidate_index;
    char path[YD_RAFT_NAMESPACE_DEPTH][YD_RAFT_NAMESPACE_COMPONENT];
    char component[YD_RAFT_NAMESPACE_COMPONENT];
    struct stat parent_identity, file_identity;
    int parent_fd; /* Borrowed identity-only directory; never close/seek it. */
} YDRaftJournalNamespaceBinding;

/* Borrow root during this call only. Owns independent directory OFDs and
 * read-only regular-file descriptors; no dup/flock/payload reads, writes,
 * metadata decoding, provenance or ownership inference. NULL means allocation
 * failure (error set), never empty. Other failures return an owned partial
 * token: inspect info.complete/reasons. Call outside backend locks. */
YDRaftJournalNamespace *yd_raft_journal_namespace_capture(int root, char *error, size_t length);
/* Additional borrowed live-registration hints (not ownership proof), <=32.
 * Opens independent directory OFDs, including empty candidates; layout is only
 * .yamora-disk and a zero regular .yamora-initializing fence. Global budgets
 * are shared with root traversal. Same-inode COPY directories are enumerated
 * once. Extra directory roots have no ancestor/name binding: caller's separate
 * producer revision must guard registration changes. */
YDRaftJournalNamespace *yd_raft_journal_namespace_capture_candidates(int root,
    const int *candidate_fds, size_t count, char *error, size_t length);
/* Copy immutable observations; clear output on invalid input. Candidate name
 * shape is not live registration or proof of ownership. */
bool yd_raft_journal_namespace_info(const YDRaftJournalNamespace *token,
    YDRaftJournalNamespaceInfo *out);
bool yd_raft_journal_namespace_binding(const YDRaftJournalNamespace *token, size_t index,
    YDRaftJournalNamespaceBinding *out);
/* Rechecks ALL original parent/name/file and directory metadata bindings,
 * including bounded fresh enumeration. Never adopts replacement/new names or
 * retries a changed namespace. False for incomplete capture or any change/error.
 * Optional reasons are cleared on success. Run AFTER dependency traversal and
 * the parent's domain revision recheck. No caller/backend locks may be held.
 * Calls may overlap with readers; join all before close. */
bool yd_raft_journal_namespace_validate(const YDRaftJournalNamespace *token, uint32_t *reasons);
void yd_raft_journal_namespace_close(YDRaftJournalNamespace *token);
#endif
