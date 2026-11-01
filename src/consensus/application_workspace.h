#ifndef YAMORA_CONSENSUS_APPLICATION_WORKSPACE_H
#define YAMORA_CONSENSUS_APPLICATION_WORKSPACE_H
#include "application_copy.h"
typedef struct YDRaftApplicationWorkspace YDRaftApplicationWorkspace;
typedef enum {
    YD_RAFT_WORKSPACE_PRESERVE = 0,
    YD_RAFT_WORKSPACE_SAFE_PRESELECTION_SKIP,
    YD_RAFT_WORKSPACE_CONFIRMED_SUCCESS
} YDRaftApplicationWorkspaceDisposition;
/* Serialize all workspace methods and image calls. Parent is an existing,
 * trusted pinned directory (for example the archive store). Attempts mkdir of
 * a private random child and opens it. mkdir/open cannot prove directory birth:
 * NO directory is ever renamed or deleted. Directory shells remain; a live owner may prove them for reuse, but unknown
 * shells block the parent's fail-closed inventory after close/crash.
 * Caller guarantees cooperative exclusive ownership INSIDE pinned custody;
 * directory fd identity and advisory flock do not enforce same-UID exclusion. */
YDRaftApplicationWorkspace *yd_raft_application_workspace_create(int parent,
    char *error, size_t length);
/* Borrowed descriptors/name through close. The directory is the empty native
 * copy destination. Parent/name locate the opened shell, not birth. Admission
 * excludes this directory by descriptor identity, never by name or prefix. */
int yd_raft_application_workspace_directory(const YDRaftApplicationWorkspace *workspace);
int yd_raft_application_workspace_parent(const YDRaftApplicationWorkspace *workspace);
const char *yd_raft_application_workspace_name(const YDRaftApplicationWorkspace *workspace);
/* Bind exactly once, after the final successful copy/catch-up while the image
 * is alive, then perform no more image mutations. After opening both files,
 * image_created_files must verify directory/native/fence against creation FDs.
 * Native read-only pins do NOT inherit the writer's created flag. The fence
 * is preserved by discard; explicit recycle may reclaim its proven inode.
 * Takes independent descriptors without
 * inheriting native flock. Release image/readers/checkpoints before discard. */
bool yd_raft_application_workspace_bind(YDRaftApplicationWorkspace *workspace,
    YDRaftApplicationImage *image, char *error, size_t length);
/* Parent supplies the outcome, with selection excluded throughout this call.
 * SAFE_PRESELECTION_SKIP is only a known safe skip before artifact selection;
 * stale/failed/uncertain selectors (even after artifact creation) must PRESERVE.
 * 1 = native work file durably reclaimed; ALL directory shells and the
 * initialization fence are preserved. Full workspace disposal/retention and
 * the automatic worker remain open.
 * 0 = native/directory pins busy, -1 = preserved or I/O.
 * Retry partial disposal on the SAME handle and disposition. Replacement or
 * unknown content is preserved. No implicit disposal or path-based authority. */
int yd_raft_application_workspace_discard(YDRaftApplicationWorkspace *workspace,
    YDRaftApplicationWorkspaceDisposition disposition, char *error, size_t length);
/* After confirmed discard, separately authorize reclamation of its proven
 * initialization fence and reuse of these SAME two pinned shells. Never deletes
 * or renames a directory. 1 empty/ready, 0 pinned/busy, -1 preserved/I/O. Partial
 * retries use the same handle. Failed/unbound copies and uncertain dispositions
 * grant no reclamation authority. Close/crash never reconstructs this capability. */
int yd_raft_application_workspace_recycle(YDRaftApplicationWorkspace *workspace,
    char *error, size_t length);
/* Read-only proof for admission: exact named workspace and optional EMPTY
 * custody beneath the supplied parent. Only ready-empty or intact-bound states
 * qualify. Borrowed outputs are -1 on failure; serialize through inventory and
 * recheck afterwards. A prefix, persisted name or reopened shell is no proof. */
bool yd_raft_application_workspace_account(const YDRaftApplicationWorkspace *workspace,
    int parent, int *directory, int *custody);
/* Parent must first join image operations and permit controller teardown.
 * Releases descriptors only; never deletes, including after partial discard. */
void yd_raft_application_workspace_close(YDRaftApplicationWorkspace *workspace);
#endif
