#ifndef YAMORA_AUDIT_CUSTODY_H
#define YAMORA_AUDIT_CUSTODY_H
#include "audit.h"
#include <sys/types.h>
typedef struct YDAuditAnchor YDAuditAnchor;
/* Walk absolute paths without symlinks/dot/empty components. Every ancestor
 * must be owned by root/helper, never the daemon, and deny untrusted replacement
 * (trusted sticky parents permitted). Directory final is helper-owned 0700. */
int yd_audit_protected_directory(const char *path, uid_t daemon_uid);
/* Helper-owned non-writable-to-others parent for a public peer-authenticated
 * socket. May be traversable by daemon; key/anchor roots remain private. */
int yd_audit_socket_directory(const char *path, uid_t daemon_uid);
bool yd_audit_protected_key(const char *path, uid_t daemon_uid, unsigned char out[32]);
/* Independent exclusive root lock. create requires empty namespace; resume
 * requires exactly one private, complete anchor-v1.yda. Never reads sink files.
 * Cancellation must already be disabled through close, single owner process. */
YDAuditAnchor *yd_audit_anchor_open(const char *path, uid_t daemon_uid, bool create,
    YDAuditHead *current);
/* Post-mutation errors poison this owner, preserve artifacts, and deny retry. */
bool yd_audit_anchor_publish(YDAuditAnchor *, const YDAuditHead *);
void yd_audit_anchor_close(YDAuditAnchor *);
#endif
