#ifndef YAMORA_AUDIT_HELPER_H
#define YAMORA_AUDIT_HELPER_H
#include "audit.h"
#include <sys/types.h>
typedef struct {
    const char *key_file, *audit_directory, *anchor_directory, *socket;
    unsigned char key_id[16];
    uid_t daemon_uid;
    bool create;
    YDAuditLimits limits;
} YDAuditHelperOptions;
/* Standalone process entry point; does not drop/raise UIDs or capabilities.
 * Validates its unprivileged custody, owns SIGINT/SIGTERM handlers, keeps every
 * key/anchor/sink descriptor private and restores handlers on orderly return.
 * Exit 0 clean shutdown, 1 refused/uncertain. No data diagnostics are printed. */
int yd_audit_helper_run(const YDAuditHelperOptions *);
#endif
