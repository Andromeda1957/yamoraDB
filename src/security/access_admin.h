#ifndef YAMORA_SECURITY_ACCESS_ADMIN_H
#define YAMORA_SECURITY_ACCESS_ADMIN_H
#include "access.h"
#include "../disk_api.h"
#include "../consensus/cluster.h"

/* Runtime user and role management for one serving daemon. Opt-in: created
 * only for --runtime-access. The transport authenticates the configured write
 * administrative credential before yd_access_admin_request; nothing here
 * grants that authority. Tokens are never logged, stored or replicated: the
 * daemon turns them into verifiers before any command leaves this file, and a
 * server-generated token is returned only in the one successful response. */
typedef struct YDAccessAdmin YDAccessAdmin;
typedef struct {
    YDAccess *access;          /* Static policy with the runtime registry. */
    YDDisk *disk;              /* Standalone native disk, or NULL. */
    YDRaftCluster *cluster;    /* Replica set, or NULL. */
    bool replica;              /* Standalone read-only replica. */
    const char *read_token, *write_token;
    size_t read_length, write_length;
    unsigned timeout_ms;
} YDAccessAdminConfig;

/* Loads and publishes the stored state. Refuses invalid state, names or tokens
 * that collide with the static policy, and verifiers equal to an
 * administrative token. Borrowed config pointers must outlive the handle. */
YDAccessAdmin *yd_access_admin_open(const YDAccessAdminConfig *config, char *error,
    size_t length);
/* Background refresh of the cached snapshot (about every 250 ms). */
bool yd_access_admin_start(YDAccessAdmin *admin);
/* Stops and joins the refresh thread. The registry stays with the policy. */
void yd_access_admin_close(YDAccessAdmin *admin);
/* Worker threads only: never the binary I/O thread. Brings the snapshot up to
 * the applied state; confirmed additionally proves leadership first in a
 * replica set (falling back to the applied state on followers). */
void yd_access_admin_refresh(YDAccessAdmin *admin, bool confirmed);
/* "/v1/access" and everything below it. */
bool yd_access_admin_target(const char *target);
/* Exact management operation (0 for list or unknown) and subject name. */
int yd_access_admin_operation(const char *method, const char *target, char name[129]);
/* Audit operation for a /v1/access request: a management operation with its
 * subject name, otherwise LIST (GET/HEAD) or WRITE_DOCUMENT and no subject. */
uint32_t yd_access_admin_audit(const char *method, const char *target, char subject[129]);
typedef struct {
    const char *method, *target;
    const unsigned char *body;
    size_t length;
    bool json;
    const unsigned char *request_id; /* 16 bytes or NULL. */
    bool receipt_epoch_present;
    uint64_t receipt_epoch;
} YDAccessAdminRequest;
YDDiskReply yd_access_admin_request(YDAccessAdmin *admin, const YDAccessAdminRequest *request);

#endif
