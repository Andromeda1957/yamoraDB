#include "application_policy.h"
#include "../disk_internal.h"
#include "../disk_replica.h"
#include "../schema/policy_store.h"
#include <openssl/evp.h>
#include <string.h>

bool yd_raft_policy_compatible(YDDisk *disk, const unsigned char frozen[40]) {
    uint32_t capabilities = disk ? yd_disk_capabilities(disk) : 0;
    return disk && frozen && capabilities && capabilities <= UINT8_MAX &&
        (capabilities & YD_DISK_CAP_CLUSTER) &&
        !(capabilities & ~YD_DISK_CAP_SUPPORTED) &&
        !memcmp(frozen + 32, "YDADM01", 7) && frozen[39] == capabilities;
}
bool yd_raft_policy_identity(YDDisk *disk, const YDDiskView *view,
    unsigned char out[40], char *error, size_t length) {
    if (out) memset(out, 0, 40);
    uint32_t capabilities = disk ? yd_disk_capabilities(disk) : 0;
    if (!disk || !view || !out || view->format != 8 || !capabilities ||
        capabilities != view->capabilities || !(capabilities & YD_DISK_CAP_CLUSTER) ||
        capabilities > UINT8_MAX || (capabilities & ~YD_DISK_CAP_SUPPORTED))
        return yd_disk_error(error, length, "incompatible consensus admission capability");
    if (!(capabilities & YD_DISK_CAP_SCHEMA) &&
        !yd_disk_replica_policy_free(disk, view, error, length)) return false;
    YDPolicyWork work;
    yd_policy_work_init(&work, false);
    YDPolicyCatalog *catalog = NULL;
    bool present = false;
    YDPCInfo info;
    bool valid = yd_policy_store_at(disk, view, &work, &catalog, &present, error, length) == YD_POLICY_OK &&
        yd_policy_catalog_info(catalog, &info) == YD_PC_OK;
    unsigned char bytes[41] = {0};
    memcpy(bytes, "YDPRED01", 8);
    bytes[8] = present;
    if (valid) memcpy(bytes + 9, info.catalog_sha256, 32);
    size_t n = 0;
    valid = valid && EVP_Q_digest(NULL, "SHA256", NULL, bytes, sizeof(bytes), out, &n) == 1 && n == 32;
    yd_policy_catalog_free(catalog);
    if (!valid) {
        memset(out, 0, 40);
        return yd_disk_error(error, length, "consensus policy identity unavailable");
    }
    memcpy(out + 32, "YDADM01", 7);
    out[39] = (unsigned char)capabilities;
    return true;
}
bool yd_raft_policy_predecessor(YDDisk *disk, const YDDiskView *view,
    const unsigned char frozen[40], char *error, size_t length) {
    unsigned char actual[40];
    return yd_raft_policy_compatible(disk, frozen) &&
        yd_raft_policy_identity(disk, view, actual, error, length) &&
        !memcmp(actual, frozen, 32);
}
