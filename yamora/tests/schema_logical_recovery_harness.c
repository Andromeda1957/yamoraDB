#define _POSIX_C_SOURCE 200809L
#include "disk_schema_recovery.h"
#include "disk_internal.h"
#include "disk_documents.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static bool progress(void *context, YDDiskValidationPhase phase) {
    (void)phase;
    size_t *remaining = context;
    if (!*remaining) return false;
    --*remaining;
    return true;
}
int main(int argc, char **argv) {
    if (argc < 5 || argc > 6) return 2;
    uint32_t capabilities = !strcmp(argv[3], "caps") ? YD_DISK_CAP_SCHEMA : 0;
    if (!capabilities && strcmp(argv[3], "schema")) return 2;
    int previous;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous)) return 3;
    char error[256] = {0};
    bool exporting = !strcmp(argv[1], "dump"), restoring = !strcmp(argv[1], "restore");
    bool probing = !strcmp(argv[1], "budget") || !strcmp(argv[1], "cancel");
    bool collection = !strcmp(argv[1], "collection");
    int fd = -1, directory = -1;
    YDDisk *disk = NULL;
    YDDiskTxn *txn = NULL;
    bool valid = false, poisoned = false, cancelled = false;
    if (collection) {
        disk = capabilities ? yd_disk_open_capabilities(argv[2], true, capabilities,
            1048576, error, sizeof(error)) :
            yd_disk_open_schema(argv[2], true, 1048576, error, sizeof(error));
        txn = disk ? yd_disk_begin_exclusive(disk, error, sizeof(error)) : NULL;
        valid = txn && yd_disk_create_collection(txn, argv[4], error, sizeof(error));
        if (valid) { valid = yd_disk_commit(txn, error, sizeof(error)); txn = NULL; }
    } else if (exporting) {
        disk = capabilities ? yd_disk_open_capabilities(argv[2], false, capabilities,
            1048576, error, sizeof(error)) :
            yd_disk_open_schema(argv[2], false, 1048576, error, sizeof(error));
        fd = open(argv[4], O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (disk && fd >= 0) {
            YDDiskView view = yd_disk_view(disk);
            size_t remaining = 0;
            YDDiskValidation state = {.progress = progress, .context = &remaining};
            valid = yd_disk_schema_logical_export(disk, &view, fd,
                argc == 6 ? &state : NULL, error, sizeof(error));
            cancelled = state.cancelled;
        }
    } else if (restoring || probing) {
        fd = open(argv[4], O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        if (restoring) {
            directory = open(argv[2], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (directory >= 0 && fd >= 0)
                valid = yd_disk_schema_recovery_restore_at(directory, fd, capabilities,
                    1048576, error, sizeof(error));
        } else {
            disk = capabilities ? yd_disk_open_capabilities(argv[2], true, capabilities,
                1048576, error, sizeof(error)) :
                yd_disk_open_schema(argv[2], true, 1048576, error, sizeof(error));
            txn = disk ? yd_disk_begin_exclusive(disk, error, sizeof(error)) : NULL;
            YDPolicyWork work;
            yd_policy_work_init(&work, true);
            size_t remaining = 0;
            YDDiskValidation state = {.progress = progress, .context = &remaining};
            if (!strcmp(argv[1], "budget")) work.catalog.work_left = 0;
            valid = txn && fd >= 0 && yd_disk_schema_logical_import(txn, fd, &work,
                !strcmp(argv[1], "cancel") ? &state : NULL, error, sizeof(error));
            poisoned = txn && txn->failed;
            cancelled = state.cancelled;
        }
    }
    yd_disk_abort(txn);
    yd_disk_close(disk);
    if (directory >= 0) close(directory);
    if (fd >= 0) close(fd);
    printf("{\"ok\":%s,\"poisoned\":%s,\"cancelled\":%s}\n",
        valid ? "true" : "false", poisoned ? "true" : "false", cancelled ? "true" : "false");
    if (!valid) fprintf(stderr, "schema logical recovery refused: %s\n", error);
    if (pthread_setcancelstate(previous, NULL)) return 3;
    return exporting || restoring || probing || collection ? 0 : 2;
}
