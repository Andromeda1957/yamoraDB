#define _POSIX_C_SOURCE 200809L
#include "disk_internal.h"
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct YDDiskCheckpoint {
    int fd;
    pid_t process;
    YDDiskSchemaProfile schema;
    YDDiskView view;
    unsigned char header[YD_DISK_PAGE];
    YDDiskLineageLink lineage;
    YDRetentionGate *retention;
    int retention_lease;
    YDStorageLease budget_lease;
};

YDDiskCheckpoint *yd_disk_checkpoint_open(YDDisk *disk, char *error, size_t length) {
    if (!yd_disk_open_fence_operation(disk, true)) return NULL;
    if (disk->schema.version) {
        int prior;
        if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &prior)) return NULL;
        if (prior != PTHREAD_CANCEL_DISABLE) {
            (void)pthread_setcancelstate(prior, NULL);
            return NULL;
        }
    }
    YDStorageLease lease = {0};
    if (!yd_disk_budget_clone(disk, 0, &lease, error, length)) return NULL;
    YDDiskCheckpoint *checkpoint = disk ? calloc(1, sizeof(*checkpoint)) : NULL;
    if (!checkpoint) {
        yd_storage_budget_release(&lease);
        yd_disk_error(error, length, "cannot allocate native checkpoint");
        return NULL;
    }
    checkpoint->budget_lease = lease;
    checkpoint->retention_lease = yd_disk_retention_enter(disk);
    checkpoint->retention = yd_retention_gate_retain(disk->retention);
    pthread_mutex_lock(&disk->root_lock);
    if (disk->active_transactions) {
        pthread_mutex_unlock(&disk->root_lock);
        if (checkpoint->retention_lease >= 0) close(checkpoint->retention_lease);
        yd_retention_gate_close(checkpoint->retention);
        yd_storage_budget_release(&checkpoint->budget_lease);
        free(checkpoint);
        yd_disk_error(error, length, "native checkpoint requires a transaction boundary");
        return NULL;
    }
    checkpoint->view = disk->view;
    checkpoint->schema = disk->schema;
    checkpoint->process = disk->schema.version || disk->view.capabilities || disk->budget_lease.budget ? getpid() : 0;
    yd_disk_lineage_export_begin(disk);
    checkpoint->fd = !disk->failed && disk->view.format >= 3 && disk->view.format <= 8
                         ? fcntl(disk->fd, F_DUPFD_CLOEXEC, 0)
                         : -1;
    pthread_mutex_unlock(&disk->root_lock);
    if (checkpoint->fd < 0) {
        yd_disk_lineage_export_finish(disk, NULL, YD_DISK_LINEAGE_CHECKPOINT,
            checkpoint->view, 0, NULL);
        if (checkpoint->retention_lease >= 0) close(checkpoint->retention_lease);
        yd_retention_gate_close(checkpoint->retention);
        yd_storage_budget_release(&checkpoint->budget_lease);
        free(checkpoint);
        yd_disk_error(error, length, "cannot capture native checkpoint");
        return NULL;
    }
    yd_disk_encode_schema_header(checkpoint->header, &checkpoint->view, &checkpoint->schema);
    YDDiskRecoverySlot slots[2] = {{true, checkpoint->view}, {0}};
    yd_disk_lineage_export_finish(disk, &checkpoint->lineage, YD_DISK_LINEAGE_CHECKPOINT,
        checkpoint->view, 1, slots);
    return checkpoint;
}

YDDiskView yd_disk_checkpoint_view(const YDDiskCheckpoint *checkpoint) {
    return checkpoint && (!checkpoint->process || checkpoint->process == getpid()) ?
        checkpoint->view : (YDDiskView){0};
}

bool yd_disk_checkpoint_read(const YDDiskCheckpoint *checkpoint, uint64_t offset, void *bytes,
                             size_t size, char *error, size_t length) {
    if (!checkpoint || (checkpoint->process && checkpoint->process != getpid()) ||
        !bytes || !size || size > YD_DISK_CHECKPOINT_CHUNK ||
        offset > checkpoint->view.end || size > checkpoint->view.end - offset)
        return yd_disk_error(error, length, "native checkpoint read outside bounds");
    unsigned char *out = bytes;
    // Only the two superblocks are overwritten by later CoW publications.
    while (size && offset < 2U * YD_DISK_PAGE) {
        size_t within = (size_t)(offset % YD_DISK_PAGE), count = YD_DISK_PAGE - within;
        if (count > size)
            count = size;
        memcpy(out, checkpoint->header + within, count);
        out += count;
        offset += count;
        size -= count;
    }
    while (size) {
        ssize_t count = pread(checkpoint->fd, out, size, (off_t)offset);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            return yd_disk_error(error, length, "native checkpoint source read failed");
        out += (size_t)count;
        offset += (size_t)count;
        size -= (size_t)count;
    }
    return true;
}

void yd_disk_checkpoint_close(YDDiskCheckpoint *checkpoint) {
    if (checkpoint && (!checkpoint->process || checkpoint->process == getpid())) {
        yd_disk_lineage_link_close(&checkpoint->lineage, checkpoint->fd);
        if (checkpoint->retention_lease >= 0) close(checkpoint->retention_lease);
        yd_retention_gate_close(checkpoint->retention);
        yd_storage_budget_release(&checkpoint->budget_lease);
        free(checkpoint);
    }
}
