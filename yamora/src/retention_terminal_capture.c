#define _GNU_SOURCE
#include "retention_terminal_capture.h"
#include "disk_internal.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static bool metadata(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
        a->st_mode == b->st_mode && a->st_uid == b->st_uid && a->st_gid == b->st_gid &&
        a->st_nlink == b->st_nlink && a->st_size == b->st_size && a->st_blocks == b->st_blocks &&
        a->st_mtim.tv_sec == b->st_mtim.tv_sec && a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
        a->st_ctim.tv_sec == b->st_ctim.tv_sec && a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}
static bool identity_fits(const struct stat *s) {
    /* dev_t/ino_t are unsigned on the supported Linux native platform. */
    return (dev_t)(uint64_t)s->st_dev == s->st_dev &&
        (ino_t)(uint64_t)s->st_ino == s->st_ino && s->st_ino != 0;
}
static bool bindings(YDDisk *disk, YDRetentionGate *gate, struct stat *native) {
    YDRetentionGateBinding original;
    struct stat root, named;
    int directory = yd_retention_gate_directory(gate);
    return yd_retention_gate_binding(gate, &original) && !fstat(directory, &root) &&
        identity_fits(&root) && S_ISDIR(root.st_mode) && root.st_uid == geteuid() &&
        !(root.st_mode & 0022) && root.st_dev == original.root.st_dev &&
        root.st_ino == original.root.st_ino && root.st_mode == original.root.st_mode &&
        root.st_gid == original.root.st_gid && !fstat(disk->fd, native) &&
        identity_fits(native) && S_ISREG(native->st_mode) && native->st_uid == geteuid() &&
        native->st_nlink == 1 && (native->st_mode & 07777) == 0600 &&
        native->st_size >= 8192 && (uintmax_t)native->st_size <= INT64_MAX &&
        !fstatat(directory, YD_DISK_FILE, &named, AT_SYMLINK_NOFOLLOW) && metadata(native, &named);
}
static bool read_pair(int fd, unsigned char pages[8192]) {
    for (unsigned slot = 0; slot < 2; slot++) {
        ssize_t n;
        do { n = pread(fd, pages + slot * 4096, 4096, (off_t)slot * 4096); }
        while (n < 0 && errno == EINTR);
        if (n != 4096) return false;
    }
    return true;
}
static bool view_equal(const YDDiskView *a, const YDDiskView *b) {
    return a->format == b->format && a->generation == b->generation && a->root == b->root &&
        a->end == b->end && a->documents == b->documents && a->collections == b->collections &&
        a->bytes == b->bytes && a->revision == b->revision;
}
static bool supported_pair(YDDisk *disk, const YDRetentionTerminalInput *input) {
    YDSchemaBarrierPair pair;
    if (yd_disk_schema_inspect((const unsigned char (*)[YD_DISK_PAGE])input->headers,
        input->file_size, &pair, NULL, 0) != YD_SCHEMA_BARRIER_OK || pair.version ||
        !pair.valid[0] || !pair.valid[1] || pair.views[0].format != 5 || pair.views[1].format != 5 ||
        memcmp(pair.retention, "YDOFENC1", 8) ||
        memcmp(pair.retention + 16, input->incarnation, 32) ||
        disk->open_fence.version != 1 || disk->open_fence.producer_protocol != 1 ||
        memcmp(disk->open_fence.incarnation, input->incarnation, 32)) return false;
    unsigned selected = pair.views[1].generation > pair.views[0].generation ? 1 : 0;
    return view_equal(&pair.views[selected], &disk->view);
}
bool yd_retention_terminal_capture(YDDisk *disk, YDRetentionGate *gate,
    YDRetentionCut cut, YDRaftRetentionBirth *birth, unsigned char digest[32],
    char *error, size_t length) {
    if (digest) memset(digest, 0, 32);
    if (error && length) error[0] = '\0';
    /* No inherited native lock or birth token is touched before cut authority. */
    if (!digest || !yd_retention_gate_cut_validate(gate, cut)) return false;
    int prior;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &prior)) return false;
    bool writer = false, root = false, success = false;
    YDRetentionTerminalInput input = {.fence_version = 1, .producer_protocol = 1};
    unsigned char again[8192], incarnation[32], hash[32];
    struct stat before, after;
    YDRetentionGateBinding binding;
    if (!yd_disk_process_valid(disk) || !birth || disk->retention != gate ||
        !disk->fence_hold || !disk->writable || !disk->lineage_independent ||
        pthread_mutex_trylock(&disk->writer)) goto done;
    writer = true;
    if (pthread_mutex_trylock(&disk->root_lock)) goto done;
    root = true;
    if (disk->failed || disk->opening || disk->active_transactions || disk->retention_lease >= 0 ||
        !yd_raft_retention_birth_hash_cut(birth, gate, cut, input.incarnation) ||
        !yd_retention_gate_binding(gate, &binding) || !bindings(disk, gate, &before)) goto done;
    input.root_device = (uint64_t)binding.root.st_dev;
    input.root_inode = (uint64_t)binding.root.st_ino;
    input.journal_device = (uint64_t)before.st_dev;
    input.journal_inode = (uint64_t)before.st_ino;
    input.file_size = (uint64_t)before.st_size;
    if (!read_pair(disk->fd, input.headers) || !supported_pair(disk, &input) ||
        !yd_retention_terminal_hash(&input, hash) ||
        !read_pair(disk->fd, again) || memcmp(input.headers, again, sizeof(again)) ||
        !yd_raft_retention_birth_hash_cut(birth, gate, cut, incarnation) ||
        memcmp(incarnation, input.incarnation, 32) ||
        !bindings(disk, gate, &after) || !metadata(&before, &after) ||
        !yd_retention_gate_cut_validate(gate, cut)) goto done;
    memcpy(digest, hash, 32);
    success = true;
done:
    if (root) pthread_mutex_unlock(&disk->root_lock);
    if (writer) pthread_mutex_unlock(&disk->writer);
    if (!success) {
        (void)yd_retention_gate_cut_fail(gate, cut);
        if (error && length) snprintf(error, length, "terminal evidence unavailable; preserve artifacts");
    }
    (void)pthread_setcancelstate(prior, NULL);
    return success;
}

bool yd_retention_terminal_resume_capture(YDDiskOpening *opening, YDDisk *disk,
    YDRetentionGate *gate, YDRetentionCut cut, YDRaftRetentionBirth *birth,
    unsigned char digest[32], char *error, size_t length) {
    if (digest) memset(digest, 0, 32);
    if (error && length) error[0] = '\0';
    /* Neither an arbitrary borrowed disk nor a copied opening can substitute
     * for the current constructor's callback. Cut authority precedes native
     * lock access, including failure paths. */
    if (!digest || !yd_retention_gate_cut_validate(gate, cut) ||
        !yd_disk_opening_resume_active(opening, disk)) return false;
    int prior;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &prior)) return false;
    bool writer = false, root = false, success = false;
    YDRetentionTerminalInput input = {.fence_version = 1, .producer_protocol = 1};
    YDDiskOpeningInfo opening_info;
    YDRetentionGateBinding binding;
    struct stat before, after;
    unsigned char again[8192], incarnation[32], hash[32];
    if (!yd_disk_process_valid(disk) || !birth || disk->retention ||
        !disk->opening || !disk->fence_hold || !disk->writable ||
        !disk->lineage_independent ||
        !yd_disk_opening_info(opening, &opening_info) ||
        opening_info.created_here || opening_info.installed_here ||
        opening_info.valid_slots != 3 || pthread_mutex_trylock(&disk->writer)) goto done;
    writer = true;
    if (pthread_mutex_trylock(&disk->root_lock)) goto done;
    root = true;
    if (disk->failed || disk->active_transactions || disk->retention_lease >= 0 ||
        !yd_raft_retention_birth_hash_cut(birth, gate, cut, input.incarnation) ||
        !yd_retention_gate_binding(gate, &binding) || !bindings(disk, gate, &before) ||
        before.st_dev != opening_info.native.st_dev || before.st_ino != opening_info.native.st_ino)
        goto done;
    input.root_device = (uint64_t)binding.root.st_dev;
    input.root_inode = (uint64_t)binding.root.st_ino;
    input.journal_device = (uint64_t)before.st_dev;
    input.journal_inode = (uint64_t)before.st_ino;
    input.file_size = (uint64_t)before.st_size;
    if (!read_pair(disk->fd, input.headers) || !supported_pair(disk, &input) ||
        !yd_retention_terminal_hash(&input, hash) ||
        !read_pair(disk->fd, again) || memcmp(input.headers, again, sizeof(again)) ||
        !yd_raft_retention_birth_hash_cut(birth, gate, cut, incarnation) ||
        memcmp(incarnation, input.incarnation, 32) ||
        !bindings(disk, gate, &after) || !metadata(&before, &after) ||
        !yd_disk_opening_resume_active(opening, disk) ||
        !yd_retention_gate_cut_validate(gate, cut)) goto done;
    memcpy(digest, hash, 32);
    success = true;
done:
    if (root) pthread_mutex_unlock(&disk->root_lock);
    if (writer) pthread_mutex_unlock(&disk->writer);
    if (!success) {
        (void)yd_retention_gate_cut_fail(gate, cut);
        if (error && length) snprintf(error, length, "resume terminal evidence unavailable; preserve artifacts");
    }
    (void)pthread_setcancelstate(prior, NULL);
    return success;
}
