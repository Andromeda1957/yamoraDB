#define _POSIX_C_SOURCE 200809L
#include "backup.h"
#include "application_internal.h"
#include "application_retire.h"
#include "capture_internal.h"
#include "raft_internal.h"
#include "recovery.h"
#include "snapshot_internal.h"
#include "snapshot_restore.h"
#include "snapshot_store_internal.h"
#include "../binary.h"
#include "../disk_internal.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#define MANIFEST_SIZE 512U
#define PAIR ".yamora-backup-pair"
#define MANIFEST "manifest"
#define ARCHIVES "archives"
#define JOURNAL "journal"
struct YDRaftBackup {
    YDRaftMeta meta;
    uint32_t configuration;
    YDDisk *journal, *application;
    YDRaftSnapshot *image;
    YDRaftSnapshotReference *base, *selected;
    size_t cache;
};
static bool fail(char *error, size_t length) {
    return yd_disk_error(error, length, "cluster backup unavailable, incomplete or mismatched");
}
static bool nonzero(const unsigned char *bytes, size_t size) {
    unsigned char value = 0;
    for (size_t i = 0; i < size; i++) value |= bytes[i];
    return value != 0;
}
static uint32_t get32(const unsigned char *p) {
    uint32_t value = 0;
    for (unsigned i = 0; i < 4; i++) value |= (uint32_t)p[i] << (8 * i);
    return value;
}
static uint64_t get64(const unsigned char *p) {
    uint64_t value = 0;
    for (unsigned i = 0; i < 8; i++) value |= (uint64_t)p[i] << (8 * i);
    return value;
}
static void put32(unsigned char *p, uint32_t value) {
    for (unsigned i = 0; i < 4; i++) p[i] = (unsigned char)(value >> (8 * i));
}
static void put64(unsigned char *p, uint64_t value) {
    for (unsigned i = 0; i < 8; i++) p[i] = (unsigned char)(value >> (8 * i));
}
static bool digest(const void *bytes, size_t size, unsigned char out[32]) {
    size_t n = 0;
    return EVP_Q_digest(NULL, "SHA256", NULL, bytes, size, out, &n) == 1 && n == 32;
}
static void hex(const unsigned char bytes[32], char name[YD_RAFT_SNAPSHOT_ID]) {
    static const char digits[] = "0123456789abcdef";
    for (unsigned i = 0; i < 32; i++) {
        name[2 * i] = digits[bytes[i] >> 4];
        name[2 * i + 1] = digits[bytes[i] & 15];
    }
    name[64] = 0;
}
static bool read_all(int fd, uint64_t offset, void *buffer, size_t size) {
    unsigned char *bytes = buffer;
    while (size) {
        ssize_t n = pread(fd, bytes, size, (off_t)offset);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        bytes += n; offset += (size_t)n; size -= (size_t)n;
    }
    return true;
}
static bool write_all(int fd, const void *buffer, size_t size) {
    const unsigned char *bytes = buffer;
    while (size) {
        ssize_t n = write(fd, bytes, size);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        bytes += n; size -= (size_t)n;
    }
    return true;
}
static bool trusted(int fd) {
    struct stat s;
    return fd >= 0 && !fstat(fd, &s) && S_ISDIR(s.st_mode) &&
        s.st_uid == geteuid() && !(s.st_mode & (S_IWGRP | S_IWOTH));
}
static int directory(int parent, const char *name) {
    return openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
}
static bool empty(int fd) {
    int copy = directory(fd, ".");
    DIR *scan = copy >= 0 ? fdopendir(copy) : NULL;
    if (!scan) { if (copy >= 0) close(copy); return false; }
    bool valid = true;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(scan);
        if (!entry) { valid = !errno; break; }
        if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) { valid = false; break; }
    }
    closedir(scan);
    return valid;
}
static int file(int parent, const char *name, uint64_t expected) {
    int fd = openat(parent, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    struct stat s;
    if (fd >= 0 && !fstat(fd, &s) && S_ISREG(s.st_mode) && s.st_uid == geteuid() &&
        s.st_nlink == 1 && !(s.st_mode & (S_IRWXG | S_IRWXO)) &&
        s.st_size >= 0 && (uint64_t)s.st_size == expected && !flock(fd, LOCK_SH | LOCK_NB))
        return fd;
    if (fd >= 0) close(fd);
    return -1;
}
static bool create(int parent, const char *name, const void *bytes, size_t size) {
    int fd = openat(parent, name, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW | O_CLOEXEC, 0600);
    bool valid = fd >= 0 && write_all(fd, bytes, size) && !fsync(fd);
    if (fd >= 0) close(fd);
    return valid && !fsync(parent);
}
static bool report(YDRaftSnapshotProgress progress, void *context, uint64_t at, uint64_t end) {
    return !progress || progress(context, at, end);
}
/* No live physical journal export: copy only logical keys into a new native
 * incarnation. A fenced source's ownership/birth metadata is deliberately never
 * cloned. Pins retain its ordinary logical read authority and producer custody. */
static bool journal_scan(YDDisk *source, const YDRaftMeta *meta, uint32_t configuration, YDDiskTxn *txn, YDDisk *compare,
    YDRaftSnapshotProgress progress, void *context, char *error, size_t length) {
    YDDiskView view = yd_disk_view(source);
    YDRaft core = {.disk = source, .meta = *meta};
    unsigned char key[YD_DISK_KEY_LIMIT], expected[144];
    size_t size, meta_size = yd_raft_encode_meta(meta, expected);
    uint64_t value, entries = 0, terms = 0, prior = meta->snapshot.term;
    bool had_meta = false, had_configuration = false, valid = view.format == 5 && !view.documents && !view.collections &&
        !view.bytes && !view.revision && meta->last >= meta->snapshot.index &&
        yd_raft_membership_recover(&core, &view);
    YDDiskCursor *cursor = valid ? yd_disk_cursor(source, &view, NULL, 0, false, error, length) : NULL;
    valid = valid && cursor;
    int next = 0;
    while (valid && (next = yd_disk_next(cursor, key, sizeof(key), &size, &value, error, length)) == 1) {
        unsigned char *bytes = NULL;
        size_t n = 0;
        bool scalar = size == 12 && !memcmp(key, "\0YRT", 4);
        if (size == 4 && !memcmp(key, "\0YRM", 4)) {
            bytes = yd_disk_record(source, &view, value, &n, error, length);
            valid = !had_meta && bytes && n == meta_size && !memcmp(bytes, expected, n);
            had_meta = true;
        } else if (size == 12 && (!memcmp(key, "\0YRE", 4) || scalar)) {
            uint64_t index = 0;
            for (unsigned i = 4; i < 12; i++) index = (index << 8) | key[i];
            /* Unreachable old suffix keys have no recovery authority. */
            if (index > meta->last || index <= meta->snapshot.index) {
                valid = report(progress, context, entries, meta->last - meta->snapshot.index);
                continue;
            }
            if (scalar) {
                uint64_t term = 0;
                valid = index == meta->snapshot.index + ++terms && value && value <= meta->term &&
                    yd_raft_term(&core, index, &term) && term == value;
            } else {
                YDRaftEntry entry = {0};
                valid = index == meta->snapshot.index + ++entries && yd_raft_entry(&core, index, &entry) &&
                    entry.term >= prior && entry.term <= meta->term;
                if (valid) {
                    n = entry.size + 40;
                    bytes = entry.allocation;
                    entry.allocation = NULL;
                    prior = entry.term;
                }
                yd_raft_entry_free(&entry);
            }
        } else if (size == 4 && !memcmp(key, "\0YRC", 4)) {
            /* Recover through the ordinary Raft validator. CONF1 stores an
             * initial voter bitmask and the packed checkpoint membership;
             * neither is a voter count or a suffix-replayed configuration. */
            bytes = yd_disk_record(source, &view, value, &n, error, length);
            valid = !had_configuration && bytes && n == 24 && !memcmp(bytes, "YDRCONF1", 8) &&
                get64(bytes + 8) == core.bootstrap_voters &&
                get64(bytes + 16) == core.configuration_base &&
                (configuration ? configuration == core.configuration_base :
                    !meta->membership_required);
            had_configuration = true;
        } else valid = false;
        if (valid && compare) {
            YDDiskView other = yd_disk_view(compare);
            uint64_t offset = 0;
            valid = yd_disk_get(compare, &other, key, size, &offset, error, length) == 1;
            if (valid && scalar) valid = offset == value;
            else if (valid) {
                size_t count = 0;
                unsigned char *actual = yd_disk_record(compare, &other, offset, &count, error, length);
                valid = actual && count == n && !memcmp(actual, bytes, n);
                free(actual);
            }
        }
        if (valid && txn) {
            uint64_t destination = value;
            valid = (scalar || yd_disk_append(txn, bytes, n, &destination, error, length)) &&
                yd_disk_put(txn, key, size, destination, error, length);
        }
        free(bytes);
        if (valid) valid = report(progress, context, entries, meta->last - meta->snapshot.index);
    }
    yd_disk_cursor_free(cursor);
    bool needs_configuration = configuration || meta->membership_required;
    return valid && next == 0 && had_meta && (had_configuration || !needs_configuration) &&
        entries == meta->last - meta->snapshot.index && entries == terms &&
        yd_raft_membership_rebuild(&core);
}
static bool hash_file(int fd, uint64_t end, unsigned char hash[32],
    YDRaftSnapshotProgress progress, void *context) {
    EVP_MD_CTX *digest_context = EVP_MD_CTX_new();
    unsigned char *bytes = malloc(YD_DISK_CHECKPOINT_CHUNK);
    unsigned int n = 0;
    bool valid = digest_context && bytes && EVP_DigestInit_ex(digest_context, EVP_sha256(), NULL) == 1;
    for (uint64_t at = 0; valid && at < end;) {
        size_t count = end - at < YD_DISK_CHECKPOINT_CHUNK ? (size_t)(end - at) : YD_DISK_CHECKPOINT_CHUNK;
        valid = report(progress, context, at, end) && read_all(fd, at, bytes, count) &&
            EVP_DigestUpdate(digest_context, bytes, count) == 1;
        at += count;
    }
    valid = valid && report(progress, context, end, end) &&
        EVP_DigestFinal_ex(digest_context, hash, &n) == 1 && n == 32;
    EVP_MD_CTX_free(digest_context);
    free(bytes);
    return valid;
}
static YDRaftSnapshotReference *reference(YDRaftSnapshotStore *store, int archives,
    const unsigned char identity[32], const YDRaftSnapshotBase *expected,
    const YDRaftMeta *meta, char *error, size_t length) {
    YDRaftSnapshotBase base = {0};
    if (expected) base = *expected;
    else {
        char id[YD_RAFT_SNAPSHOT_ID], name[80];
        hex(identity, id);
        memcpy(name, id, 64); memcpy(name + 64, ".snapshot", 10);
        int fd = openat(archives, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
        unsigned char manifest[YD_RAFT_SNAPSHOT_MANIFEST];
        YDRaftSnapshotInfo info;
        bool valid = fd >= 0 && read_all(fd, 0, manifest, sizeof(manifest)) &&
            yd_raft_snapshot_decode(manifest, sizeof(manifest), meta->cluster, meta->voters,
                &info, error, length) && info.applied.index <= meta->snapshot.index &&
                info.applied.term <= meta->snapshot.term;
        if (fd >= 0) close(fd);
        if (!valid) return NULL;
        base.index = info.applied.index; base.term = info.applied.term;
        memcpy(base.archive, identity, 32);
    }
    YDRaftSnapshotReference *result = NULL;
    return yd_raft_snapshot_reference_open(store, &base, &result, error, length) == YD_RAFT_ARCHIVE_OK
        ? result : NULL;
}
static YDRaftBackup *backup_capture(YDRaft *raft, YDRaftApplication *application,
    uint32_t configuration, size_t cache, char *error, size_t length) {
    if (!raft || !application) { fail(error, length); return NULL; }
    YDRaftApplied applied = yd_raft_application_position(application);
    if (raft->role == YD_RAFT_FAILED || yd_raft_application_failed(application) ||
        cache < 32768 || cache > 1024ULL * 1024 * 1024 || !applied.index || applied.index != raft->meta.committed) {
        fail(error, length); return NULL;
    }
    YDRaftBackup *volatile b = calloc(1, sizeof(*b));
    if (!b) { fail(error, length); return NULL; }
    b->meta = raft->meta; b->configuration = configuration; b->cache = cache;
    b->journal = yd_disk_pin(raft->disk, cache, error, length);
    YDRaftCheckpoint position;
    b->application = yd_raft_application_pin(application, cache, &position, error, length);
    b->image = yd_raft_snapshot_open(application, raft->meta.voters, error, length);
    bool valid = b->journal && b->application && b->image && !memcmp(position.cluster, b->meta.cluster, 16) &&
        position.applied.index == applied.index && position.applied.term == applied.term;
    int archives = b->meta.snapshot.index ? directory(raft->directory, YD_RAFT_ARCHIVE_DIRECTORY) : -1;
    YDRaftSnapshotStore *store = archives >= 0 ? yd_raft_snapshot_store_open_at(archives,
        b->meta.cluster, b->meta.voters, error, length) : NULL;
    if (valid && b->meta.snapshot.index) {
        b->base = store ? reference(store, archives, b->meta.snapshot.archive, &b->meta.snapshot, &b->meta, error, length) : NULL;
        valid = b->base != NULL;
    }
    if (valid && nonzero(b->meta.application, 32)) {
        b->selected = store ? reference(store, archives, b->meta.application, NULL, &b->meta, error, length) : NULL;
        valid = b->selected != NULL;
    }
    yd_raft_snapshot_store_close(store);
    if (archives >= 0) close(archives);
    if (valid) return b;
    yd_raft_backup_close(b); fail(error, length); return NULL;
}
static void backup_cancelled(void *context) { yd_raft_backup_close(context); }
YDRaftBackup *yd_raft_backup_capture(YDRaft *raft, YDRaftApplication *application,
    uint32_t configuration, size_t cache, char *error, size_t length) {
    int previous;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous)) return NULL;
    YDRaftBackup *backup = backup_capture(raft, application, configuration, cache, error, length);
    pthread_cleanup_push(backup_cancelled, backup);
    (void)pthread_setcancelstate(previous, NULL);
    if (previous == PTHREAD_CANCEL_ENABLE) pthread_testcancel();
    pthread_cleanup_pop(0);
    return backup;
}
void yd_raft_backup_close(YDRaftBackup *b) {
    if (!b) return;
    yd_raft_snapshot_reference_close(b->base);
    yd_raft_snapshot_reference_close(b->selected);
    yd_disk_close(b->journal); yd_disk_close(b->application);
    yd_raft_snapshot_close(b->image);
    free(b);
}

static bool copy_archive(const YDRaftSnapshotArchive *archive, int directory_fd,
    const YDRaftMeta *meta, uint32_t capabilities, YDRaftSnapshotProgress progress, void *context,
    char *error, size_t length) {
    unsigned char manifest[YD_RAFT_SNAPSHOT_MANIFEST];
    YDRaftSnapshotInfo info;
    bool valid = yd_raft_snapshot_archive_manifest(archive, manifest) &&
        yd_raft_snapshot_decode(manifest, sizeof(manifest), meta->cluster, meta->voters,
            &info, error, length) && info.capabilities == capabilities;
    YDRaftSnapshotStore *store = valid ? yd_raft_snapshot_store_open_at(directory_fd,
        meta->cluster, meta->voters, error, length) : NULL;
    YDRaftSnapshotStage *stage = store ? yd_raft_snapshot_stage_new(store, manifest,
        sizeof(manifest), error, length) : NULL;
    unsigned char *bytes = stage ? malloc(YD_DISK_CHECKPOINT_CHUNK) : NULL;
    valid = stage && bytes;
    for (uint64_t at = 0; valid && at < info.view.end;) {
        size_t count = info.view.end - at < YD_DISK_CHECKPOINT_CHUNK ? (size_t)(info.view.end - at) : YD_DISK_CHECKPOINT_CHUNK;
        valid = report(progress, context, at, info.view.end) &&
            yd_raft_snapshot_archive_read(archive, at, bytes, count, error, length) &&
            yd_raft_snapshot_stage_feed(stage, at, bytes, count, error, length);
        at += count;
    }
    char id[YD_RAFT_SNAPSHOT_ID];
    valid = valid && report(progress, context, info.view.end, info.view.end) &&
        yd_raft_snapshot_stage_finish(stage, id, error, length);
    free(bytes); yd_raft_snapshot_stage_close(stage); yd_raft_snapshot_store_close(store);
    return valid;
}
static bool write_reference(const YDRaftSnapshotReference *ref, int archives,
    const YDRaftMeta *meta, uint32_t capabilities, YDRaftSnapshotProgress progress, void *context,
    char *error, size_t length) {
    if (!ref) return true;
    YDRaftSnapshotArchive *archive = NULL;
    bool valid = yd_raft_snapshot_archive_open_reference(ref, progress, context, &archive,
        error, length) == YD_RAFT_ARCHIVE_OK &&
        copy_archive(archive, archives, meta, capabilities, progress, context, error, length);
    yd_raft_snapshot_archive_close(archive);
    return valid;
}
static bool decode(const unsigned char manifest[MANIFEST_SIZE], const unsigned char cluster[16],
    unsigned node, unsigned voters, YDRaftMeta *meta, YDRaftSnapshotInfo *info,
    char *error, size_t length) {
    unsigned char hash[32], canonical[144];
    YDRaftMeta identity = {.node = node, .voters = voters};
    if (cluster) memcpy(identity.cluster, cluster, 16);
    uint64_t extent = get64(manifest + 40);
    uint32_t n = get32(manifest + 36);
    bool valid = cluster && node && node <= voters && voters >= 3 && voters <= YD_RAFT_VOTERS && (voters & 1) &&
        !memcmp(manifest, "YDBAK001", 8) && !memcmp(manifest + 8, cluster, 16) &&
        get32(manifest + 24) == node && get32(manifest + 28) == voters &&
        extent >= 3U * YD_DISK_PAGE && extent <= INT64_MAX && !(extent % YD_DISK_PAGE) &&
        (n == 64 || n == 112 || n == 144) && digest(manifest, 480, hash) &&
        !memcmp(hash, manifest + 480, 32) &&
        yd_raft_decode_meta(manifest + 80, n, &identity, meta) &&
        yd_raft_snapshot_decode(manifest + 224, 256, cluster, voters, info, error, length) &&
        info->applied.index && info->applied.index == meta->committed;
    if (valid) {
        size_t size = yd_raft_encode_meta(meta, canonical);
        valid = size == n && !memcmp(canonical, manifest + 80, sizeof(canonical));
    }
    return valid || fail(error, length);
}
static bool application_binding(YDDisk *journal, const YDRaftMeta *meta,
    const unsigned char manifest[256]) {
    uint64_t index = get64(manifest + 32);
    unsigned char hash[32];
    if (index == meta->snapshot.index)
        return digest(manifest, 256, hash) && !memcmp(hash, meta->snapshot.archive, 32);
    YDRaft core = {.disk = journal, .meta = *meta};
    YDRaftEntry entry = {0};
    bool valid = index > meta->snapshot.index && index == meta->committed &&
        yd_raft_entry(&core, index, &entry) && entry.term == get64(manifest + 40);
    unsigned char header[24] = {0};
    put64(header, entry.index); put64(header + 8, entry.term); header[16] = (unsigned char)entry.kind;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new(); unsigned int n = 0;
    valid = valid && ctx && EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
        EVP_DigestUpdate(ctx, header, sizeof(header)) == 1 &&
        (!entry.size || EVP_DigestUpdate(ctx, entry.command, entry.size) == 1) &&
        EVP_DigestFinal_ex(ctx, hash, &n) == 1 && n == 32 && !memcmp(hash, manifest + 104, 32);
    EVP_MD_CTX_free(ctx); yd_raft_entry_free(&entry);
    return valid;
}
bool yd_raft_backup_write(YDRaftBackup *b, const char *destination,
    YDRaftSnapshotProgress progress, void *context, char *error, size_t length) {
    if (!b || !destination) return fail(error, length);
    int root = open(destination, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    bool valid = trusted(root) && !flock(root, LOCK_EX | LOCK_NB) && empty(root) &&
        journal_scan(b->journal, &b->meta, b->configuration, NULL, NULL, progress, context, error, length) &&
        create(root, YD_BINARY_INITIALIZING, NULL, 0) &&
        !mkdirat(root, JOURNAL, 0700) && !mkdirat(root, ARCHIVES, 0700) && !fsync(root);
    int journal = valid ? directory(root, JOURNAL) : -1;
    int archives = valid ? directory(root, ARCHIVES) : -1;
    YDDisk *copy = journal >= 0 ? yd_disk_open_at(journal, true, b->cache, error, length) : NULL;
    YDDiskTxn *txn = copy ? yd_disk_begin_exclusive(copy, error, length) : NULL;
    valid = valid && txn && journal_scan(b->journal, &b->meta, b->configuration, txn, NULL, progress, context, error, length);
    if (valid) { valid = yd_disk_commit(txn, error, length); txn = NULL; }
    yd_disk_abort(txn);
    valid = valid && journal_scan(copy, &b->meta, b->configuration, NULL, NULL, progress, context, error, length) &&
        journal_scan(b->journal, &b->meta, b->configuration, NULL, copy, progress, context, error, length);
    unsigned char manifest[MANIFEST_SIZE] = {0};
    if (valid) {
        memcpy(manifest, "YDBAK001", 8); memcpy(manifest + 8, b->meta.cluster, 16);
        put32(manifest + 24, b->meta.node); put32(manifest + 28, b->meta.voters);
        put32(manifest + 32, b->configuration);
        put32(manifest + 36, (uint32_t)yd_raft_encode_meta(&b->meta, manifest + 80));
        put64(manifest + 40, yd_disk_view(copy).end);
        valid = !fsync(copy->fd) && hash_file(copy->fd, get64(manifest + 40), manifest + 48, progress, context) &&
            !fchmod(copy->fd, 0400) && !fsync(copy->fd);
    }
    char id[YD_RAFT_SNAPSHOT_ID];
    YDRaftSnapshotArchive *current = valid ? yd_raft_capture_archive(b->image, b->application,
        archives, b->meta.cluster, b->meta.voters, progress, context, id, error, length) : NULL;
    valid = valid && current && yd_raft_snapshot_archive_manifest(current, manifest + 224) &&
        application_binding(b->journal, &b->meta, manifest + 224) &&
        write_reference(b->base, archives, &b->meta, yd_disk_capabilities(b->application), progress, context, error, length) &&
        write_reference(b->selected, archives, &b->meta, yd_disk_capabilities(b->application), progress, context, error, length);
    YDRaftMeta decoded; YDRaftSnapshotInfo info;
    valid = valid && digest(manifest, 480, manifest + 480) &&
        decode(manifest, b->meta.cluster, b->meta.node, b->meta.voters, &decoded, &info, error, length) &&
        !fsync(journal) && !fsync(archives) && create(root, MANIFEST, manifest, sizeof(manifest)) &&
        !unlinkat(root, YD_BINARY_INITIALIZING, 0) && !fsync(root);
    yd_raft_snapshot_archive_close(current); yd_disk_close(copy);
    if (journal >= 0) close(journal);
    if (archives >= 0) close(archives);
    if (root >= 0) close(root);
    return valid || fail(error, length);
}

static bool same_directory(int first, int second) {
    struct stat a, b;
    return !fstat(first, &a) && !fstat(second, &b) && a.st_dev == b.st_dev && a.st_ino == b.st_ino;
}
static bool copy_file(int from, uint64_t size, int destination, const char *name,
    YDRaftSnapshotProgress progress, void *context) {
    int fd = openat(destination, name, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW | O_CLOEXEC, 0600);
    unsigned char *bytes = fd >= 0 ? malloc(YD_DISK_CHECKPOINT_CHUNK) : NULL;
    bool valid = bytes != NULL;
    for (uint64_t at = 0; valid && at < size;) {
        size_t count = size - at < YD_DISK_CHECKPOINT_CHUNK ? (size_t)(size - at) : YD_DISK_CHECKPOINT_CHUNK;
        valid = report(progress, context, at, size) && read_all(from, at, bytes, count) && write_all(fd, bytes, count);
        at += count;
    }
    valid = valid && report(progress, context, size, size) && !fsync(fd) && !fsync(destination);
    free(bytes); if (fd >= 0) close(fd);
    return valid;
}
static bool restore_application(const YDRaftSnapshotArchive *archive, int destination,
    const YDRaftMeta *meta, const YDRaftSnapshotInfo *info,
    YDRaftSnapshotProgress progress, void *context, char *error, size_t length) {
    int fd = openat(destination, YD_DISK_FILE, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW | O_CLOEXEC, 0600);
    unsigned char *bytes = fd >= 0 ? malloc(YD_DISK_CHECKPOINT_CHUNK) : NULL;
    bool valid = bytes != NULL;
    for (uint64_t at = 0; valid && at < info->view.end;) {
        size_t count = info->view.end - at < YD_DISK_CHECKPOINT_CHUNK ? (size_t)(info->view.end - at) : YD_DISK_CHECKPOINT_CHUNK;
        valid = report(progress, context, at, info->view.end) &&
            yd_raft_snapshot_archive_read(archive, at, bytes, count, error, length) && write_all(fd, bytes, count);
        at += count;
    }
    valid = valid && report(progress, context, info->view.end, info->view.end) && !fsync(fd) && !fsync(destination);
    free(bytes); if (fd >= 0) close(fd);
    YDRaftApplication *app = !valid ? NULL : info->capabilities
        ? yd_raft_application_open_capabilities_at(destination, false, meta->cluster,
            info->capabilities, 32768, error, length)
        : yd_raft_application_open_existing_at(destination, meta->cluster,
            32768, error, length);
    YDRaftSnapshot *image = app ? yd_raft_snapshot_open(app, meta->voters, error, length) : NULL;
    unsigned char expected[256], actual[256];
    YDRaftCheckpoint checkpoint = {.applied = info->applied, .capabilities = info->capabilities};
    memcpy(checkpoint.cluster, info->cluster, 16); memcpy(checkpoint.digest, info->entry_digest, 32);
    valid = app && image && yd_raft_snapshot_archive_manifest(archive, expected) &&
        yd_raft_snapshot_seal(image, progress, context, error, length) &&
        yd_raft_snapshot_manifest(image, actual) && !memcmp(expected, actual, 256) &&
        yd_raft_snapshot_application_validate(app, &checkpoint, &info->view, progress, context, error, length);
    yd_raft_snapshot_close(image); yd_raft_application_close(app);
    return valid;
}
bool yd_raft_backup_restore(const char *source, const char *documents_path, const char *journal_path,
    const unsigned char cluster[16], unsigned node, unsigned voters, size_t cache,
    YDRaftSnapshotProgress progress, void *context, char *error, size_t length) {
    if (!source || !documents_path || !journal_path || !cluster || cache < 32768 || cache > 1024ULL * 1024 * 1024)
        return fail(error, length);
    int cancellation;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancellation)) return fail(error, length);
    int root = open(source, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int manifest_fd = trusted(root) ? file(root, MANIFEST, MANIFEST_SIZE) : -1;
    unsigned char manifest[MANIFEST_SIZE] = {0}, hash[32];
    YDRaftMeta meta = {0}; YDRaftSnapshotInfo info = {0};
    struct stat fence;
    bool valid = manifest_fd >= 0 && fstatat(root, YD_BINARY_INITIALIZING, &fence, AT_SYMLINK_NOFOLLOW) < 0 &&
        errno == ENOENT && read_all(manifest_fd, 0, manifest, sizeof(manifest)) &&
        decode(manifest, cluster, node, voters, &meta, &info, error, length);
    int source_journal = valid ? directory(root, JOURNAL) : -1;
    int source_archives = valid ? directory(root, ARCHIVES) : -1;
    int native = trusted(source_journal) ? file(source_journal, YD_DISK_FILE, get64(manifest + 40)) : -1;
    valid = valid && native >= 0 && trusted(source_archives) &&
        hash_file(native, get64(manifest + 40), hash, progress, context) && !memcmp(hash, manifest + 48, 32);
    YDDisk *source_disk = valid ? yd_disk_open_at(source_journal, false, cache, error, length) : NULL;
    valid = valid && source_disk && journal_scan(source_disk, &meta, get32(manifest + 32), NULL, NULL, progress, context, error, length) &&
        application_binding(source_disk, &meta, manifest + 224);
    YDRaftSnapshotStore *store = valid ? yd_raft_snapshot_store_open_at(source_archives, cluster, voters, error, length) : NULL;
    char id[YD_RAFT_SNAPSHOT_ID];
    unsigned char current_id[32];
    if (valid) valid = digest(manifest + 224, 256, current_id);
    if (valid) hex(current_id, id);
    YDRaftSnapshotArchive *current = valid && store ? yd_raft_snapshot_archive_open(store, id, progress, context, error, length) : NULL;
    YDRaftSnapshotArchive *base = NULL, *selected = NULL;
    unsigned char current_manifest[256], selected_manifest[256];
    valid = valid && current && yd_raft_snapshot_archive_manifest(current, current_manifest) &&
        !memcmp(current_manifest, manifest + 224, 256);
    if (valid && meta.snapshot.index) {
        hex(meta.snapshot.archive, id);
        base = yd_raft_snapshot_archive_open(store, id, progress, context, error, length);
        unsigned char base_manifest[256]; YDRaftSnapshotInfo base_info;
        valid = base && yd_raft_snapshot_archive_manifest(base, base_manifest) &&
            yd_raft_snapshot_decode(base_manifest, 256, cluster, voters, &base_info, error, length) &&
            base_info.applied.index == meta.snapshot.index && base_info.applied.term == meta.snapshot.term &&
            base_info.capabilities == info.capabilities;
    }
    if (valid && nonzero(meta.application, 32)) {
        hex(meta.application, id);
        selected = yd_raft_snapshot_archive_open(store, id, progress, context, error, length);
        YDRaftSnapshotInfo selected_info;
        valid = selected && yd_raft_snapshot_archive_manifest(selected, selected_manifest) &&
            yd_raft_snapshot_decode(selected_manifest, 256, cluster, voters, &selected_info, error, length) &&
            selected_info.applied.index <= meta.snapshot.index && selected_info.applied.term <= meta.snapshot.term &&
            selected_info.capabilities == info.capabilities;
    }
    int documents = valid ? open(documents_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC) : -1;
    int journal = valid ? open(journal_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC) : -1;
    valid = valid && trusted(documents) && trusted(journal) && !same_directory(documents, journal) &&
        !same_directory(root, documents) && !same_directory(root, journal) &&
        !flock(documents, LOCK_EX | LOCK_NB) && !flock(journal, LOCK_EX | LOCK_NB) && empty(documents) && empty(journal);
    valid = valid && create(documents, YD_BINARY_INITIALIZING, NULL, 0) &&
        create(journal, YD_BINARY_INITIALIZING, NULL, 0) &&
        create(documents, PAIR, manifest, sizeof(manifest)) && create(journal, PAIR, manifest, sizeof(manifest)) &&
        copy_file(native, get64(manifest + 40), journal, YD_DISK_FILE, progress, context) &&
        !mkdirat(journal, YD_RAFT_ARCHIVE_DIRECTORY, 0700) && !fsync(journal);
    int archives = valid ? directory(journal, YD_RAFT_ARCHIVE_DIRECTORY) : -1;
    valid = valid && copy_archive(current, archives, &meta, info.capabilities, progress, context, error, length) &&
        (!base || copy_archive(base, archives, &meta, info.capabilities, progress, context, error, length)) &&
        (!selected || copy_archive(selected, archives, &meta, info.capabilities, progress, context, error, length));
    int target = valid ? fcntl(documents, F_DUPFD_CLOEXEC, 0) : -1;
    if (valid && selected) {
        valid = !mkdirat(documents, YD_RAFT_GENERATION_DIRECTORY, 0700) && !fsync(documents);
        int parent = valid ? directory(documents, YD_RAFT_GENERATION_DIRECTORY) : -1;
        char name[YD_RAFT_SNAPSHOT_ID];
        /* A restored layout is fresh data, never inherited retirement custody. */
        if (valid && meta.application_layout == 1) {
            for (unsigned n = 0; valid && n < YD_RAFT_APPLICATION_SLOTS; n++) {
                int count = snprintf(name, sizeof(name), "%s%u", YD_RAFT_APPLICATION_SLOT_PREFIX, n);
                valid = count > 0 && (size_t)count < sizeof(name) && !mkdirat(parent, name, 0700);
                int child = valid ? directory(parent, name) : -1;
                valid = valid && trusted(child) && empty(child) && !fsync(child);
                if (child >= 0) close(child);
            }
            memcpy(name, YD_RAFT_APPLICATION_SLOT_PREFIX "0", sizeof(YD_RAFT_APPLICATION_SLOT_PREFIX "0"));
        } else if (valid) {
            hex(meta.application, name);
            valid = !mkdirat(parent, name, 0700);
        }
        valid = valid && !fsync(parent);
        if (target >= 0) close(target);
        target = valid ? directory(parent, name) : -1;
        if (parent >= 0) close(parent);
    }
    valid = valid && target >= 0 && restore_application(current, target, &meta, &info, progress, context, error, length) &&
        (!selected || create(target, YD_RAFT_SNAPSHOT_CANDIDATE, selected_manifest, sizeof(selected_manifest)));
    YDDisk *restored_disk = valid ? yd_disk_open_at(journal, false, cache, error, length) : NULL;
    YDRaft core = {.disk = restored_disk, .directory = journal, .meta = meta};
    YDRaftApplication *app = !valid ? NULL : info.capabilities
        ? yd_raft_application_open_capabilities_at(target, false, cluster, info.capabilities,
            cache, error, length)
        : yd_raft_application_open_existing_at(target, cluster, cache, error, length);
    valid = valid && restored_disk && app && hash_file(restored_disk->fd, get64(manifest + 40), hash, progress, context) &&
        !memcmp(hash, manifest + 48, 32) && journal_scan(restored_disk, &meta, get32(manifest + 32), NULL, NULL, progress, context, error, length) &&
        yd_raft_recover_application(app, &core, progress, context, error, length) &&
        !fsync(target) && !fsync(archives) && !fsync(documents) && !fsync(journal) &&
        !unlinkat(documents, YD_BINARY_INITIALIZING, 0) && !fsync(documents) &&
        !unlinkat(journal, YD_BINARY_INITIALIZING, 0) && !fsync(journal);
    yd_raft_application_close(app); yd_disk_close(restored_disk); yd_disk_close(source_disk);
    yd_raft_snapshot_archive_close(current); yd_raft_snapshot_archive_close(base); yd_raft_snapshot_archive_close(selected);
    yd_raft_snapshot_store_close(store);
    int descriptors[] = {root, manifest_fd, source_journal, source_archives, native, documents, journal, archives, target};
    for (unsigned i = 0; i < sizeof(descriptors) / sizeof(*descriptors); i++) if (descriptors[i] >= 0) close(descriptors[i]);
    (void)pthread_setcancelstate(cancellation, NULL);
    return valid || fail(error, length);
}
bool yd_raft_backup_verify_pair(int documents, int journal, const unsigned char cluster[16],
    unsigned node, unsigned voters, char *error, size_t length) {
    if (!trusted(documents) || !trusted(journal) || same_directory(documents, journal)) return fail(error, length);
    struct stat first, second;
    int a = fstatat(documents, PAIR, &first, AT_SYMLINK_NOFOLLOW);
    int a_error = errno;
    int b = fstatat(journal, PAIR, &second, AT_SYMLINK_NOFOLLOW);
    int b_error = errno;
    if (a < 0 && a_error == ENOENT && b < 0 && b_error == ENOENT) return true;
    int x = file(documents, PAIR, MANIFEST_SIZE), y = file(journal, PAIR, MANIFEST_SIZE);
    unsigned char one[MANIFEST_SIZE], two[MANIFEST_SIZE];
    YDRaftMeta meta; YDRaftSnapshotInfo info;
    bool valid = x >= 0 && y >= 0 && read_all(x, 0, one, sizeof(one)) && read_all(y, 0, two, sizeof(two)) &&
        !memcmp(one, two, sizeof(one)) && decode(one, cluster, node, voters, &meta, &info, error, length);
    if (x >= 0) close(x);
    if (y >= 0) close(y);
    return valid || fail(error, length);
}
