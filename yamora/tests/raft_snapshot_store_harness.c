#define _POSIX_C_SOURCE 200809L
#include "../src/consensus/snapshot_store.h"
#include "../src/disk_documents.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#define REQUIRE(x) do { if (!(x)) { \
    fprintf(stderr, "line %u: %s (%s)\n", __LINE__, #x, error); return 2; \
} } while (0)
static char error[512];
static const unsigned char cluster[16] = {1, 2, 3, 4};
static const unsigned char source[] = "# source\r\ncount: 7 # retained\r\n";
/* Faults are armed only after staging, except the explicit partial-write case. */
static int fault, crash, sync_count;
int __real_fsync(int fd);
int __real_linkat(int, const char *, int, const char *, int);
int __real_unlinkat(int, const char *, int);
ssize_t __real_pwrite(int, const void *, size_t, off_t);
int __wrap_fsync(int fd) {
    if (!fault && !crash)
        return __real_fsync(fd);
    sync_count++;
    if (crash == sync_count)
        _exit(93);
    if (fault == sync_count) {
        errno = EIO;
        return -1;
    }
    int result = __real_fsync(fd);
    if (crash == sync_count + 2)
        _exit(93);
    return result;
}
int __wrap_linkat(int a, const char *b, int c, const char *d, int e) {
    if (fault == 3) { errno = EIO; return -1; }
    int result = __real_linkat(a, b, c, d, e);
    if (!result && crash == 5)
        _exit(93);
    return result;
}
int __wrap_unlinkat(int fd, const char *name, int flags) {
    if (fault == 4) { errno = EIO; return -1; }
    int result = __real_unlinkat(fd, name, flags);
    if (!result && crash == 6)
        _exit(93);
    return result;
}
ssize_t __wrap_pwrite(int fd, const void *bytes, size_t size, off_t offset) {
    if (fault == 5) { fault = 6; return __real_pwrite(fd, bytes, size > 3 ? 3 : size, offset); }
    if (fault == 6) { errno = ENOSPC; return -1; }
    if (fault == 7) { fault = 8; errno = EINTR; return -1; }
    if (fault == 8) { fault = 0; return __real_pwrite(fd, bytes, size > 3 ? 3 : size, offset); }
    return __real_pwrite(fd, bytes, size, offset);
}
static YDRaftSnapshot *seed(const char *root, unsigned char manifest[256]) {
    YDRaftApplication *app = yd_raft_application_open(root, cluster, 32768, error, sizeof(error));
    if (!app)
        return NULL;
    YDRaftWrite request = {.id = {1}, .method = "PUT", .target = "/v1/collections/a/documents/b",
                           .body = source, .size = sizeof(source) - 1};
    YDRaftProposal proposal = {0};
    bool valid = yd_raft_application_prepare(app, &request, &proposal, error, sizeof(error)) == 1;
    YDRaftEntry entry = {.index = 1, .term = 1, .kind = YD_RAFT_COMMAND,
                         .command = proposal.command, .size = proposal.size};
    if (valid)
        valid = yd_raft_application_apply(app, &entry, error, sizeof(error));
    yd_raft_proposal_free(&proposal);
    YDRaftSnapshot *snapshot = valid ? yd_raft_snapshot_open(app, 3, error, sizeof(error)) : NULL;
    yd_raft_application_close(app);
    if (!snapshot)
        return NULL;
    if (!yd_raft_snapshot_seal(snapshot, NULL, NULL, error, sizeof(error)) ||
        !yd_raft_snapshot_manifest(snapshot, manifest)) {
        yd_raft_snapshot_close(snapshot);
        return NULL;
    }
    return snapshot;
}
static bool feed(YDRaftSnapshotStage *stage, YDRaftSnapshot *snapshot, unsigned char manifest[256]) {
    YDRaftSnapshotInfo info;
    if (!yd_raft_snapshot_decode(manifest, 256, cluster, 3, &info, error, sizeof(error)))
        return false;
    unsigned char bytes[4093];
    for (uint64_t at = 0; at < info.view.end;) {
        size_t size = info.view.end - at < sizeof(bytes) ? (size_t)(info.view.end - at) : sizeof(bytes);
        if (!yd_raft_snapshot_read(snapshot, at, bytes, size, error, sizeof(error)) ||
            !yd_raft_snapshot_stage_feed(stage, at, bytes, size, error, sizeof(error)))
            return false;
        at += size;
    }
    return true;
}
static bool publish(YDRaftSnapshotStore *store, YDRaftSnapshot *snapshot, unsigned char manifest[256],
                    char id[65]) {
    YDRaftSnapshotStage *stage = yd_raft_snapshot_stage_new(store, manifest, 256, error, sizeof(error));
    bool valid = stage && feed(stage, snapshot, manifest) &&
                 yd_raft_snapshot_stage_finish(stage, id, error, sizeof(error));
    yd_raft_snapshot_stage_close(stage);
    return valid;
}
static unsigned count(const char *root, const char *prefix) {
    DIR *dir = opendir(root);
    if (!dir)
        return 9999;
    unsigned n = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)))
        if (!strncmp(entry->d_name, prefix, strlen(prefix)))
            n++;
    closedir(dir);
    return n;
}
static bool cancelled(void *context, uint64_t done, uint64_t total) {
    (void)context; (void)done; (void)total;
    return false;
}
static int basic(const char *root, const char *directory, const char *restore) {
    unsigned char manifest[256], bytes[4093], compared[4093];
    YDRaftSnapshot *snapshot = seed(root, manifest);
    REQUIRE(snapshot);
    YDRaftSnapshotStore *store = yd_raft_snapshot_store_open(directory, cluster, 3, error, sizeof(error));
    REQUIRE(store);
    YDRaftSnapshotStage *stage = yd_raft_snapshot_stage_new(store, manifest, 256, error, sizeof(error));
    REQUIRE(stage && count(directory, ".incoming-") == 1);
    yd_raft_snapshot_store_close(store);
    REQUIRE(feed(stage, snapshot, manifest));
    char id[65];
    REQUIRE(yd_raft_snapshot_stage_finish(stage, id, error, sizeof(error)) && strlen(id) == 64);
    REQUIRE(!yd_raft_snapshot_stage_feed(stage, 0, bytes, 1, error, sizeof(error)));
    yd_raft_snapshot_stage_close(stage);
    REQUIRE(count(directory, ".incoming-") == 0);
    store = yd_raft_snapshot_store_open(directory, cluster, 3, error, sizeof(error));
    REQUIRE(store);
    REQUIRE(!yd_raft_snapshot_archive_open(store, id, cancelled, NULL, error, sizeof(error)));
    YDRaftSnapshotArchive *archive = yd_raft_snapshot_archive_open(store, id, NULL, NULL, error, sizeof(error));
    REQUIRE(archive);
    yd_raft_snapshot_store_close(store);
    unsigned char recovered[256];
    REQUIRE(yd_raft_snapshot_archive_manifest(archive, recovered) && !memcmp(recovered, manifest, 256));
    YDRaftSnapshotInfo info;
    REQUIRE(yd_raft_snapshot_decode(manifest, 256, cluster, 3, &info, error, sizeof(error)));
    char path[4096];
    int path_length = snprintf(path, sizeof(path), "%s/%s", restore, YD_DISK_FILE);
    REQUIRE(path_length > 0 && (size_t)path_length < sizeof(path));
    int fd = open(path, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
    REQUIRE(fd >= 0);
    for (uint64_t at = 0; at < info.view.end;) {
        size_t size = info.view.end - at < sizeof(bytes) ? (size_t)(info.view.end - at) : sizeof(bytes);
        REQUIRE(yd_raft_snapshot_archive_read(archive, at, bytes, size, error, sizeof(error)) &&
                yd_raft_snapshot_read(snapshot, at, compared, size, error, sizeof(error)) &&
                !memcmp(bytes, compared, size) && write(fd, bytes, size) == (ssize_t)size);
        at += size;
    }
    REQUIRE(!yd_raft_snapshot_archive_read(archive, info.view.end, bytes, 1, error, sizeof(error)) &&
            !yd_raft_snapshot_archive_read(archive, UINT64_MAX, bytes, 1, error, sizeof(error)) &&
            !yd_raft_snapshot_archive_read(archive, 0, bytes, 0, error, sizeof(error)) && !fsync(fd));
    close(fd);
    yd_raft_snapshot_archive_close(archive);
    yd_raft_snapshot_close(snapshot);
    YDRaftApplication *app = yd_raft_application_open(restore, cluster, 32768, error, sizeof(error));
    REQUIRE(app && yd_raft_application_position(app).index == 1);
    YDDisk *disk = yd_raft_application_disk(app);
    YDDiskView view = yd_disk_view(disk);
    YDDiskDocument document;
    REQUIRE(yd_disk_document_get(disk, &view, "a", "b", &document, error, sizeof(error)) == 1 &&
            document.length == sizeof(source) - 1 && !memcmp(document.body, source, document.length));
    yd_disk_document_free(&document);
    YDRaftWrite request = {.id = {1}, .method = "PUT", .target = "/v1/collections/a/documents/b",
                           .body = source, .size = sizeof(source) - 1};
    YDDiskReply reply;
    REQUIRE(yd_raft_application_receipt(app, &request, &reply, error, sizeof(error)) == 1 && reply.status == 201);
    yd_disk_reply_free(&reply);
    yd_raft_application_close(app);
    return 0;
}
static int invalid(const char *root, const char *directory) {
    unsigned char manifest[256], bytes[16384];
    YDRaftSnapshot *snapshot = seed(root, manifest);
    REQUIRE(snapshot);
    YDRaftSnapshotStore *store = yd_raft_snapshot_store_open(directory, cluster, 3, error, sizeof(error));
    REQUIRE(store && !yd_raft_snapshot_stage_new(store, manifest, 255, error, sizeof(error)));
    char id[65];
    for (unsigned test = 0; test < 5; test++) {
        YDRaftSnapshotStage *stage = yd_raft_snapshot_stage_new(store, manifest, 256, error, sizeof(error));
        REQUIRE(stage && yd_raft_snapshot_read(snapshot, 0, bytes, sizeof(bytes), error, sizeof(error)));
        if (test == 0)
            REQUIRE(yd_raft_snapshot_stage_feed(stage, 0, bytes, 7, error, sizeof(error)));
        if (test == 1)
            REQUIRE(!yd_raft_snapshot_stage_feed(stage, 1, bytes, 7, error, sizeof(error)));
        if (test == 2) {
            bytes[0] ^= 1;
            REQUIRE(!yd_raft_snapshot_stage_feed(stage, 0, bytes, 7, error, sizeof(error)));
        }
        if (test == 3) {
            bytes[9000] ^= 1;
            REQUIRE(yd_raft_snapshot_stage_feed(stage, 0, bytes, sizeof(bytes), error, sizeof(error)));
            YDRaftSnapshotInfo info;
            REQUIRE(yd_raft_snapshot_decode(manifest, 256, cluster, 3, &info, error, sizeof(error)));
            for (uint64_t at = sizeof(bytes); at < info.view.end;) {
                size_t n = info.view.end - at < sizeof(bytes) ? (size_t)(info.view.end - at) : sizeof(bytes);
                REQUIRE(yd_raft_snapshot_read(snapshot, at, bytes, n, error, sizeof(error)) &&
                        yd_raft_snapshot_stage_feed(stage, at, bytes, n, error, sizeof(error)));
                at += n;
            }
        }
        if (test == 4) {
            fault = 5;
            REQUIRE(!yd_raft_snapshot_stage_feed(stage, 0, bytes, 7, error, sizeof(error)));
            fault = 0;
        }
        memset(id, 'x', sizeof(id));
        REQUIRE(!yd_raft_snapshot_stage_finish(stage, id, error, sizeof(error)) && !id[0]);
        REQUIRE(!yd_raft_snapshot_stage_feed(stage, 0, bytes, 7, error, sizeof(error)));
        yd_raft_snapshot_stage_close(stage);
        REQUIRE(count(directory, ".incoming-") == 0 && count(directory, "") == 2);
    }
    fault = 7;
    REQUIRE(publish(store, snapshot, manifest, id)); /* EINTR and short writes complete. */
    fault = 0;
    yd_raft_snapshot_store_close(store);
    yd_raft_snapshot_close(snapshot);
    return 0;
}
static int conflicts(const char *root, const char *directory) {
    unsigned char manifest[256];
    YDRaftSnapshot *snapshot = seed(root, manifest);
    REQUIRE(snapshot);
    YDRaftSnapshotStore *store = yd_raft_snapshot_store_open(directory, cluster, 3, error, sizeof(error));
    char id[65], again[65], path[4096];
    REQUIRE(store && publish(store, snapshot, manifest, id) && publish(store, snapshot, manifest, again) &&
            !strcmp(id, again) && count(directory, ".incoming-") == 0 && count(directory, "") == 3);
    int path_length = snprintf(path, sizeof(path), "%s/%s.snapshot", directory, id);
    REQUIRE(path_length > 0 && (size_t)path_length < sizeof(path));
    REQUIRE(!chmod(path, 0600));
    int fd = open(path, O_RDWR | O_CLOEXEC);
    struct stat before, after;
    unsigned char byte;
    REQUIRE(fd >= 0 && pread(fd, &byte, 1, 9000) == 1);
    byte ^= 1;
    REQUIRE(pwrite(fd, &byte, 1, 9000) == 1 && !fsync(fd) && !fchmod(fd, 0400) && !fstat(fd, &before));
    REQUIRE(!yd_raft_snapshot_archive_open(store, id, NULL, NULL, error, sizeof(error)) &&
            !publish(store, snapshot, manifest, again) && !again[0] && !fstat(fd, &after) &&
            before.st_ino == after.st_ino && before.st_size == after.st_size &&
            count(directory, ".incoming-") == 0);
    unsigned char retained;
    REQUIRE(pread(fd, &retained, 1, 9000) == 1 && retained == byte);
    close(fd);
    yd_raft_snapshot_store_close(store);
    yd_raft_snapshot_close(snapshot);
    return 0;
}
static int faults(const char *root, const char *directory) {
    unsigned char manifest[256];
    YDRaftSnapshot *snapshot = seed(root, manifest);
    REQUIRE(snapshot);
    for (int test = 1; test <= 4; test++) {
        char subdir[4096];
        int path_length = snprintf(subdir, sizeof(subdir), "%s/fault-%d", directory, test);
        REQUIRE(path_length > 0 && (size_t)path_length < sizeof(subdir));
        REQUIRE(!mkdir(subdir, 0700));
        YDRaftSnapshotStore *store = yd_raft_snapshot_store_open(subdir, cluster, 3, error, sizeof(error));
        REQUIRE(store);
        YDRaftSnapshotStage *stage = yd_raft_snapshot_stage_new(store, manifest, 256, error, sizeof(error));
        REQUIRE(stage && feed(stage, snapshot, manifest));
        fault = test; sync_count = 0;
        char id[65];
        REQUIRE(!yd_raft_snapshot_stage_finish(stage, id, error, sizeof(error)) && !id[0]);
        fault = 0;
        REQUIRE(count(subdir, "") == (test == 4 ? 4U : 3U) &&
                count(subdir, ".incoming-") == (test == 2 ? 0U : 1U));
        REQUIRE(!yd_raft_snapshot_stage_finish(stage, id, error, sizeof(error)));
        yd_raft_snapshot_stage_close(stage);
        REQUIRE(!count(subdir, ".incoming-") && publish(store, snapshot, manifest, id));
        YDRaftSnapshotArchive *archive = yd_raft_snapshot_archive_open(store, id, NULL, NULL, error, sizeof(error));
        REQUIRE(archive && count(subdir, "") == 3);
        yd_raft_snapshot_archive_close(archive);
        stage = yd_raft_snapshot_stage_new(store, manifest, 256, error, sizeof(error));
        REQUIRE(stage && feed(stage, snapshot, manifest));
        fault = 2; sync_count = 0; /* Existing verified archive must also be synced. */
        REQUIRE(!yd_raft_snapshot_stage_finish(stage, id, error, sizeof(error)) && !id[0]);
        fault = 0;
        yd_raft_snapshot_stage_close(stage);
        REQUIRE(publish(store, snapshot, manifest, id) && count(subdir, "") == 3);
        yd_raft_snapshot_store_close(store);
    }
    yd_raft_snapshot_close(snapshot);
    return 0;
}
static int crashes(const char *root, const char *directory) {
    unsigned char manifest[256];
    YDRaftSnapshot *snapshot = seed(root, manifest);
    REQUIRE(snapshot);
    unsigned char digest[32];
    unsigned int digest_size;
    REQUIRE(EVP_Digest(manifest, 256, digest, &digest_size, EVP_sha256(), NULL) == 1 && digest_size == 32);
    char expected[65];
    for (unsigned i = 0; i < 32; i++)
        snprintf(expected + 2 * i, 3, "%02x", digest[i]);
    for (int test = 1; test <= 6; test++) {
        char subdir[4096];
        int path_length = snprintf(subdir, sizeof(subdir), "%s/crash-%d", directory, test);
        REQUIRE(path_length > 0 && (size_t)path_length < sizeof(subdir));
        REQUIRE(!mkdir(subdir, 0700));
        YDRaftSnapshotStore *store = yd_raft_snapshot_store_open(subdir, cluster, 3, error, sizeof(error));
        REQUIRE(store);
        pid_t child = fork();
        REQUIRE(child >= 0);
        if (!child) {
            YDRaftSnapshotStage *stage = yd_raft_snapshot_stage_new(store, manifest, 256, error, sizeof(error));
            if (!stage || !feed(stage, snapshot, manifest))
                _exit(91);
            crash = test; sync_count = 0;
            char id[65];
            yd_raft_snapshot_stage_finish(stage, id, error, sizeof(error));
            _exit(92);
        }
        int status;
        REQUIRE(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 93);
        REQUIRE(count(subdir, expected) == (test == 1 || test == 3 ? 0U : 1U));
        YDRaftSnapshotArchive *before = yd_raft_snapshot_archive_open(store, expected, NULL, NULL,
                                                                     error, sizeof(error));
        REQUIRE((before != NULL) == (test != 1 && test != 3));
        yd_raft_snapshot_archive_close(before);
        unsigned leftovers = count(subdir, ".incoming-");
        char id[65];
        REQUIRE(publish(store, snapshot, manifest, id) && count(subdir, ".incoming-") == leftovers);
        YDRaftSnapshotArchive *archive = yd_raft_snapshot_archive_open(store, id, NULL, NULL, error, sizeof(error));
        REQUIRE(archive);
        yd_raft_snapshot_archive_close(archive);
        yd_raft_snapshot_store_close(store);
    }
    yd_raft_snapshot_close(snapshot);
    return 0;
}
static int security(const char *root, const char *directory) {
    unsigned char manifest[256];
    YDRaftSnapshot *snapshot = seed(root, manifest);
    REQUIRE(snapshot);
    REQUIRE(!chmod(directory, 0770) && !yd_raft_snapshot_store_open(directory, cluster, 3, error, sizeof(error)) &&
            !chmod(directory, 0700));
    unsigned char zero[16] = {0};
    REQUIRE(!yd_raft_snapshot_store_open(directory, zero, 3, error, sizeof(error)) &&
            !yd_raft_snapshot_store_open(directory, cluster, 4, error, sizeof(error)));
    YDRaftSnapshotStore *store = yd_raft_snapshot_store_open(directory, cluster, 3, error, sizeof(error));
    REQUIRE(store);
    char id[65], path[4096], target[4096];
    REQUIRE(publish(store, snapshot, manifest, id));
    int path_length = snprintf(path, sizeof(path), "%s/%s.snapshot", directory, id);
    REQUIRE(path_length > 0 && (size_t)path_length < sizeof(path));
    REQUIRE(!yd_raft_snapshot_archive_open(store, "../escape", NULL, NULL, error, sizeof(error)));
    char bad[65];
    memcpy(bad, id, 65); bad[0] = 'G';
    REQUIRE(!yd_raft_snapshot_archive_open(store, bad, NULL, NULL, error, sizeof(error)));
    REQUIRE(!chmod(path, 0444) && !yd_raft_snapshot_archive_open(store, id, NULL, NULL, error, sizeof(error)) &&
            !chmod(path, 0400));
    unsigned char wrong[16] = {9};
    YDRaftSnapshotStore *other = yd_raft_snapshot_store_open(directory, wrong, 3, error, sizeof(error));
    REQUIRE(other && !yd_raft_snapshot_archive_open(other, id, NULL, NULL, error, sizeof(error)) &&
            !yd_raft_snapshot_stage_new(other, manifest, 256, error, sizeof(error)));
    yd_raft_snapshot_store_close(other);
    path_length = snprintf(target, sizeof(target), "%s/retained", directory);
    REQUIRE(path_length > 0 && (size_t)path_length < sizeof(target));
    memcpy(bad, id, 65); bad[0] = id[0] == 'a' ? 'b' : 'a';
    char renamed[4096];
    path_length = snprintf(renamed, sizeof(renamed), "%s/%s.snapshot", directory, bad);
    REQUIRE(path_length > 0 && (size_t)path_length < sizeof(renamed));
    REQUIRE(!rename(path, renamed) &&
            !yd_raft_snapshot_archive_open(store, bad, NULL, NULL, error, sizeof(error)) &&
            !rename(renamed, path));
    REQUIRE(!chmod(path, 0600));
    int fd = open(path, O_WRONLY | O_APPEND | O_CLOEXEC);
    REQUIRE(fd >= 0 && write(fd, "x", 1) == 1 && !fchmod(fd, 0400));
    close(fd);
    REQUIRE(!yd_raft_snapshot_archive_open(store, id, NULL, NULL, error, sizeof(error)));
    REQUIRE(!rename(path, target) && !symlink(target, path));
    REQUIRE(!yd_raft_snapshot_archive_open(store, id, NULL, NULL, error, sizeof(error)) &&
            !publish(store, snapshot, manifest, bad) && !unlink(path) && !mkfifo(path, 0600));
    REQUIRE(!yd_raft_snapshot_archive_open(store, id, NULL, NULL, error, sizeof(error)) &&
            !publish(store, snapshot, manifest, bad) && !unlink(path));
    REQUIRE(!symlink(directory, path) && !yd_raft_snapshot_store_open(path, cluster, 3, error, sizeof(error)));
    REQUIRE(count(directory, ".incoming-") == 0);
    yd_raft_snapshot_store_close(store);
    yd_raft_snapshot_close(snapshot);
    return 0;
}
typedef struct {
    YDRaftSnapshotStore *store;
    YDRaftSnapshot *snapshot;
    unsigned char *manifest;
    bool valid;
    char id[65], message[512];
} Concurrent;
static void *publish_thread(void *context) {
    Concurrent *c = context;
    YDRaftSnapshotStage *stage = yd_raft_snapshot_stage_new(c->store, c->manifest, 256,
                                                          c->message, sizeof(c->message));
    YDRaftSnapshotInfo info;
    c->valid = stage && yd_raft_snapshot_decode(c->manifest, 256, cluster, 3, &info,
                                               c->message, sizeof(c->message));
    unsigned char bytes[4093];
    uint64_t at = 0;
    while (c->valid && at < info.view.end) {
        size_t size = info.view.end - at < sizeof(bytes) ? (size_t)(info.view.end - at) : sizeof(bytes);
        c->valid = yd_raft_snapshot_read(c->snapshot, at, bytes, size, c->message, sizeof(c->message)) &&
                   yd_raft_snapshot_stage_feed(stage, at, bytes, size, c->message, sizeof(c->message));
        at += size;
    }
    c->valid = c->valid && yd_raft_snapshot_stage_finish(stage, c->id, c->message, sizeof(c->message));
    yd_raft_snapshot_stage_close(stage);
    if (c->valid) {
        YDRaftSnapshotArchive *archive = yd_raft_snapshot_archive_open(c->store, c->id, NULL, NULL,
                                                                     c->message, sizeof(c->message));
        c->valid = archive && yd_raft_snapshot_archive_read(archive, 0, bytes, sizeof(bytes),
                                                           c->message, sizeof(c->message));
        yd_raft_snapshot_archive_close(archive);
    }
    return NULL;
}
static int concurrent(const char *root, const char *directory) {
    unsigned char manifest[256];
    YDRaftSnapshot *snapshot = seed(root, manifest);
    REQUIRE(snapshot);
    YDRaftSnapshotStore *store = yd_raft_snapshot_store_open(directory, cluster, 3, error, sizeof(error));
    REQUIRE(store);
    pthread_t threads[6];
    Concurrent calls[6];
    for (unsigned i = 0; i < 6; i++) {
        calls[i] = (Concurrent){.store = store, .snapshot = snapshot, .manifest = manifest};
        REQUIRE(!pthread_create(&threads[i], NULL, publish_thread, &calls[i]));
    }
    for (unsigned i = 0; i < 6; i++)
        REQUIRE(!pthread_join(threads[i], NULL) && calls[i].valid && !strcmp(calls[0].id, calls[i].id));
    REQUIRE(count(directory, ".incoming-") == 0 && count(directory, "") == 3);
    yd_raft_snapshot_store_close(store);
    yd_raft_snapshot_close(snapshot);
    return 0;
}
int main(int argc, char **argv) {
    if (argc != 3)
        return 2;
    char root[4096], directory[4096], restore[4096];
    snprintf(root, sizeof(root), "%s/source", argv[1]);
    snprintf(directory, sizeof(directory), "%s/archive", argv[1]);
    snprintf(restore, sizeof(restore), "%s/restore", argv[1]);
    REQUIRE(!mkdir(root, 0700) && !mkdir(directory, 0700) && !mkdir(restore, 0700));
    if (!strcmp(argv[2], "basic")) return basic(root, directory, restore);
    if (!strcmp(argv[2], "invalid")) return invalid(root, directory);
    if (!strcmp(argv[2], "conflicts")) return conflicts(root, directory);
    if (!strcmp(argv[2], "faults")) return faults(root, directory);
    if (!strcmp(argv[2], "crashes")) return crashes(root, directory);
    if (!strcmp(argv[2], "concurrent")) return concurrent(root, directory);
    if (!strcmp(argv[2], "security")) return security(root, directory);
    return 2;
}
