#define _POSIX_C_SOURCE 200809L
#include "../src/consensus/snapshot_restore.h"
#include "../src/consensus/application_internal.h"
#include <dirent.h>
#include "../src/binary.h"
#include "../src/disk_documents.h"
#include "../src/disk_internal.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#define REQUIRE(x) do { if (!(x)) { \
    fprintf(stderr, "line %u: %s (%s)\n", __LINE__, #x, error); return 2; \
} } while (0)
static char error[512];
static const unsigned char cluster[16] = {1, 2, 3, 4};
static const unsigned char source[] = "# exact source\r\ncount: 7 # kept\r\n";
static int fault, crash, sync_count;
int __real_fsync(int);
int __real_linkat(int, const char *, int, const char *, int);
int __real_unlinkat(int, const char *, int);
ssize_t __real_write(int, const void *, size_t);
int __wrap_fsync(int fd) {
    if (!fault && !crash)
        return __real_fsync(fd);
    sync_count++;
    if (crash == sync_count) _exit(93);
    if (fault == sync_count) { errno = EIO; return -1; }
    return __real_fsync(fd);
}
int __wrap_linkat(int a, const char *b, int c, const char *d, int flags) {
    if (fault == 7) { errno = EIO; return -1; }
    int result = __real_linkat(a, b, c, d, flags);
    if (!result && crash == 7) _exit(93);
    return result;
}
int __wrap_unlinkat(int fd, const char *name, int flags) {
    if (fault == 8) { errno = EIO; return -1; }
    int result = __real_unlinkat(fd, name, flags);
    if (!result && crash == 8) _exit(93);
    return result;
}
ssize_t __wrap_write(int fd, const void *bytes, size_t size) {
    if (fault == 9 && size > 256) { fault = 10; return __real_write(fd, bytes, 3); }
    if (fault == 10) { errno = ENOSPC; return -1; }
    if (fault == 11 && size > 3U * YD_DISK_PAGE + 100U) {
        unsigned char *copy = malloc(size);
        if (!copy) { errno = ENOMEM; return -1; }
        memcpy(copy, bytes, size);
        copy[3U * YD_DISK_PAGE + 100U] ^= 1; /* Dead genesis root page. */
        ssize_t result = __real_write(fd, copy, size);
        free(copy);
        fault = 0;
        return result;
    }
    return __real_write(fd, bytes, size);
}
static bool tamper(YDRaftApplication *app) {
    YDDisk *disk = yd_raft_application_disk(app);
    YDDiskView view = yd_disk_view(disk);
    uint64_t offset;
    if (yd_disk_get(disk, &view, "\0YRA", 4, &offset, error, sizeof(error)) != 1)
        return false;
    size_t size;
    unsigned char *p = yd_disk_record(disk, &view, offset, &size, error, sizeof(error));
    if (!p || size != 96) { free(p); return false; }
    YDDiskTxn *txn = yd_disk_begin_exclusive(disk, error, sizeof(error));
    bool valid = txn && yd_disk_put(txn, "unknown", 7, 123, error, sizeof(error));
    yd_disk_set64(p + 24, yd_raft_application_position(app).index + 1);
    if (valid) {
        txn->log_enabled = txn->log_identity_set = true;
        memcpy(txn->log_identity, cluster, 16);
        valid = yd_disk_append(txn, p, size, &offset, error, sizeof(error)) &&
                yd_disk_put(txn, "\0YRA", 4, offset, error, sizeof(error));
    }
    free(p);
    if (valid) return yd_disk_commit(txn, error, sizeof(error));
    yd_disk_abort(txn);
    return false;
}
static YDRaftSnapshotArchive *seed(const char *root, const char *directory, bool malformed) {
    YDRaftApplication *app = yd_raft_application_open(root, cluster, 32768, error, sizeof(error));
    if (!app) return NULL;
    YDRaftWrite request = {.id = {1}, .method = "PUT", .target = "/v1/collections/a/documents/b",
                           .body = source, .size = sizeof(source) - 1};
    YDRaftProposal proposal = {0};
    bool valid = yd_raft_application_prepare(app, &request, &proposal, error, sizeof(error)) == 1;
    YDRaftEntry entry = {.index = 1, .term = 1, .kind = YD_RAFT_COMMAND,
                         .command = proposal.command, .size = proposal.size};
    valid = valid && yd_raft_application_apply(app, &entry, error, sizeof(error));
    yd_raft_proposal_free(&proposal);
    if (valid && malformed) {
        valid = tamper(app);
        yd_raft_application_close(app);
        app = valid ? yd_raft_application_open(root, cluster, 32768, error, sizeof(error)) : NULL;
        valid = app != NULL;
    }
    YDRaftSnapshot *snapshot = valid ? yd_raft_snapshot_open(app, 3, error, sizeof(error)) : NULL;
    yd_raft_application_close(app);
    unsigned char manifest[256], bytes[4093];
    YDRaftSnapshotInfo info;
    valid = snapshot && yd_raft_snapshot_seal(snapshot, NULL, NULL, error, sizeof(error)) &&
            yd_raft_snapshot_manifest(snapshot, manifest) &&
            yd_raft_snapshot_decode(manifest, 256, cluster, 3, &info, error, sizeof(error));
    YDRaftSnapshotStore *store = valid ? yd_raft_snapshot_store_open(directory, cluster, 3, error, sizeof(error)) : NULL;
    YDRaftSnapshotStage *stage = store ? yd_raft_snapshot_stage_new(store, manifest, 256, error, sizeof(error)) : NULL;
    valid = valid && stage;
    uint64_t at = 0;
    while (valid && at < info.view.end) {
        size_t size = info.view.end - at < sizeof(bytes) ? (size_t)(info.view.end - at) : sizeof(bytes);
        valid = yd_raft_snapshot_read(snapshot, at, bytes, size, error, sizeof(error)) &&
                yd_raft_snapshot_stage_feed(stage, at, bytes, size, error, sizeof(error));
        at += size;
    }
    char id[65];
    valid = valid && yd_raft_snapshot_stage_finish(stage, id, error, sizeof(error));
    yd_raft_snapshot_stage_close(stage);
    yd_raft_snapshot_close(snapshot);
    YDRaftSnapshotArchive *archive = valid ? yd_raft_snapshot_archive_open(store, id, NULL, NULL, error, sizeof(error)) : NULL;
    yd_raft_snapshot_store_close(store);
    return archive;
}
static bool restored(const YDRaftSnapshotArchive *archive, const char *destination) {
    unsigned char manifest[256], copy[256];
    if (yd_binary_initializing(destination) != 0 || !yd_raft_snapshot_archive_manifest(archive, manifest))
        return false;
    char path[4096];
    snprintf(path, sizeof(path), "%s/%s", destination, YD_RAFT_SNAPSHOT_CANDIDATE);
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    bool valid = fd >= 0 && read(fd, copy, sizeof(copy)) == sizeof(copy) && !memcmp(copy, manifest, sizeof(copy));
    if (fd >= 0) close(fd);
    YDRaftSnapshotInfo info = {0};
    valid = valid && yd_raft_snapshot_decode(manifest, 256, cluster, 3, &info, error, sizeof(error));
    YDRaftApplication *app = valid ? yd_raft_application_open(destination, cluster, 32768, error, sizeof(error)) : NULL;
    YDRaftCheckpoint expected = {.applied = info.applied};
    memcpy(expected.cluster, cluster, 16);
    memcpy(expected.digest, info.entry_digest, 32);
    valid = valid && app && yd_raft_application_validate(app, &expected, &info.view, error, sizeof(error));
    if (valid) {
        YDRaftWrite request = {.id = {1}, .method = "PUT", .target = "/v1/collections/a/documents/b",
                               .body = source, .size = sizeof(source) - 1};
        YDDiskReply reply;
        valid = yd_raft_application_receipt(app, &request, &reply, error, sizeof(error)) == 1 && reply.status == 201;
        yd_disk_reply_free(&reply);
    }
    yd_raft_application_close(app);
    return valid;
}
static int basic(YDRaftSnapshotArchive *archive, const char *destination) {
    REQUIRE(yd_raft_snapshot_restore(archive, destination, cluster, 3, 32768, NULL, NULL, error, sizeof(error)) &&
            restored(archive, destination));
    REQUIRE(!yd_raft_snapshot_restore(archive, destination, cluster, 3, 32768, NULL, NULL, error, sizeof(error)) &&
            restored(archive, destination));
    return 0;
}
static int failures(YDRaftSnapshotArchive *archive, const char *base, bool dying) {
    for (int test = 1; test <= (dying ? 8 : 11); test++) {
        if (test == 10) continue;
        char destination[4096];
        snprintf(destination, sizeof(destination), "%s/candidate-%d", base, test);
        REQUIRE(!mkdir(destination, 0700));
        if (dying) {
            pid_t child = fork();
            REQUIRE(child >= 0);
            if (!child) {
                crash = test; sync_count = 0;
                yd_raft_snapshot_restore(archive, destination, cluster, 3, 32768, NULL, NULL, error, sizeof(error));
                _exit(92);
            }
            int status;
            REQUIRE(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 93);
        } else {
            fault = test; sync_count = 0;
            REQUIRE(!yd_raft_snapshot_restore(archive, destination, cluster, 3, 32768, NULL, NULL, error, sizeof(error)));
            fault = 0;
        }
        REQUIRE(yd_binary_initializing(destination) == (test == 6 || (dying && test == 8) ? 0 : 1));
        REQUIRE(!yd_raft_snapshot_restore(archive, destination, cluster, 3, 32768, NULL, NULL, error, sizeof(error)));
        if (test == 6 || (dying && test == 8))
            REQUIRE(restored(archive, destination));
    }
    return 0;
}
typedef struct {
    YDRaftSnapshotArchive *archive;
    const char *destination;
    char retained[4096];
    unsigned mode, calls, graph_calls;
    uint64_t previous;
    bool checked;
} Progress;
static bool progress(void *context, uint64_t done, uint64_t total) {
    Progress *p = context;
    if (done < p->previous || done > total) return false;
    p->previous = done;
    if (!p->calls++) {
        if (p->mode == 1)
            p->checked = !yd_raft_snapshot_restore(p->archive, p->destination, cluster, 3, 32768,
                                                  NULL, NULL, error, sizeof(error));
        if (p->mode == 2) {
            if (rename(p->destination, p->retained) || mkdir(p->destination, 0700)) return false;
            char path[4096];
            int n = snprintf(path, sizeof(path), "%s/owner-data", p->destination);
            if (n < 0 || (size_t)n >= sizeof(path)) return false;
            int fd = open(path, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
            p->checked = fd >= 0 && write(fd, "keep", 4) == 4;
            if (fd >= 0) close(fd);
        }
    }
    if (p->mode == 5 && done == total && ++p->graph_calls == 5) return false;
    if (p->mode == 3) return false;
    if (p->mode == 4 && done >= total / 2) return false;
    return true;
}
static int callbacks(YDRaftSnapshotArchive *archive, const char *base) {
    for (unsigned mode = 1; mode <= 4; mode++) {
        char destination[4096];
        snprintf(destination, sizeof(destination), "%s/callback-%u", base, mode);
        REQUIRE(!mkdir(destination, 0700));
        Progress p = {.archive = archive, .destination = destination, .mode = mode};
        snprintf(p.retained, sizeof(p.retained), "%s/retained-%u", base, mode);
        bool valid = yd_raft_snapshot_restore(archive, destination, cluster, 3, 32768, progress, &p, error, sizeof(error));
        REQUIRE(valid == (mode <= 2));
        if (mode == 1) REQUIRE(p.checked && restored(archive, destination));
        if (mode == 2) {
            REQUIRE(p.checked && restored(archive, p.retained));
            char path[4096];
            int path_length = snprintf(path, sizeof(path), "%s/owner-data", destination);
            REQUIRE(path_length > 0 && (size_t)path_length < sizeof(path));
            char bytes[4];
            int fd = open(path, O_RDONLY | O_CLOEXEC);
            REQUIRE(fd >= 0 && read(fd, bytes, 4) == 4 && !memcmp(bytes, "keep", 4));
            close(fd);
            REQUIRE(yd_disk_present(destination) == 0 && yd_binary_initializing(destination) == 0);
        }
        if (mode > 2) REQUIRE(yd_binary_initializing(destination) == 1);
    }
    return 0;
}
static int pinned(YDRaftSnapshotArchive *archive, const char *destination, const char *base, bool cancel) {
    int directory = open(destination, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    REQUIRE(directory >= 0 && !flock(directory, LOCK_EX | LOCK_NB));
    char retained[4096];
    snprintf(retained, sizeof(retained), "%s/retained", base);
    REQUIRE(!rename(destination, retained) && !mkdir(destination, 0700));
    /* The caller's directory offset may already be at EOF. */
    DIR *scan = fdopendir(dup(directory));
    REQUIRE(scan);
    while (readdir(scan)) {}
    closedir(scan);
    Progress p = {.archive = archive, .destination = destination, .mode = 3};
    bool valid = yd_raft_snapshot_restore_at(archive, directory, cluster, 3, 32768,
        cancel ? progress : NULL, cancel ? &p : NULL, error, sizeof(error));
    REQUIRE(valid == !cancel && fcntl(directory, F_GETFD) >= 0);
    REQUIRE(cancel ? yd_binary_initializing(retained) == 1 : restored(archive, retained));
    REQUIRE(yd_disk_present(destination) == 0 && yd_binary_initializing(destination) == 0);
    int competing = open(retained, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    REQUIRE(competing >= 0 && flock(competing, LOCK_EX | LOCK_NB) < 0 &&
        (errno == EWOULDBLOCK || errno == EAGAIN));
    close(directory);
    REQUIRE(!flock(competing, LOCK_EX | LOCK_NB));
    close(competing);
    return 0;
}
static int descriptor_boundaries(YDRaftSnapshotArchive *archive, const char *destination, const char *base) {
    int directory = open(destination, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    REQUIRE(directory >= 0);
    unsigned char foreign[16] = {9};
    REQUIRE(!yd_raft_snapshot_restore_at(archive, -1, cluster, 3, 32768, NULL, NULL, error, sizeof(error)) &&
        !yd_raft_snapshot_restore_at(archive, directory, foreign, 3, 32768, NULL, NULL, error, sizeof(error)) &&
        !yd_raft_snapshot_restore_at(archive, directory, cluster, 5, 32768, NULL, NULL, error, sizeof(error)) &&
        !yd_raft_snapshot_restore_at(archive, directory, cluster, 3, 1, NULL, NULL, error, sizeof(error)) &&
        yd_disk_present(destination) == 0 && yd_binary_initializing(destination) == 0);
    REQUIRE(!chmod(destination, 0770) &&
        !yd_raft_snapshot_restore_at(archive, directory, cluster, 3, 32768, NULL, NULL, error, sizeof(error)) &&
        !chmod(destination, 0700));
    int owner = open(destination, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    REQUIRE(owner >= 0 && !flock(owner, LOCK_EX | LOCK_NB) &&
        !yd_raft_snapshot_restore_at(archive, directory, cluster, 3, 32768, NULL, NULL, error, sizeof(error)));
    close(owner);
    char path[4096];
    snprintf(path, sizeof(path), "%s/owner-data", base);
    int file = open(path, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
    REQUIRE(file >= 0 && write(file, "keep", 4) == 4 &&
        !yd_raft_snapshot_restore_at(archive, file, cluster, 3, 32768, NULL, NULL, error, sizeof(error)) &&
        fcntl(file, F_GETFD) >= 0);
    close(file);
    REQUIRE(yd_disk_present(destination) == 0 && yd_binary_initializing(destination) == 0 &&
        yd_raft_snapshot_restore_at(archive, directory, cluster, 3, 32768, NULL, NULL, error, sizeof(error)) &&
        restored(archive, destination) &&
        !yd_raft_snapshot_restore_at(archive, directory, cluster, 3, 32768, NULL, NULL, error, sizeof(error)) &&
        restored(archive, destination));
    close(directory);
    return 0;
}
static int boundaries(YDRaftSnapshotArchive *archive, const char *destination, const char *base) {
    unsigned char wrong[16] = {9};
    REQUIRE(!yd_raft_snapshot_restore(archive, destination, wrong, 3, 32768, NULL, NULL, error, sizeof(error)) &&
            !yd_raft_snapshot_restore(archive, destination, cluster, 5, 32768, NULL, NULL, error, sizeof(error)) &&
            !yd_raft_snapshot_restore(archive, destination, cluster, 3, 1, NULL, NULL, error, sizeof(error)));
    REQUIRE(yd_binary_initializing(destination) == 0 && yd_disk_present(destination) == 0);
    char link[4096], owner[4096];
    snprintf(link, sizeof(link), "%s/link", base);
    REQUIRE(!symlink(destination, link) &&
            !yd_raft_snapshot_restore(archive, link, cluster, 3, 32768, NULL, NULL, error, sizeof(error)));
    REQUIRE(!chmod(destination, 0770) &&
            !yd_raft_snapshot_restore(archive, destination, cluster, 3, 32768, NULL, NULL, error, sizeof(error)) &&
            !chmod(destination, 0700));
    int owner_length = snprintf(owner, sizeof(owner), "%s/owner-data", destination);
    REQUIRE(owner_length > 0 && (size_t)owner_length < sizeof(owner));
    int fd = open(owner, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
    REQUIRE(fd >= 0 && write(fd, "keep", 4) == 4);
    close(fd);
    REQUIRE(!yd_raft_snapshot_restore(archive, destination, cluster, 3, 32768, NULL, NULL, error, sizeof(error)) &&
            yd_disk_present(destination) == 0 && yd_binary_initializing(destination) == 0);
    int directory = open(destination, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    REQUIRE(directory >= 0);
    DIR *scan = fdopendir(dup(directory));
    REQUIRE(scan);
    while (readdir(scan)) { }
    closedir(scan);
    YDRaftApplication *app = yd_raft_application_open_at(directory, cluster, 32768, error, sizeof(error));
    bool absent = app == NULL;
    yd_raft_application_close(app);
    close(directory);
    REQUIRE(absent && yd_disk_present(destination) == 0);
    return 0;
}
int main(int argc, char **argv) {
    if (argc != 3) return 2;
    char source_root[4096], directory[4096], destination[4096];
    snprintf(source_root, sizeof(source_root), "%s/source", argv[1]);
    snprintf(directory, sizeof(directory), "%s/archive", argv[1]);
    snprintf(destination, sizeof(destination), "%s/destination", argv[1]);
    REQUIRE(!mkdir(source_root, 0700) && !mkdir(directory, 0700) && !mkdir(destination, 0700));
    if (!strcmp(argv[2], "graph-cancel")) {
        YDRaftSnapshotArchive *a = seed(source_root, directory, false);
        REQUIRE(a);
        Progress p = {.mode = 5};
        REQUIRE(!yd_raft_snapshot_restore(a, destination, cluster, 3, 32768, progress, &p, error, sizeof(error)) &&
            p.graph_calls == 5 && yd_binary_initializing(destination) == 1);
        yd_raft_snapshot_archive_close(a);
        return 0;
    }
    bool malformed = !strcmp(argv[2], "malformed");
    YDRaftSnapshotArchive *archive = seed(source_root, directory, malformed);
    REQUIRE(archive);
    int result = 2;
    if (!strcmp(argv[2], "basic")) result = basic(archive, destination);
    if (!strcmp(argv[2], "faults")) result = failures(archive, argv[1], false);
    if (!strcmp(argv[2], "crashes")) result = failures(archive, argv[1], true);
    if (!strcmp(argv[2], "callbacks")) result = callbacks(archive, argv[1]);
    if (!strcmp(argv[2], "boundaries")) result = boundaries(archive, destination, argv[1]);
    if (!strcmp(argv[2], "pinned")) result = pinned(archive, destination, argv[1], false);
    if (!strcmp(argv[2], "pinned-cancel")) result = pinned(archive, destination, argv[1], true);
    if (!strcmp(argv[2], "descriptors")) result = descriptor_boundaries(archive, destination, argv[1]);
    if (malformed) {
        REQUIRE(!yd_raft_snapshot_restore(archive, destination, cluster, 3, 32768, NULL, NULL, error, sizeof(error)) &&
                yd_binary_initializing(destination) == 1);
        result = 0;
    }
    yd_raft_snapshot_archive_close(archive);
    return result;
}
