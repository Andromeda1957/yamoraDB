#define _POSIX_C_SOURCE 200809L
#include "../src/consensus/capture_internal.h"
#include "../src/consensus/application_internal.h"
#include "../src/consensus/snapshot_restore.h"
#include "../src/disk_internal.h"
#include "../src/disk_documents.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <unistd.h>
static char error[512];
static const unsigned char cluster[16] = {1, 2, 3, 4};
static const unsigned char source[] = "# captured source\r\ncount: 0 # exact\r\n";
static int publication_directory = -1;
static bool publication_checked, publication_protected;
void __real_yd_raft_snapshot_stage_close(YDRaftSnapshotStage *);
void __wrap_yd_raft_snapshot_stage_close(YDRaftSnapshotStage *stage) {
    __real_yd_raft_snapshot_stage_close(stage);
    if (!stage || publication_directory < 0) return;
    int copy = openat(publication_directory, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    DIR *scan = copy >= 0 ? fdopendir(copy) : NULL;
    if (!scan) { if (copy >= 0) close(copy); return; }
    struct dirent *entry;
    while ((entry = readdir(scan))) {
        if (strlen(entry->d_name) != 73 || strcmp(entry->d_name + 64, ".snapshot")) continue;
        int fd = openat(publication_directory, entry->d_name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0) continue;
        int result = flock(fd, LOCK_EX | LOCK_NB), saved = errno;
        publication_checked = true;
        publication_protected = result < 0 && (saved == EWOULDBLOCK || saved == EAGAIN);
        close(fd);
    }
    closedir(scan);
}
#define REQUIRE(x) do { if (!(x)) { \
    fprintf(stderr, "line %u: %s (%s)\n", __LINE__, #x, error); return 2; \
} } while (0)
static bool put(YDRaftApplication *app, unsigned id, const unsigned char *body, size_t size,
                   char *message, size_t length) {
    YDRaftWrite write = {.method = "PUT", .target = "/v1/collections/a/documents/b", .body = body, .size = size};
    write.id[0] = (unsigned char)id;
    YDRaftProposal proposal = {0};
    bool valid = yd_raft_application_prepare(app, &write, &proposal, message, length) == 1;
    YDRaftEntry entry = {.index = yd_raft_application_position(app).index + 1, .term = 2,
        .kind = YD_RAFT_COMMAND, .command = proposal.command, .size = proposal.size};
    valid = valid && yd_raft_application_apply(app, &entry, message, length);
    yd_raft_proposal_free(&proposal);
    return valid;
}
static bool empty(int directory) {
    int copy = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    DIR *scan = copy >= 0 ? fdopendir(copy) : NULL;
    if (!scan) { if (copy >= 0) close(copy); return false; }
    bool valid = true;
    struct dirent *entry;
    while ((entry = readdir(scan)))
        if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) valid = false;
    closedir(scan);
    return valid;
}
static bool verify(YDRaftCapture *capture, YDRaftCaptureOrigin *origin, const char *archive, const char *destination) {
    unsigned char manifest[256], bytes[4093], digest[32] = {0};
    YDRaftSnapshotInfo info = {0};
    YDRaftSnapshotBase base;
    size_t size = 0;
    bool valid = yd_raft_capture_manifest(capture, manifest) &&
        yd_raft_snapshot_decode(manifest, sizeof(manifest), cluster, 3, &info, error, sizeof(error)) &&
        yd_raft_capture_origin(capture, origin, &base) && base.index == 1 && base.term == 2 &&
        EVP_Q_digest(NULL, "SHA256", NULL, manifest, sizeof(manifest), digest, &size) == 1 &&
        size == 32 && !memcmp(base.archive, digest, 32);
    YDRaftSnapshotVerifier *verifier = valid ? yd_raft_snapshot_verifier_new(manifest, 256, cluster, 3, error, sizeof(error)) : NULL;
    valid = valid && verifier;
    for (uint64_t at = 0; valid && at < info.view.end;) {
        size_t count = info.view.end - at < sizeof(bytes) ? (size_t)(info.view.end - at) : sizeof(bytes);
        valid = yd_raft_capture_read(capture, at, bytes, count, error, sizeof(error)) &&
            yd_raft_snapshot_feed(verifier, at, bytes, count, error, sizeof(error));
        at += count;
    }
    valid = valid && yd_raft_snapshot_finish(verifier, error, sizeof(error));
    yd_raft_snapshot_verifier_free(verifier);
    valid = valid && !yd_raft_capture_read(capture, info.view.end, bytes, 1, error, sizeof(error)) &&
        !yd_raft_capture_read(capture, UINT64_MAX, bytes, 1, error, sizeof(error));
    for (unsigned i = 0; valid && i < 4; i++) {
        YDRaftCaptureOrigin wrong = *origin;
        if (i == 0) wrong.cluster[0] ^= 1;
        if (i == 1) wrong.node = 2;
        if (i == 2) wrong.term++;
        if (i == 3) wrong.voters = 5;
        valid = !yd_raft_capture_origin(capture, &wrong, &base) && !base.index;
    }
    char id[65];
    static const char hex[] = "0123456789abcdef";
    for (unsigned i = 0; i < 32; i++) {
        id[2 * i] = hex[digest[i] >> 4]; id[2 * i + 1] = hex[digest[i] & 15];
    }
    id[64] = 0;
    YDRaftSnapshotStore *store = valid ? yd_raft_snapshot_store_open(archive, cluster, 3, error, sizeof(error)) : NULL;
    YDRaftSnapshotArchive *image = store ? yd_raft_snapshot_archive_open(store, id, NULL, NULL, error, sizeof(error)) : NULL;
    valid = image && yd_raft_snapshot_restore(image, destination, cluster, 3, 32768, NULL, NULL, error, sizeof(error));
    yd_raft_snapshot_archive_close(image);
    yd_raft_snapshot_store_close(store);
    YDRaftApplication *app = valid ? yd_raft_application_open(destination, cluster, 32768, error, sizeof(error)) : NULL;
    YDRaftWrite write = {.id = {1}, .method = "PUT", .target = "/v1/collections/a/documents/b", .body = source, .size = sizeof(source) - 1};
    YDDiskReply reply = {0};
    valid = app && yd_raft_application_position(app).index == 1 &&
        yd_raft_application_receipt(app, &write, &reply, error, sizeof(error)) == 1 && reply.status == 201;
    YDDiskDocument document = {0};
    YDDiskView view = app ? yd_disk_view(yd_raft_application_disk(app)) : (YDDiskView){0};
    valid = valid && yd_disk_document_get(yd_raft_application_disk(app), &view, "a", "b",
        &document, error, sizeof(error)) == 1 && document.length == sizeof(source) - 1 &&
        !memcmp(document.body, source, sizeof(source) - 1);
    yd_disk_document_free(&document);
    yd_disk_reply_free(&reply);
    yd_raft_application_close(app);
    return valid;
}
static bool cancel(void *context, uint64_t done, uint64_t total) {
    (void)context; (void)done; (void)total;
    return false;
}
static bool archive_pinned(const char *root, YDRaftCapture *capture, const YDRaftCaptureOrigin *origin,
                           bool expected) {
    YDRaftSnapshotBase base;
    if (!yd_raft_capture_origin(capture, origin, &base)) return false;
    char path[8192], id[65];
    for (unsigned i = 0; i < 32; i++) snprintf(id + 2 * i, 3, "%02x", base.archive[i]);
    snprintf(path, sizeof(path), "%s/%s.snapshot", root, id);
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return false;
    int result = flock(fd, LOCK_EX | LOCK_NB), saved = errno;
    close(fd);
    return expected ? result < 0 && (saved == EWOULDBLOCK || saved == EAGAIN) : result == 0;
}
static bool complete(int directory);
typedef struct { int directory; bool cancelled; } Progress;
static bool cancel_published(void *context, uint64_t done, uint64_t total) {
    (void)done; (void)total;
    Progress *progress = context;
    if (complete(progress->directory)) { progress->cancelled = true; return false; }
    return true;
}
static bool complete(int directory) {
    int copy = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    DIR *scan = copy >= 0 ? fdopendir(copy) : NULL;
    if (!scan) { if (copy >= 0) close(copy); return false; }
    unsigned count = 0;
    bool valid = true;
    struct dirent *entry;
    while ((entry = readdir(scan))) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        struct stat status;
        valid = valid && strlen(entry->d_name) == 73 && !strcmp(entry->d_name + 64, ".snapshot") &&
            !fstatat(directory, entry->d_name, &status, AT_SYMLINK_NOFOLLOW) && S_ISREG(status.st_mode) &&
            (status.st_mode & 0777) == 0400 && status.st_nlink == 1;
        count++;
    }
    closedir(scan);
    return valid && count == 1;
}
typedef struct { YDRaftApplication *app; bool valid; } Writer;
static void *advance(void *context) {
    Writer *writer = context;
    char message[512];
    writer->valid = true;
    for (unsigned i = 2; i <= 21 && writer->valid; i++) {
        char body[64];
        int n = snprintf(body, sizeof(body), "count: %u\n", i);
        writer->valid = put(writer->app, i, (unsigned char *)body, (size_t)n, message, sizeof(message));
    }
    return NULL;
}
static bool corrupt_graph(YDRaftApplication **app, const char *root) {
    YDRaftCheckpoint prior;
    YDDiskCheckpoint *checkpoint = yd_raft_application_checkpoint(*app, &prior, error, sizeof(error));
    if (!checkpoint) return false;
    yd_disk_checkpoint_close(checkpoint);
    yd_raft_application_close(*app);
    *app = NULL;
    YDDisk *disk = yd_disk_open_cluster(root, 32768, error, sizeof(error));
    YDDiskTxn *txn = disk ? yd_disk_begin_exclusive(disk, error, sizeof(error)) : NULL;
    unsigned char position[96] = {0};
    memcpy(position, "YDAPLY01", 8); memcpy(position + 8, cluster, 16);
    yd_disk_set64(position + 24, 2); yd_disk_set64(position + 32, 2);
    if (txn) yd_disk_set64(position + 40, txn->view.revision);
    memcpy(position + 48, prior.digest, 32);
    uint64_t offset;
    bool valid = txn && yd_disk_put(txn, "unknown", 7, 123, error, sizeof(error)) &&
        yd_disk_append(txn, position, sizeof(position), &offset, error, sizeof(error)) &&
        yd_disk_put(txn, "\0YRA", 4, offset, error, sizeof(error));
    if (valid) {
        txn->log_enabled = txn->log_identity_set = true;
        memcpy(txn->log_identity, cluster, 16);
        valid = yd_disk_commit(txn, error, sizeof(error));
    } else yd_disk_abort(txn);
    yd_disk_close(disk);
    *app = valid ? yd_raft_application_open(root, cluster, 32768, error, sizeof(error)) : NULL;
    return *app != NULL;
}
typedef struct { uint64_t previous; unsigned graph_calls; bool scanning; } ScanCancel;
static bool cancel_graph(void *context, uint64_t done, uint64_t total) {
    (void)total;
    ScanCancel *p = context;
    if (!done && p->previous) p->scanning = true;
    p->previous = done;
    return !p->scanning || done || ++p->graph_calls < 4;
}
int main(int argc, char **argv) {
    if (argc != 3) return 2;
    char root[4096], archive[4096], destination[4096];
    snprintf(root, sizeof(root), "%s/source", argv[1]);
    snprintf(archive, sizeof(archive), "%s/archive", argv[1]);
    snprintf(destination, sizeof(destination), "%s/restored", argv[1]);
    REQUIRE(!mkdir(root, 0700) && !mkdir(archive, 0700) && !mkdir(destination, 0700));
    YDRaftApplication *app = yd_raft_application_open(root, cluster, 32768, error, sizeof(error));
    REQUIRE(app && put(app, 1, source, sizeof(source) - 1, error, sizeof(error)));
    bool malformed = !strcmp(argv[2], "graph");
    if (malformed) REQUIRE(corrupt_graph(&app, root));
    YDRaftSnapshot *image = yd_raft_snapshot_open(app, 3, error, sizeof(error));
    YDDisk *disk = yd_raft_application_disk(app);
    YDRaftCaptureOrigin origin = {.cluster = {1, 2, 3, 4}, .node = 1, .voters = 3, .term = 3};
    int directory = open(archive, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    REQUIRE(image && directory >= 0);
    if (malformed) {
        YDRaftCapture *rejected = yd_raft_capture_new(image, disk, directory, &origin, NULL, NULL, error, sizeof(error));
        REQUIRE(!rejected && empty(directory));
    } else {
        if (!strcmp(argv[2], "cancel")) {
            YDRaftCapture *rejected = yd_raft_capture_new(image, disk, directory, &origin, cancel, NULL, error, sizeof(error));
            REQUIRE(!rejected && empty(directory) && fcntl(directory, F_GETFD) >= 0);
        }
        if (!strcmp(argv[2], "cancel-graph")) {
            ScanCancel p = {0};
            YDRaftCapture *rejected = yd_raft_capture_new(image, disk, directory, &origin,
                cancel_graph, &p, error, sizeof(error));
            REQUIRE(!rejected && p.graph_calls == 4 && empty(directory) && fcntl(directory, F_GETFD) >= 0);
        }
        if (!strcmp(argv[2], "cancel-published")) {
            Progress progress = {.directory = directory};
            YDRaftCapture *rejected = yd_raft_capture_new(image, disk, directory, &origin,
                cancel_published, &progress, error, sizeof(error));
            REQUIRE(!rejected && progress.cancelled && complete(directory) && fcntl(directory, F_GETFD) >= 0);
        }
        if (!strcmp(argv[2], "bounds")) {
            for (unsigned i = 0; i < 6; i++) {
                YDRaftCaptureOrigin wrong = origin;
                if (i == 0) wrong.node = 0;
                if (i == 1) wrong.term = 1;
                if (i == 2) wrong.voters = 5;
                if (i == 3) wrong.cluster[0] ^= 1;
                if (i == 4) wrong.term = 0;
                if (i == 5) wrong.node = 4;
                YDRaftCapture *rejected = yd_raft_capture_new(image, disk, directory, &wrong, NULL, NULL, error, sizeof(error));
                REQUIRE(!rejected && empty(directory));
            }
        }
        Writer writer = {.app = app};
        pthread_t thread;
        bool concurrent = !strcmp(argv[2], "concurrent");
        if (concurrent) REQUIRE(!pthread_create(&thread, NULL, advance, &writer));
        if (!strcmp(argv[2], "publication-pin")) publication_directory = directory;
        YDRaftCapture *capture = yd_raft_capture_new(image, disk, directory, &origin, NULL, NULL, error, sizeof(error));
        REQUIRE(capture);
        if (!strcmp(argv[2], "publication-pin")) {
            REQUIRE(publication_checked && publication_protected);
            publication_directory = -1;
        }
        if (concurrent) REQUIRE(!pthread_join(thread, NULL) && writer.valid);
        if (!concurrent) {
            YDRaftCapture *same = yd_raft_capture_new(image, disk, directory, &origin, NULL, NULL, error, sizeof(error));
            unsigned char first[256], second[256];
            REQUIRE(same && yd_raft_capture_manifest(capture, first) && yd_raft_capture_manifest(same, second) &&
                !memcmp(first, second, sizeof(first)));
            yd_raft_capture_close(same);
        }
        yd_raft_snapshot_close(image); image = NULL;
        yd_raft_application_close(app); app = NULL;
        close(directory); directory = -1;
        if (!strcmp(argv[2], "pin")) REQUIRE(archive_pinned(archive, capture, &origin, true));
        REQUIRE(verify(capture, &origin, archive, destination));
        yd_raft_capture_close(capture);
    }
    if (directory >= 0) close(directory);
    yd_raft_snapshot_close(image);
    yd_raft_application_close(app);
    return 0;
}
