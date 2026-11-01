#define _POSIX_C_SOURCE 200809L
#include "../src/consensus/application_archive.h"
#include "../src/consensus/recovery.h"
#include "../src/consensus/snapshot_restore.h"
#include "../src/consensus/snapshot_internal.h"
#include "../src/consensus/snapshot_store_internal.h"
#include "../src/disk_changes.h"
#include "../src/disk_internal.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#define REQUIRE(x)                                                                                 \
    do {                                                                                           \
        if (!(x)) {                                                                                \
            fprintf(stderr, "line %u: %s (%s)\n", __LINE__, #x, error);                            \
            return 2;                                                                              \
        }                                                                                          \
    } while (0)
static char error[512];
static const unsigned char cluster[16] = {1, 2, 3, 4};
static const char target[] = "/v1/collections/config/documents/node";
static const unsigned char source[] = "# exact\r\ncount: 0\r\nname: 'first' # keep\r\n";
static unsigned sync_calls, fail_sync;
static bool corrupt_archive, corrupted;
static bool archive_published;
static int corrupt_directory;
int __real_fsync(int fd);
int __wrap_fsync(int fd) {
    if (++sync_calls == fail_sync) {
        errno = EIO;
        return -1;
    }
    return __real_fsync(fd);
}
YDRaftArchiveResult __real_yd_raft_snapshot_stage_finish_retaining(YDRaftSnapshotStage *,
    char *, YDRaftSnapshotProgress, void *, YDRaftSnapshotReference **, char *, size_t);
YDRaftArchiveResult __wrap_yd_raft_snapshot_stage_finish_retaining(YDRaftSnapshotStage *stage,
    char *id, YDRaftSnapshotProgress progress, void *context, YDRaftSnapshotReference **reference,
    char *failure, size_t length) {
    YDRaftArchiveResult result = __real_yd_raft_snapshot_stage_finish_retaining(stage, id,
        progress, context, reference, failure, length);
    bool valid = result == YD_RAFT_ARCHIVE_OK;
    if (valid) archive_published = true;
    if (valid && corrupt_archive) {
        char name[80];
        snprintf(name, sizeof(name), "%s.snapshot", id);
        int fd = openat(corrupt_directory, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        bool writable = fd >= 0 && !fchmod(fd, 0600);
        if (fd >= 0)
            close(fd);
        fd = writable ? openat(corrupt_directory, name, O_RDWR | O_NOFOLLOW | O_CLOEXEC) : -1;
        struct stat status;
        unsigned char byte = 0;
        corrupted = fd >= 0 && !fstat(fd, &status) && status.st_size > 256 &&
                    pread(fd, &byte, 1, status.st_size - 1) == 1;
        byte ^= 1;
        corrupted = corrupted && pwrite(fd, &byte, 1, status.st_size - 1) == 1;
        if (fd >= 0) {
            corrupted = !fchmod(fd, 0400) && corrupted;
            close(fd);
        }
    }
    return result;
}
static int directory(const char *root, const char *name, char path[4096]) {
    snprintf(path, 4096, "%s/%s", root, name);
    return mkdir(path, 0700) ? -1 : open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
}
static bool noop(YDRaftApplication *a) {
    YDRaftEntry e = {
        .index = yd_raft_application_position(a).index + 1, .term = 1, .kind = YD_RAFT_NOOP};
    return yd_raft_application_apply(a, &e, error, sizeof(error));
}
static YDRaftWrite request(unsigned id, const char *method, const char *path, const char *body) {
    YDRaftWrite w = {.method = method,
                     .target = path,
                     .body = (const unsigned char *)body,
                     .size = body ? strlen(body) : 0};
    w.id[0] = (unsigned char)id;
    return w;
}
static bool commit(YDRaftApplication *a, YDRaftWrite w) {
    YDRaftProposal p = {0};
    int prepared = yd_raft_application_prepare(a, &w, &p, error, sizeof(error));
    YDRaftEntry e = {.index = yd_raft_application_position(a).index + 1,
                     .term = 1,
                     .kind = YD_RAFT_COMMAND,
                     .command = p.command,
                     .size = p.size};
    bool valid = prepared == 1 && yd_raft_application_apply(a, &e, error, sizeof(error));
    yd_raft_proposal_free(&p);
    return valid;
}
static YDRaftApplication *seed(const char *path) {
    YDRaftApplication *a = yd_raft_application_open(path, cluster, 32768, error, sizeof(error));
    const char indexes[] =
        "{indexes: [{collection: config, name: count, fields: [count], unique: true},"
        "{collection: config, name: words, fields: [name], type: text}]}";
    bool valid = a && noop(a) && commit(a, request(1, "PUT", target, (const char *)source)) &&
                 commit(a, request(2, "PUT", "/v1/indexes", indexes));
    for (unsigned i = 0; valid && i < 5; i++)
        valid = commit(a, request(10 + i, "PATCH", target, "{\"$inc\":{\"count\":1}}"));
    for (unsigned i = 0; valid && i < 50; i++)
        valid = noop(a);
    if (valid)
        return a;
    yd_raft_application_close(a);
    return NULL;
}
static YDRaftApplicationImage *image(const char *root, YDRaftApplication *a, const char *name) {
    char path[4096];
    int dir = directory(root, name, path);
    YDRaftApplicationCapture *c = yd_raft_application_capture(a, 32768, error, sizeof(error));
    YDRaftApplicationImage *i =
        c && dir >= 0 ? yd_raft_application_copy(c, dir, 32768, NULL, NULL, error, sizeof(error))
                      : NULL;
    yd_raft_application_capture_close(c);
    if (dir >= 0)
        close(dir);
    return i;
}
static bool verify(YDRaftSnapshotArchive *archive, unsigned char manifest[256]) {
    YDRaftSnapshotInfo info;
    if (!yd_raft_snapshot_archive_manifest(archive, manifest) ||
        !yd_raft_snapshot_decode(manifest, 256, cluster, 3, &info, error, sizeof(error)))
        return false;
    YDRaftSnapshotVerifier *v =
        yd_raft_snapshot_verifier_new(manifest, 256, cluster, 3, error, sizeof(error));
    unsigned char bytes[8192];
    bool valid = v != NULL;
    for (uint64_t at = 0; valid && at < info.view.end;) {
        size_t n =
            info.view.end - at < sizeof(bytes) ? (size_t)(info.view.end - at) : sizeof(bytes);
        valid = yd_raft_snapshot_archive_read(archive, at, bytes, n, error, sizeof(error)) &&
                yd_raft_snapshot_feed(v, at, bytes, n, error, sizeof(error));
        at += n;
    }
    valid = valid && yd_raft_snapshot_finish(v, error, sizeof(error));
    yd_raft_snapshot_verifier_free(v);
    return valid;
}
static bool document(YDDisk *d, unsigned count) {
    char expected[128];
    snprintf(expected, sizeof(expected), "# exact\r\ncount: %u\r\nname: 'first' # keep\r\n", count);
    YDDiskView v = yd_disk_view(d);
    YDDiskDocument doc = {0};
    bool valid = yd_disk_document_get(d, &v, "config", "node", &doc, error, sizeof(error)) == 1 &&
                 doc.length == strlen(expected) && !memcmp(doc.body, expected, doc.length);
    yd_disk_document_free(&doc);
    return valid;
}
static int basic(const char *root) {
    char path[4096], id[65], other[65];
    int dir = directory(root, "source", path);
    REQUIRE(dir >= 0);
    close(dir);
    YDRaftApplication *a = seed(path);
    REQUIRE(a);
    YDRaftApplicationImage *i = image(root, a, "compact");
    REQUIRE(i);
    YDDisk *d = yd_raft_application_image_disk(i);
    YDDiskView view = yd_disk_view(d);
    dir = directory(root, "archives", path);
    REQUIRE(dir >= 0);
    YDRaftSnapshotArchive *archive =
        yd_raft_application_archive(i, dir, cluster, 3, NULL, NULL, id, error, sizeof(error));
    REQUIRE(archive && strlen(id) == 64);
    unsigned char manifest[256];
    REQUIRE(verify(archive, manifest));
    YDRaftSnapshotInfo info;
    REQUIRE(yd_raft_snapshot_decode(manifest, 256, cluster, 3, &info, error, sizeof(error)) &&
            info.view.end == view.end && info.view.root == view.root &&
            info.applied.index == yd_raft_application_position(a).index &&
            info.view.end * 2 < yd_disk_view(yd_raft_application_disk(a)).end &&
            yd_raft_application_image_current(i, a));
    YDRaftSnapshotArchive *retry =
        yd_raft_application_archive(i, dir, cluster, 3, NULL, NULL, other, error, sizeof(error));
    REQUIRE(retry && !strcmp(id, other));
    yd_raft_snapshot_archive_close(retry);
    int destination = directory(root, "restored", path);
    REQUIRE(destination >= 0);
    REQUIRE(yd_raft_snapshot_restore_at(archive, destination, cluster, 3, 32768, NULL, NULL, error,
                                        sizeof(error)));
    YDRaftApplication *restored = yd_raft_candidate_open_at(
        destination, manifest, cluster, 3, 32768, NULL, NULL, error, sizeof(error));
    REQUIRE(restored && document(yd_raft_application_disk(restored), 5));
    YDDiskView rv = yd_disk_view(yd_raft_application_disk(restored));
    YDDiskReply before = yd_disk_changes_request(d, &view, "/v1/changes");
    YDDiskReply after =
        yd_disk_changes_request(yd_raft_application_disk(restored), &rv, "/v1/changes");
    REQUIRE(before.status == 200 && after.status == 200 && before.length == after.length &&
            !memcmp(before.body, after.body, before.length));
    yd_disk_reply_free(&before);
    yd_disk_reply_free(&after);
    YDRaftWrite original = request(1, "PUT", target, (const char *)source);
    YDRaftProposal p = {0};
    REQUIRE(yd_raft_application_prepare(restored, &original, &p, error, sizeof(error)) == 0 &&
            p.reply.status == 201 && document(yd_raft_application_disk(restored), 5));
    yd_raft_proposal_free(&p);
    REQUIRE(commit(restored, request(90, "PATCH", target, "{\"$inc\":{\"count\":1}}")) &&
            document(yd_raft_application_disk(restored), 6));
    yd_raft_application_close(restored);
    close(destination);
    yd_raft_snapshot_archive_close(archive);
    yd_raft_application_image_close(i);
    yd_raft_application_close(a);
    close(dir);
    return 0;
}
static int checkpoint(const char *root) {
    char path[4096];
    int dir = directory(root, "source", path);
    REQUIRE(dir >= 0);
    close(dir);
    YDRaftApplication *a = seed(path);
    REQUIRE(a);
    YDRaftApplicationImage *i = image(root, a, "compact");
    REQUIRE(i);
    YDRaftCheckpoint position;
    YDDiskCheckpoint *c = yd_raft_application_image_checkpoint(i, &position, error, sizeof(error));
    REQUIRE(c);
    YDDiskView view = yd_disk_checkpoint_view(c);
    REQUIRE(view.end == yd_disk_view(yd_raft_application_image_disk(i)).end &&
            position.applied.index == yd_raft_application_position(a).index);
    YDDiskCheckpoint *owned =
        yd_raft_application_image_checkpoint(i, &position, error, sizeof(error));
    YDRaftSnapshot *snapshot =
        yd_raft_snapshot_from_checkpoint(owned, &position, 3, error, sizeof(error));
    REQUIRE(snapshot);
    unsigned char *before = malloc((size_t)view.end), bytes[8192];
    REQUIRE(before);
    for (uint64_t at = 0; at < view.end;) {
        size_t n = view.end - at < sizeof(bytes) ? (size_t)(view.end - at) : sizeof(bytes);
        REQUIRE(yd_disk_checkpoint_read(c, at, before + at, n, error, sizeof(error)));
        at += n;
    }
    REQUIRE(commit(a, request(90, "PATCH", target, "{\"$inc\":{\"count\":1}}")));
    YDRaftApplicationCapture *later = yd_raft_application_capture(a, 32768, error, sizeof(error));
    REQUIRE(later && yd_raft_application_catch_up(i, later, NULL, NULL, error, sizeof(error)) &&
            document(yd_raft_application_image_disk(i), 6));
    yd_raft_application_capture_close(later);
    yd_raft_application_image_close(i);
    yd_raft_application_close(a);
    unsigned char manifest[256];
    REQUIRE(yd_raft_snapshot_seal(snapshot, NULL, NULL, error, sizeof(error)) &&
            yd_raft_snapshot_manifest(snapshot, manifest));
    YDRaftSnapshotVerifier *verifier =
        yd_raft_snapshot_verifier_new(manifest, 256, cluster, 3, error, sizeof(error));
    REQUIRE(verifier);
    for (uint64_t at = 0; at < view.end;) {
        size_t n = view.end - at < sizeof(bytes) ? (size_t)(view.end - at) : sizeof(bytes);
        REQUIRE(yd_disk_checkpoint_read(c, at, bytes, n, error, sizeof(error)) &&
                !memcmp(bytes, before + at, n) &&
                yd_raft_snapshot_read(snapshot, at, bytes, n, error, sizeof(error)) &&
                !memcmp(bytes, before + at, n) &&
                yd_raft_snapshot_feed(verifier, at, bytes, n, error, sizeof(error)));
        at += n;
    }
    free(before);
    REQUIRE(yd_raft_snapshot_finish(verifier, error, sizeof(error)));
    yd_raft_snapshot_verifier_free(verifier);
    yd_raft_snapshot_close(snapshot);
    yd_disk_checkpoint_close(c);
    return 0;
}
typedef struct {
    YDRaftSnapshotArchive *archive;
    bool valid;
} Reader;
static void *reader(void *context) {
    Reader *r = context;
    unsigned char manifest[256];
    for (unsigned n = 0; r->valid && n < 10; n++)
        r->valid = verify(r->archive, manifest);
    return NULL;
}
static int lifetime(const char *root) {
    char path[4096], renamed[4096], id[65];
    int dir = directory(root, "source", path);
    REQUIRE(dir >= 0);
    close(dir);
    YDRaftApplication *a = seed(path);
    REQUIRE(a);
    size_t size = 3 * 1024 * 1024;
    char *large = malloc(size + 1);
    REQUIRE(large);
    memset(large, 'x', size);
    memcpy(large, "payload: '", 10);
    memcpy(large + size - 2, "'\n", 2);
    large[size] = 0;
    REQUIRE(commit(a, request(80, "PUT", "/v1/collections/large/documents/value", large)));
    free(large);
    YDRaftApplicationImage *i = image(root, a, "compact");
    REQUIRE(i);
    dir = directory(root, "archives", path);
    REQUIRE(dir >= 0);
    YDRaftSnapshotArchive *archive =
        yd_raft_application_archive(i, dir, cluster, 3, NULL, NULL, id, error, sizeof(error));
    REQUIRE(archive);
    yd_raft_application_image_close(i);
    yd_raft_application_close(a);
    close(dir);
    snprintf(renamed, sizeof(renamed), "%s/renamed", root);
    REQUIRE(!rename(path, renamed) && !mkdir(path, 0777));
    Reader readers[3];
    pthread_t threads[3];
    for (unsigned n = 0; n < 3; n++) {
        readers[n] = (Reader){archive, true};
        REQUIRE(!pthread_create(&threads[n], NULL, reader, &readers[n]));
    }
    for (unsigned n = 0; n < 3; n++)
        REQUIRE(!pthread_join(threads[n], NULL) && readers[n].valid);
    yd_raft_snapshot_archive_close(archive);
    return 0;
}
typedef struct {
    unsigned phase, cancel;
    YDDisk *change;
    bool changed;
    bool cancel_published, cancelled_published;
} Progress;
static bool change_receipt(YDDisk *disk, unsigned status) {
    YDDiskView view = yd_disk_view(disk);
    unsigned char key[20] = {0, 'Y', 'R', 'R', 1};
    uint64_t offset;
    size_t size;
    if (yd_disk_get(disk, &view, key, 20, &offset, error, sizeof(error)) != 1)
        return false;
    unsigned char *bytes = yd_disk_record(disk, &view, offset, &size, error, sizeof(error));
    bool valid = bytes && size >= 128 && bytes[80] == 201 && !bytes[81];
    if (valid) {
        bytes[80] = (unsigned char)status;
        bytes[81] = (unsigned char)(status >> 8);
        uint32_t crc = yd_disk_crc(bytes, size);
        unsigned char encoded[4];
        for (unsigned n = 0; n < 4; n++)
            encoded[n] = (unsigned char)(crc >> (8 * n));
        valid = pwrite(disk->fd, bytes, size, (off_t)(offset + 16)) == (ssize_t)size &&
                pwrite(disk->fd, encoded, 4, (off_t)(offset + 12)) == 4;
    }
    free(bytes);
    return valid;
}
static bool progress(void *context, uint64_t done, uint64_t total) {
    Progress *p = context;
    if (p->cancel_published && archive_published) {
        p->cancelled_published = true;
        return false;
    }
    if (done > total)
        return false;
    if (!done)
        p->phase++;
    if (p->change && p->phase == 2 && !p->changed) {
        p->changed = change_receipt(p->change, 200);
        if (!p->changed)
            return false;
    }
    return p->phase != p->cancel;
}
static unsigned entries(int directory_fd);
static int cancellation(const char *root) {
    char path[4096], id[65];
    int dir = directory(root, "source", path);
    REQUIRE(dir >= 0);
    close(dir);
    YDRaftApplication *a = seed(path);
    REQUIRE(a);
    YDRaftApplicationImage *i = image(root, a, "compact");
    REQUIRE(i);
    for (unsigned n = 1; n <= 4; n++) {
        char name[32];
        snprintf(name, sizeof(name), "cancel%u", n);
        dir = directory(root, name, path);
        REQUIRE(dir >= 0);
        Progress p = {.cancel = n < 4 ? n : 0, .cancel_published = n == 4};
        archive_published = false;
        memset(id, 'x', sizeof(id));
        REQUIRE(!yd_raft_application_archive(i, dir, cluster, 3, progress, &p, id, error,
                                             sizeof(error)) &&
                !id[0] && (n < 4 ? p.phase == n : p.cancelled_published) &&
                yd_raft_application_image_current(i, a) &&
                entries(dir) == (n == 4 ? 1U : 0U));
        YDRaftSnapshotArchive *retry =
            yd_raft_application_archive(i, dir, cluster, 3, NULL, NULL, id, error, sizeof(error));
        REQUIRE(retry);
        yd_raft_snapshot_archive_close(retry);
        close(dir);
    }
    yd_raft_application_image_close(i);
    yd_raft_application_close(a);
    return 0;
}
static int sync_failure(const char *root) {
    char path[4096], id[65];
    int dir = directory(root, "source", path);
    REQUIRE(dir >= 0);
    close(dir);
    YDRaftApplication *a = seed(path);
    REQUIRE(a);
    YDRaftApplicationImage *i = image(root, a, "compact");
    REQUIRE(i);
    dir = directory(root, "measure", path);
    REQUIRE(dir >= 0);
    sync_calls = 0;
    YDRaftSnapshotArchive *archive =
        yd_raft_application_archive(i, dir, cluster, 3, NULL, NULL, id, error, sizeof(error));
    REQUIRE(archive && sync_calls >= 2);
    unsigned calls = sync_calls;
    yd_raft_snapshot_archive_close(archive);
    close(dir);
    for (unsigned n = 1; n <= calls; n++) {
        char name[32];
        snprintf(name, sizeof(name), "sync%u", n);
        dir = directory(root, name, path);
        REQUIRE(dir >= 0);
        sync_calls = 0;
        fail_sync = n;
        memset(id, 'x', sizeof(id));
        archive =
            yd_raft_application_archive(i, dir, cluster, 3, NULL, NULL, id, error, sizeof(error));
        fail_sync = 0;
        REQUIRE(!archive && !id[0] && sync_calls >= n && yd_raft_application_image_current(i, a));
        archive =
            yd_raft_application_archive(i, dir, cluster, 3, NULL, NULL, id, error, sizeof(error));
        REQUIRE(archive);
        yd_raft_snapshot_archive_close(archive);
        close(dir);
    }
    yd_raft_application_image_close(i);
    yd_raft_application_close(a);
    return 0;
}
static int corruption(const char *root, unsigned mode) {
    char path[4096], id[65];
    int dir = directory(root, "source", path);
    REQUIRE(dir >= 0);
    close(dir);
    YDRaftApplication *a = seed(path);
    REQUIRE(a);
    YDRaftApplicationImage *i = image(root, a, "compact");
    REQUIRE(i);
    dir = directory(root, "archives", path);
    REQUIRE(dir >= 0);
    corrupt_directory = dir;
    corrupt_archive = mode == 0;
    Progress p = {.change = mode == 1 ? yd_raft_application_image_disk(i) : NULL};
    if (mode == 2)
        REQUIRE(change_receipt(yd_raft_application_image_disk(i), 500));
    YDRaftSnapshotArchive *archive = yd_raft_application_archive(
        i, dir, cluster, 3, mode == 1 ? progress : NULL, &p, id, error, sizeof(error));
    REQUIRE(!archive && !id[0] &&
            (mode == 2   ? !entries(dir)
             : mode == 1 ? p.changed
                         : corrupted) &&
            document(yd_raft_application_disk(a), 5));
    if (mode == 0) {
        corrupt_archive = false;
        REQUIRE(!yd_raft_application_archive(i, dir, cluster, 3, NULL, NULL, id, error,
                                             sizeof(error)) &&
                !id[0] && entries(dir) == 1);
    }
    yd_raft_application_image_close(i);
    yd_raft_application_close(a);
    close(dir);
    return 0;
}
static unsigned entries(int directory_fd) {
    int fd = openat(directory_fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    DIR *d = fd >= 0 ? fdopendir(fd) : NULL;
    if (!d)
        return UINT32_MAX;
    unsigned n = 0;
    struct dirent *entry;
    while ((entry = readdir(d)))
        if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, ".."))
            n++;
    closedir(d);
    return n;
}
static bool stop_copy(void *context, YDRaftApplicationCopyPhase phase, uint64_t done,
                      uint64_t total) {
    (void)context;
    (void)done;
    (void)total;
    return phase != YD_RAFT_APPLICATION_COPY;
}
static int boundaries(const char *root) {
    char path[4096], id[65];
    int dir = directory(root, "source", path);
    REQUIRE(dir >= 0);
    close(dir);
    YDRaftApplication *a = yd_raft_application_open(path, cluster, 32768, error, sizeof(error));
    REQUIRE(a);
    YDRaftApplicationImage *i = image(root, a, "compact");
    REQUIRE(i);
    YDRaftCheckpoint position;
    memset(&position, 255, sizeof(position));
    REQUIRE(!yd_raft_application_image_checkpoint(NULL, &position, error, sizeof(error)) &&
            !position.applied.index &&
            !yd_raft_application_image_checkpoint(i, NULL, error, sizeof(error)));
    REQUIRE(!yd_raft_snapshot_from_checkpoint(NULL, &position, 3, error, sizeof(error)));
    for (unsigned mode = 0; mode < 4; mode++) {
        YDDiskCheckpoint *owned =
            yd_raft_application_image_checkpoint(i, &position, error, sizeof(error));
        REQUIRE(owned);
        if (mode == 2)
            position.applied.index++;
        if (mode == 3)
            memset(position.cluster, 0, sizeof(position.cluster));
        REQUIRE(!yd_raft_snapshot_from_checkpoint(owned, mode == 0 ? NULL : &position,
                                                  mode == 1 ? 2 : 3, error, sizeof(error)));
    }
    dir = directory(root, "archives", path);
    REQUIRE(dir >= 0);
    unsigned char wrong[16] = {9};
    REQUIRE(
        !yd_raft_application_archive(NULL, dir, cluster, 3, NULL, NULL, id, error, sizeof(error)) &&
        !id[0] &&
        !yd_raft_application_archive(i, -1, cluster, 3, NULL, NULL, id, error, sizeof(error)) &&
        !yd_raft_application_archive(i, dir, NULL, 3, NULL, NULL, id, error, sizeof(error)) &&
        !yd_raft_application_archive(i, dir, wrong, 3, NULL, NULL, id, error, sizeof(error)) &&
        !yd_raft_application_archive(i, dir, cluster, 2, NULL, NULL, id, error, sizeof(error)) &&
        !yd_raft_application_archive(i, dir, cluster, 3, NULL, NULL, NULL, error, sizeof(error)) &&
        !entries(dir));
    REQUIRE(
        !fchmod(dir, 0777) &&
        !yd_raft_application_archive(i, dir, cluster, 3, NULL, NULL, id, error, sizeof(error)) &&
        !entries(dir));
    REQUIRE(!fchmod(dir, 0700));
    YDRaftSnapshotArchive *archive =
        yd_raft_application_archive(i, dir, cluster, 3, NULL, NULL, id, error, sizeof(error));
    REQUIRE(archive);
    unsigned char manifest[256];
    YDRaftSnapshotInfo info;
    REQUIRE(verify(archive, manifest) &&
            yd_raft_snapshot_decode(manifest, 256, cluster, 3, &info, error, sizeof(error)) &&
            !info.applied.index && info.view.generation == 2);
    yd_raft_snapshot_archive_close(archive);
    REQUIRE(noop(a));
    YDRaftApplicationCapture *later = yd_raft_application_capture(a, 32768, error, sizeof(error));
    REQUIRE(
        later && !yd_raft_application_catch_up(i, later, stop_copy, NULL, error, sizeof(error)) &&
        !yd_raft_application_image_disk(i) &&
        !yd_raft_application_image_checkpoint(i, &position, error, sizeof(error)) &&
        !position.applied.index &&
        !yd_raft_application_archive(i, dir, cluster, 3, NULL, NULL, id, error, sizeof(error)) &&
        !id[0] && entries(dir) == 1);
    yd_raft_application_capture_close(later);
    yd_raft_application_image_close(i);
    yd_raft_application_close(a);
    close(dir);
    return 0;
}
int main(int argc, char **argv) {
    if (argc != 3)
        return 2;
    if (!strcmp(argv[2], "archive"))
        return basic(argv[1]);
    if (!strcmp(argv[2], "checkpoint"))
        return checkpoint(argv[1]);
    if (!strcmp(argv[2], "lifetime"))
        return lifetime(argv[1]);
    if (!strcmp(argv[2], "cancel"))
        return cancellation(argv[1]);
    if (!strcmp(argv[2], "sync"))
        return sync_failure(argv[1]);
    if (!strcmp(argv[2], "corrupt"))
        return corruption(argv[1], 0);
    if (!strcmp(argv[2], "changed"))
        return corruption(argv[1], 1);
    if (!strcmp(argv[2], "graph"))
        return corruption(argv[1], 2);
    if (!strcmp(argv[2], "boundaries"))
        return boundaries(argv[1]);
    return 2;
}
