#define _POSIX_C_SOURCE 200809L
#include "../src/consensus/application_copy.h"
#include "../src/consensus/application_internal.h"
#include "../src/disk_changes.h"
#include "../src/disk_internal.h"
#include "../src/disk_log.h"
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
static const unsigned char source[] = "# exact source\r\ncount: 0\r\nname: 'first' # keep\r\n";
static unsigned sync_calls, fail_sync, corrupt_copy;
static bool corrupted_copy, tampered_valid;
static YDRaftCheckpoint expected_position;
int __real_fsync(int fd);
int __wrap_fsync(int fd) {
    if (++sync_calls == fail_sync) {
        errno = EIO;
        return -1;
    }
    return __real_fsync(fd);
}
YDDisk *__real_yd_disk_pin(YDDisk *, size_t, char *, size_t);
YDDisk *__wrap_yd_disk_pin(YDDisk *source_disk, size_t cache, char *failure, size_t length) {
    YDDisk *pin = __real_yd_disk_pin(source_disk, cache, failure, length);
    if (!pin || !corrupt_copy)
        return pin;
    unsigned kind = corrupt_copy;
    corrupt_copy = 0;
    YDDiskView view = yd_disk_view(pin);
    if (kind == 2) {
        unsigned char zero[YD_DISK_PAGE] = {0};
        corrupted_copy =
            pwrite(pin->fd, zero, sizeof(zero), (off_t)((view.generation % 2) * YD_DISK_PAGE)) ==
            (ssize_t)sizeof(zero);
    } else {
        unsigned char key[20] = {0, 'Y', 'R', 'R', 1};
        uint64_t offset = 0;
        size_t size = 0;
        bool valid = yd_disk_get(pin, &view, key, sizeof(key), &offset, failure, length) == 1;
        unsigned char *bytes =
            valid ? yd_disk_record(pin, &view, offset, &size, failure, length) : NULL;
        valid = valid && bytes && size >= 128 && bytes[80] == 201;
        if (valid) {
            bytes[80] = 200; /* Another legal status with a valid native checksum. */
            uint32_t crc = yd_disk_crc(bytes, size);
            unsigned char encoded[4];
            for (unsigned i = 0; i < 4; i++)
                encoded[i] = (unsigned char)(crc >> (8 * i));
            valid = pwrite(pin->fd, bytes, size, (off_t)(offset + 16)) == (ssize_t)size &&
                    pwrite(pin->fd, encoded, 4, (off_t)(offset + 12)) == 4;
        }
        free(bytes);
        corrupted_copy = valid;
    }
    tampered_valid =
        yd_raft_application_validate_at(pin, &expected_position, &view, failure, length);
    return pin;
}
static int candidate(const char *root, const char *name, char path[4096]) {
    snprintf(path, 4096, "%s/%s", root, name);
    return mkdir(path, 0700) ? -1 : open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
}
static YDRaftWrite request(unsigned id, const char *method, const char *path,
                           const unsigned char *body, size_t size) {
    YDRaftWrite w = {.method = method, .target = path, .body = body, .size = size};
    w.id[0] = (unsigned char)id;
    return w;
}
static bool noop(YDRaftApplication *a) {
    YDRaftEntry e = {
        .index = yd_raft_application_position(a).index + 1, .term = 1, .kind = YD_RAFT_NOOP};
    return yd_raft_application_apply(a, &e, error, sizeof(error));
}
static bool commit(YDRaftApplication *a, const YDRaftWrite *w) {
    YDRaftProposal p = {0};
    int prepared = yd_raft_application_prepare(a, w, &p, error, sizeof(error));
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
    YDRaftWrite w = request(1, "PUT", target, source, sizeof(source) - 1);
    const char indexes[] =
        "{indexes: [{collection: config, name: count, fields: [count], unique: true},"
        "{collection: config, name: words, fields: [name], type: text}]}";
    bool valid = a && noop(a) && commit(a, &w);
    w = request(2, "PUT", "/v1/indexes", (const unsigned char *)indexes, strlen(indexes));
    valid = valid && commit(a, &w);
    const char historical[] = "count: -1\nname: vanished\n";
    w = request(3, "PUT", "/v1/collections/config/documents/deleted",
                (const unsigned char *)historical, strlen(historical));
    valid = valid && commit(a, &w);
    w = request(4, "DELETE", "/v1/collections/config/documents/deleted", NULL, 0);
    valid = valid && commit(a, &w);
    const unsigned char patch[] = "{\"$inc\":{\"count\":1}}";
    for (unsigned i = 0; valid && i < 20; i++) {
        w = request(10 + i, "PATCH", target, patch, sizeof(patch) - 1);
        valid = commit(a, &w);
    }
    for (unsigned i = 0; valid && i < 50; i++)
        valid = noop(a);
    if (valid)
        return a;
    yd_raft_application_close(a);
    return NULL;
}
static bool document(YDDisk *disk, const unsigned char *bytes, size_t size) {
    YDDiskView view = yd_disk_view(disk);
    YDDiskDocument d = {0};
    int found = yd_disk_document_get(disk, &view, "config", "node", &d, error, sizeof(error));
    bool valid = found == 1 && d.length == size && !memcmp(d.body, bytes, size);
    yd_disk_document_free(&d);
    return valid;
}
static YDDiskReply feed(YDDisk *disk) {
    YDDiskView view = yd_disk_view(disk);
    YDDiskLog log;
    if (yd_disk_log_load(disk, &view, &log, error, sizeof(error)) != 1)
        return (YDDiskReply){0};
    char token[53], path[128];
    yd_disk_log_token(&log, log.floor, token);
    snprintf(path, sizeof(path), "/v1/changes?after=%s&limit=100", token);
    return yd_disk_changes_request(disk, &view, path);
}
static bool same_feed(const YDDiskReply *expected, YDDisk *disk) {
    YDDiskReply actual = feed(disk);
    bool valid =
        expected->status == 200 && actual.status == 200 && actual.length == expected->length &&
        !memcmp(actual.body, expected->body, actual.length) &&
        !strcmp(actual.revision, expected->revision) && !strcmp(actual.headers, expected->headers);
    yd_disk_reply_free(&actual);
    return valid;
}
static bool inspect(YDRaftApplicationImage *image, YDRaftApplicationCopyInfo info,
                    const YDDiskReply *before) {
    YDDisk *d = yd_raft_application_image_disk(image);
    if (!d || yd_disk_writable(d) || yd_disk_stats(d).cache_bytes > 32768)
        return false;
    YDDiskView v = yd_disk_view(d);
    YDRaftApplicationCopyInfo actual = yd_raft_application_image_info(image);
    const unsigned char final[] = "# exact source\r\ncount: 20\r\nname: 'first' # keep\r\n";
    YDDiskIndexes *ix = yd_disk_indexes_load(d, &v, error, sizeof(error));
    bool valid = ix && ix->count == 2 && v.format == 6 && v.generation == info.source.generation &&
                 v.revision == info.source.revision && v.bytes == info.source.bytes &&
                 v.documents == info.source.documents && v.collections == info.source.collections &&
                 actual.source.root == info.source.root && actual.source.end == info.source.end &&
                 actual.checkpoint.applied.index == info.checkpoint.applied.index &&
                 !memcmp(actual.checkpoint.digest, info.checkpoint.digest, 32) &&
                 yd_raft_application_validate_at(d, &info.checkpoint, &v, error, sizeof(error)) &&
                 document(d, final, sizeof(final) - 1) && same_feed(before, d);
    yd_disk_indexes_free(ix);
    return valid;
}
static int basic(const char *root) {
    char path[4096], copy_path[4096];
    int dir = candidate(root, "source", path);
    REQUIRE(dir >= 0);
    close(dir);
    YDRaftApplication *a = seed(path);
    REQUIRE(a);
    YDDiskView before = yd_disk_view(yd_raft_application_disk(a));
    YDDiskReply changes = feed(yd_raft_application_disk(a));
    REQUIRE(changes.status == 200 && strstr(changes.body, "vanished"));
    YDRaftApplicationCapture *c = yd_raft_application_capture(a, 32768, error, sizeof(error));
    REQUIRE(c);
    YDRaftApplicationCopyInfo info = yd_raft_application_capture_info(c);
    dir = candidate(root, "copy", copy_path);
    REQUIRE(dir >= 0);
    YDRaftApplicationImage *image =
        yd_raft_application_copy(c, dir, 32768, NULL, NULL, error, sizeof(error));
    REQUIRE(image && inspect(image, info, &changes));
    REQUIRE(yd_disk_view(yd_raft_application_image_disk(image)).end * 2 < before.end &&
            yd_disk_view(yd_raft_application_disk(a)).generation == before.generation &&
            faccessat(dir, ".yamora-initializing", F_OK, 0) == 0 && noop(a));
    yd_raft_application_image_close(image);
    /* Explicit activation only in this disposable fixture, never production selection. */
    REQUIRE(!unlinkat(dir, ".yamora-initializing", 0) && !fsync(dir));
    YDRaftApplication *copy =
        yd_raft_application_open_existing_at(dir, cluster, 32768, error, sizeof(error));
    REQUIRE(copy);
    YDRaftWrite put = request(1, "PUT", target, source, sizeof(source) - 1);
    YDRaftProposal p = {0};
    REQUIRE(yd_raft_application_prepare(copy, &put, &p, error, sizeof(error)) == 0 &&
            p.reply.status == 201);
    yd_raft_proposal_free(&p);
    const unsigned char patch[] = "{\"$inc\":{\"count\":1}}";
    YDRaftWrite w = request(99, "PATCH", target, patch, sizeof(patch) - 1);
    const unsigned char final[] = "# exact source\r\ncount: 21\r\nname: 'first' # keep\r\n";
    REQUIRE(commit(copy, &w) && document(yd_raft_application_disk(copy), final, sizeof(final) - 1));
    yd_raft_application_close(copy);
    yd_raft_application_capture_close(c);
    yd_raft_application_close(a);
    yd_disk_reply_free(&changes);
    close(dir);
    return 0;
}
typedef struct {
    YDRaftApplication *a;
    unsigned seen, next_id;
    int cancel;
    bool valid;
} Progress;
static void *writer(void *context) {
    Progress *p = context;
    const unsigned char patch[] = "{\"$inc\":{\"count\":1}}";
    for (unsigned i = 0; p->valid && i < 20; i++) {
        YDRaftWrite w = request(p->next_id++, "PATCH", target, patch, sizeof(patch) - 1);
        p->valid = commit(p->a, &w);
    }
    return NULL;
}
static bool progress(void *context, YDRaftApplicationCopyPhase phase, uint64_t done,
                     uint64_t total) {
    Progress *p = context;
    if (total && done > total)
        p->valid = false;
    if (!(p->seen & (1U << phase))) {
        p->seen |= 1U << phase;
        if (p->a) {
            pthread_t thread;
            if (pthread_create(&thread, NULL, writer, p) || pthread_join(thread, NULL))
                p->valid = false;
        }
    }
    return p->valid && p->cancel != (int)phase;
}
static int writing(const char *root) {
    char path[4096];
    int dir = candidate(root, "source", path);
    REQUIRE(dir >= 0);
    close(dir);
    YDRaftApplication *a = seed(path);
    REQUIRE(a);
    YDDiskReply changes = feed(yd_raft_application_disk(a));
    YDRaftApplicationCapture *c = yd_raft_application_capture(a, 32768, error, sizeof(error));
    REQUIRE(c);
    YDRaftApplicationCopyInfo info = yd_raft_application_capture_info(c);
    dir = candidate(root, "copy", path);
    REQUIRE(dir >= 0);
    Progress p = {.a = a, .valid = true, .cancel = -1, .next_id = 50};
    YDRaftApplicationImage *image =
        yd_raft_application_copy(c, dir, 32768, progress, &p, error, sizeof(error));
    REQUIRE(image && p.valid && p.seen == 14 && inspect(image, info, &changes) &&
            yd_raft_application_position(a).index == info.checkpoint.applied.index + 60);
    const unsigned char final[] = "# exact source\r\ncount: 80\r\nname: 'first' # keep\r\n";
    REQUIRE(document(yd_raft_application_disk(a), final, sizeof(final) - 1));
    yd_raft_application_image_close(image);
    yd_raft_application_capture_close(c);
    yd_raft_application_close(a);
    yd_disk_reply_free(&changes);
    close(dir);
    return 0;
}
static int lifetime(const char *root) {
    char path[4096], renamed[4096];
    int dir = candidate(root, "source", path);
    REQUIRE(dir >= 0);
    close(dir);
    YDRaftApplication *a = seed(path);
    REQUIRE(a);
    YDDiskReply changes = feed(yd_raft_application_disk(a));
    YDRaftApplicationCapture *c = yd_raft_application_capture(a, 32768, error, sizeof(error));
    REQUIRE(c);
    YDRaftApplicationCopyInfo info = yd_raft_application_capture_info(c);
    yd_raft_application_close(a);
    snprintf(renamed, sizeof(renamed), "%s/renamed", root);
    REQUIRE(!rename(path, renamed));
    REQUIRE(!yd_raft_application_open(renamed, cluster, 32768, error, sizeof(error)));
    dir = candidate(root, "copy", path);
    REQUIRE(dir >= 0);
    YDRaftApplicationImage *image =
        yd_raft_application_copy(c, dir, 32768, NULL, NULL, error, sizeof(error));
    REQUIRE(image && inspect(image, info, &changes));
    YDDisk *reader =
        yd_disk_pin(yd_raft_application_image_disk(image), 32768, error, sizeof(error));
    REQUIRE(reader);
    yd_raft_application_capture_close(c);
    c = NULL;
    /* Origin identity remains pinned by the image after the capture is gone. */
    REQUIRE(!yd_raft_application_open(renamed, cluster, 32768, error, sizeof(error)));
    yd_raft_application_image_close(image);
    yd_raft_application_capture_close(c);
    YDRaftApplication *reopened =
        yd_raft_application_open(renamed, cluster, 32768, error, sizeof(error));
    REQUIRE(reopened);
    yd_raft_application_close(reopened);
    REQUIRE(same_feed(&changes, reader) && !yd_disk_writable(reader));
    yd_disk_close(reader);
    yd_disk_reply_free(&changes);
    close(dir);
    return 0;
}
static int rejection(const char *root) {
    char path[4096];
    int dir = candidate(root, "source", path);
    REQUIRE(dir >= 0);
    close(dir);
    YDRaftApplication *a = seed(path);
    REQUIRE(a);
    REQUIRE(!yd_raft_application_capture(NULL, 32768, error, sizeof(error)) &&
            !yd_raft_application_capture(a, 1, error, sizeof(error)));
    YDRaftApplicationCapture *c = yd_raft_application_capture(a, 32768, error, sizeof(error));
    REQUIRE(c);
    dir = candidate(root, "invalid", path);
    REQUIRE(dir >= 0);
    REQUIRE(!yd_raft_application_copy(NULL, dir, 32768, NULL, NULL, error, sizeof(error)) &&
            !yd_raft_application_copy(c, -1, 32768, NULL, NULL, error, sizeof(error)) &&
            !yd_raft_application_copy(c, dir, 1, NULL, NULL, error, sizeof(error)));
    REQUIRE(!fchmod(dir, 0777) &&
            !yd_raft_application_copy(c, dir, 32768, NULL, NULL, error, sizeof(error)));
    REQUIRE(!fchmod(dir, 0700) && !symlinkat("/dev/null", dir, YD_DISK_FILE) &&
            !yd_raft_application_copy(c, dir, 32768, NULL, NULL, error, sizeof(error)));
    REQUIRE(faccessat(dir, ".yamora-initializing", F_OK, 0) != 0);
    close(dir);
    for (unsigned phase = 1; phase <= 3; phase++) {
        char name[32];
        snprintf(name, sizeof(name), "cancel%u", phase);
        dir = candidate(root, name, path);
        REQUIRE(dir >= 0);
        Progress p = {.valid = true, .cancel = (int)phase};
        REQUIRE(!yd_raft_application_copy(c, dir, 32768, progress, &p, error, sizeof(error)) &&
                p.valid && (faccessat(dir, ".yamora-initializing", F_OK, 0) == 0) == (phase != 1) &&
                noop(a));
        close(dir);
    }
    /* A captured bad source must be rejected before creating any candidate files. */
    YDDisk *d = yd_raft_application_disk(a);
    YDDiskView v = yd_disk_view(d);
    unsigned char key[] = "Dconfig\0node";
    uint64_t off;
    REQUIRE(yd_disk_get(d, &v, key, sizeof(key) - 1, &off, error, sizeof(error)) == 1);
    unsigned char old;
    REQUIRE(pread(d->fd, &old, 1, (off_t)(off + 16)) == 1);
    unsigned char bad = old ^ 1;
    REQUIRE(pwrite(d->fd, &bad, 1, (off_t)(off + 16)) == 1);
    YDRaftApplicationCapture *broken = yd_raft_application_capture(a, 32768, error, sizeof(error));
    REQUIRE(broken);
    dir = candidate(root, "corrupt-source", path);
    REQUIRE(dir >= 0);
    REQUIRE(!yd_raft_application_copy(broken, dir, 32768, NULL, NULL, error, sizeof(error)) &&
            faccessat(dir, ".yamora-initializing", F_OK, 0) != 0 &&
            faccessat(dir, YD_DISK_FILE, F_OK, 0) != 0);
    REQUIRE(pwrite(d->fd, &old, 1, (off_t)(off + 16)) == 1 && noop(a));
    yd_raft_application_capture_close(broken);
    yd_raft_application_capture_close(c);
    yd_raft_application_close(a);
    close(dir);
    return 0;
}
static int sync_failure(const char *root) {
    char path[4096];
    int dir = candidate(root, "source", path);
    REQUIRE(dir >= 0);
    close(dir);
    YDRaftApplication *a = seed(path);
    REQUIRE(a);
    YDRaftApplicationCapture *c = yd_raft_application_capture(a, 32768, error, sizeof(error));
    REQUIRE(c);
    dir = candidate(root, "measure", path);
    REQUIRE(dir >= 0);
    sync_calls = 0;
    YDRaftApplicationImage *image =
        yd_raft_application_copy(c, dir, 32768, NULL, NULL, error, sizeof(error));
    REQUIRE(image && sync_calls >= 6);
    unsigned calls = sync_calls;
    yd_raft_application_image_close(image);
    close(dir);
    for (unsigned i = 1; i <= calls; i++) {
        char name[32];
        snprintf(name, sizeof(name), "sync%u", i);
        dir = candidate(root, name, path);
        REQUIRE(dir >= 0);
        YDRaftApplied before = yd_raft_application_position(a);
        sync_calls = 0;
        fail_sync = i;
        image = yd_raft_application_copy(c, dir, 32768, NULL, NULL, error, sizeof(error));
        fail_sync = 0;
        REQUIRE(!image && sync_calls >= i && faccessat(dir, ".yamora-initializing", F_OK, 0) == 0 &&
                yd_raft_application_position(a).index == before.index && noop(a));
        close(dir);
    }
    yd_raft_application_capture_close(c);
    yd_raft_application_close(a);
    return 0;
}
static int readback(const char *root) {
    char path[4096];
    int dir = candidate(root, "source", path);
    REQUIRE(dir >= 0);
    close(dir);
    YDRaftApplication *a = seed(path);
    REQUIRE(a);
    YDRaftApplicationCapture *c = yd_raft_application_capture(a, 32768, error, sizeof(error));
    REQUIRE(c);
    expected_position = yd_raft_application_capture_info(c).checkpoint;
    for (unsigned i = 1; i <= 2; i++) {
        char name[32];
        snprintf(name, sizeof(name), "readback%u", i);
        dir = candidate(root, name, path);
        REQUIRE(dir >= 0);
        corrupt_copy = i;
        corrupted_copy = tampered_valid = false;
        YDRaftApplicationImage *image =
            yd_raft_application_copy(c, dir, 32768, NULL, NULL, error, sizeof(error));
        REQUIRE(!image && corrupted_copy && tampered_valid &&
                faccessat(dir, ".yamora-initializing", F_OK, 0) == 0 && noop(a));
        close(dir);
    }
    yd_raft_application_capture_close(c);
    yd_raft_application_close(a);
    return 0;
}
static int boundaries(const char *root) {
    char path[4096];
    int dir = candidate(root, "source", path);
    REQUIRE(dir >= 0);
    close(dir);
    YDRaftApplication *a = yd_raft_application_open(path, cluster, 32768, error, sizeof(error));
    REQUIRE(a);
    for (unsigned i = 0; i < 3; i++) {
        unsigned char *large = NULL;
        size_t size = 3 * 1024 * 1024;
        if (i == 1) {
            large = malloc(size);
            REQUIRE(large);
            memset(large, 'x', size);
            memcpy(large, "# exact\r\npayload: '", 19);
            memcpy(large + size - 3, "'\r\n", 3);
            YDRaftWrite w = request(1, "PUT", target, large, size);
            REQUIRE(noop(a) && commit(a, &w));
        }
        if (i == 2) {
            /* More relocation keys than fit in one native leaf. */
            for (unsigned batch = 0; batch < 9; batch++) {
                char body[32768];
                size_t at = (size_t)snprintf(body, sizeof(body), "{\"operations\":[");
                for (unsigned j = 0; j < 128; j++) {
                    unsigned n = batch * 128 + j;
                    int added = snprintf(body + at, sizeof(body) - at,
                                         "%s{\"collection\":\"config\",\"document\":\"many%u\","
                                         "\"put\":\"value: %u\\n\"}",
                                         j ? "," : "", n, n);
                    REQUIRE(added > 0 && (size_t)added < sizeof(body) - at);
                    at += (size_t)added;
                }
                memcpy(body + at, "]}", 2);
                at += 2;
                YDRaftWrite w = request(50 + batch, "POST", "/v1/transactions",
                                        (const unsigned char *)body, at);
                REQUIRE(commit(a, &w));
            }
        }
        YDRaftApplicationCapture *c = yd_raft_application_capture(a, 32768, error, sizeof(error));
        REQUIRE(c);
        YDRaftApplicationCopyInfo info = yd_raft_application_capture_info(c);
        dir = candidate(root, i == 2 ? "many" : i ? "large" : "genesis", path);
        REQUIRE(dir >= 0);
        YDRaftApplicationImage *image =
            yd_raft_application_copy(c, dir, 32768, NULL, NULL, error, sizeof(error));
        REQUIRE(image);
        YDDisk *d = yd_raft_application_image_disk(image);
        YDDiskView v = yd_disk_view(d);
        REQUIRE(yd_raft_application_validate_at(d, &info.checkpoint, &v, error, sizeof(error)) &&
                v.generation == info.source.generation && yd_disk_stats(d).cache_bytes <= 32768 &&
                (i == 2 ? v.documents == 1153
                 : i    ? document(d, large, size)
                        : v.generation == 2 && !v.documents));
        free(large);
        yd_raft_application_image_close(image);
        yd_raft_application_capture_close(c);
        close(dir);
    }
    REQUIRE(!yd_raft_application_capture_info(NULL).source.generation &&
            !yd_raft_application_image_info(NULL).source.generation &&
            !yd_raft_application_image_disk(NULL));
    yd_raft_application_capture_close(NULL);
    yd_raft_application_image_close(NULL);
    yd_raft_application_close(a);
    return 0;
}
static int catchup(const char *root) {
    char path[4096];
    int dir = candidate(root, "source", path);
    REQUIRE(dir >= 0);
    close(dir);
    YDRaftApplication *a = seed(path);
    REQUIRE(a);
    YDRaftApplicationCapture *base = yd_raft_application_capture(a, 32768, error, sizeof(error));
    REQUIRE(base);
    YDDiskReply before = feed(yd_raft_application_disk(a));
    dir = candidate(root, "copy", path);
    REQUIRE(dir >= 0);
    YDRaftApplicationImage *image =
        yd_raft_application_copy(base, dir, 32768, NULL, NULL, error, sizeof(error));
    REQUIRE(image);
    YDDisk *old = yd_disk_pin(yd_raft_application_image_disk(image), 32768, error, sizeof(error));
    REQUIRE(old);
    const unsigned char empty[] = "{indexes: []}";
    YDRaftWrite w = request(100, "PUT", "/v1/indexes", empty, sizeof(empty) - 1);
    REQUIRE(commit(a, &w));
    w = request(101, "DELETE", target, NULL, 0);
    REQUIRE(commit(a, &w));
    for (unsigned i = 0; i < 4100; i++)
        REQUIRE(noop(a));
    YDDisk *active = yd_raft_application_disk(a);
    YDDiskView v = yd_disk_view(active);
    YDDiskLog log;
    REQUIRE(yd_disk_log_load(active, &v, &log, error, sizeof(error)) == 1 && log.floor > 0);
    YDDiskReply after = feed(active);
    REQUIRE(after.status == 200);
    YDRaftApplicationCapture *latest = yd_raft_application_capture(a, 32768, error, sizeof(error));
    REQUIRE(latest);
    REQUIRE(yd_raft_application_catch_up(image, latest, NULL, NULL, error, sizeof(error)) &&
            yd_raft_application_image_current(image, a) &&
            same_feed(&after, yd_raft_application_image_disk(image)) && same_feed(&before, old));
    YDDisk *d = yd_raft_application_image_disk(image);
    v = yd_disk_view(d);
    YDDiskDocument doc = {0};
    REQUIRE(v.documents == 1 &&
            yd_disk_document_get(d, &v, "config", "node", &doc, error, sizeof(error)) == 0);
    yd_disk_document_free(&doc);
    YDDiskIndexes *ix = yd_disk_indexes_load(d, &v, error, sizeof(error));
    REQUIRE(ix && !ix->count);
    yd_disk_indexes_free(ix);
    yd_raft_application_image_close(image);
    yd_raft_application_capture_close(base);
    yd_raft_application_capture_close(latest);
    yd_raft_application_close(a);
    REQUIRE(same_feed(&before, old));
    yd_disk_close(old);
    REQUIRE(!unlinkat(dir, ".yamora-initializing", 0) && !fsync(dir));
    YDRaftApplication *reopened =
        yd_raft_application_open_existing_at(dir, cluster, 32768, error, sizeof(error));
    REQUIRE(reopened);
    YDRaftWrite original = request(1, "PUT", target, source, sizeof(source) - 1);
    YDRaftProposal p = {0};
    REQUIRE(yd_raft_application_prepare(reopened, &original, &p, error, sizeof(error)) == 0 &&
            p.reply.status == 201);
    yd_raft_proposal_free(&p);
    d = yd_raft_application_disk(reopened);
    v = yd_disk_view(d);
    REQUIRE(yd_disk_document_get(d, &v, "config", "node", &doc, error, sizeof(error)) == 0);
    yd_disk_document_free(&doc);
    yd_raft_application_close(reopened);
    yd_disk_reply_free(&before);
    yd_disk_reply_free(&after);
    close(dir);
    return 0;
}
static int catchup_large(const char *root) {
    char path[4096], renamed[4096];
    int dir = candidate(root, "source", path);
    REQUIRE(dir >= 0);
    close(dir);
    YDRaftApplication *a = yd_raft_application_open(path, cluster, 32768, error, sizeof(error));
    REQUIRE(a);
    size_t size = 3 * 1024 * 1024;
    unsigned char *body = malloc(size);
    REQUIRE(body);
    memset(body, 'x', size);
    memcpy(body, "payload: '", 10);
    memcpy(body + size - 2, "'\n", 2);
    YDRaftWrite w = request(1, "PUT", target, body, size);
    REQUIRE(noop(a) && commit(a, &w));
    YDRaftApplicationCapture *base = yd_raft_application_capture(a, 32768, error, sizeof(error));
    REQUIRE(base);
    dir = candidate(root, "copy", renamed);
    REQUIRE(dir >= 0);
    YDRaftApplicationImage *image =
        yd_raft_application_copy(base, dir, 32768, NULL, NULL, error, sizeof(error));
    REQUIRE(image);
    uint64_t end = yd_disk_view(yd_raft_application_image_disk(image)).end;
    sync_calls = 0;
    REQUIRE(yd_raft_application_catch_up(image, base, NULL, NULL, error, sizeof(error)) &&
            !sync_calls && yd_disk_view(yd_raft_application_image_disk(image)).end == end);
    REQUIRE(noop(a));
    YDDiskReply after = feed(yd_raft_application_disk(a));
    YDRaftApplicationCapture *latest = yd_raft_application_capture(a, 32768, error, sizeof(error));
    REQUIRE(latest);
    yd_raft_application_close(a);
    snprintf(renamed, sizeof(renamed), "%s/renamed", root);
    REQUIRE(!rename(path, renamed));
    REQUIRE(yd_raft_application_catch_up(image, latest, NULL, NULL, error, sizeof(error)) &&
            document(yd_raft_application_image_disk(image), body, size) &&
            same_feed(&after, yd_raft_application_image_disk(image)) &&
            yd_disk_view(yd_raft_application_image_disk(image)).end - end < 1024 * 1024);
    free(body);
    yd_disk_reply_free(&after);
    yd_raft_application_image_close(image);
    yd_raft_application_capture_close(base);
    yd_raft_application_capture_close(latest);
    close(dir);
    return 0;
}
static int current(const char *root) {
    char path[4096];
    int dir = candidate(root, "source", path);
    REQUIRE(dir >= 0);
    close(dir);
    YDRaftApplication *a = seed(path);
    REQUIRE(a);
    YDRaftApplicationCapture *base = yd_raft_application_capture(a, 32768, error, sizeof(error));
    REQUIRE(base);
    dir = candidate(root, "copy", path);
    REQUIRE(dir >= 0);
    YDRaftApplicationImage *image =
        yd_raft_application_copy(base, dir, 32768, NULL, NULL, error, sizeof(error));
    REQUIRE(image);
    REQUIRE(yd_raft_application_image_current(image, a));
    int other_dir = candidate(root, "other", path);
    REQUIRE(other_dir >= 0);
    close(other_dir);
    YDRaftApplication *other = seed(path);
    REQUIRE(other);
    YDRaftApplicationCapture *foreign =
        yd_raft_application_capture(other, 32768, error, sizeof(error));
    REQUIRE(foreign);
    YDRaftApplicationCopyInfo first = yd_raft_application_capture_info(base),
                              second = yd_raft_application_capture_info(foreign);
    REQUIRE(first.source.generation == second.source.generation &&
            first.source.root == second.source.root && first.source.end == second.source.end &&
            !memcmp(first.checkpoint.digest, second.checkpoint.digest, 32) &&
            !yd_raft_application_image_current(image, other) &&
            !yd_raft_application_catch_up(image, foreign, NULL, NULL, error, sizeof(error)) &&
            yd_raft_application_image_disk(image));
    REQUIRE(noop(a) && !yd_raft_application_image_current(image, a));
    YDRaftApplicationCapture *latest = yd_raft_application_capture(a, 32768, error, sizeof(error));
    REQUIRE(latest);
    REQUIRE(yd_raft_application_catch_up(image, latest, NULL, NULL, error, sizeof(error)) &&
            yd_raft_application_image_current(image, a) &&
            !yd_raft_application_catch_up(image, base, NULL, NULL, error, sizeof(error)) &&
            yd_raft_application_image_disk(image) && !yd_raft_application_image_current(NULL, a) &&
            !yd_raft_application_image_current(image, NULL) &&
            !yd_raft_application_catch_up(NULL, latest, NULL, NULL, error, sizeof(error)) &&
            !yd_raft_application_catch_up(image, NULL, NULL, NULL, error, sizeof(error)));
    REQUIRE(noop(a));
    YDDiskReply before = feed(yd_raft_application_disk(a));
    YDRaftApplicationCapture *writing = yd_raft_application_capture(a, 32768, error, sizeof(error));
    REQUIRE(writing);
    YDRaftApplicationCopyInfo info = yd_raft_application_capture_info(writing);
    Progress p = {.a = a, .valid = true, .cancel = -1, .next_id = 50};
    REQUIRE(yd_raft_application_catch_up(image, writing, progress, &p, error, sizeof(error)) &&
            p.valid && p.seen == 14 && inspect(image, info, &before) &&
            yd_raft_application_position(a).index == info.checkpoint.applied.index + 60 &&
            !yd_raft_application_image_current(image, a));
    YDRaftApplicationCapture *final = yd_raft_application_capture(a, 32768, error, sizeof(error));
    REQUIRE(final && yd_raft_application_catch_up(image, final, NULL, NULL, error, sizeof(error)) &&
            yd_raft_application_image_current(image, a));
    const unsigned char changed[] = "# exact source\r\ncount: 80\r\nname: 'first' # keep\r\n";
    YDDiskReply after = feed(yd_raft_application_disk(a));
    REQUIRE(document(yd_raft_application_image_disk(image), changed, sizeof(changed) - 1) &&
            same_feed(&after, yd_raft_application_image_disk(image)));
    yd_disk_reply_free(&before);
    yd_disk_reply_free(&after);
    yd_raft_application_capture_close(writing);
    yd_raft_application_capture_close(final);
    yd_raft_application_image_close(image);
    yd_raft_application_capture_close(base);
    yd_raft_application_capture_close(latest);
    yd_raft_application_capture_close(foreign);
    yd_raft_application_close(a);
    yd_raft_application_close(other);
    close(dir);
    return 0;
}
static int catchup_failure(const char *root) {
    char path[4096];
    int dir = candidate(root, "source", path);
    REQUIRE(dir >= 0);
    close(dir);
    YDRaftApplication *a = seed(path);
    REQUIRE(a);
    YDDiskReply before = feed(yd_raft_application_disk(a));
    YDRaftApplicationCapture *base = yd_raft_application_capture(a, 32768, error, sizeof(error));
    REQUIRE(base);
    REQUIRE(noop(a));
    YDRaftApplicationCapture *latest = yd_raft_application_capture(a, 32768, error, sizeof(error));
    REQUIRE(latest);
    expected_position = yd_raft_application_capture_info(latest).checkpoint;
    dir = candidate(root, "bad-source", path);
    REQUIRE(dir >= 0);
    YDRaftApplicationImage *probe =
        yd_raft_application_copy(base, dir, 32768, NULL, NULL, error, sizeof(error));
    REQUIRE(probe);
    YDDisk *active = yd_raft_application_disk(a);
    YDDiskView view = yd_disk_view(active);
    unsigned char key[] = "Dconfig\0node", prior;
    uint64_t offset;
    REQUIRE(yd_disk_get(active, &view, key, sizeof(key) - 1, &offset, error, sizeof(error)) == 1 &&
            pread(active->fd, &prior, 1, (off_t)(offset + 16)) == 1);
    unsigned char bad = prior ^ 1;
    REQUIRE(pwrite(active->fd, &bad, 1, (off_t)(offset + 16)) == 1);
    sync_calls = 0;
    REQUIRE(!yd_raft_application_catch_up(probe, latest, NULL, NULL, error, sizeof(error)) &&
            yd_raft_application_image_disk(probe) && !sync_calls);
    REQUIRE(pwrite(active->fd, &prior, 1, (off_t)(offset + 16)) == 1 &&
            yd_raft_application_catch_up(probe, latest, NULL, NULL, error, sizeof(error)));
    yd_raft_application_image_close(probe);
    close(dir);
    for (unsigned kind = 0; kind < 3; kind++) {
        unsigned count = kind == 0 ? 3 : 2;
        for (unsigned n = 1; n <= count; n++) {
            char name[32];
            snprintf(name, sizeof(name), "failure%u-%u", kind, n);
            dir = candidate(root, name, path);
            REQUIRE(dir >= 0);
            YDRaftApplicationImage *image =
                yd_raft_application_copy(base, dir, 32768, NULL, NULL, error, sizeof(error));
            REQUIRE(image);
            YDDisk *old =
                yd_disk_pin(yd_raft_application_image_disk(image), 32768, error, sizeof(error));
            REQUIRE(old);
            Progress p = {.valid = true, .cancel = (int)n};
            if (kind == 1) {
                sync_calls = 0;
                fail_sync = n;
            }
            if (kind == 2) {
                corrupt_copy = n;
                corrupted_copy = tampered_valid = false;
            }
            bool result = yd_raft_application_catch_up(image, latest, kind == 0 ? progress : NULL,
                                                       &p, error, sizeof(error));
            fail_sync = 0;
            REQUIRE(!result && same_feed(&before, old) &&
                    faccessat(dir, ".yamora-initializing", F_OK, 0) == 0 && noop(a));
            if (kind == 0 && n == 1)
                REQUIRE(yd_raft_application_image_disk(image));
            else
                REQUIRE(
                    !yd_raft_application_image_disk(image) &&
                    !yd_raft_application_catch_up(image, latest, NULL, NULL, error, sizeof(error)));
            if (kind == 1)
                REQUIRE(sync_calls >= n);
            if (kind == 2)
                REQUIRE(corrupted_copy && tampered_valid);
            yd_raft_application_image_close(image);
            REQUIRE(same_feed(&before, old));
            yd_disk_close(old);
            close(dir);
        }
    }
    yd_disk_reply_free(&before);
    yd_raft_application_capture_close(base);
    yd_raft_application_capture_close(latest);
    yd_raft_application_close(a);
    return 0;
}
typedef struct {
    YDRaftApplicationCopyPhase phase;
    uint64_t done;
    unsigned calls;
    bool comparison;
} ScanCancel;
static bool cancel_scan(void *context, YDRaftApplicationCopyPhase phase, uint64_t done, uint64_t total) {
    (void)total;
    ScanCancel *p = context;
    if (p->comparison) return phase != YD_RAFT_APPLICATION_VERIFY || !done || ++p->calls < 3;
    return phase != p->phase || done != p->done || ++p->calls < 3;
}
static int cancel_validation(const char *root) {
    char path[4096];
    int dir = candidate(root, "source", path);
    REQUIRE(dir >= 0);
    close(dir);
    YDRaftApplication *a = seed(path);
    REQUIRE(a);
    YDRaftApplicationCapture *base = yd_raft_application_capture(a, 32768, error, sizeof(error));
    REQUIRE(base && noop(a));
    YDRaftApplicationCapture *latest = yd_raft_application_capture(a, 32768, error, sizeof(error));
    REQUIRE(latest);
    for (unsigned mode = 0; mode < 7; mode++) {
        char name[32];
        snprintf(name, sizeof(name), "scan-%u", mode);
        dir = candidate(root, name, path);
        REQUIRE(dir >= 0);
        ScanCancel p = {.phase = mode >= 3 ? YD_RAFT_APPLICATION_VERIFY : YD_RAFT_APPLICATION_SOURCE,
            .done = mode == 2 ? 1 : 0, .comparison = mode >= 5};
        if (!mode) {
            REQUIRE(!yd_raft_application_copy(base, dir, 32768, cancel_scan, &p, error, sizeof(error)) &&
                p.calls == 3 && faccessat(dir, ".yamora-initializing", F_OK, 0) < 0 &&
                yd_disk_present(path) == 0);
        } else {
            YDRaftApplicationImage *image = yd_raft_application_copy(base, dir, 32768, NULL, NULL, error, sizeof(error));
            REQUIRE(image);
            YDDisk *old = yd_disk_pin(yd_raft_application_image_disk(image), 32768, error, sizeof(error));
            REQUIRE(old);
            YDDiskReply before = feed(old);
            const YDRaftApplicationCapture *c = (mode == 4 || mode == 5) ? base : latest;
            sync_calls = 0;
            REQUIRE(!yd_raft_application_catch_up(image, c, cancel_scan, &p, error, sizeof(error)) &&
                p.calls == 3 && same_feed(&before, old));
            if (mode == 3 || mode == 6) {
                REQUIRE(!yd_raft_application_image_disk(image) &&
                    !yd_raft_application_catch_up(image, latest, NULL, NULL, error, sizeof(error)));
            } else {
                REQUIRE(!sync_calls && yd_raft_application_image_disk(image) &&
                    yd_raft_application_catch_up(image, c, NULL, NULL, error, sizeof(error)));
            }
            yd_raft_application_image_close(image);
            REQUIRE(same_feed(&before, old));
            yd_disk_reply_free(&before);
            yd_disk_close(old);
        }
        close(dir);
    }
    REQUIRE(noop(a));
    yd_raft_application_capture_close(base);
    yd_raft_application_capture_close(latest);
    yd_raft_application_close(a);
    return 0;
}
int main(int argc, char **argv) {
    if (argc == 3 && !strcmp(argv[2], "cancel-validation")) return cancel_validation(argv[1]);
    if (argc != 3)
        return 2;
    if (!strcmp(argv[2], "basic"))
        return basic(argv[1]);
    if (!strcmp(argv[2], "writing"))
        return writing(argv[1]);
    if (!strcmp(argv[2], "lifetime"))
        return lifetime(argv[1]);
    if (!strcmp(argv[2], "rejection"))
        return rejection(argv[1]);
    if (!strcmp(argv[2], "sync"))
        return sync_failure(argv[1]);
    if (!strcmp(argv[2], "readback"))
        return readback(argv[1]);
    if (!strcmp(argv[2], "boundaries"))
        return boundaries(argv[1]);
    if (!strcmp(argv[2], "catchup"))
        return catchup(argv[1]);
    if (!strcmp(argv[2], "catchup-large"))
        return catchup_large(argv[1]);
    if (!strcmp(argv[2], "catchup-failure"))
        return catchup_failure(argv[1]);
    if (!strcmp(argv[2], "current"))
        return current(argv[1]);
    return 2;
}
