#define _POSIX_C_SOURCE 200809L
#include "../src/consensus/application_archive.h"
#include "../src/consensus/capture_internal.h"
#include "../src/consensus/snapshot_restore.h"
#include "../src/disk_documents.h"
#include "../src/disk_internal.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#define REQUIRE(x) do { if (!(x)) { \
    fprintf(stderr, "line %u: %s (%s)\n", __LINE__, #x, error); return 2; \
} } while (0)
static char error[512];
static const unsigned char cluster[16] = {1, 2, 3, 4};
static const unsigned char yaml[] = "# exact YAML\r\ncount: 7 # preserve\r\n";
static int create_failure, write_failure, pwrite_failure, fail_sync;
static _Atomic unsigned creations;
static bool allocation_failure;
void *__real_calloc(size_t, size_t);
void *__wrap_calloc(size_t count, size_t size) {
    if (allocation_failure) { allocation_failure = false; errno = ENOMEM; return NULL; }
    return __real_calloc(count, size);
}
int __real_openat(int, const char *, int, ...);
int __wrap_openat(int dir, const char *name, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
        creations++;
        if (create_failure) { errno = ENOSPC; return -1; }
    }
    return __real_openat(dir, name, flags, mode);
}
ssize_t __real_write(int, const void *, size_t);
ssize_t __wrap_write(int fd, const void *bytes, size_t size) {
    if (write_failure && size > YD_RAFT_SNAPSHOT_MANIFEST) {
        if (write_failure == 1) {
            write_failure = 2;
            return __real_write(fd, bytes, 3);
        }
        errno = ENOSPC;
        return -1;
    }
    return __real_write(fd, bytes, size);
}
ssize_t __real_pwrite(int, const void *, size_t, off_t);
ssize_t __wrap_pwrite(int fd, const void *bytes, size_t size, off_t offset) {
    if (pwrite_failure) {
        if (pwrite_failure == 1) {
            pwrite_failure = 2;
            return __real_pwrite(fd, bytes, size > 3 ? 3 : size, offset);
        }
        errno = ENOSPC;
        return -1;
    }
    return __real_pwrite(fd, bytes, size, offset);
}
int __real_fsync(int);
int __wrap_fsync(int fd) {
    if (fail_sync && --fail_sync == 0) { errno = EIO; return -1; }
    return __real_fsync(fd);
}
static int directory(const char *root, const char *name, char path[4096]) {
    snprintf(path, 4096, "%s/%s", root, name);
    return mkdir(path, 0700) ? -1 : open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
}
static unsigned entries(int dir, uint64_t *largest) {
    int fd = openat(dir, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    DIR *scan = fd >= 0 ? fdopendir(fd) : NULL;
    if (!scan) return UINT32_MAX;
    unsigned count = 0;
    struct dirent *entry;
    if (largest) *largest = 0;
    while ((entry = readdir(scan))) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        count++;
        struct stat status;
        if (fstatat(dir, entry->d_name, &status, AT_SYMLINK_NOFOLLOW)) { count = UINT32_MAX; break; }
        if (largest && status.st_size >= 0 && (uint64_t)status.st_size > *largest)
            *largest = (uint64_t)status.st_size;
    }
    closedir(scan);
    return count;
}
static bool put(YDRaftApplication *app, unsigned id) {
    YDRaftWrite write = {.id = {0}, .method = "PUT", .target = "/v1/collections/a/documents/b",
        .body = yaml, .size = sizeof(yaml) - 1};
    write.id[0] = (unsigned char)id;
    YDRaftProposal proposal = {0};
    int result = yd_raft_application_prepare(app, &write, &proposal, error, sizeof(error));
    YDRaftEntry entry = {.index = yd_raft_application_position(app).index + 1,
        .term = 1, .kind = YD_RAFT_COMMAND, .command = proposal.command, .size = proposal.size};
    bool valid = result == 1 && yd_raft_application_apply(app, &entry, error, sizeof(error));
    yd_raft_proposal_free(&proposal);
    return valid;
}
typedef struct {
    YDRaftApplication *app;
    YDRaftApplicationImage *image;
    YDRaftSnapshot *snapshot;
    YDRaftSnapshotStore *store;
    YDRaftSnapshotArchive *archive;
    unsigned char manifest[YD_RAFT_SNAPSHOT_MANIFEST];
    YDRaftSnapshotInfo info;
    int dir;
} Fixture;
static bool fixture(const char *root, Fixture *f) {
    char path[4096], id[65];
    int dir = directory(root, "source", path);
    if (dir < 0) return false;
    close(dir);
    f->app = yd_raft_application_open(path, cluster, 32768, error, sizeof(error));
    if (!f->app || !put(f->app, 1)) return false;
    dir = directory(root, "image", path);
    YDRaftApplicationCapture *capture = yd_raft_application_capture(f->app, 32768, error, sizeof(error));
    f->image = capture ? yd_raft_application_copy(capture, dir, 32768, NULL, NULL, error, sizeof(error)) : NULL;
    yd_raft_application_capture_close(capture);
    if (dir >= 0) close(dir);
    f->snapshot = yd_raft_snapshot_open(f->app, 3, error, sizeof(error));
    f->dir = directory(root, "archives", path);
    f->store = yd_raft_snapshot_store_open(path, cluster, 3, error, sizeof(error));
    f->archive = yd_raft_application_archive(f->image, f->dir, cluster, 3, NULL, NULL, id, error, sizeof(error));
    return f->snapshot && f->store && f->archive &&
        yd_raft_snapshot_seal(f->snapshot, NULL, NULL, error, sizeof(error)) &&
        yd_raft_snapshot_manifest(f->snapshot, f->manifest) &&
        yd_raft_snapshot_decode(f->manifest, sizeof(f->manifest), cluster, 3, &f->info, error, sizeof(error));
}
static void fixture_close(Fixture *f) {
    yd_raft_snapshot_close(f->snapshot);
    yd_raft_snapshot_archive_close(f->archive);
    yd_raft_snapshot_store_close(f->store);
    yd_raft_application_image_close(f->image);
    yd_raft_application_close(f->app);
    if (f->dir >= 0) close(f->dir);
}
static bool feed(YDRaftSnapshotStage *stage, YDRaftSnapshot *snapshot, uint64_t end) {
    unsigned char bytes[4093];
    for (uint64_t at = 0; at < end;) {
        size_t size = end - at < sizeof(bytes) ? (size_t)(end - at) : sizeof(bytes);
        if (!yd_raft_snapshot_read(snapshot, at, bytes, size, error, sizeof(error)) ||
            !yd_raft_snapshot_stage_feed(stage, at, bytes, size, error, sizeof(error))) return false;
        at += size;
    }
    return true;
}
static int stage_caps(Fixture *f) {
    uint64_t extent = f->info.view.end + YD_RAFT_SNAPSHOT_MANIFEST;
    YDDiskAllocation usage = {0};
    unsigned before = entries(f->dir, NULL), calls = creations;
    uint64_t limits[] = {extent - 1, f->info.view.end, 0, 255, (uint64_t)INT64_MAX + 1, UINT64_MAX - 1};
    for (size_t n = 0; n < sizeof(limits) / sizeof(*limits); n++) {
        REQUIRE(!yd_raft_snapshot_stage_new_limited(f->store, f->manifest, 256, limits[n], &usage, error, sizeof(error)));
        REQUIRE(usage.limit == limits[n] && !usage.high_water && creations == calls && entries(f->dir, NULL) == before);
    }
    YDRaftSnapshotStage *stage = yd_raft_snapshot_stage_new_limited(f->store, f->manifest, 256,
        extent, &usage, error, sizeof(error));
    REQUIRE(stage && usage.limit == extent && usage.high_water == extent);
    yd_raft_snapshot_store_close(f->store); f->store = NULL; /* Stage owns its fd. */
    REQUIRE(feed(stage, f->snapshot, f->info.view.end));
    REQUIRE(yd_raft_snapshot_stage_allocation(stage).high_water == extent);
    char id[65];
    REQUIRE(yd_raft_snapshot_stage_finish(stage, id, error, sizeof(error)));
    yd_raft_snapshot_stage_close(stage);
    uint64_t largest;
    REQUIRE(entries(f->dir, &largest) == before + 1 && largest <= extent);
    REQUIRE(!yd_raft_snapshot_stage_allocation(NULL).high_water);
    return 0;
}
static void end_manifest(unsigned char *manifest, uint64_t end) {
    yd_disk_set64(manifest + 64, end);
    uint32_t crc = yd_disk_crc(manifest, 252);
    for (unsigned n = 0; n < 4; n++) manifest[252 + n] = (unsigned char)(crc >> (8 * n));
}
static int malformed(Fixture *f) {
    YDDiskAllocation usage;
    unsigned calls = creations;
    unsigned char bytes[256];
    uint64_t ends[] = {0, 8192, f->info.view.end + 1, (uint64_t)INT64_MAX + 1, UINT64_MAX - 255, UINT64_MAX};
    for (size_t n = 0; n < sizeof(ends) / sizeof(*ends); n++) {
        memcpy(bytes, f->manifest, sizeof(bytes));
        end_manifest(bytes, ends[n]);
        REQUIRE(!yd_raft_snapshot_stage_new_limited(f->store, bytes, sizeof(bytes), UINT64_MAX,
            &usage, error, sizeof(error)) && !usage.high_water && creations == calls);
    }
    /* A huge admitted reservation must not preallocate a huge physical file. */
    memcpy(bytes, f->manifest, sizeof(bytes));
    uint64_t huge = (uint64_t)INT64_MAX - (YD_DISK_PAGE - 1);
    end_manifest(bytes, huge);
    create_failure = 1;
    REQUIRE(!yd_raft_snapshot_stage_new_limited(f->store, bytes, sizeof(bytes), INT64_MAX,
        &usage, error, sizeof(error)) && usage.high_water == huge + 256);
    create_failure = 0;
    calls = creations;
    REQUIRE(!yd_raft_snapshot_stage_new_limited(f->store, f->manifest, 255, UINT64_MAX,
        &usage, error, sizeof(error)) && !usage.high_water && creations == calls);
    YDRaftSnapshotStage *stage = yd_raft_snapshot_stage_new_limited(f->store, f->manifest, 256,
        UINT64_MAX, &usage, error, sizeof(error));
    REQUIRE(stage);
    unsigned char byte = 0;
    REQUIRE(!yd_raft_snapshot_stage_feed(stage, UINT64_MAX, &byte, 1, error, sizeof(error)));
    REQUIRE(yd_raft_snapshot_stage_allocation(stage).high_water == f->info.view.end + 256);
    char id[65];
    REQUIRE(!yd_raft_snapshot_stage_finish(stage, id, error, sizeof(error)) && !id[0]);
    yd_raft_snapshot_stage_close(stage);
    return 0;
}
static int failures(Fixture *f) {
    YDDiskAllocation usage;
    uint64_t extent = f->info.view.end + 256, largest;
    unsigned before = entries(f->dir, NULL);
    allocation_failure = true;
    REQUIRE(!yd_raft_snapshot_stage_new_limited(f->store, f->manifest, 256, extent,
        &usage, error, sizeof(error)) && usage.high_water == extent && !allocation_failure);
    create_failure = 1;
    REQUIRE(!yd_raft_snapshot_stage_new_limited(f->store, f->manifest, 256, extent,
        &usage, error, sizeof(error)) && usage.high_water == extent);
    create_failure = 0;
    REQUIRE(entries(f->dir, NULL) == before);
    pwrite_failure = 1;
    REQUIRE(!yd_raft_snapshot_stage_new_limited(f->store, f->manifest, 256, extent,
        &usage, error, sizeof(error)) && usage.high_water == extent);
    pwrite_failure = 0;
    REQUIRE(entries(f->dir, &largest) == before + 1 && largest <= extent);
    YDRaftSnapshotStage *stage = yd_raft_snapshot_stage_new_limited(f->store, f->manifest, 256,
        extent, &usage, error, sizeof(error));
    REQUIRE(stage);
    pwrite_failure = 1;
    REQUIRE(!feed(stage, f->snapshot, f->info.view.end));
    pwrite_failure = 0;
    REQUIRE(yd_raft_snapshot_stage_allocation(stage).high_water == extent);
    yd_raft_snapshot_stage_close(stage);
    REQUIRE(entries(f->dir, &largest) == before + 2 && largest <= extent);
    stage = yd_raft_snapshot_stage_new_limited(f->store, f->manifest, 256, extent,
        &usage, error, sizeof(error));
    REQUIRE(stage && feed(stage, f->snapshot, f->info.view.end));
    fail_sync = 2; /* New archive linked, temp unlinked, directory sync fails. */
    char id[65];
    REQUIRE(!yd_raft_snapshot_stage_finish(stage, id, error, sizeof(error)) && !id[0]);
    REQUIRE(yd_raft_snapshot_stage_allocation(stage).high_water == extent);
    yd_raft_snapshot_stage_close(stage);
    REQUIRE(entries(f->dir, &largest) == before + 3 && largest <= extent);
    stage = yd_raft_snapshot_stage_new_limited(f->store, f->manifest, 256, extent,
        &usage, error, sizeof(error));
    REQUIRE(stage && feed(stage, f->snapshot, f->info.view.end));
    REQUIRE(yd_raft_snapshot_stage_finish(stage, id, error, sizeof(error)));
    yd_raft_snapshot_stage_close(stage);
    REQUIRE(entries(f->dir, &largest) == before + 3 && largest <= extent);
    return 0;
}
static bool stop(void *context, uint64_t done, uint64_t total) {
    (void)context; (void)done; (void)total; return false;
}
static bool stop_after_seal(void *context, uint64_t done, uint64_t total) {
    bool *sealed = context;
    if (*sealed) return false;
    if (done == total) *sealed = true;
    return true;
}
static int archive_caps(Fixture *f) {
    unsigned char manifest[256]; YDRaftSnapshotInfo info;
    REQUIRE(yd_raft_snapshot_archive_manifest(f->archive, manifest) &&
        yd_raft_snapshot_decode(manifest, 256, cluster, 3, &info, error, sizeof(error)));
    uint64_t extent = info.view.end + 256;
    unsigned calls = creations, before = entries(f->dir, NULL);
    YDDiskAllocation usage;
    char id[65];
    REQUIRE(!yd_raft_application_archive_limited(f->image, f->dir, cluster, 3,
        extent - 1, &usage, NULL, NULL, id, error, sizeof(error)) && !id[0]);
    REQUIRE(!usage.high_water && creations == calls && entries(f->dir, NULL) == before);
    YDRaftSnapshotArchive *archive = yd_raft_application_archive_limited(f->image, f->dir,
        cluster, 3, extent, &usage, NULL, NULL, id, error, sizeof(error));
    REQUIRE(archive && usage.limit == extent && usage.high_water == extent);
    yd_raft_snapshot_archive_close(archive);
    bool sealed = false;
    REQUIRE(!yd_raft_application_archive_limited(f->image, f->dir, cluster, 3,
        extent, &usage, stop_after_seal, &sealed, id, error, sizeof(error)) && !id[0] && usage.high_water == extent);
    return 0;
}
static int capture_caps(Fixture *f) {
    YDDiskAllocation usage;
    YDRaftCaptureOrigin origin = {.voters = 3, .node = 1, .term = 1};
    memcpy(origin.cluster, cluster, 16);
    uint64_t extent = f->info.view.end + 256;
    REQUIRE(!yd_raft_capture_new_limited(f->snapshot, yd_raft_application_disk(f->app),
        f->dir, &origin, extent - 1, &usage, NULL, NULL, error, sizeof(error)) && !usage.high_water);
    allocation_failure = true;
    REQUIRE(!yd_raft_capture_new_limited(f->snapshot, yd_raft_application_disk(f->app),
        f->dir, &origin, extent, &usage, NULL, NULL, error, sizeof(error)) &&
        usage.high_water == extent && !allocation_failure);
    YDRaftCapture *capture = yd_raft_capture_new_limited(f->snapshot, yd_raft_application_disk(f->app),
        f->dir, &origin, extent, &usage, NULL, NULL, error, sizeof(error));
    REQUIRE(capture && usage.high_water == extent);
    yd_raft_capture_close(capture);
    return 0;
}
static int restore_caps(const char *root, Fixture *f) {
    unsigned char manifest[256]; YDRaftSnapshotInfo info;
    REQUIRE(yd_raft_snapshot_archive_manifest(f->archive, manifest) &&
        yd_raft_snapshot_decode(manifest, 256, cluster, 3, &info, error, sizeof(error)));
    char path[4096]; int dir = directory(root, "restore", path);
    REQUIRE(dir >= 0);
    unsigned calls = creations;
    YDDiskAllocation usage;
    uint64_t limits[] = {info.view.end - 1, 0, 8191, (uint64_t)INT64_MAX + 1, UINT64_MAX - 1};
    for (size_t n = 0; n < sizeof(limits) / sizeof(*limits); n++) {
        REQUIRE(!yd_raft_snapshot_restore_at_limited(f->archive, dir, cluster, 3, 32768,
            limits[n], &usage, NULL, NULL, error, sizeof(error)));
        REQUIRE(usage.limit == limits[n] && !usage.high_water && creations == calls && !entries(dir, NULL));
    }
    REQUIRE(!yd_raft_snapshot_restore_limited(f->archive, path, cluster, 3, 32768,
        info.view.end - 1, &usage, NULL, NULL, error, sizeof(error)) && !usage.high_water && !entries(dir, NULL));
    REQUIRE(yd_raft_snapshot_restore_limited(f->archive, path, cluster, 3, 32768,
        info.view.end, &usage, NULL, NULL, error, sizeof(error)) && usage.high_water == info.view.end);
    struct stat status;
    REQUIRE(!fstatat(dir, YD_DISK_FILE, &status, 0) && (uint64_t)status.st_size == info.view.end);
    YDRaftApplication *app = yd_raft_application_open(path, cluster, 32768, error, sizeof(error));
    REQUIRE(app);
    YDDisk *disk = yd_raft_application_disk(app);
    YDDiskView view = yd_disk_view(disk);
    YDDiskDocument document = {0};
    REQUIRE(yd_disk_document_get(disk, &view, "a", "b", &document, error, sizeof(error)) == 1);
    REQUIRE(document.length == sizeof(yaml) - 1 && !memcmp(document.body, yaml, sizeof(yaml) - 1));
    yd_disk_document_free(&document);
    REQUIRE(put(app, 2)); /* Publication drops worker cap; ordinary writes grow. */
    REQUIRE(!fstatat(dir, YD_DISK_FILE, &status, 0) && (uint64_t)status.st_size > info.view.end);
    REQUIRE(usage.high_water == info.view.end);
    yd_raft_application_close(app);
    close(dir);
    return 0;
}
static int restore_failures(const char *root, Fixture *f) {
    unsigned char manifest[256]; YDRaftSnapshotInfo info;
    REQUIRE(yd_raft_snapshot_archive_manifest(f->archive, manifest) &&
        yd_raft_snapshot_decode(manifest, 256, cluster, 3, &info, error, sizeof(error)));
    YDDiskAllocation usage;
    REQUIRE(!yd_raft_snapshot_restore_at_limited(f->archive, -1, cluster, 3, 32768,
        info.view.end, &usage, NULL, NULL, error, sizeof(error)) && usage.high_water == info.view.end);
    for (unsigned n = 0; n < 5; n++) {
        char name[40], path[4096]; snprintf(name, sizeof(name), "failed-%u", n);
        int dir = directory(root, name, path); REQUIRE(dir >= 0);
        create_failure = n == 0;
        write_failure = n == 1;
        fail_sync = n == 2 ? 1 : 0;
        allocation_failure = n == 4;
        REQUIRE(!yd_raft_snapshot_restore_at_limited(f->archive, dir, cluster, 3, 32768,
            info.view.end, &usage, n == 3 ? stop : NULL, NULL, error, sizeof(error)));
        create_failure = write_failure = fail_sync = 0;
        REQUIRE(usage.limit == info.view.end && usage.high_water == info.view.end);
        uint64_t largest;
        REQUIRE(entries(dir, &largest) == (n == 0 || n == 4 ? 0U : n == 2 ? 1U : 2U) && largest <= info.view.end);
        REQUIRE(!yd_raft_snapshot_restore_at_limited(f->archive, dir, cluster, 3, 32768,
            info.view.end - 1, &usage, NULL, NULL, error, sizeof(error)) && !usage.high_water);
        close(dir);
    }
    return 0;
}
typedef struct { YDRaftSnapshotArchive *archive; int directory; uint64_t end; bool success; } Reader;
static void *concurrent(void *context) {
    Reader *r = context;
    YDDiskAllocation usage; char failure[256];
    unsigned char bytes[4096];
    r->success = yd_raft_snapshot_archive_read(r->archive, 0, bytes, sizeof(bytes), failure, sizeof(failure)) &&
        yd_raft_snapshot_restore_at_limited(r->archive, r->directory, cluster, 3, 32768,
            r->end, &usage, NULL, NULL, failure, sizeof(failure)) && usage.high_water == r->end;
    return NULL;
}
static int lifetime(const char *root, Fixture *f) {
    unsigned char manifest[256]; YDRaftSnapshotInfo info;
    REQUIRE(yd_raft_snapshot_archive_manifest(f->archive, manifest) &&
        yd_raft_snapshot_decode(manifest, 256, cluster, 3, &info, error, sizeof(error)));
    yd_raft_snapshot_close(f->snapshot); f->snapshot = NULL;
    yd_raft_application_image_close(f->image); f->image = NULL;
    yd_raft_application_close(f->app); f->app = NULL;
    yd_raft_snapshot_store_close(f->store); f->store = NULL;
    close(f->dir); f->dir = -1;
    Reader readers[3]; pthread_t threads[3];
    for (unsigned n = 0; n < 3; n++) {
        char name[40], path[4096]; snprintf(name, sizeof(name), "parallel-%u", n);
        readers[n] = (Reader){f->archive, directory(root, name, path), info.view.end, false};
        REQUIRE(readers[n].directory >= 0 && !pthread_create(&threads[n], NULL, concurrent, &readers[n]));
    }
    for (unsigned n = 0; n < 3; n++) {
        REQUIRE(!pthread_join(threads[n], NULL) && readers[n].success);
        close(readers[n].directory);
    }
    return 0;
}
int main(int argc, char **argv) {
    if (argc != 3) return 2;
    Fixture f = {.dir = -1};
    REQUIRE(fixture(argv[1], &f));
    int result = 2;
    if (!strcmp(argv[2], "stage")) result = stage_caps(&f);
    if (!strcmp(argv[2], "malformed")) result = malformed(&f);
    if (!strcmp(argv[2], "failures")) result = failures(&f);
    if (!strcmp(argv[2], "archive")) result = archive_caps(&f);
    if (!strcmp(argv[2], "capture")) result = capture_caps(&f);
    if (!strcmp(argv[2], "restore")) result = restore_caps(argv[1], &f);
    if (!strcmp(argv[2], "restore-failures")) result = restore_failures(argv[1], &f);
    if (!strcmp(argv[2], "lifetime")) result = lifetime(argv[1], &f);
    fixture_close(&f);
    return result;
}
