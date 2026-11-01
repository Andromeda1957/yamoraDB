#define _GNU_SOURCE
#include "../src/consensus/application_retire.h"
#include "../src/consensus/application_admission.h"
#include "../src/consensus/archive_retention.h"
#include "../src/consensus/snapshot_restore.h"
#include "../src/consensus/recovery.h"
#include "../src/consensus/raft_internal.h"
#include "../src/disk_internal.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "line %d: %s (%s)\n", __LINE__, #x, error); abort(); } } while (0)
static char error[512];
static const unsigned char cluster[16] = {1, 2, 3, 4};
static unsigned char manifest[256];
static YDRaftSnapshot *snapshot;
static YDRaftSnapshotInfo info;
static int root, documents, archives;
static unsigned fault, nth, calls;
static bool remove_archive_exclusion;
static bool archive_reader_violation;
enum { SYNC = 1, UNLINK, RENAME };
int __real_fsync(int);
int __real_unlinkat(int, const char *, int);
int __real_renameat2(int, const char *, int, const char *, unsigned);
int __real_flock(int, int);
int __wrap_flock(int descriptor, int operation) {
    struct stat file;
    if (remove_archive_exclusion && operation == (LOCK_EX | LOCK_NB) &&
        !fstat(descriptor, &file) && S_ISREG(file.st_mode) &&
        (file.st_mode & 0777) == 0400) return 0;
    return __real_flock(descriptor, operation);
}
static bool inject(unsigned kind) {
    if (fault != kind || ++calls != nth) return false;
    errno = EIO; return true;
}
int __wrap_fsync(int fd) { return inject(SYNC) ? -1 : __real_fsync(fd); }
int __wrap_unlinkat(int fd, const char *name, int flags) {
    return inject(UNLINK) ? -1 : __real_unlinkat(fd, name, flags);
}
int __wrap_renameat2(int a, const char *b, int c, const char *d, unsigned flags) {
    return inject(RENAME) ? -1 : __real_renameat2(a, b, c, d, flags);
}
static int directory(int parent, const char *name) {
    CHECK(!mkdirat(parent, name, 0700));
    int fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    CHECK(fd >= 0); return fd;
}
static unsigned descriptors(void) {
    DIR *scan = opendir("/proc/self/fd"); CHECK(scan);
    unsigned n = 0; while (readdir(scan)) n++;
    CHECK(!closedir(scan)); return n;
}
static unsigned entries(int parent) {
    int fd = openat(parent, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    DIR *scan = fdopendir(fd); CHECK(scan);
    unsigned n = 0; struct dirent *entry;
    while ((entry = readdir(scan))) if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) n++;
    CHECK(!closedir(scan)); return n;
}
static uint64_t clock_us(void) {
    struct timespec t; CHECK(!clock_gettime(CLOCK_MONOTONIC, &t));
    return (uint64_t)t.tv_sec * 1000000 + (uint64_t)t.tv_nsec / 1000;
}
static int compare_time(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return x < y ? -1 : x > y;
}
static void identity(const unsigned char data[256], unsigned char out[32]) {
    size_t size = 0;
    CHECK(EVP_Q_digest(NULL, "SHA256", NULL, data, 256, out, &size) == 1 && size == 32);
}
static int populate(int directory_fd, uint64_t sequence, unsigned char id[32]) {
    int native = openat(directory_fd, YD_DISK_FILE, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    CHECK(native >= 0);
    unsigned char bytes[4096];
    for (uint64_t at = 0; at < info.view.end;) {
        size_t size = info.view.end - at < sizeof(bytes) ? (size_t)(info.view.end - at) : sizeof(bytes);
        CHECK(yd_raft_snapshot_read(snapshot, at, bytes, size, error, sizeof(error)));
        CHECK(pwrite(native, bytes, size, (off_t)at) == (ssize_t)size); at += size;
    }
    unsigned char data[256]; memcpy(data, manifest, sizeof(data));
    /* The fixture exercises file custody, not admission of a graph against a
     * fabricated newest policy. Native image bytes are actual native output. */
    yd_disk_set64(data + 32, sequence);
    yd_disk_set64(data + 56, sequence + 2);
    uint32_t crc = yd_disk_crc(data, 252);
    for (unsigned n = 0; n < 4; n++) data[252+n] = (unsigned char)(crc >> (8*n));
    int marker = openat(directory_fd, YD_RAFT_SNAPSHOT_CANDIDATE,
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    CHECK(marker >= 0 && write(marker, data, sizeof(data)) == (ssize_t)sizeof(data));
    CHECK(!fsync(marker) && !close(marker) && !fsync(native) && !fsync(directory_fd));
    identity(data, id); return native;
}
static YDRaftApplicationSlots *slots(void) {
    YDRaftApplicationSlots *s = yd_raft_application_slots_create(documents, cluster, 3, error, sizeof(error));
    CHECK(s); return s;
}
static void bind(YDRaftApplicationSlots *s, uint64_t sequence, unsigned *slot, int *fd,
    unsigned char id[32]) {
    CHECK(yd_raft_application_slots_acquire(s, slot, fd, error, sizeof(error)) == 1);
    int native = populate(*fd, sequence, id);
    CHECK(yd_raft_application_slots_bind(s, *slot, native, id, error, sizeof(error)));
    CHECK(!close(native));
}
static YDRaftRetiredFiles *ticket(YDRaftApplicationSlots *s, int fd, const unsigned char id[32]) {
    int native = openat(fd, YD_DISK_FILE, O_RDWR | O_NOFOLLOW | O_CLOEXEC); CHECK(native >= 0);
    YDRaftRetiredFiles *f = yd_raft_retired_files_prepare_slots(s, native, id, error, sizeof(error));
    CHECK(f && yd_raft_retired_files_seal(f, error, sizeof(error)) && !close(native));
    return f;
}
static void account(YDRaftApplicationSlots *s, int source_directory) {
    int dirs[3], custody;
    CHECK(yd_raft_application_slots_account(s, documents, dirs, &custody));
    int source = openat(source_directory, YD_DISK_FILE, O_RDONLY | O_CLOEXEC); CHECK(source >= 0);
    YDRaftApplicationSpace space;
    CHECK(yd_raft_application_space_with_slots(documents, archives, -1, -1, dirs, 3,
        custody, source, NULL, cluster, 3, &space, error, sizeof(error)));
    CHECK(space.complete && space.files == 6 && space.documents.retained_bytes >= 3 * info.view.end);
    CHECK(yd_raft_application_slots_account(s, documents, dirs, &custody)); CHECK(!close(source));
}
static void renew(void) {
    YDRaftApplicationSlots *s = slots();
    int dirs[3]; unsigned char ids[3][32]; unsigned slot;
    for (unsigned n = 0; n < 3; n++) { bind(s, n + 1, &slot, &dirs[n], ids[n]); CHECK(slot == n); }
    uint64_t latencies[96], start = clock_us(); unsigned live_descriptors = 0;
    for (unsigned n = 0; n < 96; n++) {
        unsigned at = n % 3;
        YDRaftRetiredFiles *f = ticket(s, dirs[at], ids[at]);
        uint64_t before = clock_us();
        CHECK(yd_raft_retired_files_retire(f, error, sizeof(error)) == 1);
        latencies[n] = clock_us() - before;
        yd_raft_retired_files_close(f);
        int reused;
        bind(s, n + 4, &slot, &reused, ids[at]); CHECK(slot == at && reused == dirs[at]);
        account(s, dirs[at]);
        CHECK(entries(documents) == 2);
        unsigned count = descriptors();
        if (!n) live_descriptors = count;
        CHECK(count == live_descriptors && count < 40);
    }
    int parent = openat(documents, YD_RAFT_GENERATION_DIRECTORY, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    CHECK(parent >= 0 && entries(parent) == 3 && !close(parent));
    struct rusage usage; CHECK(!getrusage(RUSAGE_SELF, &usage));
    qsort(latencies, 96, sizeof(*latencies), compare_time);
    printf("renew cycles=96 elapsed_us=%llu p50_us=%llu p95_us=%llu p99_us=%llu rss_kib=%ld fds=%u native_bytes=%llu\n",
        (unsigned long long)(clock_us() - start), (unsigned long long)latencies[47],
        (unsigned long long)latencies[90], (unsigned long long)latencies[94], usage.ru_maxrss,
        live_descriptors, (unsigned long long)(3 * info.view.end));
    yd_raft_application_slots_close(s);
}
typedef struct { YDRaftRetiredFiles *ticket; atomic_bool go; } Closing;
static void *close_ticket(void *context) {
    Closing *closing = context;
    while (!atomic_load(&closing->go)) sched_yield();
    yd_raft_retired_files_close(closing->ticket);
    return NULL;
}
static void handoff(void) {
    YDRaftApplicationSlots *s = slots();
    for (unsigned n = 0; n < 64; n++) {
        unsigned slot; int directory_fd; unsigned char id[32];
        bind(s, 2 * n + 1, &slot, &directory_fd, id);
        YDRaftRetiredFiles *old = ticket(s, directory_fd, id);
        CHECK(yd_raft_retired_files_retire(old, error, sizeof(error)) == 1);
        bind(s, 2 * n + 2, &slot, &directory_fd, id);
        int native = openat(directory_fd, YD_DISK_FILE, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
        CHECK(native >= 0);
        Closing closing = {.ticket = old}; atomic_init(&closing.go, false);
        pthread_t worker; CHECK(!pthread_create(&worker, NULL, close_ticket, &closing));
        atomic_store(&closing.go, true);
        YDRaftRetiredFiles *next = NULL;
        for (unsigned attempt = 0; !next && attempt < 100000; attempt++) {
            next = yd_raft_retired_files_prepare_slots(s, native, id, error, sizeof(error));
            if (!next) sched_yield();
        }
        CHECK(next && !pthread_join(worker, NULL) && !close(native));
        CHECK(yd_raft_retired_files_seal(next, error, sizeof(error)) &&
            yd_raft_retired_files_retire(next, error, sizeof(error)) == 1);
        yd_raft_retired_files_close(next);
    }
    yd_raft_application_slots_close(s);
}
static void capacity(void) {
    YDRaftApplicationSlots *s = slots(); int fd; unsigned slot; unsigned char id[32];
    for (unsigned n = 0; n < 3; n++) bind(s, n + 1, &slot, &fd, id);
    CHECK(yd_raft_application_slots_acquire(s, &slot, &fd, error, sizeof(error)) == 0);
    CHECK(slot == 3 && fd == -1);
    yd_raft_application_slots_close(s);
}
static void restart(void) {
    YDRaftApplicationSlots *s = slots(); yd_raft_application_slots_close(s);
    CHECK(!yd_raft_application_slots_create(documents, cluster, 3, error, sizeof(error)));
    CHECK(entries(documents) == 1);
}
static void preserving(void) {
    YDRaftApplicationSlots *s = slots(); int fd; unsigned slot; unsigned char id[32];
    bind(s, 1, &slot, &fd, id);
    int observed = openat(fd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int native = openat(fd, YD_DISK_FILE, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    CHECK(observed >= 0 && native >= 0);
    yd_raft_application_slots_close(s);
    YDRaftApplicationSpace space;
    CHECK(yd_raft_application_documents_preserving(documents, native, cluster, 3,
        &space, error, sizeof(error)) && space.complete && space.files == 2);
    CHECK(!yd_raft_application_slots_create(documents, cluster, 3, error, sizeof(error)));
    int owner = openat(observed, "owner", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    CHECK(owner >= 0 && write(owner, "preserve", 8) == 8 && !close(owner));
    CHECK(!yd_raft_application_documents_preserving(documents, native, cluster, 3,
        &space, error, sizeof(error)) && !space.complete && entries(observed) == 3);
    CHECK(!unlinkat(observed, "owner", 0));
    CHECK(!linkat(observed, YD_DISK_FILE, documents, "alias", 0));
    CHECK(!yd_raft_application_documents_preserving(documents, native, cluster, 3,
        &space, error, sizeof(error)) && !space.complete);
    CHECK(!unlinkat(documents, "alias", 0));
    CHECK(!renameat(observed, YD_RAFT_SNAPSHOT_CANDIDATE, root, "saved-manifest"));
    CHECK(!yd_raft_application_documents_preserving(documents, native, cluster, 3,
        &space, error, sizeof(error)) && !space.complete && entries(observed) == 1);
    CHECK(!renameat(root, "saved-manifest", observed, YD_RAFT_SNAPSHOT_CANDIDATE));
    CHECK(yd_raft_application_documents_preserving(documents, native, cluster, 3,
        &space, error, sizeof(error)) && space.complete && space.files == 2);
    CHECK(!close(native) && !close(observed));
}
static void pins(void) {
    YDRaftApplicationSlots *s = slots(); int fd; unsigned slot; unsigned char id[32];
    bind(s, 1, &slot, &fd, id);
    int pin = openat(fd, YD_DISK_FILE, O_RDWR | O_CLOEXEC); CHECK(pin >= 0 && !flock(pin, LOCK_EX | LOCK_NB));
    YDRaftRetiredFiles *f = ticket(s, fd, id);
    CHECK(yd_raft_retired_files_retire(f, error, sizeof(error)) == 0 && entries(fd) == 2);
    CHECK(!close(pin));
    CHECK(yd_raft_retired_files_retire(f, error, sizeof(error)) == 1 && entries(fd) == 0);
    yd_raft_retired_files_close(f);
    bind(s, 2, &slot, &fd, id);
    pin = openat(fd, YD_DISK_FILE, O_RDWR | O_CLOEXEC);
    struct flock lock = {.l_type = F_RDLCK, .l_whence = SEEK_SET, .l_len = 1};
    CHECK(pin >= 0 && !fcntl(pin, F_OFD_SETLK, &lock));
    f = ticket(s, fd, id);
    CHECK(yd_raft_retired_files_retire(f, error, sizeof(error)) == 0 && entries(fd) == 2);
    CHECK(!close(pin) && yd_raft_retired_files_retire(f, error, sizeof(error)) == 1);
    yd_raft_retired_files_close(f); yd_raft_application_slots_close(s);
}
static void unknown(void) {
    YDRaftApplicationSlots *s = slots(); int fd; unsigned slot; unsigned char id[32];
    bind(s, 1, &slot, &fd, id);
    CHECK(!linkat(fd, YD_DISK_FILE, documents, "alias", 0));
    int native = openat(fd, YD_DISK_FILE, O_RDWR | O_CLOEXEC); CHECK(native >= 0);
    CHECK(!yd_raft_retired_files_prepare_slots(s, native, id, error, sizeof(error)));
    CHECK(!unlinkat(documents, "alias", 0) && !close(native));
    int keep = openat(fd, "owner", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    CHECK(keep >= 0 && write(keep, "preserve", 8) == 8 && !close(keep));
    int dirs[3], custody;
    CHECK(!yd_raft_application_slots_account(s, documents, dirs, &custody));
    native = openat(fd, YD_DISK_FILE, O_RDWR | O_CLOEXEC); CHECK(native >= 0);
    CHECK(!yd_raft_retired_files_prepare_slots(s, native, id, error, sizeof(error)));
    CHECK(entries(fd) == 3 && !close(native));
    yd_raft_application_slots_close(s);
    int original_documents = documents;
    documents = directory(root, "substitution");
    s = slots(); bind(s, 1, &slot, &fd, id);
    YDRaftRetiredFiles *f = ticket(s, fd, id);
    int parent = openat(documents, YD_RAFT_GENERATION_DIRECTORY, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    CHECK(parent >= 0 && !renameat(parent, ".yamora-slot-0", parent, "saved-owned-slot"));
    int replacement = directory(parent, ".yamora-slot-0");
    keep = openat(replacement, "owner", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    CHECK(keep >= 0 && write(keep, "preserve", 8) == 8 && !close(keep));
    CHECK(yd_raft_retired_files_retire(f, error, sizeof(error)) == -1);
    CHECK(entries(fd) == 2 && entries(replacement) == 1);
    yd_raft_retired_files_close(f); yd_raft_application_slots_close(s);
    CHECK(!close(parent) && !close(replacement) && !close(documents));
    documents = original_documents;
}
static void slot_faults(void) {
    YDRaftApplicationSlots *s = slots();
    for (unsigned kind = SYNC; kind <= RENAME; kind++) for (unsigned step = 1; step <= (kind == SYNC ? 7u : 2u); step++) {
        int fd; unsigned slot; unsigned char id[32]; bind(s, kind * 10 + step, &slot, &fd, id);
        YDRaftRetiredFiles *f = ticket(s, fd, id);
        fault = kind; nth = step; calls = 0;
        CHECK(yd_raft_retired_files_retire(f, error, sizeof(error)) == -1 && calls >= step);
        fault = 0;
        CHECK(yd_raft_retired_files_retire(f, error, sizeof(error)) == 1 && entries(fd) == 0);
        yd_raft_retired_files_close(f);
    }
    yd_raft_application_slots_close(s);
}
static YDRaftSnapshotStore *store;
static YDRaftSnapshotBase base;
static char archive_name[80];
static YDRaftSnapshotReference *publish(void) {
    YDRaftSnapshotStage *stage = yd_raft_snapshot_stage_new(store, manifest, sizeof(manifest), error, sizeof(error)); CHECK(stage);
    unsigned char bytes[4096];
    for (uint64_t at = 0; at < info.view.end;) {
        size_t size = info.view.end - at < sizeof(bytes) ? (size_t)(info.view.end - at) : sizeof(bytes);
        CHECK(yd_raft_snapshot_read(snapshot, at, bytes, size, error, sizeof(error)));
        CHECK(yd_raft_snapshot_stage_feed(stage, at, bytes, size, error, sizeof(error))); at += size;
    }
    char id[65]; YDRaftSnapshotReference *reference = NULL;
    CHECK(yd_raft_snapshot_stage_finish_retaining(stage, id, NULL, NULL, &reference, error, sizeof(error)) == YD_RAFT_ARCHIVE_OK);
    yd_raft_snapshot_stage_close(stage);
    CHECK(snprintf(archive_name, sizeof(archive_name), "%s.snapshot", id) == 73);
    return reference;
}
static YDRaftArchiveRetirement *archive_ticket(YDRaftSnapshotReference *reference) {
    struct stat d, file;
    CHECK(yd_raft_snapshot_reference_identity(reference, &d, &file));
    YDRaftArchiveRetirement *r = yd_raft_archive_retirement_prepare(archives, &base, &file, cluster, 3, error, sizeof(error));
    CHECK(r); return r;
}
static bool proof(void *context, const YDRaftSnapshotBase *expected) {
    CHECK(!memcmp(expected, &base, sizeof(base))); return *(bool *)context;
}
static void archive_pins(void) {
    bool valid = true;
    YDRaftSnapshotReference *reference = publish(), *clone = NULL;
    CHECK(yd_raft_snapshot_reference_clone(reference, &clone, error, sizeof(error)) == YD_RAFT_ARCHIVE_OK);
    YDRaftArchiveRetirement *r = archive_ticket(reference);
    int protected = yd_raft_archive_retirement_run(r, proof, &valid, error, sizeof(error));
    if (remove_archive_exclusion && protected == 1) {
        CHECK(entries(archives) == 0);
        archive_reader_violation = true;
        puts("ARCHIVE_READER_EXCLUSION_VIOLATION=deleted_with_two_live_references");
        yd_raft_snapshot_reference_close(reference);
        yd_raft_snapshot_reference_close(clone);
        yd_raft_archive_retirement_close(r);
        return;
    }
    CHECK(protected == 0);
    yd_raft_snapshot_reference_close(reference);
    CHECK(yd_raft_archive_retirement_run(r, proof, &valid, error, sizeof(error)) == 0);
    yd_raft_snapshot_reference_close(clone);
    int ready[2], release[2]; CHECK(!pipe(ready) && !pipe(release));
    pid_t child = fork(); CHECK(child >= 0);
    if (!child) {
        close(ready[0]); close(release[1]);
        int fd = openat(archives, archive_name, O_RDONLY | O_CLOEXEC);
        CHECK(fd >= 0 && !flock(fd, LOCK_SH | LOCK_NB) && write(ready[1], "r", 1) == 1);
        char byte; CHECK(read(release[0], &byte, 1) == 1 && !close(fd)); _exit(0);
    }
    CHECK(!close(ready[1]) && !close(release[0])); char byte;
    CHECK(read(ready[0], &byte, 1) == 1);
    CHECK(yd_raft_archive_retirement_run(r, proof, &valid, error, sizeof(error)) == 0);
    CHECK(write(release[1], "r", 1) == 1 && !close(release[1]) && !close(ready[0]));
    int status; CHECK(waitpid(child, &status, 0) == child && status == 0);
    CHECK(yd_raft_archive_retirement_run(r, proof, &valid, error, sizeof(error)) == 1 && entries(archives) == 0);
    yd_raft_archive_retirement_close(r);
}
static atomic_bool reader_ready, reader_release;
static void *archive_reader(void *unused) {
    (void)unused;
    YDRaftSnapshotReference *reference = NULL;
    char message[512];
    CHECK(yd_raft_snapshot_reference_open(store, &base, &reference, message, sizeof(message)) == YD_RAFT_ARCHIVE_OK);
    atomic_store(&reader_ready, true);
    do {
        YDRaftSnapshotArchive *archive = NULL;
        CHECK(yd_raft_snapshot_archive_open_reference(reference, NULL, NULL, &archive, message, sizeof(message)) == YD_RAFT_ARCHIVE_OK);
        unsigned char bytes[4096]; CHECK(yd_raft_snapshot_archive_read(archive, 0, bytes, sizeof(bytes), message, sizeof(message)));
        yd_raft_snapshot_archive_close(archive);
    } while (!atomic_load(&reader_release));
    yd_raft_snapshot_reference_close(reference); return NULL;
}
static void archive_thread(void) {
    bool valid = true; YDRaftSnapshotReference *reference = publish();
    YDRaftArchiveRetirement *r = archive_ticket(reference); yd_raft_snapshot_reference_close(reference);
    atomic_init(&reader_ready, false); atomic_init(&reader_release, false);
    pthread_t thread; CHECK(!pthread_create(&thread, NULL, archive_reader, NULL));
    while (!atomic_load(&reader_ready)) sched_yield();
    for (unsigned n = 0; n < 64; n++)
        CHECK(yd_raft_archive_retirement_run(r, proof, &valid, error, sizeof(error)) == 0);
    atomic_store(&reader_release, true); CHECK(!pthread_join(thread, NULL));
    CHECK(yd_raft_archive_retirement_run(r, proof, &valid, error, sizeof(error)) == 1);
    yd_raft_archive_retirement_close(r);
}
static void archive_proof(void) {
    bool valid = false;
    YDRaftSnapshotReference *reference = publish(); YDRaftArchiveRetirement *r = archive_ticket(reference);
    yd_raft_snapshot_reference_close(reference);
    CHECK(yd_raft_archive_retirement_run(r, proof, &valid, error, sizeof(error)) == 0 && entries(archives) == 1);
    CHECK(yd_raft_snapshot_reference_open(store, &base, &reference, error, sizeof(error)) == YD_RAFT_ARCHIVE_OK);
    yd_raft_snapshot_reference_close(reference);
    int guard = -1; CHECK(yd_raft_snapshot_namespace_guard(store, false, &guard, error, sizeof(error)) == YD_RAFT_ARCHIVE_OK);
    valid = true;
    CHECK(yd_raft_archive_retirement_run(r, proof, &valid, error, sizeof(error)) == 0 && !close(guard));
    int keep = openat(archives, "owner.tmp", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    CHECK(keep >= 0 && write(keep, "keep", 4) == 4 && !close(keep));
    CHECK(yd_raft_archive_retirement_run(r, proof, &valid, error, sizeof(error)) == 1 && entries(archives) == 1);
    yd_raft_archive_retirement_close(r);
}
static void archive_provenance(void) {
    YDRaftSnapshotReference *reference = publish(), *clone = NULL, *reopened = NULL;
    struct stat d, file;
    CHECK(yd_raft_snapshot_reference_publication(reference, &d, &file));
    CHECK(yd_raft_snapshot_reference_clone(reference, &clone, error, sizeof(error)) == YD_RAFT_ARCHIVE_OK);
    yd_raft_snapshot_reference_close(reference);
    CHECK(yd_raft_snapshot_reference_publication(clone, &d, &file));
    YDRaftSnapshotArchive *archive = NULL;
    CHECK(yd_raft_snapshot_archive_open_reference(clone, NULL, NULL, &archive, error, sizeof(error)) == YD_RAFT_ARCHIVE_OK);
    CHECK(yd_raft_snapshot_archive_publication(archive, &d, &file));
    yd_raft_snapshot_archive_close(archive);
    CHECK(yd_raft_snapshot_reference_open(store, &base, &reopened, error, sizeof(error)) == YD_RAFT_ARCHIVE_OK);
    CHECK(!yd_raft_snapshot_reference_publication(reopened, &d, &file) && !d.st_ino && !file.st_ino);
    YDRaftSnapshotReference *duplicate = publish();
    CHECK(!yd_raft_snapshot_reference_publication(duplicate, &d, &file) && !d.st_ino && !file.st_ino);
    yd_raft_snapshot_reference_close(duplicate); yd_raft_snapshot_reference_close(reopened);
    yd_raft_snapshot_reference_close(clone);
}
static void archive_identity(void) {
    bool valid = true; YDRaftSnapshotReference *reference = publish();
    YDRaftArchiveRetirement *r = archive_ticket(reference); yd_raft_snapshot_reference_close(reference);
    CHECK(!linkat(archives, archive_name, archives, "alias", 0));
    CHECK(yd_raft_archive_retirement_run(r, proof, &valid, error, sizeof(error)) == -1);
    CHECK(entries(archives) == 2 && !unlinkat(archives, "alias", 0));
    /* ctime changed: a fresh path stat cannot silently re-enroll this ticket. */
    CHECK(yd_raft_archive_retirement_run(r, proof, &valid, error, sizeof(error)) == -1);
    yd_raft_archive_retirement_close(r);
    CHECK(!renameat(archives, archive_name, archives, "saved"));
    int keep = openat(archives, archive_name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0400);
    CHECK(keep >= 0 && write(keep, "foreign", 7) == 7 && !close(keep));
    struct stat old; int fd = openat(archives, "saved", O_RDONLY | O_CLOEXEC);
    CHECK(fd >= 0 && !fstat(fd, &old) && !close(fd));
    CHECK(!yd_raft_archive_retirement_prepare(archives, &base, &old, cluster, 3, error, sizeof(error)));
    CHECK(entries(archives) == 2);
}
static void archive_faults(void) {
    bool valid = true;
    for (unsigned kind = SYNC; kind <= UNLINK; kind++) {
        YDRaftSnapshotReference *reference = publish(); YDRaftArchiveRetirement *r = archive_ticket(reference);
        yd_raft_snapshot_reference_close(reference);
        fault = kind; nth = 1; calls = 0;
        CHECK(yd_raft_archive_retirement_run(r, proof, &valid, error, sizeof(error)) == -1 && calls == 1);
        fault = 0;
        CHECK(yd_raft_archive_retirement_run(r, proof, &valid, error, sizeof(error)) == 1 && entries(archives) == 0);
        yd_raft_archive_retirement_close(r);
    }
}
static void metadata_layout(void) {
    YDRaftMeta meta = {.node = 1, .voters = 3, .term = 2, .last = 3, .committed = 3,
        .snapshot = {.index = 1, .term = 1, .archive = {1}}, .application = {2},
        .membership_required = true, .application_layout = 1}, decoded;
    memcpy(meta.cluster, cluster, 16);
    unsigned char bytes[144];
    CHECK(yd_raft_encode_meta(&meta, bytes) == 144 && !memcmp(bytes, "YDRMETA5", 8));
    CHECK(bytes[26] == 1 && bytes[27] == 1);
    CHECK(yd_raft_decode_meta(bytes, 144, &meta, &decoded) && decoded.application_layout == 1 &&
        decoded.membership_required && !memcmp(decoded.application, meta.application, 32));
    meta.membership_required = false;
    CHECK(yd_raft_encode_meta(&meta, bytes) == 144 && bytes[27] == 0 &&
        yd_raft_decode_meta(bytes, 144, &meta, &decoded) && !decoded.membership_required);
    bytes[27] = 2; CHECK(!yd_raft_decode_meta(bytes, 144, &meta, &decoded));
    bytes[27] = 0; bytes[26] = 0; CHECK(!yd_raft_decode_meta(bytes, 144, &meta, &decoded));
    meta.application_layout = 0; meta.membership_required = true;
    CHECK(yd_raft_encode_meta(&meta, bytes) == 144 && !memcmp(bytes, "YDRMETA4", 8) &&
        yd_raft_decode_meta(bytes, 144, &meta, &decoded) && decoded.membership_required && !decoded.application_layout);
    bytes[26] = 1; CHECK(!yd_raft_decode_meta(bytes, 144, &meta, &decoded));
    meta.application_layout = 2; CHECK(!yd_raft_encode_meta(&meta, bytes));
}
int main(int argc, char **argv) {
    CHECK(argc == 3); root = open(argv[1], O_RDONLY | O_DIRECTORY | O_CLOEXEC); CHECK(root >= 0);
    documents = directory(root, "documents"); archives = directory(root, "archives");
    char path[4096]; CHECK(snprintf(path, sizeof(path), "%s/source", argv[1]) > 0);
    CHECK(!mkdir(path, 0700));
    YDRaftApplication *app = yd_raft_application_open(path, cluster, 32768, error, sizeof(error)); CHECK(app);
    static const unsigned char source[] = "# exact source\r\ncount: 7 # retained\r\n";
    YDRaftWrite write = {.id = {1}, .method = "PUT", .target = "/v1/collections/a/documents/b", .body = source, .size = sizeof(source) - 1};
    YDRaftProposal proposal = {0}; CHECK(yd_raft_application_prepare(app, &write, &proposal, error, sizeof(error)) == 1);
    YDRaftEntry entry = {.index = 1, .term = 1, .kind = YD_RAFT_COMMAND, .command = proposal.command, .size = proposal.size};
    CHECK(yd_raft_application_apply(app, &entry, error, sizeof(error))); yd_raft_proposal_free(&proposal);
    snapshot = yd_raft_snapshot_open(app, 3, error, sizeof(error));
    CHECK(snapshot && yd_raft_snapshot_seal(snapshot, NULL, NULL, error, sizeof(error)) && yd_raft_snapshot_manifest(snapshot, manifest));
    CHECK(yd_raft_snapshot_decode(manifest, sizeof(manifest), cluster, 3, &info, error, sizeof(error)));
    yd_raft_application_close(app);
    store = yd_raft_snapshot_store_open_at(archives, cluster, 3, error, sizeof(error)); CHECK(store);
    base = (YDRaftSnapshotBase){.index = 1, .term = 1}; identity(manifest, base.archive);
    unsigned before = descriptors();
    if (!strcmp(argv[2], "renew")) renew();
    else if (!strcmp(argv[2], "handoff")) handoff();
    else if (!strcmp(argv[2], "capacity")) capacity();
    else if (!strcmp(argv[2], "restart")) restart();
    else if (!strcmp(argv[2], "preserving")) preserving();
    else if (!strcmp(argv[2], "pins")) pins();
    else if (!strcmp(argv[2], "unknown")) unknown();
    else if (!strcmp(argv[2], "slot-faults")) slot_faults();
    else if (!strcmp(argv[2], "archive-pins")) archive_pins();
    else if (!strcmp(argv[2], "archive-lock-mutant")) { remove_archive_exclusion = true; archive_pins(); }
    else if (!strcmp(argv[2], "archive-thread")) archive_thread();
    else if (!strcmp(argv[2], "archive-proof")) archive_proof();
    else if (!strcmp(argv[2], "archive-provenance")) archive_provenance();
    else if (!strcmp(argv[2], "archive-identity")) archive_identity();
    else if (!strcmp(argv[2], "archive-faults")) archive_faults();
    else if (!strcmp(argv[2], "metadata")) metadata_layout();
    else CHECK(false);
    CHECK(descriptors() == before);
    yd_raft_snapshot_store_close(store); yd_raft_snapshot_close(snapshot);
    CHECK(!close(documents) && !close(archives) && !close(root));
    return archive_reader_violation ? 2 : 0;
}
