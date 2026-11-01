#define _POSIX_C_SOURCE 200809L
#include "../src/consensus/application_admission.h"
#include "../src/consensus/recovery.h"
#include "../src/consensus/snapshot_restore.h"
#include "../src/disk_internal.h"
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
static unsigned char cluster[16] = {1, 2, 3, 4};
static char error[512];
static uint64_t position = 1;
static bool change_blocks;
static dev_t watched_device;
static ino_t watched_inode;
static unsigned stat_calls;
int __real_fstat(int, struct stat *);
int __wrap_fstat(int fd, struct stat *status) {
    int result = __real_fstat(fd, status);
    if (!result && change_blocks && status->st_dev == watched_device && status->st_ino == watched_inode && ++stat_calls == 3)
        status->st_blocks += 8;
    return result;
}
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "line%u: %s: %s\n", __LINE__, #x, error); return 2; } } while (0)
static int dir(int parent, const char *name) {
    return mkdirat(parent, name, 0700) ? -1 : openat(parent, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
}
static int file(int parent, const char *name, uint64_t size) {
    int fd = openat(parent, name, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd >= 0 && ftruncate(fd, (off_t)size)) { close(fd); return -1; }
    return fd;
}
static bool manifest(int fd, uint64_t end, char id[65]) {
    unsigned char data[256] = {0}, digest[32];
    memcpy(data, "YDRSNAP1", 8); memcpy(data + 8, cluster, 16);
    data[24] = 3; data[25] = 6;
    yd_disk_set64(data + 32, position); yd_disk_set64(data + 40, 1);
    yd_disk_set64(data + 56, position + 2); yd_disk_set64(data + 64, end);
    yd_disk_set64(data + 72, 8192); data[104] = data[136] = 1;
    uint32_t sum = yd_disk_crc(data, 252);
    for (unsigned n = 0; n < 4; n++) data[252+n] = (unsigned char)(sum >> (8*n));
    size_t size = 0;
    if (pwrite(fd, data, sizeof(data), 0) != sizeof(data) ||
        EVP_Q_digest(NULL, "SHA256", NULL, data, sizeof(data), digest, &size) != 1 || size != 32) return false;
    static const char hex[] = "0123456789abcdef";
    for (unsigned n = 0; n < 32; n++) { id[2*n] = hex[digest[n] >> 4]; id[2*n+1] = hex[digest[n] & 15]; }
    id[64] = 0;
    return true;
}
static YDRaftApplicationLimits limits(void) {
    return (YDRaftApplicationLimits){.image_bytes = 65536, .archive_bytes = 65536 + 256,
        .restore_bytes = 65536, .maximum_work_bytes = 1024*1024,
        .maximum_retained_bytes = 16*1024*1024, .minimum_free_bytes = 4096, .minimum_saved_bytes = 1};
}
static YDRaftApplicationSpace observation(void) {
    return (YDRaftApplicationSpace){.documents = {1, 16384, 1024*1024, 4096},
        .archives = {1, 32768, 1024*1024, 4096}, .complete = true};
}
static int arithmetic(void) {
    YDRaftApplicationSpace s = observation(); YDRaftApplicationLimits l = limits();
    YDRaftApplicationReservation r = yd_raft_application_reserve(s, l);
    CHECK(r.result == YD_RAFT_APPLICATION_ADMIT && r.reserved_bytes == 208896 &&
        r.retained_bytes == 49152 && r.peak_bytes == 258048);
    l.maximum_work_bytes = r.reserved_bytes - 1;
    CHECK(yd_raft_application_reserve(s, l).result == YD_RAFT_APPLICATION_ADMIT_WORK);
    l = limits(); l.maximum_retained_bytes = r.peak_bytes - 1;
    CHECK(yd_raft_application_reserve(s, l).result == YD_RAFT_APPLICATION_ADMIT_RETAINED);
    l = limits(); s.documents.available_bytes = s.archives.available_bytes = 150000;
    CHECK(yd_raft_application_reserve(s, l).result == YD_RAFT_APPLICATION_ADMIT_FREE);
    s.documents.device = 2;
    CHECK(yd_raft_application_reserve(s, l).result == YD_RAFT_APPLICATION_ADMIT);
    s.archives.available_bytes = 139264 + l.minimum_free_bytes - 1;
    CHECK(yd_raft_application_reserve(s, l).result == YD_RAFT_APPLICATION_ADMIT_FREE);
    s.archives.available_bytes++;
    CHECK(yd_raft_application_reserve(s, l).result == YD_RAFT_APPLICATION_ADMIT);
    return 0;
}
static int overflow(void) {
    YDRaftApplicationSpace s = observation(); YDRaftApplicationLimits l = limits();
    uint64_t invalid[] = {0, 8191, (uint64_t)INT64_MAX + 1, UINT64_MAX};
    for (size_t n = 0; n < sizeof(invalid)/sizeof(*invalid); n++) {
        l.image_bytes = invalid[n];
        CHECK(yd_raft_application_reserve(s, l).result == YD_RAFT_APPLICATION_ADMIT_INVALID);
    }
    l = limits(); s.archives.retained_bytes = UINT64_MAX;
    CHECK(yd_raft_application_reserve(s, l).result == YD_RAFT_APPLICATION_ADMIT_INVALID);
    s = observation(); s.documents.allocation_unit = UINT64_MAX;
    CHECK(yd_raft_application_reserve(s, l).result == YD_RAFT_APPLICATION_ADMIT_INVALID);
    s = observation(); s.complete = false;
    CHECK(yd_raft_application_reserve(s, l).result == YD_RAFT_APPLICATION_ADMIT_UNKNOWN);
    s = observation(); l.minimum_free_bytes = UINT64_MAX;
    CHECK(yd_raft_application_reserve(s, l).result == YD_RAFT_APPLICATION_ADMIT_FREE);
    return 0;
}
static int inventory(int root) {
    int d = dir(root, "documents"), a = dir(root, "archives"); CHECK(d >= 0 && a >= 0);
    int source = file(d, YD_DISK_FILE, 131072); CHECK(source >= 0);
    int snap = file(a, "temporary", 16384 + 256); char id[65], name[80];
    CHECK(snap >= 0 && manifest(snap, 16384, id) && !fchmod(snap, 0400));
    snprintf(name, sizeof(name), "%s.snapshot", id);
    CHECK(!renameat(a, "temporary", a, name));
    int generations = dir(d, YD_RAFT_GENERATION_DIRECTORY), g = dir(generations, id);
    CHECK(generations >= 0 && g >= 0);
    int native = file(g, YD_DISK_FILE, 65536), mark = file(g, YD_RAFT_SNAPSHOT_CANDIDATE, 256);
    CHECK(native >= 0 && mark >= 0 && manifest(mark, 16384, id));
    YDRaftApplicationSpace s;
    CHECK(yd_raft_application_space(d, a, -1, source, id, cluster, 3, &s, error, sizeof(error)) &&
        s.complete && s.files == 4 && s.documents.retained_bytes >= 131072 + 65536 + 256 &&
        s.archives.retained_bytes >= 16384 + 256 && s.source_bytes == 131072 && s.replacement_bytes >= 65536 + 16384 + 512);
    CHECK(yd_raft_application_space(d, a, -1, native, id, cluster, 3, &s, error, sizeof(error)) &&
        s.source_bytes == 65536 && s.documents.retained_bytes >= 131072 + 65536 + 256);
    CHECK(!fchmod(snap, 0600));
    CHECK(!yd_raft_application_space(d, a, -1, source, id, cluster, 3, &s, error, sizeof(error)));
    CHECK(!fchmod(snap, 0400));
    int workspace = dir(a, "private-copy"); CHECK(workspace >= 0);
    int image = file(workspace, YD_DISK_FILE, 60000); CHECK(image >= 0);
    CHECK(!yd_raft_application_space(d, a, -1, source, NULL, cluster, 3, &s, error, sizeof(error)) && !s.complete);
    CHECK(yd_raft_application_space(d, a, workspace, source, NULL, cluster, 3, &s, error, sizeof(error)) && s.files == 4);
    close(image); close(workspace); close(mark); close(native); close(g); close(generations); close(snap); close(source);
    close(a); close(d);
    /* Restart cannot reconstruct ownership of the leftover private copy. */
    d = openat(root, "documents", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    a = openat(root, "archives", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    source = openat(d, YD_DISK_FILE, O_RDONLY | O_CLOEXEC);
    CHECK(!yd_raft_application_space(d, a, -1, source, NULL, cluster, 3, &s, error, sizeof(error)));
    close(source);
    close(a); close(d); return 0;
}
static int unknown(int root) {
    int d = dir(root, "documents"), a = dir(root, "archives"); CHECK(d >= 0 && a >= 0);
    int source = file(d, YD_DISK_FILE, 8192); CHECK(source >= 0);
    YDRaftApplicationSpace s;
    CHECK(yd_raft_application_space(d, a, -1, source, NULL, cluster, 3, &s, error, sizeof(error)));
    int x = file(a, ".incoming-dead-process", 1234); CHECK(x >= 0);
    CHECK(!yd_raft_application_space(d, a, -1, source, NULL, cluster, 3, &s, error, sizeof(error)));
    struct stat stat; CHECK(!fstat(x, &stat) && stat.st_size == 1234);
    CHECK(!unlinkat(a, ".incoming-dead-process", 0)); close(x);
    CHECK(!symlinkat("documents", a, "unknown"));
    CHECK(!yd_raft_application_space(d, a, -1, source, NULL, cluster, 3, &s, error, sizeof(error)));
    CHECK(!unlinkat(a, "unknown", 0));
    CHECK(!linkat(d, YD_DISK_FILE, d, "another-link", 0));
    CHECK(!yd_raft_application_space(d, a, -1, source, NULL, cluster, 3, &s, error, sizeof(error)));
    CHECK(!unlinkat(d, "another-link", 0));
    int incoming = dir(d, YD_RAFT_GENERATION_DIRECTORY), partial = dir(incoming, ".incoming-uncertain");
    CHECK(incoming >= 0 && partial >= 0 && !yd_raft_application_space(d, a, -1, source, NULL, cluster, 3, &s, error, sizeof(error)));
    close(partial); close(incoming); close(source); close(a); close(d); return 0;
}
static int savings(int root) {
    int source = file(root, "source", 16384); CHECK(source >= 0);
    YDRaftApplicationSpace s = observation(); struct stat status; CHECK(!fstat(source, &status));
    s.documents.device = status.st_dev;
    s.source_bytes = 16384; s.replacement_bytes = 40960;
    YDRaftApplicationLimits l = limits(); uint64_t original = 99, saved = 99;
    CHECK(yd_raft_application_savings(source, 16384, s, l, &original, &saved) == YD_RAFT_APPLICATION_ADMIT_SAVINGS && !saved);
    /* Rejected preparation extends physical bytes without a new committed view. */
    CHECK(!ftruncate(source, 131072));
    s.source_bytes = 131072;
    CHECK(yd_raft_application_savings(source, 16384, s, l, &original, &saved) == YD_RAFT_APPLICATION_ADMIT && original == 131072 && saved == 131072 - 40960);
    l.minimum_saved_bytes = saved + 1;
    CHECK(yd_raft_application_savings(source, 16384, s, l, &original, &saved) == YD_RAFT_APPLICATION_ADMIT_SAVINGS && !saved);
    l.minimum_saved_bytes = 5000; s.replacement_bytes = 131072 - 4000;
    CHECK(yd_raft_application_savings(source, 16384, s, l, &original, &saved) == YD_RAFT_APPLICATION_ADMIT_SAVINGS && !saved);
    close(source); return 0;
}
static int stability(int root) {
    int d = dir(root, "documents"), a = dir(root, "archives"), source = file(d, YD_DISK_FILE, 32768);
    CHECK(d >= 0 && a >= 0 && source >= 0);
    struct stat original; CHECK(!fstat(source, &original));
    watched_device = original.st_dev; watched_inode = original.st_ino;
    YDRaftApplicationSpace s;
    change_blocks = true; stat_calls = 0;
    CHECK(!yd_raft_application_space(d, a, -1, source, NULL, cluster, 3, &s, error, sizeof(error)) && !s.complete);
    change_blocks = false;
    CHECK(yd_raft_application_space(d, a, -1, source, NULL, cluster, 3, &s, error, sizeof(error)));
    CHECK(!renameat(d, YD_DISK_FILE, root, "moved-source"));
    int replacement = file(d, YD_DISK_FILE, 32768); CHECK(replacement >= 0);
    CHECK(!yd_raft_application_space(d, a, -1, source, NULL, cluster, 3, &s, error, sizeof(error)) && !s.complete);
    CHECK(!fstat(source, &original) && original.st_size == 32768);
    close(replacement); close(source); close(a); close(d); return 0;
}
static int entries(int root) {
    int d = dir(root, "documents"), a = dir(root, "archives"), source = file(d, YD_DISK_FILE, 8192);
    CHECK(d >= 0 && a >= 0 && source >= 0);
    for (unsigned n = 1; n <= 4096; n++) {
        position = n;
        int fd = file(a, "temporary", 16384 + 256); char id[65], name[80];
        CHECK(fd >= 0 && manifest(fd, 16384, id) && !fchmod(fd, 0400));
        snprintf(name, sizeof(name), "%s.snapshot", id);
        CHECK(!renameat(a, "temporary", a, name)); close(fd);
        if (n == 4095) {
            YDRaftApplicationSpace s;
            CHECK(yd_raft_application_space(d, a, -1, source, NULL, cluster, 3, &s, error, sizeof(error)) && s.files == 4096);
        }
    }
    YDRaftApplicationSpace s;
    CHECK(!yd_raft_application_space(d, a, -1, source, NULL, cluster, 3, &s, error, sizeof(error)) && !s.complete);
    close(source); close(a); close(d); return 0;
}
static int custody(int root) {
    int d = dir(root, "documents"), a = dir(root, "archives");
    int source = file(d, YD_DISK_FILE, 8192), workspace = dir(a, "workspace"), owned = dir(a, "custody");
    CHECK(d >= 0 && a >= 0 && source >= 0 && workspace >= 0 && owned >= 0);
    YDRaftApplicationSpace s;
    CHECK(!yd_raft_application_space(d, a, workspace, source, NULL, cluster, 3, &s, error, sizeof(error)));
    CHECK(yd_raft_application_space_with_custody(d, a, workspace, owned, source, NULL,
        cluster, 3, &s, error, sizeof(error)) && s.complete && s.files == 1 && s.source_bytes == 8192);
    int keeper = file(owned, "owner-data", 1234); CHECK(keeper >= 0);
    CHECK(!yd_raft_application_space_with_custody(d, a, workspace, owned, source, NULL,
        cluster, 3, &s, error, sizeof(error)) && !s.complete);
    struct stat before, after;
    CHECK(!fstat(keeper, &before) && before.st_size == 1234 && before.st_nlink == 1);
    CHECK(!unlinkat(owned, "owner-data", 0)); close(keeper);
    int aliases[] = {d, a, workspace};
    for (size_t i = 0; i < sizeof(aliases)/sizeof(*aliases); i++)
        CHECK(!yd_raft_application_space_with_custody(d, a, workspace, aliases[i], source,
            NULL, cluster, 3, &s, error, sizeof(error)) && !s.complete);
    CHECK(!fchmod(owned, 0750));
    CHECK(!yd_raft_application_space_with_custody(d, a, workspace, owned, source, NULL,
        cluster, 3, &s, error, sizeof(error)));
    CHECK(!fchmod(owned, 0700));
    int unrelated = dir(a, ".discarding-workspace-unknown"); CHECK(unrelated >= 0);
    CHECK(!yd_raft_application_space_with_custody(d, a, workspace, owned, source, NULL,
        cluster, 3, &s, error, sizeof(error)));
    CHECK(!fstat(unrelated, &after) && after.st_nlink > 0);
    CHECK(!unlinkat(a, ".discarding-workspace-unknown", AT_REMOVEDIR)); close(unrelated);
    CHECK(!renameat(a, "custody", root, "preserved-custody"));
    int replacement = dir(a, "custody"); CHECK(replacement >= 0);
    CHECK(!yd_raft_application_space_with_custody(d, a, workspace, owned, source, NULL,
        cluster, 3, &s, error, sizeof(error)));
    CHECK(!fstat(owned, &before) && !fstat(replacement, &after) && before.st_ino != after.st_ino);
    CHECK(before.st_nlink > 0 && after.st_nlink > 0);
    close(replacement); close(owned); close(workspace); close(source); close(a); close(d);
    return 0;
}
static int shells(int root) {
    int d = dir(root, "documents"), a = dir(root, "archives"), source = file(d, YD_DISK_FILE, 8192);
    int g = dir(d, YD_RAFT_GENERATION_DIRECTORY);
    int held[YD_RAFT_APPLICATION_SHELLS + 1];
    char id[65]; memset(id, 'a', 64); id[64] = 0;
    held[0] = dir(d, "retired-custody"); held[1] = dir(g, id);
    CHECK(d >= 0 && a >= 0 && source >= 0 && g >= 0 && held[0] >= 0 && held[1] >= 0);
    YDRaftApplicationSpace space;
    CHECK(!yd_raft_application_space(d, a, -1, source, NULL, cluster, 3, &space, error, sizeof(error)));
    CHECK(yd_raft_application_space_with_shells(d, a, -1, -1, held, 2, source, NULL,
        cluster, 3, &space, error, sizeof(error)) && space.complete && space.files == 1 && space.source_bytes == 8192);
    CHECK(!yd_raft_application_space_with_shells(d, a, -1, -1, held, 1, source, NULL,
        cluster, 3, &space, error, sizeof(error)) && !space.complete);
    int duplicate[] = {held[0], held[0], held[1]};
    CHECK(!yd_raft_application_space_with_shells(d, a, -1, -1, duplicate, 3, source, NULL,
        cluster, 3, &space, error, sizeof(error)) && !space.complete);
    int aliases[] = {d, a, g};
    for (size_t n = 0; n < sizeof(aliases)/sizeof(*aliases); n++) {
        int list[] = {held[0], held[1], aliases[n]};
        CHECK(!yd_raft_application_space_with_shells(d, a, -1, -1, list, 3, source, NULL,
            cluster, 3, &space, error, sizeof(error)) && !space.complete);
    }
    int keep = file(held[1], "owner-data", 1234); CHECK(keep >= 0);
    CHECK(!yd_raft_application_space_with_shells(d, a, -1, -1, held, 2, source, NULL,
        cluster, 3, &space, error, sizeof(error)) && !space.complete);
    struct stat info; CHECK(!fstat(keep, &info) && info.st_size == 1234 && info.st_nlink == 1);
    CHECK(!unlinkat(held[1], "owner-data", 0)); close(keep);
    CHECK(!fchmod(held[0], 0750));
    CHECK(!yd_raft_application_space_with_shells(d, a, -1, -1, held, 2, source, NULL,
        cluster, 3, &space, error, sizeof(error)));
    CHECK(!fchmod(held[0], 0700));
    CHECK(!renameat(d, "retired-custody", root, "saved-custody"));
    int replacement = dir(d, "retired-custody"); CHECK(replacement >= 0);
    CHECK(!yd_raft_application_space_with_shells(d, a, -1, -1, held, 2, source, NULL,
        cluster, 3, &space, error, sizeof(error)) && !space.complete);
    CHECK(!fstat(held[0], &info) && info.st_nlink > 0);
    CHECK(!fstat(replacement, &info) && info.st_nlink > 0);
    CHECK(!unlinkat(d, "retired-custody", AT_REMOVEDIR)); close(replacement);
    CHECK(!renameat(root, "saved-custody", d, "retired-custody"));
    for (unsigned n = 2; n <= YD_RAFT_APPLICATION_SHELLS; n++) {
        char name[32]; snprintf(name, sizeof(name), "shell-%u", n);
        held[n] = dir(d, name); CHECK(held[n] >= 0);
        if (n == YD_RAFT_APPLICATION_SHELLS - 1)
            CHECK(yd_raft_application_space_with_shells(d, a, -1, -1, held, n + 1, source,
                NULL, cluster, 3, &space, error, sizeof(error)) && space.complete);
    }
    CHECK(!yd_raft_application_space_with_shells(d, a, -1, -1, held, YD_RAFT_APPLICATION_SHELLS,
        source, NULL, cluster, 3, &space, error, sizeof(error)) && !space.complete);
    CHECK(!yd_raft_application_space_with_shells(d, a, -1, -1, held, YD_RAFT_APPLICATION_SHELLS + 1,
        source, NULL, cluster, 3, &space, error, sizeof(error)) && !space.complete);
    for (unsigned n = 0; n <= YD_RAFT_APPLICATION_SHELLS; n++) close(held[n]);
    close(g); close(source); close(a); close(d); return 0;
}
static int bound(int root) {
    int d = dir(root, "documents"), a = dir(root, "archives"), g = dir(d, YD_RAFT_GENERATION_DIRECTORY);
    int source = file(d, YD_DISK_FILE, 8192); CHECK(source >= 0);
    CHECK(d >= 0 && a >= 0 && g >= 0);
    char id[65]; memset(id, '0', 64); id[64] = 0;
    int child = dir(g, id); CHECK(child >= 0);
    /* Structurally named but incomplete is neither invisible nor disposable. */
    YDRaftApplicationSpace s;
    CHECK(!yd_raft_application_space(d, a, -1, source, NULL, cluster, 3, &s, error, sizeof(error)));
    CHECK(!fchmod(a, 0770));
    CHECK(!yd_raft_application_space(d, a, -1, source, NULL, cluster, 3, &s, error, sizeof(error)));
    close(source); close(child); close(g); close(a); close(d); return 0;
}
int main(int argc, char **argv) {
    if (argc != 3) return 2;
    int root = open(argv[1], O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (root < 0) return 2;
    int result = !strcmp(argv[2], "arithmetic") ? arithmetic() : !strcmp(argv[2], "overflow") ? overflow() :
        !strcmp(argv[2], "inventory") ? inventory(root) : !strcmp(argv[2], "unknown") ? unknown(root) :
        !strcmp(argv[2], "savings") ? savings(root) : !strcmp(argv[2], "bound") ? bound(root) :
        !strcmp(argv[2], "stability") ? stability(root) : !strcmp(argv[2], "entries") ? entries(root) :
        !strcmp(argv[2], "custody") ? custody(root) : !strcmp(argv[2], "shells") ? shells(root) : 2;
    close(root); return result;
}
