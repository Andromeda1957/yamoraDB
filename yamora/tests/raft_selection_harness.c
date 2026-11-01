#define _POSIX_C_SOURCE 200809L
#include "../src/consensus/cluster.h"
#include "../src/consensus/cluster_internal.h"
#include "../src/consensus/application_internal.h"
#include "../src/consensus/application_retire.h"
#include "../src/consensus/install.h"
#include "../src/consensus/recovery.h"
#include "../src/consensus/raft_internal.h"
#include "../src/consensus/snapshot_restore.h"
#include "../src/disk_internal.h"
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
static char error[512];
static atomic_uint starts;
static atomic_bool observing;
static atomic_bool hold_apply, waiting_apply, hold_write, waiting_write;
static _Thread_local unsigned fail_journal_sync, journal_syncs;
static _Thread_local bool fail_restore_once;
static _Thread_local unsigned crash_publication;
static _Thread_local YDRaftCluster *contact_during_stage;
static _Thread_local YDRaftSnapshotOffer staged_contact;
static _Thread_local bool staging_contacted;
int __real_renameat2(int, const char *, int, const char *, unsigned);
int __wrap_renameat2(int a, const char *b, int c, const char *d, unsigned flags) {
    if (contact_during_stage) {
        bool needed = false;
        staging_contacted = yd_raft_cluster_snapshot_contact(contact_during_stage, &staged_contact, &needed) && needed;
        contact_during_stage = NULL;
        if (!staging_contacted) { errno = EIO; return -1; }
    }
    return __real_renameat2(a, b, c, d, flags);
}
bool __real_yd_raft_snapshot_install_layout(YDRaft *, const YDRaftSnapshotOffer *, unsigned);
bool __wrap_yd_raft_snapshot_install_layout(YDRaft *raft, const YDRaftSnapshotOffer *offer, unsigned layout) {
    if (crash_publication == 1) kill(getpid(), SIGKILL);
    bool valid = __real_yd_raft_snapshot_install_layout(raft, offer, layout);
    if (valid && crash_publication == 2) kill(getpid(), SIGKILL);
    return valid;
}
bool __real_yd_raft_application_slots_bind(YDRaftApplicationSlots *, unsigned, int,
    const unsigned char[32], char *, size_t);
bool __wrap_yd_raft_application_slots_bind(YDRaftApplicationSlots *slots, unsigned slot, int native,
    const unsigned char identity[32], char *message, size_t length) {
    bool valid = __real_yd_raft_application_slots_bind(slots, slot, native, identity, message, length);
    if (valid && contact_during_stage) {
        bool needed = false;
        staging_contacted = yd_raft_cluster_snapshot_contact(contact_during_stage, &staged_contact, &needed) && needed;
        contact_during_stage = NULL;
        valid = staging_contacted;
    }
    return valid;
}
static dev_t journal_device;
static ino_t journal_inode;
int __real_fsync(int fd);
int __wrap_fsync(int fd) {
    struct stat status;
    if (fail_restore_once && !fstat(fd, &status) && S_ISREG(status.st_mode) && status.st_size == 256) {
        fail_restore_once = false;
        errno = EIO;
        return -1;
    }
    if (fail_journal_sync && !fstat(fd, &status) && status.st_dev == journal_device &&
        status.st_ino == journal_inode && ++journal_syncs == fail_journal_sync) {
        errno = EIO;
        return -1;
    }
    return __real_fsync(fd);
}
int __real_yd_raft_runtime_wait(YDRaftRuntime *, uint64_t, unsigned);
int __wrap_yd_raft_runtime_wait(YDRaftRuntime *runtime, uint64_t after, unsigned timeout) {
    if (atomic_load(&hold_apply)) {
        atomic_store(&waiting_apply, true);
        struct timespec delay = {.tv_nsec = 1000000};
        while (atomic_load(&hold_apply)) nanosleep(&delay, NULL);
    }
    return __real_yd_raft_runtime_wait(runtime, after, timeout);
}
bool __real_yd_raft_runtime_barrier(YDRaftRuntime *, unsigned, uint64_t *, uint64_t *);
bool __wrap_yd_raft_runtime_barrier(YDRaftRuntime *runtime, unsigned timeout, uint64_t *term, uint64_t *index) {
    if (atomic_load(&hold_write)) {
        atomic_store(&waiting_write, true);
        struct timespec delay = {.tv_nsec = 1000000};
        while (atomic_load(&hold_write)) nanosleep(&delay, NULL);
    }
    return __real_yd_raft_runtime_barrier(runtime, timeout, term, index);
}
int __real_pthread_create(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);
int __wrap_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                           void *(*function)(void *), void *argument) {
    if (atomic_load(&observing)) atomic_fetch_add(&starts, 1);
    return __real_pthread_create(thread, attr, function, argument);
}
#define REQUIRE(x) do { if (!(x)) { \
    fprintf(stderr, "line %u: %s (%s)\n", __LINE__, #x, error); return 2; \
} } while (0)
static bool acknowledge(YDRaft *raft) {
    YDRaftAppend request;
    if (!yd_raft_append_request(raft, 2, &request)) return false;
    YDRaftAppendReply reply = {.term = request.term, .rpc = request.rpc, .accepted = true,
                               .matched = request.previous + request.has_entry};
    yd_raft_append_free(&request);
    return yd_raft_append_reply(raft, 2, &reply);
}
static void identity(const char id[65], unsigned char hash[32]) {
    for (unsigned i = 0; i < 32; i++) {
        char pair[3] = {id[2 * i], id[2 * i + 1], 0};
        hash[i] = (unsigned char)strtoul(pair, NULL, 16);
    }
}
static bool archive(YDRaftApplication *app, const char *journal, const unsigned char cluster[16],
                      char id[65]) {
    char directory[8192];
    snprintf(directory, sizeof(directory), "%s/.yamora-snapshots", journal);
    if (mkdir(directory, 0700) && errno != EEXIST) return false;
    YDRaftSnapshot *snapshot = yd_raft_snapshot_open(app, 3, error, sizeof(error));
    unsigned char manifest[256], bytes[4093];
    YDRaftSnapshotInfo info = {0};
    bool valid = snapshot && yd_raft_snapshot_seal(snapshot, NULL, NULL, error, sizeof(error)) &&
        yd_raft_snapshot_manifest(snapshot, manifest) &&
        yd_raft_snapshot_decode(manifest, sizeof(manifest), cluster, 3, &info, error, sizeof(error));
    YDRaftCheckpoint expected = {0};
    if (valid) {
        expected.applied = info.applied;
        memcpy(expected.cluster, cluster, 16);
        memcpy(expected.digest, info.entry_digest, 32);
        valid = yd_raft_application_validate(app, &expected, &info.view, error, sizeof(error));
    }
    YDRaftSnapshotStore *store = valid ? yd_raft_snapshot_store_open(directory, cluster, 3,
                                                                    error, sizeof(error)) : NULL;
    YDRaftSnapshotStage *stage = store ? yd_raft_snapshot_stage_new(store, manifest, 256,
                                                                    error, sizeof(error)) : NULL;
    valid = stage != NULL;
    for (uint64_t at = 0; valid && at < info.view.end;) {
        size_t count = info.view.end - at < sizeof(bytes) ? (size_t)(info.view.end - at) : sizeof(bytes);
        valid = yd_raft_snapshot_read(snapshot, at, bytes, count, error, sizeof(error)) &&
            yd_raft_snapshot_stage_feed(stage, at, bytes, count, error, sizeof(error));
        at += count;
    }
    valid = valid && yd_raft_snapshot_stage_finish(stage, id, error, sizeof(error));
    yd_raft_snapshot_stage_close(stage);
    yd_raft_snapshot_store_close(store);
    yd_raft_snapshot_close(snapshot);
    return valid;
}
static bool append_write(YDRaft *raft, YDRaftApplication *app, bool increment) {
    static const unsigned char source[] = "# selected source\r\ncount: 0 # exact\r\n";
    static const unsigned char patch[] = "{\"$inc\":{\"count\":1}}";
    YDRaftWrite write = {.id = {1}, .method = increment ? "PATCH" : "PUT",
        .target = "/v1/collections/config/documents/node",
        .body = increment ? patch : source, .size = increment ? sizeof(patch) - 1 : sizeof(source) - 1};
    write.id[0] = increment ? 2 : 1;
    YDRaftProposal proposal;
    if (yd_raft_application_prepare(app, &write, &proposal, error, sizeof(error)) != 1) return false;
    uint64_t index;
    bool valid = yd_raft_propose(raft, proposal.command, proposal.size, &index);
    yd_raft_proposal_free(&proposal);
    YDRaftEntry entry;
    valid = valid && yd_raft_entry(raft, index, &entry);
    if (valid) {
        valid = yd_raft_application_apply(app, &entry, error, sizeof(error));
        yd_raft_entry_free(&entry);
    }
    return valid;
}
static bool file_digest(const char *path, unsigned char out[32]) {
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    EVP_MD_CTX *hash = EVP_MD_CTX_new();
    bool valid = fd >= 0 && hash && EVP_DigestInit_ex(hash, EVP_sha256(), NULL) == 1;
    unsigned char bytes[4096];
    while (valid) {
        ssize_t n = read(fd, bytes, sizeof(bytes));
        if (n < 0 && errno == EINTR) continue;
        if (!n) break;
        valid = n > 0 && EVP_DigestUpdate(hash, bytes, (size_t)n) == 1;
    }
    unsigned size = 0;
    valid = valid && EVP_DigestFinal_ex(hash, out, &size) == 1 && size == 32;
    EVP_MD_CTX_free(hash);
    if (fd >= 0) close(fd);
    return valid;
}
static bool cancel_graph(void *context, uint64_t done, uint64_t total) {
    unsigned *calls = context;
    return !total || done != total || ++*calls < 5;
}
static bool cancel(void *context, uint64_t done, uint64_t total) {
    (void)context; (void)done; (void)total;
    return false;
}
/* Offline fixture utility only; all involved daemons must already be stopped. */
static int prepare(const char *journal, const char *data, const char *source,
                     unsigned node, unsigned from) {
    const unsigned char cluster[16] = {1, 2, 3, 4};
    YDRaftApplication *app = yd_raft_application_open(source, cluster, 32768, error, sizeof(error));
    YDRaft *raft = yd_raft_open(journal, cluster, node, 3, 32768, error, sizeof(error));
    REQUIRE(app && raft && yd_raft_application_position(app).index > yd_raft_status(raft).committed);
    char id[65], archive_dir[8192], generations[8192], candidate[8192];
    REQUIRE(archive(app, journal, cluster, id));
    snprintf(archive_dir, sizeof(archive_dir), "%s/.yamora-snapshots", journal);
    snprintf(generations, sizeof(generations), "%s/.yamora-generations", data);
    snprintf(candidate, sizeof(candidate), "%s/.yamora-generations/%s", data, id);
    REQUIRE((!mkdir(generations, 0700) || errno == EEXIST) && !mkdir(candidate, 0700));
    YDRaftSnapshotStore *store = yd_raft_snapshot_store_open(archive_dir, cluster, 3, error, sizeof(error));
    YDRaftSnapshotArchive *image = yd_raft_snapshot_archive_open(store, id, NULL, NULL, error, sizeof(error));
    REQUIRE(image && yd_raft_snapshot_restore(image, candidate, cluster, 3, 32768,
                                              NULL, NULL, error, sizeof(error)));
    yd_raft_snapshot_archive_close(image);
    yd_raft_snapshot_store_close(store);
    int parent = open(generations, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int root = open(data, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int journal_fd = open(journal, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    REQUIRE(parent >= 0 && root >= 0 && journal_fd >= 0 &&
        !fsync(parent) && !fsync(root) && !fsync(journal_fd));
    close(parent); close(root); close(journal_fd);
    YDRaftApplied position = yd_raft_application_position(app);
    YDRaftSnapshotOffer offer = {.from = from, .term = position.term,
        .base = {.index = position.index, .term = position.term}};
    memcpy(offer.cluster, cluster, 16);
    identity(id, offer.base.archive);
    bool needed;
    REQUIRE(yd_raft_snapshot_contact(raft, &offer, &needed) && needed &&
        yd_raft_snapshot_install(raft, &offer));
    yd_raft_application_close(app);
    yd_raft_close(raft);
    printf("selected=%llu\n", (unsigned long long)position.index);
    return 0;
}
static bool wait_flag(atomic_bool *flag) {
    struct timespec delay = {.tv_nsec = 1000000};
    for (unsigned i = 0; i < 5000 && !atomic_load(flag); i++) nanosleep(&delay, NULL);
    return atomic_load(flag);
}
static void *pending_write(void *context) {
    static const unsigned char body[] = "a: 1\n";
    YDRaftWrite write = {.id = {99}, .method = "PUT", .target = "/v1/collections/a/documents/b",
        .body = body, .size = sizeof(body) - 1};
    YDDiskReply reply = yd_raft_cluster_write(context, &write, 3000);
    bool valid = reply.status == 503;
    yd_disk_reply_free(&reply);
    return valid ? NULL : context;
}
static bool prepare_bad_candidate(YDRaftConfig *config, const char *data, const char *id, const char *mode) {
    char parent[8192], child[8192], directory[8192], file[8192], marker[8192], retained[8192];
    snprintf(parent, sizeof(parent), "%s/.yamora-generations", data);
    snprintf(child, sizeof(child), "%s/.yamora-generations/%s", data, id);
    snprintf(directory, sizeof(directory), "%s/.yamora-snapshots", config->journal_root);
    if (mkdir(parent, 0700) || mkdir(child, 0700)) return false;
    YDRaftSnapshotStore *store = yd_raft_snapshot_store_open(directory, config->cluster, 3, error, sizeof(error));
    YDRaftSnapshotArchive *archive = store ? yd_raft_snapshot_archive_open(store, id, NULL, NULL, error, sizeof(error)) : NULL;
    bool valid = archive && yd_raft_snapshot_restore(archive, child, config->cluster, 3, 32768,
        NULL, NULL, error, sizeof(error));
    yd_raft_snapshot_archive_close(archive);
    yd_raft_snapshot_store_close(store);
    if (!valid) return false;
    snprintf(file, sizeof(file), "%s/.yamora-generations/%s/%s", data, id, YD_DISK_FILE);
    snprintf(marker, sizeof(marker), "%s/.yamora-generations/%s/.yamora-snapshot", data, id);
    if (!strcmp(mode, "live-bad-fence")) {
        int fd = openat(AT_FDCWD, child, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        int fence = fd >= 0 ? openat(fd, ".yamora-initializing", O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600) : -1;
        valid = fence >= 0;
        if (fence >= 0) close(fence);
        if (fd >= 0) close(fd);
    } else if (!strcmp(mode, "live-bad-permissions")) valid = !chmod(child, 0777);
    else if (!strcmp(mode, "live-bad-hardlink")) {
        snprintf(retained, sizeof(retained), "%s/extra-link", data);
        valid = !link(file, retained);
    } else if (!strcmp(mode, "live-bad-data") || !strcmp(mode, "live-bad-marker")) {
        const char *target = !strcmp(mode, "live-bad-data") ? file : marker;
        off_t offset = !strcmp(mode, "live-bad-data") ? 3U * YD_DISK_PAGE + 100U : 104;
        int fd = open(target, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
        unsigned char byte = 0;
        valid = fd >= 0 && pread(fd, &byte, 1, offset) == 1;
        byte ^= 1;
        valid = valid && pwrite(fd, &byte, 1, offset) == 1 && !fsync(fd);
        if (fd >= 0) close(fd);
    } else if (!strcmp(mode, "live-bad-advanced")) {
        YDRaftApplication *app = yd_raft_application_open(child, config->cluster, 32768, error, sizeof(error));
        YDRaftEntry entry = {.index = 3, .term = 2, .kind = YD_RAFT_NOOP};
        valid = app && yd_raft_application_apply(app, &entry, error, sizeof(error));
        yd_raft_application_close(app);
    }
    return valid;
}
static int live_install(YDRaftConfig *config, const char *data, const char *cert, const char *key,
                          const char *ca, int listener, const char *id, const char *mode) {
    config->timing = (YDRaftTiming){.heartbeat_ms = 100, .election_min_ms = 5000,
        .election_max_ms = 8000, .rpc_ms = 1000};
    YDTLS *tls = yd_tls_peer_new(cert, key, ca, error, sizeof(error));
    REQUIRE(tls);
    atomic_store(&hold_apply, true);
    YDRaftCluster *c = yd_raft_cluster_start(config, data, 32768, tls, listener, error, sizeof(error));
    REQUIRE(c && wait_flag(&waiting_apply) && yd_raft_cluster_status(c).applied.index == 1);
    YDRaftSnapshotOffer offer = {.from = 2, .term = 2, .base = {.index = 2, .term = 1}};
    memcpy(offer.cluster, config->cluster, 16);
    identity(id, offer.base.archive);
    REQUIRE(!yd_raft_cluster_snapshot_install(c, &offer, 3000, error, sizeof(error)));
    if (!strcmp(mode, "live-invalid")) {
        YDRaftSnapshotOffer invalid = offer;
        invalid.from = 0;
        invalid.term = yd_raft_cluster_status(c).raft.term;
        REQUIRE(!yd_raft_cluster_snapshot_install(c, &invalid, 3000, error, sizeof(error)));
        char parent[8192];
        snprintf(parent, sizeof(parent), "%s/.yamora-generations", data);
        struct stat status;
        REQUIRE(lstat(parent, &status) < 0 && errno == ENOENT);
    }
    bool needed;
    REQUIRE(yd_raft_cluster_snapshot_contact(c, &offer, &needed) && needed);
    int archive_directory = yd_raft_cluster_snapshot_directory(c);
    REQUIRE(archive_directory >= 0);
    close(archive_directory);
    if (!strncmp(mode, "live-staging-", 13)) {
        contact_during_stage = c;
        staged_contact = offer;
        if (!strcmp(mode, "live-staging-term")) staged_contact.term++;
        else staged_contact.from = 3;
    }
    if (!strncmp(mode, "live-bad-", 9) || !strncmp(mode, "live-staging-", 13) || !strcmp(mode, "live-superseded") ||
        !strcmp(mode, "live-mismatch")) {
        if (!strncmp(mode, "live-bad-", 9)) REQUIRE(prepare_bad_candidate(config, data, id, mode));
        if (!strcmp(mode, "live-mismatch")) offer.base.index++;
        if (!strcmp(mode, "live-superseded")) {
            YDRaftSnapshotOffer newer = offer;
            newer.term++;
            REQUIRE(yd_raft_cluster_snapshot_contact(c, &newer, &needed) && needed);
        }
        char original[8192];
        snprintf(original, sizeof(original), "%s/%s", data, YD_DISK_FILE);
        unsigned char before[32], after[32];
        REQUIRE(file_digest(original, before) &&
            !yd_raft_cluster_snapshot_install(c, &offer, 3000, error, sizeof(error)) &&
            !yd_raft_cluster_status(c).failed && yd_raft_cluster_status(c).applied.index == 1 &&
            yd_raft_cluster_status(c).raft.committed == 1 && file_digest(original, after) &&
            !memcmp(before, after, sizeof(before)));
        if (!strncmp(mode, "live-staging-", 13)) REQUIRE(staging_contacted);
        atomic_store(&hold_apply, false);
        yd_raft_cluster_close(c);
        yd_tls_free(tls);
        puts("live=0 retained=1");
        return 0;
    }
    if (!strncmp(mode, "live-sync", 9)) {
        char journal[8192];
        snprintf(journal, sizeof(journal), "%s/%s", config->journal_root, YD_DISK_FILE);
        struct stat status;
        REQUIRE(!stat(journal, &status));
        journal_device = status.st_dev; journal_inode = status.st_ino;
        fail_journal_sync = !strcmp(mode, "live-sync1") ? 1 : 2;
        REQUIRE(!yd_raft_cluster_snapshot_install(c, &offer, 3000, error, sizeof(error)) &&
            yd_raft_cluster_status(c).failed && yd_raft_cluster_status(c).applied.index == 1);
        fail_journal_sync = 0;
        atomic_store(&hold_apply, false);
        yd_raft_cluster_close(c);
        c = yd_raft_cluster_start(config, data, 32768, tls, listener, error, sizeof(error));
        REQUIRE(c && !yd_raft_cluster_status(c).failed);
        uint64_t index = yd_raft_cluster_status(c).applied.index;
        REQUIRE((index == 1 || index == 2) && yd_raft_cluster_status(c).raft.committed == index);
        yd_raft_cluster_close(c);
        yd_tls_free(tls);
        puts("live=0 restart=1");
        return 0;
    }
    char moved_data[8192], moved_journal[8192];
    bool pinned = !strcmp(mode, "live-pinned");
    if (pinned) {
        snprintf(moved_data, sizeof(moved_data), "%s-moved", data);
        snprintf(moved_journal, sizeof(moved_journal), "%s-moved", config->journal_root);
        REQUIRE(!rename(data, moved_data) && !mkdir(data, 0700) &&
            !rename(config->journal_root, moved_journal) && !mkdir(config->journal_root, 0700));
    }
    if (!strcmp(mode, "live-write-wait")) {
        pthread_t writer;
        atomic_store(&hold_write, true);
        REQUIRE(!pthread_create(&writer, NULL, pending_write, c) && wait_flag(&waiting_write));
        REQUIRE(!yd_raft_cluster_snapshot_install(c, &offer, 150, error, sizeof(error)) &&
            yd_raft_cluster_status(c).applied.index == 1 && !yd_raft_cluster_status(c).failed);
        atomic_store(&hold_write, false);
        void *result;
        REQUIRE(!pthread_join(writer, &result) && !result);
    }
    if (!strcmp(mode, "live-crash-before")) crash_publication = 1;
    if (!strcmp(mode, "live-crash-after")) crash_publication = 2;
    char copy_fence[8192] = {0};
    if (!strcmp(mode, "live-copy-retry")) {
        fail_restore_once = true;
        REQUIRE(!yd_raft_cluster_snapshot_install(c, &offer, 3000, error, sizeof(error)) &&
            !fail_restore_once && !yd_raft_cluster_status(c).failed &&
            yd_raft_cluster_status(c).applied.index == 1);
        char parent[8192];
        snprintf(parent, sizeof(parent), "%s/.yamora-generations", data);
        DIR *scan = opendir(parent);
        REQUIRE(scan);
        struct dirent *entry;
        while ((entry = readdir(scan)))
            if (!strncmp(entry->d_name, YD_RAFT_APPLICATION_SLOT_PREFIX,
                    strlen(YD_RAFT_APPLICATION_SLOT_PREFIX))) {
                char path[8192];
                snprintf(path, sizeof(path), "%s/.yamora-generations/%s/.yamora-initializing",
                    data, entry->d_name);
                if (access(path, F_OK)) continue;
                REQUIRE(!copy_fence[0]);
                snprintf(copy_fence, sizeof(copy_fence), "%s/.yamora-generations/%s/.yamora-initializing",
                    data, entry->d_name);
            }
        closedir(scan);
        struct stat marker;
        REQUIRE(copy_fence[0] && !stat(copy_fence, &marker) && marker.st_size == 256);
        unsigned char before[32], after[32];
        REQUIRE(file_digest(copy_fence, before) &&
            !yd_raft_cluster_snapshot_install(c, &offer, 3000, error, sizeof(error)) &&
            file_digest(copy_fence, after) && !memcmp(before, after, sizeof(before)) &&
            !yd_raft_cluster_status(c).failed && yd_raft_cluster_status(c).applied.index == 1 &&
            yd_raft_cluster_status(c).raft.committed == 1);
        atomic_store(&hold_apply, false);
        yd_raft_cluster_close(c);
        c = yd_raft_cluster_start(config, data, 32768, tls, listener, error, sizeof(error));
        REQUIRE(c && yd_raft_cluster_status(c).applied.index == 1 &&
            yd_raft_cluster_snapshot_contact(c, &offer, &needed) && needed &&
            !yd_raft_cluster_snapshot_install(c, &offer, 3000, error, sizeof(error)) &&
            file_digest(copy_fence, after) && !memcmp(before, after, sizeof(before)));
        yd_raft_cluster_close(c);
        yd_tls_free(tls);
        puts("incomplete=1 preserved=1");
        return 0;
    }
    REQUIRE(yd_raft_cluster_snapshot_install(c, &offer, 3000, error, sizeof(error)));
    if (copy_fence[0]) {
        struct stat marker;
        REQUIRE(!stat(copy_fence, &marker) && marker.st_size == 256);
    }
    YDRaftClusterStatus status = yd_raft_cluster_status(c);
    REQUIRE(!status.failed && status.applied.index == 2 && status.raft.committed == 2);
    REQUIRE(!yd_raft_cluster_snapshot_install(c, &offer, 3000, error, sizeof(error)));
    char original[8192];
    int original_length = snprintf(original, sizeof(original), "%s/%s",
        pinned ? moved_data : data, YD_DISK_FILE);
    REQUIRE(original_length > 0 && (size_t)original_length < sizeof(original));
    int old_file = open(original, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    REQUIRE(old_file >= 0 && flock(old_file, LOCK_EX | LOCK_NB) < 0 &&
        (errno == EWOULDBLOCK || errno == EAGAIN));
    atomic_store(&hold_apply, false);
    struct timespec delay = {.tv_nsec = 1000000};
    /* The replacement ticket retains its independent source pin after the
     * applier releases its generation. Only controller close releases both. */
    delay.tv_nsec = 200000000;
    nanosleep(&delay, NULL);
    REQUIRE(!yd_raft_cluster_status(c).failed && yd_raft_cluster_status(c).applied.index == 2);
    yd_raft_cluster_close(c);
    REQUIRE(!flock(old_file, LOCK_EX | LOCK_NB));
    close(old_file);
    if (pinned) {
        REQUIRE(!yd_disk_present(data) && !yd_disk_present(config->journal_root) &&
            !rmdir(data) && !rename(moved_data, data) &&
            !rmdir(config->journal_root) && !rename(moved_journal, config->journal_root));
    }
    c = yd_raft_cluster_start(config, data, 32768, tls, listener, error, sizeof(error));
    REQUIRE(c && !yd_raft_cluster_status(c).failed && yd_raft_cluster_status(c).applied.index == 2);
    YDDisk *disk = yd_raft_cluster_disk(c);
    YDDiskView view = yd_disk_view(disk);
    YDDiskDocument doc;
    static const char expected[] = "# selected source\r\ncount: 0 # exact\r\n";
    REQUIRE(yd_disk_document_get(disk, &view, "config", "node", &doc, error, sizeof(error)) == 1 &&
        doc.length == sizeof(expected) - 1 && !memcmp(doc.body, expected, sizeof(expected) - 1));
    yd_disk_document_free(&doc);
    yd_raft_cluster_close(c);
    yd_tls_free(tls);
    puts("live=1 restart=1");
    return 0;
}
int main(int argc, char **argv) {
    if (argc == 4 && !strcmp(argv[1], "initialize")) {
        const unsigned char identity[16] = {1, 2, 3, 4};
        YDRaft *raft = yd_raft_open(argv[2], identity, (unsigned)strtoul(argv[3], NULL, 10),
            3, 32768, error, sizeof(error));
        REQUIRE(raft);
        yd_raft_close(raft);
        return 0;
    }
    if (argc == 4 && !strcmp(argv[1], "archive")) {
        const unsigned char cluster[16] = {1, 2, 3, 4};
        YDRaftApplication *app = yd_raft_application_open(argv[3], cluster, 32768, error, sizeof(error));
        char id[65];
        REQUIRE(app && archive(app, argv[2], cluster, id));
        YDRaftApplied position = yd_raft_application_position(app);
        printf("archive=%s index=%llu term=%llu\n", id, (unsigned long long)position.index,
            (unsigned long long)position.term);
        yd_raft_application_close(app);
        return 0;
    }
    if (argc == 7 && !strcmp(argv[1], "prepare"))
        return prepare(argv[2], argv[3], argv[4], (unsigned)strtoul(argv[5], NULL, 10),
                       (unsigned)strtoul(argv[6], NULL, 10));
    if (argc != 8) return 1;
    const char *mode = argv[7];
    char journal[4096], data[4096], source[4096], cert[4096], key[4096], ca[4096];
    snprintf(journal, sizeof(journal), "%s/journal", argv[1]);
    snprintf(data, sizeof(data), "%s/data", argv[1]);
    snprintf(source, sizeof(source), "%s/source", argv[1]);
    bool recovering = !strncmp(mode, "live-recover-", 13);
    if (!recovering) REQUIRE(!mkdir(journal, 0700) && !mkdir(data, 0700) && !mkdir(source, 0700));
    snprintf(cert, sizeof(cert), "%s/node1.pem", argv[2]);
    snprintf(key, sizeof(key), "%s/node1.key", argv[2]);
    snprintf(ca, sizeof(ca), "%s/trusted.pem", argv[2]);
    YDRaftConfig config = {.journal_root = journal, .cluster = {1, 2, 3, 4}, .node = 1, .voters = 3,
        .names = {NULL, "node1.test", "node2.test", "node3.test"},
        .addresses = {NULL, "127.0.0.1", "127.0.0.1", "127.0.0.1"},
        .timing = {.heartbeat_ms = 50, .election_min_ms = 600, .election_max_ms = 1100, .rpc_ms = 250},
        .cache_bytes = 32768, .command_bytes = 64U * 1024U * 1024U};
    for (unsigned i = 1; i <= 3; i++) config.ports[i] = (uint16_t)strtoul(argv[3 + i], NULL, 10);
    if (recovering) {
        config.timing = (YDRaftTiming){.heartbeat_ms = 100, .election_min_ms = 5000,
            .election_max_ms = 8000, .rpc_ms = 1000};
        YDTLS *tls = yd_tls_peer_new(cert, key, ca, error, sizeof(error));
        REQUIRE(tls);
        YDRaftCluster *c = yd_raft_cluster_start(&config, data, 32768, tls,
            (int)strtol(argv[3], NULL, 10), error, sizeof(error));
        REQUIRE(c);
        YDRaftClusterStatus status = yd_raft_cluster_status(c);
        uint64_t expected = !strcmp(mode, "live-recover-before") ? 1 : 2;
        REQUIRE(!status.failed && status.applied.index == expected && status.raft.committed == expected);
        YDDisk *disk = yd_raft_cluster_disk(c);
        YDDiskView view = yd_disk_view(disk);
        YDDiskDocument document;
        int found = yd_disk_document_get(disk, &view, "config", "node", &document, error, sizeof(error));
        static const char source[] = "# selected source\r\ncount: 0 # exact\r\n";
        REQUIRE(expected == 1 ? found == 0 : found == 1 && document.length == sizeof(source) - 1 &&
            !memcmp(document.body, source, sizeof(source) - 1));
        yd_disk_document_free(&document);
        yd_raft_cluster_close(c);
        yd_tls_free(tls);
        printf("recovered=%llu\n", (unsigned long long)expected);
        return 0;
    }
    YDRaftApplication *old = yd_raft_application_open(data, config.cluster, 32768, error, sizeof(error));
    YDRaftApplication *sender = yd_raft_application_open(source, config.cluster, 32768, error, sizeof(error));
    YDRaft *raft = yd_raft_open(journal, config.cluster, 1, 3, 32768, error, sizeof(error));
    YDRaftVote vote;
    REQUIRE(old && sender && raft && yd_raft_campaign(raft, &vote));
    YDRaftVoteReply reply = {.term = vote.term, .granted = true};
    REQUIRE(yd_raft_vote_reply(raft, 2, vote.term, &reply) && acknowledge(raft));
    YDRaftEntry entry;
    REQUIRE(yd_raft_entry(raft, 1, &entry) &&
        yd_raft_application_apply(old, &entry, error, sizeof(error)) &&
        yd_raft_application_apply(sender, &entry, error, sizeof(error)));
    yd_raft_entry_free(&entry);
    /* Sender represents a leader's committed application. The target retains
     * that entry only as an uncommitted tail until incoming installation. */
    REQUIRE(append_write(raft, sender, false) && yd_raft_status(raft).committed == 1);
    char id[65], directory[8192], generations[8192], candidate[8192];
    REQUIRE(archive(sender, journal, config.cluster, id));
    if (!strncmp(mode, "live", 4)) {
        yd_raft_application_close(old);
        yd_raft_application_close(sender);
        yd_raft_close(raft);
        return live_install(&config, data, cert, key, ca, (int)strtol(argv[3], NULL, 10), id, mode);
    }
    snprintf(directory, sizeof(directory), "%s/.yamora-snapshots", journal);
    snprintf(generations, sizeof(generations), "%s/.yamora-generations", data);
    snprintf(candidate, sizeof(candidate), "%s/.yamora-generations/%s", data, id);
    REQUIRE(!mkdir(generations, 0700) && !mkdir(candidate, 0700));
    YDRaftSnapshotStore *store = yd_raft_snapshot_store_open(directory, config.cluster, 3, error, sizeof(error));
    YDRaftSnapshotArchive *image = yd_raft_snapshot_archive_open(store, id, NULL, NULL, error, sizeof(error));
    REQUIRE(image && yd_raft_snapshot_restore(image, candidate, config.cluster, 3, 32768,
                                              NULL, NULL, error, sizeof(error)));
    if (!strcmp(mode, "candidate-graph")) {
        unsigned char manifest[YD_RAFT_SNAPSHOT_MANIFEST], before[32], after[32];
        char file[8192];
        snprintf(file, sizeof(file), "%s/.yamora-generations/%s/%s", data, id, YD_DISK_FILE);
        int dir = open(candidate, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        unsigned calls = 0;
        REQUIRE(dir >= 0 && file_digest(file, before) && yd_raft_snapshot_archive_manifest(image, manifest));
        YDRaftApplication *app = yd_raft_candidate_open_at(dir, manifest, config.cluster, 3, 32768,
            cancel_graph, &calls, error, sizeof(error));
        REQUIRE(!app && calls == 5 && file_digest(file, after) && !memcmp(before, after, sizeof(before)));
        app = yd_raft_candidate_open_at(dir, manifest, config.cluster, 3, 32768, NULL, NULL, error, sizeof(error));
        REQUIRE(app && !yd_disk_stats(yd_raft_application_disk(app)).bytes_written);
        yd_raft_application_close(app);
        close(dir);
        yd_raft_snapshot_archive_close(image);
        yd_raft_snapshot_store_close(store);
        yd_raft_application_close(old);
        yd_raft_application_close(sender);
        yd_raft_close(raft);
        puts("candidate=0 retry=1");
        return 0;
    }
    yd_raft_snapshot_archive_close(image);
    yd_raft_snapshot_store_close(store);
    YDRaftSnapshotOffer offer = {.from = 2, .term = 2, .base = {.index = 2, .term = 1}};
    memcpy(offer.cluster, config.cluster, 16);
    identity(id, offer.base.archive);
    bool needed;
    REQUIRE(yd_raft_snapshot_contact(raft, &offer, &needed) && needed &&
        yd_raft_snapshot_install(raft, &offer));
    yd_raft_application_close(old);
    yd_raft_application_close(sender);
    bool suffix = !strcmp(mode, "suffix") || !strcmp(mode, "checkpoint") || !strcmp(mode, "cancel-graph-suffix");
    if (suffix) {
        YDRaftApplication *app = yd_raft_application_open(candidate, config.cluster, 32768, error, sizeof(error));
        REQUIRE(app && yd_raft_campaign(raft, &vote));
        reply = (YDRaftVoteReply){.term = vote.term, .granted = true};
        REQUIRE(yd_raft_vote_reply(raft, 2, vote.term, &reply) && acknowledge(raft) &&
            yd_raft_entry(raft, 3, &entry) && yd_raft_application_apply(app, &entry, error, sizeof(error)));
        yd_raft_entry_free(&entry);
        REQUIRE(append_write(raft, app, true) && acknowledge(raft));
        if (!strcmp(mode, "checkpoint")) {
            char next[65];
            REQUIRE(archive(app, journal, config.cluster, next) && strcmp(id, next));
            YDRaftSnapshotBase base = {.index = 4, .term = vote.term};
            identity(next, base.archive);
            REQUIRE(yd_raft_checkpoint(raft, &base));
        }
        yd_raft_application_close(app);
    }
    uint64_t applied = suffix ? 4 : 2;
    YDRaftStatus before = yd_raft_status(raft);
    yd_raft_close(raft);
    char file[8192], saved[8192], marker[8192];
    snprintf(file, sizeof(file), "%s/.yamora-generations/%s/%s", data, id, YD_DISK_FILE);
    snprintf(marker, sizeof(marker), "%s/.yamora-generations/%s/.yamora-snapshot", data, id);
    snprintf(saved, sizeof(saved), "%s/saved", argv[1]);
    if (!strcmp(mode, "missing-parent")) REQUIRE(!rename(generations, saved));
    if (!strcmp(mode, "missing-child")) REQUIRE(!rename(candidate, saved));
    if (!strcmp(mode, "symlink-parent")) REQUIRE(!rename(generations, saved) && !symlink(saved, generations));
    if (!strcmp(mode, "symlink-child")) REQUIRE(!rename(candidate, saved) && !symlink(saved, candidate));
    if (!strcmp(mode, "permissions-parent")) REQUIRE(!chmod(generations, 0777));
    if (!strcmp(mode, "permissions-child")) REQUIRE(!chmod(candidate, 0777));
    if (!strcmp(mode, "missing-marker")) REQUIRE(!rename(marker, saved));
    if (!strcmp(mode, "symlink-marker")) REQUIRE(!rename(marker, saved) && !symlink(saved, marker));
    if (!strcmp(mode, "hardlink-marker")) REQUIRE(!link(marker, saved));
    if (!strcmp(mode, "permissions-marker")) REQUIRE(!chmod(marker, 0666));
    if (!strcmp(mode, "short-marker")) REQUIRE(!truncate(marker, 255));
    if (!strcmp(mode, "marker-hash")) {
        unsigned char manifest[256];
        int fd = open(marker, O_RDWR | O_CLOEXEC);
        REQUIRE(fd >= 0 && read(fd, manifest, sizeof(manifest)) == (ssize_t)sizeof(manifest));
        manifest[136] ^= 1; /* Structurally valid, different immutable image identity. */
        uint32_t crc = yd_disk_crc(manifest, 252);
        for (unsigned i = 0; i < 4; i++) manifest[252 + i] = (unsigned char)(crc >> (8 * i));
        REQUIRE(pwrite(fd, manifest, sizeof(manifest), 0) == (ssize_t)sizeof(manifest) && !fsync(fd));
        close(fd);
    }
    if (!strcmp(mode, "initializing") || !strcmp(mode, "pinned-failure")) {
        char pending[8192];
        snprintf(pending, sizeof(pending), "%s/.yamora-generations/%s/.yamora-initializing", data, id);
        int fd = open(pending, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
        REQUIRE(fd >= 0 && !fsync(fd)); close(fd);
    }
    if (!strcmp(mode, "missing-data")) REQUIRE(!rename(file, saved));
    if (!strcmp(mode, "uninitialized-data")) {
        char empty[8192], native[8192];
        snprintf(empty, sizeof(empty), "%s/empty", argv[1]);
        snprintf(native, sizeof(native), "%s/empty/%s", argv[1], YD_DISK_FILE);
        REQUIRE(!mkdir(empty, 0700));
        int directory = open(empty, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        REQUIRE(directory >= 0);
        YDRaftApplication *absent = yd_raft_application_open_existing_at(directory, config.cluster,
                                                                          32768, error, sizeof(error));
        close(directory);
        struct stat status;
        REQUIRE(!absent && lstat(native, &status) < 0 && errno == ENOENT);
        YDDisk *blank = yd_disk_open_cluster(empty, 32768, error, sizeof(error));
        REQUIRE(blank && yd_disk_view(blank).generation == 1);
        yd_disk_close(blank);
        REQUIRE(!rename(file, saved) && !rename(native, file));
    }
    if (!strcmp(mode, "symlink-data")) REQUIRE(!rename(file, saved) && !symlink(saved, file));
    if (!strcmp(mode, "permissions-data")) REQUIRE(!chmod(file, 0666));
    if (!strcmp(mode, "hardlink-data")) REQUIRE(!link(file, saved));
    if (!strcmp(mode, "corrupt-data")) {
        int fd = open(file, O_RDWR | O_CLOEXEC);
        unsigned char byte;
        REQUIRE(fd >= 0 && pread(fd, &byte, 1, 3U * YD_DISK_PAGE + 100U) == 1);
        byte ^= 1;
        REQUIRE(pwrite(fd, &byte, 1, 3U * YD_DISK_PAGE + 100U) == 1 && !fsync(fd)); close(fd);
    }
    if (!strcmp(mode, "missing-original") || !strcmp(mode, "corrupt-original")) {
        char original[8192];
        snprintf(original, sizeof(original), "%s/%s", data, YD_DISK_FILE);
        if (!strcmp(mode, "missing-original")) REQUIRE(!rename(original, saved));
        else {
            unsigned char zero[2U * YD_DISK_PAGE] = {0};
            int fd = open(original, O_RDWR | O_CLOEXEC);
            REQUIRE(fd >= 0 && pwrite(fd, zero, sizeof(zero), 0) == (ssize_t)sizeof(zero) && !fsync(fd)); close(fd);
        }
    }
    if (!strcmp(mode, "cancel-graph") || !strcmp(mode, "cancel-graph-suffix")) {
        unsigned char original[32], actual[32];
        unsigned calls = 0;
        int dir = open(data, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        raft = yd_raft_open(journal, config.cluster, 1, 3, 32768, error, sizeof(error));
        REQUIRE(dir >= 0 && raft && file_digest(file, original));
        YDRaftApplication *app = yd_raft_recover_open(dir, raft, 32768, cancel_graph, &calls, error, sizeof(error));
        REQUIRE(!app && calls == 5 && !yd_disk_stats(raft->disk).bytes_written &&
            file_digest(file, actual) && !memcmp(original, actual, sizeof(actual)));
        app = yd_raft_recover_open(dir, raft, 32768, NULL, NULL, error, sizeof(error));
        REQUIRE(app && yd_raft_application_position(app).index == applied &&
            !yd_disk_stats(yd_raft_application_disk(app)).bytes_written);
        yd_raft_application_close(app);
        close(dir);
        YDRaftStatus after = yd_raft_status(raft);
        REQUIRE(after.term == before.term && after.vote == before.vote && after.last == before.last &&
            after.committed == before.committed);
        yd_raft_close(raft);
        puts("accepted=0 retry=1 threads=0");
        return 0;
    }
    if (!strcmp(mode, "pinned") || !strcmp(mode, "cancel")) {
        bool cancelled = !strcmp(mode, "cancel");
        unsigned char original[32], actual[32];
        REQUIRE(file_digest(file, original));
        int directory = open(data, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        raft = yd_raft_open(journal, config.cluster, 1, 3, 32768, error, sizeof(error));
        REQUIRE(directory >= 0 && raft && !rename(data, saved) && !mkdir(data, 0700));
        YDRaftApplication *app = yd_raft_recover_open(directory, raft, 32768,
            cancelled ? cancel : NULL, NULL, error, sizeof(error));
        REQUIRE((app != NULL) == !cancelled && !yd_disk_stats(raft->disk).bytes_written);
        if (app) REQUIRE(yd_raft_application_position(app).index == 2 &&
            !yd_disk_stats(yd_raft_application_disk(app)).bytes_written);
        yd_raft_application_close(app);
        REQUIRE(!rmdir(data) && !rename(saved, data) && file_digest(file, actual) &&
            !memcmp(original, actual, sizeof(actual)));
        close(directory);
        YDRaftStatus after = yd_raft_status(raft);
        REQUIRE(after.term == before.term && after.vote == before.vote && after.last == before.last &&
            after.committed == before.committed);
        yd_raft_close(raft);
        printf("accepted=%u threads=0\n", !cancelled);
        return 0;
    }
    int root_owner = -1;
    bool pinned_start = !strcmp(mode, "pinned-start") || !strcmp(mode, "pinned-failure");
    if (!strcmp(mode, "locked-root") || pinned_start) {
        root_owner = open(data, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        REQUIRE(root_owner >= 0 && !flock(root_owner, LOCK_EX | LOCK_NB));
    }
    if (pinned_start) REQUIRE(!rename(data, saved) && !mkdir(data, 0700));
    YDTLS *tls = yd_tls_peer_new(cert, key, ca, error, sizeof(error));
    REQUIRE(tls);
    atomic_store(&observing, true);
    YDRaftCluster *cluster = pinned_start
        ? yd_raft_cluster_start_at(&config, root_owner, 32768, tls,
            (int)strtol(argv[3], NULL, 10), error, sizeof(error))
        : yd_raft_cluster_start(&config, data, 32768, tls,
            (int)strtol(argv[3], NULL, 10), error, sizeof(error));
    bool accepted = cluster != NULL;
    if (cluster) {
        REQUIRE(yd_raft_cluster_status(cluster).applied.index == applied);
        YDDisk *disk = yd_raft_cluster_disk(cluster);
        YDDiskView view = yd_disk_view(disk);
        YDDiskDocument doc;
        REQUIRE(yd_disk_document_get(disk, &view, "config", "node", &doc, error, sizeof(error)) == 1);
        const char *expected = suffix ? "count: 1 # exact\r\n" : "count: 0 # exact\r\n";
        REQUIRE(doc.length == 19 + strlen(expected) && !memcmp(doc.body, "# selected source\r\n", 19) &&
            !memcmp(doc.body + 19, expected, strlen(expected)));
        yd_disk_document_free(&doc);
    }
    int competing = -1;
    if (cluster && !strcmp(mode, "root-lifetime")) {
        competing = open(data, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        REQUIRE(competing >= 0 && flock(competing, LOCK_EX | LOCK_NB) < 0 &&
            (errno == EWOULDBLOCK || errno == EAGAIN));
    }
    yd_raft_cluster_close(cluster);
    if (competing >= 0) {
        REQUIRE(!flock(competing, LOCK_EX | LOCK_NB));
        close(competing);
    }
    if (pinned_start) {
        competing = open(saved, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        REQUIRE(competing >= 0 && flock(competing, LOCK_EX | LOCK_NB) < 0 &&
            (errno == EWOULDBLOCK || errno == EAGAIN));
        close(root_owner);
        root_owner = -1;
        REQUIRE(!flock(competing, LOCK_EX | LOCK_NB));
        close(competing);
        REQUIRE(!rmdir(data) && !rename(saved, data));
    }
    if (root_owner >= 0) close(root_owner);
    atomic_store(&observing, false);
    yd_tls_free(tls);
    raft = yd_raft_open(journal, config.cluster, 1, 3, 32768, error, sizeof(error));
    REQUIRE(raft);
    YDRaftStatus after = yd_raft_status(raft);
    unsigned char selected[32];
    yd_raft_application_generation(raft, selected);
    REQUIRE(after.term == before.term && after.vote == before.vote && after.last == before.last &&
        after.committed == before.committed && !memcmp(selected, offer.base.archive, 32));
    yd_raft_close(raft);
    if (!strcmp(mode, "missing-data")) {
        struct stat status;
        REQUIRE(lstat(file, &status) < 0 && errno == ENOENT);
    }
    if (!strcmp(mode, "uninitialized-data")) {
        YDDisk *blank = yd_disk_open_cluster(candidate, 32768, error, sizeof(error));
        REQUIRE(blank && yd_disk_view(blank).generation == 1 && !yd_disk_view(blank).root);
        yd_disk_close(blank);
    }
    printf("accepted=%u threads=%u\n", accepted, atomic_load(&starts));
    return 0;
}
