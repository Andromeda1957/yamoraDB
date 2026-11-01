#define _POSIX_C_SOURCE 200809L
#include "../src/consensus/cluster.h"
#include "../src/consensus/runtime_internal.h"
#include "../src/consensus/snapshot_store.h"
#include "../src/consensus/recovery.h"
#include "../src/consensus/raft_internal.h"
#include "../src/disk_internal.h"
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static char error[512];
static atomic_uint starts;
static atomic_bool observing;
static unsigned fail_thread;
int __real_pthread_create(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);
int __wrap_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                          void *(*function)(void *), void *argument) {
    if (atomic_load(&observing) && atomic_fetch_add(&starts, 1) + 1 == fail_thread)
        return EAGAIN;
    return __real_pthread_create(thread, attr, function, argument);
}
#define REQUIRE(x) do { if (!(x)) { \
    fprintf(stderr, "line %u: %s (%s)\n", __LINE__, #x, error); return 3; \
} } while (0)
static bool acknowledge(YDRaft *raft) {
    YDRaftAppend request;
    if (!yd_raft_append_request(raft, 2, &request)) return false;
    YDRaftAppendReply reply = {.term = request.term, .rpc = request.rpc, .accepted = true,
                               .matched = request.previous + request.has_entry};
    yd_raft_append_free(&request);
    return yd_raft_append_reply(raft, 2, &reply);
}
static bool check_ownership(void *context, YDRaft *raft, char *message, size_t length) {
    const YDRaftConfig *config = context;
    char locked[256];
    YDRaft *other = yd_raft_open(config->journal_root, config->cluster, 1, 3, 32768,
                                 locked, sizeof(locked));
    bool valid = !other && !atomic_load(&starts) &&
                 yd_raft_status(raft).role == YD_RAFT_FOLLOWER;
    yd_raft_close(other);
    snprintf(message, length, "%s", valid ? "checked recovery rejected while journal owned" :
                                              "checked recovery ownership failed");
    return false;
}
static bool checkpoint(YDRaft *raft, YDRaftApplication *app, const char *journal, bool wrong_term) {
    char directory[8192];
    snprintf(directory, sizeof(directory), "%s/.yamora-snapshots", journal);
    if (mkdir(directory, 0700) && errno != EEXIST) return false;
    const unsigned char identity[16] = {1, 2, 3, 4};
    YDRaftSnapshot *snapshot = yd_raft_snapshot_open(app, 3, error, sizeof(error));
    unsigned char manifest[256], bytes[4093];
    YDRaftSnapshotInfo info = {0};
    bool valid = snapshot && yd_raft_snapshot_seal(snapshot, NULL, NULL, error, sizeof(error)) &&
        yd_raft_snapshot_manifest(snapshot, manifest) &&
        yd_raft_snapshot_decode(manifest, sizeof(manifest), identity, 3, &info, error, sizeof(error));
    YDRaftCheckpoint expected = {.applied = info.applied};
    memcpy(expected.cluster, identity, 16);
    memcpy(expected.digest, info.entry_digest, 32);
    valid = valid && yd_raft_application_validate(app, &expected, &info.view, error, sizeof(error));
    YDRaftSnapshotStore *store = valid ? yd_raft_snapshot_store_open(directory, identity, 3,
                                                                    error, sizeof(error)) : NULL;
    YDRaftSnapshotStage *stage = store ? yd_raft_snapshot_stage_new(store, manifest, sizeof(manifest),
                                                                    error, sizeof(error)) : NULL;
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
    YDRaftSnapshotBase base = {.index = info.applied.index, .term = info.applied.term};
    /* Deliberately violate the caller's archive/boundary binding for one case. */
    if (wrong_term) base.term--;
    for (unsigned i = 0; valid && i < 32; i++) {
        char pair[3] = {id[2 * i], id[2 * i + 1], 0};
        base.archive[i] = (unsigned char)strtoul(pair, NULL, 16);
    }
    valid = valid && yd_raft_checkpoint(raft, &base);
    yd_raft_snapshot_stage_close(stage);
    yd_raft_snapshot_store_close(store);
    yd_raft_snapshot_close(snapshot);
    return valid;
}
static bool preserve_application(YDRaftApplication *app, const char *directory) {
    YDRaftCheckpoint position;
    YDDiskCheckpoint *image = yd_raft_application_checkpoint(app, &position, error, sizeof(error));
    char path[8192];
    snprintf(path, sizeof(path), "%s/%s", directory, YD_DISK_FILE);
    int file = open(path, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
    unsigned char bytes[4096];
    YDDiskView view = yd_disk_checkpoint_view(image);
    bool valid = image && file >= 0;
    for (uint64_t at = 0; valid && at < view.end;) {
        size_t size = view.end - at < sizeof(bytes) ? (size_t)(view.end - at) : sizeof(bytes);
        valid = yd_disk_checkpoint_read(image, at, bytes, size, error, sizeof(error)) &&
            write(file, bytes, size) == (ssize_t)size;
        at += size;
    }
    if (file >= 0) { valid = valid && !fsync(file); close(file); }
    yd_disk_checkpoint_close(image);
    return valid;
}
static bool cancel(void *context, uint64_t done, uint64_t total) {
    (void)context; (void)done; (void)total;
    return false;
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
    if (argc == 5 && !strcmp(argv[1], "checkpoint")) {
        const unsigned char identity[16] = {1, 2, 3, 4};
        YDRaftApplication *app = yd_raft_application_open(argv[3], identity, 32768,
                                                           error, sizeof(error));
        YDRaft *raft = yd_raft_open(argv[2], identity, (unsigned)strtoul(argv[4], NULL, 10), 3,
                                      32768, error, sizeof(error));
        REQUIRE(app && raft && checkpoint(raft, app, argv[2], false));
        printf("checkpoint=%llu\n", (unsigned long long)yd_raft_snapshot_base(raft).index);
        yd_raft_application_close(app);
        yd_raft_close(raft);
        return 0;
    }
    if (argc != 8) return 1;
    const char *mode = argv[7];
    char journal[4096], data[4096], fixture[4096], cert[4096], key[4096], ca[4096];
    snprintf(journal, sizeof(journal), "%s/journal", argv[1]);
    snprintf(data, sizeof(data), "%s/data", argv[1]);
    snprintf(fixture, sizeof(fixture), "%s/fixture", argv[1]);
    REQUIRE(!mkdir(journal, 0700) && !mkdir(data, 0700) && !mkdir(fixture, 0700));
    snprintf(cert, sizeof(cert), "%s/node1.pem", argv[2]);
    snprintf(key, sizeof(key), "%s/node1.key", argv[2]);
    snprintf(ca, sizeof(ca), "%s/trusted.pem", argv[2]);
    YDRaftConfig config = {.journal_root = journal, .cluster = {1, 2, 3, 4}, .node = 1, .voters = 3,
        .names = {NULL, "node1.test", "node2.test", "node3.test"},
        .addresses = {NULL, "127.0.0.1", "127.0.0.1", "127.0.0.1"},
        .timing = {.heartbeat_ms = 50, .election_min_ms = 600, .election_max_ms = 1100, .rpc_ms = 250},
        .cache_bytes = 32768, .command_bytes = 64U * 1024U * 1024U};
    for (unsigned i = 1; i <= 3; i++)
        config.ports[i] = (uint16_t)strtoul(argv[3 + i], NULL, 10);
    YDRaftApplication *app = yd_raft_application_open(!strcmp(mode, "empty") ? fixture : data,
        config.cluster, 32768, error, sizeof(error));
    YDRaft *raft = yd_raft_open(journal, config.cluster, 1, 3, 32768, error, sizeof(error));
    YDRaftVote vote;
    REQUIRE(app && raft && yd_raft_campaign(raft, &vote));
    YDRaftVoteReply voted = {.term = vote.term, .granted = true};
    REQUIRE(yd_raft_vote_reply(raft, 2, vote.term, &voted) && acknowledge(raft));
    YDRaftEntry entry;
    REQUIRE(yd_raft_entry(raft, 1, &entry));
    REQUIRE(yd_raft_application_apply(app, &entry, error, sizeof(error)));
    yd_raft_entry_free(&entry);
    if (strstr(mode, "snapshot-suffix") || !strcmp(mode, "snapshot-index"))
        REQUIRE(checkpoint(raft, app, journal, false));
    if (!strcmp(mode, "snapshot-lagging")) REQUIRE(preserve_application(app, fixture));
    const unsigned char source[] = "# startup fixture\ncount: 0 # exact\n";
    YDRaftWrite write = {.id = {1}, .method = "PUT", .target = "/v1/collections/config/documents/node",
                         .body = source, .size = sizeof(source) - 1};
    YDRaftProposal proposal;
    REQUIRE(yd_raft_application_prepare(app, &write, &proposal, error, sizeof(error)) == 1);
    uint64_t index;
    REQUIRE(yd_raft_propose(raft, proposal.command, proposal.size, &index) && index == 2);
    yd_raft_proposal_free(&proposal);
    if (strcmp(mode, "ahead")) REQUIRE(acknowledge(raft));
    REQUIRE(yd_raft_entry(raft, 2, &entry));
    if (!strcmp(mode, "digest") || !strcmp(mode, "snapshot-suffix-digest")) {
        const unsigned char other[] = "# alternate valid history\ncount: 7\n";
        write.body = other;
        write.size = sizeof(other) - 1;
        REQUIRE(yd_raft_application_prepare(app, &write, &proposal, error, sizeof(error)) == 1);
        YDRaftEntry alternate = {.index = 2, .term = entry.term, .kind = YD_RAFT_COMMAND,
                                  .command = proposal.command, .size = proposal.size};
        REQUIRE(yd_raft_application_apply(app, &alternate, error, sizeof(error)));
        yd_raft_proposal_free(&proposal);
    } else if (strcmp(mode, "behind")) {
        if (!strcmp(mode, "term") || !strcmp(mode, "snapshot-term")) entry.term++;
        REQUIRE(yd_raft_application_apply(app, &entry, error, sizeof(error)));
    }
    yd_raft_entry_free(&entry);
    if (!strncmp(mode, "snapshot", 8) && !strstr(mode, "suffix") && strcmp(mode, "snapshot-index"))
        REQUIRE(checkpoint(raft, app, journal, !strcmp(mode, "snapshot-term")));
    if (!strcmp(mode, "snapshot-index")) {
        YDRaftSnapshotBase base = yd_raft_snapshot_base(raft);
        base.index = 2; /* Valid core term/index, wrong immutable archive position. */
        REQUIRE(yd_raft_checkpoint(raft, &base));
    }
    if (!strcmp(mode, "snapshot-physical")) {
        unsigned char byte;
        int fd = yd_raft_application_disk(app)->fd;
        REQUIRE(pread(fd, &byte, 1, 3U * YD_DISK_PAGE + 100U) == 1);
        byte ^= 1; /* Unreachable genesis page; live native graph remains valid. */
        REQUIRE(pwrite(fd, &byte, 1, 3U * YD_DISK_PAGE + 100U) == 1 && !fsync(fd));
    }
    if (!strcmp(mode, "snapshot-suffix-native")) {
        YDDisk *disk = yd_raft_application_disk(app);
        YDDiskView view = yd_disk_view(disk);
        unsigned char receipt[20] = {0, 'Y', 'R', 'R', 1}, byte;
        uint64_t offset;
        REQUIRE(yd_disk_get(disk, &view, receipt, sizeof(receipt), &offset, error, sizeof(error)) == 1);
        REQUIRE(pread(disk->fd, &byte, 1, (off_t)(offset + 16)) == 1);
        byte ^= 1;
        REQUIRE(pwrite(disk->fd, &byte, 1, (off_t)(offset + 16)) == 1 && !fsync(disk->fd));
    }
    char directory[8192], saved[8192], diskfile[8192], previous[8192];
    snprintf(directory, sizeof(directory), "%s/.yamora-snapshots", journal);
    snprintf(saved, sizeof(saved), "%s/archive-saved", argv[1]);
    if (!strcmp(mode, "snapshot-missing")) REQUIRE(!rename(directory, saved));
    if (!strcmp(mode, "snapshot-symlink"))
        REQUIRE(!rename(directory, saved) && !symlink(saved, directory));
    if (!strcmp(mode, "snapshot-permissions")) REQUIRE(!chmod(directory, 0777));
    if (!strcmp(mode, "snapshot-corrupt")) {
        YDRaftSnapshotBase base = yd_raft_snapshot_base(raft);
        char id[65];
        static const char hex[] = "0123456789abcdef";
        for (unsigned i = 0; i < 32; i++) {
            id[2 * i] = hex[base.archive[i] >> 4];
            id[2 * i + 1] = hex[base.archive[i] & 15];
        }
        id[64] = 0;
        snprintf(diskfile, sizeof(diskfile), "%s/.yamora-snapshots/%s.snapshot", journal, id);
        REQUIRE(!chmod(diskfile, 0600));
        int fd = open(diskfile, O_RDWR | O_CLOEXEC);
        unsigned char byte;
        REQUIRE(fd >= 0 && pread(fd, &byte, 1, 256 + 3U * YD_DISK_PAGE + 100U) == 1);
        byte ^= 1;
        REQUIRE(pwrite(fd, &byte, 1, 256 + 3U * YD_DISK_PAGE + 100U) == 1 && !fsync(fd));
        close(fd);
        REQUIRE(!chmod(diskfile, 0400));
    }
    YDRaftStatus before = yd_raft_status(raft);
    yd_raft_application_close(app);
    yd_raft_close(raft);
    if (!strcmp(mode, "snapshot-lagging")) {
        snprintf(diskfile, sizeof(diskfile), "%s/%s", data, YD_DISK_FILE);
        snprintf(previous, sizeof(previous), "%s/%s", fixture, YD_DISK_FILE);
        REQUIRE(!rename(previous, diskfile));
    }
    if (!strcmp(mode, "snapshot-pinned") || !strcmp(mode, "snapshot-cancel")) {
        raft = yd_raft_open(journal, config.cluster, 1, 3, 32768, error, sizeof(error));
        app = yd_raft_application_open(data, config.cluster, 32768, error, sizeof(error));
        REQUIRE(raft && app);
        YDDisk *disk = yd_raft_application_disk(app);
        YDDiskStats a = yd_disk_stats(disk), b = yd_disk_stats(raft->disk);
        bool cancelled = !strcmp(mode, "snapshot-cancel");
        if (!cancelled) {
            snprintf(saved, sizeof(saved), "%s/journal-saved", argv[1]);
            REQUIRE(!rename(journal, saved) && !mkdir(journal, 0700));
        }
        bool recovered = yd_raft_recover_application(app, raft, cancelled ? cancel : NULL, NULL,
                                                       error, sizeof(error));
        REQUIRE(recovered == !cancelled && yd_disk_stats(disk).bytes_written == a.bytes_written &&
            yd_disk_stats(raft->disk).bytes_written == b.bytes_written);
        yd_raft_application_close(app);
        yd_raft_close(raft);
        if (cancelled) {
            puts("accepted=0 threads=0");
            return 0;
        }
        REQUIRE(!rmdir(journal) && !rename(saved, journal));
    }
    YDTLS *tls = yd_tls_peer_new(cert, key, ca, error, sizeof(error));
    REQUIRE(tls);
    if (!strncmp(mode, "thread", 6)) fail_thread = (unsigned)strtoul(mode + 6, NULL, 10);
    atomic_store(&observing, true);
    YDRaftCluster *cluster = NULL;
    if (!strcmp(mode, "ownership")) {
        YDRaftRuntime *runtime = yd_raft_runtime_start_checked(&config, tls,
            (int)strtol(argv[3], NULL, 10), check_ownership, &config, error, sizeof(error));
        REQUIRE(!runtime && !strcmp(error, "checked recovery rejected while journal owned"));
    } else
        cluster = yd_raft_cluster_start(&config, data, 32768, tls,
            (int)strtol(argv[3], NULL, 10), error, sizeof(error));
    bool accepted = cluster != NULL;
    if (cluster) {
        /* Existing committed suffixes replay without a new election. */
        for (unsigned attempt = 0; attempt < 1000; attempt++) {
            if (yd_raft_cluster_status(cluster).applied.index == 2) break;
            struct timespec delay = {.tv_nsec = 1000000};
            nanosleep(&delay, NULL);
        }
        REQUIRE(yd_raft_cluster_status(cluster).applied.index == 2);
    }
    yd_raft_cluster_close(cluster);
    atomic_store(&observing, false);
    yd_tls_free(tls);
    /* Both failure and success release exactly the same journal ownership. */
    raft = yd_raft_open(journal, config.cluster, 1, 3, 32768, error, sizeof(error));
    REQUIRE(raft);
    YDRaftStatus after = yd_raft_status(raft);
    REQUIRE(after.term == before.term && after.vote == before.vote &&
        after.last == before.last && after.committed == before.committed);
    yd_raft_close(raft);
    printf("accepted=%u threads=%u\n", accepted, atomic_load(&starts));
    return 0;
}
