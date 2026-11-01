#define _POSIX_C_SOURCE 200809L
#include "../src/consensus/backup.h"
#include "../src/consensus/cluster.h"
#include "../src/consensus/cluster_internal.h"
#include "../src/consensus/journal_compact.h"
#include "../src/consensus/runtime_internal.h"
#include "../src/consensus/snapshot_send.h"
#include "../src/consensus/snapshot_store.h"
#include "../src/consensus/snapshot_store_internal.h"
#include "../src/disk_internal.h"
#include "raft_cluster_application_fixture.h"
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
static const unsigned char source[] = "# exact cluster source\r\ncount: 0 # keep\r\n";
static const unsigned char patch[] = "{\"$inc\":{\"count\":1}}";
static const char path[] = "/v1/collections/config/documents/node";
static unsigned local_node;
static dev_t journal_device;
static ino_t journal_inode;
static _Thread_local unsigned sync_failure, sync_calls;
static _Thread_local bool supersede_checkpoint;
static atomic_bool hold_install, install_entered;
static atomic_bool hold_application, application_entered;
static atomic_bool hold_before_fetch, backup_fetch_returned, backup_fetch_missing;
static atomic_uint_fast64_t backup_fetch_index;
static atomic_bool fail_install_thread;
static atomic_bool slow_install_io;
static atomic_bool archive_entered, job_finished, job_success;
static atomic_bool hold_archive_once, hold_archive, archive_paused;
static atomic_uint hold_dequeue_peer, snapshot_queued_peer;
static atomic_bool dequeue_paused, close_requested;
static _Thread_local unsigned outbound_peer;
static _Thread_local bool reconfiguration_caller;
static atomic_bool reconfiguration_waiting;
static pthread_t cancellation_writer;
static bool cancellation_writer_started;
typedef struct { YDRaftCluster *cluster; unsigned timeout; } CancelConfiguration;
static CancelConfiguration cancellation_configuration;
int __real_pthread_cond_timedwait(pthread_cond_t *, pthread_mutex_t *, const struct timespec *);
int __wrap_pthread_cond_timedwait(pthread_cond_t *condition, pthread_mutex_t *mutex,
    const struct timespec *until) {
    if (reconfiguration_caller) atomic_store(&reconfiguration_waiting, true);
    return __real_pthread_cond_timedwait(condition, mutex, until);
}
static void *cancel_configuration(void *context) {
    CancelConfiguration *request = context;
    YDRaftMembership membership;
    reconfiguration_caller = true;
    (void)yd_raft_cluster_reconfigure(request->cluster, 14, request->timeout, &membership);
    return NULL;
}
bool __real_yd_raft_member_snapshot_begin(YDRaftMember *, uint64_t, unsigned, YDRaftSnapshotRequest *);
bool __wrap_yd_raft_member_snapshot_begin(YDRaftMember *member, uint64_t now, unsigned peer,
    YDRaftSnapshotRequest *request) {
    bool valid = __real_yd_raft_member_snapshot_begin(member, now, peer, request);
    if (valid && peer == atomic_load(&hold_dequeue_peer)) atomic_store(&snapshot_queued_peer, peer);
    return valid;
}
int __real_pthread_cond_wait(pthread_cond_t *, pthread_mutex_t *);
int __wrap_pthread_cond_wait(pthread_cond_t *condition, pthread_mutex_t *mutex) {
    int result = __real_pthread_cond_wait(condition, mutex);
    if (!result && outbound_peer && outbound_peer == atomic_load(&hold_dequeue_peer) &&
        outbound_peer == atomic_load(&snapshot_queued_peer)) {
        /* The worker has reacquired runtime serialization but has not returned
         * to its dequeue loop. Release it during the test pause so the timer,
         * status, writers and checkpoint B remain live. */
        pthread_mutex_unlock(mutex);
        atomic_store(&dequeue_paused, true);
        while (atomic_load(&hold_dequeue_peer) && !atomic_load(&close_requested)) {
            struct timespec delay = {.tv_nsec = 1000000}; nanosleep(&delay, NULL);
        }
        pthread_mutex_lock(mutex);
    }
    return result;
}
static _Thread_local bool delay_archive;
static atomic_bool hold_sender, sender_entered, sender_finished;
static atomic_bool lose_send_reply, lost_send_reply;
static atomic_uint_fast64_t resumed_send_offset;
static atomic_size_t sending_bytes, sending_peak;
static atomic_bool hold_policy_capture, policy_capture_entered;
static atomic_uint policy_fail_sync;
static atomic_uint hold_compaction, compaction_entered, compaction_fault;
static _Thread_local bool compaction_fail_sync;
typedef struct {
    YDRaftJournalCompactionProgress progress;
    void *context;
    unsigned fault;
} CompactionProxy;
static bool compaction_progress(void *context, YDRaftJournalCompactionPhase phase,
                               uint64_t done, uint64_t total) {
    CompactionProxy *p = context;
    if (atomic_load(&hold_compaction) == (unsigned)phase) {
        atomic_store(&compaction_entered, (unsigned)phase);
        while (atomic_load(&hold_compaction) == (unsigned)phase) {
            if (!p->progress(p->context, phase, done, total)) return false;
            struct timespec delay = {.tv_nsec = 1000000}; nanosleep(&delay, NULL);
        }
    }
    if (phase == YD_RAFT_COMPACT_SELECT && p->fault == 1) compaction_fail_sync = true;
    if (phase == YD_RAFT_COMPACT_RETIRE && p->fault == 2) return false;
    return p->progress(p->context, phase, done, total);
}
YDRaftJournalCompaction __real_yd_raft_journal_compact(YDRaftRuntime *, YDRaftJournalCompactionOptions,
    YDRaftJournalCompactionProgress, void *, char *, size_t);
YDRaftJournalCompaction __wrap_yd_raft_journal_compact(YDRaftRuntime *runtime,
    YDRaftJournalCompactionOptions options, YDRaftJournalCompactionProgress progress,
    void *context, char *error, size_t length) {
    CompactionProxy proxy = {.progress = progress, .context = context,
                            .fault = atomic_exchange(&compaction_fault, 0)};
    YDRaftJournalCompaction result = __real_yd_raft_journal_compact(runtime, options,
        compaction_progress, &proxy, error, length);
    compaction_fail_sync = false;
    return result;
}
typedef struct { YDRaftSnapshotProgress progress; void *context; } PolicyCapture;
static bool policy_capture_progress(void *context, uint64_t done, uint64_t total) {
    PolicyCapture *p = context;
    atomic_store(&policy_capture_entered, true);
    while (atomic_load(&hold_policy_capture)) {
        if (!p->progress(p->context, done, total)) return false;
        struct timespec delay = {.tv_nsec = 1000000}; nanosleep(&delay, NULL);
    }
    return p->progress(p->context, done, total);
}
YDRaftCapture *__real_yd_raft_cluster_capture(YDRaftCluster *, unsigned, YDRaftSnapshotProgress, void *, char *, size_t);
YDRaftCapture *__wrap_yd_raft_cluster_capture(YDRaftCluster *cluster, unsigned timeout,
    YDRaftSnapshotProgress progress, void *context, char *error, size_t length) {
    PolicyCapture p = {.progress = progress, .context = context};
    bool hold = progress && atomic_load(&hold_policy_capture);
    return __real_yd_raft_cluster_capture(cluster, timeout, hold ? policy_capture_progress : progress,
        hold ? &p : context, error, length);
}
typedef struct { YDRaftSnapshotSendHooks hooks; } SenderProxy;
static bool sender_current(void *ctx) {
    SenderProxy *p = ctx; return p->hooks.current(p->hooks.context);
}
static bool sender_exchange(void *ctx, const YDRaftPacket *request, YDRaftPacket *reply) {
    SenderProxy *p = ctx; return p->hooks.exchange(p->hooks.context, request, reply);
}
static bool sender_pause(void *ctx) {
    SenderProxy *p = ctx; return p->hooks.pause(p->hooks.context);
}
static bool sender_reserve(void *ctx, size_t size) {
    SenderProxy *p = ctx;
    if (!p->hooks.reserve(p->hooks.context, size)) return false;
    size_t bytes = atomic_fetch_add(&sending_bytes, size) + size, peak = atomic_load(&sending_peak);
    while (bytes > peak && !atomic_compare_exchange_weak(&sending_peak, &peak, bytes)) { }
    return true;
}
static void sender_release(void *ctx, size_t size) {
    SenderProxy *p = ctx;
    atomic_fetch_sub(&sending_bytes, size);
    p->hooks.release(p->hooks.context, size);
}
bool __real_yd_raft_snapshot_send(const YDRaftSnapshotArchive *, const YDRaftSnapshotRequest *, unsigned,
    size_t, YDRaftSnapshotSendHooks, YDRaftSnapshotReply *, char *, size_t);
bool __wrap_yd_raft_snapshot_send(const YDRaftSnapshotArchive *archive, const YDRaftSnapshotRequest *request,
    unsigned voters, size_t chunk, YDRaftSnapshotSendHooks hooks, YDRaftSnapshotReply *reply, char *error, size_t length) {
    atomic_store(&sender_entered, true); atomic_store(&sender_finished, false);
    while (atomic_load(&hold_sender)) {
        if (!hooks.current(hooks.context)) {
            memset(reply, 0, sizeof(*reply)); atomic_store(&sender_finished, true); return false;
        }
        struct timespec delay = {.tv_nsec = 1000000}; nanosleep(&delay, NULL);
    }
    SenderProxy proxy = {.hooks = hooks};
    YDRaftSnapshotSendHooks counted = {.context = &proxy, .current = sender_current, .exchange = sender_exchange,
        .pause = sender_pause, .reserve = sender_reserve, .release = sender_release};
    bool valid = __real_yd_raft_snapshot_send(archive, request, voters, chunk, counted, reply, error, length);
    atomic_store(&sender_finished, true);
    return valid;
}
bool __real_yd_raft_rpc_call(YDRaftRPC *, int, const YDRaftPacket *, YDRaftPacket *, int);
bool __wrap_yd_raft_rpc_call(YDRaftRPC *rpc, int fd, const YDRaftPacket *request, YDRaftPacket *reply, int timeout) {
    outbound_peer = request->to;
    bool valid = __real_yd_raft_rpc_call(rpc, fd, request, reply, timeout);
    if (valid && request->kind == YD_RPC_SNAPSHOT_BEGIN && reply->body.snapshot.accepted && reply->body.snapshot.offset)
        atomic_store(&resumed_send_offset, reply->body.snapshot.offset);
    if (valid && request->kind == YD_RPC_SNAPSHOT_CHUNK && atomic_exchange(&lose_send_reply, false)) {
        atomic_store(&lost_send_reply, true);
        return false;
    }
    return valid;
}
static void before_archive_open(YDRaftSnapshotProgress progress, void *context) {
    if (atomic_exchange(&hold_archive_once, false)) {
        atomic_store(&archive_paused, true);
        while (atomic_load(&hold_archive) && (!progress || progress(context, 0, 0))) {
            struct timespec delay = {.tv_nsec = 1000000}; nanosleep(&delay, NULL);
        }
    }
    if (delay_archive) {
        delay_archive = false;
        atomic_store(&archive_entered, true);
        struct timespec delay = {.tv_nsec = 600000000};
        while (nanosleep(&delay, &delay) && errno == EINTR) { }
    }
}
YDRaftSnapshotArchive *__real_yd_raft_snapshot_archive_open(const YDRaftSnapshotStore *, const char *, YDRaftSnapshotProgress, void *, char *, size_t);
YDRaftSnapshotArchive *__wrap_yd_raft_snapshot_archive_open(const YDRaftSnapshotStore *store, const char *id,
    YDRaftSnapshotProgress progress, void *context, char *error, size_t length) {
    before_archive_open(progress, context);
    return __real_yd_raft_snapshot_archive_open(store, id, progress, context, error, length);
}
YDRaftArchiveResult __real_yd_raft_snapshot_archive_open_reference(const YDRaftSnapshotReference *,
    YDRaftSnapshotProgress, void *, YDRaftSnapshotArchive **, char *, size_t);
YDRaftArchiveResult __wrap_yd_raft_snapshot_archive_open_reference(const YDRaftSnapshotReference *reference,
    YDRaftSnapshotProgress progress, void *context, YDRaftSnapshotArchive **archive, char *error, size_t length) {
    before_archive_open(progress, context);
    return __real_yd_raft_snapshot_archive_open_reference(reference, progress, context, archive, error, length);
}
int __real_pthread_create(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);
int __wrap_pthread_create(pthread_t *thread, const pthread_attr_t *attributes, void *(*function)(void *), void *context) {
    if (atomic_exchange(&fail_install_thread, false)) return EAGAIN;
    return __real_pthread_create(thread, attributes, function, context);
}
bool __real_yd_raft_runtime_entry(YDRaftRuntime *, uint64_t, YDRaftEntry *);
bool __wrap_yd_raft_runtime_entry(YDRaftRuntime *runtime, uint64_t index, YDRaftEntry *entry) {
    /* Let the real application loop capture `after`, then let controller backup
     * drain and checkpoint that prefix before the actual native fetch. */
    bool before = atomic_exchange(&hold_before_fetch, false);
    if (before) {
        atomic_store(&backup_fetch_index, index);
        atomic_store(&application_entered, true);
        while (atomic_load(&hold_application)) {
            struct timespec delay = {.tv_nsec = 1000000};
            nanosleep(&delay, NULL);
        }
    }
    bool valid = __real_yd_raft_runtime_entry(runtime, index, entry);
    if (before) {
        atomic_store(&backup_fetch_missing, !valid);
        atomic_store(&backup_fetch_returned, true);
    } else if (atomic_load(&hold_application)) {
        atomic_store(&application_entered, true);
        while (atomic_load(&hold_application)) {
            struct timespec delay = {.tv_nsec = 1000000}; nanosleep(&delay, NULL);
        }
    }
    return valid;
}
bool __real_yd_raft_cluster_snapshot_install(YDRaftCluster *, const YDRaftSnapshotOffer *, unsigned, char *, size_t);
static bool wait_install(YDRaftCluster *cluster) {
    if (atomic_load(&hold_install)) {
        atomic_store(&install_entered, true);
        while (atomic_load(&hold_install)) {
            if (yd_raft_cluster_status(cluster).failed) return false;
            struct timespec delay = {.tv_nsec = 1000000};
            nanosleep(&delay, NULL);
        }
    }
    return true;
}
bool __wrap_yd_raft_cluster_snapshot_install(YDRaftCluster *cluster, const YDRaftSnapshotOffer *offer,
                                               unsigned timeout, char *error, size_t length) {
    return wait_install(cluster) && __real_yd_raft_cluster_snapshot_install(cluster, offer, timeout, error, length);
}
bool __real_yd_raft_cluster_snapshot_job(YDRaftCluster *, const YDRaftSnapshotOffer *, unsigned, char *, size_t);
bool __wrap_yd_raft_cluster_snapshot_job(YDRaftCluster *cluster, const YDRaftSnapshotOffer *offer,
                                           unsigned timeout, char *error, size_t length) {
    if (!wait_install(cluster)) return false;
    bool slow = atomic_load(&slow_install_io);
    atomic_store(&job_finished, false);
    delay_archive = slow;
    bool valid = __real_yd_raft_cluster_snapshot_job(cluster, offer, slow ? 250 : timeout, error, length);
    delay_archive = false;
    atomic_store(&job_success, valid); atomic_store(&job_finished, true);
    return valid;
}
bool __real_yd_raft_cluster_snapshot_job_reference(YDRaftCluster *, const YDRaftSnapshotOffer *,
    const YDRaftSnapshotReference *, unsigned, char *, size_t);
bool __wrap_yd_raft_cluster_snapshot_job_reference(YDRaftCluster *cluster, const YDRaftSnapshotOffer *offer,
    const YDRaftSnapshotReference *reference, unsigned timeout, char *error, size_t length) {
    if (!wait_install(cluster)) return false;
    bool slow = atomic_load(&slow_install_io);
    atomic_store(&job_finished, false);
    delay_archive = slow;
    bool valid = __real_yd_raft_cluster_snapshot_job_reference(cluster, offer, reference,
        slow ? 250 : timeout, error, length);
    delay_archive = false;
    atomic_store(&job_success, valid); atomic_store(&job_finished, true);
    return valid;
}
int __real_fsync(int fd);
int __wrap_fsync(int fd) {
    if (yd_test_application_sync()) return -1;
    if (compaction_fail_sync) { compaction_fail_sync = false; errno = EIO; return -1; }
    struct stat status;
    if (sync_failure && !fstat(fd, &status) && status.st_dev == journal_device &&
        status.st_ino == journal_inode && ++sync_calls == sync_failure) {
        errno = EIO;
        return -1;
    }
    return __real_fsync(fd);
}
bool __real_yd_raft_runtime_checkpoint(YDRaftRuntime *, uint64_t, const YDRaftSnapshotBase *);
bool __wrap_yd_raft_runtime_checkpoint(YDRaftRuntime *runtime, uint64_t term,
                                         const YDRaftSnapshotBase *base) {
    if (supersede_checkpoint) {
        supersede_checkpoint = false;
        YDRaftSnapshotOffer offer = {.cluster = {1, 2, 3, 4}, .from = local_node % 3 + 1,
            .term = term + 1, .base = *base};
        bool needed;
        if (!yd_raft_runtime_snapshot_contact(runtime, &offer, &needed) || needed)
            return false;
    }
    unsigned fault = atomic_exchange(&policy_fail_sync, 0), prior = sync_failure, prior_calls = sync_calls;
    if (fault) { sync_failure = fault; sync_calls = 0; }
    bool valid = __real_yd_raft_runtime_checkpoint(runtime, term, base);
    if (fault) { sync_failure = prior; sync_calls = prior_calls; }
    return valid;
}
static YDDiskReply write_request(YDRaftCluster *c, unsigned id, bool increment, unsigned timeout) {
    YDRaftWrite w = {.id = {0},
                     .method = increment ? "PATCH" : "PUT",
                     .target = path,
                     .body = increment ? patch : source,
                     .size = increment ? sizeof(patch) - 1 : sizeof(source) - 1};
    w.id[0] = (unsigned char)id;
    return yd_raft_cluster_write(c, &w, timeout);
}
static void *cancellation_write(void *context) {
    CancelConfiguration *request = context;
    YDDiskReply reply = write_request(request->cluster, 2, true, request->timeout);
    yd_disk_reply_free(&reply);
    return NULL;
}
static bool cancellation_wait(atomic_bool *entered) {
    for (unsigned i = 0; i < 5000 && !atomic_load(entered); i++) {
        struct timespec delay = {.tv_nsec = 1000000}; nanosleep(&delay, NULL);
    }
    return atomic_load(entered);
}
typedef struct {
    YDRaftCluster *cluster;
    unsigned thread, timeout;
    bool valid;
} Concurrent;
static void *concurrent(void *context) {
    Concurrent *state = context;
    state->valid = true;
    for (unsigned i = 0; i < 5; i++) {
        YDDiskReply reply =
            write_request(state->cluster, 100 + state->thread * 5 + i, true, state->timeout);
        if (reply.status != 200)
            fprintf(stderr, "concurrent failure thread=%u operation=%u status=%d\n", state->thread,
                    i, reply.status);
        state->valid &= reply.status == 200;
        yd_disk_reply_free(&reply);
    }
    return NULL;
}
typedef struct {
    YDRaftView *view;
    atomic_bool *ready;
    bool valid;
} Reader;
typedef struct {
    YDRaftCluster *cluster;
    unsigned timeout;
    bool wrote, valid;
} CaptureWriter;
static bool capture_write(void *context, uint64_t done, uint64_t total) {
    (void)done; (void)total;
    CaptureWriter *writer = context;
    if (!writer->wrote) {
        writer->wrote = true;
        YDDiskReply reply = write_request(writer->cluster, 3, true, writer->timeout);
        writer->valid = reply.status == 200;
        yd_disk_reply_free(&reply);
    }
    return writer->valid;
}
static bool capture_cancel(void *context, uint64_t done, uint64_t total) {
    (void)context; (void)done; (void)total;
    return false;
}
static void *read_closed(void *context) {
    Reader *reader = context;
    while (!atomic_load(reader->ready)) {
        struct timespec delay = {.tv_nsec = 1000000};
        nanosleep(&delay, NULL);
    }
    reader->valid = true;
    YDDisk *disk = yd_raft_view_disk(reader->view);
    YDDiskView view = yd_raft_view_value(reader->view);
    char error[512];
    for (unsigned i = 0; i < 100 && reader->valid; i++) {
        YDDiskDocument doc;
        reader->valid = yd_disk_document_get(disk, &view, "config", "node", &doc, error,
                                               sizeof(error)) == 1 &&
            doc.length == sizeof(source) - 1 && !memcmp(doc.body, source, sizeof(source) - 1);
        yd_disk_document_free(&doc);
    }
    yd_raft_view_close(reader->view);
    return NULL;
}
int main(int argc, char **argv) {
    if (argc != 8 && argc != 9)
        return 1;
    unsigned node = (unsigned)strtoul(argv[3], NULL, 10);
    if (!node || node > 3)
        return 1;
    char cert[4096], key[4096], ca[4096], journal[4096], data[4096], error[512] = {0};
    snprintf(cert, sizeof(cert), "%s/node%u.pem", argv[2], node);
    snprintf(key, sizeof(key), "%s/node%u.key", argv[2], node);
    snprintf(ca, sizeof(ca), "%s/trusted.pem", argv[2]);
    snprintf(journal, sizeof(journal), "%s/journal", argv[1]);
    snprintf(data, sizeof(data), "%s/data", argv[1]);
    if ((mkdir(journal, 0700) && errno != EEXIST) || (mkdir(data, 0700) && errno != EEXIST))
        return 1;
    YDTLS *tls = yd_tls_peer_new(cert, key, ca, error, sizeof(error));
    if (!tls) {
        fprintf(stderr, "%s\n", error);
        return 2;
    }
    YDRaftConfig config = {.journal_root = journal,
                           .cluster = {1, 2, 3, 4},
                           .node = node,
                           .voters = 3,
                           .names = {NULL, "node1.test", "node2.test", "node3.test"},
                           .addresses = {NULL, "127.0.0.1", "127.0.0.1", "127.0.0.1"},
                           .timing = {.heartbeat_ms = 50,
                                      .election_min_ms = 600,
                                      .election_max_ms = 1100,
                                      .rpc_ms = 250},
                           .cache_bytes = 32768,
                           .command_bytes = 64U * 1024U * 1024U};
    for (unsigned i = 1; i <= 3; i++)
        config.ports[i] = (uint16_t)strtoul(argv[4 + i], NULL, 10);
    const char *slow = getenv("YAMORA_RAFT_TEST_SLOW");
    const char *small = getenv("YAMORA_RAFT_TEST_SMALL_BUDGET");
    if (small && !strcmp(small, "1")) config.command_bytes = 1024;
    unsigned timeout = slow && !strcmp(slow, "1") ? 12000 : 3000;
    if (timeout == 12000)
        config.timing = (YDRaftTiming){
            .heartbeat_ms = 100, .election_min_ms = 5000, .election_max_ms = 8000, .rpc_ms = 2000};
    if (argc == 9 && !strcmp(argv[8], "same-root"))
        config.journal_root = data;
    int listener = (int)strtol(argv[4], NULL, 10);
    YDRaftCluster *cluster =
        yd_raft_cluster_start(&config, data, 32768, tls, listener, error, sizeof(error));
    if (!cluster) {
        fprintf(stderr, "cluster start failed: %s\n", error);
        yd_tls_free(tls);
        return 2;
    }
    puts("ready");
    fflush(stdout);
    local_node = node;
    char native[8192];
    struct stat native_status;
    snprintf(native, sizeof(native), "%s/.yamora-disk", journal);
    if (stat(native, &native_status)) return 3;
    journal_device = native_status.st_dev;
    journal_inode = native_status.st_ino;
    YDRaftView *pinned = NULL;
    YDRaftCapture *captured = NULL;
    ApplicationFixture *app_fixture = yd_test_application_new(cluster, data, timeout);
    if (!app_fixture) return 3;
    char line[256];
    while (fgets(line, sizeof(line), stdin)) {
        size_t n = strlen(line);
        if (!n || line[n - 1] != '\n')
            break;
        line[--n] = 0;
        if (yd_test_application_command(app_fixture, line)) {
            /* Fixture methods own their asynchronous calls and diagnostic image. */
        } else if (!strcmp(line, "status")) {
            YDRaftClusterStatus s = yd_raft_cluster_status(cluster);
            printf("status %u %u %llu %llu %llu %llu %u\n", s.raft.role, s.raft.leader,
                   (unsigned long long)s.raft.term, (unsigned long long)s.raft.last,
                   (unsigned long long)s.raft.committed, (unsigned long long)s.applied.index,
                   s.failed);
        } else if (!strncmp(line, "auto-compact ", 13)) {
            unsigned long long minimum = 0, saved = 0;
            unsigned interval = 0, attempts = 0;
            bool valid = sscanf(line + 13, "%llu %llu %u %u", &minimum, &saved, &interval, &attempts) == 4 &&
                yd_raft_cluster_compactions(cluster, (YDRaftCompactionPolicy){minimum, saved, interval, attempts});
            printf("auto %u\n", valid);
        } else if (!strcmp(line, "compaction-state")) {
            YDRaftCompactionStatus s = yd_raft_cluster_status(cluster).compaction;
            printf("compaction %u %u %llu %llu %llu %llu %llu %llu %llu %d\n", s.enabled, s.running,
                (unsigned long long)s.attempted, (unsigned long long)s.succeeded,
                (unsigned long long)s.skipped, (unsigned long long)s.stale,
                (unsigned long long)s.failed, (unsigned long long)s.source_bytes,
                (unsigned long long)s.candidate_bytes, s.last_result);
        } else if (!strncmp(line, "hold-auto-compact ", 18)) {
            atomic_store(&compaction_entered, 0);
            atomic_store(&hold_compaction, (unsigned)strtoul(line + 18, NULL, 10));
            puts("holding-compaction");
        } else if (!strcmp(line, "auto-compact-entered")) {
            printf("entered %u\n", atomic_load(&compaction_entered));
        } else if (!strcmp(line, "release-auto-compact")) {
            atomic_store(&hold_compaction, 0); puts("released-compaction");
        } else if (!strncmp(line, "fail-auto-compact ", 18)) {
            atomic_store(&compaction_fault, (unsigned)strtoul(line + 18, NULL, 10));
            puts("failing-compaction");
        } else if (!strcmp(line, "hold-policy-capture")) {
            atomic_store(&policy_capture_entered, false); atomic_store(&hold_policy_capture, true);
            puts("holding-policy");
        } else if (!strcmp(line, "policy-capture-entered")) {
            printf("entered %u\n", atomic_load(&policy_capture_entered));
        } else if (!strncmp(line, "fail-auto-sync ", 15)) {
            atomic_store(&policy_fail_sync, (unsigned)strtoul(line + 15, NULL, 10));
            puts("failing-auto-sync");
        } else if (!strncmp(line, "auto-checkpoint ", 16)) {
            unsigned long long entries = 0;
            unsigned interval = 0, timeout_ms = 0;
            bool valid = sscanf(line + 16, "%llu %u %u", &entries, &interval, &timeout_ms) == 3 &&
                yd_raft_cluster_checkpoints(cluster, (YDRaftCheckpointPolicy){entries, interval, timeout_ms});
            printf("auto %u\n", valid);
        } else if (!strcmp(line, "checkpoint-state")) {
            YDRaftCheckpointStatus s = yd_raft_cluster_status(cluster).checkpoints;
            printf("checkpoints %u %u %llu %llu %llu\n", s.enabled, s.running,
                (unsigned long long)s.succeeded, (unsigned long long)s.failed, (unsigned long long)s.last_index);
        } else if (!strcmp(line, "hold-send")) {
            atomic_store(&sender_entered, false); atomic_store(&hold_sender, true);
            puts("holding-send");
        } else if (!strcmp(line, "hold-archive")) {
            atomic_store(&archive_paused, false); atomic_store(&hold_archive, true);
            atomic_store(&hold_archive_once, true); puts("holding-archive");
        } else if (!strncmp(line, "hold-dequeue ", 13)) {
            atomic_store(&dequeue_paused, false); atomic_store(&snapshot_queued_peer, 0);
            atomic_store(&hold_dequeue_peer, (unsigned)strtoul(line + 13, NULL, 10)); puts("holding-dequeue");
        } else if (!strcmp(line, "dequeue-paused")) {
            printf("paused %u\n", atomic_load(&dequeue_paused));
        } else if (!strcmp(line, "release-dequeue")) {
            atomic_store(&hold_dequeue_peer, 0); puts("released");
        } else if (!strcmp(line, "archive-paused")) {
            printf("paused %u\n", atomic_load(&archive_paused));
        } else if (!strcmp(line, "release-archive")) {
            atomic_store(&hold_archive, false); puts("released");
        } else if (!strcmp(line, "release-send")) {
            atomic_store(&hold_sender, false); puts("released");
        } else if (!strcmp(line, "send-entered")) {
            printf("entered %u\n", atomic_load(&sender_entered));
        } else if (!strcmp(line, "send-finished")) {
            printf("finished %u\n", atomic_load(&sender_finished));
        } else if (!strcmp(line, "lose-send-reply")) {
            atomic_store(&lose_send_reply, true); puts("losing-reply");
        } else if (!strcmp(line, "send-state")) {
            printf("send %u %llu\n", atomic_load(&lost_send_reply), (unsigned long long)atomic_load(&resumed_send_offset));
        } else if (!strcmp(line, "send-memory")) {
            printf("bytes %zu %zu\n", atomic_load(&sending_bytes), atomic_load(&sending_peak));
        } else if (!strcmp(line, "hold-install")) {
            atomic_store(&install_entered, false); atomic_store(&hold_install, true);
            puts("holding");
        } else if (!strcmp(line, "install-entered")) {
            printf("entered %u\n", atomic_load(&install_entered));
        } else if (!strcmp(line, "release-install")) {
            atomic_store(&hold_install, false); puts("released");
        } else if (!strcmp(line, "fail-install-thread")) {
            atomic_store(&fail_install_thread, true); puts("failing-thread");
        } else if (!strcmp(line, "slow-install-io")) {
            atomic_store(&archive_entered, false); atomic_store(&job_finished, false);
            atomic_store(&slow_install_io, true); puts("slowing-io");
        } else if (!strcmp(line, "archive-entered")) {
            printf("entered %u\n", atomic_load(&archive_entered));
        } else if (!strcmp(line, "job-result")) {
            printf("job %u %u\n", atomic_load(&job_finished), atomic_load(&job_success));
        } else if (!strcmp(line, "hold-apply")) {
            atomic_store(&application_entered, false); atomic_store(&hold_application, true);
            puts("holding-apply");
        } else if (!strcmp(line, "cancel-config-reservation")) {
            atomic_store(&application_entered, false);
            atomic_store(&hold_application, true);
            atomic_store(&reconfiguration_waiting, false);
            cancellation_configuration = (CancelConfiguration){cluster, timeout};
            pthread_t caller;
            bool valid = !cancellation_writer_started &&
                !pthread_create(&cancellation_writer, NULL, cancellation_write, &cancellation_configuration);
            cancellation_writer_started = valid;
            valid = valid && cancellation_wait(&application_entered) &&
                !pthread_create(&caller, NULL, cancel_configuration, &cancellation_configuration);
            void *result = NULL;
            if (valid) {
                bool waiting = cancellation_wait(&reconfiguration_waiting);
                valid = waiting && !pthread_cancel(caller);
                valid = !pthread_join(caller, &result) && valid && result == PTHREAD_CANCELED;
            }
            printf("cancelled %u\n", valid);
        } else if (!strcmp(line, "hold-backup-apply")) {
            atomic_store(&application_entered, false);
            atomic_store(&backup_fetch_returned, false);
            atomic_store(&backup_fetch_missing, false);
            atomic_store(&backup_fetch_index, 0);
            atomic_store(&hold_application, true);
            atomic_store(&hold_before_fetch, true);
            puts("holding-backup-apply");
        } else if (!strcmp(line, "apply-entered")) {
            printf("entered %u\n", atomic_load(&application_entered));
        } else if (!strcmp(line, "backup-fetch")) {
            printf("fetch %u %u %llu\n", atomic_load(&backup_fetch_returned),
                   atomic_load(&backup_fetch_missing),
                   (unsigned long long)atomic_load(&backup_fetch_index));
        } else if (!strcmp(line, "release-apply")) {
            atomic_store(&hold_application, false); puts("released");
        } else if (!strncmp(line, "put ", 4) || !strncmp(line, "inc ", 4) ||
                   !strncmp(line, "crash-inc ", 10)) {
            bool crash = !strncmp(line, "crash-inc ", 10), increment = line[0] != 'p';
            unsigned id = (unsigned)strtoul(line + (crash ? 10 : 4), NULL, 10);
            YDDiskReply reply = write_request(cluster, id, increment, timeout);
            if (crash && reply.status == 200) {
                kill(getpid(), SIGKILL);
                _exit(7);
            }
            printf("write %d\n", reply.status);
            yd_disk_reply_free(&reply);
        } else if (!strncmp(line, "install ", 8)) {
            unsigned from = 0;
            unsigned long long term = 0, index = 0, base_term = 0;
            char id[65];
            bool valid = sscanf(line + 8, "%u %llu %llu %llu %64s", &from, &term, &index, &base_term, id) == 5 &&
                strlen(id) == 64;
            YDRaftSnapshotOffer offer = {.from = from, .term = term,
                .base = {.index = index, .term = base_term}};
            memcpy(offer.cluster, config.cluster, 16);
            for (unsigned i = 0; valid && i < 32; i++) {
                unsigned byte;
                valid = sscanf(id + 2 * i, "%2x", &byte) == 1;
                if (valid) offer.base.archive[i] = (unsigned char)byte;
            }
            bool needed = false;
            valid = valid && yd_raft_cluster_snapshot_contact(cluster, &offer, &needed) && needed &&
                yd_raft_cluster_snapshot_install(cluster, &offer, timeout, error, sizeof(error));
            printf("installed %u\n", valid);
        } else if (!strcmp(line, "backup")) {
            char destination[8192];
            snprintf(destination, sizeof(destination), "%s/paired-backup", argv[1]);
            YDRaftBackup *backup = yd_raft_cluster_backup(cluster, timeout, error, sizeof(error));
            bool valid =
                backup && !mkdir(destination, 0700) &&
                yd_raft_backup_write(backup, destination, NULL, NULL, error, sizeof(error));
            yd_raft_backup_close(backup);
            YDRaftClusterStatus s = yd_raft_cluster_status(cluster);
            if (!valid)
                fprintf(stderr, "backup: %s\n", error);
            printf("backup %u %llu %llu\n", valid, (unsigned long long)s.applied.index,
                   (unsigned long long)s.raft.committed);
        } else if (!strcmp(line, "capture") || !strcmp(line, "capture-diagnostic") || !strcmp(line, "capture-writing") ||
                   !strcmp(line, "capture-cancel")) {
            CaptureWriter writer = {.cluster = cluster, .timeout = timeout};
            bool writing = !strcmp(line, "capture-writing");
            bool diagnostic = !strcmp(line, "capture-diagnostic");
            if (diagnostic) { error[0] = '\0'; errno = 0; }
            YDRaftCapture *next = yd_raft_cluster_capture(cluster, timeout,
                writing ? capture_write : !strcmp(line, "capture-cancel") ? capture_cancel : NULL,
                &writer, error, sizeof(error));
            unsigned char manifest[YD_RAFT_SNAPSHOT_MANIFEST];
            YDRaftSnapshotInfo info = {0};
            bool valid = next && (!writing || (writer.wrote && writer.valid)) &&
                yd_raft_capture_manifest(next, manifest) &&
                yd_raft_snapshot_decode(manifest, sizeof(manifest), config.cluster,
                    config.voters, &info, error, sizeof(error));
            if (valid) { yd_raft_capture_close(captured); captured = next; }
            else yd_raft_capture_close(next);
            printf("capture %u %llu %llu", valid, (unsigned long long)info.applied.index,
                (unsigned long long)info.applied.term);
            if (diagnostic) printf(" errno=%d error=%s", errno, error);
            putchar('\n');
        } else if (!strcmp(line, "close-app-worker")) {
            yd_test_application_close(app_fixture); app_fixture = NULL;
            yd_raft_cluster_close(cluster); cluster = NULL;
            yd_test_application_worker_report();
            break;
        } else if (!strcmp(line, "close-capture")) {
            yd_test_application_close(app_fixture); app_fixture = NULL;
            yd_raft_cluster_close(cluster);
            cluster = NULL;
            unsigned char manifest[YD_RAFT_SNAPSHOT_MANIFEST];
            YDRaftSnapshotInfo info;
            bool valid = yd_raft_capture_manifest(captured, manifest) &&
                yd_raft_snapshot_decode(manifest, sizeof(manifest), config.cluster,
                    config.voters, &info, error, sizeof(error));
            YDRaftSnapshotVerifier *verifier = valid ? yd_raft_snapshot_verifier_new(manifest,
                sizeof(manifest), config.cluster, config.voters, error, sizeof(error)) : NULL;
            unsigned char *bytes = malloc(YD_DISK_CHECKPOINT_CHUNK);
            valid = valid && verifier && bytes;
            for (uint64_t at = 0; valid && at < info.view.end;) {
                size_t count = info.view.end - at < YD_DISK_CHECKPOINT_CHUNK
                    ? (size_t)(info.view.end - at) : YD_DISK_CHECKPOINT_CHUNK;
                valid = yd_raft_capture_read(captured, at, bytes, count, error, sizeof(error)) &&
                    yd_raft_snapshot_feed(verifier, at, bytes, count, error, sizeof(error));
                at += count;
            }
            valid = valid && yd_raft_snapshot_finish(verifier, error, sizeof(error));
            free(bytes);
            yd_raft_snapshot_verifier_free(verifier);
            printf("archive %u\n", valid);
            break;
        } else if (!strcmp(line, "checkpoint") || !strcmp(line, "checkpoint-superseded") ||
                   !strncmp(line, "checkpoint-fail ", 16)) {
            supersede_checkpoint = !strcmp(line, "checkpoint-superseded");
            sync_failure = !strncmp(line, "checkpoint-fail ", 16)
                ? (unsigned)strtoul(line + 16, NULL, 10) : 0;
            sync_calls = 0;
            printf("checkpoint %u\n", yd_raft_cluster_checkpoint(cluster, captured, timeout));
            sync_failure = 0;
        } else if (!strcmp(line, "pin")) {
            YDRaftView *next = yd_raft_cluster_view(cluster, timeout);
            if (next) { yd_raft_view_close(pinned); pinned = next; }
            printf("pinned %u\n", next != NULL);
        } else if (!strcmp(line, "unpin")) {
            yd_raft_view_close(pinned);
            pinned = NULL;
            puts("unpinned");
        } else if (!strcmp(line, "close-many")) {
            Reader readers[8] = {0};
            pthread_t threads[8];
            atomic_bool ready;
            atomic_init(&ready, false);
            unsigned started = 0;
            for (unsigned i = 0; i < 8; i++) {
                readers[i].view = yd_raft_cluster_view(cluster, timeout);
                readers[i].ready = &ready;
                if (!readers[i].view || pthread_create(&threads[i], NULL, read_closed, &readers[i]))
                    break;
                started++;
            }
            yd_test_application_close(app_fixture); app_fixture = NULL;
            yd_raft_cluster_close(cluster);
            cluster = NULL;
            atomic_store(&ready, true);
            bool valid = started == 8;
            for (unsigned i = 0; i < started; i++) {
                pthread_join(threads[i], NULL);
                valid &= readers[i].valid;
            }
            for (unsigned i = started; i < 8; i++) yd_raft_view_close(readers[i].view);
            /* Last reader release must relinquish the writer's file ownership
             * in this process, before process exit could conceal an fd leak. */
            YDRaftApplication *reopened = yd_raft_application_open(data, config.cluster, 32768,
                                                                     error, sizeof(error));
            valid &= reopened != NULL;
            yd_raft_application_close(reopened);
            printf("views %u\n", valid);
            break;
        } else if (!strcmp(line, "get") || !strcmp(line, "local") || !strcmp(line, "pinned") ||
                   !strcmp(line, "close-pinned")) {
            bool captured = !strcmp(line, "pinned") || !strcmp(line, "close-pinned");
            bool closing = !strcmp(line, "close-pinned");
            if (closing) {
                yd_test_application_close(app_fixture); app_fixture = NULL;
                yd_raft_cluster_close(cluster); cluster = NULL;
            }
            YDRaftView *owned = captured ? pinned : line[0] == 'g'
                ? yd_raft_cluster_view(cluster, timeout) : yd_raft_cluster_local_view(cluster);
            if (!owned)
                puts("read 503");
            else {
                YDDisk *disk = yd_raft_view_disk(owned);
                YDDiskView view = yd_raft_view_value(owned);
                YDDiskDocument doc;
                int found =
                    yd_disk_document_get(disk, &view, "config", "node", &doc, error, sizeof(error));
                printf("read %d", found == 1 ? 200 : found ? 503 : 404);
                if (found == 1) {
                    putchar(' ');
                    for (size_t i = 0; i < doc.length; i++)
                        printf("%02x", doc.body[i]);
                }
                putchar('\n');
                yd_disk_document_free(&doc);
                if (!captured) yd_raft_view_close(owned);
            }
            if (closing) {
                YDRaftApplication *locked = yd_raft_application_open(data, config.cluster, 32768,
                                                                       error, sizeof(error));
                if (locked) { yd_raft_application_close(locked); return 3; }
                yd_raft_view_close(pinned);
                pinned = NULL;
                YDRaftApplication *reopened = yd_raft_application_open(data, config.cluster, 32768,
                                                                         error, sizeof(error));
                if (!reopened) return 3;
                yd_raft_application_close(reopened);
                break;
            }
        } else if (!strcmp(line, "corrupt-receipt")) {
            YDDisk *disk = yd_raft_cluster_disk(cluster);
            YDDiskView view = yd_disk_view(disk);
            unsigned char receipt_key[20] = {0, 'Y', 'R', 'R', 1};
            uint64_t offset = 0;
            bool valid = yd_disk_get(disk, &view, receipt_key, sizeof(receipt_key), &offset, error,
                                     sizeof(error)) == 1;
            unsigned char damaged = 255;
            valid = valid && pwrite(disk->fd, &damaged, 1, (off_t)(offset + 16)) == 1 &&
                    !fsync(disk->fd);
            printf("corrupted %u\n", valid);
        } else if (!strcmp(line, "parallel")) {
            struct timespec start, end;
            clock_gettime(CLOCK_MONOTONIC, &start);
            Concurrent states[4];
            pthread_t threads[4];
            unsigned started = 0;
            for (unsigned i = 0; i < 4; i++) {
                states[i] = (Concurrent){.cluster = cluster, .thread = i, .timeout = timeout};
                if (pthread_create(&threads[i], NULL, concurrent, &states[i]))
                    break;
                started++;
            }
            bool valid = started == 4;
            for (unsigned i = 0; i < started; i++) {
                pthread_join(threads[i], NULL);
                valid &= states[i].valid;
            }
            clock_gettime(CLOCK_MONOTONIC, &end);
            double ms = (double)(end.tv_sec - start.tv_sec) * 1000 +
                        (double)(end.tv_nsec - start.tv_nsec) / 1000000;
            printf("parallel %u %.3f\n", valid, ms);
        } else if (!strcmp(line, "shutdown-alive")) {
            atomic_store(&close_requested, true);
            atomic_store(&hold_application, false);
            yd_test_application_close(app_fixture); app_fixture = NULL;
            yd_raft_view_close(pinned); pinned = NULL;
            yd_raft_capture_close(captured); captured = NULL;
            yd_raft_cluster_close(cluster); cluster = NULL;
            puts("closed");
        } else if (!strcmp(line, "stop"))
            break;
        else
            puts("unknown");
        fflush(stdout);
    }
    atomic_store(&close_requested, true);
    atomic_store(&hold_application, false);
    if (cancellation_writer_started) pthread_join(cancellation_writer, NULL);
    yd_test_application_close(app_fixture);
    yd_raft_view_close(pinned);
    yd_raft_capture_close(captured);
    atomic_store(&hold_application, false);
    yd_raft_cluster_close(cluster);
    close(listener);
    yd_tls_free(tls);
    return 0;
}
