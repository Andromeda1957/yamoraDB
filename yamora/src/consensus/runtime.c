#define _GNU_SOURCE
#include "runtime_internal.h"
#include "read.h"
#include "raft_internal.h"
#include "snapshot_store.h"
#include "snapshot_store_internal.h"
#include "snapshot_send.h"
#include "retention_birth.h"
#include "retention_session_owner.h"
#include "journal_namespace.h"
#include "../retention_terminal_capture.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <time.h>
#include <unistd.h>
#define INBOUND_WORKERS 4U
#define FINALIZATION_INTENT ".yamora-retention-finalizing"
typedef struct {
    struct YDRaftRuntime *runtime;
    unsigned id;
    pthread_t thread;
    bool started, busy, queued, snapshot;
    YDRaftPacket packet;
    YDRaftSnapshotRequest image;
    YDRaftSnapshotReference *reference;
    uint64_t deadline, sequence, retry_at;
} Worker;
struct YDRaftRuntime {
    pid_t creator_process;
    YDRaft *raft;
    YDDiskLineage *journal_lineage;
    YDRetentionGate *retention;
    bool retention_birth;
    YDRaftJournalBinding *retention_binding;
    YDRaftRetentionBirth *birth;
    YDRaftJournalBinding *birth_binding;
    YDRaftRetentionSessionOwner *session;
    YDRaftJournalBinding *session_binding;
    enum { LEGACY_UNENROLLED, FENCED_PRESERVE, FRESH_ACTIVE, RESUMED_ACTIVE } enrollment;
    YDRaftMember *member;
    YDRaftRPC *rpc;
    YDRaftTiming timing;
    struct sockaddr_storage endpoints[YD_RAFT_VOTERS + 1];
    socklen_t endpoint_sizes[YD_RAFT_VOTERS + 1];
    unsigned node, voters;
    int listener;
    size_t bytes, budget;
    uint64_t clock;
    YDRaftReads reads;
    unsigned read_waiters;
    YDRaftDispatch receiver;
    void *receiver_context;
    atomic_bool stopping;
    pthread_mutex_t lock;
    pthread_cond_t wake;
    pthread_t timer, inbound[INBOUND_WORKERS];
    unsigned inbound_started;
    bool timer_started;
    bool drained;
    bool finalized;
    Worker peers[YD_RAFT_VOTERS + 1];
};
static bool enrolled(const YDRaftRuntime *r) {
    return r->enrollment == FRESH_ACTIVE || r->enrollment == RESUMED_ACTIVE;
}
static uint64_t now(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t))
        return 0;
    return (uint64_t)t.tv_sec * 1000 + (uint64_t)t.tv_nsec / 1000000;
}
static void block_sigpipe(void) {
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGPIPE);
    (void)pthread_sigmask(SIG_BLOCK, &set, NULL);
}
static void stop_locked(YDRaftRuntime *r) {
    atomic_store(&r->stopping, true);
    pthread_cond_broadcast(&r->wake);
}
static bool endpoint(const char *address, uint16_t port, struct sockaddr_storage *out,
                     socklen_t *size) {
    if (!address || !port || strnlen(address, 46) >= 46)
        return false;
    struct sockaddr_in v4 = {.sin_family = AF_INET, .sin_port = htons(port)};
    if (inet_pton(AF_INET, address, &v4.sin_addr) == 1) {
        uint32_t ip = ntohl(v4.sin_addr.s_addr);
        if ((ip >> 24) != 127 && (ip >> 24) != 10 && (ip >> 20) != 0xac1 && (ip >> 16) != 0xc0a8)
            return false;
        memcpy(out, &v4, sizeof(v4));
        *size = sizeof(v4);
        return true;
    }
    struct sockaddr_in6 v6 = {.sin6_family = AF_INET6, .sin6_port = htons(port)};
    if (inet_pton(AF_INET6, address, &v6.sin6_addr) != 1 ||
        (!IN6_IS_ADDR_LOOPBACK(&v6.sin6_addr) && (v6.sin6_addr.s6_addr[0] & 0xfe) != 0xfc))
        return false;
    memcpy(out, &v6, sizeof(v6));
    *size = sizeof(v6);
    return true;
}
static bool same(const struct sockaddr_storage *a, const struct sockaddr_storage *b) {
    if (a->ss_family != b->ss_family)
        return false;
    if (a->ss_family == AF_INET) {
        const struct sockaddr_in *x = (const struct sockaddr_in *)a,
                                 *y = (const struct sockaddr_in *)b;
        return x->sin_port == y->sin_port && x->sin_addr.s_addr == y->sin_addr.s_addr;
    }
    if (a->ss_family != AF_INET6)
        return false;
    const struct sockaddr_in6 *x = (const struct sockaddr_in6 *)a,
                              *y = (const struct sockaddr_in6 *)b;
    return x->sin6_port == y->sin6_port && !x->sin6_scope_id && !y->sin6_scope_id &&
           !memcmp(&x->sin6_addr, &y->sin6_addr, sizeof(x->sin6_addr));
}
static bool endpoints(const YDRaftConfig *c, struct sockaddr_storage addresses[], socklen_t sizes[]) {
    for (unsigned i = 1; i <= c->voters; i++) {
        if (!endpoint(c->addresses[i], c->ports[i], &addresses[i], &sizes[i]))
            return false;
        for (unsigned j = 1; j < i; j++)
            if (same(&addresses[i], &addresses[j]))
                return false;
    }
    return true;
}
bool yd_raft_config_valid(const YDRaftConfig *c) {
    if (!c || !c->journal_root || !*c->journal_root ||
        !yd_raft_peer_names_valid(c->voters, c->names) || !c->node || c->node > c->voters ||
        !yd_raft_timing_valid(c->timing) || c->cache_bytes < 32768 ||
        c->cache_bytes > 1024U * 1024U * 1024U || !c->command_bytes ||
        c->command_bytes > 64U * 1024U * 1024U ||
        (c->native_capabilities &&
            (!(c->native_capabilities & YD_DISK_CAP_CLUSTER) ||
             (c->native_capabilities & ~YD_DISK_CAP_SUPPORTED))))
        return false;
    if (c->initial_voters) {
        if (c->initial_voters & ~((1U << (c->voters + 1)) - 2)) return false;
        YDRaftMembership initial;
        uint32_t packed = yd_raft_membership_pack((YDRaftMembership){
            .old_voters = c->initial_voters, .new_voters = c->initial_voters});
        if (!yd_raft_membership_unpack(packed, c->voters, &initial)) return false;
    }
    unsigned char nonzero = 0;
    for (unsigned i = 0; i < 16; i++) nonzero |= c->cluster[i];
    struct sockaddr_storage addresses[YD_RAFT_VOTERS + 1] = {0};
    socklen_t sizes[YD_RAFT_VOTERS + 1] = {0};
    return nonzero && endpoints(c, addresses, sizes);
}
int yd_raft_runtime_listen(const YDRaftConfig *c, char *error, size_t length) {
    int fd = -1;
    struct sockaddr_storage address = {0};
    socklen_t size;
    if (!yd_raft_config_valid(c) || !endpoint(c->addresses[c->node], c->ports[c->node], &address, &size))
        goto fail;
    fd = socket(address.ss_family, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    int enabled = 1;
    if (fd < 0 || setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled)) ||
        (address.ss_family == AF_INET6 && setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &enabled, sizeof(enabled))) ||
        bind(fd, (struct sockaddr *)&address, size) || listen(fd, 32))
        goto fail;
    return fd;
fail:
    if (fd >= 0) close(fd);
    snprintf(error, length, "invalid or unavailable private peer listener");
    return -1;
}
static bool emit(void *context, const YDRaftPacket *packet) {
    YDRaftRuntime *r = context;
    Worker *worker = &r->peers[packet->to];
    size_t size = yd_raft_wire_payload(packet);
    if (atomic_load(&r->stopping) || worker->busy || size > r->budget - r->bytes)
        return false;
    worker->sequence = yd_raft_reads_issue(&r->reads);
    if (!worker->sequence) {
        stop_locked(r);
        return false;
    }
    worker->packet = *packet;
    worker->busy = worker->queued = true;
    worker->deadline = r->clock + r->timing.rpc_ms;
    r->bytes += size;
    pthread_cond_broadcast(&r->wake);
    return true;
}
static bool dispatch(void *context, const YDRaftPacket *request, YDRaftPacket *reply) {
    YDRaftRuntime *r = context;
    pthread_mutex_lock(&r->lock);
    if (request->kind == YD_RPC_SNAPSHOT_BEGIN || request->kind == YD_RPC_SNAPSHOT_CHUNK ||
        request->kind == YD_RPC_SNAPSHOT_FINISH) {
        YDRaftDispatch receiver = !atomic_load(&r->stopping) ? r->receiver : NULL;
        void *receiver_context = r->receiver_context;
        pthread_mutex_unlock(&r->lock);
        return receiver && receiver(receiver_context, request, reply);
    }
    uint64_t time = now();
    bool valid = time && !atomic_load(&r->stopping) &&
                 yd_raft_member_handle(r->member, time, request, reply);
    if (yd_raft_status(r->raft).role == YD_RAFT_FAILED)
        stop_locked(r);
    pthread_cond_broadcast(&r->wake);
    pthread_mutex_unlock(&r->lock);
    return valid;
}
bool yd_raft_runtime_receive(YDRaftRuntime *r, YDRaftDispatch receiver, void *context) {
    if (!r || !receiver) return false;
    pthread_mutex_lock(&r->lock);
    bool valid = !atomic_load(&r->stopping) && !r->receiver;
    if (valid) { r->receiver = receiver; r->receiver_context = context; }
    pthread_mutex_unlock(&r->lock);
    return valid;
}
static int connect_peer(YDRaftRuntime *r, unsigned id, uint64_t deadline) {
    const struct sockaddr_storage *address = &r->endpoints[id];
    int fd = socket(address->ss_family, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0)
        return -1;
    bool valid = true;
    if (valid && connect(fd, (const struct sockaddr *)address, r->endpoint_sizes[id])) {
        valid = errno == EINPROGRESS;
        while (valid) {
            uint64_t time = now();
            if (!time || time >= deadline) {
                valid = false;
                break;
            }
            struct pollfd poller = {.fd = fd, .events = POLLOUT};
            int status = poll(&poller, 1, (int)(deadline - time));
            if (status < 0 && errno == EINTR)
                continue;
            int error = 0;
            socklen_t size = sizeof(error);
            valid = status > 0 && !(poller.revents & POLLNVAL) &&
                    !getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &size) && !error;
            break;
        }
    }
    if (!valid) {
        close(fd);
        return -1;
    }
    return fd;
}
static bool snapshot_current_locked(const Worker *worker) {
    YDRaftRuntime *r = worker->runtime;
    return !atomic_load(&r->stopping) &&
        yd_raft_snapshot_source_current(r->raft, &worker->image);
}
static bool snapshot_current(void *context) {
    Worker *worker = context;
    YDRaftRuntime *r = worker->runtime;
    pthread_mutex_lock(&r->lock);
    bool valid = snapshot_current_locked(worker);
    pthread_mutex_unlock(&r->lock);
    return valid;
}
static bool snapshot_progress(void *context, uint64_t done, uint64_t total) {
    (void)done; (void)total;
    return snapshot_current(context);
}
static bool snapshot_reserve(void *context, size_t size) {
    Worker *worker = context;
    YDRaftRuntime *r = worker->runtime;
    pthread_mutex_lock(&r->lock);
    bool valid = snapshot_current_locked(worker) && size <= r->budget - r->bytes;
    if (valid) r->bytes += size;
    pthread_mutex_unlock(&r->lock);
    return valid;
}
static void snapshot_release(void *context, size_t size) {
    YDRaftRuntime *r = ((Worker *)context)->runtime;
    pthread_mutex_lock(&r->lock);
    r->bytes -= size;
    pthread_cond_broadcast(&r->wake);
    pthread_mutex_unlock(&r->lock);
}
static bool snapshot_pause(void *context) {
    Worker *worker = context;
    YDRaftRuntime *r = worker->runtime;
    pthread_mutex_lock(&r->lock);
    uint64_t start = now();
    if (!start || start > UINT64_MAX - 30000) stop_locked(r);
    uint64_t end = start + r->timing.heartbeat_ms;
    struct timespec deadline = {.tv_sec = (time_t)(end / 1000),
        .tv_nsec = (long)(end % 1000) * 1000000};
    while (snapshot_current_locked(worker)) {
        uint64_t time = now();
        if (!time) { stop_locked(r); break; }
        if (time >= end) break;
        (void)pthread_cond_timedwait(&r->wake, &r->lock, &deadline);
    }
    bool valid = snapshot_current_locked(worker);
    pthread_mutex_unlock(&r->lock);
    return valid;
}
static bool snapshot_exchange(void *context, const YDRaftPacket *request, YDRaftPacket *reply) {
    Worker *worker = context;
    YDRaftRuntime *r = worker->runtime;
    uint64_t time = now();
    if (!time || time > UINT64_MAX - r->timing.rpc_ms || !snapshot_current(worker)) return false;
    uint64_t deadline = time + r->timing.rpc_ms;
    int fd = connect_peer(r, worker->id, deadline);
    time = now();
    bool valid = fd >= 0 && time && time < deadline &&
        yd_raft_rpc_call(r->rpc, fd, request, reply, (int)(deadline - time));
    if (fd >= 0) close(fd);
    return valid;
}
/* Only fixed-size manifest/metadata checks and nonblocking cooperative locks.
 * Called before queue visibility under runtime serialization; full verification
 * and every progress callback remain in the outbound worker. */
static YDRaftArchiveResult snapshot_reference(Worker *worker) {
    YDRaftRuntime *r = worker->runtime;
    char error[256];
    /* The journal descriptor remains owned until all peer workers join. Do not
     * create a missing archive directory or recapture mutable application data. */
    int directory = openat(r->raft->directory, YD_RAFT_ARCHIVE_DIRECTORY,
        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    YDRaftSnapshotStore *store = directory >= 0 ? yd_raft_snapshot_store_open_at(directory,
        worker->image.offer.cluster, r->voters, error, sizeof(error)) : NULL;
    if (directory >= 0) close(directory);
    YDRaftArchiveResult result = store ? yd_raft_snapshot_reference_open(store,
        &worker->image.offer.base, &worker->reference, error, sizeof(error)) : YD_RAFT_ARCHIVE_IO;
    yd_raft_snapshot_store_close(store);
    return result;
}
static bool send_snapshot(Worker *worker, YDRaftSnapshotReply *reply) {
    YDRaftRuntime *r = worker->runtime;
    char error[256];
    YDRaftSnapshotArchive *archive = NULL;
    if (yd_raft_snapshot_archive_open_reference(worker->reference, snapshot_progress,
        worker, &archive, error, sizeof(error)) != YD_RAFT_ARCHIVE_OK) {
        pthread_mutex_lock(&r->lock);
        if (snapshot_current_locked(worker)) stop_locked(r);
        pthread_mutex_unlock(&r->lock);
        return false;
    }
    YDRaftSnapshotSendHooks hooks = {.context = worker, .current = snapshot_current,
        .exchange = snapshot_exchange, .pause = snapshot_pause,
        .reserve = snapshot_reserve, .release = snapshot_release};
    size_t chunk = r->budget < YD_RAFT_WIRE_CHUNK ? r->budget : YD_RAFT_WIRE_CHUNK;
    bool valid = yd_raft_snapshot_send(archive, &worker->image, r->voters, chunk, hooks,
        reply, error, sizeof(error));
    yd_raft_snapshot_archive_close(archive);
    return valid;
}
static void *outbound(void *argument) {
    block_sigpipe();
    Worker *worker = argument;
    YDRaftRuntime *r = worker->runtime;
    pthread_mutex_lock(&r->lock);
    for (;;) {
        while (!worker->queued && !atomic_load(&r->stopping))
            pthread_cond_wait(&r->wake, &r->lock);
        if (atomic_load(&r->stopping))
            break;
        YDRaftPacket request = worker->packet, reply;
        YDRaftSnapshotReply installed = {0};
        bool snapshot = worker->snapshot;
        uint64_t deadline = worker->deadline;
        worker->queued = false;
        pthread_mutex_unlock(&r->lock);
        uint64_t time;
        bool valid;
        if (snapshot) valid = send_snapshot(worker, &installed);
        else {
            int fd = connect_peer(r, worker->id, deadline);
            time = now();
            valid = fd >= 0 && time && time < deadline &&
                yd_raft_rpc_call(r->rpc, fd, &request, &reply, (int)(deadline - time));
            if (fd >= 0) close(fd);
        }
        pthread_mutex_lock(&r->lock);
        time = now();
        if (!atomic_load(&r->stopping) &&
            (!time || (snapshot
                ? !yd_raft_member_snapshot_done(r->member, time, &worker->image, valid ? &installed : NULL)
                : !yd_raft_member_done(r->member, time, &request, valid ? &reply : NULL))))
            stop_locked(r);
        if (!snapshot && valid && !atomic_load(&r->stopping))
            yd_raft_reads_observe(&r->reads, worker->sequence, &request, &reply);
        size_t size = yd_raft_wire_payload(&request);
        yd_raft_member_packet_free(&request);
        r->bytes -= size;
        yd_raft_snapshot_reference_close(worker->reference);
        worker->reference = NULL;
        worker->busy = false;
        worker->snapshot = false;
        worker->retry_at = snapshot ? time + r->timing.heartbeat_ms : 0;
        memset(&worker->image, 0, sizeof(worker->image));
        if (r->read_waiters)
            yd_raft_member_probe(r->member);
        memset(&worker->packet, 0, sizeof(worker->packet));
        pthread_cond_broadcast(&r->wake);
    }
    if (worker->queued) {
        r->bytes -= yd_raft_wire_payload(&worker->packet);
        yd_raft_member_packet_free(&worker->packet);
        worker->busy = worker->queued = false;
    }
    yd_raft_snapshot_reference_close(worker->reference);
    worker->reference = NULL;
    pthread_mutex_unlock(&r->lock);
    return NULL;
}
static void *inbound(void *argument) {
    block_sigpipe();
    YDRaftRuntime *r = argument;
    while (!atomic_load(&r->stopping)) {
        struct pollfd poller = {.fd = r->listener, .events = POLLIN};
        int status = poll(&poller, 1, 50);
        if (status < 0 && errno == EINTR)
            continue;
        if (status <= 0)
            continue;
        int fd = accept4(r->listener, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
        if (fd < 0)
            continue;
        if (!atomic_load(&r->stopping))
            (void)yd_raft_rpc_serve(r->rpc, fd, dispatch, r, (int)r->timing.rpc_ms);
        close(fd);
    }
    return NULL;
}
static void *timer(void *argument) {
    YDRaftRuntime *r = argument;
    pthread_mutex_lock(&r->lock);
    while (!atomic_load(&r->stopping)) {
        r->clock = now();
        if (!r->clock || !yd_raft_member_tick(r->member, r->clock, emit, r)) {
            stop_locked(r);
            break;
        }
        if (r->receiver && r->budget >= YD_RAFT_SNAPSHOT_MANIFEST) {
            for (unsigned id = 1; id <= r->voters; id++) {
                Worker *worker = &r->peers[id];
                if (id != r->node && !worker->busy && r->clock >= worker->retry_at &&
                    yd_raft_member_snapshot_begin(r->member, r->clock, id, &worker->image)) {
                    YDRaftArchiveResult result = snapshot_reference(worker);
                    if (result == YD_RAFT_ARCHIVE_OK) {
                        worker->snapshot = worker->busy = worker->queued = true;
                        pthread_cond_broadcast(&r->wake);
                    } else {
                        /* Contended acquisition is retryable, not corruption or
                         * an installed acknowledgement. Release this scheduler
                         * operation before another bounded attempt. */
                        bool released = yd_raft_member_snapshot_done(r->member, r->clock,
                            &worker->image, NULL);
                        memset(&worker->image, 0, sizeof(worker->image));
                        worker->retry_at = r->clock + r->timing.heartbeat_ms;
                        if (!released || result != YD_RAFT_ARCHIVE_BUSY) stop_locked(r);
                    }
                }
            }
        }
        uint64_t deadline = r->clock + 10;
        struct timespec timeout = {.tv_sec = (time_t)(deadline / 1000),
                                   .tv_nsec = (long)(deadline % 1000) * 1000000};
        (void)pthread_cond_timedwait(&r->wake, &r->lock, &timeout);
    }
    pthread_mutex_unlock(&r->lock);
    return NULL;
}
bool yd_raft_runtime_drain(YDRaftRuntime *r) {
    if (!r || r->creator_process != getpid()) return false;
    int cancellation;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancellation)) return false;
    /* The owning shutdown path has joined external callers. Never hold this
     * mutex while waiting for workers that need it to observe stopping. */
    pthread_mutex_lock(&r->lock);
    stop_locked(r);
    pthread_mutex_unlock(&r->lock);
    bool joined = true;
    if (r->timer_started) {
        if (pthread_join(r->timer, NULL)) joined = false;
        else r->timer_started = false;
    }
    for (unsigned i = 1; i <= r->voters; i++) {
        if (r->peers[i].started) {
            if (pthread_join(r->peers[i].thread, NULL)) joined = false;
            else r->peers[i].started = false;
        }
    }
    while (r->inbound_started) {
        if (pthread_join(r->inbound[r->inbound_started - 1], NULL)) {
            joined = false;
            break;
        }
        r->inbound_started--;
    }
    r->drained = joined;
    pthread_setcancelstate(cancellation, NULL);
    return joined;
}
typedef struct {
    YDRaftRuntime *runtime;
    YDRetentionCut cut;
    unsigned char terminal[32];
    bool finalized, busy;
    int intent;
    struct stat intent_stat;
    char *error;
    size_t length;
} Finalization;
static bool finalization_intent_binding(Finalization *f) {
    YDRaftRuntime *r = f->runtime;
    struct stat root, opened, named;
    YDRetentionGateBinding binding;
    return yd_retention_gate_binding(r->retention, &binding) &&
        !fstat(r->raft->directory, &root) && S_ISDIR(root.st_mode) &&
        root.st_dev == binding.root.st_dev && root.st_ino == binding.root.st_ino &&
        root.st_uid == binding.root.st_uid && root.st_gid == binding.root.st_gid &&
        root.st_mode == binding.root.st_mode && !fstat(f->intent, &opened) &&
        !fstatat(r->raft->directory, FINALIZATION_INTENT, &named, AT_SYMLINK_NOFOLLOW) &&
        S_ISREG(opened.st_mode) && opened.st_uid == geteuid() &&
        (opened.st_mode & 07777) == 0600 && opened.st_nlink == 1 && !opened.st_size &&
        opened.st_dev == f->intent_stat.st_dev && opened.st_ino == f->intent_stat.st_ino &&
        opened.st_gid == f->intent_stat.st_gid &&
        opened.st_dev == named.st_dev && opened.st_ino == named.st_ino &&
        opened.st_uid == named.st_uid && opened.st_gid == named.st_gid &&
        opened.st_mode == named.st_mode && opened.st_nlink == named.st_nlink &&
        opened.st_size == named.st_size;
}
static bool finalization_sync(int fd) {
    int result;
    do { result = fsync(fd); } while (result < 0 && errno == EINTR);
    return result == 0;
}
static bool finalization_publish(void *context) {
    Finalization *f = context;
    YDRaftRuntime *r = f->runtime;
    YDRaftRetentionSessionRecord expected, written;
    if (!yd_raft_retention_session_current(r->session, &expected) ||
        expected.state != YD_RAFT_RETENTION_SESSION_ACTIVE ||
        !yd_retention_terminal_capture(r->raft->disk, r->retention, f->cut,
            r->birth, f->terminal, f->error, f->length)) return false;
    /* This intent outlives process-local failure latches. It is created only
     * after the final census closes and is never adopted on another startup.
     * No CLEAN byte may precede durable file AND directory publication. */
    f->intent = openat(r->raft->directory, FINALIZATION_INTENT,
        O_CREAT | O_EXCL | O_RDWR | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0600);
    if (f->intent < 0 || fstat(f->intent, &f->intent_stat) ||
        !finalization_intent_binding(f) || !finalization_sync(f->intent) ||
        !finalization_sync(r->raft->directory)) return false;
    if (yd_raft_retention_session_update_cut(r->session, r->raft->disk, f->cut,
        &expected, YD_RAFT_RETENTION_SESSION_CLEAN, f->terminal, 0, &written,
        f->error, f->length) != YD_RAFT_RETENTION_SESSION_PUBLISHED) return false;
    unsigned char after[32];
    return yd_retention_terminal_capture(r->raft->disk, r->retention, f->cut,
        r->birth, after, f->error, f->length) && !memcmp(after, f->terminal, 32) &&
        yd_raft_retention_session_validate_cut(r->session, f->cut);
}
static bool finalization_cut(YDRetentionCut cut, void *context) {
    Finalization *f = context;
    YDRaftRuntime *r = f->runtime;
    f->cut = cut;
    YDDiskDrainInfo drained;
    errno = 0;
    if (!yd_disk_retention_drain_info(r->raft->disk, r->retention, cut,
        &drained, f->error, f->length)) {
        f->busy = errno == EBUSY;
        return f->busy;
    }
    if (!yd_raft_retention_session_validate_cut(r->session, cut)) return false;
    int archive = openat(r->raft->directory, YD_RAFT_ARCHIVE_DIRECTORY,
        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (archive < 0 && errno != ENOENT) return false;
    YDRaftSnapshotStore *store = archive >= 0 ? yd_raft_snapshot_store_open_at(archive,
        r->raft->meta.cluster, r->voters, f->error, f->length) : NULL;
    bool valid = archive < 0 || store;
    if (archive >= 0) close(archive);
    YDRaftJournalCensus *census = valid ? yd_raft_journal_census_observe(r->raft->directory,
        r->journal_lineage, r->raft->journal_scope, &r->raft->meta, store,
        NULL, NULL, f->error, f->length) : NULL;
    YDRaftJournalCensusInfo info;
    valid = valid && yd_raft_journal_census_info(census, &info) &&
        info.coverage_complete && info.metadata_complete && info.archive_pins_complete &&
        info.source_count == 1 && info.producer_count == 1 && info.scope_count == 3;
    yd_raft_journal_census_close(census);
    yd_raft_snapshot_store_close(store);
    if (!valid || !yd_disk_retention_drain_info(r->raft->disk, r->retention, cut,
        &drained, f->error, f->length)) return false;
    /* Make both actual physical roots and any rejected-write tail durable
     * before hashing the extent that CLEAN will bind. No producer can enter. */
    int result;
    do { result = fsync(r->raft->disk->fd); } while (result < 0 && errno == EINTR);
    if (result) return false;
    do { result = fsync(r->raft->directory); } while (result < 0 && errno == EINTR);
    if (result) return false;
    f->finalized = yd_raft_journal_scope_cut_run(r->raft->journal_scope, cut,
        finalization_publish, f);
    return f->finalized;
}
int yd_raft_runtime_finalize(YDRaftRuntime *r, char *error, size_t length) {
    if (error && length) error[0] = '\0';
    if (!r || r->creator_process != getpid() || !r->drained || !r->raft) return -1;
    if (!r->retention_birth) return 0;
    if (r->finalized) return 1;
    int cancellation;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancellation)) return -1;
    Finalization f = {.runtime = r, .intent = -1, .error = error, .length = length};
    int result = yd_retention_gate_cut_run(r->retention, finalization_cut, &f, error, length);
    if (result == 1 && f.finalized) {
        /* Scope and gate perform trailing validations after the body returns.
         * Keep the intent through BOTH. Only then, with all callers joined
         * and the original native/root EX ownership still held, may this exact
         * inode be removed. No expired cut capability is reused here. */
        if (!finalization_intent_binding(&f) ||
            unlinkat(r->raft->directory, FINALIZATION_INTENT, 0) ||
            !finalization_sync(r->raft->directory)) result = -1;
        else r->finalized = true;
    } else result = result < 0 ? -1 : 0;
    if (f.intent >= 0) close(f.intent); /* Failed attempts never remove intent. */
    pthread_setcancelstate(cancellation, NULL);
    return result;
}
void yd_raft_runtime_stop(YDRaftRuntime *r) {
    if (!r || r->creator_process != getpid()) return;
    int cancellation;
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancellation);
    /* A failed join preserves ownership rather than freeing a worker's inputs. */
    if (!yd_raft_runtime_drain(r)) {
        pthread_setcancelstate(cancellation, NULL);
        return;
    }
    yd_raft_member_free(r->member);
    yd_raft_rpc_free(r->rpc);
    yd_raft_close(r->raft);
    yd_raft_journal_binding_close(r->session_binding);
    yd_raft_journal_binding_close(r->birth_binding);
    yd_raft_journal_binding_close(r->retention_binding);
    yd_raft_retention_session_close(r->session);
    yd_raft_retention_birth_close(r->birth);
    yd_retention_gate_close(r->retention);
    yd_disk_lineage_release(r->journal_lineage);
    pthread_cond_destroy(&r->wake);
    pthread_mutex_destroy(&r->lock);
    free(r);
    pthread_setcancelstate(cancellation, NULL);
}
YDRaftRuntime *yd_raft_runtime_start(const YDRaftConfig *config, YDTLS *tls, int listener,
                                     char *error, size_t length) {
    return yd_raft_runtime_start_checked(config, tls, listener, NULL, NULL, error, length);
}
YDRaftRuntime *yd_raft_runtime_start_checked(const YDRaftConfig *config, YDTLS *tls, int listener,
                                              YDRaftRecoveryCheck check, void *context,
                                              char *error, size_t length) {
    return yd_raft_runtime_start_observed(config, tls, listener, check, context,
        NULL, NULL, error, length);
}
typedef struct {
    YDRaftRuntime *runtime;
    const YDRaftConfig *config;
    bool clean_refused;
    YDDiskOpening *resume_opening;
    YDDisk *resume_disk;
    bool resume_published, terminal_mismatch;
} RetentionConstruction;
static bool birth_prepare(YDDisk *disk, int directory, void *context,
    char *error, size_t length) {
    RetentionConstruction *c = context;
    YDRaftRuntime *r = c->runtime;
    r->retention = yd_retention_gate_open(directory, c->config->cluster,
        r->node, r->voters, true, error, length);
    return yd_retention_gate_created(r->retention) &&
        yd_raft_retention_birth_publish(disk, r->retention, &r->birth, error, length) ==
            YD_RAFT_RETENTION_BIRTH_PUBLISHED;
}
static bool active_prepare(YDDisk *disk, int directory, void *context,
    char *error, size_t length) {
    (void)directory;
    YDRaftRuntime *r = ((RetentionConstruction *)context)->runtime;
    return yd_raft_retention_session_create(disk, r->retention, r->birth,
        &r->session, error, length) == YD_RAFT_RETENTION_SESSION_PUBLISHED;
}
static bool birth_digest(YDRaftRetentionBirth *birth, unsigned char hash[32]) {
    unsigned char bytes[YD_RAFT_RETENTION_BIRTH_SIZE];
    size_t done = 0;
    if (!yd_raft_retention_birth_validate(birth)) return false;
    while (done < sizeof(bytes)) {
        ssize_t n = pread(yd_raft_retention_birth_descriptor(birth), bytes + done,
            sizeof(bytes) - done, (off_t)done);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        done += (size_t)n;
    }
    return SHA256(bytes, sizeof(bytes), hash) && yd_raft_retention_birth_validate(birth);
}
static bool fresh_namespace(int directory, const YDDiskOpeningInfo *opening) {
    YDRaftJournalNamespace *names = yd_raft_journal_namespace_capture(directory, NULL, 0);
    YDRaftJournalNamespaceInfo info;
    YDRaftJournalNamespaceBinding binding;
    bool valid = yd_raft_journal_namespace_info(names, &info) && info.complete &&
        !info.reasons && info.entries == 1 && info.file_count == 1 &&
        info.binding_count == 1 && info.directory_count == 1 &&
        yd_raft_journal_namespace_binding(names, 0, &binding) &&
        binding.kind == YD_RAFT_NAMESPACE_CURRENT &&
        binding.file_identity.st_dev == opening->native.st_dev &&
        binding.file_identity.st_ino == opening->native.st_ino &&
        yd_raft_journal_namespace_validate(names, NULL);
    yd_raft_journal_namespace_close(names);
    return valid;
}
static bool retention_sync_root(int directory) {
    int result;
    do { result = fsync(directory); } while (result < 0 && errno == EINTR);
    return result == 0;
}
static bool resume_cut(YDRetentionCut cut, void *context) {
    RetentionConstruction *c = context;
    YDRaftRuntime *r = c->runtime;
    unsigned char terminal[32], after[32];
    YDRaftRetentionSessionRecord expected, written;
    struct stat pending;
    if (!fstatat(yd_disk_opening_directory(c->resume_opening), FINALIZATION_INTENT, &pending,
        AT_SYMLINK_NOFOLLOW) || errno != ENOENT) return false;
    if (!yd_raft_retention_session_current(r->session, &expected) ||
        expected.state != YD_RAFT_RETENTION_SESSION_CLEAN ||
        !yd_retention_terminal_resume_capture(c->resume_opening, c->resume_disk,
            r->retention, cut, r->birth, terminal, NULL, 0)) return false;
    if (memcmp(terminal, expected.terminal_root, 32)) {
        /* Supported bytes with a changed physical root are untrusted evidence.
         * Preserve service and all artifacts; do not mint a new epoch. */
        c->terminal_mismatch = true;
        return true;
    }
    if (yd_raft_retention_session_resume_cut(r->session, c->resume_opening,
        c->resume_disk, cut, terminal, &written, NULL, 0) !=
        YD_RAFT_RETENTION_SESSION_PUBLISHED) return false;
    c->resume_published = true;
    return yd_retention_terminal_resume_capture(c->resume_opening, c->resume_disk,
        r->retention, cut, r->birth, after, NULL, 0) && !memcmp(terminal, after, 32) &&
        yd_raft_retention_session_validate_cut(r->session, cut);
}
static bool resume_prepare(YDDisk *disk, int directory, void *context,
    char *error, size_t length) {
    (void)directory;
    RetentionConstruction *c = context;
    c->resume_disk = disk;
    int result = yd_retention_gate_cut_run(c->runtime->retention, resume_cut, c, error, length);
    c->resume_disk = NULL;
    return result == 1 && (c->resume_published || c->terminal_mismatch);
}
static bool retention_open(void *context, YDDiskOpening *opening,
    YDDiskOpenAdmission *admission, char *error, size_t length) {
    RetentionConstruction *c = context;
    YDRaftRuntime *r = c->runtime;
    YDDiskOpeningInfo info;
    if (!yd_disk_opening_info(opening, &info)) return false;
    int directory = yd_disk_opening_directory(opening);
    if (info.created_here) {
        unsigned char hash[32];
        if (!fresh_namespace(directory, &info) ||
            !yd_disk_opening_prepare(opening, birth_prepare, c, error, length) ||
            !birth_digest(r->birth, hash) ||
            !yd_disk_opening_install_fence(opening, hash, error, length) ||
            !retention_sync_root(directory) ||
            !yd_disk_opening_prepare(opening, active_prepare, c, error, length) ||
            !yd_disk_opening_info(opening, &info) ||
            !yd_raft_retention_session_service_admission(r->session, &info,
                admission, error, length)) return false;
        r->enrollment = FRESH_ACTIVE;
        return true;
    }
    struct stat status;
    int observed = fstatat(directory, YD_RAFT_RETENTION_SESSION_FILE, &status,
        AT_SYMLINK_NOFOLLOW);
    if (observed && errno != ENOENT) return false;
    if (!info.fence.version) {
        /* An unfenced binary cannot carry a session exclusion capability. */
        return observed != 0;
    }
    /* Release a preserving observer BEFORE native's independent PRESERVE OFD.
     * Partial/malformed/missing data is not authority: native alone checks safe
     * private-object exclusion (or independent absence) without repairing it. */
    YDRetentionGate *gate = yd_retention_gate_open(directory, c->config->cluster,
        r->node, r->voters, false, NULL, 0);
    YDRaftRetentionBirth *birth = NULL;
    YDRaftRetentionSessionOwner *owner = NULL;
    YDRaftRetentionSessionInfo session_info;
    /* A failed classification operation is not malformed data. In particular,
     * allocation/I/O failure must never hide CLEAN and fall through to service.
     * Gate admission has no typed failure result: conservatively refuse NULL. */
    bool healthy = gate != NULL, clean = false;
    YDRaftRetentionBirthResult birth_result = gate
        ? yd_raft_retention_birth_observe(gate, &birth, NULL, 0)
        : YD_RAFT_RETENTION_BIRTH_INVALID;
    if (birth_result == YD_RAFT_RETENTION_BIRTH_IO ||
        birth_result == YD_RAFT_RETENTION_BIRTH_CHANGED) healthy = false;
    if (birth_result == YD_RAFT_RETENTION_BIRTH_OBSERVED) {
        YDRaftRetentionSessionResult result = yd_raft_retention_session_observe(gate,
            birth, &owner, NULL, 0);
        if (result == YD_RAFT_RETENTION_SESSION_OBSERVED) {
            healthy = healthy && yd_raft_retention_session_info(owner, &session_info);
            clean = healthy && session_info.record.state == YD_RAFT_RETENTION_SESSION_CLEAN;
        } else if (result != YD_RAFT_RETENTION_SESSION_MISSING &&
            result != YD_RAFT_RETENTION_SESSION_INVALID) healthy = false;
        /* INVALID can reflect a failed validation of this already-observed
         * input, rather than malformed session bytes. That latch is sticky. */
        healthy = healthy && yd_raft_retention_birth_validate(birth);
    }
    healthy = healthy && yd_retention_gate_validate(gate);
    /* Any object at this name is an interrupted finalization, not a cleanup
     * capability. Preserve even valid CLEAN without consuming a new epoch. */
    int pending = fstatat(directory, FINALIZATION_INTENT, &status, AT_SYMLINK_NOFOLLOW);
    if (pending && errno != ENOENT) healthy = false;
    if (!pending) clean = false;
    if (healthy && clean && session_info.record.epoch != UINT64_MAX) {
        r->retention = gate;
        r->birth = birth;
        r->session = owner;
        c->resume_opening = opening;
        bool resumed = yd_disk_opening_resume_prepare(opening, resume_prepare, c, error, length);
        c->resume_opening = NULL;
        if (!resumed) {
            c->clean_refused = true;
            return false; /* Runtime owns every reference; no preserving fallback. */
        }
        if (c->resume_published) {
            if (!yd_disk_opening_info(opening, &info) ||
                !yd_raft_retention_session_service_admission(r->session, &info,
                    admission, error, length)) return false;
            r->enrollment = RESUMED_ACTIVE;
            return true;
        }
        r->retention = NULL;
        r->birth = NULL;
        r->session = NULL;
    }
    yd_raft_retention_session_close(owner);
    yd_raft_retention_birth_close(birth);
    yd_retention_gate_close(gate);
    if (!healthy) return false;
    admission->expected = info.fence;
    admission->mode = YD_DISK_OPEN_PRESERVE;
    r->enrollment = FENCED_PRESERVE;
    return true;
}
static bool retention_attach(void *context, YDDisk *disk, int directory,
    YDRaftJournalScope *scope, YDRaftJournalConstructor token, char *error, size_t length) {
    YDRaftRuntime *r = ((RetentionConstruction *)context)->runtime;
    if (!enrolled(r)) return true;
    /* First scope operation: transfer the sole live constructor transition's
     * admission, without ending/restarting it or entering a leaf lock. */
    if (!yd_raft_journal_scope_retention_constructing(scope, token, r->retention)) return false;
    yd_disk_retention_bind_new(disk, r->retention, false);
    r->retention_binding = yd_raft_journal_scope_file(scope, directory,
        YD_RETENTION_FILE, yd_retention_gate_descriptor(r->retention), YD_RAFT_JOURNAL_BINDING_CONTROL);
    r->birth_binding = yd_raft_journal_scope_file(scope, directory,
        YD_RAFT_RETENTION_BIRTH_FILE, yd_raft_retention_birth_descriptor(r->birth),
        YD_RAFT_JOURNAL_BINDING_BIRTH);
    int descriptor = -1;
    if (yd_raft_retention_session_registration(r->session, &descriptor, error, length))
        r->session_binding = yd_raft_journal_scope_file(scope, directory,
            YD_RAFT_RETENTION_SESSION_FILE, descriptor, YD_RAFT_JOURNAL_BINDING_SESSION);
    if (descriptor >= 0) close(descriptor);
    YDRaftJournalScopeSnapshot *snapshot = yd_raft_journal_scope_snapshot(scope);
    YDRaftJournalScopeInfo info;
    bool valid = r->retention_binding && r->birth_binding && r->session_binding &&
        yd_raft_journal_scope_snapshot_info(snapshot, &info) && !info.reasons &&
        info.count == 3 && info.active == 1 && !info.complete &&
        yd_retention_gate_validate(r->retention) && yd_raft_retention_birth_validate(r->birth) &&
        yd_raft_retention_session_validate(r->session);
    yd_raft_journal_scope_snapshot_close(snapshot);
    return valid;
}
static bool retention_complete(YDRaftRuntime *r, YDRaftJournalScope *scope) {
    if (!enrolled(r)) return true;
    YDRaftJournalScopeSnapshot *names = yd_raft_journal_scope_snapshot(scope);
    YDRaftJournalScopeInfo bindings;
    YDDiskLineageSnapshot *native = yd_disk_lineage_snapshot(r->journal_lineage);
    YDDiskLineageInfo lineage;
    bool valid = yd_raft_journal_scope_snapshot_info(names, &bindings) && bindings.complete &&
        bindings.count == 3 && yd_raft_journal_scope_validate(names) &&
        yd_disk_lineage_snapshot_info(native, &lineage) && lineage.complete &&
        yd_retention_gate_validate(r->retention) && yd_raft_retention_birth_validate(r->birth) &&
        yd_raft_retention_session_validate(r->session);
    yd_disk_lineage_snapshot_close(native);
    yd_raft_journal_scope_snapshot_close(names);
    return valid;
}
static YDRaftRuntime *start(const YDRaftConfig *config, YDTLS *tls, int listener,
    YDRaftRecoveryCheck check, void *context, YDRaftJournalScope *scope,
    YDDiskLineage *lineage, bool retaining, YDStorageBudget *resources, char *error, size_t length) {
    if (error && length)
        error[0] = 0;
    if (!yd_raft_config_valid(config))
        goto invalid;
    YDRaftRuntime *r = calloc(1, sizeof(*r));
    if (!r)
        goto invalid;
    r->creator_process = getpid();
    r->node = config->node;
    r->voters = config->voters;
    r->listener = listener;
    r->timing = config->timing;
    r->budget = config->command_bytes;
    atomic_init(&r->stopping, false);
    if (pthread_mutex_init(&r->lock, NULL)) {
        free(r);
        goto invalid;
    }
    pthread_condattr_t attributes;
    if (pthread_condattr_init(&attributes)) {
        pthread_mutex_destroy(&r->lock);
        free(r);
        goto invalid;
    }
    bool valid = !pthread_condattr_setclock(&attributes, CLOCK_MONOTONIC) &&
                 !pthread_cond_init(&r->wake, &attributes);
    pthread_condattr_destroy(&attributes);
    if (!valid) {
        pthread_mutex_destroy(&r->lock);
        free(r);
        goto invalid;
    }
    r->journal_lineage = yd_disk_lineage_retain(lineage);
    if (!endpoints(config, r->endpoints, r->endpoint_sizes))
        goto fail;
    struct sockaddr_storage address = {0};
    socklen_t size = sizeof(address);
    int accepting = 0;
    socklen_t option_size = sizeof(accepting);
    if (getsockname(listener, (struct sockaddr *)&address, &size) ||
        size != r->endpoint_sizes[r->node] ||
        !same(&address, &r->endpoints[r->node]) ||
        getsockopt(listener, SOL_SOCKET, SO_ACCEPTCONN, &accepting, &option_size) || !accepting)
        goto fail;
    int flags = fcntl(listener, F_GETFL);
    if (flags < 0 || fcntl(listener, F_SETFL, flags | O_NONBLOCK))
        goto fail;
    r->rpc = yd_raft_rpc_new(tls, config->cluster, r->node, r->voters, config->names, r->budget);
    if (!r->rpc)
        goto fail;
    RetentionConstruction construction = {.runtime = r, .config = config};
    r->raft = retaining
        ? yd_raft_open_constructing_native_budgeted(config->journal_root, config->cluster,
            r->node, r->voters, config->cache_bytes, scope, lineage,
            resources,
            retention_open, &construction, retention_attach, &construction, error, length)
        : yd_raft_open_observed(config->journal_root, config->cluster, r->node, r->voters,
            config->cache_bytes, scope, lineage, error, length);
    /* Native supplies its generic preservation refusal after a guard returns;
     * retain this controller-specific unsupported-state classification. */
    if (!r->raft && construction.clean_refused && error && length)
        snprintf(error, length, "CLEAN retention session activation failed; preserve artifacts");
    /* Ordinary callers cannot enable checkpointed journals. Integrators must
     * verify application/journal recovery while this exact core remains owned. */
    if (!r->raft || !yd_raft_membership_bootstrap(r->raft, config->initial_voters) ||
        (retaining && !retention_complete(r, scope)) ||
        (check ? !check(context, r->raft, error, length) : yd_raft_snapshot_base(r->raft).index != 0) ||
        yd_raft_status(r->raft).role == YD_RAFT_FAILED)
        goto fail;
    r->retention_birth = enrolled(r);
    uint64_t seed;
    if (RAND_bytes((unsigned char *)&seed, sizeof(seed)) != 1 || !seed || !(r->clock = now()))
        goto fail;
    r->member = yd_raft_member_new(r->raft, config->cluster, r->clock, seed, r->timing);
    if (!r->member)
        goto fail;
    for (unsigned i = 1; i <= r->voters; i++)
        if (i != r->node) {
            Worker *worker = &r->peers[i];
            worker->runtime = r;
            worker->id = i;
            if (pthread_create(&worker->thread, NULL, outbound, worker))
                goto fail;
            worker->started = true;
        }
    for (unsigned i = 0; i < INBOUND_WORKERS; i++) {
        if (pthread_create(&r->inbound[i], NULL, inbound, r))
            goto fail;
        r->inbound_started++;
    }
    if (pthread_create(&r->timer, NULL, timer, r))
        goto fail;
    r->timer_started = true;
    return r;
fail:
    yd_raft_runtime_stop(r);
invalid:
    if (error && length && !error[0])
        snprintf(error, length, "invalid or unavailable native Raft runtime configuration");
    return NULL;
}
YDRaftRuntime *yd_raft_runtime_start_observed(const YDRaftConfig *config, YDTLS *tls, int listener,
    YDRaftRecoveryCheck check, void *context, YDRaftJournalScope *scope,
    YDDiskLineage *lineage, char *error, size_t length) {
    return start(config, tls, listener, check, context, scope, lineage, false, NULL, error, length);
}
static void cancel_runtime(void *context) { yd_raft_runtime_stop(context); }
YDRaftRuntime *yd_raft_runtime_start_retaining(const YDRaftConfig *config, YDTLS *tls, int listener,
    YDRaftRecoveryCheck check, void *context, char *error, size_t length) {
    return yd_raft_runtime_start_retaining_budgeted(config, tls, listener, check, context,
        NULL, error, length);
}
YDRaftRuntime *yd_raft_runtime_start_retaining_budgeted(const YDRaftConfig *config, YDTLS *tls, int listener,
    YDRaftRecoveryCheck check, void *context, YDStorageBudget *resources, char *error, size_t length) {
    if (error && length) error[0] = 0;
    int cancellation;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancellation)) return NULL;
    YDRaftJournalScope *scope = yd_raft_journal_scope_new();
    YDDiskLineage *lineage = yd_disk_lineage_new();
    YDRaftRuntime *r = scope && lineage ? start(config, tls, listener, check, context,
        scope, lineage, true, resources, error, length) : NULL;
    yd_raft_journal_scope_close(scope);
    yd_disk_lineage_release(lineage);
    if (!r && error && length && !error[0])
        snprintf(error, length, "retention runtime construction unavailable");
    /* Restoring an enabled caller may deliver pending cancellation. The whole
     * constructed runtime already has cleanup, including all started workers. */
    pthread_cleanup_push(cancel_runtime, r);
    pthread_setcancelstate(cancellation, NULL);
    if (cancellation == PTHREAD_CANCEL_ENABLE) pthread_testcancel();
    pthread_cleanup_pop(0);
    return r;
}
bool yd_raft_runtime_journal_replaceable(YDRaftRuntime *r) {
    if (!r) return false;
    pthread_mutex_lock(&r->lock);
    bool valid = !atomic_load(&r->stopping) && r->raft &&
        !r->raft->disk->open_fence.version;
    pthread_mutex_unlock(&r->lock);
    return valid;
}
bool yd_raft_runtime_archive_admit(YDRaftRuntime *r, int *out) {
    if (out) *out = -1;
    if (!r || !out || r->creator_process != getpid() || atomic_load(&r->stopping)) return false;
    if (!r->retention_birth) return true;
    *out = yd_retention_gate_enter(r->retention);
    return *out >= 0;
}
YDRaftStatus yd_raft_runtime_status(YDRaftRuntime *r) {
    pthread_mutex_lock(&r->lock);
    YDRaftStatus s = yd_raft_status(r->raft);
    if (atomic_load(&r->stopping)) {
        s.role = YD_RAFT_FAILED;
        s.leader = 0;
    }
    pthread_mutex_unlock(&r->lock);
    return s;
}
bool yd_raft_runtime_snapshot_contact(YDRaftRuntime *r, const YDRaftSnapshotOffer *offer,
                                        bool *needed) {
    if (needed) *needed = false;
    if (!r || !needed) return false;
    pthread_mutex_lock(&r->lock);
    uint64_t time = now();
    bool valid = time && !atomic_load(&r->stopping) &&
        yd_raft_member_snapshot_contact(r->member, time, offer, needed);
    if (yd_raft_status(r->raft).role == YD_RAFT_FAILED)
        stop_locked(r);
    pthread_cond_broadcast(&r->wake);
    pthread_mutex_unlock(&r->lock);
    return valid;
}
bool yd_raft_runtime_checkpoint(YDRaftRuntime *r, uint64_t term, const YDRaftSnapshotBase *base) {
    if (!r || !base || !term) return false;
    pthread_mutex_lock(&r->lock);
    YDRaftStatus status = yd_raft_status(r->raft);
    bool valid = !atomic_load(&r->stopping) && status.role == YD_RAFT_LEADER &&
        status.term == term && yd_raft_checkpoint(r->raft, base);
    if (yd_raft_status(r->raft).role == YD_RAFT_FAILED) stop_locked(r);
    pthread_cond_broadcast(&r->wake);
    pthread_mutex_unlock(&r->lock);
    return valid;
}
YDRaftSnapshotBase yd_raft_runtime_checkpoint_base(YDRaftRuntime *r) {
    if (!r) return (YDRaftSnapshotBase){0};
    pthread_mutex_lock(&r->lock);
    YDRaftSnapshotBase base = yd_raft_snapshot_base(r->raft);
    pthread_mutex_unlock(&r->lock);
    return base;
}
bool yd_raft_runtime_journal_active(const YDRaftRuntime *r) {
    return r && !atomic_load_explicit(&r->stopping, memory_order_acquire);
}
struct YDRaftApplicationCut {
    YDRetentionGate *gate;
    YDRaftJournalProtection *protection;
    int descriptor;
};
void yd_raft_runtime_application_cut_close(YDRaftApplicationCut *cut) {
    if (!cut) return;
    int cancellation;
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancellation);
    yd_raft_journal_protection_close(cut->protection);
    if (cut->descriptor >= 0) close(cut->descriptor);
    yd_retention_gate_close(cut->gate);
    free(cut);
    pthread_setcancelstate(cancellation, NULL);
}
struct YDRaftArchiveCut {
    YDRaftRuntime *runtime;
    YDRetentionGate *gate;
    YDRetentionCut token;
    YDRaftJournalProtection *protection;
    unsigned char birth[32];
    bool active;
};
typedef struct {
    YDRaftArchiveCut proof;
    YDDiskLineage *native;
    YDRaftJournalScope *scope;
    YDRaftMeta identity;
    int directory, document_root;
    unsigned char target[32];
    bool (*body)(YDRaftArchiveCut *, void *);
    void *context;
    char *error;
    size_t length;
    bool called, dependent, refresh, application_target, application_unavailable;
} ArchiveCutOperation;
bool yd_raft_runtime_archive_cut_validate(YDRaftArchiveCut *proof) {
    if (!proof || !proof->active ||
        !yd_retention_gate_cut_validate(proof->gate, proof->token)) return false;
    unsigned char hash[32];
    return yd_raft_runtime_journal_active(proof->runtime) &&
        yd_raft_retention_birth_hash_cut(proof->runtime->birth, proof->gate, proof->token, hash) &&
        !memcmp(hash, proof->birth, 32) &&
        yd_raft_retention_session_validate_cut(proof->runtime->session, proof->token);
}
static bool archive_cut_body(YDRetentionCut cut, void *context) {
    ArchiveCutOperation *op = context;
    YDRaftArchiveCut *proof = &op->proof;
    proof->token = cut;
    /* An escaped observational snapshot has no shared producer admission, but
     * can still retain an older metadata root. Exclude those real holders
     * before constructing this cut's own temporary census readers. New
     * observations under the cut see only the unchanged physical pair that
     * this census covers. Fenced journal replacement remains disabled. */
    YDDiskDrainInfo drained;
    errno = 0;
    if (!yd_disk_retention_drain_info(proof->runtime->raft->disk, proof->gate,
        cut, &drained, op->error, op->length)) return errno == EBUSY;
    if (!yd_raft_retention_birth_hash_cut(proof->runtime->birth, proof->gate, cut, proof->birth) ||
        !yd_raft_retention_session_validate_cut(proof->runtime->session, cut)) return false;
    int archive = openat(op->directory, YD_RAFT_ARCHIVE_DIRECTORY,
        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (archive < 0 && (errno != ENOENT || !op->application_target)) return false;
    YDRaftSnapshotStore *store = archive >= 0 ? yd_raft_snapshot_store_open_at(archive,
        op->identity.cluster, op->identity.voters, op->error, op->length) : NULL;
    if (archive >= 0) close(archive);
    if (archive >= 0 && !store) return false;
    YDRaftJournalCensus *census = yd_raft_journal_census_observe(op->directory,
        op->native, op->scope, &op->identity, store, NULL, NULL, op->error, op->length);
    yd_raft_snapshot_store_close(store);
    proof->protection = yd_raft_journal_protection_take(census, op->document_root,
        NULL, NULL, op->error, op->length);
    YDRaftJournalProtectionInfo info = {0};
    bool complete = yd_raft_journal_protection_info(proof->protection, &info) &&
        info.application_pins_complete && info.census.coverage_complete &&
        info.census.metadata_complete && info.census.archive_pins_complete;
    /* An unsafe application pathname grants no retirement proof. It does not
     * invalidate an otherwise complete journal census or its gate: close this
     * successful observational cut and report the refusal separately, so the
     * same live ticket may retry after the exact original files are restored.
     * Journal coverage, birth, session and gate failures remain sticky. */
    if (!complete && info.census.coverage_complete && info.census.metadata_complete &&
        info.census.archive_pins_complete && !info.application_pins_complete) {
        op->application_unavailable = true;
        proof->active = true;
        bool valid = yd_raft_runtime_archive_cut_validate(proof);
        proof->active = false;
        return valid;
    }
    bool only_physical = complete && info.census.source_count == 1;
    for (size_t i = 0; complete && i < info.census.root_count; i++) {
        YDRaftJournalCensusRoot root;
        YDRaftJournalApplicationEdge edge;
        if (!yd_raft_journal_protection_root(proof->protection, i, &root, &edge)) {
            complete = false;
            break;
        }
        if (root.dependency.state == YD_RAFT_DEPENDENCY_KNOWN &&
            (op->application_target ? !memcmp(root.dependency.metadata.application, op->target, 32) :
                root.dependency.metadata.snapshot.index &&
                !memcmp(root.dependency.metadata.snapshot.archive, op->target, 32))) {
            op->dependent = true;
            if (!root.physical_slots || root.producers) only_physical = false;
        }
    }
    proof->active = complete;
    bool valid = complete && yd_raft_runtime_archive_cut_validate(proof);
    op->refresh = valid && op->dependent && only_physical;
    if (!valid || op->dependent) {
        proof->active = false;
        return valid;
    }
    op->called = true;
    valid = op->body(proof, op->context) && yd_raft_runtime_archive_cut_validate(proof);
    proof->active = false;
    return valid;
}
static int retention_proof_run(YDRaftRuntime *r, int document_root,
    const unsigned char target[32], bool (*body)(YDRaftArchiveCut *, void *),
    void *context, bool application_target, char *error, size_t length) {
    if (error && length) error[0] = '\0';
    if (!r || r->creator_process != getpid() || document_root < 0 || !target || !body) return -1;
    unsigned char nonzero = 0;
    for (unsigned i = 0; i < 32; i++) nonzero |= target[i];
    if (!nonzero && !application_target) return -1;
    int cancellation;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancellation)) return -1;
    ArchiveCutOperation op = {.proof = {.runtime = r}, .directory = -1,
        .document_root = document_root, .body = body, .context = context,
        .error = error, .length = length, .application_target = application_target};
    memcpy(op.target, target, 32);
    /* Last runtime lock until the exclusive gate is gone. Retained inputs and
     * controller lifetime cover every read in the callback. */
    pthread_mutex_lock(&r->lock);
    bool active = !atomic_load(&r->stopping) && r->raft && r->retention && r->retention_birth;
    if (active) {
        op.directory = fcntl(r->raft->directory, F_DUPFD_CLOEXEC, 0);
        op.identity = r->raft->meta;
        op.native = yd_disk_lineage_retain(r->journal_lineage);
        op.scope = yd_raft_journal_scope_retain(r->raft->journal_scope);
        op.proof.gate = yd_retention_gate_retain(r->retention);
    }
    pthread_mutex_unlock(&r->lock);
    int result = -1;
    if (op.directory >= 0 && op.native && op.scope && op.proof.gate &&
        yd_raft_retention_birth_validate(r->birth) && yd_raft_retention_session_validate(r->session))
        result = yd_retention_gate_cut_run(op.proof.gate, archive_cut_body, &op, error, length);
    /* Protection may retain a target archive on the dependent path. Close its
     * readers before refreshing current metadata or returning to file custody. */
    yd_raft_journal_protection_close(op.proof.protection);
    yd_disk_lineage_release(op.native);
    yd_raft_journal_scope_close(op.scope);
    yd_retention_gate_close(op.proof.gate);
    if (op.directory >= 0) close(op.directory);
    if (result == 1 && op.refresh) {
        /* Only the stale physical alternate named target. This current-state
         * mirror grants no retirement; the caller must acquire a new cut. */
        pthread_mutex_lock(&r->lock);
        bool valid = !atomic_load(&r->stopping) && r->raft &&
            yd_raft_status(r->raft).role != YD_RAFT_FAILED &&
            memcmp(application_target ? r->raft->meta.application : r->raft->meta.snapshot.archive, target, 32) &&
            yd_raft_save(r->raft, &r->raft->meta, NULL);
        if (r->raft && yd_raft_status(r->raft).role == YD_RAFT_FAILED) stop_locked(r);
        pthread_mutex_unlock(&r->lock);
        if (!valid) result = -1;
    }
    if (result == 1 && op.application_unavailable) result = -1;
    if (result == 1 && !op.called) result = 0;
    pthread_setcancelstate(cancellation, NULL);
    return result;
}
int yd_raft_runtime_archive_cut_run(YDRaftRuntime *r, int document_root,
    const unsigned char target[32], bool (*body)(YDRaftArchiveCut *, void *),
    void *context, char *error, size_t length) {
    return retention_proof_run(r, document_root, target, body, context, false, error, length);
}
static bool application_proof(YDRaftArchiveCut *proof, void *context) {
    (void)context;
    return yd_raft_runtime_archive_cut_validate(proof);
}
static int application_cut(YDRaftRuntime *r, int document_root,
    const unsigned char target[32], YDRaftApplicationCut **out, char *error, size_t length) {
    if (out) *out = NULL;
    if (!out) return -1;
    /* These result slots can inline into the public wrappers' pthread cleanup
     * setjmp frame. Preserve their ownership values across that boundary. */
    volatile int result = retention_proof_run(r, document_root, target, application_proof,
        NULL, true, error, length);
    if (result != 1) return result;
    /* The caller's uninterrupted selection/install reservation spans both
     * cuts. No old holder survived the proof; every new capture/checkpoint
     * derives from target-free current roots and cannot reintroduce target.
     * Preserve this private API's independent EX lease without adopting the
     * expired callback capability or running ordinary validators under EX. */
    YDRaftApplicationCut *volatile cut = calloc(1, sizeof(*cut));
    if (!cut) return -1;
    cut->descriptor = -1;
    cut->gate = yd_retention_gate_retain(r->retention);
    result = yd_retention_gate_try_cut(cut->gate, &cut->descriptor, error, length);
    if (result == 1) *out = cut;
    else yd_raft_runtime_application_cut_close(cut);
    return result;
}
static YDRaftJournalCensus *journal_census(YDRaftRuntime *r,
    YDRaftJournalCensusProgress progress, void *context, char *error, size_t length) {
    if (!r) {
        yd_disk_error(error, length, "journal census runtime unavailable");
        return NULL;
    }
    YDRaftMeta identity = {0};
    pthread_mutex_lock(&r->lock);
    int directory = fcntl(r->raft->directory, F_DUPFD_CLOEXEC, 0);
    memcpy(identity.cluster, r->raft->meta.cluster, sizeof(identity.cluster));
    identity.node = r->raft->meta.node;
    identity.voters = r->raft->meta.voters;
    YDDiskLineage *native = yd_disk_lineage_retain(r->journal_lineage);
    YDRaftJournalScope *scope = yd_raft_journal_scope_retain(r->raft->journal_scope);
    YDRaftRetentionBirth *birth = r->birth;
    pthread_mutex_unlock(&r->lock);
    if (r->retention && !yd_raft_retention_birth_validate(birth))
        yd_raft_journal_scope_incomplete(scope);
    int archive = directory < 0 ? -1 : openat(directory, YD_RAFT_ARCHIVE_DIRECTORY,
        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    YDRaftSnapshotStore *store = archive < 0 ? NULL : yd_raft_snapshot_store_open_at(archive,
        identity.cluster, identity.voters, NULL, 0);
    if (archive >= 0) close(archive);
    YDRaftJournalCensus *volatile census = yd_raft_journal_census_observe(directory, native, scope,
        &identity, store, progress, context, error, length);
    if (r->retention && !yd_raft_retention_birth_validate(birth)) {
        yd_raft_journal_scope_incomplete(scope);
        yd_raft_journal_census_close(census);
        census = NULL;
        yd_disk_error(error, length, "retention birth evidence changed or unavailable");
    }
    yd_raft_snapshot_store_close(store);
    yd_raft_journal_scope_close(scope);
    yd_disk_lineage_release(native);
    if (directory >= 0) close(directory);
    return census;
}
static YDRaftJournalDependencies *journal_dependencies(YDRaftRuntime *r,
    size_t cache, char *error, size_t length) {
    if (!r) {
        yd_disk_error(error, length, "journal dependency runtime unavailable");
        return NULL;
    }
    YDDiskRecoveryRoots *roots = NULL;
    YDRaftMeta identity = {0};
    int directory = -1;
    pthread_mutex_lock(&r->lock);
    if (!atomic_load(&r->stopping) && yd_raft_status(r->raft).role != YD_RAFT_FAILED &&
        yd_disk_recovery_roots_pin(r->raft->disk, cache, &roots, error, length) ==
            YD_DISK_OBSERVE_OK) {
        identity = r->raft->meta;
        directory = fcntl(r->raft->directory, F_DUPFD_CLOEXEC, 0);
    }
    pthread_mutex_unlock(&r->lock);
    if (directory < 0) {
        yd_disk_recovery_roots_close(roots);
        yd_disk_error(error, length, "journal dependency roots unavailable");
        return NULL;
    }
    int archive = openat(directory, YD_RAFT_ARCHIVE_DIRECTORY,
        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    close(directory);
    YDRaftSnapshotStore *store = archive < 0 ? NULL : yd_raft_snapshot_store_open_at(archive,
        identity.cluster, identity.voters, NULL, 0);
    if (archive >= 0) close(archive);
    YDRaftJournalDependencies *volatile d = yd_raft_journal_dependencies_take_roots(roots, &identity,
        store, error, length);
    yd_raft_snapshot_store_close(store);
    return d;
}
static YDRaftJournalCapture *journal_capture(YDRaftRuntime *r, size_t cache,
                                                       char *error, size_t length) {
    if (!r) {
        if (length) snprintf(error, length, "journal capture requires a live runtime");
        return NULL;
    }
    pthread_mutex_lock(&r->lock);
    YDRaftJournalCapture *volatile capture = !atomic_load(&r->stopping)
        ? yd_raft_journal_capture(r->raft, cache, error, length) : NULL;
    if (!capture && length && atomic_load(&r->stopping))
        snprintf(error, length, "journal capture runtime is stopping");
    pthread_mutex_unlock(&r->lock);
    return capture;
}
/* Native fenced observation constructors require disabled cancellation through
 * returned-object adoption. These wrappers also protect legacy callers from
 * losing an owned result at the state-restoration boundary. None enters shared
 * admission for observational lineage inheritance, even under an EX cut. */
static void cancel_cut(void *p) { yd_raft_runtime_application_cut_close(p); }
static void cancel_census(void *p) { yd_raft_journal_census_close(p); }
static void cancel_dependencies(void *p) { yd_raft_journal_dependencies_close(p); }
static void cancel_capture(void *p) { yd_raft_journal_capture_close(p); }
int yd_raft_runtime_application_cut(YDRaftRuntime *r, int root,
    const unsigned char target[32], YDRaftApplicationCut **out, char *error, size_t length) {
    if (out) *out = NULL;
    if (!out) return -1;
    int cancellation;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancellation)) return -1;
    YDRaftApplicationCut *cut = NULL;
    int result = application_cut(r, root, target, &cut, error, length);
    pthread_cleanup_push(cancel_cut, cut);
    pthread_setcancelstate(cancellation, NULL);
    if (cancellation == PTHREAD_CANCEL_ENABLE) pthread_testcancel();
    pthread_cleanup_pop(0);
    *out = cut;
    return result;
}
YDRaftJournalCensus *yd_raft_runtime_journal_census(YDRaftRuntime *r,
    YDRaftJournalCensusProgress progress, void *context, char *error, size_t length) {
    int cancellation;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancellation)) return NULL;
    YDRaftJournalCensus *volatile result = journal_census(r, progress, context, error, length);
    pthread_cleanup_push(cancel_census, result);
    pthread_setcancelstate(cancellation, NULL);
    if (cancellation == PTHREAD_CANCEL_ENABLE) pthread_testcancel();
    pthread_cleanup_pop(0);
    return result;
}
YDRaftJournalDependencies *yd_raft_runtime_journal_dependencies(YDRaftRuntime *r,
    size_t cache, char *error, size_t length) {
    int cancellation;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancellation)) return NULL;
    YDRaftJournalDependencies *volatile result = journal_dependencies(r, cache, error, length);
    pthread_cleanup_push(cancel_dependencies, result);
    pthread_setcancelstate(cancellation, NULL);
    if (cancellation == PTHREAD_CANCEL_ENABLE) pthread_testcancel();
    pthread_cleanup_pop(0);
    return result;
}
YDRaftJournalCapture *yd_raft_runtime_journal_capture(YDRaftRuntime *r,
    size_t cache, char *error, size_t length) {
    int cancellation;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancellation)) return NULL;
    YDRaftJournalCapture *volatile result = journal_capture(r, cache, error, length);
    pthread_cleanup_push(cancel_capture, result);
    pthread_setcancelstate(cancellation, NULL);
    if (cancellation == PTHREAD_CANCEL_ENABLE) pthread_testcancel();
    pthread_cleanup_pop(0);
    return result;
}
bool yd_raft_runtime_journal_current(YDRaftRuntime *r, const YDRaftJournalImage *image) {
    if (!r || !image) return false;
    pthread_mutex_lock(&r->lock);
    bool current = !atomic_load(&r->stopping) && yd_raft_journal_image_current(image, r->raft);
    pthread_mutex_unlock(&r->lock);
    return current;
}
static int journal_root(YDRaftRuntime *r) {
    int directory = -1;
    if (r) {
        pthread_mutex_lock(&r->lock);
        if (!atomic_load(&r->stopping) && yd_raft_status(r->raft).role != YD_RAFT_FAILED)
            directory = openat(r->raft->directory, ".",
                O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        pthread_mutex_unlock(&r->lock);
    }
    return directory;
}
YDRaftJournalPublication *yd_raft_runtime_journal_prepare(YDRaftRuntime *r,
                                                          YDRaftJournalImage *image,
                                                          char *error, size_t length) {
    int directory = image ? journal_root(r) : -1;
    if (directory < 0) {
        if (error && length) snprintf(error, length, "journal preparation requires a live runtime");
        return NULL;
    }
    YDRaftJournalPublication *publication = yd_raft_journal_prepare(image, directory, error, length);
    close(directory);
    return publication;
}
static bool journal_directory_private(int fd) {
    struct stat status;
    return fd >= 0 && !fstat(fd, &status) && S_ISDIR(status.st_mode) &&
        status.st_uid == geteuid() && !(status.st_mode & (S_IWGRP | S_IWOTH));
}
YDRaftJournalScope *yd_raft_runtime_journal_scope(YDRaftRuntime *r) {
    if (!r) return NULL;
    pthread_mutex_lock(&r->lock);
    YDRaftJournalScope *scope = r->raft ? yd_raft_journal_scope_retain(r->raft->journal_scope) : NULL;
    pthread_mutex_unlock(&r->lock);
    return scope;
}
int yd_raft_runtime_journal_staging(YDRaftRuntime *r, char *error, size_t length) {
    YDRaftJournalScope *scope = yd_raft_runtime_journal_scope(r);
    yd_raft_journal_scope_begin(scope);
    int root = journal_root(r), staging = -1;
    if (journal_directory_private(root) &&
        (!mkdirat(root, YD_RAFT_JOURNAL_STAGING, 0700) || errno == EEXIST))
        staging = openat(root, YD_RAFT_JOURNAL_STAGING,
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    bool valid = journal_directory_private(staging) && !fsync(staging) && !fsync(root);
    if (root >= 0) close(root);
    yd_raft_journal_scope_end(scope);
    yd_raft_journal_scope_close(scope);
    if (!valid) {
        if (staging >= 0) close(staging);
        if (error && length) snprintf(error, length, "journal staging unavailable or untrusted");
        return -1;
    }
    return staging;
}
bool yd_raft_runtime_journal_publish(YDRaftRuntime *r, YDRaftJournalPublication *publication,
                                       bool *published, char *error, size_t length) {
    if (published) *published = false;
    if (!r || !publication || !published) {
        if (error && length) snprintf(error, length, "journal selection requires a live runtime");
        return false;
    }
    pthread_mutex_lock(&r->lock);
    bool valid = !atomic_load(&r->stopping);
    if (valid)
        valid = yd_raft_journal_publish(publication, r->raft, published, error, length);
    else if (error && length)
        snprintf(error, length, "journal selection runtime is stopping");
    if (yd_raft_status(r->raft).role == YD_RAFT_FAILED)
        stop_locked(r);
    pthread_cond_broadcast(&r->wake);
    pthread_mutex_unlock(&r->lock);
    return valid;
}
bool yd_raft_runtime_application_select(YDRaftRuntime *r, const unsigned char expected[32],
    const YDRaftSnapshotBase *base, YDRaftSnapshotPublish publish, void *context, bool *published) {
    if (published) *published = false;
    if (!r || !expected || !base || !publish || !published) return false;
    pthread_mutex_lock(&r->lock);
    bool valid = !atomic_load(&r->stopping) && yd_raft_application_select(r->raft, expected, base);
    if (valid) {
        /* Caller owns the application slot. No fallible step may separate the
         * durable selection from transferring its prepared live generation. */
        publish(context);
        *published = true;
    }
    if (yd_raft_status(r->raft).role == YD_RAFT_FAILED) stop_locked(r);
    pthread_cond_broadcast(&r->wake);
    pthread_mutex_unlock(&r->lock);
    return valid;
}
bool yd_raft_runtime_application_select_layout(YDRaftRuntime *r, const unsigned char expected[32],
    const YDRaftSnapshotBase *base, unsigned layout, YDRaftSnapshotPublish publish,
    void *context, bool *published) {
    if (published) *published = false;
    if (!r || !expected || !base || !publish || !published || layout > 1) return false;
    pthread_mutex_lock(&r->lock);
    bool valid = !atomic_load(&r->stopping) &&
        yd_raft_application_select_layout(r->raft, expected, base, layout);
    if (valid) {
        publish(context);
        *published = true;
    }
    if (yd_raft_status(r->raft).role == YD_RAFT_FAILED) stop_locked(r);
    pthread_cond_broadcast(&r->wake);
    pthread_mutex_unlock(&r->lock);
    return valid;
}
static bool snapshot_install(YDRaftRuntime *r, const YDRaftSnapshotOffer *offer,
    bool explicit_layout, unsigned layout, YDRaftSnapshotPublish publish, void *context,
    bool *published) {
    if (published) *published = false;
    if (!r || !offer || !publish || !published || layout > 1) return false;
    pthread_mutex_lock(&r->lock);
    bool valid = !atomic_load(&r->stopping) && now() &&
        offer->base.index > yd_raft_status(r->raft).committed &&
        (explicit_layout ? yd_raft_snapshot_install_layout(r->raft, offer, layout)
                         : yd_raft_snapshot_install(r->raft, offer));
    if (valid) {
        /* The caller already owns its application lock. Nothing that can fail
         * may intervene between the durable decision and this slot transfer. */
        publish(context);
        *published = true;
        bool needed = false;
        uint64_t time = now();
        valid = time && yd_raft_member_snapshot_contact(r->member, time, offer, &needed) && !needed;
        if (!valid) stop_locked(r);
    }
    if (yd_raft_status(r->raft).role == YD_RAFT_FAILED)
        stop_locked(r);
    pthread_cond_broadcast(&r->wake);
    pthread_mutex_unlock(&r->lock);
    return valid;
}
bool yd_raft_runtime_snapshot_install(YDRaftRuntime *r, const YDRaftSnapshotOffer *offer,
    YDRaftSnapshotPublish publish, void *context, bool *published) {
    return snapshot_install(r, offer, false, 0, publish, context, published);
}
bool yd_raft_runtime_snapshot_install_layout(YDRaftRuntime *r, const YDRaftSnapshotOffer *offer,
    unsigned layout, YDRaftSnapshotPublish publish, void *context, bool *published) {
    return snapshot_install(r, offer, true, layout, publish, context, published);
}
int yd_raft_runtime_snapshot_directory(YDRaftRuntime *r) {
    if (!r) return -1;
    pthread_mutex_lock(&r->lock);
    int directory = -1;
    if (!atomic_load(&r->stopping) && yd_raft_status(r->raft).role != YD_RAFT_FAILED &&
        (!mkdirat(r->raft->directory, YD_RAFT_ARCHIVE_DIRECTORY, 0700) || errno == EEXIST)) {
        directory = openat(r->raft->directory, YD_RAFT_ARCHIVE_DIRECTORY,
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        struct stat status;
        if (directory >= 0 && (fstat(directory, &status) || status.st_uid != geteuid() ||
            (status.st_mode & (S_IWGRP | S_IWOTH)) || fsync(directory) || fsync(r->raft->directory))) {
            close(directory);
            directory = -1;
        }
    }
    pthread_mutex_unlock(&r->lock);
    return directory;
}
bool yd_raft_runtime_snapshot_observe(YDRaftRuntime *r, int *directory,
    YDRaftApplicationVolume *volume) {
    if (directory) *directory = -1;
    if (volume) *volume = (YDRaftApplicationVolume){0};
    if (!r || !directory || !volume) return false;
    pthread_mutex_lock(&r->lock);
    bool valid = !atomic_load(&r->stopping) && yd_raft_status(r->raft).role != YD_RAFT_FAILED;
    int fd = valid ? openat(r->raft->directory, YD_RAFT_ARCHIVE_DIRECTORY,
        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC) : -1;
    valid = valid && (fd >= 0 || errno == ENOENT);
    int sampled = fd >= 0 ? fd : r->raft->directory;
    struct stat status;
    struct statvfs fs;
    valid = valid && !fstat(sampled, &status) && S_ISDIR(status.st_mode) &&
        status.st_uid == geteuid() && !(status.st_mode & (S_IWGRP | S_IWOTH)) &&
        !fstatvfs(sampled, &fs) && fs.f_frsize && (uint64_t)fs.f_bavail <= UINT64_MAX / fs.f_frsize;
    if (valid) {
        *volume = (YDRaftApplicationVolume){.device = status.st_dev,
            .available_bytes = (uint64_t)fs.f_bavail * fs.f_frsize, .allocation_unit = fs.f_frsize};
        *directory = fd;
    } else if (fd >= 0) close(fd);
    pthread_mutex_unlock(&r->lock);
    return valid;
}
YDRaftMembership yd_raft_runtime_membership(YDRaftRuntime *r) {
    if (!r) return (YDRaftMembership){0};
    pthread_mutex_lock(&r->lock);
    YDRaftMembership m = yd_raft_membership(r->raft);
    pthread_mutex_unlock(&r->lock);
    return m;
}
bool yd_raft_runtime_capture_locked(YDRaftRuntime *r, bool (*capture)(YDRaft *, void *), void *context) {
    if (!r || !capture) return false;
    pthread_mutex_lock(&r->lock);
    bool valid = !atomic_load(&r->stopping) && yd_raft_status(r->raft).role != YD_RAFT_FAILED &&
        capture(r->raft, context);
    if (yd_raft_status(r->raft).role == YD_RAFT_FAILED) stop_locked(r);
    pthread_mutex_unlock(&r->lock);
    return valid;
}
static int runtime_reconfigure(YDRaftRuntime *r, uint16_t voters,
    unsigned timeout_ms, YDRaftMembership *result) {
    if (result) *result = (YDRaftMembership){0};
    if (!r || !result || !timeout_ms || timeout_ms > 30000) return -1;
    uint64_t start = now();
    if (!start || start > UINT64_MAX - timeout_ms) return -1;
    uint64_t end = start + timeout_ms;
    struct timespec deadline = {.tv_sec = (time_t)(end / 1000),
        .tv_nsec = (long)(end % 1000) * 1000000};
    pthread_mutex_lock(&r->lock);
    int outcome = -1;
    YDRaftStatus s = yd_raft_status(r->raft);
    uint64_t term = s.term;
    YDRaftMembership m = yd_raft_membership(r->raft), valid_target;
    bool valid = !(voters & ~((1U << (r->voters + 1)) - 2)) &&
        yd_raft_membership_unpack(yd_raft_membership_pack((YDRaftMembership){
        .old_voters = voters, .new_voters = voters}), r->voters, &valid_target) &&
        !(voters & m.retired_voters) && (!m.joint || m.new_voters == voters);
    while (valid && !atomic_load(&r->stopping)) {
        s = yd_raft_status(r->raft);
        m = yd_raft_membership(r->raft);
        *result = m;
        if (!m.joint && m.new_voters == voters && m.index <= s.committed) {
            outcome = 1; break;
        }
        if (s.role != YD_RAFT_LEADER || s.term != term) break;
        outcome = 0;
        uint64_t index;
        if (!m.joint) (void)yd_raft_reconfigure(r->raft, voters, &index);
        if (!yd_raft_reconfigure_advance(r->raft)) break;
        yd_raft_member_probe(r->member);
        pthread_cond_broadcast(&r->wake);
        uint64_t time = now();
        if (!time || time >= end) break;
        int waited = pthread_cond_timedwait(&r->wake, &r->lock, &deadline);
        if (waited && waited != ETIMEDOUT) break;
    }
    *result = yd_raft_membership(r->raft);
    pthread_mutex_unlock(&r->lock);
    return outcome;
}
int yd_raft_runtime_reconfigure(YDRaftRuntime *r, uint16_t voters,
    unsigned timeout_ms, YDRaftMembership *result) {
    int cancellation;
    if (result) *result = (YDRaftMembership){0};
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancellation)) return -1;
    int outcome = runtime_reconfigure(r, voters, timeout_ms, result);
    /* pthread_cond_timedwait reacquires the runtime lock on cancellation.
     * Deliver a pending cancellation only after the operation releases it. */
    pthread_setcancelstate(cancellation, NULL);
    if (cancellation == PTHREAD_CANCEL_ENABLE) pthread_testcancel();
    return outcome;
}
bool yd_raft_runtime_propose(YDRaftRuntime *r, const void *command, size_t size, uint64_t *index) {
    *index = 0;
    pthread_mutex_lock(&r->lock);
    bool valid = !atomic_load(&r->stopping) && size <= r->budget &&
                 yd_raft_propose(r->raft, command, size, index);
    if (yd_raft_status(r->raft).role == YD_RAFT_FAILED)
        stop_locked(r);
    pthread_cond_broadcast(&r->wake);
    pthread_mutex_unlock(&r->lock);
    return valid;
}
bool yd_raft_runtime_propose_at(YDRaftRuntime *r, uint64_t term, uint64_t base,
                                 const void *command, size_t size, uint64_t *index) {
    *index = 0;
    pthread_mutex_lock(&r->lock);
    YDRaftStatus status = yd_raft_status(r->raft);
    bool valid = !atomic_load(&r->stopping) && status.role == YD_RAFT_LEADER &&
                 status.term == term && status.last == base && size <= r->budget &&
                 yd_raft_propose(r->raft, command, size, index);
    if (yd_raft_status(r->raft).role == YD_RAFT_FAILED)
        stop_locked(r);
    pthread_cond_broadcast(&r->wake);
    pthread_mutex_unlock(&r->lock);
    return valid;
}
bool yd_raft_runtime_barrier(YDRaftRuntime *r, unsigned timeout_ms, uint64_t *term,
                              uint64_t *index) {
    *term = *index = 0;
    if (!timeout_ms || timeout_ms > 30000)
        return false;
    uint64_t start = now();
    if (!start || start > UINT64_MAX - timeout_ms)
        return false;
    uint64_t end = start + timeout_ms;
    struct timespec deadline = {.tv_sec = (time_t)(end / 1000),
                               .tv_nsec = (long)(end % 1000) * 1000000};
    pthread_mutex_lock(&r->lock);
    YDRaftRead proof;
    bool begun = !atomic_load(&r->stopping) && yd_raft_read_begin(&r->reads, r->raft, &proof);
    if (begun) {
        r->read_waiters++;
        yd_raft_member_probe(r->member);
        pthread_cond_broadcast(&r->wake);
    }
    bool valid = false;
    while (begun && !atomic_load(&r->stopping)) {
        uint64_t time = now();
        if (!time || time >= end)
            break;
        YDRaftStatus status = yd_raft_status(r->raft);
        if (status.role != YD_RAFT_LEADER || status.term != proof.term)
            break;
        YDRaftMembership membership = yd_raft_membership(r->raft);
        if (membership.index != proof.membership.index ||
            membership.old_voters != proof.membership.old_voters ||
            membership.new_voters != proof.membership.new_voters) {
            /* A checkpoint can advance the membership epoch without changing
             * voters. Real configuration changes also require a new proof.
             * Keep the original deadline and require later acknowledgements. */
            if (!yd_raft_read_begin(&r->reads, r->raft, &proof))
                break;
            yd_raft_member_probe(r->member);
            pthread_cond_broadcast(&r->wake);
            continue;
        }
        if (yd_raft_read_ready(&r->reads, &proof, r->raft, index)) {
            time = now();
            if (time && time < end) {
                *term = proof.term;
                valid = true;
            }
            break;
        }
        if (yd_raft_status(r->raft).role == YD_RAFT_FAILED) {
            stop_locked(r);
            break;
        }
        time = now();
        if (!time || time >= end)
            break;
        int result = pthread_cond_timedwait(&r->wake, &r->lock, &deadline);
        if (result && result != ETIMEDOUT)
            break;
    }
    if (begun)
        r->read_waiters--;
    pthread_mutex_unlock(&r->lock);
    if (!valid)
        *term = *index = 0;
    return valid;
}
bool yd_raft_runtime_entry(YDRaftRuntime *r, uint64_t index, YDRaftEntry *entry) {
    memset(entry, 0, sizeof(*entry));
    pthread_mutex_lock(&r->lock);
    bool valid = !atomic_load(&r->stopping) && index <= yd_raft_status(r->raft).committed &&
                 yd_raft_entry(r->raft, index, entry);
    if (yd_raft_status(r->raft).role == YD_RAFT_FAILED)
        stop_locked(r);
    pthread_mutex_unlock(&r->lock);
    return valid;
}
void yd_raft_runtime_fence(YDRaftRuntime *r) {
    pthread_mutex_lock(&r->lock);
    stop_locked(r);
    pthread_mutex_unlock(&r->lock);
}
int yd_raft_runtime_wait(YDRaftRuntime *r, uint64_t after, unsigned timeout_ms) {
    if (!timeout_ms || timeout_ms > 30000)
        return -1;
    uint64_t start = now();
    if (!start || start > UINT64_MAX - timeout_ms)
        return -1;
    uint64_t end = start + timeout_ms;
    struct timespec deadline = {.tv_sec = (time_t)(end / 1000),
                               .tv_nsec = (long)(end % 1000) * 1000000};
    pthread_mutex_lock(&r->lock);
    int result = -1;
    while (!atomic_load(&r->stopping)) {
        YDRaftStatus status = yd_raft_status(r->raft);
        if (status.role == YD_RAFT_FAILED)
            break;
        if (status.committed > after) { result = 1; break; }
        uint64_t time = now();
        if (!time) break;
        if (time >= end) { result = 0; break; }
        int waited = pthread_cond_timedwait(&r->wake, &r->lock, &deadline);
        if (waited && waited != ETIMEDOUT) break;
    }
    pthread_mutex_unlock(&r->lock);
    return result;
}
