#define _GNU_SOURCE
#include "cluster.h"
#include "cluster_internal.h"
#include "session2_hooks.h"
#include "index_jobs.h"
#include "replica.h"
#include "backup.h"
#include "raft_internal.h"
#include "cluster_receive.h"
#include "checkpointer.h"
#include "compactor.h"
#include "application_worker.h"
#include "capture_internal.h"
#include "application_archive.h"
#include "application_internal.h"
#include "application_retire.h"
#include "archive_retention.h"
#include "../disk_internal.h"
#include "runtime_internal.h"
#include "recovery.h"
#include "snapshot_restore.h"
#include "snapshot_store_internal.h"
#include "../binary.h"
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
typedef struct {
    YDRaftApplication *application;
    unsigned char identity[32];
    YDRaftApplied origin;
    unsigned layout;
    atomic_size_t references;
} Generation;
struct YDRaftApplicationRetirement {
    Generation *previous;
    YDRaftRetiredFiles *files;
    unsigned char identity[32], cluster[16];
    YDStorageBudget *budget;
    YDStorageExtent extent;
    bool files_retired;
};
struct YDRaftView {
    Generation *generation;
    YDDiskView value;
};
struct YDRaftCluster {
    YDRaftRuntime *runtime;
    YDRaftIncoming *incoming;
    YDRaftCheckpointer *checkpointer;
    YDRaftCompactor *compactor;
    YDRaftApplicationWorker *application_worker;
    Generation *generation;
    YDRaftApplicationSlots *slots;
    YDStorageBudget *budget;
#define YD_RAFT_LIVE_ARCHIVES 8u
    YDRaftArchiveRetirement *archives[YD_RAFT_LIVE_ARCHIVES];
    uint64_t archive_charges[YD_RAFT_LIVE_ARCHIVES];
    uint64_t archive_bytes, archive_limit;
    pthread_mutex_t archives_lock;
    size_t archive_reserved;
    atomic_bool retention_active;
    bool archives_initialized, slots_failed, exposed;
    pthread_mutex_t retirement_lock;
    bool retirement_initialized;
    YDRaftApplicationRetirement *deferred_retirement;
    pthread_mutex_t lock;
    pthread_cond_t progress;
    pthread_t worker, index_worker;
    atomic_bool stopping;
    bool worker_started, index_worker_started, failed, writing, installing;
    int document_directory;
    size_t command_bytes, document_cache, journal_cache;
    unsigned char cluster[16];
    unsigned voters, node;
    uint32_t native_capabilities;
};
static void *index_jobs(void *context);
static YDRaftApplication *application(YDRaftCluster *c) { return c->generation->application; }
static bool empty_identity(const unsigned char identity[32]) {
    static const unsigned char zero[32];
    return !memcmp(identity, zero, 32);
}
static size_t archive_count_locked(YDRaftCluster *c) {
    size_t count = 0;
    for (size_t n = 0; n < YD_RAFT_LIVE_ARCHIVES; n++) count += c->archives[n] != NULL;
    return count;
}
static uint64_t archive_charge(uint64_t bytes) {
    return bytes && bytes <= UINT64_MAX - 4095 ? (bytes + 4095) & ~UINT64_C(4095) : 0;
}
/* Startup observation grants no custody. Every preexisting entry consumes
 * capacity forever in this process. Unmeasurable directories/aliases/changes
 * occupy the entire allowance; service may recover, publication must wait. */
static void archive_inventory(YDRaftCluster *c, const char *journal) {
    int root = open(journal, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int directory = root < 0 ? -1 : openat(root, YD_RAFT_ARCHIVE_DIRECTORY,
        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int absent_error = errno;
    if (root >= 0) close(root);
    if (directory < 0 && absent_error == ENOENT) return;
    struct stat before, after;
    DIR *scan = directory >= 0 && !fstat(directory, &before) &&
        S_ISDIR(before.st_mode) && before.st_uid == geteuid() &&
        !(before.st_mode & (S_IWGRP | S_IWOTH)) ? fdopendir(directory) : NULL;
    bool valid = scan != NULL;
    if (!scan && directory >= 0) close(directory);
    size_t entries = 0;
    while (valid) {
        errno = 0;
        struct dirent *entry = readdir(scan);
        if (!entry) { valid = !errno; break; }
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        struct stat file;
        if (++entries > YD_RAFT_LIVE_ARCHIVES || fstatat(directory, entry->d_name,
                &file, AT_SYMLINK_NOFOLLOW) || !S_ISREG(file.st_mode) || file.st_nlink != 1 ||
            file.st_uid != geteuid() || (file.st_mode & (S_IRWXG | S_IRWXO)) ||
            file.st_size < 0 || file.st_blocks < 0 || (uint64_t)file.st_blocks > UINT64_MAX / 512) {
            valid = false; break;
        }
        uint64_t bytes = (uint64_t)file.st_size;
        if ((uint64_t)file.st_blocks * 512 > bytes) bytes = (uint64_t)file.st_blocks * 512;
        uint64_t charge = archive_charge(bytes ? bytes : 1);
        if (!charge || charge > c->archive_limit || c->archive_bytes > c->archive_limit - charge) {
            valid = false; break;
        }
        c->archive_reserved++;
        c->archive_bytes += charge;
    }
    if (scan) {
        valid = valid && !fstat(directory, &after) && before.st_dev == after.st_dev &&
            before.st_ino == after.st_ino && before.st_mtim.tv_sec == after.st_mtim.tv_sec &&
            before.st_mtim.tv_nsec == after.st_mtim.tv_nsec;
        closedir(scan);
    }
    if (!valid) { c->archive_reserved = YD_RAFT_LIVE_ARCHIVES; c->archive_bytes = c->archive_limit; }
}
static bool archive_reserve(YDRaftCluster *c, uint64_t bytes, bool *reserved) {
    *reserved = false;
    uint64_t charge = archive_charge(bytes);
    pthread_mutex_lock(&c->archives_lock);
    bool valid = charge && archive_count_locked(c) + c->archive_reserved < YD_RAFT_LIVE_ARCHIVES &&
        c->archive_bytes <= c->archive_limit && charge <= c->archive_limit - c->archive_bytes;
    if (valid) { c->archive_reserved++; c->archive_bytes += charge; *reserved = true; }
    pthread_mutex_unlock(&c->archives_lock);
    return valid;
}
static bool archive_register(YDRaftCluster *c, bool reserved, uint64_t bytes, bool complete, int directory,
    const YDRaftSnapshotBase *base, const struct stat *publication,
    char *error, size_t length) {
    if (!reserved) return true;
    /* An attempted stage without durable completion can have left bytes. Keep
     * its full count/byte reservation for this live process, even after close. */
    if (!complete) return false;
    pthread_mutex_lock(&c->archives_lock);
    uint64_t charge = archive_charge(bytes);
    bool valid = true;
    if (publication) {
        size_t empty = YD_RAFT_LIVE_ARCHIVES;
        for (size_t n = 0; n < YD_RAFT_LIVE_ARCHIVES; n++) {
            YDRaftSnapshotBase known; struct stat file;
            if (!c->archives[n]) { if (empty == YD_RAFT_LIVE_ARCHIVES) empty = n; continue; }
            if (!yd_raft_archive_retirement_identity(c->archives[n], &known, &file)) { valid = false; break; }
            if (!memcmp(known.archive, base->archive, 32)) {
                valid = file.st_dev == publication->st_dev && file.st_ino == publication->st_ino;
                empty = YD_RAFT_LIVE_ARCHIVES;
                publication = NULL;
                break;
            }
        }
        if (valid && publication) {
            valid = empty < YD_RAFT_LIVE_ARCHIVES;
            if (valid) {
                c->archives[empty] = yd_raft_archive_retirement_prepare(directory, base,
                    publication, c->cluster, c->voters, error, length);
                valid = c->archives[empty] != NULL;
                if (valid) c->archive_charges[empty] = charge;
            }
        }
    }
    if (valid) {
        c->archive_reserved--;
        if (!publication) c->archive_bytes -= charge;
    }
    pthread_mutex_unlock(&c->archives_lock);
    return valid;
}
bool yd_raft_cluster_archive_reserve(YDRaftCluster *c, uint64_t bytes) {
    bool reserved = false;
    return c && archive_reserve(c, bytes, &reserved) && reserved;
}
bool yd_raft_cluster_archive_admit(YDRaftCluster *c, int *lease) {
    if (lease) *lease = -1;
    return c && yd_raft_runtime_archive_admit(c->runtime, lease);
}
bool yd_raft_cluster_archive_publication(YDRaftCluster *c, const YDRaftSnapshotOffer *offer,
    uint64_t bytes, const YDRaftSnapshotReference *reference, char *error, size_t length) {
    if (!c || !offer || !reference) return false;
    struct stat directory_identity, file;
    bool created = yd_raft_snapshot_reference_publication(reference, &directory_identity, &file);
    int directory = yd_raft_runtime_snapshot_directory(c->runtime);
    bool valid = directory >= 0 && archive_register(c, true, bytes, true, directory,
        &offer->base, created ? &file : NULL, error, length);
    if (directory >= 0) close(directory);
    return valid;
}
typedef struct {
    YDRaftArchiveRetirement *ticket;
    YDRaftArchiveCut *cut;
    int result;
    char *error;
    size_t length;
} ArchiveCleanup;
static bool archive_proof(void *context, const YDRaftSnapshotBase *base) {
    ArchiveCleanup *cleanup = context;
    (void)base;
    return yd_raft_runtime_archive_cut_validate(cleanup->cut);
}
static bool archive_cleanup(YDRaftArchiveCut *cut, void *context) {
    ArchiveCleanup *cleanup = context;
    cleanup->cut = cut;
    cleanup->result = yd_raft_archive_retirement_run(cleanup->ticket,
        archive_proof, cleanup, cleanup->error, cleanup->length);
    return cleanup->result >= 0;
}
/* Caller continuously owns installing; this takes no controller mutex and
 * cannot publish or recreate a dependency while its callback cut is held. */
static int archives_reconcile(YDRaftCluster *c, const unsigned char selected[32],
    char *error, size_t length) {
    int result = 1;
    pthread_mutex_lock(&c->archives_lock);
    for (size_t n = 0; n < YD_RAFT_LIVE_ARCHIVES; n++) {
        YDRaftSnapshotBase base; struct stat file;
        if (!c->archives[n]) continue;
        if (!yd_raft_archive_retirement_identity(c->archives[n], &base, &file)) { result = -1; break; }
        if (!memcmp(base.archive, selected, 32)) continue;
        ArchiveCleanup cleanup = {.ticket = c->archives[n], .error = error, .length = length};
        int cut = yd_raft_runtime_archive_cut_run(c->runtime, c->document_directory,
            base.archive, archive_cleanup, &cleanup, error, length);
        if (cut < 0) { result = -1; break; }
        if (cut == 1 && cleanup.result == 1) {
            yd_raft_archive_retirement_close(c->archives[n]);
            c->archives[n] = NULL;
            c->archive_bytes -= c->archive_charges[n];
            c->archive_charges[n] = 0;
        }
    }
    pthread_mutex_unlock(&c->archives_lock);
    return result;
}
static int archive_maintenance(YDRaftCluster *c, char *error, size_t length) {
    pthread_mutex_lock(&c->lock);
    bool valid = !c->failed && !atomic_load(&c->stopping) && !c->installing;
    unsigned char selected[32];
    if (valid) { c->installing = true; memcpy(selected, c->generation->identity, 32); }
    pthread_mutex_unlock(&c->lock);
    if (!valid) return 0;
    int result = archives_reconcile(c, selected, error, length);
    pthread_mutex_lock(&c->lock);
    c->installing = false;
    pthread_cond_broadcast(&c->progress);
    pthread_mutex_unlock(&c->lock);
    return result;
}
/* One controller-owned incoming replacement ticket. Serializing this owner is
 * independent of controller serialization; retirement acquires installing
 * itself and drops every cut before reacquiring the controller mutex. */
static int deferred_reconcile(YDRaftCluster *c, char *error, size_t length) {
    pthread_mutex_lock(&c->retirement_lock);
    int result = c->deferred_retirement
        ? yd_raft_cluster_application_retire(c, c->deferred_retirement, error, length) : 1;
    if (result == 1 && c->deferred_retirement) {
        yd_raft_application_retirement_close(c->deferred_retirement);
        c->deferred_retirement = NULL;
    }
    pthread_mutex_unlock(&c->retirement_lock);
    return result;
}
static bool generation_retain(Generation *generation) {
    size_t count = atomic_load_explicit(&generation->references, memory_order_relaxed);
    do {
        if (!count || count == SIZE_MAX)
            return false;
    } while (!atomic_compare_exchange_weak_explicit(&generation->references, &count, count + 1,
                memory_order_relaxed, memory_order_relaxed));
    return true;
}
static void generation_release(Generation *generation) {
    if (generation && atomic_fetch_sub_explicit(&generation->references, 1, memory_order_acq_rel) == 1) {
        yd_raft_application_close(generation->application);
        free(generation);
    }
}
static uint64_t now(void) {
    struct timespec t;
    return clock_gettime(CLOCK_MONOTONIC, &t)
               ? 0
               : (uint64_t)t.tv_sec * 1000 + (uint64_t)t.tv_nsec / 1000000;
}
static unsigned remaining(uint64_t end) {
    uint64_t time = now();
    return time && time < end ? (unsigned)(end - time) : 0;
}
static uint64_t deadline(unsigned ms) {
    uint64_t time = now();
    return ms && ms <= 30000 && time && time <= UINT64_MAX - ms ? time + ms : 0;
}
static bool wait_locked(YDRaftCluster *c, uint64_t end) {
    if (!remaining(end))
        return false;
    struct timespec t = {.tv_sec = (time_t)(end / 1000), .tv_nsec = (long)(end % 1000) * 1000000};
    int result = pthread_cond_timedwait(&c->progress, &c->lock, &t);
    return !result || result == ETIMEDOUT;
}
static bool available(YDRaftCluster *c) { return !c->failed && !atomic_load(&c->stopping); }
static void fence_locked(YDRaftCluster *c) {
    c->failed = true;
    yd_raft_runtime_fence(c->runtime);
    pthread_cond_broadcast(&c->progress);
}
static bool applied_locked(YDRaftCluster *c, uint64_t index, uint64_t end) {
    while (available(c) && yd_raft_application_position(application(c)).index < index)
        if (!wait_locked(c, end))
            return false;
    return available(c) && remaining(end) &&
           yd_raft_application_position(application(c)).index >= index;
}
static void *apply_entries(void *context) {
    (void)pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
    YDRaftCluster *c = context;
    for (;;) {
        pthread_mutex_lock(&c->lock);
        bool active = available(c);
        Generation *generation = c->generation;
        if (active && !generation_retain(generation)) {
            fence_locked(c);
            active = false;
        }
        uint64_t after = active ? yd_raft_application_position(generation->application).index : 0;
        pthread_mutex_unlock(&c->lock);
        if (!active)
            break;
        int ready = yd_raft_runtime_wait(c->runtime, after, 100);
        if (!ready) {
            generation_release(generation);
            continue;
        }
        YDRaftEntry entry = {0};
        bool valid = ready == 1 && after < UINT64_MAX &&
                     yd_raft_runtime_entry(c->runtime, after + 1, &entry);
        pthread_mutex_lock(&c->lock);
        if (available(c) && c->generation == generation) {
            char error[256];
            /* Backup may drain the application while this fetch is outside
             * the controller. A subsequent checkpoint can prune that entry. */
            if (after >= yd_raft_application_position(application(c)).index &&
                (!valid || !yd_raft_application_apply(application(c), &entry, error, sizeof(error))))
                fence_locked(c);
            pthread_cond_broadcast(&c->progress);
        }
        pthread_mutex_unlock(&c->lock);
        yd_raft_entry_free(&entry);
        generation_release(generation);
    }
    return NULL;
}
static bool distinct_roots(int first, const char *b) {
    if (first < 0 || !b)
        return false;
    int second = open(b, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    struct stat x, y;
    bool valid = second >= 0 && !fstat(first, &x) && S_ISDIR(x.st_mode) && !fstat(second, &y) &&
                 (x.st_dev != y.st_dev || x.st_ino != y.st_ino);
    if (second >= 0)
        close(second);
    return valid;
}
static bool recover_application(void *context, YDRaft *raft, char *error, size_t length) {
    YDRaftCluster *c = context;
    if (!yd_raft_backup_verify_pair(c->document_directory, raft->directory,
            c->cluster, c->node, c->voters, error, length)) return false;
    c->generation->application = yd_raft_recover_open_capabilities_origin_budgeted(c->document_directory, raft, c->native_capabilities, c->document_cache, c->budget,
        &c->generation->origin, NULL, NULL, error, length);
    if (application(c)) {
        yd_raft_application_generation(raft, c->generation->identity);
        c->generation->layout = raft->meta.application_layout;
    }
    return application(c) != NULL;
}
static void cancel_cluster(void *context) { yd_raft_cluster_close(context); }
static YDRaftCluster *adopt_cluster(YDRaftCluster *cluster, int cancellation) {
    pthread_cleanup_push(cancel_cluster, cluster);
    pthread_setcancelstate(cancellation, NULL);
    if (cancellation == PTHREAD_CANCEL_ENABLE) pthread_testcancel();
    pthread_cleanup_pop(0);
    return cluster;
}
YDRaftCluster *yd_raft_cluster_start(const YDRaftConfig *config, const char *document_root,
                                     size_t document_cache, YDTLS *tls, int listener, char *error,
                                     size_t length) {
    if (!document_root)
        return NULL;
    int cancellation;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancellation)) return NULL;
    int directory = open(document_root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (directory < 0)
        return adopt_cluster(NULL, cancellation);
    YDRaftCluster *cluster = yd_raft_cluster_start_at(config, directory, document_cache, tls, listener,
                                                      error, length);
    close(directory);
    return adopt_cluster(cluster, cancellation);
}
static YDRaftCluster *start_cluster(const YDRaftConfig *config, int document_directory,
                                        size_t document_cache, YDTLS *tls, int listener,
                                        char *error, size_t length) {
    if (!yd_raft_config_valid(config) || document_cache < 32768 ||
        document_cache > 1024ULL * 1024 * 1024 ||
        !distinct_roots(document_directory, config->journal_root))
        return NULL;
    YDRaftCluster *c = calloc(1, sizeof(*c));
    if (!c)
        return NULL;
    c->document_directory = -1;
    atomic_init(&c->stopping, false);
    atomic_init(&c->retention_active, false);
    c->command_bytes = config->command_bytes;
    c->document_cache = document_cache;
    c->journal_cache = config->cache_bytes;
    memcpy(c->cluster, config->cluster, sizeof(c->cluster));
    c->voters = config->voters;
    c->node = config->node;
    c->native_capabilities = config->native_capabilities;
    if (pthread_mutex_init(&c->lock, NULL)) {
        free(c);
        return NULL;
    }
    pthread_condattr_t attr;
    if (pthread_condattr_init(&attr)) {
        pthread_mutex_destroy(&c->lock);
        free(c);
        return NULL;
    }
    bool valid = !pthread_condattr_setclock(&attr, CLOCK_MONOTONIC) &&
                 !pthread_cond_init(&c->progress, &attr);
    pthread_condattr_destroy(&attr);
    if (!valid) {
        pthread_mutex_destroy(&c->lock);
        free(c);
        return NULL;
    }
    if (pthread_mutex_init(&c->archives_lock, NULL)) goto invalid;
    c->archives_initialized = true;
    if (pthread_mutex_init(&c->retirement_lock, NULL)) goto invalid;
    c->retirement_initialized = true;
    YDStorageLimits storage_limits;
    if (!yd_storage_budget_configure(&storage_limits, error, length) ||
        !(c->budget = yd_storage_budget_new(storage_limits))) goto invalid;
    c->archive_limit = storage_limits.extent_bytes;
    c->generation = calloc(1, sizeof(*c->generation));
    if (!c->generation)
        goto invalid;
    atomic_init(&c->generation->references, 1);
    c->document_directory = fcntl(document_directory, F_DUPFD_CLOEXEC, 0);
    struct stat directory, initializing;
    if (c->document_directory < 0 || fstat(c->document_directory, &directory) ||
        directory.st_uid != geteuid() || (directory.st_mode & (S_IWGRP | S_IWOTH)) ||
        flock(c->document_directory, LOCK_EX | LOCK_NB)) {
        if (error && length)
            snprintf(error, length, "data directory is unavailable or already has a writer");
        goto invalid;
    }
    /* Reject the durable fence before creating a journal or starting peers. */
    if (!fstatat(c->document_directory, YD_BINARY_INITIALIZING, &initializing, AT_SYMLINK_NOFOLLOW) ||
        errno != ENOENT) {
        if (error && length)
            snprintf(error, length, "incomplete consensus document initialization");
        goto invalid;
    }
    c->runtime = yd_raft_runtime_start_retaining_budgeted(config, tls, listener, recover_application, c, c->budget,
                                                error, length);
    if (!c->runtime)
        goto invalid;
    archive_inventory(c, config->journal_root);
    if (pthread_create(&c->worker, NULL, apply_entries, c))
        goto invalid;
    c->worker_started = true;
    c->incoming = yd_raft_incoming_new(c, config->cluster, config->node, config->voters);
    if (!c->incoming || !yd_raft_runtime_receive(c->runtime, yd_raft_incoming_handle, c->incoming))
        goto invalid;
    if (pthread_create(&c->index_worker, NULL, index_jobs, c)) goto invalid;
    c->index_worker_started = true;
    c->exposed = true;
    return c;
invalid:
    yd_raft_cluster_close(c);
    return NULL;
}
YDRaftCluster *yd_raft_cluster_start_at(const YDRaftConfig *config, int document_directory,
    size_t document_cache, YDTLS *tls, int listener, char *error, size_t length) {
    int cancellation;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancellation)) return NULL;
    YDRaftCluster *cluster = start_cluster(config, document_directory, document_cache,
        tls, listener, error, length);
    return adopt_cluster(cluster, cancellation);
}
void yd_raft_cluster_close(YDRaftCluster *c) {
    if (!c)
        return;
    int cancellation;
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancellation);
    /* Deliver atomic cancellation even when final inventory holds c->lock. */
    yd_raft_application_worker_stop(c->application_worker);
    pthread_mutex_lock(&c->lock);
    atomic_store(&c->stopping, true);
    pthread_cond_broadcast(&c->progress);
    pthread_mutex_unlock(&c->lock);
    if (c->index_worker_started) pthread_join(c->index_worker, NULL);
    yd_raft_incoming_shutdown(c->incoming);
    yd_raft_application_worker_close(c->application_worker);
    yd_raft_compactor_close(c->compactor);
    yd_raft_checkpointer_close(c->checkpointer);
    if (c->worker_started)
        pthread_join(c->worker, NULL);
    if (c->exposed && yd_raft_runtime_drain(c->runtime))
        (void)yd_raft_runtime_finalize(c->runtime, NULL, 0);
    yd_raft_runtime_stop(c->runtime);
    yd_raft_incoming_close(c->incoming);
    yd_raft_application_retirement_close(c->deferred_retirement);
    generation_release(c->generation);
    for (size_t n = 0; n < YD_RAFT_LIVE_ARCHIVES; n++) yd_raft_archive_retirement_close(c->archives[n]);
    yd_raft_application_slots_close(c->slots);
    yd_storage_budget_close(c->budget);
    if (c->archives_initialized) pthread_mutex_destroy(&c->archives_lock);
    if (c->retirement_initialized) pthread_mutex_destroy(&c->retirement_lock);
    if (c->document_directory >= 0)
        close(c->document_directory);
    pthread_cond_destroy(&c->progress);
    pthread_mutex_destroy(&c->lock);
    free(c);
    pthread_setcancelstate(cancellation, NULL);
}
YDRaftClusterStatus yd_raft_cluster_status(YDRaftCluster *c) {
    pthread_mutex_lock(&c->lock);
    YDRaftClusterStatus status = {.raft = yd_raft_runtime_status(c->runtime),
                                  .applied = yd_raft_application_position(application(c)),
                                  .checkpoints = yd_raft_checkpointer_status(c->checkpointer),
                                  .compaction = yd_raft_compactor_status(c->compactor),
                                  .application_compaction = yd_raft_application_worker_status(c->application_worker),
                                  .failed = !available(c)};
    pthread_mutex_unlock(&c->lock);
    return status;
}
bool yd_raft_cluster_checkpoints(YDRaftCluster *c, YDRaftCheckpointPolicy policy) {
    if (!c || !policy.entries || policy.entries > 1000000000 ||
        policy.interval_ms < 100 || policy.interval_ms > 3600000 ||
        policy.timeout_ms < 100 || policy.timeout_ms > 30000)
        return false;
    pthread_mutex_lock(&c->lock);
    bool valid = available(c) && c->command_bytes >= YD_RAFT_SNAPSHOT_MANIFEST && !c->checkpointer;
    if (valid) valid = (c->checkpointer = yd_raft_checkpointer_new(c, policy)) != NULL;
    pthread_mutex_unlock(&c->lock);
    return valid;
}
bool yd_raft_cluster_compactions(YDRaftCluster *c, YDRaftCompactionPolicy policy) {
    if (!c) return false;
    pthread_mutex_lock(&c->lock);
    bool valid = available(c) && !c->compactor && yd_raft_runtime_journal_replaceable(c->runtime);
    if (valid) valid = (c->compactor = yd_raft_compactor_new(c->runtime, c->journal_cache, policy)) != NULL;
    pthread_mutex_unlock(&c->lock);
    return valid;
}
bool yd_raft_cluster_application_compactions(YDRaftCluster *c, YDRaftApplicationWorkerPolicy policy) {
    if (!c) return false;
    pthread_mutex_lock(&c->lock);
    bool valid = available(c) && !c->application_worker;
    if (valid) valid = (c->application_worker =
        yd_raft_application_worker_new(c, c->document_cache, policy)) != NULL;
    pthread_mutex_unlock(&c->lock);
    return valid;
}
bool yd_raft_cluster_application_compaction_due(YDRaftCluster *c) {
    if (!c) return false;
    pthread_mutex_lock(&c->lock);
    YDRaftStatus status = yd_raft_runtime_status(c->runtime);
    YDRaftApplied applied = yd_raft_application_position(application(c));
    bool due = available(c) && status.role != YD_RAFT_FAILED && !c->writing && !c->installing &&
        applied.index && applied.index == status.committed && applied.index > c->generation->origin.index;
    pthread_mutex_unlock(&c->lock);
    return due;
}
YDRaftSnapshotBase yd_raft_cluster_checkpoint_base(YDRaftCluster *c) {
    if (!c) return (YDRaftSnapshotBase){0};
    pthread_mutex_lock(&c->lock);
    YDRaftSnapshotBase base = yd_raft_runtime_checkpoint_base(c->runtime);
    pthread_mutex_unlock(&c->lock);
    return base;
}
bool yd_raft_cluster_checkpoint_due(YDRaftCluster *c, uint64_t entries, uint64_t *term) {
    if (term) *term = 0;
    if (!c || !entries || !term) return false;
    pthread_mutex_lock(&c->lock);
    YDRaftStatus status = yd_raft_runtime_status(c->runtime);
    YDRaftSnapshotBase base = yd_raft_runtime_checkpoint_base(c->runtime);
    bool due = available(c) && status.role == YD_RAFT_LEADER &&
        status.committed >= base.index && status.committed - base.index >= entries;
    if (due) *term = status.term;
    pthread_mutex_unlock(&c->lock);
    return due;
}
bool yd_raft_cluster_snapshot_contact(YDRaftCluster *c, const YDRaftSnapshotOffer *offer, bool *needed) {
    if (needed) *needed = false;
    if (!c || !needed) return false;
    pthread_mutex_lock(&c->lock);
    bool valid = available(c) && yd_raft_runtime_snapshot_contact(c->runtime, offer, needed);
    if (yd_raft_runtime_status(c->runtime).role == YD_RAFT_FAILED) fence_locked(c);
    pthread_cond_broadcast(&c->progress);
    pthread_mutex_unlock(&c->lock);
    return valid;
}
bool yd_raft_cluster_snapshot_confirmed(YDRaftCluster *c, const YDRaftSnapshotOffer *offer) {
    if (!c || !offer) return false;
    pthread_mutex_lock(&c->lock);
    YDRaftStatus status = yd_raft_runtime_status(c->runtime);
    bool failed = yd_raft_application_failed(application(c));
    bool valid = available(c) && !failed && status.role == YD_RAFT_FOLLOWER &&
        offer->from && offer->from <= c->voters && offer->from != status.node &&
        !memcmp(offer->cluster, c->cluster, 16) && offer->term && offer->term == status.term &&
        status.leader == (offer->configuration_delivery ? 0 : offer->from) &&
        offer->base.index && offer->base.index <= UINT64_MAX - 2 &&
        offer->base.term && offer->base.term <= offer->term && status.committed >= offer->base.index &&
        yd_raft_application_position(application(c)).index >= offer->base.index;
    if (failed || status.role == YD_RAFT_FAILED) fence_locked(c);
    pthread_mutex_unlock(&c->lock);
    return valid;
}
int yd_raft_cluster_snapshot_directory(YDRaftCluster *c) {
    if (!c) return -1;
    pthread_mutex_lock(&c->lock);
    int directory = available(c) ? yd_raft_runtime_snapshot_directory(c->runtime) : -1;
    pthread_mutex_unlock(&c->lock);
    return directory;
}
static YDRaftApplicationCapture *cluster_application_capture(YDRaftCluster *c, size_t cache,
    char *error, size_t length) {
    if (!c) return NULL;
    pthread_mutex_lock(&c->lock);
    YDRaftApplicationCapture *volatile capture = available(c)
        ? yd_raft_application_capture(application(c), cache, error, length) : NULL;
    if (yd_raft_application_failed(application(c)) ||
        yd_raft_runtime_status(c->runtime).role == YD_RAFT_FAILED) fence_locked(c);
    pthread_mutex_unlock(&c->lock);
    return capture;
}
static void cancel_application_capture(void *context) {
    yd_raft_application_capture_close(context);
}
YDRaftApplicationCapture *yd_raft_cluster_application_capture(YDRaftCluster *c, size_t cache,
    char *error, size_t length) {
    int previous;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous)) return NULL;
    YDRaftApplicationCapture *capture = cluster_application_capture(c, cache, error, length);
    pthread_cleanup_push(cancel_application_capture, capture);
    (void)pthread_setcancelstate(previous, NULL);
    if (previous == PTHREAD_CANCEL_ENABLE) pthread_testcancel();
    pthread_cleanup_pop(0);
    return capture;
}
typedef struct {
    YDRaftCluster *cluster;
    YDRaftSnapshotProgress progress;
    void *context;
} Capturing;
static bool capture_progress(void *context, uint64_t done, uint64_t total) {
    Capturing *capturing = context;
    return !atomic_load(&capturing->cluster->stopping) &&
        (!capturing->progress || capturing->progress(capturing->context, done, total));
}
static YDRaftCapture *cluster_capture(YDRaftCluster *c, unsigned timeout_ms,
                                        YDRaftSnapshotProgress progress, void *context,
                                        char *error, size_t length) {
    if (!c || deferred_reconcile(c, error, length) < 0 || archive_maintenance(c, error, length) < 0) return NULL;
    int archive_lease = -1;
    if (!yd_raft_cluster_archive_admit(c, &archive_lease)) return NULL;
    uint64_t end = deadline(timeout_ms), term, index;
    unsigned ms = remaining(end);
    if (!end || !ms || !yd_raft_runtime_barrier(c->runtime, ms, &term, &index)) {
        if (archive_lease >= 0) close(archive_lease);
        return NULL;
    }
    bool reserved = false;
    uint64_t archive_bytes = 0;
    Generation *generation = NULL;
    YDRaftSnapshot *image = NULL;
    YDRaftCaptureOrigin origin = {.voters = c->voters, .term = term};
    memcpy(origin.cluster, c->cluster, sizeof(origin.cluster));
    pthread_mutex_lock(&c->lock);
    if (applied_locked(c, index, end)) {
        YDRaftStatus status = yd_raft_runtime_status(c->runtime);
        if (status.role == YD_RAFT_LEADER && status.term == term &&
            generation_retain(c->generation)) {
            generation = c->generation;
            origin.node = status.node;
            image = yd_raft_snapshot_open(generation->application, c->voters, error, length);
            YDDiskView view = yd_disk_view(yd_raft_application_disk(generation->application));
            if (view.end <= INT64_MAX - YD_RAFT_SNAPSHOT_MANIFEST)
                archive_bytes = view.end + YD_RAFT_SNAPSHOT_MANIFEST;
        }
    }
    if (yd_raft_application_failed(application(c)) ||
        yd_raft_runtime_status(c->runtime).role == YD_RAFT_FAILED) fence_locked(c);
    pthread_mutex_unlock(&c->lock);
    if (image && !archive_reserve(c, archive_bytes, &reserved)) {
        yd_raft_snapshot_close(image);
        generation_release(generation);
        yd_disk_error(error, length, "live archive capacity is occupied");
        if (archive_lease >= 0) close(archive_lease);
        return NULL;
    }
    int directory = image ? yd_raft_runtime_snapshot_directory(c->runtime) : -1;
    Capturing capturing = {.cluster = c, .progress = progress, .context = context};
    YDRaftCapture *volatile capture = image && directory >= 0 ? yd_raft_capture_new_limited(image,
        yd_raft_application_disk(generation->application), directory, &origin, archive_bytes, NULL,
        capture_progress, &capturing, error, length) : NULL;
    YDRaftSnapshotBase base = {0};
    struct stat publication_directory, publication;
    bool created = capture && yd_raft_capture_publication(capture, &base,
        &publication_directory, &publication);
    if (!archive_register(c, reserved, archive_bytes, capture || directory < 0, directory, &base,
            created ? &publication : NULL, error, length)) {
        yd_raft_capture_close(capture);
        capture = NULL;
    }
    if (directory >= 0) close(directory);
    yd_raft_snapshot_close(image);
    generation_release(generation);
    if (archive_lease >= 0) close(archive_lease);
    return capture;
}
static void cancel_owned_capture(void *context) { yd_raft_capture_close(context); }
YDRaftCapture *yd_raft_cluster_capture(YDRaftCluster *c, unsigned timeout_ms,
    YDRaftSnapshotProgress progress, void *context, char *error, size_t length) {
    int previous;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous)) return NULL;
    YDRaftCapture *capture = cluster_capture(c, timeout_ms, progress, context, error, length);
    pthread_cleanup_push(cancel_owned_capture, capture);
    (void)pthread_setcancelstate(previous, NULL);
    if (previous == PTHREAD_CANCEL_ENABLE) pthread_testcancel();
    pthread_cleanup_pop(0);
    return capture;
}
bool yd_raft_cluster_checkpoint(YDRaftCluster *c, const YDRaftCapture *capture,
                                  unsigned timeout_ms) {
    uint64_t end = deadline(timeout_ms), term, index;
    unsigned ms = remaining(end);
    if (!c || !capture || !end || !ms ||
        !yd_raft_runtime_barrier(c->runtime, ms, &term, &index))
        return false;
    pthread_mutex_lock(&c->lock);
    YDRaftStatus status = yd_raft_runtime_status(c->runtime);
    YDRaftCaptureOrigin origin = {.voters = c->voters, .node = status.node, .term = term};
    memcpy(origin.cluster, c->cluster, sizeof(origin.cluster));
    YDRaftSnapshotBase base;
    bool valid = available(c) && remaining(end) && status.role == YD_RAFT_LEADER &&
        status.term == term && yd_raft_capture_origin(capture, &origin, &base) &&
        base.index <= index && yd_raft_runtime_checkpoint(c->runtime, term, &base);
    if (yd_raft_runtime_status(c->runtime).role == YD_RAFT_FAILED) fence_locked(c);
    pthread_cond_broadcast(&c->progress);
    pthread_mutex_unlock(&c->lock);
    return valid;
}
typedef struct {
    YDRaftCluster *cluster;
    uint64_t end;
    bool background;
    YDRaftSnapshotOffer offer;
} Installation;
static bool directory_trusted(int directory) {
    struct stat status;
    return directory >= 0 && !fstat(directory, &status) && S_ISDIR(status.st_mode) &&
        status.st_uid == geteuid() && !(status.st_mode & (S_IWGRP | S_IWOTH));
}
static bool install_current(YDRaftCluster *c, const YDRaftSnapshotOffer *offer) {
    YDRaftStatus status = yd_raft_runtime_status(c->runtime);
    unsigned char archive = 0;
    for (unsigned i = 0; i < sizeof(offer->base.archive); i++) archive |= offer->base.archive[i];
    return available(c) && offer->from && offer->from <= c->voters && offer->from != status.node &&
        offer->term && offer->base.term && offer->base.term <= offer->term &&
        offer->base.index <= UINT64_MAX - 2 && archive &&
        !memcmp(c->cluster, offer->cluster, sizeof(c->cluster)) &&
        status.role == YD_RAFT_FOLLOWER && status.term == offer->term &&
        status.leader == (offer->configuration_delivery ? 0 : offer->from) &&
        offer->base.index > status.committed;
}
static bool install_progress(void *context, uint64_t done, uint64_t total) {
    (void)done; (void)total;
    Installation *install = context;
    YDRaftCluster *c = install->cluster;
    if (atomic_load(&c->stopping)) return false;
    if (!install->background) return remaining(install->end);
    pthread_mutex_lock(&c->lock);
    bool valid = install_current(c, &install->offer);
    pthread_mutex_unlock(&c->lock);
    return valid;
}
static bool preserving_incoming_space(YDRaftCluster *c, uint64_t incoming,
    char *error, size_t length) {
    YDRaftApplicationSpace space;
    YDStorageUsage usage;
    bool valid = yd_raft_application_documents_preserving(c->document_directory,
        yd_raft_application_disk(application(c))->fd, c->cluster, c->voters, &space, error, length) &&
        yd_storage_budget_usage(c->budget, &usage);
    uint64_t copy = incoming ? archive_charge(incoming) : 0;
    if (valid && incoming) valid = copy && copy <= UINT64_MAX - 4096;
    if (incoming && valid) copy += 4096; /* Native and manifest allocations. */
    /* Count the observed tree as well as the live ledger conservatively.
     * Observation never refunds an old extent or grants unlink authority. */
    if (valid) valid = space.documents.retained_bytes <= c->archive_limit &&
        usage.used.extent_bytes <= c->archive_limit - space.documents.retained_bytes &&
        copy <= c->archive_limit - space.documents.retained_bytes - usage.used.extent_bytes &&
        copy <= space.documents.available_bytes;
    if (!valid && error && length && !error[0])
        yd_disk_error(error, length, "preserved incoming application capacity unavailable");
    return valid;
}
static Generation *generation_candidate(YDRaftCluster *c, const YDRaftSnapshotBase *base,
    const YDRaftSnapshotReference *reference,
    const YDRaftApplicationLimits *limits, YDDiskAllocation *usage,
    YDRaftSnapshotProgress progress, void *context, bool fixed, bool preserving,
    char *error, size_t length) {
    char id[YD_RAFT_SNAPSHOT_ID];
    static const char hex[] = "0123456789abcdef";
    for (unsigned i = 0; i < 32; i++) {
        id[2 * i] = hex[base->archive[i] >> 4];
        id[2 * i + 1] = hex[base->archive[i] & 15];
    }
    id[64] = 0;
    int directory = reference ? -1 : yd_raft_runtime_snapshot_directory(c->runtime);
    YDRaftSnapshotStore *store = reference ? NULL : yd_raft_snapshot_store_open_at(directory, c->cluster, c->voters,
                                                                 error, length);
    if (directory >= 0) close(directory);
    YDRaftSnapshotArchive *archive = NULL;
    if (reference)
        (void)yd_raft_snapshot_archive_open_reference(reference, progress, context, &archive, error, length);
    else if (store) archive = yd_raft_snapshot_archive_open(store, id, progress, context, error, length);
    yd_raft_snapshot_store_close(store);
    unsigned char manifest[YD_RAFT_SNAPSHOT_MANIFEST];
    YDRaftSnapshotInfo info;
    unsigned char digest[32]; size_t digest_size = 0;
    bool valid = archive && yd_raft_snapshot_archive_manifest(archive, manifest) &&
        EVP_Q_digest(NULL, "SHA256", NULL, manifest, sizeof(manifest), digest, &digest_size) == 1 &&
        digest_size == sizeof(digest) && !memcmp(digest, base->archive, sizeof(digest)) &&
        yd_raft_snapshot_decode(manifest, sizeof(manifest), c->cluster, c->voters, &info, error, length) &&
        info.capabilities == c->native_capabilities &&
        info.applied.index == base->index && info.applied.term == base->term &&
        (!limits || info.view.end <= limits->restore_bytes) &&
        (!progress || progress(context, 0, 0));
    if (valid && preserving)
        valid = preserving_incoming_space(c, info.view.end, error, length);
    int parent = -1, child = -1;
    unsigned slot = 0;
    bool bound_slot = false;
    char pending[43] = {0};
    Generation *generation = NULL;
    if (valid && fixed) {
        int owned = -1;
        /* A timed-out publication can leave a complete, live-owned candidate.
         * Revalidate that exact slot instead of binding its identity twice. */
        bound_slot = c->slots && yd_raft_application_slots_find(c->slots,
            base->archive, &slot, &owned);
        valid = bound_slot || (c->slots && yd_raft_application_slots_acquire(c->slots, &slot,
            &owned, error, length) == 1);
        child = valid ? fcntl(owned, F_DUPFD_CLOEXEC, 0) : -1;
        valid = valid && directory_trusted(child);
        if (valid && !bound_slot)
            valid = yd_raft_snapshot_restore_at_budgeted(archive, child, c->cluster, c->voters,
                c->document_cache, c->budget, limits ? limits->restore_bytes : YD_DISK_ALLOCATION_UNLIMITED,
                usage, progress, context, error, length);
    }
    if (valid && !fixed) {
        valid = !mkdirat(c->document_directory, YD_RAFT_GENERATION_DIRECTORY, 0700) || errno == EEXIST;
        parent = valid ? openat(c->document_directory, YD_RAFT_GENERATION_DIRECTORY,
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC) : -1;
        valid = valid && directory_trusted(parent);
    }
    if (valid && !fixed) {
        child = openat(parent, id, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        bool created = false;
        valid = child >= 0 || errno == ENOENT;
        for (unsigned attempt = 0; valid && child < 0 && attempt < 8; attempt++) {
            unsigned char nonce[16];
            valid = RAND_bytes(nonce, sizeof(nonce)) == 1;
            if (!valid) break;
            memcpy(pending, ".incoming-", 10);
            for (unsigned i = 0; i < sizeof(nonce); i++) {
                pending[10 + 2 * i] = hex[nonce[i] >> 4];
                pending[11 + 2 * i] = hex[nonce[i] & 15];
            }
            if (!mkdirat(parent, pending, 0700)) {
                created = true;
                child = openat(parent, pending, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
                break;
            }
            valid = errno == EEXIST;
        }
        if (!created) pending[0] = 0;
        valid = valid && directory_trusted(child) && !flock(child, LOCK_EX | LOCK_NB);
        if (valid && created)
            valid = yd_raft_snapshot_restore_at_budgeted(archive, child, c->cluster, c->voters,
                c->document_cache, c->budget, limits ? limits->restore_bytes : YD_DISK_ALLOCATION_UNLIMITED,
                usage, progress, context, error, length);
    }
    if (valid) {
        generation = calloc(1, sizeof(*generation));
        if (generation) {
            atomic_init(&generation->references, 1);
            generation->application = yd_raft_candidate_open_budgeted_at(child, manifest, c->cluster,
                c->voters, c->document_cache, c->budget, progress, context, error, length);
            valid = generation->application && !fsync(child);
            if (valid && fixed && !bound_slot)
                valid = yd_raft_application_slots_bind(c->slots, slot,
                    yd_raft_application_disk(generation->application)->fd, base->archive, error, length);
            /* Only a complete, validated candidate receives the journal's
             * resolvable name. A crash during copying leaves a fenced incoming
             * sibling, so retry never needs to overwrite or delete that data. */
            if (valid && pending[0])
                valid = !renameat2(parent, pending, parent, id, RENAME_NOREPLACE);
            valid = valid && (parent < 0 || !fsync(parent)) && !fsync(c->document_directory) &&
                (!progress || progress(context, 0, 0));
            if (valid && preserving) valid = preserving_incoming_space(c, 0, error, length);
        } else valid = false;
    }
    if (child >= 0) close(child);
    if (parent >= 0) close(parent);
    yd_raft_snapshot_archive_close(archive);
    if (!valid) {
        generation_release(generation);
        return NULL;
    }
    memcpy(generation->identity, base->archive, sizeof(generation->identity));
    generation->origin = (YDRaftApplied){.index = base->index, .term = base->term};
    generation->layout = fixed ? 1 : 0;
    return generation;
}
typedef struct {
    YDRaftCluster *cluster;
    Generation *next, *previous;
} Publication;
static void publish_generation(void *context) {
    Publication *publication = context;
    publication->previous = publication->cluster->generation;
    publication->cluster->generation = publication->next;
}
static YDRaftApplicationRetirement *retirement_prepare(YDRaftCluster *c, Generation *source,
    bool slots, char *error, size_t length) {
    YDRaftApplicationRetirement *ticket = calloc(1, sizeof(*ticket));
    if (!ticket) return NULL;
    memcpy(ticket->identity, source->identity, sizeof(ticket->identity));
    memcpy(ticket->cluster, c->cluster, sizeof(ticket->cluster));
    ticket->budget = yd_storage_budget_retain(c->budget);
    YDDisk *native = yd_raft_application_disk(source->application);
    bool budgeted = ticket->budget && yd_disk_budget_extent(native, &ticket->extent);
    ticket->files = slots ? yd_raft_retired_files_prepare_slots(c->slots, native->fd,
        source->identity, error, length) : yd_raft_retired_files_prepare(c->document_directory,
        native->fd, source->identity, c->cluster, c->voters, error, length);
    if (ticket->files && budgeted) return ticket;
    yd_raft_application_retirement_close(ticket);
    return NULL;
}
bool yd_raft_cluster_application_select(YDRaftCluster *c, YDRaftApplicationImage *image,
    unsigned admission_ms, YDRaftSnapshotProgress progress, void *context, bool *published,
    char *error, size_t length) {
    return yd_raft_cluster_application_select_retaining(c, image, admission_ms, progress, context,
                                                         published, NULL, error, length);
}
bool yd_raft_cluster_application_select_retaining(YDRaftCluster *c, YDRaftApplicationImage *image,
    unsigned admission_ms, YDRaftSnapshotProgress progress, void *context, bool *published,
    YDRaftApplicationRetirement **retirement, char *error, size_t length) {
    return yd_raft_cluster_application_select_outcome(c, image, admission_ms, progress, context,
        published, retirement, error, length) == YD_RAFT_APPLICATION_SELECTED;
}
typedef struct {
    YDRaftCluster *cluster;
    YDRaftSnapshotProgress progress;
    void *context;
    bool cancelled;
} SelectionProgress;
static bool selection_progress(void *context, uint64_t done, uint64_t total) {
    SelectionProgress *p = context;
    if (atomic_load(&p->cluster->stopping) || p->cancelled) return false;
    if (p->progress && !p->progress(p->context, done, total)) p->cancelled = true;
    return !p->cancelled;
}
static bool image_at(YDRaftApplicationImage *image, int workspace) {
    struct stat opened, named;
    YDDisk *disk = yd_raft_application_image_disk(image);
    return disk && workspace >= 0 && !fstat(disk->fd, &opened) &&
        !fstatat(workspace, YD_DISK_FILE, &named, AT_SYMLINK_NOFOLLOW) &&
        S_ISREG(named.st_mode) && named.st_nlink == 1 && named.st_uid == geteuid() &&
        !(named.st_mode & (S_IRWXG | S_IRWXO)) &&
        opened.st_dev == named.st_dev && opened.st_ino == named.st_ino;
}
static bool retirement_shells(YDRaftCluster *c, YDRaftApplicationRetirement *const *retained,
    size_t count, int shells[YD_RAFT_APPLICATION_SHELLS], size_t *used) {
    *used = 0;
    if (count > YD_RAFT_APPLICATION_SHELLS / 2 || (count && !retained)) return false;
    for (size_t n = 0; n < count; n++) {
        int custody = -1, generation = -1;
        YDRaftApplicationRetirement *ticket = retained[n];
        if (!ticket || ticket->previous || memcmp(ticket->cluster, c->cluster, sizeof(c->cluster)) ||
            !memcmp(ticket->identity, c->generation->identity, sizeof(ticket->identity)) ||
            !yd_raft_retired_files_account(ticket->files, c->document_directory, &custody, &generation))
            return false;
        shells[(*used)++] = custody;
        if (generation >= 0) shells[(*used)++] = generation;
    }
    return true;
}
static bool admission_locked(YDRaftCluster *c, YDRaftApplicationImage *image,
    int workspace, YDRaftApplicationWorkspace *owned, YDRaftApplicationRetirement *const *retained,
    size_t retained_count, const char *replacement, YDRaftApplicationLimits limits,
    YDRaftApplicationAdmissionReport *report, char *error, size_t length) {
    report->space = (YDRaftApplicationSpace){0};
    int directory = -1;
    YDRaftApplicationVolume volume = {0};
    bool valid = (!image || image_at(image, workspace)) &&
        yd_raft_runtime_snapshot_observe(c->runtime, &directory, &volume);
    int owned_directory = -1, custody = -1;
    if (valid && owned)
        valid = directory >= 0 && yd_raft_application_workspace_account(owned, directory,
            &owned_directory, &custody) && owned_directory == workspace;
    int shells[YD_RAFT_APPLICATION_SHELLS];
    int slot_directories[YD_RAFT_APPLICATION_SLOTS], slot_custody = -1;
    size_t shell_count = 0;
    if (valid) valid = c->slots
        ? !retained_count && yd_raft_application_slots_account(c->slots, c->document_directory,
            slot_directories, &slot_custody)
        : retirement_shells(c, retained, retained_count, shells, &shell_count);
    if (valid) valid = directory >= 0
        ? c->slots
            ? yd_raft_application_space_with_slots(c->document_directory, directory,
                workspace, custody, slot_directories, YD_RAFT_APPLICATION_SLOTS, slot_custody,
                yd_raft_application_disk(application(c))->fd, replacement, c->cluster,
                c->voters, &report->space, error, length)
            : retained_count
            ? yd_raft_application_space_with_shells(c->document_directory, directory,
                workspace, custody, shells, shell_count, yd_raft_application_disk(application(c))->fd,
                replacement, c->cluster, c->voters, &report->space, error, length)
            : owned
            ? yd_raft_application_space_with_custody(c->document_directory, directory,
                workspace, custody, yd_raft_application_disk(application(c))->fd, replacement,
                c->cluster, c->voters, &report->space, error, length)
            : yd_raft_application_space(c->document_directory, directory,
                workspace, yd_raft_application_disk(application(c))->fd, replacement,
                c->cluster, c->voters, &report->space, error, length)
        : !owned && workspace < 0 && !replacement && yd_raft_application_space_empty_archives(
            c->document_directory, yd_raft_application_disk(application(c))->fd, volume,
            c->cluster, c->voters, &report->space, error, length);
    if (valid && owned) {
        int checked_directory = -1, checked_custody = -1;
        valid = yd_raft_application_workspace_account(owned, directory,
            &checked_directory, &checked_custody) && checked_directory == owned_directory &&
            checked_custody == custody;
    }
    if (valid && retained_count) {
        int checked[YD_RAFT_APPLICATION_SHELLS];
        size_t checked_count = 0;
        valid = retirement_shells(c, retained, retained_count, checked, &checked_count) &&
            checked_count == shell_count && !memcmp(checked, shells, shell_count * sizeof(*shells));
    }
    if (valid && c->slots) {
        int checked[YD_RAFT_APPLICATION_SLOTS], checked_custody = -1;
        valid = yd_raft_application_slots_account(c->slots, c->document_directory, checked,
            &checked_custody) && checked_custody == slot_custody &&
            !memcmp(checked, slot_directories, sizeof(checked));
    }
    if (!valid) report->space.complete = false;
    if (directory >= 0) close(directory);
    report->reservation = yd_raft_application_reserve(report->space, limits);
    report->admission = report->reservation.result;
    return valid && report->admission == YD_RAFT_APPLICATION_ADMIT;
}
bool yd_raft_cluster_application_admission(YDRaftCluster *c, int workspace,
    YDRaftApplicationLimits limits, YDRaftApplicationAdmissionReport *report,
    char *error, size_t length) {
    if (report) *report = (YDRaftApplicationAdmissionReport){0};
    if (!c || !report || !yd_raft_application_limits_valid(limits)) return false;
    pthread_mutex_lock(&c->lock);
    bool valid = available(c) && !c->installing &&
        admission_locked(c, NULL, workspace, NULL, NULL, 0, NULL, limits, report, error, length);
    pthread_mutex_unlock(&c->lock);
    return valid;
}
bool yd_raft_cluster_application_admission_owned(YDRaftCluster *c,
    YDRaftApplicationWorkspace *workspace, YDRaftApplicationLimits limits,
    YDRaftApplicationAdmissionReport *report, char *error, size_t length) {
    if (report) *report = (YDRaftApplicationAdmissionReport){0};
    if (!c || !workspace || !report || !yd_raft_application_limits_valid(limits)) return false;
    pthread_mutex_lock(&c->lock);
    bool valid = available(c) && !c->installing && admission_locked(c, NULL,
        yd_raft_application_workspace_directory(workspace), workspace, NULL, 0, NULL, limits,
        report, error, length);
    pthread_mutex_unlock(&c->lock);
    return valid;
}
bool yd_raft_cluster_application_admission_retained(YDRaftCluster *c,
    YDRaftApplicationWorkspace *workspace, YDRaftApplicationRetirement *const *retained,
    size_t count, YDRaftApplicationLimits limits, YDRaftApplicationAdmissionReport *report,
    char *error, size_t length) {
    if (report) *report = (YDRaftApplicationAdmissionReport){0};
    if (!c || !workspace || !report || !yd_raft_application_limits_valid(limits)) return false;
    pthread_mutex_lock(&c->lock);
    bool valid = available(c) && !c->installing && admission_locked(c, NULL,
        yd_raft_application_workspace_directory(workspace), workspace, retained, count, NULL, limits,
        report, error, length);
    pthread_mutex_unlock(&c->lock);
    return valid;
}
bool yd_raft_cluster_application_admission_slots(YDRaftCluster *c,
    YDRaftApplicationWorkspace *workspace, YDRaftApplicationLimits limits,
    YDRaftApplicationAdmissionReport *report, char *error, size_t length) {
    if (report) *report = (YDRaftApplicationAdmissionReport){0};
    if (!c || !report || !yd_raft_application_limits_valid(limits) ||
        deferred_reconcile(c, error, length) != 1) return false;
    pthread_mutex_lock(&c->lock);
    bool valid = available(c) && !c->installing && !c->slots_failed;
    if (!valid || (!c->slots && !workspace)) {
        if (valid && (c->generation->layout || !empty_identity(c->generation->identity)))
            report->admission = YD_RAFT_APPLICATION_ADMIT_UNKNOWN;
        bool admitted = valid && !c->generation->layout && empty_identity(c->generation->identity) &&
            admission_locked(c, NULL, -1, NULL, NULL, 0, NULL, limits, report, error, length);
        pthread_mutex_unlock(&c->lock);
        return admitted;
    }
    if (!c->slots && (c->generation->layout || !empty_identity(c->generation->identity))) {
        report->admission = YD_RAFT_APPLICATION_ADMIT_UNKNOWN;
        pthread_mutex_unlock(&c->lock); return false;
    }
    c->installing = true;
    unsigned char selected[32]; memcpy(selected, c->generation->identity, 32);
    bool create = !c->slots;
    pthread_mutex_unlock(&c->lock);
    YDRaftApplicationSlots *created = create ? yd_raft_application_slots_create(c->document_directory,
        c->cluster, c->voters, error, length) : NULL;
    int reconciled = create ? (created ? 1 : -1) : archives_reconcile(c, selected, error, length);
    pthread_mutex_lock(&c->archives_lock);
    bool room = archive_count_locked(c) + c->archive_reserved < YD_RAFT_LIVE_ARCHIVES;
    pthread_mutex_unlock(&c->archives_lock);
    pthread_mutex_lock(&c->lock);
    if (create) { c->slots = created; c->slots_failed = !created; }
    valid = available(c) && reconciled == 1 && room && c->slots &&
        admission_locked(c, NULL, workspace ? yd_raft_application_workspace_directory(workspace) : -1,
            workspace, NULL, 0, NULL, limits, report, error, length);
    c->installing = false;
    pthread_cond_broadcast(&c->progress);
    pthread_mutex_unlock(&c->lock);
    return valid;
}
static YDRaftApplicationSelection select_application(YDRaftCluster *c,
    YDRaftApplicationImage *image, unsigned admission_ms, YDRaftSnapshotProgress progress,
    void *context, bool *published, YDRaftApplicationRetirement **retirement,
    int workspace, YDRaftApplicationWorkspace *owned, YDRaftApplicationRetirement *const *retained,
    size_t retained_count, const YDRaftApplicationLimits *limits,
    YDRaftApplicationAdmissionReport *report, char *error, size_t length,
    YDRaftApplicationDecisionCheck decision_check, void *decision_context, bool slots) {
    if (retirement) *retirement = NULL;
    if (published) *published = false;
    if (report) *report = (YDRaftApplicationAdmissionReport){0};
    uint64_t end = deadline(admission_ms);
    YDRaftApplicationCopyInfo info = yd_raft_application_image_info(image);
    YDDiskAllocation allocation = yd_raft_application_image_allocation(image);
    if (!c || !image || !published || !end || !info.checkpoint.applied.index ||
        info.checkpoint.capabilities != c->native_capabilities ||
        (limits && (!report || workspace < 0 || !yd_raft_application_limits_valid(*limits) ||
            !image_at(image, workspace) ||
            allocation.limit == YD_DISK_ALLOCATION_UNLIMITED ||
            allocation.limit > limits->image_bytes || allocation.high_water > limits->image_bytes))) {
        yd_disk_error(error, length, "invalid application selection arguments");
        return YD_RAFT_APPLICATION_SELECT_INVALID;
    }
    Generation *source = NULL;
    YDRaftApplicationSelection outcome = YD_RAFT_APPLICATION_SELECT_ARTIFACT_FAILED;
    pthread_mutex_lock(&c->lock);
    if (yd_raft_application_failed(application(c)) ||
        yd_raft_runtime_status(c->runtime).role == YD_RAFT_FAILED) fence_locked(c);
    if (!available(c)) outcome = YD_RAFT_APPLICATION_SELECT_UNAVAILABLE;
    else if (!remaining(end)) outcome = YD_RAFT_APPLICATION_SELECT_TIMEOUT;
    else if (c->installing) outcome = YD_RAFT_APPLICATION_SELECT_BUSY;
    else if ((slots && !c->slots) || (!slots && c->generation->layout))
        outcome = YD_RAFT_APPLICATION_SELECT_UNAVAILABLE;
    else if (!yd_raft_application_image_current(image, application(c)))
        outcome = YD_RAFT_APPLICATION_SELECT_STALE;
    else if (limits && (yd_disk_view(yd_raft_application_image_disk(image)).end > limits->restore_bytes ||
        yd_disk_view(yd_raft_application_image_disk(image)).end > limits->archive_bytes - YD_RAFT_SNAPSHOT_MANIFEST)) {
        report->admission = YD_RAFT_APPLICATION_ADMIT_WORK;
        outcome = YD_RAFT_APPLICATION_SELECT_BUDGET;
    }
    else if (limits && !admission_locked(c, image, workspace, owned, retained, retained_count, NULL, *limits, report, error, length))
        outcome = YD_RAFT_APPLICATION_SELECT_BUDGET;
    else if (!remaining(end)) outcome = YD_RAFT_APPLICATION_SELECT_TIMEOUT;
    else if (generation_retain(c->generation)) {
        source = c->generation;
        c->installing = true;
    }
    pthread_mutex_unlock(&c->lock);
    if (!source) {
        yd_disk_error(error, length, "application selection admission rejected");
        return outcome;
    }
    YDRaftApplicationRetirement *ticket = retirement
        ? retirement_prepare(c, source, slots, error, length) : NULL;
    int archive_lease = -1;
    bool prepared = (!retirement || ticket) && yd_raft_cluster_archive_admit(c, &archive_lease);
    SelectionProgress capturing = {.cluster = c, .progress = progress, .context = context};
    bool archive_reserved = false;
    uint64_t archive_bytes = yd_disk_view(yd_raft_application_image_disk(image)).end;
    archive_bytes = archive_bytes <= INT64_MAX - YD_RAFT_SNAPSHOT_MANIFEST
        ? archive_bytes + YD_RAFT_SNAPSHOT_MANIFEST : 0;
    prepared = prepared && archive_reserve(c, archive_bytes, &archive_reserved);
    int directory = prepared ? yd_raft_runtime_snapshot_directory(c->runtime) : -1;
    char id[YD_RAFT_SNAPSHOT_ID];
    YDRaftSnapshotArchive *archive = directory < 0 ? NULL : limits
        ? yd_raft_application_archive_limited(image, directory, c->cluster, c->voters,
            limits->archive_bytes, &report->archive, selection_progress, &capturing, id, error, length)
        : yd_raft_application_archive_limited(image, directory, c->cluster, c->voters,
            archive_bytes, NULL, selection_progress, &capturing, id, error, length);
    unsigned char manifest[YD_RAFT_SNAPSHOT_MANIFEST];
    YDRaftSnapshotBase base = {.index = info.checkpoint.applied.index,
                               .term = info.checkpoint.applied.term};
    size_t size = 0;
    bool valid = archive && yd_raft_snapshot_archive_manifest(archive, manifest) &&
        EVP_Q_digest(NULL, "SHA256", NULL, manifest, sizeof(manifest), base.archive, &size) == 1 &&
        size == sizeof(base.archive);
    struct stat publication_directory, publication_file;
    bool created_archive = valid && yd_raft_snapshot_archive_publication(archive,
        &publication_directory, &publication_file);
    valid = archive_register(c, archive_reserved, archive_bytes, archive || directory < 0, directory, &base,
        created_archive ? &publication_file : NULL, error, length) && valid;
    if (directory >= 0) close(directory);
    Generation *next = valid
        ? generation_candidate(c, &base, NULL, limits, report ? &report->restore : NULL,
            selection_progress, &capturing, slots, false, error, length) : NULL;
    yd_raft_snapshot_archive_close(archive);
    if (archive_lease >= 0) close(archive_lease);
    Publication publication = {.cluster = c, .next = next};
    end = deadline(admission_ms);
    pthread_mutex_lock(&c->lock);
    while (next && c->writing && available(c) && c->generation == source && remaining(end))
        if (!wait_locked(c, end)) break;
    valid = false;
    if (!available(c)) outcome = YD_RAFT_APPLICATION_SELECT_UNAVAILABLE;
    else if (capturing.cancelled) outcome = YD_RAFT_APPLICATION_SELECT_CANCELLED;
    else if (!next) outcome = YD_RAFT_APPLICATION_SELECT_ARTIFACT_FAILED;
    else if (!remaining(end)) outcome = YD_RAFT_APPLICATION_SELECT_TIMEOUT;
    else if (c->writing) outcome = YD_RAFT_APPLICATION_SELECT_BUSY;
    else if (c->generation != source ||
        !yd_raft_application_image_current(image, application(c)))
        outcome = YD_RAFT_APPLICATION_SELECT_STALE;
    else if (ticket && !yd_raft_retired_files_seal(ticket->files, error, length))
        outcome = YD_RAFT_APPLICATION_SELECT_ARTIFACT_FAILED;
    else if (limits && (!admission_locked(c, image, workspace, owned, retained, retained_count, id, *limits, report, error, length) ||
        (report->admission = yd_raft_application_savings(
            yd_raft_application_disk(source->application)->fd,
            yd_disk_view(yd_raft_application_image_disk(image)).end, report->space, *limits,
            &report->source_bytes, &report->saved_bytes)) != YD_RAFT_APPLICATION_ADMIT))
        outcome = YD_RAFT_APPLICATION_SELECT_BUDGET;
    else if (!remaining(end)) outcome = YD_RAFT_APPLICATION_SELECT_TIMEOUT;
    else if (decision_check && !decision_check(decision_context))
        outcome = YD_RAFT_APPLICATION_SELECT_CANCELLED;
    else {
        valid = slots ? yd_raft_runtime_application_select_layout(c->runtime, source->identity, &base,
            1, publish_generation, &publication, published)
            : yd_raft_runtime_application_select(c->runtime, source->identity, &base,
                publish_generation, &publication, published);
        outcome = valid ? YD_RAFT_APPLICATION_SELECTED : YD_RAFT_APPLICATION_SELECT_UNCERTAIN;
    }
    if (yd_raft_application_failed(application(c)) ||
        yd_raft_runtime_status(c->runtime).role == YD_RAFT_FAILED) fence_locked(c);
    c->installing = false;
    pthread_cond_broadcast(&c->progress);
    pthread_mutex_unlock(&c->lock);
    if (ticket && valid && *published) {
        ticket->previous = publication.previous;
        publication.previous = NULL;
        *retirement = ticket;
        ticket = NULL;
    }
    yd_raft_application_retirement_close(ticket);
    generation_release(publication.previous);
    if (!*published) generation_release(next);
    generation_release(source);
    if (!valid && error && length)
        snprintf(error, length, "application selection unavailable or stale; preserve all artifacts");
    return outcome;
}
static void selection_cancelled(void *context) {
    (void)pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
    YDRaftApplicationRetirement **retirement = context;
    if (retirement) {
        yd_raft_application_retirement_close(*retirement);
        *retirement = NULL;
    }
}
static YDRaftApplicationSelection application_select(YDRaftCluster *c,
    YDRaftApplicationImage *image, unsigned admission_ms, YDRaftSnapshotProgress progress,
    void *context, bool *published, YDRaftApplicationRetirement **retirement,
    int workspace, YDRaftApplicationWorkspace *owned, YDRaftApplicationRetirement *const *retained,
    size_t retained_count, const YDRaftApplicationLimits *limits,
    YDRaftApplicationAdmissionReport *report, char *error, size_t length,
    YDRaftApplicationDecisionCheck decision_check, void *decision_context, bool slots) {
    if (retirement) *retirement = NULL;
    if (published) *published = false;
    int previous;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous))
        return YD_RAFT_APPLICATION_SELECT_INVALID;
    YDRaftApplicationSelection result = select_application(c, image, admission_ms, progress,
        context, published, retirement, workspace, owned, retained, retained_count, limits,
        report, error, length, decision_check, decision_context, slots);
    /* Selection can already be durable. Preserve its publication witness while
     * disposing only a returned retirement owner before pending cancellation. */
    pthread_cleanup_push(selection_cancelled, retirement);
    (void)pthread_setcancelstate(previous, NULL);
    if (previous == PTHREAD_CANCEL_ENABLE) pthread_testcancel();
    pthread_cleanup_pop(0);
    return result;
}
YDRaftApplicationSelection yd_raft_cluster_application_select_outcome(YDRaftCluster *c,
    YDRaftApplicationImage *image, unsigned admission_ms, YDRaftSnapshotProgress progress,
    void *context, bool *published, YDRaftApplicationRetirement **retirement,
    char *error, size_t length) {
    return application_select(c, image, admission_ms, progress, context, published, retirement,
        -1, NULL, NULL, 0, NULL, NULL, error, length, NULL, NULL, false);
}
YDRaftApplicationSelection yd_raft_cluster_application_select_limited(YDRaftCluster *c,
    YDRaftApplicationImage *image, int workspace, YDRaftApplicationLimits limits,
    unsigned admission_ms, YDRaftSnapshotProgress progress, void *context, bool *published,
    YDRaftApplicationRetirement **retirement, YDRaftApplicationAdmissionReport *report,
    char *error, size_t length) {
    return application_select(c, image, admission_ms, progress, context, published, retirement,
        workspace, NULL, NULL, 0, &limits, report, error, length, NULL, NULL, false);
}
YDRaftApplicationSelection yd_raft_cluster_application_select_owned(YDRaftCluster *c,
    YDRaftApplicationImage *image, YDRaftApplicationWorkspace *workspace,
    YDRaftApplicationLimits limits, unsigned admission_ms, YDRaftSnapshotProgress progress,
    void *context, bool *published, YDRaftApplicationRetirement **retirement,
    YDRaftApplicationAdmissionReport *report, char *error, size_t length) {
    return application_select(c, image, admission_ms, progress, context, published, retirement,
        yd_raft_application_workspace_directory(workspace), workspace, NULL, 0, &limits, report, error, length, NULL, NULL, false);
}
YDRaftApplicationSelection yd_raft_cluster_application_select_retained(YDRaftCluster *c,
    YDRaftApplicationImage *image, YDRaftApplicationWorkspace *workspace,
    YDRaftApplicationRetirement *const *retained, size_t count, YDRaftApplicationLimits limits,
    unsigned admission_ms, YDRaftSnapshotProgress progress, void *context,
    YDRaftApplicationDecisionCheck decision_check, void *decision_context, bool *published,
    YDRaftApplicationRetirement **retirement, YDRaftApplicationAdmissionReport *report,
    char *error, size_t length) {
    return application_select(c, image, admission_ms, progress, context, published, retirement,
        yd_raft_application_workspace_directory(workspace), workspace, retained, count,
        &limits, report, error, length, decision_check, decision_context, false);
}
YDRaftApplicationSelection yd_raft_cluster_application_select_slots(YDRaftCluster *c,
    YDRaftApplicationImage *image, YDRaftApplicationWorkspace *workspace,
    YDRaftApplicationLimits limits, unsigned admission_ms, YDRaftSnapshotProgress progress,
    void *context, YDRaftApplicationDecisionCheck decision_check, void *decision_context,
    bool *published, YDRaftApplicationRetirement **retirement,
    YDRaftApplicationAdmissionReport *report, char *error, size_t length) {
    return application_select(c, image, admission_ms, progress, context, published, retirement,
        yd_raft_application_workspace_directory(workspace), workspace, NULL, 0,
        &limits, report, error, length, decision_check, decision_context, true);
}
int yd_raft_cluster_application_retire(YDRaftCluster *c, YDRaftApplicationRetirement *ticket,
    char *error, size_t length) {
    if (!c || !ticket) return -1;
    pthread_mutex_lock(&c->lock);
    bool valid = available(c) && yd_raft_runtime_status(c->runtime).role != YD_RAFT_FAILED &&
        !yd_raft_application_failed(application(c)) &&
        !memcmp(ticket->cluster, c->cluster, sizeof(c->cluster)) &&
        memcmp(ticket->identity, c->generation->identity, sizeof(ticket->identity)) &&
        yd_raft_retired_files_root(ticket->files, c->document_directory);
    bool busy = c->installing;
    unsigned char selected[32];
    memcpy(selected, c->generation->identity, sizeof(selected));
    if (valid && !busy) c->installing = true;
    pthread_mutex_unlock(&c->lock);
    if (!valid) { yd_disk_error(error, length, "application retirement unavailable or selected"); return -1; }
    if (busy) return 0;
    int result = 0;
    if (!ticket->previous || atomic_load_explicit(&ticket->previous->references, memory_order_acquire) == 1) {
        generation_release(ticket->previous);
        ticket->previous = NULL;
        YDRaftApplicationCut *cut = NULL;
        result = yd_raft_runtime_application_cut(c->runtime, c->document_directory,
            ticket->identity, &cut, error, length);
        /* Consume the complete no-target decision in this uninterrupted
         * installing reservation. Old dependency producers were excluded by
         * the cut; new captures/copies derive from target-free current roots.
         * Checkpoints preserve that application identity. Selection/install
         * cannot reintroduce the target until this reservation ends. Release
         * admission before custody I/O so checkpoints and writes can proceed. */
        yd_raft_runtime_application_cut_close(cut);
        if (result == 1) result = yd_raft_retired_files_retire(ticket->files, error, length);
        if (result == 1) ticket->files_retired = true;
    }
    if (result == 1 && c->slots && archives_reconcile(c, selected, error, length) < 0)
        result = -1;
    pthread_mutex_lock(&c->lock);
    c->installing = false;
    pthread_cond_broadcast(&c->progress);
    pthread_mutex_unlock(&c->lock);
    return result;
}
void yd_raft_application_retirement_close(YDRaftApplicationRetirement *ticket) {
    if (ticket) {
        generation_release(ticket->previous);
        yd_raft_retired_files_close(ticket->files);
        if (ticket->files_retired) {
            YDStorageExtent current;
            /* The same live ticket proves unlink+sync. Refresh only accounting
             * high-water: intervening writes never refund failed reservations.
             * Reused inode/id or any remaining producer makes retirement fail. */
            if (yd_storage_budget_find_extent(ticket->budget, ticket->extent.device,
                    ticket->extent.inode, &current) && current.id == ticket->extent.id)
                (void)yd_storage_budget_retire_extent(ticket->budget, &current);
        }
        yd_storage_budget_close(ticket->budget);
        free(ticket);
    }
}
/* installation is reserved and the controller mutex is held. Archive stages
 * have their independent pre-BEGIN ledger; inspect all native siblings without
 * inventing exemptions for a separately owned compactor workspace. */
static bool incoming_inventory_locked(YDRaftCluster *c, char *error, size_t length) {
    int slots[YD_RAFT_APPLICATION_SLOTS], custody = -1;
    YDRaftApplicationSpace space;
    bool valid = yd_raft_application_slots_account(c->slots, c->document_directory, slots, &custody) &&
        yd_raft_application_documents_with_slots(c->document_directory, slots, YD_RAFT_APPLICATION_SLOTS,
            custody, yd_raft_application_disk(application(c))->fd, c->cluster, c->voters,
            &space, error, length);
    int checked[YD_RAFT_APPLICATION_SLOTS], checked_custody = -1;
    return valid && yd_raft_application_slots_account(c->slots, c->document_directory,
        checked, &checked_custody) && checked_custody == custody && !memcmp(checked, slots, sizeof(slots));
}
static bool snapshot_install_policy(YDRaftCluster *c, const YDRaftSnapshotOffer *offer,
    const YDRaftSnapshotReference *reference, unsigned timeout_ms, bool background,
    char *error, size_t length) {
    uint64_t end = deadline(timeout_ms);
    if (!c || !offer || !end || deferred_reconcile(c, error, length) != 1) return false;
    int archive_lease = -1;
    if (!yd_raft_cluster_archive_admit(c, &archive_lease)) return false;
    pthread_mutex_lock(&c->lock);
    struct stat generations;
    bool pristine = fstatat(c->document_directory, YD_RAFT_GENERATION_DIRECTORY,
        &generations, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT;
    bool create_slots = !c->slots && !c->slots_failed && !c->generation->layout &&
        empty_identity(c->generation->identity) && pristine;
    /* Recovered slots grant service, never the old process's cleanup ledger.
     * Without a live owner use a fresh manifest-named preserving copy. */
    bool fixed = c->slots || create_slots || c->slots_failed;
    bool valid = remaining(end) && !c->installing &&
        (!fixed || c->slots || create_slots) && install_current(c, offer);
    Generation *source = c->generation;
    if (valid) c->installing = true;
    pthread_mutex_unlock(&c->lock);
    if (!valid) {
        if (archive_lease >= 0) close(archive_lease);
        return false;
    }
    if (create_slots) {
        /* The first incoming replacement may precede local maintenance. Bind
         * newly CREATED slots under the same installation exclusion; unknown
         * existing names are never adopted and a partial creation stays sticky. */
        YDRaftApplicationSlots *created = yd_raft_application_slots_create(c->document_directory,
            c->cluster, c->voters, error, length);
        pthread_mutex_lock(&c->lock);
        c->slots = created;
        c->slots_failed = !created;
        pthread_mutex_unlock(&c->lock);
    }
    pthread_mutex_lock(&c->lock);
    bool inventoried = !fixed || incoming_inventory_locked(c, error, length);
    pthread_mutex_unlock(&c->lock);
    YDRaftApplicationRetirement *ticket = fixed && inventoried
        ? retirement_prepare(c, source, true, error, length) : NULL;
    Installation install = {.cluster = c, .end = end, .background = background, .offer = *offer};
    Generation *next = (!fixed || ticket) ? generation_candidate(c, &offer->base,
        reference, NULL, NULL, install_progress, &install, fixed, !fixed, error, length) : NULL;
    if (archive_lease >= 0) close(archive_lease);
    Publication publication = {.cluster = c, .next = next};
    bool published = false;
    if (background) end = deadline(timeout_ms);
    pthread_mutex_lock(&c->lock);
    while (next && c->writing && install_current(c, offer) && remaining(end))
        if (!wait_locked(c, end)) break;
    valid = next && !c->writing && remaining(end) && install_current(c, offer) &&
        (!ticket || yd_raft_retired_files_seal(ticket->files, error, length)) &&
        yd_raft_runtime_snapshot_install_layout(c->runtime, offer, fixed ? 1 : 0,
            publish_generation, &publication, &published);
    if (yd_raft_runtime_status(c->runtime).role == YD_RAFT_FAILED) fence_locked(c);
    c->installing = false;
    pthread_cond_broadcast(&c->progress);
    pthread_mutex_unlock(&c->lock);
    if (ticket && valid && published) {
        ticket->previous = publication.previous;
        publication.previous = NULL;
        pthread_mutex_lock(&c->retirement_lock);
        if (!c->deferred_retirement) { c->deferred_retirement = ticket; ticket = NULL; }
        pthread_mutex_unlock(&c->retirement_lock);
        (void)deferred_reconcile(c, error, length);
    }
    yd_raft_application_retirement_close(ticket);
    generation_release(publication.previous);
    if (!published) generation_release(next);
    return valid;
}
bool yd_raft_cluster_snapshot_install(YDRaftCluster *c, const YDRaftSnapshotOffer *offer,
                                        unsigned timeout_ms, char *error, size_t length) {
    return snapshot_install_policy(c, offer, NULL, timeout_ms, false, error, length);
}
bool yd_raft_cluster_snapshot_job(YDRaftCluster *c, const YDRaftSnapshotOffer *offer,
                                    unsigned admission_ms, char *error, size_t length) {
    return snapshot_install_policy(c, offer, NULL, admission_ms, true, error, length);
}
bool yd_raft_cluster_snapshot_job_reference(YDRaftCluster *c, const YDRaftSnapshotOffer *offer,
    const YDRaftSnapshotReference *reference, unsigned admission_ms, char *error, size_t length) {
    return reference && snapshot_install_policy(c, offer, reference, admission_ms, true, error, length);
}
YDRaftClusterStorage yd_raft_cluster_storage(YDRaftCluster *c) {
    pthread_mutex_lock(&c->lock);
    YDDisk *disk = yd_raft_application_disk(application(c));
    YDRaftClusterStorage storage = {.view = yd_disk_view(disk),
                                    .stats = yd_disk_stats(disk),
                                    .writable = yd_disk_writable(disk),
                                    .failed = !available(c)};
    pthread_mutex_unlock(&c->lock);
    return storage;
}
YDDisk *yd_raft_cluster_disk(YDRaftCluster *c) { return yd_raft_application_disk(application(c)); }
YDRaftView *yd_raft_cluster_local_view(YDRaftCluster *c) {
    if (!c) return NULL;
    YDRaftView *view = calloc(1, sizeof(*view));
    if (!view) return NULL;
    pthread_mutex_lock(&c->lock);
    if (!c->stopping && c->generation && generation_retain(c->generation)) {
        view->generation = c->generation;
        view->value = yd_disk_view(yd_raft_application_disk(application(c)));
    }
    pthread_mutex_unlock(&c->lock);
    if (!view->generation) { free(view); return NULL; }
    return view;
}
YDRaftView *yd_raft_cluster_view(YDRaftCluster *c, unsigned timeout_ms) {
    uint64_t end = deadline(timeout_ms), term, index;
    if (!c || !end)
        return NULL;
    YDRaftView *view = calloc(1, sizeof(*view));
    if (!view)
        return NULL;
    unsigned ms = remaining(end);
    if (!ms || !yd_raft_runtime_barrier(c->runtime, ms, &term, &index)) {
        free(view);
        return NULL;
    }
    pthread_mutex_lock(&c->lock);
    if (applied_locked(c, index, end) && generation_retain(c->generation)) {
        view->generation = c->generation;
        view->value = yd_disk_view(yd_raft_application_disk(application(c)));
    }
    pthread_mutex_unlock(&c->lock);
    if (!view->generation || !remaining(end)) {
        yd_raft_view_close(view);
        return NULL;
    }
    return view;
}
YDDisk *yd_raft_view_disk(const YDRaftView *view) {
    return view ? yd_raft_application_disk(view->generation->application) : NULL;
}
YDDiskView yd_raft_view_value(const YDRaftView *view) { return view ? view->value : (YDDiskView){0}; }
void yd_raft_view_close(YDRaftView *view) {
    if (view) {
        generation_release(view->generation);
        free(view);
    }
}
YDDiskReply yd_raft_cluster_query(YDRaftCluster *c, const char *method, const char *target,
                                  const unsigned char *body, size_t length, const char *match,
                                  const char *none, bool gzip, unsigned timeout_ms) {
    if (!timeout_ms || timeout_ms > 30000)
        return yd_disk_error_reply(400, "invalid_cluster_timeout");
    YDRaftView *owned = yd_raft_cluster_view(c, timeout_ms);
    if (!owned)
        return yd_disk_error_reply(503, "cluster_unavailable");
    YDDiskView view = yd_raft_view_value(owned);
    YDDiskReply reply;
    if (!strncmp(target, "/v1/replication/", 16))
        reply = yd_raft_replica_read(yd_raft_view_disk(owned), &view, method, target,
            body, length, match, none, gzip);
    else if (yd_raft_index_job_handles(target))
        reply = !strcmp(method, "GET") && !length && !match && !none
            ? yd_raft_index_job_read(yd_raft_view_disk(owned), &view, target)
            : yd_disk_error_reply(405, "method_not_allowed");
    else reply = yd_disk_api_read_at(yd_raft_view_disk(owned), &view, method, target,
        body, length, match, none, gzip);
    yd_raft_view_close(owned);
    return reply;
}
bool yd_raft_cluster_read(YDRaftCluster *c, unsigned timeout_ms) {
    uint64_t end = deadline(timeout_ms), term, index;
    unsigned ms = remaining(end);
    if (!end || !ms || !yd_raft_runtime_barrier(c->runtime, ms, &term, &index))
        return false;
    pthread_mutex_lock(&c->lock);
    bool valid = applied_locked(c, index, end);
    pthread_mutex_unlock(&c->lock);
    return valid;
}
bool yd_raft_cluster_receipt_retention_status(YDRaftCluster *c, unsigned timeout_ms,
    YDRaftReceiptRetention *out) {
    if (out) *out = (YDRaftReceiptRetention){0};
    uint64_t end = deadline(timeout_ms), term = 0, index = 0;
    if (!c || !out || !end || !yd_raft_runtime_barrier(c->runtime, remaining(end), &term, &index)) return false;
    pthread_mutex_lock(&c->lock);
    YDRaftStatus status = yd_raft_runtime_status(c->runtime);
    bool valid = status.role == YD_RAFT_LEADER && status.term == term && applied_locked(c, index, end) &&
        yd_raft_application_retention_status(application(c), out);
    if (yd_raft_application_failed(application(c))) fence_locked(c);
    pthread_mutex_unlock(&c->lock);
    return valid;
}
YDDiskReply yd_raft_cluster_receipt_retention_control(YDRaftCluster *c, uint64_t expected,
    const YDRaftReceiptPolicy *activate, bool prune, unsigned timeout_ms) {
    uint64_t end = deadline(timeout_ms);
    if (!c || !end || (activate && prune)) return yd_disk_error_reply(400, "invalid_receipt_retention_control");
    pthread_mutex_lock(&c->lock);
    while (c->writing && available(c)) if (!wait_locked(c, end)) break;
    if (c->writing || !available(c) || !remaining(end)) {
        pthread_mutex_unlock(&c->lock);
        return yd_disk_error_reply(503, "receipt_retention_unavailable");
    }
    c->writing = true;
    pthread_mutex_unlock(&c->lock);
    uint64_t term = 0, index = 0;
    bool confirmed = remaining(end) && yd_raft_runtime_barrier(c->runtime, remaining(end), &term, &index);
    YDDiskReply reply = {0}; YDRaftProposal proposal = {0}; char error[256];
    pthread_mutex_lock(&c->lock);
    YDRaftStatus state = yd_raft_runtime_status(c->runtime);
    if (!confirmed || !available(c) || state.role != YD_RAFT_LEADER || state.term != term ||
        !applied_locked(c, state.last, end)) goto unavailable_control;
    int prepared = prune ? yd_raft_application_retention_prune_prepare(application(c), expected,
        &proposal, error, sizeof(error)) : yd_raft_application_retention_prepare(application(c), expected,
        activate, &proposal, error, sizeof(error));
    if (prepared < 0) {
        if (yd_raft_application_failed(application(c))) fence_locked(c);
        goto unavailable_control;
    }
    if (!prepared) { reply = proposal.reply; proposal.reply = (YDDiskReply){0}; goto control_done; }
    if (proposal.size > c->command_bytes) { reply = yd_disk_error_reply(413, "cluster_command_too_large"); goto control_done; }
    uint64_t base = yd_raft_application_position(application(c)).index;
    if (!remaining(end) || !yd_raft_runtime_propose_at(c->runtime, term, base,
        proposal.command, proposal.size, &index) || !applied_locked(c, index, end)) goto unavailable_control;
    reply = proposal.reply; proposal.reply = (YDDiskReply){0};
    YDDiskView view = yd_disk_view(yd_raft_application_disk(application(c)));
    yd_disk_revision(&view, reply.revision);
    goto control_done;
unavailable_control:
    reply = yd_disk_error_reply(503, "receipt_retention_uncertain");
control_done:
    yd_raft_proposal_free(&proposal);
    c->writing = false;
    pthread_cond_broadcast(&c->progress);
    pthread_mutex_unlock(&c->lock);
    return reply;
}
typedef struct {
    YDRaftCluster *cluster;
    YDRaftBackup *backup;
    uint64_t term;
    char *error;
    size_t length;
} BackupCapture;
static bool backup_locked(YDRaft *raft, void *context) {
    BackupCapture *capture = context;
    YDRaftCluster *c = capture->cluster;
    YDRaftStatus status = yd_raft_status(raft);
    if (status.role != YD_RAFT_LEADER || status.term != capture->term) return false;
    uint64_t applied = yd_raft_application_position(application(c)).index;
    while (applied < status.committed) {
        YDRaftEntry entry = {0};
        bool valid = yd_raft_entry(raft, applied + 1, &entry) &&
            yd_raft_application_apply(application(c), &entry, capture->error, capture->length);
        yd_raft_entry_free(&entry);
        if (!valid) { c->failed = true; return false; }
        applied++;
    }
    capture->backup = yd_raft_backup_capture(raft, application(c), raft->configuration_base,
        c->document_cache, capture->error, capture->length);
    return capture->backup != NULL;
}
static YDRaftBackup *cluster_backup(YDRaftCluster *c, unsigned timeout_ms,
    char *error, size_t length) {
    if (!c) return NULL;
    uint64_t end = deadline(timeout_ms), term = 0, index = 0;
    unsigned ms = remaining(end);
    if (!ms || !yd_raft_runtime_barrier(c->runtime, ms, &term, &index)) return NULL;
    pthread_mutex_lock(&c->lock);
    while (available(c) && c->writing && remaining(end))
        if (!wait_locked(c, end)) break;
    BackupCapture capture = {.cluster = c, .term = term, .error = error, .length = length};
    if (available(c) && !c->writing && !c->installing && remaining(end)) {
        c->writing = true;
        yd_raft_runtime_capture_locked(c->runtime, backup_locked, &capture);
        c->writing = false;
        if (c->failed) yd_raft_runtime_fence(c->runtime);
        pthread_cond_broadcast(&c->progress);
    }
    pthread_mutex_unlock(&c->lock);
    return capture.backup;
}
static void cancel_backup(void *backup) { yd_raft_backup_close(backup); }
YDRaftBackup *yd_raft_cluster_backup(YDRaftCluster *c, unsigned timeout_ms,
    char *error, size_t length) {
    int cancellation;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancellation)) return NULL;
    YDRaftBackup *volatile backup = cluster_backup(c, timeout_ms, error, length);
    /* Fenced native pins require disabled cancellation through adoption. A
     * pending cancellation must close the result before it can leave here. */
    pthread_cleanup_push(cancel_backup, backup);
    pthread_setcancelstate(cancellation, NULL);
    if (cancellation == PTHREAD_CANCEL_ENABLE) pthread_testcancel();
    pthread_cleanup_pop(0);
    return backup;
}
YDRaftMembership yd_raft_cluster_membership(YDRaftCluster *c) {
    return c ? yd_raft_runtime_membership(c->runtime) : (YDRaftMembership){0};
}
static int cluster_reconfigure(YDRaftCluster *c, uint16_t voters, unsigned timeout_ms,
    YDRaftMembership *result) {
    if (!c || !result) return -1;
    uint64_t end = deadline(timeout_ms);
    if (!end) return -1;
    pthread_mutex_lock(&c->lock);
    while (c->writing && available(c)) if (!wait_locked(c, end)) break;
    if (c->writing || c->installing || !available(c) || !remaining(end)) {
        pthread_mutex_unlock(&c->lock);
        return -1;
    }
    c->writing = true;
    pthread_mutex_unlock(&c->lock);
    int outcome = yd_raft_runtime_reconfigure(c->runtime, voters, remaining(end), result);
    pthread_mutex_lock(&c->lock);
    if (outcome == 1) {
        YDRaftStatus state = yd_raft_runtime_status(c->runtime);
        if (!applied_locked(c, state.committed, end)) outcome = 0;
    }
    c->writing = false;
    pthread_cond_broadcast(&c->progress);
    pthread_mutex_unlock(&c->lock);
    return outcome;
}
int yd_raft_cluster_reconfigure(YDRaftCluster *c, uint16_t voters, unsigned timeout_ms,
    YDRaftMembership *result) {
    int cancellation;
    if (result) *result = (YDRaftMembership){0};
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancellation)) return -1;
    int outcome = cluster_reconfigure(c, voters, timeout_ms, result);
    /* A cancelled caller must release both controller locks and its write
     * reservation before the cancellation can be delivered. */
    pthread_setcancelstate(cancellation, NULL);
    if (cancellation == PTHREAD_CANCEL_ENABLE) pthread_testcancel();
    return outcome;
}
/* Controller lock and write reservation are held. The fresh quorum term is
 * checked again before preparing and before exact-base proposal. */
static YDDiskReply write_locked(YDRaftCluster *c, const YDRaftWrite *write,
    uint64_t term, uint64_t end) {
    YDDiskReply reply = {0};
    uint64_t index = 0;
    YDRaftStatus state = yd_raft_runtime_status(c->runtime);
    if (!available(c) || state.role != YD_RAFT_LEADER || state.term != term ||
        !applied_locked(c, state.last, end)) goto unavailable;
    YDRaftProposal proposal;
    char error[256];
    int prepared = yd_raft_application_prepare(application(c), write, &proposal, error, sizeof(error));
    if (prepared < 0) {
        yd_raft_proposal_free(&proposal);
        if (yd_raft_application_failed(application(c))) fence_locked(c);
        goto unavailable;
    }
    if (!prepared) {
        reply = proposal.reply;
        proposal.reply = (YDDiskReply){0};
        yd_raft_proposal_free(&proposal);
        return reply;
    }
    uint64_t base = yd_raft_application_position(application(c)).index;
    if (proposal.size > c->command_bytes) {
        yd_raft_proposal_free(&proposal);
        return yd_disk_error_reply(413, "cluster_command_too_large");
    }
    bool proposed = remaining(end) && yd_raft_runtime_propose_at(c->runtime, term, base,
        proposal.command, proposal.size, &index);
    yd_raft_proposal_free(&proposal);
    if (!proposed) goto unavailable;
    if (!applied_locked(c, index, end)) goto uncertain;
    int found = yd_raft_application_receipt(application(c), write, &reply, error, sizeof(error));
    if (found == 1) return reply;
    if (found == -1) fence_locked(c);
uncertain:
    yd_disk_reply_free(&reply);
    return yd_disk_error_reply(503, "cluster_write_uncertain");
unavailable:
    return yd_disk_error_reply(503, "cluster_write_unavailable");
}
static YDDiskReply cluster_write(YDRaftCluster *c, const YDRaftWrite *write, unsigned timeout_ms) {
    uint64_t end = deadline(timeout_ms);
    if (!end) return yd_disk_error_reply(400, "invalid_cluster_timeout");
    pthread_mutex_lock(&c->lock);
    while (c->writing && available(c)) if (!wait_locked(c, end)) break;
    if (c->writing || !available(c) || !remaining(end)) {
        pthread_mutex_unlock(&c->lock);
        return yd_disk_error_reply(503, "cluster_write_unavailable");
    }
    c->writing = true;
    pthread_mutex_unlock(&c->lock);
    uint64_t term = 0, index = 0;
    unsigned ms = remaining(end);
    bool confirmed = ms && yd_raft_runtime_barrier(c->runtime, ms, &term, &index);
    pthread_mutex_lock(&c->lock);
    YDDiskReply reply = confirmed ? write_locked(c, write, term, end) :
        yd_disk_error_reply(503, "cluster_write_unavailable");
    c->writing = false;
    pthread_cond_broadcast(&c->progress);
    pthread_mutex_unlock(&c->lock);
    return reply;
}
typedef struct {
    YDRaftCluster *cluster;
    Generation *generation;
    uint64_t term, end;
    unsigned char job[16];
    bool admitted, held;
} IndexBuild;
static bool index_progress(void *context, const char *phase) {
    IndexBuild *build = context;
    if (atomic_load(&build->cluster->stopping) || !remaining(build->end)) return false;
    if (build->admitted) return true;
    if (!build->held && !strcmp(phase, "scan")) {
        build->held = true;
        yd_session2_index_hold(build->cluster->node, build->job);
    }
    YDRaftStatus state = yd_raft_runtime_status(build->cluster->runtime);
    return state.role == YD_RAFT_LEADER && state.term == build->term;
}
static bool index_request_id(const unsigned char job[16], bool failure, unsigned char id[16]) {
    unsigned char input[24] = "YDIJPUB1", digest[32];
    if (failure) memcpy(input, "YDIJFAIL", 8);
    memcpy(input + 8, job, 16);
    size_t size = 0;
    if (EVP_Q_digest(NULL, "SHA256", NULL, input, sizeof(input), digest, &size) != 1 || size != 32)
        return false;
    memcpy(id, digest, 16);
    return true;
}
static bool index_admission(void *context, bool enter) {
    IndexBuild *build = context;
    YDRaftCluster *c = build->cluster;
    if (!enter) {
        if (build->admitted) {
            c->writing = false;
            build->admitted = false;
            pthread_cond_broadcast(&c->progress);
            pthread_mutex_unlock(&c->lock);
        }
        return true;
    }
    uint64_t term = 0, index = 0;
    unsigned ms = remaining(build->end);
    if (!ms || !yd_raft_runtime_barrier(c->runtime, ms, &term, &index)) return false;
    pthread_mutex_lock(&c->lock);
    YDRaftStatus state = yd_raft_runtime_status(c->runtime);
    if (!available(c) || c->writing || c->installing || c->generation != build->generation ||
        state.role != YD_RAFT_LEADER || state.term != term || term != build->term ||
        state.last != yd_raft_application_position(application(c)).index || !remaining(build->end)) {
        pthread_mutex_unlock(&c->lock);
        return false;
    }
    c->writing = build->admitted = true;
    return true;
}
static void *index_jobs(void *context) {
    YDRaftCluster *c = context;
    static const char hex[] = "0123456789abcdef";
    while (!atomic_load(&c->stopping)) {
        struct timespec pause = {.tv_nsec = 100000000};
        nanosleep(&pause, NULL);
        YDRaftClusterStatus status = yd_raft_cluster_status(c);
        if (status.failed || status.raft.role != YD_RAFT_LEADER) continue;
        YDRaftView *owned = yd_raft_cluster_view(c, 1000);
        if (!owned) continue;
        YDDiskView view = owned->value;
        unsigned char id[16]; char error[256] = {0};
        YDDisk *disk = yd_raft_view_disk(owned);
        int pending = yd_raft_index_job_pending(disk, &view, id, error, sizeof(error));
        if (pending == 1) {
            IndexBuild build = {.cluster = c, .generation = owned->generation,
                .term = status.raft.term, .end = deadline(30000)};
            memcpy(build.job, id, 16);
            YDDiskTxn *txn = NULL;
            YDDiskReply built = yd_raft_index_job_build(disk, id, index_progress, &build,
                index_admission, &build, &txn, error, sizeof(error));
            char path[50] = "/v1/index-builds/";
            for (unsigned i = 0; i < 16; i++) {
                path[17 + i * 2] = hex[id[i] >> 4]; path[18 + i * 2] = hex[id[i] & 15];
            }
            path[49] = 0;
            YDRaftWrite write = {.method = "PUBLISH", .target = path};
            bool identified = index_request_id(id, false, write.id);
            if (txn) {
                bool staged = identified && build.admitted &&
                    yd_raft_application_stage(application(c), &write, txn, &built);
                if (staged) {
                    txn = NULL;
                    YDDiskReply result = write_locked(c, &write, build.term, build.end);
                    yd_disk_reply_free(&result);
                    yd_raft_application_unstage(application(c));
                }
                yd_disk_abort(txn);
                index_admission(&build, false);
            } else if (!atomic_load(&c->stopping)) {
                const char *failure = strstr(error, "unique") ? "unique_constraint" :
                    strstr(error, "history") || strstr(error, "catalog changed")
                        ? "history_unavailable" : NULL;
                if (failure && index_request_id(id, true, write.id)) {
                    write.method = "FAIL";
                    write.body = (const unsigned char *)failure;
                    write.size = strlen(failure);
                    YDDiskReply result = cluster_write(c, &write, 3000);
                    yd_disk_reply_free(&result);
                }
            }
            yd_disk_reply_free(&built);
        }
        yd_raft_view_close(owned);
    }
    return NULL;
}

YDDiskReply yd_raft_cluster_write(YDRaftCluster *c, const YDRaftWrite *write, unsigned timeout_ms) {
    if (!c || !write) return yd_disk_error_reply(400, "invalid_cluster_request");
    bool allowed = true;
    uint64_t call = yd_session2_mutation_enter(c->node, write->id, &allowed);
    YDDiskReply reply = allowed ? cluster_write(c, write, timeout_ms) :
        yd_disk_error_reply(503, "qualification_gate_timeout");
    yd_session2_mutation_exit(c->node, write->id, call);
    return reply;
}
