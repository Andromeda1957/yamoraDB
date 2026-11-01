#define _POSIX_C_SOURCE 200809L
#include "raft_cluster_application_fixture.h"
#include "../src/consensus/cluster_internal.h"
#include "../src/consensus/runtime_internal.h"
#include "../src/consensus/application_compact.h"
#include "../src/consensus/application_retire.h"
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
static void fixture_bytes(int file, const void *bytes, size_t size) {
    if (write(file, bytes, size) != (ssize_t)size) {
        fputs("APPLICATION_FIXTURE_WRITE_FAILED\n", stderr);
        _Exit(3); /* Infrastructure failure, never behavioral RED. */
    }
}
struct ApplicationFixture {
    YDRaftCluster *cluster;
    YDRaftApplicationImage *image, *probe;
    YDRaftApplicationRetirement *retirement;
    YDRaftApplicationCapture *source;
    YDRaftJournalCapture *journal_capture;
    YDDisk *journal_reader;
    YDDiskRecoveryRoots *journal_roots;
    unsigned journal_kind;
    bool pin_journal;
    YDRaftApplicationWorkspace *owned;
    YDRaftApplicationCompaction *compaction;
    YDRaftApplicationCompactionReport compact_report;
    YDRaftApplicationCompactionPolicy compact_policy;
    bool compacting;
    YDDisk *reader;
    YDDiskCheckpoint *checkpoint;
    bool retaining, typed, limited;
    YDRaftApplicationLimits limits;
    YDRaftApplicationAdmissionReport admission;
    int directory, workspace;
    unsigned copies, timeout, held, fault;
    pthread_t thread, writer, retiring, checkpointing;
    bool checkpoint_started;
    atomic_uint checkpoint_result;
    bool retirement_started;
    bool retirement_birth, retirement_birth_swapped;
    int retirement_result;
    unsigned retirement_sync, retirement_unlink, retirement_hold_at, retirement_steps;
    bool refresh_fault;
    atomic_bool retirement_done, retirement_hold, retirement_entered;
    bool started, writer_started, result, published;
    unsigned writer_id, writer_status;
    atomic_bool done, hold, entered, cancel, decision, writer_done;
    unsigned terminal, outcome;
    unsigned inventory_delay;
    unsigned inventory_scans;
    bool change_after_inventory;
    bool change_retained_inventory;
    bool fail_observation;
    unsigned observations;
};
static _Thread_local ApplicationFixture *selecting, *retiring;
static _Thread_local bool files_retiring;
int __real_yd_raft_retired_files_retire(YDRaftRetiredFiles *, char *, size_t);
int __wrap_yd_raft_retired_files_retire(YDRaftRetiredFiles *files, char *error, size_t length) {
    files_retiring = true;
    int result = __real_yd_raft_retired_files_retire(files, error, length);
    files_retiring = false;
    return result;
}
static _Thread_local ApplicationFixture *capturing_journal;
YDDisk *__real_yd_disk_pin(YDDisk *, size_t, char *, size_t);
YDDisk *__wrap_yd_disk_pin(YDDisk *disk, size_t cache, char *error, size_t length) {
    YDDisk *reader = __real_yd_disk_pin(disk, cache, error, length);
    ApplicationFixture *f = capturing_journal;
    if (reader && f && f->journal_kind == 1)
        f->journal_reader = __real_yd_disk_pin(reader, cache, error, length);
    if (reader && f && f->journal_kind == 2)
        (void)yd_disk_recovery_roots_pin(disk, cache, &f->journal_roots, error, length);
    return reader;
}
static _Thread_local unsigned failing, syncs, unlink_failure, unlinks;
static atomic_uint worker_hold, worker_entered;
static atomic_bool worker_cancelled, worker_published;
static atomic_uint worker_result;
static _Thread_local bool automatic;
typedef struct { YDRaftSnapshotProgress progress; void *context; } WorkerProxy;
static bool worker_progress(void *context, uint64_t done, uint64_t total) {
    WorkerProxy *p = context;
    unsigned hold = atomic_load(&worker_hold);
    bool boundary = (hold == 1 && !done && total) || (hold == 4 && !done && !total);
    if (boundary && !atomic_exchange(&worker_entered, hold))
        while (atomic_load(&worker_hold) && !atomic_load(&worker_cancelled)) {
            if (p->progress && !p->progress(p->context, done, total)) return false;
            struct timespec pause = {.tv_nsec = 1000000}; nanosleep(&pause, NULL);
        }
    return !p->progress || p->progress(p->context, done, total);
}
YDRaftApplicationCompactionResult __real_yd_raft_application_compaction_run(
    YDRaftApplicationCompaction *, YDRaftApplicationCompactionPolicy, YDRaftSnapshotProgress,
    void *, YDRaftApplicationCompactionReport *, char *, size_t);
YDRaftApplicationCompactionResult __wrap_yd_raft_application_compaction_run(
    YDRaftApplicationCompaction *owner, YDRaftApplicationCompactionPolicy policy,
    YDRaftSnapshotProgress callback, void *context, YDRaftApplicationCompactionReport *report,
    char *error, size_t length) {
    automatic = !selecting;
    WorkerProxy proxy = {.progress = callback, .context = context};
    YDRaftApplicationCompactionResult result = __real_yd_raft_application_compaction_run(owner,
        policy, automatic ? worker_progress : callback, automatic ? &proxy : context,
        report, error, length);
    if (automatic) {
        atomic_store(&worker_published, report->published);
        atomic_store(&worker_result, result);
    }
    automatic = false;
    return result;
}
YDRaftApplicationSelection __real_yd_raft_cluster_application_select_retained(YDRaftCluster *,
    YDRaftApplicationImage *, YDRaftApplicationWorkspace *, YDRaftApplicationRetirement *const *,
    size_t, YDRaftApplicationLimits, unsigned, YDRaftSnapshotProgress, void *,
    YDRaftApplicationDecisionCheck, void *, bool *, YDRaftApplicationRetirement **,
    YDRaftApplicationAdmissionReport *, char *, size_t);
YDRaftApplicationSelection __wrap_yd_raft_cluster_application_select_retained(YDRaftCluster *cluster,
    YDRaftApplicationImage *image, YDRaftApplicationWorkspace *workspace,
    YDRaftApplicationRetirement *const *retained, size_t count, YDRaftApplicationLimits limits,
    unsigned admission_ms, YDRaftSnapshotProgress callback, void *context,
    YDRaftApplicationDecisionCheck decision, void *decision_context, bool *published,
    YDRaftApplicationRetirement **retirement, YDRaftApplicationAdmissionReport *report,
    char *error, size_t length) {
    if (automatic && atomic_load(&worker_hold) == 2) {
        atomic_store(&worker_entered, 2);
        while (atomic_load(&worker_hold) && !atomic_load(&worker_cancelled)) {
            struct timespec pause = {.tv_nsec = 1000000}; nanosleep(&pause, NULL);
        }
    }
    return __real_yd_raft_cluster_application_select_retained(cluster, image, workspace,
        retained, count, limits, admission_ms, callback, context, decision, decision_context,
        published, retirement, report, error, length);
}
YDRaftApplicationSelection __real_yd_raft_cluster_application_select_slots(YDRaftCluster *,
    YDRaftApplicationImage *, YDRaftApplicationWorkspace *, YDRaftApplicationLimits,
    unsigned, YDRaftSnapshotProgress, void *, YDRaftApplicationDecisionCheck, void *,
    bool *, YDRaftApplicationRetirement **, YDRaftApplicationAdmissionReport *, char *, size_t);
YDRaftApplicationSelection __wrap_yd_raft_cluster_application_select_slots(YDRaftCluster *cluster,
    YDRaftApplicationImage *image,YDRaftApplicationWorkspace *workspace,YDRaftApplicationLimits limits,
    unsigned admission_ms,YDRaftSnapshotProgress callback,void *context,
    YDRaftApplicationDecisionCheck decision,void *decision_context,bool *published,
    YDRaftApplicationRetirement **retirement,YDRaftApplicationAdmissionReport *report,char *error,size_t length) {
    if(automatic && atomic_load(&worker_hold)==2) {
        atomic_store(&worker_entered,2);
        while(atomic_load(&worker_hold) && !atomic_load(&worker_cancelled)) {
            struct timespec pause={.tv_nsec=1000000};nanosleep(&pause,NULL);
        }
    }
    return __real_yd_raft_cluster_application_select_slots(cluster,image,workspace,limits,
        admission_ms,callback,context,decision,decision_context,published,retirement,report,error,length);
}
void __real_yd_raft_application_compaction_cancel(YDRaftApplicationCompaction *);
void __wrap_yd_raft_application_compaction_cancel(YDRaftApplicationCompaction *owner) {
    __real_yd_raft_application_compaction_cancel(owner);
    atomic_store(&worker_cancelled, true);
}
static void worker_inventory_hold(bool valid, const char *replacement) {
    if (valid && automatic && replacement && atomic_load(&worker_hold) == 3 &&
        !atomic_exchange(&worker_entered, 3))
        while (atomic_load(&worker_hold) && !atomic_load(&worker_cancelled)) {
            struct timespec pause = {.tv_nsec = 1000000}; nanosleep(&pause, NULL);
        }
}
void yd_test_application_worker_report(void) {
    printf("worker-closed %u %u %u\n", atomic_load(&worker_result),
        atomic_load(&worker_published), atomic_load(&worker_cancelled));
}
int __real_mkdirat(int, const char *, mode_t);
int __wrap_mkdirat(int directory, const char *name, mode_t mode) {
    int result = __real_mkdirat(directory, name, mode);
    if (!result && retiring && retiring->retirement_birth && !retiring->retirement_birth_swapped &&
        !strncmp(name, ".retiring-application-", 22)) {
        retiring->retirement_birth_swapped = true;
        if (renameat(directory, name, directory, "birth-held") ||
            __real_mkdirat(directory, name, 0700)) abort();
    }
    return result;
}
bool __real_yd_raft_runtime_snapshot_observe(YDRaftRuntime *, int *, YDRaftApplicationVolume *);
bool __wrap_yd_raft_runtime_snapshot_observe(YDRaftRuntime *runtime, int *directory,
    YDRaftApplicationVolume *volume) {
    if (selecting && selecting->fail_observation && ++selecting->observations == 2) {
        *directory = -1; *volume = (YDRaftApplicationVolume){0}; return false;
    }
    return __real_yd_raft_runtime_snapshot_observe(runtime, directory, volume);
}
bool __real_yd_raft_application_space(int, int, int, int, const char *, const unsigned char *,
    unsigned, YDRaftApplicationSpace *, char *, size_t);
bool __wrap_yd_raft_application_space(int documents, int archives, int workspace, int source,
    const char *replacement, const unsigned char *cluster, unsigned voters,
    YDRaftApplicationSpace *space, char *error, size_t length) {
    if (selecting && selecting->inventory_delay) {
        unsigned delay = selecting->inventory_delay;
        selecting->inventory_delay = 0;
        struct timespec pause = {.tv_sec = delay / 1000, .tv_nsec = (long)(delay % 1000) * 1000000};
        while (nanosleep(&pause, &pause) && errno == EINTR) {}
    }
    return __real_yd_raft_application_space(documents, archives, workspace, source, replacement,
        cluster, voters, space, error, length);
}
bool __real_yd_raft_application_space_with_custody(int, int, int, int, int, const char *,
    const unsigned char *, unsigned, YDRaftApplicationSpace *, char *, size_t);
bool __wrap_yd_raft_application_space_with_custody(int documents, int archives, int workspace,
    int custody, int source, const char *replacement, const unsigned char *cluster, unsigned voters,
    YDRaftApplicationSpace *space, char *error, size_t length) {
    bool valid = __real_yd_raft_application_space_with_custody(documents, archives, workspace,
        custody, source, replacement, cluster, voters, space, error, length);
    worker_inventory_hold(valid, replacement);
    if (valid && replacement && selecting && selecting->held == 3 &&
        !atomic_exchange(&selecting->entered, true))
        while (atomic_load(&selecting->hold)) {
            struct timespec pause = {.tv_nsec = 1000000}; nanosleep(&pause, NULL);
        }
    if (valid && selecting && selecting->change_after_inventory && ++selecting->inventory_scans == 2) {
        static const char bytes[] = "# preserve after scan\n";
        int file = openat(workspace, "owner-after-scan", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (file >= 0) {
            fixture_bytes(file, bytes, sizeof(bytes) - 1);
            close(file);
        }
    }
    return valid;
}
bool __real_yd_raft_application_space_with_shells(int, int, int, int, const int *, size_t,
    int, const char *, const unsigned char *, unsigned, YDRaftApplicationSpace *, char *, size_t);
bool __wrap_yd_raft_application_space_with_shells(int documents, int archives, int workspace,
    int custody, const int *shells, size_t count, int source, const char *replacement,
    const unsigned char *cluster, unsigned voters, YDRaftApplicationSpace *space,
    char *error, size_t length) {
    bool valid = __real_yd_raft_application_space_with_shells(documents, archives, workspace,
        custody, shells, count, source, replacement, cluster, voters, space, error, length);
    worker_inventory_hold(valid, replacement);
    if (valid && count && selecting && selecting->change_retained_inventory &&
        ++selecting->inventory_scans == 3) {
        static const char bytes[] = "# preserve retained owner data\n";
        int file = openat(shells[0], "owner-after-scan", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (file >= 0) {
            fixture_bytes(file, bytes, sizeof(bytes) - 1);
            close(file);
        }
    }
    return valid;
}
bool __real_yd_raft_application_space_with_slots(int,int,int,int,const int *,size_t,int,int,
    const char *,const unsigned char *,unsigned,YDRaftApplicationSpace *,char *,size_t);
bool __wrap_yd_raft_application_space_with_slots(int documents,int archives,int workspace,
    int custody,const int *slots,size_t count,int retirement_custody,int source,const char *replacement,
    const unsigned char *cluster,unsigned voters,YDRaftApplicationSpace *space,char *error,size_t length) {
    bool valid=__real_yd_raft_application_space_with_slots(documents,archives,workspace,custody,
        slots,count,retirement_custody,source,replacement,cluster,voters,space,error,length);
    worker_inventory_hold(valid,replacement);
    if(valid && replacement && selecting && selecting->held==3 &&
        !atomic_exchange(&selecting->entered,true))
        while(atomic_load(&selecting->hold)) {
            struct timespec pause={.tv_nsec=1000000};nanosleep(&pause,NULL);
        }
    if(valid && selecting && selecting->change_after_inventory && ++selecting->inventory_scans==2) {
        static const char bytes[]="# preserve after scan\n";
        int file=openat(workspace,"owner-after-scan",O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
        if(file>=0) {fixture_bytes(file,bytes,sizeof(bytes)-1);close(file);}
    }
    if(valid && retirement_custody>=0 && selecting && selecting->change_retained_inventory &&
        ++selecting->inventory_scans==3) {
        static const char bytes[]="# preserve retained owner data\n";
        int file=openat(retirement_custody,"owner-after-scan",O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
        if(file>=0) {fixture_bytes(file,bytes,sizeof(bytes)-1);close(file);}
    }
    return valid;
}
int __real_unlinkat(int, const char *, int);
int __wrap_unlinkat(int directory, const char *name, int flags) {
    if (retiring && (flags & AT_REMOVEDIR)) abort();
    if (unlink_failure && ++unlinks == unlink_failure) { errno = EIO; return -1; }
    return __real_unlinkat(directory, name, flags);
}
bool yd_test_application_sync(void) {
    /* Journal refresh precedes filesystem retirement. Keep the existing seven
     * custody sync boundaries isolated, with a separate refresh failure oracle. */
    if (retiring && !files_retiring) {
        if (retiring->refresh_fault) {
            retiring->refresh_fault = false;
            errno = EIO;
            return true;
        }
        return false;
    }
    if (retiring && ++retiring->retirement_steps == retiring->retirement_hold_at &&
        !atomic_exchange(&retiring->retirement_entered, true))
        while (atomic_load(&retiring->retirement_hold)) {
            struct timespec delay = {.tv_nsec = 1000000}; nanosleep(&delay, NULL);
        }
    if (failing && ++syncs == failing) {
        errno = EIO;
        return true;
    }
    return false;
}
bool __real_yd_raft_runtime_application_select(YDRaftRuntime *, const unsigned char *,
                                               const YDRaftSnapshotBase *, YDRaftSnapshotPublish,
                                               void *, bool *);
static bool before_decision(YDRaftRuntime *runtime) {
    if (selecting) {
        if (selecting->pin_journal && !selecting->journal_capture) {
            capturing_journal = selecting;
            selecting->journal_capture = yd_raft_runtime_journal_capture(runtime, 32768, NULL, 0);
            capturing_journal = NULL;
            if (!selecting->journal_capture) return false;
            if (selecting->journal_kind) {
                yd_raft_journal_capture_close(selecting->journal_capture);
                selecting->journal_capture = NULL;
                if (!selecting->journal_reader && !selecting->journal_roots) return false;
            }
        }
        atomic_store(&selecting->decision, true);
        if (selecting->fault <= 2) {
            failing = selecting->fault;
            syncs = 0;
        }
        if (selecting->fault == 3)
            yd_raft_runtime_fence(runtime);
    }
    return true;
}
bool __wrap_yd_raft_runtime_application_select(YDRaftRuntime *runtime,
    const unsigned char *expected,const YDRaftSnapshotBase *base,
    YDRaftSnapshotPublish publish,void *context,bool *published) {
    if(!before_decision(runtime)) return false;
    bool valid = __real_yd_raft_runtime_application_select(runtime, expected, base, publish,
                                                           context, published);
    failing = 0;
    return valid;
}
bool __real_yd_raft_runtime_application_select_layout(YDRaftRuntime *,const unsigned char *,
    const YDRaftSnapshotBase *,unsigned,YDRaftSnapshotPublish,void *,bool *);
bool __wrap_yd_raft_runtime_application_select_layout(YDRaftRuntime *runtime,
    const unsigned char *expected,const YDRaftSnapshotBase *base,unsigned layout,
    YDRaftSnapshotPublish publish,void *context,bool *published) {
    if(!before_decision(runtime)) return false;
    bool valid=__real_yd_raft_runtime_application_select_layout(runtime,expected,base,layout,publish,context,published);
    failing=0;return valid;
}
static bool progress(void *context, uint64_t done, uint64_t total) {
    ApplicationFixture *f = context;
    bool boundary =
        (f->held == 1 && !done && total) || (f->held == 2 && !done && !total && ++f->terminal == 2) ||
        (f->held == 4 && !done && !total);
    if (boundary && !atomic_exchange(&f->entered, true))
        while (atomic_load(&f->hold) && !atomic_load(&f->cancel)) {
            struct timespec delay = {.tv_nsec = 1000000};
            nanosleep(&delay, NULL);
        }
    return !atomic_load(&f->cancel);
}
static void *select_image(void *context) {
    ApplicationFixture *f = context;
    char error[512] = {0};
    selecting = f;
    if (f->compacting) {
        (void)yd_raft_application_compaction_run(f->compaction, f->compact_policy,
            progress, f, &f->compact_report, error, sizeof(error));
        f->result = f->compact_report.result == YD_RAFT_COMPACTION_RETIRED;
        f->published = f->compact_report.published;
    } else if (f->owned) {
        f->outcome = yd_raft_cluster_application_select_owned(f->cluster, f->image,
            f->owned, f->limits, f->timeout, progress, f, &f->published,
            f->retaining ? &f->retirement : NULL, &f->admission, error, sizeof(error));
        f->result = f->outcome == YD_RAFT_APPLICATION_SELECTED;
    } else if (f->limited) {
        f->outcome = yd_raft_cluster_application_select_limited(f->cluster, f->image,
            f->workspace, f->limits, f->timeout, progress, f, &f->published,
            f->retaining ? &f->retirement : NULL, &f->admission, error, sizeof(error));
        f->result = f->outcome == YD_RAFT_APPLICATION_SELECTED;
    } else if (f->typed) {
        f->outcome = yd_raft_cluster_application_select_outcome(f->cluster, f->image, f->timeout,
            progress, f, &f->published, f->retaining ? &f->retirement : NULL, error, sizeof(error));
        f->result = f->outcome == YD_RAFT_APPLICATION_SELECTED;
    } else {
        f->result = f->retaining
            ? yd_raft_cluster_application_select_retaining(f->cluster, f->image, f->timeout,
                progress, f, &f->published, &f->retirement, error, sizeof(error))
            : yd_raft_cluster_application_select(f->cluster, f->image, f->timeout, progress, f,
                &f->published, error, sizeof(error));
        f->outcome = f->result ? YD_RAFT_APPLICATION_SELECTED : 0;
    }
    selecting = NULL;
    atomic_store(&f->done, true);
    return NULL;
}
static void *retire_image(void *context) {
    ApplicationFixture *f = context;
    char error[512] = {0};
    retiring = f;
    failing = f->retirement_sync; syncs = 0;
    unlink_failure = f->retirement_unlink; unlinks = 0;
    for (unsigned attempt = 0; attempt < 2000; attempt++) {
        f->retirement_result = yd_raft_cluster_application_retire(f->cluster, f->retirement, error, sizeof(error));
        if (f->retirement_result) break;
        struct timespec delay = {.tv_nsec = 1000000}; nanosleep(&delay, NULL);
    }
    failing = unlink_failure = 0; retiring = NULL;
    atomic_store(&f->retirement_done, true);
    return NULL;
}
static void *write_image(void *context) {
    ApplicationFixture *f = context;
    static const unsigned char patch[] = "{\"$inc\":{\"count\":1}}";
    YDRaftWrite w = {.method = "PATCH",
                     .target = "/v1/collections/config/documents/node",
                     .body = patch,
                     .size = sizeof(patch) - 1};
    w.id[0] = (unsigned char)f->writer_id;
    YDDiskReply reply = yd_raft_cluster_write(f->cluster, &w, f->timeout);
    f->writer_status = (unsigned)reply.status;
    yd_disk_reply_free(&reply);
    atomic_store(&f->writer_done, true);
    return NULL;
}
static void *checkpoint_image(void *context) {
    ApplicationFixture *f = context;
    char error[512] = {0};
    YDRaftCapture *capture = yd_raft_cluster_capture(f->cluster, f->timeout,
        NULL, NULL, error, sizeof(error));
    bool valid = capture && yd_raft_cluster_checkpoint(f->cluster, capture, f->timeout);
    yd_raft_capture_close(capture);
    atomic_store(&f->checkpoint_result, valid ? 1 : 2);
    return NULL;
}
ApplicationFixture *yd_test_application_new(YDRaftCluster *cluster, const char *root,
                                            unsigned timeout) {
    ApplicationFixture *f = calloc(1, sizeof(*f));
    if (!f)
        return NULL;
    f->cluster = cluster;
    f->workspace = -1;
    f->timeout = timeout;
    f->directory = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (f->directory < 0) {
        free(f);
        return NULL;
    }
    atomic_init(&f->done, true);
    atomic_init(&f->hold, false);
    atomic_init(&f->entered, false);
    atomic_init(&f->cancel, false);
    atomic_init(&f->decision, false);
    atomic_init(&f->writer_done, true);
    atomic_init(&f->retirement_done, true);
    atomic_init(&f->retirement_hold, false);
    atomic_init(&f->retirement_entered, false);
    atomic_init(&f->checkpoint_result, 0);
    return f;
}
bool yd_test_application_command(ApplicationFixture *f, const char *line) {
    char error[512] = {0};
    if (!f || strncmp(line, "app-", 4))
        return false;
    if (!strcmp(line, "app-copy") || !strcmp(line, "app-probe-copy")) {
        bool probe = !strcmp(line, "app-probe-copy");
        bool valid = !f->started;
        YDRaftApplicationCapture *capture =
            valid ? yd_raft_cluster_application_capture(f->cluster, 32768, error, sizeof(error))
                  : NULL;
        char name[40];
        int dir = -1;
        int parent = f->limited ? yd_raft_cluster_snapshot_directory(f->cluster) : -1;
        int destination = f->limited ? parent : f->directory;
        if (capture && f->owned && !probe)
            dir = fcntl(yd_raft_application_workspace_directory(f->owned), F_DUPFD_CLOEXEC, 3);
        for (unsigned attempt = 0; capture && !f->owned && attempt < 64; attempt++) {
            snprintf(name, sizeof(name), ".app-copy-%u", ++f->copies);
            if (!mkdirat(destination, name, 0700)) {
                dir = openat(destination, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
                break;
            }
            if (errno != EEXIST)
                break;
        }
        YDRaftApplicationImage *next =
            dir < 0 ? NULL : f->limited
                ? yd_raft_application_copy_limited(capture, dir, 32768, f->limits.image_bytes,
                    NULL, NULL, NULL, error, sizeof(error))
                : yd_raft_application_copy(capture, dir, 32768, NULL, NULL, error, sizeof(error));
        if (next && f->owned && !yd_raft_application_workspace_bind(f->owned, next, error, sizeof(error))) {
            yd_raft_application_image_close(next);
            next = NULL;
        }
        if (parent >= 0) close(parent);
        if (dir >= 0 && (!f->limited || !next))
            close(dir);
        yd_raft_application_capture_close(capture);
        if (next) {
            YDRaftApplicationImage **slot = probe ? &f->probe : &f->image;
            yd_raft_application_image_close(*slot);
            *slot = next;
            if (f->limited) { if (f->workspace >= 0) close(f->workspace); f->workspace = dir; }
        }
        printf("%s %u\n", probe ? "app-probe-copy" : "app-copy", next != NULL);
    } else if (!strncmp(line, "app-worker-hold ", 16)) {
        atomic_store(&worker_entered, 0);
        atomic_store(&worker_cancelled, false);
        atomic_store(&worker_hold, (unsigned)strtoul(line + 16, NULL, 10));
        puts("app-worker-held");
    } else if (!strcmp(line, "app-worker-entered")) {
        printf("app-worker-entered %u\n", atomic_load(&worker_entered));
    } else if (!strcmp(line, "app-worker-release")) {
        atomic_store(&worker_hold, 0);
        puts("app-worker-released");
    } else if (!strcmp(line, "app-due")) {
        printf("app-due %u\n", yd_raft_cluster_application_compaction_due(f->cluster));
    } else if (!strncmp(line, "app-worker-enable ", 18)) {
        uint64_t minimum;
        unsigned interval;
        bool valid = f->limited && sscanf(line + 18, "%" SCNu64 " %u", &minimum, &interval) == 2;
        YDRaftApplicationWorkerPolicy policy = {.operation = {.limits = f->limits,
            .minimum_source_bytes = valid ? minimum : 0, .admission_ms = f->timeout, .work_ms = 30000},
            .interval_ms = valid ? interval : 0};
        valid = valid && yd_raft_cluster_application_compactions(f->cluster, policy);
        printf("app-worker-enable %u\n", valid);
    } else if (!strcmp(line, "app-worker-state")) {
        YDRaftApplicationWorkerStatus s = yd_raft_cluster_status(f->cluster).application_compaction;
        printf("app-worker-state %u %u %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64
            " %u %u %zu %u %u %d\n", s.enabled, s.running, s.attempted, s.reconciled,
            s.publications, s.retired, s.pending, s.blocked, s.retained, s.history_full,
            (unsigned)s.stop, s.result);
    } else if (!strncmp(line, "app-compact-fault ", 18)) {
        bool valid = !f->started && sscanf(line + 18, "%u", &f->fault) == 1 && f->fault <= 2;
        printf("app-compact-fault %u\n", valid);
    } else if (!strncmp(line, "app-compact-start ", 18)) {
        bool valid = !f->started && f->limited && sscanf(line + 18, "%" SCNu64 " %u %u",
            &f->compact_policy.minimum_source_bytes, &f->compact_policy.work_ms, &f->held) == 3;
        if (valid && !f->compaction)
            f->compaction = yd_raft_application_compaction_new(f->cluster, 32768);
        valid = valid && f->compaction;
        if (valid) {
            f->compact_policy.limits = f->limits;
            f->compact_policy.admission_ms = f->timeout;
            f->compacting = true;
            f->result = f->published = false;
            f->terminal = 0;
            atomic_store(&f->done, false);
            atomic_store(&f->entered, false);
            atomic_store(&f->decision, false);
            atomic_store(&f->cancel, false);
            atomic_store(&f->hold, f->held != 0);
            valid = (f->started = !pthread_create(&f->thread, NULL, select_image, f));
            if (!valid) atomic_store(&f->done, true);
        }
        printf("app-compact-start %u\n", valid);
    } else if (!strcmp(line, "app-compact-report")) {
        bool done = atomic_load(&f->done);
        printf("app-compact-report %u %u %u %u %u %u %zu %u\n",
            done ? (unsigned)f->compact_report.result : 0,
            done && f->compact_report.published, done && f->compact_report.pending,
            done && f->compact_report.timed_out,
            done ? (unsigned)f->compact_report.admission.admission : 0,
            done ? (unsigned)f->compact_report.selection : 0,
            done ? f->compact_report.retained : 0,
            done && f->compact_report.history_full);
    } else if (!strcmp(line, "app-compact-blocked")) {
        printf("app-compact-blocked %u\n", atomic_load(&f->done) && f->compact_report.blocked);
    } else if (!strcmp(line, "app-compact-allocation")) {
        bool done = atomic_load(&f->done);
        printf("app-compact-allocation %" PRIu64 " %" PRIu64 "\n",
            done ? f->compact_report.image.limit : 0,
            done ? f->compact_report.image.high_water : 0);
    } else if (!strcmp(line, "app-compact-cancel")) {
        yd_raft_application_compaction_cancel(f->compaction);
        atomic_store(&f->hold, false);
        puts("app-compact-cancelled");
    } else if (!strcmp(line, "app-owned")) {
        int parent = !f->started && f->limited && !f->owned
            ? yd_raft_cluster_snapshot_directory(f->cluster) : -1;
        if (parent >= 0) {
            f->owned = yd_raft_application_workspace_create(parent, error, sizeof(error));
            close(parent);
        }
        printf("app-owned %u\n", f->owned != NULL);
    } else if (!strcmp(line, "app-owned-probe")) {
        YDRaftApplicationAdmissionReport report = {0};
        bool valid = !f->started && yd_raft_cluster_application_admission_owned(f->cluster,
            f->owned, f->limits, &report, error, sizeof(error));
        printf("app-owned-probe %u %u\n", valid, (unsigned)report.admission);
    } else if (!strcmp(line, "app-owned-recycle")) {
        int result = -1;
        if (!f->started && f->published && f->result && f->owned) {
            yd_raft_application_image_close(f->image); f->image = NULL;
            result = yd_raft_application_workspace_discard(f->owned,
                YD_RAFT_WORKSPACE_CONFIRMED_SUCCESS, error, sizeof(error));
            if (result == 1)
                result = yd_raft_application_workspace_recycle(f->owned, error, sizeof(error));
        }
        printf("app-owned-recycle %d\n", result);
    } else if (!strncmp(line, "app-limits ", 11)) {
        YDRaftApplicationLimits limits = {.image_bytes = 1024*1024, .minimum_free_bytes = 4096};
        bool valid = !f->started && sscanf(line + 11, "%" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64,
            &limits.maximum_work_bytes, &limits.maximum_retained_bytes, &limits.minimum_saved_bytes,
            &limits.archive_bytes, &limits.restore_bytes) == 5;
        if (valid) { f->limited = true; f->limits = limits; }
        printf("app-limits %u\n", valid);
    } else if (!strcmp(line, "app-admission")) {
        bool done = atomic_load(&f->done);
        printf("app-admission %u %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 "\n",
            done ? (unsigned)f->admission.admission : 0,
            done ? f->admission.source_bytes : 0, done ? f->admission.saved_bytes : 0,
            done ? f->admission.archive.high_water : 0, done ? f->admission.restore.high_water : 0);
    } else if (!strcmp(line, "app-probe-admission")) {
        YDRaftApplicationAdmissionReport report = {0};
        bool valid = !f->started && yd_raft_cluster_application_admission(f->cluster, -1,
            f->limits, &report, error, sizeof(error));
        printf("app-probe-admission %u %u\n", valid, (unsigned)report.admission);
    } else if (!strcmp(line, "app-change-retained-inventory")) {
        if (!f->started) { f->change_retained_inventory = true; f->inventory_scans = 0; }
        puts("app-changing-retained-inventory");
    } else if (!strcmp(line, "app-change-after-inventory")) {
        if (!f->started) { f->change_after_inventory = true; f->inventory_scans = 0; }
        puts("app-changing-after-inventory");
    } else if (!strcmp(line, "app-delay-inventory")) {
        if (!f->started) f->inventory_delay = f->timeout + 300;
        puts("app-delayed-inventory");
    } else if (!strcmp(line, "app-fail-observation")) {
        if (!f->started) { f->fail_observation = true; f->observations = 0; }
        puts("app-observation-failure");
    } else if (!strcmp(line, "app-typed")) {
        if (!f->started) f->typed = true;
        puts("app-typed");
    } else if (!strcmp(line, "app-pin-journal")) {
        if (!f->started) f->pin_journal = true;
        puts("app-pinning-journal");
    } else if (!strncmp(line, "app-pin-journal-kind ", 21)) {
        if (!f->started) {
            f->pin_journal = true;
            f->journal_kind = (unsigned)strtoul(line + 21, NULL, 10);
        }
        puts("app-pinning-journal-kind");
    } else if (!strcmp(line, "app-journal-held")) {
        printf("app-journal-held %u\n", !f->started &&
            (f->journal_capture || f->journal_reader || f->journal_roots));
    } else if (!strcmp(line, "app-drop-journal")) {
        if (!f->started) {
            yd_raft_journal_capture_close(f->journal_capture);
            yd_disk_close(f->journal_reader);
            yd_disk_recovery_roots_close(f->journal_roots);
            f->journal_capture = NULL;
            f->journal_reader = NULL;
            f->journal_roots = NULL;
            f->pin_journal = false;
        }
        puts("app-journal-closed");
    } else if (!strcmp(line, "app-checkpoint-start")) {
        bool valid = !f->checkpoint_started;
        if (valid) valid = (f->checkpoint_started = !pthread_create(&f->checkpointing, NULL, checkpoint_image, f));
        printf("app-checkpoint-start %u\n", valid);
    } else if (!strcmp(line, "app-checkpoint-state")) {
        printf("app-checkpoint-state %u\n", atomic_load(&f->checkpoint_result));
    } else if (!strcmp(line, "app-retain")) {
        bool valid = !f->started && !f->retirement;
        if (valid) f->retaining = true;
        printf("app-retain %u\n", valid);
    } else if (!strcmp(line, "app-no-retain")) {
        if (!f->started) f->retaining = false;
        puts("app-no-retain");
    } else if (!strcmp(line, "app-retire-birth")) {
        if (!f->retirement_started && !f->started) f->retirement_birth = true;
        puts("app-retire-birth");
    } else if (!strncmp(line, "app-retire-start", 16)) {
        bool valid = !f->retirement_started && !f->started && f->retirement;
        if (valid) {
            f->retirement_sync = f->retirement_unlink = 0;
            f->retirement_steps = 0;
            f->retirement_hold_at = line[16] == ' ' ? (unsigned)strtoul(line + 17, NULL, 10) : 1;
            atomic_store(&f->retirement_done, false);
            atomic_store(&f->retirement_entered, false);
            atomic_store(&f->retirement_hold, true);
            valid = (f->retirement_started = !pthread_create(&f->retiring, NULL, retire_image, f));
            if (!valid) atomic_store(&f->retirement_done, true);
        }
        printf("app-retire-start %u\n", valid);
    } else if (!strcmp(line, "app-retire-state")) {
        bool done = atomic_load(&f->retirement_done);
        printf("app-retire-state %u %u %d\n", done, atomic_load(&f->retirement_entered), done ? f->retirement_result : 0);
    } else if (!strcmp(line, "app-retire-release")) {
        atomic_store(&f->retirement_hold, false); puts("app-retire-released");
    } else if (!strcmp(line, "app-retire-join")) {
        if (f->retirement_started) { pthread_join(f->retiring, NULL); f->retirement_started = false; }
        printf("app-retire-result %d\n", f->retirement_result);
    } else if (!strcmp(line, "app-rejected-put")) {
        unsigned char body[2048];
        memset(body, 'x', sizeof(body));
        memcpy(body, "value: ", 7);
        body[sizeof(body) - 1] = '\n';
        YDRaftWrite write = {.method = "PUT", .target = "/v1/collections/config/documents/rejected",
            .body = body, .size = sizeof(body)};
        write.id[0] = 230;
        YDDiskReply reply = yd_raft_cluster_write(f->cluster, &write, f->timeout);
        printf("app-rejected-put %d\n", reply.status);
        yd_disk_reply_free(&reply);
    } else if (!strcmp(line, "app-ticket")) {
        printf("app-ticket %u\n", !f->started && f->retirement != NULL);
    } else if (!strcmp(line, "app-fail-refresh")) {
        f->refresh_fault = true;
        puts("app-failing-refresh");
    } else if (!strncmp(line, "app-retire ", 11)) {
        unsigned sync = 0, unlink = 0;
        int result = -1;
        if ((!f->started || !f->retaining) && !f->retirement_started && sscanf(line + 11, "%u %u", &sync, &unlink) == 2) {
            failing = sync; syncs = 0; unlink_failure = unlink; unlinks = 0;
            retiring = f;
            result = yd_raft_cluster_application_retire(f->cluster, f->retirement, error, sizeof(error));
            retiring = NULL;
            failing = unlink_failure = 0;
        }
        printf("app-retire %d %u %u\n", result, syncs, unlinks);
    } else if (!strcmp(line, "app-drop-ticket")) {
        if (!f->started && !f->retirement_started) { yd_raft_application_retirement_close(f->retirement); f->retirement = NULL; }
        puts("app-ticket-closed");
    } else if (!strcmp(line, "app-drop-image")) {
        if (!f->started) { yd_raft_application_image_close(f->image); f->image = NULL; }
        puts("app-image-closed");
    } else if (!strcmp(line, "app-pin-native")) {
        bool valid = !f->reader && !f->checkpoint && !f->source;
        if (valid) {
            f->reader = yd_disk_pin(yd_raft_cluster_disk(f->cluster), 32768, error, sizeof(error));
            f->checkpoint = yd_disk_checkpoint_open(yd_raft_cluster_disk(f->cluster), error, sizeof(error));
            f->source = yd_raft_cluster_application_capture(f->cluster, 32768, error, sizeof(error));
            valid = f->reader && f->checkpoint && f->source;
        }
        printf("app-pin-native %u\n", valid);
    } else if (!strcmp(line, "app-read-native")) {
        YDDiskView view = f->reader ? yd_disk_view(f->reader) : (YDDiskView){0};
        YDDiskReply reply = f->reader ? yd_disk_api_read_at(f->reader, &view, "GET",
            "/v1/collections/config/documents/node", NULL, 0, NULL, NULL, false)
            : (YDDiskReply){0};
        unsigned char header[8];
        bool valid = reply.status == 200 && yd_disk_checkpoint_read(f->checkpoint, 0, header,
            sizeof(header), error, sizeof(error));
        printf("app-read-native %u\n", valid);
        yd_disk_reply_free(&reply);
    } else if (!strcmp(line, "app-drop-reader")) {
        yd_disk_close(f->reader); f->reader = NULL; puts("app-reader-closed");
    } else if (!strcmp(line, "app-drop-checkpoint")) {
        yd_disk_checkpoint_close(f->checkpoint); f->checkpoint = NULL; puts("app-checkpoint-closed");
    } else if (!strcmp(line, "app-drop-source")) {
        yd_raft_application_capture_close(f->source); f->source = NULL; puts("app-source-closed");
    } else if (!strcmp(line, "app-catch")) {
        YDRaftApplicationCapture *capture =
            !f->started
                ? yd_raft_cluster_application_capture(f->cluster, 32768, error, sizeof(error))
                : NULL;
        bool valid = capture && yd_raft_application_catch_up(f->image, capture, NULL, NULL, error,
                                                             sizeof(error));
        yd_raft_application_capture_close(capture);
        printf("app-catch %u\n", valid);
    } else if (!strncmp(line, "app-start ", 10)) {
        bool valid =
            f->image && !f->started && (!f->retaining || !f->retirement) && sscanf(line + 10, "%u %u", &f->held, &f->fault) == 2;
        if (valid) {
            f->result = f->published = false;
            f->terminal = 0;
            atomic_store(&f->done, false);
            atomic_store(&f->entered, false);
            atomic_store(&f->decision, false);
            atomic_store(&f->cancel, false);
            atomic_store(&f->hold, f->held != 0);
            valid = (f->started = !pthread_create(&f->thread, NULL, select_image, f));
            if (!valid)
                atomic_store(&f->done, true);
        }
        printf("app-start %u\n", valid);
    } else if (!strcmp(line, "app-outcome")) {
        bool done = atomic_load(&f->done);
        printf("app-outcome %u\n", done ? f->outcome : 0);
    } else if (!strcmp(line, "app-busy-probe")) {
        bool published = false;
        YDRaftApplicationSelection outcome = yd_raft_cluster_application_select_outcome(
            f->cluster, f->probe, f->timeout, NULL, NULL, &published, NULL, error, sizeof(error));
        printf("app-probe %u %u\n", (unsigned)outcome, published);
    } else if (!strcmp(line, "app-invalid-probe")) {
        bool published = true;
        YDRaftApplicationSelection outcome = yd_raft_cluster_application_select_outcome(
            f->cluster, NULL, 0, NULL, NULL, &published, NULL, error, sizeof(error));
        printf("app-probe %u %u\n", (unsigned)outcome, published);
    } else if (!strcmp(line, "app-state")) {
        bool done = atomic_load(&f->done);
        printf("app-state %u %u %u %u %u\n", done, done && f->result, done && f->published,
               atomic_load(&f->entered), atomic_load(&f->decision));
    } else if (!strcmp(line, "app-release")) {
        atomic_store(&f->hold, false);
        puts("app-released");
    } else if (!strcmp(line, "app-cancel")) {
        atomic_store(&f->cancel, true);
        atomic_store(&f->hold, false);
        puts("app-cancelled");
    } else if (!strcmp(line, "app-join")) {
        if (f->started) {
            pthread_join(f->thread, NULL);
            f->started = false;
        }
        printf("app-result %u %u\n", f->result, f->published);
    } else if (!strncmp(line, "app-writer-start ", 17)) {
        bool valid = !f->writer_started;
        if (valid) {
            f->writer_id = (unsigned)strtoul(line + 17, NULL, 10);
            atomic_store(&f->writer_done, false);
            valid = (f->writer_started = !pthread_create(&f->writer, NULL, write_image, f));
            if (!valid)
                atomic_store(&f->writer_done, true);
        }
        printf("app-writer-start %u\n", valid);
    } else if (!strcmp(line, "app-writer-state")) {
        bool done = atomic_load(&f->writer_done);
        printf("app-writer-state %u %u\n", done, done ? f->writer_status : 0);
    } else if (!strcmp(line, "app-writer-join")) {
        if (f->writer_started) {
            pthread_join(f->writer, NULL);
            f->writer_started = false;
        }
        printf("app-writer-result %u\n", f->writer_status);
    } else
        puts("unknown-app-command");
    return true;
}
void yd_test_application_close(ApplicationFixture *f) {
    if (!f)
        return;
    atomic_store(&f->cancel, true);
    atomic_store(&f->hold, false);
    atomic_store(&f->retirement_hold, false);
    if (f->started)
        pthread_join(f->thread, NULL);
    if (f->writer_started)
        pthread_join(f->writer, NULL);
    if (f->retirement_started)
        pthread_join(f->retiring, NULL);
    if (f->checkpoint_started)
        pthread_join(f->checkpointing, NULL);
    yd_raft_application_image_close(f->image);
    yd_raft_application_image_close(f->probe);
    yd_raft_application_capture_close(f->source);
    yd_raft_journal_capture_close(f->journal_capture);
    yd_disk_close(f->journal_reader);
    yd_disk_recovery_roots_close(f->journal_roots);
    yd_disk_close(f->reader);
    yd_disk_checkpoint_close(f->checkpoint);
    yd_raft_application_retirement_close(f->retirement);
    yd_raft_application_workspace_close(f->owned);
    yd_raft_application_compaction_close(f->compaction);
    if (f->workspace >= 0) close(f->workspace);
    close(f->directory);
    free(f);
}
