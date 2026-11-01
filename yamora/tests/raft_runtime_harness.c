#define _POSIX_C_SOURCE 200809L
#include "../src/consensus/runtime.h"
#include "../src/consensus/runtime_internal.h"
#include "../src/consensus/journal_compact.h"
#include "../src/consensus/read.h"
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
static _Thread_local unsigned fail_sync, sync_count;
static _Thread_local unsigned delay_sync, fail_clock, clock_count;
static _Thread_local atomic_bool *preparation_hold, *preparation_entered, *preparation_cancel;
typedef struct {
    bool injected, checkpointed, stale_rejected, fresh, block, same_deadline, waited;
    unsigned begins, waits;
    uint64_t issued, old_epoch, new_epoch;
    struct timespec deadline;
    pthread_cond_t *condition;
} BarrierCheckpoint;
static _Thread_local BarrierCheckpoint *barrier_checkpoint;
static atomic_bool suppress_read_acks;
bool __real_yd_raft_read_begin(const YDRaftReads *, YDRaft *, YDRaftRead *);
bool __wrap_yd_raft_read_begin(const YDRaftReads *reads, YDRaft *raft, YDRaftRead *proof) {
    bool valid = __real_yd_raft_read_begin(reads, raft, proof);
    if (valid && barrier_checkpoint) barrier_checkpoint->begins++;
    return valid;
}
bool __real_yd_raft_read_ready(const YDRaftReads *, const YDRaftRead *, YDRaft *, uint64_t *);
bool __wrap_yd_raft_read_ready(const YDRaftReads *reads, const YDRaftRead *proof,
                              YDRaft *raft, uint64_t *index) {
    bool valid = __real_yd_raft_read_ready(reads, proof, raft, index);
    BarrierCheckpoint *race = barrier_checkpoint;
    if (!race) return valid;
    if (valid && !race->injected) {
        /* The runtime mutex is held. Publish a real journal checkpoint exactly
         * after a fresh native quorum, before the caller consumes that proof. */
        race->injected = true;
        race->issued = reads->issued;
        race->old_epoch = proof->membership.index;
        YDRaftStatus status = yd_raft_status(raft);
        YDRaftSnapshotBase base = {.index = status.committed, .term = status.term, .archive = {2}};
        race->checkpointed = yd_raft_checkpoint(raft, &base);
        race->new_epoch = yd_raft_membership(raft).index;
        race->stale_rejected = !__real_yd_raft_read_ready(reads, proof, raft, index);
        atomic_store(&suppress_read_acks, race->block);
        return false;
    }
    if (valid && race->injected)
        race->fresh = proof->after >= race->issued && reads->issued > proof->after;
    return valid;
}
void __real_yd_raft_reads_observe(YDRaftReads *, uint64_t, const YDRaftPacket *, const YDRaftPacket *);
void __wrap_yd_raft_reads_observe(YDRaftReads *reads, uint64_t sequence,
                                 const YDRaftPacket *request, const YDRaftPacket *reply) {
    if (!atomic_load(&suppress_read_acks))
        __real_yd_raft_reads_observe(reads, sequence, request, reply);
}
int __real_pthread_cond_timedwait(pthread_cond_t *, pthread_mutex_t *, const struct timespec *);
int __wrap_pthread_cond_timedwait(pthread_cond_t *condition, pthread_mutex_t *mutex,
                                 const struct timespec *deadline) {
    BarrierCheckpoint *race = barrier_checkpoint;
    if (race && (!race->waited || race->condition == condition)) {
        race->waits++;
        if (!race->waited) {
            race->deadline = *deadline;
            race->condition = condition;
            race->waited = true;
        } else if (race->deadline.tv_sec != deadline->tv_sec ||
                   race->deadline.tv_nsec != deadline->tv_nsec)
            race->same_deadline = false;
    }
    return __real_pthread_cond_timedwait(condition, mutex, deadline);
}
int __real_clock_gettime(clockid_t clock, struct timespec *value);
int __wrap_clock_gettime(clockid_t clock, struct timespec *value) {
    if (fail_clock && ++clock_count == fail_clock) { errno = EIO; return -1; }
    return __real_clock_gettime(clock, value);
}
int __real_fsync(int fd);
int __wrap_fsync(int fd) {
    if ((fail_sync || delay_sync) && ++sync_count == fail_sync) { errno = EIO; return -1; }
    int result = __real_fsync(fd);
    if (!result && preparation_hold) {
        atomic_store(preparation_entered,true);
        while(atomic_load(preparation_hold) && !atomic_load(preparation_cancel)) {
            struct timespec delay={.tv_nsec=1000000};nanosleep(&delay,NULL);
        }
    }
    if (!result && delay_sync && sync_count == 2) {
        struct timespec delay = {.tv_sec = delay_sync / 1000,
                                 .tv_nsec = (long)(delay_sync % 1000) * 1000000};
        while (nanosleep(&delay, &delay) && errno == EINTR) {}
    }
    return result;
}
static void published_snapshot(void *context) { (*(unsigned *)context)++; }
typedef struct {
    YDRaftJournalScope *scope;
    YDDiskLineage *lineage;
    YDDisk *pin;
    YDDiskView view;
    unsigned char metadata[144];
    size_t size;
    bool checked;
} StartupObservation;
static bool observed_recovery(void *context, YDRaft *raft, char *error, size_t length) {
    StartupObservation *o = context;
    YDDiskLineageSnapshot *native = yd_disk_lineage_snapshot(o->lineage);
    YDDiskLineageInfo info;
    YDRaftJournalScopeSnapshot *names = yd_raft_journal_scope_snapshot(o->scope);
    YDRaftJournalScopeInfo bindings;
    bool valid = yd_disk_lineage_snapshot_info(native, &info) && info.complete &&
        info.source_count == 1 && info.entry_count == 1 &&
        yd_raft_journal_scope_snapshot_info(names, &bindings) && bindings.complete &&
        raft->journal_scope == o->scope;
    yd_disk_lineage_snapshot_close(native); yd_raft_journal_scope_snapshot_close(names);
    o->pin = valid ? yd_disk_pin(raft->disk, 32768, error, length) : NULL;
    if (o->pin) {
        o->view = yd_disk_view(o->pin);
        o->size = yd_raft_encode_meta(&raft->meta, o->metadata);
    }
    o->checked = valid && o->pin && !yd_raft_snapshot_base(raft).index;
    return o->checked;
}
static bool observed_bytes(YDDiskLineageSnapshot *snapshot, const StartupObservation *o) {
    YDDiskLineageInfo info;
    if (!yd_disk_lineage_snapshot_info(snapshot, &info) || info.source_count != 1)
        return false;
    unsigned char bytes[144]; size_t size = 0; uint64_t offset = 0;
    uint64_t source = info.sources[0].id;
    return yd_disk_lineage_snapshot_get(snapshot, source, &o->view, "\0YRM", 4,
        &offset, NULL, 0) == 1 && yd_disk_lineage_snapshot_record_into(snapshot,
        source, &o->view, offset, bytes, sizeof(bytes), &size, NULL, 0) &&
        size == o->size && !memcmp(bytes, o->metadata, size);
}
typedef struct {
    YDRaftRuntime *runtime;
    YDRaftJournalCensus *token;
    pthread_t thread;
    bool started;
    atomic_bool entered, release, done, cancel;
} CensusJob;
static bool census_progress(void *context) {
    CensusJob *job = context;
    atomic_store(&job->entered, true);
    while (!atomic_load(&job->release) && !atomic_load(&job->cancel)) {
        struct timespec delay = {.tv_nsec = 1000000}; nanosleep(&delay, NULL);
    }
    return !atomic_load(&job->cancel);
}
static void *observe_census(void *context) {
    CensusJob *job = context; char error[256];
    job->token = yd_raft_runtime_journal_census(job->runtime,
        census_progress, job, error, sizeof(error));
    atomic_store(&job->done, true);
    return NULL;
}
static void show_census(const YDRaftJournalCensus *token, const char *label) {
    YDRaftJournalCensusInfo info;
    if (!yd_raft_journal_census_info(token, &info)) {
        printf("%s invalid\n", label); return;
    }
    bool initial = false;
    for (size_t i = 0; i < info.root_count; i++) {
        YDRaftJournalCensusRoot root;
        if (yd_raft_journal_census_root(token, i, &root) &&
            root.dependency.state == YD_RAFT_DEPENDENCY_KNOWN &&
            !root.dependency.metadata.term && !root.dependency.metadata.last)
            initial = true;
    }
    printf("%s %u %u %u %u %zu %zu %zu %zu %zu %u\n", label,
        info.coverage_complete, info.metadata_complete, info.archive_pins_complete,
        info.reasons, info.source_count, info.root_count, info.producer_count,
        info.binding_count, info.cache_reserved, initial);
}
typedef struct {
    YDRaftRuntime *runtime;
    YDRaftJournalCompactionOptions options;
    YDRaftJournalCompaction report;
    pthread_t thread;
    bool started, injected;
    unsigned held_phase, fault;
    atomic_bool done, cancel;
    atomic_uint phase, visits, releases;
} CompactionJob;
static bool compaction_progress(void *context,YDRaftJournalCompactionPhase phase,uint64_t done,uint64_t total) {
    CompactionJob *j=context;(void)done;(void)total;
    atomic_store(&j->phase,(unsigned)phase);
    if(!j->injected && ((j->fault==1 && phase==YD_RAFT_COMPACT_SELECT) ||
                       (j->fault==3 && phase==YD_RAFT_COMPACT_SELECT && atomic_load(&j->visits)==1) ||
                       (j->fault==2 && phase==YD_RAFT_COMPACT_RETIRE))) {
        fail_sync=1;sync_count=0;j->injected=true;
    }
    if(j->held_phase==(unsigned)phase) {
        unsigned visit=atomic_fetch_add(&j->visits,1)+1;
        while(atomic_load(&j->releases)<visit && !atomic_load(&j->cancel)) {
            struct timespec delay={.tv_nsec=1000000};nanosleep(&delay,NULL);
        }
    }
    return !atomic_load(&j->cancel);
}
static void *compact_journal(void *context) {
    CompactionJob *j=context;char error[256];
    j->report=yd_raft_journal_compact(j->runtime,j->options,compaction_progress,j,error,sizeof(error));
    fail_sync=0;atomic_store(&j->done,true);return NULL;
}
static void compaction_stop(CompactionJob *j) {
    if(j->started) {
        atomic_store(&j->cancel,true);pthread_join(j->thread,NULL);j->started=false;
    }
}
typedef struct {
    YDRaftRuntime *runtime;
    YDRaftJournalDependencies *dependencies;
    pthread_t thread;
    bool started;
    atomic_bool entered, release, done;
} DependencyJob;
static _Thread_local DependencyJob *observing;
YDRaftJournalDependencies *__real_yd_raft_journal_dependencies_take_roots(
    YDDiskRecoveryRoots *, const YDRaftMeta *, const YDRaftSnapshotStore *, char *, size_t);
YDRaftJournalDependencies *__wrap_yd_raft_journal_dependencies_take_roots(
    YDDiskRecoveryRoots *roots, const YDRaftMeta *identity,
    const YDRaftSnapshotStore *store, char *error, size_t length) {
    if (observing) {
        atomic_store(&observing->entered, true);
        while (!atomic_load(&observing->release)) {
            struct timespec delay = {.tv_nsec = 1000000}; nanosleep(&delay, NULL);
        }
    }
    return __real_yd_raft_journal_dependencies_take_roots(roots, identity, store, error, length);
}
static void *observe_dependencies(void *context) {
    DependencyJob *job = context; char error[256];
    observing = job;
    job->dependencies = yd_raft_runtime_journal_dependencies(job->runtime, 32768, error, sizeof(error));
    observing = NULL;
    atomic_store(&job->done, true);
    return NULL;
}
typedef struct {
    YDRaftJournalCapture *capture;
    YDRaftJournalImage *image;
    YDRaftJournalPublication *publication;
    YDRaftRuntime *runtime;
    int directory;
    pthread_t thread;
    pthread_t preparation;
    bool started, preparing, cleaned;
    unsigned cleanup;
    atomic_bool hold, entered, done, cancel, prepared;
} JournalJob;
static bool journal_progress(void *context,YDRaftJournalPhase phase,uint64_t done,uint64_t total) {
    JournalJob *j=context;(void)done;(void)total;
    if(phase==YD_RAFT_JOURNAL_COPY) {
        atomic_store(&j->entered,true);
        while(atomic_load(&j->hold) && !atomic_load(&j->cancel)) {
            struct timespec delay={.tv_nsec=1000000};nanosleep(&delay,NULL);
        }
    }
    return !atomic_load(&j->cancel);
}
static void *journal_copy(void *context) {
    JournalJob *j=context;char error[256];
    j->image=yd_raft_journal_copy(j->capture,j->directory,32768,journal_progress,j,error,sizeof(error));
    atomic_store(&j->done,true);return NULL;
}
static void *journal_prepare(void *context) {
    JournalJob *j=context;char error[256];
    preparation_hold=&j->hold;preparation_entered=&j->entered;preparation_cancel=&j->cancel;
    if(j->cleanup==1)j->cleaned=yd_raft_journal_retire(j->publication,error,sizeof(error));
    else if(j->cleanup==2)j->cleaned=yd_raft_journal_cancel(j->publication,error,sizeof(error));
    else j->publication=yd_raft_runtime_journal_prepare(j->runtime,j->image,error,sizeof(error));
    preparation_hold=preparation_entered=preparation_cancel=NULL;
    atomic_store(&j->prepared,true);return NULL;
}
static void journal_entry(JournalJob *j,uint64_t index) {
    YDDisk *disk=atomic_load(&j->done) ? yd_raft_journal_image_disk(j->image) : NULL;
    YDDiskView view=disk ? yd_disk_view(disk) : (YDDiskView){0};
    unsigned char key[12]={0,'Y','R','E'};uint64_t offset;size_t size;char error[256];
    for(unsigned i=0;i<8;i++)key[4+i]=(unsigned char)(index>>(56-8*i));
    unsigned char *bytes=disk && yd_disk_get(disk,&view,key,12,&offset,error,sizeof(error))==1
        ? yd_disk_record(disk,&view,offset,&size,error,sizeof(error)) : NULL;
    if(bytes && size>=40) {
        fputs("journal-entry ",stdout);
        for(size_t i=40;i<size;i++)printf("%02x",bytes[i]);
        putchar('\n');
    } else puts("journal-entry missing");
    free(bytes);
}
int main(int argc, char **argv) {
    if (argc != 8 && argc != 9)
        return 1;
    unsigned node = (unsigned)strtoul(argv[3], NULL, 10);
    if (!node || node > 3)
        return 1;
    char cert[4096], key[4096], ca[4096], error[256];
    snprintf(cert, sizeof(cert), "%s/node%u.pem", argv[2], node);
    snprintf(key, sizeof(key), "%s/node%u.key", argv[2], node);
    snprintf(ca, sizeof(ca), "%s/trusted.pem", argv[2]);
    YDTLS *tls = yd_tls_peer_new(cert, key, ca, error, sizeof(error));
    if (!tls) {
        fprintf(stderr, "%s\n", error);
        return 2;
    }
    YDRaftConfig config = {.journal_root = argv[1],
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
    if (getenv("YAMORA_RAFT_TEST_SMALL_BUDGET")) config.command_bytes = 1024;
    const char *slow = getenv("YAMORA_RAFT_TEST_SLOW");
    if (slow && !strcmp(slow, "1"))
        config.timing = (YDRaftTiming){
            .heartbeat_ms = 100, .election_min_ms = 5000, .election_max_ms = 8000, .rpc_ms = 2000};
    if (argc == 9) {
        if (!strcmp(argv[8], "duplicate"))
            config.ports[2] = config.ports[1];
        else if (!strcmp(argv[8], "listener-mismatch"))
            config.ports[node]++;
        else if (!strcmp(argv[8], "checkpointed")) {
            YDRaft *raft = yd_raft_open(config.journal_root, config.cluster, node, 3,
                                         config.cache_bytes, error, sizeof(error));
            unsigned peer = node == 1 ? 2 : 1;
            YDRaftVote vote;
            bool valid = raft && yd_raft_campaign(raft, &vote);
            YDRaftVoteReply voted = {.term = valid ? vote.term : 0, .granted = true};
            valid = valid && yd_raft_vote_reply(raft, peer, vote.term, &voted);
            YDRaftAppend append;
            valid = valid && yd_raft_append_request(raft, peer, &append);
            if (valid) {
                YDRaftAppendReply reply = {.term = append.term, .rpc = append.rpc,
                                           .matched = 1, .accepted = true};
                yd_raft_append_free(&append);
                valid = yd_raft_append_reply(raft, peer, &reply);
            }
            YDRaftSnapshotBase base = {.index = 1, .term = voted.term, .archive = {1}};
            valid = valid && yd_raft_checkpoint(raft, &base);
            yd_raft_close(raft);
            if (!valid) {
                yd_tls_free(tls);
                return 3;
            }
        } else
            config.addresses[node == 1 ? 2 : 1] = argv[8];
    }
    int listener = (int)strtol(argv[4], NULL, 10);
    StartupObservation observation = {0};
    bool observed = getenv("YAMORA_RAFT_TEST_OBSERVED") != NULL;
    if (observed) {
        observation.scope = yd_raft_journal_scope_new();
        observation.lineage = yd_disk_lineage_new();
    }
    YDRaftRuntime *runtime = observed
        ? (observation.scope && observation.lineage ? yd_raft_runtime_start_observed(&config,
            tls, listener, observed_recovery, &observation, observation.scope,
            observation.lineage, error, sizeof(error)) : NULL)
        : yd_raft_runtime_start(&config, tls, listener, error, sizeof(error));
    if (!runtime) {
        fprintf(stderr, "%s\n", error);
        yd_disk_close(observation.pin);
        yd_disk_lineage_release(observation.lineage);
        yd_raft_journal_scope_close(observation.scope);
        yd_tls_free(tls);
        return 2;
    }
    puts("ready");
    fflush(stdout);
    char line[512];
    unsigned publications = 0;
    JournalJob journal={.directory=-1};
    CompactionJob compaction={.runtime=runtime};
    YDRaftJournalDependencies *dependencies = NULL;
    YDDiskLineageSnapshot *lineage_snapshot = NULL;
    DependencyJob dependency_job = {.runtime = runtime};
    CensusJob census_job = {.runtime = runtime};
    YDRaftJournalCensus *census = NULL;
    while (fgets(line, sizeof(line), stdin)) {
        size_t length = strlen(line);
        if (!length || line[length - 1] != '\n')
            break;
        line[--length] = 0;
        if (!strcmp(line, "census")) {
            yd_raft_journal_census_close(census);
            census = yd_raft_runtime_journal_census(runtime, NULL, NULL, error, sizeof(error));
            show_census(census, "census");
        } else if (!strcmp(line, "census-start")) {
            bool valid = !census_job.started;
            if (valid) {
                yd_raft_journal_census_close(census_job.token); census_job.token = NULL;
                atomic_store(&census_job.entered, false); atomic_store(&census_job.release, false);
                atomic_store(&census_job.done, false); atomic_store(&census_job.cancel, false);
                valid = !pthread_create(&census_job.thread, NULL, observe_census, &census_job);
                census_job.started = valid;
            }
            printf("census-started %u\n", valid);
        } else if (!strcmp(line, "census-entered")) {
            printf("census-entered %u\n", atomic_load(&census_job.entered));
        } else if (!strcmp(line, "census-release")) {
            atomic_store(&census_job.release, true); puts("census-released");
        } else if (!strcmp(line, "census-cancel")) {
            atomic_store(&census_job.cancel, true); puts("census-cancelled");
        } else if (!strcmp(line, "census-result")) {
            if (!atomic_load(&census_job.done)) puts("census-pending");
            else {
                if (census_job.started) { pthread_join(census_job.thread, NULL); census_job.started = false; }
                show_census(census_job.token, "census-result");
            }
        } else if (!strcmp(line, "close-census")) {
            if (!observed || journal.started || journal.preparing || compaction.started ||
                dependency_job.started || census_job.started) {
                puts("census-close-busy"); fflush(stdout); continue;
            }
            yd_raft_journal_census_close(census_job.token); census_job.token = NULL;
            yd_raft_runtime_stop(runtime); runtime = NULL;
            yd_disk_close(observation.pin); observation.pin = NULL;
            yd_disk_lineage_release(observation.lineage); observation.lineage = NULL;
            yd_raft_journal_scope_close(observation.scope); observation.scope = NULL;
            show_census(census, "closed-census"); fflush(stdout);
            if (!fgets(line, sizeof(line), stdin) || strcmp(line, "release-census\n")) break;
            yd_raft_journal_census_close(census); census = NULL;
            puts("released-census"); fflush(stdout);
            (void)fgets(line, sizeof(line), stdin);
            break;
        } else if (!strcmp(line, "lineage")) {
            yd_disk_lineage_snapshot_close(lineage_snapshot);
            lineage_snapshot = yd_disk_lineage_snapshot(observation.lineage);
            YDDiskLineageInfo info;
            bool valid = yd_disk_lineage_snapshot_info(lineage_snapshot, &info);
            printf("lineage %u %u %zu %zu %u\n", observation.checked,
                valid && info.complete, valid ? info.source_count : 0,
                valid ? info.entry_count : 0, observed_bytes(lineage_snapshot, &observation));
        } else if (!strcmp(line, "close-lineage")) {
            if (!observed || journal.started || journal.preparing || compaction.started || dependency_job.started || census_job.started) {
                puts("lineage-close-busy"); fflush(stdout); continue;
            }
            yd_raft_runtime_stop(runtime); runtime = NULL;
            yd_disk_close(observation.pin); observation.pin = NULL;
            yd_disk_lineage_release(observation.lineage); observation.lineage = NULL;
            yd_raft_journal_scope_close(observation.scope); observation.scope = NULL;
            printf("closed-lineage %u\n", observed_bytes(lineage_snapshot, &observation));
            fflush(stdout);
            if (!fgets(line, sizeof(line), stdin) || strcmp(line, "release-lineage\n")) break;
            yd_disk_lineage_snapshot_close(lineage_snapshot); lineage_snapshot = NULL;
            puts("released-lineage"); fflush(stdout);
            (void)fgets(line, sizeof(line), stdin);
            break;
        } else if(!strncmp(line,"compact ",8)) {
            unsigned long long minimum,saved;unsigned attempts,phase,fault;
            bool valid=sscanf(line+8,"%llu %llu %u %u %u",&minimum,&saved,&attempts,&phase,&fault)==5;
            if(compaction.started && atomic_load(&compaction.done)) {
                pthread_join(compaction.thread,NULL);compaction.started=false;
            }
            valid=valid && !compaction.started;
            if(valid) {
                compaction.options=(YDRaftJournalCompactionOptions){minimum,saved,32768,attempts};
                compaction.held_phase=phase;compaction.fault=fault;compaction.injected=false;
                atomic_store(&compaction.cancel,false);atomic_store(&compaction.done,false);
                atomic_store(&compaction.phase,0);atomic_store(&compaction.visits,0);atomic_store(&compaction.releases,0);
                valid=!pthread_create(&compaction.thread,NULL,compact_journal,&compaction);
                compaction.started=valid;
            }
            printf("compaction-started %u\n",valid);
        } else if(!strcmp(line,"compact-state")) {
            if(!atomic_load(&compaction.done))puts("compaction 0");
            else {
                YDRaftJournalCompaction s=compaction.report;
                printf("compaction 1 %d %llu %llu %u %u %u\n",s.result,
                       (unsigned long long)s.source_bytes,(unsigned long long)s.candidate_bytes,
                       s.catchups,s.published,s.retired);
            }
        } else if(!strcmp(line,"compact-entered")) {
            printf("compaction-entered %u %u\n",atomic_load(&compaction.phase),atomic_load(&compaction.visits));
        } else if(!strcmp(line,"release-compaction")) {
            atomic_fetch_add(&compaction.releases,1);puts("released");
        } else if(!strcmp(line,"cancel-compaction")) {
            atomic_store(&compaction.cancel,true);puts("cancelled");
        } else if (!strcmp(line, "dependency-start")) {
            bool valid = !dependency_job.started;
            if (valid) {
                yd_raft_journal_dependencies_close(dependency_job.dependencies);
                dependency_job.dependencies = NULL;
                atomic_store(&dependency_job.entered, false);
                atomic_store(&dependency_job.release, false);
                atomic_store(&dependency_job.done, false);
                valid = !pthread_create(&dependency_job.thread, NULL, observe_dependencies, &dependency_job);
            }
            if (valid) dependency_job.started = true;
            printf("dependency-started %u\n", valid);
        } else if (!strcmp(line, "dependency-entered")) {
            printf("dependency-entered %u\n", atomic_load(&dependency_job.entered));
        } else if (!strcmp(line, "dependency-release")) {
            atomic_store(&dependency_job.release, true); puts("dependency-released");
        } else if (!strcmp(line, "dependency-result")) {
            if (!dependency_job.started || !atomic_load(&dependency_job.done)) puts("dependency-pending");
            else {
                pthread_join(dependency_job.thread, NULL); dependency_job.started = false;
                YDRaftJournalDependencyInfo info;
                bool valid = yd_raft_journal_dependencies_info(dependency_job.dependencies, &info) &&
                    info.physical.selected >= 0 && info.physical.selected < 2;
                printf("dependency-result %u %u %llu\n", valid, valid && info.metadata_complete,
                    (unsigned long long)(valid ? info.slots[info.physical.selected].metadata.last : 0));
            }
        } else if (!strcmp(line, "dependencies")) {
            yd_raft_journal_dependencies_close(dependencies);
            dependencies = yd_raft_runtime_journal_dependencies(runtime, 32768, error, sizeof(error));
            YDRaftJournalDependencyInfo info;
            if (!yd_raft_journal_dependencies_info(dependencies, &info)) puts("dependencies 0");
            else printf("dependencies 1 %u %u %d %llu\n", info.metadata_complete,
                info.archive_pins_complete, info.physical.selected,
                (unsigned long long)(info.physical.selected >= 0 && info.physical.selected < 2
                    ? info.slots[info.physical.selected].metadata.last : 0));
        } else if (!strcmp(line, "close-dependencies")) {
            if (journal.started || journal.preparing || compaction.started || dependency_job.started || census_job.started) {
                puts("dependencies-close-busy"); fflush(stdout); continue;
            }
            yd_raft_runtime_stop(runtime);
            runtime = NULL;
            YDRaftJournalDependencyInfo info;
            bool valid = yd_raft_journal_dependencies_info(dependencies, &info);
            printf("closed-dependencies %u %u %u\n", valid, valid && info.metadata_complete,
                valid && info.archive_pins_complete);
            fflush(stdout);
            /* Stay alive: process exit must not supply descriptor cleanup. */
            if (!fgets(line, sizeof(line), stdin) || strcmp(line, "release-dependencies\n")) break;
            yd_raft_journal_dependencies_close(dependencies); dependencies = NULL;
            puts("released-dependencies"); fflush(stdout);
            /* Again wait alive so a missing close cannot pass via process exit. */
            (void)fgets(line, sizeof(line), stdin);
            break;
        } else if (!strcmp(line, "status")) {
            YDRaftStatus s = yd_raft_runtime_status(runtime);
            printf("status %u %u %llu %llu %llu\n", s.role, s.leader, (unsigned long long)s.term,
                   (unsigned long long)s.last, (unsigned long long)s.committed);
        } else if (!strcmp(line,"journal-capture")) {
            if(!journal.started) {
                yd_raft_journal_capture_close(journal.capture);
                journal.capture=yd_raft_runtime_journal_capture(runtime,32768,error,sizeof(error));
            }
            printf("captured %u\n",journal.capture!=NULL);
        } else if (!strcmp(line,"hold-journal")) {
            atomic_store(&journal.hold,true);puts("holding-journal");
        } else if (!strcmp(line,"release-journal")) {
            atomic_store(&journal.hold,false);puts("released");
        } else if (!strcmp(line,"journal-entered")) {
            printf("entered %u\n",atomic_load(&journal.entered));
        } else if (!strcmp(line,"journal-start") || !strcmp(line,"journal-start-external")) {
            char path[4096];snprintf(path,sizeof(path), "%s%s", argv[1],
                !strcmp(line,"journal-start-external") ? "-journal-copy" : "/.journal-copy");
            bool valid=journal.capture && !journal.started && !mkdir(path,0700);
            if(valid)journal.directory=open(path,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
            valid=valid && journal.directory>=0 && !pthread_create(&journal.thread,NULL,journal_copy,&journal);
            journal.started=valid;printf("journal-started %u\n",valid);
        } else if (!strcmp(line,"journal-state")) {
            bool done=atomic_load(&journal.done),valid=done && journal.image;
            printf("journal %u %u %u\n",done,valid,valid && yd_raft_runtime_journal_current(runtime,journal.image));
        } else if (!strncmp(line,"journal-entry ",14)) {
            journal_entry(&journal,strtoull(line+14,NULL,10));
        } else if (!strcmp(line,"journal-prepare")) {
            if(atomic_load(&journal.done) && !journal.publication)
                journal.publication=yd_raft_runtime_journal_prepare(runtime,journal.image,error,sizeof(error));
            printf("prepared %u\n",journal.publication!=NULL);
        } else if (!strcmp(line,"hold-preparation")) {
            bool valid=atomic_load(&journal.done) && !journal.preparing && !journal.publication;
            if(valid) {
                journal.runtime=runtime;atomic_store(&journal.hold,true);atomic_store(&journal.entered,false);
                valid=!pthread_create(&journal.preparation,NULL,journal_prepare,&journal);
                journal.preparing=valid;
            }
            printf("preparing %u\n",valid);
        } else if (!strcmp(line,"preparation-state")) {
            bool done=atomic_load(&journal.prepared);
            printf("preparation %u %u\n",done,done && journal.publication);
        } else if (!strcmp(line,"hold-retirement") || !strcmp(line,"hold-cancellation")) {
            bool cancelling=!strcmp(line,"hold-cancellation");
            bool valid=atomic_load(&journal.done) && !journal.preparing && journal.publication;
            if(valid) {
                journal.cleanup=cancelling ? 2 : 1;atomic_store(&journal.hold,true);atomic_store(&journal.entered,false);
                atomic_store(&journal.prepared,false);
                valid=!pthread_create(&journal.preparation,NULL,journal_prepare,&journal);
                journal.preparing=valid;
            }
            printf("%s %u\n",cancelling ? "cancelling" : "retiring",valid);
        } else if (!strcmp(line,"retirement-state")) {
            bool done=atomic_load(&journal.prepared);
            printf("retirement %u %u\n",done,done && journal.cleaned);
        } else if (!strcmp(line,"journal-retire")) {
            printf("retired %u\n",yd_raft_journal_retire(journal.publication,error,sizeof(error)));
        } else if (!strcmp(line,"journal-cancel")) {
            printf("cancelled %u\n",yd_raft_journal_cancel(journal.publication,error,sizeof(error)));
        } else if (!strcmp(line,"cancellation-state")) {
            bool done=atomic_load(&journal.prepared);
            printf("cancellation %u %u\n",done,done && journal.cleaned);
        } else if (!strcmp(line,"journal-unprepare")) {
            yd_raft_journal_publication_close(journal.publication);journal.publication=NULL;
            puts("unprepared");
        } else if (!strcmp(line,"journal-catch-up")) {
            YDRaftJournalCapture *latest=atomic_load(&journal.done)
                ? yd_raft_runtime_journal_capture(runtime,32768,error,sizeof(error)) : NULL;
            bool valid=latest && yd_raft_journal_catch_up(journal.image,latest,NULL,NULL,error,sizeof(error));
            yd_raft_journal_capture_close(latest);printf("caught-up %u\n",valid);
        } else if (!strcmp(line,"journal-publish") || !strcmp(line,"journal-publish-fail")) {
            fail_sync=!strcmp(line,"journal-publish-fail") ? 1 : 0;sync_count=0;
            bool published=false;
            bool valid=yd_raft_runtime_journal_publish(runtime,journal.publication,&published,error,sizeof(error));
            fail_sync=0;printf("selected %u %u\n",valid,published);
        } else if (!strcmp(line,"journal-discard")) {
            if(journal.preparing) {
                atomic_store(&journal.hold,false);pthread_join(journal.preparation,NULL);journal.preparing=false;
            }
            if(journal.started) {pthread_join(journal.thread,NULL);journal.started=false;}
            yd_raft_journal_publication_close(journal.publication);journal.publication=NULL;
            yd_raft_journal_image_close(journal.image);journal.image=NULL;
            yd_raft_journal_capture_close(journal.capture);journal.capture=NULL;
            puts("discarded");
        } else if (!strcmp(line,"fence")) {
            yd_raft_runtime_fence(runtime);puts("fenced");
        } else if (!strcmp(line,"close-journal")) {
            if (census_job.started || dependency_job.started) {
                puts("journal-close-busy"); fflush(stdout); continue;
            }
            compaction_stop(&compaction);
            if(journal.preparing) {
                atomic_store(&journal.hold,false);pthread_join(journal.preparation,NULL);journal.preparing=false;
            }
            yd_raft_runtime_stop(runtime);runtime=NULL;
            atomic_store(&journal.hold,false);
            if(journal.started) { pthread_join(journal.thread,NULL);journal.started=false; }
            printf("journal-closed %u\n",journal.image!=NULL);fflush(stdout);break;
        } else if (!strncmp(line, "snapshot ", 9)) {
            unsigned from;
            unsigned long long term, index, base_term;
            if (sscanf(line + 9, "%u %llu %llu %llu", &from, &term, &index, &base_term) != 4)
                puts("invalid snapshot command");
            else {
                YDRaftSnapshotOffer offer = {.from = from, .term = term,
                    .base = {.index = index, .term = base_term, .archive = {1}}};
                memcpy(offer.cluster, config.cluster, 16);
                bool needed;
                bool valid = yd_raft_runtime_snapshot_contact(runtime, &offer, &needed);
                printf("snapshot %u %u\n", valid, needed);
            }
        } else if (!strncmp(line, "install ", 8) || !strncmp(line, "install-fail ", 13) ||
                   !strncmp(line, "install-delay ", 14) ||
                   !strncmp(line, "install-clock-fail ", 19)) {
            unsigned from;
            unsigned long long term, index, base_term;
            const char *arguments = line + 8;
            if (!strncmp(line, "install-fail ", 13)) {
                char *end;
                fail_sync = (unsigned)strtoul(line + 13, &end, 10);
                sync_count = 0;
                arguments = end;
            } else if (!strncmp(line, "install-delay ", 14)) {
                char *end;
                delay_sync = (unsigned)strtoul(line + 14, &end, 10);
                sync_count = 0;
                arguments = end;
            } else if (!strncmp(line, "install-clock-fail ", 19)) {
                fail_clock = 2;
                clock_count = 0;
                arguments = line + 19;
            }
            if (sscanf(arguments, "%u %llu %llu %llu", &from, &term, &index, &base_term) != 4)
                puts("invalid install command");
            else {
                YDRaftSnapshotOffer offer = {.from = from, .term = term,
                    .base = {.index = index, .term = base_term, .archive = {1}}};
                memcpy(offer.cluster, config.cluster, 16);
                bool published;
                bool valid = yd_raft_runtime_snapshot_install(runtime, &offer,
                    published_snapshot, &publications, &published);
                printf("installed %u %u %u\n", valid, published, publications);
            }
            fail_sync = delay_sync = fail_clock = 0;
        } else if (!strncmp(line, "checkpoint-barrier ", 19)) {
            unsigned timeout, block;
            if (sscanf(line + 19, "%u %u", &timeout, &block) != 2) {
                puts("invalid checkpoint barrier");
            } else {
                BarrierCheckpoint race = {.block = block != 0, .same_deadline = true};
                uint64_t term, index;
                barrier_checkpoint = &race;
                bool valid = yd_raft_runtime_barrier(runtime, timeout, &term, &index);
                barrier_checkpoint = NULL;
                atomic_store(&suppress_read_acks, false);
                printf("checkpoint-barrier %u %u %u %u %u %u %u %u %llu %llu %llu %llu\n",
                    valid, race.injected, race.checkpointed, race.stale_rejected, race.begins,
                    race.fresh, race.waits, race.same_deadline,
                    (unsigned long long)race.old_epoch, (unsigned long long)race.new_epoch,
                    (unsigned long long)term, (unsigned long long)index);
            }
        } else if (!strncmp(line, "barrier ", 8)) {
            uint64_t term, index;
            bool valid = yd_raft_runtime_barrier(runtime, (unsigned)strtoul(line + 8, NULL, 10),
                                                 &term, &index);
            printf("barrier %u %llu %llu\n", valid, (unsigned long long)term,
                   (unsigned long long)index);
        } else if (!strcmp(line, "oversized")) {
            unsigned char bytes[2048] = {1};
            uint64_t a, b;
            bool first = yd_raft_runtime_propose(runtime, bytes, sizeof(bytes), &a);
            YDRaftStatus s = yd_raft_runtime_status(runtime);
            bool second = yd_raft_runtime_propose_at(runtime, s.term, s.last, bytes, sizeof(bytes), &b);
            printf("oversized %u %llu %u %llu\n", first, (unsigned long long)a, second, (unsigned long long)b);
        } else if (!strncmp(line, "propose-at ", 11)) {
            char *end = NULL;
            uint64_t term = strtoull(line + 11, &end, 10);
            uint64_t base = strtoull(end, &end, 10), index;
            const char *command = *end == ' ' ? end + 1 : end;
            bool accepted =
                yd_raft_runtime_propose_at(runtime, term, base, command, strlen(command), &index);
            printf("proposed %u %llu\n", accepted, (unsigned long long)index);
        } else if (!strncmp(line, "propose ", 8)) {
            uint64_t index;
            bool accepted = yd_raft_runtime_propose(runtime, line + 8, length - 8, &index);
            printf("proposed %u %llu\n", accepted, (unsigned long long)index);
        } else if (!strncmp(line, "entry ", 6)) {
            uint64_t index = strtoull(line + 6, NULL, 10);
            YDRaftEntry entry;
            if (yd_raft_runtime_entry(runtime, index, &entry)) {
                printf("entry %llu %u ", (unsigned long long)entry.term, entry.kind);
                for (size_t i = 0; i < entry.size; i++)
                    printf("%02x", entry.command[i]);
                putchar('\n');
                yd_raft_entry_free(&entry);
            } else
                puts("missing");
        } else if (!strcmp(line, "stop"))
            break;
        else
            puts("unknown");
        fflush(stdout);
    }
    atomic_store(&journal.cancel,true);atomic_store(&journal.hold,false);
    atomic_store(&dependency_job.release, true);
    atomic_store(&census_job.cancel, true); atomic_store(&census_job.release, true);
    if (census_job.started) pthread_join(census_job.thread, NULL);
    yd_raft_journal_census_close(census_job.token);
    yd_raft_journal_census_close(census);
    if (dependency_job.started) pthread_join(dependency_job.thread, NULL);
    yd_raft_journal_dependencies_close(dependency_job.dependencies);
    compaction_stop(&compaction);
    if(journal.started)pthread_join(journal.thread,NULL);
    if(journal.preparing)pthread_join(journal.preparation,NULL);
    yd_raft_journal_publication_close(journal.publication);
    yd_raft_journal_dependencies_close(dependencies);
    yd_raft_journal_capture_close(journal.capture);yd_raft_journal_image_close(journal.image);
    if(journal.directory>=0)close(journal.directory);
    yd_raft_runtime_stop(runtime);
    yd_disk_close(observation.pin);
    yd_disk_lineage_snapshot_close(lineage_snapshot);
    yd_disk_lineage_release(observation.lineage);
    yd_raft_journal_scope_close(observation.scope);
    close(listener);
    yd_tls_free(tls);
    return 0;
}
