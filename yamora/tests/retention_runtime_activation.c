#define _GNU_SOURCE
#include "../src/consensus/runtime_internal.h"
#include "../src/consensus/raft_internal.h"
#include "../src/consensus/retention_session_owner.h"
#include "../src/consensus/journal_copy_internal.h"
#include "../src/consensus/cluster.h"
#include "../src/consensus/cluster_receive.h"
#include "../src/disk_internal.h"
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <unistd.h>

/* Only the calling constructor thread injects faults; real worker I/O is never
 * counted as a publication witness or an injected setup failure. */
static _Thread_local bool watching, recovery_seen, ordered, cancelled, mask_ok;
static _Thread_local unsigned registrations, recovery_reads, register_fault;
static _Thread_local int watching_root = -1;
static _Thread_local const char *fault;
static _Thread_local unsigned native_syncs, fault_hits;
static _Thread_local unsigned terminal_fault_at, terminal_syncs;
static _Thread_local bool terminal_fault_seen;
static _Thread_local unsigned failed_clean_mode, failed_clean_armed;
static _Thread_local bool failed_clean_seen;
static _Thread_local bool intent_stat_fault, intent_stat_seen;
static _Thread_local bool archive_phase, archive_control_fault, archive_control_seen;
static _Thread_local int archive_cut_descriptor = -1;
static _Thread_local bool application_fault_arm;
static _Thread_local bool callback_seen;
static _Thread_local bool read_ordered;
static _Thread_local uint64_t recovery_epoch;
static _Thread_local bool constructor_busy, fence_sync, fence_root_sync, active_sync, active_root_sync;
static _Thread_local bool fence_before_active;
static _Thread_local unsigned char failed_bytes[8192];
static _Thread_local size_t failed_size;
static _Thread_local YDRaftRuntime *observed_runtime;
static _Thread_local YDRaftCluster *observed_cluster;
static _Thread_local const char *case_name;
static YDDisk *escaped_pin, *escaped_nested;
static YDDiskRecoveryRoots *escaped_roots;
static YDDiskLineage *escaped_lineage;
static YDDiskLineageSnapshot *escaped_snapshot;
static bool publication_ok=true;
static _Thread_local bool preserve_phase;
static _Thread_local bool cut_cancel_arm;
static _Thread_local bool birth_read_armed, real_pin_invalid;
static _Thread_local unsigned birth_digest_target, birth_digest_calls;
static _Thread_local YDRaftRetentionBirthResult real_birth_result;
static pthread_t drain_threads[16];
static bool drain_joined[16];
static unsigned drain_started, drain_finished;
YDRaftJournalScope *__real_yd_raft_journal_scope_new(void);
YDRaftJournalScope *__wrap_yd_raft_journal_scope_new(void) {
    if(watching && !strcmp(case_name,"allocation-scope")) {fault_hits++;errno=ENOMEM;return NULL;}
    return __real_yd_raft_journal_scope_new();
}
YDDiskLineage *__real_yd_disk_lineage_new(void);
YDDiskLineage *__wrap_yd_disk_lineage_new(void) {
    if(watching && !strcmp(case_name,"allocation-lineage")) {fault_hits++;errno=ENOMEM;return NULL;}
    return __real_yd_disk_lineage_new();
}
YDDiskLineageSnapshot *__real_yd_disk_lineage_snapshot(YDDiskLineage *);
YDDiskLineageSnapshot *__wrap_yd_disk_lineage_snapshot(YDDiskLineage *lineage) {
    if(watching && !strcmp(case_name,"postcomplete")) {fault_hits++;errno=ENOMEM;return NULL;}
    return __real_yd_disk_lineage_snapshot(lineage);
}

static int assertion(bool ok, const char *name) {
    if (!ok) { fprintf(stderr, "RUNTIME_ASSERT:%s\n", name); return 2; }
    return 0;
}
static bool named_fd(int fd, const char *name) {
    struct stat opened, named;
    return !fstat(fd,&opened) && !fstatat(watching_root,name,&named,AT_SYMLINK_NOFOLLOW) &&
        opened.st_dev==named.st_dev && opened.st_ino==named.st_ino;
}
int __real_fstatat(int,const char *,struct stat *,int);
int __wrap_fstatat(int directory,const char *name,struct stat *out,int flags) {
    if(intent_stat_fault && !strcmp(name,".yamora-retention-finalizing")) {
        intent_stat_fault=false;intent_stat_seen=true;errno=EIO;return -1;
    }
    return __real_fstatat(directory,name,out,flags);
}
ssize_t __real_pread(int,void *,size_t,off_t);
ssize_t __wrap_pread(int fd,void *bytes,size_t length,off_t offset) {
    const char *late_name=failed_clean_armed==1 ? YD_DISK_FILE :
        failed_clean_armed==2 ? YD_RAFT_RETENTION_SESSION_FILE : YD_RETENTION_FILE;
    if(failed_clean_armed && named_fd(fd,late_name)) {
        failed_clean_armed=0;failed_clean_seen=true;errno=EIO;return -1;
    }
    if(archive_control_fault && named_fd(fd,YD_RETENTION_FILE)) {
        archive_control_fault=false;archive_control_seen=true;errno=EIO;return -1;
    }
    if(birth_read_armed && named_fd(fd,YD_RAFT_RETENTION_BIRTH_FILE)) {
        birth_read_armed=false;fault_hits++;errno=EIO;return -1;
    }
    return __real_pread(fd,bytes,length,offset);
}
int __real_fcntl(int,int,...);
int __wrap_fcntl(int fd,int command,...) {
    va_list args;va_start(args,command);int result;
    if(command==F_OFD_SETLK || command==F_OFD_SETLKW || command==F_OFD_GETLK) {
        struct flock *lock=va_arg(args,struct flock *);
        if(archive_phase && archive_cut_descriptor>=0 && named_fd(fd,YD_RETENTION_FILE) &&
                lock->l_type==F_RDLCK && command!=F_OFD_GETLK) {
            (void)assertion(false,"ARCHIVE_CUT_NEVER_REACQUIRES_SHARED_GATE");_Exit(2);
        }
        result=__real_fcntl(fd,command,lock);
        if(archive_phase && result==0 && command!=F_OFD_GETLK &&
                lock->l_type==F_WRLCK && named_fd(fd,YD_RETENTION_FILE))
            archive_cut_descriptor=fd;
    } else if(command==F_GETFL || command==F_GETFD) result=__real_fcntl(fd,command);
    else result=__real_fcntl(fd,command,va_arg(args,int));
    va_end(args);return result;
}
int __real_close(int);
int __wrap_close(int fd) {
    int result=__real_close(fd);
    /* Failure fallback may take SH only AFTER the independently owned EX fd
     * actually closes. Session-owner lock probes use a different file. */
    if(fd==archive_cut_descriptor && (result==0 || errno==EINTR)) archive_cut_descriptor=-1;
    return result;
}
unsigned char *__real_SHA256(const unsigned char *,size_t,unsigned char *);
unsigned char *__wrap_SHA256(const unsigned char *bytes,size_t length,unsigned char *digest) {
    if(birth_digest_target && ++birth_digest_calls==birth_digest_target) {
        birth_digest_target=0;fault_hits++;errno=EIO;return NULL;
    }
    return __real_SHA256(bytes,length,digest);
}
YDRaftRetentionBirthResult __real_yd_raft_retention_birth_observe(YDRetentionGate *,
    YDRaftRetentionBirth **,char *,size_t);
YDRaftRetentionBirthResult __wrap_yd_raft_retention_birth_observe(YDRetentionGate *gate,
    YDRaftRetentionBirth **birth,char *error,size_t length) {
    if(watching && preserve_phase && !strncmp(case_name,"observer-hash-",14)) {
        birth_digest_target=(unsigned)strtoul(case_name+14,NULL,10);
        birth_digest_calls=0;
    }
    YDRaftRetentionBirthResult result=__real_yd_raft_retention_birth_observe(gate,birth,error,length);
    if(birth_digest_calls) real_birth_result=result;
    birth_digest_target=0;
    return result;
}
int __real_fsync(int);
int __wrap_fsync(int fd) {
    if(terminal_fault_at && ++terminal_syncs==terminal_fault_at) {
        terminal_fault_at=0;terminal_fault_seen=true;errno=ENOSPC;return -1;
    }
    if (watching && case_name && !strcmp(case_name,"cancel-prepare") && !cancelled &&
        named_fd(fd,YD_RAFT_RETENTION_BIRTH_FILE)) cancelled=!pthread_cancel(pthread_self());
    if (watching && fault) {
        bool hit = (!strcmp(fault,"birth") && named_fd(fd,YD_RAFT_RETENTION_BIRTH_FILE)) ||
            (!strcmp(fault,"session") && named_fd(fd,YD_RAFT_RETENTION_SESSION_FILE));
        if (!strcmp(fault,"fence") && named_fd(fd,YD_DISK_FILE))
            hit = ++native_syncs == 2; /* Real initial header sync precedes install. */
        if (hit && !fault_hits++) {
            failed_size=!strcmp(fault,"fence") ? 8192 : 256;
            if(pread(fd,failed_bytes,failed_size,0)!=(ssize_t)failed_size) failed_size=0;
            errno=EIO; return -1;
        }
    }
    int result=__real_fsync(fd);
    if(!result && failed_clean_mode && failed_clean_mode<3 &&
        !failed_clean_seen && named_fd(fd,YD_RAFT_RETENTION_SESSION_FILE)) {
        unsigned char bytes[256];YDRaftRetentionSessionRecord record;
        if(__real_pread(fd,bytes,sizeof(bytes),0)==sizeof(bytes) &&
            yd_raft_retention_session_record_decode(bytes,sizeof(bytes),&record) &&
            record.state==YD_RAFT_RETENTION_SESSION_CLEAN) failed_clean_armed=failed_clean_mode;
    }
    if(watching && !result && case_name && !strcmp(case_name,"namespace-race") &&
        !fault_hits && named_fd(fd,YD_DISK_FILE)) {
        /* Native's empty-root precheck has already passed. Introduce a real
         * unrelated name before the controller guard can begin metadata. */
        int other=openat(watching_root,"unknown",O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC,0600);
        fault_hits=other>=0 && write(other,"preserve",8)==8 ? 1 : 2;
        if(other>=0) close(other);
    }
    if(watching && !result) {
        if(named_fd(fd,YD_DISK_FILE)) {
            unsigned char headers[8192];
            if(pread(fd,headers,sizeof(headers),0)==sizeof(headers) &&
                !memcmp(headers+64,"YDOFENC1",8) && !memcmp(headers+4160,"YDOFENC1",8)) fence_sync=true;
        }
        if(named_fd(fd,YD_RAFT_RETENTION_SESSION_FILE)) active_sync=true;
        struct stat status,root;
        if(!fstat(fd,&status) && !fstat(watching_root,&root) &&
            status.st_dev==root.st_dev && status.st_ino==root.st_ino) {
            if(fence_sync) fence_root_sync=true;
            if(active_sync) active_root_sync=true;
        }
    }
    return result;
}
bool __real_yd_raft_journal_scope_cut_run(YDRaftJournalScope *,YDRetentionCut,
    bool (*)(void *),void *);
bool __wrap_yd_raft_journal_scope_cut_run(YDRaftJournalScope *scope,YDRetentionCut cut,
    bool (*body)(void *),void *context) {
    bool result=__real_yd_raft_journal_scope_cut_run(scope,cut,body,context);
    /* Arm only AFTER the scope's own final validation. The outer gate still
     * has to validate before releasing its actual exclusive descriptor. */
    if(result && failed_clean_mode==3 && !failed_clean_seen) failed_clean_armed=3;
    return result;
}
YDRaftRetentionSessionResult __real_yd_raft_retention_session_create(YDDisk *,YDRetentionGate *,
    YDRaftRetentionBirth *,YDRaftRetentionSessionOwner **,char *,size_t);
YDRaftRetentionSessionResult __wrap_yd_raft_retention_session_create(YDDisk *disk,YDRetentionGate *gate,
    YDRaftRetentionBirth *birth,YDRaftRetentionSessionOwner **owner,char *error,size_t length) {
    if(watching) fence_before_active=fence_sync && fence_root_sync;
    return __real_yd_raft_retention_session_create(disk,gate,birth,owner,error,length);
}
YDRaftRetentionSessionResult __real_yd_raft_retention_session_observe(YDRetentionGate *,
    YDRaftRetentionBirth *,YDRaftRetentionSessionOwner **,char *,size_t);
YDRaftRetentionSessionResult __wrap_yd_raft_retention_session_observe(YDRetentionGate *gate,
    YDRaftRetentionBirth *birth,YDRaftRetentionSessionOwner **owner,char *error,size_t length) {
    if(watching && preserve_phase && !strcmp(case_name,"observer-pin-io")) {
        birth_read_armed=true;
        YDRaftRetentionSessionResult result=__real_yd_raft_retention_session_observe(gate,birth,owner,error,length);
        int observed_errno=errno;
        birth_read_armed=false;
        real_pin_invalid=result==YD_RAFT_RETENTION_SESSION_INVALID && observed_errno==EIO &&
            !*owner && !yd_raft_retention_birth_validate(birth);
        errno=observed_errno;
        return result;
    }
    if(watching && case_name && !strcmp(case_name,"observer-io")) {
        fault_hits++;*owner=NULL;errno=EIO;
        return YD_RAFT_RETENTION_SESSION_IO;
    }
    return __real_yd_raft_retention_session_observe(gate,birth,owner,error,length);
}
YDRaftIncoming *__real_yd_raft_incoming_new(YDRaftCluster *,const unsigned char *,unsigned,unsigned);
YDRaftIncoming *__wrap_yd_raft_incoming_new(YDRaftCluster *cluster,const unsigned char *id,
    unsigned local,unsigned voters) {
    if(case_name && !strcmp(case_name,"cancel-cluster")) {
        observed_cluster=cluster;
        int prior;
        pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,&prior);
        mask_ok=prior==PTHREAD_CANCEL_DISABLE;callback_seen=true;
        cancelled=!pthread_cancel(pthread_self());
        pthread_setcancelstate(prior,NULL);
    }
    return __real_yd_raft_incoming_new(cluster,id,local,voters);
}
int __real_pthread_create(pthread_t *,const pthread_attr_t *,void *(*)(void *),void *);
int __wrap_pthread_create(pthread_t *thread,const pthread_attr_t *attributes,
    void *(*body)(void *),void *argument) {
    /* First runtime worker is an outbound Worker whose first member is runtime.
     * Keep a cleanup-only witness for deliberate missing-adoption mutants. */
    if(watching && callback_seen && case_name && !strncmp(case_name,"cancel-",7) &&
        !observed_runtime) observed_runtime=*(YDRaftRuntime **)argument;
    int result=__real_pthread_create(thread,attributes,body,argument);
    if(!result && watching && case_name && !strcmp(case_name,"drain") && drain_started<16)
        drain_threads[drain_started++]=*thread;
    return result;
}
int __real_pthread_join(pthread_t,void **);
int __wrap_pthread_join(pthread_t thread,void **result) {
    int code=__real_pthread_join(thread,result);
    if(!code) for(unsigned i=0;i<drain_started;i++)
        if(!drain_joined[i] && pthread_equal(thread,drain_threads[i])) {
            drain_joined[i]=true;drain_finished++;break;
        }
    return code;
}
YDRaftJournalBinding *__real_yd_raft_journal_scope_file(YDRaftJournalScope *, int,
    const char *, int, YDRaftJournalBindingKind);
YDRaftJournalBinding *__wrap_yd_raft_journal_scope_file(YDRaftJournalScope *scope,
    int root, const char *name, int fd, YDRaftJournalBindingKind kind) {
    if (watching && register_fault == (unsigned)kind) {
        fault_hits++;
        yd_raft_journal_scope_incomplete(scope);
        return NULL;
    }
    YDRaftJournalBinding *binding = __real_yd_raft_journal_scope_file(scope, root, name, fd, kind);
    if (watching && binding) {
        if (kind == YD_RAFT_JOURNAL_BINDING_CONTROL) registrations |= 1;
        if (kind == YD_RAFT_JOURNAL_BINDING_BIRTH) registrations |= 2;
        if (kind == YD_RAFT_JOURNAL_BINDING_SESSION) registrations |= 4;
    }
    return binding;
}
static bool session_bytes(int root, unsigned char bytes[256]) {
    int fd=openat(root,YD_RAFT_RETENTION_SESSION_FILE,O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);
    bool ok=fd>=0 && pread(fd,bytes,256,0)==256;
    if(fd>=0) close(fd);
    return ok;
}
static bool session(int root, YDRaftRetentionSessionRecord *record) {
    unsigned char bytes[256];
    return session_bytes(root,bytes) && yd_raft_retention_session_record_decode(bytes,256,record);
}
YDDiskTxn *__real_yd_disk_begin_exclusive(YDDisk *, char *, size_t);
YDDiskTxn *__wrap_yd_disk_begin_exclusive(YDDisk *disk, char *error, size_t length) {
    if (watching && !recovery_seen) {
        recovery_seen = true;
        unsigned char headers[8192];
        YDRaftRetentionSessionRecord record;
        ordered = registrations == 7 && session(watching_root, &record) &&
            record.state == YD_RAFT_RETENTION_SESSION_ACTIVE && record.epoch == 1 &&
            pread(disk->fd, headers, sizeof(headers), 0) == sizeof(headers) &&
            !memcmp(headers + 64, "YDOFENC1", 8) &&
            !memcmp(headers + 4096 + 64, "YDOFENC1", 8) &&
            !memcmp(headers + 80, record.birth_hash, 32) &&
            !memcmp(headers + 4096 + 80, record.birth_hash, 32);
        unsigned char cluster[16]={1,2,3,4};
        YDRetentionGate *gate=yd_retention_gate_open(watching_root,cluster,1,3,false,NULL,0);
        int cut=-1;
        constructor_busy=yd_retention_gate_try_cut(gate,&cut,NULL,0)==0 && cut==-1;
        if(cut>=0) close(cut);
        yd_retention_gate_close(gate);
    }
    return __real_yd_disk_begin_exclusive(disk, error, length);
}
int __real_yd_disk_get(YDDisk *,const YDDiskView *,const void *,size_t,uint64_t *,char *,size_t);
int __wrap_yd_disk_get(YDDisk *disk,const YDDiskView *view,const void *key,size_t size,
    uint64_t *offset,char *error,size_t length) {
    if(watching && !recovery_reads++) {
        unsigned char headers[8192];YDRaftRetentionSessionRecord record;
        read_ordered=registrations==7 && session(watching_root,&record) &&
            record.state==YD_RAFT_RETENTION_SESSION_ACTIVE && record.epoch==(recovery_epoch ? recovery_epoch : 1) &&
            pread(disk->fd,headers,sizeof(headers),0)==sizeof(headers) &&
            !memcmp(headers+64,"YDOFENC1",8) && !memcmp(headers+4160,"YDOFENC1",8) &&
            !memcmp(headers+80,record.birth_hash,32) && !memcmp(headers+4176,record.birth_hash,32);
    }
    return __real_yd_disk_get(disk,view,key,size,offset,error,length);
}
static bool check(void *context,YDRaft *raft,char *error,size_t length) {
    (void)context;
    callback_seen=true;
    int prior;
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,&prior);
    mask_ok = prior==PTHREAD_CANCEL_DISABLE;
    pthread_setcancelstate(prior,NULL);
    if(!strcmp(case_name,"reject-check")) return false;
    if (!strcmp(case_name,"cancel-check")) {
        cancelled=!pthread_cancel(pthread_self());
        return true;
    }
    const char *kind=case_name;
    if(!strncmp(kind,"finalize-",9)) kind+=9;
    if(!strncmp(kind,"preserve-",9)) {
        if(!preserve_phase) return true;
        kind+=9;
    }
    if (!strcmp(kind,"escape-pin") || !strcmp(kind,"escape-nested")) {
        escaped_pin=yd_disk_pin(raft->disk,32768,error,length);
        if (!strcmp(kind,"escape-nested") && escaped_pin)
            escaped_nested=yd_disk_pin(escaped_pin,32768,error,length);
        return escaped_pin && (strcmp(kind,"escape-nested") || escaped_nested);
    }
    if (!strcmp(kind,"escape-roots"))
        return yd_disk_recovery_roots_pin(raft->disk,32768,&escaped_roots,error,length)==YD_DISK_OBSERVE_OK;
    if (!strcmp(kind,"escape-snapshot")) {
        escaped_lineage=yd_disk_lineage_retain(raft->disk->lineage.scope);
        escaped_snapshot=yd_disk_lineage_snapshot(escaped_lineage);
        YDDiskLineageInfo info;
        return yd_disk_lineage_snapshot_info(escaped_snapshot,&info) && info.complete;
    }
    if (!strcmp(case_name,"tracking")) yd_raft_journal_scope_incomplete(raft->journal_scope);
    if (!strcmp(case_name,"publication")) {
        bool setup=!mkdirat(raft->directory,"candidate",0700);
        int directory=openat(raft->directory,"candidate",O_RDONLY|O_DIRECTORY|O_CLOEXEC);
        int marker=directory<0 ? -1 : openat(directory,".yamora-initializing",O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC,0600);
        if(marker>=0) close(marker);
        YDDisk *writer=directory<0 ? NULL : yd_disk_open_at(directory,true,32768,error,length);
        struct stat native,status;
        setup=setup && marker>=0 && writer && !fstat(raft->disk->fd,&native);
        YDRaftJournalImage image={.writer=writer,.directory=directory};
        if(setup) image.origin=(YDRaftJournalOrigin){.device=native.st_dev,.inode=native.st_ino,
            .view=yd_disk_view(raft->disk),.meta=raft->meta};
        YDRaftJournalPublication *p=setup ? yd_raft_journal_prepare(&image,raft->directory,error,length) : NULL;
        publication_ok=setup && !p && fstatat(raft->directory,YD_RAFT_JOURNAL_RETAINED,
            &status,AT_SYMLINK_NOFOLLOW)<0 && errno==ENOENT;
        yd_raft_journal_publication_close(p);yd_disk_close(writer);
        if(directory>=0) close(directory);
    }
    return true;
}
static bool excluded(int root,bool busy) {
    int session_fd=openat(root,YD_RAFT_RETENTION_SESSION_FILE,O_RDWR|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);
    int directory=openat(root,".",O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    struct flock lock={.l_type=F_WRLCK,.l_whence=SEEK_SET,.l_start=0,.l_len=1};
    errno=0;
    int session_result=session_fd<0 ? -2 : fcntl(session_fd,F_OFD_SETLK,&lock);
    bool session_ok=busy ? session_result==-1 && (errno==EAGAIN || errno==EACCES) : session_result==0;
    errno=0;
    int root_result=directory<0 ? -2 : flock(directory,LOCK_EX|LOCK_NB);
    bool root_ok=busy ? root_result==-1 && (errno==EAGAIN || errno==EWOULDBLOCK) : root_result==0;
    if(session_fd>=0) close(session_fd);
    if(directory>=0) close(directory);
    return session_ok && root_ok;
}
static bool release_escaped(int root) {
    if(!escaped_pin && !escaped_nested && !escaped_roots && !escaped_snapshot && !escaped_lineage) return true;
    bool valid=excluded(root,true);
    yd_disk_close(escaped_pin);escaped_pin=NULL;
    if(escaped_nested) valid=valid && excluded(root,true);
    yd_disk_close(escaped_nested);escaped_nested=NULL;
    yd_disk_recovery_roots_close(escaped_roots);escaped_roots=NULL;
    yd_disk_lineage_snapshot_close(escaped_snapshot);escaped_snapshot=NULL;
    yd_disk_lineage_release(escaped_lineage);escaped_lineage=NULL;
    return valid && excluded(root,false);
}
typedef struct {YDRaftRuntime *runtime;int root;YDRaftApplicationCut *cut;bool returned,cleared,requested;} CutJob;
YDRaftJournalProtection *__real_yd_raft_journal_protection_take(YDRaftJournalCensus *,int,
    YDRaftJournalCensusProgress,void *,char *,size_t);
YDRaftJournalProtection *__wrap_yd_raft_journal_protection_take(YDRaftJournalCensus *census,int root,
    YDRaftJournalCensusProgress progress,void *context,char *error,size_t length) {
    YDRaftJournalProtection *p=__real_yd_raft_journal_protection_take(census,root,progress,context,error,length);
    YDRaftJournalProtectionInfo info;
    if(application_fault_arm) {
        application_fault_arm=false;archive_control_fault=true;
    }
    if(cut_cancel_arm && case_name && !strcmp(case_name,"cut-cancel") &&
        yd_raft_journal_protection_info(p,&info) && info.application_pins_complete &&
        info.census.coverage_complete && info.census.metadata_complete && info.census.archive_pins_complete) {
        cut_cancel_arm=false;
        cancelled=!pthread_cancel(pthread_self());
    }
    return p;
}
static void cut_witness(void *context) {
    CutJob *job=context;
    job->requested=cancelled;job->cleared=job->cut==NULL;
    /* A deliberately premature output contains an already-freed pointer.
     * Record that failure without double-closing it or hiding it with ASAN. */
    job->cut=NULL;
}
static void *cancel_cut_start(void *context) {
    CutJob *job=context;case_name="cut-cancel";cut_cancel_arm=true;
    char error[256];unsigned char target[32]={9};
    job->cut=(YDRaftApplicationCut *)(uintptr_t)0xa5;
    pthread_cleanup_push(cut_witness,job);
    (void)yd_raft_runtime_application_cut(job->runtime,job->root,target,&job->cut,error,sizeof(error));
    job->returned=true;
    yd_raft_runtime_application_cut_close(job->cut);job->cut=NULL;
    pthread_cleanup_pop(0);
    return NULL;
}
static bool replace_record(int root,YDRaftRetentionSessionState state) {
    YDRaftRetentionSessionRecord record;
    unsigned char bytes[256];
    if(!session(root,&record)) return false;
    record.state=state;
    if(state==YD_RAFT_RETENTION_SESSION_CLEAN) memset(record.terminal_root,7,32);
    if(state==YD_RAFT_RETENTION_SESSION_POISON) record.reason_bits=1;
    if(!yd_raft_retention_session_record_encode(bytes,256,&record)) return false;
    int fd=openat(root,YD_RAFT_RETENTION_SESSION_FILE,O_WRONLY|O_CLOEXEC|O_NOFOLLOW);
    bool ok=fd>=0 && pwrite(fd,bytes,256,0)==256 && !fsync(fd) && !fsync(root);
    if(fd>=0) close(fd);
    return ok;
}
static bool empty(int root) {
    int fd=openat(root,".",O_RDONLY|O_DIRECTORY|O_CLOEXEC);
    DIR *directory=fd<0 ? NULL : fdopendir(fd);
    if(!directory) { if(fd>=0) close(fd); return false; }
    bool ok=true;
    struct dirent *entry;
    while((entry=readdir(directory)))
        if(strcmp(entry->d_name,".") && strcmp(entry->d_name,"..")) ok=false;
    closedir(directory);
    return ok;
}
typedef struct {YDRaftConfig *config;YDTLS *tls;int listener,root;const char *name,*documents;bool returned,masked,seen,released,requested;} CancelJob;
static void cancel_witness(void *context) {
    CancelJob *job=context;
    job->masked=mask_ok;job->seen=callback_seen;job->requested=cancelled;
    job->released=excluded(job->root,false);
    if(job->documents) {
        int fd=open(job->documents,O_RDONLY|O_DIRECTORY|O_CLOEXEC);
        job->released=job->released && fd>=0 && !flock(fd,LOCK_EX|LOCK_NB);
        if(fd>=0) close(fd);
    }
    /* Observe before recovery cleanup: leaked ownership always fails the
     * assertion. Close deliberate mutants so LSan/stray workers cannot replace
     * the named normal-exit behavioral oracle. Never repair the actual result. */
    if(!job->released) {
        if(observed_cluster) yd_raft_cluster_close(observed_cluster);
        else if(observed_runtime) yd_raft_runtime_stop(observed_runtime);
        if(job->documents) {
            struct stat original;
            DIR *fds=opendir("/proc/self/fd");
            if(fds && !stat(job->documents,&original)) {
                struct dirent *entry;
                while((entry=readdir(fds))) {
                    char *end;long fd=strtol(entry->d_name,&end,10);struct stat status;
                    if(*end || fd<3 || fd==dirfd(fds)) continue;
                    if(!fstat((int)fd,&status) && status.st_dev==original.st_dev &&
                        status.st_ino==original.st_ino) close((int)fd);
                }
            }
            if(fds) closedir(fds);
        }
    }
}
static void *cancel_start(void *context) {
    CancelJob *job=context;
    case_name=job->name;
    watching_root=job->root;
    watching=true;
    char error[256];
    /* The worker begins enabled. Cancellation must be masked by the actual
     * constructor, then cleanup must own it before restoring the state. */
    pthread_cleanup_push(cancel_witness,job);
    if(!strcmp(case_name,"cancel-pending")) cancelled=!pthread_cancel(pthread_self());
    YDRaftRuntime *runtime=NULL;
    YDRaftCluster *cluster=NULL;
    if(job->documents) cluster=yd_raft_cluster_start(job->config,job->documents,32768,
        job->tls,job->listener,error,sizeof(error));
    else runtime=yd_raft_runtime_start_retaining(job->config,job->tls,
        job->listener,check,NULL,error,sizeof(error));
    job->returned=true;
    job->masked=mask_ok;job->seen=callback_seen;
    yd_raft_runtime_stop(runtime);
    yd_raft_cluster_close(cluster);
    pthread_cleanup_pop(0);
    return NULL;
}
static int service(const char *base,const char *certificates,YDRaftConfig config,
    const int listeners[3],bool legacy) {
    YDRaftCluster *clusters[3]={0};
    YDTLS *tls[3]={0};
    char journals[3][4096],documents[3][4096],error[256]={0};
    unsigned char saved[3][256]={{0}};
    bool ok=true,compaction_refused=true,checkpointed=false,receipts=true;
    int basefd=open(base,O_RDONLY|O_DIRECTORY|O_CLOEXEC);
    for(unsigned i=0;i<3;i++) {
        snprintf(journals[i],sizeof(journals[i]),"%s/journal%u",base,i);
        snprintf(documents[i],sizeof(documents[i]),"%s/documents%u",base,i);
        if(mkdir(journals[i],0700) || mkdir(documents[i],0700)) ok=false;
        char cert[4096],key[4096],ca[4096];
        snprintf(cert,sizeof(cert),"%s/node%u.pem",certificates,i+1);
        snprintf(key,sizeof(key),"%s/node%u.key",certificates,i+1);
        snprintf(ca,sizeof(ca),"%s/ca.pem",certificates);
        tls[i]=yd_tls_peer_new(cert,key,ca,error,sizeof(error));
        if(!tls[i]) ok=false;
        if(legacy) {
            YDRaft *raft=yd_raft_open(journals[i],config.cluster,i+1,3,32768,error,sizeof(error));
            ok=ok && raft;yd_raft_close(raft);
        }
    }
    config.timing=(YDRaftTiming){.heartbeat_ms=50,.election_min_ms=600,.election_max_ms=1100,.rpc_ms=250};
    static const unsigned char source[]="# runtime exact YAML\r\ncount: 0 # keep\r\n";
    static const unsigned char patch[]="{\"$inc\":{\"count\":1}}";
    const char *target="/v1/collections/config/documents/control";
    char revision[17]={0};
    for(unsigned phase=0;phase<(legacy?2U:4U) && ok;phase++) {
        for(unsigned i=0;i<3 && ok;i++) {
            config.node=i+1;config.journal_root=journals[i];
            clusters[i]=yd_raft_cluster_start(&config,documents[i],32768,tls[i],listeners[i],error,sizeof(error));
            ok=clusters[i]!=NULL;
            if(ok && !legacy && phase<2) {
                int root=open(journals[i],O_RDONLY|O_DIRECTORY|O_CLOEXEC);
                YDRaftRetentionSessionRecord record;
                ok=root>=0 && session(root,&record) &&
                    record.state==YD_RAFT_RETENTION_SESSION_ACTIVE && record.epoch==phase+1;
                if(root>=0) close(root);
            }
        }
        unsigned leader=3;
        for(unsigned attempts=0;attempts<500 && ok && leader==3;attempts++) {
            for(unsigned i=0;i<3;i++) if(yd_raft_cluster_status(clusters[i]).raft.role==YD_RAFT_LEADER) leader=i;
            if(leader==3) {struct timespec delay={.tv_nsec=10000000};nanosleep(&delay,NULL);}
        }
        ok=ok && leader<3;
        if(ok) {
            YDRaftWrite write={.id={1},.method="PUT",.target=target,.body=source,.size=sizeof(source)-1};
            YDDiskReply reply=yd_raft_cluster_write(clusters[leader],&write,4000);
            receipts=receipts && reply.status==201;
            if(!phase) memcpy(revision,reply.revision,sizeof(revision));
            else receipts=receipts && !memcmp(revision,reply.revision,sizeof(revision));
            yd_disk_reply_free(&reply);
            YDDiskReply read=yd_raft_cluster_query(clusters[leader],"GET",target,NULL,0,NULL,NULL,false,4000);
            ok=read.status==200;
            unsigned char expected[sizeof(source)];memcpy(expected,source,sizeof(source));
            char *count=strstr((char *)expected,"count: 0");
            if(count) count[7]=(unsigned char)('0'+(phase<2 ? 0 : phase-1));
            ok=ok && count && read.length==sizeof(source)-1 && !memcmp(read.body,expected,sizeof(source)-1);
            yd_disk_reply_free(&read);
            if(phase==1 || phase==2) {
                write=(YDRaftWrite){.id={0},.method="PATCH",.target=target,.body=patch,.size=sizeof(patch)-1};
                write.id[0]=(unsigned char)(phase+1);
                reply=yd_raft_cluster_write(clusters[leader],&write,4000);
                ok=ok && reply.status==200;yd_disk_reply_free(&reply);
            }
            if(!legacy) {
                YDRaftCompactionPolicy policy={.minimum_bytes=1,.minimum_saved_bytes=1,.interval_ms=100,.selection_attempts=1};
                compaction_refused=compaction_refused && !yd_raft_cluster_compactions(clusters[leader],policy);
            }
            if(!phase && ok) {
                YDRaftCheckpointPolicy policy={.entries=1,.interval_ms=100,.timeout_ms=2000};
                ok=yd_raft_cluster_checkpoints(clusters[leader],policy);
                for(unsigned n=0;n<300 && ok && !checkpointed;n++) {
                    checkpointed=yd_raft_cluster_status(clusters[leader]).checkpoints.succeeded>0;
                    if(!checkpointed) {struct timespec delay={.tv_nsec=10000000};nanosleep(&delay,NULL);}
                }
            }
        }
        for(unsigned i=0;i<3;i++) {yd_raft_cluster_close(clusters[i]);clusters[i]=NULL;}
        for(unsigned i=0;i<3 && ok;i++) {
            int root=open(journals[i],O_RDONLY|O_DIRECTORY|O_CLOEXEC);
            unsigned char now[256]={0};
            if(!legacy) {
                if(phase<2) {
                    YDRaftRetentionSessionRecord record;
                    ok=session(root,&record) && record.state==YD_RAFT_RETENTION_SESSION_CLEAN &&
                        record.epoch==phase+1;
                } else ok=session_bytes(root,now) && !memcmp(saved[i],now,256);
                if(phase==1) ok=ok && replace_record(root,YD_RAFT_RETENTION_SESSION_POISON);
                ok=ok && session_bytes(root,saved[i]);
            } else {struct stat st;ok=fstatat(root,YD_RAFT_RETENTION_SESSION_FILE,&st,AT_SYMLINK_NOFOLLOW)<0 && errno==ENOENT;}
            close(root);
        }
    }
    for(unsigned i=0;i<3;i++) {yd_raft_cluster_close(clusters[i]);yd_tls_free(tls[i]);}
    if(basefd>=0) close(basefd);
    int result=assertion(ok,"ACTUAL_CLUSTER_SERVICE_RESTART_YAML");
    if(!result) result=assertion(receipts,"ACTUAL_CLUSTER_RECEIPT_REISSUE");
    if(!result) result=assertion(checkpointed,"SAME_INODE_LOGICAL_CHECKPOINT_RECOVERS");
    if(!result) result=assertion(compaction_refused,"FENCED_COMPACTOR_REFUSES_CONFIGURATION");
    return result;
}
typedef struct {int probe;bool called,valid,excluded,masked,fault;} ArchiveProbe;
static bool archive_probe(YDRaftArchiveCut *cut,void *context) {
    ArchiveProbe *probe=context;
    probe->called=true;probe->valid=yd_raft_runtime_archive_cut_validate(cut);
    int prior;pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,&prior);
    probe->masked=prior==PTHREAD_CANCEL_DISABLE;pthread_setcancelstate(prior,NULL);
    struct flock lock={.l_type=F_RDLCK,.l_whence=SEEK_SET,.l_len=1};
    errno=0;
    int result=__real_fcntl(probe->probe,F_OFD_SETLK,&lock);
    probe->excluded=result<0 && (errno==EAGAIN || errno==EACCES);
    if(probe->fault) {
        archive_control_fault=true;
        bool valid=yd_raft_runtime_archive_cut_validate(cut);
        archive_control_fault=false;
        return valid;
    }
    return probe->valid && probe->excluded && probe->masked;
}
static int run_retention_probe(YDRaftRuntime *runtime,int root,const unsigned char target[32],
    ArchiveProbe *probe,bool application,char *error,size_t length) {
    if(!application) return yd_raft_runtime_archive_cut_run(runtime,root,target,archive_probe,probe,error,length);
    YDRaftApplicationCut *cut=NULL;
    application_fault_arm=probe->fault;
    int result=yd_raft_runtime_application_cut(runtime,root,target,&cut,error,length);
    application_fault_arm=false;archive_control_fault=false;
    if(result==1) {
        probe->called=cut!=NULL;probe->valid=cut!=NULL;
        struct flock lock={.l_type=F_RDLCK,.l_whence=SEEK_SET,.l_len=1};
        errno=0;
        probe->excluded=__real_fcntl(probe->probe,F_OFD_SETLK,&lock)<0 && (errno==EAGAIN || errno==EACCES);
        int prior;pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,&prior);
        probe->masked=prior==PTHREAD_CANCEL_DISABLE;pthread_setcancelstate(prior,NULL);
    }
    yd_raft_runtime_application_cut_close(cut);
    return result;
}
static int archive_lifecycle(YDRaftConfig *config,YDTLS *tls,int listener,const char *base) {
    char documents[4096],error[256]={0};
    snprintf(documents,sizeof(documents),"%s/documents",base);
    bool ok=!mkdir(documents,0700);
    YDRaftApplication *app=ok ? yd_raft_application_open(documents,config->cluster,32768,error,sizeof(error)) : NULL;
    ok=ok && app;yd_raft_application_close(app);
    int document_root=open(documents,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    const char *saved=case_name;
    const char *kind=strchr(saved,'-')+1;
    bool application=!strncmp(saved,"application-",12);
    bool observer=!strcmp(kind,"observer"),pin=!strcmp(kind,"pin");
    bool tracking=!strcmp(kind,"tracking"),faulting=!strcmp(kind,"control-fault");
    bool producer=!strcmp(kind,"producer");
    if(observer) case_name="escape-snapshot";
    if(pin) case_name="escape-pin";
    if(tracking) case_name="tracking";
    YDRaftRuntime *runtime=yd_raft_runtime_start_retaining(config,tls,listener,check,NULL,error,sizeof(error));
    case_name=saved;
    ok=ok && runtime && !mkdirat(watching_root,YD_RAFT_ARCHIVE_DIRECTORY,0700);
    ArchiveProbe probe={.probe=openat(watching_root,YD_RETENTION_FILE,O_RDWR|O_NOFOLLOW|O_CLOEXEC),.fault=faulting};
    unsigned char target[32]={9},before[256],after[256];
    ok=ok && runtime && document_root>=0 && probe.probe>=0 && session_bytes(watching_root,before);
    int producer_lease=-1;
    if(producer) ok=ok && yd_raft_runtime_archive_admit(runtime,&producer_lease);
    archive_phase=true;
    int result=runtime ? run_retention_probe(runtime,document_root,target,&probe,application,error,sizeof(error)) : -2;
    archive_phase=false;
    if(observer || pin || producer) {
        ok=ok && result==0 && !probe.called;
        if(producer_lease>=0) close(producer_lease);
        yd_disk_lineage_snapshot_close(escaped_snapshot);escaped_snapshot=NULL;
        yd_disk_lineage_release(escaped_lineage);escaped_lineage=NULL;
        yd_disk_close(escaped_pin);escaped_pin=NULL;
        archive_phase=true;
        result=run_retention_probe(runtime,document_root,target,&probe,application,error,sizeof(error));
        archive_phase=false;
    }
    if(tracking) ok=ok && result==-1 && !probe.called;
    else if(faulting) ok=ok && result==-1 && archive_control_seen &&
        (application ? !probe.called : probe.called && probe.valid && probe.excluded && probe.masked);
    else ok=ok && result==1 && probe.called && probe.valid && probe.excluded && probe.masked;
    ok=ok && session_bytes(watching_root,after) && !memcmp(before,after,256);
    yd_raft_runtime_stop(runtime);
    if(document_root>=0) close(document_root);
    if(probe.probe>=0) close(probe.probe);
    return assertion(ok,producer ? "ARCHIVE_PRODUCER_SHARED_ADMISSION_BLOCKS_CUT" :
        "ARCHIVE_CALLBACK_CUT_HOLDER_AND_FAILURE_CONTRACT");
}
static int lifecycle(YDRaftConfig *config,YDTLS *tls,int listener) {
    char error[256]={0};
    unsigned char active[256],held[256];
    watching=true;
    YDRaftRuntime *runtime=yd_raft_runtime_start_retaining(config,tls,listener,check,NULL,error,sizeof(error));
    watching=false;
    bool ok=runtime && yd_raft_runtime_drain(runtime) && session_bytes(watching_root,active);
    bool escaped=escaped_pin || escaped_roots || escaped_snapshot;
    if(ok && escaped) {
        int result=yd_raft_runtime_finalize(runtime,error,sizeof(error));
        ok=result==0 && session_bytes(watching_root,held) && !memcmp(active,held,256);
    }
    yd_disk_close(escaped_nested);escaped_nested=NULL;
    yd_disk_close(escaped_pin);escaped_pin=NULL;
    yd_disk_recovery_roots_close(escaped_roots);escaped_roots=NULL;
    yd_disk_lineage_snapshot_close(escaped_snapshot);escaped_snapshot=NULL;
    yd_disk_lineage_release(escaped_lineage);escaped_lineage=NULL;
    if(!ok) {
        yd_raft_runtime_stop(runtime);
        return assertion(false,"FINALIZE_HELD_VIEW_BACKPRESSURE_PRESERVES_ACTIVE");
    }
    if(!strncmp(case_name,"finalize-failed-clean-",22)) {
        failed_clean_mode=(unsigned)strtoul(case_name+22,NULL,10);
        int result=yd_raft_runtime_finalize(runtime,error,sizeof(error));
        failed_clean_mode=failed_clean_armed=0;
        ok=result==-1 && failed_clean_seen && session_bytes(watching_root,active);
        yd_raft_runtime_stop(runtime);
        runtime=yd_raft_runtime_start_retaining(config,tls,listener,check,NULL,error,sizeof(error));
        ok=ok && runtime && session_bytes(watching_root,held) && !memcmp(active,held,256) &&
            yd_raft_runtime_drain(runtime) && yd_raft_runtime_finalize(runtime,error,sizeof(error))==0;
        yd_raft_runtime_stop(runtime);
        return assertion(ok,"FAILED_CLEAN_NEVER_REENROLLS");
    }
    if(!strncmp(case_name,"finalize-fault-",15)) {
        unsigned boundary=(unsigned)strtoul(case_name+15,NULL,10);
        terminal_fault_at=boundary;
        int result=yd_raft_runtime_finalize(runtime,error,sizeof(error));
        terminal_fault_at=0;
        struct stat before,after;
        ok=result==-1 && terminal_fault_seen && session_bytes(watching_root,active) &&
            !fstatat(watching_root,YD_DISK_FILE,&before,AT_SYMLINK_NOFOLLOW);
        yd_raft_runtime_stop(runtime);
        ok=ok && session_bytes(watching_root,held) && !memcmp(active,held,256) &&
            !fstatat(watching_root,YD_DISK_FILE,&after,AT_SYMLINK_NOFOLLOW) &&
            before.st_dev==after.st_dev && before.st_ino==after.st_ino && before.st_size==after.st_size;
        runtime=yd_raft_runtime_start_retaining(config,tls,listener,check,NULL,error,sizeof(error));
        if(boundary<11) ok=ok && runtime && session_bytes(watching_root,held) &&
            !memcmp(active,held,256) && yd_raft_runtime_drain(runtime) &&
            yd_raft_runtime_finalize(runtime,error,sizeof(error))==0;
        else {
            /* Final intent-unlink sync is cleanup AFTER all safety proofs.
             * An absent marker safely permits the already-qualified CLEAN. */
            YDRaftRetentionSessionRecord resumed;
            ok=ok && runtime && session(watching_root,&resumed) &&
                resumed.state==YD_RAFT_RETENTION_SESSION_ACTIVE && resumed.epoch==2;
        }
        yd_raft_runtime_stop(runtime);
        return assertion(ok,"FINALIZE_FSYNC_FAILURE_PRESERVES_EXACT_ARTIFACTS");
    }
    int finalized=yd_raft_runtime_finalize(runtime,error,sizeof(error));
    YDRaftRetentionSessionRecord clean;
    ok=finalized==1 && session(watching_root,&clean) &&
        clean.state==YD_RAFT_RETENTION_SESSION_CLEAN && clean.epoch==1;
    if(!ok) fprintf(stderr,"LIFECYCLE_DETAIL:finalize=%d errno=%d %s\n",finalized,errno,error);
    yd_raft_runtime_stop(runtime);
    if(!ok) return assertion(false,"FINALIZE_CLEAN_AFTER_REAL_DRAIN");
    if(!strncmp(case_name,"finalize-marker-",16)) {
        const char *kind=case_name+16;
        const char *name=".yamora-retention-finalizing";
        bool io=!strcmp(kind,"io");
        if(!strcmp(kind,"directory")) ok=!mkdirat(watching_root,name,0700);
        else if(!strcmp(kind,"symlink")) ok=!symlinkat(YD_RAFT_RETENTION_SESSION_FILE,watching_root,name);
        else {
            int fd=openat(watching_root,name,O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC,0600);
            ok=fd>=0 && write(fd,"preserve intent",15)==15 && !fsync(fd);
            if(fd>=0) close(fd);
        }
        struct stat original,after;
        ok=ok && !fstatat(watching_root,name,&original,AT_SYMLINK_NOFOLLOW) &&
            session_bytes(watching_root,active);
        intent_stat_fault=io;watching=true;recovery_reads=0;
        runtime=yd_raft_runtime_start_retaining(config,tls,listener,check,NULL,error,sizeof(error));
        watching=false;intent_stat_fault=false;
        ok=ok && (io ? !runtime && intent_stat_seen && !recovery_reads : runtime!=NULL) &&
            session_bytes(watching_root,held) && !memcmp(active,held,256);
        if(runtime) ok=ok && yd_raft_runtime_drain(runtime) &&
            yd_raft_runtime_finalize(runtime,error,sizeof(error))==0;
        yd_raft_runtime_stop(runtime);
        ok=ok && !fstatat(watching_root,name,&after,AT_SYMLINK_NOFOLLOW) &&
            original.st_dev==after.st_dev && original.st_ino==after.st_ino &&
            original.st_mode==after.st_mode && original.st_size==after.st_size;
        return assertion(ok,"UNKNOWN_FINALIZATION_INTENT_PRESERVES_AND_VETOES_RESUME");
    }
    bool changed=!strcmp(case_name,"finalize-changed-tail");
    bool corrupt=!strcmp(case_name,"finalize-corrupt-slot");
    if(changed || corrupt) {
        int fd=openat(watching_root,YD_DISK_FILE,O_RDWR|O_NOFOLLOW|O_CLOEXEC);
        struct stat file;unsigned char byte=0;
        ok=fd>=0 && !fstat(fd,&file);
        off_t at=changed ? file.st_size : 60;
        if(corrupt) ok=ok && pread(fd,&byte,1,at)==1;
        byte^=1;
        ok=ok && pwrite(fd,&byte,1,at)==1 && !fsync(fd);
        if(fd>=0) close(fd);
        recovery_reads=0;registrations=0;watching=true;
        runtime=yd_raft_runtime_start_retaining(config,tls,listener,check,NULL,error,sizeof(error));
        watching=false;
        YDRaftRetentionSessionRecord observed;
        ok=ok && (changed ? runtime!=NULL : !runtime && !recovery_reads) &&
            session(watching_root,&observed) && !memcmp(&clean,&observed,sizeof(clean));
        yd_raft_runtime_stop(runtime);
        return assertion(ok,"CHANGED_TERMINAL_NEVER_MINTS_RESTART_EPOCH");
    }
    recovery_epoch=2;recovery_reads=0;registrations=0;read_ordered=false;
    /* Do not export a second held descendant during recovery. */
    const char *saved=case_name;case_name="resume";watching=true;
    runtime=yd_raft_runtime_start_retaining(config,tls,listener,check,NULL,error,sizeof(error));
    watching=false;case_name=saved;
    YDRaftRetentionSessionRecord resumed;
    ok=runtime && recovery_reads && read_ordered && session(watching_root,&resumed) &&
        resumed.state==YD_RAFT_RETENTION_SESSION_ACTIVE && resumed.epoch==2 &&
        memcmp(clean.nonce,resumed.nonce,sizeof(clean.nonce));
    if(!ok) fprintf(stderr,"LIFECYCLE_DETAIL:resume=%d reads=%u ordered=%d errno=%d %s\n",runtime!=NULL,recovery_reads,read_ordered,errno,error);
    if(runtime) {
        ok=ok && yd_raft_runtime_drain(runtime) &&
            yd_raft_runtime_finalize(runtime,error,sizeof(error))==1 &&
            session(watching_root,&resumed) && resumed.state==YD_RAFT_RETENTION_SESSION_CLEAN && resumed.epoch==2;
    }
    yd_raft_runtime_stop(runtime);
    return assertion(ok,"RESUME_ACTIVE_NEXT_EPOCH_BEFORE_FIRST_RECOVERY_READ");
}
int main(int argc, char **argv) {
    if (argc != 4) return 3;
    case_name=argv[3];
    char certificate[4096], key[4096], ca[4096], error[256] = {0};
    snprintf(certificate,sizeof(certificate),"%s/node1.pem",argv[2]);
    snprintf(key,sizeof(key),"%s/node1.key",argv[2]);
    snprintf(ca,sizeof(ca),"%s/ca.pem",argv[2]);
    YDTLS *tls = yd_tls_peer_new(certificate,key,ca,error,sizeof(error));
    int listeners[3] = {-1,-1,-1};
    char journal_root[4096];
    snprintf(journal_root,sizeof(journal_root),"%s/journal",argv[1]);
    YDRaftConfig config = {.journal_root=journal_root, .cluster={1,2,3,4},.node=1,.voters=3,
        .names={NULL,"node1.test","node2.test","node3.test"},
        .addresses={NULL,"127.0.0.1","127.0.0.1","127.0.0.1"},
        .timing={.heartbeat_ms=100,.election_min_ms=5000,.election_max_ms=8000,.rpc_ms=250},
        .cache_bytes=32768,.command_bytes=1024*1024};
    bool setup = tls != NULL && !mkdir(journal_root,0700);
    for (unsigned i=0; i<3 && setup; i++) {
        listeners[i] = socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0);
        struct sockaddr_in address={.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
        socklen_t size=sizeof(address);
        setup = listeners[i]>=0 && !bind(listeners[i],(void *)&address,size) &&
            !listen(listeners[i],8) && !getsockname(listeners[i],(void *)&address,&size);
        config.ports[i+1]=ntohs(address.sin_port);
    }
    if (!setup) { fprintf(stderr,"SETUP:%s\n",error); return 3; }
    if(!strcmp(case_name,"service") || !strcmp(case_name,"service-legacy")) {
        int result=service(argv[1],argv[2],config,listeners,!strcmp(case_name,"service-legacy"));
        for(unsigned i=0;i<3;i++) close(listeners[i]);
        yd_tls_free(tls);
        if(!result) printf("RUNTIME_OK:%s\n",case_name);
        return result;
    }
    int cancellation;
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,&cancellation);
    watching_root=open(journal_root,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    if(!strncmp(case_name,"finalize-",9) || !strncmp(case_name,"archive-",8) || !strncmp(case_name,"application-",12)) {
        int result=strncmp(case_name,"finalize-",9) ?
            archive_lifecycle(&config,tls,listeners[0],argv[1]) : lifecycle(&config,tls,listeners[0]);
        close(watching_root);
        for(unsigned i=0;i<3;i++) close(listeners[i]);
        yd_tls_free(tls);
        pthread_setcancelstate(cancellation,NULL);
        if(!result) printf("RUNTIME_OK:%s\n",case_name);
        return result;
    }
    bool legacy=!strcmp(case_name,"legacy");
    bool namespace=!strncmp(case_name,"namespace-",10);
    bool late_namespace=!strcmp(case_name,"namespace-race");
    bool real_observer_fault=!strcmp(case_name,"observer-pin-io") || !strncmp(case_name,"observer-hash-",14);
    bool malformed_birth=!strncmp(case_name,"birth-malformed-",16);
    if(legacy) {
        YDRaft *core=yd_raft_open(config.journal_root,config.cluster,1,3,32768,error,sizeof(error));
        setup=core!=NULL;
        yd_raft_close(core);
    }
    if(namespace && !late_namespace) {
        const char *name=case_name+10;
        int fd=openat(watching_root,name,O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC,0600);
        setup=fd>=0 && write(fd,"preserve",8)==8;
        if(fd>=0) close(fd);
    }
    if(!strncmp(case_name,"fault-",6)) fault=case_name+6;
    if(!strncmp(case_name,"register-",9)) register_fault=(unsigned)strtoul(case_name+9,NULL,10);
    bool allocation=!strncmp(case_name,"allocation-",11);
    bool after_recovery=!strcmp(case_name,"postcomplete") || !strcmp(case_name,"reject-check");
    bool expect_failure=namespace || fault || register_fault || allocation || after_recovery;
    bool cancellation_case=!strncmp(case_name,"cancel-",7);
    watching=true;
    YDRaftRuntime *runtime=NULL;
    bool cancel_ok=true;
    if(cancellation_case) {
        /* Case selection is passed to TLS explicitly by the worker below. */
        CancelJob job={.config=&config,.tls=tls,.listener=listeners[0],.root=watching_root,.name=case_name};
        char documents[4096];
        if(!strcmp(case_name,"cancel-cluster")) {
            snprintf(documents,sizeof(documents),"%s/documents",argv[1]);
            setup=!mkdir(documents,0700);
            job.documents=documents;
        }
        pthread_t thread;
        int created=pthread_create(&thread,NULL,cancel_start,&job);
        void *result=NULL;
        int joined=created ? created : pthread_join(thread,&result);
        setup=setup && !created && !joined;
        cancel_ok=!created && !joined && result==PTHREAD_CANCELED &&
            !job.returned && job.masked && job.seen && job.requested && job.released;
    } else runtime=yd_raft_runtime_start_retaining(&config,tls,listeners[0],check,NULL,error,sizeof(error));
    watching=false;
    bool started=runtime!=NULL;
    bool retained=true, copied=true, eligibility=true, preserved=true,cut_cancelled=true,cut_cleared=true;
    bool namespace_untouched=true, real_observer_refused=true, real_observer_bytes=true;
    if(runtime && (!strcmp(case_name,"copy") || !strcmp(case_name,"tracking") || !strcmp(case_name,"cut") || !strcmp(case_name,"cut-cancel"))) {
        if(!strcmp(case_name,"copy")) {
            mkdirat(watching_root,"candidate",0700);
            int destination=openat(watching_root,"candidate",O_RDONLY|O_DIRECTORY|O_CLOEXEC);
            YDRaftJournalCapture *capture=yd_raft_runtime_journal_capture(runtime,32768,error,sizeof(error));
            YDRaftJournalImage *image=yd_raft_journal_copy(capture,destination,32768,NULL,NULL,error,sizeof(error));
            copied=capture && !image && empty(destination);
            yd_raft_journal_image_close(image);yd_raft_journal_capture_close(capture);close(destination);
        } else {
            char documents[4096];snprintf(documents,sizeof(documents),"%s/documents",argv[1]);
            setup=!mkdir(documents,0700);
            YDRaftApplication *application=setup ? yd_raft_application_open(documents,config.cluster,32768,error,sizeof(error)) : NULL;
            setup=setup && application;
            yd_raft_application_close(application);
            int document_root=open(documents,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
            unsigned char target[32]={9};YDRaftApplicationCut *cut=NULL;
            if(!strcmp(case_name,"cut-cancel")) {
                CutJob job={.runtime=runtime,.root=document_root};pthread_t thread;void *result=NULL;
                int created=pthread_create(&thread,NULL,cancel_cut_start,&job);
                int joined=created ? created : pthread_join(thread,&result);
                setup=setup && !created && !joined;
                cut_cancelled=!created && !joined && result==PTHREAD_CANCELED && job.requested && !job.returned;
                cut_cleared=job.cleared;
            }
            int decision=yd_raft_runtime_application_cut(runtime,document_root,target,&cut,error,sizeof(error));
            eligibility=!strcmp(case_name,"tracking") ? decision==-1 && !cut : decision==1 && cut;
            yd_raft_runtime_application_cut_close(cut);
            if(document_root>=0) close(document_root);
        }
    }
    bool drain_ok=true;
    if(runtime && !strcmp(case_name,"drain")) {
        unsigned char before[256],after[256];
        drain_ok=session_bytes(watching_root,before) && yd_raft_runtime_drain(runtime) &&
            drain_started>0 && drain_finished==drain_started &&
            !yd_raft_runtime_journal_active(runtime) && yd_raft_runtime_drain(runtime) &&
            drain_finished==drain_started && session_bytes(watching_root,after) &&
            !memcmp(before,after,sizeof(before));
        YDRaftJournalCapture *late=yd_raft_runtime_journal_capture(runtime,32768,error,sizeof(error));
        drain_ok=drain_ok && !late;
        yd_raft_journal_capture_close(late);
        int native=openat(watching_root,YD_DISK_FILE,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
        errno=0;
        int claim=native<0 ? 0 : flock(native,LOCK_EX|LOCK_NB);
        drain_ok=drain_ok && native>=0 && claim<0 && (errno==EAGAIN || errno==EWOULDBLOCK);
        if(native>=0) close(native);
        if(!drain_ok) {
            (void)assertion(false,"DRAIN_JOINS_ALL_WORKERS_AND_RETAINS_ORIGIN");
            _Exit(2); /* A no-join mutant must not free live worker inputs. */
        }
    }
    yd_raft_runtime_stop(runtime);
    retained=release_escaped(watching_root);
    YDRaftRetentionSessionRecord record;
    bool active=session(watching_root,&record) && record.state==YD_RAFT_RETENTION_SESSION_ACTIVE;
    bool initial_read_ordered=read_ordered;
    if(!strcmp(case_name,"restart") || !strcmp(case_name,"poison") || !strcmp(case_name,"clean") ||
        !strcmp(case_name,"missing") || !strcmp(case_name,"partial") ||
        !strcmp(case_name,"busy") || !strcmp(case_name,"fifo") || !strcmp(case_name,"symlink") ||
        !strcmp(case_name,"directory") || !strcmp(case_name,"observer-io") || real_observer_fault || malformed_birth ||
        !strncmp(case_name,"preserve-escape-",16)) {
        if(!strcmp(case_name,"poison")) preserved=replace_record(watching_root,YD_RAFT_RETENTION_SESSION_POISON);
        if(!strcmp(case_name,"clean")) preserved=replace_record(watching_root,YD_RAFT_RETENTION_SESSION_CLEAN);
        if(!strcmp(case_name,"observer-io")) preserved=replace_record(watching_root,YD_RAFT_RETENTION_SESSION_CLEAN);
        if(real_observer_fault) preserved=replace_record(watching_root,YD_RAFT_RETENTION_SESSION_CLEAN);
        unsigned char invalid_birth[256]={0};
        if(malformed_birth) {
            int fd=openat(watching_root,YD_RAFT_RETENTION_BIRTH_FILE,O_RDWR|O_NOFOLLOW|O_CLOEXEC);
            setup=setup && fd>=0 && pread(fd,invalid_birth,256,0)==256;
            invalid_birth[!strcmp(case_name,"birth-malformed-format") ? 0 : 224]^=1;
            setup=setup && pwrite(fd,invalid_birth,256,0)==256 && !fsync(fd) && !fsync(watching_root);
            if(fd>=0) close(fd);
        }
        if(!strcmp(case_name,"missing")) preserved=!unlinkat(watching_root,YD_RAFT_RETENTION_SESSION_FILE,0);
        if(!strcmp(case_name,"partial")) {
            int fd=openat(watching_root,YD_RAFT_RETENTION_SESSION_FILE,O_WRONLY|O_TRUNC|O_CLOEXEC);
            preserved=fd>=0 && write(fd,"partial",7)==7;
            if(fd>=0) close(fd);
        }
        bool unsafe=!strcmp(case_name,"fifo") || !strcmp(case_name,"symlink") || !strcmp(case_name,"directory");
        if(unsafe) {
            preserved=!unlinkat(watching_root,YD_RAFT_RETENTION_SESSION_FILE,0);
            if(!strcmp(case_name,"fifo")) preserved=preserved && !mkfifoat(watching_root,YD_RAFT_RETENTION_SESSION_FILE,0600);
            else if(!strcmp(case_name,"symlink")) preserved=preserved && !symlinkat(YD_RAFT_RETENTION_BIRTH_FILE,watching_root,YD_RAFT_RETENTION_SESSION_FILE);
            else preserved=preserved && !mkdirat(watching_root,YD_RAFT_RETENTION_SESSION_FILE,0700);
        }
        int busy=-1;
        if(!strcmp(case_name,"busy")) {
            busy=openat(watching_root,YD_RAFT_RETENTION_SESSION_FILE,O_RDWR|O_CLOEXEC);
            struct flock lock={.l_type=F_WRLCK,.l_whence=SEEK_SET,.l_start=0,.l_len=1};
            preserved=preserved && busy>=0 && !fcntl(busy,F_OFD_SETLK,&lock);
        }
        unsigned char before[256]={0},after[256]={0};
        bool full=session_bytes(watching_root,before);
        recovery_reads=0; callback_seen=false; preserve_phase=true; watching=true;
        runtime=yd_raft_runtime_start_retaining(&config,tls,listeners[0],check,NULL,error,sizeof(error));
        watching=false;
        bool clean=!strcmp(case_name,"clean");
        bool refused=unsafe || busy>=0 || !strcmp(case_name,"observer-io") || real_observer_fault;
        if(real_observer_fault) real_observer_refused=!runtime && !callback_seen && !recovery_reads;
        preserved=preserved && (refused ? !runtime && !callback_seen && !recovery_reads : runtime!=NULL);
        (void)clean; /* A fabricated terminal fingerprint permits preserving service only. */
        if(runtime) {
            /* Use a valid independent application root: an invalid document
             * descriptor must not manufacture the expected authority refusal. */
            char documents[4096];snprintf(documents,sizeof(documents),"%s/documents",argv[1]);
            setup=setup && !mkdir(documents,0700);
            YDRaftApplication *application=setup ? yd_raft_application_open(documents,
                config.cluster,32768,error,sizeof(error)) : NULL;
            setup=setup && application;
            yd_raft_application_close(application);
            int document_root=open(documents,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
            setup=setup && document_root>=0;
            unsigned char target[32]={8};YDRaftApplicationCut *cut=NULL;
            eligibility=yd_raft_runtime_application_cut(runtime,document_root,target,&cut,error,sizeof(error))==-1 && !cut;
            yd_raft_runtime_application_cut_close(cut);
            if(document_root>=0) close(document_root);
        }
        yd_raft_runtime_stop(runtime);
        bool released=release_escaped(watching_root);
        retained=retained && released;
        if(busy>=0) close(busy);
        if(full) {
            bool same_session=session_bytes(watching_root,after) && !memcmp(before,after,256);
            preserved=preserved && same_session;
            if(real_observer_fault) real_observer_bytes=same_session;
        } else if(real_observer_fault) real_observer_bytes=false;
        if(malformed_birth) {
            int fd=openat(watching_root,YD_RAFT_RETENTION_BIRTH_FILE,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
            unsigned char bytes[257];
            preserved=preserved && fd>=0 && pread(fd,bytes,sizeof(bytes),0)==256 &&
                !memcmp(bytes,invalid_birth,256);
            if(fd>=0) close(fd);
        }
        if(!strcmp(case_name,"partial")) {
            int fd=openat(watching_root,YD_RAFT_RETENTION_SESSION_FILE,O_RDONLY|O_CLOEXEC);
            struct stat st;unsigned char bytes[8]={0};
            preserved=preserved && fd>=0 && !fstat(fd,&st) && st.st_size==7 &&
                read(fd,bytes,sizeof(bytes))==7 && !memcmp(bytes,"partial",7);
            if(fd>=0) close(fd);
        }
    }
    if(legacy) {
        struct stat status;
        preserved=fstatat(watching_root,YD_RETENTION_FILE,&status,AT_SYMLINK_NOFOLLOW)<0 && errno==ENOENT &&
            fstatat(watching_root,YD_RAFT_RETENTION_BIRTH_FILE,&status,AT_SYMLINK_NOFOLLOW)<0 && errno==ENOENT &&
            fstatat(watching_root,YD_RAFT_RETENTION_SESSION_FILE,&status,AT_SYMLINK_NOFOLLOW)<0 && errno==ENOENT;
    }
    if(namespace) {
        const char *original=late_namespace ? "unknown" : case_name+10;
        int fd=openat(watching_root,original,O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);
        char bytes[9]={0};struct stat st;
        preserved=fd>=0 && !fstat(fd,&st) && st.st_size==8 && read(fd,bytes,9)==8 && !memcmp(bytes,"preserve",8);
        if(fd>=0) close(fd);
        const char *names[]={YD_RETENTION_FILE,YD_RAFT_RETENTION_BIRTH_FILE,YD_RAFT_RETENTION_SESSION_FILE};
        for(unsigned i=0;i<3;i++) if(strcmp(names[i],original))
            namespace_untouched=namespace_untouched &&
                fstatat(watching_root,names[i],&st,AT_SYMLINK_NOFOLLOW)<0 && errno==ENOENT;
    }
    if(fault && failed_size) {
        const char *name=!strcmp(fault,"fence") ? YD_DISK_FILE :
            !strcmp(fault,"birth") ? YD_RAFT_RETENTION_BIRTH_FILE : YD_RAFT_RETENTION_SESSION_FILE;
        int fd=openat(watching_root,name,O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);
        unsigned char bytes[8192];
        preserved=fd>=0 && pread(fd,bytes,failed_size,0)==(ssize_t)failed_size &&
            !memcmp(bytes,failed_bytes,failed_size);
        if(fd>=0) close(fd);
    }
    if(allocation) {
        struct stat status;
        preserved=fstatat(watching_root,YD_DISK_FILE,&status,AT_SYMLINK_NOFOLLOW)<0 && errno==ENOENT;
    }
    if(after_recovery) preserved=active && excluded(watching_root,false);
    close(watching_root);
    for (unsigned i=0;i<3;i++) close(listeners[i]);
    yd_tls_free(tls);
    /* A broken cancellation injector must produce a named normal-exit failure,
     * not cancel main during its final restore and masquerade as ASAN/infra. */
    bool caller_uncancelled=!cancelled;
    if(caller_uncancelled) pthread_setcancelstate(cancellation,NULL);
    if(!setup) return 3;
    int result;
    if(cancellation_case) result=assertion(cancel_ok,"CANCEL_ADOPTION_OWNS_RUNTIME");
    else if(expect_failure) {
        result=late_namespace ? assertion(fault_hits==1,"EXACT_NAMESPACE_INJECTION_CONSUMED") : 0;
        if(!result && !namespace && strcmp(case_name,"reject-check")) result=assertion(fault_hits==1,"EXACT_FAULT_CONSUMED");
        if(!result && after_recovery) result=assertion(!started && recovery_seen && ordered &&
            (callback_seen == !strcmp(case_name,"reject-check")),"FAILURE_AFTER_RECOVERY_BEFORE_EXPOSURE");
        else if(!result) result=assertion(!started && !recovery_reads && !callback_seen,"FAILURE_BEFORE_RECOVERY_NO_FALLBACK");
        if(!result) result=assertion(preserved,"FAILED_PUBLICATION_PRESERVES_EXISTING_BYTES");
        if(!result) result=assertion(namespace_untouched,"NAMESPACE_REFUSAL_CREATES_NO_METADATA");
    } else {
        result=assertion(started,"START_SUCCEEDS");
        if(!result) result=assertion(drain_ok,"DRAIN_JOINS_ALL_WORKERS_AND_RETAINS_ORIGIN");
        if(!result && !legacy) result=assertion(recovery_seen && ordered && initial_read_ordered,"ACTIVE_AND_THREE_BINDINGS_BEFORE_RECOVERY");
        if(!result && !legacy) result=assertion(constructor_busy,"CONSTRUCTOR_SHARED_ADMISSION_BEFORE_RECOVERY");
        if(!result && !legacy) result=assertion(fence_before_active && active_sync && active_root_sync,"DURABLE_FENCES_BEFORE_ACTIVE_BEFORE_RECOVERY");
        if(!result && !legacy) result=assertion(active,"STOP_PRESERVES_ACTIVE");
        if(!result) result=assertion(mask_ok,"RECOVERY_CANCEL_MASKED");
        if(!result) result=assertion(retained,"ESCAPED_LAST_CLOSE_EXCLUSION");
        if(!result) result=assertion(copied,"COPY_REFUSES_BEFORE_DESTINATION_MUTATION");
        if(!result) result=assertion(publication_ok,"PUBLICATION_REFUSES_BEFORE_LINK_MUTATION");
        if(!result) result=assertion(caller_uncancelled,"CUT_CANCELLATION_ONLY_TARGET_THREAD");
        if(!result) result=assertion(cut_cancelled,"CANCELLED_CUT_CONTROL_REACHED");
        if(!result) result=assertion(cut_cleared,"CANCELLED_CUT_OUTPUT_CLEARED");
        if(!result && !strcmp(case_name,"observer-io")) result=assertion(fault_hits==1,"EXACT_OBSERVER_IO_CONSUMED");
        if(!result && real_observer_fault) result=assertion(fault_hits==1 &&
            (strcmp(case_name,"observer-pin-io") || real_pin_invalid),"REAL_OBSERVER_FAULT_CONSUMED");
        if(!result && real_observer_fault) result=assertion(real_observer_bytes,"REAL_OBSERVER_IO_PRESERVES_BYTES");
        if(!result && real_observer_fault) result=assertion(real_observer_refused,"REAL_OBSERVER_IO_REFUSES_CLEAN");
        if(!result && !strncmp(case_name,"observer-hash-",14))
            result=assertion(real_birth_result==YD_RAFT_RETENTION_BIRTH_IO,"BIRTH_DIGEST_FAILURE_IS_IO");
        if(!result) result=assertion(preserved,"PRESERVING_RESTART_POLICY");
        if(!result) result=assertion(eligibility,!strcmp(case_name,"cut") ?
            "FRESH_CUT_HAS_COMPLETE_CURRENT_COVERAGE" : !strcmp(case_name,"cut-cancel") ?
            "CANCELLED_CUT_RELEASES_EXCLUSION" : "NO_RESTART_OR_TRACKING_FAILURE_CUT_AUTHORITY");
    }
    if(!result) printf("RUNTIME_OK:%s\n",case_name);
    return result;
}
