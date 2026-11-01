#define _POSIX_C_SOURCE 200809L
#include "../src/consensus/runtime.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
static _Thread_local bool cancelling_configuration;
static atomic_bool cancellation_waiting;
int __real_pthread_cond_timedwait(pthread_cond_t *, pthread_mutex_t *, const struct timespec *);
int __wrap_pthread_cond_timedwait(pthread_cond_t *condition, pthread_mutex_t *mutex,
    const struct timespec *until) {
    if (cancelling_configuration) atomic_store(&cancellation_waiting, true);
    return __real_pthread_cond_timedwait(condition, mutex, until);
}
typedef struct { YDRaftRuntime *runtime; uint16_t voters; unsigned timeout; } Cancellation;
static void *cancel_configuration(void *context) {
    Cancellation *request = context;
    YDRaftMembership membership;
    cancelling_configuration = true;
    (void)yd_raft_runtime_reconfigure(request->runtime, request->voters,
        request->timeout, &membership);
    return NULL;
}
int main(int argc,char **argv) {
    if(argc!=10)return 2;
    unsigned node=(unsigned)strtoul(argv[3],NULL,10);
    char cert[4096],key[4096],ca[4096],error[256];
    snprintf(cert,sizeof(cert),"%s/node%u.pem",argv[2],node);
    snprintf(key,sizeof(key),"%s/node%u.key",argv[2],node);
    snprintf(ca,sizeof(ca),"%s/trusted.pem",argv[2]);
    YDTLS *tls=yd_tls_peer_new(cert,key,ca,error,sizeof(error));
    YDRaftConfig c={.journal_root=argv[1],.cluster={1,2,3,4},.node=node,.voters=5,
        .initial_voters=14,.names={NULL,"node1.test","node2.test","node3.test","node4.test","node5.test"},
        .addresses={NULL,"127.0.0.1","127.0.0.1","127.0.0.1","127.0.0.1","127.0.0.1"},
        .timing={50,1200,2200,400},.cache_bytes=32768,.command_bytes=1048576};
    for(unsigned i=1;i<=5;i++)c.ports[i]=(uint16_t)strtoul(argv[4+i],NULL,10);
    int fd=(int)strtol(argv[4],NULL,10);
    YDRaftRuntime *r=tls?yd_raft_runtime_start(&c,tls,fd,error,sizeof(error)):NULL;
    if(!r){fprintf(stderr,"start: %s\n",error);yd_tls_free(tls);return 2;}
    setvbuf(stdout,NULL,_IOLBF,0);puts("ready");
    char line[256];
    while(fgets(line,sizeof(line),stdin)) {
        if(!strncmp(line,"quit",4))break;
        unsigned mask,timeout;unsigned long long at;
        if(!strncmp(line,"status",6)) {
            YDRaftStatus s=yd_raft_runtime_status(r);YDRaftMembership m=yd_raft_runtime_membership(r);
            printf("%u %u %llu %llu %llu %u %u %u %u\n",s.role,s.node,
                (unsigned long long)s.term,(unsigned long long)s.last,(unsigned long long)s.committed,
                m.old_voters,m.new_voters,m.retired_voters,m.joint);
        } else if(sscanf(line,"cancel-config %u %u",&mask,&timeout)==2) {
            Cancellation request = {r, (uint16_t)mask, timeout};
            pthread_t caller; void *result = NULL;
            atomic_store(&cancellation_waiting, false);
            bool valid = !pthread_create(&caller, NULL, cancel_configuration, &request);
            if (valid) {
                for (unsigned i=0;i<5000&&!atomic_load(&cancellation_waiting);i++) {
                    struct timespec delay = {.tv_nsec=1000000}; nanosleep(&delay,NULL);
                }
                valid = atomic_load(&cancellation_waiting) && !pthread_cancel(caller);
                valid = !pthread_join(caller,&result) && valid && result==PTHREAD_CANCELED;
            }
            printf("cancelled %u\n",valid);
        } else if(sscanf(line,"reconfigure %u %u",&mask,&timeout)==2) {
            YDRaftMembership m;int result=yd_raft_runtime_reconfigure(r,(uint16_t)mask,timeout,&m);
            printf("%d %u %u %u %u\n",result,m.old_voters,m.new_voters,m.retired_voters,m.joint);
        } else if(sscanf(line,"barrier %u",&timeout)==1) {
            uint64_t term,index;bool ok=yd_raft_runtime_barrier(r,timeout,&term,&index);
            printf("%u %llu %llu\n",ok,(unsigned long long)term,(unsigned long long)index);
        } else if(!strncmp(line,"propose ",8)) {
            line[strcspn(line,"\n")]=0;uint64_t index;
            bool ok=yd_raft_runtime_propose(r,line+8,strlen(line+8),&index);
            printf("%u %llu\n",ok,(unsigned long long)index);
        } else if(sscanf(line,"entry %llu",&at)==1) {
            YDRaftEntry e;bool ok=yd_raft_runtime_entry(r,(uint64_t)at,&e);
            if(ok){printf("%u %.*s\n",e.kind,(int)e.size,e.size?(const char*)e.command:"");
                yd_raft_entry_free(&e);}else puts("missing");
        } else puts("invalid");
    }
    yd_raft_runtime_stop(r);yd_tls_free(tls);close(fd);return 0;
}
