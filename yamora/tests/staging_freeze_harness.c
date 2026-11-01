#define _POSIX_C_SOURCE 200809L
#include "disk_bulk.h"
#include "disk_index_build.h"
#include "disk_index_jobs.h"
#include "disk_internal.h"
#include "disk_replica.h"
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

static char error[512];
static const char source[] = "name: Alice\n";
static const char catalog[] =
    "{indexes: [{collection: people, name: name, fields: [name]}]}";
static const char token[] = "v1.00112233445566778899aabbccddeeff.0000000000000002";
#define CHECK(condition, label) do { if (!(condition)) { \
    fprintf(stderr, "INVARIANT:%s: %s\n", label, error); valid = false; goto done; \
} } while (0)

static bool document(YDDiskTxn *txn, const char *body) {
    YDDiskDocument old = {0}, fresh = {.body=(unsigned char *)body, .length=strlen(body)};
    strcpy(fresh.collection, "people"); strcpy(fresh.id, "alice");
    int found=yd_disk_document_tx_get(txn,"people","alice",&old,error,sizeof(error));
    bool valid=found>=0 && yd_disk_write_document(txn,found?&old:NULL,&fresh,error,sizeof(error));
    yd_disk_document_free(&old); return valid;
}
static bool body_at(YDDisk *disk,const YDDiskView *view,const char *body) {
    YDDiskDocument found={0};
    bool valid=yd_disk_document_get(disk,view,"people","alice",&found,error,sizeof(error))==1 &&
        found.length==strlen(body) && !memcmp(found.body,body,found.length);
    yd_disk_document_free(&found); return valid;
}
static bool index_at(YDDisk *disk,const YDDiskView *view) {
    YDDiskIndexes *indexes=yd_disk_indexes_load(disk,view,error,sizeof(error));
    bool valid=indexes && indexes->count==1 && !strcmp(indexes->indexes[0].name,"name") &&
        yd_disk_validate(disk,view,error,sizeof(error));
    yd_disk_indexes_free(indexes); return valid;
}
static bool staging(YDDisk *disk) {
    bool valid=true;
    YDDiskTxn *txn=NULL;
    YDDiskView public=yd_disk_view(disk), frozen={0}, later={0};
    txn=yd_disk_begin(disk,error,sizeof(error));
    CHECK(txn && !yd_disk_tx_freeze(txn,&frozen,error,sizeof(error)),
          "ordinary-transaction-cannot-freeze");
    yd_disk_abort(txn); txn=yd_disk_begin_staging(disk,error,sizeof(error));
    CHECK(txn && !yd_disk_tx_seal(txn,&frozen,error,sizeof(error)),
          "unlocked-staging-cannot-use-writer-held-seal");
    error[0]=0;
    CHECK(document(txn,"name: First private\n"),"stage-first-private-document");
    CHECK(yd_disk_tx_freeze(txn,&frozen,error,sizeof(error)),
          "exclusive-staging-freeze-must-succeed");
    CHECK(document(txn,"name: Second private\n") &&
          yd_disk_tx_freeze(txn,&later,error,sizeof(error)) &&
          body_at(disk,&frozen,"name: First private\n") &&
          body_at(disk,&later,"name: Second private\n") &&
          body_at(disk,&public,source),"frozen-private-root-remains-immutable-and-unpublished");
    yd_disk_abort(txn); txn=yd_disk_begin_exclusive(disk,error,sizeof(error));
    CHECK(txn && yd_disk_tx_seal(txn,&frozen,error,sizeof(error)),
          "writer-held-seal-remains-available");
done:
    yd_disk_abort(txn); return valid;
}
typedef struct {
    atomic_uint calls;
    YDDiskOutcome outcome;
    YDDiskView receipt;
    bool has_receipt;
} Terminal;
static bool terminal(void *context,YDDiskOutcome outcome,const YDDiskView *receipt) {
    Terminal *state=context;
    state->outcome=outcome; state->has_receipt=receipt!=NULL;
    if (receipt) state->receipt=*receipt;
    atomic_fetch_add(&state->calls,1);
    return true;
}
static bool job(YDDisk *disk) {
    bool valid=true, transferred=false;
    Terminal *state=calloc(1,sizeof(*state));
    struct YDDiskIndexJobs *jobs=yd_disk_index_jobs_new(disk);
    YDDiskReply reply={0};
    YDValue *parsed=NULL;
    CHECK(state && jobs,"job-fixture-allocation");
    atomic_init(&state->calls,0);
    reply=yd_disk_index_jobs_request_with_job(jobs,false,"POST","/v1/index-builds",
        (const unsigned char *)catalog,strlen(catalog),NULL,NULL,terminal,state,&transferred);
    CHECK(reply.status==202 && transferred,"standalone-job-adopts-terminal-owner");
    yd_disk_reply_free(&reply);
    for (unsigned attempt=0;attempt<1000;attempt++) {
        reply=yd_disk_index_jobs_request(jobs,false,"GET","/v1/index-builds",NULL,0,NULL,NULL);
        CHECK(reply.status==200,"standalone-job-status-remains-readable");
        parsed=yd_parse((const unsigned char *)reply.body,reply.length,error,sizeof(error));
        const YDValue *status=parsed?yd_get(parsed,"status"):NULL;
        CHECK(status && status->type==YD_STRING,"standalone-job-status-shape");
        if (strcmp(status->scalar,"running")) break;
        yd_free(parsed); parsed=NULL; yd_disk_reply_free(&reply);
        struct timespec pause={.tv_nsec=10000000}; nanosleep(&pause,NULL);
    }
    const YDValue *status=parsed?yd_get(parsed,"status"):NULL;
    if (!status || strcmp(status->scalar,"succeeded"))
        fprintf(stderr,"JOB_RESULT %.*s\n",(int)reply.length,reply.body?reply.body:"");
    CHECK(status && !strcmp(status->scalar,"succeeded"),
          "standalone-index-job-must-publish");
    YDDiskView published=yd_disk_view(disk);
    char revision[17]; yd_disk_revision(&published,revision);
    const YDValue *returned=yd_get(parsed,"revision");
    CHECK(atomic_load(&state->calls)==1 && state->outcome==YD_DISK_OUTCOME_RETURNED_SUCCESS &&
        state->has_receipt && state->receipt.root==published.root &&
        state->receipt.generation==published.generation && returned && returned->type==YD_STRING &&
        !strcmp(returned->scalar,revision) && index_at(disk,&published),
        "standalone-job-finishes-original-intent-once-with-published-receipt");
done:
    yd_free(parsed); yd_disk_reply_free(&reply);
    yd_disk_index_jobs_free(jobs); free(state); return valid;
}
static YDDiskReply request(YDDiskAPI *api,const char *action,const char *body) {
    char path[128]; snprintf(path,sizeof(path),"/v1/replication/%s",action);
    return yd_disk_api_request(api,"POST",path,(const unsigned char *)body,strlen(body),NULL,NULL,false);
}
static bool replica(YDDisk *disk) {
    bool valid=true, initialized=false;
    YDDiskAPI api={0}; YDDiskReply reply={0}; YDValue *parsed=NULL;
    YDDiskTxn *txn=yd_disk_begin_exclusive(disk,error,sizeof(error));
    CHECK(txn && yd_disk_indexes_replace(txn,(const unsigned char *)catalog,strlen(catalog),
        error,sizeof(error)),"replica-seed-catalog");
    bool committed=yd_disk_commit(txn,error,sizeof(error)); txn=NULL;
    CHECK(committed,"replica-seed-publication");
    YDDiskView before=yd_disk_view(disk);
    CHECK(yd_disk_api_init(&api,disk,true),"replica-api-init"); initialized=true;
    char body[1024],session[48];
    snprintf(body,sizeof(body),
        "{\"revision\":\"%016llx\",\"collections\":[\"people\",\"yamldb-system\"],"
        "\"full\":true,\"revision_scheme\":\"xor-fnv-v2\",\"source_after\":\"%s\"}",
        (unsigned long long)before.revision,token);
    reply=request(&api,"begin",body);
    CHECK(reply.status==200,"replica-full-begin");
    parsed=yd_parse((const unsigned char *)reply.body,reply.length,error,sizeof(error));
    const YDValue *value=parsed?yd_get(parsed,"session"):NULL;
    CHECK(value && value->type==YD_STRING && strlen(value->scalar)<sizeof(session),"replica-session");
    strcpy(session,value->scalar);
    yd_free(parsed); parsed=NULL; yd_disk_reply_free(&reply);
    snprintf(body,sizeof(body),
        "{\"session\":\"%s\",\"operations\":[{\"collection\":\"people\",\"document\":\"alice\","
        "\"put\":\"name: Alice\\n\"},{\"collection\":\"yamldb-system\",\"document\":\"indexes\","
        "\"put\":\"%s\"}]}",session,catalog);
    reply=request(&api,"apply",body);
    CHECK(reply.status==200,"replica-full-apply"); yd_disk_reply_free(&reply);
    YDDiskView unpublished=yd_disk_view(disk);
    CHECK(unpublished.root==before.root && unpublished.generation==before.generation,
          "replica-staging-remains-unpublished-before-commit");
    snprintf(body,sizeof(body),"{\"session\":\"%s\"}",session);
    reply=request(&api,"commit",body);
    if (reply.status!=200) fprintf(stderr,"REPLICA_COMMIT status=%d body=%.*s\n",
        reply.status,(int)reply.length,reply.body?reply.body:"");
    CHECK(reply.status==200,"replicated-index-publication-must-succeed");
    YDDiskView after=yd_disk_view(disk);
    YDDiskReplicaPosition checkpoint;
    CHECK(after.generation==before.generation+1 && after.revision==before.revision &&
        index_at(disk,&after) && body_at(disk,&after,source) &&
        yd_disk_replica_position(disk,&after,&checkpoint,error,sizeof(error))==1 &&
        !strcmp(checkpoint.after,token),"replica-catalog-data-checkpoint-publish-atomically");
done:
    yd_disk_abort(txn); yd_free(parsed); yd_disk_reply_free(&reply);
    if(initialized) yd_disk_api_destroy(&api);
    return valid;
}
int main(int argc,char **argv) {
    if(argc!=3 || mkdir(argv[1],0700)) return 2;
    YDDisk *disk=yd_disk_open(argv[1],true,32768,error,sizeof(error));
    if(!disk) {fprintf(stderr,"SETUP:%s\n",error);return 2;}
    YDDiskTxn *txn=yd_disk_begin(disk,error,sizeof(error));
    YDWrite write={.collection="people",.document="alice",
        .body=(const unsigned char *)source,.length=sizeof(source)-1};
    bool valid=txn && yd_disk_apply(txn,&write,1,error,sizeof(error));
    if(valid) valid=yd_disk_commit(txn,error,sizeof(error)); else yd_disk_abort(txn);
    if(!valid) {yd_disk_close(disk);return 2;}
    error[0]=0;
    valid=!strcmp(argv[2],"staging")?staging(disk):
        !strcmp(argv[2],"job")?job(disk):!strcmp(argv[2],"replica")?replica(disk):false;
    yd_disk_close(disk);
    if(valid) {
        disk=yd_disk_open(argv[1],false,32768,error,sizeof(error));
        YDDiskView persisted=disk?yd_disk_view(disk):(YDDiskView){0};
        valid=disk && yd_disk_validate(disk,&persisted,error,sizeof(error)) &&
            body_at(disk,&persisted,source);
        yd_disk_close(disk);
        if(!valid) fprintf(stderr,"INVARIANT:reopened-publication-remains-valid: %s\n",error);
    }
    if(valid) printf("staging boundary verified: %s\n",argv[2]);
    return valid?0:1;
}
