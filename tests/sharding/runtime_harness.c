#define _POSIX_C_SOURCE 200809L
#include "../../src/sharding/runtime.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr,"FAIL %s:%d: %s\n",__FILE__,__LINE__,#x); exit(2); } } while(0)
static const unsigned char placement[] =
    "{version: 1, key_version: 1, algorithm: sha256-64be-v1, "
    "placement_id: '0123456789abcdef0123456789abcdef', collection: records, "
    "field: tenant, epoch: 1, ranges: ["
    "{first: '0000000000000000', last: '7fffffffffffffff', shard: a, group: ga},"
    "{first: '8000000000000000', last: 'ffffffffffffffff', shard: b, group: gb}]}";
static const char *identity="0123456789abcdef0123456789abcdef";
static bool allowed=true;
static size_t calls=0;
static int die_rpc=-1;
static bool die_commit=false;
typedef struct {YDDisk *disks[5];YDShardControl *control,*replica;YDShardNative *native[3];YDShardBinding bindings[3];YDShardRouter router;} Cluster;
static const char *denied=NULL;
static long rpc_delay_ms=0;
static bool auth(void *ctx,const char *collection,bool write) {(void)ctx;(void)write;
    if(!allowed||(denied&&!strcmp(collection,denied)))return false;
    return !strcmp(collection,"records")||!strcmp(collection,"users")||!strcmp(collection,"orders")||!strcmp(collection,"empty");}
static bool stop(void *ctx) {return calls>=*(size_t*)ctx;}
static YDShardStatus rpc(void *ctx,const YDShardRequest *q,YDShardResponse *out) {
    calls++;
    if(rpc_delay_ms){struct timespec pause={0,rpc_delay_ms*1000000L};nanosleep(&pause,NULL);}
    YDShardStatus s=yd_shard_native_call(ctx,q,out);
    if(s==YD_SHARD_OK&&(int)q->operation==die_rpc)_Exit(71);
    return s;
}
static YDShardStatus commit(void *ctx,const unsigned char *b,size_t n) {
    Cluster *c=ctx;
    YDShardStatus a=yd_shard_control_apply(c->control,b,n),d=yd_shard_control_apply(c->replica,b,n);
    CHECK(a==d);
    if(a==YD_SHARD_OK&&die_commit)_Exit(72);
    return a;
}
static void open_cluster(Cluster *c,const char *root) {
    memset(c,0,sizeof(*c));
    const char *names[]={"control","replica","ga","gb","gc"};
    for(size_t i=0;i<5;i++) {
        char path[2048],error[256];snprintf(path,sizeof(path),"%s/%s",root,names[i]);
        (void)mkdir(path,0700);
        /* Room for the feed retention test's 4,104 single-write commits. */
        c->disks[i]=yd_disk_open_limited(path,true,1024*1024,1024ULL*1024U*1024U,error,sizeof(error));
        if(!c->disks[i])fprintf(stderr,"disk: %s\n",error);
        CHECK(c->disks[i]);
    }
    c->control=yd_shard_control_open(c->disks[0]);c->replica=yd_shard_control_open(c->disks[1]);
    CHECK(c->control&&c->replica);
    for(size_t i=0;i<3;i++) {
        c->native[i]=yd_shard_native_open(c->disks[i+2],names[i+2],c->control);CHECK(c->native[i]);
        c->bindings[i]=(YDShardBinding){.group=names[i+2],.call=rpc,.context=c->native[i]};
    }
    c->router=(YDShardRouter){.control=c->control,.bindings=c->bindings,.binding_count=3,.authorize=auth,.commit=commit,.commit_context=c};
}
static void close_cluster(Cluster *c) {
    for(size_t i=0;i<3;i++)yd_shard_native_close(c->native[i]);
    yd_shard_control_close(c->control);yd_shard_control_close(c->replica);
    for(size_t i=0;i<5;i++)yd_disk_close(c->disks[i]);
}
static YDShardKey integer_key(unsigned i) {
    char number[32];snprintf(number,sizeof(number),"%u",i);
    YDValue value={.type=YD_INT,.scalar=number};YDShardKey key;CHECK(yd_shard_key_encode(&value,&key)==YD_SHARD_OK);return key;
}
static uint64_t epoch(Cluster *c) {return yd_shard_placement_epoch(yd_shard_control_placement(c->control));}
static YDShardStatus put_document(Cluster *c,unsigned i,const char *id,const char *source,const char *mutation) {
    YDShardKey key=integer_key(i);YDShardResponse response;
    YDShardStatus s=yd_shard_route(&c->router,identity,"records",epoch(c),YD_SHARD_RPC_WRITE,&key,id,(const unsigned char*)source,strlen(source),mutation,&response);
    yd_shard_page_free(&response.page);return s;
}
static void seed(Cluster *c) {
    unsigned char *command=NULL;size_t length=0;
    CHECK(yd_shard_control_install(c->control,placement,sizeof(placement)-1,&command,&length)==YD_SHARD_OK);
    CHECK(commit(c,command,length)==YD_SHARD_OK);CHECK(commit(c,command,length)==YD_SHARD_OK);
    unsigned char *bad=malloc(length);CHECK(bad);memcpy(bad,command,length);bad[4]^=1;
    /* An identical final state is an idempotent receipt even after hash damage;
     * a changed state or out-of-order transition cannot be accepted. */
    bad[length-1]^=1;CHECK(yd_shard_control_apply(c->control,bad,length)!=YD_SHARD_OK);free(bad);free(command);
    for(unsigned i=0;i<320;i++) {
        char source[128],id[32],mutation[32];snprintf(source,sizeof(source),"# exact source %u\r\ntenant: %u\r\nscore: %u\r\ncategory: %s\r\nprice: %u\r\n",i,i,i%7,i%2?"b":"a",i%2?5:3);
        snprintf(id,sizeof(id),"row-%04u",i);snprintf(mutation,sizeof(mutation),"seed-%u",i);
        CHECK(put_document(c,i,id,source,mutation)==YD_SHARD_OK);
        CHECK(put_document(c,i,id,source,mutation)==YD_SHARD_OK);
        CHECK(put_document(c,i,id,"tenant: 1",mutation)!=YD_SHARD_OK);
    }
    const char *fields[]={"tenant","email"};
    CHECK(yd_shard_unique_index(yd_shard_control_placement(c->control),fields,2,false)==YD_SHARD_OK);
    CHECK(yd_shard_unique_index(yd_shard_control_placement(c->control),fields+1,1,false)==YD_SHARD_CROSS_SHARD_UNSUPPORTED);
    CHECK(yd_shard_unique_index(yd_shard_control_placement(c->control),fields,2,true)==YD_SHARD_CROSS_SHARD_UNSUPPORTED);
}
static YDShardQuery query(void) {return (YDShardQuery){.sort_field="score",.offset=11,.limit=37,.max_rows=1000,.max_bytes=1024*1024};}
static void verify(Cluster *c) {
    YDShardQuery q=query();YDShardResult result;
    CHECK(yd_shard_gather(&c->router,identity,"records",epoch(c),&q,&result)==YD_SHARD_OK);
    CHECK(result.matched==320&&result.visited==320&&result.shards==2&&result.page.count==37);
    unsigned expected[320],n=0;
    for(unsigned score=0;score<7;score++)for(unsigned i=0;i<320;i++)if(i%7==score)expected[n++]=i;
    for(size_t j=0;j<37;j++) {
        unsigned i=expected[j+11];char source[128],id[32];snprintf(source,sizeof(source),"# exact source %u\r\ntenant: %u\r\nscore: %u\r\ncategory: %s\r\nprice: %u\r\n",i,i,i%7,i%2?"b":"a",i%2?5:3);snprintf(id,sizeof(id),"row-%04u",i);
        CHECK(!strcmp(result.page.rows[j].id,id));CHECK(result.page.rows[j].length==strlen(source));CHECK(!memcmp(result.page.rows[j].source,source,strlen(source)));
    }
    size_t explain_size=0;char *explain=yd_shard_explain_json(&q,&result,&explain_size);
    CHECK(explain);YDValue *e=yd_parse((unsigned char*)explain,explain_size,NULL,0);
    CHECK(e&&yd_get(e,"visited")->number==320&&!yd_get(e,"global_snapshot")->boolean);yd_free(e);free(explain);
    yd_shard_page_free(&result.page);
    q.max_rows=17;CHECK(yd_shard_gather(&c->router,identity,"records",epoch(c),&q,&result)==YD_SHARD_BUDGET_EXCEEDED);CHECK(!result.page.rows&&!result.matched);
    q=query();allowed=false;calls=0;CHECK(yd_shard_gather(&c->router,identity,"records",epoch(c),&q,&result)==YD_SHARD_FORBIDDEN);CHECK(!calls);allowed=true;
    CHECK(yd_shard_gather(&c->router,identity,"records",epoch(c)+1,&q,&result)==YD_SHARD_STALE_PLACEMENT);
    calls=0;size_t after=1;c->router.cancelled=stop;c->router.cancel_context=&after;
    CHECK(yd_shard_gather(&c->router,identity,"records",epoch(c),&q,&result)==YD_SHARD_CANCELLED);CHECK(!result.page.rows);
    c->router.cancelled=NULL;c->router.cancel_context=NULL;
    YDShardBinding broken[3];memcpy(broken,c->bindings,sizeof(broken));
    /* Migration can replace either original group; withdraw every trusted binding. */
    for(size_t i=0;i<3;i++)broken[i].group="untrusted-host";
    c->router.bindings=broken;
    CHECK(yd_shard_gather(&c->router,identity,"records",epoch(c),&q,&result)==YD_SHARD_UNAVAILABLE);CHECK(!result.page.rows&&!result.matched);c->router.bindings=c->bindings;
    const char pipeline_text[]="[{$group: {_id: $category, total: {$sum: $price}}}, {$sort: {_id: 1}}]";
    YDValue *pipeline=yd_parse((const unsigned char*)pipeline_text,sizeof(pipeline_text)-1,NULL,0);CHECK(pipeline);char *json=NULL,error[256];size_t size;
    CHECK(yd_shard_aggregate(&c->router,identity,"records",epoch(c),pipeline,1000,1024*1024,&json,&size,error,sizeof(error))==YD_SHARD_OK);
    YDValue *value=yd_parse((unsigned char*)json,size,NULL,0);CHECK(value&&value->type==YD_ARRAY&&value->count==2);CHECK(yd_get(value->items[0],"total")->number==480);CHECK(yd_get(value->items[1],"total")->number==800);free(json);yd_free(value);yd_free(pipeline);
}
static void stable_cursor(Cluster *c) {
    YDShardQuery q=query();YDShardCursor *cursor=NULL;CHECK(yd_shard_cursor_open(&c->router,identity,"records",epoch(c),&q,&cursor)==YD_SHARD_OK);
    CHECK(put_document(c,319,"row-0319","tenant: 319\nscore: 999\ncategory: b\nprice: 5\n","cursor-edit")==YD_SHARD_OK);
    unsigned expected[320],count=0;for(unsigned score=0;score<7;score++)for(unsigned i=0;i<320;i++)if(i%7==score)expected[count++]=i;
    size_t position=0;bool end=false;
    while(!end){YDShardResult page;allowed=false;CHECK(yd_shard_cursor_next(cursor,25,8192,&page)==YD_SHARD_FORBIDDEN);allowed=true;
        CHECK(yd_shard_cursor_next(cursor,25,8192,&page)==YD_SHARD_OK);end=page.page.end;
        for(size_t j=0;j<page.page.count;j++){char id[32];snprintf(id,sizeof(id),"row-%04u",expected[position++]);CHECK(!strcmp(page.page.rows[j].id,id));}
        yd_shard_page_free(&page.page);
    }
    CHECK(position==320);yd_shard_cursor_close(cursor);
    const char *original="# exact source 319\r\ntenant: 319\r\nscore: 4\r\ncategory: b\r\nprice: 5\r\n";
    CHECK(put_document(c,319,"row-0319",original,"cursor-restore")==YD_SHARD_OK);
    puts("immutable cursor pages survive later writes and enforce per-page authorization passed");
}
static void native_validation(Cluster *c) {
    const char *foreign[]={"\001yamora-schema-profile","\001yamora-raft-identity","\001yamora-application"};
    for(size_t i=0;i<3;i++)CHECK(yd_shard_control_key(foreign[i],strlen(foreign[i]))==0);
    const char *malformed="\001yamora-shard-control-v2";
    CHECK(yd_shard_control_key(malformed,strlen(malformed))==-1);
    for(size_t d=0;d<5;d++){
        YDDiskView view=yd_disk_view(c->disks[d]);unsigned char start=1;YDDiskCursor *cursor=yd_disk_cursor(c->disks[d],&view,&start,1,false,NULL,0);CHECK(cursor);
        for(;;){unsigned char key[1024];size_t kn;uint64_t offset;int found=yd_disk_next(cursor,key,sizeof(key),&kn,&offset,NULL,0);CHECK(found>=0);if(!found)break;
            int control=yd_shard_control_key(key,kn),native=yd_shard_native_key(key,kn);CHECK(control==1||native==1);size_t size;unsigned char *bytes=yd_disk_record(c->disks[d],&view,offset,&size,NULL,0);CHECK(bytes);
            CHECK(control==1?yd_shard_control_validate_record(key,kn,bytes,size):yd_shard_native_validate_record(key,kn,bytes,size));free(bytes);
        }
        yd_disk_cursor_free(cursor);
    }
    const char *bad="\001YS/active/a/path";CHECK(yd_shard_native_key(bad,strlen(bad))==-1);
    size_t size;unsigned char *state=yd_shard_control_export(c->control,&size);CHECK(state);YDShardControl *imported=yd_shard_control_import(state,size);CHECK(imported);
    CHECK(yd_shard_placement_epoch(yd_shard_control_placement(imported))==epoch(c));CHECK(yd_shard_control_refresh(imported)==YD_SHARD_INVALID_ARGUMENT);yd_shard_control_close(imported);free(state);
}
static void prepared_transactions(Cluster *c) {
    const YDShardPlacement *p=yd_shard_control_placement(c->control);YDShardKey key=integer_key(7);YDShardPlan plan;
    CHECK(yd_shard_plan_keys(p,identity,"records",epoch(c),YD_SHARD_WRITE,&key,1,&plan)==YD_SHARD_OK);
    YDShardRange range;CHECK(yd_shard_placement_range(p,!strcmp(plan.shard,"a")?0:1,&range));size_t group=!strcmp(plan.group,"ga")?0:1;
    const unsigned char source[]="tenant: 7\nscore: 7\n";
    YDShardRequest request={.operation=YD_SHARD_RPC_WRITE,.placement=p,.range=range,.key=&key,.id="prepared",.source=source,.length=sizeof(source)-1,.mutation_id="prepared-1"};
    YDDiskView before=yd_disk_view(c->disks[group+2]);YDShardResponse response;YDDiskTxn *txn=NULL;
    CHECK(yd_shard_native_prepare_at(c->native[group],&before,&request,&response,&txn)==YD_SHARD_OK&&txn);yd_disk_abort(txn);
    CHECK(yd_disk_view(c->disks[group+2]).generation==before.generation);
    CHECK(yd_shard_native_prepare_at(c->native[group],&before,&request,&response,&txn)==YD_SHARD_OK&&txn);CHECK(yd_disk_commit(txn,NULL,0));
    request.operation=YD_SHARD_RPC_READ;request.source=NULL;request.length=0;
    CHECK(yd_shard_native_call_at(c->native[group],&before,&request,&response)==YD_SHARD_OK&&!response.page.count);yd_shard_page_free(&response.page);
    CHECK(yd_shard_native_call(c->native[group],&request,&response)==YD_SHARD_OK&&response.page.count==1);yd_shard_page_free(&response.page);
    request.operation=YD_SHARD_RPC_WRITE;request.source=source;request.length=sizeof(source)-1;
    CHECK(yd_shard_native_prepare_at(c->native[group],&before,&request,&response,&txn)==YD_SHARD_CONFLICT&&!txn);
    YDDiskView current=yd_disk_view(c->disks[group+2]);CHECK(yd_shard_native_prepare_at(c->native[group],&current,&request,&response,&txn)==YD_SHARD_OK&&txn);yd_disk_abort(txn);
    CHECK(yd_shard_route(&c->router,identity,"records",epoch(c),YD_SHARD_RPC_DELETE,&key,"prepared",NULL,0,"prepared-delete",&response)==YD_SHARD_OK);
    YDShardKey other;unsigned candidate=8;YDShardPlan other_plan;
    do {other=integer_key(candidate++);CHECK(yd_shard_plan_keys(p,identity,"records",epoch(c),YD_SHARD_WRITE,&other,1,&other_plan)==YD_SHARD_OK);} while(strcmp(other_plan.shard,plan.shard));
    CHECK(yd_shard_route(&c->router,identity,"records",epoch(c),YD_SHARD_RPC_DELETE,&other,"prepared",NULL,0,"prepared-delete",&response)==YD_SHARD_CONFLICT);
    unsigned char *command=NULL;size_t size;
    CHECK(yd_shard_control_begin(c->control,"a","gc","33333333333333333333333333333333",&command,&size)==YD_SHARD_OK);
    txn=yd_disk_begin(c->disks[0],NULL,0);CHECK(txn);CHECK(yd_shard_control_stage(c->control,command,size,txn)==YD_SHARD_OK);CHECK(yd_shard_control_migration(c->control).phase==YD_SHARD_IDLE);yd_disk_abort(txn);free(command);
    CHECK(yd_shard_control_refresh(c->control)==YD_SHARD_OK&&yd_shard_control_migration(c->control).phase==YD_SHARD_IDLE);
    puts("exact captured views and uncommitted control/data transaction preparation passed");
}
static void begin(Cluster *c) {
    unsigned char *command=NULL;size_t length;
    CHECK(yd_shard_control_begin(c->control,"a","gc","11111111111111111111111111111111",&command,&length)==YD_SHARD_OK);
    CHECK(commit(c,command,length)==YD_SHARD_OK);free(command);
}
/* A command can pass the remote control read and then wait behind FREEZE in
 * the destination's apply queue. The persisted local fence must reject it. */
static void delayed_owner_commands(const char *root) {
    char path[2048];snprintf(path,sizeof(path),"%s/ownership",root);CHECK(!mkdir(path,0700));
    Cluster c;open_cluster(&c,path);
    unsigned char *command=NULL;size_t length;
    CHECK(yd_shard_control_install(c.control,placement,sizeof(placement)-1,&command,&length)==YD_SHARD_OK);
    CHECK(commit(&c,command,length)==YD_SHARD_OK);free(command);
    unsigned char *old=yd_shard_control_export(c.control,&length);CHECK(old);
    YDShardControl *stale=yd_shard_control_import(old,length);free(old);CHECK(stale);
    const YDShardPlacement *p=yd_shard_control_placement(stale);
    YDShardRange range;CHECK(yd_shard_placement_range(p,0,&range));
    unsigned selected=0;YDShardKey key;YDShardPlan plan;
    do {key=integer_key(selected++);CHECK(yd_shard_plan_keys(p,identity,"records",1,YD_SHARD_WRITE,&key,1,&plan)==YD_SHARD_OK);} while(strcmp(plan.shard,"a"));
    char source[64];snprintf(source,sizeof(source),"tenant: %u\n",selected-1);
    CHECK(put_document(&c,selected-1,"before",source,"before")==YD_SHARD_OK);
    YDShardNative *delayed=yd_shard_native_open(c.disks[2],"ga",stale);CHECK(delayed);
    YDShardRequest q={.operation=YD_SHARD_RPC_WRITE,.placement=p,.range=range,.key=&key,.id="late",.source=(unsigned char*)source,.length=strlen(source),.mutation_id="late"};
    YDShardResponse out;
    begin(&c);
    old=yd_shard_control_export(c.control,&length);CHECK(old);
    YDShardControl *fenced=yd_shard_control_import(old,length);free(old);CHECK(fenced);
    YDShardNative *delayed_freeze=yd_shard_native_open(c.disks[2],"ga",fenced);CHECK(delayed_freeze);
    YDShardRequest freeze_request={.operation=YD_SHARD_RPC_FREEZE,.placement=yd_shard_control_placement(fenced),.range=range,.migration=yd_shard_control_migration(fenced)};
    CHECK(yd_shard_migrate_step(&c.router)==YD_SHARD_OK);
    CHECK(yd_shard_native_call(delayed,&q,&out)==YD_SHARD_MIGRATING);
    /* The durable fence also applies before an exact old receipt replay. */
    q.id="before";q.mutation_id="before";
    CHECK(yd_shard_native_call(delayed,&q,&out)==YD_SHARD_MIGRATING);
    for(unsigned i=0;yd_shard_control_migration(c.control).phase!=YD_SHARD_IDLE;i++){CHECK(i<20);CHECK(yd_shard_migrate_step(&c.router)==YD_SHARD_OK);}
    CHECK(yd_shard_control_begin(c.control,"a","ga","44444444444444444444444444444444",&command,&length)==YD_SHARD_OK);
    CHECK(commit(&c,command,length)==YD_SHARD_OK);free(command);
    for(unsigned i=0;yd_shard_control_migration(c.control).phase!=YD_SHARD_IDLE;i++){CHECK(i<20);CHECK(yd_shard_migrate_step(&c.router)==YD_SHARD_OK);}
    CHECK(yd_shard_native_call(delayed,&q,&out)==YD_SHARD_STALE_PLACEMENT);
    q.operation=YD_SHARD_RPC_READ;
    CHECK(yd_shard_native_call(delayed,&q,&out)==YD_SHARD_STALE_PLACEMENT);
    q.operation=YD_SHARD_RPC_SCAN;q.after="";q.max_rows=128;q.max_bytes=YD_SHARD_PAGE_BYTES;
    CHECK(yd_shard_native_call(delayed,&q,&out)==YD_SHARD_STALE_PLACEMENT);
    CHECK(yd_shard_native_call(delayed_freeze,&freeze_request,&out)==YD_SHARD_STALE_PLACEMENT);
    CHECK(put_document(&c,selected-1,"after",source,"after")==YD_SHARD_OK);
    yd_shard_native_close(delayed_freeze);yd_shard_control_close(fenced);
    yd_shard_native_close(delayed);yd_shard_control_close(stale);native_validation(&c);close_cluster(&c);
    puts("durable ownership fencing rejects delayed commands and old receipt replay across round-trip migration passed");
}
static void logical_freeze_layouts(const char *root) {
    char base[2048],other_path[2048],restored_path[2048],error[256];
    snprintf(base,sizeof(base),"%s/logical-freeze",root);CHECK(!mkdir(base,0700));
    snprintf(other_path,sizeof(other_path),"%s/layout-other",root);CHECK(!mkdir(other_path,0700));
    snprintf(restored_path,sizeof(restored_path),"%s/layout-restored",root);CHECK(!mkdir(restored_path,0700));
    Cluster c;open_cluster(&c,base);unsigned char *command=NULL;size_t size;
    CHECK(yd_shard_control_install(c.control,placement,sizeof(placement)-1,&command,&size)==YD_SHARD_OK);
    CHECK(commit(&c,command,size)==YD_SHARD_OK);free(command);
    unsigned selected=0;YDShardKey key;YDShardPlan plan;
    do {key=integer_key(selected++);CHECK(yd_shard_plan_keys(yd_shard_control_placement(c.control),identity,"records",1,YD_SHARD_WRITE,&key,1,&plan)==YD_SHARD_OK);} while(strcmp(plan.shard,"a"));
    char source[128];snprintf(source,sizeof(source),"tenant: %u\ncount: 17\n",selected-1);
    CHECK(put_document(&c,selected-1,"before",source,"before")==YD_SHARD_OK);
    YDDisk *other=yd_disk_open(other_path,true,32768,error,sizeof(error));CHECK(other);
    YDDiskTxn *tx=yd_disk_begin(other,NULL,0);CHECK(tx);uint64_t offset;
    CHECK(yd_disk_append(tx,"padding",7,&offset,NULL,0)&&yd_disk_put(tx,"padding",7,offset,NULL,0));CHECK(yd_disk_commit(tx,NULL,0));
    YDShardNative *native=yd_shard_native_open(other,"ga",c.control);CHECK(native);
    YDShardRange range;CHECK(yd_shard_placement_range(yd_shard_control_placement(c.control),0,&range));
    YDShardResponse response;
    YDShardRequest q={.operation=YD_SHARD_RPC_WRITE,.placement=yd_shard_control_placement(c.control),.range=range,.key=&key,.id="before",.source=(const unsigned char*)source,.length=strlen(source),.mutation_id="before"};
    CHECK(yd_shard_native_call(native,&q,&response)==YD_SHARD_OK);
    CHECK(yd_disk_view(other).generation!=yd_disk_view(c.disks[2]).generation);
    begin(&c);q=(YDShardRequest){.operation=YD_SHARD_RPC_FREEZE,.placement=yd_shard_control_placement(c.control),.range=range,.migration=yd_shard_control_migration(c.control)};
    CHECK(yd_shard_native_call(native,&q,&response)==YD_SHARD_OK);char snapshot[65];strcpy(snapshot,response.snapshot);
    CHECK(yd_shard_migrate_step(&c.router)==YD_SHARD_OK);
    CHECK(!strcmp(snapshot,yd_shard_control_migration(c.control).snapshot));
    yd_shard_native_close(native);yd_disk_close(other);
    other=yd_disk_open(other_path,true,32768,error,sizeof(error));CHECK(other);
    /* Rebuild every logical record at fresh offsets, as application snapshot
     * installation does. No old physical root/token is retained. */
    YDDisk *restored=yd_disk_open(restored_path,true,32768,error,sizeof(error));CHECK(restored);
    YDDiskView view=yd_disk_view(other);unsigned char start=0;
    YDDiskCursor *cursor=yd_disk_cursor(other,&view,&start,1,false,NULL,0);CHECK(cursor);
    tx=yd_disk_begin(restored,NULL,0);CHECK(tx);
    for(;;){unsigned char record_key[1024];size_t kn,length;uint64_t old;
        int found=yd_disk_next(cursor,record_key,sizeof(record_key),&kn,&old,NULL,0);CHECK(found>=0);if(!found)break;
        unsigned char *bytes=yd_disk_record(other,&view,old,&length,NULL,0);CHECK(bytes);
        CHECK(yd_disk_append(tx,bytes,length,&offset,NULL,0)&&yd_disk_put(tx,record_key,kn,offset,NULL,0));free(bytes);
    }
    yd_disk_cursor_free(cursor);CHECK(yd_disk_commit(tx,NULL,0));CHECK(yd_disk_view(restored).generation!=view.generation);
    yd_disk_close(restored);yd_disk_close(other);
    restored=yd_disk_open(restored_path,true,32768,error,sizeof(error));CHECK(restored);
    native=yd_shard_native_open(restored,"ga",c.control);CHECK(native);
    q=(YDShardRequest){.operation=YD_SHARD_RPC_SCAN,.placement=yd_shard_control_placement(c.control),.range=range,.migration=yd_shard_control_migration(c.control),.after="",.snapshot="",.max_rows=128,.max_bytes=YD_SHARD_PAGE_BYTES};
    CHECK(yd_shard_native_call(native,&q,&response)==YD_SHARD_OK&&response.page.count==1&&response.page.end);
    CHECK(!strcmp(response.snapshot,snapshot)&&response.page.rows[0].length==strlen(source)&&!memcmp(response.page.rows[0].source,source,strlen(source)));
    yd_shard_page_free(&response.page);yd_shard_native_close(native);yd_disk_close(restored);close_cluster(&c);
    puts("logical freeze identity across distinct layouts, logical rebuild and reopen passed");
}
static void migrate_crashes(const char *root) {
    Cluster c;open_cluster(&c,root);begin(&c);close_cluster(&c);
    int crashes=0;bool killed[10]={0};
    for(unsigned step=0;step<30;step++) {
        open_cluster(&c,root);YDShardMigration m=yd_shard_control_migration(c.control);
        if(m.phase!=YD_SHARD_ACTIVATING)verify(&c);
        if(m.phase==YD_SHARD_IDLE){CHECK(epoch(&c)==2);close_cluster(&c);break;}
        YDShardKey key;unsigned selected=0;YDShardPlan plan;
        do{key=integer_key(selected++);CHECK(yd_shard_plan_keys(yd_shard_control_placement(c.control),identity,"records",epoch(&c),YD_SHARD_WRITE,&key,1,&plan)==YD_SHARD_OK);}while(strcmp(plan.shard,"a"));
        YDShardResponse out;CHECK(yd_shard_route(&c.router,identity,"records",epoch(&c),YD_SHARD_RPC_DELETE,&key,"row-0000",NULL,0,"blocked",&out)==YD_SHARD_MIGRATING);
        int operation=m.phase==YD_SHARD_FENCING?YD_SHARD_RPC_FREEZE:m.phase==YD_SHARD_COPYING?(m.copied?YD_SHARD_RPC_SEAL:YD_SHARD_RPC_STAGE):m.phase==YD_SHARD_ACTIVATING?YD_SHARD_RPC_ACTIVATE:-1;
        bool crash=operation>=0&&!killed[operation];if(crash)killed[operation]=true;
        close_cluster(&c);
        pid_t child=fork();CHECK(child>=0);
        if(!child){open_cluster(&c,root);die_rpc=crash?operation:-1;YDShardStatus s=yd_shard_migrate_step(&c.router);CHECK(s==YD_SHARD_OK);close_cluster(&c);_Exit(0);}
        int status;CHECK(waitpid(child,&status,0)==child&&WIFEXITED(status));CHECK(WEXITSTATUS(status)==(crash?71:0));if(crash)crashes++;
    }
    CHECK(crashes==4);open_cluster(&c,root);CHECK(yd_shard_control_migration(c.control).phase==YD_SHARD_IDLE);CHECK(epoch(&c)==2);verify(&c);
    /* Stale source cannot accept a public write after ownership cutover. */
    YDShardRange range;CHECK(yd_shard_placement_range(yd_shard_control_placement(c.control),0,&range));
    YDShardRequest stale={.operation=YD_SHARD_RPC_DELETE,.placement=yd_shard_control_placement(c.control),.range=range,.id="row-0000",.mutation_id="stale"};YDShardResponse response;
    CHECK(yd_shard_native_call(c.native[0],&stale,&response)==YD_SHARD_STALE_PLACEMENT);
    close_cluster(&c);puts("crash-safe migration: four durable RPC cut points, full reopen, single ownership passed");
}
static void migrate_control_crashes(const char *root) {
    Cluster c;open_cluster(&c,root);unsigned char *command=NULL;size_t length;
    CHECK(yd_shard_control_begin(c.control,"b","ga","22222222222222222222222222222222",&command,&length)==YD_SHARD_OK);
    CHECK(commit(&c,command,length)==YD_SHARD_OK);free(command);close_cluster(&c);
    unsigned crashes=0;
    for(unsigned step=0;step<20;step++) {
        open_cluster(&c,root);YDShardMigration m=yd_shard_control_migration(c.control);
        if(m.phase==YD_SHARD_IDLE){CHECK(epoch(&c)==3);verify(&c);close_cluster(&c);break;}
        if(m.phase!=YD_SHARD_ACTIVATING)verify(&c);
        close_cluster(&c);pid_t child=fork();CHECK(child>=0);
        if(!child){open_cluster(&c,root);die_commit=true;CHECK(yd_shard_migrate_step(&c.router)==YD_SHARD_OK);_Exit(3);}
        int status;CHECK(waitpid(child,&status,0)==child&&WIFEXITED(status)&&WEXITSTATUS(status)==72);crashes++;
    }
    CHECK(crashes>=5);open_cluster(&c,root);CHECK(epoch(&c)==3);CHECK(yd_shard_control_migration(c.control).phase==YD_SHARD_IDLE);verify(&c);
    CHECK(yd_shard_control_begin(c.control,"a","gb","11111111111111111111111111111111",&command,&length)==YD_SHARD_OK);
    CHECK(commit(&c,command,length)==YD_SHARD_CONFLICT);free(command);close_cluster(&c);
    puts("control publication crash/restart at every migration phase and reused identity rejection passed");
}
/* Further sharded collections share the control namespace and group disks. */
static const unsigned char users_placement[] =
    "{version: 2, key_version: 1, algorithm: sha256-64be-v1, "
    "placement_id: '1123456789abcdef0123456789abcdef', collection: users, "
    "field: user, epoch: 1, ranges: ["
    "{first: '0000000000000000', last: '7fffffffffffffff', shard: u1, group: ga},"
    "{first: '8000000000000000', last: 'ffffffffffffffff', shard: u2, group: gb}]}";
static const unsigned char orders_placement[] =
    "{version: 2, key_version: 2, algorithm: sha256-64be-v1, "
    "placement_id: '2123456789abcdef0123456789abcdef', collection: orders, "
    "field: [tenant, order], epoch: 1, ranges: ["
    "{first: '0000000000000000', last: '7fffffffffffffff', shard: o1, group: ga},"
    "{first: '8000000000000000', last: 'ffffffffffffffff', shard: o2, group: gb}]}";
static const char *orders_id="2123456789abcdef0123456789abcdef";
typedef struct {YDShardControl *control,*replica;YDShardNative *native[3];YDShardBinding bindings[3];YDShardRouter router;} Side;
static YDShardStatus side_commit(void *ctx,const unsigned char *b,size_t n) {
    Side *s=ctx;YDShardStatus a=yd_shard_control_apply(s->control,b,n),d=yd_shard_control_apply(s->replica,b,n);
    CHECK(a==d);if(a==YD_SHARD_OK&&die_commit)_Exit(72);return a;
}
static void open_side(Cluster *c,Side *s,const char *collection) {
    const char *names[]={"ga","gb","gc"};memset(s,0,sizeof(*s));
    s->control=yd_shard_control_open_collection(c->disks[0],collection);s->replica=yd_shard_control_open_collection(c->disks[1],collection);
    CHECK(s->control&&s->replica);
    for(size_t i=0;i<3;i++){s->native[i]=yd_shard_native_open(c->disks[i+2],names[i],s->control);CHECK(s->native[i]);
        s->bindings[i]=(YDShardBinding){.group=names[i],.call=rpc,.context=s->native[i]};}
    s->router=(YDShardRouter){.control=s->control,.bindings=s->bindings,.binding_count=3,.authorize=auth,.commit=side_commit,.commit_context=s};
}
static void close_side(Side *s){for(size_t i=0;i<3;i++)yd_shard_native_close(s->native[i]);yd_shard_control_close(s->control);yd_shard_control_close(s->replica);}
static YDShardStatus install_side(Side *s,const unsigned char *metadata,size_t n){unsigned char *command=NULL;size_t length=0;
    YDShardStatus st=yd_shard_control_install(s->control,metadata,n,&command,&length);
    if(st==YD_SHARD_OK){st=side_commit(s,command,length);}
    free(command);return st;}
static uint64_t side_epoch(Side *s){return yd_shard_placement_epoch(yd_shard_control_placement(s->control));}
static YDShardStatus side_route(Side *s,YDShardRPC op,const YDShardKey *key,const char *id,const char *source,const char *mutation,size_t *rows){
    const YDShardPlacement *p=yd_shard_control_placement(s->control);YDShardResponse response;
    YDShardStatus st=yd_shard_route(&s->router,yd_shard_placement_id(p),yd_shard_placement_collection(p),side_epoch(s),op,key,id,
        (const unsigned char*)source,source?strlen(source):0,mutation,&response);
    if(rows){*rows=response.page.count;}
    yd_shard_page_free(&response.page);return st;}
static YDShardKey text_key(const char *text){YDValue v={.type=YD_STRING,.scalar=(char*)text};YDShardKey k;CHECK(yd_shard_key_encode(&v,&k)==YD_SHARD_OK);return k;}
static YDShardKey order_key(unsigned tenant,unsigned order){char t[16],o[16];snprintf(t,sizeof(t),"%u",tenant);snprintf(o,sizeof(o),"o-%u",order);
    YDValue a={.type=YD_INT,.scalar=t},b={.type=YD_STRING,.scalar=o};const YDValue *parts[]={&a,&b};YDShardKey k;
    CHECK(yd_shard_compound_key_encode(parts,2,&k)==YD_SHARD_OK);return k;}
typedef struct {Side *users,*orders;} Foreigners;
static unsigned released=0;
static YDShardStatus resolve_side(void *ctx,const char *collection,YDShardRouter **out){Foreigners *f=ctx;*out=NULL;
    if(!strcmp(collection,"users")){*out=&f->users->router;return YD_SHARD_OK;}
    if(!strcmp(collection,"orders")){*out=&f->orders->router;return YD_SHARD_OK;}
    return YD_SHARD_CROSS_SHARD_UNSUPPORTED;}
static void release_side(void *ctx,YDShardRouter *r){(void)ctx;(void)r;released++;}
static char *join_run(Cluster *c,const char *text,const YDShardJoinLimits *limits,YDShardJoinStats *stats,YDShardStatus expected){
    YDValue *pipeline=yd_parse((const unsigned char*)text,strlen(text),NULL,0);CHECK(pipeline);char *json=(char*)1,error[256]="";size_t size=7;
    YDShardStatus st=yd_shard_aggregate_join(&c->router,identity,"records",epoch(c),pipeline,limits,&json,&size,stats,error,sizeof(error));
    if(st!=expected)fprintf(stderr,"join %s: %s (%s)\n",text,yd_shard_status_name(st),error);
    CHECK(st==expected);if(st!=YD_SHARD_OK)CHECK(!json&&!size);yd_free(pipeline);return json;}
static void orders_verify(Side *s){
    YDShardQuery q={.limit=100,.max_rows=100,.max_bytes=1024*1024};YDShardResult result;
    CHECK(yd_shard_gather(&s->router,orders_id,"orders",side_epoch(s),&q,&result)==YD_SHARD_OK&&result.matched==12&&result.page.count==12);
    for(unsigned j=0;j<12;j++){char id[32];snprintf(id,sizeof(id),"order-%02u",j);CHECK(!strcmp(result.page.rows[j].id,id));
        YDShardKey key=order_key(j%4,j);size_t rows=0;CHECK(side_route(s,YD_SHARD_RPC_READ,&key,id,NULL,NULL,&rows)==YD_SHARD_OK&&rows==1);}
    yd_shard_page_free(&result.page);
}
static const char *user_shard(Side *users,unsigned k){static char shard[64];char name[32];snprintf(name,sizeof(name),"user-%u",k);
    YDShardKey key=text_key(name);YDShardPlan plan;const YDShardPlacement *p=yd_shard_control_placement(users->control);
    CHECK(yd_shard_plan_keys(p,yd_shard_placement_id(p),"users",side_epoch(users),YD_SHARD_READ,&key,1,&plan)==YD_SHARD_OK);
    strcpy(shard,plan.shard);return shard;}
static void joins(const char *root) {
    char path[2048];snprintf(path,sizeof(path),"%s/joins",root);CHECK(!mkdir(path,0700));
    Cluster c;open_cluster(&c,path);Side users,orders,dupes;unsigned char *command=NULL;size_t length;
    CHECK(yd_shard_control_install(c.control,placement,sizeof(placement)-1,&command,&length)==YD_SHARD_OK);
    CHECK(commit(&c,command,length)==YD_SHARD_OK);free(command);
    open_side(&c,&users,"users");open_side(&c,&orders,"orders");open_side(&c,&dupes,"dupes");
    CHECK(install_side(&users,users_placement,sizeof(users_placement)-1)==YD_SHARD_OK);
    CHECK(install_side(&users,users_placement,sizeof(users_placement)-1)==YD_SHARD_CONFLICT);
    CHECK(install_side(&orders,orders_placement,sizeof(orders_placement)-1)==YD_SHARD_OK);
    /* Native data keys omit the collection, so a reused shard name is refused. */
    static const unsigned char dupe_placement[]="{version: 1, key_version: 1, algorithm: sha256-64be-v1, "
        "placement_id: '3123456789abcdef0123456789abcdef', collection: dupes, field: k, epoch: 1, "
        "ranges: [{first: '0000000000000000', last: 'ffffffffffffffff', shard: u2, group: gc}]}";
    CHECK(install_side(&dupes,dupe_placement,sizeof(dupe_placement)-1)==YD_SHARD_CONFLICT);
    CHECK(!yd_shard_control_placement(dupes.control));close_side(&dupes);
    /* The first collection keeps the original record; the others are named. */
    YDShardControl *legacy=yd_shard_control_open(c.disks[0]);CHECK(legacy&&!strcmp(yd_shard_placement_collection(yd_shard_control_placement(legacy)),"records"));yd_shard_control_close(legacy);
    unsigned in_u1=0;
    for(unsigned k=0;k<10;k++){char id[16],name[16],source[96];snprintf(id,sizeof(id),"u-%u",k);snprintf(name,sizeof(name),"user-%u",k);
        snprintf(source,sizeof(source),"user: user-%u\nalias: user-%u\nname: N%u\n",k,k,k);YDShardKey key=text_key(name);
        CHECK(side_route(&users,YD_SHARD_RPC_WRITE,&key,id,source,id,NULL)==YD_SHARD_OK);in_u1+=!strcmp(user_shard(&users,k),"u1");}
    CHECK(in_u1>0&&in_u1<10);
    YDShardKey three=text_key("user-3");
    CHECK(side_route(&users,YD_SHARD_RPC_WRITE,&three,"u-3b","user: user-3\nalias: user-3\nname: N3b\n","u-3b",NULL)==YD_SHARD_OK);
    unsigned expected_u1=0;
    for(unsigned i=0;i<40;i++){char id[32],source[160],mutation[32];snprintf(id,sizeof(id),"rec-%02u",i);snprintf(mutation,sizeof(mutation),"rec-%u",i);
        if(i==36)snprintf(source,sizeof(source),"tenant: %u\nbucket: none\n",i);
        else if(i==37)snprintf(source,sizeof(source),"tenant: %u\nowner: null\nbucket: none\n",i);
        else{const char *shard=user_shard(&users,i%10);expected_u1+=!strcmp(shard,"u1");snprintf(source,sizeof(source),"tenant: %u\nowner: user-%u\nbucket: %s\n",i,i%10,shard);}
        CHECK(put_document(&c,i,id,source,mutation)==YD_SHARD_OK);}
    for(unsigned j=0;j<12;j++){char id[32],source[96];snprintf(id,sizeof(id),"order-%02u",j);snprintf(source,sizeof(source),"tenant: %u\norder: o-%u\nuser: user-%u\n",j%4,j,j%10);
        YDShardKey key=order_key(j%4,j);CHECK(side_route(&orders,YD_SHARD_RPC_WRITE,&key,id,source,id,NULL)==YD_SHARD_OK);}
    /* Compound keys route reads/writes and refuse a key that does not match. */
    orders_verify(&orders);
    YDShardKey wrong=order_key(2,5),flat=text_key("o-5");
    CHECK(side_route(&orders,YD_SHARD_RPC_WRITE,&wrong,"order-05","tenant: 1\norder: o-5\n","bad-key",NULL)==YD_SHARD_KEY_CHANGE_UNSUPPORTED);
    CHECK(side_route(&orders,YD_SHARD_RPC_WRITE,&flat,"order-05","tenant: 1\norder: o-5\n","flat-key",NULL)==YD_SHARD_INVALID_KEY);
    YDShardKey right=order_key(1,5);
    CHECK(side_route(&orders,YD_SHARD_RPC_WRITE,&right,"order-05","tenant: 1\norder: o-6\n","changed",NULL)==YD_SHARD_KEY_CHANGE_UNSUPPORTED);
    puts("multi-collection control namespace, shard-name isolation and compound-key routing passed");

    Foreigners foreign={&users,&orders};
    c.router.resolve=resolve_side;c.router.release=release_side;c.router.resolve_context=&foreign;
    YDShardJoinLimits limits={.max_rows=1000,.max_bytes=1024*1024,.max_foreign_rows=1000,.max_foreign_bytes=1024*1024,.max_matches=1024,.max_time_ms=10000};
    YDShardJoinStats stats;
    const char *targeted="[{$match: {bucket: u1}}, {$lookup: {from: users, localField: owner, foreignField: user, as: who}}, {$sort: {tenant: 1}}]";
    char *first=join_run(&c,targeted,&limits,&stats,YD_SHARD_OK);
    CHECK(stats.relations==1&&stats.relation[0].targeted&&!stats.relation[0].local&&stats.relation[0].shards==1&&stats.relation[0].ranges==2);
    CHECK(stats.input_rows==40&&stats.input_shards==2);
    YDValue *rows=yd_parse((unsigned char*)first,strlen(first),NULL,0);CHECK(rows&&rows->type==YD_ARRAY&&rows->count==expected_u1);
    for(size_t i=0;i<rows->count;i++){const char *owner=yd_get(rows->items[i],"owner")->scalar;const YDValue *who=yd_get(rows->items[i],"who");
        CHECK(who&&who->type==YD_ARRAY&&who->count==(strcmp(owner,"user-3")?1U:2U));CHECK(!strcmp(yd_get(who->items[0],"user")->scalar,owner));
        if(who->count==2)CHECK(!strcmp(yd_get(who->items[1],"name")->scalar,"N3b"));}
    yd_free(rows);
    char *again=join_run(&c,targeted,&limits,&stats,YD_SHARD_OK);CHECK(!strcmp(first,again));free(again);
    /* Keys from every input row: still targeted, now both shards; same rows. */
    const char *wide="[{$lookup: {from: users, localField: owner, foreignField: user, as: who}}, {$match: {bucket: u1}}, {$sort: {tenant: 1}}]";
    char *second=join_run(&c,wide,&limits,&stats,YD_SHARD_OK);
    CHECK(stats.relation[0].targeted&&stats.relation[0].shards==2&&!strcmp(first,second));free(second);
    /* A join on a non-key field scatters to every shard and gives the same result. */
    const char *scatter="[{$match: {bucket: u1}}, {$lookup: {from: users, localField: owner, foreignField: alias, as: who}}, {$sort: {tenant: 1}}]";
    char *third=join_run(&c,scatter,&limits,&stats,YD_SHARD_OK);
    CHECK(!stats.relation[0].targeted&&stats.relation[0].shards==2&&stats.relation[0].rows==11&&!strcmp(first,third));free(third);free(first);
    /* Part of a compound key is not a target: bounded scatter. */
    const char *bought="[{$match: {tenant: {$lt: 4}}}, {$lookup: {from: orders, localField: tenant, foreignField: tenant, as: bought}}, {$sort: {tenant: 1}}]";
    char *fourth=join_run(&c,bought,&limits,&stats,YD_SHARD_OK);
    CHECK(!stats.relation[0].targeted&&stats.relation[0].shards==2&&stats.relation[0].rows==12);
    rows=yd_parse((unsigned char*)fourth,strlen(fourth),NULL,0);CHECK(rows&&rows->count==4);
    for(size_t i=0;i<4;i++){CHECK(yd_get(rows->items[i],"bought")->count==3);}
    yd_free(rows);free(fourth);
    /* Self lookup reuses the input views; two relations: the second scatters. */
    char *self=join_run(&c,"[{$match: {tenant: 3}}, {$lookup: {from: records, localField: owner, foreignField: owner, as: same}}]",&limits,&stats,YD_SHARD_OK);
    CHECK(stats.relation[0].local);rows=yd_parse((unsigned char*)self,strlen(self),NULL,0);CHECK(rows&&rows->count==1&&yd_get(rows->items[0],"same")->count==4);yd_free(rows);free(self);
    const char *two="[{$match: {bucket: u1}}, {$lookup: {from: users, localField: owner, foreignField: user, as: who}}, "
        "{$lookup: {from: orders, localField: tenant, foreignField: tenant, as: bought}}, {$sort: {tenant: 1}}]";
    released=0;free(join_run(&c,two,&limits,&stats,YD_SHARD_OK));
    CHECK(stats.relations==2&&stats.relation[0].targeted&&!stats.relation[1].targeted&&released==2);
    /* Bounds fail the whole request with no partial result. */
    YDShardJoinLimits tight=limits;tight.max_matches=1;join_run(&c,wide,&tight,&stats,YD_SHARD_BUDGET_EXCEEDED);
    tight=limits;tight.max_foreign_rows=5;join_run(&c,scatter,&tight,&stats,YD_SHARD_BUDGET_EXCEEDED);
    tight=limits;tight.max_foreign_bytes=16;join_run(&c,scatter,&tight,&stats,YD_SHARD_BUDGET_EXCEEDED);
    tight=limits;tight.max_rows=10;join_run(&c,scatter,&tight,&stats,YD_SHARD_BUDGET_EXCEEDED);
    tight=limits;tight.max_time_ms=1;rpc_delay_ms=3;join_run(&c,scatter,&tight,&stats,YD_SHARD_DEADLINE_EXCEEDED);rpc_delay_ms=0;
    tight=limits;tight.max_matches=0;join_run(&c,scatter,&tight,&stats,YD_SHARD_INVALID_ARGUMENT);
    tight=limits;tight.max_time_ms=30001;join_run(&c,scatter,&tight,&stats,YD_SHARD_INVALID_ARGUMENT);
    /* Foreign read authorization precedes every shard call, for each relation. */
    denied="users";calls=0;join_run(&c,targeted,&limits,&stats,YD_SHARD_FORBIDDEN);CHECK(!calls);
    denied="orders";calls=0;released=0;join_run(&c,two,&limits,&stats,YD_SHARD_FORBIDDEN);CHECK(!calls&&released==1);denied=NULL;
    join_run(&c,"[{$lookup: {from: empty, localField: owner, foreignField: user, as: who}}]",&limits,&stats,YD_SHARD_CROSS_SHARD_UNSUPPORTED);
    c.router.resolve=NULL;join_run(&c,targeted,&limits,&stats,YD_SHARD_CROSS_SHARD_UNSUPPORTED);c.router.resolve=resolve_side;
    puts("cross-shard lookup: targeted, scatter, self, bounds, deadline and foreign authorization passed");
    close_side(&users);close_side(&orders);
    /* Reopen: every control record and native key validates. */
    close_cluster(&c);open_cluster(&c,path);open_side(&c,&orders,"orders");
    CHECK(yd_shard_placement_key_version(yd_shard_control_placement(orders.control))==2);orders_verify(&orders);native_validation(&c);
    CHECK(yd_shard_control_begin(orders.control,"o1","gc","55555555555555555555555555555555",&command,&length)==YD_SHARD_OK);
    CHECK(side_commit(&orders,command,length)==YD_SHARD_OK);free(command);close_side(&orders);close_cluster(&c);
    int crashes=0;bool killed[16]={0};
    for(unsigned step=0;step<40;step++){
        open_cluster(&c,path);open_side(&c,&orders,"orders");YDShardMigration m=yd_shard_control_migration(orders.control);
        if(m.phase!=YD_SHARD_ACTIVATING)orders_verify(&orders);
        if(m.phase==YD_SHARD_IDLE){CHECK(side_epoch(&orders)==2);close_side(&orders);close_cluster(&c);break;}
        YDShardKey blocked=order_key(0,0);YDShardPlan plan;
        CHECK(yd_shard_plan_keys(yd_shard_control_placement(orders.control),orders_id,"orders",side_epoch(&orders),YD_SHARD_WRITE,&blocked,1,&plan)==YD_SHARD_OK);
        if(!strcmp(plan.shard,"o1"))CHECK(side_route(&orders,YD_SHARD_RPC_DELETE,&blocked,"order-00",NULL,"blocked",NULL)==YD_SHARD_MIGRATING);
        int operation=m.phase==YD_SHARD_FENCING?YD_SHARD_RPC_FREEZE:m.phase==YD_SHARD_COPYING?(m.copied?YD_SHARD_RPC_SEAL:YD_SHARD_RPC_STAGE):m.phase==YD_SHARD_ACTIVATING?YD_SHARD_RPC_ACTIVATE:-1;
        bool crash=operation>=0&&!killed[operation];if(crash)killed[operation]=true;
        close_side(&orders);close_cluster(&c);
        pid_t child=fork();CHECK(child>=0);
        if(!child){open_cluster(&c,path);open_side(&c,&orders,"orders");die_rpc=crash?operation:-1;
            CHECK(yd_shard_migrate_step(&orders.router)==YD_SHARD_OK);close_side(&orders);close_cluster(&c);_Exit(0);}
        int status;CHECK(waitpid(child,&status,0)==child&&WIFEXITED(status));CHECK(WEXITSTATUS(status)==(crash?71:0));if(crash)crashes++;
    }
    CHECK(crashes==4);open_cluster(&c,path);open_side(&c,&orders,"orders");
    CHECK(yd_shard_control_migration(orders.control).phase==YD_SHARD_IDLE&&side_epoch(&orders)==2&&epoch(&c)==1);
    YDShardRange range;CHECK(yd_shard_placement_range(yd_shard_control_placement(orders.control),0,&range)&&!strcmp(range.group,"gc"));
    orders_verify(&orders);native_validation(&c);close_side(&orders);close_cluster(&c);
    puts("compound-key migration: four durable RPC cut points, full reopen, single ownership passed");
}
/* Change feed ledger: every logged change in write order, with its shard. */
typedef struct {char shard[64],id[256];bool deleted;} Event;
#define EVENT_LIMIT 8400U
static Event want[EVENT_LIMIT];
static size_t wants=0;
static const char *shard_of(Side *s,const YDShardKey *key){static char shard[64];YDShardPlan plan;const YDShardPlacement *p=yd_shard_control_placement(s->control);
    CHECK(yd_shard_plan_keys(p,yd_shard_placement_id(p),yd_shard_placement_collection(p),side_epoch(s),YD_SHARD_READ,key,1,&plan)==YD_SHARD_OK);
    strcpy(shard,plan.shard);return shard;}
static YDShardStatus user_put(Side *s,const char *id,const char *user,const char *source,const char *mutation,bool logged){
    YDShardKey key=text_key(user);YDShardStatus st=side_route(s,source?YD_SHARD_RPC_WRITE:YD_SHARD_RPC_DELETE,&key,id,source,mutation,NULL);
    if(st==YD_SHARD_OK&&logged){CHECK(wants<EVENT_LIMIT);Event *e=&want[wants++];strcpy(e->shard,shard_of(s,&key));snprintf(e->id,sizeof(e->id),"%s",id);e->deleted=!source;}
    return st;}
static YDShardChanges feed(Side *s,const char *after,size_t limit,size_t max_bytes,YDShardStatus expected){
    YDShardChanges c;const YDShardPlacement *p=yd_shard_control_placement(s->control);
    YDShardStatus st=yd_shard_changes(&s->router,yd_shard_placement_id(p),yd_shard_placement_collection(p),side_epoch(s),after,limit,max_bytes,&c);
    if(st!=expected)fprintf(stderr,"changes: %s, expected %s\n",yd_shard_status_name(st),yd_shard_status_name(expected));
    CHECK(st==expected);if(st!=YD_SHARD_OK)CHECK(!c.count&&!c.next&&!c.changes);return c;}
static size_t range_index(Side *s,const char *shard){const YDShardPlacement *p=yd_shard_control_placement(s->control);
    for(size_t i=0;i<yd_shard_placement_ranges(p);i++){YDShardRange r;CHECK(yd_shard_placement_range(p,i,&r));if(!strcmp(r.shard,shard))return i;}
    CHECK(false);return 0;}
/* Read every page from *token; checks page order (range order, then sequence)
 * and per-shard continuity, and leaves *token at the end. */
static size_t drain(Side *s,char **token,size_t limit,Event *got,size_t cap,size_t *pages){
    size_t n=0;uint64_t last[2]={0,0};bool seen[2]={false,false};if(pages)*pages=0;
    for(unsigned round=0;;round++){CHECK(round<20000);
        YDShardChanges c=feed(s,*token,limit,YD_SHARD_CHANGES_BYTES,YD_SHARD_OK);CHECK(c.count<=limit&&c.shards==2);
        size_t previous=0,taken[2]={0,0};
        for(size_t i=0;i<c.count;i++){const YDShardChange *e=&c.changes[i];size_t r=range_index(s,e->shard);
            /* Each shard gets at most max(1, limit / shards) entries of a page. */
            CHECK(++taken[r]<=(limit/2?limit/2:1));
            CHECK(r>=previous);previous=r;CHECK(!seen[r]||e->sequence==last[r]+1);seen[r]=true;last[r]=e->sequence;
            CHECK(e->deleted==!e->source&&(e->deleted||e->length));CHECK(!strcmp(shard_of(s,&e->key),e->shard));
            CHECK(n<cap);snprintf(got[n].shard,sizeof(got[n].shard),"%s",e->shard);snprintf(got[n].id,sizeof(got[n].id),"%s",e->id);got[n].deleted=e->deleted;n++;}
        free(*token);*token=strdup(c.next);CHECK(*token);bool more=c.more;yd_shard_changes_free(&c);
        if(pages)(*pages)++;
        if(!more)break;
    }
    return n;
}
/* Per shard, the delivered events are exactly the ledger from index from on. */
static void same_events(const Event *got,size_t n,size_t from){
    CHECK(n==wants-from);
    const char *shards[]={"u1","u2"};
    for(size_t s=0;s<2;s++){size_t i=0,j=from;
        for(;;){while(i<n&&strcmp(got[i].shard,shards[s]))i++;while(j<wants&&strcmp(want[j].shard,shards[s]))j++;
            if(i==n||j==wants){CHECK(i==n&&j==wants);break;}
            CHECK(!strcmp(got[i].id,want[j].id)&&got[i].deleted==want[j].deleted);i++;j++;}
    }
}
static char *token_edit(const char *token,size_t offset,const char *hex){
    char *t=strdup(token);CHECK(t&&strlen(t)>=5+2*offset+strlen(hex));memcpy(t+5+2*offset,hex,strlen(hex));return t;}
static Event got[EVENT_LIMIT];
static void feeds(const char *root) {
    char path[2048];snprintf(path,sizeof(path),"%s/feeds",root);CHECK(!mkdir(path,0700));
    Cluster c;open_cluster(&c,path);unsigned char *command=NULL;size_t length;
    CHECK(yd_shard_control_install(c.control,placement,sizeof(placement)-1,&command,&length)==YD_SHARD_OK);
    CHECK(commit(&c,command,length)==YD_SHARD_OK);free(command);
    /* Version-1 placements keep no change log. */
    YDShardChanges none;CHECK(yd_shard_changes(&c.router,identity,"records",epoch(&c),NULL,10,1024,&none)==YD_SHARD_UNSUPPORTED_METADATA);
    Side users,orders;open_side(&c,&users,"users");open_side(&c,&orders,"orders");
    CHECK(install_side(&users,users_placement,sizeof(users_placement)-1)==YD_SHARD_OK);
    CHECK(install_side(&orders,orders_placement,sizeof(orders_placement)-1)==YD_SHARD_OK);
    YDShardChanges start=feed(&users,NULL,10,YD_SHARD_CHANGES_BYTES,YD_SHARD_OK);
    CHECK(!start.count&&!start.more&&start.shards==2&&start.epoch==1);char *origin=strdup(start.next);yd_shard_changes_free(&start);
    for(unsigned k=0;k<30;k++){char id[16],user[16],source[96],mutation[16];snprintf(id,sizeof(id),"u-%u",k);snprintf(user,sizeof(user),"user-%u",k);
        snprintf(source,sizeof(source),"user: user-%u\nname: N%u\n",k,k);snprintf(mutation,sizeof(mutation),"f-%u",k);
        CHECK(user_put(&users,id,user,source,mutation,true)==YD_SHARD_OK);}
    /* A receipt replay, a delete of nothing and a refused write log nothing. */
    CHECK(user_put(&users,"u-0","user-0","user: user-0\nname: N0\n","f-0",false)==YD_SHARD_OK);
    CHECK(user_put(&users,"u-404","user-404",NULL,"d-404",false)==YD_SHARD_OK);
    CHECK(user_put(&users,"u-6","user-6","user: user-7\n","bad-6",false)==YD_SHARD_KEY_CHANGE_UNSUPPORTED);
    CHECK(user_put(&users,"u-3","user-3","user: user-3\nname: changed\n","f-3b",true)==YD_SHARD_OK);
    CHECK(user_put(&users,"u-5","user-5",NULL,"d-5",true)==YD_SHARD_OK);
    char *token=strdup(origin);size_t pages=0,n=drain(&users,&token,7,got,EVENT_LIMIT,&pages);same_events(got,n,0);CHECK(pages>=5);
    /* The same token always gives the same pages and the same final token. */
    char *again=strdup(origin);CHECK(drain(&users,&again,7,got,EVENT_LIMIT,NULL)==n);same_events(got,n,0);CHECK(!strcmp(again,token));free(again);
    YDShardChanges tail=feed(&users,NULL,10,YD_SHARD_CHANGES_BYTES,YD_SHARD_OK);CHECK(!strcmp(tail.next,token));yd_shard_changes_free(&tail);
    tail=feed(&users,token,10,YD_SHARD_CHANGES_BYTES,YD_SHARD_OK);CHECK(!tail.count&&!tail.more&&!strcmp(tail.next,token));yd_shard_changes_free(&tail);
    /* Content: the overwrite carries its new document, the delete none. */
    YDShardChanges all=feed(&users,origin,1024,YD_SHARD_CHANGES_BYTES,YD_SHARD_OK);bool overwrite=false,deleted=false;
    for(size_t i=0;i<all.count;i++){const YDShardChange *e=&all.changes[i];CHECK(e->epoch==1);
        if(!strcmp(e->id,"u-3")&&e->length==strlen("user: user-3\nname: changed\n")&&!memcmp(e->source,"user: user-3\nname: changed\n",e->length))overwrite=true;
        if(!strcmp(e->id,"u-5")&&e->deleted){YDShardKey five=text_key("user-5");CHECK(e->key.length==five.length&&!memcmp(e->key.bytes,five.bytes,five.length));deleted=true;}}
    CHECK(overwrite&&deleted&&all.count==32&&!all.more);yd_shard_changes_free(&all);
    /* Unhonorable tokens fail loudly. */
    char *bad=token_edit(token,35,"00000000000fffff");feed(&users,bad,10,YD_SHARD_CHANGES_BYTES,YD_SHARD_CONFLICT);free(bad);
    bad=token_edit(token,43,token[5+86]=='0'?"1":"0");feed(&users,bad,10,YD_SHARD_CHANGES_BYTES,YD_SHARD_CONFLICT);free(bad);
    bad=token_edit(token,59,token[5+118]=='0'?"1":"0");feed(&users,bad,10,YD_SHARD_CHANGES_BYTES,YD_SHARD_CONFLICT);free(bad);
    YDShardChanges other=feed(&orders,NULL,10,YD_SHARD_CHANGES_BYTES,YD_SHARD_OK);feed(&users,other.next,10,YD_SHARD_CHANGES_BYTES,YD_SHARD_CONFLICT);yd_shard_changes_free(&other);
    bad=token_edit(token,27,token[5+54]=='0'&&token[5+55]=='0'?"ff":"00");feed(&users,bad,10,YD_SHARD_CHANGES_BYTES,YD_SHARD_CONFLICT);free(bad);
    bad=token_edit(token,17,"7fffffffffffffff");feed(&users,bad,10,YD_SHARD_CHANGES_BYTES,YD_SHARD_STALE_PLACEMENT);free(bad);
    bad=token_edit(token,0,"02");feed(&users,bad,10,YD_SHARD_CHANGES_BYTES,YD_SHARD_INVALID_ARGUMENT);free(bad);
    bad=strdup(token);bad[strlen(bad)-2]=0;feed(&users,bad,10,YD_SHARD_CHANGES_BYTES,YD_SHARD_INVALID_ARGUMENT);bad[3]='2';feed(&users,bad,10,YD_SHARD_CHANGES_BYTES,YD_SHARD_INVALID_ARGUMENT);free(bad);
    feed(&users,"ysf1.zz",10,YD_SHARD_CHANGES_BYTES,YD_SHARD_INVALID_ARGUMENT);
    feed(&users,token,0,YD_SHARD_CHANGES_BYTES,YD_SHARD_INVALID_ARGUMENT);feed(&users,token,1025,YD_SHARD_CHANGES_BYTES,YD_SHARD_INVALID_ARGUMENT);
    feed(&users,token,10,0,YD_SHARD_INVALID_ARGUMENT);feed(&users,token,10,YD_SHARD_CHANGES_BYTES+1,YD_SHARD_INVALID_ARGUMENT);
    feed(&users,origin,10,16,YD_SHARD_BUDGET_EXCEEDED);
    allowed=false;calls=0;feed(&users,token,10,YD_SHARD_CHANGES_BYTES,YD_SHARD_FORBIDDEN);CHECK(!calls);allowed=true;
    puts("change feed: resume tokens, page order, exact replay and loud token failures passed");
    /* Restart: a saved token resumes with exactly the changes after it. */
    YDShardChanges page=feed(&users,origin,7,YD_SHARD_CHANGES_BYTES,YD_SHARD_OK);char *mid=strdup(page.next);size_t first_page=page.count;yd_shard_changes_free(&page);
    close_side(&users);close_side(&orders);close_cluster(&c);open_cluster(&c,path);open_side(&c,&users,"users");
    YDShardChanges resumed=feed(&users,mid,1024,YD_SHARD_CHANGES_BYTES,YD_SHARD_OK);CHECK(resumed.count==n-first_page&&!resumed.more&&!strcmp(resumed.next,token));
    yd_shard_changes_free(&resumed);free(mid);
    /* Retention keeps the newest 4096 entries of a shard. */
    YDShardKey zero=text_key("user-0");char hot[64];strcpy(hot,shard_of(&users,&zero));
    for(unsigned i=0;i<YD_SHARD_LOG_ENTRIES+8;i++){char source[64],mutation[32];snprintf(source,sizeof(source),"user: user-0\nround: %u\n",i);snprintf(mutation,sizeof(mutation),"hot-%u",i);
        YDShardStatus st=user_put(&users,"u-0","user-0",source,mutation,true);
        if(st!=YD_SHARD_OK){fprintf(stderr,"hot write %u: %s\n",i,yd_shard_status_name(st));}
        CHECK(st==YD_SHARD_OK);}
    feed(&users,origin,10,YD_SHARD_CHANGES_BYTES,YD_SHARD_EXPIRED);feed(&users,token,10,YD_SHARD_CHANGES_BYTES,YD_SHARD_EXPIRED);
    YDShardChanges now=feed(&users,NULL,10,YD_SHARD_CHANGES_BYTES,YD_SHARD_OK);char *before=strdup(now.next);yd_shard_changes_free(&now);size_t before_index=wants;
    /* One entry older than the window: expired before its hash is checked. */
    size_t hot_events=0;for(size_t i=0;i<wants;i++)hot_events+=!strcmp(want[i].shard,hot);
    char older[17];snprintf(older,sizeof(older),"%016llx",(unsigned long long)(hot_events-YD_SHARD_LOG_ENTRIES-1));
    char *oldest=token_edit(before,range_index(&users,hot)?51:35,older);feed(&users,oldest,10,YD_SHARD_CHANGES_BYTES,YD_SHARD_EXPIRED);free(oldest);
    snprintf(older,sizeof(older),"%016llx",(unsigned long long)(hot_events-YD_SHARD_LOG_ENTRIES));
    oldest=token_edit(before,range_index(&users,hot)?51:35,older);feed(&users,oldest,10,YD_SHARD_CHANGES_BYTES,YD_SHARD_CONFLICT);free(oldest);
    puts("change feed: retention window and expired positions passed");
    /* Migration with a process kill after each durable RPC. Writes to the
     * moving shard are refused; the feed keeps serving from the frozen source. */
    YDShardKey other_key;unsigned probe=1;
    do{char user[16];snprintf(user,sizeof(user),"user-%u",probe++);other_key=text_key(user);}while(!strcmp(shard_of(&users,&other_key),hot));
    char other_user[16];snprintf(other_user,sizeof(other_user),"user-%u",probe-1);
    CHECK(yd_shard_control_begin(users.control,hot,"gc","66666666666666666666666666666666",&command,&length)==YD_SHARD_OK);
    CHECK(side_commit(&users,command,length)==YD_SHARD_OK);free(command);close_side(&users);close_cluster(&c);
    int crashes=0,unavailable=0;bool killed[16]={0};unsigned writes=0;
    for(unsigned step=0;step<60;step++){
        open_cluster(&c,path);open_side(&c,&users,"users");YDShardMigration m=yd_shard_control_migration(users.control);
        /* After ownership publication the new owner serves the feed only
         * once it has activated the imported log, like its documents. */
        YDShardChanges probe_page;const YDShardPlacement *p=yd_shard_control_placement(users.control);
        YDShardStatus probe_status=yd_shard_changes(&users.router,yd_shard_placement_id(p),"users",side_epoch(&users),before,50,YD_SHARD_CHANGES_BYTES,&probe_page);
        yd_shard_changes_free(&probe_page);
        if(probe_status==YD_SHARD_UNAVAILABLE){CHECK(m.phase==YD_SHARD_ACTIVATING);unavailable++;}
        else{CHECK(probe_status==YD_SHARD_OK);
            char *cursor=strdup(before);size_t delivered=drain(&users,&cursor,50,got,EVENT_LIMIT,NULL);same_events(got,delivered,before_index);free(cursor);}
        if(m.phase==YD_SHARD_IDLE){close_side(&users);close_cluster(&c);break;}
        char id[32],source[96],mutation[32];snprintf(id,sizeof(id),"during-%u",writes);snprintf(source,sizeof(source),"user: %s\nwrite: %u\n",other_user,writes);snprintf(mutation,sizeof(mutation),"during-%u",writes++);
        CHECK(user_put(&users,id,other_user,source,mutation,true)==YD_SHARD_OK);
        CHECK(user_put(&users,"u-0","user-0","user: user-0\nblocked: true\n",mutation,false)==YD_SHARD_MIGRATING);
        int operation=m.phase==YD_SHARD_FENCING?YD_SHARD_RPC_FREEZE:m.phase==YD_SHARD_COPYING?
            (m.copied?(killed[YD_SHARD_RPC_LOG_STAGE]?YD_SHARD_RPC_SEAL:YD_SHARD_RPC_LOG_STAGE):YD_SHARD_RPC_STAGE):m.phase==YD_SHARD_ACTIVATING?YD_SHARD_RPC_ACTIVATE:-1;
        bool crash=operation>=0&&!killed[operation];if(crash)killed[operation]=true;
        close_side(&users);close_cluster(&c);
        pid_t child=fork();CHECK(child>=0);
        if(!child){open_cluster(&c,path);open_side(&c,&users,"users");die_rpc=crash?operation:-1;
            CHECK(yd_shard_migrate_step(&users.router)==YD_SHARD_OK);close_side(&users);close_cluster(&c);_Exit(0);}
        int status;CHECK(waitpid(child,&status,0)==child&&WIFEXITED(status));CHECK(WEXITSTATUS(status)==(crash?71:0));if(crash)crashes++;
    }
    CHECK(crashes==5&&unavailable==1);
    open_cluster(&c,path);open_side(&c,&users,"users");CHECK(side_epoch(&users)==2);
    /* The moved shard continues its numbering at the new owner. */
    CHECK(user_put(&users,"u-0","user-0","user: user-0\nmoved: true\n","after-move",true)==YD_SHARD_OK);
    char *cursor=strdup(before);size_t delivered=drain(&users,&cursor,50,got,EVENT_LIMIT,NULL);same_events(got,delivered,before_index);
    hot_events=0;for(size_t i=0;i<wants;i++)hot_events+=!strcmp(want[i].shard,hot);
    YDShardChanges last=feed(&users,before,1024,YD_SHARD_CHANGES_BYTES,YD_SHARD_OK);size_t continued=0;
    for(size_t i=0;i<last.count;i++)if(!strcmp(last.changes[i].shard,hot)){CHECK(last.changes[i].epoch==2&&last.changes[i].sequence==hot_events);continued++;}
    CHECK(continued==1&&last.epoch==2&&last.count==writes+1);yd_shard_changes_free(&last);
    native_validation(&c);free(cursor);free(before);free(token);free(origin);close_side(&users);close_cluster(&c);
    puts("change feed: migration with five durable RPC cut points, no loss or duplicate, continued numbering passed");
}
int main(int argc,char **argv) {
    CHECK(argc==2);delayed_owner_commands(argv[1]);logical_freeze_layouts(argv[1]);Cluster c;open_cluster(&c,argv[1]);seed(&c);verify(&c);stable_cursor(&c);prepared_transactions(&c);verify(&c);native_validation(&c);close_cluster(&c);
    puts("native routing, authorization, deterministic pagination and aggregation passed");
    migrate_crashes(argv[1]);migrate_control_crashes(argv[1]);joins(argv[1]);feeds(argv[1]);return 0;
}
