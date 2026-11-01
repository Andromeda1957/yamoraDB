#define _POSIX_C_SOURCE 200809L
#include "runtime.h"
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void yd_shard_page_free(YDShardPage *p) { if(p){for(size_t i=0;i<p->count;i++)free(p->rows[i].source);
        free(p->rows);
        memset(p,0,sizeof(*p));
    } }
static bool cancelled(YDShardRouter *r) {return r->cancelled&&r->cancelled(r->cancel_context);
}
static bool id_valid(const char *id) {if(!id||!id[0]||strnlen(id,256)>255)return false;
    for(size_t i=0;id[i];i++)if((unsigned char)id[i]<33||(unsigned char)id[i]>126||id[i]=='/'||id[i]=='\\')return false;
    return true;
}
static const YDShardBinding *binding(YDShardRouter *r,const char *group) {
    const YDShardBinding *found=NULL;
    if(!r->bindings||r->binding_count>YD_SHARD_RANGE_LIMIT)return NULL;
    for(size_t i=0;i<r->binding_count;i++)if(r->bindings[i].group&&!strcmp(r->bindings[i].group,group)){if(found)return NULL;
        found=&r->bindings[i];
    }
    return found&&found->call?found:NULL;
}
static YDShardStatus access(YDShardRouter *r,const char *id,const char *collection,uint64_t epoch,bool write) {
    if(!r||!r->control||!id||!collection)return YD_SHARD_INVALID_ARGUMENT;
    if(!r->authorize||!r->authorize(r->auth_context,collection,write))return YD_SHARD_FORBIDDEN;
    const YDShardPlacement *p=yd_shard_control_placement(r->control);
    if(!p||!epoch||strcmp(id,yd_shard_placement_id(p))||strcmp(collection,yd_shard_placement_collection(p))||epoch!=yd_shard_placement_epoch(p))return YD_SHARD_STALE_PLACEMENT;
    return cancelled(r)?YD_SHARD_CANCELLED:YD_SHARD_OK;
}
static YDShardStatus call(YDShardRouter *r,const char *group,const YDShardRequest *req,YDShardResponse *out) {
    memset(out,0,sizeof(*out));
    if(cancelled(r))return YD_SHARD_CANCELLED;
    const YDShardBinding *b=binding(r,group);
    if(!b)return YD_SHARD_UNAVAILABLE;
    YDShardStatus s=b->call(b->context,req,out);
    if(s!=YD_SHARD_OK||cancelled(r)){yd_shard_page_free(&out->page);
        memset(out,0,sizeof(*out));
        return s==YD_SHARD_OK?YD_SHARD_CANCELLED:s;
    }
    return s;
}
static bool range_for(const YDShardPlacement *p,const char *shard,YDShardRange *out) {for(size_t i=0;i<yd_shard_placement_ranges(p);i++)if(yd_shard_placement_range(p,i,out)&&!strcmp(out->shard,shard))return true;
    return false;
}
static bool row_valid(const YDShardPlacement *p,const YDShardRange *range,const YDShardRow *row,YDValue **doc) {
    *doc=NULL;
    if(!id_valid(row->id)||!row->source||!row->length||row->length>YD_DOCUMENT_LIMIT)return false;
    YDValue *v=yd_parse(row->source,row->length,NULL,0);
    if(!v)return false;
    YDShardPlan plan;
    YDShardStatus s=yd_shard_plan_document(p,yd_shard_placement_id(p),yd_shard_placement_collection(p),yd_shard_placement_epoch(p),YD_SHARD_READ,v,&plan);
    if(s!=YD_SHARD_OK||strcmp(plan.shard,range->shard)){yd_free(v);
        return false;
    }*doc=v;
    return true;
}
static bool page_valid(const YDShardPage *page,const char *after,size_t max_rows,size_t max_bytes) {
    if(page->count>max_rows||page->bytes>max_bytes||(page->count&&!page->rows)||(!page->count&&!page->end))return false;
    size_t bytes=0;
    const char *last=after?after:"";
    for(size_t i=0;i<page->count;i++){const YDShardRow *row=&page->rows[i];
        if(!id_valid(row->id)||strcmp(row->id,last)<=0||row->length>max_bytes-bytes)return false;
        bytes+=row->length;
        last=row->id;
    }
    return bytes==page->bytes;
}
YDShardStatus yd_shard_route(YDShardRouter *r,const char *placement_id,const char *collection,uint64_t epoch,YDShardRPC op,const YDShardKey *key,const char *id,const unsigned char *source,size_t length,const char *mutation,YDShardResponse *out) {
    if(!out)return YD_SHARD_INVALID_ARGUMENT;
    memset(out,0,sizeof(*out));
    if(op!=YD_SHARD_RPC_READ&&op!=YD_SHARD_RPC_WRITE&&op!=YD_SHARD_RPC_DELETE)return YD_SHARD_INVALID_ARGUMENT;
    if(op!=YD_SHARD_RPC_WRITE&&(source||length))return YD_SHARD_INVALID_ARGUMENT;
    YDShardStatus s=access(r,placement_id,collection,epoch,op!=YD_SHARD_RPC_READ);
    if(s!=YD_SHARD_OK)return s;
    if(!id_valid(id))return YD_SHARD_INVALID_ARGUMENT;
    if(op!=YD_SHARD_RPC_READ&&(!mutation||!mutation[0]||strnlen(mutation,129)>128))return YD_SHARD_INVALID_ARGUMENT;
    const YDShardPlacement *p=yd_shard_control_placement(r->control);
    YDShardPlan plan;
    s=yd_shard_plan_keys(p,placement_id,collection,epoch,op==YD_SHARD_RPC_READ?YD_SHARD_READ:YD_SHARD_WRITE,key,1,&plan);
    if(s!=YD_SHARD_OK)return s;
    YDShardMigration m=yd_shard_control_migration(r->control);
    if(op!=YD_SHARD_RPC_READ&&m.phase!=YD_SHARD_IDLE&&!strcmp(m.shard,plan.shard))return YD_SHARD_MIGRATING;
    if(op==YD_SHARD_RPC_WRITE){
        if(!source||!length||length>YD_DOCUMENT_LIMIT)return YD_SHARD_INVALID_ARGUMENT;
        YDValue *doc=yd_parse(source,length,NULL,0);
        if(!doc)return YD_SHARD_INVALID_KEY;
        YDShardKey encoded;
        s=yd_shard_document_key(p,doc,&encoded);
        yd_free(doc);
        if(s!=YD_SHARD_OK)return s;
        if(encoded.length!=key->length||memcmp(encoded.bytes,key->bytes,key->length))return YD_SHARD_KEY_CHANGE_UNSUPPORTED;
    }
    YDShardRange range;
    if(!range_for(p,plan.shard,&range))return YD_SHARD_CORRUPT;
    YDShardRequest req={.operation=op,.placement=p,.range=range,.migration=m,.id=id,.key=key,.source=source,.length=length,.mutation_id=mutation,.max_rows=1,.max_bytes=YD_DOCUMENT_LIMIT};
    s=call(r,range.group,&req,out);
    if(s!=YD_SHARD_OK)return s;
    if(out->page.count>1||(op!=YD_SHARD_RPC_READ&&out->page.count)){yd_shard_page_free(&out->page);
        return YD_SHARD_CORRUPT;
    }
    if(out->page.count){YDValue *v=NULL;
        bool ok=!strcmp(out->page.rows[0].id,id)&&row_valid(p,&range,&out->page.rows[0],&v);
        yd_free(v);
        if(!ok){yd_shard_page_free(&out->page);
            return YD_SHARD_CORRUPT;
        }}
    return YD_SHARD_OK;
}
static YDShardStatus publish(YDShardRouter *r,const YDShardMigration *m) {
    unsigned char *b=NULL;
    size_t n=0;
    YDShardStatus s=yd_shard_control_advance(r->control,m,&b,&n);
    if(s==YD_SHARD_OK)s=r->commit?r->commit(r->commit_context,b,n):YD_SHARD_UNAVAILABLE;
    free(b);
    return s;
}
/* Copy the frozen source's change log to the target, resuming from the
 * target's own staged tail, until the target reports it complete. The source
 * is fenced from FREEZE on, so its log cannot grow during the copy. */
static YDShardStatus copy_log(YDShardRouter *r,const YDShardRequest *base,const YDShardMigration *m){
    YDShardRequest req=*base;YDShardResponse out={0},ack={0};
    req.operation=YD_SHARD_RPC_LOG;req.after="";req.page=NULL;
    YDShardStatus s=call(r,m->source,&req,&out);
    yd_shard_page_free(&out.page);
    if(s!=YD_SHARD_OK)return s;
    if(strnlen(out.snapshot,65)!=64||out.page.count)return YD_SHARD_CORRUPT;
    char source[49];memcpy(source,out.snapshot+16,48);source[48]=0;  /* last + tail hash */
    YDShardPage empty={.end=true};
    YDShardRequest stage=*base;stage.operation=YD_SHARD_RPC_LOG_STAGE;stage.after=source;stage.page=&empty;
    s=call(r,m->target,&stage,&ack);
    yd_shard_page_free(&ack.page);
    /* Each round moves at least one entry; retention bounds the rounds. */
    for(unsigned round=0;s==YD_SHARD_OK;round++){
        size_t n=strnlen(ack.snapshot,65);
        if(n==49&&ack.snapshot[48]=='1')return YD_SHARD_OK;
        if(round>YD_SHARD_LOG_ENTRIES||(n!=49&&strcmp(ack.snapshot,"-")))return YD_SHARD_CORRUPT;
        char after[33]="*";
        if(n==49){memcpy(after,ack.snapshot,32);after[32]=0;}
        req.after=after;
        s=call(r,m->source,&req,&out);
        if(s!=YD_SHARD_OK)break;
        if(!out.page.count){yd_shard_page_free(&out.page);return YD_SHARD_CORRUPT;}
        stage.page=&out.page;
        s=call(r,m->target,&stage,&ack);
        yd_shard_page_free(&ack.page);
        yd_shard_page_free(&out.page);
    }
    return s;
}
YDShardStatus yd_shard_migrate_step(YDShardRouter *r) {
    if(!r||!r->control)return YD_SHARD_INVALID_ARGUMENT;
    const YDShardPlacement *p=yd_shard_control_placement(r->control);
    if(!p)return YD_SHARD_STALE_PLACEMENT;
    YDShardStatus s=access(r,yd_shard_placement_id(p),yd_shard_placement_collection(p),yd_shard_placement_epoch(p),true);
    if(s!=YD_SHARD_OK)return s;
    YDShardMigration m=yd_shard_control_migration(r->control);
    if(m.phase==YD_SHARD_IDLE)return YD_SHARD_OK;
    YDShardRange range;
    if(!range_for(p,m.shard,&range))return YD_SHARD_CORRUPT;
    if(!binding(r,m.source)||!binding(r,m.target))return YD_SHARD_UNAVAILABLE;
    YDShardRequest req={.placement=p,.range=range,.migration=m,.snapshot=m.snapshot,.after=m.cursor,.max_rows=YD_SHARD_PAGE_ROWS,.max_bytes=YD_SHARD_PAGE_BYTES};
    YDShardResponse out={0};
    if(m.phase==YD_SHARD_FENCING){
        req.operation=YD_SHARD_RPC_FREEZE;
        s=call(r,m.source,&req,&out);
        if(s!=YD_SHARD_OK)return s;
        if(strnlen(out.snapshot,65)!=64){yd_shard_page_free(&out.page);
            return YD_SHARD_CORRUPT;
        }strcpy(m.snapshot,out.snapshot);
        yd_shard_page_free(&out.page);
        m.phase=YD_SHARD_COPYING;
        return publish(r,&m);
    }
    if(m.phase==YD_SHARD_COPYING){
        if(m.copied&&yd_shard_placement_version(p)>=2){
            s=copy_log(r,&req,&m);
            if(s!=YD_SHARD_OK)return s;
        }
        if(m.copied){req.operation=YD_SHARD_RPC_SEAL;
            s=call(r,m.target,&req,&out);
            yd_shard_page_free(&out.page);
            if(s!=YD_SHARD_OK)return s;
            m.phase=YD_SHARD_SEALED;
            return publish(r,&m);
        }
        req.operation=YD_SHARD_RPC_SCAN;
        s=call(r,m.source,&req,&out);
        if(s!=YD_SHARD_OK)return s;
        if(!page_valid(&out.page,m.cursor,YD_SHARD_PAGE_ROWS,YD_SHARD_PAGE_BYTES)||strcmp(out.snapshot,m.snapshot)){yd_shard_page_free(&out.page);
            return YD_SHARD_CORRUPT;
        }
        for(size_t i=0;i<out.page.count;i++){YDValue *v=NULL;
            bool ok=row_valid(p,&range,&out.page.rows[i],&v);
            yd_free(v);
            if(!ok){yd_shard_page_free(&out.page);
                return YD_SHARD_CORRUPT;
            }}
        req.operation=YD_SHARD_RPC_STAGE;
        req.page=&out.page;
        YDShardResponse ack={0};
        s=call(r,m.target,&req,&ack);
        yd_shard_page_free(&ack.page);
        if(s==YD_SHARD_OK){if(out.page.count)strcpy(m.cursor,out.page.rows[out.page.count-1].id);
            m.rows+=out.page.count;
            m.bytes+=out.page.bytes;
            m.copied=out.page.end;
        }
        yd_shard_page_free(&out.page);
        return s==YD_SHARD_OK?publish(r,&m):s;
    }
    if(m.phase==YD_SHARD_SEALED){m.phase=YD_SHARD_ACTIVATING;
        return publish(r,&m);
    }
    req.operation=YD_SHARD_RPC_ACTIVATE;
    s=call(r,m.target,&req,&out);
    yd_shard_page_free(&out.page);
    if(s!=YD_SHARD_OK)return s;
    memset(&m,0,sizeof(m));
    return publish(r,&m);
}
typedef struct {YDShardRow row;
    YDValue *doc;
    char shard[64];
} GatherRow;
static int compare(const GatherRow *a,const GatherRow *b,const YDShardQuery *q){
    int n=q->sort_field?yd_compare(yd_path(a->doc,q->sort_field),yd_path(b->doc,q->sort_field)):0;
    if(q->descending)n=-n;
    if(!n)n=strcmp(a->row.id,b->row.id);
    if(!n)n=strcmp(a->shard,b->shard);
    return n;
}
static void merge(GatherRow *a,GatherRow *b,size_t first,size_t end,const YDShardQuery *q){
    if(end-first<2)return;
    size_t mid=first+(end-first)/2;
    merge(a,b,first,mid,q);
    merge(a,b,mid,end,q);
    size_t i=first,j=mid,k=first;
    while(i<mid||j<end)b[k++]=(j==end||(i<mid&&compare(&a[i],&a[j],q)<=0))?a[i++]:a[j++];
    for(i=first;i<end;i++)a[i]=b[i];
}
YDShardStatus yd_shard_gather(YDShardRouter *r,const char *placement_id,const char *collection,uint64_t epoch,const YDShardQuery *q,YDShardResult *out){
    if(!out)return YD_SHARD_INVALID_ARGUMENT;
    memset(out,0,sizeof(*out));
    YDShardStatus s=access(r,placement_id,collection,epoch,false);
    if(s!=YD_SHARD_OK)return s;
    if(!q||!q->limit||q->limit>YD_SHARD_GATHER_ROWS||q->offset>YD_SHARD_GATHER_ROWS||!q->max_rows||q->max_rows>YD_SHARD_GATHER_ROWS||!q->max_bytes||q->max_bytes>YD_SHARD_GATHER_BYTES||(q->sort_field&&strnlen(q->sort_field,256)>255))return YD_SHARD_INVALID_ARGUMENT;
    if(q->only&&q->only_count!=yd_shard_placement_ranges(yd_shard_control_placement(r->control)))return YD_SHARD_INVALID_ARGUMENT;
    size_t contacted=0;
    GatherRow *rows=calloc(q->max_rows,sizeof(*rows)),*tmp=calloc(q->max_rows,sizeof(*tmp));
    if(!rows||!tmp){free(rows);
        free(tmp);
        return YD_SHARD_RESOURCE_FAILURE;
    }
    size_t count=0;
    uint64_t visited=0,bytes=0;
    size_t resident=0;
    const YDShardPlacement *p=yd_shard_control_placement(r->control);
    YDShardMigration migration=yd_shard_control_migration(r->control);
    for(size_t shard=0;shard<yd_shard_placement_ranges(p);shard++){
        if(q->only&&!q->only[shard])continue;
        contacted++;
        YDShardRange range;
        yd_shard_placement_range(p,shard,&range);
        char cursor[256]="",snapshot[65]="";
        bool end=false;
        while(!end){
            YDShardRequest req={.operation=YD_SHARD_RPC_SCAN,.placement=p,.range=range,.migration=migration,.after=cursor,.snapshot=snapshot,.max_rows=YD_SHARD_PAGE_ROWS,.max_bytes=YD_SHARD_PAGE_BYTES};
            YDShardResponse response={0};
            s=call(r,range.group,&req,&response);
            if(s!=YD_SHARD_OK)goto done;
            if(!page_valid(&response.page,cursor,YD_SHARD_PAGE_ROWS,YD_SHARD_PAGE_BYTES)||strnlen(response.snapshot,65)!=64||(snapshot[0]&&strcmp(snapshot,response.snapshot))){yd_shard_page_free(&response.page);
                s=YD_SHARD_CORRUPT;
                goto done;
            }
            strcpy(snapshot,response.snapshot);
            end=response.page.end;
            for(size_t i=0;i<response.page.count;i++){
                YDShardRow *row=&response.page.rows[i];
                YDValue *doc=NULL;
                if(cancelled(r)){s=YD_SHARD_CANCELLED;
                    goto page_done;
                }
                if(!row_valid(p,&range,row,&doc)){s=YD_SHARD_CORRUPT;
                    goto page_done;
                }
                if(visited>=q->max_rows||row->length>q->max_bytes-bytes){yd_free(doc);
                    s=YD_SHARD_BUDGET_EXCEEDED;
                    goto page_done;
                }
                visited++;
                bytes+=row->length;
                strcpy(cursor,row->id);
                if(q->matches&&!q->matches(q->match_context,doc)){yd_free(doc);
                    continue;
                }
                size_t memory=yd_memory(doc)+row->length+sizeof(GatherRow);
                if(memory>q->max_bytes-resident){yd_free(doc);s=YD_SHARD_BUDGET_EXCEEDED;goto page_done;}
                resident+=memory;
                rows[count].row=*row;
                row->source=NULL;
                rows[count].doc=doc;
                strcpy(rows[count].shard,range.shard);
                count++;
            }
            page_done: yd_shard_page_free(&response.page);
            if(s!=YD_SHARD_OK)goto done;
        }
    }
    merge(rows,tmp,0,count,q);
    size_t first=q->offset<count?q->offset:count,take=count-first;
    if(take>q->limit)take=q->limit;
    if(take){out->page.rows=calloc(take,sizeof(*out->page.rows));
        if(!out->page.rows){s=YD_SHARD_RESOURCE_FAILURE;
            goto done;
        }}
    for(size_t i=0;i<take;i++){out->page.rows[i]=rows[first+i].row;
        rows[first+i].row.source=NULL;
        out->page.bytes+=out->page.rows[i].length;
    }
    out->page.count=take;
    out->page.end=first+take==count;
    out->matched=count;
    out->visited=visited;
    out->bytes=bytes;
    out->shards=contacted;
    done:
    for(size_t i=0;i<count;i++){free(rows[i].row.source);
        yd_free(rows[i].doc);
    }free(rows);
    free(tmp);
    if(s!=YD_SHARD_OK){yd_shard_page_free(&out->page);
        memset(out,0,sizeof(*out));
    }return s;
}
/* Resume token: "ysf1." + hex(1 | placement id (16 bytes) | epoch | shard
 * count (u16) | layout digest (8) | per shard in range order: sequence, hash
 * prefix (8)). Ranges never split or merge within a placement; migrations
 * change only their groups, so the layout digest survives every migration. */
typedef struct {uint64_t sequence;unsigned char hash[8];} FeedPosition;
static void be64(unsigned char *p,uint64_t n){for(unsigned i=0;i<8;i++)p[i]=(unsigned char)(n>>(56-8*i));}
static uint64_t un64(const unsigned char *p){uint64_t n=0;for(unsigned i=0;i<8;i++)n=(n<<8)|p[i];return n;}
static int hexval(char c){return c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:-1;}
static bool unhex(const char *t,size_t bytes,unsigned char *out){
    if(strnlen(t,2*bytes)<2*bytes)return false;
    for(size_t i=0;i<bytes;i++){int a=hexval(t[2*i]),b=a<0?-1:hexval(t[2*i+1]);if(b<0)return false;out[i]=(unsigned char)(a*16+b);}
    return true;
}
static void tohex(const unsigned char *b,size_t n,char *out){for(size_t i=0;i<n;i++)snprintf(out+2*i,3,"%02x",b[i]);}
static bool layout_digest(const YDShardPlacement *p,unsigned char out[8]){
    EVP_MD_CTX *ctx=EVP_MD_CTX_new();unsigned char hash[32];unsigned size=0;
    bool ok=ctx&&EVP_DigestInit_ex(ctx,EVP_sha256(),NULL)==1&&EVP_DigestUpdate(ctx,"YSFL",4)==1;
    for(size_t i=0;ok&&i<yd_shard_placement_ranges(p);i++){YDShardRange r;unsigned char bounds[16];
        ok=yd_shard_placement_range(p,i,&r);be64(bounds,r.first);be64(bounds+8,r.last);
        ok=ok&&EVP_DigestUpdate(ctx,r.shard,strlen(r.shard)+1)==1&&EVP_DigestUpdate(ctx,bounds,16)==1;
    }
    ok=ok&&EVP_DigestFinal_ex(ctx,hash,&size)==1&&size==32;
    EVP_MD_CTX_free(ctx);
    if(ok)memcpy(out,hash,8);
    return ok;
}
static char *token_encode(const YDShardPlacement *p,const unsigned char layout[8],const FeedPosition *pos,size_t n){
    size_t body=35+16*n;unsigned char *b=malloc(body);char *t=malloc(5+2*body+1);
    if(!b||!t||!unhex(yd_shard_placement_id(p),16,b+1)){free(b);free(t);return NULL;}
    b[0]=1;be64(b+17,yd_shard_placement_epoch(p));b[25]=(unsigned char)(n>>8);b[26]=(unsigned char)n;memcpy(b+27,layout,8);
    for(size_t i=0;i<n;i++){be64(b+35+16*i,pos[i].sequence);memcpy(b+43+16*i,pos[i].hash,8);}
    memcpy(t,"ysf1.",5);tohex(b,body,t+5);free(b);
    return t;
}
/* Malformed text is INVALID_ARGUMENT; a well-formed token for another
 * placement or layout is CONFLICT; one issued after this router's state is
 * STALE_PLACEMENT (refresh and retry). */
static YDShardStatus token_decode(const char *t,const YDShardPlacement *p,const unsigned char layout[8],FeedPosition *pos,size_t n){
    size_t length=strnlen(t,YD_SHARD_TOKEN_LIMIT);
    if(length>=YD_SHARD_TOKEN_LIMIT||length<5||memcmp(t,"ysf1.",5)||(length-5)%2)return YD_SHARD_INVALID_ARGUMENT;
    size_t body=(length-5)/2;
    if(body<35||(body-35)%16)return YD_SHARD_INVALID_ARGUMENT;
    unsigned char *b=malloc(body),id[16];
    if(!b)return YD_SHARD_RESOURCE_FAILURE;
    YDShardStatus s=YD_SHARD_OK;
    bool parsed=unhex(t+5,body,b);
    size_t count=parsed?((size_t)b[25]<<8)|b[26]:0;
    uint64_t epoch=parsed?un64(b+17):0;
    if(!parsed||b[0]!=1||body!=35+16*count||!epoch||epoch>INT64_MAX)s=YD_SHARD_INVALID_ARGUMENT;
    else if(!unhex(yd_shard_placement_id(p),16,id)||memcmp(id,b+1,16)||count!=n||memcmp(b+27,layout,8))s=YD_SHARD_CONFLICT;
    else if(epoch>yd_shard_placement_epoch(p))s=YD_SHARD_STALE_PLACEMENT;
    for(size_t i=0;s==YD_SHARD_OK&&i<n;i++){
        pos[i].sequence=un64(b+35+16*i);memcpy(pos[i].hash,b+43+16*i,8);
        if(pos[i].sequence>INT64_MAX)s=YD_SHARD_INVALID_ARGUMENT;
    }
    free(b);
    return s;
}
void yd_shard_changes_free(YDShardChanges *c){
    if(!c)return;
    for(size_t i=0;i<c->count;i++)free(c->changes[i].source);
    free(c->changes);free(c->next);memset(c,0,sizeof(*c));
}
/* Accept one shard's page only as the exact continuation of its position. */
static YDShardStatus feed_page(const YDShardRange *range,const YDShardPage *page,size_t want,FeedPosition *pos,YDShardChanges *out){
    if(page->count>want||(page->count&&!page->rows)||(!page->count&&!page->end))return YD_SHARD_CORRUPT;
    for(size_t i=0;i<page->count;i++){
        const YDShardRow *row=&page->rows[i];YDShardLogRecord r;char id[17];uint64_t token=0;
        if(!yd_shard_log_decode(row->source,row->length,&r)||r.sequence!=pos->sequence+1||memcmp(r.previous,pos->hash,8))return YD_SHARD_CORRUPT;
        snprintf(id,sizeof(id),"%016llx",(unsigned long long)r.sequence);
        if(strcmp(id,row->id)||yd_shard_key_token(&r.key,&token)!=YD_SHARD_OK||token<range->first||token>range->last)return YD_SHARD_CORRUPT;
        YDShardChange *c=&out->changes[out->count];
        memset(c,0,sizeof(*c));
        if(r.length&&!(c->source=malloc(r.length)))return YD_SHARD_RESOURCE_FAILURE;
        if(r.length)memcpy(c->source,r.source,r.length);
        c->length=r.length;out->count++;
        strcpy(c->shard,range->shard);strcpy(c->id,r.id);
        c->sequence=r.sequence;c->epoch=r.epoch;c->deleted=r.deleted;c->key=r.key;
        out->bytes+=row->length;
        pos->sequence=r.sequence;memcpy(pos->hash,r.hash,8);
    }
    return YD_SHARD_OK;
}
YDShardStatus yd_shard_changes(YDShardRouter *r,const char *placement_id,const char *collection,uint64_t epoch,const char *after,size_t limit,size_t max_bytes,YDShardChanges *out){
    if(!out)return YD_SHARD_INVALID_ARGUMENT;
    memset(out,0,sizeof(*out));
    YDShardStatus s=access(r,placement_id,collection,epoch,false);
    if(s!=YD_SHARD_OK)return s;
    const YDShardPlacement *p=yd_shard_control_placement(r->control);
    if(yd_shard_placement_version(p)<2)return YD_SHARD_UNSUPPORTED_METADATA;
    if(!limit||limit>YD_SHARD_CHANGES_LIMIT||!max_bytes||max_bytes>YD_SHARD_CHANGES_BYTES)return YD_SHARD_INVALID_ARGUMENT;
    size_t n=yd_shard_placement_ranges(p);
    FeedPosition *pos=calloc(n,sizeof(*pos));
    unsigned char layout[8];
    bool resume=after&&after[0];
    if(!pos||!layout_digest(p,layout)||(resume&&!(out->changes=calloc(limit,sizeof(*out->changes))))){s=YD_SHARD_RESOURCE_FAILURE;goto done;}
    if(resume&&(s=token_decode(after,p,layout,pos,n))!=YD_SHARD_OK)goto done;
    YDShardMigration migration=yd_shard_control_migration(r->control);
    size_t quota=limit/n?limit/n:1,bytes_left=max_bytes;
    for(size_t i=0;i<n;i++){
        YDShardRange range;yd_shard_placement_range(p,i,&range);
        char text[33]="";
        size_t want=resume?limit-out->count:1;
        if(want>quota)want=quota;
        if(want>YD_SHARD_PAGE_ROWS)want=YD_SHARD_PAGE_ROWS;
        if(resume){
            if(!want||!bytes_left){out->more=true;continue;}
            snprintf(text,17,"%016llx",(unsigned long long)pos[i].sequence);tohex(pos[i].hash,8,text+16);
        }
        YDShardRequest req={.operation=YD_SHARD_RPC_LOG,.placement=p,.range=range,.migration=migration,.after=text,
            .max_rows=want,.max_bytes=resume?bytes_left:YD_SHARD_PAGE_BYTES};
        YDShardResponse response;
        s=call(r,range.group,&req,&response);
        /* A record larger than the bytes left waits for the next page; only
         * a page that cannot hold even one record is an error. */
        if(s==YD_SHARD_BUDGET_EXCEEDED&&resume&&bytes_left<max_bytes){s=YD_SHARD_OK;out->more=true;continue;}
        if(s!=YD_SHARD_OK)goto done;
        unsigned char tail[24];  /* last sequence, then a hash prefix */
        if(strnlen(response.snapshot,65)!=64||!unhex(response.snapshot+16,24,tail)||un64(tail)>INT64_MAX){
            yd_shard_page_free(&response.page);s=YD_SHARD_CORRUPT;goto done;
        }
        if(!resume){
            pos[i].sequence=un64(tail);memcpy(pos[i].hash,tail+8,8);
            s=response.page.count?YD_SHARD_CORRUPT:YD_SHARD_OK;
        } else {
            s=response.page.bytes>bytes_left?YD_SHARD_CORRUPT:feed_page(&range,&response.page,want,pos+i,out);
            if(s==YD_SHARD_OK){bytes_left-=response.page.bytes;out->more|=!response.page.end;}
        }
        yd_shard_page_free(&response.page);
        if(s!=YD_SHARD_OK)goto done;
    }
    out->next=token_encode(p,layout,pos,n);
    if(!out->next){s=YD_SHARD_RESOURCE_FAILURE;goto done;}
    out->epoch=yd_shard_placement_epoch(p);
    out->shards=n;
done:
    free(pos);
    if(s!=YD_SHARD_OK)yd_shard_changes_free(out);
    return s;
}
