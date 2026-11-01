#define _POSIX_C_SOURCE 200809L
#include "runtime.h"
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* All persisted records use explicit bytes, not ABI structs. The active pointer
* atomically selects one immutable namespace, so cutover never scans data. */
struct YDShardNative {YDDisk *disk;
    YDShardControl *control;
    char group[64];
    YDDiskView views[256];
    char tokens[256][65];
    size_t next;
    const YDDiskView *at;
    bool preparing;
    YDDiskTxn *prepared;
};
static YDDiskView native_view(YDShardNative *n) {
    return n->at?*n->at:yd_disk_view(n->disk);
}
static YDShardStatus finish(YDShardNative *n,YDDiskTxn *tx) {
    if(n->preparing){n->prepared=tx;return YD_SHARD_OK;}
    return yd_disk_commit(tx,NULL,0)?YD_SHARD_OK:YD_SHARD_UNAVAILABLE;
}
typedef struct {char migration[33],snapshot[65],cursor[256],previous[256];
    uint64_t rows,bytes;
    unsigned char hash[32];
    unsigned state;
} Stage;
#define STAGE_SIZE (33U+65U+256U+256U+16U+32U+1U)
static void put64(unsigned char *p,uint64_t n){for(unsigned i=0;i<8;i++)p[i]=(unsigned char)(n>>(56-8*i));
}
static uint64_t get64(const unsigned char *p){uint64_t n=0;
    for(unsigned i=0;i<8;i++)n=(n<<8)|p[i];
    return n;
}
static bool ident(const char *s){if(!s||!s[0]||strnlen(s,256)>255)return false;
    for(size_t i=0;s[i];i++)if((unsigned char)s[i]<33||(unsigned char)s[i]>126||s[i]=='/'||s[i]=='\\')return false;
    return true;
}
static bool valid_group(const char *s){if(!s||!s[0]||strnlen(s,64)>63)return false;
    for(size_t i=0;s[i];i++)if(!((s[i]>='a'&&s[i]<='z')||(s[i]>='0'&&s[i]<='9')||s[i]=='-'))return false;
    return true;
}
static void stage_encode(const Stage *s,unsigned char b[STAGE_SIZE]){size_t k=0;
    memset(b,0,STAGE_SIZE);
#define ENC(f) memcpy(b+k,s->f,sizeof(s->f));k+=sizeof(s->f)
    ENC(migration);
    ENC(snapshot);
    ENC(cursor);
    ENC(previous);
#undef ENC
    put64(b+k,s->rows);
    k+=8;
    put64(b+k,s->bytes);
    k+=8;
    memcpy(b+k,s->hash,32);
    k+=32;
    b[k]=(unsigned char)s->state;
}
static bool stage_decode(const unsigned char *b,size_t n,Stage *s){if(n!=STAGE_SIZE)return false;
    size_t k=0;
    memset(s,0,sizeof(*s));
#define DEC(f) if(!memchr(b+k,0,sizeof(s->f)))return false;memcpy(s->f,b+k,sizeof(s->f));k+=sizeof(s->f)
    DEC(migration);
    DEC(snapshot);
    DEC(cursor);
    DEC(previous);
#undef DEC
    s->rows=get64(b+k);
    k+=8;
    s->bytes=get64(b+k);
    k+=8;
    memcpy(s->hash,b+k,32);
    k+=32;
    s->state=b[k];
    return s->state<=3&&strnlen(s->migration,33)==32&&strnlen(s->snapshot,65)==64;
}
static void token(YDDiskView v,char out[65]){snprintf(out,65,"%016llx%016llx%016llx%016llx",(unsigned long long)v.generation,(unsigned long long)v.root,(unsigned long long)v.end,(unsigned long long)v.revision);
}
/* Replicas and restored roots can have different physical layouts. The local
 * durable fence makes this partition immutable, so a logical identity binds
 * its frozen content while scans use their current confirmed native view. */
static bool freeze_token(YDShardNative *n,const YDShardRequest *q,char out[65]) {
    EVP_MD_CTX *ctx=EVP_MD_CTX_new();unsigned char hash[32],epoch[8];unsigned size=0;
    put64(epoch,yd_shard_placement_epoch(q->placement));
    const char *collection=yd_shard_placement_collection(q->placement);
    bool ok=ctx&&EVP_DigestInit_ex(ctx,EVP_sha256(),NULL)==1&&
        EVP_DigestUpdate(ctx,"YSF1",4)==1&&
        EVP_DigestUpdate(ctx,yd_shard_placement_id(q->placement),33)==1&&
        EVP_DigestUpdate(ctx,collection,strlen(collection)+1)==1&&
        EVP_DigestUpdate(ctx,n->group,strlen(n->group)+1)==1&&
        EVP_DigestUpdate(ctx,q->range.shard,strlen(q->range.shard)+1)==1&&
        EVP_DigestUpdate(ctx,epoch,sizeof(epoch))==1&&
        EVP_DigestUpdate(ctx,q->migration.migration,33)==1&&
        EVP_DigestFinal_ex(ctx,hash,&size)==1&&size==32;
    EVP_MD_CTX_free(ctx);
    if(ok)for(size_t i=0;i<32;i++)snprintf(out+i*2,3,"%02x",hash[i]);
    return ok;
}
static void key(char *out,size_t size,const char *kind,const char *shard,const char *id){snprintf(out,size,"\001YS/%s/%s/%s",kind,shard,id?id:"");
}
static int record(YDShardNative *n,YDDiskView view,const char *k,unsigned char **bytes,size_t *size){uint64_t offset;
    *bytes=NULL;
    *size=0;
    int found=yd_disk_get(n->disk,&view,k,strlen(k),&offset,NULL,0);
    if(found!=1)return found;
    *bytes=yd_disk_record(n->disk,&view,offset,size,NULL,0);
    return *bytes?1:-1;
}
static bool put(YDDiskTxn *tx,const char *k,const void *b,size_t size){uint64_t offset;
    return yd_disk_append(tx,b,size,&offset,NULL,0)&&yd_disk_put(tx,k,strlen(k),offset,NULL,0);
}
static int stage_get(YDShardNative *n,const char *shard,const char *kind,Stage *s){char k[128];
    key(k,sizeof(k),kind,shard,NULL);
    unsigned char *b=NULL;
    size_t size;
    int found=record(n,native_view(n),k,&b,&size);
    if(found==1&&!stage_decode(b,size,s))found=-1;
    free(b);
    return found;
}
static bool stage_put(YDDiskTxn *tx,const char *shard,const char *kind,const Stage *s){char k[128];
    unsigned char b[STAGE_SIZE];
    key(k,sizeof(k),kind,shard,NULL);
    stage_encode(s,b);
    return put(tx,k,b,sizeof(b));
}
static bool active_prefix(YDShardNative *n,YDDiskView view,const char *shard,char out[160]){
    char k[128];
    key(k,sizeof(k),"active",shard,NULL);
    unsigned char *b=NULL;
    size_t size;
    int f=record(n,view,k,&b,&size);
    if(f<0)return false;
    if(!f){key(out,160,"data",shard,"");
        return true;
    }
    bool ok=size==33&&b[32]==0&&strnlen((char*)b,33)==32;
    if(ok)key(out,160,"stage",(char*)b,"");
    free(b);
    return ok;
}
/* This local fence is atomic with FREEZE/ACTIVATE, unlike the independently
 * read control-group state carried by a queued replicated command. */
static bool owner_put(YDDiskTxn *tx,const YDShardRequest *q,bool active) {
    char k[128];unsigned char b[9];key(k,sizeof(k),"owner",q->range.shard,NULL);
    put64(b,yd_shard_placement_epoch(q->placement));b[8]=(unsigned char)active;
    return put(tx,k,b,sizeof(b));
}
static YDShardStatus owner_check(YDShardNative *n,const YDShardRequest *q) {
    char k[128];key(k,sizeof(k),"owner",q->range.shard,NULL);
    unsigned char *b=NULL;size_t size;
    int f=record(n,native_view(n),k,&b,&size);
    if(f<0)return YD_SHARD_UNAVAILABLE;
    if(!f)return YD_SHARD_OK;
    bool valid=size==9&&get64(b)>0&&get64(b)<=INT64_MAX&&b[8]<=1;
    YDShardStatus status=!valid?YD_SHARD_CORRUPT:
        yd_shard_placement_epoch(q->placement)<get64(b)?YD_SHARD_STALE_PLACEMENT:
        !b[8]?YD_SHARD_MIGRATING:YD_SHARD_OK;
    free(b);return status;
}
/* Change log of a version-2 placement. Entries \001YS/log/<shard>/<seq hex>
 * hold YSL1 records; \001YS/feed/<shard>/ holds the retained window and
 * \001YS/lstage/<shard>/ a migration target's import progress. An empty log
 * starts from a hash of the placement, collection and shard, so a position
 * never verifies against another placement's shard of the same name. */
static bool hex_text(const char *text,size_t length);
typedef struct {uint64_t first,last,bytes;unsigned char floor[32],hash[32];} LogMeta;
typedef struct {char migration[33];LogMeta m;bool initialized,complete;} LogStage;
#define LOG_META_SIZE 92U
#define LOG_STAGE_SIZE (4U+33U+88U+2U)
static int nibble(char c){return c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:-1;}
static bool unhex(const char *t,size_t bytes,unsigned char *out){
    if(strnlen(t,2*bytes)<2*bytes)return false;
    for(size_t i=0;i<bytes;i++){int a=nibble(t[2*i]),b=a<0?-1:nibble(t[2*i+1]);if(b<0)return false;out[i]=(unsigned char)(a*16+b);}
    return true;
}
static bool seq_text(const char *t,uint64_t *out){unsigned char b[8];if(!unhex(t,8,b))return false;*out=get64(b);return *out<=INT64_MAX;}
static void hex_out(const unsigned char *b,size_t n,char *out){for(size_t i=0;i<n;i++)snprintf(out+2*i,3,"%02x",b[i]);}
static void log_key(char *out,size_t size,const char *shard,uint64_t seq){
    char id[17];snprintf(id,sizeof(id),"%016llx",(unsigned long long)seq);key(out,size,"log",shard,id);
}
static bool log_origin(const YDShardRequest *q,unsigned char out[32]){
    const char *id=yd_shard_placement_id(q->placement),*collection=yd_shard_placement_collection(q->placement);
    EVP_MD_CTX *ctx=EVP_MD_CTX_new();unsigned size=0;
    bool ok=ctx&&EVP_DigestInit_ex(ctx,EVP_sha256(),NULL)==1&&EVP_DigestUpdate(ctx,"YSL0",4)==1&&
        EVP_DigestUpdate(ctx,id,strlen(id)+1)==1&&EVP_DigestUpdate(ctx,collection,strlen(collection)+1)==1&&
        EVP_DigestUpdate(ctx,q->range.shard,strlen(q->range.shard)+1)==1&&EVP_DigestFinal_ex(ctx,out,&size)==1&&size==32;
    EVP_MD_CTX_free(ctx);return ok;
}
static void meta_encode(const LogMeta *m,unsigned char *b){
    memcpy(b,"YSLM",4);put64(b+4,m->first);put64(b+12,m->last);put64(b+20,m->bytes);memcpy(b+28,m->floor,32);memcpy(b+60,m->hash,32);
}
static bool meta_decode(const unsigned char *b,size_t n,LogMeta *m){
    if(n!=LOG_META_SIZE||memcmp(b,"YSLM",4))return false;
    m->first=get64(b+4);m->last=get64(b+12);m->bytes=get64(b+20);memcpy(m->floor,b+28,32);memcpy(m->hash,b+60,32);
    if(!m->first||m->last>INT64_MAX||m->last+1<m->first||m->last-m->first+1>YD_SHARD_LOG_ENTRIES||m->bytes>YD_SHARD_LOG_BYTES)return false;
    return m->last>=m->first?m->bytes>0:!m->bytes&&!memcmp(m->floor,m->hash,32);
}
static int meta_get(YDShardNative *n,YDDiskView view,const YDShardRequest *q,LogMeta *m){
    char k[128];key(k,sizeof(k),"feed",q->range.shard,NULL);
    unsigned char *b=NULL;size_t size;int f=record(n,view,k,&b,&size);
    if(f<0)return -1;
    if(!f){memset(m,0,sizeof(*m));m->first=1;if(!log_origin(q,m->floor))return -1;memcpy(m->hash,m->floor,32);return 0;}
    bool ok=meta_decode(b,size,m);free(b);return ok?1:-1;
}
static bool meta_put(YDDiskTxn *tx,const char *shard,const LogMeta *m){
    char k[128];unsigned char b[LOG_META_SIZE];key(k,sizeof(k),"feed",shard,NULL);meta_encode(m,b);return put(tx,k,b,sizeof(b));
}
static void log_stage_encode(const LogStage *s,unsigned char *b){
    memset(b,0,LOG_STAGE_SIZE);memcpy(b,"YSLS",4);memcpy(b+4,s->migration,33);
    unsigned char meta[LOG_META_SIZE];meta_encode(&s->m,meta);memcpy(b+37,meta+4,88);
    b[125]=(unsigned char)s->initialized;b[126]=(unsigned char)s->complete;
}
static bool log_stage_decode(const unsigned char *b,size_t n,LogStage *s){
    if(n!=LOG_STAGE_SIZE||memcmp(b,"YSLS",4)||!memchr(b+4,0,33)||b[125]>1||b[126]>1||(b[126]&&!b[125]))return false;
    memset(s,0,sizeof(*s));memcpy(s->migration,b+4,33);
    unsigned char meta[LOG_META_SIZE];memcpy(meta,"YSLM",4);memcpy(meta+4,b+37,88);
    s->initialized=b[125];s->complete=b[126];
    if(!hex_text(s->migration,32))return false;
    if(!s->initialized){unsigned char zero[88]={0};return !memcmp(b+37,zero,88);}
    return meta_decode(meta,sizeof(meta),&s->m);
}
static int log_stage_get(YDShardNative *n,YDDiskView view,const char *shard,LogStage *s){
    char k[128];key(k,sizeof(k),"lstage",shard,NULL);
    unsigned char *b=NULL;size_t size;int f=record(n,view,k,&b,&size);
    if(f==1&&!log_stage_decode(b,size,s))f=-1;
    free(b);return f;
}
static bool log_stage_put(YDDiskTxn *tx,const char *shard,const LogStage *s){
    char k[128];unsigned char b[LOG_STAGE_SIZE];key(k,sizeof(k),"lstage",shard,NULL);log_stage_encode(s,b);return put(tx,k,b,sizeof(b));
}
/* YSL1 | seq | epoch | op (1 write, 2 delete) | u16 id | u16 key | u32 source
 * | previous hash | SHA-256 of every preceding byte. */
static unsigned char *log_encode(uint64_t seq,const YDShardRequest *q,const unsigned char previous[32],size_t *size){
    size_t idn=strlen(q->id),src=q->operation==YD_SHARD_RPC_WRITE?q->length:0,kn=q->key->length;
    size_t n=4+8+8+1+2+idn+2+kn+4+src+64,k=0;
    unsigned char *b=malloc(n);if(!b)return NULL;
    memcpy(b,"YSL1",4);k=4;put64(b+k,seq);k+=8;put64(b+k,yd_shard_placement_epoch(q->placement));k+=8;
    b[k++]=q->operation==YD_SHARD_RPC_DELETE?2:1;
    b[k++]=(unsigned char)(idn>>8);b[k++]=(unsigned char)idn;memcpy(b+k,q->id,idn);k+=idn;
    b[k++]=(unsigned char)(kn>>8);b[k++]=(unsigned char)kn;memcpy(b+k,q->key->bytes,kn);k+=kn;
    for(unsigned i=0;i<4;i++)b[k++]=(unsigned char)(src>>(24-8*i));
    if(src){memcpy(b+k,q->source,src);k+=src;}
    memcpy(b+k,previous,32);k+=32;
    unsigned hn=0;
    if(EVP_Digest(b,k,b+k,&hn,EVP_sha256(),NULL)!=1||hn!=32){free(b);return NULL;}
    *size=n;return b;
}
bool yd_shard_log_decode(const unsigned char *b,size_t n,YDShardLogRecord *r){
    if(!b||!r||n<4+8+8+1+2+2+4+64||n>YD_SHARD_LOG_RECORD||memcmp(b,"YSL1",4))return false;
    memset(r,0,sizeof(*r));size_t k=4;
    r->sequence=get64(b+k);k+=8;r->epoch=get64(b+k);k+=8;
    unsigned op=b[k++];size_t idn=((size_t)b[k]<<8)|b[k+1];k+=2;
    if(op<1||op>2||!r->sequence||r->sequence>INT64_MAX||!r->epoch||r->epoch>INT64_MAX||!idn||idn>255||n-k<idn+2)return false;
    memcpy(r->id,b+k,idn);r->id[idn]=0;k+=idn;
    if(strlen(r->id)!=idn||!ident(r->id))return false;
    size_t kn=((size_t)b[k]<<8)|b[k+1];k+=2;
    if(n-k<kn+4||yd_shard_key_decode(b+k,kn,&r->key)!=YD_SHARD_OK)return false;
    k+=kn;
    size_t src=((size_t)b[k]<<24)|((size_t)b[k+1]<<16)|((size_t)b[k+2]<<8)|b[k+3];k+=4;
    if(n-k!=src+64)return false;
    r->deleted=op==2;
    if(r->deleted?src!=0:(!src||src>YD_DOCUMENT_LIMIT))return false;
    r->source=src?b+k:NULL;r->length=src;k+=src;
    memcpy(r->previous,b+k,32);memcpy(r->hash,b+k+32,32);
    unsigned char check[32];unsigned hn=0;
    return EVP_Digest(b,k+32,check,&hn,EVP_sha256(),NULL)==1&&hn==32&&!memcmp(check,r->hash,32);
}
/* Appends in the change's own transaction; retention prunes oldest entries
 * there too, so the window and its floor hash never disagree with the log. */
static bool log_append(YDShardNative *n,YDDiskView view,YDDiskTxn *tx,const YDShardRequest *q){
    LogMeta m;
    if(meta_get(n,view,q,&m)<0||m.last>=INT64_MAX)return false;
    size_t size=0;unsigned char *b=log_encode(m.last+1,q,m.hash,&size);
    if(!b)return false;
    char k[128];log_key(k,sizeof(k),q->range.shard,m.last+1);
    bool ok=put(tx,k,b,size);
    m.last++;memcpy(m.hash,b+size-32,32);m.bytes+=size;free(b);
    while(ok&&m.first<m.last&&(m.last-m.first+1>YD_SHARD_LOG_ENTRIES||m.bytes>YD_SHARD_LOG_BYTES)){
        log_key(k,sizeof(k),q->range.shard,m.first);
        unsigned char *old=NULL;size_t on=0;YDShardLogRecord r;
        int f=record(n,view,k,&old,&on);
        ok=f==1&&yd_shard_log_decode(old,on,&r)&&r.sequence==m.first&&on<=m.bytes&&yd_disk_delete(tx,k,strlen(k),NULL,0);
        if(ok){memcpy(m.floor,r.hash,32);m.bytes-=on;m.first++;}
        free(old);
    }
    return ok&&meta_put(tx,q->range.shard,&m);
}
static YDShardStatus log_hash_at(YDShardNative *n,YDDiskView view,const YDShardRequest *q,const LogMeta *m,uint64_t seq,unsigned char out[32]){
    if(seq+1==m->first){memcpy(out,m->floor,32);return YD_SHARD_OK;}
    char k[128];log_key(k,sizeof(k),q->range.shard,seq);
    unsigned char *b=NULL;size_t size;int f=record(n,view,k,&b,&size);
    if(f<0)return YD_SHARD_UNAVAILABLE;
    YDShardLogRecord r;bool ok=f&&yd_shard_log_decode(b,size,&r)&&r.sequence==seq;
    if(ok)memcpy(out,r.hash,32);
    free(b);return ok?YD_SHARD_OK:YD_SHARD_CORRUPT;
}
/* after: "" tail only; "*" from the oldest retained entry (migration copy);
 * else 16 hex sequence + 16 hex hash prefix, verified before any entry.
 * The snapshot field returns first, last and a 16-byte prefix of the tail
 * hash, all hex. */
static YDShardStatus log_read(YDShardNative *n,const YDShardRequest *q,YDShardResponse *out){
    if(yd_shard_placement_version(q->placement)<2)return YD_SHARD_UNSUPPORTED_METADATA;
    if(!q->after||strnlen(q->after,256)>255||!q->max_rows||q->max_rows>YD_SHARD_PAGE_ROWS||!q->max_bytes||q->max_bytes>YD_SHARD_PAGE_BYTES)return YD_SHARD_INVALID_ARGUMENT;
    YDDiskView view=native_view(n);LogMeta m;
    if(meta_get(n,view,q,&m)<0)return YD_SHARD_CORRUPT;
    snprintf(out->snapshot,33,"%016llx%016llx",(unsigned long long)m.first,(unsigned long long)m.last);
    hex_out(m.hash,16,out->snapshot+32);
    out->page.end=true;
    if(!q->after[0])return YD_SHARD_OK;
    uint64_t from;unsigned char previous[32];
    if(!strcmp(q->after,"*")){from=m.first-1;memcpy(previous,m.floor,32);}
    else{
        unsigned char prefix[8];
        if(strlen(q->after)!=32||!seq_text(q->after,&from)||!unhex(q->after+16,8,prefix))return YD_SHARD_INVALID_ARGUMENT;
        if(from>m.last)return YD_SHARD_CONFLICT;
        if(from+1<m.first)return YD_SHARD_EXPIRED;
        YDShardStatus s=log_hash_at(n,view,q,&m,from,previous);
        if(s!=YD_SHARD_OK)return s;
        if(memcmp(previous,prefix,8))return YD_SHARD_CONFLICT;
    }
    if(from==m.last)return YD_SHARD_OK;
    out->page.rows=calloc(q->max_rows,sizeof(YDShardRow));
    if(!out->page.rows)return YD_SHARD_RESOURCE_FAILURE;
    YDShardStatus s=YD_SHARD_OK;
    for(uint64_t seq=from+1;seq<=m.last;seq++){
        if(out->page.count==q->max_rows){out->page.end=false;break;}
        char k[128];log_key(k,sizeof(k),q->range.shard,seq);
        unsigned char *b=NULL;size_t size;int f=record(n,view,k,&b,&size);
        if(f<0){s=YD_SHARD_UNAVAILABLE;break;}
        YDShardLogRecord r;
        if(!f||!yd_shard_log_decode(b,size,&r)||r.sequence!=seq||memcmp(r.previous,previous,32)){free(b);s=YD_SHARD_CORRUPT;break;}
        if(size>q->max_bytes-out->page.bytes){free(b);if(!out->page.count)s=YD_SHARD_BUDGET_EXCEEDED;else out->page.end=false;break;}
        memcpy(previous,r.hash,32);
        YDShardRow *row=&out->page.rows[out->page.count++];
        snprintf(row->id,sizeof(row->id),"%016llx",(unsigned long long)seq);
        row->source=b;row->length=size;out->page.bytes+=size;
    }
    if(s!=YD_SHARD_OK)yd_shard_page_free(&out->page);
    return s;
}
/* Migration target import. after carries the frozen source's last sequence
 * and tail hash prefix (16 + 32 hex). Entries must continue the staged chain;
 * a replayed page is a no-op. The reply is the staged tail and whether it now
 * equals the source ("-" before the first entry). SEAL requires complete. */
static YDShardStatus log_stage(YDShardNative *n,const YDShardRequest *q,YDShardResponse *out){
    if(yd_shard_placement_version(q->placement)<2)return YD_SHARD_UNSUPPORTED_METADATA;
    const YDShardPage *page=q->page;uint64_t src_last;unsigned char src_hash[16];
    if(!page||page->count>YD_SHARD_PAGE_ROWS||page->bytes>YD_SHARD_PAGE_BYTES||(page->count&&!page->rows)||!q->after||
        strnlen(q->after,64)!=48||!seq_text(q->after,&src_last)||!unhex(q->after+16,16,src_hash))return YD_SHARD_INVALID_ARGUMENT;
    YDDiskView view=native_view(n);LogStage st;
    int found=log_stage_get(n,view,q->range.shard,&st);
    if(found<0)return YD_SHARD_CORRUPT;
    bool changed=false;
    if(!found||strcmp(st.migration,q->migration.migration)){memset(&st,0,sizeof(st));strcpy(st.migration,q->migration.migration);changed=true;}
    YDDiskTxn *tx=NULL;YDShardStatus s=YD_SHARD_OK;
    for(size_t i=0;s==YD_SHARD_OK&&i<page->count;i++){
        const YDShardRow *row=&page->rows[i];YDShardLogRecord r;char id[17];uint64_t token=0;
        if(!yd_shard_log_decode(row->source,row->length,&r)){s=YD_SHARD_CORRUPT;break;}
        snprintf(id,sizeof(id),"%016llx",(unsigned long long)r.sequence);
        if(strcmp(id,row->id)||yd_shard_key_token(&r.key,&token)!=YD_SHARD_OK||token<q->range.first||token>q->range.last){s=YD_SHARD_CORRUPT;break;}
        if(!st.initialized){st.m.first=r.sequence;st.m.last=r.sequence-1;memcpy(st.m.floor,r.previous,32);memcpy(st.m.hash,r.previous,32);st.initialized=true;changed=true;}
        if(r.sequence<=st.m.last)continue;
        if(r.sequence!=st.m.last+1||memcmp(r.previous,st.m.hash,32)){s=YD_SHARD_CONFLICT;break;}
        char k[128];log_key(k,sizeof(k),q->range.shard,r.sequence);
        if((!tx&&!(tx=yd_disk_begin(n->disk,NULL,0)))||!put(tx,k,row->source,row->length)){s=YD_SHARD_UNAVAILABLE;break;}
        st.m.last++;memcpy(st.m.hash,r.hash,32);st.m.bytes+=row->length;changed=true;
    }
    if(s==YD_SHARD_OK&&!st.initialized&&!src_last){
        st.m.first=1;st.m.last=0;st.initialized=changed=true;
        if(!log_origin(q,st.m.floor))s=YD_SHARD_RESOURCE_FAILURE;
        memcpy(st.m.hash,st.m.floor,32);
    }
    if(s==YD_SHARD_OK&&st.initialized&&(st.m.last>src_last||st.m.last+1-st.m.first>YD_SHARD_LOG_ENTRIES||st.m.bytes>YD_SHARD_LOG_BYTES))s=YD_SHARD_CORRUPT;
    bool complete=st.initialized&&st.m.last==src_last&&!memcmp(st.m.hash,src_hash,16);
    if(s==YD_SHARD_OK&&st.initialized&&st.m.last==src_last&&!complete)s=YD_SHARD_CONFLICT;
    if(s==YD_SHARD_OK&&complete!=st.complete){st.complete=complete;changed=true;}
    if(s==YD_SHARD_OK&&changed&&((!tx&&!(tx=yd_disk_begin(n->disk,NULL,0)))||!log_stage_put(tx,q->range.shard,&st)))s=YD_SHARD_UNAVAILABLE;
    if(s!=YD_SHARD_OK){if(tx)yd_disk_abort(tx);return s;}
    if(st.initialized){snprintf(out->snapshot,17,"%016llx",(unsigned long long)st.m.last);hex_out(st.m.hash,16,out->snapshot+16);out->snapshot[48]=st.complete?'1':'0';out->snapshot[49]=0;}
    else strcpy(out->snapshot,"-");
    return tx?finish(n,tx):YD_SHARD_OK;
}
static bool current(YDShardNative *n,const YDShardRequest *q,YDShardRange *range){
    const YDShardPlacement *p=yd_shard_control_placement(n->control);
    if(!p||!q->placement||strcmp(yd_shard_placement_id(p),yd_shard_placement_id(q->placement))||strcmp(yd_shard_placement_collection(p),yd_shard_placement_collection(q->placement))||yd_shard_placement_epoch(p)!=yd_shard_placement_epoch(q->placement))return false;
    for(size_t i=0;i<yd_shard_placement_ranges(p);i++)if(yd_shard_placement_range(p,i,range)&&!strcmp(range->shard,q->range.shard))return range->first==q->range.first&&range->last==q->range.last&&!strcmp(range->group,q->range.group);
    return false;
}
static bool migration(YDShardNative *n,const YDShardRequest *q,YDShardMigration *m){*m=yd_shard_control_migration(n->control);
    return m->phase!=YD_SHARD_IDLE&&m->sequence==q->migration.sequence&&!strcmp(m->migration,q->migration.migration)&&!strcmp(m->shard,q->range.shard)&&!strcmp(m->source,q->migration.source)&&!strcmp(m->target,q->migration.target);
}
static bool document(const YDShardRequest *q,const unsigned char *source,size_t length,YDValue **doc){
    *doc=NULL;
    if(!source||!length||length>YD_DOCUMENT_LIMIT)return false;
    YDValue *v=yd_parse(source,length,NULL,0);
    if(!v)return false;
    YDShardPlan p;
    YDShardStatus s=yd_shard_plan_document(q->placement,yd_shard_placement_id(q->placement),yd_shard_placement_collection(q->placement),yd_shard_placement_epoch(q->placement),YD_SHARD_READ,v,&p);
    if(s!=YD_SHARD_OK||strcmp(p.shard,q->range.shard)){yd_free(v);
        return false;
    }*doc=v;
    return true;
}
YDShardNative *yd_shard_native_open(YDDisk *disk,const char *group,YDShardControl *c){if(!disk||!c||!valid_group(group))return NULL;
    YDShardNative *n=calloc(1,sizeof(*n));
    if(n){n->disk=disk;
        n->control=c;
        strcpy(n->group,group);
    }return n;
}
static bool matches_key(const YDShardRequest *q,const YDValue *doc) {
    if(!q->key)return false;
    YDShardKey encoded;
    return yd_shard_document_key(q->placement,doc,&encoded)==YD_SHARD_OK&&
        encoded.length==q->key->length&&!memcmp(encoded.bytes,q->key->bytes,encoded.length);
}
void yd_shard_native_close(YDShardNative *n){free(n);
}
static YDShardStatus read_one(YDShardNative *n,const YDShardRequest *q,YDShardResponse *out){
    if(!ident(q->id))return YD_SHARD_INVALID_ARGUMENT;
    YDDiskView view=native_view(n);
    char prefix[160],k[512];
    if(!active_prefix(n,view,q->range.shard,prefix))return YD_SHARD_CORRUPT;
    snprintf(k,sizeof(k),"%s%s",prefix,q->id);
    unsigned char *b=NULL;
    size_t size;
    int f=record(n,view,k,&b,&size);
    if(f<0)return YD_SHARD_UNAVAILABLE;
    out->page.end=true;
    if(!f)return YD_SHARD_OK;
    YDValue *doc=NULL;
    if(!document(q,b,size,&doc)){free(b);
        return YD_SHARD_CORRUPT;
    }
    if(!matches_key(q,doc)){yd_free(doc);free(b);return YD_SHARD_INVALID_KEY;}
    yd_free(doc);
    out->page.rows=calloc(1,sizeof(YDShardRow));
    if(!out->page.rows){free(b);
        return YD_SHARD_RESOURCE_FAILURE;
    }out->page.count=1;
    out->page.bytes=size;
    strcpy(out->page.rows[0].id,q->id);
    out->page.rows[0].source=b;
    out->page.rows[0].length=size;
    return YD_SHARD_OK;
}
static YDShardStatus write_one(YDShardNative *n,const YDShardRequest *q){
    if(q->operation==YD_SHARD_RPC_DELETE&&(q->source||q->length))return YD_SHARD_INVALID_ARGUMENT;
    if(!ident(q->id)||!q->key||!q->mutation_id||!q->mutation_id[0]||strnlen(q->mutation_id,129)>128)return YD_SHARD_INVALID_ARGUMENT;
    YDShardStatus ownership=owner_check(n,q);
    if(ownership!=YD_SHARD_OK)return ownership;
    YDDiskView view=native_view(n);
    char prefix[160],k[512],receipt[512];
    if(!active_prefix(n,view,q->range.shard,prefix))return YD_SHARD_CORRUPT;
    snprintf(k,sizeof(k),"%s%s",prefix,q->id);
    /* Digest includes operation, placement identity+epoch, shard, ID, exact bytes.
    * Mutation IDs cannot silently reuse a different operation after restart. */
    EVP_MD_CTX *ctx=EVP_MD_CTX_new();
    unsigned char hash[32];
    unsigned hsize=0;
    unsigned char epoch[8],op=(unsigned char)q->operation;
    put64(epoch,yd_shard_placement_epoch(q->placement));
    bool ok=ctx&&EVP_DigestInit_ex(ctx,EVP_sha256(),NULL)==1&&EVP_DigestUpdate(ctx,&op,1)==1&&EVP_DigestUpdate(ctx,yd_shard_placement_id(q->placement),33)==1&&EVP_DigestUpdate(ctx,epoch,8)==1&&EVP_DigestUpdate(ctx,q->range.shard,strlen(q->range.shard)+1)==1&&EVP_DigestUpdate(ctx,q->id,strlen(q->id)+1)==1&&EVP_DigestUpdate(ctx,q->key->bytes,q->key->length)==1&&EVP_DigestUpdate(ctx,q->source,q->length)==1&&EVP_DigestFinal_ex(ctx,hash,&hsize)==1&&hsize==32;
    EVP_MD_CTX_free(ctx);
    if(!ok)return YD_SHARD_RESOURCE_FAILURE;
    unsigned char idhash[32];
    unsigned dn=0;
    if(EVP_Digest(q->mutation_id,strlen(q->mutation_id),idhash,&dn,EVP_sha256(),NULL)!=1||dn!=32)return YD_SHARD_RESOURCE_FAILURE;
    char hex[65];
    for(size_t i=0;i<32;i++)snprintf(hex+i*2,3,"%02x",idhash[i]);
    key(receipt,sizeof(receipt),"receipt",q->range.shard,hex);
    unsigned char *old=NULL;
    size_t oldn;
    int f=record(n,view,receipt,&old,&oldn);
    if(f<0)return YD_SHARD_UNAVAILABLE;
    if(f){bool same=oldn==32&&!memcmp(old,hash,32);
        free(old);
        return same?YD_SHARD_OK:YD_SHARD_CONFLICT;
    }
    YDValue *candidate=NULL;
    if(q->operation==YD_SHARD_RPC_WRITE&&!document(q,q->source,q->length,&candidate))return YD_SHARD_INVALID_KEY;
    if(candidate&&!matches_key(q,candidate)){yd_free(candidate);return YD_SHARD_INVALID_KEY;}
    f=record(n,view,k,&old,&oldn);
    if(f<0){yd_free(candidate);
        return YD_SHARD_UNAVAILABLE;
    }
    /* A delete of an absent document changes nothing and is not logged. */
    bool logged=yd_shard_placement_version(q->placement)>=2&&(q->operation==YD_SHARD_RPC_WRITE||f);
    if(f){YDValue *before=yd_parse(old,oldn,NULL,0);
        YDShardStatus s=!matches_key(q,before)?YD_SHARD_INVALID_KEY:
            candidate?yd_shard_key_unchanged(q->placement,before,candidate):YD_SHARD_OK;
        yd_free(before);
        if(s!=YD_SHARD_OK){free(old);
            yd_free(candidate);
            return s;
        }}free(old);
    yd_free(candidate);
    YDDiskTxn *tx=yd_disk_begin(n->disk,NULL,0);
    if(!tx)return YD_SHARD_UNAVAILABLE;
    ok=(q->operation==YD_SHARD_RPC_DELETE?yd_disk_delete(tx,k,strlen(k),NULL,0):put(tx,k,q->source,q->length))&&put(tx,receipt,hash,32)&&owner_put(tx,q,true)&&
        (!logged||log_append(n,view,tx,q));
    if(!ok){yd_disk_abort(tx);
        return YD_SHARD_UNAVAILABLE;
    }return finish(n,tx);
}
static YDShardStatus scan(YDShardNative *n,const YDShardRequest *q,YDShardResponse *out,bool moving){
    if(!q->max_rows||q->max_rows>YD_SHARD_PAGE_ROWS||!q->max_bytes||q->max_bytes>YD_SHARD_PAGE_BYTES||!q->after||strnlen(q->after,256)>255)return YD_SHARD_INVALID_ARGUMENT;
    YDDiskView view;
    Stage freeze;
    if(moving){if(stage_get(n,q->range.shard,"freeze",&freeze)!=1||strcmp(freeze.migration,q->migration.migration)||strcmp(freeze.snapshot,q->migration.snapshot)||(q->snapshot&&q->snapshot[0]&&strcmp(freeze.snapshot,q->snapshot))||owner_check(n,q)!=YD_SHARD_MIGRATING)return YD_SHARD_UNAVAILABLE;
        view=native_view(n);
        strcpy(out->snapshot,freeze.snapshot);
    }
    else if(q->snapshot&&q->snapshot[0]){bool found=false;
        for(size_t i=0;i<256;i++) {
            if(!strcmp(n->tokens[i],q->snapshot)){view=n->views[i];
                found=true;
                break;
            }
        }
        if(!found)return YD_SHARD_STALE_PLACEMENT;
        strcpy(out->snapshot,q->snapshot);
    }
    else{view=native_view(n);
        token(view,out->snapshot);
        n->views[n->next]=view;
        strcpy(n->tokens[n->next],out->snapshot);
        n->next=(n->next+1)%256;
    }
    char prefix[160],seek[512];
    if(!active_prefix(n,view,q->range.shard,prefix))return YD_SHARD_CORRUPT;
    snprintf(seek,sizeof(seek),"%s%s",prefix,q->after);
    YDDiskCursor *cursor=yd_disk_cursor(n->disk,&view,seek,strlen(seek),q->after[0]!=0,NULL,0);
    if(!cursor)return YD_SHARD_UNAVAILABLE;
    out->page.rows=calloc(q->max_rows,sizeof(YDShardRow));
    if(!out->page.rows){yd_disk_cursor_free(cursor);
        return YD_SHARD_RESOURCE_FAILURE;
    }
    YDShardStatus s=YD_SHARD_OK;
    out->page.end=true;
    for(;;){char k[1025];
        size_t size;
        uint64_t offset;
        int f=yd_disk_next(cursor,k,sizeof(k)-1,&size,&offset,NULL,0);
        if(f<0){s=YD_SHARD_UNAVAILABLE;
            break;
        }if(!f)break;
        k[size]=0;
        if(strncmp(k,prefix,strlen(prefix)))break;
        if(out->page.count==q->max_rows){out->page.end=false;
            break;
        }
        size_t length;
        unsigned char *source=yd_disk_record(n->disk,&view,offset,&length,NULL,0);
        if(!source){s=YD_SHARD_UNAVAILABLE;
            break;
        }
        if(length>q->max_bytes-out->page.bytes){free(source);
            if(!out->page.count)s=YD_SHARD_BUDGET_EXCEEDED;
            else out->page.end=false;
            break;
        }
        const char *id=k+strlen(prefix);
        if(!ident(id)){free(source);
            s=YD_SHARD_CORRUPT;
            break;
        }
        YDValue *v=NULL;
        if(!document(q,source,length,&v)){free(source);
            s=YD_SHARD_CORRUPT;
            break;
        }yd_free(v);
        YDShardRow *row=&out->page.rows[out->page.count++];
        strcpy(row->id,id);
        row->source=source;
        row->length=length;
        out->page.bytes+=length;
    }
    yd_disk_cursor_free(cursor);
    if(s!=YD_SHARD_OK)yd_shard_page_free(&out->page);
    return s;
}
static YDShardStatus freeze(YDShardNative *n,const YDShardRequest *q){
    Stage old;
    int found=stage_get(n,q->range.shard,"freeze",&old);
    if(found<0)return YD_SHARD_CORRUPT;
    Stage s={0};
    if(found&&!strcmp(old.migration,q->migration.migration))s=old;
    else {
        strcpy(s.migration,q->migration.migration);
        if(!freeze_token(n,q,s.snapshot))return YD_SHARD_RESOURCE_FAILURE;
        s.state=1;
    }
    YDDiskTxn *tx=yd_disk_begin(n->disk,NULL,0);
    if(!tx)return YD_SHARD_UNAVAILABLE;
    if(!stage_put(tx,q->range.shard,"freeze",&s)||!owner_put(tx,q,false)){yd_disk_abort(tx);
        return YD_SHARD_UNAVAILABLE;
    }return finish(n,tx);
}
static bool page_hash(const YDShardPage *p,unsigned char hash[32]){EVP_MD_CTX *ctx=EVP_MD_CTX_new();
    if(!ctx)return false;
    bool ok=EVP_DigestInit_ex(ctx,EVP_sha256(),NULL)==1;
    for(size_t i=0;ok&&i<p->count;i++){unsigned char length[8];
        put64(length,p->rows[i].length);
        ok=EVP_DigestUpdate(ctx,p->rows[i].id,strlen(p->rows[i].id)+1)==1&&EVP_DigestUpdate(ctx,length,8)==1&&EVP_DigestUpdate(ctx,p->rows[i].source,p->rows[i].length)==1;
    }unsigned size=0;
    ok=ok&&EVP_DigestFinal_ex(ctx,hash,&size)==1&&size==32;
    EVP_MD_CTX_free(ctx);
    return ok;
}
static YDShardStatus stage(YDShardNative *n,const YDShardRequest *q){
    if(!q->page||q->page->count>YD_SHARD_PAGE_ROWS||q->page->bytes>YD_SHARD_PAGE_BYTES||(q->page->count&&!q->page->rows))return YD_SHARD_INVALID_ARGUMENT;
    Stage s={0};
    int found=stage_get(n,q->range.shard,"migration",&s);
    if(found<0)return YD_SHARD_CORRUPT;
    if(found&&strcmp(s.migration,q->migration.migration)){if(s.state!=3)return YD_SHARD_CONFLICT;
        memset(&s,0,sizeof(s));
        found=0;
    }
    if(!found){strcpy(s.migration,q->migration.migration);
        strcpy(s.snapshot,q->migration.snapshot);
        s.state=1;
    }
    if(strcmp(s.snapshot,q->migration.snapshot))return YD_SHARD_CONFLICT;
    size_t bytes=0;
    const char *last=q->migration.cursor;
    for(size_t i=0;i<q->page->count;i++){const YDShardRow *row=&q->page->rows[i];
        if(!ident(row->id)||strcmp(row->id,last)<=0||row->length>YD_SHARD_PAGE_BYTES-bytes)return YD_SHARD_CORRUPT;
        YDValue *v=NULL;
        if(!document(q,row->source,row->length,&v))return YD_SHARD_INVALID_KEY;
        yd_free(v);
        bytes+=row->length;
        last=row->id;
    }
    if(bytes!=q->page->bytes)return YD_SHARD_CORRUPT;
    unsigned char hash[32];
    if(!page_hash(q->page,hash))return YD_SHARD_RESOURCE_FAILURE;
    if(s.rows==q->migration.rows+q->page->count&&s.bytes==q->migration.bytes+bytes&&!strcmp(s.previous,q->migration.cursor)&&!strcmp(s.cursor,last)&&!memcmp(s.hash,hash,32))return YD_SHARD_OK;
    if(s.state!=1||s.rows!=q->migration.rows||s.bytes!=q->migration.bytes||strcmp(s.cursor,q->migration.cursor))return YD_SHARD_CONFLICT;
    strcpy(s.previous,s.cursor);
    strcpy(s.cursor,last);
    s.rows+=q->page->count;
    s.bytes+=bytes;
    memcpy(s.hash,hash,32);
    YDDiskTxn *tx=yd_disk_begin(n->disk,NULL,0);
    if(!tx)return YD_SHARD_UNAVAILABLE;
    bool ok=true;
    for(size_t i=0;ok&&i<q->page->count;i++){char k[512];
        key(k,sizeof(k),"stage",s.migration,q->page->rows[i].id);
        ok=put(tx,k,q->page->rows[i].source,q->page->rows[i].length);
    }
    ok=ok&&stage_put(tx,q->range.shard,"migration",&s);
    if(!ok){yd_disk_abort(tx);
        return YD_SHARD_UNAVAILABLE;
    }return finish(n,tx);
}
static YDShardStatus seal_or_activate(YDShardNative *n,const YDShardRequest *q,bool activate){
    Stage s;
    if(stage_get(n,q->range.shard,"migration",&s)!=1||strcmp(s.migration,q->migration.migration)||strcmp(s.snapshot,q->migration.snapshot)||strcmp(s.cursor,q->migration.cursor)||s.rows!=q->migration.rows||s.bytes!=q->migration.bytes||!q->migration.copied)return YD_SHARD_CONFLICT;
    /* A version-2 shard is sealed only with its complete change log, and
     * activation installs that log's window as the shard's own. */
    bool logged=yd_shard_placement_version(q->placement)>=2;
    LogStage imported;
    if(logged){int f=log_stage_get(n,native_view(n),q->range.shard,&imported);
        if(f<0)return YD_SHARD_CORRUPT;
        if(!f||strcmp(imported.migration,q->migration.migration)||!imported.complete)return YD_SHARD_CONFLICT;
    }
    if(activate&&s.state<2)return YD_SHARD_CONFLICT;
    if(!activate&&s.state>=2)return YD_SHARD_OK;
    if(activate&&s.state==3)return YD_SHARD_OK;
    s.state=activate?3:2;
    YDDiskTxn *tx=yd_disk_begin(n->disk,NULL,0);
    if(!tx)return YD_SHARD_UNAVAILABLE;
    bool ok=stage_put(tx,q->range.shard,"migration",&s);
    if(activate){char k[128];
        key(k,sizeof(k),"active",q->range.shard,NULL);
        ok=ok&&put(tx,k,s.migration,33)&&owner_put(tx,q,true)&&(!logged||meta_put(tx,q->range.shard,&imported.m));
    }
    if(!ok){yd_disk_abort(tx);
        return YD_SHARD_UNAVAILABLE;
    }return finish(n,tx);
}
YDShardStatus yd_shard_native_call(void *context,const YDShardRequest *q,YDShardResponse *out){
    if(!context||!q||!out)return YD_SHARD_INVALID_ARGUMENT;
    memset(out,0,sizeof(*out));
    YDShardNative *n=context;
    YDShardRange range;
    if(!current(n,q,&range))return YD_SHARD_STALE_PLACEMENT;
    YDShardStatus ownership=owner_check(n,q);
    if(ownership!=YD_SHARD_OK&&ownership!=YD_SHARD_MIGRATING)return ownership;
    YDShardMigration m;
    bool moving=migration(n,q,&m);
    bool migration_rpc=(q->operation>=YD_SHARD_RPC_FREEZE&&q->operation<=YD_SHARD_RPC_ACTIVATE)||q->operation==YD_SHARD_RPC_LOG_STAGE;
    if(migration_rpc){if(!moving)return YD_SHARD_STALE_PLACEMENT;
        if(q->operation==YD_SHARD_RPC_FREEZE){if(m.phase!=YD_SHARD_FENCING||strcmp(n->group,m.source))return YD_SHARD_FORBIDDEN;
            Stage f;
            int found=stage_get(n,m.shard,"freeze",&f);
            if(found<0)return YD_SHARD_CORRUPT;
            if(found&&!strcmp(f.migration,m.migration))strcpy(out->snapshot,f.snapshot);
            else if(!freeze_token(n,q,out->snapshot))return YD_SHARD_RESOURCE_FAILURE;
            return freeze(n,q);
        }
        if(strcmp(n->group,m.target))return YD_SHARD_FORBIDDEN;
        if(q->operation==YD_SHARD_RPC_STAGE)return m.phase==YD_SHARD_COPYING?stage(n,q):YD_SHARD_CONFLICT;
        if(q->operation==YD_SHARD_RPC_SEAL)return m.phase==YD_SHARD_COPYING&&m.copied?seal_or_activate(n,q,false):YD_SHARD_CONFLICT;
        if(q->operation==YD_SHARD_RPC_ACTIVATE)return m.phase==YD_SHARD_ACTIVATING?seal_or_activate(n,q,true):YD_SHARD_CONFLICT;
        if(q->operation==YD_SHARD_RPC_LOG_STAGE)return m.phase==YD_SHARD_COPYING&&m.copied?log_stage(n,q,out):YD_SHARD_CONFLICT;
        return YD_SHARD_INVALID_ARGUMENT;
    }
    if(strcmp(n->group,range.group))return YD_SHARD_STALE_PLACEMENT;
    if(q->operation==YD_SHARD_RPC_READ||q->operation==YD_SHARD_RPC_WRITE||q->operation==YD_SHARD_RPC_DELETE){
        uint64_t route_token=0;
        YDShardStatus key_status=yd_shard_key_token(q->key,&route_token);
        if(key_status!=YD_SHARD_OK)return key_status;
        if(route_token<range.first||route_token>range.last)return YD_SHARD_INVALID_KEY;
    }
    YDShardMigration control=yd_shard_control_migration(n->control);
    bool this_moving=control.phase!=YD_SHARD_IDLE&&!strcmp(control.shard,range.shard);
    if(q->operation==YD_SHARD_RPC_WRITE||q->operation==YD_SHARD_RPC_DELETE){if(this_moving)return YD_SHARD_MIGRATING;
        return write_one(n,q);
    }
    if(this_moving&&control.phase==YD_SHARD_ACTIVATING){Stage stage_state;
        if(stage_get(n,range.shard,"migration",&stage_state)!=1||stage_state.state!=3)return YD_SHARD_UNAVAILABLE;
    }
    /* Writes are fenced from the control fence until activation, so the
     * source's log stays readable and equal to the target's copy during the
     * move; the new owner serves the imported log only once activated. */
    if(q->operation==YD_SHARD_RPC_LOG)return log_read(n,q,out);
    if(q->operation==YD_SHARD_RPC_READ)return read_one(n,q,out);
    if(q->operation==YD_SHARD_RPC_SCAN)return scan(n,q,out,moving&&m.phase==YD_SHARD_COPYING);
    return YD_SHARD_INVALID_ARGUMENT;
}
YDShardStatus yd_shard_native_call_at(YDShardNative *n,const YDDiskView *view,
    const YDShardRequest *request,YDShardResponse *response) {
    if(!n||!view||!request||!response||n->at||n->preparing)return YD_SHARD_INVALID_ARGUMENT;
    if(request->operation!=YD_SHARD_RPC_READ&&request->operation!=YD_SHARD_RPC_SCAN&&request->operation!=YD_SHARD_RPC_LOG)return YD_SHARD_INVALID_ARGUMENT;
    n->at=view;
    YDShardStatus status=yd_shard_native_call(n,request,response);
    n->at=NULL;return status;
}
YDShardStatus yd_shard_native_prepare_at(YDShardNative *n,const YDDiskView *view,
    const YDShardRequest *request,YDShardResponse *response,YDDiskTxn **txn) {
    if(txn)*txn=NULL;
    if(!n||!view||!request||!response||!txn||n->at||n->preparing)return YD_SHARD_INVALID_ARGUMENT;
    if(request->operation==YD_SHARD_RPC_READ||request->operation==YD_SHARD_RPC_SCAN||request->operation==YD_SHARD_RPC_LOG)return YD_SHARD_INVALID_ARGUMENT;
    YDDiskView current_view=yd_disk_view(n->disk);
    if(current_view.generation!=view->generation||current_view.root!=view->root||current_view.end!=view->end)return YD_SHARD_CONFLICT;
    n->at=view;n->preparing=true;n->prepared=NULL;
    YDShardStatus status=yd_shard_native_call(n,request,response);
    n->at=NULL;n->preparing=false;
    if(status==YD_SHARD_OK){
        if(!n->prepared)n->prepared=yd_disk_begin(n->disk,NULL,0);
        if(!n->prepared)status=YD_SHARD_UNAVAILABLE;
        else *txn=n->prepared;
    }
    else if(n->prepared)yd_disk_abort(n->prepared);
    n->prepared=NULL;return status;
}
static bool hex_text(const char *text,size_t length) {
    if(strlen(text)!=length)return false;
    for(size_t i=0;i<length;i++)if(!((text[i]>='0'&&text[i]<='9')||(text[i]>='a'&&text[i]<='f')))return false;
    return true;
}
static int native_parts(const void *key,size_t length,char kind[16],char shard[64],char id[256]) {
    if(!key||length<4||memcmp(key,"\001YS/",4))return 0;
    if(length>400||memchr(key,0,length))return -1;
    char text[401];memcpy(text,key,length);text[length]=0;
    char *first=strchr(text+4,'/');if(!first||first==text+4||(size_t)(first-text-4)>=16)return -1;
    memcpy(kind,text+4,(size_t)(first-text-4));kind[first-text-4]=0;
    char *second=strchr(first+1,'/');if(!second||second==first+1||(size_t)(second-first-1)>=64||strchr(second+1,'/'))return -1;
    memcpy(shard,first+1,(size_t)(second-first-1));shard[second-first-1]=0;
    if(strlen(second+1)>255)return -1;
    strcpy(id,second+1);
    if(!strcmp(kind,"stage"))return hex_text(shard,32)&&ident(id)?1:-1;
    if(!valid_group(shard))return -1;
    if(!strcmp(kind,"data"))return ident(id)?1:-1;
    if(!strcmp(kind,"receipt"))return hex_text(id,64)?1:-1;
    if(!strcmp(kind,"log"))return hex_text(id,16)?1:-1;
    if(!strcmp(kind,"active")||!strcmp(kind,"freeze")||!strcmp(kind,"migration")||!strcmp(kind,"owner")||
        !strcmp(kind,"feed")||!strcmp(kind,"lstage"))return !id[0]?1:-1;
    return -1;
}
int yd_shard_native_key(const void *key,size_t length) {
    char kind[16],shard[64],id[256];return native_parts(key,length,kind,shard,id);
}
bool yd_shard_native_validate_record(const void *key,size_t key_length,
    const unsigned char *bytes,size_t length) {
    char kind[16],shard[64],id[256];
    if(native_parts(key,key_length,kind,shard,id)!=1||!bytes)return false;
    if(!strcmp(kind,"receipt"))return length==32;
    if(!strcmp(kind,"owner"))return length==9&&get64(bytes)>0&&get64(bytes)<=INT64_MAX&&bytes[8]<=1;
    if(!strcmp(kind,"active"))return length==33&&bytes[32]==0&&hex_text((const char*)bytes,32);
    if(!strcmp(kind,"log")){YDShardLogRecord r;uint64_t seq;return seq_text(id,&seq)&&yd_shard_log_decode(bytes,length,&r)&&r.sequence==seq;}
    if(!strcmp(kind,"feed")){LogMeta m;return meta_decode(bytes,length,&m);}
    if(!strcmp(kind,"lstage")){LogStage s;return log_stage_decode(bytes,length,&s);}
    if(!strcmp(kind,"data")||!strcmp(kind,"stage")){
        if(!length||length>YD_DOCUMENT_LIMIT)return false;
        YDValue *doc=yd_parse(bytes,length,NULL,0);bool valid=doc&&doc->type==YD_MAP;yd_free(doc);return valid;
    }
    Stage stage;if(!stage_decode(bytes,length,&stage)||!stage.state||!hex_text(stage.migration,32)||!hex_text(stage.snapshot,64)||stage.rows>INT64_MAX||stage.bytes>INT64_MAX)return false;
    if((stage.cursor[0]&&!ident(stage.cursor))||(stage.previous[0]&&!ident(stage.previous)))return false;
    unsigned char canonical[STAGE_SIZE];stage_encode(&stage,canonical);
    if(memcmp(canonical,bytes,length))return false;
    if(!strcmp(kind,"freeze")){
        unsigned char zero[32]={0};return stage.state==1&&!stage.rows&&!stage.bytes&&!stage.cursor[0]&&!stage.previous[0]&&!memcmp(stage.hash,zero,32);
    }
    return true;
}
