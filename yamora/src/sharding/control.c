#define _POSIX_C_SOURCE 200809L
#include "runtime.h"
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct YDShardControl { YDDisk *disk;
    YDShardPlacement *placement;
    YDShardMigration migration;
    char key[128];
    size_t key_length;
};
/* The first sharded collection keeps the original single record (so a
 * one-collection namespace stays byte-identical). Each further collection uses
 * "<legacy>/<collection>"; older binaries classify that key as a malformed
 * reserved key and refuse it instead of misreading it. */
static const char control_key[] = "\001yamora-shard-control-v1";
#define CONTROL_PREFIX (sizeof(control_key) - 1U)
#define CONTROL_COLLECTIONS 64U
static void put64(unsigned char *p, uint64_t x) { for (unsigned i=0;i<8;i++) p[i]=(unsigned char)(x>>(56-8*i));
}
static uint64_t get64(const unsigned char *p) { uint64_t x=0;
    for (unsigned i=0;i<8;i++) x=(x<<8)|p[i];
    return x;
}
static bool digest(const unsigned char *p,size_t n,unsigned char out[32]) { unsigned l=0;
    return EVP_Digest(p,n,out,&l,EVP_sha256(),NULL)==1 && l==32;
}
static bool text(const char *s,size_t cap) { return s && strnlen(s,cap)<cap;
}
static bool hexid(const char *s,size_t n) { if (!s || strnlen(s,n+1)!=n) return false;
    for(size_t i=0;i<n;i++) if (!((s[i]>='0'&&s[i]<='9')||(s[i]>='a'&&s[i]<='f'))) return false;
    return true;
}
static bool name(const char *s) { if (!text(s,64)||!s[0]) return false;
    for(size_t i=0;s[i];i++) if (!((s[i]>='a'&&s[i]<='z')||(s[i]>='0'&&s[i]<='9')||s[i]=='-')) return false;
    return true;
}
static bool identifier(const char *s) { if (!text(s,256)) return false;
    for(size_t i=0;s[i];i++) if ((unsigned char)s[i]<33 || (unsigned char)s[i]>126 || s[i]=='/' || s[i]=='\\') return false;
    return true;
}
static bool range(const YDShardPlacement *p,const char *shard,YDShardRange *out) { for(size_t i=0;i<yd_shard_placement_ranges(p);i++) if (yd_shard_placement_range(p,i,out)&&!strcmp(out->shard,shard)) return true;
    return false;
}
#define FIXED_MIGRATION (8U+1U+33U+64U+64U+64U+65U+256U+8U+8U+1U)
static unsigned char *encode(const YDShardPlacement *p,const YDShardMigration *m,size_t *length) {
    size_t n=0;
    unsigned char *metadata=p?yd_shard_placement_encode(p,&n):NULL;
    if (p&&!metadata) return NULL;
    *length=12+n+FIXED_MIGRATION;
    unsigned char *b=calloc(1,*length);
    if (!b) {free(metadata);
        return NULL;
    }
    memcpy(b,"YSC1",4);
    put64(b+4,n);
    if(n) memcpy(b+12,metadata,n);
    free(metadata);
    size_t k=12+n;
    put64(b+k,m->sequence);
    k+=8;
    b[k++]=(unsigned char)m->phase;
#define WRITE_STRING(field) memcpy(b+k,m->field,sizeof(m->field)); k+=sizeof(m->field)
    WRITE_STRING(migration);
    WRITE_STRING(shard);
    WRITE_STRING(source);
    WRITE_STRING(target);
    WRITE_STRING(snapshot);
    WRITE_STRING(cursor);
#undef WRITE_STRING
    put64(b+k,m->rows);
    k+=8;
    put64(b+k,m->bytes);
    k+=8;
    b[k]=(unsigned char)m->copied;
    return b;
}
static bool padding(const unsigned char *p,size_t n) { const unsigned char *z=memchr(p,0,n);
    if (!z) return false;
    for(size_t i=(size_t)(z-p);i<n;i++) if (p[i]) return false;
    return true;
}
static bool decode(const unsigned char *b,size_t n,YDShardPlacement **p,YDShardMigration *m) {
    *p=NULL;
    memset(m,0,sizeof(*m));
    if(!b||n<12+FIXED_MIGRATION||memcmp(b,"YSC1",4)) return false;
    uint64_t size=get64(b+4);
    if(size>YD_SHARD_METADATA_LIMIT||size!=n-12-FIXED_MIGRATION) return false;
    if(size&&yd_shard_placement_parse(b+12,(size_t)size,p)!=YD_SHARD_OK) return false;
    size_t k=12+(size_t)size;
    m->sequence=get64(b+k);
    k+=8;
    m->phase=(YDShardPhase)b[k++];
#define READ_STRING(field) if(!padding(b+k,sizeof(m->field))) goto bad; memcpy(m->field,b+k,sizeof(m->field)); k+=sizeof(m->field)
    READ_STRING(migration);
    READ_STRING(shard);
    READ_STRING(source);
    READ_STRING(target);
    READ_STRING(snapshot);
    READ_STRING(cursor);
#undef READ_STRING
    m->rows=get64(b+k);
    k+=8;
    m->bytes=get64(b+k);
    k+=8;
    if(b[k]>1) goto bad;
    m->copied=b[k]!=0;
    if(m->sequence>INT64_MAX || m->rows>INT64_MAX || m->bytes>INT64_MAX || m->phase>YD_SHARD_ACTIVATING) goto bad;
    if(!*p) { if(m->sequence || m->phase!=YD_SHARD_IDLE) goto bad;
    }
    else if(!m->sequence) goto bad;
    if(m->phase==YD_SHARD_IDLE) {
        YDShardMigration idle={.sequence=m->sequence};
        size_t an,bn;
        unsigned char *a=encode(NULL,m,&an),*c=encode(NULL,&idle,&bn);
        bool same=a&&c&&an==bn&&!memcmp(a,c,an);
        free(a);
        free(c);
        if(!same) goto bad;
    } else {
        YDShardRange r;
        if(!*p||!hexid(m->migration,32)||!name(m->source)||!name(m->target)||!strcmp(m->source,m->target)||!range(*p,m->shard,&r)||!identifier(m->cursor)) goto bad;
        if(m->phase<YD_SHARD_ACTIVATING && strcmp(r.group,m->source)) goto bad;
        if(m->phase==YD_SHARD_ACTIVATING && strcmp(r.group,m->target)) goto bad;
        if(m->phase==YD_SHARD_FENCING) { if(m->snapshot[0]||m->cursor[0]||m->rows||m->bytes||m->copied) goto bad;
        }
        else if(!hexid(m->snapshot,64)) goto bad;
    }
    return true;
    bad: yd_shard_placement_free(*p);
    *p=NULL;
    return false;
}
static bool same_placement(const YDShardPlacement *a,const YDShardPlacement *b) {
    size_t an=0,bn=0;
    unsigned char *ab=yd_shard_placement_encode(a,&an),*bb=yd_shard_placement_encode(b,&bn);
    bool same=ab&&bb&&an==bn&&!memcmp(ab,bb,an);
    free(ab);
    free(bb);
    return same;
}
static bool same_migration(const YDShardMigration *a,const YDShardMigration *b) {
    return !strcmp(a->migration,b->migration)&&!strcmp(a->shard,b->shard)&&!strcmp(a->source,b->source)&&!strcmp(a->target,b->target);
}
static bool transition(const YDShardControl *c,const YDShardPlacement *p,const YDShardMigration *m) {
    const YDShardMigration *old=&c->migration;
    if(!p||old->sequence>=INT64_MAX||m->sequence!=old->sequence+1) return false;
    if(!c->placement) return m->phase==YD_SHARD_IDLE;
    if(old->phase==YD_SHARD_IDLE) return m->phase==YD_SHARD_FENCING&&same_placement(c->placement,p);
    if(old->phase==YD_SHARD_ACTIVATING) return m->phase==YD_SHARD_IDLE&&same_placement(c->placement,p);
    if(!same_migration(old,m)) return false;
    if(old->phase==YD_SHARD_SEALED) {
        if(m->phase!=YD_SHARD_ACTIVATING) return false;
        YDShardPlacement *moved=NULL;
        if(yd_shard_placement_move(c->placement,old->shard,old->target,&moved)!=YD_SHARD_OK) return false;
        bool ok=same_placement(moved,p)&&!strcmp(m->snapshot,old->snapshot)&&!strcmp(m->cursor,old->cursor)&&m->rows==old->rows&&m->bytes==old->bytes&&m->copied;
        yd_shard_placement_free(moved);
        return ok;
    }
    if(!same_placement(c->placement,p)) return false;
    if(old->phase==YD_SHARD_FENCING) return m->phase==YD_SHARD_COPYING&&!m->cursor[0]&&!m->rows&&!m->bytes&&!m->copied;
    if(strcmp(old->snapshot,m->snapshot)) return false;
    if(m->phase==YD_SHARD_SEALED) return old->copied&&m->copied&&!strcmp(old->cursor,m->cursor)&&old->rows==m->rows&&old->bytes==m->bytes;
    if(m->phase!=YD_SHARD_COPYING||old->copied||m->rows<old->rows||m->bytes<old->bytes||m->rows-old->rows>YD_SHARD_PAGE_ROWS||m->bytes-old->bytes>YD_SHARD_PAGE_BYTES) return false;
    if(m->rows==old->rows) return m->copied&&m->bytes==old->bytes&&!strcmp(m->cursor,old->cursor);
    return strcmp(m->cursor,old->cursor)>0 && m->bytes>old->bytes;
}
static YDShardStatus command(YDShardControl *c,YDShardPlacement *p,YDShardMigration *m,unsigned char **out,size_t *length) {
    if(!out||!length) return YD_SHARD_INVALID_ARGUMENT;
    *out=NULL;
    *length=0;
    size_t before_n=0,next_n=0;
    unsigned char *before=encode(c->placement,&c->migration,&before_n),*next=encode(p,m,&next_n);
    YDShardPlacement *validated=NULL;
    YDShardMigration checked;
    if(!before||!next) { free(before);
        free(next);
        return YD_SHARD_RESOURCE_FAILURE;
    }
    bool valid=decode(next,next_n,&validated,&checked)&&transition(c,validated,&checked);
    yd_shard_placement_free(validated);
    if(!valid) {free(before);
        free(next);
        return YD_SHARD_CONFLICT;
    }
    unsigned char *b=malloc(36+next_n);
    if(!b) {free(before);
        free(next);
        return YD_SHARD_RESOURCE_FAILURE;
    }
    memcpy(b,"YCC1",4);
    bool ok=digest(before,before_n,b+4);
    free(before);
    memcpy(b+36,next,next_n);
    free(next);
    if(!ok) {free(b);
        return YD_SHARD_RESOURCE_FAILURE;
    } *out=b;
    *length=36+next_n;
    return YD_SHARD_OK;
}
/* 1 found, 0 absent, -1 unreadable/corrupt. */
static int load(YDDisk *disk,const YDDiskView *at,const char *key,size_t key_length,
    YDShardPlacement **p,YDShardMigration *m) {
    *p=NULL;
    memset(m,0,sizeof(*m));
    YDDiskView view=*at;
    uint64_t offset;
    int found=yd_disk_get(disk,&view,key,key_length,&offset,NULL,0);
    if(found<=0) return found;
    size_t n;
    unsigned char *b=yd_disk_record(disk,&view,offset,&n,NULL,0);
    bool ok=b&&decode(b,n,p,m);
    free(b);
    return ok?1:-1;
}
static size_t collection_key(const char *collection,char out[128]) {
    int n=snprintf(out,128,"%s/%s",control_key,collection);
    return n>0&&(size_t)n<128?(size_t)n+1:0; /* the NUL is part of the key, as for the legacy key */
}
YDShardControl *yd_shard_control_open_at(YDDisk *disk, const YDDiskView *at) {
    if(!disk || !at) return NULL;
    YDShardControl *c=calloc(1,sizeof(*c));
    if(!c) return NULL;
    c->disk=disk;
    memcpy(c->key,control_key,sizeof(control_key));
    c->key_length=sizeof(control_key);
    if(load(disk,at,control_key,sizeof(control_key),&c->placement,&c->migration)<0){free(c);
        return NULL;
    }
    return c;
}
YDShardControl *yd_shard_control_open(YDDisk *disk) {
    if(!disk) return NULL;
    YDDiskView view=yd_disk_view(disk);
    return yd_shard_control_open_at(disk,&view);
}
YDShardControl *yd_shard_control_open_collection_at(YDDisk *disk,const YDDiskView *at,const char *collection) {
    if(!disk||!at||!name(collection)) return NULL;
    YDShardControl *c=yd_shard_control_open_at(disk,at);
    if(!c) return NULL;
    if(!c->placement||!strcmp(yd_shard_placement_collection(c->placement),collection)) return c;
    /* The legacy record belongs to another collection. */
    yd_shard_placement_free(c->placement);
    c->placement=NULL;
    c->key_length=collection_key(collection,c->key);
    int found=c->key_length?load(disk,at,c->key,c->key_length,&c->placement,&c->migration):-1;
    if(found<0||(found&&(!c->placement||strcmp(yd_shard_placement_collection(c->placement),collection)))){
        yd_shard_control_close(c);
        return NULL;
    }
    return c;
}
YDShardControl *yd_shard_control_open_collection(YDDisk *disk,const char *collection) {
    if(!disk) return NULL;
    YDDiskView view=yd_disk_view(disk);
    return yd_shard_control_open_collection_at(disk,&view,collection);
}
unsigned char *yd_shard_control_export(const YDShardControl *c,size_t *length) {
    if(length)*length=0;
    return c&&length?encode(c->placement,&c->migration,length):NULL;
}
YDShardControl *yd_shard_control_import(const unsigned char *bytes,size_t length) {
    if(length>YD_SHARD_COMMAND_LIMIT)return NULL;
    YDShardControl *c=calloc(1,sizeof(*c));
    if(!c)return NULL;
    if(!decode(bytes,length,&c->placement,&c->migration)){free(c);return NULL;}
    return c;
}
YDShardStatus yd_shard_control_refresh(YDShardControl *c) {
    if(!c||!c->disk)return YD_SHARD_INVALID_ARGUMENT;
    YDDiskView view=yd_disk_view(c->disk);
    YDShardPlacement *p=NULL;YDShardMigration m;
    if(load(c->disk,&view,c->key,c->key_length,&p,&m)<0)return YD_SHARD_CORRUPT;
    yd_shard_placement_free(c->placement);
    c->placement=p;c->migration=m;
    return YD_SHARD_OK;
}
void yd_shard_control_close(YDShardControl *c) {if(c){yd_shard_placement_free(c->placement);
        free(c);
    }}
const YDShardPlacement *yd_shard_control_placement(const YDShardControl *c) {return c?c->placement:NULL;
}
YDShardMigration yd_shard_control_migration(const YDShardControl *c) {return c?c->migration:(YDShardMigration){0};
}
YDShardStatus yd_shard_control_install(YDShardControl *c,const unsigned char *b,size_t n,unsigned char **out,size_t *length) {
    if(!c||!out||!length) return YD_SHARD_INVALID_ARGUMENT;
    *out=NULL;
    *length=0;
    if(c->placement)return YD_SHARD_CONFLICT;
    YDShardPlacement *p=NULL;
    YDShardStatus s=yd_shard_placement_parse(b,n,&p);
    if(s!=YD_SHARD_OK)return s;
    YDShardMigration m={.sequence=1};
    s=command(c,p,&m,out,length);
    yd_shard_placement_free(p);
    return s;
}
YDShardStatus yd_shard_control_begin(YDShardControl *c,const char *shard,const char *target,const char *migration,unsigned char **out,size_t *length) {
    if(!c||!out||!length)return YD_SHARD_INVALID_ARGUMENT;
    *out=NULL;
    *length=0;
    if(!c->placement||c->migration.phase!=YD_SHARD_IDLE)return YD_SHARD_CONFLICT;
    YDShardRange r;
    if(!name(target)||!hexid(migration,32)||!shard||!range(c->placement,shard,&r)||!strcmp(target,r.group))return YD_SHARD_INVALID_ARGUMENT;
    YDShardMigration m={.sequence=c->migration.sequence+1,.phase=YD_SHARD_FENCING};
    strcpy(m.migration,migration);
    strcpy(m.shard,shard);
    strcpy(m.source,r.group);
    strcpy(m.target,target);
    return command(c,c->placement,&m,out,length);
}
YDShardStatus yd_shard_control_advance(YDShardControl *c,const YDShardMigration *next,unsigned char **out,size_t *length) {
    if(!c||!next||!out||!length)return YD_SHARD_INVALID_ARGUMENT;
    YDShardMigration m=*next;
    m.sequence=c->migration.sequence+1;
    YDShardPlacement *moved=NULL;
    const YDShardPlacement *p=c->placement;
    if(c->migration.phase==YD_SHARD_SEALED&&m.phase==YD_SHARD_ACTIVATING) {YDShardStatus s=yd_shard_placement_move(p,m.shard,m.target,&moved);
        if(s!=YD_SHARD_OK)return s;
        p=moved;
    }
    YDShardStatus s=command(c,(YDShardPlacement*)p,&m,out,length);
    yd_shard_placement_free(moved);
    return s;
}
/* Native data keys are named by logical shard, not collection, so a collection
 * joining a shared control namespace must not reuse any shard name. Bounded:
 * at most CONTROL_COLLECTIONS records are read. */
static YDShardStatus install_check(const YDShardControl *c,YDDiskTxn *tx,const YDShardPlacement *p) {
    const char *collection=yd_shard_placement_collection(p);
    if(c->key_length!=sizeof(control_key)){
        char expected[128];size_t size=collection_key(collection,expected);
        if(size!=c->key_length||memcmp(expected,c->key,size))return YD_SHARD_CONFLICT;
    }
    YDDiskView *view=yd_disk_tx_view(tx);
    YDDiskCursor *cursor=view?yd_disk_tx_cursor(tx,control_key,CONTROL_PREFIX,false,NULL,0):NULL;
    if(!cursor)return YD_SHARD_UNAVAILABLE;
    YDShardStatus status=YD_SHARD_OK;
    size_t seen=0;
    while(status==YD_SHARD_OK){
        unsigned char key[1025];size_t size=0;uint64_t offset=0;
        int next=yd_disk_next(cursor,key,sizeof(key),&size,&offset,NULL,0);
        if(next<0){status=YD_SHARD_UNAVAILABLE;break;}
        if(!next||size<CONTROL_PREFIX||memcmp(key,control_key,CONTROL_PREFIX))break;
        if(size==c->key_length&&!memcmp(key,c->key,size))continue;
        if(yd_shard_control_key(key,size)!=1)continue; /* not a control record */
        if(++seen>=CONTROL_COLLECTIONS){status=YD_SHARD_BUDGET_EXCEEDED;break;}
        size_t length=0;
        unsigned char *record=yd_disk_record(c->disk,view,offset,&length,NULL,0);
        YDShardPlacement *other=NULL;YDShardMigration migration;
        if(!record||!decode(record,length,&other,&migration)){free(record);status=YD_SHARD_CORRUPT;break;}
        free(record);
        if(other&&!strcmp(yd_shard_placement_collection(other),collection))status=YD_SHARD_CONFLICT;
        for(size_t i=0;other&&status==YD_SHARD_OK&&i<yd_shard_placement_ranges(p);i++)
            for(size_t j=0;j<yd_shard_placement_ranges(other);j++){
                YDShardRange a,b;
                if(yd_shard_placement_range(p,i,&a)&&yd_shard_placement_range(other,j,&b)&&!strcmp(a.shard,b.shard)){
                    status=YD_SHARD_CONFLICT;break;
                }
            }
        yd_shard_placement_free(other);
    }
    yd_disk_cursor_free(cursor);
    return status;
}
YDShardStatus yd_shard_control_stage(YDShardControl *c,const unsigned char *b,size_t n,YDDiskTxn *tx) {
    if(!c||!c->disk||!tx||!b||n>YD_SHARD_COMMAND_LIMIT||n<36||memcmp(b,"YCC1",4))return YD_SHARD_INVALID_ARGUMENT;
    /* A captured control read cannot overwrite an intervening publication. */
    if(!c->key_length)return YD_SHARD_INVALID_ARGUMENT;
    uint64_t existing=0;
    int found=yd_disk_tx_get(tx,c->key,c->key_length,&existing,NULL,0);
    if(found<0)return YD_SHARD_UNAVAILABLE;
    YDDiskView current=yd_disk_view(c->disk);
    if(found){
        size_t size=0;unsigned char *stored=yd_disk_record(c->disk,&current,existing,&size,NULL,0);
        size_t expected_size=0;unsigned char *expected=encode(c->placement,&c->migration,&expected_size);
        bool equal=stored&&expected&&size==expected_size&&!memcmp(stored,expected,size);
        free(stored);free(expected);if(!equal)return YD_SHARD_CONFLICT;
    }else if(c->placement)return YD_SHARD_CONFLICT;
    YDShardPlacement *p=NULL;
    YDShardMigration m;
    if(!decode(b+36,n-36,&p,&m))return YD_SHARD_CORRUPT;
    size_t before_n;
    unsigned char *before=encode(c->placement,&c->migration,&before_n);
    if(!before){yd_shard_placement_free(p);
        return YD_SHARD_RESOURCE_FAILURE;
    }
    if(before_n==n-36&&!memcmp(before,b+36,before_n)) {free(before);
        yd_shard_placement_free(p);
        return YD_SHARD_OK;
    }
    unsigned char hash[32];
    bool ok=digest(before,before_n,hash)&&!memcmp(hash,b+4,32)&&transition(c,p,&m);
    free(before);
    if(!ok){yd_shard_placement_free(p);
        return YD_SHARD_CONFLICT;
    }
    if(!c->placement){
        YDShardStatus shared=install_check(c,tx,p);
        if(shared!=YD_SHARD_OK){yd_shard_placement_free(p);return shared;}
    }
    uint64_t offset;
    if(c->migration.phase==YD_SHARD_IDLE&&m.phase==YD_SHARD_FENCING){
        char receipt[80];snprintf(receipt,sizeof(receipt),"\001shard-migration/%s",m.migration);
        uint64_t used=0;int seen=yd_disk_tx_get(tx,receipt,strlen(receipt),&used,NULL,0);
        if(seen!=0){yd_shard_placement_free(p);return seen>0?YD_SHARD_CONFLICT:YD_SHARD_UNAVAILABLE;}
        uint64_t marker;
        if(!yd_disk_append(tx,"YSM1",4,&marker,NULL,0)||!yd_disk_put(tx,receipt,strlen(receipt),marker,NULL,0)){yd_shard_placement_free(p);return YD_SHARD_UNAVAILABLE;}
    }
    if(!yd_disk_append(tx,b+36,n-36,&offset,NULL,0)||!yd_disk_put(tx,c->key,c->key_length,offset,NULL,0)){
        yd_shard_placement_free(p);
        return YD_SHARD_UNAVAILABLE;
    }
    yd_shard_placement_free(p);
    return YD_SHARD_OK;
}
YDShardStatus yd_shard_control_apply(YDShardControl *c,const unsigned char *b,size_t n) {
    if(!c||!c->disk)return YD_SHARD_INVALID_ARGUMENT;
    YDDiskTxn *tx=yd_disk_begin(c->disk,NULL,0);
    if(!tx)return YD_SHARD_UNAVAILABLE;
    YDShardStatus status=yd_shard_control_stage(c,b,n,tx);
    if(status!=YD_SHARD_OK){yd_disk_abort(tx);return status;}
    if(!yd_disk_commit(tx,NULL,0))return YD_SHARD_UNAVAILABLE;
    return yd_shard_control_refresh(c);
}
int yd_shard_control_key(const void *key,size_t length) {
    if(!key)return 0;
    const unsigned char *bytes=key;
    if(length==sizeof(control_key)&&!memcmp(bytes,control_key,length))return 1;
    const char prefix[]="\001shard-migration/";
    size_t prefix_length=sizeof(prefix)-1;
    if(length>=prefix_length&&!memcmp(bytes,prefix,prefix_length)){
        if(length!=prefix_length+32)return -1;
        char id[33];memcpy(id,bytes+prefix_length,32);id[32]=0;
        return hexid(id,32)?1:-1;
    }
    if(length>CONTROL_PREFIX+2&&length<=CONTROL_PREFIX+65&&!memcmp(bytes,control_key,CONTROL_PREFIX)&&
        bytes[CONTROL_PREFIX]=='/'&&!bytes[length-1]){
        char collection[64];size_t size=length-CONTROL_PREFIX-2;
        memcpy(collection,bytes+CONTROL_PREFIX+1,size);collection[size]=0;
        if(strlen(collection)==size&&name(collection))return 1;
    }
    const char control_prefix[]="\001yamora-shard-control";
    if(length>=sizeof(control_prefix)-1&&!memcmp(bytes,control_prefix,sizeof(control_prefix)-1))return -1;
    return 0;
}
static bool collection_record(const void *key,size_t length,char collection[64]) {
    const unsigned char *bytes=key;
    if(length<=CONTROL_PREFIX+2||length>CONTROL_PREFIX+65||memcmp(bytes,control_key,CONTROL_PREFIX)||bytes[CONTROL_PREFIX]!='/')return false;
    size_t size=length-CONTROL_PREFIX-2;
    memcpy(collection,bytes+CONTROL_PREFIX+1,size);collection[size]=0;
    return true;
}
bool yd_shard_control_validate_record(const void *key,size_t key_length,
    const unsigned char *bytes,size_t length) {
    if(yd_shard_control_key(key,key_length)!=1||!bytes)return false;
    char collection[64];
    bool named=collection_record(key,key_length,collection);
    if(key_length!=sizeof(control_key)&&!named)return length==4&&!memcmp(bytes,"YSM1",4);
    YDShardPlacement *p=NULL;YDShardMigration migration;
    bool valid=length<=YD_SHARD_COMMAND_LIMIT&&decode(bytes,length,&p,&migration);
    if(valid){size_t size=0;unsigned char *canonical=encode(p,&migration,&size);
        valid=canonical&&size==length&&!memcmp(canonical,bytes,length);free(canonical);}
    /* A collection record holds exactly its own collection's placement. */
    if(valid&&named)valid=p&&!strcmp(yd_shard_placement_collection(p),collection);
    yd_shard_placement_free(p);return valid;
}
