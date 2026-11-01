#define _POSIX_C_SOURCE 200809L
#include "disk_history.h"
#include "disk_internal.h"
#include "name.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const unsigned char key[] = {0,'Y','B','H'};
#define HEADER 48U
#define COMMIT 80U
#define BRANCH 152U

YDHistoryCommit *yd_disk_history_commit(YDHistory *h, uint64_t sequence) {
    for (size_t i=0;i<h->count;i++) if (h->commits[i].sequence==sequence) return &h->commits[i];
    return NULL;
}
YDHistoryBranch *yd_disk_history_branch(YDHistory *h, const char *name) {
    for (size_t i=0;i<h->branches;i++) if (!strcmp(h->names[i].name,name)) return &h->names[i];
    return NULL;
}
static bool shape(YDHistory *h, const YDDiskView *view) {
    unsigned identity=0;
    for (unsigned i=0;i<16;i++) identity|=h->identity[i];
    if (!identity || !h->last || !h->count || h->count>YD_HISTORY_COMMITS ||
        !h->branches || h->branches>YD_HISTORY_BRANCHES || strcmp(h->names[0].name,"main")) return false;
    uint64_t prior=0;
    for (size_t i=0;i<h->count;i++) {
        YDHistoryCommit *c=&h->commits[i];
        YDDiskView *v=&c->view;
        if (c->sequence<=prior || c->sequence>h->last || c->parent>=c->sequence ||
            !c->base || c->base>c->sequence ||
            v->format!=view->format || v->capabilities!=view->capabilities ||
            !v->generation || v->generation>view->generation || v->end>view->end ||
            v->end<2*YD_DISK_PAGE || (v->root && (v->root<2*YD_DISK_PAGE ||
                v->root%YD_DISK_PAGE || v->root>v->end-YD_DISK_PAGE))) return false;
        prior=c->sequence;
    }
    for (size_t i=0;i<h->branches;i++) {
        YDHistoryBranch *b=&h->names[i];
        if (!yd_name_valid(b->name) || !yd_disk_history_commit(h,b->head) ||
            (i && !yd_disk_history_commit(h,b->base))) return false;
        for (size_t j=0;j<i;j++) if (!strcmp(b->name,h->names[j].name)) return false;
    }
    return true;
}
static int decode(YDDisk *disk, const YDDiskView *view, uint64_t offset,
    YDHistory *h,char *error,size_t length) {
    size_t n=0;
    unsigned char *p=yd_disk_record(disk,view,offset,&n,error,length);
    bool valid=p && n>=HEADER && !memcmp(p,"YDBRAN01",8);
    if (valid) {
        memcpy(h->identity,p+8,16); h->last=yd_disk_u64(p+24);
        h->count=yd_disk_u64(p+32); h->branches=yd_disk_u64(p+40);
        valid=h->count<=YD_HISTORY_COMMITS && h->branches<=YD_HISTORY_BRANCHES &&
            n==HEADER+h->count*COMMIT+h->branches*BRANCH;
    }
    size_t at=HEADER;
    for (size_t i=0;valid && i<h->count;i++,at+=COMMIT) {
        YDHistoryCommit *c=&h->commits[i];
        c->sequence=yd_disk_u64(p+at); c->parent=yd_disk_u64(p+at+8);
        /* Retained roots live in the same file as the catalog that names them. */
        c->view=(YDDiskView){.format=view->format,.capabilities=view->capabilities,
            .generation=yd_disk_u64(p+at+16),.root=yd_disk_u64(p+at+24),
            .end=yd_disk_u64(p+at+32),.documents=yd_disk_u64(p+at+40),
            .collections=yd_disk_u64(p+at+48),.bytes=yd_disk_u64(p+at+56),
            .revision=yd_disk_u64(p+at+64),.epoch=view->epoch};
        c->base=yd_disk_u64(p+at+72);
    }
    for (size_t i=0;valid && i<h->branches;i++,at+=BRANCH) {
        YDHistoryBranch *b=&h->names[i];
        const unsigned char *zero=memchr(p+at,0,129);
        valid=zero!=NULL;
        if (!valid) break;
        size_t used=(size_t)(zero-(p+at));
        memcpy(b->name,p+at,used);
        for (size_t j=used;j<136;j++) if (p[at+j]) valid=false;
        b->head=yd_disk_u64(p+at+136); b->base=yd_disk_u64(p+at+144);
    }
    valid=valid && shape(h,view);
    free(p);
    if (!valid) { memset(h,0,sizeof(*h)); yd_disk_error(error,length,"invalid retained root catalog"); }
    return valid?1:-1;
}
int yd_disk_history_load(YDDisk *disk,const YDDiskView *view,YDHistory *h,char *error,size_t length) {
    memset(h,0,sizeof(*h));
    uint64_t offset=0;
    int found=yd_disk_get(disk,view,key,sizeof(key),&offset,error,length);
    if (found!=1) return found;
    if (!(view->capabilities&YD_DISK_CAP_HISTORY)) return -1;
    return decode(disk,view,offset,h,error,length);
}
int yd_disk_history_tx_load(YDDiskTxn *txn,YDHistory *h,char *error,size_t length) {
    memset(h,0,sizeof(*h));
    uint64_t offset=0;
    int found=yd_disk_tx_peek(txn,key,sizeof(key),&offset,error,length);
    YDDiskView v=txn->view; v.end=txn->next; v.generation++;
    return found==1?decode(txn->disk,&v,offset,h,error,length):found;
}
bool yd_disk_history_store(YDDiskTxn *txn,const YDHistory *h,char *error,size_t length) {
    size_t n=0; unsigned char *p=yd_disk_history_encode(h,&n);
    if (!p) return false;
    uint64_t offset=0;
    bool valid=yd_disk_append(txn,p,n,&offset,error,length) && yd_disk_put(txn,key,sizeof(key),offset,error,length);
    free(p); return valid;
}
unsigned char *yd_disk_history_encode(const YDHistory *h,size_t *size) {
    *size=0;
    size_t n=HEADER+h->count*COMMIT+h->branches*BRANCH;
    if (h->count>YD_HISTORY_COMMITS || h->branches>YD_HISTORY_BRANCHES) return NULL;
    unsigned char *p=calloc(1,n);
    if (!p) return NULL;
    memcpy(p,"YDBRAN01",8); memcpy(p+8,h->identity,16);
    yd_disk_set64(p+24,h->last); yd_disk_set64(p+32,h->count); yd_disk_set64(p+40,h->branches);
    size_t at=HEADER;
    for (size_t i=0;i<h->count;i++,at+=COMMIT) {
        const YDHistoryCommit *c=&h->commits[i]; const YDDiskView *v=&c->view;
        yd_disk_set64(p+at,c->sequence); yd_disk_set64(p+at+8,c->parent);
        yd_disk_set64(p+at+16,v->generation); yd_disk_set64(p+at+24,v->root);
        yd_disk_set64(p+at+32,v->end); yd_disk_set64(p+at+40,v->documents);
        yd_disk_set64(p+at+48,v->collections); yd_disk_set64(p+at+56,v->bytes);
        yd_disk_set64(p+at+64,v->revision);
        yd_disk_set64(p+at+72,c->base);
    }
    for (size_t i=0;i<h->branches;i++,at+=BRANCH) {
        const YDHistoryBranch *b=&h->names[i];
        memcpy(p+at,b->name,strlen(b->name));
        yd_disk_set64(p+at+136,b->head); yd_disk_set64(p+at+144,b->base);
    }
    *size=n; return p;
}
int yd_disk_history_decode_at(YDDisk *disk,const YDDiskView *view,uint64_t offset,
    YDHistory *h,char *error,size_t length) {
    memset(h,0,sizeof(*h));
    if (!(view->capabilities&YD_DISK_CAP_HISTORY)) return -1;
    return decode(disk,view,offset,h,error,length);
}
void yd_disk_history_token(const YDHistory *h,uint64_t sequence,char out[YD_HISTORY_TOKEN]) {
    static const char hex[]="0123456789abcdef";
    memcpy(out,"c1.",3);
    for (unsigned i=0;i<16;i++) { out[3+2*i]=hex[h->identity[i]>>4]; out[4+2*i]=hex[h->identity[i]&15]; }
    snprintf(out+35,YD_HISTORY_TOKEN-35,".%016llx",(unsigned long long)sequence);
}
int yd_disk_history_select(YDHistory *h,const char *selector,YDHistoryCommit **out) {
    *out=NULL;
    if (!selector) return 400;
    uint64_t sequence=0;
    if (!strncmp(selector,"c1.",3)) {
        if (strlen(selector)!=52 || selector[35]!='.') return 400;
        for (unsigned i=3;i<52;i++) if (i!=35 &&
            !((selector[i]>='0' && selector[i]<='9') || (selector[i]>='a' && selector[i]<='f'))) return 400;
        char expected[YD_HISTORY_TOKEN]; yd_disk_history_token(h,0,expected);
        if (memcmp(selector,expected,35)) return 409;
        for (unsigned i=36;i<52;i++) sequence=(sequence<<4)|(unsigned)(selector[i]<='9'?selector[i]-'0':selector[i]-'a'+10);
    } else {
        if (!yd_name_valid(selector)) return 400;
        YDHistoryBranch *b=yd_disk_history_branch(h,selector);
        if (!b) return 404;
        sequence=b->head;
    }
    *out=yd_disk_history_commit(h,sequence);
    return *out?200:sequence && sequence<=h->last?410:404;
}
int yd_disk_history_resolve(YDDisk *disk,const YDDiskView *view,const char *selector,
    YDDiskView *out,char token[YD_HISTORY_TOKEN],char *error,size_t length) {
    memset(out,0,sizeof(*out)); token[0]=0;
    if (!(view->capabilities&YD_DISK_CAP_HISTORY)) return 409;
    YDHistory h;
    int loaded=yd_disk_history_load(disk,view,&h,error,length);
    if (loaded<=0) return loaded<0?503:404;
    YDHistoryCommit *c=NULL;
    int status=yd_disk_history_select(&h,selector,&c);
    if (status!=200) return status;
    *out=c->view; yd_disk_history_token(&h,c->sequence,token); return 200;
}
bool yd_disk_history_start(YDDiskTxn *txn,char *error,size_t length) {
    YDHistory h;
    int found=yd_disk_history_tx_load(txn,&h,error,length);
    if (found) return found==1;
    uint64_t offset=0;
    if (!(txn->view.capabilities&YD_DISK_CAP_CLUSTER) ||
        yd_disk_tx_peek(txn,"\0YRA",4,&offset,error,length)!=1) return false;
    size_t n=0; YDDiskView v=txn->view; v.end=txn->next;
    unsigned char *p=yd_disk_record(txn->disk,&v,offset,&n,error,length);
    bool valid=p && n==96 && !memcmp(p,"YDAPLY01",8);
    if (valid) memcpy(h.identity,p+8,16);
    free(p);
    h.branches=1; strcpy(h.names[0].name,"main");
    uint64_t sequence=0;
    valid=valid && yd_disk_tx_freeze(txn,&v,error,length) &&
        yd_disk_history_add(&h,&v,0,&sequence,error,length);
    h.names[0].head=sequence;
    return valid && yd_disk_history_store(txn,&h,error,length);
}
bool yd_disk_history_add(YDHistory *h,const YDDiskView *view,uint64_t parent,
    uint64_t *sequence,char *error,size_t length) {
    if (h->last==UINT64_MAX) return yd_disk_error(error,length,"history sequence exhausted");
    if (h->count==YD_HISTORY_COMMITS) {
        size_t remove=0;
        for (;remove<h->count;remove++) {
            bool held=false;
            for (size_t j=0;j<h->branches;j++)
                held|=h->names[j].head==h->commits[remove].sequence || h->names[j].base==h->commits[remove].sequence;
            if (!held) break;
        }
        if (remove==h->count) return yd_disk_error(error,length,"all retained roots pinned");
        memmove(h->commits+remove,h->commits+remove+1,(h->count-remove-1)*sizeof(*h->commits)); h->count--;
    }
    *sequence=++h->last;
    h->commits[h->count++]=(YDHistoryCommit){.sequence=*sequence,.parent=parent,.view=*view,.base=*sequence}; return true;
}
bool yd_disk_history_publish(YDDiskTxn *txn,const YDDiskView *current,char *error,size_t length) {
    if (!(txn->view.capabilities&YD_DISK_CAP_HISTORY) || txn->history_copy) return true;
    if ((txn->view.capabilities&YD_DISK_CAP_CLUSTER) && !txn->log_identity_set) return true; /* genesis */
    YDHistory h;
    int found=yd_disk_history_tx_load(txn,&h,error,length);
    if (found<0) return false;
    if (!found) {
        uint64_t offset=0;
        if (yd_disk_tx_peek(txn,"\0YLM",4,&offset,error,length)!=1) return false;
        YDDiskView view=txn->view; view.end=txn->next;
        size_t size=0; unsigned char *meta=yd_disk_record(txn->disk,&view,offset,&size,error,length);
        bool valid=meta && size==56 && !memcmp(meta,"YDLOGM01",8);
        if (valid) memcpy(h.identity,meta+8,16);
        free(meta); if (!valid) return false;
        h.branches=1; strcpy(h.names[0].name,"main");
    }
    uint64_t parent=h.names[0].head, sequence=0;
    bool replay=txn->replay; txn->replay=true;
    YDDiskView snapshot;
    bool valid=yd_disk_delete(txn,key,sizeof(key),error,length) &&
        yd_disk_tx_seal(txn,&snapshot,error,length);
    snapshot.generation=current->generation+1;
    valid=valid && yd_disk_history_add(&h,&snapshot,parent,&sequence,error,length);
    if (valid) { h.names[0].head=sequence; valid=yd_disk_history_store(txn,&h,error,length); }
    txn->replay=replay; return valid;
}
bool yd_disk_history_copy(YDDisk *source,const YDDiskView *view,YDDiskTxn *txn,
    YDHistoryCopyRoot copy,void *context,char *error,size_t length) {
    YDHistory h; int found=yd_disk_history_load(source,view,&h,error,length);
    if (found<=0) return found==0;
    for (size_t i=0;i<h.count;i++) {
        YDDiskView relocated;
        if (!copy(context,&h.commits[i].view,&relocated,error,length)) return false;
        h.commits[i].view=relocated;
    }
    return yd_disk_history_store(txn,&h,error,length);
}
bool yd_disk_history_same(YDDisk *a,const YDDiskView *av,YDDisk *b,const YDDiskView *bv,
    YDHistorySameRoot same,void *context,char *error,size_t length) {
    YDHistory x,y;
    int ax=yd_disk_history_load(a,av,&x,error,length), by=yd_disk_history_load(b,bv,&y,error,length);
    if (ax!=by || ax<0) return false;
    if (!ax) return true;
    if (memcmp(x.identity,y.identity,16) || x.last!=y.last || x.count!=y.count || x.branches!=y.branches) return false;
    for (size_t i=0;i<x.branches;i++) if (strcmp(x.names[i].name,y.names[i].name) ||
        x.names[i].head!=y.names[i].head || x.names[i].base!=y.names[i].base) return false;
    for (size_t i=0;i<x.count;i++) if (x.commits[i].sequence!=y.commits[i].sequence ||
        x.commits[i].parent!=y.commits[i].parent || x.commits[i].base!=y.commits[i].base ||
        !same(context,&x.commits[i].view,&y.commits[i].view,error,length)) return false;
    return true;
}
