#include "disk_branch.h"
#include "disk_internal.h"
#include <stdlib.h>
#include <string.h>

static bool matches(YDHistory *h,uint64_t sequence,const char *token) {
    char expected[YD_HISTORY_TOKEN]; yd_disk_history_token(h,sequence,expected);
    return token && !strcmp(expected,token);
}
static int catalog(YDDiskTxn *txn,YDHistory *h,char *error,size_t length) {
    if (!txn || !txn->exclusive || !(txn->view.capabilities&YD_DISK_CAP_HISTORY)) return 409;
    if (!yd_disk_history_start(txn,error,length)) return 503;
    int found=yd_disk_history_tx_load(txn,h,error,length);
    if (found==1 && h->last>UINT64_MAX-2) return 413;
    return found==1?200:found<0?503:409;
}
int yd_disk_branch_create(YDDiskTxn *txn,const char *name,const char *from,char *error,size_t length) {
    YDHistory h; int status=catalog(txn,&h,error,length);
    if (status!=200) return status;
    if (!yamldb_valid_name(name) || !strcmp(name,"main")) return 400;
    if (yd_disk_history_branch(&h,name)) return 409;
    if (h.branches==YD_HISTORY_BRANCHES) return 413;
    YDHistoryCommit *commit=NULL;
    status=yd_disk_history_select(&h,from,&commit);
    if (status!=200) return status;
    uint64_t source=commit->sequence,base=commit->base;
    YDHistoryBranch *source_branch=yd_disk_history_branch(&h,from);
    if (source_branch) base=!strcmp(from,"main")?source:source_branch->base;
    if (!source) return 503;
    if (!yd_disk_history_commit(&h,base)) return 410;
    YDHistoryBranch *b=&h.names[h.branches++];
    strcpy(b->name,name); b->head=source;b->base=base;
    return yd_disk_history_store(txn,&h,error,length)?201:503;
}
int yd_disk_branch_delete(YDDiskTxn *txn,const char *name,const char *head,char *error,size_t length) {
    YDHistory h; int status=catalog(txn,&h,error,length);
    if (status!=200) return status;
    if (!strcmp(name,"main")) return 400;
    YDHistoryBranch *b=yd_disk_history_branch(&h,name);
    if (!b) return 404;
    if (!matches(&h,b->head,head)) return 412;
    size_t at=(size_t)(b-h.names);
    memmove(b,b+1,(h.branches-at-1)*sizeof(*b)); h.branches--;
    return yd_disk_history_store(txn,&h,error,length)?200:503;
}
int yd_disk_branch_enter(YDDiskTxn *txn,const char *name,const char *head,YDHistory *h,
    YDDiskView *main,char *error,size_t length) {
    int status=catalog(txn,h,error,length);
    if (status!=200) return status;
    if (!strcmp(name,"main")) return 400;
    YDHistoryBranch *b=yd_disk_history_branch(h,name);
    if (!b) return 404;
    if (!matches(h,b->head,head)) return 412;
    *main=txn->view;
    txn->view=yd_disk_history_commit(h,b->head)->view;
    /* The private branch may read old records but reserves only after the
     * complete current publication; never overwrite another retained root. */
    txn->view.generation=txn->base.generation;
    txn->view.end=txn->next;
    return 200;
}
static bool clear_feed(YDDiskTxn *txn,char *error,size_t length) {
    /* A branch is a source/query snapshot, not a second producer of the main
     * feed identity/sequence. Inherited log or legacy-follow checkpoints would
     * falsely claim that their old revision describes this changed dataset. */
    for (;;) {
        YDDiskCursor *cursor=yd_disk_tx_cursor(txn,"\0YLF",4,false,error,length);
        unsigned char key[YD_DISK_KEY_LIMIT];size_t size=0;uint64_t value=0;
        int next=cursor?yd_disk_next(cursor,key,sizeof(key),&size,&value,error,length):-1;
        yd_disk_cursor_free(cursor);
        if (next<0) return false;
        if (!next || size<4 || memcmp(key,"\0YLF",4)) break;
        if (size!=12 || !yd_disk_delete(txn,key,size,error,length)) return false;
    }
    return yd_disk_delete(txn,"\0YLM",4,error,length) &&
        yd_disk_delete(txn,"\0YRP",4,error,length);
}
bool yd_disk_branch_leave(YDDiskTxn *txn,YDHistory *h,const char *name,
    const YDDiskView *main,char token[YD_HISTORY_TOKEN],char *error,size_t length) {
    YDHistoryBranch *b=yd_disk_history_branch(h,name);
    YDDiskView view;
    if (!b || !clear_feed(txn,error,length) || !yd_disk_tx_freeze(txn,&view,error,length)) return false;
    view.generation=txn->base.generation+1;
    uint64_t sequence=0;
    if (!yd_disk_history_add(h,&view,b->head,&sequence,error,length)) return false;
    yd_disk_history_commit(h,sequence)->base=b->base;
    b->head=sequence;
    txn->view=*main; txn->view.end=txn->next;
    /* Branch document changes do not describe the live main dataset. One
     * reset marker advances observers to a coherent unchanged main root. */
    yd_disk_log_free(txn); txn->log_enabled=txn->log_reset=true;
    yd_disk_history_token(h,sequence,token);
    return yd_disk_history_store(txn,h,error,length);
}
typedef struct { unsigned char key[YD_DISK_KEY_LIMIT];size_t size;uint64_t value;int next; } Item;
static bool advance(YDDiskCursor *cursor,Item *item,char *error,size_t length) {
    item->next=yd_disk_next(cursor,item->key,sizeof(item->key),&item->size,&item->value,error,length);
    if (item->next==1 && item->key[0]!='D') item->next=0;
    return item->next>=0;
}
static int order(const Item *a,const Item *b) {
    if (!a->next) return b->next?1:0;
    if (!b->next) return -1;
    int n=memcmp(a->key,b->key,a->size<b->size?a->size:b->size);
    return n?n:(a->size>b->size)-(a->size<b->size);
}
static bool same(const YDDiskDocument *a,bool have_a,const YDDiskDocument *b,bool have_b) {
    return have_a==have_b && (!have_a || (a->length==b->length && !memcmp(a->body,b->body,a->length)));
}
int yd_disk_branch_merge(YDDiskTxn *txn,const char *name,const char *head,const char *main,
    YDPolicyWork *work,size_t *operations,char *error,size_t length) {
    YDHistory h; int status=catalog(txn,&h,error,length); *operations=0;
    if (status!=200) return status;
    if (!strcmp(name,"main")) return 400;
    YDHistoryBranch *b=yd_disk_history_branch(&h,name);
    if (!b) return 404;
    if (!matches(&h,b->head,head) || !matches(&h,h.names[0].head,main)) return 412;
    YDDiskView base=yd_disk_history_commit(&h,b->base)->view;
    YDDiskView source=yd_disk_history_commit(&h,b->head)->view;
    YDDiskCursor *ac=yd_disk_cursor(txn->disk,&base,"D",1,false,error,length);
    YDDiskCursor *bc=ac?yd_disk_cursor(txn->disk,&source,"D",1,false,error,length):NULL;
    Item a={0},c={0};
    YDDiskDocument replacements[128]={0}; YDWrite writes[128]={0};
    size_t count=0,scanned=0,charged=0;
    bool valid=ac && bc && advance(ac,&a,error,length) && advance(bc,&c,error,length);
    while (valid && (a.next || c.next)) {
        if (++scanned>65536) { status=413; break; }
        int cmp=order(&a,&c);
        bool have_a=a.next && cmp<=0, have_c=c.next && cmp>=0;
        YDDiskDocument old={0},incoming={0},current={0};
        valid=(!have_a || yd_disk_document_at(txn->disk,&base,a.value,&old,error,length)) &&
            (!have_c || yd_disk_document_at(txn->disk,&source,c.value,&incoming,error,length));
        if (valid && old.length+incoming.length>64U*1024U*1024U-charged) status=413;
        if (valid && status==200) charged+=old.length+incoming.length;
        if (valid && status==200 && !same(&old,have_a,&incoming,have_c)) {
            const YDDiskDocument *identity=have_c?&incoming:&old;
            int found=yd_disk_document_tx_get(txn,identity->collection,identity->id,&current,error,length);
            valid=found>=0;
            if (valid && current.length>64U*1024U*1024U-charged) status=413;
            else if (valid) charged+=current.length;
            if (valid && status==200 && !same(&current,found==1,&old,have_a) &&
                !same(&current,found==1,&incoming,have_c)) status=409;
            if (valid && status==200 && !same(&current,found==1,&incoming,have_c)) {
                if (count==128) status=413;
                else {
                    replacements[count]=have_c?incoming:old;
                    if (have_c) memset(&incoming,0,sizeof(incoming)); else memset(&old,0,sizeof(old));
                    YDDiskDocument *r=&replacements[count];
                    writes[count++]=(YDWrite){.collection=r->collection,.document=r->id,
                        .body=have_c?r->body:NULL,.length=have_c?r->length:0};
                }
            }
        }
        yd_disk_document_free(&old); yd_disk_document_free(&incoming); yd_disk_document_free(&current);
        if (!valid || status!=200) break;
        if (have_a) valid=advance(ac,&a,error,length);
        if (valid && have_c) valid=advance(bc,&c,error,length);
    }
    yd_disk_cursor_free(ac); yd_disk_cursor_free(bc);
    if (!valid) status=503;
    if (status==200 && count) {
        YDPolicyResult applied=yd_disk_apply_with_policy(txn,writes,count,work,error,length);
        if (applied!=YD_POLICY_OK) status=applied==YD_POLICY_LIMIT?413:409;
    }
    for (size_t i=0;i<count;i++) yd_disk_document_free(&replacements[i]);
    if (status==200) { b->base=b->head; *operations=count;
        if (!yd_disk_history_store(txn,&h,error,length)) status=503; }
    return status;
}
