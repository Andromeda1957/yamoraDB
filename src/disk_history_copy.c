#include "disk_history.h"
#include "disk_internal.h"
#include "sharding/service.h"
#include <stdlib.h>
#include <string.h>

/* Shared by history copies and online compaction (disk_compact.c). */
bool yd_disk_relocation_record_key(const unsigned char *key,size_t n) {
    return (n==4 && (!memcmp(key,"\0YRA",4) || !memcmp(key,"\0YLM",4) ||
        !memcmp(key,"\0YRD",4) || !memcmp(key,"\0YRS",4) || !memcmp(key,"\0YRP",4))) ||
        (n==20 && (!memcmp(key,"\0YRR",4) || !memcmp(key,"\0YRI",4) ||
        !memcmp(key,"\0YSP",4) || !memcmp(key,"\0YBR",4))) ||
        ((n==4 || n==20) && !memcmp(key,"\0YRJ",4)) ||
        (n>=6 && !memcmp(key,"\0YRO",4)) || yd_shard_service_key(key,n)==1;
}
static void map_key(unsigned char key[12],uint64_t old) {memcpy(key,"\0YMP",4);yd_disk_set64(key+4,old);}
static int mapped(YDDiskTxn *txn,YDDiskView *map,uint64_t old,uint64_t *value,bool store,char *error,size_t length) {
    unsigned char key[12];map_key(key,old);YDDiskView saved=txn->view;
    if (!map->format) {*map=saved;map->root=map->documents=map->collections=map->bytes=map->revision=0;}
    txn->view=*map;txn->view.end=txn->next;
    int result=store?(yd_disk_put(txn,key,sizeof(key),*value,error,length)?1:-1):
        yd_disk_tx_peek(txn,key,sizeof(key),value,error,length);
    *map=txn->view;txn->view=saved;txn->view.end=txn->next;return result;
}
static bool relocate(YDDisk *source,const YDDiskView *view,YDDiskTxn *txn,YDDiskView *map,uint64_t old,
    uint64_t *out,char *error,size_t length) {
    int found=mapped(txn,map,old,out,false,error,length);
    if (found) return found==1;
    size_t n=0;unsigned char *p=yd_disk_record(source,view,old,&n,error,length);
    bool valid=p && yd_disk_append(txn,p,n,out,error,length) && mapped(txn,map,old,out,true,error,length)==1;
    free(p);return valid;
}
static bool frame(YDDisk *source,const YDDiskView *view,YDDiskTxn *txn,YDDiskView *map,uint64_t old,
    uint64_t *out,char *error,size_t length) {
    int found=mapped(txn,map,old,out,false,error,length);
    if (found) return found==1;
    size_t n=0;unsigned char *p=yd_disk_record(source,view,old,&n,error,length);
    bool valid=p && n>=56 && !memcmp(p,"YDLOGF01",8);
    size_t at=56;unsigned count=valid?yd_disk_u16(p+42):0;
    for (unsigned i=0;valid && i<count;i++) {
        valid=n-at>=20;
        size_t size=valid?yd_disk_u16(p+at):0;
        valid=valid && size && size<=n-at-20;
        if (!valid) break;
        if (!p[at+2] && p[at+20]=='D') {
            uint64_t replacement=0;
            valid=relocate(source,view,txn,map,yd_disk_u64(p+at+4),&replacement,error,length);
            if (valid) yd_disk_set64(p+at+4,replacement);
        }
        at+=20+size;
    }
    valid=valid && at==n && yd_disk_append(txn,p,n,out,error,length) && mapped(txn,map,old,out,true,error,length)==1;
    free(p);return valid;
}
bool yd_disk_history_root_copy_mapped(YDDisk *source,const YDDiskView *view,YDDiskTxn *txn,
    YDDiskView *out,YDDiskView *map,YDDiskValidation *state,char *error,size_t length) {
    if (!txn || !txn->exclusive || view->format!=txn->view.format ||
        view->capabilities!=txn->view.capabilities ||
        !yd_disk_validation_step(state,YD_VALIDATE_HISTORY)) return false;
    YDDiskView saved=txn->view;
    txn->view=*view;txn->view.root=0;txn->view.end=txn->next;
    bool valid=true;
    for (unsigned pass=0;valid && pass<3;pass++) {
        YDDiskCursor *cursor=yd_disk_cursor(source,view,NULL,0,false,error,length);
        unsigned char key[YD_DISK_KEY_LIMIT];size_t size=0;uint64_t old=0,value=0;
        int next=0;valid=cursor!=NULL;
        while (valid && (next=yd_disk_next(cursor,key,sizeof(key),&size,&old,error,length))==1) {
            if (!yd_disk_validation_step(state,YD_VALIDATE_HISTORY)) {valid=false;break;}
            bool document=key[0]=='D',index=key[0]=='I' || key[0]=='U';
            bool logged=size==12 && !memcmp(key,"\0YLF",4);
            bool catalog=size==4 && !memcmp(key,"\0YBH",4);
            if (catalog) continue;
            if (key[0]!='C' && !document && !index && !logged && !yd_disk_relocation_record_key(key,size)) {valid=false;break;}
            if (pass==0 && key[0]=='C') valid=yd_disk_put(txn,key,size,old,error,length);
            else if (pass==0 && document) valid=relocate(source,view,txn,map,old,&value,error,length) && yd_disk_put(txn,key,size,value,error,length);
            else if (pass==1 && (logged || yd_disk_relocation_record_key(key,size))) {
                valid=(logged?frame(source,view,txn,map,old,&value,error,length):relocate(source,view,txn,map,old,&value,error,length)) &&
                    yd_disk_put(txn,key,size,value,error,length);
            } else if (pass==2 && index) {
                valid=mapped(txn,map,old,&value,false,error,length)==1 && yd_disk_put(txn,key,size,value,error,length);
            }
        }
        yd_disk_cursor_free(cursor);valid=valid && next==0;
    }
    if (valid) valid=yd_disk_tx_freeze(txn,out,error,length);
    txn->view=saved;txn->view.end=txn->next;
    return valid;
}
bool yd_disk_history_root_copy(YDDisk *source,const YDDiskView *view,YDDiskTxn *txn,
    YDDiskView *out,char *error,size_t length) {
    YDDiskView map={0};return yd_disk_history_root_copy_mapped(source,view,txn,out,&map,NULL,error,length);
}
static bool same_record(YDDisk *a,const YDDiskView *av,uint64_t ao,YDDisk *b,const YDDiskView *bv,
    uint64_t bo,char *error,size_t length) {
    size_t an=0,bn=0;unsigned char *ap=yd_disk_record(a,av,ao,&an,error,length);
    unsigned char *bp=ap?yd_disk_record(b,bv,bo,&bn,error,length):NULL;
    bool valid=ap && bp && an==bn && !memcmp(ap,bp,an);
    free(ap);free(bp);return valid;
}
static bool same_frame(YDDisk *a,const YDDiskView *av,uint64_t ao,YDDisk *b,const YDDiskView *bv,
    uint64_t bo,char *error,size_t length) {
    size_t an=0,bn=0;unsigned char *ap=yd_disk_record(a,av,ao,&an,error,length);
    unsigned char *bp=ap?yd_disk_record(b,bv,bo,&bn,error,length):NULL;
    bool valid=ap && bp && an==bn && an>=56 && !memcmp(ap,bp,56);
    size_t at=56;unsigned count=valid?yd_disk_u16(ap+42):0;
    for (unsigned i=0;valid && i<count;i++) {
        valid=an-at>=20;
        size_t size=valid?yd_disk_u16(ap+at):0;
        valid=valid && size && size<=an-at-20 && !memcmp(ap+at,bp+at,4) && !memcmp(ap+at+12,bp+at+12,8+size);
        if (!valid) break;
        uint64_t ar=yd_disk_u64(ap+at+4),br=yd_disk_u64(bp+at+4);
        valid=!ap[at+2] && ap[at+20]=='D'?same_record(a,av,ar,b,bv,br,error,length):ar==br;
        at+=20+size;
    }
    free(ap);free(bp);return valid && at==an;
}
bool yd_disk_history_root_same_checked(YDDisk *a,const YDDiskView *av,YDDisk *b,const YDDiskView *bv,
    YDDiskValidation *state,char *error,size_t length) {
    if (!yd_disk_validation_step(state,YD_VALIDATE_HISTORY)) return false;
    if (av->format!=bv->format || av->capabilities!=bv->capabilities || av->generation!=bv->generation ||
        av->documents!=bv->documents || av->collections!=bv->collections || av->bytes!=bv->bytes || av->revision!=bv->revision) return false;
    YDDiskCursor *ac=yd_disk_cursor(a,av,NULL,0,false,error,length),*bc=yd_disk_cursor(b,bv,NULL,0,false,error,length);
    unsigned char ak[YD_DISK_KEY_LIMIT],bk[YD_DISK_KEY_LIMIT];size_t an=0,bn=0;uint64_t ao=0,bo=0;
    bool valid=ac && bc;
    while (valid) {
        if (!yd_disk_validation_step(state,YD_VALIDATE_HISTORY)) {valid=false;break;}
        int ax=yd_disk_next(ac,ak,sizeof(ak),&an,&ao,error,length),bx=yd_disk_next(bc,bk,sizeof(bk),&bn,&bo,error,length);
        if (ax!=1 || bx!=1) {valid=ax==0 && bx==0;break;}
        valid=an==bn && !memcmp(ak,bk,an);
        if (!valid) break;
        if (ak[0]=='C') valid=ao==bo;
        else if (ak[0]=='I' || ak[0]=='U') { /* Full native validators establish postings. */ }
        else if (an==12 && !memcmp(ak,"\0YLF",4)) valid=same_frame(a,av,ao,b,bv,bo,error,length);
        else if (ak[0]=='D' || yd_disk_relocation_record_key(ak,an)) valid=same_record(a,av,ao,b,bv,bo,error,length);
        else valid=false;
    }
    yd_disk_cursor_free(ac);yd_disk_cursor_free(bc);return valid;
}
bool yd_disk_history_root_same(YDDisk *a,const YDDiskView *av,YDDisk *b,const YDDiskView *bv,
    char *error,size_t length) {
    return yd_disk_history_root_same_checked(a,av,b,bv,NULL,error,length);
}
