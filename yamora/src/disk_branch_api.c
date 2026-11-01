#define _POSIX_C_SOURCE 200809L
#include "disk_branch_api.h"
#include "disk_branch.h"
#include "disk_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

bool yd_disk_branch_target(const char *target) {
    return !strcmp(target,"/v1/branches") || !strncmp(target,"/v1/branches/",13);
}
int yd_disk_history_target(const char *target,char selector[129],const char **underlying) {
    selector[0]=0; *underlying=NULL;
    if (strncmp(target,"/v1/at/",7)) return 0;
    const char *slash=strchr(target+7,'/');
    size_t n=slash?(size_t)(slash-(target+7)):0;
    if (!n || n>128 || strncmp(slash,"/v1/",4)) return -1;
    memcpy(selector,target+7,n); selector[n]=0; *underlying=slash;
    return 1;
}
static YDDiskReply json(int status,const char *text,const YDDiskView *view) {
    YDDiskReply r={.status=status,.content_type="application/json; charset=utf-8"};
    r.body=strdup(text); r.length=r.body?strlen(text):0;
    if (!r.body) r.status=503;
    yd_disk_revision(view,r.revision); return r;
}
static bool only(const YDValue *v,const char *const *keys,size_t count) {
    if (!v || v->type!=YD_MAP) return false;
    for (size_t i=0;i<v->count;i++) {
        bool found=false;
        for (size_t j=0;j<count;j++) found|=!strcmp(v->keys[i],keys[j]);
        if (!found) return false;
    }
    return true;
}
static const char *text(const YDValue *v) {return v && v->type==YD_STRING?v->scalar:NULL;}
static bool digest_request(const char *method,const char *target,const unsigned char *body,
    size_t length,const char *match,const char *none,unsigned char out[32]) {
    const void *parts[]={method,target,body,match?match:"",none?none:""};
    size_t sizes[]={strlen(method),strlen(target),length,match?strlen(match):0,none?strlen(none):0};
    EVP_MD_CTX *ctx=EVP_MD_CTX_new(); unsigned n=0;
    bool valid=ctx && EVP_DigestInit_ex(ctx,EVP_sha256(),NULL)==1;
    for (unsigned i=0;valid && i<5;i++) {
        unsigned char size[8];yd_disk_set64(size,sizes[i]);
        valid=EVP_DigestUpdate(ctx,size,sizeof(size))==1 &&
            (!sizes[i] || EVP_DigestUpdate(ctx,parts[i],sizes[i])==1);
    }
    valid=valid && EVP_DigestFinal_ex(ctx,out,&n)==1 && n==32;
    EVP_MD_CTX_free(ctx);return valid;
}
static bool receipt_shape(const unsigned char *p,size_t n) {
    if (!p || n<80 || n>4160 || memcmp(p,"YDBRCP01",8) ||
        yd_disk_u64(p+48)!=n-64 || yd_disk_u64(p+40)<200 || yd_disk_u64(p+40)>=300) return false;
    for (unsigned i=56;i<64;i++) if (p[i]) return false;
    for (unsigned i=64;i<80;i++) if (!((p[i]>='0' && p[i]<='9') || (p[i]>='a' && p[i]<='f'))) return false;
    if (memchr(p+80,0,n-80)) return false;
    char error[128]={0};YDValue *reply=yd_parse_request(p+80,n-80,error,sizeof(error));
    bool valid=reply && reply->type==YD_MAP;
    yd_free(reply);return valid;
}
bool yd_disk_branch_receipts_validate(YDDisk *disk,const YDDiskView *view,
    YDDiskValidation *state,char *error,size_t length) {
    YDDiskCursor *cursor=yd_disk_cursor(disk,view,"\0YBR",4,false,error,length);
    unsigned char key[YD_DISK_KEY_LIMIT],bytes[4160];size_t kn=0,n=0;uint64_t offset=0;
    int next=0;bool valid=cursor!=NULL;
    while (valid && (next=yd_disk_next(cursor,key,sizeof(key),&kn,&offset,error,length))==1) {
        if (kn<4 || memcmp(key,"\0YBR",4)) break;
        unsigned nonzero=0;
        if (kn==20) for (unsigned i=4;i<20;i++) nonzero|=key[i];
        valid=(view->capabilities&YD_DISK_CAP_HISTORY) && kn==20 && nonzero &&
            yd_disk_validation_step(state,YD_VALIDATE_OPERATION) &&
            yd_disk_record_into(disk,view,offset,bytes,sizeof(bytes),&n,error,length) && receipt_shape(bytes,n);
    }
    yd_disk_cursor_free(cursor);return valid && next>=0;
}
static int receipt(YDDiskTxn *txn,const unsigned char id[16],const unsigned char digest[32],
    YDDiskReply *reply,char *error,size_t length) {
    unsigned char key[20];memcpy(key,"\0YBR",4);memcpy(key+4,id,16);
    uint64_t offset=0;int found=yd_disk_tx_peek(txn,key,sizeof(key),&offset,error,length);
    if (found!=1) return found;
    YDDiskView view=txn->view;view.end=txn->next;
    size_t n=0;unsigned char *p=yd_disk_record(txn->disk,&view,offset,&n,error,length);
    bool valid=receipt_shape(p,n);
    if (valid && memcmp(p+8,digest,32)) {free(p);return -2;}
    if (valid) {
        *reply=json((int)yd_disk_u64(p+40),(const char *)"",&txn->view);
        free(reply->body);reply->body=malloc(n-64+1);
        valid=reply->body!=NULL;
        if (valid) {memcpy(reply->body,p+64,n-64);reply->body[n-64]=0;reply->length=n-64;
            /* The original reply revision is contained in its own JSON and
             * stored separately as a fixed16-byte prefix of the payload. */
            valid=reply->length>=16;
            if (valid) {memcpy(reply->revision,reply->body,16);reply->revision[16]=0;
                memmove(reply->body,reply->body+16,reply->length-16);reply->length-=16;reply->body[reply->length]=0;}
        }
    }
    free(p);return valid?1:-1;
}
static bool save_receipt(YDDiskTxn *txn,const unsigned char id[16],const unsigned char digest[32],
    const YDDiskReply *reply,char *error,size_t length) {
    if (reply->length>4080) return false;
    size_t n=80+reply->length;unsigned char *p=calloc(1,n),key[20];
    if (!p) return false;
    memcpy(p,"YDBRCP01",8);memcpy(p+8,digest,32);yd_disk_set64(p+40,(uint64_t)reply->status);
    yd_disk_set64(p+48,16+reply->length);memcpy(p+64,reply->revision,16);memcpy(p+80,reply->body,reply->length);
    memcpy(key,"\0YBR",4);memcpy(key+4,id,16);uint64_t offset=0;
    bool valid=yd_disk_append(txn,p,n,&offset,error,length) && yd_disk_put(txn,key,sizeof(key),offset,error,length);
    free(p);return valid;
}
YDDiskReply yd_disk_branch_read(YDDisk *disk,const YDDiskView *view,const char *method,
    const char *target,const unsigned char *body,size_t length,const char *match,const char *none,bool gzip) {
    char error[512]={0},selector[129],token[YD_HISTORY_TOKEN]; const char *underlying=NULL;
    int addressed=yd_disk_history_target(target,selector,&underlying);
    if (addressed<0) return yd_disk_error_reply(400,"invalid_history_target");
    if (addressed) {
        YDDiskView resolved;
        int status=yd_disk_history_resolve(disk,view,selector,&resolved,token,error,sizeof(error));
        if (status!=200) return yd_disk_error_reply(status,"history_unavailable");
        /* Temporal feeds/replication/jobs would export live/session state.
         * Restrict to finite source/catalog/query reads at the captured root. */
        bool allowed=!strncmp(underlying,"/v1/collections",15) ||
            !strncmp(underlying,"/v1/documents/",14) || !strncmp(underlying,"/v1/query/",10) ||
            !strncmp(underlying,"/v1/aggregate/",14) || !strncmp(underlying,"/v1/search/",11) ||
            !strcmp(underlying,"/v1/indexes") || !strcmp(underlying,"/v1/stats");
        if (!allowed) return yd_disk_error_reply(405,"history_operation_unavailable");
        YDDiskReply r=yd_disk_api_read_at(disk,&resolved,method,underlying,body,length,match,none,gzip);
        size_t used=strlen(r.headers);
        snprintf(r.headers+used,sizeof(r.headers)-used,"X-Yamora-Commit: %s\r\n",token);
        return r;
    }
    if (strcmp(method,"GET") || strcmp(target,"/v1/branches")) return yd_disk_error_reply(405,"method_not_allowed");
    if (!(view->capabilities&YD_DISK_CAP_HISTORY)) return yd_disk_error_reply(409,"history_capability_required");
    YDHistory h; int found=yd_disk_history_load(disk,view,&h,error,sizeof(error));
    if (found<=0) return yd_disk_error_reply(found<0?503:404,"history_unavailable");
    char output[16384],oldest[YD_HISTORY_TOKEN],newest[YD_HISTORY_TOKEN];
    yd_disk_history_token(&h,h.commits[0].sequence,oldest); yd_disk_history_token(&h,h.last,newest);
    size_t at=(size_t)snprintf(output,sizeof(output),"{\"retained\":%zu,\"oldest\":\"%s\",\"latest\":\"%s\",\"branches\":[",h.count,oldest,newest);
    for (size_t i=0;i<h.branches;i++) {
        yd_disk_history_token(&h,h.names[i].head,token);
        at+=(size_t)snprintf(output+at,sizeof(output)-at,"%s{\"name\":\"%s\",\"head\":\"%s\"}",i?",":"",h.names[i].name,token);
    }
    snprintf(output+at,sizeof(output)-at,"]}\n"); return json(200,output,view);
}
static YDDiskReply prepare(YDDisk *disk,const char *method,const char *target,
    const unsigned char *body,size_t length,const char *match,const char *none,
    const unsigned char id[16],YDDiskTxn **prepared) {
    *prepared=NULL;
    if (!disk || !method || !target || (length && !body)) return yd_disk_error_reply(400,"invalid_branch_request");
    if (length>YD_DISK_REQUEST_LIMIT(8)) return yd_disk_error_reply(413,"branch_request_too_large");
    if (!(yd_disk_capabilities(disk)&YD_DISK_CAP_HISTORY)) return yd_disk_error_reply(409,"history_capability_required");
    if (strncmp(target,"/v1/branches/",13)) return yd_disk_error_reply(405,"method_not_allowed");
    const char *name=target+13,*suffix=strchr(name,'/');
    size_t n=suffix?(size_t)(suffix-name):strlen(name);
    if (!n || n>128) return yd_disk_error_reply(400,"invalid_branch_name");
    char branch[129]; memcpy(branch,name,n); branch[n]=0;
    if (!yamldb_valid_name(branch) || !strcmp(branch,"main")) return yd_disk_error_reply(400,"invalid_branch_name");
    char error[512]={0},commit[YD_HISTORY_TOKEN]={0};
    YDValue *spec=length?yd_parse_sized(body,length,YD_DISK_REQUEST_LIMIT(8),error,sizeof(error)):NULL;
    YDDiskTxn *txn=yd_disk_begin_exclusive(disk,error,sizeof(error));
    if (!txn) {yd_free(spec); return yd_disk_error_reply(503,"recovery_required");}
    unsigned char digest[32]={0};
    if (id) {
        YDDiskReply stored={0};
        if (!digest_request(method,target,body,length,match,none,digest)) {
            yd_free(spec);yd_disk_abort(txn);return yd_disk_error_reply(503,"receipt_unavailable");
        }
        int found=receipt(txn,id,digest,&stored,error,sizeof(error));
        if (found) {yd_free(spec);yd_disk_abort(txn);
            if (found==1) return stored;
            yd_disk_reply_free(&stored);return yd_disk_error_reply(found==-2?409:503,"request_id_conflict_or_invalid_receipt");}
    }
    int status=405; size_t operations=0; YDPolicyWork work; yd_policy_work_init(&work,false);
    if (!suffix && !strcmp(method,"PUT")) {
        static const char *const keys[]={"from"};
        if (!only(spec,keys,1) || !text(yd_get(spec,"from"))) status=400;
        else status=yd_disk_branch_create(txn,branch,text(yd_get(spec,"from")),error,sizeof(error));
    } else if (!suffix && !strcmp(method,"DELETE")) {
        char token[YD_HISTORY_TOKEN]={0};
        bool quoted=match && strlen(match)==54 && match[0]=='"' && match[53]=='"';
        if (quoted) memcpy(token,match+1,52);
        status=length || !quoted?400:yd_disk_branch_delete(txn,branch,token,error,sizeof(error));
    } else if (suffix && !strcmp(suffix,"/transactions") && !strcmp(method,"POST")) {
        static const char *const keys[]={"head","transaction"};
        if (!only(spec,keys,2) || !text(yd_get(spec,"head"))) status=400;
        else {
            YDHistory h; YDDiskView main;
            status=yd_disk_branch_enter(txn,branch,text(yd_get(spec,"head")),&h,&main,error,sizeof(error));
            if (status==200) {
                YDDiskReply applied=yd_disk_api_apply_transaction(txn,yd_get(spec,"transaction"),&work);
                status=applied.status; yd_disk_reply_free(&applied);
                const YDValue *transaction=yd_get(spec,"transaction"),*ops=yd_get(transaction,"operations");
                if (status==200 && ops) operations=ops->count;
                if (status==200 && !yd_disk_branch_leave(txn,&h,branch,&main,commit,error,sizeof(error))) status=503;
            }
        }
    } else if (suffix && !strcmp(suffix,"/merge") && !strcmp(method,"POST")) {
        static const char *const keys[]={"head","main"};
        if (!only(spec,keys,2) || !text(yd_get(spec,"head")) || !text(yd_get(spec,"main"))) status=400;
        else status=yd_disk_branch_merge(txn,branch,text(yd_get(spec,"head")),text(yd_get(spec,"main")),&work,&operations,error,sizeof(error));
    }
    yd_free(spec);
    if (status<200 || status>=300) {yd_disk_abort(txn); return yd_disk_error_reply(status,"branch_rejected");}
    YDHistory h;
    if (yd_disk_history_tx_load(txn,&h,error,sizeof(error))!=1) {
        yd_disk_abort(txn); return yd_disk_error_reply(503,"history_unavailable");
    }
    if (!commit[0]) {
        YDHistoryBranch *b=yd_disk_history_branch(&h,branch);
        if (suffix && !strcmp(suffix,"/merge")) yd_disk_history_token(&h,h.last+1,commit);
        else if (b) yd_disk_history_token(&h,b->head,commit);
    }
    YDDiskView reply_view=txn->view;
    if (suffix && !strcmp(suffix,"/transactions")) {
        YDHistoryBranch *b=yd_disk_history_branch(&h,branch);
        if (b) reply_view=yd_disk_history_commit(&h,b->head)->view;
    }
    char result[512],revision[17]; yd_disk_revision(&reply_view,revision);
    snprintf(result,sizeof(result),"{\"status\":\"committed\",\"branch\":\"%s\",\"commit\":\"%s\",\"operations\":%zu,\"revision\":\"%s\"}\n",branch,commit,operations,revision);
    YDDiskReply reply=json(status,result,&reply_view);
    if (reply.status>=300 || (id && !save_receipt(txn,id,digest,&reply,error,sizeof(error)))) {
        yd_disk_reply_free(&reply);yd_disk_abort(txn);return yd_disk_error_reply(503,"receipt_unavailable");
    }
    *prepared=txn; return reply;
}
YDDiskReply yd_disk_branch_prepare(YDDisk *disk,const char *method,const char *target,
    const unsigned char *body,size_t length,const char *match,YDDiskTxn **prepared) {
    return prepare(disk,method,target,body,length,match,NULL,NULL,prepared);
}
YDDiskReply yd_disk_branch_prepare_with_id(YDDisk *disk,const char *method,const char *target,
    const unsigned char *body,size_t length,const char *match,const char *none,
    const unsigned char id[16],YDDiskTxn **prepared) {
    *prepared=NULL;unsigned nonzero=0;
    if (id) for (unsigned i=0;i<16;i++) nonzero|=id[i];
    if (!nonzero) return yd_disk_error_reply(400,"request_id_required");
    return prepare(disk,method,target,body,length,match,none,id,prepared);
}
