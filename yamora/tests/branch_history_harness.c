/* Links the actual native library; no replacement storage/auth/consensus. */
#define _POSIX_C_SOURCE 200809L
#include "disk_api.h"
#include "disk_bulk.h"
#include "disk_history.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
static const char *text(const YDValue *map,const char *key) {
    const YDValue *v=yd_get(map,key);return v && v->type==YD_STRING?v->scalar:NULL;
}
static bool unhex(const char *p,unsigned char id[16]) {
    if (!p || strlen(p)!=32) return false;
    for (unsigned i=0;i<16;i++) {
        unsigned v=0;
        for (unsigned j=0;j<2;j++) {
            unsigned c=(unsigned char)p[2*i+j];
            if (!((c>='0' && c<='9') || (c>='a' && c<='f'))) return false;
            v=16*v+(c<='9'?c-'0':c-'a'+10);
        }
        id[i]=(unsigned char)v;
    }
    return true;
}
static unsigned char *read_file(const char *path,size_t *length) {
    int fd=open(path,O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK);struct stat st;
    if (fd<0) return NULL;
    if (fstat(fd,&st) || !S_ISREG(st.st_mode) || st.st_size<=0 || st.st_size>YD_LARGE_REQUEST_LIMIT) {close(fd);return NULL;}
    size_t n=(size_t)st.st_size,at=0;unsigned char *p=malloc(n+1);
    while (p && at<n) {ssize_t got=read(fd,p+at,n-at);if (got<=0) {free(p);p=NULL;break;}at+=(size_t)got;}
    if (close(fd)) {free(p);return NULL;}
    if (p) {p[n]=0;*length=n;}return p;
}
static void hex(const void *p,size_t n) {const unsigned char *b=p;for (size_t i=0;i<n;i++) printf("%02x",b[i]);}
static void output(YDDisk *disk,const YDDiskReply *r) {
    YDDiskView v=yd_disk_view(disk);
    printf("{\"status\":%d,\"body\":\"",r->status);hex(r->body,r->length);
    printf("\",\"headers\":\"");hex(r->headers,strlen(r->headers));
    printf("\",\"revision\":\"%s\",\"generation\":%llu,\"format\":%u,\"capabilities\":%u}\n",
        r->revision,(unsigned long long)v.generation,v.format,v.capabilities);
}
typedef struct {YDDiskAPI *api;unsigned thread;bool good;} Race;
static void *race(void *context) {
    Race *r=context;r->good=true;
    for (unsigned i=0;i<4;i++) {
        char target[128],body[64];
        snprintf(target,sizeof(target),"/v1/collections/items/documents/race-%u-%u",r->thread,i);
        snprintf(body,sizeof(body),"value: %u\n",r->thread*4+i);
        YDDiskReply reply=yd_disk_api_request(r->api,"PUT",target,(const unsigned char *)body,strlen(body),NULL,NULL,false);
        r->good=r->good && (reply.status==200 || reply.status==201);yd_disk_reply_free(&reply);
    }
    return NULL;
}
int main(int argc,char **argv) {
    if (argc!=4) return 2;
    char error[512]={0};
    if (!strcmp(argv[1],"legacy")) {
        YDDisk *legacy=yd_disk_open(argv[2],false,32768,error,sizeof(error));
        if (legacy) {yd_disk_close(legacy);fputs("ASSERT: legacy constructor opened profile8\n",stderr);return 2;}
        puts("{\"rejected\":true}");return 0;
    }
    char *end=NULL;errno=0;unsigned long caps=strtoul(argv[1],&end,10);
    if (errno || !end || *end || caps>UINT32_MAX) return 2;
    int cancellation=0;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,&cancellation)) return 2;
    YDDisk *disk=yd_disk_open_capabilities(argv[2],true,(uint32_t)caps,32768,error,sizeof(error));
    if (!disk) {fprintf(stderr,"ASSERT: native open: %s\n",error);return 2;}
    YDDiskAPI api;
    if (!yd_disk_api_init(&api,disk,false)) {yd_disk_close(disk);return 2;}
    size_t length=0;unsigned char *source=read_file(argv[3],&length);
    YDValue *commands=source?yd_parse_request(source,length,error,sizeof(error)):NULL;
    free(source);
    YDDisk *pin=NULL;int code=0;
    if (!commands || commands->type!=YD_ARRAY) code=2;
    for (size_t i=0;!code && i<commands->count;i++) {
        const YDValue *c=commands->items[i];const char *method=text(c,"method"),*target=text(c,"target");
        const char *body=text(c,"body"),*match=text(c,"if_match"),*none=text(c,"if_none_match"),*wrapper=text(c,"wrapper");
        YDDiskReply r={0};
        if (method && !strcmp(method,"RACE")) {
            pthread_t threads[4];Race races[4];size_t started=0;r.status=200;
            for (unsigned t=0;t<4;t++) {
                races[t]=(Race){.api=&api,.thread=t};
                if (pthread_create(&threads[t],NULL,race,&races[t])) {r.status=503;break;}
                started++;
            }
            for (size_t t=0;t<started;t++) if (pthread_join(threads[t],NULL) || !races[t].good) r.status=503;
        } else if (method && !strcmp(method,"CHECKPOINT")) {
            YDDiskCheckpoint *checkpoint=yd_disk_checkpoint_open(disk,error,sizeof(error));
            unsigned char header[YD_DISK_PAGE];YDDiskView decoded={0};
            YDDiskView saved=yd_disk_checkpoint_view(checkpoint);
            r.status=checkpoint && yd_disk_checkpoint_read(checkpoint,0,header,sizeof(header),error,sizeof(error)) &&
                yd_disk_decode_header(header,saved.end,&decoded) && decoded.capabilities==(uint32_t)caps &&
                decoded.generation==saved.generation && decoded.root==saved.root?200:500;
            yd_disk_checkpoint_close(checkpoint);
        } else if (method && !strcmp(method,"PIN")) {
            yd_disk_close(pin);pin=yd_disk_pin(disk,32768,error,sizeof(error));r.status=pin?204:503;
        } else if (method && !strcmp(method,"COMPACT")) {
            r.status=target && yd_disk_compact(disk,target,32768,error,sizeof(error))?200:500;
        } else if (method && !strcmp(method,"VALIDATE")) {
            YDDiskView v=yd_disk_view(disk);
            r.status=yd_disk_validate(disk,&v,error,sizeof(error)) && yd_disk_history_validate(disk,&v,NULL,error,sizeof(error))?200:500;
        } else if (!method || !target) {code=2;break;}
        else if (wrapper && !strcmp(wrapper,"pin")) {
            YDDiskView v=yd_disk_view(pin);
            r=yd_disk_api_read_at(pin,&v,method,target,(const unsigned char *)body,body?strlen(body):0,match,none,false);
        } else {
            unsigned char id[16]={0};const char *request_id=text(c,"request_id");
            if (request_id && !unhex(request_id,id)) {code=2;break;}
            r=yd_disk_api_request_with_id(&api,method,target,(const unsigned char *)body,body?strlen(body):0,
                match,none,false,request_id?id:NULL);
        }
        if (r.status>=500 && error[0] && !r.body) {r.body=strdup(error);r.length=r.body?strlen(r.body):0;}
        output(disk,&r);yd_disk_reply_free(&r);
    }
    if (code) fprintf(stderr,"ASSERT: fixture command rejected: %s\n",error);
    yd_free(commands);yd_disk_close(pin);yd_disk_api_destroy(&api);yd_disk_close(disk);
    if (pthread_setcancelstate(cancellation,NULL)) return 2;
    return code;
}
