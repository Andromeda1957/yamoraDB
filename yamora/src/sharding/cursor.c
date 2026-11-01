#include "runtime.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct YDShardCursor {
    YDShardRouter *router;
    char collection[64];
    YDShardResult result;
    size_t position;
};
static bool cancelled(YDShardRouter *router) {
    return router->cancelled&&router->cancelled(router->cancel_context);
}
YDShardStatus yd_shard_cursor_open(YDShardRouter *router,const char *identity,
    const char *collection,uint64_t epoch,const YDShardQuery *query,YDShardCursor **out) {
    if(!out)return YD_SHARD_INVALID_ARGUMENT;
    *out=NULL;
    if(!query)return YD_SHARD_INVALID_ARGUMENT;
    YDShardCursor *cursor=calloc(1,sizeof(*cursor));
    if(!cursor)return YD_SHARD_RESOURCE_FAILURE;
    YDShardQuery full=*query;full.offset=0;full.limit=query->max_rows;
    YDShardStatus status=yd_shard_gather(router,identity,collection,epoch,&full,&cursor->result);
    if(status!=YD_SHARD_OK){free(cursor);return status;}
    cursor->router=router;strcpy(cursor->collection,collection);
    *out=cursor;return YD_SHARD_OK;
}
YDShardStatus yd_shard_cursor_next(YDShardCursor *cursor,size_t max_rows,
    size_t max_bytes,YDShardResult *out) {
    if(!out)return YD_SHARD_INVALID_ARGUMENT;
    memset(out,0,sizeof(*out));
    if(!cursor||!max_rows||max_rows>YD_SHARD_PAGE_ROWS||!max_bytes||max_bytes>YD_SHARD_PAGE_BYTES)return YD_SHARD_INVALID_ARGUMENT;
    YDShardRouter *router=cursor->router;
    if(!router->authorize||!router->authorize(router->auth_context,cursor->collection,false))return YD_SHARD_FORBIDDEN;
    if(cancelled(router))return YD_SHARD_CANCELLED;
    out->page.rows=calloc(max_rows,sizeof(YDShardRow));
    if(!out->page.rows)return YD_SHARD_RESOURCE_FAILURE;
    size_t position=cursor->position;
    while(position<cursor->result.page.count&&out->page.count<max_rows){
        const YDShardRow *row=&cursor->result.page.rows[position];
        if(row->length>max_bytes-out->page.bytes){
            if(!out->page.count){yd_shard_page_free(&out->page);return YD_SHARD_BUDGET_EXCEEDED;}
            break;
        }
        if(cancelled(router)){yd_shard_page_free(&out->page);return YD_SHARD_CANCELLED;}
        unsigned char *source=malloc(row->length);
        if(!source){yd_shard_page_free(&out->page);return YD_SHARD_RESOURCE_FAILURE;}
        memcpy(source,row->source,row->length);
        out->page.rows[out->page.count]=*row;
        out->page.rows[out->page.count++].source=source;
        out->page.bytes+=row->length;position++;
    }
    out->page.end=position==cursor->result.page.count;
    out->matched=cursor->result.matched;out->visited=cursor->result.visited;
    out->bytes=cursor->result.bytes;out->shards=cursor->result.shards;
    cursor->position=position;return YD_SHARD_OK;
}
void yd_shard_cursor_close(YDShardCursor *cursor) {
    if(cursor){yd_shard_page_free(&cursor->result.page);free(cursor);}
}
char *yd_shard_explain_json(const YDShardQuery *query,const YDShardResult *result,size_t *length) {
    if(length)*length=0;
    if(!query||!result||!length)return NULL;
    char *json=malloc(1024);
    if(!json)return NULL;
    int size=snprintf(json,1024,
        "{\"version\":1,\"consistency\":\"per-shard-immutable\",\"global_snapshot\":false,"
        "\"stages\":[\"native-shard-scan\",\"bounded-materialization\",\"deterministic-merge\",\"global-offset-limit\"],"
        "\"sorted\":%s,\"shards\":%zu,\"visited\":%llu,\"matched\":%llu,\"returned\":%zu,"
        "\"source_bytes\":%llu,\"row_limit\":%zu,\"byte_limit\":%zu,\"offset\":%zu,\"limit\":%zu}",
        query->sort_field?"true":"false",result->shards,(unsigned long long)result->visited,
        (unsigned long long)result->matched,result->page.count,(unsigned long long)result->bytes,
        query->max_rows,query->max_bytes,query->offset,query->limit);
    if(size<0||size>=1024){free(json);return NULL;}
    *length=(size_t)size;return json;
}
