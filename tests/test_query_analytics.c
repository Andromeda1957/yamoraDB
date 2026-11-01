#define _POSIX_C_SOURCE 200809L
#include "../src/aggregate.h"
#include "../src/query_expression.h"
#include "../src/disk_aggregate.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#define CHECK(x) do {if(!(x)){fprintf(stderr,"line %u: %s: %s\n",__LINE__,#x,error);return 2;}}while(0)
static char error[512];
static YDValue *parse(const char *s) {return yd_parse_request((const unsigned char*)s,strlen(s),error,sizeof(error));}
static int expressions(void) {
    const char *cases[][2]={
        {"{$type: '$absent'}","\"missing\""},{"{$type: '$nil'}","\"null\""},
        {"{$eq: ['$nil','$absent']}","false"},{"{$eq: ['$absent','$other']}","true"},
        {"{$eq: [1,1.0]}","true"},{"{$eq: [false,0]}","false"},
        {"{$add: [2,{$multiply: [3,4]}]}","14"},
        {"{$subtract: [10,4]}","6"},{"{$divide: [9,2]}","4.5"},{"{$mod: [9,2]}","1"},
        {"{$add: ['$nil',2]}","null"},{"{$add: ['$absent',2]}","null"},
        {"{$cond: [true,7,{$divide: [1,0]}]}","7"},
        {"{$ifNull: ['$absent',8]}","8"}, {"{$ifNull: [false,8]}","false"},
        {"{$ifNull: [4,{$divide: [1,0]}]}","4"},
        {"{$lt: ['$absent','$nil']}","true"},
        {"{$type: false}","\"bool\""},{"{$type: 1}","\"int\""},
        {"{$type: 1.5}","\"float\""},{"{$type: 'text'}","\"string\""},
        {"{$type: '$list'}","\"array\""},{"{$type: {$literal: {x: 1}}}","\"map\""},
        {"{$concat: ['a','b','c']}","\"abc\""},{"{$size: '$list'}","3"},
        {"{$arrayElemAt: ['$list',-1]}","3"},{"{$arrayElemAt: ['$list',9]}",NULL},
        {"{$and: [true,{$not: false}]}","true"}, {"{$or: [false,true]}","true"},
        {"{$literal: '$literal'}","\"$literal\""}, {"['$absent','$nil',1]","[null,null,1]"},
        {"{$add: [9007199254740993,2]}","9007199254740995"},
        {"{$gt: ['b','a']}","true"},{"{$gte: [2,2]}","true"},
        {"{$lt: [1,2]}","true"},{"{$lte: [2,2]}","true"},{"{$ne: [true,1]}","true"}
    };
    YDValue *doc=parse("{nil: null,list: [1,2,3]}");CHECK(doc);
    for(size_t i=0;i<sizeof(cases)/sizeof(*cases);i++) {
        YDValue *expr=parse(cases[i][0]),*result=NULL;size_t remaining=100000;
        CHECK(expr && yd_expression_evaluate(expr,doc,&result,&remaining,65536,error,sizeof(error)));
        CHECK(remaining<100000);
        if(cases[i][1]) {size_t n;char *json=yd_json(result,&n);CHECK(json && !strcmp(json,cases[i][1]));free(json);}
        else CHECK(!result);
        yd_free(expr);yd_free(result);
    }
    const char *bad[]={"{$unknown: []}","{$cond: [true,1]}","{$add: []}","'$$ROOT'","{$divide: [1,0]}","{$add: [true,1]}","{$size: 1}","{$not: 1}","{$concat: [1,'x']}"};
    for(size_t i=0;i<sizeof(bad)/sizeof(*bad);i++) {
        YDValue *expr=parse(bad[i]),*result=NULL;size_t remaining=100000;
        CHECK(expr && !yd_expression_evaluate(expr,doc,&result,&remaining,65536,error,sizeof(error)));
        CHECK(!result);yd_free(expr);
    }
    YDValue *expr=parse("{$literal: [1,2,3]}");YDValue *result=NULL;size_t remaining=0;
    CHECK(!yd_expression_evaluate(expr,doc,&result,&remaining,65536,error,sizeof(error)));
    remaining=100;CHECK(!yd_expression_evaluate(expr,doc,&result,&remaining,1,error,sizeof(error)));
    yd_free(expr);yd_free(doc);return 0;
}
static bool feed_text(YDAggregate *a,const char *text) {
    YDValue *d=parse(text);bool ok=d && yd_aggregate_feed(a,d,error,sizeof(error));yd_free(d);return ok;
}
static bool foreign_text(YDAggregate *a,size_t at,const char *text) {
    YDValue *d=parse(text);bool ok=d && yd_aggregate_foreign_feed_at(a,at,d,error,sizeof(error));yd_free(d);return ok;
}
static int pipeline(void) {
    YDValue *spec=parse("[{$lookup: {from: cities,localField: city,foreignField: id,as: cities}},"
        "{$set: {country: '$cities.0.country'}},"
        "{$lookup: {from: countries,localField: country,foreignField: code,as: countries}},"
        "{$unwind: '$cities'},"
        "{$group: {_id: '$countries.0.name',total: {$sum: {$multiply: ['$price','$cities.rate']}}}},"
        "{$set: {double: {$multiply: ['$total',2]}}},{$sort: {_id: 1}}]");
    YDAggregate *a=yd_aggregate_new(spec,error,sizeof(error));CHECK(a);
    CHECK(!strcmp(yd_aggregate_lookup_collection_at(a,0),"cities"));
    CHECK(!strcmp(yd_aggregate_lookup_collection_at(a,1),"countries"));
    CHECK(!yd_aggregate_lookup_collection_at(a,2));
    CHECK(foreign_text(a,0,"{id: 1,country: US,rate: 2}"));
    CHECK(foreign_text(a,0,"{id: 2,country: CA,rate: 3}"));
    CHECK(yd_aggregate_foreign_end_at(a,0,error,sizeof(error)));
    CHECK(foreign_text(a,1,"{code: US,name: USA}"));CHECK(foreign_text(a,1,"{code: CA,name: Canada}"));
    CHECK(yd_aggregate_foreign_end_at(a,1,error,sizeof(error)));
    CHECK(feed_text(a,"{city: 1,price: 10}"));CHECK(feed_text(a,"{city: 2,price: 5}"));
    CHECK(feed_text(a,"{city: 1,price: 7}"));CHECK(feed_text(a,"{city: null,price: 99}"));
    size_t n;char *json=yd_aggregate_json(a,&n,error,sizeof(error));
    CHECK(json && !strcmp(json,"[{\"_id\":\"Canada\",\"total\":15,\"double\":30},{\"_id\":\"USA\",\"total\":34,\"double\":68}]"));
    free(json);char *plan=yd_aggregate_explain_json(a,error,sizeof(error));CHECK(plan && strstr(plan,"hash-equality") && strstr(plan,"hash-reduce"));
    free(plan);yd_aggregate_free(a);yd_free(spec);
    spec=parse("[{$group: {_id: '$key',total: {$sum: '$n'}}},{$group: {_id: null,total: {$sum: '$total'}}}]");
    a=yd_aggregate_new(spec,error,sizeof(error));CHECK(a);
    CHECK(feed_text(a,"{key: a,n: 5}"));CHECK(feed_text(a,"{key: b,n: 7}"));
    json=yd_aggregate_json(a,&n,error,sizeof(error));CHECK(json && !strcmp(json,"[{\"_id\":null,\"total\":12}]"));
    free(json);yd_aggregate_free(a);yd_free(spec);
    /* Assignments share the original row; missing preserves, null replaces,
     * unwind drops absent/null/empty values and retains array order for ties. */
    spec=parse("[{$set: {old: '$absent',new: '$absent',a: 9,b: '$a',reset: '$nil'}},"
        "{$unwind: '$items'},{$sort: {b: 1}},{$project: [old,new,a,b,reset,items]}]");
    CHECK(spec);
    for(size_t repeat=0;repeat<3;repeat++) {
        a=yd_aggregate_new(spec,error,sizeof(error));CHECK(a);
        CHECK(feed_text(a,"{old: 7,a: 1,reset: 5,nil: null,items: [2,1]}"));
        CHECK(feed_text(a,"{old: 8,a: 2,nil: null,items: []}"));
        CHECK(feed_text(a,"{old: 9,a: 3,nil: null,items: null}"));
        CHECK(feed_text(a,"{old: 10,a: 4,nil: null}"));
        json=yd_aggregate_json(a,&n,error,sizeof(error));
        CHECK(json && !strcmp(json,"[{\"old\":7,\"a\":9,\"b\":1,\"reset\":null,\"items\":2},{\"old\":7,\"a\":9,\"b\":1,\"reset\":null,\"items\":1}]"));
        free(json);yd_aggregate_free(a);
    }
    yd_free(spec);
    spec=parse("[{$unwind: '$items'}]");a=yd_aggregate_new(spec,error,sizeof(error));CHECK(a);
    CHECK(!feed_text(a,"{items: 3}"));n=42;
    CHECK(!yd_aggregate_json(a,&n,error,sizeof(error)) && n==0);
    yd_aggregate_free(a);yd_free(spec);
    const char *invalid[]={"[{$set: {x: {$unknown: []}}}]","[{$set: {x: '$$ROOT'}}]","[{$unwind: '$a.b'}]","[{$set: {}},{$project: ['x']},{$count: n}]","[{$facet: {x: [{$lookup: {from: x,localField: a,foreignField: a,as: x}}]}}]"};
    for(size_t i=0;i<sizeof(invalid)/sizeof(*invalid);i++){spec=parse(invalid[i]);CHECK(spec && !yd_aggregate_new(spec,error,sizeof(error)));yd_free(spec);}
    return 0;
}
static bool stop(void *context) {size_t *calls=context;(*calls)++;return *calls>=3;}
static bool signaled(void *context) {return *(bool *)context;}
static int filter_budget(unsigned position) {
    char word[4097],pipeline[16384],document[8192];
    memset(word,'q',sizeof(word)-1);word[sizeof(word)-1]=0;
    const char *formats[]={
        "[{$match: {name: '%s'}},{$set: {}}]",
        "[{$set: {}},{$match: {name: '%s'}}]",
        "[{$set: {}},{$group: {_id: '$name'}},{$match: {_id: '%s'}}]",
        "[{$match: {name: '%s'}},{$group: {_id: {$literal: 1}}}]",
        "[{$match: {name: '%s'}},{$group: {_id: null,n: {$sum: {$literal: 1}}}}]"
    };
    CHECK(position<5);snprintf(pipeline,sizeof(pipeline),formats[position],word);
    if(position>=3)word[sizeof(word)-2]='r';
    snprintf(document,sizeof(document),"{name: '%s'}",word);
    YDValue *spec=parse(pipeline);YDAggregate *a=yd_aggregate_new(spec,error,sizeof(error));CHECK(a);
    if(position<3){YDQueryControl control={.work_limit=4096};yd_aggregate_control(a,&control);}
    bool fed=true;
    for(size_t i=0;i<(position<3?1:5000);i++)if(!(fed=feed_text(a,document)))break;
    if(!fed)CHECK(strstr(error,"work"));
    size_t n=42;char *json=yd_aggregate_json(a,&n,error,sizeof(error));
    CHECK(!json && n==0);if(fed)CHECK(strstr(error,"work"));
    yd_aggregate_free(a);yd_free(spec);return 0;
}
static int cancellation(void) {
    YDValue *spec=parse("[{$set: {x: {$add: ['$n',1]}}},{$sort: {x: 1}}]");
    YDAggregate *a=yd_aggregate_new(spec,error,sizeof(error));size_t calls=0;
    YDQueryControl control={.cancelled=stop,.context=&calls};yd_aggregate_control(a,&control);
    CHECK(a && !feed_text(a,"{n: 2}"));CHECK(strstr(error,"cancelled"));
    size_t n=99;CHECK(!yd_aggregate_json(a,&n,error,sizeof(error)) && n==0);
    yd_aggregate_free(a);a=yd_aggregate_new(spec,error,sizeof(error));control=(YDQueryControl){.work_limit=1};yd_aggregate_control(a,&control);
    CHECK(!feed_text(a,"{n: 2}"));CHECK(strstr(error,"work limit"));yd_aggregate_free(a);
    a=yd_aggregate_new(spec,error,sizeof(error));CHECK(a);bool cancelled=false;
    control=(YDQueryControl){.cancelled=signaled,.context=&cancelled};yd_aggregate_control(a,&control);
    CHECK(feed_text(a,"{n: 2}"));CHECK(feed_text(a,"{n: 1}"));cancelled=true;n=42;
    CHECK(!yd_aggregate_json(a,&n,error,sizeof(error)) && n==0);CHECK(strstr(error,"cancelled"));
    yd_aggregate_free(a);yd_free(spec);return 0;
}
static bool write_value(YDDisk *disk,const char *collection,const char *text) {
    YDWrite w={.collection=collection,.document="one",.body=(const unsigned char*)text,.length=strlen(text)};
    YDDiskTxn *t=yd_disk_begin(disk,error,sizeof(error));if(!t)return false;
    if(!yd_disk_apply(t,&w,1,error,sizeof(error))){yd_disk_abort(t);return false;}
    return yd_disk_commit(t,error,sizeof(error));
}
static int disk_view(const char *root) {
    YDDisk *disk=yd_disk_open(root,true,65536,error,sizeof(error));CHECK(disk);
    CHECK(write_value(disk,"local","# preserve\r\nkey: 1\r\n"));
    CHECK(write_value(disk,"foreign","key: 1\n"));CHECK(write_value(disk,"third","key: 1\n"));
    YDDisk *pin=yd_disk_pin(disk,65536,error,sizeof(error));CHECK(pin);YDDiskView view=yd_disk_view(pin);
    YDValue *spec=parse("{explain: true,pipeline: [{$lookup: {from: foreign,localField: key,foreignField: key,as: first}},{$lookup: {from: third,localField: key,foreignField: key,as: second}}]}");
    CHECK(spec);size_t n;
    char *before=yd_disk_aggregate_controlled(pin,&view,"local",spec,NULL,&n,error,sizeof(error));
    CHECK(before && strstr(before,"\"first\":[{\"key\":1}]") && strstr(before,"\"second\":[{\"key\":1}]"));
    CHECK(strstr(before,"\"foreign_documents_examined\":2") && strstr(before,"\"read_view\":\"caller-pinned\""));
    CHECK(write_value(disk,"third","key: 2\n"));
    char *current_handle=yd_disk_aggregate(disk,&view,"local",spec,&n,error,sizeof(error));
    CHECK(current_handle && !strcmp(before,current_handle));free(current_handle);yd_disk_close(disk);
    char *after=yd_disk_aggregate(pin,&view,"local",spec,&n,error,sizeof(error));CHECK(after && !strcmp(before,after));
    free(after);free(before);
    YDQueryControl control={.work_limit=1};n=42;
    CHECK(!yd_disk_aggregate_controlled(pin,&view,"local",spec,&control,&n,error,sizeof(error)) && n==0);
    CHECK(strstr(error,"work limit"));bool cancelled=true;
    control=(YDQueryControl){.cancelled=signaled,.context=&cancelled};n=42;
    CHECK(!yd_disk_aggregate_controlled(pin,&view,"local",spec,&control,&n,error,sizeof(error)) && n==0);
    CHECK(strstr(error,"cancelled"));yd_free(spec);yd_disk_close(pin);return 0;
}
static int performance(void) {
    YDValue *spec=parse("[{$set: {net: {$multiply: ['$price',2]}}},{$group: {_id: '$category',total: {$sum: '$net'}}},{$sort: {_id: 1}}]");
    YDAggregate *a=yd_aggregate_new(spec,error,sizeof(error));CHECK(a);
    struct timespec begin,end;clock_gettime(CLOCK_MONOTONIC,&begin);
    for(size_t i=0;i<1000;i++)CHECK(feed_text(a,i%2?"{price: 3,category: a}":"{price: 5,category: b}"));
    size_t n;char *json=yd_aggregate_json(a,&n,error,sizeof(error));CHECK(json && !strcmp(json,"[{\"_id\":\"a\",\"total\":3000},{\"_id\":\"b\",\"total\":5000}]"));
    clock_gettime(CLOCK_MONOTONIC,&end);
    printf("{\"documents\":1000,\"state_bytes\":%zu,\"work_units\":%zu,\"seconds\":%.6f}\n",yd_aggregate_memory(a),yd_aggregate_work(a),(end.tv_sec-begin.tv_sec)+(end.tv_nsec-begin.tv_nsec)/1e9);
    CHECK(yd_aggregate_memory(a)<4*1024*1024 && yd_aggregate_work(a)<16*1024*1024);
    free(json);yd_aggregate_free(a);yd_free(spec);return 0;
}
int main(int argc,char **argv) {
    if(argc<2)return 2;
    if(!strcmp(argv[1],"expressions"))return expressions();
    if(!strcmp(argv[1],"pipeline"))return pipeline();
    if(!strcmp(argv[1],"cancel"))return cancellation();
    if(!strncmp(argv[1],"filter-budget-",14))return filter_budget((unsigned)atoi(argv[1]+14));
    if(!strcmp(argv[1],"disk") && argc==3)return disk_view(argv[2]);
    if(!strcmp(argv[1],"performance"))return performance();
    return 2;
}
