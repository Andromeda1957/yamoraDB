#include "branch.h"
#include "../disk_history.h"
#include <string.h>
YDDiskReply yd_raft_branch_prepare(YDDisk *disk,const YDRaftWrite *write,YDDiskTxn **prepared) {
    return yd_disk_branch_prepare(disk,write->method,write->target,write->body,write->size,write->match,prepared);
}
bool yd_raft_branch_policy_view(YDDisk *disk,const YDDiskView *current,const YDRaftWrite *write,
    YDDiskView *out,char *error,size_t length) {
    *out=*current;
    if (!(current->capabilities&YD_DISK_CAP_HISTORY) || strcmp(write->method,"POST") ||
        strncmp(write->target,"/v1/branches/",13)) return true;
    const char *name=write->target+13,*suffix=strchr(name,'/');
    size_t n=suffix?(size_t)(suffix-name):0;
    if (!n || n>128 || strcmp(suffix,"/transactions")) return true;
    char branch[129];memcpy(branch,name,n);branch[n]=0;
    if (!yamldb_valid_name(branch)) return true;
    YDValue *spec=yd_parse_sized(write->body,write->size,YD_DISK_REQUEST_LIMIT(current->format),error,length);
    const YDValue *head=yd_get(spec,"head");
    if (!head || head->type!=YD_STRING) {yd_free(spec);return true;}
    YDHistory history;int loaded=yd_disk_history_load(disk,current,&history,error,length);
    if (loaded<0) {yd_free(spec);return false;}
    YDHistoryBranch *b=loaded?yd_disk_history_branch(&history,branch):NULL;
    if (b) {
        char expected[YD_HISTORY_TOKEN];yd_disk_history_token(&history,b->head,expected);
        if (!strcmp(head->scalar,expected)) *out=yd_disk_history_commit(&history,b->head)->view;
    }
    yd_free(spec);return true;
}
