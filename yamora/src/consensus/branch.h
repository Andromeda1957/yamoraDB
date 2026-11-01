#ifndef YAMORA_CONSENSUS_BRANCH_H
#define YAMORA_CONSENSUS_BRANCH_H
#include "application.h"
#include "../disk_branch_api.h"
YDDiskReply yd_raft_branch_prepare(YDDisk *,const YDRaftWrite *,YDDiskTxn **);
bool yd_raft_branch_policy_view(YDDisk *,const YDDiskView *,const YDRaftWrite *,
    YDDiskView *,char *,size_t);
#endif
