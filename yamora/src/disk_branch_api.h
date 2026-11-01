#ifndef YAMORA_DISK_BRANCH_API_H
#define YAMORA_DISK_BRANCH_API_H
#include "disk_api.h"
#include "disk_validation.h"
bool yd_disk_branch_target(const char *);
/* Pure route unwrap for authentication BEFORE any storage access. Selector
 * is bounded; underlying route is borrowed and begins /v1/. 1 valid,0other,-1bad. */
int yd_disk_history_target(const char *,char selector[129],const char **underlying);
YDDiskReply yd_disk_branch_read(YDDisk *,const YDDiskView *,const char *,const char *,
    const unsigned char *,size_t,const char *,const char *,bool);
YDDiskReply yd_disk_branch_prepare(YDDisk *,const char *,const char *,const unsigned char *,
    size_t,const char *,YDDiskTxn **);
YDDiskReply yd_disk_branch_prepare_with_id(YDDisk *,const char *,const char *,const unsigned char *,
    size_t,const char *,const char *,const unsigned char[16],YDDiskTxn **);
bool yd_disk_branch_receipts_validate(YDDisk *,const YDDiskView *,YDDiskValidation *,char *,size_t);
#endif
