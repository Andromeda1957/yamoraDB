#ifndef YAMORA_DISK_BRANCH_H
#define YAMORA_DISK_BRANCH_H
#include "disk_history.h"
#include "disk_documents.h"
/* All mutation helpers borrow an EXCLUSIVE unpublished transaction. Caller
 * aborts on any failure. Catalog and affected data publish in one native root. */
int yd_disk_branch_create(YDDiskTxn *,const char *,const char *,char *,size_t);
int yd_disk_branch_delete(YDDiskTxn *,const char *,const char *,char *,size_t);
int yd_disk_branch_enter(YDDiskTxn *,const char *,const char *,YDHistory *,YDDiskView *,char *,size_t);
bool yd_disk_branch_leave(YDDiskTxn *,YDHistory *,const char *,const YDDiskView *,
    char[YD_HISTORY_TOKEN],char *,size_t);
int yd_disk_branch_merge(YDDiskTxn *,const char *,const char *,const char *,
    YDPolicyWork *,size_t *,char *,size_t);
#endif
