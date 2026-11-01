#include "disk_history.h"
#include "disk_bulk.h"

/* Typed document/index/feed/policy validation stays above the structural
 * storage publisher, so scalar native users keep their minimal link closure. */
static const unsigned char key[] = {0,'Y','B','H'};

bool yd_disk_history_validate(YDDisk *disk,const YDDiskView *view,YDDiskValidation *state,char *error,size_t length) {
    YDHistory h; int found=yd_disk_history_load(disk,view,&h,error,length);
    if (found<=0) return found==0 && (!(view->capabilities&YD_DISK_CAP_HISTORY) ||
        (!view->documents && !view->collections && view->generation<=2));
    for (size_t i=0;i<h.count;i++) {
        uint64_t ignored=0; YDDiskView *v=&h.commits[i].view;
        if (!yd_disk_validation_step(state,YD_VALIDATE_APPLICATION) ||
            yd_disk_get(disk,v,key,sizeof(key),&ignored,error,length)!=0 ||
            !yd_disk_validate_cancellable(disk,v,state,error,length)) return false;
    }
    return true;
}
