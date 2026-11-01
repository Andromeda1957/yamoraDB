#ifndef YAMORA_DISK_CHANGES_H
#define YAMORA_DISK_CHANGES_H
#include "disk_api.h"
#include "disk_validation.h"
YDDiskReply yd_disk_changes_request(YDDisk *disk, const YDDiskView *view, const char *target);
bool yd_disk_changes_validate(YDDisk *disk, const YDDiskView *view, char *error, size_t length);
bool yd_disk_changes_validate_cancellable(YDDisk *disk, const YDDiskView *view,
                                            YDDiskValidation *state, char *error, size_t length);
#endif
