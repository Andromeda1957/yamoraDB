#ifndef YAMORA_DISK_SEARCH_H
#define YAMORA_DISK_SEARCH_H
#include "disk_documents.h"
char *yd_disk_search(YDDisk *disk, const YDDiskView *view, const char *collection,
                     const YDValue *spec, size_t *size, char *error, size_t length);
#endif
