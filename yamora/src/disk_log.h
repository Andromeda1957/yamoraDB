#ifndef YAMORA_DISK_LOG_H
#define YAMORA_DISK_LOG_H
#include "disk.h"

#define YD_LOG_TOKEN_SIZE 53U
#define YD_LOG_HEADER_SIZE 56U
typedef struct {
    unsigned char identity[16];
    uint64_t floor, last, count, bytes;
} YDDiskLog;
/* 1 available, 0 predates log activation, -1 corrupt/unreadable. */
int yd_disk_log_load(YDDisk *disk, const YDDiskView *view, YDDiskLog *log, char *error,
                     size_t length);
void yd_disk_log_token(const YDDiskLog *log, uint64_t sequence, char token[YD_LOG_TOKEN_SIZE]);
/* 1 valid, 0 malformed, -1 foreign, -2 expired, -3 future. */
int yd_disk_log_resume(const YDDiskLog *log, const char *token, uint64_t *sequence);
size_t yd_disk_log_key(unsigned char key[12], uint64_t sequence);
#endif
