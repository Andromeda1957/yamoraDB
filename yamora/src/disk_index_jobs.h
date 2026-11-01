#ifndef YAMORA_DISK_INDEX_JOBS_H
#define YAMORA_DISK_INDEX_JOBS_H
#include "disk_api.h"
struct YDDiskIndexJobs;
struct YDDiskIndexJobs *yd_disk_index_jobs_new(YDDisk *disk);
void yd_disk_index_jobs_free(struct YDDiskIndexJobs *jobs);
YDDiskReply yd_disk_index_jobs_request(struct YDDiskIndexJobs *jobs, bool replica,
                                       const char *method, const char *target,
                                       const unsigned char *body, size_t length,
                                       const char *match, const char *none);
/* Same transfer/lifetime contract as yd_disk_api_request_with_job. */
YDDiskReply yd_disk_index_jobs_request_with_job(struct YDDiskIndexJobs *jobs, bool replica,
                                       const char *method, const char *target,
                                       const unsigned char *body, size_t length,
                                       const char *match, const char *none,
                                       YDDiskJobTerminal terminal, void *context,
                                       bool *transferred);
#endif
