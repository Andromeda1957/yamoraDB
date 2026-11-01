#ifndef YAMORA_DISK_VECTOR_H
#define YAMORA_DISK_VECTOR_H
#include "disk_api.h"

#define YD_VECTOR_REQUEST_LIMIT (1024U * 1024U)
#define YD_VECTOR_K_MAX 1000U
#define YD_VECTOR_CANDIDATES_MAX 10000U

/* POST /v1/vector-search/<collection> at one immutable view. The whole
 * request is validated (shape, bounds, filter, index, vector) before any
 * posting or document is read. Exact search scores every indexed document;
 * approximate search probes LSH buckets in a deterministic order and re-ranks
 * a bounded candidate set exactly. See docs/vector-search.md. */
YDDiskReply yd_disk_vector_request(YDDisk *disk, const YDDiskView *view, const char *method,
                                   const char *collection, const unsigned char *body,
                                   size_t length, const char *match, const char *none);
#endif
