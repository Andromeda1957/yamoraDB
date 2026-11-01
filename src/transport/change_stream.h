#ifndef YAMORA_TRANSPORT_CHANGE_STREAM_H
#define YAMORA_TRANSPORT_CHANGE_STREAM_H
#include "tls.h"
#include "../disk_changes.h"
#include <signal.h>
typedef struct YDChangeStream YDChangeStream;
/* Returns one owned paged-feed reply, including revision/resume_after. Acquire
 * and release any application/view lifetime within each call. The finite
 * timeout bounds acquisition; callers authorize before opening the stream.
 * Context remains borrowed until the stream is freed. */
typedef YDDiskReply (*YDChangeStreamPage)(void *context, const char *target,
                                         unsigned timeout_ms);
/* Validates the initial token before any streaming headers are sent. Failure
 * owns a normal JSON reply. The caller reserves/relinquishes session capacity. */
YDChangeStream *yd_change_stream_open(YDDisk *disk, const char *target, YDDiskReply *error);
/* Revalidates the source independently on every page. Idle waits retain no
 * disk or application pointer; they poll at the requested heartbeat interval.
 * timeout_ms is 1..30000 and is capped by remaining duration after admission. */
YDChangeStream *yd_change_stream_open_source(YDChangeStreamPage page, void *context,
    unsigned timeout_ms, const char *target, YDDiskReply *error);
typedef enum { YD_CHANGE_PAGE, YD_CHANGE_WAIT, YD_CHANGE_END } YDChangePull;
/* Worker-side page producer, independent of HTTP/TLS. Call again only after the
 * previous complete page was delivered: that advances after to its next_after.
 * PAGE transfers one owned JSON page (without LF), including terminal failures.
 * WAIT returns 1..5000ms and performs no sleep. No disk/application is retained
 * across source callbacks. limit excludes a separate <=4096-byte terminal reserve.
 * Initial oversized pages fail before streaming admission; later failures carry
 * the last complete cursor. A caller owns transport/page/total byte budgets. */
YDChangePull yd_change_stream_pull(YDChangeStream *stream, unsigned remaining_ms,
    size_t limit, YDDiskReply *page, unsigned *wait_ms);
bool yd_change_stream_send(YDChangeStream *stream, YDConnection *connection,
                            const volatile sig_atomic_t *running, size_t *bytes);
void yd_change_stream_free(YDChangeStream *stream);
#endif
