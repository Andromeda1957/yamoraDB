#ifndef YAMORA_TRANSPORT_BINARY_SESSION_H
#define YAMORA_TRANSPORT_BINARY_SESSION_H
#include "binary_message.h"
#include "tls.h"
#include <netinet/in.h>

typedef struct YDBinaryRuntime YDBinaryRuntime;
typedef struct {
    unsigned char *body; /* Transferred malloc-compatible chunk; feed pages include LF. */
    size_t length;
    unsigned wait_ms; /* With no body/end: reschedule after 1..5000ms, no worker sleep. */
    bool end; /* With no body/wait: successful terminal END. */
} YDBinaryChunk;
typedef struct {
    void *context;
    /* Worker only, after the previous complete page was delivered. One finite
     * pull, capped by the remaining absolute request budget. No TLS/session use. */
    YDBinaryChunk (*next)(void *context, unsigned remaining_ms);
    /* Optional exact-once terminal callback, on a dispatch worker with
     * cancellation disabled and outside transport locks. It runs after END
     * delivery, or after cancel/disconnect/deadline/shutdown retirement.
     * complete is true only after normal END left TLS; it is not native
     * outcome evidence. Terminal callbacks bypass ordinary request expiry.
     * No next call overlaps or follows finish. False marks runtime unhealthy.
     * Context remains owned until close, including failed acknowledgement. */
    bool (*finish)(void *context, bool complete);
    /* Exact-once finite deallocation only; no backend I/O, waits or audit IPC. */
    void (*close)(void *context);
} YDBinaryProducer;
/* Single transferred owner. body is malloc/free compatible, NULL for zero
 * message.body_length; the allocation covers that length. No implicit string
 * terminator. GET/HEAD allocations may include one additional byte. Acks and
 * error bodies are <=4096 bytes; GET/HEAD representations are <=16 MiB.
 * The module validates metadata, lengths and HEAD correlation before sending,
 * and frees the body on every completion/discard path, including cancellation. */
typedef struct {
    YDBinaryResponseMessage message;
    unsigned char *body;
    /* Producer's first chunk. Feed pages include LF; finite GET producers retain
     * ordinary declared body/representation lengths and need no new wire mode.
     * Only one chunk is owned at a time. Lifetime includes detached pulls. */
    size_t page_length;
    YDBinaryProducer producer;
} YDBinaryReply;
typedef struct {
    struct in_addr address;
    uint16_t port; /* 0 requests an OS-assigned port. */
    unsigned io_timeout_ms; /* 1..30000; explicit phase budgets. */
    size_t max_body; /* 0 defaults to 16 MiB; otherwise 1..16 MiB. */
    YDTLS *tls; /* Dedicated binary profile; borrowed until close returns. */
    void *context; /* Borrowed until close returns. Callbacks must be thread-safe. */
    /* I/O thread, before request body allocation/reservation; no backend I/O.
     * rejection starts zeroed. True leaves it empty; false transfers a valid
     * typed rejection (400..599, body <=4096). Parent checks auth/disk profile.
     * Valid rejection drains the declared body and responds after exact END. */
    bool (*admit)(void *context, const YDBinaryRequestMessage *request,
                  YDBinaryReply *rejection);
    /* Two workers may invoke execute concurrently; each invocation borrows
     * immutable owned request/body only for its call lifetime. remaining_ms is
     * the remaining absolute request budget at dispatch, never a fresh budget;
     * parent caps it further to its configured backend/cluster timeout.
     * Queued cancellation prevents dispatch. Running cancellation detaches:
     * it cannot interrupt/roll back execute and cannot prove write outcome.
     * The returned reply transfers sole ownership even for detached work. */
    YDBinaryReply (*execute)(void *context, const YDBinaryRequestMessage *request,
                             const unsigned char *body, size_t length,
                             unsigned remaining_ms);
    /* Optional worker-only terminal hook for a valid admission rejection after
     * exact body drain. Consumes the owned rejection on every return path.
     * Enables bounded durable audit without I/O-thread filesystem/IPC waits.
     * No request body was allocated; this callback must never dispatch data.
     * Disconnected/expired queued work is discarded before callback entry. */
    YDBinaryReply (*complete_rejection)(void *context, const YDBinaryRequestMessage *,
        const YDTLSClientIdentity *, YDBinaryReply rejection, unsigned remaining_ms);
    /* Both required, nonblocking/thread-safe; bridge the HTTP >2 MiB upload
     * ledger. Successful reserve is balanced exactly once at actual job free,
     * including queued, executing, cancelled and disconnected requests. */
    bool (*reserve_upload)(void *context, size_t length);
    void (*release_upload)(void *context, size_t length);
} YDBinaryRuntimeOptions;

/* Opens/binds a listener and starts one I/O thread and two dispatch workers.
 * HELLO advertises four streams per connection; the negotiated peer minimum
 * applies. Four globally owned jobs still bound assembly, queued/running work,
 * retained replies and detached callbacks across all eight connections.
 * Each ready reply yields after one complete frame. Callbacks remain finite
 * schema-1 document calls; no producer streaming or automatic replay is added.
 * Options are copied. Failure cleans partial startup and returns NULL.
 * No daemon wiring, backend ownership, replay or production acceptance implied. */
YDBinaryRuntime *yd_binary_runtime_start(const YDBinaryRuntimeOptions *options,
                                      char *error, size_t error_length);
/* Additive credential-evidence callbacks. Supply BOTH callbacks; their copied
 * evidence belongs to the owned job and survives disconnect/session reuse.
 * The I/O owner extracts it once after the inbound TLS handshake; workers
 * never access SSL or session memory. The options' legacy admit/execute may
 * be NULL here and are ignored. Other options and lifetime rules are identical.
 * Evidence establishes channel identity only; callbacks choose credentials and
 * apply policy independently for every request. Never accept wire evidence. */
typedef bool (*YDBinaryIdentityAdmit)(void *context, const YDBinaryRequestMessage *,
    const YDTLSClientIdentity *, YDBinaryReply *rejection);
typedef YDBinaryReply (*YDBinaryIdentityExecute)(void *context, const YDBinaryRequestMessage *,
    const YDTLSClientIdentity *, const unsigned char *body, size_t length, unsigned remaining_ms);
YDBinaryRuntime *yd_binary_runtime_start_with_identity(const YDBinaryRuntimeOptions *,
    YDBinaryIdentityAdmit, YDBinaryIdentityExecute, char *error, size_t error_length);
uint16_t yd_binary_runtime_port(const YDBinaryRuntime *server);
bool yd_binary_runtime_healthy(const YDBinaryRuntime *server);
/* External lifecycle owner only; never from a callback. Stops admission/I/O,
 * detaches jobs, joins I/O and both workers, then frees owned state. Does not
 * destroy borrowed tls/context. A running callback/filesystem may block this
 * join; caller destroys backend only after return. NULL is a no-op. Accessors
 * may run before close starts; callers serialize destruction against access. */
void yd_binary_runtime_close(YDBinaryRuntime *server);
#endif
