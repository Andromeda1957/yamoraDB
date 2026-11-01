#define _GNU_SOURCE
#include "binary_session.h"
#include "binary_frame.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define SESSIONS 8U
#define JOBS 4U
#define STREAMS 4U
#define WORKERS 2U
#define QUEUED 2U
#define FRAME (64U * 1024U)
#define TAIL (16U * 1024U)
#define CONTROL 4096U
#define CONTROLS 32U
#define MEMORY (128U * 1024U * 1024U)
#define LARGE (2U * 1024U * 1024U)
#ifndef YD_SESSION_IDLE_MS
#define YD_SESSION_IDLE_MS 5000U
#endif
#ifndef YD_SESSION_LIFE_MS
#define YD_SESSION_LIFE_MS 60000U
#endif
#define DRAIN_MS 2000U
#define REQUESTS 128U

typedef enum { FREE, ASSEMBLY, WAITING, RUNNING, DONE, SLEEPING, FINAL_WAIT, FINAL_RUNNING } JobState;
typedef struct {
    JobState state;
    YDBinaryRequestMessage request;
    YDTLSClientIdentity identity;
    unsigned char *body;
    size_t received, reservation, upload;
    YDBinaryReply reply;
    uint64_t generation, deadline, upload_deadline, queue_deadline, sequence, send_deadline;
    unsigned session, response_stage;
    size_t response_offset;
    uint64_t pull_at, produced_bytes;
    bool producer_end, producer_failed;
    bool terminal_complete, terminal_done;
    uint32_t stream;
    bool rejected, ended, detached, release_ready;
} Job;
typedef struct {
    YDBinaryType type;
    uint32_t stream;
    unsigned length;
    unsigned char payload[12];
    uint64_t deadline;
    YDBinaryTicket ticket;
} Control;
typedef enum { TX_OTHER, TX_METADATA, TX_BODY, TX_END, TX_TERMINAL } TxKind;
typedef struct {
    int fd;
    YDConnection tls;
    YDTLSClientIdentity identity;
    uint64_t generation, accepted, phase_deadline, frame_deadline, application_activity;
    uint64_t drain_deadline, ping_time;
    unsigned requests, ping_tokens;
    bool handshaken, draining, fatal, rx_ready, rx_admitted, write_pending;
    YDBinaryConnection wire;
    YDBinaryParser parser;
    unsigned char rx[FRAME], tx[FRAME + YD_BINARY_HEADER_SIZE], tail[TAIL];
    size_t tail_offset, tail_length, tx_length, tx_offset;
    YDBinaryFrame incoming;
    YDBinaryTicket rx_ticket, tx_ticket;
    uint64_t tx_deadline;
    TxKind tx_kind;
    YDTLSStep handshake_wait, write_wait, read_wait;
    Control controls[CONTROLS];
    unsigned control_head, control_count;
    Job *tx_job; /* Fixed job owner of the immutable active frame, if any. */
    unsigned next_response;
} Session;
struct YDBinaryRuntime {
    YDBinaryRuntimeOptions options;
    YDBinaryIdentityAdmit identity_admit;
    YDBinaryIdentityExecute identity_execute;
    int listener, wake[2];
    uint16_t port;
    pthread_t io, workers[WORKERS];
    unsigned worker_count;
    bool io_started, io_done; /* io_done is protected by lock */
    atomic_bool stop, healthy;
    pthread_mutex_t lock;
    pthread_cond_t changed;
    Job jobs[JOBS];
    Session sessions[SESSIONS];
    size_t reserved;
    uint64_t generation, sequence, accept_after;
};
static uint64_t clock_ms(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t))
        return 0;
    return (uint64_t)t.tv_sec * 1000 + (uint64_t)t.tv_nsec / 1000000;
}
static uint64_t minimum(uint64_t a, uint64_t b) { return a < b ? a : b; }
static void wake_io(YDBinaryRuntime *r) {
    unsigned char b = 1;
    ssize_t written = write(r->wake[1], &b, 1);
    if (written < 0 && errno != EAGAIN && errno != EINTR)
        atomic_store(&r->healthy, false);
}
static YDBinaryReply error_reply(unsigned status) {
    YDBinaryReply reply = {0};
    reply.message.status = (uint16_t)status;
    memcpy(reply.message.content_type, "application/json", 17);
    memcpy(reply.message.revision, "0000000000000000", 17);
    return reply;
}
static size_t response_cap(const Job *j) {
    return j->request.method == YD_BINARY_METHOD_GET || j->request.method == YD_BINARY_METHOD_HEAD ||
        (j->request.method == YD_BINARY_METHOD_POST && strcmp(j->request.target, "/v1/transactions"))
               ? (size_t)YD_BINARY_BODY_LIMIT + 1
               : CONTROL;
}
static size_t backend_response_reservation(const Job *j) {
    /* Existing native readers may allocate a full 64 MiB output buffer even
     * for an empty page. Charge before dispatch, separately from wire limits.
     * A live feed keeps this conservative reservation between pulls. Backend
     * evaluator/decoder workspace has its own native bounds, not this ledger. */
    bool page = j->request.schema == 2 &&
        ((j->request.method == YD_BINARY_METHOD_POST && strcmp(j->request.target, "/v1/transactions")) ||
         (j->request.method == YD_BINARY_METHOD_GET && !strncmp(j->request.target, "/v1/changes", 11)));
    return page ? 64U * 1024U * 1024U + 1U : response_cap(j);
}
static bool valid_reply(Job *j) {
    YDBinaryResponseMessage *m = &j->reply.message;
    size_t encoded;
    uint64_t cap =
        (!j->rejected && m->status < 400 &&
         response_cap(j) > CONTROL)
            ? YD_BINARY_BODY_LIMIT
            : CONTROL;
    m->schema = j->request.schema;
    bool stream = m->streaming;
    bool producer = j->reply.producer.next != NULL;
    if (producer && (j->rejected || j->request.method != YD_BINARY_METHOD_GET ||
        m->status != 200 || !j->reply.producer.close || !j->reply.page_length ||
        j->reply.page_length > cap || (!stream && j->reply.page_length > m->body_length))) return false;
    if (stream && (m->schema != 2 || !producer ||
        strncmp(j->request.target, "/v1/changes/stream?", 19))) return false;
    if (!producer && (j->reply.producer.close || j->reply.producer.finish || j->reply.page_length)) return false;
    size_t bytes = producer ? j->reply.page_length : (size_t)m->body_length;
    if (m->body_length > cap || m->representation_length > cap ||
        (bytes ? !j->reply.body : j->reply.body != NULL) ||
        (j->request.method == YD_BINARY_METHOD_HEAD && m->body_length) ||
        (j->request.method != YD_BINARY_METHOD_HEAD && m->status != 304 &&
         m->body_length != m->representation_length) ||
        (j->rejected && (m->status < 400 || m->status > 599)))
        return false;
    /* Correlation is owned by the runtime, not a backend-supplied assertion. */
    m->present &= (uint16_t)~YD_BINARY_RESPONSE_ID;
    memset(m->request_id, 0, sizeof(m->request_id));
    if (j->request.present & YD_BINARY_REQUEST_ID) {
        m->present |= YD_BINARY_RESPONSE_ID;
        memcpy(m->request_id, j->request.request_id, sizeof(m->request_id));
    }
    return yd_binary_response_message_size(m, &encoded);
}
/* Only the I/O/lifecycle owner frees jobs. The mutex excludes dispatch; a
 * RUNNING job is never recycled, including after its session disappears. */
/* Caller holds lock. Keep the fixed job and all reservations until its
 * worker-only terminal callback has returned. Never overlap execute/next. */
static void queue_terminal(YDBinaryRuntime *r, Job *j) {
    if (!j->reply.producer.finish || j->terminal_done ||
        j->state == RUNNING || j->state == FINAL_RUNNING || j->state == FINAL_WAIT) return;
    j->state = FINAL_WAIT;
    pthread_cond_broadcast(&r->changed);
}
static void free_job(YDBinaryRuntime *r, Job *j) {
    if (j->reply.producer.finish && !j->terminal_done) {
        queue_terminal(r, j);
        return;
    }
    if (j->upload)
        r->options.release_upload(r->options.context, j->upload);
    free(j->body);
    free(j->reply.body);
    if (j->reply.producer.close) j->reply.producer.close(j->reply.producer.context);
    r->reserved -= j->reservation;
    memset(j, 0, sizeof(*j));
}
static bool owns_job(const YDBinaryRuntime *r, const Session *s, const Job *j) {
    return j->state != FREE && j->session == (unsigned)(s - r->sessions) &&
           j->generation == s->generation && !j->release_ready;
}
/* The I/O owner alone changes job identity/free state. Workers only publish
 * reply/state under lock; a returned pointer stays owned until I/O releases it. */
static Job *session_job(YDBinaryRuntime *r, Session *s, uint32_t stream) {
    Job *found = NULL;
    pthread_mutex_lock(&r->lock);
    for (unsigned i = 0; i < JOBS; i++)
        if (owns_job(r, s, &r->jobs[i]) && (!stream || r->jobs[i].stream == stream)) {
            found = &r->jobs[i];
            break;
        }
    pthread_mutex_unlock(&r->lock);
    return found;
}
static void detach_job(YDBinaryRuntime *r, Job *j, bool release_ready) {
    pthread_mutex_lock(&r->lock);
    j->detached = true;
    j->release_ready = release_ready;
    if (j->state != RUNNING && j->state != FINAL_RUNNING && j->state != FINAL_WAIT)
        j->state = DONE;
    if (release_ready) {
        if (j->state == DONE)
            free_job(r, j);
    }
    pthread_mutex_unlock(&r->lock);
}
static void detach_session(YDBinaryRuntime *r, Session *s) {
    Job *j;
    while ((j = session_job(r, s, 0)))
        detach_job(r, j, true);
    s->tx_job = NULL;
}
static void release_ticket(Session *s, YDBinaryTicket *t) {
    if (t->owner)
        (void)yd_binary_release(&s->wire, t);
}
static void close_session(YDBinaryRuntime *r, Session *s) {
    if (s->fd < 0)
        return;
    detach_session(r, s);
    release_ticket(s, &s->rx_ticket);
    release_ticket(s, &s->tx_ticket);
    for (unsigned i = 0; i < s->control_count; i++)
        release_ticket(s, &s->controls[(s->control_head + i) % CONTROLS].ticket);
    yd_connection_close(&s->tls);
    close(s->fd);
    s->fd = -1;
}
/* Control tickets are acquired once on queueing and moved, never duplicated,
 * into the one active transmit frame. Their wire budget is exactly 4 KiB. */
static bool control_push(Session *s, YDBinaryType type, uint32_t stream,
                         const unsigned char *payload, unsigned length, uint64_t deadline) {
    if (s->control_count == CONTROLS || length > 12)
        return false;
    Control *c = &s->controls[(s->control_head + s->control_count) % CONTROLS];
    YDBinaryFrame f = {.type = type, .stream_id = stream, .length = length, .payload = payload};
    YDBinaryTicket t = {0};
    if (yd_binary_admit(&s->wire, YD_BINARY_SEND, &f, &t) != YD_BINARY_OK)
        return false;
    *c = (Control){
        .type = type, .stream = stream, .length = length, .deadline = deadline, .ticket = t};
    if (length)
        memcpy(c->payload, payload, length);
    s->control_count++;
    return true;
}
static void begin_drain(Session *s, uint64_t now) {
    if (!s->draining) {
        s->draining = true;
        s->drain_deadline = now + DRAIN_MS;
    }
}
static void fatal_stream(YDBinaryRuntime *r, Session *s, uint32_t stream, uint64_t now) {
    static const unsigned char code[4] = {0, 0, 0, 1};
    if (!s->fatal) {
        detach_session(r, s);
        s->fatal = true;
        begin_drain(s, now);
        if (!control_push(s, YD_BINARY_ERROR, stream, code, sizeof(code),
                          minimum(s->drain_deadline, now + r->options.io_timeout_ms)))
            s->drain_deadline = now;
    }
}
static void *worker(void *argument) {
    (void)pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
    YDBinaryRuntime *r = argument;
    pthread_mutex_lock(&r->lock);
    for (;;) {
        Job *j = NULL;
        /* Terminal callbacks are ownership cleanup: they bypass ordinary
         * queue/deadline admission and still run during shutdown. */
        for (unsigned i = 0; i < JOBS; i++)
            if (r->jobs[i].state == FINAL_WAIT) {
                j = &r->jobs[i];
                break;
            }
        if (j) {
            j->state = FINAL_RUNNING;
            bool complete = j->terminal_complete;
            bool (*finish)(void *, bool) = j->reply.producer.finish;
            void *context = j->reply.producer.context;
            pthread_mutex_unlock(&r->lock);
            bool acknowledged = finish(context, complete);
            pthread_mutex_lock(&r->lock);
            j->terminal_done = true;
            j->state = DONE;
            if (!acknowledged) atomic_store(&r->healthy, false);
            wake_io(r);
            continue;
        }
        if (atomic_load(&r->stop)) {
            /* I/O must first detach every session. A still-running execute
             * adopts and queues its own eventual producer before it exits. */
            if (r->io_done) break;
            pthread_cond_wait(&r->changed, &r->lock);
            continue;
        }
        for (unsigned i = 0; i < JOBS; i++)
            if (r->jobs[i].state == WAITING && (!j || r->jobs[i].sequence < j->sequence))
                j = &r->jobs[i];
        if (!j) {
            pthread_cond_wait(&r->changed, &r->lock);
            continue;
        }
        uint64_t now = clock_ms();
        if (!now || now >= j->deadline || now >= j->queue_deadline || j->detached) {
            if (j->reply.producer.next) j->producer_failed = true;
            else {
                free(j->reply.body);
                j->reply = error_reply(504);
            }
            j->state = DONE;
            if (j->release_ready || atomic_load(&r->stop)) queue_terminal(r, j);
            wake_io(r);
            continue;
        }
        j->state = RUNNING;
        pthread_mutex_unlock(&r->lock);
        now = clock_ms();
        bool pull = j->reply.producer.next && j->response_stage >= 2;
        YDBinaryReply reply = error_reply(504);
        YDBinaryChunk chunk = {0};
        if (now && now < j->deadline && now < j->queue_deadline && !atomic_load(&r->stop)) {
            if (pull)
                chunk = j->reply.producer.next(j->reply.producer.context,
                    (unsigned)(j->deadline - now));
            else if (j->rejected && r->options.complete_rejection) {
                YDBinaryReply rejection = j->reply;
                memset(&j->reply, 0, sizeof(j->reply));
                reply = r->options.complete_rejection(r->options.context, &j->request,
                    &j->identity, rejection, (unsigned)(j->deadline - now));
            } else
                reply = r->identity_execute
                    ? r->identity_execute(r->options.context, &j->request, &j->identity,
                        j->body, (size_t)j->request.body_length, (unsigned)(j->deadline - now))
                    : r->options.execute(r->options.context, &j->request, j->body,
                        (size_t)j->request.body_length, (unsigned)(j->deadline - now));
        } else if (!pull) {
            free(j->reply.body);
            memset(&j->reply, 0, sizeof(j->reply));
        }
        pthread_mutex_lock(&r->lock);
        if (pull) {
            uint64_t total = j->reply.message.streaming
                ? YD_BINARY_BODY_LIMIT : j->reply.message.body_length;
            bool page = chunk.body && chunk.length && !chunk.wait_ms && !chunk.end &&
                j->produced_bytes <= total && chunk.length <= total - j->produced_bytes;
            bool wait = j->reply.message.streaming && !chunk.body && !chunk.length &&
                !chunk.end && chunk.wait_ms && chunk.wait_ms <= 5000;
            bool end = !chunk.body && !chunk.length && !chunk.wait_ms && chunk.end &&
                (j->reply.message.streaming || j->produced_bytes == total);
            j->producer_failed = !page && !wait && !end;
            j->producer_end = end;
            if (page) {
                j->reply.body = chunk.body;
                j->reply.page_length = chunk.length;
                j->produced_bytes += chunk.length;
            } else free(chunk.body);
            j->pull_at = clock_ms() + chunk.wait_ms;
            j->queue_deadline = minimum(j->deadline, j->pull_at + 1000);
            j->state = wait ? SLEEPING : DONE;
        } else {
            j->reply = reply;
            j->state = DONE;
        }
        if ((j->detached && j->release_ready) || atomic_load(&r->stop))
            queue_terminal(r, j);
        wake_io(r);
    }
    pthread_mutex_unlock(&r->lock);
    return NULL;
}
static Job *admit_request(YDBinaryRuntime *r, Session *s, const YDBinaryFrame *f, uint64_t now) {
    YDBinaryRequestMessage request;
    if (f->length > YD_BINARY_METADATA_LIMIT ||
        !yd_binary_request_message_decode(f->payload, f->length, &request) ||
        (request.schema == 2 && s->wire.protocol < 2) ||
        request.body_length > r->options.max_body)
        return NULL;
    pthread_mutex_lock(&r->lock);
    Job *j = NULL;
    for (unsigned i = 0; i < JOBS; i++)
        if (r->jobs[i].state == FREE) {
            j = &r->jobs[i];
            break;
        }
    if (!j || r->reserved > MEMORY - CONTROL) {
        pthread_mutex_unlock(&r->lock);
        return NULL;
    }
    *j = (Job){.state = ASSEMBLY,
               .request = request,
               .identity = s->identity,
               .reservation = CONTROL,
               .session = (unsigned)(s - r->sessions),
               .generation = s->generation,
               .stream = f->stream_id,
               .deadline = s->frame_deadline - r->options.io_timeout_ms + request.timeout_ms};
    j->upload_deadline = minimum(j->deadline, s->frame_deadline);
    r->reserved += j->reservation;
    pthread_mutex_unlock(&r->lock);
    /* Parent performs authentication and actual disk profile validation before
     * any upload reservation or peer-sized body allocation. */
    j->rejected = !(r->identity_admit
        ? r->identity_admit(r->options.context, &j->request, &j->identity, &j->reply)
        : r->options.admit(r->options.context, &j->request, &j->reply));
    if (j->rejected) {
        if (!valid_reply(j))
            goto fail;
        return j;
    }
    if (j->reply.body || j->reply.message.status || now >= j->upload_deadline)
        goto fail;
    size_t wanted = (size_t)request.body_length + backend_response_reservation(j);
    pthread_mutex_lock(&r->lock);
    if (wanted > MEMORY - (r->reserved - j->reservation)) {
        pthread_mutex_unlock(&r->lock);
        goto fail;
    }
    r->reserved = r->reserved - j->reservation + wanted;
    j->reservation = wanted;
    pthread_mutex_unlock(&r->lock);
    if (request.body_length > LARGE) {
        if (!r->options.reserve_upload(r->options.context, (size_t)request.body_length))
            goto fail;
        j->upload = (size_t)request.body_length;
    }
    if (request.body_length) {
        j->body = malloc((size_t)request.body_length);
        if (!j->body)
            goto fail;
    }
    return j;
fail:
    pthread_mutex_lock(&r->lock);
    free_job(r, j);
    pthread_mutex_unlock(&r->lock);
    return NULL;
}
static void schedule_job(YDBinaryRuntime *r, Job *j, uint64_t now) {
    pthread_mutex_lock(&r->lock);
    if ((j->state == ASSEMBLY || (j->state == SLEEPING && now >= j->pull_at)) &&
        j->ended && !j->detached) {
        unsigned queued = 0;
        for (unsigned i = 0; i < JOBS; i++)
            queued += r->jobs[i].state == WAITING;
        if (j->rejected && !r->options.complete_rejection)
            j->state = DONE;
        else if (now < j->deadline && now < j->queue_deadline && queued < QUEUED) {
            j->sequence = ++r->sequence;
            j->state = WAITING;
            pthread_cond_signal(&r->changed);
        }
    }
    pthread_mutex_unlock(&r->lock);
}
/* Complete received frames remain in rx with their ticket until processed.
 * False means bounded backpressure: neither parser nor coalesced tail moves. */
static bool process_frame(YDBinaryRuntime *r, Session *s, uint64_t now) {
    const YDBinaryFrame *f = &s->incoming;
    if (f->type == YD_BINARY_HELLO) {
        uint32_t offered = (uint32_t)f->payload[4] << 24 | (uint32_t)f->payload[5] << 16 |
                           (uint32_t)f->payload[6] << 8 | f->payload[7];
        if (offered < 4096) {
            s->drain_deadline = now;
            s->fatal = true;
            return true;
        }
        s->application_activity = now;
        return yd_binary_parser_init(&s->parser, s->rx, sizeof(s->rx), s->wire.max_frame);
    }
    if (f->type == YD_BINARY_PING) {
        uint64_t elapsed = now - s->ping_time;
        uint64_t tokens = s->ping_tokens + minimum(elapsed, 1000) * 4;
        if (tokens > 4000)
            tokens = 4000;
        if (tokens < 1000) {
            s->fatal = true;
            s->drain_deadline = now;
            return true;
        }
        if (!control_push(s, YD_BINARY_PONG, 0, f->payload, 8, now + r->options.io_timeout_ms))
            return false;
        s->ping_tokens = (unsigned)tokens - 1000;
        s->ping_time = now;
        return true;
    }
    if (f->type == YD_BINARY_PONG)
        return true;
    if (f->type == YD_BINARY_GOAWAY) {
        begin_drain(s, now);
        return true;
    }
    /* Explicit control traffic has its own limits, but cannot keep an idle
     * application connection alive. Only application frames refresh this. */
    s->application_activity = now;
    if (f->type == YD_BINARY_REQUEST) {
        if (!admit_request(r, s, f, now))
            fatal_stream(r, s, f->stream_id, now);
        else if (++s->requests >= REQUESTS) {
            if (!control_push(s, YD_BINARY_GOAWAY, 0, NULL, 0, now + DRAIN_MS))
                return false;
            begin_drain(s, now);
        }
        return true;
    }
    if (f->type == YD_BINARY_CANCEL) {
        Job *j = session_job(r, s, f->stream_id);
        if (!j || j->detached ||
            (s->tx_job == j && (s->tx_kind == TX_END || s->tx_kind == TX_TERMINAL)))
            return true; /* Historical no-op. */
        if (!control_push(s, YD_BINARY_END, f->stream_id, NULL, 0, now + r->options.io_timeout_ms))
            return false;
        detach_job(r, j, false);
        return true;
    }
    Job *j = session_job(r, s, f->stream_id);
    if (!j || j->ended || j->detached) {
        fatal_stream(r, s, f->stream_id, now);
        return true;
    }
    if (f->type == YD_BINARY_DATA) {
        if (f->length > j->request.body_length - j->received) {
            fatal_stream(r, s, f->stream_id, now);
            return true;
        }
        if (!j->rejected && f->length)
            memcpy(j->body + j->received, f->payload, f->length);
        j->received += f->length;
        return true;
    }
    if (f->type != YD_BINARY_END || j->received != j->request.body_length) {
        fatal_stream(r, s, f->stream_id, now);
        return true;
    }
    j->ended = true;
    j->queue_deadline = minimum(j->deadline, now + 1000);
    schedule_job(r, j, now);
    return true;
}
static bool receive_frames(YDBinaryRuntime *r, Session *s, uint64_t now, bool *progress) {
    for (unsigned rounds = 0; rounds < 16; rounds++) {
        if (s->fatal) {
            s->tail_offset = s->tail_length = 0;
            return true;
        }
        if (!s->rx_ready) {
            if (s->tail_offset == s->tail_length)
                break;
            if (!s->parser.header_used && !s->parser.payload_used)
                s->frame_deadline = now + r->options.io_timeout_ms;
            size_t consumed = 0;
            YDBinaryResult result =
                yd_binary_parser_feed(&s->parser, s->tail + s->tail_offset,
                                      s->tail_length - s->tail_offset, &consumed, &s->incoming);
            s->tail_offset += consumed;
            if (result == YD_BINARY_MORE)
                break;
            if (result != YD_BINARY_FRAME)
                return false;
            s->rx_ready = true;
        }
        if (!s->rx_admitted) {
            YDBinaryResult result =
                yd_binary_admit(&s->wire, YD_BINARY_RECEIVE, &s->incoming, &s->rx_ticket);
            if (result == YD_BINARY_BACKPRESSURE)
                return true;
            if (result != YD_BINARY_OK)
                return false;
            s->rx_admitted = true;
        }
        if (!process_frame(r, s, now))
            return true;
        release_ticket(s, &s->rx_ticket);
        s->rx_ready = s->rx_admitted = false;
        *progress = true;
    }
    if (s->tail_offset == s->tail_length)
        s->tail_offset = s->tail_length = 0;
    return true;
}
static bool queue_frame(Session *s, YDBinaryType type, uint32_t stream, const unsigned char *data,
                        size_t length, uint64_t deadline, TxKind kind, YDBinaryTicket *owned) {
    YDBinaryFrame f = {
        .type = type, .stream_id = stream, .length = (uint32_t)length, .payload = data};
    YDBinaryTicket ticket = {0};
    if (owned) {
        ticket = *owned;
        memset(owned, 0, sizeof(*owned));
    } else {
        YDBinaryResult result = yd_binary_admit(&s->wire, YD_BINARY_SEND, &f, &ticket);
        if (result == YD_BINARY_BACKPRESSURE)
            return true; /* Keep source/stage, retry unchanged. */
        if (result != YD_BINARY_OK)
            return false;
    }
    if (yd_binary_header_encode(&f, s->tx) != YD_BINARY_OK) {
        release_ticket(s, &ticket);
        return false;
    }
    if (length)
        memcpy(s->tx + YD_BINARY_HEADER_SIZE, data, length);
    s->tx_length = YD_BINARY_HEADER_SIZE + length;
    s->tx_offset = 0;
    s->tx_ticket = ticket;
    s->tx_deadline = deadline;
    s->tx_kind = kind;
    return true;
}
static bool prepare_send(YDBinaryRuntime *r, Session *s, uint64_t now) {
    if (s->tx_length)
        return true;
    if (s->control_count) {
        Control *c = &s->controls[s->control_head];
        TxKind kind = c->type == YD_BINARY_END || c->type == YD_BINARY_ERROR
                          ? TX_TERMINAL : TX_OTHER;
        Job *j = kind == TX_TERMINAL ? session_job(r, s, c->stream) : NULL;
        if (!queue_frame(s, c->type, c->stream, c->payload, c->length, c->deadline, kind,
                         &c->ticket))
            return false;
        s->tx_job = j;
        s->control_head = (s->control_head + 1) % CONTROLS;
        s->control_count--;
        return true;
    }
    if (s->fatal)
        return true;
    Job *j = NULL;
    pthread_mutex_lock(&r->lock);
    for (unsigned n = 0; n < JOBS; n++) {
        unsigned i = (s->next_response + n) % JOBS;
        if (owns_job(r, s, &r->jobs[i]) && r->jobs[i].state == DONE && !r->jobs[i].detached) {
            j = &r->jobs[i];
            break;
        }
    }
    pthread_mutex_unlock(&r->lock);
    if (!j)
        return true;
    if (!j->response_stage) {
        if (!valid_reply(j)) {
            if (j->reply.producer.next || j->reply.producer.close || j->reply.producer.finish) {
                /* Invalid producer metadata cannot discard its admitted
                 * lifetime on I/O. Send terminal ERROR, then retire normally. */
                j->producer_failed = true;
            } else {
                free(j->reply.body);
                j->reply = error_reply(500);
                (void)valid_reply(j);
            }
        }
        j->send_deadline = minimum(j->deadline, now + r->options.io_timeout_ms);
        j->response_stage = 1;
        j->produced_bytes = j->reply.page_length;
    }
    if (!j->send_deadline) j->send_deadline = minimum(j->deadline, now + r->options.io_timeout_ms);
    bool queued;
    size_t body_length = j->reply.producer.next ? j->reply.page_length : (size_t)j->reply.message.body_length;
    if (j->producer_failed) {
        static const unsigned char code[4] = {0, 0, 0, 1};
        queued = queue_frame(s, YD_BINARY_ERROR, j->stream, code, sizeof(code), j->send_deadline, TX_TERMINAL, NULL);
    } else if (j->response_stage == 1) {
        unsigned char metadata[YD_BINARY_METADATA_LIMIT];
        size_t length = 0;
        if (!yd_binary_response_message_encode(&j->reply.message, metadata, sizeof(metadata),
                                               &length))
            return false;
        queued = queue_frame(s, YD_BINARY_RESPONSE, j->stream, metadata, length, j->send_deadline,
                             TX_METADATA, NULL);
    } else if (j->response_offset < body_length) {
        size_t length = body_length - j->response_offset;
        if (length > s->wire.max_frame)
            length = s->wire.max_frame;
        queued = queue_frame(s, YD_BINARY_DATA, j->stream, j->reply.body + j->response_offset,
                             length, j->send_deadline, TX_BODY, NULL);
    } else {
        queued = queue_frame(s, YD_BINARY_END, j->stream, NULL, 0, j->send_deadline, TX_END, NULL);
    }
    if (queued && s->tx_length) {
        s->tx_job = j;
        /* Each complete frame yields to the next ready stream, including
         * metadata/END. No stream can consume another's send deadline. */
        s->next_response = ((unsigned)(j - r->jobs) + 1) % JOBS;
    }
    return queued;
}
static void finished_send(YDBinaryRuntime *r, Session *s) {
    release_ticket(s, &s->tx_ticket);
    Job *j = s->tx_job;
    if (j) {
        if (s->tx_kind == TX_METADATA)
            j->response_stage = 2;
        if (s->tx_kind == TX_BODY)
            j->response_offset += s->tx_length - YD_BINARY_HEADER_SIZE;
        if (j->reply.producer.next && s->tx_kind == TX_BODY &&
            j->response_offset == j->reply.page_length) {
            /* A pull is never scheduled until the entire prior page left TLS.
             * The callback can now advance its cursor. Cancellation keeps the
             * in-flight owner alive and prevents all subsequent pulls. */
            pthread_mutex_lock(&r->lock);
            free(j->reply.body);
            j->reply.body = NULL;
            j->reply.page_length = j->response_offset = 0;
            j->send_deadline = 0;
            bool complete = !j->reply.message.streaming &&
                j->produced_bytes == j->reply.message.body_length;
            if (!j->detached && !complete) {
                j->queue_deadline = minimum(j->deadline, clock_ms() + 1000);
                j->state = ASSEMBLY;
            }
            pthread_mutex_unlock(&r->lock);
        }
        if (s->tx_kind == TX_END || s->tx_kind == TX_TERMINAL) {
            pthread_mutex_lock(&r->lock);
            j->terminal_complete = s->tx_kind == TX_END && !j->detached && !j->producer_failed;
            pthread_mutex_unlock(&r->lock);
            detach_job(r, j, true);
        }
    }
    s->tx_job = NULL;
    s->tx_length = s->tx_offset = 0;
}
static bool session_step(YDBinaryRuntime *r, Session *s, uint64_t now, bool *progress) {
    if (!s->handshaken) {
        YDTLSStep result = yd_connection_handshake_step(&s->tls, s->phase_deadline);
        s->handshake_wait = result;
        if (result == YD_TLS_ERROR || result == YD_TLS_EOF)
            return false;
        if (result != YD_TLS_READY)
            return true;
        if (r->identity_admit &&
            yd_connection_client_identity(&s->tls, &s->identity) == YD_TLS_CLIENT_ERROR)
            return false;
        s->handshaken = true;
        s->phase_deadline = now + r->options.io_timeout_ms;
        unsigned char hello[YD_BINARY_HELLO_SIZE];
        yd_binary_hello_protocols(hello, FRAME, STREAMS, 2);
        if (!control_push(s, YD_BINARY_HELLO, 0, hello, sizeof(hello), s->phase_deadline))
            return false;
        *progress = true;
    }
    bool ready = yd_binary_connection_ready(&s->wire);
    if (!ready && now >= s->phase_deadline)
        return false;
    if (s->fatal && now >= s->drain_deadline)
        return false;
    if (!s->draining && now - s->accepted >= YD_SESSION_LIFE_MS && ready) {
        if (!control_push(s, YD_BINARY_GOAWAY, 0, NULL, 0, now + DRAIN_MS))
            return false;
        begin_drain(s, now);
    }
    if (s->draining && now >= s->drain_deadline)
        return false;
    if (ready && !s->draining && !session_job(r, s, 0) &&
        now - s->application_activity >= YD_SESSION_IDLE_MS)
        return false;
    if ((s->parser.header_used || s->parser.payload_used || s->rx_ready) &&
        now >= s->frame_deadline)
        return false;
    for (unsigned i = 0; i < JOBS && !s->fatal; i++) {
        Job *j = &r->jobs[i];
        pthread_mutex_lock(&r->lock);
        bool owned = owns_job(r, s, j) && !j->detached;
        bool expired = owned && (now >= j->deadline ||
            (!j->ended && now >= j->upload_deadline) ||
            (j->send_deadline && now >= j->send_deadline) ||
            ((j->state == WAITING || (j->state == ASSEMBLY && j->ended) ||
              (j->state == SLEEPING && now >= j->pull_at)) &&
             now >= j->queue_deadline));
        pthread_mutex_unlock(&r->lock);
        if (expired) {
            /* A complete request can terminate independently. An unfinished
             * upload still requires bounded connection drain: no END exists
             * to retire its request half safely. Pending TLS bytes likewise
             * retain their original deadline and may close the connection. */
            static const unsigned char code[4] = {0, 0, 0, 1};
            if (!j->ended || !control_push(s, YD_BINARY_ERROR, j->stream, code, sizeof(code),
                                           now + r->options.io_timeout_ms))
                fatal_stream(r, s, j->stream, now);
            else
                detach_job(r, j, false);
        } else if (owned && j->ended)
            schedule_job(r, j, now);
    }
    if (!prepare_send(r, s, now))
        return false;
    if (s->tx_length) {
        size_t sent = 0;
        YDTLSStep result = yd_connection_write_step(
            &s->tls, s->tx + s->tx_offset, s->tx_length - s->tx_offset, s->tx_deadline, &sent);
        s->write_wait = result;
        s->write_pending = result == YD_TLS_WANT_READ || result == YD_TLS_WANT_WRITE;
        if (result == YD_TLS_ERROR || result == YD_TLS_EOF)
            return false;
        if (result == YD_TLS_READY) {
            s->tx_offset += sent;
            if (s->tx_kind != TX_OTHER)
                s->application_activity = now;
            *progress = true;
            if (s->tx_offset == s->tx_length)
                finished_send(r, s);
        }
        if (s->write_pending)
            return true; /* Immutable SSL retry, no RX interleave. */
    }
    if (s->draining && !s->fatal && !session_job(r, s, 0) && !s->tx_length && !s->control_count)
        return false;
    if (!receive_frames(r, s, now, progress))
        return false;
    if (!s->rx_ready && s->tail_offset == s->tail_length) {
        s->tail_offset = s->tail_length = 0;
        size_t got = 0;
        uint64_t deadline = !ready ? s->phase_deadline
            : session_job(r, s, 0) ? now + r->options.io_timeout_ms
                                  : s->application_activity + YD_SESSION_IDLE_MS;
        if (s->parser.header_used || s->parser.payload_used)
            deadline = minimum(deadline, s->frame_deadline);
        for (unsigned i = 0; i < JOBS; i++) {
            Job *j = &r->jobs[i];
            pthread_mutex_lock(&r->lock);
            /* Completed requests expire in the per-stream loop above. Their
             * budgets must not become a connection-wide TLS read timeout if
             * the clock crosses the deadline between the two checks. */
            if (owns_job(r, s, j) && !j->detached && !j->ended)
                deadline = minimum(deadline, j->upload_deadline);
            pthread_mutex_unlock(&r->lock);
        }
        if (s->fatal)
            deadline = s->drain_deadline;
        YDTLSStep result =
            yd_connection_read_step(&s->tls, s->tail, sizeof(s->tail), deadline, &got);
        s->read_wait = result;
        if (result == YD_TLS_ERROR || result == YD_TLS_EOF)
            return false;
        if (result == YD_TLS_READY) {
            s->tail_length = got;
            *progress = true;
            if (!receive_frames(r, s, now, progress))
                return false;
        }
    }
    return true;
}
static void accept_sessions(YDBinaryRuntime *r, uint64_t now) {
    if (now < r->accept_after)
        return;
    for (unsigned attempt = 0; attempt < SESSIONS; attempt++) {
        int fd = accept4(r->listener, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return;
            switch (errno) {
            case EINTR:
            case ECONNABORTED:
            case ECONNRESET:
            case EPROTO:
            case ENETDOWN:
            case ENOPROTOOPT:
            case EHOSTDOWN:
            case ENONET:
            case EHOSTUNREACH:
            case EOPNOTSUPP:
            case ENETUNREACH:
                continue; /* Per-connection errors consume the bounded batch. */
            case EMFILE:
            case ENFILE:
            case ENOBUFS:
            case ENOMEM:
                r->accept_after = now + 50;
                return;
            default:
                break; /* Invalid/unusable listener: fail health explicitly. */
            }
            atomic_store(&r->healthy, false);
            atomic_store(&r->stop, true);
            return;
        }
        Session *s = NULL;
        for (unsigned i = 0; i < SESSIONS; i++)
            if (r->sessions[i].fd < 0) {
                s = &r->sessions[i];
                break;
            }
        if (!s || r->generation == UINT64_MAX) {
            close(fd);
            continue;
        }
        memset(s, 0, sizeof(*s));
        s->fd = fd;
        s->generation = ++r->generation;
        s->accepted = s->application_activity = s->ping_time = now;
        s->ping_tokens = 4000;
        s->phase_deadline = now + r->options.io_timeout_ms;
        YDBinaryLimits limits = {.max_frame = FRAME,
                                 .max_streams = STREAMS,
                                 .max_protocol = 2,
                                 .max_message = YD_BINARY_BODY_LIMIT,
                                 .receive_budget = FRAME + 16,
                                 .send_budget = FRAME + 16,
                                 .control_budget = CONTROL};
        if (!yd_binary_connection_init(&s->wire, false, &limits) ||
            !yd_binary_parser_init(&s->parser, s->rx, sizeof(s->rx), FRAME) ||
            !yd_connection_binary_begin(&s->tls, fd, r->options.tls))
            close_session(r, s);
    }
    /* A persistently failing/overloaded accept queue must not spin, even while
     * other sessions or wakeups keep the reactor active. */
    r->accept_after = now + 50;
}
static void collect_detached(YDBinaryRuntime *r) {
    pthread_mutex_lock(&r->lock);
    for (unsigned i = 0; i < JOBS; i++) {
        Job *j = &r->jobs[i];
        if (j->state != DONE)
            continue;
        bool stale = j->session >= SESSIONS || r->sessions[j->session].fd < 0 ||
                     r->sessions[j->session].generation != j->generation;
        if ((j->detached && j->release_ready) || stale)
            free_job(r, j);
    }
    pthread_mutex_unlock(&r->lock);
}
static void *io_loop(void *argument) {
    YDBinaryRuntime *r = argument;
    sigset_t signals;
    sigemptyset(&signals);
    sigaddset(&signals, SIGPIPE);
    (void)pthread_sigmask(SIG_BLOCK, &signals, NULL);
    while (!atomic_load(&r->stop)) {
        uint64_t now = clock_ms();
        if (!now) {
            atomic_store(&r->healthy, false);
            break;
        }
        bool progress = false;
        accept_sessions(r, now);
        collect_detached(r);
        struct pollfd fds[2 + SESSIONS] = {
            {.fd = now < r->accept_after ? -1 : r->listener, .events = POLLIN},
            {.fd = r->wake[0], .events = POLLIN}};
        for (unsigned i = 0; i < SESSIONS; i++) {
            Session *s = &r->sessions[i];
            if (s->fd >= 0 && !session_step(r, s, now, &progress))
                close_session(r, s);
            bool can_read = !s->rx_ready && s->tail_offset == s->tail_length;
            fds[2 + i] = (struct pollfd){.fd = s->fd, .events = can_read ? POLLIN : 0};
            if (!s->handshaken && s->handshake_wait == YD_TLS_WANT_WRITE)
                fds[2 + i].events = POLLOUT;
            else if (s->write_pending)
                fds[2 + i].events = s->write_wait == YD_TLS_WANT_READ ? POLLIN : POLLOUT;
            else if (s->tx_length || (can_read && s->read_wait == YD_TLS_WANT_WRITE))
                fds[2 + i].events |= POLLOUT;
            if (!fds[2 + i].events)
                fds[2 + i].fd = -1; /* Even unrequested HUP would spin. Worker
                                     * wakeups and the <=50ms timer still run. */
        }
        int result = poll(fds, 2 + SESSIONS, progress ? 0 : 50);
        if (result < 0 && errno != EINTR) {
            atomic_store(&r->healthy, false);
            break;
        }
        if (fds[1].revents) {
            unsigned char data[64];
            ssize_t drained = read(r->wake[0], data, sizeof(data));
            if (drained < 0 && errno != EAGAIN && errno != EINTR)
                atomic_store(&r->healthy, false);
        }
    }
    atomic_store(&r->stop, true);
    pthread_mutex_lock(&r->lock);
    pthread_cond_broadcast(&r->changed);
    pthread_mutex_unlock(&r->lock);
    for (unsigned i = 0; i < SESSIONS; i++)
        close_session(r, &r->sessions[i]);
    pthread_mutex_lock(&r->lock);
    r->io_done = true;
    pthread_cond_broadcast(&r->changed);
    pthread_mutex_unlock(&r->lock);
    return NULL;
}
static YDBinaryRuntime *start(const YDBinaryRuntimeOptions *options,
    YDBinaryIdentityAdmit admit, YDBinaryIdentityExecute execute, char *error, size_t length) {
    if (error && length)
        error[0] = 0;
    if (!options || !yd_tls_is_binary(options->tls) ||
        ((admit == NULL) != (execute == NULL)) ||
        (!admit && (!options->admit || !options->execute)) ||
        !options->reserve_upload || !options->release_upload || !options->io_timeout_ms ||
        options->io_timeout_ms > YD_BINARY_TIMEOUT_LIMIT ||
        options->max_body > YD_BINARY_BODY_LIMIT)
        goto invalid;
    YDBinaryRuntime *r = calloc(1, sizeof(*r));
    if (!r)
        goto invalid;
    r->options = *options;
    r->identity_admit = admit;
    r->identity_execute = execute;
    if (!r->options.max_body)
        r->options.max_body = YD_BINARY_BODY_LIMIT;
    r->listener = r->wake[0] = r->wake[1] = -1;
    for (unsigned i = 0; i < SESSIONS; i++)
        r->sessions[i].fd = -1;
    atomic_init(&r->stop, false);
    atomic_init(&r->healthy, true);
    if (pthread_mutex_init(&r->lock, NULL)) {
        free(r);
        goto invalid;
    }
    if (pthread_cond_init(&r->changed, NULL)) {
        pthread_mutex_destroy(&r->lock);
        free(r);
        goto invalid;
    }
    r->listener = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    struct sockaddr_in address = {
        .sin_family = AF_INET, .sin_port = htons(options->port), .sin_addr = options->address};
    socklen_t address_length = sizeof(address);
    if (r->listener < 0 || bind(r->listener, (struct sockaddr *)&address, sizeof(address)) ||
        getsockname(r->listener, (struct sockaddr *)&address, &address_length) ||
        listen(r->listener, 16) || pipe2(r->wake, O_NONBLOCK | O_CLOEXEC))
        goto failed;
    r->port = ntohs(address.sin_port);
    for (; r->worker_count < WORKERS; r->worker_count++)
        if (pthread_create(&r->workers[r->worker_count], NULL, worker, r))
            goto failed;
    if (pthread_create(&r->io, NULL, io_loop, r))
        goto failed;
    r->io_started = true;
    return r;
failed:
    yd_binary_runtime_close(r);
invalid:
    if (error && length)
        snprintf(error, length, "binary runtime configuration or startup failed");
    return NULL;
}
YDBinaryRuntime *yd_binary_runtime_start(const YDBinaryRuntimeOptions *options,
    char *error, size_t length) {
    return start(options, NULL, NULL, error, length);
}
YDBinaryRuntime *yd_binary_runtime_start_with_identity(const YDBinaryRuntimeOptions *options,
    YDBinaryIdentityAdmit admit, YDBinaryIdentityExecute execute, char *error, size_t length) {
    if (!admit || !execute) {
        if (error && length) snprintf(error, length, "binary identity callbacks must both be configured");
        return NULL;
    }
    return start(options, admit, execute, error, length);
}
uint16_t yd_binary_runtime_port(const YDBinaryRuntime *r) { return r ? r->port : 0; }
bool yd_binary_runtime_healthy(const YDBinaryRuntime *r) {
    return r && atomic_load(&r->healthy) && !atomic_load(&r->stop);
}
void yd_binary_runtime_close(YDBinaryRuntime *r) {
    if (!r)
        return;
    atomic_store(&r->stop, true);
    pthread_mutex_lock(&r->lock);
    pthread_cond_broadcast(&r->changed);
    pthread_mutex_unlock(&r->lock);
    if (r->wake[1] >= 0)
        wake_io(r);
    if (r->io_started)
        pthread_join(r->io, NULL);
    pthread_mutex_lock(&r->lock);
    r->io_done = true; /* Also covers partial startup without an I/O thread. */
    for (unsigned i = 0; i < JOBS; i++) {
        Job *j = &r->jobs[i];
        if (j->state == FREE) continue;
        j->detached = j->release_ready = true;
        if (j->state != RUNNING && j->state != FINAL_RUNNING && j->state != FINAL_WAIT) {
            j->state = DONE;
            queue_terminal(r, j);
        }
    }
    pthread_cond_broadcast(&r->changed);
    pthread_mutex_unlock(&r->lock);
    for (unsigned i = 0; i < r->worker_count; i++)
        pthread_join(r->workers[i], NULL);
    for (unsigned i = 0; i < JOBS; i++)
        if (r->jobs[i].state != FREE)
            free_job(r, &r->jobs[i]);
    if (r->listener >= 0)
        close(r->listener);
    if (r->wake[0] >= 0)
        close(r->wake[0]);
    if (r->wake[1] >= 0)
        close(r->wake[1]);
    pthread_cond_destroy(&r->changed);
    pthread_mutex_destroy(&r->lock);
    free(r);
}
