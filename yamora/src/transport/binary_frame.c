#include "binary_frame.h"
#include <string.h>

static uint32_t get32(const unsigned char *p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}
static void put32(unsigned char *p, uint32_t value) {
    p[0] = (unsigned char)(value >> 24);
    p[1] = (unsigned char)(value >> 16);
    p[2] = (unsigned char)(value >> 8);
    p[3] = (unsigned char)value;
}
static bool frame_bound(uint32_t limit) {
    return limit >= YD_BINARY_HELLO_SIZE && limit <= YD_BINARY_FRAME_LIMIT;
}
static bool control(YDBinaryType type) {
    return type != YD_BINARY_REQUEST && type != YD_BINARY_RESPONSE && type != YD_BINARY_DATA;
}
static YDBinaryResult shape(const YDBinaryFrame *f, uint32_t limit) {
    if (!f || !frame_bound(limit) || f->flags || f->type < YD_BINARY_HELLO ||
        f->type > YD_BINARY_GOAWAY) return YD_BINARY_INVALID;
    if (f->length > limit) return YD_BINARY_LIMIT;
    bool connection = f->type == YD_BINARY_HELLO || f->type == YD_BINARY_PING ||
        f->type == YD_BINARY_PONG || f->type == YD_BINARY_GOAWAY;
    if (connection ? f->stream_id != 0 : !(f->stream_id & 1U)) return YD_BINARY_INVALID;
    switch (f->type) {
    case YD_BINARY_HELLO: return f->length == 12 ? YD_BINARY_OK : YD_BINARY_INVALID;
    case YD_BINARY_PING: case YD_BINARY_PONG:
        return f->length == 8 ? YD_BINARY_OK : YD_BINARY_INVALID;
    case YD_BINARY_ERROR: return f->length == 4 ? YD_BINARY_OK : YD_BINARY_INVALID;
    case YD_BINARY_END: case YD_BINARY_CANCEL: case YD_BINARY_GOAWAY:
        return f->length == 0 ? YD_BINARY_OK : YD_BINARY_INVALID;
    default: return f->length ? YD_BINARY_OK : YD_BINARY_INVALID;
    }
}
YDBinaryResult yd_binary_header_encode(const YDBinaryFrame *f, unsigned char h[16]) {
    if (!h) return YD_BINARY_INVALID;
    YDBinaryResult result = shape(f, YD_BINARY_FRAME_LIMIT);
    if (result != YD_BINARY_OK) return result;
    unsigned char header[16] = {'Y', 'M', 'B', 'F', 1, (unsigned char)f->type, 0, 0};
    put32(header + 8, f->stream_id);
    put32(header + 12, f->length);
    memcpy(h, header, sizeof(header));
    return YD_BINARY_OK;
}
YDBinaryResult yd_binary_header_decode(const unsigned char h[16], uint32_t limit,
                                      YDBinaryFrame *out) {
    if (!h || !out || memcmp(h, "YMBF", 4) || h[4] != YD_BINARY_VERSION)
        return YD_BINARY_INVALID;
    YDBinaryFrame f = {.type = (YDBinaryType)h[5],
        .flags = (uint16_t)((unsigned)h[6] << 8 | h[7]),
        .stream_id = get32(h + 8), .length = get32(h + 12)};
    YDBinaryResult result = shape(&f, limit);
    if (result == YD_BINARY_OK) *out = f;
    return result;
}
void yd_binary_hello(unsigned char p[12], uint32_t frame, uint32_t streams) {
    p[0] = p[2] = 0;
    p[1] = p[3] = YD_BINARY_VERSION;
    put32(p + 4, frame);
    put32(p + 8, streams);
}
void yd_binary_hello_protocols(unsigned char p[12], uint32_t frame, uint32_t streams,
    unsigned maximum) {
    yd_binary_hello(p, frame, streams);
    p[3] = (unsigned char)maximum;
}
bool yd_binary_parser_init(YDBinaryParser *p, unsigned char *payload, size_t capacity,
                           uint32_t limit) {
    if (!p || !payload || !frame_bound(limit) || capacity < limit) return false;
    *p = (YDBinaryParser){.payload = payload, .capacity = capacity, .max_frame = limit};
    return true;
}
YDBinaryResult yd_binary_parser_feed(YDBinaryParser *p, const unsigned char *bytes,
    size_t length, size_t *consumed, YDBinaryFrame *out) {
    if (!p || !consumed || !out || (length && !bytes)) return YD_BINARY_INVALID;
    *consumed = 0;
    if (p->error) return p->error;
    if (p->header_used < 16) {
        size_t n = 16 - p->header_used;
        if (n > length) n = length;
        if (n) memcpy(p->header + p->header_used, bytes, n);
        p->header_used += n;
        *consumed += n;
        if (p->header_used < 16) return YD_BINARY_MORE;
        YDBinaryResult result = yd_binary_header_decode(p->header, p->max_frame, &p->current);
        if (result != YD_BINARY_OK) return p->error = result;
    }
    size_t n = p->current.length - p->payload_used;
    if (n > length - *consumed) n = length - *consumed;
    if (n) memcpy(p->payload + p->payload_used, bytes + *consumed, n);
    p->payload_used += n;
    *consumed += n;
    if (p->payload_used < p->current.length) return YD_BINARY_MORE;
    p->current.payload = p->current.length ? p->payload : NULL;
    *out = p->current;
    p->header_used = p->payload_used = 0;
    return YD_BINARY_FRAME;
}
YDBinaryResult yd_binary_parser_finish(YDBinaryParser *p) {
    if (!p) return YD_BINARY_INVALID;
    if (p->error) return p->error;
    if (p->header_used || p->payload_used) return p->error = YD_BINARY_TRUNCATED;
    return YD_BINARY_OK;
}
bool yd_binary_connection_init(YDBinaryConnection *c, bool client, const YDBinaryLimits *l) {
    if (!c || !l || l->max_protocol > 2 || !frame_bound(l->max_frame) || !l->max_streams ||
        l->max_streams > YD_BINARY_STREAM_LIMIT || l->max_message < YD_BINARY_MESSAGE_MIN ||
        l->max_message > YD_BINARY_MESSAGE_LIMIT ||
        l->receive_budget < (uint64_t)l->max_frame + 16 ||
        l->send_budget < (uint64_t)l->max_frame + 16 ||
        l->receive_budget > YD_BINARY_MESSAGE_LIMIT || l->send_budget > YD_BINARY_MESSAGE_LIMIT ||
        l->control_budget < 28 || l->control_budget > YD_BINARY_CONTROL_LIMIT) return false;
    *c = (YDBinaryConnection){.limits = *l, .client = client,
        .max_frame = l->max_frame, .max_streams = l->max_streams};
    return true;
}
bool yd_binary_connection_ready(const YDBinaryConnection *c) {
    return c && c->hello_sent && c->hello_received;
}
static YDBinaryResult hello(YDBinaryConnection *c, bool sending, const YDBinaryFrame *f) {
    if (sending ? c->hello_sent : c->hello_received) return YD_BINARY_INVALID;
    const unsigned char *p = f->payload;
    unsigned minimum = (unsigned)p[0] << 8 | p[1], maximum = (unsigned)p[2] << 8 | p[3];
    uint32_t frame = get32(p + 4), streams = get32(p + 8);
    unsigned supported = c->limits.max_protocol ? c->limits.max_protocol : 1;
    if (!minimum || minimum > maximum || minimum > supported || maximum < 1 ||
        !frame_bound(frame) || !streams || streams > YD_BINARY_STREAM_LIMIT)
        return YD_BINARY_INVALID;
    if (sending) {
        if (minimum != 1 || maximum != supported || frame != c->limits.max_frame ||
            streams != c->limits.max_streams) return YD_BINARY_INVALID;
        c->hello_sent = true;
    } else {
        c->protocol = maximum < supported ? maximum : supported;
        if (frame < c->max_frame) c->max_frame = frame;
        if (streams < c->max_streams) c->max_streams = streams;
        c->hello_received = true;
    }
    return YD_BINARY_OK;
}
static YDBinaryResult transition(YDBinaryConnection *c, bool sending, const YDBinaryFrame *f) {
    if (f->type == YD_BINARY_HELLO) return hello(c, sending, f);
    if (!yd_binary_connection_ready(c)) return YD_BINARY_INVALID;
    if (f->type == YD_BINARY_GOAWAY) {
        if (sending ? c->local_goaway : c->remote_goaway) return YD_BINARY_INVALID;
        if (sending) c->local_goaway = true;
        else c->remote_goaway = true;
        return YD_BINARY_OK;
    }
    if (f->type == YD_BINARY_PING || f->type == YD_BINARY_PONG) return YD_BINARY_OK;
    bool client = sending == c->client;
    YDBinaryStream *s = NULL, *empty = NULL;
    for (uint32_t i = 0; i < c->limits.max_streams; i++) {
        if (c->streams[i].id == f->stream_id) s = &c->streams[i];
        if (!c->streams[i].id && !empty) empty = &c->streams[i];
    }
    if (f->type == YD_BINARY_REQUEST) {
        if (!client || s || f->stream_id <= c->last_stream_id ||
            c->local_goaway || c->remote_goaway) return YD_BINARY_INVALID;
        if (!empty || c->active_streams >= c->max_streams) return YD_BINARY_BACKPRESSURE;
        *empty = (YDBinaryStream){.id = f->stream_id};
        c->last_stream_id = f->stream_id;
        c->active_streams++;
        return YD_BINARY_OK;
    }
    /* A cancel may cross the server's terminal response on the wire. Old IDs
     * cannot be reused, so this bounded no-op cannot affect a newer request. */
    if (!s) return client && f->type == YD_BINARY_CANCEL && f->stream_id <= c->last_stream_id
        ? YD_BINARY_OK : YD_BINARY_INVALID;
    switch (f->type) {
    case YD_BINARY_RESPONSE:
        if (client || s->response_started || s->response_ended || !s->request_ended)
            return YD_BINARY_INVALID;
        s->response_started = true;
        break;
    case YD_BINARY_DATA: {
        if (client ? s->request_ended : (!s->response_started || s->response_ended))
            return YD_BINARY_INVALID;
        uint64_t *total = client ? &s->request_bytes : &s->response_bytes;
        if (*total > c->limits.max_message || f->length > c->limits.max_message - *total)
            return YD_BINARY_LIMIT;
        *total += f->length;
        break;
    }
    case YD_BINARY_END:
        if (client) {
            if (s->request_ended) return YD_BINARY_INVALID;
            s->request_ended = true;
        } else {
            if (s->response_ended || (!s->response_started && !s->cancelled))
                return YD_BINARY_INVALID;
            s->response_ended = true;
        }
        break;
    case YD_BINARY_CANCEL:
        if (!client || s->cancelled) return YD_BINARY_INVALID;
        s->cancelled = s->request_ended = true;
        break;
    case YD_BINARY_ERROR:
        if (client || s->response_ended || !get32(f->payload)) return YD_BINARY_INVALID;
        s->errored = s->response_ended = true;
        break;
    default: return YD_BINARY_INVALID;
    }
    if (s->request_ended && s->response_ended) {
        *s = (YDBinaryStream){0};
        c->active_streams--;
    }
    return YD_BINARY_OK;
}
YDBinaryResult yd_binary_admit(YDBinaryConnection *c, YDBinaryDirection d,
    const YDBinaryFrame *f, YDBinaryTicket *out) {
    if (!c || !out || (d != YD_BINARY_RECEIVE && d != YD_BINARY_SEND)) return YD_BINARY_INVALID;
    /* HELLO always uses the fixed negotiation envelope, even if the peer's
     * advertised minimum frame cap has already reduced the application cap. */
    YDBinaryResult result = shape(f, c->max_frame);
    if (result != YD_BINARY_OK) return result;
    if (f->length && !f->payload) return YD_BINARY_INVALID;
    bool lane = control(f->type);
    uint64_t bytes = (uint64_t)YD_BINARY_HEADER_SIZE + f->length;
    uint64_t budget = lane ? c->limits.control_budget :
        (d == YD_BINARY_SEND ? c->limits.send_budget : c->limits.receive_budget);
    if (c->held[d][lane] > budget || bytes > budget - c->held[d][lane])
        return YD_BINARY_BACKPRESSURE;
    YDBinaryConnection next = *c;
    result = transition(&next, d == YD_BINARY_SEND, f);
    if (result != YD_BINARY_OK) return result;
    next.held[d][lane] += bytes;
    *c = next;
    *out = (YDBinaryTicket){.owner = c, .bytes = bytes, .direction = d, .control = lane};
    return YD_BINARY_OK;
}
YDBinaryResult yd_binary_release(YDBinaryConnection *c, YDBinaryTicket *t) {
    if (!c || !t || t->owner != c || !t->bytes ||
        (t->direction != YD_BINARY_RECEIVE && t->direction != YD_BINARY_SEND) ||
        t->bytes > c->held[t->direction][t->control]) return YD_BINARY_INVALID;
    c->held[t->direction][t->control] -= t->bytes;
    *t = (YDBinaryTicket){0};
    return YD_BINARY_OK;
}
