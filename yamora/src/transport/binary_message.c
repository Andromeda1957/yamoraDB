#include "binary_message.h"
#include <string.h>

#define REQUEST_OPTIONAL 0x01f0U
#define RESPONSE_OPTIONAL 0x0fe0U

typedef struct {
    unsigned char bytes[YD_BINARY_METADATA_LIMIT];
    size_t used;
    uint16_t count;
    bool valid;
} Writer;
typedef struct { const unsigned char *bytes; size_t length; } Field;
typedef struct { size_t maximum, width; } Spec;

static void put(unsigned char *p, uint64_t value, size_t width) {
    while (width) { p[--width] = (unsigned char)value; value >>= 8; }
}
static uint64_t get(const unsigned char *p, size_t width) {
    uint64_t value = 0;
    for (size_t i = 0; i < width; i++) value = (value << 8) | p[i];
    return value;
}
static bool ascii(const unsigned char *p, size_t n) {
    for (size_t i = 0; i < n; i++) if (p[i] < 0x20 || p[i] > 0x7e) return false;
    return true;
}
static bool text_length(const char *p, size_t capacity, size_t *n) {
    const char *end = memchr(p, 0, capacity);
    if (!end) return false;
    *n = (size_t)(end - p);
    return ascii((const unsigned char *)p, *n);
}
/* Keep the existing snapshot.c name profile without linking storage into the
 * pure transport codec. Reserved collections remain an application decision. */
static bool name(const char *p, size_t n) {
    if (!n || n > YD_BINARY_NAME_LIMIT) return false;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)p[i];
        if (!(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') && c != '-') return false;
    }
    return true;
}
static bool target(const char *p) {
    static const char prefix[] = "/v1/collections/", middle[] = "/documents/";
    if (strncmp(p, prefix, sizeof(prefix) - 1)) return false;
    const char *collection = p + sizeof(prefix) - 1;
    const char *slash = strchr(collection, '/');
    if (!slash || !name(collection, (size_t)(slash - collection)) ||
        strncmp(slash, middle, sizeof(middle) - 1)) return false;
    const char *document = slash + sizeof(middle) - 1;
    return name(document, strlen(document));
}
static bool operation_target(const YDBinaryRequestMessage *m) {
    if (target(m->target)) return m->method != YD_BINARY_METHOD_POST;
    if (m->schema != 2) return false;
    if (m->method == YD_BINARY_METHOD_POST) {
        if (!strcmp(m->target, "/v1/transactions")) return true;
        static const char *const prefixes[] = {"/v1/query/", "/v1/aggregate/", "/v1/search/"};
        for (size_t i = 0; i < 3; i++) {
            size_t n = strlen(prefixes[i]);
            if (!strncmp(m->target, prefixes[i], n))
                return name(m->target + n, strlen(m->target + n));
        }
    }
    return m->method == YD_BINARY_METHOD_GET &&
        (!strcmp(m->target, "/v1/changes") || !strncmp(m->target, "/v1/changes?", 12) ||
         !strncmp(m->target, "/v1/changes/stream?", 19));
}
static unsigned char lower(unsigned char c) {
    return c >= 'A' && c <= 'Z' ? (unsigned char)(c + ('a' - 'A')) : c;
}
static bool yaml_type(const char *p, size_t n) {
    static const char *const types[] = {"application/yaml", "text/yaml"};
    size_t base = 0;
    while (base < n && p[base] != ';') base++;
    for (size_t t = 0; t < sizeof(types) / sizeof(types[0]); t++) {
        if (base != strlen(types[t])) continue;
        size_t i = 0;
        while (i < base && lower((unsigned char)p[i]) == (unsigned char)types[t][i]) i++;
        if (i == base) return true;
    }
    return false;
}
static bool json_type(const char *p, size_t n) {
    static const char expected[] = "application/json";
    size_t base = 0;
    while (base < n && p[base] != ';') base++;
    if (base != sizeof(expected) - 1) return false;
    for (size_t i = 0; i < base; i++)
        if (lower((unsigned char)p[i]) != (unsigned char)expected[i]) return false;
    return true;
}
static bool hex(const char *p, size_t n) {
    for (size_t i = 0; i < n; i++)
        if (!(p[i] >= '0' && p[i] <= '9') && !(p[i] >= 'a' && p[i] <= 'f')) return false;
    return true;
}
static bool nonzero_id(const unsigned char *p) {
    unsigned char value = 0;
    for (size_t i = 0; i < 16; i++) value |= p[i];
    return value != 0;
}
static void field(Writer *w, unsigned id, const void *p, size_t n) {
    if (!w->valid || w->used > YD_BINARY_METADATA_LIMIT - 4 ||
        n > YD_BINARY_METADATA_LIMIT - 4 - w->used) { w->valid = false; return; }
    put(w->bytes + w->used, id, 2);
    put(w->bytes + w->used + 2, n, 2);
    if (n) memcpy(w->bytes + w->used + 4, p, n);
    w->used += 4 + n;
    w->count++;
}
static void number(Writer *w, unsigned id, uint64_t value, size_t width) {
    unsigned char bytes[8];
    put(bytes, value, width);
    field(w, id, bytes, width);
}
static bool text(Writer *w, unsigned id, const char *p, size_t capacity, size_t *n) {
    if (!text_length(p, capacity, n)) return false;
    field(w, id, p, *n);
    return w->valid;
}
static bool finish(Writer *w, unsigned schema) {
    if (!w->valid) return false;
    put(w->bytes, schema == 2 ? 2 : YD_BINARY_MESSAGE_SCHEMA, 2);
    put(w->bytes + 2, w->count, 2);
    return true;
}
static bool build_request(const YDBinaryRequestMessage *m, Writer *w) {
    *w = (Writer){.used = 4, .valid = true};
    if ((m->schema && m->schema != 2) || m->method < YD_BINARY_METHOD_GET ||
        m->method > (m->schema == 2 ? YD_BINARY_METHOD_PATCH : YD_BINARY_METHOD_DELETE) ||
        (m->present & ~REQUEST_OPTIONAL) || m->body_length > YD_BINARY_BODY_LIMIT) return false;
    number(w, 1, m->method, 1);
    size_t n;
    if (!text(w, 2, m->target, sizeof(m->target), &n) || !operation_target(m) ||
        !text(w, 3, m->content_type, sizeof(m->content_type), &n)) return false;
    if (m->method == YD_BINARY_METHOD_PUT || m->method == YD_BINARY_METHOD_POST ||
        m->method == YD_BINARY_METHOD_PATCH) {
        bool json = m->schema == 2 && m->method != YD_BINARY_METHOD_PUT &&
            json_type(m->content_type, n);
        if (!yaml_type(m->content_type, n) && !json) return false;
    } else if (n || m->body_length) return false;
    number(w, 4, m->body_length, 8);
    if (m->present & YD_BINARY_REQUEST_AUTHORIZATION) {
        if (!text(w, 5, m->authorization, sizeof(m->authorization), &n) ||
            n <= 7 || memcmp(m->authorization, "Bearer ", 7)) return false;
        for (size_t i = 7; i < n; i++) if (m->authorization[i] == ' ') return false;
    }
    if ((m->present & YD_BINARY_REQUEST_IF_MATCH) &&
        !text(w, 6, m->if_match, sizeof(m->if_match), &n)) return false;
    if ((m->present & YD_BINARY_REQUEST_IF_NONE_MATCH) &&
        !text(w, 7, m->if_none_match, sizeof(m->if_none_match), &n)) return false;
    if (m->present & YD_BINARY_REQUEST_ID) {
        if (!nonzero_id(m->request_id)) return false;
        field(w, 8, m->request_id, 16);
    }
    if (m->present & YD_BINARY_REQUEST_TIMEOUT) {
        if (!m->timeout_ms || m->timeout_ms > YD_BINARY_TIMEOUT_LIMIT) return false;
        number(w, 9, m->timeout_ms, 4);
    }
    return finish(w, m->schema);
}
static bool build_response(const YDBinaryResponseMessage *m, Writer *w) {
    *w = (Writer){.used = 4, .valid = true};
    if ((m->schema && m->schema != 2) ||
        (m->streaming && (m->schema != 2 || m->status != 200 || m->body_length ||
                          m->representation_length)) ||
        m->status < 200 || m->status > 599 || (m->present & ~RESPONSE_OPTIONAL) ||
        m->body_length > YD_BINARY_BODY_LIMIT || m->representation_length > YD_BINARY_BODY_LIMIT ||
        (m->body_length && m->body_length != m->representation_length) ||
        (m->status == 204 && (m->body_length || m->representation_length)) ||
        (m->status == 304 && m->body_length)) return false;
    number(w, 1, m->status, 2);
    size_t n;
    if (!text(w, 2, m->content_type, sizeof(m->content_type), &n) || !n) return false;
    number(w, 3, m->body_length, 8);
    number(w, 4, m->representation_length, 8);
    if (!text(w, 5, m->revision, sizeof(m->revision), &n) || n != 16 || !hex(m->revision, 16))
        return false;
    if (m->present & YD_BINARY_RESPONSE_ETAG) {
        if (!text(w, 6, m->etag, sizeof(m->etag), &n) || n != 18 ||
            m->etag[0] != '"' || m->etag[17] != '"' || !hex(m->etag + 1, 16)) return false;
    }
    if ((m->present & YD_BINARY_RESPONSE_COLLECTION) &&
        (!text(w, 7, m->collection, sizeof(m->collection), &n) || !name(m->collection, n)))
        return false;
    if ((m->present & YD_BINARY_RESPONSE_DOCUMENT) &&
        (!text(w, 8, m->document, sizeof(m->document), &n) || !name(m->document, n))) return false;
    if (m->present & YD_BINARY_RESPONSE_ALLOW) {
        if (!m->allow || (m->allow & ~(m->schema == 2 ? 63U : YD_BINARY_ALLOW_ALL))) return false;
        number(w, 9, m->allow, 1);
    }
    if (m->present & YD_BINARY_RESPONSE_AUTHENTICATE) {
        if (m->authenticate != YD_BINARY_AUTHENTICATE_BEARER) return false;
        number(w, 10, m->authenticate, 1);
    }
    if (m->present & YD_BINARY_RESPONSE_RETRY_AFTER) number(w, 11, m->retry_after_seconds, 4);
    if (m->present & YD_BINARY_RESPONSE_ID) {
        if (!nonzero_id(m->request_id)) return false;
        field(w, 12, m->request_id, 16);
    }
    if (m->schema == 2) number(w, 13, m->streaming, 1);
    return finish(w, m->schema);
}

/* Integer address comparisons avoid undefined relational comparisons between
 * unrelated objects. Callers still provide real objects of the stated extent. */
static bool extent(const void *p, size_t n) {
    return p && n <= UINTPTR_MAX - (uintptr_t)p;
}
static bool overlap(const void *a, size_t an, const void *b, size_t bn) {
    if (!an || !bn) return false;
    uintptr_t av = (uintptr_t)a, bv = (uintptr_t)b;
    return av <= bv ? bv - av < an : av - bv < bn;
}
static bool size_arguments(const void *m, size_t n, const size_t *length) {
    return extent(m, n) && extent(length, sizeof(*length)) &&
        !overlap(m, n, length, sizeof(*length));
}
static bool encode_arguments(const void *m, size_t n, unsigned char *bytes,
                             size_t capacity, const size_t *length) {
    return size_arguments(m, n, length) && extent(bytes, capacity) &&
        !overlap(length, sizeof(*length), bytes, capacity);
}
bool yd_binary_request_message_size(const YDBinaryRequestMessage *m, size_t *length) {
    Writer w;
    if (!size_arguments(m, sizeof(*m), length) || !build_request(m, &w)) return false;
    *length = w.used;
    return true;
}
bool yd_binary_request_message_encode(const YDBinaryRequestMessage *m,
    unsigned char *bytes, size_t capacity, size_t *length) {
    Writer w;
    if (!encode_arguments(m, sizeof(*m), bytes, capacity, length) ||
        !build_request(m, &w) || capacity < w.used) return false;
    memcpy(bytes, w.bytes, w.used);
    *length = w.used;
    return true;
}
bool yd_binary_response_message_size(const YDBinaryResponseMessage *m, size_t *length) {
    Writer w;
    if (!size_arguments(m, sizeof(*m), length) || !build_response(m, &w)) return false;
    *length = w.used;
    return true;
}
bool yd_binary_response_message_encode(const YDBinaryResponseMessage *m,
    unsigned char *bytes, size_t capacity, size_t *length) {
    Writer w;
    if (!encode_arguments(m, sizeof(*m), bytes, capacity, length) ||
        !build_response(m, &w) || capacity < w.used) return false;
    memcpy(bytes, w.bytes, w.used);
    *length = w.used;
    return true;
}
static bool scan(const unsigned char *bytes, size_t length, const Spec *spec,
                 unsigned max_id, unsigned required, Field *fields, uint16_t *seen) {
    if (!bytes || length < 4 || length > YD_BINARY_METADATA_LIMIT ||
        (get(bytes, 2) != YD_BINARY_MESSAGE_SCHEMA && get(bytes, 2) != 2)) return false;
    unsigned count = (unsigned)get(bytes + 2, 2), previous = 0;
    if (count < required || count > max_id) return false;
    size_t at = 4;
    for (unsigned i = 0; i < count; i++) {
        if (length - at < 4) return false;
        unsigned id = (unsigned)get(bytes + at, 2);
        size_t n = (size_t)get(bytes + at + 2, 2);
        at += 4;
        if (!id || id <= previous || id > max_id || n > length - at ||
            n > spec[id].maximum || (spec[id].width && n != spec[id].width)) return false;
        fields[id] = (Field){bytes + at, n};
        *seen |= (uint16_t)(1U << (id - 1));
        previous = id;
        at += n;
    }
    unsigned required_mask = (1U << required) - 1;
    return at == length && (*seen & required_mask) == required_mask;
}
static bool copy_text(char *out, size_t capacity, const Field *f) {
    if (f->length >= capacity || !ascii(f->bytes, f->length)) return false;
    if (f->length) memcpy(out, f->bytes, f->length);
    out[f->length] = 0;
    return true;
}
bool yd_binary_request_message_decode(const unsigned char *bytes, size_t length,
    YDBinaryRequestMessage *out) {
    static const Spec spec[] = {
        {0, 0}, {1, 1}, {1024, 0}, {95, 0}, {8, 8}, {519, 0},
        {31, 0}, {31, 0}, {16, 16}, {4, 4}
    };
    if (!out) return false;
    YDBinaryRequestMessage m;
    memset(&m, 0, sizeof(m));
    Field fields[10] = {{0}};
    uint16_t seen = 0;
    Writer w;
    if (!scan(bytes, length, spec, 9, 4, fields, &seen)) goto bad;
    m.schema = get(bytes, 2) == 2 ? 2 : 0;
    m.present = seen & REQUEST_OPTIONAL;
    m.method = (YDBinaryMethod)get(fields[1].bytes, 1);
    m.body_length = get(fields[4].bytes, 8);
    if (!copy_text(m.target, sizeof(m.target), &fields[2]) ||
        !copy_text(m.content_type, sizeof(m.content_type), &fields[3]) ||
        !copy_text(m.authorization, sizeof(m.authorization), &fields[5]) ||
        !copy_text(m.if_match, sizeof(m.if_match), &fields[6]) ||
        !copy_text(m.if_none_match, sizeof(m.if_none_match), &fields[7])) goto bad;
    if (m.present & YD_BINARY_REQUEST_ID) memcpy(m.request_id, fields[8].bytes, 16);
    m.timeout_ms = m.present & YD_BINARY_REQUEST_TIMEOUT ?
        (uint32_t)get(fields[9].bytes, 4) : YD_BINARY_TIMEOUT_DEFAULT;
    if (!build_request(&m, &w)) goto bad;
    memcpy(out, &m, sizeof(m));
    return true;
bad:
    memset(out, 0, sizeof(*out));
    return false;
}
bool yd_binary_response_message_decode(const unsigned char *bytes, size_t length,
    YDBinaryResponseMessage *out) {
    static const Spec spec[] = {
        {0, 0}, {2, 2}, {95, 0}, {8, 8}, {8, 8}, {16, 16}, {18, 18},
        {128, 0}, {128, 0}, {1, 1}, {1, 1}, {4, 4}, {16, 16}, {1, 1}
    };
    if (!out) return false;
    YDBinaryResponseMessage m;
    memset(&m, 0, sizeof(m));
    Field fields[14] = {{0}};
    uint16_t seen = 0;
    Writer w;
    unsigned schema = bytes && length >= 4 ? (unsigned)get(bytes, 2) : 0;
    if (!scan(bytes, length, spec, schema == 2 ? 13 : 12, 5, fields, &seen)) goto bad;
    if (schema == 2) {
        if (!(seen & (1U << 12)) || get(fields[13].bytes, 1) > 1) goto bad;
        m.schema = 2;
        m.streaming = get(fields[13].bytes, 1) != 0;
    }
    m.present = seen & RESPONSE_OPTIONAL;
    m.status = (uint16_t)get(fields[1].bytes, 2);
    m.body_length = get(fields[3].bytes, 8);
    m.representation_length = get(fields[4].bytes, 8);
    if (!copy_text(m.content_type, sizeof(m.content_type), &fields[2]) ||
        !copy_text(m.revision, sizeof(m.revision), &fields[5]) ||
        !copy_text(m.etag, sizeof(m.etag), &fields[6]) ||
        !copy_text(m.collection, sizeof(m.collection), &fields[7]) ||
        !copy_text(m.document, sizeof(m.document), &fields[8])) goto bad;
    if (m.present & YD_BINARY_RESPONSE_ALLOW) m.allow = (uint8_t)get(fields[9].bytes, 1);
    if (m.present & YD_BINARY_RESPONSE_AUTHENTICATE)
        m.authenticate = (uint8_t)get(fields[10].bytes, 1);
    if (m.present & YD_BINARY_RESPONSE_RETRY_AFTER)
        m.retry_after_seconds = (uint32_t)get(fields[11].bytes, 4);
    if (m.present & YD_BINARY_RESPONSE_ID) memcpy(m.request_id, fields[12].bytes, 16);
    if (!build_response(&m, &w)) goto bad;
    memcpy(out, &m, sizeof(m));
    return true;
bad:
    memset(out, 0, sizeof(*out));
    return false;
}
