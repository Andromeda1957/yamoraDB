#include "../src/transport/binary_message.h"
#include <pthread.h>
#include <stdio.h>
#include <string.h>

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "FAIL %s:%d: %s\n", __func__, __LINE__, #condition); \
    return false; } } while (0)
#define SIZE(bytes) (sizeof(bytes) - 1U)

/* Independent wire fixtures: these bytes are not produced by the encoder.
 * Minimal GET: schema=1/count=4, target length=29, empty type, zero body.
 * Full PUT: all nine fields, three DATA bytes, opaque BOTH conditions.
 * Full response: all twelve fields, native quoted ETag and revision formats.
 * Kept as literal concatenated bytes for cross-language conformance. */
static const unsigned char get_wire[] =
    "\x00\x01\x00\x04"
    "\x00\x01\x00\x01\x01"
    "\x00\x02\x00\x1d" "/v1/collections/a/documents/b"
    "\x00\x03\x00\x00"
    "\x00\x04\x00\x08" "\x00\x00\x00\x00\x00\x00\x00\x00";
static const unsigned char put_wire[] =
    "\x00\x01\x00\x09"
    "\x00\x01\x00\x01\x03"
    "\x00\x02\x00\x1d" "/v1/collections/a/documents/b"
    "\x00\x03\x00\x10" "application/yaml"
    "\x00\x04\x00\x08" "\x00\x00\x00\x00\x00\x00\x00\x03"
    "\x00\x05\x00\x11" "Bearer test-token"
    "\x00\x06\x00\x12" "\"0123456789abcdef\""
    "\x00\x07\x00\x01" "*"
    "\x00\x08\x00\x10" "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
    "\x00\x09\x00\x04" "\x00\x00\x05\xdc";
static const unsigned char response_wire[] =
    "\x00\x01\x00\x0c"
    "\x00\x01\x00\x02\x00\xc8"
    "\x00\x02\x00\x1f" "application/yaml; charset=utf-8"
    "\x00\x03\x00\x08" "\x00\x00\x00\x00\x00\x00\x00\x03"
    "\x00\x04\x00\x08" "\x00\x00\x00\x00\x00\x00\x00\x03"
    "\x00\x05\x00\x10" "0123456789abcdef"
    "\x00\x06\x00\x12" "\"0123456789abcdef\""
    "\x00\x07\x00\x01" "a"
    "\x00\x08\x00\x01" "b"
    "\x00\x09\x00\x01\x0f"
    "\x00\x0a\x00\x01\x01"
    "\x00\x0b\x00\x04\x00\x00\x00\x01"
    "\x00\x0c\x00\x10" "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10";

static bool zero(const void *value, size_t length) {
    const unsigned char *p = value;
    for (size_t i = 0; i < length; i++) if (p[i]) return false;
    return true;
}
static YDBinaryRequestMessage get_message(void) {
    YDBinaryRequestMessage m;
    memset(&m, 0, sizeof(m));
    m.method = YD_BINARY_METHOD_GET;
    strcpy(m.target, "/v1/collections/a/documents/b");
    m.timeout_ms = YD_BINARY_TIMEOUT_DEFAULT;
    return m;
}
static YDBinaryRequestMessage put_message(void) {
    YDBinaryRequestMessage m = get_message();
    m.method = YD_BINARY_METHOD_PUT;
    m.present = 0x1f0;
    strcpy(m.content_type, "application/yaml");
    m.body_length = 3;
    strcpy(m.authorization, "Bearer test-token");
    strcpy(m.if_match, "\"0123456789abcdef\"");
    strcpy(m.if_none_match, "*");
    for (unsigned i = 0; i < 16; i++) m.request_id[i] = (unsigned char)(i + 1);
    m.timeout_ms = 1500;
    return m;
}
static YDBinaryResponseMessage response_message(void) {
    YDBinaryResponseMessage m;
    memset(&m, 0, sizeof(m));
    m.status = 200;
    m.present = 0xfe0;
    strcpy(m.content_type, "application/yaml; charset=utf-8");
    m.body_length = m.representation_length = 3;
    strcpy(m.revision, "0123456789abcdef");
    strcpy(m.etag, "\"0123456789abcdef\"");
    strcpy(m.collection, "a"); strcpy(m.document, "b");
    m.allow = YD_BINARY_ALLOW_ALL;
    m.authenticate = YD_BINARY_AUTHENTICATE_BEARER;
    m.retry_after_seconds = 1;
    for (unsigned i = 0; i < 16; i++) m.request_id[i] = (unsigned char)(i + 1);
    return m;
}
static bool golden(void) {
    unsigned char bytes[YD_BINARY_METADATA_LIMIT];
    size_t n = 999, measured = 999;
    YDBinaryRequestMessage request, expected = get_message();
    CHECK(SIZE(get_wire) == 58 && SIZE(put_wire) == 150 && SIZE(response_wire) == 159);
    CHECK(yd_binary_request_message_decode(get_wire, SIZE(get_wire), &request));
    CHECK(request.method == expected.method && request.present == 0);
    CHECK(!strcmp(request.target, expected.target) && !request.content_type[0]);
    CHECK(request.body_length == 0 && request.timeout_ms == 30000);
    CHECK(zero(request.authorization, sizeof(request.authorization)));
    CHECK(zero(request.if_match, sizeof(request.if_match)));
    CHECK(zero(request.if_none_match, sizeof(request.if_none_match)));
    CHECK(zero(request.request_id, sizeof(request.request_id)));
    CHECK(yd_binary_request_message_size(&expected, &measured) && measured == SIZE(get_wire));
    CHECK(yd_binary_request_message_encode(&expected, bytes, sizeof(bytes), &n));
    CHECK(n == SIZE(get_wire) && !memcmp(bytes, get_wire, n));
    expected = put_message();
    CHECK(yd_binary_request_message_decode(put_wire, SIZE(put_wire), &request));
    CHECK(request.method == expected.method && request.present == expected.present);
    CHECK(!strcmp(request.content_type, expected.content_type) && request.body_length == 3);
    CHECK(!strcmp(request.authorization, expected.authorization));
    CHECK(!strcmp(request.if_match, expected.if_match));
    CHECK(!strcmp(request.if_none_match, "*") && request.timeout_ms == 1500);
    CHECK(!memcmp(request.request_id, expected.request_id, 16));
    CHECK(yd_binary_request_message_size(&expected, &measured) && measured == SIZE(put_wire));
    CHECK(yd_binary_request_message_encode(&expected, bytes, sizeof(bytes), &n));
    CHECK(n == SIZE(put_wire) && !memcmp(bytes, put_wire, n));
    YDBinaryResponseMessage response, want = response_message();
    CHECK(yd_binary_response_message_decode(response_wire, SIZE(response_wire), &response));
    CHECK(response.status == 200 && response.present == want.present);
    CHECK(response.body_length == 3 && response.representation_length == 3);
    CHECK(!strcmp(response.content_type, want.content_type));
    CHECK(!strcmp(response.revision, want.revision) && !strcmp(response.etag, want.etag));
    CHECK(!strcmp(response.collection, "a") && !strcmp(response.document, "b"));
    CHECK(response.allow == 15 && response.authenticate == 1 && response.retry_after_seconds == 1);
    CHECK(!memcmp(response.request_id, want.request_id, 16));
    CHECK(yd_binary_response_message_size(&want, &measured) && measured == SIZE(response_wire));
    CHECK(yd_binary_response_message_encode(&want, bytes, sizeof(bytes), &n));
    CHECK(n == SIZE(response_wire) && !memcmp(bytes, response_wire, n));
    want.present = 0;
    /* Unflagged storage is ignored, even if invalid or unterminated. */
    memset(want.etag, 0xff, sizeof(want.etag)); want.authenticate = 99;
    CHECK(yd_binary_response_message_encode(&want, bytes, sizeof(bytes), &n));
    CHECK(yd_binary_response_message_decode(bytes, n, &response));
    CHECK(response.present == 0 && !response.allow && !response.authenticate);
    CHECK(!response.retry_after_seconds && zero(response.etag, sizeof(response.etag)));
    CHECK(zero(response.collection, sizeof(response.collection)));
    CHECK(zero(response.document, sizeof(response.document)));
    CHECK(zero(response.request_id, sizeof(response.request_id)));
    return true;
}

/* A test-side TLV builder operates on literal fixtures; never calls the codec.
 * Replacement/deletion lets each width/required/type check fail independently. */
typedef struct { unsigned char bytes[4096]; size_t size; } Wire;
static unsigned u16(const unsigned char *p) { return (unsigned)p[0] * 256 + p[1]; }
static Wire change(const unsigned char *p, size_t n, unsigned id,
                   const unsigned char *value, size_t length, bool remove) {
    Wire w = {{0}, 4};
    memcpy(w.bytes, p, 4);
    for (size_t at = 4; at < n;) {
        size_t size = u16(p + at + 2), total = 4 + size;
        if (u16(p + at) == id) {
            if (remove) { w.bytes[3]--; at += total; continue; }
            memcpy(w.bytes + w.size, p + at, 2);
            w.bytes[w.size + 2] = (unsigned char)(length >> 8);
            w.bytes[w.size + 3] = (unsigned char)length;
            if (length) memcpy(w.bytes + w.size + 4, value, length);
            w.size += 4 + length;
        } else { memcpy(w.bytes + w.size, p + at, total); w.size += total; }
        at += total;
    }
    return w;
}
static bool rejected(const unsigned char *p, size_t n, bool response) {
    if (response) {
        YDBinaryResponseMessage out; memset(&out, 0xa5, sizeof(out));
        CHECK(!yd_binary_response_message_decode(p, n, &out));
        CHECK(zero(&out, sizeof(out)));
    } else {
        YDBinaryRequestMessage out; memset(&out, 0xa5, sizeof(out));
        CHECK(!yd_binary_request_message_decode(p, n, &out));
        CHECK(zero(&out, sizeof(out)));
    }
    return true;
}
static bool malformed(void) {
    static const size_t request_widths[] = {1, 0, 0, 8, 0, 0, 0, 16, 4};
    static const size_t response_widths[] = {2, 0, 8, 8, 16, 18, 0, 0, 1, 1, 4, 16};
    unsigned char data[2200]; memset(data, 'x', sizeof(data));
    const unsigned char *wires[] = {put_wire, response_wire};
    const size_t sizes[] = {SIZE(put_wire), SIZE(response_wire)};
    for (unsigned direction = 0; direction < 2; direction++) {
        const unsigned char *p = wires[direction]; size_t n = sizes[direction];
        unsigned required = direction ? 5 : 4, fields = direction ? 12 : 9;
        const size_t *widths = direction ? response_widths : request_widths;
        for (size_t cut = 0; cut < n; cut++) CHECK(rejected(p, cut, direction != 0));
        CHECK(rejected(NULL, 0, direction != 0));
        CHECK(rejected(NULL, SIZE_MAX, direction != 0));
        CHECK(rejected(p, SIZE_MAX, direction != 0));
        CHECK(rejected(p, 2049, direction != 0));
        for (unsigned id = 1; id <= required; id++) {
            Wire w = change(p, n, id, NULL, 0, true);
            CHECK(rejected(w.bytes, w.size, direction != 0));
        }
        for (unsigned id = 1; id <= fields; id++) {
            if (widths[id - 1]) for (size_t width = 0; width <= 20; width++) {
                if (width == widths[id - 1]) continue;
                Wire w = change(p, n, id, data, width, false);
                CHECK(rejected(w.bytes, w.size, direction != 0));
            }
        }
        Wire w = change(p, n, 2, data, direction ? 96 : 1025, false);
        CHECK(rejected(w.bytes, w.size, direction != 0));
        memcpy(data, p, n); data[n] = 0;
        CHECK(rejected(data, n + 1, direction != 0));
        memcpy(data, p, n); data[1] = 3;
        CHECK(rejected(data, n, direction != 0));
        data[1] = 1; data[0] = 1;
        CHECK(rejected(data, n, direction != 0));
        for (unsigned count = 0; count < 256; count++) {
            if (count == fields) continue;
            memcpy(data, p, n); data[3] = (unsigned char)count;
            CHECK(rejected(data, n, direction != 0));
        }
        memcpy(data, p, n); data[2] = data[3] = 255;
        CHECK(rejected(data, n, direction != 0));
        for (unsigned bad = 0; bad <= 13; bad++) {
            if (bad == 1) continue;
            memcpy(data, p, n); data[5] = (unsigned char)bad;
            CHECK(rejected(data, n, direction != 0));
        }
        memcpy(data, p, n); data[4] = data[5] = 255;
        CHECK(rejected(data, n, direction != 0));
        /* Duplicate the final optional TLV and adjust count. */
        size_t last = n - (direction ? 20 : 8);
        memcpy(data, p, n); memcpy(data + n, p + last, n - last); data[3]++;
        CHECK(rejected(data, n + n - last, direction != 0));
        /* Order violation with two otherwise valid mandatory TLVs. */
        size_t first = direction ? 6 : 5, second = 4 + u16(p + 4 + first + 2);
        memcpy(data, p, 4); memcpy(data + 4, p + 4 + first, second);
        memcpy(data + 4 + second, p + 4, first);
        memcpy(data + 4 + first + second, p + 4 + first + second, n - 4 - first - second);
        CHECK(rejected(data, n, direction != 0));
        /* Hostile declared TLV length must never read past the payload. */
        memcpy(data, p, n); data[6] = data[7] = 255;
        CHECK(rejected(data, n, direction != 0));
    }
    /* Every ASCII control, DEL, high byte and embedded NUL is rejected in text. */
    const unsigned request_text[] = {2, 3, 5, 6, 7};
    const unsigned response_text[] = {2, 5, 6, 7, 8};
    for (unsigned direction = 0; direction < 2; direction++) {
        const unsigned *ids = direction ? response_text : request_text;
        for (size_t i = 0; i < 5; i++) for (unsigned byte = 0; byte < 256; byte++) {
            if (byte >= 32 && byte <= 126) continue;
            const unsigned char *p = wires[direction];
            size_t at = 4;
            while (u16(p + at) != ids[i]) at += 4 + u16(p + at + 2);
            size_t width = u16(p + at + 2);
            memcpy(data, p + at + 4, width); data[width / 2] = (unsigned char)byte;
            Wire w = change(p, sizes[direction], ids[i], data, width, false);
            CHECK(rejected(w.bytes, w.size, direction != 0));
        }
    }
    return true;
}

static bool request_bad(YDBinaryRequestMessage m) {
    unsigned char out[2048], before[2048]; memset(out, 0xa5, sizeof(out));
    memcpy(before, out, sizeof(out)); size_t n = 987;
    CHECK(!yd_binary_request_message_size(&m, &n) && n == 987);
    CHECK(!yd_binary_request_message_encode(&m, out, sizeof(out), &n));
    CHECK(n == 987 && !memcmp(out, before, sizeof(out)));
    return true;
}
static bool response_bad(YDBinaryResponseMessage m) {
    unsigned char out[2048], before[2048]; memset(out, 0xa5, sizeof(out));
    memcpy(before, out, sizeof(out)); size_t n = 987;
    CHECK(!yd_binary_response_message_size(&m, &n) && n == 987);
    CHECK(!yd_binary_response_message_encode(&m, out, sizeof(out), &n));
    CHECK(n == 987 && !memcmp(out, before, sizeof(out)));
    return true;
}
static bool validators(void) {
    YDBinaryRequestMessage r = get_message(), got;
    YDBinaryResponseMessage s = response_message(), decoded;
    unsigned char bytes[2048]; size_t n;
    const char *bad_paths[] = {"", "/v1/collections/a/documents", "/v1/collections/a/documents/",
        "/v1/collections//documents/b", "/v1/collections/A/documents/b",
        "/v1/collections/a/documents/B", "/v1/collections/a/documents/b?x=1",
        "/v1/collections/a/documents/b#f", "/v1/collections/a/documents/../b",
        "/v1/collections/a/documents/b/", "/v1/collections/a/documents/%62",
        "https://host/v1/collections/a/documents/b", "/v1/collections/a/documents/b_b",
        "/v1/collections/a/documents/b.c", "/v1/collections/a/documents/b\\c"};
    for (size_t i = 0; i < sizeof(bad_paths)/sizeof(*bad_paths); i++) {
        strcpy(r.target, bad_paths[i]); CHECK(request_bad(r));
        Wire w = change(get_wire, SIZE(get_wire), 2,
            (const unsigned char *)bad_paths[i], strlen(bad_paths[i]), false);
        CHECK(rejected(w.bytes, w.size, false));
    }
    r = get_message();
    for (int method = -1; method <= 256; method++) {
        if (method >= 1 && method <= 4) continue;
        r.method = (YDBinaryMethod)method; CHECK(request_bad(r));
        if (method >= 0 && method <= 255) {
            unsigned char value = (unsigned char)method;
            Wire w = change(get_wire, SIZE(get_wire), 1, &value, 1, false);
            CHECK(rejected(w.bytes, w.size, false));
        }
    }
    for (unsigned method = 1; method <= 4; method++) {
        r = get_message(); r.method = (YDBinaryMethod)method;
        if (method == 3) strcpy(r.content_type, "application/yaml");
        CHECK(yd_binary_request_message_encode(&r, bytes, sizeof(bytes), &n));
        CHECK(yd_binary_request_message_decode(bytes, n, &got) && got.method == r.method);
        if (method != 3) {
            r.body_length = 1; CHECK(request_bad(r)); r.body_length = 0;
            strcpy(r.content_type, "application/yaml"); CHECK(request_bad(r));
        }
    }
    const char *types[] = {"application/yaml", "text/yaml", "APPLICATION/YAML;charset=utf-8", "Text/Yaml;"};
    for (size_t i = 0; i < sizeof(types)/sizeof(*types); i++) {
        r = put_message(); strcpy(r.content_type, types[i]);
        CHECK(yd_binary_request_message_encode(&r, bytes, sizeof(bytes), &n));
    }
    const char *bad_types[] = {"", "application/json", "application/yamlx", "application/yaml ;x", " text/yaml"};
    for (size_t i = 0; i < sizeof(bad_types)/sizeof(*bad_types); i++) {
        r = put_message(); strcpy(r.content_type, bad_types[i]); CHECK(request_bad(r));
        Wire w = change(put_wire, SIZE(put_wire), 3,
            (const unsigned char *)bad_types[i], strlen(bad_types[i]), false);
        CHECK(rejected(w.bytes, w.size, false));
    }
    const char *bad_auth[] = {"", "Bearer ", "bearer token", "Basic token", "Bearer a b", "Bearer\ttoken"};
    for (size_t i = 0; i < sizeof(bad_auth)/sizeof(*bad_auth); i++) {
        r = put_message(); strcpy(r.authorization, bad_auth[i]); CHECK(request_bad(r));
        Wire w = change(put_wire, SIZE(put_wire), 5,
            (const unsigned char *)bad_auth[i], strlen(bad_auth[i]), false);
        CHECK(rejected(w.bytes, w.size, false));
    }
    r = put_message(); r.timeout_ms = 0; CHECK(request_bad(r));
    r.timeout_ms = 30001; CHECK(request_bad(r)); r.timeout_ms = UINT32_MAX; CHECK(request_bad(r));
    r = put_message(); memset(r.request_id, 0, 16); CHECK(request_bad(r));
    s = response_message(); memset(s.request_id, 0, 16); CHECK(response_bad(s));
    unsigned char zeros[16] = {0};
    Wire w = change(put_wire, SIZE(put_wire), 8, zeros, 16, false);
    CHECK(rejected(w.bytes, w.size, false));
    w = change(response_wire, SIZE(response_wire), 12, zeros, 16, false);
    CHECK(rejected(w.bytes, w.size, true));
    for (unsigned bit = 0; bit < 16; bit++) {
        if (!(0x1f0 & (1U << bit))) { r = get_message(); r.present = (uint16_t)(1U << bit); CHECK(request_bad(r)); }
        if (!(0xfe0 & (1U << bit))) { s = response_message(); s.present |= (uint16_t)(1U << bit); CHECK(response_bad(s)); }
    }
    for (unsigned status = 0; status <= 65535; status++) {
        s = response_message(); s.status = (uint16_t)status;
        if (status < 200 || status > 599 || status == 204 || status == 304) CHECK(response_bad(s));
        else CHECK(yd_binary_response_message_encode(&s, bytes, sizeof(bytes), &n));
    }
    s = response_message(); s.status = 204; s.body_length = s.representation_length = 0;
    CHECK(yd_binary_response_message_encode(&s, bytes, sizeof(bytes), &n));
    s.representation_length = 1; CHECK(response_bad(s));
    s = response_message(); s.status = 304; s.body_length = 0;
    CHECK(yd_binary_response_message_encode(&s, bytes, sizeof(bytes), &n));
    s = response_message(); s.body_length = 0;
    CHECK(yd_binary_response_message_encode(&s, bytes, sizeof(bytes), &n));
    CHECK(yd_binary_response_message_decode(bytes, n, &decoded) && decoded.representation_length == 3);
    s.body_length = 1; CHECK(response_bad(s)); s.body_length = 4; CHECK(response_bad(s));
    const char *bad_etags[] = {"0123456789abcdef", "ETag: \"0123456789abcdef\"", "\"0123456789abcdeF\"",
        "\"0123456789abcdeg\"", "x0123456789abcdefx", "'0123456789abcdef'", "*", ""};
    for (size_t i = 0; i < sizeof(bad_etags)/sizeof(*bad_etags); i++) {
        s = response_message();
        if (strlen(bad_etags[i]) < sizeof(s.etag)) { strcpy(s.etag, bad_etags[i]); CHECK(response_bad(s)); }
        w = change(response_wire, SIZE(response_wire), 6,
            (const unsigned char *)bad_etags[i], strlen(bad_etags[i]), false);
        CHECK(rejected(w.bytes, w.size, true));
    }
    for (unsigned value = 0; value <= 255; value++) {
        s = response_message(); s.allow = (uint8_t)value;
        if (!value || value > 15) CHECK(response_bad(s));
        else CHECK(yd_binary_response_message_encode(&s, bytes, sizeof(bytes), &n));
        s = response_message(); s.authenticate = (uint8_t)value;
        if (value != 1) CHECK(response_bad(s));
    }
    return true;
}

static Wire change_number(const unsigned char *p, size_t n, unsigned id, uint64_t value, size_t width) {
    unsigned char bytes[8];
    for (size_t i = width; i > 0; i--) { bytes[i - 1] = (unsigned char)value; value >>= 8; }
    return change(p, n, id, bytes, width, false);
}
static bool wire_values(void) {
    YDBinaryRequestMessage r, source = put_message();
    YDBinaryResponseMessage s, response = response_message();
    unsigned char bytes[2048], payload[2200]; size_t n;
    const uint64_t lengths[] = {UINT64_C(16777217), UINT64_C(0x100000000), UINT64_MAX};
    for (size_t i = 0; i < sizeof(lengths)/sizeof(*lengths); i++) {
        Wire w = change_number(put_wire, SIZE(put_wire), 4, lengths[i], 8);
        CHECK(rejected(w.bytes, w.size, false));
        for (unsigned id = 3; id <= 4; id++) {
            /* A zero wire body isolates the representation cap from the
             * nonzero-body equality rule (HEAD/304 metadata shape). */
            Wire base = change_number(response_wire, SIZE(response_wire), 3, 0, 8);
            w = change_number(base.bytes, base.size, id, lengths[i], 8);
            CHECK(rejected(w.bytes, w.size, true));
        }
    }
    const uint32_t timeouts[] = {0, 30001, UINT32_MAX};
    for (size_t i = 0; i < sizeof(timeouts)/sizeof(*timeouts); i++) {
        Wire w = change_number(put_wire, SIZE(put_wire), 9, timeouts[i], 4);
        CHECK(rejected(w.bytes, w.size, false));
    }
    for (unsigned value = 0; value < 256; value++) {
        Wire w = change_number(response_wire, SIZE(response_wire), 9, value, 1);
        if (!value || value > 15) CHECK(rejected(w.bytes, w.size, true));
        else CHECK(yd_binary_response_message_decode(w.bytes, w.size, &s) && s.allow == value);
        w = change_number(response_wire, SIZE(response_wire), 10, value, 1);
        if (value != 1) CHECK(rejected(w.bytes, w.size, true));
        else CHECK(yd_binary_response_message_decode(w.bytes, w.size, &s) && s.authenticate == 1);
    }
    const unsigned statuses[] = {0, 199, 204, 304, 600, 65535};
    for (size_t i = 0; i < sizeof(statuses)/sizeof(*statuses); i++) {
        Wire w = change_number(response_wire, SIZE(response_wire), 1, statuses[i], 2);
        CHECK(rejected(w.bytes, w.size, true));
    }
    for (unsigned method = 1; method <= 4; method++) {
        if (method == 3) continue;
        Wire w = change_number(put_wire, SIZE(put_wire), 1, method, 1);
        CHECK(rejected(w.bytes, w.size, false));
        w = change_number(get_wire, SIZE(get_wire), 1, method, 1);
        Wire with_body = change_number(w.bytes, w.size, 4, 1, 8);
        CHECK(rejected(with_body.bytes, with_body.size, false));
    }
    for (unsigned value = 0; value <= 4; value++) {
        Wire w = change_number(response_wire, SIZE(response_wire), 3, value, 8);
        if (value == 0 || value == 3) CHECK(yd_binary_response_message_decode(w.bytes, w.size, &s));
        else CHECK(rejected(w.bytes, w.size, true));
    }
    /* All optional subsets, including holes, preserve their explicit presence. */
    for (unsigned mask = 0; mask < 32; mask++) {
        source.present = (uint16_t)(mask << 4);
        CHECK(yd_binary_request_message_encode(&source, bytes, sizeof(bytes), &n));
        CHECK(yd_binary_request_message_decode(bytes, n, &r) && r.present == source.present);
        CHECK(r.timeout_ms == (mask & 16 ? 1500 : 30000));
    }
    for (unsigned mask = 0; mask < 128; mask++) {
        response.present = (uint16_t)(mask << 5);
        CHECK(yd_binary_response_message_encode(&response, bytes, sizeof(bytes), &n));
        CHECK(yd_binary_response_message_decode(bytes, n, &s) && s.present == response.present);
    }
    /* Every variable text field rejects its own oversize and invalid grammar. */
    const unsigned request_ids[] = {2, 3, 5, 6, 7}, response_ids[] = {2, 7, 8};
    const size_t request_limits[] = {1024, 95, 519, 31, 31}, response_limits[] = {95, 128, 128};
    memset(payload, 'a', sizeof(payload));
    for (size_t i = 0; i < 5; i++) {
        Wire w = change(put_wire, SIZE(put_wire), request_ids[i], payload, request_limits[i] + 1, false);
        CHECK(rejected(w.bytes, w.size, false));
    }
    for (size_t i = 0; i < 3; i++) {
        Wire w = change(response_wire, SIZE(response_wire), response_ids[i], payload, response_limits[i] + 1, false);
        CHECK(rejected(w.bytes, w.size, true));
        w = change(response_wire, SIZE(response_wire), response_ids[i], NULL, 0, false);
        CHECK(rejected(w.bytes, w.size, true));
    }
    const char *bad_names[] = {"A", "a_b", "a.b", "a/b", "a b", "?", "%61"};
    for (size_t i = 0; i < sizeof(bad_names)/sizeof(*bad_names); i++) for (unsigned id = 7; id <= 8; id++) {
        Wire w = change(response_wire, SIZE(response_wire), id,
            (const unsigned char *)bad_names[i], strlen(bad_names[i]), false);
        CHECK(rejected(w.bytes, w.size, true));
    }
    const char *bad_revision[] = {"0123456789abcdeF", "g123456789abcdef", "0123456789abcde ", "0123456789abcde"};
    for (size_t i = 0; i < sizeof(bad_revision)/sizeof(*bad_revision); i++) {
        Wire w = change(response_wire, SIZE(response_wire), 5,
            (const unsigned char *)bad_revision[i], strlen(bad_revision[i]), false);
        CHECK(rejected(w.bytes, w.size, true));
    }
    /* Duplicate within a legal count, so the ordering/uniqueness check matters. */
    memcpy(payload, get_wire, SIZE(get_wire));
    memcpy(payload + SIZE(get_wire), get_wire + SIZE(get_wire) - 12, 12); payload[3] = 5;
    CHECK(rejected(payload, SIZE(get_wire) + 12, false));
    memset(payload, 0, sizeof(payload));
    CHECK(rejected(payload, 2047, false) && rejected(payload, 2048, true));
    return true;
}

static bool bounds(void) {
    YDBinaryRequestMessage r = put_message(), got;
    YDBinaryResponseMessage s = response_message(), decoded;
    unsigned char bytes[2048], check[2048]; size_t n, wanted;
    /* Largest grammar-valid target: 16 + 128 + 11 + 128 = 283 bytes. */
    memcpy(r.target, "/v1/collections/", 16); memset(r.target + 16, 'a', 128);
    memcpy(r.target + 144, "/documents/", 11); memset(r.target + 155, '-', 128); r.target[283] = 0;
    memset(r.content_type, 'x', 95); memcpy(r.content_type, "application/yaml;", 17); r.content_type[95] = 0;
    memcpy(r.authorization, "Bearer ", 7); memset(r.authorization + 7, '~', 512); r.authorization[519] = 0;
    memset(r.if_match, ' ', 31); r.if_match[31] = 0;
    memset(r.if_none_match, '*', 31); r.if_none_match[31] = 0;
    r.body_length = YD_BINARY_BODY_LIMIT; r.timeout_ms = 30000;
    CHECK(yd_binary_request_message_size(&r, &wanted) && wanted == 1028);
    CHECK(yd_binary_request_message_encode(&r, bytes, sizeof(bytes), &n) && n == wanted);
    CHECK(yd_binary_request_message_decode(bytes, n, &got));
    CHECK(got.body_length == YD_BINARY_BODY_LIMIT && strlen(got.target) == 283);
    CHECK(strlen(got.authorization) == 519 && strlen(got.if_match) == 31);
    r.body_length++; CHECK(request_bad(r)); r.body_length = UINT64_MAX; CHECK(request_bad(r));
    r.body_length = 0; r.timeout_ms = 1;
    r.if_match[0] = r.if_none_match[0] = 0;
    CHECK(yd_binary_request_message_encode(&r, bytes, sizeof(bytes), &n));
    CHECK(yd_binary_request_message_decode(bytes, n, &got) && got.timeout_ms == 1);
    r.target[283] = 'a'; r.target[284] = 0; CHECK(request_bad(r));
    r = put_message(); memset(r.target, 'a', sizeof(r.target)); CHECK(request_bad(r));
    r = put_message(); memset(r.content_type, 'a', sizeof(r.content_type)); CHECK(request_bad(r));
    r = put_message(); memset(r.authorization, 'a', sizeof(r.authorization)); CHECK(request_bad(r));
    r = put_message(); memset(r.if_match, 'a', sizeof(r.if_match)); CHECK(request_bad(r));
    r = put_message(); memset(r.if_none_match, 'a', sizeof(r.if_none_match)); CHECK(request_bad(r));
    r = get_message(); strcpy(r.target, "/v1/collections/yamldb-system/documents/b");
    CHECK(yd_binary_request_message_encode(&r, bytes, sizeof(bytes), &n));
    memset(s.content_type, '~', 95); s.content_type[95] = 0;
    memset(s.collection, 'a', 128); s.collection[128] = 0;
    memset(s.document, '-', 128); s.document[128] = 0;
    s.body_length = s.representation_length = YD_BINARY_BODY_LIMIT;
    s.retry_after_seconds = UINT32_MAX;
    CHECK(yd_binary_response_message_size(&s, &wanted) && wanted == 477);
    CHECK(yd_binary_response_message_encode(&s, bytes, sizeof(bytes), &n) && n == wanted);
    CHECK(yd_binary_response_message_decode(bytes, n, &decoded));
    CHECK(decoded.representation_length == YD_BINARY_BODY_LIMIT && decoded.retry_after_seconds == UINT32_MAX);
    /* HEAD-shaped metadata at the cap remains valid. Oversize cases below
     * must fail size/encode solely on the representation cap, not equality. */
    s.body_length = 0;
    CHECK(yd_binary_response_message_size(&s, &wanted) && wanted == 477);
    CHECK(yd_binary_response_message_encode(&s, bytes, sizeof(bytes), &n) && n == wanted);
    CHECK(yd_binary_response_message_decode(bytes, n, &decoded));
    CHECK(decoded.body_length == 0 && decoded.representation_length == YD_BINARY_BODY_LIMIT);
    s.representation_length++; CHECK(response_bad(s)); s.representation_length = UINT64_MAX; CHECK(response_bad(s));
    s = response_message(); s.body_length = UINT64_MAX; CHECK(response_bad(s));
    s = response_message(); s.content_type[0] = 0; CHECK(response_bad(s));
    s = response_message(); s.revision[0] = 'A'; CHECK(response_bad(s));
    s = response_message(); s.revision[16] = 'x'; CHECK(response_bad(s));
    s = response_message(); s.collection[0] = 0; CHECK(response_bad(s));
    s = response_message(); s.document[0] = 'A'; CHECK(response_bad(s));
    s = response_message(); memset(s.content_type, 'a', sizeof(s.content_type)); CHECK(response_bad(s));
    s = response_message(); memset(s.etag, 'a', sizeof(s.etag)); CHECK(response_bad(s));
    s = response_message(); memset(s.collection, 'a', sizeof(s.collection)); CHECK(response_bad(s));
    s = response_message(); memset(s.document, 'a', sizeof(s.document)); CHECK(response_bad(s));
    for (unsigned direction = 0; direction < 2; direction++) {
        r = put_message(); s = response_message();
        wanted = direction ? SIZE(response_wire) : SIZE(put_wire);
        for (size_t capacity = 0; capacity <= wanted + 1; capacity++) {
            memset(bytes, 0xa5, sizeof(bytes)); memcpy(check, bytes, sizeof(bytes)); n = 999;
            bool ok = direction ? yd_binary_response_message_encode(&s, bytes, capacity, &n)
                                : yd_binary_request_message_encode(&r, bytes, capacity, &n);
            CHECK(ok == (capacity >= wanted));
            if (ok) {
                CHECK(n == wanted);
                CHECK(!memcmp(bytes, direction ? response_wire : put_wire, n));
                CHECK(!memcmp(bytes + n, check + n, sizeof(bytes) - n));
            } else CHECK(n == 999 && !memcmp(bytes, check, sizeof(bytes)));
        }
    }
    return true;
}

static bool aliases(void) {
    union { max_align_t align; unsigned char bytes[4096]; YDBinaryRequestMessage request;
        YDBinaryResponseMessage response; } a;
    size_t n = 999; YDBinaryRequestMessage r = get_message(); YDBinaryResponseMessage s = response_message();
    unsigned char bytes[2048]; memset(bytes, 0xa5, sizeof(bytes));
    CHECK(!yd_binary_request_message_decode(NULL, 0, NULL));
    CHECK(!yd_binary_response_message_decode(NULL, 0, NULL));
    CHECK(!yd_binary_request_message_decode(get_wire, SIZE(get_wire), NULL));
    CHECK(!yd_binary_response_message_decode(response_wire, SIZE(response_wire), NULL));
    CHECK(!yd_binary_request_message_size(NULL, &n) && n == 999);
    CHECK(!yd_binary_response_message_size(NULL, &n) && n == 999);
    CHECK(!yd_binary_request_message_size(&r, NULL));
    CHECK(!yd_binary_response_message_size(&s, NULL));
    CHECK(!yd_binary_request_message_encode(NULL, bytes, sizeof(bytes), &n) && n == 999);
    CHECK(!yd_binary_response_message_encode(NULL, bytes, sizeof(bytes), &n) && n == 999);
    CHECK(!yd_binary_request_message_encode(&r, NULL, 0, &n) && n == 999);
    CHECK(!yd_binary_response_message_encode(&s, NULL, 0, &n) && n == 999);
    CHECK(!yd_binary_request_message_encode(&r, bytes, sizeof(bytes), NULL));
    CHECK(!yd_binary_response_message_encode(&s, bytes, sizeof(bytes), NULL));
    CHECK(!yd_binary_request_message_encode(&r, bytes, SIZE_MAX, &n) && n == 999);
    CHECK(!yd_binary_response_message_encode(&s, bytes, SIZE_MAX, &n) && n == 999);
    for (unsigned direction = 0; direction < 2; direction++) {
        const unsigned char *wire = direction ? response_wire : get_wire;
        size_t size = direction ? SIZE(response_wire) : SIZE(get_wire);
        memset(&a, 0xa5, sizeof(a)); memcpy(a.bytes + 7, wire, size);
        bool ok = direction ? yd_binary_response_message_decode(a.bytes + 7, size, &a.response)
                            : yd_binary_request_message_decode(a.bytes + 7, size, &a.request);
        CHECK(ok);
        CHECK(direction ? a.response.status == 200 : a.request.method == YD_BINARY_METHOD_GET);
        /* Encode with source/output fully overlapping, then at a shifted offset. */
        if (direction) a.response = s; else a.request = r;
        ok = direction ? yd_binary_response_message_encode(&a.response, a.bytes, sizeof(a.bytes), &n)
                       : yd_binary_request_message_encode(&a.request, a.bytes, sizeof(a.bytes), &n);
        CHECK(ok && n == size && !memcmp(a.bytes, wire, n));
        if (direction) a.response = s; else a.request = r;
        ok = direction ? yd_binary_response_message_encode(&a.response, a.bytes + 13, sizeof(a.bytes) - 13, &n)
                       : yd_binary_request_message_encode(&a.request, a.bytes + 13, sizeof(a.bytes) - 13, &n);
        CHECK(ok && n == size && !memcmp(a.bytes + 13, wire, n));
        memset(&a, 0xa5, sizeof(a)); memcpy(a.bytes + 7, wire, size);
        ok = direction ? yd_binary_response_message_decode(a.bytes + 7, size - 1, &a.response)
                       : yd_binary_request_message_decode(a.bytes + 7, size - 1, &a.request);
        CHECK(!ok && zero(&a, direction ? sizeof(a.response) : sizeof(a.request)));
        /* length cannot alias source or ANY byte of the output capacity. */
        if (direction) a.response = s; else a.request = r;
        unsigned char before[sizeof(a)]; memcpy(before, &a, sizeof(a));
        size_t *overlap = (size_t *)(void *)&a;
        ok = direction ? yd_binary_response_message_size(&a.response, overlap)
                       : yd_binary_request_message_size(&a.request, overlap);
        CHECK(!ok && !memcmp(before, &a, sizeof(a)));
        ok = direction ? yd_binary_response_message_encode(&a.response, bytes, sizeof(bytes), overlap)
                       : yd_binary_request_message_encode(&a.request, bytes, sizeof(bytes), overlap);
        CHECK(!ok && !memcmp(before, &a, sizeof(a)));
        memset(&a, 0xa5, sizeof(a)); memcpy(before, &a, sizeof(a));
        overlap = (size_t *)(void *)(a.bytes + sizeof(a.bytes) - sizeof(size_t));
        ok = direction ? yd_binary_response_message_encode(&s, a.bytes, sizeof(a.bytes), overlap)
                       : yd_binary_request_message_encode(&r, a.bytes, sizeof(a.bytes), overlap);
        CHECK(!ok && !memcmp(before, &a, sizeof(a)));
    }
    return true;
}

static bool fragments(void) {
    const unsigned char *wires[] = {get_wire, put_wire, response_wire};
    const size_t sizes[] = {SIZE(get_wire), SIZE(put_wire), SIZE(response_wire)};
    for (unsigned which = 0; which < 3; which++) {
        for (size_t split = 0; split <= sizes[which]; split++) {
            unsigned char assembled[2048]; memset(assembled, 0xa5, sizeof(assembled));
            memcpy(assembled, wires[which], split);
            if (split < sizes[which]) CHECK(rejected(assembled, split, which == 2));
            memcpy(assembled + split, wires[which] + split, sizes[which] - split);
            YDBinaryRequestMessage r; YDBinaryResponseMessage s;
            CHECK(which == 2 ? yd_binary_response_message_decode(assembled, sizes[which], &s)
                             : yd_binary_request_message_decode(assembled, sizes[which], &r));
            memset(assembled, 0, sizeof(assembled));
            CHECK(which == 2 ? !strcmp(s.revision, "0123456789abcdef")
                             : !strcmp(r.target, "/v1/collections/a/documents/b"));
        }
        unsigned char assembled[2048];
        for (size_t i = 0; i < sizes[which]; i++) {
            assembled[i] = wires[which][i];
            if (i + 1 < sizes[which]) CHECK(rejected(assembled, i + 1, which == 2));
        }
    }
    return true;
}
typedef struct { const YDBinaryRequestMessage *request; const YDBinaryResponseMessage *response; bool ok; } Thread;
static void *worker(void *arg) {
    Thread *t = arg; t->ok = false;
    for (unsigned i = 0; i < 1500; i++) {
        unsigned char bytes[2048]; size_t n; YDBinaryRequestMessage r; YDBinaryResponseMessage s;
        if (!yd_binary_request_message_encode(t->request, bytes, sizeof(bytes), &n) ||
            n != SIZE(put_wire) || memcmp(bytes, put_wire, n) ||
            !yd_binary_request_message_decode(put_wire, SIZE(put_wire), &r) || r.timeout_ms != 1500 ||
            !yd_binary_response_message_encode(t->response, bytes, sizeof(bytes), &n) ||
            n != SIZE(response_wire) || memcmp(bytes, response_wire, n) ||
            !yd_binary_response_message_decode(response_wire, SIZE(response_wire), &s) || s.status != 200)
            return NULL;
    }
    t->ok = true; return NULL;
}
static bool parallel(void) {
    const YDBinaryRequestMessage request = put_message();
    const YDBinaryResponseMessage response = response_message();
    pthread_t threads[4]; Thread args[4]; unsigned started = 0;
    for (unsigned i = 0; i < 4; i++) {
        args[i] = (Thread){.request = &request, .response = &response, .ok = false};
        if (pthread_create(&threads[i], NULL, worker, &args[i])) break;
        started++;
    }
    bool ok = started == 4;
    for (unsigned i = 0; i < started; i++) if (pthread_join(threads[i], NULL) || !args[i].ok) ok = false;
    CHECK(ok); return true;
}
static bool operations(void) {
    static const unsigned char query_wire[] =
        "\x00\x02\x00\x04"
        "\x00\x01\x00\x01\x05"
        "\x00\x02\x00\x0b" "/v1/query/a"
        "\x00\x03\x00\x10" "application/json"
        "\x00\x04\x00\x08" "\x00\x00\x00\x00\x00\x00\x00\x02";
    unsigned char bytes[2048]; size_t n;
    YDBinaryRequestMessage request;
    CHECK(yd_binary_request_message_decode(query_wire, SIZE(query_wire), &request));
    CHECK(request.schema == 2 && request.method == YD_BINARY_METHOD_POST && request.body_length == 2);
    CHECK(yd_binary_request_message_encode(&request, bytes, sizeof(bytes), &n));
    CHECK(n == SIZE(query_wire) && !memcmp(bytes, query_wire, n));
    request.schema = 0;
    CHECK(!yd_binary_request_message_size(&request, &n));
    request.schema = 2;
    strcpy(request.content_type, "Application/JSON; charset=utf-8");
    CHECK(yd_binary_request_message_size(&request, &n));
    request.method = YD_BINARY_METHOD_PATCH;
    strcpy(request.target, "/v1/collections/a/documents/b");
    CHECK(yd_binary_request_message_size(&request, &n));
    strcpy(request.target, "/v1/transactions");
    CHECK(!yd_binary_request_message_size(&request, &n));
    request.method = YD_BINARY_METHOD_POST;
    CHECK(yd_binary_request_message_size(&request, &n));
    request.method = YD_BINARY_METHOD_GET;
    request.body_length = 0; request.content_type[0] = 0;
    strcpy(request.target, "/v1/changes/stream?after=abc");
    CHECK(yd_binary_request_message_size(&request, &n));
    request.schema = 0;
    CHECK(!yd_binary_request_message_size(&request, &n));
    YDBinaryResponseMessage response = response_message(), decoded;
    response.schema = 2; response.present = 0; response.streaming = true;
    response.body_length = response.representation_length = 0;
    CHECK(yd_binary_response_message_encode(&response, bytes, sizeof(bytes), &n));
    CHECK(yd_binary_response_message_decode(bytes, n, &decoded) && decoded.streaming && decoded.schema == 2);
    CHECK(rejected(bytes, n - 5, true));
    bytes[n-1] = 2; CHECK(rejected(bytes, n, true)); bytes[n-1] = 1;
    bytes[1] = 1; CHECK(rejected(bytes, n, true)); bytes[1] = 2;
    response.body_length = response.representation_length = 1;
    CHECK(!yd_binary_response_message_size(&response, &n));
    response.body_length = response.representation_length = 0;
    response.status = 204; CHECK(!yd_binary_response_message_size(&response, &n));
    response.status = 200; response.streaming = false;
    response.present = YD_BINARY_RESPONSE_ALLOW; response.allow = YD_BINARY_ALLOW_POST;
    CHECK(yd_binary_response_message_size(&response, &n));
    response.schema = 0; CHECK(!yd_binary_response_message_size(&response, &n));
    return true;
}
int main(int argc, char **argv) {
    struct { const char *name; bool (*run)(void); } cases[] = {
        {"golden", golden}, {"malformed", malformed}, {"validators", validators},
        {"wire_values", wire_values}, {"bounds", bounds}, {"aliases", aliases},
        {"fragments", fragments}, {"parallel", parallel}, {"operations", operations}
    };
    if (argc > 2) return 2;
    const char *name = argc == 2 ? argv[1] : "all"; bool found = false;
    for (size_t i = 0; i < sizeof(cases)/sizeof(*cases); i++) {
        if (strcmp(name, "all") && strcmp(name, cases[i].name)) continue;
        found = true; if (!cases[i].run()) return 1;
        printf("binary messages: %s ok\n", cases[i].name);
    }
    return found ? 0 : 2;
}
