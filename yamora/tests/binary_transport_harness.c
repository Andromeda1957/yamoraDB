#include "../src/transport/binary_frame.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef YD_BINARY_WITH_STORAGE
#include "../src/binary.h"
#endif

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); exit(1); } } while (0)
static const unsigned char metadata[] = "opaque application metadata";
static YDBinaryFrame frame(YDBinaryType type, uint32_t id, const void *p, uint32_t n) {
    return (YDBinaryFrame){.type = type, .stream_id = id, .payload = p, .length = n};
}
static YDBinaryLimits limits(uint32_t max_frame, uint32_t streams) {
    return (YDBinaryLimits){.max_frame = max_frame, .max_streams = streams,
        .max_message = YD_BINARY_MESSAGE_MIN, .receive_budget = max_frame + 16U,
        .send_budget = max_frame + 16U, .control_budget = 256};
}
static void accepted(YDBinaryConnection *c, YDBinaryDirection d, YDBinaryFrame f) {
    YDBinaryTicket t = {0};
    CHECK(yd_binary_admit(c, d, &f, &t) == YD_BINARY_OK);
    CHECK(t.bytes == (uint64_t)f.length + 16);
    CHECK(yd_binary_release(c, &t) == YD_BINARY_OK);
    CHECK(yd_binary_release(c, &t) == YD_BINARY_INVALID);
}
static void rejected(YDBinaryConnection *c, YDBinaryDirection d, YDBinaryFrame f,
                     YDBinaryResult expected) {
    YDBinaryConnection before;
    memcpy(&before, c, sizeof(before));
    YDBinaryTicket t, original;
    memset(&t, 0xa5, sizeof(t));
    memcpy(&original, &t, sizeof(t));
    CHECK(yd_binary_admit(c, d, &f, &t) == expected);
    CHECK(memcmp(&before, c, sizeof(before)) == 0);
    CHECK(memcmp(&original, &t, sizeof(t)) == 0);
}
static void ready(YDBinaryConnection *c, bool client, uint32_t cap, uint32_t streams) {
    YDBinaryLimits l = limits(cap, streams);
    CHECK(yd_binary_connection_init(c, client, &l));
    unsigned char hello[12];
    yd_binary_hello(hello, cap, streams);
    accepted(c, YD_BINARY_SEND, frame(YD_BINARY_HELLO, 0, hello, 12));
    CHECK(!yd_binary_connection_ready(c));
    accepted(c, YD_BINARY_RECEIVE, frame(YD_BINARY_HELLO, 0, hello, 12));
    CHECK(yd_binary_connection_ready(c));
}
static void request(YDBinaryConnection *c, uint32_t id) {
    accepted(c, c->client ? YD_BINARY_SEND : YD_BINARY_RECEIVE,
        frame(YD_BINARY_REQUEST, id, metadata, sizeof(metadata) - 1));
}
static void finish_stream(YDBinaryConnection *c, uint32_t id) {
    YDBinaryDirection client = c->client ? YD_BINARY_SEND : YD_BINARY_RECEIVE;
    YDBinaryDirection server = c->client ? YD_BINARY_RECEIVE : YD_BINARY_SEND;
    accepted(c, client, frame(YD_BINARY_END, id, NULL, 0));
    accepted(c, server, frame(YD_BINARY_RESPONSE, id, metadata, sizeof(metadata) - 1));
    accepted(c, server, frame(YD_BINARY_END, id, NULL, 0));
}
static void parser_tests(void) {
    static const unsigned char payload[] = {'#', ' ', 'x', '\r', '\n', 'a', ':', ' ', '0', 'x', 'f', 'f', '\n', 0, 255};
    unsigned char wire[128], buffer[64];
    YDBinaryFrame f = frame(YD_BINARY_DATA, UINT32_MAX, payload, sizeof(payload));
    CHECK(yd_binary_header_encode(&f, wire) == YD_BINARY_OK);
    const unsigned char expected[16] = {'Y','M','B','F',1,4,0,0,255,255,255,255,0,0,0,15};
    CHECK(!memcmp(wire, expected, 16));
    memcpy(wire + 16, payload, sizeof(payload));
    size_t size = 16 + sizeof(payload);
    CHECK(yd_binary_header_encode(&(YDBinaryFrame){.type = YD_BINARY_END, .stream_id = 1},
        wire + size) == YD_BINARY_OK);
    /* Every possible two-part fragmentation, including header/body boundaries
     * and a second, coalesced, zero-payload frame. */
    for (size_t split = 0; split <= size; split++) {
        YDBinaryParser parser;
        CHECK(yd_binary_parser_init(&parser, buffer, sizeof(buffer), 64));
        YDBinaryFrame out = frame(YD_BINARY_GOAWAY, 0, NULL, 0), before = out;
        size_t consumed = SIZE_MAX;
        YDBinaryResult result = yd_binary_parser_feed(&parser, wire, split, &consumed, &out);
        CHECK(consumed == split);
        if (split < size) {
            CHECK(result == YD_BINARY_MORE);
            CHECK(!memcmp(&out, &before, sizeof(out)));
            result = yd_binary_parser_feed(&parser, wire + split, size + 16 - split, &consumed, &out);
            CHECK(consumed == size - split);
        }
        CHECK(result == YD_BINARY_FRAME && out.stream_id == UINT32_MAX);
        CHECK(out.length == sizeof(payload) && !memcmp(out.payload, payload, sizeof(payload)));
        CHECK(yd_binary_parser_feed(&parser, wire + size, 16, &consumed, &out) == YD_BINARY_FRAME);
        CHECK(consumed == 16 && out.type == YD_BINARY_END && out.payload == NULL);
        CHECK(yd_binary_parser_finish(&parser) == YD_BINARY_OK);
    }
    YDBinaryParser parser;
    CHECK(yd_binary_parser_init(&parser, buffer, sizeof(buffer), 64));
    YDBinaryFrame out;
    size_t used;
    for (size_t i = 0; i < size; i++) {
        CHECK(yd_binary_parser_feed(&parser, wire + i, 1, &used, &out) ==
            (i + 1 == size ? YD_BINARY_FRAME : YD_BINARY_MORE));
        CHECK(used == 1);
    }
    CHECK(!memcmp(out.payload, payload, sizeof(payload)));
    /* EOF at every strict prefix fails; a complete frame is clean. */
    for (size_t end = 1; end < size; end++) {
        CHECK(yd_binary_parser_init(&parser, buffer, sizeof(buffer), 64));
        CHECK(yd_binary_parser_feed(&parser, wire, end, &used, &out) == YD_BINARY_MORE);
        CHECK(yd_binary_parser_finish(&parser) == YD_BINARY_TRUNCATED);
        CHECK(yd_binary_parser_feed(&parser, wire, size, &used, &out) == YD_BINARY_TRUNCATED);
        CHECK(used == 0);
    }
    /* Header corruption, invalid versions/types/flags, stream class/parity,
     * hostile lengths (including UINT32_MAX), never publish a partial frame. */
    unsigned offsets[] = {0, 4, 5, 6, 7, 11, 12, 13, 14, 15};
    for (size_t i = 0; i < sizeof(offsets) / sizeof(offsets[0]); i++) {
        unsigned char bad[16];
        memcpy(bad, wire, 16);
        bad[offsets[i]] = offsets[i] == 11 ? 0 : 255;
        CHECK(yd_binary_parser_init(&parser, buffer, sizeof(buffer), 64));
        memset(&out, 0x5a, sizeof(out));
        YDBinaryFrame before;
        memcpy(&before, &out, sizeof(out));
        YDBinaryResult result = yd_binary_parser_feed(&parser, bad, 16, &used, &out);
        CHECK(result == YD_BINARY_INVALID || result == YD_BINARY_LIMIT);
        CHECK(used == 16 && !memcmp(&out, &before, sizeof(out)));
        CHECK(yd_binary_parser_finish(&parser) == result);
    }
    memset(wire + 12, 255, 4);
    CHECK(yd_binary_header_decode(wire, 64, &out) == YD_BINARY_LIMIT);
    f.flags = 1;
    unsigned char untouched[16];
    memset(untouched, 0xaa, 16);
    CHECK(yd_binary_header_encode(&f, untouched) == YD_BINARY_INVALID);
    for (size_t i = 0; i < 16; i++) CHECK(untouched[i] == 0xaa);
    CHECK(!yd_binary_parser_init(&parser, buffer, sizeof(buffer), UINT32_MAX));
    CHECK(!yd_binary_parser_init(&parser, buffer, 11, 12));
    CHECK(!yd_binary_parser_init(&parser, buffer, sizeof(buffer), 0));
    /* Bounded deterministic hostile-byte corpus, also run under sanitizers. */
    uint32_t rng = 42;
    for (unsigned i = 0; i < 10000; i++) {
        for (size_t j = 0; j < sizeof(wire); j++) {
            rng = rng * 1664525U + 1013904223U;
            wire[j] = (unsigned char)(rng >> 24);
        }
        if (i & 1U) memcpy(wire, "YMBF\1", 5);
        CHECK(yd_binary_parser_init(&parser, buffer, sizeof(buffer), 64));
        YDBinaryResult result = yd_binary_parser_feed(&parser, wire, sizeof(wire), &used, &out);
        CHECK(used <= sizeof(wire));
        CHECK(result == YD_BINARY_INVALID || result == YD_BINARY_LIMIT ||
            result == YD_BINARY_MORE || result == YD_BINARY_FRAME);
    }
    puts("parser: fragmentation/coalescing/EOF/hostile corpus passed");
}
static void negotiation_tests(void) {
    YDBinaryConnection c;
    YDBinaryLimits l = limits(1024, 4);
    CHECK(yd_binary_connection_init(&c, false, &l));
    rejected(&c, YD_BINARY_RECEIVE, frame(YD_BINARY_REQUEST, 1, metadata, 1), YD_BINARY_INVALID);
    unsigned char hello[12];
    yd_binary_hello(hello, 64, 2);
    accepted(&c, YD_BINARY_RECEIVE, frame(YD_BINARY_HELLO, 0, hello, 12));
    CHECK(c.protocol == 1);
    CHECK(c.max_frame == 64 && c.max_streams == 2 && !yd_binary_connection_ready(&c));
    rejected(&c, YD_BINARY_SEND, frame(YD_BINARY_HELLO, 0, hello, 12), YD_BINARY_INVALID);
    yd_binary_hello(hello, 1024, 4);
    accepted(&c, YD_BINARY_SEND, frame(YD_BINARY_HELLO, 0, hello, 12));
    CHECK(yd_binary_connection_ready(&c) && c.max_frame == 64 && c.max_streams == 2);
    rejected(&c, YD_BINARY_RECEIVE, frame(YD_BINARY_HELLO, 0, hello, 12), YD_BINARY_INVALID);
    rejected(&c, YD_BINARY_SEND, frame(YD_BINARY_HELLO, 0, hello, 12), YD_BINARY_INVALID);
    CHECK(yd_binary_connection_init(&c, false, &l));
    hello[1] = hello[3] = 2;
    rejected(&c, YD_BINARY_RECEIVE, frame(YD_BINARY_HELLO, 0, hello, 12), YD_BINARY_INVALID);
    yd_binary_hello(hello, 0, 4);
    rejected(&c, YD_BINARY_RECEIVE, frame(YD_BINARY_HELLO, 0, hello, 12), YD_BINARY_INVALID);
    yd_binary_hello(hello, 64, UINT32_MAX);
    rejected(&c, YD_BINARY_RECEIVE, frame(YD_BINARY_HELLO, 0, hello, 12), YD_BINARY_INVALID);
    yd_binary_hello(hello, 64, 2);
    hello[3] = 255; /* A future compatible range still selects v1. */
    accepted(&c, YD_BINARY_RECEIVE, frame(YD_BINARY_HELLO, 0, hello, 12));
    l.max_frame = UINT32_MAX;
    YDBinaryConnection before;
    memcpy(&before, &c, sizeof(c));
    CHECK(!yd_binary_connection_init(&c, false, &l) && !memcmp(&before, &c, sizeof(c)));
    l = limits(64, UINT32_MAX);
    CHECK(!yd_binary_connection_init(&c, false, &l));
    l = limits(64, 2); l.max_message = UINT64_MAX;
    CHECK(!yd_binary_connection_init(&c, false, &l));
    l = limits(64, 2); l.max_message = YD_BINARY_MESSAGE_MIN - 1;
    CHECK(!yd_binary_connection_init(&c, false, &l));
    l = limits(64, 2); l.receive_budget = 79;
    CHECK(!yd_binary_connection_init(&c, false, &l));
    l = limits(1024, 4); l.max_protocol = 2;
    CHECK(yd_binary_connection_init(&c, false, &l));
    yd_binary_hello_protocols(hello, 1024, 4, 2);
    accepted(&c, YD_BINARY_SEND, frame(YD_BINARY_HELLO, 0, hello, 12));
    yd_binary_hello_protocols(hello, 64, 2, 2);
    accepted(&c, YD_BINARY_RECEIVE, frame(YD_BINARY_HELLO, 0, hello, 12));
    CHECK(yd_binary_connection_ready(&c) && c.protocol == 2);
    CHECK(yd_binary_connection_init(&c, false, &l));
    yd_binary_hello(hello, 64, 2);
    accepted(&c, YD_BINARY_RECEIVE, frame(YD_BINARY_HELLO, 0, hello, 12));
    CHECK(c.protocol == 1);
    puts("negotiation: compatible minima and hostile ranges passed");
}
static void admission_tests(void) {
    for (unsigned role = 0; role < 2; role++) {
        YDBinaryConnection c;
        ready(&c, role != 0, 64, 2);
        YDBinaryDirection client = c.client ? YD_BINARY_SEND : YD_BINARY_RECEIVE;
        YDBinaryDirection server = c.client ? YD_BINARY_RECEIVE : YD_BINARY_SEND;
        rejected(&c, server, frame(YD_BINARY_REQUEST, 1, metadata, 1), YD_BINARY_INVALID);
        rejected(&c, client, frame(YD_BINARY_REQUEST, 0, metadata, 1), YD_BINARY_INVALID);
        rejected(&c, client, frame(YD_BINARY_REQUEST, 2, metadata, 1), YD_BINARY_INVALID);
        request(&c, 1); request(&c, 3);
        CHECK(c.active_streams == 2);
        rejected(&c, client, frame(YD_BINARY_REQUEST, 5, metadata, 1), YD_BINARY_BACKPRESSURE);
        rejected(&c, client, frame(YD_BINARY_REQUEST, 1, metadata, 1), YD_BINARY_INVALID);
        rejected(&c, server, frame(YD_BINARY_DATA, 1, metadata, 1), YD_BINARY_INVALID);
        rejected(&c, server, frame(YD_BINARY_RESPONSE, 1, metadata, 1), YD_BINARY_INVALID);
        accepted(&c, client, frame(YD_BINARY_DATA, 1, metadata, 7));
        CHECK(c.streams[0].request_bytes == 7 && c.streams[0].response_bytes == 0);
        accepted(&c, client, frame(YD_BINARY_END, 1, NULL, 0));
        CHECK(c.streams[0].request_ended && !c.streams[0].response_ended && c.active_streams == 2);
        rejected(&c, client, frame(YD_BINARY_DATA, 1, metadata, 1), YD_BINARY_INVALID);
        rejected(&c, client, frame(YD_BINARY_END, 1, NULL, 0), YD_BINARY_INVALID);
        accepted(&c, server, frame(YD_BINARY_RESPONSE, 1, metadata, 1));
        rejected(&c, server, frame(YD_BINARY_RESPONSE, 1, metadata, 1), YD_BINARY_INVALID);
        accepted(&c, server, frame(YD_BINARY_DATA, 1, metadata, 9));
        CHECK(c.streams[0].request_bytes == 7 && c.streams[0].response_bytes == 9);
        accepted(&c, server, frame(YD_BINARY_END, 1, NULL, 0));
        CHECK(c.active_streams == 1 && c.streams[0].id == 0);
        rejected(&c, client, frame(YD_BINARY_REQUEST, 1, metadata, 1), YD_BINARY_INVALID);
        request(&c, 5);
        finish_stream(&c, 5); finish_stream(&c, 3);
        CHECK(c.active_streams == 0);
        request(&c, UINT32_MAX);
        finish_stream(&c, UINT32_MAX);
        rejected(&c, client, frame(YD_BINARY_REQUEST, 1, metadata, 1), YD_BINARY_INVALID);
        rejected(&c, client, frame(YD_BINARY_REQUEST, UINT32_MAX, metadata, 1), YD_BINARY_INVALID);
        rejected(&c, client, frame(YD_BINARY_DATA, UINT32_MAX, metadata, UINT32_MAX), YD_BINARY_LIMIT);
        rejected(&c, (YDBinaryDirection)99, frame(YD_BINARY_GOAWAY, 0, NULL, 0), YD_BINARY_INVALID);
    }
    puts("admission: atomic rejection, roles, half-closes, stream exhaustion passed");
}
static void budget_tests(void) {
    YDBinaryConnection c;
    ready(&c, false, 64, 2);
    request(&c, 1);
    unsigned char data[64] = {0};
    YDBinaryTicket held;
    YDBinaryFrame f = frame(YD_BINARY_DATA, 1, data, sizeof(data));
    CHECK(yd_binary_admit(&c, YD_BINARY_RECEIVE, &f, &held) == YD_BINARY_OK);
    CHECK(c.held[0][0] == 80 && c.held[1][0] == 0);
    rejected(&c, YD_BINARY_RECEIVE, frame(YD_BINARY_DATA, 1, data, 1), YD_BINARY_BACKPRESSURE);
    /* Control still gets through when the receive data budget is exhausted. */
    accepted(&c, YD_BINARY_RECEIVE, frame(YD_BINARY_END, 1, NULL, 0));
    accepted(&c, YD_BINARY_SEND, frame(YD_BINARY_RESPONSE, 1, metadata, 1));
    YDBinaryTicket send;
    CHECK(yd_binary_admit(&c, YD_BINARY_SEND, &f, &send) == YD_BINARY_OK);
    rejected(&c, YD_BINARY_SEND, frame(YD_BINARY_DATA, 1, data, 1), YD_BINARY_BACKPRESSURE);
    accepted(&c, YD_BINARY_SEND, frame(YD_BINARY_END, 1, NULL, 0));
    CHECK(c.active_streams == 0); /* Tickets outlive stream slots. */
    YDBinaryConnection other;
    ready(&other, true, 64, 2);
    CHECK(yd_binary_release(&other, &held) == YD_BINARY_INVALID);
    CHECK(yd_binary_release(&c, &held) == YD_BINARY_OK);
    CHECK(yd_binary_release(&c, &send) == YD_BINARY_OK);
    CHECK(c.held[0][0] == 0 && c.held[1][0] == 0);
    request(&c, 3);
    /* Arithmetic guards also fail closed for corrupted local counters. */
    c.held[0][0] = UINT64_MAX;
    rejected(&c, YD_BINARY_RECEIVE, f, YD_BINARY_BACKPRESSURE);
    c.held[0][0] = 0;
    c.streams[0].request_bytes = UINT64_MAX;
    rejected(&c, YD_BINARY_RECEIVE, frame(YD_BINARY_DATA, 3, data, 1), YD_BINARY_LIMIT);
    c.streams[0].request_bytes = c.limits.max_message;
    rejected(&c, YD_BINARY_RECEIVE, frame(YD_BINARY_DATA, 3, data, 1), YD_BINARY_LIMIT);
    c.held[0][1] = c.limits.control_budget;
    rejected(&c, YD_BINARY_RECEIVE, frame(YD_BINARY_PING, 0, data, 8), YD_BINARY_BACKPRESSURE);
    puts("budgets: receive/send/control reserves and overflow passed");
}
static void cancel_tests(void) {
    YDBinaryConnection c;
    unsigned char error[4] = {0, 0, 0, 1};
    for (unsigned role = 0; role < 2; role++) {
        ready(&c, role != 0, 64, 2);
        YDBinaryDirection client = c.client ? YD_BINARY_SEND : YD_BINARY_RECEIVE;
        YDBinaryDirection server = c.client ? YD_BINARY_RECEIVE : YD_BINARY_SEND;
        request(&c, 1);
        rejected(&c, server, frame(YD_BINARY_CANCEL, 1, NULL, 0), YD_BINARY_INVALID);
        rejected(&c, client, frame(YD_BINARY_ERROR, 1, error, 4), YD_BINARY_INVALID);
        accepted(&c, client, frame(YD_BINARY_CANCEL, 1, NULL, 0));
        CHECK(c.active_streams == 1 && c.streams[0].cancelled);
        CHECK(c.streams[0].request_ended && !c.streams[0].response_ended);
        rejected(&c, client, frame(YD_BINARY_CANCEL, 1, NULL, 0), YD_BINARY_INVALID);
        rejected(&c, client, frame(YD_BINARY_DATA, 1, metadata, 1), YD_BINARY_INVALID);
        accepted(&c, server, frame(YD_BINARY_END, 1, NULL, 0));
        CHECK(c.active_streams == 0);
        /* Late cancel crossing the response's END is harmless, no new slot. */
        accepted(&c, client, frame(YD_BINARY_CANCEL, 1, NULL, 0));
        rejected(&c, client, frame(YD_BINARY_CANCEL, 3, NULL, 0), YD_BINARY_INVALID);
        request(&c, 3);
        error[3] = 0;
        rejected(&c, server, frame(YD_BINARY_ERROR, 3, error, 4), YD_BINARY_INVALID);
        error[3] = 1;
        accepted(&c, server, frame(YD_BINARY_ERROR, 3, error, 4));
        CHECK(c.active_streams == 1 && !c.streams[0].request_ended);
        CHECK(c.streams[0].response_ended && c.streams[0].errored);
        /* Already in-flight request bytes drain after an early server error. */
        accepted(&c, client, frame(YD_BINARY_DATA, 3, metadata, 1));
        rejected(&c, server, frame(YD_BINARY_DATA, 3, metadata, 1), YD_BINARY_INVALID);
        accepted(&c, client, frame(YD_BINARY_END, 3, NULL, 0));
        CHECK(c.active_streams == 0);
        request(&c, 5);
        accepted(&c, client, frame(YD_BINARY_END, 5, NULL, 0));
        accepted(&c, server, frame(YD_BINARY_RESPONSE, 5, metadata, 1));
        accepted(&c, client, frame(YD_BINARY_CANCEL, 5, NULL, 0));
        accepted(&c, server, frame(YD_BINARY_DATA, 5, metadata, 1));
        accepted(&c, server, frame(YD_BINARY_ERROR, 5, error, 4));
        CHECK(c.active_streams == 0);
        request(&c, 7);
        accepted(&c, YD_BINARY_SEND, frame(YD_BINARY_GOAWAY, 0, NULL, 0));
        rejected(&c, client, frame(YD_BINARY_REQUEST, 9, metadata, 1), YD_BINARY_INVALID);
        finish_stream(&c, 7);
        accepted(&c, YD_BINARY_RECEIVE, frame(YD_BINARY_GOAWAY, 0, NULL, 0));
        rejected(&c, YD_BINARY_RECEIVE, frame(YD_BINARY_GOAWAY, 0, NULL, 0), YD_BINARY_INVALID);
        accepted(&c, server, frame(YD_BINARY_PING, 0, metadata, 8));
        accepted(&c, client, frame(YD_BINARY_PONG, 0, metadata, 8));
    }
    puts("cancellation: crossing frames, advisory outcome, draining and controls passed");
}
static void large_tests(void) {
    const size_t length = YD_BINARY_MESSAGE_MIN;
    unsigned char *source = malloc(length), *received = malloc(length);
    CHECK(source && received);
    memset(source, 'x', length);
    memcpy(source, "a: '", 4);
    memcpy(source + length - 2, "'\n", 2);
    YDBinaryConnection c;
    ready(&c, false, 8192, 2);
    /* Peer reduces frame/stream limits; message size remains independent. */
    YDBinaryLimits l = limits(8192, 2);
    CHECK(yd_binary_connection_init(&c, false, &l));
    unsigned char hello[12];
    yd_binary_hello(hello, 4096, 1);
    accepted(&c, YD_BINARY_RECEIVE, frame(YD_BINARY_HELLO, 0, hello, 12));
    yd_binary_hello(hello, 8192, 2);
    accepted(&c, YD_BINARY_SEND, frame(YD_BINARY_HELLO, 0, hello, 12));
    CHECK(c.max_frame == 4096 && c.max_streams == 1);
    request(&c, 1);
    unsigned char wire[4112], buffer[4096];
    YDBinaryParser p;
    CHECK(yd_binary_parser_init(&p, buffer, sizeof(buffer), c.max_frame));
    for (size_t offset = 0; offset < length; offset += 4096) {
        YDBinaryFrame f = frame(YD_BINARY_DATA, 1, source + offset, 4096), out;
        CHECK(yd_binary_header_encode(&f, wire) == YD_BINARY_OK);
        memcpy(wire + 16, f.payload, 4096);
        size_t consumed;
        CHECK(yd_binary_parser_feed(&p, wire, sizeof(wire), &consumed, &out) == YD_BINARY_FRAME);
        CHECK(consumed == sizeof(wire));
        accepted(&c, YD_BINARY_RECEIVE, out);
        memcpy(received + offset, out.payload, out.length);
    }
    CHECK(c.streams[0].request_bytes == length && !memcmp(source, received, length));
    rejected(&c, YD_BINARY_RECEIVE, frame(YD_BINARY_DATA, 1, source, 1), YD_BINARY_LIMIT);
    finish_stream(&c, 1);
    CHECK(yd_binary_parser_finish(&p) == YD_BINARY_OK && c.active_streams == 0);
#ifdef YD_BINARY_WITH_STORAGE
    char error[256];
    size_t packed_length, restored_length;
    unsigned char *packed = yd_binary_pack_profile(received, length, true, &packed_length,
        error, sizeof(error));
    CHECK(packed);
    unsigned char *restored = NULL;
    YDValue *value = NULL;
    CHECK(yd_binary_unpack_profile(packed, packed_length, true, &restored, &restored_length, &value));
    CHECK(restored_length == length && !memcmp(restored, source, length));
    yd_free(value); free(restored); free(packed);
    puts("storage: native large-profile 16MiB YAML pack/unpack passed");
#endif
    free(source); free(received);
    puts("large: exact 16MiB over negotiated 4KiB DATA frames passed");
}
#ifdef YD_BINARY_WITH_STORAGE
static void storage_tests(void) {
    static const char *const samples[] = {
        "# comment\r\nanswer: 0x7fffffffffffffff\r\nname: 'hello'\r\n",
        "# Unicode and source spelling\nname: \xce\xbb\ntext: |\n  \xc3\xa9\n  hello\n",
        "---\n{a: [true, null, -0.0], b: \"line\\nnext\"}\n"
    };
    for (size_t i = 0; i < sizeof(samples) / sizeof(samples[0]); i++) {
        const unsigned char *source = (const unsigned char *)samples[i];
        size_t length = strlen(samples[i]), packed_length = 0, restored_length = 0;
        char error[256];
        unsigned char *packed = yd_binary_pack(source, length, &packed_length, error, sizeof(error));
        CHECK(packed);
        unsigned char *restored = NULL;
        YDValue *value = NULL;
        CHECK(yd_binary_unpack(packed, packed_length, &restored, &restored_length, &value));
        CHECK(restored_length == length && !memcmp(restored, source, length));
        /* Exercise actual native storage bytes through arbitrary tiny DATA
         * boundaries, never serialize a value tree into the wire payload. */
        YDBinaryConnection c;
        ready(&c, false, 64, 1); request(&c, 1);
        YDBinaryParser parser;
        unsigned char buffer[64], wire[80], reassembled[256];
        CHECK(length <= sizeof(reassembled));
        CHECK(yd_binary_parser_init(&parser, buffer, sizeof(buffer), 64));
        for (size_t at = 0; at < length;) {
            size_t n = length - at;
            if (n > 7) n = 7;
            YDBinaryFrame f = frame(YD_BINARY_DATA, 1, restored + at, (uint32_t)n), out;
            CHECK(yd_binary_header_encode(&f, wire) == YD_BINARY_OK);
            memcpy(wire + 16, f.payload, n);
            for (size_t j = 0; j < n + 16; j++) {
                size_t used;
                CHECK(yd_binary_parser_feed(&parser, wire + j, 1, &used, &out) ==
                    (j == n + 15 ? YD_BINARY_FRAME : YD_BINARY_MORE));
            }
            accepted(&c, YD_BINARY_RECEIVE, out);
            memcpy(reassembled + at, out.payload, n);
            at += n;
        }
        CHECK(!memcmp(reassembled, source, length));
        finish_stream(&c, 1);
        yd_free(value); free(restored); free(packed);
    }
    puts("storage: native pack/unpack plus fragmented raw YAML bytes passed");
}
#endif
int main(int argc, char **argv) {
    const char *selected = argc == 2 ? argv[1] : "all";
#define RUN(name) do { if (!strcmp(selected, "all") || !strcmp(selected, #name)) name##_tests(); } while (0)
    RUN(parser); RUN(negotiation); RUN(admission); RUN(budget); RUN(cancel); RUN(large);
#ifdef YD_BINARY_WITH_STORAGE
    RUN(storage);
#endif
    return 0;
}
