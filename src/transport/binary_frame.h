#ifndef YAMORA_TRANSPORT_BINARY_FRAME_H
#define YAMORA_TRANSPORT_BINARY_FRAME_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define YD_BINARY_HEADER_SIZE 16U
#define YD_BINARY_VERSION 1U
#define YD_BINARY_FRAME_LIMIT (1024U * 1024U)
#define YD_BINARY_STREAM_LIMIT 128U
#define YD_BINARY_MESSAGE_MIN (16U * 1024U * 1024U)
#define YD_BINARY_MESSAGE_LIMIT (64U * 1024U * 1024U)
#define YD_BINARY_CONTROL_LIMIT (64U * 1024U)
#define YD_BINARY_HELLO_SIZE 12U

typedef enum {
    YD_BINARY_HELLO = 1, YD_BINARY_REQUEST, YD_BINARY_RESPONSE, YD_BINARY_DATA,
    YD_BINARY_END, YD_BINARY_CANCEL, YD_BINARY_ERROR, YD_BINARY_PING,
    YD_BINARY_PONG, YD_BINARY_GOAWAY
} YDBinaryType;
typedef enum {
    YD_BINARY_OK = 0, YD_BINARY_MORE, YD_BINARY_FRAME, YD_BINARY_BACKPRESSURE,
    YD_BINARY_INVALID, YD_BINARY_LIMIT, YD_BINARY_TRUNCATED
} YDBinaryResult;
typedef enum { YD_BINARY_RECEIVE = 0, YD_BINARY_SEND = 1 } YDBinaryDirection;

/* Flags are reserved, always zero. Payload is borrowed, never a C string. */
typedef struct {
    YDBinaryType type;
    uint16_t flags;
    uint32_t stream_id, length;
    const unsigned char *payload;
} YDBinaryFrame;

/* Wire integers are big endian. Header helpers validate shape, not state or
 * payload contents. Outputs remain unchanged on failure. */
YDBinaryResult yd_binary_header_encode(const YDBinaryFrame *frame,
    unsigned char header[YD_BINARY_HEADER_SIZE]);
YDBinaryResult yd_binary_header_decode(const unsigned char header[YD_BINARY_HEADER_SIZE],
    uint32_t max_frame, YDBinaryFrame *frame);
void yd_binary_hello(unsigned char payload[YD_BINARY_HELLO_SIZE],
    uint32_t max_frame, uint32_t max_streams);
/* Framing remains version 1; HELLO selects the highest common message protocol. */
void yd_binary_hello_protocols(unsigned char payload[YD_BINARY_HELLO_SIZE],
    uint32_t max_frame, uint32_t max_streams, unsigned maximum);

/* No allocation or I/O. Caller owns a max_frame-sized buffer for the parser's
 * entire lifetime. Each feed stops at one frame, leaving coalesced bytes to the
 * caller. Returned payload is valid until the next feed. Errors are sticky;
 * finish distinguishes a clean frame boundary from truncated EOF. */
typedef struct {
    unsigned char header[YD_BINARY_HEADER_SIZE];
    unsigned char *payload;
    size_t header_used, payload_used, capacity;
    uint32_t max_frame;
    YDBinaryFrame current;
    YDBinaryResult error;
} YDBinaryParser;
bool yd_binary_parser_init(YDBinaryParser *parser, unsigned char *payload,
    size_t capacity, uint32_t max_frame);
YDBinaryResult yd_binary_parser_feed(YDBinaryParser *parser, const unsigned char *bytes,
    size_t length, size_t *consumed, YDBinaryFrame *frame);
YDBinaryResult yd_binary_parser_finish(YDBinaryParser *parser);

typedef struct {
    uint32_t max_frame, max_streams;
    unsigned max_protocol; /* 0 defaults to legacy 1; otherwise 1..2. */
    uint64_t max_message, receive_budget, send_budget, control_budget;
} YDBinaryLimits;
typedef struct {
    uint32_t id;
    uint64_t request_bytes, response_bytes;
    bool request_ended, response_ended, response_started, cancelled, errored;
} YDBinaryStream;
typedef struct {
    YDBinaryLimits limits;
    YDBinaryStream streams[YD_BINARY_STREAM_LIMIT];
    uint64_t held[2][2]; /* [receive/send][data/control], includes wire headers */
    uint32_t max_frame, max_streams, active_streams, last_stream_id;
    unsigned protocol; /* Meaningful after ready(). */
    bool client, hello_sent, hello_received, local_goaway, remote_goaway;
} YDBinaryConnection;
typedef struct {
    YDBinaryConnection *owner;
    uint64_t bytes;
    YDBinaryDirection direction;
    bool control;
} YDBinaryTicket;

bool yd_binary_connection_init(YDBinaryConnection *connection, bool client,
    const YDBinaryLimits *limits);
bool yd_binary_connection_ready(const YDBinaryConnection *connection);
/* One serialized caller per connection. Pure admission: no dispatch, allocation,
 * authentication, send, or replay. Commit once per complete received frame or
 * once before queueing a sent frame. Any rejection leaves connection AND ticket
 * unchanged. BACKPRESSURE is retryable with the same frame; INVALID/LIMIT require
 * closing the connection. Release tickets when bytes leave their local queue,
 * even after their stream retires. Do not copy/reuse a live ticket or move a
 * connection with live tickets. A failed send requires closing, never rollback
 * or automatic replay of the admitted request. */
YDBinaryResult yd_binary_admit(YDBinaryConnection *connection, YDBinaryDirection direction,
    const YDBinaryFrame *frame, YDBinaryTicket *ticket);
YDBinaryResult yd_binary_release(YDBinaryConnection *connection, YDBinaryTicket *ticket);

#endif
