#ifndef YAMORA_TRANSPORT_BINARY_MESSAGE_H
#define YAMORA_TRANSPORT_BINARY_MESSAGE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define YD_BINARY_MESSAGE_SCHEMA 1U
#define YD_BINARY_METADATA_LIMIT 2048U
#define YD_BINARY_BODY_LIMIT UINT64_C(16777216)
#define YD_BINARY_TARGET_LIMIT 1024U
#define YD_BINARY_NAME_LIMIT 128U
#define YD_BINARY_CONTENT_TYPE_LIMIT 95U
#define YD_BINARY_AUTHORIZATION_LIMIT 519U
#define YD_BINARY_CONDITION_LIMIT 31U
#define YD_BINARY_TIMEOUT_LIMIT 30000U
#define YD_BINARY_TIMEOUT_DEFAULT 30000U

typedef enum {
    YD_BINARY_METHOD_GET = 1, YD_BINARY_METHOD_HEAD = 2,
    YD_BINARY_METHOD_PUT = 3, YD_BINARY_METHOD_DELETE = 4,
    YD_BINARY_METHOD_POST = 5, YD_BINARY_METHOD_PATCH = 6
} YDBinaryMethod;

/* REQUEST TLVs: 1 method:u8, 2 target:text, 3 content_type:text,
 * 4 body_length:u64 are mandatory. Optional fields below use their wire ID's
 * bit (1 << (id-1)) in present. 8 is a nonzero 16-byte ID; 9 is timeout:u32.
 * Text is printable ASCII, excludes NUL/controls, and has no wire terminator.
 * target is exactly /v1/collections/<name>/documents/<name>, each name
 * [a-z0-9-]{1,128}, matching snapshot.c's name profile. PUT requires the
 * existing case-insensitive application/yaml or text/yaml base media type,
 * optionally followed by ';' and printable parameters. Other methods require
 * empty content_type and zero body_length. Conditions are opaque, including
 * empty present values; storage validates them. Auth is exactly "Bearer "
 * followed by 1..512 non-space printable ASCII bytes; this is NOT auth proof.
 */
enum {
    YD_BINARY_REQUEST_AUTHORIZATION = 1U << 4, /* field 5: text, <=519 */
    YD_BINARY_REQUEST_IF_MATCH = 1U << 5,      /* field 6: text, <=31 */
    YD_BINARY_REQUEST_IF_NONE_MATCH = 1U << 6, /* field 7: text, <=31 */
    YD_BINARY_REQUEST_ID = 1U << 7,           /* field 8: bytes[16] */
    YD_BINARY_REQUEST_TIMEOUT = 1U << 8       /* field 9: u32, 1..30000 */
};
typedef struct {
    uint16_t schema; /* 0 is the original schema 1; 2 requires negotiated protocol 2. */
    YDBinaryMethod method;
    uint16_t present;
    char target[YD_BINARY_TARGET_LIMIT + 1];
    char content_type[YD_BINARY_CONTENT_TYPE_LIMIT + 1];
    uint64_t body_length;
    char authorization[YD_BINARY_AUTHORIZATION_LIMIT + 1];
    char if_match[YD_BINARY_CONDITION_LIMIT + 1];
    char if_none_match[YD_BINARY_CONDITION_LIMIT + 1];
    unsigned char request_id[16];
    uint32_t timeout_ms;
} YDBinaryRequestMessage;

enum {
    YD_BINARY_ALLOW_GET = 1U, YD_BINARY_ALLOW_HEAD = 2U,
    YD_BINARY_ALLOW_PUT = 4U, YD_BINARY_ALLOW_DELETE = 8U,
    YD_BINARY_ALLOW_ALL = 15U, YD_BINARY_ALLOW_POST = 16U, YD_BINARY_ALLOW_PATCH = 32U,
    YD_BINARY_AUTHENTICATE_BEARER = 1U
};
/* RESPONSE mandatory TLVs: 1 status:u16 (200..599), 2 content_type:text
 * (nonempty <=95), 3 body_length:u64, 4 representation_length:u64,
 * 5 revision:exactly 16 lowercase hex ASCII bytes (unquoted).
 * Lengths are <=16 MiB; body_length is zero or equals representation_length.
 * 204 requires both zero; 304 requires body_length zero. HEAD correlation and
 * all other method/body/status expectations belong to the runtime.
 * Optional ETag is exactly quoted lowercase hex: "0123456789abcdef" (18
 * bytes), NOT the JSON receipt's unquoted etag or the full ETag header line.
 * Collection/document names use the same name profile as request targets.
 * Allow is a nonzero u8 mask of the four bits above; authenticate is u8=1
 * (Bearer); retry_after_seconds is any u32 delta, including zero.
 * None of these fields or a decoded JSON receipt establishes authority or
 * proves a write outcome. The runtime preserves existing receipt semantics.
 */
enum {
    YD_BINARY_RESPONSE_ETAG = 1U << 5,         /* field 6: text[18] */
    YD_BINARY_RESPONSE_COLLECTION = 1U << 6,   /* field 7: text, <=128 */
    YD_BINARY_RESPONSE_DOCUMENT = 1U << 7,     /* field 8: text, <=128 */
    YD_BINARY_RESPONSE_ALLOW = 1U << 8,        /* field 9: u8 */
    YD_BINARY_RESPONSE_AUTHENTICATE = 1U << 9, /* field 10: u8 */
    YD_BINARY_RESPONSE_RETRY_AFTER = 1U << 10, /* field 11: u32 */
    YD_BINARY_RESPONSE_ID = 1U << 11           /* field 12: bytes[16], nonzero */
};
typedef struct {
    uint16_t schema; /* 0 encodes schema 1; 2 encodes schema 2. */
    bool streaming; /* Schema 2 field 13, mandatory u8=0/1; 1 has zero fixed lengths. */
    uint16_t status, present;
    char content_type[YD_BINARY_CONTENT_TYPE_LIMIT + 1];
    uint64_t body_length, representation_length;
    char revision[17], etag[19];
    char collection[YD_BINARY_NAME_LIMIT + 1];
    char document[YD_BINARY_NAME_LIMIT + 1];
    uint8_t allow, authenticate;
    uint32_t retry_after_seconds;
    unsigned char request_id[16];
} YDBinaryResponseMessage;

/* Whole metadata payloads only, not incremental parsers. Wire prefix is u16
 * schema=1/u16 field count, then strictly increasing unique u16 id/u16 length
 * TLVs, with all integers big endian. No padding, unknown fields or trailers.
 * The caller assembles fragments through binary_frame before decoding.
 * No allocation, I/O, auth, dispatch, body conversion, or mutable globals.
 * Absent optional members are ignored by encoders. Decoders own all fields,
 * zero absent members, and set an absent request timeout to 30000 ms.
 * Every input pointer must cover its declared readable object/byte extent;
 * every output pointer must cover its declared writable extent. Decode copies
 * via local storage: input may alias out, but that overlap is overwritten on
 * success AND failure. Otherwise input is unchanged. All decode failures clear
 * every byte of a non-NULL out, including padding. NULL out returns false.
 * Size/encode require non-NULL length, disjoint from the input struct and,
 * for encode, the output capacity extent. Failure leaves output and *length
 * unchanged. Size reports exact encoded length. Encode needs non-NULL bytes
 * and sufficient capacity, writes exactly that length and leaves the tail
 * unchanged. Struct/output overlap IS supported via a bounded local copy.
 * Concurrent calls are safe with shared immutable inputs and disjoint outputs;
 * callers synchronize any overlapping writable objects. No struct is wire ABI.
 */
bool yd_binary_request_message_size(const YDBinaryRequestMessage *message, size_t *length);
bool yd_binary_request_message_encode(const YDBinaryRequestMessage *message,
    unsigned char *bytes, size_t capacity, size_t *length);
bool yd_binary_request_message_decode(const unsigned char *bytes, size_t length,
    YDBinaryRequestMessage *out);
bool yd_binary_response_message_size(const YDBinaryResponseMessage *message, size_t *length);
bool yd_binary_response_message_encode(const YDBinaryResponseMessage *message,
    unsigned char *bytes, size_t capacity, size_t *length);
bool yd_binary_response_message_decode(const unsigned char *bytes, size_t length,
    YDBinaryResponseMessage *out);

#endif
