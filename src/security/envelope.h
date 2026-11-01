#ifndef YAMORA_SECURITY_ENVELOPE_H
#define YAMORA_SECURITY_ENVELOPE_H
#include "key_provider.h"
#include <stddef.h>
#include <stdint.h>

#define YD_ENVELOPE_VERSION 1U
#define YD_ENVELOPE_HEADER_BYTES 128U
#define YD_ENVELOPE_PLAINTEXT_MAX (64U * 1024U * 1024U)
#define YD_ENVELOPE_WIRE_MAX (YD_ENVELOPE_PLAINTEXT_MAX + \
    YD_ENVELOPE_HEADER_BYTES + YD_KEY_ID_MAX + YD_KEY_WRAPPED_MAX + 16U)
typedef struct {
    unsigned char store_id[16];
    unsigned char object_id[32];
    uint64_t generation;
    uint32_t kind;
} YDEnvelopeIdentity;
typedef enum {
    YD_ENVELOPE_ERROR = -1, YD_ENVELOPE_INVALID = 0, YD_ENVELOPE_OK = 1
} YDEnvelopeResult;
/* Stable leaf API. Caller owns trusted store/object identity and exact expected
 * generation/kind independently of ciphertext; generation/kind and ids must be
 * nonzero. NEVER derive expected identity from the envelope being checked.
 * This rejects relocation and stale generations, but does not itself provide
 * an external monotonic anchor or crash-consistent publication. Storage must
 * durably commit its expected generation with the encrypted object. Restore
 * uses the authenticated backup manifest's original identity/generation.
 * All input/output buffers must be disjoint; *out=NULL,*length=0 on failure.
 * Successful bytes are owned; free with yd_envelope_free(bytes,length).
 * Exact arbitrary plaintext bytes, including authored YAML, are preserved.
 * No file/network I/O except the provider's trusted callback. Concurrent calls
 * supported with an immutable provider and thread-safe transport. */
/* Cancellation boundary: seal/open/rotate REQUIRE pthread cancellation already
 * DISABLED on entry; otherwise return ERROR with cleared outputs before taking
 * ownership of sensitive buffers. Caller keeps it disabled through adopting
 * outputs and registering their own cleanup or cleansing/freeing them. Trusted
 * provider callbacks MUST preserve the disabled state. Async cancellation is
 * unsupported. These functions never reenable cancellation for the caller. */
YDEnvelopeResult yd_envelope_seal(const YDKeyProvider *provider, const char *key_id,
    const YDEnvelopeIdentity *identity, const unsigned char *plaintext, size_t length,
    unsigned char **out, size_t *out_length);
YDEnvelopeResult yd_envelope_open(const YDKeyProvider *provider,
    const YDEnvelopeIdentity *expected, const unsigned char *wire, size_t length,
    unsigned char **out, size_t *out_length);
/* Authenticates first, then seals with a fresh DEK/nonce under the new provider
 * and key id. new_generation MUST exceed expected->generation. The old wire is
 * borrowed and unchanged on success/failure. Publish atomically and retain old
 * keys until all active objects and retained backup generations are verified.
 * Does not reuse a GCM nonce when metadata/key wrapping changes. */
YDEnvelopeResult yd_envelope_rotate(const YDKeyProvider *source,
    const YDKeyProvider *target, const char *new_key_id,
    const YDEnvelopeIdentity *expected, uint64_t new_generation,
    const unsigned char *wire, size_t length,
    unsigned char **out, size_t *out_length);
/* NULL-safe; cleanses before release. length is the exact successful length. */
void yd_envelope_free(unsigned char *bytes, size_t length);
#endif
