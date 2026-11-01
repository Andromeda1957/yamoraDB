#ifndef YAMORA_SECURITY_FIELD_RESPONSE_H
#define YAMORA_SECURITY_FIELD_RESPONSE_H
#include "../transport/binary_message.h"
#include "../value.h"

#define YD_FIELD_RESPONSE_LIMIT YD_LARGE_REQUEST_LIMIT
#define YD_FIELD_RESPONSE_HEADERS_LIMIT 8192U
#define YD_FIELD_RESPONSE_PRIVATE_REVISION "0000000000000000"
typedef enum { YD_FIELD_RESPONSE_SOURCE = 1, YD_FIELD_RESPONSE_JSON = 2 } YDFieldResponseKind;

/* CALLER MUST classify the authenticated principal and response representation.
 * Apply to every v4 masked-principal reply: success, denial, replay, binary
 * admission/execution and fallback errors. Before identity is usable, suppress
 * metadata when masked principals exist, including anonymous health/errors.
 * This module authenticates nothing and hooks no daemon. Native FNV revision
 * and ETag fingerprints are NOT confidential opaque tokens. Reject global
 * revision preconditions/pagination for masked requests; reject source-hash
 * conditions without whole-document read authority BEFORE dispatch. */

/* Takes a malloc-owned body and byte length. SOURCE retains identical pointer
 * and bytes (authorized exact-source GET/HEAD only). JSON uses the existing
 * bounded native parser/serializer on trusted internal JSON envelopes, deleting
 * ONLY root-map revision/etag keys; arrays/nested user properties survive.
 * Never classify authored source JSON, even when it resembles JSON. Empty
 * bodies succeed. Failure with valid pointer arguments frees/clears *body and
 * *length: caller MUST use a fixed safe 503/empty fallback, never the original
 * response. Invalid pointer arguments do not consume a supplied body. */
bool yd_field_response_body(YDFieldResponseKind kind, char **body, size_t *length,
                            char *error, size_t error_length);

/* In-place bounded strict CRLF header block, without final empty line. Removes
 * case-insensitive ETag/X-YamlDB-Revision fields; retains other valid ASCII
 * name/value lines. Rejects folds, controls, bad names and incomplete lines.
 * Success zeroes unused bytes; failure clears the valid-capacity block.
 * Caller MUST discard pending output on failure and never append hashes later. */
bool yd_field_response_headers(char *headers, size_t capacity);

/* Required binary revision becomes a fixed non-content sentinel; ETag presence
 * and backing bytes clear. Invoke AFTER fallback construction, BEFORE metadata
 * size/encoding. Body adapter must already have updated message lengths. */
void yd_field_response_binary_metadata(YDBinaryResponseMessage *message);
#endif
