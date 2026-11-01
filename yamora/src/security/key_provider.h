#ifndef YAMORA_SECURITY_KEY_PROVIDER_H
#define YAMORA_SECURITY_KEY_PROVIDER_H
#include <stddef.h>
#include <stdint.h>

#define YD_KEY_BYTES 32U
#define YD_KEY_CONTEXT_BYTES 32U
#define YD_KEY_ID_MAX 255U
#define YD_KEY_WRAPPED_MAX 8192U
#define YD_KEY_HTTP_MAX 32768U
#define YD_KEY_RING_MAX 16U
typedef struct YDKeyProvider YDKeyProvider;
typedef enum {
    YD_KEY_ERROR = -1, YD_KEY_REJECTED = 0, YD_KEY_OK = 1
} YDKeyResult;
typedef enum {
    YD_KEY_LOCAL = 1, YD_KEY_AWS_KMS = 2, YD_KEY_VAULT_TRANSIT = 3
} YDKeyProviderKind;
typedef struct {
    const char *id;
    unsigned char bytes[YD_KEY_BYTES];
} YDKeyEntry;
/* Trusted transport boundary, borrowed for provider lifetime. POST only. The
 * callback MUST pin its configured endpoint, authenticate requests (AWS SigV4
 * or Vault token), verify TLS peer/hostname, reject redirects, bound the entire
 * call with a deadline, cap reads to response_capacity, and return ERROR on any
 * transport failure. It may not log request/response bodies. path/target/body
 * are borrowed for this call only; no credentials live in adapter metadata.
 * Return OK only after setting status and actual response_length <= capacity.
 * A failed callback must not retain plaintext data keys. Concurrent use needs
 * a thread-safe callback/context. A provider never retries or falls back.
 * Callbacks run with pthread cancellation disabled and MUST preserve it.
 * KMS target uses x-amz-target; content type is application/x-amz-json-1.1.
 * Vault target is empty; content type is application/json. */
typedef YDKeyResult (*YDKeyHTTP)(void *context, const char *path,
    const char *target, const unsigned char *body, size_t body_length,
    unsigned *status, unsigned char *response, size_t response_capacity,
    size_t *response_length);

/* Immutable owned key copies, 1..16 unique versioned ids. No file/network I/O.
 * Constructor failure returns NULL. Callers cleanse their own entry buffers.
 * Key ids are 1..255 ASCII letters/digits and :/_-.; no mutable alias semantics
 * are inferred. Historical keys must be retained for snapshots/backups. */
YDKeyProvider *yd_key_provider_local(const YDKeyEntry *entries, size_t count);
/* Pinned full symmetric KMS key ARN (no aliases), exact response KeyId and
 * SYMMETRIC_DEFAULT required. HTTP authentication is the callback's job. */
YDKeyProvider *yd_key_provider_aws(const char *key_arn, YDKeyHTTP http, void *context);
/* Standard /v1/<mount>/encrypt|decrypt/<name>, a non-derived/non-convergent
 * aes256-gcm96 transit key, explicit positive write version. mount/name each
 * 1..128 ASCII letters, digits, underscores or hyphens. Decrypt accepts historical embedded versions.
 * Key id in envelope is exactly name. Provision/rotate policy outside adapter. */
YDKeyProvider *yd_key_provider_vault(const char *mount, const char *name,
    uint32_t write_version, YDKeyHTTP http, void *context);
YDKeyProviderKind yd_key_provider_kind(const YDKeyProvider *provider);
/* All outputs cleared on failure. Disjoint inputs/outputs. The context is a
 * SHA-256 envelope-metadata digest, never secret/user plaintext. No key cache.
 * Missing/wrong keys and malformed responses fail closed. Wrapped output has
 * YD_KEY_WRAPPED_MAX capacity; plaintext output has YD_KEY_BYTES capacity.
 * wrap/unwrap REQUIRE pthread cancellation already DISABLED on entry, else
 * ERROR with cleared outputs. Caller preserves that state through adopting or
 * cleansing returned keys/buffers. Async cancellation is unsupported. No key
 * constructors/free functions call user code or cancellation points. */
YDKeyResult yd_key_provider_wrap(const YDKeyProvider *provider, const char *key_id,
    const unsigned char context[YD_KEY_CONTEXT_BYTES],
    const unsigned char key[YD_KEY_BYTES], unsigned char *wrapped, size_t *length);
YDKeyResult yd_key_provider_unwrap(const YDKeyProvider *provider, const char *key_id,
    const unsigned char context[YD_KEY_CONTEXT_BYTES], const unsigned char *wrapped,
    size_t length, unsigned char key[YD_KEY_BYTES]);
/* NULL-safe. Exclude destruction from concurrent calls. Cleanses local keys. */
void yd_key_provider_free(YDKeyProvider *provider);
#endif
