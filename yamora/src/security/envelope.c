#include "envelope.h"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

static const unsigned char magic[8] = {'Y','D','E','N','V','P','1',0};
static bool cancellation_disabled(void) {
    int previous = PTHREAD_CANCEL_ENABLE;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous)) return false;
    if (previous == PTHREAD_CANCEL_DISABLE) return true;
    (void)pthread_setcancelstate(previous, NULL);
    return false; /* caller must own the cancellation boundary */
}
static void put(unsigned char *p, uint64_t n, size_t bytes) {
    while (bytes) { p[--bytes] = (unsigned char)n; n >>= 8; }
}
static uint64_t get(const unsigned char *p, size_t bytes) {
    uint64_t n = 0;
    for (size_t i = 0; i < bytes; ++i) n = (n << 8) | p[i];
    return n;
}
static bool nonzero(const unsigned char *p, size_t n) {
    unsigned char any = 0;
    for (size_t i = 0; i < n; ++i) any |= p[i];
    return any != 0;
}
static bool identity_valid(const YDEnvelopeIdentity *id) {
    return id && id->generation && id->kind && nonzero(id->store_id, 16) &&
        nonzero(id->object_id, 32);
}
static size_t key_length(const char *id) {
    if (!id) return 0;
    for (size_t i = 0; i <= YD_KEY_ID_MAX; ++i) {
        unsigned char c = (unsigned char)id[i];
        if (!c) return i;
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || strchr(":/_-.", c))) return 0;
    }
    return 0;
}
/* Wrap context excludes only the as-yet-unknown wrapped length. The complete
 * serialized header and wrapped DEK are authenticated as payload AAD below. */
static bool context_digest(const unsigned char *header, const char *key_id,
    size_t key_len, unsigned char digest[32]) {
    unsigned char input[YD_ENVELOPE_HEADER_BYTES + YD_KEY_ID_MAX];
    memcpy(input, header, YD_ENVELOPE_HEADER_BYTES);
    input[38] = input[39] = 0;
    memcpy(input + YD_ENVELOPE_HEADER_BYTES, key_id, key_len);
    unsigned n = 0;
    return EVP_Digest(input, YD_ENVELOPE_HEADER_BYTES + key_len,
        digest, &n, EVP_sha256(), NULL) == 1 && n == 32;
}
void yd_envelope_free(unsigned char *bytes, size_t length) {
    if (bytes) { OPENSSL_cleanse(bytes, length ? length : 1); free(bytes); }
}
static YDEnvelopeResult provider_result(YDKeyResult result) {
    return result == YD_KEY_REJECTED ? YD_ENVELOPE_INVALID : YD_ENVELOPE_ERROR;
}
YDEnvelopeResult yd_envelope_seal(const YDKeyProvider *provider, const char *key_id,
    const YDEnvelopeIdentity *id, const unsigned char *plaintext, size_t length,
    unsigned char **out, size_t *out_length) {
    if (out) *out = NULL;
    if (out_length) *out_length = 0;
    size_t key_len = key_length(key_id);
    if (!cancellation_disabled() || !out || !out_length || !provider || !key_len || !identity_valid(id) ||
        (!plaintext && length) || length > YD_ENVELOPE_PLAINTEXT_MAX)
        return YD_ENVELOPE_ERROR;
    unsigned char header[YD_ENVELOPE_HEADER_BYTES] = {0}, key[32] = {0};
    unsigned char wrapped[YD_KEY_WRAPPED_MAX] = {0}, digest[32] = {0};
    unsigned char *wire = NULL;
    size_t wrapped_len = 0, total = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    YDEnvelopeResult result = YD_ENVELOPE_ERROR;
    memcpy(header, magic, sizeof(magic));
    put(header + 8, YD_ENVELOPE_VERSION, 2);
    put(header + 10, 1, 2); /* AES-256-GCM, 96-bit nonce, 128-bit tag. */
    put(header + 12, yd_key_provider_kind(provider), 2);
    put(header + 20, length, 4);
    put(header + 24, id->generation, 8);
    put(header + 32, id->kind, 4);
    put(header + 36, key_len, 2);
    memcpy(header + 40, id->store_id, 16);
    memcpy(header + 56, id->object_id, 32);
    /* Header length is derived during decoding; omit it from the key context
     * (zero on wire too). Reserved fields remain canonical zero. */
    if (RAND_priv_bytes(key, sizeof(key)) != 1 ||
        RAND_bytes(header + 88, 12) != 1 ||
        !context_digest(header, key_id, key_len, digest)) goto done;
    YDKeyResult wrapped_result = yd_key_provider_wrap(provider, key_id, digest,
        key, wrapped, &wrapped_len);
    if (wrapped_result != YD_KEY_OK) { result = provider_result(wrapped_result); goto done; }
    if (!wrapped_len || wrapped_len > YD_KEY_WRAPPED_MAX) goto done;
    put(header + 38, wrapped_len, 2);
    size_t aad_len = sizeof(header) + key_len + wrapped_len;
    total = aad_len + length + 16;
    wire = malloc(total);
    ctx = EVP_CIPHER_CTX_new();
    if (!wire || !ctx) goto done;
    memcpy(wire, header, sizeof(header));
    memcpy(wire + sizeof(header), key_id, key_len);
    memcpy(wire + sizeof(header) + key_len, wrapped, wrapped_len);
    int n = 0, final = 0;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, header + 88) != 1 ||
        EVP_EncryptUpdate(ctx, NULL, &n, wire, (int)aad_len) != 1 ||
        (length && (EVP_EncryptUpdate(ctx, wire + aad_len, &n, plaintext, (int)length) != 1 ||
                    n != (int)length)) ||
        EVP_EncryptFinal_ex(ctx, wire + aad_len + length, &final) != 1 || final != 0 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, wire + aad_len + length) != 1)
        goto done;
    *out = wire; *out_length = total; wire = NULL;
    result = YD_ENVELOPE_OK;
done:
    EVP_CIPHER_CTX_free(ctx);
    yd_envelope_free(wire, total);
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(wrapped, sizeof(wrapped));
    return result;
}
YDEnvelopeResult yd_envelope_open(const YDKeyProvider *provider,
    const YDEnvelopeIdentity *expected, const unsigned char *wire, size_t length,
    unsigned char **out, size_t *out_length) {
    if (out) *out = NULL;
    if (out_length) *out_length = 0;
    if (!cancellation_disabled() || !out || !out_length || !provider || !identity_valid(expected) || (!wire && length))
        return YD_ENVELOPE_ERROR;
    if (length < YD_ENVELOPE_HEADER_BYTES + 1 + 1 + 16 || length > YD_ENVELOPE_WIRE_MAX)
        return YD_ENVELOPE_INVALID;
    size_t key_len = (size_t)get(wire + 36, 2), wrapped_len = (size_t)get(wire + 38, 2);
    size_t plain_len = (size_t)get(wire + 20, 4);
    if (memcmp(wire, magic, 8) || get(wire + 8, 2) != YD_ENVELOPE_VERSION ||
        get(wire + 10, 2) != 1 || get(wire + 12, 2) != yd_key_provider_kind(provider) ||
        nonzero(wire + 14, 6) || nonzero(wire + 100, 28) ||
        get(wire + 24, 8) != expected->generation || get(wire + 32, 4) != expected->kind ||
        memcmp(wire + 40, expected->store_id, 16) || memcmp(wire + 56, expected->object_id, 32) ||
        !key_len || key_len > YD_KEY_ID_MAX || !wrapped_len || wrapped_len > YD_KEY_WRAPPED_MAX ||
        plain_len > YD_ENVELOPE_PLAINTEXT_MAX)
        return YD_ENVELOPE_INVALID;
    size_t aad_len = YD_ENVELOPE_HEADER_BYTES + key_len + wrapped_len;
    if (aad_len + plain_len + 16 != length) return YD_ENVELOPE_INVALID;
    char key_id[YD_KEY_ID_MAX + 1];
    memcpy(key_id, wire + YD_ENVELOPE_HEADER_BYTES, key_len); key_id[key_len] = 0;
    if (key_length(key_id) != key_len) return YD_ENVELOPE_INVALID;
    unsigned char digest[32] = {0}, key[32] = {0};
    unsigned char *plaintext = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    YDEnvelopeResult result = YD_ENVELOPE_ERROR;
    if (!context_digest(wire, key_id, key_len, digest)) goto done;
    YDKeyResult unwrapped = yd_key_provider_unwrap(provider, key_id, digest,
        wire + YD_ENVELOPE_HEADER_BYTES + key_len, wrapped_len, key);
    if (unwrapped != YD_KEY_OK) { result = provider_result(unwrapped); goto done; }
    plaintext = malloc(plain_len ? plain_len : 1);
    ctx = EVP_CIPHER_CTX_new();
    if (!plaintext || !ctx) goto done;
    int n = 0, final = 0;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, wire + 88) != 1 ||
        EVP_DecryptUpdate(ctx, NULL, &n, wire, (int)aad_len) != 1 ||
        (plain_len && (EVP_DecryptUpdate(ctx, plaintext, &n, wire + aad_len, (int)plain_len) != 1 ||
                       n != (int)plain_len)) ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
            (void *)(wire + aad_len + plain_len)) != 1) goto done;
    if (EVP_DecryptFinal_ex(ctx, plaintext + plain_len, &final) != 1) {
        result = YD_ENVELOPE_INVALID; goto done;
    }
    if (final != 0) goto done;
    *out = plaintext; *out_length = plain_len; plaintext = NULL;
    result = YD_ENVELOPE_OK;
done:
    EVP_CIPHER_CTX_free(ctx);
    yd_envelope_free(plaintext, plain_len);
    OPENSSL_cleanse(key, sizeof(key));
    return result;
}
YDEnvelopeResult yd_envelope_rotate(const YDKeyProvider *source,
    const YDKeyProvider *target, const char *new_key_id,
    const YDEnvelopeIdentity *expected, uint64_t new_generation,
    const unsigned char *wire, size_t length, unsigned char **out, size_t *out_length) {
    if (out) *out = NULL;
    if (out_length) *out_length = 0;
    if (!cancellation_disabled() || !out || !out_length || !identity_valid(expected) ||
        new_generation <= expected->generation) return YD_ENVELOPE_ERROR;
    unsigned char *plaintext = NULL;
    size_t plain_len = 0;
    YDEnvelopeResult result = yd_envelope_open(source, expected, wire, length, &plaintext, &plain_len);
    if (result == YD_ENVELOPE_OK) {
        YDEnvelopeIdentity next = *expected;
        next.generation = new_generation;
        result = yd_envelope_seal(target, new_key_id, &next, plaintext, plain_len, out, out_length);
    }
    yd_envelope_free(plaintext, plain_len);
    return result;
}
