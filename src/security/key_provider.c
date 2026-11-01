#include "key_provider.h"
#include "oidc_json.h"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { char id[YD_KEY_ID_MAX + 1]; unsigned char key[32]; } LocalKey;
struct YDKeyProvider {
    YDKeyProviderKind kind;
    size_t count;
    LocalKey keys[YD_KEY_RING_MAX];
    char key_id[YD_KEY_ID_MAX + 1], mount[129];
    uint32_t version;
    YDKeyHTTP http;
    void *context;
};
static bool cancellation_disabled(void) {
    int previous = PTHREAD_CANCEL_ENABLE;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous)) return false;
    if (previous == PTHREAD_CANCEL_DISABLE) return true;
    (void)pthread_setcancelstate(previous, NULL);
    return false; /* caller must own the cancellation boundary */
}
static size_t identifier(const char *id, size_t maximum, bool path) {
    if (!id) return 0;
    for (size_t i = 0; i <= maximum; ++i) {
        unsigned char c = (unsigned char)id[i];
        if (!c) return i;
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_' || c == '-' ||
              (!path && (c == ':' || c == '/' || c == '.')))) return 0;
    }
    return 0;
}
YDKeyProvider *yd_key_provider_local(const YDKeyEntry *entries, size_t count) {
    if (!entries || !count || count > YD_KEY_RING_MAX) return NULL;
    YDKeyProvider *provider = calloc(1, sizeof(*provider));
    if (!provider) return NULL;
    provider->kind = YD_KEY_LOCAL;
    provider->count = count;
    for (size_t i = 0; i < count; ++i) {
        size_t n = identifier(entries[i].id, YD_KEY_ID_MAX, false);
        if (!n) goto fail;
        for (size_t j = 0; j < i; ++j)
            if (!strcmp(provider->keys[j].id, entries[i].id)) goto fail;
        memcpy(provider->keys[i].id, entries[i].id, n + 1);
        memcpy(provider->keys[i].key, entries[i].bytes, 32);
    }
    return provider;
fail:
    yd_key_provider_free(provider); return NULL;
}
static bool aws_arn(const char *arn) {
    size_t n = identifier(arn, YD_KEY_ID_MAX, false);
    if (!n) return false;
    const char *prefixes[] = {"arn:aws:kms:", "arn:aws-us-gov:kms:", "arn:aws-cn:kms:"};
    const char *region = NULL;
    for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); ++i)
        if (!strncmp(arn, prefixes[i], strlen(prefixes[i]))) region = arn + strlen(prefixes[i]);
    if (!region) return false;
    const char *account = strchr(region, ':');
    if (!account || account == region || account - region > 32) return false;
    for (const char *p = region; p < account; ++p)
        if (!((*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') || *p == '-')) return false;
    ++account;
    if (strlen(account) < 17) return false;
    for (size_t i = 0; i < 12; ++i) if (account[i] < '0' || account[i] > '9') return false;
    if (strncmp(account + 12, ":key/", 5)) return false;
    const char *id = account + 17;
    bool multi = !strncmp(id, "mrk-", 4);
    if (strlen(id) != 36) return false;
    for (size_t i = multi ? 4 : 0; i < 36; ++i) {
        if (!multi && (i == 8 || i == 13 || i == 18 || i == 23)) {
            if (id[i] != '-') return false;
        } else if (!((id[i] >= '0' && id[i] <= '9') || (id[i] >= 'a' && id[i] <= 'f')))
            return false;
    }
    return true;
}
YDKeyProvider *yd_key_provider_aws(const char *arn, YDKeyHTTP http, void *context) {
    /* Full key ARN rather than aliases: an alias update cannot redirect reads. */
    if (!aws_arn(arn) || !http) return NULL;
    size_t n = strlen(arn);
    YDKeyProvider *provider = calloc(1, sizeof(*provider));
    if (!provider) return NULL;
    provider->kind = YD_KEY_AWS_KMS;
    memcpy(provider->key_id, arn, n + 1);
    provider->http = http; provider->context = context;
    return provider;
}
YDKeyProvider *yd_key_provider_vault(const char *mount, const char *name,
    uint32_t version, YDKeyHTTP http, void *context) {
    size_t mn = identifier(mount, 128, true), nn = identifier(name, 128, true);
    if (!mn || !nn || !version || !http) return NULL;
    YDKeyProvider *provider = calloc(1, sizeof(*provider));
    if (!provider) return NULL;
    provider->kind = YD_KEY_VAULT_TRANSIT;
    memcpy(provider->mount, mount, mn + 1); memcpy(provider->key_id, name, nn + 1);
    provider->version = version; provider->http = http; provider->context = context;
    return provider;
}
YDKeyProviderKind yd_key_provider_kind(const YDKeyProvider *provider) {
    return provider ? provider->kind : 0;
}
void yd_key_provider_free(YDKeyProvider *provider) {
    if (provider) { OPENSSL_cleanse(provider, sizeof(*provider)); free(provider); }
}
static const unsigned char *local_key(const YDKeyProvider *provider, const char *id) {
    for (size_t i = 0; i < provider->count; ++i)
        if (!strcmp(provider->keys[i].id, id)) return provider->keys[i].key;
    return NULL;
}
static YDKeyResult local_wrap(const YDKeyProvider *provider, const char *id,
    const unsigned char *context, const unsigned char *key, unsigned char *out, size_t *length) {
    const unsigned char *kek = local_key(provider, id);
    if (!kek) return YD_KEY_REJECTED;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    YDKeyResult result = YD_KEY_ERROR;
    int n = 0, final = 0;
    if (!ctx || RAND_bytes(out, 12) != 1 ||
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, kek, out) != 1 ||
        EVP_EncryptUpdate(ctx, NULL, &n, context, 32) != 1 ||
        EVP_EncryptUpdate(ctx, out + 12, &n, key, 32) != 1 || n != 32 ||
        EVP_EncryptFinal_ex(ctx, out + 44, &final) != 1 || final != 0 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, out + 44) != 1) goto done;
    *length = 60; result = YD_KEY_OK;
done:
    EVP_CIPHER_CTX_free(ctx); return result;
}
static YDKeyResult local_unwrap(const YDKeyProvider *provider, const char *id,
    const unsigned char *context, const unsigned char *wrapped, size_t length, unsigned char *key) {
    const unsigned char *kek = local_key(provider, id);
    if (!kek || length != 60) return YD_KEY_REJECTED;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    YDKeyResult result = YD_KEY_ERROR;
    unsigned char decoded[48] = {0};
    int n = 0, final = 0;
    if (!ctx || EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, kek, wrapped) != 1 ||
        EVP_DecryptUpdate(ctx, NULL, &n, context, 32) != 1 ||
        EVP_DecryptUpdate(ctx, decoded, &n, wrapped + 12, 32) != 1 || n != 32 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)(wrapped + 44)) != 1) goto done;
    if (EVP_DecryptFinal_ex(ctx, decoded + 32, &final) != 1) {
        result = YD_KEY_REJECTED; goto done;
    }
    if (final != 0) goto done;
    memcpy(key, decoded, 32); result = YD_KEY_OK;
done:
    OPENSSL_cleanse(decoded, sizeof(decoded));
    EVP_CIPHER_CTX_free(ctx); return result;
}
static void b64(const unsigned char *input, size_t n, char *output) {
    int length = EVP_EncodeBlock((unsigned char *)output, input, (int)n);
    output[length] = 0;
}
static bool unb64(const YDOIDCJSONNode *node, unsigned char *output,
    size_t capacity, size_t *length) {
    if (!node || node->type != YD_OIDC_JSON_STRING || !node->length ||
        node->length % 4 || node->length > 4 * ((capacity + 2) / 3)) return false;
    size_t n = node->length, padding = 0;
    if (node->text[n - 1] == '=') ++padding;
    if (node->text[n - 2] == '=') ++padding;
    for (size_t i = 0; i < n - padding; ++i) {
        unsigned char c = (unsigned char)node->text[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '+' || c == '/')) return false;
    }
    size_t decoded_len = n / 4 * 3 - padding;
    if (decoded_len > capacity) return false;
    /* EVP_DecodeBlock writes padding bytes too, so use its full bounded size. */
    unsigned char decoded[YD_KEY_WRAPPED_MAX + 3] = {0};
    char canonical[4 * ((YD_KEY_WRAPPED_MAX + 2) / 3) + 1];
    int decoded_count = EVP_DecodeBlock(decoded, (const unsigned char *)node->text, (int)n);
    bool okay = decoded_count >= 0 && (size_t)decoded_count == n / 4 * 3;
    if (okay) {
        b64(decoded, decoded_len, canonical);
        okay = strlen(canonical) == n && !memcmp(canonical, node->text, n);
    }
    if (okay) { memcpy(output, decoded, decoded_len); *length = decoded_len; }
    OPENSSL_cleanse(decoded, sizeof(decoded)); OPENSSL_cleanse(canonical, sizeof(canonical));
    return okay;
}
static bool equals(const YDOIDCJSONNode *node, const char *text) {
    return node && node->type == YD_OIDC_JSON_STRING &&
        node->length == strlen(text) && !memcmp(node->text, text, node->length);
}
static bool version_number(const YDOIDCJSONNode *node, uint32_t wanted) {
    char version[16];
    (void)snprintf(version, sizeof(version), "%u", wanted);
    return node && node->type == YD_OIDC_JSON_NUMBER &&
        node->length == strlen(version) && !memcmp(node->text, version, node->length);
}
/* Vault encodes the KEK version in the ciphertext. Validate prefix, positive
 * canonical uint32 version and bounded standard base64 body before retention. */
static bool vault_cipher(const char *text, size_t n, uint32_t wanted) {
    if (n < 14 || n > YD_KEY_WRAPPED_MAX || memcmp(text, "vault:v", 7)) return false;
    size_t at = 7;
    uint64_t version = 0;
    if (text[at] < '1' || text[at] > '9') return false;
    while (at < n && text[at] >= '0' && text[at] <= '9') {
        version = version * 10 + (unsigned)(text[at++] - '0');
        if (version > UINT32_MAX) return false;
    }
    if (at >= n || text[at++] != ':' || (wanted && version != wanted)) return false;
    unsigned char decoded[YD_KEY_WRAPPED_MAX];
    size_t count = 0;
    YDOIDCJSONNode node = {.type = YD_OIDC_JSON_STRING, .text = text + at, .length = n - at};
    bool okay = unb64(&node, decoded, sizeof(decoded), &count) && count >= 28;
    OPENSSL_cleanse(decoded, sizeof(decoded));
    return okay;
}
static YDKeyResult remote(const YDKeyProvider *provider, const char *id,
    const unsigned char context[32], const unsigned char *input, size_t input_len,
    bool encrypt, unsigned char *output, size_t *output_len) {
    if (strcmp(id, provider->key_id)) return YD_KEY_REJECTED;
    char encoded[4 * ((YD_KEY_WRAPPED_MAX + 2) / 3) + 1] = {0};
    char binding[65] = {0}, associated[45] = {0};
    unsigned char request[YD_KEY_HTTP_MAX] = {0}, response[YD_KEY_HTTP_MAX] = {0};
    char path[300] = "/";
    const char *target = "";
    YDOIDCJSON *doc = NULL;
    const YDOIDCJSONNode *sensitive = NULL;
    YDKeyResult result = YD_KEY_ERROR;
    int request_len = -1;
    if (provider->kind == YD_KEY_AWS_KMS) {
        b64(input, input_len, encoded);
        for (size_t i = 0; i < 32; ++i)
            (void)snprintf(binding + i * 2, 3, "%02x", context[i]);
        request_len = snprintf((char *)request, sizeof(request),
            "{\"KeyId\":\"%s\",\"EncryptionAlgorithm\":\"SYMMETRIC_DEFAULT\","
            "\"EncryptionContext\":{\"yamora-envelope-v1\":\"%s\"},\"%s\":\"%s\"}",
            id, binding, encrypt ? "Plaintext" : "CiphertextBlob", encoded);
        target = encrypt ? "TrentService.Encrypt" : "TrentService.Decrypt";
    } else if (provider->kind == YD_KEY_VAULT_TRANSIT) {
        b64(context, 32, associated);
        (void)snprintf(path, sizeof(path), "/v1/%s/%s/%s", provider->mount,
            encrypt ? "encrypt" : "decrypt", id);
        if (encrypt) {
            b64(input, input_len, encoded);
            request_len = snprintf((char *)request, sizeof(request),
                "{\"plaintext\":\"%s\",\"associated_data\":\"%s\",\"key_version\":%u}",
                encoded, associated, provider->version);
        } else {
            if (!vault_cipher((const char *)input, input_len, 0)) {
                result = YD_KEY_REJECTED; goto done;
            }
            memcpy(encoded, input, input_len); encoded[input_len] = 0;
            request_len = snprintf((char *)request, sizeof(request),
                "{\"ciphertext\":\"%s\",\"associated_data\":\"%s\"}", encoded, associated);
        }
    }
    if (request_len <= 0 || (size_t)request_len >= sizeof(request)) goto done;
    unsigned status = 0;
    size_t response_len = 0;
    if (provider->http(provider->context, path, target, request, (size_t)request_len,
        &status, response, sizeof(response), &response_len) != YD_KEY_OK ||
        response_len > sizeof(response)) goto done;
    /* Permission, disabled-key and availability failures are terminal, with no
     * diagnostic body retained or surfaced. Never silently substitute a key. */
    if (status != 200 || !response_len) goto done;
    YDOIDCJSONResult parsed = yd_oidc_json_parse(response, response_len, 256, &doc);
    if (parsed != YD_OIDC_JSON_OK) goto done;
    const YDOIDCJSONNode *root = yd_oidc_json_root(doc), *data = root;
    if (!root || root->type != YD_OIDC_JSON_OBJECT) goto done;
    const YDOIDCJSONNode *errors = yd_oidc_json_get(root, "errors");
    if ((errors && (errors->type != YD_OIDC_JSON_ARRAY || errors->count)) ||
        yd_oidc_json_get(root, "__type") || yd_oidc_json_get(root, "Error")) goto done;
    if (provider->kind == YD_KEY_AWS_KMS) {
        if (!equals(yd_oidc_json_get(root, "KeyId"), id) ||
            !equals(yd_oidc_json_get(root, "EncryptionAlgorithm"), "SYMMETRIC_DEFAULT")) goto done;
    } else {
        data = yd_oidc_json_get(root, "data");
        if (!data || data->type != YD_OIDC_JSON_OBJECT) goto done;
    }
    const YDOIDCJSONNode *value = yd_oidc_json_get(data,
        provider->kind == YD_KEY_AWS_KMS ? (encrypt ? "CiphertextBlob" : "Plaintext") :
        (encrypt ? "ciphertext" : "plaintext"));
    if (!encrypt) sensitive = value;
    if (encrypt && provider->kind == YD_KEY_VAULT_TRANSIT) {
        if (!value || value->type != YD_OIDC_JSON_STRING ||
            !vault_cipher(value->text, value->length, provider->version) ||
            !version_number(yd_oidc_json_get(data, "key_version"), provider->version)) goto done;
        memcpy(output, value->text, value->length); *output_len = value->length;
    } else {
        size_t n = 0;
        if (!unb64(value, output, encrypt ? YD_KEY_WRAPPED_MAX : 32, &n) ||
            (!encrypt && n != 32) || (encrypt && !n)) goto done;
        *output_len = n;
    }
    result = YD_KEY_OK;
done:
    if (sensitive && sensitive->type == YD_OIDC_JSON_STRING)
        OPENSSL_cleanse((void *)sensitive->text, sensitive->length);
    yd_oidc_json_free(doc);
    OPENSSL_cleanse(encoded, sizeof(encoded));
    OPENSSL_cleanse(request, sizeof(request)); OPENSSL_cleanse(response, sizeof(response));
    return result;
}
YDKeyResult yd_key_provider_wrap(const YDKeyProvider *provider, const char *id,
    const unsigned char context[32], const unsigned char key[32],
    unsigned char *wrapped, size_t *length) {
    if (wrapped) memset(wrapped, 0, YD_KEY_WRAPPED_MAX);
    if (length) *length = 0;
    if (!cancellation_disabled() || !provider || !identifier(id, YD_KEY_ID_MAX, false) || !context || !key || !wrapped || !length)
        return YD_KEY_ERROR;
    YDKeyResult result = provider->kind == YD_KEY_LOCAL ?
        local_wrap(provider, id, context, key, wrapped, length) :
        remote(provider, id, context, key, 32, true, wrapped, length);
    if (result != YD_KEY_OK) { OPENSSL_cleanse(wrapped, YD_KEY_WRAPPED_MAX); *length = 0; }
    return result;
}
YDKeyResult yd_key_provider_unwrap(const YDKeyProvider *provider, const char *id,
    const unsigned char context[32], const unsigned char *wrapped, size_t length, unsigned char key[32]) {
    if (key) memset(key, 0, 32);
    if (!cancellation_disabled() || !provider || !identifier(id, YD_KEY_ID_MAX, false) || !context || !wrapped || !key)
        return YD_KEY_ERROR;
    if (!length || length > YD_KEY_WRAPPED_MAX) return YD_KEY_REJECTED;
    size_t key_len = 0;
    YDKeyResult result = provider->kind == YD_KEY_LOCAL ?
        local_unwrap(provider, id, context, wrapped, length, key) :
        remote(provider, id, context, wrapped, length, false, key, &key_len);
    if (result != YD_KEY_OK) OPENSSL_cleanse(key, 32);
    return result;
}
