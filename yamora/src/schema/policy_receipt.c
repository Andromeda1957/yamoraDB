#define _POSIX_C_SOURCE 200809L
#include "policy_store.h"
#include "../disk_internal.h"
#include "../disk_documents.h"
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>

#define RECEIPT_HEADER 88U
#define REPLY_HEADER 32U
_Static_assert(YD_POLICY_RECEIPT_COUNT_LIMIT > 0 && YD_POLICY_RECEIPT_COUNT_LIMIT <= 4096U,
               "finite policy receipt count cap");
_Static_assert(YD_POLICY_RECEIPT_BYTES_LIMIT > 0 &&
               YD_POLICY_RECEIPT_BYTES_LIMIT <= 4U * 1024U * 1024U,
               "finite policy receipt byte cap");

static YDPolicyResult fail(YDPolicyResult result, char *error, size_t length,
                           const char *message) {
    yd_disk_error(error, length, message);
    return result;
}
static bool zero(const unsigned char *bytes, size_t size) {
    for (size_t i = 0; i < size; i++)
        if (bytes[i]) return false;
    return true;
}
static bool revision(const char *text) {
    if (strnlen(text, 17) != 16) return false;
    for (size_t i = 0; i < 16; i++)
        if (!((text[i] >= '0' && text[i] <= '9') ||
              (text[i] >= 'a' && text[i] <= 'f'))) return false;
    return true;
}
YDPolicyResult yd_policy_request_digest(const YDPolicyRequest *request,
    unsigned char digest[32], char *error, size_t length) {
    if (digest) memset(digest, 0, 32);
    if (!request || !digest || !request->method || !request->target ||
        (request->length && !request->body))
        return fail(YD_POLICY_INVALID, error, length, "invalid policy request");
    const char *parts[] = {request->method, request->target,
                          request->if_match, request->if_none_match};
    const size_t bounds[] = {8, 1025, 19, 2};
    size_t sizes[4];
    unsigned char header[32] = {0};
    memcpy(header, "YDREQ001", 8);
    for (size_t i = 0; i < 4; i++) {
        sizes[i] = parts[i] ? strnlen(parts[i], bounds[i]) : 0;
        if (sizes[i] == bounds[i] || (i < 2 && !sizes[i]) ||
            (i >= 2 && parts[i] && !sizes[i]))
            return fail(YD_POLICY_INVALID, error, length, "invalid policy request framing");
        yd_disk_set16(header + 8 + 2 * i, (uint16_t)sizes[i]);
    }
    if (request->length > YD_PC_SOURCE_LIMIT)
        return fail(YD_POLICY_LIMIT, error, length, "policy request exceeds source limit");
    yd_disk_set64(header + 16, request->length);
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    unsigned written = 0;
    bool valid = context && EVP_DigestInit_ex(context, EVP_sha256(), NULL) == 1 &&
                 EVP_DigestUpdate(context, header, sizeof(header)) == 1;
    for (size_t i = 0; valid && i < 4; i++)
        if (sizes[i]) valid = EVP_DigestUpdate(context, parts[i], sizes[i]) == 1;
    valid = valid && (!request->length ||
            EVP_DigestUpdate(context, request->body, request->length) == 1) &&
            EVP_DigestFinal_ex(context, digest, &written) == 1 && written == 32;
    EVP_MD_CTX_free(context);
    if (!valid) {
        memset(digest, 0, 32);
        return fail(YD_POLICY_ERROR, error, length, "policy request digest unavailable");
    }
    return YD_POLICY_OK;
}
bool yd_policy_receipt_key(const unsigned char id[16], unsigned char key[20]) {
    if (key) memset(key, 0, 20);
    if (!id || !key || zero(id, 16)) return false;
    memcpy(key, "\0YSP", 4);
    memcpy(key + 4, id, 16);
    return true;
}
static bool reply_size(const YDPolicyReply *reply, size_t *headers,
                        size_t *type, size_t *size) {
    if (!reply || (reply->status != 200 && reply->status != 201 && reply->status != 204) ||
        !revision(reply->revision)) return false;
    *headers = strnlen(reply->headers, sizeof(reply->headers));
    *type = strnlen(reply->content_type, sizeof(reply->content_type));
    if (*headers >= sizeof(reply->headers) || !*type || *type >= sizeof(reply->content_type) ||
        reply->length > YD_POLICY_REPLY_LIMIT - REPLY_HEADER - *headers - *type ||
        (reply->status == 204 && reply->length)) return false;
    for (size_t i = 0; i < *type; i++)
        if ((unsigned char)reply->content_type[i] < 32 ||
            (unsigned char)reply->content_type[i] > 126) return false;
    *size = RECEIPT_HEADER + *headers + *type + reply->length;
    return true;
}
YDPolicyResult yd_policy_receipt_decode(const unsigned char *bytes, size_t size,
    const unsigned char id[16], unsigned char digest[32], YDPolicyReply *reply,
    char *error, size_t length) {
    if (digest) memset(digest, 0, 32);
    if (reply) memset(reply, 0, sizeof(*reply));
    if (!bytes || !id || !digest || !reply || zero(id, 16) || size < RECEIPT_HEADER ||
        size > YD_POLICY_RECEIPT_LIMIT || memcmp(bytes, "YDSPRC01", 8) ||
        memcmp(bytes + 40, id, 16) || !zero(bytes + 62, 2))
        return fail(YD_POLICY_CORRUPT, error, length, "invalid policy receipt framing");
    size_t headers = yd_disk_u16(bytes + 58), type = yd_disk_u16(bytes + 60);
    if (headers >= sizeof(reply->headers) || !type || type >= sizeof(reply->content_type) ||
        headers + type > size - RECEIPT_HEADER ||
        yd_disk_u64(bytes + 64) != size - RECEIPT_HEADER - headers - type ||
        memchr(bytes + RECEIPT_HEADER, 0, headers + type))
        return fail(YD_POLICY_CORRUPT, error, length, "invalid policy receipt lengths");
    YDPolicyReply decoded = {.status = yd_disk_u16(bytes + 56),
                            .length = size - RECEIPT_HEADER - headers - type};
    memcpy(decoded.revision, bytes + 72, 16);
    memcpy(decoded.headers, bytes + RECEIPT_HEADER, headers);
    memcpy(decoded.content_type, bytes + RECEIPT_HEADER + headers, type);
    memcpy(decoded.body, bytes + RECEIPT_HEADER + headers + type, decoded.length);
    size_t checked_headers = 0, checked_type = 0, checked_size = 0;
    if (!reply_size(&decoded, &checked_headers, &checked_type, &checked_size) ||
        checked_size != size)
        return fail(YD_POLICY_CORRUPT, error, length, "invalid policy receipt reply");
    *reply = decoded;
    memcpy(digest, bytes + 8, 32);
    return YD_POLICY_OK;
}
YDPolicyResult yd_policy_receipt_get(YDDiskTxn *txn, const unsigned char id[16],
    const unsigned char digest[32], YDPolicyReply *reply, char *error, size_t length) {
    if (reply) memset(reply, 0, sizeof(*reply));
    unsigned char key[20], bytes[YD_POLICY_RECEIPT_LIMIT], stored_digest[32];
    if (!txn || !digest || !reply || !yd_policy_receipt_key(id, key))
        return fail(YD_POLICY_INVALID, error, length, "invalid policy receipt lookup");
    uint64_t offset = 0;
    int found = yd_disk_tx_get(txn, key, sizeof(key), &offset, error, length);
    if (found == 0) return YD_POLICY_ABSENT;
    if (found < 0) return fail(YD_POLICY_ERROR, error, length, "policy receipt lookup failed");
    YDDiskView view = txn->view;
    view.end = txn->next;
    size_t size = 0;
    if (!yd_disk_record_into(txn->disk, &view, offset, bytes, sizeof(bytes), &size, error, length))
        return fail(YD_POLICY_CORRUPT, error, length, "policy receipt record unavailable");
    YDPolicyResult result = yd_policy_receipt_decode(bytes, size, id, stored_digest, reply,
                                                    error, length);
    if (result == YD_POLICY_OK && memcmp(stored_digest, digest, 32)) {
        memset(reply, 0, sizeof(*reply));
        return fail(YD_POLICY_CONFLICT, error, length, "policy request ID reused");
    }
    return result;
}
YDPolicyResult yd_policy_receipt_admit(YDDiskTxn *txn, size_t addition,
    char *error, size_t length) {
    if (!txn || !txn->exclusive || !txn->locked || txn->failed ||
        !yd_policy_store_view_capable(txn->disk, &txn->view) || addition > YD_POLICY_RECEIPT_LIMIT)
        return fail(YD_POLICY_UNSUPPORTED, error, length, "policy receipt admission unavailable");
    static const unsigned char prefix[] = {0, 'Y', 'S', 'P'};
    YDDiskCursor *cursor = yd_disk_tx_cursor(txn, prefix, sizeof(prefix), false, error, length);
    if (!cursor) return fail(YD_POLICY_ERROR, error, length, "policy receipt census unavailable");
    YDDiskView view = txn->view; view.end = txn->next;
    unsigned char key[YD_DISK_KEY_LIMIT], bytes[YD_POLICY_RECEIPT_LIMIT], digest[32];
    uint64_t count = 0, total = 0, offset = 0;
    size_t key_size = 0, size = 0;
    YDPolicyResult result = YD_POLICY_OK;
    int next = 0;
    while ((next = yd_disk_next(cursor, key, sizeof(key), &key_size, &offset, error, length)) == 1) {
        if (key_size < sizeof(prefix) || memcmp(key, prefix, sizeof(prefix))) break;
        YDPolicyReply saved;
        if (key_size != YD_POLICY_RECEIPT_KEY_SIZE ||
            !yd_disk_record_into(txn->disk, &view, offset, bytes, sizeof(bytes), &size, error, length) ||
            yd_policy_receipt_decode(bytes, size, key + 4, digest, &saved, error, length) != YD_POLICY_OK) {
            result = fail(YD_POLICY_CORRUPT, error, length, "invalid policy receipt census"); break;
        }
        if (size > YD_POLICY_RECEIPT_BYTES_LIMIT - total || ++count == YD_POLICY_RECEIPT_COUNT_LIMIT) {
            result = fail(YD_POLICY_LIMIT, error, length, "policy receipt capacity exhausted"); break;
        }
        total += size;
    }
    yd_disk_cursor_free(cursor);
    if (next < 0) return fail(YD_POLICY_ERROR, error, length, "policy receipt census failed");
    /* Every valid receipt needs the fixed header and a nonempty media type.
     * Refuse a completely full namespace before catalog staging, too. */
    size_t required = addition ? addition : RECEIPT_HEADER + 1U;
    if (result == YD_POLICY_OK && required > YD_POLICY_RECEIPT_BYTES_LIMIT - total)
        result = fail(YD_POLICY_LIMIT, error, length, "policy receipt capacity exhausted");
    return result;
}
YDPolicyResult yd_policy_receipt_put(YDDiskTxn *txn, const unsigned char id[16],
    const unsigned char digest[32], const YDPolicyReply *reply, char *error, size_t length) {
    unsigned char key[20], bytes[YD_POLICY_RECEIPT_LIMIT] = {0};
    size_t headers = 0, type = 0, size = 0;
    if (!txn || !txn->exclusive || !txn->locked || txn->failed ||
        !yd_policy_store_view_capable(txn->disk, &txn->view)) {
        if (txn) txn->failed = true;
        return fail(YD_POLICY_UNSUPPORTED, error, length, "policy receipts require exclusive profile 7");
    }
    YDPolicyResult result = YD_POLICY_INVALID;
    char expected[17];
    yd_disk_revision(&txn->view, expected);
    if (!digest || !yd_policy_receipt_key(id, key) ||
        !reply_size(reply, &headers, &type, &size) || strcmp(reply->revision, expected)) {
        fail(result, error, length, "invalid policy receipt reply or revision");
        goto failed;
    }
    uint64_t existing = 0;
    int found = yd_disk_tx_get(txn, key, sizeof(key), &existing, error, length);
    if (found) {
        result = found > 0 ? YD_POLICY_CONFLICT : YD_POLICY_ERROR;
        fail(result, error, length, "policy receipt cannot be replaced");
        goto failed;
    }
    result = yd_policy_receipt_admit(txn, size, error, length);
    if (result != YD_POLICY_OK) goto failed;
    memcpy(bytes, "YDSPRC01", 8);
    memcpy(bytes + 8, digest, 32);
    memcpy(bytes + 40, id, 16);
    yd_disk_set16(bytes + 56, (uint16_t)reply->status);
    yd_disk_set16(bytes + 58, (uint16_t)headers);
    yd_disk_set16(bytes + 60, (uint16_t)type);
    yd_disk_set64(bytes + 64, reply->length);
    memcpy(bytes + 72, reply->revision, 16);
    memcpy(bytes + RECEIPT_HEADER, reply->headers, headers);
    memcpy(bytes + RECEIPT_HEADER + headers, reply->content_type, type);
    memcpy(bytes + RECEIPT_HEADER + headers + type, reply->body, reply->length);
    uint64_t offset = 0;
    if (!yd_disk_append(txn, bytes, size, &offset, error, length) ||
        !yd_disk_put(txn, key, sizeof(key), offset, error, length)) {
        result = YD_POLICY_ERROR;
        goto failed;
    }
    return YD_POLICY_OK;
failed:
    txn->failed = true;
    return result;
}
