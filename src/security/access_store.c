#define _POSIX_C_SOURCE 200809L
#include "access_store.h"
#include "../disk_documents.h"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define JSON_TYPE "application/json; charset=utf-8"

static bool digest_of(const unsigned char *body, size_t length, unsigned char out[32]) {
    size_t n = 0;
    return EVP_Q_digest(NULL, "SHA256", NULL, body, length, out, &n) == 1 && n == 32;
}
int yd_access_store_record(YDDisk *disk, const YDDiskView *view, uint64_t *record) {
    if (record) *record = 0;
    if (!disk || !view || !record) return -1;
    unsigned char key[YD_DISK_KEY_LIMIT];
    size_t size = yd_disk_document_key(key, YD_ACCESS_STATE_COLLECTION, YD_ACCESS_STATE_DOCUMENT);
    char error[128];
    return size ? yd_disk_get(disk, view, key, size, record, error, sizeof(error)) : -1;
}
int yd_access_store_read(YDDisk *disk, const YDDiskView *view, YDAccessState **state,
    unsigned char digest[32]) {
    if (state) *state = NULL;
    if (digest) memset(digest, 0, 32);
    if (!disk || !view || !state || !digest) return -1;
    YDDiskDocument document = {0};
    char error[256];
    int found = yd_disk_document_get(disk, view, YD_ACCESS_STATE_COLLECTION,
        YD_ACCESS_STATE_DOCUMENT, &document, error, sizeof(error));
    if (found < 0) return -1;
    if (!found) {
        *state = yd_access_state_new();
        return *state ? 0 : -1;
    }
    *state = yd_access_state_parse(document.body, document.length);
    bool valid = *state && digest_of(document.body, document.length, digest);
    yd_disk_document_free(&document);
    if (!valid) {
        yd_access_state_free(*state);
        *state = NULL;
        memset(digest, 0, 32);
        return -1;
    }
    return 1;
}
static const char *word(const YDValue *v) {
    const YDValue *op = v && v->type == YD_MAP ? yd_get(v, "op") : NULL;
    return op && op->type == YD_STRING ? op->scalar : NULL;
}
/* The verb inside the command must agree with the exact public target shape. */
static YDAccessOperation operation_for(const char *target, const unsigned char *body,
    size_t length, char name[129]) {
    static const struct { const char *op, *method; } verbs[] = {
        {"role_put", "PUT"}, {"role_delete", "DELETE"}, {"principal_put", "PUT"},
        {"principal_rotate", "POST"}, {"principal_delete", "DELETE"}};
    static const YDAccessOperation operations[] = {YD_ACCESS_ROLE_PUT, YD_ACCESS_ROLE_DELETE,
        YD_ACCESS_PRINCIPAL_PUT, YD_ACCESS_PRINCIPAL_ROTATE, YD_ACCESS_PRINCIPAL_DELETE};
    char error[128];
    YDValue *v = body && length <= YD_ACCESS_COMMAND_BYTES ?
        yd_parse_sized(body, length, YD_ACCESS_COMMAND_BYTES, error, sizeof(error)) : NULL;
    const char *op = word(v);
    YDAccessOperation found = YD_ACCESS_OP_NONE;
    for (size_t i = 0; op && i < sizeof(verbs) / sizeof(*verbs); i++)
        if (!strcmp(op, verbs[i].op) &&
            yd_access_state_target(verbs[i].method, target, name) == operations[i])
            found = operations[i];
    yd_free(v);
    if (!found) name[0] = 0;
    return found;
}
static const char *kind(YDAccessOperation operation) {
    return operation == YD_ACCESS_ROLE_PUT || operation == YD_ACCESS_ROLE_DELETE ?
        "role" : "principal";
}
YDDiskReply yd_access_store_prepare(YDDisk *disk, const char *target,
    const unsigned char *body, size_t length, const char *match, const char *none,
    YDDiskTxn **prepared) {
    if (prepared) *prepared = NULL;
    char name[129];
    if (!prepared || !disk || !target || (length && !body))
        return yd_disk_error_reply(400, "invalid_access_command");
    if (match || none) return yd_disk_error_reply(400, "invalid_precondition");
    YDAccessOperation operation = operation_for(target, body, length, name);
    if (!operation) return yd_disk_error_reply(400, "invalid_access_command");
    char error[256];
    YDDiskTxn *txn = yd_disk_begin_exclusive(disk, error, sizeof(error));
    if (!txn) return yd_disk_error_reply(503, "recovery_required");
    YDDiskDocument old = {0};
    int found = yd_disk_document_tx_get(txn, YD_ACCESS_STATE_COLLECTION,
        YD_ACCESS_STATE_DOCUMENT, &old, error, sizeof(error));
    YDAccessState *state = found < 0 ? NULL : found ?
        yd_access_state_parse(old.body, old.length) : yd_access_state_new();
    if (!state) {
        yd_disk_document_free(&old);
        yd_disk_abort(txn);
        return yd_disk_error_reply(503, "access_state_unavailable");
    }
    YDAccessResult outcome = yd_access_state_apply(state, operation, name, body, length);
    if (outcome.status != 200 && outcome.status != 201) {
        yd_access_state_free(state);
        yd_disk_document_free(&old);
        yd_disk_abort(txn);
        return yd_disk_error_reply(outcome.status, outcome.code);
    }
    size_t size = 0;
    char *encoded = yd_access_state_encode(state, &size);
    if (!encoded) {
        yd_access_state_free(state);
        yd_disk_document_free(&old);
        yd_disk_abort(txn);
        return yd_disk_error_reply(413, "access_state_limit");
    }
    YDDiskDocument replacement = {.body = (unsigned char *)encoded, .length = size};
    memcpy(replacement.collection, YD_ACCESS_STATE_COLLECTION,
        sizeof(YD_ACCESS_STATE_COLLECTION));
    memcpy(replacement.id, YD_ACCESS_STATE_DOCUMENT, sizeof(YD_ACCESS_STATE_DOCUMENT));
    bool valid = yd_disk_write_document(txn, found ? &old : NULL, &replacement,
        error, sizeof(error));
    OPENSSL_cleanse(encoded, size);
    free(encoded);
    yd_disk_document_free(&old);
    const YDAccessStatePrincipal *principal = operation == YD_ACCESS_PRINCIPAL_ROTATE ?
        yd_access_state_principal(state, name) : NULL;
    long long until = principal ? (long long)principal->previous_expires_at : 0;
    unsigned long long version = (unsigned long long)state->version;
    yd_access_state_free(state);
    if (!valid) {
        yd_disk_abort(txn);
        return yd_disk_error_reply(503, "access_state_unavailable");
    }
    YDDiskReply reply = {.status = outcome.status, .content_type = JSON_TYPE};
    char text[512];
    int n = until ?
        snprintf(text, sizeof(text),
            "{\"status\":\"%s\",\"kind\":\"%s\",\"name\":\"%s\",\"version\":%llu,"
            "\"previous_expires_at\":%lld}\n", outcome.code, kind(operation), name, version, until) :
        snprintf(text, sizeof(text), "{\"status\":\"%s\",\"kind\":\"%s\",\"name\":\"%s\","
            "\"version\":%llu}\n", outcome.code, kind(operation), name, version);
    reply.body = n > 0 && (size_t)n < sizeof(text) ? malloc((size_t)n + 1) : NULL;
    if (!reply.body) {
        yd_disk_abort(txn);
        return yd_disk_error_reply(503, "allocation_failed");
    }
    memcpy(reply.body, text, (size_t)n + 1);
    reply.length = (size_t)n;
    memcpy(reply.headers, "Cache-Control: no-store\r\n", sizeof("Cache-Control: no-store\r\n"));
    yd_disk_revision(yd_disk_tx_view(txn), reply.revision);
    *prepared = txn;
    return reply;
}
