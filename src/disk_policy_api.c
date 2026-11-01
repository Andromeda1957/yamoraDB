#include "disk_policy_api.h"
#include "disk_documents.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define JSON_TYPE "application/json; charset=utf-8"
static const char prefix[] = "/v1/schema-policies/";

bool yd_disk_policy_api_target(const char *target) {
    return target && (!strcmp(target, "/v1/schema-policies") ||
        !strncmp(target, prefix, sizeof(prefix) - 1));
}

int yd_disk_policy_status(YDPolicyResult result) {
    switch (result) {
    case YD_POLICY_OK: return 200;
    case YD_POLICY_ABSENT: return 404;
    case YD_POLICY_INVALID: return 400;
    case YD_POLICY_UNSUPPORTED: case YD_POLICY_REJECTED: return 422;
    case YD_POLICY_LIMIT: return 413;
    case YD_POLICY_CONFLICT: return 412;
    case YD_POLICY_CORRUPT: case YD_POLICY_ERROR: return 503;
    }
    return 503;
}

static void hex(const unsigned char bytes[32], char text[65]) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < 32; i++) {
        text[2 * i] = digits[bytes[i] >> 4];
        text[2 * i + 1] = digits[bytes[i] & 15];
    }
    text[64] = 0;
}

static bool version(const char *text, uint64_t *out) {
    if (!text || strlen(text) != 18 || text[0] != '"' || text[17] != '"') return false;
    uint64_t value = 0;
    for (size_t i = 1; i < 17; i++) {
        unsigned char c = (unsigned char)text[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
        value = (value << 4) | (uint64_t)(c <= '9' ? c - '0' : c - 'a' + 10);
    }
    *out = value;
    return true;
}

static YDDiskReply stored_reply(const YDPolicyReply *saved) {
    /* This endpoint's successful receipt type is fixed by this API version.
     * Use a static lifetime, never a pointer into a returned stack structure. */
    if (strcmp(saved->content_type, JSON_TYPE) || saved->length > sizeof(saved->body))
        return yd_disk_error_reply(503, "invalid_policy_receipt");
    char *body = malloc(saved->length + 1);
    if (!body) return yd_disk_error_reply(503, "allocation_failed");
    memcpy(body, saved->body, saved->length);
    body[saved->length] = 0;
    YDDiskReply result = {.status = saved->status, .body = body, .length = saved->length,
        .content_type = JSON_TYPE};
    memcpy(result.revision, saved->revision, sizeof(result.revision));
    memcpy(result.headers, saved->headers, sizeof(result.headers));
    return result;
}

static YDDiskReply read_policy(YDDisk *disk, const YDDiskView *view,
    const char *collection, YDPolicyWork *work) {
    char error[256];
    bool present = false;
    YDPolicyCatalog *catalog = NULL;
    YDPolicyResult loaded = yd_policy_store_at(disk, view, work, &catalog, &present,
        error, sizeof(error));
    if (loaded != YD_POLICY_OK)
        return yd_disk_error_reply(yd_disk_policy_status(loaded), "policy_unavailable");
    YDPCEntry entry;
    YDPCResult found = yd_policy_catalog_find(catalog, collection, strlen(collection), &entry);
    if (!present || found != YD_PC_OK) {
        yd_policy_catalog_free(catalog);
        return yd_disk_error_reply(found == YD_PC_NOT_FOUND || !present ? 404 : 503,
            "policy_not_found");
    }
    YDValue scalar = {.type = YD_STRING, .scalar = (char *)entry.source};
    size_t quoted_length = 0;
    char *quoted = yd_json_sized(&scalar, &quoted_length, 6U * YD_PC_SOURCE_LIMIT + 16U);
    size_t capacity = quoted_length + 1024;
    char *body = quoted ? malloc(capacity) : NULL;
    char source_hash[65], policy_hash[65];
    hex(entry.source_sha256, source_hash);
    hex(entry.policy_sha256, policy_hash);
    int n = body ? snprintf(body, capacity,
        "{\"collection\":\"%s\",\"version\":\"%016llx\",\"mode\":\"%s\","
        "\"profile\":\"%s\",\"source\":%s,\"source_sha256\":\"%s\","
        "\"policy_sha256\":\"%s\"}\n", collection, (unsigned long long)entry.version,
        entry.mode == YD_PC_ENFORCE ? "enforce" : "off", entry.profile,
        quoted, source_hash, policy_hash) : -1;
    free(quoted);
    uint64_t policy_version = entry.version;
    yd_policy_catalog_free(catalog);
    if (n < 0 || (size_t)n >= capacity) {
        free(body);
        return yd_disk_error_reply(503, "serialization_failed");
    }
    YDDiskReply result = {.status = 200, .body = body, .length = (size_t)n,
        .content_type = JSON_TYPE};
    snprintf(result.headers, sizeof(result.headers), "ETag: \"%016llx\"\r\n",
        (unsigned long long)policy_version);
    yd_disk_revision(view, result.revision);
    return result;
}

static bool mutation_reply(YDDiskTxn *txn, const YDPolicyCatalog *catalog,
    const char *collection, bool created, YDPolicyReply *reply) {
    YDPCEntry entry;
    if (yd_policy_catalog_find(catalog, collection, strlen(collection), &entry) != YD_PC_OK)
        return false;
    memset(reply, 0, sizeof(*reply));
    reply->status = created ? 201 : 200;
    yd_disk_revision(yd_disk_tx_view(txn), reply->revision);
    snprintf(reply->headers, sizeof(reply->headers), "ETag: \"%016llx\"\r\n",
        (unsigned long long)entry.version);
    memcpy(reply->content_type, JSON_TYPE, sizeof(JSON_TYPE));
    char source_hash[65], policy_hash[65];
    hex(entry.source_sha256, source_hash);
    hex(entry.policy_sha256, policy_hash);
    int n = snprintf((char *)reply->body, sizeof(reply->body),
        "{\"status\":\"%s\",\"collection\":\"%s\",\"version\":\"%016llx\","
        "\"mode\":\"%s\",\"profile\":\"%s\",\"source_sha256\":\"%s\","
        "\"policy_sha256\":\"%s\",\"revision\":\"%s\"}\n",
        entry.mode == YD_PC_ENFORCE ? "stored" : "disabled", collection,
        (unsigned long long)entry.version, entry.mode == YD_PC_ENFORCE ? "enforce" : "off",
        entry.profile, source_hash, policy_hash, reply->revision);
    if (n < 0 || (size_t)n >= sizeof(reply->body)) return false;
    reply->length = (size_t)n;
    return true;
}

static YDDiskReply change_policy(YDDisk *disk, const char *collection,
    const YDPolicyRequest *request, const unsigned char id[16], YDPolicyWork *work,
    YDDiskTxn **prepared) {
    unsigned char key[YD_POLICY_RECEIPT_KEY_SIZE], digest[32];
    if (!id || !yd_policy_receipt_key(id, key))
        return yd_disk_error_reply(400, "request_id_required");
    if (request->length > YD_PC_SOURCE_LIMIT)
        return yd_disk_error_reply(413, "policy_source_too_large");
    char error[256];
    YDPolicyResult result = yd_policy_request_digest(request, digest, error, sizeof(error));
    if (result != YD_POLICY_OK)
        return yd_disk_error_reply(yd_disk_policy_status(result), "invalid_policy_request");
    YDDiskTxn *txn = yd_disk_begin_exclusive(disk, error, sizeof(error));
    if (!txn) return yd_disk_error_reply(503, "recovery_required");
    YDPolicyReply saved;
    /* The transport authenticated ADMIN before this call. Exact receipt lookup
     * precedes today's preconditions, catalog, compilation and admission. */
    result = yd_policy_receipt_get(txn, id, digest, &saved, error, sizeof(error));
    if (result != YD_POLICY_ABSENT) {
        yd_disk_abort(txn);
        if (prepared && result == YD_POLICY_OK)
            return yd_disk_error_reply(503, "policy_raft_receipt_missing");
        if (result == YD_POLICY_OK) return stored_reply(&saved);
        return yd_disk_error_reply(result == YD_POLICY_CONFLICT ? 409 : yd_disk_policy_status(result),
            result == YD_POLICY_CONFLICT ? "request_id_conflict" : "policy_receipt_unavailable");
    }
    const char *match = request->if_match, *none = request->if_none_match;
    uint64_t expected_version = 0;
    bool disabling = !strcmp(request->method, "DELETE");
    if ((match && none) || (!match && !none) || (match && !version(match, &expected_version)) ||
        (none && strcmp(none, "*")) || (disabling && (none || request->length)) ||
        (!disabling && (!request->body || !request->length))) {
        yd_disk_abort(txn);
        return yd_disk_error_reply(400, "invalid_policy_precondition_or_source");
    }
    YDPolicyCatalog *catalog = NULL, *updated = NULL;
    bool present = false;
    result = yd_policy_store_load(txn, work, &catalog, &present, error, sizeof(error));
    if (result != YD_POLICY_OK) {
        yd_disk_abort(txn);
        return yd_disk_error_reply(yd_disk_policy_status(result), "policy_unavailable");
    }
    YDPCEntry old;
    YDPCResult found = yd_policy_catalog_find(catalog, collection, strlen(collection), &old);
    bool exists = found == YD_PC_OK;
    if (found != YD_PC_OK && found != YD_PC_NOT_FOUND) {
        yd_policy_catalog_free(catalog);
        yd_disk_abort(txn);
        return yd_disk_error_reply(503, "policy_unavailable");
    }
    int status = disabling && !exists ? 404 :
        ((none && exists) || (match && (!exists || old.version != expected_version))) ? 412 : 200;
    if (status != 200) {
        yd_policy_catalog_free(catalog);
        yd_disk_abort(txn);
        return yd_disk_error_reply(status, status == 404 ? "policy_not_found" : "policy_changed");
    }
    result = yd_policy_receipt_admit(txn, 0, error, sizeof(error));
    if (result != YD_POLICY_OK) {
        yd_policy_catalog_free(catalog);
        yd_disk_abort(txn);
        return yd_disk_error_reply(yd_disk_policy_status(result), "policy_receipt_capacity");
    }
    YDPCInfo info;
    if (yd_policy_catalog_info(catalog, &info) != YD_PC_OK) {
        yd_policy_catalog_free(catalog);
        yd_disk_abort(txn);
        return yd_disk_error_reply(503, "policy_unavailable");
    }
    YDPCChange change = {.collection = collection, .collection_length = strlen(collection),
        .operation = disabling ? YD_PC_DISABLE : YD_PC_SET,
        .source = disabling ? NULL : request->body,
        .source_length = disabling ? 0 : request->length,
        .expected = {.generation = info.generation, .version = exists ? old.version : 0}};
    memcpy(change.expected.catalog_sha256, info.catalog_sha256, 32);
    yd_policy_catalog_free(catalog);
    result = yd_policy_store_change(txn, &change, work, &updated, error, sizeof(error));
    if (result != YD_POLICY_OK) {
        yd_disk_abort(txn);
        return yd_disk_error_reply(yd_disk_policy_status(result), "policy_rejected");
    }
    bool built = mutation_reply(txn, updated, collection, !exists, &saved);
    yd_policy_catalog_free(updated);
    /* Allocate the exact transport reply BEFORE publication. A post-commit
     * allocation failure must not manufacture a different successful reply. */
    YDDiskReply reply = built ? stored_reply(&saved) :
        yd_disk_error_reply(503, "serialization_failed");
    if (!built || reply.status != saved.status) {
        yd_disk_abort(txn);
        return reply;
    }
    if (prepared) {
        result = yd_policy_receipt_put(txn, id, digest, &saved, error, sizeof(error));
        if (result != YD_POLICY_OK) {
            yd_disk_abort(txn);
            yd_disk_reply_free(&reply);
            return yd_disk_error_reply(yd_disk_policy_status(result), "policy_receipt_unavailable");
        }
        *prepared = txn;
        return reply;
    }
    result = yd_policy_store_commit(txn, id, digest, &saved, error, sizeof(error));
    if (result != YD_POLICY_OK) {
        yd_disk_reply_free(&reply);
        return yd_disk_error_reply(yd_disk_policy_status(result), "policy_commit_unavailable");
    }
    return reply;
}

YDDiskReply yd_disk_policy_api_request(YDDisk *disk, const YDDiskView *view,
    const char *method, const char *target, const unsigned char *body, size_t length,
    const char *match, const char *none, const unsigned char id[16]) {
    if (!disk || !view || !method || !target || (length && !body) ||
        strncmp(target, prefix, sizeof(prefix) - 1))
        return yd_disk_error_reply(400, "invalid_policy_path");
    const char *collection = target + sizeof(prefix) - 1;
    if (!yamldb_valid_name(collection) || !strcmp(collection, YD_POLICY_COLLECTION))
        return yd_disk_error_reply(400, "invalid_collection");
    bool read = !strcmp(method, "GET") || !strcmp(method, "HEAD");
    if (!read && strcmp(method, "PUT") && strcmp(method, "DELETE"))
        return yd_disk_error_reply(405, "method_not_allowed");
    /* Structural catalog reads also serve activation/preservation. Operational
     * dispatch additionally requires the handle's immutable protocol support. */
    if (!yd_policy_store_capable(disk))
        return yd_disk_error_reply(422, "schema_policy_unsupported");
    YDPolicyWork work;
    yd_policy_work_init(&work, true);
    if (read) {
        if (match || none || length) return yd_disk_error_reply(400, "invalid_policy_read");
        return read_policy(disk, view, collection, &work);
    }
    YDPolicyRequest request = {.method = method, .target = target, .if_match = match,
        .if_none_match = none, .body = body, .length = length};
    return change_policy(disk, collection, &request, id, &work, NULL);
}

YDDiskReply yd_disk_policy_api_prepare(YDDisk *disk, const char *method, const char *target,
    const unsigned char *body, size_t length, const char *match, const char *none,
    const unsigned char id[16], YDDiskTxn **prepared) {
    if (prepared) *prepared = NULL;
    if (!prepared || !disk || !method || !target || (length && !body) ||
        strncmp(target, prefix, sizeof(prefix) - 1))
        return yd_disk_error_reply(400, "invalid_policy_path");
    const char *collection = target + sizeof(prefix) - 1;
    if (!yamldb_valid_name(collection) || !strcmp(collection, YD_POLICY_COLLECTION))
        return yd_disk_error_reply(400, "invalid_collection");
    if (strcmp(method, "PUT") && strcmp(method, "DELETE"))
        return yd_disk_error_reply(405, "method_not_allowed");
    if (!yd_policy_store_capable(disk))
        return yd_disk_error_reply(422, "schema_policy_unsupported");
    YDPolicyWork work;
    yd_policy_work_init(&work, true);
    YDPolicyRequest request = {.method = method, .target = target, .if_match = match,
        .if_none_match = none, .body = body, .length = length};
    return change_policy(disk, collection, &request, id, &work, prepared);
}
