#define _POSIX_C_SOURCE 200809L
#include "policy_store.h"
#include "policy_admission.h"
#include "policy_profile.h"
#include "../disk_documents.h"
#include "../disk_internal.h"
#include <stdlib.h>
#include <string.h>

static YDPolicyResult fail(YDPolicyResult result, char *error, size_t length,
                           const char *message) {
    yd_disk_error(error, length, message);
    return result;
}
static YDPolicyResult codec(YDPCResult result, bool stored, char *error, size_t length) {
    switch (result) {
    case YD_PC_OK: return YD_POLICY_OK;
    case YD_PC_NOT_FOUND: return fail(YD_POLICY_ABSENT, error, length, "policy not found");
    case YD_PC_LIMIT: return fail(YD_POLICY_LIMIT, error, length, "policy catalog limit exhausted");
    case YD_PC_CONFLICT: return fail(YD_POLICY_CONFLICT, error, length, "policy catalog guard conflict");
    case YD_PC_INVALID:
        return fail(stored ? YD_POLICY_CORRUPT : YD_POLICY_INVALID,
                    error, length, "invalid policy catalog");
    case YD_PC_UNSUPPORTED:
        return fail(stored ? YD_POLICY_CORRUPT : YD_POLICY_UNSUPPORTED,
                    error, length, "unsupported policy catalog");
    default: return fail(YD_POLICY_ERROR, error, length, "policy catalog unavailable");
    }
}
void yd_policy_work_init(YDPolicyWork *work, bool activation) {
    if (!work) return;
    *work = (YDPolicyWork){
        .catalog = {YD_POLICY_CATALOG_WORK, YD_POLICY_CATALOG_ALLOCATION},
        .shape = {activation ? YD_POLICY_SCAN_WORK : YD_POLICY_MUTATION_WORK},
        .documents_left = YD_POLICY_SCAN_DOCUMENTS,
        .source_bytes_left = YD_POLICY_SCAN_BYTES,
        .compilations_left = YD_POLICY_COMPILE_COUNT,
        .compile_bytes_left = YD_POLICY_COMPILE_BYTES
    };
}
bool yd_policy_store_capable(YDDisk *disk) {
    YDDiskSchemaProfile profile = {0};
    YDDiskView view = disk ? yd_disk_view(disk) : (YDDiskView){0};
    return disk && yd_disk_schema_profile(disk, &profile) &&
           profile.version == YD_DISK_SCHEMA_VERSION &&
           profile.required_protocol == YD_DISK_SCHEMA_PROTOCOL &&
           (view.format == 7 || (view.format == 8 &&
            (yd_disk_capabilities(disk) & YD_DISK_CAP_SCHEMA) &&
            view.capabilities == yd_disk_capabilities(disk)));
}
bool yd_policy_store_view_capable(YDDisk *disk, const YDDiskView *view) {
    YDDiskView actual = disk ? yd_disk_view(disk) : (YDDiskView){0};
    return view && yd_policy_store_capable(disk) && view->format == actual.format &&
        view->capabilities == actual.capabilities;
}
static YDPolicyResult load(YDDisk *disk, const YDDiskView *view, YDDiskTxn *txn,
    YDPolicyWork *work, YDPolicyCatalog **catalog, bool *present, char *error, size_t length) {
    if (catalog) *catalog = NULL;
    if (present) *present = false;
    if (!disk || !view || !work || !catalog || !present)
        return fail(YD_POLICY_INVALID, error, length, "missing policy catalog arguments");
    unsigned char key[YD_DISK_KEY_LIMIT];
    size_t key_size = yd_disk_document_key(key, YD_POLICY_COLLECTION, YD_POLICY_DOCUMENT);
    uint64_t record = 0;
    int found = txn ? yd_disk_tx_get(txn, key, key_size, &record, error, length)
                    : yd_disk_get(disk, view, key, key_size, &record, error, length);
    if (found < 0)
        return fail(YD_POLICY_ERROR, error, length, "policy catalog lookup failed");
    *present = found == 1;
    YDPCProfile profile = view->format >= 5 ? YD_PC_LARGE : YD_PC_ORDINARY;
    if (!found) {
        /* A catalog is never deleted after first use. A surviving receipt is
         * therefore corruption evidence, not an empty-policy interpretation. */
        static const unsigned char prefix[] = {0, 'Y', 'S', 'P'};
        if (work->catalog.work_left < 1 + YD_DISK_KEY_LIMIT) {
            work->catalog.work_left = 0;
            return fail(YD_POLICY_LIMIT, error, length, "policy catalog work exhausted");
        }
        work->catalog.work_left -= 1 + YD_DISK_KEY_LIMIT;
        YDDiskCursor *cursor = txn
            ? yd_disk_tx_cursor(txn, prefix, sizeof(prefix), false, error, length)
            : yd_disk_cursor(disk, view, prefix, sizeof(prefix), false, error, length);
        if (!cursor) return fail(YD_POLICY_ERROR, error, length, "policy receipt witness unavailable");
        unsigned char first[YD_DISK_KEY_LIMIT];
        size_t size = 0;
        uint64_t ignored = 0;
        int next = yd_disk_next(cursor, first, sizeof(first), &size, &ignored, error, length);
        yd_disk_cursor_free(cursor);
        if (next < 0 || (next == 1 && size >= sizeof(prefix) &&
                         !memcmp(first, prefix, sizeof(prefix))))
            return fail(YD_POLICY_CORRUPT, error, length, "policy catalog missing beside receipt evidence");
        return codec(yd_policy_catalog_empty(profile, &work->catalog, catalog, NULL),
                     false, error, length);
    }
    if (txn && !yd_policy_store_view_capable(disk, view))
        return fail(YD_POLICY_UNSUPPORTED, error, length, "policy catalog requires profile 7");
    YDDiskDocument document = {0};
    if (!yd_disk_document_at(disk, view, record, &document, error, length))
        return fail(YD_POLICY_CORRUPT, error, length, "policy catalog record unavailable");
    YDPolicyResult result;
    if (strcmp(document.collection, YD_POLICY_COLLECTION) ||
        strcmp(document.id, YD_POLICY_DOCUMENT))
        result = fail(YD_POLICY_CORRUPT, error, length, "policy catalog record identity mismatch");
    else
        result = codec(yd_policy_catalog_parse(document.body, document.length,
            profile, &work->catalog, catalog, NULL), true, error, length);
    yd_disk_document_free(&document);
    return result;
}
YDPolicyResult yd_policy_store_load(YDDiskTxn *txn, YDPolicyWork *work,
    YDPolicyCatalog **catalog, bool *present, char *error, size_t length) {
    YDDiskView view = txn ? txn->view : (YDDiskView){0};
    if (txn) view.end = txn->next;
    return load(txn ? txn->disk : NULL, &view, txn, work, catalog, present, error, length);
}
YDPolicyResult yd_policy_store_at(YDDisk *disk, const YDDiskView *view,
    YDPolicyWork *work, YDPolicyCatalog **catalog, bool *present, char *error, size_t length) {
    return load(disk, view, NULL, work, catalog, present, error, length);
}
YDPolicyResult yd_policy_store_change(YDDiskTxn *txn, const YDPCChange *change,
    YDPolicyWork *work, YDPolicyCatalog **updated, char *error, size_t length) {
    if (updated) *updated = NULL;
    if (!txn || !change || !work || !updated)
        return fail(YD_POLICY_INVALID, error, length, "missing policy change arguments");
    if (!txn->exclusive || !txn->locked || txn->failed ||
        !yd_policy_store_view_capable(txn->disk, &txn->view)) {
        txn->failed = true;
        return fail(YD_POLICY_UNSUPPORTED, error, length, "policy change requires exclusive profile 7");
    }
    YDPolicyCatalog *base = NULL, *next = NULL;
    YDDiskDocument old = {0}, fresh = {0};
    bool present = false;
    YDPolicyResult result = yd_policy_store_load(txn, work, &base, &present, error, length);
    if (result != YD_POLICY_OK) goto done;
    YDPCChange selected = *change;
    if (change->operation == YD_PC_SET && !change->schema_profile) {
        YDSchemaResult detected = yd_policy_source_profile(change->source,
            change->source_length, &selected.schema_profile);
        if (detected != YD_SCHEMA_OK) {
            result = detected == YD_SCHEMA_ERROR ? YD_POLICY_ERROR :
                detected == YD_SCHEMA_LIMIT ? YD_POLICY_LIMIT :
                detected == YD_SCHEMA_UNSUPPORTED ? YD_POLICY_UNSUPPORTED : YD_POLICY_INVALID;
            goto done;
        }
    }
    result = codec(yd_policy_catalog_change(base, &selected, YD_PC_LARGE,
                    &work->catalog, &next, NULL), false, error, length);
    if (result != YD_POLICY_OK) goto done;
    YDPCEntry entry;
    if (yd_policy_catalog_find(next, change->collection, change->collection_length, &entry) != YD_PC_OK) {
        result = fail(YD_POLICY_ERROR, error, length, "changed policy unavailable");
        goto done;
    }
    result = yd_policy_admission_scan(txn, &entry, work, error, length);
    if (result != YD_POLICY_OK) goto done;
    YDPCInfo info;
    if (yd_policy_catalog_info(next, &info) != YD_PC_OK) {
        result = YD_POLICY_ERROR;
        goto done;
    }
    fresh.body = malloc(info.encoded_bytes);
    fresh.owns_body = true;
    if (!fresh.body) { result = YD_POLICY_ERROR; goto done; }
    result = codec(yd_policy_catalog_encode(next, YD_PC_LARGE, &work->catalog,
                    fresh.body, info.encoded_bytes, &fresh.length, NULL), false, error, length);
    if (result != YD_POLICY_OK) goto done;
    memcpy(fresh.collection, YD_POLICY_COLLECTION, sizeof(YD_POLICY_COLLECTION));
    memcpy(fresh.id, YD_POLICY_DOCUMENT, sizeof(YD_POLICY_DOCUMENT));
    if (yd_disk_document_tx_get(txn, YD_POLICY_COLLECTION, YD_POLICY_DOCUMENT,
                                &old, error, length) != (present ? 1 : 0)) {
        result = fail(YD_POLICY_CORRUPT, error, length, "policy catalog changed during exclusive operation");
        goto done;
    }
    txn->log_enabled = txn->log_reset = true;
    if (!yd_disk_write_document(txn, present ? &old : NULL, &fresh, error, length)) {
        result = fail(YD_POLICY_ERROR, error, length, "policy catalog write failed");
        goto done;
    }
    *updated = next;
    next = NULL;
done:
    yd_disk_document_free(&old);
    yd_disk_document_free(&fresh);
    yd_policy_catalog_free(base);
    yd_policy_catalog_free(next);
    if (result != YD_POLICY_OK) txn->failed = true;
    return result;
}
YDPolicyResult yd_policy_store_commit(YDDiskTxn *txn, const unsigned char id[16],
    const unsigned char digest[32], const YDPolicyReply *reply, char *error, size_t length) {
    if (!txn) return fail(YD_POLICY_INVALID, error, length, "missing policy transaction");
    YDPolicyResult result = YD_POLICY_UNSUPPORTED;
    if (!txn->exclusive || !txn->locked || txn->failed ||
        !yd_policy_store_view_capable(txn->disk, &txn->view)) {
        fail(result, error, length, "policy commit requires exclusive profile 7");
        goto abort;
    }
    unsigned char key[YD_DISK_KEY_LIMIT];
    size_t key_size = yd_disk_document_key(key, YD_POLICY_COLLECTION, YD_POLICY_DOCUMENT);
    uint64_t before = 0, after = 0;
    int prior = yd_disk_get(txn->disk, &txn->base, key, key_size, &before, error, length);
    int current = yd_disk_tx_get(txn, key, key_size, &after, error, length);
    if (prior < 0 || current != 1 || (prior == 1 && before == after)) {
        result = fail(YD_POLICY_INVALID, error, length, "policy receipt requires a catalog change");
        goto abort;
    }
    result = yd_policy_receipt_put(txn, id, digest, reply, error, length);
    if (result != YD_POLICY_OK) goto abort;
    txn->log_enabled = txn->log_reset = true;
    uint64_t expected = txn->view.revision;
    YDDiskView published;
    if (!yd_disk_commit_view(txn, &published, error, length))
        return fail(YD_POLICY_ERROR, error, length, "policy commit failed or has uncertain durability");
    return published.revision == expected ? YD_POLICY_OK :
        fail(YD_POLICY_ERROR, error, length, "policy commit revision mismatch");
abort:
    yd_disk_abort(txn);
    return result;
}
