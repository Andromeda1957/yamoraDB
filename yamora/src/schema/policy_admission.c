#define _POSIX_C_SOURCE 200809L
#include "policy_admission.h"
#include "policy_profile.h"
#include "../disk_documents.h"
#include "../disk_internal.h"
#include <stdlib.h>
#include <string.h>

struct YDPolicyAdmission {
    YDPolicyCatalog *catalog;
    YDPolicyWork *work;
    size_t count;
    YDPolicyProgram *programs[YD_PC_ENTRY_LIMIT];
};
static YDPolicyResult fail(YDPolicyResult result, char *error, size_t length,
                           const char *message) {
    yd_disk_error(error, length, message);
    return result;
}
static bool charge(YDPolicyWork *work, uint64_t cost) {
    if (cost > work->catalog.work_left) {
        work->catalog.work_left = 0;
        return false;
    }
    work->catalog.work_left -= cost;
    return true;
}
static YDPolicyResult compile(const unsigned char *source, size_t size,
    YDPolicyWork *work, bool stored, YDSchema **schema, char *error, size_t length) {
    if (schema) *schema = NULL;
    if (!source || !work || !schema)
        return fail(YD_POLICY_INVALID, error, length, "missing policy compilation arguments");
    if (!work->compilations_left)
        return fail(YD_POLICY_LIMIT, error, length, "policy compilation count exhausted");
    work->compilations_left--;
    if (size > work->compile_bytes_left) {
        work->compile_bytes_left = 0;
        return fail(YD_POLICY_LIMIT, error, length, "policy compilation bytes exhausted");
    }
    work->compile_bytes_left -= size;
    YDSchemaResult result = yd_schema_compile(source, size, schema, NULL);
    switch (result) {
    case YD_SCHEMA_OK: return YD_POLICY_OK;
    case YD_SCHEMA_LIMIT:
        return fail(stored ? YD_POLICY_CORRUPT : YD_POLICY_LIMIT,
                    error, length, "policy program exceeds profile limits");
    case YD_SCHEMA_UNSUPPORTED:
        return fail(stored ? YD_POLICY_CORRUPT : YD_POLICY_UNSUPPORTED,
                    error, length, "unsupported policy program");
    case YD_SCHEMA_INVALID:
        return fail(stored ? YD_POLICY_CORRUPT : YD_POLICY_INVALID,
                    error, length, "invalid policy program");
    default: return fail(YD_POLICY_ERROR, error, length, "policy compiler unavailable");
    }
}
static YDPolicyResult compile_program(const YDPCEntry *entry, YDPolicyWork *work,
    bool stored, YDPolicyProgram **program, char *error, size_t length) {
    *program = NULL;
    if (!work->compilations_left)
        return fail(YD_POLICY_LIMIT, error, length, "policy compilation count exhausted");
    work->compilations_left--;
    if (entry->source_length > work->compile_bytes_left) {
        work->compile_bytes_left = 0;
        return fail(YD_POLICY_LIMIT, error, length, "policy compilation bytes exhausted");
    }
    work->compile_bytes_left -= entry->source_length;
    YDSchemaResult result = yd_policy_program_compile(entry->profile, entry->source,
        entry->source_length, program);
    if (result == YD_SCHEMA_OK) return YD_POLICY_OK;
    if (result == YD_SCHEMA_ERROR)
        return fail(YD_POLICY_ERROR, error, length, "policy compiler unavailable");
    return fail(stored ? YD_POLICY_CORRUPT : result == YD_SCHEMA_LIMIT ? YD_POLICY_LIMIT :
        result == YD_SCHEMA_UNSUPPORTED ? YD_POLICY_UNSUPPORTED : YD_POLICY_INVALID,
        error, length, "policy program rejected");
}
YDPolicyResult yd_policy_admission_compile(const unsigned char *source, size_t size,
    YDPolicyWork *work, YDSchema **schema, char *error, size_t length) {
    return compile(source, size, work, false, schema, error, length);
}
static YDPolicyResult check(const YDPolicyProgram *schema, const YDValue *value,
    YDPolicyWork *work, char *error, size_t length) {
    YDSchemaResult result = yd_policy_program_check(schema, value, &work->shape);
    if (result == YD_SCHEMA_OK) return YD_POLICY_OK;
    if (result == YD_SCHEMA_LIMIT)
        return fail(YD_POLICY_LIMIT, error, length, "schema admission work exhausted");
    if (result == YD_SCHEMA_INVALID)
        return fail(YD_POLICY_REJECTED, error, length, "document violates collection policy");
    return fail(YD_POLICY_CORRUPT, error, length, "schema admission unavailable");
}
void yd_policy_admission_free(YDPolicyAdmission *admission) {
    if (!admission) return;
    for (size_t i = 0; i < admission->count; i++) yd_policy_program_free(admission->programs[i]);
    yd_policy_catalog_free(admission->catalog);
    free(admission);
}
YDPolicyResult yd_policy_admission_begin(YDDiskTxn *txn, YDPolicyWork *work,
    YDPolicyAdmission **admission, char *error, size_t length) {
    if (admission) *admission = NULL;
    if (!txn || txn->failed || !work || !admission)
        return fail(YD_POLICY_INVALID, error, length, "missing schema admission arguments");
    YDPolicyAdmission *owned = calloc(1, sizeof(*owned));
    if (!owned) return fail(YD_POLICY_ERROR, error, length, "schema admission allocation failed");
    owned->work = work;
    bool present = false;
    YDPolicyResult result = yd_policy_store_load(txn, work, &owned->catalog, &present, error, length);
    YDPCInfo info;
    if (result == YD_POLICY_OK && yd_policy_catalog_info(owned->catalog, &info) != YD_PC_OK)
        result = YD_POLICY_CORRUPT;
    if (result == YD_POLICY_OK) owned->count = info.count;
    for (size_t i = 0; result == YD_POLICY_OK && i < owned->count; i++) {
        YDPCEntry entry;
        if (yd_policy_catalog_at(owned->catalog, i, &entry) != YD_PC_OK) {
            result = YD_POLICY_CORRUPT;
            break;
        }
        if (entry.mode == YD_PC_ENFORCE)
            result = compile_program(&entry, work, true,
                              &owned->programs[i], error, length);
    }
    if (result != YD_POLICY_OK) {
        yd_policy_admission_free(owned);
        return result;
    }
    *admission = owned;
    return YD_POLICY_OK;
}
YDPolicyResult yd_policy_admission_check(YDPolicyAdmission *admission,
    const char *collection, const YDValue *final_value, char *error, size_t length) {
    if (!admission || !collection || !yamldb_valid_name(collection) || !final_value)
        return fail(YD_POLICY_INVALID, error, length, "invalid schema admission value");
    size_t size = strlen(collection);
    for (size_t i = 0; i < admission->count; i++) {
        YDPCEntry entry;
        if (yd_policy_catalog_at(admission->catalog, i, &entry) != YD_PC_OK)
            return fail(YD_POLICY_CORRUPT, error, length, "schema policy unavailable");
        if (entry.collection_length == size && !memcmp(entry.collection, collection, size))
            return admission->programs[i] ? check(admission->programs[i], final_value,
                admission->work, error, length) : YD_POLICY_OK;
    }
    return YD_POLICY_OK;
}
static YDPolicyResult scan(YDDisk *disk, const YDDiskView *view, YDDiskTxn *txn,
    const YDPCEntry *entry, YDPolicyWork *work, YDDiskValidation *state, char *error, size_t length) {
    if (!disk || !view || !entry || !work || !entry->collection ||
        strnlen(entry->collection, YAMLDB_NAME_LIMIT + 1) != entry->collection_length ||
        !yamldb_valid_name(entry->collection) || !strcmp(entry->collection, YD_POLICY_COLLECTION))
        return fail(YD_POLICY_INVALID, error, length, "invalid policy scan arguments");
    if (entry->mode == YD_PC_OFF) return YD_POLICY_OK;
    if (entry->mode != YD_PC_ENFORCE)
        return fail(YD_POLICY_CORRUPT, error, length, "invalid stored policy mode");
    YDPolicyProgram *schema = NULL;
    YDPolicyResult result = compile_program(entry, work, false,
                                    &schema, error, length);
    if (result != YD_POLICY_OK) return result;
    unsigned char prefix[YD_DISK_KEY_LIMIT], key[YD_DISK_KEY_LIMIT];
    size_t prefix_size = yd_disk_document_key(prefix, entry->collection, NULL);
    if (!charge(work, 1)) {
        yd_policy_program_free(schema);
        return fail(YD_POLICY_LIMIT, error, length, "policy scan work exhausted");
    }
    YDDiskCursor *cursor = txn
        ? yd_disk_tx_cursor(txn, prefix, prefix_size, false, error, length)
        : yd_disk_cursor(disk, view, prefix, prefix_size, false, error, length);
    if (!cursor) result = YD_POLICY_ERROR;
    while (result == YD_POLICY_OK) {
        if (!yd_disk_validation_step(state, YD_VALIDATE_APPLICATION)) {
            result = fail(YD_POLICY_ERROR, error, length, "policy validation cancelled");
            break;
        }
        if (!charge(work, 1 + sizeof(key))) {
            result = fail(YD_POLICY_LIMIT, error, length, "policy scan work exhausted");
            break;
        }
        size_t size = 0;
        uint64_t record = 0;
        int next = yd_disk_next(cursor, key, sizeof(key), &size, &record, error, length);
        if (next < 0) { result = YD_POLICY_CORRUPT; break; }
        if (!next || size < prefix_size || memcmp(key, prefix, prefix_size)) break;
        if (!work->documents_left || !work->source_bytes_left) {
            result = fail(YD_POLICY_LIMIT, error, length, "policy scan document or source limit exhausted");
            break;
        }
        work->documents_left--;
        size_t source_size = 0;
        if (!yd_disk_document_source_length(disk, view, record, &source_size, error, length)) {
            result = YD_POLICY_CORRUPT;
            break;
        }
        if (source_size > work->source_bytes_left) {
            work->source_bytes_left = 0;
            result = fail(YD_POLICY_LIMIT, error, length, "policy scan source limit exhausted");
            break;
        }
        work->source_bytes_left -= source_size;
        YDDiskDocument document = {0};
        if (!yd_disk_document_at(disk, view, record, &document, error, length)) {
            result = YD_POLICY_CORRUPT;
            break;
        }
        bool identity = !strcmp(document.collection, entry->collection) &&
            strlen(document.id) == size - prefix_size &&
            !memcmp(document.id, key + prefix_size, size - prefix_size);
        if (!identity)
            result = fail(YD_POLICY_CORRUPT, error, length, "policy scan document identity mismatch");
        else if (document.length != source_size)
            result = fail(YD_POLICY_CORRUPT, error, length, "policy scan source length changed");
        else
            result = check(schema, document.value, work, error, length);
        yd_disk_document_free(&document);
    }
    yd_disk_cursor_free(cursor);
    yd_policy_program_free(schema);
    return result;
}
YDPolicyResult yd_policy_admission_scan(YDDiskTxn *txn, const YDPCEntry *entry,
    YDPolicyWork *work, char *error, size_t length) {
    if (!txn || !txn->exclusive || txn->failed)
        return fail(YD_POLICY_UNSUPPORTED, error, length, "policy scan requires maintenance transaction");
    YDDiskView view = txn->view;
    view.end = txn->next;
    return scan(txn->disk, &view, txn, entry, work, NULL, error, length);
}
static YDPolicyResult receipts(YDDisk *disk, const YDDiskView *view, YDDiskTxn *txn,
    YDPolicyWork *work, YDDiskValidation *state, char *error, size_t length) {
    static const unsigned char prefix[] = {0, 'Y', 'S', 'P'};
    if (!charge(work, 1)) return YD_POLICY_LIMIT;
    YDDiskCursor *cursor = txn
        ? yd_disk_tx_cursor(txn, prefix, sizeof(prefix), false, error, length)
        : yd_disk_cursor(disk, view, prefix, sizeof(prefix), false, error, length);
    if (!cursor) return YD_POLICY_ERROR;
    YDPolicyResult result = YD_POLICY_OK;
    for (;;) {
        if (!yd_disk_validation_step(state, YD_VALIDATE_APPLICATION)) { result = YD_POLICY_ERROR; break; }
        unsigned char key[YD_DISK_KEY_LIMIT], bytes[YD_POLICY_RECEIPT_LIMIT], digest[32];
        YDPolicyReply reply;
        size_t size = 0;
        uint64_t offset = 0;
        if (!charge(work, 1 + sizeof(key))) { result = YD_POLICY_LIMIT; break; }
        int next = yd_disk_next(cursor, key, sizeof(key), &size, &offset, error, length);
        if (next < 0) { result = YD_POLICY_CORRUPT; break; }
        if (!next || size < sizeof(prefix) || memcmp(key, prefix, sizeof(prefix))) break;
        if (size != YD_POLICY_RECEIPT_KEY_SIZE) { result = YD_POLICY_CORRUPT; break; }
        if (!charge(work, sizeof(bytes))) { result = YD_POLICY_LIMIT; break; }
        if (!yd_disk_record_into(disk, view, offset, bytes, sizeof(bytes), &size, error, length)) {
            result = YD_POLICY_CORRUPT;
            break;
        }
        result = yd_policy_receipt_decode(bytes, size, key + sizeof(prefix), digest, &reply,
                                          error, length);
        if (result != YD_POLICY_OK) break;
    }
    yd_disk_cursor_free(cursor);
    if (result != YD_POLICY_OK) fail(result, error, length, "policy receipt validation failed");
    return result;
}
static YDPolicyResult validate(YDDisk *disk, const YDDiskView *view, YDDiskTxn *txn,
    YDPolicyWork *work, YDDiskValidation *state, char *error, size_t length) {
    YDPolicyCatalog *catalog = NULL;
    bool present = false;
    YDPolicyResult result = txn ? yd_policy_store_load(txn, work, &catalog, &present, error, length)
                               : yd_policy_store_at(disk, view, work, &catalog, &present, error, length);
    YDPCInfo info;
    if (result == YD_POLICY_OK && yd_policy_catalog_info(catalog, &info) != YD_PC_OK)
        result = YD_POLICY_CORRUPT;
    for (size_t i = 0; result == YD_POLICY_OK && i < info.count; i++) {
        if (!yd_disk_validation_step(state, YD_VALIDATE_APPLICATION)) { result = YD_POLICY_ERROR; break; }
        YDPCEntry entry;
        if (yd_policy_catalog_at(catalog, i, &entry) != YD_PC_OK) { result = YD_POLICY_CORRUPT; break; }
        if (entry.mode == YD_PC_ENFORCE) result = scan(disk, view, txn, &entry, work, state, error, length);
    }
    yd_policy_catalog_free(catalog);
    return result == YD_POLICY_OK ? receipts(disk, view, txn, work, state, error, length) : result;
}
YDPolicyResult yd_policy_admission_validate_root(YDDiskTxn *txn, YDPolicyWork *work,
    char *error, size_t length) {
    return yd_policy_admission_validate_root_cancellable(txn, work, NULL, error, length);
}
YDPolicyResult yd_policy_admission_validate_root_cancellable(YDDiskTxn *txn, YDPolicyWork *work,
    YDDiskValidation *state, char *error, size_t length) {
    if (!txn || !txn->exclusive || txn->failed || !work)
        return fail(YD_POLICY_INVALID, error, length, "invalid staged policy validation");
    YDDiskView view = txn->view;
    view.end = txn->next;
    return validate(txn->disk, &view, txn, work, state, error, length);
}
YDPolicyResult yd_policy_validate_view(YDDisk *disk, const YDDiskView *view,
    YDPolicyWork *work, char *error, size_t length) {
    return yd_policy_validate_view_cancellable(disk, view, work, NULL, error, length);
}
YDPolicyResult yd_policy_validate_view_cancellable(YDDisk *disk, const YDDiskView *view,
    YDPolicyWork *work, YDDiskValidation *state, char *error, size_t length) {
    if (!disk || !view || !work)
        return fail(YD_POLICY_INVALID, error, length, "invalid immutable policy validation");
    return validate(disk, view, NULL, work, state, error, length);
}
