#define _POSIX_C_SOURCE 200809L
#include "disk_documents.h"
#include "disk_internal.h"
#include "binary.h"
#include "schema/policy_admission.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TX_MEMORY_LIMIT (64U * 1024U * 1024U)
size_t yd_disk_collection_key(unsigned char key[YD_DISK_KEY_LIMIT], const char *collection) {
    size_t n = strlen(collection);
    if (!yamldb_valid_name(collection))
        return 0;
    key[0] = 'C';
    memcpy(key + 1, collection, n);
    return n + 1;
}
size_t yd_disk_document_key(unsigned char key[YD_DISK_KEY_LIMIT], const char *collection,
                            const char *id) {
    if (!yamldb_valid_name(collection) || (id && !yamldb_valid_name(id)))
        return 0;
    size_t c = strlen(collection), d = id ? strlen(id) : 0;
    key[0] = 'D';
    memcpy(key + 1, collection, c);
    key[c + 1] = 0;
    if (d)
        memcpy(key + c + 2, id, d);
    return c + d + 2;
}
static uint64_t hash_more(uint64_t hash, const void *data, size_t size) {
    const unsigned char *p = data;
    for (size_t i = 0; i < size; i++) {
        hash ^= p[i];
        hash *= UINT64_C(1099511628211);
    }
    return hash;
}
uint64_t yd_disk_source_hash(const void *body, size_t size) {
    return hash_more(UINT64_C(1469598103934665603), body, size);
}
uint64_t yd_disk_fingerprint(const char *collection, const char *id, const void *body,
                             size_t size) {
    unsigned char sizes[24];
    size_t a = strlen(collection), b = id ? strlen(id) : 0;
    yd_disk_set64(sizes, a);
    yd_disk_set64(sizes + 8, b);
    yd_disk_set64(sizes + 16, size);
    uint64_t hash = hash_more(UINT64_C(1469598103934665603), sizes, sizeof(sizes));
    hash = hash_more(hash, collection, a);
    if (id)
        hash = hash_more(hash, id, b);
    if (size)
        hash = hash_more(hash, body, size);
    return hash;
}
void yd_disk_revision(const YDDiskView *view, char revision[17]) {
    (void)snprintf(revision, 17, "%016llx", (unsigned long long)view->revision);
}
void yd_disk_document_free(YDDiskDocument *document) {
    if (!document)
        return;
    if (document->owns_body)
        free(document->body);
    yd_free(document->value);
    memset(document, 0, sizeof(*document));
}
static uint32_t document_u32(const unsigned char *p) {
    return (uint32_t)yd_disk_u16(p) | (uint32_t)yd_disk_u16(p + 2) << 16;
}
bool yd_disk_document_source_length(YDDisk *disk, const YDDiskView *view, uint64_t record,
    size_t *source_length, char *error, size_t length) {
    if (source_length) *source_length = 0;
    unsigned char prefix[12 + 2 * YAMLDB_NAME_LIMIT + 20];
    size_t size = 0;
    if (!source_length || !yd_disk_record_prefix(disk, view, record, prefix,
            sizeof(prefix), &size, error, length)) return false;
    bool valid = size >= 12 && !memcmp(prefix, "YDDOC002", 8);
    size_t c = valid ? yd_disk_u16(prefix + 8) : 0;
    size_t d = valid ? yd_disk_u16(prefix + 10) : 0;
    valid = valid && c && d && c <= YAMLDB_NAME_LIMIT && d <= YAMLDB_NAME_LIMIT &&
            size >= 12 + c + d + 24;
    if (!valid) return yd_disk_error(error, length, "invalid native document metadata");
    const unsigned char *packed = prefix + 12 + c + d;
    bool extended = !memcmp(packed, "YAMDOC02", 8);
    size_t n = document_u32(packed + 8), m = document_u32(packed + 12);
    if ((extended && view->format < 5) ||
        (!extended && memcmp(packed, "YAMDOC01", 8)) || document_u32(packed + 16) ||
        !n || n > (extended ? YD_LARGE_DOCUMENT_LIMIT : YD_DOCUMENT_LIMIT) ||
        m > (extended ? YD_BINARY_LARGE_VALUE_LIMIT : YD_BINARY_VALUE_LIMIT) ||
        size - 12 - c - d != 24 + n + m)
        return yd_disk_error(error, length, "invalid native document source length");
    *source_length = n;
    return true;
}
bool yd_disk_document_at(YDDisk *disk, const YDDiskView *view, uint64_t record, YDDiskDocument *doc,
                         char *error, size_t length) {
    memset(doc, 0, sizeof(*doc));
    size_t size = 0;
    unsigned char *bytes = yd_disk_record(disk, view, record, &size, error, length);
    if (!bytes)
        return false;
    bool valid = size >= 12 && !memcmp(bytes, "YDDOC002", 8);
    size_t c = valid ? yd_disk_u16(bytes + 8) : 0, d = valid ? yd_disk_u16(bytes + 10) : 0;
    valid =
        valid && c && d && c <= YAMLDB_NAME_LIMIT && d <= YAMLDB_NAME_LIMIT && 12 + c + d < size;
    if (valid) {
        memcpy(doc->collection, bytes + 12, c);
        memcpy(doc->id, bytes + 12 + c, d);
        valid = yamldb_valid_name(doc->collection) && yamldb_valid_name(doc->id) &&
                yd_binary_unpack_profile(bytes + 12 + c + d, size - 12 - c - d, view->format >= 5, &doc->body, &doc->length,
                                 &doc->value);
    }
    free(bytes);
    if (!valid) {
        yd_disk_document_free(doc);
        return yd_disk_error(error, length, "invalid native document record");
    }
    doc->owns_body = true;
    doc->record = record;
    doc->hash = yd_disk_source_hash(doc->body, doc->length);
    return true;
}
int yd_disk_document_get(YDDisk *disk, const YDDiskView *view, const char *collection,
                         const char *id, YDDiskDocument *doc, char *error, size_t length) {
    memset(doc, 0, sizeof(*doc));
    unsigned char key[YD_DISK_KEY_LIMIT];
    size_t size = yd_disk_document_key(key, collection, id);
    uint64_t record = 0;
    if (!size || !id) {
        yd_disk_error(error, length, "invalid document identifier");
        return -1;
    }
    int result = yd_disk_get(disk, view, key, size, &record, error, length);
    if (result <= 0)
        return result;
    if (!yd_disk_document_at(disk, view, record, doc, error, length))
        return -1;
    if (strcmp(doc->collection, collection) || strcmp(doc->id, id)) {
        yd_disk_document_free(doc);
        yd_disk_error(error, length, "document key/record mismatch");
        return -1;
    }
    return 1;
}
int yd_disk_document_tx_get(YDDiskTxn *txn, const char *collection, const char *id,
                            YDDiskDocument *doc, char *error, size_t length) {
    memset(doc, 0, sizeof(*doc));
    unsigned char key[YD_DISK_KEY_LIMIT];
    size_t size = yd_disk_document_key(key, collection, id);
    uint64_t record = 0;
    if (!size || !id)
        return -1;
    int result = yd_disk_tx_get(txn, key, size, &record, error, length);
    if (result <= 0)
        return result;
    YDDiskView view = txn->view;
    view.end = txn->next;
    if (!yd_disk_document_at(txn->disk, &view, record, doc, error, length))
        return -1;
    if (strcmp(doc->collection, collection) || strcmp(doc->id, id)) {
        yd_disk_document_free(doc);
        return -1;
    }
    return 1;
}
bool yd_disk_create_collection(YDDiskTxn *txn, const char *collection, char *error, size_t length) {
    txn->log_enabled = true;
    unsigned char key[YD_DISK_KEY_LIMIT];
    size_t size = yd_disk_collection_key(key, collection);
    uint64_t count = 0;
    if (!size)
        return yd_disk_error(error, length, "invalid collection");
    int result = yd_disk_tx_peek(txn, key, size, &count, error, length);
    if (result < 0)
        return false;
    if (result)
        return true;
    if (txn->view.collections >= YD_DISK_COLLECTION_LIMIT)
        return yd_disk_error(error, length, "collection catalog exceeds its capacity");
    if (!yd_disk_put(txn, key, size, 0, error, length))
        return false;
    txn->view.collections++;
    txn->view.revision ^= yd_disk_fingerprint(collection, NULL, NULL, 0);
    return yd_disk_log_capture(txn, key, size, 0, 1, 0, error, length);
}
bool yd_disk_drop_collection(YDDiskTxn *txn, const char *collection, char *error, size_t length) {
    unsigned char key[YD_DISK_KEY_LIMIT];
    size_t size = yd_disk_collection_key(key, collection);
    uint64_t count = 0;
    if (!size)
        return yd_disk_error(error, length, "invalid collection");
    int result = yd_disk_tx_peek(txn, key, size, &count, error, length);
    if (result < 0)
        return false;
    if (!result || count || !txn->view.collections)
        return yd_disk_error(error, length, "collection drop requires an existing empty collection");
    /* Deleting the counter key makes its optimistic record a strict compare
     * of the reviewed count, so a concurrent insert here forces a retry. */
    if (!yd_disk_delete(txn, key, size, error, length))
        return false;
    txn->view.collections--;
    txn->view.revision ^= yd_disk_fingerprint(collection, NULL, NULL, 0);
    yd_disk_log_free(txn);
    txn->log_enabled = txn->log_reset = true;
    return true;
}
bool yd_disk_write_document(YDDiskTxn *txn, const YDDiskDocument *old, YDDiskDocument *replacement,
                            char *error, size_t length) {
    const YDDiskDocument *identity = replacement ? replacement : old;
    if (!identity)
        return true;
    unsigned char key[YD_DISK_KEY_LIMIT], collection_key[YD_DISK_KEY_LIMIT];
    size_t key_size = yd_disk_document_key(key, identity->collection, identity->id);
    size_t collection_size = yd_disk_collection_key(collection_key, identity->collection);
    uint64_t count = 0;
    if (!key_size || !collection_size ||
        !yd_disk_create_collection(txn, identity->collection, error, length) ||
        yd_disk_tx_peek(txn, collection_key, collection_size, &count, error, length) != 1)
        return false;
    if (replacement) {
        size_t packed_size = 0;
        unsigned char *packed =
            yd_binary_pack_profile(replacement->body, replacement->length, txn->view.format >= 5, &packed_size, error, length);
        if (!packed)
            return false;
        size_t c = strlen(replacement->collection), d = strlen(replacement->id),
               total = 12 + c + d + packed_size;
        unsigned char *bytes = malloc(total);
        if (!bytes) {
            free(packed);
            return false;
        }
        memcpy(bytes, "YDDOC002", 8);
        yd_disk_set16(bytes + 8, (uint16_t)c);
        yd_disk_set16(bytes + 10, (uint16_t)d);
        memcpy(bytes + 12, replacement->collection, c);
        memcpy(bytes + 12 + c, replacement->id, d);
        memcpy(bytes + 12 + c + d, packed, packed_size);
        free(packed);
        bool valid = yd_disk_append(txn, bytes, total, &replacement->record, error, length);
        free(bytes);
        if (!valid || !yd_disk_put(txn, key, key_size, replacement->record, error, length))
            return false;
    } else if (!yd_disk_delete(txn, key, key_size, error, length))
        return false;
    if (old) {
        if (!count || !txn->view.documents || old->length > txn->view.bytes)
            return yd_disk_error(error, length, "inconsistent document counters");
        count--;
        txn->view.documents--;
        txn->view.bytes -= old->length;
        txn->view.revision ^= yd_disk_fingerprint(old->collection, old->id, old->body, old->length);
    }
    if (replacement) {
        if (txn->view.documents == UINT64_MAX || replacement->length > UINT64_MAX - txn->view.bytes)
            return false;
        count++;
        txn->view.documents++;
        txn->view.bytes += replacement->length;
        txn->view.revision ^= yd_disk_fingerprint(replacement->collection, replacement->id,
                                                  replacement->body, replacement->length);
    }
    int64_t delta = (replacement ? 1 : 0) - (old ? 1 : 0);
    return yd_disk_add(txn, collection_key, collection_size, delta, error, length) &&
           yd_disk_log_capture(txn, key, key_size, old ? old->record : 0,
                               replacement ? replacement->record : 0,
                               replacement ? replacement->length : 0, error, length);
}
/* Delete every document of one collection as ordinary document deletes, so
 * counters, bytes, the revision and index entries stay exact. Reseeking after
 * each removal never walks a tree the deletion changed. The caller drops the
 * then-empty collection in the same commit, which becomes a resnapshot
 * boundary, so per-document change frames are never captured. */
static bool purge_collection(YDDiskTxn *txn, const YDDiskIndexes *indexes, const char *collection,
                             char *error, size_t length) {
    unsigned char prefix[YD_DISK_KEY_LIMIT], key[YD_DISK_KEY_LIMIT];
    size_t prefix_size = yd_disk_document_key(prefix, collection, NULL);
    if (!prefix_size)
        return yd_disk_error(error, length, "invalid collection");
    yd_disk_log_free(txn);
    txn->log_enabled = txn->log_reset = true;
    for (;;) {
        size_t size = 0;
        uint64_t record = 0;
        YDDiskCursor *cursor = yd_disk_tx_cursor(txn, prefix, prefix_size, false, error, length);
        int next = cursor ? yd_disk_next(cursor, key, sizeof(key), &size, &record, error, length) : -1;
        yd_disk_cursor_free(cursor);
        if (next < 0)
            return false;
        if (!next || size <= prefix_size || memcmp(key, prefix, prefix_size))
            return true;
        YDDiskDocument doc;
        YDDiskView view = txn->view;
        view.end = txn->next;
        if (!yd_disk_document_at(txn->disk, &view, record, &doc, error, length))
            return false;
        bool valid = !strcmp(doc.collection, collection) &&
                     size - prefix_size == strlen(doc.id) &&
                     !memcmp(key + prefix_size, doc.id, size - prefix_size);
        if (!valid)
            yd_disk_error(error, length, "document key/record mismatch");
        valid = valid && yd_disk_indexes_change(txn, indexes, &doc, false, error, length) &&
                yd_disk_write_document(txn, &doc, NULL, error, length);
        yd_disk_document_free(&doc);
        if (!valid)
            return false;
    }
}
YDPolicyResult yd_disk_apply_with_policy(YDDiskTxn *txn, const YDWrite *writes,
    size_t count, YDPolicyWork *work, char *error, size_t length) {
    if (!txn || !work || !writes || !count || count > 128) {
        yd_disk_error(error, length, "transaction requires 1..128 operations and a work pool");
        if (txn) txn->failed = true;
        return YD_POLICY_INVALID;
    }
    YDPolicyResult result = YD_POLICY_INVALID;
    YDDiskDocument *old = calloc(count, sizeof(*old)), *fresh = calloc(count, sizeof(*fresh));
    bool valid = old && fresh;
    size_t memory = 0;
    YDDiskIndexes *indexes = valid ? yd_disk_indexes_load_tx(txn, error, length) : NULL;
    if (!indexes)
        valid = false;
    for (size_t i = 0; valid && i < count; i++) {
        const YDWrite *write = &writes[i];
        if (!write->collection || !yamldb_valid_name(write->collection)) {
            valid = false;
            break;
        }
        if (write->kind == YD_WRITE_CREATE_COLLECTION || write->kind == YD_WRITE_DELETE_COLLECTION ||
            write->kind == YD_WRITE_PURGE_COLLECTION) {
            valid = write->document == NULL && write->body == NULL && !write->length;
            if (!valid)
                break;
            continue;
        }
        if (write->kind != YD_WRITE_DOCUMENT || !write->document ||
            !yamldb_valid_name(write->document)) {
            valid = false;
            break;
        }
        if (!strcmp(write->collection, YD_POLICY_COLLECTION) &&
            !strcmp(write->document, YD_POLICY_DOCUMENT)) {
            yd_disk_error(error, length, "policy catalog requires administrative publication");
            result = YD_POLICY_UNSUPPORTED;
            valid = false;
            break;
        }
        for (size_t j = 0; j < i; j++)
            if (writes[j].document && !strcmp(writes[j].collection, write->collection) &&
                !strcmp(writes[j].document, write->document))
                valid = false;
        if (!valid)
            break;
        int found = yd_disk_document_tx_get(txn, write->collection, write->document, &old[i], error,
                                            length);
        if (found < 0) {
            valid = false;
            break;
        }
        memory += old[i].length + yd_memory(old[i].value);
        if (write->body) {
            YDDiskDocument *doc = &fresh[i];
            memcpy(doc->collection, write->collection, strlen(write->collection) + 1);
            memcpy(doc->id, write->document, strlen(write->document) + 1);
            doc->body = (unsigned char *)write->body;
            doc->length = write->length;
            doc->value = yd_parse_sized(write->body, write->length, YD_DISK_DOCUMENT_LIMIT(txn->view.format), error, length);
            doc->hash = yd_disk_source_hash(doc->body, doc->length);
            if (!doc->value) {
                valid = false;
                break;
            }
            memory += doc->length + yd_memory(doc->value);
        } else if (write->length) {
            valid = false;
            break;
        }
        if (memory > (txn->view.format >= 5 ? 2U * TX_MEMORY_LIMIT : TX_MEMORY_LIMIT)) {
            yd_disk_error(error, length, "transaction working memory exceeds profile limit");
            valid = false;
            result = YD_POLICY_LIMIT;
        }
    }
    YDPolicyAdmission *admission = NULL;
    if (valid) {
        result = yd_policy_admission_begin(txn, work, &admission, error, length);
        valid = result == YD_POLICY_OK;
    }
    for (size_t i = 0; valid && i < count; i++)
        if (fresh[i].value) {
            result = yd_policy_admission_check(admission, fresh[i].collection,
                                                fresh[i].value, error, length);
            valid = result == YD_POLICY_OK;
        }
    yd_policy_admission_free(admission);
    /* Further errors belong to the existing native/index validators. */
    if (valid) result = YD_POLICY_INVALID;
    /* Remove every old key first so valid unique-key swaps are atomic. */
    for (size_t i = 0; valid && i < count; i++)
        if (old[i].value)
            valid = yd_disk_indexes_change(txn, indexes, &old[i], false, error, length);
    for (size_t i = 0; valid && i < count; i++) {
        if (writes[i].kind == YD_WRITE_DELETE_COLLECTION ||
            writes[i].kind == YD_WRITE_PURGE_COLLECTION)
            continue;
        if (writes[i].kind == YD_WRITE_CREATE_COLLECTION)
            valid = yd_disk_create_collection(txn, writes[i].collection, error, length);
        else
            valid = yd_disk_write_document(txn, old[i].value ? &old[i] : NULL,
                                           fresh[i].value ? &fresh[i] : NULL, error, length);
    }
    for (size_t i = 0; valid && i < count; i++)
        if (fresh[i].value)
            valid = yd_disk_indexes_change(txn, indexes, &fresh[i], true, error, length);
    /* Drops follow every document write, so each sees its final count. */
    for (size_t i = 0; valid && i < count; i++)
        if (writes[i].kind == YD_WRITE_DELETE_COLLECTION ||
            writes[i].kind == YD_WRITE_PURGE_COLLECTION)
            valid = (writes[i].kind != YD_WRITE_PURGE_COLLECTION ||
                     purge_collection(txn, indexes, writes[i].collection, error, length)) &&
                    yd_disk_drop_collection(txn, writes[i].collection, error, length);
    if (old)
        for (size_t i = 0; i < count; i++)
            yd_disk_document_free(&old[i]);
    if (fresh)
        for (size_t i = 0; i < count; i++)
            yd_disk_document_free(&fresh[i]);
    free(old);
    free(fresh);
    yd_disk_indexes_free(indexes);
    if (!valid)
        txn->failed = true;
    return valid ? YD_POLICY_OK : txn->capacity_exhausted ? YD_POLICY_ERROR : result;
}
bool yd_disk_apply(YDDiskTxn *txn, const YDWrite *writes, size_t count, char *error,
                   size_t length) {
    YDPolicyWork work;
    yd_policy_work_init(&work, false);
    return yd_disk_apply_with_policy(txn, writes, count, &work, error, length) == YD_POLICY_OK;
}
