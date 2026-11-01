#define _POSIX_C_SOURCE 200809L
#include "disk_index_build.h"
#include "disk_internal.h"
#include "disk_log.h"
#include "disk_bulk.h"
#include "schema/policy_store.h"
#include <stdlib.h>
#include <string.h>

#define MAX_CATCHUP 65536U
#define MAX_POLICY_RESNAPSHOTS 4U
static const unsigned char meta_key[] = {0, 'Y', 'L', 'M'};
static const unsigned char policy_key[] = "Dyamldb-system\0schema-policies";
typedef struct {
    char collection[129], id[129];
    uint64_t record, bytes;
    bool deleted;
} Operation;
typedef struct { YDIndexProgress progress; void *context; } ReceiptProgress;
static bool receipt_progress(void *context, YDDiskValidationPhase phase) {
    (void)phase;
    ReceiptProgress *state = context;
    return !state->progress || state->progress(state->context, "receipts");
}
static int policy_changed(YDDisk *disk, const YDDiskView *base, const YDDiskView *current,
                            char *error, size_t length) {
    uint64_t before = 0, after = 0;
    int a = yd_disk_get(disk, base, policy_key, sizeof(policy_key) - 1, &before, error, length);
    int b = yd_disk_get(disk, current, policy_key, sizeof(policy_key) - 1, &after, error, length);
    return a < 0 || b < 0 ? -1 : a != b || before != after;
}
static bool policy_snapshot(YDDisk *disk, const YDDiskView *view, YDPolicyWork *work,
                               char *error, size_t length) {
    YDPolicyCatalog *catalog = NULL;
    bool present = false;
    bool valid = yd_policy_store_at(disk, view, work, &catalog, &present, error, length) == YD_POLICY_OK;
    yd_policy_catalog_free(catalog);
    return valid;
}
static bool step(YDIndexProgress progress, void *context, const char *phase,
                  char *error, size_t length) {
    return !progress || progress(context, phase) ||
           yd_disk_error(error, length, "index build cancelled or deadline exceeded");
}
static bool operation(const unsigned char *frame, size_t size, size_t *at, Operation *op,
                       unsigned char previous[258], size_t *pn) {
    memset(op, 0, sizeof(*op));
    if (*at > size || size - *at < 20) return false;
    const unsigned char *header = frame + *at, *key = header + 20;
    size_t kn = yd_disk_u16(header);
    if (kn < 2 || kn > 258 || kn > size - *at - 20 || header[2] > 1 || header[3]) return false;
    int order = *pn ? memcmp(previous, key, *pn < kn ? *pn : kn) : -1;
    if (order > 0 || (!order && *pn >= kn)) return false;
    memcpy(previous, key, kn); *pn = kn;
    const unsigned char *separator = key[0] == 'D' ? memchr(key + 1, 0, kn - 1) : NULL;
    size_t cn = key[0] == 'C' ? kn - 1 : separator ? (size_t)(separator - key - 1) : 0;
    size_t dn = separator ? kn - cn - 2 : 0;
    op->deleted = header[2] != 0;
    op->record = yd_disk_u64(header + 4); op->bytes = yd_disk_u64(header + 12);
    if (!cn || cn > 128 || dn > 128 ||
        !((key[0] == 'C' && !op->deleted && op->record == 1 && !op->bytes) ||
          (key[0] == 'D' && dn && (op->deleted ? !op->record && !op->bytes : op->record != 0))))
        return false;
    memcpy(op->collection, key + 1, cn);
    if (dn) memcpy(op->id, key + cn + 2, dn);
    if (strlen(op->collection) != cn || strlen(op->id) != dn ||
        !yamldb_valid_name(op->collection) || (dn && !yamldb_valid_name(op->id)) ||
        (!strcmp(op->collection, "yamldb-system") && !strcmp(op->id, "indexes"))) return false;
    *at += 20 + kn;
    return true;
}
static bool replay_frame(YDDiskTxn *txn, const YDDiskIndexes *indexes,
                          const YDDiskView *current, uint64_t offset, uint64_t sequence,
                          uint64_t previous_sequence, YDIndexProgress progress, void *context,
                          char *error, size_t length) {
    if (error && length) *error = 0;
    size_t size = 0;
    unsigned char *frame = yd_disk_record(txn->disk, current, offset, &size, error, length);
    bool valid = frame && size >= YD_LOG_HEADER_SIZE && !memcmp(frame, "YDLOGF01", 8) &&
                 yd_disk_u64(frame + 8) == sequence &&
                 yd_disk_u64(frame + 16) == txn->view.revision &&
                 yd_disk_u64(frame + 48) == previous_sequence &&
                 yd_disk_u16(frame + 40) == 0 && yd_disk_u64(frame + 40) >> 32 == 0;
    size_t count = valid ? yd_disk_u16(frame + 42) : 257;
    valid = valid && count <= 256;
    Operation *ops = valid ? calloc(count ? count : 1, sizeof(*ops)) : NULL;
    valid = valid && ops;
    size_t at = YD_LOG_HEADER_SIZE, pn = 0;
    unsigned char previous[258];
    uint64_t bytes = 0;
    for (size_t i = 0; valid && i < count; i++) {
        valid = operation(frame, size, &at, &ops[i], previous, &pn) &&
                ops[i].bytes <= YD_DISK_CAPTURE_LIMIT(current->format) - bytes;
        if (valid) bytes += ops[i].bytes;
    }
    valid = valid && at == size && yd_disk_u64(frame + 32) == size + bytes;
    /* Remove the whole commit first: unique-key swaps must not conflict with
     * another document whose old key is removed later in this same commit. */
    for (unsigned pass = 0; valid && pass < 3; pass++) {
        for (size_t i = 0; valid && i < count; i++) {
            const Operation *op = &ops[i];
            valid = step(progress, context, "replay", error, length);
            if (!valid) break;
            if (!op->id[0]) {
                if (pass == 1) valid = yd_disk_create_collection(txn, op->collection, error, length);
                continue;
            }
            YDDiskDocument old = {0}, fresh = {0};
            int found = yd_disk_document_tx_get(txn, op->collection, op->id, &old, error, length);
            valid = found >= 0;
            if (valid && pass == 0 && found)
                valid = yd_disk_indexes_change(txn, indexes, &old, false, error, length);
            if (valid && pass == 1) {
                if (!op->deleted)
                    valid = yd_disk_document_at(txn->disk, current, op->record, &fresh, error, length) &&
                            fresh.length == op->bytes && !strcmp(fresh.collection, op->collection) &&
                            !strcmp(fresh.id, op->id);
                else valid = found == 1;
                if (valid) valid = yd_disk_write_document(txn, found ? &old : NULL,
                                                           op->deleted ? NULL : &fresh, error, length);
            }
            if (valid && pass == 2 && !op->deleted)
                valid = found == 1 && yd_disk_indexes_change(txn, indexes, &old, true, error, length);
            yd_disk_document_free(&old); yd_disk_document_free(&fresh);
        }
    }
    valid = valid && txn->view.revision == yd_disk_u64(frame + 24);
    free(ops); free(frame);
    /* Keep the actionable failure from replay (including a newly violated
     * unique constraint); structural failures still get the history error. */
    if (!valid && error && length && *error) return false;
    return valid || yd_disk_error(error, length, "index catch-up history invalid, reset, or conflicting");
}
/* Preserve ALL current hidden metadata, including Raft position, retry receipts
 * and durable jobs, along with the exact feed and its retention floor. A scan
 * only replays document effects; those other keys can change without revision
 * changes and must never come from its older private root. */
static bool copy_log(YDDiskTxn *txn, const YDDiskView *current, const YDDiskLog *log,
                      YDIndexProgress progress, void *context, char *error, size_t length) {
    YDDiskView frozen;
    if (!yd_disk_tx_freeze(txn, &frozen, error, length)) return false;
    const unsigned char prefix[] = {0};
    unsigned char key[YD_DISK_KEY_LIMIT]; size_t kn = 0;
    uint64_t record = 0;
    YDDiskCursor *cursor = yd_disk_cursor(txn->disk, &frozen, prefix, sizeof(prefix), false, error, length);
    bool valid = cursor != NULL; int next = 0;
    while (valid && (next = yd_disk_next(cursor, key, sizeof(key), &kn, &record, error, length)) == 1) {
        if (!kn || key[0]) break;
        valid = step(progress, context, "history", error, length) && yd_disk_delete(txn, key, kn, error, length);
    }
    valid = valid && next >= 0; yd_disk_cursor_free(cursor);
    cursor = valid ? yd_disk_cursor(txn->disk, current, prefix, sizeof(prefix), false, error, length) : NULL;
    valid = valid && cursor; next = 0;
    uint64_t count = 0, bytes = 0, sequence = log->floor;
    while (valid && (next = yd_disk_next(cursor, key, sizeof(key), &kn, &record, error, length)) == 1) {
        if (!kn || key[0]) break;
        if (kn == 12 && !memcmp(key, "\0YLF", 4)) {
            size_t size = 0;
            unsigned char *frame = yd_disk_record(txn->disk, current, record, &size, error, length);
            uint64_t number = 0;
            for (size_t j = 4; j < 12; j++) number = (number << 8) | key[j];
            valid = frame && size >= YD_LOG_HEADER_SIZE && !memcmp(frame, "YDLOGF01", 8) &&
                    yd_disk_u64(frame + 8) == number && number > sequence && number <= log->last &&
                    yd_disk_u64(frame + 48) == sequence && count < log->count &&
                    yd_disk_u64(frame + 32) <= log->bytes - bytes;
            if (valid) { count++; bytes += yd_disk_u64(frame + 32); sequence = number; }
            free(frame);
        }
        if (valid) valid = step(progress, context, "history", error, length) &&
                           yd_disk_put(txn, key, kn, record, error, length);
    }
    valid = valid && next >= 0 && sequence == log->last && count == log->count && bytes == log->bytes;
    yd_disk_cursor_free(cursor);
    if (valid) valid = yd_disk_get(txn->disk, current, meta_key, sizeof(meta_key), &record, error, length) == 1 &&
                       yd_disk_put(txn, meta_key, sizeof(meta_key), record, error, length);
    return valid || yd_disk_error(error, length, "index catch-up log metadata invalid");
}
bool yd_disk_indexes_online(YDDisk *disk, const unsigned char *source, size_t size,
                             YDIndexProgress progress, void *context, YDDiskView *receipt,
                             char *error, size_t length) {
    YDDiskTxn *txn = yd_disk_begin_staging(disk, error, length);
    if (!txn) return false;
    return yd_disk_indexes_online_from(txn, source, size, progress, context, receipt, error, length);
}
bool yd_disk_indexes_online_from(YDDiskTxn *txn, const unsigned char *source, size_t size,
                                  YDIndexProgress progress, void *context, YDDiskView *receipt,
                                  char *error, size_t length) {
    YDDiskTxn *ready = NULL;
    if (!yd_disk_indexes_stage_from(txn, source, size, progress, context, NULL, NULL,
                                    &ready, error, length)) return false;
    if (yd_disk_commit_view(ready, receipt, error, length)) return true;
    return yd_disk_error(error, length, "index publication failed; recovery may be required");
}
bool yd_disk_indexes_stage_from(YDDiskTxn *txn, const unsigned char *source, size_t size,
    YDIndexProgress progress, void *context, YDIndexAdmission admission,
    void *admission_context, YDDiskTxn **ready, char *error, size_t length) {
    if (ready) *ready = NULL;
    if (!ready || !txn || !txn->exclusive || txn->locked || txn->view.root != txn->base.root) {
        yd_disk_abort(txn);
        return yd_disk_error(error, length, "online index build requires a fresh staging root");
    }
    YDDisk *disk = txn->disk;
    YDPolicyWork work;
    yd_policy_work_init(&work, true);
    bool valid = policy_snapshot(disk, &txn->base, &work, error, length);
    YDDiskIndexes *indexes = valid ? yd_disk_indexes_prepare(txn, source, size, error, length) : NULL;
    YDDiskLog original;
    valid = indexes && yd_disk_log_load(disk, &txn->base, &original, error, length) == 1 &&
            original.last == txn->base.generation;
    uint64_t sequence = valid ? original.last : 0;
    size_t replayed = 0;
    unsigned resnapshots = 0;
    bool admitted = false;
    if (valid) valid = yd_disk_indexes_build_root(txn, indexes, progress, context, error, length);
    while (valid) {
        if (!step(progress, context, "catchup", error, length)) { valid = false; break; }
        YDDiskView current = yd_disk_view(disk);
        int changed = policy_changed(disk, &txn->base, &current, error, length);
        if (changed < 0) { valid = false; break; }
        if (changed) {
            /* Policy publications carry raw receipt keys outside document-log
             * operations. Discard the stale private tree rather than replaying
             * its reset frame or overwriting the new catalog/receipt namespace.
             * Restart count and replay allowance belong to the whole build. */
            valid = resnapshots++ < MAX_POLICY_RESNAPSHOTS &&
                    step(progress, context, "resnapshot", error, length);
            yd_disk_indexes_free(indexes);
            indexes = NULL;
            yd_disk_abort(txn);
            txn = valid ? yd_disk_begin_staging(disk, error, length) : NULL;
            valid = txn && policy_snapshot(disk, &txn->base, &work, error, length);
            if (valid) indexes = yd_disk_indexes_prepare(txn, source, size, error, length);
            valid = valid && indexes && yd_disk_log_load(disk, &txn->base, &original, error, length) == 1 &&
                    original.last == txn->base.generation;
            if (valid) {
                sequence = original.last;
                valid = yd_disk_indexes_build_root(txn, indexes, progress, context, error, length);
            }
            if (!valid) yd_disk_error(error, length, "index policy resnapshot failed, cancelled, or exhausted");
            continue;
        }
        YDDiskLog log;
        valid = yd_disk_log_load(disk, &current, &log, error, length) == 1 &&
                !memcmp(log.identity, original.identity, 16) && sequence >= log.floor &&
                sequence <= log.last && log.last == current.generation;
        if (!valid) { yd_disk_error(error, length, "index catch-up history expired or changed"); break; }
        if (txn->next < current.end) txn->next = current.end;
        unsigned char key[12], actual[YD_DISK_KEY_LIMIT]; size_t kn = 0;
        uint64_t record = 0;
        yd_disk_log_key(key, sequence);
        YDDiskCursor *cursor = yd_disk_cursor(disk, &current, key, sizeof(key), true, error, length);
        valid = cursor != NULL; int next = 0;
        while (valid && sequence < log.last &&
               (next = yd_disk_next(cursor, actual, sizeof(actual), &kn, &record, error, length)) == 1) {
            if (kn != 12 || memcmp(actual, "\0YLF", 4)) { valid = false; break; }
            uint64_t number = 0;
            for (size_t j = 4; j < 12; j++) number = (number << 8) | actual[j];
            valid = number > sequence && number <= log.last &&
                    replayed++ < MAX_CATCHUP && replay_frame(txn, indexes, &current, record, number,
                                                              sequence, progress, context, error, length);
            if (valid) { sequence = number; valid = step(progress, context, "frame", error, length); }
        }
        yd_disk_cursor_free(cursor);
        valid = valid && next >= 0 && sequence == log.last && txn->view.revision == current.revision &&
                txn->view.documents == current.documents && txn->view.collections == current.collections &&
                txn->view.bytes == current.bytes;
        if (!valid) break;
        ReceiptProgress receipt_progress_state = {progress, context};
        YDDiskValidation validation = {.progress = receipt_progress, .context = &receipt_progress_state};
        valid = yd_disk_policy_receipts_copy(disk, &current, txn, &validation, error, length) &&
                copy_log(txn, &current, &log, progress, context, error, length);
        YDDiskView frozen;
        if (valid) valid = yd_disk_tx_freeze(txn, &frozen, error, length) &&
                           step(progress, context, "publish", error, length);
        if (!valid) break;
        if (admission && !admission(admission_context, true)) {
            valid = yd_disk_error(error, length, "index publication admission rejected");
            break;
        }
        admitted = admission != NULL;
        pthread_mutex_lock(&disk->writer);
        YDDiskView latest = yd_disk_view(disk);
        if (latest.generation != current.generation) {
            pthread_mutex_unlock(&disk->writer);
            if (admitted) { admission(admission_context, false); admitted = false; }
            continue;
        }
        txn->locked = true;
        txn->base = current;
        txn->view.generation = current.generation;
        valid = step(progress, context, "commit", error, length) &&
                yd_disk_indexes_install(txn, indexes, source, size, error, length);
        if (valid) {
            *ready = txn;
            txn = NULL;
        }
        break;
    }
    yd_disk_indexes_free(indexes);
    yd_disk_abort(txn);
    if (!valid && admitted) admission(admission_context, false);
    return valid;
}
