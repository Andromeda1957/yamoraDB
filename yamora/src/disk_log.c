#define _POSIX_C_SOURCE 200809L
#include "disk_log.h"
#include "disk_internal.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef YD_DISK_LOG_FRAMES
#define YD_DISK_LOG_FRAMES 4096U
#endif
#ifndef YD_DISK_LOG_BYTES
#define YD_DISK_LOG_BYTES (64U * 1024U * 1024U)
#endif
static const unsigned char meta_key[] = {0, 'Y', 'L', 'M'};

size_t yd_disk_log_key(unsigned char key[12], uint64_t sequence) {
    memcpy(key, "\0YLF", 4);
    for (size_t i = 0; i < 8; i++)
        key[4 + i] = (unsigned char)(sequence >> (56 - 8 * i));
    return 12;
}
int yd_disk_log_load(YDDisk *disk, const YDDiskView *view, YDDiskLog *log, char *error,
                     size_t length) {
    memset(log, 0, sizeof(*log));
    uint64_t offset = 0;
    int found = yd_disk_get(disk, view, meta_key, sizeof(meta_key), &offset, error, length);
    if (found != 1)
        return found;
    size_t size = 0;
    unsigned char *bytes = yd_disk_record(disk, view, offset, &size, error, length);
    bool valid = bytes && size == 56 && !memcmp(bytes, "YDLOGM01", 8);
    if (valid) {
        memcpy(log->identity, bytes + 8, 16);
        log->floor = yd_disk_u64(bytes + 24);
        log->last = yd_disk_u64(bytes + 32);
        log->count = yd_disk_u64(bytes + 40);
        log->bytes = yd_disk_u64(bytes + 48);
        valid = log->floor < log->last && log->last <= view->generation && log->count &&
                log->count <= log->last - log->floor && log->bytes >= YD_LOG_HEADER_SIZE;
    }
    free(bytes);
    if (!valid) {
        yd_disk_error(error, length, "invalid change log metadata");
        return -1;
    }
    return 1;
}
void yd_disk_log_token(const YDDiskLog *log, uint64_t sequence, char token[YD_LOG_TOKEN_SIZE]) {
    static const char hex[] = "0123456789abcdef";
    memcpy(token, "v1.", 3);
    for (size_t i = 0; i < 16; i++) {
        token[3 + i * 2] = hex[log->identity[i] >> 4];
        token[4 + i * 2] = hex[log->identity[i] & 15];
    }
    snprintf(token + 35, YD_LOG_TOKEN_SIZE - 35, ".%016llx", (unsigned long long)sequence);
}
int yd_disk_log_resume(const YDDiskLog *log, const char *token, uint64_t *sequence) {
    if (!token || strlen(token) != 52 || memcmp(token, "v1.", 3) || token[35] != '.')
        return 0;
    for (size_t i = 3; i < 52; i++)
        if (i != 35 &&
            !((token[i] >= '0' && token[i] <= '9') || (token[i] >= 'a' && token[i] <= 'f')))
            return 0;
    char expected[YD_LOG_TOKEN_SIZE];
    yd_disk_log_token(log, 0, expected);
    if (memcmp(expected, token, 35))
        return -1;
    uint64_t number = 0;
    for (size_t i = 36; i < 52; i++)
        number = (number << 4) | (unsigned)(token[i] <= '9' ? token[i] - '0' : token[i] - 'a' + 10);
    *sequence = number;
    return number < log->floor ? -2 : number > log->last ? -3 : 1;
}
void yd_disk_log_free(YDDiskTxn *txn) {
    while (txn->log_changes) {
        YDLogChange *op = txn->log_changes;
        txn->log_changes = op->next;
        free(op);
    }
    txn->log_count = txn->log_bytes = 0;
}
bool yd_disk_log_capture(YDDiskTxn *txn, const unsigned char *key, size_t size, uint64_t before,
                         uint64_t after, size_t source_bytes, char *error, size_t length) {
    txn->log_enabled = true;
    if (txn->log_reset)
        return true;
    YDLogChange *op = txn->log_changes;
    while (op && (op->size != size || memcmp(op->key, key, size)))
        op = op->next;
    size_t previous = op ? op->source_bytes : 0;
    if (size > sizeof(((YDLogChange *)0)->key) || (!op && txn->log_count == 256) ||
        source_bytes > YD_DISK_CAPTURE_LIMIT(txn->view.format) - (txn->log_bytes - previous)) {
        yd_disk_log_free(txn);
        txn->log_reset = true;
        return true;
    }
    if (!op) {
        op = calloc(1, sizeof(*op));
        if (!op) {
            txn->failed = true;
            return yd_disk_error(error, length, "change capture allocation failed");
        }
        memcpy(op->key, key, size);
        op->size = size;
        op->had_old = before != 0;
        op->next = txn->log_changes;
        txn->log_changes = op;
        txn->log_count++;
    }
    op->deleted = after == 0;
    op->record = after;
    op->source_bytes = source_bytes;
    txn->log_bytes = txn->log_bytes - previous + source_bytes;
    return true;
}
static bool random_identity(unsigned char identity[16]) {
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return false;
    size_t at = 0;
    while (at < 16) {
        ssize_t n = read(fd, identity + at, 16 - at);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            break;
        at += (size_t)n;
    }
    close(fd);
    return at == 16;
}
static int order(const void *a, const void *b) {
    const YDLogChange *x = *(YDLogChange *const *)a, *y = *(YDLogChange *const *)b;
    int c = memcmp(x->key, y->key, x->size < y->size ? x->size : y->size);
    return c ? c : (x->size > y->size) - (x->size < y->size);
}
bool yd_disk_log_publish(YDDiskTxn *txn, const YDDiskView *current, char *error, size_t length) {
    if (!txn->log_enabled)
        return true;
    YDDiskLog log;
    int found = yd_disk_log_load(txn->disk, current, &log, error, length);
    if (found < 0 || ((txn->view.format == 6 ||
        (txn->view.capabilities & YD_DISK_CAP_CLUSTER)) && !txn->log_identity_set) ||
        (found && txn->log_identity_set && memcmp(log.identity, txn->log_identity, 16)))
        return yd_disk_error(error, length, "invalid change log identity");
    if (!found && txn->log_identity_set)
        memcpy(log.identity, txn->log_identity, 16);
    else if (!found && !random_identity(log.identity))
        return yd_disk_error(error, length, "cannot prepare change log identity");
    uint64_t ignored = 0;
    int retained = yd_disk_tx_peek(txn, meta_key, sizeof(meta_key), &ignored, error, length);
    if (retained < 0)
        return false;
    if (!found || !retained) {
        log.floor = current->generation;
        log.last = log.floor;
        log.count = log.bytes = 0;
        if (found)
            txn->log_reset = true;
    }
    uint64_t previous_sequence = log.last;
    log.last = current->generation + 1;
    YDLogChange *ops[256];
    size_t count = 0, total = YD_LOG_HEADER_SIZE;
    for (YDLogChange *op = txn->log_changes; !txn->log_reset && op; op = op->next)
        if (op->had_old || !op->deleted) {
            ops[count++] = op;
            total += 20 + op->size;
        }
    qsort(ops, count, sizeof(*ops), order);
    unsigned char *frame = calloc(1, total);
    if (!frame)
        return yd_disk_error(error, length, "change frame allocation failed");
    memcpy(frame, "YDLOGF01", 8);
    yd_disk_set64(frame + 8, log.last);
    yd_disk_set64(frame + 16, current->revision);
    yd_disk_set64(frame + 24, txn->view.revision);
    uint64_t charge = total + (txn->log_reset ? 0 : txn->log_bytes);
    yd_disk_set64(frame + 32, charge);
    yd_disk_set16(frame + 40, txn->log_reset ? 1 : 0);
    yd_disk_set16(frame + 42, (uint16_t)count);
    yd_disk_set64(frame + 48, previous_sequence);
    size_t at = YD_LOG_HEADER_SIZE;
    for (size_t i = 0; i < count; i++) {
        YDLogChange *op = ops[i];
        yd_disk_set16(frame + at, (uint16_t)op->size);
        frame[at + 2] = op->deleted;
        yd_disk_set64(frame + at + 4, op->record);
        yd_disk_set64(frame + at + 12, op->source_bytes);
        memcpy(frame + at + 20, op->key, op->size);
        at += 20 + op->size;
    }
    unsigned char key[12];
    yd_disk_log_key(key, log.last);
    bool replay = txn->replay;
    txn->replay = true;
    uint64_t offset = 0;
    bool valid = yd_disk_append(txn, frame, total, &offset, error, length) &&
                 yd_disk_put(txn, key, sizeof(key), offset, error, length);
    free(frame);
    log.count++;
    log.bytes += charge;
    /* Delete complete oldest frames; never discard the frame being committed. */
    while (valid && log.count > 1 &&
           (log.count > YD_DISK_LOG_FRAMES || log.bytes > YD_DISK_LOG_BYTES)) {
        yd_disk_log_key(key, log.floor);
        YDDiskCursor *cursor = yd_disk_tx_cursor(txn, key, sizeof(key), true, error, length);
        unsigned char oldest[YD_DISK_KEY_LIMIT];
        size_t kn = 0, size = 0;
        uint64_t record = 0;
        valid = cursor &&
                yd_disk_next(cursor, oldest, sizeof(oldest), &kn, &record, error, length) == 1 &&
                kn == 12 && !memcmp(oldest, "\0YLF", 4);
        yd_disk_cursor_free(cursor);
        YDDiskView prepared = txn->view;
        prepared.end = txn->next;
        unsigned char *old =
            valid ? yd_disk_record(txn->disk, &prepared, record, &size, error, length) : NULL;
        valid = valid && old && size >= YD_LOG_HEADER_SIZE && !memcmp(old, "YDLOGF01", 8) &&
                yd_disk_u64(old + 32) <= log.bytes;
        if (valid) {
            log.floor = yd_disk_u64(old + 8);
            log.bytes -= yd_disk_u64(old + 32);
            log.count--;
            valid = yd_disk_delete(txn, oldest, kn, error, length);
        }
        free(old);
    }
    unsigned char metadata[56] = {0};
    memcpy(metadata, "YDLOGM01", 8);
    memcpy(metadata + 8, log.identity, 16);
    yd_disk_set64(metadata + 24, log.floor);
    yd_disk_set64(metadata + 32, log.last);
    yd_disk_set64(metadata + 40, log.count);
    yd_disk_set64(metadata + 48, log.bytes);
    if (valid)
        valid = yd_disk_append(txn, metadata, sizeof(metadata), &offset, error, length) &&
                yd_disk_put(txn, meta_key, sizeof(meta_key), offset, error, length);
    txn->replay = replay;
    return valid;
}
