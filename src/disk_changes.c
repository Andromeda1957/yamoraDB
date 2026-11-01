#define _POSIX_C_SOURCE 200809L
#include "disk_changes.h"
#include "disk_internal.h"
#include "disk_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PAGE_BYTES YD_DISK_RESPONSE_LIMIT(view->format)
static uint64_t sequence_of(const unsigned char key[12]) {
    uint64_t sequence = 0;
    for (size_t i = 4; i < 12; i++)
        sequence = (sequence << 8) | key[i];
    return sequence;
}
/* Render and validate one complete commit, retaining one source record at a
 * time. */
static char *frame_json(YDDisk *disk, const YDDiskView *view, const YDDiskLog *log, uint64_t offset,
                        uint64_t sequence, size_t *length, uint64_t *charge, uint64_t *previous,
                        uint64_t *revision, uint64_t *previous_sequence, YDDiskValidation *state, char *error,
                        size_t error_size) {
    size_t size = 0;
    unsigned char *frame = yd_disk_record(disk, view, offset, &size, error, error_size);
    if (!frame)
        return NULL;
    bool valid = size >= YD_LOG_HEADER_SIZE && !memcmp(frame, "YDLOGF01", 8) &&
                 yd_disk_u64(frame + 8) == sequence && frame[41] == 0 &&
                 yd_disk_u64(frame + 40) >> 32 == 0;
    unsigned flags = valid ? yd_disk_u16(frame + 40) : 2;
    size_t count = valid ? yd_disk_u16(frame + 42) : 257;
    valid = valid && flags <= 1 && count <= 256 && (!flags || !count);
    *charge = valid ? yd_disk_u64(frame + 32) : 0;
    *previous = valid ? yd_disk_u64(frame + 16) : 0;
    *revision = valid ? yd_disk_u64(frame + 24) : 0;
    *previous_sequence = valid ? yd_disk_u64(frame + 48) : 0;
    valid = valid && *previous_sequence < sequence;
    char *text = NULL;
    size_t used = 0;
    FILE *out = valid ? open_memstream(&text, &used) : NULL;
    if (valid && !out)
        valid = false;
    char token[YD_LOG_TOKEN_SIZE];
    yd_disk_log_token(log, sequence, token);
    if (valid)
        valid = fprintf(out,
                        "{\"token\":\"%s\",\"previous_revision\":\"%016llx\","
                        "\"revision\":\"%016llx\",\"resnapshot_required\":%s,"
                        "\"operations\":[",
                        token, (unsigned long long)*previous, (unsigned long long)*revision,
                        flags ? "true" : "false") > 0;
    size_t at = YD_LOG_HEADER_SIZE;
    uint64_t source_bytes = 0;
    unsigned char prior[258];
    size_t pn = 0;
    for (size_t i = 0; valid && i < count; i++) {
        if (!yd_disk_validation_step(state, YD_VALIDATE_OPERATION)) {
            valid = false;
            break;
        }
        if (size - at < 20) {
            valid = false;
            break;
        }
        size_t kn = yd_disk_u16(frame + at);
        bool deleted = frame[at + 2] != 0;
        uint64_t record = yd_disk_u64(frame + at + 4), bytes = yd_disk_u64(frame + at + 12);
        valid = kn >= 2 && kn <= sizeof(prior) && kn <= size - at - 20 && frame[at + 2] <= 1 &&
                frame[at + 3] == 0 && bytes <= YD_DISK_CAPTURE_LIMIT(view->format) - source_bytes;
        if (!valid)
            break;
        const unsigned char *key = frame + at + 20;
        if (pn) {
            int order = memcmp(prior, key, pn < kn ? pn : kn);
            if (order > 0 || (!order && pn >= kn)) {
                valid = false;
                break;
            }
        }
        memcpy(prior, key, kn);
        pn = kn;
        char collection[129] = {0}, id[129] = {0};
        const unsigned char *separator = key[0] == 'D' ? memchr(key + 1, 0, kn - 1) : NULL;
        size_t cn = key[0] == 'C' ? kn - 1 : separator ? (size_t)(separator - key - 1) : 0;
        size_t dn = separator ? kn - cn - 2 : 0;
        valid = cn && cn <= 128 && dn <= 128 &&
                ((key[0] == 'C' && !deleted && record == 1 && bytes == 0) ||
                 (key[0] == 'D' && dn && (deleted ? !record && !bytes : record != 0)));
        if (!valid)
            break;
        memcpy(collection, key + 1, cn);
        if (dn)
            memcpy(id, key + cn + 2, dn);
        valid = strlen(collection) == cn && strlen(id) == dn && yamldb_valid_name(collection) &&
                (!dn || yamldb_valid_name(id));
        if (!valid)
            break;
        if (i)
            fputc(',', out);
        fprintf(out, "{\"collection\":\"%s\"", collection);
        if (key[0] == 'C')
            fputs(",\"create_collection\":true}", out);
        else {
            fprintf(out, ",\"document\":\"%s\"", id);
            if (deleted)
                fputs(",\"delete\":true}", out);
            else {
                YDDiskDocument doc;
                if (!yd_disk_document_at(disk, view, record, &doc, error, error_size)) {
                    valid = false;
                    break;
                }
                valid = bytes == doc.length && !strcmp(collection, doc.collection) &&
                        !strcmp(id, doc.id);
                /* Binary source records are length-delimited, not C strings. */
                char *source = malloc(doc.length + 1);
                valid = valid && source && !memchr(doc.body, 0, doc.length);
                if (valid) {
                    memcpy(source, doc.body, doc.length);
                    source[doc.length] = 0;
                }
                YDValue raw = {.type = YD_STRING, .scalar = source};
                size_t n = 0;
                char *json = valid ? yd_json_sized(&raw, &n, YD_DISK_REQUEST_LIMIT(view->format)) : NULL;
                valid = valid && json;
                if (valid) {
                    fputs(",\"put\":", out);
                    fwrite(json, 1, n, out);
                    fputc('}', out);
                }
                free(json);
                free(source);
                yd_disk_document_free(&doc);
            }
        }
        source_bytes += bytes;
        at += 20 + kn;
    }
    valid = valid && at == size && *charge == size + source_bytes;
    if (out) {
        if (valid)
            fputs("]}", out);
        valid = valid && !ferror(out);
        if (fclose(out))
            valid = false;
    }
    free(frame);
    if (!valid || used > PAGE_BYTES - 1024) {
        free(text);
        yd_disk_error(error, error_size, "invalid or oversized change frame");
        return NULL;
    }
    *length = used;
    return text;
}
YDDiskReply yd_disk_changes_request(YDDisk *disk, const YDDiskView *view, const char *target) {
    char copy[1025], error[256] = {0};
    if (strlen(target) >= sizeof(copy))
        return yd_disk_error_reply(400, "invalid_change_request");
    strcpy(copy, target);
    char *options = strchr(copy, '?');
    if (options)
        *options++ = 0;
    if (strcmp(copy, "/v1/changes"))
        return yd_disk_error_reply(404, "invalid_path");
    char *after = NULL;
    size_t limit = 100;
    bool seen_limit = false;
    while (options && *options) {
        char *next = strchr(options, '&');
        if (next)
            *next++ = 0;
        if (!strncmp(options, "after=", 6) && !after && options[6])
            after = options + 6;
        else if (!strncmp(options, "limit=", 6) && !seen_limit && options[6]) {
            seen_limit = true;
            limit = 0;
            for (const char *p = options + 6; *p; p++) {
                if (*p < '0' || *p > '9' || limit > 100)
                    return yd_disk_error_reply(400, "invalid_change_limit");
                limit = limit * 10 + (unsigned)(*p - '0');
            }
            if (!limit || limit > 100)
                return yd_disk_error_reply(400, "invalid_change_limit");
        } else
            return yd_disk_error_reply(400, "invalid_change_request");
        if (next && !*next)
            return yd_disk_error_reply(400, "invalid_change_request");
        options = next;
    }
    YDDiskLog log;
    int found = yd_disk_log_load(disk, view, &log, error, sizeof(error));
    if (found != 1)
        return yd_disk_error_reply(503,
                                   found ? "invalid_change_log" : "change_log_not_initialized");
    uint64_t sequence = log.last;
    int resumed = after ? yd_disk_log_resume(&log, after, &sequence) : 1;
    if (resumed != 1)
        return yd_disk_error_reply(resumed == -2                    ? 410
                                   : resumed == -1 || resumed == -3 ? 409
                                                                    : 400,
                                   resumed == -2   ? "change_token_expired"
                                   : resumed == -1 ? "foreign_change_token"
                                                   : "invalid_change_token");
    char *body = malloc(PAGE_BYTES + 1);
    if (!body)
        return yd_disk_error_reply(503, "allocation_failed");
    size_t used = 0, count = 0;
    const char *prefix = "{\"transactions\":[";
    memcpy(body, prefix, strlen(prefix));
    used = strlen(prefix);
    unsigned char key[12], actual[YD_DISK_KEY_LIMIT];
    yd_disk_log_key(key, sequence);
    YDDiskCursor *cursor = yd_disk_cursor(disk, view, key, sizeof(key), true, error, sizeof(error));
    bool valid = cursor != NULL, more = false;
    size_t kn = 0;
    uint64_t record = 0;
    int next = 0;
    while (valid && (next = yd_disk_next(cursor, actual, sizeof(actual), &kn, &record, error,
                                         sizeof(error))) == 1) {
        if (kn != 12 || memcmp(actual, "\0YLF", 4))
            break;
        if (count == limit) {
            more = true;
            break;
        }
        uint64_t number = sequence_of(actual), charge, previous, revision, previous_sequence;
        size_t n = 0;
        char *json = frame_json(disk, view, &log, record, number, &n, &charge, &previous, &revision,
                                &previous_sequence, NULL, error, sizeof(error));
        if (!json || number <= sequence || number > log.last || previous_sequence != sequence) {
            free(json);
            valid = false;
            break;
        }
        if (n + 1024 + (count ? 1 : 0) > PAGE_BYTES - used) {
            free(json);
            more = true;
            break;
        }
        if (count)
            body[used++] = ',';
        memcpy(body + used, json, n);
        used += n;
        free(json);
        sequence = number;
        count++;
    }
    yd_disk_cursor_free(cursor);
    if (!valid || next < 0 || (!more && sequence != log.last)) {
        free(body);
        return yd_disk_error_reply(503, "invalid_change_log");
    }
    char token[YD_LOG_TOKEN_SIZE], oldest[YD_LOG_TOKEN_SIZE], current[YD_LOG_TOKEN_SIZE];
    yd_disk_log_token(&log, sequence, token);
    yd_disk_log_token(&log, log.floor, oldest);
    yd_disk_log_token(&log, log.last, current);
    int n = snprintf(body + used, PAGE_BYTES + 1 - used,
                     "],\"next_after\":\"%s\",\"oldest_after\":\"%s\",\"checkpoint\":\"%s\","
                     "\"revision\":\"%016llx\",\"has_more\":%s}",
                     token, oldest, current, (unsigned long long)view->revision,
                     more ? "true" : "false");
    if (n < 0 || (size_t)n > PAGE_BYTES - used) {
        free(body);
        return yd_disk_error_reply(503, "change_response_too_large");
    }
    YDDiskReply reply = {.status = 200, .body = body, .length = used + (size_t)n,
                         .content_type = "application/json; charset=utf-8", .has_more = more};
    memcpy(reply.resume_after, token, sizeof(reply.resume_after));
    return reply;
}
bool yd_disk_changes_validate(YDDisk *disk, const YDDiskView *view, char *error, size_t length) {
    return yd_disk_changes_validate_cancellable(disk, view, NULL, error, length);
}
bool yd_disk_changes_validate_cancellable(YDDisk *disk, const YDDiskView *view,
                                            YDDiskValidation *state, char *error, size_t length) {
    if (!yd_disk_validation_step(state, YD_VALIDATE_HISTORY))
        return yd_disk_error(error, length, "change log validation cancelled");
    YDDiskLog log;
    int found = yd_disk_log_load(disk, view, &log, error, length);
    if (found <= 0)
        return found == 0;
    unsigned char key[12], actual[YD_DISK_KEY_LIMIT];
    yd_disk_log_key(key, log.floor);
    YDDiskCursor *cursor = yd_disk_cursor(disk, view, key, sizeof(key), true, error, length);
    bool valid = cursor != NULL;
    uint64_t records = 0, bytes = 0, last = log.floor, last_revision = 0, offset = 0;
    size_t kn = 0;
    int next = 0;
    while (valid && (next = yd_disk_next(cursor, actual, sizeof(actual), &kn, &offset, error,
                                         length)) == 1) {
        if (kn != 12 || memcmp(actual, "\0YLF", 4))
            break;
        if (!yd_disk_validation_step(state, YD_VALIDATE_HISTORY)) {
            valid = false;
            break;
        }
        uint64_t sequence = sequence_of(actual), charge = 0, before = 0, revision = 0,
                 previous_sequence = 0;
        size_t n = 0;
        char *json = frame_json(disk, view, &log, offset, sequence, &n, &charge, &before, &revision,
                                &previous_sequence, state, error, length);
        uint64_t reachable = 0;
        valid = json && sequence > last && sequence <= log.last && previous_sequence == last &&
                (!records || before == last_revision) && charge <= UINT64_MAX - bytes &&
                yd_disk_get(disk, view, actual, kn, &reachable, error, length) == 1 &&
                reachable == offset;
        free(json);
        if (valid) {
            last = sequence;
            last_revision = revision;
            bytes += charge;
            records++;
        }
    }
    yd_disk_cursor_free(cursor);
    return (valid && next >= 0 && records == log.count && bytes == log.bytes && last == log.last &&
            last_revision == view->revision) ||
           yd_disk_error(error, length, "change log validation failed");
}
