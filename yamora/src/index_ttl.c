#define _GNU_SOURCE
#include "index_ttl.h"
#include "disk_internal.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 0000-01-01T00:00:00Z: the earliest time a four-digit year can spell. */
#define TTL_TIME_FLOOR INT64_C(-62167219200)

static bool digits(const char *text, size_t count, int *out) {
    int value = 0;
    for (size_t i = 0; i < count; i++) {
        if (text[i] < '0' || text[i] > '9') return false;
        value = value * 10 + (text[i] - '0');
    }
    *out = value;
    return true;
}

static bool leap(int year) { return (year % 4 == 0 && year % 100 != 0) || year % 400 == 0; }

static int month_days(int year, int month) {
    static const int days[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    return month == 2 && leap(year) ? 29 : days[month - 1];
}

/* Proleptic Gregorian civil date <-> days since 1970-01-01 (H. Hinnant). */
static int64_t days_from_civil(int64_t year, int month, int day) {
    year -= month <= 2;
    int64_t era = (year >= 0 ? year : year - 399) / 400;
    int64_t yoe = year - era * 400;
    int64_t doy = (153 * (month + (month > 2 ? -3 : 9)) + 2) / 5 + day - 1;
    int64_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

static void civil_from_days(int64_t z, int64_t *year, int *month, int *day) {
    z += 719468;
    int64_t era = (z >= 0 ? z : z - 146096) / 146097;
    int64_t doe = z - era * 146097;
    int64_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    int64_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    int64_t mp = (5 * doy + 2) / 153;
    *day = (int)(doy - (153 * mp + 2) / 5 + 1);
    *month = (int)(mp < 10 ? mp + 3 : mp - 9);
    *year = yoe + era * 400 + (*month <= 2);
}

static int string_time(const char *text, int64_t *seconds) {
    size_t size = strlen(text);
    int year, month, day, hour = 0, minute = 0, second = 0;
    if (size < 10 || !digits(text, 4, &year) || text[4] != '-' || !digits(text + 5, 2, &month) ||
        text[7] != '-' || !digits(text + 8, 2, &day) || month < 1 || month > 12 || day < 1 ||
        day > month_days(year, month))
        return 0;
    bool round_up = false;
    if (size > 10) {
        if (size < 20 || text[10] != 'T' || !digits(text + 11, 2, &hour) || text[13] != ':' ||
            !digits(text + 14, 2, &minute) || text[16] != ':' || !digits(text + 17, 2, &second) ||
            hour > 23 || minute > 59 || second > 59)
            return 0;
        size_t at = 19;
        if (text[at] == '.') {
            size_t first = ++at;
            while (at < size && at - first < 10 && text[at] >= '0' && text[at] <= '9') {
                if (text[at] != '0') round_up = true;
                at++;
            }
            if (at == first || at - first > 9) return 0;
        }
        if (strcmp(text + at, "Z") && strcmp(text + at, "+00:00")) return 0;
    }
    int64_t value = days_from_civil(year, month, day) * 86400 + hour * 3600 + minute * 60 + second +
                    (round_up ? 1 : 0);
    if (value < TTL_TIME_FLOOR || value > YD_TTL_TIME_LIMIT) return 0;
    *seconds = value;
    return 1;
}

int yd_ttl_time(const YDValue *value, int64_t *seconds) {
    if (!value) return 0;
    if (value->type == YD_INT || value->type == YD_FLOAT) {
        long double number = value->type == YD_FLOAT ? ceill(value->number) : value->number;
        if (!(number >= (long double)TTL_TIME_FLOOR && number <= (long double)YD_TTL_TIME_LIMIT))
            return 0;
        *seconds = (int64_t)number;
        return 1;
    }
    if (value->type == YD_STRING && value->scalar) return string_time(value->scalar, seconds);
    return 0;
}

static int keycmp(const unsigned char *a, size_t an, const unsigned char *b, size_t bn) {
    int c = memcmp(a, b, an < bn ? an : bn);
    return c ? c : an < bn ? -1 : an > bn ? 1 : 0;
}

static bool append(unsigned char *key, size_t *size, const void *bytes, size_t count) {
    if (count > YD_DISK_KEY_LIMIT - *size) return false;
    memcpy(key + *size, bytes, count);
    *size += count;
    return true;
}

/* [lower, upper) covers every entry of the range whose value can be due at
 * cutoff, plus at most a few not-yet-due or unparseable values that each
 * document check rejects. false means the range cannot contain a due value. */
static bool range_bounds(const YDDiskIndex *index, unsigned range, int64_t cutoff,
                         unsigned char *lower, size_t *ln, unsigned char *upper, size_t *un,
                         char *error, size_t length) {
    if (!yd_disk_index_prefix(index, NULL, 0, lower, ln, error, length)) return false;
    memcpy(upper, lower, *ln);
    *un = *ln;
    if (range == 0) {
        unsigned char tag = 3, end[2] = {255, 255};
        if (!append(lower, ln, &tag, 1)) return false;
        YDValue number = {.type = YD_INT, .number = (long double)cutoff};
        const YDValue *values[1] = {&number};
        /* Entries are tuple + 0xFF + document ID, and IDs never contain 0xFF. */
        return yd_disk_index_prefix(index, values, 1, upper, un, error, length) &&
               append(upper, un, end, 2);
    }
    unsigned char tag = 4;
    if (cutoff < TTL_TIME_FLOOR || !append(lower, ln, &tag, 1)) return false;
    if (cutoff >= YD_TTL_TIME_LIMIT) {
        unsigned char next = 5;
        return append(upper, un, &next, 1);
    }
    /* Due strings all sort before the fixed-width second after the cutoff:
     * a timestamp's first 19 bytes are its whole seconds (fractions round up),
     * and a date is a prefix of its own midnight. */
    int64_t limit = cutoff + 1, days = limit / 86400, rest = limit % 86400;
    if (rest < 0) { rest += 86400; days--; }
    int64_t year;
    int month, day;
    civil_from_days(days, &year, &month, &day);
    char text[32];
    int n = snprintf(text, sizeof(text), "%04lld-%02d-%02dT%02d:%02d:%02d", (long long)year, month,
                     day, (int)(rest / 3600), (int)(rest / 60 % 60), (int)(rest % 60));
    return n == 19 && append(upper, un, &tag, 1) && append(upper, un, text, 19);
}

static bool ttl_index(const YDDiskIndex *index) { return index->ttl && !index->text && index->count == 1; }

int yd_ttl_present(YDDisk *disk, const YDDiskView *view, char *error, size_t length) {
    YDDiskIndexes *indexes = yd_disk_indexes_load(disk, view, error, length);
    if (!indexes) return -1;
    int present = 0;
    for (size_t i = 0; i < indexes->count; i++)
        if (ttl_index(&indexes->indexes[i])) present = 1;
    yd_disk_indexes_free(indexes);
    return present;
}

static void cursor_at(YDTTLCursor *cursor, const YDDiskIndex *index) {
    memset(cursor, 0, sizeof(*cursor));
    if (!index) return;
    snprintf(cursor->collection, sizeof(cursor->collection), "%s", index->collection);
    snprintf(cursor->name, sizeof(cursor->name), "%s", index->name);
}

int yd_ttl_collect(YDDisk *disk, const YDDiskView *view, int64_t now, YDTTLCursor *cursor,
                   YDTTLCandidate *candidates, size_t capacity, size_t *count, size_t budget,
                   uint64_t *examined, char *error, size_t length) {
    *count = 0;
    if (capacity > YD_TTL_BATCH_LIMIT) capacity = YD_TTL_BATCH_LIMIT;
    YDDiskIndexes *indexes = yd_disk_indexes_load(disk, view, error, length);
    if (!indexes) return -1;
    size_t position = indexes->count;
    for (size_t i = 0; cursor->collection[0] && i < indexes->count; i++)
        if (ttl_index(&indexes->indexes[i]) && !strcmp(indexes->indexes[i].collection, cursor->collection) &&
            !strcmp(indexes->indexes[i].name, cursor->name))
            position = i;
    if (position == indexes->count) {
        for (position = 0; position < indexes->count && !ttl_index(&indexes->indexes[position]);)
            position++;
        cursor_at(cursor, position < indexes->count ? &indexes->indexes[position] : NULL);
    }
    int result = 0;
    size_t spent = 0;
    YDDiskDocument document = {0};
    while (position < indexes->count) {
        const YDDiskIndex *index = &indexes->indexes[position];
        if (!ttl_index(index)) { position++; continue; }
        unsigned char lower[YD_DISK_KEY_LIMIT], upper[YD_DISK_KEY_LIMIT], key[YD_DISK_KEY_LIMIT];
        size_t ln = 0, un = 0, kn = 0;
        int64_t cutoff = now - index->expire_after;
        char local[256] = {0};
        bool scan = range_bounds(index, cursor->range, cutoff, lower, &ln, upper, &un, local,
                                 sizeof(local));
        if (!scan && local[0]) { yd_disk_error(error, length, local); result = -1; break; }
        YDDiskCursor *walk = NULL;
        if (scan) {
            bool resume = cursor->key_size && keycmp(cursor->key, cursor->key_size, lower, ln) >= 0;
            walk = resume ? yd_disk_cursor(disk, view, cursor->key, cursor->key_size, true, error, length)
                          : yd_disk_cursor(disk, view, lower, ln, false, error, length);
            if (!walk) { result = -1; break; }
        }
        bool finished = !scan;
        while (scan) {
            if (spent >= budget || *count >= capacity) { result = 1; break; }
            uint64_t record = 0;
            int next = yd_disk_next(walk, key, sizeof(key), &kn, &record, error, length);
            if (next < 0) { result = -1; break; }
            if (!next || keycmp(key, kn, upper, un) >= 0) { finished = true; break; }
            spent++;
            (*examined)++;
            memcpy(cursor->key, key, kn);
            cursor->key_size = kn;
            if (!yd_disk_document_at(disk, view, record, &document, error, length)) { result = -1; break; }
            if (strcmp(document.collection, index->collection)) {
                yd_disk_error(error, length, "TTL index points outside its collection");
                result = -1;
                break;
            }
            int64_t time = 0;
            bool due = yd_ttl_time(yd_path(document.value, index->fields[0]), &time) && time <= cutoff;
            for (size_t i = 0; due && i < *count; i++)
                if (!strcmp(candidates[i].collection, document.collection) &&
                    !strcmp(candidates[i].id, document.id))
                    due = false;
            if (due) {
                YDTTLCandidate *candidate = &candidates[(*count)++];
                memcpy(candidate->collection, document.collection, sizeof(candidate->collection));
                memcpy(candidate->id, document.id, sizeof(candidate->id));
                candidate->hash = document.hash;
            }
            yd_disk_document_free(&document);
        }
        yd_disk_cursor_free(walk);
        if (result) break;
        if (finished) {
            if (cursor->range == 0) {
                cursor->range = 1;
                cursor->key_size = 0;
                continue;
            }
            do position++;
            while (position < indexes->count && !ttl_index(&indexes->indexes[position]));
            cursor_at(cursor, position < indexes->count ? &indexes->indexes[position] : NULL);
        }
    }
    yd_disk_document_free(&document);
    if (result == 0) memset(cursor, 0, sizeof(*cursor));
    yd_disk_indexes_free(indexes);
    return result;
}

char *yd_ttl_transaction(const YDTTLCandidate *candidates, size_t count, size_t *size) {
    if (!count || count > YD_TTL_BATCH_LIMIT) return NULL;
    size_t capacity = 32 + count * (2 * YAMLDB_NAME_LIMIT + 96);
    char *body = malloc(capacity);
    if (!body) return NULL;
    size_t used = (size_t)snprintf(body, capacity, "{\"operations\":[");
    for (size_t i = 0; i < count; i++) {
        int n = snprintf(body + used, capacity - used,
                         "%s{\"collection\":\"%s\",\"document\":\"%s\",\"delete\":true,"
                         "\"etag\":\"%016llx\"}",
                         i ? "," : "", candidates[i].collection, candidates[i].id,
                         (unsigned long long)candidates[i].hash);
        if (n < 0 || (size_t)n >= capacity - used) { free(body); return NULL; }
        used += (size_t)n;
    }
    if (capacity - used < 3) { free(body); return NULL; }
    memcpy(body + used, "]}", 3);
    *size = used + 2;
    return body;
}
