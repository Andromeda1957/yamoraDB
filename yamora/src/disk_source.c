#define _POSIX_C_SOURCE 200809L
#include "disk_source.h"
#include "disk_source_value.h"
#include "disk_documents.h"
#include "disk_internal.h"
#include "binary.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct YDDiskSource {
    YDDiskCheckpoint *checkpoint;
    YDDiskSourceInfo info;
    uint64_t offset;
};
static uint64_t now_ms(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return 0;
    return (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
}
static uint32_t u32(const unsigned char *p) {
    return (uint32_t)yd_disk_u16(p) | (uint32_t)yd_disk_u16(p + 2) << 16;
}
static uint32_t crc_table[256];
static pthread_once_t crc_once = PTHREAD_ONCE_INIT;
static void crc_init(void) {
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t value = i;
        for (unsigned bit = 0; bit < 8; bit++)
            value = (value >> 1) ^ ((value & 1) ? UINT32_C(0x82f63b78) : 0);
        crc_table[i] = value;
    }
}
static uint32_t crc_more(uint32_t crc, const unsigned char *p, size_t n) {
    (void)pthread_once(&crc_once, crc_init);
    for (size_t i = 0; i < n; i++) crc = crc_table[(crc ^ p[i]) & 255] ^ (crc >> 8);
    return crc;
}
typedef struct { unsigned remaining, width; uint32_t codepoint; } UTF8;
static bool text_byte(UTF8 *state, unsigned char byte) {
    if (state->remaining) {
        if ((byte & 0xc0) != 0x80) return false;
        state->codepoint = (state->codepoint << 6) | (byte & 0x3f);
        if (--state->remaining) return true;
        return !((state->width == 2 && state->codepoint < 0x800) ||
            (state->width == 3 && state->codepoint < 0x10000) ||
            (state->codepoint >= 0xd800 && state->codepoint <= 0xdfff) ||
            state->codepoint > 0x10ffff);
    }
    if (!byte || (byte < 0x20 && byte != '\n' && byte != '\r' && byte != '\t')) return false;
    if (byte < 0x80) return true;
    if ((byte & 0xe0) == 0xc0) {
        state->width = state->remaining = 1;
        state->codepoint = byte & 0x1f;
        return state->codepoint >= 2;
    }
    if ((byte & 0xf0) == 0xe0) {
        state->width = state->remaining = 2; state->codepoint = byte & 0x0f;
        return true;
    }
    if ((byte & 0xf8) == 0xf0) {
        state->width = state->remaining = 3; state->codepoint = byte & 7;
        return true;
    }
    return false;
}
static bool verify(YDDiskSource *source, uint64_t record, const char *collection,
    const char *document, uint64_t deadline, char *error, size_t length) {
    unsigned char header[16], prefix[12 + 2 * YAMLDB_NAME_LIMIT + 20];
    YDDiskView view = source->info.view;
    if (record < 2U * YD_DISK_PAGE || record % 16 || record >= view.end ||
        view.end - record < sizeof(header) ||
        !yd_disk_checkpoint_read(source->checkpoint, record, header, sizeof(header), error, length) ||
        memcmp(header, "YDBLOB02", 8)) goto invalid;
    size_t n = u32(header + 8);
    if (n < 36 || n > (view.format >= 5 ? 64U * 1024U * 1024U : 16U * 1024U * 1024U) ||
        n > view.end - record - sizeof(header)) goto invalid;
    size_t peek = n < sizeof(prefix) ? n : sizeof(prefix);
    if (!yd_disk_checkpoint_read(source->checkpoint, record + 16, prefix, peek, error, length) ||
        memcmp(prefix, "YDDOC002", 8)) goto invalid;
    size_t c = yd_disk_u16(prefix + 8), d = yd_disk_u16(prefix + 10);
    if (!c || !d || c > YAMLDB_NAME_LIMIT || d > YAMLDB_NAME_LIMIT ||
        c != strlen(collection) || d != strlen(document) ||
        12 + c + d + 24 > n || memcmp(prefix + 12, collection, c) ||
        memcmp(prefix + 12 + c, document, d)) goto invalid;
    size_t packed = 12 + c + d;
    const unsigned char *p = prefix + packed;
    bool large = !memcmp(p, "YAMDOC02", 8);
    size_t raw = u32(p + 8), encoded = u32(p + 12);
    if ((large && view.format < 5) || (!large && memcmp(p, "YAMDOC01", 8)) ||
        !raw || raw > (large ? YD_LARGE_DOCUMENT_LIMIT : YD_DOCUMENT_LIMIT) ||
        encoded > (large ? YD_BINARY_LARGE_VALUE_LIMIT : YD_BINARY_VALUE_LIMIT) ||
        u32(p + 16) || n - packed != 24 + raw + encoded) goto invalid;
    unsigned char buffer[YD_DISK_SOURCE_CHUNK], tail[4];
    uint32_t outer = UINT32_MAX, inner = UINT32_MAX;
    uint64_t hash = UINT64_C(1469598103934665603);
    UTF8 utf8 = {0};
    size_t start = packed + 20, end = start + raw;
    for (size_t at = 0; at < n;) {
        uint64_t now = now_ms();
        if (!now || now >= deadline)
            return yd_disk_error(error, length, "native source deadline");
        size_t count = n - at < sizeof(buffer) ? n - at : sizeof(buffer);
        if (!yd_disk_checkpoint_read(source->checkpoint, record + 16 + at,
                buffer, count, error, length)) return false;
        outer = crc_more(outer, buffer, count);
        size_t lo = at > packed ? at : packed, hi = at + count < n - 4 ? at + count : n - 4;
        if (lo < hi) inner = crc_more(inner, buffer + (lo - at), hi - lo);
        lo = at > start ? at : start; hi = at + count < end ? at + count : end;
        for (size_t i = lo; i < hi; i++) {
            unsigned char byte = buffer[i - at];
            if (!text_byte(&utf8, byte)) goto invalid;
            hash = (hash ^ byte) * UINT64_C(1099511628211);
        }
        at += count;
    }
    if (utf8.remaining || (outer ^ UINT32_MAX) != u32(header + 12) ||
        !yd_disk_checkpoint_read(source->checkpoint, record + 16 + n - 4, tail, 4, error, length) ||
        (inner ^ UINT32_MAX) != u32(tail)) goto invalid;
    if (!yd_disk_source_value_validate(source->checkpoint, record + 16 + end,
            encoded, raw, large, deadline, error, length)) return false;
    source->offset = record + 16 + start;
    source->info.length = raw;
    source->info.hash = hash;
    return true;
invalid:
    return yd_disk_error(error, length, "invalid native source record");
}
int yd_disk_source_open(YDDisk *disk, const char *collection, const char *document,
    uint64_t deadline, YDDiskSource **out, char *error, size_t length) {
    return yd_disk_source_open_at(disk, NULL, collection, document, deadline, out, error, length);
}
int yd_disk_source_open_at(YDDisk *disk, const YDDiskView *requested,
    const char *collection, const char *document, uint64_t deadline,
    YDDiskSource **out, char *error, size_t length) {
    if (out) *out = NULL;
    if (!out || !disk || !yamldb_valid_name(collection) || !yamldb_valid_name(document)) {
        yd_disk_error(error, length, "invalid native source arguments"); return -1;
    }
    /* Pin the file the requested view's offsets belong to, even when online
     * compaction adopted a newer file after the caller captured that view. */
    YDDisk *pin = yd_disk_pin_view(disk, requested, 32768, error, length);
    if (!pin) return -1;
    YDDiskView latest = yd_disk_view(pin), view = requested ? *requested : latest;
    if (view.epoch != latest.epoch || view.format != latest.format ||
        view.capabilities != latest.capabilities ||
        !view.generation || view.generation > latest.generation ||
        view.end < 2 * YD_DISK_PAGE || view.end > latest.end || view.end % YD_DISK_PAGE ||
        (view.root && (view.root < 2 * YD_DISK_PAGE || view.root % YD_DISK_PAGE ||
            view.root > view.end - YD_DISK_PAGE))) {
        yd_disk_close(pin);
        yd_disk_error(error, length, "source view outside captured incarnation"); return -1;
    }
    unsigned char key[YD_DISK_KEY_LIMIT];
    size_t kn = yd_disk_document_key(key, collection, document);
    uint64_t record;
    int found = yd_disk_get(pin, &view, key, kn, &record, error, length);
    YDDiskSource *source = NULL;
    if (found == 1) {
        source = calloc(1, sizeof(*source));
        if (source) {
            source->checkpoint = yd_disk_checkpoint_open(pin, error, length);
            source->info.view = view;
        }
    }
    yd_disk_close(pin);
    if (found != 1) return found;
    if (!source || !source->checkpoint ||
        !verify(source, record, collection, document, deadline, error, length)) {
        yd_disk_source_close(source); return -1;
    }
    *out = source;
    return 1;
}
bool yd_disk_source_info(const YDDiskSource *source, YDDiskSourceInfo *out) {
    if (out) memset(out, 0, sizeof(*out));
    if (!source || !out) return false;
    *out = source->info;
    return true;
}
bool yd_disk_source_read(const YDDiskSource *source, size_t offset, void *buffer,
    size_t size, char *error, size_t length) {
    bool valid = buffer && size && size <= YD_DISK_SOURCE_CHUNK;
    if (valid) memset(buffer, 0, size);
    if (!source || !valid || offset > source->info.length || size > source->info.length - offset)
        return yd_disk_error(error, length, "native source range outside bounds");
    if (!yd_disk_checkpoint_read(source->checkpoint, source->offset + offset,
            buffer, size, error, length)) {
        memset(buffer, 0, size); return false;
    }
    return true;
}
void yd_disk_source_close(YDDiskSource *source) {
    if (source) {
        yd_disk_checkpoint_close(source->checkpoint);
        free(source);
    }
}
