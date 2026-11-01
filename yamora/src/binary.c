#define _POSIX_C_SOURCE 200809L
#include "binary.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static bool fail(char *error, size_t length, const char *message)
{ (void)snprintf(error, length, "%s", message); return false; }
static uint32_t read32(const unsigned char *p)
{ return (uint32_t)p[0] | (uint32_t)p[1]<<8 | (uint32_t)p[2]<<16 | (uint32_t)p[3]<<24; }
static void write32(unsigned char *p, size_t n)
{ for (unsigned i=0; i<4; i++) p[i] = (unsigned char)(n >> (8*i)); }
static uint32_t crc32c(const unsigned char *p, size_t n)
{
    uint32_t crc = UINT32_MAX;
    for (size_t i=0; i<n; i++) {
        crc ^= p[i];
        for (unsigned b=0; b<8; b++) crc = (crc>>1) ^ ((crc&1) ? UINT32_C(0x82f63b78) : 0);
    }
    return crc ^ UINT32_MAX;
}
int yd_binary_initializing(const char *root)
{
    int fd = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return -1;
    struct stat st;
    int result = fstatat(fd, YD_BINARY_INITIALIZING, &st, AT_SYMLINK_NOFOLLOW);
    int saved = errno; close(fd);
    return result == 0 ? 1 : (saved == ENOENT ? 0 : -1);
}
int yd_binary_present(const char *root, char *error, size_t length)
{
    int fd = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) { fail(error, length, "cannot open storage root"); return -1; }
    int marker = openat(fd, YD_BINARY_MARKER, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    int saved = errno; close(fd);
    if (marker < 0 && saved == ENOENT) return 0;
    if (marker < 0) { fail(error, length, "cannot open binary format marker"); return -1; }
    struct stat st; unsigned char bytes[9];
    bool valid = fstat(marker, &st) == 0 && S_ISREG(st.st_mode) && st.st_size == 8 &&
        read(marker, bytes, sizeof(bytes)) == 8 && memcmp(bytes, "YAMORA1\n", 8) == 0;
    close(marker);
    if (!valid) { fail(error, length, "unsupported or invalid binary format marker"); return -1; }
    return 1;
}
static bool extended_strings(const YDValue *v) {
    if (v->scalar && strlen(v->scalar) > YD_DOCUMENT_LIMIT) return true;
    for (size_t i = 0; i < v->count; i++)
        if ((v->type == YD_MAP && strlen(v->keys[i]) > YD_DOCUMENT_LIMIT) || extended_strings(v->items[i])) return true;
    return false;
}
unsigned char *yd_binary_pack_profile(const unsigned char *source, size_t length, bool large,
                              size_t *packed_length, char *error, size_t error_length)
{
    if (length == 0 || length > (large ? YD_LARGE_DOCUMENT_LIMIT : YD_DOCUMENT_LIMIT)) return NULL;
    YDValue *value = yd_parse_sized(source, length, large ? YD_LARGE_DOCUMENT_LIMIT : YD_DOCUMENT_LIMIT, error, error_length);
    if (value == NULL) return NULL;
    bool extended = length > YD_DOCUMENT_LIMIT || extended_strings(value);
    if (extended && !large) { yd_free(value); return NULL; }
    size_t n = 0; unsigned char *encoded = yd_value_encode_profile(value, &n, extended); yd_free(value);
    if (encoded == NULL) return NULL;
    size_t size = 20 + length + n + 4;
    unsigned char *packed = calloc(1, size);
    if (packed == NULL) { free(encoded); return NULL; }
    memcpy(packed, extended ? "YAMDOC02" : "YAMDOC01", 8); write32(packed+8, length); write32(packed+12, n);
    memcpy(packed+20, source, length); memcpy(packed+20+length, encoded, n); free(encoded);
    write32(packed+size-4, crc32c(packed, size-4));
    *packed_length = size; return packed;
}
bool yd_binary_unpack_profile(const unsigned char *packed, size_t packed_length, bool large,
                       unsigned char **source, size_t *length, YDValue **value)
{
    *source = NULL; *value = NULL; *length = 0;
    if (packed_length < 24) return false;
    bool extended = !memcmp(packed, "YAMDOC02", 8);
    if ((extended && !large) || (!extended && memcmp(packed, "YAMDOC01", 8)) ||
        packed_length > (extended ? YD_BINARY_LARGE_FILE_LIMIT : YD_BINARY_FILE_LIMIT) || read32(packed+16)) return false;
    size_t n = read32(packed+8), m = read32(packed+12);
    if (n == 0 || n > (extended ? YD_LARGE_DOCUMENT_LIMIT : YD_DOCUMENT_LIMIT) ||
        m > (extended ? YD_BINARY_LARGE_VALUE_LIMIT : YD_BINARY_VALUE_LIMIT) ||
        packed_length != 24+n+m || read32(packed+packed_length-4) != crc32c(packed, packed_length-4) ||
        !yamldb_valid_document_body(packed+20, n)) return false;
    YDValue *decoded = yd_value_decode_profile(packed+20+n, m, n, extended);
    if (decoded == NULL) return false;
    unsigned char *body = malloc(n);
    if (body == NULL) { yd_free(decoded); return false; }
    memcpy(body, packed+20, n); *source = body; *length = n; *value = decoded; return true;
}

unsigned char *yd_binary_pack(const unsigned char *source, size_t length, size_t *packed_length, char *error, size_t error_length) {
    return yd_binary_pack_profile(source, length, false, packed_length, error, error_length);
}
bool yd_binary_unpack(const unsigned char *packed, size_t packed_length, unsigned char **source, size_t *length, YDValue **value) {
    return yd_binary_unpack_profile(packed, packed_length, false, source, length, value);
}

bool yd_binary_initialize(const char *root, const YamlDBSnapshot *source, char *error, size_t length)
{
    /* Validate before creating any destination state. */
    for (size_t c=0; c<source->collection_count; c++)
        for (size_t d=0; d<source->collections[c].document_count; d++)
            if (source->collections[c].documents[d].value == NULL)
                return fail(error, length, "binary import requires documents in Yamora's typed YAML profile");
    int rootfd = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (rootfd < 0) return fail(error, length, "cannot open binary destination");
    int scan = dup(rootfd); DIR *dir = scan < 0 ? NULL : fdopendir(scan);
    if (dir == NULL) { if (scan >= 0) close(scan); close(rootfd); return fail(error, length, "cannot scan binary destination"); }
    bool valid = true;
    for (;;) {
        errno = 0; struct dirent *entry = readdir(dir);
        if (entry == NULL) { if (errno) valid = false; break; }
        if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) { valid = false; break; }
    }
    closedir(dir);
    if (!valid) { close(rootfd); return fail(error, length, "binary initialization requires an empty root"); }
    size_t count = source->collection_count + source->document_count;
    YDWrite *writes = count == 0 ? NULL : calloc(count, sizeof(*writes));
    if (count && writes == NULL) { close(rootfd); return false; }
    size_t used = 0;
    for (size_t c=0; c<source->collection_count; c++) {
        const YamlDBCollection *collection = &source->collections[c];
        writes[used++] = (YDWrite){.collection=collection->name, .kind=YD_WRITE_CREATE_COLLECTION};
        for (size_t d=0; d<collection->document_count; d++) {
            const YamlDBDocument *doc = &collection->documents[d];
            writes[used++] = (YDWrite){.collection=collection->name, .document=doc->name, .body=doc->body, .length=doc->length};
        }
    }
    /* This sentinel precedes every other destination change. Failed or killed
     * imports must never be mistaken for successfully initialized empty roots. */
    int pending = openat(rootfd, YD_BINARY_INITIALIZING, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    valid = pending >= 0;
    if (valid) { valid = fsync(pending) == 0; if (close(pending)) valid = false; }
    if (valid) valid = fsync(rootfd) == 0;
    if (!valid) { close(rootfd); free(writes); return fail(error, length, "cannot persist initialization sentinel"); }
    int fd = openat(rootfd, YD_BINARY_MARKER, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    valid = fd >= 0;
    if (valid) { valid = write(fd, "YAMORA1\n", 8) == 8 && fsync(fd) == 0; if (close(fd)) valid = false; }
    if (valid) valid = fsync(rootfd) == 0;
    close(rootfd);
    bool committed = false;
    if (valid && count) valid = yd_journal_commit(root, writes, count, &committed, error, length);
    free(writes);
    if (valid && source->revision[0] != 0) {
        YamlDBSnapshot check;
        valid = yamldb_snapshot_load(root, &check, error, length);
        if (valid) { valid = strcmp(source->revision, check.revision) == 0; yamldb_snapshot_free(&check); }
    }
    if (valid) {
        rootfd = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        valid = rootfd >= 0;
        if (valid) { valid = unlinkat(rootfd, YD_BINARY_INITIALIZING, 0) == 0 && fsync(rootfd) == 0; close(rootfd); }
    }
    return valid || fail(error, length, "native initialization failed; source unchanged; preserve destination and import into a new root");
}
