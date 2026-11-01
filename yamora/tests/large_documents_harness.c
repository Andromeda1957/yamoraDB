#define _POSIX_C_SOURCE 200809L
#include "../src/binary.h"
#include "../src/disk_bulk.h"
#include "../src/disk_index_build.h"
#include "../src/disk_internal.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static unsigned fail_sync, calls;
int __real_fsync(int fd);
int __wrap_fsync(int fd) {
    if (++calls == fail_sync) { errno = EIO; return -1; }
    return __real_fsync(fd);
}
static char error[512];
#define REQUIRE(x) do { if (!(x)) { fprintf(stderr, "line %u: %s: %s\n", __LINE__, #x, error); return false; } } while (0)
static bool codec(void) {
    /* Escaped YAML can decode to a larger UTF-8 scalar than its source. */
    size_t length = YD_LARGE_DOCUMENT_LIMIT;
    unsigned char *source = malloc(length);
    REQUIRE(source);
    source[0] = '"'; source[1] = 'x';
    for (size_t i = 2; i < length - 2; i += 2) { source[i] = '\\'; source[i+1] = 'L'; }
    source[length-2] = '"'; source[length-1] = '\n';
    size_t size = 0, n = 0; unsigned char *decoded = NULL; YDValue *value = NULL;
    unsigned char *packed = yd_binary_pack_profile(source, length, true, &size, error, sizeof(error));
    REQUIRE(packed && !memcmp(packed, "YAMDOC02", 8));
    REQUIRE(!yd_binary_unpack(packed, size, &decoded, &n, &value));
    REQUIRE(yd_binary_unpack_profile(packed, size, true, &decoded, &n, &value));
    REQUIRE(n == length && !memcmp(decoded, source, n) && strlen(value->scalar) > length);
    yd_free(value); free(decoded);
    REQUIRE(!yd_binary_unpack_profile(packed, size - 1, true, &decoded, &n, &value));
    packed[size / 2] ^= 1;
    REQUIRE(!yd_binary_unpack_profile(packed, size, true, &decoded, &n, &value));
    free(packed); free(source);
    const unsigned char small[] = "v: 1\n";
    packed = yd_binary_pack_profile(small, sizeof(small)-1, true, &size, error, sizeof(error));
    REQUIRE(packed && !memcmp(packed, "YAMDOC01", 8));
    REQUIRE(yd_binary_unpack(packed, size, &decoded, &n, &value));
    yd_free(value); free(decoded); free(packed);
    return true;
}
static unsigned char *body(unsigned char ch, size_t *size) {
    *size = 3U * 1024U * 1024U;
    unsigned char *source = malloc(*size);
    if (source) { memcpy(source, "n: 1\ntext: ", 11); memset(source + 11, ch, *size - 12); source[*size - 1] = '\n'; }
    return source;
}
static bool put(YDDisk *disk, unsigned char ch) {
    size_t size; unsigned char *source = body(ch, &size);
    REQUIRE(source);
    YDWrite write = {.collection="items", .document="large", .body=source, .length=size};
    YDDiskTxn *txn = yd_disk_begin(disk, error, sizeof(error));
    REQUIRE(txn);
    bool valid = yd_disk_apply(txn, &write, 1, error, sizeof(error));
    free(source);
    if (valid) valid = yd_disk_commit(txn, error, sizeof(error));
    else yd_disk_abort(txn);
    return valid;
}
typedef struct { YDDisk *disk; bool injected; } Build;
static bool progress(void *context, const char *phase) {
    Build *build = context;
    if (!build->injected && !strcmp(phase, "scan")) {
        build->injected = true;
        return put(build->disk, 'y');
    }
    return true;
}
static bool inspect(YDDisk *disk, bool indexed) {
    YDDiskView view = yd_disk_view(disk);
    REQUIRE(view.format == 5 && view.documents == (indexed ? 2U : 1U) && view.collections == (indexed ? 2U : 1U));
    YDDiskDocument doc;
    REQUIRE(yd_disk_document_get(disk, &view, "items", "large", &doc, error, sizeof(error)) == 1);
    size_t size; unsigned char *expected = body(doc.body[11], &size);
    REQUIRE(expected && (doc.body[11] == 'x' || doc.body[11] == 'y') && doc.length == size && !memcmp(expected, doc.body, size));
    yd_disk_document_free(&doc); free(expected);
    REQUIRE(yd_disk_validate(disk, &view, error, sizeof(error)));
    return true;
}
int main(int argc, char **argv) {
    if (argc != 3) return 2;
    if (!strcmp(argv[2], "codec")) return codec() ? 0 : 3;
    YDDisk *disk = yd_disk_open(argv[1], strcmp(argv[2], "check") != 0, 32768, error, sizeof(error));
    if (!disk) { fprintf(stderr, "%s\n", error); return 4; }
    bool valid = false;
    if (!strcmp(argv[2], "seed")) valid = put(disk, 'x');
    else if (!strcmp(argv[2], "check")) valid = inspect(disk, false);
    else if (!strcmp(argv[2], "online")) {
        YDDiskView pinned = yd_disk_view(disk), receipt;
        Build build = {.disk=disk};
        const unsigned char catalog[] = "{indexes: [{collection: items, name: number, fields: [n], unique: true}]}";
        valid = yd_disk_indexes_online(disk, catalog, sizeof(catalog)-1, progress, &build, &receipt, error, sizeof(error)) && build.injected && inspect(disk, true);
        YDDiskDocument old;
        if (valid) valid = yd_disk_document_get(disk, &pinned, "items", "large", &old, error, sizeof(error)) == 1;
        if (valid) { valid = old.body[11] == 'x'; yd_disk_document_free(&old); }
    } else {
        bool fault = !strncmp(argv[2], "fail-", 5);
        if (fault) { fail_sync = (unsigned)strtoul(argv[2]+5, NULL, 10); calls = 0; }
        YDDiskView before = yd_disk_view(disk);
        valid = put(disk, 'y');
        if (fault) {
            YDDiskView current = yd_disk_view(disk);
            valid = !valid && current.root == before.root && current.generation == before.generation;
            /* Failure before header publication leaves a known old root. Only
             * the ambiguous header synchronization failure must fence writes. */
            if (fail_sync == 2)
                valid = valid && !yd_disk_writable(disk) && yd_disk_begin(disk, error, sizeof(error)) == NULL;
            else valid = valid && yd_disk_writable(disk);
        }
    }
    yd_disk_close(disk);
    if (!valid) fprintf(stderr, "%s\n", error);
    return valid ? 0 : 5;
}
