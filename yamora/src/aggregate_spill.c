#define _GNU_SOURCE
#include "aggregate_spill.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* A run is a contiguous sequence of sealed blocks: up to BLOCK plaintext bytes
 * followed by a 16-byte GCM tag. The nonce is the request's block counter and
 * the associated data binds each block to its file offset and length. */
#define BLOCK 16384U
#define TAG_BYTES 16U
#define SEALED (BLOCK + TAG_BYTES)
#define FAN_IN 16U
#define RECORD_LIMIT (80U * 1024U * 1024U)
#define DECODE_DEPTH (YD_DEPTH_LIMIT + 16U)
#define PRESSURE_RUN (64U * 1024U)
#define LIMIT_MINIMUM (64ULL * 1024ULL)
#define LIMIT_MAXIMUM (1ULL << 40)
#define PREFIX ".yamora-spill-"
#define NAME_HEX 32U
/* Native tests define this to exercise the named-file fallback used where the
 * filesystem lacks O_TMPFILE; production builds always try O_TMPFILE first. */
#ifdef YD_AGGREGATE_SPILL_NAMED_FILES
#undef O_TMPFILE
#endif

static int directory = -1;
static unsigned long long total_limit = YD_AGGREGATE_SPILL_DEFAULT_TOTAL;
static unsigned long long request_limit = YD_AGGREGATE_SPILL_DEFAULT_REQUEST;
static size_t memory_limit = YD_AGGREGATE_MEMORY_DEFAULT;
static bool named_fallback;
static _Atomic unsigned long long in_use;
static const char *option_directory;
static unsigned long long option_total, option_request, option_memory;

static bool fail(char *error, size_t length, const char *message) {
    if (length)
        snprintf(error, length, "%s", message);
    return false;
}

static bool parse_bytes(const char *text, unsigned long long minimum, unsigned long long maximum,
                        unsigned long long *out) {
    if (!text || !*text || strlen(text) > 20)
        return false;
    for (const char *s = text; *s; s++)
        if (*s < '0' || *s > '9')
            return false;
    errno = 0;
    char *end = NULL;
    unsigned long long value = strtoull(text, &end, 10);
    if (errno || !end || *end || value < minimum || value > maximum)
        return false;
    *out = value;
    return true;
}

int yd_aggregate_spill_argument(int argc, char **argv, int index) {
    static const char *const names[] = {"--aggregate-spill-directory", "--aggregate-spill-limit",
                                        "--aggregate-spill-request-limit",
                                        "--aggregate-memory-limit"};
    if (index < 0 || index >= argc || !argv[index])
        return 0;
    size_t which = 0;
    while (which < 4 && strcmp(argv[index], names[which]))
        which++;
    if (which == 4)
        return 0;
    if (index + 1 >= argc || !argv[index + 1])
        return -1;
    const char *value = argv[index + 1];
    if (which == 0) {
        if (option_directory || !*value)
            return -1;
        option_directory = value;
        return 2;
    }
    unsigned long long *slot = which == 1 ? &option_total : which == 2 ? &option_request : &option_memory;
    unsigned long long low = which == 3 ? YD_AGGREGATE_MEMORY_MINIMUM : LIMIT_MINIMUM;
    unsigned long long high = which == 3 ? YD_AGGREGATE_MEMORY_MAXIMUM : LIMIT_MAXIMUM;
    if (*slot || !parse_bytes(value, low, high, slot))
        return -1;
    return 2;
}

const char *yd_aggregate_spill_usage(void) {
    return "       [--aggregate-spill-directory PRIVATE_DIR [--aggregate-spill-limit BYTES] "
           "[--aggregate-spill-request-limit BYTES] [--aggregate-memory-limit BYTES]]\n";
}

static bool leftover(const char *name) {
    size_t prefix = strlen(PREFIX);
    if (strncmp(name, PREFIX, prefix) || strlen(name) != prefix + NAME_HEX)
        return false;
    for (const char *s = name + prefix; *s; s++)
        if (!((*s >= '0' && *s <= '9') || (*s >= 'a' && *s <= 'f')))
            return false;
    return true;
}

/* Only regular files with the exact spill name and the daemon's owner are
 * removed; links, directories and anything else are left untouched. */
static bool sweep(int fd, char *error, size_t length) {
    int copy = openat(fd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    DIR *listing = copy >= 0 ? fdopendir(copy) : NULL;
    if (!listing) {
        if (copy >= 0)
            close(copy);
        return fail(error, length, "aggregate spill directory cannot be listed");
    }
    bool ok = true;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(listing);
        if (!entry) {
            ok = errno == 0;
            break;
        }
        if (!leftover(entry->d_name))
            continue;
        struct stat st;
        if (fstatat(fd, entry->d_name, &st, AT_SYMLINK_NOFOLLOW)) {
            if (errno == ENOENT)
                continue;
            ok = false;
            break;
        }
        if (!S_ISREG(st.st_mode) || st.st_uid != geteuid())
            continue;
        if (unlinkat(fd, entry->d_name, 0) && errno != ENOENT) {
            ok = false;
            break;
        }
    }
    closedir(listing);
    return ok || fail(error, length, "aggregate spill directory cleanup failed");
}

static int named(int dir, char *error, size_t length) {
    for (int attempt = 0; attempt < 8; attempt++) {
        unsigned char random[NAME_HEX / 2];
        char name[sizeof(PREFIX) + NAME_HEX];
        if (RAND_bytes(random, sizeof(random)) != 1) {
            fail(error, length, "aggregate spill name generation failed");
            return -1;
        }
        size_t at = (size_t)snprintf(name, sizeof(name), "%s", PREFIX);
        for (size_t i = 0; i < sizeof(random); i++)
            at += (size_t)snprintf(name + at, sizeof(name) - at, "%02x", random[i]);
        int fd = openat(dir, name, O_CREAT | O_EXCL | O_RDWR | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (fd < 0) {
            if (errno == EEXIST)
                continue;
            fail(error, length, "aggregate spill file could not be created");
            return -1;
        }
        /* A crash before this unlink leaves a name that the next start removes. */
        if (unlinkat(dir, name, 0) && errno != ENOENT) {
            close(fd);
            fail(error, length, "aggregate spill file could not be unlinked");
            return -1;
        }
        return fd;
    }
    fail(error, length, "aggregate spill file could not be created");
    return -1;
}

#ifdef O_TMPFILE
static bool tmpfile_unsupported(int code) {
    return code == EOPNOTSUPP || code == EISDIR || code == EINVAL;
}
#endif

static int create(int dir, bool fallback, char *error, size_t length) {
    int fd = -1;
#ifdef O_TMPFILE
    if (!fallback) {
        fd = openat(dir, ".", O_TMPFILE | O_RDWR | O_CLOEXEC, 0600);
        if (fd < 0 && !tmpfile_unsupported(errno)) {
            fail(error, length, "aggregate spill file could not be created");
            return -1;
        }
    }
#else
    (void)fallback;
#endif
    if (fd < 0 && (fd = named(dir, error, length)) < 0)
        return -1;
    struct stat st;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_uid != geteuid() || st.st_nlink ||
        (st.st_mode & 077)) {
        close(fd);
        fail(error, length, "aggregate spill file is not private");
        return -1;
    }
    return fd;
}

bool yd_aggregate_spill_configure(const char *path, unsigned long long total,
                                  unsigned long long request, size_t memory, char *error,
                                  size_t length) {
    if (!path || path[0] != '/')
        return fail(error, length, "aggregate spill directory must be an absolute path");
    if (!total)
        total = YD_AGGREGATE_SPILL_DEFAULT_TOTAL;
    if (!request)
        request = YD_AGGREGATE_SPILL_DEFAULT_REQUEST < total ? YD_AGGREGATE_SPILL_DEFAULT_REQUEST
                                                             : total;
    if (!memory)
        memory = YD_AGGREGATE_MEMORY_DEFAULT;
    if (total < LIMIT_MINIMUM || total > LIMIT_MAXIMUM || request < LIMIT_MINIMUM || request > total)
        return fail(error, length,
                    "aggregate spill limits must be 64 KiB..1 TiB with the request limit within the server limit");
    if (memory < YD_AGGREGATE_MEMORY_MINIMUM || memory > YD_AGGREGATE_MEMORY_MAXIMUM)
        return fail(error, length, "aggregate memory limit must be 64 KiB..48 MiB");
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return fail(error, length, "aggregate spill directory is unavailable or a symbolic link");
    struct stat st;
    if (fstat(fd, &st) || !S_ISDIR(st.st_mode) || st.st_uid != geteuid() || (st.st_mode & 077)) {
        close(fd);
        return fail(error, length,
                    "aggregate spill directory must be owned by the daemon user with mode 0700");
    }
    if (!sweep(fd, error, length)) {
        close(fd);
        return false;
    }
    bool fallback = false;
    int probe = -1;
#ifdef O_TMPFILE
    probe = openat(fd, ".", O_TMPFILE | O_RDWR | O_CLOEXEC, 0600);
    if (probe < 0 && !tmpfile_unsupported(errno)) {
        close(fd);
        return fail(error, length, "aggregate spill directory is not writable");
    }
#endif
    if (probe < 0) {
        fallback = true;
        probe = create(fd, true, error, length);
        if (probe < 0) {
            close(fd);
            return false;
        }
    }
    close(probe);
    if (directory >= 0)
        close(directory);
    directory = fd;
    total_limit = total;
    request_limit = request;
    memory_limit = memory;
    named_fallback = fallback;
    return true;
}

void yd_aggregate_spill_shutdown(void) {
    if (directory >= 0)
        close(directory);
    directory = -1;
    total_limit = YD_AGGREGATE_SPILL_DEFAULT_TOTAL;
    request_limit = YD_AGGREGATE_SPILL_DEFAULT_REQUEST;
    memory_limit = YD_AGGREGATE_MEMORY_DEFAULT;
    named_fallback = false;
}

bool yd_aggregate_spill_start(char *error, size_t length) {
    if (!option_directory) {
        if (option_total || option_request || option_memory)
            return fail(error, length, "aggregate spill limits require --aggregate-spill-directory");
        return true;
    }
    return yd_aggregate_spill_configure(option_directory, option_total, option_request,
                                        (size_t)option_memory, error, length);
}

bool yd_aggregate_spill_available(void) { return directory >= 0; }
unsigned long long yd_aggregate_spill_request_limit(void) { return request_limit; }
size_t yd_aggregate_spill_memory_limit(void) { return memory_limit; }
unsigned long long yd_aggregate_spill_in_use(void) { return atomic_load(&in_use); }

typedef struct {
    unsigned char *data;
    size_t size, capacity;
    bool failed;
} Bytes;

struct YDSpill {
    int fd;
    unsigned long long limit, written, accounted, runs;
    uint64_t nonce;
    unsigned char key[32];
    EVP_CIPHER_CTX *seal, *open;
    size_t used;
    unsigned char plain[BLOCK];
    unsigned char sealed[SEALED];
    Bytes scratch;
};

YDSpill *yd_spill_open(unsigned long long max_bytes, char *error, size_t length) {
    if (directory < 0) {
        fail(error, length, "aggregate disk use is not enabled on this server");
        return NULL;
    }
    if (max_bytes > request_limit) {
        fail(error, length, "maxSpillBytes exceeds the server request spill limit");
        return NULL;
    }
    YDSpill *spill = calloc(1, sizeof(*spill));
    if (!spill) {
        fail(error, length, "aggregation allocation failed");
        return NULL;
    }
    spill->fd = -1;
    spill->limit = max_bytes ? max_bytes : request_limit;
    return spill;
}

void yd_spill_close(YDSpill *spill) {
    if (!spill)
        return;
    if (spill->fd >= 0)
        close(spill->fd);
    if (spill->accounted)
        atomic_fetch_sub(&in_use, spill->accounted);
    EVP_CIPHER_CTX_free(spill->seal);
    EVP_CIPHER_CTX_free(spill->open);
    if (spill->scratch.data)
        OPENSSL_cleanse(spill->scratch.data, spill->scratch.capacity);
    free(spill->scratch.data);
    OPENSSL_cleanse(spill, sizeof(*spill));
    free(spill);
}

unsigned long long yd_spill_bytes(const YDSpill *spill) { return spill ? spill->written : 0; }
unsigned long long yd_spill_runs(const YDSpill *spill) { return spill ? spill->runs : 0; }
unsigned long long yd_spill_limit(const YDSpill *spill) { return spill ? spill->limit : 0; }

/* The file and key exist only once the first block is sealed. */
static bool prepare(YDSpill *spill, char *error, size_t length) {
    if (spill->fd >= 0)
        return true;
    if (directory < 0)
        return fail(error, length, "aggregate disk use is not enabled on this server");
    if (RAND_priv_bytes(spill->key, sizeof(spill->key)) != 1)
        return fail(error, length, "aggregate spill key generation failed");
    if (!spill->seal)
        spill->seal = EVP_CIPHER_CTX_new();
    if (!spill->open)
        spill->open = EVP_CIPHER_CTX_new();
    if (!spill->seal || !spill->open ||
        EVP_EncryptInit_ex(spill->seal, EVP_aes_256_gcm(), NULL, spill->key, NULL) != 1 ||
        EVP_DecryptInit_ex(spill->open, EVP_aes_256_gcm(), NULL, spill->key, NULL) != 1)
        return fail(error, length, "aggregate spill cipher initialization failed");
    int fd = create(directory, named_fallback, error, length);
    if (fd < 0)
        return false;
    spill->fd = fd;
    return true;
}

static void be64(unsigned char *out, uint64_t value) {
    for (int i = 7; i >= 0; i--) {
        out[i] = (unsigned char)(value & 255U);
        value >>= 8;
    }
}

static void block_context(unsigned char iv[12], unsigned char aad[12], uint64_t nonce,
                          uint64_t offset, size_t size) {
    memset(iv, 0, 12);
    be64(iv + 4, nonce);
    be64(aad, offset);
    for (int i = 0; i < 4; i++)
        aad[8 + i] = (unsigned char)((size >> (24 - 8 * i)) & 255U);
}

static bool seal_block(YDSpill *spill, const unsigned char *plain, size_t size, char *error,
                       size_t length) {
    size_t bytes = size + TAG_BYTES;
    if (spill->written > spill->limit || bytes > spill->limit - spill->written)
        return fail(error, length, "aggregate spill exceeds the request limit");
    if (!prepare(spill, error, length))
        return false;
    unsigned long long before = atomic_fetch_add(&in_use, bytes);
    if (before > total_limit || bytes > total_limit - before) {
        atomic_fetch_sub(&in_use, bytes);
        return fail(error, length, "aggregate spill exceeds the server limit");
    }
    spill->accounted += bytes;
    unsigned char iv[12], aad[12];
    block_context(iv, aad, spill->nonce, spill->written, size);
    int out = 0, final = 0;
    if (EVP_EncryptInit_ex(spill->seal, NULL, NULL, NULL, iv) != 1 ||
        EVP_EncryptUpdate(spill->seal, NULL, &out, aad, sizeof(aad)) != 1 ||
        EVP_EncryptUpdate(spill->seal, spill->sealed, &out, plain, (int)size) != 1 ||
        out != (int)size || EVP_EncryptFinal_ex(spill->seal, spill->sealed + out, &final) != 1 ||
        final != 0 ||
        EVP_CIPHER_CTX_ctrl(spill->seal, EVP_CTRL_GCM_GET_TAG, TAG_BYTES, spill->sealed + size) != 1)
        return fail(error, length, "aggregate spill encryption failed");
    size_t done = 0;
    while (done < bytes) {
        ssize_t n = pwrite(spill->fd, spill->sealed + done, bytes - done,
                           (off_t)(spill->written + done));
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return fail(error, length, "aggregate spill write failed");
        done += (size_t)n;
    }
    spill->written += bytes;
    spill->nonce++;
    return true;
}

static bool unseal_block(YDSpill *spill, uint64_t offset, uint64_t nonce, size_t size,
                         unsigned char *out, char *error, size_t length) {
    size_t bytes = size + TAG_BYTES, done = 0;
    if (spill->fd < 0 || size > BLOCK || offset > spill->written || bytes > spill->written - offset)
        return fail(error, length, "aggregate spill block is out of range");
    while (done < bytes) {
        ssize_t n = pread(spill->fd, spill->sealed + done, bytes - done, (off_t)(offset + done));
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return fail(error, length, "aggregate spill read failed");
        done += (size_t)n;
    }
    unsigned char iv[12], aad[12];
    block_context(iv, aad, nonce, offset, size);
    int got = 0, final = 0;
    if (EVP_DecryptInit_ex(spill->open, NULL, NULL, NULL, iv) != 1 ||
        EVP_DecryptUpdate(spill->open, NULL, &got, aad, sizeof(aad)) != 1 ||
        EVP_DecryptUpdate(spill->open, out, &got, spill->sealed, (int)size) != 1 ||
        got != (int)size ||
        EVP_CIPHER_CTX_ctrl(spill->open, EVP_CTRL_GCM_SET_TAG, TAG_BYTES, spill->sealed + size) != 1 ||
        EVP_DecryptFinal_ex(spill->open, out + got, &final) != 1)
        return fail(error, length, "aggregate spill block failed authentication");
    return true;
}

typedef struct {
    uint64_t offset, plain, nonce, records;
} Run;

static void writer_begin(YDSpill *spill, Run *run) {
    spill->used = 0;
    *run = (Run){.offset = spill->written, .nonce = spill->nonce};
}

static bool writer_put(YDSpill *spill, Run *run, const unsigned char *data, size_t size,
                       char *error, size_t length) {
    while (size) {
        size_t take = BLOCK - spill->used;
        if (take > size)
            take = size;
        memcpy(spill->plain + spill->used, data, take);
        spill->used += take;
        data += take;
        size -= take;
        run->plain += take;
        if (spill->used == BLOCK) {
            if (!seal_block(spill, spill->plain, BLOCK, error, length))
                return false;
            spill->used = 0;
        }
    }
    return true;
}

static bool writer_end(YDSpill *spill, Run *run, char *error, size_t length) {
    (void)run;
    if (spill->used && !seal_block(spill, spill->plain, spill->used, error, length))
        return false;
    spill->used = 0;
    spill->runs++;
    return true;
}

static void put(Bytes *b, const void *data, size_t size) {
    if (b->failed)
        return;
    if (size > RECORD_LIMIT || b->size > RECORD_LIMIT - size) {
        b->failed = true;
        return;
    }
    if (b->size + size > b->capacity) {
        size_t capacity = b->capacity ? b->capacity : 256;
        while (capacity < b->size + size)
            capacity *= 2;
        unsigned char *grown = realloc(b->data, capacity);
        if (!grown) {
            b->failed = true;
            return;
        }
        b->data = grown;
        b->capacity = capacity;
    }
    if (size)
        memcpy(b->data + b->size, data, size);
    b->size += size;
}

static size_t varint(unsigned char out[10], uint64_t value) {
    size_t n = 0;
    do {
        unsigned char c = (unsigned char)(value & 127U);
        value >>= 7;
        out[n++] = (unsigned char)(c | (value ? 128U : 0U));
    } while (value);
    return n;
}

static void put_varint(Bytes *b, uint64_t value) {
    unsigned char out[10];
    put(b, out, varint(out, value));
}

static void put_text(Bytes *b, const char *text) {
    size_t n = strlen(text);
    put_varint(b, n);
    put(b, text, n);
}

typedef union {
    long double number;
    unsigned char bytes[sizeof(long double)];
} Number;

/* Exact tree encoding: type, numeric bits, decoded spelling, source offsets,
 * keys and members, with NULL members preserved as missing. */
static void encode(Bytes *b, const YDValue *v, unsigned depth) {
    if (b->failed)
        return;
    if (depth > DECODE_DEPTH) {
        b->failed = true;
        return;
    }
    if (!v) {
        unsigned char missing = 0;
        put(b, &missing, 1);
        return;
    }
    if ((unsigned)v->type > (unsigned)YD_MAP ||
        (v->count && v->type != YD_ARRAY && v->type != YD_MAP)) {
        b->failed = true;
        return;
    }
    bool number = v->type == YD_INT || v->type == YD_FLOAT || v->number != 0;
    unsigned char head[2] = {(unsigned char)(1U + (unsigned)v->type),
                             (unsigned char)((v->scalar ? 1U : 0U) | (v->boolean ? 2U : 0U) |
                                             (number ? 4U : 0U))};
    put(b, head, sizeof(head));
    if (number) {
        Number n;
        memset(&n, 0, sizeof(n));
        n.number = v->number;
        put(b, n.bytes, sizeof(n.bytes));
    }
    if (v->scalar)
        put_text(b, v->scalar);
    put_varint(b, v->start);
    put_varint(b, v->end);
    if (v->type == YD_ARRAY || v->type == YD_MAP) {
        put_varint(b, v->count);
        for (size_t i = 0; i < v->count; i++) {
            if (v->type == YD_MAP)
                put_text(b, v->keys[i]);
            encode(b, v->items[i], depth + 1);
        }
    }
}

typedef struct {
    const unsigned char *data;
    size_t size, at;
} Reader;

static bool get(Reader *r, void *out, size_t size) {
    if (size > r->size - r->at)
        return false;
    memcpy(out, r->data + r->at, size);
    r->at += size;
    return true;
}

static bool get_varint(Reader *r, uint64_t *out) {
    uint64_t value = 0;
    for (unsigned shift = 0; shift < 64; shift += 7) {
        if (r->at == r->size)
            return false;
        unsigned char c = r->data[r->at++];
        if (shift == 63 && (c & 126U))
            return false;
        value |= (uint64_t)(c & 127U) << shift;
        if (!(c & 128U)) {
            *out = value;
            return true;
        }
    }
    return false;
}

static char *get_text(Reader *r) {
    uint64_t n = 0;
    if (!get_varint(r, &n) || n > r->size - r->at || memchr(r->data + r->at, 0, (size_t)n))
        return NULL;
    char *text = malloc((size_t)n + 1);
    if (!text)
        return NULL;
    memcpy(text, r->data + r->at, (size_t)n);
    text[n] = 0;
    r->at += (size_t)n;
    return text;
}

static bool decode(Reader *r, unsigned depth, YDValue **out) {
    *out = NULL;
    unsigned char tag = 0, flags = 0;
    if (!get(r, &tag, 1))
        return false;
    if (!tag)
        return true;
    if (tag > 1U + (unsigned)YD_MAP || depth > DECODE_DEPTH || !get(r, &flags, 1) || flags > 7U)
        return false;
    YDValue *v = calloc(1, sizeof(*v));
    if (!v)
        return false;
    v->type = (YDType)(tag - 1U);
    v->boolean = (flags & 2U) != 0;
    bool ok = true;
    if (flags & 4U) {
        Number n;
        ok = get(r, n.bytes, sizeof(n.bytes));
        v->number = ok ? n.number : 0;
    }
    if (ok && (flags & 1U))
        ok = (v->scalar = get_text(r)) != NULL;
    uint64_t start = 0, end = 0;
    ok = ok && get_varint(r, &start) && get_varint(r, &end) && start <= SIZE_MAX && end <= SIZE_MAX;
    v->start = (size_t)start;
    v->end = (size_t)end;
    if (ok && (v->type == YD_ARRAY || v->type == YD_MAP)) {
        uint64_t count = 0;
        /* Every member occupies at least one byte, which bounds the arrays. */
        ok = get_varint(r, &count) && count <= r->size - r->at;
        if (ok && count) {
            v->items = calloc((size_t)count, sizeof(*v->items));
            if (v->type == YD_MAP)
                v->keys = calloc((size_t)count, sizeof(*v->keys));
            ok = v->items && (v->type != YD_MAP || v->keys);
        }
        for (uint64_t i = 0; ok && i < count; i++) {
            char *key = NULL;
            if (v->type == YD_MAP && !(key = get_text(r))) {
                ok = false;
                break;
            }
            YDValue *item = NULL;
            ok = decode(r, depth + 1, &item);
            if (v->keys)
                v->keys[v->count] = key;
            v->items[v->count++] = item;
        }
    }
    if (!ok) {
        yd_free(v);
        return false;
    }
    *out = v;
    return true;
}

static bool put_raw(YDSpill *spill, Run *run, const unsigned char *data, size_t size, char *error,
                    size_t length) {
    unsigned char prefix[10];
    bool ok = writer_put(spill, run, prefix, varint(prefix, size), error, length) &&
              writer_put(spill, run, data, size, error, length);
    if (ok)
        run->records++;
    return ok;
}

static bool put_record(YDSpill *spill, Run *run, const YDValue *record, char *error, size_t length) {
    Bytes *b = &spill->scratch;
    b->size = 0;
    b->failed = false;
    encode(b, record, 0);
    bool ok = !b->failed || fail(error, length, "aggregate spill record exceeds bounds");
    if (ok)
        ok = put_raw(spill, run, b->data, b->size, error, length);
    if (b->capacity > 1024U * 1024U) {
        OPENSSL_cleanse(b->data, b->capacity);
        free(b->data);
        *b = (Bytes){0};
    }
    return ok;
}

typedef struct {
    Run run;
    uint64_t block, consumed;
    unsigned char *buffer;
    size_t size, at;
    YDValue *head;
    unsigned char *raw;
    size_t raw_size, head_charge, raw_charge;
    bool buffer_charged;
} Cursor;

struct YDSpillSorter {
    YDSpill *spill;
    YDSpillHooks hooks;
    size_t flush_bytes;
    YDValue **records;
    size_t count, capacity, held, at;
    Run *runs;
    size_t run_count, run_capacity;
    Cursor *cursors;
    size_t cursor_count;
    bool finished;
};

static bool hold(YDSpillSorter *s, size_t bytes, char *error, size_t length) {
    return !bytes || !s->hooks.reserve || s->hooks.reserve(s->hooks.memory_context, bytes, error, length);
}

static void drop(YDSpillSorter *s, size_t bytes) {
    if (bytes && s->hooks.release)
        s->hooks.release(s->hooks.memory_context, bytes);
}

static bool check(YDSpillSorter *s, char *error, size_t length) {
    return !s->hooks.check || s->hooks.check(s->hooks.memory_context, error, length);
}

static int compare(YDSpillSorter *s, const YDValue *a, const YDValue *b) {
    return s->hooks.compare(a, b, s->hooks.compare_context);
}

static void sift(YDSpillSorter *s, YDValue **a, size_t n, size_t at) {
    for (;;) {
        size_t child = at * 2 + 1;
        if (child >= n)
            return;
        if (child + 1 < n && compare(s, a[child], a[child + 1]) < 0)
            child++;
        if (compare(s, a[at], a[child]) >= 0)
            return;
        YDValue *t = a[at];
        a[at] = a[child];
        a[child] = t;
        at = child;
    }
}

static void sort_records(YDSpillSorter *s, YDValue **a, size_t n) {
    for (size_t i = n / 2; i; i--)
        sift(s, a, n, i - 1);
    for (size_t i = n; i > 1; i--) {
        YDValue *t = a[0];
        a[0] = a[i - 1];
        a[i - 1] = t;
        sift(s, a, i - 1, 0);
    }
}

YDSpillSorter *yd_spill_sorter_new(YDSpill *spill, const YDSpillHooks *hooks, size_t flush_bytes,
                                   char *error, size_t length) {
    if (!hooks || !hooks->compare) {
        fail(error, length, "aggregate sorter requires an ordering");
        return NULL;
    }
    YDSpillSorter *s = calloc(1, sizeof(*s));
    if (!s) {
        fail(error, length, "aggregation allocation failed");
        return NULL;
    }
    s->spill = spill;
    s->hooks = *hooks;
    s->flush_bytes = flush_bytes ? flush_bytes : SIZE_MAX;
    return s;
}

static bool append_run(YDSpillSorter *s, Run run, char *error, size_t length) {
    if (s->run_count == s->run_capacity) {
        size_t capacity = s->run_capacity ? s->run_capacity * 2 : 16;
        Run *runs = realloc(s->runs, capacity * sizeof(*runs));
        if (!runs)
            return fail(error, length, "aggregation allocation failed");
        s->runs = runs;
        s->run_capacity = capacity;
    }
    s->runs[s->run_count++] = run;
    return true;
}

bool yd_spill_sorter_flush(YDSpillSorter *s, size_t min_bytes, char *error, size_t length) {
    if (!s || s->finished)
        return fail(error, length, "aggregate sorter is closed");
    if (!s->spill || !s->count || s->held < min_bytes)
        return true;
    sort_records(s, s->records, s->count);
    bool ok = check(s, error, length);
    Run run;
    writer_begin(s->spill, &run);
    for (size_t i = 0; i < s->count; i++) {
        ok = ok && put_record(s->spill, &run, s->records[i], error, length);
        drop(s, yd_memory(s->records[i]));
        yd_free(s->records[i]);
        s->records[i] = NULL;
    }
    s->count = 0;
    s->held = 0;
    ok = ok && writer_end(s->spill, &run, error, length) && append_run(s, run, error, length);
    return ok;
}

bool yd_spill_sorter_add(YDSpillSorter *s, YDValue *record, char *error, size_t length) {
    if (!s || s->finished || !record) {
        yd_free(record);
        return fail(error, length, "aggregate sorter is closed");
    }
    if (s->count == s->capacity) {
        size_t capacity = s->capacity ? s->capacity * 2 : 64;
        size_t grow = (capacity - s->capacity) * sizeof(*s->records);
        if (capacity > SIZE_MAX / sizeof(*s->records) || !hold(s, grow, error, length)) {
            yd_free(record);
            return false;
        }
        YDValue **records = realloc(s->records, capacity * sizeof(*records));
        if (!records) {
            drop(s, grow);
            yd_free(record);
            return fail(error, length, "aggregation allocation failed");
        }
        s->records = records;
        s->capacity = capacity;
    }
    size_t charge = yd_memory(record);
    if (!hold(s, charge, error, length)) {
        /* Under a hard budget a spilling sorter first writes what it holds. */
        if (!s->spill || !s->count || !yd_spill_sorter_flush(s, 0, error, length) ||
            !hold(s, charge, error, length)) {
            yd_free(record);
            return false;
        }
    }
    s->records[s->count++] = record;
    s->held += charge;
    if (s->spill && (s->held >= s->flush_bytes ||
                     (s->held >= PRESSURE_RUN && s->hooks.pressure &&
                      s->hooks.pressure(s->hooks.memory_context))))
        return yd_spill_sorter_flush(s, 0, error, length);
    return true;
}

static void cursor_release(YDSpillSorter *s, Cursor *c) {
    yd_free(c->head);
    c->head = NULL;
    drop(s, c->head_charge);
    c->head_charge = 0;
    if (c->raw)
        OPENSSL_cleanse(c->raw, c->raw_size);
    free(c->raw);
    c->raw = NULL;
    c->raw_size = 0;
    drop(s, c->raw_charge);
    c->raw_charge = 0;
}

static void cursor_close(YDSpillSorter *s, Cursor *c) {
    cursor_release(s, c);
    if (c->buffer)
        OPENSSL_cleanse(c->buffer, BLOCK);
    free(c->buffer);
    c->buffer = NULL;
    if (c->buffer_charged)
        drop(s, BLOCK);
    c->buffer_charged = false;
}

static bool cursor_bytes(YDSpill *spill, Cursor *c, unsigned char *out, size_t size, char *error,
                         size_t length) {
    while (size) {
        if (c->at == c->size) {
            uint64_t start = c->block * (uint64_t)BLOCK;
            if (start >= c->run.plain)
                return fail(error, length, "aggregate spill run is truncated");
            uint64_t left = c->run.plain - start;
            size_t block = left < BLOCK ? (size_t)left : BLOCK;
            if (!unseal_block(spill, c->run.offset + c->block * (uint64_t)SEALED,
                              c->run.nonce + c->block, block, c->buffer, error, length))
                return false;
            c->size = block;
            c->at = 0;
            c->block++;
        }
        size_t take = c->size - c->at;
        if (take > size)
            take = size;
        memcpy(out, c->buffer + c->at, take);
        c->at += take;
        c->consumed += take;
        out += take;
        size -= take;
    }
    return true;
}

/* Replace the head with the run's next record, or leave it NULL at the end. */
static bool cursor_advance(YDSpillSorter *s, Cursor *c, bool keep_raw, char *error, size_t length) {
    cursor_release(s, c);
    if (c->consumed == c->run.plain)
        return true;
    uint64_t size = 0;
    for (unsigned shift = 0;; shift += 7) {
        unsigned char byte = 0;
        if (shift > 63 || !cursor_bytes(s->spill, c, &byte, 1, error, length))
            return shift > 63 ? fail(error, length, "aggregate spill record is malformed") : false;
        size |= (uint64_t)(byte & 127U) << shift;
        if (!(byte & 128U))
            break;
    }
    if (!size || size > RECORD_LIMIT || size > c->run.plain - c->consumed)
        return fail(error, length, "aggregate spill record is malformed");
    if (!hold(s, (size_t)size, error, length))
        return false;
    c->raw_charge = (size_t)size;
    c->raw = malloc((size_t)size);
    if (!c->raw)
        return fail(error, length, "aggregation allocation failed");
    c->raw_size = (size_t)size;
    if (!cursor_bytes(s->spill, c, c->raw, (size_t)size, error, length))
        return false;
    Reader r = {.data = c->raw, .size = (size_t)size};
    YDValue *v = NULL;
    if (!decode(&r, 0, &v) || !v || r.at != r.size || v->type != YD_ARRAY) {
        yd_free(v);
        return fail(error, length, "aggregate spill record is malformed");
    }
    size_t charge = yd_memory(v);
    if (!hold(s, charge, error, length)) {
        yd_free(v);
        return false;
    }
    c->head = v;
    c->head_charge = charge;
    if (!keep_raw) {
        OPENSSL_cleanse(c->raw, c->raw_size);
        free(c->raw);
        c->raw = NULL;
        c->raw_size = 0;
        drop(s, c->raw_charge);
        c->raw_charge = 0;
    }
    return true;
}

static bool cursor_open(YDSpillSorter *s, Cursor *c, const Run *run, bool keep_raw, char *error,
                        size_t length) {
    memset(c, 0, sizeof(*c));
    c->run = *run;
    if (!hold(s, BLOCK, error, length))
        return false;
    c->buffer_charged = true;
    c->buffer = malloc(BLOCK);
    if (!c->buffer)
        return fail(error, length, "aggregation allocation failed");
    return cursor_advance(s, c, keep_raw, error, length);
}

static Cursor *smallest(YDSpillSorter *s, Cursor *cursors, size_t n) {
    Cursor *best = NULL;
    for (size_t i = 0; i < n; i++)
        if (cursors[i].head && (!best || compare(s, cursors[i].head, best->head) < 0))
            best = &cursors[i];
    return best;
}

/* Merge runs[at, at + n) into one run; ties keep the earlier run first. */
static bool merge_runs(YDSpillSorter *s, size_t at, size_t n, Run *out, char *error, size_t length) {
    if (n == 1) {
        *out = s->runs[at];
        return true;
    }
    Cursor cursors[FAN_IN];
    memset(cursors, 0, sizeof(cursors));
    size_t opened = 0;
    bool ok = true;
    while (ok && opened < n) {
        ok = cursor_open(s, &cursors[opened], &s->runs[at + opened], true, error, length);
        opened++;
    }
    if (ok)
        writer_begin(s->spill, out);
    while (ok) {
        Cursor *c = smallest(s, cursors, opened);
        if (!c)
            break;
        ok = check(s, error, length) && put_raw(s->spill, out, c->raw, c->raw_size, error, length) &&
             cursor_advance(s, c, true, error, length);
    }
    if (ok)
        ok = writer_end(s->spill, out, error, length);
    for (size_t i = 0; i < opened; i++)
        cursor_close(s, &cursors[i]);
    return ok;
}

bool yd_spill_sorter_finish(YDSpillSorter *s, char *error, size_t length) {
    if (!s || s->finished)
        return fail(error, length, "aggregate sorter is closed");
    if (!s->run_count) {
        sort_records(s, s->records, s->count);
        s->at = 0;
        s->finished = true;
        return check(s, error, length);
    }
    if (!yd_spill_sorter_flush(s, 0, error, length))
        return false;
    drop(s, s->capacity * sizeof(*s->records));
    free(s->records);
    s->records = NULL;
    s->capacity = 0;
    while (s->run_count > FAN_IN) {
        size_t produced = 0;
        for (size_t at = 0; at < s->run_count; at += FAN_IN) {
            size_t n = s->run_count - at < FAN_IN ? s->run_count - at : FAN_IN;
            Run merged;
            if (!merge_runs(s, at, n, &merged, error, length))
                return false;
            s->runs[produced++] = merged;
        }
        s->run_count = produced;
    }
    s->cursors = calloc(s->run_count, sizeof(*s->cursors));
    if (!s->cursors)
        return fail(error, length, "aggregation allocation failed");
    s->finished = true;
    for (size_t i = 0; i < s->run_count; i++) {
        s->cursor_count = i + 1;
        if (!cursor_open(s, &s->cursors[i], &s->runs[i], false, error, length))
            return false;
    }
    return true;
}

int yd_spill_sorter_next(YDSpillSorter *s, YDValue **record, char *error, size_t length) {
    *record = NULL;
    if (!s || !s->finished) {
        fail(error, length, "aggregate sorter is not finished");
        return -1;
    }
    if (!s->run_count) {
        if (s->at == s->count)
            return 0;
        YDValue *v = s->records[s->at];
        s->records[s->at++] = NULL;
        size_t charge = yd_memory(v);
        s->held -= charge;
        drop(s, charge);
        *record = v;
        return 1;
    }
    Cursor *c = smallest(s, s->cursors, s->cursor_count);
    if (!c)
        return 0;
    if (!check(s, error, length))
        return -1;
    YDValue *v = c->head;
    c->head = NULL;
    drop(s, c->head_charge);
    c->head_charge = 0;
    if (!cursor_advance(s, c, false, error, length)) {
        yd_free(v);
        return -1;
    }
    *record = v;
    return 1;
}

bool yd_spill_sorter_spilled(const YDSpillSorter *s) { return s && s->run_count; }

void yd_spill_sorter_free(YDSpillSorter *s) {
    if (!s)
        return;
    for (size_t i = 0; i < s->count; i++)
        if (s->records[i]) {
            drop(s, yd_memory(s->records[i]));
            yd_free(s->records[i]);
        }
    drop(s, s->capacity * sizeof(*s->records));
    free(s->records);
    for (size_t i = 0; i < s->cursor_count; i++)
        cursor_close(s, &s->cursors[i]);
    free(s->cursors);
    free(s->runs);
    free(s);
}
