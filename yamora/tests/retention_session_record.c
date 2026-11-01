#define _GNU_SOURCE
#define OPENSSL_API_COMPAT 0x10100000L
#include "consensus/retention_session_record.h"
#include <openssl/sha.h>
#include <stddef.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

typedef YDRaftRetentionSessionRecord Record;
#define REQUIRE(name, condition) do { if (!(condition)) { \
    fprintf(stderr, "ASSERT %s\n", name); exit(2); } } while (0)

/* Independent Python hashlib/struct vectors, not output from this codec. */
static const char *const vectors[] = {
    "5944525345535331000000010000010000000001000000010102030405060708"
    "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
    "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
    "0000000000000000102030405060708000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "38da789b28c1ba967f1749d934195277904b0c626537406e280ae1bd3c0174a1",
    "5944525345535331000000010000010000000001000000020102030405060708"
    "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
    "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
    "00000000000000001020304050607080c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
    "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf00000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "5dde5be19fab2143293d0d6440499e01b1384b826d00b494fb81cc8f87aa9e50",
    "5944525345535331000000010000010000000001000000030102030405060708"
    "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
    "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
    "0000000000000000102030405060708000000000000000000000000000000000"
    "0000000000000000000000000000000080000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "cecd5739b9b084eb7146a3f596fba65f64b5fd0defe97563aa867074e147483c"
};
static _Thread_local unsigned hash_failure, measured_allocations;
static _Thread_local bool measure_allocations;
void *__real_malloc(size_t);
void *__real_calloc(size_t, size_t);
void *__real_realloc(void *, size_t);
void *__wrap_malloc(size_t n) {
    if (measure_allocations) measured_allocations++;
    return __real_malloc(n);
}
void *__wrap_calloc(size_t n, size_t s) {
    if (measure_allocations) measured_allocations++;
    return __real_calloc(n, s);
}
void *__wrap_realloc(void *p, size_t n) {
    if (measure_allocations) measured_allocations++;
    return __real_realloc(p, n);
}
int __real_SHA256_Init(SHA256_CTX *);
int __real_SHA256_Update(SHA256_CTX *, const void *, size_t);
int __real_SHA256_Final(unsigned char *, SHA256_CTX *);
int __wrap_SHA256_Init(SHA256_CTX *c) {
    return hash_failure == 1 ? 0 : __real_SHA256_Init(c);
}
int __wrap_SHA256_Update(SHA256_CTX *c, const void *p, size_t n) {
    return hash_failure == 2 ? 0 : __real_SHA256_Update(c, p, n);
}
int __wrap_SHA256_Final(unsigned char *p, SHA256_CTX *c) {
    /* A failed primitive may still leave complete bytes. Return status must
     * reject even when the produced digest happens to match. */
    if (hash_failure == 3) { (void)__real_SHA256_Final(p, c); return 0; }
    return __real_SHA256_Final(p, c);
}
static bool zero(const void *p, size_t n) {
    const unsigned char *b = p;
    for (size_t i = 0; i < n; i++) if (b[i]) return false;
    return true;
}
static Record fixture(unsigned state) {
    Record r;
    memset(&r, 0, sizeof(r));
    r.state = state;
    r.epoch = UINT64_C(0x0102030405060708);
    r.journal_inode = UINT64_C(0x1020304050607080);
    for (unsigned i = 0; i < 32; i++) {
        r.birth_hash[i] = (unsigned char)(i + 1);
        r.nonce[i] = (unsigned char)(0xa0 + i);
        if (state == 2) r.terminal_root[i] = (unsigned char)(0xc0 + i);
    }
    if (state == 3) r.reason_bits = UINT64_C(1) << 63;
    return r;
}
static void literal(unsigned state, unsigned char bytes[256]) {
    const char *s = vectors[state - 1];
    REQUIRE("literal-length", strlen(s) == 512);
    for (unsigned i = 0; i < 256; i++) {
        unsigned value;
        REQUIRE("literal-hex", sscanf(s + 2*i, "%2x", &value) == 1);
        bytes[i] = (unsigned char)value;
    }
}
static bool same(const Record *a, const Record *b) {
    return a->state == b->state && a->epoch == b->epoch &&
        a->journal_device == b->journal_device && a->journal_inode == b->journal_inode &&
        a->reason_bits == b->reason_bits && !memcmp(a->birth_hash, b->birth_hash, 32) &&
        !memcmp(a->nonce, b->nonce, 32) && !memcmp(a->terminal_root, b->terminal_root, 32);
}
static void rehash(unsigned char bytes[256]) {
    REQUIRE("independent-hash", SHA256(bytes, 224, bytes + 224) != NULL);
}
static void reject_wire(const char *name, const unsigned char *bytes, size_t length) {
    Record out;
    memset(&out, 0x5a, sizeof(out));
    REQUIRE(name, !yd_raft_retention_session_record_decode(bytes, length, &out));
    REQUIRE("decode-failure-clears", zero(&out, sizeof(out)));
}
static void reject_record(const char *name, const Record *r) {
    unsigned char out[257];
    memset(out, 0x5a, sizeof(out));
    REQUIRE(name, !yd_raft_retention_session_record_encode(out, sizeof(out), r));
    REQUIRE("encode-failure-clears", zero(out, 256));
    REQUIRE("encode-tail-untouched", out[256] == 0x5a);
}
static void vector_test(void) {
    for (unsigned state = 1; state <= 3; state++) {
        unsigned char expected[256], bytes[257], hash[32];
        literal(state, expected);
        REQUIRE("literal-digest", SHA256(expected, 224, hash) && !memcmp(hash, expected + 224, 32));
        Record r = fixture(state), out;
        memset(bytes, 0x5a, sizeof(bytes));
        REQUIRE("vector-encode", yd_raft_retention_session_record_encode(bytes, sizeof(bytes), &r));
        REQUIRE("literal-wire", !memcmp(bytes, expected, 256));
        REQUIRE("encode-tail-untouched", bytes[256] == 0x5a);
        REQUIRE("vector-decode", yd_raft_retention_session_record_decode(expected, 256, &out));
        REQUIRE("literal-fields", same(&r, &out));
    }
}
/* Rehash every semantic mutation so integrity cannot hide a missing guard. */
static void semantic(const char *name) {
    unsigned char bytes[256]; literal(1, bytes);
    Record r = fixture(1);
    bool host = true;
    if (!strcmp(name, "magic")) { bytes[0] ^= 1; host = false; }
    else if (!strcmp(name, "version")) { bytes[11] = 2; host = false; }
    else if (!strcmp(name, "wire-length")) { bytes[15] = 1; host = false; }
    else if (!strcmp(name, "protocol")) { bytes[19] = 2; host = false; }
    else if (!strcmp(name, "state")) { bytes[23] = 4; r.state = 4; }
    else if (!strcmp(name, "epoch")) { memset(bytes + 24, 0, 8); r.epoch = 0; }
    else if (!strcmp(name, "birth")) { memset(bytes + 32, 0, 32); memset(r.birth_hash, 0, 32); }
    else if (!strcmp(name, "nonce")) { memset(bytes + 64, 0, 32); memset(r.nonce, 0, 32); }
    else if (!strcmp(name, "inode")) { memset(bytes + 104, 0, 8); r.journal_inode = 0; }
    else if (!strcmp(name, "active-root")) { bytes[112] = 1; r.terminal_root[0] = 1; }
    else if (!strcmp(name, "active-reason")) { bytes[151] = 1; r.reason_bits = 1; }
    else if (!strcmp(name, "clean-root")) {
        literal(2, bytes); memset(bytes + 112, 0, 32); r = fixture(2); memset(r.terminal_root, 0, 32);
    } else if (!strcmp(name, "clean-reason")) {
        literal(2, bytes); bytes[151] = 1; r = fixture(2); r.reason_bits = 1;
    } else if (!strcmp(name, "poison-reason")) {
        literal(3, bytes); memset(bytes + 144, 0, 8); r = fixture(3); r.reason_bits = 0;
    } else if (!strcmp(name, "reserved")) {
        for (unsigned offset = 152; offset < 224; offset++) {
            literal(1, bytes); bytes[offset] = 1; rehash(bytes); reject_wire(name, bytes, 256);
        }
        return;
    } else { REQUIRE("known-semantic-case", false); }
    rehash(bytes);
    reject_wire(name, bytes, 256);
    if (host) reject_record(name, &r);
}
static void corruption(void) {
    unsigned char bytes[256];
    for (unsigned i = 0; i < 256; i++) for (unsigned bit = 0; bit < 8; bit++) {
        literal(1, bytes); bytes[i] ^= (unsigned char)(1U << bit);
        reject_wire("corruption", bytes, sizeof(bytes));
    }
    /* These remain semantically valid; only checksum rejection catches them. */
    literal(1, bytes); bytes[32] ^= 1; reject_wire("checksum", bytes, sizeof(bytes));
}
static void bounds(void) {
    long page_size = sysconf(_SC_PAGESIZE);
    REQUIRE("page-size", page_size >= 256);
    size_t page = (size_t)page_size;
    unsigned char *memory = mmap(NULL, 3*page, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE("guard-allocation", memory != MAP_FAILED);
    REQUIRE("guard-protection", !mprotect(memory + page, page, PROT_READ | PROT_WRITE));
    const unsigned char *unreadable = memory;
    Record r = fixture(1), out;
    for (size_t n = 0; n < 256; n++) {
        reject_wire("exact-length", unreadable, n);
        unsigned char bytes[258]; memset(bytes, 0x5a, sizeof(bytes));
        REQUIRE("encode-capacity", !yd_raft_retention_session_record_encode(bytes + 1, n, (const Record *)unreadable));
        REQUIRE("capacity-clears", zero(bytes + 1, n));
        REQUIRE("capacity-canary", bytes[0] == 0x5a);
        for (size_t i = n + 1; i < sizeof(bytes); i++) REQUIRE("capacity-tail", bytes[i] == 0x5a);
    }
    reject_wire("exact-length", unreadable, 257);
    reject_wire("exact-length", unreadable, SIZE_MAX);
    reject_wire("null-wire", NULL, 256);
    reject_record("null-record", NULL);
    REQUIRE("null-encode-out", !yd_raft_retention_session_record_encode(NULL, SIZE_MAX, (const Record *)unreadable));
    REQUIRE("null-decode-out", !yd_raft_retention_session_record_decode(unreadable, 256, NULL));
    unsigned char *edge = memory + 2*page - 256;
    REQUIRE("fixed-encode-bound", yd_raft_retention_session_record_encode(edge, SIZE_MAX, &r));
    REQUIRE("fixed-decode-bound", yd_raft_retention_session_record_decode(edge, 256, &out) && same(&r, &out));
    r.epoch = 0;
    REQUIRE("fixed-clear-bound", !yd_raft_retention_session_record_encode(edge, SIZE_MAX, &r) && zero(edge, 256));
    REQUIRE("guard-release", !munmap(memory, 3*page));
}
static void aliases(void) {
    /* A declared Record supplies correct alignment/effective type; char wire
     * access to its representation is legal, including while it overlaps. */
    struct Storage { unsigned char before[256]; Record r; unsigned char after[256]; } storage;
    const int shifts[] = {-128, -1, 0, 1, 32, 128};
    for (unsigned i = 0; i < sizeof(shifts)/sizeof(shifts[0]); i++) {
        unsigned char expected[256]; literal(2, expected);
        memset(&storage, 0x5a, sizeof(storage)); storage.r = fixture(2);
        unsigned char *wire = (unsigned char *)&storage + offsetof(struct Storage, r) + shifts[i];
        REQUIRE("alias-encode", yd_raft_retention_session_record_encode(wire, 256, &storage.r));
        REQUIRE("alias-encode-wire", !memcmp(wire, expected, 256));
        memcpy(wire, expected, 256);
        REQUIRE("alias-decode", yd_raft_retention_session_record_decode(wire, 256, &storage.r));
        Record r = fixture(2); REQUIRE("alias-decode-fields", same(&storage.r, &r));
        memcpy(wire, expected, 256); wire[255] ^= 1;
        REQUIRE("alias-decode-failure", !yd_raft_retention_session_record_decode(wire, 256, &storage.r));
        REQUIRE("alias-decode-clears", zero(&storage.r, sizeof(storage.r)));
        storage.r = fixture(1); storage.r.epoch = 0;
        REQUIRE("alias-encode-failure", !yd_raft_retention_session_record_encode(wire, 256, &storage.r));
        REQUIRE("alias-encode-clears", zero(wire, 256));
    }
}
static void upper_bounds(void) {
    Record r = fixture(3), out;
    unsigned char bytes[256];
    r.epoch = r.journal_device = r.journal_inode = r.reason_bits = UINT64_MAX;
    memset(r.terminal_root, 0xff, 32);
    REQUIRE("upper-encode", yd_raft_retention_session_record_encode(bytes, 256, &r));
    REQUIRE("upper-wire", bytes[24] == 255 && bytes[31] == 255 && bytes[96] == 255 &&
        bytes[103] == 255 && bytes[104] == 255 && bytes[111] == 255 && bytes[144] == 255 && bytes[151] == 255);
    REQUIRE("upper-decode", yd_raft_retention_session_record_decode(bytes, 256, &out) && same(&r, &out));
    r.epoch = r.journal_inode = 1; r.journal_device = 0;
    r.birth_hash[0] = r.nonce[0] = 0;
    for (unsigned i = 0; i < 64; i++) {
        r.reason_bits = UINT64_C(1) << i;
        REQUIRE("unknown-poison-bits", yd_raft_retention_session_record_encode(bytes, 256, &r));
        REQUIRE("unknown-poison-roundtrip", yd_raft_retention_session_record_decode(bytes, 256, &out) && same(&r, &out));
    }
    memset(r.birth_hash, 0, 32); memset(r.nonce, 0, 32);
    r.birth_hash[31] = r.nonce[31] = 1;
    REQUIRE("sparse-nonzero-bindings", yd_raft_retention_session_record_encode(bytes, 256, &r));
    for (unsigned i = 0; i < 32; i++) {
        memset(r.terminal_root, 0, 32); r.terminal_root[i] = 1; r.state = 2; r.reason_bits = 0;
        REQUIRE("sparse-clean-root", yd_raft_retention_session_record_encode(bytes, 256, &r));
        REQUIRE("sparse-clean-roundtrip", yd_raft_retention_session_record_decode(bytes, 256, &out) && same(&r, &out));
    }
    const uint32_t states[] = {0, 4, UINT32_MAX};
    for (unsigned i = 0; i < sizeof(states)/sizeof(states[0]); i++) {
        r.state = states[i]; reject_record("unknown-state", &r);
        literal(1, bytes); memset(bytes + 20, states[i] == UINT32_MAX ? 255 : 0, 4);
        bytes[23] = (unsigned char)states[i]; rehash(bytes); reject_wire("unknown-state", bytes, 256);
    }
    const unsigned offsets[] = {8, 12, 16};
    for (unsigned i = 0; i < 3; i++) for (unsigned fill = 0; fill < 2; fill++) {
        literal(1, bytes); memset(bytes + offsets[i], fill ? 255 : 0, 4); rehash(bytes);
        reject_wire("unknown-header-integer", bytes, 256);
    }
}
static void hash_faults(void) {
    Record r = fixture(1);
    unsigned char bytes[256]; literal(1, bytes);
    for (unsigned i = 1; i <= 3; i++) {
        hash_failure = i;
        reject_record("hash-encode-fails", &r);
        reject_wire("hash-decode-fails", bytes, 256);
    }
    hash_failure = 0;
    unsigned char out[256]; Record decoded;
    measured_allocations = 0; measure_allocations = true;
    bool encoded = yd_raft_retention_session_record_encode(out, 256, &r);
    bool read = yd_raft_retention_session_record_decode(bytes, 256, &decoded);
    measure_allocations = false;
    REQUIRE("no-heap-allocation", encoded && read && measured_allocations == 0);
}
static void length_guard(void) {
    unsigned char bytes[257]; literal(1, bytes); bytes[256] = 0;
    reject_wire("exact-length", bytes, sizeof(bytes));
}
static void hash_decode_final(void) {
    unsigned char bytes[256]; literal(1, bytes);
    hash_failure = 3; reject_wire("hash-decode-fails", bytes, 256); hash_failure = 0;
}
static void capacity_guard(void) {
    Record r = fixture(1);
    unsigned char bytes[256]; memset(bytes, 0x5a, sizeof(bytes));
    REQUIRE("encode-capacity", !yd_raft_retention_session_record_encode(bytes, 255, &r));
    REQUIRE("capacity-clears", zero(bytes, 255) && bytes[255] == 0x5a);
}
typedef struct { const unsigned char *shared; unsigned index; } Thread;
static void *parallel(void *argument) {
    const Thread *t = argument;
    for (unsigned i = 0; i < 1500; i++) {
        Record expected = fixture(1), out;
        unsigned char bytes[256];
        REQUIRE("parallel-shared-input", yd_raft_retention_session_record_decode(t->shared, 256, &out) && same(&expected, &out));
        expected.epoch = ((uint64_t)t->index << 32) + i + 1;
        expected.nonce[0] = (unsigned char)t->index;
        REQUIRE("parallel-encode", yd_raft_retention_session_record_encode(bytes, 256, &expected));
        REQUIRE("parallel-decode", yd_raft_retention_session_record_decode(bytes, 256, &out) && same(&expected, &out));
        bytes[80] ^= 1;
        reject_wire("parallel-corruption", bytes, 256);
    }
    return NULL;
}
static void threads(void) {
    unsigned char shared[256]; literal(1, shared);
    pthread_t workers[8]; Thread args[8];
    for (unsigned i = 0; i < 8; i++) {
        args[i] = (Thread){.shared = shared, .index = i};
        REQUIRE("thread-create", !pthread_create(&workers[i], NULL, parallel, &args[i]));
    }
    for (unsigned i = 0; i < 8; i++) REQUIRE("thread-join", !pthread_join(workers[i], NULL));
}
int main(int argc, char **argv) {
    REQUIRE("scenario-argument", argc == 2);
    const char *name = argv[1];
    if (!strcmp(name, "vectors")) vector_test();
    else if (!strcmp(name, "corruption")) corruption();
    else if (!strcmp(name, "checksum")) {
        unsigned char bytes[256]; literal(1, bytes); bytes[32] ^= 1; reject_wire(name, bytes, 256);
    } else if (!strcmp(name, "bounds")) bounds();
    else if (!strcmp(name, "aliases")) aliases();
    else if (!strcmp(name, "upper")) upper_bounds();
    else if (!strcmp(name, "hash-faults")) hash_faults();
    else if (!strcmp(name, "hash-decode-final")) hash_decode_final();
    else if (!strcmp(name, "length-guard")) length_guard();
    else if (!strcmp(name, "capacity-guard")) capacity_guard();
    else if (!strcmp(name, "threads")) threads();
    else semantic(name);
    puts("SESSION_RECORD_OK");
    return 0;
}
