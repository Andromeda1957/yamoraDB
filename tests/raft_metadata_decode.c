#include "../src/consensus/raft_internal.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define REQUIRE(x) do { if (!(x)) { \
    fprintf(stderr, "line %u: %s\n", __LINE__, #x); return 1; \
} } while (0)

/* Construct wire bytes independently of the production encoder. */
static void put64(unsigned char *p, uint64_t value) {
    for (unsigned i = 0; i < 8; i++)
        p[i] = (unsigned char)(value >> (8 * i));
}
static size_t fixture(unsigned version, unsigned char bytes[145], YDRaftMeta *want) {
    *want = (YDRaftMeta){.cluster = {1, 2, 3, 4}, .node = 2, .voters = 3,
                        .term = 7, .vote = 3, .last = 9, .committed = 8};
    memset(bytes, 0, 145);
    memcpy(bytes, "YDRMETA1", 8);
    bytes[7] = (unsigned char)('0' + version);
    memcpy(bytes + 8, want->cluster, 16);
    bytes[24] = (unsigned char)want->node;
    bytes[25] = (unsigned char)want->voters;
    put64(bytes + 32, want->term);
    put64(bytes + 40, want->vote);
    put64(bytes + 48, want->last);
    put64(bytes + 56, want->committed);
    if (version >= 2) {
        want->snapshot = (YDRaftSnapshotBase){.index = 5, .term = 4};
        for (unsigned i = 0; i < 32; i++)
            want->snapshot.archive[i] = (unsigned char)(i + 1);
        put64(bytes + 64, want->snapshot.index);
        put64(bytes + 72, want->snapshot.term);
        memcpy(bytes + 80, want->snapshot.archive, 32);
    }
    if (version == 3) {
        for (unsigned i = 0; i < 32; i++)
            want->application[i] = (unsigned char)(255 - i);
        memcpy(bytes + 112, want->application, 32);
    }
    return version == 1 ? 64 : version == 2 ? 112 : 144;
}
static bool same(const YDRaftMeta *a, const YDRaftMeta *b) {
    return !memcmp(a->cluster, b->cluster, 16) && a->node == b->node && a->voters == b->voters &&
           a->term == b->term && a->vote == b->vote && a->last == b->last &&
           a->committed == b->committed && a->snapshot.index == b->snapshot.index &&
           a->snapshot.term == b->snapshot.term &&
           !memcmp(a->snapshot.archive, b->snapshot.archive, 32) &&
           !memcmp(a->application, b->application, 32);
}
static bool cleared(const YDRaftMeta *out) {
    const unsigned char *p = (const unsigned char *)out;
    for (size_t i = 0; i < sizeof(*out); i++)
        if (p[i]) return false;
    return true;
}
static YDRaftMeta stale_identity(const YDRaftMeta *want) {
    YDRaftMeta expected;
    memset(&expected, 0xa5, sizeof(expected));
    memcpy(expected.cluster, want->cluster, 16);
    expected.node = want->node;
    expected.voters = want->voters;
    return expected;
}
static int accepts(const unsigned char *bytes, size_t size, const YDRaftMeta *want) {
    YDRaftMeta expected = stale_identity(want), saved = expected, out;
    memset(&out, 0xcc, sizeof(out));
    REQUIRE(yd_raft_decode_meta(bytes, size, &expected, &out));
    REQUIRE(same(&out, want) && same(&expected, &saved));
    REQUIRE(yd_raft_decode_meta(bytes, size, &expected, &expected));
    REQUIRE(same(&expected, want));
    unsigned char encoded[144];
    REQUIRE(yd_raft_encode_meta(&out, encoded) == size && !memcmp(encoded, bytes, size));
    return 0;
}
static int rejects(const unsigned char *bytes, size_t size, const YDRaftMeta *expected) {
    YDRaftMeta saved = *expected, out;
    memset(&out, 0xcc, sizeof(out));
    REQUIRE(!yd_raft_decode_meta(bytes, size, expected, &out) && cleared(&out));
    REQUIRE(same(expected, &saved));
    out = *expected;
    REQUIRE(!yd_raft_decode_meta(bytes, size, &out, &out) && cleared(&out));
    return 0;
}
static int valid(void) {
    for (unsigned version = 1; version <= 3; version++) {
        unsigned char bytes[145], original[145];
        YDRaftMeta want;
        size_t size = fixture(version, bytes, &want);
        memcpy(original, bytes, sizeof(bytes));
        REQUIRE(!accepts(bytes, size, &want));
        REQUIRE(!memcmp(bytes, original, sizeof(bytes)));
        /* Decode works from an unaligned source too. */
        unsigned char unaligned[146];
        memcpy(unaligned + 1, bytes, size);
        REQUIRE(!accepts(unaligned + 1, size, &want));
        want.term = UINT64_MAX;
        want.last = UINT64_MAX - 1;
        want.committed = want.last;
        put64(bytes + 32, want.term);
        put64(bytes + 48, want.last);
        put64(bytes + 56, want.committed);
        if (version >= 2) {
            want.snapshot.index = UINT64_MAX - 2;
            want.snapshot.term = want.term;
            put64(bytes + 64, want.snapshot.index);
            put64(bytes + 72, want.snapshot.term);
        }
        REQUIRE(!accepts(bytes, size, &want));
    }
    unsigned char bytes[145];
    YDRaftMeta want;
    size_t size = fixture(1, bytes, &want);
    want.term = want.vote = want.last = want.committed = 0;
    memset(bytes + 32, 0, 32);
    REQUIRE(!accepts(bytes, size, &want));
    want.term = 1;
    want.vote = 3; /* A vote with no log entries is accepted. */
    put64(bytes + 32, want.term);
    put64(bytes + 40, want.vote);
    REQUIRE(!accepts(bytes, size, &want));
    size = fixture(3, bytes, &want);
    want.snapshot.index = want.committed = want.last;
    want.snapshot.term = want.term;
    put64(bytes + 56, want.committed);
    put64(bytes + 64, want.snapshot.index);
    put64(bytes + 72, want.snapshot.term);
    REQUIRE(!accepts(bytes, size, &want));
    /* META3 distinguishes archive from selected application, but permits equality. */
    memcpy(want.application, want.snapshot.archive, 32);
    memcpy(bytes + 112, want.application, 32);
    REQUIRE(!accepts(bytes, size, &want));
    return 0;
}
static int framing(void) {
    for (unsigned version = 1; version <= 3; version++) {
        unsigned char bytes[145];
        YDRaftMeta want;
        size_t size = fixture(version, bytes, &want);
        for (size_t i = 0; i < 8; i++) {
            bytes[i] ^= 0x40;
            REQUIRE(!rejects(bytes, size, &want));
            bytes[i] ^= 0x40;
        }
        for (size_t i = 26; i < 32; i++) {
            bytes[i] = 1;
            REQUIRE(!rejects(bytes, size, &want));
            bytes[i] = 0;
        }
        for (size_t length = 0; length < size; length++) {
            /* Exact allocations make premature header/body reads ASan-visible. */
            unsigned char *shortened = malloc(length ? length : 1);
            REQUIRE(shortened);
            memcpy(shortened, bytes, length);
            int result = rejects(shortened, length, &want);
            free(shortened);
            REQUIRE(!result);
        }
        REQUIRE(!rejects(bytes, size + 1, &want));
        REQUIRE(!rejects(bytes, SIZE_MAX, &want));
        for (unsigned other = 1; other <= 3; other++) {
            if (other == version) continue;
            bytes[7] = (unsigned char)('0' + other);
            REQUIRE(!rejects(bytes, size, &want));
        }
    }
    return 0;
}
static int identity(void) {
    for (unsigned version = 1; version <= 3; version++) {
        unsigned char bytes[145];
        YDRaftMeta want;
        size_t size = fixture(version, bytes, &want);
        for (size_t i = 8; i < 26; i++) {
            bytes[i] ^= 1;
            REQUIRE(!rejects(bytes, size, &want));
            bytes[i] ^= 1;
        }
        YDRaftMeta expected = want;
        memset(expected.cluster, 0, 16);
        REQUIRE(!rejects(bytes, size, &expected));
        expected = want;
        expected.node = 0;
        REQUIRE(!rejects(bytes, size, &expected));
        expected.node = 256 + want.node; /* Do not narrow expected unsigned identity. */
        REQUIRE(!rejects(bytes, size, &expected));
        expected = want;
        expected.voters = UINT32_MAX;
        REQUIRE(!rejects(bytes, size, &expected));
    }
    return 0;
}
static int bounds(void) {
    const struct { size_t offset; uint64_t value; } bad[] = {
        {32, 0}, {40, 4}, {40, UINT64_MAX}, {48, UINT64_MAX},
        {48, 7}, {56, 10}, {56, UINT64_MAX},
        {64, 0}, {64, 9}, {64, UINT64_MAX - 1}, {64, UINT64_MAX},
        {72, 0}, {72, 8}, {72, UINT64_MAX}
    };
    for (unsigned version = 1; version <= 3; version++) {
        for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
            if (version == 1 && bad[i].offset >= 64) continue;
            unsigned char bytes[145];
            YDRaftMeta want;
            size_t size = fixture(version, bytes, &want);
            put64(bytes + bad[i].offset, bad[i].value);
            REQUIRE(!rejects(bytes, size, &want));
        }
    }
    unsigned char bytes[145];
    YDRaftMeta want;
    size_t size = fixture(1, bytes, &want);
    memset(bytes + 32, 0, 16); /* Zero term, zero vote, nonzero last still rejects. */
    REQUIRE(!rejects(bytes, size, &want));
    size = fixture(2, bytes, &want);
    put64(bytes + 48, UINT64_MAX - 1);
    put64(bytes + 56, UINT64_MAX - 1);
    put64(bytes + 64, UINT64_MAX - 1); /* Isolate snapshot overflow guard. */
    REQUIRE(!rejects(bytes, size, &want));
    return 0;
}
static int hashes(void) {
    for (unsigned version = 2; version <= 3; version++) {
        for (size_t field = 80; field < (version == 3 ? 144U : 112U); field += 32) {
            unsigned char bytes[145];
            YDRaftMeta want;
            size_t size = fixture(version, bytes, &want);
            memset(bytes + field, 0, 32);
            REQUIRE(!rejects(bytes, size, &want));
            unsigned char *hash = field == 80 ? want.snapshot.archive : want.application;
            memset(hash, 0, 32);
            /* Any one nonzero byte is valid metadata, even an unknown/wrong digest.
             * Authenticating archive/application content belongs to recovery. */
            for (size_t i = 0; i < 32; i++) {
                bytes[field + i] = hash[i] = 1;
                REQUIRE(!accepts(bytes, size, &want));
                bytes[field + i] = hash[i] = 0;
            }
        }
    }
    return 0;
}
static int outputs(void) {
    unsigned char bytes[145];
    YDRaftMeta want, out;
    size_t size = fixture(3, bytes, &want);
    REQUIRE(!rejects(NULL, size, &want));
    REQUIRE(!rejects(NULL, 0, &want));
    REQUIRE(!rejects(NULL, SIZE_MAX, &want));
    memset(&out, 0xa5, sizeof(out));
    REQUIRE(!yd_raft_decode_meta(bytes, size, NULL, &out) && cleared(&out));
    memset(&out, 0xa5, sizeof(out));
    REQUIRE(!yd_raft_decode_meta(NULL, 0, NULL, &out) && cleared(&out));
    YDRaftMeta before = want;
    REQUIRE(!yd_raft_decode_meta(bytes, size, &want, NULL) && same(&want, &before));
    REQUIRE(!yd_raft_decode_meta(NULL, SIZE_MAX, NULL, NULL));
    YDRaftMeta expected = stale_identity(&want);
    /* Reuse a selected output for older records: omitted fields become zero. */
    for (unsigned version = 3; version; version--) {
        size = fixture(version, bytes, &want);
        REQUIRE(yd_raft_decode_meta(bytes, size, &expected, &out) && same(&out, &want));
        expected = stale_identity(&want);
        REQUIRE(yd_raft_decode_meta(bytes, size, &expected, &expected) && same(&expected, &want));
    }
    return 0;
}

typedef struct {
    unsigned char bytes[145];
    size_t size;
    YDRaftMeta want;
    atomic_uint *started;
    unsigned workers;
    int result;
} Worker;
static void *decode_worker(void *context) {
    Worker *w = context;
    atomic_fetch_add(w->started, 1);
    while (atomic_load(w->started) != w->workers) { }
    for (unsigned i = 0; i < 2000; i++) {
        if (accepts(w->bytes, w->size, &w->want) || rejects(NULL, w->size, &w->want)) {
            w->result = 1;
            break;
        }
    }
    return NULL;
}
static int parallel(void) {
    enum { WORKERS = 8 };
    Worker workers[WORKERS] = {0};
    pthread_t threads[WORKERS];
    atomic_uint started = 0;
    for (unsigned i = 0; i < WORKERS; i++) {
        Worker *w = &workers[i];
        w->size = fixture(1 + i % 3, w->bytes, &w->want);
        w->want.cluster[0] = w->bytes[8] = (unsigned char)(i + 1);
        w->want.term += i;
        put64(w->bytes + 32, w->want.term);
        w->started = &started;
        w->workers = WORKERS;
        REQUIRE(!pthread_create(&threads[i], NULL, decode_worker, w));
    }
    for (unsigned i = 0; i < WORKERS; i++) {
        REQUIRE(!pthread_join(threads[i], NULL));
        REQUIRE(!workers[i].result);
    }
    return 0;
}
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    if (!strcmp(argv[1], "valid")) return valid();
    if (!strcmp(argv[1], "framing")) return framing();
    if (!strcmp(argv[1], "identity")) return identity();
    if (!strcmp(argv[1], "bounds")) return bounds();
    if (!strcmp(argv[1], "hashes")) return hashes();
    if (!strcmp(argv[1], "outputs")) return outputs();
    if (!strcmp(argv[1], "parallel")) return parallel();
    return 2;
}
