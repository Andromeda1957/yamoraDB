#include "policy_catalog.h"
#include <openssl/evp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(test, label) do { if (!(test)) { \
    fprintf(stderr, "%s (line %d)\n", label, __LINE__); exit(1); } } while (0)

/* Link wrappers affect codec calls, not OpenSSL's internal allocation. */
static int fail_malloc, fail_digest;
void *__real_malloc(size_t n);
int __real_EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl);
void *__wrap_malloc(size_t n) { return fail_malloc ? NULL : __real_malloc(n); }
int __wrap_EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl) {
    return fail_digest ? 0 : __real_EVP_DigestInit_ex(ctx, type, impl);
}
static YDPCBudget ample(void) { YDPCBudget b = {UINT64_MAX, SIZE_MAX}; return b; }
static YDPCInfo info_of(const YDPolicyCatalog *c) {
    YDPCInfo i; CHECK(yd_policy_catalog_info(c, &i) == YD_PC_OK, "INFO_OK"); return i;
}
static YDPolicyCatalog *empty(void) {
    YDPCBudget b = ample(); YDPolicyCatalog *c = NULL;
    CHECK(yd_policy_catalog_empty(YD_PC_ORDINARY, &b, &c, NULL) == YD_PC_OK, "EMPTY_CATALOG_OK");
    return c;
}
static YDPCChange change_for(const YDPolicyCatalog *c, const char *name) {
    YDPCChange x = {0}; YDPCInfo i = info_of(c); YDPCEntry e;
    x.collection = name; x.collection_length = strlen(name); x.operation = YD_PC_SET;
    x.source = (const unsigned char *)"type: object\r\n"; x.source_length = 14;
    x.expected.generation = i.generation;
    memcpy(x.expected.catalog_sha256, i.catalog_sha256, 32);
    if (yd_policy_catalog_find(c, name, strlen(name), &e) == YD_PC_OK) x.expected.version = e.version;
    return x;
}
static YDPolicyCatalog *changed(const YDPolicyCatalog *c, YDPCChange *x) {
    YDPCBudget b = ample(); YDPolicyCatalog *next = NULL;
    CHECK(yd_policy_catalog_change(c, x, YD_PC_LARGE, &b, &next, NULL) == YD_PC_OK, "CHANGE_OK");
    return next;
}
static void hash_is(const unsigned char hash[32], const char *hex, const char *label) {
    char actual[65];
    for (size_t i = 0; i < 32; ++i) (void)snprintf(actual + 2 * i, 3, "%02x", hash[i]);
    CHECK(!strcmp(actual, hex), label);
}
static void empty_catalog(void) {
    YDPCBudget budget = {UINT64_MAX, SIZE_MAX};
    YDPolicyCatalog *catalog = NULL;
    YDPCError error;
    CHECK(yd_policy_catalog_empty(YD_PC_ORDINARY, &budget, &catalog, &error) == YD_PC_OK,
          "EMPTY_CATALOG_OK");
    YDPCInfo info;
    CHECK(yd_policy_catalog_info(catalog, &info) == YD_PC_OK, "EMPTY_INFO_OK");
    CHECK(info.count == 0 && info.generation == 0, "EMPTY_ZERO_GENERATION");
    hash_is(info.catalog_sha256, "9673bdd85106866bac56becab0d3c2e83c08b602221ee9c87f704c495ef18b80", "EMPTY_HASH");
    CHECK(budget.work_left == UINT64_MAX - 1024, "EMPTY_WORK");
    YDPCEntry e;
    memset(&e, 0xff, sizeof(e));
    CHECK(yd_policy_catalog_at(catalog, 0, &e) == YD_PC_NOT_FOUND && !e.source, "ABSENT_CLEAR");
    yd_policy_catalog_free(catalog);
}

static void changes(void) {
    YDPolicyCatalog *base = empty(); YDPCChange x = change_for(base, "a");
    YDPolicyCatalog *one = changed(base, &x); YDPCInfo i = info_of(one); YDPCEntry e;
    CHECK(i.generation == 1 && i.count == 1 && info_of(base).count == 0, "BASE_IMMUTABLE");
    hash_is(i.catalog_sha256, "8741df15e087e878e4ed1208478c746094754ecec5fdbf5fce4b24956ffa3d6f", "CATALOG_VECTOR");
    CHECK(yd_policy_catalog_at(one, 0, &e) == YD_PC_OK, "ENTRY_OK");
    hash_is(e.source_sha256, "5b526d02514ecdc9f48c4a2ecd40b573ebc34485505c8de7177194ce6d48a311", "SOURCE_VECTOR");
    hash_is(e.policy_sha256, "f0b4bdcc5327e6b63250d6da76308e755e210f03ea99e4f05dbce9caf2095e01", "POLICY_VECTOR");
    for (int guard = 0; guard < 3; ++guard) {
        x = change_for(one, "a");
        if (guard == 0) ++x.expected.generation;
        if (guard == 1) ++x.expected.version;
        if (guard == 2) x.expected.catalog_sha256[31] ^= 1;
        YDPCBudget b = ample(); YDPolicyCatalog *out = base;
        CHECK(yd_policy_catalog_change(one, &x, YD_PC_LARGE, &b, &out, NULL) == YD_PC_CONFLICT && !out,
              guard == 0 ? "CAS_GENERATION" : guard == 1 ? "CAS_VERSION" : "CAS_HASH");
    }
    x = change_for(one, "a"); x.operation = YD_PC_DISABLE; x.source = NULL; x.source_length = 0;
    YDPolicyCatalog *off = changed(one, &x); i = info_of(off);
    hash_is(i.catalog_sha256, "0b946303721acf18e1ef73901be23fa899e15b77c19ecc77140f3e2ddc7349d7", "OFF_CATALOG_VECTOR");
    CHECK(yd_policy_catalog_at(off, 0, &e) == YD_PC_OK && e.mode == YD_PC_OFF && e.version == 2 &&
          e.source_length == 14 && !memcmp(e.source, "type: object\r\n", 14), "TOMBSTONE_PRESERVES_SOURCE");
    hash_is(e.policy_sha256, "6d2183326905d6f5ad6fe585af5a9a9eed625d671a83e0fd926b912e8f68864b", "OFF_POLICY_VECTOR");
    x = change_for(off, "a"); x.operation = YD_PC_DISABLE; x.source = NULL; x.source_length = 0;
    YDPCBudget b = ample(); YDPolicyCatalog *out = base;
    CHECK(yd_policy_catalog_change(off, &x, YD_PC_LARGE, &b, &out, NULL) == YD_PC_CONFLICT && !out, "ALREADY_OFF");
    x = change_for(off, "missing"); x.operation = YD_PC_DISABLE; x.source = NULL; x.source_length = 0;
    CHECK(yd_policy_catalog_change(off, &x, YD_PC_LARGE, &b, &out, NULL) == YD_PC_NOT_FOUND && !out, "DISABLE_MISSING");
    x = change_for(off, "a"); YDPolicyCatalog *again = changed(off, &x);
    CHECK(info_of(again).generation == 3, "REACTIVATE_EPOCH");
    CHECK(yd_policy_catalog_at(again, 0, &e) == YD_PC_OK && e.version == 3 && e.mode == YD_PC_ENFORCE, "REACTIVATE");
    x = change_for(again, "a"); YDPolicyCatalog *same = changed(again, &x);
    CHECK(info_of(same).generation == 4, "SAME_SOURCE_NEW_EPOCH");
    yd_policy_catalog_free(base); yd_policy_catalog_free(one); yd_policy_catalog_free(off);
    yd_policy_catalog_free(again); yd_policy_catalog_free(same);
}

static void budgets(void) {
    YDPCBudget b = {1023, SIZE_MAX}; YDPCError error; YDPolicyCatalog *out = NULL;
    CHECK(yd_policy_catalog_empty(YD_PC_ORDINARY, &b, &out, &error) == YD_PC_LIMIT && !out && !b.work_left, "EMPTY_WORK_LIMIT");
    YDPolicyCatalog *base = empty(); YDPCInfo i = info_of(base);
    b = ample(); b.allocation_limit = i.owned_bytes - 1;
    CHECK(yd_policy_catalog_empty(YD_PC_ORDINARY, &b, &out, NULL) == YD_PC_LIMIT && !out, "ALLOCATION_LIMIT");
    b = ample(); b.allocation_limit = i.owned_bytes;
    CHECK(yd_policy_catalog_empty(YD_PC_ORDINARY, &b, &out, NULL) == YD_PC_OK, "EXACT_ALLOCATION");
    yd_policy_catalog_free(out);
    YDPCChange x = change_for(base, "a"); b = ample(); b.work_left = 1048576 + 16 * 14 - 1;
    CHECK(yd_policy_catalog_change(base, &x, YD_PC_LARGE, &b, &out, NULL) == YD_PC_LIMIT && !out && !b.work_left, "CHANGE_WORK_LIMIT");
    b = ample(); b.work_left = 1048576 + 16 * 14;
    CHECK(yd_policy_catalog_change(base, &x, YD_PC_LARGE, &b, &out, NULL) == YD_PC_OK && !b.work_left, "CHANGE_EXACT_WORK");
    unsigned char bytes[1024]; memset(bytes, 0xa5, sizeof(bytes)); size_t n = 55;
    b = ample(); b.allocation_limit = 0;
    CHECK(yd_policy_catalog_encode(out, YD_PC_LARGE, &b, bytes, 0, &n, NULL) == YD_PC_LIMIT && n == 0 && bytes[0] == 0xa5, "ENCODE_CAPACITY_ATOMIC");
    b.work_left = 1024 + info_of(out).encoded_bytes - 1;
    CHECK(yd_policy_catalog_encode(out, YD_PC_LARGE, &b, bytes, sizeof(bytes), &n, NULL) == YD_PC_LIMIT && !n && !b.work_left && bytes[0] == 0xa5, "ENCODE_WORK_ATOMIC");
    b.work_left = 1024 + info_of(out).encoded_bytes;
    CHECK(yd_policy_catalog_encode(out, YD_PC_LARGE, &b, bytes, sizeof(bytes), &n, NULL) == YD_PC_OK && !b.work_left && bytes[n] == 0xa5, "ENCODE_NO_TERMINATOR");
    b.work_left = 1048576 + 16 * n - 1; YDPolicyCatalog *parsed = NULL;
    CHECK(yd_policy_catalog_parse(bytes, n, YD_PC_LARGE, &b, &parsed, NULL) == YD_PC_LIMIT && !parsed && !b.work_left, "PARSE_WORK_LIMIT");
    b.work_left = 1048576 + 16 * n; b.allocation_limit = info_of(out).owned_bytes;
    CHECK(yd_policy_catalog_parse(bytes, n, YD_PC_LARGE, &b, &parsed, NULL) == YD_PC_OK && !b.work_left, "PARSE_EXACT_BUDGET");
    yd_policy_catalog_free(parsed); yd_policy_catalog_free(out);
    fail_malloc = 1; b = ample();
    CHECK(yd_policy_catalog_empty(YD_PC_LARGE, &b, &out, NULL) == YD_PC_ERROR && !out, "MALLOC_ERROR");
    fail_malloc = 0; fail_digest = 1;
    CHECK(yd_policy_catalog_empty(YD_PC_LARGE, &b, &out, NULL) == YD_PC_ERROR && !out, "DIGEST_ERROR");
    fail_digest = 0; yd_policy_catalog_free(base);
}

static void ownership(void) {
    YDPolicyCatalog *base = empty(); YDPCChange x = change_for(base, "z");
    unsigned char source[] = "[invalid YAML\r\n# still exact\t\xef\xbb\xbf\xf0\x9f\x98\x80";
    unsigned char expected[sizeof(source)]; memcpy(expected, source, sizeof(source));
    x.source = source; x.source_length = sizeof(source) - 1;
    YDPolicyCatalog *one = changed(base, &x); memset(source, 'x', sizeof(source));
    x = change_for(one, "a"); YDPolicyCatalog *two = changed(one, &x);
    yd_policy_catalog_free(base); yd_policy_catalog_free(one);
    YDPCEntry e;
    CHECK(yd_policy_catalog_at(two, 0, &e) == YD_PC_OK && !strcmp(e.collection, "a"), "SORTED_ENTRIES");
    CHECK(yd_policy_catalog_at(two, 1, &e) == YD_PC_OK && e.source_length == sizeof(expected) - 1 &&
          !memcmp(e.source, expected, e.source_length), "OWNED_EXACT_SOURCE");
    const char *bad_names[] = {"", "A", "a_b", "a/b", "yamldb-system"};
    YDPCBudget b = ample(); YDPolicyCatalog *out = NULL;
    for (size_t j = 0; j < sizeof(bad_names) / sizeof(*bad_names); ++j) {
        x = change_for(two, bad_names[j]);
        CHECK(yd_policy_catalog_change(two, &x, YD_PC_LARGE, &b, &out, NULL) == YD_PC_INVALID && !out, "NATIVE_NAME_RULES");
    }
    yd_policy_catalog_free(two);
}

static void change_limits(void) {
    YDPolicyCatalog *base = empty(); YDPCBudget b = ample(); YDPolicyCatalog *out = NULL;
    unsigned char source[32769]; memset(source, '\t', sizeof(source));
    YDPCChange x = change_for(base, "a"); x.source = source; x.source_length = sizeof(source);
    CHECK(yd_policy_catalog_change(base, &x, YD_PC_LARGE, &b, &out, NULL) == YD_PC_LIMIT && !out,
          "CHANGE_SOURCE_BOUND");
    x.source_length = sizeof(source) - 1; YDPolicyCatalog *one = changed(base, &x);
    x = change_for(one, "b"); x.source = source; x.source_length = sizeof(source) - 1;
    CHECK(yd_policy_catalog_change(one, &x, YD_PC_ORDINARY, &b, &out, NULL) == YD_PC_UNSUPPORTED &&
          !out && info_of(one).generation == 1, "CHANGE_PROFILE_ATOMIC");
    YDPolicyCatalog *two = changed(one, &x); unsigned char output[8]; memset(output, 0xa5, sizeof(output));
    size_t written = 123;
    CHECK(yd_policy_catalog_encode(two, YD_PC_ORDINARY, &b, output, sizeof(output), &written, NULL) == YD_PC_UNSUPPORTED &&
          !written && output[0] == 0xa5, "ENCODE_PROFILE_ATOMIC");
    const unsigned char invalid[][4] = {{0}, {8}, {127}, {0xc0, 0xaf}, {0xed, 0xa0, 0x80}, {0xf4, 0x90, 0x80, 0x80}};
    const size_t lengths[] = {1, 1, 1, 2, 3, 4};
    for (size_t j = 0; j < sizeof(lengths) / sizeof(*lengths); ++j) {
        x = change_for(base, "a"); x.source = invalid[j]; x.source_length = lengths[j];
        CHECK(yd_policy_catalog_change(base, &x, YD_PC_LARGE, &b, &out, NULL) == YD_PC_INVALID && !out,
              "CHANGE_INVALID_SOURCE");
    }
    x = change_for(base, "a"); x.operation = (YDPCOperation)99;
    CHECK(yd_policy_catalog_change(base, &x, YD_PC_LARGE, &b, &out, NULL) == YD_PC_UNSUPPORTED, "UNKNOWN_OPERATION");
    CHECK(yd_policy_catalog_empty((YDPCProfile)99, &b, &out, NULL) == YD_PC_UNSUPPORTED && !out, "UNKNOWN_SIZE_PROFILE");
    yd_policy_catalog_free(one); yd_policy_catalog_free(two);
    for (size_t j = 0; j < 64; ++j) {
        char name[8]; (void)snprintf(name, sizeof(name), "c%zu", j); x = change_for(base, name);
        one = changed(base, &x); yd_policy_catalog_free(base); base = one;
    }
    x = change_for(base, "c0"); x.operation = YD_PC_DISABLE; x.source = NULL; x.source_length = 0;
    one = changed(base, &x); yd_policy_catalog_free(base); base = one;
    x = change_for(base, "new");
    CHECK(yd_policy_catalog_change(base, &x, YD_PC_LARGE, &b, &out, NULL) == YD_PC_LIMIT && !out &&
          info_of(base).count == 64, "TOMBSTONE_COUNTS_TOWARD_CAP");
    x = change_for(base, "c0"); one = changed(base, &x);
    CHECK(info_of(one).count == 64 && info_of(one).generation == 66, "FULL_REACTIVATION");
    yd_policy_catalog_free(base); yd_policy_catalog_free(one);
}

static unsigned char *read_file(const char *path, size_t *length) {
    FILE *f = fopen(path, "rb"); CHECK(f, "OPEN_FIXTURE");
    CHECK(!fseek(f, 0, SEEK_END), "SEEK_FIXTURE"); long end = ftell(f);
    CHECK(end >= 0 && !fseek(f, 0, SEEK_SET), "SIZE_FIXTURE");
    *length = (size_t)end; unsigned char *s = malloc(*length + 1); CHECK(s, "FIXTURE_ALLOC");
    CHECK(fread(s, 1, *length, f) == *length && !fclose(f), "READ_FIXTURE");
    s[*length] = 0; return s;
}
static void parse_fixture(int argc, char **argv) {
    CHECK(argc == 5 || argc == 6, "PARSE_ARGUMENTS");
    size_t length; unsigned char *s = read_file(argv[2], &length);
    YDPCResult expected = (YDPCResult)atoi(argv[3]); YDPCProfile profile = (YDPCProfile)atoi(argv[4]);
    YDPCBudget b = ample(); YDPolicyCatalog *c = NULL; YDPCError error;
    YDPCResult result = yd_policy_catalog_parse(s, length, profile, &b, &c, &error); free(s);
    CHECK(result == expected, "PARSE_EXPECTED_RESULT");
    if (result != YD_PC_OK) { CHECK(!c && error.message[0], "PARSE_FAILURE_ATOMIC"); return; }
    YDPCInfo info = info_of(c);
    CHECK(info.owned_bytes <= info.source_bytes + 32768, "OWNED_MEMORY_BOUND");
    unsigned char *encoded = malloc(info.encoded_bytes + 1); CHECK(encoded, "ENCODE_ALLOC");
    encoded[info.encoded_bytes] = 0x5a; size_t n = 0; b = ample();
    CHECK(yd_policy_catalog_encode(c, profile, &b, encoded, info.encoded_bytes, &n, NULL) == YD_PC_OK &&
          n == info.encoded_bytes && encoded[n] == 0x5a, "ENCODE_EXACT_CAPACITY");
    if (argc == 6) {
        size_t golden_n; unsigned char *golden = read_file(argv[5], &golden_n);
        CHECK(n == golden_n && !memcmp(encoded, golden, n), "CANONICAL_GOLDEN"); free(golden);
    }
    YDPolicyCatalog *again = NULL; b = ample();
    CHECK(yd_policy_catalog_parse(encoded, n, profile, &b, &again, NULL) == YD_PC_OK &&
          !memcmp(info_of(again).catalog_sha256, info.catalog_sha256, 32), "ROUNDTRIP_IDENTITY");
    if (info.generation == UINT64_MAX) {
        hash_is(info.catalog_sha256, "3c244c4368b5eb9c69a6a218f5386d3919c6f087f6891fe9e81d0993bfad1778", "MAX_LE_VECTOR");
        YDPCEntry e; CHECK(yd_policy_catalog_at(c, 0, &e) == YD_PC_OK, "MAX_ENTRY");
        YDPCChange x = change_for(c, e.collection); YDPolicyCatalog *out = NULL; b = ample();
        CHECK(yd_policy_catalog_change(c, &x, profile, &b, &out, NULL) == YD_PC_LIMIT && !out, "GENERATION_NO_WRAP");
    }
    if (info.generation == UINT64_C(0x0102030405060708))
        hash_is(info.catalog_sha256, "9ef62094049edcf38237193642cd9141eb9e7d83c7284620b013112c1edcbd1a", "HIGH_LE_VECTOR");
    free(encoded); yd_policy_catalog_free(c); yd_policy_catalog_free(again);
}

typedef struct { const YDPolicyCatalog *catalog; } Reader;
static void *reader(void *argument) {
    const YDPolicyCatalog *c = ((Reader *)argument)->catalog;
    for (int i = 0; i < 200; ++i) {
        YDPCEntry e; YDPCInfo info = info_of(c); unsigned char output[1024]; size_t n = 0;
        CHECK(yd_policy_catalog_find(c, "a", 1, &e) == YD_PC_OK && e.version == 1, "CONCURRENT_VIEW");
        YDPCBudget b = ample();
        CHECK(yd_policy_catalog_encode(c, YD_PC_ORDINARY, &b, output, sizeof(output), &n, NULL) == YD_PC_OK &&
              n == info.encoded_bytes, "CONCURRENT_ENCODE");
    }
    return NULL;
}
static void concurrent(void) {
    YDPolicyCatalog *base = empty(); YDPCChange x = change_for(base, "a");
    YDPolicyCatalog *c = changed(base, &x); yd_policy_catalog_free(base);
    Reader r = {c}; pthread_t threads[8];
    for (size_t i = 0; i < 8; ++i) CHECK(!pthread_create(&threads[i], NULL, reader, &r), "THREAD_CREATE");
    for (size_t i = 0; i < 8; ++i) CHECK(!pthread_join(threads[i], NULL), "THREAD_JOIN");
    yd_policy_catalog_free(c);
}
int main(int argc, char **argv) {
    CHECK(argc >= 2, "SCENARIO");
    if (!strcmp(argv[1], "empty")) empty_catalog();
    else if (!strcmp(argv[1], "changes")) changes();
    else if (!strcmp(argv[1], "budgets")) budgets();
    else if (!strcmp(argv[1], "ownership")) ownership();
    else if (!strcmp(argv[1], "limits")) change_limits();
    else if (!strcmp(argv[1], "parse")) parse_fixture(argc, argv);
    else if (!strcmp(argv[1], "concurrent")) concurrent();
    else CHECK(0, "UNKNOWN_SCENARIO");
    puts("policy catalog scenario passed");
    return 0;
}
