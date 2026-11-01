#define _POSIX_C_SOURCE 200809L
#include "sharding/routing.h"
#include "disk.h"

#include <inttypes.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "check failed at %s:%d: %s\n", __FILE__, __LINE__, #condition); exit(1); } } while (0)
#define STATUS(expression, expected) do { YDShardStatus actual = (expression); \
    if (actual != (expected)) { fprintf(stderr, "line %d: got %s expected %s\n", __LINE__, \
        yd_shard_status_name(actual), yd_shard_status_name(expected)); exit(1); } } while (0)

static const char placement_id[] = "0123456789abcdef0123456789abcdef";
static const char source[] = "# keep comments and CRLF\r\nprofile: {tenant: 'abc'} # unchanged\r\nvalue: 42\r\n";
static const char metadata[] =
    "# a trusted static routing snapshot\n"
    "version: 1\nkey_version: 1\nalgorithm: sha256-64be-v1\n"
    "placement_id: '0123456789abcdef0123456789abcdef'\n"
    "collection: records\nfield: profile.tenant\nepoch: 7\n"
    "ranges:\n"
    "- {first: '0000000000000000', last: '7fffffffffffffff', shard: a, group: raft-a}\n"
    "- {first: '8000000000000000', last: 'ffffffffffffffff', shard: b, group: raft-b}\n";

static YDValue *parse(const char *text) {
    char error[128] = {0};
    YDValue *v = yd_parse((const unsigned char *)text, strlen(text), error, sizeof(error));
    if (!v) fprintf(stderr, "parse failed: %s\n", error);
    CHECK(v); return v;
}
static YDShardKey key(const char *text) {
    YDValue *v = parse(text); YDShardKey k;
    STATUS(yd_shard_key_encode(v, &k), YD_SHARD_OK);
    yd_free(v); return k;
}
static YDShardPlacement *placement(const char *text) {
    YDShardPlacement *p = NULL;
    STATUS(yd_shard_placement_parse((const unsigned char *)text, strlen(text), &p), YD_SHARD_OK);
    CHECK(p); return p;
}
static char *replace(const char *text, const char *old, const char *replacement) {
    const char *p = strstr(text, old); CHECK(p);
    size_t before = (size_t)(p - text), old_size = strlen(old), new_size = strlen(replacement);
    size_t length = strlen(text) - old_size + new_size;
    char *out = malloc(length + 1); CHECK(out);
    memcpy(out, text, before); memcpy(out + before, replacement, new_size);
    strcpy(out + before + new_size, p + old_size); return out;
}
static void hex(const unsigned char *bytes, size_t length, char *out) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < length; i++) { out[i * 2] = digits[bytes[i] >> 4]; out[i * 2 + 1] = digits[bytes[i] & 15]; }
    out[length * 2] = 0;
}
static void empty_plan(const YDShardPlan *p) {
    YDShardPlan zero = {0}; CHECK(!memcmp(p, &zero, sizeof(zero)));
}

static void keys(void) {
    /* RFC 6234 section 8.5 SHA256 TEST1: verify the system primitive alongside
     * independently frozen wire/token vectors published in sharding.md. */
    unsigned char digest[EVP_MAX_MD_SIZE]; unsigned size = 0; char text[129];
    CHECK(EVP_Digest("abc", 3, digest, &size, EVP_sha256(), NULL) == 1 && size == 32);
    hex(digest, size, text);
    CHECK(!strcmp(text, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    static const struct { const char *yaml, *wire; uint64_t token; } vectors[] = {
        {"'abc'", "59534b01030003616263", UINT64_C(0x8e8dbe51e84d01a0)},
        {"0", "59534b010200080000000000000000", UINT64_C(0x064ca6a581ecc2b8)},
        {"9223372036854775807", "59534b010200087fffffffffffffff", UINT64_C(0x7edc06f618a2f694)},
        {"-9223372036854775808", "59534b010200088000000000000000", UINT64_C(0x411434b470ff72da)},
        {"-1", "59534b01020008ffffffffffffffff", UINT64_C(0x155ae025c9dae005)},
        {"false", "59534b0101000100", UINT64_C(0xc5ab786d7307b88a)},
        {"true", "59534b0101000101", UINT64_C(0x52eabbdff2c2cfc1)},
        {"''", "59534b01030000", UINT64_C(0x2ed2884e1f71923e)}
    };
    for (size_t i = 0; i < sizeof(vectors) / sizeof(vectors[0]); i++) {
        YDShardKey k = key(vectors[i].yaml), decoded;
        char wire[YD_SHARD_KEY_LIMIT * 2 + 1]; hex(k.bytes, k.length, wire);
        CHECK(!strcmp(wire, vectors[i].wire));
        STATUS(yd_shard_key_decode(k.bytes, k.length, &decoded), YD_SHARD_OK);
        CHECK(decoded.length == k.length && !memcmp(decoded.bytes, k.bytes, k.length));
        uint64_t token;
        STATUS(yd_shard_key_token(&decoded, &token), YD_SHARD_OK); CHECK(token == vectors[i].token);
        /* No complete key is a proper prefix of another accepted key. */
        for (size_t n = 0; n < k.length; n++) CHECK(yd_shard_key_decode(k.bytes, n, &decoded) != YD_SHARD_OK);
        k.bytes[k.length++] = 0;
        STATUS(yd_shard_key_decode(k.bytes, k.length, &decoded), YD_SHARD_INVALID_KEY);
        CHECK(!decoded.length);
    }
    YDShardKey a = key("1"), b = key("0x1"), c = key("+01");
    CHECK(a.length == b.length && !memcmp(a.bytes, b.bytes, a.length));
    CHECK(a.length == c.length && !memcmp(a.bytes, c.bytes, a.length));
    a = key("0"); b = key("-0"); CHECK(!memcmp(a.bytes, b.bytes, a.length));
    char padded[128]; memset(padded, '0', sizeof(padded)); padded[sizeof(padded)-1] = 0;
    c = key(padded); CHECK(!memcmp(a.bytes, c.bytes, a.length));
    a = key("\"caf\\u00e9\""); b = key("'café'"); CHECK(!memcmp(a.bytes, b.bytes, a.length));
    c = key("\"cafe\\u0301\""); CHECK(c.length != a.length); /* no Unicode normalization */
    for (size_t i = 0; i < 4; i++) {
        const char *unsupported[] = {"null", "1.0", "[]", "{}"}; YDValue *v = parse(unsupported[i]);
        STATUS(yd_shard_key_encode(v, &a), YD_SHARD_UNSUPPORTED_KEY); CHECK(!a.length); yd_free(v);
    }
    STATUS(yd_shard_key_encode(NULL, &a), YD_SHARD_MISSING_KEY);
    CHECK(!a.length);
    char long_text[YD_SHARD_STRING_LIMIT + 2]; memset(long_text, 'x', sizeof(long_text));
    long_text[YD_SHARD_STRING_LIMIT] = 0;
    YDValue v = {.type = YD_STRING, .scalar = long_text};
    STATUS(yd_shard_key_encode(&v, &a), YD_SHARD_OK); CHECK(a.length == YD_SHARD_KEY_LIMIT);
    long_text[YD_SHARD_STRING_LIMIT] = 'x'; long_text[YD_SHARD_STRING_LIMIT + 1] = 0;
    STATUS(yd_shard_key_encode(&v, &a), YD_SHARD_INVALID_KEY);
    v.type = YD_INT; v.scalar = "9223372036854775808";
    STATUS(yd_shard_key_encode(&v, &a), YD_SHARD_INVALID_KEY);
    v.scalar = "-9223372036854775809";
    STATUS(yd_shard_key_encode(&v, &a), YD_SHARD_INVALID_KEY);
    v.type = YD_STRING; v.scalar = "\xc0\xaf";
    STATUS(yd_shard_key_encode(&v, &a), YD_SHARD_INVALID_KEY);
    a = key("'abc'"); a.bytes[3] = 2;
    STATUS(yd_shard_key_decode(a.bytes, a.length, &b), YD_SHARD_UNSUPPORTED_KEY);
    a.bytes[3] = 1; a.bytes[4] = 9;
    STATUS(yd_shard_key_decode(a.bytes, a.length, &b), YD_SHARD_UNSUPPORTED_KEY);
    a = key("true"); a.bytes[7] = 2;
    STATUS(yd_shard_key_decode(a.bytes, a.length, &b), YD_SHARD_INVALID_KEY);
    a = key("'abc'"); a.length = SIZE_MAX;
    uint64_t token = 99; STATUS(yd_shard_key_token(&a, &token), YD_SHARD_INVALID_KEY); CHECK(token == 0);
    STATUS(yd_shard_key_decode(NULL, 8, &b), YD_SHARD_INVALID_KEY);
    CHECK(!b.length);
    /* Invalid UTF-8 and embedded NUL cannot enter through the binary API. */
    const unsigned char bad[][4] = {{0,0,0,0}, {0xc0,0xaf,0,0}, {0xed,0xa0,0x80,0},
        {0xf4,0x90,0x80,0x80}, {0xe2,0x82,0,0}, {0x7f,0,0,0}};
    const size_t lengths[] = {1,2,3,4,2,1};
    for (size_t i = 0; i < sizeof(lengths)/sizeof(lengths[0]); i++) {
        unsigned char encoded[11] = {'Y','S','K',1,3,0,(unsigned char)lengths[i]};
        memcpy(encoded+7, bad[i], lengths[i]);
        STATUS(yd_shard_key_decode(encoded, 7+lengths[i], &b), YD_SHARD_INVALID_KEY);
    }
    puts("key codec and published vectors passed");
}

static void metadata_tests(void) {
    YDShardPlacement *p = placement(metadata);
    CHECK(yd_shard_placement_epoch(p) == 7);
    CHECK(!strcmp(yd_shard_placement_field(p), "profile.tenant"));
    yd_shard_placement_free(p);
    const struct { const char *old, *replacement; YDShardStatus status; } cases[] = {
        /* Version 2 is now readable (compound-key test below); the next
         * unknown version is refused the same way version 2 was before. */
        {"version: 1", "version: 3", YD_SHARD_UNSUPPORTED_METADATA},
        {"key_version: 1", "key_version: 2", YD_SHARD_UNSUPPORTED_METADATA},
        {"sha256-64be-v1", "unknown", YD_SHARD_UNSUPPORTED_METADATA},
        {"epoch: 7", "epoch: 0", YD_SHARD_INVALID_METADATA},
        {"epoch: 7", "epoch: -1", YD_SHARD_INVALID_METADATA},
        {"epoch: 7", "epoch: 9223372036854775808", YD_SHARD_INVALID_METADATA},
        {"epoch: 7", "epoch: 7.0", YD_SHARD_INVALID_METADATA},
        {"epoch: 7", "epoch: 7\nextra: true", YD_SHARD_INVALID_METADATA},
        {"epoch: 7", "epoch: 7\nepoch: 7", YD_SHARD_INVALID_METADATA},
        {"profile.tenant", "profile..tenant", YD_SHARD_INVALID_METADATA},
        {"profile.tenant", "profile.0.tenant", YD_SHARD_INVALID_METADATA},
        {"profile.tenant", "$tenant", YD_SHARD_INVALID_METADATA},
        {"collection: records", "collection: ../records", YD_SHARD_INVALID_METADATA},
        {"0123456789abcdef0123456789abcdef", "00000000000000000000000000000000", YD_SHARD_INVALID_METADATA},
        {"0123456789abcdef0123456789abcdef", "0123456789ABCDEF0123456789abcdef", YD_SHARD_INVALID_METADATA},
        {"last: '7fffffffffffffff'", "last: '7ffffffffffffffe'", YD_SHARD_INVALID_METADATA}, /* gap */
        {"last: '7fffffffffffffff'", "last: '8000000000000000'", YD_SHARD_INVALID_METADATA}, /* overlap */
        {"last: '7fffffffffffffff'", "last: 'ffffffffffffffff'", YD_SHARD_INVALID_METADATA}, /* overflow */
        {"first: '0000000000000000'", "first: '0000000000000001'", YD_SHARD_INVALID_METADATA},
        {"last: 'ffffffffffffffff'", "last: 'fffffffffffffffe'", YD_SHARD_INVALID_METADATA},
        {"first: '8000000000000000'", "first: 'ffffffffffffffff'", YD_SHARD_INVALID_METADATA},
        {"last: 'ffffffffffffffff'", "last: '0000000000000000'", YD_SHARD_INVALID_METADATA},
        {"first: '8000000000000000'", "first: '0000000000000000'", YD_SHARD_INVALID_METADATA},
        {"last: '7fffffffffffffff'", "last: 'fffffffffffffffff'", YD_SHARD_INVALID_METADATA},
        {"first: '8000000000000000'", "first: '800000000000000A'", YD_SHARD_INVALID_METADATA},
        {"shard: b", "shard: a", YD_SHARD_INVALID_METADATA},
        {"shard: b", "shard: b, shard: c", YD_SHARD_INVALID_METADATA},
        {"group: raft-a", "group: raft-a, unknown: 1", YD_SHARD_INVALID_METADATA},
        {"group: raft-a", "group: ''", YD_SHARD_INVALID_METADATA}
    };
    /* The single-field format stays byte-identical: canonical encoding of the
     * version-1 snapshot is frozen here. */
    p = placement(metadata); size_t frozen_size = 0;
    unsigned char *frozen = yd_shard_placement_encode(p, &frozen_size); CHECK(frozen);
    static const char frozen_v1[] = "{\"version\":1,\"key_version\":1,\"algorithm\":\"sha256-64be-v1\","
        "\"placement_id\":\"0123456789abcdef0123456789abcdef\",\"collection\":\"records\","
        "\"field\":\"profile.tenant\",\"epoch\":7,\"ranges\":[{\"first\":\"0000000000000000\","
        "\"last\":\"7fffffffffffffff\",\"shard\":\"a\",\"group\":\"raft-a\"},{\"first\":\"8000000000000000\","
        "\"last\":\"ffffffffffffffff\",\"shard\":\"b\",\"group\":\"raft-b\"}]}";
    CHECK(frozen_size == strlen(frozen_v1) && !memcmp(frozen, frozen_v1, frozen_size));
    CHECK(yd_shard_placement_version(p) == 1 && yd_shard_placement_key_version(p) == 1);
    free(frozen); yd_shard_placement_free(p);
    for (size_t i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) {
        char *input = replace(metadata, cases[i].old, cases[i].replacement);
        p = (YDShardPlacement *)(uintptr_t)1;
        STATUS(yd_shard_placement_parse((const unsigned char *)input, strlen(input), &p), cases[i].status);
        CHECK(p == NULL); free(input);
    }
    const char *invalid[] = {"", "[]", "{}", "&x {a: *x}", "version: 1\n---\nversion: 1"};
    for (size_t i = 0; i < sizeof(invalid)/sizeof(invalid[0]); i++) {
        STATUS(yd_shard_placement_parse((const unsigned char *)invalid[i], strlen(invalid[i]), &p), YD_SHARD_INVALID_METADATA);
        CHECK(p == NULL);
    }
    STATUS(yd_shard_placement_parse(NULL, SIZE_MAX, &p), YD_SHARD_INVALID_METADATA);
    char *oversize = malloc(YD_SHARD_METADATA_LIMIT + 1); CHECK(oversize);
    memset(oversize, ' ', YD_SHARD_METADATA_LIMIT + 1);
    STATUS(yd_shard_placement_parse((const unsigned char *)oversize, YD_SHARD_METADATA_LIMIT+1, &p), YD_SHARD_INVALID_METADATA);
    free(oversize);
    /* JSON uses the same typed native parser, and the placement owns its copy. */
    YDValue *v = parse(metadata); size_t size;
    char *json = yd_json(v, &size); CHECK(json); yd_free(v);
    STATUS(yd_shard_placement_parse((unsigned char *)json, size, &p), YD_SHARD_OK);
    memset(json, 'x', size); free(json);
    CHECK(!strcmp(yd_shard_placement_field(p), "profile.tenant")); yd_shard_placement_free(p);
    const char *ranges_start = strstr(metadata, "ranges:\n"); CHECK(ranges_start);
    size_t prefix = (size_t)(ranges_start - metadata);
    char *many = calloc(1, YD_SHARD_METADATA_LIMIT); CHECK(many);
    memcpy(many, metadata, prefix); strcpy(many + prefix, "ranges:\n");
    size_t used = strlen(many);
    /* Maximum-size valid table and the first rejected count. Shifts use
     * unsigned fixed-width arithmetic, including the final UINT64_MAX end. */
    for (unsigned i = 0; i <= YD_SHARD_RANGE_LIMIT; i++) {
        uint64_t first = (uint64_t)(i & 255) << 56, last = first | UINT64_C(0x00ffffffffffffff);
        int wrote = snprintf(many + used, YD_SHARD_METADATA_LIMIT - used,
            "- {first: '%016" PRIx64 "', last: '%016" PRIx64 "', shard: s%u, group: raft-a}\n", first, last, i);
        CHECK(wrote > 0 && (size_t)wrote < YD_SHARD_METADATA_LIMIT-used); used += (size_t)wrote;
        if (i == YD_SHARD_RANGE_LIMIT - 1) { p = placement(many); yd_shard_placement_free(p); }
    }
    STATUS(yd_shard_placement_parse((unsigned char *)many, used, &p), YD_SHARD_INVALID_METADATA);
    CHECK(!p); free(many);
    /* Unknown nested fields, empty tables and a single full-ring shard. */
    char *one = replace(metadata, ranges_start,
        "ranges: [{first: '0000000000000000', last: 'ffffffffffffffff', shard: only, group: raft-a}]\n");
    p = placement(one); yd_shard_placement_free(p); free(one);
    char *none = replace(metadata, ranges_start, "ranges: []\n");
    STATUS(yd_shard_placement_parse((unsigned char *)none, strlen(none), &p), YD_SHARD_INVALID_METADATA); free(none);
    puts("strict placement validation passed");
}

static void routing(void) {
    YDShardPlacement *p = placement(metadata); YDShardPlan plan;
    YDShardKey batch[3] = {key("0"), key("true"), key("'abc'")};
    STATUS(yd_shard_plan_keys(p, placement_id, "records", 7, YD_SHARD_READ, batch, 1, &plan), YD_SHARD_OK);
    CHECK(!strcmp(plan.shard, "a") && !strcmp(plan.group, "raft-a"));
    CHECK(plan.token == UINT64_C(0x064ca6a581ecc2b8) && plan.epoch == 7 && plan.key_count == 1);
    STATUS(yd_shard_plan_keys(p, placement_id, "records", 7, YD_SHARD_TRANSACTION, batch, 2, &plan), YD_SHARD_OK);
    CHECK(plan.key_count == 2 && plan.operation == YD_SHARD_TRANSACTION);
    STATUS(yd_shard_plan_keys(p, placement_id, "records", 7, YD_SHARD_TRANSACTION, batch, 3, &plan), YD_SHARD_CROSS_SHARD_UNSUPPORTED);
    empty_plan(&plan);
    YDShardKey full_batch[YD_SHARD_BATCH_LIMIT];
    for (size_t i = 0; i < YD_SHARD_BATCH_LIMIT; i++) full_batch[i] = batch[0];
    STATUS(yd_shard_plan_keys(p, placement_id, "records", 7, YD_SHARD_TRANSACTION,
        full_batch, YD_SHARD_BATCH_LIMIT, &plan), YD_SHARD_OK);
    CHECK(plan.key_count == YD_SHARD_BATCH_LIMIT);
    batch[2].bytes[3] = 8;
    STATUS(yd_shard_plan_keys(p, placement_id, "records", 7, YD_SHARD_TRANSACTION, batch, 3, &plan), YD_SHARD_UNSUPPORTED_KEY);
    empty_plan(&plan); batch[2] = key("'abc'");
    STATUS(yd_shard_plan_keys(p, placement_id, "records", 6, YD_SHARD_WRITE, batch, 1, &plan), YD_SHARD_STALE_PLACEMENT); empty_plan(&plan);
    STATUS(yd_shard_plan_keys(p, placement_id, "records", 8, YD_SHARD_WRITE, batch, 1, &plan), YD_SHARD_STALE_PLACEMENT);
    STATUS(yd_shard_plan_keys(p, "1123456789abcdef0123456789abcdef", "records", 7, YD_SHARD_READ, batch, 1, &plan), YD_SHARD_STALE_PLACEMENT);
    STATUS(yd_shard_plan_keys(p, placement_id, "other", 7, YD_SHARD_READ, batch, 1, &plan), YD_SHARD_STALE_PLACEMENT);
    STATUS(yd_shard_plan_keys(p, placement_id, "records", 0, YD_SHARD_READ, batch, 1, &plan), YD_SHARD_INVALID_ARGUMENT);
    STATUS(yd_shard_plan_keys(p, placement_id, "records", 7, YD_SHARD_READ, NULL, 0, &plan), YD_SHARD_MISSING_KEY);
    STATUS(yd_shard_plan_keys(p, placement_id, "records", 7, YD_SHARD_QUERY, batch, 2, &plan), YD_SHARD_INVALID_ARGUMENT);
    STATUS(yd_shard_plan_keys(p, placement_id, "records", 7, YD_SHARD_TRANSACTION, batch, SIZE_MAX, &plan), YD_SHARD_INVALID_ARGUMENT);
    STATUS(yd_shard_plan_keys(p, placement_id, "records", 7, YD_SHARD_SCAN, NULL, 0, &plan), YD_SHARD_CROSS_SHARD_UNSUPPORTED);
    STATUS(yd_shard_plan_keys(p, placement_id, "records", 7, YD_SHARD_UNIQUE_INDEX, NULL, 0, &plan), YD_SHARD_CROSS_SHARD_UNSUPPORTED);
    STATUS(yd_shard_plan_keys(p, placement_id, "records", 7, (YDShardOperation)99, batch, 1, &plan), YD_SHARD_INVALID_ARGUMENT); empty_plan(&plan);
    YDValue *doc = parse(source), *same = parse("profile: {tenant: abc}\nvalue: different"),
        *changed = parse("profile: {tenant: 'xyz'}"), *missing = parse("id: abc"), *null = parse("profile: {tenant: null}"),
        *array = parse("profile: [{tenant: abc}]");
    STATUS(yd_shard_plan_document(p, placement_id, "records", 7, YD_SHARD_QUERY, doc, &plan), YD_SHARD_OK);
    CHECK(!strcmp(plan.shard, "b") && plan.token == UINT64_C(0x8e8dbe51e84d01a0));
    STATUS(yd_shard_plan_document(p, placement_id, "records", 7, YD_SHARD_READ, missing, &plan), YD_SHARD_MISSING_KEY);
    STATUS(yd_shard_plan_document(p, placement_id, "records", 7, YD_SHARD_READ, null, &plan), YD_SHARD_UNSUPPORTED_KEY);
    STATUS(yd_shard_plan_document(p, placement_id, "records", 7, YD_SHARD_READ, array, &plan), YD_SHARD_MISSING_KEY);
    STATUS(yd_shard_key_unchanged(p, doc, same), YD_SHARD_OK);
    STATUS(yd_shard_key_unchanged(p, doc, changed), YD_SHARD_KEY_CHANGE_UNSUPPORTED);
    STATUS(yd_shard_key_unchanged(p, doc, missing), YD_SHARD_MISSING_KEY);
    STATUS(yd_shard_key_unchanged(p, doc, null), YD_SHARD_UNSUPPORTED_KEY);
    yd_free(doc); yd_free(same); yd_free(changed); yd_free(missing); yd_free(null); yd_free(array);
    yd_shard_placement_free(p);
    /* Distinct logical shards in the same group are still cross-shard. */
    char *shared = replace(metadata, "group: raft-b", "group: raft-a"); p = placement(shared); free(shared);
    batch[1] = batch[2];
    STATUS(yd_shard_plan_keys(p, placement_id, "records", 7, YD_SHARD_TRANSACTION, batch, 2, &plan), YD_SHARD_CROSS_SHARD_UNSUPPORTED);
    yd_shard_placement_free(p);
    /* Exact inclusive token endpoints, not a platform-dependent modulo. */
    char *lower = replace(metadata, "7fffffffffffffff", "8e8dbe51e84d01a0");
    char *edge = replace(lower, "8000000000000000", "8e8dbe51e84d01a1"); free(lower); p = placement(edge); free(edge);
    STATUS(yd_shard_plan_keys(p, placement_id, "records", 7, YD_SHARD_READ, &batch[2], 1, &plan), YD_SHARD_OK);
    CHECK(!strcmp(plan.shard, "a")); yd_shard_placement_free(p);
    lower = replace(metadata, "7fffffffffffffff", "8e8dbe51e84d019f");
    edge = replace(lower, "8000000000000000", "8e8dbe51e84d01a0"); free(lower); p = placement(edge); free(edge);
    STATUS(yd_shard_plan_keys(p, placement_id, "records", 7, YD_SHARD_READ, &batch[2], 1, &plan), YD_SHARD_OK);
    CHECK(!strcmp(plan.shard, "b")); yd_shard_placement_free(p);
    puts("routing, stale placement and cross-shard rejection passed");
}

static const char compound_metadata[] =
    "version: 2\nkey_version: 2\nalgorithm: sha256-64be-v1\n"
    "placement_id: '0123456789abcdef0123456789abcdef'\n"
    "collection: records\nfield: [tenant, profile.user]\nepoch: 7\n"
    "ranges:\n"
    "- {first: '0000000000000000', last: '7fffffffffffffff', shard: a, group: raft-a}\n"
    "- {first: '8000000000000000', last: 'ffffffffffffffff', shard: b, group: raft-b}\n";

static YDShardKey compound_key(const char *yaml) {
    YDValue *v = parse(yaml); YDShardKey k; CHECK(v->type == YD_ARRAY);
    STATUS(yd_shard_compound_key_encode((const YDValue *const *)v->items, v->count, &k), YD_SHARD_OK);
    yd_free(v); return k;
}
static YDShardStatus compound_status(const char *yaml) {
    YDValue *v = parse(yaml); YDShardKey k; CHECK(v->type == YD_ARRAY);
    YDShardStatus s = yd_shard_compound_key_encode((const YDValue *const *)v->items, v->count, &k);
    if (s != YD_SHARD_OK) CHECK(!k.length);
    yd_free(v); return s;
}

/* Version-2 keys, version-2 metadata, per-component validation, routing and
 * unique-index admission. Wire/token vectors were computed independently with
 * Python hashlib (sha256(key)[:8], big-endian) and are published in sharding.md. */
static void compound(void) {
    static const struct { const char *yaml, *wire; uint64_t token; } vectors[] = {
        {"['abc']", "59534b0201030003616263", UINT64_C(0xa2b9310653e71c65)},
        {"['abc', 1]", "59534b02020300036162630200080000000000000001", UINT64_C(0xa3922b2478c730bb)},
        {"[true, -1, '']", "59534b020301000101020008ffffffffffffffff030000", UINT64_C(0x8a673f8e5a7234d4)},
        {"['tenant-a', 'user-42', 7, false]",
         "59534b020403000874656e616e742d61030007757365722d3432020008000000000000000701000100",
         UINT64_C(0x187bce757d32db75)},
        {"[0, 'abc']", "59534b02020200080000000000000000030003616263", UINT64_C(0x373dc0f47d1a81e9)},
        {"[-9223372036854775808, 9223372036854775807]",
         "59534b020202000880000000000000000200087fffffffffffffff", UINT64_C(0x76a0687dcb4517ee)},
    };
    for (size_t i = 0; i < sizeof(vectors) / sizeof(vectors[0]); i++) {
        YDShardKey k = compound_key(vectors[i].yaml), decoded;
        char wire[YD_SHARD_KEY_BYTES * 2 + 1]; hex(k.bytes, k.length, wire);
        CHECK(!strcmp(wire, vectors[i].wire));
        STATUS(yd_shard_key_decode(k.bytes, k.length, &decoded), YD_SHARD_OK);
        CHECK(decoded.length == k.length && !memcmp(decoded.bytes, k.bytes, k.length));
        uint64_t token;
        STATUS(yd_shard_key_token(&decoded, &token), YD_SHARD_OK); CHECK(token == vectors[i].token);
        for (size_t n = 0; n < k.length; n++) CHECK(yd_shard_key_decode(k.bytes, n, &decoded) != YD_SHARD_OK);
        k.bytes[k.length++] = 0;
        STATUS(yd_shard_key_decode(k.bytes, k.length, &decoded), YD_SHARD_INVALID_KEY);
    }
    /* A one-component compound key is a different key from the version-1 key. */
    YDShardKey one = compound_key("['abc']"), v1 = key("'abc'");
    CHECK(one.length != v1.length);
    /* Exact maximum: four 256-byte strings; one more byte is invalid. */
    char long_text[YD_SHARD_STRING_LIMIT + 2]; memset(long_text, 'x', sizeof(long_text));
    long_text[YD_SHARD_STRING_LIMIT] = 0;
    YDValue big = {.type = YD_STRING, .scalar = long_text};
    const YDValue *four[] = {&big, &big, &big, &big}; YDShardKey k; uint64_t token;
    STATUS(yd_shard_compound_key_encode(four, 4, &k), YD_SHARD_OK);
    CHECK(k.length == YD_SHARD_KEY_BYTES && k.length == 1041);
    STATUS(yd_shard_key_token(&k, &token), YD_SHARD_OK); CHECK(token == UINT64_C(0xfe7ea5bf0fdbbdf5));
    long_text[YD_SHARD_STRING_LIMIT] = 'x'; long_text[YD_SHARD_STRING_LIMIT + 1] = 0;
    STATUS(yd_shard_compound_key_encode(four, 4, &k), YD_SHARD_INVALID_KEY); CHECK(!k.length);
    STATUS(yd_shard_compound_key_encode(four, 0, &k), YD_SHARD_INVALID_ARGUMENT);
    const YDValue *five[] = {&big, &big, &big, &big, &big};
    STATUS(yd_shard_compound_key_encode(five, 5, &k), YD_SHARD_INVALID_ARGUMENT);
    /* The first failing component in field order decides the status. */
    YDValue *abc = parse("abc"), *nul = parse("null");
    const YDValue *missing_first[] = {NULL, nul}, *null_first[] = {nul, NULL}, *second[] = {abc, NULL};
    STATUS(yd_shard_compound_key_encode(missing_first, 2, &k), YD_SHARD_MISSING_KEY);
    STATUS(yd_shard_compound_key_encode(null_first, 2, &k), YD_SHARD_UNSUPPORTED_KEY);
    STATUS(yd_shard_compound_key_encode(second, 2, &k), YD_SHARD_MISSING_KEY); CHECK(!k.length);
    yd_free(abc); yd_free(nul);
    STATUS(compound_status("[abc, null]"), YD_SHARD_UNSUPPORTED_KEY);
    STATUS(compound_status("[abc, 1.0]"), YD_SHARD_UNSUPPORTED_KEY);
    STATUS(compound_status("[abc, []]"), YD_SHARD_UNSUPPORTED_KEY);
    STATUS(compound_status("[abc, {}]"), YD_SHARD_UNSUPPORTED_KEY);
    YDValue overflow = {.type = YD_INT, .scalar = "9223372036854775808"};
    const YDValue *bad_int[] = {&overflow, NULL};
    STATUS(yd_shard_compound_key_encode(bad_int, 2, &k), YD_SHARD_INVALID_KEY);
    /* Integer spellings canonicalize per component, as in version 1. */
    YDShardKey a = compound_key("[1, x]"), b = compound_key("[0x1, x]");
    CHECK(a.length == b.length && !memcmp(a.bytes, b.bytes, a.length));
    /* Decoder: count bounds, unknown component types, values, versions. */
    a = compound_key("['abc', 1]");
    b = a; b.bytes[4] = 0; STATUS(yd_shard_key_decode(b.bytes, b.length, &k), YD_SHARD_INVALID_KEY);
    b = a; b.bytes[4] = 5; STATUS(yd_shard_key_decode(b.bytes, b.length, &k), YD_SHARD_INVALID_KEY);
    b = a; b.bytes[4] = 3; STATUS(yd_shard_key_decode(b.bytes, b.length, &k), YD_SHARD_INVALID_KEY);
    b = a; b.bytes[4] = 1; STATUS(yd_shard_key_decode(b.bytes, b.length, &k), YD_SHARD_INVALID_KEY);
    b = a; b.bytes[11] = 9; STATUS(yd_shard_key_decode(b.bytes, b.length, &k), YD_SHARD_UNSUPPORTED_KEY);
    b = a; b.bytes[3] = 3; STATUS(yd_shard_key_decode(b.bytes, b.length, &k), YD_SHARD_UNSUPPORTED_KEY);
    a = compound_key("[x, true]"); a.bytes[a.length - 1] = 2;
    STATUS(yd_shard_key_decode(a.bytes, a.length, &k), YD_SHARD_INVALID_KEY);
    a = compound_key("[x, y]"); a.bytes[a.length - 1] = 0xff;
    STATUS(yd_shard_key_decode(a.bytes, a.length, &k), YD_SHARD_INVALID_KEY); CHECK(!k.length);

    /* Metadata version 2 with an ordered compound field list. */
    YDShardPlacement *p = placement(compound_metadata); YDShardPlan plan;
    CHECK(yd_shard_placement_version(p) == 2 && yd_shard_placement_key_version(p) == 2);
    CHECK(yd_shard_placement_fields(p) == 2 && !yd_shard_placement_field(p));
    CHECK(!strcmp(yd_shard_placement_field_at(p, 0), "tenant"));
    CHECK(!strcmp(yd_shard_placement_field_at(p, 1), "profile.user"));
    CHECK(!yd_shard_placement_field_at(p, 2));
    size_t size = 0; unsigned char *encoded = yd_shard_placement_encode(p, &size); CHECK(encoded);
    CHECK(strstr((char *)encoded, "\"version\":2,\"key_version\":2,") &&
          strstr((char *)encoded, "\"field\":[\"tenant\",\"profile.user\"]"));
    YDShardPlacement *again = NULL;
    STATUS(yd_shard_placement_parse(encoded, size, &again), YD_SHARD_OK);
    size_t size2 = 0; unsigned char *encoded2 = yd_shard_placement_encode(again, &size2);
    CHECK(encoded2 && size2 == size && !memcmp(encoded, encoded2, size));
    free(encoded); free(encoded2); yd_shard_placement_free(again);
    /* Whole-partition moves keep the compound key and bump the epoch once. */
    YDShardPlacement *moved = NULL;
    STATUS(yd_shard_placement_move(p, "b", "raft-c", &moved), YD_SHARD_OK);
    CHECK(yd_shard_placement_epoch(moved) == 8 && yd_shard_placement_fields(moved) == 2 &&
          yd_shard_placement_key_version(moved) == 2);
    yd_shard_placement_free(moved);
    YDValue *doc = parse("tenant: abc\nprofile: {user: 1}\nvalue: 2"),
        *same = parse("{profile: {user: 0x1}, tenant: abc, value: 3}"),
        *changed = parse("tenant: abc\nprofile: {user: 2}"),
        *no_tenant = parse("profile: {user: 1}"), *no_user = parse("tenant: abc\nprofile: {}"),
        *null_tenant = parse("tenant: null\nprofile: {}"), *float_user = parse("tenant: abc\nprofile: {user: 1.5}"),
        *array_profile = parse("tenant: abc\nprofile: [{user: 1}]");
    STATUS(yd_shard_plan_document(p, placement_id, "records", 7, YD_SHARD_WRITE, doc, &plan), YD_SHARD_OK);
    CHECK(plan.token == UINT64_C(0xa3922b2478c730bb) && !strcmp(plan.shard, "b") && !strcmp(plan.group, "raft-b"));
    STATUS(yd_shard_document_key(p, doc, &k), YD_SHARD_OK);
    a = compound_key("['abc', 1]"); CHECK(k.length == a.length && !memcmp(k.bytes, a.bytes, a.length));
    STATUS(yd_shard_plan_document(p, placement_id, "records", 7, YD_SHARD_READ, no_tenant, &plan), YD_SHARD_MISSING_KEY);
    empty_plan(&plan);
    STATUS(yd_shard_plan_document(p, placement_id, "records", 7, YD_SHARD_READ, no_user, &plan), YD_SHARD_MISSING_KEY);
    STATUS(yd_shard_plan_document(p, placement_id, "records", 7, YD_SHARD_READ, null_tenant, &plan), YD_SHARD_UNSUPPORTED_KEY);
    STATUS(yd_shard_plan_document(p, placement_id, "records", 7, YD_SHARD_READ, float_user, &plan), YD_SHARD_UNSUPPORTED_KEY);
    STATUS(yd_shard_plan_document(p, placement_id, "records", 7, YD_SHARD_READ, array_profile, &plan), YD_SHARD_MISSING_KEY);
    STATUS(yd_shard_key_unchanged(p, doc, same), YD_SHARD_OK);
    STATUS(yd_shard_key_unchanged(p, doc, changed), YD_SHARD_KEY_CHANGE_UNSUPPORTED);
    STATUS(yd_shard_key_unchanged(p, doc, no_user), YD_SHARD_MISSING_KEY);
    yd_free(doc); yd_free(same); yd_free(changed); yd_free(no_tenant); yd_free(no_user);
    yd_free(null_tenant); yd_free(float_user); yd_free(array_profile);
    /* A key must match the placement's key version and component count. */
    YDShardKey wrong[3] = {key("'abc'"), compound_key("['abc']"), compound_key("['abc', 1, 2]")};
    for (size_t i = 0; i < 3; i++)
        STATUS(yd_shard_plan_keys(p, placement_id, "records", 7, YD_SHARD_READ, &wrong[i], 1, &plan), YD_SHARD_INVALID_KEY);
    YDShardKey right[2] = {compound_key("['abc', 1]"), compound_key("['abc', 1]")};
    STATUS(yd_shard_plan_keys(p, placement_id, "records", 7, YD_SHARD_TRANSACTION, right, 2, &plan), YD_SHARD_OK);
    YDValue *pair = parse("[abc, 1]"), *single = parse("[abc]"), *scalar = parse("abc");
    STATUS(yd_shard_placement_key(p, pair, &k), YD_SHARD_OK);
    CHECK(k.length == right[0].length && !memcmp(k.bytes, right[0].bytes, k.length));
    STATUS(yd_shard_placement_key(p, single, &k), YD_SHARD_INVALID_KEY);
    STATUS(yd_shard_placement_key(p, scalar, &k), YD_SHARD_INVALID_KEY);
    STATUS(yd_shard_placement_key(p, NULL, &k), YD_SHARD_MISSING_KEY);
    /* Unique indexes must start with the complete key, in order. */
    const char *full[] = {"tenant", "profile.user", "email"}, *reversed[] = {"profile.user", "tenant"},
        *partial[] = {"tenant", "email"};
    STATUS(yd_shard_unique_index(p, full, 2, false), YD_SHARD_OK);
    STATUS(yd_shard_unique_index(p, full, 3, false), YD_SHARD_OK);
    STATUS(yd_shard_unique_index(p, full, 1, false), YD_SHARD_CROSS_SHARD_UNSUPPORTED);
    STATUS(yd_shard_unique_index(p, reversed, 2, false), YD_SHARD_CROSS_SHARD_UNSUPPORTED);
    STATUS(yd_shard_unique_index(p, partial, 2, false), YD_SHARD_CROSS_SHARD_UNSUPPORTED);
    STATUS(yd_shard_unique_index(p, full, 3, true), YD_SHARD_CROSS_SHARD_UNSUPPORTED);
    yd_shard_placement_free(p);
    /* Version-1 placements reject version-2 keys and keep their own rules. */
    p = placement(metadata);
    STATUS(yd_shard_plan_keys(p, placement_id, "records", 7, YD_SHARD_READ, &one, 1, &plan), YD_SHARD_INVALID_KEY);
    STATUS(yd_shard_placement_key(p, pair, &k), YD_SHARD_UNSUPPORTED_KEY);
    STATUS(yd_shard_placement_key(p, scalar, &k), YD_SHARD_OK);
    yd_shard_placement_free(p); yd_free(pair); yd_free(single); yd_free(scalar);
    /* Version 2 with key_version 1 keeps the version-1 key bytes and tokens. */
    char *scalar_v2 = replace(compound_metadata, "key_version: 2", "key_version: 1");
    char *scalar_field = replace(scalar_v2, "[tenant, profile.user]", "profile.tenant"); free(scalar_v2);
    p = placement(scalar_field); free(scalar_field);
    CHECK(yd_shard_placement_version(p) == 2 && !strcmp(yd_shard_placement_field(p), "profile.tenant"));
    doc = parse(source);
    STATUS(yd_shard_plan_document(p, placement_id, "records", 7, YD_SHARD_READ, doc, &plan), YD_SHARD_OK);
    CHECK(plan.token == UINT64_C(0x8e8dbe51e84d01a0)); yd_free(doc); yd_shard_placement_free(p);
    const struct { const char *old, *replacement; YDShardStatus status; } cases[] = {
        {"[tenant, profile.user]", "[]", YD_SHARD_INVALID_METADATA},
        {"[tenant, profile.user]", "[a, b, c, d, e]", YD_SHARD_INVALID_METADATA},
        {"[tenant, profile.user]", "[tenant, tenant]", YD_SHARD_INVALID_METADATA},
        {"[tenant, profile.user]", "[profile, profile.user]", YD_SHARD_INVALID_METADATA},
        {"[tenant, profile.user]", "[profile.user, profile]", YD_SHARD_INVALID_METADATA},
        {"[tenant, profile.user]", "[tenant, profile..user]", YD_SHARD_INVALID_METADATA},
        {"[tenant, profile.user]", "[tenant, 1]", YD_SHARD_INVALID_METADATA},
        {"[tenant, profile.user]", "tenant", YD_SHARD_INVALID_METADATA},
        {"[tenant, profile.user]", "[[tenant]]", YD_SHARD_INVALID_METADATA},
        {"key_version: 2", "key_version: 3", YD_SHARD_UNSUPPORTED_METADATA},
        {"version: 2", "version: 3", YD_SHARD_UNSUPPORTED_METADATA},
        {"version: 2", "version: 1", YD_SHARD_UNSUPPORTED_METADATA},
    };
    for (size_t i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) {
        char *input = replace(compound_metadata, cases[i].old, cases[i].replacement);
        p = (YDShardPlacement *)(uintptr_t)1;
        STATUS(yd_shard_placement_parse((const unsigned char *)input, strlen(input), &p), cases[i].status);
        CHECK(p == NULL); free(input);
    }
    /* Prefix-sharing fields that are not path prefixes are distinct fields. */
    char *distinct = replace(compound_metadata, "[tenant, profile.user]", "[ab, abc, a, a.bc]");
    STATUS(yd_shard_placement_parse((const unsigned char *)distinct, strlen(distinct), &p), YD_SHARD_INVALID_METADATA);
    free(distinct);
    distinct = replace(compound_metadata, "[tenant, profile.user]", "[ab, abc, x.b, x.bc]");
    p = placement(distinct); CHECK(yd_shard_placement_fields(p) == 4); yd_shard_placement_free(p); free(distinct);
    puts("compound shard keys, version-2 metadata and prefix unique indexes passed");
}

/* Real native journal/tree persistence across separate harness processes. Store
 * the exact YAML and metadata as opaque records; no document APIs are changed. */
static void native(const char *directory, bool create) {
    char error[256] = {0};
    YDDisk *disk = yd_disk_open(directory, create, 32768, error, sizeof(error));
    if (!disk) fprintf(stderr, "%s\n", error);
    CHECK(disk);
    if (create) {
        YDDiskTxn *tx = yd_disk_begin(disk, error, sizeof(error)); CHECK(tx);
        uint64_t offset;
        CHECK(yd_disk_append(tx, metadata, strlen(metadata), &offset, error, sizeof(error)));
        CHECK(yd_disk_put(tx, "route-meta", 10, offset, error, sizeof(error)));
        CHECK(yd_disk_append(tx, source, strlen(source), &offset, error, sizeof(error)));
        CHECK(yd_disk_put(tx, "route-doc", 9, offset, error, sizeof(error)));
        CHECK(yd_disk_commit(tx, error, sizeof(error)));
    }
    YDDiskView view = yd_disk_view(disk); uint64_t offset; size_t n, m;
    CHECK(yd_disk_get(disk, &view, "route-meta", 10, &offset, error, sizeof(error)) == 1);
    unsigned char *raw_meta = yd_disk_record(disk, &view, offset, &n, error, sizeof(error)); CHECK(raw_meta);
    CHECK(n == strlen(metadata) && !memcmp(raw_meta, metadata, n));
    YDShardPlacement *p;
    STATUS(yd_shard_placement_parse(raw_meta, n, &p), YD_SHARD_OK);
    CHECK(yd_disk_get(disk, &view, "route-doc", 9, &offset, error, sizeof(error)) == 1);
    unsigned char *raw = yd_disk_record(disk, &view, offset, &m, error, sizeof(error)); CHECK(raw);
    CHECK(m == strlen(source) && !memcmp(raw, source, m));
    YDValue *v = yd_parse(raw, m, error, sizeof(error)); CHECK(v); YDShardPlan plan;
    STATUS(yd_shard_plan_document(p, placement_id, "records", 7, YD_SHARD_WRITE, v, &plan), YD_SHARD_OK);
    CHECK(plan.token == UINT64_C(0x8e8dbe51e84d01a0) && !strcmp(plan.shard, "b"));
    CHECK(!memcmp(raw, source, m) && !memcmp(raw_meta, metadata, n));
    printf("native route %s/%s epoch=%" PRIu64 " token=%016" PRIx64 " exact YAML preserved\n", plan.shard, plan.group, plan.epoch, plan.token);
    yd_free(v); free(raw); free(raw_meta); yd_shard_placement_free(p); yd_disk_close(disk);
}

/* Runnable local planning example: a bounded YAML/JSON envelope on stdin with
 * placement, placement_id, collection, epoch, document. Always plans a read.
 * Output contains validated identifiers only; no document/key payload is echoed. */
static int cli(void) {
    unsigned char input[YD_SHARD_METADATA_LIMIT + 1];
    size_t length = fread(input, 1, sizeof(input), stdin);
    if (length == sizeof(input) || ferror(stdin)) return 2;
    YDValue *v = yd_parse(input, length, NULL, 0); if (!v) return 2;
    const YDValue *meta = yd_get(v, "placement"), *id = yd_get(v, "placement_id"),
        *collection = yd_get(v, "collection"), *epoch = yd_get(v, "epoch");
    uint64_t epoch_bits = 0; size_t size = 0;
    char *json = meta ? yd_json(meta, &size) : NULL; YDShardPlacement *p = NULL; YDShardPlan plan = {0};
    YDShardStatus status = YD_SHARD_INVALID_ARGUMENT;
    if (json && id && id->type == YD_STRING && collection && collection->type == YD_STRING &&
        epoch && epoch->type == YD_INT && yd_integer_bits(epoch->scalar, &epoch_bits)) {
        status = yd_shard_placement_parse((unsigned char *)json, size, &p);
        if (status == YD_SHARD_OK) status = yd_shard_plan_document(p, id->scalar, collection->scalar,
            epoch_bits, YD_SHARD_READ, yd_get(v, "document"), &plan);
    }
    printf("{\"status\":\"%s\"", yd_shard_status_name(status));
    if (status == YD_SHARD_OK) printf(",\"shard\":\"%s\",\"group\":\"%s\",\"epoch\":%" PRIu64 ",\"token\":\"%016" PRIx64 "\"", plan.shard, plan.group, plan.epoch, plan.token);
    puts("}");
    yd_shard_placement_free(p); free(json); yd_free(v); return status == YD_SHARD_OK ? 0 : 2;
}
int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "--plan")) return cli();
    if (argc == 3 && !strcmp(argv[1], "--store")) { native(argv[2], true); return 0; }
    if (argc == 3 && !strcmp(argv[1], "--reopen")) { native(argv[2], false); return 0; }
    if (argc == 2 && !strcmp(argv[1], "--keys")) { keys(); return 0; }
    if (argc == 2 && !strcmp(argv[1], "--metadata")) { metadata_tests(); return 0; }
    if (argc == 2 && !strcmp(argv[1], "--routing")) { routing(); return 0; }
    if (argc == 2 && !strcmp(argv[1], "--compound")) { compound(); return 0; }
    if (argc != 1) return 2;
    keys(); metadata_tests(); routing(); compound(); return 0;
}
