#define _POSIX_C_SOURCE 200809L
#include "../src/schema/policy_admission.h"
#include "../src/disk_documents.h"
#include "../src/disk_internal.h"
#include "../src/store.h"
#include "../src/binary.h"
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

char policy_error[512];
#define REQUIRE(condition, label) do { if (!(condition)) { \
    fprintf(stderr, "%s: %s\n", label, policy_error); fflush(stderr); _Exit(2); } } while (0)

/* Deliberate fsync failures only start after an existing image was opened. */
int policy_sync_fail, policy_sync_calls;
int __real_fsync(int descriptor);
int __wrap_fsync(int descriptor) {
    if (policy_sync_fail && ++policy_sync_calls == policy_sync_fail) {
        errno = EIO;
        return -1;
    }
    return __real_fsync(descriptor);
}
YDDisk *policy_open(const char *root, bool writable) {
    int prior;
    REQUIRE(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &prior) == 0, "CANCEL_DISABLE");
    YDDisk *disk = yd_disk_open_schema(root, writable, 65536, policy_error, sizeof(policy_error));
    REQUIRE(pthread_setcancelstate(prior, NULL) == 0, "CANCEL_RESTORE");
    REQUIRE(disk != NULL, "OPERATIONAL_PROFILE7_OPEN");
    return disk;
}
YDPCChange policy_change(YDDiskTxn *txn, const char *collection, const char *source,
                         YDPolicyWork *work) {
    YDPolicyCatalog *catalog = NULL;
    bool present = false;
    REQUIRE(yd_policy_store_load(txn, work, &catalog, &present, policy_error,
                                sizeof(policy_error)) == YD_POLICY_OK, "LOAD_GUARD");
    YDPCInfo info;
    YDPCEntry entry;
    REQUIRE(yd_policy_catalog_info(catalog, &info) == YD_PC_OK, "CATALOG_INFO");
    YDPCChange change = {.collection = collection, .collection_length = strlen(collection),
        .operation = source ? YD_PC_SET : YD_PC_DISABLE,
        .source = (const unsigned char *)source, .source_length = source ? strlen(source) : 0,
        .expected = {.generation = info.generation}};
    memcpy(change.expected.catalog_sha256, info.catalog_sha256, 32);
    if (yd_policy_catalog_find(catalog, collection, strlen(collection), &entry) == YD_PC_OK)
        change.expected.version = entry.version;
    yd_policy_catalog_free(catalog);
    return change;
}
void policy_request(unsigned seed, const char *source, unsigned char id[16],
                     unsigned char digest[32]) {
    memset(id, 0, 16);
    id[0] = (unsigned char)seed;
    YDPolicyRequest request = {.method = source ? "PUT" : "DELETE",
        .target = "/v1/schema-policies/books", .if_none_match = "*",
        .body = (const unsigned char *)source, .length = source ? strlen(source) : 0};
    REQUIRE(yd_policy_request_digest(&request, digest, policy_error,
                                     sizeof(policy_error)) == YD_POLICY_OK, "REQUEST_DIGEST");
}
YDPolicyReply policy_reply(YDDiskTxn *txn, uint64_t version) {
    YDPolicyReply reply = {.status = 201, .length = 5};
    memcpy(reply.body, "a\0b\r\n", 5);
    memcpy(reply.content_type, "application/json; charset=utf-8", 32);
    (void)snprintf(reply.headers, sizeof(reply.headers), "ETag: \"%016llx\"\r\n",
                   (unsigned long long)version);
    yd_disk_revision(yd_disk_tx_view(txn), reply.revision);
    return reply;
}
YDPolicyReply policy_publish(YDDisk *disk, const char *source, unsigned seed) {
    YDPolicyWork work;
    yd_policy_work_init(&work, true);
    YDDiskTxn *txn = yd_disk_begin_exclusive(disk, policy_error, sizeof(policy_error));
    REQUIRE(txn != NULL, "EXCLUSIVE_BEGIN");
    YDPCChange change = policy_change(txn, "books", source, &work);
    YDPolicyCatalog *updated = NULL;
    REQUIRE(yd_policy_store_change(txn, &change, &work, &updated, policy_error,
                                  sizeof(policy_error)) == YD_POLICY_OK, "CATALOG_STAGE");
    YDPCEntry entry;
    REQUIRE(yd_policy_catalog_find(updated, "books", 5, &entry) == YD_PC_OK,
            "PUBLISHED_POLICY_VERSION");
    YDPolicyReply reply = policy_reply(txn, entry.version);
    yd_policy_catalog_free(updated);
    unsigned char id[16], digest[32];
    policy_request(seed, source, id, digest);
    REQUIRE(yd_policy_store_commit(txn, id, digest, &reply, policy_error,
                                  sizeof(policy_error)) == YD_POLICY_OK, "CATALOG_RECEIPT_COMMIT");
    return reply;
}
bool policy_same_view(YDDiskView a, YDDiskView b) {
    return a.format == b.format && a.generation == b.generation && a.root == b.root &&
        a.end == b.end && a.revision == b.revision && a.documents == b.documents &&
        a.collections == b.collections && a.bytes == b.bytes;
}
void policy_replay(YDDisk *disk, unsigned seed, const char *source, const YDPolicyReply *expected) {
    unsigned char id[16], digest[32];
    policy_request(seed, source, id, digest);
    YDDiskTxn *txn = yd_disk_begin_exclusive(disk, policy_error, sizeof(policy_error));
    REQUIRE(txn != NULL, "REPLAY_BEGIN");
    YDPolicyReply actual;
    REQUIRE(yd_policy_receipt_get(txn, id, digest, &actual, policy_error,
                                 sizeof(policy_error)) == YD_POLICY_OK, "DURABLE_ORIGINAL_REPLY");
    if (expected) REQUIRE(actual.status == expected->status &&
        actual.length == expected->length && !strcmp(actual.revision, expected->revision) &&
        !strcmp(actual.headers, expected->headers) &&
        !strcmp(actual.content_type, expected->content_type) &&
        !memcmp(actual.body, expected->body, actual.length), "EXACT_ORIGINAL_REPLY_BYTES");
    digest[0] ^= 1;
    REQUIRE(yd_policy_receipt_get(txn, id, digest, &actual, policy_error,
                                 sizeof(policy_error)) == YD_POLICY_CONFLICT, "REQUEST_ID_CONFLICT");
    REQUIRE(actual.status == 0 && actual.length == 0, "CONFLICT_CLEARS_OUTPUT");
    yd_disk_abort(txn);
}
int policy_store_case(const char *root, const char *scenario) {
    if (!strncmp(scenario, "legacy-", 7)) {
        if (!strcmp(scenario, "legacy-binary")) {
            YamlDBSnapshot empty = {0};
            REQUIRE(yd_binary_initialize(root, &empty, policy_error, sizeof(policy_error)),
                    "LEGACY_BINARY_INITIALIZE");
        }
        bool published = false;
        const char *ordinary = !strcmp(scenario, "legacy-system") ? "yamldb-system" : "books";
        REQUIRE(yamldb_store_put(root, ordinary, "existing", (const unsigned char *)"ok: true\n",
            9, &published, policy_error, sizeof(policy_error)) && published,
            "POLICY_FREE_LEGACY_WRITE_PRESERVED");
        REQUIRE(!yamldb_store_put(root, YD_POLICY_COLLECTION, YD_POLICY_DOCUMENT,
            (const unsigned char *)"{}\n", 3, &published, policy_error, sizeof(policy_error)),
            "LEGACY_FIRST_POLICY_CATALOG_REFUSED");
        REQUIRE(!published && strstr(policy_error, "schema policies require operational native storage"),
                "LEGACY_POLICY_REFUSAL_DIAGNOSTIC");
        char path[4096];
        REQUIRE(snprintf(path, sizeof(path), "%s/yamldb-system/schema-policies.%s", root,
            !strcmp(scenario, "legacy-binary") ? "ymdb" : "yaml") > 0,
            "LEGACY_POLICY_PATH");
        REQUIRE(access(path, F_OK) != 0 && errno == ENOENT, "LEGACY_POLICY_NOT_PUBLISHED");
        puts("legacy policy guard verified");
        return 0;
    }
    YDDisk *disk = policy_open(root, true);
    if (!strcmp(scenario, "digest")) {
        unsigned char id[16], digest[32];
        policy_request(1, "# exact CRLF\r\ntype: integer\r\n", id, digest);
        for (size_t i = 0; i < sizeof(digest); i++) printf("%02x", digest[i]);
        putchar('\n');
    } else if (!strcmp(scenario, "receipt")) {
        const char *source = "# exact CRLF\r\ntype: integer\r\n";
        const char *sources[] = {source, "type: number\n", NULL};
        YDPolicyReply originals[3];
        for (unsigned i = 0; i < 3; i++) {
            originals[i] = policy_publish(disk, sources[i], i + 1);
            char expected[64];
            (void)snprintf(expected, sizeof(expected), "ETag: \"%016llx\"\r\n",
                           (unsigned long long)(i + 1));
            REQUIRE(!strcmp(originals[i].headers, expected), "RECEIPT_ETAG_POLICY_VERSION");
        }
        for (unsigned i = 0; i < 3; i++) policy_replay(disk, i + 1, sources[i], &originals[i]);
        yd_disk_close(disk);
        disk = policy_open(root, true);
        for (unsigned i = 0; i < 3; i++) policy_replay(disk, i + 1, sources[i], &originals[i]);
    } else if (!strcmp(scenario, "budgets")) {
        YDPolicyWork work;
        yd_policy_work_init(&work, true);
        YDDiskView before = yd_disk_view(disk);
        YDDiskTxn *txn = yd_disk_begin_exclusive(disk, policy_error, sizeof(policy_error));
        REQUIRE(txn != NULL, "BUDGET_BEGIN");
        YDPCChange change = policy_change(txn, "books", "type: integer\n", &work);
        work.catalog.work_left = 0;
        YDPolicyCatalog *updated = NULL;
        REQUIRE(yd_policy_store_change(txn, &change, &work, &updated, policy_error,
            sizeof(policy_error)) == YD_POLICY_LIMIT && !updated, "CATALOG_POOL_FAIL_CLOSED");
        yd_disk_abort(txn);
        REQUIRE(policy_same_view(before, yd_disk_view(disk)), "CATALOG_BUDGET_NO_PUBLICATION");
    } else if (!strcmp(scenario, "mode")) {
        YDDiskTxn *txn = yd_disk_begin(disk, policy_error, sizeof(policy_error));
        REQUIRE(txn != NULL, "OPTIMISTIC_BEGIN");
        YDPolicyReply reply = policy_reply(txn, 1);
        unsigned char id[16], digest[32];
        policy_request(1, "type: integer\n", id, digest);
        REQUIRE(yd_policy_receipt_put(txn, id, digest, &reply, policy_error,
            sizeof(policy_error)) == YD_POLICY_UNSUPPORTED, "OPTIMISTIC_RECEIPT_REFUSED");
        yd_disk_abort(txn);
        txn = yd_disk_begin_exclusive(disk, policy_error, sizeof(policy_error));
        REQUIRE(txn != NULL, "RECEIPT_ONLY_BEGIN");
        reply = policy_reply(txn, 1);
        REQUIRE(yd_policy_store_commit(txn, id, digest, &reply, policy_error,
            sizeof(policy_error)) == YD_POLICY_INVALID, "RECEIPT_ONLY_PUBLICATION_REFUSED");
    } else if (!strcmp(scenario, "seed")) {
        policy_publish(disk, "type: integer\n", 1);
    } else if (!strcmp(scenario, "change")) {
        policy_publish(disk, "type: number\n", 2);
    } else if (!strcmp(scenario, "recovered")) {
        YDPolicyWork work;
        yd_policy_work_init(&work, false);
        YDPolicyCatalog *catalog = NULL;
        bool present;
        YDDiskView view = yd_disk_view(disk);
        REQUIRE(yd_policy_store_at(disk, &view, &work, &catalog, &present, policy_error,
            sizeof(policy_error)) == YD_POLICY_OK && present, "RECOVER_CATALOG");
        YDPCInfo info;
        REQUIRE(yd_policy_catalog_info(catalog, &info) == YD_PC_OK, "RECOVER_INFO");
        yd_policy_catalog_free(catalog);
        unsigned char id[16], digest[32];
        policy_request(2, "type: number\n", id, digest);
        YDDiskTxn *txn = yd_disk_begin_exclusive(disk, policy_error, sizeof(policy_error));
        REQUIRE(txn != NULL, "RECOVER_RECEIPT_BEGIN");
        YDPolicyReply reply;
        YDPolicyResult found = yd_policy_receipt_get(txn, id, digest, &reply, policy_error,
                                                    sizeof(policy_error));
        char revision[17];
        yd_disk_revision(&view, revision);
        REQUIRE((info.generation == 1 && found == YD_POLICY_ABSENT) ||
                (info.generation == 2 && found == YD_POLICY_OK &&
                    !strcmp(reply.revision, revision)), "CATALOG_RECEIPT_ATOMIC");
        printf("generation=%llu\n", (unsigned long long)info.generation);
        yd_disk_abort(txn);
    } else if (!strcmp(scenario, "fsync1") || !strcmp(scenario, "fsync2")) {
        YDPolicyWork work;
        yd_policy_work_init(&work, true);
        YDDiskTxn *txn = yd_disk_begin_exclusive(disk, policy_error, sizeof(policy_error));
        REQUIRE(txn != NULL, "FSYNC_BEGIN");
        YDPCChange change = policy_change(txn, "books", "type: number\n", &work);
        YDPolicyCatalog *updated = NULL;
        REQUIRE(yd_policy_store_change(txn, &change, &work, &updated, policy_error,
            sizeof(policy_error)) == YD_POLICY_OK, "FSYNC_STAGE");
        YDPCEntry entry;
        REQUIRE(yd_policy_catalog_find(updated, "books", 5, &entry) == YD_PC_OK,
                "FSYNC_POLICY_VERSION");
        YDPolicyReply reply = policy_reply(txn, entry.version);
        yd_policy_catalog_free(updated);
        unsigned char id[16], digest[32];
        policy_request(2, "type: number\n", id, digest);
        policy_sync_fail = scenario[5] - '0';
        REQUIRE(yd_policy_store_commit(txn, id, digest, &reply, policy_error,
            sizeof(policy_error)) == YD_POLICY_ERROR, "FSYNC_UNCERTAINTY_NOT_SUCCESS");
        policy_sync_fail = 0;
    } else REQUIRE(false, "UNKNOWN_SCENARIO");
    yd_disk_close(disk);
    puts("policy store scenario verified");
    return 0;
}
#ifndef YD_POLICY_HARNESS_LIBRARY
int main(int argc, char **argv) {
    if (argc != 3) return 3;
    return policy_store_case(argv[1], argv[2]);
}
#endif
