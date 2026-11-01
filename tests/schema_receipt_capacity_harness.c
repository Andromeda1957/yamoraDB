#define YD_POLICY_HARNESS_LIBRARY
#include "schema_policy_store_harness.c"
#include "../src/disk_policy_api.h"

static const char *sources[] = {"type: integer\n", "type: number\n", "type: string\n",
                                "type: boolean\n"};

static YDPolicyReply small_reply(YDDiskTxn *txn) {
    YDPolicyReply reply = {.status = 200, .length = 11, .content_type = "x"};
    memcpy(reply.body, "a\0b\r\n123456", 11);
    yd_disk_revision(yd_disk_tx_view(txn), reply.revision);
    return reply;
}

static YDPolicyReply publish_small(YDDisk *disk, unsigned seed) {
    YDPolicyWork work;
    yd_policy_work_init(&work, true);
    YDDiskTxn *txn = yd_disk_begin_exclusive(disk, policy_error, sizeof(policy_error));
    REQUIRE(txn, "SMALL_RECEIPT_BEGIN");
    YDPCChange change = policy_change(txn, "books", sources[seed - 1], &work);
    YDPolicyCatalog *updated = NULL;
    REQUIRE(yd_policy_store_change(txn, &change, &work, &updated, policy_error,
        sizeof(policy_error)) == YD_POLICY_OK, "SMALL_RECEIPT_STAGE");
    yd_policy_catalog_free(updated);
    YDPolicyReply reply = small_reply(txn);
    unsigned char id[16], digest[32];
    policy_request(seed, sources[seed - 1], id, digest);
    REQUIRE(yd_policy_store_commit(txn, id, digest, &reply, policy_error,
        sizeof(policy_error)) == YD_POLICY_OK, "INCLUSIVE_BYTE_CAP_ADMITS");
    return reply; /* Exactly 88 + 1 + 11 = 100 encoded bytes. */
}

static void refuses_publication(YDDisk *disk) {
    YDDiskView before = yd_disk_view(disk);
    struct stat physical_before, physical_after;
    REQUIRE(!fstat(disk->fd, &physical_before), "BEFORE_PHYSICAL_SIZE");
    unsigned char id[16] = {99};
    YDDiskReply reply = yd_disk_policy_api_request(disk, &before, "PUT",
        "/v1/schema-policies/books", (const unsigned char *)sources[3], strlen(sources[3]),
        "\"0000000000000003\"", NULL, id);
    REQUIRE(reply.status == 413 && strstr((const char *)reply.body, "policy_receipt_capacity"),
            "FULL_NAMESPACE_REFUSES_NEW_ID_BEFORE_EFFECTS");
    yd_disk_reply_free(&reply);
    REQUIRE(policy_same_view(before, yd_disk_view(disk)), "FULL_NO_PUBLICATION");
    REQUIRE(!fstat(disk->fd, &physical_after) &&
        physical_after.st_size == physical_before.st_size, "FULL_NO_PRIVATE_APPEND");
}

int main(int argc, char **argv) {
    if (argc != 3 || chmod(argv[1], 0700)) return 3;
    YDDisk *disk = policy_open(argv[1], true);
    if (!strcmp(argv[2], "count") || !strcmp(argv[2], "bytes")) {
        bool small = !strcmp(argv[2], "bytes");
        YDPolicyReply originals[3];
        for (unsigned i = 0; i < 3; i++)
            originals[i] = small ? publish_small(disk, i + 1) :
                                  policy_publish(disk, sources[i], i + 1);
        refuses_publication(disk);
        yd_disk_close(disk);
        disk = policy_open(argv[1], true);
        for (unsigned i = 0; i < 3; i++) policy_replay(disk, i + 1, sources[i], &originals[i]);
        refuses_publication(disk);
    } else if (!strcmp(argv[2], "private")) {
        YDDiskView before = yd_disk_view(disk);
        YDDiskTxn *txn = yd_disk_begin_exclusive(disk, policy_error, sizeof(policy_error));
        REQUIRE(txn, "PRIVATE_BEGIN");
        for (unsigned i = 1; i <= 4; i++) {
            unsigned char id[16], digest[32];
            policy_request(i, sources[i - 1], id, digest);
            YDPolicyReply reply = YD_POLICY_RECEIPT_BYTES_LIMIT == 300 ?
                small_reply(txn) : policy_reply(txn, i);
            YDPolicyResult result = yd_policy_receipt_put(txn, id, digest, &reply,
                policy_error, sizeof(policy_error));
            REQUIRE(result == (i <= 3 ? YD_POLICY_OK : YD_POLICY_LIMIT),
                    "PRIVATE_RECEIPTS_SHARE_ONE_CAP");
        }
        REQUIRE(txn->failed, "FULL_NATIVE_INSERT_POISONS_TRANSACTION");
        yd_disk_abort(txn);
        REQUIRE(policy_same_view(before, yd_disk_view(disk)), "PRIVATE_FAILURE_NO_PUBLICATION");
    } else if (!strcmp(argv[2], "seed-overset")) {
        for (unsigned i = 1; i <= 4; i++) policy_publish(disk, sources[i - 1], i);
    } else if (!strcmp(argv[2], "overset")) {
        for (unsigned i = 1; i <= 4; i++) policy_replay(disk, i, sources[i - 1], NULL);
        YDDiskView before = yd_disk_view(disk);
        unsigned char id[16] = {99};
        YDDiskReply reply = yd_disk_policy_api_request(disk, &before, "PUT",
            "/v1/schema-policies/books", (const unsigned char *)sources[0], strlen(sources[0]),
            "\"0000000000000004\"", NULL, id);
        REQUIRE(reply.status == 413, "LEGACY_OVERSET_CANNOT_GROW");
        yd_disk_reply_free(&reply);
        REQUIRE(policy_same_view(before, yd_disk_view(disk)), "OVERSET_PRESERVED");
    } else REQUIRE(false, "UNKNOWN_CAPACITY_SCENARIO");
    yd_disk_close(disk);
    puts("schema receipt capacity verified");
    return 0;
}
