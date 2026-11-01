#define _POSIX_C_SOURCE 200809L
#include "consensus/application_internal.h"
#include "disk_internal.h"
#include "disk_replica.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char error[512];
#define REQUIRE(condition) do { if (!(condition)) { \
    fprintf(stderr, "line %u: %s (%s)\n", __LINE__, #condition, error); return 2; \
} } while (0)

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    const unsigned char cluster[16] = {1};
    YDRaftApplication *app = yd_raft_application_open(argv[1], cluster, 32768, error, sizeof(error));
    REQUIRE(app);
    YDDisk *disk = yd_raft_application_disk(app);
    YDDiskView before = yd_disk_view(disk);
    YDRaftWrite request = {.method = "PUT", .target = "/v1/schema-policies/items",
        .body = (const unsigned char *)"type: object\n", .size = 13, .id = {1}};
    YDRaftProposal proposal = {0};
    if (!strcmp(argv[2], "route")) {
        REQUIRE(yd_raft_application_prepare(app, &request, &proposal, error, sizeof(error)) == 0);
        REQUIRE(!proposal.command && proposal.reply.status == 405);
        REQUIRE(proposal.reply.body && strstr(proposal.reply.body, "schema_policy_cluster_unsupported"));
    } else {
        request.target = "/v1/collections/items/documents/a";
        request.body = (const unsigned char *)"n: 7\n";
        request.size = 5;
        if (!strcmp(argv[2], "error")) {
            /* Deliberate private fault: distinguish inaccessible state from
             * recognized unsupported state before any proposal is created. */
            disk->view.root = 1;
        } else {
            /* Inject forbidden state below the application API to exercise its
             * selection boundary. This is corruption, never supported writing. */
            const unsigned char catalog[] = "Dyamldb-system\0schema-policies";
            const unsigned char receipt[] = {0, 'Y', 'S', 'P', 1};
            const unsigned char *key = !strcmp(argv[2], "catalog") ? catalog : receipt;
            size_t size = !strcmp(argv[2], "catalog") ? sizeof(catalog) - 1 : sizeof(receipt);
            YDDiskTxn *txn = yd_disk_begin_exclusive(disk, error, sizeof(error));
            REQUIRE(txn);
            uint64_t record = 0;
            REQUIRE(yd_disk_append(txn, "x", 1, &record, error, sizeof(error)));
            REQUIRE(yd_disk_put(txn, key, size, record, error, sizeof(error)));
            REQUIRE(yd_disk_commit(txn, error, sizeof(error)));
        }
        YDDiskView current = yd_disk_view(disk);
        REQUIRE(yd_raft_application_prepare(app, &request, &proposal, error, sizeof(error)) == 0);
        REQUIRE(!proposal.command && proposal.reply.status == (!strcmp(argv[2], "error") ? 503 : 409));
        REQUIRE(proposal.reply.body && strstr(proposal.reply.body,
            !strcmp(argv[2], "error") ? "policy_state_unavailable" : "schema_policy_cluster_unsupported"));
        YDRaftCheckpoint expected = {.cluster = {1}};
        error[0] = 0;
        REQUIRE(!yd_raft_application_validate_at(disk, &expected, &current, error, sizeof(error)));
        REQUIRE(strstr(error, !strcmp(argv[2], "error") ? "consensus policy state unavailable" :
            "schema-policy consensus application unsupported"));
        if (!strcmp(argv[2], "error")) disk->view = before;
        else {
            yd_raft_application_close(app);
            app = NULL;
            error[0] = 0;
            app = yd_raft_application_open(argv[1], cluster, 32768, error, sizeof(error));
            REQUIRE(!app && strstr(error, "schema-policy consensus application unsupported"));
        }
    }
    yd_raft_proposal_free(&proposal);
    yd_raft_application_close(app);
    return 0;
}
