#define _POSIX_C_SOURCE 200809L
#include "consensus/application_internal.h"
#include "disk_internal.h"
#include "disk_policy_api.h"
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static char error[512], paths[3][4096];
static YDRaftApplication *apps[3];
static YDRaftProposal proposals[64];
static size_t count;
static const unsigned char cluster[16] = {1};
static bool sync_fault;
static unsigned sync_calls, sync_fail;
int __real_fsync(int);
int __wrap_fsync(int fd) {
    if (sync_fault && ++sync_calls == sync_fail) { errno = EIO; return -1; }
    return __real_fsync(fd);
}
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "consensus policy assertion line %u: %s (%s)\n", __LINE__, #x, error); return false; } } while (0)
static const char *shape = "type: object\nproperties: {value: {type: integer}}\nrequired: [value]\n";
static const char *number = "type: object\nproperties: {value: {type: number}}\nrequired: [value]\n";
static bool open_apps(const char *root, unsigned n) {
    for (unsigned i = 0; i < n; i++) {
        int size = snprintf(paths[i], sizeof(paths[i]), "%s/n%u", root, i);
        CHECK(size > 0 && (size_t)size < sizeof(paths[i]));
        CHECK(!mkdir(paths[i], 0700) || errno == EEXIST);
        apps[i] = yd_raft_application_open_capabilities(paths[i], cluster,
            YD_DISK_CAP_CLUSTER | YD_DISK_CAP_SCHEMA, 32768, error, sizeof(error));
        CHECK(apps[i]);
    }
    return true;
}
static YDRaftProposal *prepare(YDRaftApplication *app, const char *method,
    const char *target, const char *body, unsigned char id, const char *match,
    const char *none, int *result) {
    if (count == sizeof(proposals)/sizeof(*proposals)) return NULL;
    YDRaftWrite write = {.method = method, .target = target,
        .body = (const unsigned char *)body, .size = body ? strlen(body) : 0,
        .match = match, .none = none, .id = {id}};
    YDRaftProposal *proposal = &proposals[count++];
    *result = yd_raft_application_prepare(app, &write, proposal, error, sizeof(error));
    return proposal;
}
static YDRaftProposal *policy(YDRaftApplication *app, const char *source,
    unsigned char id, const char *match, int *result) {
    return prepare(app, "PUT", "/v1/schema-policies/items", source, id,
        match, match ? NULL : "*", result);
}
static bool apply(YDRaftApplication *app, YDRaftProposal *proposal, uint64_t index, uint64_t term) {
    YDRaftEntry entry = {.index = index, .term = term, .kind = YD_RAFT_COMMAND,
        .command = proposal->command, .size = proposal->size};
    return yd_raft_application_apply(app, &entry, error, sizeof(error));
}
static bool original_reply(const YDDiskReply *a, const YDDiskReply *b) {
    return a->status == b->status && !strcmp(a->revision, b->revision) &&
        !strcmp(a->headers, b->headers) && a->length == b->length &&
        (!a->length || !memcmp(a->body, b->body, a->length));
}
static bool basic(const char *root, const char *profile) {
    CHECK(open_apps(root, 3));
    const char *source = shape;
    if (!strcmp(profile, "json")) source = "{profile: yamora-json-schema-2020-12-v1, schema: {type: object, properties: {value: {type: integer}}, required: [value]}}";
    if (!strcmp(profile, "openapi")) source = "{profile: yamora-openapi-3.1-schema-v1, name: R, document: {openapi: 3.1.1, components: {schemas: {R: {type: object, properties: {value: {type: integer}}, required: [value]}}}}}";
    int result = 0;
    YDRaftProposal *first = policy(apps[0], source, 1, NULL, &result);
    CHECK(first && result == 1 && first->reply.status == 201);
    CHECK(first->size > 128 && !memcmp(first->command, "YDAPPL02", 8) &&
        !memcmp(first->command + 120, "YDADM01", 7) && first->command[127] == 3);
    for (unsigned i = 0; i < 3; i++) CHECK(apply(apps[i], first, 1, 1));
    YDRaftProposal *put = prepare(apps[0], "PUT", "/v1/collections/items/documents/a",
        "value: 7\n", 2, NULL, NULL, &result);
    CHECK(put && result == 1 && put->reply.status == 201);
    for (unsigned i = 0; i < 3; i++) CHECK(apply(apps[i], put, 2, 1));
    YDDiskView before = yd_disk_view(yd_raft_application_disk(apps[0]));
    YDRaftProposal *bad = prepare(apps[0], "PATCH", "/v1/collections/items/documents/a",
        "{$set: {value: wrong}}", 3, NULL, NULL, &result);
    CHECK(bad && result == 0 && bad->reply.status == 422 && !bad->command);
    CHECK(yd_disk_view(yd_raft_application_disk(apps[0])).root == before.root);
    YDRaftProposal *later = policy(apps[0], number, 4, "\"0000000000000001\"", &result);
    CHECK(later && result == 1 && later->reply.status == 200);
    for (unsigned i = 0; i < 3; i++) CHECK(apply(apps[i], later, 3, 2));
    for (unsigned i = 0; i < 3; i++) {
        yd_raft_application_close(apps[i]); apps[i] = NULL;
        apps[i] = yd_raft_application_open_capabilities(paths[i], cluster, 3, 32768, error, sizeof(error));
        CHECK(apps[i]);
        YDRaftProposal *retry = policy(apps[i], source, 1, NULL, &result);
        CHECK(retry && result == 0 && !retry->command && original_reply(&retry->reply, &first->reply));
        YDRaftProposal *conflict = policy(apps[i], "type: string\n", 1, NULL, &result);
        CHECK(conflict && result == 0 && conflict->reply.status == 409);
        /* Historical exact receipt does not re-run today's predecessor/CAS. */
        CHECK(apply(apps[i], first, 4, 2));
        CHECK(yd_raft_application_position(apps[i]).index == 4);
        YDRaftCheckpoint expected;
        YDDiskCheckpoint *image = yd_raft_application_checkpoint(apps[i], &expected, error, sizeof(error));
        CHECK(image && expected.capabilities == 3);
        YDDiskView captured = yd_disk_checkpoint_view(image);
        yd_disk_checkpoint_close(image);
        CHECK(yd_raft_application_validate(apps[i], &expected, &captured, error, sizeof(error)));
    }
    return true;
}
static bool tampered(const char *root, const char *mode) {
    CHECK(open_apps(root, 1));
    int result;
    YDRaftProposal *proposal = prepare(apps[0], "PUT", "/v1/collections/items/documents/a",
        "value: 7\n", 1, NULL, NULL, &result);
    CHECK(proposal && result == 1);
    uint64_t index = 1;
    if (!strcmp(mode, "receipt")) {
        CHECK(apply(apps[0], proposal, 1, 1));
        proposal->command[proposal->size - 1] ^= 1;
        index = 2;
    } else if (!strcmp(mode, "catalog")) proposal->command[88] ^= 1;
    else if (!strcmp(mode, "profile")) proposal->command[120] ^= 1;
    else if (!strcmp(mode, "capability")) proposal->command[127] = 1;
    else if (!strcmp(mode, "legacy")) {
        memcpy(proposal->command, "YDAPPL01", 8); memset(proposal->command + 88, 0, 40);
    } else if (!strcmp(mode, "stale")) {
        YDRaftProposal *next = prepare(apps[0], "PUT", "/v1/collections/items/documents/b",
            "value: 8\n", 2, NULL, NULL, &result);
        CHECK(next && result == 1 && apply(apps[0], next, 1, 1));
        index = 2;
    } else return false;
    YDDiskView before = yd_disk_view(yd_raft_application_disk(apps[0]));
    CHECK(!apply(apps[0], proposal, index, 2) && yd_raft_application_failed(apps[0]));
    YDDiskView after = yd_disk_view(yd_raft_application_disk(apps[0]));
    CHECK(after.root == before.root && after.revision == before.revision &&
        after.generation == before.generation && after.documents == before.documents);
    return true;
}
static bool consistent(YDRaftApplication *app, uint64_t *index) {
    YDDisk *disk = yd_raft_application_disk(app);
    YDDiskView view = yd_disk_view(disk);
    *index = yd_raft_application_position(app).index;
    CHECK(*index <= 1);
    const unsigned char catalog[] = "Dyamldb-system\0schema-policies";
    unsigned char policy_receipt[20] = {0, 'Y', 'S', 'P', 1}, raft_receipt[20] = {0, 'Y', 'R', 'R', 1};
    uint64_t ignored = 0;
    CHECK(yd_disk_get(disk, &view, catalog, sizeof(catalog)-1, &ignored, error, sizeof(error)) == (int)*index);
    CHECK(yd_disk_get(disk, &view, policy_receipt, sizeof(policy_receipt), &ignored, error, sizeof(error)) == (int)*index);
    CHECK(yd_disk_get(disk, &view, raft_receipt, sizeof(raft_receipt), &ignored, error, sizeof(error)) == (int)*index);
    return true;
}
static bool recover(const char *root) {
    CHECK(open_apps(root, 1));
    uint64_t index;
    CHECK(consistent(apps[0], &index));
    int result;
    YDRaftProposal *proposal = policy(apps[0], shape, 1, NULL, &result);
    CHECK(proposal && proposal->reply.status == 201 && result == (index ? 0 : 1));
    if (!index) CHECK(apply(apps[0], proposal, 1, 1));
    CHECK(consistent(apps[0], &index) && index == 1);
    YDRaftProposal *retry = policy(apps[0], shape, 1, NULL, &result);
    CHECK(retry && result == 0 && original_reply(&retry->reply, &proposal->reply));
    return true;
}
static bool fault(const char *root, const char *mode) {
    CHECK(open_apps(root, 1));
    int result;
    YDRaftProposal *proposal = policy(apps[0], shape, 1, NULL, &result);
    CHECK(proposal && result == 1 && proposal->reply.status == 201);
    if (!strncmp(mode, "kill", 4)) {
        CHECK(!setenv("YAMORA_DISK_KILL_AT", mode + 4, 1));
        (void)apply(apps[0], proposal, 1, 1);
        CHECK(false);
    }
    sync_fail = (unsigned)strtoul(mode + 4, NULL, 10); sync_calls = 0; sync_fault = true;
    CHECK(!apply(apps[0], proposal, 1, 1) && yd_raft_application_failed(apps[0]));
    sync_fault = false;
    yd_raft_application_close(apps[0]); apps[0] = NULL;
    return recover(root);
}
int main(int argc, char **argv) {
    int previous;
    if (argc != 3 || pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous)) return 2;
    bool valid;
    if (!strcmp(argv[2], "shape") || !strcmp(argv[2], "json") || !strcmp(argv[2], "openapi"))
        valid = basic(argv[1], argv[2]);
    else if (!strncmp(argv[2], "kill", 4) || !strncmp(argv[2], "sync", 4)) valid = fault(argv[1], argv[2]);
    else if (!strcmp(argv[2], "recover")) valid = recover(argv[1]);
    else valid = tampered(argv[1], argv[2]);
    for (size_t i = 0; i < count; i++) yd_raft_proposal_free(&proposals[i]);
    for (unsigned i = 0; i < 3; i++) yd_raft_application_close(apps[i]);
    (void)pthread_setcancelstate(previous, NULL);
    return valid ? 0 : 1;
}
