/* Production-core fixture, not a daemon or replacement authorization layer.
 * Parent build: LIB_SOURCE + SECURITY_SOURCE + disk_policy_api.c + schema/
 * {policy_catalog,shape_compile,shape_check,policy_store,policy_receipt,
 * policy_admission}.c and profile-core additions. C17 strict flags, -Isrc,
 * pkg-config yaml-0.1/openssl flags, -pthread -lm (sanitizers at link too).
 * Every fixture directory/file is owned disposable input supplied by the test.
 */
#define _POSIX_C_SOURCE 200809L
#include "disk_policy_api.h"
#include "disk_documents.h"
#include "document_api.h"
#include "security/access.h"
#include "store.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static unsigned char *file_bytes(const char *path, size_t *length) {
    *length = 0;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    struct stat s;
    if (fd < 0) return NULL;
    if (fstat(fd, &s) || !S_ISREG(s.st_mode) || s.st_size < 0 ||
        (uint64_t)s.st_size > YD_LARGE_REQUEST_LIMIT) { close(fd); return NULL; }
    size_t size = (size_t)s.st_size, used = 0;
    unsigned char *bytes = malloc(size + 1);
    if (!bytes) { close(fd); return NULL; }
    while (used < size) {
        ssize_t n = read(fd, bytes + used, size - used);
        if (n <= 0) { free(bytes); close(fd); return NULL; }
        used += (size_t)n;
    }
    if (close(fd)) { free(bytes); return NULL; }
    bytes[size] = 0; *length = size; return bytes;
}

static const char *string(const YDValue *map, const char *key) {
    const YDValue *v = yd_get(map, key);
    return v && v->type == YD_STRING ? v->scalar : NULL;
}

static bool unhex(const char *text, unsigned char *bytes, size_t size) {
    if (!text || strlen(text) != 2 * size) return false;
    for (size_t i = 0; i < size; i++) {
        unsigned value = 0;
        for (unsigned j = 0; j < 2; j++) {
            unsigned char c = (unsigned char)text[2 * i + j];
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
            value = value * 16 + (c <= '9' ? (unsigned)(c - '0') : (unsigned)(c - 'a' + 10));
        }
        bytes[i] = (unsigned char)value;
    }
    return true;
}

static void hex_bytes(const void *data, size_t length) {
    const unsigned char *bytes = data;
    for (size_t i = 0; i < length; i++) printf("%02x", (unsigned)bytes[i]);
}

static void view_json(YDDisk *disk) {
    YDDiskView v = yd_disk_view(disk);
    printf("\"view\":[%u,%llu,%llu,%llu,%llu,%llu,%llu]", v.format,
        (unsigned long long)v.generation, (unsigned long long)v.root,
        (unsigned long long)v.documents, (unsigned long long)v.collections,
        (unsigned long long)v.bytes, (unsigned long long)v.revision);
}

static void disk_reply(YDDiskAPI *api, const YDDiskReply *reply) {
    printf("{\"status\":%d,\"body\":\"", reply->status);
    hex_bytes(reply->body, reply->length);
    printf("\",\"headers\":\""); hex_bytes(reply->headers, strlen(reply->headers));
    printf("\",\"content_type\":\"");
    if (reply->content_type) hex_bytes(reply->content_type, strlen(reply->content_type));
    printf("\",\"revision\":\"%s\",\"length\":%zu,\"stage\":%s,",
        reply->revision, reply->length, api->stage ? "true" : "false");
    view_json(api->disk); puts("}");
}

static YDValue *commands(const char *path) {
    size_t length = 0;
    unsigned char *bytes = file_bytes(path, &length);
    char error[256];
    YDValue *value = bytes ? yd_parse_sized(bytes, length, YD_LARGE_REQUEST_LIMIT,
        error, sizeof(error)) : NULL;
    free(bytes);
    if (value && value->type == YD_ARRAY) return value;
    yd_free(value); return NULL;
}

/* Only fixture session substitution; method/target/body still go through the
 * actual production dispatcher, parser, stage state and publication paths. */
static char *session_body(const char *body, const char *session) {
    const char *marker = body ? strstr(body, "$session") : NULL;
    if (!body) return NULL;
    if (!marker) return strdup(body);
    size_t before = (size_t)(marker - body), tail = strlen(marker + 8), n = strlen(session);
    char *copy = malloc(before + n + tail + 1);
    if (!copy) return NULL;
    memcpy(copy, body, before); memcpy(copy + before, session, n);
    memcpy(copy + before + n, marker + 8, tail + 1); return copy;
}

static int native_api(int argc, char **argv) {
    if (argc != 5) return 2;
    char error[256];
    bool replica = !strcmp(argv[3], "replica"), legacy = !strcmp(argv[3], "legacy");
    bool capabilities = !strcmp(argv[3], "caps");
    if (!replica && !legacy && !capabilities && strcmp(argv[3], "schema")) return 2;
    YDValue *list = commands(argv[4]);
    if (!list) return 2;
    YDDisk *disk = capabilities ? yd_disk_open_capabilities(argv[2], true,
        YD_DISK_CAP_SCHEMA, 1048576, error, sizeof(error)) :
        legacy ? yd_disk_open(argv[2], true, 1048576, error, sizeof(error)) :
        yd_disk_open_schema(argv[2], true, 1048576, error, sizeof(error));
    if (!disk) { yd_free(list); fprintf(stderr, "native open failed: %s\n", error); return 3; }
    YDDiskAPI api;
    if (!yd_disk_api_init(&api, disk, replica)) { yd_free(list); yd_disk_close(disk); return 3; }
    int status = 0;
    for (size_t i = 0; i < list->count; i++) {
        const YDValue *command = list->items[i];
        const char *method = string(command, "method"), *target = string(command, "target");
        const char *id = string(command, "request_id"), *wrapper = string(command, "wrapper");
        const char *source = string(command, "body");
        char *body = session_body(source, api.session);
        unsigned char request_id[16];
        if (!method || !target || (source && !body) ||
            (id && !unhex(id, request_id, sizeof(request_id)))) { free(body); status = 2; break; }
        const char *match = string(command, "if_match"), *none = string(command, "if_none_match");
        size_t length = body ? strlen(body) : 0;
        YDDiskReply reply;
        if (wrapper && !strcmp(wrapper, "old"))
            reply = yd_disk_api_request(&api, method, target, (unsigned char *)body,
                length, match, none, false);
        else if (wrapper && !strcmp(wrapper, "read_at")) {
            YDDiskView view = yd_disk_view(disk);
            reply = yd_disk_api_read_at(disk, &view, method, target, (unsigned char *)body,
                length, match, none, false);
        } else
            reply = yd_disk_api_request_with_id(&api, method, target, (unsigned char *)body,
                length, match, none, false, id ? request_id : NULL);
        disk_reply(&api, &reply); yd_disk_reply_free(&reply); free(body);
    }
    yd_disk_api_destroy(&api); yd_disk_close(disk); yd_free(list); return status;
}

/* Corruption/preservation fixture uses structural production primitives only;
 * it deliberately bypasses operational admission to create invalid metadata. */
static int raw_fixture(int argc, char **argv) {
    if (argc != 5) return 2;
    size_t length = 0;
    unsigned char *bytes = file_bytes(argv[4], &length);
    if (!bytes) return 2;
    char error[256];
    YDDisk *disk = yd_disk_open_schema(argv[2], true, 1048576, error, sizeof(error));
    if (!disk) { free(bytes); return 3; }
    YDDiskTxn *txn = yd_disk_begin_exclusive(disk, error, sizeof(error));
    bool valid = false;
    if (txn && !strcmp(argv[3], "catalog")) {
        YDDiskDocument old = {0}, fresh = {.body = bytes, .length = length};
        strcpy(fresh.collection, YD_POLICY_COLLECTION); strcpy(fresh.id, YD_POLICY_DOCUMENT);
        int found = yd_disk_document_tx_get(txn, fresh.collection, fresh.id, &old, error, sizeof(error));
        valid = found >= 0 && yd_disk_write_document(txn, found ? &old : NULL, &fresh, error, sizeof(error));
        yd_disk_document_free(&old);
    } else if (txn && !strcmp(argv[3], "receipt")) {
        unsigned char key[YD_POLICY_RECEIPT_KEY_SIZE] = {0, 'Y', 'S', 'P', 1};
        uint64_t offset = 0;
        valid = yd_disk_append(txn, bytes, length, &offset, error, sizeof(error)) &&
            yd_disk_put(txn, key, sizeof(key), offset, error, sizeof(error));
    }
    if (valid) valid = yd_disk_commit(txn, error, sizeof(error));
    else yd_disk_abort(txn);
    if (valid) { putchar('{'); view_json(disk); puts("}"); }
    yd_disk_close(disk); free(bytes); return valid ? 0 : 3;
}

static int legacy(int argc, char **argv) {
    if (argc < 4) return 2;
    char error[256];
    if (!strcmp(argv[3], "put") || !strcmp(argv[3], "delete")) {
        bool put = !strcmp(argv[3], "put"), published = false;
        if (argc != (put ? 7 : 6)) return 2;
        size_t length = 0;
        unsigned char *bytes = put ? file_bytes(argv[6], &length) : NULL;
        if (put && !bytes) return 2;
        bool valid = put ? yamldb_store_put(argv[2], argv[4], argv[5], bytes, length,
            &published, error, sizeof(error)) : yamldb_store_delete(argv[2], argv[4], argv[5],
            &published, error, sizeof(error));
        free(bytes);
        printf("{\"ok\":%s,\"published\":%s}\n", valid ? "true" : "false", published ? "true" : "false");
        return 0;
    }
    if (strcmp(argv[3], "engine") || (argc != 4 && argc != 5)) return 2;
    YamlDBSnapshot *snapshot = malloc(sizeof(*snapshot));
    if (!snapshot) return 3;
    if (!yamldb_snapshot_load(argv[2], snapshot, error, sizeof(error))) { free(snapshot); return 3; }
    pthread_rwlock_t lock;
    if (pthread_rwlock_init(&lock, NULL)) { yamldb_snapshot_free(snapshot); free(snapshot); return 3; }
    YDEngine engine;
    bool initialized = yd_engine_init(&engine, snapshot, argv[2], true, &lock, error, sizeof(error));
    printf("{\"initialized\":%s}\n", initialized ? "true" : "false");
    YDValue *list = initialized && argc == 5 ? commands(argv[4]) : NULL;
    int status = initialized && argc == 5 && !list ? 2 : 0;
    for (size_t i = 0; list && i < list->count; i++) {
        const YDValue *command = list->items[i];
        const char *method = string(command, "method"), *target = string(command, "target");
        const char *source = string(command, "body");
        char *body = session_body(source, engine.session);
        if (!method || !target || (source && !body)) { free(body); status = 2; break; }
        YDReply reply = yd_engine_request(&engine, method, target, (unsigned char *)body,
            body ? strlen(body) : 0, NULL, NULL);
        printf("{\"status\":%d,\"stage\":%s,\"revision\":\"%s\"}\n",
            reply.status, engine.staged ? "true" : "false", engine.snapshot->revision);
        yd_reply_free(&reply); free(body);
    }
    yd_free(list); yd_engine_destroy(&engine);
    yamldb_snapshot_free(engine.snapshot); free(engine.snapshot);
    pthread_rwlock_destroy(&lock); return status;
}

static int access_request(int argc, char **argv) {
    /* access POLICY token|foreign|certificate|oidc IDENTITY METHOD TARGET */
    if (argc != 7) return 2;
    char error[256];
    YDAccess *policy = yd_access_load(argv[2], error, sizeof(error));
    if (!policy) { fprintf(stderr, "access fixture policy refused\n"); return 3; }
    const YDAccessPrincipal *principal = NULL;
    YDAccess *foreign = NULL;
    unsigned char *identity = NULL;
    char *authorization = NULL;
    size_t length = 0;
    int authentication = 0, wrapped = -1;
    if (!strcmp(argv[3], "certificate")) {
        unsigned char pin[32];
        if (!unhex(argv[4], pin, sizeof(pin))) { yd_access_free(policy); return 2; }
        principal = yd_access_identify_certificate(policy, pin);
    } else {
        identity = file_bytes(argv[4], &length);
        if (!identity) { yd_access_free(policy); return 2; }
        if (!strcmp(argv[3], "oidc"))
            authentication = yd_access_authenticate_oidc(policy, (char *)identity, length,
                INT64_C(1900000000), &principal);
        else if (!strcmp(argv[3], "token") || !strcmp(argv[3], "foreign")) {
            if (!strcmp(argv[3], "foreign")) foreign = yd_access_load(argv[2], error, sizeof(error));
            if (!strcmp(argv[3], "foreign") && !foreign) {
                free(identity); yd_access_free(policy); return 3;
            }
            principal = yd_access_identify_token(foreign ? foreign : policy, (char *)identity, length);
            authorization = malloc(length + 8);
            if (!authorization) { free(identity); yd_access_free(foreign); yd_access_free(policy); return 3; }
            memcpy(authorization, "Bearer ", 7); memcpy(authorization + 7, identity, length + 1);
            wrapped = yd_access_request(policy, authorization, argv[5], argv[6], NULL, 0);
        } else { free(identity); yd_access_free(policy); return 2; }
    }
    int status = authentication ? authentication :
        yd_access_principal_request(policy, principal, argv[5], argv[6], NULL, 0);
    printf("{\"status\":%d,\"writer\":%s,\"wrapped\":%d}\n", status,
        yd_access_principal_writer(policy, principal) ? "true" : "false", wrapped);
    free(authorization); free(identity); yd_access_free(foreign); yd_access_free(policy); return 0;
}

int main(int argc, char **argv) {
    /* Match the explicit native constructor adoption requirement. This fixture
     * owns no other threads and retains the disabled state through close. */
    int previous;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous)) return 3;
    int result = 2;
    if (argc > 1 && !strcmp(argv[1], "api")) result = native_api(argc, argv);
    else if (argc > 1 && !strcmp(argv[1], "raw")) result = raw_fixture(argc, argv);
    else if (argc > 1 && !strcmp(argv[1], "legacy")) result = legacy(argc, argv);
    else if (argc > 1 && !strcmp(argv[1], "access")) result = access_request(argc, argv);
    else if (argc == 2 && !strcmp(argv[1], "statuses")) {
        printf("[%d,%d,%d,%d,%d,%d,%d,%d,%d]\n", yd_disk_policy_status(YD_POLICY_OK),
            yd_disk_policy_status(YD_POLICY_ABSENT), yd_disk_policy_status(YD_POLICY_INVALID),
            yd_disk_policy_status(YD_POLICY_UNSUPPORTED), yd_disk_policy_status(YD_POLICY_LIMIT),
            yd_disk_policy_status(YD_POLICY_CONFLICT), yd_disk_policy_status(YD_POLICY_REJECTED),
            yd_disk_policy_status(YD_POLICY_CORRUPT), yd_disk_policy_status(YD_POLICY_ERROR));
        result = 0;
    }
    if (pthread_setcancelstate(previous, NULL)) return 3;
    return result;
}
