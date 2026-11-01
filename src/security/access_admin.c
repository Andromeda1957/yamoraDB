#define _POSIX_C_SOURCE 200809L
#include "access_admin.h"
#include "access_internal.h"
#include "access_state.h"
#include "access_store.h"
#include "audit.h"
#include "../consensus/cluster_internal.h"
#include "../disk_documents.h"
#include <errno.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define JSON_TYPE "application/json; charset=utf-8"
#define NO_STORE "Cache-Control: no-store\r\n"
#define REFRESH_MS 250
#define FORCED_EVERY 20U
#define TOKEN_MINIMUM 32U
#define TOKEN_MAXIMUM 512U

struct YDAccessAdmin {
    YDAccessAdminConfig config;
    pthread_mutex_t sync_lock;
    const YDDisk *disk;
    uint64_t generation, record;
    unsigned char digest[32];
    bool synced, failure_reported;
    pthread_mutex_t stop_lock;
    pthread_cond_t stop_signal;
    bool stopping, started;
    pthread_t thread;
};
typedef enum { SYNC_OK, SYNC_INVALID, SYNC_UNAVAILABLE } SyncResult;

bool yd_access_admin_target(const char *target) {
    return target && (!strcmp(target, "/v1/access") || !strncmp(target, "/v1/access/", 11));
}
int yd_access_admin_operation(const char *method, const char *target, char name[129]) {
    return (int)yd_access_state_target(method, target, name);
}
uint32_t yd_access_admin_audit(const char *method, const char *target, char subject[129]) {
    char name[129];
    subject[0] = 0;
    uint32_t operation;
    switch (yd_access_state_target(method, target, name)) {
    case YD_ACCESS_ROLE_PUT: operation = YD_AUDIT_ACCESS_ROLE_PUT; break;
    case YD_ACCESS_ROLE_DELETE: operation = YD_AUDIT_ACCESS_ROLE_DELETE; break;
    case YD_ACCESS_PRINCIPAL_PUT: operation = YD_AUDIT_ACCESS_PRINCIPAL_PUT; break;
    case YD_ACCESS_PRINCIPAL_ROTATE: operation = YD_AUDIT_ACCESS_PRINCIPAL_ROTATE; break;
    case YD_ACCESS_PRINCIPAL_DELETE: operation = YD_AUDIT_ACCESS_PRINCIPAL_DELETE; break;
    default:
        return method && !strcmp(method, "GET") ? YD_AUDIT_LIST : YD_AUDIT_WRITE_DOCUMENT;
    }
    memcpy(subject, name, strlen(name) + 1);
    return operation;
}
/* Caller holds sync_lock. Publishes only a newer or changed document. */
static SyncResult sync_locked(YDAccessAdmin *admin, YDDisk *disk, const YDDiskView *view,
    bool force) {
    if (!force && admin->synced && admin->disk == disk && view->generation <= admin->generation)
        return SYNC_OK;
    uint64_t record = 0;
    int present = yd_access_store_record(disk, view, &record);
    if (present < 0) return SYNC_UNAVAILABLE;
    if (!force && admin->synced && admin->disk == disk && record == admin->record) {
        admin->generation = view->generation;
        return SYNC_OK;
    }
    YDAccessState *state = NULL;
    unsigned char digest[32];
    if (yd_access_store_read(disk, view, &state, digest) < 0) return SYNC_INVALID;
    char error[256];
    bool same = admin->synced && !CRYPTO_memcmp(digest, admin->digest, 32);
    bool published = same ||
        yd_access_runtime_publish(admin->config.access, state, error, sizeof(error));
    yd_access_state_free(state);
    if (!published) return SYNC_INVALID;
    admin->disk = disk;
    admin->generation = view->generation;
    admin->record = record;
    memcpy(admin->digest, digest, 32);
    admin->synced = true;
    admin->failure_reported = false;
    return SYNC_OK;
}
static SyncResult refresh_view(YDAccessAdmin *admin, bool confirmed, bool force) {
    SyncResult result = SYNC_UNAVAILABLE;
    if (admin->config.cluster) {
        YDRaftView *view = NULL;
        if (confirmed) {
            unsigned timeout = admin->config.timeout_ms;
            view = yd_raft_cluster_view(admin->config.cluster,
                timeout && timeout < 2000 ? timeout : 2000);
        }
        /* Followers have no leadership proof; they enforce their applied state. */
        if (!view) view = yd_raft_cluster_local_view(admin->config.cluster);
        if (!view) return SYNC_UNAVAILABLE;
        YDDiskView value = yd_raft_view_value(view);
        pthread_mutex_lock(&admin->sync_lock);
        result = sync_locked(admin, yd_raft_view_disk(view), &value, force);
        pthread_mutex_unlock(&admin->sync_lock);
        yd_raft_view_close(view);
        return result;
    }
    if (!admin->config.disk) return SYNC_UNAVAILABLE;
    YDDiskView value = yd_disk_view(admin->config.disk);
    pthread_mutex_lock(&admin->sync_lock);
    result = sync_locked(admin, admin->config.disk, &value, force);
    pthread_mutex_unlock(&admin->sync_lock);
    return result;
}
/* An unreadable or invalid stored state disables every runtime principal. */
static void fail_closed(YDAccessAdmin *admin) {
    YDAccessState *empty = yd_access_state_new();
    char error[256];
    pthread_mutex_lock(&admin->sync_lock);
    if (empty) (void)yd_access_runtime_publish(admin->config.access, empty, error, sizeof(error));
    admin->synced = false;
    bool report = !admin->failure_reported;
    admin->failure_reported = true;
    pthread_mutex_unlock(&admin->sync_lock);
    yd_access_state_free(empty);
    if (report)
        fprintf(stderr, "yamora: runtime access state is unavailable or invalid; "
            "runtime principals are disabled\n");
}
void yd_access_admin_refresh(YDAccessAdmin *admin, bool confirmed) {
    if (admin && refresh_view(admin, confirmed, false) != SYNC_OK) fail_closed(admin);
}
YDAccessAdmin *yd_access_admin_open(const YDAccessAdminConfig *config, char *error,
    size_t length) {
    if (!config || !config->access || !yd_access_runtime_enabled(config->access) ||
        (!config->disk == !config->cluster)) {
        snprintf(error, length, "runtime access requires native storage");
        return NULL;
    }
    YDAccessAdmin *admin = calloc(1, sizeof(*admin));
    if (!admin) {
        snprintf(error, length, "cannot allocate runtime access state");
        return NULL;
    }
    admin->config = *config;
    bool locks = !pthread_mutex_init(&admin->sync_lock, NULL);
    if (locks && pthread_mutex_init(&admin->stop_lock, NULL)) {
        (void)pthread_mutex_destroy(&admin->sync_lock);
        locks = false;
    }
    if (locks && pthread_cond_init(&admin->stop_signal, NULL)) {
        (void)pthread_mutex_destroy(&admin->stop_lock);
        (void)pthread_mutex_destroy(&admin->sync_lock);
        locks = false;
    }
    if (!locks) {
        free(admin);
        snprintf(error, length, "cannot initialize runtime access locks");
        return NULL;
    }
    SyncResult result = refresh_view(admin, false, true);
    /* A replica-set member may start before its application is readable. It
     * serves with no runtime principal until the refresh worker loads them. */
    if (result == SYNC_UNAVAILABLE && config->cluster) result = SYNC_OK;
    bool conflict = result == SYNC_OK &&
        ((config->read_token && yd_access_conflicts(config->access, config->read_token,
            config->read_length)) ||
         (config->write_token && yd_access_conflicts(config->access, config->write_token,
            config->write_length)));
    if (result != SYNC_OK || conflict) {
        snprintf(error, length, result == SYNC_UNAVAILABLE ?
            "runtime access state is unavailable" :
            "runtime access state is invalid or conflicts with the static policy or "
            "administrative tokens");
        YDAccessState *empty = yd_access_state_new();
        char ignored[64];
        if (empty) (void)yd_access_runtime_publish(config->access, empty, ignored, sizeof(ignored));
        yd_access_state_free(empty);
        admin->started = false;
        yd_access_admin_close(admin);
        return NULL;
    }
    return admin;
}
static void *watch(void *context) {
    YDAccessAdmin *admin = context;
    int ignored;
    (void)pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &ignored);
    unsigned tick = 0;
    pthread_mutex_lock(&admin->stop_lock);
    while (!admin->stopping) {
        pthread_mutex_unlock(&admin->stop_lock);
        bool force = ++tick % FORCED_EVERY == 0;
        if (refresh_view(admin, false, force) != SYNC_OK) fail_closed(admin);
        struct timespec until;
        (void)clock_gettime(CLOCK_REALTIME, &until);
        until.tv_nsec += (long)REFRESH_MS * 1000000L;
        if (until.tv_nsec >= 1000000000L) { until.tv_sec++; until.tv_nsec -= 1000000000L; }
        pthread_mutex_lock(&admin->stop_lock);
        while (!admin->stopping &&
            pthread_cond_timedwait(&admin->stop_signal, &admin->stop_lock, &until) != ETIMEDOUT) {
        }
    }
    pthread_mutex_unlock(&admin->stop_lock);
    return NULL;
}
bool yd_access_admin_start(YDAccessAdmin *admin) {
    if (!admin || admin->started) return false;
    admin->started = pthread_create(&admin->thread, NULL, watch, admin) == 0;
    return admin->started;
}
void yd_access_admin_close(YDAccessAdmin *admin) {
    if (!admin) return;
    if (admin->started) {
        pthread_mutex_lock(&admin->stop_lock);
        admin->stopping = true;
        pthread_cond_broadcast(&admin->stop_signal);
        pthread_mutex_unlock(&admin->stop_lock);
        (void)pthread_join(admin->thread, NULL);
    }
    (void)pthread_cond_destroy(&admin->stop_signal);
    (void)pthread_mutex_destroy(&admin->stop_lock);
    (void)pthread_mutex_destroy(&admin->sync_lock);
    OPENSSL_cleanse(admin, sizeof(*admin));
    free(admin);
}

typedef struct {
    char *data;
    size_t length, capacity, limit;
    bool failed;
} Buffer;
static void append(Buffer *b, const char *text, size_t n) {
    if (b->failed) return;
    if (n > b->limit - b->length) { b->failed = true; return; }
    if (b->length + n + 1 > b->capacity) {
        size_t capacity = b->capacity ? b->capacity : 1024;
        while (capacity < b->length + n + 1) capacity *= 2;
        char *next = realloc(b->data, capacity);
        if (!next) { b->failed = true; return; }
        b->data = next;
        b->capacity = capacity;
    }
    memcpy(b->data + b->length, text, n);
    b->length += n;
    b->data[b->length] = 0;
}
static void text(Buffer *b, const char *s) { append(b, s, strlen(s)); }
static void quoted(Buffer *b, const char *s) { text(b, "\""); text(b, s); text(b, "\""); }
static void value(Buffer *b, const YDValue *v) {
    size_t n = 0;
    char *json = yd_json_sized(v, &n, YD_ACCESS_COMMAND_BYTES);
    if (!json) { b->failed = true; return; }
    append(b, json, n);
    free(json);
}
static void buffer_free(Buffer *b) {
    if (b->data) OPENSSL_cleanse(b->data, b->capacity);
    free(b->data);
    memset(b, 0, sizeof(*b));
}
static YDDiskReply json_reply(int status, Buffer *b, const YDDiskView *view) {
    YDDiskReply reply = {.status = status, .content_type = JSON_TYPE};
    if (b->failed || !b->data) {
        buffer_free(b);
        return yd_disk_error_reply(503, "serialization_failed");
    }
    reply.body = b->data;
    reply.length = b->length;
    b->data = NULL;
    memcpy(reply.headers, NO_STORE, sizeof(NO_STORE));
    if (view) yd_disk_revision(view, reply.revision);
    return reply;
}
static YDDiskReply error_reply(int status, const char *code, YDDiskOutcome outcome) {
    YDDiskReply reply = yd_disk_error_reply(status, code);
    memcpy(reply.headers, NO_STORE, sizeof(NO_STORE));
    reply.outcome = outcome;
    return reply;
}
static void names(Buffer *b, char items[][129], size_t count) {
    text(b, "[");
    for (size_t i = 0; i < count; i++) {
        if (i) text(b, ",");
        quoted(b, items[i]);
    }
    text(b, "]");
}
static void static_roles(Buffer *b, const YDAccess *a, uint64_t mask) {
    text(b, "[");
    bool first = true;
    for (size_t i = 0; i < a->role_count; i++)
        if (mask & (UINT64_C(1) << i)) {
            if (!first) text(b, ",");
            first = false;
            quoted(b, a->roles[i].name);
        }
    text(b, "]");
}
static YDDiskReply list(YDAccessAdmin *admin) {
    YDRaftView *owned = NULL;
    YDDisk *disk = admin->config.disk;
    YDDiskView view;
    if (admin->config.cluster) {
        owned = yd_raft_cluster_view(admin->config.cluster,
            admin->config.timeout_ms ? admin->config.timeout_ms : 3000);
        if (!owned) return error_reply(503, "cluster_unavailable", YD_DISK_OUTCOME_NOT_DISPATCHED);
        disk = yd_raft_view_disk(owned);
        view = yd_raft_view_value(owned);
    } else {
        view = yd_disk_view(disk);
    }
    YDAccessState *state = NULL;
    unsigned char digest[32];
    int found = yd_access_store_read(disk, &view, &state, digest);
    OPENSSL_cleanse(digest, sizeof(digest));
    if (found < 0) {
        yd_raft_view_close(owned);
        return error_reply(503, "access_state_unavailable", YD_DISK_OUTCOME_NOT_DISPATCHED);
    }
    const YDAccess *a = admin->config.access;
    Buffer b = {.limit = YD_LARGE_DOCUMENT_LIMIT};
    char number[32];
    time_t now = time(NULL);
    snprintf(number, sizeof(number), "%llu", (unsigned long long)state->version);
    text(&b, "{\"runtime_access\":true,\"version\":");
    text(&b, number);
    text(&b, ",\"roles\":[");
    bool first = true;
    for (size_t i = 0; i < a->role_count; i++) {
        if (!first) text(&b, ",");
        first = false;
        text(&b, "{\"name\":");
        quoted(&b, a->roles[i].name);
        text(&b, ",\"source\":\"file\",\"read\":");
        names(&b, (char (*)[129])a->roles[i].read, a->roles[i].reads);
        text(&b, ",\"write\":");
        names(&b, (char (*)[129])a->roles[i].write, a->roles[i].writes);
        text(&b, "}");
    }
    for (size_t i = 0; i < state->role_count; i++) {
        const YDAccessStateRole *r = &state->roles[i];
        if (!first) text(&b, ",");
        first = false;
        text(&b, "{\"name\":");
        quoted(&b, r->name);
        text(&b, ",\"source\":\"runtime\",\"read\":");
        names(&b, (char (*)[129])r->read, r->reads);
        text(&b, ",\"write\":");
        names(&b, (char (*)[129])r->write, r->writes);
        text(&b, "}");
    }
    text(&b, "],\"principals\":[");
    first = true;
    for (size_t i = 0; i < a->principal_count; i++) {
        const YDAccessPrincipal *p = &a->principals[i];
        if (!first) text(&b, ",");
        first = false;
        text(&b, "{\"name\":");
        quoted(&b, p->name);
        text(&b, ",\"source\":\"file\",\"roles\":");
        static_roles(&b, a, p->roles);
        text(&b, ",\"credential\":");
        quoted(&b, p->token ? "token" : p->certificate_count ? "certificate" : "external");
        text(&b, p->fields ? ",\"field_permissions\":true}" : ",\"field_permissions\":false}");
    }
    for (size_t i = 0; i < state->principal_count; i++) {
        const YDAccessStatePrincipal *p = &state->principals[i];
        if (!first) text(&b, ",");
        first = false;
        text(&b, "{\"name\":");
        quoted(&b, p->name);
        text(&b, ",\"source\":\"runtime\",\"roles\":");
        names(&b, (char (*)[129])p->roles, p->role_count);
        text(&b, ",\"credential\":\"token\",\"field_permissions\":");
        text(&b, p->fields ? "true" : "false");
        if (p->previous_expires_at && now != (time_t)-1 && (int64_t)now < p->previous_expires_at) {
            snprintf(number, sizeof(number), "%lld", (long long)p->previous_expires_at);
            text(&b, ",\"previous_expires_at\":");
            text(&b, number);
        }
        text(&b, "}");
    }
    text(&b, "]}\n");
    yd_access_state_free(state);
    YDDiskReply reply = json_reply(200, &b, &view);
    reply.outcome = YD_DISK_OUTCOME_RETURNED_SUCCESS;
    yd_raft_view_close(owned);
    return reply;
}
static const char *string(const YDValue *v) {
    return v && v->type == YD_STRING ? v->scalar : NULL;
}
static bool only(const YDValue *map, const char *const *keys, size_t count) {
    if (!map || map->type != YD_MAP) return false;
    for (size_t i = 0; i < map->count; i++) {
        size_t j = 0;
        while (j < count && strcmp(map->keys[i], keys[j])) j++;
        if (j == count) return false;
    }
    return true;
}
static bool token_profile(const char *token) {
    size_t n = token ? strnlen(token, TOKEN_MAXIMUM + 1) : 0;
    if (n < TOKEN_MINIMUM || n > TOKEN_MAXIMUM) return false;
    for (size_t i = 0; i < n; i++)
        if ((unsigned char)token[i] < 0x21 || (unsigned char)token[i] > 0x7e) return false;
    return true;
}
/* 256 random bits, base64url without padding, behind a scannable prefix. */
static bool generate(char out[48]) {
    unsigned char raw[32], encoded[48];
    bool valid = RAND_bytes(raw, sizeof(raw)) == 1 &&
        EVP_EncodeBlock(encoded, raw, sizeof(raw)) == 44;
    if (valid) {
        memcpy(out, "yrt_", 4);
        for (size_t i = 0; i < 43; i++)
            out[4 + i] = encoded[i] == '+' ? '-' : encoded[i] == '/' ? '_' : (char)encoded[i];
        out[47] = 0;
    }
    OPENSSL_cleanse(raw, sizeof(raw));
    OPENSSL_cleanse(encoded, sizeof(encoded));
    return valid;
}
typedef struct {
    char token[TOKEN_MAXIMUM + 1];
    size_t token_length;
    bool generated, present;
    unsigned char verifier[32];
} Credential;
static void credential_clear(Credential *c) { OPENSSL_cleanse(c, sizeof(*c)); }
/* The parsed request may hold a token: clear every string before release. */
static void wipe_strings(YDValue *v) {
    if (!v) return;
    if (v->scalar) OPENSSL_cleanse(v->scalar, strlen(v->scalar));
    for (size_t i = 0; i < v->count; i++) {
        if (v->type == YD_MAP && v->keys && v->keys[i])
            OPENSSL_cleanse(v->keys[i], strlen(v->keys[i]));
        if (v->items) wipe_strings(v->items[i]);
    }
}
static void spec_free(YDValue *spec) {
    wipe_strings(spec);
    yd_free(spec);
}
/* 0 or an HTTP status. Produces a verifier; the token itself never leaves. */
static int credential(YDAccessAdmin *admin, const YDValue *spec, Credential *out,
    const char **code) {
    const YDValue *token = yd_get(spec, "token"), *generate_token = yd_get(spec, "generate_token");
    memset(out, 0, sizeof(*out));
    if (!token && !generate_token) return 0;
    if ((token && generate_token) ||
        (generate_token && (generate_token->type != YD_BOOL || !generate_token->boolean)) ||
        (token && !token_profile(string(token)))) {
        *code = "invalid_credential";
        return 400;
    }
    out->present = true;
    if (token) {
        out->token_length = strlen(token->scalar);
        memcpy(out->token, token->scalar, out->token_length + 1);
    } else {
        if (!generate(out->token)) { *code = "token_generation_failed"; return 503; }
        out->token_length = strlen(out->token);
        out->generated = true;
    }
    if (!yd_access_runtime_verifier(out->token, out->token_length, out->verifier)) {
        *code = "token_generation_failed";
        return 503;
    }
    const YDAccessAdminConfig *c = &admin->config;
    /* Both comparisons always run. */
    bool read_match = c->read_token && yd_access_secure_equal(out->token, out->token_length,
        c->read_token, c->read_length);
    bool write_match = c->write_token && yd_access_secure_equal(out->token, out->token_length,
        c->write_token, c->write_length);
    if (read_match || write_match || yd_access_static_token_matches(c->access, out->verifier)) {
        *code = "token_conflict";
        return 409;
    }
    return 0;
}
static void verifier_field(Buffer *b, const unsigned char verifier[32]) {
    char hex[65];
    yd_access_state_hex(verifier, hex);
    text(b, ",\"verifier\":");
    quoted(b, hex);
    OPENSSL_cleanse(hex, sizeof(hex));
}
/* Builds the internal command. 0 or an HTTP status with a static code. */
static int command(YDAccessAdmin *admin, YDAccessOperation operation, const char *name,
    const YDValue *spec, Buffer *out, Credential *cred, const char **code) {
    const YDAccess *a = admin->config.access;
    bool role = operation == YD_ACCESS_ROLE_PUT || operation == YD_ACCESS_ROLE_DELETE;
    if (yd_access_static_name(a, name, role)) { *code = "static_policy_read_only"; return 409; }
    if (operation == YD_ACCESS_ROLE_DELETE) { text(out, "{\"op\":\"role_delete\"}"); return 0; }
    if (operation == YD_ACCESS_PRINCIPAL_DELETE) {
        text(out, "{\"op\":\"principal_delete\"}");
        return 0;
    }
    *code = "invalid_access_request";
    if (!spec || spec->type != YD_MAP) return 400;
    if (operation == YD_ACCESS_ROLE_PUT) {
        static const char *const keys[] = {"read", "write"};
        const YDValue *read = yd_get(spec, "read"), *write = yd_get(spec, "write");
        if (spec->count != 2 || !only(spec, keys, 2) || !read || read->type != YD_ARRAY ||
            !write || write->type != YD_ARRAY)
            return 400;
        text(out, "{\"op\":\"role_put\",\"read\":");
        value(out, read);
        text(out, ",\"write\":");
        value(out, write);
        text(out, "}");
        return 0;
    }
    int status = credential(admin, spec, cred, code);
    if (status) return status;
    *code = "invalid_access_request";
    if (operation == YD_ACCESS_PRINCIPAL_PUT) {
        static const char *const keys[] = {"roles", "token", "generate_token", "field_permissions"};
        const YDValue *roles = yd_get(spec, "roles"), *fields = yd_get(spec, "field_permissions");
        if (!only(spec, keys, 4) || !roles || roles->type != YD_ARRAY) return 400;
        if (fields) {
            char error[128];
            YDFieldPolicy *policy = yd_field_policy_new(fields, error, sizeof(error));
            if (!policy || !yd_access_state_fields_shape(fields)) {
                yd_field_policy_free(policy);
                *code = "invalid_field_permissions";
                return 400;
            }
            yd_field_policy_free(policy);
        }
        text(out, "{\"op\":\"principal_put\",\"roles\":");
        value(out, roles);
        if (cred->present) verifier_field(out, cred->verifier);
        if (fields) {
            text(out, ",\"field_permissions\":");
            value(out, fields);
        }
        text(out, "}");
        return 0;
    }
    static const char *const keys[] = {"token", "generate_token", "overlap_seconds"};
    const YDValue *overlap = yd_get(spec, "overlap_seconds");
    if (!only(spec, keys, 3) || !cred->present ||
        (overlap && (overlap->type != YD_INT || overlap->number < 0 ||
            overlap->number > YD_ACCESS_OVERLAP_LIMIT)))
        return 400;
    long long until = 0;
    if (overlap && overlap->number > 0) {
        time_t now = time(NULL);
        if (now == (time_t)-1) { *code = "clock_unavailable"; return 503; }
        until = (long long)now + (long long)overlap->number;
    }
    char number[32];
    snprintf(number, sizeof(number), "%lld", until);
    text(out, "{\"op\":\"principal_rotate\"");
    verifier_field(out, cred->verifier);
    text(out, ",\"previous_expires_at\":");
    text(out, number);
    text(out, "}");
    return 0;
}
static YDDiskReply execute(YDAccessAdmin *admin, const YDAccessAdminRequest *request,
    const Buffer *command_body) {
    const unsigned char *body = (const unsigned char *)command_body->data;
    size_t size = command_body->length;
    if (admin->config.cluster) {
        YDRaftWrite write = {.method = YD_ACCESS_COMMAND_METHOD, .target = request->target,
            .body = body, .size = size, .receipt_epoch = request->receipt_epoch};
        memcpy(write.id, request->request_id, 16);
        YDDiskReply reply = yd_raft_cluster_write(admin->config.cluster, &write,
            admin->config.timeout_ms);
        reply.outcome = reply.status >= 200 && reply.status < 300 ?
            YD_DISK_OUTCOME_RETURNED_SUCCESS : reply.status >= 400 && reply.status < 500 ?
            YD_DISK_OUTCOME_RETURNED_FAILURE : YD_DISK_OUTCOME_UNKNOWN;
        if (reply.outcome == YD_DISK_OUTCOME_RETURNED_SUCCESS) yd_access_admin_refresh(admin, true);
        return reply;
    }
    YDDiskTxn *txn = NULL;
    YDDiskReply reply = yd_access_store_prepare(admin->config.disk, request->target, body, size,
        NULL, NULL, &txn);
    if (!txn) {
        reply.outcome = YD_DISK_OUTCOME_RETURNED_FAILURE;
        return reply;
    }
    char error[256];
    YDDiskView receipt;
    if (!yd_disk_commit_view(txn, &receipt, error, sizeof(error))) {
        yd_disk_reply_free(&reply);
        reply = yd_disk_error_reply(500, "access_durability_failed_restart_required");
        reply.outcome = YD_DISK_OUTCOME_UNKNOWN;
        yd_access_admin_refresh(admin, false);
        return reply;
    }
    yd_disk_revision(&receipt, reply.revision);
    reply.outcome = YD_DISK_OUTCOME_RETURNED_SUCCESS;
    reply.has_receipt = true;
    reply.receipt = receipt;
    yd_access_admin_refresh(admin, false);
    return reply;
}
/* The receipt never contains the token: add it to this one response only. */
static YDDiskReply with_token(YDDiskReply reply, const Credential *cred) {
    if (!cred->generated || reply.status < 200 || reply.status >= 300 || reply.length < 3 ||
        memcmp(reply.body + reply.length - 2, "}\n", 2))
        return reply;
    size_t n = reply.length - 2 + sizeof(",\"token\":\"\"}\n") - 1 + cred->token_length;
    char *body = malloc(n + 1);
    if (!body) {
        yd_disk_reply_free(&reply);
        YDDiskReply failed = yd_disk_error_reply(500, "token_response_unavailable");
        failed.outcome = YD_DISK_OUTCOME_RETURNED_SUCCESS;
        return failed;
    }
    memcpy(body, reply.body, reply.length - 2);
    snprintf(body + reply.length - 2, n + 1 - (reply.length - 2), ",\"token\":\"%s\"}\n",
        cred->token);
    free(reply.body);
    reply.body = body;
    reply.length = n;
    return reply;
}
YDDiskReply yd_access_admin_request(YDAccessAdmin *admin, const YDAccessAdminRequest *request) {
    if (!admin || !request || !request->method || !request->target)
        return error_reply(400, "invalid_access_request", YD_DISK_OUTCOME_NOT_DISPATCHED);
    bool read = !strcmp(request->method, "GET") || !strcmp(request->method, "HEAD");
    if (!strcmp(request->target, "/v1/access")) {
        if (!read) {
            YDDiskReply reply = error_reply(405, "method_not_allowed", YD_DISK_OUTCOME_NOT_DISPATCHED);
            memcpy(reply.headers, NO_STORE "Allow: GET, HEAD\r\n",
                sizeof(NO_STORE "Allow: GET, HEAD\r\n"));
            return reply;
        }
        if (request->length) return error_reply(400, "invalid_access_request", YD_DISK_OUTCOME_NOT_DISPATCHED);
        return list(admin);
    }
    char name[129];
    YDAccessOperation operation = yd_access_state_target(request->method, request->target, name);
    if (!operation) {
        char other[129];
        bool known = yd_access_state_target("PUT", request->target, other) ||
            yd_access_state_target("POST", request->target, other);
        return error_reply(known ? 405 : 404, known ? "method_not_allowed" : "not_found",
            YD_DISK_OUTCOME_NOT_DISPATCHED);
    }
    if (admin->config.replica)
        return error_reply(405, "replica_is_read_only", YD_DISK_OUTCOME_NOT_DISPATCHED);
    if (!admin->config.cluster && request->receipt_epoch_present)
        return error_reply(409, "receipt_retention_disabled", YD_DISK_OUTCOME_NOT_DISPATCHED);
    if (admin->config.cluster && !request->request_id)
        return error_reply(400, "request_id_required", YD_DISK_OUTCOME_NOT_DISPATCHED);
    bool deletion = operation == YD_ACCESS_ROLE_DELETE || operation == YD_ACCESS_PRINCIPAL_DELETE;
    if (deletion ? request->length != 0 : !request->length)
        return error_reply(400, "invalid_access_request", YD_DISK_OUTCOME_NOT_DISPATCHED);
    if (request->length > YD_ACCESS_COMMAND_BYTES)
        return error_reply(413, "access_request_too_large", YD_DISK_OUTCOME_NOT_DISPATCHED);
    if (!deletion && !request->json)
        return error_reply(415, "json_content_type_required", YD_DISK_OUTCOME_NOT_DISPATCHED);
    char error[128];
    YDValue *spec = deletion ? NULL : yd_parse_sized(request->body, request->length,
        YD_ACCESS_COMMAND_BYTES, error, sizeof(error));
    if (!deletion && (!spec || spec->type != YD_MAP)) {
        spec_free(spec);
        return error_reply(400, "invalid_access_request", YD_DISK_OUTCOME_NOT_DISPATCHED);
    }
    Credential *cred = calloc(1, sizeof(*cred));
    Buffer body = {.limit = YD_ACCESS_COMMAND_BYTES};
    const char *code = "invalid_access_request";
    int status = cred ? command(admin, operation, name, spec, &body, cred, &code) : 503;
    spec_free(spec);
    if (!cred) code = "allocation_failed";
    if (!status && body.failed) { status = 413; code = "access_request_too_large"; }
    YDDiskReply reply = status ? error_reply(status, code, YD_DISK_OUTCOME_NOT_DISPATCHED) :
        execute(admin, request, &body);
    buffer_free(&body);
    if (!status) reply = with_token(reply, cred);
    /* Replicated receipts carry no headers: restore the policy on every reply. */
    memcpy(reply.headers, NO_STORE, sizeof(NO_STORE));
    if (cred) credential_clear(cred);
    free(cred);
    return reply;
}
