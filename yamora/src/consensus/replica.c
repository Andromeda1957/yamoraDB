#define _POSIX_C_SOURCE 200809L
#include "replica.h"
#include "../disk_internal.h"
#include "../disk_replica.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The one active transfer is durable. Operation records contain exact authored
 * bytes, not a parsed/serialized substitute. All limits apply before append. */
#define FULL_OPERATIONS 65536U
#define FULL_BYTES (256U * 1024U * 1024U)
#define STATE_HEADER 96U
#define OP_HEADER 32U
static const unsigned char state_key[] = {0, 'Y', 'R', 'S'};
static const unsigned char op_prefix[] = {0, 'Y', 'R', 'O'};
static const unsigned char destination_key[] = {0, 'Y', 'R', 'D'};
static const unsigned char destination_record[32] = {'Y', 'D', 'R', 'P', 'L', 'D', '0', '1'};
typedef struct {
    bool full;
    unsigned char id[16];
    uint64_t base, count, bytes;
    YDValue *spec;
    unsigned char *source;
    size_t size;
} State;
typedef struct {
    unsigned kind;
    char collection[129], document[129];
    const unsigned char *body;
    size_t size;
    unsigned char *owned;
} Operation;
static const char *string(const YDValue *v) { return v && v->type == YD_STRING ? v->scalar : NULL; }
static bool zeros(const unsigned char *p, size_t n) {
    for (size_t i = 0; i < n; i++) if (p[i]) return false;
    return true;
}
static bool hex(const char *s, size_t n) {
    if (!s || strlen(s) != n) return false;
    for (size_t i = 0; i < n; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f'))) return false;
    return true;
}
static bool only(const YDValue *v, const char *const *names, size_t n) {
    if (!v || v->type != YD_MAP) return false;
    for (size_t i = 0; i < v->count; i++) {
        bool found = false;
        for (size_t j = 0; j < n; j++) found |= !strcmp(v->keys[i], names[j]);
        if (!found) return false;
    }
    return true;
}
static bool contains(const YDValue *names, const char *name) {
    for (size_t i = 0; names && i < names->count; i++)
        if (!strcmp(string(names->items[i]), name)) return true;
    return false;
}
static int name_order(const void *left, const void *right) {
    return strcmp(*(const char *const *)left, *(const char *const *)right);
}
static bool begin_valid(const YDValue *v, bool full) {
    const char *revision = string(yd_get(v, "revision"));
    if (!hex(revision, 16)) return false;
    if (full) {
        const char *const keys[] = {"revision", "collections", "full", "revision_scheme", "source_after"};
        const YDValue *names = yd_get(v, "collections"), *flag = yd_get(v, "full");
        const char *scheme = string(yd_get(v, "revision_scheme")),
                   *after = string(yd_get(v, "source_after"));
        if (!only(v, keys, 5) || !flag || flag->type != YD_BOOL || !flag->boolean ||
            !scheme || strcmp(scheme, "xor-fnv-v2") || !yd_disk_replica_token(after) ||
            !names || names->type != YD_ARRAY || names->count > YD_DISK_COLLECTION_LIMIT)
            return false;
        const char **sorted = names->count ? malloc(names->count * sizeof(*sorted)) : NULL;
        if (names->count && !sorted) return false;
        bool valid = true;
        for (size_t i = 0; i < names->count; i++) {
            const char *name = string(names->items[i]);
            if (!name || !yamldb_valid_name(name)) { valid = false; break; }
            sorted[i] = name;
        }
        if (valid && names->count > 1) {
            qsort(sorted, names->count, sizeof(*sorted), name_order);
            for (size_t i = 1; i < names->count; i++) if (!strcmp(sorted[i - 1], sorted[i])) { valid = false; break; }
        }
        free(sorted); return valid;
    }
    const char *const keys[] = {"after", "token", "previous_revision", "revision", "operations"};
    const char *after = string(yd_get(v, "after")), *token = string(yd_get(v, "token"));
    const YDValue *count = yd_get(v, "operations");
    return only(v, keys, 5) && yd_disk_replica_token(after) && yd_disk_replica_token(token) &&
        !memcmp(after, token, 36) && strcmp(after + 36, token + 36) < 0 &&
        hex(string(yd_get(v, "previous_revision")), 16) && count && count->type == YD_INT &&
        count->number >= 0 && count->number <= 256;
}
static void state_free(State *s) { yd_free(s->spec); free(s->source); memset(s, 0, sizeof(*s)); }
static int state_load(YDDisk *disk, const YDDiskView *view, State *s, char *error, size_t length) {
    memset(s, 0, sizeof(*s));
    uint64_t offset = 0;
    int found = yd_disk_get(disk, view, state_key, sizeof(state_key), &offset, error, length);
    if (found != 1) return found;
    size_t n = 0;
    unsigned char *p = yd_disk_record(disk, view, offset, &n, error, length);
    bool valid = p && n >= STATE_HEADER && !memcmp(p, "YDRPLS01", 8) &&
        (p[8] == 1 || p[8] == 2) && zeros(p + 9, 7) && !zeros(p + 16, 16) &&
        zeros(p + 64, 32) && yd_disk_u64(p + 56) == n - STATE_HEADER;
    if (valid) {
        s->full = p[8] == 1;
        memcpy(s->id, p + 16, 16);
        s->base = yd_disk_u64(p + 32);
        s->count = yd_disk_u64(p + 40);
        s->bytes = yd_disk_u64(p + 48);
        s->size = n - STATE_HEADER;
        s->source = malloc(s->size);
        if (s->source) memcpy(s->source, p + STATE_HEADER, s->size);
        s->spec = yd_parse_sized(p + STATE_HEADER, s->size, YD_DISK_REQUEST_LIMIT(view->format), error, length);
        valid = s->source && begin_valid(s->spec, s->full) &&
            s->count <= (s->full ? FULL_OPERATIONS : 256U) &&
            s->bytes <= (s->full ? FULL_BYTES : YD_DISK_CAPTURE_LIMIT(view->format));
    }
    free(p);
    if (!valid) { state_free(s); return -1; }
    return 1;
}
static bool state_put(YDDiskTxn *txn, const State *s, char *error, size_t length) {
    unsigned char *p = calloc(1, STATE_HEADER + s->size);
    if (!p) return false;
    memcpy(p, "YDRPLS01", 8); p[8] = s->full ? 1 : 2;
    memcpy(p + 16, s->id, 16);
    yd_disk_set64(p + 32, s->base); yd_disk_set64(p + 40, s->count);
    yd_disk_set64(p + 48, s->bytes); yd_disk_set64(p + 56, s->size);
    memcpy(p + STATE_HEADER, s->source, s->size);
    uint64_t offset = 0;
    bool valid = yd_disk_append(txn, p, STATE_HEADER + s->size, &offset, error, length) &&
        yd_disk_put(txn, state_key, sizeof(state_key), offset, error, length);
    free(p); return valid;
}
static size_t operation_key(unsigned char key[YD_DISK_KEY_LIMIT], const Operation *op) {
    size_t cn = strlen(op->collection), dn = strlen(op->document);
    memcpy(key, op_prefix, 4); memcpy(key + 4, op->collection, cn);
    key[4 + cn] = 0; memcpy(key + 5 + cn, op->document, dn);
    return 5 + cn + dn;
}
static bool operation_parse(const YDValue *v, bool full, Operation *op, char *error, size_t length) {
    memset(op, 0, sizeof(*op));
    const char *const keys[] = {"collection", "document", "put", "delete", "create_collection"};
    const char *col = string(yd_get(v, "collection")), *doc = string(yd_get(v, "document"));
    const YDValue *put = yd_get(v, "put"), *del = yd_get(v, "delete"), *create = yd_get(v, "create_collection");
    if (!only(v, keys, 5) || !col || !yamldb_valid_name(col) ||
        (!full && !strcmp(col, "yamldb-system")) || (doc && !yamldb_valid_name(doc)) ||
        (yd_get(v, "document") && !doc)) return false;
    if (!doc) {
        if (full || put || del || !create || create->type != YD_BOOL || !create->boolean) return false;
        op->kind = 1;
    } else if (put && !del && !create && string(put)) {
        op->size = strlen(put->scalar); op->body = (const unsigned char *)put->scalar; op->kind = 3;
        YDValue *document = op->size && op->size <= 16U * 1024U * 1024U
            ? yd_parse_sized(op->body, op->size, 16U * 1024U * 1024U, error, length) : NULL;
        bool valid = document && document->type == YD_MAP;
        yd_free(document); if (!valid) return false;
    } else if (del && !put && !create && del->type == YD_BOOL && del->boolean && !full) op->kind = 2;
    else return false;
    memcpy(op->collection, col, strlen(col) + 1);
    if (doc) memcpy(op->document, doc, strlen(doc) + 1);
    return true;
}
static bool operation_put(YDDiskTxn *txn, const Operation *op, char *error, size_t length) {
    size_t cn = strlen(op->collection), dn = strlen(op->document), n = OP_HEADER + cn + dn + op->size;
    unsigned char *p = calloc(1, n), key[YD_DISK_KEY_LIMIT];
    if (!p) return false;
    memcpy(p, "YDRPLO01", 8); p[8] = (unsigned char)op->kind;
    yd_disk_set16(p + 10, (uint16_t)cn); yd_disk_set16(p + 12, (uint16_t)dn);
    yd_disk_set64(p + 16, op->size);
    memcpy(p + OP_HEADER, op->collection, cn); memcpy(p + OP_HEADER + cn, op->document, dn);
    if (op->size) memcpy(p + OP_HEADER + cn + dn, op->body, op->size);
    uint64_t offset = 0;
    bool valid = yd_disk_append(txn, p, n, &offset, error, length) &&
        yd_disk_put(txn, key, operation_key(key, op), offset, error, length);
    free(p); return valid;
}
static bool operation_load(YDDisk *disk, const YDDiskView *view, uint64_t offset,
                             Operation *op, char *error, size_t length) {
    memset(op, 0, sizeof(*op));
    size_t n = 0;
    unsigned char *p = yd_disk_record(disk, view, offset, &n, error, length);
    size_t cn = p && n >= OP_HEADER ? yd_disk_u16(p + 10) : 0,
           dn = p && n >= OP_HEADER ? yd_disk_u16(p + 12) : 0;
    bool valid = p && n >= OP_HEADER && !memcmp(p, "YDRPLO01", 8) && p[8] >= 1 && p[8] <= 3 &&
        !p[9] && zeros(p + 14, 2) && zeros(p + 24, 8) && cn && cn <= 128 && dn <= 128 &&
        cn + dn <= n - OP_HEADER && yd_disk_u64(p + 16) == n - OP_HEADER - cn - dn &&
        !memchr(p + OP_HEADER, 0, cn + dn);
    if (valid) {
        op->kind = p[8]; op->size = (size_t)yd_disk_u64(p + 16);
        memcpy(op->collection, p + OP_HEADER, cn); memcpy(op->document, p + OP_HEADER + cn, dn);
        op->body = p + OP_HEADER + cn + dn;
        valid = yamldb_valid_name(op->collection) && (!dn || yamldb_valid_name(op->document)) &&
            (op->kind == 1 ? !dn && !op->size : dn && (op->kind == 2 ? !op->size :
                op->size && op->size <= YD_DISK_DOCUMENT_LIMIT(view->format)));
        if (valid && op->kind == 3) {
            YDValue *v = yd_parse_sized(op->body, op->size, YD_DISK_DOCUMENT_LIMIT(view->format), error, length);
            valid = v && v->type == YD_MAP; yd_free(v);
        }
    }
    if (!valid) { free(p); memset(op, 0, sizeof(*op)); return false; }
    op->owned = p; return true;
}
static void session(const State *s, char text[33]) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < 16; i++) { text[2 * i] = digits[s->id[i] >> 4]; text[2 * i + 1] = digits[s->id[i] & 15]; }
    text[32] = 0;
}
static YDDiskReply response(const YDDiskView *v, const char *status, const char *after, const State *s) {
    char text[512], revision[17], id[33] = {0}, transfer[128] = {0};
    yd_disk_revision(v, revision); if (s) session(s, id);
    if (s) snprintf(transfer, sizeof(transfer), ",\"transfer\":\"%s\",\"staged_operations\":%llu",
        s->full ? "bootstrap" : "follow", (unsigned long long)s->count);
    int n = snprintf(text, sizeof(text), "{\"status\":\"%s\",\"revision\":\"%s\",\"after\":%s%s%s%s%s%s%s}",
        status, revision, after ? "\"" : "null", after ? after : "", after ? "\"" : "",
        s ? ",\"session\":\"" : "", s ? id : "", s ? "\"" : "", transfer);
    YDDiskReply r = {.status = 200, .content_type = "application/json; charset=utf-8"};
    if (n < 0 || (size_t)n >= sizeof(text) || !(r.body = strdup(text))) return yd_disk_error_reply(503, "allocation_failed");
    r.length = (size_t)n; memcpy(r.revision, revision, 17); return r;
}
int yd_raft_replica_destination(YDDisk *disk, const YDDiskView *view, char *error, size_t length) {
    uint64_t offset = 0;
    int found = yd_disk_get(disk, view, destination_key, sizeof(destination_key), &offset, error, length);
    if (found != 1) return found;
    size_t n = 0; unsigned char *p = yd_disk_record(disk, view, offset, &n, error, length);
    bool valid = p && n == sizeof(destination_record) && !memcmp(p, destination_record, n);
    free(p); return valid ? 1 : -1;
}
YDDiskReply yd_raft_replica_read(YDDisk *disk, const YDDiskView *view, const char *method,
    const char *target, const unsigned char *body, size_t size, const char *match, const char *none, bool gzip) {
    (void)body; (void)match; (void)none; (void)gzip;
    if (strcmp(target, "/v1/replication/status")) return yd_disk_error_reply(404, "not_found");
    if (strcmp(method, "GET") || size) return yd_disk_error_reply(405, "method_not_allowed");
    YDDiskReplicaPosition p; char error[256];
    int found = yd_disk_replica_position(disk, view, &p, error, sizeof(error));
    State s; int staged = state_load(disk, view, &s, error, sizeof(error));
    int bound = yd_raft_replica_destination(disk, view, error, sizeof(error));
    YDDiskReply r = staged < 0 || bound < 0 || ((staged || found == 1) && bound != 1)
        ? yd_disk_error_reply(503, "replication_state_corrupt") :
        found < 0 ? yd_disk_error_reply(409, "replica_requires_bootstrap") :
        response(view, found ? "following" : "uninitialized", found ? p.after : NULL, staged ? &s : NULL);
    state_free(&s); return r;
}
static bool erase_transfer(YDDiskTxn *txn, const YDDiskView *before, char *error, size_t length) {
    YDDiskCursor *cursor = yd_disk_cursor(txn->disk, before, op_prefix, 4, false, error, length);
    if (!cursor) return false;
    unsigned char key[YD_DISK_KEY_LIMIT]; size_t n = 0; uint64_t offset; int next = 0; bool valid = true;
    while (valid && (next = yd_disk_next(cursor, key, sizeof(key), &n, &offset, error, length)) == 1) {
        if (n < 4 || memcmp(key, op_prefix, 4)) break;
        valid = yd_disk_delete(txn, key, n, error, length);
    }
    yd_disk_cursor_free(cursor);
    return valid && next >= 0 && yd_disk_delete(txn, state_key, sizeof(state_key), error, length);
}
static bool clear_documents(YDDiskTxn *txn, const YDDiskView *before, char *error, size_t length) {
    const unsigned char tags[] = {'C', 'D', 'I', 'U'};
    for (size_t i = 0; i < sizeof(tags); i++) {
        YDDiskCursor *c = yd_disk_cursor(txn->disk, before, tags + i, 1, false, error, length);
        if (!c) return false;
        unsigned char key[YD_DISK_KEY_LIMIT]; size_t n; uint64_t offset; int next; bool valid = true;
        while ((next = yd_disk_next(c, key, sizeof(key), &n, &offset, error, length)) == 1) {
            if (key[0] != tags[i]) break;
            if (!yd_disk_delete(txn, key, n, error, length)) { valid = false; break; }
        }
        yd_disk_cursor_free(c); if (!valid || next < 0) return false;
    }
    txn->view.documents = txn->view.collections = txn->view.bytes = txn->view.revision = 0;
    txn->log_enabled = txn->log_reset = true; return true;
}
/* Three bounded scans permit unique-key swaps without rebuilding unchanged
 * indexes: remove old keys, write the complete frame, add final keys. */
static bool replay(YDDiskTxn *txn, const YDDiskView *before, const State *s,
                     YDDiskIndexes *indexes, unsigned pass, char *error, size_t length) {
    YDDiskCursor *c = yd_disk_cursor(txn->disk, before, op_prefix, 4, false, error, length);
    if (!c) return false;
    unsigned char key[YD_DISK_KEY_LIMIT]; size_t n; uint64_t offset, count = 0, bytes = 0; int next = 0; bool valid = true;
    while (valid && (next = yd_disk_next(c, key, sizeof(key), &n, &offset, error, length)) == 1) {
        if (n < 4 || memcmp(key, op_prefix, 4)) break;
        Operation op;
        if (!operation_load(txn->disk, before, offset, &op, error, length)) { valid = false; break; }
        count++; bytes += op.size;
        if (op.kind == 1) {
            if (pass == 1) valid = yd_disk_create_collection(txn, op.collection, error, length);
        } else {
            YDDiskDocument old = {0}, fresh = {0};
            int found = yd_disk_document_tx_get(txn, op.collection, op.document, &old, error, length);
            valid = found >= 0 && !(pass == 1 && op.kind == 2 && !found);
            if (valid && pass == 0 && found) valid = yd_disk_indexes_change(txn, indexes, &old, false, error, length);
            if (valid && pass == 1) {
                memcpy(fresh.collection, op.collection, sizeof(fresh.collection)); memcpy(fresh.id, op.document, sizeof(fresh.id));
                fresh.body = (unsigned char *)op.body; fresh.length = op.size;
                valid = yd_disk_write_document(txn, found ? &old : NULL, op.kind == 3 ? &fresh : NULL, error, length);
            }
            if (valid && pass == 2 && found) valid = yd_disk_indexes_change(txn, indexes, &old, true, error, length);
            yd_disk_document_free(&old);
        }
        free(op.owned);
    }
    yd_disk_cursor_free(c);
    return valid && next >= 0 && count == s->count && bytes == s->bytes;
}
YDDiskReply yd_raft_replica_prepare(YDDisk *disk, const YDRaftWrite *w, YDDiskTxn **prepared) {
    *prepared = NULL;
    if (strcmp(w->method, "POST")) return yd_disk_error_reply(405, "method_not_allowed");
    if (w->match || w->none) return yd_disk_error_reply(400, "unsupported_replication_precondition");
    const char *p = w->target;
    if (strncmp(p, "/v1/replication/", 16)) return yd_disk_error_reply(404, "not_found");
    p += 16; bool full = strncmp(p, "follow/", 7) != 0; if (!full) p += 7;
    bool begin = !strcmp(p, "begin"), apply = !strcmp(p, "apply"), commit = !strcmp(p, "commit"), abort = !strcmp(p, "abort");
    if (!begin && !apply && !commit && !abort) return yd_disk_error_reply(404, "not_found");
    char error[512]; YDDiskView before = yd_disk_view(disk);
    YDValue *v = yd_parse_sized(w->body, w->size, YD_DISK_REQUEST_LIMIT(before.format), error, sizeof(error));
    if (!v || v->type != YD_MAP) { yd_free(v); return yd_disk_error_reply(400, "invalid_replication"); }
    State s; int found = state_load(disk, &before, &s, error, sizeof(error));
    YDDiskReply r = {0}; YDDiskTxn *txn = NULL;
    const char *failure = "replication_unavailable"; int status = 503;
    if (found < 0) { failure = "replication_state_corrupt"; goto rejected; }
    int bound = yd_raft_replica_destination(disk, &before, error, sizeof(error));
    if (bound < 0 || (found && bound != 1)) { failure = "replication_state_corrupt"; goto rejected; }
    if (begin) {
        if (!begin_valid(v, full)) { status = 400; failure = "invalid_replication_begin"; goto rejected; }
        if (found) { status = 409; failure = "replication_in_progress"; goto rejected; }
        if (!full) {
            YDDiskReplicaPosition position;
            int initialized = yd_disk_replica_position(disk, &before, &position, error, sizeof(error));
            const char *after = string(yd_get(v, "after")), *token = string(yd_get(v, "token"));
            if (initialized != 1) { status = 409; failure = "replica_requires_bootstrap"; goto rejected; }
            if (!strcmp(position.after, token) && before.revision == strtoull(string(yd_get(v, "revision")), NULL, 16)) {
                txn = yd_disk_begin_exclusive(disk, error, sizeof(error));
                if (!txn) goto rejected;
                r = response(&before, "already_applied", token, NULL); goto success;
            }
            if (strcmp(position.after, after) || before.revision != strtoull(string(yd_get(v, "previous_revision")), NULL, 16)) {
                status = 409; failure = "replica_checkpoint_mismatch"; goto rejected;
            }
        }
        s.full = full; memcpy(s.id, w->id, 16); s.base = before.revision;
        s.size = w->size; s.source = malloc(s.size); s.spec = yd_clone(v);
        if (!s.source || !s.spec || zeros(s.id, 16)) goto rejected;
        memcpy(s.source, w->body, s.size);
        txn = yd_disk_begin_exclusive(disk, error, sizeof(error));
        if (!txn || !state_put(txn, &s, error, sizeof(error))) goto rejected;
        uint64_t marker = 0;
        if (!yd_disk_append(txn, destination_record, sizeof(destination_record), &marker, error, sizeof(error)) ||
            !yd_disk_put(txn, destination_key, sizeof(destination_key), marker, error, sizeof(error))) goto rejected;
        r = response(&before, "staging", full ? NULL : string(yd_get(v, "after")), &s); goto success;
    }
    char id[33]; session(&s, id);
    if (!found || s.full != full || !string(yd_get(v, "session")) || strcmp(id, string(yd_get(v, "session")))) {
        status = 409; failure = "replication_session_expired"; goto rejected;
    }
    const char *const keys[] = {"session", "operations", "revision"};
    if (!only(v, keys, 3) || (apply ? yd_get(v, "revision") != NULL : yd_get(v, "operations") != NULL) ||
        (!full && yd_get(v, "revision"))) { status = 400; failure = "invalid_replication"; goto rejected; }
    txn = yd_disk_begin_exclusive(disk, error, sizeof(error)); if (!txn) goto rejected;
    if (abort) {
        if (!erase_transfer(txn, &before, error, sizeof(error))) goto rejected;
        r = response(&before, "aborted", NULL, NULL); goto success;
    }
    if (apply) {
        const YDValue *ops = yd_get(v, "operations");
        if (!ops || ops->type != YD_ARRAY || !ops->count || ops->count > 128) { status = 400; failure = "invalid_replication_operations"; goto rejected; }
        for (size_t i = 0; i < ops->count; i++) {
            Operation op; unsigned char key[YD_DISK_KEY_LIMIT]; uint64_t offset = 0;
            if (!operation_parse(ops->items[i], full, &op, error, sizeof(error)) ||
                (full && !contains(yd_get(s.spec, "collections"), op.collection))) { status = 400; failure = "replication_operations_rejected"; goto rejected; }
            if (s.count == (full ? FULL_OPERATIONS : (uint64_t)yd_get(s.spec, "operations")->number) ||
                op.size > (full ? FULL_BYTES : YD_DISK_CAPTURE_LIMIT(before.format)) - s.bytes) { status = 413; failure = "replication_transfer_limit"; goto rejected; }
            if (yd_disk_tx_peek(txn, key, operation_key(key, &op), &offset, error, sizeof(error)) != 0) {
                status = 400; failure = "duplicate_replication_identity"; goto rejected;
            }
            if (!operation_put(txn, &op, error, sizeof(error))) goto rejected;
            s.count++; s.bytes += op.size;
        }
        if (!state_put(txn, &s, error, sizeof(error))) goto rejected;
        r = response(&before, "staging", NULL, &s); goto success;
    }
    if (before.revision != s.base) { status = 409; failure = "replica_publication_conflict"; goto rejected; }
    if (!full && s.count != (uint64_t)yd_get(s.spec, "operations")->number) {
        status = 409; failure = "replica_revision_mismatch"; goto rejected;
    }
    YDDiskIndexes *indexes = NULL;
    bool valid = true;
    if (full) {
        valid = clear_documents(txn, &before, error, sizeof(error));
        const YDValue *names = yd_get(s.spec, "collections");
        for (size_t i = 0; valid && i < names->count; i++) valid = yd_disk_create_collection(txn, names->items[i]->scalar, error, sizeof(error));
    } else {
        indexes = yd_disk_indexes_load_tx(txn, error, sizeof(error));
        valid = indexes && replay(txn, &before, &s, indexes, 0, error, sizeof(error));
    }
    if (valid) valid = replay(txn, &before, &s, indexes, 1, error, sizeof(error));
    if (valid) valid = full ? yd_disk_rebuild_indexes(txn, error, sizeof(error)) : replay(txn, &before, &s, indexes, 2, error, sizeof(error));
    yd_disk_indexes_free(indexes);
    if (!valid) { status = 409; failure = "replication_publication_rejected"; goto rejected; }
    const char *revision = string(yd_get(v, "revision"));
    if (revision && !hex(revision, 16)) { status = 400; failure = "invalid_revision"; goto rejected; }
    if (!revision) revision = string(yd_get(s.spec, "revision"));
    if (txn->view.revision != strtoull(revision, NULL, 16)) { status = 409; failure = "replica_revision_mismatch"; goto rejected; }
    const char *token = string(yd_get(s.spec, full ? "source_after" : "token"));
    if (!yd_disk_replica_checkpoint(txn, token, error, sizeof(error)) || !erase_transfer(txn, &before, error, sizeof(error))) goto rejected;
    r = response(&txn->view, "committed", token, NULL);
success:
    if (r.status != 200) goto rejected;
    *prepared = txn; txn = NULL; goto done;
rejected:
    yd_disk_reply_free(&r); r = yd_disk_error_reply(status, failure);
done:
    yd_disk_abort(txn); state_free(&s); yd_free(v); return r;
}
int yd_raft_replica_key(YDDisk *disk, const YDDiskView *view, const unsigned char *key,
    size_t size, uint64_t offset, char *error, size_t length) {
    if (size == 4 && !memcmp(key, destination_key, 4))
        return yd_raft_replica_destination(disk, view, error, length) == 1 ? 1 : -1;
    if (size == 4 && !memcmp(key, "\0YRP", 4)) {
        YDDiskReplicaPosition p; return yd_disk_replica_position(disk, view, &p, error, length) == 1 ? 1 : -1;
    }
    if (size == 4 && !memcmp(key, state_key, 4)) {
        State s; int found = state_load(disk, view, &s, error, length); state_free(&s); return found == 1 ? 1 : -1;
    }
    if (size < 4 || memcmp(key, op_prefix, 4)) return 0;
    Operation op; if (!operation_load(disk, view, offset, &op, error, length)) return -1;
    unsigned char expected[YD_DISK_KEY_LIMIT]; size_t n = operation_key(expected, &op);
    bool valid = n == size && !memcmp(expected, key, size); free(op.owned); return valid ? 1 : -1;
}
bool yd_raft_replica_validate(YDDisk *disk, const YDDiskView *view, char *error, size_t length) {
    State s; int found = state_load(disk, view, &s, error, length);
    if (found < 0) return false;
    int bound = yd_raft_replica_destination(disk, view, error, length);
    YDDiskReplicaPosition position;
    int positioned = yd_disk_replica_position(disk, view, &position, error, length);
    if (bound < 0 || positioned < 0 || ((found || positioned) && bound != 1)) {
        state_free(&s); return false;
    }
    YDDiskCursor *c = yd_disk_cursor(disk, view, op_prefix, 4, false, error, length);
    if (!c) { state_free(&s); return false; }
    unsigned char key[YD_DISK_KEY_LIMIT]; size_t n; uint64_t offset, count = 0, bytes = 0; int next = 0; bool valid = true;
    while (valid && (next = yd_disk_next(c, key, sizeof(key), &n, &offset, error, length)) == 1) {
        if (n < 4 || memcmp(key, op_prefix, 4)) break;
        Operation op;
        valid = found == 1 && yd_raft_replica_key(disk, view, key, n, offset, error, length) == 1 &&
            operation_load(disk, view, offset, &op, error, length);
        if (valid) {
            valid = s.full ? op.kind == 3 && contains(yd_get(s.spec, "collections"), op.collection) : strcmp(op.collection, "yamldb-system") != 0;
            count++; bytes += op.size; free(op.owned);
            valid = valid && count <= s.count && bytes <= s.bytes;
        }
    }
    yd_disk_cursor_free(c);
    valid = valid && next >= 0 && count == s.count && bytes == s.bytes;
    state_free(&s); return valid;
}
