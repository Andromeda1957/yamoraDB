#define _POSIX_C_SOURCE 200809L
#include "access_state.h"
#include "../snapshot.h"
#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
static bool valid_name(const char *name) {
    return name && strlen(name) <= 128 && yamldb_valid_name(name);
}
YDAccessOperation yd_access_state_target(const char *method, const char *target,
    char name[129]) {
    if (name) name[0] = 0;
    if (!method || !target || !name) return YD_ACCESS_OP_NONE;
    static const char roles[] = "/v1/access/roles/", principals[] = "/v1/access/principals/";
    bool role = !strncmp(target, roles, sizeof(roles) - 1);
    bool principal = !strncmp(target, principals, sizeof(principals) - 1);
    if (!role && !principal) return YD_ACCESS_OP_NONE;
    const char *rest = target + (role ? sizeof(roles) - 1 : sizeof(principals) - 1);
    const char *slash = strchr(rest, '/');
    size_t n = slash ? (size_t)(slash - rest) : strlen(rest);
    if (!n || n > 128) return YD_ACCESS_OP_NONE;
    char candidate[129];
    memcpy(candidate, rest, n);
    candidate[n] = 0;
    if (!valid_name(candidate)) return YD_ACCESS_OP_NONE;
    YDAccessOperation operation = YD_ACCESS_OP_NONE;
    if (slash) {
        if (principal && !strcmp(slash, "/rotate") && !strcmp(method, "POST"))
            operation = YD_ACCESS_PRINCIPAL_ROTATE;
    } else if (!strcmp(method, "PUT")) {
        operation = role ? YD_ACCESS_ROLE_PUT : YD_ACCESS_PRINCIPAL_PUT;
    } else if (!strcmp(method, "DELETE")) {
        operation = role ? YD_ACCESS_ROLE_DELETE : YD_ACCESS_PRINCIPAL_DELETE;
    }
    if (operation) memcpy(name, candidate, n + 1);
    return operation;
}
YDAccessState *yd_access_state_new(void) { return calloc(1, sizeof(YDAccessState)); }
static void principal_clear(YDAccessStatePrincipal *p) {
    yd_free(p->fields);
    OPENSSL_cleanse(p, sizeof(*p));
}
void yd_access_state_free(YDAccessState *state) {
    if (!state) return;
    for (size_t i = 0; i < state->principal_count; i++) principal_clear(&state->principals[i]);
    OPENSSL_cleanse(state, sizeof(*state));
    free(state);
}
void yd_access_state_hex(const unsigned char bytes[32], char text[65]) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < 32; i++) {
        text[2 * i] = digits[bytes[i] >> 4];
        text[2 * i + 1] = digits[bytes[i] & 15];
    }
    text[64] = 0;
}
bool yd_access_state_verifier_hex(const char *text, unsigned char out[32]) {
    if (!text || strlen(text) != 64) return false;
    unsigned char value[32] = {0};
    unsigned char any = 0;
    for (size_t i = 0; i < 64; i++) {
        unsigned char c = (unsigned char)text[i];
        unsigned digit;
        if (c >= '0' && c <= '9') digit = c - '0';
        else if (c >= 'a' && c <= 'f') digit = c - 'a' + 10;
        else return false;
        value[i / 2] = (unsigned char)(value[i / 2] | (i % 2 ? digit : digit << 4));
    }
    for (size_t i = 0; i < 32; i++) any |= value[i];
    if (!any) return false;
    memcpy(out, value, 32);
    OPENSSL_cleanse(value, sizeof(value));
    return true;
}
bool yd_access_state_fields_shape(const YDValue *fields) {
    if (!fields || fields->type != YD_ARRAY || fields->count > 64) return false;
    for (size_t i = 0; i < fields->count; i++)
        if (!fields->items[i] || fields->items[i]->type != YD_MAP) return false;
    return true;
}
static bool names(const YDValue *v, char out[][129], size_t limit, size_t *count,
    bool collections) {
    if (!v || v->type != YD_ARRAY || v->count > limit) return false;
    for (size_t i = 0; i < v->count; i++) {
        const char *name = string(v->items[i]);
        if (!valid_name(name) || (collections && !strcmp(name, "yamldb-system"))) return false;
        for (size_t j = 0; j < i; j++) if (!strcmp(out[j], name)) return false;
        memcpy(out[i], name, strlen(name) + 1);
    }
    *count = v->count;
    return true;
}
const YDAccessStateRole *yd_access_state_role(const YDAccessState *s, const char *name) {
    if (s && name) for (size_t i = 0; i < s->role_count; i++)
        if (!strcmp(s->roles[i].name, name)) return &s->roles[i];
    return NULL;
}
const YDAccessStatePrincipal *yd_access_state_principal(const YDAccessState *s,
    const char *name) {
    if (s && name) for (size_t i = 0; i < s->principal_count; i++)
        if (!strcmp(s->principals[i].name, name)) return &s->principals[i];
    return NULL;
}
static bool role_parse(const YDValue *v, YDAccessStateRole *role) {
    static const char *const keys[] = {"read", "write"};
    return v && v->type == YD_MAP && v->count == 2 && only(v, keys, 2) &&
        names(yd_get(v, "read"), role->read, YD_ACCESS_STATE_GRANTS, &role->reads, true) &&
        names(yd_get(v, "write"), role->write, YD_ACCESS_STATE_GRANTS, &role->writes, true) &&
        (role->reads || role->writes);
}
static bool roles_exist(const YDAccessState *s, const YDAccessStatePrincipal *p) {
    if (!p->role_count) return false;
    for (size_t i = 0; i < p->role_count; i++)
        if (!yd_access_state_role(s, p->roles[i])) return false;
    return true;
}
/* Every stored current and overlapping verifier names one principal only. */
static bool verifier_used(const YDAccessState *s, const unsigned char v[32], size_t except) {
    bool used = false;
    for (size_t i = 0; i < s->principal_count; i++) {
        if (i == except) continue;
        const YDAccessStatePrincipal *p = &s->principals[i];
        used |= CRYPTO_memcmp(p->verifier, v, 32) == 0;
        used |= p->previous_expires_at && CRYPTO_memcmp(p->previous, v, 32) == 0;
    }
    return used;
}
static bool expiry(const YDValue *v, int64_t *out) {
    if (!v || v->type != YD_INT || v->number < 1 || v->number > 253402300799.0L) return false;
    *out = (int64_t)v->number;
    return true;
}
static bool principal_parse(const YDValue *v, YDAccessStatePrincipal *p, bool command) {
    static const char *const stored[] = {"roles", "verifier", "previous", "field_permissions"};
    if (!v || v->type != YD_MAP || !only(v, stored, 4)) return false;
    const YDValue *roles = yd_get(v, "roles"), *fields = yd_get(v, "field_permissions");
    const YDValue *previous = yd_get(v, "previous");
    const char *verifier = string(yd_get(v, "verifier"));
    if (!names(roles, p->roles, YD_ACCESS_STATE_ROLES, &p->role_count, false) ||
        !p->role_count || (!command && !verifier) || (command && previous) ||
        (yd_get(v, "verifier") && !yd_access_state_verifier_hex(verifier, p->verifier)) ||
        (fields && !yd_access_state_fields_shape(fields)))
        return false;
    if (previous) {
        static const char *const keys[] = {"verifier", "expires_at"};
        if (previous->type != YD_MAP || previous->count != 2 || !only(previous, keys, 2) ||
            !yd_access_state_verifier_hex(string(yd_get(previous, "verifier")), p->previous) ||
            !expiry(yd_get(previous, "expires_at"), &p->previous_expires_at) ||
            !CRYPTO_memcmp(p->previous, p->verifier, 32))
            return false;
    }
    if (fields && !(p->fields = yd_clone(fields))) return false;
    return true;
}
YDAccessState *yd_access_state_parse(const unsigned char *body, size_t length) {
    if (!body || !length || length > YD_ACCESS_STATE_BYTES) return NULL;
    char error[128];
    YDValue *v = yd_parse_sized(body, length, YD_ACCESS_STATE_BYTES, error, sizeof(error));
    YDAccessState *s = v ? yd_access_state_new() : NULL;
    static const char *const keys[] = {"format", "version", "roles", "principals"};
    const YDValue *version = yd_get(v, "version"), *roles = yd_get(v, "roles"),
                  *principals = yd_get(v, "principals");
    const char *format = string(yd_get(v, "format"));
    if (!s || v->type != YD_MAP || v->count != 4 || !only(v, keys, 4) || !format ||
        strcmp(format, YD_ACCESS_STATE_FORMAT) || !version || version->type != YD_INT ||
        version->number < 1 || version->number > 9007199254740991.0L ||
        !roles || roles->type != YD_MAP || roles->count > YD_ACCESS_STATE_ROLES ||
        !principals || principals->type != YD_MAP ||
        principals->count > YD_ACCESS_STATE_PRINCIPALS)
        goto invalid;
    s->version = (uint64_t)version->number;
    for (size_t i = 0; i < roles->count; i++) {
        YDAccessStateRole *role = &s->roles[i];
        if (!valid_name(roles->keys[i]) || !role_parse(roles->items[i], role)) goto invalid;
        memcpy(role->name, roles->keys[i], strlen(roles->keys[i]) + 1);
        s->role_count++;
    }
    for (size_t i = 0; i < principals->count; i++) {
        YDAccessStatePrincipal *p = &s->principals[i];
        s->principal_count++;
        if (!valid_name(principals->keys[i]) ||
            !principal_parse(principals->items[i], p, false))
            goto invalid;
        memcpy(p->name, principals->keys[i], strlen(principals->keys[i]) + 1);
        if (!roles_exist(s, p)) goto invalid;
    }
    for (size_t i = 0; i < s->principal_count; i++) {
        const YDAccessStatePrincipal *p = &s->principals[i];
        if (verifier_used(s, p->verifier, i) ||
            (p->previous_expires_at && verifier_used(s, p->previous, i)))
            goto invalid;
    }
    yd_free(v);
    return s;
invalid:
    yd_free(v);
    yd_access_state_free(s);
    return NULL;
}
typedef struct {
    char *data;
    size_t length, capacity;
    bool failed;
} Buffer;
static void append(Buffer *b, const char *text, size_t n) {
    if (b->failed) return;
    if (n > YD_ACCESS_STATE_BYTES - b->length) { b->failed = true; return; }
    if (b->length + n + 1 > b->capacity) {
        size_t capacity = b->capacity ? b->capacity : 4096;
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
static void quoted(Buffer *b, const char *s) {
    /* Names use the native [a-z0-9-] profile; no escaping can be required. */
    text(b, "\""); text(b, s); text(b, "\"");
}
static void list(Buffer *b, char items[][129], size_t count) {
    text(b, "[");
    for (size_t i = 0; i < count; i++) {
        if (i) text(b, ",");
        quoted(b, items[i]);
    }
    text(b, "]");
}
static int by_role(const void *x, const void *y) {
    return strcmp((*(const YDAccessStateRole *const *)x)->name,
        (*(const YDAccessStateRole *const *)y)->name);
}
static int by_principal(const void *x, const void *y) {
    return strcmp((*(const YDAccessStatePrincipal *const *)x)->name,
        (*(const YDAccessStatePrincipal *const *)y)->name);
}
char *yd_access_state_encode(const YDAccessState *s, size_t *length) {
    if (length) *length = 0;
    if (!s || !length) return NULL;
    const YDAccessStateRole *roles[YD_ACCESS_STATE_ROLES];
    const YDAccessStatePrincipal *principals[YD_ACCESS_STATE_PRINCIPALS];
    for (size_t i = 0; i < s->role_count; i++) roles[i] = &s->roles[i];
    for (size_t i = 0; i < s->principal_count; i++) principals[i] = &s->principals[i];
    qsort(roles, s->role_count, sizeof(*roles), by_role);
    qsort(principals, s->principal_count, sizeof(*principals), by_principal);
    Buffer b = {0};
    char number[32];
    snprintf(number, sizeof(number), "%llu", (unsigned long long)s->version);
    text(&b, "{\"format\":\"" YD_ACCESS_STATE_FORMAT "\",\"version\":");
    text(&b, number);
    text(&b, ",\"roles\":{");
    for (size_t i = 0; i < s->role_count; i++) {
        if (i) text(&b, ",");
        quoted(&b, roles[i]->name);
        text(&b, ":{\"read\":");
        list(&b, (char (*)[129])roles[i]->read, roles[i]->reads);
        text(&b, ",\"write\":");
        list(&b, (char (*)[129])roles[i]->write, roles[i]->writes);
        text(&b, "}");
    }
    text(&b, "},\"principals\":{");
    for (size_t i = 0; i < s->principal_count; i++) {
        const YDAccessStatePrincipal *p = principals[i];
        char hex[65];
        if (i) text(&b, ",");
        quoted(&b, p->name);
        text(&b, ":{\"roles\":");
        list(&b, (char (*)[129])p->roles, p->role_count);
        yd_access_state_hex(p->verifier, hex);
        text(&b, ",\"verifier\":");
        quoted(&b, hex);
        if (p->previous_expires_at) {
            yd_access_state_hex(p->previous, hex);
            text(&b, ",\"previous\":{\"verifier\":");
            quoted(&b, hex);
            snprintf(number, sizeof(number), "%lld", (long long)p->previous_expires_at);
            text(&b, ",\"expires_at\":");
            text(&b, number);
            text(&b, "}");
        }
        OPENSSL_cleanse(hex, sizeof(hex));
        if (p->fields) {
            size_t n = 0;
            char *json = yd_json_sized(p->fields, &n, YD_ACCESS_STATE_BYTES);
            if (!json) b.failed = true;
            else {
                text(&b, ",\"field_permissions\":");
                append(&b, json, n);
                free(json);
            }
        }
        text(&b, "}");
    }
    text(&b, "}}\n");
    if (b.failed) {
        if (b.data) OPENSSL_cleanse(b.data, b.capacity);
        free(b.data);
        return NULL;
    }
    *length = b.length;
    return b.data;
}
static YDAccessResult result(int status, const char *code) {
    return (YDAccessResult){.status = status, .code = code};
}
static YDAccessStateRole *role_at(YDAccessState *s, const char *name, size_t *index) {
    for (size_t i = 0; i < s->role_count; i++)
        if (!strcmp(s->roles[i].name, name)) { *index = i; return &s->roles[i]; }
    return NULL;
}
static YDAccessStatePrincipal *principal_at(YDAccessState *s, const char *name, size_t *index) {
    for (size_t i = 0; i < s->principal_count; i++)
        if (!strcmp(s->principals[i].name, name)) { *index = i; return &s->principals[i]; }
    return NULL;
}
static bool op_is(const YDValue *v, const char *op) {
    const char *text = string(yd_get(v, "op"));
    return text && !strcmp(text, op);
}
static YDAccessResult role_put(YDAccessState *s, const char *name, const YDValue *v) {
    static const char *const keys[] = {"op", "read", "write"};
    YDAccessStateRole role = {0};
    if (v->count != 3 || !only(v, keys, 3) || !op_is(v, "role_put"))
        return result(400, "invalid_access_command");
    if (!names(yd_get(v, "read"), role.read, YD_ACCESS_STATE_GRANTS, &role.reads, true) ||
        !names(yd_get(v, "write"), role.write, YD_ACCESS_STATE_GRANTS, &role.writes, true) ||
        (!role.reads && !role.writes))
        return result(400, "invalid_role");
    memcpy(role.name, name, strlen(name) + 1);
    size_t index = 0;
    YDAccessStateRole *old = role_at(s, name, &index);
    if (old) { *old = role; return result(200, "updated"); }
    if (s->role_count == YD_ACCESS_STATE_ROLES) return result(413, "access_role_limit");
    s->roles[s->role_count++] = role;
    return result(201, "created");
}
static YDAccessResult role_delete(YDAccessState *s, const char *name, const YDValue *v) {
    static const char *const keys[] = {"op"};
    if (v->count != 1 || !only(v, keys, 1) || !op_is(v, "role_delete"))
        return result(400, "invalid_access_command");
    size_t index = 0;
    if (!role_at(s, name, &index)) return result(404, "role_not_found");
    for (size_t i = 0; i < s->principal_count; i++)
        for (size_t j = 0; j < s->principals[i].role_count; j++)
            if (!strcmp(s->principals[i].roles[j], name)) return result(409, "role_in_use");
    memmove(&s->roles[index], &s->roles[index + 1],
        (s->role_count - index - 1) * sizeof(s->roles[0]));
    s->role_count--;
    memset(&s->roles[s->role_count], 0, sizeof(s->roles[0]));
    return result(200, "deleted");
}
static YDAccessResult principal_put(YDAccessState *s, const char *name, const YDValue *v) {
    static const char *const keys[] = {"op", "roles", "verifier", "field_permissions"};
    if (!only(v, keys, 4) || !op_is(v, "principal_put"))
        return result(400, "invalid_access_command");
    YDAccessStatePrincipal fresh = {0};
    /* Reuse the stored-principal parser after removing the command verb. */
    YDValue view = *v;
    char *stored_keys[4];
    YDValue *stored_items[4];
    size_t n = 0;
    for (size_t i = 0; i < v->count; i++)
        if (strcmp(v->keys[i], "op")) {
            stored_keys[n] = v->keys[i];
            stored_items[n++] = v->items[i];
        }
    view.keys = stored_keys;
    view.items = stored_items;
    view.count = n;
    if (!principal_parse(&view, &fresh, true)) {
        principal_clear(&fresh);
        return result(400, "invalid_principal");
    }
    memcpy(fresh.name, name, strlen(name) + 1);
    if (!roles_exist(s, &fresh)) {
        principal_clear(&fresh);
        return result(400, "unknown_role");
    }
    bool credential = yd_get(v, "verifier") != NULL;
    size_t index = 0;
    YDAccessStatePrincipal *old = principal_at(s, name, &index);
    if (old) {
        if (credential && CRYPTO_memcmp(old->verifier, fresh.verifier, 32)) {
            principal_clear(&fresh);
            return result(409, "principal_exists");
        }
        memcpy(fresh.verifier, old->verifier, 32);
        memcpy(fresh.previous, old->previous, 32);
        fresh.previous_expires_at = old->previous_expires_at;
        principal_clear(old);
        *old = fresh;
        return result(200, "updated");
    }
    if (!credential) {
        principal_clear(&fresh);
        return result(400, "credential_required");
    }
    if (verifier_used(s, fresh.verifier, SIZE_MAX)) {
        principal_clear(&fresh);
        return result(409, "token_conflict");
    }
    if (s->principal_count == YD_ACCESS_STATE_PRINCIPALS) {
        principal_clear(&fresh);
        return result(413, "access_principal_limit");
    }
    s->principals[s->principal_count++] = fresh;
    return result(201, "created");
}
static YDAccessResult principal_rotate(YDAccessState *s, const char *name, const YDValue *v) {
    static const char *const keys[] = {"op", "verifier", "previous_expires_at"};
    unsigned char verifier[32];
    const YDValue *expires = yd_get(v, "previous_expires_at");
    if (v->count != 3 || !only(v, keys, 3) || !op_is(v, "principal_rotate") || !expires ||
        expires->type != YD_INT || expires->number < 0 || expires->number > 253402300799.0L ||
        !yd_access_state_verifier_hex(string(yd_get(v, "verifier")), verifier))
        return result(400, "invalid_access_command");
    size_t index = 0;
    YDAccessStatePrincipal *p = principal_at(s, name, &index);
    YDAccessResult r = result(200, "rotated");
    if (!p) r = result(404, "principal_not_found");
    else if (!CRYPTO_memcmp(p->verifier, verifier, 32) ||
        (p->previous_expires_at && !CRYPTO_memcmp(p->previous, verifier, 32)) ||
        verifier_used(s, verifier, index))
        r = result(409, "token_conflict");
    else {
        int64_t until = (int64_t)expires->number;
        if (until) memcpy(p->previous, p->verifier, 32);
        else memset(p->previous, 0, 32);
        p->previous_expires_at = until;
        memcpy(p->verifier, verifier, 32);
    }
    OPENSSL_cleanse(verifier, sizeof(verifier));
    return r;
}
static YDAccessResult principal_delete(YDAccessState *s, const char *name, const YDValue *v) {
    static const char *const keys[] = {"op"};
    if (v->count != 1 || !only(v, keys, 1) || !op_is(v, "principal_delete"))
        return result(400, "invalid_access_command");
    size_t index = 0;
    YDAccessStatePrincipal *p = principal_at(s, name, &index);
    if (!p) return result(404, "principal_not_found");
    principal_clear(p);
    memmove(&s->principals[index], &s->principals[index + 1],
        (s->principal_count - index - 1) * sizeof(s->principals[0]));
    s->principal_count--;
    memset(&s->principals[s->principal_count], 0, sizeof(s->principals[0]));
    return result(200, "deleted");
}
YDAccessResult yd_access_state_apply(YDAccessState *s, YDAccessOperation operation,
    const char *name, const unsigned char *command, size_t length) {
    if (!s || !valid_name(name) || !command || !length || length > YD_ACCESS_COMMAND_BYTES)
        return result(400, "invalid_access_command");
    char error[128];
    YDValue *v = yd_parse_sized(command, length, YD_ACCESS_COMMAND_BYTES, error, sizeof(error));
    if (!v || v->type != YD_MAP) {
        yd_free(v);
        return result(400, "invalid_access_command");
    }
    /* Apply to a private copy so every rejection leaves the state untouched. */
    YDAccessState *copy = yd_access_state_new();
    if (!copy) { yd_free(v); return result(503, "allocation_failed"); }
    *copy = *s;
    for (size_t i = 0; i < copy->principal_count; i++) {
        copy->principals[i].fields = NULL;
        if (s->principals[i].fields && !(copy->principals[i].fields = yd_clone(s->principals[i].fields))) {
            yd_access_state_free(copy);
            yd_free(v);
            return result(503, "allocation_failed");
        }
    }
    YDAccessResult r = operation == YD_ACCESS_ROLE_PUT ? role_put(copy, name, v) :
        operation == YD_ACCESS_ROLE_DELETE ? role_delete(copy, name, v) :
        operation == YD_ACCESS_PRINCIPAL_PUT ? principal_put(copy, name, v) :
        operation == YD_ACCESS_PRINCIPAL_ROTATE ? principal_rotate(copy, name, v) :
        operation == YD_ACCESS_PRINCIPAL_DELETE ? principal_delete(copy, name, v) :
        result(400, "invalid_access_command");
    yd_free(v);
    if (r.status == 200 || r.status == 201) {
        if (copy->version >= 9007199254740991ULL) {
            yd_access_state_free(copy);
            return result(413, "access_version_limit");
        }
        copy->version++;
        for (size_t i = 0; i < s->principal_count; i++) yd_free(s->principals[i].fields);
        *s = *copy;
        OPENSSL_cleanse(copy, sizeof(*copy));
        free(copy);
        return r;
    }
    yd_access_state_free(copy);
    return r;
}
