#define _POSIX_C_SOURCE 200809L
#include "access_internal.h"
#include "access_state.h"
#include "../snapshot.h"
#include "../aggregate.h"
#include <errno.h>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define POLICY_LIMIT (128U * 1024U)
#define ROLE_LIMIT YD_ACCESS_ROLE_LIMIT
#define PRINCIPAL_LIMIT YD_ACCESS_PRINCIPAL_LIMIT
#define GRANT_LIMIT YD_ACCESS_GRANT_LIMIT
#define TOKEN_LIMIT 512U
typedef YDAccessRole Role;
typedef struct YDAccessPrincipal Principal;
/* Published runtime snapshots are immutable. A thread pins the snapshot it
 * authenticated against until its next runtime authentication, so principal
 * handles stay valid for the whole request on that thread. Superseded
 * snapshots are freed once no thread pins them. */
struct YDAccessRuntime {
    pthread_mutex_t lock;
    YDAccess *current, *live;
    atomic_bool fields;
};
static _Thread_local YDAccess *pinned;
static void wipe(void *data, size_t length) {
    volatile unsigned char *p = data;
    while (length--) *p++ = 0;
}
bool yd_access_secure_equal(const char *a, size_t an, const char *b, size_t bn) {
    size_t maximum = an > bn ? an : bn;
    size_t different = an ^ bn;
    for (size_t i = 0; i < maximum; i++)
        different |= (unsigned char)(i < an ? a[i] : 0) ^ (unsigned char)(i < bn ? b[i] : 0);
    return different == 0;
}
char *yd_access_read_private(const char *path, size_t maximum, size_t *length) {
    int fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return NULL;
    struct stat st;
    /* Preserve systemd LoadCredential's private 0440 profile. */
    mode_t forbidden = S_IXUSR | S_IWGRP | S_IXGRP | S_IRWXO;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || (st.st_mode & forbidden) ||
        st.st_size < 1 || (uint64_t)st.st_size > maximum) { close(fd); return NULL; }
    size_t wanted = (size_t)st.st_size, used = 0;
    char *text = malloc(wanted + 1);
    if (!text) { close(fd); return NULL; }
    bool valid = true;
    while (used < wanted) {
        ssize_t n = read(fd, text + used, wanted - used);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { valid = false; break; }
        used += (size_t)n;
    }
    char extra;
    ssize_t end;
    do { end = read(fd, &extra, 1); } while (end < 0 && errno == EINTR);
    close(fd);
    if (!valid || end != 0) { wipe(text, wanted); free(text); return NULL; }
    text[used] = 0; *length = used; return text;
}
char *yd_access_read_token(const char *path, size_t *length, char *error, size_t error_length) {
    size_t size = 0;
    char *text = yd_access_read_private(path, TOKEN_LIMIT, &size);
    if (text) {
        if (size && text[size-1] == '\n') { size--; if (size && text[size-1] == '\r') size--; }
        bool valid = size >= 32;
        for (size_t i = 0; i < size; i++)
            if ((unsigned char)text[i] < 0x21 || (unsigned char)text[i] > 0x7e) valid = false;
        if (valid) { text[size] = 0; *length = size; return text; }
        wipe(text, size); free(text);
    }
    snprintf(error, error_length, "authentication token file is invalid"); return NULL;
}
static void snapshot_free(YDAccess *s) {
    if (!s) return;
    for (size_t i = 0; i < s->principal_count; i++) {
        yd_field_policy_free(s->principals[i].fields);
        OPENSSL_cleanse(&s->principals[i], sizeof(s->principals[i]));
    }
    free(s);
}
static void runtime_free(YDAccessRuntime *r) {
    if (!r) return;
    /* Every serving thread has joined; only this thread's pin can remain. */
    if (pinned && pinned->parent == r) pinned = NULL;
    for (YDAccess *s = r->live, *next; s; s = next) {
        next = s->next;
        snapshot_free(s);
    }
    (void)pthread_mutex_destroy(&r->lock);
    free(r);
}
void yd_access_free(YDAccess *access) {
    if (!access) return;
    runtime_free(access->runtime);
    yd_oidc_free(access->oidc);
    for (size_t i = 0; i < access->principal_count; i++) {
        Principal *p = &access->principals[i];
        yd_field_policy_free(p->fields);
        if (p->token) { wipe(p->token, p->length); free(p->token); }
    }
    wipe(access, sizeof(*access)); free(access);
}
YDAccess *yd_access_new_empty(void) { return calloc(1, sizeof(YDAccess)); }
bool yd_access_runtime_enable(YDAccess *a) {
    if (!a || a->runtime || a->parent) return false;
    YDAccessRuntime *r = calloc(1, sizeof(*r));
    YDAccess *empty = r ? calloc(1, sizeof(*empty)) : NULL;
    if (!empty || pthread_mutex_init(&r->lock, NULL)) { free(empty); free(r); return false; }
    empty->parent = r;
    r->current = r->live = empty;
    atomic_init(&r->fields, false);
    a->runtime = r;
    return true;
}
bool yd_access_runtime_enabled(const YDAccess *a) { return a && a->runtime; }
bool yd_access_runtime_verifier(const char *token, size_t length, unsigned char out[32]) {
    static const unsigned char domain[] = "yamora-runtime-access-token-v1";
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    unsigned n = 0;
    bool valid = context && token && EVP_DigestInit_ex(context, EVP_sha256(), NULL) == 1 &&
        EVP_DigestUpdate(context, domain, sizeof(domain)) == 1 &&
        EVP_DigestUpdate(context, token, length) == 1 &&
        EVP_DigestFinal_ex(context, out, &n) == 1 && n == 32;
    EVP_MD_CTX_free(context);
    if (!valid) OPENSSL_cleanse(out, 32);
    return valid;
}
static bool static_name(const YDAccess *a, const char *name, bool role) {
    if (role) {
        for (size_t i = 0; i < a->role_count; i++) if (!strcmp(a->roles[i].name, name)) return true;
    } else {
        for (size_t i = 0; i < a->principal_count; i++)
            if (!strcmp(a->principals[i].name, name)) return true;
    }
    return false;
}
bool yd_access_static_name(const YDAccess *a, const char *name, bool role) {
    return a && name && static_name(a, name, role);
}
bool yd_access_static_token_matches(const YDAccess *a, const unsigned char verifier[32]) {
    bool found = false;
    unsigned char candidate[32];
    if (a && verifier) for (size_t i = 0; i < a->principal_count; i++)
        if (a->principals[i].token && yd_access_runtime_verifier(a->principals[i].token,
                a->principals[i].length, candidate))
            found |= CRYPTO_memcmp(candidate, verifier, 32) == 0;
    OPENSSL_cleanse(candidate, sizeof(candidate));
    return found;
}
static bool compile(const YDAccess *parent, const YDAccessState *state, YDAccess *s,
    char *error, size_t length) {
    if (state->role_count > ROLE_LIMIT || state->principal_count > PRINCIPAL_LIMIT) return false;
    for (size_t i = 0; i < state->role_count; i++) {
        const YDAccessStateRole *from = &state->roles[i];
        Role *role = &s->roles[i];
        if (static_name(parent, from->name, true) || from->reads > GRANT_LIMIT ||
            from->writes > GRANT_LIMIT) return false;
        memcpy(role->name, from->name, sizeof(role->name));
        memcpy(role->read, from->read, from->reads * sizeof(role->read[0]));
        memcpy(role->write, from->write, from->writes * sizeof(role->write[0]));
        role->reads = from->reads;
        role->writes = from->writes;
        s->role_count++;
    }
    for (size_t i = 0; i < state->principal_count; i++) {
        const YDAccessStatePrincipal *from = &state->principals[i];
        Principal *p = &s->principals[i];
        s->principal_count++;
        if (static_name(parent, from->name, false) || !from->role_count) return false;
        memcpy(p->name, from->name, sizeof(p->name));
        for (size_t j = 0; j < from->role_count; j++) {
            size_t k = 0;
            while (k < s->role_count && strcmp(s->roles[k].name, from->roles[j])) k++;
            if (k == s->role_count || (p->roles & (UINT64_C(1) << k))) return false;
            p->roles |= UINT64_C(1) << k;
        }
        memcpy(p->verifier, from->verifier, 32);
        memcpy(p->previous, from->previous, 32);
        p->previous_expires_at = from->previous_expires_at;
        p->runtime = true;
        if (from->fields && !(p->fields = yd_field_policy_new(from->fields, error, length)))
            return false;
        if (yd_access_static_token_matches(parent, p->verifier) ||
            (p->previous_expires_at && yd_access_static_token_matches(parent, p->previous)))
            return false;
    }
    return true;
}
bool yd_access_runtime_publish(YDAccess *a, const YDAccessState *state, char *error,
    size_t length) {
    if (!a || !a->runtime || !state) return false;
    YDAccess *s = calloc(1, sizeof(*s));
    if (!s) return false;
    bool fields = false;
    if (!compile(a, state, s, error, length)) {
        snapshot_free(s);
        snprintf(error, length, "runtime access state conflicts with the static policy or is invalid");
        return false;
    }
    for (size_t i = 0; i < s->principal_count; i++) fields |= s->principals[i].fields != NULL;
    YDAccessRuntime *r = a->runtime;
    s->parent = r;
    pthread_mutex_lock(&r->lock);
    YDAccess *old = r->current;
    s->next = r->live;
    r->live = s;
    r->current = s;
    atomic_store(&r->fields, fields);
    if (old && !old->references) {
        for (YDAccess **at = &r->live; *at; at = &(*at)->next)
            if (*at == old) { *at = old->next; break; }
        snapshot_free(old);
    }
    pthread_mutex_unlock(&r->lock);
    return true;
}
/* Called with the registry lock held. */
static void release_locked(YDAccessRuntime *r, YDAccess *s) {
    if (s->references) s->references--;
    if (s->references || s == r->current) return;
    for (YDAccess **at = &r->live; *at; at = &(*at)->next)
        if (*at == s) { *at = s->next; break; }
    snapshot_free(s);
}
static YDAccess *runtime_pin(YDAccessRuntime *r) {
    pthread_mutex_lock(&r->lock);
    YDAccess *s = r->current, *old = pinned;
    if (old != s) {
        s->references++;
        pinned = s;
        if (old && old->parent == r) release_locked(r, old);
    }
    pthread_mutex_unlock(&r->lock);
    return s;
}
void yd_access_runtime_unpin(const YDAccess *a) {
    if (!a || !a->runtime || !pinned || pinned->parent != a->runtime) return;
    YDAccessRuntime *r = a->runtime;
    pthread_mutex_lock(&r->lock);
    YDAccess *old = pinned;
    pinned = NULL;
    release_locked(r, old);
    pthread_mutex_unlock(&r->lock);
}
static const Principal *runtime_identify(const YDAccess *a, const char *token, size_t size) {
    if (!a->runtime || size < 32 || size > TOKEN_LIMIT) return NULL;
    unsigned char verifier[32];
    if (!yd_access_runtime_verifier(token, size, verifier)) return NULL;
    YDAccess *s = runtime_pin(a->runtime);
    time_t now = time(NULL);
    const Principal *found = NULL;
    /* Constant-time per comparison and no early exit across principals. */
    for (size_t i = 0; i < s->principal_count; i++) {
        const Principal *p = &s->principals[i];
        bool current = CRYPTO_memcmp(verifier, p->verifier, 32) == 0;
        bool previous = p->previous_expires_at && now != (time_t)-1 &&
            (int64_t)now < p->previous_expires_at &&
            CRYPTO_memcmp(verifier, p->previous, 32) == 0;
        if (current || previous) found = p;
    }
    OPENSSL_cleanse(verifier, sizeof(verifier));
    return found;
}
static const char *string(const YDValue *v) { return v && v->type == YD_STRING ? v->scalar : NULL; }
static bool names(const YDValue *v, char out[GRANT_LIMIT][129], size_t *count) {
    if (!v || v->type != YD_ARRAY || v->count > GRANT_LIMIT) return false;
    for (size_t i = 0; i < v->count; i++) {
        const char *name = string(v->items[i]);
        if (!name || !yamldb_valid_name(name) || !strcmp(name, "yamldb-system")) return false;
        for (size_t j = 0; j < i; j++) if (!strcmp(out[j], name)) return false;
        strcpy(out[i], name);
    }
    *count = v->count; return true;
}
static bool certificate_pin(const YDValue *v, const char *source, size_t size,
                             unsigned char out[32]) {
    const char *s = string(v);
    /* Check the original scalar too: YAML plain/numeric/block scalars and
     * escapes must not create alternate spellings of the fixed pin profile. */
    if (!s || strlen(s) != 64 || v->start > v->end || v->end > size ||
        v->end - v->start != 66 ||
        (source[v->start] != '\'' && source[v->start] != '"') ||
        source[v->end - 1] != source[v->start] || memcmp(source + v->start + 1, s, 64))
        return false;
    for (size_t i = 0; i < 64; i++) {
        unsigned char c = (unsigned char)s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
        unsigned value = c <= '9' ? c - '0' : c - 'a' + 10;
        if (!(i % 2)) out[i / 2] = (unsigned char)(value << 4);
        else out[i / 2] |= (unsigned char)value;
    }
    return true;
}
static YDOIDC *load_oidc(const YDValue *spec, char *error, size_t length) {
    if (!spec || spec->type != YD_MAP || spec->count != 7) return NULL;
    const char *issuer = string(yd_get(spec, "issuer"));
    const char *audience = string(yd_get(spec, "audience"));
    const char *file = string(yd_get(spec, "jwks_file"));
    const char *algorithm = string(yd_get(spec, "algorithm"));
    const char *scope = string(yd_get(spec, "required_scope"));
    const YDValue *skew = yd_get(spec, "clock_skew_seconds");
    const YDValue *lifetime = yd_get(spec, "max_token_lifetime_seconds");
    if (!issuer || !audience || !scope || !file || file[0] != '/' ||
        strlen(file) > 4096 || !algorithm || strcmp(algorithm, "RS256") ||
        !skew || skew->type != YD_INT || skew->number < 0 || skew->number > 120 ||
        !lifetime || lifetime->type != YD_INT || lifetime->number < 60 ||
        lifetime->number > 3600) return NULL;
    size_t size = 0;
    char *jwks = yd_access_read_private(file, YD_OIDC_JWKS_MAX_BYTES, &size);
    if (!jwks) return NULL;
    YDOIDCOptions options = {.issuer = issuer, .audience = audience,
        .required_scope = scope, .clock_skew_seconds = (unsigned)skew->number,
        .max_token_lifetime_seconds = (unsigned)lifetime->number};
    YDOIDC *oidc = yd_oidc_new(&options, (const unsigned char *)jwks, size, error, length);
    free(jwks);
    return oidc;
}
static bool oidc_principal(Principal *principal, const YDValue *spec) {
    if (!spec || spec->type != YD_MAP || spec->count != 2) return false;
    const char *subject = string(yd_get(spec, "subject"));
    const char *client = string(yd_get(spec, "client_id"));
    if (!subject || !*subject || strlen(subject) > 255 ||
        !client || !*client || strlen(client) > 255) return false;
    strcpy(principal->oidc_subject, subject);
    strcpy(principal->oidc_client, client);
    return true;
}
YDAccess *yd_access_load(const char *path, char *error, size_t length) {
    size_t size = 0;
    char *text = yd_access_read_private(path, POLICY_LIMIT, &size);
    YDValue *spec = text ? yd_parse_sized((const unsigned char *)text, size, POLICY_LIMIT, error, length) : NULL;
    YDAccess *a = NULL;
    const YDValue *version = yd_get(spec, "version"), *roles = yd_get(spec, "roles"), *principals = yd_get(spec, "principals");
    if (!spec || spec->type != YD_MAP || !version || version->type != YD_INT ||
        (version->number < 1 || version->number > 4) ||
        spec->count != ((version->number == 3 || (version->number == 4 && yd_get(spec, "oidc"))) ? 4U : 3U) ||
        !roles || roles->type != YD_MAP || !roles->count || roles->count > ROLE_LIMIT ||
        !principals || principals->type != YD_MAP || !principals->count || principals->count > PRINCIPAL_LIMIT)
        goto invalid;
    a = calloc(1, sizeof(*a));
    if (!a) goto invalid;
    if ((version->number == 3 || (version->number == 4 && yd_get(spec, "oidc"))) &&
        !(a->oidc = load_oidc(yd_get(spec, "oidc"), error, length)))
        goto invalid;
    a->role_count = roles->count; a->principal_count = principals->count;
    for (size_t i = 0; i < roles->count; i++) {
        const YDValue *r = roles->items[i]; Role *role = &a->roles[i];
        if (!yamldb_valid_name(roles->keys[i]) || r->type != YD_MAP || r->count != 2 ||
            !names(yd_get(r, "read"), role->read, &role->reads) ||
            !names(yd_get(r, "write"), role->write, &role->writes) || (!role->reads && !role->writes)) goto invalid;
        strcpy(role->name, roles->keys[i]);
    }
    size_t oidc_principals = 0;
    for (size_t i = 0; i < principals->count; i++) {
        const YDValue *p = principals->items[i], *grants = yd_get(p, "roles");
        const YDValue *token = yd_get(p, "token_file"), *pins = yd_get(p, "tls_client_sha256");
        const YDValue *oidc = yd_get(p, "oidc");
        const YDValue *fields = yd_get(p, "field_permissions");
        Principal *principal = &a->principals[i];
        if (!yamldb_valid_name(principals->keys[i]) || p->type != YD_MAP || p->count != (fields ? 3U : 2U) ||
            (unsigned)(token != NULL) + (unsigned)(pins != NULL) + (unsigned)(oidc != NULL) != 1 ||
            (pins && version->number == 1) || (oidc && !a->oidc) ||
            (fields && version->number != 4) ||
            !grants || grants->type != YD_ARRAY ||
            !grants->count || grants->count > ROLE_LIMIT) goto invalid;
        strcpy(principal->name, principals->keys[i]);
        if (fields && !(principal->fields = yd_field_policy_new(fields, error, length))) goto invalid;
        for (size_t j = 0; j < grants->count; j++) {
            const char *name = string(grants->items[j]); size_t k = 0;
            if (!name) goto invalid;
            while (k < a->role_count && strcmp(name, a->roles[k].name)) k++;
            if (k == a->role_count || (principal->roles & (UINT64_C(1) << k))) goto invalid;
            principal->roles |= UINT64_C(1) << k;
        }
        if (token) {
            const char *file = string(token);
            if (!file || file[0] != '/' || strlen(file) > 4096) goto invalid;
            principal->token = yd_access_read_token(file, &principal->length, error, length);
            if (!principal->token) goto invalid;
            for (size_t j = 0; j < i; j++)
                if (a->principals[j].token && yd_access_secure_equal(principal->token,
                    principal->length, a->principals[j].token, a->principals[j].length)) goto invalid;
        } else if (pins) {
            if (pins->type != YD_ARRAY || !pins->count || pins->count > 2) goto invalid;
            for (size_t j = 0; j < pins->count; j++) {
                unsigned char *pin = principal->certificates[j];
                if (!certificate_pin(pins->items[j], text, size, pin)) goto invalid;
                for (size_t k = 0; k <= i; k++)
                    for (size_t n = 0; n < a->principals[k].certificate_count; n++)
                        if (!memcmp(pin, a->principals[k].certificates[n], 32)) goto invalid;
                principal->certificate_count++;
            }
        } else {
            if (!oidc_principal(principal, oidc)) goto invalid;
            for (size_t j = 0; j < i; j++)
                if (!strcmp(a->principals[j].oidc_subject, principal->oidc_subject) &&
                    !strcmp(a->principals[j].oidc_client, principal->oidc_client)) goto invalid;
            oidc_principals++;
        }
    }
    if (a->oidc && !oidc_principals) goto invalid;
    free(text); yd_free(spec); return a;
invalid:
    free(text); yd_free(spec); yd_access_free(a); snprintf(error, length, "invalid access policy or credential file"); return NULL;
}
bool yd_access_conflicts(const YDAccess *a, const char *token, size_t length) {
    bool found = false;
    if (a && token) for (size_t i = 0; i < a->principal_count; i++)
        if (a->principals[i].token)
            found |= yd_access_secure_equal(token, length, a->principals[i].token, a->principals[i].length);
    unsigned char verifier[32];
    if (a && a->runtime && token && yd_access_runtime_verifier(token, length, verifier)) {
        pthread_mutex_lock(&a->runtime->lock);
        const YDAccess *s = a->runtime->current;
        for (size_t i = 0; i < s->principal_count; i++) {
            found |= CRYPTO_memcmp(verifier, s->principals[i].verifier, 32) == 0;
            found |= s->principals[i].previous_expires_at &&
                CRYPTO_memcmp(verifier, s->principals[i].previous, 32) == 0;
        }
        pthread_mutex_unlock(&a->runtime->lock);
        OPENSSL_cleanse(verifier, sizeof(verifier));
    }
    return found;
}
static const Principal *identify(const YDAccess *a, const char *authorization) {
    if (!a || !authorization || strncmp(authorization, "Bearer ", 7)) return NULL;
    const char *token = authorization + 7; size_t size = strlen(token);
    return yd_access_identify_token(a, token, size);
}
const YDAccessPrincipal *yd_access_identify_token(const YDAccess *a, const char *token,
                                                size_t size) {
    if (!a || !token) return NULL;
    const Principal *found = NULL;
    for (size_t i = 0; i < a->principal_count; i++)
        if (a->principals[i].token && yd_access_secure_equal(token, size,
            a->principals[i].token, a->principals[i].length)) found = &a->principals[i];
    /* Static credentials win; creation and startup reject equal runtime tokens. */
    return found ? found : runtime_identify(a, token, size);
}
bool yd_access_principal_runtime(const YDAccess *a, const YDAccessPrincipal *p) {
    const YDAccess *s = pinned;
    if (!a || !p || !a->runtime || !s || s->parent != a->runtime) return false;
    for (size_t i = 0; i < s->principal_count; i++)
        if (p == &s->principals[i]) return true;
    return false;
}
const YDAccessPrincipal *yd_access_identify_local(const YDAccess *a, const char *name) {
    if (a && name) for (size_t i = 0; i < a->principal_count; i++)
        if (!strcmp(a->principals[i].name, name)) return &a->principals[i];
    return NULL;
}
bool yd_access_has_oidc(const YDAccess *a) { return a && a->oidc; }
int yd_access_authenticate_oidc(const YDAccess *a, const char *jwt, size_t size,
                              int64_t now, const YDAccessPrincipal **out) {
    if (out) *out = NULL;
    if (!a || !a->oidc || !out) return 503;
    YDOIDCIdentity identity;
    YDOIDCResult result = yd_oidc_verify(a->oidc, jwt, size, now, &identity);
    if (result == YD_OIDC_ERROR) return 503;
    if (result != YD_OIDC_VALID) return 401;
    for (size_t i = 0; i < a->principal_count; i++) {
        const Principal *principal = &a->principals[i];
        if (*principal->oidc_subject && !strcmp(principal->oidc_subject, identity.subject) &&
            !strcmp(principal->oidc_client, identity.client_id)) {
            if (!identity.required_scope_present) return 403;
            *out = principal;
            return 0;
        }
    }
    return 401;
}
bool yd_access_has_certificate_principals(const YDAccess *a) {
    if (a) for (size_t i = 0; i < a->principal_count; i++)
        if (a->principals[i].certificate_count) return true;
    return false;
}
const YDAccessPrincipal *yd_access_identify_certificate(const YDAccess *a,
                                                       const unsigned char leaf_sha256[32]) {
    if (a && leaf_sha256) for (size_t i = 0; i < a->principal_count; i++)
        for (size_t j = 0; j < a->principals[i].certificate_count; j++)
            if (!memcmp(leaf_sha256, a->principals[i].certificates[j], 32)) return &a->principals[i];
    return NULL;
}
/* The policy whose roles a handle uses: the static policy itself, or the
 * runtime snapshot this thread pinned when it authenticated the handle. */
static const YDAccess *owner(const YDAccess *a, const Principal *p) {
    /* Equality, not ordering/subtraction or dereference of a foreign pointer. */
    if (a && p) for (size_t i = 0; i < a->principal_count; i++)
        if (p == &a->principals[i]) return a;
    const YDAccess *s = pinned;
    if (a && p && a->runtime && s && s->parent == a->runtime)
        for (size_t i = 0; i < s->principal_count; i++)
            if (p == &s->principals[i]) return s;
    return NULL;
}
static bool owns(const YDAccess *a, const Principal *p) { return owner(a, p) != NULL; }
const char *yd_access_principal_name(const YDAccess *a, const YDAccessPrincipal *p) {
    return owns(a, p) ? p->name : NULL;
}
bool yd_access_has_field_principals(const YDAccess *a) {
    if (a) for (size_t i = 0; i < a->principal_count; i++)
        if (a->principals[i].fields) return true;
    return a && a->runtime && atomic_load(&a->runtime->fields);
}
bool yd_access_principal_masked(const YDAccess *a, const YDAccessPrincipal *p) {
    return owns(a, p) && p->fields;
}
int yd_access_principal_preconditions(const YDAccess *a, const YDAccessPrincipal *p,
                                      bool match, bool none) {
    if (!owns(a, p)) return 401;
    /* Native ETags fingerprint the complete authored source. A matching-value
     * precondition is a hidden-value oracle even when no ETag is returned.
     * Creation preconditions also reveal existence to write-only masks. */
    return p->fields && (match || none) ? 403 : 0;
}
static bool grant(const YDAccess *a, const Principal *p, const char *collection, bool write) {
    if (!yamldb_valid_name(collection) || !strcmp(collection, "yamldb-system")) return false;
    for (size_t i = 0; i < a->role_count; i++) if (p->roles & (UINT64_C(1) << i)) {
        const Role *r = &a->roles[i]; size_t count = write ? r->writes : r->reads;
        for (size_t j = 0; j < count; j++) if (!strcmp(write ? r->write[j] : r->read[j], collection)) return true;
    }
    return false;
}
static bool masked_document(const Principal *p, const char *collection, const char *document,
    const char *method, const YDValue *patch) {
    if (!p->fields) return true;
    char error[128];
    if (!strcmp(method, "PATCH"))
        return yd_field_policy_patch(p->fields, collection, document, patch, error, sizeof(error));
    bool write = !strcmp(method, "PUT") || !strcmp(method, "DELETE");
    return yd_field_policy_allows(p->fields, collection, document, "", write);
}
/* A filter update reads the collection to choose its targets and reports
 * match counts, so a masked principal needs collection-wide read over the
 * filter, collection-wide authority over the update and, to upsert,
 * whole-document write over the new document. */
static bool masked_filter_update(const Principal *p, const char *collection, const YDValue *op) {
    if (!p->fields) return true;
    const YDValue *filter = yd_get(op, "filter"), *update = yd_get(op, "update"),
        *upsert = yd_get(op, "upsert");
    if (!filter || filter->type != YD_MAP || yd_get(op, "etag") || yd_get(op, "create_only"))
        return false;
    char *keys[2] = {"filter", "count_only"}, error[128];
    YDValue count = {.type = YD_BOOL, .boolean = true};
    YDValue *items[2] = {(YDValue *)filter, &count};
    YDValue spec = {.type = YD_MAP, .keys = keys, .items = items, .count = 2};
    if (!yd_field_policy_query(p->fields, collection, NULL, &spec, "0000000000000000", error,
            sizeof(error)) ||
        !yd_field_policy_patch(p->fields, collection, NULL, update, error, sizeof(error)))
        return false;
    if (!upsert || (upsert->type == YD_BOOL && !upsert->boolean)) return true;
    const char *document = string(yd_get(op, "document"));
    return document && yamldb_valid_name(document) &&
        yd_field_policy_allows(p->fields, collection, document, "", true);
}
bool yd_access_writer(const YDAccess *a, const char *authorization) {
    return yd_access_principal_writer(a, identify(a, authorization));
}
bool yd_access_principal_writer(const YDAccess *a, const YDAccessPrincipal *p) {
    const YDAccess *o = owner(a, p);
    if (o) for (size_t i = 0; i < o->role_count; i++)
        if ((p->roles & (UINT64_C(1) << i)) && o->roles[i].writes) return true;
    return false;
}
int yd_access_request(const YDAccess *a, const char *authorization, const char *method,
                       const char *target, const unsigned char *body, size_t length) {
    return yd_access_principal_request(a, identify(a, authorization), method, target, body, length);
}
int yd_access_principal_request(const YDAccess *a, const YDAccessPrincipal *p, const char *method,
                                const char *target, const unsigned char *body, size_t length) {
    const YDAccess *o = owner(a, p);
    if (!o) return 401;
    a = o; /* Grants come only from the policy that authenticated the handle. */
    if (!method || !target || (length && !body)) return 403;
    bool read = !strcmp(method, "GET") || !strcmp(method, "HEAD");
    static const char policy_prefix[] = "/v1/schema-policies/";
    if (!strncmp(target, policy_prefix, sizeof(policy_prefix) - 1)) {
        /* A collection writer is never a policy administrator. The daemon
         * authenticates its separately configured administrative credential
         * before dispatch or durable receipt lookup. This rule applies equally
         * to static, certificate and OIDC principals selected by the caller. */
        const char *collection = target + sizeof(policy_prefix) - 1;
        return read && grant(a, p, collection, false) &&
            (!p->fields || yd_field_policy_allows(p->fields, collection, NULL, "", false)) ? 0 : 403;
    }
    if (read && !strcmp(target, "/v1/cluster/leader")) return 0;
    if (!strcmp(method, "POST")) {
        /* Vector search reads whole documents exactly like text search. */
        static const char *const prefixes[] = {"/v1/query/", "/v1/aggregate/", "/v1/search/",
                                               "/v1/vector-search/"};
        for (size_t i = 0; i < 4; i++) {
            size_t n = strlen(prefixes[i]);
            if (strncmp(target, prefixes[i], n)) continue;
            if (!grant(a, p, target + n, false)) return 403;
            if (p->fields) {
                char error[128];
                YDValue *spec = yd_parse_sized(body, length, YD_LARGE_REQUEST_LIMIT, error, sizeof(error));
                bool allowed = false;
                if (spec && !yd_get(spec, "revision") && !yd_get(spec, "after")) {
                    if (i == 0) {
                        /* Only preflight syntax/field dependencies. The actual
                         * disk handler validates its live snapshot. Global
                         * content-hash pins/cursors are denied for masks. */
                        allowed = yd_field_policy_query(p->fields, target + n, NULL, spec,
                            "0000000000000000", error, sizeof(error));
                    } else if (i == 1) allowed = yd_field_policy_aggregate(p->fields, target + n,
                        yd_get(spec, "pipeline"), error, sizeof(error));
                    else allowed = yd_field_policy_search(p->fields, target + n);
                }
                yd_free(spec);
                if (!allowed) return 403;
            }
            if (i != 1) return 0;
            /* Compile the entire supported shape before any collection access.
             * Never decide foreign permission by whether local rows match. The
             * daemon's generic administrative credential bypass stays intact. */
            char error[128];
            YDValue *spec = yd_parse_sized(body, length, YD_LARGE_REQUEST_LIMIT, error, sizeof(error));
            const YDValue *pipeline = yd_get(spec, "pipeline");
            bool has_lookup = false;
            if (pipeline && pipeline->type == YD_ARRAY)
                for (size_t j = 0; j < pipeline->count; j++)
                    has_lookup |= yd_get(pipeline->items[j], "$lookup") != NULL;
            if (!has_lookup) {
                /* Preserve legacy malformed-request 400s. The disk compiler
                 * rejects unsupported/nested pipelines before opening cursors;
                 * only a top-level lookup can access another collection. */
                yd_free(spec);
                return 0;
            }
            YDAggregate *aggregate = yd_aggregate_new(pipeline, error, sizeof(error));
            bool valid = aggregate != NULL;
            for (size_t lookup = 0; valid; lookup++) {
                const char *foreign = yd_aggregate_lookup_collection_at(aggregate, lookup);
                if (!foreign) break;
                valid = grant(a, p, foreign, false);
            }
            yd_aggregate_free(aggregate);
            yd_free(spec);
            return valid ? 0 : 403;
        }
        if (!strcmp(target, "/v1/transactions")) {
            char error[128];
            YDValue *spec = yd_parse_sized(body, length, YD_LARGE_REQUEST_LIMIT, error, sizeof(error));
            const YDValue *ops = yd_get(spec, "operations");
            bool valid = ops && ops->type == YD_ARRAY && ops->count && ops->count <= 128 &&
                (!p->fields || !yd_get(spec, "revision"));
            for (size_t i = 0; valid && i < ops->count; i++) {
                const char *collection = string(yd_get(ops->items[i], "collection"));
                valid = collection && grant(a, p, collection, true);
                if (valid && yd_get(ops->items[i], "filter")) {
                    /* Choosing targets by content is a read of the collection. */
                    valid = grant(a, p, collection, false) &&
                        masked_filter_update(p, collection, ops->items[i]);
                } else if (valid && p->fields) {
                    const YDValue *op = ops->items[i], *patch = yd_get(op, "patch");
                    const char *document = string(yd_get(op, "document"));
                    const YDValue *put = yd_get(op, "put"), *del = yd_get(op, "delete");
                    valid = document && yamldb_valid_name(document) &&
                        !yd_get(op, "etag") && !yd_get(op, "create_only") &&
                        (unsigned)(patch != NULL) + (unsigned)(put != NULL) + (unsigned)(del != NULL) == 1 &&
                        masked_document(p, collection, document, patch ? "PATCH" : put ? "PUT" : "DELETE", patch);
                }
            }
            yd_free(spec); return valid ? 0 : 403;
        }
    }
    if (strncmp(target, "/v1/collections/", 16) || strlen(target) > 1024) return 403;
    char copy[1025]; strcpy(copy, target + 16);
    char *query = strchr(copy, '?'); if (query) *query++ = 0;
    char *path = strchr(copy, '/'); if (!path) return 403;
    *path++ = 0;
    if (strcmp(path, "documents")) {
        if (strncmp(path, "documents/", 10) || !yamldb_valid_name(path + 10)) return 403;
    } else if (!read) return 403;
    bool write = !strcmp(method, "PUT") || !strcmp(method, "PATCH") || !strcmp(method, "DELETE");
    if ((!read && !write) || (write && query)) return 403;
    if (!grant(a, p, copy, write)) return 403;
    if (p->fields) {
        const char *document = !strcmp(path, "documents") ? NULL : path + 10;
        char error[128];
        YDValue *patch = !strcmp(method, "PATCH") ? yd_parse_sized(body, length,
            YD_LARGE_REQUEST_LIMIT, error, sizeof(error)) : NULL;
        bool allowed = masked_document(p, copy, document, method, patch);
        yd_free(patch);
        if (!allowed) return 403;
    }
    return 0;
}
