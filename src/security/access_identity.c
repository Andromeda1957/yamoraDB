#define _POSIX_C_SOURCE 200809L
#include "access_identity.h"
#include "access.h"
#include "identity.h"
#include "oidc_json.h"
#include <arpa/inet.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

typedef YDOIDCJSONNode Node;
typedef struct {
    YDAccessIdentityCategory category;
    const char *subject, *client, *local;
} Mapping;
struct YDAccessIdentity {
    YDOIDCJSON *document;
    YDIdentityEndpoint endpoints[8];
    YDIdentityNetwork network;
    Mapping mappings[64];
    size_t mapping_count;
    YDIdentityDiscovery discovery;
    YDOIDC *oidc;
    const char *audience, *scope, *client_id, *aws_url, *server_id, *ldap_origin;
    char *secret;
    size_t secret_length;
    YDIdentityKerberos *kerberos;
    pthread_mutex_t lock;
    bool lock_ready;
};
static const Node *get(const Node *n, const char *key) { return yd_oidc_json_get(n, key); }
static const char *string(const Node *n, size_t maximum) {
    if (!n || n->type != YD_OIDC_JSON_STRING || !n->length || n->length > maximum) return NULL;
    for (size_t i = 0; i < n->length; i++)
        if ((unsigned char)n->text[i] < 32 || (unsigned char)n->text[i] == 127) return NULL;
    return n->text;
}
static bool keys(const Node *n, const char *const *allowed, size_t count, size_t required) {
    if (!n || n->type != YD_OIDC_JSON_OBJECT || n->count < required || n->count > count) return false;
    for (const Node *p = n->first; p; p = p->next) {
        bool found = false;
        for (size_t i = 0; i < count; i++) if (!strcmp(p->name, allowed[i])) found = true;
        if (!found) return false;
    }
    for (size_t i = 0; i < required; i++) if (!get(n, allowed[i])) return false;
    return true;
}
static YDAccessIdentityCategory category(const char *s) {
    if (!s) return YD_ACCESS_IDENTITY_NONE;
    if (!strcmp(s, "oidc")) return YD_ACCESS_IDENTITY_OIDC;
    if (!strcmp(s, "aws")) return YD_ACCESS_IDENTITY_AWS;
    if (!strcmp(s, "ldap")) return YD_ACCESS_IDENTITY_LDAP;
    if (!strcmp(s, "kerberos")) return YD_ACCESS_IDENTITY_KERBEROS;
    return YD_ACCESS_IDENTITY_NONE;
}
static bool local_name(const char *s) {
    if (!s || !strcmp(s, "yamldb-system")) return false;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++)
        if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
            (*p >= '0' && *p <= '9') || *p == '_' || *p == '.' || *p == '-')) return false;
    return true;
}
static bool allowed_url(const YDAccessIdentity *a, const char *url, bool ldap) {
    const char *scheme = ldap ? "ldaps://" : "https://";
    if (!url || strncmp(url, scheme, strlen(scheme))) return false;
    const char *end = strchr(url + strlen(scheme), '/');
    size_t length = end ? (size_t)(end - url) : strlen(url);
    if (strpbrk(url, "\\#@") || (ldap && end)) return false;
    for (const unsigned char *p = (const unsigned char *)url; *p; p++)
        if (*p < 33 || *p > 126) return false;
    for (size_t i = 0; i < a->network.count; i++)
        if (strlen(a->endpoints[i].origin) == length &&
            !memcmp(a->endpoints[i].origin, url, length)) return true;
    return false;
}
static bool endpoint(YDIdentityEndpoint *out, const Node *n) {
    static const char *const fields[] = {"origin", "address", "ca_file", "timeout_ms"};
    if (!keys(n, fields, 4, 4)) return false;
    out->origin = string(get(n, "origin"), 280);
    out->address = string(get(n, "address"), 64);
    out->ca_file = string(get(n, "ca_file"), 4096);
    const Node *timeout = get(n, "timeout_ms");
    if (!out->origin || !out->address || !out->ca_file || out->ca_file[0] != '/' ||
        !timeout || timeout->type != YD_OIDC_JSON_NUMBER || timeout->length > 5) return false;
    unsigned ms = 0;
    for (size_t i = 0; i < timeout->length; i++) {
        if (timeout->text[i] < '0' || timeout->text[i] > '9') return false;
        ms = ms * 10 + (unsigned)(timeout->text[i] - '0');
    }
    if (!ms || ms > 10000) return false;
    out->timeout_ms = ms;
    unsigned char address[16];
    if (inet_pton(AF_INET, out->address, address) != 1 &&
        inet_pton(AF_INET6, out->address, address) != 1) return false;
    const char *host = NULL;
    if (!strncmp(out->origin, "https://", 8)) host = out->origin + 8;
    if (!strncmp(out->origin, "ldaps://", 8)) host = out->origin + 8;
    if (!host || strpbrk(host, "/?#@\\")) return false;
    const char *colon = strchr(host, ':');
    if (!colon || colon == host || colon - host > 253 || !colon[1]) return false;
    for (const char *p = host; p < colon; p++)
        if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
            (*p >= '0' && *p <= '9') || *p == '-' || *p == '.')) return false;
    unsigned port = 0;
    for (const char *p = colon + 1; *p; p++) {
        if (*p < '0' || *p > '9' || port > 6553) return false;
        port = port * 10 + (unsigned)(*p - '0');
    }
    if (!port || port > 65535) return false;
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    bool valid = ctx && SSL_CTX_load_verify_locations(ctx, out->ca_file, NULL) == 1;
    SSL_CTX_free(ctx); return valid;
}
static void destroy(YDAccessIdentity *a) {
    if (!a) return;
    yd_identity_kerberos_free(a->kerberos); yd_oidc_free(a->oidc);
    if (a->secret) { OPENSSL_cleanse(a->secret, a->secret_length); free(a->secret); }
    yd_oidc_json_free(a->document);
    if (a->lock_ready) pthread_mutex_destroy(&a->lock);
    OPENSSL_cleanse(a, sizeof(*a)); free(a);
}
static bool load_oidc(YDAccessIdentity *a, const Node *n) {
    static const char *const fields[] = {"issuer", "audience", "scope", "client_id", "client_secret_file"};
    if (!keys(n, fields, 5, 5)) return false;
    const char *issuer = string(get(n, "issuer"), 512);
    a->audience = string(get(n, "audience"), 256);
    a->scope = string(get(n, "scope"), 128);
    a->client_id = string(get(n, "client_id"), 255);
    const char *path = string(get(n, "client_secret_file"), 4096);
    if (!issuer || !a->audience || !a->scope || !a->client_id || !path || path[0] != '/') return false;
    a->secret = yd_access_read_private(path, 1024, &a->secret_length);
    if (!a->secret || memchr(a->secret, 0, a->secret_length)) return false;
    if (a->secret_length && a->secret[a->secret_length - 1] == '\n') a->secret[--a->secret_length] = 0;
    if (!a->secret_length || yd_identity_discover(&a->network, issuer, &a->discovery) != YD_IDENTITY_VALID ||
        !a->discovery.introspection_endpoint[0] || !a->discovery.revocation_endpoint[0]) return false;
    unsigned char jwks[YD_OIDC_JWKS_MAX_BYTES]; size_t length = 0;
    bool valid = yd_identity_jwks(&a->network, a->discovery.jwks_uri, jwks, sizeof(jwks), &length) == YD_IDENTITY_VALID;
    YDOIDCOptions options = {issuer, a->audience, a->scope, 0, 3600};
    if (valid) a->oidc = yd_oidc_new(&options, jwks, length, NULL, 0);
    OPENSSL_cleanse(jwks, sizeof(jwks)); return a->oidc != NULL;
}
static YDAccessIdentity *load(const char *path, bool offline) {
    if (!path || offline) return NULL;
    size_t length = 0;
    char *text = yd_access_read_private(path, 65536, &length);
    if (!text) return NULL;
    YDAccessIdentity *volatile a = calloc(1, sizeof(*a));
    bool valid = a && yd_oidc_json_parse((const unsigned char *)text, length, 2048, &a->document) == YD_OIDC_JSON_OK;
    OPENSSL_cleanse(text, length); free(text);
    if (!valid) { destroy(a); return NULL; }
    static const char *const root_fields[] = {"version", "endpoints", "mappings", "oidc", "aws", "ldap", "kerberos"};
    const Node *root = yd_oidc_json_root(a->document), *v = get(root, "version");
    if (!keys(root, root_fields, 7, 3) || !v || v->type != YD_OIDC_JSON_NUMBER || strcmp(v->text, "1")) goto fail;
    const Node *eps = get(root, "endpoints"), *maps = get(root, "mappings");
    if (!eps || eps->type != YD_OIDC_JSON_ARRAY || eps->count > 8 ||
        !maps || maps->type != YD_OIDC_JSON_ARRAY || !maps->count || maps->count > 64) goto fail;
    a->network = (YDIdentityNetwork){a->endpoints, eps->count};
    size_t i = 0;
    for (const Node *p = eps->first; p; p = p->next, i++) {
        if (!endpoint(&a->endpoints[i], p)) goto fail;
        for (size_t j = 0; j < i; j++) if (!strcmp(a->endpoints[j].origin, a->endpoints[i].origin)) goto fail;
    }
    const Node *n = get(root, "oidc");
    if (n && !load_oidc(a, n)) goto fail;
    n = get(root, "aws");
    if (n) {
        static const char *const f[] = {"url", "server_id"};
        if (!keys(n, f, 2, 2) || !(a->aws_url = string(get(n, "url"), 1024)) ||
            !(a->server_id = string(get(n, "server_id"), 255)) || !allowed_url(a, a->aws_url, false)) goto fail;
        const char *end = strchr(a->aws_url + 8, '/');
        if (end && strcmp(end, "/")) goto fail;
    }
    n = get(root, "ldap");
    if (n) {
        static const char *const f[] = {"origin"};
        if (!keys(n, f, 1, 1) || !(a->ldap_origin = string(get(n, "origin"), 280)) ||
            !allowed_url(a, a->ldap_origin, true)) goto fail;
    }
    n = get(root, "kerberos");
    if (n) {
        static const char *const f[] = {"principal", "keytab"};
        const char *principal = string(get(n, "principal"), 512), *keytab = string(get(n, "keytab"), 4096);
        size_t size = 0;
        if (!keys(n, f, 2, 2) || !principal || !keytab || keytab[0] != '/') goto fail;
        char *probe = yd_access_read_private(keytab, 65536, &size);
        if (!probe) goto fail;
        OPENSSL_cleanse(probe, size); free(probe);
        if (!(a->kerberos = yd_identity_kerberos_new(principal, keytab))) goto fail;
    }
    if (!a->oidc && !a->aws_url && !a->ldap_origin && !a->kerberos) goto fail;
    static const char *const map_fields[] = {"category", "subject", "local_name", "client_id"};
    for (const Node *p = maps->first; p; p = p->next) {
        Mapping *m = &a->mappings[a->mapping_count];
        if (!keys(p, map_fields, 4, 3)) goto fail;
        m->category = category(string(get(p, "category"), 16));
        m->subject = string(get(p, "subject"), 1024);
        m->local = string(get(p, "local_name"), 128);
        m->client = string(get(p, "client_id"), 255);
        if (!m->category || !m->subject || !local_name(m->local) ||
            (m->category == YD_ACCESS_IDENTITY_OIDC ? (!a->oidc || !m->client || p->count != 4) : p->count != 3) ||
            (m->category == YD_ACCESS_IDENTITY_AWS && !a->aws_url) ||
            (m->category == YD_ACCESS_IDENTITY_LDAP && (!a->ldap_origin || strchr(m->subject, ':'))) ||
            (m->category == YD_ACCESS_IDENTITY_KERBEROS && !a->kerberos)) goto fail;
        for (size_t j = 0; j < a->mapping_count; j++) {
            const Mapping *old = &a->mappings[j];
            if (old->category == m->category && !strcmp(old->subject, m->subject) &&
                ((!old->client && !m->client) || (old->client && m->client && !strcmp(old->client, m->client)))) goto fail;
        }
        a->mapping_count++;
    }
    if (pthread_mutex_init(&a->lock, NULL)) goto fail;
    a->lock_ready = true; return a;
fail:
    destroy(a); return NULL;
}
static const Mapping *mapping(const YDAccessIdentity *a, YDAccessIdentityCategory c,
    const char *subject, const char *client) {
    for (size_t i = 0; i < a->mapping_count; i++) {
        const Mapping *m = &a->mappings[i];
        if (m->category == c && !strcmp(m->subject, subject) &&
            (!m->client || (client && !strcmp(m->client, client)))) return m;
    }
    return NULL;
}
static size_t decode(const char *proof, unsigned char *out, size_t capacity) {
    size_t n = strlen(proof);
    if (!n || n % 4 || n > YD_ACCESS_IDENTITY_AUTHORIZATION_MAX || n / 4 * 3 > capacity) return 0;
    size_t padding = proof[n-1] == '=' ? 1 : 0;
    if (n > 1 && proof[n-2] == '=') padding++;
    for (size_t i = 0; i < n; i++) {
        char c = proof[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '+' || c == '/' || (c == '=' && i >= n-padding))) return 0;
    }
    int result = EVP_DecodeBlock(out, (const unsigned char *)proof, (int)n);
    if (result < 0 || (size_t)result < padding) return 0;
    char canonical[YD_ACCESS_IDENTITY_AUTHORIZATION_MAX + 1];
    int encoded = EVP_EncodeBlock((unsigned char *)canonical, out, result - (int)padding);
    bool valid = encoded == (int)n && !memcmp(canonical, proof, n);
    OPENSSL_cleanse(canonical, sizeof(canonical)); return valid ? (size_t)result-padding : 0;
}
static int status(YDIdentityResult r) { return r == YD_IDENTITY_VALID ? 0 : r == YD_IDENTITY_INVALID ? 401 : 503; }
static int authenticate(YDAccessIdentity *a, const char *auth, bool tls,
    const unsigned char *binding, size_t binding_length, int64_t now, YDAccessIdentityVerified *out) {
    if (!out) return 503;
    memset(out, 0, sizeof(*out));
    if (!a || !tls || !auth || now < 0 || now > INT64_C(253402300799)) return 401;
    size_t length = strnlen(auth, YD_ACCESS_IDENTITY_AUTHORIZATION_MAX + 1);
    if (!length || length > YD_ACCESS_IDENTITY_AUTHORIZATION_MAX) return 401;
    const char *space = strchr(auth, ' ');
    if (!space || space == auth || !space[1] || strchr(space + 1, ' ') || strchr(space + 1, '\t')) return 401;
    size_t scheme = (size_t)(space - auth); const char *proof = space + 1;
    YDAccessIdentityCategory c = YD_ACCESS_IDENTITY_NONE;
    const Mapping *m = NULL; int result = 401;
    unsigned char decoded[4609] = {0}; YDOIDCJSON *doc = NULL;
    if (scheme == 6 && !strncasecmp(auth, "Bearer", 6) && a->oidc) {
        YDOIDCIdentity signed_id, online;
        YDOIDCResult r = yd_oidc_verify(a->oidc, proof, strlen(proof), now, &signed_id);
        if (r != YD_OIDC_VALID) { result = r == YD_OIDC_ERROR ? 503 : 401; goto done; }
        if (!signed_id.required_scope_present) { result = 403; goto done; }
        result = status(yd_identity_introspect(&a->network, a->discovery.introspection_endpoint,
            a->client_id, a->secret, proof, a->discovery.issuer, a->audience, a->scope, now, &online));
        if (result) goto done;
        if (strcmp(signed_id.subject, online.subject) || strcmp(signed_id.client_id, online.client_id) ||
            signed_id.expires_at != online.expires_at) { result = 401; goto done; }
        out->expires_at = online.expires_at;
        c = YD_ACCESS_IDENTITY_OIDC; m = mapping(a, c, online.subject, online.client_id);
    } else if (scheme == 10 && !strncasecmp(auth, "Yamora-IAM", 10) && a->aws_url) {
        size_t used = decode(proof, decoded, sizeof(decoded)-1);
        static const char *const f[] = {"authorization", "date", "session_token"};
        if (!used || yd_oidc_json_parse(decoded, used, 16, &doc) != YD_OIDC_JSON_OK) goto done;
        const Node *root = yd_oidc_json_root(doc);
        const char *authorization = string(get(root, "authorization"), 2048);
        const char *date = string(get(root, "date"), 16), *token = string(get(root, "session_token"), 4096);
        if (!keys(root, f, 3, 3) || !authorization || !date || !token) goto done;
        YDIdentityAWS identity;
        result = status(yd_identity_aws(&a->network, a->aws_url, a->server_id, authorization, date, token, now, &identity));
        if (result) goto done;
        c = YD_ACCESS_IDENTITY_AWS; m = mapping(a, c, identity.arn, NULL);
    } else if (scheme == 5 && !strncasecmp(auth, "Basic", 5) && a->ldap_origin) {
        size_t used = decode(proof, decoded, sizeof(decoded)-1);
        if (!used || memchr(decoded, 0, used)) goto done;
        char *colon = strchr((char *)decoded, ':');
        if (!colon || colon == (char *)decoded || !colon[1]) goto done;
        *colon = 0; c = YD_ACCESS_IDENTITY_LDAP;
        m = mapping(a, c, (char *)decoded, NULL);
        if (!m) { result = 403; goto done; }
        result = status(yd_identity_ldap(&a->network, a->ldap_origin, (char *)decoded, colon+1));
        if (result) goto done;
    } else if (scheme == 9 && !strncasecmp(auth, "Negotiate", 9) && a->kerberos) {
        size_t used = decode(proof, decoded, sizeof(decoded)-1);
        if (!used || used > 4096 || !binding || binding_length != YD_ACCESS_IDENTITY_BINDING_SIZE) goto done;
        char principal[1025];
        if (pthread_mutex_lock(&a->lock)) { result = 503; goto done; }
        result = status(yd_identity_kerberos_accept(a->kerberos, decoded, used, binding, binding_length,
            principal, sizeof(principal), out->reply, sizeof(out->reply), &out->reply_length));
        pthread_mutex_unlock(&a->lock);
        if (result) goto done;
        c = YD_ACCESS_IDENTITY_KERBEROS; m = mapping(a, c, principal, NULL);
    } else goto done;
    if (!m) { result = 403; goto done; }
    strcpy(out->local_name, m->local); out->category = c; result = 0;
done:
    yd_oidc_json_free(doc); OPENSSL_cleanse(decoded, sizeof(decoded));
    if (result) memset(out, 0, sizeof(*out));
    return result;
}
static void restore(int prior) {
    (void)pthread_setcancelstate(prior, NULL);
    if (prior == PTHREAD_CANCEL_ENABLE) pthread_testcancel();
}
static void cancelled_load(void *object) { destroy(object); }
YDAccessIdentity *yd_access_identity_load(const char *path, bool offline, char *error, size_t capacity) {
    int prior;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &prior)) return NULL;
    YDAccessIdentity *a = load(path, offline);
    if (error && capacity) snprintf(error, capacity, "%s", a ? "" : "identity provider configuration unavailable or invalid");
    pthread_cleanup_push(cancelled_load, a);
    restore(prior);
    pthread_cleanup_pop(0);
    return a;
}
void yd_access_identity_free(YDAccessIdentity *a) {
    int prior;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &prior)) return;
    destroy(a); restore(prior);
}
int yd_access_identity_authenticate(YDAccessIdentity *a, const char *auth, bool tls,
    const unsigned char *binding, size_t length, int64_t now, YDAccessIdentityVerified *out) {
    int prior;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &prior)) { if (out) memset(out, 0, sizeof(*out)); return 503; }
    int result = authenticate(a, auth, tls, binding, length, now, out);
    restore(prior); return result;
}
int yd_access_identity_revoke(YDAccessIdentity *a, const char *token) {
    int prior;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &prior)) return 503;
    int result = a && a->oidc && token && yd_identity_revoke(&a->network, a->discovery.revocation_endpoint,
        a->client_id, a->secret, token) == YD_IDENTITY_VALID ? 0 : 503;
    restore(prior); return result;
}
