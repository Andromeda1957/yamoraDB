#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#include "identity.h"
#include "oidc_json.h"
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <openssl/crypto.h>
#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <dlfcn.h>

typedef YDOIDCJSONNode Node;
typedef struct {
    const YDIdentityEndpoint *endpoint;
    char host[254], authority[270];
    const char *path;
    unsigned port;
} Target;
typedef struct { int fd; SSL_CTX *ctx; SSL *ssl; BIO_METHOD *method; int64_t deadline; } Connection;
static bool text(const char *s, size_t max, bool space) {
    if (!s) return false;
    size_t n = strnlen(s, max + 1);
    if (!n || n > max) return false;
    for (size_t i = 0; i < n; i++)
        if ((unsigned char)s[i] < (space ? 32 : 33) || (unsigned char)s[i] > 126)
            return false;
    return true;
}
static const Node *get(const Node *n, const char *k) { return yd_oidc_json_get(n, k); }
static bool eq(const Node *n, const char *s) {
    return n && n->type == YD_OIDC_JSON_STRING && s && strlen(s) == n->length &&
        !memcmp(n->text, s, n->length);
}
static bool string(const Node *n, size_t max) {
    if (!n || n->type != YD_OIDC_JSON_STRING || !n->length || n->length > max) return false;
    /* The strict JSON parser has already validated UTF-8. */
    for (size_t i = 0; i < n->length; i++)
        if ((unsigned char)n->text[i] < 32 || (unsigned char)n->text[i] == 127) return false;
    return true;
}
static bool target(const YDIdentityNetwork *network, const char *url,
    bool ldap, Target *out) {
    memset(out, 0, sizeof(*out));
    const char *scheme = ldap ? "ldaps://" : "https://";
    if (!network || !network->endpoints || !network->count || network->count > 8 ||
        !text(url, YD_IDENTITY_URL_MAX, false) || strncmp(url, scheme, strlen(scheme)) ||
        strpbrk(url, "\\#@")) return false;
    const char *authority = url + strlen(scheme), *end = strchr(authority, '/');
    if (!end) end = url + strlen(url);
    if (memchr(authority, '?', (size_t)(end - authority))) return false;
    size_t origin_length = (size_t)(end - url), an = (size_t)(end - authority);
    if (!an || an >= sizeof(out->authority)) return false;
    memcpy(out->authority, authority, an);
    const char *colon = memchr(authority, ':', an);
    size_t hn = colon ? (size_t)(colon - authority) : an;
    if (!hn || hn >= sizeof(out->host)) return false;
    for (size_t i = 0; i < hn; i++) {
        unsigned char c = (unsigned char)authority[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '.' || c == '-')) return false;
    }
    memcpy(out->host, authority, hn);
    out->port = ldap ? 636U : 443U;
    if (colon) {
        if (colon + 1 == end) return false;
        out->port = 0;
        for (const char *p = colon + 1; p < end; p++) {
            if (*p < '0' || *p > '9' || out->port > 6553) return false;
            out->port = out->port * 10 + (unsigned)(*p - '0');
        }
        if (!out->port || out->port > 65535) return false;
    }
    if (ldap && *end) return false;
    out->path = *end ? end : "/";
    for (size_t i = 0; i < network->count; i++) {
        const YDIdentityEndpoint *ep = &network->endpoints[i];
        if (!text(ep->origin, 280, false) || strlen(ep->origin) != origin_length ||
            memcmp(ep->origin, url, origin_length)) continue;
        if (out->endpoint || !ep->address || !ep->ca_file || !*ep->ca_file ||
            !ep->timeout_ms || ep->timeout_ms > 10000) return false;
        out->endpoint = ep;
    }
    return out->endpoint != NULL;
}
static int64_t milliseconds(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) return -1;
    return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}
static bool wait_io(Connection *c, short events) {
    int64_t now = milliseconds();
    if (now < 0 || now >= c->deadline) return false;
    struct pollfd p = {.fd = c->fd, .events = events};
    int r;
    do { r = poll(&p, 1, (int)(c->deadline - now)); } while (r < 0 && errno == EINTR &&
        (now = milliseconds()) >= 0 && now < c->deadline);
    return r > 0 && !(p.revents & (POLLERR | POLLNVAL));
}
static bool ssl_retry(Connection *c, int result) {
    int e = SSL_get_error(c->ssl, result);
    if (e == SSL_ERROR_WANT_READ) return wait_io(c, POLLIN);
    if (e == SSL_ERROR_WANT_WRITE) return wait_io(c, POLLOUT);
    return false;
}
static bool deadline_valid(const Connection *c) {
    int64_t now = milliseconds();
    return now >= 0 && now < c->deadline;
}
/* The default OpenSSL socket BIO may raise SIGPIPE. This non-owning BIO uses
 * Linux MSG_NOSIGNAL per send, leaving process/thread signal policy untouched. */
static int socket_read(BIO *bio, char *data, size_t size, size_t *used) {
    *used = 0; BIO_clear_retry_flags(bio);
    ssize_t n = recv((int)(intptr_t)BIO_get_data(bio), data, size, 0);
    if (n > 0) { *used = (size_t)n; return 1; }
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) BIO_set_retry_read(bio);
    return 0;
}
static int socket_write(BIO *bio, const char *data, size_t size, size_t *used) {
    *used = 0; BIO_clear_retry_flags(bio);
    ssize_t n = send((int)(intptr_t)BIO_get_data(bio), data, size, MSG_NOSIGNAL);
    if (n > 0) { *used = (size_t)n; return 1; }
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) BIO_set_retry_write(bio);
    return 0;
}
static long socket_control(BIO *bio, int command, long number, void *pointer) {
    (void)number;
    if (command == BIO_CTRL_FLUSH) return 1;
    if (command == BIO_C_GET_FD) {
        int fd = (int)(intptr_t)BIO_get_data(bio);
        if (pointer) *(int *)pointer = fd;
        return fd;
    }
    return 0;
}
static void disconnect(Connection *c) {
    SSL_free(c->ssl); BIO_meth_free(c->method); SSL_CTX_free(c->ctx);
    if (c->fd >= 0) close(c->fd);
    memset(c, 0, sizeof(*c)); c->fd = -1;
    ERR_clear_error();
}
static bool connect_tls(const Target *t, Connection *c) {
    memset(c, 0, sizeof(*c)); c->fd = -1;
    int64_t now = milliseconds();
    if (now < 0) return false;
    c->deadline = now + t->endpoint->timeout_ms;
    struct sockaddr_storage address = {0}; socklen_t length;
    struct sockaddr_in *v4 = (struct sockaddr_in *)&address;
    struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&address;
    if (inet_pton(AF_INET, t->endpoint->address, &v4->sin_addr) == 1) {
        v4->sin_family = AF_INET; v4->sin_port = htons((uint16_t)t->port);
        length = sizeof(*v4);
    } else if (inet_pton(AF_INET6, t->endpoint->address, &v6->sin6_addr) == 1) {
        v6->sin6_family = AF_INET6; v6->sin6_port = htons((uint16_t)t->port);
        length = sizeof(*v6);
    } else return false;
    c->fd = socket(address.ss_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (c->fd < 0) goto fail;
    if (connect(c->fd, (struct sockaddr *)&address, length)) {
        if (errno != EINPROGRESS || !wait_io(c, POLLOUT)) goto fail;
        int error = 0; socklen_t n = sizeof(error);
        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, &error, &n) || error) goto fail;
    }
    c->ctx = SSL_CTX_new(TLS_client_method());
    if (!c->ctx || SSL_CTX_set_min_proto_version(c->ctx, TLS1_3_VERSION) != 1 ||
        SSL_CTX_load_verify_locations(c->ctx, t->endpoint->ca_file, NULL) != 1) goto fail;
    SSL_CTX_set_verify(c->ctx, SSL_VERIFY_PEER, NULL);
    c->ssl = SSL_new(c->ctx);
    c->method = BIO_meth_new(BIO_get_new_index() | BIO_TYPE_SOURCE_SINK, "Yamora identity socket");
    if (!c->ssl || !c->method || BIO_meth_set_read_ex(c->method, socket_read) != 1 ||
        BIO_meth_set_write_ex(c->method, socket_write) != 1 ||
        BIO_meth_set_ctrl(c->method, socket_control) != 1) goto fail;
    BIO *bio = BIO_new(c->method);
    if (!bio) goto fail;
    BIO_set_data(bio, (void *)(intptr_t)c->fd); BIO_set_init(bio, 1);
    SSL_set_bio(c->ssl, bio, bio);
    if (SSL_set_tlsext_host_name(c->ssl, t->host) != 1) goto fail;
    unsigned char ip[16];
    if (inet_pton(AF_INET, t->host, ip) == 1 || inet_pton(AF_INET6, t->host, ip) == 1) {
        if (X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(c->ssl), t->host) != 1) goto fail;
    } else if (SSL_set1_host(c->ssl, t->host) != 1) goto fail;
    int r;
    for (;;) {
        ERR_clear_error(); r = SSL_connect(c->ssl);
        if (r == 1) break;
        if (!ssl_retry(c, r)) goto fail;
    }
    if (!deadline_valid(c) || SSL_get_verify_result(c->ssl) != X509_V_OK) goto fail;
    return true;
fail:
    disconnect(c); return false;
}
static bool write_all(Connection *c, const unsigned char *data, size_t size) {
    while (size) {
        size_t n = 0;
        ERR_clear_error();
        int r = SSL_write_ex(c->ssl, data, size, &n);
        if (r != 1) { if (!ssl_retry(c, r)) return false; continue; }
        if (!n || !deadline_valid(c)) return false;
        data += n; size -= n;
    }
    return true;
}
static bool read_exact(Connection *c, unsigned char *data, size_t size) {
    while (size) {
        size_t n = 0;
        ERR_clear_error();
        int r = SSL_read_ex(c->ssl, data, size, &n);
        if (r != 1) { if (!ssl_retry(c, r)) return false; continue; }
        if (!n || !deadline_valid(c)) return false;
        data += n; size -= n;
    }
    return true;
}
/* Deliberately bounded HTTP/1.1 profile: a Content-Length is required. Ambiguous
 * framing, transfer encodings, folding and duplicate headers fail closed. */
static YDIdentityResult http(const YDIdentityNetwork *network, const char *url,
    const char *method, const char *headers, const char *body,
    unsigned char *out, size_t capacity, size_t *used) {
    *used = 0; Target t; Connection c;
    if (!out || capacity < 1 || !target(network, url, false, &t)) return YD_IDENTITY_ERROR;
    char request[24576], response[8193];
    size_t bn = body ? strlen(body) : 0;
    int n = snprintf(request, sizeof(request), "%s %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nAccept: application/json, text/xml\r\n%sContent-Length: %zu\r\n\r\n%s",
        method, t.path, t.authority, headers ? headers : "", bn, body ? body : "");
    if (n < 0 || (size_t)n >= sizeof(request)) {
        OPENSSL_cleanse(request, sizeof(request)); return YD_IDENTITY_ERROR;
    }
    YDIdentityResult result = YD_IDENTITY_ERROR;
    if (!connect_tls(&t, &c)) goto done;
    if (!write_all(&c, (unsigned char *)request, (size_t)n)) goto connected;
    size_t hn = 0;
    while (hn < sizeof(response) - 1) {
        if (!read_exact(&c, (unsigned char *)response + hn, 1)) goto connected;
        hn++;
        if (hn >= 4 && !memcmp(response + hn - 4, "\r\n\r\n", 4)) break;
    }
    response[hn] = 0;
    if (hn < 4 || memcmp(response + hn - 4, "\r\n\r\n", 4) ||
        memchr(response, 0, hn) || strncmp(response, "HTTP/1.1 ", 9) ||
        response[9] < '1' || response[9] > '5' || response[10] < '0' ||
        response[10] > '9' || response[11] < '0' || response[11] > '9' || response[12] != ' ')
        goto connected;
    int status = (response[9] - '0') * 100 + (response[10] - '0') * 10 + response[11] - '0';
    char *line = strstr(response, "\r\n");
    if (!line) goto connected;
    line += 2;
    bool have_length = false, have_type = false;
    size_t content_length = 0, header_count = 0;
    char *names[64]; size_t name_lengths[64];
    while (*line != '\r') {
        char *end = strstr(line, "\r\n"), *colon = strchr(line, ':');
        if (!end || !colon || colon >= end || colon == line || header_count == 64) goto connected;
        size_t name_length = (size_t)(colon - line);
        for (size_t i = 0; i < name_length; i++)
            if (!((line[i] >= 'a' && line[i] <= 'z') || (line[i] >= 'A' && line[i] <= 'Z') || line[i] == '-')) goto connected;
        for (size_t i = 0; i < header_count; i++)
            if (name_lengths[i] == name_length && !strncasecmp(names[i], line, name_length)) goto connected;
        names[header_count] = line; name_lengths[header_count++] = name_length;
        *colon = 0; *end = 0;
        char *value = colon + 1;
        while (*value == ' ') value++;
        if (!strcasecmp(line, "transfer-encoding")) goto connected;
        if (!strcasecmp(line, "content-length")) {
            if (!*value) goto connected;
            for (char *p = value; *p; p++) {
                if (*p < '0' || *p > '9' || content_length > capacity / 10) goto connected;
                content_length = content_length * 10 + (unsigned)(*p - '0');
                if (content_length >= capacity) goto connected;
            }
            have_length = true;
        } else if (!strcasecmp(line, "content-type")) {
            if (strncmp(value, "application/json", 16) && strncmp(value, "text/xml", 8) &&
                strncmp(value, "application/xml", 15)) goto connected;
            have_type = true;
        }
        line = end + 2;
    }
    if (!have_length || (content_length && !have_type)) goto connected;
    if (!read_exact(&c, out, content_length)) goto connected;
    out[content_length] = 0;
    if (status == 200) { *used = content_length; result = YD_IDENTITY_VALID; }
    else if (status == 400 || status == 401 || status == 403) result = YD_IDENTITY_INVALID;
connected:
    disconnect(&c);
done:
    OPENSSL_cleanse(request, sizeof(request)); OPENSSL_cleanse(response, sizeof(response));
    if (result != YD_IDENTITY_VALID) { OPENSSL_cleanse(out, capacity); *used = 0; }
    return result;
}
static bool uri(const YDIdentityNetwork *network, const Node *node, char *out) {
    Target t;
    if (!string(node, YD_IDENTITY_URL_MAX) || !target(network, node->text, false, &t)) return false;
    memcpy(out, node->text, node->length + 1); return true;
}
static YDIdentityResult discover(const YDIdentityNetwork *network, const char *issuer,
    YDIdentityDiscovery *out) {
    if (!out) return YD_IDENTITY_ERROR;
    memset(out, 0, sizeof(*out)); Target t;
    if (!text(issuer, 512, false) || strchr(issuer, '?') || !target(network, issuer, false, &t))
        return YD_IDENTITY_ERROR;
    char url[YD_IDENTITY_URL_MAX + 1]; size_t length = strlen(issuer);
    int n = snprintf(url, sizeof(url), "%.*s/.well-known/openid-configuration",
        (int)(length - (issuer[length - 1] == '/')), issuer);
    if (n < 0 || (size_t)n >= sizeof(url)) return YD_IDENTITY_ERROR;
    unsigned char response[YD_IDENTITY_RESPONSE_MAX + 1]; size_t used;
    YDOIDCJSON *doc = NULL;
    YDIdentityResult result = http(network, url, "GET", NULL, NULL, response, sizeof(response), &used);
    if (result != YD_IDENTITY_VALID) goto done;
    result = YD_IDENTITY_ERROR;
    if (yd_oidc_json_parse(response, used, 1024, &doc) != YD_OIDC_JSON_OK) goto done;
    const Node *root = yd_oidc_json_root(doc);
    if (!root || root->type != YD_OIDC_JSON_OBJECT || !eq(get(root, "issuer"), issuer) ||
        !uri(network, get(root, "jwks_uri"), out->jwks_uri)) goto done;
    const Node *ip = get(root, "introspection_endpoint"), *rp = get(root, "revocation_endpoint");
    if ((ip && !uri(network, ip, out->introspection_endpoint)) ||
        (rp && !uri(network, rp, out->revocation_endpoint))) goto done;
    strcpy(out->issuer, issuer); result = YD_IDENTITY_VALID;
done:
    yd_oidc_json_free(doc); OPENSSL_cleanse(response, sizeof(response));
    if (result != YD_IDENTITY_VALID) memset(out, 0, sizeof(*out));
    return result;
}
static YDIdentityResult jwks(const YDIdentityNetwork *network, const char *url,
    unsigned char *out, size_t capacity, size_t *length) {
    if (length) *length = 0;
    if (!out || !length || !capacity || capacity > YD_IDENTITY_RESPONSE_MAX + 1) return YD_IDENTITY_ERROR;
    memset(out, 0, capacity);
    return http(network, url, "GET", NULL, NULL, out, capacity, length);
}
static bool form(const char *input, size_t max, char *out, size_t capacity) {
    if (!text(input, max, true)) return false;
    static const char hex[] = "0123456789ABCDEF";
    size_t n = 0;
    for (const unsigned char *p = (const unsigned char *)input; *p; p++) {
        bool plain = (*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
            (*p >= '0' && *p <= '9') || strchr("-._~", *p);
        size_t need = plain ? 1U : 3U;
        if (n + need >= capacity) return false;
        if (plain) out[n++] = (char)*p;
        else { out[n++] = '%'; out[n++] = hex[*p >> 4]; out[n++] = hex[*p & 15]; }
    }
    out[n] = 0; return true;
}
static YDIdentityResult oauth(const YDIdentityNetwork *network, const char *url,
    const char *id, const char *secret, const char *token, unsigned char *out,
    size_t capacity, size_t *length) {
    char a[769], b[3073], t[12289], pair[4096], basic[5465], headers[5600], body[12500];
    YDIdentityResult result = YD_IDENTITY_ERROR;
    if (!form(id, 256, a, sizeof(a)) || !form(secret, 1024, b, sizeof(b)) ||
        !form(token, 4096, t, sizeof(t))) goto done;
    int n = snprintf(pair, sizeof(pair), "%s:%s", a, b);
    if (n < 0 || (size_t)n >= sizeof(pair)) goto done;
    if (EVP_EncodeBlock((unsigned char *)basic, (unsigned char *)pair, n) <= 0) goto done;
    n = snprintf(headers, sizeof(headers), "Content-Type: application/x-www-form-urlencoded\r\nAuthorization: Basic %s\r\n", basic);
    if (n < 0 || (size_t)n >= sizeof(headers)) goto done;
    n = snprintf(body, sizeof(body), "token=%s&token_type_hint=access_token", t);
    if (n < 0 || (size_t)n >= sizeof(body)) goto done;
    result = http(network, url, "POST", headers, body, out, capacity, length);
done:
    OPENSSL_cleanse(a, sizeof(a)); OPENSSL_cleanse(b, sizeof(b)); OPENSSL_cleanse(t, sizeof(t));
    OPENSSL_cleanse(pair, sizeof(pair)); OPENSSL_cleanse(basic, sizeof(basic));
    OPENSSL_cleanse(headers, sizeof(headers)); OPENSSL_cleanse(body, sizeof(body));
    return result;
}
static bool date(const Node *n, int64_t *out) {
    if (!n || n->type != YD_OIDC_JSON_NUMBER || !n->length || n->length > 12) return false;
    int64_t value = 0;
    for (size_t i = 0; i < n->length; i++) {
        if (n->text[i] < '0' || n->text[i] > '9' || value > (INT64_C(253402300799) - (n->text[i] - '0')) / 10) return false;
        value = value * 10 + n->text[i] - '0';
    }
    *out = value; return true;
}
static bool has_scope(const Node *node, const char *required) {
    if (!string(node, 1024) || !text(required, 128, false) || strpbrk(required, " \"\\")) return false;
    size_t n = strlen(required), start = 0; bool found = false;
    for (size_t i = 0; i <= node->length; i++) {
        if (i < node->length && ((unsigned char)node->text[i] > 126 ||
            node->text[i] == '"' || node->text[i] == '\\')) return false;
        if (i < node->length && node->text[i] != ' ') continue;
        if (i == start) return false;
        if (i - start == n && !memcmp(node->text + start, required, n)) found = true;
        start = i + 1;
    }
    return found;
}
static YDIdentityResult introspect(const YDIdentityNetwork *network, const char *url,
    const char *id, const char *secret, const char *token, const char *issuer,
    const char *audience, const char *required_scope, int64_t now, YDOIDCIdentity *out) {
    if (!out) return YD_IDENTITY_ERROR;
    memset(out, 0, sizeof(*out));
    if (!text(issuer, 512, false) || !text(audience, 256, false) ||
        !text(required_scope, 128, false) || now < 0 || now > INT64_C(253402300799)) return YD_IDENTITY_ERROR;
    unsigned char response[YD_IDENTITY_RESPONSE_MAX + 1]; size_t used = 0;
    YDOIDCJSON *doc = NULL;
    YDIdentityResult result = oauth(network, url, id, secret, token, response, sizeof(response), &used);
    if (result != YD_IDENTITY_VALID) goto done;
    result = YD_IDENTITY_ERROR;
    if (yd_oidc_json_parse(response, used, 512, &doc) != YD_OIDC_JSON_OK) goto done;
    const Node *root = yd_oidc_json_root(doc), *active = get(root, "active");
    if (!root || root->type != YD_OIDC_JSON_OBJECT || !active || active->type != YD_OIDC_JSON_BOOL) goto done;
    result = YD_IDENTITY_INVALID;
    if (strcmp(active->text, "true")) goto done;
    const Node *sub = get(root, "sub"), *client = get(root, "client_id");
    int64_t expires = 0, issued = 0, nbf = 0;
    if (!eq(get(root, "iss"), issuer) || !eq(get(root, "aud"), audience) ||
        !eq(get(root, "token_type"), "Bearer") || !string(sub, 255) || !string(client, 255) ||
        !date(get(root, "exp"), &expires) || !date(get(root, "iat"), &issued) ||
        issued > now || now >= expires || expires <= issued || expires - issued > 3600 ||
        (get(root, "nbf") && (!date(get(root, "nbf"), &nbf) || nbf > now || nbf >= expires)) ||
        !has_scope(get(root, "scope"), required_scope)) goto done;
    strcpy(out->subject, sub->text); strcpy(out->client_id, client->text);
    out->expires_at = expires; out->required_scope_present = true; result = YD_IDENTITY_VALID;
done:
    yd_oidc_json_free(doc); OPENSSL_cleanse(response, sizeof(response));
    if (result != YD_IDENTITY_VALID) memset(out, 0, sizeof(*out));
    return result;
}
static YDIdentityResult revoke_token(const YDIdentityNetwork *network, const char *url,
    const char *id, const char *secret, const char *token) {
    unsigned char response[4097]; size_t used = 0;
    YDIdentityResult result = oauth(network, url, id, secret, token, response, sizeof(response), &used);
    OPENSSL_cleanse(response, sizeof(response)); return result;
}
/* Narrow BER definite-length codec for an LDAPv3 simple bind only. */
static size_t ber(unsigned char *out, unsigned char tag, const unsigned char *value, size_t n) {
    size_t k = 0; out[k++] = tag;
    if (n < 128) out[k++] = (unsigned char)n;
    else if (n < 256) { out[k++] = 0x81; out[k++] = (unsigned char)n; }
    else { out[k++] = 0x82; out[k++] = (unsigned char)(n >> 8); out[k++] = (unsigned char)n; }
    memcpy(out + k, value, n); return k + n;
}
static bool take(const unsigned char **p, const unsigned char *end, unsigned char tag,
    const unsigned char **value, size_t *length) {
    if ((size_t)(end - *p) < 2 || *(*p)++ != tag) return false;
    size_t n = *(*p)++;
    if (n & 128) {
        size_t bytes = n & 127; n = 0;
        if (!bytes || bytes > 2 || (size_t)(end - *p) < bytes || !**p) return false;
        for (size_t i = 0; i < bytes; i++) n = (n << 8) | *(*p)++;
        if (n < 128 || (bytes == 2 && n < 256)) return false;
    }
    if ((size_t)(end - *p) < n) return false;
    *value = *p; *length = n; *p += n; return true;
}
static bool ldap_string(const char *s) {
    if (!s) return false;
    size_t n = strnlen(s, 1025);
    if (!n || n > 1024) return false;
    for (size_t i = 0; i < n; i++) if ((unsigned char)s[i] < 32 || (unsigned char)s[i] == 127) return false;
    ASN1_STRING *validated = NULL;
    int result = ASN1_mbstring_copy(&validated, (const unsigned char *)s,
        (int)n, MBSTRING_UTF8, B_ASN1_UTF8STRING);
    ASN1_STRING_clear_free(validated);
    return result >= 0;
}
static YDIdentityResult ldap_bind(const YDIdentityNetwork *network, const char *origin,
    const char *dn, const char *password) {
    Target t; Connection c;
    if (!target(network, origin, true, &t) || !ldap_string(dn) ||
        !ldap_string(password)) return YD_IDENTITY_ERROR;
    unsigned char inner[2200], message[2240], packet[2280], response[4096];
    const unsigned char version[] = {2, 1, 3}, id[] = {2, 1, 1};
    memcpy(inner, version, sizeof(version)); size_t n = sizeof(version);
    n += ber(inner + n, 4, (const unsigned char *)dn, strlen(dn));
    n += ber(inner + n, 0x80, (const unsigned char *)password, strlen(password));
    memcpy(message, id, sizeof(id)); size_t mn = sizeof(id) + ber(message + sizeof(id), 0x60, inner, n);
    size_t pn = ber(packet, 0x30, message, mn);
    YDIdentityResult result = YD_IDENTITY_ERROR;
    if (!connect_tls(&t, &c)) goto done;
    if (!write_all(&c, packet, pn) || !read_exact(&c, response, 2) || response[0] != 0x30) goto connected;
    size_t header = 2, total = response[1];
    if (total & 128) {
        size_t count = total & 127; total = 0;
        if (!count || count > 2 || !read_exact(&c, response + 2, count) || !response[2]) goto connected;
        header += count;
        for (size_t i = 0; i < count; i++) total = (total << 8) | response[2 + i];
        if (total < 128 || (count == 2 && total < 256)) goto connected;
    }
    if (total > sizeof(response) - header || !read_exact(&c, response + header, total)) goto connected;
    const unsigned char *p = response + header, *end = p + total, *v; size_t vn;
    if (!take(&p, end, 2, &v, &vn) || vn != 1 || *v != 1 ||
        !take(&p, end, 0x61, &v, &vn) || p != end) goto connected;
    p = v; end = p + vn;
    if (!take(&p, end, 10, &v, &vn) || vn != 1) goto connected;
    unsigned code = *v;
    if (!take(&p, end, 4, &v, &vn) || !take(&p, end, 4, &v, &vn) || p != end) goto connected;
    result = code == 0 ? YD_IDENTITY_VALID : YD_IDENTITY_INVALID;
connected:
    disconnect(&c);
done:
    OPENSSL_cleanse(inner, sizeof(inner)); OPENSSL_cleanse(message, sizeof(message));
    OPENSSL_cleanse(packet, sizeof(packet)); OPENSSL_cleanse(response, sizeof(response)); return result;
}
static bool aws_date(const char *s, int64_t *out) {
    if (!text(s, 16, false) || strlen(s) != 16 || s[8] != 'T' || s[15] != 'Z') return false;
    unsigned value[6] = {0};
    static const size_t offsets[] = {0, 4, 6, 9, 11, 13}, sizes[] = {4, 2, 2, 2, 2, 2};
    for (size_t i = 0; i < 6; i++) for (size_t j = 0; j < sizes[i]; j++) {
        char c = s[offsets[i] + j];
        if (c < '0' || c > '9') return false;
        value[i] = value[i] * 10 + (unsigned)(c - '0');
    }
    unsigned y = value[0], m = value[1], d = value[2];
    static const unsigned days[] = {31,28,31,30,31,30,31,31,30,31,30,31};
    bool leap = !(y % 4) && ((y % 100) || !(y % 400));
    if (y < 1970 || y > 9999 || !m || m > 12 || !d ||
        d > days[m - 1] + (unsigned)(m == 2 && leap) || value[3] > 23 || value[4] > 59 || value[5] > 59)
        return false;
    int64_t count = 0;
    for (unsigned year = 1970; year < y; year++) count += 365 +
        (unsigned)(!(year % 4) && ((year % 100) || !(year % 400)));
    for (unsigned month = 1; month < m; month++) count += days[month - 1] + (unsigned)(month == 2 && leap);
    *out = (count + d - 1) * 86400 + value[3] * 3600 + value[4] * 60 + value[5]; return true;
}
static void xml_space(const char **p) {
    while (**p == ' ' || **p == '\t' || **p == '\r' || **p == '\n') (*p)++;
}
static bool xml_token(const char **p, const char *token) {
    size_t n = strlen(token);
    if (strncmp(*p, token, n)) return false;
    *p += n; return true;
}
static bool xml_field(const char **cursor, const char *field, char *out, size_t capacity) {
    char start[32], finish[32];
    if (snprintf(start, sizeof(start), "<%s>", field) <= 0 ||
        snprintf(finish, sizeof(finish), "</%s>", field) <= 0 || !xml_token(cursor, start)) return false;
    const char *p = *cursor, *q = strchr(p, '<');
    if (!q || q == p || (size_t)(q - p) >= capacity) return false;
    for (const char *r = p; r < q; r++)
        if ((unsigned char)*r < 33 || (unsigned char)*r > 126 || strchr("<>&\"'", *r)) return false;
    *cursor = q;
    if (!xml_token(cursor, finish)) return false;
    memcpy(out, p, (size_t)(q - p)); out[q - p] = 0; xml_space(cursor); return true;
}
static bool aws_xml(const unsigned char *response, size_t n, YDIdentityAWS *out) {
    if (memchr(response, 0, n)) return false;
    const char *p = (const char *)response; xml_space(&p);
    if (!strncmp(p, "<?xml", 5)) {
        if (!xml_token(&p, "<?xml version=\"1.0\"?>") &&
            !xml_token(&p, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>")) return false;
        xml_space(&p);
    }
    if (!xml_token(&p, "<GetCallerIdentityResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\">")) return false;
    xml_space(&p); bool result = false, metadata = false;
    char unused[513];
    for (unsigned children = 0; children < 2; children++) {
        if (xml_token(&p, "<GetCallerIdentityResult>")) {
            if (result) return false;
            result = true; xml_space(&p); unsigned fields = 0;
            for (unsigned i = 0; i < 3; i++) {
                unsigned bit;
                if (!strncmp(p, "<Arn>", 5)) {
                    bit = 1;
                    if (!xml_field(&p, "Arn", out->arn, sizeof(out->arn))) return false;
                } else if (!strncmp(p, "<Account>", 9)) {
                    bit = 2;
                    if (!xml_field(&p, "Account", out->account, sizeof(out->account))) return false;
                } else {
                    bit = 4;
                    if (!xml_field(&p, "UserId", unused, sizeof(unused))) return false;
                }
                if (fields & bit) return false;
                fields |= bit;
            }
            if (fields != 7 || !xml_token(&p, "</GetCallerIdentityResult>")) return false;
        } else if (xml_token(&p, "<ResponseMetadata>")) {
            if (metadata) return false;
            metadata = true; xml_space(&p);
            if (!xml_field(&p, "RequestId", unused, sizeof(unused)) ||
                !xml_token(&p, "</ResponseMetadata>")) return false;
        } else break;
        xml_space(&p);
    }
    return result && xml_token(&p, "</GetCallerIdentityResponse>") && (xml_space(&p), !*p);
}
static YDIdentityResult aws(const YDIdentityNetwork *network, const char *url,
    const char *server_id, const char *authorization, const char *amz_date,
    const char *session_token, int64_t now, YDIdentityAWS *out) {
    if (!out) return YD_IDENTITY_ERROR;
    memset(out, 0, sizeof(*out)); Target t; int64_t stamp;
    if (!target(network, url, false, &t) || strcmp(t.path, "/") ||
        !text(server_id, 256, false) || !text(authorization, 2048, true) ||
        !text(session_token, 4096, false) || !aws_date(amz_date, &stamp) ||
        now < 0 || now > INT64_C(253402300799)) return YD_IDENTITY_ERROR;
    if (stamp < now - 60 || stamp > now + 5) return YD_IDENTITY_INVALID;
    const char *prefix = "AWS4-HMAC-SHA256 Credential=", *signed_headers =
        ", SignedHeaders=host;x-amz-date;x-amz-security-token;x-yamora-server-id, Signature=";
    if (strncmp(authorization, prefix, strlen(prefix))) return YD_IDENTITY_INVALID;
    const char *scope = strstr(authorization + strlen(prefix), signed_headers);
    if (!scope || scope == authorization + strlen(prefix)) return YD_IDENTITY_INVALID;
    const char *signature = scope + strlen(signed_headers);
    if (strlen(signature) != 64) return YD_IDENTITY_INVALID;
    for (const char *p = signature; *p; p++)
        if (!((*p >= 'a' && *p <= 'f') || (*p >= '0' && *p <= '9'))) return YD_IDENTITY_INVALID;
    const char *credential = authorization + strlen(prefix), *slash = memchr(credential, '/', (size_t)(scope - credential));
    if (!slash || slash - credential < 16 || slash - credential > 128 ||
        scope - slash < 24 || memcmp(slash + 1, amz_date, 8) || slash[9] != '/' ||
        (size_t)(scope - slash) < strlen("/00000000/x/sts/aws4_request") ||
        memcmp(scope - strlen("/sts/aws4_request"), "/sts/aws4_request", strlen("/sts/aws4_request")))
        return YD_IDENTITY_INVALID;
    /* The endpoint's authenticated STS service, not this process, validates the
     * signature and AWS key state. The request is never sent to a caller URL. */
    char headers[8800];
    int hn = snprintf(headers, sizeof(headers), "Content-Type: application/x-www-form-urlencoded\r\nAuthorization: %s\r\nX-Amz-Date: %s\r\nX-Amz-Security-Token: %s\r\nX-Yamora-Server-ID: %s\r\n",
        authorization, amz_date, session_token, server_id);
    if (hn < 0 || (size_t)hn >= sizeof(headers)) {
        OPENSSL_cleanse(headers, sizeof(headers)); return YD_IDENTITY_ERROR;
    }
    unsigned char response[8193]; size_t used = 0;
    YDIdentityResult result = http(network, url, "POST", headers,
        "Action=GetCallerIdentity&Version=2011-06-15", response, sizeof(response), &used);
    if (result == YD_IDENTITY_VALID) {
        result = YD_IDENTITY_ERROR;
        if (!aws_xml(response, used, out) ||
            strlen(out->account) != 12) goto done;
        for (size_t i = 0; i < 12; i++) if (out->account[i] < '0' || out->account[i] > '9') goto done;
        const char *arn = out->arn;
        if (strncmp(arn, "arn:aws:iam::", 13) && strncmp(arn, "arn:aws:sts::", 13)) goto done;
        if (memcmp(arn + 13, out->account, 12) || arn[25] != ':' || !arn[26]) goto done;
        result = YD_IDENTITY_VALID;
    }
done:
    OPENSSL_cleanse(headers, sizeof(headers)); OPENSSL_cleanse(response, sizeof(response));
    if (result != YD_IDENTITY_VALID) memset(out, 0, sizeof(*out));
    return result;
}
/* RFC2744 C bindings and MIT credential-store extension ABI. Keeping this
 * optional backend behind dlopen avoids making GSS headers or libraries a
 * mandatory dependency for installations that use only OIDC/LDAPS/AWS. */
typedef uint32_t GUint;
typedef struct { size_t length; void *value; } GBuffer;
typedef struct { GUint length; void *elements; } GOID;
typedef struct { size_t count; GOID *elements; } GOIDSet;
typedef struct { GUint initiator_type; GBuffer initiator; GUint acceptor_type;
    GBuffer acceptor; GBuffer application; } GBindings;
typedef struct { const char *key, *value; } GStoreElement;
typedef struct { GUint count; GStoreElement *elements; } GStore;
struct YDIdentityKerberos {
    void *library, *credential, *expected_name;
    GUint (*import_name)(GUint *, const GBuffer *, const GOID *, void **);
    GUint (*acquire)(GUint *, void *, GUint, const GOIDSet *, int, const GStore *, void **, GOIDSet **, GUint *);
    GUint (*accept)(GUint *, void **, void *, const GBuffer *, const GBindings *, void **,
        GOID **, GBuffer *, GUint *, GUint *, void **);
    GUint (*display)(GUint *, void *, GBuffer *, GOID **);
    GUint (*inquire)(GUint *, void *, void **, void **, GUint *, GOID **, GUint *, int *, int *);
    GUint (*compare)(GUint *, void *, void *, int *);
    GUint (*release_name)(GUint *, void **);
    GUint (*release_cred)(GUint *, void **);
    GUint (*release_buffer)(GUint *, GBuffer *);
    GUint (*delete_context)(GUint *, void **, GBuffer *);
};
static const unsigned char kerberos_oid[] = {0x2a,0x86,0x48,0x86,0xf7,0x12,1,2,2};
static const unsigned char principal_oid[] = {0x2a,0x86,0x48,0x86,0xf7,0x12,1,2,2,1};
static bool symbol(void *library, const char *name, void *out, size_t size) {
    void *p = dlsym(library, name);
    if (!p || size != sizeof(p)) return false;
    memcpy(out, &p, size); return true;
}
static void kerberos_free(YDIdentityKerberos *k) {
    if (!k) return;
    GUint minor;
    if (k->credential && k->release_cred) k->release_cred(&minor, &k->credential);
    if (k->expected_name && k->release_name) k->release_name(&minor, &k->expected_name);
    if (k->library) dlclose(k->library);
    OPENSSL_cleanse(k, sizeof(*k)); free(k);
}
static YDIdentityKerberos *kerberos_new(const char *principal, const char *keytab) {
    if (!text(principal, 512, false) || !strchr(principal, '@') ||
        !text(keytab, 4096, true) || keytab[0] != '/') return NULL;
    /* Disabling MIT's replay cache is incompatible with authentication. */
    const char *cache = getenv("KRB5RCACHETYPE");
    if (cache && !strcmp(cache, "none")) return NULL;
    YDIdentityKerberos *volatile k = calloc(1, sizeof(*k));
    if (!k) return NULL;
    /* MIT GSS owns thread-local error caches and destructor pointers. Keep the
     * one fixed system module mapped for the process lifetime; release each
     * dlopen reference normally without unloading code behind those caches. */
    k->library = dlopen("libgssapi_krb5.so.2", RTLD_NOW | RTLD_LOCAL | RTLD_NODELETE);
    if (!k->library) goto fail;
#define LOAD(member, name) if (!symbol(k->library, name, &k->member, sizeof(k->member))) goto fail
    LOAD(import_name, "gss_import_name"); LOAD(acquire, "gss_acquire_cred_from");
    LOAD(accept, "gss_accept_sec_context"); LOAD(display, "gss_display_name");
    LOAD(inquire, "gss_inquire_context"); LOAD(compare, "gss_compare_name");
    LOAD(release_name, "gss_release_name"); LOAD(release_cred, "gss_release_cred");
    LOAD(release_buffer, "gss_release_buffer"); LOAD(delete_context, "gss_delete_sec_context");
#undef LOAD
    GUint minor;
    GBuffer buffer = {strlen(principal), (void *)principal};
    GOID name_type = {sizeof(principal_oid), (void *)principal_oid};
    GOID mechanism = {sizeof(kerberos_oid), (void *)kerberos_oid};
    GOIDSet mechanisms = {1, &mechanism};
    GStoreElement element = {"keytab", keytab}; GStore store = {1, &element};
    if (k->import_name(&minor, &buffer, &name_type, &k->expected_name) != 0) goto fail;
    /* Acquire only from the explicit keytab; authenticate the exact target
     * after acceptance below. Name-specific acquisition in the qualified MIT
     * library leaks an internal principal on a missing-name failure. Avoid that
     * path without weakening target admission or suppressing leak checks. */
    GUint major = k->acquire(&minor, NULL, 0, &mechanisms, 2, &store, &k->credential, NULL, NULL);
    if (major != 0 || !k->credential) goto fail;
    return k;
fail:
    kerberos_free(k); return NULL;
}
static bool raw_kerberos(const unsigned char *token, size_t length) {
    const unsigned char *p = token, *end = token + length, *v; size_t n;
    if (!take(&p, end, 0x60, &v, &n) || p != end) return false;
    p = v; end = p + n;
    if (!take(&p, end, 6, &v, &n) || n != sizeof(kerberos_oid) ||
        memcmp(v, kerberos_oid, n)) return false;
    return end - p >= 3 && p[0] == 1 && p[1] == 0 && p[2] == 0x6e;
}
static YDIdentityResult kerberos_accept(YDIdentityKerberos *k,
    const unsigned char *token, size_t length, const unsigned char *binding,
    size_t binding_length, char *principal, size_t principal_capacity,
    unsigned char *reply, size_t reply_capacity, size_t *reply_length) {
    if (principal && principal_capacity && principal_capacity <= 1025) memset(principal, 0, principal_capacity);
    if (reply && reply_capacity && reply_capacity <= YD_IDENTITY_GSS_TOKEN_MAX) memset(reply, 0, reply_capacity);
    if (reply_length) *reply_length = 0;
    if (!k || !token || !length || length > YD_IDENTITY_GSS_TOKEN_MAX ||
        !binding || binding_length < 16 || binding_length > 256 || !principal ||
        principal_capacity < 2 || principal_capacity > 1025 || !reply ||
        !reply_capacity || reply_capacity > YD_IDENTITY_GSS_TOKEN_MAX || !reply_length)
        return YD_IDENTITY_ERROR;
    if (!raw_kerberos(token, length)) return YD_IDENTITY_INVALID;
    GBuffer input = {length, (void *)token}, output = {0}, name_text = {0};
    GBindings bindings = {0}; bindings.application.length = binding_length;
    bindings.application.value = (void *)binding;
    GUint minor, flags = 0, lifetime = 0;
    void *context = NULL, *name = NULL, *target_name = NULL, *delegated = NULL; GOID *mechanism = NULL;
    GUint major = k->accept(&minor, &context, k->credential, &input, &bindings,
        &name, &mechanism, &output, &flags, &lifetime, &delegated);
    YDIdentityResult result = YD_IDENTITY_INVALID;
    /* Exact COMPLETE excludes CONTINUE and all supplementary replay statuses.
     * Channel-bound, mutual, replay and integrity flags are mandatory. */
    const GUint required = 2U | 4U | 32U | 2048U;
    if (major != 0 || !name || !context || !lifetime || !mechanism ||
        mechanism->length != sizeof(kerberos_oid) ||
        memcmp(mechanism->elements, kerberos_oid, sizeof(kerberos_oid)) ||
        (flags & required) != required || (flags & (1U | 64U)) || delegated ||
        !output.length || output.length > reply_capacity) goto done;
    int local = 1, open = 0, same = 0;
    if (k->inquire(&minor, context, NULL, &target_name, NULL, NULL, NULL, &local, &open) != 0 ||
        local || !open || !target_name ||
        k->compare(&minor, target_name, k->expected_name, &same) != 0 || !same) goto done;
    if (k->display(&minor, name, &name_text, NULL) != 0) { result = YD_IDENTITY_ERROR; goto done; }
    if (!name_text.length || name_text.length >= principal_capacity ||
        memchr(name_text.value, 0, name_text.length)) goto done;
    const unsigned char *p = name_text.value;
    for (size_t i = 0; i < name_text.length; i++) if (p[i] < 33 || p[i] > 126) goto done;
    memcpy(principal, name_text.value, name_text.length);
    memcpy(reply, output.value, output.length); *reply_length = output.length; result = YD_IDENTITY_VALID;
done:
    if (name_text.value) k->release_buffer(&minor, &name_text);
    if (output.value) k->release_buffer(&minor, &output);
    if (name) k->release_name(&minor, &name);
    if (target_name) k->release_name(&minor, &target_name);
    if (delegated) k->release_cred(&minor, &delegated);
    if (context) k->delete_context(&minor, &context, NULL);
    if (result != YD_IDENTITY_VALID) {
        memset(principal, 0, principal_capacity); memset(reply, 0, reply_capacity); *reply_length = 0;
    }
    return result;
}
/* All blocking public boundaries defer POSIX cancellation through complete
 * cleanup. Restoring the caller's state may deliver pending cancellation only
 * after owned buffers, descriptors and protocol contexts have been released. */
static void restore_cancellation(int prior) {
    (void)pthread_setcancelstate(prior, NULL);
    if (prior == PTHREAD_CANCEL_ENABLE) pthread_testcancel();
}
#define GUARDED(call) \
    int prior; \
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &prior)) return YD_IDENTITY_ERROR; \
    YDIdentityResult result = (call); \
    restore_cancellation(prior); \
    return result
YDIdentityResult yd_identity_discover(const YDIdentityNetwork *n, const char *issuer, YDIdentityDiscovery *out) {
    GUARDED(discover(n, issuer, out));
}
YDIdentityResult yd_identity_jwks(const YDIdentityNetwork *n, const char *url, unsigned char *out,
    size_t capacity, size_t *length) { GUARDED(jwks(n, url, out, capacity, length)); }
YDIdentityResult yd_identity_introspect(const YDIdentityNetwork *n, const char *url,
    const char *id, const char *secret, const char *token, const char *issuer,
    const char *audience, const char *scope, int64_t now, YDOIDCIdentity *out) {
    GUARDED(introspect(n, url, id, secret, token, issuer, audience, scope, now, out));
}
YDIdentityResult yd_identity_revoke(const YDIdentityNetwork *n, const char *url, const char *id,
    const char *secret, const char *token) { GUARDED(revoke_token(n, url, id, secret, token)); }
YDIdentityResult yd_identity_ldap(const YDIdentityNetwork *n, const char *origin,
    const char *dn, const char *password) { GUARDED(ldap_bind(n, origin, dn, password)); }
YDIdentityResult yd_identity_aws(const YDIdentityNetwork *n, const char *url, const char *server,
    const char *auth, const char *date_string, const char *token, int64_t now, YDIdentityAWS *out) {
    GUARDED(aws(n, url, server, auth, date_string, token, now, out));
}
YDIdentityResult yd_identity_kerberos_accept(YDIdentityKerberos *k, const unsigned char *token,
    size_t length, const unsigned char *binding, size_t binding_length, char *principal,
    size_t capacity, unsigned char *reply, size_t reply_capacity, size_t *reply_length) {
    GUARDED(kerberos_accept(k, token, length, binding, binding_length, principal, capacity,
        reply, reply_capacity, reply_length));
}
#undef GUARDED
static void cancelled_constructor(void *object) { kerberos_free(object); }
YDIdentityKerberos *yd_identity_kerberos_new(const char *principal, const char *keytab) {
    int prior;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &prior)) return NULL;
    YDIdentityKerberos *object = kerberos_new(principal, keytab);
    pthread_cleanup_push(cancelled_constructor, object);
    restore_cancellation(prior);
    pthread_cleanup_pop(0);
    return object;
}
void yd_identity_kerberos_free(YDIdentityKerberos *k) {
    int prior;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &prior)) return;
    kerberos_free(k);
    restore_cancellation(prior);
}
