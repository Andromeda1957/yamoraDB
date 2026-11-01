#define _POSIX_C_SOURCE 200809L
#include "identity.h"
#include "oidc_json.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <openssl/ssl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
static int no_backend;
static int fail_clock_after_read, fail_clock_after_write, read_done, write_done;
static int bad_descriptor, descriptors[16], descriptor_count, bad_send;
static int cancel_mode, cancellation_started;
static int cancel_constructor;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t condition = PTHREAD_COND_INITIALIZER;
int __real_pthread_setcancelstate(int, int *);
int __wrap_pthread_setcancelstate(int state, int *prior) {
    if (cancel_constructor && state == PTHREAD_CANCEL_ENABLE) {
        cancel_constructor = 0;
        if (pthread_cancel(pthread_self())) abort();
    }
    return __real_pthread_setcancelstate(state, prior);
}
int __real_socket(int, int, int);
int __wrap_socket(int domain, int type, int protocol) {
    int fd = __real_socket(domain, type, protocol);
    if (fd >= 0) {
        if (descriptor_count == 16) abort();
        descriptors[descriptor_count++] = fd;
        if (!(fcntl(fd, F_GETFD) & FD_CLOEXEC) || !(fcntl(fd, F_GETFL) & O_NONBLOCK)) bad_descriptor = 1;
    }
    return fd;
}
ssize_t __real_send(int, const void *, size_t, int);
ssize_t __wrap_send(int fd, const void *data, size_t n, int flags) {
    if (!(flags & MSG_NOSIGNAL)) bad_send = 1;
    return __real_send(fd, data, n, flags);
}
int __real_clock_gettime(clockid_t, struct timespec *);
int __wrap_clock_gettime(clockid_t id, struct timespec *time_value) {
    if (id == CLOCK_MONOTONIC && ((fail_clock_after_read && read_done) ||
        (fail_clock_after_write && write_done))) { errno = EIO; return -1; }
    return __real_clock_gettime(id, time_value);
}
int __real_SSL_read_ex(SSL *, void *, size_t, size_t *);
int __wrap_SSL_read_ex(SSL *ssl, void *data, size_t n, size_t *used) {
    int r = __real_SSL_read_ex(ssl, data, n, used);
    if (r == 1 && *used) read_done = 1;
    return r;
}
int __real_SSL_write_ex(SSL *, const void *, size_t, size_t *);
int __wrap_SSL_write_ex(SSL *ssl, const void *data, size_t n, size_t *used) {
    int r = __real_SSL_write_ex(ssl, data, n, used);
    if (r == 1 && *used) write_done = 1;
    return r;
}
int __real_poll(struct pollfd *, nfds_t, int);
int __wrap_poll(struct pollfd *fds, nfds_t count, int timeout) {
    if (cancel_mode && write_done && count && (fds[0].events & POLLIN)) {
        pthread_mutex_lock(&mutex); cancellation_started = 1;
        pthread_cond_signal(&condition); pthread_mutex_unlock(&mutex);
    }
    return __real_poll(fds, count, timeout);
}
void *__real_dlopen(const char *, int);
void *__wrap_dlopen(const char *name, int flags) {
    if (no_backend && name && !strcmp(name, "libgssapi_krb5.so.2")) return NULL;
    return __real_dlopen(name, flags);
}
typedef YDOIDCJSONNode Node;
static const Node *root;
static const char *value(const char *key) {
    const Node *n = yd_oidc_json_get(root, key);
    return n && n->type == YD_OIDC_JSON_STRING ? n->text : "";
}
static int64_t number(const char *key) {
    const Node *n = yd_oidc_json_get(root, key);
    return n && n->type == YD_OIDC_JSON_NUMBER ? strtoll(n->text, NULL, 10) : 0;
}
static size_t unhex(const char *s, unsigned char *out, size_t capacity) {
    size_t n = strlen(s);
    if (n % 2 || n / 2 > capacity) return 0;
    for (size_t i = 0; i < n; i += 2) {
        unsigned v = 0;
        for (size_t j = 0; j < 2; j++) {
            char c = s[i + j];
            if (c >= '0' && c <= '9') v = v * 16 + (unsigned)(c - '0');
            else if (c >= 'a' && c <= 'f') v = v * 16 + (unsigned)(c - 'a' + 10);
            else return 0;
        }
        out[i / 2] = (unsigned char)v;
    }
    return n / 2;
}
static void *cancelled_request(void *argument) {
    YDIdentityNetwork *network = argument;
    YDOIDCIdentity out;
    (void)yd_identity_introspect(network, value("url"), "client", "synthetic-secret",
        "synthetic-token", value("issuer"), "yamora", "read", number("now"), &out);
    return NULL;
}
static void *cancelled_owner(void *argument) {
    (void)argument;
    YDIdentityKerberos *k = yd_identity_kerberos_new(value("principal"), value("keytab"));
    yd_identity_kerberos_free(k); return NULL;
}
int main(void) {
    signal(SIGPIPE, SIG_DFL);
    unsigned char input[65537]; size_t n = fread(input, 1, sizeof(input), stdin);
    YDOIDCJSON *doc = NULL;
    if (n > 65536 || yd_oidc_json_parse(input, n, 1024, &doc) != YD_OIDC_JSON_OK) return 2;
    root = yd_oidc_json_root(doc);
    no_backend = (int)number("no_backend");
    fail_clock_after_read = (int)number("fail_clock_after_read");
    fail_clock_after_write = (int)number("fail_clock_after_write");
    YDIdentityEndpoint endpoint = {value("origin"), value("address"), value("ca"), (unsigned)number("timeout")};
    YDIdentityNetwork network = {&endpoint, 1};
    const char *op = value("op"); int result = -1;
    if (!strcmp(op, "cancel_constructor")) {
        YDIdentityKerberos *k = yd_identity_kerberos_new(value("principal"), value("keytab"));
        if (!k) return 3;
        yd_identity_kerberos_free(k);
        cancel_constructor = 1; pthread_t worker; void *returned = NULL;
        if (pthread_create(&worker, NULL, cancelled_owner, NULL) ||
            pthread_join(worker, &returned) || returned != PTHREAD_CANCELED) return 3;
        printf("1\n");
    } else if (!strcmp(op, "cancel")) {
        cancel_mode = 1; pthread_t worker;
        if (pthread_create(&worker, NULL, cancelled_request, &network)) return 3;
        struct timespec until;
        clock_gettime(CLOCK_REALTIME, &until); until.tv_sec += 3;
        pthread_mutex_lock(&mutex);
        int error = 0;
        while (!cancellation_started && !error) error = pthread_cond_timedwait(&condition, &mutex, &until);
        pthread_mutex_unlock(&mutex);
        if (error || pthread_cancel(worker)) return 3;
        void *returned = NULL;
        if (pthread_join(worker, &returned) || returned != PTHREAD_CANCELED) return 3;
        printf("1\n");
    } else if (!strcmp(op, "discover")) {
        YDIdentityDiscovery out;
        result = yd_identity_discover(&network, value("issuer"), &out);
        printf("%d\n%s\n%s\n%s\n%s\n", result, out.issuer, out.jwks_uri,
            out.introspection_endpoint, out.revocation_endpoint);
    } else if (!strcmp(op, "jwks")) {
        unsigned char out[65537]; size_t used = 0;
        result = yd_identity_jwks(&network, value("url"), out, sizeof(out), &used);
        printf("%d\n%zu\n", result, used);
        if (used) fwrite(out, 1, used, stdout);
    } else if (!strcmp(op, "introspect")) {
        YDOIDCIdentity out;
        result = yd_identity_introspect(&network, value("url"), value("id"), value("secret"),
            value("token"), value("issuer"), value("audience"), value("scope"), number("now"), &out);
        printf("%d\n%s\n%s\n%lld\n%d\n", result, out.subject, out.client_id,
            (long long)out.expires_at, out.required_scope_present);
    } else if (!strcmp(op, "revoke")) {
        result = yd_identity_revoke(&network, value("url"), value("id"), value("secret"), value("token"));
        printf("%d\n", result);
    } else if (!strcmp(op, "ldap")) {
        result = yd_identity_ldap(&network, value("origin"), value("dn"), value("password"));
        printf("%d\n", result);
    } else if (!strcmp(op, "aws")) {
        YDIdentityAWS out;
        result = yd_identity_aws(&network, value("url"), value("server_id"), value("authorization"),
            value("date"), value("session_token"), number("now"), &out);
        printf("%d\n%s\n%s\n", result, out.arn, out.account);
    } else if (!strcmp(op, "google")) {
        YDOIDCOptions options = {value("issuer"), value("audience"), "openid", 0, 3600};
        const char *jwks = value("jwks");
        YDOIDC *oidc = yd_oidc_new_id(&options, (const unsigned char *)jwks, strlen(jwks), NULL, 0);
        YDOIDCIdentity out = {0};
        if (oidc) {
            if (number("as_access")) result = yd_oidc_verify(oidc, value("token"), strlen(value("token")), number("now"), &out);
            else result = yd_oidc_verify_id(oidc, value("token"), strlen(value("token")), value("nonce"), number("now"), &out);
        }
        printf("%d\n%s\n%s\n", result, out.subject, out.client_id); yd_oidc_free(oidc);
    } else if (!strcmp(op, "kerberos")) {
        unsigned char token[16384], binding[256], reply[16384];
        size_t tn = unhex(value("token"), token, sizeof(token));
        size_t bn = unhex(value("binding"), binding, sizeof(binding)), rn = 0;
        char principal[1025] = {0};
        YDIdentityKerberos *k = yd_identity_kerberos_new(value("principal"), value("keytab"));
        if (k) result = yd_identity_kerberos_accept(k, token, tn, binding, bn, principal,
            sizeof(principal), reply, sizeof(reply), &rn);
        printf("%d\n%s\n", result, principal);
        for (size_t i = 0; i < rn; i++) printf("%02x", reply[i]);
        putchar('\n'); yd_identity_kerberos_free(k);
    } else { yd_oidc_json_free(doc); return 2; }
    yd_oidc_json_free(doc);
    for (int i = 0; i < descriptor_count; i++) {
        errno = 0;
        if (fcntl(descriptors[i], F_GETFD) != -1 || errno != EBADF) bad_descriptor = 1;
    }
    if (bad_descriptor || bad_send) {
        fputs("socket flags or descriptor cleanup failed\n", stderr); return 3;
    }
    return 0;
}
