#define _POSIX_C_SOURCE 200809L
#include "transport/tls.h"
#include "security/access.h"
#include <arpa/inet.h>
#include <errno.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static _Thread_local bool hide_leaf, fail_digest;
X509 *__real_SSL_get0_peer_certificate(const SSL *ssl);
X509 *__wrap_SSL_get0_peer_certificate(const SSL *ssl) {
    return hide_leaf ? NULL : __real_SSL_get0_peer_certificate(ssl);
}
int __real_X509_digest(const X509 *cert, const EVP_MD *type, unsigned char *out, unsigned int *size);
int __wrap_X509_digest(const X509 *cert, const EVP_MD *type, unsigned char *out, unsigned int *size) {
    return fail_digest ? 0 : __real_X509_digest(cert, type, out, size);
}
static pthread_mutex_t gate_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t gate_changed;
static bool gate_active, gate_arrived, gate_release;
static SSL_CTX *gate_context;
void __real_SSL_CTX_free(SSL_CTX *context);
void __wrap_SSL_CTX_free(SSL_CTX *context) {
    pthread_mutex_lock(&gate_lock);
    if (gate_active && context == gate_context) {
        gate_arrived = true;
        pthread_cond_broadcast(&gate_changed);
        struct timespec limit;
        clock_gettime(CLOCK_MONOTONIC, &limit);
        limit.tv_sec += 5;
        while (!gate_release)
            if (pthread_cond_timedwait(&gate_changed, &gate_lock, &limit)) abort();
    }
    pthread_mutex_unlock(&gate_lock);
    __real_SSL_CTX_free(context);
}
static uint64_t now(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) abort();
    return (uint64_t)t.tv_sec * 1000 + (uint64_t)t.tv_nsec / 1000000;
}
static bool hash(const char *text, unsigned char out[32]) {
    if (strlen(text) != 64) return false;
    for (size_t i = 0; i < 32; i++) {
        unsigned value;
        if (sscanf(text + i * 2, "%2x", &value) != 1) return false;
        out[i] = (unsigned char)value;
    }
    return true;
}
static void identity(YDConnection *connection) {
    YDTLSClientIdentity value;
    memset(&value, 0xa5, sizeof(value));
    YDTLSClientIdentityResult result = yd_connection_client_identity(connection, &value);
    printf("{\"result\":%d,\"verified\":%s,\"sha256\":\"", result,
           value.verified ? "true" : "false");
    for (size_t i = 0; i < sizeof(value.leaf_sha256); i++) printf("%02x", value.leaf_sha256[i]);
    bool clear = true;
    if (result != YD_TLS_CLIENT_VERIFIED)
        for (size_t i = 0; i < sizeof(value); i++) clear &= ((unsigned char *)&value)[i] == 0;
    printf("\",\"cleared\":%s}\n", clear ? "true" : "false");
}
static void request(YDAccess *access, const YDAccessPrincipal *principal,
                    const char *authorization, char *line) {
    char method[8], target[1025];
    int consumed = 0;
    if (sscanf(line, "%7s %1024s %n", method, target, &consumed) < 2) abort();
    const unsigned char *body = (const unsigned char *)line + consumed;
    const char *name = yd_access_principal_name(access, principal);
    int status = authorization ? yd_access_request(access, authorization, method, target, body, strlen((const char *)body)) :
        yd_access_principal_request(access, principal, method, target, body, strlen((const char *)body));
    bool writer = authorization ? yd_access_writer(access, authorization) : yd_access_principal_writer(access, principal);
    printf("{\"status\":%d,\"writer\":%s,\"name\":\"%s\"}\n", status,
           writer ? "true" : "false", name ? name : "");
}
typedef struct { YDTLS *tls; bool valid; } Reload;
static void *reload_context(void *argument) {
    Reload *reload = argument;
    char error[256];
    reload->valid = yd_tls_reload(reload->tls, error, sizeof(error));
    return NULL;
}
/* Force the old SSL_CTX's profile-owned reference release to overlap identity
 * extraction. The SSL still owns its context; no raw tag points at YDTLS. */
static void overlap(YDTLS *tls, YDConnection *connection) {
    YDTLSClientIdentity before, during, after;
    if (yd_connection_client_identity(connection, &before) != YD_TLS_CLIENT_VERIFIED) abort();
    pthread_mutex_lock(&gate_lock);
    gate_context = SSL_get_SSL_CTX(connection->tls);
    gate_active = true; gate_arrived = gate_release = false;
    pthread_mutex_unlock(&gate_lock);
    Reload reload = {.tls = tls};
    pthread_t thread;
    if (pthread_create(&thread, NULL, reload_context, &reload)) abort();
    pthread_mutex_lock(&gate_lock);
    struct timespec limit;
    clock_gettime(CLOCK_MONOTONIC, &limit);
    limit.tv_sec += 5;
    while (!gate_arrived)
        if (pthread_cond_timedwait(&gate_changed, &gate_lock, &limit)) abort();
    pthread_mutex_unlock(&gate_lock);
    bool valid = yd_connection_client_identity(connection, &during) == YD_TLS_CLIENT_VERIFIED &&
        !memcmp(before.leaf_sha256, during.leaf_sha256, 32);
    pthread_mutex_lock(&gate_lock);
    gate_release = true;
    pthread_cond_broadcast(&gate_changed);
    pthread_mutex_unlock(&gate_lock);
    pthread_join(thread, NULL);
    pthread_mutex_lock(&gate_lock);
    gate_active = false;
    pthread_mutex_unlock(&gate_lock);
    valid &= reload.valid && yd_connection_client_identity(connection, &after) == YD_TLS_CLIENT_VERIFIED &&
        !memcmp(before.leaf_sha256, after.leaf_sha256, 32);
    puts(valid ? "OVERLAP" : "BROKEN");
}
typedef struct { const YDAccess *access; const YDAccessPrincipal *principal; bool valid; } PolicyReader;
static void *policy_reader(void *argument) {
    PolicyReader *reader = argument;
    reader->valid = true;
    for (unsigned i = 0; i < 1000; i++)
        reader->valid &= yd_access_principal_name(reader->access, reader->principal) != NULL &&
            yd_access_principal_request(reader->access, reader->principal, "GET",
                "/v1/collections/allowed/documents/item", NULL, 0) == 0 &&
            yd_access_principal_request(reader->access, reader->principal, "GET",
                "/v1/collections/private/documents/item", NULL, 0) == 403;
    return NULL;
}
static void ownership(const char *path, YDAccess *access, const unsigned char pin[32]) {
    char error[256];
    YDAccess *other = yd_access_load(path, error, sizeof(error));
    const YDAccessPrincipal *p = yd_access_identify_certificate(access, pin);
    bool valid = other && p && !yd_access_principal_name(other, p) && !yd_access_principal_writer(other, p) &&
        yd_access_principal_request(other, p, "GET", "/v1/cluster/leader", NULL, 0) == 401;
    yd_access_free(other);
    PolicyReader readers[4];
    pthread_t threads[4];
    for (size_t i = 0; i < 4; i++) {
        readers[i] = (PolicyReader){.access = access, .principal = p};
        if (pthread_create(&threads[i], NULL, policy_reader, &readers[i])) abort();
    }
    for (size_t i = 0; i < 4; i++) {
        pthread_join(threads[i], NULL);
        valid &= readers[i].valid;
    }
    puts(valid ? "OWNED" : "BROKEN");
}
static int policy(const char *path) {
    char error[256], line[8192];
    YDAccess *access = yd_access_load(path, error, sizeof(error));
    if (!access) { puts("REJECTED"); return 1; }
    printf("LOADED %d\n", yd_access_has_certificate_principals(access));
    while (fgets(line, sizeof(line), stdin)) {
        line[strcspn(line, "\n")] = 0;
        if (!strncmp(line, "cert ", 5) || !strncmp(line, "ownership ", 10)) {
            bool own = line[0] == 'o';
            char *pin = line + (own ? 10 : 5), *rest = strchr(pin, ' ');
            if (rest) *rest++ = 0;
            unsigned char bytes[32];
            if (!hash(pin, bytes)) abort();
            if (own) ownership(path, access, bytes);
            else if (rest) request(access, yd_access_identify_certificate(access, bytes), NULL, rest);
            else abort();
        } else if (!strncmp(line, "bearer ", 7)) {
            char *token = line + 7, *rest = strchr(token, ' '), authorization[520];
            if (!rest) abort();
            *rest++ = 0;
            if (snprintf(authorization, sizeof(authorization), "Bearer %s", !strcmp(token, "-") ? "" : token) >= (int)sizeof(authorization)) abort();
            request(access, NULL, authorization, rest);
        } else if (!strncmp(line, "conflict ", 9)) {
            printf("CONFLICT %d\n", yd_access_conflicts(access, line + 9, strlen(line + 9)));
        } else break;
        fflush(stdout);
    }
    yd_access_free(access);
    return 0;
}
static bool handshake(YDConnection *connection, int fd, YDTLS *tls, bool binary) {
    if (!binary) return yd_connection_init(connection, fd, tls, 2000);
    if (!yd_connection_binary_begin(connection, fd, tls)) return false;
    YDTLSClientIdentity value;
    if (yd_connection_client_identity(connection, &value) != YD_TLS_CLIENT_ERROR) abort();
    uint64_t deadline = now() + 2000;
    for (;;) {
        YDTLSStep result = yd_connection_handshake_step(connection, deadline);
        if (result == YD_TLS_READY) return true;
        if (result == YD_TLS_ERROR || result == YD_TLS_EOF) return false;
        struct pollfd waiter = {.fd = fd, .events = result == YD_TLS_WANT_READ ? POLLIN : POLLOUT};
        if (now() >= deadline || poll(&waiter, 1, (int)(deadline - now())) <= 0) return false;
    }
}
static bool byte_io(YDConnection *connection, char *byte, bool write) {
    uint64_t deadline = now() + 2000;
    for (;;) {
        size_t transferred = 0;
        YDTLSStep result = write ? yd_connection_write_step(connection, byte, 1, deadline, &transferred) :
                                  yd_connection_read_step(connection, byte, 1, deadline, &transferred);
        if (result == YD_TLS_READY) return transferred == 1;
        if (result == YD_TLS_ERROR || result == YD_TLS_EOF) return false;
        struct pollfd waiter = {.fd = connection->fd, .events = result == YD_TLS_WANT_READ ? POLLIN : POLLOUT};
        uint64_t current = now();
        if (current >= deadline || poll(&waiter, 1, (int)(deadline - current)) <= 0) return false;
    }
}
static const char *optional(const char *s) { return strcmp(s, "-") ? s : NULL; }
static int serve(char **args) {
    char error[256], line[8192];
    bool binary = !strcmp(args[0], "binary"), peer = !strcmp(args[0], "peer");
    YDTLSOptions options = {.crl_file = optional(args[4])};
    YDTLS *tls = binary ? yd_tls_binary_new_with_options(args[1], args[2], optional(args[3]), &options, error, sizeof(error)) :
        peer ? yd_tls_peer_new_with_options(args[1], args[2], optional(args[3]), &options, error, sizeof(error)) :
               yd_tls_new_with_options(args[1], args[2], optional(args[3]), &options, error, sizeof(error));
    YDAccess *access = optional(args[5]) ? yd_access_load(args[5], error, sizeof(error)) : NULL;
    if (!tls || (optional(args[5]) && !access)) { yd_tls_free(tls); yd_access_free(access); return 2; }
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t size = sizeof(address);
    if (listener < 0 || bind(listener, (struct sockaddr *)&address, sizeof(address)) ||
        listen(listener, 4) || getsockname(listener, (struct sockaddr *)&address, &size)) abort();
    printf("PORT %u\n", (unsigned)ntohs(address.sin_port));
    fflush(stdout);
    YDConnection connection = {0};
    int fd = -1;
    while (fgets(line, sizeof(line), stdin)) {
        line[strcspn(line, "\n")] = 0;
        if (!strcmp(line, "accept")) {
            if (fd >= 0 || !tls) abort();
            struct pollfd waiter = {.fd = listener, .events = POLLIN};
            if (poll(&waiter, 1, 5000) <= 0) abort();
            fd = accept(listener, NULL, NULL);
            if (fd < 0) abort();
            if (handshake(&connection, fd, tls, binary)) puts("ACCEPTED");
            else { yd_connection_close(&connection); close(fd); fd = -1; puts("REJECTED"); }
        } else if (!strcmp(line, "identity")) identity(&connection);
        else if (!strcmp(line, "reload")) puts(tls && yd_tls_reload(tls, error, sizeof(error)) ? "RELOADED" : "RETAINED");
        else if (!strcmp(line, "overlap")) overlap(tls, &connection);
        else if (!strcmp(line, "free-profile")) { yd_tls_free(tls); tls = NULL; puts("FREED"); }
        else if (!strncmp(line, "request ", 8)) {
            YDTLSClientIdentity value;
            const YDAccessPrincipal *p = yd_connection_client_identity(&connection, &value) == YD_TLS_CLIENT_VERIFIED ?
                yd_access_identify_certificate(access, value.leaf_sha256) : NULL;
            request(access, p, NULL, line + 8);
        } else if (!strcmp(line, "echo")) {
            char byte;
            bool ok = binary ? byte_io(&connection, &byte, false) && byte_io(&connection, &byte, true) :
                yd_connection_read(&connection, &byte, 1, now() + 2000) == 1 && yd_connection_send(&connection, &byte, 1);
            puts(ok ? "ECHOED" : "BROKEN");
        } else if (!strcmp(line, "close")) {
            yd_connection_close(&connection); if (fd >= 0) close(fd); fd = -1; puts("CLOSED");
        } else if (!strcmp(line, "null")) {
            YDTLSClientIdentity value;
            memset(&value, 0xa5, sizeof(value));
            bool ok = yd_connection_client_identity(NULL, &value) == YD_TLS_CLIENT_ERROR &&
                      !value.verified && yd_connection_client_identity(&connection, NULL) == YD_TLS_CLIENT_ERROR;
            puts(ok ? "NULL-SAFE" : "BROKEN");
        } else if (!strcmp(line, "failed")) {
            bool saved = connection.failed; connection.failed = true; identity(&connection); connection.failed = saved;
        } else if (!strcmp(line, "verify-off")) {
            int mode = SSL_get_verify_mode(connection.tls);
            SSL_set_verify(connection.tls, SSL_VERIFY_NONE, NULL); identity(&connection);
            SSL_set_verify(connection.tls, mode, NULL);
        } else if (!strcmp(line, "verify-bad")) {
            long saved = SSL_get_verify_result(connection.tls);
            SSL_set_verify_result(connection.tls, X509_V_ERR_CERT_REVOKED); identity(&connection);
            SSL_set_verify_result(connection.tls, saved);
        } else if (!strcmp(line, "shutdown")) {
            int saved = SSL_get_shutdown(connection.tls);
            SSL_set_shutdown(connection.tls, SSL_RECEIVED_SHUTDOWN); identity(&connection);
            SSL_set_shutdown(connection.tls, saved);
        } else if (!strcmp(line, "no-leaf")) { hide_leaf = true; identity(&connection); hide_leaf = false; }
        else if (!strcmp(line, "digest-fail")) { fail_digest = true; identity(&connection); fail_digest = false; }
        else break;
        fflush(stdout);
    }
    yd_connection_close(&connection);
    if (fd >= 0) close(fd);
    close(listener);
    yd_tls_free(tls);
    yd_access_free(access);
    return 0;
}
int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    setvbuf(stdout, NULL, _IOLBF, 0);
    pthread_condattr_t attr;
    if (pthread_condattr_init(&attr) || pthread_condattr_setclock(&attr, CLOCK_MONOTONIC) ||
        pthread_cond_init(&gate_changed, &attr)) abort();
    pthread_condattr_destroy(&attr);
    if (argc == 3 && !strcmp(argv[1], "policy")) return policy(argv[2]);
    if (argc == 7) return serve(argv + 1);
    return 2;
}
