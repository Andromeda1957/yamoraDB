#define _POSIX_C_SOURCE 200809L
#include "access_identity.h"
#include "oidc_json.h"
#include "../src/transport/tls.h"
#include <openssl/ssl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
typedef YDOIDCJSONNode Node;
static const char *str(const Node *root, const char *key) {
    const Node *n = yd_oidc_json_get(root, key);
    return n && n->type == YD_OIDC_JSON_STRING ? n->text : "";
}
static long long num(const Node *root, const char *key) {
    const Node *n = yd_oidc_json_get(root, key);
    return n && n->type == YD_OIDC_JSON_NUMBER ? strtoll(n->text, NULL, 10) : 0;
}
static size_t unhex(const char *s, unsigned char *out, size_t capacity) {
    size_t n = strlen(s);
    if (n % 2 || n/2 > capacity) return 0;
    for (size_t i = 0; i < n; i += 2) {
        unsigned value;
        if (sscanf(s+i, "%2x", &value) != 1) return 0;
        out[i/2] = (unsigned char)value;
    }
    return n/2;
}
typedef struct { YDConnection connection; YDTLS *profile; int fd; bool success; } TLSFixture;
static void *server(void *argument) {
    TLSFixture *f = argument;
    f->success = yd_connection_init(&f->connection, f->fd, f->profile, 2000);
    return NULL;
}
static bool zero(const unsigned char out[32]) {
    unsigned char all = 0; for (size_t i = 0; i < 32; i++) all |= out[i];
    return all == 0;
}
static int tls_test(const char *cert, const char *key) {
    unsigned char binding[32], expected[32];
    YDConnection plain = {.fd = -1}; memset(binding, 1, sizeof(binding));
    if (yd_connection_channel_binding(&plain, binding) || !zero(binding)) return 10;
    for (int binary = 0; binary <= 1; binary++) {
        char error[128]; int pair[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair)) return 11;
        TLSFixture f = {.fd = pair[0]};
        f.profile = binary ? yd_tls_binary_new(cert, key, NULL, error, sizeof(error)) :
            yd_tls_new(cert, key, NULL, error, sizeof(error));
        if (!f.profile) return 12;
        pthread_t worker;
        if (pthread_create(&worker, NULL, server, &f)) return 13;
        SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx || !SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) ||
            SSL_CTX_load_verify_locations(ctx, cert, NULL) != 1) return 14;
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        SSL *client = SSL_new(ctx);
        if (!client || SSL_set_fd(client, pair[1]) != 1 || SSL_set1_host(client, "identity.local") != 1) return 15;
        if (binary) {
            static const unsigned char alpn[] = "\x0f" "yamora-binary/1";
            if (SSL_set_alpn_protos(client, alpn, sizeof(alpn)-1)) return 16;
        }
        if (SSL_connect(client) != 1 || pthread_join(worker, NULL) || !f.success) return 17;
        int failure = 0;
        YDConnection outbound = {.fd = pair[1], .tls = client};
        memset(binding, 1, sizeof(binding));
        if (yd_connection_channel_binding(&outbound, binding) || !zero(binding)) { failure = 18; goto cleanup; }
        memset(binding, 1, sizeof(binding));
        bool ok = yd_connection_channel_binding(&f.connection, binding);
        if (binary) { if (ok || !zero(binding)) { failure = 19; goto cleanup; } }
        else {
            static const char label[] = "EXPORTER-Channel-Binding";
            if (!ok || SSL_export_keying_material(client, expected, 32, label,
                sizeof(label)-1, NULL, 0, 1) != 1 || memcmp(binding, expected, 32)) { failure = 20; goto cleanup; }
            f.connection.failed = true; memset(binding, 1, sizeof(binding));
            if (yd_connection_channel_binding(&f.connection, binding) || !zero(binding)) { failure = 21; goto cleanup; }
            f.connection.failed = false;
            SSL_set_shutdown(f.connection.tls, SSL_RECEIVED_SHUTDOWN);
            memset(binding, 1, sizeof(binding));
            if (yd_connection_channel_binding(&f.connection, binding) || !zero(binding)) { failure = 22; goto cleanup; }
        }
cleanup:
        yd_connection_close(&f.connection); memset(binding, 1, sizeof(binding));
        if (yd_connection_channel_binding(&f.connection, binding) || !zero(binding)) failure = 23;
        SSL_free(client); SSL_CTX_free(ctx); yd_tls_free(f.profile); close(pair[0]); close(pair[1]);
        if (failure) return failure;
    }
    puts("ok"); return 0;
}
int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    if (argc == 4 && !strcmp(argv[1], "--tls")) return tls_test(argv[2], argv[3]);
    unsigned char input[65537]; size_t n = fread(input, 1, sizeof(input), stdin);
    YDOIDCJSON *doc = NULL;
    if (n > 65536 || yd_oidc_json_parse(input, n, 64, &doc) != YD_OIDC_JSON_OK) return 2;
    const Node *root = yd_oidc_json_root(doc);
    YDAccessIdentity *a = yd_access_identity_load(str(root, "path"), num(root, "offline") != 0, NULL, 0);
    if (!a) { puts("-1"); yd_oidc_json_free(doc); return 0; }
    puts("1");
    unsigned char binding[256]; size_t size = unhex(str(root, "binding"), binding, sizeof(binding));
    YDAccessIdentityVerified out;
    int result = yd_access_identity_authenticate(a, str(root, "authorization"), num(root, "tls") != 0,
        binding, size, num(root, "now"), &out);
    printf("%d\n%s\n%d\n", result, out.local_name, out.category);
    for (size_t i = 0; i < out.reply_length; i++) printf("%02x", out.reply[i]);
    putchar('\n');
    if (num(root, "expiry")) printf("%lld\n", (long long)out.expires_at);
    if (*str(root, "revoke")) {
        printf("%d\n", yd_access_identity_revoke(a, str(root, "revoke")));
        result = yd_access_identity_authenticate(a, str(root, "authorization"), num(root, "tls") != 0,
            binding, size, num(root, "now"), &out);
        printf("%d\n", result);
    }
    yd_access_identity_free(a); yd_oidc_json_free(doc); return 0;
}
