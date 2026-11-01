#define _POSIX_C_SOURCE 200809L
#include "transport/tls.h"
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static const char request[] = "GET /readyz HTTP/1.1\r\nHost: server.test\r\n\r\n";
static const char response[] = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
typedef struct {
    YDTLS *tls;
    int fd;
    bool accepted, peer;
    size_t bytes;
} Server;
static uint64_t deadline(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000 + 2000;
}
static size_t receive(YDConnection *connection, const char *expected) {
    char data[256];
    size_t used = 0, size = strlen(expected);
    uint64_t end = deadline();
    while (used < size) {
        ssize_t got = yd_connection_read(connection, data + used, size - used, end);
        if (got <= 0)
            break;
        used += (size_t)got;
    }
    return used == size && !memcmp(data, expected, size) ? used : 0;
}
static void *serve(void *argument) {
    Server *server = argument;
    YDConnection connection;
    server->accepted = yd_connection_init(&connection, server->fd, server->tls, 2000);
    if (server->accepted && server->peer)
        server->accepted = yd_connection_peer_name(&connection, "client.test");
    if (server->accepted) {
        server->bytes = receive(&connection, request);
        if (server->bytes)
            (void)yd_connection_send(&connection, response, strlen(response));
    }
    yd_connection_close(&connection);
    close(server->fd);
    return NULL;
}
static const char *optional(const char *value) {
    return strcmp(value, "-") ? value : NULL;
}
static YDTLS *make(bool peer, bool legacy, char **arguments) {
    char error[256] = {0};
    YDTLSOptions options = {.crl_file = optional(arguments[3])};
    if (legacy)
        return peer ? yd_tls_peer_new(arguments[0], arguments[1], optional(arguments[2]), error,
                                      sizeof(error))
                    : yd_tls_new(arguments[0], arguments[1], optional(arguments[2]), error,
                                 sizeof(error));
    return peer ? yd_tls_peer_new_with_options(arguments[0], arguments[1], optional(arguments[2]),
                                               &options, error, sizeof(error))
                : yd_tls_new_with_options(arguments[0], arguments[1], optional(arguments[2]),
                                          &options, error, sizeof(error));
}
static SSL_CTX *http_client(char **arguments) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    bool valid = ctx && SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) == 1 &&
                 SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) == 1 &&
                 SSL_CTX_load_verify_locations(ctx, arguments[2], NULL) == 1;
    if (valid && optional(arguments[0]))
        valid = SSL_CTX_use_certificate_chain_file(ctx, arguments[0]) == 1 &&
                SSL_CTX_use_PrivateKey_file(ctx, arguments[1], SSL_FILETYPE_PEM) == 1;
    if (!valid) {
        SSL_CTX_free(ctx);
        return NULL;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    return ctx;
}
static void exchange(YDTLS *server_tls, YDTLS *client_tls, SSL_CTX *http, const char *name,
                     YDTLS *reload) {
    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets))
        exit(3);
    struct timeval timeout = {.tv_sec = 2};
    for (int i = 0; i < 2; i++) {
        setsockopt(sockets[i], SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        setsockopt(sockets[i], SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    }
    Server server = {.tls = server_tls, .fd = sockets[0], .peer = client_tls != NULL};
    pthread_t thread;
    if (pthread_create(&thread, NULL, serve, &server))
        exit(3);
    YDConnection client = {.fd = sockets[1], .timeout_ms = 2000};
    bool accepted;
    if (client_tls) {
        accepted = yd_connection_peer_connect(&client, sockets[1], client_tls, name, 2000);
    } else {
        SSL *ssl = SSL_new(http);
        static const unsigned char alpn[] = "\x08http/1.1";
        client.tls = ssl;
        accepted = ssl && SSL_set_fd(ssl, sockets[1]) == 1 && SSL_set1_host(ssl, name) == 1 &&
                   SSL_set_alpn_protos(ssl, alpn, sizeof(alpn) - 1) == 0 && SSL_connect(ssl) == 1;
    }
    char error[256];
    bool reloaded = reload && yd_tls_reload(reload, error, sizeof(error));
    size_t bytes = 0;
    if (accepted && yd_connection_send(&client, request, strlen(request)))
        bytes = receive(&client, response);
    /* A failed handshake must not attempt a shutdown that waits for a peer. */
    if (!accepted)
        client.failed = true;
    yd_connection_close(&client);
    close(sockets[1]);
    pthread_join(thread, NULL);
    printf("{\"server_accepted\":%s,\"client_accepted\":%s,\"server_bytes\":%zu,"
           "\"client_bytes\":%zu,\"reloaded\":%s}\n",
           server.accepted ? "true" : "false", accepted ? "true" : "false", server.bytes, bytes,
           reloaded ? "true" : "false");
    fflush(stdout);
}
int main(int argc, char **argv) {
    if (argc != 11)
        return 2;
    signal(SIGPIPE, SIG_IGN);
    bool peer = strstr(argv[1], "peer") != NULL, legacy = strstr(argv[1], "legacy") != NULL;
    YDTLS *server = make(peer, legacy, argv + 2);
    YDTLS *client = peer ? make(true, legacy, argv + 6) : NULL;
    SSL_CTX *http = peer ? NULL : http_client(argv + 6);
    if (!server || (peer ? !client : !http)) {
        yd_tls_free(server);
        yd_tls_free(client);
        SSL_CTX_free(http);
        puts("REJECTED");
        return 1;
    }
    puts("READY");
    fflush(stdout);
    char command[64], error[256];
    while (fgets(command, sizeof(command), stdin)) {
        if (!strcmp(command, "exchange\n"))
            exchange(server, client, http, argv[10], NULL);
        else if (!strcmp(command, "exchange-reload-server\n"))
            exchange(server, client, http, argv[10], server);
        else if (!strcmp(command, "exchange-reload-client\n") && client)
            exchange(server, client, http, argv[10], client);
        else if (!strcmp(command, "reload-server\n"))
            puts(yd_tls_reload(server, error, sizeof(error)) ? "RELOADED" : "RETAINED");
        else if (!strcmp(command, "reload-client\n") && client)
            puts(yd_tls_reload(client, error, sizeof(error)) ? "RELOADED" : "RETAINED");
        else
            break;
        fflush(stdout);
    }
    yd_tls_free(server);
    yd_tls_free(client);
    SSL_CTX_free(http);
    return 0;
}
