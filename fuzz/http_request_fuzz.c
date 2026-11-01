#define _POSIX_C_SOURCE 200809L

#define main yamldb_daemon_main
#include "../src/daemon.c"
#undef main

#include "filesystem.h"

#include <sys/socket.h>

static bool read_input(
    const char *path,
    unsigned char **input,
    size_t *input_length
)
{
    *input = NULL;
    *input_length = 0;
    int descriptor = open(path, O_RDONLY | O_CLOEXEC);
    if (descriptor < 0) {
        return false;
    }
    struct stat status;
    if (fstat(descriptor, &status) != 0 || status.st_size < 0 ||
        status.st_size > REQUEST_LIMIT + REQUEST_BODY_LIMIT) {
        close(descriptor);
        return false;
    }
    size_t length = (size_t)status.st_size;
    unsigned char *buffer = malloc(length == 0 ? 1 : length);
    if (buffer == NULL) {
        close(descriptor);
        return false;
    }
    size_t used = 0;
    while (used < length) {
        ssize_t result = read(descriptor, buffer + used, length - used);
        if (result < 0 && errno == EINTR) {
            continue;
        }
        if (result <= 0) {
            free(buffer);
            close(descriptor);
            return false;
        }
        used += (size_t)result;
    }
    close(descriptor);
    *input = buffer;
    *input_length = length;
    return true;
}

static unsigned char hex_value(unsigned char byte)
{
    if (byte >= '0' && byte <= '9') {
        return (unsigned char)(byte - '0');
    }
    if (byte >= 'a' && byte <= 'f') {
        return (unsigned char)(byte - 'a' + 10);
    }
    if (byte >= 'A' && byte <= 'F') {
        return (unsigned char)(byte - 'A' + 10);
    }
    return 255;
}

static size_t decode_escaped_seed(unsigned char *input, size_t length)
{
    static const unsigned char prefix[] = "ESCAPED\n";
    if (length < sizeof(prefix) - 1 ||
        memcmp(input, prefix, sizeof(prefix) - 1) != 0) {
        return length;
    }
    size_t source = sizeof(prefix) - 1;
    size_t target = 0;
    if (length > source && input[length - 1] == '\n') {
        length--;
    }
    while (source < length) {
        if (input[source] != '\\' || source + 1 >= length) {
            input[target++] = input[source++];
            continue;
        }
        unsigned char escape = input[source + 1];
        if (escape == 'r' || escape == 'n' || escape == 't' || escape == '\\') {
            input[target++] = escape == 'r' ? '\r' :
                escape == 'n' ? '\n' : escape == 't' ? '\t' : '\\';
            source += 2;
            continue;
        }
        if (escape == 'x' && source + 3 < length) {
            unsigned char high = hex_value(input[source + 2]);
            unsigned char low = hex_value(input[source + 3]);
            if (high != 255 && low != 255) {
                input[target++] = (unsigned char)((high << 4) | low);
                source += 4;
                continue;
            }
        }
        input[target++] = input[source++];
    }
    return target;
}

static void initialize_metrics(Metrics *metrics)
{
    atomic_init(&metrics->accepted, 0);
    atomic_init(&metrics->active, 0);
    atomic_init(&metrics->completed, 0);
    atomic_init(&metrics->responses_2xx, 0);
    atomic_init(&metrics->responses_4xx, 0);
    atomic_init(&metrics->responses_5xx, 0);
    atomic_init(&metrics->authentication_failures, 0);
    atomic_init(&metrics->overload_rejections, 0);
    atomic_init(&metrics->response_bytes, 0);
    atomic_init(&metrics->writes, 0);
    atomic_init(&metrics->write_conflicts, 0);
}

static bool initialize_server(Server *server, const char *data_dir, bool replica)
{
    static const char auth_token[] = "0123456789abcdef0123456789abcdef";
    static const unsigned char document_body[] = "value: seed\n";
    bool published = false;
    char error[256];
    if (!yamldb_store_put(
            data_dir,
            "notes",
            "seed",
            document_body,
            sizeof(document_body) - 1,
            &published,
            error,
            sizeof(error)
        )) {
        return false;
    }
    YamlDBSnapshot *snapshot = malloc(sizeof(*snapshot));
    if (snapshot == NULL || !yamldb_snapshot_load(data_dir, snapshot, error, sizeof(error))) {
        free(snapshot);
        return false;
    }

    memset(server, 0, sizeof(*server));
    server->data_dir = data_dir;
    server->auth_token = auth_token;
    server->auth_token_length = sizeof(auth_token) - 1;
    server->write_auth_token = auth_token;
    server->write_auth_token_length = sizeof(auth_token) - 1;
    server->io_timeout_ms = 25;
    server->worker_count = 1;
    initialize_metrics(&server->metrics);
    if (!initialize_queue(&server->queue, 1)) {
        yamldb_snapshot_free(snapshot);
        free(snapshot);
        return false;
    }
    if (pthread_rwlock_init(&server->snapshot_lock, NULL) != 0) {
        destroy_queue(&server->queue);
        yamldb_snapshot_free(snapshot);
        free(snapshot);
        return false;
    }
    if (pthread_mutex_init(&server->write_lock, NULL) != 0) {
        (void)pthread_rwlock_destroy(&server->snapshot_lock);
        destroy_queue(&server->queue);
        yamldb_snapshot_free(snapshot);
        free(snapshot);
        return false;
    }
    if (!yd_engine_init(
            &server->engine,
            snapshot,
            data_dir,
            replica,
            &server->snapshot_lock,
            error,
            sizeof(error)
        )) {
        (void)pthread_mutex_destroy(&server->write_lock);
        (void)pthread_rwlock_destroy(&server->snapshot_lock);
        destroy_queue(&server->queue);
        yamldb_snapshot_free(snapshot);
        free(snapshot);
        return false;
    }
    (void)clock_gettime(CLOCK_MONOTONIC, &server->started_at);
    return true;
}

static void destroy_server(Server *server)
{
    YamlDBSnapshot *snapshot = server->engine.snapshot;
    yd_engine_destroy(&server->engine);
    yamldb_snapshot_free(snapshot);
    free(snapshot);
    (void)pthread_mutex_destroy(&server->write_lock);
    (void)pthread_rwlock_destroy(&server->snapshot_lock);
    destroy_queue(&server->queue);
}

static void prime_replication(Server *server, const char *target)
{
    if (strcmp(target, "/v1/replication/begin") == 0 ||
        strncmp(target, "/v1/replication/", 16) != 0) {
        return;
    }
    char body[128];
    int length = snprintf(
        body,
        sizeof(body),
        "revision: '%s'\ncollections: [notes]\n",
        server->engine.snapshot->revision
    );
    if (length <= 0 || (size_t)length >= sizeof(body)) {
        return;
    }
    YDReply result = yd_engine_request(
        &server->engine,
        "POST",
        "/v1/replication/begin",
        (const unsigned char *)body,
        (size_t)length,
        NULL,
        NULL
    );
    if (result.status == 200) {
        (void)snprintf(server->engine.session, sizeof(server->engine.session), "fuzz-session");
    }
    yd_reply_free(&result);
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        return 2;
    }
    unsigned char *input;
    size_t input_length;
    if (!read_input(argv[1], &input, &input_length)) {
        return 0;
    }
    input_length = decode_escaped_seed(input, input_length);

    char *request_bytes = malloc(input_length + 1);
    if (request_bytes == NULL) {
        free(input);
        return 0;
    }
    memcpy(request_bytes, input, input_length);
    request_bytes[input_length] = '\0';
    char *terminator = strstr(request_bytes, "\r\n\r\n");
    if (terminator == NULL) {
        free(request_bytes);
        free(input);
        return 0;
    }
    size_t header_length = (size_t)(terminator - request_bytes) + 4;
    if (header_length > REQUEST_LIMIT) {
        free(request_bytes);
        free(input);
        return 0;
    }
    Request request;
    const char *error_code = NULL;
    if (parse_request(request_bytes, header_length, &request, &error_code, false, false) != 0) {
        free(request_bytes);
        free(input);
        return 0;
    }
    size_t body_length = input_length - header_length;
    if (body_length != request.content_length) {
        free(request_bytes);
        free(input);
        return 0;
    }
    if (body_length > 0) {
        request.body = malloc(body_length);
        if (request.body == NULL) {
            free(request_bytes);
            free(input);
            return 0;
        }
        memcpy(request.body, input + header_length, body_length);
        request.body_length = body_length;
    }

    char data_dir[PATH_MAX];
    if (!yd_fuzz_data_dir(data_dir, "http-fuzz")) {
        free(request.body);
        free(request_bytes);
        free(input);
        return 0;
    }
    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) {
        yd_fuzz_remove_data_dir(data_dir);
        free(request.body);
        free(request_bytes);
        free(input);
        return 0;
    }
    Server server;
    bool replica = strncmp(request.target, "/v1/replication/", 16) == 0;
    if (!initialize_server(&server, data_dir, replica)) {
        close(sockets[0]);
        close(sockets[1]);
        yd_fuzz_remove_data_dir(data_dir);
        free(request.body);
        free(request_bytes);
        free(input);
        return 0;
    }
    prime_replication(&server, request.target);
    YDConnection connection;
    if (yd_connection_init(&connection, sockets[0], NULL, 100)) {
        route_request(&server, &connection, &request);
        yd_connection_close(&connection);
    }
    (void)shutdown(sockets[0], SHUT_RDWR);
    close(sockets[0]);
    unsigned char response[4096];
    while (recv(sockets[1], response, sizeof(response), 0) > 0) {
    }
    close(sockets[1]);
    destroy_server(&server);
    yd_fuzz_remove_data_dir(data_dir);
    free(request.body);
    free(request_bytes);
    free(input);
    return 0;
}
