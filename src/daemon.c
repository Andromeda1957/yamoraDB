#define _POSIX_C_SOURCE 200809L

#include "snapshot.h"
#include "store.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_PORT 8765
#define DEFAULT_WORKERS 8
#define DEFAULT_QUEUE_CAPACITY 128
#define DEFAULT_IO_TIMEOUT_MS 1500
#define REQUEST_LIMIT 8192
#define REQUEST_TARGET_LIMIT 1024
#define REQUEST_HEADER_LIMIT 64
#define AUTH_TOKEN_LIMIT 512
#define CONTENT_TYPE_LIMIT 96
#define ETAG_HEADER_LIMIT 32
#define RESPONSE_HEADER_LIMIT 1024
#define METRICS_BODY_LIMIT 4096

typedef struct {
    int *descriptors;
    size_t capacity;
    size_t head;
    size_t tail;
    size_t count;
    bool stopping;
    pthread_mutex_t mutex;
    pthread_cond_t available;
} WorkQueue;

typedef struct {
    atomic_uint_fast64_t accepted;
    atomic_uint_fast64_t active;
    atomic_uint_fast64_t completed;
    atomic_uint_fast64_t responses_2xx;
    atomic_uint_fast64_t responses_4xx;
    atomic_uint_fast64_t responses_5xx;
    atomic_uint_fast64_t authentication_failures;
    atomic_uint_fast64_t overload_rejections;
    atomic_uint_fast64_t response_bytes;
    atomic_uint_fast64_t writes;
    atomic_uint_fast64_t write_conflicts;
} Metrics;

typedef struct {
    YamlDBSnapshot *snapshot;
    const char *data_dir;
    const char *auth_token;
    size_t auth_token_length;
    const char *write_auth_token;
    size_t write_auth_token_length;
    int io_timeout_ms;
    int worker_count;
    WorkQueue queue;
    Metrics metrics;
    pthread_rwlock_t snapshot_lock;
    pthread_mutex_t write_lock;
    struct timespec started_at;
} Server;

typedef struct {
    char method[8];
    char target[REQUEST_TARGET_LIMIT + 1];
    bool head_only;
    bool authorization_present;
    bool accepts_gzip;
    char authorization[AUTH_TOKEN_LIMIT + 8];
    bool content_length_present;
    size_t content_length;
    bool content_type_present;
    char content_type[CONTENT_TYPE_LIMIT];
    bool if_match_present;
    char if_match[ETAG_HEADER_LIMIT];
    bool if_none_match_present;
    char if_none_match[ETAG_HEADER_LIMIT];
    unsigned char *body;
    size_t body_length;
} Request;

static volatile sig_atomic_t running = 1;
static volatile sig_atomic_t listening_descriptor = -1;

static void stop_server(int signal_number)
{
    (void)signal_number;
    running = 0;
}

static uint64_t monotonic_milliseconds(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return 0;
    }
    return (uint64_t)now.tv_sec * UINT64_C(1000) +
        (uint64_t)now.tv_nsec / UINT64_C(1000000);
}

static bool parse_number(const char *value, long minimum, long maximum, int *result)
{
    char *end = NULL;
    errno = 0;
    long parsed = strtol(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' ||
        parsed < minimum || parsed > maximum) {
        return false;
    }
    *result = (int)parsed;
    return true;
}

static bool parse_bind_address(
    const char *value,
    struct in_addr *address,
    bool *loopback
)
{
    if (inet_pton(AF_INET, value, address) != 1) {
        return false;
    }
    uint32_t host = ntohl(address->s_addr);
    unsigned int first = (host >> 24) & 0xffU;
    unsigned int second = (host >> 16) & 0xffU;
    *loopback = first == 127;
    bool private_network = first == 10 ||
        (first == 172 && second >= 16 && second <= 31) ||
        (first == 192 && second == 168);
    return *loopback || private_network;
}

static bool parse_size(const char *value, size_t maximum, size_t *result)
{
    if (*value == '\0') {
        return false;
    }
    for (const char *cursor = value; *cursor != '\0'; cursor++) {
        if (!isdigit((unsigned char)*cursor)) {
            return false;
        }
    }
    char *end = NULL;
    errno = 0;
    unsigned long long parsed = strtoull(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' || parsed > maximum) {
        return false;
    }
    *result = (size_t)parsed;
    return true;
}

static bool initialize_queue(WorkQueue *queue, size_t capacity)
{
    memset(queue, 0, sizeof(*queue));
    queue->descriptors = calloc(capacity, sizeof(*queue->descriptors));
    if (queue->descriptors == NULL) {
        return false;
    }
    queue->capacity = capacity;
    if (pthread_mutex_init(&queue->mutex, NULL) != 0) {
        free(queue->descriptors);
        memset(queue, 0, sizeof(*queue));
        return false;
    }
    if (pthread_cond_init(&queue->available, NULL) != 0) {
        (void)pthread_mutex_destroy(&queue->mutex);
        free(queue->descriptors);
        memset(queue, 0, sizeof(*queue));
        return false;
    }
    return true;
}

static void destroy_queue(WorkQueue *queue)
{
    for (size_t index = 0; index < queue->count; index++) {
        size_t position = (queue->head + index) % queue->capacity;
        close(queue->descriptors[position]);
    }
    (void)pthread_cond_destroy(&queue->available);
    (void)pthread_mutex_destroy(&queue->mutex);
    free(queue->descriptors);
    memset(queue, 0, sizeof(*queue));
}

static bool enqueue_connection(WorkQueue *queue, int descriptor)
{
    bool accepted = false;
    (void)pthread_mutex_lock(&queue->mutex);
    if (!queue->stopping && queue->count < queue->capacity) {
        queue->descriptors[queue->tail] = descriptor;
        queue->tail = (queue->tail + 1) % queue->capacity;
        queue->count++;
        accepted = true;
        (void)pthread_cond_signal(&queue->available);
    }
    (void)pthread_mutex_unlock(&queue->mutex);
    return accepted;
}

static int dequeue_connection(WorkQueue *queue)
{
    (void)pthread_mutex_lock(&queue->mutex);
    while (queue->count == 0 && !queue->stopping) {
        (void)pthread_cond_wait(&queue->available, &queue->mutex);
    }
    if (queue->count == 0) {
        (void)pthread_mutex_unlock(&queue->mutex);
        return -1;
    }
    int descriptor = queue->descriptors[queue->head];
    queue->head = (queue->head + 1) % queue->capacity;
    queue->count--;
    (void)pthread_mutex_unlock(&queue->mutex);
    return descriptor;
}

static size_t queue_depth(WorkQueue *queue)
{
    (void)pthread_mutex_lock(&queue->mutex);
    size_t count = queue->count;
    (void)pthread_mutex_unlock(&queue->mutex);
    return count;
}

static void stop_queue(WorkQueue *queue)
{
    (void)pthread_mutex_lock(&queue->mutex);
    queue->stopping = true;
    (void)pthread_cond_broadcast(&queue->available);
    (void)pthread_mutex_unlock(&queue->mutex);
}

static const char *status_text(int status)
{
    switch (status) {
    case 200:
        return "OK";
    case 201:
        return "Created";
    case 204:
        return "No Content";
    case 400:
        return "Bad Request";
    case 401:
        return "Unauthorized";
    case 404:
        return "Not Found";
    case 405:
        return "Method Not Allowed";
    case 408:
        return "Request Timeout";
    case 409:
        return "Conflict";
    case 412:
        return "Precondition Failed";
    case 413:
        return "Content Too Large";
    case 415:
        return "Unsupported Media Type";
    case 431:
        return "Request Header Fields Too Large";
    case 503:
        return "Service Unavailable";
    default:
        return "Internal Server Error";
    }
}

static bool send_all(int descriptor, const char *body, size_t length)
{
    size_t sent = 0;
    while (sent < length) {
        ssize_t result = send(
            descriptor,
            body + sent,
            length - sent,
#ifdef MSG_NOSIGNAL
            MSG_NOSIGNAL
#else
            0
#endif
        );
        if (result < 0 && errno == EINTR) {
            continue;
        }
        if (result <= 0) {
            return false;
        }
        sent += (size_t)result;
    }
    return true;
}

static void record_response(Server *server, int status, size_t body_length)
{
    if (status >= 200 && status < 300) {
        atomic_fetch_add_explicit(
            &server->metrics.responses_2xx,
            1,
            memory_order_relaxed
        );
    } else if (status >= 400 && status < 500) {
        atomic_fetch_add_explicit(
            &server->metrics.responses_4xx,
            1,
            memory_order_relaxed
        );
    } else if (status >= 500) {
        atomic_fetch_add_explicit(
            &server->metrics.responses_5xx,
            1,
            memory_order_relaxed
        );
    }
    atomic_fetch_add_explicit(
        &server->metrics.response_bytes,
        body_length,
        memory_order_relaxed
    );
}

static void send_response(
    Server *server,
    int descriptor,
    int status,
    const char *content_type,
    const char *body,
    size_t body_length,
    const char *extra_headers,
    bool head_only
)
{
    char header[RESPONSE_HEADER_LIMIT];
    int written = snprintf(
        header,
        sizeof(header),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "Cache-Control: no-store\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "X-YamlDB-Revision: %s\r\n"
        "%s"
        "\r\n",
        status,
        status_text(status),
        content_type,
        body_length,
        server->snapshot->revision,
        extra_headers == NULL ? "" : extra_headers
    );
    record_response(server, status, body_length);
    if (written < 0 || (size_t)written >= sizeof(header)) {
        return;
    }
    if (!send_all(descriptor, header, (size_t)written) || head_only) {
        return;
    }
    (void)send_all(descriptor, body, body_length);
}

static void send_json_error(
    Server *server,
    int descriptor,
    int status,
    const char *code,
    bool head_only
)
{
    char body[256];
    int written = snprintf(body, sizeof(body), "{\"error\":\"%s\"}\n", code);
    if (written < 0 || (size_t)written >= sizeof(body)) {
        return;
    }
    const char *headers = NULL;
    if (status == 405) {
        headers = server->write_auth_token == NULL ?
            "Allow: GET, HEAD\r\n" :
            "Allow: GET, HEAD, PUT, DELETE\r\n";
    } else if (status == 401) {
        headers = "WWW-Authenticate: Bearer\r\n";
    } else if (status == 503) {
        headers = "Retry-After: 1\r\n";
    }
    send_response(
        server,
        descriptor,
        status,
        "application/json; charset=utf-8",
        body,
        (size_t)written,
        headers,
        head_only
    );
}

static bool secure_equal(
    const char *left,
    size_t left_length,
    const char *right,
    size_t right_length
)
{
    size_t maximum = left_length > right_length ? left_length : right_length;
    unsigned int difference = (unsigned int)(left_length ^ right_length);
    for (size_t index = 0; index < maximum; index++) {
        unsigned char left_byte = index < left_length ? (unsigned char)left[index] : 0;
        unsigned char right_byte = index < right_length ? (unsigned char)right[index] : 0;
        difference |= (unsigned int)(left_byte ^ right_byte);
    }
    return difference == 0;
}

static bool request_authorized(
    const Server *server,
    const Request *request,
    bool write
)
{
    const char *token = write ? server->write_auth_token : server->auth_token;
    size_t token_length = write ?
        server->write_auth_token_length : server->auth_token_length;
    if (token == NULL) {
        return true;
    }
    static const char prefix[] = "Bearer ";
    size_t authorization_length = strlen(request->authorization);
    if (!request->authorization_present ||
        authorization_length < sizeof(prefix) - 1 ||
        memcmp(request->authorization, prefix, sizeof(prefix) - 1) != 0) {
        return false;
    }
    const char *candidate = request->authorization + sizeof(prefix) - 1;
    size_t candidate_length = authorization_length - (sizeof(prefix) - 1);
    return secure_equal(
        candidate,
        candidate_length,
        token,
        token_length
    );
}

static bool valid_header_value(const char *value)
{
    for (size_t index = 0; value[index] != '\0'; index++) {
        unsigned char byte = (unsigned char)value[index];
        if ((byte < 0x20 && byte != '\t') || byte == 0x7f) {
            return false;
        }
    }
    return true;
}

static bool header_accepts_gzip(const char *value)
{
    const char *cursor = value;
    while (*cursor != '\0') {
        while (*cursor == ' ' || *cursor == '\t' || *cursor == ',') {
            cursor++;
        }
        const char *token = cursor;
        while (*cursor != '\0' && *cursor != ',' && *cursor != ';' &&
               *cursor != ' ' && *cursor != '\t') {
            cursor++;
        }
        if ((size_t)(cursor - token) == 4 && strncasecmp(token, "gzip", 4) == 0) {
            const char *parameters = cursor;
            const char *end = strchr(parameters, ',');
            size_t parameter_length = end == NULL ? strlen(parameters) :
                (size_t)(end - parameters);
            bool disabled = false;
            for (size_t index = 0; index + 2 < parameter_length; index++) {
                if (tolower((unsigned char)parameters[index]) == 'q' &&
                    parameters[index + 1] == '=' &&
                    parameters[index + 2] == '0') {
                    disabled = true;
                    break;
                }
            }
            if (!disabled) {
                return true;
            }
        }
        const char *comma = strchr(cursor, ',');
        if (comma == NULL) {
            break;
        }
        cursor = comma + 1;
    }
    return false;
}

static int parse_request(
    char *buffer,
    size_t header_length,
    Request *request,
    const char **error_code
)
{
    memset(request, 0, sizeof(*request));
    buffer[header_length] = '\0';
    char *line_end = strstr(buffer, "\r\n");
    if (line_end == NULL) {
        *error_code = "invalid_request_line";
        return 400;
    }
    *line_end = '\0';
    char version[16];
    char trailing;
    int fields = sscanf(
        buffer,
        "%7s %1024s %15s %c",
        request->method,
        request->target,
        version,
        &trailing
    );
    if (fields != 3 ||
        (strcmp(version, "HTTP/1.1") != 0 && strcmp(version, "HTTP/1.0") != 0)) {
        *error_code = "invalid_request_line";
        return 400;
    }
    request->head_only = strcmp(request->method, "HEAD") == 0;

    bool host_present = false;
    size_t header_count = 0;
    char *cursor = line_end + 2;
    while (*cursor != '\0') {
        char *next = strstr(cursor, "\r\n");
        if (next == NULL) {
            *error_code = "invalid_headers";
            return 400;
        }
        if (next == cursor) {
            break;
        }
        if (++header_count > REQUEST_HEADER_LIMIT ||
            *cursor == ' ' || *cursor == '\t') {
            *error_code = "invalid_headers";
            return 400;
        }
        *next = '\0';
        char *colon = strchr(cursor, ':');
        if (colon == NULL || colon == cursor) {
            *error_code = "invalid_headers";
            return 400;
        }
        for (char *name = cursor; name < colon; name++) {
            unsigned char byte = (unsigned char)*name;
            if (!(isalnum(byte) || byte == '-')) {
                *error_code = "invalid_headers";
                return 400;
            }
        }
        *colon = '\0';
        char *value = colon + 1;
        while (*value == ' ' || *value == '\t') {
            value++;
        }
        char *value_end = value + strlen(value);
        while (value_end > value &&
               (value_end[-1] == ' ' || value_end[-1] == '\t')) {
            *--value_end = '\0';
        }
        if (!valid_header_value(value)) {
            *error_code = "invalid_headers";
            return 400;
        }
        if (strcasecmp(cursor, "Host") == 0) {
            if (host_present || *value == '\0') {
                *error_code = "invalid_host";
                return 400;
            }
            host_present = true;
        } else if (strcasecmp(cursor, "Authorization") == 0) {
            if (request->authorization_present ||
                strlen(value) >= sizeof(request->authorization)) {
                *error_code = "invalid_authorization";
                return 400;
            }
            request->authorization_present = true;
            memcpy(request->authorization, value, strlen(value) + 1);
        } else if (strcasecmp(cursor, "Accept-Encoding") == 0) {
            request->accepts_gzip = request->accepts_gzip ||
                header_accepts_gzip(value);
        } else if (strcasecmp(cursor, "Content-Length") == 0) {
            if (request->content_length_present ||
                !parse_size(value, SIZE_MAX, &request->content_length)) {
                *error_code = "invalid_content_length";
                return 400;
            }
            request->content_length_present = true;
            if (request->content_length > YAMLDB_DOCUMENT_LIMIT) {
                *error_code = "request_body_too_large";
                return 413;
            }
        } else if (strcasecmp(cursor, "Content-Type") == 0) {
            if (request->content_type_present ||
                strlen(value) >= sizeof(request->content_type)) {
                *error_code = "invalid_content_type";
                return 400;
            }
            request->content_type_present = true;
            memcpy(request->content_type, value, strlen(value) + 1);
        } else if (strcasecmp(cursor, "If-Match") == 0) {
            if (request->if_match_present ||
                strlen(value) >= sizeof(request->if_match)) {
                *error_code = "invalid_if_match";
                return 400;
            }
            request->if_match_present = true;
            memcpy(request->if_match, value, strlen(value) + 1);
        } else if (strcasecmp(cursor, "If-None-Match") == 0) {
            if (request->if_none_match_present ||
                strlen(value) >= sizeof(request->if_none_match)) {
                *error_code = "invalid_if_none_match";
                return 400;
            }
            request->if_none_match_present = true;
            memcpy(request->if_none_match, value, strlen(value) + 1);
        } else if (strcasecmp(cursor, "Transfer-Encoding") == 0 ||
                   strcasecmp(cursor, "Expect") == 0 ||
                   strcasecmp(cursor, "Upgrade") == 0) {
            *error_code = "request_body_not_allowed";
            return 400;
        }
        cursor = next + 2;
    }
    if (strcmp(version, "HTTP/1.1") == 0 && !host_present) {
        *error_code = "host_required";
        return 400;
    }
    if ((strcmp(request->method, "GET") == 0 ||
         strcmp(request->method, "HEAD") == 0 ||
         strcmp(request->method, "DELETE") == 0) &&
        request->content_length != 0) {
        *error_code = "request_body_not_allowed";
        return 400;
    }
    return 0;
}

static int receive_request(
    int descriptor,
    int timeout_ms,
    Request *request,
    const char **error_code
)
{
    char buffer[REQUEST_LIMIT + 1];
    size_t used = 0;
    uint64_t deadline = monotonic_milliseconds() + (uint64_t)timeout_ms;
    for (;;) {
        char *terminator = used >= 4 ? strstr(buffer, "\r\n\r\n") : NULL;
        if (terminator != NULL) {
            size_t header_length = (size_t)(terminator - buffer) + 4;
            size_t initial_body_length = used - header_length;
            unsigned char *initial_body = NULL;
            if (initial_body_length > 0) {
                initial_body = malloc(initial_body_length);
                if (initial_body == NULL) {
                    *error_code = "request_allocation_failed";
                    return 500;
                }
                memcpy(initial_body, buffer + header_length, initial_body_length);
            }
            int status = parse_request(
                buffer, header_length, request, error_code
            );
            if (status != 0) {
                free(initial_body);
                return status;
            }
            if (initial_body_length > request->content_length) {
                free(initial_body);
                *error_code = "unexpected_request_bytes";
                return 400;
            }
            if (request->content_length == 0) {
                free(initial_body);
                return 0;
            }
            request->body = malloc(request->content_length);
            if (request->body == NULL) {
                free(initial_body);
                *error_code = "request_allocation_failed";
                return 500;
            }
            if (initial_body_length > 0) {
                memcpy(request->body, initial_body, initial_body_length);
            }
            free(initial_body);
            request->body_length = initial_body_length;
            while (request->body_length < request->content_length) {
                uint64_t now = monotonic_milliseconds();
                if (now >= deadline) {
                    *error_code = "request_timeout";
                    return 408;
                }
                struct pollfd body_poll = {
                    .fd = descriptor,
                    .events = POLLIN,
                    .revents = 0,
                };
                int body_ready;
                do {
                    body_ready = poll(
                        &body_poll, 1, (int)(deadline - now)
                    );
                } while (body_ready < 0 && errno == EINTR);
                if (body_ready == 0) {
                    *error_code = "request_timeout";
                    return 408;
                }
                if (body_ready < 0 ||
                    (body_poll.revents & (POLLERR | POLLNVAL)) != 0) {
                    *error_code = "invalid_request";
                    return 400;
                }
                ssize_t result = recv(
                    descriptor,
                    request->body + request->body_length,
                    request->content_length - request->body_length,
                    0
                );
                if (result < 0 && errno == EINTR) {
                    continue;
                }
                if (result <= 0) {
                    *error_code = "incomplete_request_body";
                    return 400;
                }
                request->body_length += (size_t)result;
            }
            return 0;
        }
        if (used == REQUEST_LIMIT) {
            *error_code = "headers_too_large";
            return 431;
        }
        uint64_t now = monotonic_milliseconds();
        if (now >= deadline) {
            *error_code = "request_timeout";
            return 408;
        }
        int remaining = (int)(deadline - now);
        struct pollfd poll_descriptor = {
            .fd = descriptor,
            .events = POLLIN,
            .revents = 0,
        };
        int ready;
        do {
            ready = poll(&poll_descriptor, 1, remaining);
        } while (ready < 0 && errno == EINTR);
        if (ready == 0) {
            *error_code = "request_timeout";
            return 408;
        }
        if (ready < 0 ||
            (poll_descriptor.revents & (POLLERR | POLLNVAL)) != 0) {
            *error_code = "invalid_request";
            return 400;
        }
        ssize_t result = recv(descriptor, buffer + used, REQUEST_LIMIT - used, 0);
        if (result < 0 && errno == EINTR) {
            continue;
        }
        if (result <= 0) {
            *error_code = "invalid_request";
            return 400;
        }
        used += (size_t)result;
        buffer[used] = '\0';
    }
}

static void serve_health(Server *server, int descriptor, bool head_only)
{
    static const char body[] =
        "{\"status\":\"ok\",\"service\":\"yamldb\",\"api_version\":2}\n";
    send_response(
        server,
        descriptor,
        200,
        "application/json; charset=utf-8",
        body,
        sizeof(body) - 1,
        NULL,
        head_only
    );
}

static void serve_ready(Server *server, int descriptor, bool head_only)
{
    char body[512];
    int written = snprintf(
        body,
        sizeof(body),
        "{\"status\":\"ready\",\"revision\":\"%s\","
        "\"collections\":%zu,\"documents\":%zu,\"bytes\":%zu,"
        "\"compressed_bytes\":%zu,\"writable\":%s}\n",
        server->snapshot->revision,
        server->snapshot->collection_count,
        server->snapshot->document_count,
        server->snapshot->byte_count,
        server->snapshot->compressed_byte_count,
        server->write_auth_token == NULL ? "false" : "true"
    );
    if (written < 0 || (size_t)written >= sizeof(body)) {
        send_json_error(server, descriptor, 500, "stats_unavailable", head_only);
        return;
    }
    send_response(
        server,
        descriptor,
        200,
        "application/json; charset=utf-8",
        body,
        (size_t)written,
        NULL,
        head_only
    );
}

static uint64_t server_uptime_seconds(const Server *server)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0 ||
        now.tv_sec < server->started_at.tv_sec) {
        return 0;
    }
    return (uint64_t)(now.tv_sec - server->started_at.tv_sec);
}

static void serve_stats(Server *server, int descriptor, bool head_only)
{
    char body[1024];
    int written = snprintf(
        body,
        sizeof(body),
        "{\"revision\":\"%s\",\"collections\":%zu,\"documents\":%zu,"
        "\"snapshot_bytes\":%zu,\"compressed_bytes\":%zu,\"workers\":%d,"
        "\"queue_capacity\":%zu,"
        "\"queue_depth\":%zu,\"uptime_seconds\":%llu,"
        "\"accepted\":%llu,\"active\":%llu,\"completed\":%llu,"
        "\"responses_2xx\":%llu,\"responses_4xx\":%llu,"
        "\"responses_5xx\":%llu,\"authentication_failures\":%llu,"
        "\"overload_rejections\":%llu,\"response_bytes\":%llu,"
        "\"writes\":%llu,\"write_conflicts\":%llu}\n",
        server->snapshot->revision,
        server->snapshot->collection_count,
        server->snapshot->document_count,
        server->snapshot->byte_count,
        server->snapshot->compressed_byte_count,
        server->worker_count,
        server->queue.capacity,
        queue_depth(&server->queue),
        (unsigned long long)server_uptime_seconds(server),
        (unsigned long long)atomic_load_explicit(&server->metrics.accepted, memory_order_relaxed),
        (unsigned long long)atomic_load_explicit(&server->metrics.active, memory_order_relaxed),
        (unsigned long long)atomic_load_explicit(&server->metrics.completed, memory_order_relaxed),
        (unsigned long long)atomic_load_explicit(&server->metrics.responses_2xx, memory_order_relaxed),
        (unsigned long long)atomic_load_explicit(&server->metrics.responses_4xx, memory_order_relaxed),
        (unsigned long long)atomic_load_explicit(&server->metrics.responses_5xx, memory_order_relaxed),
        (unsigned long long)atomic_load_explicit(&server->metrics.authentication_failures, memory_order_relaxed),
        (unsigned long long)atomic_load_explicit(&server->metrics.overload_rejections, memory_order_relaxed),
        (unsigned long long)atomic_load_explicit(&server->metrics.response_bytes, memory_order_relaxed),
        (unsigned long long)atomic_load_explicit(&server->metrics.writes, memory_order_relaxed),
        (unsigned long long)atomic_load_explicit(&server->metrics.write_conflicts, memory_order_relaxed)
    );
    if (written < 0 || (size_t)written >= sizeof(body)) {
        send_json_error(server, descriptor, 500, "stats_unavailable", head_only);
        return;
    }
    send_response(
        server,
        descriptor,
        200,
        "application/json; charset=utf-8",
        body,
        (size_t)written,
        NULL,
        head_only
    );
}

static void serve_metrics(Server *server, int descriptor, bool head_only)
{
    char body[METRICS_BODY_LIMIT];
    int written = snprintf(
        body,
        sizeof(body),
        "# TYPE yamldb_uptime_seconds gauge\n"
        "yamldb_uptime_seconds %llu\n"
        "# TYPE yamldb_snapshot_collections gauge\n"
        "yamldb_snapshot_collections %zu\n"
        "# TYPE yamldb_snapshot_documents gauge\n"
        "yamldb_snapshot_documents %zu\n"
        "# TYPE yamldb_snapshot_bytes gauge\n"
        "yamldb_snapshot_bytes %zu\n"
        "# TYPE yamldb_snapshot_compressed_bytes gauge\n"
        "yamldb_snapshot_compressed_bytes %zu\n"
        "# TYPE yamldb_queue_depth gauge\n"
        "yamldb_queue_depth %zu\n"
        "# TYPE yamldb_connections_active gauge\n"
        "yamldb_connections_active %llu\n"
        "# TYPE yamldb_connections_accepted_total counter\n"
        "yamldb_connections_accepted_total %llu\n"
        "# TYPE yamldb_connections_completed_total counter\n"
        "yamldb_connections_completed_total %llu\n"
        "# TYPE yamldb_responses_total counter\n"
        "yamldb_responses_total{class=\"2xx\"} %llu\n"
        "yamldb_responses_total{class=\"4xx\"} %llu\n"
        "yamldb_responses_total{class=\"5xx\"} %llu\n"
        "# TYPE yamldb_authentication_failures_total counter\n"
        "yamldb_authentication_failures_total %llu\n"
        "# TYPE yamldb_overload_rejections_total counter\n"
        "yamldb_overload_rejections_total %llu\n"
        "# TYPE yamldb_response_bytes_total counter\n"
        "yamldb_response_bytes_total %llu\n"
        "# TYPE yamldb_writes_total counter\n"
        "yamldb_writes_total %llu\n"
        "# TYPE yamldb_write_conflicts_total counter\n"
        "yamldb_write_conflicts_total %llu\n",
        (unsigned long long)server_uptime_seconds(server),
        server->snapshot->collection_count,
        server->snapshot->document_count,
        server->snapshot->byte_count,
        server->snapshot->compressed_byte_count,
        queue_depth(&server->queue),
        (unsigned long long)atomic_load_explicit(&server->metrics.active, memory_order_relaxed),
        (unsigned long long)atomic_load_explicit(&server->metrics.accepted, memory_order_relaxed),
        (unsigned long long)atomic_load_explicit(&server->metrics.completed, memory_order_relaxed),
        (unsigned long long)atomic_load_explicit(&server->metrics.responses_2xx, memory_order_relaxed),
        (unsigned long long)atomic_load_explicit(&server->metrics.responses_4xx, memory_order_relaxed),
        (unsigned long long)atomic_load_explicit(&server->metrics.responses_5xx, memory_order_relaxed),
        (unsigned long long)atomic_load_explicit(&server->metrics.authentication_failures, memory_order_relaxed),
        (unsigned long long)atomic_load_explicit(&server->metrics.overload_rejections, memory_order_relaxed),
        (unsigned long long)atomic_load_explicit(&server->metrics.response_bytes, memory_order_relaxed),
        (unsigned long long)atomic_load_explicit(&server->metrics.writes, memory_order_relaxed),
        (unsigned long long)atomic_load_explicit(&server->metrics.write_conflicts, memory_order_relaxed)
    );
    if (written < 0 || (size_t)written >= sizeof(body)) {
        send_json_error(server, descriptor, 500, "metrics_unavailable", head_only);
        return;
    }
    send_response(
        server,
        descriptor,
        200,
        "text/plain; version=0.0.4; charset=utf-8",
        body,
        (size_t)written,
        NULL,
        head_only
    );
}

static void serve_collection(
    Server *server,
    int descriptor,
    const char *collection_name,
    bool head_only
)
{
    const YamlDBCollection *collection = yamldb_snapshot_collection(
        server->snapshot,
        collection_name
    );
    if (collection == NULL) {
        send_json_error(server, descriptor, 404, "collection_not_found", head_only);
        return;
    }
    send_response(
        server,
        descriptor,
        200,
        "application/json; charset=utf-8",
        collection->index_body,
        collection->index_length,
        NULL,
        head_only
    );
}

static void serve_collection_page(
    Server *server,
    int descriptor,
    const char *collection_name,
    size_t limit,
    const char *after,
    bool head_only
)
{
    const YamlDBCollection *collection = yamldb_snapshot_collection(
        server->snapshot,
        collection_name
    );
    if (collection == NULL) {
        send_json_error(server, descriptor, 404, "collection_not_found", head_only);
        return;
    }
    size_t start = 0;
    if (after != NULL) {
        size_t low = 0;
        size_t high = collection->document_count;
        while (low < high) {
            size_t middle = low + (high - low) / 2;
            if (strcmp(collection->documents[middle].name, after) <= 0) {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        start = low;
    }
    size_t count = collection->document_count - start;
    if (count > limit) {
        count = limit;
    }
    size_t capacity = 128 + strlen(collection_name);
    for (size_t index = 0; index < count; index++) {
        capacity += strlen(collection->documents[start + index].name) + 4;
    }
    char *body = malloc(capacity);
    if (body == NULL) {
        send_json_error(server, descriptor, 500, "index_unavailable", head_only);
        return;
    }
    int initial = snprintf(
        body,
        capacity,
        "{\"collection\":\"%s\",\"documents\":[",
        collection_name
    );
    if (initial < 0 || (size_t)initial >= capacity) {
        free(body);
        send_json_error(server, descriptor, 500, "index_unavailable", head_only);
        return;
    }
    size_t used = (size_t)initial;
    for (size_t index = 0; index < count; index++) {
        int written = snprintf(
            body + used,
            capacity - used,
            "%s\"%s\"",
            index == 0 ? "" : ",",
            collection->documents[start + index].name
        );
        if (written < 0 || (size_t)written >= capacity - used) {
            free(body);
            send_json_error(server, descriptor, 500, "index_unavailable", head_only);
            return;
        }
        used += (size_t)written;
    }
    const char *next_after = NULL;
    if (count > 0 && start + count < collection->document_count) {
        next_after = collection->documents[start + count - 1].name;
    }
    int written;
    if (next_after == NULL) {
        written = snprintf(
            body + used, capacity - used, "],\"next_after\":null}\n"
        );
    } else {
        written = snprintf(
            body + used,
            capacity - used,
            "],\"next_after\":\"%s\"}\n",
            next_after
        );
    }
    if (written < 0 || (size_t)written >= capacity - used) {
        free(body);
        send_json_error(server, descriptor, 500, "index_unavailable", head_only);
        return;
    }
    used += (size_t)written;
    send_response(
        server,
        descriptor,
        200,
        "application/json; charset=utf-8",
        body,
        used,
        NULL,
        head_only
    );
    free(body);
}

static void serve_document(
    Server *server,
    int descriptor,
    const char *collection_name,
    const char *document_name,
    bool accepts_gzip,
    bool head_only
)
{
    const YamlDBCollection *collection = yamldb_snapshot_collection(
        server->snapshot,
        collection_name
    );
    const YamlDBDocument *document = collection == NULL ? NULL :
        yamldb_collection_document(collection, document_name);
    if (document == NULL) {
        send_json_error(server, descriptor, 404, "document_not_found", head_only);
        return;
    }
    bool compressed = accepts_gzip && document->gzip_body != NULL;
    const unsigned char *body = compressed ? document->gzip_body : document->body;
    size_t body_length = compressed ? document->gzip_length : document->length;
    char extra_headers[320];
    int written = snprintf(
        extra_headers,
        sizeof(extra_headers),
        "ETag: \"%016llx\"\r\n"
        "Vary: Accept-Encoding\r\n"
        "%s"
        "X-YamlDB-Collection: %s\r\n"
        "X-YamlDB-Document: %s\r\n",
        (unsigned long long)document->hash,
        compressed ? "Content-Encoding: gzip\r\n" : "",
        collection_name,
        document_name
    );
    if (written < 0 || (size_t)written >= sizeof(extra_headers)) {
        send_json_error(server, descriptor, 500, "document_unavailable", head_only);
        return;
    }
    send_response(
        server,
        descriptor,
        200,
        "application/yaml; charset=utf-8",
        (const char *)body,
        body_length,
        extra_headers,
        head_only
    );
}

static bool yaml_content_type(const Request *request)
{
    if (!request->content_type_present) {
        return false;
    }
    static const char application_yaml[] = "application/yaml";
    static const char text_yaml[] = "text/yaml";
    size_t length = strcspn(request->content_type, ";");
    return (length == sizeof(application_yaml) - 1 &&
            strncasecmp(request->content_type, application_yaml, length) == 0) ||
        (length == sizeof(text_yaml) - 1 &&
         strncasecmp(request->content_type, text_yaml, length) == 0);
}

static bool parse_etag_header(const char *value, uint64_t *hash)
{
    if (strlen(value) != 18 || value[0] != '"' || value[17] != '"') {
        return false;
    }
    uint64_t parsed = 0;
    for (size_t index = 1; index < 17; index++) {
        unsigned char byte = (unsigned char)value[index];
        unsigned int digit;
        if (byte >= '0' && byte <= '9') {
            digit = byte - '0';
        } else if (byte >= 'a' && byte <= 'f') {
            digit = byte - 'a' + 10;
        } else {
            return false;
        }
        parsed = (parsed << 4) | digit;
    }
    *hash = parsed;
    return true;
}

static bool reload_snapshot(Server *server, char *error, size_t error_length)
{
    YamlDBSnapshot *candidate = malloc(sizeof(*candidate));
    if (candidate == NULL) {
        (void)snprintf(error, error_length, "cannot allocate replacement snapshot");
        return false;
    }
    if (!yamldb_snapshot_load(
            server->data_dir, candidate, error, error_length
        )) {
        free(candidate);
        return false;
    }
    (void)pthread_rwlock_wrlock(&server->snapshot_lock);
    YamlDBSnapshot *previous = server->snapshot;
    server->snapshot = candidate;
    (void)pthread_rwlock_unlock(&server->snapshot_lock);
    yamldb_snapshot_free(previous);
    free(previous);
    return true;
}

static void serve_write_result(
    Server *server,
    int descriptor,
    int status,
    const char *collection_name,
    const char *document_name
)
{
    (void)pthread_rwlock_rdlock(&server->snapshot_lock);
    const YamlDBCollection *collection = yamldb_snapshot_collection(
        server->snapshot, collection_name
    );
    const YamlDBDocument *document = collection == NULL ? NULL :
        yamldb_collection_document(collection, document_name);
    if (document == NULL) {
        send_json_error(server, descriptor, 500, "write_visibility_failed", false);
        (void)pthread_rwlock_unlock(&server->snapshot_lock);
        return;
    }
    char body[384];
    int body_length = snprintf(
        body,
        sizeof(body),
        "{\"status\":\"stored\",\"collection\":\"%s\","
        "\"document\":\"%s\",\"etag\":\"%016llx\","
        "\"revision\":\"%s\"}\n",
        collection_name,
        document_name,
        (unsigned long long)document->hash,
        server->snapshot->revision
    );
    char headers[64];
    int header_length = snprintf(
        headers,
        sizeof(headers),
        "ETag: \"%016llx\"\r\n",
        (unsigned long long)document->hash
    );
    if (body_length < 0 || (size_t)body_length >= sizeof(body) ||
        header_length < 0 || (size_t)header_length >= sizeof(headers)) {
        send_json_error(server, descriptor, 500, "write_response_failed", false);
    } else {
        send_response(
            server,
            descriptor,
            status,
            "application/json; charset=utf-8",
            body,
            (size_t)body_length,
            headers,
            false
        );
    }
    (void)pthread_rwlock_unlock(&server->snapshot_lock);
}

static void write_document(
    Server *server,
    int descriptor,
    const Request *request,
    const char *collection_name,
    const char *document_name
)
{
    if (!yaml_content_type(request) || request->body_length == 0) {
        (void)pthread_rwlock_rdlock(&server->snapshot_lock);
        send_json_error(server, descriptor, 415, "yaml_content_type_required", false);
        (void)pthread_rwlock_unlock(&server->snapshot_lock);
        return;
    }
    if (!yamldb_valid_document_body(request->body, request->body_length)) {
        (void)pthread_rwlock_rdlock(&server->snapshot_lock);
        send_json_error(server, descriptor, 400, "invalid_document", false);
        (void)pthread_rwlock_unlock(&server->snapshot_lock);
        return;
    }
    if (request->if_match_present && request->if_none_match_present) {
        (void)pthread_rwlock_rdlock(&server->snapshot_lock);
        send_json_error(server, descriptor, 400, "conflicting_preconditions", false);
        (void)pthread_rwlock_unlock(&server->snapshot_lock);
        return;
    }
    bool create_only = request->if_none_match_present;
    if (create_only && strcmp(request->if_none_match, "*") != 0) {
        (void)pthread_rwlock_rdlock(&server->snapshot_lock);
        send_json_error(server, descriptor, 400, "invalid_if_none_match", false);
        (void)pthread_rwlock_unlock(&server->snapshot_lock);
        return;
    }
    uint64_t expected_hash = 0;
    if (request->if_match_present &&
        !parse_etag_header(request->if_match, &expected_hash)) {
        (void)pthread_rwlock_rdlock(&server->snapshot_lock);
        send_json_error(server, descriptor, 400, "invalid_if_match", false);
        (void)pthread_rwlock_unlock(&server->snapshot_lock);
        return;
    }

    (void)pthread_mutex_lock(&server->write_lock);
    (void)pthread_rwlock_rdlock(&server->snapshot_lock);
    const YamlDBCollection *collection = yamldb_snapshot_collection(
        server->snapshot, collection_name
    );
    const YamlDBDocument *existing = collection == NULL ? NULL :
        yamldb_collection_document(collection, document_name);
    bool conflict = (create_only && existing != NULL) ||
        (request->if_match_present &&
         (existing == NULL || existing->hash != expected_hash));
    bool created = existing == NULL;
    bool exceeds_limits =
        (created && server->snapshot->document_count == YAMLDB_SNAPSHOT_DOCUMENT_LIMIT) ||
        (collection != NULL && created &&
         collection->document_count == YAMLDB_COLLECTION_DOCUMENT_LIMIT) ||
        (collection == NULL &&
         server->snapshot->collection_count == YAMLDB_COLLECTION_LIMIT);
    (void)pthread_rwlock_unlock(&server->snapshot_lock);
    if (conflict) {
        atomic_fetch_add_explicit(
            &server->metrics.write_conflicts, 1, memory_order_relaxed
        );
        (void)pthread_rwlock_rdlock(&server->snapshot_lock);
        send_json_error(server, descriptor, 412, "write_precondition_failed", false);
        (void)pthread_rwlock_unlock(&server->snapshot_lock);
        (void)pthread_mutex_unlock(&server->write_lock);
        return;
    }
    if (exceeds_limits) {
        (void)pthread_rwlock_rdlock(&server->snapshot_lock);
        send_json_error(server, descriptor, 413, "database_limit_reached", false);
        (void)pthread_rwlock_unlock(&server->snapshot_lock);
        (void)pthread_mutex_unlock(&server->write_lock);
        return;
    }
    char error[256];
    if (!yamldb_store_put(
            server->data_dir,
            collection_name,
            document_name,
            request->body,
            request->body_length,
            error,
            sizeof(error)
        ) || !reload_snapshot(server, error, sizeof(error))) {
        (void)pthread_rwlock_rdlock(&server->snapshot_lock);
        send_json_error(server, descriptor, 500, "write_failed", false);
        (void)pthread_rwlock_unlock(&server->snapshot_lock);
        (void)pthread_mutex_unlock(&server->write_lock);
        return;
    }
    atomic_fetch_add_explicit(&server->metrics.writes, 1, memory_order_relaxed);
    serve_write_result(
        server,
        descriptor,
        created ? 201 : 200,
        collection_name,
        document_name
    );
    (void)pthread_mutex_unlock(&server->write_lock);
}

static void delete_document(
    Server *server,
    int descriptor,
    const Request *request,
    const char *collection_name,
    const char *document_name
)
{
    uint64_t expected_hash = 0;
    if (request->if_match_present &&
        !parse_etag_header(request->if_match, &expected_hash)) {
        (void)pthread_rwlock_rdlock(&server->snapshot_lock);
        send_json_error(server, descriptor, 400, "invalid_if_match", false);
        (void)pthread_rwlock_unlock(&server->snapshot_lock);
        return;
    }
    if (request->if_none_match_present) {
        (void)pthread_rwlock_rdlock(&server->snapshot_lock);
        send_json_error(server, descriptor, 400, "invalid_if_none_match", false);
        (void)pthread_rwlock_unlock(&server->snapshot_lock);
        return;
    }
    (void)pthread_mutex_lock(&server->write_lock);
    (void)pthread_rwlock_rdlock(&server->snapshot_lock);
    const YamlDBCollection *collection = yamldb_snapshot_collection(
        server->snapshot, collection_name
    );
    const YamlDBDocument *existing = collection == NULL ? NULL :
        yamldb_collection_document(collection, document_name);
    bool conflict = request->if_match_present &&
        (existing == NULL || existing->hash != expected_hash);
    (void)pthread_rwlock_unlock(&server->snapshot_lock);
    if (existing == NULL) {
        (void)pthread_rwlock_rdlock(&server->snapshot_lock);
        send_json_error(
            server,
            descriptor,
            conflict ? 412 : 404,
            conflict ? "write_precondition_failed" : "document_not_found",
            false
        );
        (void)pthread_rwlock_unlock(&server->snapshot_lock);
        (void)pthread_mutex_unlock(&server->write_lock);
        return;
    }
    if (conflict) {
        atomic_fetch_add_explicit(
            &server->metrics.write_conflicts, 1, memory_order_relaxed
        );
        (void)pthread_rwlock_rdlock(&server->snapshot_lock);
        send_json_error(server, descriptor, 412, "write_precondition_failed", false);
        (void)pthread_rwlock_unlock(&server->snapshot_lock);
        (void)pthread_mutex_unlock(&server->write_lock);
        return;
    }
    char error[256];
    if (!yamldb_store_delete(
            server->data_dir,
            collection_name,
            document_name,
            error,
            sizeof(error)
        ) || !reload_snapshot(server, error, sizeof(error))) {
        (void)pthread_rwlock_rdlock(&server->snapshot_lock);
        send_json_error(server, descriptor, 500, "delete_failed", false);
        (void)pthread_rwlock_unlock(&server->snapshot_lock);
        (void)pthread_mutex_unlock(&server->write_lock);
        return;
    }
    atomic_fetch_add_explicit(&server->metrics.writes, 1, memory_order_relaxed);
    (void)pthread_rwlock_rdlock(&server->snapshot_lock);
    send_response(
        server,
        descriptor,
        204,
        "application/json; charset=utf-8",
        "",
        0,
        NULL,
        false
    );
    (void)pthread_rwlock_unlock(&server->snapshot_lock);
    (void)pthread_mutex_unlock(&server->write_lock);
}

static bool parse_database_target(
    char *target,
    char collection[YAMLDB_NAME_LIMIT + 1],
    char **document
)
{
    static const char prefix[] = "/v1/collections/";
    static const char documents_path[] = "/documents";
    if (strncmp(target, prefix, sizeof(prefix) - 1) != 0) {
        return false;
    }
    char *collection_start = target + sizeof(prefix) - 1;
    char *separator = strchr(collection_start, '/');
    if (separator == NULL) {
        return false;
    }
    if (strcmp(separator, documents_path) != 0) {
        char *document_separator = strstr(separator, "/documents/");
        if (document_separator != separator) {
            return false;
        }
    }
    size_t collection_length = (size_t)(separator - collection_start);
    if (collection_length == 0 || collection_length > YAMLDB_NAME_LIMIT) {
        return false;
    }
    memcpy(collection, collection_start, collection_length);
    collection[collection_length] = '\0';
    if (!yamldb_valid_name(collection)) {
        return false;
    }
    char *remainder = separator + sizeof(documents_path) - 1;
    if (*remainder == '\0') {
        *document = NULL;
        return true;
    }
    if (*remainder != '/' || remainder[1] == '\0' ||
        strchr(remainder + 1, '/') != NULL ||
        !yamldb_valid_name(remainder + 1)) {
        return false;
    }
    *document = remainder + 1;
    return true;
}

static bool parse_page_query(
    char *query,
    size_t *limit,
    char after[YAMLDB_NAME_LIMIT + 1],
    const char **after_value
)
{
    bool limit_present = false;
    bool after_present = false;
    *limit = 100;
    *after_value = NULL;
    if (*query == '\0') {
        return false;
    }
    char *cursor = query;
    while (*cursor != '\0') {
        char *end = strchr(cursor, '&');
        if (end != NULL) {
            *end = '\0';
        }
        char *equals = strchr(cursor, '=');
        if (equals == NULL || equals == cursor ||
            strchr(equals + 1, '=') != NULL) {
            return false;
        }
        *equals = '\0';
        const char *value = equals + 1;
        if (strcmp(cursor, "limit") == 0) {
            if (limit_present || !parse_size(value, 1000, limit) || *limit == 0) {
                return false;
            }
            limit_present = true;
        } else if (strcmp(cursor, "after") == 0) {
            size_t length = strlen(value);
            if (after_present || length > YAMLDB_NAME_LIMIT ||
                !yamldb_valid_name(value)) {
                return false;
            }
            memcpy(after, value, length + 1);
            *after_value = after;
            after_present = true;
        } else {
            return false;
        }
        if (end == NULL) {
            break;
        }
        cursor = end + 1;
        if (*cursor == '\0') {
            return false;
        }
    }
    return true;
}

static void route_request(Server *server, int descriptor, const Request *request)
{
    bool write = strcmp(request->method, "PUT") == 0 ||
        strcmp(request->method, "DELETE") == 0;
    bool read = strcmp(request->method, "GET") == 0 || request->head_only;
    if (!write && !read) {
        (void)pthread_rwlock_rdlock(&server->snapshot_lock);
        send_json_error(server, descriptor, 405, "method_not_allowed", false);
        (void)pthread_rwlock_unlock(&server->snapshot_lock);
        return;
    }
    if (read && strcmp(request->target, "/healthz") == 0) {
        (void)pthread_rwlock_rdlock(&server->snapshot_lock);
        serve_health(server, descriptor, request->head_only);
        (void)pthread_rwlock_unlock(&server->snapshot_lock);
        return;
    }
    if (strchr(request->target, '#') != NULL ||
        strncmp(request->target, "http://", 7) == 0 ||
        strncmp(request->target, "https://", 8) == 0) {
        (void)pthread_rwlock_rdlock(&server->snapshot_lock);
        send_json_error(server, descriptor, 400, "invalid_path", request->head_only);
        (void)pthread_rwlock_unlock(&server->snapshot_lock);
        return;
    }
    if (write && server->write_auth_token == NULL) {
        (void)pthread_rwlock_rdlock(&server->snapshot_lock);
        send_json_error(server, descriptor, 405, "writes_disabled", false);
        (void)pthread_rwlock_unlock(&server->snapshot_lock);
        return;
    }
    if (!request_authorized(server, request, write)) {
        atomic_fetch_add_explicit(
            &server->metrics.authentication_failures,
            1,
            memory_order_relaxed
        );
        (void)pthread_rwlock_rdlock(&server->snapshot_lock);
        send_json_error(server, descriptor, 401, "unauthorized", request->head_only);
        (void)pthread_rwlock_unlock(&server->snapshot_lock);
        return;
    }
    char target[REQUEST_TARGET_LIMIT + 1];
    memcpy(target, request->target, strlen(request->target) + 1);
    char *query = strchr(target, '?');
    if (query != NULL) {
        *query++ = '\0';
    }
    char collection[YAMLDB_NAME_LIMIT + 1];
    char *document = NULL;
    if (write) {
        if (query != NULL ||
            !parse_database_target(target, collection, &document) ||
            document == NULL) {
            (void)pthread_rwlock_rdlock(&server->snapshot_lock);
            send_json_error(server, descriptor, 400, "invalid_path", false);
            (void)pthread_rwlock_unlock(&server->snapshot_lock);
            return;
        }
        if (strcmp(request->method, "PUT") == 0) {
            write_document(server, descriptor, request, collection, document);
        } else {
            delete_document(server, descriptor, request, collection, document);
        }
        return;
    }

    (void)pthread_rwlock_rdlock(&server->snapshot_lock);
    if (strcmp(request->target, "/readyz") == 0) {
        serve_ready(server, descriptor, request->head_only);
        goto read_complete;
    }
    if (strcmp(request->target, "/metrics") == 0) {
        serve_metrics(server, descriptor, request->head_only);
        goto read_complete;
    }
    if (strcmp(request->target, "/v1/stats") == 0) {
        serve_stats(server, descriptor, request->head_only);
        goto read_complete;
    }
    if (strcmp(request->target, "/v1/collections") == 0) {
        send_response(
            server,
            descriptor,
            200,
            "application/json; charset=utf-8",
            server->snapshot->collection_index_body,
            server->snapshot->collection_index_length,
            NULL,
            request->head_only
        );
        goto read_complete;
    }
    if (!parse_database_target(target, collection, &document)) {
        static const char database_prefix[] = "/v1/collections/";
        bool database_path = strncmp(
            target, database_prefix, sizeof(database_prefix) - 1
        ) == 0;
        send_json_error(
            server,
            descriptor,
            database_path ? 400 : 404,
            database_path ? "invalid_path" : "not_found",
            request->head_only
        );
        goto read_complete;
    }
    if (document == NULL) {
        if (query == NULL) {
            serve_collection(server, descriptor, collection, request->head_only);
        } else {
            size_t limit;
            char after[YAMLDB_NAME_LIMIT + 1];
            const char *after_value;
            if (!parse_page_query(query, &limit, after, &after_value)) {
                send_json_error(
                    server, descriptor, 400, "invalid_query", request->head_only
                );
            } else {
                serve_collection_page(
                    server,
                    descriptor,
                    collection,
                    limit,
                    after_value,
                    request->head_only
                );
            }
        }
        goto read_complete;
    }
    if (query != NULL) {
        send_json_error(server, descriptor, 400, "invalid_query", request->head_only);
        goto read_complete;
    }
    serve_document(
        server, descriptor, collection, document,
        request->accepts_gzip, request->head_only
    );

read_complete:
    (void)pthread_rwlock_unlock(&server->snapshot_lock);
}

static void handle_connection(Server *server, int descriptor)
{
    struct timeval send_timeout = {
        .tv_sec = server->io_timeout_ms / 1000,
        .tv_usec = (server->io_timeout_ms % 1000) * 1000,
    };
    (void)setsockopt(
        descriptor,
        SOL_SOCKET,
        SO_SNDTIMEO,
        &send_timeout,
        sizeof(send_timeout)
    );
    Request request;
    memset(&request, 0, sizeof(request));
    const char *error_code = NULL;
    int status = receive_request(
        descriptor,
        server->io_timeout_ms,
        &request,
        &error_code
    );
    if (status != 0) {
        (void)pthread_rwlock_rdlock(&server->snapshot_lock);
        send_json_error(server, descriptor, status, error_code, false);
        (void)pthread_rwlock_unlock(&server->snapshot_lock);
        free(request.body);
        return;
    }
    route_request(server, descriptor, &request);
    free(request.body);
}

static void *worker_main(void *argument)
{
    Server *server = argument;
    for (;;) {
        int descriptor = dequeue_connection(&server->queue);
        if (descriptor < 0) {
            break;
        }
        atomic_fetch_add_explicit(&server->metrics.active, 1, memory_order_relaxed);
        handle_connection(server, descriptor);
        (void)shutdown(descriptor, SHUT_RDWR);
        close(descriptor);
        atomic_fetch_sub_explicit(&server->metrics.active, 1, memory_order_relaxed);
        atomic_fetch_add_explicit(&server->metrics.completed, 1, memory_order_relaxed);
    }
    return NULL;
}

static char *read_auth_token(
    const char *path,
    size_t *token_length,
    char *error,
    size_t error_length
)
{
    int descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        (void)snprintf(error, error_length, "cannot open authentication token file");
        return NULL;
    }
    struct stat status;
    /* systemd LoadCredential exposes private credentials as mode 0440. */
    mode_t insecure_permissions = S_IXUSR | S_IWGRP | S_IXGRP | S_IRWXO;
    if (fstat(descriptor, &status) != 0 || !S_ISREG(status.st_mode) ||
        (status.st_mode & insecure_permissions) != 0 ||
        status.st_size < 32 || status.st_size > AUTH_TOKEN_LIMIT) {
        close(descriptor);
        (void)snprintf(error, error_length, "authentication token file is invalid");
        return NULL;
    }
    size_t length = (size_t)status.st_size;
    char *token = malloc(length + 1);
    if (token == NULL) {
        close(descriptor);
        (void)snprintf(error, error_length, "cannot allocate authentication token");
        return NULL;
    }
    size_t used = 0;
    while (used < length) {
        ssize_t result = read(descriptor, token + used, length - used);
        if (result < 0 && errno == EINTR) {
            continue;
        }
        if (result <= 0) {
            free(token);
            close(descriptor);
            (void)snprintf(error, error_length, "cannot read authentication token");
            return NULL;
        }
        used += (size_t)result;
    }
    close(descriptor);
    if (length > 0 && token[length - 1] == '\n') {
        length--;
        if (length > 0 && token[length - 1] == '\r') {
            length--;
        }
    }
    if (length < 32) {
        free(token);
        (void)snprintf(error, error_length, "authentication token is too short");
        return NULL;
    }
    for (size_t index = 0; index < length; index++) {
        unsigned char byte = (unsigned char)token[index];
        if (byte < 0x21 || byte > 0x7e) {
            free(token);
            (void)snprintf(error, error_length, "authentication token contains invalid bytes");
            return NULL;
        }
    }
    token[length] = '\0';
    *token_length = length;
    return token;
}

static void usage(const char *program)
{
    fprintf(
        stderr,
        "Usage: %s --data-dir PATH [--port 0-65535] [--workers 1-64] "
        "[--queue-capacity 1-4096] [--io-timeout-ms 100-30000] "
        "[--bind-address RFC1918_OR_LOOPBACK_IPV4] "
        "[--auth-token-file PATH] [--write-auth-token-file PATH] "
        "[--validate-only]\n",
        program
    );
}

int main(int argc, char **argv)
{
    const char *data_dir = NULL;
    const char *bind_address = "127.0.0.1";
    const char *auth_token_path = NULL;
    const char *write_auth_token_path = NULL;
    int port = DEFAULT_PORT;
    int workers = DEFAULT_WORKERS;
    int queue_capacity = DEFAULT_QUEUE_CAPACITY;
    int io_timeout_ms = DEFAULT_IO_TIMEOUT_MS;
    bool validate_only = false;

    for (int index = 1; index < argc; index++) {
        if (strcmp(argv[index], "--data-dir") == 0 && index + 1 < argc) {
            data_dir = argv[++index];
        } else if (strcmp(argv[index], "--bind-address") == 0 &&
                   index + 1 < argc) {
            bind_address = argv[++index];
        } else if (strcmp(argv[index], "--port") == 0 && index + 1 < argc) {
            if (!parse_number(argv[++index], 0, 65535, &port)) {
                usage(argv[0]);
                return 2;
            }
        } else if (strcmp(argv[index], "--workers") == 0 && index + 1 < argc) {
            if (!parse_number(argv[++index], 1, 64, &workers)) {
                usage(argv[0]);
                return 2;
            }
        } else if (strcmp(argv[index], "--queue-capacity") == 0 && index + 1 < argc) {
            if (!parse_number(argv[++index], 1, 4096, &queue_capacity)) {
                usage(argv[0]);
                return 2;
            }
        } else if (strcmp(argv[index], "--io-timeout-ms") == 0 && index + 1 < argc) {
            if (!parse_number(argv[++index], 100, 30000, &io_timeout_ms)) {
                usage(argv[0]);
                return 2;
            }
        } else if (strcmp(argv[index], "--auth-token-file") == 0 && index + 1 < argc) {
            auth_token_path = argv[++index];
        } else if (strcmp(argv[index], "--write-auth-token-file") == 0 &&
                   index + 1 < argc) {
            write_auth_token_path = argv[++index];
        } else if (strcmp(argv[index], "--validate-only") == 0) {
            validate_only = true;
        } else {
            usage(argv[0]);
            return 2;
        }
    }
    if (data_dir == NULL) {
        usage(argv[0]);
        return 2;
    }
    struct in_addr bind_network_address;
    bool loopback_bind = false;
    if (!parse_bind_address(
            bind_address, &bind_network_address, &loopback_bind
        )) {
        fprintf(stderr, "yamldb: bind address must be numeric loopback or RFC1918 IPv4\n");
        return 2;
    }
    if (!loopback_bind && auth_token_path == NULL) {
        fprintf(stderr, "yamldb: an authentication token is required for LAN binding\n");
        return 1;
    }

    YamlDBSnapshot *snapshot = malloc(sizeof(*snapshot));
    char error[256];
    if (snapshot == NULL) {
        fprintf(stderr, "yamldb: cannot allocate snapshot\n");
        return 1;
    }
    if (!yamldb_snapshot_load(data_dir, snapshot, error, sizeof(error))) {
        fprintf(stderr, "yamldb: %s\n", error);
        free(snapshot);
        return 1;
    }
    if (validate_only) {
        printf(
            "{\"status\":\"valid\",\"revision\":\"%s\","
            "\"collections\":%zu,\"documents\":%zu,\"bytes\":%zu,"
            "\"compressed_bytes\":%zu}\n",
            snapshot->revision,
            snapshot->collection_count,
            snapshot->document_count,
            snapshot->byte_count,
            snapshot->compressed_byte_count
        );
        yamldb_snapshot_free(snapshot);
        free(snapshot);
        return 0;
    }

    size_t auth_token_length = 0;
    char *auth_token = NULL;
    if (auth_token_path != NULL) {
        auth_token = read_auth_token(
            auth_token_path,
            &auth_token_length,
            error,
            sizeof(error)
        );
        if (auth_token == NULL) {
            fprintf(stderr, "yamldb: %s\n", error);
            yamldb_snapshot_free(snapshot);
            free(snapshot);
            return 1;
        }
    }

    size_t write_auth_token_length = 0;
    char *write_auth_token = NULL;
    if (write_auth_token_path != NULL) {
        write_auth_token = read_auth_token(
            write_auth_token_path,
            &write_auth_token_length,
            error,
            sizeof(error)
        );
        if (write_auth_token == NULL) {
            fprintf(stderr, "yamldb: %s\n", error);
            if (auth_token != NULL) {
                memset(auth_token, 0, auth_token_length);
            }
            free(auth_token);
            yamldb_snapshot_free(snapshot);
            free(snapshot);
            return 1;
        }
        if (auth_token != NULL && secure_equal(
                auth_token,
                auth_token_length,
                write_auth_token,
                write_auth_token_length
            )) {
            fprintf(stderr, "yamldb: read and write tokens must differ\n");
            memset(write_auth_token, 0, write_auth_token_length);
            free(write_auth_token);
            memset(auth_token, 0, auth_token_length);
            free(auth_token);
            yamldb_snapshot_free(snapshot);
            free(snapshot);
            return 1;
        }
    }

    Server server;
    memset(&server, 0, sizeof(server));
    server.snapshot = snapshot;
    server.data_dir = data_dir;
    server.auth_token = auth_token;
    server.auth_token_length = auth_token_length;
    server.write_auth_token = write_auth_token;
    server.write_auth_token_length = write_auth_token_length;
    server.io_timeout_ms = io_timeout_ms;
    server.worker_count = workers;
    (void)clock_gettime(CLOCK_MONOTONIC, &server.started_at);
    if (pthread_rwlock_init(&server.snapshot_lock, NULL) != 0) {
        fprintf(stderr, "yamldb: cannot initialize database locks\n");
        if (write_auth_token != NULL) {
            memset(write_auth_token, 0, write_auth_token_length);
        }
        free(write_auth_token);
        if (auth_token != NULL) {
            memset(auth_token, 0, auth_token_length);
        }
        free(auth_token);
        yamldb_snapshot_free(snapshot);
        free(snapshot);
        return 1;
    }
    if (pthread_mutex_init(&server.write_lock, NULL) != 0) {
        fprintf(stderr, "yamldb: cannot initialize database locks\n");
        (void)pthread_rwlock_destroy(&server.snapshot_lock);
        if (write_auth_token != NULL) {
            memset(write_auth_token, 0, write_auth_token_length);
        }
        free(write_auth_token);
        if (auth_token != NULL) {
            memset(auth_token, 0, auth_token_length);
        }
        free(auth_token);
        yamldb_snapshot_free(snapshot);
        free(snapshot);
        return 1;
    }
    if (!initialize_queue(&server.queue, (size_t)queue_capacity)) {
        fprintf(stderr, "yamldb: cannot allocate work queue\n");
        (void)pthread_mutex_destroy(&server.write_lock);
        (void)pthread_rwlock_destroy(&server.snapshot_lock);
        if (write_auth_token != NULL) {
            memset(write_auth_token, 0, write_auth_token_length);
        }
        free(write_auth_token);
        if (auth_token != NULL) {
            memset(auth_token, 0, auth_token_length);
        }
        free(auth_token);
        yamldb_snapshot_free(snapshot);
        free(snapshot);
        return 1;
    }

    pthread_t *worker_threads = calloc((size_t)workers, sizeof(*worker_threads));
    if (worker_threads == NULL) {
        fprintf(stderr, "yamldb: cannot allocate worker threads\n");
        destroy_queue(&server.queue);
        (void)pthread_mutex_destroy(&server.write_lock);
        (void)pthread_rwlock_destroy(&server.snapshot_lock);
        if (write_auth_token != NULL) {
            memset(write_auth_token, 0, write_auth_token_length);
        }
        free(write_auth_token);
        if (auth_token != NULL) {
            memset(auth_token, 0, auth_token_length);
        }
        free(auth_token);
        yamldb_snapshot_free(snapshot);
        free(snapshot);
        return 1;
    }
    int started_workers = 0;
    for (; started_workers < workers; started_workers++) {
        if (pthread_create(
                &worker_threads[started_workers],
                NULL,
                worker_main,
                &server
            ) != 0) {
            fprintf(stderr, "yamldb: cannot start worker threads\n");
            break;
        }
    }
    if (started_workers != workers) {
        stop_queue(&server.queue);
        for (int index = 0; index < started_workers; index++) {
            (void)pthread_join(worker_threads[index], NULL);
        }
        free(worker_threads);
        destroy_queue(&server.queue);
        (void)pthread_mutex_destroy(&server.write_lock);
        (void)pthread_rwlock_destroy(&server.snapshot_lock);
        if (write_auth_token != NULL) {
            memset(write_auth_token, 0, write_auth_token_length);
        }
        free(write_auth_token);
        if (auth_token != NULL) {
            memset(auth_token, 0, auth_token_length);
        }
        free(auth_token);
        yamldb_snapshot_free(snapshot);
        free(snapshot);
        return 1;
    }

    int exit_status = 0;
    int server_descriptor = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (server_descriptor < 0) {
        fprintf(stderr, "yamldb: cannot create socket\n");
        running = 0;
        exit_status = 1;
    }
    int enabled = 1;
    if (server_descriptor >= 0) {
        (void)setsockopt(
            server_descriptor,
            SOL_SOCKET,
            SO_REUSEADDR,
            &enabled,
            sizeof(enabled)
        );
    }
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons((uint16_t)port);
    address.sin_addr = bind_network_address;
    if (server_descriptor >= 0 &&
        (bind(server_descriptor, (struct sockaddr *)&address, sizeof(address)) != 0 ||
         listen(server_descriptor, queue_capacity) != 0)) {
        fprintf(stderr, "yamldb: cannot bind %s port %d\n", bind_address, port);
        close(server_descriptor);
        server_descriptor = -1;
        running = 0;
        exit_status = 1;
    }
    socklen_t address_length = sizeof(address);
    if (server_descriptor >= 0 &&
        getsockname(
            server_descriptor,
            (struct sockaddr *)&address,
            &address_length
        ) != 0) {
        fprintf(stderr, "yamldb: cannot resolve listening port\n");
        close(server_descriptor);
        server_descriptor = -1;
        running = 0;
        exit_status = 1;
    }

    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = stop_server;
    sigemptyset(&action.sa_mask);
    (void)sigaction(SIGINT, &action, NULL);
    (void)sigaction(SIGTERM, &action, NULL);
    (void)signal(SIGPIPE, SIG_IGN);

    if (server_descriptor >= 0) {
        listening_descriptor = server_descriptor;
        printf(
            "yamldb listening on %s:%u revision=%s workers=%d "
            "queue=%d auth=%s writes=%s\n",
            bind_address,
            (unsigned int)ntohs(address.sin_port),
            server.snapshot->revision,
            workers,
            queue_capacity,
            auth_token == NULL ? "off" : "on",
            write_auth_token == NULL ? "off" : "on"
        );
        fflush(stdout);
    }
    while (running && server_descriptor >= 0) {
        struct pollfd listening = {
            .fd = server_descriptor,
            .events = POLLIN,
            .revents = 0,
        };
        int ready;
        do {
            ready = poll(&listening, 1, 250);
        } while (ready < 0 && errno == EINTR && running);
        if (!running) {
            break;
        }
        if (ready == 0) {
            continue;
        }
        if (ready < 0 || (listening.revents & (POLLERR | POLLNVAL)) != 0) {
            fprintf(stderr, "yamldb: listener failed\n");
            exit_status = 1;
            break;
        }
        int descriptor = accept(server_descriptor, NULL, NULL);
        if (descriptor < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (running) {
                fprintf(stderr, "yamldb: accept failed\n");
                exit_status = 1;
            }
            break;
        }
        (void)fcntl(descriptor, F_SETFD, FD_CLOEXEC);
        atomic_fetch_add_explicit(&server.metrics.accepted, 1, memory_order_relaxed);
        if (!enqueue_connection(&server.queue, descriptor)) {
            atomic_fetch_add_explicit(
                &server.metrics.overload_rejections,
                1,
                memory_order_relaxed
            );
            struct timeval overload_timeout = {.tv_sec = 0, .tv_usec = 100000};
            (void)setsockopt(
                descriptor,
                SOL_SOCKET,
                SO_SNDTIMEO,
                &overload_timeout,
                sizeof(overload_timeout)
            );
            (void)pthread_rwlock_rdlock(&server.snapshot_lock);
            send_json_error(&server, descriptor, 503, "server_busy", false);
            (void)pthread_rwlock_unlock(&server.snapshot_lock);
            (void)shutdown(descriptor, SHUT_RDWR);
            close(descriptor);
        }
    }
    if (server_descriptor >= 0 && listening_descriptor == server_descriptor) {
        listening_descriptor = -1;
        close(server_descriptor);
    }
    stop_queue(&server.queue);
    for (int index = 0; index < workers; index++) {
        (void)pthread_join(worker_threads[index], NULL);
    }
    free(worker_threads);
    destroy_queue(&server.queue);
    (void)pthread_mutex_destroy(&server.write_lock);
    (void)pthread_rwlock_destroy(&server.snapshot_lock);
    if (write_auth_token != NULL) {
        memset(write_auth_token, 0, write_auth_token_length);
    }
    free(write_auth_token);
    if (auth_token != NULL) {
        memset(auth_token, 0, auth_token_length);
    }
    free(auth_token);
    yamldb_snapshot_free(server.snapshot);
    free(server.snapshot);
    return exit_status;
}
