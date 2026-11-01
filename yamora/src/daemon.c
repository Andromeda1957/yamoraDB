#define _POSIX_C_SOURCE 200809L

#include "snapshot.h"
#include "aggregate_spill.h"
#include "binary.h"
#include "store.h"
#include "document_api.h"
#include "disk_api.h"
#include "disk_source.h"
#include "disk_branch_api.h"
#include "disk_history.h"
#include "disk_bulk.h"
#include "disk_compact.h"
#include "disk_internal.h"
#include "disk_index_jobs.h"
#include "disk_policy_api.h"
#include "disk_replica.h"
#include "disk_schema_activation.h"
#include "storage_budget.h"
#include "disk_schema_recovery.h"
#include "index_ttl_runtime.h"
#include "schema/policy_admission.h"
#include "transport/tls.h"
#include "transport/change_stream.h"
#include "transport/binary_session.h"
#include "security/access.h"
#include "security/access_admin.h"
#include "security/access_identity.h"
#include "security/audit_dispatch.h"
#include "security/storage_config.h"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include "security/field_response.h"
#include "consensus/cluster.h"
#include "consensus/config.h"
#include "consensus/backup.h"
#include "sharding/service.h"

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
#include <sys/file.h>
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
#define REQUEST_BODY_LIMIT (2 * 1024 * 1024)
#define REQUEST_TARGET_LIMIT 1024
#define REQUEST_HEADER_LIMIT 64
#define AUTH_TOKEN_LIMIT 512
#define HTTP_OIDC_TOKEN_LIMIT 4096
#define CONTENT_TYPE_LIMIT 96
#define ETAG_HEADER_LIMIT 128
#define RESPONSE_HEADER_LIMIT 8192
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

static void copy_metrics(Metrics *to, const Metrics *from) {
#define COPY_METRIC(field) atomic_store_explicit(&to->field, \
    atomic_load_explicit(&from->field, memory_order_relaxed), memory_order_relaxed)
    COPY_METRIC(accepted);
    COPY_METRIC(active);
    COPY_METRIC(completed);
    COPY_METRIC(responses_2xx);
    COPY_METRIC(responses_4xx);
    COPY_METRIC(responses_5xx);
    COPY_METRIC(authentication_failures);
    COPY_METRIC(overload_rejections);
    COPY_METRIC(response_bytes);
    COPY_METRIC(writes);
    COPY_METRIC(write_conflicts);
#undef COPY_METRIC
}

typedef struct {
    YDEngine engine;
    YDDisk *disk;
    YDDiskAPI disk_api;
    YDCompactor *compactor; /* Standalone native writer only; joined before disk_api. */
    YDTLS *tls;
    YDAccess *access;
    YDAccessAdmin *access_admin; /* --runtime-access only. */
    YDAccessIdentity *identity;
    YDAuditDispatcher *audit;
    YDStorageConfig *encrypted;
    YDRaftCluster *cluster;
    YDShardService *shards;
    YDTLS *peer_tls;
    YDTLS *binary_tls;
    YDBinaryRuntime *binary_runtime;
    size_t binary_document_limit;
    atomic_uint_fast64_t binary_revision;
    atomic_bool dispatch_ready;
    unsigned cluster_timeout_ms;
    atomic_size_t large_body_bytes, active_streams;
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
    uint64_t maintenance_threshold, maintenance_baseline;
    YDTTLMonitor *ttl;
    unsigned ttl_interval_seconds;
} Server;

typedef struct {
    char method[8];
    char target[REQUEST_TARGET_LIMIT + 1];
    bool head_only;
    bool authorization_present;
    bool metadata_selected, redact_metadata;
    const YDAccessPrincipal *selected_principal;
    bool http_origin, inbound_tls;
    unsigned char channel_binding[32];
    char identity_reply[5504];
    YDAuditAuthentication authentication;
    uint64_t deadline;
    bool identity_checked;
    int identity_status;
    YDAccessIdentityCategory identity_category;
    int64_t identity_expires_at;
    YDAuditedOperation *audit_operation;
    YDAuditOutcome audit_outcome;
    bool audit_has_receipt;
    YDDiskView audit_receipt;
    YDTLSClientIdentity client_identity;
    bool accepts_gzip;
    char authorization[HTTP_OIDC_TOKEN_LIMIT + 8];
    bool content_length_present;
    size_t content_length;
    bool content_type_present;
    char content_type[CONTENT_TYPE_LIMIT];
    bool if_match_present;
    char if_match[ETAG_HEADER_LIMIT];
    bool if_none_match_present;
    char if_none_match[ETAG_HEADER_LIMIT];
    bool request_id_present;
    unsigned char request_id[16];
    bool receipt_epoch_present;
    uint64_t receipt_epoch;
    unsigned char *body;
    size_t body_length;
    size_t reserved_bytes;
    /* Runtime access: binary I/O admission uses only the cached snapshot;
     * worker threads refresh it at most once per request. */
    bool access_cached, access_synced;
} Request;

/* Each HTTP worker owns one stack request through its last response. This
 * private context exists only to carry the audit completion through legacy
 * summary/error senders; binary workers use explicit Request ownership. It
 * never supplies authentication or grants, and clears before request cleanup. */
static _Thread_local Request *http_request;
static bool request_private(const Server *, const Request *);
static bool response_private(const Server *server) {
    return http_request ? request_private(server, http_request) :
        yd_access_has_field_principals(server->access);
}
static bool audit_finish_request(Request *request, unsigned status) {
    if (!request || !request->audit_operation) return true;
    YDAuditedOperation *operation = request->audit_operation;
    request->audit_operation = NULL;
    return yd_audit_dispatch_finish(operation, request->audit_outcome, status,
        request->audit_has_receipt ? &request->audit_receipt : NULL);
}
static volatile sig_atomic_t running = 1;
static volatile sig_atomic_t reload_requested = 0;
static void reload_tls(int signal_number) {
    (void)signal_number;
    reload_requested = 1;
}
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
    case 202:
        return "Accepted";
    case 204:
        return "No Content";
    case 400:
        return "Bad Request";
    case 401:
        return "Unauthorized";
    case 403:
        return "Forbidden";
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

static bool send_all(YDConnection *connection, const char *body, size_t length)
{
    return yd_connection_send(connection, body, length);
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

static void send_response_revision(Server *server, YDConnection *connection, int status,
                                   const char *content_type, const char *body, size_t body_length,
                                   const char *extra_headers, bool head_only,
                                   const char *revision, bool private_metadata) {
    char *filtered_body = NULL;
    char filtered_headers[RESPONSE_HEADER_LIMIT];
    char failure_headers[RESPONSE_HEADER_LIMIT];
    if (private_metadata) {
        bool valid = true;
        revision = YD_FIELD_RESPONSE_PRIVATE_REVISION;
        size_t n = extra_headers ? strlen(extra_headers) : 0;
        if (n >= sizeof(filtered_headers)) valid = false;
        else {
            memcpy(filtered_headers, extra_headers ? extra_headers : "", n + 1);
            valid = yd_field_response_headers(filtered_headers, sizeof(filtered_headers));
        }
        if (valid && content_type && !strncmp(content_type, "application/json", 16)) {
            if (body_length == SIZE_MAX || (body_length && !body)) valid = false;
            else filtered_body = malloc(body_length + 1);
            if (!filtered_body) valid = false;
            else {
                if (body_length) memcpy(filtered_body, body, body_length);
                filtered_body[body_length] = 0;
                char error[128];
                valid = yd_field_response_body(YD_FIELD_RESPONSE_JSON, &filtered_body,
                    &body_length, error, sizeof(error));
                if (valid) body = filtered_body;
            }
        }
        if (valid) extra_headers = filtered_headers;
        else {
            free(filtered_body); filtered_body = NULL;
            status = 503; content_type = "application/json; charset=utf-8";
            body = "{\"error\":\"private_response_unavailable\"}\n";
            body_length = strlen(body); extra_headers = "Retry-After: 1\r\n";
        }
    }
    if (!audit_finish_request(http_request, (unsigned)status)) {
        status = 503; content_type = "application/json; charset=utf-8";
        body = "{\"error\":\"operation_audit_uncertain\"}\n";
        body_length = strlen(body); extra_headers = "Retry-After: 1\r\n";
        revision = YD_FIELD_RESPONSE_PRIVATE_REVISION;
    }
    if (extra_headers && !strcmp(extra_headers, "Retry-After: 1\r\n") &&
        http_request && http_request->identity_reply[0]) {
        int n = snprintf(failure_headers, sizeof(failure_headers), "Retry-After: 1\r\n%s",
            http_request->identity_reply);
        if (n > 0 && (size_t)n < sizeof(failure_headers)) extra_headers = failure_headers;
    }
    char header[RESPONSE_HEADER_LIMIT];
    int written = snprintf(header, sizeof(header),
                           "HTTP/1.1 %d %s\r\n"
                           "Content-Type: %s\r\n"
                           "Content-Length: %zu\r\n"
                           "Connection: close\r\n"
                           "Cache-Control: no-store\r\n"
                           "X-Content-Type-Options: nosniff\r\n"
                           "X-YamlDB-Revision: %s\r\n"
                           "%s"
                           "\r\n",
                           status, status_text(status), content_type, body_length, revision,
                           extra_headers == NULL ? "" : extra_headers);
    record_response(server, status, body_length);
    if (written >= 0 && (size_t)written < sizeof(header) &&
        send_all(connection, header, (size_t)written) && !head_only)
        (void)send_all(connection, body, body_length);
    free(filtered_body);
}

static bool native_storage(const Server *server) { return server->disk || server->cluster; }
static YDDiskView native_view(Server *server) {
    return server->cluster ? yd_raft_cluster_storage(server->cluster).view : yd_disk_view(server->disk);
}
static bool native_writable(Server *server) {
    if (!server->cluster)
        return yd_disk_writable(server->disk);
    YDRaftClusterStorage storage = yd_raft_cluster_storage(server->cluster);
    return storage.writable && !storage.failed;
}
static void send_response(Server *server, YDConnection *connection, int status, const char *content_type,
                          const char *body, size_t body_length, const char *extra_headers,
                          bool head_only) {
    char revision[17];
    if (native_storage(server)) {
        YDDiskView view = native_view(server);
        yd_disk_revision(&view, revision);
    } else
        memcpy(revision, server->engine.snapshot->revision, 17);
    send_response_revision(server, connection, status, content_type, body, body_length,
                           extra_headers, head_only, revision, response_private(server));
}

static void send_json_error(
    Server *server,
    YDConnection *connection,
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
        connection,
        status,
        "application/json; charset=utf-8",
        body,
        (size_t)written,
        headers,
        head_only
    );
}

static bool request_authorized(
    const Server *server,
    Request *request,
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
        strncasecmp(request->authorization, prefix, sizeof(prefix) - 1) != 0) {
        return false;
    }
    const char *candidate = request->authorization + sizeof(prefix) - 1;
    size_t candidate_length = authorization_length - (sizeof(prefix) - 1);
    return yd_access_secure_equal(
        candidate,
        candidate_length,
        token,
        token_length
    );
}

static bool request_query_target(const char *method, const char *target) {
    char selector[129];
    const char *underlying = NULL;
    int temporal = yd_disk_history_target(target, selector, &underlying);
    if (temporal < 0) return false;
    if (temporal) target = underlying;
    return !strcmp(method, "POST") &&
        (!strncmp(target, "/v1/query/", 10) ||
         !strncmp(target, "/v1/aggregate/", 14) ||
         !strncmp(target, "/v1/search/", 11) ||
         !strncmp(target, "/v1/vector-search/", 18));
}
static bool branch_transaction_target(const char *target) {
    if (strncmp(target, "/v1/branches/", 13)) return false;
    const char *suffix = strchr(target + 13, '/');
    return suffix && !strcmp(suffix, "/transactions");
}
/* Project only the authorization request. Dispatch retains the original raw
 * envelope and YAML bytes; collection and aggregate-lookup grants are checked
 * before any branch or historical root is resolved. */
static int disk_principal_access(const Server *server, const YDAccessPrincipal *principal,
    const Request *request, bool header_only) {
    char selector[129];
    const char *target = request->target, *underlying = NULL;
    int temporal = yd_disk_history_target(target, selector, &underlying);
    if (temporal < 0) return 403;
    if (temporal) {
        if (strcmp(request->method, "GET") && strcmp(request->method, "HEAD") &&
            !request_query_target(request->method, target)) return 403;
        target = underlying;
    }
    bool transaction = !strcmp(target, "/v1/transactions");
    bool branch = !strcmp(request->method, "POST") && branch_transaction_target(target);
    if (header_only && (transaction || branch) &&
        yd_access_principal_writer(server->access, principal)) return 0;
    if (!branch) return yd_access_principal_request(server->access, principal,
        request->method, target, request->body, request->body_length);
    char error[128];
    YDValue *envelope = yd_parse_sized(request->body, request->body_length,
        YD_LARGE_REQUEST_LIMIT, error, sizeof(error));
    const YDValue *nested = yd_get(envelope, "transaction");
    size_t size = 0;
    char *body = nested && nested->type == YD_MAP
        ? yd_json_sized(nested, &size, YD_LARGE_REQUEST_LIMIT) : NULL;
    int status = body ? yd_access_principal_request(server->access, principal,
        "POST", "/v1/transactions", (const unsigned char *)body, size) : 403;
    free(body);
    yd_free(envelope);
    return status;
}
static int principal_access(const Server *server, Request *request,
    const YDAccessPrincipal *principal, bool header_only) {
    request->selected_principal = principal;
    request->redact_metadata = yd_access_principal_masked(server->access, principal) ||
        (!yd_access_principal_name(server->access, principal) &&
         yd_access_has_field_principals(server->access));
    int conditional = yd_access_principal_preconditions(server->access, principal,
        request->if_match_present, request->if_none_match_present);
    if (conditional) return conditional;
    return disk_principal_access(server, principal, request, header_only);
}
static bool request_private(const Server *server, const Request *request) {
    return request->metadata_selected ? request->redact_metadata :
        yd_access_has_field_principals(server->access);
}
/* Runtime principals are checked against the replicated access state on every
 * request outside the binary I/O thread, so a delete or rotation applies to
 * the next request of every session. A replica-set leader proves leadership
 * before trusting a cached runtime principal; followers use applied state. */
static const YDAccessPrincipal *identify_bearer(const Server *server, Request *request,
    const char *token, size_t size) {
    const YDAccessPrincipal *principal = yd_access_identify_token(server->access, token, size);
    if (!server->access_admin || request->access_cached || request->access_synced ||
        (principal && !yd_access_principal_runtime(server->access, principal)))
        return principal;
    request->access_synced = true;
    yd_access_admin_refresh(server->access_admin, principal && server->cluster);
    return yd_access_identify_token(server->access, token, size);
}
static int disk_access_credential(const Server *, Request *, bool, bool);
static int disk_access(const Server *server, Request *request, bool write, bool header_only) {
    if (!server->access_admin || !yd_access_admin_target(request->target))
        return disk_access_credential(server, request, write, header_only);
    /* Only the write administrative credential, over HTTP, manages access.
     * Every other recognized credential is 403; unknown or absent is 401. */
    if (request->http_origin && server->write_auth_token &&
        request_authorized(server, request, true)) {
        request->metadata_selected = true;
        request->selected_principal = NULL;
        request->authentication = YD_AUDIT_ADMIN_WRITE;
        request->redact_metadata = false;
        return 0;
    }
    if (request->authorization_present && server->write_auth_token &&
        request_authorized(server, request, true)) return 403;
    int status = disk_access_credential(server, request, false, header_only);
    return status == 0 || status == 403 ? 403 : status;
}
static int disk_access_credential(const Server *server, Request *request, bool write,
    bool header_only) {
    request->metadata_selected = true;
    request->redact_metadata = yd_access_has_field_principals(server->access);
    if (!request->identity_checked) request->selected_principal = NULL;
    /* Expiry closes retry identities for every writer. Only the separately
     * configured administrative credential may inspect or change that floor. */
    if (!strcmp(request->target, "/v1/cluster/receipt-retention"))
        return server->write_auth_token && request_authorized(server, request, true) ? 0 :
            request->authorization_present ? 403 : 401;
    /* Storage maintenance (online compaction, in-place format upgrade) belongs
     * to the administrative credentials only, never to a principal role: the
     * write credential starts or cancels it, either credential reads status. */
    if (!strncmp(request->target, "/v1/storage/", 12)) {
        if (server->write_auth_token && request_authorized(server, request, true)) {
            request->authentication = YD_AUDIT_ADMIN_WRITE;
            request->redact_metadata = false; return 0;
        }
        if (!write && request_authorized(server, request, false)) {
            request->authentication = YD_AUDIT_ADMIN_READ;
            request->redact_metadata = false; return 0;
        }
        return request->authorization_present ? 403 : 401;
    }
    /* Policy authority is the explicitly configured administrative credential.
     * Authenticate every attempt before dispatch, including durable replay. */
    if (write && yd_disk_policy_api_target(request->target)) {
        if (server->write_auth_token && request_authorized(server, request, true)) {
            request->authentication = YD_AUDIT_ADMIN_WRITE;
            request->redact_metadata = false; return 0;
        }
        return 403;
    }
    /* Explicit Authorization chooses bearer exclusively, including invalid or
     * insufficient credentials. Certificate roles never augment a bearer. */
    if (!request->authorization_present && request->client_identity.verified &&
        yd_access_has_certificate_principals(server->access)) {
        const YDAccessPrincipal *principal = yd_access_identify_certificate(server->access,
            request->client_identity.leaf_sha256);
        request->authentication = YD_AUDIT_CERTIFICATE;
        return principal_access(server, request, principal, header_only);
    }
    if (request_authorized(server, request, write)) {
        request->authentication = write ? YD_AUDIT_ADMIN_WRITE : YD_AUDIT_ADMIN_READ;
        request->redact_metadata = false; return 0;
    }
    if (!server->access || !request->authorization_present) return 401;
    bool bearer = !strncasecmp(request->authorization, "Bearer ", 7);
    const char *token = bearer ? request->authorization + 7 : "";
    size_t size = strlen(token);
    /* Static/admin recognition is terminal, including wrong-mode admin use. */
    if (bearer && ((server->auth_token && yd_access_secure_equal(token, size,
            server->auth_token, server->auth_token_length)) ||
        (server->write_auth_token && yd_access_secure_equal(token, size,
            server->write_auth_token, server->write_auth_token_length)))) return 401;
    const YDAccessPrincipal *principal = bearer ?
        identify_bearer(server, request, token, size) : NULL;
    if (principal) request->authentication = YD_AUDIT_STATIC;
    else if (request->http_origin && server->identity) {
        if (!request->identity_checked) {
            YDAccessIdentityVerified verified;
            time_t now = time(NULL);
            request->identity_status = now == (time_t)-1 ||
                (uintmax_t)now > UINT64_C(253402300799) ? 503 :
                yd_access_identity_authenticate(server->identity, request->authorization,
                    request->inbound_tls, request->channel_binding,
                    request->inbound_tls ? sizeof(request->channel_binding) : 0,
                    (int64_t)now, &verified);
            request->identity_checked = true;
            if (!request->identity_status) {
                request->identity_category = verified.category;
                request->identity_expires_at = verified.expires_at;
                principal = yd_access_identify_local(server->access, verified.local_name);
                request->selected_principal = principal;
                request->authentication = verified.category == YD_ACCESS_IDENTITY_OIDC ? YD_AUDIT_OIDC :
                    verified.category == YD_ACCESS_IDENTITY_AWS ? YD_AUDIT_AWS :
                    verified.category == YD_ACCESS_IDENTITY_LDAP ? YD_AUDIT_LDAP : YD_AUDIT_KERBEROS;
                if (verified.reply_length) {
                    strcpy(request->identity_reply, "WWW-Authenticate: Negotiate ");
                    size_t prefix = strlen(request->identity_reply);
                    int encoded = EVP_EncodeBlock((unsigned char *)request->identity_reply + prefix,
                        verified.reply, (int)verified.reply_length);
                    if (encoded <= 0 || prefix + (size_t)encoded + 3 > sizeof(request->identity_reply))
                        request->identity_status = 503;
                    else memcpy(request->identity_reply + prefix + encoded, "\r\n", 3);
                }
                if (!principal && !request->identity_status) request->identity_status = 403;
            }
        } else principal = request->selected_principal;
        if (request->identity_status) return request->identity_status;
    } else if (bearer && request->http_origin && yd_access_has_oidc(server->access)) {
        time_t now = time(NULL);
        if (now == (time_t)-1 || (uintmax_t)now > UINT64_C(253402300799)) return 503;
        int status = yd_access_authenticate_oidc(server->access, token, size,
            (int64_t)now, &principal);
        if (status) return status;
        request->authentication = YD_AUDIT_OIDC;
    }

    return principal_access(server, request, principal, header_only);
}
static const char *access_error(int status) {
    return status == 401 ? "unauthorized" : status == 503 ?
        "authentication_unavailable" : "forbidden";
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

static bool receipt_decimal(const unsigned char *text, size_t size, uint64_t *out) {
    if (!size || size > 20 || (size > 1 && text[0] == '0')) return false;
    uint64_t value = 0;
    for (size_t i = 0; i < size; i++) {
        if (text[i] < '0' || text[i] > '9' ||
            value > (UINT64_MAX - (text[i] - '0')) / 10) return false;
        value = value * 10 + text[i] - '0';
    }
    *out = value;
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
    const char **error_code,
    bool large,
    bool oidc
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
                strlen(value) >= (oidc ? HTTP_OIDC_TOKEN_LIMIT : AUTH_TOKEN_LIMIT) + 8U) {
                *error_code = "invalid_authorization";
                return 400;
            }
            request->authorization_present = true;
            memcpy(request->authorization, value, strlen(value) + 1);
        } else if (strcasecmp(cursor, "Accept-Encoding") == 0) {
            request->accepts_gzip = request->accepts_gzip ||
                header_accepts_gzip(value);
        } else if (strcasecmp(cursor, "X-Yamora-Request-Id") == 0) {
            if (request->request_id_present || !yd_raft_id_parse(value, request->request_id)) {
                *error_code = "invalid_request_id";
                return 400;
            }
            request->request_id_present = true;
        } else if (strcasecmp(cursor, "X-Yamora-Receipt-Epoch") == 0) {
            if (request->receipt_epoch_present ||
                !receipt_decimal((const unsigned char *)value, strlen(value), &request->receipt_epoch) ||
                !request->receipt_epoch) {
                *error_code = "invalid_receipt_epoch";
                return 400;
            }
            request->receipt_epoch_present = true;
        } else if (strcasecmp(cursor, "Content-Length") == 0) {
            if (request->content_length_present ||
                !parse_size(value, SIZE_MAX, &request->content_length)) {
                *error_code = "invalid_content_length";
                return 400;
            }
            request->content_length_present = true;
            bool document = strncmp(request->target, "/v1/collections/", 16) == 0;
            bool raw = document && !strcmp(request->method, "PUT");
            bool wide = large && ((document && !strcmp(request->method, "PATCH")) ||
                (!strcmp(request->method, "POST") && (!strcmp(request->target, "/v1/transactions") ||
                 !strcmp(request->target, "/v1/replication/apply") ||
                 !strcmp(request->target, "/v1/replication/follow/apply"))));
            size_t maximum = !strcmp(request->target, "/v1/cluster/receipt-retention") ? 512 :
                             raw && large ? YD_LARGE_DOCUMENT_LIMIT :
                             wide ? YD_LARGE_REQUEST_LIMIT : REQUEST_BODY_LIMIT;
            if (request->content_length > maximum ||
                (strcmp(request->method, "PUT") == 0 &&
                 strncmp(request->target, "/v1/collections/", 16) == 0 &&
                 request->content_length > (large ? YD_LARGE_DOCUMENT_LIMIT : YAMLDB_DOCUMENT_LIMIT))) {
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
    Server *server,
    YDConnection *connection,
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
                buffer, header_length, request, error_code,
                server->cluster || (server->disk && yd_disk_view(server->disk).format >= 5),
                yd_access_has_oidc(server->access) || server->identity
            );
            if (status != 0) {
                free(initial_body);
                return status;
            }
            /* Parsing clears Request. Attach verified connection evidence only
             * afterwards, before large-body authorization/reservation. */
            request->http_origin = true;
            request->deadline = deadline;
            request->inbound_tls = yd_connection_channel_binding(connection, request->channel_binding);
            if (yd_connection_client_identity(connection, &request->client_identity) ==
                YD_TLS_CLIENT_ERROR) {
                free(initial_body);
                *error_code = "client_identity_unavailable";
                return 401;
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
            if (request->content_length > REQUEST_BODY_LIMIT) {
                bool write = strcmp(request->method, "GET") && !request->head_only &&
                    !request_query_target(request->method, request->target);
                int access = !write || server->write_auth_token
                    ? disk_access(server, request, write, true) : 401;
                if (access) {
                    free(initial_body);
                    if (access == 401) atomic_fetch_add(&server->metrics.authentication_failures, 1);
                    *error_code = access_error(access);
                    return access;
                }
                size_t held = atomic_load(&server->large_body_bytes);
                for (;;) {
                    if (held > YD_LARGE_REQUEST_LIMIT - request->content_length) {
                        free(initial_body);
                        atomic_fetch_add(&server->metrics.overload_rejections, 1);
                        *error_code = "large_request_capacity";
                        return 503;
                    }
                    if (atomic_compare_exchange_weak(&server->large_body_bytes, &held,
                                                      held + request->content_length)) break;
                }
                request->reserved_bytes = request->content_length;
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
                ssize_t result = yd_connection_read(connection,
                    request->body + request->body_length,
                    request->content_length - request->body_length, deadline);
                if (result <= 0) {
                    *error_code = errno == ETIMEDOUT ? "request_timeout" : "incomplete_request_body";
                    return errno == ETIMEDOUT ? 408 : 400;
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
        ssize_t result = yd_connection_read(connection, buffer + used, REQUEST_LIMIT - used, deadline);
        if (result <= 0) {
            *error_code = errno == ETIMEDOUT ? "request_timeout" : "invalid_request";
            return errno == ETIMEDOUT ? 408 : 400;
        }
        used += (size_t)result;
        buffer[used] = '\0';
    }
}

static void serve_health(Server *server, YDConnection *connection, bool head_only)
{
    static const char body[] =
        "{\"status\":\"ok\",\"service\":\"yamora\",\"api_version\":2}\n";
    send_response(
        server,
        connection,
        200,
        "application/json; charset=utf-8",
        body,
        sizeof(body) - 1,
        NULL,
        head_only
    );
}

static const YamlDBSnapshot *server_summary(Server *server, YamlDBSnapshot *summary) {
    if (!native_storage(server))
        return server->engine.snapshot;
    memset(summary, 0, sizeof(*summary));
    YDDiskView view = native_view(server);
    summary->collection_count = (size_t)view.collections;
    summary->document_count = (size_t)view.documents;
    summary->byte_count = (size_t)view.bytes;
    yd_disk_revision(&view, summary->revision);
    return summary;
}

static void serve_ready(Server *server, YDConnection *connection, bool head_only)
{
    YamlDBSnapshot summary;
    const YamlDBSnapshot *snapshot = server_summary(server, &summary);
    YDDiskReplicaPolicyState policy = YD_REPLICA_POLICY_FREE;
    bool change_feed = false;
    if (native_storage(server)) {
        YDRaftView *owned = server->cluster ?
            yd_raft_cluster_view(server->cluster, server->cluster_timeout_ms) : NULL;
        if (server->cluster && !owned) {
            send_json_error(server, connection, 503, "cluster_unavailable", head_only);
            return;
        }
        YDDiskView view = owned ? yd_raft_view_value(owned) : yd_disk_view(server->disk);
        char error[256] = {0};
        policy = yd_disk_replica_policy_state(owned ? yd_raft_view_disk(owned) :
            server->disk, &view, error, sizeof(error));
        yd_raft_view_close(owned);
        if (policy == YD_REPLICA_POLICY_ERROR) {
            send_json_error(server, connection, 503, "policy_state_unavailable", head_only);
            return;
        }
        summary.collection_count = (size_t)view.collections;
        summary.document_count = (size_t)view.documents;
        summary.byte_count = (size_t)view.bytes;
        yd_disk_revision(&view, summary.revision);
        change_feed = view.format >= 3;
    }
    char body[512];
    int written = snprintf(
        body, sizeof(body),
        "{\"status\":\"ready\",\"revision\":\"%s\","
        "\"collections\":%zu,\"documents\":%zu,\"bytes\":%zu,"
        "\"compressed_bytes\":%zu,\"writable\":%s,\"replica\":%s,\"storage\":\"%s\",\"revision_"
        "scheme\":\"%s\",\"change_feed\":%s,\"replication_policy_free\":%s}\n",
        snapshot->revision, snapshot->collection_count, snapshot->document_count,
        snapshot->byte_count, snapshot->compressed_byte_count,
        server->write_auth_token == NULL || server->engine.replica ||
                server->engine.writes_failed || (native_storage(server) && !native_writable(server))
            ? "false"
            : "true",
        server->engine.replica ? "true" : "false", native_storage(server) ? "native-disk-v2" : "snapshot-v1",
        native_storage(server) ? "xor-fnv-v2" : "fnv-v1",
        change_feed ? "true" : "false",
        policy == YD_REPLICA_POLICY_FREE ? "true" : "false");
    if (written < 0 || (size_t)written >= sizeof(body)) {
        send_json_error(server, connection, 500, "stats_unavailable", head_only);
        return;
    }
    send_response_revision(server, connection, 200, "application/json; charset=utf-8", body,
                           (size_t)written, NULL, head_only, snapshot->revision, response_private(server));
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

static void serve_stats(Server *server, YDConnection *connection, bool head_only)
{
    YamlDBSnapshot summary;
    const YamlDBSnapshot *snapshot = server_summary(server, &summary);
    YDDiskStats disk_stats = server->cluster ? yd_raft_cluster_storage(server->cluster).stats :
        server->disk ? yd_disk_stats(server->disk) : (YDDiskStats){0};
    YDCompactStatus compaction;
    yd_compactor_status(server->compactor, &compaction);
    char body[2048];
    int written = snprintf(
        body, sizeof(body),
        "{\"revision\":\"%s\",\"collections\":%zu,\"documents\":%zu,"
        "\"snapshot_bytes\":%zu,\"compressed_bytes\":%zu,\"workers\":%d,"
        "\"queue_capacity\":%zu,"
        "\"queue_depth\":%zu,\"uptime_seconds\":%llu,"
        "\"accepted\":%llu,\"active\":%llu,\"completed\":%llu,"
        "\"responses_2xx\":%llu,\"responses_4xx\":%llu,"
        "\"responses_5xx\":%llu,\"authentication_failures\":%llu,"
        "\"overload_rejections\":%llu,\"response_bytes\":%llu,"
        "\"writes\":%llu,\"write_conflicts\":%llu,\"storage\":\"%s\",\"revision_scheme\":\"%s\","
        "\"cache_bytes\":%llu,\"cache_hits\":%llu,\"cache_misses\":%llu,\"pages_written\":%llu,"
        "\"bytes_written\":%llu,\"large_body_bytes\":%zu,\"active_change_streams\":%zu,\"change_stream_limit\":%u,"
        "\"file_bytes\":%llu,\"compaction_state\":\"%s\",\"compaction_runs\":%llu,"
        "\"compaction_reclaimed_bytes\":%llu}\n",
        snapshot->revision, snapshot->collection_count, snapshot->document_count,
        snapshot->byte_count, snapshot->compressed_byte_count, server->worker_count,
        server->queue.capacity, queue_depth(&server->queue),
        (unsigned long long)server_uptime_seconds(server),
        (unsigned long long)atomic_load_explicit(&server->metrics.accepted, memory_order_relaxed),
        (unsigned long long)atomic_load_explicit(&server->metrics.active, memory_order_relaxed),
        (unsigned long long)atomic_load_explicit(&server->metrics.completed, memory_order_relaxed),
        (unsigned long long)atomic_load_explicit(&server->metrics.responses_2xx,
                                                 memory_order_relaxed),
        (unsigned long long)atomic_load_explicit(&server->metrics.responses_4xx,
                                                 memory_order_relaxed),
        (unsigned long long)atomic_load_explicit(&server->metrics.responses_5xx,
                                                 memory_order_relaxed),
        (unsigned long long)atomic_load_explicit(&server->metrics.authentication_failures,
                                                 memory_order_relaxed),
        (unsigned long long)atomic_load_explicit(&server->metrics.overload_rejections,
                                                 memory_order_relaxed),
        (unsigned long long)atomic_load_explicit(&server->metrics.response_bytes,
                                                 memory_order_relaxed),
        (unsigned long long)atomic_load_explicit(&server->metrics.writes, memory_order_relaxed),
        (unsigned long long)atomic_load_explicit(&server->metrics.write_conflicts,
                                                 memory_order_relaxed),
        native_storage(server) ? "native-disk-v2" : "snapshot-v1", native_storage(server) ? "xor-fnv-v2" : "fnv-v1",
        (unsigned long long)disk_stats.cache_bytes, (unsigned long long)disk_stats.cache_hits,
        (unsigned long long)disk_stats.cache_misses, (unsigned long long)disk_stats.pages_written,
        (unsigned long long)disk_stats.bytes_written, atomic_load(&server->large_body_bytes),
        atomic_load(&server->active_streams), native_storage(server) ? (unsigned)(server->worker_count / 2 > 8 ? 8 : server->worker_count / 2) : 0,
        (unsigned long long)(server->cluster ? 0 : yd_disk_file_bytes(server->disk)),
        server->compactor ? yd_compact_state_name(compaction.state) : "unavailable",
        (unsigned long long)compaction.runs, (unsigned long long)compaction.total_reclaimed_bytes);
    if (written < 0 || (size_t)written >= sizeof(body)) {
        send_json_error(server, connection, 500, "stats_unavailable", head_only);
        return;
    }
    send_response_revision(server, connection, 200, "application/json; charset=utf-8", body,
                           (size_t)written, NULL, head_only, snapshot->revision, response_private(server));
}

/* Storage maintenance controls accept no parameters: an empty body or {}. */
static bool control_space(unsigned char byte) {
    return byte == ' ' || byte == '\t' || byte == '\r' || byte == '\n';
}
static bool empty_control_body(const Request *request) {
    size_t start = 0, end = request->body_length;
    while (start < end && control_space(request->body[start])) start++;
    while (end > start && control_space(request->body[end - 1])) end--;
    if (start == end) return true;
    if (end - start < 2 || request->body[start] != '{' || request->body[end - 1] != '}') return false;
    for (size_t index = start + 1; index + 1 < end; index++)
        if (!control_space(request->body[index])) return false;
    return true;
}
/* Library diagnostics are fixed English text; quote nothing a client sent. */
static void json_text(char *out, size_t size, const char *text) {
    size_t used = 0;
    for (; text && *text && used + 1 < size; text++)
        out[used++] = *text >= 0x20 && *text < 0x7f && *text != '"' && *text != '\\' ? *text : '?';
    out[used] = 0;
}
static void serve_compaction_status(Server *server, YDConnection *connection, int status,
    bool head_only) {
    YDCompactStatus s;
    yd_compactor_status(server->compactor, &s);
    char error[sizeof(s.error)], body[1536];
    json_text(error, sizeof(error), s.error);
    int written = snprintf(body, sizeof(body),
        "{\"state\":\"%s\",\"phase\":\"%s\",\"supported\":%s,\"automatic\":%s,"
        "\"runs\":%llu,\"succeeded\":%llu,\"failed\":%llu,\"cancelled\":%llu,\"busy\":%llu,"
        "\"rounds\":%llu,\"pages\":%llu,\"records\":%llu,\"bytes_copied\":%llu,"
        "\"pause_attempts\":%llu,\"pause_ms\":%llu,\"size_before\":%llu,\"size_after\":%llu,"
        "\"reclaimed_bytes\":%llu,\"total_reclaimed_bytes\":%llu,\"generation\":%llu,"
        "\"started_unix\":%llu,\"finished_unix\":%llu,\"retired_files\":%zu,"
        "\"file_bytes\":%llu,\"error\":\"%s\"}\n",
        yd_compact_state_name(s.state), s.phase[0] ? s.phase : "idle",
        yd_compactor_supported(server->compactor) ? "true" : "false", s.automatic ? "true" : "false",
        (unsigned long long)s.runs, (unsigned long long)s.succeeded, (unsigned long long)s.failed,
        (unsigned long long)s.cancelled, (unsigned long long)s.busy, (unsigned long long)s.rounds,
        (unsigned long long)s.pages, (unsigned long long)s.records, (unsigned long long)s.bytes_copied,
        (unsigned long long)s.pause_attempts, (unsigned long long)s.pause_ms,
        (unsigned long long)s.size_before, (unsigned long long)s.size_after,
        (unsigned long long)s.reclaimed_bytes, (unsigned long long)s.total_reclaimed_bytes,
        (unsigned long long)s.generation, (unsigned long long)s.started_unix,
        (unsigned long long)s.finished_unix, s.retired_files,
        (unsigned long long)yd_disk_file_bytes(server->disk), error);
    if (written < 0 || (size_t)written >= sizeof(body)) {
        send_json_error(server, connection, 500, "compaction_status_unavailable", head_only);
        return;
    }
    send_response(server, connection, status, "application/json; charset=utf-8", body,
        (size_t)written, NULL, head_only);
}
static void send_storage_error(Server *server, YDConnection *connection, int status,
    const char *code, const char *detail) {
    char text[160], body[320];
    json_text(text, sizeof(text), detail);
    int written = snprintf(body, sizeof(body), "{\"error\":\"%s\",\"detail\":\"%s\"}\n", code, text);
    if (written < 0 || (size_t)written >= sizeof(body)) {
        send_json_error(server, connection, status, code, false);
        return;
    }
    send_response(server, connection, status, "application/json; charset=utf-8", body,
        (size_t)written, status == 503 ? "Retry-After: 1\r\n" : NULL, false);
}
/* Standalone native maintenance: online compaction and in-place upgrade.
 * disk_access already restricted these targets to the administrative
 * credentials; clustered and snapshot servers have no such surface. */
static void serve_storage(Server *server, YDConnection *connection, Request *request) {
    bool get = !strcmp(request->method, "GET") || request->head_only;
    bool post = !strcmp(request->method, "POST"), remove = !strcmp(request->method, "DELETE");
    bool compaction = !strcmp(request->target, "/v1/storage/compaction");
    bool upgrade = !strcmp(request->target, "/v1/storage/upgrade");
    if (!compaction && !upgrade) {
        send_json_error(server, connection, 404, "not_found", request->head_only); return;
    }
    if ((compaction && !get && !post && !remove) || (upgrade && !post)) {
        static const char body[] = "{\"error\":\"method_not_allowed\"}\n";
        send_response(server, connection, 405, "application/json; charset=utf-8", body,
            sizeof(body) - 1, compaction ? "Allow: GET, HEAD, POST, DELETE\r\n" : "Allow: POST\r\n",
            request->head_only);
        return;
    }
    if (request->if_match_present || request->if_none_match_present || !empty_control_body(request)) {
        send_json_error(server, connection, 400, "invalid_storage_control", request->head_only); return;
    }
    if (!server->disk || server->cluster || !server->compactor) {
        send_json_error(server, connection, 409, "storage_maintenance_unavailable", request->head_only);
        return;
    }
    request->audit_outcome = YD_AUDIT_RETURNED_SUCCESS;
    if (compaction && get) { serve_compaction_status(server, connection, 200, request->head_only); return; }
    if (compaction && remove) {
        bool cancelled = yd_compactor_cancel(server->compactor);
        char body[32];
        int n = snprintf(body, sizeof(body), "{\"cancelled\":%s}\n", cancelled ? "true" : "false");
        send_response(server, connection, 200, "application/json; charset=utf-8", body, (size_t)n, NULL, false);
        return;
    }
    char error[256] = {0};
    if (compaction) {
        int started = yd_compactor_start(server->compactor, error, sizeof(error));
        if (started < 0) {
            request->audit_outcome = YD_AUDIT_RETURNED_FAILURE;
            send_storage_error(server, connection, 409, "compaction_unsupported", error); return;
        }
        if (!started) {
            request->audit_outcome = YD_AUDIT_RETURNED_FAILURE;
            send_storage_error(server, connection, 409, "compaction_already_running",
                "a compaction is already queued or running"); return;
        }
        serve_compaction_status(server, connection, 202, false);
        return;
    }
    YDDiskUpgradeInfo info;
    int upgraded = yd_disk_upgrade_live(server->disk, 250, &info, error, sizeof(error));
    if (upgraded < 0) {
        request->audit_outcome = YD_AUDIT_RETURNED_FAILURE;
        if (upgraded == -2) send_storage_error(server, connection, 503, "storage_busy", error);
        else send_storage_error(server, connection, 409, "upgrade_unsupported", error);
        return;
    }
    if (upgraded) yd_compactor_refresh(server->compactor);
    char body[160];
    int n = snprintf(body, sizeof(body), "{\"upgraded\":%s,\"from\":%u,\"to\":%u,\"generation\":%llu}\n",
        upgraded ? "true" : "false", (unsigned)info.from, (unsigned)info.to,
        (unsigned long long)info.generation);
    send_response(server, connection, 200, "application/json; charset=utf-8", body, (size_t)n, NULL, false);
}

static void serve_metrics(Server *server, YDConnection *connection, bool head_only)
{
    YamlDBSnapshot summary;
    const YamlDBSnapshot *snapshot = server_summary(server, &summary);
    char body[METRICS_BODY_LIMIT];
    int written = snprintf(
        body, sizeof(body),
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
        (unsigned long long)server_uptime_seconds(server), snapshot->collection_count,
        snapshot->document_count, snapshot->byte_count, snapshot->compressed_byte_count,
        queue_depth(&server->queue),
        (unsigned long long)atomic_load_explicit(&server->metrics.active, memory_order_relaxed),
        (unsigned long long)atomic_load_explicit(&server->metrics.accepted, memory_order_relaxed),
        (unsigned long long)atomic_load_explicit(&server->metrics.completed, memory_order_relaxed),
        (unsigned long long)atomic_load_explicit(&server->metrics.responses_2xx,
                                                 memory_order_relaxed),
        (unsigned long long)atomic_load_explicit(&server->metrics.responses_4xx,
                                                 memory_order_relaxed),
        (unsigned long long)atomic_load_explicit(&server->metrics.responses_5xx,
                                                 memory_order_relaxed),
        (unsigned long long)atomic_load_explicit(&server->metrics.authentication_failures,
                                                 memory_order_relaxed),
        (unsigned long long)atomic_load_explicit(&server->metrics.overload_rejections,
                                                 memory_order_relaxed),
        (unsigned long long)atomic_load_explicit(&server->metrics.response_bytes,
                                                 memory_order_relaxed),
        (unsigned long long)atomic_load_explicit(&server->metrics.writes, memory_order_relaxed),
        (unsigned long long)atomic_load_explicit(&server->metrics.write_conflicts,
                                                 memory_order_relaxed));
    if (written < 0 || (size_t)written >= sizeof(body)) {
        send_json_error(server, connection, 500, "metrics_unavailable", head_only);
        return;
    }
    send_response_revision(server, connection, 200, "text/plain; version=0.0.4; charset=utf-8",
                           body, (size_t)written, NULL, head_only, snapshot->revision,
                           response_private(server));
}

static void serve_collection(
    Server *server,
    YDConnection *connection,
    const char *collection_name,
    bool head_only
)
{
    const YamlDBCollection *collection = yamldb_snapshot_collection(
        server->engine.snapshot,
        collection_name
    );
    if (collection == NULL) {
        send_json_error(server, connection, 404, "collection_not_found", head_only);
        return;
    }
    send_response(
        server,
        connection,
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
    YDConnection *connection,
    const char *collection_name,
    size_t limit,
    const char *after,
    bool head_only
)
{
    const YamlDBCollection *collection = yamldb_snapshot_collection(
        server->engine.snapshot,
        collection_name
    );
    if (collection == NULL) {
        send_json_error(server, connection, 404, "collection_not_found", head_only);
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
    size_t capacity = 128 + YAMLDB_NAME_LIMIT + strlen(collection_name);
    for (size_t index = 0; index < count; index++) {
        capacity += strlen(collection->documents[start + index].name) + 4;
    }
    char *body = malloc(capacity);
    if (body == NULL) {
        send_json_error(server, connection, 500, "index_unavailable", head_only);
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
        send_json_error(server, connection, 500, "index_unavailable", head_only);
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
            send_json_error(server, connection, 500, "index_unavailable", head_only);
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
        send_json_error(server, connection, 500, "index_unavailable", head_only);
        return;
    }
    used += (size_t)written;
    send_response(
        server,
        connection,
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
    YDConnection *connection,
    const char *collection_name,
    const char *document_name,
    bool accepts_gzip,
    bool head_only
)
{
    const YamlDBCollection *collection = yamldb_snapshot_collection(
        server->engine.snapshot,
        collection_name
    );
    const YamlDBDocument *document = collection == NULL ? NULL :
        yamldb_collection_document(collection, document_name);
    if (document == NULL) {
        send_json_error(server, connection, 404, "document_not_found", head_only);
        return;
    }
    bool compressed = accepts_gzip && document->gzip_body != NULL;
    const unsigned char *body = compressed ? document->gzip_body : document->body;
    size_t body_length = compressed ? document->gzip_length : document->length;
    char extra_headers[160 + 2 * YAMLDB_NAME_LIMIT];
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
        send_json_error(server, connection, 500, "document_unavailable", head_only);
        return;
    }
    send_response(
        server,
        connection,
        200,
        "application/yaml; charset=utf-8",
        (const char *)body,
        body_length,
        extra_headers,
        head_only
    );
}

static bool yaml_content_type(Request *request)
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

static bool json_content_type(Request *request)
{
    if (!request->content_type_present) {
        return false;
    }
    static const char application_json[] = "application/json";
    size_t length = strcspn(request->content_type, ";");
    return length == sizeof(application_json) - 1 &&
        strncasecmp(request->content_type, application_json, length) == 0;
}

static bool json_has_raw_yaml_line_break(const unsigned char *body, size_t length)
{
    for (size_t index = 0; index < length; index++) {
        if (index + 1 < length && body[index] == 0xc2 && body[index + 1] == 0x85) {
            return true;
        }
        if (index + 2 < length && body[index] == 0xe2 && body[index + 1] == 0x80 &&
            (body[index + 2] == 0xa8 || body[index + 2] == 0xa9)) {
            return true;
        }
    }
    return false;
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

static void send_engine_reply(Server *server, YDConnection *connection, YDReply *reply, bool head)
{
    if (reply->status >= 200 && reply->status < 300)
        atomic_fetch_add_explicit(&server->metrics.writes, 1, memory_order_relaxed);
    if (reply->status == 412)
        atomic_fetch_add_explicit(&server->metrics.write_conflicts, 1, memory_order_relaxed);
    (void)pthread_rwlock_rdlock(&server->snapshot_lock);
    send_response(server,connection,reply->status,"application/json; charset=utf-8",
                  reply->body,reply->length,reply->etag,head);
    (void)pthread_rwlock_unlock(&server->snapshot_lock);
    yd_reply_free(reply);
}

static bool route_document_api(Server *server, YDConnection *connection, Request *request)
{
    bool query=strncmp(request->target,"/v1/query/",10)==0;
    bool indexes=strcmp(request->target,"/v1/indexes")==0;
    bool transaction=strcmp(request->target,"/v1/transactions")==0;
    bool replica=strncmp(request->target,"/v1/replication/",16)==0;
    if (!query && !indexes && !transaction && !replica) return false;
    bool read=(query && strcmp(request->method,"POST")==0) ||
              (indexes && (strcmp(request->method,"GET")==0 || request->head_only));
    bool write=(indexes && strcmp(request->method,"PUT")==0) ||
               ((transaction || replica) && strcmp(request->method,"POST")==0);
    bool json=json_content_type(request);
    YDReply result={0};
    if (!read && !write) result=(YDReply){.status=405};
    else if (write && server->write_auth_token==NULL) result=(YDReply){.status=405};
    else if (!request_authorized(server,request,write)) {
        atomic_fetch_add_explicit(&server->metrics.authentication_failures,1,memory_order_relaxed);
        result=(YDReply){.status=401};
    } else if (!(indexes && read) && !yaml_content_type(request) && !json) {
        result=(YDReply){.status=415};
    } else if (json && json_has_raw_yaml_line_break(request->body,request->body_length)) {
        result=(YDReply){.status=400};
    }
    if (result.status!=0) {
        (void)pthread_rwlock_rdlock(&server->snapshot_lock);
        send_json_error(server,connection,result.status,
                        result.status==401 ? "unauthorized" : "unsupported_request",request->head_only);
        (void)pthread_rwlock_unlock(&server->snapshot_lock);
        return true;
    }
    if (write) (void)pthread_mutex_lock(&server->write_lock);
    else (void)pthread_rwlock_rdlock(&server->snapshot_lock);
    result=yd_engine_request(&server->engine,request->head_only ? "GET" : request->method,
        request->target,request->body,request->body_length,
        request->if_match_present ? request->if_match : NULL,
        request->if_none_match_present ? request->if_none_match : NULL);
    if (write) {
        send_engine_reply(server,connection,&result,request->head_only);
        (void)pthread_mutex_unlock(&server->write_lock);
    } else {
        send_response(server,connection,result.status,"application/json; charset=utf-8",
                      result.body,result.length,result.etag,request->head_only);
        yd_reply_free(&result);
        (void)pthread_rwlock_unlock(&server->snapshot_lock);
    }
    return true;
}

static void serve_cluster_status(Server *server, YDConnection *connection, Request *request,
                                  bool detailed) {
    YDRaftClusterStatus s = yd_raft_cluster_status(server->cluster);
    static const char *const roles[] = {"follower", "candidate", "leader", "failed"};
    char body[4096];
    int n = detailed ? snprintf(body, sizeof(body),
        "{\"node\":%u,\"leader\":%u,\"term\":%llu,\"role\":\"%s\",\"voters\":%u,"
        "\"last\":%llu,\"committed\":%llu,\"applied\":%llu,\"failed\":%s,"
        "\"checkpoints\":{\"enabled\":%s,\"running\":%s,\"succeeded\":%llu,\"failed\":%llu,\"last_index\":%llu},"
        "\"compaction\":{\"enabled\":%s,\"running\":%s,\"attempted\":%llu,\"succeeded\":%llu,"
        "\"skipped\":%llu,\"stale\":%llu,\"failed\":%llu,\"source_bytes\":%llu,"
        "\"candidate_bytes\":%llu,\"last_result\":%d},"
        "\"application_compaction\":{\"enabled\":%s,\"running\":%s,\"published\":%s,\"pending\":%s,"
        "\"blocked\":%s,\"timed_out\":%s,\"history_full\":%s,\"retained\":%zu,\"capacity\":32,"
        "\"stop\":%d,\"result\":%d,\"selection\":%d,\"admission\":%d,"
        "\"attempted\":%llu,\"reconciled\":%llu,\"publications\":%llu,\"retired\":%llu,"
        "\"source_bytes\":%llu,\"saved_bytes\":%llu,\"retained_bytes\":%llu,\"reserved_bytes\":%llu,"
        "\"image_high_water\":%llu,\"archive_high_water\":%llu,\"restore_high_water\":%llu}}\n",
        s.raft.node, s.raft.leader, (unsigned long long)s.raft.term, roles[s.raft.role], s.raft.voters,
        (unsigned long long)s.raft.last, (unsigned long long)s.raft.committed,
        (unsigned long long)s.applied.index, s.failed ? "true" : "false",
        s.checkpoints.enabled ? "true" : "false", s.checkpoints.running ? "true" : "false",
        (unsigned long long)s.checkpoints.succeeded, (unsigned long long)s.checkpoints.failed,
        (unsigned long long)s.checkpoints.last_index,
        s.compaction.enabled ? "true" : "false", s.compaction.running ? "true" : "false",
        (unsigned long long)s.compaction.attempted, (unsigned long long)s.compaction.succeeded,
        (unsigned long long)s.compaction.skipped, (unsigned long long)s.compaction.stale,
        (unsigned long long)s.compaction.failed, (unsigned long long)s.compaction.source_bytes,
        (unsigned long long)s.compaction.candidate_bytes, s.compaction.last_result,
        s.application_compaction.enabled ? "true" : "false", s.application_compaction.running ? "true" : "false",
        s.application_compaction.published ? "true" : "false", s.application_compaction.pending ? "true" : "false",
        s.application_compaction.blocked ? "true" : "false", s.application_compaction.timed_out ? "true" : "false",
        s.application_compaction.history_full ? "true" : "false", s.application_compaction.retained,
        s.application_compaction.stop, s.application_compaction.result, s.application_compaction.selection,
        s.application_compaction.admission,
        (unsigned long long)s.application_compaction.attempted, (unsigned long long)s.application_compaction.reconciled,
        (unsigned long long)s.application_compaction.publications, (unsigned long long)s.application_compaction.retired,
        (unsigned long long)s.application_compaction.source_bytes, (unsigned long long)s.application_compaction.saved_bytes,
        (unsigned long long)s.application_compaction.retained_bytes, (unsigned long long)s.application_compaction.reserved_bytes,
        (unsigned long long)s.application_compaction.image_high_water, (unsigned long long)s.application_compaction.archive_high_water,
        (unsigned long long)s.application_compaction.restore_high_water) :
        snprintf(body, sizeof(body), "{\"node\":%u,\"leader\":%u,\"term\":%llu,\"role\":\"%s\"}\n",
                 s.raft.node, s.raft.leader, (unsigned long long)s.raft.term, roles[s.raft.role]);
    if (n < 0 || (size_t)n >= sizeof(body)) {
        send_json_error(server, connection, 503, "cluster_unavailable", request->head_only); return;
    }
    /* Advisory routing information is not a quorum or document read proof. */
    send_response(server, connection, 200, "application/json; charset=utf-8", body, (size_t)n,
                  "Cache-Control: no-store\r\n", request->head_only);
}
/* A deliberately small flat JSON control schema: ASCII names/operations and
 * canonical unsigned decimal integers. No YAML coercion, duplicate fields,
 * escapes, nested values, floats or trailing input are admitted. */
static void retention_space(const unsigned char **at, const unsigned char *end) {
    while (*at < end && (**at == ' ' || **at == '\t' || **at == '\r' || **at == '\n')) (*at)++;
}
static bool retention_word(const unsigned char **at, const unsigned char *end, char out[32]) {
    if (*at == end || *(*at)++ != '"') return false;
    size_t size = 0;
    while (*at < end && **at != '"') {
        if (size == 31 || **at < 0x20 || **at > 0x7e || **at == '\\') return false;
        out[size++] = (char)*(*at)++;
    }
    out[size] = 0;
    return *at < end && *(*at)++ == '"';
}
static bool retention_control_body(const Request *request, uint64_t *expected,
    YDRaftReceiptPolicy *policy, bool *activate, bool *prune) {
    if (!request->body_length || request->body_length > 512) return false;
    const unsigned char *at = request->body, *end = at + request->body_length;
    unsigned fields = 0; char operation[32] = {0};
    uint64_t numbers[4] = {0};
    static const char *const names[] = {"operation", "expected_epoch", "maximum_count", "maximum_bytes", "prune_limit"};
    retention_space(&at, end);
    if (at == end || *at++ != '{') return false;
    for (;;) {
        char name[32]; retention_space(&at, end);
        if (!retention_word(&at, end, name)) return false;
        unsigned field = 0;
        while (field < 5 && strcmp(name, names[field])) field++;
        if (field == 5 || (fields & (1U << field))) return false;
        fields |= 1U << field;
        retention_space(&at, end);
        if (at == end || *at++ != ':') return false;
        retention_space(&at, end);
        if (!field) {
            if (!retention_word(&at, end, operation)) return false;
        } else {
            const unsigned char *start = at;
            while (at < end && *at >= '0' && *at <= '9') at++;
            if (!receipt_decimal(start, (size_t)(at - start), &numbers[field - 1])) return false;
        }
        retention_space(&at, end);
        if (at == end) return false;
        if (*at == '}') { at++; break; }
        if (*at++ != ',') return false;
    }
    retention_space(&at, end);
    *activate = !strcmp(operation, "activate");
    *prune = !strcmp(operation, "prune");
    if (at != end || (!*activate && !*prune && strcmp(operation, "advance")) ||
        fields != (*activate ? 31U : 3U) || (*activate && numbers[0]) ||
        (!*activate && !numbers[0]) ||
        numbers[3] > YD_RAFT_RECEIPT_PRUNE_LIMIT) return false;
    *expected = numbers[0];
    *policy = (YDRaftReceiptPolicy){numbers[1], numbers[2], (uint32_t)numbers[3]};
    return !*activate || yd_raft_receipt_policy_valid(*policy);
}
static void serve_receipt_retention(Server *server, YDConnection *connection, Request *request) {
    if (request->receipt_epoch_present || request->request_id_present ||
        request->if_match_present || request->if_none_match_present) {
        send_json_error(server, connection, 400, "invalid_receipt_control", request->head_only); return;
    }
    if (!strcmp(request->method, "GET")) {
        if (request->body_length) {
            send_json_error(server, connection, 400, "invalid_receipt_control", false); return;
        }
        YDRaftReceiptRetention state;
        if (!yd_raft_cluster_receipt_retention_status(server->cluster, server->cluster_timeout_ms, &state)) {
            send_json_error(server, connection, 503, "cluster_unavailable", false); return;
        }
        char body[512];
        int size = snprintf(body, sizeof(body), "{\"enabled\":%s,\"epoch\":%llu,\"count\":%llu,"
            "\"bytes\":%llu,\"maximum_count\":%llu,\"maximum_bytes\":%llu,\"prune_limit\":%u,\"pruning\":%s}\n",
            state.enabled ? "true" : "false", (unsigned long long)state.epoch,
            (unsigned long long)state.count, (unsigned long long)state.bytes,
            (unsigned long long)state.maximum_count, (unsigned long long)state.maximum_bytes,
            state.prune_limit, state.pruning ? "true" : "false");
        send_response(server, connection, 200, "application/json; charset=utf-8", body,
            (size_t)size, "Cache-Control: no-store\r\n", false);
        return;
    }
    if (strcmp(request->method, "POST")) {
        static const char body[] = "{\"error\":\"method_not_allowed\"}\n";
        send_response(server, connection, 405, "application/json; charset=utf-8", body,
            sizeof(body) - 1, "Allow: GET, POST\r\n", request->head_only); return;
    }
    if (!json_content_type(request)) {
        send_json_error(server, connection, 415, "json_content_type_required", false); return;
    }
    uint64_t expected = 0; YDRaftReceiptPolicy policy; bool activate, prune;
    if (!retention_control_body(request, &expected, &policy, &activate, &prune)) {
        send_json_error(server, connection, 400, "invalid_receipt_control", false); return;
    }
    YDDiskReply reply = yd_raft_cluster_receipt_retention_control(server->cluster, expected,
        activate ? &policy : NULL, prune, server->cluster_timeout_ms);
    send_response_revision(server, connection, reply.status, "application/json; charset=utf-8",
        reply.body, reply.length, reply.headers, false, reply.revision, request_private(server, request));
    yd_disk_reply_free(&reply);
}
/* Owned response boundary shared by native transports. No socket operations;
 * the caller authenticates/validates its operation before dispatch. Keep the
 * original commit receipt's revision even if another writer has since won. */
static YDDiskReply native_final_admission(Server *server, Request *request, bool write) {
    /* Online access-token liveness is checked at final dispatch, after any
     * large-body preflight or durable audit wait. Kerberos retains its one-use
     * verified context and mutual-authentication reply. */
    if (request->identity_checked && request->identity_category == YD_ACCESS_IDENTITY_OIDC) {
        request->identity_checked = false;
        int status = disk_access(server, request, write, false);
        if (status) {
            request->audit_outcome = YD_AUDIT_NOT_DISPATCHED;
            return yd_disk_error_reply(status, access_error(status));
        }
    }
    if (request->identity_checked && request->identity_category == YD_ACCESS_IDENTITY_OIDC) {
        time_t wall = time(NULL);
        if (wall == (time_t)-1 || (uintmax_t)wall > UINT64_C(253402300799) ||
            !request->identity_expires_at || (int64_t)wall >= request->identity_expires_at) {
            request->audit_outcome = YD_AUDIT_NOT_DISPATCHED;
            return yd_disk_error_reply(wall == (time_t)-1 ? 503 : 401, "authentication_expired");
        }
    }
    uint64_t now = monotonic_milliseconds();
    if (request->deadline && (!now || now >= request->deadline)) {
        request->audit_outcome = YD_AUDIT_NOT_DISPATCHED;
        return yd_disk_error_reply(504, "request_deadline");
    }
    return (YDDiskReply){0};
}
static YDDiskReply execute_native_request(Server *server, Request *request, bool write,
    unsigned timeout_ms) {
    YDDiskReply reply;
    if (server->cluster && write && server->engine.replica &&
        strncmp(request->target, "/v1/replication/", 16))
        return yd_disk_error_reply(405, "replica_read_only");
    YDDiskReply admission = native_final_admission(server, request, write);
    if (admission.status) return admission;
    if (!server->cluster && request->receipt_epoch_present)
        return yd_disk_error_reply(409, "receipt_retention_disabled");
    if (server->cluster && write) {
        if (!request->request_id_present)
            return yd_disk_error_reply(400, "request_id_required");
        YDRaftWrite command = {.method = request->method, .target = request->target,
            .body = request->body, .size = request->body_length,
            .match = request->if_match_present ? request->if_match : NULL,
            .none = request->if_none_match_present ? request->if_none_match : NULL,
            .receipt_epoch = request->receipt_epoch};
        memcpy(command.id, request->request_id, 16);
        reply = yd_raft_cluster_write(server->cluster, &command, timeout_ms);
    } else if (server->cluster) {
        reply = yd_raft_cluster_query(
            server->cluster, request->head_only ? "GET" : request->method, request->target,
            request->body, request->body_length, request->if_match_present ? request->if_match : NULL,
            request->if_none_match_present ? request->if_none_match : NULL, request->accepts_gzip,
            timeout_ms);
    } else if (!server->audit) {
        /* Preserve the ordinary dispatch seam used by transport ownership and
         * fault-injection qualification when protected auditing is not enabled. */
        if (write && (yd_disk_policy_api_target(request->target) || yd_disk_branch_target(request->target)))
            reply = yd_disk_api_request_with_id(&server->disk_api, request->method,
                request->target, request->body, request->body_length,
                request->if_match_present ? request->if_match : NULL,
                request->if_none_match_present ? request->if_none_match : NULL,
                request->accepts_gzip, request->request_id_present ? request->request_id : NULL);
        else reply = yd_disk_api_request(&server->disk_api,
            request->head_only ? "GET" : request->method, request->target,
            request->body, request->body_length,
            request->if_match_present ? request->if_match : NULL,
            request->if_none_match_present ? request->if_none_match : NULL, request->accepts_gzip);
    } else {
        bool transferred = false;
        reply = yd_disk_api_request_with_job(&server->disk_api,
            request->head_only ? "GET" : request->method, request->target,
            request->body, request->body_length,
            request->if_match_present ? request->if_match : NULL,
            request->if_none_match_present ? request->if_none_match : NULL,
            request->accepts_gzip, request->request_id_present ? request->request_id : NULL,
            request->audit_operation ? yd_audit_dispatch_job_terminal : NULL,
            request->audit_operation, &transferred);
        if (transferred) request->audit_operation = NULL;
    }

    request->audit_outcome = reply.outcome == YD_DISK_OUTCOME_RETURNED_SUCCESS ? YD_AUDIT_RETURNED_SUCCESS :
        reply.outcome == YD_DISK_OUTCOME_RETURNED_FAILURE ? YD_AUDIT_RETURNED_FAILURE :
        reply.outcome == YD_DISK_OUTCOME_NOT_DISPATCHED ? YD_AUDIT_NOT_DISPATCHED : YD_AUDIT_UNKNOWN;
    request->audit_has_receipt = reply.has_receipt;
    if (reply.has_receipt) request->audit_receipt = reply.receipt;
    if (!reply.revision[0] || server->binary_tls) {
        /* Workers may acquire backend locks; the binary I/O admission callback
         * uses only the resulting advisory revision cache. A receipt keeps its
         * own original revision, even when this observation is newer. */
        YDDiskView view = native_view(server);
        if (!reply.revision[0]) yd_disk_revision(&view, reply.revision);
        if (server->binary_tls)
            atomic_store_explicit(&server->binary_revision, view.revision, memory_order_relaxed);
    }
    if (write && reply.status >= 200 && reply.status < 300)
        atomic_fetch_add_explicit(&server->metrics.writes, 1, memory_order_relaxed);
    if (write && reply.status == 412)
        atomic_fetch_add_explicit(&server->metrics.write_conflicts, 1, memory_order_relaxed);
    return reply;
}
static YDDiskReply native_document_error_at(Server *server, int status, const char *code,
    const char *revision) {
    YDDiskReply reply = yd_disk_error_reply(status, code);
    const char *headers = "";
    if (reply.status == 405) headers = server->write_auth_token ?
        "Allow: GET, HEAD, PUT, DELETE\r\n" : "Allow: GET, HEAD\r\n";
    else if (reply.status == 401) headers = "WWW-Authenticate: Bearer\r\n";
    else if (reply.status == 503) headers = "Retry-After: 1\r\n";
    memcpy(reply.headers, headers, strlen(headers) + 1);
    if (revision) memcpy(reply.revision, revision, sizeof(reply.revision));
    else {
        YDDiskView view = native_view(server);
        yd_disk_revision(&view, reply.revision);
    }
    return reply;
}
static void send_native_reply(Server *server, YDConnection *connection,
    Request *request, const YDDiskReply *reply) {
    char headers[RESPONSE_HEADER_LIMIT];
    int n = snprintf(headers, sizeof(headers), "%s%s", reply->headers, request->identity_reply);
    if (n < 0 || (size_t)n >= sizeof(headers)) {
        send_json_error(server, connection, 503, "response_headers_unavailable", request->head_only);
        return;
    }
    send_response_revision(server, connection, reply->status,
        reply->content_type ? reply->content_type : "application/json; charset=utf-8",
        reply->body, reply->length, headers, request->head_only, reply->revision,
        request_private(server, request));
}
static void send_request_error(Server *server, YDConnection *connection, Request *request,
    int status, const char *code, bool head_only) {
    (void)head_only;
    YDDiskReply reply = native_document_error_at(server, status, code, NULL);
    send_native_reply(server, connection, request, &reply);
    yd_disk_reply_free(&reply);
}
static bool native_document_target(Request *request) {
    if (strcmp(request->method, "GET") && strcmp(request->method, "PUT") &&
        strcmp(request->method, "DELETE") && !request->head_only)
        return false;
    char target[REQUEST_TARGET_LIMIT + 1], collection[YAMLDB_NAME_LIMIT + 1], *document;
    memcpy(target, request->target, strlen(request->target) + 1);
    return parse_database_target(target, collection, &document) && document;
}
/* Document CRUD only; operational/query/stream routes keep their own adapters.
 * The request and body are immutable/borrowed for the entire synchronous call.
 * Returned response owns its body; mTLS never substitutes for bearer grants. */
static YDDiskReply admit_native_document(Server *server, Request *request,
    const char *revision) {
    if (!native_document_target(request))
        return native_document_error_at(server, 400, "invalid_path", revision);
    bool write = strcmp(request->method, "GET") && !request->head_only;
    if (write && !server->write_auth_token)
        return native_document_error_at(server, 405, "writes_disabled", revision);
    int access = disk_access(server, request, write, false);
    if (access) {
        if (access == 401) atomic_fetch_add_explicit(&server->metrics.authentication_failures,
            1, memory_order_relaxed);
        return native_document_error_at(server, access, access_error(access), revision);
    }
    if (!strcmp(request->method, "PUT") && !yaml_content_type(request))
        return native_document_error_at(server, 415, "yaml_content_type_required", revision);
    if (write && server->cluster && !request->request_id_present)
        return native_document_error_at(server, 400, "request_id_required", revision);
    return (YDDiskReply){0};
}
static YDDiskReply execute_native_document(Server *server, Request *request,
    unsigned timeout_ms) {
    YDDiskReply rejected = admit_native_document(server, request, NULL);
    if (rejected.status) return rejected;
    return execute_native_request(server, request,
        strcmp(request->method, "GET") && !request->head_only, timeout_ms);
}
/* Binary metadata is already bounded and canonical. Project the same bytes and
 * preconditions used by HTTP so durable cluster receipt fingerprints agree. */
static Request binary_request(const YDBinaryRequestMessage *message,
    const unsigned char *body, size_t length) {
    static const char *const methods[] = {"", "GET", "HEAD", "PUT", "DELETE", "POST", "PATCH"};
    Request request = {0};
    if (message->method < YD_BINARY_METHOD_GET || message->method > YD_BINARY_METHOD_PATCH)
        return request;
    strcpy(request.method, methods[message->method]);
    request.head_only = message->method == YD_BINARY_METHOD_HEAD;
    memcpy(request.target, message->target, sizeof(request.target));
    memcpy(request.content_type, message->content_type, sizeof(request.content_type));
    request.content_type_present = message->method == YD_BINARY_METHOD_PUT ||
        message->method == YD_BINARY_METHOD_POST || message->method == YD_BINARY_METHOD_PATCH;
    request.content_length_present = request.content_type_present;
    request.content_length = (size_t)message->body_length;
    request.authorization_present = (message->present & YD_BINARY_REQUEST_AUTHORIZATION) != 0;
    memcpy(request.authorization, message->authorization, sizeof(message->authorization));
    request.if_match_present = (message->present & YD_BINARY_REQUEST_IF_MATCH) != 0;
    memcpy(request.if_match, message->if_match, sizeof(message->if_match));
    request.if_none_match_present = (message->present & YD_BINARY_REQUEST_IF_NONE_MATCH) != 0;
    memcpy(request.if_none_match, message->if_none_match, sizeof(message->if_none_match));
    request.request_id_present = (message->present & YD_BINARY_REQUEST_ID) != 0;
    memcpy(request.request_id, message->request_id, sizeof(request.request_id));
    request.body = (unsigned char *)body; /* Synchronous borrowed input, never mutated. */
    request.body_length = length;
    return request;
}
static bool binary_text(char *out, size_t capacity, const char *value) {
    size_t n = strlen(value);
    if (n >= capacity) return false;
    memcpy(out, value, n + 1);
    return true;
}
/* Only these trusted internal CRUD headers have binary counterparts. Even an
 * unexpected internal field must fail rather than silently lose semantics. */
static bool binary_reply_headers(YDBinaryResponseMessage *message, const char *headers) {
    char copy[512];
    if (strnlen(headers, sizeof(copy)) == sizeof(copy)) return false;
    strcpy(copy, headers);
    unsigned seen = 0;
    for (char *line = copy; *line;) {
        char *end = strstr(line, "\r\n");
        if (!end) return false;
        *end = 0;
        char *value = strstr(line, ": ");
        if (!value) return false;
        *value = 0;
        value += 2;
        unsigned bit = 0;
        if (!strcmp(line, "ETag")) {
            bit = YD_BINARY_RESPONSE_ETAG;
            if (!binary_text(message->etag, sizeof(message->etag), value)) return false;
        } else if (!strcmp(line, "X-YamlDB-Collection")) {
            bit = YD_BINARY_RESPONSE_COLLECTION;
            if (!binary_text(message->collection, sizeof(message->collection), value)) return false;
        } else if (!strcmp(line, "X-YamlDB-Document")) {
            bit = YD_BINARY_RESPONSE_DOCUMENT;
            if (!binary_text(message->document, sizeof(message->document), value)) return false;
        } else if (!strcmp(line, "Allow")) {
            bit = YD_BINARY_RESPONSE_ALLOW;
            if (!strcmp(value, "GET, HEAD")) message->allow = YD_BINARY_ALLOW_GET | YD_BINARY_ALLOW_HEAD;
            else if (!strcmp(value, "GET, HEAD, PUT, DELETE")) message->allow = YD_BINARY_ALLOW_ALL;
            else return false;
        } else if (!strcmp(line, "WWW-Authenticate")) {
            bit = YD_BINARY_RESPONSE_AUTHENTICATE;
            if (strcmp(value, "Bearer")) return false;
            message->authenticate = YD_BINARY_AUTHENTICATE_BEARER;
        } else if (!strcmp(line, "Retry-After")) {
            bit = YD_BINARY_RESPONSE_RETRY_AFTER;
            /* Current native CRUD only emits this fixed delta. */
            if (strcmp(value, "1")) return false;
            message->retry_after_seconds = 1;
        } else if (!strcmp(line, "Vary")) {
            bit = 1U << 12;
            if (strcmp(value, "Accept-Encoding")) return false;
        } else if (!strcmp(line, "Cache-Control")) {
            bit = 1U << 13;
            if (strcmp(value, "no-store")) return false;
        } else return false;
        if (seen & bit) return false;
        seen |= bit;
        if (bit < (1U << 12)) message->present |= (uint16_t)bit;
        line = end + 2;
    }
    return true;
}
static YDBinaryReply binary_reply(Server *server, const YDBinaryRequestMessage *request,
    YDDiskReply reply, const char *admission_revision, bool private_metadata) {
    if (reply.length > YD_BINARY_BODY_LIMIT) {
        char revision[17]; memcpy(revision, reply.revision, sizeof(revision));
        yd_disk_reply_free(&reply);
        reply = native_document_error_at(server, 413, "binary_response_limit", revision);
    }
    YDBinaryReply result = {0};
    YDBinaryResponseMessage *message = &result.message;
    message->schema = request->schema;
    message->status = (uint16_t)reply.status;
    message->representation_length = reply.length;
    message->body_length = request->method == YD_BINARY_METHOD_HEAD ? 0 : reply.length;
    memcpy(message->revision, reply.revision, sizeof(message->revision));
    bool valid = binary_text(message->content_type, sizeof(message->content_type),
        reply.content_type ? reply.content_type : "application/json; charset=utf-8") &&
        binary_reply_headers(message, reply.headers) && (!reply.length || reply.body);
    if (request->present & YD_BINARY_REQUEST_ID) {
        message->present |= YD_BINARY_RESPONSE_ID;
        memcpy(message->request_id, request->request_id, 16);
    }
    size_t metadata_size = 0;
    valid = valid && yd_binary_response_message_size(message, &metadata_size);
    if (!valid) {
        yd_disk_reply_free(&reply);
        memset(&result, 0, sizeof(result));
        message->schema = request->schema;
        reply = native_document_error_at(server, 500, "binary_response_invalid", admission_revision);
        message->status = (uint16_t)reply.status;
        strcpy(message->content_type, "application/json; charset=utf-8");
        memcpy(message->revision, reply.revision, sizeof(message->revision));
        message->representation_length = reply.length;
        message->body_length = request->method == YD_BINARY_METHOD_HEAD ? 0 : reply.length;
        (void)binary_reply_headers(message, reply.headers);
        if (request->present & YD_BINARY_REQUEST_ID) {
            message->present |= YD_BINARY_RESPONSE_ID;
            memcpy(message->request_id, request->request_id, 16);
        }
    }
    if (private_metadata) {
        char error[128];
        YDFieldResponseKind kind = reply.content_type &&
            !strncmp(reply.content_type, "application/json", 16) ?
            YD_FIELD_RESPONSE_JSON : YD_FIELD_RESPONSE_SOURCE;
        if (!yd_field_response_body(kind, &reply.body, &reply.length, error, sizeof(error))) {
            yd_disk_reply_free(&reply);
            reply = yd_disk_error_reply(503, "private_response_unavailable");
            message->status = 503;
            strcpy(message->content_type, "application/json; charset=utf-8");
            message->present &= YD_BINARY_RESPONSE_ID;
        }
        message->representation_length = reply.length;
        message->body_length = request->method == YD_BINARY_METHOD_HEAD ? 0 : reply.length;
        yd_field_response_binary_metadata(message);
    }
    record_response(server, message->status, (size_t)message->representation_length);
    if (message->body_length) {
        result.body = (unsigned char *)reply.body;
        reply.body = NULL;
    }
    yd_disk_reply_free(&reply);
    return result;
}
static bool audit_begin_request(Server *, Request *, bool);
static bool binary_query(const Request *request) {
    return request_query_target(request->method, request->target);
}
static bool binary_write(const Request *request) {
    return strcmp(request->method, "GET") && !request->head_only && !binary_query(request);
}
static YDDiskReply binary_operation_admit(Server *server, Request *request,
    bool header_only, const char *revision) {
    bool write = binary_write(request);
    if (write && !server->write_auth_token)
        return native_document_error_at(server, 405, "writes_disabled", revision);
    int access = disk_access(server, request, write, header_only);
    if (access) {
        if (access == 401) atomic_fetch_add(&server->metrics.authentication_failures, 1);
        return native_document_error_at(server, access, access_error(access), revision);
    }
    if (write && server->cluster && !request->request_id_present)
        return native_document_error_at(server, 400, "request_id_required", revision);
    if (!strncmp(request->target, "/v1/changes/stream?", 19) &&
        (request->if_match_present || request->if_none_match_present))
        return native_document_error_at(server, 405, "unsupported_stream_request", revision);
    if (!header_only && request->content_type_present) {
        bool structured = binary_query(request) || !strcmp(request->method, "PATCH") ||
            !strcmp(request->target, "/v1/transactions");
        bool json = json_content_type(request);
        if (!yaml_content_type(request) && !(structured && json))
            return native_document_error_at(server, 415, "yaml_content_type_required", revision);
        if (json && json_has_raw_yaml_line_break(request->body, request->body_length))
            return native_document_error_at(server, 400, "invalid_json_request", revision);
    }
    return (YDDiskReply){0};
}
static bool binary_admit(void *context, const YDBinaryRequestMessage *message,
    const YDTLSClientIdentity *identity, YDBinaryReply *rejection) {
    Server *server = context;
    /* The binary constructor exposes its listener before final service
     * admission. An audited startup must remain rejected until its anchored
     * completion; readiness cannot turn an already rejected job into data work. */
    if (!atomic_load_explicit(&server->dispatch_ready, memory_order_acquire)) {
        YDDiskReply reply = yd_disk_error_reply(503, "service_starting");
        memcpy(reply.revision, YD_FIELD_RESPONSE_PRIVATE_REVISION, sizeof(reply.revision));
        *rejection = binary_reply(server, message, reply,
            YD_FIELD_RESPONSE_PRIVATE_REVISION, true);
        return false;
    }
    Request request = binary_request(message, NULL, 0);
    request.client_identity = *identity;
    request.access_cached = true;
    /* No disk/controller mutex or filesystem call on the I/O thread. The
     * profile is immutable; error revisions are last-observed advisory data. */
    char revision[17];
    snprintf(revision, sizeof(revision), "%016llx",
        (unsigned long long)atomic_load_explicit(&server->binary_revision, memory_order_relaxed));
    YDDiskReply reply = message->schema == 2
        ? binary_operation_admit(server, &request, true, revision)
        : admit_native_document(server, &request, revision);
    if (!reply.status && message->method == YD_BINARY_METHOD_PUT &&
        message->body_length > server->binary_document_limit)
        reply = native_document_error_at(server, 413, "document_limit", revision);
    if (!reply.status && message->body_length > REQUEST_BODY_LIMIT) {
        int access = disk_access(server, &request, binary_write(&request), true);
        if (access) {
            if (access == 401) atomic_fetch_add(&server->metrics.authentication_failures, 1);
            reply = native_document_error_at(server, access, access_error(access), revision);
        }
    }
    if (!reply.status) return true;
    *rejection = binary_reply(server, message, reply, revision, request_private(server, &request));
    return false;
}
static YDBinaryReply binary_complete_rejection(void *context,
    const YDBinaryRequestMessage *message, const YDTLSClientIdentity *identity,
    YDBinaryReply rejection, unsigned remaining_ms) {
    Server *server = context;
    Request request = binary_request(message, NULL, 0);
    request.client_identity = *identity;
    request.deadline = monotonic_milliseconds() + remaining_ms;
    int cancellation;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancellation)) {
        free(rejection.body);
        return binary_reply(server, message, yd_disk_error_reply(503, "audit_unavailable"), NULL, true);
    }
    /* Repeat immutable credential selection for the event's local actor only.
     * No admission rejection reaches native execution. */
    (void)disk_access(server, &request,
        binary_write(&request), true);
    bool recorded = audit_begin_request(server, &request, true) &&
        audit_finish_request(&request, rejection.message.status);
    if (!recorded) {
        free(rejection.body);
        rejection = binary_reply(server, message, yd_disk_error_reply(503, "audit_unavailable"), NULL, true);
    }
    (void)pthread_setcancelstate(cancellation, NULL);
    return rejection;
}
static bool binary_reserve_upload(void *context, size_t length) {
    if (length <= REQUEST_BODY_LIMIT) return true;
    Server *server = context;
    if (length > YD_LARGE_REQUEST_LIMIT) return false;
    size_t held = atomic_load(&server->large_body_bytes);
    do {
        if (held > YD_LARGE_REQUEST_LIMIT - length) {
            atomic_fetch_add(&server->metrics.overload_rejections, 1);
            return false;
        }
    } while (!atomic_compare_exchange_weak(&server->large_body_bytes, &held, held + length));
    return true;
}
static void binary_release_upload(void *context, size_t length) {
    if (length > REQUEST_BODY_LIMIT) {
        Server *server = context;
        atomic_fetch_sub(&server->large_body_bytes, length);
    }
}
static YDDiskReply cluster_change_page(void *context, const char *target, unsigned timeout_ms);
typedef struct { YDChangeStream *stream; size_t bytes; } BinaryFeed;
static YDBinaryChunk binary_feed_next(void *context, unsigned remaining_ms) {
    BinaryFeed *feed = context;
    YDDiskReply page = {0};
    unsigned wait = 0;
    size_t limit = feed->bytes < YD_BINARY_BODY_LIMIT - 4096
        ? (size_t)YD_BINARY_BODY_LIMIT - 4096 - feed->bytes : 0;
    YDChangePull result = yd_change_stream_pull(feed->stream, remaining_ms, limit, &page, &wait);
    if (result == YD_CHANGE_END) return (YDBinaryChunk){.end = true};
    if (result == YD_CHANGE_WAIT) return (YDBinaryChunk){.wait_ms = wait};
    if (!page.body || !page.length || page.length > YD_BINARY_BODY_LIMIT - feed->bytes - 1) {
        yd_disk_reply_free(&page);
        return (YDBinaryChunk){0};
    }
    size_t length = page.length;
    while (length && (page.body[length-1] == '\n' || page.body[length-1] == '\r')) length--;
    unsigned char *body = realloc(page.body, length + 1);
    if (!body) { yd_disk_reply_free(&page); return (YDBinaryChunk){0}; }
    body[length++] = '\n';
    feed->bytes += length;
    return (YDBinaryChunk){.body = body, .length = length};
}
static void binary_feed_close(void *context) {
    BinaryFeed *feed = context;
    yd_change_stream_free(feed->stream);
    free(feed);
}
static YDBinaryReply binary_feed_open(Server *server, const YDBinaryRequestMessage *message,
    const Request *request, uint64_t deadline) {
    uint64_t at = monotonic_milliseconds();
    if (!at || deadline <= at + 100)
        return binary_reply(server, message, yd_disk_error_reply(504, "request_deadline"), NULL, request_private(server, request));
    unsigned backend_timeout = (unsigned)(deadline - at);
    if (server->cluster && backend_timeout > server->cluster_timeout_ms)
        backend_timeout = server->cluster_timeout_ms;
    YDDiskReply error = {0};
    YDChangeStream *stream = server->cluster
        ? yd_change_stream_open_source(cluster_change_page, server, backend_timeout, request->target, &error)
        : yd_change_stream_open(server->disk, request->target, &error);
    if (!stream) return binary_reply(server, message, error, NULL, request_private(server, request));
    at = monotonic_milliseconds();
    if (!at || deadline <= at + 100) {
        yd_change_stream_free(stream);
        return binary_reply(server, message, yd_disk_error_reply(504, "request_deadline"), NULL, request_private(server, request));
    }
    unsigned remaining_ms = (unsigned)(deadline - at);
    BinaryFeed *feed = calloc(1, sizeof(*feed));
    if (!feed) {
        yd_change_stream_free(stream);
        return binary_reply(server, message, yd_disk_error_reply(503, "allocation_failed"), NULL, request_private(server, request));
    }
    feed->stream = stream;
    /* Initial token/capacity/size failures precede RESPONSE. Future pulls run
     * only after the previous page has left TLS; no whole-stream buffer exists. */
    YDDiskReply first = {0}; unsigned wait = 0;
    (void)yd_change_stream_pull(stream, remaining_ms, YD_BINARY_BODY_LIMIT - 4096, &first, &wait);
    if (first.status != 200) {
        binary_feed_close(feed);
        return binary_reply(server, message, first, NULL, request_private(server, request));
    }
    size_t n = first.length;
    while (n && (first.body[n-1] == '\n' || first.body[n-1] == '\r')) n--;
    unsigned char *body = realloc(first.body, n + 1);
    if (!body) {
        yd_disk_reply_free(&first); binary_feed_close(feed);
        return binary_reply(server, message, yd_disk_error_reply(503, "allocation_failed"), NULL, request_private(server, request));
    }
    body[n++] = '\n'; feed->bytes = n;
    YDBinaryReply reply = {.body = body, .page_length = n,
        .producer = {.context = feed, .next = binary_feed_next, .close = binary_feed_close}};
    reply.message.schema = 2;
    reply.message.streaming = true;
    reply.message.status = 200;
    strcpy(reply.message.content_type, "application/x-ndjson");
    memcpy(reply.message.revision, first.revision, sizeof(reply.message.revision));
    return reply;
}
typedef struct { YDDiskSource *source; size_t offset, length; } BinarySource;
static YDBinaryChunk binary_source_next(void *context, unsigned remaining_ms) {
    BinarySource *source = context;
    if (!remaining_ms || source->offset >= source->length) return (YDBinaryChunk){0};
    size_t n = source->length - source->offset;
    if (n > YD_DISK_SOURCE_CHUNK) n = YD_DISK_SOURCE_CHUNK;
    unsigned char *bytes = malloc(n);
    char error[128];
    if (!bytes || !yd_disk_source_read(source->source, source->offset, bytes, n, error, sizeof(error))) {
        free(bytes); return (YDBinaryChunk){0};
    }
    source->offset += n;
    return (YDBinaryChunk){.body = bytes, .length = n};
}
static void binary_source_close(void *context) {
    BinarySource *source = context;
    yd_disk_source_close(source->source);
    free(source);
}
static YDBinaryReply binary_source_open(Server *server, const YDBinaryRequestMessage *message,
    const Request *request, uint64_t deadline) {
    char target[REQUEST_TARGET_LIMIT + 1], collection[YAMLDB_NAME_LIMIT + 1], *document;
    memcpy(target, request->target, strlen(request->target) + 1);
    if (!parse_database_target(target, collection, &document) || !document)
        return binary_reply(server, message, yd_disk_error_reply(400, "invalid_path"), NULL, request_private(server, request));
    uint64_t now = monotonic_milliseconds();
    if (!now || now >= deadline)
        return binary_reply(server, message, yd_disk_error_reply(504, "request_deadline"), NULL, request_private(server, request));
    unsigned timeout = (unsigned)(deadline - now);
    if (server->cluster && timeout > server->cluster_timeout_ms) timeout = server->cluster_timeout_ms;
    int cancellation;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancellation))
        return binary_reply(server, message, yd_disk_error_reply(503, "document_unavailable"), NULL, request_private(server, request));
    YDRaftView *confirmed = server->cluster ? yd_raft_cluster_view(server->cluster, timeout) : NULL;
    YDDisk *disk = server->cluster ? yd_raft_view_disk(confirmed) : server->disk;
    YDDiskView observed = server->cluster ? yd_raft_view_value(confirmed) : yd_disk_view(disk);
    YDDiskSource *source = NULL;
    char error[128];
    int found = disk ? yd_disk_source_open_at(disk, &observed, collection, document, deadline,
        &source, error, sizeof(error)) : -1;
    yd_raft_view_close(confirmed);
    (void)pthread_setcancelstate(cancellation, NULL);
    if (found != 1) {
        YDDiskReply rejected = yd_disk_error_reply(found ? 503 : 404,
            found ? "document_unavailable" : "document_not_found");
        if (disk) yd_disk_revision(&observed, rejected.revision);
        return binary_reply(server, message, rejected, NULL, request_private(server, request));
    }
    YDDiskSourceInfo info;
    (void)yd_disk_source_info(source, &info);
    YDBinaryReply reply = {0};
    reply.message.schema = message->schema;
    reply.message.status = 200;
    reply.message.representation_length = info.length;
    reply.message.body_length = request->head_only ? 0 : info.length;
    reply.message.present = YD_BINARY_RESPONSE_ETAG | YD_BINARY_RESPONSE_COLLECTION | YD_BINARY_RESPONSE_DOCUMENT;
    strcpy(reply.message.content_type, "application/yaml; charset=utf-8");
    strcpy(reply.message.collection, collection);
    strcpy(reply.message.document, document);
    snprintf(reply.message.etag, sizeof(reply.message.etag), "\"%016llx\"", (unsigned long long)info.hash);
    yd_disk_revision(&info.view, reply.message.revision);
    if (request_private(server, request)) {
        memcpy(reply.message.revision, YD_FIELD_RESPONSE_PRIVATE_REVISION, sizeof(reply.message.revision));
        reply.message.present &= (uint16_t)~YD_BINARY_RESPONSE_ETAG;
        reply.message.etag[0] = 0;
    }
    if (request->head_only) yd_disk_source_close(source);
    else {
        BinarySource *producer = calloc(1, sizeof(*producer));
        if (producer) {
            producer->source = source; producer->length = info.length;
            YDBinaryChunk first = binary_source_next(producer, timeout);
            if (first.body) {
                reply.body = first.body; reply.page_length = first.length;
                reply.producer = (YDBinaryProducer){.context = producer,
                    .next = binary_source_next, .close = binary_source_close};
            } else binary_source_close(producer);
        } else yd_disk_source_close(source);
        if (!reply.body)
            return binary_reply(server, message, yd_disk_error_reply(503, "document_unavailable"), NULL, request_private(server, request));
    }
    record_response(server, reply.message.status, info.length);
    return reply;
}
typedef struct {
    YDBinaryProducer inner;
    YDAuditedOperation *operation;
    unsigned status;
} BinaryAuditedProducer;
static YDBinaryChunk binary_audited_next(void *context, unsigned remaining_ms) {
    BinaryAuditedProducer *owner = context;
    return owner->inner.next(owner->inner.context, remaining_ms);
}
static bool binary_audited_finish(void *context, bool complete) {
    BinaryAuditedProducer *owner = context;
    bool inner_ok = true;
    if (owner->inner.finish) {
        bool (*finish)(void *, bool) = owner->inner.finish;
        owner->inner.finish = NULL;
        inner_ok = finish(owner->inner.context, complete);
    }
    YDAuditedOperation *operation = owner->operation;
    owner->operation = NULL; /* finish consumes caller use on every result */
    /* Match HTTP stream truth: wire completion alone is not native outcome
     * evidence. Interrupted/detached/deadline/shutdown paths are UNKNOWN too. */
    bool audit_ok = !operation || yd_audit_dispatch_finish(operation, YD_AUDIT_UNKNOWN,
        complete ? owner->status : 0, NULL);
    return inner_ok && audit_ok;
}
static void binary_audited_close(void *context) {
    BinaryAuditedProducer *owner = context;
    /* The runtime has already invoked finish on a worker. No IPC/backend
     * work, callbacks or waits are permitted in this I/O-owner destructor. */
    owner->inner.close(owner->inner.context);
    free(owner);
}
static void binary_owned_reply_dispose(YDBinaryReply *reply) {
    free(reply->body);
    if (reply->producer.finish)
        (void)reply->producer.finish(reply->producer.context, false);
    if (reply->producer.close)
        reply->producer.close(reply->producer.context);
    memset(reply, 0, sizeof(*reply));
}
static bool binary_transfer_audit(Request *request, YDBinaryReply *reply) {
    if (!request->audit_operation || !reply->producer.next) return true;
    BinaryAuditedProducer *owner = calloc(1, sizeof(*owner));
    if (!owner) return false;
    owner->inner = reply->producer;
    owner->operation = request->audit_operation;
    owner->status = reply->message.status;
    request->audit_operation = NULL;
    reply->producer = (YDBinaryProducer){.context = owner,
        .next = binary_audited_next, .finish = binary_audited_finish,
        .close = binary_audited_close};
    return true;
}
static YDBinaryReply binary_execute(void *context, const YDBinaryRequestMessage *message,
    const YDTLSClientIdentity *identity, const unsigned char *body, size_t length,
    unsigned remaining_ms) {
    Server *server = context;
    int cancellation;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancellation))
        return binary_reply(server, message, yd_disk_error_reply(503, "audit_unavailable"), NULL, true);
    Request request = binary_request(message, body, length);
    request.client_identity = *identity;
    uint64_t now = monotonic_milliseconds();
    request.deadline = now ? now + remaining_ms : 0;
    YDDiskReply reply = message->schema == 2
        ? binary_operation_admit(server, &request, false, NULL)
        : admit_native_document(server, &request, NULL);
    YDBinaryReply response = {0};
    bool owns_response = false;
    if (!audit_begin_request(server, &request, reply.status != 0)) {
        yd_disk_reply_free(&reply);
        reply = yd_disk_error_reply(503, "audit_unavailable");
    } else if (!reply.status) {
        reply = native_final_admission(server, &request, binary_write(&request));
        now = monotonic_milliseconds();
        if (!reply.status && (!now || !request.deadline || now >= request.deadline)) {
            request.audit_outcome = YD_AUDIT_NOT_DISPATCHED;
            reply = yd_disk_error_reply(504, "request_deadline");
        }
        if (!reply.status) {
            bool source = (message->method == YD_BINARY_METHOD_GET ||
                message->method == YD_BINARY_METHOD_HEAD) &&
                /* Physical checkpoints cannot export encrypted or fenced cluster images.
                 * These owners use the ordinary native read path and its owned reply. */
                !server->encrypted && !server->cluster &&
                native_document_target(&request) && !request_private(server, &request) &&
                !request.if_match_present && !request.if_none_match_present;
            bool feed = message->schema == 2 &&
                !strncmp(request.target, "/v1/changes/stream?", 19);
            if (source || feed) {
                request.audit_outcome = YD_AUDIT_UNKNOWN;
                response = source
                    ? binary_source_open(server, message, &request, request.deadline)
                    : binary_feed_open(server, message, &request, request.deadline);
                owns_response = true;
            } else {
                unsigned budget = (unsigned)(request.deadline - now);
                if (server->cluster && budget > server->cluster_timeout_ms)
                    budget = server->cluster_timeout_ms;
                reply = execute_native_request(server, &request, binary_write(&request), budget);
            }
        }
    }
    if (owns_response && response.producer.next && request.audit_operation) {
        if (binary_transfer_audit(&request, &response)) {
            /* Only heap-owned operation/producer state survives this stack.
             * The transport's terminal worker now owns FINISH. */
            (void)pthread_setcancelstate(cancellation, NULL);
            return response;
        }
        binary_owned_reply_dispose(&response);
        owns_response = false;
        reply = yd_disk_error_reply(503, "audit_unavailable");
    }
    unsigned status = owns_response ? response.message.status : (unsigned)reply.status;
    if (!audit_finish_request(&request, status)) {
        if (owns_response) binary_owned_reply_dispose(&response);
        else yd_disk_reply_free(&reply);
        owns_response = false;
        reply = yd_disk_error_reply(503, "operation_audit_uncertain");
    }
    if (!owns_response)
        response = binary_reply(server, message, reply, NULL, request_private(server, &request));
    (void)pthread_setcancelstate(cancellation, NULL);
    return response;
}
/* The transport owns bytes only. Each page releases its confirmed application
 * view inside query(), before delivery or waiting for another heartbeat. */
static YDDiskReply cluster_change_page(void *context, const char *target, unsigned timeout_ms) {
    Server *server = context;
    return yd_raft_cluster_query(server->cluster, "GET", target, NULL, 0,
                                 NULL, NULL, false, timeout_ms);
}
/* Runtime user and role management (security/access_admin.c). disk_access has
 * already admitted only the write administrative credential over HTTP. The
 * request and response may carry a token; both are wiped before release. */
static void serve_access_admin(Server *server, YDConnection *connection, Request *request) {
    YDDiskReply reply = native_final_admission(server, request, true);
    if (!reply.status && request->body_length &&
        json_has_raw_yaml_line_break(request->body, request->body_length))
        reply = yd_disk_error_reply(400, "invalid_json_request");
    if (!reply.status) {
        YDAccessAdminRequest admin = {.method = request->method, .target = request->target,
            .body = request->body, .length = request->body_length,
            .json = json_content_type(request),
            .request_id = request->request_id_present ? request->request_id : NULL,
            .receipt_epoch_present = request->receipt_epoch_present,
            .receipt_epoch = request->receipt_epoch};
        reply = yd_access_admin_request(server->access_admin, &admin);
    } else reply.outcome = YD_DISK_OUTCOME_NOT_DISPATCHED;
    if (request->body) OPENSSL_cleanse(request->body, request->body_length);
    request->audit_outcome = reply.outcome == YD_DISK_OUTCOME_RETURNED_SUCCESS ?
        YD_AUDIT_RETURNED_SUCCESS : reply.outcome == YD_DISK_OUTCOME_RETURNED_FAILURE ?
        YD_AUDIT_RETURNED_FAILURE : reply.outcome == YD_DISK_OUTCOME_NOT_DISPATCHED ?
        YD_AUDIT_NOT_DISPATCHED : YD_AUDIT_UNKNOWN;
    request->audit_has_receipt = reply.has_receipt;
    if (reply.has_receipt) request->audit_receipt = reply.receipt;
    if (!reply.revision[0]) {
        YDDiskView view = native_view(server);
        yd_disk_revision(&view, reply.revision);
    }
    send_native_reply(server, connection, request, &reply);
    if (reply.body) OPENSSL_cleanse(reply.body, reply.length);
    yd_disk_reply_free(&reply);
}
static void route_disk_request(Server *server, YDConnection *connection, Request *request) {
    /* Private replicated verbs are C-only operations. The HTTP parser accepts
     * extension tokens, so admit public methods before any backend dispatch. */
    if (strcmp(request->method, "GET") && strcmp(request->method, "HEAD") &&
        strcmp(request->method, "POST") && strcmp(request->method, "PUT") &&
        strcmp(request->method, "PATCH") && strcmp(request->method, "DELETE")) {
        send_json_error(server, connection, 405, "method_not_allowed", false);
        return;
    }
    if (native_document_target(request)) {
        YDDiskReply reply = execute_native_document(server, request, server->cluster_timeout_ms);
        send_native_reply(server, connection, request, &reply);
        yd_disk_reply_free(&reply);
        return;
    }
    bool get = !strcmp(request->method, "GET") || request->head_only;
    bool query = request_query_target(request->method, request->target);
    bool write = !get && !query;
    if (get && !strcmp(request->target, "/healthz")) {
        serve_health(server, connection, request->head_only);
        return;
    }
    if (strchr(request->target, '#') || strstr(request->target, "://")) {
        send_request_error(server, connection, request, 400, "invalid_path", request->head_only);
        return;
    }
    if (write && !server->write_auth_token) {
        send_request_error(server, connection, request, 405, "writes_disabled", request->head_only);
        return;
    }
    if (server->cluster && !strncmp(request->target, "/v1/sharding", 12)) {
        if (request->head_only || request->if_match_present || request->if_none_match_present ||
            (!get && !yaml_content_type(request) && !json_content_type(request))) {
            send_json_error(server, connection, 400, "invalid_sharding_request", request->head_only);
            return;
        }
        YDDiskReply reply = yd_shard_service_request(server->shards,
            request->authorization_present ? request->authorization : NULL,
            request->method, request->target, request->body, request->body_length);
        send_response_revision(server, connection, reply.status,
            reply.content_type ? reply.content_type : "application/json; charset=utf-8",
            reply.body, reply.length, reply.headers, false, reply.revision, request_private(server, request));
        yd_disk_reply_free(&reply);
        return;
    }
    int access = disk_access(server, request, write, false);
    if (access) {
        if (access == 401) {
            atomic_fetch_add_explicit(&server->metrics.authentication_failures, 1,
                                      memory_order_relaxed);
        }
        send_request_error(server, connection, request, access, access_error(access), request->head_only);
        return;
    }
    if (server->access_admin && yd_access_admin_target(request->target)) {
        serve_access_admin(server, connection, request);
        return;
    }
    if (get && !strcmp(request->target, "/v1/encryption/status")) {
        YDEnvelopeIdentity identity;
        if (!server->encrypted || !yd_storage_config_identity(server->encrypted, &identity)) {
            send_request_error(server, connection, request, 404, "encrypted_storage_not_configured", request->head_only);
            return;
        }
        static const char hex[] = "0123456789abcdef";
        char store[33] = {0}, object[65] = {0}, body[256];
        for (unsigned i = 0; i < 16; i++) {
            store[2*i] = hex[identity.store_id[i] >> 4]; store[2*i+1] = hex[identity.store_id[i] & 15];
        }
        for (unsigned i = 0; i < 32; i++) {
            object[2*i] = hex[identity.object_id[i] >> 4]; object[2*i+1] = hex[identity.object_id[i] & 15];
        }
        int size = snprintf(body, sizeof(body), "{\"store_id\":\"%s\",\"object_id\":\"%s\","
            "\"generation\":%llu,\"kind\":%u}\n", store, object,
            (unsigned long long)identity.generation, identity.kind);
        if (size < 0 || (size_t)size >= sizeof(body)) {
            send_request_error(server, connection, request, 503, "encryption_status_unavailable", request->head_only);
            return;
        }
        request->audit_outcome = YD_AUDIT_RETURNED_SUCCESS;
        send_response(server, connection, 200, "application/json; charset=utf-8", body,
            (size_t)size, NULL, request->head_only);
        return;
    }
    if (get && !strcmp(request->target, "/readyz")) {
        /* serve_ready retains one quorum-confirmed generation while deriving
         * both its summary and its policy transfer capability. */
        serve_ready(server, connection, request->head_only);
        return;
    }
    if (get && !strcmp(request->target, "/v1/stats")) {
        serve_stats(server, connection, request->head_only);
        return;
    }
    if (!strncmp(request->target, "/v1/storage/", 12)) {
        serve_storage(server, connection, request);
        return;
    }
    if (get && !strcmp(request->target, "/v1/ttl")) {
        /* Expirer diagnostics need the database-wide administrative reader. */
        if (!request_authorized(server, request, false)) {
            send_request_error(server, connection, request, 403, "forbidden", request->head_only);
            return;
        }
        size_t size = 0;
        char *body = yd_ttl_monitor_status(server->ttl, server->ttl_interval_seconds, &size);
        if (!body) {
            send_request_error(server, connection, request, 503, "ttl_status_unavailable", request->head_only);
            return;
        }
        request->audit_outcome = YD_AUDIT_RETURNED_SUCCESS;
        send_response(server, connection, 200, "application/json; charset=utf-8", body, size, NULL,
            request->head_only);
        free(body);
        return;
    }
    if (get && !strcmp(request->target, "/metrics")) {
        serve_metrics(server, connection, request->head_only);
        return;
    }
    if (server->cluster) {
        if (!strcmp(request->target, "/v1/cluster/membership")) {
            if (!request_authorized(server, request, !get)) {
                send_json_error(server, connection, 403, "forbidden", request->head_only);
                return;
            }
            YDRaftMembership membership;
            int outcome = 1;
            if (get) membership = yd_raft_cluster_membership(server->cluster);
            else if (!strcmp(request->method, "POST")) {
                char error[256];
                YDValue *value = yd_parse_request(request->body, request->body_length, error, sizeof(error));
                const YDValue *members = yd_get(value, "voters");
                uint16_t mask = 0;
                bool valid = value && value->type == YD_MAP && value->count == 1 && members &&
                    members->type == YD_ARRAY && members->count >= 3 && members->count <= YD_RAFT_VOTERS;
                for (size_t i = 0; valid && i < members->count; i++) {
                    const YDValue *id = members->items[i];
                    valid = id && id->type == YD_INT && id->number >= 1 && id->number <= YD_RAFT_VOTERS;
                    if (valid) {
                        uint16_t bit = (uint16_t)(1U << (unsigned)id->number);
                        valid = !(mask & bit); mask |= bit;
                    }
                }
                yd_free(value);
                if (!valid) { send_json_error(server, connection, 400, "invalid_membership", false); return; }
                outcome = yd_raft_cluster_reconfigure(server->cluster, mask,
                    server->cluster_timeout_ms, &membership);
            } else { send_json_error(server, connection, 405, "method_not_allowed", false); return; }
            if (outcome != 1) {
                send_json_error(server, connection, outcome < 0 ? 409 : 503,
                    outcome < 0 ? "membership_rejected" : "membership_uncertain", false);
                return;
            }
            char body[256];
            int n = snprintf(body, sizeof(body),
                "{\"old_voters\":%u,\"new_voters\":%u,\"retired_voters\":%u,\"joint\":%s}\n",
                membership.old_voters, membership.new_voters, membership.retired_voters,
                membership.joint ? "true" : "false");
            send_response(server, connection, 200, "application/json; charset=utf-8", body,
                n > 0 ? (size_t)n : 0, NULL, request->head_only);
            return;
        }
        if (!strcmp(request->target, "/v1/cluster/receipt-retention")) {
            serve_receipt_retention(server, connection, request); return;
        }
        if (get && (!strcmp(request->target, "/v1/cluster/leader") ||
                    !strcmp(request->target, "/v1/cluster/status"))) {
            serve_cluster_status(server, connection, request, !strcmp(request->target, "/v1/cluster/status"));
            return;
        }
    }
    if (!strncmp(request->target, "/v1/changes/stream", 18)) {
        unsigned capacity = (unsigned)server->worker_count / 2;
        if (capacity > 8) capacity = 8;
        if (!get || request->head_only || request->if_match_present || request->if_none_match_present) {
            send_request_error(server, connection, request, 405, "unsupported_stream_request", request->head_only); return;
        }
        size_t active = atomic_load(&server->active_streams);
        for (;;) {
            if (active >= capacity) { send_request_error(server, connection, request, 503, "change_stream_capacity", false); return; }
            if (atomic_compare_exchange_weak(&server->active_streams, &active, active + 1)) break;
        }
        YDDiskReply error = {0};
        YDChangeStream *stream = server->cluster
            ? yd_change_stream_open_source(cluster_change_page, server, server->cluster_timeout_ms,
                                            request->target, &error)
            : yd_change_stream_open(server->disk, request->target, &error);
        if (!stream) {
            send_response(server, connection, error.status, "application/json; charset=utf-8", error.body, error.length, NULL, false);
            yd_disk_reply_free(&error);
        } else {
            request->audit_outcome = YD_AUDIT_UNKNOWN;
            size_t bytes = 0;
            (void)yd_change_stream_send(stream, connection, &running, &bytes);
            record_response(server, 200, bytes);
            yd_change_stream_free(stream);
        }
        atomic_fetch_sub(&server->active_streams, 1);
        return;
    }
    bool structured = query || !strcmp(request->method, "PATCH") ||
                      !strcmp(request->target, "/v1/indexes") ||
                      !strcmp(request->target, "/v1/index-builds") ||
                      !strcmp(request->target, "/v1/transactions") ||
                      !strncmp(request->target, "/v1/replication/", 16) ||
                      yd_disk_branch_target(request->target);
    bool json = json_content_type(request);
    if (!get && strcmp(request->method, "DELETE") && !yaml_content_type(request) &&
        !(structured && json)) {
        send_request_error(server, connection, request, 415, "yaml_content_type_required", request->head_only);
        return;
    }
    if (!get && json && json_has_raw_yaml_line_break(request->body, request->body_length)) {
        send_request_error(server, connection, request, 400, "invalid_json_request", request->head_only);
        return;
    }
    if (write && (server->cluster || yd_disk_branch_target(request->target))) {
        if (server->cluster && yd_disk_policy_api_target(request->target) &&
            !(yd_raft_cluster_storage(server->cluster).view.capabilities & YD_DISK_CAP_SCHEMA)) {
            send_request_error(server, connection, request, 405, "schema_policy_cluster_unsupported", false);
            return;
        }
        if (!request->request_id_present) {
            send_request_error(server, connection, request, 400, "request_id_required", false); return;
        }
    }
    YDDiskReply reply = execute_native_request(server, request, write, server->cluster_timeout_ms);
    send_native_reply(server, connection, request, &reply);
    yd_disk_reply_free(&reply);
}

static void route_request(Server *server, YDConnection *connection, Request *request)
{
    if (native_storage(server)) {
        route_disk_request(server, connection, request);
        return;
    }
    if (request->receipt_epoch_present) {
        send_json_error(server, connection, 409, "receipt_retention_disabled", request->head_only); return;
    }
    if (route_document_api(server, connection, request)) return;
    bool write = strcmp(request->method, "PUT") == 0 ||
        strcmp(request->method, "DELETE") == 0 || strcmp(request->method, "PATCH") == 0;
    bool read = strcmp(request->method, "GET") == 0 || request->head_only;
    if (!write && !read) {
        (void)pthread_rwlock_rdlock(&server->snapshot_lock);
        send_json_error(server, connection, 405, "method_not_allowed", false);
        (void)pthread_rwlock_unlock(&server->snapshot_lock);
        return;
    }
    if (read && strcmp(request->target, "/healthz") == 0) {
        (void)pthread_rwlock_rdlock(&server->snapshot_lock);
        serve_health(server, connection, request->head_only);
        (void)pthread_rwlock_unlock(&server->snapshot_lock);
        return;
    }
    if (strchr(request->target, '#') != NULL ||
        strncmp(request->target, "http://", 7) == 0 ||
        strncmp(request->target, "https://", 8) == 0) {
        (void)pthread_rwlock_rdlock(&server->snapshot_lock);
        send_json_error(server, connection, 400, "invalid_path", request->head_only);
        (void)pthread_rwlock_unlock(&server->snapshot_lock);
        return;
    }
    if (write && server->write_auth_token == NULL) {
        (void)pthread_rwlock_rdlock(&server->snapshot_lock);
        send_json_error(server, connection, 405, "writes_disabled", false);
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
        send_json_error(server, connection, 401, "unauthorized", request->head_only);
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
            send_json_error(server, connection, 400, "invalid_path", false);
            (void)pthread_rwlock_unlock(&server->snapshot_lock);
            return;
        }
        bool patch = strcmp(request->method,"PATCH") == 0;
        bool json = json_content_type(request);
        if (strcmp(request->method,"DELETE") != 0 && !yaml_content_type(request) &&
            !(patch && json)) {
            (void)pthread_rwlock_rdlock(&server->snapshot_lock);
            send_json_error(server,connection,415,"yaml_content_type_required",false);
            (void)pthread_rwlock_unlock(&server->snapshot_lock);
            return;
        }
        if (json && json_has_raw_yaml_line_break(request->body,request->body_length)) {
            (void)pthread_rwlock_rdlock(&server->snapshot_lock);
            send_json_error(server,connection,400,"invalid_json_request",false);
            (void)pthread_rwlock_unlock(&server->snapshot_lock);
            return;
        }
        if (strcmp(request->method,"PUT")==0 && request->body_length>YAMLDB_DOCUMENT_LIMIT) {
            (void)pthread_rwlock_rdlock(&server->snapshot_lock);
            send_json_error(server,connection,413,"document_too_large",false);
            (void)pthread_rwlock_unlock(&server->snapshot_lock);
            return;
        }
        (void)pthread_mutex_lock(&server->write_lock);
        YDReply result=yd_engine_document(&server->engine,request->method,collection,document,
            request->body,request->body_length,
            request->if_match_present ? request->if_match : NULL,
            request->if_none_match_present ? request->if_none_match : NULL);
        send_engine_reply(server,connection,&result,false);
        (void)pthread_mutex_unlock(&server->write_lock);
        return;
    }

    (void)pthread_rwlock_rdlock(&server->snapshot_lock);
    if (strcmp(request->target, "/readyz") == 0) {
        serve_ready(server, connection, request->head_only);
        goto read_complete;
    }
    if (strcmp(request->target, "/metrics") == 0) {
        serve_metrics(server, connection, request->head_only);
        goto read_complete;
    }
    if (strcmp(request->target, "/v1/stats") == 0) {
        serve_stats(server, connection, request->head_only);
        goto read_complete;
    }
    if (strcmp(request->target, "/v1/collections") == 0) {
        send_response(
            server,
            connection,
            200,
            "application/json; charset=utf-8",
            server->engine.snapshot->collection_index_body,
            server->engine.snapshot->collection_index_length,
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
            connection,
            database_path ? 400 : 404,
            database_path ? "invalid_path" : "not_found",
            request->head_only
        );
        goto read_complete;
    }
    if (document == NULL) {
        if (query == NULL) {
            serve_collection(server, connection, collection, request->head_only);
        } else {
            size_t limit;
            char after[YAMLDB_NAME_LIMIT + 1];
            const char *after_value;
            if (!parse_page_query(query, &limit, after, &after_value)) {
                send_json_error(
                    server, connection, 400, "invalid_query", request->head_only
                );
            } else {
                serve_collection_page(
                    server,
                    connection,
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
        send_json_error(server, connection, 400, "invalid_query", request->head_only);
        goto read_complete;
    }
    serve_document(
        server, connection, collection, document,
        request->accepts_gzip, request->head_only
    );

read_complete:
    (void)pthread_rwlock_unlock(&server->snapshot_lock);
}

static YDAuditOperation audit_request_kind(const Request *request) {
    bool get = !strcmp(request->method, "GET") || request->head_only;
    char selector[129];
    const char *target = request->target, *underlying = NULL;
    if (yd_disk_history_target(target, selector, &underlying) == 1) target = underlying;
    if (!strncmp(target, "/v1/query/", 10)) return YD_AUDIT_QUERY;
    if (!strncmp(target, "/v1/aggregate/", 14)) return YD_AUDIT_AGGREGATE;
    if (!strncmp(target, "/v1/search/", 11)) return YD_AUDIT_SEARCH;
    if (!strncmp(target, "/v1/vector-search/", 18)) return YD_AUDIT_SEARCH;
    if (!strncmp(target, "/v1/replication/", 16)) return YD_AUDIT_REPLICATION_ADMIN;
    if (!strncmp(target, "/v1/changes/stream", 18)) return YD_AUDIT_STREAM;
    if (!strncmp(target, "/v1/index", 9)) return YD_AUDIT_INDEX_ADMIN;
    /* Storage maintenance shares the existing administrative class so the
     * durable audit operation enumeration is unchanged. */
    if (!strncmp(target, "/v1/storage/", 12)) return YD_AUDIT_INDEX_ADMIN;
    if (!strcmp(target, "/v1/transactions") || branch_transaction_target(target))
        return YD_AUDIT_TRANSACTION;
    return get ? YD_AUDIT_READ_DOCUMENT : YD_AUDIT_WRITE_DOCUMENT;
}

static bool audit_begin_request(Server *server, Request *request, bool rejected) {
    request->audit_outcome = YD_AUDIT_NOT_DISPATCHED;
    if (!server->audit) return true;
    YDAuditEvent event = {.transport = request->http_origin ? YD_AUDIT_HTTP : YD_AUDIT_BINARY,
        .authentication = request->authentication,
        .operation = rejected ? YD_AUDIT_ACCESS_REJECT : audit_request_kind(request)};
    /* Management records name the role or principal, never a credential. */
    if (!rejected && server->access_admin && yd_access_admin_target(request->target))
        event.operation = yd_access_admin_audit(request->method, request->target, event.subject);
    const char *actor = yd_access_principal_name(server->access, request->selected_principal);
    if (actor) memcpy(event.actor, actor, strlen(actor) + 1);
    else if (event.authentication == YD_AUDIT_STATIC ||
        event.authentication == YD_AUDIT_CERTIFICATE || event.authentication == YD_AUDIT_OIDC ||
        event.authentication >= YD_AUDIT_AWS) event.authentication = YD_AUDIT_AUTH_UNKNOWN;
    uint64_t now = monotonic_milliseconds();
    uint64_t deadline = request->deadline ? request->deadline : now + 2000;
    request->audit_operation = yd_audit_dispatch_begin(server->audit, &event, deadline);
    return request->audit_operation != NULL;
}
static void handle_connection(Server *server, int descriptor)
{
    int cancellation;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancellation)) return;
    YDConnection connection;
    if (!yd_connection_init(&connection, descriptor, server->tls, server->io_timeout_ms)) {
        (void)pthread_setcancelstate(cancellation, NULL); return;
    }
    Request request = {0};
    const char *error_code = NULL;
    int status = receive_request(server, &connection, server->io_timeout_ms, &request, &error_code);
    request.http_origin = true;
    if (!status && server->audit) {
        bool get = !strcmp(request.method, "GET") || request.head_only;
        bool query = request_query_target(request.method, request.target);
        status = disk_access(server, &request, !get && !query, false);
        if (status) error_code = access_error(status);
    }
    if (!audit_begin_request(server, &request, status != 0)) {
        status = 503; error_code = "audit_unavailable";
    }
    http_request = &request;
    if (status && native_storage(server))
        send_request_error(server, &connection, &request, status, error_code, request.head_only);
    else if (status) send_json_error(server, &connection, status, error_code, request.head_only);
    else {
        request.audit_outcome = YD_AUDIT_UNKNOWN;
        route_request(server, &connection, &request);
    }
    /* Streaming has already sent its body, but retains the intent until its
     * transport closes. UNKNOWN reports no unsupported success inference. */
    (void)audit_finish_request(&request, 0);
    http_request = NULL;
    free(request.body);
    atomic_fetch_sub(&server->large_body_bytes, request.reserved_bytes);
    yd_connection_close(&connection);
    (void)pthread_setcancelstate(cancellation, NULL);
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

static void usage(const char *program)
{
    fprintf(stderr,
            "Usage: %s --data-dir PATH [--port 0-65535] [--workers 1-64] "
            "[--queue-capacity 1-4096] [--io-timeout-ms 100-30000] "
            "[--bind-address RFC1918_OR_LOOPBACK_IPV4] "
            "[--auth-token-file PATH] [--write-auth-token-file PATH] "
            "[--access-policy-file PATH] [--runtime-access] [--identity-provider-file PATH] "
            "[--binary-port 0-65535] "
            "[--encrypted-storage-file PATH] [--cluster-config-file PATH [--shard-config-file PATH] "
            "[--cluster-backup-to PATH | --cluster-restore-from PATH]] [--audit-socket PATH --audit-helper-uid UID] "
            "[--validate-only] [--replica] [--init-binary | --init-disk [--import-yaml PATH]] "
            "[--cache-bytes N] [--compact-to PATH] [--upgrade-format] "
            "[--auto-compact [--auto-compact-min-bytes N] [--auto-compact-interval-seconds 1-86400]] "
            "[--schema-policies] "
            "[--native-capabilities MASK] [--ttl-interval-seconds 1-86400] "
            "[--activate-schema-to NEWROOT --validate-only] "
            "[--schema-dump-to NEWFILE | --schema-restore-from FILE --validate-only] "
            "[--tls-cert-file PATH --tls-key-file PATH [--tls-client-ca-file PATH "
            "[--tls-crl-file PATH]]]\n",
            program);
    fputs(yd_aggregate_spill_usage(), stderr);
}

typedef struct {
    const char *data_dir;
    const char *bind_address;
    const char *auth_token_path;
    const char *write_auth_token_path;
    const char *access_path;
    const char *identity_path;
    const char *audit_socket;
    const char *encrypted_path;
    uid_t audit_uid;
    YDAuditedOperation **startup;
    YDAccess *access;
    YDAccessIdentity *identity;
    YDAuditDispatcher *audit;
    YDStorageConfig *encrypted;
    const char *cluster_path;
    const char *shard_path, *backup_to, *restore_from;
    YDRaftCluster *cluster;
    YDTLS *peer_tls;
    unsigned cluster_timeout_ms;
    const char *tls_cert, *tls_key, *tls_client_ca, *tls_crl;
    YDTLS *binary_tls;
    int binary_port;
    int port;
    int workers;
    int queue_capacity;
    int io_timeout_ms;
    bool validate_only;
    bool init_binary;
    bool init_disk;
    bool schema_policies;
    uint32_t native_capabilities;
    size_t cache_bytes;
    const char *compact_to;
    const char *activate_schema_to;
    const char *schema_dump_to, *schema_restore_from;
    const char *import_yaml;
    bool replica;
    bool upgrade_format, auto_compact;
    size_t auto_compact_min_bytes;
    int auto_compact_interval_seconds;
    bool runtime_access;
    struct in_addr bind_network_address;
    unsigned ttl_interval_seconds;
} Options;

static int parse_options(int argc, char **argv, Options *options)
{
    const char *data_dir = NULL;
    int spill_argument = 0;
    const char *bind_address = "127.0.0.1";
    const char *auth_token_path = NULL;
    const char *write_auth_token_path = NULL;
    const char *access_path = NULL;
    const char *identity_path = NULL;
    const char *audit_socket = NULL;
    const char *encrypted_path = NULL;
    int audit_uid = -1;
    const char *cluster_path = NULL;
    const char *shard_path = NULL, *backup_to = NULL, *restore_from = NULL;
    int port = DEFAULT_PORT;
    int binary_port = -1;
    int workers = DEFAULT_WORKERS;
    int queue_capacity = DEFAULT_QUEUE_CAPACITY;
    int io_timeout_ms = DEFAULT_IO_TIMEOUT_MS;
    const char *tls_cert = NULL, *tls_key = NULL, *tls_client_ca = NULL, *tls_crl = NULL;
    bool init_binary = false;
    bool init_disk = false;
    bool schema_policies = false;
    size_t native_capabilities = 0;
    size_t cache_bytes = 64U * 1024U * 1024U;
    const char *compact_to = NULL;
    const char *activate_schema_to = NULL;
    const char *schema_dump_to = NULL, *schema_restore_from = NULL;
    const char *import_yaml = NULL;
    bool validate_only = false;
    bool replica = false;
    bool upgrade_format = false, auto_compact = false, compact_tuned = false;
    size_t auto_compact_min_bytes = 64U * 1024U * 1024U;
    int auto_compact_interval_seconds = 60;
    bool runtime_access = false;
    int ttl_interval_seconds = YD_TTL_INTERVAL_DEFAULT;

    for (int index = 1; index < argc; index++) {
        if (strcmp(argv[index], "--data-dir") == 0 && index + 1 < argc) {
            data_dir = argv[++index];
        } else if (strcmp(argv[index], "--ttl-interval-seconds") == 0 && index + 1 < argc) {
            if (!parse_number(argv[++index], 1, YD_TTL_INTERVAL_LIMIT, &ttl_interval_seconds)) {
                usage(argv[0]);
                return 2;
            }
        } else if (strcmp(argv[index], "--bind-address") == 0 &&
                   index + 1 < argc) {
            bind_address = argv[++index];
        } else if (strcmp(argv[index], "--port") == 0 && index + 1 < argc) {
            if (!parse_number(argv[++index], 0, 65535, &port)) {
                usage(argv[0]);
                return 2;
            }
        } else if (strcmp(argv[index], "--binary-port") == 0 && index + 1 < argc) {
            if (!parse_number(argv[++index], 0, 65535, &binary_port)) {
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
        } else if (strcmp(argv[index], "--tls-cert-file") == 0 && index + 1 < argc) {
            tls_cert = argv[++index];
        } else if (strcmp(argv[index], "--access-policy-file") == 0 && index + 1 < argc) {
            access_path = argv[++index];
        } else if (strcmp(argv[index], "--encrypted-storage-file") == 0 && index + 1 < argc) {
            encrypted_path = argv[++index];
        } else if (strcmp(argv[index], "--audit-socket") == 0 && index + 1 < argc) {
            audit_socket = argv[++index];
        } else if (strcmp(argv[index], "--audit-helper-uid") == 0 && index + 1 < argc) {
            if (!parse_number(argv[++index], 1, 2147483647, &audit_uid)) return 2;
        } else if (strcmp(argv[index], "--identity-provider-file") == 0 && index + 1 < argc) {
            identity_path = argv[++index];
        } else if (strcmp(argv[index], "--cluster-config-file") == 0 && index + 1 < argc) {
            cluster_path = argv[++index];
        } else if (strcmp(argv[index], "--tls-key-file") == 0 && index + 1 < argc) {
            tls_key = argv[++index];
        } else if (strcmp(argv[index], "--tls-client-ca-file") == 0 && index + 1 < argc) {
            tls_client_ca = argv[++index];
        } else if (strcmp(argv[index], "--tls-crl-file") == 0 && index + 1 < argc) {
            tls_crl = argv[++index];
        } else if (strcmp(argv[index], "--init-disk") == 0) {
            init_disk = true;
        } else if (strcmp(argv[index], "--schema-policies") == 0) {
            schema_policies = true;
        } else if (strcmp(argv[index], "--native-capabilities") == 0 && index + 1 < argc) {
            if (!parse_size(argv[++index], YD_DISK_CAP_SUPPORTED, &native_capabilities) ||
                !native_capabilities) { usage(argv[0]); return 2; }
        } else if (strcmp(argv[index], "--activate-schema-to") == 0 && index + 1 < argc) {
            activate_schema_to = argv[++index];
        } else if (strcmp(argv[index], "--schema-dump-to") == 0 && index + 1 < argc) {
            schema_dump_to = argv[++index];
        } else if (strcmp(argv[index], "--schema-restore-from") == 0 && index + 1 < argc) {
            schema_restore_from = argv[++index];
        } else if (strcmp(argv[index], "--cache-bytes") == 0 && index + 1 < argc) {
            if (!parse_size(argv[++index], 1024U * 1024U * 1024U, &cache_bytes) ||
                cache_bytes < 32768) {
                usage(argv[0]);
                return 2;
            }
        } else if (strcmp(argv[index], "--compact-to") == 0 && index + 1 < argc) {
            compact_to = argv[++index];
        } else if (strcmp(argv[index], "--upgrade-format") == 0) {
            upgrade_format = true;
        } else if (strcmp(argv[index], "--auto-compact") == 0) {
            auto_compact = true;
        } else if (strcmp(argv[index], "--auto-compact-min-bytes") == 0 && index + 1 < argc) {
            compact_tuned = true;
            if (!parse_size(argv[++index], (size_t)INT64_MAX, &auto_compact_min_bytes) ||
                auto_compact_min_bytes < 65536) {
                usage(argv[0]);
                return 2;
            }
        } else if (strcmp(argv[index], "--auto-compact-interval-seconds") == 0 && index + 1 < argc) {
            compact_tuned = true;
            if (!parse_number(argv[++index], 1, 86400, &auto_compact_interval_seconds)) {
                usage(argv[0]);
                return 2;
            }
        } else if (strcmp(argv[index], "--init-binary") == 0) {
            init_binary = true;
        } else if (strcmp(argv[index], "--import-yaml") == 0 && index + 1 < argc) {
            import_yaml = argv[++index];
        } else if (strcmp(argv[index], "--shard-config-file") == 0 && index + 1 < argc) {
            shard_path = argv[++index];
        } else if (strcmp(argv[index], "--cluster-backup-to") == 0 && index + 1 < argc) {
            backup_to = argv[++index];
        } else if (strcmp(argv[index], "--cluster-restore-from") == 0 && index + 1 < argc) {
            restore_from = argv[++index];
        } else if (strcmp(argv[index], "--replica") == 0) {
            replica = true;
        } else if (strcmp(argv[index], "--runtime-access") == 0) {
            runtime_access = true;
        } else if (strcmp(argv[index], "--validate-only") == 0) {
            validate_only = true;
        } else if ((spill_argument = yd_aggregate_spill_argument(argc, argv, index)) != 0) {
            if (spill_argument < 0) { usage(argv[0]); return 2; }
            index += spill_argument - 1;
        } else {
            usage(argv[0]);
            return 2;
        }
    }
    if ((shard_path && replica) || ((shard_path || backup_to || restore_from) && !cluster_path) ||
        (backup_to && restore_from) || ((backup_to || restore_from) && shard_path) ||
        (import_yaml != NULL && !init_binary && !init_disk) ||
        (schema_policies && (init_binary || cluster_path || native_capabilities)) ||
        (native_capabilities && (init_binary || cluster_path || replica ||
            (native_capabilities & YD_DISK_CAP_CLUSTER))) ||
        ((schema_dump_to || schema_restore_from) && (!validate_only ||
            (schema_dump_to && schema_restore_from) ||
            (!schema_policies && native_capabilities != YD_DISK_CAP_SCHEMA) ||
            init_binary || init_disk || import_yaml || compact_to || activate_schema_to ||
            replica || cluster_path || binary_port >= 0)) ||
        (activate_schema_to && (!validate_only || schema_policies || native_capabilities || init_binary || init_disk ||
            compact_to || import_yaml || replica || cluster_path || binary_port >= 0)) ||
        ((init_binary || init_disk || compact_to) && !validate_only) ||
        (init_binary && init_disk) || (compact_to && (init_binary || init_disk)) ||
        data_dir == NULL || (replica && write_auth_token_path == NULL) ||
        ((tls_cert != NULL) != (tls_key != NULL)) || (tls_client_ca && !tls_cert) ||
        (tls_crl && (!*tls_crl || !tls_client_ca || !tls_cert)) ||
        (access_path && (!auth_token_path || init_binary)) ||
        (encrypted_path && (native_capabilities || schema_dump_to || schema_restore_from || init_binary || init_disk || import_yaml || compact_to ||
            activate_schema_to || schema_policies || cluster_path || !auth_token_path)) ||
        ((audit_socket != NULL) != (audit_uid != -1)) ||
        (audit_socket && (!*audit_socket || audit_socket[0] != '/' || strlen(audit_socket) > 107 ||
            (uid_t)audit_uid == geteuid() || !auth_token_path || validate_only || init_binary ||
            init_disk || compact_to || import_yaml || cluster_path)) ||
        (identity_path && (!access_path || !tls_cert || validate_only || init_binary || cluster_path)) ||
        (binary_port >= 0 && (!tls_cert || validate_only || init_binary || init_disk ||
                              compact_to || import_yaml)) ||
        (cluster_path && (init_binary || init_disk || compact_to || import_yaml ||
                          validate_only || !auth_token_path || !write_auth_token_path || !tls_cert)) ||
        /* Explicit in-place upgrade: offline with --validate-only, or by the
         * writer before it serves. Never combined with other root producers. */
        (upgrade_format && ((!validate_only && !write_auth_token_path) || init_binary || init_disk ||
            import_yaml || compact_to || activate_schema_to || schema_dump_to || schema_restore_from ||
            encrypted_path || cluster_path)) ||
        (compact_tuned && !auto_compact) ||
        (auto_compact && (!write_auth_token_path || validate_only || cluster_path || encrypted_path)) ||
        (runtime_access && (!auth_token_path || !write_auth_token_path || validate_only ||
            replica || shard_path || init_binary))) {
        usage(argv[0]);
        return 2;
    }
    struct in_addr bind_network_address;
    bool loopback_bind = false;
    if (!parse_bind_address(
            bind_address, &bind_network_address, &loopback_bind
        )) {
        fprintf(stderr, "yamora: bind address must be numeric loopback or RFC1918 IPv4\n");
        return 2;
    }
    if (!loopback_bind && auth_token_path == NULL) {
        fprintf(stderr, "yamora: an authentication token is required for LAN binding\n");
        return 1;
    }

    *options = (Options){
        .data_dir = data_dir,
        .tls_cert = tls_cert, .tls_key = tls_key, .tls_client_ca = tls_client_ca, .tls_crl = tls_crl,
        .bind_address = bind_address,
        .auth_token_path = auth_token_path,
        .write_auth_token_path = write_auth_token_path,
        .access_path = access_path,
        .identity_path = identity_path,
        .encrypted_path = encrypted_path,
        .audit_socket = audit_socket, .audit_uid = (uid_t)audit_uid,
        .cluster_path = cluster_path,
        .shard_path = shard_path, .backup_to = backup_to, .restore_from = restore_from,
        .port = port,
        .binary_port = binary_port,
        .workers = workers,
        .queue_capacity = queue_capacity,
        .io_timeout_ms = io_timeout_ms,
        .validate_only = validate_only,
        .init_binary = init_binary,
        .init_disk = init_disk,
        .schema_policies = schema_policies,
        .native_capabilities = (uint32_t)native_capabilities,
        .schema_dump_to = schema_dump_to,
        .schema_restore_from = schema_restore_from,
        .cache_bytes = cache_bytes,
        .compact_to = compact_to,
        .activate_schema_to = activate_schema_to,
        .import_yaml = import_yaml,
        .replica = replica,
        .upgrade_format = upgrade_format,
        .auto_compact = auto_compact,
        .auto_compact_min_bytes = auto_compact_min_bytes,
        .auto_compact_interval_seconds = auto_compact_interval_seconds,
        .runtime_access = runtime_access,
        .bind_network_address = bind_network_address,
        .ttl_interval_seconds = (unsigned)ttl_interval_seconds,
    };
    return 0;
}

static int serve_connections(Server *server, int server_descriptor)
{
    int exit_status = 0;
    while (running && server_descriptor >= 0) {
        if (server->binary_runtime && !yd_binary_runtime_healthy(server->binary_runtime)) {
            fprintf(stderr, "yamora: binary listener failed\n");
            exit_status = 1;
            break;
        }
        if (server->maintenance_threshold) {
            /* This includes aborted reservations, not only selected root.end.
             * Further growth is required after EVERY attempt, so a full live
             * graph or healthy BUSY result cannot spin maintenance forever. */
            uint64_t high = yd_disk_allocation(server->disk).high_water;
            if (high >= server->maintenance_threshold && high > server->maintenance_baseline)
                return 2;
        }
        if (reload_requested) {
            reload_requested = 0;
            char error[256] = {0};
            int cancellation;
            if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancellation)) continue;
            YDAuditEvent event = {.transport = YD_AUDIT_INTERNAL,
                .authentication = YD_AUDIT_LOCAL, .operation = YD_AUDIT_TLS_RELOAD};
            YDAuditedOperation *operation = server->audit ?
                yd_audit_dispatch_begin(server->audit, &event, monotonic_milliseconds() + 2000) : NULL;
            bool valid = !server->audit || operation;
            if (valid) {
                if (server->tls && !yd_tls_reload(server->tls, error, sizeof(error))) {
                    valid = false;
                    fprintf(stderr, "yamora: TLS reload rejected; previous identity retained\n");
                }
                if (server->binary_tls && !yd_tls_reload(server->binary_tls, error, sizeof(error))) {
                    valid = false;
                    fprintf(stderr, "yamora: binary TLS reload rejected; previous identity retained\n");
                }
                if (server->peer_tls && !yd_tls_reload(server->peer_tls, error, sizeof(error))) {
                    valid = false;
                    fprintf(stderr, "yamora: peer TLS reload rejected; previous identity retained\n");
                }
                if (operation && !yd_audit_dispatch_finish(operation, valid ?
                    YD_AUDIT_RETURNED_SUCCESS : YD_AUDIT_RETURNED_FAILURE, 0, NULL)) valid = false;
            }
            if (!valid) fprintf(stderr, "yamora: TLS reload or audit acknowledgement unavailable\n");
            (void)pthread_setcancelstate(cancellation, NULL);
        }
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
            fprintf(stderr, "yamora: listener failed\n");
            exit_status = 1;
            break;
        }
        int descriptor = accept(server_descriptor, NULL, NULL);
        if (descriptor < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (running) {
                fprintf(stderr, "yamora: accept failed\n");
                exit_status = 1;
            }
            break;
        }
        (void)fcntl(descriptor, F_SETFD, FD_CLOEXEC);
        atomic_fetch_add_explicit(&server->metrics.accepted, 1, memory_order_relaxed);
        if (!enqueue_connection(&server->queue, descriptor)) {
            atomic_fetch_add_explicit(
                &server->metrics.overload_rejections,
                1,
                memory_order_relaxed
            );
            if (server->tls) { close(descriptor); continue; }
            YDConnection connection;
            if (!yd_connection_init(&connection, descriptor, NULL, 100)) { close(descriptor); continue; }
            struct timeval overload_timeout = {.tv_sec = 0, .tv_usec = 100000};
            (void)setsockopt(
                descriptor,
                SOL_SOCKET,
                SO_SNDTIMEO,
                &overload_timeout,
                sizeof(overload_timeout)
            );
            (void)pthread_rwlock_rdlock(&server->snapshot_lock);
            send_json_error(server, &connection, 503, "server_busy", false);
            (void)pthread_rwlock_unlock(&server->snapshot_lock);
            yd_connection_close(&connection);
            (void)shutdown(descriptor, SHUT_RDWR);
            close(descriptor);
        }
    }
    return exit_status;
}

static YDDiskReply shard_execute(void *context, const YDRaftWrite *write, unsigned timeout_ms) {
    Server *server = context;
    return yd_raft_cluster_write(server->cluster, write, timeout_ms);
}
static YDRaftView *shard_view(void *context, unsigned timeout_ms) {
    Server *server = context;
    return yd_raft_cluster_view(server->cluster, timeout_ms);
}
static bool shard_authorize(void *context, const char *credential, const char *collection,
    bool write, bool admin) {
    Server *server = context;
    if (!credential || strncmp(credential, "Bearer ", 7) || !collection ||
        !yamldb_valid_name(collection) || strlen(credential) >= sizeof(((Request *)0)->authorization)) return false;
    Request request = {.authorization_present = true, .http_origin = true};
    memcpy(request.authorization, credential, strlen(credential) + 1);
    if (server->write_auth_token && request_authorized(server, &request, true)) return true;
    if (admin) return false;
    snprintf(request.method, sizeof(request.method), "%s", write ? "PUT" : "GET");
    snprintf(request.target, sizeof(request.target), "/v1/collections/%s/documents/shard-auth", collection);
    return disk_access(server, &request, write, false) == 0;
}
typedef struct {
    uint64_t threshold, baseline;
    int http_port, binary_port;
    bool initialized;
    Metrics totals;
    struct timespec started_at;
    struct YDDiskIndexJobs *index_jobs;
} StandaloneMaintenance;

static int run_server_body(const Options *options, YDDisk *disk, YDTLS *tls,
    StandaloneMaintenance *maintenance) {
    const char *data_dir = options->data_dir;
    const char *bind_address = options->bind_address;
    const char *auth_token_path = options->auth_token_path;
    const char *write_auth_token_path = options->write_auth_token_path;
    int port = options->port;
    int workers = options->workers;
    int queue_capacity = options->queue_capacity;
    int io_timeout_ms = options->io_timeout_ms;
    bool validate_only = options->validate_only;
    struct in_addr bind_network_address = options->bind_network_address;
    YamlDBSnapshot *snapshot = calloc(1, sizeof(*snapshot));
    char error[256] = {0};
    if (snapshot == NULL) {
        fprintf(stderr, "yamora: cannot allocate snapshot\n");
        return 1;
    }
    if (options->init_binary) {
        YamlDBSnapshot source = {0};
        int source_lock = -1;
        bool valid = true;
        if (options->import_yaml != NULL) {
            source_lock = open(options->import_yaml, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
            valid = source_lock >= 0 && flock(source_lock, LOCK_SH | LOCK_NB) == 0;
            if (!valid) (void)snprintf(error, sizeof(error), "import source unavailable or has a writer");
            if (valid && yd_binary_present(options->import_yaml, error, sizeof(error)) != 0) {
                valid = false;
                (void)snprintf(error, sizeof(error), "--import-yaml requires a YAML source directory");
            }
            if (valid) valid = yd_journal_recover(options->import_yaml, false, error, sizeof(error)) &&
                yamldb_snapshot_load(options->import_yaml, &source, error, sizeof(error));
        }
        if (valid) valid = yd_binary_initialize(data_dir, &source, error, sizeof(error));
        yamldb_snapshot_free(&source);
        if (source_lock >= 0) close(source_lock);
        if (!valid) { fprintf(stderr, "yamora: %s\n", error); free(snapshot); return 1; }
    }
    if (yd_binary_initializing(data_dir) != 0) {
        fprintf(stderr, "yamora: incomplete binary initialization; preserve destination and import into a new root\n");
        free(snapshot); return 1;
    }
    if (options->cluster) {
        YDDiskView view = yd_raft_cluster_storage(options->cluster).view;
        yd_disk_revision(&view, snapshot->revision);
    } else if (disk) {
        YDDiskView view = yd_disk_view(disk);
        yd_disk_revision(&view, snapshot->revision);
        if (validate_only) {
            bool valid = yd_disk_validate(disk, &view, error, sizeof(error)) &&
                yd_disk_history_validate(disk, &view, NULL, error, sizeof(error));
            if (valid && options->compact_to)
                valid = yd_disk_compact(disk, options->compact_to, options->cache_bytes, error,
                                        sizeof(error));
            if (!valid) {
                fprintf(stderr, "yamora: %s\n", error);
                free(snapshot);
                return 1;
            }
            printf("{\"status\":\"valid\",\"storage\":\"native-disk-v2\",\"revision_scheme\":\"xor-"
                   "fnv-v2\",\"revision\":\"%s\",\"collections\":%llu,\"documents\":%llu,\"bytes\":"
                   "%llu,\"compressed_bytes\":0}\n",
                   snapshot->revision, (unsigned long long)view.collections,
                   (unsigned long long)view.documents, (unsigned long long)view.bytes);
            free(snapshot);
            return 0;
        }
    } else if (!yd_journal_recover(data_dir, write_auth_token_path != NULL, error, sizeof(error)) ||
               !yamldb_snapshot_load(data_dir, snapshot, error, sizeof(error))) {
        fprintf(stderr, "yamora: %s\n", error);
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
        auth_token = yd_access_read_token(
            auth_token_path,
            &auth_token_length,
            error,
            sizeof(error)
        );
        if (auth_token == NULL) {
            fprintf(stderr, "yamora: %s\n", error);
            yamldb_snapshot_free(snapshot);
            free(snapshot);
            return 1;
        }
    }

    size_t write_auth_token_length = 0;
    char *write_auth_token = NULL;
    if (write_auth_token_path != NULL) {
        write_auth_token = yd_access_read_token(
            write_auth_token_path,
            &write_auth_token_length,
            error,
            sizeof(error)
        );
        if (write_auth_token == NULL) {
            fprintf(stderr, "yamora: %s\n", error);
            if (auth_token != NULL) {
                memset(auth_token, 0, auth_token_length);
            }
            free(auth_token);
            yamldb_snapshot_free(snapshot);
            free(snapshot);
            return 1;
        }
        if (auth_token != NULL && yd_access_secure_equal(
                auth_token,
                auth_token_length,
                write_auth_token,
                write_auth_token_length
            )) {
            fprintf(stderr, "yamora: read and write tokens must differ\n");
            memset(write_auth_token, 0, write_auth_token_length);
            free(write_auth_token);
            memset(auth_token, 0, auth_token_length);
            free(auth_token);
            yamldb_snapshot_free(snapshot);
            free(snapshot);
            return 1;
        }
    }

    if (yd_access_conflicts(options->access, auth_token, auth_token_length) ||
        yd_access_conflicts(options->access, write_auth_token, write_auth_token_length)) {
        fprintf(stderr, "yamora: access principal and administrative tokens must differ\n");
        if (auth_token) memset(auth_token, 0, auth_token_length);
        if (write_auth_token) memset(write_auth_token, 0, write_auth_token_length);
        free(auth_token); free(write_auth_token); free(snapshot); return 1;
    }
    Server server;
    memset(&server, 0, sizeof(server));
    server.tls = tls;
    server.access = options->access;
    server.identity = options->identity;
    server.audit = options->audit;
    server.encrypted = options->encrypted;
    server.cluster = options->cluster;
    server.peer_tls = options->peer_tls;
    server.binary_tls = options->binary_tls;
    server.cluster_timeout_ms = options->cluster_timeout_ms;
    server.ttl_interval_seconds = options->ttl_interval_seconds;
    server.engine.snapshot = snapshot;
    server.disk = disk;
    if (maintenance) {
        server.maintenance_threshold = maintenance->threshold;
        server.maintenance_baseline = maintenance->baseline;
    }
    server.data_dir = data_dir;
    server.auth_token = auth_token;
    server.auth_token_length = auth_token_length;
    server.write_auth_token = write_auth_token;
    server.write_auth_token_length = write_auth_token_length;
    server.io_timeout_ms = io_timeout_ms;
    server.worker_count = workers;
    atomic_init(&server.binary_revision, 0);
    atomic_init(&server.dispatch_ready, !options->startup || !*options->startup);
    if (server.binary_tls) {
        /* Initialize before any listener/thread can invoke binary admission. */
        YDDiskView view = native_view(&server);
        server.binary_document_limit = YD_DISK_DOCUMENT_LIMIT(view.format);
        atomic_store_explicit(&server.binary_revision, view.revision, memory_order_relaxed);
    }
    if (maintenance && maintenance->initialized) {
        copy_metrics(&server.metrics, &maintenance->totals);
        server.started_at = maintenance->started_at;
    } else (void)clock_gettime(CLOCK_MONOTONIC, &server.started_at);
    if (pthread_rwlock_init(&server.snapshot_lock, NULL) != 0) {
        fprintf(stderr, "yamora: cannot initialize database locks\n");
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
        fprintf(stderr, "yamora: cannot initialize database locks\n");
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
    bool backend_failed = (!disk && !options->cluster && !yd_engine_init(&server.engine, snapshot, data_dir, options->replica,
                                  &server.snapshot_lock, error, sizeof(error))) ||
        (disk && !yd_disk_api_init(&server.disk_api, disk, options->replica));
    if (!backend_failed && disk && maintenance && maintenance->index_jobs) {
        int cancellation;
        bool disabled = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancellation) == 0;
        bool rebound = disabled && yd_disk_index_jobs_rebind(maintenance->index_jobs, disk,
            error, sizeof(error));
        if (rebound) {
            yd_disk_index_jobs_free(server.disk_api.index_jobs);
            server.disk_api.index_jobs = maintenance->index_jobs;
            maintenance->index_jobs = NULL;
        } else { yd_disk_api_destroy(&server.disk_api); backend_failed = true; }
        if (disabled) (void)pthread_setcancelstate(cancellation, NULL);
    }
    if (backend_failed) {
        fprintf(stderr,"yamora: %s\n",error);
        (void)pthread_mutex_destroy(&server.write_lock);
        (void)pthread_rwlock_destroy(&server.snapshot_lock);
        if (write_auth_token != NULL) memset(write_auth_token,0,write_auth_token_length);
        if (auth_token != NULL) memset(auth_token,0,auth_token_length);
        free(write_auth_token);free(auth_token);yamldb_snapshot_free(snapshot);free(snapshot);
        return 1;
    }
    server.engine.replica = options->replica;
    if (!initialize_queue(&server.queue, (size_t)queue_capacity)) {
        fprintf(stderr, "yamora: cannot allocate work queue\n");
        if (disk)
            yd_disk_api_destroy(&server.disk_api);
        else if (!options->cluster)
            yd_engine_destroy(&server.engine);
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
        fprintf(stderr, "yamora: cannot allocate worker threads\n");
        if (disk)
            yd_disk_api_destroy(&server.disk_api);
        else if (!options->cluster)
            yd_engine_destroy(&server.engine);
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
            fprintf(stderr, "yamora: cannot start worker threads\n");
            break;
        }
    }
    if (started_workers != workers) {
        yd_disk_stop_waiters(server.disk);
        stop_queue(&server.queue);
        for (int index = 0; index < started_workers; index++) {
            (void)pthread_join(worker_threads[index], NULL);
        }
        free(worker_threads);
        if (disk)
            yd_disk_api_destroy(&server.disk_api);
        else if (!options->cluster)
            yd_engine_destroy(&server.engine);
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
    /* Online compaction belongs to the private standalone writer. A failure
     * to start leaves serving intact; the operator surface reports it. */
    if (disk && !options->cluster && !options->replica && write_auth_token && yd_disk_writable(disk)) {
        YDCompactPolicy policy = yd_compact_policy_defaults();
        policy.automatic = options->auto_compact;
        if (options->auto_compact) {
            policy.min_bytes = options->auto_compact_min_bytes;
            policy.interval_ms = (unsigned)options->auto_compact_interval_seconds * 1000U;
        }
        server.compactor = yd_compactor_new(disk, data_dir, &policy, error, sizeof(error));
        if (!server.compactor)
            fprintf(stderr, "yamora: online compaction unavailable: %s\n", error);
        else if (options->auto_compact && !yd_compactor_supported(server.compactor))
            fprintf(stderr, "yamora: automatic compaction needs a private format 5, 7 or 8 store\n");
    }

    int exit_status = 0;
    int server_descriptor = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (server_descriptor < 0) {
        fprintf(stderr, "yamora: cannot create socket\n");
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
        fprintf(stderr, "yamora: cannot bind %s port %d\n", bind_address, port);
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
        fprintf(stderr, "yamora: cannot resolve listening port\n");
        close(server_descriptor);
        server_descriptor = -1;
        running = 0;
        exit_status = 1;
    }
    /* Before any connection is accepted: load, validate and publish the stored
     * runtime access state, then keep the cached snapshot fresh. */
    if (server_descriptor >= 0 && yd_access_runtime_enabled(server.access)) {
        YDAccessAdminConfig admin = {.access = server.access, .disk = disk,
            .cluster = options->cluster, .replica = options->replica,
            .read_token = auth_token, .read_length = auth_token_length,
            .write_token = write_auth_token, .write_length = write_auth_token_length,
            .timeout_ms = server.cluster_timeout_ms};
        server.access_admin = yd_access_admin_open(&admin, error, sizeof(error));
        if (!server.access_admin || !yd_access_admin_start(server.access_admin)) {
            fprintf(stderr, "yamora: runtime access startup rejected: %s\n",
                server.access_admin ? "refresh worker unavailable" : error);
            close(server_descriptor);
            server_descriptor = -1;
            running = 0;
            exit_status = 1;
        }
    }

    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = stop_server;
    sigemptyset(&action.sa_mask);
    (void)sigaction(SIGINT, &action, NULL);
    (void)sigaction(SIGTERM, &action, NULL);
    action.sa_handler = reload_tls;
    (void)sigaction(SIGHUP, &action, NULL);
    (void)signal(SIGPIPE, SIG_IGN);

    if (server_descriptor >= 0 && options->binary_port >= 0) {
        YDBinaryRuntimeOptions binary_options = {.address = bind_network_address,
            .port = (uint16_t)options->binary_port, .io_timeout_ms = (unsigned)io_timeout_ms,
            .tls = options->binary_tls, .context = &server,
            .reserve_upload = binary_reserve_upload,
            .release_upload = binary_release_upload,
            .complete_rejection = server.audit ? binary_complete_rejection : NULL};
        server.binary_runtime = yd_binary_runtime_start_with_identity(&binary_options,
            binary_admit, binary_execute, error, sizeof(error));
        if (!server.binary_runtime) {
            fprintf(stderr, "yamora: binary listener startup rejected: %s\n", error);
            close(server_descriptor);
            server_descriptor = -1;
            running = 0;
            exit_status = 1;
        }
    }
    if (server_descriptor >= 0 && options->shard_path) {
        YDShardServiceCallbacks callbacks = {.execute = shard_execute, .view = shard_view,
            .context = &server, .authorize = shard_authorize, .auth_context = &server};
        server.shards = yd_shard_service_load(options->shard_path, &callbacks, error, sizeof(error));
        if (!server.shards || !yd_shard_service_start(server.shards)) {
            fprintf(stderr, "yamora: shard listener startup rejected: %s\n", error);
            close(server_descriptor); server_descriptor = -1; running = 0; exit_status = 1;
        }
    }
    /* All listener/worker constructors completed; final audited admission follows. */
    if (server_descriptor >= 0 && options->startup && *options->startup) {
        YDAuditedOperation *startup = *options->startup; *options->startup = NULL;
        if (!yd_audit_dispatch_finish(startup, YD_AUDIT_RETURNED_SUCCESS, 0, NULL)) {
            fprintf(stderr, "yamora: startup audit completion unavailable\n");
            close(server_descriptor);
            server_descriptor = -1;
            running = 0;
            exit_status = 1;
        }
    }
    /* Only a serving writer expires documents: a replica-set member (while it
     * leads) or a writable, non-replica standalone root. Read-only roots,
     * followers of incremental replication and the YAML engine never do. */
    if (server_descriptor >= 0 && !options->replica &&
        (server.cluster || (server.disk && server.write_auth_token && yd_disk_writable(server.disk)))) {
        YDTTLConfig ttl = {.api = server.cluster ? NULL : &server.disk_api,
            .audit = server.cluster ? NULL : server.audit, .cluster = server.cluster,
            .interval_seconds = server.ttl_interval_seconds, .timeout_ms = server.cluster_timeout_ms};
        server.ttl = yd_ttl_monitor_start(&ttl);
        if (!server.ttl) {
            fprintf(stderr, "yamora: TTL expirer startup failed\n");
            close(server_descriptor);
            server_descriptor = -1;
            running = 0;
            exit_status = 1;
        }
    }
    if (server_descriptor >= 0) {
        atomic_store_explicit(&server.dispatch_ready, true, memory_order_release);
        if (maintenance) {
            maintenance->http_port = (int)ntohs(address.sin_port);
            maintenance->binary_port = server.binary_runtime ?
                (int)yd_binary_runtime_port(server.binary_runtime) : -1;
        }
        listening_descriptor = server_descriptor;
        printf(
            "yamora listening on %s:%u revision=%s workers=%d "
            "queue=%d auth=%s writes=%s\n",
            bind_address,
            (unsigned int)ntohs(address.sin_port),
            server.engine.snapshot->revision,
            workers,
            queue_capacity,
            auth_token == NULL ? "off" : "on",
            write_auth_token == NULL ? "off" : "on"
        );
        if (server.binary_runtime)
            printf("binary listening on %s:%u\n", bind_address,
                (unsigned)yd_binary_runtime_port(server.binary_runtime));
        fflush(stdout);
    }
    if (exit_status == 0) {
        exit_status = serve_connections(&server, server_descriptor);
    }
    yd_ttl_monitor_stop(server.ttl);
    if (server_descriptor >= 0 && listening_descriptor == server_descriptor) {
        listening_descriptor = -1;
        close(server_descriptor);
    }
    yd_binary_runtime_close(server.binary_runtime);
    yd_disk_stop_waiters(server.disk);
    stop_queue(&server.queue);
    for (int index = 0; index < workers; index++) {
        (void)pthread_join(worker_threads[index], NULL);
    }
    /* No request can reach the compactor now; it cancels any run, joins and
     * retires superseded files before the disk API or a rollover handoff. */
    yd_compactor_free(server.compactor);
    server.compactor = NULL;
    yd_ttl_monitor_free(server.ttl);
    server.ttl = NULL;
    /* HTTP callers retain the service until they join; service peer callers
     * retain Server/backend state until its own shutdown completes. */
    yd_shard_service_free(server.shards);
    /* Every request worker has joined; the registry stays with the policy. */
    yd_access_admin_close(server.access_admin);
    server.access_admin = NULL;
    if (maintenance) {
        copy_metrics(&maintenance->totals, &server.metrics);
        maintenance->started_at = server.started_at;
        maintenance->initialized = true;
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
    int handoff_cancellation_state = 0;
    bool handoff_disabled = false;
    if (disk && maintenance && exit_status == 2) {
        handoff_disabled = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,
            &handoff_cancellation_state) == 0;
        if (handoff_disabled && yd_disk_index_jobs_quiesce(server.disk_api.index_jobs,
                error, sizeof(error))) {
            maintenance->index_jobs = server.disk_api.index_jobs;
            server.disk_api.index_jobs = NULL;
        } else {
            fprintf(stderr, "yamora: index maintenance handoff failed: %s\n", error);
            exit_status = 1;
        }
    }
    if (disk)
        yd_disk_api_destroy(&server.disk_api);
    else if (!options->cluster)
        yd_engine_destroy(&server.engine);
    yamldb_snapshot_free(server.engine.snapshot);
    free(server.engine.snapshot);
    if (handoff_disabled) (void)pthread_setcancelstate(handoff_cancellation_state, NULL);
    return exit_status;
}

static int run_server_opened(const Options *options, YDDisk **current, YDTLS *tls,
    uint64_t extent_limit) {
    /* A cluster holds its directory lock before either engine is opened.
     * Standalone initialization has its own lock and must finish before this
     * serving lock is acquired; flock does not recurse on independent opens. */
    if (options->cluster) return run_server_body(options, NULL, tls, NULL);
    int fd = open(options->data_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    int mode = options->write_auth_token_path || options->init_binary ? LOCK_EX : LOCK_SH;
    if (fd < 0 || flock(fd, mode | LOCK_NB)) {
        if (fd >= 0) close(fd);
        fprintf(stderr, "yamora: data directory is unavailable or already has a writer\n"); return 1;
    }
    YDDisk *disk = current ? *current : NULL;
    YDDiskView view = disk ? yd_disk_view(disk) : (YDDiskView){0};
    bool eligible = disk && options->write_auth_token_path && !options->validate_only &&
        (view.format == 5 || view.format == 7) && extent_limit;
    uint64_t threshold = extent_limit / 3;
    if (threshold < 65536) threshold = 65536;
    uint64_t window = threshold / 4;
    if (window < 65536) window = 65536;
    Options serving = *options;
    StandaloneMaintenance maintenance = {.threshold = eligible ? threshold : 0,
        .baseline = disk ? yd_disk_allocation(disk).high_water : 0};
    int result;
    for (;;) {
        result = run_server_body(&serving, disk, tls, eligible ? &maintenance : NULL);
        if (result != 2 || !running) break;
        /* Every request, upload, raw view, waiter and index-job worker joined
         * before body returned. Keep this same EX root fd throughout adoption.
         * Failed stages remain excluded and are reported as a serving failure. */
        int cancellation;
        char error[512] = {0};
        if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancellation)) {
            result = 1; break;
        }
        YDDiskRolloverInfo info;
        int rolled = yd_disk_rollover(&disk, fd, options->cache_bytes, &info,
            error, sizeof(error));
        *current = disk;
        if (rolled == 0 && !yd_disk_resume_waiters(disk, error, sizeof(error))) rolled = -1;
        if (rolled < 0) {
            fprintf(stderr, "yamora: standalone maintenance failed: %s; preserve stage %s\n",
                *error ? error : "native owner unavailable", *info.stage ? info.stage : "(none)");
            result = 1;
        } else {
            uint64_t high = yd_disk_allocation(disk).high_water;
            uint64_t saved = rolled == 1 && info.old_extent.high_water > info.new_extent.high_water ?
                info.old_extent.high_water - info.new_extent.high_water : 0;
            /* Low-yield copies and BUSY results need progressively more new
             * growth before another attempt. Finite native admission remains
             * authoritative when exact retained feed history cannot fit. */
            if (saved < window && window < extent_limit)
                window = window > extent_limit / 2 ? extent_limit : 2 * window;
            else if (saved >= window) {
                window = threshold / 4;
                if (window < 65536) window = 65536;
            }
            maintenance.baseline = high;
            maintenance.threshold = high > UINT64_MAX - window ? UINT64_MAX : high + window;
            if (maintenance.threshold < threshold) maintenance.threshold = threshold;
            serving.port = maintenance.http_port;
            serving.binary_port = maintenance.binary_port;
            serving.init_binary = false;
            fprintf(stderr, "yamora: standalone maintenance %s saved=%llu high_water=%llu\n",
                rolled == 1 ? "retired" : "busy", (unsigned long long)saved,
                (unsigned long long)high);
            result = 0;
        }
        (void)pthread_setcancelstate(cancellation, NULL);
        if (result || !running) break;
    }
    yd_disk_index_jobs_free(maintenance.index_jobs);
    close(fd); return result == 2 ? 0 : result;
}
static int run_cluster(const Options *options, YDTLS *tls, int document_directory) {
    char error[512] = {0};
    YDRaftSettings *settings = yd_raft_settings_load(options->cluster_path, error, sizeof(error));
    if (!settings) { fprintf(stderr, "yamora: %s\n", error); return 1; }
    /* Reject bad admin credentials before creating cluster storage. The server
     * loads its own lifetime-owned buffers after startup. */
    size_t rn = 0, wn = 0;
    char *read = yd_access_read_token(options->auth_token_path, &rn, error, sizeof(error));
    char *write = yd_access_read_token(options->write_auth_token_path, &wn, error, sizeof(error));
    bool valid = read && write && !yd_access_secure_equal(read, rn, write, wn) &&
        !yd_access_conflicts(options->access, read, rn) && !yd_access_conflicts(options->access, write, wn);
    if (read) memset(read, 0, rn);
    if (write) memset(write, 0, wn);
    free(read); free(write);
    YDTLSOptions peer_options = {.crl_file = settings->crl_file};
    YDTLS *peer = valid ? yd_tls_peer_new_with_options(settings->certificate, settings->key,
                          settings->ca, &peer_options, error, sizeof(error)) : NULL;
    int listener = peer ? yd_raft_runtime_listen(&settings->raft, error, sizeof(error)) : -1;
    YDRaftCluster *cluster = listener >= 0 ? yd_raft_cluster_start_at(&settings->raft, document_directory,
        options->cache_bytes, peer, listener, error, sizeof(error)) : NULL;
    if (cluster && settings->checkpoints.entries &&
        !yd_raft_cluster_checkpoints(cluster, settings->checkpoints)) {
        yd_raft_cluster_close(cluster);
        cluster = NULL;
        snprintf(error, sizeof(error), "checkpoint worker unavailable");
    }
    if (cluster && settings->compaction.minimum_bytes &&
        !yd_raft_cluster_compactions(cluster, settings->compaction)) {
        yd_raft_cluster_close(cluster);
        cluster = NULL;
        snprintf(error, sizeof(error), "compaction worker unavailable");
    }
    if (cluster && settings->application_compaction.operation.minimum_source_bytes &&
        !yd_raft_cluster_application_compactions(cluster, settings->application_compaction)) {
        yd_raft_cluster_close(cluster);
        cluster = NULL;
        snprintf(error, sizeof(error), "application compaction worker unavailable");
    }
    int result = 1;
    if (cluster) {
        Options configured = *options;
        configured.cluster = cluster; configured.peer_tls = peer;
        configured.cluster_timeout_ms = settings->request_timeout_ms;
        if (options->backup_to) {
            YDRaftBackup *backup = NULL;
            uint64_t deadline = monotonic_milliseconds() + 30000;
            while (!backup) {
                uint64_t now = monotonic_milliseconds();
                if (!now || now >= deadline) break;
                unsigned remaining = (unsigned)(deadline - now);
                backup = yd_raft_cluster_backup(cluster, remaining < 1000 ? remaining : 1000,
                    error, sizeof(error));
                if (!backup) {
                    struct timespec pause = {.tv_nsec = 100000000};
                    nanosleep(&pause, NULL);
                }
            }
            if (!backup && !*error)
                snprintf(error, sizeof(error), "fresh leader quorum unavailable before backup deadline");
            result = backup && yd_raft_backup_write(backup, options->backup_to, NULL, NULL,
                error, sizeof(error)) ? 0 : 1;
            yd_raft_backup_close(backup);
            if (result) fprintf(stderr, "yamora: cluster backup rejected: %s\n", error);
        } else result = run_server_opened(&configured, NULL, tls, 0);
        yd_raft_cluster_close(cluster);
    } else fprintf(stderr, "yamora: replica-set startup rejected: %s\n", *error ? error : "invalid roots or credentials");
    if (listener >= 0) close(listener);
    yd_tls_free(peer); yd_raft_settings_free(settings);
    return result;
}
/* Offline conversion has independent physical and logical work pools. The
 * physical pool also pays for every structural graph step; neither pool is
 * refilled between validation phases. Limits are intentionally finite. */
static bool schema_activation_step(void *context, YDDiskValidationPhase phase) {
    (void)phase;
    uint64_t *remaining = context;
    if (!*remaining) return false;
    --*remaining;
    return true;
}
static YDSchemaBarrierResult schema_activation_validate(void *context, YDDisk *disk,
    const YDDiskView *view, uint64_t *remaining, char *error, size_t length) {
    YDDiskValidation state = {.progress = schema_activation_step, .context = remaining};
    if (!yd_disk_validate_cancellable(disk, view, &state, error, length))
        return state.cancelled ? YD_SCHEMA_BARRIER_LIMIT : YD_SCHEMA_BARRIER_INVALID;
    YDPolicyResult result = yd_policy_validate_view(disk, view, context, error, length);
    return result == YD_POLICY_OK ? YD_SCHEMA_BARRIER_OK :
        result == YD_POLICY_LIMIT ? YD_SCHEMA_BARRIER_LIMIT : YD_SCHEMA_BARRIER_INVALID;
}
static int activate_schema(const Options *options) {
    char error[512] = {0};
    int cancellation = 0;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancellation)) {
        fprintf(stderr, "yamora: schema activation cancellation admission failed\n");
        return 1;
    }
    int source = open(options->data_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    int destination = open(options->activate_schema_to,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    YDSchemaBarrierResult result = YD_SCHEMA_BARRIER_IO;
    YDSchemaBarrierPrepared prepared = {0};
    YDPolicyWork work;
    yd_policy_work_init(&work, true);
    uint64_t remaining = UINT64_C(128) * 1024 * 1024 * 1024;
    if (source >= 0 && destination >= 0)
        result = yd_disk_schema_activate_at(source, destination,
            UINT64_C(16) * 1024 * 1024 * 1024, &remaining,
            schema_activation_validate, &work, &prepared, error, sizeof(error));
    if (destination >= 0 && close(destination)) result = YD_SCHEMA_BARRIER_IO;
    if (source >= 0 && close(source)) result = YD_SCHEMA_BARRIER_IO;
    (void)pthread_setcancelstate(cancellation, NULL);
    if (result != YD_SCHEMA_BARRIER_OK) {
        fprintf(stderr, "yamora: schema activation refused (%u): %s\n", (unsigned)result,
            *error ? error : "source or destination unavailable");
        return 1;
    }
    printf("{\"status\":\"schema-activated\",\"physical_bytes\":%llu}\n",
        (unsigned long long)prepared.physical_bytes);
    return 0;
}
static int schema_recovery_output(const char *path, int source, int *parent) {
    *parent = -1;
    char *copy = path && *path ? strdup(path) : NULL;
    if (!copy) return -1;
    char *name = strrchr(copy, '/');
    const char *directory = ".";
    if (name) {
        *name++ = 0;
        directory = *copy ? copy : "/";
    } else name = copy;
    if (!*name || !strcmp(name, ".") || !strcmp(name, "..")) {
        free(copy); return -1;
    }
    int owner = open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat status, original;
    bool trusted = owner >= 0 && !fstat(owner, &status) && status.st_uid == geteuid() &&
        !(status.st_mode & (S_IWGRP | S_IWOTH)) && source >= 0 && !fstat(source, &original) &&
        (status.st_dev != original.st_dev || status.st_ino != original.st_ino);
    int fd = trusted ? openat(owner, name,
        O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW | O_CLOEXEC, 0600) : -1;
    free(copy);
    if (fd < 0) { if (owner >= 0) close(owner); return -1; }
    *parent = owner;
    return fd;
}
static int schema_recovery(const Options *options, YDStorageBudget *budget) {
    char error[512] = {0};
    int cancellation = 0;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancellation)) return 1;
    bool restoring = options->schema_restore_from != NULL;
    bool valid = false;
    if (restoring) {
        int directory = open(options->data_dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        int input = open(options->schema_restore_from, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
        valid = directory >= 0 && input >= 0 && yd_disk_schema_recovery_restore_budgeted_at(
            directory, input, options->native_capabilities, options->cache_bytes,
            budget, error, sizeof(error));
        if (input >= 0 && close(input)) valid = false;
        if (directory >= 0 && close(directory)) valid = false;
    } else {
        int source = open(options->data_dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        YDDisk *disk = source < 0 ? NULL : options->native_capabilities
            ? yd_disk_open_capabilities_budgeted_at(source, false, false, options->native_capabilities,
                options->cache_bytes, YD_DISK_ALLOCATION_UNLIMITED, budget, error, sizeof(error))
            : yd_disk_open_schema_budgeted_at(source, false, options->cache_bytes,
                YD_DISK_ALLOCATION_UNLIMITED, budget, error, sizeof(error));
        int parent = -1;
        int output = disk ? schema_recovery_output(options->schema_dump_to, source, &parent) : -1;
        uint64_t remaining = UINT64_C(128) * 1024 * 1024 * 1024;
        YDDiskValidation state = {.progress = schema_activation_step, .context = &remaining};
        YDDiskView view = yd_disk_view(disk);
        valid = disk && output >= 0 && yd_disk_schema_logical_export(disk, &view, output,
            &state, error, sizeof(error)) && !fsync(output) && !fsync(parent);
        if (output >= 0 && close(output)) valid = false;
        if (parent >= 0 && close(parent)) valid = false;
        yd_disk_close(disk);
        if (source >= 0 && close(source)) valid = false;
    }
    (void)pthread_setcancelstate(cancellation, NULL);
    if (!valid) {
        fprintf(stderr, "yamora: schema recovery refused: %s; retain any partial output and retry into a new target\n",
            *error ? error : "unavailable or incompatible source/target");
        return 1;
    }
    printf("{\"status\":\"schema-%s\"}\n", restoring ? "restored" : "dumped");
    return 0;
}
static int run_server_budgeted(const Options *options, YDTLS *tls, YDStorageBudget *budget,
    uint64_t extent_limit) {
    char error[512] = {0};
    if (options->encrypted_path) {
        YDStorageConfig *encrypted = yd_storage_config_open(options->encrypted_path,
            options->data_dir, error, sizeof(error));
        if (!encrypted) { fprintf(stderr, "yamora: encrypted storage unavailable\n"); return 1; }
        /* The encrypted owner holds the directory exclusion through the final
         * native pin. A second independent flock would conflict with itself. */
        Options configured = *options; configured.encrypted = encrypted;
        int result = run_server_body(&configured, yd_storage_config_disk(encrypted), tls, NULL);
        yd_storage_config_close(encrypted);
        return result;
    }
    if (options->activate_schema_to) return activate_schema(options);
    if (options->schema_dump_to || options->schema_restore_from) return schema_recovery(options, budget);
    bool initialized = !options->init_disk || (options->native_capabilities ?
        yd_disk_initialize_capabilities_budgeted(options->data_dir, options->import_yaml,
            options->cache_bytes, options->native_capabilities, budget, error, sizeof(error)) : options->schema_policies ?
        yd_disk_initialize_schema_budgeted(options->data_dir, options->import_yaml,
            options->cache_bytes, budget, error, sizeof(error)) :
        yd_disk_initialize_budgeted(options->data_dir, options->import_yaml,
            options->cache_bytes, budget, error, sizeof(error)));
    if (!initialized) {
        fprintf(stderr, "yamora: %s\n", error);
        return 1;
    }
    if (yd_binary_initializing(options->data_dir) != 0) {
        fprintf(stderr, "yamora: incomplete binary initialization; retain destination and import "
                        "into a new root\n");
        return 1;
    }
    int present = yd_disk_present(options->data_dir);
    if (present < 0) {
        fprintf(stderr, "yamora: invalid native disk root\n");
        return 1;
    }
    if (options->binary_port >= 0 && !present) {
        fprintf(stderr, "yamora: binary listener requires native disk storage\n");
        return 1;
    }
    if (options->compact_to && !present) {
        fprintf(stderr, "yamora: --compact-to requires a native disk source\n");
        return 1;
    }
    if ((options->access || options->audit) && !present) {
        fprintf(stderr, "yamora: access policies require native disk storage\n");
        return 1;
    }
    if ((options->schema_policies || options->native_capabilities) && !present) {
        fprintf(stderr, "yamora: selected native capabilities require an explicit native root\n");
        return 1;
    }
    if (options->upgrade_format && !present) {
        fprintf(stderr, "yamora: --upgrade-format requires a native disk root\n");
        return 1;
    }
    /* Before any handle opens: the writer removes crash-leftover online
     * compaction stages (ROOT/.yamora-disk stays authoritative), and an
     * explicit --upgrade-format rewrites an older format in place. */
    if (present && ((options->write_auth_token_path && !options->validate_only) ||
                    options->upgrade_format)) {
        int root = open(options->data_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        int removed = root >= 0 ? yd_disk_compact_recover(root, error, sizeof(error)) : -1;
        if (removed < 0) {
            fprintf(stderr, "yamora: %s\n", root >= 0 ? error : "cannot open native disk root");
            if (root >= 0) close(root);
            return 1;
        }
        if (removed)
            fprintf(stderr, "yamora: removed %d interrupted online compaction stage%s\n",
                removed, removed == 1 ? "" : "s");
        int upgraded = 0;
        YDDiskUpgradeInfo upgrade = {0};
        if (options->upgrade_format)
            upgraded = yd_disk_upgrade_root(root, options->cache_bytes, budget, &upgrade,
                error, sizeof(error));
        close(root);
        if (upgraded < 0) {
            fprintf(stderr, "yamora: %s\n", error);
            return 1;
        }
        if (options->upgrade_format && options->validate_only) {
            printf("{\"status\":\"%s\",\"from\":%u,\"to\":%u,\"generation\":%llu,\"resumed\":%s}\n",
                upgraded ? "upgraded" : "current", (unsigned)upgrade.from, (unsigned)upgrade.to,
                (unsigned long long)upgrade.generation, upgrade.resumed ? "true" : "false");
            return fflush(stdout) ? 1 : 0;
        }
        if (upgraded)
            fprintf(stderr, "yamora: upgraded native format %u to %u in place\n",
                (unsigned)upgrade.from, (unsigned)upgrade.to);
    }
    int cancellation = 0;
    bool protected_open = options->schema_policies || options->native_capabilities;
    if (protected_open && pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancellation)) {
        fprintf(stderr, "yamora: schema opening cancellation admission failed\n");
        return 1;
    }
    YDDisk *disk = !present ? NULL : options->native_capabilities ?
        yd_disk_open_capabilities_budgeted(options->data_dir, options->write_auth_token_path != NULL,
            options->native_capabilities, options->cache_bytes, budget, error, sizeof(error)) : options->schema_policies ?
        yd_disk_open_schema_budgeted(options->data_dir, options->write_auth_token_path != NULL,
            options->cache_bytes, budget, error, sizeof(error)) :
        yd_disk_open_budgeted(options->data_dir, options->write_auth_token_path != NULL,
            options->cache_bytes, budget, error, sizeof(error));
    if (present && !disk) {
        fprintf(stderr, "yamora: %s\n", error);
        if (protected_open) (void)pthread_setcancelstate(cancellation, NULL);
        return 1;
    }
    int status = run_server_opened(options, &disk, tls, extent_limit);
    yd_disk_close(disk);
    if (protected_open) (void)pthread_setcancelstate(cancellation, NULL);
    return status;
}
static int run_server_locked(const Options *options, YDTLS *tls) {
    if (options->activate_schema_to) return activate_schema(options);
    YDStorageLimits limits; char error[512] = {0};
    if (!yd_storage_budget_configure(&limits, error, sizeof(error))) {
        fprintf(stderr, "yamora: %s\n", error); return 1;
    }
    YDStorageBudget *budget = yd_storage_budget_new(limits);
    if (!budget) { fprintf(stderr, "yamora: storage admission unavailable\n"); return 1; }
    int status = run_server_budgeted(options, tls, budget, limits.extent_bytes);
    /* Native serving/initialization handles close first. Escaped descendants
     * retain their own tickets and therefore keep this shared owner alive. */
    yd_storage_budget_close(budget);
    return status;
}
static int run_server(const Options *options, YDTLS *tls) {
    if (!options->cluster_path) return run_server_locked(options, tls);
    if (options->restore_from) {
        char error[512] = {0};
        YDRaftSettings *settings = yd_raft_settings_load(options->cluster_path, error, sizeof(error));
        bool restored = settings && yd_raft_backup_restore(options->restore_from, options->data_dir,
            settings->raft.journal_root, settings->raft.cluster, settings->raft.node,
            settings->raft.voters, options->cache_bytes, NULL, NULL, error, sizeof(error));
        yd_raft_settings_free(settings);
        if (!restored) fprintf(stderr, "yamora: cluster restore rejected: %s\n", error);
        return restored ? 0 : 1;
    }
    /* A cluster lock must outlive both its HTTP and peer workers. */
    int fd = open(options->data_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 || flock(fd, LOCK_EX | LOCK_NB)) {
        if (fd >= 0) close(fd);
        fprintf(stderr, "yamora: data directory is unavailable or already has a writer\n"); return 1;
    }
    int result = run_cluster(options, tls, fd);
    close(fd); return result;
}

int main(int argc, char **argv)
{
    Options options;
    int status = parse_options(argc, argv, &options);
    if (status) return status;
    char error[256] = {0};
    if (!yd_aggregate_spill_start(error, sizeof(error))) {
        fprintf(stderr, "yamora: %s\n", error);
        return 1;
    }
    options.access = options.access_path ? yd_access_load(options.access_path, error, sizeof(error)) : NULL;
    if (options.access_path && !options.access) {
        fprintf(stderr, "yamora: %s\n", error);
        return 1;
    }
    if (options.runtime_access) {
        /* The static file, when present, stays immutable and owns the registry. */
        if (!options.access) options.access = yd_access_new_empty();
        if (!yd_access_runtime_enable(options.access)) {
            fprintf(stderr, "yamora: runtime access unavailable\n");
            yd_access_free(options.access);
            return 1;
        }
    }
    if (yd_access_has_oidc(options.access) && (!options.tls_cert || !options.tls_key)) {
        fprintf(stderr, "yamora: OIDC principals require server TLS\n");
        yd_access_free(options.access);
        return 1;
    }
    if (yd_access_has_certificate_principals(options.access) &&
        (!options.tls_cert || !options.tls_key || !options.tls_client_ca)) {
        fprintf(stderr, "yamora: certificate principals require server TLS and an explicit client CA\n");
        yd_access_free(options.access);
        return 1;
    }
    YDTLSOptions tls_options = {.crl_file = options.tls_crl};
    YDTLS *tls = options.tls_cert && !options.validate_only
        ? yd_tls_new_with_options(options.tls_cert, options.tls_key, options.tls_client_ca,
                                   &tls_options, error, sizeof(error)) : NULL;
    if (options.tls_cert && !options.validate_only && !tls) {
        fprintf(stderr, "yamora: %s\n", error);
        yd_access_free(options.access);
        return 1;
    }
    options.binary_tls = options.binary_port >= 0 ?
        yd_tls_binary_new_with_options(options.tls_cert, options.tls_key, options.tls_client_ca,
            &tls_options, error, sizeof(error)) : NULL;
    if (options.binary_port >= 0 && !options.binary_tls) {
        fprintf(stderr, "yamora: %s\n", error);
        yd_tls_free(tls);
        yd_access_free(options.access);
        return 1;
    }
    options.identity = options.identity_path ? yd_access_identity_load(options.identity_path,
        yd_access_has_oidc(options.access), error, sizeof(error)) : NULL;
    if (options.identity_path && !options.identity) {
        fprintf(stderr, "yamora: identity provider configuration unavailable\n");
        yd_tls_free(options.binary_tls); yd_tls_free(tls); yd_access_free(options.access);
        return 1;
    }
    int cancellation;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancellation)) {
        yd_access_identity_free(options.identity); yd_tls_free(options.binary_tls);
        yd_tls_free(tls); yd_access_free(options.access); return 1;
    }
    options.audit = options.audit_socket ? yd_audit_dispatcher_new(options.audit_socket,
        options.audit_uid, monotonic_milliseconds() + 2000) : NULL;
    YDAuditedOperation *startup = NULL;
    if (options.audit) {
        YDAuditEvent event = {.transport = YD_AUDIT_INTERNAL, .authentication = YD_AUDIT_LOCAL,
            .operation = YD_AUDIT_STARTUP};
        startup = yd_audit_dispatch_begin(options.audit, &event, monotonic_milliseconds() + 2000);
        options.startup = &startup;
    }
    if (options.audit_socket && (!options.audit || !startup)) status = 1;
    else status = run_server(&options, tls);
    if (startup) (void)yd_audit_dispatch_finish(startup, YD_AUDIT_RETURNED_FAILURE, 0, NULL);
    if (options.audit) {
        YDAuditEvent event = {.transport = YD_AUDIT_INTERNAL, .authentication = YD_AUDIT_LOCAL,
            .operation = YD_AUDIT_SHUTDOWN};
        YDAuditedOperation *shutdown = yd_audit_dispatch_begin(options.audit, &event,
            monotonic_milliseconds() + 2000);
        if (!shutdown || !yd_audit_dispatch_finish(shutdown,
            status ? YD_AUDIT_RETURNED_FAILURE : YD_AUDIT_RETURNED_SUCCESS, 0, NULL)) status = 1;
        yd_audit_dispatcher_close(options.audit);
    }

    yd_access_identity_free(options.identity);
    yd_tls_free(options.binary_tls);
    yd_tls_free(tls);
    yd_access_free(options.access);
    (void)pthread_setcancelstate(cancellation, NULL);
    return status;
}
