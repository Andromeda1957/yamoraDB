/* Test-only linker gates around actual native mutations. No daemon endpoint or
 * production environment control is compiled into ordinary builds. A gate is
 * single-use; closing its controller releases it without undoing the operation. */
#define _POSIX_C_SOURCE 200809L
#include "../src/disk_api.h"
#include "../src/consensus/cluster.h"
#include "../src/transport/tls.h"
#include "../src/transport/binary_message.h"
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static atomic_bool used[2];
static _Thread_local bool binary_io_thread;
static _Thread_local bool binary_page_operation;
static atomic_bool page_used;
static void pause_page_read(void);
void yd_binary_test_page_operation(const YDBinaryRequestMessage *request) {
    binary_page_operation = request && request->schema == 2 &&
        request->method == YD_BINARY_METHOD_GET &&
        !strncmp(request->target, "/v1/changes/stream?", 19);
}
YDTLSStep __real_yd_connection_read_step(YDConnection *, void *, size_t, uint64_t, size_t *);
YDTLSStep __wrap_yd_connection_read_step(YDConnection *connection, void *buffer,
    size_t length, uint64_t deadline, size_t *transferred) {
    binary_io_thread = true;
    return __real_yd_connection_read_step(connection, buffer, length, deadline, transferred);
}
static void reject_reactor_metadata(void) {
    if (binary_io_thread) {
        fputs("binary runtime guard: backend metadata on I/O thread\n", stderr);
        _Exit(70);
    }
}
YDRaftClusterStorage __real_yd_raft_cluster_storage(YDRaftCluster *);
YDRaftClusterStorage __wrap_yd_raft_cluster_storage(YDRaftCluster *cluster) {
    reject_reactor_metadata();
    return __real_yd_raft_cluster_storage(cluster);
}
YDDiskView __real_yd_disk_view(YDDisk *);
YDDiskView __wrap_yd_disk_view(YDDisk *disk) {
    reject_reactor_metadata();
    if (binary_page_operation) pause_page_read();
    return __real_yd_disk_view(disk);
}
static uint64_t clock_ms(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return 0;
    return (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
}
static bool transfer(int fd, void *buffer, size_t length, bool writing) {
    uint64_t end = clock_ms() + 15000;
    unsigned char *bytes = buffer;
    while (length) {
        uint64_t now = clock_ms();
        if (!now || now >= end) return false;
        struct pollfd p = {.fd = fd, .events = writing ? POLLOUT : POLLIN};
        int ready = poll(&p, 1, (int)(end - now));
        if (ready < 0 && errno == EINTR) continue;
        if (ready <= 0) return false;
        ssize_t n = writing ? send(fd, bytes, length, MSG_NOSIGNAL | MSG_DONTWAIT) :
            recv(fd, bytes, length, MSG_DONTWAIT);
        if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        if (n <= 0) return false;
        bytes += n;
        length -= (size_t)n;
    }
    return true;
}
static void pause_page_read(void) {
    const char *value = getenv("YAMORA_BINARY_PAGE_GATE_FD");
    if (!value) return;
    char *end = NULL;
    errno = 0;
    long descriptor = strtol(value, &end, 10);
    if (errno || !*value || *end || descriptor < 3 || descriptor > INT_MAX) return;
    struct pollfd poller = {.fd = (int)descriptor, .events = POLLIN};
    if (poll(&poller, 1, 0) != 1 || !(poller.revents & POLLIN)) return;
    bool unused = false;
    if (!atomic_compare_exchange_strong(&page_used, &unused, true)) return;
    unsigned char byte = 0;
    if (transfer((int)descriptor, &byte, 1, false) && byte == 'A') {
        byte = 'B';
        if (transfer((int)descriptor, &byte, 1, true))
            (void)transfer((int)descriptor, &byte, 1, false);
    }
}
static int gate_for(const char *method, const char *target, bool *after) {
    if (strcmp(method, "PUT")) return -1;
    for (unsigned i = 0; i < 2; i++) {
        const char *expected = i ? "/v1/collections/config/documents/blocked1" :
            "/v1/collections/config/documents/blocked0";
        if (strcmp(target, expected)) continue;
        const char *value = getenv(i ? "YAMORA_BINARY_GATE_1_FD" : "YAMORA_BINARY_GATE_0_FD");
        const char *phase = getenv(i ? "YAMORA_BINARY_GATE_1_PHASE" : "YAMORA_BINARY_GATE_0_PHASE");
        if (!value || !phase || (strcmp(phase, "before") && strcmp(phase, "after"))) return -1;
        char *end = NULL;
        errno = 0;
        long descriptor = strtol(value, &end, 10);
        if (errno || !*value || *end || descriptor < 3 || descriptor > INT_MAX) return -1;
        bool expected_unused = false;
        if (!atomic_compare_exchange_strong(&used[i], &expected_unused, true)) return -1;
        *after = !strcmp(phase, "after");
        return (int)descriptor;
    }
    return -1;
}
static void put16(unsigned char *p, unsigned value) {
    p[0] = (unsigned char)(value >> 8); p[1] = (unsigned char)value;
}
static void pause_call(int descriptor, const YDDiskReply *reply) {
    unsigned char header[25] = {0};
    header[0] = reply ? 'C' : 'B';
    size_t body = reply ? reply->length : 0;
    size_t headers = reply ? strnlen(reply->headers, sizeof(reply->headers)) : 0;
    if (body > 4096 || headers >= 512 || (body && !reply->body)) {
        close(descriptor);
        return;
    }
    if (reply) {
        put16(header + 1, (unsigned)reply->status);
        header[3] = (unsigned char)(body >> 24); header[4] = (unsigned char)(body >> 16);
        header[5] = (unsigned char)(body >> 8); header[6] = (unsigned char)body;
        put16(header + 7, (unsigned)headers);
        memcpy(header + 9, reply->revision, 16);
    }
    bool sent = transfer(descriptor, header, sizeof(header), true);
    if (sent && headers) sent = transfer(descriptor, (void *)reply->headers, headers, true);
    if (sent && body) sent = transfer(descriptor, reply->body, body, true);
    unsigned char resume = 0;
    if (sent) (void)transfer(descriptor, &resume, 1, false);
    if (reply) close(descriptor);
}
static void native_completed(int descriptor) {
    unsigned char complete = 'D';
    (void)transfer(descriptor, &complete, 1, true);
    close(descriptor);
}
YDDiskReply __real_yd_disk_api_request(YDDiskAPI *, const char *, const char *,
    const unsigned char *, size_t, const char *, const char *, bool);
YDDiskReply __wrap_yd_disk_api_request(YDDiskAPI *api, const char *method, const char *target,
    const unsigned char *body, size_t length, const char *match, const char *none, bool gzip) {
    bool after = false;
    int fd = gate_for(method, target, &after);
    if (fd >= 0 && !after) pause_call(fd, NULL);
    YDDiskReply reply = __real_yd_disk_api_request(api, method, target, body, length, match, none, gzip);
    if (fd >= 0 && after) pause_call(fd, &reply);
    else if (fd >= 0) native_completed(fd);
    return reply;
}
YDDiskReply __real_yd_raft_cluster_write(YDRaftCluster *, const YDRaftWrite *, unsigned);
YDDiskReply __wrap_yd_raft_cluster_write(YDRaftCluster *cluster, const YDRaftWrite *write,
    unsigned timeout_ms) {
    bool after = false;
    int fd = gate_for(write->method, write->target, &after);
    if (fd >= 0 && !after) pause_call(fd, NULL);
    YDDiskReply reply = __real_yd_raft_cluster_write(cluster, write, timeout_ms);
    if (fd >= 0 && after) pause_call(fd, &reply);
    else if (fd >= 0) native_completed(fd);
    return reply;
}
