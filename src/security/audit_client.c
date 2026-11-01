#define _GNU_SOURCE
#include "audit_client.h"
#include "audit_helper_codec.h"
#include "audit_codec.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <openssl/rand.h>
#include <poll.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
struct YDAuditClient {
    pid_t process;
    int fd;
    pthread_mutex_t mutex;
    unsigned char incarnation[16], owner[16];
    uint64_t request;
    bool healthy;
};
uint64_t yd_audit_clock_ms(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t) || t.tv_sec < 0 || (uint64_t)t.tv_sec > UINT64_MAX / 1000) return 0;
    return (uint64_t)t.tv_sec * 1000 + (uint64_t)t.tv_nsec / 1000000;
}
bool yd_audit_unprivileged_process(uid_t peer) {
    uid_t r, e, s;
    if (!peer || getresuid(&r, &e, &s) || !r || r != e || e != s || e == peer ||
        prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1) return false;
    struct __user_cap_header_struct header = {.version = _LINUX_CAPABILITY_VERSION_3, .pid = 0};
    struct __user_cap_data_struct data[2] = {{0}};
    if (syscall(SYS_capget, &header, data)) return false;
    for (unsigned i = 0; i < 2; i++)
        if (data[i].effective || data[i].permitted || data[i].inheritable) return false;
    return true;
}
static bool wait_fd(int fd, short event, uint64_t deadline) {
    for (;;) {
        uint64_t now = yd_audit_clock_ms();
        if (!now || now >= deadline) return false;
        uint64_t left = deadline - now;
        struct pollfd p = {.fd = fd, .events = event};
        int r = poll(&p, 1, left > 2000 ? 2000 : (int)left);
        if (r < 0 && errno == EINTR) continue;
        return r > 0 && (p.revents & event) != 0;
    }
}
static YDAuditResult native(uint32_t r) {
    switch (r) {
        case YD_AUDIT_ACK: return YD_AUDIT_OK;
        case YD_AUDIT_IPC_REFUSED: return YD_AUDIT_REFUSED;
        case YD_AUDIT_IPC_BUSY: return YD_AUDIT_BUSY;
        case YD_AUDIT_IPC_LIMIT: return YD_AUDIT_LIMIT;
        case YD_AUDIT_IPC_UNCERTAIN: return YD_AUDIT_UNCERTAIN;
        default: return YD_AUDIT_ERROR;
    }
}
static YDAuditResult exchange(YDAuditClient *c, YDAuditPacket *request, uint64_t deadline,
    YDAuditPacket *reply) {
    if (!c->healthy || c->request == UINT64_MAX) return YD_AUDIT_UNCERTAIN;
    uint64_t now = yd_audit_clock_ms();
    if (!now || deadline <= now) return YD_AUDIT_REFUSED;
    if (deadline - now > 2000) deadline = now + 2000;
    request->id = c->request + 1;
    unsigned char bytes[512];
    if (!yd_audit_packet_encode(request, bytes)) return YD_AUDIT_REFUSED;
    c->healthy = false; c->request = request->id;
    ssize_t sent;
    do { sent = send(c->fd, bytes, 512, MSG_DONTWAIT | MSG_NOSIGNAL); }
    while (sent < 0 && errno == EINTR);
    if (sent != 512 || !wait_fd(c->fd, POLLIN, deadline)) return YD_AUDIT_UNCERTAIN;
    struct iovec io = {.iov_base = bytes, .iov_len = 512};
    struct msghdr m = {.msg_iov = &io, .msg_iovlen = 1};
    ssize_t n;
    do { n = recvmsg(c->fd, &m, MSG_DONTWAIT | MSG_CMSG_CLOEXEC); } while (n < 0 && errno == EINTR);
    if (n != 512 || m.msg_flags & (MSG_TRUNC | MSG_CTRUNC) ||
        !yd_audit_packet_decode(bytes, reply) || reply->kind != YD_AUDIT_REPLY ||
        reply->id != request->id || reply->request_kind != request->kind ||
        (request->kind != YD_AUDIT_HELLO && memcmp(reply->incarnation, c->incarnation, 16)))
        return YD_AUDIT_UNCERTAIN;
    now = yd_audit_clock_ms();
    if (!now || now >= deadline) return YD_AUDIT_UNCERTAIN;
    YDAuditResult r = native(reply->result);
    c->healthy = r != YD_AUDIT_UNCERTAIN && r != YD_AUDIT_ERROR;
    if (request->kind == YD_AUDIT_HELLO && r == YD_AUDIT_OK) memcpy(c->incarnation, reply->incarnation, 16);
    return r;
}
static bool constructor_state(void) {
    int prior;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &prior)) return false;
    if (prior == PTHREAD_CANCEL_DISABLE) return true;
    (void)pthread_setcancelstate(prior, NULL);
    return false;
}
static bool lock_until(YDAuditClient *c, uint64_t *deadline) {
    uint64_t now = yd_audit_clock_ms();
    if (!now || *deadline <= now) return false;
    if (*deadline - now > 2000) *deadline = now + 2000;
    struct timespec end = {.tv_sec = (time_t)(*deadline / 1000), .tv_nsec = (long)(*deadline % 1000) * 1000000};
    return pthread_mutex_clocklock(&c->mutex, CLOCK_MONOTONIC, &end) == 0;
}
YDAuditClient *yd_audit_client_open(const char *path, uid_t helper, uint64_t deadline) {
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    if (!path || *path != '/' || strnlen(path, sizeof(address.sun_path)) == sizeof(address.sun_path) ||
        !yd_audit_unprivileged_process(helper) || !constructor_state()) return NULL;
    YDAuditClient *c = calloc(1, sizeof(*c));
    if (!c) return NULL;
    c->process = getpid(); c->fd = -1;
    if (pthread_mutex_init(&c->mutex, NULL)) { free(c); return NULL; }
    if (RAND_bytes(c->owner, 16) != 1 || !yd_audit_nonzero(c->owner, 16)) { yd_audit_client_close(c); return NULL; }
    c->fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    strcpy(address.sun_path, path);
    if (c->fd < 0 || connect(c->fd, (struct sockaddr *)&address, sizeof(address))) {
        yd_audit_client_close(c); return NULL;
    }
    struct ucred peer; socklen_t length = sizeof(peer);
    if (getsockopt(c->fd, SOL_SOCKET, SO_PEERCRED, &peer, &length) || length != sizeof(peer) || peer.uid != helper) {
        yd_audit_client_close(c); return NULL;
    }
    c->healthy = true;
    YDAuditPacket request = {.kind = YD_AUDIT_HELLO}, reply;
    if (exchange(c, &request, deadline, &reply) != YD_AUDIT_OK) { yd_audit_client_close(c); return NULL; }
    return c;
}
YDAuditResult yd_audit_client_begin(YDAuditClient *c, const YDAuditEvent *event,
    uint64_t deadline, YDAuditLease *out) {
    if (out) memset(out, 0, sizeof(*out));
    if (!c || c->process != getpid() || !event || !out) return YD_AUDIT_REFUSED;
    int prior;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &prior)) return YD_AUDIT_ERROR;
    if (!lock_until(c, &deadline)) { (void)pthread_setcancelstate(prior, NULL); return YD_AUDIT_REFUSED; }
    YDAuditPacket request = {.kind = YD_AUDIT_BEGIN, .event = *event}, reply;
    YDAuditResult r = exchange(c, &request, deadline, &reply);
    if (r == YD_AUDIT_OK) {
        memcpy(out->owner, c->owner, 16); memcpy(out->handle, reply.handle, 16); out->sequence = reply.sequence;
    }
    pthread_mutex_unlock(&c->mutex); (void)pthread_setcancelstate(prior, NULL);
    return r;
}
YDAuditResult yd_audit_client_finish(YDAuditClient *c, YDAuditLease *lease,
    const YDAuditCompletion *completion, uint64_t deadline) {
    if (!c || c->process != getpid() || !lease || !completion || !lease->sequence ||
        memcmp(c->owner, lease->owner, 16)) return YD_AUDIT_REFUSED;
    int prior;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &prior)) return YD_AUDIT_ERROR;
    if (!lock_until(c, &deadline)) { (void)pthread_setcancelstate(prior, NULL); return YD_AUDIT_REFUSED; }
    YDAuditPacket request = {.kind = YD_AUDIT_FINISH_REQUEST, .completion = *completion}, reply;
    memcpy(request.handle, lease->handle, 16);
    YDAuditResult r = exchange(c, &request, deadline, &reply);
    if (r == YD_AUDIT_OK || r == YD_AUDIT_UNCERTAIN || r == YD_AUDIT_ERROR) memset(lease, 0, sizeof(*lease));
    pthread_mutex_unlock(&c->mutex); (void)pthread_setcancelstate(prior, NULL);
    return r;
}
void yd_audit_client_close(YDAuditClient *c) {
    if (!c || c->process != getpid()) return;
    int prior;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &prior)) return;
    if (c->fd >= 0) close(c->fd);
    pthread_mutex_destroy(&c->mutex); free(c);
    (void)pthread_setcancelstate(prior, NULL);
}
