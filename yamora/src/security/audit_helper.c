#define _GNU_SOURCE
#include "audit_helper.h"
#include "audit_client.h"
#include "audit_codec.h"
#include "audit_custody.h"
#include "audit_helper_codec.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#define CONNECTIONS 8U
typedef struct { int fd; uint64_t request, activity; bool hello; } Connection;
typedef struct { bool used; unsigned connection; unsigned char handle[16]; YDAuditTicket ticket; } Intent;
typedef struct {
    YDAudit *sink;
    YDAuditAnchor *anchor;
    unsigned char incarnation[16];
    bool poisoned;
    Intent intents[YD_AUDIT_MAX_PENDING];
} Helper;
static volatile sig_atomic_t stopping;
static void stop(int signal_number) { (void)signal_number; stopping = 1; }
static uint32_t ipc_result(YDAuditResult r) {
    switch (r) {
        case YD_AUDIT_OK: return YD_AUDIT_ACK;
        case YD_AUDIT_REFUSED: return YD_AUDIT_IPC_REFUSED;
        case YD_AUDIT_BUSY: return YD_AUDIT_IPC_BUSY;
        case YD_AUDIT_LIMIT: return YD_AUDIT_IPC_LIMIT;
        case YD_AUDIT_UNCERTAIN: return YD_AUDIT_IPC_UNCERTAIN;
        default: return YD_AUDIT_IPC_ERROR;
    }
}
static YDAuditResult anchored(Helper *h, YDAuditResult r, const YDAuditHead *head) {
    if (r == YD_AUDIT_OK && !yd_audit_anchor_publish(h->anchor, head)) r = YD_AUDIT_UNCERTAIN;
    if (r == YD_AUDIT_UNCERTAIN || r == YD_AUDIT_ERROR || r == YD_AUDIT_CORRUPT || r == YD_AUDIT_INCOMPLETE)
        h->poisoned = true;
    return r;
}
static bool send_packet(int fd, const YDAuditPacket *p) {
    unsigned char bytes[512];
    if (!yd_audit_packet_encode(p, bytes)) return false;
    ssize_t n;
    do { n = send(fd, bytes, 512, MSG_DONTWAIT | MSG_NOSIGNAL); } while (n < 0 && errno == EINTR);
    return n == 512;
}
static void disconnect(Helper *h, Connection *c, unsigned index) {
    for (unsigned i = 0; i < YD_AUDIT_MAX_PENDING; i++) {
        Intent *intent = &h->intents[i];
        if (!intent->used || intent->connection != index) continue;
        if (!h->poisoned) {
            YDAuditCompletion completion = {.outcome = YD_AUDIT_UNKNOWN}; YDAuditHead head;
            if (anchored(h, yd_audit_finish(h->sink, &intent->ticket, &completion, &head), &head) != YD_AUDIT_OK)
                h->poisoned = true;
        }
        intent->used = false;
    }
    if (c->fd >= 0) close(c->fd);
    *c = (Connection){.fd = -1};
}
static bool unique_handle(Helper *h, unsigned char out[16]) {
    if (RAND_bytes(out, 16) != 1 || !yd_audit_nonzero(out, 16)) return false;
    for (unsigned i = 0; i < YD_AUDIT_MAX_PENDING; i++)
        if (h->intents[i].used && !memcmp(out, h->intents[i].handle, 16)) return false;
    return true;
}
static void request(Helper *h, Connection *c, unsigned index, const YDAuditPacket *p, YDAuditPacket *reply) {
    *reply = (YDAuditPacket){.kind = YD_AUDIT_REPLY, .id = p->id, .request_kind = p->kind,
        .result = YD_AUDIT_IPC_REFUSED};
    memcpy(reply->incarnation, h->incarnation, 16);
    if (p->kind > YD_AUDIT_FINISH_REQUEST || p->id <= c->request) return;
    c->request = p->id;
    if (h->poisoned) { reply->result = YD_AUDIT_IPC_UNCERTAIN; return; }
    if (p->kind == YD_AUDIT_HELLO) {
        if (!c->hello) { c->hello = true; reply->result = YD_AUDIT_ACK; }
        return;
    }
    if (!c->hello) return;
    YDAuditHead head; YDAuditResult r = YD_AUDIT_REFUSED;
    if (p->kind == YD_AUDIT_BEGIN) {
        unsigned i = 0;
        while (i < YD_AUDIT_MAX_PENDING && h->intents[i].used) i++;
        if (i == YD_AUDIT_MAX_PENDING) { reply->result = YD_AUDIT_IPC_BUSY; return; }
        Intent *intent = &h->intents[i];
        if (!unique_handle(h, intent->handle)) { reply->result = YD_AUDIT_IPC_ERROR; h->poisoned = true; return; }
        r = yd_audit_begin(h->sink, &p->event, &intent->ticket, &head);
        if (r == YD_AUDIT_LIMIT) {
            YDAuditState state;
            if (yd_audit_state(h->sink, &state) == YD_AUDIT_OK && !state.pending) {
                r = anchored(h, yd_audit_rotate(h->sink, &head), &head);
                if (r == YD_AUDIT_OK) r = yd_audit_begin(h->sink, &p->event, &intent->ticket, &head);
            }
        }
        r = anchored(h, r, &head);
        if (r == YD_AUDIT_OK) {
            intent->used = true; intent->connection = index;
            memcpy(reply->handle, intent->handle, 16); reply->sequence = intent->ticket.intent_sequence;
        }
    } else {
        unsigned i = 0;
        while (i < YD_AUDIT_MAX_PENDING && (!h->intents[i].used || h->intents[i].connection != index ||
            memcmp(h->intents[i].handle, p->handle, 16))) i++;
        if (i < YD_AUDIT_MAX_PENDING) {
            Intent *intent = &h->intents[i];
            r = anchored(h, yd_audit_finish(h->sink, &intent->ticket, &p->completion, &head), &head);
            if (r == YD_AUDIT_OK || r == YD_AUDIT_UNCERTAIN) intent->used = false;
        }
    }
    reply->result = ipc_result(r);
}
static int socket_listener(const YDAuditHelperOptions *o, int *directory, char name[NAME_MAX + 1], struct stat *identity) {
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    if (!o->socket || *o->socket != '/' || strnlen(o->socket, sizeof(address.sun_path)) == sizeof(address.sun_path)) return -1;
    char parent[sizeof(address.sun_path)]; strcpy(parent, o->socket);
    char *last = strrchr(parent, '/');
    if (!last || last == parent || !last[1] || !strcmp(last + 1, ".") || !strcmp(last + 1, "..")) return -1;
    strcpy(name, last + 1); *last = 0;
    *directory = yd_audit_socket_directory(parent, o->daemon_uid);
    if (*directory < 0) return -1;
    struct stat old;
    if (!fstatat(*directory, name, &old, AT_SYMLINK_NOFOLLOW)) {
        if (o->create || !S_ISSOCK(old.st_mode) || old.st_uid != geteuid() || old.st_nlink != 1 ||
            (old.st_mode & 07777) != 0666) return -1;
        int probe = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (probe < 0) return -1;
        strcpy(address.sun_path, o->socket);
        int r = connect(probe, (struct sockaddr *)&address, sizeof(address)); int error = errno;
        close(probe);
        if (r == 0 || error != ECONNREFUSED || unlinkat(*directory, name, 0) || fsync(*directory)) return -1;
    } else if (errno != ENOENT) return -1;
    int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    strcpy(address.sun_path, o->socket);
    if (bind(fd, (struct sockaddr *)&address, sizeof(address)) ||
        fchmodat(*directory, name, 0666, 0) || fstatat(*directory, name, identity, AT_SYMLINK_NOFOLLOW) ||
        !S_ISSOCK(identity->st_mode) || identity->st_uid != geteuid() || identity->st_nlink != 1 ||
        fsync(*directory) || listen(fd, CONNECTIONS)) { close(fd); return -1; }
    return fd;
}
int yd_audit_helper_run(const YDAuditHelperOptions *o) {
    if (!o || !yd_audit_unprivileged_process(o->daemon_uid) || !yd_audit_limits_valid(&o->limits) ||
        !yd_audit_nonzero(o->key_id, 16)) return 1;
    int prior;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &prior)) return 1;
    Helper h = {0}; unsigned char key[32];
    int sink_directory = -1, socket_directory = -1, listener = -1;
    char socket_name[NAME_MAX + 1] = {0}; struct stat socket_identity = {0};
    int result = 1;
    struct sigaction action = {.sa_handler = stop}, oldterm, oldint;
    bool signals = false;
    Connection peers[CONNECTIONS];
    for (unsigned i = 0; i < CONNECTIONS; i++) peers[i] = (Connection){.fd = -1};
    if (!yd_audit_protected_key(o->key_file, o->daemon_uid, key)) goto done;
    YDAuditConfig config = {.key = key, .key_length = 32, .limits = o->limits};
    memcpy(config.key_id, o->key_id, 16);
    sink_directory = yd_audit_protected_directory(o->audit_directory, o->daemon_uid);
    YDAuditHead head;
    h.anchor = yd_audit_anchor_open(o->anchor_directory, o->daemon_uid, o->create, &head);
    if (sink_directory < 0 || !h.anchor) goto done;
    YDAuditResult r = o->create ? yd_audit_create_at(sink_directory, &config, &h.sink, &head) :
        yd_audit_recover_at(sink_directory, &config, &head, &h.sink);
    OPENSSL_cleanse(key, 32);
    if (r != YD_AUDIT_OK) goto done;
    if (o->create && !yd_audit_anchor_publish(h.anchor, &head)) goto done;
    if (!o->create) for (;;) {
        bool changed;
        if (yd_audit_recovery_next(h.sink, &changed, &head) != YD_AUDIT_OK) goto done;
        if (!changed) break;
        if (!yd_audit_anchor_publish(h.anchor, &head)) goto done;
    }
    if (RAND_bytes(h.incarnation, 16) != 1 || !yd_audit_nonzero(h.incarnation, 16)) goto done;
    listener = socket_listener(o, &socket_directory, socket_name, &socket_identity);
    if (listener < 0) goto done;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGTERM, &action, &oldterm)) goto done;
    if (sigaction(SIGINT, &action, &oldint)) { (void)sigaction(SIGTERM, &oldterm, NULL); goto done; }
    signals = true; stopping = 0;
    while (!stopping) {
        struct pollfd pollers[CONNECTIONS + 1] = {{.fd = listener, .events = POLLIN}};
        for (unsigned i = 0; i < CONNECTIONS; i++) pollers[i + 1] = (struct pollfd){.fd = peers[i].fd, .events = POLLIN};
        int ready = poll(pollers, CONNECTIONS + 1, 100);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0) { h.poisoned = true; break; }
        if (pollers[0].revents & POLLIN) {
            int fd = accept4(listener, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
            if (fd >= 0) {
                struct ucred peer; socklen_t length = sizeof(peer); unsigned i = 0;
                while (i < CONNECTIONS && peers[i].fd >= 0) i++;
                bool authorized = !getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &length) &&
                    length == sizeof(peer) && peer.uid == o->daemon_uid;
                if (!authorized || i == CONNECTIONS) {
                    unsigned char ignored[512]; (void)recv(fd, ignored, sizeof(ignored), MSG_DONTWAIT | MSG_TRUNC);
                    close(fd);
                } else peers[i] = (Connection){.fd = fd, .activity = yd_audit_clock_ms()};
            }
        }
        for (unsigned i = 0; i < CONNECTIONS; i++) {
            if (peers[i].fd < 0) continue;
            uint64_t now = yd_audit_clock_ms();
            if (!now) { h.poisoned = true; stopping = 1; break; }
            if (!peers[i].hello && now - peers[i].activity >= 2000) {
                disconnect(&h, &peers[i], i); continue;
            }
            if (!pollers[i + 1].revents) continue;
            if (!(pollers[i + 1].revents & POLLIN)) { disconnect(&h, &peers[i], i); continue; }
            unsigned char bytes[512]; struct iovec io = {.iov_base = bytes, .iov_len = 512};
            struct msghdr message = {.msg_iov = &io, .msg_iovlen = 1};
            ssize_t n = recvmsg(peers[i].fd, &message, MSG_DONTWAIT | MSG_CMSG_CLOEXEC);
            YDAuditPacket p, reply;
            if (n < 0 && (errno == EAGAIN || errno == EINTR)) continue;
            if (n != 512 || message.msg_flags & (MSG_TRUNC | MSG_CTRUNC) ||
                !yd_audit_packet_decode(bytes, &p) || p.kind == YD_AUDIT_REPLY) {
                disconnect(&h, &peers[i], i); continue;
            }
            request(&h, &peers[i], i, &p, &reply);
            peers[i].activity = yd_audit_clock_ms();
            if (!send_packet(peers[i].fd, &reply)) disconnect(&h, &peers[i], i);
        }
    }
    result = h.poisoned ? 1 : 0;
done:
    for (unsigned i = 0; i < CONNECTIONS; i++) if (peers[i].fd >= 0) disconnect(&h, &peers[i], i);
    if (h.poisoned) result = 1;
    if (signals) { (void)sigaction(SIGTERM, &oldterm, NULL); (void)sigaction(SIGINT, &oldint, NULL); }
    if (listener >= 0) {
        close(listener);
        struct stat named;
        if (!fstatat(socket_directory, socket_name, &named, AT_SYMLINK_NOFOLLOW) &&
            named.st_dev == socket_identity.st_dev && named.st_ino == socket_identity.st_ino &&
            named.st_uid == geteuid() && S_ISSOCK(named.st_mode)) {
            if (unlinkat(socket_directory, socket_name, 0) || fsync(socket_directory)) result = 1;
        } else result = 1;
    }
    if (socket_directory >= 0) close(socket_directory);
    yd_audit_close(h.sink); yd_audit_anchor_close(h.anchor);
    if (sink_directory >= 0) close(sink_directory);
    OPENSSL_cleanse(key, 32);
    (void)pthread_setcancelstate(prior, NULL);
    return result;
}
