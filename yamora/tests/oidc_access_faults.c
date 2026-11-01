/* Test-only real-daemon linkage: --wrap=time --wrap=yd_oidc_verify -pthread.
 * No production switches. The owning test passes one AF_UNIX socketpair FD in
 * YAMORA_OIDC_CONTROL_FD and an initial epoch in YAMORA_OIDC_NOW. Fixed 9-byte
 * frames: R+epoch startup; T+epoch sets time; F+0/1 disables/enables local ERROR.
 * Commands receive identical acknowledgements AFTER atomic publication. EOF,
 * malformed commands or a 30-second idle deadline fail verifier calls closed.
 * Ordinary calls always use the real verifier and EVP. CLOCK_MONOTONIC and TLS
 * library clocks are untouched. Destructor shuts down and joins the sole thread.
 */
#define _POSIX_C_SOURCE 200809L
#include "../src/security/oidc.h"
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static int control_fd = -1;
static pthread_t controller;
static int started;
static atomic_llong epoch;
static atomic_bool provider_error;
static atomic_bool connected;
static atomic_bool stopping;

time_t __real_time(time_t *);
int __real_yd_oidc_verify(const YDOIDC *, const char *, size_t, int64_t, YDOIDCIdentity *);

static int transfer(unsigned char *buffer, size_t length, int writing) {
    struct timespec initial;
    if (clock_gettime(CLOCK_MONOTONIC, &initial)) return 0;
    while (length && !atomic_load(&stopping)) {
        struct timespec now;
        if (clock_gettime(CLOCK_MONOTONIC, &now)) return 0;
        int64_t remaining = 30000 - (now.tv_sec - initial.tv_sec) * 1000 -
            (now.tv_nsec - initial.tv_nsec) / 1000000;
        if (remaining <= 0) return 0;
        struct pollfd descriptor = {.fd = control_fd, .events = writing ? POLLOUT : POLLIN};
        int ready = poll(&descriptor, 1, (int)remaining);
        if (ready < 0 && errno == EINTR) continue;
        if (ready <= 0) return 0;
        ssize_t count = writing ? send(control_fd, buffer, length, MSG_NOSIGNAL | MSG_DONTWAIT) :
            recv(control_fd, buffer, length, MSG_DONTWAIT);
        if (count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        if (count <= 0) return 0;
        buffer += count;
        length -= (size_t)count;
    }
    return length == 0;
}
static uint64_t decode(const unsigned char *bytes) {
    uint64_t value = 0;
    for (unsigned i = 0; i < 8; ++i) value = (value << 8) | bytes[i];
    return value;
}
static void encode(unsigned char *bytes, uint64_t value) {
    for (unsigned i = 8; i; --i) { bytes[i - 1] = (unsigned char)value; value >>= 8; }
}
static void *serve(void *unused) {
    (void)unused;
    unsigned char frame[9] = {'R'};
    encode(frame + 1, (uint64_t)atomic_load(&epoch));
    if (!transfer(frame, sizeof(frame), 1)) goto done;
    while (transfer(frame, sizeof(frame), 0)) {
        uint64_t value = decode(frame + 1);
        if (frame[0] == 'T' && value <= INT64_C(253402300799))
            atomic_store(&epoch, (long long)value);
        else if (frame[0] == 'F' && value <= 1)
            atomic_store(&provider_error, value != 0);
        else break;
        if (!transfer(frame, sizeof(frame), 1)) break;
    }
done:
    atomic_store(&connected, 0);
    return NULL;
}
static int setting(const char *name, uint64_t maximum, uint64_t *result) {
    const char *text = getenv(name);
    if (!text || !*text) return 0;
    uint64_t value = 0;
    for (; *text; ++text) {
        if (*text < '0' || *text > '9' || value > (maximum - (unsigned)(*text - '0')) / 10)
            return 0;
        value = value * 10 + (unsigned)(*text - '0');
    }
    *result = value;
    return 1;
}
__attribute__((constructor)) static void initialize(void) {
    uint64_t fd, now;
    if (!getenv("YAMORA_OIDC_CONTROL_FD")) return;
    if (!setting("YAMORA_OIDC_CONTROL_FD", INT_MAX, &fd) || fd < 3 ||
        !setting("YAMORA_OIDC_NOW", INT64_C(253402300799), &now)) _exit(78);
    int type = 0;
    socklen_t size = sizeof(type);
    struct sockaddr_storage address;
    socklen_t address_size = sizeof(address);
    if (getsockopt((int)fd, SOL_SOCKET, SO_TYPE, &type, &size) || type != SOCK_STREAM ||
        getsockname((int)fd, (struct sockaddr *)&address, &address_size) ||
        address.ss_family != AF_UNIX) _exit(78);
    control_fd = (int)fd;
    atomic_store(&epoch, (long long)now);
    atomic_store(&connected, 1);
    if (pthread_create(&controller, NULL, serve, NULL)) _exit(78);
    started = 1;
}
__attribute__((destructor)) static void finish(void) {
    if (!started) return;
    atomic_store(&stopping, 1);
    shutdown(control_fd, SHUT_RDWR);
    pthread_join(controller, NULL);
    close(control_fd);
}
time_t __wrap_time(time_t *destination) {
    if (!started) return __real_time(destination);
    time_t now = (time_t)atomic_load(&epoch);
    if (destination) *destination = now;
    return now;
}
int __wrap_yd_oidc_verify(const YDOIDC *configuration, const char *jwt, size_t length,
    int64_t now, YDOIDCIdentity *identity) {
    if (started && (!atomic_load(&connected) || atomic_load(&provider_error))) return -1;
    return __real_yd_oidc_verify(configuration, jwt, length, now, identity);
}
