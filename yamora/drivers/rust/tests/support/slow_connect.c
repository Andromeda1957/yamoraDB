/* Test-only Linux interposer: successful TCP completion takes 120ms. The actual
 * socket still connects to the private HTTPS fixture; no TLS is intercepted. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

static _Thread_local int pending_fd = -1;
static _Thread_local struct timespec started;

int connect(int fd, const struct sockaddr *address, socklen_t length) {
    int (*original)(int, const struct sockaddr *, socklen_t) = dlsym(RTLD_NEXT, "connect");
    int result = original(fd, address, length);
    int error = errno;
    const char *port = getenv("YAMORA_DELAY_CONNECT_PORT");
    if (port && length >= sizeof(struct sockaddr_in) && address->sa_family == AF_INET &&
        ntohs(((const struct sockaddr_in *)address)->sin_port) == strtoul(port, NULL, 10) &&
        (result == 0 || error == EINPROGRESS)) {
        pending_fd = fd;
        clock_gettime(CLOCK_MONOTONIC, &started);
        const char *path = getenv("YAMORA_DELAY_CONNECT_LOG");
        if (path) {
            int log = open(path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0600);
            if (log >= 0) { (void)write(log, "connect\n", 8); close(log); }
        }
        errno = EINPROGRESS;
        return -1;
    }
    errno = error;
    return result;
}

int poll(struct pollfd *fds, nfds_t count, int timeout) {
    int (*original)(struct pollfd *, nfds_t, int) = dlsym(RTLD_NEXT, "poll");
    for (nfds_t i = 0; i < count; ++i) {
        if (fds[i].fd != pending_fd) continue;
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        long elapsed = (now.tv_sec - started.tv_sec) * 1000 + (now.tv_nsec - started.tv_nsec) / 1000000;
        int delay = (int)(120 - elapsed);
        if (delay <= 0) break;
        int wait = timeout >= 0 && timeout < delay ? timeout : delay;
        struct timespec pause = {wait / 1000, (wait % 1000) * 1000000};
        while (nanosleep(&pause, &pause) < 0 && errno == EINTR) {}
        if (timeout >= 0 && timeout <= delay) return 0;
        if (timeout > 0) timeout -= delay;
        break;
    }
    return original(fds, count, timeout);
}
