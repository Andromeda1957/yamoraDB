#define _POSIX_C_SOURCE 200809L
#include "transport/tls.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

/* Link wrappers exercise failure paths and check SSL's exact retry contract.
 * They never replace the network in the positive TCP/verified-client cases. */
static _Thread_local int alloc_fail, new_fail, fd_fail, force_error, forced;
static _Thread_local bool stepping;
static _Thread_local const void *retry_buffer;
static _Thread_local size_t retry_size;
static _Thread_local bool short_write;
typedef struct {
    pthread_mutex_t lock;
    pthread_cond_t changed;
    pthread_mutex_t *profile_lock;
    SSL_CTX *previous;
    pthread_t acquiring_thread;
    bool acquiring, contended, referenced, released, distinct_threads;
} ContextOverlap;
static _Thread_local ContextOverlap *overlap;
static _Thread_local bool acquiring_context;
static _Thread_local pthread_mutex_t *last_lock;
void *__real_malloc(size_t);
void *__real_calloc(size_t, size_t);
SSL *__real_SSL_new(SSL_CTX *);
void __real_SSL_CTX_free(SSL_CTX *);
int __real_pthread_mutex_lock(pthread_mutex_t *);
int __real_SSL_set_fd(SSL *, int);
int __real_SSL_read_ex(SSL *, void *, size_t, size_t *);
int __real_SSL_write_ex(SSL *, const void *, size_t, size_t *);
int __real_SSL_get_error(const SSL *, int);
int __real_poll(struct pollfd *, nfds_t, int);
static void overlap_require(bool valid, const char *message) {
    if (!valid) {
        fprintf(stderr, "OVERLAP FAILED: %s\n", message);
        abort();
    }
}
/* All gate state is protected separately from the production profile mutex.
 * A bounded condition wait rejects a serialized schedule instead of hanging.
 * These gates never add synchronization to normal transport or step calls. */
static void overlap_wait(ContextOverlap *o, const bool *condition, const char *message) {
    struct timespec end;
    assert(clock_gettime(CLOCK_MONOTONIC, &end) == 0);
    end.tv_sec += 5;
    while (!*condition) {
        int result = pthread_cond_timedwait(&o->changed, &o->lock, &end);
        overlap_require(result == 0 || (result == ETIMEDOUT && *condition), message);
    }
}
int __wrap_pthread_mutex_lock(pthread_mutex_t *lock) {
    ContextOverlap *o = overlap;
    if (o && !acquiring_context && lock == o->profile_lock) {
        /* This must encounter a mutex actually held by the begin thread,
         * before SSL_new acquires the old context reference. */
        overlap_require(pthread_mutex_trylock(lock) == EBUSY,
                        "reload did not encounter begin's held context mutex");
        assert(__real_pthread_mutex_lock(&o->lock) == 0);
        o->distinct_threads = !pthread_equal(pthread_self(), o->acquiring_thread);
        overlap_require(o->distinct_threads && o->acquiring && !o->referenced,
                        "reload and context acquisition were not separate overlapping threads");
        o->contended = true;
        assert(pthread_cond_broadcast(&o->changed) == 0);
        assert(pthread_mutex_unlock(&o->lock) == 0);
    }
    int result = __real_pthread_mutex_lock(lock);
    if (o && acquiring_context && result == 0)
        last_lock = lock;
    return result;
}
void *__wrap_malloc(size_t n) {
    if (alloc_fail > 0 && --alloc_fail == 0)
        return NULL;
    return __real_malloc(n);
}
void *__wrap_calloc(size_t n, size_t s) {
    if (alloc_fail > 0 && --alloc_fail == 0)
        return NULL;
    return __real_calloc(n, s);
}
SSL *__wrap_SSL_new(SSL_CTX *ctx) {
    if (new_fail)
        return NULL;
    ContextOverlap *o = overlap;
    if (o && acquiring_context) {
        assert(__real_pthread_mutex_lock(&o->lock) == 0);
        o->profile_lock = last_lock;
        o->previous = ctx;
        o->acquiring_thread = pthread_self();
        o->acquiring = true;
        assert(pthread_cond_broadcast(&o->changed) == 0);
        overlap_wait(o, &o->contended, "reload did not contend while begin held context lock");
        assert(pthread_mutex_unlock(&o->lock) == 0);
    }
    SSL *ssl = __real_SSL_new(ctx);
    if (o && acquiring_context) {
        overlap_require(ssl && SSL_get_SSL_CTX(ssl) == ctx,
                        "SSL_new did not retain the acquired context");
        assert(__real_pthread_mutex_lock(&o->lock) == 0);
        o->referenced = true;
        assert(pthread_cond_broadcast(&o->changed) == 0);
        assert(pthread_mutex_unlock(&o->lock) == 0);
    }
    return ssl;
}
void __wrap_SSL_CTX_free(SSL_CTX *ctx) {
    ContextOverlap *o = overlap;
    bool previous = o && !acquiring_context && ctx == o->previous;
    if (previous) {
        assert(__real_pthread_mutex_lock(&o->lock) == 0);
        overlap_require(o->contended && o->referenced,
                        "replacement released old context before the session retained it");
        assert(pthread_mutex_unlock(&o->lock) == 0);
    }
    __real_SSL_CTX_free(ctx);
    if (previous) {
        assert(__real_pthread_mutex_lock(&o->lock) == 0);
        o->released = true;
        assert(pthread_cond_broadcast(&o->changed) == 0);
        assert(pthread_mutex_unlock(&o->lock) == 0);
    }
}
int __wrap_SSL_set_fd(SSL *ssl, int fd) {
    if (overlap && acquiring_context) {
        assert(__real_pthread_mutex_lock(&overlap->lock) == 0);
        overlap_wait(overlap, &overlap->released,
                     "replacement did not release old context while begin remained active");
        assert(pthread_mutex_unlock(&overlap->lock) == 0);
    }
    return fd_fail ? 0 : __real_SSL_set_fd(ssl, fd);
}
int __wrap_poll(struct pollfd *p, nfds_t n, int ms) {
    assert(!stepping); /* A step that polls is a behavioral harness failure. */
    return __real_poll(p, n, ms);
}
int __wrap_SSL_read_ex(SSL *ssl, void *b, size_t n, size_t *out) {
    if (force_error) {
        forced = force_error;
        force_error = 0;
        *out = 0;
        return 0;
    }
    return __real_SSL_read_ex(ssl, b, n, out);
}
int __wrap_SSL_write_ex(SSL *ssl, const void *b, size_t n, size_t *out) {
    if (retry_buffer) {
        assert(b == retry_buffer && n == retry_size);
        retry_buffer = NULL;
    }
    if (force_error) {
        forced = force_error;
        force_error = 0;
        retry_buffer = b;
        retry_size = n;
        *out = 0;
        return 0;
    }
    int result = __real_SSL_write_ex(ssl, b, short_write && n > 7 ? 7 : n, out);
    if (result != 1) {
        int error = __real_SSL_get_error(ssl, result);
        if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {
            retry_buffer = b;
            retry_size = n;
        }
    }
    return result;
}
int __wrap_SSL_get_error(const SSL *ssl, int result) {
    if (forced) {
        int error = forced;
        forced = 0;
        return error;
    }
    return __real_SSL_get_error(ssl, result);
}
static uint64_t milliseconds(void) {
    struct timespec t;
    assert(clock_gettime(CLOCK_MONOTONIC, &t) == 0);
    return (uint64_t)t.tv_sec * 1000 + (uint64_t)t.tv_nsec / 1000000;
}
static YDTLSStep handshake(YDConnection *c, uint64_t end) {
    stepping = true;
    YDTLSStep result = yd_connection_handshake_step(c, end);
    stepping = false;
    return result;
}
static YDTLSStep read_step(YDConnection *c, void *b, size_t n, uint64_t end, size_t *out) {
    stepping = true;
    YDTLSStep result = yd_connection_read_step(c, b, n, end, out);
    stepping = false;
    return result;
}
static YDTLSStep write_step(YDConnection *c, const void *b, size_t n, uint64_t end, size_t *out) {
    stepping = true;
    YDTLSStep result = yd_connection_write_step(c, b, n, end, out);
    stepping = false;
    return result;
}
static bool wait_step(YDTLSStep step, int fd, uint64_t end) {
    if (step != YD_TLS_WANT_READ && step != YD_TLS_WANT_WRITE)
        return false;
    uint64_t current = milliseconds();
    if (current < end) {
        struct pollfd p = {.fd = fd, .events = step == YD_TLS_WANT_READ ? POLLIN : POLLOUT};
        int ms = (int)(end - current);
        int result;
        do { result = poll(&p, 1, ms); } while (result < 0 && errno == EINTR);
    }
    return true; /* Call the step even on timeout, so its deadline is tested. */
}
static const char *optional(const char *s) { return strcmp(s, "-") ? s : NULL; }
static YDTLS *profile(char **a) {
    YDTLSOptions options = {.crl_file = optional(a[3])};
    char error[256];
    return yd_tls_binary_new_with_options(a[0], a[1], optional(a[2]), &options, error, sizeof(error));
}
static void close_check(YDConnection *c) {
    int fd = c->fd;
    stepping = true;
    yd_connection_close(c);
    stepping = false;
    assert(!c->tls && !c->binary_state);
    assert(fcntl(fd, F_GETFD) >= 0);
    yd_connection_close(c);
    close(fd);
    retry_buffer = NULL;
}
static void selftest(char **a) {
    YDTLS *tls = profile(a);
    assert(tls && yd_tls_is_binary(tls) && !yd_tls_is_peer(tls));
    YDTLS *basic = yd_tls_binary_new(a[0], a[1], NULL, NULL, 0);
    assert(basic && yd_tls_is_binary(basic));
    yd_tls_free(basic);
    alloc_fail = 1;
    assert(!yd_tls_binary_new(a[0], a[1], NULL, NULL, 0));
    alloc_fail = 0;
    YDTLS *http = yd_tls_new(a[0], a[1], NULL, NULL, 0);
    assert(http && !yd_tls_is_binary(http) && !yd_tls_is_peer(http));
    YDConnection c;
    assert(!yd_connection_binary_begin(&c, -1, tls) && c.failed && !c.tls && !c.binary_state);
    yd_connection_close(&c);
    for (int i = 0; i < 5; i++) {
        int sockets[2];
        assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
        alloc_fail = i == 0 ? 1 : 0;
        new_fail = i == 1;
        fd_fail = i == 2;
        bool result = yd_connection_binary_begin(&c, sockets[0], i == 3 ? http : tls);
        alloc_fail = new_fail = fd_fail = 0;
        if (i < 4)
            assert(!result && c.failed && !c.tls && !c.binary_state);
        else {
            assert(result && (fcntl(c.fd, F_GETFL) & O_NONBLOCK));
            uint64_t end = milliseconds() + 1000;
            uint64_t start = milliseconds();
            assert(handshake(&c, end) == YD_TLS_WANT_READ);
            assert(milliseconds() - start < 100);
            size_t out = 99;
            char b = 0;
            assert(read_step(&c, &b, 1, end, &out) == YD_TLS_ERROR && out == 0 && c.failed);
            assert(handshake(&c, end) == YD_TLS_ERROR);
        }
        close_check(&c);
        close(sockets[1]);
    }
    int sockets[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    assert(yd_connection_binary_begin(&c, sockets[0], tls));
    assert(handshake(&c, milliseconds() - 1) == YD_TLS_ERROR && errno == ETIMEDOUT && c.failed);
    assert(handshake(&c, milliseconds() + 1000) == YD_TLS_ERROR);
    close_check(&c);
    close(sockets[1]);
    for (int i = 0; i < 3; i++) {
        assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
        assert(yd_connection_binary_begin(&c, sockets[0], tls));
        size_t out = 99;
        char b = 0;
        if (i == 0)
            assert(write_step(&c, &b, 1, milliseconds() + 1000, &out) == YD_TLS_ERROR && !out);
        else if (i == 1)
            assert(handshake(&c, 0) == YD_TLS_ERROR && errno == ETIMEDOUT);
        else
            assert(read_step(&c, &b, 0, milliseconds() + 1000, &out) == YD_TLS_ERROR && !out);
        assert(c.failed);
        close_check(&c);
        close(sockets[1]);
    }
    size_t out = 99;
    char b = 0;
    assert(read_step(NULL, &b, 1, milliseconds() + 1000, &out) == YD_TLS_ERROR && !out);
    yd_tls_free(http);
    yd_tls_free(tls);
    puts("SELFTEST OK");
}

typedef struct {
    YDConnection c;
    unsigned id;
    const char *mode;
    int timeout;
    YDTLS *legacy;
} Worker;
typedef struct {
    ContextOverlap gate;
    YDTLS *tls;
    YDConnection *connection;
    int fd;
    bool begun, reloaded;
} BeginReload;
static void *overlap_begin(void *argument) {
    BeginReload *test = argument;
    overlap = &test->gate;
    acquiring_context = true;
    test->begun = yd_connection_binary_begin(test->connection, test->fd, test->tls);
    overlap = NULL;
    return NULL;
}
static void *overlap_reload(void *argument) {
    BeginReload *test = argument;
    overlap = &test->gate;
    acquiring_context = false;
    char error[256];
    test->reloaded = yd_tls_reload(test->tls, error, sizeof(error));
    overlap = NULL;
    return NULL;
}
static void coordinated_begin_reload(YDConnection *connection, int fd, YDTLS *tls) {
    BeginReload test = {.tls = tls, .connection = connection, .fd = fd};
    ContextOverlap *o = &test.gate;
    assert(pthread_mutex_init(&o->lock, NULL) == 0);
    pthread_condattr_t attributes;
    assert(pthread_condattr_init(&attributes) == 0);
    assert(pthread_condattr_setclock(&attributes, CLOCK_MONOTONIC) == 0);
    assert(pthread_cond_init(&o->changed, &attributes) == 0);
    assert(pthread_condattr_destroy(&attributes) == 0);
#ifdef YD_TEST_SERIALIZE_OVERLAP
    /* Deliberately broken negative control: the first call must fail its
     * overlap gate, rather than letting serialization certify concurrency. */
    overlap_begin(&test);
    overlap_reload(&test);
#else
    pthread_t begin_thread, reload_thread;
    assert(pthread_create(&begin_thread, NULL, overlap_begin, &test) == 0);
    assert(__real_pthread_mutex_lock(&o->lock) == 0);
    overlap_wait(o, &o->acquiring, "begin did not reach context acquisition");
    assert(pthread_mutex_unlock(&o->lock) == 0);
    assert(pthread_create(&reload_thread, NULL, overlap_reload, &test) == 0);
    assert(pthread_join(begin_thread, NULL) == 0);
    assert(pthread_join(reload_thread, NULL) == 0);
#endif
    overlap_require(test.begun && test.reloaded && o->acquiring && o->contended &&
                    o->referenced && o->released && o->distinct_threads,
                    "begin/reload overlap evidence was incomplete");
    printf("OVERLAP %d %d %d %d %d\n", o->acquiring, o->contended, o->referenced,
           o->released, o->distinct_threads);
    assert(pthread_cond_destroy(&o->changed) == 0);
    assert(pthread_mutex_destroy(&o->lock) == 0);
}
static void *serve(void *argument) {
    Worker *w = argument;
    YDConnection *c = &w->c;
    uint64_t end = milliseconds() + (uint64_t)w->timeout;
    if (w->legacy) {
        bool accepted = yd_connection_init(c, c->fd, w->legacy, w->timeout);
        printf("HANDSHAKE %u %d\n", w->id, accepted ? YD_TLS_READY : YD_TLS_ERROR);
        if (accepted) {
            char b[256];
            ssize_t got = yd_connection_read(c, b, sizeof(b), end);
            assert(got > 0 && yd_connection_send(c, b, (size_t)got));
        }
        close_check(c);
        return NULL;
    }
    YDTLSStep result;
    unsigned wants_read = 0, wants_write = 0, partials = 0;
    size_t total = 0;
    do {
        result = handshake(c, end);
        wants_read += result == YD_TLS_WANT_READ;
        wants_write += result == YD_TLS_WANT_WRITE;
    } while (wait_step(result, c->fd, end));
    printf("HANDSHAKE %u %d\n", w->id, result);
    fflush(stdout);
    if (result != YD_TLS_READY)
        goto done;
    if (!strcmp(w->mode, "validate")) {
        unsigned char code = 0;
        size_t out;
        end = milliseconds() + 2000;
        do { result = read_step(c, &code, 1, end, &out); } while (wait_step(result, c->fd, end));
        assert(result == YD_TLS_READY && out == 1);
        out = 99;
        switch (code) {
        case 0: result = read_step(c, NULL, 1, end, &out); break;
        case 1: result = write_step(c, NULL, 1, end, &out); break;
        case 2: result = read_step(c, &code, 0, end, &out); break;
        case 3: result = write_step(c, &code, 0, end, &out); break;
        case 4: result = read_step(c, &code, 1, end, NULL); out = 0; break;
        case 5: result = write_step(c, &code, 1, end, NULL); out = 0; break;
        case 6: result = read_step(c, &code, 1, milliseconds() - 1, &out); break;
        default: result = write_step(c, &code, 1, milliseconds() - 1, &out); break;
        }
        assert(result == YD_TLS_ERROR && out == 0 && c->failed);
        goto done;
    }
    if (!strcmp(w->mode, "write-eof") || !strcmp(w->mode, "write-error")) {
        size_t out = 99;
        force_error = !strcmp(w->mode, "write-eof") ? SSL_ERROR_ZERO_RETURN : SSL_ERROR_SYSCALL;
        result = write_step(c, "terminal", 8, milliseconds() + 1000, &out);
        assert(!out);
        if (!strcmp(w->mode, "write-eof")) {
            assert(result == YD_TLS_EOF && !c->failed);
            assert(write_step(c, "terminal", 8, milliseconds() + 1000, &out) == YD_TLS_EOF && !out);
        } else {
            assert(result == YD_TLS_ERROR && c->failed);
            assert(handshake(c, milliseconds() + 1000) == YD_TLS_ERROR);
        }
        goto done;
    }
    if (!strcmp(w->mode, "alloc-write")) {
        size_t out = 99;
        alloc_fail = 1;
        result = write_step(c, "allocation", 10, milliseconds() + 1000, &out);
        alloc_fail = 0;
        assert(result == YD_TLS_ERROR && !out && c->failed);
        goto done;
    }
    if (!strncmp(w->mode, "retry-", 6) || !strcmp(w->mode, "opposite")) {
        char b[] = "immutable retry";
        size_t out = 99;
        end = milliseconds() + 2000;
        force_error = SSL_ERROR_WANT_READ;
        result = write_step(c, b, sizeof(b), end, &out);
        assert(result == YD_TLS_WANT_READ && !out);
        if (!strcmp(w->mode, "retry-pointer")) {
            char other[sizeof(b)];
            memcpy(other, b, sizeof(b));
            result = write_step(c, other, sizeof(other), end, &out);
        } else if (!strcmp(w->mode, "retry-length"))
            result = write_step(c, b, sizeof(b) - 1, end, &out);
        else if (!strcmp(w->mode, "retry-bytes")) {
            b[0] ^= 1;
            result = write_step(c, b, sizeof(b), end, &out);
        } else if (!strcmp(w->mode, "retry-read"))
            result = read_step(c, b, sizeof(b), end, &out);
        else {
            result = write_step(c, b, sizeof(b), end, &out);
            assert(result == YD_TLS_READY && out == sizeof(b));
            force_error = SSL_ERROR_WANT_WRITE;
            result = read_step(c, b, sizeof(b), end, &out);
            assert(result == YD_TLS_WANT_WRITE && out == 0 && !c->failed);
            result = YD_TLS_READY;
            goto done;
        }
        assert(result == YD_TLS_ERROR && !out && c->failed);
        assert(write_step(c, b, sizeof(b), end, &out) == YD_TLS_ERROR && !out);
        goto done;
    }
    if (!strcmp(w->mode, "write") || !strcmp(w->mode, "short")) {
        unsigned char b[65536];
        for (size_t i = 0; i < sizeof(b); i++)
            b[i] = (unsigned char)(i % 251);
        size_t used = 0, target = !strcmp(w->mode, "short") ? 1000 : 4U * 1024U * 1024U;
        short_write = !strcmp(w->mode, "short");
        end = milliseconds() + (uint64_t)w->timeout;
        while (used < target) {
            size_t offset = used % sizeof(b), n = sizeof(b) - offset;
            if (n > target - used)
                n = target - used;
            size_t out = 99;
            result = write_step(c, b + offset, n, end, &out);
            wants_read += result == YD_TLS_WANT_READ;
            wants_write += result == YD_TLS_WANT_WRITE;
            if (result == YD_TLS_READY) {
                assert(out && out <= n);
                partials += out < n;
                used += out;
            } else {
                assert(out == 0);
                if (!wait_step(result, c->fd, end))
                    break;
            }
        }
        total = used;
        goto done;
    }
    /* Echo is deliberately reusable: each response receives a fresh write
     * deadline while a second request can arrive beyond the first one's end. */
    for (;;) {
        unsigned char b[16384];
        size_t out = 99;
        end = milliseconds() + (uint64_t)w->timeout;
        do {
            result = read_step(c, b, !strcmp(w->mode, "pending") ? 1 : sizeof(b), end, &out);
            wants_read += result == YD_TLS_WANT_READ;
            wants_write += result == YD_TLS_WANT_WRITE;
            if (result != YD_TLS_READY)
                assert(out == 0);
        } while (wait_step(result, c->fd, end));
        if (result != YD_TLS_READY) {
            if (result == YD_TLS_EOF) {
                assert(!c->failed);
                assert(read_step(c, b, sizeof(b), end, &out) == YD_TLS_EOF && !out);
            }
            break;
        }
        size_t used = 0, n = out;
        end = milliseconds() + 200; /* Independent from handshake/first response. */
        while (used < n) {
            result = write_step(c, b + used, n - used, end, &out);
            if (result == YD_TLS_READY)
                used += out;
            else if (!wait_step(result, c->fd, end))
                goto done;
        }
        total += n;
    }
done:
    printf("DONE %u %d %d %zu %u %u %u\n", w->id, result, c->failed, total,
           wants_read, wants_write, partials);
    fflush(stdout);
    close_check(c);
    return NULL;
}
int main(int argc, char **argv) {
    if (argc != 7)
        return 2;
    struct rlimit core = {0};
    assert(setrlimit(RLIMIT_CORE, &core) == 0);
    signal(SIGPIPE, SIG_IGN);
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (!strcmp(argv[1], "selftest")) {
        selftest(argv + 2);
        return 0;
    }
    YDTLS *tls = !strcmp(argv[1], "http")
                    ? yd_tls_new(argv[2], argv[3], NULL, NULL, 0) : profile(argv + 2);
    if (!tls) {
        puts("REJECTED");
        return 1;
    }
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    assert(listener >= 0);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t length = sizeof(address);
    assert(bind(listener, (struct sockaddr *)&address, length) == 0);
    assert(getsockname(listener, (struct sockaddr *)&address, &length) == 0);
    assert(listen(listener, 32) == 0);
    printf("PORT %u\n", ntohs(address.sin_port));
    Worker workers[128];
    pthread_t threads[128];
    unsigned count = 0;
    for (;;) {
        struct pollfd fds[2] = {{.fd = listener, .events = POLLIN}, {.fd = STDIN_FILENO, .events = POLLIN}};
        assert(poll(fds, 2, -1) > 0);
        if (fds[1].revents) {
            char command[64], error[256];
            if (!fgets(command, sizeof(command), stdin) || !strcmp(command, "quit\n"))
                break;
            if (!strcmp(command, "reload\n"))
                puts(yd_tls_reload(tls, error, sizeof(error)) ? "RELOADED" : "RETAINED");
            if (!strcmp(command, "free\n")) {
                yd_tls_free(tls);
                tls = NULL;
                puts("FREED");
            }
        }
        if (fds[0].revents & POLLIN) {
            int fd = accept(listener, NULL, NULL);
            assert(fd >= 0 && count < 128);
            int size = 4096;
            assert(setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)) == 0);
            Worker *w = &workers[count];
            *w = (Worker){.id = count, .mode = argv[1], .timeout = atoi(argv[6])};
            if (!strcmp(argv[1], "http")) {
                w->legacy = tls;
                w->c.fd = fd;
            } else if (!strcmp(argv[1], "overlap") && count == 0)
                coordinated_begin_reload(&w->c, fd, tls);
            else
                assert(yd_connection_binary_begin(&w->c, fd, tls));
            assert(pthread_create(&threads[count], NULL, serve, w) == 0);
            count++;
        }
    }
    close(listener);
    for (unsigned i = 0; i < count; i++)
        assert(pthread_join(threads[i], NULL) == 0);
    yd_tls_free(tls);
    return 0;
}
