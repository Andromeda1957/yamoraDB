#define _GNU_SOURCE
#include "transport/binary_frame.h"
#include "transport/binary_session.h"
#include <arpa/inet.h>
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static atomic_uint forced_want, want_count, retry_count, rx_pressure, tx_pressure, pressure_count;
static atomic_uint large_allocations, fail_large, tickets;
static atomic_uint startup_fault, thread_attempts, threads_created, threads_joined, short_write;
static atomic_uint accept_faults, accept_error, accept_injected, poll_calls, blocked_interest;
static atomic_uint reads;
static atomic_uint hold_end, end_held;
static pthread_t runtime_workers[2];
static atomic_uint workers_published;
static bool on_dispatch_worker(void) {
    if (atomic_load(&workers_published) != 2) return false;
    return pthread_equal(pthread_self(), runtime_workers[0]) ||
        pthread_equal(pthread_self(), runtime_workers[1]);
}
static atomic_int blocked_fd = -1;
static atomic_int want_read_fd = -1;
static _Thread_local int last_read_fd = -1;
static atomic_uint_fast64_t advance_ms;
int __real_clock_gettime(clockid_t, struct timespec *);
int __wrap_clock_gettime(clockid_t id, struct timespec *t) {
    int result = __real_clock_gettime(id, t);
    if (!result && id == CLOCK_MONOTONIC) {
        uint64_t delta = atomic_load(&advance_ms);
        t->tv_sec += (time_t)(delta / 1000);
        t->tv_nsec += (long)(delta % 1000) * 1000000;
        if (t->tv_nsec >= 1000000000) {
            t->tv_nsec -= 1000000000;
            t->tv_sec++;
        }
    }
    return result;
}
void *__real_malloc(size_t);
void *__real_calloc(size_t, size_t);
int __real_socket(int, int, int);
int __real_pipe2(int[2], int);
int __real_accept4(int, struct sockaddr *, socklen_t *, int);
int __real_poll(struct pollfd *, nfds_t, int);
int __wrap_accept4(int fd, struct sockaddr *address, socklen_t *length, int flags) {
    unsigned left = atomic_load(&accept_faults);
    if (left && atomic_compare_exchange_strong(&accept_faults, &left, left - 1)) {
        atomic_fetch_add(&accept_injected, 1);
        errno = (int)atomic_load(&accept_error);
        return -1;
    }
    return __real_accept4(fd, address, length, flags);
}
int __wrap_poll(struct pollfd *fds, nfds_t count, int timeout) {
    atomic_fetch_add(&poll_calls, 1);
    int blocked = atomic_load(&blocked_fd);
    if (blocked >= 0) {
        short events = 0;
        for (nfds_t i = 0; i < count; i++)
            if (fds[i].fd == blocked)
                events = fds[i].events;
        if (events & POLLIN)
            atomic_fetch_add(&blocked_interest, 1);
        if (atomic_exchange(&blocked_fd, -1) >= 0)
            printf("BLOCKED POLL %d\n", events);
    }
    int wanted = atomic_exchange(&want_read_fd, -1);
    if (wanted >= 0) {
        short events = 0;
        for (nfds_t i = 0; i < count; i++)
            if (fds[i].fd == wanted)
                events = fds[i].events;
        assert(events & POLLIN);
        puts("WANT READ POLL");
    }
    return __real_poll(fds, count, timeout);
}
int __real_pthread_create(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);
int __real_pthread_join(pthread_t, void **);
void *__wrap_calloc(size_t n, size_t size) {
    if (atomic_load(&startup_fault) == 1) {
        atomic_store(&startup_fault, 0);
        return NULL;
    }
    return __real_calloc(n, size);
}
int __wrap_socket(int domain, int type, int protocol) {
    if (atomic_load(&startup_fault) == 2) {
        errno = EMFILE;
        return -1;
    }
    return __real_socket(domain, type, protocol);
}
int __wrap_pipe2(int fd[2], int flags) {
    if (atomic_load(&startup_fault) == 3) {
        errno = EMFILE;
        return -1;
    }
    return __real_pipe2(fd, flags);
}
int __wrap_pthread_create(pthread_t *id, const pthread_attr_t *attr, void *(*start)(void *),
                          void *arg) {
    unsigned attempt = atomic_fetch_add(&thread_attempts, 1) + 1;
    if (atomic_load(&startup_fault) == attempt + 3)
        return EAGAIN;
    int result = __real_pthread_create(id, attr, start, arg);
    if (!result) {
        unsigned created = atomic_fetch_add(&threads_created, 1);
        if (created < 2) {
            runtime_workers[created] = *id;
            atomic_fetch_add(&workers_published, 1);
        }
    }
    return result;
}
int __wrap_pthread_join(pthread_t id, void **result) {
    int error = __real_pthread_join(id, result);
    if (!error)
        atomic_fetch_add(&threads_joined, 1);
    return error;
}
static unsigned fd_count(void) {
    DIR *dir = opendir("/proc/self/fd");
    assert(dir);
    unsigned count = 0;
    while (readdir(dir))
        count++;
    closedir(dir);
    return count;
}
int __real_SSL_write_ex(SSL *, const void *, size_t, size_t *);
int __real_SSL_read_ex(SSL *, void *, size_t, size_t *);
int __real_SSL_get_error(const SSL *, int);
void __real_SSL_free(SSL *);
YDBinaryResult __real_yd_binary_admit(YDBinaryConnection *, YDBinaryDirection,
                                      const YDBinaryFrame *, YDBinaryTicket *);
YDBinaryResult __real_yd_binary_release(YDBinaryConnection *, YDBinaryTicket *);
static _Thread_local int forced_error;
typedef struct {
    SSL *ssl;
    const void *pointer;
    size_t length;
    unsigned char data[65552];
} Pending;
static _Thread_local Pending pending[8];
void *__wrap_malloc(size_t n) {
    if (n == 3U * 1024U * 1024U)
        atomic_fetch_add(&large_allocations, 1);
    if (n > 2U * 1024U * 1024U && atomic_exchange(&fail_large, 0))
        return NULL;
    return __real_malloc(n);
}
int __wrap_SSL_write_ex(SSL *ssl, const void *b, size_t n, size_t *sent) {
    Pending *slot = NULL;
    for (unsigned i = 0; i < 8; i++) {
        if (pending[i].ssl == ssl) {
            assert(pending[i].pointer == b && pending[i].length == n);
            assert(!memcmp(pending[i].data, b, n));
            pending[i].ssl = NULL;
            atomic_fetch_add(&retry_count, 1);
        }
        if (!pending[i].ssl)
            slot = &pending[i];
    }
    unsigned want = atomic_exchange(&forced_want, 0);
    if (atomic_load(&hold_end) && n == 16 && !memcmp(b, "YMBF", 4) &&
        ((const unsigned char *)b)[5] == YD_BINARY_END) {
        if (!atomic_exchange(&end_held, 1)) puts("END HELD");
        want = 1;
    }
    if (want) {
        assert(slot && n <= sizeof(slot->data));
        *slot = (Pending){.ssl = ssl, .pointer = b, .length = n};
        memcpy(slot->data, b, n);
        forced_error = want == 2 ? SSL_ERROR_WANT_READ : SSL_ERROR_WANT_WRITE;
        if (want == 2)
            atomic_store(&want_read_fd, SSL_get_fd(ssl));
        *sent = 0;
        atomic_fetch_add(&want_count, 1);
        return 0;
    }
    if (atomic_exchange(&short_write, 0) && n > 7)
        n = 7;
    return __real_SSL_write_ex(ssl, b, n, sent);
}
int __wrap_SSL_read_ex(SSL *ssl, void *b, size_t n, size_t *got) {
    for (unsigned i = 0; i < 8; i++)
        assert(pending[i].ssl != ssl);
    last_read_fd = SSL_get_fd(ssl);
    int result = __real_SSL_read_ex(ssl, b, n, got);
    if (result == 1)
        atomic_fetch_add(&reads, 1);
    return result;
}
int __wrap_SSL_get_error(const SSL *ssl, int result) {
    if (forced_error) {
        int e = forced_error;
        forced_error = 0;
        return e;
    }
    return __real_SSL_get_error(ssl, result);
}
void __wrap_SSL_free(SSL *ssl) {
    for (unsigned i = 0; i < 8; i++)
        if (pending[i].ssl == ssl)
            pending[i].ssl = NULL;
    __real_SSL_free(ssl);
    puts("TLS FREED");
}
YDBinaryResult __wrap_yd_binary_admit(YDBinaryConnection *c, YDBinaryDirection d,
                                      const YDBinaryFrame *f, YDBinaryTicket *t) {
    atomic_uint *fault = d == YD_BINARY_SEND ? &tx_pressure : &rx_pressure;
    if (((d == YD_BINARY_SEND && f->type == YD_BINARY_DATA) ||
         (d == YD_BINARY_RECEIVE && f->type == YD_BINARY_REQUEST)) &&
        atomic_exchange(fault, 0)) {
        atomic_fetch_add(&pressure_count, 1);
        return YD_BINARY_BACKPRESSURE;
    }
    YDBinaryResult result = __real_yd_binary_admit(c, d, f, t);
    if (result == YD_BINARY_BACKPRESSURE && d == YD_BINARY_RECEIVE && f->type == YD_BINARY_REQUEST)
        atomic_store(&blocked_fd, last_read_fd);
    if (result == YD_BINARY_OK)
        atomic_fetch_add(&tickets, 1);
    return result;
}
YDBinaryResult __wrap_yd_binary_release(YDBinaryConnection *c, YDBinaryTicket *t) {
    YDBinaryResult result = __real_yd_binary_release(c, t);
    if (result == YD_BINARY_OK)
        assert(atomic_fetch_sub(&tickets, 1) > 0);
    return result;
}
typedef struct {
    pthread_mutex_t lock;
    pthread_cond_t changed;
    unsigned admitted, executed, active, peak, permits, reserved, released;
    size_t upload;
    unsigned remaining_min;
    unsigned producer_finished, producer_closed;
    bool deny_upload, closing, closed;
    char file[4096];
    YDBinaryRuntime *runtime;
} Context;
static YDBinaryReply reply(unsigned status, const char *content, size_t size) {
    YDBinaryReply r = {0};
    r.message.status = (uint16_t)status;
    strcpy(r.message.content_type, "application/yaml");
    strcpy(r.message.revision, "0123456789abcdef");
    r.message.body_length = r.message.representation_length = size;
    if (size) {
        r.body = malloc(size + 1);
        assert(r.body);
        if (content)
            memcpy(r.body, content, size);
        else
            memset(r.body, 'x', size);
        r.body[size] = 0;
    }
    return r;
}
static bool admit(void *arg, const YDBinaryRequestMessage *request, YDBinaryReply *rejection) {
    Context *c = arg;
    pthread_mutex_lock(&c->lock);
    c->admitted++;
    pthread_mutex_unlock(&c->lock);
    if (strcmp(request->authorization, "Bearer accepted")) {
        *rejection = reply(401, "denied", 6);
        if (request->method == YD_BINARY_METHOD_HEAD) {
            free(rejection->body);
            rejection->body = NULL;
            rejection->message.body_length = 0;
        }
        rejection->message.present = YD_BINARY_RESPONSE_AUTHENTICATE;
        rejection->message.authenticate = YD_BINARY_AUTHENTICATE_BEARER;
        return false;
    }
    if (strstr(request->target, "profile-reject")) {
        *rejection = reply(413, NULL, 0);
        return false;
    }
    return true;
}
typedef struct {
    unsigned pull, finishes;
    bool short_body, overflow, audited, barrier, fail_finish;
    atomic_bool next_active;
    Context *owner;
} FiniteProducer;
static bool finite_finish(void *arg, bool complete) {
    FiniteProducer *producer = arg;
    int previous;
    assert(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous) == 0);
    producer->finishes++;
    pthread_mutex_lock(&producer->owner->lock);
    producer->owner->producer_finished++;
    pthread_mutex_unlock(&producer->owner->lock);
    printf("PRODUCER FINISHED %u %u %u %u %u\n", producer->finishes, complete,
           on_dispatch_worker(), !atomic_load(&producer->next_active),
           previous == PTHREAD_CANCEL_DISABLE);
    assert(pthread_setcancelstate(previous, NULL) == 0);
    return !producer->fail_finish;
}
static YDBinaryChunk finite_next(void *arg, unsigned remaining) {
    FiniteProducer *producer = arg;
    assert(remaining);
    atomic_store(&producer->next_active, true);
    producer->pull++;
    if (producer->barrier && producer->pull == 1) {
        pthread_mutex_lock(&producer->owner->lock);
        puts("PRODUCER PULL HELD");
        while (!producer->owner->permits)
            pthread_cond_wait(&producer->owner->changed, &producer->owner->lock);
        producer->owner->permits--;
        pthread_mutex_unlock(&producer->owner->lock);
    }
    if (producer->short_body) {
        atomic_store(&producer->next_active, false);
        return (YDBinaryChunk){.end = true};
    }
    const char *text = producer->overflow ? "overflow!!" : producer->pull == 1 ? "beta" : "gamma";
    size_t n = strlen(text);
    unsigned char *body = malloc(n);
    assert(body); memcpy(body, text, n);
    atomic_store(&producer->next_active, false);
    return (YDBinaryChunk){.body = body, .length = n};
}
static void finite_close(void *arg) {
    FiniteProducer *producer = arg;
    if (producer->audited) {
        pthread_mutex_lock(&producer->owner->lock);
        producer->owner->producer_closed++;
        pthread_mutex_unlock(&producer->owner->lock);
        printf("PRODUCER TERMINAL CHECK %u %u\n", producer->finishes, on_dispatch_worker());
    }
    printf("PRODUCER CLOSED %u\n", producer->pull);
    free(producer);
}
static YDBinaryReply execute(void *arg, const YDBinaryRequestMessage *request,
                             const unsigned char *body, size_t length, unsigned remaining) {
    Context *c = arg;
    pthread_mutex_lock(&c->lock);
    assert(!c->closed && remaining > 0 && remaining <= 30000);
    c->executed++;
    c->active++;
    if (c->active > c->peak)
        c->peak = c->active;
    if (remaining < c->remaining_min)
        c->remaining_min = remaining;
    printf("EXEC %u %s\n", c->executed, request->target);
    pthread_cond_broadcast(&c->changed);
    while (strstr(request->target, "hold") && !c->permits)
        pthread_cond_wait(&c->changed, &c->lock);
    if (strstr(request->target, "hold"))
        c->permits--;
    pthread_mutex_unlock(&c->lock);
    YDBinaryReply result;
    if (strstr(request->target, "producer")) {
        FiniteProducer *producer = calloc(1, sizeof(*producer));
        assert(producer);
        atomic_init(&producer->next_active, false);
        producer->owner = c;
        producer->audited = strstr(request->target, "audited") != NULL;
        producer->barrier = strstr(request->target, "barrier") != NULL;
        producer->fail_finish = strstr(request->target, "failfinish") != NULL;
        producer->short_body = strstr(request->target, "short") != NULL;
        producer->overflow = strstr(request->target, "overflow") != NULL;
        result = reply(200, "alpha", 5);
        result.message.body_length = result.message.representation_length = 14;
        result.page_length = 5;
        result.producer = (YDBinaryProducer){.context = producer, .next = finite_next,
            .finish = producer->audited ? finite_finish : NULL, .close = finite_close};
    } else if (strstr(request->target, "missingbody")) {
        result = reply(200, NULL, 0);
        result.message.representation_length = 12;
    } else if (strstr(request->target, "oversizeack"))
        result = reply(200, NULL, 4097);
    else if (strstr(request->target, "oversize"))
        result = reply(200, NULL, 16777217);
    else if (strstr(request->target, "large"))
        result = reply(200, NULL, 16777216);
    else if (request->method == YD_BINARY_METHOD_PUT) {
        int fd = open(c->file, O_WRONLY | O_TRUNC | O_CREAT | O_CLOEXEC, 0600);
        assert(fd >= 0);
        size_t used = 0;
        while (used < length) {
            ssize_t n = write(fd, body + used, length - used);
            assert(n > 0);
            used += (size_t)n;
        }
        assert(fsync(fd) == 0 && close(fd) == 0);
        result = reply(201, "written", 7);
    } else {
        int fd = open(c->file, O_RDONLY | O_CLOEXEC);
        if (fd < 0)
            result = reply(200, "ok", 2);
        else {
            off_t size = lseek(fd, 0, SEEK_END);
            assert(size >= 0 && size <= 16777216 && lseek(fd, 0, SEEK_SET) == 0);
            result = reply(200, NULL, (size_t)size);
            size_t used = 0;
            while (used < (size_t)size) {
                ssize_t n = read(fd, result.body + used, (size_t)size - used);
                assert(n > 0);
                used += (size_t)n;
            }
            close(fd);
        }
    }
    if (request->method == YD_BINARY_METHOD_HEAD) {
        free(result.body);
        result.body = NULL;
        result.message.body_length = 0;
    }
    pthread_mutex_lock(&c->lock);
    c->active--;
    pthread_cond_broadcast(&c->changed);
    pthread_mutex_unlock(&c->lock);
    return result;
}
static bool reserve(void *arg, size_t length) {
    Context *c = arg;
    assert(length > 2097152);
    pthread_mutex_lock(&c->lock);
    bool success = !c->deny_upload && c->upload + length <= 64U * 1024U * 1024U;
    if (success) {
        c->upload += length;
        c->reserved++;
    }
    pthread_mutex_unlock(&c->lock);
    return success;
}
static void release(void *arg, size_t length) {
    Context *c = arg;
    pthread_mutex_lock(&c->lock);
    assert(c->upload >= length && !c->closed);
    c->upload -= length;
    c->released++;
    pthread_mutex_unlock(&c->lock);
}
static void stats(Context *c) {
    pthread_mutex_lock(&c->lock);
    printf("STATS %u %u %u %u %zu %u %u %u %u %u %u %u %u %u %u %u\n", c->admitted, c->executed,
           c->active, c->peak, c->upload, c->reserved, c->released, atomic_load(&large_allocations),
           atomic_load(&want_count), atomic_load(&retry_count), atomic_load(&pressure_count),
           c->remaining_min, atomic_load(&accept_injected), atomic_load(&poll_calls),
           atomic_load(&blocked_interest), atomic_load(&reads));
    pthread_mutex_unlock(&c->lock);
}
static void *closer(void *arg) {
    Context *c = arg;
    yd_binary_runtime_close(c->runtime);
    pthread_mutex_lock(&c->lock);
    c->closed = true;
    pthread_mutex_unlock(&c->lock);
    puts("CLOSED");
    return NULL;
}
int main(int argc, char **argv) {
    if (argc != 6)
        return 2;
    struct rlimit core = {0};
    setrlimit(RLIMIT_CORE, &core);
    signal(SIGPIPE, SIG_IGN);
    setvbuf(stdout, NULL, _IOLBF, 0);
    Context c = {.lock = PTHREAD_MUTEX_INITIALIZER,
                 .changed = PTHREAD_COND_INITIALIZER,
                 .remaining_min = UINT_MAX};
    assert(strlen(argv[3]) < sizeof(c.file));
    strcpy(c.file, argv[3]);
    char error[256];
    YDTLS *tls = yd_tls_binary_new(argv[1], argv[2], NULL, error, sizeof(error));
    assert(tls);
    YDBinaryRuntimeOptions options = {.address.s_addr = htonl(INADDR_LOOPBACK),
                                      .io_timeout_ms = (unsigned)atoi(argv[4]),
                                      .max_body = (size_t)strtoull(argv[5], NULL, 10),
                                      .tls = tls,
                                      .context = &c,
                                      .admit = admit,
                                      .execute = execute,
                                      .reserve_upload = reserve,
                                      .release_upload = release};
    const char *fault = getenv("BINARY_SESSION_START_FAILURE");
    if (fault) {
        unsigned before = fd_count();
        unsigned code = (unsigned)atoi(fault);
        atomic_store(&startup_fault, code);
        if (code == 7)
            options.execute = NULL;
        c.runtime = yd_binary_runtime_start(&options, error, sizeof(error));
        assert(!c.runtime && error[0] && fd_count() == before);
        assert(atomic_load(&threads_created) == atomic_load(&threads_joined));
        assert(!yd_binary_runtime_healthy(NULL) && yd_binary_runtime_port(NULL) == 0);
        yd_binary_runtime_close(NULL);
        yd_tls_free(tls);
        puts("STARTUP CLEAN");
        return 0;
    }
    c.runtime = yd_binary_runtime_start(&options, error, sizeof(error));
    assert(c.runtime && yd_binary_runtime_healthy(c.runtime));
    printf("PORT %u\n", yd_binary_runtime_port(c.runtime));
    char line[128];
    pthread_t closing;
    while (fgets(line, sizeof(line), stdin)) {
        if (!strcmp(line, "stats\n"))
            stats(&c);
        else if (!strcmp(line, "endgate\n")) {
            atomic_store(&end_held, 0);
            atomic_store(&hold_end, 1);
            puts("END GATED");
        } else if (!strcmp(line, "endunblock\n")) {
            atomic_store(&hold_end, 0);
            puts("END UNBLOCKED");
        } else if (!strcmp(line, "terminalstats\n")) {
            pthread_mutex_lock(&c.lock);
            printf("TERMINAL STATS %u %u\n", c.producer_finished, c.producer_closed);
            pthread_mutex_unlock(&c.lock);
        } else if (!strcmp(line, "health\n"))
            printf("HEALTH %u\n", yd_binary_runtime_healthy(c.runtime));
        else if (!strncmp(line, "acceptfault ", 12)) {
            unsigned code, count;
            assert(sscanf(line + 12, "%u %u", &code, &count) == 2);
            atomic_store(&accept_error, code);
            atomic_store(&accept_faults, count);
            puts("ACCEPTFAULT SET");
        } else if (!strncmp(line, "release ", 8)) {
            pthread_mutex_lock(&c.lock);
            c.permits += (unsigned)atoi(line + 8);
            pthread_cond_broadcast(&c.changed);
            pthread_mutex_unlock(&c.lock);
            puts("RELEASED");
        } else if (!strcmp(line, "close\n")) {
            assert(!c.closing);
            c.closing = true;
            assert(pthread_create(&closing, NULL, closer, &c) == 0);
            puts("CLOSING");
        } else if (!strcmp(line, "want\n")) {
            atomic_store(&forced_want, 1);
            puts("WANT SET");
        } else if (!strcmp(line, "wantread\n")) {
            atomic_store(&forced_want, 2);
            puts("WANTREAD SET");
        } else if (!strcmp(line, "short\n")) {
            atomic_store(&short_write, 1);
            puts("SHORT SET");
        } else if (!strcmp(line, "pressure\n")) {
            atomic_store(&rx_pressure, 1);
            atomic_store(&tx_pressure, 1);
            puts("PRESSURE SET");
        } else if (!strcmp(line, "failalloc\n")) {
            atomic_store(&fail_large, 1);
            puts("FAILALLOC SET");
        } else if (!strcmp(line, "denyupload\n")) {
            pthread_mutex_lock(&c.lock);
            c.deny_upload = true;
            pthread_mutex_unlock(&c.lock);
            puts("DENYUPLOAD SET");
        } else if (!strncmp(line, "advance ", 8)) {
            atomic_fetch_add(&advance_ms, strtoull(line + 8, NULL, 10));
            puts("ADVANCED");
        } else if (!strcmp(line, "quit\n"))
            break;
    }
    pthread_mutex_lock(&c.lock);
    c.permits += 100;
    pthread_cond_broadcast(&c.changed);
    pthread_mutex_unlock(&c.lock);
    if (c.closing)
        pthread_join(closing, NULL);
    else
        yd_binary_runtime_close(c.runtime);
    assert(c.upload == 0 && c.reserved == c.released && atomic_load(&tickets) == 0);
    yd_tls_free(tls);
    pthread_cond_destroy(&c.changed);
    pthread_mutex_destroy(&c.lock);
    return 0;
}
