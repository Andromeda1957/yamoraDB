/* Test-only callback gate, linked with:
 *   -Wl,--wrap=yd_binary_runtime_start_with_identity
 *
 * Interpose BEFORE the daemon execute callback copies its identity argument.
 * Gating yd_access_identify_certificate is too late: binary_execute has already
 * copied the evidence into its stack Request at that point. No identity bytes
 * are read by this gate before the controller releases the callback.
 *
 * One runtime per test daemon. No environment configuration means passthrough.
 * A socketpair carries P + big-endian call number, R to resume, then D +
 * big-endian status + 16 revision bytes after the real callback completes.
 * Controller EOF releases a held callback during cleanup.
 */
#define _POSIX_C_SOURCE 200809L
#include "../src/transport/binary_session.h"
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static YDBinaryIdentityExecute execute_callback;
static int gate_fd = -1;
static unsigned gate_nth;
static atomic_uint calls;
void yd_binary_test_page_operation(const YDBinaryRequestMessage *request);

static uint64_t milliseconds(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return 0;
    return (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
}
static bool transfer(int fd, void *buffer, size_t length, bool writing) {
    uint64_t end = milliseconds() + 15000;
    unsigned char *bytes = buffer;
    while (length) {
        uint64_t now = milliseconds();
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
static long setting(const char *name, long maximum) {
    const char *value = getenv(name);
    if (!value) return -1;
    char *end = NULL;
    errno = 0;
    long number = strtol(value, &end, 10);
    return errno || !*value || *end || number < 1 || number > maximum ? -1 : number;
}
static YDBinaryReply gated_execute(void *context, const YDBinaryRequestMessage *request,
    const YDTLSClientIdentity *identity, const unsigned char *body, size_t length,
    unsigned remaining_ms) {
    bool selected = false, resumed = true;
    if (request->method == YD_BINARY_METHOD_PUT &&
        !strcmp(request->target, "/v1/collections/allowed/documents/detached")) {
        unsigned call = atomic_fetch_add_explicit(&calls, 1, memory_order_relaxed) + 1;
        selected = call == gate_nth;
        if (selected) {
            unsigned char event[5] = {'P', (unsigned char)(call >> 24),
                (unsigned char)(call >> 16), (unsigned char)(call >> 8), (unsigned char)call};
            unsigned char resume = 0;
            resumed = transfer(gate_fd, event, sizeof(event), true) &&
                transfer(gate_fd, &resume, 1, false) && resume == 'R';
        }
    }
    yd_binary_test_page_operation(request);
    YDBinaryReply reply = execute_callback(context, request, identity, body, length, remaining_ms);
    yd_binary_test_page_operation(NULL);
    if (selected) {
        unsigned char event[19] = {resumed ? 'D' : 'F', (unsigned char)(reply.message.status >> 8),
            (unsigned char)reply.message.status};
        memcpy(event + 3, reply.message.revision, 16);
        (void)transfer(gate_fd, event, sizeof(event), true);
        close(gate_fd);
    }
    return reply;
}
YDBinaryRuntime *__real_yd_binary_runtime_start_with_identity(const YDBinaryRuntimeOptions *,
    YDBinaryIdentityAdmit, YDBinaryIdentityExecute, char *, size_t);
YDBinaryRuntime *__wrap_yd_binary_runtime_start_with_identity(const YDBinaryRuntimeOptions *options,
    YDBinaryIdentityAdmit admit, YDBinaryIdentityExecute execute, char *error, size_t length) {
    long fd = setting("YAMORA_CERTIFICATE_GATE_FD", INT_MAX);
    long nth = setting("YAMORA_CERTIFICATE_GATE_NTH", 128);
    if (!execute || ((fd < 3 || nth < 1) && !getenv("YAMORA_BINARY_PAGE_GATE_FD")))
        return __real_yd_binary_runtime_start_with_identity(options, admit, execute, error, length);
    gate_fd = (int)fd;
    gate_nth = (unsigned)nth;
    execute_callback = execute;
    atomic_init(&calls, 0);
    return __real_yd_binary_runtime_start_with_identity(options, admit, gated_execute, error, length);
}
