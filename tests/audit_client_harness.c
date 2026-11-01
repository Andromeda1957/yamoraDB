#define _GNU_SOURCE
#include "audit_client.h"
#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/wait.h>
#include <sys/socket.h>
static bool delayed_reply;
ssize_t __real_recvmsg(int fd, struct msghdr *message, int flags);
ssize_t __wrap_recvmsg(int fd, struct msghdr *message, int flags) {
    ssize_t result = __real_recvmsg(fd, message, flags);
    if (delayed_reply && result > 0) {
        struct timespec delay = {.tv_nsec = 400000000};
        (void)nanosleep(&delay, NULL);
    }
    return result;
}
typedef struct { YDAuditClient *client; YDAuditEvent event; YDAuditResult result; } Concurrent;
static void *wait_begin(void *value) {
    Concurrent *c = value; YDAuditLease lease;
    c->result = yd_audit_client_begin(c->client, &c->event, yd_audit_clock_ms() + 2000, &lease);
    return NULL;
}
int main(int argc, char **argv) {
    if (argc != 4) return 2;
    if (!strcmp(argv[3], "constructor") && yd_audit_client_open(argv[1],
        (uid_t)strtoul(argv[2], NULL, 10), yd_audit_clock_ms() + 2000) != NULL) {
        fputs("ASSERTION:AUDIT_CLIENT_CONSTRUCTOR_CANCEL_CONTRACT\n", stderr); _Exit(2);
    }
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL)) return 2;
    YDAuditClient *client = yd_audit_client_open(argv[1], (uid_t)strtoul(argv[2], NULL, 10), yd_audit_clock_ms() + 2000);
    if (!client) { puts("DENIED"); return 0; }
    YDAuditEvent event = {.transport = YD_AUDIT_HTTP, .authentication = YD_AUDIT_STATIC,
        .operation = YD_AUDIT_QUERY, .actor = "fixture"};
    YDAuditLease lease;
    if (!strcmp(argv[3], "late")) {
        delayed_reply = true;
        memset(&lease, 0xa5, sizeof(lease));
        YDAuditResult late = yd_audit_client_begin(client, &event, yd_audit_clock_ms() + 100, &lease);
        YDAuditLease empty = {0};
        if (late != YD_AUDIT_UNCERTAIN || memcmp(&lease, &empty, sizeof(lease))) {
            fputs("ASSERTION:AUDIT_LATE_ACK_MUST_NOT_DISPATCH\n", stderr); _Exit(2);
        }
        delayed_reply = false;
        if (yd_audit_client_begin(client, &event, yd_audit_clock_ms() + 2000, &lease) != YD_AUDIT_UNCERTAIN) return 3;
        yd_audit_client_close(client); puts("LATE_OK"); return 0;
    }
    if (!strcmp(argv[3], "lock")) {
        Concurrent context = {.client = client, .event = event}; pthread_t thread;
        if (pthread_create(&thread, NULL, wait_begin, &context)) return 3;
        /* The controller releases this only after the fake helper actually
         * receives the first BEGIN, proving that thread owns the mutex. */
        (void)getchar();
        uint64_t start = yd_audit_clock_ms();
        YDAuditResult second = yd_audit_client_begin(client, &event, start + 100, &lease);
        uint64_t elapsed = yd_audit_clock_ms() - start;
        if (second != YD_AUDIT_REFUSED || elapsed > 750) {
            fputs("ASSERTION:AUDIT_MUTEX_DEADLINE\n", stderr); _Exit(2);
        }
        if (pthread_join(thread, NULL) || context.result != YD_AUDIT_UNCERTAIN) return 3;
        yd_audit_client_close(client); puts("LOCK_OK"); return 0;
    }
    if (!strcmp(argv[3], "idle")) {
        struct timespec pause = {.tv_sec = 2, .tv_nsec = 200000000};
        (void)nanosleep(&pause, NULL);
    }
    if (!strcmp(argv[3], "capacity")) {
        YDAuditLease leases[8];
        for (unsigned i = 0; i < 8; i++)
            if (yd_audit_client_begin(client, &event, yd_audit_clock_ms() + 2000, &leases[i]) != YD_AUDIT_OK) return 3;
        if (yd_audit_client_begin(client, &event, yd_audit_clock_ms() + 2000, &lease) != YD_AUDIT_BUSY) return 3;
        YDAuditCompletion done = {.outcome = YD_AUDIT_RETURNED_SUCCESS, .status = 200};
        for (unsigned i = 0; i < 8; i++)
            if (yd_audit_client_finish(client, &leases[i], &done, yd_audit_clock_ms() + 2000) != YD_AUDIT_OK) return 3;
        puts("CAPACITY_OK"); yd_audit_client_close(client); return 0;
    }
    YDAuditResult r = yd_audit_client_begin(client, &event, yd_audit_clock_ms() + 2000, &lease);
    if (r != YD_AUDIT_OK) { printf("BEGIN:%d\n", (int)r); yd_audit_client_close(client); return 0; }
    if (!strcmp(argv[3], "fork")) {
        pid_t child = fork();
        if (child < 0) return 3;
        if (!child) {
            YDAuditLease denied;
            YDAuditCompletion done = {.outcome = YD_AUDIT_RETURNED_SUCCESS, .status = 200};
            if (yd_audit_client_begin(client, &event, yd_audit_clock_ms() + 2000, &denied) != YD_AUDIT_REFUSED ||
                yd_audit_client_finish(client, &lease, &done, yd_audit_clock_ms() + 2000) != YD_AUDIT_REFUSED) _Exit(2);
            yd_audit_client_close(client); _Exit(0);
        }
        int status;
        if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status)) return 3;
    }
    if (!strcmp(argv[3], "hold")) { puts("INTENT"); fflush(stdout); (void)getchar(); }
    if (!strcmp(argv[3], "abandon")) { puts("INTENT"); yd_audit_client_close(client); return 0; }
    YDAuditCompletion completion = {.outcome = YD_AUDIT_RETURNED_SUCCESS, .status = 200};
    r = yd_audit_client_finish(client, &lease, &completion, yd_audit_clock_ms() + 2000);
    printf("FINISH:%d\n", (int)r);
    if (r == YD_AUDIT_OK && yd_audit_client_finish(client, &lease, &completion, yd_audit_clock_ms() + 2000) != YD_AUDIT_REFUSED) return 3;
    yd_audit_client_close(client); return 0;
}
