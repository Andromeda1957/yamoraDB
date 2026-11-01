#define _POSIX_C_SOURCE 200809L
#include "session2_hooks.h"

#ifdef YD_RAFT_SESSION2_TEST_HOOKS
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

typedef struct {
    uint64_t call;
    unsigned node;
    unsigned char id[16];
    bool overlapped;
} Active;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t changed = PTHREAD_COND_INITIALIZER;
static Active active[256];
static uint64_t serial;

static uint64_t now(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) return 0;
    return (uint64_t)t.tv_sec * 1000000000 + (uint64_t)t.tv_nsec;
}
static uint64_t token(void) {
    uint64_t time = now();
    if (time > serial) serial = time;
    return ++serial;
}
static void hex_id(const unsigned char id[16], char text[33]) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < 16; i++) {
        text[i * 2] = digits[id[i] >> 4];
        text[i * 2 + 1] = digits[id[i] & 15];
    }
    text[32] = 0;
}
static bool regular(int fd) {
    struct stat st;
    return fd >= 0 && !fstat(fd, &st) && S_ISREG(st.st_mode) && st.st_nlink == 1 &&
        st.st_uid == geteuid() && (st.st_mode & 07777) == 0600;
}
static int control(void) {
    const char *path = getenv("YAMORA_SESSION2_CONTROL");
    if (!path || !*path) return -1;
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    struct stat st;
    if (fd >= 0 && !fstat(fd, &st) && S_ISDIR(st.st_mode) && st.st_uid == geteuid() &&
        (st.st_mode & 07777) == 0700) return fd;
    if (fd >= 0) close(fd);
    return -1;
}
/* Return -1 for unsafe/malformed, 0 absent, positive byte count otherwise. */
static int read_control(const char *name, char bytes[65]) {
    int dir = control();
    if (dir < 0) return -1;
    int fd = openat(dir, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    int saved = errno;
    close(dir);
    if (fd < 0) return saved == ENOENT ? 0 : -1;
    if (!regular(fd)) { close(fd); return -1; }
    ssize_t size;
    do { size = read(fd, bytes, 65); } while (size < 0 && errno == EINTR);
    close(fd);
    if (size < 0 || size >= 65) return -1;
    bytes[size] = 0;
    return (int)size;
}
static bool event(unsigned node, const char *name, const char *fields) {
    const char *path = getenv("YAMORA_SESSION2_TRACE");
    if (!path || !*path) return false;
    int fd = open(path, O_WRONLY | O_APPEND | O_CLOEXEC | O_NOFOLLOW);
    if (!regular(fd)) { if (fd >= 0) close(fd); return false; }
    char line[768];
    int length = snprintf(line, sizeof(line),
        "{\"version\":1,\"event\":\"%s\",\"node\":%u,\"monotonic_ns\":%llu%s}\n",
        name, node, (unsigned long long)now(), fields);
    bool valid = length > 0 && (size_t)length < sizeof(line);
    ssize_t written = -1;
    if (valid) do { written = write(fd, line, (size_t)length); } while (written < 0 && errno == EINTR);
    close(fd);
    return valid && written == length;
}
static bool mutation_event(unsigned node, const char *name, const char *id, uint64_t call) {
    char fields[160];
    snprintf(fields, sizeof(fields), ",\"request_id\":\"%s\",\"call\":%llu", id,
             (unsigned long long)call);
    return event(node, name, fields);
}
uint64_t yd_session2_mutation_enter(unsigned node, const unsigned char id[16], bool *allowed) {
    if (allowed) *allowed = true;
    if (!getenv("YAMORA_SESSION2_TRACE") && !getenv("YAMORA_SESSION2_CONTROL")) return 0;
    if (!allowed || !id || !node || node > 9) { if (allowed) *allowed = false; return 0; }
    pthread_mutex_lock(&mutex);
    Active *slot = NULL;
    for (size_t i = 0; i < 256; i++) if (!active[i].call) { slot = &active[i]; break; }
    char text[33], wanted[65];
    hex_id(id, text);
    int length = read_control("overlap-id", wanted);
    if (!slot || length < 0 || (length && length != 32)) {
        *allowed = false; pthread_mutex_unlock(&mutex); return 0;
    }
    if (length) for (int i = 0; i < 32; i++)
        if (!((wanted[i] >= '0' && wanted[i] <= '9') || (wanted[i] >= 'a' && wanted[i] <= 'f')))
            *allowed = false;
    *slot = (Active){.call = token(), .node = node};
    memcpy(slot->id, id, 16);
    uint64_t call = slot->call;
    *allowed = *allowed && mutation_event(node, "mutation_enter", text, call);
    if (*allowed && length == 32 && !memcmp(wanted, text, 32)) {
        for (size_t i = 0; i < 256; i++) {
            if (&active[i] != slot && active[i].call && active[i].node == node &&
                !memcmp(active[i].id, id, 16)) {
                active[i].overlapped = slot->overlapped = true;
            }
        }
        pthread_cond_broadcast(&changed);
        struct timespec deadline = {0};
        bool timed = !clock_gettime(CLOCK_REALTIME, &deadline);
        deadline.tv_sec += 3;
        while (timed && !slot->overlapped)
            if (pthread_cond_timedwait(&changed, &mutex, &deadline)) timed = false;
        char fields[160];
        snprintf(fields, sizeof(fields), ",\"request_id\":\"%s\",\"active\":%u",
                 text, slot->overlapped ? 2 : 1);
        *allowed = event(node, slot->overlapped ? "gate_pass" : "gate_timeout", fields) &&
            slot->overlapped;
    }
    pthread_mutex_unlock(&mutex);
    return call;
}
void yd_session2_mutation_exit(unsigned node, const unsigned char id[16], uint64_t call) {
    if (!call || !id) return;
    pthread_mutex_lock(&mutex);
    char text[33];
    hex_id(id, text);
    mutation_event(node, "mutation_exit", text, call);
    for (size_t i = 0; i < 256; i++)
        if (active[i].call == call && active[i].node == node) active[i] = (Active){0};
    pthread_cond_broadcast(&changed);
    pthread_mutex_unlock(&mutex);
}
void yd_session2_disk_delay(unsigned node) {
    if (!getenv("YAMORA_SESSION2_CONTROL")) return;
    char bytes[65];
    int size = read_control("disk-delay-ms", bytes);
    if (size <= 0 || size > 4) return;
    unsigned value = 0;
    for (int i = 0; i < size; i++) {
        if (i == size - 1 && bytes[i] == '\n') break;
        if (bytes[i] < '0' || bytes[i] > '9') return;
        value = value * 10 + (unsigned)(bytes[i] - '0');
    }
    if (!value || value > 250) return;
    char fields[80];
    snprintf(fields, sizeof(fields), ",\"delay_ms\":%u", value);
    pthread_mutex_lock(&mutex);
    event(node, "disk_delay", fields);
    pthread_mutex_unlock(&mutex);
    struct timespec delay = {.tv_sec = 0, .tv_nsec = (long)value * 1000000};
    while (nanosleep(&delay, &delay) && errno == EINTR) {}
}
void yd_session2_index_hold(unsigned node, const unsigned char id[16]) {
    if (!id || !getenv("YAMORA_SESSION2_CONTROL")) return;
    char wanted[65], text[33];
    hex_id(id, text);
    if (read_control("index-hold", wanted) != 32 || memcmp(wanted, text, 32)) return;
    pthread_mutex_lock(&mutex);
    mutation_event(node, "index_hold", text, 0);
    pthread_mutex_unlock(&mutex);
    uint64_t start = now();
    while (start && now() - start < UINT64_C(3000000000) &&
        read_control("index-hold", wanted) == 32 && !memcmp(wanted, text, 32)) {
        struct timespec delay = {.tv_nsec = 10000000};
        while (nanosleep(&delay, &delay) && errno == EINTR) {}
    }
}
static bool kind_valid(const char *kind) {
    return kind && (!strcmp(kind, "journal_compaction") ||
        !strcmp(kind, "application_compaction") || !strcmp(kind, "checkpoint"));
}
static void maintenance(unsigned node, const char *name, const char *kind, uint64_t cycle) {
    char fields[160];
    snprintf(fields, sizeof(fields), ",\"kind\":\"%s\",\"cycle\":%llu", kind,
        (unsigned long long)cycle);
    event(node, name, fields);
}
uint64_t yd_session2_maintenance_begin(unsigned node, const char *kind) {
    if (!kind_valid(kind) || !getenv("YAMORA_SESSION2_TRACE")) return 0;
    pthread_mutex_lock(&mutex);
    uint64_t cycle = token();
    maintenance(node, "maintenance_begin", kind, cycle);
    pthread_mutex_unlock(&mutex);
    return cycle;
}
void yd_session2_maintenance_end(unsigned node, const char *kind, uint64_t cycle) {
    if (!cycle || !kind_valid(kind)) return;
    pthread_mutex_lock(&mutex);
    maintenance(node, "maintenance_end", kind, cycle);
    pthread_mutex_unlock(&mutex);
}
#endif
