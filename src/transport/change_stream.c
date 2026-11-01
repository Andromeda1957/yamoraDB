#define _POSIX_C_SOURCE 200809L
#include "change_stream.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct YDChangeStream {
    YDDisk *disk;
    YDChangeStreamPage read_page;
    void *context;
    unsigned timeout_ms;
    YDDiskView view;
    YDDiskReply page;
    char after[53];
    unsigned limit, duration, heartbeat;
    uint64_t pull_end, pull_at;
    bool pulled, pull_done, pull_more;
    char delivered_after[53];
};
static uint64_t now(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) return 0;
    return (uint64_t)t.tv_sec * 1000 + (uint64_t)t.tv_nsec / 1000000;
}
static bool number(const char *text, unsigned low, unsigned high, unsigned *out) {
    unsigned value = 0;
    if (!*text) return false;
    for (; *text; text++) {
        if (*text < '0' || *text > '9' || value > high / 10) return false;
        value = value * 10 + (unsigned)(*text - '0');
        if (value > high) return false;
    }
    if (value < low) return false;
    *out = value; return true;
}
static bool options(YDChangeStream *s, const char *target) {
    const char prefix[] = "/v1/changes/stream?";
    if (strncmp(target, prefix, sizeof(prefix)-1) || strlen(target) > 1024) return false;
    char copy[1025]; strcpy(copy, target + sizeof(prefix)-1);
    char *p = copy; unsigned seen = 0;
    while (*p) {
        char *next = strchr(p, '&');
        if (next) *next++ = 0;
        char *value = strchr(p, '=');
        if (!value || !value[1]) return false;
        *value++ = 0;
        unsigned flag = 0;
        if (!strcmp(p, "after")) {
            flag = 1;
            if (strlen(value) != 52) return false;
            strcpy(s->after, value);
        } else if (!strcmp(p, "limit")) {
            flag = 2; if (!number(value, 1, 100, &s->limit)) return false;
        } else if (!strcmp(p, "duration_ms")) {
            flag = 4; if (!number(value, 100, 30000, &s->duration)) return false;
        } else if (!strcmp(p, "heartbeat_ms")) {
            flag = 8; if (!number(value, 100, 5000, &s->heartbeat)) return false;
        } else return false;
        if (seen & flag) return false;
        seen |= flag;
        if (next && !*next) return false;
        p = next ? next : p + strlen(p);
    }
    return (seen & 1) != 0;
}
static YDDiskReply page(YDChangeStream *s, unsigned timeout_ms) {
    char target[128];
    snprintf(target, sizeof(target), "/v1/changes?after=%s&limit=%u", s->after, s->limit);
    if (s->read_page) return s->read_page(s->context, target, timeout_ms);
    s->view = yd_disk_view(s->disk);
    YDDiskReply reply = yd_disk_changes_request(s->disk, &s->view, target);
    yd_disk_revision(&s->view, reply.revision);
    return reply;
}
static YDChangeStream *open_stream(YDDisk *disk, YDChangeStreamPage read_page, void *context,
    unsigned timeout_ms, const char *target, YDDiskReply *error) {
    if (!target || (!disk && !read_page) || !timeout_ms || timeout_ms > 30000) {
        *error = yd_disk_error_reply(400, "invalid_change_stream"); return NULL;
    }
    YDChangeStream *s = calloc(1, sizeof(*s));
    if (!s) { *error = yd_disk_error_reply(503, "allocation_failed"); return NULL; }
    *s = (YDChangeStream){.disk=disk, .read_page=read_page, .context=context,
        .timeout_ms=timeout_ms, .limit=100, .duration=30000, .heartbeat=1000};
    if (!options(s, target)) {
        *error = yd_disk_error_reply(400, "invalid_change_stream"); free(s); return NULL;
    }
    s->page = page(s, timeout_ms);
    if (s->page.status != 200) { *error = s->page; free(s); return NULL; }
    return s;
}
YDChangeStream *yd_change_stream_open(YDDisk *disk, const char *target, YDDiskReply *error) {
    return open_stream(disk, NULL, NULL, 30000, target, error);
}
YDChangeStream *yd_change_stream_open_source(YDChangeStreamPage read_page, void *context,
    unsigned timeout_ms, const char *target, YDDiskReply *error) {
    return open_stream(NULL, read_page, context, timeout_ms, target, error);
}
static YDDiskReply terminal_page(YDChangeStream *s, YDDiskReply *reply) {
    const char *detail = reply->body ? reply->body : "{}";
    size_t length = reply->body ? reply->length : 2;
    if (length > 512) { detail = "{}"; length = 2; }
    while (length && (detail[length-1] == '\n' || detail[length-1] == '\r')) length--;
    char text[1024];
    int n = snprintf(text, sizeof(text), "{\"terminal\":true,\"status\":%d,\"after\":\"%s\",\"detail\":%.*s}",
        reply->status, s->after, (int)length, detail);
    YDDiskReply result = {.status = reply->status, .content_type = "application/x-ndjson"};
    memcpy(result.revision, reply->revision, sizeof(result.revision));
    if (n > 0 && (size_t)n < sizeof(text)) {
        result.body = malloc((size_t)n + 1);
        if (result.body) { memcpy(result.body, text, (size_t)n + 1); result.length = (size_t)n; }
    }
    yd_disk_reply_free(reply);
    return result;
}
YDChangePull yd_change_stream_pull(YDChangeStream *s, unsigned remaining_ms,
    size_t limit, YDDiskReply *out, unsigned *wait_ms) {
    *out = (YDDiskReply){0};
    *wait_ms = 0;
    if (s->pull_done) return YD_CHANGE_END;
    uint64_t at = now();
    if (!s->pulled) {
        unsigned duration = remaining_ms > 100 ? remaining_ms - 100 : 0;
        if (duration > s->duration) duration = s->duration;
        s->pull_end = at + duration;
    }
    else {
        /* The caller invokes pull only after successful delivery. Neither the
         * checkpoint/tip nor a partially sent page advances this cursor. */
        if (s->delivered_after[0]) {
            strcpy(s->after, s->delivered_after);
            s->delivered_after[0] = 0;
        }
        if (!at || at >= s->pull_end || !remaining_ms) return YD_CHANGE_END;
        if (at < s->pull_at) {
            *wait_ms = (unsigned)(s->pull_at - at);
            return YD_CHANGE_WAIT;
        }
        unsigned timeout = remaining_ms < s->timeout_ms ? remaining_ms : s->timeout_ms;
        if (s->pull_end - at < timeout) timeout = (unsigned)(s->pull_end - at);
        s->page = page(s, timeout);
        /* A final acquisition can consume the remaining producer duration.
         * Duration completion is END, rather than a spurious backend failure
         * caused only by that deliberately shortened acquisition budget. */
        if (s->page.status != 200 && now() >= s->pull_end) {
            yd_disk_reply_free(&s->page);
            s->pull_done = true;
            return YD_CHANGE_END;
        }
    }
    bool initial = !s->pulled;
    s->pulled = true;
    if (s->page.status == 200 && s->page.length >= limit) {
        char revision[17]; memcpy(revision, s->page.revision, sizeof(revision));
        yd_disk_reply_free(&s->page);
        s->page = yd_disk_error_reply(413, "binary_feed_byte_limit");
        memcpy(s->page.revision, revision, sizeof(revision));
    }
    if (s->page.status != 200) {
        s->pull_done = true;
        if (initial) { *out = s->page; s->page = (YDDiskReply){0}; }
        else *out = terminal_page(s, &s->page);
        return YD_CHANGE_PAGE;
    }
    strcpy(s->delivered_after, s->page.resume_after);
    s->pull_more = s->page.has_more;
    s->pull_at = at + (s->pull_more ? 0 : s->heartbeat);
    if (s->pull_at > s->pull_end) s->pull_at = s->pull_end;
    *out = s->page;
    s->page = (YDDiskReply){0};
    return YD_CHANGE_PAGE;
}
static int wait_page(YDChangeStream *s, unsigned ms,
                     const volatile sig_atomic_t *running) {
    if (s->disk) return yd_disk_wait_changed(s->disk, s->view.generation, ms);
    uint64_t at = now(), end = at + ms;
    if (!at) return -1;
    while (*running && at < end) {
        unsigned slice = end - at > 10 ? 10 : (unsigned)(end - at);
        struct timespec delay = {.tv_nsec=(long)slice * 1000000};
        /* A signal interrupts this bounded sleep; recheck shutdown and time. */
        (void)nanosleep(&delay, NULL);
        at = now();
        if (!at) return -1;
    }
    return 0;
}
static bool chunk(YDConnection *c, const char *data, size_t length) {
    char size[32];
    int n = snprintf(size, sizeof(size), "%zx\r\n", length + 1);
    /* An absolute deadline applies to this complete page, including framing.
     * Waiting for a later commit does not consume its future write budget. */
    c->write_deadline = 0;
    return n > 0 && yd_connection_send(c, size, (size_t)n) &&
           yd_connection_send(c, data, length) && yd_connection_send(c, "\n\r\n", 3);
}
static bool terminal(YDChangeStream *s, YDConnection *c, YDDiskReply *reply, size_t *bytes) {
    char text[1024];
    const char *detail = reply->body ? reply->body : "{}";
    size_t length = reply->body ? reply->length : 2;
    if (length > 512) return false;
    while (length && (detail[length - 1] == '\n' || detail[length - 1] == '\r')) length--;
    int n = snprintf(text, sizeof(text), "{\"terminal\":true,\"status\":%d,\"after\":\"%s\",\"detail\":%.*s}",
                     reply->status, s->after, (int)length, detail);
    bool valid = n > 0 && (size_t)n < sizeof(text) && chunk(c, text, (size_t)n);
    if (valid) *bytes += (size_t)n + 1;
    return valid;
}
bool yd_change_stream_send(YDChangeStream *s, YDConnection *c,
                            const volatile sig_atomic_t *running, size_t *bytes) {
    char header[512];
    int n = snprintf(header, sizeof(header), "HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\n"
                     "Transfer-Encoding: chunked\r\nConnection: close\r\nCache-Control: no-store\r\n"
                     "X-Content-Type-Options: nosniff\r\nX-YamlDB-Revision: %s\r\n\r\n", s->page.revision);
    *bytes = 0;
    if (n <= 0 || (size_t)n >= sizeof(header) || !yd_connection_send(c, header, (size_t)n)) return false;
    uint64_t end = now() + s->duration;
    bool valid = true;
    while (valid && *running) {
        size_t length = s->page.length;
        if (length && s->page.body[length - 1] == '\n') length--;
        valid = chunk(c, s->page.body, length);
        if (!valid) break;
        *bytes += length + 1;
        strcpy(s->after, s->page.resume_after);
        bool more = s->page.has_more;
        yd_disk_reply_free(&s->page);
        uint64_t at = now();
        if (at >= end) break;
        if (!more) {
            unsigned wait = (unsigned)(end - at);
            if (wait > s->heartbeat) wait = s->heartbeat;
            int changed = wait_page(s, wait, running);
            if (!*running) break;
            if (changed < 0) {
                s->page = yd_disk_error_reply(503, "change_stream_stopped");
                valid = terminal(s, c, &s->page, bytes);
                break;
            }
        }
        at = now();
        if (!*running || at >= end) break;
        unsigned timeout_ms = end - at < s->timeout_ms ? (unsigned)(end - at) : s->timeout_ms;
        s->page = page(s, timeout_ms);
        if (s->page.status != 200) { valid = terminal(s, c, &s->page, bytes); break; }
    }
    if (valid) { c->write_deadline = 0; valid = yd_connection_send(c, "0\r\n\r\n", 5); }
    return valid;
}
void yd_change_stream_free(YDChangeStream *s) {
    if (!s) return;
    yd_disk_reply_free(&s->page); free(s);
}
