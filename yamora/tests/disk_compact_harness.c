/* Online compaction and in-place format upgrade against the actual native
 * library: no replacement storage, documents, indexes, feed or history code. */
#define _GNU_SOURCE
#include "disk_api.h"
#include "disk_bulk.h"
#include "disk_compact.h"
#include "disk_history.h"
#include "disk_internal.h"
#include "storage_budget.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define CACHE 65536U
#define LIVE 120U
#define CHURN 240U
/* Profile 8 retains a history root per commit; fewer rounds keep it bounded. */
#define ROUNDS(store) ((store)->profile == 8 ? 3U : 6U)
#define BATCH 40U

static char error[512];
#define REQUIRE(name, condition) do { if (!(condition)) { \
    fprintf(stderr, "ASSERT %s (line %d): %s\n", name, __LINE__, error); exit(2); } } while (0)

typedef struct {
    int profile;
    YDStorageBudget *budget;
    YDDisk *disk;
    YDDiskAPI api;
    const char *root;
} Store;

static void sleep_ms(unsigned ms) {
    struct timespec t = {.tv_sec = ms / 1000U, .tv_nsec = (long)(ms % 1000U) * 1000000L};
    while (nanosleep(&t, &t) && errno == EINTR) {}
}
static YDDiskReply call(Store *s, const char *method, const char *target, const char *body) {
    return yd_disk_api_request(&s->api, method, target, (const unsigned char *)body,
        body ? strlen(body) : 0, NULL, NULL, false);
}
static YDDiskReply call_id(Store *s, const char *method, const char *target, const char *body) {
    unsigned char id[16];
    REQUIRE("REQUEST_ID", getrandom(id, sizeof(id), 0) == (ssize_t)sizeof(id));
    return yd_disk_api_request_with_id(&s->api, method, target, (const unsigned char *)body,
        body ? strlen(body) : 0, NULL, NULL, false, id);
}
static void expect(Store *s, const char *method, const char *target, const char *body, int a, int b) {
    YDDiskReply r = call(s, method, target, body);
    if (r.status != a && r.status != b)
        snprintf(error, sizeof(error), "%s %s -> %d %.*s", method, target, r.status,
            (int)(r.length > 200 ? 200 : r.length), r.body ? r.body : "");
    REQUIRE("REQUEST_STATUS", r.status == a || r.status == b);
    yd_disk_reply_free(&r);
}
/* Exact authored bytes: comments, CRLF and an inline comment survive. */
static size_t document(unsigned id, unsigned version, char *out, size_t size) {
    int n = snprintf(out, size, "# authored d-%u v%u keep this comment\r\nvalue: %u # inline\n"
        "text: alpha%u beta gamma\npad: ", id, version, id, version);
    size_t at = (size_t)n, pad = 60U + (id * 37U + version * 11U) % 120U;
    for (size_t i = 0; i < pad && at + 2 < size; i++) out[at++] = (char)('a' + (id + i) % 26U);
    out[at++] = '\n';
    out[at] = 0;
    return at;
}
static size_t json_escape(const char *in, char *out) {
    size_t at = 0;
    for (; *in; in++) {
        if (*in == '\n') { out[at++] = '\\'; out[at++] = 'n'; }
        else if (*in == '\r') { out[at++] = '\\'; out[at++] = 'r'; }
        else out[at++] = *in;
    }
    out[at] = 0;
    return at;
}
static void open_store(Store *s, const char *root, int profile, bool budgeted, bool create) {
    memset(s, 0, sizeof(*s));
    s->profile = profile;
    s->root = root;
    if (budgeted) {
        s->budget = yd_storage_budget_new((YDStorageLimits){64, 64U * 1024U * 1024U, 4ULL << 30});
        REQUIRE("BUDGET", s->budget);
    }
    /* A writable open creates the profile only in an empty directory. */
    REQUIRE("ROOT_STATE", yd_disk_present(root) == (create ? 0 : 1));
    s->disk = profile == 5 ? (s->budget ? yd_disk_open_budgeted(root, true, CACHE, s->budget, error, sizeof(error)) :
            yd_disk_open(root, true, CACHE, error, sizeof(error))) :
        profile == 7 ? (s->budget ? yd_disk_open_schema_budgeted(root, true, CACHE, s->budget, error, sizeof(error)) :
            yd_disk_open_schema(root, true, CACHE, error, sizeof(error))) :
        profile == 8 ? (s->budget ? yd_disk_open_capabilities_budgeted(root, true, YD_DISK_CAP_HISTORY, CACHE, s->budget, error, sizeof(error)) :
            yd_disk_open_capabilities(root, true, YD_DISK_CAP_HISTORY, CACHE, error, sizeof(error))) :
        yd_disk_open(root, true, CACHE, error, sizeof(error));
    REQUIRE("OPEN", s->disk && yd_disk_api_init(&s->api, s->disk, false));
}
static void close_store(Store *s) {
    yd_disk_api_destroy(&s->api);
    yd_disk_close(s->disk);
    yd_storage_budget_close(s->budget);
    memset(s, 0, sizeof(*s));
}
/* Deterministic sustained write/delete churn in batched transactions. */
static void churn(Store *s, unsigned rounds) {
    size_t capacity = 128U * 4096U;
    char *body = malloc(capacity), *raw = malloc(4096), *escaped = malloc(8192);
    REQUIRE("CHURN_ALLOCATE", body && raw && escaped);
    for (unsigned r = 0; r < rounds; r++) {
        for (unsigned start = 0; start < LIVE + CHURN; start += BATCH) {
            size_t at = (size_t)snprintf(body, capacity, "{\"operations\":[");
            for (unsigned id = start; id < start + BATCH && id < LIVE + CHURN; id++) {
                document(id, r, raw, 4096);
                json_escape(raw, escaped);
                at += (size_t)snprintf(body + at, capacity - at,
                    "%s{\"collection\":\"items\",\"document\":\"d-%u\",\"put\":\"%s\"}",
                    id == start ? "" : ",", id, escaped);
            }
            snprintf(body + at, capacity - at, "]}");
            expect(s, "POST", "/v1/transactions", body, 200, 201);
        }
        for (unsigned start = LIVE; start < LIVE + CHURN; start += BATCH) {
            size_t at = (size_t)snprintf(body, capacity, "{\"operations\":[");
            for (unsigned id = start; id < start + BATCH; id++)
                at += (size_t)snprintf(body + at, capacity - at,
                    "%s{\"collection\":\"items\",\"document\":\"d-%u\",\"delete\":true}",
                    id == start ? "" : ",", id);
            snprintf(body + at, capacity - at, "]}");
            expect(s, "POST", "/v1/transactions", body, 200, 201);
        }
    }
    free(body); free(raw); free(escaped);
}
static const char *INDEXES = "{\"indexes\":[{\"collection\":\"items\",\"name\":\"by-value\","
    "\"fields\":[\"value\"],\"unique\":false}]}";
static const char *BRANCH_SOURCE = "branch: true\r\n# authored on work\r\n";
/* Profile 8 keeps the newest YD_HISTORY_COMMITS roots reachable. Small commits
 * push earlier churn out of that window, so its pages become reclaimable, as
 * any longer-running history store's would. */
static void age_history(Store *s) {
    if (s->profile != 8) return;
    char body[64];
    for (unsigned i = 0; i < YD_HISTORY_COMMITS + 8U; i++) {
        snprintf(body, sizeof(body), "tick: %u\n", i);
        expect(s, "PUT", "/v1/collections/ticks/documents/t", body, 200, 201);
    }
}
static void prepare(Store *s) {
    expect(s, "PUT", "/v1/indexes", INDEXES, 200, 201);
    churn(s, ROUNDS(s));
    if (s->profile == 8) {
        YDDiskReply made = call_id(s, "PUT", "/v1/branches/work", "{\"from\":\"main\"}");
        REQUIRE("BRANCH_CREATE", made.status == 201);
        yd_disk_reply_free(&made);
        YDDiskReply heads = call(s, "GET", "/v1/branches", NULL);
        REQUIRE("BRANCH_HEADS", heads.status == 200 && heads.body);
        char *work = strstr(heads.body, "\"name\":\"work\"");
        char *head = work ? strstr(work, "\"head\":\"") : NULL;
        REQUIRE("BRANCH_HEAD", head);
        char token[128] = {0};
        head += 8;
        for (size_t i = 0; i + 1 < sizeof(token) && head[i] && head[i] != '"'; i++) token[i] = head[i];
        yd_disk_reply_free(&heads);
        char body[512];
        snprintf(body, sizeof(body), "{\"head\":\"%s\",\"transaction\":{\"operations\":[{\"collection\":"
            "\"items\",\"document\":\"d-0\",\"put\":\"branch: true\\r\\n# authored on work\\r\\n\"}]}}", token);
        YDDiskReply wrote = call_id(s, "POST", "/v1/branches/work/transactions", body);
        if (wrote.status != 200) snprintf(error, sizeof(error), "%.*s", (int)wrote.length, wrote.body ? wrote.body : "");
        REQUIRE("BRANCH_WRITE", wrote.status == 200);
        yd_disk_reply_free(&wrote);
    }
    age_history(s);
}
static void verify_document(Store *s, const YDDiskView *view, unsigned id, unsigned version) {
    char target[96], want[4096];
    snprintf(target, sizeof(target), "/v1/collections/items/documents/d-%u", id);
    size_t n = document(id, version, want, sizeof(want));
    YDDiskReply r = view ? yd_disk_api_read_at(s->disk, view, "GET", target, NULL, 0, NULL, NULL, false) :
        call(s, "GET", target, NULL);
    if (r.status != 200 || r.length != n || memcmp(r.body, want, n))
        snprintf(error, sizeof(error), "d-%u status %d length %zu", id, r.status, r.length);
    REQUIRE("EXACT_SOURCE", r.status == 200 && r.length == n && !memcmp(r.body, want, n));
    yd_disk_reply_free(&r);
}
/* Survivors byte-exact, churned documents absent, index answers unchanged,
 * branch isolation intact, both validators pass. */
static void verify(Store *s) {
    for (unsigned id = 0; id < LIVE; id++) verify_document(s, NULL, id, ROUNDS(s) - 1);
    if (s->profile == 8) {
        YDDiskReply branch = call(s, "GET", "/v1/at/work/v1/collections/items/documents/d-0", NULL);
        REQUIRE("BRANCH_SOURCE", branch.status == 200 && branch.length == strlen(BRANCH_SOURCE) &&
            !memcmp(branch.body, BRANCH_SOURCE, branch.length));
        yd_disk_reply_free(&branch);
    }
    for (unsigned id = LIVE; id < LIVE + CHURN; id += 17) {
        char target[96];
        snprintf(target, sizeof(target), "/v1/collections/items/documents/d-%u", id);
        expect(s, "GET", target, NULL, 404, 404);
    }
    YDDiskReply q = call(s, "POST", "/v1/query/items", "{\"filter\":{\"value\":{\"$gte\":100}},\"limit\":1}");
    REQUIRE("INDEX_QUERY", q.status == 200 && q.body && strstr(q.body, "\"matched\":20"));
    yd_disk_reply_free(&q);
    YDDiskView v = yd_disk_view(s->disk);
    REQUIRE("VALIDATE", yd_disk_validate(s->disk, &v, error, sizeof(error)));
    REQUIRE("HISTORY_VALIDATE", s->profile != 8 || yd_disk_history_validate(s->disk, &v, NULL, error, sizeof(error)));
    YDDiskReply feed = call(s, "GET", "/v1/changes?limit=5", NULL);
    REQUIRE("FEED_READABLE", feed.status == 200);
    yd_disk_reply_free(&feed);
}
static uint64_t file_bytes(const char *root) {
    char path[4096];
    struct stat st;
    snprintf(path, sizeof(path), "%s/" YD_DISK_FILE, root);
    REQUIRE("STAT_NATIVE", !stat(path, &st));
    return (uint64_t)st.st_size;
}
static unsigned stages(const char *root) {
    DIR *d = opendir(root);
    REQUIRE("OPEN_ROOT", d);
    unsigned count = 0;
    for (struct dirent *e; (e = readdir(d));)
        if (!strncmp(e->d_name, YD_COMPACT_STAGE_PREFIX, strlen(YD_COMPACT_STAGE_PREFIX))) count++;
    closedir(d);
    return count;
}
static YDCompactPolicy policy(void) {
    YDCompactPolicy p = yd_compact_policy_defaults();
    p.cache_bytes = 262144;
    return p;
}
static int compact(Store *s, const YDCompactPolicy *p, YDCompactControl *control) {
    int root = open(s->root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    REQUIRE("ROOT_FD", root >= 0);
    int result = yd_disk_compact_online(s->disk, root, p, control, error, sizeof(error));
    close(root);
    return result;
}
/* Changes page bytes up to and including next_after: every retained
 * transaction, its token and the resume token stay exact across compaction. */
static char *feed_prefix(Store *s, const char *after, size_t *n) {
    char target[160];
    snprintf(target, sizeof(target), "/v1/changes?after=%s&limit=20", after);
    YDDiskReply r = call(s, "GET", target, NULL);
    char *end = r.body ? strstr(r.body, ",\"oldest_after\"") : NULL;
    REQUIRE("FEED_PAGE", r.status == 200 && end && strstr(r.body, "\"has_more\":true"));
    *n = (size_t)(end - r.body);
    char *copy = malloc(*n);
    REQUIRE("FEED_COPY", copy);
    memcpy(copy, r.body, *n);
    yd_disk_reply_free(&r);
    return copy;
}
static void oldest(Store *s, char token[64]) {
    YDDiskReply r = call(s, "GET", "/v1/changes?limit=1", NULL);
    char *at = r.body ? strstr(r.body, "\"oldest_after\":\"") : NULL;
    REQUIRE("FEED_OLDEST", r.status == 200 && at);
    at += 16;
    size_t i = 0;
    for (; i < 63 && at[i] != '"'; i++) token[i] = at[i];
    token[i] = 0;
    yd_disk_reply_free(&r);
}

/* Sustained traffic while compaction runs. */
typedef struct {
    Store *store;
    atomic_bool stop, failed;
    atomic_ulong writes, reads;
    unsigned written[64];
} Load;
/* Writer iterations (about 1.2 commits each). With every other commit of a
 * run, this stays inside the 4,096-commit feed window, so the frames the
 * retained-feed checks read are never rotated out. Without the cap, a slow
 * sanitizer copy of profile 8 let the writer pass that window. */
#define WRITES 1500U
static void *writer(void *argument) {
    Load *l = argument;
    char target[96], body[128];
    for (unsigned i = 0; !atomic_load(&l->stop); i++) {
        if (i >= WRITES) { sleep_ms(1); continue; }
        unsigned slot = i % 64U;
        snprintf(target, sizeof(target), "/v1/collections/live/documents/w-%u", slot);
        snprintf(body, sizeof(body), "# concurrent\nslot: %u\nround: %u\n", slot, i);
        YDDiskReply r = call(l->store, "PUT", target, body);
        if (r.status != 200 && r.status != 201) atomic_store(&l->failed, true);
        else { l->written[slot] = i + 1; atomic_fetch_add(&l->writes, 1); }
        yd_disk_reply_free(&r);
        if (i % 5U == 4U) {
            unsigned gone = (slot + 7U) % 64U;
            if (!l->written[gone]) continue;
            snprintf(target, sizeof(target), "/v1/collections/live/documents/w-%u", gone);
            r = call(l->store, "DELETE", target, NULL);
            if (r.status != 200 && r.status != 204) atomic_store(&l->failed, true);
            else l->written[gone] = 0;
            yd_disk_reply_free(&r);
        }
    }
    return NULL;
}
static void *reader(void *argument) {
    Load *l = argument;
    char target[96], want[4096];
    for (unsigned i = 0; !atomic_load(&l->stop); i++) {
        unsigned id = i % LIVE;
        snprintf(target, sizeof(target), "/v1/collections/items/documents/d-%u", id);
        size_t n = document(id, ROUNDS(l->store) - 1, want, sizeof(want));
        YDDiskReply r = call(l->store, "GET", target, NULL);
        if (r.status != 200 || r.length != n || memcmp(r.body, want, n)) atomic_store(&l->failed, true);
        yd_disk_reply_free(&r);
        if (i % 16U == 0) {
            r = call(l->store, "POST", "/v1/query/items", "{\"filter\":{\"value\":{\"$gte\":100}},\"limit\":1}");
            if (r.status != 200 || !r.body || !strstr(r.body, "\"matched\":20")) atomic_store(&l->failed, true);
            yd_disk_reply_free(&r);
        }
        atomic_fetch_add(&l->reads, 1);
    }
    return NULL;
}
static void verify_load(Store *s, const Load *l) {
    for (unsigned slot = 0; slot < 64U; slot++) {
        char target[96], want[128];
        snprintf(target, sizeof(target), "/v1/collections/live/documents/w-%u", slot);
        YDDiskReply r = call(s, "GET", target, NULL);
        if (!l->written[slot]) REQUIRE("CONCURRENT_DELETE_DURABLE", r.status == 404);
        else {
            int n = snprintf(want, sizeof(want), "# concurrent\nslot: %u\nround: %u\n", slot, l->written[slot] - 1);
            REQUIRE("CONCURRENT_WRITE_DURABLE", r.status == 200 && r.length == (size_t)n && !memcmp(r.body, want, (size_t)n));
        }
        yd_disk_reply_free(&r);
    }
}

/* The exact {"name":...,"head":"<token>"} entry of one branch in both lists. */
static bool same_head(const YDDiskReply *a, const YDDiskReply *b, const char *name) {
    char needle[96];
    int k = snprintf(needle, sizeof(needle), "{\"name\":\"%s\",\"head\":\"", name);
    const char *x = a->body ? strstr(a->body, needle) : NULL, *y = b->body ? strstr(b->body, needle) : NULL;
    const char *xe = x ? strchr(x + k, '"') : NULL, *ye = y ? strchr(y + k, '"') : NULL;
    snprintf(error, sizeof(error), "branch %s: %.200s | %.200s", name, a->body ? a->body : "",
        b->body ? b->body : "");
    return xe && ye && xe - x == ye - y && xe - x > k && !memcmp(x, y, (size_t)(xe - x));
}
static void mode_online(const char *root, int profile) {
    Store s;
    open_store(&s, root, profile, true, true);
    prepare(&s);
    verify(&s);
    char start[64];
    oldest(&s, start);
    size_t feed_n = 0;
    char *feed = feed_prefix(&s, start, &feed_n);
    YDDiskView before = yd_disk_view(s.disk);
    /* Retained readers: a pin, a raw view and (profiles 5/7) a checkpoint. */
    YDDisk *pin = yd_disk_pin(s.disk, CACHE, error, sizeof(error));
    REQUIRE("PIN", pin);
    YDDiskView pinned = yd_disk_view(pin);
    YDDiskCheckpoint *checkpoint = profile == 8 ? NULL : yd_disk_checkpoint_open(s.disk, error, sizeof(error));
    REQUIRE("CHECKPOINT", profile == 8 || checkpoint);
    YDDiskReply heads = call(&s, "GET", "/v1/branches", NULL);
    uint64_t size_before = file_bytes(root);

    Load load = {.store = &s};
    pthread_t threads[2];
    REQUIRE("LOAD_START", !pthread_create(&threads[0], NULL, writer, &load) &&
        !pthread_create(&threads[1], NULL, reader, &load));
    sleep_ms(50);
    unsigned long writes_before = atomic_load(&load.writes), reads_before = atomic_load(&load.reads);
    YDCompactControl control;
    REQUIRE("CONTROL", yd_compact_control_init(&control));
    YDCompactPolicy p = policy();
    int result = compact(&s, &p, &control);
    unsigned long writes_during = atomic_load(&load.writes) - writes_before;
    unsigned long reads_during = atomic_load(&load.reads) - reads_before;
    sleep_ms(50);
    atomic_store(&load.stop, true);
    pthread_join(threads[0], NULL);
    pthread_join(threads[1], NULL);
    if (result != 1) {
        size_t used = strlen(error);
        snprintf(error + used, sizeof(error) - used, " (rounds %llu attempts %llu pause %llu ms pages %llu "
            "records %llu writes %lu)", (unsigned long long)control.status.rounds,
            (unsigned long long)control.status.pause_attempts, (unsigned long long)control.status.pause_ms,
            (unsigned long long)control.status.pages, (unsigned long long)control.status.records, writes_during);
    }
    REQUIRE("COMPACTED", result == 1);
    REQUIRE("LOAD_CORRECT", !atomic_load(&load.failed));
    REQUIRE("TRAFFIC_DURING_COMPACTION", writes_during > 0 && reads_during > 0);
    REQUIRE("NO_STAGE_LEFT", !stages(root));
    REQUIRE("EPOCH_ADVANCED", yd_disk_view(s.disk).epoch == before.epoch + 1);
    REQUIRE("STATUS", control.status.state == YD_COMPACT_SUCCEEDED && control.status.reclaimed_bytes > 0 &&
        control.status.size_before > control.status.size_after && control.status.rounds >= 1);

    /* Captured views keep reading the superseded file during grace. */
    verify_document(&s, &before, 5, ROUNDS(&s) - 1);
    YDDiskReply old = yd_disk_api_read_at(pin, &pinned, "GET", "/v1/collections/items/documents/d-7",
        NULL, 0, NULL, NULL, false);
    char want[4096];
    size_t n = document(7, ROUNDS(&s) - 1, want, sizeof(want));
    REQUIRE("PIN_READS_OLD_FILE", old.status == 200 && old.length == n && !memcmp(old.body, want, n));
    yd_disk_reply_free(&old);
    if (checkpoint) {
        unsigned char page[YD_DISK_PAGE];
        YDDiskView decoded;
        REQUIRE("CHECKPOINT_READS_OLD_FILE", yd_disk_checkpoint_read(checkpoint, 0, page, sizeof(page), error, sizeof(error)) &&
            yd_disk_decode_header(page, yd_disk_checkpoint_view(checkpoint).end, &decoded));
        yd_disk_checkpoint_close(checkpoint);
    }
    yd_disk_close(pin);

    /* Retained feed, tokens and branch heads are exact. */
    size_t after_n = 0;
    char *after = feed_prefix(&s, start, &after_n);
    REQUIRE("FEED_EXACT", after_n == feed_n && !memcmp(after, feed, feed_n));
    free(after);
    if (profile == 8) {
        /* Main advanced with the concurrent writer; the idle branch did not. */
        YDDiskReply now = call(&s, "GET", "/v1/branches", NULL);
        REQUIRE("BRANCH_HEAD_EXACT", heads.status == 200 && now.status == 200 && same_head(&heads, &now, "work"));
        yd_disk_reply_free(&now);
    }
    yd_disk_reply_free(&heads);
    verify(&s);
    verify_load(&s, &load);

    /* The superseded file closes once idle; its ledger extent is retired. */
    REQUIRE("RETIRED_COLLECTED", yd_disk_retired_collect(s.disk, true) == 0);
    YDStorageUsage usage;
    REQUIRE("LEDGER_ONE_EXTENT", yd_storage_budget_usage(s.budget, &usage) && usage.extents == 1);
    uint64_t size_after = file_bytes(root);
    snprintf(error, sizeof(error), "before %llu at switch %llu after %llu copied %llu",
        (unsigned long long)size_before, (unsigned long long)control.status.size_before,
        (unsigned long long)size_after, (unsigned long long)control.status.bytes_copied);
    /* The writer keeps appending while the copy runs. In profile 8 its commits
     * can outweigh the prepared store, and the retained feed window and history
     * roots keep them, so that file is held to halving from its size at the
     * switch. The reuse cycles below bound it once the writer stops. Other
     * profiles must also halve from their size before the run. */
    REQUIRE("FILE_SHRANK", size_after * 2 < control.status.size_before &&
        (profile == 8 || size_after * 2 < size_before));

    /* Freed space is reused under sustained churn. Each compaction reclaims
     * most growth since the previous one; only the retained feed window and
     * live data remain, so garbage never accumulates across cycles. Profile 8
     * validates all its retained roots in every run, so it takes one cycle. */
    uint64_t previous = size_after, first_grown = 0, compacted = 0;
    for (unsigned cycle = 0; cycle < (profile == 8 ? 1U : 2U); cycle++) {
        churn(&s, ROUNDS(&s));
        age_history(&s);
        uint64_t grown = file_bytes(root);
        if (cycle == 0) first_grown = grown;
        REQUIRE("RECOMPACT", compact(&s, &p, &control) == 1);
        REQUIRE("RECOLLECT", yd_disk_retired_collect(s.disk, true) == 0);
        compacted = file_bytes(root);
        snprintf(error, sizeof(error), "previous %llu grown %llu compacted %llu",
            (unsigned long long)previous, (unsigned long long)grown, (unsigned long long)compacted);
        REQUIRE("REUSED_SPACE", grown > previous && compacted < grown &&
            (grown - compacted) * 5 >= (grown - previous) * 2);
        previous = compacted;
    }
    snprintf(error, sizeof(error), "first grown %llu final %llu", (unsigned long long)first_grown,
        (unsigned long long)compacted);
    REQUIRE("BOUNDED_PEAK", compacted < first_grown);
    verify(&s);
    verify_load(&s, &load);
    yd_compact_control_destroy(&control);
    close_store(&s);

    /* Restart from the compacted root. */
    open_store(&s, root, profile, true, false);
    verify(&s);
    verify_load(&s, &load);
    size_t restart_n = 0;
    char *restart = feed_prefix(&s, start, &restart_n);
    REQUIRE("FEED_EXACT_AFTER_RESTART", restart_n == feed_n && !memcmp(restart, feed, feed_n));
    free(restart);
    free(feed);
    expect(&s, "PUT", "/v1/collections/items/documents/after", "after: restart\n", 201, 201);
    close_store(&s);
    printf("online compaction verified profile=%d before=%llu after=%llu grown=%llu final=%llu\n", profile,
        (unsigned long long)size_before, (unsigned long long)size_after, (unsigned long long)first_grown,
        (unsigned long long)compacted);
}

/* Kill-point driver: prepare, compact (killed by YAMORA_COMPACT_KILL_AT) and
 * restart recovery. */
static void mode_prepare(const char *root, int profile) {
    Store s;
    open_store(&s, root, profile, false, true);
    prepare(&s);
    verify(&s);
    close_store(&s);
    printf("prepared size=%llu\n", (unsigned long long)file_bytes(root));
}
static void mode_compact(const char *root, int profile) {
    Store s;
    open_store(&s, root, profile, false, false);
    YDCompactControl control;
    REQUIRE("CONTROL", yd_compact_control_init(&control));
    YDCompactPolicy p = policy();
    int result = compact(&s, &p, &control);
    printf("compact result=%d\n", result);
    yd_compact_control_destroy(&control);
    close_store(&s);
    exit(result == 1 ? 3 : 4); /* reaching here means the kill hook never fired */
}
static void mode_recover(const char *root, int profile) {
    int fd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    REQUIRE("ROOT", fd >= 0);
    int removed = yd_disk_compact_recover(fd, error, sizeof(error));
    close(fd);
    REQUIRE("RECOVER", removed >= 0 && !stages(root));
    Store s;
    open_store(&s, root, profile, false, false);
    verify(&s);
    uint64_t before = file_bytes(root);
    YDCompactControl control;
    REQUIRE("CONTROL", yd_compact_control_init(&control));
    YDCompactPolicy p = policy();
    REQUIRE("COMPACT_AFTER_RECOVERY", compact(&s, &p, &control) == 1 && !stages(root));
    REQUIRE("COLLECT", yd_disk_retired_collect(s.disk, true) == 0);
    verify(&s);
    yd_compact_control_destroy(&control);
    close_store(&s);
    printf("recovered removed=%d before=%llu after=%llu\n", removed, (unsigned long long)before,
        (unsigned long long)file_bytes(root));
}

/* Cancellation, busy writers and refused handles change nothing. */
static void mode_controls(const char *root) {
    Store s;
    open_store(&s, root, 5, true, true);
    prepare(&s);
    YDDiskView view = yd_disk_view(s.disk);
    uint64_t size = file_bytes(root);
    YDCompactControl control;
    REQUIRE("CONTROL", yd_compact_control_init(&control));
    YDCompactPolicy p = policy();
    atomic_store(&control.cancel, true);
    REQUIRE("CANCELLED", compact(&s, &p, &control) == -1 && control.status.state == YD_COMPACT_CANCELLED &&
        !stages(root) && file_bytes(root) == size && yd_disk_view(s.disk).epoch == view.epoch);
    atomic_store(&control.cancel, false);

    p.drain_ms = 5;
    YDDiskTxn *open_txn = yd_disk_begin(s.disk, error, sizeof(error));
    REQUIRE("OPEN_TXN", open_txn);
    REQUIRE("BUSY", compact(&s, &p, &control) == 0 && control.status.state == YD_COMPACT_BUSY &&
        control.status.pause_attempts == 8 && !stages(root) && yd_disk_view(s.disk).epoch == view.epoch);
    yd_disk_abort(open_txn);
    verify(&s);

    /* Wrong root directory and a read-only handle are refused. */
    char other[4096];
    snprintf(other, sizeof(other), "%s/../other-root", root);
    REQUIRE("OTHER_ROOT", !mkdir(other, 0700) || errno == EEXIST);
    int wrong = open(other, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    REQUIRE("WRONG_ROOT_REFUSED", wrong >= 0 && yd_disk_compact_online(s.disk, wrong, &p, &control, error, sizeof(error)) == -1 &&
        strstr(error, "private standalone"));
    close(wrong);
    YDDisk *pin = yd_disk_pin(s.disk, CACHE, error, sizeof(error));
    int fd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    REQUIRE("READER_REFUSED", pin && yd_disk_compact_online(pin, fd, &p, &control, error, sizeof(error)) == -1);
    close(fd);
    yd_disk_close(pin);

    /* Background owner: operator start, held cursor, then fail-closed views. */
    YDCompactPolicy q = policy();
    q.grace_ms = 0;
    YDCompactor *k = yd_compactor_new(s.disk, root, &q, error, sizeof(error));
    REQUIRE("COMPACTOR", k && yd_compactor_supported(k));
    YDDiskView captured = yd_disk_view(s.disk);
    YDDiskCursor *cursor = yd_disk_cursor(s.disk, &captured, "D", 1, false, error, sizeof(error));
    REQUIRE("CURSOR", cursor);
    unsigned char key[YD_DISK_KEY_LIMIT];
    size_t key_n = 0;
    uint64_t value = 0;
    REQUIRE("CURSOR_FIRST", yd_disk_next(cursor, key, sizeof(key), &key_n, &value, error, sizeof(error)) == 1);
    REQUIRE("START", yd_compactor_start(k, error, sizeof(error)) == 1);
    YDCompactStatus status;
    for (unsigned i = 0; i < 6000; i++) {
        yd_compactor_status(k, &status);
        if (status.state != YD_COMPACT_RUNNING) break;
        sleep_ms(10);
    }
    REQUIRE("BACKGROUND_SUCCEEDED", status.state == YD_COMPACT_SUCCEEDED && status.runs == 1 && !status.automatic);
    REQUIRE("SUPERSEDED", yd_disk_view(s.disk).epoch == captured.epoch + 1);
    sleep_ms(1200); /* at least one owner tick past the zero grace */
    REQUIRE("HELD_BY_CURSOR", yd_disk_retired_collect(s.disk, false) == 1);
    unsigned remaining = 0;
    while (yd_disk_next(cursor, key, sizeof(key), &key_n, &value, error, sizeof(error)) == 1 && key[0] == 'D')
        remaining++;
    REQUIRE("HELD_CURSOR_COMPLETE", remaining > 0);
    YDDiskReply held = yd_disk_api_read_at(s.disk, &captured, "GET", "/v1/collections/items/documents/d-3",
        NULL, 0, NULL, NULL, false);
    REQUIRE("HELD_FILE_READS", held.status == 200);
    yd_disk_reply_free(&held);
    yd_disk_cursor_free(cursor);
    REQUIRE("RELEASED", yd_disk_retired_collect(s.disk, false) == 0);
    unsigned char doc_key[] = "Ditems";
    uint64_t ignored = 0;
    YDDiskReply stale = yd_disk_api_read_at(s.disk, &captured, "GET", "/v1/collections/items/documents/d-3",
        NULL, 0, NULL, NULL, false);
    REQUIRE("STALE_VIEW_FAILS_CLOSED", stale.status != 200);
    yd_disk_reply_free(&stale);
    error[0] = 0;
    REQUIRE("STALE_GET_FAILS_CLOSED", yd_disk_get(s.disk, &captured, doc_key, sizeof(doc_key) - 1, &ignored,
        error, sizeof(error)) == -1 && strstr(error, "superseded"));
    REQUIRE("CANCEL_IDLE", !yd_compactor_cancel(k));
    yd_compactor_free(k);
    verify(&s);
    yd_compact_control_destroy(&control);
    close_store(&s);
    puts("compaction controls verified");
}

/* Upgrade fixtures: a real store relabelled to an older superblock format.
 * Format 2 predates the change feed, so its feed namespace is removed. */
static void relabel(const char *root, unsigned format) {
    char path[4096];
    snprintf(path, sizeof(path), "%s/" YD_DISK_FILE, root);
    int fd = open(path, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    REQUIRE("RELABEL_OPEN", fd >= 0);
    for (unsigned slot = 0; slot < 2; slot++) {
        unsigned char page[YD_DISK_PAGE];
        REQUIRE("RELABEL_READ", pread(fd, page, sizeof(page), (off_t)slot * YD_DISK_PAGE) == (ssize_t)sizeof(page));
        page[7] = (unsigned char)('0' + format);
        uint32_t crc = yd_disk_crc(page, YD_DISK_PAGE - 4);
        for (unsigned i = 0; i < 4; i++) page[YD_DISK_PAGE - 4 + i] = (unsigned char)(crc >> (8 * i));
        REQUIRE("RELABEL_WRITE", pwrite(fd, page, sizeof(page), (off_t)slot * YD_DISK_PAGE) == (ssize_t)sizeof(page));
    }
    REQUIRE("RELABEL_SYNC", !fsync(fd) && !close(fd));
}
static void drop_feed(Store *s) {
    YDDiskTxn *txn = yd_disk_begin_exclusive(s->disk, error, sizeof(error));
    REQUIRE("DROP_BEGIN", txn);
    txn->log_enabled = false;
    unsigned char keys[256][16];
    size_t sizes[256], count = 0;
    YDDiskCursor *cursor = yd_disk_tx_cursor(txn, "\0YL", 3, false, error, sizeof(error));
    REQUIRE("DROP_CURSOR", cursor);
    unsigned char key[YD_DISK_KEY_LIMIT];
    size_t n = 0;
    uint64_t value = 0;
    while (yd_disk_next(cursor, key, sizeof(key), &n, &value, error, sizeof(error)) == 1 &&
        n >= 3 && !memcmp(key, "\0YL", 3)) {
        REQUIRE("DROP_BOUND", count < 256 && n <= 16);
        memcpy(keys[count], key, n);
        sizes[count++] = n;
    }
    yd_disk_cursor_free(cursor);
    for (size_t i = 0; i < count; i++) REQUIRE("DROP_KEY", yd_disk_delete(txn, keys[i], sizes[i], error, sizeof(error)));
    REQUIRE("DROP_COMMIT", count && yd_disk_commit(txn, error, sizeof(error)));
}
static void mode_legacy(const char *root, unsigned format) {
    Store s;
    open_store(&s, root, 5, false, true);
    expect(&s, "PUT", "/v1/indexes", INDEXES, 200, 201);
    churn(&s, 2);
    if (format == 2) drop_feed(&s);
    close_store(&s);
    relabel(root, format);
    printf("legacy fixture format=%u\n", format);
}
static void verify_upgraded(const char *root, bool fresh_feed) {
    Store s;
    open_store(&s, root, 5, false, false);
    REQUIRE("FORMAT5", yd_disk_view(s.disk).format == 5);
    for (unsigned id = 0; id < LIVE; id++) verify_document(&s, NULL, id, 1);
    YDDiskReply q = call(&s, "POST", "/v1/query/items", "{\"filter\":{\"value\":{\"$gte\":100}},\"limit\":1}");
    REQUIRE("UPGRADED_INDEX", q.status == 200 && q.body && strstr(q.body, "\"matched\":20"));
    yd_disk_reply_free(&q);
    /* A format-5 limit beyond the old 256 KiB document bound now applies. */
    size_t big = 300U * 1024U;
    char *body = malloc(big + 16);
    REQUIRE("BIG_ALLOCATE", body);
    int at = snprintf(body, big + 16, "big: ");
    memset(body + at, 'x', big - (size_t)at - 1);
    body[big - 1] = '\n';
    body[big] = 0;
    expect(&s, "PUT", "/v1/collections/items/documents/big", body, 200, 201);
    free(body);
    /* The feed records the first write after the upgrade, including a format
     * 2 root that had no feed before. */
    char first[64], target[160];
    oldest(&s, first);
    snprintf(target, sizeof(target), "/v1/changes?after=%s&limit=100", first);
    YDDiskReply feed = call(&s, "GET", target, NULL);
    REQUIRE("UPGRADED_FEED", feed.status == 200 && feed.body && strstr(feed.body, "\"document\":\"big\"") &&
        (!fresh_feed || strstr(feed.body, "\"document\":\"d-0\"") == NULL));
    yd_disk_reply_free(&feed);
    YDDiskView v = yd_disk_view(s.disk);
    REQUIRE("UPGRADED_VALIDATE", yd_disk_validate(s.disk, &v, error, sizeof(error)));
    close_store(&s);
}
/* Format 5 JSON spells tab, CR and LF as two-character escapes where formats
 * 3 and 4 use six-character u0009, u000d and u000a escapes. Rewrite those to
 * the short form, escape by escape, so an upgraded page must otherwise match
 * byte for byte. Decoded strings are identical either way. */
static size_t short_escapes(char *text, size_t n) {
    size_t out = 0;
    for (size_t at = 0; at < n;) {
        if (text[at] == '\\' && at + 5 < n && text[at + 1] == 'u' && !memcmp(text + at + 2, "000", 3) &&
            (text[at + 5] == '9' || text[at + 5] == 'a' || text[at + 5] == 'd')) {
            text[out++] = '\\';
            text[out++] = text[at + 5] == '9' ? 't' : text[at + 5] == 'a' ? 'n' : 'r';
            at += 6;
        } else if (text[at] == '\\' && at + 1 < n) {
            text[out++] = text[at++];
            text[out++] = text[at++];
        } else text[out++] = text[at++];
    }
    return out;
}
static bool same_feed(char *before, size_t before_n, char *after, size_t after_n) {
    before_n = short_escapes(before, before_n);
    after_n = short_escapes(after, after_n);
    size_t at = 0;
    while (at < before_n && at < after_n && after[at] == before[at]) at++;
    int left = (int)(before_n - at < 60 ? before_n - at : 60), right = (int)(after_n - at < 60 ? after_n - at : 60);
    snprintf(error, sizeof(error), "before %zu after %zu differ at %zu: %.*s | %.*s", before_n, after_n, at,
        left, before + at, right, after + at);
    return before_n == after_n && at == before_n;
}
/* Retained feed bytes of a readable 3/4 root, or NULL. */
static char *feed_before(const char *root, char token[64], size_t *n) {
    Store s = {0};
    s.disk = yd_disk_open(root, false, CACHE, error, sizeof(error));
    if (!s.disk) return NULL;
    char *copy = NULL;
    uint32_t format = yd_disk_view(s.disk).format;
    if ((format == 3 || format == 4) && yd_disk_api_init(&s.api, s.disk, false)) {
        oldest(&s, token);
        copy = feed_prefix(&s, token, n);
        yd_disk_api_destroy(&s.api);
    }
    yd_disk_close(s.disk);
    return copy;
}
static void mode_upgrade(const char *root, bool expect_refusal) {
    char token[64];
    size_t feed_n = 0;
    char *feed = expect_refusal ? NULL : feed_before(root, token, &feed_n);
    int fd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    REQUIRE("ROOT", fd >= 0);
    YDDiskUpgradeInfo info;
    int result = yd_disk_upgrade_root(fd, CACHE, NULL, &info, error, sizeof(error));
    close(fd);
    if (feed && result >= 0) {
        Store s;
        open_store(&s, root, 5, false, false);
        size_t after_n = 0;
        char *after = feed_prefix(&s, token, &after_n);
        REQUIRE("UPGRADE_FEED_EXACT", same_feed(feed, feed_n, after, after_n));
        free(after);
        close_store(&s);
    }
    free(feed);
    if (expect_refusal) {
        REQUIRE("REFUSED", result == -1);
        printf("refused: %s\n", error);
        return;
    }
    REQUIRE("UPGRADE", result >= 0);
    /* Only a format 5 to 8 root may report current; older roots end at 5. */
    snprintf(error, sizeof(error), "result %d from %u to %u", result, info.from, info.to);
    REQUIRE("UPGRADE_TARGET", info.from >= 5 ? result == 0 && info.to == info.from :
        result == 1 && info.to == 5);
    printf("upgrade result=%d from=%u to=%u generation=%llu resumed=%d\n", result, info.from, info.to,
        (unsigned long long)info.generation, (int)info.resumed);
    if (info.to == 5) verify_upgraded(root, info.from == 2);
}
static void mode_live(const char *root) {
    Store s;
    open_store(&s, root, 0, false, false);
    uint32_t from = yd_disk_view(s.disk).format;
    REQUIRE("LIVE_FROM", from == 3 || from == 4);
    expect(&s, "PUT", "/v1/collections/items/documents/live", "live: before\n", 201, 201);
    char token[64];
    size_t feed_n = 0, after_n = 0;
    oldest(&s, token);
    char *feed = feed_prefix(&s, token, &feed_n);
    YDDiskUpgradeInfo info;
    YDDiskTxn *open_txn = yd_disk_begin(s.disk, error, sizeof(error));
    REQUIRE("LIVE_BUSY", open_txn && yd_disk_upgrade_live(s.disk, 5, &info, error, sizeof(error)) == -2 &&
        yd_disk_view(s.disk).format == from);
    yd_disk_abort(open_txn);
    REQUIRE("LIVE_UPGRADE", yd_disk_upgrade_live(s.disk, 250, &info, error, sizeof(error)) == 1 &&
        info.from == from && info.to == 5 && yd_disk_view(s.disk).format == 5);
    REQUIRE("LIVE_CURRENT", yd_disk_upgrade_live(s.disk, 250, &info, error, sizeof(error)) == 0);
    char *after = feed_prefix(&s, token, &after_n);
    REQUIRE("LIVE_FEED_EXACT", same_feed(feed, feed_n, after, after_n));
    free(after);
    free(feed);
    expect(&s, "PUT", "/v1/collections/items/documents/live", "live: after\n", 200, 200);
    close_store(&s);
    verify_upgraded(root, false);
    printf("live upgrade verified from=%u\n", from);
}

int main(int argc, char **argv) {
    if (argc < 3) return 2;
    int cancellation;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancellation)) return 2;
    const char *mode = argv[1], *root = argv[2];
    int profile = argc > 3 ? atoi(argv[3]) : 5;
    if (!strcmp(mode, "online")) mode_online(root, profile);
    else if (!strcmp(mode, "prepare")) mode_prepare(root, profile);
    else if (!strcmp(mode, "compact")) mode_compact(root, profile);
    else if (!strcmp(mode, "recover")) mode_recover(root, profile);
    else if (!strcmp(mode, "controls")) mode_controls(root);
    else if (!strcmp(mode, "legacy")) mode_legacy(root, (unsigned)profile);
    else if (!strcmp(mode, "upgrade")) mode_upgrade(root, false);
    else if (!strcmp(mode, "refuse")) mode_upgrade(root, true);
    else if (!strcmp(mode, "live")) mode_live(root);
    else return 2;
    return 0;
}
