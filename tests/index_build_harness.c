#define _POSIX_C_SOURCE 200809L
#include "../src/disk_index_build.h"
#include "../src/disk_bulk.h"
#include "../src/disk_changes.h"
#include "../src/disk_internal.h"
#include "../src/disk_log.h"
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

/* Faults are armed only inside a child after its pre-existing store is open. */
static unsigned fail_sync, sync_calls;
int __real_fsync(int descriptor);
int __wrap_fsync(int descriptor) {
    if (++sync_calls == fail_sync) { errno = EIO; return -1; }
    return __real_fsync(descriptor);
}

static const char *catalog = "{indexes: [{collection: items, name: number, fields: [n], unique: true},"
                             "{collection: items, name: words, fields: [$source], type: text}]}";
static const char *old_catalog = "{indexes: [{collection: items, name: old, fields: [n]}]}";
typedef struct {
    YDDisk *disk;
    unsigned mode, scanned, published, frames;
    bool injected, late, failed;
    YDDiskView expected;
    char error[512];
} State;
static bool apply(State *state, const YDWrite *writes, size_t count) {
    YDDiskTxn *txn = yd_disk_begin(state->disk, state->error, sizeof(state->error));
    bool ok = txn && yd_disk_apply(txn, writes, count, state->error, sizeof(state->error));
    if (ok) ok = yd_disk_commit_view(txn, &state->expected, state->error, sizeof(state->error));
    else yd_disk_abort(txn);
    return ok;
}
static bool put(State *state, const char *id, const char *body) {
    YDWrite write = {.collection = "items", .document = id, .body = (const unsigned char *)body,
                     .length = strlen(body)};
    return apply(state, &write, 1);
}
static bool replace(State *state, const char *source) {
    YDDiskTxn *txn = yd_disk_begin_exclusive(state->disk, state->error, sizeof(state->error));
    bool ok = txn && yd_disk_indexes_replace(txn, (const unsigned char *)source, strlen(source),
                                              state->error, sizeof(state->error));
    if (ok) ok = yd_disk_commit_view(txn, &state->expected, state->error, sizeof(state->error));
    else yd_disk_abort(txn);
    return ok;
}
static bool corrupt(State *state) {
    if (!put(state, "new", "n: 105\nname: rollback\n")) return false;
    YDDiskLog log;
    YDDiskView view = yd_disk_view(state->disk);
    unsigned char key[12]; uint64_t offset;
    if (yd_disk_log_load(state->disk, &view, &log, state->error, sizeof(state->error)) != 1) return false;
    yd_disk_log_key(key, log.last);
    if (yd_disk_get(state->disk, &view, key, 12, &offset, state->error, sizeof(state->error)) != 1) return false;
    size_t size = 0;
    unsigned char *frame = yd_disk_record(state->disk, &view, offset, &size, state->error, sizeof(state->error));
    if (!frame || size < 80) { free(frame); return false; }
    if (state->mode == 5) yd_disk_set64(frame + 48, log.last);
    if (state->mode == 6) yd_disk_set16(frame + 42, 257);
    if (state->mode == 7) yd_disk_set64(frame + 32, yd_disk_u64(frame + 32) + 1);
    if (state->mode == 8) frame[size - 1] = 'X';
    if (state->mode == 9) yd_disk_set16(frame + 40, 1);
    YDDiskTxn *txn = yd_disk_begin(state->disk, state->error, sizeof(state->error));
    bool ok = txn && yd_disk_append(txn, frame, size, &offset, state->error, sizeof(state->error)) &&
              yd_disk_put(txn, key, 12, offset, state->error, sizeof(state->error));
    free(frame);
    const unsigned char body[] = "n: 106\nname: another\n";
    YDWrite write = {.collection = "items", .document = "newer", .body = body, .length = sizeof(body) - 1};
    ok = ok && yd_disk_apply(txn, &write, 1, state->error, sizeof(state->error));
    if (ok) ok = yd_disk_commit_view(txn, &state->expected, state->error, sizeof(state->error));
    else yd_disk_abort(txn);
    return ok;
}
static bool inject(State *state) {
    if (state->mode == 2) return put(state, "duplicate", "n: 1\nname: duplicate\n");
    if (state->mode == 3) return replace(state, "{indexes: []}");
    if (state->mode == 4) {
        for (unsigned i = 0; i < 6; i++) {
            char id[32], body[64];
            snprintf(id, sizeof(id), "new-%u", i); snprintf(body, sizeof(body), "n: %u\n", 100 + i);
            if (!put(state, id, body)) return false;
        }
        return true;
    }
    if (state->mode >= 5 && state->mode <= 9) return corrupt(state);
    if (state->mode >= 11) return true;
    const unsigned char a[] = "n: 1\nname: rollback first\n", b[] = "n: 0\nname: rollback second\n",
                        c[] = "n: 100\nname: rollback added\n";
    YDWrite writes[] = {
        {.collection="items", .document="d00", .body=a, .length=sizeof(a)-1},
        {.collection="items", .document="d01", .body=b, .length=sizeof(b)-1},
        {.collection="items", .document="new", .body=c, .length=sizeof(c)-1},
        {.collection="items", .document="d02"},
        {.collection="empty", .kind=YD_WRITE_CREATE_COLLECTION}
    };
    return apply(state, writes, sizeof(writes) / sizeof(*writes));
}
static bool progress(void *context, const char *phase) {
    State *state = context;
    if (!strcmp(phase, "scan") && ++state->scanned == 3) {
        if (state->mode == 1) return false;
        state->injected = true;
        if (!inject(state)) { state->failed = true; return false; }
        YDDiskIndexes *visible = yd_disk_indexes_load(state->disk, &state->expected,
                                                       state->error, sizeof(state->error));
        bool ok = visible && ((state->mode == 3 && !visible->count) ||
                               (state->mode != 3 && visible->count == 1 &&
                                !strcmp(visible->indexes[0].name, "old")));
        yd_disk_indexes_free(visible);
        if (!ok) { state->failed = true; return false; }
    }
    if (!strcmp(phase, "replay") && state->mode == 10) return false;
    if (!strcmp(phase, "frame")) state->frames++;
    if (!strcmp(phase, "publish")) {
        state->published++;
        if (state->mode == 11) _exit(0);
        if (state->mode == 0 && !state->late) {
            state->late = true;
            if (!put(state, "late", "n: 101\nname: rollback late\n")) { state->failed = true; return false; }
        }
    }
    return true;
}
static bool seed(State *state) {
    char bodies[40][64], ids[40][16]; YDWrite writes[40] = {0};
    for (unsigned i = 0; i < 40; i++) {
        snprintf(ids[i], sizeof(ids[i]), "d%02u", i);
        snprintf(bodies[i], sizeof(bodies[i]), "n: %u\nname: rollback word%u\n", i, i);
        writes[i] = (YDWrite){.collection="items", .document=ids[i],
                              .body=(const unsigned char *)bodies[i], .length=strlen(bodies[i])};
    }
    return apply(state, writes, 40) && replace(state, old_catalog);
}
static bool check_case(const char *root, unsigned mode) {
    char path[4096]; snprintf(path, sizeof(path), "%s/case-%u", root, mode);
    if (mkdir(path, 0700)) return false;
    State state = {.mode=mode};
    state.disk = yd_disk_open(path, true, 32768, state.error, sizeof(state.error));
    bool ok = state.disk && seed(&state);
    if (ok && mode == 12) ok = put(&state, "duplicate", "n: 1\n");
    YDDiskView pinned = state.expected, receipt;
    YDDiskLog before;
    char token[YD_LOG_TOKEN_SIZE];
    ok = ok && yd_disk_log_load(state.disk, &pinned, &before, state.error, sizeof(state.error)) == 1;
    if (ok) yd_disk_log_token(&before, before.last, token);
    YDDiskTxn *stale = NULL;
    if (ok && mode == 0) {
        stale = yd_disk_begin(state.disk, state.error, sizeof(state.error));
        const unsigned char body[] = "n: 1\nname: stale writer\n";
        YDWrite write = {.collection="items", .document="stale", .body=body, .length=sizeof(body)-1};
        ok = stale && yd_disk_apply(stale, &write, 1, state.error, sizeof(state.error));
    }
    bool built = ok && yd_disk_indexes_online(state.disk, (const unsigned char *)catalog,
                                               strlen(catalog), progress, &state, &receipt,
                                               state.error, sizeof(state.error));
    if (mode == 0) ok = ok && built && state.late && state.published == 2 && state.frames == 2;
    else ok = ok && !built;
    ok = ok && !state.failed;
    YDDiskView current = yd_disk_view(state.disk);
    if (mode != 0) ok = ok && current.generation == state.expected.generation && current.root == state.expected.root;
    else {
        ok = ok && receipt.root == current.root && receipt.revision == current.revision;
        errno = 0;
        bool stale_committed = stale && yd_disk_commit(stale, state.error, sizeof(state.error));
        stale = NULL;
        ok = ok && !stale_committed && errno == EAGAIN && yd_disk_view(state.disk).root == current.root;
        ok = ok && !put(&state, "stale", "n: 1\nname: stale writer\n") &&
             strstr(state.error, "unique index") && yd_disk_view(state.disk).root == current.root;
        YDDiskReply changes = yd_disk_changes_request(state.disk, &current, "/v1/changes");
        yd_disk_reply_free(&changes);
        char target[128]; snprintf(target, sizeof(target), "/v1/changes?after=%s", token);
        changes = yd_disk_changes_request(state.disk, &current, target);
        ok = ok && changes.status == 200 && strstr(changes.body, "resnapshot_required\":true") &&
             strstr(changes.body, "rollback late") && strstr(changes.body, "rollback first");
        yd_disk_reply_free(&changes);
    }
    yd_disk_abort(stale);
    /* The old reader root remains complete while the latest generation has all
     * accepted concurrent writes and either the old or the new entire catalog. */
    ok = ok && yd_disk_validate(state.disk, &pinned, state.error, sizeof(state.error));
    bool validated = yd_disk_validate(state.disk, &current, state.error, sizeof(state.error));
    ok = ok && ((mode >= 5 && mode <= 9) ? !validated : validated);
    if (mode >= 5 && mode <= 9) {
        YDDiskDocument accepted;
        ok = ok && yd_disk_document_get(state.disk, &current, "items", "newer", &accepted,
                                         state.error, sizeof(state.error)) == 1;
        yd_disk_document_free(&accepted);
    }
    if (!ok) fprintf(stderr, "mode %u built=%d scans=%u frames=%u publishes=%u: %s\n",
                     mode, built, state.scanned, state.frames, state.published, state.error);
    yd_disk_close(state.disk);
    return ok;
}
static bool recovery_case(const char *root, unsigned kind) {
    char path[4096]; snprintf(path, sizeof(path), "%s/recovery-%u", root, kind);
    if (mkdir(path, 0700)) return false;
    State state = {.mode=kind ? 13 : 11};
    state.disk = yd_disk_open(path, true, 32768, state.error, sizeof(state.error));
    bool ok = state.disk && seed(&state);
    YDDiskView before = state.expected;
    yd_disk_close(state.disk);
    if (!ok) return false;
    pid_t child = fork();
    if (!child) {
        state.disk = yd_disk_open(path, true, 32768, state.error, sizeof(state.error));
        if (!state.disk) _exit(4);
        if (kind > 0 && kind <= 6) {
            char value[16]; snprintf(value, sizeof(value), "%u", kind);
            if (setenv("YAMORA_DISK_KILL_AT", value, 1)) _exit(5);
        }
        if (kind == 7 || kind == 8) { sync_calls = 0; fail_sync = kind - 6; }
        YDDiskView receipt;
        bool built = yd_disk_indexes_online(state.disk, (const unsigned char *)catalog, strlen(catalog),
                                              progress, &state, &receipt, state.error, sizeof(state.error));
        if (kind >= 7) {
            bool valid = !built && yd_disk_view(state.disk).root == before.root &&
                         strstr(state.error, "index publication failed") &&
                         (kind != 8 || !yd_disk_writable(state.disk));
            yd_disk_close(state.disk); _exit(valid ? 0 : 6);
        }
        _exit(2);
    }
    int status = 0;
    ok = child > 0 && waitpid(child, &status, 0) == child;
    ok = ok && (kind > 0 && kind <= 6 ? WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL :
                                           WIFEXITED(status) && WEXITSTATUS(status) == 0);
    state.disk = yd_disk_open(path, true, 32768, state.error, sizeof(state.error));
    YDDiskView after = state.disk ? yd_disk_view(state.disk) : (YDDiskView){0};
    ok = ok && state.disk && yd_disk_validate(state.disk, &after, state.error, sizeof(state.error));
    YDDiskIndexes *indexes = state.disk ? yd_disk_indexes_load(state.disk, &after, state.error, sizeof(state.error)) : NULL;
    bool old = indexes && indexes->count == 1 && !strcmp(indexes->indexes[0].name, "old");
    bool fresh = indexes && indexes->count == 2 && !strcmp(indexes->indexes[0].name, "number");
    ok = ok && (old || fresh);
    if (kind <= 3 || kind == 7) ok = ok && old && before.root == after.root && before.generation == after.generation;
    if (kind == 5 || kind == 6) ok = ok && fresh && after.generation == before.generation + 1;
    yd_disk_indexes_free(indexes);
    if (!ok) fprintf(stderr, "recovery %u status=%d old=%d new=%d: %s\n", kind, status, old, fresh, state.error);
    yd_disk_close(state.disk);
    return ok;
}
int main(int argc, char **argv) {
    if (argc != 2) return 1;
    for (unsigned mode = 0; mode <= 12; mode++)
        if (mode != 11 && !check_case(argv[1], mode)) return 2;
    for (unsigned kind = 0; kind <= 8; kind++)
        if (!recovery_case(argv[1], kind)) return 3;
    puts("online index interleavings verified");
    return 0;
}
