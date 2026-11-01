#define _POSIX_C_SOURCE 200809L
#include "../src/consensus/application.h"
#include "../src/consensus/application_internal.h"
#include "../src/disk_internal.h"
#include "../src/disk_bulk.h"
#include "../src/disk_log.h"
#include <stdio.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#define REQUIRE(x) do { if (!(x)) { \
    fprintf(stderr, "line %u: %s (%s)\n", __LINE__, #x, error); return 2; \
} } while (0)
static char error[512];
static const unsigned char cluster[16] = {1, 2, 3, 4};
static const unsigned char source[] = "# exact\r\ncount: 7 # keep\r\ndescription: hello world\r\n";
static const unsigned char definitions[] =
    "indexes:\n- collection: a\n  name: count\n  fields: [count]\n  unique: true\n"
    "- collection: a\n  name: description\n  fields: [description]\n  type: text\n";
static bool write_entry(YDRaftApplication *app, const char *target,
                         const unsigned char *bytes, size_t size, unsigned id) {
    YDRaftWrite write = {.method = "PUT", .target = target, .body = bytes, .size = size};
    write.id[0] = (unsigned char)id;
    YDRaftProposal proposal = {0};
    if (yd_raft_application_prepare(app, &write, &proposal, error, sizeof(error)) != 1) {
        yd_raft_proposal_free(&proposal);
        return false;
    }
    YDRaftEntry entry = {.index = yd_raft_application_position(app).index + 1, .term = 1,
                         .kind = YD_RAFT_COMMAND, .command = proposal.command, .size = proposal.size};
    bool valid = yd_raft_application_apply(app, &entry, error, sizeof(error));
    yd_raft_proposal_free(&proposal);
    return valid;
}
static YDRaftApplication *seed(const char *root, bool indexes) {
    YDRaftApplication *app = yd_raft_application_open(root, cluster, 32768, error, sizeof(error));
    if (!app)
        return NULL;
    bool valid = write_entry(app, "/v1/collections/a/documents/b", source, sizeof(source) - 1, 1);
    if (valid && indexes)
        valid = write_entry(app, "/v1/indexes", definitions, sizeof(definitions) - 1, 2);
    if (!valid) {
        yd_raft_application_close(app);
        return NULL;
    }
    return app;
}
static bool captured(YDRaftApplication *app, YDRaftCheckpoint *expected, YDDiskView *view) {
    YDDiskCheckpoint *image = yd_raft_application_checkpoint(app, expected, error, sizeof(error));
    if (!image)
        return false;
    *view = yd_disk_checkpoint_view(image);
    yd_disk_checkpoint_close(image);
    return true;
}
static bool validate(YDRaftApplication *app) {
    YDRaftCheckpoint expected;
    YDDiskView view;
    return captured(app, &expected, &view) &&
           yd_raft_application_validate(app, &expected, &view, error, sizeof(error));
}
static bool replace(YDDiskTxn *txn, const void *key, size_t key_size, const void *bytes, size_t size) {
    uint64_t offset;
    return yd_disk_append(txn, bytes, size, &offset, error, sizeof(error)) &&
           yd_disk_put(txn, key, key_size, offset, error, sizeof(error));
}
/* Publish deliberately malformed state with a consistent applied checkpoint and
 * feed. Opening it is intentionally insufficient; complete validation must fail. */
static bool publish_malformed(YDDiskTxn *txn, const YDRaftCheckpoint *prior) {
    unsigned char position[96] = {0};
    memcpy(position, "YDAPLY01", 8);
    memcpy(position + 8, cluster, 16);
    yd_disk_set64(position + 24, prior->applied.index + 1);
    yd_disk_set64(position + 32, prior->applied.term);
    yd_disk_set64(position + 40, txn->view.revision);
    memcpy(position + 48, prior->digest, 32);
    txn->log_enabled = txn->log_identity_set = true;
    memcpy(txn->log_identity, cluster, 16);
    bool valid = replace(txn, "\0YRA", 4, position, sizeof(position));
    if (valid)
        return yd_disk_commit(txn, error, sizeof(error));
    yd_disk_abort(txn);
    return false;
}
typedef struct {
    YDRaftApplication *app;
    atomic_bool done;
    bool valid;
} Writer;
static void *advance(void *context) {
    Writer *writer = context;
    writer->valid = true;
    char error[512];
    for (unsigned i = 0; i < 20 && writer->valid; i++) {
        char body[128];
        int n = snprintf(body, sizeof(body), "# later source\ncount: %u\ndescription: changed\n", i + 10);
        YDRaftWrite write = {.method = "PUT", .target = "/v1/collections/a/documents/b",
            .body = (unsigned char *)body, .size = (size_t)n};
        write.id[0] = (unsigned char)(i + 3);
        YDRaftProposal proposal = {0};
        writer->valid = yd_raft_application_prepare(writer->app, &write, &proposal, error, sizeof(error)) == 1;
        YDRaftEntry entry = {.index = i + 3, .term = 2, .kind = YD_RAFT_COMMAND,
            .command = proposal.command, .size = proposal.size};
        writer->valid = writer->valid && yd_raft_application_apply(writer->app, &entry, error, sizeof(error));
        yd_raft_proposal_free(&proposal);
    }
    atomic_store(&writer->done, true);
    return NULL;
}
static bool cancel_document(void *context, YDDiskValidationPhase phase) {
    unsigned *seen = context;
    return phase != YD_VALIDATE_DOCUMENT || ++*seen < 1;
}
static int historical(const char *root, bool concurrent) {
    YDRaftApplication *app = seed(root, true);
    REQUIRE(app);
    YDRaftCheckpoint expected;
    YDDiskCheckpoint *image = yd_raft_application_checkpoint(app, &expected, error, sizeof(error));
    REQUIRE(image);
    YDDiskView view = yd_disk_checkpoint_view(image);
    YDDisk *disk = yd_raft_application_disk(app);
    REQUIRE(yd_raft_application_validate_at(disk, &expected, &view, error, sizeof(error)));
    Writer writer = {.app = app};
    atomic_init(&writer.done, false);
    pthread_t thread;
    if (concurrent) REQUIRE(!pthread_create(&thread, NULL, advance, &writer));
    else advance(&writer);
    unsigned passes = 0;
    do {
        unsigned seen = 0;
        YDDiskValidation state = {cancel_document, &seen, false};
        REQUIRE(!yd_raft_application_validate_at_cancellable(disk, &expected, &view, &state, error, sizeof(error)) &&
            state.cancelled && seen == 1);
        REQUIRE(yd_raft_application_validate_at(disk, &expected, &view, error, sizeof(error)));
        passes++;
    } while (!atomic_load(&writer.done) || passes < 10);
    if (concurrent) REQUIRE(!pthread_join(thread, NULL));
    REQUIRE(writer.valid && yd_raft_application_position(app).index == 22 &&
        !yd_raft_application_validate(app, &expected, &view, error, sizeof(error)) && validate(app));
    YDDiskStats before = yd_disk_stats(disk);
    for (unsigned i = 0; i < 4; i++) {
        YDRaftCheckpoint wrong = expected;
        if (i == 0) wrong.cluster[0] ^= 1;
        if (i == 1) wrong.digest[0] ^= 1;
        if (i == 2) wrong.applied.index++;
        if (i == 3) wrong.applied.term++;
        REQUIRE(!yd_raft_application_validate_at(disk, &wrong, &view, error, sizeof(error)));
    }
    REQUIRE(!yd_raft_application_validate_at(NULL, &expected, &view, error, sizeof(error)) &&
        !yd_raft_application_validate_at(disk, NULL, &view, error, sizeof(error)) &&
        !yd_raft_application_validate_at(disk, &expected, NULL, error, sizeof(error)) &&
        yd_raft_application_validate_at(disk, &expected, &view, error, sizeof(error)));
    YDDiskStats after = yd_disk_stats(disk);
    REQUIRE(before.bytes_written == after.bytes_written && before.pages_written == after.pages_written);
    yd_disk_checkpoint_close(image);
    yd_raft_application_close(app);
    return 0;
}
static int basic(const char *root) {
    YDRaftApplication *app = yd_raft_application_open(root, cluster, 32768, error, sizeof(error));
    REQUIRE(app && validate(app));
    REQUIRE(write_entry(app, "/v1/collections/a/documents/b", source, sizeof(source) - 1, 1));
    REQUIRE(write_entry(app, "/v1/indexes", definitions, sizeof(definitions) - 1, 2) && validate(app));
    YDRaftEntry noop = {.index = 3, .term = 2, .kind = YD_RAFT_NOOP};
    REQUIRE(yd_raft_application_apply(app, &noop, error, sizeof(error)) && validate(app));
    yd_raft_application_close(app);
    app = yd_raft_application_open(root, cluster, 32768, error, sizeof(error));
    REQUIRE(app);
    YDDisk *disk = yd_raft_application_disk(app);
    YDDiskView before = yd_disk_view(disk);
    YDDiskStats stats = yd_disk_stats(disk);
    REQUIRE(validate(app));
    YDDiskStats after = yd_disk_stats(disk);
    REQUIRE(yd_disk_view(disk).generation == before.generation &&
            stats.pages_written == after.pages_written && stats.bytes_written == after.bytes_written);
    yd_raft_application_close(app);
    return 0;
}
static int metadata(const char *root) {
    YDRaftApplication *app = seed(root, false);
    REQUIRE(app);
    YDRaftCheckpoint expected;
    YDDiskView view;
    REQUIRE(captured(app, &expected, &view) && validate(app));
    for (unsigned i = 0; i < 8; i++) {
        YDDiskView bad = view;
        switch (i) {
        case 0: bad.format++; break;
        case 1: bad.generation++; break;
        case 2: bad.root += YD_DISK_PAGE; break;
        case 3: bad.end += YD_DISK_PAGE; break;
        case 4: bad.documents++; break;
        case 5: bad.collections++; break;
        case 6: bad.bytes++; break;
        case 7: bad.revision++; break;
        }
        REQUIRE(!yd_raft_application_validate(app, &expected, &bad, error, sizeof(error)) && validate(app));
    }
    for (unsigned i = 0; i < 4; i++) {
        YDRaftCheckpoint bad = expected;
        if (i == 0) bad.cluster[0] ^= 1;
        if (i == 1) bad.digest[0] ^= 1;
        if (i == 2) bad.applied.index++;
        if (i == 3) bad.applied.term++;
        REQUIRE(!yd_raft_application_validate(app, &bad, &view, error, sizeof(error)) && validate(app));
    }
    REQUIRE(!yd_raft_application_validate(app, NULL, &view, error, sizeof(error)) &&
            !yd_raft_application_validate(NULL, &expected, &view, error, sizeof(error)));
    YDDiskTxn *txn = yd_disk_begin(yd_raft_application_disk(app), error, sizeof(error));
    REQUIRE(txn && !yd_raft_application_validate(app, &expected, &view, error, sizeof(error)));
    yd_disk_abort(txn);
    REQUIRE(validate(app));
    yd_raft_application_close(app);
    return 0;
}
static int receipts(const char *base, bool live) {
    for (unsigned test = 0; test < (live ? 1U : 14U); test++) {
        char root[4096];
        snprintf(root, sizeof(root), "%s/r%u", base, test);
        REQUIRE(!mkdir(root, 0700));
        YDRaftApplication *app = seed(root, false);
        REQUIRE(app);
        YDRaftCheckpoint prior;
        YDDiskView view;
        REQUIRE(captured(app, &prior, &view));
        yd_raft_application_close(app);
        YDDisk *disk = yd_disk_open_cluster(root, 32768, error, sizeof(error));
        REQUIRE(disk);
        YDDiskTxn *txn = yd_disk_begin_exclusive(disk, error, sizeof(error));
        unsigned char key[20] = {0, 'Y', 'R', 'R', 1};
        uint64_t value;
        REQUIRE(txn && yd_disk_get(disk, &view, key, sizeof(key), &value, error, sizeof(error)) == 1);
        size_t size;
        unsigned char *p = yd_disk_record(disk, &view, value, &size, error, sizeof(error));
        REQUIRE(p && size >= 128);
        switch (live ? 10 : test) {
        case 0: p[0] ^= 1; break;
        case 1: p[64] ^= 1; break;
        case 2: yd_disk_set64(p + 40, 0); break;
        case 3: yd_disk_set64(p + 40, 99); break;
        case 4: yd_disk_set64(p + 48, 0); break;
        case 5: yd_disk_set64(p + 48, 99); break;
        case 6: yd_disk_set64(p + 56, size); break;
        case 7: size = 79; break;
        case 8: yd_disk_set16(p + 80, 500); break;
        case 9: p[80 + 2] = 1; break;
        case 10: p[80 + 16] = 'G'; break;
        case 11: yd_disk_set64(p + 80 + 8, 9999); break;
        case 12: yd_disk_set16(p + 80 + 32, 9999); break;
        case 13:
            REQUIRE(yd_disk_delete(txn, key, sizeof(key), error, sizeof(error)));
            key[4] = 0; p[64] = 0; break;
        }
        REQUIRE(replace(txn, key, sizeof(key), p, size));
        free(p);
        REQUIRE(publish_malformed(txn, &prior));
        yd_disk_close(disk);
        app = yd_raft_application_open(root, cluster, 32768, error, sizeof(error));
        REQUIRE(app);
        if (live) {
            const unsigned char other[] = "count: 20\n";
            YDRaftWrite request = {.id = {1}, .method = "PUT", .target = "/v1/collections/a/documents/b",
                                   .body = other, .size = sizeof(other) - 1};
            YDDiskReply reply;
            REQUIRE(yd_raft_application_receipt(app, &request, &reply, error, sizeof(error)) == -1 &&
                    yd_raft_application_failed(app));
            yd_disk_reply_free(&reply);
        } else
            REQUIRE(!validate(app));
        yd_raft_application_close(app);
    }
    return 0;
}
static int namespaces(const char *base) {
    for (unsigned test = 0; test < 7; test++) {
        char root[4096];
        snprintf(root, sizeof(root), "%s/n%u", base, test);
        REQUIRE(!mkdir(root, 0700));
        YDRaftApplication *app = seed(root, false);
        YDRaftCheckpoint prior;
        YDDiskView view;
        REQUIRE(app && captured(app, &prior, &view));
        yd_raft_application_close(app);
        YDDisk *disk = yd_disk_open_cluster(root, 32768, error, sizeof(error));
        YDDiskTxn *txn = disk ? yd_disk_begin_exclusive(disk, error, sizeof(error)) : NULL;
        REQUIRE(txn);
        if (test < 4) {
            const unsigned char *keys[] = {(unsigned char *)"unknown", (unsigned char *)"\0YRP",
                                           (unsigned char *)"\0YRAx", (unsigned char *)"\0YRR"};
            const size_t sizes[] = {7, 4, 5, 4};
            REQUIRE(yd_disk_put(txn, keys[test], sizes[test], 123, error, sizeof(error)));
        } else if (test < 6) {
            unsigned char key[12];
            yd_disk_log_key(key, test == 4 ? 1 : 999);
            REQUIRE(yd_disk_put(txn, key, sizeof(key), 123, error, sizeof(error)));
        } else {
            unsigned char key[20] = {0, 'Y', 'R', 'R', 1};
            uint64_t value;
            REQUIRE(yd_disk_get(disk, &view, key, sizeof(key), &value, error, sizeof(error)) == 1);
            size_t size;
            unsigned char *p = yd_disk_record(disk, &view, value, &size, error, sizeof(error));
            REQUIRE(p);
            for (unsigned i = 2; i <= 3; i++) {
                key[4] = (unsigned char)i; p[64] = (unsigned char)i;
                REQUIRE(replace(txn, key, sizeof(key), p, size));
            }
            free(p);
        }
        REQUIRE(publish_malformed(txn, &prior));
        yd_disk_close(disk);
        app = yd_raft_application_open(root, cluster, 32768, error, sizeof(error));
        REQUIRE(app && !validate(app));
        yd_raft_application_close(app);
    }
    return 0;
}
static int native(const char *base) {
    for (unsigned test = 0; test < 5; test++) {
        char root[4096];
        snprintf(root, sizeof(root), "%s/d%u", base, test);
        REQUIRE(!mkdir(root, 0700));
        YDRaftApplication *app = seed(root, true);
        YDRaftCheckpoint prior;
        YDDiskView view;
        REQUIRE(app && captured(app, &prior, &view));
        yd_raft_application_close(app);
        YDDisk *disk = yd_disk_open_cluster(root, 32768, error, sizeof(error));
        YDDiskTxn *txn = disk ? yd_disk_begin_exclusive(disk, error, sizeof(error)) : NULL;
        REQUIRE(txn);
        if (test == 0)
            REQUIRE(yd_disk_delete(txn, "Da\0b", 4, error, sizeof(error)));
        if (test == 1)
            REQUIRE(yd_disk_put(txn, "Ca", 2, 999, error, sizeof(error)));
        if (test == 2) {
            unsigned char key[1024], prefix = 'I';
            size_t size;
            uint64_t value;
            YDDiskCursor *cursor = yd_disk_cursor(disk, &view, &prefix, 1, false, error, sizeof(error));
            REQUIRE(cursor && yd_disk_next(cursor, key, sizeof(key), &size, &value, error, sizeof(error)) == 1 &&
                    key[0] == 'I');
            yd_disk_cursor_free(cursor);
            REQUIRE(yd_disk_delete(txn, key, size, error, sizeof(error)));
        }
        if (test == 3)
            REQUIRE(yd_disk_put(txn, "Da\0b", 4, 0, error, sizeof(error)));
        if (test == 4) {
            unsigned char key[12];
            yd_disk_log_key(key, view.generation);
            uint64_t value;
            REQUIRE(yd_disk_get(disk, &view, key, 12, &value, error, sizeof(error)) == 1);
            size_t size;
            unsigned char *p = yd_disk_record(disk, &view, value, &size, error, sizeof(error));
            REQUIRE(p && size >= 56);
            p[40] = 3;
            REQUIRE(replace(txn, key, 12, p, size));
            free(p);
        }
        REQUIRE(publish_malformed(txn, &prior));
        yd_disk_close(disk);
        app = yd_raft_application_open(root, cluster, 32768, error, sizeof(error));
        REQUIRE(app && !validate(app));
        yd_raft_application_close(app);
    }
    return 0;
}
static int large(const char *root) {
    YDRaftApplication *app = seed(root, false);
    REQUIRE(app);
    size_t size = 3U * 1024U * 1024U;
    unsigned char *bytes = malloc(size);
    REQUIRE(bytes);
    memset(bytes, 'x', size);
    bytes[0] = '#';
    const char end[] = "\ncount: 11\ndescription: large\n";
    memcpy(bytes + size - sizeof(end) + 1, end, sizeof(end) - 1);
    REQUIRE(write_entry(app, "/v1/collections/a/documents/b", bytes, size, 2) && validate(app));
    free(bytes);
    yd_raft_application_close(app);
    app = yd_raft_application_open(root, cluster, 32768, error, sizeof(error));
    REQUIRE(app && validate(app));
    yd_raft_application_close(app);
    return 0;
}
typedef struct {
    unsigned counts[6], stop, at;
} Validation;
static bool validation_progress(void *context, YDDiskValidationPhase phase) {
    Validation *p = context;
    if ((unsigned)phase >= 6) return false;
    return ++p->counts[phase] != p->at || (unsigned)phase != p->stop;
}
static int cancellable(const char *root) {
    YDRaftApplication *app = seed(root, true);
    REQUIRE(app);
    for (unsigned i = 0; i < 6; i++) {
        char target[128], body[128];
        snprintf(target, sizeof(target), "/v1/collections/a/documents/d%u", i);
        int n = snprintf(body, sizeof(body), "# exact source %u\r\ncount: %u\r\ndescription: hello world\r\n", i, i + 10);
        REQUIRE(n > 0 && write_entry(app, target, (unsigned char *)body, (size_t)n, i + 10));
    }
    YDRaftCheckpoint expected;
    YDDiskView view;
    REQUIRE(captured(app, &expected, &view));
    YDDisk *disk = yd_raft_application_disk(app);
    YDDiskStats before = yd_disk_stats(disk);
    for (unsigned mode = 0; mode < 3; mode++) {
        Validation p = {.stop = 99};
        YDDiskValidation state = {validation_progress, &p, false};
        bool valid = mode == 0 ? yd_raft_application_validate_cancellable(app, &expected, &view, &state, error, sizeof(error))
            : mode == 1 ? yd_raft_application_validate_at_cancellable(disk, &expected, &view, &state, error, sizeof(error))
            : yd_disk_validate_cancellable(disk, &view, &state, error, sizeof(error));
        REQUIRE(valid && !state.cancelled);
        for (unsigned phase = mode == 2 ? 1 : 0; phase < 6; phase++) {
            REQUIRE(p.counts[phase] >= 3);
            for (unsigned at = 1; at <= 3; at++) {
                Validation cancel = {.stop = phase, .at = at};
                YDDiskValidation stop = {validation_progress, &cancel, false};
                valid = mode == 0 ? yd_raft_application_validate_cancellable(app, &expected, &view, &stop, error, sizeof(error))
                    : mode == 1 ? yd_raft_application_validate_at_cancellable(disk, &expected, &view, &stop, error, sizeof(error))
                    : yd_disk_validate_cancellable(disk, &view, &stop, error, sizeof(error));
                REQUIRE(!valid && stop.cancelled && cancel.counts[phase] == at && !yd_raft_application_failed(app));
                Validation saved = cancel;
                REQUIRE(!yd_raft_application_validate_cancellable(app, &expected, &view, &stop, error, sizeof(error)) &&
                    !memcmp(&cancel, &saved, sizeof(cancel)) && validate(app));
            }
        }
    }
    YDDiskValidation no_callback = {0};
    REQUIRE(yd_raft_application_validate_cancellable(app, &expected, &view, &no_callback, error, sizeof(error)) &&
        yd_raft_application_validate_at_cancellable(disk, &expected, &view, NULL, error, sizeof(error)));
    expected.digest[0] ^= 1;
    Validation p = {.stop = 99};
    YDDiskValidation state = {validation_progress, &p, false};
    REQUIRE(!yd_raft_application_validate_cancellable(app, &expected, &view, &state, error, sizeof(error)) &&
        !state.cancelled);
    YDDiskStats after = yd_disk_stats(disk);
    REQUIRE(before.bytes_written == after.bytes_written && before.pages_written == after.pages_written);
    yd_raft_application_close(app);
    return 0;
}
int main(int argc, char **argv) {
    if (argc != 3) return 2;
    if (!strcmp(argv[2], "cancellable")) return cancellable(argv[1]);
    if (!strcmp(argv[2], "basic")) return basic(argv[1]);
    if (!strcmp(argv[2], "metadata")) return metadata(argv[1]);
    if (!strcmp(argv[2], "receipts")) return receipts(argv[1], false);
    if (!strcmp(argv[2], "live")) return receipts(argv[1], true);
    if (!strcmp(argv[2], "namespaces")) return namespaces(argv[1]);
    if (!strcmp(argv[2], "large")) return large(argv[1]);
    if (!strcmp(argv[2], "native")) return native(argv[1]);
    if (!strcmp(argv[2], "historical")) return historical(argv[1], false);
    if (!strcmp(argv[2], "concurrent")) return historical(argv[1], true);
    return 2;
}
