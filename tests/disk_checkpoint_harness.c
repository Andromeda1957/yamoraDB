#define _POSIX_C_SOURCE 200809L
#include "../src/consensus/application.h"
#include "../src/disk.h"
#include "../src/disk_documents.h"
#include "../src/disk_log.h"
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#define REQUIRE(x)                                                                                 \
    do {                                                                                           \
        if (!(x)) {                                                                                \
            fprintf(stderr, "line %u: %s (%s)\n", __LINE__, #x, error);                            \
            return 2;                                                                              \
        }                                                                                          \
    } while (0)
static char error[512];
static bool put(YDDisk *disk, uint64_t value) {
    char failure[512];
    YDDiskTxn *txn = yd_disk_begin(disk, failure, sizeof(failure));
    if (!txn)
        return false;
    if (!yd_disk_put(txn, "value", 5, value, failure, sizeof(failure))) {
        yd_disk_abort(txn);
        return false;
    }
    return yd_disk_commit(txn, failure, sizeof(failure));
}
static bool copy(YDDiskCheckpoint *checkpoint, const char *root, size_t chunk) {
    char path[4096];
    snprintf(path, sizeof(path), "%s/%s", root, YD_DISK_FILE);
    int fd = open(path, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
    if (fd < 0)
        return false;
    unsigned char *bytes = malloc(chunk);
    uint64_t end = yd_disk_checkpoint_view(checkpoint).end;
    bool valid = bytes != NULL;
    for (uint64_t at = 0; valid && at < end;) {
        size_t size = end - at < chunk ? (size_t)(end - at) : chunk;
        valid = yd_disk_checkpoint_read(checkpoint, at, bytes, size, error, sizeof(error));
        size_t done = 0;
        while (valid && done < size) {
            ssize_t count = write(fd, bytes + done, size - done);
            if (count <= 0)
                valid = false;
            else
                done += (size_t)count;
        }
        at += size;
    }
    valid = valid && fsync(fd) == 0;
    close(fd);
    free(bytes);
    return valid;
}
static bool value(const char *root, uint64_t expected, size_t record_size) {
    YDDisk *disk = yd_disk_open(root, false, 32768, error, sizeof(error));
    if (!disk)
        return false;
    YDDiskView view = yd_disk_view(disk);
    uint64_t actual = 0, offset = 0;
    bool valid = yd_disk_get(disk, &view, "value", 5, &actual, error, sizeof(error)) == 1 &&
                 actual == expected;
    if (record_size) {
        valid = valid && yd_disk_get(disk, &view, "record", 6, &offset, error, sizeof(error)) == 1;
        size_t size = 0;
        unsigned char *record =
            valid ? yd_disk_record(disk, &view, offset, &size, error, sizeof(error)) : NULL;
        valid = valid && record && size == record_size;
        for (size_t i = 0; valid && i < size; i++)
            valid = record[i] == (unsigned char)(i % 251);
        free(record);
    }
    yd_disk_close(disk);
    return valid;
}
typedef struct {
    YDDisk *disk;
    atomic_bool started;
    bool valid;
} Writer;
static void *writer(void *context) {
    Writer *w = context;
    w->valid = true;
    atomic_store(&w->started, true);
    for (unsigned i = 1; i <= 300 && w->valid; i++)
        w->valid = put(w->disk, i);
    return NULL;
}
static int concurrent(const char *source, const char *one, const char *two) {
    YDDisk *disk = yd_disk_open(source, true, 32768, error, sizeof(error));
    REQUIRE(disk && put(disk, 0));
    const size_t large = 3U * 1024U * 1024U;
    unsigned char *bytes = malloc(large);
    REQUIRE(bytes);
    for (size_t i = 0; i < large; i++)
        bytes[i] = (unsigned char)(i % 251);
    YDDiskTxn *txn = yd_disk_begin(disk, error, sizeof(error));
    uint64_t offset = 0;
    REQUIRE(txn && yd_disk_append(txn, bytes, large, &offset, error, sizeof(error)) &&
            yd_disk_put(txn, "record", 6, offset, error, sizeof(error)) &&
            yd_disk_commit(txn, error, sizeof(error)));
    free(bytes);
    YDDiskCheckpoint *first = yd_disk_checkpoint_open(disk, error, sizeof(error));
    REQUIRE(first);
    YDDiskView pinned = yd_disk_checkpoint_view(first);
    Writer state = {.disk = disk};
    atomic_init(&state.started, false);
    pthread_t thread;
    REQUIRE(!pthread_create(&thread, NULL, writer, &state));
    while (!atomic_load(&state.started)) {
    }
    bool copied = copy(first, one, 4093);
    REQUIRE(!pthread_join(thread, NULL) && state.valid && copied);
    YDDiskView unchanged = yd_disk_checkpoint_view(first);
    REQUIRE(unchanged.generation == pinned.generation && unchanged.root == pinned.root &&
            unchanged.end == pinned.end);
    YDDiskCheckpoint *second = yd_disk_checkpoint_open(disk, error, sizeof(error));
    REQUIRE(second);
    REQUIRE(yd_disk_checkpoint_view(second).generation > pinned.generation &&
            copy(second, two, 65537));
    REQUIRE(value(one, 0, large) && value(two, 300, large));
    yd_disk_checkpoint_close(first);
    yd_disk_checkpoint_close(second);
    yd_disk_close(disk);
    return 0;
}
static int lifetime(const char *source, const char *destination) {
    YDDisk *disk = yd_disk_open(source, true, 32768, error, sizeof(error));
    REQUIRE(disk && put(disk, 77));
    YDDiskCheckpoint *checkpoint = yd_disk_checkpoint_open(disk, error, sizeof(error));
    REQUIRE(checkpoint);
    yd_disk_close(disk);
    REQUIRE(!yd_disk_open(source, true, 32768, error, sizeof(error)));
    REQUIRE(copy(checkpoint, destination, 7) && value(destination, 77, 0));
    yd_disk_checkpoint_close(checkpoint);
    disk = yd_disk_open(source, true, 32768, error, sizeof(error));
    REQUIRE(disk);
    yd_disk_close(disk);
    return 0;
}
static int bounds(const char *source, const char *destination) {
    YDDisk *disk = yd_disk_open(source, true, 32768, error, sizeof(error));
    REQUIRE(disk);
    YDDiskCheckpoint *checkpoint = yd_disk_checkpoint_open(disk, error, sizeof(error));
    REQUIRE(checkpoint);
    YDDiskView view = yd_disk_checkpoint_view(checkpoint);
    unsigned char bytes[8192];
    REQUIRE(view.end == 8192 &&
            yd_disk_checkpoint_read(checkpoint, 0, bytes, sizeof(bytes), error, sizeof(error)));
    REQUIRE(!memcmp(bytes, bytes + 4096, 4096));
    REQUIRE(!yd_disk_checkpoint_open(NULL, error, sizeof(error)));
    REQUIRE(!yd_disk_checkpoint_read(NULL, 0, bytes, 1, error, sizeof(error)));
    REQUIRE(!yd_disk_checkpoint_read(checkpoint, 0, NULL, 1, error, sizeof(error)));
    REQUIRE(!yd_disk_checkpoint_read(checkpoint, 0, bytes, 0, error, sizeof(error)));
    REQUIRE(!yd_disk_checkpoint_read(checkpoint, 0, bytes, 1048577, error, sizeof(error)));
    REQUIRE(!yd_disk_checkpoint_read(checkpoint, view.end, bytes, 1, error, sizeof(error)));
    REQUIRE(!yd_disk_checkpoint_read(checkpoint, UINT64_MAX, bytes, 1, error, sizeof(error)));
    REQUIRE(yd_disk_checkpoint_read(checkpoint, view.end - 1, bytes, 1, error, sizeof(error)));
    REQUIRE(copy(checkpoint, destination, 4093));
    YDDisk *restored = yd_disk_open(destination, false, 32768, error, sizeof(error));
    REQUIRE(restored && yd_disk_view(restored).generation == 1);
    yd_disk_close(restored);
    yd_disk_checkpoint_close(checkpoint);
    yd_disk_checkpoint_close(NULL);
    yd_disk_close(disk);
    return 0;
}
static int application(const char *source, const char *destination) {
    const unsigned char cluster[16] = {1, 2, 3, 4};
    const unsigned char yaml[] = "# preserved\r\ncount: 0 # exact\r\n";
    YDRaftApplication *app = yd_raft_application_open(source, cluster, 32768, error, sizeof(error));
    REQUIRE(app);
    YDRaftEntry noop = {.index = 1, .term = 1, .kind = YD_RAFT_NOOP};
    REQUIRE(yd_raft_application_apply(app, &noop, error, sizeof(error)));
    YDRaftWrite request = {.id = {1},
                           .method = "PUT",
                           .target = "/v1/collections/a/documents/b",
                           .body = yaml,
                           .size = sizeof(yaml) - 1};
    YDRaftProposal proposal;
    REQUIRE(yd_raft_application_prepare(app, &request, &proposal, error, sizeof(error)) == 1);
    YDRaftEntry entry = {.index = 2,
                         .term = 1,
                         .kind = YD_RAFT_COMMAND,
                         .command = proposal.command,
                         .size = proposal.size};
    REQUIRE(yd_raft_application_apply(app, &entry, error, sizeof(error)));
    yd_raft_proposal_free(&proposal);
    YDDisk *disk = yd_raft_application_disk(app);
    YDDiskCheckpoint *checkpoint = yd_disk_checkpoint_open(disk, error, sizeof(error));
    REQUIRE(checkpoint);
    YDDiskLog original;
    YDDiskView pinned = yd_disk_checkpoint_view(checkpoint);
    REQUIRE(yd_disk_log_load(disk, &pinned, &original, error, sizeof(error)) == 1);
    const unsigned char patch[] = "{\"$inc\":{\"count\":1}}";
    YDRaftWrite increment = {.id = {2},
                             .method = "PATCH",
                             .target = request.target,
                             .body = patch,
                             .size = sizeof(patch) - 1};
    REQUIRE(yd_raft_application_prepare(app, &increment, &proposal, error, sizeof(error)) == 1);
    entry = (YDRaftEntry){.index = 3,
                          .term = 1,
                          .kind = YD_RAFT_COMMAND,
                          .command = proposal.command,
                          .size = proposal.size};
    REQUIRE(yd_raft_application_apply(app, &entry, error, sizeof(error)));
    yd_raft_proposal_free(&proposal);
    entry = (YDRaftEntry){.index = 4, .term = 1, .kind = YD_RAFT_NOOP};
    REQUIRE(yd_raft_application_apply(app, &entry, error, sizeof(error)));
    REQUIRE(copy(checkpoint, destination, 4093));
    yd_disk_checkpoint_close(checkpoint);
    yd_raft_application_close(app);
    app = yd_raft_application_open(destination, cluster, 32768, error, sizeof(error));
    REQUIRE(app && yd_raft_application_position(app).index == 2);
    REQUIRE(yd_raft_application_prepare(app, &request, &proposal, error, sizeof(error)) == 0 &&
            proposal.reply.status == 201);
    yd_raft_proposal_free(&proposal);
    YDDiskReply receipt;
    REQUIRE(yd_raft_application_receipt(app, &increment, &receipt, error, sizeof(error)) == 0);
    disk = yd_raft_application_disk(app);
    YDDiskView view = yd_disk_view(disk);
    YDDiskDocument document;
    REQUIRE(yd_disk_document_get(disk, &view, "a", "b", &document, error, sizeof(error)) == 1 &&
            document.length == sizeof(yaml) - 1 && !memcmp(document.body, yaml, document.length));
    yd_disk_document_free(&document);
    YDDiskLog restored;
    REQUIRE(yd_disk_log_load(disk, &view, &restored, error, sizeof(error)) == 1 &&
            !memcmp(original.identity, restored.identity, 16) && restored.last == original.last);
    yd_raft_application_close(app);
    return 0;
}
static int truncated(const char *source) {
    YDDisk *disk = yd_disk_open(source, true, 32768, error, sizeof(error));
    REQUIRE(disk && put(disk, 1));
    YDDiskCheckpoint *checkpoint = yd_disk_checkpoint_open(disk, error, sizeof(error));
    REQUIRE(checkpoint);
    int directory = open(source, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    REQUIRE(directory >= 0);
    int native = openat(directory, YD_DISK_FILE, O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
    REQUIRE(native >= 0 && !ftruncate(native, 8192));
    REQUIRE(!close(native) && !close(directory));
    unsigned char byte;
    REQUIRE(!yd_disk_checkpoint_read(checkpoint, yd_disk_checkpoint_view(checkpoint).end - 1, &byte,
                                     1, error, sizeof(error)));
    yd_disk_checkpoint_close(checkpoint);
    yd_disk_close(disk);
    return 0;
}
static int reservations(const char *source, const char *destination) {
    YDDisk *disk = yd_disk_open(source, true, 32768, error, sizeof(error));
    REQUIRE(disk && put(disk, 1));
    YDDiskTxn *pending = yd_disk_begin_staging(disk, error, sizeof(error));
    REQUIRE(pending && yd_disk_put(pending, "private", 7, 9, error, sizeof(error)));
    uint64_t page = yd_disk_tx_view(pending)->root;
    REQUIRE(put(disk, 2));
    YDDiskCheckpoint *checkpoint = yd_disk_checkpoint_open(disk, error, sizeof(error));
    unsigned char before[4096], after[4096];
    if (checkpoint) {
        REQUIRE(yd_disk_checkpoint_read(checkpoint, page, before, sizeof(before), error,
                                        sizeof(error)));
    } else {
        REQUIRE(strstr(error, "transaction") != NULL);
    }
    YDDiskView frozen;
    REQUIRE(yd_disk_tx_freeze(pending, &frozen, error, sizeof(error)));
    if (checkpoint) {
        REQUIRE(
            yd_disk_checkpoint_read(checkpoint, page, after, sizeof(after), error, sizeof(error)));
        bool stable = !memcmp(before, after, sizeof(before));
        yd_disk_checkpoint_close(checkpoint);
        yd_disk_abort(pending);
        yd_disk_close(disk);
        REQUIRE(stable);
        return 0;
    }
    yd_disk_abort(pending);
    for (unsigned exclusive = 0; exclusive < 2; exclusive++) {
        pending = exclusive ? yd_disk_begin_exclusive(disk, error, sizeof(error))
                            : yd_disk_begin(disk, error, sizeof(error));
        REQUIRE(pending);
        checkpoint = yd_disk_checkpoint_open(disk, error, sizeof(error));
        bool rejected = checkpoint == NULL;
        yd_disk_checkpoint_close(checkpoint);
        yd_disk_abort(pending);
        REQUIRE(rejected);
    }
    checkpoint = yd_disk_checkpoint_open(disk, error, sizeof(error));
    REQUIRE(checkpoint && copy(checkpoint, destination, 4093) && value(destination, 2, 0));
    yd_disk_checkpoint_close(checkpoint);
    yd_disk_close(disk);
    return 0;
}
int main(int argc, char **argv) {
    if (argc != 3)
        return 2;
    char paths[3][4096];
    for (unsigned i = 0; i < 3; i++) {
        snprintf(paths[i], sizeof(paths[i]), "%s/%u", argv[1], i);
        REQUIRE(!mkdir(paths[i], 0700));
    }
    if (!strcmp(argv[2], "concurrent"))
        return concurrent(paths[0], paths[1], paths[2]);
    if (!strcmp(argv[2], "lifetime"))
        return lifetime(paths[0], paths[1]);
    if (!strcmp(argv[2], "bounds"))
        return bounds(paths[0], paths[1]);
    if (!strcmp(argv[2], "application"))
        return application(paths[0], paths[1]);
    if (!strcmp(argv[2], "truncated"))
        return truncated(paths[0]);
    if (!strcmp(argv[2], "reservations"))
        return reservations(paths[0], paths[1]);
    return 2;
}
