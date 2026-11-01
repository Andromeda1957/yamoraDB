#define _POSIX_C_SOURCE 200809L
#include "../src/consensus/journal_copy.h"
#include "../src/consensus/raft_internal.h"
#include "../src/disk_internal.h"
#include <errno.h>
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
static const unsigned char cluster[16] = {1, 2, 3, 4};
static unsigned fail_sync;
static atomic_uint sync_calls;
static unsigned corrupt_copy;
static bool corrupted_copy;
int __real_fsync(int fd);
int __wrap_fsync(int fd) {
    if (++sync_calls == fail_sync) {
        errno = EIO;
        return -1;
    }
    return __real_fsync(fd);
}
YDDisk *__real_yd_disk_pin(YDDisk *, size_t, char *, size_t);
YDDisk *__wrap_yd_disk_pin(YDDisk *source, size_t cache, char *failure, size_t length) {
    YDDisk *pin = __real_yd_disk_pin(source, cache, failure, length);
    if (pin && corrupt_copy) {
        unsigned kind = corrupt_copy;
        corrupt_copy = false;
        if (kind == 2) {
            unsigned char zero[YD_DISK_PAGE] = {0};
            YDDiskView view = yd_disk_view(pin);
            corrupted_copy =
                pwrite(pin->fd, zero, sizeof(zero),
                       (off_t)((view.generation % 2) * YD_DISK_PAGE)) == (ssize_t)sizeof(zero);
            return pin;
        }
        unsigned char key[12] = {0, 'Y', 'R', 'E', 0, 0, 0, 0, 0, 0, 0, 46};
        uint64_t offset;
        size_t size;
        YDDiskView view = yd_disk_view(pin);
        bool valid = yd_disk_get(pin, &view, key, 12, &offset, failure, length) == 1;
        unsigned char *bytes =
            valid ? yd_disk_record(pin, &view, offset, &size, failure, length) : NULL;
        valid = valid && bytes && size > 40;
        if (valid) {
            bytes[40] ^= 1;
            uint32_t crc = yd_disk_crc(bytes, size);
            unsigned char encoded[4];
            for (unsigned i = 0; i < 4; i++)
                encoded[i] = (unsigned char)(crc >> (8 * i));
            valid = pwrite(pin->fd, bytes, size, (off_t)(offset + 16)) == (ssize_t)size &&
                    pwrite(pin->fd, encoded, 4, (off_t)(offset + 12)) == 4;
        }
        free(bytes);
        corrupted_copy = valid;
    }
    return pin;
}
static bool acknowledge(YDRaft *r) {
    YDRaftAppend request;
    if (!yd_raft_append_request(r, 2, &request))
        return false;
    YDRaftAppendReply reply = {.term = request.term,
                               .rpc = request.rpc,
                               .accepted = true,
                               .matched = request.previous + request.has_entry};
    yd_raft_append_free(&request);
    return yd_raft_append_reply(r, 2, &reply);
}
static bool propose(YDRaft *r, const char *text) {
    uint64_t index;
    return yd_raft_propose(r, text, strlen(text), &index);
}
static bool elect(YDRaft *r) {
    YDRaftVote vote;
    if (!yd_raft_campaign(r, &vote))
        return false;
    YDRaftVoteReply reply = {.term = vote.term, .granted = true};
    return yd_raft_vote_reply(r, 2, vote.term, &reply) && acknowledge(r);
}
static YDRaft *seed(const char *root) {
    YDRaft *r = yd_raft_open(root, cluster, 1, 3, 32768, error, sizeof(error));
    bool valid = r && elect(r);
    for (unsigned i = 0; valid && i < 50; i++)
        valid = propose(r, "# YAML\r\nkey: value # keep\r\n") && acknowledge(r);
    YDRaftSnapshotBase base = {.index = 45, .term = 1, .archive = {4, 5, 6}};
    if (valid) {
        valid = yd_raft_checkpoint(r, &base);
        /* Fixture a remote-selected generation through the real metadata writer;
         * this journal-copy layer does not open or validate application images. */
        YDRaftMeta meta = r->meta;
        meta.application[0] = 9;
        valid = valid && yd_raft_save(r, &meta, NULL) && propose(r, "pending");
    }
    if (valid)
        return r;
    yd_raft_close(r);
    return NULL;
}
static int candidate(const char *root, const char *name, char path[4096]) {
    snprintf(path, 4096, "%s/%s", root, name);
    return mkdir(path, 0700) ? -1 : open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
}
static bool read_copy(YDRaftJournalImage *image, const YDRaftMeta *expected) {
    YDDisk *disk = yd_raft_journal_image_disk(image);
    if (!disk || yd_disk_writable(disk))
        return false;
    YDRaft r = {.disk = disk, .meta = *expected};
    for (uint64_t i = expected->snapshot.index + 1; i <= expected->last; i++) {
        YDRaftEntry entry;
        if (!yd_raft_entry(&r, i, &entry))
            return false;
        const char *text = i == 52 ? "pending" : "# YAML\r\nkey: value # keep\r\n";
        bool valid = entry.term == 1 && entry.size == strlen(text) &&
                     !memcmp(entry.command, text, entry.size);
        yd_raft_entry_free(&entry);
        if (!valid)
            return false;
    }
    unsigned char key[4] = {0, 'Y', 'R', 'M'};
    uint64_t offset;
    size_t size;
    YDDiskView view = yd_disk_view(disk);
    if (yd_disk_get(disk, &view, key, 4, &offset, error, sizeof(error)) != 1)
        return false;
    unsigned char *bytes = yd_disk_record(disk, &view, offset, &size, error, sizeof(error));
    bool valid =
        bytes && size == 144 && !memcmp(bytes, "YDRMETA3", 8) && !memcmp(bytes + 8, cluster, 16) &&
        bytes[24] == 1 && bytes[25] == 3 && yd_disk_u64(bytes + 32) == expected->term &&
        yd_disk_u64(bytes + 40) == expected->vote && yd_disk_u64(bytes + 48) == expected->last &&
        yd_disk_u64(bytes + 56) == expected->committed &&
        yd_disk_u64(bytes + 64) == expected->snapshot.index &&
        yd_disk_u64(bytes + 72) == expected->snapshot.term &&
        !memcmp(bytes + 80, expected->snapshot.archive, 32) &&
        !memcmp(bytes + 112, expected->application, 32);
    free(bytes);
    return valid;
}
static int basic(const char *root) {
    char source_path[4096], path[4096];
    int dir = candidate(root, "source", source_path);
    REQUIRE(dir >= 0);
    close(dir);
    YDRaft *r = seed(source_path);
    REQUIRE(r);
    YDRaftMeta expected = r->meta;
    YDDiskView before = yd_disk_view(r->disk);
    YDRaftJournalCapture *capture = yd_raft_journal_capture(r, 32768, error, sizeof(error));
    REQUIRE(capture);
    dir = candidate(root, "copy", path);
    REQUIRE(dir >= 0);
    YDRaftJournalImage *image =
        yd_raft_journal_copy(capture, dir, 32768, NULL, NULL, error, sizeof(error));
    REQUIRE(image && read_copy(image, &expected) && yd_raft_journal_image_current(image, r) &&
            yd_disk_view(yd_raft_journal_image_disk(image)).end * 4 < before.end &&
            yd_disk_view(r->disk).generation == before.generation && r->role == YD_RAFT_LEADER);
    char other_path[4096];
    int other_dir = candidate(root, "same-state-other-inode", other_path);
    REQUIRE(other_dir >= 0);
    close(other_dir);
    YDRaft *other = seed(other_path);
    REQUIRE(other);
    unsigned char first_meta[144], second_meta[144];
    REQUIRE(yd_raft_encode_meta(&other->meta, first_meta) ==
                yd_raft_encode_meta(&expected, second_meta) &&
            !memcmp(first_meta, second_meta, sizeof(first_meta)) &&
            yd_disk_view(other->disk).generation == before.generation &&
            yd_disk_view(other->disk).root == before.root &&
            yd_disk_view(other->disk).end == before.end &&
            !yd_raft_journal_image_current(image, other));
    yd_raft_close(other);
    REQUIRE(faccessat(dir, ".yamora-initializing", F_OK, 0) == 0 &&
            !yd_raft_open(path, cluster, 1, 3, 32768, error, sizeof(error)));
    REQUIRE(propose(r, "later") && !yd_raft_journal_image_current(image, r) &&
            read_copy(image, &expected));
    yd_raft_journal_capture_close(capture);
    yd_raft_close(r);
    REQUIRE(read_copy(image, &expected));
    yd_raft_journal_image_close(image);
    REQUIRE(!yd_raft_open(path, cluster, 1, 3, 32768, error, sizeof(error)));
    close(dir);
    return 0;
}
typedef struct {
    YDRaft *source;
    unsigned seen;
    int cancel;
    bool valid;
    int directory;
} Progress;
static bool progress(void *context, YDRaftJournalPhase phase, uint64_t done, uint64_t total) {
    Progress *p = context;
    if (done > total)
        p->valid = false;
    if (!(p->seen & (1U << phase))) {
        p->seen |= 1U << phase;
        if (p->source)
            p->valid &= propose(p->source, "concurrent") && acknowledge(p->source);
    }
    return p->valid && p->cancel != (int)phase;
}
static int writing(const char *root) {
    char source_path[4096], path[4096];
    int dir = candidate(root, "source", source_path);
    REQUIRE(dir >= 0);
    close(dir);
    YDRaft *r = seed(source_path);
    REQUIRE(r);
    YDRaftMeta expected = r->meta;
    YDRaftJournalCapture *capture = yd_raft_journal_capture(r, 32768, error, sizeof(error));
    REQUIRE(capture);
    dir = candidate(root, "copy", path);
    REQUIRE(dir >= 0);
    Progress p = {.source = r, .cancel = -1, .valid = true};
    YDRaftJournalImage *image =
        yd_raft_journal_copy(capture, dir, 32768, progress, &p, error, sizeof(error));
    REQUIRE(image && p.valid && p.seen == 7 && read_copy(image, &expected) &&
            !yd_raft_journal_image_current(image, r) && r->meta.last == expected.last + 3);
    yd_raft_journal_image_close(image);
    yd_raft_journal_capture_close(capture);
    yd_raft_close(r);
    close(dir);
    return 0;
}
static int lifetime(const char *root) {
    char source_path[4096], path[4096], moved[4096];
    int dir = candidate(root, "source", source_path);
    REQUIRE(dir >= 0);
    close(dir);
    YDRaft *r = seed(source_path);
    REQUIRE(r);
    YDRaftMeta expected = r->meta;
    YDRaftJournalCapture *capture = yd_raft_journal_capture(r, 32768, error, sizeof(error));
    REQUIRE(capture);
    yd_raft_close(r);
    REQUIRE(!yd_raft_open(source_path, cluster, 1, 3, 32768, error, sizeof(error)));
    dir = candidate(root, "copy", path);
    REQUIRE(dir >= 0);
    snprintf(moved, sizeof(moved), "%s/moved", root);
    REQUIRE(!rename(path, moved) && !mkdir(path, 0700));
    YDRaftJournalImage *image =
        yd_raft_journal_copy(capture, dir, 32768, NULL, NULL, error, sizeof(error));
    REQUIRE(image && read_copy(image, &expected) && yd_disk_present(path) == 0 &&
            yd_disk_present(moved) == 1);
    yd_raft_journal_capture_close(capture);
    r = yd_raft_open(source_path, cluster, 1, 3, 32768, error, sizeof(error));
    REQUIRE(r && read_copy(image, &expected));
    yd_raft_close(r);
    yd_raft_journal_image_close(image);
    close(dir);
    return 0;
}
static int rejection(const char *root) {
    char source_path[4096], path[4096];
    int dir = candidate(root, "source", source_path);
    REQUIRE(dir >= 0);
    close(dir);
    YDRaft *r = seed(source_path);
    REQUIRE(r);
    YDDiskView before = yd_disk_view(r->disk);
    REQUIRE(!yd_raft_journal_capture(NULL, 32768, error, sizeof(error)) &&
            !yd_raft_journal_capture(r, 32767, error, sizeof(error)));
    YDRaftJournalCapture *capture = yd_raft_journal_capture(r, 32768, error, sizeof(error));
    REQUIRE(capture);
    REQUIRE(!yd_raft_journal_copy(capture, -1, 32768, NULL, NULL, error, sizeof(error)));
    for (int phase = 0; phase < 3; phase++) {
        char name[32];
        snprintf(name, sizeof(name), "cancel-%d", phase);
        dir = candidate(root, name, path);
        REQUIRE(dir >= 0);
        Progress p = {.cancel = phase, .valid = true};
        REQUIRE(!yd_raft_journal_copy(capture, dir, 32768, progress, &p, error, sizeof(error)));
        REQUIRE(phase == 0 ? yd_disk_present(path) == 0
                           : faccessat(dir, ".yamora-initializing", F_OK, 0) == 0);
        close(dir);
    }
    dir = candidate(root, "occupied", path);
    REQUIRE(dir >= 0);
    int fd = openat(dir, "owner", O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
    REQUIRE(fd >= 0);
    close(fd);
    REQUIRE(!yd_raft_journal_copy(capture, dir, 32768, NULL, NULL, error, sizeof(error)) &&
            yd_disk_present(path) == 0);
    close(dir);
    dir = candidate(root, "untrusted", path);
    REQUIRE(dir >= 0 && !fchmod(dir, 0770));
    REQUIRE(!yd_raft_journal_copy(capture, dir, 32768, NULL, NULL, error, sizeof(error)) &&
            yd_disk_present(path) == 0);
    close(dir);
    /* Alter a checksummed metadata payload after capture: structural validity
     * alone must not allow metadata differing from the captured core. */
    unsigned char key[4] = {0, 'Y', 'R', 'M'};
    uint64_t offset;
    REQUIRE(yd_disk_get(r->disk, &before, key, 4, &offset, error, sizeof(error)) == 1);
    size_t size;
    unsigned char *bytes = yd_disk_record(r->disk, &before, offset, &size, error, sizeof(error));
    REQUIRE(bytes);
    bytes[40] = 2;
    uint32_t crc = yd_disk_crc(bytes, size);
    unsigned char encoded[4];
    for (unsigned i = 0; i < 4; i++)
        encoded[i] = (unsigned char)(crc >> (8 * i));
    REQUIRE(pwrite(r->disk->fd, bytes, size, (off_t)(offset + 16)) == (ssize_t)size &&
            pwrite(r->disk->fd, encoded, 4, (off_t)(offset + 12)) == 4);
    free(bytes);
    dir = candidate(root, "damaged", path);
    REQUIRE(dir >= 0);
    REQUIRE(!yd_raft_journal_copy(capture, dir, 32768, NULL, NULL, error, sizeof(error)) &&
            yd_disk_present(path) == 0);
    REQUIRE(yd_disk_view(r->disk).generation == before.generation && r->role == YD_RAFT_LEADER);
    close(dir);
    yd_raft_journal_capture_close(capture);
    yd_raft_close(r);
    return 0;
}
static int sync_failure(const char *root) {
    char source_path[4096], path[4096];
    int dir = candidate(root, "source", source_path);
    REQUIRE(dir >= 0);
    close(dir);
    YDRaft *r = seed(source_path);
    REQUIRE(r);
    YDDiskView before = yd_disk_view(r->disk);
    YDRaftJournalCapture *capture = yd_raft_journal_capture(r, 32768, error, sizeof(error));
    REQUIRE(capture);
    for (unsigned i = 1; i <= 6; i++) {
        char name[32];
        snprintf(name, sizeof(name), "sync-%u", i);
        dir = candidate(root, name, path);
        REQUIRE(dir >= 0);
        sync_calls = 0;
        fail_sync = i;
        YDRaftJournalImage *image =
            yd_raft_journal_copy(capture, dir, 32768, NULL, NULL, error, sizeof(error));
        fail_sync = 0;
        REQUIRE(!image && sync_calls >= i && faccessat(dir, ".yamora-initializing", F_OK, 0) == 0 &&
                !yd_raft_open(path, cluster, 1, 3, 32768, error, sizeof(error)) &&
                yd_disk_view(r->disk).generation == before.generation && r->role == YD_RAFT_LEADER);
        close(dir);
    }
    REQUIRE(propose(r, "after-failures") && acknowledge(r));
    yd_raft_journal_capture_close(capture);
    yd_raft_close(r);
    return 0;
}
static int fence(const char *root) {
    int dir = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    REQUIRE(dir >= 0);
    int fd = openat(dir, ".yamora-initializing", O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
    REQUIRE(fd >= 0);
    close(fd);
    REQUIRE(!yd_raft_open(root, cluster, 1, 3, 32768, error, sizeof(error)) &&
            yd_disk_present(root) == 0);
    close(dir);
    return 0;
}
static int readback(const char *root) {
    char source_path[4096], path[4096];
    int dir = candidate(root, "source", source_path);
    REQUIRE(dir >= 0);
    close(dir);
    YDRaft *r = seed(source_path);
    REQUIRE(r);
    YDDiskView before = yd_disk_view(r->disk);
    YDRaftJournalCapture *capture = yd_raft_journal_capture(r, 32768, error, sizeof(error));
    REQUIRE(capture);
    for (unsigned kind = 1; kind <= 2; kind++) {
        char name[32];
        snprintf(name, sizeof(name), "copy-%u", kind);
        dir = candidate(root, name, path);
        REQUIRE(dir >= 0);
        corrupt_copy = kind;
        corrupted_copy = false;
        REQUIRE(!yd_raft_journal_copy(capture, dir, 32768, NULL, NULL, error, sizeof(error)) &&
                corrupted_copy && faccessat(dir, ".yamora-initializing", F_OK, 0) == 0 &&
                yd_disk_view(r->disk).generation == before.generation && r->role == YD_RAFT_LEADER);
        close(dir);
    }
    yd_raft_journal_capture_close(capture);
    yd_raft_close(r);
    return 0;
}
static int formats(const char *root) {
    char source_path[4096], path[4096];
    int dir = candidate(root, "source", source_path);
    REQUIRE(dir >= 0);
    close(dir);
    YDRaft *r = yd_raft_open(source_path, cluster, 1, 3, 32768, error, sizeof(error));
    REQUIRE(r);
    for (unsigned stage = 0; stage < 2; stage++) {
        if (stage) {
            REQUIRE(elect(r) && propose(r, "kept") && acknowledge(r));
            YDRaftSnapshotBase base = {.index = 2, .term = 1, .archive = {1}};
            REQUIRE(yd_raft_checkpoint(r, &base));
        }
        YDRaftJournalCapture *capture = yd_raft_journal_capture(r, 32768, error, sizeof(error));
        REQUIRE(capture);
        char name[32];
        snprintf(name, sizeof(name), "copy-%u", stage);
        dir = candidate(root, name, path);
        REQUIRE(dir >= 0);
        YDRaftJournalImage *image =
            yd_raft_journal_copy(capture, dir, 32768, NULL, NULL, error, sizeof(error));
        REQUIRE(image && yd_raft_journal_image_current(image, r));
        unsigned char key[4] = {0, 'Y', 'R', 'M'};
        uint64_t offset;
        size_t size;
        YDDisk *disk = yd_raft_journal_image_disk(image);
        YDDiskView view = yd_disk_view(disk);
        REQUIRE(yd_disk_get(disk, &view, key, 4, &offset, error, sizeof(error)) == 1);
        unsigned char *bytes = yd_disk_record(disk, &view, offset, &size, error, sizeof(error));
        REQUIRE(bytes && size == (stage ? 112 : 64) &&
                !memcmp(bytes, stage ? "YDRMETA2" : "YDRMETA1", 8));
        free(bytes);
        yd_raft_journal_image_close(image);
        yd_raft_journal_capture_close(capture);
        close(dir);
    }
    yd_raft_close(r);
    int old = open(source_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    REQUIRE(old >= 0);
    close(old);
    dir = candidate(root, "with-tail", source_path);
    REQUIRE(dir >= 0);
    close(dir);
    r = seed(source_path);
    REQUIRE(r);
    YDRaftMeta metadata = r->meta;
    metadata.last--;
    REQUIRE(yd_raft_save(r, &metadata, NULL));
    YDRaftJournalCapture *capture = yd_raft_journal_capture(r, 32768, error, sizeof(error));
    REQUIRE(capture);
    dir = candidate(root, "trimmed", path);
    REQUIRE(dir >= 0);
    YDRaftJournalImage *image =
        yd_raft_journal_copy(capture, dir, 32768, NULL, NULL, error, sizeof(error));
    REQUIRE(image && read_copy(image, &metadata));
    unsigned char key[12] = {0, 'Y', 'R', 'E', 0, 0, 0, 0, 0, 0, 0, 52};
    uint64_t offset;
    YDDisk *disk = yd_raft_journal_image_disk(image);
    YDDiskView view = yd_disk_view(disk);
    REQUIRE(yd_disk_get(disk, &view, key, 12, &offset, error, sizeof(error)) == 0);
    yd_raft_journal_image_close(image);
    yd_raft_journal_capture_close(capture);
    yd_raft_close(r);
    close(dir);
    return 0;
}
typedef struct {
    YDRaft *raft;
    atomic_bool start;
    bool valid;
} Writer;
static void *writer(void *context) {
    Writer *w = context;
    while (!atomic_load(&w->start)) {
    }
    w->valid = true;
    for (unsigned i = 0; i < 100 && w->valid; i++)
        w->valid = propose(w->raft, "during-copy") && acknowledge(w->raft);
    return NULL;
}
static bool start_writer(void *context, YDRaftJournalPhase phase, uint64_t done, uint64_t total) {
    Writer *w = context;
    (void)phase;
    (void)done;
    (void)total;
    atomic_store(&w->start, true);
    return true;
}
static int large(const char *root) {
    char source_path[4096], path[4096];
    int dir = candidate(root, "source", source_path);
    REQUIRE(dir >= 0);
    close(dir);
    YDRaft *r = yd_raft_open(source_path, cluster, 1, 3, 32768, error, sizeof(error));
    REQUIRE(r && elect(r));
    size_t size = 3U * 1024 * 1024;
    unsigned char *bytes = malloc(size);
    REQUIRE(bytes);
    for (size_t i = 0; i < size; i++)
        bytes[i] = (unsigned char)(i % 251);
    uint64_t index;
    REQUIRE(yd_raft_propose(r, bytes, size, &index) && acknowledge(r));
    YDRaftJournalCapture *capture = yd_raft_journal_capture(r, 32768, error, sizeof(error));
    REQUIRE(capture);
    YDRaftMeta metadata = r->meta;
    dir = candidate(root, "copy", path);
    REQUIRE(dir >= 0);
    Writer w = {.raft = r};
    atomic_init(&w.start, false);
    pthread_t thread;
    REQUIRE(!pthread_create(&thread, NULL, writer, &w));
    YDRaftJournalImage *image =
        yd_raft_journal_copy(capture, dir, 32768, start_writer, &w, error, sizeof(error));
    REQUIRE(!pthread_join(thread, NULL) && w.valid && image &&
            r->meta.last == metadata.last + 100 && !yd_raft_journal_image_current(image, r));
    yd_raft_close(r);
    YDRaft check = {.disk = yd_raft_journal_image_disk(image), .meta = metadata};
    YDRaftEntry entry;
    REQUIRE(yd_raft_entry(&check, index, &entry) && entry.size == size &&
            !memcmp(entry.command, bytes, size) && yd_disk_stats(check.disk).cache_bytes <= 32768);
    yd_raft_entry_free(&entry);
    free(bytes);
    yd_raft_journal_image_close(image);
    yd_raft_journal_capture_close(capture);
    close(dir);
    return 0;
}
static bool copied_entry(YDRaftJournalImage *image, const YDRaftMeta *metadata, uint64_t index,
                         const void *bytes, size_t size) {
    YDRaft copy = {.disk = yd_raft_journal_image_disk(image), .meta = *metadata};
    YDRaftEntry entry;
    if (!copy.disk || !yd_raft_entry(&copy, index, &entry))
        return false;
    bool valid = entry.size == size && !memcmp(entry.command, bytes, size);
    yd_raft_entry_free(&entry);
    return valid;
}
static uint64_t copied_offset(YDDisk *disk, uint64_t index) {
    unsigned char key[12] = {0, 'Y', 'R', 'E'};
    uint64_t offset = 0;
    YDDiskView view = yd_disk_view(disk);
    for (unsigned i = 0; i < 8; i++)
        key[4 + i] = (unsigned char)(index >> (56 - 8 * i));
    return yd_disk_get(disk, &view, key, 12, &offset, error, sizeof(error)) == 1 ? offset : 0;
}
static int catch_up(const char *root) {
    char source_path[4096], path[4096];
    int dir = candidate(root, "source", source_path);
    REQUIRE(dir >= 0);
    close(dir);
    YDRaft *r = yd_raft_open(source_path, cluster, 1, 3, 32768, error, sizeof(error));
    REQUIRE(r && elect(r));
    size_t size = 3U * 1024 * 1024;
    unsigned char *bytes = malloc(size);
    REQUIRE(bytes);
    memset(bytes, 0x93, size);
    uint64_t index;
    REQUIRE(yd_raft_propose(r, bytes, size, &index) && acknowledge(r));
    YDRaftJournalCapture *old = yd_raft_journal_capture(r, 32768, error, sizeof(error));
    REQUIRE(old);
    dir = candidate(root, "copy", path);
    REQUIRE(dir >= 0);
    YDRaftJournalImage *image =
        yd_raft_journal_copy(old, dir, 32768, NULL, NULL, error, sizeof(error));
    REQUIRE(image);
    YDDisk *pinned = yd_disk_pin(yd_raft_journal_image_disk(image), 32768, error, sizeof(error));
    REQUIRE(pinned);
    uint64_t offset = copied_offset(pinned, 2), end = yd_disk_view(pinned).end;
    REQUIRE(offset);
    REQUIRE(propose(r, "new") && acknowledge(r));
    YDRaftJournalCapture *latest = yd_raft_journal_capture(r, 32768, error, sizeof(error));
    REQUIRE(latest);
    REQUIRE(yd_raft_journal_catch_up(image, latest, NULL, NULL, error, sizeof(error)) &&
            yd_raft_journal_image_current(image, r) &&
            copied_entry(image, &r->meta, 2, bytes, size) &&
            copied_entry(image, &r->meta, 3, "new", 3) &&
            copied_offset(yd_raft_journal_image_disk(image), 2) == offset &&
            yd_disk_view(yd_raft_journal_image_disk(image)).end - end < 262144 &&
            !copied_offset(pinned, 3));
    YDDiskView before = yd_disk_view(yd_raft_journal_image_disk(image));
    REQUIRE(yd_raft_journal_catch_up(image, latest, NULL, NULL, error, sizeof(error)) &&
            yd_disk_view(yd_raft_journal_image_disk(image)).generation == before.generation);
    yd_raft_journal_capture_close(latest);
    YDRaftSnapshotBase base = {.index = 2, .term = 1, .archive = {1}};
    REQUIRE(yd_raft_checkpoint(r, &base));
    latest = yd_raft_journal_capture(r, 32768, error, sizeof(error));
    REQUIRE(latest);
    REQUIRE(yd_raft_journal_catch_up(image, latest, NULL, NULL, error, sizeof(error)) &&
            yd_raft_journal_image_current(image, r) &&
            !copied_offset(yd_raft_journal_image_disk(image), 2) &&
            copied_entry(image, &r->meta, 3, "new", 3) && copied_offset(pinned, 2) == offset);
    free(bytes);
    yd_disk_close(pinned);
    yd_raft_journal_capture_close(old);
    yd_raft_journal_capture_close(latest);
    yd_raft_journal_image_close(image);
    yd_raft_close(r);
    close(dir);
    return 0;
}
static int catch_up_reject(const char *root) {
    char source_path[4096], path[4096];
    int dir = candidate(root, "source", source_path);
    REQUIRE(dir >= 0);
    close(dir);
    YDRaft *r = seed(source_path);
    REQUIRE(r);
    YDRaftJournalCapture *old = yd_raft_journal_capture(r, 32768, error, sizeof(error));
    REQUIRE(old);
    dir = candidate(root, "copy", path);
    REQUIRE(dir >= 0);
    YDRaftJournalImage *image =
        yd_raft_journal_copy(old, dir, 32768, NULL, NULL, error, sizeof(error));
    REQUIRE(image);
    char other_path[4096];
    int other_dir = candidate(root, "other", other_path);
    REQUIRE(other_dir >= 0);
    close(other_dir);
    YDRaft *other = seed(other_path);
    REQUIRE(other);
    YDRaftJournalCapture *foreign = yd_raft_journal_capture(other, 32768, error, sizeof(error));
    REQUIRE(foreign);
    REQUIRE(!yd_raft_journal_catch_up(image, foreign, NULL, NULL, error, sizeof(error)) &&
            yd_raft_journal_image_current(image, r) &&
            !yd_raft_journal_catch_up(image, NULL, NULL, NULL, error, sizeof(error)));
    REQUIRE(propose(r, "later"));
    YDRaftJournalCapture *latest = yd_raft_journal_capture(r, 32768, error, sizeof(error));
    REQUIRE(latest);
    REQUIRE(yd_raft_journal_catch_up(image, latest, NULL, NULL, error, sizeof(error)) &&
            !yd_raft_journal_catch_up(image, old, NULL, NULL, error, sizeof(error)) &&
            yd_raft_journal_image_current(image, r));
    yd_raft_journal_capture_close(foreign);
    yd_raft_journal_capture_close(latest);
    yd_raft_journal_capture_close(old);
    yd_raft_journal_image_close(image);
    yd_raft_close(other);
    yd_raft_close(r);
    close(dir);
    return 0;
}
static int catch_up_fail(const char *root) {
    char source_path[4096], path[4096];
    int dir = candidate(root, "source", source_path);
    REQUIRE(dir >= 0);
    close(dir);
    YDRaft *r = seed(source_path);
    REQUIRE(r);
    YDRaftJournalCapture *old = yd_raft_journal_capture(r, 32768, error, sizeof(error));
    REQUIRE(old);
    REQUIRE(propose(r, "later"));
    YDRaftJournalCapture *latest = yd_raft_journal_capture(r, 32768, error, sizeof(error));
    REQUIRE(latest);
    YDDiskView before = yd_disk_view(r->disk);
    for (unsigned i = 0; i < 4; i++) {
        char name[32];
        snprintf(name, sizeof(name), "copy-%u", i);
        dir = candidate(root, name, path);
        REQUIRE(dir >= 0);
        YDRaftJournalImage *image =
            yd_raft_journal_copy(old, dir, 32768, NULL, NULL, error, sizeof(error));
        REQUIRE(image);
        Progress p = {.cancel = i == 2 ? YD_RAFT_JOURNAL_COPY : YD_RAFT_JOURNAL_VERIFY,
                      .valid = true};
        sync_calls = 0;
        fail_sync = i < 2 ? i + 1 : 0;
        bool valid = yd_raft_journal_catch_up(image, latest, i < 2 ? NULL : progress, &p, error,
                                              sizeof(error));
        fail_sync = 0;
        REQUIRE(!valid && !yd_raft_journal_image_disk(image) &&
                !yd_raft_journal_image_current(image, r) &&
                faccessat(dir, ".yamora-initializing", F_OK, 0) == 0 &&
                yd_disk_view(r->disk).generation == before.generation && r->role == YD_RAFT_LEADER);
        yd_raft_journal_image_close(image);
        close(dir);
    }
    yd_raft_journal_capture_close(old);
    yd_raft_journal_capture_close(latest);
    yd_raft_close(r);
    return 0;
}
static bool receive(YDRaft *r, unsigned from, uint64_t term, uint64_t previous,
                    uint64_t previous_term, uint64_t committed, const char *text) {
    YDRaftAppend request = {.from = from,
                            .term = term,
                            .rpc = previous + term,
                            .previous = previous,
                            .previous_term = previous_term,
                            .committed = committed,
                            .has_entry = text != NULL,
                            .entry = {.index = previous + 1,
                                      .term = term,
                                      .kind = YD_RAFT_COMMAND,
                                      .command = (const unsigned char *)text,
                                      .size = text ? strlen(text) : 0}};
    memcpy(request.cluster, cluster, 16);
    YDRaftAppendReply reply;
    return yd_raft_append(r, &request, &reply) && reply.accepted;
}
static int catch_up_repair(const char *root) {
    char source_path[4096], path[4096];
    int dir = candidate(root, "source", source_path);
    REQUIRE(dir >= 0);
    close(dir);
    YDRaft *r = seed(source_path);
    REQUIRE(r);
    YDRaftJournalCapture *old = yd_raft_journal_capture(r, 32768, error, sizeof(error));
    REQUIRE(old);
    dir = candidate(root, "copy", path);
    REQUIRE(dir >= 0);
    YDRaftJournalImage *image =
        yd_raft_journal_copy(old, dir, 32768, NULL, NULL, error, sizeof(error));
    REQUIRE(image);
    REQUIRE(receive(r, 2, 2, 51, 1, 51, "replacement") &&
            receive(r, 2, 2, 52, 2, 52, "temporary-53") &&
            receive(r, 2, 2, 53, 2, 52, "temporary-54"));
    YDRaftJournalCapture *latest = yd_raft_journal_capture(r, 32768, error, sizeof(error));
    REQUIRE(latest);
    REQUIRE(yd_raft_journal_catch_up(image, latest, NULL, NULL, error, sizeof(error)) &&
            copied_entry(image, &r->meta, 52, "replacement", 11) &&
            copied_offset(yd_raft_journal_image_disk(image), 54));
    yd_raft_journal_capture_close(latest);
    REQUIRE(receive(r, 3, 3, 52, 2, 52, "shorter"));
    YDRaftMeta metadata = r->meta;
    metadata.application[0] = 10;
    REQUIRE(yd_raft_save(r, &metadata, NULL));
    latest = yd_raft_journal_capture(r, 32768, error, sizeof(error));
    REQUIRE(latest);
    REQUIRE(yd_raft_journal_catch_up(image, latest, NULL, NULL, error, sizeof(error)) &&
            yd_raft_journal_image_current(image, r) &&
            copied_entry(image, &r->meta, 52, "replacement", 11) &&
            copied_entry(image, &r->meta, 53, "shorter", 7) &&
            !copied_offset(yd_raft_journal_image_disk(image), 54));
    unsigned char key[4] = {0, 'Y', 'R', 'M'};
    uint64_t offset;
    size_t size;
    YDDisk *disk = yd_raft_journal_image_disk(image);
    YDDiskView view = yd_disk_view(disk);
    REQUIRE(yd_disk_get(disk, &view, key, 4, &offset, error, sizeof(error)) == 1);
    unsigned char *bytes = yd_disk_record(disk, &view, offset, &size, error, sizeof(error));
    REQUIRE(bytes && size == 144 && bytes[112] == 10 && yd_disk_u64(bytes + 32) == 3 &&
            yd_disk_u64(bytes + 56) == 52);
    free(bytes);
    yd_raft_journal_capture_close(old);
    yd_raft_journal_capture_close(latest);
    yd_raft_journal_image_close(image);
    yd_raft_close(r);
    close(dir);
    return 0;
}
static int catch_up_writing(const char *root) {
    char source_path[4096], path[4096];
    int dir = candidate(root, "source", source_path);
    REQUIRE(dir >= 0);
    close(dir);
    YDRaft *r = seed(source_path);
    REQUIRE(r);
    YDRaftJournalCapture *old = yd_raft_journal_capture(r, 32768, error, sizeof(error));
    REQUIRE(old);
    dir = candidate(root, "copy", path);
    REQUIRE(dir >= 0);
    YDRaftJournalImage *image =
        yd_raft_journal_copy(old, dir, 32768, NULL, NULL, error, sizeof(error));
    REQUIRE(image);
    REQUIRE(propose(r, "before-catchup") && acknowledge(r));
    YDRaftMeta captured = r->meta;
    YDRaftJournalCapture *latest = yd_raft_journal_capture(r, 32768, error, sizeof(error));
    REQUIRE(latest);
    Progress p = {.source = r, .cancel = -1, .valid = true};
    REQUIRE(yd_raft_journal_catch_up(image, latest, progress, &p, error, sizeof(error)) &&
            p.valid && p.seen == 7 && r->meta.last == captured.last + 3 &&
            !yd_raft_journal_image_current(image, r) &&
            copied_entry(image, &captured, 53, "before-catchup", 14) &&
            !copied_offset(yd_raft_journal_image_disk(image), 54));
    yd_raft_journal_capture_close(old);
    yd_raft_journal_capture_close(latest);
    yd_raft_journal_image_close(image);
    yd_raft_close(r);
    close(dir);
    return 0;
}
int main(int argc, char **argv) {
    if (argc != 3)
        return 2;
    if (!strcmp(argv[2], "basic"))
        return basic(argv[1]);
    if (!strcmp(argv[2], "writing"))
        return writing(argv[1]);
    if (!strcmp(argv[2], "lifetime"))
        return lifetime(argv[1]);
    if (!strcmp(argv[2], "rejection"))
        return rejection(argv[1]);
    if (!strcmp(argv[2], "sync"))
        return sync_failure(argv[1]);
    if (!strcmp(argv[2], "fence"))
        return fence(argv[1]);
    if (!strcmp(argv[2], "readback"))
        return readback(argv[1]);
    if (!strcmp(argv[2], "formats"))
        return formats(argv[1]);
    if (!strcmp(argv[2], "large"))
        return large(argv[1]);
    if (!strcmp(argv[2], "catch-up"))
        return catch_up(argv[1]);
    if (!strcmp(argv[2], "catch-up-reject"))
        return catch_up_reject(argv[1]);
    if (!strcmp(argv[2], "catch-up-fail"))
        return catch_up_fail(argv[1]);
    if (!strcmp(argv[2], "catch-up-repair"))
        return catch_up_repair(argv[1]);
    if (!strcmp(argv[2], "catch-up-writing"))
        return catch_up_writing(argv[1]);
    return 2;
}
