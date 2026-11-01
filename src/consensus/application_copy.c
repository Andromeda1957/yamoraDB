#define _POSIX_C_SOURCE 200809L
#include "application_copy.h"
#include "application_internal.h"
#include "../disk_internal.h"
#include "../disk_history.h"
#include "../sharding/service.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

struct YDRaftApplicationCapture {
    YDDisk *disk;
    YDRaftApplicationCopyInfo info;
    dev_t device;
    ino_t inode;
};
struct YDRaftApplicationImage {
    YDStorageLease origin_budget;
    int directory, origin, marker;
    YDDisk *writer, *disk;
    YDRaftApplicationCopyInfo info;
    dev_t device;
    ino_t inode;
    size_t cache;
    uint64_t limit;
    bool failed, opening;
};
static bool fail(char *error, size_t length) {
    return yd_disk_error(error, length, "application copy unavailable, cancelled or invalid");
}
static bool cache_valid(size_t cache) {
    return cache >= 32768 && cache <= 1024ULL * 1024 * 1024;
}
static YDRaftApplicationCapture *application_capture(YDRaftApplication *a, size_t cache,
                                                      char *error, size_t length) {
    if (!cache_valid(cache)) {
        fail(error, length);
        return NULL;
    }
    YDRaftApplicationCapture *volatile c = calloc(1, sizeof(*c));
    if (!c) {
        fail(error, length);
        return NULL;
    }
    c->disk = yd_raft_application_pin(a, cache, &c->info.checkpoint, error, length);
    if (!c->disk) {
        free(c);
        return NULL;
    }
    c->info.source = yd_disk_view(c->disk);
    struct stat status;
    if (fstat(c->disk->fd, &status)) {
        yd_raft_application_capture_close(c);
        fail(error, length);
        return NULL;
    }
    c->device = status.st_dev;
    c->inode = status.st_ino;
    return c;
}
static void capture_cancelled(void *context) { yd_raft_application_capture_close(context); }
YDRaftApplicationCapture *yd_raft_application_capture(YDRaftApplication *a, size_t cache,
    char *error, size_t length) {
    int previous;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous)) return NULL;
    YDRaftApplicationCapture *capture = application_capture(a, cache, error, length);
    pthread_cleanup_push(capture_cancelled, capture);
    (void)pthread_setcancelstate(previous, NULL);
    if (previous == PTHREAD_CANCEL_ENABLE) pthread_testcancel();
    pthread_cleanup_pop(0);
    return capture;
}
YDRaftApplicationCopyInfo yd_raft_application_capture_info(const YDRaftApplicationCapture *c) {
    return c ? c->info : (YDRaftApplicationCopyInfo){0};
}
void yd_raft_application_capture_close(YDRaftApplicationCapture *c) {
    if (c) {
        yd_disk_close(c->disk);
        free(c);
    }
}
YDRaftApplicationCopyInfo yd_raft_application_image_info(const YDRaftApplicationImage *i) {
    return i ? i->info : (YDRaftApplicationCopyInfo){0};
}
YDDisk *yd_raft_application_image_disk(const YDRaftApplicationImage *i) {
    return i && !i->failed ? i->disk : NULL;
}
static bool same_file(int a, int b) {
    struct stat left, right;
    return a >= 0 && b >= 0 && !fstat(a, &left) && !fstat(b, &right) &&
        left.st_dev == right.st_dev && left.st_ino == right.st_ino;
}
bool yd_raft_application_image_created_files(const YDRaftApplicationImage *i,
    int directory, int native, int fence) {
    return i && !i->failed && i->disk && i->writer && i->writer->created &&
        same_file(directory, i->directory) && same_file(native, i->writer->fd) &&
        same_file(fence, i->marker);
}
YDDiskAllocation yd_raft_application_image_allocation(const YDRaftApplicationImage *i) {
    if (!i)
        return (YDDiskAllocation){0};
    if (i->writer)
        return yd_disk_allocation(i->writer);
    /* Admit both headers before attempting initialization. An open failure can
     * leave a partial file or no handle (including fstat/cache failure); never
     * need another successful filesystem query to account for that growth. */
    return (YDDiskAllocation){i->limit, i->opening ? 2 * YD_DISK_PAGE : 0};
}
static bool same_info(YDRaftApplicationCopyInfo a, YDRaftApplicationCopyInfo b) {
    YDDiskView av = a.source, bv = b.source;
    return av.format == bv.format && av.capabilities == bv.capabilities && av.generation == bv.generation && av.root == bv.root &&
           av.end == bv.end && av.documents == bv.documents && av.collections == bv.collections &&
           av.bytes == bv.bytes && av.revision == bv.revision &&
           a.checkpoint.applied.index == b.checkpoint.applied.index &&
           a.checkpoint.applied.term == b.checkpoint.applied.term &&
           !memcmp(a.checkpoint.cluster, b.checkpoint.cluster, 16) &&
           !memcmp(a.checkpoint.digest, b.checkpoint.digest, 32);
}
static YDDiskCheckpoint *image_checkpoint(YDRaftApplicationImage *i,
                                                       YDRaftCheckpoint *position, char *error,
                                                       size_t length) {
    if (position)
        memset(position, 0, sizeof(*position));
    if (!i || i->failed || !position) {
        fail(error, length);
        return NULL;
    }
    YDDiskCheckpoint *volatile checkpoint = yd_disk_checkpoint_open(i->writer, error, length);
    if (!checkpoint)
        return NULL;
    YDDiskView view = yd_disk_checkpoint_view(checkpoint);
    YDRaftApplicationCopyInfo physical = {.checkpoint = i->info.checkpoint, .source = view};
    YDRaftApplicationCopyInfo pinned = {.checkpoint = i->info.checkpoint,
                                        .source = yd_disk_view(i->disk)};
    if (!same_info(physical, pinned) || (view.format != 6 &&
        !(view.format == 8 && (view.capabilities & YD_DISK_CAP_CLUSTER))) ||
        i->info.checkpoint.applied.index > UINT64_MAX - 2 ||
        view.generation != i->info.checkpoint.applied.index + 2) {
        yd_disk_checkpoint_close(checkpoint);
        i->failed = true;
        fail(error, length);
        return NULL;
    }
    *position = i->info.checkpoint;
    return checkpoint;
}
static void image_checkpoint_cancelled(void *context) { yd_disk_checkpoint_close(context); }
YDDiskCheckpoint *yd_raft_application_image_checkpoint(YDRaftApplicationImage *i,
    YDRaftCheckpoint *position, char *error, size_t length) {
    int previous;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous)) return NULL;
    YDDiskCheckpoint *checkpoint = image_checkpoint(i, position, error, length);
    pthread_cleanup_push(image_checkpoint_cancelled, checkpoint);
    (void)pthread_setcancelstate(previous, NULL);
    if (previous == PTHREAD_CANCEL_ENABLE) pthread_testcancel();
    pthread_cleanup_pop(0);
    return checkpoint;
}
bool yd_raft_application_image_current(const YDRaftApplicationImage *i, YDRaftApplication *a) {
    if (!i || i->failed || !a)
        return false;
    YDRaftApplicationCapture *c = yd_raft_application_capture(a, 32768, NULL, 0);
    bool valid = c && c->device == i->device && c->inode == i->inode && same_info(c->info, i->info);
    yd_raft_application_capture_close(c);
    return valid;
}
void yd_raft_application_image_close(YDRaftApplicationImage *i) {
    if (i) {
        yd_disk_close(i->disk);
        yd_disk_close(i->writer);
        if (i->directory >= 0)
            close(i->directory);
        if (i->origin >= 0)
            close(i->origin);
        yd_storage_budget_release(&i->origin_budget);
        if (i->marker >= 0)
            close(i->marker);
        free(i);
    }
}
static bool report(YDRaftApplicationCopyProgress p, void *ctx, YDRaftApplicationCopyPhase phase,
                   uint64_t done) {
    return !p || p(ctx, phase, done, 0);
}
static bool empty(int directory) {
    int fd = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    DIR *scan = fd >= 0 ? fdopendir(fd) : NULL;
    if (!scan) {
        if (fd >= 0)
            close(fd);
        return false;
    }
    bool valid = true;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(scan);
        if (!entry) {
            valid = !errno;
            break;
        }
        if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) {
            valid = false;
            break;
        }
    }
    closedir(scan);
    return valid;
}
typedef enum { INVALID, COLLECTION, DOCUMENT, INDEX, FRAME, RECORD, HISTORY } Kind;
static Kind kind(const unsigned char *key, size_t size) {
    if (!size)
        return INVALID;
    if (key[0] == 'C')
        return COLLECTION;
    if (key[0] == 'D')
        return DOCUMENT;
    if (key[0] == 'I' || key[0] == 'U')
        return INDEX;
    if (size == 12 && !memcmp(key, "\0YLF", 4))
        return FRAME;
    if (size == 4 && !memcmp(key,"\0YBH",4)) return HISTORY;
    /* YRA is copied byte-for-byte, including the version-2 durable epoch,
     * policy, pruning and exact receipt accounting. Never reconstruct it from
     * surviving IDs: absence alone cannot authorize retry admission.
     * Other validated hidden records contain logical identities and source,
     * not native offsets. Relocate their B-tree values, preserving payloads. */
    if ((size == 4 && (!memcmp(key, "\0YRA", 4) || !memcmp(key, "\0YLM", 4) ||
                      !memcmp(key, "\0YRD", 4) || !memcmp(key, "\0YRS", 4) ||
                      !memcmp(key, "\0YRP", 4))) ||
        (size == 20 && (!memcmp(key, "\0YRR", 4) || !memcmp(key, "\0YRI", 4) ||
                       !memcmp(key, "\0YSP", 4) || !memcmp(key, "\0YBR", 4))) ||
        ((size == 4 || size == 20) && !memcmp(key, "\0YRJ", 4)) ||
        (size >= 6 && !memcmp(key, "\0YRO", 4)) || yd_shard_service_key(key, size) == 1)
        return RECORD;
    return INVALID;
}
/* Temporary native-tree keys bound relocation memory independently of dataset
 * size. Source validation forbids this namespace; none survive publication. */
static void map_key(unsigned char key[12], uint64_t offset) {
    memcpy(key, "\0YMP", 4);
    yd_disk_set64(key + 4, offset);
}
static bool relocated(YDDiskTxn *txn, uint64_t old, uint64_t *value, char *error, size_t length) {
    unsigned char key[12];
    map_key(key, old);
    return yd_disk_tx_peek(txn, key, sizeof(key), value, error, length) == 1;
}
static bool relocate(const YDRaftApplicationCapture *c, YDDiskTxn *txn, YDDisk *existing,
                     uint64_t reuse, uint64_t old, uint64_t *value, char *error, size_t length) {
    unsigned char key[12];
    map_key(key, old);
    int found = yd_disk_tx_peek(txn, key, sizeof(key), value, error, length);
    if (found != 0)
        return found == 1;
    size_t size;
    unsigned char *bytes = yd_disk_record(c->disk, &c->info.source, old, &size, error, length);
    bool valid = bytes != NULL, same = false;
    if (valid && existing && reuse) {
        YDDiskView view = yd_disk_view(existing);
        size_t n;
        unsigned char *previous = yd_disk_record(existing, &view, reuse, &n, error, length);
        valid = previous != NULL;
        same = valid && n == size && !memcmp(bytes, previous, size);
        free(previous);
    }
    if (same)
        *value = reuse;
    valid = valid && (same || yd_disk_append(txn, bytes, size, value, error, length)) &&
            yd_disk_put(txn, key, sizeof(key), *value, error, length);
    free(bytes);
    return valid;
}
static int previous_record(YDDisk *existing, const unsigned char *key, size_t size,
                           unsigned char **bytes, size_t *count, uint64_t *offset, char *error,
                           size_t length) {
    *bytes = NULL;
    *count = 0;
    *offset = 0;
    if (!existing)
        return 0;
    YDDiskView view = yd_disk_view(existing);
    int found = yd_disk_get(existing, &view, key, size, offset, error, length);
    if (found == 1) {
        *bytes = yd_disk_record(existing, &view, *offset, count, error, length);
        if (!*bytes)
            return -1;
    }
    return found;
}
static bool store_record(YDDiskTxn *txn, const unsigned char *key, size_t size,
                         const unsigned char *bytes, size_t count, const unsigned char *previous,
                         size_t prior, uint64_t offset, char *error, size_t length) {
    bool same = previous && prior == count && !memcmp(bytes, previous, count);
    return (same || yd_disk_append(txn, bytes, count, &offset, error, length)) &&
           yd_disk_put(txn, key, size, offset, error, length);
}
static bool raw_copy(const YDRaftApplicationCapture *c, YDDiskTxn *txn, YDDisk *existing,
                     const unsigned char *key, size_t size, uint64_t old, char *error,
                     size_t length) {
    size_t count, prior;
    uint64_t value;
    unsigned char *bytes = yd_disk_record(c->disk, &c->info.source, old, &count, error, length);
    unsigned char *previous;
    int found = previous_record(existing, key, size, &previous, &prior, &value, error, length);
    bool valid = bytes && found >= 0 &&
                 store_record(txn, key, size, bytes, count, previous, prior, value, error, length);
    free(bytes);
    free(previous);
    return valid;
}
/* Recheck lengths even after full source validation: never trust mutable I/O
 * bytes as array bounds. Only D PUT offsets change; every other byte is exact. */
static bool frame_copy(const YDRaftApplicationCapture *c, YDDiskTxn *txn, YDDisk *existing,
                       const unsigned char *key, size_t size, uint64_t old, char *error,
                       size_t length) {
    size_t count, prior;
    uint64_t value, previous_offset;
    unsigned char *bytes = yd_disk_record(c->disk, &c->info.source, old, &count, error, length);
    unsigned char *previous;
    int found =
        previous_record(existing, key, size, &previous, &prior, &previous_offset, error, length);
    bool valid = bytes && found >= 0 && count >= 56 && !memcmp(bytes, "YDLOGF01", 8);
    bool same_header = valid && previous && count == prior && !memcmp(bytes, previous, 56);
    size_t at = 56;
    unsigned n = valid ? yd_disk_u16(bytes + 42) : 0;
    for (unsigned i = 0; valid && i < n; i++) {
        valid = count - at >= 20;
        size_t ks = valid ? yd_disk_u16(bytes + at) : 0;
        valid = valid && ks && ks <= count - at - 20;
        if (!valid)
            break;
        if (!bytes[at + 2] && bytes[at + 20] == 'D') {
            uint64_t reuse = same_header && !memcmp(bytes + at, previous + at, 4) &&
                                     !memcmp(bytes + at + 12, previous + at + 12, 8 + ks)
                                 ? yd_disk_u64(previous + at + 4)
                                 : 0;
            valid = relocate(c, txn, existing, reuse, yd_disk_u64(bytes + at + 4), &value, error,
                             length);
            if (valid)
                yd_disk_set64(bytes + at + 4, value);
        }
        at += 20 + ks;
    }
    valid =
        valid && at == count &&
        store_record(txn, key, size, bytes, count, previous, prior, previous_offset, error, length);
    free(bytes);
    free(previous);
    return valid;
}
static bool copy_keys(const YDRaftApplicationCapture *c, YDDiskTxn *txn, YDDisk *existing,
                      unsigned pass, YDRaftApplicationCopyProgress p, void *ctx, uint64_t *done,
                      char *error, size_t length) {
    YDDiskCursor *cursor = yd_disk_cursor(c->disk, &c->info.source, NULL, 0, false, error, length);
    unsigned char key[YD_DISK_KEY_LIMIT];
    size_t size;
    uint64_t old, value;
    bool valid = cursor != NULL;
    int next = 0;
    while (valid &&
           (next = yd_disk_next(cursor, key, sizeof(key), &size, &old, error, length)) == 1) {
        Kind k = kind(key, size);
        if (k == INVALID) {
            valid = false;
            break;
        }
        if (pass == 0 && k == COLLECTION)
            valid = yd_disk_put(txn, key, size, old, error, length);
        else if (pass == 0 && k == DOCUMENT) {
            uint64_t reuse = 0;
            YDDiskView view = existing ? yd_disk_view(existing) : (YDDiskView){0};
            int found =
                existing ? yd_disk_get(existing, &view, key, size, &reuse, error, length) : 0;
            valid = found >= 0 && relocate(c, txn, existing, reuse, old, &value, error, length) &&
                    yd_disk_put(txn, key, size, value, error, length);
        } else if (pass == 1 && k == RECORD)
            valid = raw_copy(c, txn, existing, key, size, old, error, length);
        else if (pass == 1 && k == FRAME)
            valid = frame_copy(c, txn, existing, key, size, old, error, length);
        else if (pass == 2 && k == INDEX)
            valid = relocated(txn, old, &value, error, length) &&
                    yd_disk_put(txn, key, size, value, error, length);
        if (valid)
            valid = report(p, ctx, YD_RAFT_APPLICATION_COPY, ++*done);
    }
    yd_disk_cursor_free(cursor);
    return valid && next == 0;
}
static bool remove_map(YDDiskTxn *txn, YDRaftApplicationCopyProgress p, void *ctx, uint64_t *done,
                       char *error, size_t length) {
    for (;;) {
        /* Deletion mutates private pages: never reuse a cursor across deletion. */
        YDDiskCursor *cursor = yd_disk_tx_cursor(txn, "\0YMP", 4, false, error, length);
        unsigned char key[YD_DISK_KEY_LIMIT];
        size_t size = 0;
        uint64_t value;
        int next =
            cursor ? yd_disk_next(cursor, key, sizeof(key), &size, &value, error, length) : -1;
        yd_disk_cursor_free(cursor);
        if (next < 0)
            return false;
        if (!next || size < 4 || memcmp(key, "\0YMP", 4))
            return true;
        if (size != 12 || !yd_disk_delete(txn, key, size, error, length) ||
            !report(p, ctx, YD_RAFT_APPLICATION_COPY, ++*done))
            return false;
    }
}
static bool same_record(YDDisk *a, const YDDiskView *av, uint64_t ao, YDDisk *b,
                        const YDDiskView *bv, uint64_t bo, char *error, size_t length) {
    size_t an, bn;
    unsigned char *ab = yd_disk_record(a, av, ao, &an, error, length);
    unsigned char *bb = ab ? yd_disk_record(b, bv, bo, &bn, error, length) : NULL;
    bool valid = ab && bb && an == bn && !memcmp(ab, bb, an);
    free(ab);
    free(bb);
    return valid;
}
static bool same_frame(const YDRaftApplicationCapture *c, YDDisk *disk, const YDDiskView *view,
                       uint64_t ao, uint64_t bo, char *error, size_t length) {
    size_t an = 0, bn;
    unsigned char *a = yd_disk_record(c->disk, &c->info.source, ao, &an, error, length);
    unsigned char *b = a ? yd_disk_record(disk, view, bo, &bn, error, length) : NULL;
    bool valid = a && b && an == bn && an >= 56 && !memcmp(a, b, 56);
    size_t at = 56;
    unsigned n = valid ? yd_disk_u16(a + 42) : 0;
    for (unsigned i = 0; valid && i < n; i++) {
        valid = an - at >= 20;
        size_t ks = valid ? yd_disk_u16(a + at) : 0;
        valid = valid && ks && ks <= an - at - 20 && !memcmp(a + at, b + at, 4) &&
                !memcmp(a + at + 12, b + at + 12, 8 + ks);
        if (!valid)
            break;
        uint64_t ar = yd_disk_u64(a + at + 4), br = yd_disk_u64(b + at + 4);
        valid = !a[at + 2] && a[at + 20] == 'D'
                    ? same_record(c->disk, &c->info.source, ar, disk, view, br, error, length)
                    : ar == br;
        at += 20 + ks;
    }
    free(a);
    free(b);
    return valid && at == an;
}
static bool compare(const YDRaftApplicationCapture *c, YDDisk *disk,
                    YDRaftApplicationCopyProgress p, void *ctx, YDDiskValidation *state,
                    char *error, size_t length) {
    YDDiskView view = yd_disk_view(disk), source = c->info.source;
    if (view.format != source.format || view.capabilities != source.capabilities || view.generation != source.generation ||
        view.documents != source.documents || view.collections != source.collections ||
        view.bytes != source.bytes || view.revision != source.revision)
        return false;
    YDDiskCursor *a = yd_disk_cursor(c->disk, &source, NULL, 0, false, error, length);
    YDDiskCursor *b = a ? yd_disk_cursor(disk, &view, NULL, 0, false, error, length) : NULL;
    unsigned char ak[YD_DISK_KEY_LIMIT], bk[YD_DISK_KEY_LIMIT];
    size_t an, bn;
    uint64_t av, bv, done = 0;
    bool valid = a && b;
    while (valid) {
        int ax = yd_disk_next(a, ak, sizeof(ak), &an, &av, error, length);
        int bx = yd_disk_next(b, bk, sizeof(bk), &bn, &bv, error, length);
        if (ax != 1 || bx != 1) {
            valid = ax == 0 && bx == 0;
            break;
        }
        valid = an == bn && !memcmp(ak, bk, an);
        if (!valid)
            break;
        switch (kind(ak, an)) {
        case COLLECTION:
            valid = av == bv;
            break;
        case DOCUMENT:
        case RECORD:
            valid = same_record(c->disk, &source, av, disk, &view, bv, error, length);
            break;
        case FRAME:
            valid = same_frame(c, disk, &view, av, bv, error, length);
            break;
        /* Both full graph validators prove every posting points to its unique
         * primary record, including text postings. Identical primary/catalog
         * bytes and identical key sets prove relocated index equality without
         * decoding a potentially 16 MiB document for every posting. */
        case INDEX:
            break;
        case HISTORY:
            /* Compared separately below, including every retained root. */
            break;
        default:
            valid = false;
            break;
        }
        if (valid) {
            valid = report(p, ctx, YD_RAFT_APPLICATION_VERIFY, ++done);
            if (!valid)
                state->cancelled = true;
        }
    }
    yd_disk_cursor_free(a);
    yd_disk_cursor_free(b);
    return valid;
}
typedef struct {
    YDDisk *source,*destination;YDDiskTxn *txn;YDDiskView map;
    YDRaftApplicationCopyProgress progress;void *context;
    YDRaftApplicationCopyPhase phase;uint64_t *done;YDDiskValidation *validation;
} HistoryContext;
static bool history_progress(void *context,YDDiskValidationPhase phase) {
    (void)phase;HistoryContext *h=context;
    return report(h->progress,h->context,h->phase,++*h->done);
}
static bool history_root_copy(void *context,const YDDiskView *view,YDDiskView *out,char *error,size_t length) {
    HistoryContext *h=context;
    YDDiskValidation validation={history_progress,h,false};
    bool valid=yd_disk_history_root_copy_mapped(h->source,view,h->txn,out,&h->map,&validation,error,length);
    if (validation.cancelled) h->validation->cancelled=true;
    return valid;
}
static bool history_root_same(void *context,const YDDiskView *a,const YDDiskView *b,char *error,size_t length) {
    HistoryContext *h=context;
    YDDiskValidation validation={history_progress,h,false};
    bool valid=yd_disk_history_root_same_checked(h->source,a,h->destination,b,&validation,error,length);
    if (validation.cancelled) h->validation->cancelled=true;
    return valid;
}
static bool history_compare(const YDRaftApplicationCapture *c,YDDisk *disk,
    YDRaftApplicationCopyProgress progress,void *ctx,YDDiskValidation *validation,char *error,size_t length) {
    uint64_t done=0;
    HistoryContext context={.source=c->disk,.destination=disk,.progress=progress,.context=ctx,
        .phase=YD_RAFT_APPLICATION_VERIFY,.done=&done,.validation=validation};
    YDDiskView view=yd_disk_view(disk);
    return yd_disk_history_same(c->disk,&c->info.source,disk,&view,history_root_same,&context,error,length);
}
static bool header(YDDisk *disk) {
    YDDiskView view = yd_disk_view(disk);
    unsigned char expected[YD_DISK_PAGE], actual[YD_DISK_PAGE];
    yd_disk_encode_header(expected, &view);
    size_t done = 0;
    uint64_t offset = (view.generation % 2) * YD_DISK_PAGE;
    while (done < sizeof(actual)) {
        ssize_t n = pread(disk->fd, actual + done, sizeof(actual) - done, (off_t)(offset + done));
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return false;
        done += (size_t)n;
    }
    return !memcmp(expected, actual, sizeof(actual));
}
typedef struct {
    YDRaftApplicationCopyProgress progress;
    void *context;
    YDRaftApplicationCopyPhase phase;
    uint64_t done;
} ValidationProgress;
static bool validation_progress(void *context, YDDiskValidationPhase phase) {
    (void)phase;
    ValidationProgress *p = context;
    return report(p->progress, p->context, p->phase, p->done);
}
YDRaftApplicationImage *yd_raft_application_copy(const YDRaftApplicationCapture *c, int directory,
                                                 size_t cache, YDRaftApplicationCopyProgress p,
                                                 void *ctx, char *error, size_t length) {
    return yd_raft_application_copy_limited(c, directory, cache, YD_DISK_ALLOCATION_UNLIMITED,
                                            NULL, p, ctx, error, length);
}
static YDRaftApplicationImage *copy_limited(const YDRaftApplicationCapture *c,
    int directory, size_t cache, uint64_t limit, YDDiskAllocation *usage,
    YDRaftApplicationCopyProgress p, void *ctx, char *error, size_t length,
    YDRaftApplicationImage **owned) {
    if (usage)
        *usage = (YDDiskAllocation){limit, 0};
    if (!c || directory < 0 || !cache_valid(cache) ||
        (limit != YD_DISK_ALLOCATION_UNLIMITED &&
         (limit < 2 * YD_DISK_PAGE || limit > (uint64_t)INT64_MAX))) {
        fail(error, length);
        return NULL;
    }
    YDStorageLease origin_budget = {0};
    if (!yd_disk_budget_clone(c->disk, 0, &origin_budget, error, length)) return NULL;
    YDRaftApplicationImage *i = calloc(1, sizeof(*i));
    if (!i) {
        yd_storage_budget_release(&origin_budget);
        fail(error, length);
        return NULL;
    }
    i->directory=i->origin=i->marker=-1;
    if (owned) *owned=i;
    i->limit = limit;
    i->origin_budget = origin_budget;
    i->marker = -1;
    /* Keep the source inode alive even after its application/capture close:
     * a numeric dev/inode pair alone can later be recycled. No app is retained. */
    i->origin = fcntl(c->disk->fd, F_DUPFD_CLOEXEC, 0);
    i->directory = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    ValidationProgress vp = {p, ctx, YD_RAFT_APPLICATION_SOURCE, 0};
    YDDiskValidation validation = {validation_progress, &vp, false};
    struct stat status;
    bool valid = i->origin >= 0 && i->directory >= 0 && !fstat(i->directory, &status) &&
                 S_ISDIR(status.st_mode) && status.st_uid == geteuid() &&
                 !(status.st_mode & (S_IWGRP | S_IWOTH)) &&
                 !flock(i->directory, LOCK_EX | LOCK_NB) && empty(i->directory) &&
                 report(p, ctx, YD_RAFT_APPLICATION_SOURCE, 0) &&
                 yd_raft_application_validate_at_cancellable(c->disk, &c->info.checkpoint, &c->info.source,
                                                             &validation, error, length) &&
                 report(p, ctx, YD_RAFT_APPLICATION_SOURCE, 1);
    i->marker = valid ? openat(i->directory, ".yamora-initializing",
                                O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW | O_CLOEXEC, 0600)
                       : -1;
    valid = valid && i->marker >= 0 && !fsync(i->marker) && !fsync(i->directory);
    i->opening = valid;
    YDStorageBudget *budget = c->disk->budget_lease.budget;
    i->writer = !valid ? NULL : c->info.source.format == 8
        ? yd_disk_create_capabilities_staging_budgeted_at(i->directory,
            c->info.source.capabilities, cache, limit, budget, error, length)
        : budget
        ? yd_disk_open_cluster_budgeted_at(i->directory, true, cache, limit,
            budget, error, length)
        : yd_disk_open_cluster_at_limited(i->directory, true, cache, limit, error, length);
    /* An existing native file can appear after empty() but before native open.
     * Opening it performs no writes. Never adopt it into a copy transaction. */
    valid = valid && i->writer && i->writer->created;
    YDDiskTxn *txn = valid ? yd_disk_begin_exclusive(i->writer, error, length) : NULL;
    if (txn) txn->history_copy=true;
    uint64_t done = 0;
    valid = valid && txn && report(p, ctx, YD_RAFT_APPLICATION_COPY, 0);
    for (unsigned pass = 0; valid && pass < 3; pass++)
        valid = copy_keys(c, txn, NULL, pass, p, ctx, &done, error, length);
    valid = valid && remove_map(txn, p, ctx, &done, error, length);
    HistoryContext history={.source=c->disk,.txn=txn,.progress=p,.context=ctx,
        .phase=YD_RAFT_APPLICATION_COPY,.done=&done,.validation=&validation};
    valid=valid && yd_disk_history_copy(c->disk,&c->info.source,txn,history_root_copy,&history,error,length);
    if (valid) {
        YDDiskView *v = yd_disk_tx_view(txn);
        v->generation = c->info.source.generation - 1;
        v->documents = c->info.source.documents;
        v->collections = c->info.source.collections;
        v->bytes = c->info.source.bytes;
        v->revision = c->info.source.revision;
        valid = yd_disk_commit(txn, error, length);
        txn = NULL;
    }
    yd_disk_abort(txn);
    i->disk = valid ? yd_disk_pin(i->writer, cache, error, length) : NULL;
    YDDiskView v = i->disk ? yd_disk_view(i->disk) : (YDDiskView){0};
    vp.phase = YD_RAFT_APPLICATION_VERIFY;
    valid = valid && i->disk &&
            yd_raft_application_validate_at_cancellable(i->disk, &c->info.checkpoint, &v,
                                                         &validation, error, length) &&
            compare(c, i->disk, p, ctx, &validation, error, length) &&
            history_compare(c,i->disk,p,ctx,&validation,error,length) && header(i->disk);
    if (usage)
        *usage = yd_raft_application_image_allocation(i);
    if (!valid) {
        if (owned) *owned=NULL;
        yd_raft_application_image_close(i);
        fail(error, length);
        return NULL;
    }
    i->info = c->info;
    i->device = c->device;
    i->inode = c->inode;
    i->cache = cache;
    return i;
}
static void copy_cancelled(void *context) {
    YDRaftApplicationImage **image=context;
    yd_raft_application_image_close(*image);
    *image=NULL;
}
YDRaftApplicationImage *yd_raft_application_copy_limited(const YDRaftApplicationCapture *c,
    int directory,size_t cache,uint64_t limit,YDDiskAllocation *usage,
    YDRaftApplicationCopyProgress progress,void *context,char *error,size_t length) {
    if (!c || !(c->info.source.capabilities&YD_DISK_CAP_SCHEMA))
        return copy_limited(c,directory,cache,limit,usage,progress,context,error,length,NULL);
    int previous=0;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,&previous)) {
        fail(error,length);return NULL;
    }
    YDRaftApplicationImage *image=NULL;
    /* The holder is populated immediately after allocation, before any I/O or
     * callback. Pending cancellation at restoration disposes the adopted image
     * without touching its preserved destination files or source. */
    pthread_cleanup_push(copy_cancelled,&image);
    image=copy_limited(c,directory,cache,limit,usage,progress,context,error,length,&image);
    if (pthread_setcancelstate(previous,NULL)) {copy_cancelled(&image);fail(error,length);}
    pthread_cleanup_pop(0);
    return image;
}
static bool prune(const YDRaftApplicationCapture *c, YDDisk *existing, YDDiskTxn *txn,
                  YDRaftApplicationCopyProgress p, void *ctx, uint64_t *done, char *error,
                  size_t length) {
    YDDiskView view = yd_disk_view(existing);
    YDDiskCursor *cursor = yd_disk_cursor(existing, &view, NULL, 0, false, error, length);
    unsigned char key[YD_DISK_KEY_LIMIT];
    size_t size;
    uint64_t value;
    int next = 0;
    bool valid = cursor != NULL;
    while (valid &&
           (next = yd_disk_next(cursor, key, sizeof(key), &size, &value, error, length)) == 1) {
        int found = yd_disk_get(c->disk, &c->info.source, key, size, &value, error, length);
        valid = found >= 0 && (found || yd_disk_delete(txn, key, size, error, length)) &&
                report(p, ctx, YD_RAFT_APPLICATION_COPY, ++*done);
    }
    yd_disk_cursor_free(cursor);
    return valid && next == 0;
}
bool yd_raft_application_catch_up(YDRaftApplicationImage *i, const YDRaftApplicationCapture *c,
                                  YDRaftApplicationCopyProgress p, void *ctx, char *error,
                                  size_t length) {
    if (!i || i->failed || !c || i->device != c->device || i->inode != c->inode ||
        memcmp(i->info.checkpoint.cluster, c->info.checkpoint.cluster, 16) ||
        c->info.source.generation < i->info.source.generation ||
        c->info.source.end < i->info.source.end ||
        c->info.checkpoint.applied.term < i->info.checkpoint.applied.term ||
        (c->info.source.generation == i->info.source.generation && !same_info(c->info, i->info)))
        return fail(error, length);
    ValidationProgress vp = {p, ctx, YD_RAFT_APPLICATION_SOURCE, 0};
    YDDiskValidation validation = {validation_progress, &vp, false};
    if (!yd_raft_application_validate_at_cancellable(c->disk, &c->info.checkpoint, &c->info.source,
                                                     &validation, error, length) ||
        !report(p, ctx, YD_RAFT_APPLICATION_SOURCE, 1))
        return fail(error, length);
    YDDiskView old = yd_disk_view(i->disk);
    vp.done = 1;
    if (!yd_raft_application_validate_at_cancellable(i->disk, &i->info.checkpoint, &old,
                                                     &validation, error, length) ||
        !header(i->disk)) {
        i->failed = !validation.cancelled;
        return fail(error, length);
    }
    bool unchanged = c->info.source.generation == i->info.source.generation;
    YDDisk *reader = NULL;
    bool valid = true;
    if (!unchanged) {
        YDDiskTxn *txn = yd_disk_begin_exclusive(i->writer, error, length);
        if (txn) txn->history_copy=true;
        uint64_t done = 0;
        valid = txn && report(p, ctx, YD_RAFT_APPLICATION_COPY, 0) &&
                prune(c, i->disk, txn, p, ctx, &done, error, length);
        for (unsigned pass = 0; valid && pass < 3; pass++)
            valid = copy_keys(c, txn, i->disk, pass, p, ctx, &done, error, length);
        valid = valid && remove_map(txn, p, ctx, &done, error, length);
        HistoryContext history={.source=c->disk,.txn=txn,.progress=p,.context=ctx,
            .phase=YD_RAFT_APPLICATION_COPY,.done=&done,.validation=&validation};
        valid=valid && yd_disk_history_copy(c->disk,&c->info.source,txn,history_root_copy,&history,error,length);
        if (valid) {
            YDDiskView *v = yd_disk_tx_view(txn);
            v->generation = c->info.source.generation - 1;
            v->documents = c->info.source.documents;
            v->collections = c->info.source.collections;
            v->bytes = c->info.source.bytes;
            v->revision = c->info.source.revision;
            valid = yd_disk_commit(txn, error, length);
            txn = NULL;
        }
        yd_disk_abort(txn);
        reader = valid ? yd_disk_pin(i->writer, i->cache, error, length) : NULL;
        valid = valid && reader;
    }
    YDDisk *disk = unchanged ? i->disk : reader;
    YDDiskView view = disk ? yd_disk_view(disk) : (YDDiskView){0};
    vp.phase = YD_RAFT_APPLICATION_VERIFY;
    vp.done = 0;
    valid = valid &&
            yd_raft_application_validate_at_cancellable(disk, &c->info.checkpoint, &view,
                                                         &validation, error, length) &&
            compare(c, disk, p, ctx, &validation, error, length) &&
            history_compare(c,disk,p,ctx,&validation,error,length) && header(disk);
    if (!valid) {
        yd_disk_close(reader);
        i->failed = !unchanged || !validation.cancelled;
        return fail(error, length);
    }
    if (reader) {
        yd_disk_close(i->disk);
        i->disk = reader;
    }
    i->info = c->info;
    return true;
}
