/* Reuse the journal-copy fixture and its scenario dispatcher with a distinct
 * entry point; publication tests exercise the same real metadata and I/O paths. */
#define main journal_copy_fixture_main
#define __wrap_fsync journal_copy_fixture_fsync
#include "raft_journal_copy_harness.c"
#undef main
#undef __wrap_fsync
#include "../src/consensus/journal_publish.h"
#include "../src/consensus/journal_copy_internal.h"
#include <dirent.h>
#include <signal.h>
#include <sys/file.h>
#include <sys/wait.h>
static unsigned rename_failure;
static unsigned unlink_calls, fail_unlink;
static bool uncertain_unlink;
int __real_unlinkat(int, const char *, int);
int __wrap_unlinkat(int directory, const char *name, int flags) {
    if (++unlink_calls == fail_unlink) {
        if (uncertain_unlink && __real_unlinkat(directory, name, flags))
            return -1;
        errno = EIO;
        return -1;
    }
    return __real_unlinkat(directory, name, flags);
}
int __real_renameat(int, const char *, int, const char *);
int __wrap_renameat(int from, const char *old, int to, const char *name) {
    unsigned failure = rename_failure;
    rename_failure = 0;
    if (failure == 1) {
        errno = EIO;
        return -1;
    }
    int status = __real_renameat(from, old, to, name);
    if (failure == 2 && !status) {
        errno = EIO;
        return -1;
    }
    return status;
}
static YDRaft *writing_source;
static unsigned wrote_during_prepare;
static bool writing_valid;
static YDRaftJournalScope *scope_probe;
static YDDiskLineage *lineage_probe;
static unsigned lineage_checks;
static bool lineage_bad;
YDDiskTxn *__real_yd_disk_begin_exclusive(YDDisk *, char *, size_t);
YDDiskTxn *__wrap_yd_disk_begin_exclusive(YDDisk *disk, char *error, size_t length) {
    if (lineage_probe) lineage_bad |= disk->lineage.scope != lineage_probe || !disk->lineage.source;
    return __real_yd_disk_begin_exclusive(disk, error, length);
}
static unsigned scope_checks;
static bool scope_bad;
static bool fail_workspace_tracking;
static int swap_scope_root = -1;
static unsigned swap_scope_syncs;
static bool scope_source_swapped;
YDRaftJournalBinding *__real_yd_raft_journal_scope_workspace(YDRaftJournalScope *, int);
YDRaftJournalBinding *__wrap_yd_raft_journal_scope_workspace(YDRaftJournalScope *scope, int directory) {
    if (scope && fail_workspace_tracking) {
        yd_raft_journal_scope_incomplete(scope);
        return NULL;
    }
    return __real_yd_raft_journal_scope_workspace(scope, directory);
}
int __wrap_fsync(int fd) {
    static bool nested;
    if (nested)
        return __real_fsync(fd);
    nested = true;
    if (scope_probe) {
        YDRaftJournalScopeSnapshot *snapshot = yd_raft_journal_scope_snapshot(scope_probe);
        YDRaftJournalScopeInfo observed;
        scope_bad |= !yd_raft_journal_scope_snapshot_info(snapshot, &observed) ||
            !observed.active || observed.complete;
        scope_checks++;
        yd_raft_journal_scope_snapshot_close(snapshot);
    }
    if (lineage_probe) {
        YDDiskLineageSnapshot *snapshot = yd_disk_lineage_snapshot(lineage_probe);
        YDDiskLineageInfo info;
        bool valid = yd_disk_lineage_snapshot_info(snapshot, &info);
        struct stat file;
        bool bound = false;
        if (valid && !fstat(fd, &file))
            for (size_t i = 0; i < info.source_count; i++)
                bound |= info.sources[i].device == file.st_dev && info.sources[i].inode == file.st_ino;
        lineage_bad |= !valid || (bound && (!info.in_progress || info.complete || !info.entry_count));
        if (bound) lineage_checks++;
        yd_disk_lineage_snapshot_close(snapshot);
    }
    int result = journal_copy_fixture_fsync(fd);
    if (!result && swap_scope_root >= 0) {
        struct stat actual, root;
        if (!fstat(fd, &actual) && !fstat(swap_scope_root, &root) &&
            actual.st_dev == root.st_dev && actual.st_ino == root.st_ino &&
            ++swap_scope_syncs == 2) {
            scope_source_swapped = !renameat(swap_scope_root, YD_DISK_FILE,
                swap_scope_root, "preserved-source") &&
                !mkfifoat(swap_scope_root, YD_DISK_FILE, 0600);
            swap_scope_root = -1;
        }
    }
    if (!result && writing_source) {
        writing_valid &= propose(writing_source, "during-prepare") && acknowledge(writing_source);
        wrote_during_prepare++;
    }
    nested = false;
    return result;
}
static unsigned links_at(int root, const char *prefix, dev_t device, ino_t inode) {
    int fd = openat(root, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    DIR *scan = fd >= 0 ? fdopendir(fd) : NULL;
    if (!scan) {
        if (fd >= 0)
            close(fd);
        return 0;
    }
    unsigned count = 0;
    struct dirent *entry;
    while ((entry = readdir(scan))) {
        if (strncmp(entry->d_name, prefix, strlen(prefix)))
            continue;
        struct stat status;
        if (!fstatat(root, entry->d_name, &status, AT_SYMLINK_NOFOLLOW) &&
            S_ISREG(status.st_mode) && status.st_dev == device && status.st_ino == inode)
            count++;
    }
    closedir(scan);
    return count;
}
static int prepared(const char *root, bool writing) {
    char source_path[4096], path[4096];
    int dir = candidate(root, "source", source_path);
    REQUIRE(dir >= 0);
    YDRaft *r = seed(source_path);
    REQUIRE(r);
    YDDiskView before = yd_disk_view(r->disk);
    struct stat original;
    REQUIRE(!fstat(r->disk->fd, &original));
    YDRaftJournalCapture *capture = yd_raft_journal_capture(r, 32768, error, sizeof(error));
    REQUIRE(capture);
    int target = candidate(root, "copy", path);
    REQUIRE(target >= 0);
    YDRaftJournalImage *image =
        yd_raft_journal_copy(capture, target, 32768, NULL, NULL, error, sizeof(error));
    REQUIRE(image);
    struct stat copied;
    REQUIRE(!fstat(yd_raft_journal_image_disk(image)->fd, &copied));
    writing_source = writing ? r : NULL;
    writing_valid = true;
    wrote_during_prepare = 0;
    YDRaftJournalPublication *publication =
        yd_raft_journal_prepare(image, dir, error, sizeof(error));
    writing_source = NULL;
    REQUIRE(publication && writing_valid &&
            yd_raft_journal_prepared_current(publication, r) == !writing &&
            (!writing || wrote_during_prepare == 4) &&
            !yd_raft_journal_prepare(image, dir, error, sizeof(error)) &&
            !yd_raft_journal_catch_up(image, capture, NULL, NULL, error, sizeof(error)));
    struct stat selected;
    REQUIRE(!fstatat(dir, YD_DISK_FILE, &selected, AT_SYMLINK_NOFOLLOW) &&
            selected.st_dev == original.st_dev && selected.st_ino == original.st_ino &&
            links_at(dir, ".prepared-journal-", copied.st_dev, copied.st_ino) == 1);
    int retained =
        openat(dir, YD_RAFT_JOURNAL_RETAINED, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    REQUIRE(retained >= 0);
    REQUIRE(links_at(retained, "old-", original.st_dev, original.st_ino) == 1 &&
            r->role == YD_RAFT_LEADER &&
            (writing || yd_disk_view(r->disk).generation == before.generation));
    close(retained);
    yd_raft_journal_publication_close(publication);
    REQUIRE(yd_raft_journal_image_disk(image));
    if (!writing)
        REQUIRE(yd_raft_journal_catch_up(image, capture, NULL, NULL, error, sizeof(error)));
    yd_raft_journal_capture_close(capture);
    yd_raft_journal_image_close(image);
    yd_raft_close(r);
    close(dir);
    close(target);
    return 0;
}
static int prepare_roots(const char *root) {
    char source_path[4096], path[4096], moved[4096];
    int dir = candidate(root, "source", source_path);
    REQUIRE(dir >= 0);
    YDRaft *r = seed(source_path);
    REQUIRE(r);
    YDRaftJournalCapture *capture = yd_raft_journal_capture(r, 32768, error, sizeof(error));
    REQUIRE(capture);
    int target = candidate(root, "copy", path);
    REQUIRE(target >= 0);
    YDRaftJournalImage *image =
        yd_raft_journal_copy(capture, target, 32768, NULL, NULL, error, sizeof(error));
    REQUIRE(image);
    int foreign = candidate(root, "foreign", path);
    REQUIRE(foreign >= 0);
    REQUIRE(!yd_raft_journal_prepare(image, foreign, error, sizeof(error)) &&
            !yd_raft_journal_prepare(image, -1, error, sizeof(error)) &&
            !yd_raft_journal_prepare(NULL, dir, error, sizeof(error)));
    REQUIRE(!linkat(dir, YD_DISK_FILE, foreign, YD_DISK_FILE, 0));
    YDRaftJournalPublication *alias = yd_raft_journal_prepare(image, foreign, error, sizeof(error));
    REQUIRE(alias && !yd_raft_journal_prepared_current(alias, r));
    yd_raft_journal_publication_close(alias);
    REQUIRE(!fchmod(dir, 0770) && !yd_raft_journal_prepare(image, dir, error, sizeof(error)) &&
            !fchmod(dir, 0700));
    REQUIRE(!symlinkat("elsewhere", dir, YD_RAFT_JOURNAL_RETAINED) &&
            !yd_raft_journal_prepare(image, dir, error, sizeof(error)));
    REQUIRE(!unlinkat(dir, YD_RAFT_JOURNAL_RETAINED, 0));
    snprintf(moved, sizeof(moved), "%s/moved", root);
    REQUIRE(!rename(source_path, moved) && !mkdir(source_path, 0700));
    YDRaftJournalPublication *publication =
        yd_raft_journal_prepare(image, dir, error, sizeof(error));
    REQUIRE(publication && yd_raft_journal_prepared_current(publication, r) &&
            yd_disk_present(source_path) == 0 && yd_disk_present(moved) == 1);
    yd_raft_journal_publication_close(publication);
    yd_raft_journal_capture_close(capture);
    yd_raft_journal_image_close(image);
    yd_raft_close(r);
    close(foreign);
    close(dir);
    close(target);
    return 0;
}
static int prepare_sync(const char *root) {
    char source_path[4096], path[4096];
    int dir = candidate(root, "source", source_path);
    REQUIRE(dir >= 0);
    YDRaft *r = seed(source_path);
    REQUIRE(r);
    YDDiskView before = yd_disk_view(r->disk);
    YDRaftJournalCapture *capture = yd_raft_journal_capture(r, 32768, error, sizeof(error));
    REQUIRE(capture);
    int target = candidate(root, "copy", path);
    REQUIRE(target >= 0);
    YDRaftJournalImage *image =
        yd_raft_journal_copy(capture, target, 32768, NULL, NULL, error, sizeof(error));
    REQUIRE(image);
    for (unsigned i = 1; i <= 4; i++) {
        sync_calls = 0;
        fail_sync = i;
        YDRaftJournalPublication *publication =
            yd_raft_journal_prepare(image, dir, error, sizeof(error));
        fail_sync = 0;
        REQUIRE(!publication && sync_calls >= i && yd_raft_journal_image_current(image, r) &&
                yd_disk_view(r->disk).generation == before.generation && r->role == YD_RAFT_LEADER);
    }
    YDRaftJournalPublication *publication =
        yd_raft_journal_prepare(image, dir, error, sizeof(error));
    REQUIRE(publication && yd_raft_journal_prepared_current(publication, r));
    yd_raft_journal_publication_close(publication);
    yd_raft_journal_capture_close(capture);
    yd_raft_journal_image_close(image);
    yd_raft_close(r);
    close(dir);
    close(target);
    return 0;
}
static bool replace_link(int directory, const char *prefix) {
    int fd = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    DIR *scan = fd >= 0 ? fdopendir(fd) : NULL;
    if (!scan) {
        if (fd >= 0)
            close(fd);
        return false;
    }
    char name[80] = {0};
    struct dirent *entry;
    while ((entry = readdir(scan))) {
        if (!strncmp(entry->d_name, prefix, strlen(prefix)) &&
            strlen(entry->d_name) < sizeof(name)) {
            memcpy(name, entry->d_name, strlen(entry->d_name) + 1);
            break;
        }
    }
    closedir(scan);
    if (!name[0] || renameat(directory, name, directory, "saved-link"))
        return false;
    fd = openat(directory, name, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0)
        return false;
    close(fd);
    return true;
}
static int prepare_tamper(const char *root) {
    for (unsigned i = 0; i < 6; i++) {
        char name[32], base[4096], source_path[4096], path[4096];
        snprintf(name, sizeof(name), "case-%u", i);
        int basefd = candidate(root, name, base);
        REQUIRE(basefd >= 0);
        close(basefd);
        int dir = candidate(base, "source", source_path);
        REQUIRE(dir >= 0);
        YDRaft *r = seed(source_path);
        REQUIRE(r);
        YDDiskView before = yd_disk_view(r->disk);
        YDRaftJournalCapture *capture = yd_raft_journal_capture(r, 32768, error, sizeof(error));
        REQUIRE(capture);
        int target = candidate(base, "copy", path);
        REQUIRE(target >= 0);
        YDRaftJournalImage *image =
            yd_raft_journal_copy(capture, target, 32768, NULL, NULL, error, sizeof(error));
        REQUIRE(image);
        YDRaftJournalPublication *p = yd_raft_journal_prepare(image, dir, error, sizeof(error));
        REQUIRE(p && yd_raft_journal_prepared_current(p, r));
        if (i == 0)
            REQUIRE(replace_link(dir, ".prepared-journal-"));
        if (i == 1) {
            int retained = openat(dir, YD_RAFT_JOURNAL_RETAINED,
                                  O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            REQUIRE(retained >= 0);
            REQUIRE(replace_link(retained, "old-"));
            close(retained);
        }
        if (i == 2)
            REQUIRE(!renameat(dir, YD_RAFT_JOURNAL_RETAINED, dir, "saved-directory") &&
                    !mkdirat(dir, YD_RAFT_JOURNAL_RETAINED, 0700));
        if (i == 3) {
            int marker = openat(target, ".yamora-initializing", O_WRONLY | O_NOFOLLOW | O_CLOEXEC);
            REQUIRE(marker >= 0);
            REQUIRE(!ftruncate(marker, 1));
            close(marker);
        }
        if (i == 4)
            REQUIRE(replace_link(dir, YD_DISK_FILE));
        if (i == 5) {
            int marker =
                openat(dir, ".yamora-initializing", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
            REQUIRE(marker >= 0);
            close(marker);
        }
        bool published = true;
        unsigned unlinks = unlink_calls;
        REQUIRE(!yd_raft_journal_prepared_current(p, r) &&
                !yd_raft_journal_publish(p, r, &published, error, sizeof(error)) && !published &&
                !yd_raft_journal_cancel(p, error, sizeof(error)) && unlink_calls == unlinks &&
                r->role == YD_RAFT_LEADER && yd_disk_view(r->disk).generation == before.generation);
        yd_raft_journal_publication_close(p);
        yd_raft_journal_capture_close(capture);
        yd_raft_journal_image_close(image);
        yd_raft_close(r);
        close(dir);
        close(target);
    }
    return 0;
}
typedef struct {
    int source, target;
    char path[4096];
    YDRaft *raft;
    YDRaftJournalCapture *capture;
    YDRaftJournalImage *image;
    YDRaftJournalPublication *publication;
} Fixture;
static bool fixture(const char *root, Fixture *f) {
    char target[4096];
    f->source = candidate(root, "source", f->path);
    f->target = candidate(root, "copy", target);
    f->raft = f->source >= 0 && f->target >= 0 ? seed(f->path) : NULL;
    f->capture = f->raft ? yd_raft_journal_capture(f->raft, 32768, error, sizeof(error)) : NULL;
    f->image = f->capture ? yd_raft_journal_copy(f->capture, f->target, 32768, NULL, NULL, error,
                                                 sizeof(error))
                          : NULL;
    f->publication =
        f->image ? yd_raft_journal_prepare(f->image, f->source, error, sizeof(error)) : NULL;
    return f->publication != NULL;
}
static void fixture_close(Fixture *f) {
    yd_raft_journal_publication_close(f->publication);
    yd_raft_journal_capture_close(f->capture);
    yd_raft_journal_image_close(f->image);
    yd_raft_close(f->raft);
    if (f->source >= 0)
        close(f->source);
    if (f->target >= 0)
        close(f->target);
}
static bool metadata_is(YDRaft *r, const YDRaftMeta *expected) {
    unsigned char first[144], second[144];
    size_t n = yd_raft_encode_meta(&r->meta, first), m = yd_raft_encode_meta(expected, second);
    return n == m && !memcmp(first, second, n);
}
static bool command_is(YDRaft *r, uint64_t index, const char *text) {
    YDRaftEntry entry;
    if (!yd_raft_entry(r, index, &entry))
        return false;
    bool valid = entry.size == strlen(text) && !memcmp(entry.command, text, entry.size);
    yd_raft_entry_free(&entry);
    return valid;
}
static int publish(const char *root) {
    Fixture f = {0};
    REQUIRE(fixture(root, &f));
    YDRaftMeta metadata = f.raft->meta;
    unsigned leader = f.raft->leader;
    YDRaftPeer peers[YD_RAFT_VOTERS + 1];
    memcpy(peers, f.raft->peers, sizeof(peers));
    struct stat original, copy, current;
    REQUIRE(!fstat(f.raft->disk->fd, &original) &&
            !fstat(yd_raft_journal_image_disk(f.image)->fd, &copy));
    YDDisk *old_view =
        yd_disk_pin(yd_raft_journal_image_disk(f.image), 32768, error, sizeof(error));
    REQUIRE(old_view);
    bool published = false;
    REQUIRE(!yd_raft_journal_publish(f.publication, f.raft, NULL, error, sizeof(error)) &&
            !yd_raft_journal_publish(NULL, f.raft, &published, error, sizeof(error)) &&
            !published &&
            !yd_raft_journal_publish(f.publication, NULL, &published, error, sizeof(error)) &&
            !published && yd_raft_journal_prepared_current(f.publication, f.raft));
    REQUIRE(yd_raft_journal_publish(f.publication, f.raft, &published, error, sizeof(error)) &&
            published && metadata_is(f.raft, &metadata) && f.raft->role == YD_RAFT_LEADER &&
            f.raft->leader == leader && !memcmp(peers, f.raft->peers, sizeof(peers)) &&
            !yd_raft_journal_image_disk(f.image) &&
            !yd_raft_journal_prepared_current(f.publication, f.raft) &&
            !fstat(f.raft->disk->fd, &current) && current.st_dev == copy.st_dev &&
            current.st_ino == copy.st_ino && current.st_ino != original.st_ino);
    bool again = true;
    REQUIRE(!yd_raft_journal_publish(f.publication, f.raft, &again, error, sizeof(error)) &&
            !again);
    REQUIRE(propose(f.raft, "after-selection") && acknowledge(f.raft) && acknowledge(f.raft) &&
            command_is(f.raft, 53, "after-selection"));
    YDRaftMeta updated = f.raft->meta;
    REQUIRE(copied_offset(old_view, 52) && !copied_offset(old_view, 53));
    yd_disk_close(old_view);
    char historical[4096];
    int dir = candidate(root, "historical", historical);
    REQUIRE(dir >= 0);
    YDRaftJournalImage *old =
        yd_raft_journal_copy(f.capture, dir, 32768, NULL, NULL, error, sizeof(error));
    REQUIRE(old && copied_entry(old, &metadata, 52, "pending", 7));
    yd_raft_journal_image_close(old);
    close(dir);
    fixture_close(&f);
    YDRaft *r = yd_raft_open(f.path, cluster, 1, 3, 32768, error, sizeof(error));
    REQUIRE(r && metadata_is(r, &updated) && command_is(r, 52, "pending") &&
            command_is(r, 53, "after-selection"));
    yd_raft_close(r);
    return 0;
}
static int publish_stale(const char *root) {
    Fixture f = {0};
    REQUIRE(fixture(root, &f));
    struct stat before, after;
    REQUIRE(!fstat(f.raft->disk->fd, &before));
    REQUIRE(propose(f.raft, "newer"));
    bool published = true;
    REQUIRE(!yd_raft_journal_publish(f.publication, f.raft, &published, error, sizeof(error)) &&
            !published && f.raft->role == YD_RAFT_LEADER &&
            !fstatat(f.source, YD_DISK_FILE, &after, AT_SYMLINK_NOFOLLOW) &&
            after.st_dev == before.st_dev && after.st_ino == before.st_ino);
    yd_raft_journal_publication_close(f.publication);
    f.publication = NULL;
    YDRaftJournalCapture *latest = yd_raft_journal_capture(f.raft, 32768, error, sizeof(error));
    REQUIRE(latest);
    REQUIRE(yd_raft_journal_catch_up(f.image, latest, NULL, NULL, error, sizeof(error)));
    f.publication = yd_raft_journal_prepare(f.image, f.source, error, sizeof(error));
    REQUIRE(f.publication);
    REQUIRE(yd_raft_journal_publish(f.publication, f.raft, &published, error, sizeof(error)) &&
            published && command_is(f.raft, 53, "newer"));
    yd_raft_journal_capture_close(latest);
    fixture_close(&f);
    return 0;
}
static int publish_fail(const char *root) {
    for (unsigned i = 0; i < 3; i++) {
        char name[32], path[4096];
        snprintf(name, sizeof(name), "case-%u", i);
        int dir = candidate(root, name, path);
        REQUIRE(dir >= 0);
        close(dir);
        Fixture f = {0};
        REQUIRE(fixture(path, &f));
        YDRaftMeta metadata = f.raft->meta;
        bool published = false;
        sync_calls = 0;
        fail_sync = i == 0 ? 1 : 0;
        rename_failure = i;
        bool valid =
            yd_raft_journal_publish(f.publication, f.raft, &published, error, sizeof(error));
        fail_sync = 0;
        rename_failure = 0;
        REQUIRE(!valid && published == (i != 1) && f.raft->role == YD_RAFT_FAILED &&
                metadata_is(f.raft, &metadata));
        fixture_close(&f);
        YDRaft *r = yd_raft_open(f.path, cluster, 1, 3, 32768, error, sizeof(error));
        REQUIRE(r && metadata_is(r, &metadata) && command_is(r, 52, "pending"));
        yd_raft_close(r);
    }
    return 0;
}
static int publish_kill(const char *root) {
    for (unsigned stage = 1; stage <= 4; stage++) {
        char name[32], path[4096];
        snprintf(name, sizeof(name), "case-%u", stage);
        int dir = candidate(root, name, path);
        REQUIRE(dir >= 0);
        close(dir);
        Fixture f = {0};
        REQUIRE(fixture(path, &f));
        YDRaftMeta metadata = f.raft->meta;
        pid_t child = fork();
        REQUIRE(child >= 0);
        if (!child) {
            char text[16];
            snprintf(text, sizeof(text), "%u", stage);
            if (setenv("YAMORA_JOURNAL_PUBLISH_KILL_AT", text, 1))
                _exit(90);
            bool published;
            yd_raft_journal_publish(f.publication, f.raft, &published, error, sizeof(error));
            _exit(91);
        }
        fixture_close(&f);
        int status;
        REQUIRE(waitpid(child, &status, 0) == child && WIFSIGNALED(status) &&
                WTERMSIG(status) == SIGKILL);
        YDRaft *r = yd_raft_open(f.path, cluster, 1, 3, 32768, error, sizeof(error));
        REQUIRE(r && metadata_is(r, &metadata) && command_is(r, 52, "pending") && elect(r) &&
                propose(r, "after-kill") && acknowledge(r) && command_is(r, 54, "after-kill"));
        yd_raft_close(r);
    }
    return 0;
}
static int retire(const char *root, bool writing) {
    Fixture f = {0};
    REQUIRE(fixture(root, &f));
    YDDisk *historical = yd_disk_pin(f.raft->disk, 32768, error, sizeof(error));
    REQUIRE(historical);
    bool published = false;
    REQUIRE(!yd_raft_journal_retire(NULL, error, sizeof(error)) &&
            !yd_raft_journal_retire(f.publication, error, sizeof(error)) &&
            yd_raft_journal_publish(f.publication, f.raft, &published, error, sizeof(error)) &&
            published);
    /* Unknown files are not this operation's cleanup targets. */
    int unknown = openat(f.target, "owner-note", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    REQUIRE(unknown >= 0 && write(unknown, "keep", 4) == 4);
    close(unknown);
    if (writing) {
        writing_source = f.raft;
        writing_valid = true;
        wrote_during_prepare = 0;
    }
    bool cleaned = yd_raft_journal_retire(f.publication, error, sizeof(error));
    writing_source = NULL;
    REQUIRE(cleaned && (!writing || (writing_valid && wrote_during_prepare == 2)));
    struct stat old, current, named;
    REQUIRE(!fstat(historical->fd, &old) && old.st_nlink == 0 && copied_offset(historical, 52) &&
            !fstat(f.raft->disk->fd, &current) && current.st_nlink == 1 &&
            current.st_size < old.st_size &&
            fstatat(f.target, YD_DISK_FILE, &named, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT &&
            !fstatat(f.target, ".yamora-initializing", &named, AT_SYMLINK_NOFOLLOW) &&
            !fstatat(f.target, "owner-note", &named, AT_SYMLINK_NOFOLLOW) && named.st_size == 4 &&
            yd_raft_journal_retire(f.publication, error, sizeof(error)));
    char path[4096];
    int dir = candidate(root, "historical", path);
    REQUIRE(dir >= 0);
    YDRaftJournalImage *image =
        yd_raft_journal_copy(f.capture, dir, 32768, NULL, NULL, error, sizeof(error));
    REQUIRE(image && copied_entry(image, &f.raft->meta, 52, "pending", 7));
    yd_raft_journal_image_close(image);
    close(dir);
    yd_disk_close(historical);
    REQUIRE(propose(f.raft, "after-retirement") && acknowledge(f.raft) && acknowledge(f.raft));
    YDRaftMeta expected = f.raft->meta;
    REQUIRE(command_is(f.raft, expected.last, "after-retirement"));
    fixture_close(&f);
    YDRaft *r = yd_raft_open(f.path, cluster, 1, 3, 32768, error, sizeof(error));
    REQUIRE(r && metadata_is(r, &expected) && command_is(r, expected.last, "after-retirement"));
    yd_raft_close(r);
    return 0;
}
static int retire_uncertain(const char *root) {
    for (unsigned i = 0; i < 4; i++) {
        char name[32], path[4096];
        snprintf(name, sizeof(name), "case-%u", i);
        int dir = candidate(root, name, path);
        REQUIRE(dir >= 0);
        close(dir);
        Fixture f = {0};
        REQUIRE(fixture(path, &f));
        bool published = false;
        if (i) {
            sync_calls = 0;
            fail_sync = i == 1 ? 1 : 0;
            rename_failure = i == 2 ? 1 : i == 3 ? 2 : 0;
            REQUIRE(
                !yd_raft_journal_publish(f.publication, f.raft, &published, error, sizeof(error)));
            fail_sync = rename_failure = 0;
        }
        struct stat before, after;
        REQUIRE(!fstatat(f.target, YD_DISK_FILE, &before, AT_SYMLINK_NOFOLLOW));
        unsigned unlinks = unlink_calls;
        REQUIRE(!yd_raft_journal_retire(f.publication, error, sizeof(error)) &&
                unlink_calls == unlinks &&
                !fstatat(f.target, YD_DISK_FILE, &after, AT_SYMLINK_NOFOLLOW) &&
                before.st_nlink == after.st_nlink);
        fixture_close(&f);
        YDRaft *r = yd_raft_open(f.path, cluster, 1, 3, 32768, error, sizeof(error));
        REQUIRE(r && command_is(r, 52, "pending"));
        yd_raft_close(r);
    }
    return 0;
}
static int retire_tamper(const char *root) {
    for (unsigned i = 0; i < 4; i++) {
        char name[32], path[4096];
        snprintf(name, sizeof(name), "case-%u", i);
        int dir = candidate(root, name, path);
        REQUIRE(dir >= 0);
        close(dir);
        Fixture f = {0};
        REQUIRE(fixture(path, &f));
        bool published = false;
        REQUIRE(yd_raft_journal_publish(f.publication, f.raft, &published, error, sizeof(error)) &&
                published);
        if (i == 0) {
            int retained = openat(f.source, YD_RAFT_JOURNAL_RETAINED,
                                  O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            REQUIRE(retained >= 0 && replace_link(retained, "old-"));
            close(retained);
        } else if (i == 1)
            REQUIRE(replace_link(f.target, YD_DISK_FILE));
        else if (i == 2)
            REQUIRE(replace_link(f.source, YD_DISK_FILE));
        else
            REQUIRE(!renameat(f.source, YD_RAFT_JOURNAL_RETAINED, f.source, "saved-retained") &&
                    !mkdirat(f.source, YD_RAFT_JOURNAL_RETAINED, 0700));
        unsigned unlinks = unlink_calls;
        REQUIRE(!yd_raft_journal_retire(f.publication, error, sizeof(error)) &&
                unlink_calls == unlinks && f.raft->role == YD_RAFT_LEADER &&
                command_is(f.raft, 52, "pending"));
        fixture_close(&f);
    }
    return 0;
}
static int retire_fail(const char *root) {
    for (unsigned i = 0; i < 6; i++) {
        char name[32], path[4096];
        snprintf(name, sizeof(name), "case-%u", i);
        int dir = candidate(root, name, path);
        REQUIRE(dir >= 0);
        close(dir);
        Fixture f = {0};
        REQUIRE(fixture(path, &f));
        bool published = false;
        REQUIRE(yd_raft_journal_publish(f.publication, f.raft, &published, error, sizeof(error)) &&
                published);
        sync_calls = unlink_calls = 0;
        fail_sync = i < 2 ? i + 1 : 0;
        fail_unlink = i >= 2 ? 1 + (i - 2) % 2 : 0;
        uncertain_unlink = i >= 4;
        bool cleaned = yd_raft_journal_retire(f.publication, error, sizeof(error));
        fail_sync = fail_unlink = 0;
        uncertain_unlink = false;
        REQUIRE(!cleaned && f.raft->role == YD_RAFT_LEADER && command_is(f.raft, 52, "pending") &&
                propose(f.raft, "between-retirement-attempts") &&
                yd_raft_journal_retire(f.publication, error, sizeof(error)) &&
                command_is(f.raft, 53, "between-retirement-attempts"));
        YDRaftMeta expected = f.raft->meta;
        fixture_close(&f);
        YDRaft *r = yd_raft_open(f.path, cluster, 1, 3, 32768, error, sizeof(error));
        REQUIRE(r && metadata_is(r, &expected) && command_is(r, 53, "between-retirement-attempts"));
        yd_raft_close(r);
    }
    return 0;
}
static int cleanup_kill(const char *root, bool cancelling) {
    for (unsigned stage = 1; stage <= 5; stage++) {
        char name[32], path[4096];
        snprintf(name, sizeof(name), "case-%u", stage);
        int dir = candidate(root, name, path);
        REQUIRE(dir >= 0);
        close(dir);
        Fixture f = {0};
        REQUIRE(fixture(path, &f));
        bool published = false;
        if (!cancelling)
            REQUIRE(
                yd_raft_journal_publish(f.publication, f.raft, &published, error, sizeof(error)) &&
                published);
        YDRaftMeta expected = f.raft->meta;
        struct stat selected;
        REQUIRE(!fstat(f.raft->disk->fd, &selected));
        pid_t child = fork();
        REQUIRE(child >= 0);
        if (!child) {
            char text[16];
            snprintf(text, sizeof(text), "%u", stage);
            if (setenv(cancelling ? "YAMORA_JOURNAL_CANCEL_KILL_AT"
                                  : "YAMORA_JOURNAL_RETIRE_KILL_AT",
                       text, 1))
                _exit(90);
            if (cancelling)
                yd_raft_journal_cancel(f.publication, error, sizeof(error));
            else
                yd_raft_journal_retire(f.publication, error, sizeof(error));
            _exit(91);
        }
        fixture_close(&f);
        int status;
        REQUIRE(waitpid(child, &status, 0) == child && WIFSIGNALED(status) &&
                WTERMSIG(status) == SIGKILL);
        YDRaft *r = yd_raft_open(f.path, cluster, 1, 3, 32768, error, sizeof(error));
        struct stat current;
        REQUIRE(r && metadata_is(r, &expected) && !fstat(r->disk->fd, &current) &&
                current.st_ino == selected.st_ino && command_is(r, 52, "pending") && elect(r) &&
                propose(r, "after-retirement-kill") && acknowledge(r) &&
                command_is(r, 54, "after-retirement-kill"));
        yd_raft_close(r);
    }
    return 0;
}
static int cancel_preparation(const char *root) {
    Fixture f = {0};
    REQUIRE(fixture(root, &f));
    REQUIRE(propose(f.raft, "after-prepare"));
    bool published = true;
    REQUIRE(!yd_raft_journal_publish(f.publication, f.raft, &published, error, sizeof(error)) &&
            !published);
    REQUIRE(!yd_raft_journal_cancel(NULL, error, sizeof(error)) &&
            yd_raft_journal_cancel(f.publication, error, sizeof(error)) &&
            yd_raft_journal_cancel(f.publication, error, sizeof(error)));
    struct stat source, copied;
    REQUIRE(!fstat(f.raft->disk->fd, &source) && source.st_nlink == 1 &&
            !fstat(yd_raft_journal_image_disk(f.image)->fd, &copied) && copied.st_nlink == 1 &&
            links_at(f.source, ".prepared-journal-", copied.st_dev, copied.st_ino) == 0);
    REQUIRE(!yd_raft_journal_publish(f.publication, f.raft, &published, error, sizeof(error)) &&
            !published && f.raft->role == YD_RAFT_LEADER &&
            !yd_raft_journal_prepare(f.image, f.source, error, sizeof(error)));
    yd_raft_journal_publication_close(f.publication);
    f.publication = NULL;
    YDRaftJournalCapture *latest = yd_raft_journal_capture(f.raft, 32768, error, sizeof(error));
    REQUIRE(latest && yd_raft_journal_catch_up(f.image, latest, NULL, NULL, error, sizeof(error)));
    yd_raft_journal_capture_close(latest);
    f.publication = yd_raft_journal_prepare(f.image, f.source, error, sizeof(error));
    REQUIRE(f.publication &&
            yd_raft_journal_publish(f.publication, f.raft, &published, error, sizeof(error)) &&
            published && yd_raft_journal_retire(f.publication, error, sizeof(error)) &&
            command_is(f.raft, 53, "after-prepare"));
    YDRaftMeta expected = f.raft->meta;
    fixture_close(&f);
    YDRaft *r = yd_raft_open(f.path, cluster, 1, 3, 32768, error, sizeof(error));
    REQUIRE(r && metadata_is(r, &expected) && command_is(r, 53, "after-prepare"));
    yd_raft_close(r);
    return 0;
}
static int cancel_attempted(const char *root) {
    for (unsigned i = 0; i < 4; i++) {
        char name[32], path[4096];
        snprintf(name, sizeof(name), "case-%u", i);
        int dir = candidate(root, name, path);
        REQUIRE(dir >= 0);
        close(dir);
        Fixture f = {0};
        REQUIRE(fixture(path, &f));
        bool published = false;
        sync_calls = 0;
        fail_sync = i == 1 ? 1 : 0;
        rename_failure = i == 2 ? 1 : i == 3 ? 2 : 0;
        bool selected =
            yd_raft_journal_publish(f.publication, f.raft, &published, error, sizeof(error));
        fail_sync = rename_failure = 0;
        REQUIRE(selected == (i == 0));
        unsigned unlinks = unlink_calls;
        struct stat before, after;
        REQUIRE(!fstatat(f.target, YD_DISK_FILE, &before, AT_SYMLINK_NOFOLLOW) &&
                !yd_raft_journal_cancel(f.publication, error, sizeof(error)) &&
                unlink_calls == unlinks &&
                !fstatat(f.target, YD_DISK_FILE, &after, AT_SYMLINK_NOFOLLOW) &&
                before.st_nlink == after.st_nlink);
        fixture_close(&f);
        YDRaft *r = yd_raft_open(f.path, cluster, 1, 3, 32768, error, sizeof(error));
        REQUIRE(r && command_is(r, 52, "pending"));
        yd_raft_close(r);
    }
    return 0;
}
static int cancel_fail(const char *root) {
    for (unsigned i = 0; i < 6; i++) {
        char name[32], path[4096];
        snprintf(name, sizeof(name), "case-%u", i);
        int dir = candidate(root, name, path);
        REQUIRE(dir >= 0);
        close(dir);
        Fixture f = {0};
        REQUIRE(fixture(path, &f));
        sync_calls = unlink_calls = 0;
        fail_sync = i < 2 ? i + 1 : 0;
        fail_unlink = i >= 2 ? 1 + (i - 2) % 2 : 0;
        uncertain_unlink = i >= 4;
        bool cancelled = yd_raft_journal_cancel(f.publication, error, sizeof(error));
        fail_sync = fail_unlink = 0;
        uncertain_unlink = false;
        REQUIRE(!cancelled && f.raft->role == YD_RAFT_LEADER &&
                propose(f.raft, "between-cancel-attempts") &&
                yd_raft_journal_cancel(f.publication, error, sizeof(error)) &&
                command_is(f.raft, 53, "between-cancel-attempts"));
        struct stat source, copied;
        REQUIRE(!fstat(f.raft->disk->fd, &source) && source.st_nlink == 1 &&
                !fstat(yd_raft_journal_image_disk(f.image)->fd, &copied) && copied.st_nlink == 1);
        YDRaftMeta expected = f.raft->meta;
        fixture_close(&f);
        YDRaft *r = yd_raft_open(f.path, cluster, 1, 3, 32768, error, sizeof(error));
        REQUIRE(r && metadata_is(r, &expected) && command_is(r, 53, "between-cancel-attempts"));
        yd_raft_close(r);
    }
    return 0;
}
static bool scope_current(YDRaftJournalScope *scope, size_t count, bool complete) {
    YDRaftJournalScopeSnapshot *snapshot = yd_raft_journal_scope_snapshot(scope);
    YDRaftJournalScopeInfo observed;
    bool valid = yd_raft_journal_scope_snapshot_info(snapshot, &observed) &&
        !observed.active && observed.count == count && observed.complete == complete;
    yd_raft_journal_scope_snapshot_close(snapshot);
    return valid;
}
static bool scope_phase(void) {
    bool valid = scope_checks && !scope_bad;
    scope_checks = 0;
    return valid;
}
static void scope_require(bool valid, unsigned line, const char *expression) {
    if (!valid) {
        fprintf(stderr, "scope line %u: %s (%s)\n", line, expression, error);
        _Exit(2);
    }
}
#define SCOPE_REQUIRE(x) scope_require((x), __LINE__, #x)
static int scoped_producers(const char *root, bool tracking_failure) {
    char source_path[4096], target_path[4096];
    int source = candidate(root, "source", source_path);
    int target = candidate(root, "copy", target_path);
    SCOPE_REQUIRE(source >= 0 && target >= 0);
    YDRaftJournalScope *scope = yd_raft_journal_scope_new(); SCOPE_REQUIRE(scope);
    YDDiskLineage *lineage = yd_disk_lineage_new(); SCOPE_REQUIRE(lineage);
    scope_probe = scope;
    lineage_probe = lineage;
    YDRaft *r = yd_raft_open_observed(source_path, cluster, 1, 3, 32768, scope, lineage, error, sizeof(error));
    SCOPE_REQUIRE(r && scope_phase() && scope_current(scope, 0, true));
    SCOPE_REQUIRE(lineage_checks && !lineage_bad);
    SCOPE_REQUIRE(elect(r) && propose(r, "# exact YAML\r\nkey: value # keep\r\n") && acknowledge(r));
    SCOPE_REQUIRE(scope_phase() && scope_current(scope, 0, true));
    YDRaftSnapshotBase base = {.index = 1, .term = 1, .archive = {7}};
    SCOPE_REQUIRE(yd_raft_checkpoint(r, &base) && scope_phase() && scope_current(scope, 0, true));
    YDRaftJournalCapture *capture = yd_raft_journal_capture(r, 32768, error, sizeof(error));
    SCOPE_REQUIRE(capture);
    fail_workspace_tracking = tracking_failure;
    YDRaftJournalImage *image = yd_raft_journal_copy(capture, target, 32768,
        NULL, NULL, error, sizeof(error));
    fail_workspace_tracking = false;
    size_t base_count = tracking_failure ? 1 : 2;
    bool covered = !tracking_failure;
    SCOPE_REQUIRE(image && scope_phase() && scope_current(scope, base_count, covered));
    YDDiskLineageSnapshot *native = yd_disk_lineage_snapshot(lineage);
    YDDiskLineageInfo info;
    SCOPE_REQUIRE(yd_disk_lineage_snapshot_info(native, &info) && info.complete &&
        info.source_count == 2 && info.entry_count == 4);
    yd_disk_lineage_snapshot_close(native);
    YDRaftJournalScopeSnapshot *saved = yd_raft_journal_scope_snapshot(scope);
    SCOPE_REQUIRE(saved && yd_raft_journal_scope_validate(saved) == covered);
    YDRaftJournalPublication *p = yd_raft_journal_prepare(image, source, error, sizeof(error));
    SCOPE_REQUIRE(p && scope_phase() && scope_current(scope, base_count + 2, covered));
    SCOPE_REQUIRE(!yd_raft_journal_scope_validate(saved));
    SCOPE_REQUIRE(yd_raft_journal_cancel(p, error, sizeof(error)) && scope_phase());
    yd_raft_journal_publication_close(p);
    SCOPE_REQUIRE(scope_current(scope, base_count, covered));
    p = yd_raft_journal_prepare(image, source, error, sizeof(error));
    SCOPE_REQUIRE(p && scope_phase() && scope_current(scope, base_count + 2, covered));
    bool selected = false;
    SCOPE_REQUIRE(yd_raft_journal_publish(p, r, &selected, error, sizeof(error)) && selected && scope_phase());
    SCOPE_REQUIRE(scope_current(scope, base_count + 1, covered));
    SCOPE_REQUIRE(yd_raft_journal_retire(p, error, sizeof(error)) && scope_phase());
    yd_raft_journal_publication_close(p);
    SCOPE_REQUIRE(scope_current(scope, base_count, covered));
    SCOPE_REQUIRE(command_is(r, 2, "# exact YAML\r\nkey: value # keep\r\n"));
    scope_probe = NULL;
    lineage_probe = NULL;
    SCOPE_REQUIRE(lineage_checks >= 4 && !lineage_bad);
    yd_raft_journal_scope_snapshot_close(saved);
    yd_raft_journal_scope_close(scope); /* Drop caller ownership before the core/capture. */
    yd_raft_close(r); yd_raft_journal_capture_close(capture);
    SCOPE_REQUIRE(scope_current(scope, base_count, covered)); /* Escaped image owns its scope. */
    saved = yd_raft_journal_scope_snapshot(scope); /* Retain observation through final close. */
    SCOPE_REQUIRE(saved);
    yd_raft_journal_image_close(image);
    native = yd_disk_lineage_snapshot(lineage);
    SCOPE_REQUIRE(yd_disk_lineage_snapshot_info(native, &info) && info.complete &&
        !info.source_count && !info.entry_count);
    yd_disk_lineage_snapshot_close(native);
    yd_disk_lineage_release(lineage);
    SCOPE_REQUIRE(scope_current(scope, 0, false)); /* Preserved fence/shell are unexplained. */
    struct stat fence;
    SCOPE_REQUIRE(!fstatat(target, ".yamora-initializing", &fence, AT_SYMLINK_NOFOLLOW));
    yd_raft_journal_scope_snapshot_close(saved);
    close(source); close(target);
    return 0;
}
static int scoped_fifo(const char *root) {
    char source_path[4096], target_path[4096];
    int source = candidate(root, "source", source_path);
    int target = candidate(root, "copy", target_path);
    SCOPE_REQUIRE(source >= 0 && target >= 0);
    YDRaftJournalScope *scope = yd_raft_journal_scope_new(); SCOPE_REQUIRE(scope);
    YDRaft *r = yd_raft_open_scoped(source_path, cluster, 1, 3, 32768, scope, error, sizeof(error));
    SCOPE_REQUIRE(r && elect(r) && propose(r, "preserved YAML\n") && acknowledge(r));
    YDRaftJournalCapture *capture = yd_raft_journal_capture(r, 32768, error, sizeof(error));
    SCOPE_REQUIRE(capture);
    YDRaftJournalImage *image = yd_raft_journal_copy(capture, target, 32768,
        NULL, NULL, error, sizeof(error)); SCOPE_REQUIRE(image);
    swap_scope_root = source;
    YDRaftJournalPublication *p = yd_raft_journal_prepare(image, source, error, sizeof(error));
    SCOPE_REQUIRE(scope_source_swapped && p && !yd_raft_journal_prepared_current(p, r));
    SCOPE_REQUIRE(command_is(r, 2, "preserved YAML\n"));
    struct stat fifo, original, held;
    SCOPE_REQUIRE(!fstatat(source, YD_DISK_FILE, &fifo, AT_SYMLINK_NOFOLLOW) && S_ISFIFO(fifo.st_mode));
    SCOPE_REQUIRE(!fstatat(source, "preserved-source", &original, AT_SYMLINK_NOFOLLOW) &&
        !fstat(r->disk->fd, &held) && original.st_dev == held.st_dev && original.st_ino == held.st_ino);
    YDRaftJournalScopeSnapshot *snapshot = yd_raft_journal_scope_snapshot(scope);
    YDRaftJournalScopeInfo observed;
    SCOPE_REQUIRE(yd_raft_journal_scope_snapshot_info(snapshot, &observed) && !observed.complete);
    yd_raft_journal_scope_snapshot_close(snapshot);
    yd_raft_journal_publication_close(p); yd_raft_journal_image_close(image);
    yd_raft_journal_capture_close(capture); yd_raft_close(r); yd_raft_journal_scope_close(scope);
    close(source); close(target);
    return 0;
}
static bool lineage_bytes(const YDDiskLineageSnapshot *snapshot, uint64_t source,
    const YDDiskView *view, const unsigned char *expected, size_t expected_size) {
    uint64_t offset = 0;
    unsigned char bytes[144];
    size_t size = 0;
    return yd_disk_lineage_snapshot_get(snapshot, source, view, "\0YRM", 4,
        &offset, error, sizeof(error)) == 1 &&
        yd_disk_lineage_snapshot_record_into(snapshot, source, view, offset,
            bytes, sizeof(bytes), &size, error, sizeof(error)) &&
        size == expected_size && !memcmp(bytes, expected, size);
}
static int scoped_lineage(const char *root) {
    char source_path[4096], target_path[4096];
    int source = candidate(root, "source", source_path);
    int target = candidate(root, "copy", target_path);
    SCOPE_REQUIRE(source >= 0 && target >= 0);
    YDRaftJournalScope *scope = yd_raft_journal_scope_new();
    YDDiskLineage *lineage = yd_disk_lineage_new();
    SCOPE_REQUIRE(scope && lineage);
    YDRaft *r = yd_raft_open_observed(source_path, cluster, 1, 3, 32768,
        scope, lineage, error, sizeof(error));
    SCOPE_REQUIRE(r && elect(r) && propose(r, "# untouched\r\nkey: value # exact\r\n") && acknowledge(r));
    YDRaftJournalCapture *capture = yd_raft_journal_capture(r, 32768, error, sizeof(error));
    YDRaftJournalImage *image = capture ? yd_raft_journal_copy(capture, target, 32768,
        NULL, NULL, error, sizeof(error)) : NULL;
    SCOPE_REQUIRE(image);
    YDDisk *pin = yd_disk_pin(yd_raft_journal_image_disk(image), 32768, error, sizeof(error));
    YDDisk *nested = pin ? yd_disk_pin(pin, 32768, error, sizeof(error)) : NULL;
    SCOPE_REQUIRE(nested);
    YDDiskView old = yd_disk_view(nested);
    unsigned char original[144], saved[2][144];
    size_t original_size = yd_raft_encode_meta(&r->meta, original), saved_size[2] = {0};
    yd_disk_close(pin);
    YDDisk *root_clone = NULL;
    YDDiskRecoveryInfo physical = {0};
    for (unsigned cycle = 0; cycle < 3; cycle++) {
        SCOPE_REQUIRE(propose(r, "after-escaped-pin") && acknowledge(r));
        YDRaftJournalCapture *latest = yd_raft_journal_capture(r, 32768, error, sizeof(error));
        SCOPE_REQUIRE(latest && yd_raft_journal_catch_up(image, latest, NULL, NULL, error, sizeof(error)));
        yd_raft_journal_capture_close(latest);
        if (!cycle) {
            YDDiskRecoveryRoots *roots = NULL;
            SCOPE_REQUIRE(yd_disk_recovery_roots_pin(image->writer, 32768, &roots,
                error, sizeof(error)) == YD_DISK_OBSERVE_OK &&
                yd_disk_recovery_roots_info(roots, &physical));
            YDDisk *reader = yd_disk_recovery_roots_reader(roots);
            root_clone = yd_disk_pin(reader, 32768, error, sizeof(error));
            SCOPE_REQUIRE(root_clone);
            for (unsigned slot = 0; slot < 2; slot++) {
                uint64_t offset = 0;
                SCOPE_REQUIRE(physical.slots[slot].valid &&
                    yd_disk_get(reader, &physical.slots[slot].view, "\0YRM", 4,
                        &offset, error, sizeof(error)) == 1 &&
                    yd_disk_record_into(reader, &physical.slots[slot].view, offset,
                        saved[slot], sizeof(saved[slot]), &saved_size[slot], error, sizeof(error)));
            }
            yd_disk_recovery_roots_close(roots);
        }
    }
    YDRaftJournalPublication *publication = yd_raft_journal_prepare(image, source, error, sizeof(error));
    bool selected = false;
    SCOPE_REQUIRE(publication && yd_raft_journal_publish(publication, r, &selected,
        error, sizeof(error)) && selected && yd_raft_journal_retire(publication, error, sizeof(error)));
    SCOPE_REQUIRE(command_is(r, 2, "# untouched\r\nkey: value # exact\r\n"));
    yd_raft_journal_publication_close(publication);
    yd_raft_journal_capture_close(capture);
    yd_raft_journal_image_close(image);
    yd_raft_close(r);
    yd_raft_journal_scope_close(scope);
    YDDiskLineageSnapshot *snapshot = yd_disk_lineage_snapshot(lineage);
    YDDiskLineageInfo info;
    SCOPE_REQUIRE(yd_disk_lineage_snapshot_info(snapshot, &info) && info.complete &&
        info.source_count == 1 && info.entry_count == 2 &&
        info.sources[0].physical_known && info.sources[0].physical_final &&
        !info.sources[0].writer_alive);
    uint64_t id = info.sources[0].id;
    SCOPE_REQUIRE(lineage_bytes(snapshot, id, &old, original, original_size));
    for (unsigned slot = 0; slot < 2; slot++)
        SCOPE_REQUIRE(lineage_bytes(snapshot, id, &physical.slots[slot].view,
            saved[slot], saved_size[slot]));
    bool both = false;
    for (size_t i = 0; i < info.entry_count; i++) both |= info.entries[i].slot_count == 2;
    SCOPE_REQUIRE(both);
    yd_disk_close(nested); yd_disk_close(root_clone);
    YDDiskLineageSnapshot *empty = yd_disk_lineage_snapshot(lineage);
    SCOPE_REQUIRE(yd_disk_lineage_snapshot_info(empty, &info) && info.complete &&
        !info.source_count && !info.entry_count);
    yd_disk_lineage_snapshot_close(empty);
    yd_disk_lineage_release(lineage);
    int probe = openat(source, YD_DISK_FILE, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    SCOPE_REQUIRE(probe >= 0 && flock(probe, LOCK_EX | LOCK_NB) &&
        (errno == EAGAIN || errno == EWOULDBLOCK));
    SCOPE_REQUIRE(lineage_bytes(snapshot, id, &old, original, original_size));
    yd_disk_lineage_snapshot_close(snapshot);
    SCOPE_REQUIRE(!flock(probe, LOCK_EX | LOCK_NB));
    close(probe); close(source); close(target);
    return 0;
}
int main(int argc, char **argv) {
    if (argc != 3)
        return 2;
    if (!strcmp(argv[2], "scope"))
        return scoped_producers(argv[1], false);
    if (!strcmp(argv[2], "scope-tracking-failure"))
        return scoped_producers(argv[1], true);
    if (!strcmp(argv[2], "scope-fifo"))
        return scoped_fifo(argv[1]);
    if (!strcmp(argv[2], "scope-lineage"))
        return scoped_lineage(argv[1]);
    if (!strcmp(argv[2], "prepare"))
        return prepared(argv[1], false);
    if (!strcmp(argv[2], "prepare-writing"))
        return prepared(argv[1], true);
    if (!strcmp(argv[2], "prepare-roots"))
        return prepare_roots(argv[1]);
    if (!strcmp(argv[2], "prepare-sync"))
        return prepare_sync(argv[1]);
    if (!strcmp(argv[2], "prepare-tamper"))
        return prepare_tamper(argv[1]);
    if (!strcmp(argv[2], "publish"))
        return publish(argv[1]);
    if (!strcmp(argv[2], "publish-stale"))
        return publish_stale(argv[1]);
    if (!strcmp(argv[2], "publish-fail"))
        return publish_fail(argv[1]);
    if (!strcmp(argv[2], "publish-kill"))
        return publish_kill(argv[1]);
    if (!strcmp(argv[2], "retire"))
        return retire(argv[1], false);
    if (!strcmp(argv[2], "retire-writing"))
        return retire(argv[1], true);
    if (!strcmp(argv[2], "retire-uncertain"))
        return retire_uncertain(argv[1]);
    if (!strcmp(argv[2], "retire-tamper"))
        return retire_tamper(argv[1]);
    if (!strcmp(argv[2], "retire-fail"))
        return retire_fail(argv[1]);
    if (!strcmp(argv[2], "retire-kill"))
        return cleanup_kill(argv[1], false);
    if (!strcmp(argv[2], "cancel-kill"))
        return cleanup_kill(argv[1], true);
    if (!strcmp(argv[2], "cancel"))
        return cancel_preparation(argv[1]);
    if (!strcmp(argv[2], "cancel-attempted"))
        return cancel_attempted(argv[1]);
    if (!strcmp(argv[2], "cancel-fail"))
        return cancel_fail(argv[1]);
    return 2;
}
