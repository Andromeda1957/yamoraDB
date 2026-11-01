#define _GNU_SOURCE
#include "../src/consensus/application_workspace.h"
#include "../src/consensus/application_internal.h"
#include "../src/disk_internal.h"
#include "../src/binary.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <unistd.h>

static char error[512];
#define REQUIRE(x) do { if (!(x)) { \
    fprintf(stderr, "line %u: %s (%s)\n", __LINE__, #x, error); abort(); } } while (0)
static const unsigned char cluster[16] = {1, 2, 3, 4};
static const char sentinel[] = "owner replacement must survive";
static unsigned sync_count, rename_count, unlink_count, fault_step, swap_step;
static char operation[16], swap_phase[16];
static bool armed, attacked, creating;
static int parent_fd = -1, workspace_fd = -1, stage_fd = -1, replacement_fd = -1, saved_fd = -1;
static char workspace_name[80], custody_name[80];
static unsigned birth_kind;
static bool birth_swapped;
static unsigned swap_parent;
static int birth_original = -1, birth_replacement = -1;
static char birth_name[80];

int __real_fsync(int);
int __real_mkdirat(int, const char *, mode_t);
int __real_renameat2(int, const char *, int, const char *, unsigned);
int __real_unlinkat(int, const char *, int);
int __real_flock(int, int);
int __wrap_flock(int fd, int flags) {
    if (armed && flags == LOCK_UN && !strcmp(operation, "unlock")) {
        errno = EIO;
        return -1;
    }
    return __real_flock(fd, flags);
}
int __wrap_mkdirat(int directory, const char *name, mode_t mode) {
    int result = __real_mkdirat(directory, name, mode);
    if (!result && !strncmp(name, ".discarding-workspace-", 22)) {
        REQUIRE(strlen(name) < sizeof(custody_name));
        memmove(custody_name, name, strlen(name) + 1);
    }
    const char *prefix = birth_kind == 1 ? ".yamora-workspace-" : ".discarding-workspace-";
    if (!result && birth_kind && !birth_swapped && !strncmp(name, prefix, strlen(prefix))) {
        /* The directory has not yet been opened by production code. Replace
         * it with another same-user private EMPTY directory, not a symlink. */
        birth_swapped = true;
        REQUIRE(!__real_renameat2(directory, name, parent_fd, "birth-original", RENAME_NOREPLACE));
        birth_original = openat(parent_fd, "birth-original", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        REQUIRE(birth_original >= 0);
        REQUIRE(!__real_mkdirat(directory, name, 0700));
        birth_replacement = openat(directory, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        REQUIRE(birth_replacement >= 0 && strlen(name) < sizeof(birth_name));
        strcpy(birth_name, name);
    }
    return result;
}

static bool exists(int fd, const char *name) {
    struct stat s;
    return !fstatat(fd, name, &s, AT_SYMLINK_NOFOLLOW);
}
static void write_file(int fd, const char *name, const char *body) {
    int file = openat(fd, name, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW | O_CLOEXEC, 0600);
    REQUIRE(file >= 0);
    REQUIRE(write(file, body, strlen(body)) == (ssize_t)strlen(body));
    REQUIRE(!close(file));
}
/* Called from one deterministic syscall boundary, outside production code.
 * Hold both moved original and replacement to prove neither gets unlinked. */
static void replace(int directory, const char *name, bool is_directory) {
    REQUIRE(!attacked);
    attacked = true;
    REQUIRE(!__real_renameat2(directory, name, parent_fd, "saved", RENAME_NOREPLACE));
    saved_fd = openat(parent_fd, "saved", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    REQUIRE(saved_fd >= 0);
    if (is_directory) {
        REQUIRE(!mkdirat(directory, name, 0700));
        int fd = openat(directory, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        REQUIRE(fd >= 0);
        write_file(fd, "owner-data", sentinel);
        replacement_fd = openat(fd, "owner-data", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        REQUIRE(!close(fd));
    } else {
        write_file(directory, name, sentinel);
        replacement_fd = openat(directory, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    }
    REQUIRE(replacement_fd >= 0);
}
static void sync_swap(void) {
    if (creating) {
        int fd = openat(parent_fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        DIR *scan = fdopendir(fd);
        REQUIRE(scan);
        struct dirent *entry;
        char name[80] = {0};
        while ((entry = readdir(scan))) {
            if (!strncmp(entry->d_name, ".yamora-workspace-", 18)) {
                REQUIRE(strlen(entry->d_name) < sizeof(name));
                strcpy(name, entry->d_name);
            }
        }
        closedir(scan);
        REQUIRE(name[0]);
        replace(parent_fd, name, true);
        return;
    }
    if (swap_parent) {
        const char *name = swap_parent == 1 ? workspace_name : custody_name;
        REQUIRE(name[0]);
        replace(parent_fd, name, true);
        return;
    }
    const char *files[] = {YD_DISK_FILE, YD_BINARY_INITIALIZING};
    for (unsigned i = 0; i < 2; i++) {
        if (exists(workspace_fd, files[i])) { replace(workspace_fd, files[i], false); return; }
    }
    if (stage_fd >= 0) {
        const char *staged[] = {"native", "fence"};
        for (unsigned i = 0; i < 2; i++) {
            if (exists(stage_fd, staged[i])) { replace(stage_fd, staged[i], false); return; }
        }
    }
    if (custody_name[0] && exists(parent_fd, custody_name)) {
        replace(parent_fd, custody_name, true);
        return;
    }
    REQUIRE(false);
}
int __wrap_fsync(int fd) {
    if (!armed) return __real_fsync(fd);
    ++sync_count;
    if (!strcmp(operation, "sync") && sync_count == fault_step) { errno = EIO; return -1; }
    int result = __real_fsync(fd);
    if (!strcmp(operation, "sync") && sync_count == swap_step && !attacked) sync_swap();
    return result;
}
int __wrap_renameat2(int from, const char *name, int to, const char *target, unsigned flags) {
    if (!armed) return __real_renameat2(from, name, to, target, flags);
    ++rename_count;
    if (stage_fd < 0 && (!strcmp(target, "native") || !strcmp(target, "fence"))) {
        stage_fd = fcntl(to, F_DUPFD_CLOEXEC, 0);
        REQUIRE(stage_fd >= 0);
        /* Resolve the custody name by identity, for adversarial last-sync
         * reintroduction; test-only bounded parent has just a few entries. */
        int fd = openat(parent_fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        DIR *scan = fdopendir(fd);
        REQUIRE(scan);
        struct stat held, named;
        REQUIRE(!fstat(to, &held));
        struct dirent *entry;
        while ((entry = readdir(scan))) {
            if (!fstatat(parent_fd, entry->d_name, &named, AT_SYMLINK_NOFOLLOW) &&
                named.st_dev == held.st_dev && named.st_ino == held.st_ino) {
                REQUIRE(strlen(entry->d_name) < sizeof(custody_name));
                strcpy(custody_name, entry->d_name);
            }
        }
        closedir(scan);
    }
    if (!strcmp(operation, "rename") && rename_count == fault_step) { errno = EIO; return -1; }
    bool swap = !strcmp(operation, "rename") && rename_count == swap_step && !attacked;
    if (swap && !strcmp(swap_phase, "before")) replace(from, name, false);
    int result = __real_renameat2(from, name, to, target, flags);
    if (!result && swap && !strcmp(swap_phase, "after")) replace(to, target, false);
    return result;
}
int __wrap_unlinkat(int fd, const char *name, int flags) {
    if (armed) {
        ++unlink_count;
        if (!strcmp(operation, "unlink") && unlink_count == fault_step) { errno = EIO; return -1; }
    }
    return __real_unlinkat(fd, name, flags);
}
static void verify_attack(void) {
    struct stat s;
    REQUIRE(attacked && replacement_fd >= 0 && !fstat(replacement_fd, &s) && s.st_nlink == 1);
    char bytes[sizeof(sentinel)];
    REQUIRE(pread(replacement_fd, bytes, sizeof(sentinel)-1, 0) == (ssize_t)sizeof(sentinel)-1);
    REQUIRE(!memcmp(bytes, sentinel, sizeof(sentinel)-1));
    REQUIRE(!close(replacement_fd));
    replacement_fd = -1;
    if (saved_fd >= 0) {
        REQUIRE(!fstat(saved_fd, &s) && s.st_nlink > 0);
        REQUIRE(!close(saved_fd));
        saved_fd = -1;
    }
}
static void reset(void) {
    armed = false;
    sync_count = rename_count = unlink_count = fault_step = swap_step = 0;
    operation[0] = swap_phase[0] = custody_name[0] = 0;
    attacked = false;
    if (stage_fd >= 0) close(stage_fd);
    stage_fd = -1;
}
typedef struct {
    YDRaftApplication *application;
    YDRaftApplicationCapture *capture;
    YDRaftApplicationImage *image;
    YDRaftApplicationWorkspace *workspace;
} Fixture;
static YDRaftApplication *seed(const char *root) {
    char path[4096];
    REQUIRE(snprintf(path, sizeof(path), "%s/source", root) < (int)sizeof(path));
    REQUIRE(!mkdir(path, 0700));
    YDRaftApplication *a = yd_raft_application_open(path, cluster, 32768, error, sizeof(error));
    REQUIRE(a);
    YDRaftEntry noop = {.index = 1, .term = 1, .kind = YD_RAFT_NOOP};
    REQUIRE(yd_raft_application_apply(a, &noop, error, sizeof(error)));
    static const unsigned char body[] = "name: 'exact source' # preserve\nvalue: 42\n";
    YDRaftWrite write = {.method = "PUT", .target = "/v1/collections/config/documents/node",
        .body = body, .size = sizeof(body)-1, .id = {1}};
    YDRaftProposal proposal = {0};
    REQUIRE(yd_raft_application_prepare(a, &write, &proposal, error, sizeof(error)) == 1);
    YDRaftEntry entry = {.index = 2, .term = 1, .kind = YD_RAFT_COMMAND,
        .command = proposal.command, .size = proposal.size};
    REQUIRE(yd_raft_application_apply(a, &entry, error, sizeof(error)));
    yd_raft_proposal_free(&proposal);
    return a;
}
static Fixture setup(const char *root, bool copy, bool bind) {
    Fixture f = {.application = seed(root)};
    char path[4096];
    REQUIRE(snprintf(path, sizeof(path), "%s/archive", root) < (int)sizeof(path));
    REQUIRE(!mkdir(path, 0700));
    parent_fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    REQUIRE(parent_fd >= 0);
    f.workspace = yd_raft_application_workspace_create(parent_fd, error, sizeof(error));
    REQUIRE(f.workspace);
    workspace_fd = yd_raft_application_workspace_directory(f.workspace);
    strcpy(workspace_name, yd_raft_application_workspace_name(f.workspace));
    f.capture = yd_raft_application_capture(f.application, 32768, error, sizeof(error));
    REQUIRE(f.capture);
    if (copy) {
        f.image = yd_raft_application_copy(f.capture, workspace_fd, 32768, NULL, NULL,
            error, sizeof(error));
        REQUIRE(f.image);
    }
    if (bind) REQUIRE(yd_raft_application_workspace_bind(f.workspace, f.image, error, sizeof(error)));
    return f;
}
static void close_image(Fixture *f) {
    yd_raft_application_image_close(f->image);
    f->image = NULL;
}
static void finish(Fixture *f) {
    reset();
    close_image(f);
    yd_raft_application_workspace_close(f->workspace);
    yd_raft_application_capture_close(f->capture);
    yd_raft_application_close(f->application);
    close(parent_fd);
    parent_fd = workspace_fd = -1;
}
static int discard(Fixture *f) {
    return yd_raft_application_workspace_discard(f->workspace,
        YD_RAFT_WORKSPACE_CONFIRMED_SUCCESS, error, sizeof(error));
}
static void document(YDDisk *disk) {
    YDDiskView view = yd_disk_view(disk);
    YDDiskDocument d = {0};
    REQUIRE(yd_disk_document_get(disk, &view, "config", "node", &d, error, sizeof(error)) == 1);
    REQUIRE(d.length == strlen("name: 'exact source' # preserve\nvalue: 42\n"));
    REQUIRE(!memcmp(d.body, "name: 'exact source' # preserve\nvalue: 42\n", d.length));
    yd_disk_document_free(&d);
}
static void reclaimed_native(int directory) {
    struct stat s;
    REQUIRE(!fstat(directory, &s) && s.st_nlink > 0);
    REQUIRE(!exists(directory, YD_DISK_FILE) && exists(directory, YD_BINARY_INITIALIZING));
    int fd = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    DIR *scan = fdopendir(fd);
    REQUIRE(scan);
    struct dirent *entry;
    while ((entry = readdir(scan))) REQUIRE(!strcmp(entry->d_name, ".") ||
        !strcmp(entry->d_name, "..") || !strcmp(entry->d_name, YD_BINARY_INITIALIZING));
    closedir(scan);
}
static void basic(const char *root) {
    Fixture f = setup(root, true, true);
    REQUIRE(!yd_raft_application_image_disk(f.image)->created);
    int fence = openat(workspace_fd, YD_BINARY_INITIALIZING, O_RDONLY | O_CLOEXEC);
    REQUIRE(fence >= 0);
    struct stat a, b;
    REQUIRE(!fstat(parent_fd, &a));
    REQUIRE(!fstat(yd_raft_application_workspace_parent(f.workspace), &b));
    REQUIRE(a.st_ino == b.st_ino && a.st_dev == b.st_dev);
    REQUIRE(workspace_name[0] && !fstat(workspace_fd, &a) && !(a.st_mode & 077));
    REQUIRE(!yd_raft_application_workspace_bind(f.workspace, f.image, error, sizeof(error)));
    document(yd_raft_application_image_disk(f.image));
    REQUIRE(discard(&f) == 0);
    close_image(&f);
    write_file(parent_fd, "owner-backup", sentinel);
    REQUIRE(discard(&f) == 1 && discard(&f) == 1);
    REQUIRE(exists(parent_fd, workspace_name) && exists(parent_fd, "owner-backup"));
    REQUIRE(!fstat(workspace_fd, &b) && a.st_ino == b.st_ino && a.st_dev == b.st_dev);
    reclaimed_native(workspace_fd);
    struct stat held_fence, named_fence;
    REQUIRE(!fstat(fence, &held_fence) && held_fence.st_nlink == 1);
    REQUIRE(!fstatat(workspace_fd, YD_BINARY_INITIALIZING, &named_fence, AT_SYMLINK_NOFOLLOW));
    REQUIRE(held_fence.st_ino == named_fence.st_ino && held_fence.st_dev == named_fence.st_dev);
    REQUIRE(!close(fence));
    f.workspace = (yd_raft_application_workspace_close(f.workspace), NULL);
    f.workspace = yd_raft_application_workspace_create(parent_fd, error, sizeof(error));
    REQUIRE(f.workspace);
    REQUIRE(strcmp(workspace_name, yd_raft_application_workspace_name(f.workspace)));
    workspace_fd = yd_raft_application_workspace_directory(f.workspace);
    f.image = yd_raft_application_copy(f.capture, workspace_fd, 32768, NULL, NULL, error, sizeof(error));
    REQUIRE(f.image && yd_raft_application_workspace_bind(f.workspace, f.image, error, sizeof(error)));
    close_image(&f);
    REQUIRE(yd_raft_application_workspace_discard(f.workspace,
        YD_RAFT_WORKSPACE_SAFE_PRESELECTION_SKIP, error, sizeof(error)) == 1);
    finish(&f);
}
typedef struct {
    YDDiskCheckpoint *checkpoint;
    pthread_barrier_t barrier;
    bool valid;
} CheckpointReader;
static void barrier(pthread_barrier_t *b) {
    int result = pthread_barrier_wait(b);
    REQUIRE(!result || result == PTHREAD_BARRIER_SERIAL_THREAD);
}
static void *read_checkpoint(void *context) {
    CheckpointReader *reader = context;
    unsigned char bytes[64];
    char failure[128];
    reader->valid = yd_disk_checkpoint_read(reader->checkpoint, 0, bytes, sizeof(bytes),
        failure, sizeof(failure));
    barrier(&reader->barrier);
    barrier(&reader->barrier);
    yd_disk_checkpoint_close(reader->checkpoint);
    return NULL;
}
static void pins(const char *root, const char *kind) {
    Fixture f = setup(root, true, true);
    YDDisk *reader = NULL;
    YDDiskCheckpoint *checkpoint = NULL;
    YDRaftApplicationCapture *capture = NULL;
    if (!strcmp(kind, "reader")) {
        reader = yd_disk_pin(yd_raft_application_image_disk(f.image), 32768, error, sizeof(error));
        REQUIRE(reader);
    } else if (!strcmp(kind, "checkpoint") || !strcmp(kind, "thread")) {
        YDRaftCheckpoint position;
        checkpoint = yd_raft_application_image_checkpoint(f.image, &position, error, sizeof(error));
        REQUIRE(checkpoint);
    } else {
        /* A later capture of the private image also owns a duplicate flock. */
        close_image(&f);
        YDRaftApplication *a = yd_raft_application_open_existing_at(workspace_fd,
            cluster, 32768, error, sizeof(error));
        REQUIRE(a);
        capture = yd_raft_application_capture(a, 32768, error, sizeof(error));
        yd_raft_application_close(a);
        REQUIRE(capture);
    }
    close_image(&f);
    if (!strcmp(kind, "thread")) {
        CheckpointReader reader_state = {.checkpoint = checkpoint};
        pthread_t thread;
        REQUIRE(!pthread_barrier_init(&reader_state.barrier, NULL, 2));
        REQUIRE(!pthread_create(&thread, NULL, read_checkpoint, &reader_state));
        barrier(&reader_state.barrier);
        REQUIRE(discard(&f) == 0 && exists(parent_fd, workspace_name));
        barrier(&reader_state.barrier);
        REQUIRE(!pthread_join(thread, NULL) && reader_state.valid);
        REQUIRE(!pthread_barrier_destroy(&reader_state.barrier));
        checkpoint = NULL;
        REQUIRE(discard(&f) == 1);
        finish(&f);
        return;
    }
    REQUIRE(discard(&f) == 0 && exists(parent_fd, workspace_name));
    if (reader) document(reader);
    if (checkpoint) {
        unsigned char bytes[64];
        REQUIRE(yd_disk_checkpoint_read(checkpoint, 0, bytes, sizeof(bytes), error, sizeof(error)));
    }
    yd_disk_close(reader);
    yd_disk_checkpoint_close(checkpoint);
    yd_raft_application_capture_close(capture);
    REQUIRE(discard(&f) == 1);
    finish(&f);
}
static void close_only(const char *root) {
    Fixture f = setup(root, true, true);
    close_image(&f);
    int directory = fcntl(workspace_fd, F_DUPFD_CLOEXEC, 0);
    REQUIRE(directory >= 0);
    yd_raft_application_workspace_close(f.workspace); f.workspace = NULL;
    REQUIRE(exists(parent_fd, workspace_name) && exists(directory, YD_DISK_FILE));
    REQUIRE(exists(directory, YD_BINARY_INITIALIZING));
    close(directory);
    f.workspace = yd_raft_application_workspace_create(parent_fd, error, sizeof(error));
    REQUIRE(f.workspace);
    strcpy(workspace_name, yd_raft_application_workspace_name(f.workspace));
    yd_raft_application_workspace_close(f.workspace); f.workspace = NULL;
    REQUIRE(exists(parent_fd, workspace_name));
    f.workspace = yd_raft_application_workspace_create(parent_fd, error, sizeof(error));
    REQUIRE(f.workspace);
    workspace_fd = yd_raft_application_workspace_directory(f.workspace);
    strcpy(workspace_name, yd_raft_application_workspace_name(f.workspace));
    f.image = yd_raft_application_copy(f.capture, workspace_fd, 32768, NULL, NULL, error, sizeof(error));
    REQUIRE(f.image && yd_raft_application_workspace_bind(f.workspace, f.image, error, sizeof(error)));
    close_image(&f);
    strcpy(operation, "sync"); fault_step = 6; armed = true;
    REQUIRE(discard(&f) == -1);
    armed = false;
    REQUIRE(stage_fd >= 0 && exists(parent_fd, workspace_name));
    int custody = fcntl(stage_fd, F_DUPFD_CLOEXEC, 0);
    REQUIRE(custody >= 0);
    directory = fcntl(workspace_fd, F_DUPFD_CLOEXEC, 0);
    REQUIRE(directory >= 0);
    yd_raft_application_workspace_close(f.workspace); f.workspace = NULL;
    REQUIRE(exists(parent_fd, workspace_name) && exists(directory, YD_BINARY_INITIALIZING));
    REQUIRE(!exists(custody, "native") && !exists(directory, YD_DISK_FILE));
    close(directory);
    close(custody);
    finish(&f);
}
static bool cancel(void *context, YDRaftApplicationCopyPhase phase, uint64_t done, uint64_t total) {
    (void)done; (void)total;
    return phase != *(YDRaftApplicationCopyPhase *)context;
}
static void cancellation(const char *root) {
    Fixture f = setup(root, false, false);
    for (YDRaftApplicationCopyPhase phase = YD_RAFT_APPLICATION_SOURCE;
         phase <= YD_RAFT_APPLICATION_VERIFY; phase++) {
        f.image = yd_raft_application_copy(f.capture, workspace_fd, 32768, cancel, &phase,
            error, sizeof(error));
        REQUIRE(!f.image);
        REQUIRE(!yd_raft_application_workspace_bind(f.workspace, NULL, error, sizeof(error)));
        REQUIRE(discard(&f) == -1 && exists(parent_fd,
            yd_raft_application_workspace_name(f.workspace)));
        if (phase > YD_RAFT_APPLICATION_SOURCE) REQUIRE(exists(workspace_fd, YD_BINARY_INITIALIZING));
        yd_raft_application_workspace_close(f.workspace);
        f.workspace = yd_raft_application_workspace_create(parent_fd, error, sizeof(error));
        REQUIRE(f.workspace);
        workspace_fd = yd_raft_application_workspace_directory(f.workspace);
    }
    f.image = yd_raft_application_copy(f.capture, workspace_fd, 32768, NULL, NULL, error, sizeof(error));
    REQUIRE(f.image && yd_raft_application_workspace_bind(f.workspace, f.image, error, sizeof(error)));
    close_image(&f);
    REQUIRE(yd_raft_application_workspace_discard(f.workspace, YD_RAFT_WORKSPACE_PRESERVE,
        error, sizeof(error)) == -1);
    REQUIRE(yd_raft_application_workspace_discard(f.workspace,
        (YDRaftApplicationWorkspaceDisposition)99, error, sizeof(error)) == -1);
    REQUIRE(exists(workspace_fd, YD_DISK_FILE) && exists(workspace_fd, YD_BINARY_INITIALIZING));
    yd_raft_application_workspace_close(f.workspace);
    close_image(&f);
    f.workspace = yd_raft_application_workspace_create(parent_fd, error, sizeof(error));
    REQUIRE(f.workspace);
    workspace_fd = yd_raft_application_workspace_directory(f.workspace);
    f.image = yd_raft_application_copy(f.capture, workspace_fd, 32768, NULL, NULL, error, sizeof(error));
    REQUIRE(f.image);
    YDRaftEntry later = {.index = 3, .term = 1, .kind = YD_RAFT_NOOP};
    REQUIRE(yd_raft_application_apply(f.application, &later, error, sizeof(error)));
    YDRaftApplicationCapture *newer = yd_raft_application_capture(f.application, 32768,
        error, sizeof(error));
    REQUIRE(newer);
    YDRaftApplicationCopyPhase phase = YD_RAFT_APPLICATION_COPY;
    REQUIRE(!yd_raft_application_catch_up(f.image, newer, cancel, &phase, error, sizeof(error)));
    REQUIRE(!yd_raft_application_image_disk(f.image));
    REQUIRE(!yd_raft_application_workspace_bind(f.workspace, f.image, error, sizeof(error)));
    close_image(&f);
    REQUIRE(discard(&f) == -1 && exists(workspace_fd, YD_DISK_FILE));
    yd_raft_application_capture_close(newer);
    finish(&f);
}
static void binding(const char *root) {
    Fixture f = setup(root, true, false);
    YDRaftApplicationWorkspace *other = yd_raft_application_workspace_create(parent_fd, error, sizeof(error));
    REQUIRE(other && !yd_raft_application_workspace_bind(other, f.image, error, sizeof(error)));
    REQUIRE(yd_raft_application_workspace_discard(other, YD_RAFT_WORKSPACE_CONFIRMED_SUCCESS,
        error, sizeof(error)) == -1);
    yd_raft_application_workspace_close(other);
    write_file(workspace_fd, "unknown", sentinel);
    REQUIRE(!yd_raft_application_workspace_bind(f.workspace, f.image, error, sizeof(error)));
    REQUIRE(!unlinkat(workspace_fd, "unknown", 0));
    REQUIRE(!linkat(workspace_fd, YD_DISK_FILE, parent_fd, "linked-native", 0));
    REQUIRE(!yd_raft_application_workspace_bind(f.workspace, f.image, error, sizeof(error)));
    REQUIRE(!unlinkat(parent_fd, "linked-native", 0));
    REQUIRE(yd_raft_application_workspace_bind(f.workspace, f.image, error, sizeof(error)));
    close_image(&f);
    REQUIRE(discard(&f) == 1);
    finish(&f);
}
static void rejection(const char *root) {
    Fixture f = setup(root, true, true);
    close_image(&f);
    write_file(workspace_fd, "unknown", sentinel);
    REQUIRE(discard(&f) == -1 && exists(workspace_fd, YD_DISK_FILE));
    REQUIRE(!unlinkat(workspace_fd, "unknown", 0));
    const char *names[] = {YD_DISK_FILE, YD_BINARY_INITIALIZING};
    for (unsigned i = 0; i < 2; i++) {
        REQUIRE(!linkat(workspace_fd, names[i], parent_fd, "linked", 0));
        REQUIRE(discard(&f) == -1 && exists(workspace_fd, names[i]));
        REQUIRE(!unlinkat(parent_fd, "linked", 0));
        REQUIRE(!renameat(workspace_fd, names[i], parent_fd, "temporarily-missing"));
        REQUIRE(discard(&f) == -1 && exists(parent_fd, "temporarily-missing"));
        REQUIRE(!renameat(parent_fd, "temporarily-missing", workspace_fd, names[i]));
        REQUIRE(!renameat(workspace_fd, names[i], parent_fd, "saved-link"));
        REQUIRE(!symlinkat("../saved-link", workspace_fd, names[i]));
        REQUIRE(discard(&f) == -1 && exists(workspace_fd, names[i]));
        REQUIRE(!unlinkat(workspace_fd, names[i], 0));
        REQUIRE(!renameat(parent_fd, "saved-link", workspace_fd, names[i]));
    }
    REQUIRE(!fchmod(parent_fd, 0770));
    REQUIRE(discard(&f) == -1);
    REQUIRE(!fchmod(parent_fd, 0700));
    REQUIRE(!renameat(parent_fd, workspace_name, parent_fd, "saved-directory"));
    REQUIRE(!symlinkat("saved-directory", parent_fd, workspace_name));
    REQUIRE(discard(&f) == -1 && exists(workspace_fd, YD_DISK_FILE));
    REQUIRE(!unlinkat(parent_fd, workspace_name, 0));
    REQUIRE(!renameat(parent_fd, "saved-directory", parent_fd, workspace_name));
    REQUIRE(discard(&f) == 1);
    finish(&f);
}
static void fault(const char *root, const char *kind, unsigned step) {
    Fixture f = setup(root, true, true);
    close_image(&f);
    strcpy(operation, kind); fault_step = step; armed = true;
    REQUIRE(discard(&f) == -1);
    REQUIRE((!strcmp(kind, "sync") ? sync_count : !strcmp(kind, "rename") ? rename_count : unlink_count) >= step);
    armed = false;
    REQUIRE(yd_raft_application_workspace_discard(f.workspace, YD_RAFT_WORKSPACE_SAFE_PRESELECTION_SKIP,
        error, sizeof(error)) == -1);
    REQUIRE(discard(&f) == 1);
    REQUIRE(exists(parent_fd, workspace_name));
    reclaimed_native(workspace_fd);
    finish(&f);
}
static void swapping(const char *root, const char *phase, unsigned step) {
    Fixture f = setup(root, true, true);
    close_image(&f);
    strcpy(operation, !strcmp(phase, "sync") ? "sync" : "rename");
    strcpy(swap_phase, phase); swap_step = step; armed = true;
    REQUIRE(discard(&f) == -1);
    armed = false;
    verify_attack();
    /* A contaminated claim remains preserved; retries must never mistake an
     * old failed operation for new provenance. */
    REQUIRE(discard(&f) == -1);
    finish(&f);
}
static void creation(const char *root, unsigned step, bool swap) {
    parent_fd = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    REQUIRE(parent_fd >= 0);
    strcpy(operation, "sync");
    creating = true;
    if (swap) swap_step = step;
    else fault_step = step;
    armed = true;
    REQUIRE(!yd_raft_application_workspace_create(parent_fd, error, sizeof(error)));
    armed = false;
    creating = false;
    if (swap) verify_attack();
    int scanfd = openat(parent_fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    DIR *scan = fdopendir(scanfd);
    REQUIRE(scan);
    unsigned found = 0;
    struct dirent *entry;
    while ((entry = readdir(scan))) if (entry->d_name[0] != '.' || strlen(entry->d_name) > 2) found++;
    REQUIRE(found == (swap ? 2U : 1U));
    closedir(scan);
    close(parent_fd);
    parent_fd = -1;
}
static void birth(const char *root, unsigned kind) {
    birth_kind = kind;
    Fixture f = setup(root, true, true);
    close_image(&f);
    int result = discard(&f);
    REQUIRE(result == 1 || result == -1);
    struct stat original, replacement;
    REQUIRE(birth_swapped && !fstat(birth_original, &original) && original.st_nlink > 0);
    REQUIRE(!fstat(birth_replacement, &replacement) && replacement.st_nlink > 0);
    REQUIRE(exists(parent_fd, "birth-original") && exists(parent_fd, birth_name));
    REQUIRE(!close(birth_original) && !close(birth_replacement));
    birth_original = birth_replacement = -1;
    finish(&f);
}
static void foreign_fence(const char *root) {
    Fixture f = setup(root, true, false);
    REQUIRE(!renameat(workspace_fd, YD_BINARY_INITIALIZING, parent_fd, "created-fence"));
    write_file(workspace_fd, YD_BINARY_INITIALIZING, "");
    int fence = openat(workspace_fd, YD_BINARY_INITIALIZING, O_RDONLY | O_CLOEXEC);
    REQUIRE(fence >= 0 && !yd_raft_application_workspace_bind(f.workspace, f.image, error, sizeof(error)));
    close_image(&f);
    REQUIRE(discard(&f) == -1 && exists(workspace_fd, YD_DISK_FILE));
    struct stat original, named;
    REQUIRE(!fstat(fence, &original) && original.st_nlink == 1);
    REQUIRE(!fstatat(workspace_fd, YD_BINARY_INITIALIZING, &named, AT_SYMLINK_NOFOLLOW));
    REQUIRE(original.st_ino == named.st_ino && original.st_dev == named.st_dev);
    REQUIRE(exists(workspace_fd, YD_BINARY_INITIALIZING) && exists(parent_fd, "created-fence"));
    REQUIRE(!close(fence));
    finish(&f);
}
static void parent_swap(const char *root, unsigned kind) {
    Fixture f = setup(root, true, true);
    close_image(&f);
    strcpy(operation, "sync"); swap_step = 3; swap_parent = kind; armed = true;
    REQUIRE(discard(&f) == -1);
    armed = false;
    verify_attack();
    REQUIRE(exists(workspace_fd, YD_DISK_FILE) && exists(workspace_fd, YD_BINARY_INITIALIZING));
    REQUIRE(discard(&f) == -1);
    finish(&f);
}
static bool insert_foreign_native(void *context, YDRaftApplicationCopyPhase phase,
    uint64_t done, uint64_t total) {
    (void)total;
    bool *inserted = context;
    if (!*inserted && phase == YD_RAFT_APPLICATION_SOURCE && done == 1) {
        YDDisk *foreign = yd_disk_open_cluster_at(workspace_fd, true, 32768, error, sizeof(error));
        REQUIRE(foreign);
        yd_disk_close(foreign);
        *inserted = true;
    }
    return true;
}
static void foreign_native(const char *root) {
    Fixture f = setup(root, false, false);
    bool inserted = false;
    f.image = yd_raft_application_copy(f.capture, workspace_fd, 32768,
        insert_foreign_native, &inserted, error, sizeof(error));
    REQUIRE(inserted && !f.image);
    REQUIRE(discard(&f) == -1 && exists(workspace_fd, YD_DISK_FILE));
    YDDisk *foreign = yd_disk_open_cluster_at(workspace_fd, false, 32768, error, sizeof(error));
    REQUIRE(foreign && yd_disk_view(foreign).generation == 1);
    yd_disk_close(foreign);
    finish(&f);
}
static unsigned entries(int directory) {
    int fd = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    DIR *scan = fd >= 0 ? fdopendir(fd) : NULL;
    REQUIRE(scan);
    unsigned count = 0;
    struct dirent *entry;
    while ((entry = readdir(scan)))
        if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) count++;
    closedir(scan);
    return count;
}
static void recycle_basic(const char *root) {
    Fixture f = setup(root, true, true);
    struct stat workspace, custody = {0}, again;
    REQUIRE(!fstat(workspace_fd, &workspace));
    int directory = -1, owned_custody = -1;
    REQUIRE(yd_raft_application_workspace_account(f.workspace, parent_fd, &directory, &owned_custody));
    REQUIRE(directory == workspace_fd && owned_custody == -1);
    for (unsigned cycle = 0; cycle < 8; cycle++) {
        document(yd_raft_application_image_disk(f.image));
        close_image(&f);
        REQUIRE(discard(&f) == 1);
        REQUIRE(!yd_raft_application_workspace_account(f.workspace, parent_fd, &directory, &owned_custody));
        REQUIRE(directory == -1 && owned_custody == -1);
        REQUIRE(yd_raft_application_workspace_recycle(f.workspace, error, sizeof(error)) == 1);
        REQUIRE(yd_raft_application_workspace_recycle(f.workspace, error, sizeof(error)) == 1);
        REQUIRE(yd_raft_application_workspace_account(f.workspace, parent_fd, &directory, &owned_custody));
        REQUIRE(directory == workspace_fd && owned_custody >= 0 && entries(parent_fd) == 2);
        REQUIRE(!fstat(directory, &again) && workspace.st_ino == again.st_ino && workspace.st_dev == again.st_dev);
        REQUIRE(!fstat(owned_custody, &again));
        if (!cycle) custody = again;
        REQUIRE(custody.st_ino == again.st_ino && custody.st_dev == again.st_dev);
        REQUIRE(!entries(directory) && !entries(owned_custody));
        if (cycle == 7) break;
        YDRaftEntry noop = {.index = 3 + cycle, .term = 1, .kind = YD_RAFT_NOOP};
        REQUIRE(yd_raft_application_apply(f.application, &noop, error, sizeof(error)));
        yd_raft_application_capture_close(f.capture);
        f.capture = yd_raft_application_capture(f.application, 32768, error, sizeof(error));
        REQUIRE(f.capture);
        f.image = yd_raft_application_copy_limited(f.capture, workspace_fd, 32768, 1024*1024,
            NULL, NULL, NULL, error, sizeof(error));
        REQUIRE(f.image && yd_raft_application_workspace_bind(f.workspace, f.image, error, sizeof(error)));
        REQUIRE(yd_raft_application_workspace_account(f.workspace, parent_fd, &directory, &owned_custody));
    }
    finish(&f);
}
static void recycle_unconfirmed(const char *root) {
    Fixture f = setup(root, true, true);
    REQUIRE(yd_raft_application_workspace_recycle(f.workspace, error, sizeof(error)) == -1);
    REQUIRE(exists(workspace_fd, YD_DISK_FILE) && exists(workspace_fd, YD_BINARY_INITIALIZING));
    close_image(&f);
    REQUIRE(yd_raft_application_workspace_recycle(f.workspace, error, sizeof(error)) == -1);
    REQUIRE(exists(workspace_fd, YD_DISK_FILE) && exists(workspace_fd, YD_BINARY_INITIALIZING));
    REQUIRE(yd_raft_application_workspace_discard(f.workspace, YD_RAFT_WORKSPACE_PRESERVE,
        error, sizeof(error)) == -1);
    REQUIRE(yd_raft_application_workspace_recycle(f.workspace, error, sizeof(error)) == -1);
    REQUIRE(exists(workspace_fd, YD_DISK_FILE) && exists(workspace_fd, YD_BINARY_INITIALIZING));
    finish(&f);
}
static void recycle_fence(const char *root) {
    Fixture f = setup(root, true, true);
    close_image(&f);
    REQUIRE(discard(&f) == 1);
    REQUIRE(!renameat(workspace_fd, YD_BINARY_INITIALIZING, parent_fd, "original-fence"));
    write_file(workspace_fd, YD_BINARY_INITIALIZING, "");
    int replacement = openat(workspace_fd, YD_BINARY_INITIALIZING, O_RDONLY | O_CLOEXEC);
    REQUIRE(replacement >= 0);
    REQUIRE(yd_raft_application_workspace_recycle(f.workspace, error, sizeof(error)) == -1);
    struct stat s;
    REQUIRE(!fstat(replacement, &s) && s.st_nlink == 1);
    REQUIRE(exists(workspace_fd, YD_BINARY_INITIALIZING) && exists(parent_fd, "original-fence"));
    close(replacement);
    finish(&f);
}
static void recycle_fault(const char *root, const char *kind, unsigned step) {
    Fixture f = setup(root, true, true);
    close_image(&f);
    REQUIRE(discard(&f) == 1);
    reset();
    strcpy(operation, kind); fault_step = step; armed = true;
    REQUIRE(yd_raft_application_workspace_recycle(f.workspace, error, sizeof(error)) == -1);
    armed = false;
    REQUIRE(exists(parent_fd, workspace_name));
    REQUIRE(yd_raft_application_workspace_recycle(f.workspace, error, sizeof(error)) == 1);
    REQUIRE(!entries(workspace_fd) && entries(parent_fd) == 2);
    finish(&f);
}
static void recycle_swap(const char *root, unsigned parent, unsigned step) {
    Fixture f = setup(root, true, true);
    close_image(&f);
    REQUIRE(discard(&f) == 1);
    char custody[80];
    strcpy(custody, custody_name);
    reset();
    strcpy(custody_name, custody);
    swap_parent = parent;
    strcpy(operation, "sync"); swap_step = step; armed = true;
    REQUIRE(yd_raft_application_workspace_recycle(f.workspace, error, sizeof(error)) == -1);
    armed = false;
    verify_attack();
    REQUIRE(yd_raft_application_workspace_recycle(f.workspace, error, sizeof(error)) == -1);
    swap_parent = 0;
    finish(&f);
}
int main(int argc, char **argv) {
    REQUIRE(argc == 3);
    const char *mode = argv[2];
    char kind[16];
    unsigned step;
    if (!strcmp(mode, "basic")) basic(argv[1]);
    else if (!strcmp(mode, "recycle-basic")) recycle_basic(argv[1]);
    else if (!strcmp(mode, "recycle-unconfirmed")) recycle_unconfirmed(argv[1]);
    else if (!strcmp(mode, "recycle-fence")) recycle_fence(argv[1]);
    else if (sscanf(mode, "recycle-swap-%15[^-]-%u", kind, &step) == 2)
        recycle_swap(argv[1], !strcmp(kind, "workspace") ? 1 : 2, step);
    else if (sscanf(mode, "recycle-fault-%15[^-]-%u", kind, &step) == 2) recycle_fault(argv[1], kind, step);
    else if (!strncmp(mode, "pins-", 5)) pins(argv[1], mode + 5);
    else if (!strcmp(mode, "close")) close_only(argv[1]);
    else if (!strcmp(mode, "cancel")) cancellation(argv[1]);
    else if (!strcmp(mode, "binding")) binding(argv[1]);
    else if (!strcmp(mode, "rejection")) rejection(argv[1]);
    else if (!strcmp(mode, "birth-workspace")) birth(argv[1], 1);
    else if (!strcmp(mode, "birth-custody")) birth(argv[1], 2);
    else if (!strcmp(mode, "foreign-fence")) foreign_fence(argv[1]);
    else if (!strcmp(mode, "foreign-native")) foreign_native(argv[1]);
    else if (!strcmp(mode, "parent-workspace")) parent_swap(argv[1], 1);
    else if (!strcmp(mode, "parent-custody")) parent_swap(argv[1], 2);
    else if (sscanf(mode, "fault-%15[^-]-%u", kind, &step) == 2) fault(argv[1], kind, step);
    else if (sscanf(mode, "swap-%15[^-]-%u", kind, &step) == 2) swapping(argv[1], kind, step);
    else if (sscanf(mode, "creation-swap-%u", &step) == 1) creation(argv[1], step, true);
    else if (sscanf(mode, "creation-%u", &step) == 1) creation(argv[1], step, false);
    else REQUIRE(false);
    return 0;
}
