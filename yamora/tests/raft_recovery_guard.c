#define _GNU_SOURCE
#include "../src/consensus/raft_internal.h"
#include "../src/disk_internal.h"
#include "../src/consensus/retention_birth.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHECK(condition, marker) do { if (!(condition)) { \
    fprintf(stderr, "GUARD_ASSERT:%s\n", marker); return 2; } } while (0)
static const unsigned char cluster[16] = {1, 2, 3, 4};
static unsigned writes, syncs;
static YDRaftJournalScope *initializing_scope;
static int initializing_directory = -1;
static bool writes_active = true, writes_locked = true;
static unsigned guarded_writes;
static bool cut_free(int directory) {
    int fd = openat(directory, YD_RETENTION_FILE, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    struct flock lock = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_len = 1};
    int result = fcntl(fd, F_OFD_SETLK, &lock);
    close(fd);
    return result == 0;
}
static YDRaftJournalScopeInfo scoped_info(YDRaftJournalScope *scope) {
    YDRaftJournalScopeInfo out = {0};
    YDRaftJournalScopeSnapshot *snapshot = yd_raft_journal_scope_snapshot(scope);
    (void)yd_raft_journal_scope_snapshot_info(snapshot, &out);
    yd_raft_journal_scope_snapshot_close(snapshot);
    return out;
}
static unsigned descriptors(void) {
    DIR *directory = opendir("/proc/self/fd");
    if (!directory) abort();
    unsigned count = 0;
    while (readdir(directory)) count++;
    closedir(directory);
    return count;
}
ssize_t __real_pwrite(int, const void *, size_t, off_t);
int __real_fsync(int);
ssize_t __wrap_pwrite(int fd, const void *bytes, size_t size, off_t offset) {
    writes++;
    if (initializing_scope) {
        YDRaftJournalScopeInfo info = scoped_info(initializing_scope);
        writes_active &= info.active > 0 && !info.complete && !info.reasons;
        if (initializing_directory >= 0) {
            writes_locked &= !cut_free(initializing_directory);
            guarded_writes++;
        }
    }
    return __real_pwrite(fd, bytes, size, offset);
}
int __wrap_fsync(int fd) { syncs++; return __real_fsync(fd); }

static YDRaftJournalScope *expired_scope;
static YDRetentionGate *expired_gate;
static YDRaftJournalConstructor expired_token;
static bool probe_expired, expired_attached;
static unsigned expired_calls;
YDDiskView __real_yd_disk_view(YDDisk *disk);
YDDiskView __wrap_yd_disk_view(YDDisk *disk) {
    if (probe_expired) {
        probe_expired = false;
        expired_calls++;
        expired_attached = yd_raft_journal_scope_retention_constructing(expired_scope,
            expired_token, expired_gate);
    }
    return __real_yd_disk_view(disk);
}
typedef struct {
    unsigned calls;
    bool allow, empty, unlocked, bound, transition, marker, diagnostic;
    YDDiskLineage *lineage;
    YDRaftJournalScope *scope;
} Guard;
static bool admit(void *context, YDDisk *disk, int directory, char *error, size_t length) {
    Guard *guard = context;
    guard->calls++;
    YDDiskView view = yd_disk_view(disk);
    uint64_t value = 0;
    guard->empty = yd_disk_get(disk, &view, "\0YRM", 4, &value, error, length) == 0;
    bool writer = pthread_mutex_trylock(&disk->writer) == 0;
    bool root = pthread_mutex_trylock(&disk->root_lock) == 0;
    guard->unlocked = writer && root;
    if (root) pthread_mutex_unlock(&disk->root_lock);
    if (writer) pthread_mutex_unlock(&disk->writer);
    if (guard->lineage) {
        YDDiskLineageSnapshot *snapshot = yd_disk_lineage_snapshot(guard->lineage);
        YDDiskLineageInfo info;
        guard->bound = snapshot && yd_disk_lineage_snapshot_info(snapshot, &info) &&
            info.complete && info.source_count == 1 && info.entry_count == 1;
        yd_disk_lineage_snapshot_close(snapshot);
    }
    if (guard->scope) {
        YDRaftJournalScopeSnapshot *snapshot = yd_raft_journal_scope_snapshot(guard->scope);
        YDRaftJournalScopeInfo info;
        guard->transition = snapshot && yd_raft_journal_scope_snapshot_info(snapshot, &info) &&
            info.active == 1 && !info.complete;
        yd_raft_journal_scope_snapshot_close(snapshot);
    }
    if (guard->marker) {
        int fd = openat(directory, ".guard-proof", O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
        if (fd < 0) return false;
        bool valid = write(fd, "ok", 2) == 2 && fsync(fd) == 0 && fsync(directory) == 0;
        close(fd);
        if (!valid) return false;
    }
    if (guard->diagnostic && error && length)
        snprintf(error, length, "test guard refused");
    return guard->allow;
}
static YDRaft *open_guarded(const char *root, Guard *guard, char *error, size_t length) {
    return yd_raft_open_guarded(root, cluster, 1, 3, 32768, guard->scope,
        guard->lineage, admit, guard, error, length);
}
static bool drained(Guard *guard) {
    YDDiskLineageSnapshot *native = yd_disk_lineage_snapshot(guard->lineage);
    YDDiskLineageInfo info;
    bool valid = native && yd_disk_lineage_snapshot_info(native, &info) &&
        info.complete && !info.entry_count && !info.source_count;
    yd_disk_lineage_snapshot_close(native);
    YDRaftJournalScopeSnapshot *scope = yd_raft_journal_scope_snapshot(guard->scope);
    YDRaftJournalScopeInfo scoped;
    valid = valid && scope && yd_raft_journal_scope_snapshot_info(scope, &scoped) &&
        scoped.complete && !scoped.active;
    yd_raft_journal_scope_snapshot_close(scope);
    yd_disk_lineage_release(guard->lineage);
    yd_raft_journal_scope_close(guard->scope);
    return valid;
}
static int fresh(const char *root, bool allow) {
    Guard guard = {.allow = allow, .marker = !allow,
        .lineage = yd_disk_lineage_new(), .scope = yd_raft_journal_scope_new()};
    CHECK(guard.lineage && guard.scope, "SETUP_SCOPES");
    char error[256] = {0};
    YDRaft *raft = open_guarded(root, &guard, error, sizeof(error));
    bool admitted = (raft != NULL) == allow;
    if (raft) {
        YDDiskView view = yd_disk_view(raft->disk);
        uint64_t offset;
        CHECK(yd_disk_get(raft->disk, &view, "\0YRM", 4, &offset, error, sizeof(error)) == 1,
            "SUCCESS_RECOVERS");
    } else {
        CHECK(!strcmp(error, "raft recovery admission refused"), "DEFAULT_DIAGNOSTIC");
        int directory = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        CHECK(directory >= 0, "SETUP_ROOT");
        char proof[2];
        int fd = openat(directory, ".guard-proof", O_RDONLY | O_CLOEXEC);
        CHECK(fd >= 0 && read(fd, proof, 2) == 2 && !memcmp(proof, "ok", 2), "PRESERVE_ARTIFACT");
        close(fd);
        YDDisk *disk = yd_disk_open_at(directory, true, 32768, error, sizeof(error));
        CHECK(disk && !disk->created, "REFUSAL_RELEASES_WRITER");
        YDDiskView view = yd_disk_view(disk);
        uint64_t offset;
        CHECK(yd_disk_get(disk, &view, "\0YRM", 4, &offset, error, sizeof(error)) == 0,
            "REFUSAL_LEAVES_METADATA_ABSENT");
        yd_disk_close(disk);
        close(directory);
    }
    yd_raft_close(raft);
    CHECK(drained(&guard), "SCOPES_DRAINED");
    raft = yd_raft_open(root, cluster, 1, 3, 32768, error, sizeof(error));
    CHECK(raft, "LEGACY_REOPEN");
    yd_raft_close(raft);
    /* Deliberate guard mutants must fail only after releasing all owners, so
     * leak reports or process exit cannot substitute for behavior evidence. */
    CHECK(guard.calls == 1, "CALL_ONCE");
    CHECK(guard.empty, "BEFORE_RECOVERY");
    CHECK(guard.bound, "LINEAGE_BOUND_BEFORE_GUARD");
    CHECK(guard.transition && guard.unlocked, "OWNED_UNLOCKED_TRANSITION");
    CHECK(admitted, "REFUSAL_PREVENTS_RECOVERY");
    return 0;
}
static int existing(const char *root) {
    char error[256];
    YDRaft *raft = yd_raft_open(root, cluster, 1, 3, 32768, error, sizeof(error));
    CHECK(raft, "SETUP_RAFT");
    YDRaftVote request;
    CHECK(yd_raft_campaign(raft, &request), "SETUP_DURABLE_TERM");
    yd_raft_close(raft);
    int directory = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int fd = openat(directory, YD_DISK_FILE, O_RDONLY | O_CLOEXEC);
    struct stat before, after;
    CHECK(fd >= 0 && !fstat(fd, &before) && before.st_size > 0 && before.st_size < 1048576,
        "SETUP_BYTES");
    size_t size = (size_t)before.st_size;
    unsigned char *bytes = malloc(size), *copy = malloc(size);
    CHECK(bytes && copy && pread(fd, bytes, size, 0) == (ssize_t)size, "SETUP_READ");
    Guard guard = {.diagnostic = true};
    unsigned old_writes = writes, old_syncs = syncs;
    raft = open_guarded(root, &guard, error, sizeof(error));
    CHECK(guard.calls == 1 && !guard.empty && guard.unlocked, "EXISTING_GUARD");
    CHECK(!raft && !strcmp(error, "test guard refused"), "PRESERVE_DIAGNOSTIC");
    CHECK(writes == old_writes && syncs == old_syncs, "EXISTING_NO_WRITES");
    CHECK(!fstat(fd, &after) && after.st_size == before.st_size &&
        pread(fd, copy, size, 0) == (ssize_t)size && !memcmp(bytes, copy, size),
        "EXISTING_EXACT_BYTES");
    free(bytes); free(copy); close(fd); close(directory);
    raft = yd_raft_open(root, cluster, 1, 3, 32768, error, sizeof(error));
    CHECK(raft && yd_raft_status(raft).term == request.term, "EXISTING_RECOVERS");
    yd_raft_close(raft);
    return 0;
}
static int invalid(const char *root) {
    Guard guard = {.allow = true};
    char error[256];
    unsigned char zero[16] = {0};
    YDRaft *raft = yd_raft_open_guarded(root, zero, 1, 3, 32768, NULL, NULL,
        admit, &guard, error, sizeof(error));
    CHECK(!raft && !guard.calls, "INVALID_NO_CALLBACK");
    int directory = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    struct stat metadata;
    CHECK(directory >= 0 && fstatat(directory, YD_DISK_FILE, &metadata, 0) && errno == ENOENT,
        "INVALID_NO_NATIVE");
    close(directory);
    return 0;
}
static int corrupt(const char *root) {
    char error[256];
    YDDisk *disk = yd_disk_open(root, true, 32768, error, sizeof(error));
    CHECK(disk, "SETUP_NATIVE");
    YDDiskTxn *txn = yd_disk_begin(disk, error, sizeof(error));
    CHECK(txn && yd_disk_put(txn, "\0YRM", 4, 1, error, sizeof(error)) &&
        yd_disk_commit(txn, error, sizeof(error)), "SETUP_CORRUPT_METADATA");
    yd_disk_close(disk);
    Guard guard = {.diagnostic = true};
    unsigned old_writes = writes, old_syncs = syncs;
    YDRaft *raft = open_guarded(root, &guard, error, sizeof(error));
    CHECK(!raft && guard.calls == 1 && !strcmp(error, "test guard refused"),
        "GUARD_BEFORE_CORRUPT_METADATA");
    guard.allow = true;
    raft = open_guarded(root, &guard, error, sizeof(error));
    CHECK(!raft && guard.calls == 2 && !strcmp(error, "invalid or mismatched raft journal"),
        "ADMITTED_RECOVERY_STILL_VALIDATES");
    CHECK(writes == old_writes && syncs == old_syncs, "CORRUPT_NO_WRITES");
    return 0;
}
static int diagnostics(const char *root) {
    Guard guard = {.diagnostic = true};
    char bytes[4] = {'a', 'b', 'c', 'd'};
    YDRaft *raft = open_guarded(root, &guard, bytes + 1, 1);
    CHECK(!raft && guard.calls == 1 && bytes[0] == 'a' && !bytes[1] &&
        bytes[2] == 'c' && bytes[3] == 'd', "BOUNDED_DIAGNOSTIC");
    raft = open_guarded(root, &guard, NULL, 0);
    CHECK(!raft && guard.calls == 2, "NULL_DIAGNOSTIC");
    guard.allow = true;
    char error[256];
    raft = open_guarded(root, &guard, error, sizeof(error));
    CHECK(raft && guard.calls == 3 && !error[0], "SUCCESS_CLEARS_DIAGNOSTIC");
    yd_raft_close(raft);
    return 0;
}
typedef struct {
    YDRaftJournalScope *scope;
    YDRetentionGate *gate;
} Attachment;
static bool attach_ordinary(void *context, YDDisk *disk, int directory,
    char *error, size_t length) {
    Attachment *a = context;
    a->gate = yd_retention_gate_open(directory, cluster, 1, 3, disk->created, error, length);
    if (!a->gate) return false;
    yd_raft_journal_scope_retention(a->scope, a->gate);
    return true;
}
static int attachment_baseline(const char *root) {
    Attachment a = {.scope = yd_raft_journal_scope_new()};
    CHECK(a.scope, "SETUP_SCOPE");
    char error[256];
    YDRaft *raft = yd_raft_open_guarded(root, cluster, 1, 3, 32768, a.scope, NULL,
        attach_ordinary, &a, error, sizeof(error));
    bool opened = raft != NULL;
    yd_raft_close(raft);
    YDRaftJournalScopeSnapshot *snapshot = yd_raft_journal_scope_snapshot(a.scope);
    YDRaftJournalScopeInfo info;
    bool complete = snapshot && yd_raft_journal_scope_snapshot_info(snapshot, &info) &&
        info.complete;
    bool valid = yd_retention_gate_validate(a.gate);
    yd_raft_journal_scope_snapshot_close(snapshot);
    yd_raft_journal_scope_close(a.scope);
    yd_retention_gate_close(a.gate);
    CHECK(opened, "ORDINARY_PRODUCER_ACCEPTANCE");
    CHECK(!valid && !complete, "ORDINARY_ACTIVE_ATTACHMENT_REJECTED");
    return 0;
}
typedef struct {
    Attachment attachment;
    YDRaftJournalConstructor saved;
    YDRaftRetentionBirth *birth;
    YDRaftJournalBinding *control, *receipt;
    bool allow, attached, active, lease, native_created, gate_created, born, unlocked;
    unsigned calls;
} Constructor;
static bool attach_constructor(void *context, YDDisk *disk, int directory,
    YDRaftJournalScope *scope, YDRaftJournalConstructor token, char *error, size_t length) {
    Constructor *c = context;
    c->calls++;
    c->saved = token;
    c->attachment.scope = scope;
    c->native_created = disk->created;
    c->attachment.gate = yd_retention_gate_open(directory, cluster, 1, 3, disk->created,
        error, length);
    if (!c->attachment.gate) return false;
    c->gate_created = yd_retention_gate_created(c->attachment.gate);
    YDRaftJournalScopeInfo before = scoped_info(scope);
    c->active = before.active == 1 && !before.complete && !before.reasons;
    bool writer = pthread_mutex_trylock(&disk->writer) == 0;
    bool root = pthread_mutex_trylock(&disk->root_lock) == 0;
    c->unlocked = writer && root;
    if (root) pthread_mutex_unlock(&disk->root_lock);
    if (writer) pthread_mutex_unlock(&disk->writer);
    errno = EDOM;
    c->attached = yd_raft_journal_scope_retention_constructing(scope, token, c->attachment.gate);
    if (errno != EDOM || !c->attached) return false;
    c->lease = !cut_free(directory);
    YDRaftRetentionBirthResult result = yd_raft_retention_birth_publish(disk,
        c->attachment.gate, &c->birth, error, length);
    YDRaftRetentionBirthInfo birth;
    c->born = result == YD_RAFT_RETENTION_BIRTH_PUBLISHED &&
        yd_raft_retention_birth_info(c->birth, &birth) && birth.published_here &&
        yd_raft_retention_birth_validate(c->birth);
    c->control = yd_raft_journal_scope_file(scope, directory, YD_RETENTION_FILE,
        yd_retention_gate_descriptor(c->attachment.gate), YD_RAFT_JOURNAL_BINDING_CONTROL);
    if (c->birth) c->receipt = yd_raft_journal_scope_file(scope, directory,
        YD_RAFT_RETENTION_BIRTH_FILE, yd_raft_retention_birth_descriptor(c->birth),
        YD_RAFT_JOURNAL_BINDING_BIRTH);
    initializing_scope = scope;
    initializing_directory = directory;
    if (!c->allow && error && length) snprintf(error, length, "constructor refuses");
    return c->allow;
}
static int constructor(const char *root, const char *mode) {
    unsigned count = descriptors();
    bool refuse = !strcmp(mode, "constructor-refuse");
    bool existing = !strcmp(mode, "constructor-existing");
    bool corrupt = !strcmp(mode, "constructor-corrupt");
    char error[256];
    if (existing) {
        YDRaft *prior = yd_raft_open(root, cluster, 1, 3, 32768, error, sizeof(error));
        CHECK(prior, "SETUP_EXISTING"); yd_raft_close(prior);
        int directory = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        YDRetentionGate *prior_gate = yd_retention_gate_open(directory, cluster, 1, 3,
            true, error, sizeof(error)); CHECK(prior_gate, "SETUP_EXISTING_GATE");
        yd_retention_gate_close(prior_gate); close(directory);
    }
    if (corrupt) {
        YDDisk *disk = yd_disk_open(root, true, 32768, error, sizeof(error));
        CHECK(disk, "SETUP_CORRUPT_NATIVE");
        YDDiskTxn *txn = yd_disk_begin(disk, error, sizeof(error));
        CHECK(txn && yd_disk_put(txn, "\0YRM", 4, 1, error, sizeof(error)) &&
            yd_disk_commit(txn, error, sizeof(error)), "SETUP_CORRUPT_RECORD");
        yd_disk_close(disk);
        int directory = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        YDRetentionGate *prior_gate = yd_retention_gate_open(directory, cluster, 1, 3,
            true, error, sizeof(error)); CHECK(prior_gate, "SETUP_CORRUPT_GATE");
        yd_retention_gate_close(prior_gate); close(directory);
    }
    Constructor c = {.allow = !refuse, .attachment.scope = yd_raft_journal_scope_new()};
    YDDiskLineage *lineage = yd_disk_lineage_new();
    CHECK(c.attachment.scope && lineage, "SETUP_CONSTRUCTOR_SCOPES");
    initializing_scope = c.attachment.scope;
    YDRaft *raft = yd_raft_open_constructing(root, cluster, 1, 3, 32768, c.attachment.scope,
        lineage, attach_constructor, &c, error, sizeof(error));
    initializing_scope = NULL;
    bool opened = raft != NULL;
    bool diagnostic = refuse ? !strcmp(error, "constructor refuses") :
        corrupt ? !strcmp(error, "invalid or mismatched raft journal") : !error[0];
    bool initialized = false;
    if (raft) {
        YDDiskView view = yd_disk_view(raft->disk);
        uint64_t offset;
        initialized = yd_disk_get(raft->disk, &view, "\0YRM", 4, &offset, error, sizeof(error)) == 1;
    }
    YDRaftJournalScopeInfo out = scoped_info(c.attachment.scope);
    bool complete = out.complete && !out.active && !out.reasons;
    bool valid = yd_retention_gate_validate(c.attachment.gate);
    int directory = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    CHECK(directory >= 0, "SETUP_PROBE");
    bool released = cut_free(directory);
    /* Exact native/birth provenance is unchanged by scope completeness or
     * metadata registration. Reopened native/control files cannot publish. */
    bool provenance = existing || corrupt ? !c.native_created && !c.gate_created && !c.born && !c.birth :
        c.native_created && c.gate_created && c.born && c.control && c.receipt;
    yd_raft_close(raft);
    yd_raft_journal_binding_close(c.control);
    yd_raft_journal_binding_close(c.receipt);
    yd_raft_retention_birth_close(c.birth);
    yd_disk_lineage_release(lineage);
    yd_raft_journal_scope_close(c.attachment.scope);
    yd_retention_gate_close(c.attachment.gate);
    close(directory);
    CHECK(descriptors() == count, "CONSTRUCTOR_NO_DANGLING_OWNERS");
    CHECK(c.calls == 1 && opened == (!refuse && !corrupt), "CONSTRUCTOR_REFUSAL_AND_RECOVERY");
    CHECK(diagnostic, "CONSTRUCTOR_DIAGNOSTIC");
    CHECK(valid && complete, "FRESH_GUARDED_ATTACHMENT_VALID_AND_COMPLETE");
    CHECK(c.active && c.unlocked, "CONSTRUCTOR_ACTIVE_UNLOCKED");
    CHECK(c.lease, "CONSTRUCTOR_FIRST_LEASE");
    CHECK(released, "CONSTRUCTOR_END_RELEASES_BEFORE_CLOSE");
    CHECK(provenance, "BIRTH_PROVENANCE_NOT_BROADENED");
    if (!refuse && !corrupt) CHECK(initialized, "CONSTRUCTOR_INITIALIZES_NATIVE");
    if (!existing && !refuse && !corrupt) CHECK(guarded_writes && writes_active && writes_locked,
        "INITIALIZATION_NO_GAP_AND_CUT_BUSY");
    return 0;
}
static bool save_unused_token(void *context, YDDisk *disk, int directory,
    YDRaftJournalScope *scope, YDRaftJournalConstructor token, char *error, size_t length) {
    (void)context;
    expired_scope = scope;
    expired_token = token;
    expired_gate = yd_retention_gate_open(directory, cluster, 1, 3, disk->created, error, length);
    probe_expired = expired_gate != NULL;
    return probe_expired;
}
static int expired_before_recovery(const char *root) {
    unsigned count = descriptors();
    char error[256];
    YDRaftJournalScope *scope = yd_raft_journal_scope_new(); CHECK(scope, "SETUP_EXPIRED_SCOPE");
    YDRaft *raft = yd_raft_open_constructing(root, cluster, 1, 3, 32768, scope, NULL,
        save_unused_token, NULL, error, sizeof(error));
    bool opened = raft != NULL;
    bool diagnosed = !error[0];
    yd_raft_close(raft);
    yd_raft_journal_scope_close(scope);
    yd_retention_gate_close(expired_gate);
    CHECK(descriptors() == count, "EXPIRED_TOKEN_NO_DANGLING_OWNERS");
    CHECK(opened && diagnosed, "EXPIRED_ATTEMPT_PRESERVES_ORDINARY_RECOVERY");
    CHECK(expired_calls == 1 && !expired_attached, "TOKEN_INVALID_BEFORE_RECOVERY");
    return 0;
}
int main(int argc, char **argv) {
    if (argc != 3) return 3;
    if (!strcmp(argv[2], "expired-before-recovery")) return expired_before_recovery(argv[1]);
    if (!strncmp(argv[2], "constructor", 11)) return constructor(argv[1], argv[2]);
    if (!strcmp(argv[2], "attachment-baseline")) return attachment_baseline(argv[1]);
    if (!strcmp(argv[2], "fresh")) return fresh(argv[1], true);
    if (!strcmp(argv[2], "refuse")) return fresh(argv[1], false);
    if (!strcmp(argv[2], "existing")) return existing(argv[1]);
    if (!strcmp(argv[2], "invalid")) return invalid(argv[1]);
    if (!strcmp(argv[2], "corrupt")) return corrupt(argv[1]);
    if (!strcmp(argv[2], "diagnostics")) return diagnostics(argv[1]);
    return 3;
}
