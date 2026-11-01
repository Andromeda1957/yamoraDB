#define _POSIX_C_SOURCE 200809L
#include "../src/consensus/backup.h"
#include "../src/consensus/raft_internal.h"
#include "../src/consensus/application_internal.h"
#include "../src/consensus/capture_internal.h"
#include "../src/consensus/recovery.h"
#include "../src/disk_documents.h"
#include "../src/disk_history.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#define REQUIRE(x) do { if (!(x)) { fprintf(stderr, "line %u: %s (%s)\n", __LINE__, #x, error); return 2; } } while (0)
static char error[512];
static const unsigned char cluster[16] = {1, 4, 9, 16};
static const unsigned char authored[] = "# exact source\r\nanswer: 42 # preserve\r\n";
static YDRaft *nodes[3];
static YDRaftApplication *apps[3];
static uint32_t capabilities;
static char retained_commit[YD_HISTORY_TOKEN];
static YDDiskReply policy_original;
static const unsigned char policy_source[] =
    "# exact policy\r\ntype: object\r\nproperties: {answer: {type: integer}}\r\nrequired: [answer]\r\n";
static char journals[3][4096], documents[3][4096];
static unsigned sync_fail;
static atomic_uint sync_count;
int __real_fsync(int);
int __wrap_fsync(int fd) {
    if (++sync_count == sync_fail) { errno = EIO; return -1; }
    return __real_fsync(fd);
}
static bool path(char out[4096], const char *root, const char *name) {
    int n = snprintf(out, 4096, "%s/%s", root, name);
    return n > 0 && n < 4096;
}
static bool directory_new(char out[4096], const char *root, const char *name) {
    return path(out, root, name) && !mkdir(out, 0700);
}
static bool apply(void) {
    for (unsigned n = 0; n < 3; n++) {
        while (yd_raft_application_position(apps[n]).index < yd_raft_status(nodes[n]).committed) {
            YDRaftEntry entry = {0};
            bool valid = yd_raft_entry(nodes[n], yd_raft_application_position(apps[n]).index + 1, &entry) &&
                yd_raft_application_apply(apps[n], &entry, error, sizeof(error));
            yd_raft_entry_free(&entry);
            if (!valid) return false;
        }
    }
    return true;
}
static bool replicate(void) {
    for (unsigned loop = 0; loop < 8; loop++) {
        for (unsigned n = 1; n < 3; n++) {
            YDRaftAppend request = {0}; YDRaftAppendReply reply;
            bool valid = yd_raft_append_request(nodes[0], n + 1, &request) &&
                yd_raft_append(nodes[n], &request, &reply) && yd_raft_append_reply(nodes[0], n + 1, &reply);
            yd_raft_append_free(&request);
            if (!valid) return false;
        }
    }
    return apply();
}
static YDRaftWrite request(unsigned id, const unsigned char *bytes, size_t size) {
    YDRaftWrite write = {.method = "PUT", .target = "/v1/collections/a/documents/x", .body = bytes, .size = size};
    write.id[0] = (unsigned char)id; write.id[1] = (unsigned char)(id >> 8);
    return write;
}
static bool put(unsigned id, const unsigned char *bytes, size_t size) {
    YDRaftWrite write = request(id, bytes, size);
    YDRaftProposal proposal = {0}; uint64_t index;
    bool valid = yd_raft_application_prepare(apps[0], &write, &proposal, error, sizeof(error)) == 1 &&
        yd_raft_propose(nodes[0], proposal.command, proposal.size, &index) && replicate();
    yd_raft_proposal_free(&proposal);
    return valid;
}
static bool policy(void) {
    YDRaftWrite write = {.id = {11}, .method = "PUT", .target = "/v1/schema-policies/a",
        .none = "*", .body = policy_source, .size = sizeof(policy_source) - 1};
    YDRaftProposal proposal = {0}; uint64_t index;
    bool valid = yd_raft_application_prepare(apps[0], &write, &proposal, error, sizeof(error)) == 1 &&
        yd_raft_propose(nodes[0], proposal.command, proposal.size, &index) && replicate();
    yd_raft_proposal_free(&proposal);
    valid = valid && yd_raft_application_receipt(apps[0], &write, &policy_original, error, sizeof(error)) == 1 &&
        policy_original.status == 201;
    const char *etag = valid ? strstr(policy_original.headers, "ETag: ") : NULL;
    const char *end = etag ? strstr(etag + 6, "\r\n") : NULL;
    char match[128] = {0};
    valid = valid && end && (size_t)(end - etag - 6) < sizeof(match);
    if (!valid) return false;
    memcpy(match, etag + 6, (size_t)(end - etag - 6));
    unsigned char changed[sizeof(policy_source) + 8];
    memcpy(changed, policy_source, sizeof(policy_source) - 1);
    memcpy(changed + sizeof(policy_source) - 1, "# later\n", 8);
    write.id[0] = 12; write.none = NULL; write.match = match;
    write.body = changed; write.size = sizeof(policy_source) - 1 + 8;
    valid = yd_raft_application_prepare(apps[0], &write, &proposal, error, sizeof(error)) == 1 &&
        yd_raft_propose(nodes[0], proposal.command, proposal.size, &index) && replicate();
    yd_raft_proposal_free(&proposal);
    return valid;
}
static bool seed(const char *root) {
    for (unsigned n = 0; n < 3; n++) {
        char name[32];
        snprintf(name, sizeof(name), "journal-%u", n + 1);
        if (!directory_new(journals[n], root, name)) return false;
        snprintf(name, sizeof(name), "documents-%u", n + 1);
        if (!directory_new(documents[n], root, name)) return false;
        nodes[n] = yd_raft_open(journals[n], cluster, n + 1, 3, 32768, error, sizeof(error));
        apps[n] = capabilities
            ? yd_raft_application_open_capabilities(documents[n], cluster, capabilities, 32768, error, sizeof(error))
            : yd_raft_application_open(documents[n], cluster, 32768, error, sizeof(error));
        if (!nodes[n] || !apps[n]) return false;
    }
    YDRaftVote vote; YDRaftVoteReply reply;
    if (!yd_raft_campaign(nodes[0], &vote) || !yd_raft_vote(nodes[1], &vote, &reply) ||
        !yd_raft_vote_reply(nodes[0], 2, vote.term, &reply) || !replicate()) return false;
    bool valid = put(1, authored, sizeof(authored) - 1) &&
        (!(capabilities & YD_DISK_CAP_SCHEMA) || policy());
    if (valid && (capabilities & YD_DISK_CAP_HISTORY)) {
        YDDisk *disk = yd_raft_application_disk(apps[0]);
        YDDiskView view = yd_disk_view(disk), selected;
        valid = yd_disk_history_resolve(disk, &view, "main", &selected, retained_commit,
            error, sizeof(error)) == 200;
    }
    return valid;
}
static void close_all(void) {
    for (unsigned n = 0; n < 3; n++) {
        yd_raft_application_close(apps[n]); apps[n] = NULL;
        yd_raft_close(nodes[n]); nodes[n] = NULL;
    }
}
static bool checkpoint(bool selected) {
    char archives[4096];
    if (!directory_new(archives, journals[0], YD_RAFT_ARCHIVE_DIRECTORY)) return false;
    int fd = open(archives, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    YDRaftSnapshot *image = yd_raft_snapshot_open(apps[0], 3, error, sizeof(error));
    YDRaftCheckpoint origin;
    YDDisk *pin = yd_raft_application_pin(apps[0], 32768, &origin, error, sizeof(error));
    char id[65];
    YDRaftSnapshotArchive *archive = image && pin ? yd_raft_capture_archive(image, pin, fd,
        cluster, 3, NULL, NULL, id, error, sizeof(error)) : NULL;
    unsigned char manifest[256]; size_t n = 0;
    YDRaftSnapshotBase base = {.index = origin.applied.index, .term = origin.applied.term};
    bool valid = archive && yd_raft_snapshot_archive_manifest(archive, manifest) &&
        EVP_Q_digest(NULL, "SHA256", NULL, manifest, sizeof(manifest), base.archive, &n) == 1 && n == 32;
    if (valid) {
        if (selected) { unsigned char zero[32] = {0}; valid = yd_raft_application_select(nodes[0], zero, &base); }
        else valid = yd_raft_checkpoint(nodes[0], &base);
    }
    yd_raft_snapshot_archive_close(archive); yd_raft_snapshot_close(image); yd_disk_close(pin);
    if (fd >= 0) close(fd);
    return valid;
}
static bool original_receipt(YDRaftApplication *app) {
    YDRaftWrite write = request(1, authored, sizeof(authored) - 1);
    YDDiskReply reply = {0};
    bool valid = yd_raft_application_receipt(app, &write, &reply, error, sizeof(error)) == 1 && reply.status == 201;
    yd_disk_reply_free(&reply);
    return valid;
}
static bool verify(const char *docs, const char *journal, uint64_t applied, uint64_t last, bool original) {
    int d = open(docs, O_RDONLY | O_DIRECTORY | O_CLOEXEC), j = open(journal, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    bool valid = yd_raft_backup_verify_pair(d, j, cluster, 1, 3, error, sizeof(error));
    YDRaft *raft = valid ? yd_raft_open(journal, cluster, 1, 3, 32768, error, sizeof(error)) : NULL;
    YDRaftApplied origin;
    YDRaftApplication *app = !raft ? NULL : capabilities
        ? yd_raft_recover_open_capabilities_origin(d, raft, capabilities, 32768, &origin,
            NULL, NULL, error, sizeof(error))
        : yd_raft_recover_open(d, raft, 32768, NULL, NULL, error, sizeof(error));
    valid = valid && raft && app && yd_raft_status(raft).committed == applied && yd_raft_status(raft).last == last &&
        yd_raft_application_position(app).index == applied && original_receipt(app) &&
        yd_disk_capabilities(yd_raft_application_disk(app)) == capabilities;
    if (valid && original) {
        YDDiskDocument document = {0}; YDDisk *disk = yd_raft_application_disk(app); YDDiskView view = yd_disk_view(disk);
        valid = yd_disk_document_get(disk, &view, "a", "x", &document, error, sizeof(error)) == 1 &&
            document.length == sizeof(authored) - 1 && !memcmp(document.body, authored, sizeof(authored) - 1);
        yd_disk_document_free(&document);
    }
    if (valid && (capabilities & YD_DISK_CAP_SCHEMA)) {
        YDRaftWrite write = {.id = {11}, .method = "PUT", .target = "/v1/schema-policies/a",
            .none = "*", .body = policy_source, .size = sizeof(policy_source) - 1};
        YDDiskReply reply = {0};
        valid = yd_raft_application_receipt(app, &write, &reply, error, sizeof(error)) == 1 &&
            reply.status == policy_original.status && reply.length == policy_original.length &&
            !memcmp(reply.body, policy_original.body, reply.length) &&
            !strcmp(reply.headers, policy_original.headers) && !strcmp(reply.revision, policy_original.revision);
        yd_disk_reply_free(&reply);
    }
    if (valid && (capabilities & YD_DISK_CAP_HISTORY)) {
        YDDisk *disk = yd_raft_application_disk(app); YDDiskView view = yd_disk_view(disk), old;
        char token[YD_HISTORY_TOKEN]; YDDiskDocument document = {0};
        valid = yd_disk_history_resolve(disk, &view, retained_commit, &old, token, error, sizeof(error)) == 200 &&
            !strcmp(token, retained_commit) &&
            yd_disk_document_get(disk, &old, "a", "x", &document, error, sizeof(error)) == 1 &&
            document.length == sizeof(authored) - 1 && !memcmp(document.body, authored, document.length);
        yd_disk_document_free(&document);
    }
    yd_raft_application_close(app); yd_raft_close(raft);
    if (d >= 0) close(d);
    if (j >= 0) close(j);
    return valid;
}
static bool cancel(void *context, uint64_t done, uint64_t total) {
    (void)context; (void)done; (void)total; return false;
}
static atomic_uint write_requested, write_completed;
static atomic_bool worker_done, worker_failed;
static void *writer(void *context) {
    (void)context;
    unsigned next = 2;
    while (!atomic_load(&worker_done)) {
        if (atomic_load(&write_requested) >= next) {
            if (!put(next, (const unsigned char *)"answer: 43\n", 11)) { atomic_store(&worker_failed, true); break; }
            atomic_store(&write_completed, next++);
        } else { struct timespec delay = {.tv_nsec = 1000000}; nanosleep(&delay, NULL); }
    }
    return NULL;
}
static bool concurrent(void *context, uint64_t done, uint64_t total) {
    (void)context; (void)done; (void)total;
    unsigned complete = atomic_load(&write_completed);
    if (complete >= 8) return !atomic_load(&worker_failed);
    unsigned next = complete ? complete + 1 : 2;
    atomic_store(&write_requested, next);
    for (unsigned i = 0; i < 10000 && atomic_load(&write_completed) < next && !atomic_load(&worker_failed); i++) {
        struct timespec delay = {.tv_nsec = 1000000}; nanosleep(&delay, NULL);
    }
    return atomic_load(&write_completed) >= next && !atomic_load(&worker_failed);
}
static bool corrupt_archive(const char *root, bool missing) {
    char archive_root[4096];
    if (!path(archive_root, root, "archives")) return false;
    DIR *scan = opendir(archive_root);
    if (!scan) return false;
    bool valid = false;
    struct dirent *entry;
    while ((entry = readdir(scan))) {
        if (strlen(entry->d_name) != 73 || strcmp(entry->d_name + 64, ".snapshot")) continue;
        if (missing) valid = !unlinkat(dirfd(scan), entry->d_name, 0);
        else {
            int fd = openat(dirfd(scan), entry->d_name, O_WRONLY | O_CLOEXEC);
            if (fd < 0 && !fchmodat(dirfd(scan), entry->d_name, 0600, 0))
                fd = openat(dirfd(scan), entry->d_name, O_WRONLY | O_CLOEXEC);
            valid = fd >= 0 && !ftruncate(fd, 300);
            if (fd >= 0) close(fd);
        }
        break;
    }
    closedir(scan); return valid;
}
static bool mixed_application(const char *root) {
    char other[4096], bundle[4096];
    if (!directory_new(other, root, "other-app") || !directory_new(bundle, root, "mixed-bundle")) return false;
    YDRaftApplication *app = yd_raft_application_open(other, cluster, 32768, error, sizeof(error));
    YDRaftEntry noop = {0};
    bool valid = app && yd_raft_entry(nodes[0], 1, &noop) && yd_raft_application_apply(app, &noop, error, sizeof(error));
    yd_raft_entry_free(&noop);
    YDRaftWrite write = request(1, (const unsigned char *)"answer: 99\n", 11);
    YDRaftProposal proposal = {0};
    valid = valid && yd_raft_application_prepare(app, &write, &proposal, error, sizeof(error)) == 1;
    YDRaftEntry entry = {.index = 2, .term = nodes[0]->meta.term, .kind = YD_RAFT_COMMAND,
        .command = proposal.command, .size = proposal.size};
    valid = valid && yd_raft_application_apply(app, &entry, error, sizeof(error));
    yd_raft_proposal_free(&proposal);
    YDRaftBackup *backup = valid ? yd_raft_backup_capture(nodes[0], app, nodes[0]->configuration_base, 32768, error, sizeof(error)) : NULL;
    valid = valid && backup && !yd_raft_backup_write(backup, bundle, NULL, NULL, error, sizeof(error));
    yd_raft_backup_close(backup); yd_raft_application_close(app);
    return valid;
}
int main(int argc, char **argv) {
    if (argc != 3) return 2;
    const char *root = argv[1], *scenario = argv[2];
    if (!strncmp(scenario, "capabilities-", 13)) {
        capabilities = (uint32_t)strtoul(scenario + 13, NULL, 10);
        REQUIRE(capabilities == 3 || capabilities == 5 || capabilities == 7);
        REQUIRE(!pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL));
    }
    REQUIRE(seed(root));
    if (!strcmp(scenario, "mixed-application")) { REQUIRE(mixed_application(root)); close_all(); return 0; }
    bool snapshots = !strcmp(scenario, "snapshot"), selected = !strcmp(scenario, "selected") || capabilities;
    if (snapshots || selected) REQUIRE(checkpoint(selected));
    if (selected) REQUIRE(put(2, (const unsigned char *)"answer: 43\n", 11));
    if (!strcmp(scenario, "pending")) { uint64_t index; REQUIRE(yd_raft_propose(nodes[0], "pending", 7, &index)); }
    uint64_t applied = yd_raft_status(nodes[0]).committed, last = yd_raft_status(nodes[0]).last;
    uint32_t configuration = !strcmp(scenario, "packed-membership") ? nodes[0]->configuration_base : 0;
    if (!strcmp(scenario, "wrong-membership")) configuration = nodes[0]->configuration_base ^ 1U;
    YDRaftBackup *backup = yd_raft_backup_capture(nodes[0], apps[0],
        configuration, 32768, error, sizeof(error));
    REQUIRE(backup);
    char bundle[4096], docs[4096], journal[4096], other_bundle[4096] = {0};
    REQUIRE(directory_new(bundle, root, "bundle"));
    if (!strcmp(scenario, "wrong-membership")) {
        bool rejected = !yd_raft_backup_write(backup, bundle, NULL, NULL, error, sizeof(error));
        yd_raft_backup_close(backup); close_all(); REQUIRE(rejected); return 0;
    }
    pthread_t thread;
    bool writes = !strcmp(scenario, "concurrent");
    if (writes) REQUIRE(!pthread_create(&thread, NULL, writer, NULL));
    if (!strcmp(scenario, "cancel")) {
        REQUIRE(!yd_raft_backup_write(backup, bundle, cancel, NULL, error, sizeof(error)));
        REQUIRE(directory_new(bundle, root, "retry-bundle"));
    }
    sync_count = 0;
    REQUIRE(yd_raft_backup_write(backup, bundle, writes ? concurrent : NULL, NULL, error, sizeof(error)));
    if (!strcmp(scenario, "sync-write")) {
        unsigned boundaries = sync_count;
        REQUIRE(boundaries >= 8);
        for (unsigned n = 1; n <= boundaries; n++) {
            char name[64], failed[4096]; snprintf(name, sizeof(name), "failed-backup-%u", n);
            REQUIRE(directory_new(failed, root, name));
            sync_count = 0; sync_fail = n;
            REQUIRE(!yd_raft_backup_write(backup, failed, NULL, NULL, error, sizeof(error)));
            sync_fail = 0;
        }
        printf("backup-sync-boundaries=%u\n", boundaries);
    }
    if (writes) { atomic_store(&worker_done, true); REQUIRE(!pthread_join(thread, NULL)); REQUIRE(atomic_load(&write_completed) >= 8); }
    if (!strcmp(scenario, "swapped-components") || !strcmp(scenario, "swapped-pair")) {
        REQUIRE(put(2, (const unsigned char *)"answer: 43\n", 11));
        YDRaftBackup *other = yd_raft_backup_capture(nodes[0], apps[0], nodes[0]->configuration_base, 32768, error, sizeof(error));
        REQUIRE(other); REQUIRE(directory_new(other_bundle, root, "other-bundle"));
        REQUIRE(yd_raft_backup_write(other, other_bundle, NULL, NULL, error, sizeof(error)));
        yd_raft_backup_close(other);
    }
    yd_raft_backup_close(backup); close_all();
    REQUIRE(directory_new(docs, root, "restored-documents"));
    REQUIRE(directory_new(journal, root, "restored-journal"));
    if (!strcmp(scenario, "swapped-components")) {
        char original[4096], different[4096]; unsigned char bytes[512];
        REQUIRE(path(original, bundle, "manifest")); REQUIRE(path(different, other_bundle, "manifest"));
        int source_fd = open(different, O_RDONLY | O_CLOEXEC), target_fd = open(original, O_WRONLY | O_CLOEXEC);
        REQUIRE(source_fd >= 0 && target_fd >= 0 && read(source_fd, bytes, 512) == 512 && write(target_fd, bytes, 512) == 512);
        close(source_fd); close(target_fd);
        REQUIRE(!yd_raft_backup_restore(bundle, docs, journal, cluster, 1, 3, 32768, NULL, NULL, error, sizeof(error)));
        return 0;
    }
    if (!strcmp(scenario, "restore-cancel")) {
        REQUIRE(!yd_raft_backup_restore(bundle, docs, journal, cluster, 1, 3, 32768, cancel, NULL, error, sizeof(error)));
        REQUIRE(directory_new(docs, root, "retry-documents")); REQUIRE(directory_new(journal, root, "retry-journal"));
    }
    if (!strcmp(scenario, "wrong-identity")) {
        unsigned char other[16] = {2};
        REQUIRE(!yd_raft_backup_restore(bundle, docs, journal, other, 1, 3, 32768, NULL, NULL, error, sizeof(error)));
        REQUIRE(!yd_raft_backup_restore(bundle, docs, journal, cluster, 2, 3, 32768, NULL, NULL, error, sizeof(error)));
        REQUIRE(!yd_raft_backup_restore(bundle, docs, journal, cluster, 1, 5, 32768, NULL, NULL, error, sizeof(error)));
        REQUIRE(!yd_raft_backup_restore(bundle, docs, docs, cluster, 1, 3, 32768, NULL, NULL, error, sizeof(error)));
    }
    if (!strcmp(scenario, "corrupt")) {
        char p[4096]; REQUIRE(path(p, bundle, "journal/.yamora-disk")); REQUIRE(!chmod(p, 0600));
        int fd = open(p, O_WRONLY | O_CLOEXEC); REQUIRE(fd >= 0); unsigned char bad = 0xa5;
        REQUIRE(pwrite(fd, &bad, 1, 8192) == 1); close(fd);
        REQUIRE(!yd_raft_backup_restore(bundle, docs, journal, cluster, 1, 3, 32768, NULL, NULL, error, sizeof(error)));
        return 0;
    }
    if (!strcmp(scenario, "missing-journal")) {
        char p[4096]; REQUIRE(path(p, bundle, "journal/.yamora-disk")); REQUIRE(!unlink(p));
        REQUIRE(!yd_raft_backup_restore(bundle, docs, journal, cluster, 1, 3, 32768, NULL, NULL, error, sizeof(error)));
        return 0;
    }
    if (!strcmp(scenario, "missing-archive") || !strcmp(scenario, "truncated-archive")) {
        REQUIRE(corrupt_archive(bundle, !strcmp(scenario, "missing-archive")));
        REQUIRE(!yd_raft_backup_restore(bundle, docs, journal, cluster, 1, 3, 32768, NULL, NULL, error, sizeof(error)));
        return 0;
    }
    sync_count = 0;
    REQUIRE(yd_raft_backup_restore(bundle, docs, journal, cluster, 1, 3, 32768, NULL, NULL, error, sizeof(error)));
    if (!strcmp(scenario, "sync-restore")) {
        unsigned boundaries = sync_count;
        REQUIRE(boundaries >= 10);
        for (unsigned n = 1; n <= boundaries; n++) {
            char name[64], failed_docs[4096], failed_journal[4096];
            snprintf(name, sizeof(name), "failed-docs-%u", n); REQUIRE(directory_new(failed_docs, root, name));
            snprintf(name, sizeof(name), "failed-journal-%u", n); REQUIRE(directory_new(failed_journal, root, name));
            sync_count = 0; sync_fail = n;
            REQUIRE(!yd_raft_backup_restore(bundle, failed_docs, failed_journal, cluster, 1, 3, 32768, NULL, NULL, error, sizeof(error)));
            sync_fail = 0;
        }
        printf("restore-sync-boundaries=%u\n", boundaries);
    }
    REQUIRE(verify(docs, journal, applied, last, !selected));
    yd_disk_reply_free(&policy_original);
    if (!strcmp(scenario, "swapped-pair")) {
        char other_docs[4096], other_journal[4096];
        REQUIRE(directory_new(other_docs, root, "other-docs")); REQUIRE(directory_new(other_journal, root, "other-journal"));
        REQUIRE(yd_raft_backup_restore(other_bundle, other_docs, other_journal, cluster, 1, 3, 32768, NULL, NULL, error, sizeof(error)));
        int d = open(docs, O_RDONLY | O_DIRECTORY | O_CLOEXEC), j = open(other_journal, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        REQUIRE(!yd_raft_backup_verify_pair(d, j, cluster, 1, 3, error, sizeof(error))); close(d); close(j);
    }
    REQUIRE(!yd_raft_backup_restore(bundle, docs, journal, cluster, 1, 3, 32768, NULL, NULL, error, sizeof(error)));
    if (!strcmp(scenario, "pair")) {
        char p[4096]; REQUIRE(path(p, docs, ".yamora-backup-pair")); REQUIRE(!unlink(p));
        int d = open(docs, O_RDONLY | O_DIRECTORY | O_CLOEXEC), j = open(journal, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        REQUIRE(!yd_raft_backup_verify_pair(d, j, cluster, 1, 3, error, sizeof(error))); close(d); close(j);
    }
    return 0;
}
