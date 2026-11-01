/* Test-only reuse: keep quorum, proposal, receipt and legacy fixture setup shared. */
#define main legacy_backup_main
#include "cluster_backup_fixture.c"
#undef main
#include "../src/consensus/application_retire.h"
#include "../src/consensus/snapshot_restore.h"

_Static_assert(YD_RAFT_APPLICATION_SLOTS == 3, "backup fixture requires three fixed slots");
static const unsigned char slots_newer[] = "# newer source\r\nanswer: 43 # exact\r\n";
static const char *const slots_names[] = {
    YD_RAFT_APPLICATION_SLOT_PREFIX "0", YD_RAFT_APPLICATION_SLOT_PREFIX "1",
    YD_RAFT_APPLICATION_SLOT_PREFIX "2"
};
typedef struct {
    unsigned char manifest[YD_RAFT_SNAPSHOT_MANIFEST], identity[32];
    YDRaftApplied origin, applied;
    YDRaftMeta meta;
} SlotsExpected;

static bool slots_view_equal(YDDiskView a, YDDiskView b) {
    return a.format == b.format && a.generation == b.generation && a.root == b.root &&
        a.end == b.end && a.documents == b.documents && a.collections == b.collections &&
        a.bytes == b.bytes && a.revision == b.revision;
}
static int slots_directory(int parent, const char *name) {
    int fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat s;
    if (fd >= 0 && !fstat(fd, &s) && S_ISDIR(s.st_mode) && s.st_uid == geteuid() &&
        !(s.st_mode & (S_IWGRP | S_IWOTH))) return fd;
    if (fd >= 0) close(fd);
    return -1;
}
static bool slots_members(int directory, const char *const *names, size_t count) {
    int fd = slots_directory(directory, ".");
    DIR *scan = fd >= 0 ? fdopendir(fd) : NULL;
    if (!scan) { if (fd >= 0) close(fd); return false; }
    size_t found = 0;
    bool valid = true;
    while (valid) {
        errno = 0;
        struct dirent *entry = readdir(scan);
        if (!entry) { valid = !errno; break; }
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        size_t n = 0;
        while (n < count && strcmp(entry->d_name, names[n])) n++;
        valid = n < count;
        found++;
    }
    closedir(scan);
    return valid && found == count;
}
static bool slots_image(int directory, const SlotsExpected *expected) {
    const char *const names[] = {YD_DISK_FILE, YD_RAFT_SNAPSHOT_CANDIDATE};
    int fd = openat(directory, YD_RAFT_SNAPSHOT_CANDIDATE,
        O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    unsigned char manifest[YD_RAFT_SNAPSHOT_MANIFEST], identity[32];
    struct stat marker, native;
    bool valid = fd >= 0 && !fstat(fd, &marker) && S_ISREG(marker.st_mode) &&
        marker.st_uid == geteuid() && marker.st_nlink == 1 &&
        !(marker.st_mode & (S_IRWXG | S_IRWXO)) &&
        marker.st_size == (off_t)sizeof(manifest);
    size_t at = 0;
    while (valid && at < sizeof(manifest)) {
        ssize_t n = read(fd, manifest + at, sizeof(manifest) - at);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) valid = false;
        else at += (size_t)n;
    }
    size_t size = 0;
    valid = valid && !memcmp(manifest, expected->manifest, sizeof(manifest)) &&
        EVP_Q_digest(NULL, "SHA256", NULL, manifest, sizeof(manifest), identity, &size) == 1 &&
        size == sizeof(identity) && !memcmp(identity, expected->identity, sizeof(identity)) &&
        !fstatat(directory, YD_DISK_FILE, &native, AT_SYMLINK_NOFOLLOW) &&
        S_ISREG(native.st_mode) && native.st_uid == geteuid() && native.st_nlink == 1 &&
        !(native.st_mode & (S_IRWXG | S_IRWXO)) && native.st_size >= 2 * YD_DISK_PAGE &&
        slots_members(directory, names, 2);
    if (fd >= 0) close(fd);
    return valid;
}
static bool slots_inventory(int documents_fd, int journal_fd, const SlotsExpected *expected) {
    const char *const document_names[] = {".yamora-backup-pair", YD_RAFT_GENERATION_DIRECTORY};
    const char *const journal_names[] = {
        ".yamora-backup-pair", YD_DISK_FILE, YD_RAFT_ARCHIVE_DIRECTORY
    };
    int generations = slots_directory(documents_fd, YD_RAFT_GENERATION_DIRECTORY);
    bool valid = slots_members(documents_fd, document_names, 2) &&
        slots_members(journal_fd, journal_names, 3) &&
        generations >= 0 && slots_members(generations, slots_names, YD_RAFT_APPLICATION_SLOTS);
    for (unsigned n = 0; valid && n < YD_RAFT_APPLICATION_SLOTS; n++) {
        int child = slots_directory(generations, slots_names[n]);
        valid = child >= 0 && (n ? slots_members(child, NULL, 0) : slots_image(child, expected));
        if (child >= 0) close(child);
    }
    if (generations >= 0) close(generations);
    return valid;
}
/* This exact complete hash layout identifies the old restore bug. Other
 * recovery failures remain setup failures and cannot count as behavioral RED. */
static bool slots_old_layout(int documents_fd, const SlotsExpected *expected) {
    static const char digits[] = "0123456789abcdef";
    char name[YD_RAFT_SNAPSHOT_ID];
    for (unsigned n = 0; n < 32; n++) {
        name[2 * n] = digits[expected->identity[n] >> 4];
        name[2 * n + 1] = digits[expected->identity[n] & 15];
    }
    name[64] = 0;
    const char *const names[] = {name};
    int generations = slots_directory(documents_fd, YD_RAFT_GENERATION_DIRECTORY);
    int child = generations >= 0 ? slots_directory(generations, name) : -1;
    bool valid = generations >= 0 && slots_members(generations, names, 1) &&
        child >= 0 && slots_image(child, expected);
    if (child >= 0) close(child);
    if (generations >= 0) close(generations);
    return valid;
}
static bool slots_meta5(YDRaft *raft, const SlotsExpected *expected) {
    static const unsigned char key[] = {0, 'Y', 'R', 'M'};
    unsigned char encoded[144];
    YDDiskView view = yd_disk_view(raft->disk);
    uint64_t offset = 0;
    size_t size = 0;
    bool valid = yd_raft_encode_meta(&expected->meta, encoded) == sizeof(encoded) &&
        !memcmp(encoded, "YDRMETA5", 8) && encoded[26] == 1 &&
        encoded[27] == (expected->meta.membership_required ? 1 : 0) &&
        raft->meta.application_layout == 1 &&
        raft->meta.membership_required == expected->meta.membership_required &&
        !memcmp(raft->meta.application, expected->identity, 32) &&
        yd_disk_get(raft->disk, &view, key, sizeof(key), &offset, error, sizeof(error)) == 1;
    unsigned char *bytes = valid
        ? yd_disk_record(raft->disk, &view, offset, &size, error, sizeof(error)) : NULL;
    valid = valid && bytes && size == sizeof(encoded) && !memcmp(bytes, encoded, sizeof(encoded));
    free(bytes);
    return valid;
}
static bool slots_application(YDRaftApplication *app, YDRaftApplied origin,
    const SlotsExpected *expected) {
    YDRaftApplied applied = yd_raft_application_position(app);
    YDDisk *disk = yd_raft_application_disk(app);
    YDDiskView view = yd_disk_view(disk);
    YDDiskDocument document = {0};
    bool valid = origin.index == expected->origin.index && origin.term == expected->origin.term &&
        origin.index < applied.index && applied.index == expected->applied.index &&
        applied.term == expected->applied.term && original_receipt(app) &&
        yd_disk_document_get(disk, &view, "a", "x", &document, error, sizeof(error)) == 1 &&
        document.length == sizeof(slots_newer) - 1 &&
        !memcmp(document.body, slots_newer, sizeof(slots_newer) - 1);
    yd_disk_document_free(&document);
    return valid;
}
static bool slots_checkpoint(SlotsExpected *expected) {
    char archives_path[4096], id[YD_RAFT_SNAPSHOT_ID];
    int root_fd = open(documents[0], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int archives_fd = -1, generations = -1, directories[YD_RAFT_APPLICATION_SLOTS];
    for (unsigned n = 0; n < YD_RAFT_APPLICATION_SLOTS; n++) directories[n] = -1;
    YDRaftCheckpoint origin = {0};
    YDRaftSnapshot *image = NULL;
    YDDisk *pin = NULL;
    YDRaftSnapshotArchive *archive = NULL;
    YDRaftApplication *candidate = NULL;
    YDDiskView source = yd_disk_view(yd_raft_application_disk(apps[0]));
    bool valid = root_fd >= 0 &&
        directory_new(archives_path, journals[0], YD_RAFT_ARCHIVE_DIRECTORY);
    if (valid) archives_fd = open(archives_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (valid && archives_fd >= 0) {
        image = yd_raft_snapshot_open(apps[0], 3, error, sizeof(error));
        pin = yd_raft_application_pin(apps[0], 32768, &origin, error, sizeof(error));
    }
    if (image && pin) archive = yd_raft_capture_archive(image, pin, archives_fd,
        cluster, 3, NULL, NULL, id, error, sizeof(error));
    size_t size = 0;
    valid = valid && archive &&
        yd_raft_snapshot_archive_manifest(archive, expected->manifest) &&
        EVP_Q_digest(NULL, "SHA256", NULL, expected->manifest, sizeof(expected->manifest),
            expected->identity, &size) == 1 && size == sizeof(expected->identity) &&
        slots_view_equal(source, yd_disk_view(pin)) &&
        !mkdirat(root_fd, YD_RAFT_GENERATION_DIRECTORY, 0700) && !fsync(root_fd);
    if (valid) generations = slots_directory(root_fd, YD_RAFT_GENERATION_DIRECTORY);
    valid = valid && generations >= 0;
    for (unsigned n = 0; valid && n < YD_RAFT_APPLICATION_SLOTS; n++) {
        valid = !mkdirat(generations, slots_names[n], 0700);
        if (valid) directories[n] = slots_directory(generations, slots_names[n]);
        valid = valid && directories[n] >= 0 &&
            slots_members(directories[n], NULL, 0) && !fsync(directories[n]);
    }
    valid = valid && !fsync(generations) && !fsync(root_fd) &&
        yd_raft_snapshot_restore_at(archive, directories[0], cluster, 3, 32768,
            NULL, NULL, error, sizeof(error));
    if (valid) candidate = yd_raft_candidate_open_at(directories[0], expected->manifest,
        cluster, 3, 32768, NULL, NULL, error, sizeof(error));
    YDRaftSnapshotBase base = {.index = origin.applied.index, .term = origin.applied.term};
    memcpy(base.archive, expected->identity, sizeof(base.archive));
    unsigned char zero[32] = {0};
    valid = valid && candidate &&
        slots_view_equal(source, yd_disk_view(yd_raft_application_disk(apps[0]))) &&
        yd_raft_application_select_layout(nodes[0], zero, &base, 1);
    if (valid) {
        YDRaftApplication *previous = apps[0];
        apps[0] = candidate; candidate = NULL;
        yd_raft_application_close(previous);
        expected->origin = origin.applied;
    }
    yd_raft_application_close(candidate);
    yd_raft_snapshot_archive_close(archive);
    yd_raft_snapshot_close(image);
    yd_disk_close(pin);
    for (unsigned n = 0; n < YD_RAFT_APPLICATION_SLOTS; n++)
        if (directories[n] >= 0) close(directories[n]);
    if (generations >= 0) close(generations);
    if (archives_fd >= 0) close(archives_fd);
    if (root_fd >= 0) close(root_fd);
    return valid;
}
#define SLOTS_SETUP(expression) do { phase = #expression; if (!(expression)) goto finished; } while (0)

int main(int argc, char **argv) {
    if (argc != 3) return 64;
    bool required = !strcmp(argv[2], "required") || !strcmp(argv[2], "required-zero");
    bool refuse_zero = !strcmp(argv[2], "required-zero");
    if (!required && strcmp(argv[2], "legacy")) return 64;
    const char *phase = "seed";
    int result = 3, documents_fd = -1, journal_fd = -1;
    YDRaftBackup *backup = NULL;
    YDRaft *restored = NULL;
    YDRaftApplication *application = NULL;
    SlotsExpected expected = {0};
    char bundle[4096], restored_documents[4096], restored_journal[4096];
    SLOTS_SETUP(seed(argv[1]));
    SLOTS_SETUP(slots_checkpoint(&expected));
    SLOTS_SETUP(put(2, slots_newer, sizeof(slots_newer) - 1));
    if (required) {
        YDRaftMeta metadata = nodes[0]->meta;
        metadata.membership_required = true;
        SLOTS_SETUP(yd_raft_save(nodes[0], &metadata, NULL));
    }
    expected.meta = nodes[0]->meta;
    expected.applied = yd_raft_application_position(apps[0]);
    SLOTS_SETUP(slots_meta5(nodes[0], &expected));
    documents_fd = open(documents[0], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    SLOTS_SETUP(documents_fd >= 0);
    yd_raft_application_close(apps[0]); apps[0] = NULL;
    YDRaftApplied source_origin = {0};
    apps[0] = yd_raft_recover_open_origin(documents_fd, nodes[0], 32768, &source_origin,
        NULL, NULL, error, sizeof(error));
    SLOTS_SETUP(apps[0] && slots_application(apps[0], source_origin, &expected));
    close(documents_fd); documents_fd = -1;
    uint32_t configuration = required ? nodes[0]->configuration_base : 0;
    backup = yd_raft_backup_capture(nodes[0], apps[0], configuration, 32768, error, sizeof(error));
    SLOTS_SETUP(backup && directory_new(bundle, argv[1], "bundle"));
    SLOTS_SETUP(yd_raft_backup_write(backup, bundle, NULL, NULL, error, sizeof(error)));
    yd_raft_backup_close(backup); backup = NULL;
    if (refuse_zero) {
        /* The exact-word positive control above proves the same source is valid. */
        backup = yd_raft_backup_capture(nodes[0], apps[0], 0, 32768, error, sizeof(error));
        SLOTS_SETUP(backup && directory_new(bundle, argv[1], "zero-word-bundle"));
        if (yd_raft_backup_write(backup, bundle, NULL, NULL, error, sizeof(error))) {
            phase = "required configuration zero was accepted"; result = 4; goto finished;
        }
        result = 0; goto finished;
    }
    close_all();
    SLOTS_SETUP(directory_new(restored_documents, argv[1], "restored-documents"));
    SLOTS_SETUP(directory_new(restored_journal, argv[1], "restored-journal"));
    SLOTS_SETUP(yd_raft_backup_restore(bundle, restored_documents, restored_journal,
        cluster, 1, 3, 32768, NULL, NULL, error, sizeof(error)));
    documents_fd = open(restored_documents, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    journal_fd = open(restored_journal, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    SLOTS_SETUP(documents_fd >= 0 && journal_fd >= 0 &&
        yd_raft_backup_verify_pair(documents_fd, journal_fd, cluster, 1, 3, error, sizeof(error)));
    restored = yd_raft_open(restored_journal, cluster, 1, 3, 32768, error, sizeof(error));
    SLOTS_SETUP(restored && slots_meta5(restored, &expected));
    YDRaftApplied restored_origin = {0};
    application = yd_raft_recover_open_origin(documents_fd, restored, 32768, &restored_origin,
        NULL, NULL, error, sizeof(error));
    if (!application) {
        phase = "ordinary restored META5 selected recovery";
        if (slots_old_layout(documents_fd, &expected)) result = 2;
        goto finished;
    }
    phase = "restored exact YAML, receipt, selected origin and fixed-slot inventory";
    if (!slots_application(application, restored_origin, &expected) ||
        !slots_inventory(documents_fd, journal_fd, &expected)) { result = 4; goto finished; }
    result = 0;
finished:
    yd_raft_application_close(application);
    yd_raft_close(restored);
    yd_raft_backup_close(backup);
    close_all();
    if (documents_fd >= 0) close(documents_fd);
    if (journal_fd >= 0) close(journal_fd);
    if (result == 2)
        fprintf(stderr, "META5_BACKUP_SELECTED_RECOVERY_FAILED scenario=%s error=%s\n", argv[2], error);
    else if (result)
        fprintf(stderr, "META5_BACKUP_%s_FAILED phase=%s error=%s\n",
            result == 3 ? "SETUP" : "VALIDATION", phase, error);
    else
        printf("META5_BACKUP_SLOTS_OK scenario=%s\n", argv[2]);
    return result;
}
