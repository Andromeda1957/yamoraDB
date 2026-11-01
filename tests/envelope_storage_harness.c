#define _GNU_SOURCE
#include "security/storage_image.h"
#include "security/storage_config.h"
#include "disk_internal.h"
#include "disk_documents.h"
#include "disk_replica.h"
#include "disk_bulk.h"
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define REQUIRE(test) do { if (!(test)) { fprintf(stderr, "CONTROL line %d: %s [%s]\n", __LINE__, #test, error); return 70; } } while (0)
static char error[512];
static const char original[] = "# authored comment\nname: 'caf\xc3\xa9'\nrating: 7\nbody: |\n  ENCRYPTED-STORAGE-EXACT-BYTES\n";
static const char replacement[] = "# replacement comment\nname: 'caf\xc3\xa9'\nrating: 8\nbody: |\n  ENCRYPTED-STORAGE-EXACT-BYTES\n";
static const char receipt[] = "native opaque receipt: ENCRYPTED-STORAGE-RECEIPT\0binary";
static const unsigned char receipt_key[] = {0, 'E', 'R', 1};
static const char token_a[] = "v1.00112233445566778899aabbccddeeff.0000000000000002";
static const char token_b[] = "v1.00112233445566778899aabbccddeeff.0000000000000003";
static const char *fault;
static unsigned file_syncs, directory_syncs, renames;
static int kill_stage;
static unsigned providers_freed;
void __real_yd_key_provider_free(YDKeyProvider *);
void __wrap_yd_key_provider_free(YDKeyProvider *provider) {
    if (provider) providers_freed++;
    __real_yd_key_provider_free(provider);
}
static void trace(unsigned char kind, uint64_t offset, const void *bytes, size_t size) {
    const char *path = getenv("ENVELOPE_STORAGE_TRACE");
    if (!path) return;
    static int fd = -1;
    if (fd < 0) fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) _exit(90);
    unsigned char header[17] = {kind};
    for (unsigned i = 0; i < 8; i++) {
        header[1 + i] = (unsigned char)(offset >> (8 * i));
        header[9 + i] = (unsigned char)((uint64_t)size >> (8 * i));
    }
    const unsigned char *data[] = {header, bytes};
    size_t lengths[] = {sizeof(header), size};
    for (size_t part = 0; part < 2; part++) {
        size_t at = 0;
        while (at < lengths[part]) {
            ssize_t n = write(fd, data[part] + at, lengths[part] - at);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) _exit(91);
            at += (size_t)n;
        }
    }
}
static bool stage_file(int fd) {
    struct stat s;
    return !fstat(fd, &s) && S_ISREG(s.st_mode) && s.st_nlink == 1;
}
static void boundary(int stage) { if (kill_stage == stage) (void)kill(getpid(), SIGKILL); }
int __real_fsync(int);
int __wrap_fsync(int fd) {
    struct stat s;
    bool file = stage_file(fd), directory = !fstat(fd, &s) && S_ISDIR(s.st_mode);
    if (file) boundary(1);
    if (directory) boundary(5);
    if (fault && ((!strcmp(fault, "file-sync") && file) ||
        (!strcmp(fault, "directory-sync") && directory))) { errno = EIO; return -1; }
    int result = __real_fsync(fd);
    if (!result && file) { file_syncs++; trace('F', 0, NULL, 0); boundary(2); }
    if (!result && directory) {
        directory_syncs++;
        if (fault && !strcmp(fault, "backup-unlink")) (void)unlinkat(fd, YD_DISK_FILE, 0);
        if (fault && !strcmp(fault, "backup-root-mode")) (void)fchmod(fd, 0755);
        if (fault && !strcmp(fault, "post-rename-corruption")) {
            int target = openat(fd, YD_DISK_FILE, O_WRONLY | O_NOFOLLOW | O_CLOEXEC);
            unsigned char changed = 0;
            if (target >= 0) { (void)pwrite(target, &changed, 1, 0); close(target); }
        }
        trace('D', 0, NULL, 0);
        boundary(6);
    }
    return result;
}
int __real_renameat(int, const char *, int, const char *);
int __wrap_renameat(int old_directory, const char *old_name, int new_directory, const char *new_name) {
    boundary(3);
    if (fault && !strcmp(fault, "rename")) { errno = EIO; return -1; }
    int result = __real_renameat(old_directory, old_name, new_directory, new_name);
    if (!result) { renames++; trace('R', 0, NULL, 0); boundary(4); }
    return result;
}
ssize_t __real_pwrite(int, const void *, size_t, off_t);
ssize_t __wrap_pwrite(int fd, const void *bytes, size_t size, off_t offset) {
    if (fault && stage_file(fd)) {
        if (!strcmp(fault, "enospc")) { errno = ENOSPC; return -1; }
        if (!strcmp(fault, "silent-corruption") && size && offset == 0) {
            unsigned char changed = ((const unsigned char *)bytes)[0] ^ 1;
            ssize_t result = __real_pwrite(fd, bytes, size, offset);
            if (result > 0) (void)__real_pwrite(fd, &changed, 1, offset);
            return result;
        }
    }
    ssize_t result = __real_pwrite(fd, bytes, size, offset);
    if (result > 0 && stage_file(fd)) trace('W', (uint64_t)offset, bytes, (size_t)result);
    return result;
}
int __real_mlock2(const void *, size_t, unsigned);
int __wrap_mlock2(const void *address, size_t length, unsigned flags) {
    if (fault && !strcmp(fault, "mlock")) { errno = ENOMEM; return -1; }
    return __real_mlock2(address, length, flags);
}
int __real_madvise(void *, size_t, int);
int __wrap_madvise(void *address, size_t length, int advice) {
    if (fault && !strcmp(fault, "dontdump")) { errno = EINVAL; return -1; }
    return __real_madvise(address, length, advice);
}
static YDKeyProvider *provider(const char *mode) {
    YDKeyEntry keys[2] = {{.id = "image-key-1"}, {.id = "image-key-2"}};
    memset(keys[0].bytes, !strcmp(mode, "wrong") ? 0x50 : 0x51, 32);
    memset(keys[1].bytes, 0x62, 32);
    return !strcmp(mode, "missing") || !strcmp(mode, "read-key2") ?
        yd_key_provider_local(&keys[1], 1) : yd_key_provider_local(keys, 2);
}
static YDStorageImageOptions options(uint64_t generation, bool initialize) {
    YDStorageImageOptions result = {.maximum_bytes = 1024U * 1024U, .cache_bytes = 32768,
        .initialize = initialize, .expected = {.generation = generation, .kind = YD_STORAGE_IMAGE_KIND}};
    memset(result.expected.store_id, 0xA1, sizeof(result.expected.store_id));
    memset(result.expected.object_id, 0xB2, sizeof(result.expected.object_id));
    return result;
}
static bool document(YDDisk *disk, const char *body) {
    YDDiskTxn *txn = yd_disk_begin(disk, error, sizeof(error));
    YDWrite write = {.collection = "people", .document = "alice",
        .body = (const unsigned char *)body, .length = strlen(body)};
    if (!txn || !yd_disk_apply(txn, &write, 1, error, sizeof(error))) {
        yd_disk_abort(txn); return false;
    }
    return yd_disk_commit(txn, error, sizeof(error));
}
static bool change(YDDisk *disk) {
    YDDiskTxn *txn = yd_disk_begin(disk, error, sizeof(error));
    YDWrite write = {.collection = "people", .document = "alice",
        .body = (const unsigned char *)replacement, .length = sizeof(replacement) - 1};
    if (!txn || !yd_disk_apply(txn, &write, 1, error, sizeof(error)) ||
        !yd_disk_replica_checkpoint(txn, token_b, error, sizeof(error))) {
        yd_disk_abort(txn); return false;
    }
    return yd_disk_commit(txn, error, sizeof(error));
}
static bool check_document(YDDisk *disk, bool newer) {
    YDDiskView view = yd_disk_view(disk);
    YDDiskDocument got = {0};
    const char *body = newer ? replacement : original;
    bool valid = yd_disk_document_get(disk, &view, "people", "alice", &got, error, sizeof(error)) == 1 &&
        got.length == strlen(body) && !memcmp(got.body, body, got.length);
    yd_disk_document_free(&got);
    return valid;
}
static bool real_kernel_lock(void) {
    FILE *status = fopen("/proc/self/smaps", "re");
    if (!status) return false;
    char line[512];
    unsigned long long locked = 0;
    bool native = false, valid = false;
    size_t total = 0;
    while (total < 8U * 1024U * 1024U && fgets(line, sizeof(line), status)) {
        total += strlen(line);
        unsigned long long start, end;
        if (sscanf(line, "%llx-%llx", &start, &end) == 2) {
            native = strstr(line, "memfd:yamora-encrypted-native") != NULL;
            locked = 0;
        } else if (native && sscanf(line, "Locked: %llu kB", &locked) == 1) {
            if (locked < 1024) break;
        } else if (native && !strncmp(line, "VmFlags:", 8)) {
            valid = locked >= 1024 && strstr(line, " lo ") && strstr(line, " dd ");
            break;
        }
    }
    fclose(status);
    return valid;
}
static bool check_records(YDDisk *disk, bool newer) {
    if (!check_document(disk, newer)) return false;
    YDDiskView view = yd_disk_view(disk);
    YDDiskIndexes *indexes = yd_disk_indexes_load(disk, &view, error, sizeof(error));
    bool valid = indexes && indexes->count == 1 && !strcmp(indexes->indexes[0].name, "rating");
    YDValue rating = {.type = YD_INT, .number = newer ? 8 : 7};
    const YDValue *values[] = {&rating};
    unsigned char prefix[YD_DISK_KEY_LIMIT], key[YD_DISK_KEY_LIMIT];
    size_t prefix_size = 0, key_size = 0;
    uint64_t record = 0;
    valid = valid && yd_disk_index_prefix(&indexes->indexes[0], values, 1,
        prefix, &prefix_size, error, sizeof(error));
    YDDiskCursor *cursor = valid ? yd_disk_cursor(disk, &view, prefix, prefix_size, false, error, sizeof(error)) : NULL;
    valid = cursor && yd_disk_next(cursor, key, sizeof(key), &key_size, &record, error, sizeof(error)) == 1 &&
        key_size > prefix_size && !memcmp(key, prefix, prefix_size);
    yd_disk_cursor_free(cursor);
    yd_disk_indexes_free(indexes);
    uint64_t offset = 0;
    valid = valid && yd_disk_get(disk, &view, receipt_key, sizeof(receipt_key), &offset, error, sizeof(error)) == 1;
    size_t size = 0;
    unsigned char *saved = valid ? yd_disk_record(disk, &view, offset, &size, error, sizeof(error)) : NULL;
    valid = saved && size == sizeof(receipt) && !memcmp(saved, receipt, size);
    free(saved);
    return valid;
}
static bool check_all(YDDisk *disk, bool newer) {
    YDDiskView view = yd_disk_view(disk);
    YDDiskReplicaPosition position;
    return check_records(disk, newer) && yd_disk_replica_position(disk, &view, &position, error, sizeof(error)) == 1 &&
        !strcmp(position.after, newer ? token_b : token_a);
}
static int seed(YDStorageImage *image) {
    YDDisk *disk = yd_storage_image_disk(image);
    REQUIRE(document(disk, original));
    YDDiskTxn *txn = yd_disk_begin_exclusive(disk, error, sizeof(error));
    const char catalog[] = "{indexes: [{collection: people, name: rating, fields: [rating], unique: true}]}";
    REQUIRE(txn && yd_disk_indexes_replace(txn, (const unsigned char *)catalog, sizeof(catalog) - 1, error, sizeof(error)));
    REQUIRE(yd_disk_commit(txn, error, sizeof(error)));
    txn = yd_disk_begin(disk, error, sizeof(error));
    uint64_t offset = 0;
    REQUIRE(txn && yd_disk_append(txn, receipt, sizeof(receipt), &offset, error, sizeof(error)) &&
        yd_disk_put(txn, receipt_key, sizeof(receipt_key), offset, error, sizeof(error)));
    REQUIRE(yd_disk_commit(txn, error, sizeof(error)));
    txn = yd_disk_begin(disk, error, sizeof(error));
    REQUIRE(txn && yd_disk_replica_checkpoint(txn, token_a, error, sizeof(error)));
    YDDiskView committed;
    REQUIRE(yd_disk_commit_view(txn, &committed, error, sizeof(error)));
    REQUIRE(committed.generation == yd_disk_view(disk).generation && check_all(disk, false));
    return 0;
}
static YDDiskReply request(YDDiskAPI *api, const char *action, const char *body) {
    char path[128];
    snprintf(path, sizeof(path), "/v1/replication/follow/%s", action);
    return yd_disk_api_request(api, "POST", path, (const unsigned char *)body, strlen(body), NULL, NULL, false);
}
static int staging(YDStorageImage *image, int destination) {
    YDDisk *disk = yd_storage_image_disk(image);
    YDDiskAPI api;
    REQUIRE(yd_disk_api_init(&api, disk, true));
    YDDiskView view = yd_disk_view(disk);
    uint64_t revision = view.revision ^ yd_disk_fingerprint("people", "alice", original, sizeof(original) - 1) ^
        yd_disk_fingerprint("people", "alice", replacement, sizeof(replacement) - 1);
    char body[1024];
    snprintf(body, sizeof(body), "{\"after\":\"%s\",\"token\":\"%s\",\"previous_revision\":\"%016llx\","
        "\"revision\":\"%016llx\",\"operations\":1}", token_a, token_b,
        (unsigned long long)view.revision, (unsigned long long)revision);
    YDDiskReply reply = request(&api, "begin", body);
    REQUIRE(reply.status == 200);
    YDValue *begun = yd_parse_request((const unsigned char *)reply.body, reply.length, error, sizeof(error));
    const YDValue *session = begun ? yd_get(begun, "session") : NULL;
    REQUIRE(session && session->type == YD_STRING);
    yd_disk_reply_free(&reply);
    snprintf(body, sizeof(body), "{\"session\":\"%s\",\"operations\":[{\"collection\":\"people\",\"document\":\"alice\","
        "\"put\":\"# replacement comment\\nname: 'caf\xc3\xa9'\\nrating: 8\\nbody: |\\n  ENCRYPTED-STORAGE-EXACT-BYTES\\n\"}]}", session->scalar);
    reply = request(&api, "apply", body);
    REQUIRE(reply.status == 200 && check_all(disk, false));
    yd_disk_reply_free(&reply);
    YDEnvelopeIdentity backup;
    REQUIRE(yd_storage_image_backup_at(image, destination, &backup, error, sizeof(error)) && backup.generation == 5);
    snprintf(body, sizeof(body), "{\"session\":\"%s\"}", session->scalar);
    reply = request(&api, "commit", body);
    REQUIRE(reply.status == 200 && check_all(disk, true));
    yd_disk_reply_free(&reply);
    yd_free(begun);
    yd_disk_api_destroy(&api);
    return 0;
}
typedef struct { YDDisk *disk; unsigned worker; bool ok; } Worker;
static void *concurrent_writer(void *context) {
    Worker *worker = context;
    char local_error[512] = {0};
    worker->ok = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL) == 0;
    for (unsigned i = 0; worker->ok && i < 4; i++) {
        char id[32];
        snprintf(id, sizeof(id), "worker-%u-%u", worker->worker, i);
        YDDiskTxn *txn = yd_disk_begin(worker->disk, local_error, sizeof(local_error));
        YDWrite write = {.collection = "workers", .document = id,
            .body = (const unsigned char *)original, .length = sizeof(original) - 1};
        worker->ok = txn && yd_disk_apply(txn, &write, 1, local_error, sizeof(local_error));
        if (worker->ok) worker->ok = yd_disk_commit(txn, local_error, sizeof(local_error));
        else yd_disk_abort(txn);
        if (!worker->ok) fprintf(stderr, "worker %u item %u: errno=%d %s\n",
            worker->worker, i, errno, local_error);
    }
    return NULL;
}
static bool check_workers(YDDisk *disk) {
    YDDiskView view = yd_disk_view(disk);
    bool records = check_records(disk, false);
    /* Alice and the persisted yamldb-system/indexes catalog precede the eight
     * worker documents; the catalog is a native document, not an opaque key. */
    bool valid = view.documents == 10 && records;
    if (!valid) fprintf(stderr, "workers view: documents=%llu generation=%llu records=%d %s\n",
        (unsigned long long)view.documents, (unsigned long long)view.generation, records, error);
    for (unsigned worker = 0; valid && worker < 2; worker++) {
        for (unsigned i = 0; valid && i < 4; i++) {
            char id[32];
            snprintf(id, sizeof(id), "worker-%u-%u", worker, i);
            YDDiskDocument got = {0};
            valid = yd_disk_document_get(disk, &view, "workers", id, &got, error, sizeof(error)) == 1 &&
                got.length == sizeof(original) - 1 && !memcmp(got.body, original, got.length);
            if (!valid) fprintf(stderr, "worker document %s invalid: length=%zu %s\n", id, got.length, error);
            yd_disk_document_free(&got);
        }
    }
    return valid;
}
int main(int argc, char **argv) {
    if (argc < 4) return 2;
    REQUIRE(!pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL));
    const char *mode = argv[2];
    uint64_t generation = strtoull(argv[3], NULL, 10);
    if (!strncmp(mode, "config-", 7)) {
        REQUIRE(argc == 5);
        if (!strcmp(mode, "config-cancel")) REQUIRE(!pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL));
        YDStorageConfig *config = yd_storage_config_open(argv[4], argv[1], error, sizeof(error));
        REQUIRE(!pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL));
        if (!strcmp(mode, "config-refuse") || !strcmp(mode, "config-cancel")) { REQUIRE(!config); return 0; }
        REQUIRE(config && real_kernel_lock());
        YDDisk *configured = yd_storage_config_disk(config);
        if (!strcmp(mode, "config-seed")) REQUIRE(document(configured, original));
        else REQUIRE(check_document(configured, false));
        YDEnvelopeIdentity identity;
        REQUIRE(yd_storage_config_identity(config, &identity));
        printf("%llu\n", (unsigned long long)identity.generation);
        if (!strcmp(mode, "config-pin")) {
            YDDisk *pin = yd_disk_pin(configured, 32768, error, sizeof(error));
            REQUIRE(pin);
            unsigned before = providers_freed;
            yd_storage_config_close(config);
            REQUIRE(providers_freed == before && check_document(pin, false));
            yd_disk_close(pin);
            REQUIRE(providers_freed == before + 1);
        } else yd_storage_config_close(config);
        return 0;
    }
    bool initialize = !strcmp(mode, "seed") || !strcmp(mode, "mlock") || !strcmp(mode, "dontdump");
    YDStorageImageOptions config = options(generation, initialize);
    YDKeyProvider *keys = provider(mode);
    REQUIRE(keys);
    int root = open(argv[1], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    REQUIRE(root >= 0);
    if (!strcmp(mode, "mlock") || !strcmp(mode, "dontdump")) fault = mode;
    if (!strcmp(mode, "relocation")) config.expected.object_id[0] ^= 1;
    YDStorageImage *image = yd_storage_image_open_at(root, keys, "image-key-1", &config, error, sizeof(error));
    if (!strcmp(mode, "missing") || !strcmp(mode, "wrong") || !strcmp(mode, "refuse") ||
        !strcmp(mode, "relocation") || !strcmp(mode, "mlock") || !strcmp(mode, "dontdump")) {
        REQUIRE(!image);
        close(root); yd_key_provider_free(keys); return 0;
    }
    REQUIRE(image);
    REQUIRE(real_kernel_lock());
    YDDisk *disk = yd_storage_image_disk(image);
    if (!strcmp(mode, "seed")) REQUIRE(seed(image) == 0);
    else if (!strcmp(mode, "read-old")) REQUIRE(check_all(disk, false));
    else if (!strcmp(mode, "read-workers")) REQUIRE(check_workers(disk));
    else if (!strcmp(mode, "read-new") || !strcmp(mode, "read-key2")) REQUIRE(check_all(disk, true));
    else if (!strcmp(mode, "stage-backup")) {
        REQUIRE(argc == 5);
        int destination = open(argv[4], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        REQUIRE(destination >= 0 && staging(image, destination) == 0);
        close(destination);
    } else if (!strcmp(mode, "rotate")) {
        YDKeyProvider *target = provider("read-key2");
        REQUIRE(target && yd_storage_image_rotate(image, target, "image-key-2", error, sizeof(error)));
        REQUIRE(check_all(disk, true));
        YDEnvelopeIdentity identity;
        REQUIRE(yd_storage_image_identity(image, &identity));
        printf("%llu\n", (unsigned long long)identity.generation);
        yd_storage_image_close(image); yd_key_provider_free(target);
        close(root); yd_key_provider_free(keys); return 0;
    } else if (!strcmp(mode, "concurrent")) {
        YDDiskTxn *txn = yd_disk_begin(disk, error, sizeof(error));
        REQUIRE(txn && yd_disk_create_collection(txn, "workers", error, sizeof(error)) &&
            yd_disk_commit(txn, error, sizeof(error)));
        YDDisk *pin = yd_disk_pin(disk, 32768, error, sizeof(error));
        REQUIRE(pin);
        Worker workers[2] = {{disk, 0, false}, {disk, 1, false}};
        pthread_t threads[2];
        REQUIRE(!pthread_create(&threads[0], NULL, concurrent_writer, &workers[0]));
        REQUIRE(!pthread_create(&threads[1], NULL, concurrent_writer, &workers[1]));
        REQUIRE(!pthread_join(threads[0], NULL) && !pthread_join(threads[1], NULL));
        REQUIRE(workers[0].ok && workers[1].ok && check_workers(disk) && check_document(pin, false));
        yd_disk_close(pin);
    } else if (!strcmp(mode, "guards")) {
        REQUIRE(!yd_disk_checkpoint_open(disk, error, sizeof(error)));
        YDDiskRecoveryRoots *roots = NULL;
        REQUIRE(yd_disk_recovery_roots_pin(disk, 32768, &roots, error, sizeof(error)) != YD_DISK_OBSERVE_OK && !roots);
        REQUIRE(!yd_disk_open(argv[1], false, 32768, error, sizeof(error)));
        YDDisk *pin = yd_disk_pin(disk, 32768, error, sizeof(error));
        REQUIRE(pin && check_all(pin, false));
        REQUIRE(document(disk, replacement) && check_document(pin, false));
        YDEnvelopeIdentity identity;
        REQUIRE(yd_storage_image_identity(image, &identity));
        yd_storage_image_close(image); image = NULL;
        config.expected = identity; config.initialize = false;
        REQUIRE(!yd_storage_image_open_at(root, keys, "image-key-1", &config, error, sizeof(error)));
        REQUIRE(check_document(pin, false));
        yd_disk_close(pin);
        image = yd_storage_image_open_at(root, keys, "image-key-1", &config, error, sizeof(error));
        REQUIRE(image);
    } else if (!strcmp(mode, "restore")) {
        REQUIRE(argc == 5);
        yd_storage_image_close(image); image = NULL;
        int destination = open(argv[4], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        REQUIRE(destination >= 0 && yd_storage_image_restore_at(root, destination, keys, "image-key-1", &config, error, sizeof(error)));
        close(destination);
    } else if (!strcmp(mode, "backup-fault")) {
        REQUIRE(argc == 6);
        int destination = open(argv[4], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        REQUIRE(destination >= 0);
        fault = argv[5];
        YDEnvelopeIdentity identity;
        REQUIRE(!yd_storage_image_backup_at(image, destination, &identity, error, sizeof(error)));
        REQUIRE(identity.generation == 0);
        fault = NULL;
        REQUIRE(check_all(disk, false) && yd_disk_writable(disk));
        close(destination);
    } else if (!strcmp(mode, "write-fault") || !strcmp(mode, "kill") || !strcmp(mode, "change")) {
        unsigned before_file = file_syncs, before_directory = directory_syncs, before_rename = renames;
        if (!strcmp(mode, "write-fault")) { REQUIRE(argc == 5); fault = argv[4]; }
        if (!strcmp(mode, "kill")) { REQUIRE(argc == 5); kill_stage = atoi(argv[4]); }
        YDDiskView before = yd_disk_view(disk);
        bool committed = change(disk);
        if (!strcmp(mode, "write-fault")) {
            REQUIRE(!committed && !yd_disk_writable(disk) && !yd_disk_begin(disk, error, sizeof(error)));
            REQUIRE(yd_disk_view(disk).generation == before.generation && check_document(disk, false));
        } else {
            REQUIRE(committed && file_syncs > before_file && directory_syncs > before_directory && renames > before_rename);
        }
        fault = NULL;
    } else { REQUIRE(false); }
    if (image) {
        YDEnvelopeIdentity identity;
        if (yd_storage_image_identity(image, &identity)) printf("%llu\n", (unsigned long long)identity.generation);
        yd_storage_image_close(image);
    }
    close(root);
    yd_key_provider_free(keys);
    return 0;
}
