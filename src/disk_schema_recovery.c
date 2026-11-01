#define _POSIX_C_SOURCE 200809L
#include "disk_schema_recovery.h"
#include "disk_bulk.h"
#include "disk_internal.h"
#include "disk_documents.h"
#include "binary.h"
#include "schema/policy_admission.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#define HEADER 128U
#define FRAME 16U
static uint32_t u32(const unsigned char *p) {
    return (uint32_t)yd_disk_u16(p) | (uint32_t)yd_disk_u16(p + 2) << 16;
}
static void set32(unsigned char *p, uint32_t value) {
    yd_disk_set16(p, (uint16_t)value);
    yd_disk_set16(p + 2, (uint16_t)(value >> 16));
}
typedef struct {
    int fd;
    uint64_t at;
    bool writing;
    EVP_MD_CTX *hash;
    YDPolicyWork *work;
    YDDiskValidation *state;
} Stream;
static bool zero(const unsigned char *p, size_t n) {
    for (size_t i = 0; i < n; i++) if (p[i]) return false;
    return true;
}
static bool profile(const YDDiskView *v) {
    return (v->format == 7 && !v->capabilities) ||
        (v->format == 8 && v->capabilities == YD_DISK_CAP_SCHEMA);
}
static bool private_file(int fd, struct stat *s) {
    return fd >= 0 && !fstat(fd, s) && S_ISREG(s->st_mode) && s->st_uid == geteuid() &&
        s->st_nlink == 1 && !(s->st_mode & (S_IRWXG | S_IRWXO)) && s->st_size >= 0 &&
        (uint64_t)s->st_size <= YD_SCHEMA_RECOVERY_LIMIT;
}
static bool stable(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino && a->st_size == b->st_size &&
        a->st_mode == b->st_mode && a->st_uid == b->st_uid && a->st_nlink == b->st_nlink &&
        a->st_mtim.tv_sec == b->st_mtim.tv_sec && a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
        a->st_ctim.tv_sec == b->st_ctim.tv_sec && a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}
static bool transfer(Stream *s, void *data, size_t size, bool hashed) {
    if (!size) return true;
    if (s->at > YD_SCHEMA_RECOVERY_LIMIT || size > YD_SCHEMA_RECOVERY_LIMIT - s->at ||
        size > s->work->catalog.work_left) { s->work->catalog.work_left = 0; return false; }
    s->work->catalog.work_left -= size;
    unsigned char *bytes = data;
    size_t done = 0;
    while (done < size) {
        if (!yd_disk_validation_step(s->state, YD_VALIDATE_OPERATION) ||
            !s->work->catalog.work_left) return false;
        s->work->catalog.work_left--;
        size_t count = size - done;
        if (count > YD_DISK_CHECKPOINT_CHUNK) count = YD_DISK_CHECKPOINT_CHUNK;
        ssize_t n = s->writing ? pwrite(s->fd, bytes + done, count, (off_t)(s->at + done)) :
            pread(s->fd, bytes + done, count, (off_t)(s->at + done));
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        done += (size_t)n;
    }
    s->at += size;
    return !hashed || EVP_DigestUpdate(s->hash, data, size) == 1;
}
static bool digest(Stream *s, unsigned char out[32]) {
    unsigned n = 0;
    return EVP_DigestFinal_ex(s->hash, out, &n) == 1 && n == 32;
}
static bool catalog_identity(YDDisk *disk, const YDDiskView *view, YDDiskTxn *txn,
    YDPolicyWork *work, unsigned char out[33], char *error, size_t length) {
    bool present = false;
    YDPolicyCatalog *catalog = NULL;
    YDPCInfo info;
    bool valid = (txn ? yd_policy_store_load(txn, work, &catalog, &present, error, length) :
        yd_policy_store_at(disk, view, work, &catalog, &present, error, length)) == YD_POLICY_OK &&
        yd_policy_catalog_info(catalog, &info) == YD_PC_OK;
    if (valid) { out[0] = present; memcpy(out + 1, info.catalog_sha256, 32); }
    yd_policy_catalog_free(catalog);
    return valid;
}
static bool frame(Stream *s, uint32_t kind, const void *name, size_t names,
    const void *id, size_t ids, const void *body, size_t size) {
    unsigned char header[FRAME] = {0};
    set32(header, kind);
    yd_disk_set16(header + 4, (uint16_t)names);
    yd_disk_set16(header + 6, (uint16_t)ids);
    yd_disk_set64(header + 8, size);
    return transfer(s, header, sizeof(header), true) &&
        transfer(s, (void *)name, names, true) && transfer(s, (void *)id, ids, true) &&
        transfer(s, (void *)body, size, true);
}
bool yd_disk_schema_logical_export(YDDisk *disk, const YDDiskView *view, int output,
    YDDiskValidation *state, char *error, size_t length) {
    struct stat file;
    if (!disk || !view || !profile(view) || !yd_policy_store_view_capable(disk, view) ||
        view->documents > YD_POLICY_SCAN_DOCUMENTS || view->bytes > YD_POLICY_SCAN_BYTES ||
        view->collections > YD_DISK_COLLECTION_LIMIT || !private_file(output, &file) || file.st_size)
        return yd_disk_error(error, length, "logical schema export profile or descriptor unsupported");
    YDPolicyWork work;
    yd_policy_work_init(&work, true);
    Stream stream = {.fd = output, .writing = true, .work = &work, .state = state,
        .hash = EVP_MD_CTX_new()};
    unsigned char header[HEADER] = {0};
    memcpy(header, "YDSREC01", 8);
    set32(header + 8, view->format);
    set32(header + 12, view->capabilities);
    yd_disk_set64(header + 16, view->collections);
    yd_disk_set64(header + 24, view->documents);
    yd_disk_set64(header + 32, view->bytes);
    yd_disk_set64(header + 40, view->revision);
    bool valid = stream.hash && EVP_DigestInit_ex(stream.hash, EVP_sha256(), NULL) == 1 &&
        yd_disk_validate_cancellable(disk, view, state, error, length) &&
        yd_policy_validate_view_cancellable(disk, view, &work, state, error, length) == YD_POLICY_OK &&
        catalog_identity(disk, view, NULL, &work, header + 48, error, length) &&
        transfer(&stream, header, sizeof(header), true);
    unsigned char key[YD_DISK_KEY_LIMIT];
    size_t kn = 0;
    uint64_t record = 0, collections = 0, documents = 0, bytes = 0, receipts = 0;
    YDDiskCursor *cursor = valid ? yd_disk_cursor(disk, view, NULL, 0, false, error, length) : NULL;
    if (valid && !cursor) valid = false;
    int next = 0;
    while (valid && (next = yd_disk_next(cursor, key, sizeof(key), &kn, &record, error, length)) == 1) {
        if (!yd_disk_validation_step(state, YD_VALIDATE_OPERATION) || !kn) { valid = false; break; }
        if (key[0] == 'C') {
            valid = kn > 1 && kn <= 129 && frame(&stream, 1, key + 1, kn - 1, NULL, 0, NULL, 0);
            collections++;
        } else if (key[0] == 'D') {
            YDDiskDocument doc = {0};
            valid = yd_disk_document_at(disk, view, record, &doc, error, length);
            if (valid) valid = frame(&stream, 2, doc.collection, strlen(doc.collection),
                doc.id, strlen(doc.id), doc.body, doc.length);
            if (valid) { documents++; bytes += doc.length; }
            yd_disk_document_free(&doc);
        } else if (kn == YD_POLICY_RECEIPT_KEY_SIZE && !memcmp(key, "\0YSP", 4)) {
            unsigned char body[YD_POLICY_RECEIPT_LIMIT], request[32];
            YDPolicyReply reply;
            size_t size = 0;
            valid = receipts++ < YD_SCHEMA_RECOVERY_RECEIPTS &&
                yd_disk_record_into(disk, view, record, body, sizeof(body), &size, error, length) &&
                yd_policy_receipt_decode(body, size, key + 4, request, &reply, error, length) == YD_POLICY_OK &&
                frame(&stream, 3, key, kn, NULL, 0, body, size);
        } else if (key[0] != 'I' && key[0] != 'U' &&
            !(kn == 4 && !memcmp(key, "\0YLM", 4)) &&
            !(kn == 12 && !memcmp(key, "\0YLF", 4))) valid = false;
    }
    yd_disk_cursor_free(cursor);
    unsigned char end[FRAME] = {0}, seal[32];
    valid = valid && next == 0 && collections == view->collections && documents == view->documents &&
        bytes == view->bytes && transfer(&stream, end, sizeof(end), true) &&
        digest(&stream, seal) && transfer(&stream, seal, sizeof(seal), false) && !fsync(output);
    EVP_MD_CTX_free(stream.hash);
    return valid || yd_disk_error(error, length, "logical schema export incomplete; preserve partial file");
}
static bool document(YDDiskTxn *txn, const char *collection, const char *id,
    unsigned char *body, size_t size, char *error, size_t length) {
    unsigned char key[YD_DISK_KEY_LIMIT];
    size_t kn = yd_disk_document_key(key, collection, id);
    uint64_t ignored = 0;
    if (!kn || yd_disk_tx_get(txn, key, kn, &ignored, error, length) != 0) return false;
    YDDiskDocument doc = {.body = body, .length = size};
    memcpy(doc.collection, collection, strlen(collection) + 1);
    memcpy(doc.id, id, strlen(id) + 1);
    return yd_disk_write_document(txn, NULL, &doc, error, length);
}
bool yd_disk_schema_logical_import(YDDiskTxn *txn, int input, YDPolicyWork *work,
    YDDiskValidation *state, char *error, size_t length) {
    struct stat before, after;
    if (!txn || !txn->exclusive || !txn->locked || txn->failed || !work ||
        !profile(&txn->view) || !yd_policy_store_view_capable(txn->disk, &txn->view) ||
        txn->view.root || txn->view.documents || txn->view.collections || txn->view.bytes ||
        !private_file(input, &before) || before.st_size < HEADER + FRAME + 32) {
        if (txn) txn->failed = true;
        return yd_disk_error(error, length, "logical schema restore requires empty compatible private staging");
    }
    Stream stream = {.fd = input, .work = work, .state = state, .hash = EVP_MD_CTX_new()};
    unsigned char header[HEADER], record[FRAME], actual[32], seal[32];
    bool valid = stream.hash && EVP_DigestInit_ex(stream.hash, EVP_sha256(), NULL) == 1 &&
        transfer(&stream, header, sizeof(header), true) && !memcmp(header, "YDSREC01", 8) &&
        u32(header + 8) == txn->view.format && u32(header + 12) == txn->view.capabilities &&
        yd_disk_u64(header + 16) <= YD_DISK_COLLECTION_LIMIT &&
        yd_disk_u64(header + 24) <= YD_POLICY_SCAN_DOCUMENTS &&
        yd_disk_u64(header + 32) <= YD_POLICY_SCAN_BYTES && header[48] <= 1 && zero(header + 81, 47);
    uint64_t collections = 0, documents = 0, bytes = 0, receipts = 0;
    bool ended = false;
    txn->log_enabled = txn->log_reset = true;
    while (valid) {
        if (!transfer(&stream, record, sizeof(record), true)) { valid = false; break; }
        uint32_t kind = u32(record);
        size_t cn = yd_disk_u16(record + 4), dn = yd_disk_u16(record + 6);
        uint64_t size = yd_disk_u64(record + 8);
        if (!kind) { valid = zero(record, sizeof(record)); ended = true; break; }
        if ((kind != 1 && kind != 2 && kind != 3) || cn > 128 || dn > 128 ||
            size > YD_DISK_DOCUMENT_LIMIT(txn->view.format) ||
            (kind == 1 && (!cn || dn || size)) ||
            (kind == 2 && (!cn || !dn || !size || documents >= yd_disk_u64(header + 24) ||
                size > yd_disk_u64(header + 32) - bytes)) ||
            (kind == 3 && (cn != YD_POLICY_RECEIPT_KEY_SIZE || dn || size > YD_POLICY_RECEIPT_LIMIT || !size))) {
            valid = false; break;
        }
        char collection[129] = {0}, id[129] = {0};
        valid = transfer(&stream, collection, cn, true) && transfer(&stream, id, dn, true);
        unsigned char *body = valid && size ? malloc((size_t)size) : NULL;
        valid = valid && (!size || body) && transfer(&stream, body, (size_t)size, true);
        if (valid && kind != 3)
            valid = !memchr(collection, 0, cn) && yamldb_valid_name(collection) &&
                (!dn || (!memchr(id, 0, dn) && yamldb_valid_name(id)));
        if (valid && kind == 1) {
            unsigned char key[YD_DISK_KEY_LIMIT];
            uint64_t ignored = 0;
            size_t kn = yd_disk_collection_key(key, collection);
            valid = collections < yd_disk_u64(header + 16) &&
                yd_disk_tx_get(txn, key, kn, &ignored, error, length) == 0 &&
                yd_disk_create_collection(txn, collection, error, length);
            if (valid) collections++;
        } else if (valid && kind == 2) {
            valid = document(txn, collection, id, body, (size_t)size, error, length);
            if (valid) { documents++; bytes += size; }
        } else if (valid && kind == 3) {
            YDPolicyReply reply;
            unsigned char request[32];
            uint64_t offset = 0;
            valid = receipts++ < YD_SCHEMA_RECOVERY_RECEIPTS && !memcmp(collection, "\0YSP", 4) &&
                yd_policy_receipt_decode(body, (size_t)size, (unsigned char *)collection + 4,
                    request, &reply, error, length) == YD_POLICY_OK &&
                yd_disk_tx_get(txn, collection, cn, &offset, error, length) == 0 &&
                yd_disk_append(txn, body, (size_t)size, &offset, error, length) &&
                yd_disk_put(txn, collection, cn, offset, error, length);
        }
        free(body);
    }
    valid = valid && ended && digest(&stream, actual) && transfer(&stream, seal, sizeof(seal), false) &&
        !memcmp(actual, seal, sizeof(actual)) && stream.at == (uint64_t)before.st_size &&
        private_file(input, &after) && stable(&before, &after) &&
        collections == yd_disk_u64(header + 16) && documents == yd_disk_u64(header + 24) &&
        bytes == yd_disk_u64(header + 32) && txn->view.collections == collections &&
        txn->view.documents == documents && txn->view.bytes == bytes &&
        txn->view.revision == yd_disk_u64(header + 40);
    unsigned char identity[33];
    if (valid) valid = catalog_identity(txn->disk, &txn->view, txn, work, identity, error, length) &&
        !memcmp(identity, header + 48, sizeof(identity));
    if (valid) valid = yd_policy_admission_validate_root_cancellable(txn, work, state,
        error, length) == YD_POLICY_OK && yd_disk_rebuild_indexes(txn, error, length);
    EVP_MD_CTX_free(stream.hash);
    if (!valid) txn->failed = true;
    return valid || yd_disk_error(error, length, "logical schema restore rejected; abort private root");
}
static int prepare(int destination, char *error, size_t length) {
    int root = openat(destination, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat st;
    bool valid = root >= 0 && !fstat(root, &st) && st.st_uid == geteuid() &&
        (st.st_mode & 07777) == 0700 && !flock(root, LOCK_EX | LOCK_NB);
    int copy = valid ? openat(root, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC) : -1;
    DIR *dir = copy >= 0 ? fdopendir(copy) : NULL;
    valid = valid && dir;
    while (valid) {
        errno = 0;
        struct dirent *entry = readdir(dir);
        if (!entry) { valid = !errno; break; }
        if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) valid = false;
    }
    if (dir) closedir(dir); else if (copy >= 0) close(copy);
    int marker = valid ? openat(root, YD_BINARY_INITIALIZING,
        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600) : -1;
    valid = valid && marker >= 0 && !fsync(marker) && !fsync(root);
    if (marker >= 0) close(marker);
    if (!valid) { if (root >= 0) close(root); yd_disk_error(error, length, "schema restore destination must be empty private owned directory"); return -1; }
    return root;
}
bool yd_disk_schema_recovery_restore_at(int destination, int input, uint32_t required,
    size_t cache, char *error, size_t length) {
    return yd_disk_schema_recovery_restore_budgeted_at(destination, input, required, cache,
        NULL, error, length);
}
bool yd_disk_schema_recovery_restore_budgeted_at(int destination, int input, uint32_t required,
    size_t cache, YDStorageBudget *resources, char *error, size_t length) {
    struct stat input_stat;
    if ((resources && !yd_storage_budget_process_valid(resources)) ||
        (required && required != YD_DISK_CAP_SCHEMA) || !private_file(input, &input_stat))
        return yd_disk_error(error, length, "schema restore input, resource owner or capability unsupported");
    int prior;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &prior)) return false;
    int root = prepare(destination, error, length);
    YDDisk *disk = root < 0 ? NULL : required ?
        yd_disk_create_capabilities_staging_budgeted_at(root, required, cache,
            YD_SCHEMA_RECOVERY_ALLOCATION, resources, error, length) :
        yd_disk_create_schema_staging_budgeted_at_limited(root, cache,
            YD_SCHEMA_RECOVERY_ALLOCATION, resources, error, length);
    YDDiskTxn *txn = disk ? yd_disk_begin_exclusive(disk, error, length) : NULL;
    YDPolicyWork work;
    yd_policy_work_init(&work, true);
    bool valid = txn && yd_disk_schema_logical_import(txn, input, &work, NULL, error, length);
    if (valid) { valid = yd_disk_commit(txn, error, length); txn = NULL; }
    yd_disk_abort(txn);
    if (valid) {
        YDDiskView view = yd_disk_view(disk);
        valid = yd_disk_validate(disk, &view, error, length) &&
            !unlinkat(root, YD_BINARY_INITIALIZING, 0) && !fsync(root);
    }
    yd_disk_close(disk);
    if (root >= 0) close(root);
    (void)pthread_setcancelstate(prior, NULL);
    return valid;
}
