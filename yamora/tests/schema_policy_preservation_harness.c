#define _POSIX_C_SOURCE 200809L
#include "../src/disk_bulk.h"
#include "../src/disk_index_build.h"
#include "../src/disk_internal.h"
#include "../src/disk_replica.h"
#include "../src/schema/policy_admission.h"
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
static const unsigned char shape[] = "# exact policy\r\ntype: object\r\nproperties:\r\n  n: {type: integer}\r\nrequired: [n]\r\nadditionalProperties: false\r\n";
static const unsigned char good[] = "# exact data\r\nn: 7 # keep\r\n";
static const unsigned char bad[] = "# historical exact\r\nn: false\r\n";
static bool expect(bool valid, const char *witness) {
    if (!valid) fprintf(stderr, "FAIL: %s: %s\n", witness, error);
    return valid;
}
static bool directory(const char *path) { return mkdir(path, 0700) == 0; }
static bool file(const char *path, const void *bytes, size_t size) {
    FILE *out = fopen(path, "wb");
    if (!out) return false;
    bool valid = fwrite(bytes, 1, size, out) == size;
    return fclose(out) == 0 && valid;
}
/* Force the actual importer to encounter the catalog LAST, independently of
 * directory enumeration order. Only the selected source directory is affected. */
static dev_t source_device;
static ino_t source_inode;
static struct dirent saved;
static bool saved_pending;
static unsigned late_catalogs;
static const char *custody_path;
static bool custody_lost;
struct dirent *__real_readdir(DIR *dir);
struct dirent *__wrap_readdir(DIR *dir) {
    struct stat st;
    if (!source_inode || fstat(dirfd(dir), &st) || st.st_dev != source_device || st.st_ino != source_inode)
        return __real_readdir(dir);
    if (custody_path) {
        int saved_errno = errno;
        int probe = open(custody_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (probe < 0 || !flock(probe, LOCK_SH | LOCK_NB)) custody_lost = true;
        if (probe >= 0) close(probe);
        errno = saved_errno;
    }
    for (;;) {
        struct dirent *entry = __real_readdir(dir);
        if (!entry) {
            if (saved_pending) { saved_pending = false; late_catalogs++; return &saved; }
            return NULL;
        }
        if (!strcmp(entry->d_name, "yamldb-system")) {
            memset(&saved, 0, sizeof(saved));
            memcpy(saved.d_name, entry->d_name, strlen(entry->d_name) + 1); saved_pending = true;
        } else return entry;
    }
}
static YDDisk *open_schema(const char *path, bool writable) {
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    YDDisk *disk = fd < 0 ? NULL : yd_disk_open_schema_at(fd, writable, 32768,
        YD_DISK_ALLOCATION_UNLIMITED, error, sizeof(error));
    if (fd >= 0) close(fd);
    return disk;
}
static bool source_document(YDDiskTxn *txn, const char *collection, const char *id,
                               const unsigned char *bytes, size_t size) {
    YDDiskDocument old = {0}, fresh = {.body = (unsigned char *)bytes, .length = size};
    memcpy(fresh.collection, collection, strlen(collection) + 1);
    memcpy(fresh.id, id, strlen(id) + 1);
    int found = yd_disk_document_tx_get(txn, collection, id, &old, error, sizeof(error));
    bool valid = found >= 0 && yd_disk_write_document(txn, found ? &old : NULL, &fresh, error, sizeof(error));
    yd_disk_document_free(&old);
    return valid;
}
static bool put(YDDisk *disk, const char *id, const unsigned char *bytes, size_t size) {
    YDWrite write = {.collection = "items", .document = id, .body = bytes, .length = size};
    YDDiskTxn *txn = yd_disk_begin(disk, error, sizeof(error));
    bool valid = txn && yd_disk_apply(txn, &write, 1, error, sizeof(error));
    if (valid) return yd_disk_commit(txn, error, sizeof(error));
    yd_disk_abort(txn); return false;
}
static bool catalog_bytes(unsigned char **bytes, size_t *size) {
    *bytes = NULL; *size = 0;
    YDPolicyWork work; yd_policy_work_init(&work, true);
    YDPolicyCatalog *empty = NULL, *catalog = NULL;
    YDPCInfo info;
    bool valid = yd_policy_catalog_empty(YD_PC_LARGE, &work.catalog, &empty, NULL) == YD_PC_OK &&
                 yd_policy_catalog_info(empty, &info) == YD_PC_OK;
    YDPCChange change = {.collection = "items", .collection_length = 5,
        .operation = YD_PC_SET, .source = shape, .source_length = sizeof(shape) - 1};
    if (valid) {
        change.expected.generation = info.generation;
        memcpy(change.expected.catalog_sha256, info.catalog_sha256, 32);
        valid = yd_policy_catalog_change(empty, &change, YD_PC_LARGE, &work.catalog, &catalog, NULL) == YD_PC_OK &&
                yd_policy_catalog_info(catalog, &info) == YD_PC_OK;
    }
    if (valid) { *bytes = malloc(info.encoded_bytes); valid = *bytes != NULL; }
    if (valid) valid = yd_policy_catalog_encode(catalog, YD_PC_LARGE, &work.catalog, *bytes,
        info.encoded_bytes, size, NULL) == YD_PC_OK;
    yd_policy_catalog_free(empty); yd_policy_catalog_free(catalog);
    if (!valid) { free(*bytes); *bytes = NULL; }
    return valid;
}
static bool policy(YDDisk *disk, unsigned number) {
    YDPolicyWork work; yd_policy_work_init(&work, true);
    YDDiskTxn *txn = yd_disk_begin_exclusive(disk, error, sizeof(error));
    YDPolicyCatalog *base = NULL, *updated = NULL;
    bool present = false;
    YDPCInfo info;
    YDPCEntry entry;
    bool valid = txn && yd_policy_store_load(txn, &work, &base, &present, error, sizeof(error)) == YD_POLICY_OK &&
                 yd_policy_catalog_info(base, &info) == YD_PC_OK;
    YDPCChange change = {.collection = "items", .collection_length = 5, .operation = YD_PC_SET,
        .source = shape, .source_length = sizeof(shape) - 1};
    if (valid) {
        change.expected.generation = info.generation;
        memcpy(change.expected.catalog_sha256, info.catalog_sha256, 32);
        if (yd_policy_catalog_find(base, "items", 5, &entry) == YD_PC_OK) change.expected.version = entry.version;
        valid = yd_policy_store_change(txn, &change, &work, &updated, error, sizeof(error)) == YD_POLICY_OK;
    }
    YDPolicyReply reply = {.status = 200, .content_type = "application/json"};
    const unsigned char body[] = {'{', '}', '\n', 0, '\r'};
    memcpy(reply.body, body, sizeof(body)); reply.length = sizeof(body);
    unsigned char id[16] = {0}, digest[32]; id[15] = (unsigned char)number;
    YDPolicyRequest request = {.method = "PUT", .target = "/v1/schema-policies/items",
        .body = shape, .length = sizeof(shape) - 1};
    if (valid) {
        yd_disk_revision(yd_disk_tx_view(txn), reply.revision);
        valid = yd_policy_request_digest(&request, digest, error, sizeof(error)) == YD_POLICY_OK;
    }
    yd_policy_catalog_free(base); yd_policy_catalog_free(updated);
    if (valid) return yd_policy_store_commit(txn, id, digest, &reply, error, sizeof(error)) == YD_POLICY_OK;
    yd_disk_abort(txn); return false;
}
static bool exact_document(YDDisk *disk, const YDDiskView *view, const char *collection,
                              const char *id, const unsigned char *bytes, size_t size) {
    YDDiskDocument document = {0};
    bool valid = yd_disk_document_get(disk, view, collection, id, &document, error, sizeof(error)) == 1 &&
                 document.length == size && !memcmp(document.body, bytes, size);
    yd_disk_document_free(&document); return valid;
}
static bool receipt(YDDisk *disk, const YDDiskView *view, unsigned number,
                       unsigned char bytes[YD_POLICY_RECEIPT_LIMIT], size_t *size) {
    unsigned char id[16] = {0}, key[20]; id[15] = (unsigned char)number;
    uint64_t offset = 0;
    return yd_policy_receipt_key(id, key) && yd_disk_get(disk, view, key, sizeof(key), &offset, error, sizeof(error)) == 1 &&
           yd_disk_record_into(disk, view, offset, bytes, YD_POLICY_RECEIPT_LIMIT, size, error, sizeof(error));
}
static bool import_case(const char *root, bool invalid, bool ordinary) {
    char source[4096], target[4096], path[4096];
    snprintf(source, sizeof(source), "%s/source", root); snprintf(target, sizeof(target), "%s/target", root);
    if (!directory(source) || !directory(target)) return false;
    snprintf(path, sizeof(path), "%s/source/items", root); if (!directory(path)) return false;
    snprintf(path, sizeof(path), "%s/source/items/a.yaml", root);
    if (!file(path, invalid ? bad : good, invalid ? sizeof(bad) - 1 : sizeof(good) - 1)) return false;
    snprintf(path, sizeof(path), "%s/source/yamldb-system", root); if (!directory(path)) return false;
    unsigned char *catalog = NULL; size_t size = 0;
    bool valid = catalog_bytes(&catalog, &size);
    snprintf(path, sizeof(path), "%s/source/yamldb-system/schema-policies.yaml", root);
    valid = valid && file(path, catalog, size);
    struct stat st;
    valid = valid && stat(source, &st) == 0;
    if (valid) { source_device = st.st_dev; source_inode = st.st_ino; custody_path = target; }
    bool imported = valid && (ordinary ? yd_disk_initialize(target, source, 32768, error, sizeof(error)) :
        yd_disk_initialize_schema(target, source, 32768, error, sizeof(error)));
    source_inode = 0;
    custody_path = NULL;
    valid = valid && expect(!custody_lost, "bulk schema staging retains exclusive directory custody");
    valid = valid && expect(late_catalogs != 0, "actual import catalog enumerated last");
    bool refused = invalid || ordinary;
    valid = valid && expect(imported != refused, "complete late-catalog import admission");
    snprintf(path, sizeof(path), "%s/target/%s", root, YD_BINARY_INITIALIZING);
    valid = valid && expect((access(path, F_OK) == 0) == refused, "import sentinel publication boundary");
    YDDisk *disk = ordinary ? yd_disk_open(target, false, 32768, error, sizeof(error)) : open_schema(target, false);
    YDDiskView view = disk ? yd_disk_view(disk) : (YDDiskView){0};
    valid = valid && expect(refused ? (ordinary ? disk && !view.documents : !disk) : disk && (view.documents == 2 && exact_document(disk, &view, "items", "a", good, sizeof(good) - 1) &&
        exact_document(disk, &view, "yamldb-system", "schema-policies", catalog, size)), "import no partial published root");
    yd_disk_close(disk); free(catalog); return valid;
}
static bool compact_case(const char *root) {
    char source[4096], target[4096]; snprintf(source, sizeof(source), "%s/source", root);
    snprintf(target, sizeof(target), "%s/target", root);
    if (!directory(source) || !directory(target)) return false;
    YDDisk *disk = open_schema(source, true);
    bool valid = disk && put(disk, "a", bad, sizeof(bad) - 1);
    YDDisk *pin = valid ? yd_disk_pin(disk, 32768, error, sizeof(error)) : NULL;
    YDDiskView pinned = pin ? yd_disk_view(pin) : (YDDiskView){0};
    valid = valid && put(disk, "a", good, sizeof(good) - 1) && policy(disk, 1);
    /* Trusted maintenance deliberately supplies a historical value that today's
     * policy rejects. Copy/validation must preserve it, not re-admit it. */
    YDDiskTxn *txn = valid ? yd_disk_begin_exclusive(disk, error, sizeof(error)) : NULL;
    valid = valid && txn && source_document(txn, "items", "a", bad, sizeof(bad) - 1);
    if (valid) valid = yd_disk_commit(txn, error, sizeof(error)); else yd_disk_abort(txn);
    YDDiskView before = disk ? yd_disk_view(disk) : (YDDiskView){0};
    unsigned char a[YD_POLICY_RECEIPT_LIMIT], b[YD_POLICY_RECEIPT_LIMIT]; size_t an = 0, bn = 0;
    valid = valid && receipt(disk, &before, 1, a, &an) &&
            expect(yd_disk_compact(disk, target, 32768, error, sizeof(error)), "trusted compaction does not re-admit history");
    YDDisk *copy = valid ? open_schema(target, false) : NULL;
    YDDiskView after = copy ? yd_disk_view(copy) : (YDDiskView){0};
    valid = valid && expect(copy && after.format == 7 && after.revision == before.revision &&
        yd_disk_validate(copy, &after, error, sizeof(error)) &&
        receipt(copy, &after, 1, b, &bn) && an == bn && !memcmp(a, b, an), "compaction exact raw receipt and profile");
    YDDiskDocument catalog = {0};
    valid = valid && yd_disk_document_get(disk, &before, "yamldb-system", "schema-policies", &catalog, error, sizeof(error)) == 1 &&
        exact_document(copy, &after, "yamldb-system", "schema-policies", catalog.body, catalog.length) &&
        exact_document(copy, &after, "items", "a", bad, sizeof(bad) - 1) &&
        pin && exact_document(pin, &pinned, "items", "a", bad, sizeof(bad) - 1);
    yd_disk_document_free(&catalog); yd_disk_close(copy); yd_disk_close(pin); yd_disk_close(disk);
    copy = valid ? open_schema(target, false) : NULL;
    after = copy ? yd_disk_view(copy) : (YDDiskView){0};
    valid = valid && expect(copy && receipt(copy, &after, 1, b, &bn) && an == bn && !memcmp(a, b, an), "compacted receipt restart");
    yd_disk_close(copy); return valid;
}
typedef struct { YDDisk *disk; unsigned changes, resets; bool failed, churn, late; } Build;
static bool progress(void *context, const char *phase) {
    Build *state = context;
    bool inject = (!strcmp(phase, "scan") && (!state->changes || state->churn)) ||
                  (!strcmp(phase, "publish") && state->late && state->changes == 1);
    if (!strcmp(phase, "resnapshot")) state->resets++;
    if (inject) {
        state->changes++;
        if (!policy(state->disk, state->changes)) { state->failed = true; return false; }
    }
    return true;
}
static bool index_case(const char *root, bool churn, bool late) {
    char source[4096]; snprintf(source, sizeof(source), "%s/source", root);
    if (!directory(source)) return false;
    YDDisk *disk = open_schema(source, true);
    bool valid = disk && put(disk, "a", good, sizeof(good) - 1);
    Build state = {.disk = disk, .churn = churn, .late = late};
    const unsigned char indexes[] = "{indexes: [{collection: items, name: n, fields: [n]}]}";
    YDDiskView receipt_view;
    bool built = valid && yd_disk_indexes_online(disk, indexes, sizeof(indexes) - 1, progress, &state,
        &receipt_view, error, sizeof(error));
    valid = valid && expect(!state.failed && (churn ? !built && state.resets == 4 : built && state.resets == (late ? 2U : 1U)),
        "index policy publication resnapshots boundedly");
    YDDiskView current = disk ? yd_disk_view(disk) : (YDDiskView){0};
    for (unsigned i = 1; valid && i <= state.changes; i++) {
        unsigned char bytes[YD_POLICY_RECEIPT_LIMIT]; size_t size = 0;
        valid = expect(receipt(disk, &current, i, bytes, &size), "index publication preserves all receipts");
    }
    YDPolicyWork work; yd_policy_work_init(&work, true); YDPolicyCatalog *catalog = NULL; bool present = false;
    YDPCEntry entry;
    valid = valid && yd_policy_store_at(disk, &current, &work, &catalog, &present, error, sizeof(error)) == YD_POLICY_OK &&
        present && yd_policy_catalog_find(catalog, "items", 5, &entry) == YD_PC_OK && entry.version == state.changes &&
        yd_disk_validate(disk, &current, error, sizeof(error));
    YDDiskIndexes *visible = valid ? yd_disk_indexes_load(disk, &current, error, sizeof(error)) : NULL;
    valid = valid && expect(visible && visible->count == (churn ? 0U : 1U), "index private failure does not publish");
    yd_disk_indexes_free(visible); yd_policy_catalog_free(catalog); yd_disk_close(disk); return valid;
}
static bool replica_case(const char *root, bool raw_only) {
    char path[4096]; snprintf(path, sizeof(path), "%s/source", root); if (!directory(path)) return false;
    YDDisk *disk = open_schema(path, true);
    YDDiskView before = disk ? yd_disk_view(disk) : (YDDiskView){0};
    bool valid = disk && expect(yd_disk_replica_policy_free(disk, &before, error, sizeof(error)), "policy-free profile7 replication control");
    YDDiskTxn *txn = valid ? yd_disk_begin_staging(disk, error, sizeof(error)) : NULL;
    valid = valid && txn && expect(yd_disk_replica_policy_free_tx(txn, error, sizeof(error)), "policy-free staged replica control");
    if (valid && raw_only) {
        unsigned char key[20] = {0, 'Y', 'S', 'P'}; key[19] = 1;
        uint64_t record = 0;
        valid = yd_disk_append(txn, "invalid", 7, &record, error, sizeof(error)) && yd_disk_put(txn, key, sizeof(key), record, error, sizeof(error));
    } else if (valid) {
        unsigned char *bytes = NULL; size_t size = 0;
        valid = catalog_bytes(&bytes, &size) && source_document(txn, "yamldb-system", "schema-policies", bytes, size); free(bytes);
    }
    valid = valid && expect(!yd_disk_replica_policy_free_tx(txn, error, sizeof(error)), "private policy-bearing replica guard");
    if (valid) valid = yd_disk_commit(txn, error, sizeof(error)); else yd_disk_abort(txn);
    before = disk ? yd_disk_view(disk) : (YDDiskView){0};
    valid = valid && expect(!yd_disk_replica_policy_free(disk, &before, error, sizeof(error)), "outgoing policy-bearing replica guard");
    YDDiskAPI api;
    bool initialized = valid && yd_disk_api_init(&api, disk, true);
    if (initialized) {
        const unsigned char begin[] = "{after: 'v1.00112233445566778899aabbccddeeff.0000000000000001', token: 'v1.00112233445566778899aabbccddeeff.0000000000000002', previous_revision: '0000000000000000', revision: '0000000000000000', operations: 0}";
        YDDiskReply reply = yd_disk_api_request(&api, "POST", "/v1/replication/follow/begin", begin, sizeof(begin) - 1, NULL, NULL, false);
        valid = expect(reply.status == 409 && strstr(reply.body, "schema_policy_replication_unsupported") && !api.stage, "follow refuses before stage");
        yd_disk_reply_free(&reply); yd_disk_api_destroy(&api);
    } else valid = false;
    YDDiskView after = disk ? yd_disk_view(disk) : (YDDiskView){0};
    valid = valid && expect(before.root == after.root && before.generation == after.generation, "replica refusal atomic root");
    yd_disk_close(disk); return valid;
}
static bool budget_case(const char *root, unsigned pool) {
    char path[4096]; snprintf(path, sizeof(path), "%s/source", root); if (!directory(path)) return false;
    YDDisk *disk = open_schema(path, true);
    YDDiskTxn *txn = disk ? yd_disk_begin_staging(disk, error, sizeof(error)) : NULL;
    unsigned char *catalog = NULL; size_t size = 0;
    bool valid = txn && catalog_bytes(&catalog, &size) &&
        source_document(txn, "items", "a", good, sizeof(good) - 1) &&
        source_document(txn, "items", "b", good, sizeof(good) - 1) &&
        source_document(txn, "yamldb-system", "schema-policies", catalog, size);
    free(catalog);
    YDPolicyWork work; yd_policy_work_init(&work, true);
    if (pool == 0) work.documents_left = 1;
    if (pool == 1) work.source_bytes_left = 2 * (sizeof(good) - 1) - 1;
    if (pool == 2) {
        YDSchema *program = NULL; YDSchemaBudget shape_work = {.remaining = 10000000};
        YDValue *value = yd_parse(good, sizeof(good) - 1, error, sizeof(error));
        valid = valid && value && yd_schema_compile(shape, sizeof(shape) - 1, &program, NULL) == YD_SCHEMA_OK &&
            yd_schema_check(program, value, &shape_work, NULL) == YD_SCHEMA_OK;
        work.shape.remaining = 10000000 - shape_work.remaining;
        yd_schema_free(program); yd_free(value);
    }
    valid = valid && expect(yd_policy_admission_validate_root(txn, &work, error, sizeof(error)) == YD_POLICY_LIMIT,
        "complete import shared budget rejects before publication");
    yd_disk_abort(txn);
    YDDiskView view = disk ? yd_disk_view(disk) : (YDDiskView){0};
    valid = valid && expect(view.documents == 0 && view.revision == 0 && view.root == 0,
        "import budget rejection preserves public root");
    yd_disk_close(disk); return valid;
}
static bool corrupt_receipt_case(const char *root) {
    char source[4096], target[4096]; snprintf(source, sizeof(source), "%s/source", root);
    snprintf(target, sizeof(target), "%s/target", root);
    if (!directory(source) || !directory(target)) return false;
    YDDisk *disk = open_schema(source, true);
    bool valid = disk && put(disk, "a", good, sizeof(good) - 1) && policy(disk, 1);
    YDDiskTxn *txn = valid ? yd_disk_begin_exclusive(disk, error, sizeof(error)) : NULL;
    unsigned char key[20] = {0, 'Y', 'S', 'P'}; key[19] = 1;
    uint64_t offset = 0;
    valid = valid && txn && yd_disk_append(txn, "broken receipt", 14, &offset, error, sizeof(error)) &&
        yd_disk_put(txn, key, sizeof(key), offset, error, sizeof(error));
    if (valid) valid = yd_disk_commit(txn, error, sizeof(error)); else yd_disk_abort(txn);
    YDDiskView before = disk ? yd_disk_view(disk) : (YDDiskView){0};
    valid = valid && expect(!yd_disk_validate(disk, &before, error, sizeof(error)), "raw receipt structural validation");
    valid = valid && expect(!yd_disk_compact(disk, target, 32768, error, sizeof(error)), "corrupt receipt copy refuses");
    YDDiskView after = disk ? yd_disk_view(disk) : (YDDiskView){0};
    valid = valid && expect(after.root == before.root && after.generation == before.generation,
        "corrupt receipt failure preserves source");
    yd_disk_close(disk); return valid;
}
static bool cancel_copy(void *context, YDDiskValidationPhase phase) {
    (void)phase;
    unsigned *calls = context; (*calls)++; return false;
}
static bool cancel_case(const char *root) {
    char source[4096]; snprintf(source, sizeof(source), "%s/source", root);
    if (!directory(source)) return false;
    YDDisk *disk = open_schema(source, true);
    bool valid = disk && put(disk, "a", good, sizeof(good) - 1) && policy(disk, 1);
    YDDiskView before = disk ? yd_disk_view(disk) : (YDDiskView){0};
    YDDiskTxn *txn = valid ? yd_disk_begin_staging(disk, error, sizeof(error)) : NULL;
    unsigned calls = 0;
    YDDiskValidation validation = {.progress = cancel_copy, .context = &calls};
    valid = valid && txn && expect(!yd_disk_policy_receipts_copy(disk, &before, txn, &validation,
        error, sizeof(error)) && validation.cancelled && calls == 1, "receipt copy cancellation before work");
    yd_disk_abort(txn);
    YDDiskView after = disk ? yd_disk_view(disk) : (YDDiskView){0};
    unsigned char bytes[YD_POLICY_RECEIPT_LIMIT]; size_t size = 0;
    valid = valid && expect(after.root == before.root && after.generation == before.generation &&
        receipt(disk, &after, 1, bytes, &size), "cancelled receipt copy preserves publication");
    yd_disk_close(disk); return valid;
}
int main(int argc, char **argv) {
    if (argc != 3 || pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL)) return 2;
    bool valid = false;
    if (!strcmp(argv[2], "import-valid")) valid = import_case(argv[1], false, false);
    else if (!strcmp(argv[2], "import-invalid")) valid = import_case(argv[1], true, false);
    else if (!strcmp(argv[2], "import-ordinary")) valid = import_case(argv[1], false, true);
    else if (!strcmp(argv[2], "compact")) valid = compact_case(argv[1]);
    else if (!strcmp(argv[2], "index")) valid = index_case(argv[1], false, false);
    else if (!strcmp(argv[2], "index-late")) valid = index_case(argv[1], false, true);
    else if (!strcmp(argv[2], "index-churn")) valid = index_case(argv[1], true, false);
    else if (!strcmp(argv[2], "replica-catalog")) valid = replica_case(argv[1], false);
    else if (!strcmp(argv[2], "replica-receipt")) valid = replica_case(argv[1], true);
    else if (!strcmp(argv[2], "budget-documents")) valid = budget_case(argv[1], 0);
    else if (!strcmp(argv[2], "budget-source")) valid = budget_case(argv[1], 1);
    else if (!strcmp(argv[2], "budget-shape")) valid = budget_case(argv[1], 2);
    else if (!strcmp(argv[2], "corrupt-receipt")) valid = corrupt_receipt_case(argv[1]);
    else if (!strcmp(argv[2], "cancel-copy")) valid = cancel_case(argv[1]);
    else if (!strcmp(argv[2], "emit-catalog")) {
        unsigned char *bytes = NULL; size_t size = 0;
        valid = catalog_bytes(&bytes, &size) && file(argv[1], bytes, size); free(bytes);
    }
    if (!valid) { fprintf(stderr, "FAIL: preservation %s: %s\n", argv[2], error); return 11; }
    printf("PASS: preservation %s\n", argv[2]); return 0;
}
