#define YD_POLICY_HARNESS_LIBRARY
#include "schema_policy_store_harness.c"

unsigned policy_decode_calls;
bool policy_track_reads;
size_t policy_read_bytes;
ssize_t __real_pread(int, void *, size_t, off_t);
ssize_t __wrap_pread(int fd, void *buffer, size_t size, off_t offset) {
    ssize_t read = __real_pread(fd, buffer, size, offset);
    if (policy_track_reads && read > 0) policy_read_bytes += (size_t)read;
    return read;
}
bool __real_yd_binary_unpack_profile(const unsigned char *, size_t, bool,
                                    unsigned char **, size_t *, YDValue **);
bool __wrap_yd_binary_unpack_profile(const unsigned char *packed, size_t size, bool large,
    unsigned char **body, size_t *length, YDValue **value) {
    policy_decode_calls++;
    return __real_yd_binary_unpack_profile(packed, size, large, body, length, value);
}

const char *policy_object =
    "type: object\nproperties:\n  title: {type: string}\n"
    "  chapters:\n    type: array\n    items:\n      type: object\n"
    "      properties: {page: {type: integer}}\n      required: [page]\n"
    "      additionalProperties: false\nrequired: [title]\nadditionalProperties: false\n";
const char *policy_valid = "{title: valid, chapters: [{page: 1}]}\n";

YDPolicyResult policy_apply(YDDiskTxn *txn, const char *id, const char *source, YDPolicyWork *work) {
    YDWrite write = {.kind = YD_WRITE_DOCUMENT, .collection = "books", .document = id,
                    .body = (const unsigned char *)source, .length = source ? strlen(source) : 0};
    return yd_disk_apply_with_policy(txn, &write, 1, work, policy_error, sizeof(policy_error));
}
void policy_write(YDDisk *disk, const char *id, const char *source) {
    YDPolicyWork work;
    yd_policy_work_init(&work, false);
    YDDiskTxn *txn = yd_disk_begin(disk, policy_error, sizeof(policy_error));
    REQUIRE(txn != NULL, "WRITE_BEGIN");
    REQUIRE(policy_apply(txn, id, source, &work) == YD_POLICY_OK, "VALID_DOCUMENT_ADMITTED");
    REQUIRE(yd_disk_commit(txn, policy_error, sizeof(policy_error)), "DOCUMENT_COMMIT");
}
void policy_raw(YDDiskTxn *txn, const char *collection, const char *id, const char *source) {
    YDDiskDocument document = {.body = (unsigned char *)source, .length = strlen(source)};
    memcpy(document.collection, collection, strlen(collection) + 1);
    memcpy(document.id, id, strlen(id) + 1);
    REQUIRE(yd_disk_write_document(txn, NULL, &document, policy_error,
                                   sizeof(policy_error)), "TRUSTED_STRUCTURAL_WRITE");
}
int main(int argc, char **argv) {
    if (argc != 3) return 3;
    const char *scenario = argv[2];
    YDDisk *disk = policy_open(argv[1], true);
    if (!strcmp(scenario, "admission")) {
        policy_publish(disk, policy_object, 1);
        policy_write(disk, "existing", policy_valid);
        const char *indexes = "{indexes: [{collection: books, name: title, fields: [title], unique: true}]}";
        YDDiskTxn *txn = yd_disk_begin_exclusive(disk, policy_error, sizeof(policy_error));
        REQUIRE(txn && yd_disk_indexes_replace(txn, (const unsigned char *)indexes,
            strlen(indexes), policy_error, sizeof(policy_error)), "INDEX_INSTALL");
        REQUIRE(yd_disk_commit(txn, policy_error, sizeof(policy_error)), "INDEX_COMMIT");
        const char *invalid[] = {"{chapters: []}\n", "{title: 1}\n",
            "{title: valid, chapters: [{page: 1, extra: true}]}\n"};
        const char *labels[] = {"SCHEMA_ADMISSION_REQUIRED", "SCHEMA_ADMISSION_TYPE",
                                "SCHEMA_ADMISSION_NESTED_ADDITIONAL"};
        for (size_t i = 0; i < 3; i++) {
            YDDiskView before = yd_disk_view(disk);
            YDPolicyWork work;
            yd_policy_work_init(&work, false);
            txn = yd_disk_begin(disk, policy_error, sizeof(policy_error));
            REQUIRE(txn != NULL, "REJECT_BEGIN");
            REQUIRE(policy_apply(txn, "existing", invalid[i], &work) == YD_POLICY_REJECTED, labels[i]);
            REQUIRE(txn->view.root == before.root && txn->view.revision == before.revision &&
                txn->view.documents == before.documents && txn->view.bytes == before.bytes &&
                txn->log_count == 0, "ADMISSION_PRECEDES_INDEX_REMOVAL");
            yd_disk_abort(txn);
            REQUIRE(policy_same_view(before, yd_disk_view(disk)), "REJECT_PRESERVES_PUBLICATION");
        }
        policy_write(disk, "existing", NULL);
    } else if (!strcmp(scenario, "shared")) {
        policy_publish(disk, "type: integer\n", 1);
        YDDiskView before = yd_disk_view(disk);
        YDPolicyWork work;
        yd_policy_work_init(&work, false);
        work.shape.remaining = 1;
        YDDiskTxn *txn = yd_disk_begin(disk, policy_error, sizeof(policy_error));
        REQUIRE(txn != NULL, "SHARED_BEGIN");
        REQUIRE(policy_apply(txn, "one", "1\n", &work) == YD_POLICY_OK, "INDIVIDUAL_BUDGET_FITS");
        REQUIRE(policy_apply(txn, "two", "2\n", &work) == YD_POLICY_LIMIT, "SHARED_BUDGET_NOT_REFILLED");
        yd_disk_abort(txn);
        REQUIRE(policy_same_view(before, yd_disk_view(disk)), "SHARED_REJECT_ATOMIC");
        txn = yd_disk_begin(disk, policy_error, sizeof(policy_error));
        REQUIRE(txn != NULL, "RETRY_BEGIN");
        REQUIRE(policy_apply(txn, "one", "1\n", &work) == YD_POLICY_LIMIT, "RETRY_BUDGET_NOT_REFILLED");
        yd_disk_abort(txn);
        yd_policy_work_init(&work, false);
        work.shape.remaining = 1;
        txn = yd_disk_begin(disk, policy_error, sizeof(policy_error));
        REQUIRE(txn && policy_apply(txn, "two", "2\n", &work) == YD_POLICY_OK,
                "SECOND_INDIVIDUAL_BUDGET_FITS");
        yd_disk_abort(txn);
    } else if (!strcmp(scenario, "absence") || !strcmp(scenario, "prepared")) {
        if (!strcmp(scenario, "prepared")) policy_publish(disk, "type: number\n", 1);
        YDPolicyWork work;
        yd_policy_work_init(&work, false);
        YDDiskTxn *writer = yd_disk_begin(disk, policy_error, sizeof(policy_error));
        REQUIRE(writer && policy_apply(writer, "late", "1.5\n", &work) == YD_POLICY_OK,
                "PREPARED_WRITE_ACCEPTED_OLD_POLICY");
        policy_publish(disk, "type: integer\n", 2);
        REQUIRE(!yd_disk_commit(writer, policy_error, sizeof(policy_error)),
                "CATALOG_OBSERVATION_BLOCKS_STALE_REBASE");
        YDDiskView view = yd_disk_view(disk);
        YDDiskDocument doc;
        REQUIRE(yd_disk_document_get(disk, &view, "books", "late", &doc, policy_error,
            sizeof(policy_error)) == 0, "STALE_WRITE_NOT_PUBLISHED");
    } else if (!strcmp(scenario, "activation")) {
        policy_write(disk, "bad", "1.5\n");
        YDDiskView before = yd_disk_view(disk);
        YDPolicyWork work;
        yd_policy_work_init(&work, true);
        YDDiskTxn *txn = yd_disk_begin_exclusive(disk, policy_error, sizeof(policy_error));
        REQUIRE(txn != NULL, "ACTIVATION_BEGIN");
        YDPCChange change = policy_change(txn, "books", "type: integer\n", &work);
        YDPolicyCatalog *updated = NULL;
        REQUIRE(yd_policy_store_change(txn, &change, &work, &updated, policy_error,
            sizeof(policy_error)) == YD_POLICY_REJECTED && !updated, "FULL_ACTIVATION_SCAN");
        yd_disk_abort(txn);
        REQUIRE(policy_same_view(before, yd_disk_view(disk)), "ACTIVATION_NO_PUBLICATION");
        yd_policy_work_init(&work, true);
        work.documents_left = 0;
        txn = yd_disk_begin_exclusive(disk, policy_error, sizeof(policy_error));
        REQUIRE(txn != NULL, "SCAN_LIMIT_BEGIN");
        change = policy_change(txn, "books", "type: number\n", &work);
        REQUIRE(yd_policy_store_change(txn, &change, &work, &updated, policy_error,
            sizeof(policy_error)) == YD_POLICY_LIMIT, "ACTIVATION_SCAN_CAP");
        yd_disk_abort(txn);
        REQUIRE(policy_same_view(before, yd_disk_view(disk)), "SCAN_LIMIT_NO_PUBLICATION");
    } else if (!strncmp(scenario, "precharge-", 10)) {
        bool shared = !strcmp(scenario, "precharge-shared");
        size_t size = !strcmp(scenario, "precharge-large") ? 1024 * 1024 : 8;
        char *source = malloc(size + 1);
        REQUIRE(source != NULL, "SCAN_SOURCE_ALLOCATION");
        memset(source, ' ', size);
        memcpy(source, "1\n#", 3);
        source[size - 1] = '\n';
        source[size] = 0;
        policy_write(disk, "one", source);
        if (shared) policy_write(disk, "two", source);
        YDDiskView before = yd_disk_view(disk);
        YDPolicyWork work;
        yd_policy_work_init(&work, true);
        work.source_bytes_left = shared ? 2 * size - 1 : size - 1;
        YDDiskTxn *txn = yd_disk_begin_exclusive(disk, policy_error, sizeof(policy_error));
        REQUIRE(txn != NULL, "PRECHARGE_BEGIN");
        YDPCChange change = policy_change(txn, "books", "type: integer\n", &work);
        YDPolicyCatalog *updated = NULL;
        policy_decode_calls = 0;
        policy_read_bytes = 0;
        policy_track_reads = true;
        REQUIRE(yd_policy_store_change(txn, &change, &work, &updated, policy_error,
            sizeof(policy_error)) == YD_POLICY_LIMIT && !updated, "SCAN_SOURCE_LIMIT");
        policy_track_reads = false;
        REQUIRE(policy_decode_calls == (shared ? 1U : 0U),
                "SCAN_BUDGET_PRECEDES_DOCUMENT_DECODE");
        if (size == 1024 * 1024)
            REQUIRE(policy_read_bytes < 65536, "SCAN_PRECHARGE_BOUNDS_PAYLOAD_IO");
        REQUIRE(work.source_bytes_left == 0, "SCAN_SOURCE_BUDGET_EXHAUSTED");
        yd_disk_abort(txn);
        REQUIRE(policy_same_view(before, yd_disk_view(disk)), "PRECHARGE_NO_PUBLICATION");
        free(source);
    } else if (!strcmp(scenario, "trusted")) {
        policy_publish(disk, "type: integer\n", 1);
        int prior;
        REQUIRE(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &prior) == 0, "PIN_CANCEL_DISABLE");
        YDDisk *historical = yd_disk_pin(disk, 65536, policy_error, sizeof(policy_error));
        REQUIRE(pthread_setcancelstate(prior, NULL) == 0, "PIN_CANCEL_RESTORE");
        REQUIRE(historical != NULL, "HISTORICAL_PIN");
        YDDiskTxn *txn = yd_disk_begin_exclusive(disk, policy_error, sizeof(policy_error));
        REQUIRE(txn != NULL, "PRESERVATION_BEGIN");
        policy_raw(txn, "books", "historic", "old: source\n");
        REQUIRE(yd_disk_commit(txn, policy_error, sizeof(policy_error)), "PRESERVATION_NOT_READMITTED");
        YDDiskView view = yd_disk_view(disk);
        YDDiskDocument doc;
        REQUIRE(yd_disk_document_get(disk, &view, "books", "historic", &doc, policy_error,
            sizeof(policy_error)) == 1, "HISTORY_READABLE");
        REQUIRE(doc.length == strlen("old: source\n") &&
                !memcmp(doc.body, "old: source\n", doc.length), "HISTORY_EXACT_SOURCE");
        yd_disk_document_free(&doc);
        YDPolicyWork work;
        yd_policy_work_init(&work, true);
        REQUIRE(yd_policy_validate_view(disk, &view, &work, policy_error,
            sizeof(policy_error)) == YD_POLICY_REJECTED, "ACTIVATION_VALIDATES_PRIVATE_VIEW");
        yd_disk_close(historical);
        policy_write(disk, "historic", NULL);
    } else if (!strcmp(scenario, "malformed")) {
        YDDiskTxn *txn = yd_disk_begin_exclusive(disk, policy_error, sizeof(policy_error));
        REQUIRE(txn != NULL, "CORRUPT_STAGE");
        policy_raw(txn, YD_POLICY_COLLECTION, YD_POLICY_DOCUMENT, "{}\n");
        REQUIRE(yd_disk_commit(txn, policy_error, sizeof(policy_error)), "CORRUPT_FIXTURE_PUBLISHED");
        YDDiskView before = yd_disk_view(disk);
        YDPolicyWork work;
        yd_policy_work_init(&work, false);
        txn = yd_disk_begin(disk, policy_error, sizeof(policy_error));
        REQUIRE(txn != NULL, "CORRUPT_WRITE_BEGIN");
        REQUIRE(policy_apply(txn, "unsafe", "1\n", &work) == YD_POLICY_CORRUPT,
                "CORRUPT_CATALOG_NEVER_EMPTY");
        yd_disk_abort(txn);
        REQUIRE(policy_same_view(before, yd_disk_view(disk)), "CORRUPT_REJECT_NO_PUBLICATION");
    } else if (!strcmp(scenario, "import")) {
        policy_publish(disk, "type: integer\n", 1);
        YDDiskTxn *txn = yd_disk_begin_staging(disk, policy_error, sizeof(policy_error));
        REQUIRE(txn != NULL, "IMPORT_STAGE");
        policy_raw(txn, "books", "late", "not: an-integer\n");
        YDPolicyWork work;
        yd_policy_work_init(&work, true);
        REQUIRE(yd_policy_admission_validate_root(txn, &work, policy_error,
            sizeof(policy_error)) == YD_POLICY_REJECTED, "COMPLETE_IMPORT_VALIDATION");
        yd_disk_abort(txn);
    } else REQUIRE(false, "UNKNOWN_SCENARIO");
    yd_disk_close(disk);
    puts("policy admission scenario verified");
    return 0;
}
