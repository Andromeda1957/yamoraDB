#define _GNU_SOURCE
#include "disk_bulk.h"
#include "disk_history.h"
#include "disk_branch_api.h"
#include "disk_internal.h"
#include "disk_changes.h"
#include "disk_log.h"
#include "disk_replica.h"
#include "schema/policy_admission.h"
#include "binary.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/random.h>
#include <sys/syscall.h>
#include <linux/fs.h>
#include <unistd.h>
#include <time.h>
/* A verified private copy has no preceding recovery root to preserve. Mirror
 * its selected root before removing the initialization marker so either slot
 * independently opens the complete migrated graph, including odd generations. */
static bool copied_headers(YDDisk *disk, const YDDiskView *view, char *error, size_t length) {
    unsigned char page[YD_DISK_PAGE];
    yd_disk_encode_schema_header(page, view, &disk->schema);
    uint64_t offset = ((view->generation + 1) % 2) * YD_DISK_PAGE;
    size_t done = 0;
    while (done < sizeof(page)) {
        ssize_t n = pwrite(disk->fd, page + done, sizeof(page) - done, (off_t)(offset + done));
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return yd_disk_error(error, length, "cannot seal copied recovery header");
        done += (size_t)n;
    }
    return !fsync(disk->fd) || yd_disk_error(error, length, "cannot sync copied recovery header");
}
static bool dot(const char *name) { return !strcmp(name, ".") || !strcmp(name, ".."); }
static DIR *scan(int fd) {
    int copy = openat(fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (copy < 0)
        return NULL;
    DIR *dir = fdopendir(copy);
    if (!dir)
        close(copy);
    return dir;
}
static int prepare(const char *destination, char *error, size_t length) {
    int fd = open(destination, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        yd_disk_error(error, length, "cannot open initialization destination");
        return -1;
    }
    if (flock(fd, LOCK_EX | LOCK_NB)) {
        close(fd);
        yd_disk_error(error, length, "initialization destination has another owner");
        return -1;
    }
    DIR *dir = scan(fd);
    bool empty = dir != NULL;
    struct dirent *entry;
    while (empty) {
        errno = 0;
        entry = readdir(dir);
        if (!entry) {
            if (errno)
                empty = false;
            break;
        }
        if (!dot(entry->d_name))
            empty = false;
    }
    if (dir)
        closedir(dir);
    if (!empty) {
        close(fd);
        yd_disk_error(error, length, "initialization destination must be empty");
        return -1;
    }
    int marker = openat(fd, YD_BINARY_INITIALIZING,
                        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    bool valid = marker >= 0 && fsync(marker) == 0 && fsync(fd) == 0;
    if (marker >= 0)
        close(marker);
    if (!valid) {
        close(fd);
        yd_disk_error(error, length, "cannot persist initialization sentinel");
        return -1;
    }
    return fd;
}
static bool finish(int fd, YDDisk *disk, char *error, size_t length) {
    YDDiskView view = yd_disk_view(disk);
    return yd_disk_validate(disk, &view, error, length) &&
           yd_disk_history_validate(disk, &view, NULL, error, length) &&
           unlinkat(fd, YD_BINARY_INITIALIZING, 0) == 0 && fsync(fd) == 0;
}
static const unsigned char receipt_prefix[] = {0, 'Y', 'S', 'P'};
/* No policy evaluation here: old successful replies are historical evidence.
 * record_into rejects an oversized framed payload before reading/allocating it. */
static bool receipts(YDDisk *source, const YDDiskView *view, YDDiskTxn *destination,
                       YDDiskValidation *state, char *error, size_t length) {
    unsigned char key[YD_DISK_KEY_LIMIT], bytes[YD_POLICY_RECEIPT_LIMIT], digest[32];
    size_t kn = 0, size = 0;
    uint64_t record = 0;
    YDDiskCursor *cursor = yd_disk_cursor(source, view, receipt_prefix,
                                           sizeof(receipt_prefix), false, error, length);
    bool valid = cursor != NULL;
    int next = 0;
    while (valid && (next = yd_disk_next(cursor, key, sizeof(key), &kn, &record, error, length)) == 1) {
        if (kn < sizeof(receipt_prefix) || memcmp(key, receipt_prefix, sizeof(receipt_prefix)))
            break;
        YDPolicyReply reply;
        valid = yd_disk_validation_step(state, YD_VALIDATE_OPERATION) &&
                (view->format == 7 || (view->capabilities & YD_DISK_CAP_SCHEMA)) &&
                (!destination || destination->view.format == 7 ||
                    (destination->view.capabilities & YD_DISK_CAP_SCHEMA)) &&
                kn == YD_POLICY_RECEIPT_KEY_SIZE &&
                yd_disk_record_into(source, view, record, bytes, sizeof(bytes), &size, error, length) &&
                yd_policy_receipt_decode(bytes, size, key + 4, digest, &reply, error, length) == YD_POLICY_OK;
        if (valid && destination) {
            uint64_t copied = record;
            valid = (destination->disk == source ||
                     yd_disk_append(destination, bytes, size, &copied, error, length)) &&
                    yd_disk_put(destination, key, kn, copied, error, length);
        }
    }
    yd_disk_cursor_free(cursor);
    return (valid && next >= 0) || yd_disk_error(error, length, "invalid native policy receipt or cancelled copy");
}
bool yd_disk_policy_receipts_copy(YDDisk *source, const YDDiskView *view,
                                   YDDiskTxn *destination, YDDiskValidation *state,
                                   char *error, size_t length) {
    if (!source || !view || !destination || !destination->exclusive || destination->failed)
        return yd_disk_error(error, length, "policy receipt copy requires an exclusive private root");
    /* Freeze the OLD private namespace before deleting keys. The immutable
     * cursor remains valid as the transaction constructs replacement pages. */
    YDDiskView old;
    if (!yd_disk_tx_freeze(destination, &old, error, length))
        return false;
    YDDiskCursor *cursor = yd_disk_cursor(destination->disk, &old, receipt_prefix,
                                           sizeof(receipt_prefix), false, error, length);
    bool valid = cursor != NULL;
    unsigned char key[YD_DISK_KEY_LIMIT];
    size_t kn = 0;
    uint64_t record = 0;
    int next = 0;
    while (valid && (next = yd_disk_next(cursor, key, sizeof(key), &kn, &record, error, length)) == 1) {
        if (kn < sizeof(receipt_prefix) || memcmp(key, receipt_prefix, sizeof(receipt_prefix)))
            break;
        valid = yd_disk_validation_step(state, YD_VALIDATE_OPERATION) &&
                yd_disk_delete(destination, key, kn, error, length);
    }
    yd_disk_cursor_free(cursor);
    return valid && next >= 0 && receipts(source, view, destination, state, error, length);
}
static bool source_record(YDDiskTxn *txn, const char *collection, const char *id,
                          const unsigned char *body, size_t size, char *error, size_t length) {
    YDDiskDocument document = {.body = (unsigned char *)body, .length = size};
    memcpy(document.collection, collection, strlen(collection) + 1);
    memcpy(document.id, id, strlen(id) + 1);
    unsigned char key[YD_DISK_KEY_LIMIT];
    size_t kn = yd_disk_document_key(key, collection, id);
    uint64_t ignored;
    if (yd_disk_tx_peek(txn, key, kn, &ignored, error, length) != 0)
        return yd_disk_error(error, length, "duplicate imported document");
    return yd_disk_write_document(txn, NULL, &document, error, length);
}
static bool import_collection(YDDiskTxn *txn, int root, const char *name, char *error,
                              size_t length) {
    int fd = openat(root, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return yd_disk_error(error, length, "invalid source collection");
    DIR *dir = scan(fd);
    bool valid = dir && yd_disk_create_collection(txn, name, error, length);
    struct dirent *entry;
    unsigned char *body = malloc(YD_LARGE_DOCUMENT_LIMIT + 1);
    if (!body)
        valid = false;
    while (valid) {
        errno = 0;
        entry = readdir(dir);
        if (!entry) {
            if (errno)
                valid = false;
            break;
        }
        if (dot(entry->d_name))
            continue;
        size_t n = strlen(entry->d_name);
        char id[129];
        if (n <= 5 || n > 133 || strcmp(entry->d_name + n - 5, ".yaml")) {
            valid = false;
            break;
        }
        memcpy(id, entry->d_name, n - 5);
        id[n - 5] = 0;
        if (!yamldb_valid_name(id)) {
            valid = false;
            break;
        }
        int doc = openat(fd, entry->d_name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
        struct stat st;
        valid = doc >= 0 && fstat(doc, &st) == 0 && S_ISREG(st.st_mode) && st.st_size > 0 &&
                st.st_size <= YD_LARGE_DOCUMENT_LIMIT;
        size_t used = 0;
        if (valid)
            for (;;) {
                ssize_t got = read(doc, body + used, YD_LARGE_DOCUMENT_LIMIT + 1 - used);
                if (got < 0 && errno == EINTR)
                    continue;
                if (got < 0) {
                    valid = false;
                    break;
                }
                if (!got)
                    break;
                used += (size_t)got;
                if (used > YD_LARGE_DOCUMENT_LIMIT) {
                    valid = false;
                    break;
                }
            }
        if (doc >= 0)
            close(doc);
        if (valid)
            valid = used == (size_t)st.st_size &&
                    source_record(txn, name, id, body, used, error, length);
    }
    free(body);
    if (dir)
        closedir(dir);
    close(fd);
    if (!valid && length && !*error)
        yd_disk_error(error, length, "invalid YAML source entry");
    return valid;
}
static bool initialize(const char *destination, const char *yaml, size_t cache, bool schema,
    uint32_t capabilities, YDStorageBudget *resources, char *error, size_t length) {
    if (length)
        *error = 0;
    int source = -1;
    bool valid = true;
    if (yaml) {
        source = open(yaml, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        valid = source >= 0 && flock(source, LOCK_SH | LOCK_NB) == 0;
        if (valid)
            valid = yd_disk_present(yaml) == 0 && yd_binary_present(yaml, error, length) == 0 &&
                    yd_binary_initializing(yaml) == 0 &&
                    yd_journal_recover(yaml, false, error, length);
        if (!valid) {
            if (source >= 0)
                close(source);
            return yd_disk_error(error, length,
                                 "YAML import source unavailable, incompatible, or has a writer");
        }
    }
    int target = prepare(destination, error, length);
    if (target < 0) {
        if (source >= 0)
            close(source);
        return false;
    }
    YDDisk *disk = capabilities ? yd_disk_create_capabilities_staging_budgeted_at(target,
        capabilities,cache,YD_DISK_ALLOCATION_UNLIMITED,resources,error,length) : resources ? schema ?
        yd_disk_create_schema_staging_budgeted_at(target, cache, resources, error, length) :
        yd_disk_open_budgeted_at(target, true, cache, YD_DISK_ALLOCATION_UNLIMITED, resources, error, length) :
        schema ? yd_disk_create_schema_staging_at(target, cache, error, length) :
        yd_disk_open_at(target, true, cache, error, length);
    YDDiskTxn *txn = disk ? yd_disk_begin_exclusive(disk, error, length) : NULL;
    valid = txn != NULL;
    if (txn)
        txn->log_enabled = true;
    DIR *dir = valid && yaml ? scan(source) : NULL;
    if (valid && yaml && !dir)
        valid = false;
    struct dirent *entry;
    while (valid && dir) {
        errno = 0;
        entry = readdir(dir);
        if (!entry) {
            if (errno)
                valid = false;
            break;
        }
        if (dot(entry->d_name) || yd_journal_internal_name(entry->d_name))
            continue;
        if (!yamldb_valid_name(entry->d_name)) {
            valid = false;
            break;
        }
        valid = import_collection(txn, source, entry->d_name, error, length);
    }
    if (dir)
        closedir(dir);
    if (source >= 0)
        close(source);
    /* Catalog order is immaterial: only the COMPLETE private candidate is
     * admitted, once, before indexes or a public root can be installed. */
    YDPolicyWork work;
    yd_policy_work_init(&work, true);
    if (valid)
        valid = yd_policy_admission_validate_root(txn, &work, error, length) == YD_POLICY_OK;
    if (valid)
        valid = yd_disk_rebuild_indexes(txn, error, length);
    if (valid) {
        valid = yd_disk_commit(txn, error, length);
        txn = NULL;
    }
    yd_disk_abort(txn);
    if (valid)
        valid = finish(target, disk, error, length);
    yd_disk_close(disk);
    close(target);
    if (!valid && length && !*error)
        yd_disk_error(error, length,
                      "disk initialization failed; retain destination and retry into a new root");
    return valid;
}
bool yd_disk_initialize(const char *destination, const char *yaml, size_t cache, char *error,
                        size_t length) {
    return initialize(destination, yaml, cache, false, 0, NULL, error, length);
}
bool yd_disk_initialize_schema(const char *destination, const char *yaml, size_t cache,
                                char *error, size_t length) {
    int previous = 0;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous))
        return yd_disk_error(error, length, "cannot disable schema initialization cancellation");
    bool valid = initialize(destination, yaml, cache, true, 0, NULL, error, length);
    int restored = pthread_setcancelstate(previous, NULL);
    return restored ? yd_disk_error(error, length, "cannot restore initialization cancellation") : valid;
}
bool yd_disk_initialize_budgeted(const char *destination, const char *yaml, size_t cache,
    YDStorageBudget *resources, char *error, size_t length) {
    return yd_storage_budget_process_valid(resources) &&
        initialize(destination, yaml, cache, false, 0, resources, error, length);
}
bool yd_disk_initialize_schema_budgeted(const char *destination, const char *yaml, size_t cache,
    YDStorageBudget *resources, char *error, size_t length) {
    if (!yd_storage_budget_process_valid(resources)) return false;
    int prior;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &prior)) return false;
    bool valid = initialize(destination, yaml, cache, true, 0, resources, error, length);
    return pthread_setcancelstate(prior, NULL) ? false : valid;

}
bool yd_disk_initialize_capabilities_budgeted(const char *destination,const char *yaml,size_t cache,
    uint32_t required,YDStorageBudget *resources,char *error,size_t length) {
    if (resources && !yd_storage_budget_process_valid(resources)) return false;
    if (!required || (required&~YD_DISK_CAP_SUPPORTED) || (required&YD_DISK_CAP_CLUSTER))
        return yd_disk_error(error,length,"invalid standalone initialization capabilities");
    int previous=0;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,&previous)) return false;
    bool valid=initialize(destination,yaml,cache,false,required,resources,error,length);
    int restored=pthread_setcancelstate(previous,NULL);
    return restored?yd_disk_error(error,length,"cannot restore initialization cancellation"):valid;
}
bool yd_disk_validate(YDDisk *disk, const YDDiskView *view, char *error, size_t length) {
    return yd_disk_validate_cancellable(disk, view, NULL, error, length);
}
bool yd_disk_validate_cancellable(YDDisk *disk, const YDDiskView *view, YDDiskValidation *state,
                                    char *error, size_t length) {
    if (!yd_disk_validation_step(state, YD_VALIDATE_COLLECTION))
        return yd_disk_error(error, length, "native disk validation cancelled");
    unsigned char key[YD_DISK_KEY_LIMIT], tag = 'C';
    size_t kn = 0;
    uint64_t value = 0, collections = 0, documents = 0, bytes = 0, revision = 0, total = 0;
    int next;
    YDDiskCursor *cursor = yd_disk_cursor(disk, view, &tag, 1, false, error, length);
    if (!cursor)
        return false;
    YDDiskIndexes *indexes = yd_disk_indexes_load(disk, view, error, length);
    bool valid = indexes != NULL;
    uint64_t text_expected[64] = {0}, text_actual[64] = {0};
    unsigned char text_prefix[64][YD_DISK_KEY_LIMIT];
    size_t text_sizes[64] = {0};
    for (size_t i = 0; valid && i < indexes->count; i++)
        if (indexes->indexes[i].text)
            valid = yd_disk_index_prefix(&indexes->indexes[i], NULL, 0, text_prefix[i],
                                         &text_sizes[i], error, length);
    char previous_collection[129] = {0};
    uint64_t collection_actual = 0, collection_expected = 0;
    next = 0;
    while (valid &&
           (next = yd_disk_next(cursor, key, sizeof(key), &kn, &value, error, length)) == 1) {
        if (key[0] != 'C')
            break;
        if (!yd_disk_validation_step(state, YD_VALIDATE_COLLECTION)) {
            valid = false;
            break;
        }
        char name[129];
        if (kn < 2 || kn > 129) {
            valid = false;
            break;
        }
        memcpy(name, key + 1, kn - 1);
        name[kn - 1] = 0;
        uint64_t reachable = 0;
        if (!yamldb_valid_name(name) || UINT64_MAX - total < value ||
            yd_disk_get(disk, view, key, kn, &reachable, error, length) != 1 ||
            reachable != value) {
            valid = false;
            break;
        }
        total += value;
        collections++;
        revision ^= yd_disk_fingerprint(name, NULL, NULL, 0);
    }
    if (next < 0)
        valid = false;
    yd_disk_cursor_free(cursor);
    tag = 'D';
    cursor = valid ? yd_disk_cursor(disk, view, &tag, 1, false, error, length) : NULL;
    if (valid && !cursor)
        valid = false;
    while (valid &&
           (next = yd_disk_next(cursor, key, sizeof(key), &kn, &value, error, length)) == 1) {
        if (key[0] != 'D')
            break;
        if (!yd_disk_validation_step(state, YD_VALIDATE_DOCUMENT)) {
            valid = false;
            break;
        }
        YDDiskDocument doc;
        if (!yd_disk_document_at(disk, view, value, &doc, error, length)) {
            valid = false;
            break;
        }
        unsigned char expected[YD_DISK_KEY_LIMIT], col[YD_DISK_KEY_LIMIT];
        size_t en = yd_disk_document_key(expected, doc.collection, doc.id),
               cn = yd_disk_collection_key(col, doc.collection);
        uint64_t count = 0, reachable = 0;
        valid = en == kn && !memcmp(expected, key, kn) &&
                yd_disk_get(disk, view, key, kn, &reachable, error, length) == 1 &&
                reachable == value &&
                yd_disk_get(disk, view, col, cn, &count, error, length) == 1 && count > 0 &&
                doc.length <= UINT64_MAX - bytes;
        if (valid && strcmp(previous_collection, doc.collection)) {
            if (previous_collection[0] && collection_actual != collection_expected)
                valid = false;
            memcpy(previous_collection, doc.collection, strlen(doc.collection) + 1);
            collection_actual = 0;
            collection_expected = count;
        }
        if (valid)
            valid = yd_disk_indexes_verify_document(disk, view, indexes, &doc, text_expected,
                                                    error, length);
        if (valid) {
            collection_actual++;
            documents++;
            bytes += doc.length;
            revision ^= yd_disk_fingerprint(doc.collection, doc.id, doc.body, doc.length);
        }
        yd_disk_document_free(&doc);
    }
    if (next < 0)
        valid = false;
    yd_disk_cursor_free(cursor);
    if (valid && previous_collection[0] && collection_actual != collection_expected)
        valid = false;
    if (valid)
        valid = collections == view->collections && documents == view->documents &&
                documents == total && bytes == view->bytes && revision == view->revision;
    const unsigned char tags[] = {'I', 'U'};
    for (size_t t = 0; valid && t < 2; t++) {
        cursor = yd_disk_cursor(disk, view, &tags[t], 1, false, error, length);
        if (!cursor) {
            valid = false;
            break;
        }
        while (valid &&
               (next = yd_disk_next(cursor, key, sizeof(key), &kn, &value, error, length)) == 1) {
            if (key[0] != tags[t])
                break;
            if (!yd_disk_validation_step(state, YD_VALIDATE_INDEX)) {
                valid = false;
                break;
            }
            /* The document pass verified every required distinct text key and
             * its record pointer. Equal cardinality then proves there are no
             * extra text entries, without decoding/tokenizing per posting. */
            bool text = false;
            if (tags[t] == 'I')
                for (size_t i = 0; i < indexes->count; i++)
                    if (text_sizes[i] && kn >= text_sizes[i] &&
                        !memcmp(key, text_prefix[i], text_sizes[i])) {
                        text = true;
                        if (text_actual[i] == UINT64_MAX)
                            valid = false;
                        else
                            text_actual[i]++;
                        break;
                    }
            if (text)
                continue;
            YDDiskDocument doc;
            if (!yd_disk_document_at(disk, view, value, &doc, error, length)) {
                valid = false;
                break;
            }
            unsigned char primary[YD_DISK_KEY_LIMIT];
            size_t pn = yd_disk_document_key(primary, doc.collection, doc.id);
            uint64_t expected = 0;
            valid = yd_disk_get(disk, view, primary, pn, &expected, error, length) == 1 &&
                    expected == value &&
                    yd_disk_index_entry_valid(indexes, &doc, key, kn, error, length);
            yd_disk_document_free(&doc);
        }
        if (next < 0)
            valid = false;
        yd_disk_cursor_free(cursor);
    }
    for (size_t i = 0; valid && i < indexes->count; i++)
        valid = text_expected[i] == text_actual[i];
    yd_disk_indexes_free(indexes);
    if (valid)
        valid = yd_disk_changes_validate_cancellable(disk, view, state, error, length);
    if (valid) {
        YDDiskReplicaPosition position;
        valid = yd_disk_replica_position(disk, view, &position, error, length) >= 0;
    }
    if (valid) {
        YDPolicyWork work;
        YDPolicyCatalog *catalog = NULL;
        bool present = false;
        yd_policy_work_init(&work, true);
        valid = yd_disk_validation_step(state, YD_VALIDATE_APPLICATION) &&
                yd_policy_store_at(disk, view, &work, &catalog, &present, error, length) == YD_POLICY_OK;
        yd_policy_catalog_free(catalog);
    }
    if (valid)
        valid = receipts(disk, view, NULL, state, error, length);
    if (valid)
        valid = yd_disk_branch_receipts_validate(disk,view,state,error,length);
    return valid || yd_disk_error(error, length, "native disk validation failed");
}
typedef struct {YDDisk *source;YDDiskTxn *txn;YDDiskView map;} HistoryCopy;
bool yd_disk_initialize_capabilities(const char *destination,const char *yaml,size_t cache,
    uint32_t required,char *error,size_t length) {
    return yd_disk_initialize_capabilities_budgeted(destination,yaml,cache,required,NULL,error,length);
}
static bool copy_history_root(void *context,const YDDiskView *source,YDDiskView *out,char *error,size_t length) {
    HistoryCopy *copy=context;
    return yd_disk_history_root_copy_mapped(copy->source,source,copy->txn,out,&copy->map,NULL,error,length);
}
static bool compact_capabilities(YDDisk *source,const YDDiskView *original,
    const char *destination,size_t cache,char *error,size_t length) {
    if (!yd_disk_validate(source,original,error,length) ||
        !yd_disk_history_validate(source,original,NULL,error,length)) return false;
    int target=prepare(destination,error,length);
    if (target<0) return false;
    YDDisk *disk=yd_disk_create_capabilities_staging_budgeted_at(target,original->capabilities,cache,
        YD_DISK_ALLOCATION_UNLIMITED,source->budget_lease.budget,error,length);
    YDDiskTxn *txn=disk?yd_disk_begin_exclusive(disk,error,length):NULL;
    YDDiskView main={0};
    bool valid=txn!=NULL;
    if (valid) {txn->history_copy=true;txn->log_enabled=false;}
    HistoryCopy copy={.source=source,.txn=txn};
    valid=valid && yd_disk_history_root_copy_mapped(source,original,txn,&main,&copy.map,NULL,error,length);
    if (valid) txn->view=main;
    valid=valid && yd_disk_history_copy(source,original,txn,copy_history_root,&copy,error,length);
    if (valid) {
        txn->view.generation=original->generation-1;
        valid=yd_disk_commit(txn,error,length);txn=NULL;
    }
    yd_disk_abort(txn);
    valid=valid && finish(target,disk,error,length);
    yd_disk_close(disk);close(target);return valid;
}
/* Preserve the exact retained feed, relocating historical document references.
 * Retention already bounds logical frame/source bytes; process one framed
 * record at a time and never build a dataset-sized relocation table. */
typedef struct { uint64_t remaining; struct timespec until; } RolloverWork;
static bool rollover_progress(void *context, YDDiskValidationPhase phase) {
    (void)phase;
    RolloverWork *work = context;
    struct timespec now;
    if (!work->remaining || clock_gettime(CLOCK_MONOTONIC, &now)) return false;
    work->remaining--;
    return now.tv_sec < work->until.tv_sec ||
        (now.tv_sec == work->until.tv_sec && now.tv_nsec <= work->until.tv_nsec);
}
static bool history_copy(YDDisk *source, const YDDiskView *view, YDDiskTxn *txn,
    YDDiskValidation *state, char *error, size_t length) {
    if (!yd_disk_changes_validate_cancellable(source, view, state, error, length)) return false;
    YDDiskCursor *cursor = yd_disk_cursor(source, view, "\0YL", 3, false, error, length);
    unsigned char key[YD_DISK_KEY_LIMIT];
    size_t kn = 0;
    uint64_t offset = 0;
    int next = 0;
    bool valid = cursor != NULL, replay = txn->replay;
    txn->replay = true;
    while (valid && (next = yd_disk_next(cursor, key, sizeof(key), &kn, &offset, error, length)) == 1) {
        if (kn < 3 || memcmp(key, "\0YL", 3)) break;
        if (!yd_disk_validation_step(state, YD_VALIDATE_OPERATION)) { valid = false; break; }
        size_t size = 0;
        unsigned char *bytes = yd_disk_record(source, view, offset, &size, error, length);
        bool frame = kn == 12 && !memcmp(key, "\0YLF", 4);
        valid = bytes && (frame || (kn == 4 && !memcmp(key, "\0YLM", 4)));
        if (valid && frame) {
            valid = size >= YD_LOG_HEADER_SIZE && !memcmp(bytes, "YDLOGF01", 8);
            size_t at = YD_LOG_HEADER_SIZE;
            unsigned count = valid ? yd_disk_u16(bytes + 42) : 0;
            valid = valid && count <= 256;
            for (unsigned i = 0; i < count && valid; i++) {
                valid = yd_disk_validation_step(state, YD_VALIDATE_OPERATION) && at <= size && size - at >= 20;
                size_t ks = valid ? yd_disk_u16(bytes + at) : 0;
                valid = valid && ks && ks <= size - at - 20;
                if (!valid) break;
                if (!bytes[at + 2] && bytes[at + 20] == 'D') {
                    size_t document_size = 0;
                    unsigned char *document = yd_disk_record(source, view,
                        yd_disk_u64(bytes + at + 4), &document_size, error, length);
                    uint64_t moved = 0;
                    valid = document && yd_disk_append(txn, document, document_size, &moved, error, length);
                    free(document);
                    if (valid) yd_disk_set64(bytes + at + 4, moved);
                }
                at += 20 + ks;
            }
            valid = valid && at == size;
        }
        uint64_t moved = 0;
        valid = valid && yd_disk_append(txn, bytes, size, &moved, error, length) &&
            yd_disk_put(txn, key, kn, moved, error, length);
        free(bytes);
    }
    yd_disk_cursor_free(cursor);
    txn->replay = replay;
    return valid && next >= 0;
}
static bool compact(YDDisk *source, const char *destination, size_t cache, YDDisk **owned,
                       char *error, size_t length) {
    if (owned) *owned = NULL;
    if (!yd_disk_open_fence_operation(source, true))
        return yd_disk_error(error, length, "fenced copy is unsupported");
    YDDiskView original = yd_disk_view(source);
    if (original.format==8) {
        if (owned) return yd_disk_error(error,length,"capability rollover requires explicit compaction");
        return compact_capabilities(source,&original,destination,cache,error,length);
    }
    RolloverWork work = {.remaining = 1000000};
    if (owned && clock_gettime(CLOCK_MONOTONIC, &work.until)) return false;
    work.until.tv_sec += 60;
    YDDiskValidation validation = {rollover_progress, &work, false};
    YDDiskValidation *state = owned ? &validation : NULL;
    if (!yd_disk_validate_cancellable(source, &original, state, error, length)) return false;
    int target = prepare(destination, error, length);
    if (target < 0)
        return false;
    YDStorageBudget *resources = source->budget_lease.budget;
    YDDisk *disk = resources ? original.format == 7 ?
        yd_disk_create_schema_staging_budgeted_at(target, cache, resources, error, length) :
        yd_disk_open_budgeted_at(target, true, cache, YD_DISK_ALLOCATION_UNLIMITED, resources, error, length) :
        original.format == 7 ? yd_disk_create_schema_staging_at(target, cache, error, length) :
        yd_disk_open_at(target, true, cache, error, length);
    YDDiskTxn *txn = disk ? yd_disk_begin_exclusive(disk, error, length) : NULL;
    bool valid = txn != NULL;
    if (txn)
        txn->log_enabled = true;
    unsigned char key[YD_DISK_KEY_LIMIT], tag = 'C';
    size_t kn = 0;
    uint64_t value = 0;
    int next = 0;
    YDDiskCursor *cursor =
        valid ? yd_disk_cursor(source, &original, &tag, 1, false, error, length) : NULL;
    if (valid && !cursor)
        valid = false;
    while (valid &&
           (next = yd_disk_next(cursor, key, sizeof(key), &kn, &value, error, length)) == 1) {
        if (key[0] != 'C')
            break;
        if (!yd_disk_validation_step(state, YD_VALIDATE_OPERATION)) { valid = false; break; }
        char name[129];
        if (kn < 2 || kn > 129) {
            valid = false;
            break;
        }
        memcpy(name, key + 1, kn - 1);
        name[kn - 1] = 0;
        valid = yd_disk_create_collection(txn, name, error, length);
    }
    if (next < 0)
        valid = false;
    yd_disk_cursor_free(cursor);
    tag = 'D';
    cursor = valid ? yd_disk_cursor(source, &original, &tag, 1, false, error, length) : NULL;
    if (valid && !cursor)
        valid = false;
    while (valid &&
           (next = yd_disk_next(cursor, key, sizeof(key), &kn, &value, error, length)) == 1) {
        if (key[0] != 'D')
            break;
        if (!yd_disk_validation_step(state, YD_VALIDATE_OPERATION)) { valid = false; break; }
        YDDiskDocument doc;
        if (!yd_disk_document_at(source, &original, value, &doc, error, length)) {
            valid = false;
            break;
        }
        valid = source_record(txn, doc.collection, doc.id, doc.body, doc.length, error, length);
        yd_disk_document_free(&doc);
    }
    if (next < 0)
        valid = false;
    yd_disk_cursor_free(cursor);
    if (valid)
        valid = yd_disk_policy_receipts_copy(source, &original, txn, state, error, length);
    if (valid)
        valid = yd_disk_rebuild_indexes_cancellable(txn, state, error, length);
    if (valid) {
        txn->log_enabled = false;
        txn->view.generation = original.generation - 1;
        valid = history_copy(source, &original, txn, state, error, length);
    }
    if (valid)
        valid = txn->view.revision == original.revision &&
                txn->view.documents == original.documents &&
                txn->view.collections == original.collections && txn->view.bytes == original.bytes;
    if (valid) {
        valid = yd_disk_commit(txn, error, length);
        txn = NULL;
    }
    yd_disk_abort(txn);
    if (valid) {
        YDDiskView selected = yd_disk_view(disk);
        valid = yd_disk_validate_cancellable(disk, &selected, state, error, length) &&
            copied_headers(disk, &selected, error, length) &&
            unlinkat(target, YD_BINARY_INITIALIZING, 0) == 0 && fsync(target) == 0;
    }
    if (valid && owned) { *owned = disk; disk = NULL; }
    yd_disk_close(disk);
    close(target);
    return valid;
}
bool yd_disk_compact(YDDisk *source, const char *destination, size_t cache, char *error,
                     size_t length) {
    int previous = 0;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous))
        return yd_disk_error(error, length, "cannot disable compaction cancellation");
    bool valid = compact(source, destination, cache, NULL, error, length);
    int restored = pthread_setcancelstate(previous, NULL);
    return restored ? yd_disk_error(error, length, "cannot restore compaction cancellation") : valid;
}
static bool roll_inode(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino;
}
static bool roll_private(const struct stat *s) {
    return S_ISREG(s->st_mode) && s->st_uid == geteuid() &&
        (s->st_mode & 07777) == 0600 && s->st_nlink == 1 && s->st_size >= 8192;
}
static bool roll_file(const struct stat *a, const struct stat *b) {
    return roll_inode(a, b) && a->st_size == b->st_size && a->st_mode == b->st_mode &&
        a->st_uid == b->st_uid && a->st_gid == b->st_gid && a->st_nlink == b->st_nlink &&
        a->st_mtim.tv_sec == b->st_mtim.tv_sec && a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
        a->st_ctim.tv_sec == b->st_ctim.tv_sec && a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}
static bool roll_root_exclusive(int root) {
    /* A fresh SH probe must conflict BEFORE idempotently checking the borrowed
     * EX OFD. Never convert a shared lock into an exclusive one as proof. */
    int probe = openat(root, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (probe < 0) return false;
    bool excluded = flock(probe, LOCK_SH | LOCK_NB) < 0 &&
        (errno == EWOULDBLOCK || errno == EAGAIN);
    close(probe);
    return excluded && flock(root, LOCK_EX | LOCK_NB) == 0;
}
int yd_disk_rollover(YDDisk **current, int root, size_t cache, YDDiskRolloverInfo *out,
    char *error, size_t length) {
    if (out) memset(out, 0, sizeof(*out));
    if (!current || !out || !yd_disk_process_valid(*current) || root < 0 ||
            cache < 32768 || cache > 1024U * 1024U * 1024U) return -1;
    int prior;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &prior)) return -1;
    if (prior != PTHREAD_CANCEL_DISABLE) {
        (void)pthread_setcancelstate(prior, NULL);
        yd_disk_error(error, length, "rollover requires caller-disabled cancellation");
        return -1;
    }
    YDDisk *source = *current, *candidate = NULL;
    YDStorageBudget *budget = source->budget_lease.budget;
    struct stat directory, original, named, stage_birth, stage_now, candidate_file;
    if (!budget || source->fence_hold || source->open_fence.version || source->retention ||
            source->lineage.scope || source->opening || source->schema_preparing ||
            !roll_root_exclusive(root) || fstat(root, &directory) || !S_ISDIR(directory.st_mode) ||
            directory.st_uid != geteuid() || (directory.st_mode & (S_IWGRP | S_IWOTH))) {
        yd_disk_error(error, length, "rollover requires the original private standalone owner");
        return -1;
    }
    if (pthread_mutex_trylock(&source->writer)) { errno = EBUSY; return 0; }
    if (pthread_mutex_trylock(&source->root_lock)) {
        pthread_mutex_unlock(&source->writer); errno = EBUSY; return 0;
    }
    bool valid = source->writable && !source->failed && !source->schema_invalid &&
        (source->view.format == 5 || source->view.format == 7) && source->view.generation &&
        !fstat(source->fd, &original) && roll_private(&original) &&
        !fstatat(root, YD_DISK_FILE, &named, AT_SYMLINK_NOFOLLOW) && roll_file(&original, &named);
    bool busy = valid && (source->active_transactions ||
        !yd_storage_budget_freeze(&source->budget_lease, 1));
    pthread_mutex_unlock(&source->root_lock);
    pthread_mutex_unlock(&source->writer);
    if (busy) { errno = EBUSY; return 0; }
    if (!valid) { yd_disk_error(error, length, "rollover source changed or unsupported"); return -1; }
    int stage = -1;
    valid = yd_disk_budget_extent(source, &out->old_extent);
    unsigned char random[16];
    size_t at = 0;
    while (valid && at < sizeof(random)) {
        ssize_t n = getrandom(random + at, sizeof(random) - at, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { valid = false; break; }
        at += (size_t)n;
    }
    if (valid) {
        memcpy(out->stage, ".yamora-rollover-", 17);
        const char *hex = "0123456789abcdef";
        for (unsigned i = 0; i < 16; i++) {
            out->stage[17 + i * 2] = hex[random[i] >> 4];
            out->stage[18 + i * 2] = hex[random[i] & 15];
        }
        valid = mkdirat(root, out->stage, 0700) == 0;
    }
    if (valid) {
        stage = openat(root, out->stage, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        valid = stage >= 0 && !fstat(stage, &stage_birth) &&
            stage_birth.st_uid == geteuid() && (stage_birth.st_mode & 07777) == 0700 && !fsync(root);
    }
    char destination[80];
    if (valid) {
        int n = snprintf(destination, sizeof(destination), "/proc/self/fd/%d/.", stage);
        valid = n > 0 && (size_t)n < sizeof(destination) &&
            compact(source, destination, cache, &candidate, error, length);
    }
    if (valid) valid = candidate && !candidate->fence_hold && !candidate->open_fence.version &&
        candidate->budget_lease.budget == budget && !fstat(candidate->fd, &candidate_file) &&
        roll_private(&candidate_file) && !fstatat(stage, YD_DISK_FILE, &named, AT_SYMLINK_NOFOLLOW) &&
        roll_file(&candidate_file, &named) && !fstat(stage, &stage_now) && roll_inode(&stage_birth, &stage_now) &&
        !fstatat(root, out->stage, &stage_now, AT_SYMLINK_NOFOLLOW) && roll_inode(&stage_birth, &stage_now) &&
        !fstat(source->fd, &named) && roll_file(&original, &named) &&
        !fstatat(root, YD_DISK_FILE, &named, AT_SYMLINK_NOFOLLOW) && roll_file(&original, &named) &&
        yd_disk_budget_extent(candidate, &out->new_extent);
    if (valid) valid = syscall(SYS_renameat2, root, YD_DISK_FILE, stage, YD_DISK_FILE, RENAME_EXCHANGE) == 0;
    if (valid) {
        /* Unfenced native handles contain no retained directory/fence holder.
         * Both locked file descriptors survive exchange; no reopened lock gap. */
        candidate->created = false;
        *current = candidate; candidate = NULL;
        out->selected = true;
        struct stat moved;
        valid = !fsync(root) && !fsync(stage) && !fstat(source->fd, &moved) &&
            roll_inode(&original, &moved) && moved.st_size == original.st_size && roll_private(&moved) &&
            moved.st_mtim.tv_sec == original.st_mtim.tv_sec && moved.st_mtim.tv_nsec == original.st_mtim.tv_nsec &&
            !fstatat(stage, YD_DISK_FILE, &named, AT_SYMLINK_NOFOLLOW) && roll_file(&moved, &named) &&
            unlinkat(stage, YD_DISK_FILE, 0) == 0 && fsync(stage) == 0;
        yd_disk_close(source); source = NULL;
        if (valid) valid = unlinkat(root, out->stage, AT_REMOVEDIR) == 0 && fsync(root) == 0;
        if (valid) out->retired = valid = yd_storage_budget_retire_extent(budget, &out->old_extent);
    }
    if (stage >= 0) close(stage);
    yd_disk_close(candidate);
    if (source) yd_storage_budget_thaw(&source->budget_lease);
    if (!valid) {
        yd_disk_error(error, length, "rollover failed; stop serving and preserve its diagnostic stage");
        return -1;
    }
    return 1;
}
