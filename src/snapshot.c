#define _POSIX_C_SOURCE 200809L

#include "snapshot.h"
#include "binary.h"

#include "compression.h"
#include "store.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static uint64_t hash_update(uint64_t hash, const unsigned char *value, size_t length)
{
    for (size_t index = 0; index < length; index++) {
        hash ^= value[index];
        hash *= UINT64_C(1099511628211);
    }
    return hash;
}

static uint64_t content_hash(const unsigned char *value, size_t length)
{
    return hash_update(UINT64_C(1469598103934665603), value, length);
}

bool yamldb_valid_name(const char *value)
{
    return yd_name_valid(value);
}

bool yamldb_valid_document_body(const unsigned char *value, size_t length)
{
    size_t index = 0;

    while (index < length) {
        unsigned char byte = value[index];
        size_t continuation_count = 0;
        uint32_t codepoint = 0;

        if (byte == 0 || (byte < 0x20 && byte != '\n' && byte != '\r' && byte != '\t')) {
            return false;
        }
        if (byte < 0x80) {
            index++;
            continue;
        }
        if ((byte & 0xe0) == 0xc0) {
            continuation_count = 1;
            codepoint = byte & 0x1f;
            if (codepoint < 2) {
                return false;
            }
        } else if ((byte & 0xf0) == 0xe0) {
            continuation_count = 2;
            codepoint = byte & 0x0f;
        } else if ((byte & 0xf8) == 0xf0) {
            continuation_count = 3;
            codepoint = byte & 0x07;
        } else {
            return false;
        }
        if (index + continuation_count >= length) {
            return false;
        }
        for (size_t offset = 1; offset <= continuation_count; offset++) {
            unsigned char continuation = value[index + offset];
            if ((continuation & 0xc0) != 0x80) {
                return false;
            }
            codepoint = (codepoint << 6) | (continuation & 0x3f);
        }
        if ((continuation_count == 2 && codepoint < 0x800) ||
            (continuation_count == 3 && codepoint < 0x10000) ||
            (codepoint >= 0xd800 && codepoint <= 0xdfff) ||
            codepoint > 0x10ffff) {
            return false;
        }
        index += continuation_count + 1;
    }
    return true;
}

static int compare_documents(const void *left, const void *right)
{
    const YamlDBDocument *left_document = left;
    const YamlDBDocument *right_document = right;
    return strcmp(left_document->name, right_document->name);
}

static int compare_collections(const void *left, const void *right)
{
    const YamlDBCollection *left_collection = left;
    const YamlDBCollection *right_collection = right;
    return strcmp(left_collection->name, right_collection->name);
}

static void free_document(YamlDBDocument *document)
{
    if (document->references != NULL && --*document->references > 0) {
        memset(document, 0, sizeof(*document));
        return;
    }
    free(document->references);
    yd_free(document->value);
    free(document->name);
    free(document->body);
    free(document->gzip_body);
    memset(document, 0, sizeof(*document));
}

static void free_collection(YamlDBCollection *collection)
{
    for (size_t index = 0; index < collection->document_count; index++) {
        free_document(&collection->documents[index]);
    }
    free(collection->documents);
    free(collection->index_body);
    free(collection->name);
    memset(collection, 0, sizeof(*collection));
}

void yamldb_snapshot_free(YamlDBSnapshot *snapshot)
{
    for (size_t index = 0; index < snapshot->collection_count; index++) {
        free_collection(&snapshot->collections[index]);
    }
    free(snapshot->collections);
    free(snapshot->collection_index_body);
    memset(snapshot, 0, sizeof(*snapshot));
}

static bool yaml_filename(
    const char *filename,
    char document_name[YAMLDB_NAME_LIMIT + 1], bool binary
)
{
    size_t length = strlen(filename);

    if (length <= 5 ||
        length > YAMLDB_NAME_LIMIT + 5 ||
        strcmp(filename + length - 5, binary ? ".ymdb" : ".yaml") != 0) {
        return false;
    }
    memcpy(document_name, filename, length - 5);
    document_name[length - 5] = '\0';
    return yamldb_valid_name(document_name);
}

static bool load_document(
    int collection_fd,
    const char *filename,
    const char *document_name,
    bool binary,
    YamlDBDocument *document,
    char *error,
    size_t error_length
)
{
    int descriptor = openat(
        collection_fd,
        filename,
        O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW
    );
    if (descriptor < 0) {
        (void)snprintf(error, error_length, "cannot open document %s", filename);
        return false;
    }
    struct stat status;
    if (fstat(descriptor, &status) != 0 ||
        !S_ISREG(status.st_mode) ||
        status.st_size <= 0) {
        close(descriptor);
        (void)snprintf(
            error,
            error_length,
            "document %s is not a non-empty regular file",
            filename
        );
        return false;
    }
    if (status.st_size > (off_t)(binary ? YD_BINARY_FILE_LIMIT : YAMLDB_DOCUMENT_LIMIT)) {
        close(descriptor);
        (void)snprintf(
            error,
            error_length,
            "document %s exceeds %d bytes",
            filename,
            YAMLDB_DOCUMENT_LIMIT
        );
        return false;
    }

    size_t length = (size_t)status.st_size;
    unsigned char *body = malloc(length);
    if (body == NULL) {
        close(descriptor);
        (void)snprintf(error, error_length, "cannot allocate document %s", filename);
        return false;
    }
    size_t used = 0;
    while (used < length) {
        ssize_t result = read(descriptor, body + used, length - used);
        if (result < 0 && errno == EINTR) {
            continue;
        }
        if (result <= 0) {
            free(body);
            close(descriptor);
            (void)snprintf(
                error,
                error_length,
                "cannot read complete document %s",
                filename
            );
            return false;
        }
        used += (size_t)result;
    }
    unsigned char extra;
    ssize_t trailing;
    do {
        trailing = read(descriptor, &extra, 1);
    } while (trailing < 0 && errno == EINTR);
    close(descriptor);
    if (trailing != 0 || (!binary && !yamldb_valid_document_body(body, length))) {
        free(body);
        (void)snprintf(
            error,
            error_length,
            "document %s changed or is not valid UTF-8 text",
            filename
        );
        return false;
    }

    YDValue *decoded = NULL;
    if (binary) {
        unsigned char *source = NULL; size_t source_length = 0;
        if (!yd_binary_unpack(body, length, &source, &source_length, &decoded)) {
            free(body); (void)snprintf(error, error_length, "invalid binary document %s", filename); return false;
        }
        free(body); body = source; length = source_length;
    }
    document->value = decoded;
    document->name = strdup(document_name);
    if (document->name == NULL) {
        free(body);
        (void)snprintf(
            error,
            error_length,
            "cannot allocate document name %s",
            filename
        );
        return false;
    }
    document->body = body;
    document->length = length;
    document->hash = content_hash(body, length);
    document->references = malloc(sizeof(*document->references));
    if (document->references == NULL) {
        (void)snprintf(error, error_length, "cannot allocate document reference");
        return false;
    }
    *document->references = 1;
    /* Version 2 was an opaque byte store. Preserve legacy reads even when a
     * document is outside the semantic YAML profile; semantic endpoints reject
     * those documents explicitly instead of silently omitting their fields. */
    char parse_error[256];
    if (!binary) document->value = yd_parse(body, length, parse_error, sizeof(parse_error));
    return yamldb_gzip_compress(
        document->body,
        document->length,
        &document->gzip_body,
        &document->gzip_length,
        error,
        error_length
    );
}

static bool build_collection_index(
    YamlDBCollection *collection,
    char *error,
    size_t error_length
)
{
    size_t capacity = 64 + strlen(collection->name);
    for (size_t index = 0; index < collection->document_count; index++) {
        capacity += strlen(collection->documents[index].name) + 4;
    }
    char *body = malloc(capacity);
    if (body == NULL) {
        (void)snprintf(
            error,
            error_length,
            "cannot allocate collection index %s",
            collection->name
        );
        return false;
    }
    int initial = snprintf(
        body,
        capacity,
        "{\"collection\":\"%s\",\"documents\":[",
        collection->name
    );
    if (initial < 0 || (size_t)initial >= capacity) {
        free(body);
        (void)snprintf(
            error,
            error_length,
            "cannot format collection index %s",
            collection->name
        );
        return false;
    }
    size_t used = (size_t)initial;
    for (size_t index = 0; index < collection->document_count; index++) {
        int written = snprintf(
            body + used,
            capacity - used,
            "%s\"%s\"",
            index == 0 ? "" : ",",
            collection->documents[index].name
        );
        if (written < 0 || (size_t)written >= capacity - used) {
            free(body);
            (void)snprintf(
                error,
                error_length,
                "cannot format collection index %s",
                collection->name
            );
            return false;
        }
        used += (size_t)written;
    }
    if (capacity - used < 4) {
        free(body);
        (void)snprintf(
            error,
            error_length,
            "collection index %s exceeds its allocation",
            collection->name
        );
        return false;
    }
    memcpy(body + used, "]}\n", 4);
    used += 3;
    body[used] = '\0';
    collection->index_body = body;
    collection->index_length = used;
    return true;
}

static bool load_collection(
    int root_fd,
    const char *collection_name,
    bool binary,
    YamlDBCollection *collection,
    YamlDBSnapshot *budget,
    char *error,
    size_t error_length
)
{
    static const size_t initial_document_capacity = 64;
    int collection_fd = openat(
        root_fd,
        collection_name,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
    );
    if (collection_fd < 0) {
        (void)snprintf(
            error,
            error_length,
            "cannot open collection %s",
            collection_name
        );
        return false;
    }
    DIR *directory = fdopendir(collection_fd);
    if (directory == NULL) {
        close(collection_fd);
        (void)snprintf(
            error,
            error_length,
            "cannot scan collection %s",
            collection_name
        );
        return false;
    }

    collection->name = strdup(collection_name);
    if (collection->name == NULL) {
        closedir(directory);
        (void)snprintf(
            error,
            error_length,
            "cannot allocate collection %s",
            collection_name
        );
        return false;
    }
    collection->documents = calloc(
        initial_document_capacity,
        sizeof(*collection->documents)
    );
    size_t document_capacity = initial_document_capacity;
    if (collection->documents == NULL) {
        free(collection->name);
        collection->name = NULL;
        closedir(directory);
        (void)snprintf(
            error,
            error_length,
            "cannot allocate collection %s",
            collection_name
        );
        return false;
    }

    bool valid = true;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (entry == NULL) {
            if (errno != 0) {
                (void)snprintf(
                    error,
                    error_length,
                    "cannot finish scanning collection %s",
                    collection_name
                );
                valid = false;
            }
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        if (yamldb_store_temporary_name(entry->d_name)) {
            continue;
        }
        char document_name[YAMLDB_NAME_LIMIT + 1];
        if (!yaml_filename(entry->d_name, document_name, binary)) {
            (void)snprintf(
                error,
                error_length,
                "collection %s contains an invalid entry",
                collection_name
            );
            valid = false;
            break;
        }
        if (budget->document_count == YAMLDB_SNAPSHOT_DOCUMENT_LIMIT) {
            (void)snprintf(
                error,
                error_length,
                "collection %s exceeds its document limit",
                collection_name
            );
            valid = false;
            break;
        }
        if (collection->document_count == document_capacity) {
            size_t next_capacity = document_capacity * 2;
            if (next_capacity > YAMLDB_COLLECTION_DOCUMENT_LIMIT) {
                next_capacity = YAMLDB_COLLECTION_DOCUMENT_LIMIT;
            }
            YamlDBDocument *documents = realloc(
                collection->documents,
                next_capacity * sizeof(*collection->documents)
            );
            if (documents == NULL) {
                (void)snprintf(
                    error,
                    error_length,
                    "cannot grow collection %s",
                    collection_name
                );
                valid = false;
                break;
            }
            memset(
                documents + document_capacity,
                0,
                (next_capacity - document_capacity) * sizeof(*documents)
            );
            collection->documents = documents;
            document_capacity = next_capacity;
        }
        YamlDBDocument *document =
            &collection->documents[collection->document_count];
        if (!load_document(
                collection_fd,
                entry->d_name,
                document_name,
                binary,
                document,
                error,
                error_length
            )) {
            free_document(document);
            valid = false;
            break;
        }
        collection->document_count++;
        budget->document_count++;
        budget->byte_count += document->length;
        budget->compressed_byte_count += document->gzip_length;
        budget->model_byte_count += yd_memory(document->value);
        if (budget->byte_count > YAMLDB_SNAPSHOT_BYTES_LIMIT ||
            budget->compressed_byte_count > YAMLDB_SNAPSHOT_BYTES_LIMIT - budget->byte_count ||
            budget->model_byte_count > YAMLDB_MODEL_BYTES_LIMIT) {
            (void)snprintf(error, error_length, "snapshot exceeds its global byte limit");
            valid = false;
            break;
        }
    }
    closedir(directory);
    if (!valid) {
        return false;
    }

    qsort(
        collection->documents,
        collection->document_count,
        sizeof(*collection->documents),
        compare_documents
    );
    for (size_t index = 1; index < collection->document_count; index++) {
        if (strcmp(
                collection->documents[index - 1].name,
                collection->documents[index].name
            ) == 0) {
            (void)snprintf(
                error,
                error_length,
                "collection %s repeats a document",
                collection_name
            );
            return false;
        }
    }
    return build_collection_index(collection, error, error_length);
}

static bool build_collection_catalog(
    YamlDBSnapshot *snapshot,
    char *error,
    size_t error_length
)
{
    size_t capacity = 32;
    for (size_t index = 0; index < snapshot->collection_count; index++) {
        capacity += strlen(snapshot->collections[index].name) + 4;
    }
    char *body = malloc(capacity);
    if (body == NULL) {
        (void)snprintf(error, error_length, "cannot allocate collection catalog");
        return false;
    }
    size_t used = 0;
    static const char prefix[] = "{\"collections\":[";
    memcpy(body, prefix, sizeof(prefix) - 1);
    used = sizeof(prefix) - 1;
    for (size_t index = 0; index < snapshot->collection_count; index++) {
        int written = snprintf(
            body + used,
            capacity - used,
            "%s\"%s\"",
            index == 0 ? "" : ",",
            snapshot->collections[index].name
        );
        if (written < 0 || (size_t)written >= capacity - used) {
            free(body);
            (void)snprintf(error, error_length, "cannot format collection catalog");
            return false;
        }
        used += (size_t)written;
    }
    if (capacity - used < 4) {
        free(body);
        (void)snprintf(error, error_length, "collection catalog exceeds its allocation");
        return false;
    }
    memcpy(body + used, "]}\n", 4);
    used += 3;
    body[used] = '\0';
    snapshot->collection_index_body = body;
    snapshot->collection_index_length = used;
    return true;
}

bool yamldb_snapshot_finalize(YamlDBSnapshot *snapshot, char *error, size_t error_length)
{
    snapshot->document_count = 0;
    snapshot->byte_count = 0;
    snapshot->compressed_byte_count = 0;
    snapshot->model_byte_count = 0;
    qsort(
        snapshot->collections,
        snapshot->collection_count,
        sizeof(*snapshot->collections),
        compare_collections
    );
    uint64_t revision = UINT64_C(1469598103934665603);
    static const unsigned char separator = 0xff;
    for (size_t collection_index = 0;
         collection_index < snapshot->collection_count;
         collection_index++) {
        YamlDBCollection *collection = &snapshot->collections[collection_index];
        if (collection->index_body == NULL &&
            !build_collection_index(collection, error, error_length)) {
            yamldb_snapshot_free(snapshot);
            return false;
        }
        if (collection_index > 0 && strcmp(
                snapshot->collections[collection_index - 1].name,
                collection->name
            ) == 0) {
            (void)snprintf(error, error_length, "snapshot repeats a collection");
            yamldb_snapshot_free(snapshot);
            return false;
        }
        revision = hash_update(
            revision,
            (const unsigned char *)collection->name,
            strlen(collection->name)
        );
        revision = hash_update(revision, &separator, 1);
        for (size_t document_index = 0;
             document_index < collection->document_count;
             document_index++) {
            YamlDBDocument *document = &collection->documents[document_index];
            snapshot->document_count++;
            snapshot->byte_count += document->length;
            snapshot->compressed_byte_count += document->gzip_length;
            snapshot->model_byte_count += yd_memory(document->value);
            if (snapshot->document_count > YAMLDB_SNAPSHOT_DOCUMENT_LIMIT ||
                snapshot->byte_count > YAMLDB_SNAPSHOT_BYTES_LIMIT ||
                snapshot->compressed_byte_count >
                    YAMLDB_SNAPSHOT_BYTES_LIMIT - snapshot->byte_count ||
                snapshot->model_byte_count > YAMLDB_MODEL_BYTES_LIMIT) {
                (void)snprintf(
                    error,
                    error_length,
                    "snapshot exceeds its global limits"
                );
                yamldb_snapshot_free(snapshot);
                errno = EFBIG;
                return false;
            }
            revision = hash_update(
                revision,
                (const unsigned char *)document->name,
                strlen(document->name)
            );
            revision = hash_update(revision, &separator, 1);
            revision = hash_update(revision, document->body, document->length);
            revision = hash_update(revision, &separator, 1);
        }
    }
    snapshot->revision_hash = revision;
    (void)snprintf(
        snapshot->revision,
        sizeof(snapshot->revision),
        "%016llx",
        (unsigned long long)revision
    );
    if (!build_collection_catalog(snapshot, error, error_length)) {
        yamldb_snapshot_free(snapshot);
        return false;
    }
    return true;
}

bool yamldb_snapshot_load(
    const char *data_dir,
    YamlDBSnapshot *snapshot,
    char *error,
    size_t error_length
)
{
    memset(snapshot, 0, sizeof(*snapshot));
    int binary = yd_binary_present(data_dir, error, error_length);
    if (binary < 0) return false;
    int root_fd = open(
        data_dir,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
    );
    if (root_fd < 0) {
        (void)snprintf(error, error_length, "cannot open data directory");
        return false;
    }
    int scan_fd = dup(root_fd);
    if (scan_fd < 0) {
        close(root_fd);
        (void)snprintf(
            error,
            error_length,
            "cannot duplicate data directory descriptor"
        );
        return false;
    }
    DIR *directory = fdopendir(scan_fd);
    if (directory == NULL) {
        close(scan_fd);
        close(root_fd);
        (void)snprintf(error, error_length, "cannot scan data directory");
        return false;
    }
    snapshot->collections = calloc(
        YAMLDB_COLLECTION_LIMIT,
        sizeof(*snapshot->collections)
    );
    if (snapshot->collections == NULL) {
        closedir(directory);
        close(root_fd);
        (void)snprintf(error, error_length, "cannot allocate snapshot collections");
        return false;
    }

    bool valid = true;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (entry == NULL) {
            if (errno != 0) {
                (void)snprintf(
                    error,
                    error_length,
                    "cannot finish scanning data directory"
                );
                valid = false;
            }
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0 ||
            yd_journal_internal_name(entry->d_name) ||
            (binary && (strcmp(entry->d_name, YD_BINARY_MARKER) == 0 ||
                        strcmp(entry->d_name, YD_BINARY_INITIALIZING) == 0))) {
            continue;
        }
        struct stat status;
        if (!yamldb_valid_name(entry->d_name) ||
            fstatat(
                root_fd,
                entry->d_name,
                &status,
                AT_SYMLINK_NOFOLLOW
            ) != 0 ||
            !S_ISDIR(status.st_mode)) {
            (void)snprintf(
                error,
                error_length,
                "data directory contains an invalid collection"
            );
            valid = false;
            break;
        }
        if (snapshot->collection_count == YAMLDB_COLLECTION_LIMIT) {
            (void)snprintf(
                error,
                error_length,
                "snapshot exceeds its collection limit"
            );
            valid = false;
            break;
        }
        YamlDBCollection *collection =
            &snapshot->collections[snapshot->collection_count];
        if (!load_collection(
                root_fd,
                entry->d_name,
                binary,
                collection,
                snapshot,
                error,
                error_length
            )) {
            free_collection(collection);
            valid = false;
            break;
        }
        snapshot->collection_count++;
    }
    closedir(directory);
    close(root_fd);
    if (!valid) {
        yamldb_snapshot_free(snapshot);
        return false;
    }

    return yamldb_snapshot_finalize(snapshot, error, error_length);
}

const YamlDBCollection *yamldb_snapshot_collection(
    const YamlDBSnapshot *snapshot,
    const char *name
)
{
    size_t low = 0;
    size_t high = snapshot->collection_count;

    while (low < high) {
        size_t middle = low + (high - low) / 2;
        int comparison = strcmp(name, snapshot->collections[middle].name);
        if (comparison == 0) {
            return &snapshot->collections[middle];
        }
        if (comparison < 0) {
            high = middle;
        } else {
            low = middle + 1;
        }
    }
    return NULL;
}

const YamlDBDocument *yamldb_collection_document(
    const YamlDBCollection *collection,
    const char *name
)
{
    size_t low = 0;
    size_t high = collection->document_count;

    while (low < high) {
        size_t middle = low + (high - low) / 2;
        int comparison = strcmp(name, collection->documents[middle].name);
        if (comparison == 0) {
            return &collection->documents[middle];
        }
        if (comparison < 0) {
            high = middle;
        } else {
            low = middle + 1;
        }
    }
    return NULL;
}

/* Build the entire next generation before touching durable storage. The write
 * mutex keeps source alive; readers continue using its immutable buffers. */
bool yamldb_snapshot_mutate(
    const YamlDBSnapshot *source, YamlDBSnapshot *candidate,
    const char *collection, const char *document,
    const unsigned char *body, size_t length, char *error, size_t error_length
)
{
    YDWrite write = {.collection=collection, .document=document,
                     .body=body, .length=length};
    return yamldb_snapshot_apply(source, candidate, &write, 1, error, error_length);
}
