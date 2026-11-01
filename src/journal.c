#define _POSIX_C_SOURCE 200809L

#include "journal.h"
#include "binary.h"

#include "snapshot.h"
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

/* v1 is explicitly little endian, never a dumped C structure:
 * header: magic[8], version:u32, operations:u32, payload bytes:u32, zero:u32
 * record: operation:u8, zero:u8, collection bytes:u16, document bytes:u16,
 *         zero:u16, body bytes:u32, collection, document, body
 * footer: commit magic[8], complete file bytes:u32, CRC32C:u32.
 * CRC32C covers every byte except its final four bytes. It detects accidental
 * corruption; it is not authentication. The caller owns a private, locked root.
 * Recovery validates the complete file before it starts any materialization.
 */
#define HEADER_LENGTH 24u
#define RECORD_LENGTH 12u
#define FOOTER_LENGTH 16u
#define JOURNAL_MAX_LENGTH (HEADER_LENGTH + FOOTER_LENGTH + \
    YD_JOURNAL_OPERATION_LIMIT * (RECORD_LENGTH + 2u * YAMLDB_NAME_LIMIT) + \
    YD_JOURNAL_BODY_LIMIT)

static const unsigned char journal_magic[8] = {'Y', 'D', 'J', 'N', 'L', '0', '0', '1'};
static const unsigned char commit_magic[8] = {'Y', 'D', 'C', 'O', 'M', 'M', 'I', 'T'};

typedef struct {
    int descriptor;
    uint32_t crc;
    size_t consumed;
} Stream;

static bool fail(char *error, size_t length, const char *message)
{
    (void)snprintf(error, length, "%s", message);
    return false;
}

bool yd_journal_internal_name(const char *name)
{
    return name != NULL && (strcmp(name, YAMLDB_JOURNAL_NAME) == 0 ||
                            strcmp(name, YAMLDB_JOURNAL_TEMP_NAME) == 0);
}

static uint32_t crc_update(uint32_t crc, const unsigned char *bytes, size_t length)
{
    static const uint32_t nibble[16] = {
        UINT32_C(0x00000000), UINT32_C(0x105ec76f), UINT32_C(0x20bd8ede), UINT32_C(0x30e349b1),
        UINT32_C(0x417b1dbc), UINT32_C(0x5125dad3), UINT32_C(0x61c69362), UINT32_C(0x7198540d),
        UINT32_C(0x82f63b78), UINT32_C(0x92a8fc17), UINT32_C(0xa24bb5a6), UINT32_C(0xb21572c9),
        UINT32_C(0xc38d26c4), UINT32_C(0xd3d3e1ab), UINT32_C(0xe330a81a), UINT32_C(0xf36e6f75)
    };
    for (size_t index = 0; index < length; index++) {
        crc ^= bytes[index];
        crc = (crc >> 4) ^ nibble[crc & 15u];
        crc = (crc >> 4) ^ nibble[crc & 15u];
    }
    return crc;
}

static uint16_t read_u16(const unsigned char *bytes)
{
    return (uint16_t)((uint16_t)bytes[0] | ((uint16_t)bytes[1] << 8));
}

static uint32_t read_u32(const unsigned char *bytes)
{
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) |
           ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
}

static void write_u16(unsigned char *bytes, size_t value)
{
    bytes[0] = (unsigned char)value;
    bytes[1] = (unsigned char)(value >> 8);
}

static void write_u32(unsigned char *bytes, size_t value)
{
    for (unsigned int index = 0; index < 4; index++) {
        bytes[index] = (unsigned char)(value >> (index * 8));
    }
}

static bool stream_write(Stream *stream, const void *input, size_t length)
{
    const unsigned char *bytes = input;
    size_t used = 0;
    while (used < length) {
        ssize_t result = write(stream->descriptor, bytes + used, length - used);
        if (result < 0 && errno == EINTR) {
            continue;
        }
        if (result <= 0) {
            return false;
        }
        used += (size_t)result;
    }
    stream->crc = crc_update(stream->crc, bytes, length);
    stream->consumed += length;
    return true;
}

static bool stream_read(Stream *stream, void *output, size_t length)
{
    unsigned char *bytes = output;
    size_t used = 0;
    while (used < length) {
        ssize_t result = read(stream->descriptor, bytes + used, length - used);
        if (result < 0 && errno == EINTR) {
            continue;
        }
        if (result <= 0) {
            return false;
        }
        used += (size_t)result;
    }
    stream->crc = crc_update(stream->crc, bytes, length);
    stream->consumed += length;
    return true;
}

static bool valid_name(const char *name)
{
    return name != NULL && strnlen(name, YAMLDB_NAME_LIMIT + 1u) <= YAMLDB_NAME_LIMIT &&
           yamldb_valid_name(name);
}

static int open_root(const char *data_dir, char *error, size_t error_length)
{
    int descriptor = open(data_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        (void)fail(error, error_length, "cannot open journal data directory");
    }
    return descriptor;
}

static bool inspect_reserved(int root, const char *name, bool *exists,
                             char *error, size_t error_length)
{
    struct stat status;
    if (fstatat(root, name, &status, AT_SYMLINK_NOFOLLOW) == 0) {
        *exists = true;
        return S_ISREG(status.st_mode) ||
               fail(error, error_length, "journal namespace is not regular");
    }
    *exists = false;
    return errno == ENOENT || fail(error, error_length, "cannot inspect journal namespace");
}

/* Do not create a directory or touch a document during precommit validation. */
static bool inspect_destination(const char *data_dir, int root, const YDWrite *write,
                                char *error, size_t error_length)
{
    int collection = openat(root, write->collection,
                            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (collection < 0) {
        return errno == ENOENT || fail(error, error_length, "journal collection is unavailable");
    }
    bool valid = true;
    if (write->kind == YD_WRITE_DOCUMENT) {
        char filename[YAMLDB_NAME_LIMIT + 6];
        int binary = yd_binary_present(data_dir, error, error_length);
        if (binary < 0) { close(collection); return false; }
        (void)snprintf(filename, sizeof(filename), "%s%s", write->document, binary ? ".ymdb" : ".yaml");
        struct stat status;
        int result = fstatat(collection, filename, &status, AT_SYMLINK_NOFOLLOW);
        if ((result == 0 && !S_ISREG(status.st_mode)) || (result != 0 && errno != ENOENT)) {
            valid = fail(error, error_length, "journal document destination is unavailable");
        }
    }
    (void)close(collection);
    return valid;
}

static bool validate_writes(const char *data_dir, int root, const YDWrite *writes, size_t count,
                           size_t *payload_length, char *error, size_t error_length)
{
    if (writes == NULL || count == 0 || count > YD_JOURNAL_OPERATION_LIMIT) {
        return fail(error, error_length, "journal operation count is invalid");
    }
    size_t body_total = 0;
    *payload_length = 0;
    for (size_t index = 0; index < count; index++) {
        const YDWrite *write = &writes[index];
        if (!valid_name(write->collection)) {
            return fail(error, error_length, "journal collection name is invalid");
        }
        size_t document_length = 0;
        if (write->kind == YD_WRITE_DOCUMENT) {
            if (!valid_name(write->document)) {
                return fail(error, error_length, "journal document name is invalid");
            }
            document_length = strlen(write->document);
            if ((write->body == NULL && write->length != 0) ||
                (write->body != NULL && (write->length == 0 || write->length > YAMLDB_DOCUMENT_LIMIT ||
                 !yamldb_valid_document_body(write->body, write->length)))) {
                return fail(error, error_length, "journal document body is invalid");
            }
        } else if ((write->kind != YD_WRITE_CREATE_COLLECTION && write->kind != YD_WRITE_DELETE_COLLECTION) ||
                   write->document != NULL || write->body != NULL || write->length != 0) {
            return fail(error, error_length, "journal collection operation is invalid");
        }
        if (write->length > YD_JOURNAL_BODY_LIMIT - body_total) {
            return fail(error, error_length, "journal body budget exceeded");
        }
        body_total += write->length;
        *payload_length += RECORD_LENGTH + strlen(write->collection) + document_length + write->length;
        int binary = yd_binary_present(data_dir, error, error_length);
        if (binary < 0) return false;
        if (binary && write->kind == YD_WRITE_DOCUMENT && write->body != NULL) {
            YDValue *value = yd_parse(write->body, write->length, error, error_length);
            if (value == NULL) return false;
            yd_free(value);
        }
        if (!inspect_destination(data_dir, root, write, error, error_length)) {
            return false;
        }
    }
    return true;
}

static bool delete_document(const char *data_dir, int root, const YDWrite *write,
                            char *error, size_t error_length)
{
    int collection = openat(root, write->collection,
                            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (collection < 0) {
        if (errno == ENOENT && fsync(root) == 0) {
            return true;
        }
        return fail(error, error_length, "cannot recover document deletion collection");
    }
    char filename[YAMLDB_NAME_LIMIT + 6];
    int binary = yd_binary_present(data_dir, error, error_length);
    if (binary < 0) { close(collection); return false; }
    (void)snprintf(filename, sizeof(filename), "%s%s", write->document, binary ? ".ymdb" : ".yaml");
    struct stat status;
    int result = fstatat(collection, filename, &status, AT_SYMLINK_NOFOLLOW);
    if (result != 0 && errno == ENOENT) {
        /* Repeated deletion must also make a preceding uncertain unlink durable. */
        bool durable = fsync(collection) == 0;
        (void)close(collection);
        return durable || fail(error, error_length, "cannot persist recovered missing document");
    }
    (void)close(collection);
    if (result != 0 || !S_ISREG(status.st_mode)) {
        return fail(error, error_length, "recovery document destination is unavailable");
    }
    bool published = false;
    return yamldb_store_delete(data_dir, write->collection, write->document,
                                &published, error, error_length);
}

static bool remove_store_temporaries(int collection, char *error, size_t error_length)
{
    DIR *directory = fdopendir(collection);
    if (directory == NULL) {
        (void)close(collection);
        return fail(error, error_length, "cannot scan collection for interrupted writes");
    }
    bool valid = true;
    bool removed = false;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (entry == NULL) {
            if (errno != 0) {
                valid = fail(error, error_length, "cannot finish scanning interrupted writes");
            }
            break;
        }
        if (!yamldb_store_temporary_name(entry->d_name)) {
            continue;
        }
        if (unlinkat(collection, entry->d_name, 0) != 0) {
            valid = fail(error, error_length, "cannot remove interrupted document write");
            break;
        }
        removed = true;
    }
    if (valid && removed && fsync(collection) != 0) {
        valid = fail(error, error_length, "cannot persist interrupted write cleanup");
    }
    if (closedir(directory) != 0 && valid) {
        valid = fail(error, error_length, "cannot close interrupted write scan");
    }
    return valid;
}

static bool apply_write(const char *data_dir, int root, const YDWrite *write,
                        char *error, size_t error_length)
{
    if (write->kind == YD_WRITE_DOCUMENT) {
        if (write->body == NULL) {
            return delete_document(data_dir, root, write, error, error_length);
        }
        bool published = false;
        return yamldb_store_put(data_dir, write->collection, write->document,
                               write->body, write->length, &published, error, error_length);
    }
    int collection = openat(root, write->collection,
                            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (collection < 0) {
        if (errno != ENOENT) {
            return fail(error, error_length, "recovery collection is unavailable");
        }
        if (write->kind == YD_WRITE_CREATE_COLLECTION && mkdirat(root, write->collection, 0700) != 0) {
            return fail(error, error_length, "cannot recover collection creation");
        }
    } else if (write->kind == YD_WRITE_DELETE_COLLECTION) {
        if (!remove_store_temporaries(collection, error, error_length)) {
            return false;
        }
        if (unlinkat(root, write->collection, AT_REMOVEDIR) != 0) {
            return fail(error, error_length, "cannot recover nonempty or unavailable collection removal");
        }
    } else {
        (void)close(collection);
    }
    return fsync(root) == 0 || fail(error, error_length, "cannot persist recovered collection operation");
}

static bool encode_journal(int descriptor, const YDWrite *writes, size_t count,
                           size_t payload_length)
{
    Stream stream = {.descriptor = descriptor, .crc = UINT32_MAX};
    unsigned char header[HEADER_LENGTH] = {0};
    memcpy(header, journal_magic, sizeof(journal_magic));
    write_u32(header + 8, 1);
    write_u32(header + 12, count);
    write_u32(header + 16, payload_length);
    if (!stream_write(&stream, header, sizeof(header))) {
        return false;
    }
    for (size_t index = 0; index < count; index++) {
        const YDWrite *write = &writes[index];
        size_t collection_length = strlen(write->collection);
        size_t document_length = write->document == NULL ? 0 : strlen(write->document);
        unsigned char record[RECORD_LENGTH] = {0};
        record[0] = write->kind == YD_WRITE_DOCUMENT ? (write->body == NULL ? 2 : 1) :
                    (write->kind == YD_WRITE_CREATE_COLLECTION ? 3 : 4);
        write_u16(record + 2, collection_length);
        write_u16(record + 4, document_length);
        write_u32(record + 8, write->length);
        if (!stream_write(&stream, record, sizeof(record)) ||
            !stream_write(&stream, write->collection, collection_length) ||
            !stream_write(&stream, write->document, document_length) ||
            !stream_write(&stream, write->body, write->length)) {
            return false;
        }
    }
    unsigned char footer[FOOTER_LENGTH] = {0};
    memcpy(footer, commit_magic, sizeof(commit_magic));
    write_u32(footer + 8, HEADER_LENGTH + payload_length + FOOTER_LENGTH);
    if (!stream_write(&stream, footer, FOOTER_LENGTH - 4u)) {
        return false;
    }
    write_u32(footer + 12, stream.crc ^ UINT32_MAX);
    return stream_write(&stream, footer + 12, 4);
}

static bool read_journal(int descriptor, const char *data_dir, int root,
                         bool apply, char *error, size_t error_length)
{
    struct stat status;
    if (fstat(descriptor, &status) != 0 || !S_ISREG(status.st_mode) ||
        status.st_size < (off_t)(HEADER_LENGTH + FOOTER_LENGTH) ||
        status.st_size > (off_t)JOURNAL_MAX_LENGTH || lseek(descriptor, 0, SEEK_SET) != 0) {
        return fail(error, error_length, "journal size or file type is invalid");
    }
    Stream stream = {.descriptor = descriptor, .crc = UINT32_MAX};
    unsigned char header[HEADER_LENGTH];
    if (!stream_read(&stream, header, sizeof(header)) ||
        memcmp(header, journal_magic, sizeof(journal_magic)) != 0 ||
        read_u32(header + 8) != 1 || read_u32(header + 20) != 0) {
        return fail(error, error_length, "journal header is malformed");
    }
    size_t count = read_u32(header + 12);
    size_t payload_length = read_u32(header + 16);
    if (count == 0 || count > YD_JOURNAL_OPERATION_LIMIT ||
        payload_length > JOURNAL_MAX_LENGTH - HEADER_LENGTH - FOOTER_LENGTH ||
        (size_t)status.st_size != HEADER_LENGTH + payload_length + FOOTER_LENGTH ||
        payload_length < count * (RECORD_LENGTH + 1u)) {
        return fail(error, error_length, "journal framing exceeds its bounds");
    }
    int binary = yd_binary_present(data_dir, error, error_length);
    if (binary < 0) return false;
    unsigned char *body = malloc(YAMLDB_DOCUMENT_LIMIT);
    if (body == NULL) {
        return fail(error, error_length, "cannot allocate bounded journal replay buffer");
    }
    bool valid = true;
    size_t body_total = 0;
    for (size_t index = 0; valid && index < count; index++) {
        unsigned char record[RECORD_LENGTH];
        char collection[YAMLDB_NAME_LIMIT + 1];
        char document[YAMLDB_NAME_LIMIT + 1];
        if (stream.consumed > HEADER_LENGTH + payload_length ||
            HEADER_LENGTH + payload_length - stream.consumed < RECORD_LENGTH ||
            !stream_read(&stream, record, sizeof(record))) {
            valid = false;
            break;
        }
        unsigned int operation = record[0];
        size_t collection_length = read_u16(record + 2);
        size_t document_length = read_u16(record + 4);
        size_t body_length = read_u32(record + 8);
        bool is_document = operation == 1 || operation == 2;
        if (operation < 1 || operation > 4 || record[1] != 0 || read_u16(record + 6) != 0 ||
            collection_length == 0 || collection_length > YAMLDB_NAME_LIMIT ||
            document_length > YAMLDB_NAME_LIMIT || (is_document ? document_length == 0 : document_length != 0) ||
            body_length > YAMLDB_DOCUMENT_LIMIT || (operation == 1 ? body_length == 0 : body_length != 0) ||
            body_length > YD_JOURNAL_BODY_LIMIT - body_total ||
            collection_length + document_length + body_length > HEADER_LENGTH + payload_length - stream.consumed) {
            valid = false;
            break;
        }
        if (!stream_read(&stream, collection, collection_length) ||
            !stream_read(&stream, document, document_length) ||
            !stream_read(&stream, body, body_length)) {
            valid = false;
            break;
        }
        collection[collection_length] = '\0';
        document[document_length] = '\0';
        if (memchr(collection, '\0', collection_length) != NULL ||
            memchr(document, '\0', document_length) != NULL ||
            !valid_name(collection) || (is_document && !valid_name(document)) ||
            (operation == 1 && !yamldb_valid_document_body(body, body_length))) {
            valid = false;
            break;
        }
        if (binary && operation == 1) {
            YDValue *value = yd_parse(body, body_length, error, error_length);
            if (value == NULL) { valid = false; break; }
            yd_free(value);
        }
        body_total += body_length;
        if (apply) {
            YDWrite write = {
                .collection = collection,
                .document = is_document ? document : NULL,
                .body = operation == 1 ? body : NULL,
                .length = body_length,
                .kind = is_document ? YD_WRITE_DOCUMENT :
                        (operation == 3 ? YD_WRITE_CREATE_COLLECTION : YD_WRITE_DELETE_COLLECTION)
            };
            if (!apply_write(data_dir, root, &write, error, error_length)) {
                free(body);
                return false;
            }
        }
    }
    free(body);
    unsigned char footer[FOOTER_LENGTH];
    if (!valid || stream.consumed != HEADER_LENGTH + payload_length ||
        !stream_read(&stream, footer, FOOTER_LENGTH - 4u) ||
        memcmp(footer, commit_magic, sizeof(commit_magic)) != 0 ||
        read_u32(footer + 8) != (uint32_t)status.st_size) {
        return fail(error, error_length, "journal record or commit framing is malformed");
    }
    uint32_t checksum = stream.crc ^ UINT32_MAX;
    if (!stream_read(&stream, footer + 12, 4) || read_u32(footer + 12) != checksum) {
        return fail(error, error_length, "journal checksum is invalid");
    }
    unsigned char trailing;
    ssize_t result;
    do {
        result = read(descriptor, &trailing, 1);
    } while (result < 0 && errno == EINTR);
    return result == 0 || fail(error, error_length, "journal has trailing bytes");
}

static bool checkpoint(int root, bool temporary_exists, char *error, size_t error_length)
{
    if (temporary_exists && unlinkat(root, YAMLDB_JOURNAL_TEMP_NAME, 0) != 0) {
        return fail(error, error_length, "cannot remove orphan journal temporary");
    }
    if (unlinkat(root, YAMLDB_JOURNAL_NAME, 0) != 0 || fsync(root) != 0) {
        return fail(error, error_length, "cannot checkpoint completed journal durably");
    }
    return true;
}

bool yd_journal_commit(const char *data_dir, const YDWrite *writes, size_t count,
                       bool *committed, char *error, size_t error_length)
{
    *committed = false;
    int binary = yd_binary_present(data_dir, error, error_length);
    if (binary < 0) return false;
    int root = open_root(data_dir, error, error_length);
    if (root < 0) {
        return false;
    }
    bool journal_exists = false;
    bool temporary_exists = false;
    size_t payload_length = 0;
    bool valid = inspect_reserved(root, YAMLDB_JOURNAL_NAME, &journal_exists, error, error_length) &&
                 inspect_reserved(root, YAMLDB_JOURNAL_TEMP_NAME, &temporary_exists, error, error_length);
    if (valid && (journal_exists || temporary_exists)) {
        valid = fail(error, error_length, "journal recovery required before another commit");
    }
    if (!valid || !validate_writes(data_dir, root, writes, count, &payload_length, error, error_length)) {
        (void)close(root);
        return false;
    }
    int descriptor = openat(root, YAMLDB_JOURNAL_TEMP_NAME,
                             O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (descriptor < 0) {
        (void)close(root);
        return fail(error, error_length, "cannot create exclusive journal temporary");
    }
    valid = encode_journal(descriptor, writes, count, payload_length) && fsync(descriptor) == 0;
    if (close(descriptor) != 0) {
        valid = false;
    }
    if (!valid || renameat(root, YAMLDB_JOURNAL_TEMP_NAME, root, YAMLDB_JOURNAL_NAME) != 0) {
        (void)unlinkat(root, YAMLDB_JOURNAL_TEMP_NAME, 0);
        (void)close(root);
        return fail(error, error_length, "cannot persist and publish complete journal");
    }
    /* Publication precedes directory fsync. Its failure is an uncertain commit,
     * never permission to accept another transaction or serve the old snapshot. */
    *committed = true;
    if (fsync(root) != 0) {
        (void)close(root);
        return fail(error, error_length, "published journal has uncertain durability; recovery required");
    }
    for (size_t index = 0; index < count; index++) {
        if (!apply_write(data_dir, root, &writes[index], error, error_length)) {
            (void)close(root);
            return false;
        }
    }
    valid = checkpoint(root, false, error, error_length);
    (void)close(root);
    return valid;
}

bool yd_journal_recover(const char *data_dir, bool writable, char *error, size_t error_length)
{
    int binary = yd_binary_present(data_dir, error, error_length);
    if (binary < 0) return false;
    int root = open_root(data_dir, error, error_length);
    if (root < 0) {
        return false;
    }
    bool journal_exists = false;
    bool temporary_exists = false;
    bool valid = inspect_reserved(root, YAMLDB_JOURNAL_NAME, &journal_exists, error, error_length) &&
                 inspect_reserved(root, YAMLDB_JOURNAL_TEMP_NAME, &temporary_exists, error, error_length);
    if (!valid || (journal_exists && !writable)) {
        (void)close(root);
        return valid ? fail(error, error_length, "pending journal requires writable recovery") : false;
    }
    if (!journal_exists) {
        if (writable && temporary_exists &&
            (unlinkat(root, YAMLDB_JOURNAL_TEMP_NAME, 0) != 0 || fsync(root) != 0)) {
            valid = fail(error, error_length, "cannot clean uncommitted journal temporary durably");
        }
        (void)close(root);
        return valid;
    }
    int descriptor = openat(root, YAMLDB_JOURNAL_NAME, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (descriptor < 0) {
        (void)close(root);
        return fail(error, error_length, "cannot open journal for recovery");
    }
    valid = read_journal(descriptor, data_dir, root, false, error, error_length);
    /* Re-sync a journal whose original publication fsync might have failed,
     * before any replay writes. The lifetime lock keeps the record immutable. */
    if (valid && (fsync(descriptor) != 0 || fsync(root) != 0)) {
        valid = fail(error, error_length, "cannot establish journal recovery durability");
    }
    if (valid) {
        valid = read_journal(descriptor, data_dir, root, true, error, error_length);
    }
    if (close(descriptor) != 0) {
        valid = fail(error, error_length, "cannot close recovered journal");
    }
    if (valid) {
        valid = checkpoint(root, temporary_exists, error, error_length);
    }
    (void)close(root);
    return valid;
}
