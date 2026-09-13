#define _POSIX_C_SOURCE 200809L

#include "store.h"

#include "snapshot.h"

#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static atomic_uint_fast64_t temporary_counter = 1;

static bool write_all(int descriptor, const unsigned char *body, size_t length)
{
    size_t used = 0;
    while (used < length) {
        ssize_t result = write(descriptor, body + used, length - used);
        if (result < 0 && errno == EINTR) {
            continue;
        }
        if (result <= 0) {
            return false;
        }
        used += (size_t)result;
    }
    return true;
}

static int open_root(const char *data_dir, char *error, size_t error_length)
{
    int root_fd = open(
        data_dir,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
    );
    if (root_fd < 0) {
        (void)snprintf(error, error_length, "cannot open data directory for writing");
    }
    return root_fd;
}

static int open_collection(
    int root_fd,
    const char *collection,
    bool create,
    bool *created,
    char *error,
    size_t error_length
)
{
    *created = false;
    int collection_fd = openat(
        root_fd,
        collection,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
    );
    if (collection_fd >= 0 || !create || errno != ENOENT) {
        if (collection_fd < 0) {
            (void)snprintf(error, error_length, "cannot open collection for writing");
        }
        return collection_fd;
    }
    if (mkdirat(root_fd, collection, 0700) != 0) {
        (void)snprintf(error, error_length, "cannot create collection durably");
        return -1;
    }
    *created = true;
    if (fsync(root_fd) != 0) {
        (void)unlinkat(root_fd, collection, AT_REMOVEDIR);
        *created = false;
        (void)snprintf(error, error_length, "cannot create collection durably");
        return -1;
    }
    collection_fd = openat(
        root_fd,
        collection,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
    );
    if (collection_fd < 0) {
        (void)unlinkat(root_fd, collection, AT_REMOVEDIR);
        (void)fsync(root_fd);
        *created = false;
        (void)snprintf(error, error_length, "cannot open created collection");
    }
    return collection_fd;
}

static void remove_empty_collection(
    int root_fd,
    const char *collection,
    bool created
)
{
    if (created) {
        (void)unlinkat(root_fd, collection, AT_REMOVEDIR);
        (void)fsync(root_fd);
    }
}

bool yamldb_store_put(
    const char *data_dir,
    const char *collection,
    const char *document,
    const unsigned char *body,
    size_t body_length,
    char *error,
    size_t error_length
)
{
    if (!yamldb_valid_name(collection) || !yamldb_valid_name(document) ||
        body_length == 0 || body_length > YAMLDB_DOCUMENT_LIMIT ||
        !yamldb_valid_document_body(body, body_length)) {
        (void)snprintf(error, error_length, "document write is invalid");
        return false;
    }
    int root_fd = open_root(data_dir, error, error_length);
    if (root_fd < 0) {
        return false;
    }
    bool collection_created = false;
    int collection_fd = open_collection(
        root_fd, collection, true, &collection_created, error, error_length
    );
    if (collection_fd < 0) {
        close(root_fd);
        return false;
    }
    char filename[YAMLDB_NAME_LIMIT + 6];
    (void)snprintf(filename, sizeof(filename), "%s.yaml", document);
    struct stat existing;
    errno = 0;
    int stat_result = fstatat(
        collection_fd, filename, &existing, AT_SYMLINK_NOFOLLOW
    );
    if (stat_result == 0 && !S_ISREG(existing.st_mode)) {
        (void)snprintf(error, error_length, "document destination is not regular");
        close(collection_fd);
        remove_empty_collection(root_fd, collection, collection_created);
        close(root_fd);
        return false;
    }
    if (stat_result != 0 && errno != ENOENT) {
        (void)snprintf(error, error_length, "cannot inspect document destination");
        close(collection_fd);
        remove_empty_collection(root_fd, collection, collection_created);
        close(root_fd);
        return false;
    }

    struct timespec now = {0};
    (void)clock_gettime(CLOCK_MONOTONIC, &now);
    uint64_t counter = atomic_fetch_add_explicit(
        &temporary_counter, 1, memory_order_relaxed
    );
    char temporary[96];
    (void)snprintf(
        temporary,
        sizeof(temporary),
        ".yamldb-%ld-%llu-%llu",
        (long)getpid(),
        (unsigned long long)now.tv_nsec,
        (unsigned long long)counter
    );
    int descriptor = openat(
        collection_fd,
        temporary,
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
        0600
    );
    if (descriptor < 0) {
        (void)snprintf(error, error_length, "cannot create temporary document");
        close(collection_fd);
        remove_empty_collection(root_fd, collection, collection_created);
        close(root_fd);
        return false;
    }
    bool valid = write_all(descriptor, body, body_length) &&
        fsync(descriptor) == 0;
    if (close(descriptor) != 0) {
        valid = false;
    }
    if (!valid) {
        (void)unlinkat(collection_fd, temporary, 0);
        (void)snprintf(error, error_length, "cannot persist complete document");
        close(collection_fd);
        remove_empty_collection(root_fd, collection, collection_created);
        close(root_fd);
        return false;
    }
    if (renameat(collection_fd, temporary, collection_fd, filename) != 0 ||
        fsync(collection_fd) != 0) {
        (void)unlinkat(collection_fd, temporary, 0);
        (void)snprintf(error, error_length, "cannot publish document atomically");
        close(collection_fd);
        remove_empty_collection(root_fd, collection, collection_created);
        close(root_fd);
        return false;
    }
    close(collection_fd);
    close(root_fd);
    return true;
}

bool yamldb_store_delete(
    const char *data_dir,
    const char *collection,
    const char *document,
    char *error,
    size_t error_length
)
{
    if (!yamldb_valid_name(collection) || !yamldb_valid_name(document)) {
        (void)snprintf(error, error_length, "document delete is invalid");
        return false;
    }
    int root_fd = open_root(data_dir, error, error_length);
    if (root_fd < 0) {
        return false;
    }
    bool collection_created = false;
    int collection_fd = open_collection(
        root_fd, collection, false, &collection_created, error, error_length
    );
    if (collection_fd < 0) {
        close(root_fd);
        return false;
    }
    char filename[YAMLDB_NAME_LIMIT + 6];
    (void)snprintf(filename, sizeof(filename), "%s.yaml", document);
    struct stat status;
    if (fstatat(collection_fd, filename, &status, AT_SYMLINK_NOFOLLOW) != 0 ||
        !S_ISREG(status.st_mode)) {
        (void)snprintf(error, error_length, "document destination is unavailable");
        close(collection_fd);
        close(root_fd);
        return false;
    }
    if (unlinkat(collection_fd, filename, 0) != 0 || fsync(collection_fd) != 0) {
        (void)snprintf(error, error_length, "cannot delete document durably");
        close(collection_fd);
        close(root_fd);
        return false;
    }
    close(collection_fd);
    close(root_fd);
    return true;
}
