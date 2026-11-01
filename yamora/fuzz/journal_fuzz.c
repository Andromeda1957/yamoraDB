#define _POSIX_C_SOURCE 200809L

#include "../src/journal.h"
#include "filesystem.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#define JOURNAL_FUZZ_INPUT_LIMIT (2u * 1024u * 1024u)

static bool write_all(int descriptor, const unsigned char *bytes, size_t length)
{
    size_t used = 0;
    while (used < length) {
        ssize_t count = write(descriptor, bytes + used, length - used);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            return false;
        }
        used += (size_t)count;
    }
    return true;
}

static bool read_input(const char *path, unsigned char **input, size_t *length)
{
    *input = NULL;
    *length = 0;
    int descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (descriptor < 0) {
        return false;
    }
    struct stat status;
    if (fstat(descriptor, &status) != 0 || !S_ISREG(status.st_mode) ||
        status.st_size < 0 || status.st_size > (off_t)JOURNAL_FUZZ_INPUT_LIMIT) {
        (void)close(descriptor);
        return false;
    }
    size_t expected = (size_t)status.st_size;
    unsigned char *bytes = malloc(expected == 0 ? 1 : expected);
    if (bytes == NULL) {
        (void)close(descriptor);
        return false;
    }
    size_t used = 0;
    while (used < expected) {
        ssize_t count = read(descriptor, bytes + used, expected - used);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            free(bytes);
            (void)close(descriptor);
            return false;
        }
        used += (size_t)count;
    }
    (void)close(descriptor);
    *input = bytes;
    *length = used;
    return true;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        return 2;
    }
    unsigned char *input = NULL;
    size_t input_length = 0;
    if (!read_input(argv[1], &input, &input_length)) {
        return 0;
    }
    char data_dir[PATH_MAX];
    if (!yd_fuzz_data_dir(data_dir, "journal-fuzz")) {
        free(input);
        return 0;
    }
    char journal[PATH_MAX];
    int length = snprintf(journal, sizeof(journal), "%s/%s", data_dir, YAMLDB_JOURNAL_NAME);
    if (length > 0 && (size_t)length < sizeof(journal)) {
        int descriptor = open(
            journal,
            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
            0600
        );
        if (descriptor >= 0) {
            if (write_all(descriptor, input, input_length)) {
                char error[256];
                (void)yd_journal_recover(data_dir, true, error, sizeof(error));
            }
            (void)close(descriptor);
        }
    }
    yd_fuzz_remove_data_dir(data_dir);
    free(input);
    return 0;
}
