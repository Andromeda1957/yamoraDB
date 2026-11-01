#define _POSIX_C_SOURCE 200809L

#include "../src/compression.h"
#include "../src/snapshot.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static bool read_input(
    const char *path,
    unsigned char **input,
    size_t *input_length
)
{
    *input = NULL;
    *input_length = 0;
    int descriptor = open(path, O_RDONLY | O_CLOEXEC);
    if (descriptor < 0) {
        return false;
    }
    struct stat status;
    if (fstat(descriptor, &status) != 0 || status.st_size < 0 ||
        status.st_size > YAMLDB_DOCUMENT_LIMIT) {
        close(descriptor);
        return false;
    }
    size_t length = (size_t)status.st_size;
    unsigned char *buffer = malloc(length == 0 ? 1 : length);
    if (buffer == NULL) {
        close(descriptor);
        return false;
    }
    size_t used = 0;
    while (used < length) {
        ssize_t result = read(descriptor, buffer + used, length - used);
        if (result < 0 && errno == EINTR) {
            continue;
        }
        if (result <= 0) {
            free(buffer);
            close(descriptor);
            return false;
        }
        used += (size_t)result;
    }
    close(descriptor);
    *input = buffer;
    *input_length = length;
    return true;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        return 2;
    }
    unsigned char *input;
    size_t input_length;
    if (!read_input(argv[1], &input, &input_length)) {
        return 0;
    }

    (void)yamldb_valid_document_body(input, input_length);
    char parse_error[256];
    YDValue *parsed = yd_parse(input, input_length, parse_error, sizeof(parse_error));
    if (parsed != NULL) {
        size_t json_length;
        char *json = yd_json(parsed, &json_length);
        free(json);
        yd_free(parsed);
    }
    char name[YAMLDB_NAME_LIMIT + 2];
    size_t name_length = input_length < YAMLDB_NAME_LIMIT + 1 ?
        input_length : YAMLDB_NAME_LIMIT + 1;
    memcpy(name, input, name_length);
    name[name_length] = '\0';
    (void)yamldb_valid_name(name);

    unsigned char *compressed = NULL;
    size_t compressed_length = 0;
    char error[256];
    (void)yamldb_gzip_compress(
        input,
        input_length,
        &compressed,
        &compressed_length,
        error,
        sizeof(error)
    );
    free(compressed);
    free(input);
    return 0;
}
