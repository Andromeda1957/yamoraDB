#ifndef YAMLDB_COMPRESSION_H
#define YAMLDB_COMPRESSION_H

#include <stdbool.h>
#include <stddef.h>

bool yamldb_gzip_compress(
    const unsigned char *input,
    size_t input_length,
    unsigned char **output,
    size_t *output_length,
    char *error,
    size_t error_length
);

#endif
