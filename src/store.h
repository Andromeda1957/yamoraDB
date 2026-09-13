#ifndef YAMLDB_STORE_H
#define YAMLDB_STORE_H

#include <stdbool.h>
#include <stddef.h>

bool yamldb_store_put(
    const char *data_dir,
    const char *collection,
    const char *document,
    const unsigned char *body,
    size_t body_length,
    char *error,
    size_t error_length
);

bool yamldb_store_delete(
    const char *data_dir,
    const char *collection,
    const char *document,
    char *error,
    size_t error_length
);

#endif
