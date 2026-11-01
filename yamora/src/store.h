#ifndef YAMLDB_STORE_H
#define YAMLDB_STORE_H

#include <stdbool.h>
#include <stddef.h>

bool yamldb_store_temporary_name(const char *name);

/* Legacy YAML/binary-file mutations refuse any schema-policy catalog before
 * creating collections, temporary files, renaming or deleting documents.
 * Policy-free file-store behavior is unchanged. Native policies require the
 * operational native API; these wrappers cannot administer or admit them. */
bool yamldb_store_put(
    const char *data_dir,
    const char *collection,
    const char *document,
    const unsigned char *body,
    size_t body_length,
    bool *published,
    char *error,
    size_t error_length
);

bool yamldb_store_delete(
    const char *data_dir,
    const char *collection,
    const char *document,
    bool *published,
    char *error,
    size_t error_length
);

#endif
