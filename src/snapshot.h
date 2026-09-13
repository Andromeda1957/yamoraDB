#ifndef YAMLDB_SNAPSHOT_H
#define YAMLDB_SNAPSHOT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define YAMLDB_NAME_LIMIT 128
#define YAMLDB_DOCUMENT_LIMIT (256 * 1024)
#define YAMLDB_COLLECTION_LIMIT 256
#define YAMLDB_SNAPSHOT_DOCUMENT_LIMIT 50000
#define YAMLDB_COLLECTION_DOCUMENT_LIMIT YAMLDB_SNAPSHOT_DOCUMENT_LIMIT
#define YAMLDB_SNAPSHOT_BYTES_LIMIT (256 * 1024 * 1024)

typedef struct {
    char *name;
    unsigned char *body;
    size_t length;
    unsigned char *gzip_body;
    size_t gzip_length;
    uint64_t hash;
} YamlDBDocument;

typedef struct {
    char *name;
    YamlDBDocument *documents;
    size_t document_count;
    char *index_body;
    size_t index_length;
} YamlDBCollection;

typedef struct {
    YamlDBCollection *collections;
    size_t collection_count;
    size_t document_count;
    size_t byte_count;
    size_t compressed_byte_count;
    uint64_t revision_hash;
    char revision[17];
    char *collection_index_body;
    size_t collection_index_length;
} YamlDBSnapshot;

bool yamldb_snapshot_load(
    const char *data_dir,
    YamlDBSnapshot *snapshot,
    char *error,
    size_t error_length
);
void yamldb_snapshot_free(YamlDBSnapshot *snapshot);
const YamlDBCollection *yamldb_snapshot_collection(
    const YamlDBSnapshot *snapshot,
    const char *name
);
const YamlDBDocument *yamldb_collection_document(
    const YamlDBCollection *collection,
    const char *name
);
bool yamldb_valid_name(const char *value);
bool yamldb_valid_document_body(const unsigned char *value, size_t length);

#endif
