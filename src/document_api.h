#ifndef YAMLDB_DOCUMENT_API_H
#define YAMLDB_DOCUMENT_API_H

#include "snapshot.h"
#include "indexes.h"
#include <pthread.h>

typedef struct {
    YamlDBSnapshot *snapshot;
    YDIndexCatalog *indexes;
    const char *data_dir;
    pthread_rwlock_t *lock;
    bool replica;
    bool writes_failed;
    YamlDBSnapshot *staged;
    YDValue *stage_spec;
    char session[48];
    uint64_t stage_deadline;
    uint64_t serial;
} YDEngine;

typedef struct {
    int status;
    char *body;
    size_t length;
    char etag[48];
} YDReply;

bool yd_engine_init(YDEngine *engine, YamlDBSnapshot *snapshot, const char *data_dir,
                    bool replica, pthread_rwlock_t *lock, char *error, size_t length);
void yd_engine_destroy(YDEngine *engine);
/* Policy-bearing legacy snapshots are unsupported, including an off/empty or
 * malformed reserved policy document. Initialization and mutation fail before
 * filesystem publication; policy-free callers retain the existing wrappers.
 * The daemon serializes mutations with its writer mutex. Query callers hold a
 * read lock. Publication alone acquires the engine's snapshot write lock. */
YDReply yd_engine_request(YDEngine *engine, const char *method, const char *target,
                         const unsigned char *body, size_t length,
                         const char *if_match, const char *if_none_match);
YDReply yd_engine_document(YDEngine *engine, const char *method,
                          const char *collection, const char *document,
                          const unsigned char *body, size_t length,
                          const char *if_match, const char *if_none_match);
void yd_reply_free(YDReply *reply);

#endif
