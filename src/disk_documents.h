#ifndef YAMORA_DISK_DOCUMENTS_H
#define YAMORA_DISK_DOCUMENTS_H
#include "disk.h"
#include "snapshot.h"
#include "schema/policy_store.h"

typedef struct {
    char collection[YAMLDB_NAME_LIMIT + 1], id[YAMLDB_NAME_LIMIT + 1];
    unsigned char *body;
    size_t length;
    YDValue *value;
    uint64_t hash, record;
    bool owns_body;
} YDDiskDocument;
typedef struct {
    /* Vector definition borrowed from YDDiskIndexes.spec, or NULL. Vector
     * indexes also set text, so every typed-index guard covers them. */
    const YDValue *vector;
    const char *collection, *name, *fields[8];
    size_t count;
    bool unique, text;
    /* Optional, borrowed from YDDiskIndexes.spec. Only matching documents
     * have entries; expire_after is meaningful only when ttl is set. */
    const YDValue *partial;
    bool ttl;
    int64_t expire_after;
    /* Geospatial cell postings (also typed, so text is set); see geo.h. */
    bool geo;
} YDDiskIndex;
typedef struct {
    YDValue *spec;
    YDDiskIndex indexes[64];
    size_t count;
} YDDiskIndexes;

size_t yd_disk_document_key(unsigned char key[YD_DISK_KEY_LIMIT], const char *collection,
                            const char *id);
size_t yd_disk_collection_key(unsigned char key[YD_DISK_KEY_LIMIT], const char *collection);
uint64_t yd_disk_source_hash(const void *body, size_t size);
uint64_t yd_disk_fingerprint(const char *collection, const char *id, const void *body, size_t size);
void yd_disk_revision(const YDDiskView *view, char revision[17]);
void yd_disk_document_free(YDDiskDocument *document);
int yd_disk_document_get(YDDisk *disk, const YDDiskView *view, const char *collection,
                         const char *id, YDDiskDocument *document, char *error, size_t length);
int yd_disk_document_tx_get(YDDiskTxn *txn, const char *collection, const char *id,
                            YDDiskDocument *document, char *error, size_t length);
bool yd_disk_document_at(YDDisk *disk, const YDDiskView *view, uint64_t record,
                         YDDiskDocument *document, char *error, size_t length);
/* Bounded untrusted metadata peek for precharging scan source bytes. The
 * caller must still use document_at and compare the fully verified length. */
bool yd_disk_document_source_length(YDDisk *disk, const YDDiskView *view, uint64_t record,
                                    size_t *source_length, char *error, size_t length);
bool yd_disk_create_collection(YDDiskTxn *txn, const char *collection, char *error, size_t length);
/* Remove one existing collection whose document count is already zero in this
 * transaction. The commit becomes a change-feed resnapshot boundary because
 * incremental frames represent collection creation but not removal. */
bool yd_disk_drop_collection(YDDiskTxn *txn, const char *collection, char *error, size_t length);
/* Apply at most 128 source operations; indexes and records share the same root.
 * Caller commits on success and aborts on any failure. */
bool yd_disk_apply(YDDiskTxn *txn, const YDWrite *writes, size_t count, char *error, size_t length);
/* Request-aware admission. Initialize work once OUTSIDE retry/operation loops.
 * Checks every final replacement before any index/document mutation; callers
 * abort on failure. The original bool API initializes one single-call pool. */
YDPolicyResult yd_disk_apply_with_policy(YDDiskTxn *txn, const YDWrite *writes,
    size_t count, YDPolicyWork *work, char *error, size_t length);
/* Used by index catalog publication after removing/rebuilding index entries. */
bool yd_disk_write_document(YDDiskTxn *txn, const YDDiskDocument *old, YDDiskDocument *replacement,
                            char *error, size_t length);

YDDiskIndexes *yd_disk_indexes_load(YDDisk *disk, const YDDiskView *view, char *error,
                                    size_t length);
YDDiskIndexes *yd_disk_indexes_load_tx(YDDiskTxn *txn, char *error, size_t length);
YDDiskIndexes *yd_disk_indexes_parse(const YDValue *spec, char *error, size_t length);
void yd_disk_indexes_free(YDDiskIndexes *indexes);
bool yd_disk_indexes_change(YDDiskTxn *txn, const YDDiskIndexes *indexes,
                            const YDDiskDocument *document, bool adding, char *error,
                            size_t length);
/* A fresh maintenance transaction prevents a catalog scan from rebasing stale
 * index entries over concurrently replaced documents. */
bool yd_disk_indexes_replace(YDDiskTxn *txn, const unsigned char *source, size_t size, char *error,
                             size_t length);
typedef bool (*YDIndexProgress)(void *context, const char *phase);
/* Internal maintenance primitives: prepare and scan a private root without
 * changing its source catalog; install the catalog only after catch-up. */
YDDiskIndexes *yd_disk_indexes_prepare(YDDiskTxn *txn, const unsigned char *source, size_t size,
                                      char *error, size_t length);
bool yd_disk_indexes_build_root(YDDiskTxn *txn, const YDDiskIndexes *indexes,
                                YDIndexProgress progress, void *context, char *error, size_t length);
bool yd_disk_indexes_install(YDDiskTxn *txn, const YDDiskIndexes *indexes,
                             const unsigned char *source, size_t size, char *error, size_t length);
/* Order-preserving tuple prefix. Numeric ints/floats use the shared value
 * model's comparison order. Missing fields and empty arrays have sentinels. */
bool yd_disk_index_prefix(const YDDiskIndex *index, const YDValue *const *values, size_t count,
                          unsigned char key[YD_DISK_KEY_LIMIT], size_t *size, char *error,
                          size_t length);
int yd_disk_index_canonical(const YDDiskIndex *index, const YDDiskDocument *document,
                            const unsigned char *lower, size_t ln, const unsigned char *upper,
                            size_t un, const unsigned char *current, size_t cn, char *error,
                            size_t length);
bool yd_disk_rebuild_indexes(YDDiskTxn *txn, char *error, size_t length);
bool yd_disk_indexes_verify_document(YDDisk *disk, const YDDiskView *view,
                                     const YDDiskIndexes *indexes, const YDDiskDocument *doc,
                                     uint64_t text_counts[64], char *error, size_t length);
bool yd_disk_index_entry_valid(const YDDiskIndexes *indexes, const YDDiskDocument *doc,
                               const unsigned char *key, size_t size, char *error, size_t length);
#endif
