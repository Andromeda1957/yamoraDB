#ifndef YAMLDB_JOURNAL_H
#define YAMLDB_JOURNAL_H

#include <stdbool.h>
#include <stddef.h>

#define YAMLDB_JOURNAL_NAME ".yamldb-journal"
#define YAMLDB_JOURNAL_TEMP_NAME ".yamldb-journal-tmp"
#define YD_JOURNAL_OPERATION_LIMIT 101000u
#define YD_JOURNAL_BODY_LIMIT (256u * 1024u * 1024u)

typedef enum {
    YD_WRITE_DOCUMENT = 0,
    YD_WRITE_CREATE_COLLECTION = 1,
    YD_WRITE_DELETE_COLLECTION = 2,
    /* Native disk only: delete every document, then the collection. The
     * journal and snapshot backends reject it like any unknown kind. */
    YD_WRITE_PURGE_COLLECTION = 3
} YDWriteKind;

typedef struct {
    const char *collection;
    const char *document;
    const unsigned char *body;
    size_t length;
    YDWriteKind kind;
} YDWrite;

/* Caller holds the root's lifetime-exclusive writer lock and has prepared and
 * validated its logical candidate before committing. Returns true only after
 * every change and the checkpoint are durable. `committed` becomes true when
 * the journal is published, INCLUDING an uncertain directory-fsync result:
 * false + committed means publish the prepared candidate and prohibit further
 * writes until recovery. false + !committed made no document/collection changes.
 * A NULL document body deletes that document (length must be zero). Collection
 * operations require document/body NULL and length zero; removal is empty-only.
 */
bool yd_journal_commit(
    const char *data_dir, const YDWrite *writes, size_t count,
    bool *committed, char *error, size_t error_length
);

/* Call before snapshot load, under the same root lock. Read-only startup
 * refuses any published journal. Writable startup validates the entire bounded
 * journal before replay and checkpoints only after all operations are durable.
 */
bool yd_journal_recover(
    const char *data_dir, bool writable, char *error, size_t error_length
);

/* Only these exact reserved root names may be ignored by the snapshot loader. */
bool yd_journal_internal_name(const char *name);

#endif
