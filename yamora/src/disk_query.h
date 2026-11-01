#ifndef YAMORA_DISK_QUERY_H
#define YAMORA_DISK_QUERY_H
#include "disk_documents.h"
#include "query.h"
/* Bounded page heap, one decoded candidate, and an immutable pinned root.
 * No allocation depends on the collection's document count. */
char *yd_disk_query(YDDisk *disk, const YDDiskView *view, const char *collection,
                    const YDValue *spec, size_t *size, char *error, size_t length);
/* IDs of documents matching plan's filter in the transaction's view, using the
 * same index plans as yd_disk_query. first keeps only the least ID; otherwise
 * at most capacity IDs, ascending. Source bytes and evaluation debit *work.
 * Returns 1, 0 when the work or ID bound is exceeded, or -1 on failure. */
int yd_disk_query_tx_matches(YDDiskTxn *txn, const char *collection, const YDQueryPlan *plan,
                             size_t *work, bool first, char ids[][YAMLDB_NAME_LIMIT + 1],
                             size_t capacity, size_t *count, char *error, size_t length);
/* The query route's own index choice, for other readers of the same plan.
 * index NULL selects the collection's primary ID range. Each range is a
 * half-open key interval; ordered means one range already yields the plan's
 * sort order. Free with yd_disk_query_selection_free after success. */
typedef struct {
    unsigned char lower[YD_DISK_KEY_LIMIT], upper[YD_DISK_KEY_LIMIT];
    size_t lower_size, upper_size;
} YDDiskQueryRange;
typedef struct {
    const YDDiskIndex *index;
    YDDiskQueryRange *ranges;
    size_t count;
    bool ordered;
} YDDiskQuerySelection;
bool yd_disk_query_select(const YDQueryPlan *plan, const YDDiskIndexes *indexes,
                          const char *collection, YDDiskQuerySelection *selection, char *error,
                          size_t length);
void yd_disk_query_selection_free(YDDiskQuerySelection *selection);
#endif
