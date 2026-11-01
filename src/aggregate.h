#ifndef YAMORA_AGGREGATE_H
#define YAMORA_AGGREGATE_H
#include "value.h"

typedef struct YDAggregate YDAggregate;
typedef struct {
    bool (*cancelled)(void *context);
    void *context;
    size_t work_limit; /* zero selects native maximum; cannot raise it */
    size_t fanout_limit; /* $lookup matches per input row; zero selects the native 1024 */
} YDQueryControl;
void yd_aggregate_control(YDAggregate *aggregate, const YDQueryControl *control);
size_t yd_aggregate_work(const YDAggregate *aggregate);
bool yd_aggregate_bounded(const YDAggregate *aggregate);
char *yd_aggregate_explain_json(const YDAggregate *aggregate, char *error, size_t length);
const char *yd_aggregate_lookup_collection_at(const YDAggregate *aggregate, size_t index);
bool yd_aggregate_foreign_feed_at(YDAggregate *aggregate, size_t index,
    const YDValue *document, char *error, size_t length);
bool yd_aggregate_foreign_end_at(YDAggregate *aggregate, size_t index, char *error, size_t length);
/* The request tree must outlive the reducer. Compilation validates every stage,
 * including empty-input branches. Feed borrows one document at a time. */
YDAggregate *yd_aggregate_new(const YDValue *pipeline, char *error, size_t length);
bool yd_aggregate_feed(YDAggregate *aggregate, const YDValue *document, char *error, size_t length);
/* Returns a JSON array. State is capped at 64 MiB, output at 16 MiB. Group, row
 * and sort state stays in memory unless disk use was allowed before feeding. */
char *yd_aggregate_json(YDAggregate *aggregate, size_t *size, char *error, size_t length);
/* Opt one request in to encrypted disk spill (aggregate_spill.h). Fails when the
 * server has no spill directory or max_bytes exceeds its per-request limit;
 * zero selects that limit. Output is identical to the in-memory result. */
bool yd_aggregate_allow_disk_use(YDAggregate *aggregate, unsigned long long max_bytes,
                                 char *error, size_t length);
/* The root's $match filters before its first reducer and its input $sort
 * (NULL when absent), borrowed from the request for the disk planner. The
 * reducer still applies every filter to every document it is fed. */
size_t yd_aggregate_input_filters(const YDAggregate *aggregate, const YDValue **filters,
                                  size_t capacity);
const YDValue *yd_aggregate_input_sort(const YDAggregate *aggregate);
/* The caller feeds root input already in input-$sort order with ties in
 * document-ID order, so the reducer skips buffering. Each document is checked
 * against its predecessor and an out-of-order document fails the request. */
void yd_aggregate_input_ordered(YDAggregate *aggregate);
size_t yd_aggregate_memory(const YDAggregate *aggregate);
/* Enumerate and authorize every top-level lookup before scanning. The disk
 * caller supplies each foreign relation in ID order before local documents,
 * all from its selected immutable view. Unindexed functions select relation 0. */
const char *yd_aggregate_lookup_collection(const YDAggregate *aggregate);
bool yd_aggregate_foreign_feed(YDAggregate *aggregate, const YDValue *document,
                                char *error, size_t length);
bool yd_aggregate_foreign_end(YDAggregate *aggregate, char *error, size_t length);
/* Charge a disk document's decoded tree and exact source during its borrowed
 * lifetime, sharing the reducer's state ceiling. Release only a successful hold. */
bool yd_aggregate_hold(YDAggregate *aggregate, size_t bytes, char *error, size_t length);
void yd_aggregate_release(YDAggregate *aggregate, size_t bytes);
/* Native lookup scans charge frame and payload byte counts before reading the
 * payload/checksumming/decoding, including source comments and filtered rows. */
bool yd_aggregate_record_work(YDAggregate *aggregate, size_t bytes, char *error, size_t length);
void yd_aggregate_free(YDAggregate *aggregate);
#endif
