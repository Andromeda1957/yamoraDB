#define _POSIX_C_SOURCE 200809L
#include "runtime.h"
#include "../aggregate.h"
#include "../query.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* A deadline wraps the caller's cancellation for every router and the native
 * reducer, so one expiry stops shard paging, foreign feeding and joining. */
typedef struct {
    YDShardCancelled cancelled; void *context;
    struct timespec end; bool timed, expired, caller;
} Deadline;
static bool deadline_cancelled(void *p) {
    Deadline *d = p;
    if (d->cancelled && d->cancelled(d->context)) return d->caller = true;
    if (!d->timed) return false;
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return d->expired = true;
    if (now.tv_sec > d->end.tv_sec || (now.tv_sec == d->end.tv_sec && now.tv_nsec >= d->end.tv_nsec))
        d->expired = true;
    return d->expired;
}
/* The reducer reports its own cancellation as a failed feed; name the cause. */
static YDShardStatus stopped(const Deadline *d, YDShardStatus s) {
    if (s != YD_SHARD_CANCELLED && s != YD_SHARD_BUDGET_EXCEEDED) return s;
    return d->caller ? YD_SHARD_CANCELLED : d->expired ? YD_SHARD_DEADLINE_EXCEEDED : s;
}
static const YDValue *stage_spec(const YDValue *stage, const char *name) {
    return stage && stage->type == YD_MAP && stage->count == 1 && !strcmp(stage->keys[0], name) ?
        stage->items[0] : NULL;
}
/* The i-th top-level $lookup stage, its pipeline position, and whether only
 * $match stages precede it, so the input documents' raw key values are the
 * values the join will see. */
static const YDValue *lookup_stage(const YDValue *pipeline, size_t index, size_t *position, bool *only_matches) {
    *only_matches = true;
    *position = 0;
    if (!pipeline || pipeline->type != YD_ARRAY) return NULL;
    for (size_t i = 0, seen = 0; i < pipeline->count; i++) {
        const YDValue *spec = stage_spec(pipeline->items[i], "$lookup");
        if (spec && seen++ == index) { *position = i; return spec; }
        if (!stage_spec(pipeline->items[i], "$match")) *only_matches = false;
    }
    return NULL;
}
/* 1 when the document passes every $match before position, 0 when one rejects
 * it, -1 when the native evaluator cannot decide (targeting is then dropped).
 * This is the same evaluator the reducer's $match stages use. */
static int leading_matches(const YDValue *pipeline, size_t position, const YDValue *doc) {
    for (size_t i = 0; i < position; i++) {
        const YDValue *spec = stage_spec(pipeline->items[i], "$match");
        if (!spec) return -1;
        char *keys[] = {"filter"};
        YDValue *items[] = {(YDValue *)spec};
        YDValue query = {.type = YD_MAP, .keys = keys, .items = items, .count = 1};
        YDQueryPlan plan;
        const YDValue *values[8] = {0};
        char error[128];
        if (!yd_query_plan(&query, "", &plan, error, sizeof(error))) return -1;
        int result = yd_query_evaluate(&plan, doc, values, error, sizeof(error));
        if (result <= 0) return result < 0 ? -1 : 0;
    }
    return 1;
}
static const char *text(const YDValue *map, const char *name) {
    const YDValue *v = yd_get(map, name);
    return v && v->type == YD_STRING ? v->scalar : NULL;
}
static void identity(YDShardRouter *r, const char **id, const char **collection, uint64_t *epoch) {
    const YDShardPlacement *p = yd_shard_control_placement(r ? r->control : NULL);
    *id = yd_shard_placement_id(p);
    *collection = yd_shard_placement_collection(p);
    *epoch = yd_shard_placement_epoch(p);
}
/* Select the foreign ranges that can hold a match. Returns false when the
 * relation cannot be targeted (it is then a full bounded scatter). */
static bool target(const YDShardPlacement *p, const YDValue *pipeline, size_t position,
    const char *foreign_field, const char *local_field, const YDShardPage *input, bool *only) {
    if (yd_shard_placement_fields(p) != 1 || strcmp(yd_shard_placement_field_at(p, 0), foreign_field))
        return false;
    size_t ranges = yd_shard_placement_ranges(p);
    memset(only, 0, ranges * sizeof(*only));
    for (size_t i = 0; i < input->count; i++) {
        YDValue *doc = yd_parse(input->rows[i].source, input->rows[i].length, NULL, 0);
        if (!doc) return false;
        int reaches = leading_matches(pipeline, position, doc);
        if (reaches <= 0) { yd_free(doc); if (reaches < 0) return false; continue; }
        const YDValue *v = yd_path(doc, local_field);
        /* Floats compare numerically with integers in the native comparator but
         * have no shard-key encoding; containers fail the join itself. */
        bool usable = !v || v->type == YD_NULL || v->type == YD_BOOL || v->type == YD_INT || v->type == YD_STRING;
        YDShardKey key;
        YDShardStatus s = YD_SHARD_MISSING_KEY;
        if (usable && v && v->type != YD_NULL)
            s = yd_shard_placement_key_version(p) == 1 ? yd_shard_key_encode(v, &key)
                : yd_shard_compound_key_encode(&v, 1, &key);
        uint64_t token = 0;
        /* A value without a valid key encoding (over-long or invalid text)
         * cannot equal any stored shard key, so it selects no range. */
        if (s == YD_SHARD_OK && yd_shard_key_token(&key, &token) == YD_SHARD_OK) {
            for (size_t r = 0; r < ranges; r++) {
                YDShardRange range;
                if (yd_shard_placement_range(p, r, &range) && token >= range.first && token <= range.last) {
                    only[r] = true; break;
                }
            }
        }
        yd_free(doc);
        if (!usable) return false;
    }
    return true;
}
static YDShardStatus feed_rows(YDAggregate *a, YDShardRouter *r, const YDShardPage *page, size_t relation,
    bool foreign, char *error, size_t error_length) {
    for (size_t i = 0; i < page->count; i++) {
        if (r->cancelled && r->cancelled(r->cancel_context)) return YD_SHARD_CANCELLED;
        const YDShardRow *row = &page->rows[i];
        YDValue *v = yd_parse(row->source, row->length, NULL, 0);
        if (!v) return YD_SHARD_CORRUPT;
        size_t held = yd_memory(v) + row->length;
        if (!yd_aggregate_record_work(a, row->length, error, error_length) ||
            !yd_aggregate_hold(a, held, error, error_length)) {
            yd_free(v);
            return YD_SHARD_BUDGET_EXCEEDED;
        }
        bool ok = foreign ? yd_aggregate_foreign_feed_at(a, relation, v, error, error_length)
                          : yd_aggregate_feed(a, v, error, error_length);
        yd_aggregate_release(a, held);
        yd_free(v);
        if (!ok) return YD_SHARD_BUDGET_EXCEEDED;
    }
    return YD_SHARD_OK;
}
YDShardStatus yd_shard_aggregate_join(YDShardRouter *router, const char *id, const char *collection,
    uint64_t epoch, const YDValue *pipeline, const YDShardJoinLimits *limits, char **json, size_t *length,
    YDShardJoinStats *stats, char *error, size_t error_length) {
    if (!json || !length) return YD_SHARD_INVALID_ARGUMENT;
    *json = NULL;
    *length = 0;
    YDShardJoinStats local_stats;
    if (!stats) stats = &local_stats;
    memset(stats, 0, sizeof(*stats));
    if (!router || !limits || !collection || !limits->max_matches || limits->max_matches > 1024 ||
        limits->max_time_ms > 30000 || limits->max_foreign_rows > YD_SHARD_GATHER_ROWS ||
        limits->max_foreign_bytes > YD_SHARD_GATHER_BYTES)
        return YD_SHARD_INVALID_ARGUMENT;
    if (!router->authorize || !router->authorize(router->auth_context, collection, false)) return YD_SHARD_FORBIDDEN;
    YDAggregate *aggregate = yd_aggregate_new(pipeline, error, error_length);
    if (!aggregate) return YD_SHARD_INVALID_ARGUMENT;
    Deadline deadline = {.cancelled = router->cancelled, .context = router->cancel_context, .timed = limits->max_time_ms > 0};
    if (deadline.timed) {
        clock_gettime(CLOCK_MONOTONIC, &deadline.end);
        deadline.end.tv_sec += (time_t)(limits->max_time_ms / 1000);
        deadline.end.tv_nsec += (long)(limits->max_time_ms % 1000) * 1000000L;
        if (deadline.end.tv_nsec >= 1000000000L) { deadline.end.tv_sec++; deadline.end.tv_nsec -= 1000000000L; }
    }
    YDQueryControl control = {.cancelled = deadline_cancelled, .context = &deadline, .fanout_limit = limits->max_matches};
    yd_aggregate_control(aggregate, &control);
    YDShardRouter local = *router;
    local.cancelled = deadline_cancelled;
    local.cancel_context = &deadline;
    YDShardRouter *foreign[YD_SHARD_JOIN_RELATIONS] = {0};
    YDShardResult input = {0};
    YDShardStatus s = YD_SHARD_OK;
    size_t relations = 0;
    while (yd_aggregate_lookup_collection_at(aggregate, relations)) relations++;
    if (relations > YD_SHARD_JOIN_RELATIONS) { s = YD_SHARD_INVALID_ARGUMENT; goto done; }
    if (relations && (!limits->max_foreign_rows || !limits->max_foreign_bytes)) { s = YD_SHARD_INVALID_ARGUMENT; goto done; }
    stats->relations = relations;
    /* Authorize and resolve every relation before any shard call. */
    for (size_t i = 0; i < relations; i++) {
        const char *from = yd_aggregate_lookup_collection_at(aggregate, i);
        YDShardJoinRelation *rel = &stats->relation[i];
        snprintf(rel->collection, sizeof(rel->collection), "%s", from);
        if (!router->authorize(router->auth_context, from, false)) { s = YD_SHARD_FORBIDDEN; goto done; }
        if (!strcmp(from, collection)) { rel->local = true; continue; }
        if (!router->resolve) { s = YD_SHARD_CROSS_SHARD_UNSUPPORTED; goto done; }
        s = router->resolve(router->resolve_context, from, &foreign[i]);
        if (s != YD_SHARD_OK || !foreign[i] || !yd_shard_control_placement(foreign[i]->control) ||
            strcmp(yd_shard_placement_collection(yd_shard_control_placement(foreign[i]->control)), from)) {
            if (s == YD_SHARD_OK) s = YD_SHARD_STALE_PLACEMENT;
            goto done;
        }
    }
    YDShardQuery query = {.limit = limits->max_rows, .max_rows = limits->max_rows, .max_bytes = limits->max_bytes};
    s = yd_shard_gather(&local, id, collection, epoch, &query, &input);
    if (s != YD_SHARD_OK) goto done;
    stats->input_rows = input.visited;
    stats->input_bytes = input.bytes;
    stats->input_shards = input.shards;
    size_t rows_left = limits->max_foreign_rows, bytes_left = limits->max_foreign_bytes;
    for (size_t i = 0; i < relations; i++) {
        YDShardJoinRelation *rel = &stats->relation[i];
        if (rel->local) {
            /* A self lookup reads exactly the input's shard views. */
            if (input.page.count > rows_left || input.page.bytes > bytes_left) { s = YD_SHARD_BUDGET_EXCEEDED; goto done; }
            rows_left -= input.page.count;
            bytes_left -= input.page.bytes;
            rel->rows = input.page.count;
            rel->bytes = input.page.bytes;
            rel->shards = rel->ranges = input.shards;
            s = feed_rows(aggregate, &local, &input.page, i, true, error, error_length);
        } else {
            YDShardRouter remote = *foreign[i];
            remote.cancelled = deadline_cancelled;
            remote.cancel_context = &deadline;
            const YDShardPlacement *p = yd_shard_control_placement(remote.control);
            size_t ranges = yd_shard_placement_ranges(p);
            bool only[YD_SHARD_RANGE_LIMIT], before_only_matches = false;
            size_t position = 0;
            const YDValue *spec = lookup_stage(pipeline, i, &position, &before_only_matches);
            const char *foreign_field = text(spec, "foreignField"), *local_field = text(spec, "localField");
            rel->ranges = ranges;
            rel->targeted = before_only_matches && foreign_field && local_field &&
                target(p, pipeline, position, foreign_field, local_field, &input.page, only);
            size_t selected = 0;
            for (size_t r = 0; rel->targeted && r < ranges; r++) selected += only[r];
            YDShardResult result = {0};
            if (!rel->targeted || selected) {
                if (!rows_left || !bytes_left) { s = YD_SHARD_BUDGET_EXCEEDED; goto done; }
                const char *fid, *fcollection;
                uint64_t fepoch;
                identity(&remote, &fid, &fcollection, &fepoch);
                YDShardQuery fq = {.limit = rows_left, .max_rows = rows_left, .max_bytes = bytes_left,
                    .only = rel->targeted ? only : NULL, .only_count = rel->targeted ? ranges : 0};
                s = yd_shard_gather(&remote, fid, fcollection, fepoch, &fq, &result);
                if (s != YD_SHARD_OK) goto done;
                rows_left -= result.visited;
                bytes_left -= result.bytes;
            }
            rel->rows = result.visited;
            rel->bytes = result.bytes;
            rel->shards = result.shards;
            s = feed_rows(aggregate, &remote, &result.page, i, true, error, error_length);
            yd_shard_page_free(&result.page);
        }
        if (s != YD_SHARD_OK) goto done;
        if (!yd_aggregate_foreign_end_at(aggregate, i, error, error_length)) { s = YD_SHARD_BUDGET_EXCEEDED; goto done; }
    }
    s = feed_rows(aggregate, &local, &input.page, 0, false, error, error_length);
    if (s == YD_SHARD_OK) {
        *json = yd_aggregate_json(aggregate, length, error, error_length);
        if (!*json) s = YD_SHARD_BUDGET_EXCEEDED;
    }
done:
    s = stopped(&deadline, s);
    if (s == YD_SHARD_DEADLINE_EXCEEDED && error && error_length)
        snprintf(error, error_length, "lookup max_time_ms exceeded");
    if (s != YD_SHARD_OK) {
        free(*json);
        *json = NULL;
        *length = 0;
    }
    yd_shard_page_free(&input.page);
    for (size_t i = 0; i < YD_SHARD_JOIN_RELATIONS; i++)
        if (foreign[i] && router->release) router->release(router->resolve_context, foreign[i]);
    yd_aggregate_free(aggregate);
    return s;
}
YDShardStatus yd_shard_aggregate(YDShardRouter *router, const char *id, const char *collection,
    uint64_t epoch, const YDValue *pipeline, size_t max_rows, size_t max_bytes,
    char **json, size_t *length, char *error, size_t error_length) {
    YDShardJoinLimits limits = {.max_rows = max_rows, .max_bytes = max_bytes,
        .max_foreign_rows = YD_SHARD_GATHER_ROWS, .max_foreign_bytes = YD_SHARD_GATHER_BYTES,
        .max_matches = 1024};
    return yd_shard_aggregate_join(router, id, collection, epoch, pipeline, &limits, json, length,
        NULL, error, error_length);
}
