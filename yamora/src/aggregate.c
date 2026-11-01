#define _POSIX_C_SOURCE 200809L
#include "aggregate.h"
#include "aggregate_keys.h"
#include "aggregate_spill.h"
#include "query.h"
#include "query_expression.h"
#include "snapshot.h"
#include <limits.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define STATE_LIMIT (64U * 1024U * 1024U)
#define OUTPUT_LIMIT (16U * 1024U * 1024U)
#define GROUP_LIMIT 65536U
/* Groups or rows one reducer may emit once its state has spilled to disk.
 * Native tests may lower it; production uses the documented bound. */
#ifndef YD_AGGREGATE_SPILLED_GROUPS
#define YD_AGGREGATE_SPILLED_GROUPS (16U * 1024U * 1024U)
#endif
#define SPILL_GROUP_LIMIT ((size_t)YD_AGGREGATE_SPILLED_GROUPS)
#define HASH_SIZE 4096U
#define STAGES 32U
#define ACCUMULATORS 32U
#define FACETS 8U
#define FACET_DEPTH 4U
#ifndef YD_JOIN_WORK_LIMIT
#define YD_JOIN_WORK_LIMIT (16U * 1024U * 1024U)
#endif
#define FANOUT_LIMIT 1024U
typedef enum { MATCH, GROUP, BUCKET, COUNT, SORT, LIMIT, FACET, LOOKUP, SKIP, PROJECT, SET, UNWIND } StageKind;
typedef enum { SUM, AVG, MIN, MAX } AccKind;
typedef struct {
    StageKind kind;
    YDQueryPlan query;
    size_t limit;
    const YDValue *spec;
} Stage;
typedef struct {
    const char *name;
    AccKind kind;
    const YDValue *expression;
} AccSpec;
typedef struct {
    int64_t integer;
    long double sum;
    uint64_t count;
    bool floating;
    YDValue *extreme;
} Acc;
typedef struct Group {
    struct Group *next;
    YDValue *key;
    YDValue *document;
    size_t sort_at;
    Acc values[];
} Group;
typedef struct Foreign {
    struct Foreign *next;
    YDValue *document;
    const YDValue *key;
} Foreign;
/* Sorter records are arrays. Group state: [key, sequence, tag, payload...],
 * ordered by key then sequence. Sorted rows: [sort values..., sequence, row],
 * ordered like the in-memory sort with the sequence breaking ties. */
typedef struct {
    struct YDAggregate *aggregate;
    const YDQueryPlan *sort;
    size_t values;
} Ordering;
enum { STATE_RECORD, INPUT_RECORD, ROW_RECORD };
typedef struct Pipe {
    Stage stages[STAGES];
    size_t count, reduce_at, acc_count, group_count, facet_count;
    AccSpec acc[ACCUMULATORS];
    const YDValue *key, *boundaries, *fallback;
    const char *facet_names[FACETS];
    struct Pipe *facets[FACETS];
    Group *groups[HASH_SIZE];
    const char *from, *local_field, *foreign_field, *as;
    Foreign *foreign[HASH_SIZE], *tails[HASH_SIZE];
    size_t foreign_count;
    bool foreign_ready, rows;
    struct Pipe *next;
    /* depth counts enclosing facets; input_sort indexes a $sort before the reducer. */
    size_t depth, input_sort;
    bool structured, frozen;
    uint64_t input_sequence, spill_sequence;
    Ordering input_order, state_order;
    YDSpillSorter *input, *state;
} Pipe;
struct YDAggregate {
    Pipe *root;
    size_t memory, stages, work;
    bool failed, bounded, emitted;
    const YDValue *pipeline;
    YDQueryControl control;
    YDSpill *spill;
    size_t soft_limit;
    bool input_ordered, has_previous;
    YDValue *previous[8];
};
static const YDValue null_value = {.type = YD_NULL};
static const YDValue one = {.type = YD_INT, .number = 1};
static bool fail(char *error, size_t length, const char *message) {
    if (length)
        snprintf(error, length, "%s", message);
    return false;
}
static bool reserve(YDAggregate *a, size_t bytes, char *error, size_t length) {
    if (bytes > STATE_LIMIT - a->memory)
        return fail(error, length, "aggregation state exceeds 64 MiB");
    a->memory += bytes;
    return true;
}
bool yd_aggregate_hold(YDAggregate *a, size_t bytes, char *error, size_t length) {
    return a && !a->failed && reserve(a, bytes, error, length);
}
void yd_aggregate_release(YDAggregate *a, size_t bytes) { a->memory -= bytes; }
static bool work(YDAggregate *a, size_t units, char *error, size_t length) {
    if (a->control.cancelled && a->control.cancelled(a->control.context))
        return fail(error, length, "aggregation cancelled");
    size_t ceiling = a->control.work_limit && a->control.work_limit < YD_JOIN_WORK_LIMIT
        ? a->control.work_limit : YD_JOIN_WORK_LIMIT;
    if (a->work > ceiling || units > ceiling - a->work)
        return fail(error, length, "lookup work limit exceeded");
    a->work += units;
    return true;
}
bool yd_aggregate_record_work(YDAggregate *a, size_t bytes, char *error, size_t length) {
    if (!a || a->failed)
        return fail(error, length, "aggregation already failed");
    if (!work(a, bytes, error, length)) {
        a->failed = true;
        return false;
    }
    return true;
}
static bool scalar(const YDValue *v) { return v && v->type <= YD_STRING; }
static bool numeric(const YDValue *v) { return v && (v->type == YD_INT || v->type == YD_FLOAT); }
static bool field(const char *name) {
    return name && *name && strlen(name) <= 128 && *name != '$' && !strchr(name, '.');
}
static bool path(const YDValue *v) {
    if (!v || v->type != YD_STRING || !*v->scalar || strlen(v->scalar) > 256 ||
        *v->scalar == '$' || *v->scalar == '.')
        return false;
    for (const char *s = v->scalar; *s; s++)
        if (*s == '.' && (!s[1] || s[1] == '.'))
            return false;
    return true;
}
static bool lookup(Pipe *p, const YDValue *spec, char *error, size_t length) {
    const YDValue *from = yd_get(spec, "from"), *local = yd_get(spec, "localField"),
                  *foreign = yd_get(spec, "foreignField"), *as = yd_get(spec, "as");
    if (!spec || spec->type != YD_MAP || spec->count != 4 || !from ||
        from->type != YD_STRING || !yamldb_valid_name(from->scalar) ||
        !strcmp(from->scalar, "yamldb-system") || !path(local) || !path(foreign) ||
        !as || as->type != YD_STRING || !field(as->scalar))
        return fail(error, length, "lookup requires from/localField/foreignField/as");
    p->from = from->scalar;
    p->local_field = local->scalar;
    p->foreign_field = foreign->scalar;
    p->as = as->scalar;
    return true;
}
static bool expression(const YDValue *v) {
    return yd_expression_validate(v, NULL, 0);
}
static bool evaluate(YDAggregate *a, const YDValue *expr, const YDValue *document,
                     YDValue **out, char *error, size_t length) {
    if (!work(a, 0, error, length)) return false;
    if(expr->type != YD_MAP && expr->type != YD_ARRAY) {
        const YDValue *v=expr->type==YD_STRING && expr->scalar[0]=='$' ? yd_path(document,expr->scalar+1):expr;
        if(a->bounded && !work(a,1+yd_memory(document)/64+yd_memory(v)/64,error,length)) return false;
        if(yd_memory(v)>STATE_LIMIT-a->memory) return fail(error,length,"expression state limit exceeded");
        *out=v?yd_clone(v):NULL;
        return !v || *out || fail(error,length,"aggregation allocation failed");
    }
    size_t ceiling = a->control.work_limit && a->control.work_limit < YD_JOIN_WORK_LIMIT
        ? a->control.work_limit : YD_JOIN_WORK_LIMIT;
    size_t remaining = ceiling - a->work, initial = remaining;
    bool ok = yd_expression_evaluate(expr, document, out, &remaining,
                                    STATE_LIMIT - a->memory, error, length);
    a->work += initial - remaining;
    return ok;
}
static int match(YDAggregate *a, const YDQueryPlan *plan, const YDValue *document,
                  const YDValue *values[8], char *error, size_t length) {
    if (!work(a, 0, error, length)) return -1;
    /* Scalar streaming reducers keep their established source-volume policy.
     * Every bounded segment shares the actual native evaluator cost, including
     * rejecting filters and stages after a sequential reducer. */
    if (!a->bounded && !a->control.work_limit)
        return yd_query_evaluate(plan, document, values, error, length);
    size_t ceiling = a->control.work_limit && a->control.work_limit < YD_JOIN_WORK_LIMIT
        ? a->control.work_limit : YD_JOIN_WORK_LIMIT;
    size_t remaining = ceiling - a->work, initial = remaining;
    int result = yd_query_evaluate_work(plan, document, values, &remaining, error, length);
    a->work += initial - remaining;
    return result;
}
static bool query_option(const char *key, const YDValue *value, YDQueryPlan *plan, char *error,
                         size_t length) {
    char *keys[] = {(char *)key};
    YDValue *items[] = {(YDValue *)value};
    YDValue spec = {.type = YD_MAP, .keys = keys, .items = items, .count = 1};
    return yd_query_plan(&spec, "", plan, error, length);
}
static bool accumulators(Pipe *p, const YDValue *spec, bool group, char *error, size_t length) {
    if (!spec || spec->type != YD_MAP || spec->count > ACCUMULATORS + (group ? 1U : 0U))
        return fail(error, length, "aggregation requires at most 32 accumulators");
    for (size_t i = 0; i < spec->count; i++) {
        if (group && !strcmp(spec->keys[i], "_id"))
            continue;
        const YDValue *v = spec->items[i];
        if (!field(spec->keys[i]) || !strcmp(spec->keys[i], "_id") || v->type != YD_MAP ||
            v->count != 1 || !expression(v->items[0]))
            return fail(error, length, "invalid aggregation accumulator");
        AccSpec *acc = &p->acc[p->acc_count++];
        acc->name = spec->keys[i];
        acc->expression = v->items[0];
        if (!strcmp(v->keys[0], "$sum"))
            acc->kind = SUM;
        else if (!strcmp(v->keys[0], "$avg"))
            acc->kind = AVG;
        else if (!strcmp(v->keys[0], "$min"))
            acc->kind = MIN;
        else if (!strcmp(v->keys[0], "$max"))
            acc->kind = MAX;
        else
            return fail(error, length, "unsupported aggregation accumulator");
    }
    return true;
}
static bool bucket(Pipe *p, const YDValue *spec, char *error, size_t length) {
    if (spec->type != YD_MAP)
        return fail(error, length, "bucket requires a mapping");
    for (size_t i = 0; i < spec->count; i++)
        if (strcmp(spec->keys[i], "groupBy") && strcmp(spec->keys[i], "boundaries") &&
            strcmp(spec->keys[i], "default") && strcmp(spec->keys[i], "output"))
            return fail(error, length, "unknown bucket option");
    p->key = yd_get(spec, "groupBy");
    p->boundaries = yd_get(spec, "boundaries");
    p->fallback = yd_get(spec, "default");
    if (!expression(p->key) || !p->boundaries || p->boundaries->type != YD_ARRAY ||
        p->boundaries->count < 2 || p->boundaries->count > 1024)
        return fail(error, length, "invalid bucket expression or boundaries");
    const YDValue *first = p->boundaries->items[0];
    for (size_t i = 0; i < p->boundaries->count; i++) {
        const YDValue *v = p->boundaries->items[i];
        if (!scalar(v) || v->type == YD_NULL ||
            (!(numeric(first) && numeric(v)) && v->type != first->type))
            return fail(error, length, "bucket boundaries must have one scalar type");
        if (i && yd_compare(p->boundaries->items[i - 1], v) >= 0)
            return fail(error, length, "bucket boundaries must increase");
    }
    if (p->fallback &&
        (!scalar(p->fallback) ||
         (yd_compare(p->fallback, first) >= 0 &&
          yd_compare(p->fallback, p->boundaries->items[p->boundaries->count - 1]) < 0)))
        return fail(error, length, "bucket default must be outside the boundaries");
    const YDValue *output = yd_get(spec, "output");
    if (output)
        return accumulators(p, output, false, error, length);
    p->acc_count = 1;
    p->acc[0] = (AccSpec){.name = "count", .kind = SUM, .expression = &one};
    return true;
}
/* Structured group keys name 1..32 fields, each an ordinary key expression. */
static bool structured_key(const YDValue *spec) {
    if (!spec->count || spec->count > YD_GROUP_KEY_FIELDS)
        return false;
    for (size_t i = 0; i < spec->count; i++)
        if (!field(spec->keys[i]) || !expression(spec->items[i]))
            return false;
    return true;
}
static void free_pipe(Pipe *p);
/* depth counts enclosing facets: lookups only at the root, facets nested to
 * FACET_DEPTH levels. Every branch is compiled before any input is read. */
static Pipe *compile(YDAggregate *a, const YDValue *pipeline, size_t depth, char *error,
                     size_t length) {
    if (!pipeline || pipeline->type != YD_ARRAY || !pipeline->count || pipeline->count > STAGES) {
        fail(error, length, "pipeline requires 1..32 stages");
        return NULL;
    }
    if (!reserve(a, sizeof(Pipe), error, length))
        return NULL;
    Pipe *p = calloc(1, sizeof(*p));
    if (!p) {
        fail(error, length, "aggregation allocation failed");
        return NULL;
    }
    p->reduce_at = SIZE_MAX;
    p->input_sort = SIZE_MAX;
    p->depth = depth;
    /* Attach before validation so every partially compiled facet is recoverable. */
    for (size_t i = 0; i < pipeline->count; i++) {
        if (++a->stages > 64) {
            fail(error, length, "at most 64 total aggregation stages");
            goto bad;
        }
        const YDValue *entry = pipeline->items[i];
        if (entry->type != YD_MAP || entry->count != 1) {
            fail(error, length, "each aggregation stage needs exactly one operator");
            goto bad;
        }
        Stage *stage = &p->stages[p->count++];
        const char *name = entry->keys[0];
        const YDValue *v = entry->items[0];
        if (!strcmp(name, "$match")) {
            stage->kind = MATCH;
            if (!query_option("filter", v, &stage->query, error, length))
                goto bad;
            continue;
        }
        if (!strcmp(name, "$project") || !strcmp(name, "$skip")) {
            if (p->reduce_at == SIZE_MAX) {
                fail(error, length, "project/skip require a preceding materialization or reducer");
                goto bad;
            }
            if (!strcmp(name, "$project")) {
                stage->kind = PROJECT;
                if (i+1 != pipeline->count || !query_option("projection", v, &stage->query, error, length)) {
                    fail(error, length, "lookup project must be terminal with field paths");
                    goto bad;
                }
            } else {
                stage->kind = SKIP;
                if (v->type != YD_INT || v->number < 0 || v->number > GROUP_LIMIT) {
                    fail(error, length, "lookup skip must be 0..65536");
                    goto bad;
                }
                stage->limit = (size_t)v->number;
            }
            continue;
        }
        if (!strcmp(name, "$sort") || !strcmp(name, "$limit")) {
            if (p->reduce_at == SIZE_MAX) {
                /* One input sort may order documents before the first reducer. */
                if (strcmp(name, "$sort") || p->input_sort != SIZE_MAX) {
                    fail(error, length, "sort/limit must follow a reducer");
                    goto bad;
                }
                stage->kind = SORT;
                if (!query_option("sort", v, &stage->query, error, length))
                    goto bad;
                p->input_sort = p->count - 1;
                continue;
            }
            if (!strcmp(name, "$sort")) {
                stage->kind = SORT;
                if (!query_option("sort", v, &stage->query, error, length))
                    goto bad;
            } else {
                stage->kind = LIMIT;
                if (v->type != YD_INT || v->number < 1 || v->number > GROUP_LIMIT) {
                    fail(error, length, "aggregation limit must be 1..65536");
                    goto bad;
                }
                stage->limit = (size_t)v->number;
            }
            continue;
        }
        if (p->reduce_at != SIZE_MAX) {
            p->count--;
            a->stages--;
            YDValue rest = {.type = YD_ARRAY, .count = pipeline->count - i,
                            .items = pipeline->items + i};
            p->next = compile(a, &rest, depth, error, length);
            if (!p->next) goto bad;
            break;
        }
        p->reduce_at = i;
        if (!strcmp(name, "$lookup") && !depth) {
            stage->kind = LOOKUP;
            a->bounded = true;
            /* Lookups keep their established input contract: no input sort. */
            if (p->input_sort != SIZE_MAX) {
                fail(error, length, "lookup does not accept an input sort");
                goto bad;
            }
            if (!lookup(p, v, error, length))
                goto bad;
        } else if (!strcmp(name, "$set")) {
            stage->kind = SET;
            a->bounded = true;
            stage->spec = v;
            p->rows = true;
            if (v->type != YD_MAP || v->count > 64) {
                fail(error,length,"set requires at most 64 fields"); goto bad;
            }
            for(size_t j=0;j<v->count;j++)
                if (!field(v->keys[j]) || !expression(v->items[j])) {
                    fail(error,length,"invalid set field or expression"); goto bad;
                }
        } else if (!strcmp(name, "$unwind")) {
            stage->kind = UNWIND;
            a->bounded = true;
            stage->spec = v;
            p->rows = true;
            if(v->type != YD_STRING || v->scalar[0] != '$' || !field(v->scalar+1)) {
                fail(error,length,"unwind requires a top-level field reference"); goto bad;
            }
        } else if (!strcmp(name, "$group")) {
            stage->kind = GROUP;
            p->key = yd_get(v, "_id");
            p->structured = yd_group_key_structured(p->key);
            if (!(p->structured ? structured_key(p->key) : expression(p->key)) ||
                !accumulators(p, v, true, error, length)) {
                fail(error, length, "invalid group specification");
                goto bad;
            }
        } else if (!strcmp(name, "$bucket")) {
            stage->kind = BUCKET;
            if (!bucket(p, v, error, length))
                goto bad;
        } else if (!strcmp(name, "$count")) {
            stage->kind = COUNT;
            if (v->type != YD_STRING || !field(v->scalar)) {
                fail(error, length, "invalid count field");
                goto bad;
            }
            p->key = &null_value;
            p->acc_count = 1;
            p->acc[0] = (AccSpec){.name = v->scalar, .kind = SUM, .expression = &one};
        } else if (!strcmp(name, "$facet")) {
            stage->kind = FACET;
            if (depth >= FACET_DEPTH) {
                fail(error, length, "facet nesting exceeds 4 levels");
                goto bad;
            }
            if (i + 1 != pipeline->count || v->type != YD_MAP || !v->count || v->count > FACETS) {
                fail(error, length, "facet must be terminal with 1..8 branches");
                goto bad;
            }
            for (size_t j = 0; j < v->count; j++) {
                if (!field(v->keys[j])) {
                    fail(error, length, "invalid facet field");
                    goto bad;
                }
                p->facet_names[j] = v->keys[j];
                p->facet_count++;
                p->facets[j] = compile(a, v->items[j], depth + 1, error, length);
                if (!p->facets[j])
                    goto bad;
            }
        } else if (!strcmp(name, "$lookup")) {
            fail(error, length, "lookup is not supported inside a facet");
            goto bad;
        } else {
            fail(error, length, "unsupported aggregation stage");
            goto bad;
        }
    }
    if (p->reduce_at == SIZE_MAX) {
        fail(error, length, "pipeline requires a reducer or materialization");
        goto bad;
    }
    for (size_t i = 0; i <= p->acc_count; i++) {
        const YDValue *expr = i == p->acc_count ? p->key : p->acc[i].expression;
        /* Field-path components keep a structured key on the streaming policy. */
        size_t parts = i == p->acc_count && p->structured ? expr->count : 1;
        for (size_t j = 0; expr && j < parts; j++) {
            const YDValue *part = i == p->acc_count && p->structured ? expr->items[j] : expr;
            if (part->type == YD_MAP || part->type == YD_ARRAY)
                a->bounded = true;
        }
    }
    return p;
bad:
    free_pipe(p);
    return NULL;
}
YDAggregate *yd_aggregate_new(const YDValue *pipeline, char *error, size_t length) {
    YDAggregate *a = calloc(1, sizeof(*a));
    if (!a) {
        fail(error, length, "aggregation allocation failed");
        return NULL;
    }
    a->memory = sizeof(*a);
    a->pipeline = pipeline;
    a->root = compile(a, pipeline, 0, error, length);
    if (!a->root) {
        free(a);
        return NULL;
    }
    return a;
}
static uint64_t hash(const YDValue *key) { return yd_group_key_hash(key); }
static YDValue *copy(YDAggregate *a, const YDValue *v, char *error, size_t length) {
    size_t bytes = yd_memory(v);
    if (!reserve(a, bytes, error, length))
        return NULL;
    YDValue *result = yd_clone(v);
    if (!result)
        fail(error, length, "aggregation allocation failed");
    return result;
}
static Pipe *lookup_at(Pipe *p, size_t *index) {
    for (; p; p=p->next) {
        if (p->from) { if (!*index) return p; (*index)--; }
    }
    return NULL;
}
const char *yd_aggregate_lookup_collection_at(const YDAggregate *a, size_t index) {
    Pipe *p = a ? lookup_at(a->root, &index) : NULL;
    return p ? p->from : NULL;
}
const char *yd_aggregate_lookup_collection(const YDAggregate *a) {
    return yd_aggregate_lookup_collection_at(a, 0);
}
void yd_aggregate_control(YDAggregate *a, const YDQueryControl *control) {
    if (a && control) a->control = *control;
}
size_t yd_aggregate_work(const YDAggregate *a) { return a ? a->work : 0; }
bool yd_aggregate_foreign_feed_at(YDAggregate *a, size_t index, const YDValue *document,
                                  char *error, size_t length) {
    Pipe *p = a ? lookup_at(a->root, &index) : NULL;
    if (!p || a->failed || p->foreign_ready)
        return fail(error, length, "lookup foreign input is not open");
    const YDValue *key = yd_path(document, p->foreign_field);
    bool ok = document && document->type == YD_MAP && (!key || scalar(key));
    if (!ok)
        fail(error, length, "lookup documents must be mappings with scalar keys");
    if (ok)
        ok = work(a, 1 + yd_memory(document) / 64, error, length);
    /* Missing and explicit null never match, including each other. */
    if (ok && key && key->type != YD_NULL) {
        if (p->foreign_count == GROUP_LIMIT)
            ok = fail(error, length, "lookup foreign row limit exceeded");
        if (ok)
            ok = reserve(a, sizeof(Foreign), error, length);
        Foreign *f = ok ? calloc(1, sizeof(*f)) : NULL;
        if (ok && !f)
            ok = fail(error, length, "aggregation allocation failed");
        if (ok) {
            f->document = copy(a, document, error, length);
            if (!f->document) {
                free(f);
                ok = false;
            } else {
                f->key = yd_path(f->document, p->foreign_field);
                size_t slot = hash(key) % HASH_SIZE;
                if (p->tails[slot])
                    p->tails[slot]->next = f;
                else
                    p->foreign[slot] = f;
                p->tails[slot] = f;
                p->foreign_count++;
            }
        }
    }
    if (!ok)
        a->failed = true;
    return ok;
}
bool yd_aggregate_foreign_feed(YDAggregate *a, const YDValue *document, char *error, size_t length) {
    return yd_aggregate_foreign_feed_at(a, 0, document, error, length);
}
bool yd_aggregate_foreign_end_at(YDAggregate *a, size_t index, char *error, size_t length) {
    Pipe *p = a ? lookup_at(a->root, &index) : NULL;
    if (!p || a->failed || p->foreign_ready)
        return fail(error, length, "lookup foreign input is not open");
    p->foreign_ready = true;
    return true;
}
bool yd_aggregate_foreign_end(YDAggregate *a, char *error, size_t length) {
    return yd_aggregate_foreign_end_at(a, 0, error, length);
}
static bool join(YDAggregate *a, Pipe *p, const YDValue *document, char *error, size_t length) {
    if (!p->foreign_ready)
        return fail(error, length, "lookup foreign input is incomplete");
    const YDValue *key = yd_path(document, p->local_field);
    if (!document || document->type != YD_MAP || (key && !scalar(key)))
        return fail(error, length, "lookup documents must be mappings with scalar keys");
    if (yd_get(document, p->as))
        return fail(error, length, "lookup output field already exists");
    YDValue *matches[FANOUT_LIMIT];
    size_t count = 0, fanout = a->control.fanout_limit && a->control.fanout_limit < FANOUT_LIMIT
        ? a->control.fanout_limit : FANOUT_LIMIT;
    if (key && key->type != YD_NULL) {
        if (!work(a, 1 + yd_memory(key) / 64, error, length))
            return false;
        for (Foreign *f = p->foreign[hash(key) % HASH_SIZE]; f; f = f->next) {
            if (!work(a, 1 + (yd_memory(key) + yd_memory(f->key)) / 64, error, length))
                return false;
            if (yd_equal(key, f->key)) {
                if (count == fanout)
                    return fail(error, length, fanout == FANOUT_LIMIT ? "lookup fanout exceeds 1024"
                                                                      : "lookup fanout exceeds max_matches");
                matches[count++] = f->document;
            }
        }
    }
    if (p->group_count == GROUP_LIMIT)
        return fail(error, length, "lookup local row limit exceeded");
    /* Precharge both new member arrays while the original clone still owns
     * its arrays. Foreign trees are immutable and owned once by this reducer. */
    size_t bytes = sizeof(Group) + sizeof(YDValue) + strlen(p->as) + 1 +
                   (document->count + 1) * (sizeof(char *) + sizeof(YDValue *)) +
                   count * sizeof(YDValue *);
    if (!reserve(a, bytes, error, length))
        return false;
    Group *g = calloc(1, sizeof(*g));
    YDValue *array = calloc(1, sizeof(*array));
    char **keys = calloc(document->count + 1, sizeof(*keys));
    YDValue **items = calloc(document->count + 1, sizeof(*items));
    char *name = strdup(p->as);
    YDValue **references = count ? malloc(count * sizeof(*references)) : NULL;
    YDValue *local = copy(a, document, error, length);
    if (!g || !array || !keys || !items || !name || (count && !references) || !local) {
        free(g); free(array); free(keys); free(items); free(name); free(references); yd_free(local);
        if (!local)
            return false;
        return fail(error, length, "aggregation allocation failed");
    }
    YDValue sequence = {.type = YD_INT, .number = p->group_count};
    g->key = copy(a, &sequence, error, length);
    if (!g->key) {
        free(g); free(array); free(keys); free(items); free(name); free(references); yd_free(local);
        return false;
    }
    for (size_t i = 0; i < count; i++)
        references[i] = matches[i];
    *array = (YDValue){.type = YD_ARRAY, .count = count, .items = references};
    for (size_t i = 0; i < local->count; i++) {
        keys[i] = local->keys[i];
        items[i] = local->items[i];
    }
    a->memory -= local->count * (sizeof(char *) + sizeof(YDValue *));
    free(local->keys);
    free(local->items);
    keys[local->count] = name;
    items[local->count++] = array;
    local->keys = keys;
    local->items = items;
    g->document = local;
    g->next = p->groups[0];
    p->groups[0] = g;
    p->group_count++;
    return true;
}
static bool accumulate_value(YDAggregate *a, Acc *acc, const AccSpec *spec, const YDValue *v,
                             char *error, size_t length) {
    if (spec->kind == MIN || spec->kind == MAX) {
        if (!v || v->type == YD_NULL)
            return true;
        if (!scalar(v))
            return fail(error, length, "min/max require scalar values");
        int order = acc->extreme ? yd_compare(v, acc->extreme) : 0;
        if (!acc->extreme || (spec->kind == MIN ? order < 0 : order > 0)) {
            /* Account peak allocation before releasing the superseded value. */
            YDValue *next = copy(a, v, error, length);
            if (!next)
                return false;
            if (acc->extreme)
                a->memory -= yd_memory(acc->extreme);
            yd_free(acc->extreme);
            acc->extreme = next;
        }
        return true;
    }
    if (!numeric(v))
        return true;
    if (acc->count == UINT64_MAX)
        return fail(error, length, "aggregation numeric count overflow");
    acc->count++;
    if (!acc->floating && v->type == YD_INT) {
        uint64_t bits;
        /* Stack constants deliberately have no source spelling. */
        int64_t n = (int64_t)v->number;
        if (v->scalar) {
            if (!yd_integer_bits(v->scalar, &bits))
                return fail(error, length, "invalid integer input");
            memcpy(&n, &bits, sizeof(n));
        }
        if ((n > 0 && acc->integer > INT64_MAX - n) || (n < 0 && acc->integer < INT64_MIN - n)) {
            acc->floating = true;
            acc->sum = (long double)acc->integer + v->number;
        } else
            acc->integer += n;
    } else {
        if (!acc->floating) {
            acc->sum = acc->integer;
            acc->floating = true;
        }
        acc->sum += v->number;
    }
    if (acc->floating && !isfinite(acc->sum))
        return fail(error, length, "aggregation numeric overflow");
    return true;
}
static bool accumulate(YDAggregate *a, Acc *acc, const AccSpec *spec, const YDValue *document,
                       char *error, size_t length) {
    YDValue *v = NULL;
    if (!evaluate(a,spec->expression,document,&v,error,length)) return false;
    size_t held = yd_memory(v);
    bool ok = reserve(a,held,error,length);
    if (ok) { ok=accumulate_value(a,acc,spec,v,error,length); a->memory-=held; }
    yd_free(v);
    return ok;
}
/* Disk spill. Without allowDiskUse no sorter ever writes and every in-memory
 * limit above is unchanged. With it, a hash or row reducer that reaches the
 * memory threshold or GROUP_LIMIT freezes: each group becomes one STATE record
 * holding its exact accumulator state, and every later document becomes one
 * INPUT record holding its evaluated accumulator inputs. Merging by key then
 * sequence replays the same additions in the same order, so floating sums,
 * min/max ties and representative keys match the in-memory result exactly. */
static bool over(const YDAggregate *a) { return a->spill && a->memory > a->soft_limit; }
static bool spill_reserve(void *context, size_t bytes, char *error, size_t length) {
    return reserve(context, bytes, error, length);
}
static void spill_release(void *context, size_t bytes) { ((YDAggregate *)context)->memory -= bytes; }
static bool spill_pressure(void *context) { return over(context); }
static bool spill_check(void *context, char *error, size_t length) {
    return work(context, 0, error, length);
}
static int sequence(const YDValue *left, const YDValue *right) {
    long double l = left ? left->number : 0, r = right ? right->number : 0;
    return (l > r) - (l < r);
}
static int ordered_records(const YDValue *left, const YDValue *right, void *context) {
    const Ordering *o = context;
    size_t at = 0;
    if (!o->sort) {
        int c = yd_group_key_compare(left->items[0], right->items[0]);
        if (c)
            return c;
        at = 1;
    } else
        for (; at < o->values; at++) {
            int c = yd_compare(left->items[at], right->items[at]);
            if (c)
                return (c > 0 ? 1 : -1) * o->sort->direction[at];
        }
    return sequence(left->items[at], right->items[at]);
}
static YDSpillSorter *sorter(YDAggregate *a, Ordering *order, char *error, size_t length) {
    YDSpillHooks hooks = {.compare = ordered_records, .compare_context = order,
                          .reserve = spill_reserve, .release = spill_release,
                          .pressure = spill_pressure, .check = spill_check,
                          .memory_context = a};
    size_t flush = a->spill ? a->soft_limit / 4 : 0;
    if (a->spill && flush < YD_AGGREGATE_MEMORY_MINIMUM)
        flush = YD_AGGREGATE_MEMORY_MINIMUM;
    return yd_spill_sorter_new(a->spill, &hooks, flush, error, length);
}
static YDValue *record_new(size_t count) {
    YDValue *r = calloc(1, sizeof(*r));
    YDValue **items = count ? calloc(count, sizeof(*items)) : NULL;
    if (!r || (count && !items)) {
        free(r);
        free(items);
        return NULL;
    }
    *r = (YDValue){.type = YD_ARRAY, .items = items, .count = count};
    return r;
}
static YDValue *number_value(YDType type, long double number) {
    YDValue *v = calloc(1, sizeof(*v));
    if (v) {
        v->type = type;
        v->number = number;
    }
    return v;
}
static bool complete(const YDValue *r, size_t from) {
    for (size_t i = from; i < r->count; i++)
        if (!r->items[i])
            return false;
    return true;
}
/* Exactly the bytes reserve() charged for this group and its owned values. */
static size_t group_bytes(const Pipe *p, const Group *g) {
    size_t bytes = sizeof(*g) + p->acc_count * sizeof(Acc) + yd_memory(g->key) + yd_memory(g->document);
    for (size_t i = 0; i < p->acc_count; i++)
        bytes += yd_memory(g->values[i].extreme);
    return bytes;
}
static void free_group(const Pipe *p, Group *g) {
    yd_free(g->key);
    if (g->document) {
        /* The last member is the lookup array; its children are owned
         * by the foreign table, and must not be recursively freed. */
        if (p->from) {
            YDValue *array = g->document->items[g->document->count - 1];
            array->count = 0;
        }
        yd_free(g->document);
    }
    for (size_t j = 0; j < p->acc_count; j++)
        yd_free(g->values[j].extreme);
    free(g);
}
/* Moves the key, extremes and row out of g; allocation failure frees them. */
static YDValue *state_record(const Pipe *p, Group *g) {
    YDValue *r = record_new(p->rows ? 4 : 3 + p->acc_count);
    if (!r)
        return NULL;
    long double at = p->rows && g->key ? g->key->number : 0;
    r->items[0] = g->key;
    g->key = NULL;
    r->items[1] = number_value(YD_INT, at);
    r->items[2] = number_value(YD_INT, p->rows ? ROW_RECORD : STATE_RECORD);
    if (p->rows) {
        r->items[3] = g->document;
        g->document = NULL;
    }
    for (size_t i = 0; !p->rows && i < p->acc_count; i++) {
        Acc *acc = &g->values[i];
        YDValue *state = record_new(5);
        if (state) {
            state->items[0] = number_value(YD_INT, (long double)acc->integer);
            state->items[1] = number_value(YD_FLOAT, acc->sum);
            state->items[2] = number_value(YD_INT, (long double)acc->count);
            state->items[3] = number_value(YD_BOOL, 0);
            if (state->items[3])
                state->items[3]->boolean = acc->floating;
            state->items[4] = acc->extreme;
            acc->extreme = NULL;
        } else {
            yd_free(acc->extreme);
            acc->extreme = NULL;
        }
        r->items[3 + i] = state;
        if (!state || !state->items[0] || !state->items[1] || !state->items[2] || !state->items[3]) {
            yd_free(r);
            return NULL;
        }
    }
    if (!r->items[0] || !complete(r, 1)) {
        yd_free(r);
        return NULL;
    }
    return r;
}
static bool freeze(YDAggregate *a, Pipe *p, char *error, size_t length) {
    p->state_order = (Ordering){.aggregate = a};
    p->state = sorter(a, &p->state_order, error, length);
    if (!p->state)
        return false;
    p->frozen = true;
    bool ok = true;
    for (size_t i = 0; i < HASH_SIZE; i++) {
        Group *g = p->groups[i];
        p->groups[i] = NULL;
        while (g) {
            Group *next = g->next;
            size_t bytes = group_bytes(p, g);
            YDValue *record = ok ? state_record(p, g) : NULL;
            if (ok && !record)
                ok = fail(error, length, "aggregation allocation failed");
            free_group(p, g);
            a->memory -= bytes;
            if (ok)
                ok = yd_spill_sorter_add(p->state, record, error, length);
            g = next;
        }
    }
    return ok;
}
static bool should_freeze(const YDAggregate *a, const Pipe *p) {
    return a->spill && !p->frozen && !p->from && (p->group_count >= GROUP_LIMIT || over(a));
}
/* Accumulator inputs exactly as accumulate_value() would read them: ignored
 * values are stored missing; non-scalar min/max inputs fail here, as in memory. */
static bool spill_input(YDAggregate *a, Pipe *p, const YDValue *document, const YDValue *key,
                        char *error, size_t length) {
    if (p->spill_sequence == UINT64_MAX)
        return fail(error, length, "aggregation spill sequence exhausted");
    YDValue *r = record_new(3 + p->acc_count);
    if (!r)
        return fail(error, length, "aggregation allocation failed");
    r->items[0] = yd_clone(key);
    r->items[1] = number_value(YD_INT, (long double)++p->spill_sequence);
    r->items[2] = number_value(YD_INT, INPUT_RECORD);
    if (!r->items[0] || !r->items[1] || !r->items[2]) {
        yd_free(r);
        return fail(error, length, "aggregation allocation failed");
    }
    for (size_t i = 0; i < p->acc_count; i++) {
        const AccSpec *spec = &p->acc[i];
        YDValue *v = NULL;
        if (!evaluate(a, spec->expression, document, &v, error, length)) {
            yd_free(r);
            return false;
        }
        if (spec->kind == MIN || spec->kind == MAX) {
            if (v && v->type == YD_NULL) {
                yd_free(v);
                v = NULL;
            }
            if (v && !scalar(v)) {
                yd_free(v);
                yd_free(r);
                return fail(error, length, "min/max require scalar values");
            }
        } else if (!numeric(v)) {
            yd_free(v);
            v = NULL;
        }
        r->items[3 + i] = v;
    }
    return yd_spill_sorter_add(p->state, r, error, length);
}
static bool store_row(YDAggregate *a, Pipe *p, const YDValue *document, char *error, size_t length) {
    if (should_freeze(a, p) && !freeze(a, p, error, length))
        return false;
    if (p->frozen) {
        if (p->group_count >= SPILL_GROUP_LIMIT)
            return fail(error, length, "pipeline spilled row limit exceeded");
        if (!work(a, 1 + yd_memory(document) / 64, error, length))
            return false;
        YDValue *r = record_new(4);
        if (r) {
            r->items[0] = number_value(YD_INT, (long double)p->group_count);
            r->items[1] = number_value(YD_INT, (long double)p->group_count);
            r->items[2] = number_value(YD_INT, ROW_RECORD);
            r->items[3] = yd_clone(document);
        }
        if (!r || !complete(r, 0)) {
            yd_free(r);
            return fail(error, length, "aggregation allocation failed");
        }
        p->group_count++;
        return yd_spill_sorter_add(p->state, r, error, length);
    }
    if(p->group_count == GROUP_LIMIT) return fail(error,length,"pipeline row limit exceeded");
    if(!work(a,1+yd_memory(document)/64,error,length) || !reserve(a,sizeof(Group),error,length)) return false;
    Group *g=calloc(1,sizeof(*g));
    if(!g) return fail(error,length,"aggregation allocation failed");
    g->next=p->groups[0];p->groups[0]=g;
    YDValue seq={.type=YD_INT,.number=p->group_count++};
    g->key=copy(a,&seq,error,length);
    g->document=copy(a,document,error,length);
    return g->key && g->document;
}
static bool set_field(YDValue *doc, const char *name, YDValue *value) {
    for(size_t i=0;i<doc->count;i++) if(!strcmp(doc->keys[i],name)) {
        yd_free(doc->items[i]);doc->items[i]=value;return true;
    }
    char **keys=malloc((doc->count+1)*sizeof(*keys));
    YDValue **items=malloc((doc->count+1)*sizeof(*items));
    char *key=strdup(name);
    if(!keys || !items || !key) { free(keys);free(items);free(key);return false; }
    if(doc->count) {memcpy(keys,doc->keys,doc->count*sizeof(*keys));memcpy(items,doc->items,doc->count*sizeof(*items));}
    free(doc->keys);free(doc->items);doc->keys=keys;doc->items=items;
    doc->keys[doc->count]=key;doc->items[doc->count++]=value;return true;
}
static bool transform(YDAggregate *a, Pipe *p, const YDValue *document, char *error, size_t length) {
    Stage *s=&p->stages[p->reduce_at];
    if(!document || document->type!=YD_MAP) return fail(error,length,"pipeline documents must be mappings");
    const YDValue *array=s->kind==UNWIND?yd_get(document,s->spec->scalar+1):NULL;
    if(s->kind==UNWIND && (!array || array->type==YD_NULL)) return true;
    if(s->kind==UNWIND && array->type!=YD_ARRAY) return fail(error,length,"unwind requires array values");
    size_t n=s->kind==UNWIND?array->count:1;
    for(size_t i=0;i<n;i++) {
        /* Intermediate clones coexist with retained rows and expression values. */
        size_t hold=yd_memory(document);
        if(!reserve(a,hold,error,length)) return false;
        YDValue *doc=yd_clone(document);
        bool ok=doc!=NULL;
        if(!ok) fail(error,length,"aggregation allocation failed");
        size_t extras=0;
        size_t fields=s->kind==SET?s->spec->count:1;
        for(size_t j=0;ok && j<fields;j++) {
            YDValue *value=NULL;
            const char *name=s->kind==SET?s->spec->keys[j]:s->spec->scalar+1;
            if(s->kind==SET) ok=evaluate(a,s->spec->items[j],document,&value,error,length);
            else {value=yd_clone(array->items[i]);if(!value) ok=fail(error,length,"aggregation allocation failed");}
            if(!ok) break;
            if(!value) continue; /* A missing expression leaves an existing field unchanged. */
            size_t bytes=yd_memory(value)+strlen(name)+1+sizeof(char*)+sizeof(YDValue*);
            ok=reserve(a,bytes,error,length);
            if(ok) extras+=bytes;
            size_t transient=doc->count*(sizeof(char*)+sizeof(YDValue*));
            if(ok) ok=reserve(a,transient,error,length);
            if(ok) {ok=set_field(doc,name,value);a->memory-=transient;}
            if(!ok) {yd_free(value);if(length && !*error) fail(error,length,"aggregation allocation failed");}
        }
        if(ok) ok=store_row(a,p,doc,error,length);
        yd_free(doc);a->memory-=hold+extras;
        if(!ok) return false;
    }
    return true;
}
static bool reduce(YDAggregate *a, Pipe *p, const YDValue *document, const YDValue *key,
                   char *error, size_t length) {
    if (!key)
        key = &null_value;
    if (!scalar(key) && !(p->structured && key->type == YD_MAP))
        return fail(error, length, "group keys must be scalar");
    if (p->stages[p->reduce_at].kind == BUCKET) {
        const YDValue *v = key;
        key = p->fallback;
        const YDValue *first = p->boundaries->items[0];
        size_t lo = 0, hi = p->boundaries->count;
        if ((numeric(v) && numeric(first)) || v->type == first->type) {
            while (lo < hi) {
                size_t mid = lo + (hi - lo) / 2;
                if (yd_compare(v, p->boundaries->items[mid]) >= 0)
                    lo = mid + 1;
                else
                    hi = mid;
            }
            if (lo && lo < p->boundaries->count)
                key = p->boundaries->items[lo - 1];
        }
        if (!key)
            return fail(error, length, "bucket input is outside the boundaries");
    }
    if (p->frozen)
        return spill_input(a, p, document, key, error, length);
    size_t slot = hash(key) % HASH_SIZE;
    Group *g;
    size_t comparisons = 0;
    for (g = p->groups[slot]; g; g = g->next) {
        if (++comparisons > 256)
            return fail(error, length, "aggregation hash collision limit exceeded");
        if (yd_group_key_equal(g->key, key))
            break;
    }
    if (!g && should_freeze(a, p)) {
        if (!freeze(a, p, error, length))
            return false;
        return spill_input(a, p, document, key, error, length);
    }
    if (!g) {
        size_t bytes = sizeof(*g) + p->acc_count * sizeof(Acc);
        if (p->group_count == GROUP_LIMIT || !reserve(a, bytes, error, length))
            return fail(error, length, "aggregation group/state limit exceeded");
        g = calloc(1, bytes);
        if (!g)
            return fail(error, length, "aggregation allocation failed");
        g->next = p->groups[slot];
        p->groups[slot] = g;
        p->group_count++;
        g->key = copy(a, key, error, length);
        if (!g->key)
            return false;
    }
    for (size_t i = 0; i < p->acc_count; i++)
        if (!accumulate(a, &g->values[i], &p->acc[i], document, error, length))
            return false;
    return true;
}
/* Missing components are null; every component must be a scalar. */
static bool group_key(YDAggregate *a, Pipe *p, const YDValue *document, YDValue **out,
                      char *error, size_t length) {
    *out = NULL;
    if (!p->structured)
        return evaluate(a, p->key, document, out, error, length);
    const YDValue *spec = p->key;
    YDValue *key = calloc(1, sizeof(*key));
    char **keys = calloc(spec->count, sizeof(*keys));
    YDValue **items = calloc(spec->count, sizeof(*items));
    if (!key || !keys || !items) {
        free(key);
        free(keys);
        free(items);
        return fail(error, length, "aggregation allocation failed");
    }
    *key = (YDValue){.type = YD_MAP, .keys = keys, .items = items};
    for (size_t i = 0; i < spec->count; i++) {
        YDValue *v = NULL;
        if (!evaluate(a, spec->items[i], document, &v, error, length)) {
            yd_free(key);
            return false;
        }
        if (!v && !(v = yd_clone(&null_value))) {
            yd_free(key);
            return fail(error, length, "aggregation allocation failed");
        }
        if (!scalar(v)) {
            yd_free(v);
            yd_free(key);
            return fail(error, length, "group key components must be scalar");
        }
        if (!(keys[i] = strdup(spec->keys[i]))) {
            yd_free(v);
            yd_free(key);
            return fail(error, length, "aggregation allocation failed");
        }
        items[i] = v;
        key->count++;
    }
    *out = key;
    return true;
}
static bool feed_at(YDAggregate *a, Pipe *p, const YDValue *document, size_t start, char *error,
                    size_t length);
/* Buffer one document for this pipe's input sort; drain() resumes after it. */
static bool buffer_input(YDAggregate *a, Pipe *p, const YDValue *document, size_t at, char *error,
                         size_t length) {
    const YDQueryPlan *sort = &p->stages[at].query;
    const YDValue *values[8] = {0};
    if (match(a, sort, document, values, error, length) < 0)
        return false;
    if (!p->input) {
        p->input_order = (Ordering){.aggregate = a, .sort = sort, .values = sort->sort_count};
        if (!(p->input = sorter(a, &p->input_order, error, length)))
            return false;
    }
    size_t k = sort->sort_count;
    YDValue *r = record_new(k + 2);
    bool ok = r != NULL;
    for (size_t i = 0; ok && i < k; i++)
        if (values[i] && !(r->items[i] = yd_clone(values[i])))
            ok = false;
    if (ok)
        ok = (r->items[k] = number_value(YD_INT, (long double)p->input_sequence++)) &&
             (r->items[k + 1] = yd_clone(document));
    if (!ok) {
        yd_free(r);
        return fail(error, length, "aggregation allocation failed");
    }
    return yd_spill_sorter_add(p->input, r, error, length);
}
/* Index-ordered root input skips buffering but must never move backwards. */
static bool ordered_input(YDAggregate *a, const YDQueryPlan *sort, const YDValue *document,
                          char *error, size_t length) {
    const YDValue *values[8] = {0};
    if (match(a, sort, document, values, error, length) < 0)
        return false;
    for (size_t i = 0; a->has_previous && i < sort->sort_count; i++) {
        int c = yd_compare(a->previous[i], values[i]);
        if (c * sort->direction[i] > 0)
            return fail(error, length, "aggregate input order violated");
        if (c)
            break;
    }
    for (size_t i = 0; i < sort->sort_count; i++) {
        YDValue *next = values[i] ? copy(a, values[i], error, length) : NULL;
        if (values[i] && !next)
            return false;
        a->memory -= yd_memory(a->previous[i]);
        yd_free(a->previous[i]);
        a->previous[i] = next;
    }
    a->has_previous = true;
    return true;
}
static bool feed(YDAggregate *a, Pipe *p, const YDValue *document, char *error, size_t length) {
    return feed_at(a, p, document, 0, error, length);
}
static bool feed_at(YDAggregate *a, Pipe *p, const YDValue *document, size_t start, char *error,
                    size_t length) {
    if (!start && (a->bounded || a->control.work_limit) &&
        !work(a, 1 + yd_memory(document) / 64, error, length))
        return false;
    for (size_t i = start; i < p->reduce_at; i++) {
        if (p->stages[i].kind == SORT) {
            if (p != a->root || !a->input_ordered)
                return buffer_input(a, p, document, i, error, length);
            if (!ordered_input(a, &p->stages[i].query, document, error, length))
                return false;
            continue;
        }
        const YDValue *values[8];
        int matched = match(a, &p->stages[i].query, document, values, error, length);
        if (matched <= 0)
            return matched == 0;
    }
    if (p->from)
        return join(a, p, document, error, length);
    if (p->facet_count) {
        for (size_t i = 0; i < p->facet_count; i++)
            if (!feed(a, p->facets[i], document, error, length))
                return false;
        return true;
    }
    if(p->rows) return transform(a,p,document,error,length);
    YDValue *key=NULL;
    if(!group_key(a,p,document,&key,error,length)) return false;
    size_t held=yd_memory(key);
    bool ok=reserve(a,held,error,length);
    if(ok) {ok=reduce(a,p,document,key,error,length);a->memory-=held;}
    yd_free(key);
    return ok;
}
bool yd_aggregate_feed(YDAggregate *a, const YDValue *document, char *error, size_t length) {
    if (!a || a->failed)
        return fail(error, length, "aggregation already failed");
    if (!work(a,0,error,length) || !feed(a, a->root, document, error, length)) {
        a->failed = true;
        return false;
    }
    return true;
}
typedef struct {
    YDValue object, numbers[ACCUMULATORS];
    char *keys[ACCUMULATORS + 1];
    YDValue *items[ACCUMULATORS + 1];
} Row;
static void row(Pipe *p, Group *g, Row *r) {
    memset(r, 0, sizeof(*r));
    if (p->from || p->rows) {
        r->object = *g->document;
        return;
    }
    size_t n = 0;
    if (p->stages[p->reduce_at].kind != COUNT) {
        r->keys[n] = "_id";
        r->items[n++] = g->key;
    }
    for (size_t i = 0; i < p->acc_count; i++) {
        const Acc *acc = &g->values[i];
        const AccSpec *spec = &p->acc[i];
        r->keys[n] = (char *)spec->name;
        YDValue *v = &r->numbers[i];
        if (spec->kind == MIN || spec->kind == MAX)
            r->items[n] = acc->extreme;
        else if (spec->kind == AVG && !acc->count)
            r->items[n] = NULL;
        else {
            v->type = acc->floating || spec->kind == AVG ? YD_FLOAT : YD_INT;
            v->number = acc->floating ? acc->sum : acc->integer;
            if (spec->kind == AVG)
                v->number /= acc->count;
            r->items[n] = v;
        }
        if (!r->items[n])
            r->items[n] = (YDValue *)&null_value;
        n++;
    }
    r->object = (YDValue){.type = YD_MAP, .count = n, .keys = r->keys, .items = r->items};
}
/* Resolve each requested key once per row. Charge actual map probes/key bytes
 * to the aggregate, rather than only the found value (which may be missing). */
static bool sort_path(YDAggregate *a, const YDValue *value, const char *path,
                       const YDValue **out, char *error, size_t length) {
    size_t depth = 0;
    while (value && *path && depth++ <= YD_DEPTH_LIMIT) {
        const char *dot = strchr(path, '.');
        size_t n = dot ? (size_t)(dot - path) : strlen(path);
        if (!work(a, n + 1, error, length))
            return false;
        const YDValue *next = NULL;
        if (value->type == YD_MAP) {
            for (size_t i = 0; i < value->count; i++) {
                size_t kn = strlen(value->keys[i]);
                if (!work(a, kn + 1, error, length))
                    return false;
                if (kn == n && !memcmp(value->keys[i], path, n)) {
                    next = value->items[i];
                    break;
                }
            }
        } else if (value->type == YD_ARRAY) {
            size_t index = 0;
            bool valid = n && !(n > 1 && *path == '0');
            for (size_t i = 0; valid && i < n; i++) {
                unsigned digit = (unsigned char)path[i] - '0';
                if (digit > 9 || index > (SIZE_MAX - digit) / 10)
                    valid = false;
                else
                    index = index * 10 + digit;
            }
            if (valid && index < value->count)
                next = value->items[index];
        }
        value = next;
        if (!dot) {
            *out = value;
            return true;
        }
        path = dot + 1;
    }
    *out = NULL;
    return true;
}
typedef struct {
    long double number;
    const YDValue *value;
    size_t units;
    bool numeric;
} SortKey;
typedef struct { SortKey keys[8]; } SortCache;
typedef struct {
    YDAggregate *aggregate;
    const YDQueryPlan *sort;
    SortCache *cache;
    char *error;
    size_t length;
    bool ok;
} Sorting;
static bool sort_work(Sorting *s, size_t units) {
    if (s->ok)
        s->ok = work(s->aggregate, units, s->error, s->length);
    return s->ok;
}
static int order(Sorting *s, Group *a, Group *b) {
    if (!s->ok)
        return 0;
    if (s->cache) {
        for (size_t i = 0; i < s->sort->sort_count; i++) {
            const SortKey *left = &s->cache[a->sort_at].keys[i],
                          *right = &s->cache[b->sort_at].keys[i];
            if (!sort_work(s, 1 + left->units + right->units))
                return 0;
            /* Reducer numeric results are synthesized on the row() stack;
             * snapshot those numbers while other scalar owners stay borrowed. */
            YDValue ln = {.type = YD_FLOAT, .number = left->number},
                    rn = {.type = YD_FLOAT, .number = right->number};
            int c = yd_compare(left->numeric ? &ln : left->value,
                               right->numeric ? &rn : right->value);
            if (c)
                return c * s->sort->direction[i];
        }
    }
    if (!sort_work(s, 1 + yd_memory(a->key) / 64 + yd_memory(b->key) / 64))
        return 0;
    return yd_group_key_compare(a->key, b->key);
}
static void down(Sorting *s, Group **groups, size_t n, size_t at) {
    while (s->ok && at * 2 + 1 < n) {
        size_t child = at * 2 + 1;
        if (child + 1 < n && order(s, groups[child], groups[child + 1]) < 0)
            child++;
        if (order(s, groups[at], groups[child]) >= 0 || !s->ok)
            break;
        Group *g = groups[at];
        groups[at] = groups[child];
        groups[child] = g;
        at = child;
    }
}
static bool sorted(YDAggregate *a, Pipe *p, const YDQueryPlan *sort, Group **groups, size_t n,
                    char *error, size_t length) {
    Sorting s = {.aggregate = a, .sort = sort, .error = error, .length = length, .ok = true};
    size_t bytes = sort && sort->sort_count ? n * sizeof(SortCache) : 0;
    if (bytes) {
        if (!reserve(a, bytes, error, length))
            return false;
        s.cache = malloc(bytes);
        if (!s.cache) {
            a->memory -= bytes;
            return fail(error, length, "aggregation allocation failed");
        }
        for (size_t j = 0; s.ok && j < n; j++) {
            Row r;
            row(p, groups[j], &r);
            groups[j]->sort_at = j;
            for (size_t i = 0; s.ok && i < sort->sort_count; i++) {
                const YDValue *v = NULL;
                s.ok = sort_path(a, &r.object, sort->sort_spec->keys[i], &v, error, length);
                if (!s.ok)
                    break;
                if (v && !scalar(v)) {
                    s.ok = fail(error, length, "sort fields must be scalar values");
                    break;
                }
                size_t units = 1 + yd_memory(v) / 64;
                if (!sort_work(&s, units))
                    break;
                s.cache[j].keys[i] = (SortKey){.numeric = numeric(v),
                    .number = numeric(v) ? v->number : 0, .value = numeric(v) ? NULL : v,
                    .units = units};
            }
        }
    }
    /* Empty sorts retain the original ID/key tie order, but comparisons still
     * consume shared work, as does the initial deterministic ordering. */
    for (size_t i = n / 2; s.ok && i; i--)
        down(&s, groups, n, i - 1);
    for (size_t i = n; s.ok && i > 1; i--) {
        Group *g = groups[0];
        groups[0] = groups[i - 1];
        groups[i - 1] = g;
        down(&s, groups, i - 1, 0);
    }
    free(s.cache);
    a->memory -= bytes;
    if (!s.ok)
        a->failed = true;
    return s.ok;
}
typedef struct {
    char *data;
    size_t size;
} Output;
static bool append(Output *out, const char *text, size_t n, char *error, size_t length) {
    if (n > OUTPUT_LIMIT - out->size)
        return fail(error, length, "aggregation output exceeds 16 MiB");
    memcpy(out->data + out->size, text, n);
    out->size += n;
    out->data[out->size] = 0;
    return true;
}
/* One reducer row, after the post-reducer stages: feed the next segment or
 * encode it. Shared by the in-memory and spilled emitters. */
static bool output_row(YDAggregate *a, Pipe *p, Output *out, const YDQueryPlan *projection,
                       size_t *emitted, const YDValue *object, char *error, size_t length) {
    if (p->next) {
        if (projection)
            return fail(error, length, "projection must be terminal");
        return feed(a, p->next, object, error, length);
    }
    size_t size;
    if (p->from && !work(a, 1 + yd_memory(object) / 64, error, length))
        return false;
    char *text = projection ? yd_query_project_sized(projection, object, &size, OUTPUT_LIMIT, error,
                                                     length)
                            : yd_json_sized(object, &size, p->from ? OUTPUT_LIMIT : YD_REQUEST_LIMIT);
    bool ok = text && (!*emitted || append(out, ",", 1, error, length)) &&
              append(out, text, size, error, length);
    free(text);
    if (!ok && length && !*error)
        fail(error, length, "aggregation encoding failed");
    if (ok)
        (*emitted)++;
    return ok;
}
/* Feed a buffered input sort's documents, in order, to the rest of its pipe. */
static bool drain(YDAggregate *a, Pipe *p, char *error, size_t length) {
    YDSpillSorter *input = p->input;
    if (!input)
        return true;
    size_t k = p->input_order.values;
    bool ok = yd_spill_sorter_finish(input, error, length);
    while (ok) {
        YDValue *record = NULL;
        int got = yd_spill_sorter_next(input, &record, error, length);
        if (got <= 0) {
            ok = got == 0;
            break;
        }
        size_t held = yd_memory(record);
        ok = reserve(a, held, error, length);
        if (ok) {
            ok = record->count == k + 2 && record->items[k + 1]
                     ? feed_at(a, p, record->items[k + 1], p->input_sort + 1, error, length)
                     : fail(error, length, "aggregate spill record is malformed");
            a->memory -= held;
        }
        yd_free(record);
    }
    p->input = NULL;
    yd_spill_sorter_free(input);
    return ok;
}
/* The post-reducer stages over a spilled reducer's key-ordered rows. MATCH,
 * SKIP, LIMIT and PROJECT stream; each SORT is a barrier through its own
 * sorter whose records carry the row's key rank, the in-memory tie-breaker. */
typedef struct {
    YDAggregate *a;
    Pipe *p;
    Output *out;
    const YDQueryPlan *projection;
    size_t first, emitted, sort_stage;
    size_t counts[STAGES];
    Ordering orders[STAGES];
    YDSpillSorter *sorter;
    bool saturated;
    char *error;
    size_t length;
} Chain;
static bool chain_sort(Chain *c, size_t at, uint64_t rank, const YDValue *row) {
    const YDQueryPlan *sort = &c->p->stages[at].query;
    if (!c->sorter) {
        c->orders[at] = (Ordering){.aggregate = c->a, .sort = sort, .values = sort->sort_count};
        c->sort_stage = at;
        if (!(c->sorter = sorter(c->a, &c->orders[at], c->error, c->length)))
            return false;
    }
    size_t k = sort->sort_count;
    YDValue *r = record_new(k + 2);
    if (!r)
        return fail(c->error, c->length, "aggregation allocation failed");
    bool ok = true;
    for (size_t i = 0; ok && i < k; i++) {
        const YDValue *v = yd_path(row, sort->sort_spec->keys[i]);
        if (v && !scalar(v)) {
            yd_free(r);
            return fail(c->error, c->length, "sort fields must be scalar values");
        }
        if (v && !(r->items[i] = yd_clone(v)))
            ok = false;
    }
    if (ok)
        ok = (r->items[k] = number_value(YD_INT, (long double)rank)) &&
             (r->items[k + 1] = yd_clone(row));
    if (!ok) {
        yd_free(r);
        return fail(c->error, c->length, "aggregation allocation failed");
    }
    return yd_spill_sorter_add(c->sorter, r, c->error, c->length);
}
static bool chain_push(Chain *c, uint64_t rank, const YDValue *row) {
    YDAggregate *a = c->a;
    Pipe *p = c->p;
    if (!work(a, 0, c->error, c->length))
        return false;
    for (size_t i = c->first; i < p->count; i++) {
        Stage *s = &p->stages[i];
        if (s->kind == MATCH) {
            const YDValue *values[8];
            int matched = match(a, &s->query, row, values, c->error, c->length);
            if (matched <= 0)
                return matched == 0;
        } else if (s->kind == SKIP) {
            if (c->counts[i] < s->limit) {
                c->counts[i]++;
                return true;
            }
        } else if (s->kind == LIMIT) {
            /* Every later row of this source would stop here. */
            if (c->counts[i] >= s->limit) {
                c->saturated = true;
                return true;
            }
            if (++c->counts[i] == s->limit)
                c->saturated = true;
        } else if (s->kind == PROJECT)
            c->projection = &s->query;
        else if (s->kind == SORT)
            return chain_sort(c, i, rank, row);
    }
    return output_row(a, p, c->out, c->projection, &c->emitted, row, c->error, c->length);
}
static bool produce(Chain *c, Group *g, uint64_t rank) {
    Row r;
    row(c->p, g, &r);
    return chain_push(c, rank, &r.object);
}
static void release_group(YDAggregate *a, const Pipe *p, Group *g) {
    if (g) {
        a->memory -= group_bytes(p, g);
        free_group(p, g);
    }
}
static bool malformed(Chain *c) {
    return fail(c->error, c->length, "aggregate spill record is malformed");
}
/* Fold one merged record into the current group, emitting the previous group
 * when the key changes. Takes ownership of record. */
static bool absorb(Chain *c, Group **current, uint64_t *rank, YDValue *record) {
    YDAggregate *a = c->a;
    Pipe *p = c->p;
    size_t expected = p->rows ? 4 : 3 + p->acc_count;
    if (record->count != expected || !record->items[0] || !numeric(record->items[2])) {
        yd_free(record);
        return malformed(c);
    }
    int tag = (int)record->items[2]->number;
    if (p->rows) {
        size_t held = yd_memory(record);
        Group g = {.key = record->items[0], .document = record->items[3]};
        bool ok = tag == ROW_RECORD && g.document && g.document->type == YD_MAP ? true : malformed(c);
        if (ok && *rank >= SPILL_GROUP_LIMIT)
            ok = fail(c->error, c->length, "pipeline spilled row limit exceeded");
        if (ok)
            ok = reserve(a, held, c->error, c->length);
        if (ok) {
            ok = produce(c, &g, (*rank)++);
            a->memory -= held;
        }
        yd_free(record);
        return ok;
    }
    Group *g = *current;
    if (g && yd_group_key_compare(g->key, record->items[0])) {
        bool ok = produce(c, g, (*rank)++);
        release_group(a, p, g);
        *current = g = NULL;
        if (!ok || c->saturated) {
            yd_free(record);
            return ok;
        }
    }
    bool fresh = !g, ok = true;
    if (!g) {
        size_t bytes = sizeof(*g) + p->acc_count * sizeof(Acc);
        if (*rank >= SPILL_GROUP_LIMIT)
            ok = fail(c->error, c->length, "aggregation spilled group limit exceeded");
        if (ok)
            ok = reserve(a, bytes, c->error, c->length);
        if (ok && !(g = calloc(1, bytes))) {
            a->memory -= bytes;
            ok = fail(c->error, c->length, "aggregation allocation failed");
        }
        if (ok) {
            /* Reserve the representative key before the group owns it. */
            ok = reserve(a, yd_memory(record->items[0]), c->error, c->length);
            if (!ok) {
                a->memory -= bytes;
                free(g);
                g = NULL;
            } else {
                g->key = record->items[0];
                record->items[0] = NULL;
                *current = g;
            }
        }
    }
    if (ok && tag == STATE_RECORD) {
        if (!fresh)
            ok = malformed(c);
        for (size_t i = 0; ok && i < p->acc_count; i++) {
            YDValue *s = record->items[3 + i];
            if (!s || s->type != YD_ARRAY || s->count != 5 || !numeric(s->items[0]) ||
                !numeric(s->items[1]) || !numeric(s->items[2]) || !s->items[3] ||
                s->items[3]->type != YD_BOOL) {
                ok = malformed(c);
                break;
            }
            Acc *acc = &g->values[i];
            acc->integer = (int64_t)s->items[0]->number;
            acc->sum = s->items[1]->number;
            acc->count = (uint64_t)s->items[2]->number;
            acc->floating = s->items[3]->boolean;
            if (s->items[4]) {
                ok = reserve(a, yd_memory(s->items[4]), c->error, c->length);
                if (ok) {
                    acc->extreme = s->items[4];
                    s->items[4] = NULL;
                }
            }
        }
    } else if (ok && tag == INPUT_RECORD) {
        for (size_t i = 0; ok && i < p->acc_count; i++)
            ok = accumulate_value(a, &g->values[i], &p->acc[i], record->items[3 + i], c->error,
                                  c->length);
    } else if (ok)
        ok = malformed(c);
    yd_free(record);
    return ok;
}
static bool stream(YDAggregate *a, Pipe *p, Output *out, char *error, size_t length) {
    Chain c = {.a = a, .p = p, .out = out, .first = p->reduce_at + 1, .error = error,
               .length = length};
    Group *g = NULL;
    uint64_t rank = 0;
    bool ok = yd_spill_sorter_finish(p->state, error, length);
    while (ok && !c.saturated) {
        YDValue *record = NULL;
        int got = yd_spill_sorter_next(p->state, &record, error, length);
        if (got <= 0) {
            ok = got == 0;
            break;
        }
        ok = absorb(&c, &g, &rank, record);
    }
    if (ok && g && !c.saturated)
        ok = produce(&c, g, rank++);
    release_group(a, p, g);
    yd_spill_sorter_free(p->state);
    p->state = NULL;
    while (ok && c.sorter) {
        YDSpillSorter *s = c.sorter;
        size_t k = c.orders[c.sort_stage].values;
        c.sorter = NULL;
        c.first = c.sort_stage + 1;
        c.saturated = false;
        ok = yd_spill_sorter_finish(s, error, length);
        while (ok && !c.saturated) {
            YDValue *record = NULL;
            int got = yd_spill_sorter_next(s, &record, error, length);
            if (got <= 0) {
                ok = got == 0;
                break;
            }
            size_t held = yd_memory(record);
            ok = record->count == k + 2 && record->items[k] && record->items[k + 1]
                     ? reserve(a, held, error, length)
                     : fail(error, length, "aggregate spill record is malformed");
            if (ok) {
                ok = chain_push(&c, (uint64_t)record->items[k]->number, record->items[k + 1]);
                a->memory -= held;
            }
            yd_free(record);
        }
        yd_spill_sorter_free(s);
    }
    yd_spill_sorter_free(c.sorter);
    return ok;
}
static bool emit(YDAggregate *a, Pipe *p, Output *out, char *error, size_t length) {
    if (!work(a,0,error,length)) return false;
    if (!drain(a, p, error, length))
        return false;
    if (!p->next && !append(out, "[", 1, error, length))
        return false;
    if (p->frozen) {
        if (!stream(a, p, out, error, length))
            return false;
        return p->next ? emit(a, p->next, out, error, length) : append(out, "]", 1, error, length);
    }
    if (p->facet_count) {
        if (!append(out, "{", 1, error, length))
            return false;
        for (size_t i = 0; i < p->facet_count; i++) {
            YDValue name = {.type = YD_STRING, .scalar = (char *)p->facet_names[i]};
            size_t n;
            char *text = yd_json(&name, &n);
            bool ok = text && (!i || append(out, ",", 1, error, length)) &&
                      append(out, text, n, error, length) && append(out, ":", 1, error, length);
            free(text);
            if (!ok || !emit(a, p->facets[i], out, error, length))
                return false;
        }
        return append(out, "}]", 2, error, length);
    }
    size_t bytes = (p->group_count ? p->group_count : 1) * sizeof(Group *);
    if (!reserve(a, bytes, error, length))
        return false;
    Group **groups = malloc(bytes);
    if (!groups)
        return fail(error, length, "aggregation allocation failed");
    size_t n = 0;
    for (size_t i = 0; i < HASH_SIZE; i++)
        for (Group *g = p->groups[i]; g; g = g->next)
            groups[n++] = g;
    bool ok = sorted(a, p, NULL, groups, n, error, length);
    const YDQueryPlan *projection = NULL;
    for (size_t i = p->reduce_at + 1; ok && i < p->count; i++) {
        Stage *s = &p->stages[i];
        if (s->kind == LIMIT && n > s->limit)
            n = s->limit;
        else if (s->kind == SKIP) {
            size_t skip = s->limit < n ? s->limit : n;
            memmove(groups, groups + skip, (n - skip) * sizeof(*groups));
            n -= skip;
        } else if (s->kind == PROJECT)
            projection = &s->query;
        else if (s->kind == SORT) {
            ok = sorted(a, p, &s->query, groups, n, error, length);
        } else if (s->kind == MATCH) {
            size_t kept = 0;
            for (size_t j = 0; j < n; j++) {
                Row r;
                row(p, groups[j], &r);
                const YDValue *values[8];
                int matched = match(a, &s->query, &r.object, values, error, length);
                if (matched < 0) {
                    ok = false;
                    break;
                }
                if (matched)
                    groups[kept++] = groups[j];
            }
            n = kept;
        }
    }
    size_t emitted = 0;
    for (size_t i = 0; ok && i < n; i++) {
        Row r;
        row(p, groups[i], &r);
        ok = output_row(a, p, out, projection, &emitted, &r.object, error, length);
    }
    free(groups);
    a->memory -= bytes;
    return ok && (p->next ? emit(a,p->next,out,error,length) : append(out,"]",1,error,length));
}
char *yd_aggregate_json(YDAggregate *a, size_t *size, char *error, size_t length) {
    if (size)
        *size = 0;
    if (!a || a->failed || a->emitted || (a->root->from && !a->root->foreign_ready)) {
        fail(error, length, "aggregation already failed");
        return NULL;
    }
    for(Pipe *p=a->root;p;p=p->next)
        if(p->from && !p->foreign_ready) {fail(error,length,"lookup foreign input is incomplete");return NULL;}
    a->emitted = true;
    Output out = {.data = malloc(OUTPUT_LIMIT + 1)};
    if (!out.data) {
        fail(error, length, "aggregation allocation failed");
        return NULL;
    }
    if (!emit(a, a->root, &out, error, length)) {
        free(out.data);
        return NULL;
    }
    if (size)
        *size = out.size;
    return out.data;
}
bool yd_aggregate_bounded(const YDAggregate *a) { return a && a->bounded; }
bool yd_aggregate_allow_disk_use(YDAggregate *a, unsigned long long max_bytes, char *error,
                                 size_t length) {
    if (!a || a->failed || a->spill)
        return fail(error, length, "aggregation disk use cannot be enabled");
    if (!(a->spill = yd_spill_open(max_bytes, error, length)))
        return false;
    a->soft_limit = yd_aggregate_spill_memory_limit();
    return true;
}
size_t yd_aggregate_input_filters(const YDAggregate *a, const YDValue **filters, size_t capacity) {
    size_t n = 0;
    const Pipe *p = a ? a->root : NULL;
    for (size_t i = 0; p && i < p->reduce_at && i < p->count && n < capacity; i++)
        if (p->stages[i].kind == MATCH)
            filters[n++] = p->stages[i].query.filter;
    return n;
}
const YDValue *yd_aggregate_input_sort(const YDAggregate *a) {
    return a && a->root->input_sort != SIZE_MAX ? a->root->stages[a->root->input_sort].query.sort_spec
                                                 : NULL;
}
void yd_aggregate_input_ordered(YDAggregate *a) {
    if (a && a->root->input_sort != SIZE_MAX)
        a->input_ordered = true;
}
char *yd_aggregate_explain_json(const YDAggregate *a, char *error, size_t length) {
    if(!a) {fail(error,length,"missing aggregation");return NULL;}
    size_t capacity=16384, at=0;
    char *json=malloc(capacity);
    if(!json) {fail(error,length,"aggregation allocation failed");return NULL;}
    char threshold[32] = "null", request[32] = "null";
    if (a->spill) {
        snprintf(threshold, sizeof(threshold), "%zu", a->soft_limit);
        snprintf(request, sizeof(request), "%llu", yd_spill_limit(a->spill));
    }
    at+=(size_t)snprintf(json,capacity,"{\"profile\":\"native-local-v2\",\"scan\":\"%s\",\"read_view\":\"caller-pinned\","
        "\"spill\":%s,\"allow_disk_use\":%s,\"spill_bytes\":%llu,\"spill_runs\":%llu,\"spill_request_limit\":%s,"
        "\"spill_threshold\":%s,\"stages\":[",
        a->input_ordered ? "index-order" : "primary-id-order", yd_spill_runs(a->spill) ? "true" : "false",
        a->spill ? "true" : "false", yd_spill_bytes(a->spill), yd_spill_runs(a->spill), request, threshold);
    for(size_t i=0;i<a->pipeline->count;i++) {
        const YDValue *entry=a->pipeline->items[i];
        const char *op=entry->keys[0];
        const char *algorithm=!strcmp(op,"$lookup")?"hash-equality":!strcmp(op,"$sort")?"bounded-heapsort":
            !strcmp(op,"$group") || !strcmp(op,"$bucket") || !strcmp(op,"$count")?"hash-reduce":
            !strcmp(op,"$facet")?"shared-scan-facets":"bounded-transform";
        if (i == a->root->input_sort)
            algorithm = a->input_ordered ? "index-order" : "input-sort";
        at+=(size_t)snprintf(json+at,capacity-at,"%s{\"operator\":\"%s\",\"algorithm\":\"%s\"}",i?",":"",op,algorithm);
    }
    snprintf(json+at,capacity-at,"],\"work_units\":%zu,\"state_bytes\":%zu,\"state_limit\":%u,\"row_limit\":%u,"
        "\"spilled_row_limit\":%zu,\"fanout_limit\":%u,\"output_limit\":%u,\"facet_depth_limit\":%u,"
        "\"group_key_fields_limit\":%u,\"work_limit\":%zu}",
        a->work,a->memory,STATE_LIMIT,GROUP_LIMIT,SPILL_GROUP_LIMIT,FANOUT_LIMIT,OUTPUT_LIMIT,FACET_DEPTH,
        YD_GROUP_KEY_FIELDS,
        a->control.work_limit && a->control.work_limit<YD_JOIN_WORK_LIMIT?a->control.work_limit:(size_t)YD_JOIN_WORK_LIMIT);
    return json;
}
size_t yd_aggregate_memory(const YDAggregate *a) { return a ? a->memory : 0; }
static void free_pipe(Pipe *p) {
    if (!p)
        return;
    free_pipe(p->next);
    for (size_t i = 0; i < p->facet_count; i++)
        free_pipe(p->facets[i]);
    yd_spill_sorter_free(p->input);
    yd_spill_sorter_free(p->state);
    for (size_t i = 0; i < HASH_SIZE; i++) {
        Group *g = p->groups[i];
        while (g) {
            Group *next = g->next;
            free_group(p, g);
            g = next;
        }
        Foreign *f = p->foreign[i];
        while (f) {
            Foreign *next = f->next;
            yd_free(f->document);
            free(f);
            f = next;
        }
    }
    free(p);
}
void yd_aggregate_free(YDAggregate *a) {
    if (a) {
        free_pipe(a->root);
        for (size_t i = 0; i < 8; i++)
            yd_free(a->previous[i]);
        yd_spill_close(a->spill);
        free(a);
    }
}
