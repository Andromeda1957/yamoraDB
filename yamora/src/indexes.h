#ifndef YAMLDB_INDEXES_H
#define YAMLDB_INDEXES_H

#include "snapshot.h"
#include "value.h"

#include <string.h>

/* Catalogs borrow document values from their immutable snapshot. Free the
 * catalog before freeing its snapshot, and publish the pair atomically. */
typedef struct YDIndexCatalog YDIndexCatalog;

typedef struct {
    const char *path;
    const YDValue *equal;
    const YDValue *lower;
    const YDValue *upper;
    bool has_equal;
    bool lower_inclusive;
    bool upper_inclusive;
} YDIndexBound;

/* True when a query path can fan out over sequence elements: some segment
 * after the first is not a canonical decimal index. Index entries store the
 * exact path value, so such a document indexes as missing; planners must also
 * visit the missing entries of these fields to agree with a collection scan. */
static inline bool yd_index_path_traverses(const char *path) {
    const char *segment = path ? strchr(path, '.') : NULL;
    while (segment) {
        segment++;
        size_t length = 0;
        bool canonical = *segment != '.' && *segment != 0;
        for (; segment[length] && segment[length] != '.'; length++)
            if (segment[length] < '0' || segment[length] > '9') canonical = false;
        if (length > 1 && *segment == '0') canonical = false;
        if (!canonical) return true;
        segment = segment[length] ? segment + length : NULL;
    }
    return false;
}

typedef struct {
    const char *name; /* NULL means a collection scan; documents is then NULL. */
    size_t *documents;
    size_t count;
    size_t entries_examined;
} YDIndexSelection;

/* spec is NULL, a sequence, or {indexes: [definitions]}. Each definition is
 * {collection: string, name: string, fields: [dot.path, ...], unique: bool,
 * partial: filter}. Scalar arrays create multikey entries. Nested containers
 * are rejected. A partial index holds only matching documents (uniqueness is
 * among them) and this snapshot planner never selects it. TTL definitions
 * (expire_after_seconds) are native-only and rejected here. */
YDIndexCatalog *yd_indexes_build(const YamlDBSnapshot *snapshot,
    const YDValue *spec, char *error, size_t error_length);
/* The shared structural validation used by the native engine: identical
 * rules, plus expire_after_seconds on exactly one field. */
bool yd_indexes_validate_native(const YDValue *spec, char *error, size_t error_length);
void yd_indexes_free(YDIndexCatalog *catalog);
bool yd_indexes_select(const YDIndexCatalog *catalog, const char *collection,
    const YDIndexBound *bounds, size_t bound_count, YDIndexSelection *selection,
    char *error, size_t error_length);
void yd_indexes_selection_free(YDIndexSelection *selection);

#endif
