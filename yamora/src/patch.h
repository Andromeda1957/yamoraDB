#ifndef YAMLDB_PATCH_H
#define YAMLDB_PATCH_H

#include "value.h"

/* Atomic field mutations. Operators map dot paths to values: $set, $unset
 * (true), $inc and $mul (numbers; a missing field becomes the increment or a
 * zero of the multiplier's type), $min, $max, $push and $addToSet (a value or
 * {$each: [values]}; a missing field becomes a new sequence), $pull (a
 * missing field is unchanged), $rename (destination path; not through
 * sequences) and $setOnInsert (applies only to an upserted document). Paths
 * must not overlap. Array indices refer to the original document, even when
 * sibling elements are removed. Untouched source and comments are retained;
 * a layout that cannot be safely edited fails closed instead of falling back
 * to a canonical document rewrite. An operation the document already
 * satisfies leaves the source byte-identical. Output is malloc-owned and is
 * NULL with length zero on every failure. */
bool yd_patch(const unsigned char *body, size_t length, const YDValue *operations,
    unsigned char **output, size_t *output_length, char *error, size_t error_length);

bool yd_patch_sized(const unsigned char *body, size_t length, const YDValue *operations,
    unsigned char **output, size_t *output_length, size_t limit, char *error, size_t error_length);

/* Structural validation without a document: operators, paths, operands and
 * overlap. Requires at least one mutation path. */
bool yd_patch_validate(const YDValue *operations, char *error, size_t error_length);

/* The document an upsert inserts: the filter's equality fields (literal
 * predicates and $eq, including inside $and), then the update applied with
 * $setOnInsert enabled, written as canonical block YAML. */
bool yd_patch_upsert_sized(const YDValue *filter, const YDValue *operations, unsigned char **output,
    size_t *output_length, size_t limit, char *error, size_t error_length);
#endif
