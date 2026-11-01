#ifndef YAMLDB_VALUE_H
#define YAMLDB_VALUE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define YD_DOCUMENT_LIMIT (256U * 1024U)
#define YD_REQUEST_LIMIT (2U * 1024U * 1024U)
#define YD_LARGE_DOCUMENT_LIMIT (16U * 1024U * 1024U)
#define YD_LARGE_REQUEST_LIMIT (64U * 1024U * 1024U)
#define YD_DEPTH_LIMIT 64U
#define YD_NODE_LIMIT 65536U

typedef enum { YD_NULL, YD_BOOL, YD_INT, YD_FLOAT, YD_STRING, YD_ARRAY, YD_MAP } YDType;

/* Borrowed UTF-8 source with sparse character-to-byte checkpoints. Initialization
 * validates the safe YAML input profile. Free after either success or failure. */
typedef struct {
    const unsigned char *source;
    size_t *offsets, characters;
} YDSourceMap;
bool yd_source_map_init(YDSourceMap *map, const unsigned char *body, size_t length);
size_t yd_source_offset(const YDSourceMap *map, size_t character);
void yd_source_map_free(YDSourceMap *map);

/* Owned immutable tree. Maps own keys and items; arrays own only items. Numeric
 * scalars retain their decoded YAML spelling and number holds their value.
 * start/end are source byte offsets, excluding trailing trivia. */
typedef struct YDValue {
    YDType type;
    char *scalar;
    long double number;
    bool boolean;
    char **keys;
    struct YDValue **items;
    size_t count;
    size_t start, end;
} YDValue;

/* One YAML 1.2 core document, signed 64-bit integers and finite floats. Aliases,
 * anchors, custom tags, duplicate/non-string keys and invalid UTF-8 are errors.
 * An empty document is null. Errors never return a partial tree. */
YDValue *yd_parse(const unsigned char *body, size_t length, char *error, size_t error_length);
/* The identical safe profile with a larger bound for escaped request envelopes.
 * Stored documents must still pass yd_parse(). */
YDValue *yd_parse_request(const unsigned char *body, size_t length, char *error, size_t error_length);
/* Exact two's-complement bits from a supported signed-64 YAML integer spelling. */
bool yd_integer_bits(const char *text, uint64_t *bits);
void yd_free(YDValue *value);
YDValue *yd_clone(const YDValue *value);
const YDValue *yd_get(const YDValue *value, const char *key);
/* Empty path selects the root; dotted fields and canonical decimal array indices
 * select descendants. Literal dots in mapping keys require yd_get(). */
const YDValue *yd_path(const YDValue *value, const char *path);
/* Explicit bounded native profiles; limits above the large request bound fail. */
YDValue *yd_parse_sized(const unsigned char *body, size_t length, size_t limit, char *error, size_t error_length);
char *yd_json_sized(const YDValue *value, size_t *length, size_t limit);
char *yd_json(const YDValue *value, size_t *length);
int yd_compare(const YDValue *left, const YDValue *right);
bool yd_equal(const YDValue *left, const YDValue *right);
size_t yd_memory(const YDValue *value);

#endif
