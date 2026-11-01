#ifndef YAMORA_SECURITY_OIDC_JSON_H
#define YAMORA_SECURITY_OIDC_JSON_H
/* Module-private, strict bounded JSON. No YAML or retained source pointers. */
#include <stddef.h>
#define YD_OIDC_JSON_MAX_NODES 4096U
#define YD_OIDC_JSON_MAX_DEPTH 8U
typedef enum {
    YD_OIDC_JSON_OBJECT, YD_OIDC_JSON_ARRAY, YD_OIDC_JSON_STRING,
    YD_OIDC_JSON_NUMBER, YD_OIDC_JSON_BOOL, YD_OIDC_JSON_NULL
} YDOIDCJSONType;
typedef struct YDOIDCJSONNode {
    YDOIDCJSONType type;
    /* BOOL text is the static literal "true" or "false", length 4 or 5. */
    const char *text, *name;
    size_t length, name_length, count;
    struct YDOIDCJSONNode *first, *next;
} YDOIDCJSONNode;
typedef struct YDOIDCJSON YDOIDCJSON;
typedef enum {
    YD_OIDC_JSON_ERROR = -1, YD_OIDC_JSON_INVALID = 0, YD_OIDC_JSON_OK = 1
} YDOIDCJSONResult;
/* Text <=65536 bytes; node_limit 1..4096; depth <=8. Rejects duplicate
 * decoded names, NUL, non-JSON extensions, invalid UTF-8 and lone surrogates.
 * Allocated arena owns nodes/text until free; *out cleared on failure. */
YDOIDCJSONResult yd_oidc_json_parse(const unsigned char *text, size_t length,
    size_t node_limit, YDOIDCJSON **out);
const YDOIDCJSONNode *yd_oidc_json_root(const YDOIDCJSON *json);
const YDOIDCJSONNode *yd_oidc_json_get(const YDOIDCJSONNode *object, const char *key);
void yd_oidc_json_free(YDOIDCJSON *json);
#endif
