#include "oidc_json.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct YDOIDCJSON {
    YDOIDCJSONNode *nodes;
    char *strings;
    size_t used, capacity, string_used, string_capacity;
};
typedef struct {
    const unsigned char *text;
    size_t length, at;
    YDOIDCJSON *doc;
} Reader;
static void space(Reader *r) {
    while (r->at < r->length) {
        unsigned char c = r->text[r->at];
        if (c != ' ' && c != '\r' && c != '\n' && c != '\t') break;
        r->at++;
    }
}
static bool take(Reader *r, unsigned char c) {
    if (r->at == r->length || r->text[r->at] != c) return false;
    r->at++; return true;
}
static bool put(Reader *r, unsigned char c) {
    if (r->doc->string_used == r->doc->string_capacity) return false;
    r->doc->strings[r->doc->string_used++] = (char)c; return true;
}
static bool hex4(Reader *r, uint32_t *value) {
    if (r->length - r->at < 4) return false;
    *value = 0;
    for (unsigned i = 0; i < 4; i++) {
        unsigned char c = r->text[r->at++];
        unsigned n;
        if (c >= '0' && c <= '9') n = c - '0';
        else if (c >= 'a' && c <= 'f') n = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') n = c - 'A' + 10;
        else return false;
        *value = (*value << 4) | n;
    }
    return true;
}
static bool codepoint(Reader *r, uint32_t c) {
    if (!c) return false; /* Explicit profile: no NUL in any decoded string. */
    if (c < 0x80) return put(r, (unsigned char)c);
    if (c < 0x800) return put(r, (unsigned char)(0xc0 | (c >> 6))) &&
        put(r, (unsigned char)(0x80 | (c & 63)));
    if (c < 0x10000) return put(r, (unsigned char)(0xe0 | (c >> 12))) &&
        put(r, (unsigned char)(0x80 | ((c >> 6) & 63))) &&
        put(r, (unsigned char)(0x80 | (c & 63)));
    return put(r, (unsigned char)(0xf0 | (c >> 18))) &&
        put(r, (unsigned char)(0x80 | ((c >> 12) & 63))) &&
        put(r, (unsigned char)(0x80 | ((c >> 6) & 63))) &&
        put(r, (unsigned char)(0x80 | (c & 63)));
}
static bool unicode_escape(Reader *r) {
    uint32_t c;
    if (!hex4(r, &c)) return false;
    if (c >= 0xd800 && c <= 0xdbff) {
        uint32_t low;
        if (!take(r, '\\') || !take(r, 'u') || !hex4(r, &low) ||
            low < 0xdc00 || low > 0xdfff) return false;
        c = 0x10000 + ((c - 0xd800) << 10) + low - 0xdc00;
    } else if (c >= 0xdc00 && c <= 0xdfff) return false;
    return codepoint(r, c);
}
static bool utf8(Reader *r, unsigned char first) {
    unsigned remaining;
    uint32_t value, minimum;
    if (first >= 0xc2 && first <= 0xdf) {
        remaining = 1; value = first & 31; minimum = 0x80;
    } else if (first >= 0xe0 && first <= 0xef) {
        remaining = 2; value = first & 15; minimum = 0x800;
    } else if (first >= 0xf0 && first <= 0xf4) {
        remaining = 3; value = first & 7; minimum = 0x10000;
    } else return false;
    if (r->length - r->at < remaining) return false;
    for (unsigned i = 0; i < remaining; i++) {
        unsigned char c = r->text[r->at++];
        if ((c & 0xc0) != 0x80) return false;
        value = (value << 6) | (c & 63);
    }
    if (value < minimum || value > 0x10ffff || (value >= 0xd800 && value <= 0xdfff))
        return false;
    return codepoint(r, value);
}
static bool string(Reader *r, const char **text, size_t *length) {
    if (!take(r, '"')) return false;
    size_t start = r->doc->string_used;
    while (r->at < r->length) {
        unsigned char c = r->text[r->at++];
        if (c == '"') {
            *text = r->doc->strings + start;
            *length = r->doc->string_used - start;
            return put(r, 0);
        }
        if (c < 0x20) return false;
        if (c >= 0x80) {
            if (!utf8(r, c)) return false;
        } else if (c == '\\') {
            if (r->at == r->length) return false;
            c = r->text[r->at++];
            if (c == 'u') {
                if (!unicode_escape(r)) return false;
            } else {
                switch (c) {
                case '"': case '\\': case '/': break;
                case 'b': c = '\b'; break;
                case 'f': c = '\f'; break;
                case 'n': c = '\n'; break;
                case 'r': c = '\r'; break;
                case 't': c = '\t'; break;
                default: return false;
                }
                if (!put(r, c)) return false;
            }
        } else if (!put(r, c)) return false;
    }
    return false;
}
static bool digit(Reader *r) {
    return r->at < r->length && r->text[r->at] >= '0' && r->text[r->at] <= '9';
}
static bool number(Reader *r, YDOIDCJSONNode *node) {
    size_t start = r->at;
    (void)take(r, '-');
    if (!take(r, '0')) {
        if (!digit(r) || r->text[r->at] == '0') return false;
        while (digit(r)) r->at++;
    }
    if (take(r, '.')) {
        if (!digit(r)) return false;
        while (digit(r)) r->at++;
    }
    if (take(r, 'e') || take(r, 'E')) {
        if (!take(r, '+')) (void)take(r, '-');
        if (!digit(r)) return false;
        while (digit(r)) r->at++;
    }
    node->type = YD_OIDC_JSON_NUMBER;
    node->text = r->doc->strings + r->doc->string_used;
    node->length = r->at - start;
    for (size_t i = start; i < r->at; i++) if (!put(r, r->text[i])) return false;
    return put(r, 0);
}
static bool literal(Reader *r, const char *text) {
    size_t n = strlen(text);
    if (r->length - r->at < n || memcmp(r->text + r->at, text, n)) return false;
    r->at += n; return true;
}
static YDOIDCJSONNode *value(Reader *r, unsigned depth) {
    space(r);
    if (r->at == r->length || r->doc->used == r->doc->capacity) return NULL;
    YDOIDCJSONNode *node = &r->doc->nodes[r->doc->used++];
    unsigned char c = r->text[r->at];
    if (c == '{' || c == '[') {
        if (depth >= YD_OIDC_JSON_MAX_DEPTH) return NULL;
        bool object = c == '{';
        unsigned char close = object ? '}' : ']';
        node->type = object ? YD_OIDC_JSON_OBJECT : YD_OIDC_JSON_ARRAY;
        r->at++; space(r);
        if (take(r, close)) return node;
        YDOIDCJSONNode *tail = NULL;
        for (;;) {
            const char *name = NULL;
            size_t length = 0;
            if (object) {
                if (!string(r, &name, &length)) return NULL;
                for (const YDOIDCJSONNode *p = node->first; p; p = p->next)
                    if (length == p->name_length && !memcmp(name, p->name, length)) return NULL;
                space(r);
                if (!take(r, ':')) return NULL;
            }
            YDOIDCJSONNode *child = value(r, depth + 1);
            if (!child) return NULL;
            child->name = name; child->name_length = length;
            if (tail) tail->next = child; else node->first = child;
            tail = child; node->count++;
            space(r);
            if (take(r, close)) return node;
            if (!take(r, ',')) return NULL;
            space(r);
        }
    }
    if (c == '"') {
        node->type = YD_OIDC_JSON_STRING;
        return string(r, &node->text, &node->length) ? node : NULL;
    }
    if (c == '-' || (c >= '0' && c <= '9')) return number(r, node) ? node : NULL;
    if (literal(r, "true") || literal(r, "false")) {
        node->type = YD_OIDC_JSON_BOOL;
        node->text = c == 't' ? "true" : "false";
        node->length = c == 't' ? 4U : 5U;
    }
    else if (literal(r, "null")) node->type = YD_OIDC_JSON_NULL;
    else return NULL;
    return node;
}
void yd_oidc_json_free(YDOIDCJSON *doc) {
    if (!doc) return;
    if (doc->strings) {
        volatile unsigned char *p = (volatile unsigned char *)doc->strings;
        for (size_t i = 0; i < doc->string_capacity; i++) p[i] = 0;
    }
    free(doc->strings); free(doc->nodes); free(doc);
}
YDOIDCJSONResult yd_oidc_json_parse(const unsigned char *text, size_t length,
    size_t limit, YDOIDCJSON **out) {
    if (out) *out = NULL;
    if (!out || (!text && length) || !limit || limit > YD_OIDC_JSON_MAX_NODES)
        return YD_OIDC_JSON_ERROR;
    if (!length || length > 65536) return YD_OIDC_JSON_INVALID;
    YDOIDCJSON *doc = calloc(1, sizeof(*doc));
    if (!doc) return YD_OIDC_JSON_ERROR;
    doc->capacity = limit; doc->string_capacity = length + 1;
    doc->nodes = calloc(limit, sizeof(*doc->nodes));
    doc->strings = malloc(doc->string_capacity);
    if (!doc->nodes || !doc->strings) {
        yd_oidc_json_free(doc); return YD_OIDC_JSON_ERROR;
    }
    Reader r = {text, length, 0, doc};
    bool valid = value(&r, 0) != NULL;
    space(&r);
    if (!valid || r.at != length) {
        yd_oidc_json_free(doc); return YD_OIDC_JSON_INVALID;
    }
    *out = doc; return YD_OIDC_JSON_OK;
}
const YDOIDCJSONNode *yd_oidc_json_root(const YDOIDCJSON *doc) {
    return doc && doc->used ? doc->nodes : NULL;
}
const YDOIDCJSONNode *yd_oidc_json_get(const YDOIDCJSONNode *object, const char *key) {
    if (!object || object->type != YD_OIDC_JSON_OBJECT || !key) return NULL;
    size_t size = strlen(key);
    for (const YDOIDCJSONNode *p = object->first; p; p = p->next)
        if (p->name_length == size && !memcmp(p->name, key, size)) return p;
    return NULL;
}
