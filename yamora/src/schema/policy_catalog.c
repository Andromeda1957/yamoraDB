#include "policy_catalog.h"

#include <openssl/evp.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char name[129];
    size_t name_length, source_length;
    uint64_t version;
    YDPCMode mode;
    const char *profile;
    const unsigned char *source;
    unsigned char source_hash[32], policy_hash[32];
} Entry;

struct YDPolicyCatalog {
    YDPCInfo info;
    Entry entries[YD_PC_ENTRY_LIMIT];
    unsigned char sources[];
};

typedef struct { Entry entry; size_t source_offset; } ParsedEntry;
typedef struct {
    uint64_t generation;
    size_t count, source_bytes;
    ParsedEntry entries[YD_PC_ENTRY_LIMIT];
} Parsed;
typedef struct {
    const unsigned char *bytes;
    size_t length, at;
    YDPCResult result;
    YDPCError *error;
} Parser;
typedef struct { unsigned char *output; size_t at; } Writer;

_Static_assert(sizeof(YDPolicyCatalog) + YD_PC_ENTRY_LIMIT <= 32768,
               "owned catalog overhead bound");
_Static_assert(sizeof(Parsed) + 4096 <= 65536, "parser stack bound");

static void clear_error(YDPCError *error) {
    if (error) { memset(error, 0, sizeof(*error)); error->offset = SIZE_MAX; }
}
static YDPCResult fail(YDPCError *error, YDPCResult result, size_t offset,
                         const char *message) {
    if (error) {
        error->offset = offset;
        size_t n = strlen(message);
        if (n >= sizeof(error->message)) n = sizeof(error->message) - 1;
        memcpy(error->message, message, n);
        error->message[n] = 0;
    }
    return result;
}
static bool bad(Parser *p, YDPCResult result, const char *message) {
    if (p->result == YD_PC_OK) p->result = fail(p->error, result, p->at, message);
    return false;
}
static size_t profile_limit(YDPCProfile profile) {
    return profile == YD_PC_ORDINARY ? YD_PC_ORDINARY_LIMIT :
           profile == YD_PC_LARGE ? YD_PC_LARGE_LIMIT : 0;
}
static const char *schema_profile(const char *name) {
    static const char *const profiles[] = {YD_PC_SCHEMA_PROFILE, YD_PC_JSON_PROFILE,
        YD_PC_OPENAPI_PROFILE, YD_PC_CRD_PROFILE};
    if (name) for (size_t i = 0; i < sizeof(profiles) / sizeof(*profiles); i++)
        if (!strcmp(name, profiles[i])) return profiles[i];
    return NULL;
}
static bool charge(YDPCBudget *budget, uint64_t work) {
    if (budget->work_left < work) { budget->work_left = 0; return false; }
    budget->work_left -= work;
    return true;
}
static bool valid_name(const char *name, size_t n) {
    if (!name || !n || n > 128) return false;
    for (size_t i = 0; i < n; ++i)
        if (!((name[i] >= 'a' && name[i] <= 'z') ||
              (name[i] >= '0' && name[i] <= '9') || name[i] == '-')) return false;
    return n != 13 || memcmp(name, "yamldb-system", 13) != 0;
}
static bool safe_code(uint32_t cp) {
    return (cp >= 32 || cp == 9 || cp == 10 || cp == 13) &&
           !(cp >= 127 && cp <= 159) && !(cp >= 0xd800 && cp <= 0xdfff) &&
           cp <= 0x10ffff && cp != 0xfffe && cp != 0xffff;
}
static bool utf8(const unsigned char *s, size_t n, uint32_t *cp, size_t *used) {
    if (!n) return false;
    uint32_t x = s[0];
    size_t k;
    if (x < 0x80) k = 1;
    else if (x >= 0xc2 && x <= 0xdf) { k = 2; x &= 31; }
    else if (x >= 0xe0 && x <= 0xef) { k = 3; x &= 15; }
    else if (x >= 0xf0 && x <= 0xf4) { k = 4; x &= 7; }
    else return false;
    if (k > n) return false;
    for (size_t i = 1; i < k; ++i) {
        if ((s[i] & 0xc0) != 0x80) return false;
        x = (x << 6) | (s[i] & 63);
    }
    if ((k == 2 && x < 0x80) || (k == 3 && x < 0x800) ||
        (k == 4 && x < 0x10000) || !safe_code(x)) return false;
    *cp = x; *used = k;
    return true;
}
static size_t code_bytes(uint32_t cp, unsigned char s[4]) {
    if (cp < 0x80) { s[0] = (unsigned char)cp; return 1; }
    if (cp < 0x800) {
        s[0] = (unsigned char)(0xc0 | (cp >> 6));
        s[1] = (unsigned char)(0x80 | (cp & 63)); return 2;
    }
    if (cp < 0x10000) {
        s[0] = (unsigned char)(0xe0 | (cp >> 12));
        s[1] = (unsigned char)(0x80 | ((cp >> 6) & 63));
        s[2] = (unsigned char)(0x80 | (cp & 63)); return 3;
    }
    s[0] = (unsigned char)(0xf0 | (cp >> 18));
    s[1] = (unsigned char)(0x80 | ((cp >> 12) & 63));
    s[2] = (unsigned char)(0x80 | ((cp >> 6) & 63));
    s[3] = (unsigned char)(0x80 | (cp & 63)); return 4;
}
static bool valid_source(const unsigned char *s, size_t n) {
    if (!s || !n) return false;
    for (size_t i = 0; i < n;) {
        uint32_t cp; size_t k;
        if (!utf8(s + i, n - i, &cp, &k)) return false;
        i += k;
    }
    return true;
}
static const char digits[] = "0123456789abcdef";
static int hex_digit(unsigned char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}
static void le64(uint64_t n, unsigned char out[8]) {
    for (size_t i = 0; i < 8; ++i) out[i] = (unsigned char)(n >> (i * 8));
}
static void hex64(uint64_t n, char out[16]) {
    for (size_t i = 0; i < 16; ++i) out[15 - i] = digits[(n >> (i * 4)) & 15];
}
static void hex_hash(const unsigned char hash[32], char out[64]) {
    for (size_t i = 0; i < 32; ++i) {
        out[i * 2] = digits[hash[i] >> 4]; out[i * 2 + 1] = digits[hash[i] & 15];
    }
}
static void whitespace(Parser *p) {
    while (p->at < p->length && (p->bytes[p->at] == ' ' || p->bytes[p->at] == '\t' ||
           p->bytes[p->at] == '\r' || p->bytes[p->at] == '\n')) ++p->at;
}
static bool take(Parser *p, unsigned char c) {
    whitespace(p);
    if (p->at == p->length || p->bytes[p->at] != c)
        return bad(p, YD_PC_INVALID, "unexpected envelope token");
    ++p->at; return true;
}
static bool is_next(Parser *p, unsigned char c) {
    whitespace(p); return p->at < p->length && p->bytes[p->at] == c;
}
static bool metadata(Parser *p, char *out, size_t capacity) {
    if (!take(p, '"')) return false;
    size_t n = 0;
    while (p->at < p->length && p->bytes[p->at] != '"') {
        unsigned char c = p->bytes[p->at];
        if (c < 32 || c > 126 || c == '\\' || n + 1 >= capacity)
            return bad(p, YD_PC_INVALID, "metadata must be literal quoted ASCII");
        out[n++] = (char)c; ++p->at;
    }
    if (!take(p, '"')) return false;
    out[n] = 0; return true;
}
static bool unicode16(Parser *p, uint32_t *out) {
    uint32_t n = 0;
    for (size_t i = 0; i < 4; ++i) {
        if (p->at == p->length) return bad(p, YD_PC_INVALID, "short unicode escape");
        unsigned char c = p->bytes[p->at++];
        int h = hex_digit(c);
        if (c >= 'A' && c <= 'F') h = c - 'A' + 10;
        if (h < 0) return bad(p, YD_PC_INVALID, "invalid unicode escape");
        n = (n << 4) | (uint32_t)h;
    }
    *out = n; return true;
}
static bool source_string(Parser *p, unsigned char *output, size_t capacity, size_t *size) {
    if (!take(p, '"')) return false;
    size_t n = 0;
    while (p->at < p->length && p->bytes[p->at] != '"') {
        uint32_t cp; size_t used;
        if (p->bytes[p->at] == '\\') {
            if (++p->at == p->length) return bad(p, YD_PC_INVALID, "short source escape");
            unsigned char c = p->bytes[p->at++];
            switch (c) {
                case '"': case '\\': case '/': cp = c; break;
                case 'b': cp = 8; break;
                case 'f': cp = 12; break;
                case 'n': cp = 10; break;
                case 'r': cp = 13; break;
                case 't': cp = 9; break;
                case 'u': {
                    if (!unicode16(p, &cp)) return false;
                    if (cp >= 0xd800 && cp <= 0xdbff) {
                        if (p->length - p->at < 2 || p->bytes[p->at] != '\\' ||
                            p->bytes[p->at + 1] != 'u')
                            return bad(p, YD_PC_INVALID, "missing low surrogate");
                        p->at += 2; uint32_t low;
                        if (!unicode16(p, &low)) return false;
                        if (low < 0xdc00 || low > 0xdfff)
                            return bad(p, YD_PC_INVALID, "invalid low surrogate");
                        cp = 0x10000 + ((cp - 0xd800) << 10) + low - 0xdc00;
                    }
                    break;
                }
                default: return bad(p, YD_PC_INVALID, "invalid source escape");
            }
        } else {
            if (p->bytes[p->at] < 32 ||
                !utf8(p->bytes + p->at, p->length - p->at, &cp, &used))
                return bad(p, YD_PC_INVALID, "invalid source UTF-8");
            p->at += used;
        }
        if (!safe_code(cp)) return bad(p, YD_PC_INVALID, "unsupported source codepoint");
        unsigned char bytes[4]; size_t k = code_bytes(cp, bytes);
        if (n > capacity || k > capacity - n)
            return bad(p, YD_PC_LIMIT, "decoded source exceeds bound");
        if (output) memcpy(output + n, bytes, k);
        n += k;
    }
    if (!take(p, '"')) return false;
    if (!n) return bad(p, YD_PC_INVALID, "empty source");
    *size = n; return true;
}
static bool integer_text(Parser *p, uint64_t *value) {
    char text[17];
    if (!metadata(p, text, sizeof(text))) return false;
    if (strlen(text) != 16) return bad(p, YD_PC_INVALID, "integer needs sixteen lowercase hex digits");
    uint64_t n = 0;
    for (size_t i = 0; i < 16; ++i) {
        int h = hex_digit((unsigned char)text[i]);
        if (h < 0) return bad(p, YD_PC_INVALID, "invalid integer hex");
        n = (n << 4) | (unsigned)h;
    }
    *value = n; return true;
}
static bool digest_text(Parser *p, unsigned char hash[32]) {
    char text[65];
    if (!metadata(p, text, sizeof(text))) return false;
    if (strlen(text) != 64) return bad(p, YD_PC_INVALID, "digest needs sixty-four lowercase hex digits");
    for (size_t i = 0; i < 32; ++i) {
        int a = hex_digit((unsigned char)text[i * 2]);
        int b = hex_digit((unsigned char)text[i * 2 + 1]);
        if (a < 0 || b < 0) return bad(p, YD_PC_INVALID, "invalid digest hex");
        hash[i] = (unsigned char)((a << 4) | b);
    }
    return true;
}
static int field(Parser *p, const char *const *names, size_t count, unsigned *seen) {
    char key[32];
    if (!metadata(p, key, sizeof(key)) || !take(p, ':')) return -1;
    for (size_t i = 0; i < count; ++i) {
        if (strcmp(key, names[i])) continue;
        if (*seen & (1U << i)) { bad(p, YD_PC_INVALID, "duplicate field"); return -1; }
        *seen |= 1U << i; return (int)i;
    }
    bad(p, YD_PC_INVALID, "unknown field"); return -1;
}
static bool entry_parse(Parser *p, ParsedEntry *parsed) {
    static const char *const keys[] = {
        "collection", "version", "mode", "profile", "source", "source_sha256", "policy_sha256"
    };
    Entry *e = &parsed->entry; unsigned seen = 0;
    if (!take(p, '{')) return false;
    for (;;) {
        int f = field(p, keys, 7, &seen); char text[129];
        switch (f) {
            case 0:
                if (!metadata(p, e->name, sizeof(e->name))) return false;
                e->name_length = strlen(e->name);
                if (!valid_name(e->name, e->name_length)) return bad(p, YD_PC_INVALID, "invalid collection name");
                break;
            case 1: if (!integer_text(p, &e->version)) return false; break;
            case 2:
                if (!metadata(p, text, sizeof(text))) return false;
                if (!strcmp(text, "enforce")) e->mode = YD_PC_ENFORCE;
                else if (!strcmp(text, "off")) e->mode = YD_PC_OFF;
                else return bad(p, YD_PC_UNSUPPORTED, "unknown policy mode");
                break;
            case 3:
                if (!metadata(p, text, sizeof(text))) return false;
                e->profile = schema_profile(text);
                if (!e->profile) return bad(p, YD_PC_UNSUPPORTED, "unknown schema profile");
                break;
            case 4:
                whitespace(p); parsed->source_offset = p->at;
                if (!source_string(p, NULL, YD_PC_SOURCE_LIMIT, &e->source_length)) return false;
                break;
            case 5: if (!digest_text(p, e->source_hash)) return false; break;
            case 6: if (!digest_text(p, e->policy_hash)) return false; break;
            default: return false;
        }
        if (is_next(p, '}')) { ++p->at; break; }
        if (!take(p, ',')) return false;
    }
    return seen == 127 || bad(p, YD_PC_INVALID, "missing policy field");
}
static bool policies_parse(Parser *p, Parsed *data) {
    if (!take(p, '[')) return false;
    if (is_next(p, ']')) { ++p->at; return true; }
    for (;;) {
        if (data->count == YD_PC_ENTRY_LIMIT) return bad(p, YD_PC_LIMIT, "too many policies");
        ParsedEntry *e = &data->entries[data->count];
        if (!entry_parse(p, e)) return false;
        for (size_t i = 0; i < data->count; ++i)
            if (!strcmp(data->entries[i].entry.name, e->entry.name))
                return bad(p, YD_PC_INVALID, "duplicate collection");
        if (e->entry.source_length > YD_PC_SOURCE_TOTAL_LIMIT - data->source_bytes)
            return bad(p, YD_PC_LIMIT, "aggregate source exceeds bound");
        data->source_bytes += e->entry.source_length; ++data->count;
        if (is_next(p, ']')) { ++p->at; return true; }
        if (!take(p, ',')) return false;
    }
}
static bool catalog_parse(Parser *p, Parsed *data) {
    static const char *const keys[] = {"format", "generation", "policies"};
    unsigned seen = 0;
    if (!take(p, '{')) return false;
    for (;;) {
        int f = field(p, keys, 3, &seen); char text[129];
        if (f == 0) {
            if (!metadata(p, text, sizeof(text))) return false;
            if (strcmp(text, YD_PC_FORMAT)) return bad(p, YD_PC_UNSUPPORTED, "unknown catalog format");
        } else if (f == 1) {
            if (!integer_text(p, &data->generation)) return false;
        } else if (f == 2) {
            if (!policies_parse(p, data)) return false;
        } else return false;
        if (is_next(p, '}')) { ++p->at; break; }
        if (!take(p, ',')) return false;
    }
    whitespace(p);
    if (seen != 7 || p->at != p->length) return bad(p, YD_PC_INVALID, "incomplete or trailing envelope");
    uint64_t maximum = 0;
    for (size_t i = 0; i < data->count; ++i) {
        uint64_t v = data->entries[i].entry.version;
        if (!v || v > data->generation) return bad(p, YD_PC_INVALID, "invalid policy version");
        if (v > maximum) maximum = v;
    }
    if (maximum != data->generation) return bad(p, YD_PC_INVALID, "generation has no matching policy");
    for (size_t i = 1; i < data->count; ++i) {
        ParsedEntry e = data->entries[i]; size_t j = i;
        while (j && strcmp(data->entries[j - 1].entry.name, e.entry.name) > 0) {
            data->entries[j] = data->entries[j - 1]; --j;
        }
        data->entries[j] = e;
    }
    return true;
}
static void put(Writer *w, const void *bytes, size_t n) {
    if (w->output) memcpy(w->output + w->at, bytes, n);
    w->at += n;
}
static void literal(Writer *w, const char *s) { put(w, s, strlen(s)); }
static void escaped16(Writer *w, uint32_t cp) {
    char text[6] = {'\\', 'u', 0, 0, 0, 0};
    for (size_t i = 0; i < 4; ++i) text[5 - i] = digits[(cp >> (4 * i)) & 15];
    put(w, text, sizeof(text));
}
static void quoted(Writer *w, const unsigned char *s, size_t n) {
    literal(w, "\"");
    for (size_t i = 0; i < n;) {
        /* Owned bytes have already passed UTF-8 validation. */
        uint32_t cp = 0; size_t used = 0;
        (void)utf8(s + i, n - i, &cp, &used); i += used;
        if (cp == '"' || cp == '\\') {
            unsigned char text[2] = {'\\', (unsigned char)cp}; put(w, text, 2);
        } else if (cp >= 32 && cp <= 126) {
            unsigned char c = (unsigned char)cp; put(w, &c, 1);
        } else if (cp <= 0xffff) escaped16(w, cp);
        else { cp -= 0x10000; escaped16(w, 0xd800 + (cp >> 10)); escaped16(w, 0xdc00 + (cp & 1023)); }
    }
    literal(w, "\"");
}
static size_t encode(const YDPolicyCatalog *c, unsigned char *output) {
    Writer w = {output, 0}; char number[16], hash[64];
    literal(&w, "{\"format\":\"" YD_PC_FORMAT "\",\"generation\":\"");
    hex64(c->info.generation, number); put(&w, number, 16);
    literal(&w, "\",\"policies\":[");
    for (size_t i = 0; i < c->info.count; ++i) {
        const Entry *e = &c->entries[i];
        if (i) literal(&w, ",");
        literal(&w, "{\"collection\":"); quoted(&w, (const unsigned char *)e->name, e->name_length);
        literal(&w, ",\"version\":\""); hex64(e->version, number); put(&w, number, 16);
        literal(&w, "\",\"mode\":\""); literal(&w, e->mode == YD_PC_ENFORCE ? "enforce" : "off");
        literal(&w, "\",\"profile\":\""); literal(&w, e->profile); literal(&w, "\",\"source\":");
        quoted(&w, e->source, e->source_length);
        literal(&w, ",\"source_sha256\":\""); hex_hash(e->source_hash, hash); put(&w, hash, 64);
        literal(&w, "\",\"policy_sha256\":\""); hex_hash(e->policy_hash, hash); put(&w, hash, 64);
        literal(&w, "\"}");
    }
    literal(&w, "]}\n"); return w.at;
}
static bool hash_integer(EVP_MD_CTX *ctx, uint64_t n) {
    unsigned char bytes[8]; le64(n, bytes);
    return EVP_DigestUpdate(ctx, bytes, sizeof(bytes)) == 1;
}
static bool hash_end(EVP_MD_CTX *ctx, unsigned char hash[32]) {
    unsigned int n = 0;
    return EVP_DigestFinal_ex(ctx, hash, &n) == 1 && n == 32;
}
static YDPCResult finish(YDPolicyCatalog *c, bool verify, size_t limit, YDPCError *error) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    YDPCResult result = YD_PC_ERROR;
    if (!ctx) return fail(error, YD_PC_ERROR, SIZE_MAX, "digest context allocation failed");
    for (size_t i = 0; i < c->info.count; ++i) {
        Entry *e = &c->entries[i]; unsigned char source[32], policy[32], mode = (unsigned char)e->mode;
        if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
            EVP_DigestUpdate(ctx, e->source, e->source_length) != 1 || !hash_end(ctx, source) ||
            EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
            EVP_DigestUpdate(ctx, "YDPOL001", 8) != 1 || !hash_integer(ctx, e->name_length) ||
            EVP_DigestUpdate(ctx, e->name, e->name_length) != 1 ||
            !hash_integer(ctx, strlen(e->profile)) ||
            EVP_DigestUpdate(ctx, e->profile, strlen(e->profile)) != 1 ||
            EVP_DigestUpdate(ctx, &mode, 1) != 1 || !hash_integer(ctx, e->source_length) ||
            EVP_DigestUpdate(ctx, e->source, e->source_length) != 1 || !hash_end(ctx, policy)) goto done;
        if (verify && (memcmp(source, e->source_hash, 32) || memcmp(policy, e->policy_hash, 32))) {
            result = YD_PC_INVALID; goto done;
        }
        memcpy(e->source_hash, source, 32); memcpy(e->policy_hash, policy, 32);
    }
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, "YDCAT001", 8) != 1 || !hash_integer(ctx, c->info.generation) ||
        !hash_integer(ctx, c->info.count)) goto done;
    for (size_t i = 0; i < c->info.count; ++i) {
        const Entry *e = &c->entries[i];
        if (!hash_integer(ctx, e->name_length) || EVP_DigestUpdate(ctx, e->name, e->name_length) != 1 ||
            !hash_integer(ctx, e->version) || EVP_DigestUpdate(ctx, e->policy_hash, 32) != 1) goto done;
    }
    if (!hash_end(ctx, c->info.catalog_sha256)) goto done;
    c->info.encoded_bytes = encode(c, NULL);
    result = c->info.encoded_bytes > YD_PC_LARGE_LIMIT ? YD_PC_LIMIT :
             c->info.encoded_bytes > limit ? YD_PC_UNSUPPORTED : YD_PC_OK;
done:
    EVP_MD_CTX_free(ctx);
    if (result != YD_PC_OK) return fail(error, result, SIZE_MAX,
        result == YD_PC_INVALID ? "source or policy digest mismatch" :
        result == YD_PC_UNSUPPORTED ? "catalog requires a larger explicit profile" :
        result == YD_PC_LIMIT ? "encoded catalog exceeds bound" : "digest provider failed");
    return result;
}
static YDPolicyCatalog *allocate(size_t count, size_t source_bytes, YDPCBudget *budget,
                                  YDPCResult *result, YDPCError *error) {
    size_t bytes = sizeof(YDPolicyCatalog) + source_bytes + count;
    if (bytes > budget->allocation_limit) {
        *result = fail(error, YD_PC_LIMIT, SIZE_MAX, "catalog allocation budget exhausted"); return NULL;
    }
    YDPolicyCatalog *c = malloc(bytes);
    if (!c) { *result = fail(error, YD_PC_ERROR, SIZE_MAX, "catalog allocation failed"); return NULL; }
    memset(c, 0, sizeof(*c));
    c->info.count = count; c->info.source_bytes = source_bytes; c->info.owned_bytes = bytes;
    return c;
}
YDPCResult yd_policy_catalog_empty(YDPCProfile profile, YDPCBudget *budget,
    YDPolicyCatalog **out, YDPCError *error) {
    clear_error(error); if (out) *out = NULL;
    if (!out || !budget) return fail(error, YD_PC_ERROR, SIZE_MAX, "missing API argument");
    size_t limit = profile_limit(profile);
    if (!limit) return fail(error, YD_PC_UNSUPPORTED, SIZE_MAX, "unknown size profile");
    if (!charge(budget, 1024)) return fail(error, YD_PC_LIMIT, SIZE_MAX, "work budget exhausted");
    YDPCResult result = YD_PC_OK;
    YDPolicyCatalog *c = allocate(0, 0, budget, &result, error);
    if (!c) return result;
    result = finish(c, false, limit, error);
    if (result == YD_PC_OK) *out = c; else free(c);
    return result;
}
YDPCResult yd_policy_catalog_parse(const unsigned char *bytes, size_t length,
    YDPCProfile profile, YDPCBudget *budget, YDPolicyCatalog **out, YDPCError *error) {
    clear_error(error); if (out) *out = NULL;
    if (!out || !budget || !bytes) return fail(error, YD_PC_ERROR, SIZE_MAX, "missing API argument");
    size_t limit = profile_limit(profile);
    if (!limit) return fail(error, YD_PC_UNSUPPORTED, SIZE_MAX, "unknown size profile");
    if (length > YD_PC_LARGE_LIMIT) return fail(error, YD_PC_LIMIT, SIZE_MAX, "encoded input exceeds bound");
    if (length > limit) return fail(error, YD_PC_UNSUPPORTED, SIZE_MAX, "input requires a larger explicit profile");
    if (!charge(budget, 1048576 + 16 * (uint64_t)length))
        return fail(error, YD_PC_LIMIT, SIZE_MAX, "work budget exhausted");
    Parsed parsed = {0}; Parser p = {bytes, length, 0, YD_PC_OK, error};
    if (!catalog_parse(&p, &parsed)) return p.result;
    YDPCResult result = YD_PC_OK;
    YDPolicyCatalog *c = allocate(parsed.count, parsed.source_bytes, budget, &result, error);
    if (!c) return result;
    c->info.generation = parsed.generation;
    unsigned char *cursor = c->sources;
    for (size_t i = 0; i < parsed.count; ++i) {
        c->entries[i] = parsed.entries[i].entry; Entry *e = &c->entries[i];
        p.at = parsed.entries[i].source_offset; size_t n = 0;
        if (!source_string(&p, cursor, e->source_length, &n) || n != e->source_length) {
            free(c); return fail(error, YD_PC_INVALID, p.at, "source changed during parse");
        }
        cursor[n] = 0; e->source = cursor; cursor += n + 1;
    }
    result = finish(c, true, limit, error);
    if (result == YD_PC_OK) *out = c; else free(c);
    return result;
}
static size_t find_index(const YDPolicyCatalog *c, const char *name, size_t n) {
    for (size_t i = 0; i < c->info.count; ++i)
        if (c->entries[i].name_length == n && !memcmp(c->entries[i].name, name, n)) return i;
    return c->info.count;
}
YDPCResult yd_policy_catalog_change(const YDPolicyCatalog *base, const YDPCChange *change,
    YDPCProfile profile, YDPCBudget *budget, YDPolicyCatalog **out, YDPCError *error) {
    clear_error(error); if (out) *out = NULL;
    if (!base || !change || !budget || !out) return fail(error, YD_PC_ERROR, SIZE_MAX, "missing API argument");
    size_t limit = profile_limit(profile);
    if (!limit) return fail(error, YD_PC_UNSUPPORTED, SIZE_MAX, "unknown size profile");
    if (change->operation != YD_PC_SET && change->operation != YD_PC_DISABLE)
        return fail(error, YD_PC_UNSUPPORTED, SIZE_MAX, "unknown operation");
    if (!valid_name(change->collection, change->collection_length))
        return fail(error, YD_PC_INVALID, SIZE_MAX, "invalid collection name");
    if (change->source_length > YD_PC_SOURCE_LIMIT)
        return fail(error, YD_PC_LIMIT, SIZE_MAX, "source exceeds bound");
    if (!charge(budget, 1048576 + 16 * (uint64_t)(base->info.source_bytes + change->source_length)))
        return fail(error, YD_PC_LIMIT, SIZE_MAX, "work budget exhausted");
    size_t index = find_index(base, change->collection, change->collection_length);
    bool exists = index < base->info.count;
    uint64_t version = exists ? base->entries[index].version : 0;
    if (change->expected.generation != base->info.generation ||
        change->expected.version != version ||
        memcmp(change->expected.catalog_sha256, base->info.catalog_sha256, 32))
        return fail(error, YD_PC_CONFLICT, SIZE_MAX, "catalog guard mismatch");
    if (change->operation == YD_PC_SET) {
        if (!schema_profile(change->schema_profile ? change->schema_profile : YD_PC_SCHEMA_PROFILE))
            return fail(error, YD_PC_UNSUPPORTED, SIZE_MAX, "unknown schema profile");
        if (!valid_source(change->source, change->source_length))
            return fail(error, YD_PC_INVALID, SIZE_MAX, "invalid source UTF-8 or empty source");
    } else {
        if (change->source || change->source_length || change->schema_profile)
            return fail(error, YD_PC_INVALID, SIZE_MAX, "disable must not supply source");
        if (!exists) return fail(error, YD_PC_NOT_FOUND, SIZE_MAX, "policy not found");
        if (base->entries[index].mode == YD_PC_OFF)
            return fail(error, YD_PC_CONFLICT, SIZE_MAX, "policy already disabled");
    }
    if (base->info.generation == UINT64_MAX)
        return fail(error, YD_PC_LIMIT, SIZE_MAX, "catalog generation exhausted");
    size_t count = base->info.count + !exists;
    if (count > YD_PC_ENTRY_LIMIT) return fail(error, YD_PC_LIMIT, SIZE_MAX, "too many policies");
    size_t source_bytes = base->info.source_bytes;
    if (change->operation == YD_PC_SET) {
        if (exists) source_bytes -= base->entries[index].source_length;
        source_bytes += change->source_length;
    }
    if (source_bytes > YD_PC_SOURCE_TOTAL_LIMIT)
        return fail(error, YD_PC_LIMIT, SIZE_MAX, "aggregate source exceeds bound");
    YDPCResult result = YD_PC_OK;
    YDPolicyCatalog *c = allocate(count, source_bytes, budget, &result, error);
    if (!c) return result;
    c->info.generation = base->info.generation + 1;
    memcpy(c->entries, base->entries, base->info.count * sizeof(Entry));
    Entry *target = &c->entries[index];
    if (!exists) {
        memcpy(target->name, change->collection, change->collection_length);
        target->name_length = change->collection_length;
    }
    target->version = c->info.generation;
    target->mode = change->operation == YD_PC_SET ? YD_PC_ENFORCE : YD_PC_OFF;
    if (change->operation == YD_PC_SET) {
        target->source = change->source; target->source_length = change->source_length;
        target->profile = schema_profile(change->schema_profile ? change->schema_profile : YD_PC_SCHEMA_PROFILE);
    }
    for (size_t i = 1; i < count; ++i) {
        Entry e = c->entries[i]; size_t j = i;
        while (j && strcmp(c->entries[j - 1].name, e.name) > 0) { c->entries[j] = c->entries[j - 1]; --j; }
        c->entries[j] = e;
    }
    unsigned char *cursor = c->sources;
    for (size_t i = 0; i < count; ++i) {
        Entry *e = &c->entries[i]; memcpy(cursor, e->source, e->source_length);
        cursor[e->source_length] = 0; e->source = cursor; cursor += e->source_length + 1;
    }
    result = finish(c, false, limit, error);
    if (result == YD_PC_OK) *out = c; else free(c);
    return result;
}
YDPCResult yd_policy_catalog_encode(const YDPolicyCatalog *c, YDPCProfile profile,
    YDPCBudget *budget, unsigned char *output, size_t capacity, size_t *written, YDPCError *error) {
    clear_error(error); if (written) *written = 0;
    if (!c || !budget || !output || !written) return fail(error, YD_PC_ERROR, SIZE_MAX, "missing API argument");
    size_t limit = profile_limit(profile);
    if (!limit) return fail(error, YD_PC_UNSUPPORTED, SIZE_MAX, "unknown size profile");
    if (c->info.encoded_bytes > limit) return fail(error, YD_PC_UNSUPPORTED, SIZE_MAX, "catalog requires a larger explicit profile");
    if (!charge(budget, 1024 + c->info.encoded_bytes)) return fail(error, YD_PC_LIMIT, SIZE_MAX, "work budget exhausted");
    if (capacity < c->info.encoded_bytes) return fail(error, YD_PC_LIMIT, SIZE_MAX, "output capacity too small");
    *written = encode(c, output); return YD_PC_OK;
}
YDPCResult yd_policy_catalog_info(const YDPolicyCatalog *c, YDPCInfo *out) {
    if (out) memset(out, 0, sizeof(*out));
    if (!c || !out) return YD_PC_ERROR;
    *out = c->info; return YD_PC_OK;
}
YDPCResult yd_policy_catalog_at(const YDPolicyCatalog *c, size_t index, YDPCEntry *out) {
    if (out) memset(out, 0, sizeof(*out));
    if (!c || !out) return YD_PC_ERROR;
    if (index >= c->info.count) return YD_PC_NOT_FOUND;
    const Entry *e = &c->entries[index];
    out->collection = e->name; out->collection_length = e->name_length;
    out->profile = e->profile; out->version = e->version; out->mode = e->mode;
    out->source = e->source; out->source_length = e->source_length;
    memcpy(out->source_sha256, e->source_hash, 32); memcpy(out->policy_sha256, e->policy_hash, 32);
    return YD_PC_OK;
}
YDPCResult yd_policy_catalog_find(const YDPolicyCatalog *c, const char *name, size_t length, YDPCEntry *out) {
    if (out) memset(out, 0, sizeof(*out));
    if (!c || !out) return YD_PC_ERROR;
    if (!valid_name(name, length)) return YD_PC_INVALID;
    return yd_policy_catalog_at(c, find_index(c, name, length), out);
}
void yd_policy_catalog_free(YDPolicyCatalog *catalog) { free(catalog); }
