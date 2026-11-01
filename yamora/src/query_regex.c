#define _POSIX_C_SOURCE 200809L
#include "query_regex.h"
#include "text.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PROGRAM_LIMIT 16384U
#define NODE_LIMIT 16384U
#define DEPTH_LIMIT 64U
#define REPEAT_LIMIT 1000U
#define RANGE_LIMIT 16384U
#define CODE_MAX 0x10FFFFU
#define UNBOUNDED UINT32_MAX
#define NONE UINT32_MAX

enum { FLAG_I = 1, FLAG_M = 2, FLAG_S = 4, FLAG_X = 8 };
typedef enum { N_CHAR, N_ANY, N_CLASS, N_CAT, N_ALT, N_REPEAT, N_ASSERT } NodeType;
typedef enum { A_BOT, A_BOL, A_EOT, A_EOTNL, A_EOL, A_WORD, A_NOTWORD } Assertion;
typedef enum { I_CHAR, I_ANY, I_ANYNL, I_CLASS, I_SPLIT, I_JMP, I_ASSERT, I_MATCH } Opcode;

typedef struct { uint32_t lo, hi; } Range;
typedef struct {
    Range *ranges;
    size_t count, capacity;
    bool negated, fold;
} Class;
/* Lists use sibling indices: a node array may move while the parser grows. */
typedef struct {
    NodeType type;
    uint32_t value, min, max, child, next;
} Node;
typedef struct {
    Opcode op;
    uint32_t x, y;
} Inst;

struct YDRegex {
    Inst *program;
    size_t count;
    Class *classes;
    size_t class_count;
    bool fold;
};

typedef struct {
    const unsigned char *pattern;
    size_t length, at;
    unsigned flags;
    Node *nodes;
    size_t node_count, node_capacity;
    Class *classes;
    size_t class_count, class_capacity, ranges;
    Inst *program;
    size_t count;
    size_t *work;
    char *error;
    size_t error_length;
    bool failed;
} Parser;

static uint32_t fail(Parser *p, const char *message) {
    if (!p->failed && p->error_length) snprintf(p->error, p->error_length, "%s", message);
    p->failed = true;
    return NONE;
}

static bool charge(Parser *p, size_t units) {
    if (units > *p->work) {
        *p->work = 0;
        fail(p, "regular expression exceeds work budget");
        return false;
    }
    *p->work -= units;
    return true;
}

static bool decode(const unsigned char *s, size_t size, uint32_t *code, size_t *used) {
    if (!size) return false;
    uint32_t c = s[0], minimum;
    size_t n;
    if (c < 0x80) {
        *code = c;
        *used = 1;
        return true;
    }
    if (c >= 0xc2 && c <= 0xdf) { n = 2; c &= 0x1f; minimum = 0x80; }
    else if (c >= 0xe0 && c <= 0xef) { n = 3; c &= 0x0f; minimum = 0x800; }
    else if (c >= 0xf0 && c <= 0xf4) { n = 4; c &= 0x07; minimum = 0x10000; }
    else return false;
    if (size < n) return false;
    for (size_t i = 1; i < n; i++) {
        if ((s[i] & 0xc0) != 0x80) return false;
        c = (c << 6) | (s[i] & 0x3f);
    }
    if (c < minimum || c > CODE_MAX || (c >= 0xd800 && c <= 0xdfff)) return false;
    *code = c;
    *used = n;
    return true;
}

static uint32_t node(Parser *p, NodeType type, uint32_t value) {
    if (p->failed) return NONE;
    if (p->node_count == NODE_LIMIT || !charge(p, 1))
        return fail(p, "regular expression is too complex");
    if (p->node_count == p->node_capacity) {
        size_t capacity = p->node_capacity ? p->node_capacity * 2 : 32;
        Node *nodes = realloc(p->nodes, capacity * sizeof(*nodes));
        if (!nodes) return fail(p, "out of memory compiling regular expression");
        p->nodes = nodes;
        p->node_capacity = capacity;
    }
    p->nodes[p->node_count] = (Node){.type = type, .value = value, .child = NONE, .next = NONE};
    return (uint32_t)p->node_count++;
}

static bool peek(const Parser *p, unsigned char c) { return p->at < p->length && p->pattern[p->at] == c; }

static void skip_extended(Parser *p) {
    if (!(p->flags & FLAG_X)) return;
    while (p->at < p->length) {
        unsigned char c = p->pattern[p->at];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v') p->at++;
        else if (c == '#') {
            while (p->at < p->length && p->pattern[p->at] != '\n') p->at++;
        } else break;
    }
}

static bool add_range(Parser *p, Class *c, uint32_t lo, uint32_t hi) {
    if (p->failed) return false;
    if (p->ranges + c->count >= RANGE_LIMIT || !charge(p, 1)) {
        fail(p, "regular expression is too complex");
        return false;
    }
    if (c->count == c->capacity) {
        size_t capacity = c->capacity ? c->capacity * 2 : 8;
        Range *ranges = realloc(c->ranges, capacity * sizeof(*ranges));
        if (!ranges) {
            fail(p, "out of memory compiling regular expression");
            return false;
        }
        c->ranges = ranges;
        c->capacity = capacity;
    }
    c->ranges[c->count++] = (Range){lo, hi};
    return true;
}

/* Sets are ASCII, matching PCRE without Unicode properties. */
static const Range DIGIT[] = {{'0', '9'}};
static const Range WORD[] = {{'0', '9'}, {'A', 'Z'}, {'_', '_'}, {'a', 'z'}};
static const Range SPACE[] = {{'\t', '\r'}, {' ', ' '}};
static const Range ALPHA[] = {{'A', 'Z'}, {'a', 'z'}};
static const Range ALNUM[] = {{'0', '9'}, {'A', 'Z'}, {'a', 'z'}};
static const Range UPPER[] = {{'A', 'Z'}};
static const Range LOWER[] = {{'a', 'z'}};
static const Range PUNCT[] = {{'!', '/'}, {':', '@'}, {'[', '`'}, {'{', '~'}};
static const Range XDIGIT[] = {{'0', '9'}, {'A', 'F'}, {'a', 'f'}};
static const Range BLANK[] = {{'\t', '\t'}, {' ', ' '}};
static const Range CNTRL[] = {{0, 0x1f}, {0x7f, 0x7f}};
static const Range PRINT[] = {{0x20, 0x7e}};
static const Range GRAPH[] = {{0x21, 0x7e}};

static bool add_set(Parser *p, Class *c, const Range *set, size_t count, bool negated) {
    if (!negated) {
        for (size_t i = 0; i < count; i++)
            if (!add_range(p, c, set[i].lo, set[i].hi)) return false;
        return true;
    }
    uint32_t next = 0;
    for (size_t i = 0; i < count; i++) {
        if (set[i].lo > next && !add_range(p, c, next, set[i].lo - 1)) return false;
        next = set[i].hi + 1;
    }
    return add_range(p, c, next, CODE_MAX);
}

static bool shorthand(Parser *p, Class *c, unsigned char letter) {
    switch (letter) {
    case 'd': return add_set(p, c, DIGIT, 1, false);
    case 'D': return add_set(p, c, DIGIT, 1, true);
    case 'w': return add_set(p, c, WORD, 4, false);
    case 'W': return add_set(p, c, WORD, 4, true);
    case 's': return add_set(p, c, SPACE, 2, false);
    default: return add_set(p, c, SPACE, 2, true);
    }
}

static int range_order(const void *left, const void *right) {
    const Range *a = left, *b = right;
    return (a->lo > b->lo) - (a->lo < b->lo);
}

/* Case-insensitive classes also contain the simple folding of each member,
 * so a subject matches when either it or its own folding is a member. */
static bool class_finish(Parser *p, Class *c) {
    if (c->fold) {
        size_t original = c->count;
        for (size_t r = 0; r < original; r++) {
            for (size_t entry = yd_text_fold_seek(c->ranges[r].lo);; entry++) {
                uint32_t code, folded;
                if (!yd_text_fold_entry(entry, &code, &folded) || code > c->ranges[r].hi) break;
                if (!charge(p, 1)) return false;
                if (folded != code && !add_range(p, c, folded, folded)) return false;
            }
        }
    }
    if (c->count > 1) {
        if (!charge(p, c->count)) return false;
        qsort(c->ranges, c->count, sizeof(*c->ranges), range_order);
    }
    size_t kept = 0;
    for (size_t i = 0; i < c->count; i++) {
        if (kept && c->ranges[i].lo <= c->ranges[kept - 1].hi + 1) {
            if (c->ranges[i].hi > c->ranges[kept - 1].hi) c->ranges[kept - 1].hi = c->ranges[i].hi;
        } else c->ranges[kept++] = c->ranges[i];
    }
    c->count = kept;
    p->ranges += kept;
    return true;
}

static uint32_t class_node(Parser *p, Class *c) {
    if (p->failed || !class_finish(p, c)) {
        free(c->ranges);
        return NONE;
    }
    if (p->class_count == p->class_capacity) {
        size_t capacity = p->class_capacity ? p->class_capacity * 2 : 4;
        Class *classes = realloc(p->classes, capacity * sizeof(*classes));
        if (!classes) {
            free(c->ranges);
            return fail(p, "out of memory compiling regular expression");
        }
        p->classes = classes;
        p->class_capacity = capacity;
    }
    p->classes[p->class_count] = *c;
    uint32_t index = (uint32_t)p->class_count++;
    return node(p, N_CLASS, index);
}

static int hex_digit(unsigned char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Reads one escaped code point after the backslash. Letters and digits are
 * reserved: an unknown escape is an error instead of a silent literal. */
static bool escape_code(Parser *p, uint32_t *code) {
    unsigned char c = p->pattern[p->at];
    static const char simple[] = "ntrfvea", values[] = {'\n', '\t', '\r', '\f', '\v', 27, 7};
    const char *found = c ? strchr(simple, c) : NULL;
    if (found) {
        p->at++;
        *code = (uint32_t)values[found - simple];
        return true;
    }
    if (c == 'x') {
        p->at++;
        uint32_t value = 0;
        size_t digits = 0;
        if (peek(p, '{')) {
            p->at++;
            while (p->at < p->length && hex_digit(p->pattern[p->at]) >= 0 && digits < 7) {
                value = value * 16 + (uint32_t)hex_digit(p->pattern[p->at++]);
                digits++;
            }
            if (!digits || !peek(p, '}') || value > CODE_MAX || (value >= 0xd800 && value <= 0xdfff)) {
                fail(p, "invalid \\x{...} escape");
                return false;
            }
            p->at++;
        } else {
            while (p->at < p->length && digits < 2 && hex_digit(p->pattern[p->at]) >= 0) {
                value = value * 16 + (uint32_t)hex_digit(p->pattern[p->at++]);
                digits++;
            }
            if (!digits) {
                fail(p, "invalid \\x escape");
                return false;
            }
        }
        *code = value;
        return true;
    }
    if (c == '0') {
        p->at++;
        uint32_t value = 0;
        for (size_t digits = 0; digits < 2 && p->at < p->length && p->pattern[p->at] >= '0' &&
                                p->pattern[p->at] <= '7'; digits++)
            value = value * 8 + (uint32_t)(p->pattern[p->at++] - '0');
        *code = value;
        return true;
    }
    if (c >= '1' && c <= '9') {
        fail(p, "backreferences are not supported");
        return false;
    }
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
        fail(p, "unsupported escape sequence in regular expression");
        return false;
    }
    size_t used;
    if (!decode(p->pattern + p->at, p->length - p->at, code, &used)) {
        fail(p, "regular expression must be valid UTF-8");
        return false;
    }
    p->at += used;
    return true;
}

static bool posix_class(Parser *p, Class *c) {
    static const struct { const char *name; const Range *set; size_t count; } names[] = {
        {"alpha", ALPHA, 2}, {"digit", DIGIT, 1}, {"alnum", ALNUM, 3}, {"space", SPACE, 2},
        {"upper", UPPER, 1}, {"lower", LOWER, 1}, {"punct", PUNCT, 4}, {"xdigit", XDIGIT, 3},
        {"word", WORD, 4}, {"blank", BLANK, 2}, {"cntrl", CNTRL, 2}, {"print", PRINT, 1},
        {"graph", GRAPH, 1}};
    size_t start = p->at + 2;
    bool negated = start < p->length && p->pattern[start] == '^';
    if (negated) start++;
    for (size_t i = 0; i < sizeof(names) / sizeof(*names); i++) {
        size_t n = strlen(names[i].name);
        if (start + n + 2 <= p->length && !memcmp(p->pattern + start, names[i].name, n) &&
            !memcmp(p->pattern + start + n, ":]", 2)) {
            p->at = start + n + 2;
            return add_set(p, c, names[i].set, names[i].count, negated);
        }
    }
    fail(p, "unknown POSIX character class");
    return false;
}

/* 1: one code point in *code, 2: a set was added, 0: failure. */
static int class_atom(Parser *p, Class *c, uint32_t *code) {
    unsigned char ch = p->pattern[p->at];
    if (ch == '\\') {
        p->at++;
        if (p->at == p->length) {
            fail(p, "pattern ends with a backslash");
            return 0;
        }
        unsigned char letter = p->pattern[p->at];
        if (letter && strchr("dDwWsS", letter)) {
            p->at++;
            return shorthand(p, c, letter) ? 2 : 0;
        }
        if (letter == 'b') {
            p->at++;
            *code = 8;
            return 1;
        }
        return escape_code(p, code) ? 1 : 0;
    }
    if (ch == '[' && p->at + 1 < p->length && p->pattern[p->at + 1] == ':')
        return posix_class(p, c) ? 2 : 0;
    size_t used;
    if (!decode(p->pattern + p->at, p->length - p->at, code, &used)) {
        fail(p, "regular expression must be valid UTF-8");
        return 0;
    }
    p->at += used;
    return 1;
}

static uint32_t parse_class(Parser *p) {
    p->at++;
    Class c = {.fold = (p->flags & FLAG_I) != 0};
    if (peek(p, '^')) {
        c.negated = true;
        p->at++;
    }
    for (bool first = true;; first = false) {
        if (p->at >= p->length) {
            free(c.ranges);
            return fail(p, "unterminated character class");
        }
        if (p->pattern[p->at] == ']' && !first) {
            p->at++;
            break;
        }
        uint32_t lo = 0, hi = 0;
        int kind = class_atom(p, &c, &lo);
        if (!kind) break;
        if (kind == 1 && p->at + 1 < p->length && p->pattern[p->at] == '-' &&
            p->pattern[p->at + 1] != ']') {
            p->at++;
            int end = class_atom(p, &c, &hi);
            if (!end) break;
            if (end == 2) {
                fail(p, "invalid character class range");
                break;
            }
            if (hi < lo) {
                fail(p, "character class range is out of order");
                break;
            }
            if (!add_range(p, &c, lo, hi)) break;
        } else if (kind == 1 && !add_range(p, &c, lo, lo)) break;
    }
    if (p->failed) {
        free(c.ranges);
        return NONE;
    }
    return class_node(p, &c);
}

static uint32_t char_node(Parser *p, uint32_t code) {
    return node(p, N_CHAR, (p->flags & FLAG_I) ? yd_text_fold_simple(code) : code);
}

static uint32_t parse_escape(Parser *p) {
    p->at++;
    if (p->at == p->length) return fail(p, "pattern ends with a backslash");
    unsigned char c = p->pattern[p->at];
    if (c && strchr("dDwWsS", c)) {
        p->at++;
        Class set = {0};
        if (!shorthand(p, &set, c)) {
            free(set.ranges);
            return NONE;
        }
        return class_node(p, &set);
    }
    static const char anchors[] = "bBAzZ";
    static const Assertion kinds[] = {A_WORD, A_NOTWORD, A_BOT, A_EOT, A_EOTNL};
    const char *anchor = c ? strchr(anchors, c) : NULL;
    if (anchor) {
        p->at++;
        return node(p, N_ASSERT, kinds[anchor - anchors]);
    }
    uint32_t code;
    if (!escape_code(p, &code)) return NONE;
    return char_node(p, code);
}

/* {n}, {n,} or {n,m}. Anything else is a literal brace, as in PCRE. */
static bool counted(Parser *p, uint32_t *min, uint32_t *max) {
    size_t at = p->at + 1;
    uint32_t a = 0, b = 0;
    bool digits = false, large = false;
    while (at < p->length && p->pattern[at] >= '0' && p->pattern[at] <= '9') {
        a = a * 10 + (uint32_t)(p->pattern[at++] - '0');
        if (a > REPEAT_LIMIT) { large = true; a = REPEAT_LIMIT + 1; }
        digits = true;
    }
    if (!digits || at >= p->length) return false;
    if (p->pattern[at] == '}') b = a;
    else if (p->pattern[at] == ',') {
        at++;
        if (at < p->length && p->pattern[at] == '}') b = UNBOUNDED;
        else {
            bool upper = false;
            while (at < p->length && p->pattern[at] >= '0' && p->pattern[at] <= '9') {
                b = b * 10 + (uint32_t)(p->pattern[at++] - '0');
                if (b > REPEAT_LIMIT) { large = true; b = REPEAT_LIMIT + 1; }
                upper = true;
            }
            if (!upper || at >= p->length || p->pattern[at] != '}') return false;
        }
    } else return false;
    p->at = at + 1;
    if (large) fail(p, "counted repetition exceeds 1000");
    else if (b < a) fail(p, "counted repetition range is out of order");
    *min = a;
    *max = b;
    return true;
}

static uint32_t parse_alt(Parser *p, unsigned depth);

static uint32_t parse_atom(Parser *p, unsigned depth) {
    unsigned char c = p->pattern[p->at];
    if (c == '(') {
        p->at++;
        if (peek(p, '?')) {
            if (p->at + 1 < p->length && p->pattern[p->at + 1] == ':') p->at += 2;
            else return fail(p, "only (?:...) groups are supported; lookaround, named groups and inline options are not");
        }
        uint32_t inner = parse_alt(p, depth + 1);
        if (inner == NONE) return NONE;
        if (!peek(p, ')')) return fail(p, "unbalanced parenthesis in regular expression");
        p->at++;
        return inner;
    }
    if (c == '*' || c == '+' || c == '?') return fail(p, "quantifier has nothing to repeat");
    if (c == '{') {
        size_t at = p->at;
        uint32_t min, max;
        if (counted(p, &min, &max)) {
            p->at = at;
            return fail(p, "quantifier has nothing to repeat");
        }
    }
    if (c == '.') {
        p->at++;
        return node(p, N_ANY, 0);
    }
    if (c == '^') {
        p->at++;
        return node(p, N_ASSERT, (p->flags & FLAG_M) ? A_BOL : A_BOT);
    }
    if (c == '$') {
        p->at++;
        return node(p, N_ASSERT, (p->flags & FLAG_M) ? A_EOL : A_EOTNL);
    }
    if (c == '[') return parse_class(p);
    if (c == '\\') return parse_escape(p);
    uint32_t code;
    size_t used;
    if (!decode(p->pattern + p->at, p->length - p->at, &code, &used))
        return fail(p, "regular expression must be valid UTF-8");
    p->at += used;
    return char_node(p, code);
}

static bool quantifier_next(Parser *p) {
    if (p->at >= p->length) return false;
    unsigned char c = p->pattern[p->at];
    if (c == '*' || c == '+' || c == '?') return true;
    if (c != '{') return false;
    size_t at = p->at;
    uint32_t min, max;
    bool found = counted(p, &min, &max);
    p->at = at;
    return found;
}

static uint32_t parse_repeat(Parser *p, unsigned depth) {
    uint32_t atom = parse_atom(p, depth);
    if (atom == NONE) return NONE;
    skip_extended(p);
    if (!quantifier_next(p)) return atom;
    uint32_t min = 0, max = UNBOUNDED;
    unsigned char c = p->pattern[p->at];
    if (c == '*') p->at++;
    else if (c == '+') { min = 1; p->at++; }
    else if (c == '?') { max = 1; p->at++; }
    else counted(p, &min, &max);
    if (p->failed) return NONE;
    /* A lazy quantifier accepts the same language; only existence matters. */
    if (peek(p, '?')) p->at++;
    else if (peek(p, '+')) return fail(p, "possessive quantifiers are not supported");
    skip_extended(p);
    if (quantifier_next(p)) return fail(p, "nested quantifiers require a group");
    uint32_t repeat = node(p, N_REPEAT, 0);
    if (repeat == NONE) return NONE;
    p->nodes[repeat].min = min;
    p->nodes[repeat].max = max;
    p->nodes[repeat].child = atom;
    return repeat;
}

static uint32_t parse_cat(Parser *p, unsigned depth) {
    uint32_t cat = node(p, N_CAT, 0), last = NONE;
    if (cat == NONE) return NONE;
    for (;;) {
        skip_extended(p);
        if (p->at == p->length || peek(p, '|') || peek(p, ')')) break;
        uint32_t item = parse_repeat(p, depth);
        if (item == NONE) return NONE;
        if (last == NONE) p->nodes[cat].child = item;
        else p->nodes[last].next = item;
        last = item;
    }
    return cat;
}

static uint32_t parse_alt(Parser *p, unsigned depth) {
    if (depth > DEPTH_LIMIT) return fail(p, "regular expression nesting exceeds 64");
    uint32_t first = parse_cat(p, depth);
    if (first == NONE || !peek(p, '|')) return first;
    uint32_t alt = node(p, N_ALT, 0), last = first;
    if (alt == NONE) return NONE;
    p->nodes[alt].child = first;
    while (peek(p, '|')) {
        p->at++;
        uint32_t next = parse_cat(p, depth);
        if (next == NONE) return NONE;
        p->nodes[last].next = next;
        last = next;
    }
    return alt;
}

static size_t add_size(size_t a, size_t b) { return a > PROGRAM_LIMIT || b > PROGRAM_LIMIT - a ? PROGRAM_LIMIT + 1 : a + b; }
static size_t times(size_t a, size_t b) { return b && a > (PROGRAM_LIMIT + 1) / b ? PROGRAM_LIMIT + 1 : add_size(0, a * b); }

static size_t program_size(const Parser *p, uint32_t index) {
    const Node *n = &p->nodes[index];
    size_t total = 0, children = 0;
    switch (n->type) {
    case N_CAT:
    case N_ALT:
        for (uint32_t child = n->child; child != NONE; child = p->nodes[child].next, children++)
            total = add_size(total, program_size(p, child));
        return n->type == N_ALT && children ? add_size(total, 2 * (children - 1)) : total;
    case N_REPEAT: {
        size_t child = program_size(p, n->child);
        total = times(child, n->min);
        return n->max == UNBOUNDED ? add_size(total, add_size(child, 2))
                                   : add_size(total, times(add_size(child, 1), n->max - n->min));
    }
    default:
        return 1;
    }
}

static uint32_t emit_one(Parser *p, Opcode op, uint32_t x, uint32_t y) {
    p->program[p->count] = (Inst){.op = op, .x = x, .y = y};
    return (uint32_t)p->count++;
}

static void emit(Parser *p, uint32_t index) {
    const Node n = p->nodes[index];
    switch (n.type) {
    case N_CHAR: emit_one(p, I_CHAR, n.value, (p->flags & FLAG_I) != 0); break;
    case N_ANY: emit_one(p, (p->flags & FLAG_S) ? I_ANY : I_ANYNL, 0, 0); break;
    case N_CLASS: emit_one(p, I_CLASS, n.value, 0); break;
    case N_ASSERT: emit_one(p, I_ASSERT, n.value, 0); break;
    case N_CAT:
        for (uint32_t child = n.child; child != NONE; child = p->nodes[child].next) emit(p, child);
        break;
    case N_ALT: {
        uint32_t chain = NONE;
        for (uint32_t child = n.child; child != NONE; child = p->nodes[child].next) {
            if (p->nodes[child].next == NONE) {
                emit(p, child);
                break;
            }
            uint32_t split = emit_one(p, I_SPLIT, (uint32_t)p->count + 1, 0);
            emit(p, child);
            chain = emit_one(p, I_JMP, chain, 0);
            p->program[split].y = (uint32_t)p->count;
        }
        for (uint32_t jump = chain; jump != NONE;) {
            uint32_t next = p->program[jump].x;
            p->program[jump].x = (uint32_t)p->count;
            jump = next;
        }
        break;
    }
    case N_REPEAT:
        for (uint32_t i = 0; i < n.min; i++) emit(p, n.child);
        if (n.max == UNBOUNDED) {
            uint32_t loop = emit_one(p, I_SPLIT, (uint32_t)p->count + 1, 0);
            emit(p, n.child);
            emit_one(p, I_JMP, loop, 0);
            p->program[loop].y = (uint32_t)p->count;
        } else {
            uint32_t chain = NONE;
            for (uint32_t i = n.min; i < n.max; i++) {
                chain = emit_one(p, I_SPLIT, (uint32_t)p->count + 1, chain);
                emit(p, n.child);
            }
            for (uint32_t split = chain; split != NONE;) {
                uint32_t next = p->program[split].y;
                p->program[split].y = (uint32_t)p->count;
                split = next;
            }
        }
        break;
    }
}

static void parser_free(Parser *p) {
    for (size_t i = 0; i < p->class_count; i++) free(p->classes[i].ranges);
    free(p->classes);
    free(p->nodes);
    free(p->program);
}

void yd_regex_free(YDRegex *regex) {
    if (!regex) return;
    for (size_t i = 0; i < regex->class_count; i++) free(regex->classes[i].ranges);
    free(regex->classes);
    free(regex->program);
    free(regex);
}

YDRegex *yd_regex_compile(const char *pattern, const char *options, size_t *work,
                          char *error, size_t length) {
    if (length) error[0] = 0;
    Parser p = {.work = work, .error = error, .error_length = length};
    if (!pattern || !work) {
        fail(&p, "invalid regular expression request");
        return NULL;
    }
    p.pattern = (const unsigned char *)pattern;
    p.length = strnlen(pattern, YD_REGEX_PATTERN_LIMIT + 1);
    if (p.length > YD_REGEX_PATTERN_LIMIT) {
        fail(&p, "regular expression exceeds 4096 bytes");
        return NULL;
    }
    for (const char *option = options ? options : ""; *option; option++) {
        const char *known = strchr("imsx", *option);
        unsigned bit = known ? 1U << (known - "imsx") : 0;
        if (!bit || (p.flags & bit)) {
            fail(&p, "$options accepts distinct letters from imsx");
            return NULL;
        }
        p.flags |= bit;
    }
    if (!charge(&p, p.length + 1)) return NULL;
    for (size_t at = 0; at < p.length;) {
        uint32_t code;
        size_t used;
        if (!decode(p.pattern + at, p.length - at, &code, &used)) {
            fail(&p, "regular expression must be valid UTF-8");
            return NULL;
        }
        at += used;
    }
    YDRegex *regex = NULL;
    uint32_t root = parse_alt(&p, 0);
    if (!p.failed && p.at < p.length) fail(&p, "unbalanced parenthesis in regular expression");
    size_t size = p.failed ? 0 : add_size(program_size(&p, root), 1);
    if (!p.failed && size > PROGRAM_LIMIT) fail(&p, "regular expression is too complex");
    if (!p.failed && charge(&p, size)) {
        p.program = malloc(size * sizeof(*p.program));
        regex = calloc(1, sizeof(*regex));
        if (!p.program || !regex) fail(&p, "out of memory compiling regular expression");
    }
    if (p.failed) {
        free(regex);
        parser_free(&p);
        return NULL;
    }
    emit(&p, root);
    emit_one(&p, I_MATCH, 0, 0);
    *regex = (YDRegex){.program = p.program, .count = p.count, .classes = p.classes,
                       .class_count = p.class_count, .fold = (p.flags & FLAG_I) != 0};
    free(p.nodes);
    return regex;
}

typedef struct {
    size_t pos;
    uint32_t previous, current;
    size_t used;
} Context;

static void read_at(const unsigned char *subject, size_t size, size_t pos, uint32_t previous,
                    Context *context) {
    context->pos = pos;
    context->previous = previous;
    context->current = NONE;
    context->used = 0;
    if (pos >= size) return;
    if (!decode(subject + pos, size - pos, &context->current, &context->used)) {
        context->current = subject[pos];
        context->used = 1;
    }
}

static bool word(uint32_t code) {
    return code != NONE && ((code >= '0' && code <= '9') || (code >= 'A' && code <= 'Z') ||
                            (code >= 'a' && code <= 'z') || code == '_');
}

static bool holds(uint32_t assertion, const Context *c, size_t size) {
    switch (assertion) {
    case A_BOT: return c->pos == 0;
    case A_BOL: return c->pos == 0 || c->previous == '\n';
    case A_EOT: return c->pos >= size;
    case A_EOTNL: return c->pos >= size || (c->pos + 1 == size && c->current == '\n');
    case A_EOL: return c->pos >= size || c->current == '\n';
    case A_WORD: return word(c->previous) != word(c->current);
    default: return word(c->previous) == word(c->current);
    }
}

static bool member(const Class *c, uint32_t code) {
    size_t lo = 0, hi = c->count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (code < c->ranges[mid].lo) hi = mid;
        else if (code > c->ranges[mid].hi) lo = mid + 1;
        else return true;
    }
    return false;
}

typedef struct {
    const YDRegex *regex;
    uint32_t *mark, *stack, generation;
    size_t size, *work;
} Machine;

/* Follows every epsilon edge once per position; a pending match wins. */
static int closure(Machine *m, uint32_t start, const Context *context, uint32_t *list,
                   size_t *count) {
    size_t top = 0;
    m->stack[top++] = start;
    while (top) {
        uint32_t pc = m->stack[--top];
        if (m->mark[pc] == m->generation) continue;
        m->mark[pc] = m->generation;
        if (!*m->work) return -1;
        --*m->work;
        const Inst *in = &m->regex->program[pc];
        switch (in->op) {
        case I_JMP: m->stack[top++] = in->x; break;
        case I_SPLIT:
            m->stack[top++] = in->y;
            m->stack[top++] = in->x;
            break;
        case I_ASSERT:
            if (holds(in->x, context, m->size)) m->stack[top++] = pc + 1;
            break;
        case I_MATCH: return 1;
        default: list[(*count)++] = pc;
        }
    }
    return 0;
}

static bool consumes(const YDRegex *regex, const Inst *in, uint32_t code, uint32_t folded) {
    switch (in->op) {
    case I_CHAR: return (in->y ? folded : code) == in->x;
    case I_ANY: return true;
    case I_ANYNL: return code != '\n';
    case I_CLASS: {
        const Class *c = &regex->classes[in->x];
        bool found = member(c, code) || (c->fold && folded != code && member(c, folded));
        return found != c->negated;
    }
    default: return false;
    }
}

int yd_regex_search(const YDRegex *regex, const char *subject, size_t size, size_t *work) {
    if (!regex || !work || (!subject && size)) return -1;
    size_t n = regex->count;
    uint32_t *current = malloc(n * sizeof(uint32_t)), *next = malloc(n * sizeof(uint32_t));
    Machine m = {.regex = regex, .mark = calloc(n, sizeof(uint32_t)),
                 .stack = malloc((2 * n + 2) * sizeof(uint32_t)), .generation = 1, .size = size,
                 .work = work};
    int result = -1;
    if (!current || !next || !m.mark || !m.stack) goto done;
    const unsigned char *bytes = (const unsigned char *)subject;
    size_t count = 0;
    Context context;
    read_at(bytes, size, 0, NONE, &context);
    for (;;) {
        /* Unanchored search: a fresh thread starts at every position. */
        result = closure(&m, 0, &context, current, &count);
        if (result || context.pos >= size) break;
        uint32_t code = context.current;
        uint32_t folded = regex->fold ? yd_text_fold_simple(code) : code;
        Context following;
        read_at(bytes, size, context.pos + context.used, code, &following);
        m.generation++;
        size_t following_count = 0;
        if (count + 1 > *work) {
            *work = 0;
            result = -1;
            break;
        }
        *work -= count + 1;
        for (size_t i = 0; i < count && !result; i++) {
            if (consumes(regex, &regex->program[current[i]], code, folded))
                result = closure(&m, current[i] + 1, &following, next, &following_count);
        }
        if (result) break;
        uint32_t *swap = current;
        current = next;
        next = swap;
        count = following_count;
        context = following;
    }
done:
    free(current);
    free(next);
    free(m.mark);
    free(m.stack);
    return result;
}
