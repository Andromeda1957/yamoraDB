#define _POSIX_C_SOURCE 200809L
#include "patch.h"

#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <yaml.h>

#define PATCH_OPERATION_LIMIT 1024U
#define PATCH_EACH_LIMIT 1024U

typedef struct Meta {
    const YDValue *value;
    struct Meta **children;
    size_t key_start, key_end;
    bool flow;
} Meta;

/* A requested operator, or after resolve() one primitive source edit: $set,
 * $unset, $push (argument is the sequence of items to append), $pull or
 * $rename. Primitives own their computed argument. */
typedef struct {
    const char *name;
    const YDValue *argument;
    const YDValue *each; /* $each list of $push or $addToSet */
    const char *path;
    char *storage;
    char *parts[YD_DEPTH_LIMIT];
    size_t count;
    char *target_storage; /* $rename destination */
    char *target_parts[YD_DEPTH_LIMIT];
    size_t target_count;
    YDValue *owned;
} Operation;

typedef struct {
    unsigned char *body;
    size_t length, limit;
    YDValue *root;
    Meta *meta;
    unsigned char *trivia;
    char *error;
    size_t error_length;
} Patch;

static bool failure(Patch *patch, const char *message) {
    if (patch->error && patch->error_length && !patch->error[0])
        snprintf(patch->error, patch->error_length, "%s", message);
    return false;
}

static void meta_free(Meta *meta) {
    if (!meta) return;
    if (meta->children)
        for (size_t index = 0; index < meta->value->count; index++) meta_free(meta->children[index]);
    free(meta->children); free(meta);
}

static Meta *meta_read(yaml_parser_t *parser, yaml_event_t *event, const YDValue *value, const YDSourceMap *offsets) {
    Meta *meta = calloc(1, sizeof(*meta));
    if (!meta) return NULL;
    meta->value = value;
    if (value->type != YD_ARRAY && value->type != YD_MAP) return meta;
    meta->flow = value->type == YD_MAP ? event->data.mapping_start.style == YAML_FLOW_MAPPING_STYLE :
        event->data.sequence_start.style == YAML_FLOW_SEQUENCE_STYLE;
    if (value->count && !(meta->children = calloc(value->count, sizeof(*meta->children)))) { meta_free(meta); return NULL; }
    for (size_t index = 0; index < value->count; index++) {
        yaml_event_t child;
        if (!yaml_parser_parse(parser, &child)) { meta_free(meta); return NULL; }
        size_t key_start = 0, key_end = 0;
        if (value->type == YD_MAP) {
            key_start = yd_source_offset(offsets, child.start_mark.index); key_end = yd_source_offset(offsets, child.end_mark.index);
            yaml_event_delete(&child);
            if (!yaml_parser_parse(parser, &child)) { meta_free(meta); return NULL; }
        }
        meta->children[index] = meta_read(parser, &child, value->items[index], offsets);
        yaml_event_delete(&child);
        if (!meta->children[index]) { meta_free(meta); return NULL; }
        meta->children[index]->key_start = key_start;
        meta->children[index]->key_end = key_end;
    }
    yaml_event_t end;
    if (!yaml_parser_parse(parser, &end)) { meta_free(meta); return NULL; }
    yaml_event_delete(&end);
    return meta;
}

static void protect_scalars(const Meta *meta, unsigned char *trivia) {
    if (meta->key_end > meta->key_start) memset(trivia + meta->key_start, 1, meta->key_end - meta->key_start);
    if (meta->value->type != YD_MAP && meta->value->type != YD_ARRAY) {
        memset(trivia + meta->value->start, 1, meta->value->end - meta->value->start);
    } else for (size_t index = 0; index < meta->value->count; index++) protect_scalars(meta->children[index], trivia);
}

static void release_tree(Patch *patch) {
    meta_free(patch->meta); patch->meta = NULL;
    yd_free(patch->root); patch->root = NULL;
    free(patch->trivia); patch->trivia = NULL;
}

static bool parse_source(Patch *patch) {
    release_tree(patch);
    patch->root = yd_parse_sized(patch->body, patch->length, patch->limit, patch->error, patch->error_length);
    if (!patch->root) return false;
    YDSourceMap offsets;
    bool mapped = yd_source_map_init(&offsets, patch->body, patch->length);
    patch->trivia = calloc(patch->length + 1, 1);
    if (!mapped || !patch->trivia) { yd_source_map_free(&offsets); return failure(patch, "out of memory"); }
    yaml_parser_t parser;
    if (!yaml_parser_initialize(&parser)) { yd_source_map_free(&offsets); return failure(patch, "out of memory"); }
    yaml_parser_set_input_string(&parser, patch->body, patch->length);
    yaml_event_t event;
    bool found = false;
    while (yaml_parser_parse(&parser, &event)) {
        if (event.type == YAML_SCALAR_EVENT || event.type == YAML_SEQUENCE_START_EVENT || event.type == YAML_MAPPING_START_EVENT) {
            patch->meta = meta_read(&parser, &event, patch->root, &offsets);
            yaml_event_delete(&event); found = patch->meta != NULL; break;
        }
        bool end = event.type == YAML_STREAM_END_EVENT;
        yaml_event_delete(&event);
        if (end) {
            patch->meta = calloc(1, sizeof(*patch->meta));
            if (patch->meta) { patch->meta->value = patch->root; found = true; }
            break;
        }
    }
    yaml_parser_delete(&parser); yd_source_map_free(&offsets);
    if (!found) return failure(patch, "cannot locate YAML source spans");
    protect_scalars(patch->meta, patch->trivia);
    for (size_t index = 0; index < patch->length; index++) {
        if (!patch->trivia[index] && patch->body[index] == '#') {
            while (index < patch->length && patch->body[index] != '\r' && patch->body[index] != '\n') patch->trivia[index++] = 2;
            if (index == patch->length) break;
        }
    }
    return true;
}

static bool splice(Patch *patch, size_t start, size_t end, const char *replacement, size_t length) {
    if (start > end || end > patch->length || length > patch->limit - (patch->length - (end - start)))
        return failure(patch, "patched document exceeds size limit");
    size_t new_length = patch->length - (end - start) + length;
    unsigned char *body = malloc(new_length + 1);
    if (!body) return failure(patch, "out of memory");
    memcpy(body, patch->body, start);
    if (length) memcpy(body + start, replacement, length);
    memcpy(body + start + length, patch->body + end, patch->length - end);
    body[new_length] = 0;
    free(patch->body); patch->body = body; patch->length = new_length;
    return true;
}

static bool numeric_index(const char *part, size_t *index) {
    if (!*part || (part[0] == '0' && part[1])) return false;
    *index = 0;
    for (; *part; part++) {
        if (*part < '0' || *part > '9' || *index > (SIZE_MAX - (unsigned)(*part - '0')) / 10) return false;
        *index = *index * 10 + (unsigned)(*part - '0');
    }
    return true;
}

static size_t child_index(const YDValue *value, const char *part) {
    if (value->type == YD_MAP) {
        for (size_t index = 0; index < value->count; index++) if (strcmp(value->keys[index], part) == 0) return index;
    } else if (value->type == YD_ARRAY) {
        size_t index;
        if (numeric_index(part, &index) && index < value->count) return index;
    }
    return SIZE_MAX;
}

static Meta *locate(Meta *meta, const Operation *operation, size_t count) {
    for (size_t part = 0; meta && part < count; part++) {
        size_t index = child_index(meta->value, operation->parts[part]);
        meta = index == SIZE_MAX ? NULL : meta->children[index];
    }
    return meta;
}

static bool add_child(YDValue *parent, const char *key, YDValue *child) {
    YDValue **items = realloc(parent->items, (parent->count + 1) * sizeof(*items));
    if (!items) return false;
    parent->items = items;
    if (parent->type == YD_MAP) {
        char **keys = realloc(parent->keys, (parent->count + 1) * sizeof(*keys));
        if (!keys) return false;
        parent->keys = keys;
        parent->keys[parent->count] = strdup(key);
        if (!parent->keys[parent->count]) return false;
    }
    parent->items[parent->count++] = child;
    return true;
}

static YDValue *branch(const Operation *operation, size_t first) {
    YDValue *value = yd_clone(operation->argument);
    for (size_t part = operation->count; value && part > first; part--) {
        YDValue *map = calloc(1, sizeof(*map));
        if (!map) { yd_free(value); return NULL; }
        map->type = YD_MAP;
        if (!add_child(map, operation->parts[part - 1], value)) { yd_free(value); yd_free(map); return NULL; }
        value = map;
    }
    return value;
}

static void remove_value(YDValue *parent, size_t index) {
    yd_free(parent->items[index]);
    if (parent->type == YD_MAP) {
        free(parent->keys[index]);
        memmove(parent->keys + index, parent->keys + index + 1, (parent->count - index - 1) * sizeof(*parent->keys));
    }
    memmove(parent->items + index, parent->items + index + 1, (parent->count - index - 1) * sizeof(*parent->items));
    parent->count--;
}

static bool expected_change(Patch *patch, YDValue **root, const Operation *operation) {
    bool set = strcmp(operation->name, "$set") == 0;
    bool unset = strcmp(operation->name, "$unset") == 0;
    YDValue **slot = root;
    YDValue *parent = NULL;
    size_t index = 0;
    for (size_t part = 0; part < operation->count; part++) {
        if ((*slot)->type == YD_NULL && unset) return true;
        if ((*slot)->type == YD_NULL && set) {
            YDValue *created = branch(operation, part);
            if (!created) return failure(patch, "out of memory");
            yd_free(*slot); *slot = created; return true;
        }
        parent = *slot;
        index = child_index(parent, operation->parts[part]);
        if (index == SIZE_MAX) {
            if (set && parent->type == YD_MAP) {
                YDValue *created = branch(operation, part + 1);
                if (!created || !add_child(parent, operation->parts[part], created)) { yd_free(created); return failure(patch, "out of memory"); }
                return true;
            }
            if (unset && (parent->type == YD_MAP || parent->type == YD_ARRAY)) return true;
            return failure(patch, "mutation path is missing or traverses a scalar");
        }
        slot = &parent->items[index];
    }
    if (set) {
        YDValue *created = yd_clone(operation->argument);
        if (!created) return failure(patch, "out of memory");
        yd_free(*slot); *slot = created;
    } else if (unset) remove_value(parent, index);
    else {
        if ((*slot)->type != YD_ARRAY) return failure(patch, "array mutation target must be an array");
        if (strcmp(operation->name, "$push") == 0) {
            for (size_t item = 0; item < operation->argument->count; item++) {
                YDValue *created = yd_clone(operation->argument->items[item]);
                if (!created || !add_child(*slot, NULL, created)) { yd_free(created); return failure(patch, "out of memory"); }
            }
        } else {
            for (size_t item = (*slot)->count; item > 0; item--)
                if (yd_equal((*slot)->items[item - 1], operation->argument)) remove_value(*slot, item - 1);
        }
    }
    return true;
}

static size_t column(const Patch *patch, size_t position) {
    size_t begin = position;
    while (begin && patch->body[begin - 1] != '\n' && patch->body[begin - 1] != '\r') begin--;
    if (!begin && position >= 3 && patch->length >= 3 && memcmp(patch->body, "\xef\xbb\xbf", 3) == 0) begin = 3;
    return position - begin;
}

static bool indentless_sequence(const Patch *patch, const Meta *meta) {
    return meta->value->type == YD_ARRAY && !meta->flow && meta->key_end > meta->key_start &&
        column(patch, meta->value->start) <= column(patch, meta->key_start);
}

static size_t after_line(const Patch *patch, size_t end) {
    if (end && patch->body[end - 1] == '\n') return end;
    while (end < patch->length && patch->body[end] != '\n') end++;
    return end < patch->length ? end + 1 : end;
}

static size_t indentation(const Patch *patch, const Meta *meta) {
    if (!meta->value->count) return column(patch, meta->value->start);
    if (meta->value->type == YD_MAP) return column(patch, meta->children[0]->key_start);
    size_t start = meta->children[0]->value->start;
    size_t line = start - column(patch, start), dash = SIZE_MAX;
    for (size_t index = line; index < start; index++)
        if (patch->body[index] == '-' && index + 1 < patch->length &&
            (patch->body[index + 1] == ' ' || patch->body[index + 1] == '\n' || patch->body[index + 1] == '\r')) dash = index;
    return dash == SIZE_MAX ? column(patch, meta->value->start) : dash - line;
}

static const char *newline(const Patch *patch) {
    for (size_t index = 0; index < patch->length; index++) if (patch->body[index] == '\n')
        return index && patch->body[index - 1] == '\r' ? "\r\n" : "\n";
    return "\n";
}

static bool replace_node(Patch *patch, const Meta *meta, const YDValue *value) {
    size_t start = meta->value->start, end = meta->value->end;
    for (size_t index = start; index < end; index++) if (patch->trivia[index] == 2)
        return failure(patch, "replacement would discard comments inside the target; mutate its fields instead");
    size_t length;
    char *json = yd_json_sized(value, &length, patch->limit > YD_DOCUMENT_LIMIT ? YD_LARGE_REQUEST_LIMIT : YD_REQUEST_LIMIT);
    if (!json) return failure(patch, "cannot serialize mutation value");
    const char *prefix = "";
    /* YAML allows block sequences in the key's column. A flow replacement
     * needs ordinary value indentation instead of that sequence exception. */
    if (indentless_sequence(patch, meta)) prefix = "  ";
    if (start == end && start && patch->body[start - 1] == ':') prefix = " ";
    if (start == end && meta == patch->meta && start && patch->body[start - 1] != '\n' && patch->body[start - 1] != '\r') prefix = newline(patch);
    const char *suffix = end > start && patch->body[end - 1] == '\n' ? newline(patch) : "";
    size_t prefix_length = strlen(prefix), suffix_length = strlen(suffix);
    char *text = malloc(prefix_length + length + suffix_length + 1);
    if (!text) { free(json); return failure(patch, "out of memory"); }
    memcpy(text, prefix, prefix_length); memcpy(text + prefix_length, json, length);
    memcpy(text + prefix_length + length, suffix, suffix_length);
    bool result = splice(patch, start, end, text, prefix_length + length + suffix_length);
    free(text); free(json); return result;
}

static size_t comma_between(const Patch *patch, size_t start, size_t end) {
    for (size_t index = start; index < end; index++)
        if (!patch->trivia[index] && patch->body[index] == ',') return index;
    return SIZE_MAX;
}

/* Delete YAML syntax while retaining every comment, line ending, and indentation
 * byte in the removed region. Comments belong to the source, not the data tree. */
static bool erase(Patch *patch, size_t start, size_t end, const char *empty) {
    size_t prefix = strlen(empty), length = end - start;
    char *text = malloc(prefix + length + 1);
    if (!text) return failure(patch, "out of memory");
    memcpy(text, empty, prefix);
    for (size_t index = 0; index < length; index++) {
        unsigned char byte = patch->body[start + index];
        text[prefix + index] = patch->trivia[start + index] == 2 || byte == '\n' || byte == '\r' || byte == '\t' ? (char)byte : ' ';
    }
    bool result = splice(patch, start, end, text, prefix + length);
    free(text); return result;
}

static bool remove_child(Patch *patch, const Meta *parent, size_t index) {
    const Meta *child = parent->children[index];
    size_t start = parent->value->type == YD_MAP ? child->key_start : child->value->start;
    size_t end = child->value->end;
    if (parent->flow) {
        if (index + 1 < parent->value->count) {
            size_t next_start = parent->value->type == YD_MAP ? parent->children[index + 1]->key_start : parent->children[index + 1]->value->start;
            size_t comma = comma_between(patch, end, next_start);
            if (comma == SIZE_MAX) return failure(patch, "cannot locate flow separator");
            end = comma + 1;
        } else if (index) {
            size_t comma = comma_between(patch, parent->children[index - 1]->value->end, start);
            if (comma == SIZE_MAX) return failure(patch, "cannot locate flow separator");
            start = comma;
        } else {
            size_t comma = comma_between(patch, end, parent->value->end);
            if (comma != SIZE_MAX) end = comma + 1;
        }
    } else {
        if (parent->value->count == 1) {
            const char *empty = parent->value->type == YD_MAP ? "{}" : indentless_sequence(patch, parent) ? "  []" : "[]";
            return erase(patch, parent->value->start, parent->value->end, empty);
        }
        if (parent->value->type == YD_ARRAY) {
            size_t line = start - column(patch, start), dash = line + indentation(patch, parent);
            if (dash >= start || patch->body[dash] != '-') return failure(patch, "unsupported compact array deletion layout");
            start = dash;
        }
    }
    return erase(patch, start, end, "");
}

static bool append_source(Patch *patch, const Meta *parent, const char *key, const YDValue *value) {
    size_t value_length;
    char *json = yd_json_sized(value, &value_length, patch->limit > YD_DOCUMENT_LIMIT ? YD_LARGE_REQUEST_LIMIT : YD_REQUEST_LIMIT);
    if (!json) return failure(patch, "cannot serialize mutation value");
    char *key_json = NULL;
    size_t key_length = 0;
    if (key) {
        YDValue key_value = {.type = YD_STRING, .scalar = (char *)key};
        key_json = yd_json(&key_value, &key_length);
        if (!key_json) { free(json); return failure(patch, "cannot serialize mutation key"); }
    }
    size_t position, indent = 0;
    const char *prefix = "", *suffix = "";
    if (parent->flow) {
        position = parent->value->end - 1;
        if (parent->value->count && comma_between(patch, parent->children[parent->value->count - 1]->value->end, position) == SIZE_MAX) prefix = ",";
    } else {
        position = after_line(patch, parent->value->end);
        if (position && patch->body[position - 1] != '\n') prefix = newline(patch);
        indent = indentation(patch, parent);
        suffix = newline(patch);
    }
    size_t capacity = strlen(prefix) + indent + key_length + value_length + strlen(suffix) + 5;
    char *text = malloc(capacity);
    if (!text) { free(json); free(key_json); return failure(patch, "out of memory"); }
    size_t used = strlen(prefix); memcpy(text, prefix, used);
    memset(text + used, ' ', indent); used += indent;
    if (key) {
        memcpy(text + used, key_json, key_length); used += key_length;
        text[used++] = ':'; text[used++] = ' ';
    } else if (!parent->flow) { text[used++] = '-'; text[used++] = ' '; }
    memcpy(text + used, json, value_length); used += value_length;
    memcpy(text + used, suffix, strlen(suffix)); used += strlen(suffix);
    bool result = splice(patch, position, position, text, used);
    free(text); free(json); free(key_json); return result;
}

/* Appends every item of a sequence in one splice, so an $each list costs one
 * reparse. A single item keeps the established flow and block layouts. */
static bool append_items(Patch *patch, const Meta *parent, const YDValue *items) {
    size_t limit = patch->limit > YD_DOCUMENT_LIMIT ? YD_LARGE_REQUEST_LIMIT : YD_REQUEST_LIMIT;
    size_t position, indent = 0;
    const char *prefix = "", *suffix = "";
    if (parent->flow) {
        position = parent->value->end - 1;
        if (parent->value->count && comma_between(patch, parent->children[parent->value->count - 1]->value->end, position) == SIZE_MAX) prefix = ",";
    } else {
        position = after_line(patch, parent->value->end);
        if (position && patch->body[position - 1] != '\n') prefix = newline(patch);
        indent = indentation(patch, parent);
        suffix = newline(patch);
    }
    size_t used = strlen(prefix), capacity = used + 1;
    char *text = malloc(capacity);
    if (!text) return failure(patch, "out of memory");
    memcpy(text, prefix, used);
    bool result = true;
    for (size_t item = 0; result && item < items->count; item++) {
        size_t length;
        char *json = yd_json_sized(items->items[item], &length, limit);
        if (!json) { result = failure(patch, "cannot serialize mutation value"); break; }
        size_t needed = indent + length + strlen(suffix) + 4;
        if (needed > patch->limit || used > patch->limit - needed) {
            free(json); result = failure(patch, "patched document exceeds size limit"); break;
        }
        char *grown = realloc(text, used + needed + 1);
        if (!grown) { free(json); result = failure(patch, "out of memory"); break; }
        text = grown;
        if (parent->flow) {
            if (item) { text[used++] = ','; text[used++] = ' '; }
        } else {
            memset(text + used, ' ', indent); used += indent;
            text[used++] = '-'; text[used++] = ' ';
        }
        memcpy(text + used, json, length); used += length;
        memcpy(text + used, suffix, strlen(suffix)); used += strlen(suffix);
        free(json);
    }
    if (result) result = splice(patch, position, position, text, used);
    free(text);
    return result;
}

static bool same_parts(char *const *left, char *const *right, size_t count) {
    for (size_t part = 0; part < count; part++) if (strcmp(left[part], right[part])) return false;
    return true;
}

static bool plain_key(const char *key) {
    static const char *const reserved[] = {"null", "Null", "NULL", "true", "True", "TRUE", "false", "False", "FALSE"};
    if (!((*key >= 'A' && *key <= 'Z') || (*key >= 'a' && *key <= 'z') || *key == '_')) return false;
    for (const char *c = key; *c; c++)
        if (!((*c >= 'A' && *c <= 'Z') || (*c >= 'a' && *c <= 'z') || (*c >= '0' && *c <= '9') || *c == '_' || *c == '-'))
            return false;
    for (size_t index = 0; index < sizeof(reserved) / sizeof(*reserved); index++)
        if (!strcmp(key, reserved[index])) return false;
    return true;
}

/* Mapping key text: plain when unambiguous in the core schema, else JSON. */
static char *key_text(const char *key, size_t *length) {
    if (plain_key(key)) {
        *length = strlen(key);
        return strdup(key);
    }
    YDValue string = {.type = YD_STRING, .scalar = (char *)key};
    return yd_json(&string, length);
}

static bool edit_source(Patch *patch, const Operation *operation, const YDValue *expected);

/* A sibling rename rewrites only the key, keeping the value's own layout and
 * comments. A move to another parent removes the source and sets the value. */
static bool rename_source(Patch *patch, const Operation *operation) {
    Meta *parent = locate(patch->meta, operation, operation->count - 1);
    size_t last = operation->count - 1;
    size_t index = parent ? child_index(parent->value, operation->parts[last]) : SIZE_MAX;
    if (index == SIZE_MAX) return failure(patch, "unsupported mutation layout");
    if (operation->count == operation->target_count && same_parts(operation->parts, operation->target_parts, last)) {
        size_t existing = child_index(parent->value, operation->target_parts[last]);
        if (existing != SIZE_MAX) {
            if (!remove_child(patch, parent, existing) || !parse_source(patch)) return false;
            parent = locate(patch->meta, operation, last);
            index = parent ? child_index(parent->value, operation->parts[last]) : SIZE_MAX;
            if (index == SIZE_MAX) return failure(patch, "unsupported mutation layout");
        }
        const Meta *child = parent->children[index];
        if (child->key_end <= child->key_start) return failure(patch, "unsupported mutation layout");
        size_t length;
        char *text = key_text(operation->target_parts[last], &length);
        if (!text) return failure(patch, "out of memory");
        bool result = splice(patch, child->key_start, child->key_end, text, length);
        free(text);
        return result;
    }
    YDValue *moved = yd_clone(parent->children[index]->value);
    if (!moved) return failure(patch, "out of memory");
    Operation set = {.name = "$set", .argument = moved, .count = operation->target_count};
    memcpy(set.parts, operation->target_parts, sizeof(set.parts));
    bool result = remove_child(patch, parent, index) && parse_source(patch) && edit_source(patch, &set, NULL);
    yd_free(moved);
    return result;
}

static bool expected_rename(Patch *patch, YDValue **root, const Operation *operation) {
    YDValue *parent = *root;
    for (size_t part = 0; parent && part + 1 < operation->count; part++) {
        size_t index = child_index(parent, operation->parts[part]);
        parent = index == SIZE_MAX ? NULL : parent->items[index];
    }
    size_t index = parent ? child_index(parent, operation->parts[operation->count - 1]) : SIZE_MAX;
    if (index == SIZE_MAX) return failure(patch, "unsupported mutation layout");
    YDValue *moved = yd_clone(parent->items[index]);
    if (!moved) return failure(patch, "out of memory");
    remove_value(parent, index);
    Operation set = {.name = "$set", .argument = moved, .count = operation->target_count};
    memcpy(set.parts, operation->target_parts, sizeof(set.parts));
    bool result = expected_change(patch, root, &set);
    yd_free(moved);
    return result;
}

static bool edit_source(Patch *patch, const Operation *operation, const YDValue *expected) {
    (void)expected;
    if (strcmp(operation->name, "$rename") == 0) return rename_source(patch, operation);
    Meta *target = locate(patch->meta, operation, operation->count);
    if (strcmp(operation->name, "$set") == 0) {
        if (target) return replace_node(patch, target, operation->argument);
        Meta *parent = patch->meta;
        for (size_t part = 0; part < operation->count; part++) {
            if (parent->value->type == YD_NULL) {
                YDValue *created = branch(operation, part);
                bool result = created && replace_node(patch, parent, created);
                yd_free(created); return result;
            }
            size_t index = child_index(parent->value, operation->parts[part]);
            if (index == SIZE_MAX) {
                YDValue *created = branch(operation, part + 1);
                bool result = created && append_source(patch, parent, operation->parts[part], created);
                yd_free(created); return result;
            }
            parent = parent->children[index];
        }
    } else if (strcmp(operation->name, "$unset") == 0) {
        if (!target) return true;
        Meta *parent = locate(patch->meta, operation, operation->count - 1);
        return remove_child(patch, parent, child_index(parent->value, operation->parts[operation->count - 1]));
    } else if (strcmp(operation->name, "$push") == 0) return target && append_items(patch, target, operation->argument);
    else {
        for (size_t index = target->value->count; index > 0; index--) {
            target = locate(patch->meta, operation, operation->count);
            if (yd_equal(target->value->items[index - 1], operation->argument)) {
                if (!remove_child(patch, target, index - 1) || !parse_source(patch)) return false;
            }
        }
        return true;
    }
    return failure(patch, "unsupported mutation layout");
}

static bool split_path(const char *path, char **storage, char **parts, size_t *count) {
    if (!*path || strlen(path) > 1024) return false;
    *storage = strdup(path);
    if (!*storage) return false;
    char *part = *storage;
    while (part) {
        if (!*part || *count == YD_DEPTH_LIMIT) return false;
        parts[(*count)++] = part;
        char *dot = strchr(part, '.');
        if (dot) *dot++ = 0;
        if (!*part) return false;
        part = dot;
    }
    return true;
}

static bool path_valid(Operation *operation) {
    return split_path(operation->path, &operation->storage, operation->parts, &operation->count);
}

static bool prefix_overlap(char *const *left, size_t left_count, char *const *right, size_t right_count) {
    size_t count = left_count < right_count ? left_count : right_count;
    return same_parts(left, right, count);
}

/* A $rename touches both of its paths; no other operation may share either. */
static bool overlaps(const Operation *left, const Operation *right) {
    if (prefix_overlap(left->parts, left->count, right->parts, right->count)) return true;
    if (left->target_count && prefix_overlap(left->target_parts, left->target_count, right->parts, right->count)) return true;
    if (right->target_count && prefix_overlap(left->parts, left->count, right->target_parts, right->target_count)) return true;
    return left->target_count && right->target_count &&
           prefix_overlap(left->target_parts, left->target_count, right->target_parts, right->target_count);
}

static int operation_order(const void *first, const void *second) {
    const Operation *left = first, *right = second;
    for (size_t part = 0; part < left->count && part < right->count; part++) {
        const char *a = left->parts[part], *b = right->parts[part];
        if (strcmp(a, b) == 0) continue;
        size_t a_index, b_index;
        if (numeric_index(a, &a_index) && numeric_index(b, &b_index)) return (a_index < b_index) - (a_index > b_index);
        return strcmp(b, a);
    }
    return (left->count < right->count) - (left->count > right->count);
}

static bool known_operator(const char *name) {
    static const char *const names[] = {"$set", "$unset", "$inc", "$push", "$pull", "$addToSet",
                                        "$rename", "$min", "$max", "$mul", "$setOnInsert"};
    for (size_t index = 0; index < sizeof(names) / sizeof(*names); index++)
        if (!strcmp(name, names[index])) return true;
    return false;
}

static bool numeric(const YDValue *value) { return value->type == YD_INT || value->type == YD_FLOAT; }

static bool operand_valid(Patch *patch, Operation *operation) {
    const char *name = operation->name;
    const YDValue *argument = operation->argument;
    if ((!strcmp(name, "$inc") || !strcmp(name, "$mul")) && !numeric(argument))
        return failure(patch, "invalid mutation operand type");
    if (!strcmp(name, "$unset") && (argument->type != YD_BOOL || !argument->boolean))
        return failure(patch, "invalid mutation operand type");
    if (!strcmp(name, "$rename")) {
        if (argument->type != YD_STRING ||
            !split_path(argument->scalar, &operation->target_storage, operation->target_parts, &operation->target_count))
            return failure(patch, "$rename requires a valid destination path");
        if (prefix_overlap(operation->parts, operation->count, operation->target_parts, operation->target_count))
            return failure(patch, "$rename source and destination overlap");
    }
    if ((!strcmp(name, "$push") || !strcmp(name, "$addToSet")) && argument->type == YD_MAP &&
        yd_get(argument, "$each")) {
        const YDValue *each = yd_get(argument, "$each");
        if (argument->count != 1 || each->type != YD_ARRAY || each->count > PATCH_EACH_LIMIT)
            return failure(patch, "$each must be the only modifier and a sequence of at most 1024 values");
        operation->each = each;
    }
    return true;
}

static bool parse_operations(Patch *patch, const YDValue *operations, Operation *list, size_t *count) {
    if (!operations || operations->type != YD_MAP) return failure(patch, "invalid mutation request");
    for (size_t group = 0; group < operations->count; group++) {
        const char *name = operations->keys[group];
        const YDValue *fields = operations->items[group];
        if (!known_operator(name) || fields->type != YD_MAP)
            return failure(patch, "unknown operator or nonmapping operator body");
        for (size_t field = 0; field < fields->count; field++) {
            if (*count == PATCH_OPERATION_LIMIT) return failure(patch, "too many mutation paths");
            Operation *operation = &list[(*count)++];
            operation->name = name; operation->argument = fields->items[field]; operation->path = fields->keys[field];
            if (!path_valid(operation)) return failure(patch, "invalid or overlong mutation path");
            if (!operand_valid(patch, operation)) return false;
            for (size_t previous = 0; previous + 1 < *count; previous++)
                if (overlaps(operation, &list[previous])) return failure(patch, "mutation paths overlap");
        }
    }
    return true;
}

static void operations_free(Operation *list, size_t count) {
    for (size_t index = 0; list && index < count; index++) {
        free(list[index].storage);
        free(list[index].target_storage);
    }
    free(list);
}

static const YDValue *find(const YDValue *value, char *const *parts, size_t count, bool *sequence) {
    for (size_t part = 0; value && part < count; part++) {
        if (value->type == YD_ARRAY) *sequence = true;
        size_t index = child_index(value, parts[part]);
        value = index == SIZE_MAX ? NULL : value->items[index];
    }
    return value;
}

static YDValue *number_value(Patch *patch, YDType type, long double number) {
    YDValue *value = calloc(1, sizeof(*value));
    if (!value) { failure(patch, "out of memory"); return NULL; }
    value->type = type; value->number = number;
    return value;
}

static bool arithmetic(Patch *patch, const Operation *operation, const YDValue *current, Operation *primitive) {
    bool multiply = !strcmp(operation->name, "$mul");
    const YDValue *argument = operation->argument;
    if (current && !numeric(current)) return failure(patch, "$inc and $mul targets must be numeric");
    long double result = !current ? (multiply ? 0 : argument->number) :
        multiply ? current->number * argument->number : current->number + argument->number;
    bool integers = argument->type == YD_INT && (!current || current->type == YD_INT);
    if (!isfinite(result) || (integers && (result < -9223372036854775808.0L || result > 9223372036854775807.0L)))
        return failure(patch, multiply ? "$mul numeric overflow" : "$inc numeric overflow");
    primitive->owned = number_value(patch, integers ? YD_INT : YD_FLOAT, result);
    primitive->argument = primitive->owned;
    return primitive->owned != NULL;
}

static bool contains(const YDValue *array, size_t count, const YDValue *value) {
    for (size_t index = 0; array && index < count; index++) if (yd_equal(array->items[index], value)) return true;
    return false;
}

/* Collects the items a $push or $addToSet adds; $addToSet skips values the
 * target or an earlier $each item already holds. */
static bool additions(Patch *patch, const Operation *operation, const YDValue *current, Operation *primitive) {
    if (current && current->type != YD_ARRAY) return failure(patch, "array mutation target must be an array");
    bool set = !strcmp(operation->name, "$addToSet");
    size_t count = operation->each ? operation->each->count : 1;
    YDValue *list = calloc(1, sizeof(*list));
    if (!list || (count && !(list->items = calloc(count, sizeof(*list->items))))) {
        free(list); return failure(patch, "out of memory");
    }
    list->type = YD_ARRAY;
    primitive->owned = list;
    for (size_t index = 0; index < count; index++) {
        const YDValue *item = operation->each ? operation->each->items[index] : operation->argument;
        if (set && (contains(current, current ? current->count : 0, item) || contains(list, list->count, item))) continue;
        if (!(list->items[list->count] = yd_clone(item))) return failure(patch, "out of memory");
        list->count++;
    }
    primitive->argument = list;
    primitive->name = !current ? "$set" : list->count ? "$push" : NULL;
    return true;
}

/* Same type and value throughout, keys in the same order: setting one to the
 * other changes nothing, so its source is left exactly as written. */
static bool identical(const YDValue *left, const YDValue *right) {
    if (left->type != right->type || left->count != right->count) return false;
    if (left->type != YD_ARRAY && left->type != YD_MAP) return yd_equal(left, right);
    for (size_t index = 0; index < left->count; index++)
        if ((left->type == YD_MAP && strcmp(left->keys[index], right->keys[index])) ||
            !identical(left->items[index], right->items[index])) return false;
    return true;
}

/* Resolves one operator against the current tree into a primitive source
 * edit, or a NULL name when the document already satisfies it. Insert mode
 * builds an upserted document and enables $setOnInsert. */
static bool resolve(Patch *patch, const Operation *operation, bool insert, Operation *primitive) {
    *primitive = *operation;
    primitive->owned = NULL;
    primitive->name = "$set";
    const char *name = operation->name;
    bool sequence = false;
    const YDValue *current = find(patch->root, operation->parts, operation->count, &sequence);
    bool on_insert = !strcmp(name, "$setOnInsert");
    if (on_insert || !strcmp(name, "$set")) {
        /* Rewriting an identical value would only respell its scalar text. */
        if ((on_insert && !insert) || (current && identical(current, operation->argument)))
            primitive->name = NULL;
        return true;
    }
    if (!strcmp(name, "$unset")) { primitive->name = "$unset"; return true; }
    if (!strcmp(name, "$min") || !strcmp(name, "$max")) {
        int order = current ? yd_compare(operation->argument, current) : 0;
        if (current && (!strcmp(name, "$min") ? order >= 0 : order <= 0)) primitive->name = NULL;
        return true;
    }
    if (!strcmp(name, "$inc") || !strcmp(name, "$mul")) return arithmetic(patch, operation, current, primitive);
    if (!strcmp(name, "$push") || !strcmp(name, "$addToSet")) return additions(patch, operation, current, primitive);
    if (!strcmp(name, "$pull")) {
        if (current && current->type != YD_ARRAY) return failure(patch, "array mutation target must be an array");
        primitive->name = current ? "$pull" : NULL;
        return true;
    }
    bool target_sequence = false;
    find(patch->root, operation->target_parts, operation->target_count, &target_sequence);
    if (sequence || target_sequence) return failure(patch, "$rename paths cannot traverse sequences");
    primitive->name = current ? "$rename" : NULL;
    return true;
}

static bool apply(const unsigned char *body, size_t length, const YDValue *operations, bool insert,
    unsigned char **output, size_t *output_length, size_t limit, char *error, size_t error_length) {
    if (output) *output = NULL;
    if (output_length) *output_length = 0;
    if (error && error_length) error[0] = 0;
    Patch patch = {.error = error, .error_length = error_length, .limit = limit};
    if (!output || !output_length || !operations || operations->type != YD_MAP ||
        !limit || limit > YD_LARGE_DOCUMENT_LIMIT || length > limit || (!body && length)) return failure(&patch, "invalid mutation request");
    Operation *list = calloc(PATCH_OPERATION_LIMIT, sizeof(*list));
    if (!list) return failure(&patch, "out of memory");
    size_t count = 0;
    bool result = false;
    if (!parse_operations(&patch, operations, list, &count)) goto done;
    qsort(list, count, sizeof(*list), operation_order);
    patch.body = malloc(length + 1);
    if (!patch.body) { failure(&patch, "out of memory"); goto done; }
    if (length) memcpy(patch.body, body, length);
    patch.body[length] = 0; patch.length = length;
    if (!parse_source(&patch)) goto done;
    for (size_t index = 0; index < count; index++) {
        Operation primitive;
        bool changed = resolve(&patch, &list[index], insert, &primitive);
        if (changed && primitive.name) {
            YDValue *expected = yd_clone(patch.root);
            if (!expected) changed = failure(&patch, "out of memory");
            else if (!strcmp(primitive.name, "$rename")) changed = expected_rename(&patch, &expected, &primitive);
            else changed = expected_change(&patch, &expected, &primitive);
            if (changed) changed = edit_source(&patch, &primitive, expected);
            if (changed) changed = parse_source(&patch);
            if (changed && !yd_equal(patch.root, expected)) changed = failure(&patch, "source layout cannot preserve the requested mutation safely");
            yd_free(expected);
        }
        yd_free(primitive.owned);
        if (!changed) goto done;
    }
    *output = patch.body; *output_length = patch.length; patch.body = NULL;
    result = true;
done:
    operations_free(list, count);
    release_tree(&patch); free(patch.body);
    if (!result) failure(&patch, "cannot apply mutation");
    return result;
}

bool yd_patch_sized(const unsigned char *body, size_t length, const YDValue *operations,
    unsigned char **output, size_t *output_length, size_t limit, char *error, size_t error_length) {
    return apply(body, length, operations, false, output, output_length, limit, error, error_length);
}

bool yd_patch(const unsigned char *body, size_t length, const YDValue *operations,
    unsigned char **output, size_t *output_length, char *error, size_t error_length) {
    return yd_patch_sized(body, length, operations, output, output_length, YD_DOCUMENT_LIMIT, error, error_length);
}

bool yd_patch_validate(const YDValue *operations, char *error, size_t error_length) {
    if (error && error_length) error[0] = 0;
    Patch patch = {.error = error, .error_length = error_length};
    Operation *list = calloc(PATCH_OPERATION_LIMIT, sizeof(*list));
    if (!list) return failure(&patch, "out of memory");
    size_t count = 0;
    bool result = parse_operations(&patch, operations, list, &count);
    if (result && !count) result = failure(&patch, "update requires at least one mutation path");
    operations_free(list, count);
    return result;
}

typedef struct {
    char **keys;
    YDValue **items;
    size_t count;
} Fields;

static bool filter_operators(const YDValue *value) {
    if (value->type != YD_MAP) return false;
    for (size_t index = 0; index < value->count; index++) if (value->keys[index][0] == '$') return true;
    return false;
}

/* Equality conditions of a query filter: literal predicates and $eq on
 * fields, including those inside $and. Other operators constrain nothing. */
static bool equality_fields(Patch *patch, const YDValue *filter, Fields *fields, unsigned depth) {
    if (!filter || filter->type != YD_MAP || depth > 32) return failure(patch, "upsert filter must be a mapping");
    for (size_t index = 0; index < filter->count; index++) {
        const char *key = filter->keys[index];
        const YDValue *predicate = filter->items[index];
        if (!strcmp(key, "$and") && predicate->type == YD_ARRAY) {
            for (size_t item = 0; item < predicate->count; item++)
                if (!equality_fields(patch, predicate->items[item], fields, depth + 1)) return false;
            continue;
        }
        if (key[0] == '$') continue;
        const YDValue *value = filter_operators(predicate) ? yd_get(predicate, "$eq") : predicate;
        if (!value) continue;
        if (fields->count == PATCH_OPERATION_LIMIT) return failure(patch, "too many upsert equality fields");
        fields->keys[fields->count] = (char *)key;
        fields->items[fields->count++] = (YDValue *)value;
    }
    return true;
}

/* The new document is canonical block YAML: one line per top-level field. */
static bool emit_document(Patch *patch, const YDValue *model, unsigned char **output, size_t *output_length) {
    size_t limit = patch->limit, used = 0;
    char *text = malloc(limit + 1);
    if (!text) return failure(patch, "out of memory");
    bool result = true;
    if (!model->count) { memcpy(text, "{}\n", 3); used = 3; }
    for (size_t index = 0; result && index < model->count; index++) {
        size_t key_length, value_length;
        char *key = key_text(model->keys[index], &key_length);
        char *value = yd_json_sized(model->items[index], &value_length, limit > YD_DOCUMENT_LIMIT ? YD_LARGE_REQUEST_LIMIT : YD_REQUEST_LIMIT);
        if (!key || !value) result = failure(patch, "cannot serialize upserted document");
        else if (key_length + value_length + 3 > limit - used) result = failure(patch, "upserted document exceeds size limit");
        else {
            memcpy(text + used, key, key_length); used += key_length;
            text[used++] = ':'; text[used++] = ' ';
            memcpy(text + used, value, value_length); used += value_length;
            text[used++] = '\n';
        }
        free(key); free(value);
    }
    if (result) {
        text[used] = 0;
        YDValue *parsed = yd_parse_sized((unsigned char *)text, used, limit, patch->error, patch->error_length);
        result = parsed && yd_equal(parsed, model);
        if (parsed && !result) failure(patch, "cannot serialize upserted document");
        yd_free(parsed);
    }
    if (!result) { free(text); return false; }
    *output = (unsigned char *)text; *output_length = used;
    return true;
}

bool yd_patch_upsert_sized(const YDValue *filter, const YDValue *operations, unsigned char **output,
    size_t *output_length, size_t limit, char *error, size_t error_length) {
    if (output) *output = NULL;
    if (output_length) *output_length = 0;
    Patch patch = {.error = error, .error_length = error_length, .limit = limit};
    if (!output || !output_length || !limit || limit > YD_LARGE_DOCUMENT_LIMIT) return failure(&patch, "invalid mutation request");
    if (!yd_patch_validate(operations, error, error_length)) return false;
    Fields fields = {.keys = calloc(PATCH_OPERATION_LIMIT, sizeof(char *)),
                     .items = calloc(PATCH_OPERATION_LIMIT, sizeof(YDValue *))};
    unsigned char *base = NULL, *patched = NULL;
    size_t base_length = 2, patched_length = 0;
    YDValue *model = NULL;
    bool result = fields.keys && fields.items ? equality_fields(&patch, filter, &fields, 0) : failure(&patch, "out of memory");
    if (result && fields.count) {
        YDValue set = {.type = YD_MAP, .keys = fields.keys, .items = fields.items, .count = fields.count};
        char *name = "$set";
        YDValue *body = &set;
        YDValue spec = {.type = YD_MAP, .keys = &name, .items = &body, .count = 1};
        result = apply((const unsigned char *)"{}", 2, &spec, true, &base, &base_length, limit, error, error_length);
    }
    if (result)
        result = apply(base ? base : (const unsigned char *)"{}", base_length, operations, true, &patched, &patched_length,
                       limit, error, error_length);
    if (result) {
        model = yd_parse_sized(patched, patched_length, limit, error, error_length);
        result = model && (model->type == YD_MAP || failure(&patch, "upserted document must be a mapping"));
    }
    if (result) result = emit_document(&patch, model, output, output_length);
    yd_free(model);
    free(base); free(patched); free(fields.keys); free(fields.items);
    if (!result) failure(&patch, "cannot build upserted document");
    return result;
}
