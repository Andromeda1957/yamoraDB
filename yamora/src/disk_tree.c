#define _POSIX_C_SOURCE 200809L
#include "disk_internal.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>

#define NODE_HEADER 32U
#define NODE_END (YD_DISK_PAGE - 4U)
#define NODE_MAX ((NODE_END - NODE_HEADER) / 11U)
typedef struct {
    unsigned char *key;
    size_t size;
    uint64_t value;
} Entry;
typedef struct {
    Entry *entries;
    size_t count;
    bool branch;
} Node;
typedef struct {
    uint64_t offset, right;
    unsigned char minimum[YD_DISK_KEY_LIMIT], right_minimum[YD_DISK_KEY_LIMIT];
    size_t size, right_size;
} Change;
typedef struct {
    Node node;
    size_t index;
} Frame;
struct YDDiskCursor {
    YDDisk *disk;
    pid_t process; /* Zero for legacy; independent of the borrowed disk lifetime. */
    YDDiskTxn *txn;
    YDDiskView view;
    Frame frames[YD_DISK_DEPTH];
    size_t depth;
    bool failed, held; /* held: owes yd_disk_epoch_release for view.epoch */
};
static int get(YDDisk *, const YDDiskView *, YDDiskTxn *, const void *, size_t, uint64_t *, char *,
               size_t);
static YDKeyChange *observe(YDDiskTxn *, const void *, size_t, char *, size_t);

static int compare(const void *a, size_t an, const void *b, size_t bn) {
    int n = memcmp(a, b, an < bn ? an : bn);
    return n ? n : (an > bn) - (an < bn);
}
static void node_free(Node *node) {
    for (size_t i = 0; i < node->count; i++)
        free(node->entries[i].key);
    free(node->entries);
    memset(node, 0, sizeof(*node));
}
static bool node_read(YDDisk *disk, const YDDiskView *view, YDDiskTxn *txn, uint64_t offset,
                      Node *node, char *error, size_t length) {
    memset(node, 0, sizeof(*node));
    unsigned char bytes[YD_DISK_PAGE];
    if (!yd_disk_read_page(disk, view, txn, offset, bytes, error, length))
        return false;
    size_t count = yd_disk_u16(bytes + 10), used = yd_disk_u16(bytes + 12);
    if (bytes[8] > 1 || bytes[9] || !count || count > NODE_MAX || used < NODE_HEADER ||
        used > NODE_END)
        goto bad;
    for (size_t i = 14; i < NODE_HEADER; i++)
        if (bytes[i])
            goto bad;
    for (size_t i = used; i < NODE_END; i++)
        if (bytes[i])
            goto bad;
    node->branch = bytes[8] != 0;
    node->entries = calloc(count + 2, sizeof(*node->entries));
    if (!node->entries)
        return false;
    size_t position = NODE_HEADER;
    for (size_t i = 0; i < count; i++) {
        if (used - position < 10)
            goto bad;
        size_t size = yd_disk_u16(bytes + position);
        uint64_t value = yd_disk_u64(bytes + position + 2);
        position += 10;
        if (!size || size > YD_DISK_KEY_LIMIT || size > used - position)
            goto bad;
        Entry *entry = &node->entries[node->count++];
        entry->key = malloc(size);
        if (!entry->key)
            goto bad;
        entry->size = size;
        entry->value = value;
        memcpy(entry->key, bytes + position, size);
        position += size;
        if (i &&
            compare(node->entries[i - 1].key, node->entries[i - 1].size, entry->key, size) >= 0)
            goto bad;
        if (node->branch && (value < 2 * YD_DISK_PAGE || value % YD_DISK_PAGE ||
                             value >= (txn ? txn->next : view->end)))
            goto bad;
    }
    if (position != used)
        goto bad;
    return true;
bad:
    node_free(node);
    return yd_disk_error(error, length, "invalid tree node framing or ordering");
}
static size_t bytes_needed(const Node *node, size_t begin, size_t end) {
    size_t size = NODE_HEADER;
    for (size_t i = begin; i < end; i++)
        size += 10 + node->entries[i].size;
    return size;
}
static bool node_write(YDDiskTxn *txn, uint64_t old, const Node *node, size_t begin, size_t end,
                       uint64_t *offset, char *error, size_t length) {
    unsigned char bytes[YD_DISK_PAGE] = {0};
    memcpy(bytes, "YDBTREE2", 8);
    bytes[8] = node->branch ? 1 : 0;
    size_t used = bytes_needed(node, begin, end);
    if (begin == end || end - begin > NODE_MAX || used > NODE_END)
        return yd_disk_error(error, length, "tree node exceeds page bounds");
    yd_disk_set16(bytes + 10, (uint16_t)(end - begin));
    yd_disk_set16(bytes + 12, (uint16_t)used);
    size_t position = NODE_HEADER;
    for (size_t i = begin; i < end; i++) {
        Entry *e = &node->entries[i];
        yd_disk_set16(bytes + position, (uint16_t)e->size);
        yd_disk_set64(bytes + position + 2, e->value);
        position += 10;
        memcpy(bytes + position, e->key, e->size);
        position += e->size;
    }
    uint32_t crc = yd_disk_crc(bytes, NODE_END);
    for (unsigned i = 0; i < 4; i++)
        bytes[NODE_END + i] = (unsigned char)(crc >> (i * 8));
    return yd_disk_write_page(txn, old, bytes, offset, error, length);
}
static size_t lower(const Node *node, const void *key, size_t size) {
    size_t a = 0, b = node->count;
    while (a < b) {
        size_t mid = a + (b - a) / 2;
        Entry *e = &node->entries[mid];
        if (compare(e->key, e->size, key, size) < 0)
            a = mid + 1;
        else
            b = mid;
    }
    return a;
}
static size_t child_at(const Node *node, const void *key, size_t size) {
    size_t position = lower(node, key, size);
    if (position < node->count &&
        compare(node->entries[position].key, node->entries[position].size, key, size) == 0)
        return position;
    return position ? position - 1 : 0;
}
static bool entry_set(Entry *entry, const void *key, size_t size, uint64_t value) {
    unsigned char *copy = malloc(size);
    if (!copy)
        return false;
    memcpy(copy, key, size);
    free(entry->key);
    *entry = (Entry){.key = copy, .size = size, .value = value};
    return true;
}
static bool entry_insert(Node *node, size_t at, const void *key, size_t size, uint64_t value) {
    /* node_read reserves two spare entries for an insertion and child split. */
    memmove(node->entries + at + 1, node->entries + at,
            (node->count - at) * sizeof(*node->entries));
    memset(&node->entries[at], 0, sizeof(*node->entries));
    node->count++;
    return entry_set(&node->entries[at], key, size, value);
}
static void entry_delete(Node *node, size_t at) {
    free(node->entries[at].key);
    memmove(node->entries + at, node->entries + at + 1,
            (node->count - at - 1) * sizeof(*node->entries));
    node->count--;
}
static bool change_node(YDDiskTxn *txn, uint64_t offset, const void *key, size_t size,
                        uint64_t value, bool deleting, unsigned depth, Change *change, char *error,
                        size_t length) {
    memset(change, 0, sizeof(*change));
    if (depth >= YD_DISK_DEPTH)
        return yd_disk_error(error, length, "tree depth exceeds limit");
    Node node = {0};
    bool valid;
    if (offset) {
        if (!node_read(txn->disk, &txn->view, txn, offset, &node, error, length))
            return false;
    } else {
        if (deleting)
            return true;
        node.entries = calloc(3, sizeof(*node.entries));
        if (!node.entries)
            return false;
    }
    if (node.branch) {
        size_t at = child_at(&node, key, size);
        Change child;
        valid = change_node(txn, node.entries[at].value, key, size, value, deleting, depth + 1,
                            &child, error, length);
        if (!valid) {
            node_free(&node);
            return false;
        }
        if (!child.offset)
            entry_delete(&node, at);
        else if (!entry_set(&node.entries[at], child.minimum, child.size, child.offset)) {
            node_free(&node);
            return false;
        }
        if (child.right &&
            !entry_insert(&node, at + 1, child.right_minimum, child.right_size, child.right)) {
            node_free(&node);
            return false;
        }
    } else {
        size_t at = lower(&node, key, size);
        bool exists =
            at < node.count && compare(node.entries[at].key, node.entries[at].size, key, size) == 0;
        if (deleting) {
            if (exists)
                entry_delete(&node, at);
        } else if (exists)
            node.entries[at].value = value;
        else if (!entry_insert(&node, at, key, size, value)) {
            node_free(&node);
            return false;
        }
    }
    if (!node.count) {
        node_free(&node);
        return true;
    }
    memcpy(change->minimum, node.entries[0].key, node.entries[0].size);
    change->size = node.entries[0].size;
    if (bytes_needed(&node, 0, node.count) <= NODE_END && node.count <= NODE_MAX) {
        valid = node_write(txn, offset, &node, 0, node.count, &change->offset, error, length);
    } else {
        size_t total = bytes_needed(&node, 0, node.count) - NODE_HEADER, weight = 0, split = 0;
        size_t balance = SIZE_MAX;
        for (size_t i = 0; i + 1 < node.count; i++) {
            weight += 10 + node.entries[i].size;
            size_t right = total - weight;
            size_t difference = weight > right ? weight - right : right - weight;
            /* Replacing a short branch minimum and adding a split child can
             * grow by two long keys. A rounded 50% split need not fit. */
            if (weight <= NODE_END - NODE_HEADER && right <= NODE_END - NODE_HEADER &&
                difference < balance) {
                split = i + 1;
                balance = difference;
            }
        }
        valid = split && node_write(txn, offset, &node, 0, split, &change->offset, error, length) &&
                node_write(txn, 0, &node, split, node.count, &change->right, error, length);
        if (!split)
            yd_disk_error(error, length, "tree cannot split within page bounds");
        if (valid) {
            change->right_size = node.entries[split].size;
            memcpy(change->right_minimum, node.entries[split].key, change->right_size);
        }
    }
    node_free(&node);
    return valid;
}
static bool mutate(YDDiskTxn *txn, const void *key, size_t size, uint64_t value, bool deleting,
                   char *error, size_t length) {
    if (txn->failed || !key || !size || size > YD_DISK_KEY_LIMIT) {
        txn->failed = true;
        return yd_disk_error(error, length, "invalid tree key or failed transaction");
    }
    YDKeyChange *operation = NULL;
    if (!txn->exclusive && !txn->replay) {
        operation = observe(txn, key, size, error, length);
        if (!operation) {
            txn->failed = true;
            return false;
        }
    }
    Change change;
    if (!change_node(txn, txn->view.root, key, size, value, deleting, 0, &change, error, length)) {
        txn->failed = true;
        return false;
    }
    if (change.right) {
        Entry entries[2] = {
            {.key = change.minimum, .size = change.size, .value = change.offset},
            {.key = change.right_minimum, .size = change.right_size, .value = change.right}};
        Node root = {.entries = entries, .count = 2, .branch = true};
        if (!node_write(txn, 0, &root, 0, 2, &change.offset, error, length)) {
            txn->failed = true;
            return false;
        }
    }
    txn->view.root = change.offset;
    txn->view.end = txn->next;
    if (operation) {
        operation->write = true;
        operation->deleted = deleting;
        operation->counter = false;
        operation->value = value;
    }
    return true;
}
bool yd_disk_put(YDDiskTxn *txn, const void *key, size_t size, uint64_t value, char *error,
                 size_t length) {
    if (!txn || !yd_disk_process_valid(txn->disk)) return false;
    return mutate(txn, key, size, value, false, error, length);
}
bool yd_disk_delete(YDDiskTxn *txn, const void *key, size_t size, char *error, size_t length) {
    if (!txn || !yd_disk_process_valid(txn->disk)) return false;
    return mutate(txn, key, size, 0, true, error, length);
}
static int get(YDDisk *disk, const YDDiskView *view, YDDiskTxn *txn, const void *key, size_t size,
               uint64_t *value, char *error, size_t length) {
    if (!yd_disk_process_valid(disk)) return -1;
    if (!key || !size || size > YD_DISK_KEY_LIMIT) {
        yd_disk_error(error, length, "invalid lookup key");
        return -1;
    }
    uint64_t offset = view->root;
    for (unsigned depth = 0; offset && depth < YD_DISK_DEPTH; depth++) {
        Node node;
        if (!node_read(disk, view, txn, offset, &node, error, length))
            return -1;
        if (node.branch) {
            size_t at = child_at(&node, key, size);
            offset = node.entries[at].value;
            node_free(&node);
            continue;
        }
        size_t at = lower(&node, key, size);
        bool found =
            at < node.count && compare(node.entries[at].key, node.entries[at].size, key, size) == 0;
        if (found)
            *value = node.entries[at].value;
        node_free(&node);
        return found ? 1 : 0;
    }
    if (offset) {
        yd_disk_error(error, length, "tree traversal depth exceeded");
        return -1;
    }
    return 0;
}
int yd_disk_get(YDDisk *disk, const YDDiskView *view, const void *key, size_t size, uint64_t *value,
                char *error, size_t length) {
    return get(disk, view, NULL, key, size, value, error, length);
}
int yd_disk_tx_peek(YDDiskTxn *txn, const void *key, size_t size, uint64_t *value, char *error,
                    size_t length) {
    if (!txn || !yd_disk_process_valid(txn->disk)) return -1;
    return get(txn->disk, &txn->view, txn, key, size, value, error, length);
}
int yd_disk_tx_get(YDDiskTxn *txn, const void *key, size_t size, uint64_t *value, char *error,
                   size_t length) {
    if (!txn || !yd_disk_process_valid(txn->disk)) return -1;
    if (!txn->exclusive && !txn->replay && !observe(txn, key, size, error, length)) {
        txn->failed = true;
        return -1;
    }
    return yd_disk_tx_peek(txn, key, size, value, error, length);
}
static YDKeyChange *observe(YDDiskTxn *txn, const void *key, size_t size, char *error,
                            size_t length) {
    if (!txn || !yd_disk_process_valid(txn->disk)) return NULL;
    if (!key || !size || size > YD_DISK_KEY_LIMIT)
        return NULL;
    const unsigned char *bytes = key;
    uint64_t hash = UINT64_C(1469598103934665603);
    for (size_t i = 0; i < size; i++) {
        hash ^= bytes[i];
        hash *= UINT64_C(1099511628211);
    }
    size_t slot = (size_t)(hash % 1024);
    for (YDKeyChange *op = txn->changes[slot]; op; op = op->next)
        if (op->size == size && !memcmp(op->key, key, size))
            return op;
    if (sizeof(YDKeyChange) + size > 64U * 1024U * 1024U - txn->change_bytes) {
        yd_disk_error(error, length, "optimistic transaction exceeds 64 MiB write-set budget");
        return NULL;
    }
    YDKeyChange *op = calloc(1, sizeof(*op));
    if (!op)
        return NULL;
    op->key = malloc(size);
    if (!op->key) {
        free(op);
        return NULL;
    }
    memcpy(op->key, key, size);
    op->size = size;
    int found = get(txn->disk, &txn->base, NULL, key, size, &op->expected, error, length);
    if (found < 0) {
        free(op->key);
        free(op);
        return NULL;
    }
    op->found = found != 0;
    op->next = txn->changes[slot];
    txn->changes[slot] = op;
    txn->change_bytes += sizeof(*op) + size;
    return op;
}
void yd_disk_changes_free(YDDiskTxn *txn) {
    for (size_t i = 0; i < 1024; i++)
        while (txn->changes[i]) {
            YDKeyChange *op = txn->changes[i];
            txn->changes[i] = op->next;
            free(op->key);
            free(op);
        }
}
static bool add_value(uint64_t value, int64_t delta, uint64_t *result) {
    uint64_t magnitude = delta < 0 ? (uint64_t)(-(delta + 1)) + 1 : (uint64_t)delta;
    if (delta < 0) {
        if (value < magnitude)
            return false;
        *result = value - magnitude;
    } else {
        if (magnitude > UINT64_MAX - value)
            return false;
        *result = value + magnitude;
    }
    return true;
}
bool yd_disk_add(YDDiskTxn *txn, const void *key, size_t size, int64_t delta, char *error,
                 size_t length) {
    uint64_t current = 0, next = 0;
    int found = yd_disk_tx_peek(txn, key, size, &current, error, length);
    if (found != 1 || !add_value(current, delta, &next)) {
        txn->failed = true;
        return yd_disk_error(error, length, "counter delta outside unsigned 64-bit range");
    }
    YDKeyChange *op = NULL;
    bool additive = false;
    int64_t previous = 0;
    if (!txn->exclusive && !txn->replay) {
        op = observe(txn, key, size, error, length);
        if (!op) {
            txn->failed = true;
            return false;
        }
        additive = op->found && (!op->write || op->counter);
        previous = op->counter ? op->delta : 0;
        if ((delta > 0 && previous > INT64_MAX - delta) ||
            (delta < 0 && previous < INT64_MIN - delta)) {
            txn->failed = true;
            return false;
        }
    }
    if (!mutate(txn, key, size, next, false, error, length))
        return false;
    if (op && additive) {
        op->counter = true;
        op->delta = previous + delta;
    }
    return true;
}
static bool merge_stat(uint64_t current, uint64_t before, uint64_t after, uint64_t *result) {
    if (after >= before) {
        uint64_t difference = after - before;
        if (difference > UINT64_MAX - current)
            return false;
        *result = current + difference;
    } else {
        uint64_t difference = before - after;
        if (difference > current)
            return false;
        *result = current - difference;
    }
    return true;
}
bool yd_disk_rebase(YDDiskTxn *txn, const YDDiskView *current, char *error, size_t length) {
    if (current->generation == txn->base.generation)
        return true;
    if (txn->exclusive) {
        errno = EAGAIN;
        return yd_disk_error(error, length, "maintenance root changed");
    }
    for (size_t i = 0; i < 1024; i++)
        for (YDKeyChange *op = txn->changes[i]; op; op = op->next) {
            uint64_t value = 0;
            int found = get(txn->disk, current, NULL, op->key, op->size, &value, error, length);
            if (found < 0)
                return false;
            if ((found != 0) != op->found || (found && !op->counter && value != op->expected)) {
                yd_disk_error(error, length, "transaction conflicted with a newer root");
                errno = EAGAIN;
                return false;
            }
        }
    YDDiskView prepared = txn->view, merged = *current;
    if (!merge_stat(current->documents, txn->base.documents, prepared.documents,
                    &merged.documents) ||
        !merge_stat(current->collections, txn->base.collections, prepared.collections,
                    &merged.collections) ||
        !merge_stat(current->bytes, txn->base.bytes, prepared.bytes, &merged.bytes))
        return yd_disk_error(error, length, "generation counters overflowed while merging");
    if (merged.collections > YD_DISK_COLLECTION_LIMIT) {
        /* Each preparation can fit independently while their combined catalog
         * cannot. Retry against the new root so the document layer reports the
         * capacity failure without publishing an oversized catalog. */
        errno = EAGAIN;
        return yd_disk_error(error, length, "concurrent collection capacity exceeded");
    }
    merged.revision = current->revision ^ txn->base.revision ^ prepared.revision;
    yd_disk_dirty_discard(txn);
    txn->view = merged;
    txn->base_end = current->end;
    if (txn->next < current->end)
        txn->next = current->end;
    txn->replay = true;
    for (size_t i = 0; i < 1024; i++)
        for (YDKeyChange *op = txn->changes[i]; op; op = op->next)
            if (op->write) {
                uint64_t value = op->value;
                if (op->counter) {
                    uint64_t existing = 0;
                    if (get(txn->disk, &txn->view, txn, op->key, op->size, &existing, error,
                            length) != 1 ||
                        !add_value(existing, op->delta, &value))
                        return yd_disk_error(error, length,
                                             "concurrent counter delta cannot be applied");
                }
                if (!mutate(txn, op->key, op->size, value, op->deleted, error, length))
                    return false;
            }
    txn->replay = false;
    return true;
}
static bool descend(YDDiskCursor *cursor, uint64_t offset, const void *key, size_t size,
                    bool exclusive, char *error, size_t length) {
    while (offset) {
        if (cursor->depth == YD_DISK_DEPTH)
            return yd_disk_error(error, length, "cursor depth exceeded");
        Frame *frame = &cursor->frames[cursor->depth];
        if (!node_read(cursor->disk, &cursor->view, cursor->txn, offset, &frame->node, error,
                       length))
            return false;
        cursor->depth++;
        if (frame->node.branch) {
            frame->index = size ? child_at(&frame->node, key, size) : 0;
            offset = frame->node.entries[frame->index].value;
        } else {
            frame->index = size ? lower(&frame->node, key, size) : 0;
            if (exclusive && frame->index < frame->node.count &&
                compare(frame->node.entries[frame->index].key,
                        frame->node.entries[frame->index].size, key, size) == 0)
                frame->index++;
            return true;
        }
    }
    return true;
}
static YDDiskCursor *cursor_new(YDDisk *disk, const YDDiskView *view, YDDiskTxn *txn,
                                const void *key, size_t size, bool exclusive, char *error,
                                size_t length) {
    if (!yd_disk_process_valid(disk)) return NULL;
    if (size > YD_DISK_KEY_LIMIT || (!key && size)) {
        yd_disk_error(error, length, "invalid cursor key");
        return NULL;
    }
    YDDiskCursor *cursor = calloc(1, sizeof(*cursor));
    if (!cursor)
        return NULL;
    cursor->disk = disk;
    cursor->process = disk->fence_hold ? getpid() : 0;
    cursor->view = *view;
    cursor->txn = txn;
    /* Transactions exclude compaction; a view cursor keeps its file readable. */
    cursor->held = !txn && yd_disk_epoch_hold(disk, view->epoch);
    if (!descend(cursor, view->root, key, size, exclusive, error, length)) {
        yd_disk_cursor_free(cursor);
        return NULL;
    }
    return cursor;
}
YDDiskCursor *yd_disk_cursor(YDDisk *disk, const YDDiskView *view, const void *key, size_t size,
                             bool exclusive, char *error, size_t length) {
    return cursor_new(disk, view, NULL, key, size, exclusive, error, length);
}
YDDiskCursor *yd_disk_tx_cursor(YDDiskTxn *txn, const void *key, size_t size, bool exclusive,
                                char *error, size_t length) {
    if (!txn || !yd_disk_process_valid(txn->disk)) return NULL;
    return cursor_new(txn->disk, &txn->view, txn, key, size, exclusive, error, length);
}
int yd_disk_next(YDDiskCursor *cursor, void *key, size_t capacity, size_t *size, uint64_t *value,
                 char *error, size_t length) {
    if (!cursor || (cursor->process && cursor->process != getpid()) || cursor->failed) {
        yd_disk_error(error, length, "invalid or failed cursor");
        return -1;
    }
    while (cursor->depth) {
        Frame *frame = &cursor->frames[cursor->depth - 1];
        if (!frame->node.branch && frame->index < frame->node.count) {
            Entry *entry = &frame->node.entries[frame->index++];
            if (entry->size > capacity) {
                cursor->failed = true;
                yd_disk_error(error, length, "cursor key buffer too small");
                return -1;
            }
            memcpy(key, entry->key, entry->size);
            *size = entry->size;
            *value = entry->value;
            return 1;
        }
        if (frame->node.branch && ++frame->index < frame->node.count) {
            if (!descend(cursor, frame->node.entries[frame->index].value, NULL, 0, false, error,
                         length)) {
                cursor->failed = true;
                return -1;
            }
        } else {
            node_free(&frame->node);
            cursor->depth--;
        }
    }
    return 0;
}
void yd_disk_cursor_free(YDDiskCursor *cursor) {
    if (!cursor || (cursor->process && cursor->process != getpid()))
        return;
    while (cursor->depth)
        node_free(&cursor->frames[--cursor->depth].node);
    if (cursor->held) yd_disk_epoch_release(cursor->disk, cursor->view.epoch);
    free(cursor);
}
