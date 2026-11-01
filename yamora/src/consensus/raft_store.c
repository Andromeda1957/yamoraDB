#define _POSIX_C_SOURCE 200809L
#include "raft_internal.h"
#include "session2_hooks.h"
#include "../disk_internal.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
static const unsigned char meta_key[4] = {0, 'Y', 'R', 'M'};
static const unsigned char membership_key[4] = {0, 'Y', 'R', 'C'};
static uint64_t read64(const unsigned char *p) {
    uint64_t n = 0;
    for (unsigned i = 0; i < 8; i++)
        n |= (uint64_t)p[i] << (8 * i);
    return n;
}
static void write64(unsigned char *p, uint64_t n) {
    for (unsigned i = 0; i < 8; i++)
        p[i] = (unsigned char)(n >> (8 * i));
}
/* Separate namespace and version: the immutable META1/2/3 identity and retention
 * consumers retain their existing meaning. This record is selected atomically
 * with every journal root, including checkpoint and remote installation. */
bool yd_raft_membership_record(YDRaft *r, YDDiskTxn *txn) {
    unsigned char bytes[24] = "YDRCONF1";
    write64(bytes + 8, r->bootstrap_voters);
    write64(bytes + 16, r->configuration_base);
    uint64_t offset;
    return yd_disk_append(txn, bytes, sizeof(bytes), &offset, r->error, sizeof(r->error)) &&
        yd_disk_put(txn, membership_key, sizeof(membership_key), offset, r->error, sizeof(r->error));
}
bool yd_raft_membership_recover(YDRaft *r, const YDDiskView *view) {
    uint16_t all = (uint16_t)((1U << (r->meta.voters + 1)) - 2);
    r->bootstrap_voters = all;
    r->configuration_base = yd_raft_membership_pack((YDRaftMembership){
        .old_voters = all, .new_voters = all});
    uint64_t offset;
    int found = yd_disk_get(r->disk, view, membership_key, 4, &offset, r->error, sizeof(r->error));
    if (found < 0) return false;
    if (!found) return !r->meta.membership_required; /* Legacy static journal. */
    size_t size = 0;
    unsigned char *bytes = yd_disk_record(r->disk, view, offset, &size, r->error, sizeof(r->error));
    bool valid = bytes && size == 24 && !memcmp(bytes, "YDRCONF1", 8);
    uint64_t initial = valid ? read64(bytes + 8) : 0, base = valid ? read64(bytes + 16) : 0;
    YDRaftMembership ignored;
    valid = valid && initial <= UINT16_MAX && !(initial & ~all) &&
        yd_raft_membership_unpack(yd_raft_membership_pack((YDRaftMembership){
            .old_voters = (uint16_t)initial, .new_voters = (uint16_t)initial}), r->meta.voters, &ignored) &&
        base <= UINT32_MAX && yd_raft_membership_unpack((uint32_t)base, r->meta.voters, &ignored);
    if (valid && !r->meta.snapshot.index)
        valid = base == yd_raft_membership_pack((YDRaftMembership){
            .old_voters = (uint16_t)initial, .new_voters = (uint16_t)initial});
    if (valid && !r->meta.membership_required)
        valid = initial == all && base == yd_raft_membership_pack((YDRaftMembership){
            .old_voters = all, .new_voters = all});
    free(bytes);
    if (valid) {
        r->bootstrap_voters = (uint16_t)initial;
        r->configuration_base = (uint32_t)base;
    }
    return valid;
}
bool yd_raft_membership_bootstrap(YDRaft *r, uint16_t voters) {
    if (!r || r->role == YD_RAFT_FAILED) return false;
    if (!voters) voters = (uint16_t)((1U << (r->meta.voters + 1)) - 2);
    if (voters & ~((1U << (r->meta.voters + 1)) - 2)) return false;
    if (voters == r->bootstrap_voters) return true;
    YDRaftMembership m;
    uint32_t packed = yd_raft_membership_pack((YDRaftMembership){.old_voters = voters,
        .new_voters = voters});
    if (r->meta.term || r->meta.last || !yd_raft_membership_unpack(packed, r->meta.voters, &m))
        return false;
    r->bootstrap_voters = voters;
    r->configuration_base = packed;
    r->meta.membership_required = true;
    return yd_raft_save(r, &r->meta, NULL) && yd_raft_membership_rebuild(r);
}
static void key(unsigned char out[12], char type, uint64_t index) {
    out[0] = 0;
    out[1] = 'Y';
    out[2] = 'R';
    out[3] = (unsigned char)type;
    for (unsigned i = 0; i < 8; i++)
        out[4 + i] = (unsigned char)(index >> (56 - 8 * i));
}
bool yd_raft_fail(YDRaft *r, const char *reason) {
    if (reason)
        snprintf(r->error, sizeof(r->error), "%s", reason);
    r->role = YD_RAFT_FAILED;
    r->leader = 0;
    return false;
}
static bool nonzero(const unsigned char bytes[32]) {
    unsigned char value = 0;
    for (unsigned i = 0; i < 32; i++)
        value |= bytes[i];
    return value != 0;
}
bool yd_raft_decode_meta(const unsigned char *bytes, size_t size,
                          const YDRaftMeta *expected_identity, YDRaftMeta *out) {
    if (!out)
        return false;
    YDRaftMeta m = {0};
    if (expected_identity) {
        memcpy(m.cluster, expected_identity->cluster, sizeof(m.cluster));
        m.node = expected_identity->node;
        m.voters = expected_identity->voters;
    }
    bool slotted = bytes && size == 144 && !memcmp(bytes, "YDRMETA5", 8);
    bool configured = bytes && size == 144 && (!memcmp(bytes, "YDRMETA4", 8) ||
        (slotted && bytes[27] == 1));
    bool selected = bytes && size == 144 && !memcmp(bytes, "YDRMETA3", 8);
    bool modern = slotted || configured || selected || (bytes && size == 112 && !memcmp(bytes, "YDRMETA2", 8));
    bool valid = bytes && expected_identity &&
                 (modern || (size == 64 && !memcmp(bytes, "YDRMETA1", 8))) &&
                 !memcmp(bytes + 8, m.cluster, 16) &&
                 bytes[24] == m.node && bytes[25] == m.voters;
    if (slotted) valid = valid && bytes[26] == 1 && bytes[27] <= 1;
    for (size_t i = slotted ? 28 : 26; valid && i < 32; i++)
        if (bytes[i])
            valid = false;
    if (valid) {
        m.membership_required = configured;
        m.application_layout = slotted ? 1 : 0;
        m.term = read64(bytes + 32);
        m.vote = read64(bytes + 40);
        m.last = read64(bytes + 48);
        m.committed = read64(bytes + 56);
        valid = m.vote <= m.voters && m.last < UINT64_MAX && m.committed <= m.last &&
                (m.term || (!m.vote && !m.last));
        if (valid && modern && (slotted || !configured || read64(bytes + 64))) {
            m.snapshot.index = read64(bytes + 64);
            m.snapshot.term = read64(bytes + 72);
            memcpy(m.snapshot.archive, bytes + 80, sizeof(m.snapshot.archive));
            valid = m.snapshot.index && m.snapshot.index <= UINT64_MAX - 2 &&
                    m.snapshot.index <= m.committed && m.snapshot.term &&
                    m.snapshot.term <= m.term && nonzero(m.snapshot.archive);
            if (valid && (slotted || selected || configured)) {
                memcpy(m.application, bytes + 112, sizeof(m.application));
                valid = (configured && !slotted) || nonzero(m.application);
            }
        } else if (valid && configured) {
            for (unsigned i = 64; valid && i < 144; i++) valid = bytes[i] == 0;
        }
    }
    if (valid)
        *out = m;
    else
        memset(out, 0, sizeof(*out));
    return valid;
}
size_t yd_raft_encode_meta(const YDRaftMeta *m, unsigned char out[144]) {
    memset(out, 0, 144);
    if (m->application_layout > 1 ||
        (m->application_layout && (!m->snapshot.index || !nonzero(m->application)))) return 0;
    bool selected = nonzero(m->application);
    memcpy(out, m->application_layout ? "YDRMETA5" : m->membership_required ? "YDRMETA4" : selected ? "YDRMETA3" :
        m->snapshot.index ? "YDRMETA2" : "YDRMETA1", 8);
    memcpy(out + 8, m->cluster, 16);
    out[24] = (unsigned char)m->node;
    out[25] = (unsigned char)m->voters;
    if (m->application_layout) { out[26] = 1; out[27] = m->membership_required ? 1 : 0; }
    write64(out + 32, m->term);
    write64(out + 40, m->vote);
    write64(out + 48, m->last);
    write64(out + 56, m->committed);
    if (m->snapshot.index) {
        write64(out + 64, m->snapshot.index);
        write64(out + 72, m->snapshot.term);
        memcpy(out + 80, m->snapshot.archive, 32);
        if (selected || m->membership_required || m->application_layout) {
            memcpy(out + 112, m->application, 32);
            return 144;
        }
        return 112;
    }
    return m->membership_required ? 144 : 64;
}
static bool write_meta(YDRaft *r, YDDiskTxn *txn, const YDRaftMeta *m) {
    unsigned char bytes[144];
    size_t size = yd_raft_encode_meta(m, bytes);
    uint64_t offset;
    return size && yd_disk_append(txn, bytes, size, &offset, r->error, sizeof(r->error)) &&
           yd_disk_put(txn, meta_key, sizeof(meta_key), offset, r->error, sizeof(r->error));
}
static bool save(YDRaft *r, const YDRaftMeta *m, const YDRaftEntry *entry) {
    if (r->role == YD_RAFT_FAILED)
        return false;
    YDDiskTxn *txn = yd_disk_begin_exclusive(r->disk, r->error, sizeof(r->error));
    if (!txn)
        return yd_raft_fail(r, NULL);
    bool valid = true;
    uint64_t offset;
    unsigned char k[12];
    if (entry) {
        size_t size = 40 + entry->size;
        unsigned char *bytes = calloc(1, size);
        valid = bytes != NULL;
        if (valid) {
            memcpy(bytes, "YDRLOG01", 8);
            write64(bytes + 8, entry->index);
            write64(bytes + 16, entry->term);
            write64(bytes + 24, entry->size);
            bytes[32] = (unsigned char)entry->kind;
            if (entry->size)
                memcpy(bytes + 40, entry->command, entry->size);
            valid = yd_disk_append(txn, bytes, size, &offset, r->error, sizeof(r->error));
            if (valid) {
                key(k, 'E', entry->index);
                valid = yd_disk_put(txn, k, 12, offset, r->error, sizeof(r->error));
            }
            if (valid) {
                key(k, 'T', entry->index);
                valid = yd_disk_put(txn, k, 12, entry->term, r->error, sizeof(r->error));
            }
        }
        free(bytes);
    }
    if (valid)
        valid = write_meta(r, txn, m) && yd_raft_membership_record(r, txn);
    if (valid) {
        yd_session2_disk_delay(r->meta.node);
        valid = yd_disk_commit(txn, r->error, sizeof(r->error));
    }
    else
        yd_disk_abort(txn);
    if (!valid)
        return yd_raft_fail(r, "raft journal persistence failed; reopen required");
    bool rebuild = (entry && entry->kind == YD_RAFT_CONFIGURATION) ||
        (entry && entry->index <= r->meta.last) ||
        m->last < r->meta.last || (r->configuration_final && m->committed >= r->configuration_final);
    r->meta = *m;
    return !rebuild || yd_raft_membership_rebuild(r);
}
bool yd_raft_save(YDRaft *r, const YDRaftMeta *m, const YDRaftEntry *entry) {
    yd_raft_journal_scope_begin(r->journal_scope);
    bool valid = save(r, m, entry);
    yd_raft_journal_scope_end(r->journal_scope);
    return valid;
}
bool yd_raft_term(YDRaft *r, uint64_t index, uint64_t *term) {
    if (index == r->meta.snapshot.index) {
        *term = r->meta.snapshot.term;
        return true;
    }
    if (index < r->meta.snapshot.index || index > r->meta.last)
        return false;
    unsigned char k[12];
    key(k, 'T', index);
    YDDiskView view = yd_disk_view(r->disk);
    if (yd_disk_get(r->disk, &view, k, 12, term, r->error, sizeof(r->error)) != 1 || !*term ||
        *term > r->meta.term)
        return yd_raft_fail(r, "invalid raft term index");
    return true;
}
bool yd_raft_entry(YDRaft *r, uint64_t index, YDRaftEntry *entry) {
    memset(entry, 0, sizeof(*entry));
    if (r->role == YD_RAFT_FAILED || index <= r->meta.snapshot.index || index > r->meta.last)
        return false;
    unsigned char k[12];
    key(k, 'E', index);
    uint64_t offset = 0, term = 0;
    size_t size = 0;
    YDDiskView view = yd_disk_view(r->disk);
    if (yd_disk_get(r->disk, &view, k, 12, &offset, r->error, sizeof(r->error)) != 1)
        return yd_raft_fail(r, "missing raft log entry");
    unsigned char *bytes =
        yd_disk_record(r->disk, &view, offset, &size, r->error, sizeof(r->error));
    bool valid = bytes && size >= 40 && size - 40 <= YD_RAFT_COMMAND_LIMIT &&
                 !memcmp(bytes, "YDRLOG01", 8) && read64(bytes + 8) == index &&
                 read64(bytes + 24) == size - 40 && bytes[32] <= YD_RAFT_CONFIGURATION;
    for (size_t i = 33; valid && i < 40; i++)
        if (bytes[i])
            valid = false;
    if (valid)
        valid = (bytes[32] == YD_RAFT_NOOP ? size == 40 : size > 40) &&
                yd_raft_term(r, index, &term) && read64(bytes + 16) == term;
    if (!valid) {
        free(bytes);
        return yd_raft_fail(r, "invalid raft log record");
    }
    *entry = (YDRaftEntry){.index = index,
                           .term = term,
                           .kind = (YDRaftKind)bytes[32],
                           .command = size > 40 ? bytes + 40 : NULL,
                           .size = size - 40,
                           .allocation = bytes};
    return true;
}
void yd_raft_entry_free(YDRaftEntry *entry) {
    free(entry->allocation);
    memset(entry, 0, sizeof(*entry));
}
void yd_raft_append_free(YDRaftAppend *request) {
    yd_raft_entry_free(&request->entry);
    memset(request, 0, sizeof(*request));
}
static bool recover(YDRaft *r) {
    YDDiskView view = yd_disk_view(r->disk);
    uint64_t offset = 0;
    int found = yd_disk_get(r->disk, &view, meta_key, 4, &offset, r->error, sizeof(r->error));
    if (found < 0)
        return false;
    if (!found)
        return !view.root && yd_raft_membership_recover(r, &view) &&
            yd_raft_membership_rebuild(r) && yd_raft_save(r, &r->meta, NULL);
    size_t size = 0;
    unsigned char *bytes =
        yd_disk_record(r->disk, &view, offset, &size, r->error, sizeof(r->error));
    bool valid = yd_raft_decode_meta(bytes, size, &r->meta, &r->meta);
    free(bytes);
    if (!valid || !yd_raft_membership_recover(r, &view))
        return false;
    unsigned char k[1024], start = 0;
    size_t key_size;
    uint64_t value, entries = 0, terms = 0, prior = r->meta.snapshot.term;
    YDDiskCursor *cursor =
        yd_disk_cursor(r->disk, &view, &start, 1, false, r->error, sizeof(r->error));
    if (!cursor)
        return false;
    int next;
    while ((next = yd_disk_next(cursor, k, sizeof(k), &key_size, &value, r->error,
                                sizeof(r->error))) == 1) {
        if (key_size == 4 && (!memcmp(k, meta_key, 4) || !memcmp(k, membership_key, 4)))
            continue;
        if (key_size != 12 || k[0] || k[1] != 'Y' || k[2] != 'R' || (k[3] != 'E' && k[3] != 'T')) {
            valid = false;
            break;
        }
        uint64_t index = 0;
        for (unsigned i = 0; i < 8; i++)
            index = (index << 8) | k[4 + i];
        if (index <= r->meta.snapshot.index) {
            valid = false;
            break;
        }
        if (index > r->meta.last)
            continue; /* Unreachable tail after conflict repair. */
        if (k[3] == 'E') {
            YDRaftEntry entry;
            if (index != r->meta.snapshot.index + entries + 1 || !yd_raft_entry(r, index, &entry)) {
                valid = false;
                break;
            }
            valid = entry.term >= prior;
            prior = entry.term;
            yd_raft_entry_free(&entry);
            if (!valid)
                break;
            entries++;
        } else {
            if (index != r->meta.snapshot.index + terms + 1 || !value || value > r->meta.term) {
                valid = false;
                break;
            }
            terms++;
        }
    }
    yd_disk_cursor_free(cursor);
    return valid && next == 0 && entries == r->meta.last - r->meta.snapshot.index &&
           terms == r->meta.last - r->meta.snapshot.index && yd_raft_membership_rebuild(r);
}
void yd_raft_application_generation(const YDRaft *r, unsigned char generation[32]) {
    if (r)
        memcpy(generation, r->meta.application, 32);
    else
        memset(generation, 0, 32);
}
YDRaftSnapshotBase yd_raft_snapshot_base(const YDRaft *r) {
    return r ? r->meta.snapshot : (YDRaftSnapshotBase){0};
}
bool yd_raft_checkpoint(YDRaft *r, const YDRaftSnapshotBase *base) {
    if (!r || !base || r->role == YD_RAFT_FAILED || !base->index || base->index > UINT64_MAX - 2 ||
        !base->term ||
        base->index < r->meta.snapshot.index || base->index > r->meta.committed)
        return false;
    unsigned char nonzero = 0;
    for (size_t i = 0; i < sizeof(base->archive); i++)
        nonzero |= base->archive[i];
    if (!nonzero)
        return false;
    if (base->index == r->meta.snapshot.index)
        return base->term == r->meta.snapshot.term &&
               !memcmp(base->archive, r->meta.snapshot.archive, sizeof(base->archive));
    uint64_t term = 0;
    if (!yd_raft_term(r, base->index, &term) || term != base->term)
        return false;
    YDRaftMeta m = r->meta;
    m.snapshot = *base;
    return yd_raft_publish_snapshot(r, &m);
}
bool yd_raft_application_select(YDRaft *r, const unsigned char expected[32],
                                 const YDRaftSnapshotBase *base) {
    return yd_raft_application_select_layout(r, expected, base, r ? r->meta.application_layout : 0);
}
bool yd_raft_application_select_layout(YDRaft *r, const unsigned char expected[32],
    const YDRaftSnapshotBase *base, unsigned layout) {
    if (!r || !expected || !base || layout > 1 || r->role == YD_RAFT_FAILED ||
        memcmp(expected, r->meta.application, 32) || !base->index ||
        base->index > UINT64_MAX - 2 || base->index < r->meta.snapshot.index ||
        base->index > r->meta.committed || !base->term)
        return false;
    unsigned char nonzero = 0;
    for (size_t i = 0; i < sizeof(base->archive); i++)
        nonzero |= base->archive[i];
    if (!nonzero)
        return false;
    uint64_t term = 0;
    if (!yd_raft_term(r, base->index, &term) || term != base->term)
        return false;
    if (base->index == r->meta.snapshot.index &&
        !memcmp(base->archive, r->meta.snapshot.archive, 32) &&
        !memcmp(base->archive, r->meta.application, 32) && layout == r->meta.application_layout)
        return true;
    YDRaftMeta m = r->meta;
    m.application_layout = layout;
    m.snapshot = *base;
    memcpy(m.application, base->archive, sizeof(m.application));
    return yd_raft_publish_snapshot(r, &m);
}
static bool publish_snapshot(YDRaft *r, const YDRaftMeta *m) {
    YDDiskTxn *txn = yd_disk_begin_exclusive(r->disk, r->error, sizeof(r->error));
    YDDiskView view = yd_disk_view(r->disk);
    unsigned char k[1024];
    size_t size = 0;
    uint64_t value;
    YDDiskCursor *cursor = txn
        ? yd_disk_cursor(r->disk, &view, NULL, 0, false, r->error, sizeof(r->error)) : NULL;
    bool valid = cursor != NULL;
    int next = 0;
    while (valid && (next = yd_disk_next(cursor, k, sizeof(k), &size, &value, r->error,
                                         sizeof(r->error))) == 1) {
        if (size == sizeof(meta_key) && (!memcmp(k, meta_key, size) ||
            !memcmp(k, membership_key, size)))
            continue;
        if (size != 12 || memcmp(k, "\0YR", 3) || (k[3] != 'E' && k[3] != 'T')) {
            valid = false;
            break;
        }
        uint64_t index = 0;
        for (size_t i = 4; i < 12; i++)
            index = (index << 8) | k[i];
        valid = index != 0;
        if (valid && (index <= m->snapshot.index || index > m->last))
            valid = yd_disk_delete(txn, k, size, r->error, sizeof(r->error));
    }
    yd_disk_cursor_free(cursor);
    valid = valid && next == 0 && write_meta(r, txn, m) && yd_raft_membership_record(r, txn);
    if (valid)
        valid = yd_disk_commit(txn, r->error, sizeof(r->error));
    else
        yd_disk_abort(txn);
    if (!valid)
        return yd_raft_fail(r, "raft snapshot persistence failed; reopen required");
    r->meta = *m;
    return yd_raft_membership_rebuild(r);
}
bool yd_raft_publish_snapshot(YDRaft *r, const YDRaftMeta *m) {
    yd_raft_journal_scope_begin(r->journal_scope);
    /* A remote offer supplies an already selected base. Local checkpoints
     * compute the configuration at their exact committed application boundary. */
    bool valid = true;
    if (m->snapshot.index <= r->meta.committed) {
        YDRaftMembership at;
        valid = yd_raft_membership_at(r, m->snapshot.index, &at);
        if (valid) r->configuration_base = yd_raft_membership_pack(at);
    }
    if (valid) valid = publish_snapshot(r, m);
    yd_raft_journal_scope_end(r->journal_scope);
    return valid;
}
YDRaft *yd_raft_open(const char *root, const unsigned char cluster[16], unsigned node,
                     unsigned voters, size_t cache, char *error, size_t length) {
    return yd_raft_open_scoped(root, cluster, node, voters, cache, NULL, error, length);
}
YDRaft *yd_raft_open_scoped(const char *root, const unsigned char cluster[16], unsigned node,
    unsigned voters, size_t cache, YDRaftJournalScope *scope, char *error, size_t length) {
    return yd_raft_open_observed(root, cluster, node, voters, cache, scope, NULL, error, length);
}
YDRaft *yd_raft_open_observed(const char *root, const unsigned char cluster[16], unsigned node,
    unsigned voters, size_t cache, YDRaftJournalScope *scope,
    YDDiskLineage *lineage, char *error, size_t length) {
    return yd_raft_open_guarded(root, cluster, node, voters, cache, scope, lineage,
        NULL, NULL, error, length);
}
static YDRaft *open_guarded(const char *root, const unsigned char cluster[16], unsigned node,
    unsigned voters, size_t cache, YDRaftJournalScope *scope,
    YDDiskLineage *lineage, YDDiskOpenGuard native_guard, void *native_context,
    YDRaftRecoveryGuard guard, YDRaftConstructorGuard constructor_guard,
    void *context, YDStorageBudget *budget, char *error, size_t length);
YDRaft *yd_raft_open_constructing(const char *root, const unsigned char cluster[16], unsigned node,
    unsigned voters, size_t cache, YDRaftJournalScope *scope,
    YDDiskLineage *lineage, YDRaftConstructorGuard guard, void *context,
    char *error, size_t length) {
    return open_guarded(root, cluster, node, voters, cache, scope, lineage,
        NULL, NULL, NULL, guard, context, NULL, error, length);
}
YDRaft *yd_raft_open_constructing_native(const char *root, const unsigned char cluster[16], unsigned node,
    unsigned voters, size_t cache, YDRaftJournalScope *scope,
    struct YDDiskLineage *lineage, YDDiskOpenGuard native_guard, void *native_context,
    YDRaftConstructorGuard guard, void *context, char *error, size_t length) {
    return yd_raft_open_constructing_native_budgeted(root, cluster, node, voters, cache,
        scope, lineage, NULL, native_guard, native_context, guard, context, error, length);
}
YDRaft *yd_raft_open_constructing_native_budgeted(const char *root,
    const unsigned char cluster[16], unsigned node, unsigned voters, size_t cache,
    YDRaftJournalScope *scope, YDDiskLineage *lineage, YDStorageBudget *budget, YDDiskOpenGuard native_guard,
    void *native_context, YDRaftConstructorGuard guard, void *context,
    char *error, size_t length) {
    if (error && length)
        error[0] = 0;
    int prior;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &prior)) {
        yd_disk_error(error, length, "cannot verify Raft native constructor cancellation state");
        return NULL;
    }
    if (prior != PTHREAD_CANCEL_DISABLE) {
        (void)pthread_setcancelstate(prior, NULL);
        yd_disk_error(error, length, "Raft native constructor requires caller-disabled cancellation");
        return NULL;
    }
    return open_guarded(root, cluster, node, voters, cache, scope, lineage,
        native_guard, native_context, NULL, guard, context, budget, error, length);
}
YDRaft *yd_raft_open_guarded(const char *root, const unsigned char cluster[16], unsigned node,
    unsigned voters, size_t cache, YDRaftJournalScope *scope,
    YDDiskLineage *lineage, YDRaftRecoveryGuard guard, void *context,
    char *error, size_t length) {
    return open_guarded(root, cluster, node, voters, cache, scope, lineage,
        NULL, NULL, guard, NULL, context, NULL, error, length);
}
static YDRaft *open_guarded(const char *root, const unsigned char cluster[16], unsigned node,
    unsigned voters, size_t cache, YDRaftJournalScope *scope,
    YDDiskLineage *lineage, YDDiskOpenGuard native_guard, void *native_context,
    YDRaftRecoveryGuard guard, YDRaftConstructorGuard constructor_guard,
    void *context, YDStorageBudget *budget, char *error, size_t length) {
    if (error && length)
        error[0] = 0;
    bool identity = false;
    for (unsigned i = 0; cluster && i < 16; i++)
        identity |= cluster[i] != 0;
    if (!identity || voters < 3 || voters > YD_RAFT_VOTERS || !(voters & 1) || !node ||
        node > voters) {
        snprintf(error, length, "invalid raft identity or voter configuration");
        return NULL;
    }
    YDRaft *r = calloc(1, sizeof(*r));
    if (!r) {
        snprintf(error, length, "cannot allocate raft core");
        return NULL;
    }
    YDRaftJournalConstructor constructor = {0};
    if (constructor_guard) constructor = yd_raft_journal_scope_constructor_begin(scope);
    else yd_raft_journal_scope_begin(scope);
    r->journal_scope = yd_raft_journal_scope_retain(scope);
    memcpy(r->meta.cluster, cluster, 16);
    r->meta.node = node;
    r->meta.voters = voters;
    r->directory = root ? open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC) : -1;
    struct stat fence;
    if (r->directory < 0 || !fstatat(r->directory, ".yamora-initializing", &fence, AT_SYMLINK_NOFOLLOW) ||
        errno != ENOENT) {
        snprintf(error, length, "raft journal unavailable or initialization incomplete");
        yd_raft_journal_scope_constructor_invalidate(scope);
        yd_raft_close(r);
        yd_raft_journal_scope_end(scope);
        return NULL;
    }
    r->disk = native_guard ? budget
        ? yd_disk_open_guarded_budgeted_at(r->directory, true, cache,
            YD_DISK_ALLOCATION_UNLIMITED, budget, native_guard, native_context, error, length)
        : yd_disk_open_guarded_at(r->directory, true, cache,
            YD_DISK_ALLOCATION_UNLIMITED, native_guard, native_context, error, length)
        : budget ? yd_disk_open_budgeted_at(r->directory, true, cache,
            YD_DISK_ALLOCATION_UNLIMITED, budget, error, length)
        : yd_disk_open_at(r->directory, true, cache, error, length);
    yd_disk_lineage_bind_new(lineage, r->disk);
    if (!r->disk || yd_disk_view(r->disk).format != 5) {
        if (r->disk)
            snprintf(error, length, "invalid or mismatched raft journal");
        yd_raft_journal_scope_constructor_invalidate(scope);
        yd_raft_close(r);
        yd_raft_journal_scope_end(scope);
        return NULL;
    }
    bool admitted = true;
    if (constructor_guard) {
        yd_raft_journal_scope_constructor_guard(scope, constructor, r->directory,
            cluster, node, voters);
        admitted = constructor_guard(context, r->disk, r->directory, scope, constructor,
            error, length);
        yd_raft_journal_scope_constructor_invalidate(scope);
    }
    if (!admitted) {
        if (error && length) {
            error[length - 1] = 0;
            if (!error[0]) snprintf(error, length, "raft recovery admission refused");
        }
        yd_raft_journal_scope_constructor_invalidate(scope);
        yd_raft_close(r);
        yd_raft_journal_scope_end(scope);
        return NULL;
    }
    if (guard && !guard(context, r->disk, r->directory, error, length)) {
        if (error && length) {
            error[length - 1] = 0;
            if (!error[0])
                snprintf(error, length, "raft recovery admission refused");
        }
        yd_raft_journal_scope_constructor_invalidate(scope);
        yd_raft_close(r);
        yd_raft_journal_scope_end(scope);
        return NULL;
    }
    if (error && length)
        error[0] = 0;
    if (!recover(r)) {
        snprintf(error, length, "invalid or mismatched raft journal");
        yd_raft_journal_scope_constructor_invalidate(scope);
        yd_raft_close(r);
        yd_raft_journal_scope_end(scope);
        return NULL;
    }
    yd_raft_journal_scope_end(scope);
    return r;
}
void yd_raft_close(YDRaft *r) {
    if (r) {
        YDRaftJournalScope *scope = r->journal_scope;
        yd_raft_journal_scope_begin(scope);
        yd_disk_close(r->disk);
        if (r->directory >= 0)
            close(r->directory);
        yd_raft_journal_scope_end(scope);
        yd_raft_journal_scope_close(scope);
        free(r);
    }
}
YDRaftStatus yd_raft_status(const YDRaft *r) {
    return (YDRaftStatus){.role = r->role,
                          .node = r->meta.node,
                          .voters = r->meta.voters,
                          .leader = r->leader,
                          .term = r->meta.term,
                          .vote = r->meta.vote,
                          .last = r->meta.last,
                          .committed = r->meta.committed};
}
const char *yd_raft_error(const YDRaft *r) { return r->error; }
