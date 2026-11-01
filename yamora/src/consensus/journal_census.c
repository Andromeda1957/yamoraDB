#define _POSIX_C_SOURCE 200809L
#include "journal_census.h"
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct YDRaftJournalCensus {
    YDRaftJournalCensusInfo info;
    YDRaftJournalCensusSource sources[YD_RAFT_CENSUS_SOURCES];
    YDRaftJournalCensusRoot roots[YD_RAFT_CENSUS_ROOTS];
    YDRaftJournalCensusBinding bindings[YD_RAFT_NAMESPACE_BINDINGS];
    YDDiskLineageInfo native_info;
    YDRaftJournalScopeInfo scope_info;
    YDDiskLineageSnapshot *native;
    YDRaftJournalScopeSnapshot *scope;
    YDRaftJournalNamespace *names;
    YDDiskRecoveryRoots *independent[YD_RAFT_CENSUS_SOURCES];
    YDRaftSnapshotReference *archives[YD_RAFT_CENSUS_ROOTS];
};

static bool same_view(const YDDiskView *a, const YDDiskView *b) {
    return a->format == b->format && a->generation == b->generation &&
        a->root == b->root && a->end == b->end && a->documents == b->documents &&
        a->collections == b->collections && a->bytes == b->bytes && a->revision == b->revision;
}
static bool inode(dev_t device, ino_t number, const struct stat *s) {
    return device == s->st_dev && number == s->st_ino;
}
/* Guard only the identity check; release by close before any callback/metadata
 * work. The borrowed store and namespace token keep the original inode pinned.
 * A second guard checks that SAME binding after pins, never adopts a new one. */
static YDRaftArchiveResult store_binding(int root, const YDRaftSnapshotStore *store,
    struct stat *original, bool capture) {
    int guard = -1;
    YDRaftArchiveResult code = yd_raft_snapshot_namespace_guard(store, false, &guard, NULL, 0);
    if (code != YD_RAFT_ARCHIVE_OK) return code;
    struct stat actual, named;
    if (fstat(guard, &actual) || fstatat(root, YD_RAFT_ARCHIVE_DIRECTORY, &named, AT_SYMLINK_NOFOLLOW))
        code = YD_RAFT_ARCHIVE_IO;
    else if (!S_ISDIR(named.st_mode) || !inode(actual.st_dev, actual.st_ino, &named) ||
        (!capture && !inode(original->st_dev, original->st_ino, &actual)))
        code = YD_RAFT_ARCHIVE_INVALID;
    else if (capture) *original = actual;
    close(guard);
    return code;
}
static void add_root(YDRaftJournalCensus *c, size_t source, const YDDiskView *view,
    unsigned physical, uint64_t producers) {
    size_t i = 0;
    while (i < c->info.root_count && (c->roots[i].source_index != source ||
        !same_view(&c->roots[i].dependency.view, view))) i++;
    if (i == c->info.root_count) {
        if (i == YD_RAFT_CENSUS_ROOTS) {
            c->info.reasons |= YD_RAFT_CENSUS_LIMIT;
            return;
        }
        c->info.root_count++;
        c->roots[i].source_index = source;
        c->roots[i].dependency.view = *view;
        c->roots[i].dependency.state = YD_RAFT_DEPENDENCY_UNKNOWN;
        c->roots[i].dependency.archive_pin = YD_RAFT_ARCHIVE_INVALID;
    }
    c->roots[i].physical_slots |= physical;
    c->roots[i].producers |= producers;
}
static void physical_roots(YDRaftJournalCensus *c, size_t source) {
    const YDRaftJournalCensusSource *s = &c->sources[source];
    if (!s->physical_known || s->physical.selected < 0)
        c->info.reasons |= YD_RAFT_CENSUS_METADATA;
    if (s->physical_known)
        for (unsigned i = 0; i < 2; i++)
            if (s->physical.slots[i].valid)
                add_root(c, source, &s->physical.slots[i].view, 1U << i, 0);
}
static void capture_native(YDRaftJournalCensus *c, YDDiskLineage *native) {
    c->native = yd_disk_lineage_snapshot(native);
    if (!yd_disk_lineage_snapshot_info(c->native, &c->native_info)) {
        c->info.reasons |= YD_RAFT_CENSUS_NATIVE;
        return;
    }
    const YDDiskLineageInfo *n = &c->native_info;
    c->info.native_revision = n->revision;
    c->info.native_revision_after = n->revision_after;
    c->info.native_active = n->in_progress;
    c->info.native_active_after = n->in_progress_after;
    c->info.native_reasons = n->reasons;
    if (!n->complete) c->info.reasons |= YD_RAFT_CENSUS_NATIVE;
    c->info.source_count = n->source_count;
    c->info.producer_count = n->entry_count;
    /* Reserve even failed-reader slots; never allocate an independent reader
     * against budget that could belong to a retained lineage cache. */
    c->info.cache_reserved = n->source_count * YD_DISK_LINEAGE_CACHE;
    for (size_t i = 0; i < n->source_count; i++) {
        const YDDiskLineageSourceInfo *s = &n->sources[i];
        c->sources[i] = (YDRaftJournalCensusSource){.native_id = s->id,
            .device = s->device, .inode = s->inode, .writer_alive = s->writer_alive,
            .physical_known = s->physical_known, .physical_final = s->physical_final,
            .physical = s->physical,
            .observation = s->physical_known ? YD_DISK_OBSERVE_OK : YD_DISK_OBSERVE_IO};
        physical_roots(c, i);
    }
    for (size_t i = 0; i < n->entry_count; i++) {
        const YDDiskLineageEntry *entry = &n->entries[i];
        size_t s = 0;
        while (s < n->source_count && n->sources[s].id != entry->source_id) s++;
        if (s == n->source_count || entry->slot_count > 2) {
            c->info.reasons |= YD_RAFT_CENSUS_NATIVE;
            continue;
        }
        for (unsigned j = 0; j < entry->slot_count; j++)
            if (entry->slots[j].valid)
                add_root(c, s, &entry->slots[j].view, 0, UINT64_C(1) << i);
    }
}
static bool exact(const YDRaftJournalBindingInfo *r,
    const YDRaftJournalNamespaceBinding *b, YDRaftJournalBindingKind kind) {
    return r->kind == kind && inode(r->parent_device, r->parent_inode, &b->parent_identity) &&
        inode(r->device, r->inode, &b->file_identity) && !strcmp(r->name, b->component);
}
static bool registrations(YDRaftJournalCensus *c, const YDRaftJournalNamespaceBinding *b,
    YDRaftJournalBindingKind kind, bool used[YD_RAFT_JOURNAL_BINDINGS]) {
    bool matched = false;
    for (size_t i = 0; i < c->scope_info.count; i++)
        if (exact(&c->scope_info.bindings[i], b, kind)) used[i] = matched = true;
    return matched;
}
static bool workspace(YDRaftJournalCensus *c, const YDRaftJournalNamespaceBinding *b,
    bool used[YD_RAFT_JOURNAL_BINDINGS]) {
    bool matched = false;
    for (size_t i = 0; i < c->scope_info.count; i++) {
        const YDRaftJournalBindingInfo *r = &c->scope_info.bindings[i];
        if (r->kind == YD_RAFT_JOURNAL_BINDING_WORKSPACE &&
            inode(r->device, r->inode, &b->parent_identity)) used[i] = matched = true;
    }
    return matched;
}
static bool matching_fence(YDRaftJournalCensus *c,
    const YDRaftJournalNamespaceBinding *b, bool used[YD_RAFT_JOURNAL_BINDINGS]) {
    for (size_t i = 0; i < c->info.binding_count; i++) {
        YDRaftJournalNamespaceBinding fence;
        if (yd_raft_journal_namespace_binding(c->names, i, &fence) &&
            fence.kind == YD_RAFT_NAMESPACE_STAGING_FENCE &&
            inode(b->parent_identity.st_dev, b->parent_identity.st_ino, &fence.parent_identity) &&
            registrations(c, &fence, YD_RAFT_JOURNAL_BINDING_FENCE, used)) return true;
    }
    return false;
}
static uint32_t source_mask(const YDRaftJournalCensus *c, const struct stat *file) {
    uint32_t mask = 0;
    for (size_t i = 0; i < c->info.source_count; i++)
        if (inode(c->sources[i].device, c->sources[i].inode, file)) mask |= UINT32_C(1) << i;
    return mask;
}
static uint32_t independent(YDRaftJournalCensus *c, const YDRaftJournalNamespaceBinding *b) {
    size_t s = c->info.source_count;
    if (s == YD_RAFT_CENSUS_SOURCES ||
        c->info.cache_reserved > YD_RAFT_CENSUS_CACHE - YD_DISK_LINEAGE_CACHE) {
        c->info.reasons |= YD_RAFT_CENSUS_LIMIT;
        return 0;
    }
    /* This creates an independent SH OFD. It must never be attempted on any
     * inode already supplied by native lineage (including an escaped EX pin). */
    YDRaftJournalCensusSource *out = &c->sources[s];
    *out = (YDRaftJournalCensusSource){.device = b->file_identity.st_dev,
        .inode = b->file_identity.st_ino, .independent = true};
    out->physical.selected = -1;
    c->info.source_count++;
    out->observation = yd_disk_recovery_roots_open_at(b->parent_fd, b->component,
        YD_DISK_LINEAGE_CACHE, &c->independent[s], NULL, 0);
    if (out->observation != YD_DISK_OBSERVE_OK) {
        c->info.reasons |= out->observation == YD_DISK_OBSERVE_BUSY ?
            YD_RAFT_CENSUS_BUSY : YD_RAFT_CENSUS_IO;
        c->info.reasons |= YD_RAFT_CENSUS_METADATA;
    } else {
        c->info.cache_reserved += YD_DISK_LINEAGE_CACHE;
        out->physical_known = yd_disk_recovery_roots_info(c->independent[s], &out->physical);
        if (!out->physical_known || out->physical.device != out->device ||
            out->physical.inode != out->inode) {
            out->physical_known = false;
            memset(&out->physical, 0, sizeof(out->physical));
            out->physical.selected = -1;
            c->info.reasons |= YD_RAFT_CENSUS_CHANGED;
        }
        physical_roots(c, s);
    }
    return UINT32_C(1) << s;
}
static void capture_names(YDRaftJournalCensus *c, int root) {
    int candidates[YD_RAFT_NAMESPACE_CANDIDATES];
    size_t count = 0;
    for (size_t i = 0; i < c->scope_info.count; i++)
        if (c->scope_info.bindings[i].kind == YD_RAFT_JOURNAL_BINDING_WORKSPACE) {
            if (count == YD_RAFT_NAMESPACE_CANDIDATES) {
                c->info.reasons |= YD_RAFT_CENSUS_LIMIT;
                continue;
            }
            candidates[count++] = yd_raft_journal_scope_workspace_directory(c->scope, i);
        }
    c->names = yd_raft_journal_namespace_capture_candidates(root, candidates, count, NULL, 0);
    YDRaftJournalNamespaceInfo names;
    if (!yd_raft_journal_namespace_info(c->names, &names)) {
        c->info.reasons |= YD_RAFT_CENSUS_NAMESPACE;
        return;
    }
    c->info.root = names.root;
    c->info.namespace_reasons = names.reasons;
    c->info.namespace_entries = names.entries;
    c->info.binding_count = names.binding_count;
    if (!names.complete) c->info.reasons |= YD_RAFT_CENSUS_NAMESPACE;
    bool used[YD_RAFT_JOURNAL_BINDINGS] = {0};
    for (size_t i = 0; i < names.binding_count; i++) {
        YDRaftJournalNamespaceBinding b;
        if (!yd_raft_journal_namespace_binding(c->names, i, &b)) {
            c->info.reasons |= YD_RAFT_CENSUS_NAMESPACE;
            continue;
        }
        YDRaftJournalCensusBinding *out = &c->bindings[i];
        out->kind = b.kind; out->depth = b.depth; out->candidate_index = b.candidate_index;
        memcpy(out->path, b.path, sizeof(out->path));
        memcpy(out->component, b.component, sizeof(out->component));
        out->parent_identity = b.parent_identity; out->file_identity = b.file_identity;
        bool owned = false;
        if (b.kind == YD_RAFT_NAMESPACE_RETENTION_CONTROL) {
            out->registered = registrations(c, &b, YD_RAFT_JOURNAL_BINDING_CONTROL, used);
            if (!out->registered) c->info.reasons |= YD_RAFT_CENSUS_UNOWNED;
            continue;
        }
        if (b.kind == YD_RAFT_NAMESPACE_RETENTION_BIRTH) {
            out->registered = registrations(c, &b, YD_RAFT_JOURNAL_BINDING_BIRTH, used);
            if (!out->registered) c->info.reasons |= YD_RAFT_CENSUS_UNOWNED;
            continue;
        }
        if (b.kind == YD_RAFT_NAMESPACE_RETENTION_SESSION) {
            out->registered = registrations(c, &b, YD_RAFT_JOURNAL_BINDING_SESSION, used);
            if (!out->registered) c->info.reasons |= YD_RAFT_CENSUS_UNOWNED;
            continue;
        }
        if (b.kind == YD_RAFT_NAMESPACE_STAGING_FENCE) {
            bool w = workspace(c, &b, used);
            bool f = registrations(c, &b, YD_RAFT_JOURNAL_BINDING_FENCE, used);
            out->registered = w && f;
            if (!out->registered) c->info.reasons |= YD_RAFT_CENSUS_UNOWNED;
            continue;
        }
        out->sources = source_mask(c, &b.file_identity);
        /* An independent diagnostic reader is not a live native owner. */
        for (size_t j = 0; j < c->native_info.source_count; j++)
            if (out->sources & (UINT32_C(1) << j)) owned = true;
        if (b.kind == YD_RAFT_NAMESPACE_CURRENT) out->registered = true;
        else if (b.kind == YD_RAFT_NAMESPACE_RETAINED_CANDIDATE)
            out->registered = registrations(c, &b, YD_RAFT_JOURNAL_BINDING_RETAINED, used);
        else if (b.kind == YD_RAFT_NAMESPACE_PREPARED_CANDIDATE)
            out->registered = registrations(c, &b, YD_RAFT_JOURNAL_BINDING_PREPARED, used);
        else {
            bool w = workspace(c, &b, used);
            bool f = matching_fence(c, &b, used);
            out->registered = w && f;
        }
        if (!out->registered || (b.kind != YD_RAFT_NAMESPACE_CURRENT && !owned))
            c->info.reasons |= YD_RAFT_CENSUS_UNOWNED;
        if (!out->sources) out->sources = independent(c, &b);
    }
    for (size_t i = 0; i < c->scope_info.count; i++)
        if (!used[i]) c->info.reasons |= YD_RAFT_CENSUS_UNOWNED;
}
static bool step(YDRaftJournalCensus *c, YDRaftJournalCensusProgress progress, void *context) {
    if (c->info.reasons & YD_RAFT_CENSUS_CANCELLED) return false;
    if (progress && !progress(context)) c->info.reasons |= YD_RAFT_CENSUS_CANCELLED;
    return !(c->info.reasons & YD_RAFT_CENSUS_CANCELLED);
}
static void decode_root(YDRaftJournalCensus *c, size_t index, const YDRaftSnapshotStore *store,
    YDRaftArchiveResult store_status) {
    YDRaftJournalCensusRoot *r = &c->roots[index];
    const YDRaftJournalCensusSource *s = &c->sources[r->source_index];
    YDDiskView view = r->dependency.view;
    unsigned char bytes[144];
    uint64_t offset = 0;
    size_t size = 0;
    int found = -1;
    /* Unsupported profiles need no tree or payload reads. */
    if (view.format == 5 && !view.documents && !view.collections && !view.bytes && !view.revision) {
        YDDisk *reader = yd_disk_recovery_roots_reader(c->independent[r->source_index]);
        found = s->independent ? yd_disk_get(reader, &view, "\0YRM", 4, &offset, NULL, 0) :
            yd_disk_lineage_snapshot_get(c->native, s->native_id, &view, "\0YRM", 4,
                &offset, NULL, 0);
        if (found == 1) {
            bool read = s->independent ?
                yd_disk_record_into(reader, &view, offset, bytes, sizeof(bytes), &size, NULL, 0) :
                yd_disk_lineage_snapshot_record_into(c->native, s->native_id, &view,
                    offset, bytes, sizeof(bytes), &size, NULL, 0);
            if (!read) found = -1;
        }
    }
    r->dependency = yd_raft_journal_dependency_decode(&view, found,
        found == 1 ? bytes : NULL, size, &c->info.identity);
    if (r->dependency.state == YD_RAFT_DEPENDENCY_UNKNOWN) {
        c->info.reasons |= YD_RAFT_CENSUS_METADATA;
        return;
    }
    if (r->dependency.state == YD_RAFT_DEPENDENCY_KNOWN && r->dependency.metadata.snapshot.index) {
        r->dependency.archive_pin = store_status;
        if (store_status == YD_RAFT_ARCHIVE_OK)
            r->dependency.archive_pin = yd_raft_snapshot_reference_open(store,
                &r->dependency.metadata.snapshot, &c->archives[index], NULL, 0);
    }
    if (r->dependency.archive_pin != YD_RAFT_ARCHIVE_OK) c->info.reasons |= YD_RAFT_CENSUS_ARCHIVE;
}
YDRaftJournalCensus *yd_raft_journal_census_observe(int root, YDDiskLineage *native,
    YDRaftJournalScope *scope, const YDRaftMeta *identity, const YDRaftSnapshotStore *store,
    YDRaftJournalCensusProgress progress, void *context, char *error, size_t length) {
    YDRaftJournalCensus *c = calloc(1, sizeof(*c));
    if (!c) {
        yd_disk_error(error, length, "cannot allocate journal dependency census");
        return NULL;
    }
    if (identity) {
        memcpy(c->info.identity.cluster, identity->cluster, 16);
        c->info.identity.node = identity->node;
        c->info.identity.voters = identity->voters;
    }
    const YDDiskView empty = {.format = 5};
    if (root < 0 || !native || !scope ||
        yd_raft_journal_dependency_decode(&empty, 0, NULL, 0,
            &c->info.identity).state != YD_RAFT_DEPENDENCY_EMPTY)
        c->info.reasons |= YD_RAFT_CENSUS_ARGUMENT;
    step(c, progress, context);
    struct stat archive_identity;
    YDRaftArchiveResult store_status = store ? store_binding(root, store, &archive_identity, true) :
        YD_RAFT_ARCHIVE_INVALID;
    if (store && store_status != YD_RAFT_ARCHIVE_OK) {
        c->info.reasons |= YD_RAFT_CENSUS_ARCHIVE;
        if (store_status != YD_RAFT_ARCHIVE_BUSY) c->info.reasons |= YD_RAFT_CENSUS_CHANGED;
    }
    capture_native(c, native);
    c->scope = yd_raft_journal_scope_snapshot(scope);
    if (!yd_raft_journal_scope_snapshot_info(c->scope, &c->scope_info))
        c->info.reasons |= YD_RAFT_CENSUS_SCOPE;
    c->info.scope_revision = c->scope_info.revision;
    c->info.scope_active = c->scope_info.active;
    c->info.scope_count = c->scope_info.count;
    c->info.scope_reasons = c->scope_info.reasons;
    if (!c->scope_info.complete) c->info.reasons |= YD_RAFT_CENSUS_SCOPE;
    capture_names(c, root);
    for (size_t i = 0; i < c->info.root_count; i++)
        if (step(c, progress, context)) decode_root(c, i, store, store_status);
    /* Last callback precedes every final check. A callback can itself exercise
     * producer transitions; it never runs under a scope/backend mutex. */
    step(c, progress, context);
    if (store && store_status == YD_RAFT_ARCHIVE_OK &&
        store_binding(root, store, &archive_identity, false) != YD_RAFT_ARCHIVE_OK)
        c->info.reasons |= YD_RAFT_CENSUS_ARCHIVE | YD_RAFT_CENSUS_CHANGED;
    YDRaftJournalScopeSnapshot *endpoint = yd_raft_journal_scope_snapshot(scope);
    YDRaftJournalScopeInfo after;
    if (yd_raft_journal_scope_snapshot_info(endpoint, &after)) {
        c->info.scope_revision_after = after.revision;
        c->info.scope_active_after = after.active;
        c->info.scope_count_after = after.count;
        c->info.scope_reasons |= after.reasons;
        if (!after.complete) c->info.reasons |= YD_RAFT_CENSUS_SCOPE;
    } else c->info.reasons |= YD_RAFT_CENSUS_SCOPE;
    yd_raft_journal_scope_snapshot_close(endpoint);
    uint32_t reasons = 0;
    c->info.namespace_validated = yd_raft_journal_namespace_validate(c->names, &reasons);
    c->info.namespace_reasons |= reasons;
    c->info.scope_validated = yd_raft_journal_scope_validate(c->scope);
    c->info.native_validated = yd_disk_lineage_validate(native, c->info.native_revision);
    if (!c->info.scope_validated || !c->info.namespace_validated || !c->info.native_validated)
        c->info.reasons |= YD_RAFT_CENSUS_CHANGED;
    unsigned coverage = c->info.reasons & ~(YD_RAFT_CENSUS_METADATA | YD_RAFT_CENSUS_ARCHIVE);
    c->info.coverage_complete = !coverage;
    c->info.metadata_complete = c->info.coverage_complete && !(c->info.reasons & YD_RAFT_CENSUS_METADATA);
    c->info.archive_pins_complete = c->info.metadata_complete && !(c->info.reasons & YD_RAFT_CENSUS_ARCHIVE);
    if (error && length) {
        error[0] = 0;
        if (c->info.reasons) yd_disk_error(error, length, "partial journal dependency census");
    }
    return c;
}
/* Accessors expose only values; the observation resources remain private. */
bool yd_raft_journal_census_info(const YDRaftJournalCensus *c, YDRaftJournalCensusInfo *out) {
    if (out) memset(out, 0, sizeof(*out));
    if (!c || !out) return false;
    *out = c->info; return true;
}
#define ACCESSOR(name, type, member, count) \
bool yd_raft_journal_census_##name(const YDRaftJournalCensus *c, size_t i, type *out) { \
    if (out) memset(out, 0, sizeof(*out)); \
    if (!c || !out || i >= (count)) return false; \
    *out = c->member[i]; return true; \
}
ACCESSOR(source, YDRaftJournalCensusSource, sources, c->info.source_count)
ACCESSOR(root, YDRaftJournalCensusRoot, roots, c->info.root_count)
ACCESSOR(producer, YDDiskLineageEntry, native_info.entries, c->info.producer_count)
ACCESSOR(binding, YDRaftJournalCensusBinding, bindings, c->info.binding_count)
ACCESSOR(registration, YDRaftJournalBindingInfo, scope_info.bindings, c->info.scope_count)
#undef ACCESSOR
void yd_raft_journal_census_close(YDRaftJournalCensus *c) {
    if (!c) return;
    for (size_t i = 0; i < YD_RAFT_CENSUS_ROOTS; i++) yd_raft_snapshot_reference_close(c->archives[i]);
    for (size_t i = 0; i < YD_RAFT_CENSUS_SOURCES; i++) yd_disk_recovery_roots_close(c->independent[i]);
    yd_raft_journal_namespace_close(c->names);
    yd_raft_journal_scope_snapshot_close(c->scope);
    yd_disk_lineage_snapshot_close(c->native);
    free(c);
}
