#include "journal_dependencies.h"
#include <stdlib.h>
#include <string.h>

struct YDRaftJournalDependencies {
    YDDiskRecoveryRoots *roots;
    YDRaftJournalDependencyInfo info;
    YDRaftSnapshotReference *references[2];
};

static bool trusted_identity(const YDRaftMeta *identity) {
    if (!identity || identity->voters < 3 || identity->voters > YD_RAFT_VOTERS ||
        !(identity->voters & 1) || !identity->node || identity->node > identity->voters)
        return false;
    unsigned char nonzero = 0;
    for (unsigned i = 0; i < 16; i++) nonzero |= identity->cluster[i];
    return nonzero != 0;
}
static bool journal_view(const YDDiskView *view) {
    return view && view->format == 5 && !view->documents && !view->collections &&
        !view->bytes && !view->revision;
}
YDRaftJournalDependency yd_raft_journal_dependency_decode(const YDDiskView *view,
    int found, const unsigned char *bytes, size_t size, const YDRaftMeta *identity) {
    YDRaftJournalDependency result = {0};
    YDRaftJournalDependency *slot = &result;
    slot->state = YD_RAFT_DEPENDENCY_UNKNOWN;
    slot->archive_pin = YD_RAFT_ARCHIVE_INVALID;
    if (view) slot->view = *view;
    if (!trusted_identity(identity) || !journal_view(view)) return result;
    if (!found && !slot->view.root && !bytes && !size) {
        slot->state = YD_RAFT_DEPENDENCY_EMPTY;
        slot->archive_pin = YD_RAFT_ARCHIVE_OK;
        return result;
    }
    if (found != 1 || !yd_raft_decode_meta(bytes, size, identity, &slot->metadata))
        return result;
    slot->state = YD_RAFT_DEPENDENCY_KNOWN;
    if (!slot->metadata.snapshot.index) slot->archive_pin = YD_RAFT_ARCHIVE_OK;
    return result;
}
static void observe_slot(YDRaftJournalDependencies *d, unsigned i, const YDRaftMeta *identity,
    const YDRaftSnapshotStore *store) {
    const YDDiskRecoverySlot *physical = &d->info.physical.slots[i];
    YDRaftJournalDependency *slot = &d->info.slots[i];
    slot->archive_pin = YD_RAFT_ARCHIVE_INVALID;
    if (!physical->valid) {
        slot->state = YD_RAFT_DEPENDENCY_INVALID_HEADER;
        return;
    }
    slot->view = physical->view;
    slot->state = YD_RAFT_DEPENDENCY_UNKNOWN;
    if (!journal_view(&slot->view)) return;
    uint64_t offset = 0;
    YDDisk *reader = yd_disk_recovery_roots_reader(d->roots);
    int found = yd_disk_get(reader, &slot->view, "\0YRM", 4, &offset, NULL, 0);
    unsigned char bytes[144];
    size_t size = 0;
    if (found == 1 && !yd_disk_record_into(reader, &slot->view, offset, bytes,
        sizeof(bytes), &size, NULL, 0)) return;
    *slot = yd_raft_journal_dependency_decode(&physical->view, found,
        found == 1 ? bytes : NULL, size, identity);
    if (slot->state == YD_RAFT_DEPENDENCY_KNOWN && slot->metadata.snapshot.index && store)
        slot->archive_pin = yd_raft_snapshot_reference_open(store,
        &slot->metadata.snapshot, &d->references[i], NULL, 0);
}
YDRaftJournalDependencies *yd_raft_journal_dependencies_take_roots(
    YDDiskRecoveryRoots *roots, const YDRaftMeta *identity,
    const YDRaftSnapshotStore *store, char *error, size_t length) {
    YDDiskRecoveryInfo physical;
    if (!trusted_identity(identity) || !yd_disk_recovery_roots_info(roots, &physical)) {
        yd_disk_recovery_roots_close(roots);
        yd_disk_error(error, length, "invalid journal dependency observation");
        return NULL;
    }
    YDRaftJournalDependencies *d = calloc(1, sizeof(*d));
    if (!d) {
        yd_disk_recovery_roots_close(roots);
        yd_disk_error(error, length, "cannot allocate journal dependency observation");
        return NULL;
    }
    d->roots = roots;
    d->info.physical = physical;
    d->info.metadata_complete = physical.selected >= 0;
    bool pinned = true;
    for (unsigned i = 0; i < 2; i++) {
        observe_slot(d, i, identity, store);
        if (d->info.slots[i].state == YD_RAFT_DEPENDENCY_UNKNOWN)
            d->info.metadata_complete = false;
        if (physical.slots[i].valid && d->info.slots[i].archive_pin != YD_RAFT_ARCHIVE_OK)
            pinned = false;
    }
    d->info.archive_pins_complete = d->info.metadata_complete && pinned;
    if (error && length) error[0] = 0;
    return d;
}
bool yd_raft_journal_dependencies_info(const YDRaftJournalDependencies *d,
    YDRaftJournalDependencyInfo *out) {
    if (out) memset(out, 0, sizeof(*out));
    if (!d || !out) return false;
    *out = d->info;
    return true;
}
void yd_raft_journal_dependencies_close(YDRaftJournalDependencies *d) {
    if (!d) return;
    for (unsigned i = 0; i < 2; i++)
        yd_raft_snapshot_reference_close(d->references[i]);
    yd_disk_recovery_roots_close(d->roots);
    free(d);
}
