#define _POSIX_C_SOURCE 200809L
#include "journal_protection.h"
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

struct YDRaftJournalProtection {
    YDRaftJournalCensus *census;
    YDRaftJournalProtectionInfo info;
    YDRaftJournalApplicationEdge edges[YD_RAFT_CENSUS_ROOTS];
    YDRaftApplicationReference *references[YD_RAFT_CENSUS_ROOTS];
};
static bool same(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino;
}
static bool root_status(int fd, struct stat *s) {
    return fd >= 0 && !fstat(fd, s) && S_ISDIR(s->st_mode) && s->st_uid == geteuid() &&
        !(s->st_mode & (S_IWGRP | S_IWOTH));
}
static bool step(YDRaftJournalProtection *p, YDRaftJournalCensusProgress progress, void *context) {
    if (p->info.reasons & YD_RAFT_PROTECTION_CANCELLED) return false;
    if (progress && !progress(context)) {
        p->info.reasons |= YD_RAFT_PROTECTION_CANCELLED;
        return false;
    }
    return true;
}
YDRaftJournalProtection *yd_raft_journal_protection_take(YDRaftJournalCensus *census,
    int document_root, YDRaftJournalCensusProgress progress, void *context,
    char *error, size_t length) {
    YDRaftJournalProtection *p = calloc(1, sizeof(*p));
    if (!p) { yd_raft_journal_census_close(census); return NULL; }
    p->census = census;
    bool available = yd_raft_journal_census_info(census, &p->info.census) &&
        p->info.census.root_count <= YD_RAFT_CENSUS_ROOTS;
    if (!available || !p->info.census.metadata_complete) p->info.reasons |= YD_RAFT_PROTECTION_CENSUS;
    int root = document_root < 0 ? -1 : openat(document_root, ".",
        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    bool valid_root = root_status(root, &p->info.document_root) && available &&
        !same(&p->info.document_root, &p->info.census.root);
    if (!valid_root) p->info.reasons |= YD_RAFT_PROTECTION_ARGUMENT;
    if (available) for (size_t i = 0; i < p->info.census.root_count; i++) {
        YDRaftJournalCensusRoot captured;
        YDRaftJournalApplicationEdge *edge = &p->edges[i];
        edge->result = YD_RAFT_APPLICATION_REFERENCE_INVALID;
        if (!yd_raft_journal_census_root(census, i, &captured)) {
            p->info.reasons |= YD_RAFT_PROTECTION_CENSUS; continue;
        }
        if (captured.dependency.state == YD_RAFT_DEPENDENCY_UNKNOWN) {
            p->info.reasons |= YD_RAFT_PROTECTION_CENSUS; continue;
        }
        if (captured.dependency.state != YD_RAFT_DEPENDENCY_KNOWN) continue;
        edge->required = true; p->info.required++;
        if (!valid_root || !step(p, progress, context)) continue;
        edge->attempted = true;
        edge->result = yd_raft_application_reference_open(root, &captured.dependency.metadata,
            &p->references[i], error, length);
        if (edge->result == YD_RAFT_APPLICATION_REFERENCE_OK &&
            yd_raft_application_reference_info(p->references[i], &edge->application)) p->info.pinned++;
        else {
            p->info.reasons |= YD_RAFT_PROTECTION_APPLICATION;
            if (edge->result == YD_RAFT_APPLICATION_REFERENCE_BUSY) p->info.reasons |= YD_RAFT_PROTECTION_BUSY;
            if (edge->result == YD_RAFT_APPLICATION_REFERENCE_IO) p->info.reasons |= YD_RAFT_PROTECTION_IO;
        }
    }
    /* Last callback precedes ALL final binding checks. Partial observations
     * retain acquired protection; no input names are refreshed or adopted. */
    step(p, progress, context);
    if (valid_root) {
        struct stat after;
        if (!root_status(root, &after) || !same(&after, &p->info.document_root))
            p->info.reasons |= YD_RAFT_PROTECTION_CHANGED;
    }
    for (size_t i = 0; i < YD_RAFT_CENSUS_ROOTS; i++) if (p->references[i]) {
        p->edges[i].binding_validated = yd_raft_application_reference_validate(p->references[i]);
        if (!p->edges[i].binding_validated) p->info.reasons |= YD_RAFT_PROTECTION_CHANGED;
    }
    if (root >= 0) close(root);
    p->info.application_pins_complete = !p->info.reasons && p->info.required == p->info.pinned;
    if (error && length) {
        error[0] = 0;
        if (p->info.reasons) yd_disk_error(error, length, "partial journal application protection");
    }
    return p;
}
bool yd_raft_journal_protection_info(const YDRaftJournalProtection *p, YDRaftJournalProtectionInfo *out) {
    if (out) *out = (YDRaftJournalProtectionInfo){0};
    if (!p || !out) return false;
    *out = p->info; return true;
}
bool yd_raft_journal_protection_root(const YDRaftJournalProtection *p, size_t i,
    YDRaftJournalCensusRoot *root, YDRaftJournalApplicationEdge *edge) {
    if (root) *root = (YDRaftJournalCensusRoot){0};
    if (edge) *edge = (YDRaftJournalApplicationEdge){0};
    if (!p || !root || !edge || i >= p->info.census.root_count || i >= YD_RAFT_CENSUS_ROOTS ||
        !yd_raft_journal_census_root(p->census, i, root)) return false;
    *edge = p->edges[i]; return true;
}
void yd_raft_journal_protection_close(YDRaftJournalProtection *p) {
    if (!p) return;
    for (size_t i = 0; i < YD_RAFT_CENSUS_ROOTS; i++) yd_raft_application_reference_close(p->references[i]);
    yd_raft_journal_census_close(p->census); free(p);
}
