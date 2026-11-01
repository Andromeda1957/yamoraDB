#include "application_internal.h"
#include "../disk_bulk.h"
#include "../disk_internal.h"
#include "../disk_log.h"
#include "../disk_replica.h"
#include "replica.h"
#include "index_jobs.h"
#include "../sharding/service.h"
#include "../disk_history.h"
#include "../disk_branch_api.h"
#include "../schema/policy_admission.h"
#include <stdlib.h>
#include <string.h>

static bool same_view(const YDDiskView *a, const YDDiskView *b) {
    return a->format == b->format && a->capabilities == b->capabilities &&
           a->generation == b->generation && a->root == b->root &&
           a->end == b->end && a->documents == b->documents && a->collections == b->collections &&
           a->bytes == b->bytes && a->revision == b->revision;
}
static int order(const unsigned char *a, size_t an, const unsigned char *b, size_t bn) {
    int compared = memcmp(a, b, an < bn ? an : bn);
    return compared ? compared : (an > bn) - (an < bn);
}
static bool position(YDDisk *disk, const YDDiskView *view, uint64_t offset,
    const YDRaftCheckpoint *expected, YDRaftReceiptRetention *retention,
    char *error, size_t length) {
    size_t n = 0;
    unsigned char p[160];
    bool read = yd_disk_record_into(disk, view, offset, p, sizeof(p), &n, error, length);
    bool retained = read && n == 160 && !memcmp(p, "YDAPLY02", 8) &&
        yd_raft_receipt_state_decode(p + 96, retention) && retention->enabled;
    bool valid = read && ((n == 96 && !memcmp(p, "YDAPLY01", 8)) || retained) &&
                 !memcmp(p + 8, expected->cluster, 16) &&
                 yd_disk_u64(p + 24) == expected->applied.index &&
                 yd_disk_u64(p + 32) == expected->applied.term &&
                 yd_disk_u64(p + 40) == view->revision && !memcmp(p + 48, expected->digest, 32);
    for (size_t i = 80; valid && i < 96; i++)
        valid = p[i] == 0;
    return valid;
}
bool yd_raft_application_validate(YDRaftApplication *app, const YDRaftCheckpoint *expected,
                                   const YDDiskView *view, char *error, size_t length) {
    return yd_raft_application_validate_cancellable(app, expected, view, NULL, error, length);
}
bool yd_raft_application_validate_cancellable(YDRaftApplication *app,
    const YDRaftCheckpoint *expected, const YDDiskView *view, YDDiskValidation *state,
    char *error, size_t length) {
    if (!yd_disk_validation_step(state, YD_VALIDATE_APPLICATION))
        return yd_disk_error(error, length, "application validation cancelled");
    YDRaftCheckpoint actual;
    YDDiskCheckpoint *image = expected && view
        ? yd_raft_application_checkpoint(app, &actual, error, length) : NULL;
    if (!image)
        return yd_disk_error(error, length, "staged consensus application unavailable");
    YDDiskView captured = yd_disk_checkpoint_view(image);
    yd_disk_checkpoint_close(image);
    if (!same_view(&captured, view) || memcmp(actual.cluster, expected->cluster, 16) ||
        memcmp(actual.digest, expected->digest, 32) || actual.applied.index != expected->applied.index ||
        actual.applied.term != expected->applied.term)
        return yd_disk_error(error, length, "staged consensus application metadata mismatch");
    return yd_raft_application_validate_at_cancellable(yd_raft_application_disk(app), expected, view,
                                                       state, error, length);
}
bool yd_raft_application_validate_at(YDDisk *disk, const YDRaftCheckpoint *expected,
                                       const YDDiskView *view, char *error, size_t length) {
    return yd_raft_application_validate_at_cancellable(disk, expected, view, NULL, error, length);
}
bool yd_raft_application_validate_at_cancellable(YDDisk *disk, const YDRaftCheckpoint *expected,
    const YDDiskView *view, YDDiskValidation *state, char *error, size_t length) {
    if (!yd_disk_validation_step(state, YD_VALIDATE_APPLICATION))
        return yd_disk_error(error, length, "application validation cancelled");
    if (!disk || !expected || !view)
        return yd_disk_error(error, length, "captured consensus application unavailable");
    YDDiskReplicaPolicyState policies = yd_disk_replica_policy_state(disk, view, error, length);
    bool schema = view->format == 8 && (view->capabilities & YD_DISK_CAP_SCHEMA) &&
        view->capabilities == yd_disk_capabilities(disk);
    if (!schema && policies != YD_REPLICA_POLICY_FREE)
        return yd_disk_error(error, length, policies == YD_REPLICA_POLICY_ERROR ?
            "consensus policy state unavailable" : "schema-policy consensus application unsupported");
    unsigned char cluster = 0, digest = 0;
    for (unsigned i = 0; i < sizeof(expected->cluster); i++) cluster |= expected->cluster[i];
    for (unsigned i = 0; i < sizeof(expected->digest); i++) digest |= expected->digest[i];
    bool compatible = expected->capabilities ? view->format == 8 &&
        view->capabilities == expected->capabilities &&
        view->capabilities == yd_disk_capabilities(disk) &&
        (view->capabilities & YD_DISK_CAP_CLUSTER) &&
        !(view->capabilities & ~YD_DISK_CAP_SUPPORTED) : view->format == 6 && !view->capabilities;
    if (!cluster || !compatible || expected->applied.index > UINT64_MAX - 2 ||
        view->generation != expected->applied.index + 2 || view->end < 3U * YD_DISK_PAGE ||
        view->end > INT64_MAX || view->end % YD_DISK_PAGE || view->root < 2U * YD_DISK_PAGE ||
        view->root % YD_DISK_PAGE || view->root > view->end - YD_DISK_PAGE ||
        (expected->applied.index ? !expected->applied.term || !digest :
            expected->applied.term || digest || view->revision || view->documents ||
            view->collections || view->bytes))
        return yd_disk_error(error, length, "invalid captured consensus metadata");
    YDDiskLog log;
    int logged = yd_disk_log_load(disk, view, &log, error, length);
    bool valid = expected->applied.index
        ? logged == 1 && !memcmp(log.identity, expected->cluster, 16) && log.last == view->generation
        : logged == 0;
    unsigned char key[YD_DISK_KEY_LIMIT], previous[YD_DISK_KEY_LIMIT];
    size_t size = 0, prior = 0;
    uint64_t value = 0, receipts = 0, all_receipts = 0, receipt_bytes = 0, frames = 0;
    YDRaftReceiptRetention retention = {0};
    unsigned positions = 0, metadata = 0;
    YDDiskCursor *cursor = valid ? yd_disk_cursor(disk, view, NULL, 0, false, error, length) : NULL;
    valid = valid && cursor;
    int next = 0;
    while (valid && (next = yd_disk_next(cursor, key, sizeof(key), &size, &value, error, length)) == 1) {
        if (!yd_disk_validation_step(state, YD_VALIDATE_APPLICATION)) {
            valid = false;
            break;
        }
        uint64_t reachable = 0;
        valid = (!prior || order(previous, prior, key, size) < 0) &&
                yd_disk_get(disk, view, key, size, &reachable, error, length) == 1 && reachable == value;
        if (!valid)
            break;
        memcpy(previous, key, size);
        prior = size;
        if (size == 4 && !memcmp(key, "\0YRA", 4)) {
            positions++;
            valid = position(disk, view, value, expected, &retention, error, length);
        } else if (size == 20 && (!memcmp(key, "\0YRR", 4) || !memcmp(key, "\0YRI", 4))) {
            bool internal = !memcmp(key, "\0YRI", 4);
            size_t n = 0;
            unsigned char p[88U + 2048U];
            YDDiskReply reply = {0};
            uint64_t epoch = 0;
            valid = yd_disk_record_into(disk, view, value, p, sizeof(p), &n, error, length) &&
                yd_raft_receipt_decode_epoch(p, n, key + 4, expected->applied, &epoch, &reply) &&
                (internal ? !epoch : retention.enabled ?
                    (retention.pruning ? epoch < retention.epoch : epoch == retention.epoch) : !epoch);
            yd_disk_reply_free(&reply);
            if (all_receipts >= expected->applied.index)
                valid = false;
            else
                all_receipts++;
            if (!internal) receipts++;
            if (valid && !internal && retention.enabled) {
                valid = receipts <= retention.maximum_count &&
                    n <= retention.maximum_bytes - receipt_bytes;
                if (valid) receipt_bytes += n;
            }
        } else if ((size == 4 || size == 20) && !memcmp(key, "\0YRJ", 4)) {
            size_t n = 0;
            unsigned char *p = yd_disk_record(disk, view, value, &n, error, length);
            valid = yd_raft_index_job_validate_record(key, size, p, n,
                expected->cluster, view->generation);
            free(p);
        } else if (yd_shard_service_key(key, size)) {
            size_t n = 0;
            unsigned char *p = yd_disk_record(disk, view, value, &n, error, length);
            valid = yd_shard_service_key(key, size) == 1 &&
                yd_shard_service_validate(key, size, p, n);
            free(p);
        } else if (size >= 4 && (!memcmp(key, "\0YRD", 4) || !memcmp(key, "\0YRS", 4) ||
                                !memcmp(key, "\0YRO", 4) || !memcmp(key, "\0YRP", 4))) {
            valid = yd_raft_replica_key(disk, view, key, size, value, error, length) == 1;
        } else if (size == 4 && !memcmp(key, "\0YLM", 4)) {
            metadata++;
            valid = logged == 1;
        } else if (size == 12 && !memcmp(key, "\0YLF", 4)) {
            uint64_t sequence = 0;
            for (size_t i = 4; i < 12; i++)
                sequence = (sequence << 8) | key[i];
            valid = logged == 1 && sequence > log.floor && sequence <= log.last && frames < log.count;
            if (valid)
                frames++;
        } else if (size == YD_POLICY_RECEIPT_KEY_SIZE && !memcmp(key, "\0YSP", 4)) {
            valid = schema;
        } else if ((size == 4 && !memcmp(key, "\0YBH", 4)) ||
                   (size == 20 && !memcmp(key, "\0YBR", 4))) {
            valid = (view->capabilities & YD_DISK_CAP_HISTORY) != 0;
        } else if (key[0] != 'C' && key[0] != 'D' && key[0] != 'I' && key[0] != 'U')
            valid = false;
    }
    yd_disk_cursor_free(cursor);
    valid = valid && next == 0 && positions == 1 && metadata == (unsigned)(logged == 1) &&
            frames == (logged == 1 ? log.count : 0) &&
            (!retention.enabled || (receipts == retention.count && receipt_bytes == retention.bytes));
    if (valid)
        valid = yd_raft_replica_validate(disk, view, error, length);
    if (valid)
        valid = yd_disk_validate_cancellable(disk, view, state, error, length);
    if (valid)
        valid = yd_disk_history_validate(disk, view, state, error, length);
    if (valid && schema) {
        YDPolicyWork work;
        yd_policy_work_init(&work, true);
        valid = yd_disk_validation_step(state, YD_VALIDATE_APPLICATION) &&
            yd_policy_validate_view_cancellable(disk, view, &work, state, error, length) == YD_POLICY_OK;
    }
    return valid || yd_disk_error(error, length, "invalid staged consensus application");
}
