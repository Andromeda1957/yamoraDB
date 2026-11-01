#include "snapshot_receive.h"
#include "snapshot_store_internal.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
typedef enum { EMPTY, STAGING, PENDING, COMPLETE, FAILED } Phase;
_Static_assert(YD_RAFT_WIRE_MANIFEST == YD_RAFT_SNAPSHOT_MANIFEST, "snapshot manifest wire size");
struct YDRaftSnapshotReceiver {
    pthread_mutex_t lock;
    YDRaftSnapshotStore *store;
    YDRaftSnapshotStage *stage;
    YDRaftSnapshotReference *reference;
    YDRaftSnapshotReceiverHooks hooks;
    unsigned char cluster[16], manifest[YD_RAFT_SNAPSHOT_MANIFEST];
    unsigned local, voters;
    YDRaftSnapshotJob job;
    uint64_t received, end, reservation;
    Phase phase;
};
static bool nonzero(const unsigned char *bytes, size_t size) {
    unsigned char value = 0;
    for (size_t i = 0; i < size; i++) value |= bytes[i];
    return value != 0;
}
static bool same_offer(const YDRaftSnapshotOffer *a, const YDRaftSnapshotOffer *b) {
    return a->from == b->from && a->term == b->term && !memcmp(a->cluster, b->cluster, 16) &&
           a->base.index == b->base.index && a->base.term == b->base.term &&
           !memcmp(a->base.archive, b->base.archive, 32) && a->configuration == b->configuration &&
           a->configuration_delivery == b->configuration_delivery;
}
YDRaftSnapshotReceiver *yd_raft_snapshot_receiver_new(int directory,
    const unsigned char cluster[16], unsigned local, unsigned voters,
    YDRaftSnapshotReceiverHooks hooks, char *error, size_t length) {
    if (!local || local > voters || !hooks.contact || !hooks.confirmed ||
        (!!hooks.reserve != !!hooks.publication)) return NULL;
    YDRaftSnapshotReceiver *receiver = calloc(1, sizeof(*receiver));
    if (!receiver) return NULL;
    if (pthread_mutex_init(&receiver->lock, NULL)) { free(receiver); return NULL; }
    receiver->store = yd_raft_snapshot_store_open_at(directory, cluster, voters, error, length);
    if (!receiver->store) { pthread_mutex_destroy(&receiver->lock); free(receiver); return NULL; }
    receiver->hooks = hooks;
    receiver->local = local; receiver->voters = voters;
    memcpy(receiver->cluster, cluster, 16);
    return receiver;
}
void yd_raft_snapshot_receiver_close(YDRaftSnapshotReceiver *receiver) {
    if (!receiver) return;
    yd_raft_snapshot_stage_close(receiver->stage);
    yd_raft_snapshot_reference_close(receiver->reference);
    yd_raft_snapshot_store_close(receiver->store);
    pthread_mutex_destroy(&receiver->lock);
    free(receiver);
}
static bool contact(YDRaftSnapshotReceiver *r, const YDRaftSnapshotOffer *offer,
                       YDRaftSnapshotFrame *reply, bool *needed) {
    *needed = false;
    reply->term = 0;
    return r->hooks.contact(r->hooks.context, offer, needed, &reply->term) &&
        reply->term == offer->term;
}
static void begin(YDRaftSnapshotReceiver *r, const YDRaftPacket *request,
    const YDRaftSnapshotOffer *offer, YDRaftSnapshotFrame *reply, char *error, size_t length) {
    const YDRaftSnapshotFrame *frame = &request->body.snapshot;
    YDRaftSnapshotInfo info;
    unsigned char digest[32]; size_t size = 0;
    if (!yd_raft_snapshot_decode(frame->bytes, frame->size, r->cluster, r->voters, &info, error, length) ||
        info.applied.index != offer->base.index || info.applied.term != offer->base.term ||
        EVP_Q_digest(NULL, "SHA256", NULL, frame->bytes, frame->size, digest, &size) != 1 ||
        size != sizeof(digest) || memcmp(digest, offer->base.archive, sizeof(digest))) return;
    bool needed;
    if (!contact(r, offer, reply, &needed)) return;
    if (!needed) {
        if (r->hooks.confirmed(r->hooks.context, offer)) {
            reply->accepted = reply->installed = true;
            reply->offset = info.view.end;
        }
        return;
    }
    if (r->phase != EMPTY && r->phase != FAILED && same_offer(offer, &r->job.offer) &&
        !memcmp(frame->bytes, r->manifest, sizeof(r->manifest))) {
        reply->accepted = true;
        reply->offset = r->received;
        memcpy(reply->session, r->job.session, 16);
        return;
    }
    if (r->phase == PENDING) return;
    unsigned char session[16];
    if (RAND_bytes(session, sizeof(session)) != 1 || !nonzero(session, sizeof(session))) return;
    if (info.view.end > INT64_MAX - YD_RAFT_SNAPSHOT_MANIFEST) return;
    uint64_t reservation = info.view.end + YD_RAFT_SNAPSHOT_MANIFEST;
    if (r->hooks.reserve && !r->hooks.reserve(r->hooks.context, reservation)) return;
    YDRaftSnapshotStage *stage = r->hooks.reserve
        ? yd_raft_snapshot_stage_new_limited(r->store, frame->bytes, frame->size,
            reservation, NULL, error, length)
        : yd_raft_snapshot_stage_new(r->store, frame->bytes, frame->size, error, length);
    if (!stage) return;
    yd_raft_snapshot_stage_close(r->stage);
    yd_raft_snapshot_reference_close(r->reference);
    r->reference = NULL;
    r->stage = stage; r->received = 0; r->end = info.view.end; r->phase = STAGING;
    r->reservation = reservation;
    r->job.offer = *offer; memcpy(r->job.session, session, 16);
    memcpy(r->manifest, frame->bytes, sizeof(r->manifest));
    reply->accepted = true; memcpy(reply->session, session, 16);
}
static bool session_matches(YDRaftSnapshotReceiver *r, const YDRaftSnapshotOffer *offer,
                               const YDRaftSnapshotFrame *frame) {
    return r->phase != EMPTY && same_offer(offer, &r->job.offer) &&
        !memcmp(frame->session, r->job.session, 16);
}
static void chunk(YDRaftSnapshotReceiver *r, const YDRaftSnapshotFrame *frame,
    const YDRaftSnapshotOffer *offer, YDRaftSnapshotFrame *reply, char *error, size_t length) {
    if (r->phase != STAGING || !session_matches(r, offer, frame) || frame->size > r->end ||
        frame->offset > r->end - frame->size || frame->offset > r->received ||
        (frame->offset < r->received && frame->offset + frame->size > r->received)) return;
    bool needed;
    if (!contact(r, offer, reply, &needed) || !needed) return;
    if (frame->offset == r->received) {
        if (!yd_raft_snapshot_stage_feed(r->stage, frame->offset, frame->bytes, frame->size, error, length)) {
            r->phase = FAILED;
            return;
        }
        r->received += frame->size;
    }
    reply->accepted = true; reply->offset = r->received;
}
static void finish(YDRaftSnapshotReceiver *r, const YDRaftSnapshotFrame *frame,
    const YDRaftSnapshotOffer *offer, YDRaftSnapshotFrame *reply, YDRaftSnapshotJob *job,
    char *error, size_t length) {
    if (!session_matches(r, offer, frame) || r->phase == FAILED || frame->offset != r->end ||
        r->received != r->end) return;
    bool needed;
    if (!contact(r, offer, reply, &needed)) return;
    if (!needed) {
        if (r->hooks.confirmed(r->hooks.context, offer)) {
            reply->accepted = reply->installed = true; reply->offset = r->end;
        }
        return;
    }
    if (r->phase == STAGING) {
        char id[YD_RAFT_SNAPSHOT_ID];
        if (yd_raft_snapshot_stage_finish_retaining(r->stage, id, NULL, NULL,
            &r->reference, error, length) != YD_RAFT_ARCHIVE_OK) {
            r->phase = FAILED;
            return;
        }
        yd_raft_snapshot_stage_close(r->stage); r->stage = NULL;
        if (r->hooks.publication && !r->hooks.publication(r->hooks.context, offer,
                r->reservation, r->reference, error, length)) {
            r->phase = FAILED;
            return;
        }
        r->phase = PENDING; *job = r->job;
    }
    if (r->phase == PENDING) { reply->accepted = true; reply->offset = r->end; }
}
bool yd_raft_snapshot_receiver_handle(YDRaftSnapshotReceiver *r,
    const YDRaftPacket *request, YDRaftPacket *reply, YDRaftSnapshotJob *job,
    char *error, size_t length) {
    if (job) *job = (YDRaftSnapshotJob){0};
    if (reply) *reply = (YDRaftPacket){0};
    if (!r || !request || !reply || !job || (request->kind != YD_RPC_SNAPSHOT_BEGIN &&
        request->kind != YD_RPC_SNAPSHOT_CHUNK && request->kind != YD_RPC_SNAPSHOT_FINISH)) return false;
    unsigned char header[128]; YDRaftPacket checked;
    if (!yd_raft_wire_encode(request, header) ||
        !yd_raft_wire_decode(header, &checked, r->cluster, r->local, r->voters)) return false;
    const YDRaftSnapshotFrame *frame = &request->body.snapshot;
    YDRaftSnapshotOffer offer = {.from = request->from,
                                 .term = frame->term,
                                 .base = frame->base,
                                 .configuration = frame->configuration,
                                 .configuration_delivery = frame->configuration_delivery};
    memcpy(offer.cluster, r->cluster, 16);
    *reply =
        (YDRaftPacket){.kind = (YDRaftRPCKind)(request->kind + 1),
                       .from = r->local,
                       .to = request->from,
                       .body.snapshot = {.rpc = frame->rpc,
                                         .base = frame->base,
                                         .configuration = frame->configuration,
                                         .configuration_delivery = frame->configuration_delivery}};
    memcpy(reply->cluster, r->cluster, 16);
    memcpy(reply->body.snapshot.session, frame->session, 16);
    pthread_mutex_lock(&r->lock);
    if (request->kind == YD_RPC_SNAPSHOT_BEGIN) begin(r, request, &offer, &reply->body.snapshot, error, length);
    else if (request->kind == YD_RPC_SNAPSHOT_CHUNK) chunk(r, frame, &offer, &reply->body.snapshot, error, length);
    else finish(r, frame, &offer, &reply->body.snapshot, job, error, length);
    pthread_mutex_unlock(&r->lock);
    return true;
}
bool yd_raft_snapshot_receiver_complete(YDRaftSnapshotReceiver *r,
    const YDRaftSnapshotJob *job, bool reported_installed) {
    if (!r || !job) return false;
    pthread_mutex_lock(&r->lock);
    bool valid = r->phase == PENDING && same_offer(&r->job.offer, &job->offer) &&
        !memcmp(r->job.session, job->session, 16);
    if (valid) {
        r->phase = reported_installed && r->hooks.confirmed(r->hooks.context, &job->offer)
            ? COMPLETE : FAILED;
        yd_raft_snapshot_reference_close(r->reference);
        r->reference = NULL;
    }
    pthread_mutex_unlock(&r->lock);
    return valid;
}
bool yd_raft_snapshot_receiver_reference(YDRaftSnapshotReceiver *r,
    const YDRaftSnapshotJob *job, YDRaftSnapshotReference **reference, char *error, size_t length) {
    if (reference) *reference = NULL;
    if (!r || !job || !reference) return false;
    pthread_mutex_lock(&r->lock);
    bool valid = r->phase == PENDING && same_offer(&r->job.offer, &job->offer) &&
        !memcmp(r->job.session, job->session, sizeof(job->session)) &&
        yd_raft_snapshot_reference_clone(r->reference, reference, error, length) == YD_RAFT_ARCHIVE_OK;
    pthread_mutex_unlock(&r->lock);
    return valid;
}
