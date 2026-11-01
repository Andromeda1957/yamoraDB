#include "cluster_receive.h"
#include "cluster_internal.h"
#include "snapshot_receive.h"
#include "snapshot_store_internal.h"
#include <openssl/evp.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
struct YDRaftIncoming {
    YDRaftCluster *cluster;
    YDRaftSnapshotReceiver *receiver;
    pthread_mutex_t lock;
    pthread_cond_t wake;
    pthread_t worker;
    unsigned char identity[16];
    unsigned local, voters;
    uint32_t native_capabilities;
    bool stopping, started, busy, queued;
    YDRaftSnapshotJob job;
    YDRaftSnapshotReference *reference;
};
static bool contact(void *context, const YDRaftSnapshotOffer *offer, bool *needed, uint64_t *term) {
    YDRaftCluster *cluster = context;
    bool valid = yd_raft_cluster_snapshot_contact(cluster, offer, needed);
    YDRaftClusterStatus status = yd_raft_cluster_status(cluster);
    *term = status.raft.term;
    return valid && !status.failed && status.raft.role == YD_RAFT_FOLLOWER &&
        status.raft.leader == (offer->configuration_delivery ? 0 : offer->from);
}
static bool confirmed(void *context, const YDRaftSnapshotOffer *offer) {
    return yd_raft_cluster_snapshot_confirmed(context, offer);
}
static bool reserve(void *context, uint64_t bytes) {
    return yd_raft_cluster_archive_reserve(context, bytes);
}
static bool publication(void *context, const YDRaftSnapshotOffer *offer, uint64_t bytes,
    const YDRaftSnapshotReference *reference, char *error, size_t length) {
    return yd_raft_cluster_archive_publication(context, offer, bytes, reference, error, length);
}
static void *install(void *context) {
    (void)pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
    YDRaftIncoming *incoming = context;
    pthread_mutex_lock(&incoming->lock);
    for (;;) {
        while (!incoming->queued && !incoming->stopping)
            pthread_cond_wait(&incoming->wake, &incoming->lock);
        if (incoming->stopping) {
            if (incoming->queued) {
                (void)yd_raft_snapshot_receiver_complete(incoming->receiver, &incoming->job, false);
                yd_raft_snapshot_reference_close(incoming->reference);
                incoming->reference = NULL;
                incoming->job = (YDRaftSnapshotJob){0};
                incoming->busy = incoming->queued = false;
            }
            break;
        }
        YDRaftSnapshotJob job = incoming->job;
        YDRaftSnapshotReference *reference = incoming->reference;
        incoming->reference = NULL;
        incoming->queued = false;
        pthread_mutex_unlock(&incoming->lock);
        char error[512];
        bool installed = yd_raft_cluster_snapshot_job_reference(incoming->cluster, &job.offer,
            reference, 30000, error, sizeof(error));
        yd_raft_snapshot_reference_close(reference);
        pthread_mutex_lock(&incoming->lock);
        (void)yd_raft_snapshot_receiver_complete(incoming->receiver, &job, installed);
        incoming->busy = false;
        incoming->job = (YDRaftSnapshotJob){0};
    }
    pthread_mutex_unlock(&incoming->lock);
    return NULL;
}
YDRaftIncoming *yd_raft_incoming_new(YDRaftCluster *cluster, const unsigned char identity[16], unsigned local, unsigned voters) {
    if (!cluster || !identity || !local || local > voters || voters < 3 || voters > YD_RAFT_VOTERS || !(voters & 1)) return NULL;
    YDRaftIncoming *incoming = calloc(1, sizeof(*incoming));
    if (!incoming) return NULL;
    if (pthread_mutex_init(&incoming->lock, NULL)) { free(incoming); return NULL; }
    if (pthread_cond_init(&incoming->wake, NULL)) {
        pthread_mutex_destroy(&incoming->lock); free(incoming); return NULL;
    }
    incoming->cluster = cluster; incoming->local = local; incoming->voters = voters;
    incoming->native_capabilities = yd_raft_cluster_storage(cluster).view.capabilities;
    memcpy(incoming->identity, identity, 16);
    return incoming;
}
static bool begin_valid(YDRaftIncoming *incoming, const YDRaftPacket *request) {
    if (request->kind != YD_RPC_SNAPSHOT_BEGIN) return false;
    const YDRaftSnapshotFrame *frame = &request->body.snapshot;
    YDRaftSnapshotInfo info;
    unsigned char digest[32]; size_t size = 0; char error[256];
    return frame->size == YD_RAFT_SNAPSHOT_MANIFEST && frame->bytes &&
        yd_raft_snapshot_decode(frame->bytes, frame->size, incoming->identity, incoming->voters, &info, error, sizeof(error)) &&
        info.capabilities == incoming->native_capabilities &&
        info.applied.index == frame->base.index && info.applied.term == frame->base.term &&
        EVP_Q_digest(NULL, "SHA256", NULL, frame->bytes, frame->size, digest, &size) == 1 &&
        size == sizeof(digest) && !memcmp(digest, frame->base.archive, sizeof(digest));
}
bool yd_raft_incoming_handle(void *context, const YDRaftPacket *request, YDRaftPacket *reply) {
    YDRaftIncoming *incoming = context;
    if (!incoming || !request || !reply) return false;
    unsigned char header[128]; YDRaftPacket checked;
    if (!yd_raft_wire_encode(request, header) || !yd_raft_wire_decode(header, &checked,
        incoming->identity, incoming->local, incoming->voters)) return false;
    int archive_lease = -1;
    if (!yd_raft_cluster_archive_admit(incoming->cluster, &archive_lease)) return false;
    pthread_mutex_lock(&incoming->lock);
    if (incoming->stopping ||
        (request->kind == YD_RPC_SNAPSHOT_BEGIN && !begin_valid(incoming, request))) {
        pthread_mutex_unlock(&incoming->lock);
        if (archive_lease >= 0) close(archive_lease);
        return false;
    }
    char error[512];
    if (!incoming->receiver && begin_valid(incoming, request)) {
        int directory = yd_raft_cluster_snapshot_directory(incoming->cluster);
        YDRaftSnapshotReceiverHooks hooks = {.context = incoming->cluster, .contact = contact,
            .confirmed = confirmed, .reserve = reserve, .publication = publication};
        if (directory >= 0) {
            incoming->receiver = yd_raft_snapshot_receiver_new(directory, incoming->identity,
                incoming->local, incoming->voters, hooks, error, sizeof(error));
            close(directory);
        }
    }
    YDRaftSnapshotJob job;
    bool valid = incoming->receiver && yd_raft_snapshot_receiver_handle(incoming->receiver,
        request, reply, &job, error, sizeof(error));
    if (valid && job.offer.base.index) {
        YDRaftSnapshotReference *reference = NULL;
        if (!incoming->busy && yd_raft_snapshot_receiver_reference(incoming->receiver, &job,
            &reference, error, sizeof(error)) && (incoming->started ||
            !pthread_create(&incoming->worker, NULL, install, incoming))) {
            incoming->started = incoming->busy = incoming->queued = true;
            incoming->job = job;
            incoming->reference = reference;
            pthread_cond_signal(&incoming->wake);
        } else {
            yd_raft_snapshot_reference_close(reference);
            (void)yd_raft_snapshot_receiver_complete(incoming->receiver, &job, false);
            reply->body.snapshot.accepted = reply->body.snapshot.installed = false;
            reply->body.snapshot.offset = 0;
        }
    }
    pthread_mutex_unlock(&incoming->lock);
    if (archive_lease >= 0) close(archive_lease);
    return valid;
}
void yd_raft_incoming_shutdown(YDRaftIncoming *incoming) {
    if (!incoming) return;
    pthread_mutex_lock(&incoming->lock);
    incoming->stopping = true;
    pthread_cond_broadcast(&incoming->wake);
    bool join = incoming->started;
    pthread_mutex_unlock(&incoming->lock);
    if (join) {
        pthread_join(incoming->worker, NULL);
        pthread_mutex_lock(&incoming->lock); incoming->started = false; pthread_mutex_unlock(&incoming->lock);
    }
}
void yd_raft_incoming_close(YDRaftIncoming *incoming) {
    if (!incoming) return;
    yd_raft_incoming_shutdown(incoming);
    yd_raft_snapshot_receiver_close(incoming->receiver);
    pthread_cond_destroy(&incoming->wake);
    pthread_mutex_destroy(&incoming->lock);
    free(incoming);
}
