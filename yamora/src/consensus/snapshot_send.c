#include "snapshot_send.h"
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static bool exchange(YDRaftSnapshotSendHooks hooks, const YDRaftPacket *request,
                        YDRaftPacket *reply, unsigned voters) {
    unsigned char header[128];
    YDRaftPacket decoded;
    memset(reply, 0, sizeof(*reply));
    return hooks.current(hooks.context) && hooks.exchange(hooks.context, request, reply) &&
        yd_raft_wire_encode(reply, header) &&
        yd_raft_wire_decode(header, &decoded, request->cluster, request->from, voters) &&
        yd_raft_wire_corresponds(request, reply);
}
static bool terminal(const YDRaftPacket *packet, YDRaftSnapshotReply *reply) {
    const YDRaftSnapshotFrame *frame = &packet->body.snapshot;
    if (frame->accepted && !frame->installed) return false;
    *reply = (YDRaftSnapshotReply){.term = frame->term, .rpc = frame->rpc,
        .installed = frame->installed};
    return true;
}
bool yd_raft_snapshot_send(const YDRaftSnapshotArchive *archive,
                             const YDRaftSnapshotRequest *request, unsigned voters,
                             size_t chunk_bytes, YDRaftSnapshotSendHooks hooks,
                             YDRaftSnapshotReply *reply, char *error, size_t length) {
    if (reply) memset(reply, 0, sizeof(*reply));
    if (error && length) error[0] = 0;
    if (!archive || !request || !reply || !chunk_bytes || chunk_bytes > YD_RAFT_WIRE_CHUNK ||
        !hooks.current || !hooks.exchange || !hooks.pause || !hooks.reserve || !hooks.release)
        goto failed;
    unsigned char manifest[YD_RAFT_SNAPSHOT_MANIFEST], digest[32], header[128];
    size_t digest_size;
    YDRaftSnapshotInfo info;
    YDRaftPacket packet = {.kind = YD_RPC_SNAPSHOT_BEGIN,
                           .from = request->offer.from,
                           .to = request->to,
                           .body.snapshot = {.term = request->offer.term,
                                             .rpc = request->rpc,
                                             .base = request->offer.base,
                                             .configuration = request->offer.configuration,
                                             .configuration_delivery =
                                                 request->offer.configuration_delivery,
                                             .bytes = manifest,
                                             .size = sizeof(manifest)}},
                 check, response;
    memcpy(packet.cluster, request->offer.cluster, 16);
    if (!yd_raft_snapshot_archive_manifest(archive, manifest) ||
        !yd_raft_snapshot_decode(manifest, sizeof(manifest), packet.cluster, voters,
                                   &info, error, length) ||
        EVP_Q_digest(NULL, "SHA256", NULL, manifest, sizeof(manifest), digest, &digest_size) != 1 ||
        digest_size != sizeof(digest) || memcmp(digest, request->offer.base.archive, sizeof(digest)) ||
        info.applied.index != request->offer.base.index || info.applied.term != request->offer.base.term ||
        !yd_raft_wire_encode(&packet, header) ||
        !yd_raft_wire_decode(header, &check, packet.cluster, packet.to, voters) ||
        !hooks.current(hooks.context) || !hooks.reserve(hooks.context, sizeof(manifest)))
        goto failed;
    bool valid = exchange(hooks, &packet, &response, voters);
    hooks.release(hooks.context, sizeof(manifest));
    if (!valid || (response.body.snapshot.accepted &&
        (response.body.snapshot.offset > info.view.end ||
         (response.body.snapshot.installed && response.body.snapshot.offset != info.view.end))))
        goto failed;
    if (terminal(&response, reply)) return true;
    memcpy(packet.body.snapshot.session, response.body.snapshot.session, 16);
    uint64_t at = response.body.snapshot.offset;
    while (at < info.view.end) {
        size_t count = info.view.end - at < chunk_bytes ? (size_t)(info.view.end - at) : chunk_bytes;
        if (!hooks.current(hooks.context) || !hooks.reserve(hooks.context, count)) goto failed;
        unsigned char *bytes = malloc(count);
        packet.kind = YD_RPC_SNAPSHOT_CHUNK;
        packet.body.snapshot.offset = at;
        packet.body.snapshot.bytes = bytes;
        packet.body.snapshot.size = count;
        valid = bytes && yd_raft_snapshot_archive_read(archive, at, bytes, count, error, length) &&
            exchange(hooks, &packet, &response, voters);
        free(bytes);
        packet.body.snapshot.bytes = NULL;
        hooks.release(hooks.context, count);
        if (!valid || (response.body.snapshot.accepted && response.body.snapshot.offset > info.view.end))
            goto failed;
        if (terminal(&response, reply)) return true;
        at = response.body.snapshot.offset;
    }
    packet.kind = YD_RPC_SNAPSHOT_FINISH;
    packet.body.snapshot.offset = info.view.end;
    packet.body.snapshot.bytes = NULL;
    packet.body.snapshot.size = 0;
    for (;;) {
        if (!exchange(hooks, &packet, &response, voters)) goto failed;
        if (terminal(&response, reply)) return true;
        if (!hooks.pause(hooks.context)) goto failed;
    }
failed:
    if (error && length && !error[0]) snprintf(error, length, "snapshot send failed or cancelled");
    return false;
}
