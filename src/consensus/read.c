#include "read.h"
#include <string.h>
uint64_t yd_raft_reads_issue(YDRaftReads *reads) {
    return reads->issued == UINT64_MAX ? 0 : ++reads->issued;
}
bool yd_raft_read_begin(const YDRaftReads *reads, YDRaft *raft, YDRaftRead *proof) {
    memset(proof, 0, sizeof(*proof));
    YDRaftStatus status = yd_raft_status(raft);
    if (status.role != YD_RAFT_LEADER)
        return false;
    *proof = (YDRaftRead){
        .term = status.term, .after = reads->issued, .node = status.node, .voters = status.voters,
        .membership = yd_raft_membership(raft)};
    return true;
}
void yd_raft_reads_observe(YDRaftReads *reads, uint64_t sequence, const YDRaftPacket *request,
                           const YDRaftPacket *reply) {
    if (!sequence || sequence > reads->issued || !request || !reply ||
        request->kind != YD_RPC_APPEND || request->body.append.configuration_delivery ||
        reply->kind != YD_RPC_APPENDED || !request->from || request->from > YD_RAFT_VOTERS ||
        !request->to || request->to > YD_RAFT_VOTERS || request->from == request->to ||
        reply->from != request->to || reply->to != request->from ||
        memcmp(request->cluster, reply->cluster, 16) || !request->body.append.term ||
        reply->body.appended.term != request->body.append.term || !request->body.append.rpc ||
        reply->body.appended.rpc != request->body.append.rpc || !reply->body.appended.accepted ||
        request->body.append.previous == UINT64_MAX ||
        reply->body.appended.matched !=
            request->body.append.previous + (request->body.append.has_entry ? 1U : 0U))
        return;
    if (sequence > reads->acknowledgements[reply->from]) {
        reads->acknowledgements[reply->from] = sequence;
        reads->terms[reply->from] = reply->body.appended.term;
    }
}
bool yd_raft_read_ready(const YDRaftReads *reads, const YDRaftRead *proof, YDRaft *raft,
                        uint64_t *index) {
    *index = 0;
    YDRaftStatus status = yd_raft_status(raft);
    YDRaftMembership membership = yd_raft_membership(raft);
    if (status.role != YD_RAFT_LEADER || status.term != proof->term || status.node != proof->node ||
        status.voters != proof->voters || proof->after > reads->issued ||
        membership.index != proof->membership.index ||
        membership.old_voters != proof->membership.old_voters ||
        membership.new_voters != proof->membership.new_voters)
        return false;
    uint16_t votes = (uint16_t)(1U << status.node);
    for (unsigned i = 1; i <= status.voters; i++)
        if (i != status.node && reads->acknowledgements[i] > proof->after &&
            reads->terms[i] == proof->term)
            votes |= (uint16_t)(1U << i);
    return yd_raft_quorum(raft, votes) && yd_raft_read_index(raft, index);
}
