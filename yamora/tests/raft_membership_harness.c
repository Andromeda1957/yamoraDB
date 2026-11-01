#define _POSIX_C_SOURCE 200809L
#include "../src/consensus/install.h"
#include "../src/consensus/journal_copy.h"
#include "../src/consensus/member.h"
#include "../src/consensus/raft_internal.h"
#include "../src/consensus/read.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"line %u: %s (%s)\n",__LINE__,#x, \
    nodes[0] ? yd_raft_error(nodes[0]) : "closed"); return 2; } } while (0)
static const unsigned char cluster[16] = {1,2,3,4};
static bool send(YDRaft *leader, YDRaft *follower, unsigned id) {
    YDRaftAppend a; YDRaftAppendReply b;
    if (!yd_raft_append_request(leader,id,&a)) return false;
    bool ok = yd_raft_append(follower,&a,&b) && yd_raft_append_reply(leader,id,&b);
    yd_raft_append_free(&a); return ok;
}
static bool catchup(YDRaft *leader,YDRaft *follower,unsigned id) {
    for (unsigned n=0;n<100;n++) {
        if (!send(leader,follower,id)) return false;
        if (yd_raft_status(follower).last == yd_raft_status(leader).last &&
            yd_raft_status(follower).committed == yd_raft_status(leader).committed) return true;
    }
    return false;
}
static bool vote(YDRaft *candidate,YDRaft *voter,unsigned id,const YDRaftVote *request) {
    YDRaftVoteReply reply;
    return yd_raft_vote(voter,request,&reply) &&
        yd_raft_vote_reply(candidate,id,request->term,&reply);
}
static int delivery_recovery(const char *root) {
    YDRaft *nodes[5] = {0};
    char paths[5][4096], error[256];
    for (unsigned i = 0; i < 5; i++) {
        snprintf(paths[i], sizeof(paths[i]), "%s/recovery%u", root, i + 1);
        CHECK(!mkdir(paths[i], 0700));
        nodes[i] = yd_raft_open(paths[i], cluster, i + 1, 5, 32768, error, sizeof(error));
        CHECK(nodes[i] && yd_raft_membership_bootstrap(nodes[i], 14));
    }
    YDRaftVote election;
    uint64_t joint, index;
    CHECK(yd_raft_campaign(nodes[0], &election));
    CHECK(vote(nodes[0], nodes[1], 2, &election));
    for (unsigned i = 1; i < 5; i++)
        CHECK(catchup(nodes[0], nodes[i], i + 1));
    CHECK(yd_raft_reconfigure(nodes[0], 56, &joint));
    CHECK(send(nodes[0], nodes[1], 2)); /* joint durable on an old majority only */
    yd_raft_close(nodes[0]);
    nodes[0] = NULL;
    yd_raft_close(nodes[1]);
    nodes[1] = yd_raft_open(paths[1], cluster, 2, 5, 32768, error, sizeof(error));
    CHECK(nodes[1] && yd_raft_campaign(nodes[1], &election));
    CHECK(vote(nodes[1], nodes[2], 3, &election));
    CHECK(vote(nodes[1], nodes[3], 4, &election));
    CHECK(yd_raft_status(nodes[1]).role == YD_RAFT_CANDIDATE);
    CHECK(!yd_raft_campaign(nodes[3], &election));
    YDRaftAppend delivery;
    YDRaftAppendReply reply;
    CHECK(yd_raft_configuration_delivery(nodes[1], 4, &delivery));
    CHECK(delivery.configuration_delivery && delivery.entry.index == joint);
    uint64_t committed = yd_raft_status(nodes[3]).committed;
    YDRaftAppend invalid;
    CHECK(!yd_raft_configuration_delivery(nodes[4], 4,
                                          &invalid)); /* learner has no delivery authority */
    delivery.committed = joint;
    CHECK(!yd_raft_append(nodes[3], &delivery, &reply)); /* delivery carries no commit authority */
    delivery.committed = 0;
    CHECK(yd_raft_append(nodes[3], &delivery, &reply) && reply.accepted);
    CHECK(yd_raft_status(nodes[3]).committed == committed && !yd_raft_status(nodes[3]).leader);
    YDRaftReads reads = {.issued = 1};
    YDRaftPacket packet = {.from = 2, .to = 4, .kind = YD_RPC_APPEND, .body.append = delivery};
    YDRaftPacket response = {.from = 4, .to = 2, .kind = YD_RPC_APPENDED, .body.appended = reply};
    memcpy(packet.cluster, cluster, 16);
    memcpy(response.cluster, cluster, 16);
    yd_raft_reads_observe(&reads, 1, &packet, &response);
    CHECK(!reads.acknowledgements[4]);
    CHECK(!yd_raft_read_index(nodes[1], &index) && !yd_raft_propose(nodes[1], "x", 1, &index));
    /* Receipt is durable; restart the promoted learner before its first vote. */
    yd_raft_close(nodes[3]);
    nodes[3] = yd_raft_open(paths[3], cluster, 4, 5, 32768, error, sizeof(error));
    CHECK(nodes[3] && yd_raft_membership(nodes[3]).joint);
    /* Reissue the same candidate's vote after its configuration delivery. */
    CHECK(yd_raft_campaign(nodes[1], &election));
    CHECK(vote(nodes[1], nodes[2], 3, &election));
    CHECK(vote(nodes[1], nodes[3], 4, &election));
    CHECK(yd_raft_status(nodes[1]).role == YD_RAFT_LEADER);
    /* Delayed candidate delivery must not depose a same-term elected voter. */
    delivery.from = 3;
    delivery.term = yd_raft_status(nodes[1]).term;
    CHECK(yd_raft_append(nodes[1], &delivery, &reply) && !reply.accepted);
    CHECK(yd_raft_status(nodes[1]).role == YD_RAFT_LEADER);
    delivery.term += 10;
    CHECK(yd_raft_append(nodes[1], &delivery, &reply) && !reply.accepted);
    CHECK(yd_raft_status(nodes[1]).role == YD_RAFT_LEADER &&
          yd_raft_status(nodes[1]).term == election.term);
    yd_raft_append_free(&delivery);
    CHECK(catchup(nodes[1], nodes[2], 3) && catchup(nodes[1], nodes[3], 4));
    CHECK(yd_raft_status(nodes[1]).committed >= joint);
    CHECK(yd_raft_reconfigure_advance(nodes[1]));
    uint64_t final = yd_raft_status(nodes[1]).last;
    CHECK(send(nodes[1], nodes[2], 3)); /* durable final enables the new election quorum */
    CHECK(yd_raft_status(nodes[1]).committed < final);
    yd_raft_close(nodes[1]);
    nodes[1] = NULL;
    nodes[0] = yd_raft_open(paths[0], cluster, 1, 5, 32768, error, sizeof(error));
    CHECK(nodes[0] && yd_raft_campaign(nodes[2], &election));
    CHECK(vote(nodes[2], nodes[0], 1, &election));
    CHECK(yd_raft_status(nodes[2]).role == YD_RAFT_CANDIDATE);
    CHECK(vote(nodes[2], nodes[3], 4, &election));
    CHECK(yd_raft_status(nodes[2]).role == YD_RAFT_LEADER);
    CHECK(catchup(nodes[2], nodes[0], 1) && catchup(nodes[2], nodes[3], 4));
    CHECK(yd_raft_status(nodes[2]).committed >= final && !yd_raft_membership(nodes[2]).joint);
    for (unsigned i = 0; i < 5; i++)
        yd_raft_close(nodes[i]);
    return 0;
}
static int disjoint_recovery(const char *root) {
    YDRaft *nodes[7] = {0};
    char paths[7][4096], error[256];
    for (unsigned i = 0; i < 7; i++) {
        snprintf(paths[i], sizeof(paths[i]), "%s/disjoint%u", root, i + 1);
        CHECK(!mkdir(paths[i], 0700));
        nodes[i] = yd_raft_open(paths[i], cluster, i + 1, 7, 32768, error, sizeof(error));
        CHECK(nodes[i] && yd_raft_membership_bootstrap(nodes[i], 14));
    }
    YDRaftVote election;
    uint64_t joint, suffix;
    CHECK(yd_raft_campaign(nodes[0], &election) && vote(nodes[0], nodes[1], 2, &election));
    for (unsigned i = 1; i < 7; i++)
        CHECK(catchup(nodes[0], nodes[i], i + 1));
    CHECK(yd_raft_reconfigure(nodes[0], 112, &joint)); /* wholly disjoint voter sets */
    CHECK(send(nodes[0], nodes[1], 2) && send(nodes[0], nodes[3], 4));
    CHECK(yd_raft_status(nodes[0]).committed < joint);
    CHECK(yd_raft_propose(nodes[0], "newest-suffix", 13, &suffix));
    CHECK(send(nodes[0], nodes[3], 4));
    yd_raft_close(nodes[0]);
    nodes[0] = NULL;
    CHECK(yd_raft_campaign(nodes[3], &election));
    CHECK(vote(nodes[3], nodes[1], 2, &election) && vote(nodes[3], nodes[2], 3, &election));
    CHECK(yd_raft_status(nodes[3]).role == YD_RAFT_CANDIDATE);
    YDRaftAppend delivery;
    YDRaftAppendReply reply;
    /* The newest candidate is newly promoted. It must repair both a missing
     * old voter and a learner; neither may replace either quorum requirement. */
    for (unsigned i = 2; i <= 4; i += 2) {
        CHECK(yd_raft_configuration_delivery(nodes[3], i + 1, &delivery));
        CHECK(yd_raft_append(nodes[i], &delivery, &reply) && reply.accepted);
        yd_raft_append_free(&delivery);
        CHECK(vote(nodes[3], nodes[i], i + 1, &election));
    }
    CHECK(yd_raft_status(nodes[3]).role == YD_RAFT_LEADER);
    CHECK(catchup(nodes[3], nodes[1], 2) && catchup(nodes[3], nodes[2], 3) &&
          catchup(nodes[3], nodes[4], 5));
    CHECK(yd_raft_status(nodes[3]).committed >= suffix);
    YDRaftEntry entry;
    CHECK(yd_raft_entry(nodes[3], suffix, &entry));
    CHECK(entry.size == 13 && !memcmp(entry.command, "newest-suffix", 13));
    yd_raft_entry_free(&entry);
    for (unsigned i = 0; i < 7; i++)
        yd_raft_close(nodes[i]);
    return 0;
}
static bool hold_final(void *context, const YDRaftPacket *packet) {
    if (packet->to != 4 || packet->kind != YD_RPC_APPEND)
        return false;
    *(YDRaftPacket *)context = *packet;
    return true;
}
static int passive_final_recovery(const char *root, bool compact) {
    YDRaft *nodes[7] = {0};
    char paths[7][4096], error[256];
    for (unsigned i = 0; i < 7; i++) {
        snprintf(paths[i], sizeof(paths[i]), "%s/passive%u-%u", root, compact, i + 1);
        CHECK(!mkdir(paths[i], 0700));
        nodes[i] = yd_raft_open(paths[i], cluster, i + 1, 7, 32768, error, sizeof(error));
        CHECK(nodes[i] && yd_raft_membership_bootstrap(nodes[i], 14));
    }
    YDRaftVote election;
    uint64_t joint;
    CHECK(yd_raft_campaign(nodes[0], &election) && vote(nodes[0], nodes[1], 2, &election));
    for (unsigned i = 1; i < 7; i++)
        CHECK(catchup(nodes[0], nodes[i], i + 1));
    CHECK(yd_raft_reconfigure(nodes[0], 112, &joint));
    CHECK(send(nodes[0], nodes[1], 2) && send(nodes[0], nodes[4], 5) &&
          send(nodes[0], nodes[5], 6));
    CHECK(yd_raft_status(nodes[0]).committed == joint);
    CHECK(catchup(nodes[0], nodes[1], 2) && catchup(nodes[0], nodes[4], 5));
    if (!compact)
        CHECK(catchup(nodes[0], nodes[3], 4));
    uint64_t gap;
    CHECK(yd_raft_propose(nodes[0], "intervening", 11, &gap));
    CHECK(yd_raft_reconfigure_advance(nodes[0]));
    uint64_t final = yd_raft_status(nodes[0]).last;
    CHECK(send(nodes[0], nodes[1], 2) && send(nodes[0], nodes[1], 2)); /* gap, then final */
    CHECK(yd_raft_status(nodes[0]).role == YD_RAFT_LEADER &&
          yd_raft_status(nodes[0]).committed < final);
    yd_raft_close(nodes[0]);
    nodes[0] = NULL;
    if (compact) {
        YDRaftSnapshotBase base = {.index = joint, .term = 1, .archive = {11}};
        CHECK(yd_raft_checkpoint(nodes[1], &base));
    }
    yd_raft_close(nodes[1]);
    nodes[1] = yd_raft_open(paths[1], cluster, 2, 7, 32768, error, sizeof(error));
    CHECK(nodes[1] && !yd_raft_campaign(nodes[1], &election));
    YDRaftMember *member =
        yd_raft_member_new(nodes[1], cluster, 0, 1, (YDRaftTiming){50, 1000, 2000, 400});
    CHECK(member);
    bool installed = false;
    for (unsigned attempt = 0; attempt < 20 && yd_raft_membership(nodes[3]).index != final;
         attempt++) {
        YDRaftPacket packet = {0};
        uint64_t now = 1 + attempt * 100;
        CHECK(yd_raft_member_tick(member, now, hold_final, &packet));
        if (packet.kind) {
            CHECK(packet.kind == YD_RPC_APPEND && packet.body.append.configuration_delivery);
            YDRaftPacket reply = {.kind = YD_RPC_APPENDED, .from = 4, .to = 2};
            memcpy(reply.cluster, cluster, 16);
            CHECK(yd_raft_append(nodes[3], &packet.body.append, &reply.body.appended));
            CHECK(yd_raft_member_done(member, now, &packet, &reply));
            yd_raft_member_packet_free(&packet);
        } else if (yd_raft_snapshot_required(nodes[1], 4)) {
            YDRaftSnapshotRequest request;
            bool needed;
            CHECK(yd_raft_snapshot_request(nodes[1], 4, &request));
            CHECK(request.offer.configuration_delivery &&
                  yd_raft_snapshot_source_current(nodes[1], &request));
            CHECK(yd_raft_snapshot_contact(nodes[3], &request.offer, &needed) && needed);
            CHECK(!yd_raft_status(nodes[3]).leader &&
                  yd_raft_snapshot_install(nodes[3], &request.offer));
            YDRaftSnapshotReply reply = {
                .term = request.offer.term, .rpc = request.rpc, .installed = true};
            CHECK(yd_raft_snapshot_reply(nodes[1], 4, &reply));
            CHECK(!yd_raft_snapshot_source_current(nodes[1], &request));
            installed = true;
        }
    }
    CHECK(installed == compact);
    CHECK(yd_raft_status(nodes[3]).committed == joint && !yd_raft_membership(nodes[3]).joint);
    yd_raft_member_free(member);
    CHECK(yd_raft_campaign(nodes[3], &election) && vote(nodes[3], nodes[4], 5, &election));
    CHECK(yd_raft_status(nodes[3]).role == YD_RAFT_LEADER);
    CHECK(catchup(nodes[3], nodes[4], 5) && yd_raft_status(nodes[3]).committed >= final);
    CHECK(!yd_raft_campaign(nodes[1], &election));
    for (unsigned i = 0; i < 7; i++)
        yd_raft_close(nodes[i]);
    return 0;
}
int main(int argc,char **argv) {
    if (argc != 2) return 3;
    if (delivery_recovery(argv[1]))
        return 2;
    if (disjoint_recovery(argv[1]))
        return 2;
    if (passive_final_recovery(argv[1], false) || passive_final_recovery(argv[1], true))
        return 2;
    YDRaft *nodes[5] = {0}; char paths[5][4096],error[256];
    for (unsigned i=0;i<5;i++) {
        snprintf(paths[i],sizeof(paths[i]),"%s/node%u",argv[1],i+1);
        CHECK(!mkdir(paths[i],0700));
        nodes[i]=yd_raft_open(paths[i],cluster,i+1,5,32768,error,sizeof(error));
        CHECK(nodes[i] && yd_raft_membership_bootstrap(nodes[i],14));
    }
    YDRaftVote request;
    CHECK(!yd_raft_campaign(nodes[3],&request)); /* learner cannot disrupt terms */
    CHECK(yd_raft_campaign(nodes[0],&request));
    CHECK(vote(nodes[0],nodes[1],2,&request));
    CHECK(yd_raft_status(nodes[0]).role==YD_RAFT_LEADER);
    CHECK(catchup(nodes[0],nodes[1],2));
    uint64_t joint;
    CHECK(!yd_raft_reconfigure(nodes[0],56,&joint)); /* learners not caught up */
    CHECK(catchup(nodes[0],nodes[2],3));
    CHECK(catchup(nodes[0],nodes[3],4));
    CHECK(catchup(nodes[0],nodes[4],5));
    CHECK(yd_raft_reconfigure(nodes[0],56,&joint));
    CHECK(yd_raft_membership(nodes[0]).joint);
    CHECK(!yd_raft_quorum(nodes[0],6)); /* old majority alone */
    CHECK(!yd_raft_quorum(nodes[0],48)); /* new majority alone */
    CHECK(yd_raft_quorum(nodes[0],26)); /* 1,3,4 covers both */
    CHECK(send(nodes[0],nodes[1],2));
    CHECK(yd_raft_status(nodes[0]).committed < joint);
    CHECK(send(nodes[0],nodes[2],3));
    CHECK(yd_raft_status(nodes[0]).committed < joint);
    CHECK(send(nodes[0],nodes[3],4));
    CHECK(yd_raft_status(nodes[0]).committed == joint);
    for (unsigned i=1;i<5;i++) CHECK(catchup(nodes[0],nodes[i],i+1));
    char copy_path[4096];
    snprintf(copy_path, sizeof(copy_path), "%s/copy", argv[1]);
    CHECK(!mkdir(copy_path, 0700));
    int copy_fd = open(copy_path, O_RDONLY | O_DIRECTORY);
    YDRaftJournalCapture *capture = yd_raft_journal_capture(nodes[2], 32768, error, sizeof(error));
    CHECK(copy_fd >= 0 && capture);
    YDRaftJournalImage *image =
        yd_raft_journal_copy(capture, copy_fd, 32768, NULL, NULL, error, sizeof(error));
    CHECK(image && yd_raft_journal_image_current(image, nodes[2]));
    yd_raft_journal_capture_close(capture);
    /* Fresh read proof requires BOTH majorities, and pre-change proofs cannot
     * cross a configuration boundary, even within the same leader term. */
    YDRaftReads reads={0}; YDRaftRead proof;
    CHECK(yd_raft_read_begin(&reads,nodes[0],&proof));
    reads.issued=1;
    reads.acknowledgements[2]=1;reads.terms[2]=proof.term;
    uint64_t read_index;
    CHECK(!yd_raft_read_ready(&reads,&proof,nodes[0],&read_index));
    reads.acknowledgements[3]=1;reads.terms[3]=proof.term;
    CHECK(!yd_raft_read_ready(&reads,&proof,nodes[0],&read_index));
    reads.acknowledgements[4]=1;reads.terms[4]=proof.term;
    CHECK(yd_raft_read_ready(&reads,&proof,nodes[0],&read_index));
    /* Restart during the joint phase, checkpoint it, restart again. */
    yd_raft_close(nodes[0]);nodes[0]=yd_raft_open(paths[0],cluster,1,5,32768,error,sizeof(error));
    CHECK(nodes[0] && yd_raft_membership(nodes[0]).joint);
    YDRaftSnapshotBase base={.index=joint,.term=1,.archive={9}};
    CHECK(yd_raft_checkpoint(nodes[0],&base));
    yd_raft_close(nodes[0]);nodes[0]=yd_raft_open(paths[0],cluster,1,5,32768,error,sizeof(error));
    CHECK(nodes[0] && yd_raft_membership(nodes[0]).joint);
    CHECK(yd_raft_campaign(nodes[2],&request));
    CHECK(vote(nodes[2],nodes[0],1,&request));
    CHECK(yd_raft_status(nodes[2]).role==YD_RAFT_CANDIDATE); /* election old only */
    CHECK(vote(nodes[2],nodes[3],4,&request));
    CHECK(yd_raft_status(nodes[2]).role==YD_RAFT_LEADER);
    CHECK(catchup(nodes[2],nodes[0],1));
    CHECK(catchup(nodes[2],nodes[3],4));
    CHECK(yd_raft_reconfigure_advance(nodes[2]));
    uint64_t final=yd_raft_status(nodes[2]).last;
    CHECK(final > joint && !yd_raft_membership(nodes[2]).joint);
    CHECK(catchup(nodes[2],nodes[0],1));
    CHECK(yd_raft_status(nodes[2]).committed <
          final); /* old acknowledgements do not commit final */
    CHECK(catchup(nodes[2],nodes[3],4));
    CHECK(!yd_raft_membership(nodes[2]).joint && yd_raft_membership(nodes[2]).new_voters==56);
    CHECK(catchup(nodes[2],nodes[0],1));
    CHECK(!yd_raft_campaign(nodes[0],&request));
    CHECK(!yd_raft_reconfigure(nodes[2],14,&joint)); /* retired identity is fenced */
    CHECK(yd_raft_membership(nodes[2]).retired_voters==6);
    base=(YDRaftSnapshotBase){.index=final,.term=yd_raft_status(nodes[2]).term,.archive={7}};
    CHECK(yd_raft_checkpoint(nodes[2],&base));
    yd_raft_close(nodes[2]);nodes[2]=yd_raft_open(paths[2],cluster,3,5,32768,error,sizeof(error));
    CHECK(nodes[2] && yd_raft_membership(nodes[2]).new_voters==56 &&
        yd_raft_membership(nodes[2]).retired_voters==6);
    capture = yd_raft_journal_capture(nodes[2], 32768, error, sizeof(error));
    CHECK(capture && yd_raft_journal_catch_up(image, capture, NULL, NULL, error, sizeof(error)));
    YDRaft copied = {.disk = yd_raft_journal_image_disk(image), .meta = nodes[2]->meta};
    YDDiskView copied_view = yd_disk_view(copied.disk);
    CHECK(yd_raft_membership_recover(&copied, &copied_view) && yd_raft_membership_rebuild(&copied));
    CHECK(copied.membership.new_voters == 56 && copied.membership.retired_voters == 6);
    yd_raft_journal_capture_close(capture);
    yd_raft_journal_image_close(image);
    close(copy_fd);
    /* A snapshot carries the checkpoint's membership, not the sender's latest
     * uncommitted masks; omission cannot revive the immutable catalog quorum. */
    YDRaftSnapshotOffer offer={.from=3,.term=yd_raft_status(nodes[2]).term,
        .base=base,.configuration=nodes[2]->configuration_base};
    memcpy(offer.cluster,cluster,16);bool needed;
    CHECK(yd_raft_snapshot_contact(nodes[4],&offer,&needed) && needed);
    CHECK(yd_raft_snapshot_install(nodes[4],&offer));
    CHECK(yd_raft_membership(nodes[4]).new_voters==56 && yd_raft_membership(nodes[4]).retired_voters==6);
    unsigned char manifest[YD_RAFT_WIRE_MANIFEST] = {0}, header[128];
    YDRaftPacket snapshot_request = {.kind = YD_RPC_SNAPSHOT_BEGIN,
                                     .from = 3,
                                     .to = 5,
                                     .body.snapshot = {.term = offer.term,
                                                       .rpc = 42,
                                                       .base = base,
                                                       .configuration = offer.configuration,
                                                       .bytes = manifest,
                                                       .size = sizeof(manifest)}},
                 decoded;
    memcpy(snapshot_request.cluster, cluster, 16);
    CHECK(yd_raft_wire_encode(&snapshot_request, header) &&
          yd_raft_wire_decode(header, &decoded, cluster, 5, 5));
    CHECK(decoded.body.snapshot.configuration == offer.configuration);
    YDRaftPacket snapshot_reply = {
        .kind = YD_RPC_SNAPSHOT_BEGUN,
        .from = 5,
        .to = 3,
        .body.snapshot = {
            .term = offer.term, .rpc = 42, .base = base, .configuration = offer.configuration}};
    memcpy(snapshot_reply.cluster, cluster, 16);
    CHECK(yd_raft_wire_corresponds(&snapshot_request, &snapshot_reply));
    snapshot_reply.body.snapshot.configuration = 0;
    CHECK(!yd_raft_wire_corresponds(&snapshot_request, &snapshot_reply));
    snapshot_reply.body.snapshot.configuration = offer.configuration;
    snapshot_request.body.snapshot.configuration_delivery = true;
    CHECK(!yd_raft_wire_corresponds(&snapshot_request, &snapshot_reply));
    snapshot_reply.body.snapshot.configuration_delivery = true;
    CHECK(yd_raft_wire_corresponds(&snapshot_request, &snapshot_reply));
    CHECK(yd_raft_wire_encode(&snapshot_request, header) &&
          yd_raft_wire_decode(header, &decoded, cluster, 5, 5) &&
          decoded.body.snapshot.configuration_delivery);
    offer.configuration =
        yd_raft_membership_pack((YDRaftMembership){.old_voters = 14, .new_voters = 14});
    CHECK(!yd_raft_snapshot_contact(nodes[4], &offer,
                                    &needed)); /* same snapshot, conflicting topology */
    offer.configuration=0;
    CHECK(!yd_raft_snapshot_contact(nodes[4],&offer,&needed));
    yd_raft_close(nodes[4]);nodes[4]=yd_raft_open(paths[4],cluster,5,5,32768,error,sizeof(error));
    CHECK(nodes[4] && yd_raft_membership(nodes[4]).new_voters==56);
    for(unsigned i=0;i<5;i++) yd_raft_close(nodes[i]);
    nodes[0]=NULL;
    /* Missing membership evidence must refuse recovery, not recreate all five
     * catalog voters. The record and metadata are one native atomic root. */
    YDDisk *disk = yd_disk_open(paths[2], true, 32768, error, sizeof(error));
    CHECK(disk);
    YDDiskTxn *txn=yd_disk_begin_exclusive(disk,error,sizeof(error));
    CHECK(txn && yd_disk_delete(txn,"\0YRC",4,error,sizeof(error)) &&
        yd_disk_commit(txn,error,sizeof(error)));
    yd_disk_close(disk);
    CHECK(!yd_raft_open(paths[2],cluster,3,5,32768,error,sizeof(error)));
    disk = yd_disk_open(paths[4], true, 32768, error, sizeof(error));
    CHECK(disk);
    txn = yd_disk_begin_exclusive(disk, error, sizeof(error));
    uint64_t offset;
    unsigned char corrupt[24] = "YDRCONF1";
    CHECK(txn && yd_disk_append(txn, corrupt, sizeof(corrupt), &offset, error, sizeof(error)) &&
          yd_disk_put(txn, "\0YRC", 4, offset, error, sizeof(error)) &&
          yd_disk_commit(txn, error, sizeof(error)));
    yd_disk_close(disk);
    CHECK(!yd_raft_open(paths[4], cluster, 5, 5, 32768, error, sizeof(error)));
    return 0;
}
