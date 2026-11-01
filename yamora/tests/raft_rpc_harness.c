#define _POSIX_C_SOURCE 200809L
#include "../src/consensus/rpc.h"
#include <arpa/inet.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#define REQUIRE(x)                                                                                 \
    do {                                                                                           \
        if (!(x)) {                                                                                \
            fprintf(stderr, "line %u: %s\n", __LINE__, #x);                                        \
            return 2;                                                                              \
        }                                                                                          \
    } while (0)
static const unsigned char cluster[16] = {1, 2, 3, 4};
static const char *const names[] = {NULL, "node1.test", "node2.test", "node3.test"};
static int snapshot_codec(void) {
    unsigned char bytes[YD_RAFT_WIRE_MANIFEST] = {0}, header[128], mutated[128];
    YDRaftPacket packet = {.kind = YD_RPC_SNAPSHOT_BEGIN, .from = 1, .to = 2,
        .body.snapshot = {.term = 3, .rpc = 4, .base = {.index = 2, .term = 1,
            .archive = {1}}, .bytes = bytes, .size = sizeof(bytes)}};
    memcpy(packet.cluster, cluster, 16);
    for (unsigned kind = YD_RPC_SNAPSHOT_BEGIN; kind <= YD_RPC_SNAPSHOT_FINISHED; kind++) {
        packet.kind = (YDRaftRPCKind)kind;
        YDRaftSnapshotFrame *frame = &packet.body.snapshot;
        bool reply = !(kind & 1);
        frame->accepted = reply;
        frame->installed = false;
        frame->size = kind == YD_RPC_SNAPSHOT_BEGIN ? YD_RAFT_WIRE_MANIFEST :
            kind == YD_RPC_SNAPSHOT_CHUNK ? YD_RAFT_WIRE_CHUNK : 0;
        frame->offset = kind >= YD_RPC_SNAPSHOT_FINISH ? 12288 : 0;
        if (kind == YD_RPC_SNAPSHOT_CHUNKED) frame->offset = YD_RAFT_WIRE_CHUNK;
        memset(frame->session, 0, sizeof(frame->session));
        if (kind != YD_RPC_SNAPSHOT_BEGIN) frame->session[0] = 1;
        REQUIRE(yd_raft_wire_encode(&packet, header));
        YDRaftPacket decoded;
        REQUIRE(yd_raft_wire_decode(header, &decoded, cluster, 2, 3));
        REQUIRE(decoded.kind == packet.kind && decoded.body.snapshot.bytes == NULL &&
            decoded.body.snapshot.size == frame->size && decoded.body.snapshot.offset == frame->offset &&
            decoded.body.snapshot.rpc == 4 && decoded.body.snapshot.base.index == 2 &&
            decoded.body.snapshot.base.term == 1 && decoded.body.snapshot.base.archive[0] == 1 &&
            !memcmp(decoded.body.snapshot.session, frame->session, 16) &&
            yd_raft_wire_payload(&decoded) == frame->size);
        for (unsigned byte = 0; byte < 128; byte++) {
            for (unsigned bit = 0; bit < 8; bit++) {
                memcpy(mutated, header, 128);
                mutated[byte] ^= (unsigned char)(1U << bit);
                if (yd_raft_wire_decode(mutated, &decoded, cluster, 2, 3)) {
                    decoded.body.snapshot.bytes = bytes;
                    unsigned char canonical[128];
                    REQUIRE(yd_raft_wire_encode(&decoded, canonical));
                    REQUIRE(!memcmp(canonical, mutated, 128));
                }
            }
        }
        static const unsigned invalid[][2] = {{8, 255}, {9, 0}, {10, 1}, {11, 255}, {12, 1},
            {15, 1}, {16, 0}, {40, 0}, {48, 0}, {56, 0}};
        for (unsigned i = 0; i < sizeof(invalid) / sizeof(*invalid); i++) {
            memcpy(mutated, header, 128);
            mutated[invalid[i][0]] = (unsigned char)invalid[i][1];
            REQUIRE(!yd_raft_wire_decode(mutated, &decoded, cluster, 2, 3));
        }
        memcpy(mutated, header, 128);
        memset(mutated + 80, 0, 32);
        REQUIRE(!yd_raft_wire_decode(mutated, &decoded, cluster, 2, 3));
        if (kind == YD_RPC_SNAPSHOT_CHUNK || kind == YD_RPC_SNAPSHOT_CHUNKED ||
            kind >= YD_RPC_SNAPSHOT_FINISH) {
            memcpy(mutated, header, 128); memset(mutated + 112, 0, 16);
            REQUIRE(!yd_raft_wire_decode(mutated, &decoded, cluster, 2, 3));
        }
        if (reply) {
            frame->accepted = false; frame->offset = 0;
            if (kind == YD_RPC_SNAPSHOT_BEGUN) memset(frame->session, 0, 16);
            frame->term = 0;
            REQUIRE(yd_raft_wire_encode(&packet, header));
            frame->installed = true;
            REQUIRE(!yd_raft_wire_encode(&packet, header));
            frame->accepted = true; frame->term = 3; frame->offset = 12288;
            REQUIRE(yd_raft_wire_encode(&packet, header) == (kind != YD_RPC_SNAPSHOT_CHUNKED));
        } else {
            frame->size++;
            REQUIRE(!yd_raft_wire_encode(&packet, header));
            frame->size--;
            if (frame->size) {
                frame->bytes = NULL;
                REQUIRE(!yd_raft_wire_encode(&packet, header));
                frame->bytes = bytes;
            }
        }
        frame->term = 3;
    }
    /* Overflow and oversized chunks must reject before payload allocation. */
    packet.kind = YD_RPC_SNAPSHOT_CHUNK;
    packet.body.snapshot = (YDRaftSnapshotFrame){.term = 3, .rpc = 4,
        .base = {.index = 2, .term = 1, .archive = {1}}, .session = {1}, .bytes = bytes,
        .offset = INT64_MAX, .size = 1};
    REQUIRE(!yd_raft_wire_encode(&packet, header));
    packet.body.snapshot.offset = 0;
    packet.body.snapshot.size = YD_RAFT_WIRE_CHUNK + 1U;
    REQUIRE(!yd_raft_wire_encode(&packet, header));
    return 0;
}
static int snapshot_correlation(void) {
    unsigned char bytes[YD_RAFT_WIRE_MANIFEST] = {0};
    for (unsigned kind = YD_RPC_SNAPSHOT_BEGIN; kind <= YD_RPC_SNAPSHOT_FINISH; kind += 2) {
        YDRaftPacket request = {.kind = (YDRaftRPCKind)kind, .from = 1, .to = 2,
            .body.snapshot = {.term = 3, .rpc = 4, .base = {.index = 2, .term = 1,
                .archive = {1}}, .bytes = bytes}};
        memcpy(request.cluster, cluster, 16);
        request.body.snapshot.size = kind == YD_RPC_SNAPSHOT_BEGIN ? 256 :
            kind == YD_RPC_SNAPSHOT_CHUNK ? 128 : 0;
        request.body.snapshot.offset = kind == YD_RPC_SNAPSHOT_FINISH ? 12288 : 0;
        if (kind != YD_RPC_SNAPSHOT_BEGIN) request.body.snapshot.session[0] = 1;
        YDRaftPacket reply = request;
        reply.kind = (YDRaftRPCKind)(kind + 1);
        reply.from = 2; reply.to = 1;
        reply.body.snapshot.size = 0;
        reply.body.snapshot.bytes = NULL;
        reply.body.snapshot.accepted = true;
        reply.body.snapshot.session[0] = 1;
        if (kind == YD_RPC_SNAPSHOT_CHUNK) reply.body.snapshot.offset = 128;
        REQUIRE(yd_raft_wire_corresponds(&request, &reply));
        YDRaftPacket bad = reply;
        bad.to = 3; REQUIRE(!yd_raft_wire_corresponds(&request, &bad));
        bad = reply; bad.from = 3; REQUIRE(!yd_raft_wire_corresponds(&request, &bad));
        bad = reply; bad.cluster[0]++; REQUIRE(!yd_raft_wire_corresponds(&request, &bad));
        bad = reply; bad.kind = YD_RPC_APPENDED; REQUIRE(!yd_raft_wire_corresponds(&request, &bad));
        bad = reply; bad.body.snapshot.rpc++; REQUIRE(!yd_raft_wire_corresponds(&request, &bad));
        bad = reply; bad.body.snapshot.base.index++; REQUIRE(!yd_raft_wire_corresponds(&request, &bad));
        bad = reply; bad.body.snapshot.base.term++; REQUIRE(!yd_raft_wire_corresponds(&request, &bad));
        bad = reply; bad.body.snapshot.base.archive[31]++; REQUIRE(!yd_raft_wire_corresponds(&request, &bad));
        bad = reply; bad.body.snapshot.term++; REQUIRE(!yd_raft_wire_corresponds(&request, &bad));
        if (kind != YD_RPC_SNAPSHOT_BEGIN) {
            bad = reply; bad.body.snapshot.session[15]++;
            REQUIRE(!yd_raft_wire_corresponds(&request, &bad));
            bad = reply; bad.body.snapshot.offset--;
            REQUIRE(!yd_raft_wire_corresponds(&request, &bad));
        }
        reply.body.snapshot.accepted = false;
        reply.body.snapshot.offset = 0;
        reply.body.snapshot.term = 4;
        if (kind == YD_RPC_SNAPSHOT_BEGIN) memset(reply.body.snapshot.session, 0, 16);
        REQUIRE(yd_raft_wire_corresponds(&request, &reply));
    }
    return 0;
}
static int codec(void) {
    YDRaftPacket p = {.kind = YD_RPC_APPEND, .from = 1, .to = 2};
    memcpy(p.cluster, cluster, 16);
    p.body.append = (YDRaftAppend){.from = 1,
                                   .term = 1,
                                   .rpc = 9,
                                   .has_entry = true,
                                   .entry = {.index = 1,
                                             .term = 1,
                                             .kind = YD_RAFT_COMMAND,
                                             .size = 3,
                                             .command = (const unsigned char *)"abc"}};
    memcpy(p.body.append.cluster, cluster, 16);
    unsigned char header[128], bad[128];
    YDRaftPacket decoded;
    REQUIRE(yd_raft_wire_encode(&p, header));
    REQUIRE(yd_raft_wire_decode(header, &decoded, cluster, 2, 3));
    REQUIRE(decoded.body.append.entry.size == 3 && decoded.body.append.rpc == 9 &&
            decoded.body.append.entry.command == NULL && yd_raft_wire_payload(&decoded) == 3);
    const unsigned mutations[][2] = {
        {0, 255}, {8, 255},  {9, 255},  {10, 255}, {11, 255}, {12, 255},  {16, 255},  {32, 0},
        {40, 0},  {56, 255}, {83, 255}, {88, 255}, {89, 255}, {100, 255}, {112, 255}, {127, 255}};
    for (size_t i = 0; i < sizeof(mutations) / sizeof(*mutations); i++) {
        memcpy(bad, header, 128);
        bad[mutations[i][0]] = (unsigned char)mutations[i][1];
        REQUIRE(!yd_raft_wire_decode(bad, &decoded, cluster, 2, 3));
    }
    REQUIRE(!yd_raft_wire_decode(header, &decoded, cluster, 1, 3));
    REQUIRE(!yd_raft_wire_decode(header, &decoded, cluster, 2, 2));
    /* Every accepted bit mutation must have one canonical encoding. */
    for (unsigned i = 0; i < 128; i++)
        for (unsigned bit = 0; bit < 8; bit++) {
            memcpy(bad, header, 128);
            bad[i] ^= (unsigned char)(1U << bit);
            if (yd_raft_wire_decode(bad, &decoded, cluster, 2, 3)) {
                decoded.body.append.entry.command = (const unsigned char *)"abc";
                unsigned char canonical[128];
                REQUIRE(yd_raft_wire_encode(&decoded, canonical));
                REQUIRE(!memcmp(bad, canonical, 128));
            }
        }
    p = (YDRaftPacket){.kind = YD_RPC_VOTE, .from = 1, .to = 2};
    memcpy(p.cluster, cluster, 16);
    p.body.vote = (YDRaftVote){.from = 1, .term = 3, .last = 2, .last_term = 1};
    memcpy(p.body.vote.cluster, cluster, 16);
    REQUIRE(yd_raft_wire_encode(&p, header) &&
            yd_raft_wire_decode(header, &decoded, cluster, 2, 3));
    REQUIRE(decoded.body.vote.term == 3 && decoded.body.vote.last == 2 &&
            decoded.body.vote.last_term == 1);
    p = (YDRaftPacket){
        .kind = YD_RPC_VOTED, .from = 2, .to = 1, .request_term = 3, .body.voted = {.term = 4}};
    memcpy(p.cluster, cluster, 16);
    REQUIRE(yd_raft_wire_encode(&p, header) &&
            yd_raft_wire_decode(header, &decoded, cluster, 1, 3));
    REQUIRE(decoded.request_term == 3 && decoded.body.voted.term == 4 &&
            !decoded.body.voted.granted);
    return 0;
}
typedef struct {
    YDRaftRPC *rpc;
    YDRaft *raft;
    int fd;
    unsigned calls;
    bool success;
} Server;
static bool dispatch(void *context, const YDRaftPacket *request, YDRaftPacket *reply) {
    Server *s = context;
    s->calls++;
    if (request->kind == YD_RPC_SNAPSHOT_BEGIN || request->kind == YD_RPC_SNAPSHOT_CHUNK ||
        request->kind == YD_RPC_SNAPSHOT_FINISH) {
        /* Synthetic transport fixture: checks byte delivery and correlation;
         * it grants no application or journal installation acknowledgement. */
        static const unsigned char pattern[3] = {'a', 0, 255};
        for (size_t i = 0; i < request->body.snapshot.size; i++)
            if (request->body.snapshot.bytes[i] != pattern[i % 3]) return false;
        *reply = *request;
        reply->kind = (YDRaftRPCKind)(request->kind + 1);
        reply->from = 2; reply->to = request->from;
        reply->body.snapshot.size = 0; reply->body.snapshot.bytes = NULL;
        reply->body.snapshot.accepted = true;
        reply->body.snapshot.installed = false;
        if (request->kind == YD_RPC_SNAPSHOT_BEGIN) reply->body.snapshot.session[0] = 7;
        if (request->kind == YD_RPC_SNAPSHOT_CHUNK)
            reply->body.snapshot.offset += request->body.snapshot.size;
        return true;
    }
    *reply = (YDRaftPacket){.kind = request->kind == YD_RPC_VOTE ? YD_RPC_VOTED : YD_RPC_APPENDED,
                            .from = 2,
                            .to = request->from,
                            .request_term = request->body.vote.term};
    memcpy(reply->cluster, cluster, 16);
    if (request->kind == YD_RPC_VOTE)
        return yd_raft_vote(s->raft, &request->body.vote, &reply->body.voted);
    return request->kind == YD_RPC_APPEND &&
           yd_raft_append(s->raft, &request->body.append, &reply->body.appended);
}
static void *serve(void *argument) {
    Server *s = argument;
    int fd = accept(s->fd, NULL, NULL);
    if (fd >= 0) {
        s->success = yd_raft_rpc_serve(s->rpc, fd, dispatch, s, 800);
        close(fd);
    }
    return NULL;
}
static YDTLS *identity(const char *certificates, const char *name) {
    char cert[4096], key[4096], ca[4096], error[256];
    snprintf(cert, sizeof(cert), "%s/%s.pem", certificates, name);
    snprintf(key, sizeof(key), "%s/%s.key", certificates, name);
    snprintf(ca, sizeof(ca), "%s/trusted.pem", certificates);
    return yd_tls_peer_new(cert, key, ca, error, sizeof(error));
}
int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    if (argc == 2 && !strcmp(argv[1], "codec"))
        return codec();
    if (argc == 2 && !strcmp(argv[1], "snapshot-codec"))
        return snapshot_codec();
    if (argc == 2 && !strcmp(argv[1], "snapshot-correlation"))
        return snapshot_correlation();
    if (argc != 4)
        return 1;
    YDTLS *tls = identity(argv[2], "node2");
    REQUIRE(tls);
    size_t budget = !strcmp(argv[3], "small") ? 1024 : 64U * 1024U * 1024U;
    YDRaftRPC *rpc = yd_raft_rpc_new(tls, cluster, 2, 3, names, budget);
    REQUIRE(rpc);
    char error[256];
    YDRaft *raft = yd_raft_open(argv[1], cluster, 2, 3, 32768, error, sizeof(error));
    REQUIRE(raft);
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    REQUIRE(listener >= 0);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    REQUIRE(!bind(listener, (struct sockaddr *)&address, sizeof(address)) && !listen(listener, 4));
    socklen_t size = sizeof(address);
    REQUIRE(!getsockname(listener, (struct sockaddr *)&address, &size));
    Server server = {.rpc = rpc, .raft = raft, .fd = listener};
    if (!strncmp(argv[3], "pair", 4)) {
        pthread_t thread;
        REQUIRE(!pthread_create(&thread, NULL, serve, &server));
        YDTLS *client_tls = identity(argv[2], "node1");
        REQUIRE(client_tls);
        const char *const wrong_names[] = {NULL, "node1.test", "node3.test", "node2.test"};
        bool wrong = !strcmp(argv[3], "pair-wrong-server");
        YDRaftRPC *client =
            yd_raft_rpc_new(client_tls, cluster, 1, 3, wrong ? wrong_names : names, budget);
        REQUIRE(client);
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        REQUIRE(fd >= 0 && !connect(fd, (struct sockaddr *)&address, sizeof(address)));
        YDRaftPacket request = {.kind = YD_RPC_APPEND, .from = 1, .to = 2}, reply;
        memcpy(request.cluster, cluster, 16);
        request.body.append = (YDRaftAppend){.from = 1,
                                             .term = 1,
                                             .rpc = 9,
                                             .committed = 1,
                                             .has_entry = true,
                                             .entry = {.index = 1,
                                                       .term = 1,
                                                       .kind = YD_RAFT_COMMAND,
                                                       .size = 3,
                                                       .command = (const unsigned char *)"abc"}};
        memcpy(request.body.append.cluster, cluster, 16);
        bool snapshot = !strncmp(argv[3], "pair-snapshot-", 14);
        unsigned char *payload = NULL;
        if (snapshot) {
            request.kind = !strcmp(argv[3], "pair-snapshot-begin") ? YD_RPC_SNAPSHOT_BEGIN :
                !strcmp(argv[3], "pair-snapshot-chunk") ? YD_RPC_SNAPSHOT_CHUNK : YD_RPC_SNAPSHOT_FINISH;
            request.body.snapshot = (YDRaftSnapshotFrame){.term = 3, .rpc = 4,
                .base = {.index = 2, .term = 1, .archive = {1}}};
            request.body.snapshot.size = request.kind == YD_RPC_SNAPSHOT_BEGIN ? 256 :
                request.kind == YD_RPC_SNAPSHOT_CHUNK ? YD_RAFT_WIRE_CHUNK : 0;
            if (request.kind != YD_RPC_SNAPSHOT_BEGIN) request.body.snapshot.session[0] = 7;
            if (request.kind == YD_RPC_SNAPSHOT_FINISH) request.body.snapshot.offset = 12288;
            payload = malloc(request.body.snapshot.size ? request.body.snapshot.size : 1);
            REQUIRE(payload);
            for (size_t i = 0; i < request.body.snapshot.size; i++) payload[i] = (unsigned char[]){'a', 0, 255}[i % 3];
            request.body.snapshot.bytes = payload;
        }
        bool called = yd_raft_rpc_call(client, fd, &request, &reply, 800);
        free(payload);
        close(fd);
        REQUIRE(!pthread_join(thread, NULL));
        REQUIRE(called != wrong && server.success != wrong && server.calls == (wrong ? 0U : 1U));
        if (snapshot)
            REQUIRE(reply.kind == request.kind + 1 && reply.body.snapshot.accepted &&
                !reply.body.snapshot.installed && reply.body.snapshot.rpc == 4);
        else if (!wrong)
            REQUIRE(reply.kind == YD_RPC_APPENDED && reply.body.appended.accepted &&
                    reply.body.appended.matched == 1);
        yd_raft_rpc_free(client);
        yd_tls_free(client_tls);
        if (!wrong && !snapshot) {
            YDRaftEntry entry;
            REQUIRE(yd_raft_entry(raft, 1, &entry) && entry.size == 3 &&
                    !memcmp(entry.command, "abc", 3));
            yd_raft_entry_free(&entry);
        }
    } else {
        printf("port=%u\n", ntohs(address.sin_port));
        fflush(stdout);
        serve(&server);
    }
    if (!strcmp(argv[3], "large") && server.success) {
        static const unsigned char pattern[3] = {'a', 0, 255};
        YDRaftEntry entry;
        REQUIRE(yd_raft_entry(raft, 1, &entry) && entry.size == 3U * 1024U * 1024U);
        for (size_t i = 0; i < entry.size; i++)
            REQUIRE(entry.command[i] == pattern[i % 3]);
        yd_raft_entry_free(&entry);
        REQUIRE(yd_raft_status(raft).committed == 1);
    }
    size_t current, peak;
    yd_raft_rpc_bytes(rpc, &current, &peak);
    YDRaftStatus status = yd_raft_status(raft);
    printf("success=%u calls=%u current=%zu peak=%zu term=%llu last=%llu\n", server.success,
           server.calls, current, peak, (unsigned long long)status.term,
           (unsigned long long)status.last);
    close(listener);
    yd_raft_close(raft);
    yd_raft_rpc_free(rpc);
    yd_tls_free(tls);
    return 0;
}
