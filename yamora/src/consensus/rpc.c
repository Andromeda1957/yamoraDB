#define _POSIX_C_SOURCE 200809L
#include "rpc.h"
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
struct YDRaftRPC {
    YDTLS *tls;
    unsigned char cluster[16];
    unsigned local, voters;
    char names[YD_RAFT_VOTERS + 1][254];
    size_t budget;
    atomic_size_t current, peak;
};
static uint64_t now(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t))
        return 0;
    return (uint64_t)t.tv_sec * 1000 + (uint64_t)t.tv_nsec / 1000000;
}
static bool name_valid(const char *name) {
    if (!name)
        return false;
    size_t n = strnlen(name, 254);
    if (!n || n > 253)
        return false;
    size_t label = 0;
    bool letter = false;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)name[i];
        if (c == '.') {
            if (!label || name[i - 1] == '-')
                return false;
            label = 0;
            continue;
        }
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') || (!label && c == '-'))
            return false;
        if (c >= 'a' && c <= 'z')
            letter = true;
        if (++label > 63)
            return false;
    }
    return letter && label && name[n - 1] != '-';
}
bool yd_raft_peer_names_valid(unsigned voters, const char *const names[]) {
    if (!names || voters < 3 || voters > YD_RAFT_VOTERS || !(voters & 1))
        return false;
    for (unsigned i = 1; i <= voters; i++) {
        if (!name_valid(names[i]))
            return false;
        for (unsigned j = 1; j < i; j++)
            if (!strcmp(names[i], names[j]))
                return false;
    }
    return true;
}
YDRaftRPC *yd_raft_rpc_new(YDTLS *tls, const unsigned char cluster[16], unsigned local,
                           unsigned voters, const char *const names[], size_t budget) {
    bool nonzero = false;
    for (unsigned i = 0; cluster && i < 16; i++)
        nonzero |= cluster[i] != 0;
    if (!yd_tls_is_peer(tls) || !nonzero || voters < 3 || voters > YD_RAFT_VOTERS ||
        !(voters & 1) || !local || local > voters || !names || !budget ||
        budget > 64U * 1024U * 1024U)
        return NULL;
    if (!yd_raft_peer_names_valid(voters, names))
        return NULL;
    YDRaftRPC *rpc = calloc(1, sizeof(*rpc));
    if (!rpc)
        return NULL;
    rpc->tls = tls;
    rpc->local = local;
    rpc->voters = voters;
    rpc->budget = budget;
    memcpy(rpc->cluster, cluster, 16);
    for (unsigned i = 1; i <= voters; i++)
        memcpy(rpc->names[i], names[i], strlen(names[i]) + 1);
    atomic_init(&rpc->current, 0);
    atomic_init(&rpc->peak, 0);
    return rpc;
}
void yd_raft_rpc_free(YDRaftRPC *rpc) { free(rpc); }
void yd_raft_rpc_bytes(YDRaftRPC *rpc, size_t *current, size_t *peak) {
    *current = atomic_load(&rpc->current);
    *peak = atomic_load(&rpc->peak);
}
static bool reserve(YDRaftRPC *rpc, size_t size) {
    size_t used = atomic_load(&rpc->current);
    do {
        if (size > rpc->budget - used)
            return false;
    } while (!atomic_compare_exchange_weak(&rpc->current, &used, used + size));
    size_t peak = atomic_load(&rpc->peak);
    while (peak < used + size && !atomic_compare_exchange_weak(&rpc->peak, &peak, used + size)) {
    }
    return true;
}
static bool receive(YDConnection *connection, void *buffer, size_t size, uint64_t deadline) {
    size_t used = 0;
    while (used < size) {
        ssize_t n =
            yd_connection_read(connection, (unsigned char *)buffer + used, size - used, deadline);
        if (n <= 0)
            return false;
        used += (size_t)n;
    }
    return true;
}
static bool header(YDRaftRPC *rpc, YDConnection *connection, YDRaftPacket *p, uint64_t deadline) {
    unsigned char bytes[128];
    return receive(connection, bytes, sizeof(bytes), deadline) &&
           yd_raft_wire_decode(bytes, p, rpc->cluster, rpc->local, rpc->voters) &&
           yd_connection_peer_name(connection, rpc->names[p->from]);
}
static bool send_packet(YDRaftRPC *rpc, YDConnection *connection, const YDRaftPacket *p) {
    unsigned char bytes[128];
    YDRaftPacket check;
    if (p->from != rpc->local || !yd_raft_wire_encode(p, bytes) ||
        !yd_raft_wire_decode(bytes, &check, rpc->cluster, p->to, rpc->voters))
        return false;
    size_t size = yd_raft_wire_payload(p);
    const unsigned char *payload = NULL;
    if (size) payload = p->kind == YD_RPC_APPEND ? p->body.append.entry.command : p->body.snapshot.bytes;
    return yd_connection_send(connection, bytes, sizeof(bytes)) &&
           (!size || yd_connection_send(connection, payload, size));
}
static bool request_kind(YDRaftRPCKind kind) {
    return kind == YD_RPC_VOTE || kind == YD_RPC_APPEND || kind == YD_RPC_SNAPSHOT_BEGIN ||
        kind == YD_RPC_SNAPSHOT_CHUNK || kind == YD_RPC_SNAPSHOT_FINISH;
}
bool yd_raft_rpc_call(YDRaftRPC *rpc, int fd, const YDRaftPacket *request, YDRaftPacket *reply,
                      int timeout) {
    memset(reply, 0, sizeof(*reply));
    if (!rpc || timeout < 1 || timeout > 30000 || !request->to || request->to > rpc->voters ||
        request->to == rpc->local ||
        !request_kind(request->kind))
        return false;
    uint64_t start = now();
    if (!start)
        return false;
    uint64_t deadline = start + (unsigned)timeout;
    YDConnection connection;
    bool valid =
        yd_connection_peer_connect(&connection, fd, rpc->tls, rpc->names[request->to], timeout);
    connection.write_deadline = deadline;
    valid = valid && send_packet(rpc, &connection, request) &&
            header(rpc, &connection, reply, deadline) && yd_raft_wire_corresponds(request, reply);
    yd_connection_close(&connection);
    if (!valid)
        memset(reply, 0, sizeof(*reply));
    return valid;
}
bool yd_raft_rpc_serve(YDRaftRPC *rpc, int fd, YDRaftDispatch dispatch, void *context,
                       int timeout) {
    if (!rpc || !dispatch || timeout < 1 || timeout > 30000)
        return false;
    uint64_t start = now();
    if (!start)
        return false;
    uint64_t deadline = start + (unsigned)timeout;
    YDConnection connection;
    bool valid = yd_connection_init(&connection, fd, rpc->tls, timeout);
    connection.write_deadline = deadline;
    YDRaftPacket request, reply;
    valid = valid && header(rpc, &connection, &request, deadline) &&
            request_kind(request.kind);
    size_t size = valid ? yd_raft_wire_payload(&request) : 0;
    bool reserved = valid && reserve(rpc, size);
    unsigned char *bytes = reserved && size ? malloc(size) : NULL;
    valid = reserved && (!size || (bytes && receive(&connection, bytes, size, deadline)));
    if (valid) {
        if (request.kind == YD_RPC_APPEND)
            request.body.append.entry.command = bytes;
        else if (request.kind == YD_RPC_SNAPSHOT_BEGIN || request.kind == YD_RPC_SNAPSHOT_CHUNK)
            request.body.snapshot.bytes = bytes;
        memset(&reply, 0, sizeof(reply));
        valid = now() < deadline && dispatch(context, &request, &reply) &&
                yd_raft_wire_corresponds(&request, &reply) && send_packet(rpc, &connection, &reply);
    }
    free(bytes);
    if (reserved)
        atomic_fetch_sub(&rpc->current, size);
    yd_connection_close(&connection);
    return valid;
}
