#include "retention_session_record.h"
/* Stack SHA256_CTX avoids the one-shot EVP path's implicit heap allocation.
 * The system OpenSSL low-level SHA256 API remains the deliberate dependency. */
#define OPENSSL_API_COMPAT 0x10100000L
#include <openssl/sha.h>
#include <string.h>

static void put32(unsigned char *p, uint32_t n) {
    for (unsigned i = 0; i < 4; i++) p[i] = (unsigned char)(n >> (24 - 8*i));
}
static void put64(unsigned char *p, uint64_t n) {
    for (unsigned i = 0; i < 8; i++) p[i] = (unsigned char)(n >> (56 - 8*i));
}
static uint32_t get32(const unsigned char *p) {
    uint32_t n = 0;
    for (unsigned i = 0; i < 4; i++) n = (n << 8) | p[i];
    return n;
}
static uint64_t get64(const unsigned char *p) {
    uint64_t n = 0;
    for (unsigned i = 0; i < 8; i++) n = (n << 8) | p[i];
    return n;
}
static bool nonzero(const unsigned char *p, size_t length) {
    unsigned char n = 0;
    for (size_t i = 0; i < length; i++) n |= p[i];
    return n != 0;
}
static bool digest(const unsigned char *bytes, unsigned char out[32]) {
    SHA256_CTX context;
    return SHA256_Init(&context) == 1 && SHA256_Update(&context, bytes, 224) == 1 &&
        SHA256_Final(out, &context) == 1;
}
static bool valid(const YDRaftRetentionSessionRecord *r) {
    if (!r->epoch || !nonzero(r->birth_hash, 32) || !nonzero(r->nonce, 32) ||
        !r->journal_inode) return false;
    switch (r->state) {
    case YD_RAFT_RETENTION_SESSION_ACTIVE:
        return !nonzero(r->terminal_root, 32) && r->reason_bits == 0;
    case YD_RAFT_RETENTION_SESSION_CLEAN:
        return nonzero(r->terminal_root, 32) && r->reason_bits == 0;
    case YD_RAFT_RETENTION_SESSION_POISON:
        return r->reason_bits != 0;
    default:
        return false;
    }
}
bool yd_raft_retention_session_record_encode(unsigned char *out, size_t capacity,
    const YDRaftRetentionSessionRecord *record) {
    YDRaftRetentionSessionRecord r;
    if (out && record && capacity >= YD_RAFT_RETENTION_SESSION_RECORD_SIZE)
        memcpy(&r, record, sizeof(r));
    if (out) memset(out, 0, capacity < YD_RAFT_RETENTION_SESSION_RECORD_SIZE ?
        capacity : YD_RAFT_RETENTION_SESSION_RECORD_SIZE);
    if (!out || !record || capacity < YD_RAFT_RETENTION_SESSION_RECORD_SIZE) return false;
    if (!valid(&r)) return false;
    unsigned char bytes[YD_RAFT_RETENTION_SESSION_RECORD_SIZE] = {0};
    memcpy(bytes, "YDRSESS1", 8);
    put32(bytes + 8, YD_RAFT_RETENTION_SESSION_RECORD_VERSION);
    put32(bytes + 12, YD_RAFT_RETENTION_SESSION_RECORD_SIZE);
    put32(bytes + 16, YD_RAFT_RETENTION_SESSION_PRODUCER_PROTOCOL);
    put32(bytes + 20, r.state);
    put64(bytes + 24, r.epoch);
    memcpy(bytes + 32, r.birth_hash, 32);
    memcpy(bytes + 64, r.nonce, 32);
    put64(bytes + 96, r.journal_device);
    put64(bytes + 104, r.journal_inode);
    memcpy(bytes + 112, r.terminal_root, 32);
    put64(bytes + 144, r.reason_bits);
    if (!digest(bytes, bytes + 224)) return false;
    memcpy(out, bytes, sizeof(bytes));
    return true;
}
bool yd_raft_retention_session_record_decode(const unsigned char *bytes, size_t length,
    YDRaftRetentionSessionRecord *out) {
    unsigned char wire[YD_RAFT_RETENTION_SESSION_RECORD_SIZE];
    if (out && bytes && length == sizeof(wire)) memcpy(wire, bytes, sizeof(wire));
    if (out) memset(out, 0, sizeof(*out));
    if (!out || !bytes || length != sizeof(wire)) return false;
    if (memcmp(wire, "YDRSESS1", 8) ||
        get32(wire + 8) != YD_RAFT_RETENTION_SESSION_RECORD_VERSION ||
        get32(wire + 12) != YD_RAFT_RETENTION_SESSION_RECORD_SIZE ||
        get32(wire + 16) != YD_RAFT_RETENTION_SESSION_PRODUCER_PROTOCOL ||
        nonzero(wire + 152, 72)) return false;
    unsigned char hash[32];
    if (!digest(wire, hash) || memcmp(wire + 224, hash, 32)) return false;
    YDRaftRetentionSessionRecord r;
    memset(&r, 0, sizeof(r));
    r.state = get32(wire + 20);
    r.epoch = get64(wire + 24);
    memcpy(r.birth_hash, wire + 32, 32);
    memcpy(r.nonce, wire + 64, 32);
    r.journal_device = get64(wire + 96);
    r.journal_inode = get64(wire + 104);
    memcpy(r.terminal_root, wire + 112, 32);
    r.reason_bits = get64(wire + 144);
    if (!valid(&r)) return false;
    memcpy(out, &r, sizeof(r));
    return true;
}
