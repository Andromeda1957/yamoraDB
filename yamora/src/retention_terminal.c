#include "retention_terminal.h"
/* Match the existing session codec's explicit low-level OpenSSL API. A local
 * SHA256_CTX avoids selecting the one-shot EVP/provider path. This is not an
 * allocation guarantee for every linked OpenSSL build or application hook. */
#define OPENSSL_API_COMPAT 0x10100000L
#include <openssl/sha.h>
#include <string.h>

static void put32(unsigned char *p, uint32_t value) {
    for (unsigned i = 0; i < 4; i++) p[i] = (unsigned char)(value >> (8 * i));
}
static void put64(unsigned char *p, uint64_t value) {
    for (unsigned i = 0; i < 8; i++) p[i] = (unsigned char)(value >> (8 * i));
}
static bool valid(const YDRetentionTerminalInput *input) {
    unsigned char nonzero = 0;
    for (unsigned i = 0; i < 32; i++) nonzero |= input->incarnation[i];
    return input->fence_version == 1 && input->producer_protocol == 1 &&
        input->root_inode != 0 && input->journal_inode != 0 && nonzero != 0 &&
        input->file_size >= YD_RETENTION_TERMINAL_HEADER_BYTES &&
        input->file_size <= INT64_MAX;
}
bool yd_retention_terminal_hash(const YDRetentionTerminalInput *input,
    unsigned char digest[YD_RETENTION_TERMINAL_DIGEST_BYTES]) {
    if (!digest) return false;
    YDRetentionTerminalInput snapshot;
    if (input) memcpy(&snapshot, input, sizeof(snapshot));
    memset(digest, 0, YD_RETENTION_TERMINAL_DIGEST_BYTES);
    if (!input || !valid(&snapshot)) return false;

    unsigned char prefix[100];
    memcpy(prefix, "YAMORA-TERMROOT", 16);
    put32(prefix + 16, YD_RETENTION_TERMINAL_VERSION);
    put32(prefix + 20, snapshot.fence_version);
    put32(prefix + 24, snapshot.producer_protocol);
    put64(prefix + 28, snapshot.root_device);
    put64(prefix + 36, snapshot.root_inode);
    put64(prefix + 44, snapshot.journal_device);
    put64(prefix + 52, snapshot.journal_inode);
    put64(prefix + 60, snapshot.file_size);
    memcpy(prefix + 68, snapshot.incarnation, 32);

    SHA256_CTX context;
    unsigned char hash[YD_RETENTION_TERMINAL_DIGEST_BYTES];
    if (SHA256_Init(&context) != 1 ||
        SHA256_Update(&context, prefix, sizeof(prefix)) != 1 ||
        SHA256_Update(&context, snapshot.headers, sizeof(snapshot.headers)) != 1 ||
        SHA256_Final(hash, &context) != 1) return false;
    memcpy(digest, hash, sizeof(hash));
    return true;
}
