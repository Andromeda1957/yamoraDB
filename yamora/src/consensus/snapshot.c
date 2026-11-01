#define _POSIX_C_SOURCE 200809L
#include "snapshot_internal.h"
#include "../disk_internal.h"
#include <limits.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>

struct YDRaftSnapshot {
    YDDiskCheckpoint *image;
    YDRaftSnapshotInfo info;
    bool sealed;
};
struct YDRaftSnapshotVerifier {
    YDRaftSnapshotInfo info;
    EVP_MD_CTX *hash;
    uint64_t received;
    bool failed, finished;
    unsigned char header[YD_DISK_PAGE];
};
static bool zero(const unsigned char *p, size_t size) {
    unsigned char n = 0;
    for (size_t i = 0; i < size; i++)
        n |= p[i];
    return n == 0;
}
static bool electorate(unsigned voters) {
    return voters >= 3 && voters <= YD_RAFT_VOTERS && (voters & 1);
}
static uint32_t get32(const unsigned char *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
static bool shape(const YDRaftSnapshotInfo *i) {
    bool profile = !i->capabilities ? i->view.format == 6 && !i->view.capabilities :
        i->view.format == 8 && i->view.capabilities == i->capabilities &&
        (i->capabilities & YD_DISK_CAP_CLUSTER) && !(i->capabilities & ~YD_DISK_CAP_SUPPORTED);
    return electorate(i->voters) && !zero(i->cluster, 16) && profile &&
           i->applied.index <= UINT64_MAX - 2 && i->view.generation == i->applied.index + 2 &&
           i->view.end >= 3U * YD_DISK_PAGE && i->view.end <= INT64_MAX &&
           !(i->view.end % YD_DISK_PAGE) && i->view.root >= 2U * YD_DISK_PAGE &&
           !(i->view.root % YD_DISK_PAGE) && i->view.root <= i->view.end - YD_DISK_PAGE &&
           (i->applied.index ? i->applied.term && !zero(i->entry_digest, 32)
                             : !i->applied.term && zero(i->entry_digest, 32) && !i->view.revision &&
                                   !i->view.documents && !i->view.collections && !i->view.bytes);
}
YDRaftSnapshot *yd_raft_snapshot_from_checkpoint(YDDiskCheckpoint *image,
                                                 const YDRaftCheckpoint *position, unsigned voters,
                                                 char *error, size_t length) {
    if (!image || !position || !electorate(voters)) {
        yd_disk_checkpoint_close(image);
        yd_disk_error(error, length, "invalid snapshot checkpoint or voter configuration");
        return NULL;
    }
    YDRaftSnapshot *snapshot = calloc(1, sizeof(*snapshot));
    if (!snapshot) {
        yd_disk_checkpoint_close(image);
        yd_disk_error(error, length, "cannot allocate consensus snapshot");
        return NULL;
    }
    snapshot->image = image;
    snapshot->info.voters = voters;
    snapshot->info.view = yd_disk_checkpoint_view(snapshot->image);
    snapshot->info.applied = position->applied;
    snapshot->info.capabilities = position->capabilities;
    memcpy(snapshot->info.cluster, position->cluster, 16);
    memcpy(snapshot->info.entry_digest, position->digest, 32);
    if (!shape(&snapshot->info)) {
        yd_raft_snapshot_close(snapshot);
        yd_disk_error(error, length, "invalid consensus snapshot capture");
        return NULL;
    }
    return snapshot;
}
static YDRaftSnapshot *snapshot_open(YDRaftApplication *app, unsigned voters, char *error,
                                      size_t length) {
    if (!electorate(voters)) {
        yd_disk_error(error, length, "invalid snapshot voter configuration");
        return NULL;
    }
    YDRaftCheckpoint position;
    YDDiskCheckpoint *image = yd_raft_application_checkpoint(app, &position, error, length);
    return image ? yd_raft_snapshot_from_checkpoint(image, &position, voters, error, length) : NULL;
}
static void snapshot_cancelled(void *context) { yd_raft_snapshot_close(context); }
YDRaftSnapshot *yd_raft_snapshot_open(YDRaftApplication *app, unsigned voters,
    char *error, size_t length) {
    int previous;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous)) return NULL;
    /* pthread_cleanup_push uses setjmp on glibc. Preserve the captured pointer
       across its cancellation boundary, including an inlined checkpoint open. */
    YDRaftSnapshot *volatile snapshot = snapshot_open(app, voters, error, length);
    pthread_cleanup_push(snapshot_cancelled, snapshot);
    (void)pthread_setcancelstate(previous, NULL);
    if (previous == PTHREAD_CANCEL_ENABLE) pthread_testcancel();
    pthread_cleanup_pop(0);
    return snapshot;
}
bool yd_raft_snapshot_seal(YDRaftSnapshot *snapshot, YDRaftSnapshotProgress progress, void *context,
                           char *error, size_t length) {
    if (!snapshot)
        return yd_disk_error(error, length, "consensus snapshot unavailable");
    if (snapshot->sealed)
        return true;
    EVP_MD_CTX *hash = EVP_MD_CTX_new();
    unsigned char *bytes = malloc(YD_DISK_CHECKPOINT_CHUNK), digest[32];
    unsigned int digest_size = 0;
    bool valid = hash && bytes && EVP_DigestInit_ex(hash, EVP_sha256(), NULL) == 1;
    uint64_t at = 0, end = snapshot->info.view.end;
    while (valid && at < end) {
        if (progress && !progress(context, at, end)) {
            valid = false;
            break;
        }
        size_t size =
            end - at < YD_DISK_CHECKPOINT_CHUNK ? (size_t)(end - at) : YD_DISK_CHECKPOINT_CHUNK;
        valid = yd_disk_checkpoint_read(snapshot->image, at, bytes, size, error, length) &&
                EVP_DigestUpdate(hash, bytes, size) == 1;
        at += size;
    }
    if (valid && progress)
        valid = progress(context, at, end);
    if (valid)
        valid = EVP_DigestFinal_ex(hash, digest, &digest_size) == 1 && digest_size == 32;
    EVP_MD_CTX_free(hash);
    free(bytes);
    if (!valid)
        return yd_disk_error(error, length, "consensus snapshot hashing failed or cancelled");
    memcpy(snapshot->info.image_digest, digest, 32);
    snapshot->sealed = true;
    return true;
}
bool yd_raft_snapshot_manifest(const YDRaftSnapshot *snapshot, unsigned char bytes[256]) {
    if (!snapshot || !snapshot->sealed || !bytes)
        return false;
    const YDRaftSnapshotInfo *i = &snapshot->info;
    memset(bytes, 0, 256);
    memcpy(bytes, i->capabilities ? "YDRSNAP2" : "YDRSNAP1", 8);
    memcpy(bytes + 8, i->cluster, 16);
    bytes[24] = (unsigned char)i->voters;
    bytes[25] = (unsigned char)i->view.format;
    bytes[26] = (unsigned char)i->capabilities;
    yd_disk_set64(bytes + 32, i->applied.index);
    yd_disk_set64(bytes + 40, i->applied.term);
    yd_disk_set64(bytes + 48, i->view.revision);
    yd_disk_set64(bytes + 56, i->view.generation);
    yd_disk_set64(bytes + 64, i->view.end);
    yd_disk_set64(bytes + 72, i->view.root);
    yd_disk_set64(bytes + 80, i->view.documents);
    yd_disk_set64(bytes + 88, i->view.collections);
    yd_disk_set64(bytes + 96, i->view.bytes);
    memcpy(bytes + 104, i->entry_digest, 32);
    memcpy(bytes + 136, i->image_digest, 32);
    uint32_t sum = yd_disk_crc(bytes, 252);
    for (unsigned n = 0; n < 4; n++)
        bytes[252 + n] = (unsigned char)(sum >> (8 * n));
    return true;
}
bool yd_raft_snapshot_read(const YDRaftSnapshot *snapshot, uint64_t offset, void *bytes,
                           size_t size, char *error, size_t length) {
    return snapshot && snapshot->sealed
               ? yd_disk_checkpoint_read(snapshot->image, offset, bytes, size, error, length)
               : yd_disk_error(error, length, "consensus snapshot is not sealed");
}
void yd_raft_snapshot_close(YDRaftSnapshot *snapshot) {
    if (snapshot) {
        yd_disk_checkpoint_close(snapshot->image);
        free(snapshot);
    }
}
bool yd_raft_snapshot_decode(const void *bytes, size_t size, const unsigned char cluster[16],
                             unsigned voters, YDRaftSnapshotInfo *info, char *error,
                             size_t length) {
    if (info)
        memset(info, 0, sizeof(*info));
    const unsigned char *p = bytes;
    bool version2 = p && size == 256 && !memcmp(p, "YDRSNAP2", 8);
    if (!p || !cluster || !info || size != 256 || (!version2 && memcmp(p, "YDRSNAP1", 8)) ||
        memcmp(p + 8, cluster, 16) || p[24] != voters ||
        (!version2 && p[26]) || (version2 && !p[26]) ||
        !zero(p + 27, 5) || !zero(p + 168, 84) ||
        get32(p + 252) != yd_disk_crc(p, 252))
        return yd_disk_error(error, length, "invalid consensus snapshot manifest");
    YDRaftSnapshotInfo decoded = {.voters = p[24],
                                  .capabilities = p[26],
                                  .applied = {yd_disk_u64(p + 32), yd_disk_u64(p + 40)},
                                  .view = {.format = p[25], .capabilities = p[26],
                                           .generation = yd_disk_u64(p + 56),
                                           .root = yd_disk_u64(p + 72),
                                           .end = yd_disk_u64(p + 64),
                                           .documents = yd_disk_u64(p + 80),
                                           .collections = yd_disk_u64(p + 88),
                                           .bytes = yd_disk_u64(p + 96),
                                           .revision = yd_disk_u64(p + 48)}};
    memcpy(decoded.cluster, p + 8, 16);
    memcpy(decoded.entry_digest, p + 104, 32);
    memcpy(decoded.image_digest, p + 136, 32);
    if (!shape(&decoded))
        return yd_disk_error(error, length, "invalid consensus snapshot metadata");
    *info = decoded;
    return true;
}
YDRaftSnapshotVerifier *yd_raft_snapshot_verifier_new(const void *manifest, size_t size,
                                                      const unsigned char cluster[16],
                                                      unsigned voters, char *error, size_t length) {
    YDRaftSnapshotInfo info;
    if (!yd_raft_snapshot_decode(manifest, size, cluster, voters, &info, error, length))
        return NULL;
    YDRaftSnapshotVerifier *v = calloc(1, sizeof(*v));
    if (!v) {
        yd_disk_error(error, length, "cannot allocate snapshot verifier");
        return NULL;
    }
    v->info = info;
    v->hash = EVP_MD_CTX_new();
    if (!v->hash || EVP_DigestInit_ex(v->hash, EVP_sha256(), NULL) != 1) {
        yd_raft_snapshot_verifier_free(v);
        yd_disk_error(error, length, "cannot initialize snapshot verifier");
        return NULL;
    }
    yd_disk_encode_header(v->header, &v->info.view);
    return v;
}
static bool reject(YDRaftSnapshotVerifier *v, char *error, size_t length) {
    if (v)
        v->failed = true;
    return yd_disk_error(error, length, "invalid or incomplete consensus snapshot stream");
}
bool yd_raft_snapshot_feed(YDRaftSnapshotVerifier *v, uint64_t offset, const void *bytes,
                           size_t size, char *error, size_t length) {
    if (!v || v->failed || v->finished || !bytes || !size || size > YD_DISK_CHECKPOINT_CHUNK ||
        offset != v->received || size > v->info.view.end - v->received)
        return reject(v, error, length);
    const unsigned char *p = bytes;
    size_t at = 0;
    while (at < size && offset + at < 2U * YD_DISK_PAGE) {
        size_t within = (size_t)((offset + at) % YD_DISK_PAGE), count = YD_DISK_PAGE - within;
        if (count > size - at)
            count = size - at;
        if (memcmp(p + at, v->header + within, count))
            return reject(v, error, length);
        at += count;
    }
    if (EVP_DigestUpdate(v->hash, bytes, size) != 1)
        return reject(v, error, length);
    v->received += size;
    return true;
}
bool yd_raft_snapshot_finish(YDRaftSnapshotVerifier *v, char *error, size_t length) {
    if (!v || v->failed || v->finished)
        return reject(v, error, length);
    v->finished = true;
    unsigned char digest[32];
    unsigned int size = 0;
    if (v->received != v->info.view.end || EVP_DigestFinal_ex(v->hash, digest, &size) != 1 ||
        size != 32 || CRYPTO_memcmp(digest, v->info.image_digest, 32))
        return reject(v, error, length);
    return true;
}
void yd_raft_snapshot_verifier_free(YDRaftSnapshotVerifier *v) {
    if (v) {
        EVP_MD_CTX_free(v->hash);
        free(v);
    }
}
