#define _POSIX_C_SOURCE 200809L
#include "../src/consensus/snapshot.h"
#include "../src/disk_documents.h"
#include "../src/disk_internal.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#define REQUIRE(x)                                                                                 \
    do {                                                                                           \
        if (!(x)) {                                                                                \
            fprintf(stderr, "line %u: %s (%s)\n", __LINE__, #x, error);                            \
            return 2;                                                                              \
        }                                                                                          \
    } while (0)
static char error[512];
static const unsigned char cluster[16] = {1, 2, 3, 4};
static uint32_t capabilities;
static const unsigned char source[] = "# exact source\r\ncount: 0 # retained\r\n";
static YDRaftApplication *seed(const char *root, const unsigned char *bytes, size_t size) {
    YDRaftApplication *app = capabilities
        ? yd_raft_application_open_capabilities(root, cluster, capabilities, 32768, error, sizeof(error))
        : yd_raft_application_open(root, cluster, 32768, error, sizeof(error));
    if (!app)
        return NULL;
    YDRaftEntry noop = {.index = 1, .term = 1, .kind = YD_RAFT_NOOP};
    bool valid = yd_raft_application_apply(app, &noop, error, sizeof(error));
    YDRaftWrite request = {.id = {1},
                           .method = "PUT",
                           .target = "/v1/collections/a/documents/b",
                           .body = bytes,
                           .size = size};
    YDRaftProposal proposal = {0};
    if (valid)
        valid = yd_raft_application_prepare(app, &request, &proposal, error, sizeof(error)) == 1;
    YDRaftEntry entry = {.index = 2,
                         .term = 1,
                         .kind = YD_RAFT_COMMAND,
                         .command = proposal.command,
                         .size = proposal.size};
    if (valid)
        valid = yd_raft_application_apply(app, &entry, error, sizeof(error));
    yd_raft_proposal_free(&proposal);
    if (!valid) {
        yd_raft_application_close(app);
        return NULL;
    }
    return app;
}
static YDRaftSnapshot *sealed(YDRaftApplication *app, unsigned char manifest[256]) {
    YDRaftSnapshot *snapshot = yd_raft_snapshot_open(app, 3, error, sizeof(error));
    if (!snapshot)
        return NULL;
    if (!yd_raft_snapshot_seal(snapshot, NULL, NULL, error, sizeof(error)) ||
        !yd_raft_snapshot_manifest(snapshot, manifest)) {
        yd_raft_snapshot_close(snapshot);
        return NULL;
    }
    return snapshot;
}
static bool transfer(YDRaftSnapshot *snapshot, const unsigned char manifest[256], int fd,
                     size_t chunk, bool damage) {
    YDRaftSnapshotInfo info;
    if (!yd_raft_snapshot_decode(manifest, 256, cluster, 3, &info, error, sizeof(error)))
        return false;
    YDRaftSnapshotVerifier *verifier =
        yd_raft_snapshot_verifier_new(manifest, 256, cluster, 3, error, sizeof(error));
    unsigned char *bytes = malloc(chunk);
    bool valid = verifier && bytes;
    for (uint64_t offset = 0; valid && offset < info.view.end;) {
        size_t size = info.view.end - offset < chunk ? (size_t)(info.view.end - offset) : chunk;
        valid = yd_raft_snapshot_read(snapshot, offset, bytes, size, error, sizeof(error));
        if (damage && offset + size == info.view.end)
            bytes[size - 1] ^= 1;
        if (valid)
            valid = yd_raft_snapshot_feed(verifier, offset, bytes, size, error, sizeof(error));
        if (valid && fd >= 0) {
            size_t at = 0;
            while (valid && at < size) {
                ssize_t count = write(fd, bytes + at, size - at);
                if (count <= 0)
                    valid = false;
                else
                    at += (size_t)count;
            }
        }
        offset += size;
    }
    if (valid)
        valid = yd_raft_snapshot_finish(verifier, error, sizeof(error));
    yd_raft_snapshot_verifier_free(verifier);
    free(bytes);
    return valid;
}
static void crc(unsigned char manifest[256]);
static int basic(const char *root, const char *destination) {
    YDRaftApplication *app = seed(root, source, sizeof(source) - 1);
    REQUIRE(app);
    YDRaftSnapshot *snapshot = yd_raft_snapshot_open(app, 3, error, sizeof(error));
    REQUIRE(snapshot);
    YDRaftEntry noop = {.index = 3, .term = 2, .kind = YD_RAFT_NOOP};
    REQUIRE(yd_raft_application_apply(app, &noop, error, sizeof(error)));
    noop.index = 4;
    REQUIRE(yd_raft_application_apply(app, &noop, error, sizeof(error)));
    yd_raft_application_close(app);
    unsigned char manifest[256];
    REQUIRE(!yd_raft_snapshot_manifest(snapshot, manifest));
    REQUIRE(yd_raft_snapshot_seal(snapshot, NULL, NULL, error, sizeof(error)) &&
            yd_raft_snapshot_manifest(snapshot, manifest));
    YDRaftSnapshotInfo info;
    REQUIRE(yd_raft_snapshot_decode(manifest, sizeof(manifest), cluster, 3, &info, error,
                                    sizeof(error)));
    REQUIRE(info.applied.index == 2 && info.applied.term == 1 && info.view.generation == 4 &&
            info.view.format == (capabilities ? 8U : 6U) && info.capabilities == capabilities &&
            info.view.capabilities == capabilities && info.view.documents == 1 && info.view.collections == 1);
    if (capabilities) {
        unsigned char altered[256];
        memcpy(altered, manifest, sizeof(altered));
        altered[26] = (unsigned char)(capabilities ^ YD_DISK_CAP_SCHEMA);
        crc(altered);
        /* Another supported mask is structurally valid, but cannot describe
         * this actual native image. Recomputed manifest CRC is insufficient. */
        REQUIRE(yd_raft_snapshot_decode(altered, sizeof(altered), cluster, 3, &info, error, sizeof(error)));
        REQUIRE(!transfer(snapshot, altered, -1, 4093, false));
        static const unsigned char invalid[] = {0, YD_DISK_CAP_SCHEMA, 8, 255};
        for (size_t i = 0; i < sizeof(invalid); i++) {
            memcpy(altered, manifest, sizeof(altered));
            altered[26] = invalid[i]; crc(altered);
            REQUIRE(!yd_raft_snapshot_decode(altered, sizeof(altered), cluster, 3, &info, error, sizeof(error)));
        }
    }
    char path[4096];
    int path_length = snprintf(path, sizeof(path), "%s/%s", destination, YD_DISK_FILE);
    REQUIRE(path_length > 0 && (size_t)path_length < sizeof(path));
    int fd = open(path, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
    REQUIRE(fd >= 0 && transfer(snapshot, manifest, fd, 4093, false) && !fsync(fd));
    close(fd);
    if (capabilities) {
        REQUIRE(!yd_raft_application_open(destination, cluster, 32768, error, sizeof(error)));
        app = yd_raft_application_open_capabilities(destination, cluster, capabilities,
            32768, error, sizeof(error));
    } else app = yd_raft_application_open(destination, cluster, 32768, error, sizeof(error));
    REQUIRE(app && yd_raft_application_position(app).index == 2);
    YDDisk *disk = yd_raft_application_disk(app);
    YDDiskView view = yd_disk_view(disk);
    YDDiskDocument document;
    REQUIRE(yd_disk_document_get(disk, &view, "a", "b", &document, error, sizeof(error)) == 1 &&
            document.length == sizeof(source) - 1 &&
            !memcmp(document.body, source, document.length));
    yd_disk_document_free(&document);
    YDRaftWrite request = {.id = {1},
                           .method = "PUT",
                           .target = "/v1/collections/a/documents/b",
                           .body = source,
                           .size = sizeof(source) - 1};
    YDDiskReply reply;
    REQUIRE(yd_raft_application_receipt(app, &request, &reply, error, sizeof(error)) == 1 &&
            reply.status == 201);
    yd_disk_reply_free(&reply);
    yd_raft_application_close(app);
    yd_raft_snapshot_close(snapshot);
    return 0;
}
static void crc(unsigned char manifest[256]) {
    uint32_t sum = yd_disk_crc(manifest, 252);
    for (unsigned i = 0; i < 4; i++)
        manifest[252 + i] = (unsigned char)(sum >> (i * 8));
}
static int metadata(const char *root) {
    YDRaftApplication *app = seed(root, source, sizeof(source) - 1);
    REQUIRE(app);
    unsigned char good[256], bad[256];
    YDRaftSnapshot *snapshot = sealed(app, good);
    REQUIRE(snapshot);
    YDRaftSnapshotInfo info;
    for (size_t i = 0; i < 256; i++) {
        memcpy(bad, good, 256);
        bad[i] ^= 1;
        REQUIRE(!yd_raft_snapshot_decode(bad, 256, cluster, 3, &info, error, sizeof(error)));
    }
    for (size_t size = 0; size < 256; size++)
        REQUIRE(!yd_raft_snapshot_decode(good, size, cluster, 3, &info, error, sizeof(error)));
    unsigned char wrong[16] = {9};
    REQUIRE(!yd_raft_snapshot_decode(good, 256, wrong, 3, &info, error, sizeof(error)));
    REQUIRE(!yd_raft_snapshot_decode(good, 256, cluster, 5, &info, error, sizeof(error)));
    const size_t fields[] = {0, 24, 25, 26, 32, 40, 56, 64, 72, 168, 251};
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
        memcpy(bad, good, 256);
        size_t at = fields[i];
        if (at == 32)
            yd_disk_set64(bad + at, UINT64_MAX);
        else if (at == 40 || at == 56 || at == 64 || at == 72)
            memset(bad + at, 0, 8);
        else
            bad[at] ^= 0x80;
        crc(bad);
        REQUIRE(!yd_raft_snapshot_decode(bad, 256, cluster, 3, &info, error, sizeof(error)));
    }
    yd_raft_snapshot_close(snapshot);
    yd_raft_application_close(app);
    return 0;
}
static int stream(const char *root) {
    YDRaftApplication *app = seed(root, source, sizeof(source) - 1);
    REQUIRE(app);
    unsigned char manifest[256], bytes[8192];
    YDRaftSnapshot *snapshot = sealed(app, manifest);
    REQUIRE(snapshot);
    for (unsigned mode = 0; mode < 6; mode++) {
        YDRaftSnapshotVerifier *verifier =
            yd_raft_snapshot_verifier_new(manifest, 256, cluster, 3, error, sizeof(error));
        REQUIRE(verifier);
        REQUIRE(yd_raft_snapshot_read(snapshot, 0, bytes, sizeof(bytes), error, sizeof(error)));
        if (mode == 0)
            REQUIRE(!yd_raft_snapshot_feed(verifier, 1, bytes, 1, error, sizeof(error)));
        if (mode == 1) {
            REQUIRE(yd_raft_snapshot_feed(verifier, 0, bytes, 1, error, sizeof(error)));
            REQUIRE(!yd_raft_snapshot_feed(verifier, 0, bytes, 1, error, sizeof(error)));
        }
        if (mode == 2) {
            bytes[50] ^= 1;
            REQUIRE(
                !yd_raft_snapshot_feed(verifier, 0, bytes, sizeof(bytes), error, sizeof(error)));
        }
        if (mode == 3)
            REQUIRE(!yd_raft_snapshot_feed(verifier, 0, bytes, 0, error, sizeof(error)));
        if (mode == 4)
            REQUIRE(!yd_raft_snapshot_feed(verifier, 0, bytes, 1048577, error, sizeof(error)));
        if (mode == 5)
            REQUIRE(yd_raft_snapshot_feed(verifier, 0, bytes, sizeof(bytes), error, sizeof(error)));
        REQUIRE(!yd_raft_snapshot_finish(verifier, error, sizeof(error)));
        REQUIRE(!yd_raft_snapshot_feed(verifier, 0, bytes, 1, error, sizeof(error)));
        yd_raft_snapshot_verifier_free(verifier);
    }
    REQUIRE(!transfer(snapshot, manifest, -1, 4093, true));
    REQUIRE(transfer(snapshot, manifest, -1, 1, false) &&
            transfer(snapshot, manifest, -1, 65537, false));
    yd_raft_snapshot_close(snapshot);
    yd_raft_application_close(app);
    return 0;
}
static bool cancel_hash(void *context, uint64_t done, uint64_t total) {
    unsigned *calls = context;
    (*calls)++;
    return done == 0 && total > 1048576;
}
static int cancel(const char *root) {
    size_t size = 3U * 1024U * 1024U;
    unsigned char *large = malloc(size);
    REQUIRE(large);
    memset(large, 'x', size);
    large[0] = '#';
    memcpy(large + size - 10, "\ncount: 0\n", 10);
    YDRaftApplication *app = seed(root, large, size);
    free(large);
    REQUIRE(app);
    YDRaftSnapshot *snapshot = yd_raft_snapshot_open(app, 3, error, sizeof(error));
    REQUIRE(snapshot);
    unsigned char manifest[256], byte;
    unsigned calls = 0;
    REQUIRE(!yd_raft_snapshot_read(snapshot, 0, &byte, 1, error, sizeof(error)));
    REQUIRE(!yd_raft_snapshot_seal(snapshot, cancel_hash, &calls, error, sizeof(error)) &&
            calls >= 2);
    REQUIRE(!yd_raft_snapshot_manifest(snapshot, manifest));
    REQUIRE(yd_raft_snapshot_seal(snapshot, NULL, NULL, error, sizeof(error)) &&
            yd_raft_snapshot_manifest(snapshot, manifest));
    REQUIRE(transfer(snapshot, manifest, -1, 1048576, false));
    yd_raft_snapshot_close(snapshot);
    yd_raft_application_close(app);
    return 0;
}
static int boundaries(const char *root) {
    YDRaftApplication *app = yd_raft_application_open(root, cluster, 32768, error, sizeof(error));
    REQUIRE(app);
    for (unsigned voters = 0; voters <= 10; voters++) {
        if (voters >= 3 && voters <= 9 && (voters & 1))
            continue;
        REQUIRE(!yd_raft_snapshot_open(app, voters, error, sizeof(error)));
    }
    unsigned char manifest[256];
    YDRaftSnapshot *snapshot = sealed(app, manifest);
    REQUIRE(snapshot);
    YDRaftSnapshotInfo info;
    REQUIRE(yd_raft_snapshot_decode(manifest, 256, cluster, 3, &info, error, sizeof(error)) &&
            !info.applied.index && !info.applied.term && info.view.generation == 2);
    REQUIRE(transfer(snapshot, manifest, -1, 4093, false));
    yd_raft_snapshot_close(snapshot);
    YDDiskTxn *pending = yd_disk_begin_staging(yd_raft_application_disk(app), error, sizeof(error));
    REQUIRE(pending && !yd_raft_snapshot_open(app, 3, error, sizeof(error)));
    yd_disk_abort(pending);
    YDRaftEntry invalid = {.index = 5, .term = 1, .kind = YD_RAFT_NOOP};
    REQUIRE(!yd_raft_application_apply(app, &invalid, error, sizeof(error)));
    REQUIRE(!yd_raft_snapshot_open(app, 3, error, sizeof(error)) &&
            !yd_raft_snapshot_open(NULL, 3, error, sizeof(error)));
    yd_raft_snapshot_close(NULL);
    yd_raft_snapshot_verifier_free(NULL);
    yd_raft_application_close(app);
    return 0;
}
int main(int argc, char **argv) {
    if (argc != 3)
        return 2;
    if (!strncmp(argv[2], "capabilities-", 13)) {
        capabilities = (uint32_t)strtoul(argv[2] + 13, NULL, 10);
        REQUIRE(capabilities == 3 || capabilities == 5 || capabilities == 7);
        REQUIRE(!pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL));
    }
    char paths[2][4096];
    for (unsigned i = 0; i < 2; i++) {
        snprintf(paths[i], sizeof(paths[i]), "%s/%u", argv[1], i);
        REQUIRE(!mkdir(paths[i], 0700));
    }
    if (!strcmp(argv[2], "basic") || capabilities)
        return basic(paths[0], paths[1]);
    if (!strcmp(argv[2], "manifest"))
        return metadata(paths[0]);
    if (!strcmp(argv[2], "stream"))
        return stream(paths[0]);
    if (!strcmp(argv[2], "cancel"))
        return cancel(paths[0]);
    if (!strcmp(argv[2], "boundaries"))
        return boundaries(paths[0]);
    return 2;
}
