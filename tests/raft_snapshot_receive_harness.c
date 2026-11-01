#define _POSIX_C_SOURCE 200809L
#include "../src/consensus/snapshot_receive.h"
#include "../src/consensus/snapshot_store.h"
#include "../src/consensus/snapshot_store_internal.h"
#include "../src/consensus/snapshot_restore.h"
#include "../src/disk_documents.h"
#include <fcntl.h>
#include <errno.h>
#include <openssl/evp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <unistd.h>
static char error[512];
static const unsigned char cluster[16] = {1, 2, 3, 4};
static _Thread_local bool uncertain_publication;
YDRaftArchiveResult __real_yd_raft_snapshot_stage_finish_retaining(YDRaftSnapshotStage *, char *,
    YDRaftSnapshotProgress, void *, YDRaftSnapshotReference **, char *, size_t);
YDRaftArchiveResult __wrap_yd_raft_snapshot_stage_finish_retaining(YDRaftSnapshotStage *stage, char *id,
    YDRaftSnapshotProgress progress, void *context, YDRaftSnapshotReference **reference,
    char *message, size_t length) {
    YDRaftArchiveResult valid = __real_yd_raft_snapshot_stage_finish_retaining(stage, id,
        progress, context, reference, message, length);
    if (uncertain_publication) {
        uncertain_publication = false;
        yd_raft_snapshot_reference_close(*reference); *reference = NULL; id[0] = 0;
        return YD_RAFT_ARCHIVE_IO;
    }
    return valid;
}
#define REQUIRE(x) do { if (!(x)) { \
    fprintf(stderr, "line %u: %s (%s)\n", __LINE__, #x, error); return 2; \
} } while (0)
typedef struct {
    uint64_t term, committed;
    unsigned leader, contacts, confirms;
    bool confirmed;
} Authority;
static bool contact(void *context, const YDRaftSnapshotOffer *offer, bool *needed, uint64_t *term) {
    Authority *authority = context;
    authority->contacts++;
    if (offer->term >= authority->term) {
        authority->term = offer->term;
        authority->leader = offer->from;
    }
    *term = authority->term;
    *needed = offer->term == authority->term && offer->base.index > authority->committed;
    return true;
}
static bool confirmed(void *context, const YDRaftSnapshotOffer *offer) {
    Authority *authority = context;
    authority->confirms++;
    return authority->confirmed && offer->term == authority->term && offer->from == authority->leader &&
        authority->committed >= offer->base.index;
}
typedef struct {
    Authority authority;
    YDRaftSnapshotReceiver *receiver;
    YDRaftSnapshot *image;
    unsigned char manifest[256], session[16];
    unsigned char *source;
    size_t length;
    YDRaftSnapshotInfo info;
    YDRaftPacket request;
    char archive[4096], destination[4096];
} Fixture;
static bool exchange(Fixture *f, YDRaftPacket *request, YDRaftPacket *reply, YDRaftSnapshotJob *job) {
    request->body.snapshot.rpc++;
    bool valid = yd_raft_snapshot_receiver_handle(f->receiver, request, reply, job, error, sizeof(error));
    unsigned char header[128];
    return valid && yd_raft_wire_encode(reply, header) && yd_raft_wire_corresponds(request, reply);
}
static bool begin(Fixture *f, YDRaftPacket *reply) {
    f->request.kind = YD_RPC_SNAPSHOT_BEGIN;
    f->request.body.snapshot.offset = 0;
    f->request.body.snapshot.size = 256;
    f->request.body.snapshot.bytes = f->manifest;
    memset(f->request.body.snapshot.session, 0, 16);
    YDRaftSnapshotJob job;
    bool valid = exchange(f, &f->request, reply, &job) && !job.offer.base.index;
    if (valid && reply->body.snapshot.accepted && !reply->body.snapshot.installed)
        memcpy(f->session, reply->body.snapshot.session, 16);
    return valid;
}
static bool chunk(Fixture *f, uint64_t at, size_t count, bool corrupt, YDRaftPacket *reply) {
    unsigned char *bytes = malloc(count);
    bool valid = bytes && yd_raft_snapshot_read(f->image, at, bytes, count, error, sizeof(error));
    if (valid && corrupt) bytes[count - 1] ^= 1;
    f->request.kind = YD_RPC_SNAPSHOT_CHUNK;
    f->request.body.snapshot.offset = at;
    f->request.body.snapshot.size = count;
    f->request.body.snapshot.bytes = bytes;
    memcpy(f->request.body.snapshot.session, f->session, 16);
    YDRaftSnapshotJob job;
    valid = valid && exchange(f, &f->request, reply, &job) && !job.offer.base.index;
    f->request.body.snapshot.bytes = NULL;
    free(bytes);
    return valid;
}
static bool stream(Fixture *f, uint64_t at, bool corrupt) {
    while (at < f->info.view.end) {
        size_t count = f->info.view.end - at < YD_RAFT_WIRE_CHUNK
            ? (size_t)(f->info.view.end - at) : YD_RAFT_WIRE_CHUNK;
        YDRaftPacket reply;
        if (!chunk(f, at, count, corrupt && at + count == f->info.view.end, &reply) ||
            !reply.body.snapshot.accepted || reply.body.snapshot.installed ||
            reply.body.snapshot.offset != at + count) return false;
        at += count;
    }
    return true;
}
static bool finish(Fixture *f, YDRaftPacket *reply, YDRaftSnapshotJob *job) {
    f->request.kind = YD_RPC_SNAPSHOT_FINISH;
    f->request.body.snapshot.offset = f->info.view.end;
    f->request.body.snapshot.size = 0;
    f->request.body.snapshot.bytes = NULL;
    memcpy(f->request.body.snapshot.session, f->session, 16);
    return exchange(f, &f->request, reply, job);
}
static bool restored(Fixture *f) {
    char id[65];
    for (unsigned i = 0; i < 32; i++) snprintf(id + 2 * i, 3, "%02x", f->request.body.snapshot.base.archive[i]);
    YDRaftSnapshotStore *store = yd_raft_snapshot_store_open(f->archive, cluster, 3, error, sizeof(error));
    YDRaftSnapshotArchive *archive = store ? yd_raft_snapshot_archive_open(store, id, NULL, NULL, error, sizeof(error)) : NULL;
    bool valid = archive && yd_raft_snapshot_restore(archive, f->destination, cluster, 3, 32768, NULL, NULL, error, sizeof(error));
    yd_raft_snapshot_archive_close(archive); yd_raft_snapshot_store_close(store);
    YDRaftApplication *app = valid ? yd_raft_application_open(f->destination, cluster, 32768, error, sizeof(error)) : NULL;
    YDRaftWrite write = {.id = {1}, .method = "PUT", .target = "/v1/collections/a/documents/b", .body = f->source, .size = f->length};
    YDDiskReply receipt = {0};
    YDDiskDocument doc = {0};
    YDDiskView view = app ? yd_disk_view(yd_raft_application_disk(app)) : (YDDiskView){0};
    valid = app && yd_raft_application_position(app).index == 1 &&
        yd_raft_application_receipt(app, &write, &receipt, error, sizeof(error)) == 1 && receipt.status == 201 &&
        yd_disk_document_get(yd_raft_application_disk(app), &view, "a", "b", &doc, error, sizeof(error)) == 1 &&
        doc.length == f->length && !memcmp(doc.body, f->source, f->length);
    yd_disk_document_free(&doc); yd_disk_reply_free(&receipt); yd_raft_application_close(app);
    if (valid) { f->authority.confirmed = true; f->authority.committed = 1; }
    return valid;
}
static bool archive_pin(Fixture *f, bool expected) {
    char path[8192], id[65];
    for (unsigned i = 0; i < 32; i++) snprintf(id + 2 * i, 3, "%02x", f->request.body.snapshot.base.archive[i]);
    snprintf(path, sizeof(path), "%s/%s.snapshot", f->archive, id);
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return false;
    int result = flock(fd, LOCK_EX | LOCK_NB), saved = errno;
    close(fd);
    return expected ? result < 0 && (saved == EWOULDBLOCK || saved == EAGAIN) : result == 0;
}
typedef struct { Fixture *fixture; YDRaftPacket request, reply; bool valid; } Concurrent;
static void *duplicate_begin(void *context) {
    Concurrent *call = context;
    YDRaftSnapshotJob job;
    char message[512];
    call->valid = yd_raft_snapshot_receiver_handle(call->fixture->receiver, &call->request,
        &call->reply, &job, message, sizeof(message)) && !job.offer.base.index &&
        call->reply.body.snapshot.accepted && !call->reply.body.snapshot.installed;
    return NULL;
}
int main(int argc, char **argv) {
    if (argc != 3) return 1;
    Fixture f = {.authority = {.term = 3, .leader = 1}};
    char source[4096], moved[4096];
    snprintf(source, sizeof(source), "%s/source", argv[1]);
    snprintf(f.archive, sizeof(f.archive), "%s/archive", argv[1]);
    snprintf(f.destination, sizeof(f.destination), "%s/candidate", argv[1]);
    REQUIRE(!mkdir(source, 0700) && !mkdir(f.archive, 0700) && !mkdir(f.destination, 0700));
    static const unsigned char short_source[] = "# exact received source\r\nvalue: preserved # keep\r\n";
    f.length = !strcmp(argv[2], "basic") ? 2U * 1024U * 1024U : sizeof(short_source) - 1;
    f.source = malloc(f.length);
    REQUIRE(f.source);
    if (f.length == sizeof(short_source) - 1) memcpy(f.source, short_source, f.length);
    else { memset(f.source, 'a', f.length); memcpy(f.source, "# exact\r\nvalue: \"", 17); memcpy(f.source + f.length - 3, "\"\r\n", 3); }
    YDRaftApplication *app = yd_raft_application_open(source, cluster, 32768, error, sizeof(error));
    REQUIRE(app);
    YDRaftWrite write = {.id = {1}, .method = "PUT", .target = "/v1/collections/a/documents/b", .body = f.source, .size = f.length};
    YDRaftProposal proposal = {0};
    REQUIRE(yd_raft_application_prepare(app, &write, &proposal, error, sizeof(error)) == 1);
    YDRaftEntry entry = {.index = 1, .term = 2, .kind = YD_RAFT_COMMAND, .command = proposal.command, .size = proposal.size};
    REQUIRE(yd_raft_application_apply(app, &entry, error, sizeof(error)));
    yd_raft_proposal_free(&proposal);
    f.image = yd_raft_snapshot_open(app, 3, error, sizeof(error));
    REQUIRE(f.image && yd_raft_snapshot_seal(f.image, NULL, NULL, error, sizeof(error)) &&
        yd_raft_snapshot_manifest(f.image, f.manifest) &&
        yd_raft_snapshot_decode(f.manifest, 256, cluster, 3, &f.info, error, sizeof(error)));
    yd_raft_application_close(app);
    f.request = (YDRaftPacket){.kind = YD_RPC_SNAPSHOT_BEGIN, .from = 1, .to = 2,
        .body.snapshot = {.term = 3, .rpc = 1, .base = {.index = 1, .term = 2}}};
    memcpy(f.request.cluster, cluster, 16);
    size_t digest_size;
    REQUIRE(EVP_Q_digest(NULL, "SHA256", NULL, f.manifest, 256, f.request.body.snapshot.base.archive, &digest_size) == 1 && digest_size == 32);
    int directory = open(f.archive, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    YDRaftSnapshotReceiverHooks hooks = {.context = &f.authority, .contact = contact, .confirmed = confirmed};
    f.receiver = yd_raft_snapshot_receiver_new(directory, cluster, 2, 3, hooks, error, sizeof(error));
    REQUIRE(f.receiver);
    close(directory);
    YDRaftPacket reply;
    YDRaftSnapshotJob job, other;
    REQUIRE(begin(&f, &reply) && reply.body.snapshot.accepted && !reply.body.snapshot.installed && !reply.body.snapshot.offset);
    if (!strcmp(argv[2], "basic")) {
        snprintf(moved, sizeof(moved), "%s/archive-moved", argv[1]);
        REQUIRE(!rename(f.archive, moved));
        memcpy(f.archive, moved, strlen(moved) + 1);
    } else if (!strcmp(argv[2], "resume")) {
        unsigned char session[16]; memcpy(session, f.session, 16);
        REQUIRE(chunk(&f, 0, 4093, false, &reply) && reply.body.snapshot.accepted);
        REQUIRE(begin(&f, &reply) && reply.body.snapshot.offset == 4093 && !memcmp(session, f.session, 16));
        REQUIRE(chunk(&f, 0, 4093, false, &reply) && reply.body.snapshot.offset == 4093);
        REQUIRE(stream(&f, 4093, false));
    } else if (!strcmp(argv[2], "invalid")) {
        unsigned contacts = f.authority.contacts;
        REQUIRE(finish(&f, &reply, &other) && !reply.body.snapshot.accepted && !other.offer.base.index);
        unsigned char bytes[256] = {0};
        YDRaftPacket bad = f.request;
        bad.kind = YD_RPC_SNAPSHOT_CHUNK; bad.body.snapshot.bytes = bytes; bad.body.snapshot.size = 1;
        bad.body.snapshot.offset = f.info.view.end;
        REQUIRE(exchange(&f, &bad, &reply, &other) && !reply.body.snapshot.accepted);
        bad.body.snapshot.offset = 0; bad.body.snapshot.session[0] ^= 1;
        REQUIRE(exchange(&f, &bad, &reply, &other) && !reply.body.snapshot.accepted);
        memcpy(bad.body.snapshot.session, f.session, 16); bad.from = 3;
        REQUIRE(exchange(&f, &bad, &reply, &other) && !reply.body.snapshot.accepted);
        bad = f.request; bad.kind = YD_RPC_SNAPSHOT_BEGIN; bad.body.snapshot.offset = 0;
        bad.body.snapshot.size = 256; bad.body.snapshot.bytes = bytes; memset(bad.body.snapshot.session, 0, 16);
        REQUIRE(exchange(&f, &bad, &reply, &other) && !reply.body.snapshot.accepted);
        bad.body.snapshot.bytes = f.manifest; bad.body.snapshot.base.archive[1]++;
        REQUIRE(exchange(&f, &bad, &reply, &other) && !reply.body.snapshot.accepted);
        REQUIRE(f.authority.contacts == contacts);
    } else if (!strcmp(argv[2], "concurrent")) {
        Concurrent calls[8]; pthread_t threads[8];
        for (unsigned i = 0; i < 8; i++) {
            calls[i] = (Concurrent){.fixture = &f, .request = f.request};
            REQUIRE(!pthread_create(&threads[i], NULL, duplicate_begin, &calls[i]));
        }
        for (unsigned i = 0; i < 8; i++) {
            REQUIRE(!pthread_join(threads[i], NULL) && calls[i].valid &&
                !memcmp(calls[i].reply.body.snapshot.session, f.session, 16));
        }
    }
    if (strcmp(argv[2], "resume")) REQUIRE(stream(&f, 0, !strcmp(argv[2], "corrupt")));
    uncertain_publication = !strcmp(argv[2], "uncertain");
    REQUIRE(finish(&f, &reply, &job));
    if (!strcmp(argv[2], "uncertain")) {
        char filename[8192], id[65]; struct stat status;
        for (unsigned i = 0; i < 32; i++) snprintf(id + 2 * i, 3, "%02x", f.request.body.snapshot.base.archive[i]);
        snprintf(filename, sizeof(filename), "%s/%s.snapshot", f.archive, id);
        REQUIRE(!stat(filename, &status) && S_ISREG(status.st_mode) && status.st_nlink == 1 &&
            (status.st_mode & 0777) == 0400 && (uint64_t)status.st_size == f.info.view.end + 256);
    }
    if (!strcmp(argv[2], "corrupt") || !strcmp(argv[2], "uncertain")) {
        REQUIRE(!reply.body.snapshot.accepted && !job.offer.base.index);
        REQUIRE(begin(&f, &reply) && reply.body.snapshot.accepted && stream(&f, 0, false));
        REQUIRE(finish(&f, &reply, &job));
    }
    REQUIRE(reply.body.snapshot.accepted && !reply.body.snapshot.installed && job.offer.base.index == 1);
    if (!strcmp(argv[2], "job-clone")) {
        YDRaftSnapshotReference *reference = (void *)1;
        other = job; other.session[15]++;
        REQUIRE(!yd_raft_snapshot_receiver_reference(f.receiver, &other, &reference, error, sizeof(error)) && !reference);
        REQUIRE(yd_raft_snapshot_receiver_reference(f.receiver, &job, &reference, error, sizeof(error)) && reference);
        REQUIRE(yd_raft_snapshot_receiver_complete(f.receiver, &job, false) && archive_pin(&f, true));
        yd_raft_snapshot_receiver_close(f.receiver); f.receiver = NULL;
        REQUIRE(archive_pin(&f, true));
        YDRaftSnapshotArchive *owned = NULL;
        REQUIRE(yd_raft_snapshot_archive_open_reference(reference, NULL, NULL, &owned, error, sizeof(error)) == YD_RAFT_ARCHIVE_OK);
        yd_raft_snapshot_reference_close(reference);
        REQUIRE(archive_pin(&f, true));
        yd_raft_snapshot_archive_close(owned);
        REQUIRE(archive_pin(&f, false));
        goto done;
    }
    if (!strcmp(argv[2], "pin")) {
        REQUIRE(archive_pin(&f, true));
        other = job; other.session[15]++;
        REQUIRE(!yd_raft_snapshot_receiver_complete(f.receiver, &other, false) && archive_pin(&f, true));
        REQUIRE(yd_raft_snapshot_receiver_complete(f.receiver, &job, false) && archive_pin(&f, false));
        REQUIRE(begin(&f, &reply) && reply.body.snapshot.accepted && stream(&f, 0, false));
        REQUIRE(finish(&f, &reply, &job) && job.offer.base.index == 1 && archive_pin(&f, true));
        yd_raft_snapshot_receiver_close(f.receiver); f.receiver = NULL;
        REQUIRE(archive_pin(&f, false));
        goto done;
    }
    REQUIRE(finish(&f, &reply, &other) && !other.offer.base.index && !reply.body.snapshot.installed);
    if (!strcmp(argv[2], "jobs")) {
        other = job; other.session[15]++;
        REQUIRE(!yd_raft_snapshot_receiver_complete(f.receiver, &other, true));
        REQUIRE(yd_raft_snapshot_receiver_complete(f.receiver, &job, true));
        REQUIRE(finish(&f, &reply, &other) && !reply.body.snapshot.accepted);
        REQUIRE(begin(&f, &reply) && reply.body.snapshot.accepted && memcmp(job.session, f.session, 16));
        REQUIRE(stream(&f, 0, false) && finish(&f, &reply, &job) && job.offer.base.index == 1);
        REQUIRE(yd_raft_snapshot_receiver_complete(f.receiver, &job, false));
        REQUIRE(begin(&f, &reply) && reply.body.snapshot.accepted && stream(&f, 0, false));
        REQUIRE(finish(&f, &reply, &job) && job.offer.base.index == 1);
    } else if (!strcmp(argv[2], "applied")) {
        f.authority.committed = 1;
        REQUIRE(finish(&f, &reply, &other) && !reply.body.snapshot.accepted && !other.offer.base.index);
        REQUIRE(begin(&f, &reply) && !reply.body.snapshot.accepted);
        REQUIRE(yd_raft_snapshot_receiver_complete(f.receiver, &job, true));
        REQUIRE(begin(&f, &reply) && !reply.body.snapshot.accepted);
        REQUIRE(restored(&f));
        REQUIRE(begin(&f, &reply) && reply.body.snapshot.accepted && reply.body.snapshot.installed);
        goto done;
    } else if (!strcmp(argv[2], "authority")) {
        f.request.from = 3; f.request.body.snapshot.term = 4;
        REQUIRE(begin(&f, &reply) && !reply.body.snapshot.accepted && f.authority.term == 4);
        f.request.from = 1; f.request.body.snapshot.term = 3;
        REQUIRE(finish(&f, &reply, &other) && !reply.body.snapshot.accepted && reply.body.snapshot.term == 4);
        REQUIRE(restored(&f) && yd_raft_snapshot_receiver_complete(f.receiver, &job, true));
        REQUIRE(finish(&f, &reply, &other) && !reply.body.snapshot.accepted);
        f.request.from = 3; f.request.body.snapshot.term = 4;
        REQUIRE(begin(&f, &reply) && reply.body.snapshot.accepted && reply.body.snapshot.installed);
        goto done;
    } else if (!strcmp(argv[2], "restart")) {
        yd_raft_snapshot_receiver_close(f.receiver);
        directory = open(f.archive, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        f.receiver = yd_raft_snapshot_receiver_new(directory, cluster, 2, 3, hooks, error, sizeof(error));
        close(directory); REQUIRE(f.receiver);
        REQUIRE(!yd_raft_snapshot_receiver_complete(f.receiver, &job, true));
        REQUIRE(begin(&f, &reply) && reply.body.snapshot.accepted && memcmp(job.session, f.session, 16));
        REQUIRE(stream(&f, 0, false) && finish(&f, &reply, &job) && job.offer.base.index == 1);
    }
    REQUIRE(restored(&f) && yd_raft_snapshot_receiver_complete(f.receiver, &job, true));
    REQUIRE(!yd_raft_snapshot_receiver_complete(f.receiver, &job, true));
    REQUIRE(finish(&f, &reply, &other) && reply.body.snapshot.accepted && reply.body.snapshot.installed && !other.offer.base.index);
    REQUIRE(begin(&f, &reply) && reply.body.snapshot.accepted && reply.body.snapshot.installed);
done:
    yd_raft_snapshot_receiver_close(f.receiver);
    yd_raft_snapshot_close(f.image);
    free(f.source);
    return 0;
}
