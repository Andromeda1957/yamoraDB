#define _POSIX_C_SOURCE 200809L
#include "../src/consensus/snapshot_send.h"
#include "../src/consensus/snapshot_receive.h"
#include "../src/consensus/snapshot_restore.h"
#include "../src/disk_documents.h"
#include <fcntl.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#define REQUIRE(x) do { if (!(x)) { \
    fprintf(stderr, "line %u: %s (%s)\n", __LINE__, #x, error); return 2; \
} } while (0)
static char error[512];
static const unsigned char cluster[16] = {1, 2, 3, 4};
typedef struct {
    YDRaftSnapshotReceiver *receiver;
    YDRaftSnapshotArchive *archive;
    YDRaftSnapshotRequest request;
    YDRaftSnapshotJob job;
    YDRaftSnapshotInfo info;
    YDRaftSnapshotSendHooks hooks;
    unsigned char *source;
    size_t length, used, peak, budget, fail_reserve;
    uint64_t term, first_offset;
    unsigned reservations, calls, chunks, begins, finishes, pauses, jobs;
    unsigned mutate, mutate_kind, fail_kind;
    bool current, confirmed, higher, lose_chunk, cancel, fail_job;
    char destination[4096], received[4096];
} Fixture;
static bool contact(void *ctx, const YDRaftSnapshotOffer *offer, bool *needed, uint64_t *term) {
    Fixture *f = ctx;
    *term = f->term;
    *needed = !f->confirmed && offer->term == *term;
    return true;
}
static bool confirmed(void *ctx, const YDRaftSnapshotOffer *offer) {
    Fixture *f = ctx;
    return f->confirmed && offer->term == f->term;
}
static bool current(void *ctx) { return ((Fixture *)ctx)->current; }
static bool reserve(void *ctx, size_t bytes) {
    Fixture *f = ctx;
    f->reservations++;
    if (f->reservations == f->fail_reserve || bytes > f->budget - f->used) return false;
    f->used += bytes;
    if (f->used > f->peak) f->peak = f->used;
    return true;
}
static void release(void *ctx, size_t bytes) { ((Fixture *)ctx)->used -= bytes; }
static bool exchange(void *ctx, const YDRaftPacket *request, YDRaftPacket *reply) {
    Fixture *f = ctx;
    f->calls++;
    if (request->kind == YD_RPC_SNAPSHOT_BEGIN) f->begins++;
    if (request->kind == YD_RPC_SNAPSHOT_CHUNK) {
        if (!f->chunks) f->first_offset = request->body.snapshot.offset;
        f->chunks++;
    }
    if (request->kind == YD_RPC_SNAPSHOT_FINISH) f->finishes++;
    if (f->higher) f->term = request->body.snapshot.term + 1;
    YDRaftSnapshotJob job;
    bool valid = yd_raft_snapshot_receiver_handle(f->receiver, request, reply, &job, error, sizeof(error));
    if (job.offer.base.index) { f->job = job; f->jobs++; }
    if (f->lose_chunk && request->kind == YD_RPC_SNAPSHOT_CHUNK) {
        f->lose_chunk = false;
        return false;
    }
    if (f->fail_kind == (unsigned)request->kind) return false;
    if (f->mutate_kind == (unsigned)request->kind) {
        if (f->mutate == 1) reply->from = 3;
        if (f->mutate == 2) reply->body.snapshot.rpc++;
        if (f->mutate == 3) reply->body.snapshot.base.archive[0] ^= 1;
        if (f->mutate == 4) reply->body.snapshot.term++;
        if (f->mutate == 5) reply->body.snapshot.session[0] ^= 1;
        if (f->mutate == 6) reply->body.snapshot.offset = f->info.view.end + 1;
        if (f->mutate == 7) reply->body.snapshot.installed = true;
        if (f->mutate == 8) reply->body.snapshot.base.index++;
    }
    return valid;
}
static bool restore(Fixture *f) {
    char id[65];
    for (unsigned i = 0; i < 32; i++) snprintf(id + 2 * i, 3, "%02x", f->request.offer.base.archive[i]);
    YDRaftSnapshotStore *store = yd_raft_snapshot_store_open(f->received, cluster, 3, error, sizeof(error));
    YDRaftSnapshotArchive *archive = store ? yd_raft_snapshot_archive_open(store, id, NULL, NULL, error, sizeof(error)) : NULL;
    bool valid = archive && yd_raft_snapshot_restore(archive, f->destination, cluster, 3, 32768, NULL, NULL, error, sizeof(error));
    yd_raft_snapshot_archive_close(archive); yd_raft_snapshot_store_close(store);
    YDRaftApplication *app = valid ? yd_raft_application_open(f->destination, cluster, 32768, error, sizeof(error)) : NULL;
    YDDiskDocument doc = {0}; YDDiskReply receipt = {0};
    YDDiskView view = app ? yd_disk_view(yd_raft_application_disk(app)) : (YDDiskView){0};
    YDRaftWrite write = {.id = {1}, .method = "PUT", .target = "/v1/collections/a/documents/b", .body = f->source, .size = f->length};
    valid = app && yd_disk_document_get(yd_raft_application_disk(app), &view, "a", "b", &doc, error, sizeof(error)) == 1 &&
        doc.length == f->length && !memcmp(doc.body, f->source, f->length) &&
        yd_raft_application_receipt(app, &write, &receipt, error, sizeof(error)) == 1 && receipt.status == 201;
    yd_disk_document_free(&doc); yd_disk_reply_free(&receipt); yd_raft_application_close(app);
    return valid;
}
static bool pause_job(void *ctx) {
    Fixture *f = ctx;
    f->pauses++;
    if (f->used || !f->job.offer.base.index) return false;
    if (f->cancel) { f->current = false; return false; }
    if (f->pauses < 3) return true;
    if (f->fail_job) {
        f->fail_job = false;
        yd_raft_snapshot_receiver_complete(f->receiver, &f->job, false);
    } else {
        if (!restore(f)) return false;
        f->confirmed = true;
        yd_raft_snapshot_receiver_complete(f->receiver, &f->job, true);
    }
    return true;
}
static bool incoming(Fixture *f) {
    int directory = open(f->received, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    YDRaftSnapshotReceiverHooks hooks = {.context = f, .contact = contact, .confirmed = confirmed};
    f->receiver = yd_raft_snapshot_receiver_new(directory, cluster, 2, 3, hooks, error, sizeof(error));
    if (directory >= 0) close(directory);
    return f->receiver != NULL;
}
static bool setup(Fixture *f, const char *root, bool large) {
    memset(f, 0, sizeof(*f));
    f->current = true; f->term = 3; f->budget = 65536;
    f->hooks = (YDRaftSnapshotSendHooks){.context = f, .current = current, .exchange = exchange,
        .pause = pause_job, .reserve = reserve, .release = release};
    char source[4096], outgoing[4096];
    snprintf(source, sizeof(source), "%s/source", root);
    snprintf(outgoing, sizeof(outgoing), "%s/outgoing", root);
    snprintf(f->received, sizeof(f->received), "%s/received", root);
    snprintf(f->destination, sizeof(f->destination), "%s/destination", root);
    if (mkdir(source, 0700) || mkdir(outgoing, 0700) || mkdir(f->received, 0700) || mkdir(f->destination, 0700)) return false;
    static const char exact[] = "# source comment\r\nvalue: 'keep' # trailing\r\n";
    f->length = large ? 2U * 1024U * 1024U : sizeof(exact) - 1;
    f->source = malloc(f->length);
    if (!f->source) return false;
    if (large) { memset(f->source, 'a', f->length); memcpy(f->source, "# exact\r\nvalue: \"", 17); memcpy(f->source + f->length - 3, "\"\r\n", 3); }
    else memcpy(f->source, exact, f->length);
    YDRaftApplication *app = yd_raft_application_open(source, cluster, 32768, error, sizeof(error));
    YDRaftWrite write = {.id = {1}, .method = "PUT", .target = "/v1/collections/a/documents/b", .body = f->source, .size = f->length};
    YDRaftProposal proposal = {0};
    bool valid = app && yd_raft_application_prepare(app, &write, &proposal, error, sizeof(error)) == 1;
    YDRaftEntry entry = {.index = 1, .term = 2, .kind = YD_RAFT_COMMAND, .command = proposal.command, .size = proposal.size};
    valid = valid && yd_raft_application_apply(app, &entry, error, sizeof(error));
    yd_raft_proposal_free(&proposal);
    YDRaftSnapshot *image = valid ? yd_raft_snapshot_open(app, 3, error, sizeof(error)) : NULL;
    unsigned char manifest[256], buffer[65536];
    valid = image && yd_raft_snapshot_seal(image, NULL, NULL, error, sizeof(error)) &&
        yd_raft_snapshot_manifest(image, manifest) && yd_raft_snapshot_decode(manifest, 256, cluster, 3, &f->info, error, sizeof(error));
    YDRaftSnapshotStore *store = valid ? yd_raft_snapshot_store_open(outgoing, cluster, 3, error, sizeof(error)) : NULL;
    YDRaftSnapshotStage *stage = store ? yd_raft_snapshot_stage_new(store, manifest, 256, error, sizeof(error)) : NULL;
    valid = stage != NULL;
    for (uint64_t at = 0; valid && at < f->info.view.end;) {
        size_t count = f->info.view.end - at < sizeof(buffer) ? (size_t)(f->info.view.end - at) : sizeof(buffer);
        valid = yd_raft_snapshot_read(image, at, buffer, count, error, sizeof(error)) &&
            yd_raft_snapshot_stage_feed(stage, at, buffer, count, error, sizeof(error));
        at += count;
    }
    char id[65];
    valid = valid && yd_raft_snapshot_stage_finish(stage, id, error, sizeof(error));
    yd_raft_snapshot_stage_close(stage); yd_raft_snapshot_close(image); yd_raft_application_close(app);
    f->archive = valid ? yd_raft_snapshot_archive_open(store, id, NULL, NULL, error, sizeof(error)) : NULL;
    yd_raft_snapshot_store_close(store);
    f->request = (YDRaftSnapshotRequest){.offer = {.from = 1, .term = 3, .base = {.index = 1, .term = 2}}, .to = 2, .rpc = 7};
    memcpy(f->request.offer.cluster, cluster, 16);
    size_t size;
    valid = f->archive && EVP_Q_digest(NULL, "SHA256", NULL, manifest, 256, f->request.offer.base.archive, &size) == 1 && size == 32;
    return valid && incoming(f);
}
static bool send(Fixture *f, YDRaftSnapshotReply *reply) {
    return yd_raft_snapshot_send(f->archive, &f->request, 3, 65536, f->hooks, reply, error, sizeof(error));
}
static void cleanup(Fixture *f) {
    yd_raft_snapshot_receiver_close(f->receiver);
    yd_raft_snapshot_archive_close(f->archive);
    free(f->source);
}
int main(int argc, char **argv) {
    if (argc != 3) return 1;
    Fixture f; YDRaftSnapshotReply reply;
    REQUIRE(setup(&f, argv[1], !strcmp(argv[2], "basic") || !strcmp(argv[2], "resume")));
    if (!strcmp(argv[2], "basic")) {
        REQUIRE(send(&f, &reply) && reply.installed && reply.rpc == 7 && reply.term == 3 &&
            f.confirmed && f.jobs == 1 && f.pauses == 3 && f.finishes == 4 &&
            f.peak == 65536 && !f.used && f.chunks > 32);
    } else if (!strcmp(argv[2], "resume")) {
        f.lose_chunk = true;
        REQUIRE(!send(&f, &reply) && !reply.installed && !f.used && f.chunks == 1);
        f.chunks = 0; f.request.rpc++;
        REQUIRE(send(&f, &reply) && reply.installed && f.first_offset == 65536 && f.begins == 2 && !f.used);
    } else if (!strcmp(argv[2], "higher")) {
        f.higher = true;
        REQUIRE(send(&f, &reply) && !reply.installed && reply.term == 4 && reply.rpc == 7 &&
            f.calls == 1 && !f.used && !f.jobs);
    } else if (!strcmp(argv[2], "cancel")) {
        f.cancel = true;
        REQUIRE(!send(&f, &reply) && !reply.installed && !f.used && f.jobs == 1 && f.pauses == 1);
        yd_raft_snapshot_receiver_complete(f.receiver, &f.job, false);
    } else if (!strcmp(argv[2], "correlation")) {
        const unsigned kinds[] = {YD_RPC_SNAPSHOT_BEGIN, YD_RPC_SNAPSHOT_CHUNK, YD_RPC_SNAPSHOT_FINISH};
        for (unsigned k = 0; k < 3; k++) for (unsigned mutation = 1; mutation <= 8; mutation++) {
            /* BEGIN chooses a fresh random session; changing it cannot be detected
             * until its next use. installed=true is only invalid on CHUNKED. */
            if ((k == 0 && mutation == 5) || (k != 1 && mutation == 7)) continue;
            yd_raft_snapshot_receiver_close(f.receiver);
            REQUIRE(incoming(&f));
            f.mutate_kind = kinds[k]; f.mutate = mutation; f.request.rpc++;
            bool result = send(&f, &reply);
            if (result || reply.installed || f.used)
                fprintf(stderr, "phase=%u mutation=%u result=%u installed=%u bytes=%zu\n",
                    kinds[k], mutation, result, reply.installed, f.used);
            REQUIRE(!result && !reply.installed && !f.used);
            if (f.job.offer.base.index) yd_raft_snapshot_receiver_complete(f.receiver, &f.job, false);
            f.job = (YDRaftSnapshotJob){0};
        }
    } else if (!strcmp(argv[2], "identity")) {
        YDRaftSnapshotRequest original = f.request;
        for (unsigned i = 0; i < 8; i++) {
            f.request = original;
            if (i == 0) f.request.offer.base.archive[0] ^= 1;
            if (i == 1) f.request.offer.base.index++;
            if (i == 2) f.request.offer.base.term++;
            if (i == 3) f.request.offer.cluster[0] ^= 1;
            if (i == 4) f.request.offer.term = 1;
            if (i == 5) f.request.to = 1;
            if (i == 6) f.request.to = 4;
            if (i == 7) f.request.rpc = 0;
            REQUIRE(!send(&f, &reply) && !reply.installed && !f.calls && !f.reservations);
        }
        REQUIRE(!yd_raft_snapshot_send(NULL, &original, 3, 65536, f.hooks, &reply, error, sizeof(error)) &&
            !yd_raft_snapshot_send(f.archive, NULL, 3, 65536, f.hooks, &reply, error, sizeof(error)) &&
            !yd_raft_snapshot_send(f.archive, &original, 3, 0, f.hooks, &reply, error, sizeof(error)) &&
            !yd_raft_snapshot_send(f.archive, &original, 3, YD_RAFT_WIRE_CHUNK + 1, f.hooks, &reply, error, sizeof(error)) &&
            !yd_raft_snapshot_send(f.archive, &original, 3, 65536, f.hooks, NULL, error, sizeof(error)) &&
            !f.calls && !f.used);
    } else if (!strcmp(argv[2], "budget")) {
        f.fail_reserve = 1;
        REQUIRE(!send(&f, &reply) && !f.calls && !f.used && !reply.installed);
        f.fail_reserve = 3;
        REQUIRE(!send(&f, &reply) && f.calls == 1 && !f.used && !reply.installed);
        f.fail_reserve = 0;
        REQUIRE(send(&f, &reply) && reply.installed && !f.used);
    } else if (!strcmp(argv[2], "retry")) {
        f.fail_job = true;
        REQUIRE(send(&f, &reply) && !reply.installed && !f.used && f.jobs == 1);
        f.pauses = 0; f.job = (YDRaftSnapshotJob){0}; f.request.rpc++;
        REQUIRE(send(&f, &reply) && reply.installed && f.jobs == 2 && !f.used);
    } else return 1;
    cleanup(&f);
    return 0;
}
